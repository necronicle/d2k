#include "experiment.h"
#include "raw_tls.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
static int first_response_step(void *ctx,size_t state,size_t input,size_t *next) {
    const d2k_experiment *e=ctx;
    if(!e || !next || state>1 || input>=e->operation_count || !e->operations)return -1;
    const d2k_experiment_operation *op=&e->operations[input];
    if(state==0 && op->kind==D2K_EXPERIMENT_SEND && op->trigger &&
       op->trigger->len && op->offset==0 && op->next_offset==op->trigger->len) {
        *next=1;return 1;
    }
    if(state==1 && (op->kind==D2K_EXPERIMENT_READ || op->kind==D2K_EXPERIMENT_PACKET)) {
        *next=1;return 1;
    }
    return 0;
}
d2k_input_domain d2k_first_response_domain(const d2k_experiment *e) {
    return (d2k_input_domain){(void *)e,2,0,e?e->operation_count:0,first_response_step};
}

struct d2k_experiment_channel {
    const d2k_experiment *experiment;
    d2k_raw_episode *episode;
    int sealed;
    size_t operation_state;
    d2k_experiment_operation last_operation;
    int operation_available;
    uint8_t *coverage,*retained,*incoming;
    size_t covered,retained_length,retained_at;
    uint32_t stream_next;
    int stream_bad,tls_owned,tls_first,stream_eof;
    d2k_raw_tls_sink sink;
    d2k_raw_tuple tuple;
    uint64_t ordinal;
    d2k_raw_observation tls_read_observation;
    int tls_read_observed;
};
static int stream_event(d2k_experiment_channel *c,d2k_raw_tls_action action,
    int64_t started,int result,int wait,uint32_t offset,const d2k_raw_observation *raw,
    const uint8_t *bytes,size_t length,const char *program)
{
    if(!c || !c->sink.record)return 0;
    d2k_raw_tls_event event={.experience=c->sink.experience,.ordinal=c->ordinal++,
        .started_ms=started,.finished_ms=d2k_now_ms(),.action=action,.send_offset=offset,
        .result=result,.wait_ms=wait,.observation=*raw,.tuple=c->tuple,
        .bytes=bytes,.length=length,.program=program};
    if(!c->sink.record(c->sink.context,&event))return 0;
    c->stream_bad=1;c->sealed=1;return -1;
}
static const char stream_identity[]=D2K_RAW_TLS_IDENTITY;
static int stream_write(void *ctx,const uint8_t *bytes,size_t length,char *err,size_t cap)
{
    d2k_experiment_channel *c=ctx;
    const d2k_experiment *e=c->experiment;
    if(c->stream_bad || !bytes || !length || d2k_detect_stopped(e->cancel))goto failed;
    if(c->tls_first) {
        if(length!=e->tls_input_length || memcmp(bytes,e->tls_input,length))goto failed;
        c->tls_first=0;return 0;
    }
    if(length>UINT32_MAX-c->stream_next)goto failed;
    d2k_trigger *tr=calloc(1,sizeof *tr);
    if(!tr)goto failed;
    for(size_t at=0;at<length;) {
        size_t n=length-at;if(n>sizeof tr->payload)n=sizeof tr->payload;
        memcpy(tr->payload,bytes+at,n);tr->len=n;
        d2k_raw_observation observed={0};
        int64_t started=d2k_now_ms();
        int rc=d2k_raw_episode_send(c->episode,c->stream_next,c->stream_next+(uint32_t)n,
            tr,stream_identity,e->cancel,err,cap,&observed);
        if(stream_event(c,D2K_RAW_TLS_SEND,started,rc,0,c->stream_next,&observed,
            bytes+at,n,stream_identity)){free(tr);goto failed;}
        if(rc || !observed.sent || !observed.program_packets ||
           observed.submitted_packets!=observed.program_packets) {free(tr);goto failed;}
        c->stream_next+=(uint32_t)n;at+=n;
    }
    free(tr);return 0;
failed:
    c->stream_bad=1;
    snprintf(err,cap,"experiment TLS write unavailable or input mismatch");return -1;
}
static long stream_read(void *ctx,uint8_t *bytes,size_t capacity,int wait,char *err,size_t cap)
{
    d2k_experiment_channel *c=ctx;
    memset(&c->tls_read_observation,0,sizeof c->tls_read_observation);
    c->tls_read_observation.kind=D2K_RAW_OBS_LOCAL;
    c->tls_read_observed=1;
    if(c->stream_bad || c->tls_first || !bytes || !capacity || wait<=0 ||
       d2k_detect_stopped(c->experiment->cancel))goto failed;
    if(c->retained_at<c->retained_length) {
        size_t n=c->retained_length-c->retained_at;if(n>capacity)n=capacity;
        memcpy(bytes,c->retained+c->retained_at,n);c->retained_at+=n;
        c->tls_read_observation.kind=D2K_RAW_OBS_RESPONSE_BYTES;
        return (long)n;
    }
    if(c->stream_eof){c->tls_read_observation.kind=D2K_RAW_OBS_RESPONSE_FIN;return 0;}
    /* Read into a full backend buffer: a small TLS read must not discard the
       remainder of an already acknowledged TCP payload. */
    uint8_t *buffer=realloc(c->retained,65535);
    if(!buffer)goto failed;
    c->retained=buffer;c->retained_at=c->retained_length=0;
    d2k_raw_observation observed={0};
    int64_t started=d2k_now_ms();
    int rc=d2k_raw_episode_read(c->episode,wait,c->experiment->cancel,buffer,65535,
        &c->retained_length,1,&observed);
    if(stream_event(c,D2K_RAW_TLS_READ,started,rc,wait,c->stream_next,&observed,
        buffer,c->retained_length,NULL))goto failed;
    c->tls_read_observation=observed;
    if(observed.kind==D2K_RAW_OBS_RESPONSE_FIN) {
        c->stream_eof=1;
        if(!c->retained_length)return 0;
    } else if(rc || !c->retained_length)goto failed;
    size_t n=c->retained_length;if(n>capacity)n=capacity;
    c->tls_read_observation.kind=D2K_RAW_OBS_RESPONSE_BYTES;
    memcpy(bytes,buffer,n);c->retained_at=n;return (long)n;
failed:
    c->stream_bad=1;snprintf(err,cap,"experiment TLS read unavailable");return -1;
}
d2k_tls_io d2k_experiment_tls_io(d2k_experiment_channel *channel)
{
    if(!channel || !channel->coverage || channel->tls_owned || channel->stream_bad ||
       channel->covered!=channel->experiment->tls_input_length ||
       channel->stream_next!=channel->experiment->tls_input_length)return (d2k_tls_io){0};
    channel->tls_owned=1;channel->tls_first=1;channel->sealed=1;
    return (d2k_tls_io){channel,stream_read,stream_write};
}
int d2k_experiment_tls_read_observation(const d2k_tls_io *io,d2k_raw_observation *out)
{
    if(out)memset(out,0,sizeof *out);
    if(!io || !out || !io->context || io->read!=stream_read || io->write!=stream_write)return 0;
    const d2k_experiment_channel *c=io->context;
    if(!c->tls_read_observed)return 0;
    *out=c->tls_read_observation;return 1;
}

d2k_experiment_channel *d2k_experiment_open(const d2k_experiment *e,
    d2k_raw_observation *last,char *err,size_t cap)
{
    d2k_experiment_channel *channel;
    if(last) memset(last,0,sizeof(*last));
    if(err && cap) err[0]=0;
    if(!e || !last || !err || !cap || (e->sink && e->make_sink) ||
       (e->sink && (!e->sink->experience || !e->sink->record))) return NULL;
    channel=calloc(1,sizeof(*channel));
    if(!channel) { snprintf(err,cap,"channel allocation failed"); return NULL; }
    if(e->sink)channel->sink=*e->sink;
    if(e->make_sink && (e->make_sink(e->sink_context,&channel->sink) ||
       !channel->sink.experience || !channel->sink.record)) {
        snprintf(err,cap,"experiment identity allocation failed");free(channel);return NULL;
    }
    if(e->tls_input || e->tls_input_length) {
        if(!e->tls_input || !e->tls_input_length || e->tls_input_length>D2K_TRIGGER_MAX) {
            snprintf(err,cap,"invalid controlled TLS input");free(channel);return NULL;
        }
        channel->coverage=calloc(e->tls_input_length,1);
        channel->incoming=malloc(65535);
        if(!channel->coverage || !channel->incoming) {
            snprintf(err,cap,"TLS transcript allocation failed");
            free(channel->coverage);free(channel->incoming);free(channel);return NULL;
        }
    }
    if(e->begin_decode && e->begin_decode(e->decoder_context)) {
        snprintf(err,cap,"experiment decoder initialization failed");
        free(channel->coverage);free(channel->incoming);free(channel); return NULL;
    }
    int64_t started=d2k_now_ms();
    channel->episode=d2k_raw_episode_open(e->ip,e->family,e->port,
        e->connect_ms,e->mark,e->offer_ts,e->cancel,err,cap,last);
    if(channel->episode && channel->sink.record && !d2k_raw_episode_tuple(channel->episode,&channel->tuple)) {
        d2k_raw_episode_free(channel->episode);channel->episode=NULL;last->kind=D2K_RAW_OBS_LOCAL;
    }
    if(stream_event(channel,D2K_RAW_TLS_OPEN,started,channel->episode?0:-1,e->connect_ms,0,last,NULL,0,NULL)) {
        d2k_raw_episode_free(channel->episode);channel->episode=NULL;
        snprintf(err,cap,"experiment OPEN evidence rejected");last->kind=D2K_RAW_OBS_LOCAL;
    }
    if(!channel->episode) { free(channel->coverage);free(channel->incoming);free(channel); return NULL; }
    channel->experiment=e;
    return channel;
}

void d2k_experiment_close(d2k_experiment_channel *channel)
{
    if(!channel) return;
    int64_t started=d2k_now_ms();
    d2k_raw_episode_free(channel->episode);
    d2k_raw_observation closed={0};
    (void)stream_event(channel,D2K_RAW_TLS_CLOSE,started,0,0,channel->stream_next,&closed,NULL,0,NULL);
    free(channel->coverage);free(channel->retained);free(channel->incoming);
    free(channel);
}

int d2k_experiment_last_operation(const d2k_experiment_channel *c,d2k_experiment_operation *op)
{
    if(!c || !op || !c->operation_available)return 0;
    *op=c->last_operation;return 1;
}

static d2k_experiment_status run_word(const d2k_experiment *e,d2k_experiment_channel *channel,
    const size_t *word,size_t n,d2k_sample *samples,size_t *completed,
    d2k_raw_observation *last,char *err,size_t cap)
{
    if(completed) *completed=0;
    if(last) memset(last,0,sizeof *last);
    if(err && cap) err[0]=0;
    if(!e || !completed || !last || !err || !cap ||
       (n && (!word || !samples || (!e->operations && !e->resolve_operation))) ||
       n>SIZE_MAX/sizeof *samples) return D2K_EXPERIMENT_ERROR;
    if(!n) return D2K_EXPERIMENT_COMPLETE;
    memset(samples,0,n*sizeof *samples);
    int need_slice=0;
    d2k_experiment_operation *resolved=NULL;
    size_t *states=NULL,state=channel?channel->operation_state:0;
    if(e->resolve_operation) {
        if(n>SIZE_MAX/sizeof *resolved || n>SIZE_MAX/sizeof *states)goto invalid;
        resolved=calloc(n,sizeof *resolved);states=calloc(n,sizeof *states);
        if(!resolved || !states) {
            free(resolved);free(states);
            snprintf(err,cap,"operation resolution allocation failed");return D2K_EXPERIMENT_ERROR;
        }
    }

    for(size_t i=0;i<n;i++) {
        if(word[i]>=e->operation_count) goto invalid;
        if(resolved) {
            if(e->resolve_operation(e->operation_context,state,word[i],&resolved[i],&states[i])!=1)
                goto invalid;
            state=states[i];
        }
        const d2k_experiment_operation *op=resolved?&resolved[i]:&e->operations[word[i]];

        if(op->kind==D2K_EXPERIMENT_SEND || op->kind==D2K_EXPERIMENT_SEND_SLICE) {
            if(!op->trigger || !op->trigger->len ||
               op->trigger->len>sizeof op->trigger->payload ||
               !op->program || !*op->program) goto invalid;
            if(op->kind==D2K_EXPERIMENT_SEND_SLICE) {
                if(!op->payload_length || op->payload_offset>op->trigger->len ||
                   op->payload_length>op->trigger->len-op->payload_offset)goto invalid;
                need_slice=1;
            }
        } else if(op->kind==D2K_EXPERIMENT_READ) {
            if(!e->reply || !e->decode || !op->minimum ||
               op->minimum>e->reply_capacity || op->timeout_ms<=0 ||
               (channel && channel->coverage && op->minimum>65535)) goto invalid;
        } else if(op->kind==D2K_EXPERIMENT_PACKET) {
            if(channel && channel->sink.record)goto invalid;
            if(!e->reply || !e->reply_capacity || !e->decode_packet || op->timeout_ms<=0) goto invalid;
        } else goto invalid;

    }
    d2k_trigger *slice=need_slice?malloc(sizeof *slice):NULL;
    if(need_slice && !slice){free(resolved);free(states);snprintf(err,cap,"slice buffer allocation failed");return D2K_EXPERIMENT_ERROR;}
    if(!channel && e->begin_decode && e->begin_decode(e->decoder_context)) {
        snprintf(err,cap,"experiment decoder initialization failed");
        free(slice);free(resolved);free(states);
        return D2K_EXPERIMENT_ERROR;
    }
    d2k_raw_episode *ep=channel?channel->episode:d2k_raw_episode_open(e->ip,e->family,e->port,
        e->connect_ms,e->mark,e->offer_ts,e->cancel,err,cap,last);
    if(!ep){free(slice);free(resolved);free(states);return D2K_EXPERIMENT_INCONCLUSIVE;}
    d2k_experiment_status status=D2K_EXPERIMENT_COMPLETE;
    for(size_t i=0;i<n;i++) {
        int terminal=0;
        const d2k_experiment_operation *op=resolved?&resolved[i]:&e->operations[word[i]];
        if(channel) {channel->last_operation=*op;channel->operation_available=1;}

        samples[i].operation=word[i];
        if(op->kind==D2K_EXPERIMENT_SEND || op->kind==D2K_EXPERIMENT_SEND_SLICE) {
            const d2k_trigger *trigger=op->trigger;
            if(op->kind==D2K_EXPERIMENT_SEND_SLICE) {
                *slice=*trigger;
                memmove(slice->payload,trigger->payload+op->payload_offset,op->payload_length);
                slice->len=op->payload_length;
                slice->sni_off=0;slice->sni_len=0;
                if(trigger->sni_off>0 && trigger->sni_len>0 &&
                   (size_t)trigger->sni_off>=op->payload_offset &&
                   (size_t)trigger->sni_off-op->payload_offset<=op->payload_length &&
                   (size_t)trigger->sni_len<=op->payload_length-((size_t)trigger->sni_off-op->payload_offset)) {
                    slice->sni_off=(int)((size_t)trigger->sni_off-op->payload_offset);
                    slice->sni_len=trigger->sni_len;
                }
                trigger=slice;
            }
            int64_t started=d2k_now_ms();
            int sent=d2k_raw_episode_send(ep,op->offset,op->next_offset,trigger,
                op->program,e->cancel,err,cap,last);
            if(stream_event(channel,D2K_RAW_TLS_SEND,started,sent,0,op->offset,last,
                trigger->payload,trigger->len,op->program)) {
                snprintf(err,cap,"experiment SEND evidence rejected");status=D2K_EXPERIMENT_ERROR;break;
            }
            if(sent || !last->sent ||
                !last->program_packets || last->submitted_packets!=last->program_packets) {
                status=D2K_EXPERIMENT_INCONCLUSIVE;break;
            }
            samples[i].observation=0;
            if(channel)channel->stream_next=op->next_offset;
            if(channel && channel->coverage) {
                size_t offset=op->offset,length=trigger->len;
                if(offset>e->tls_input_length || length>e->tls_input_length-offset ||
                   op->next_offset!=offset+length ||
                   memcmp(trigger->payload,e->tls_input+offset,length))channel->stream_bad=1;
                else for(size_t j=offset;j<offset+length;j++)
                    if(!channel->coverage[j]) {channel->coverage[j]=1;channel->covered++;}
                if(!channel->stream_bad && channel->covered==e->tls_input_length)
                    channel->stream_next=(uint32_t)e->tls_input_length;
            }
        } else {
          int64_t now=d2k_now_ms();
          if(now>INT64_MAX-op->timeout_ms){status=D2K_EXPERIMENT_ERROR;break;}
          int64_t deadline=now+op->timeout_ms;
          for(;;) {
            size_t have=0;
            d2k_raw_packet_event event={0};
            int packet=op->kind==D2K_EXPERIMENT_PACKET;
            uint8_t *read_bytes=channel && channel->coverage && !packet?channel->incoming:e->reply;
            size_t read_capacity=read_bytes==e->reply?e->reply_capacity:65535;
            if(d2k_detect_stopped(e->cancel)) {
                last->kind=D2K_RAW_OBS_CANCELLED;
                status=D2K_EXPERIMENT_INCONCLUSIVE;break;
            }
            int64_t remaining=deadline-d2k_now_ms();
            if(remaining>op->timeout_ms)remaining=op->timeout_ms;
            int rc;
            int64_t read_started=d2k_now_ms();
            if(remaining<=0) {
                last->kind=D2K_RAW_OBS_RESPONSE_TIMEOUT;last->response_bytes=0;rc=-1;
            } else rc=packet
                ? d2k_raw_episode_event(ep,(int)remaining,e->cancel,e->reply,
                                       e->reply_capacity,&event,last)
                : d2k_raw_episode_read(ep,(int)remaining,e->cancel,read_bytes,
                                      read_capacity,&have,op->minimum,last);
            if(packet) have=event.payload_len;
            if(!packet && stream_event(channel,D2K_RAW_TLS_READ,read_started,rc,
                remaining>0?(int)remaining:0,channel?channel->stream_next:0,last,read_bytes,have,NULL)) {
                snprintf(err,cap,"experiment READ evidence rejected");status=D2K_EXPERIMENT_ERROR;break;
            }
            if(channel && channel->coverage) {
                if(packet || last->kind==D2K_RAW_OBS_RESPONSE_RESET ||
                   last->kind==D2K_RAW_OBS_RESPONSE_FIN)channel->stream_bad=1;
                if(!packet && have && !channel->stream_bad) {
                    uint8_t *kept=NULL;
                    if(have<=SIZE_MAX-channel->retained_length)
                        kept=realloc(channel->retained,channel->retained_length+have);
                    if(!kept) {channel->stream_bad=1;status=D2K_EXPERIMENT_ERROR;break;}
                    channel->retained=kept;
                    memcpy(kept+channel->retained_length,read_bytes,have);
                    channel->retained_length+=have;
                }
            }

            if(rc && last->kind!=D2K_RAW_OBS_RESPONSE_TIMEOUT &&
                     last->kind!=D2K_RAW_OBS_RESPONSE_RESET &&
                     last->kind!=D2K_RAW_OBS_RESPONSE_FIN) {
                status=D2K_EXPERIMENT_INCONCLUSIVE;break;
            }
            int decoded=packet
                ? e->decode_packet(e->decoder_context,word[i],last,&event,e->reply,have,
                                   &samples[i].observation)
                : e->decode(e->decoder_context,word[i],last,read_bytes,have,
                            &samples[i].observation);

            terminal=decoded==2;
            if(decoded!=1 && !terminal) {
                status=decoded<0?D2K_EXPERIMENT_ERROR:D2K_EXPERIMENT_INCONCLUSIVE;break;
            }
            if(packet || !e->read_to_terminal || terminal || rc ||
               last->kind==D2K_RAW_OBS_RESPONSE_TIMEOUT || last->kind==D2K_RAW_OBS_RESPONSE_RESET ||
               last->kind==D2K_RAW_OBS_RESPONSE_FIN)break;
          }
          if(status!=D2K_EXPERIMENT_COMPLETE)break;
        }
        if(channel && states)channel->operation_state=states[i];
        samples[i].conclusive=1;*completed=i+1;
        if(terminal || last->kind==D2K_RAW_OBS_RESPONSE_RESET || last->kind==D2K_RAW_OBS_RESPONSE_FIN) {
            samples[i].conclusive=D2K_SAMPLE_TERMINAL;
            status=D2K_EXPERIMENT_TERMINAL;break;
        }
    }
    if(!channel) d2k_raw_episode_free(ep);
    free(slice);free(resolved);free(states);
    return status;
invalid:
    free(resolved);free(states);
    snprintf(err,cap,"invalid experiment word or operation");
    return D2K_EXPERIMENT_ERROR;
}

d2k_experiment_status d2k_experiment_run(const d2k_experiment *e,
    const size_t *word,size_t n,d2k_sample *samples,size_t *completed,
    d2k_raw_observation *last,char *err,size_t cap)
{
    if(e && (e->sink || e->make_sink)) {
        if(completed)*completed=0;
        if(last)memset(last,0,sizeof *last);
        if(err && cap)snprintf(err,cap,"observed experiments require an explicit channel");
        return D2K_EXPERIMENT_ERROR;
    }
    return run_word(e,NULL,word,n,samples,completed,last,err,cap);
}

d2k_experiment_status d2k_experiment_continue(d2k_experiment_channel *channel,
    const size_t *word,size_t n,d2k_sample *samples,size_t *completed,
    d2k_raw_observation *last,char *err,size_t cap)
{
    d2k_experiment_status status;
    if(completed) *completed=0;
    if(last) memset(last,0,sizeof(*last));
    if(err && cap) err[0]=0;
    if(channel)channel->operation_available=0;
    if(!channel || channel->sealed) {
        if(err && cap) snprintf(err,cap,"missing or sealed experiment channel");
        return D2K_EXPERIMENT_ERROR;
    }
    status=run_word(channel->experiment,channel,word,n,samples,completed,last,err,cap);
    if(status==D2K_EXPERIMENT_ERROR || status==D2K_EXPERIMENT_INCONCLUSIVE)channel->stream_bad=1;
    if(status!=D2K_EXPERIMENT_COMPLETE) channel->sealed=1;
    return status;
}
