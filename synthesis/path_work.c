#include "path_work.h"
#include "tls_decode.h"
#include "token_content.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

static int plan_stream_step(void *ctx,size_t state,size_t op,size_t *next)
{
    const d2k_tls_stream *s=ctx;
    /* Current Plan can emit a partition, then observe the reply. Broader
       distinguishing questions still use the unrestricted stream domain. */
    if(op==s->chunks && state<s->trigger->len)return 0;
    d2k_input_domain d=d2k_tls_stream_path_domain(s);
    return d.step?d.step(ctx,state,op,next):-1;
}
static int path_hello(void *ctx,uint64_t symbol)
{
    d2k_tls_response r;int timeout,reset;
    (void)ctx;
    int rc=d2k_tls_symbol_read(symbol,&r,&timeout,&reset);
    return rc<0?-1:rc==1 && r.kind==D2K_TLS_OBS_HELLO && !r.retry && !timeout && !reset && !d2k_tls_symbol_closed(symbol);
}
static int worker_follow(const d2k_path_run *p,d2k_input_domain *domain,size_t *seen,int *probes)
{
    size_t count,next;
    const d2k_path_event *events=d2k_path_run_history(p,&count);
    for(;*seen<count;(*seen)++) {
        size_t op=events[*seen].sample.operation;
        if(op+2==domain->operations && *probes<INT_MAX)(*probes)++;
        if(events[*seen].sample.conclusive!=D2K_SAMPLE_OBSERVED ||
           domain->step(domain->ctx,domain->initial,op,&next)!=1)return -1;
        domain->initial=next;
    }
    return 0;
}
typedef struct {size_t parent,bytes;int rejected;} rejected_prefix;
struct d2k_tls_path_session {
    d2k_tls_application application;
    d2k_vres *application_program;
    d2k_ordered_stream *application_stream;
    d2k_stream_action *actions;
    size_t action_capacity;
    d2k_experiment *application_experiment;
    rejected_prefix *rejections;
    size_t rejection_count;
    d2k_trigger trigger;
    d2k_tls_stream stream;
    d2k_experiment experiment;
    d2k_detect_stop cancel;
    d2k_tls_decoder decoder;
    d2k_tls_decoder response_decoder;
    uint64_t response_symbol;
    int response_only,response_known,response_feedback_pending;
    unsigned response_content_phase;
    d2k_path_run *path;
    d2k_input_domain domain;
    size_t *chunks,whole,seen,input_chunks;
    size_t token_cut,token_witness;
    int token_pending;
    size_t *order_word,order_length,order_witness;
    int order_attempted,order_pending;
    size_t prefix_pending;
    int prefix_observing,initial_prefix;
    uint64_t generation;
    int probes,started,ready,direct;
    d2k_syn_status status;
    size_t program_len;
    char program[sizeof(((d2k_vres *)0)->program)];
    char reason[sizeof(((d2k_vres *)0)->reason)];
};
int d2k_tls_path_session_resumable(const d2k_tls_path_session *w) {return w && w->started && !w->ready;}
int d2k_tls_path_session_probes(const d2k_tls_path_session *w) {return w?w->probes:0;}
d2k_tls_io d2k_tls_path_session_tls_io(d2k_tls_path_session *w)
{
    if(!w || !w->ready || !w->experiment.tls_input ||
       (w->status!=D2K_SYN_CANDIDATE && w->status!=D2K_SYN_DIRECT_RESPONSE))return (d2k_tls_io){0};
    return d2k_path_run_tls_io(w->path);
}
int d2k_tls_path_session_matches(const d2k_tls_path_session *w,const d2k_tls_stream *s,
    const d2k_experiment *e)
{
    if(!w || !s || !e || e->sink || !d2k_tls_stream_domain(s).states)return 0;
    const d2k_trigger *a=&w->trigger,*b=s->trigger;
    const d2k_experiment *old=&w->experiment;
    if(a->len!=b->len || a->sni_off!=b->sni_off || a->sni_len!=b->sni_len ||
       a->accept!=b->accept || a->client_tcp_known!=b->client_tcp_known ||
       a->client_tcp_options_len!=b->client_tcp_options_len ||
       b->client_tcp_options_len>sizeof b->client_tcp_options ||
       memcmp(a->payload,b->payload,a->len) || memcmp(a->name,b->name,sizeof a->name) ||
       memcmp(a->client_tcp_options,b->client_tcp_options,a->client_tcp_options_len))return 0;
    if(w->input_chunks!=s->chunks || w->stream.read_timeout_ms!=s->read_timeout_ms ||
       w->stream.read_minimum!=s->read_minimum ||
       memcmp(w->chunks,s->chunk_bytes,s->chunks*sizeof *s->chunk_bytes))return 0;
    if(old->family!=e->family || old->port!=e->port || old->mark!=e->mark ||
       old->connect_ms!=e->connect_ms || old->offer_ts!=e->offer_ts ||
       old->reply_capacity!=e->reply_capacity || old->make_sink!=e->make_sink ||
       old->sink_context!=e->sink_context || !!old->tls_input!=!!e->tls_input ||
       old->tls_input_length!=e->tls_input_length ||
       (old->tls_input && (!e->tls_input || memcmp(old->tls_input,e->tls_input,old->tls_input_length))) ||
       memcmp(old->ip,e->ip,e->family==6?16:4) || !!old->cancel!=!!e->cancel)return 0;
    return !e->cancel || (old->cancel->fn==e->cancel->fn && old->cancel->ctx==e->cancel->ctx);
}
static size_t rejection_next(const d2k_tls_path_session *w,size_t at,size_t bytes)
{
    if(at==w->rejection_count)return at;
    for(size_t i=1;i<w->rejection_count;i++)
        if(w->rejections[i].parent==at && w->rejections[i].bytes==bytes)return i;
    return w->rejection_count;
}
static size_t current_rejection(const d2k_tls_path_session *w)
{
    size_t count,at=0;
    const d2k_path_event *events=d2k_path_run_history(w->path,&count);
    for(size_t i=0;i<count;i++) {
        size_t op=events[i].sample.operation;
        if(op==w->stream.chunks+1)at=0;
        else if(events[i].operation_available && events[i].operation.kind==D2K_EXPERIMENT_SEND_SLICE)
            at=rejection_next(w,at,events[i].operation.payload_length);
    }
    return at;
}
static int candidate_step(void *ctx,size_t state,size_t op,size_t *next)
{
    d2k_tls_path_session *w=ctx;
    size_t width=w->rejection_count+1,position=state/width,monitor=state%width,after;
    int rc=plan_stream_step(&w->stream,position,op,&after);
    if(rc!=1)return rc;
    if(op>=w->stream.chunks+1)monitor=0;
    else if(op<w->stream.chunks)monitor=rejection_next(w,monitor,after-position);
    *next=after*width+monitor;return 1;
}
static int candidate_preserved(void *ctx,size_t state)
{
    d2k_tls_path_session *w=ctx;
    size_t width=w->rejection_count+1,monitor=state%width;
    int preserved=d2k_tls_stream_path_preserved(&w->stream,state/width);
    return preserved==1 && monitor<w->rejection_count && w->rejections[monitor].rejected?0:preserved;
}
static d2k_input_domain candidate_domain(d2k_tls_path_session *w,size_t position)
{
    d2k_input_domain base=d2k_tls_stream_path_domain(&w->stream);
    size_t width=w->rejection_count+1;
    if(!width || base.states>SIZE_MAX/width)return (d2k_input_domain){0};
    size_t monitor=position==w->stream.trigger->len+1?0:current_rejection(w);
    return (d2k_input_domain){w,base.states*width,position*width+monitor,base.operations,candidate_step};
}
int d2k_tls_path_session_disposition(d2k_tls_path_session *w,uint64_t generation,
    const char *program,d2k_verification_status outcome)
{
    if(w && w->response_only) {
        if(!w->ready || w->status!=D2K_SYN_CANDIDATE ||
           outcome!=D2K_VF_NOT_MET || generation!=w->generation ||
           !program || strcmp(program,w->program))return 0;
        /* The separate verifier did not change the earlier ServerHello.
           Preserve that event and mark the intervening connection as a gap. */
        if(d2k_path_run_interrupt(w->path)!=1)return -1;
        w->response_feedback_pending=1;w->ready=0;return 1;
    }
    if(!w || w->experiment.tls_input || !w->ready || w->status!=D2K_SYN_CANDIDATE ||
       outcome!=D2K_VF_NOT_MET || generation!=w->generation ||
       !program || strcmp(program,w->program))return 0;
    size_t count,start,at=0,total=0,n=w->rejection_count;
    const d2k_path_event *events=d2k_path_run_history(w->path,&count);
    start=count;
    while(start && events[start-1].sample.operation!=w->stream.chunks+1)start--;
    if(!start || count-start>(SIZE_MAX/sizeof(rejected_prefix))-n)return -1;
    rejected_prefix *nodes=malloc((n+count-start)*sizeof *nodes);
    if(!nodes)return -1;
    memcpy(nodes,w->rejections,n*sizeof *nodes);
    for(size_t i=start;i<count;i++) {
        if(!events[i].operation_available || events[i].operation.kind!=D2K_EXPERIMENT_SEND_SLICE)continue;
        size_t bytes=events[i].operation.payload_length,j;
        if(bytes>w->trigger.len-total){free(nodes);return -1;}
        total+=bytes;
        for(j=1;j<n;j++)if(nodes[j].parent==at && nodes[j].bytes==bytes)break;
        if(j==n)nodes[n++]=(rejected_prefix){at,bytes,0};
        at=j;
    }
    if(total!=w->trigger.len || !at){free(nodes);return -1;}
    nodes[at].rejected=1;
    free(w->rejections);w->rejections=nodes;w->rejection_count=n;
    w->ready=0;w->program_len=0;w->program[0]=0;w->direct=0;
    return 1;
}
void d2k_tls_path_session_free(d2k_tls_path_session *w)
{
    if(!w)return;
    d2k_path_run_free(w->path);d2k_tls_decoder_free(&w->decoder);
    d2k_tls_decoder_free(&w->response_decoder);
    if(w->actions)for(size_t i=0;i<w->stream.chunks;i++)
        d2k_stream_prefix_free((d2k_stream_prefix *)w->actions[i].prefix);
    free(w->application_stream);free(w->application_experiment);free(w->actions);free(w->order_word);
    free(w->experiment.reply);free(w->chunks);free(w->rejections);free(w->application_program);free(w);
}
const d2k_path_event *d2k_tls_path_session_history(const d2k_tls_path_session *w,size_t *count)
{ return d2k_path_run_history(w?w->path:NULL,count); }
d2k_tls_path_session *d2k_tls_path_session_new(const d2k_tls_stream *stream,
    const d2k_experiment *base,uint64_t generation)
{
    if(!stream || !base || base->sink || !generation || !d2k_tls_stream_domain(stream).states ||
       !base->reply_capacity || stream->chunks>=SIZE_MAX/sizeof(size_t))return NULL;
    if((base->tls_input || base->tls_input_length) &&
       (!base->tls_input || base->tls_input_length!=stream->trigger->len ||
        memcmp(base->tls_input,stream->trigger->payload,base->tls_input_length)))return NULL;
    d2k_tls_path_session *w=calloc(1,sizeof *w);
    if(!w)return NULL;
    w->rejections=calloc(1,sizeof *w->rejections);
    if(!w->rejections)goto fail;
    w->rejection_count=1;
    w->input_chunks=stream->chunks;w->trigger=*stream->trigger;w->stream=*stream;w->generation=generation;
    w->stream.trigger=&w->trigger;w->whole=SIZE_MAX;
    w->chunks=malloc((stream->chunks+1)*sizeof *w->chunks);
    if(!w->chunks)goto fail;
    memcpy(w->chunks,stream->chunk_bytes,stream->chunks*sizeof *w->chunks);
    for(size_t i=0;i<stream->chunks;i++)if(w->chunks[i]==stream->trigger->len){w->whole=i;break;}
    if(w->whole==SIZE_MAX) {w->whole=w->stream.chunks;w->chunks[w->stream.chunks++]=w->trigger.len;}
    w->stream.chunk_bytes=w->chunks;
    w->experiment=*base;
    if(base->tls_input)w->experiment.tls_input=w->trigger.payload;
    w->experiment.reply=malloc(base->reply_capacity);
    if(!w->experiment.reply)goto fail;
    if(base->cancel) {w->cancel=*base->cancel;w->experiment.cancel=&w->cancel;}
    w->experiment.operations=NULL;w->experiment.operation_count=w->stream.chunks+1;
    w->experiment.operation_context=&w->stream;
    w->experiment.resolve_operation=d2k_tls_stream_operation;
    w->experiment.operation_prefix_equal=NULL;
    w->experiment.decoder_context=&w->decoder;w->experiment.begin_decode=d2k_tls_decoder_begin;
    w->experiment.decode=d2k_tls_decoder_read;w->experiment.decode_packet=NULL;
    w->experiment.read_to_terminal=1;
    w->path=d2k_path_run_new(&w->experiment);if(!w->path)goto fail;
    w->domain=d2k_tls_stream_path_domain(&w->stream);
    return w;
fail:
    d2k_tls_path_session_free(w);return NULL;
}
/* Only the last attempted OPEN can explain this failed measurement. */
static void session_open_timeout(const d2k_tls_path_session *w,d2k_vres *out,
    d2k_syn_status status)
{
    size_t count=0;
    const d2k_path_event *events=d2k_path_run_history(w->path,&count);
    if(status==D2K_SYN_ERROR && count &&
       events[count-1].action.kind==D2K_PATH_ACTION_OPEN &&
       events[count-1].raw.kind==D2K_RAW_OBS_CONNECT_TIMEOUT &&
       !events[count-1].raw.connected) {
        out->verdict=D2K_V_FLAKY;out->dial_deadline=1;
    }
}
static d2k_syn_status session_result(const d2k_tls_path_session *w,d2k_vres *out)
{
    memset(out,0,sizeof *out);out->verdict=D2K_V_INCONCLUSIVE;out->owns_search=1;
    out->probes=w->probes;out->protocol_response=w->direct;
    session_open_timeout(w,out,w->status);
    out->program_len=w->program_len;
    memcpy(out->program,w->program,w->program_len+1);
    if(w->status==D2K_SYN_CANDIDATE)out->synthesis_generation=w->generation;
    snprintf(out->reason,sizeof out->reason,"%s",w->reason);
    return w->status;
}
static int application_prepare(void *ctx,const d2k_path_run *path)
{
    d2k_tls_path_session *w=ctx;
    if(d2k_path_run_tls_input_program(path,&w->trigger,w->generation,w->application_program)!=1)return -1;
    return w->application.prepare(w->application.context,w->application_program->program);
}
static int application_run(void *ctx,const d2k_tls_io *io)
{d2k_tls_path_session *w=ctx;return w->application.run(w->application.context,io);}
static int application_finish(void *ctx,uint64_t *value)
{d2k_tls_path_session *w=ctx;return w->application.finish(w->application.context,value);}
static int application_step(void *ctx,size_t state,size_t op,size_t *next)
{
    d2k_tls_path_session *w=ctx;
    if(op==0 || op==w->stream.chunks+2)return 0;
    d2k_input_domain d=d2k_ordered_stream_domain(w->application_stream);
    return d.step(d.ctx,state,op,next);
}
static int application_preserved(void *ctx,size_t state)
{return d2k_ordered_stream_preserved(((d2k_tls_path_session *)ctx)->application_stream,state);}
static int application_accepted(void *ctx,uint64_t value)
{d2k_tls_path_session *w=ctx;return w->application.accepted(w->application.context,value);}
d2k_tls_path_session *d2k_tls_path_session_new_application(const d2k_tls_stream *stream,
    const d2k_experiment *base,uint64_t generation,const d2k_tls_application *application)
{
    if(!base || !base->tls_input || !application || !application->prepare ||
       !application->run || !application->finish || !application->accepted)return NULL;
    d2k_tls_path_session *w=d2k_tls_path_session_new(stream,base,generation);if(!w)return NULL;
    w->application=*application;w->application_program=calloc(1,sizeof *w->application_program);
    d2k_path_run_free(w->path);w->path=NULL;
    d2k_path_application app={w,application_run,application_finish,application_prepare};
    w->application_stream=malloc(sizeof *w->application_stream);
    w->application_experiment=malloc(sizeof *w->application_experiment);
    if(!w->application_program || !w->application_stream || !w->application_experiment) {
        d2k_tls_path_session_free(w);return NULL;
    }
    w->action_capacity=w->stream.chunks;
    w->actions=calloc(w->action_capacity,sizeof *w->actions);
    if(!w->actions){d2k_tls_path_session_free(w);return NULL;}
    for(size_t i=0;i<w->stream.chunks;i++)w->actions[i]=(d2k_stream_action){.bytes=w->chunks[i]};
    *w->application_stream=(d2k_ordered_stream){&w->trigger,w->actions,w->stream.chunks,w->stream.read_timeout_ms,w->stream.read_minimum};
    *w->application_experiment=w->experiment;
    w->application_experiment->operation_context=w->application_stream;
    w->application_experiment->resolve_operation=d2k_ordered_stream_operation;
    w->application_experiment->operation_prefix_equal=d2k_ordered_stream_prefix_equal;
    w->path=d2k_path_run_new_application(w->application_experiment,&app);
    if(!w->path){d2k_tls_path_session_free(w);return NULL;}
    w->domain=d2k_ordered_stream_domain(w->application_stream);
    w->domain.ctx=w;w->domain.step=application_step;
    return w;
}
static int response_prepare(void *ctx,const char *program)
{
    d2k_tls_path_session *w=ctx;
    (void)program;w->response_known=0;w->response_symbol=0;
    return d2k_tls_decoder_begin(&w->response_decoder);
}
static int response_run(void *ctx,const d2k_tls_io *io)
{
    d2k_tls_path_session *w=ctx;
    char err[160];uint8_t bytes[4096];
    if(!io || !io->write || !io->read ||
       io->write(io->context,w->trigger.payload,w->trigger.len,err,sizeof err))return -1;
    int64_t deadline=d2k_now_ms()+w->stream.read_timeout_ms;
    for(;;) {
        int64_t left=deadline-d2k_now_ms();
        if(left<=0 || d2k_detect_stopped(w->experiment.cancel))return -1;
        int wait=left>INT_MAX?INT_MAX:(int)left;
        long n=io->read(io->context,bytes,sizeof bytes,wait,err,sizeof err);
        d2k_raw_observation observed;
        if(!d2k_experiment_tls_read_observation(io,&observed))return -1;
        int decoded=d2k_tls_decoder_read(&w->response_decoder,0,&observed,
            n>0?bytes:NULL,n>0?(size_t)n:0,&w->response_symbol);
        if(decoded<1)return -1;
        if(decoded==2 || observed.kind==D2K_RAW_OBS_RESPONSE_TIMEOUT) {
            w->response_known=1;return 0;
        }
        if(n<=0)return -1;
    }
}
static int response_finish(void *ctx,uint64_t *symbol)
{
    d2k_tls_path_session *w=ctx;
    *symbol=w->response_symbol;return w->response_known;
}
static int response_question(void *ctx,uint64_t symbol)
{
    d2k_tls_response response;int timeout,reset;
    (void)ctx;
    if(d2k_tls_symbol_read(symbol,&response,&timeout,&reset)!=1)return -1;
    return response.kind==D2K_TLS_OBS_MORE && (timeout || reset || d2k_tls_symbol_closed(symbol))?1:0;
}
d2k_tls_path_session *d2k_tls_path_session_new_response(const d2k_tls_stream *stream,
    const d2k_experiment *base,uint64_t generation)
{
    if(!stream || !stream->trigger || !base)return NULL;
    d2k_experiment owned=*base;
    owned.tls_input=stream->trigger->payload;owned.tls_input_length=stream->trigger->len;
    d2k_tls_application response={NULL,response_prepare,response_run,response_finish,path_hello,response_question};
    d2k_tls_path_session *w=d2k_tls_path_session_new_application(stream,&owned,generation,&response);
    if(w){w->response_only=1;w->application.context=w;}
    return w;
}
static int append_action(d2k_tls_path_session *w,size_t bytes,int reverse,d2k_stream_prefix *prefix)
{
    if(!w || !w->started || !w->application.accepted || w->status!=D2K_SYN_CLOSED ||
       (reverse!=0 && reverse!=1) || !bytes || bytes>w->trigger.len ||
       (w->domain.initial!=2*(w->trigger.len+1)+1 && w->domain.initial!=2*(w->trigger.len+1)))return 0;
    for(size_t i=0;i<w->stream.chunks;i++) {
        const d2k_stream_action *old=&w->actions[i];
        if(old->bytes!=bytes || old->reverse!=reverse || !!old->prefix!=!!prefix)continue;
        if(!prefix || !strcmp(d2k_stream_prefix_program(old->prefix),d2k_stream_prefix_program(prefix)))return 0;
    }
    size_t count=w->stream.chunks,capacity=w->action_capacity;
    size_t *chunks=w->chunks;
    d2k_stream_action *actions=w->actions;
    size_t limit=SIZE_MAX/sizeof *actions;
    if(SIZE_MAX/sizeof *chunks<limit)limit=SIZE_MAX/sizeof *chunks;
    if(count>=limit)return -1;
    d2k_ordered_stream *stream=malloc(sizeof *stream);
    d2k_experiment *experiment=malloc(sizeof *experiment);
    if(!stream || !experiment)goto failed;
    if(count==capacity) {
        capacity=capacity>limit/2?limit:capacity*2;
        chunks=malloc(capacity*sizeof *chunks);
        actions=malloc(capacity*sizeof *actions);
        if(!chunks || !actions)goto failed;
        memcpy(chunks,w->chunks,count*sizeof *chunks);
        memcpy(actions,w->actions,count*sizeof *actions);
    }
    chunks[count]=bytes;
    actions[count]=(d2k_stream_action){.bytes=bytes,.reverse=reverse,.prefix=prefix};
    *stream=*w->application_stream;stream->count++;stream->actions=actions;
    *experiment=*w->application_experiment;
    experiment->operation_count=stream->count+1;experiment->operation_context=stream;
    d2k_path_run *path=d2k_path_run_extend(w->path,experiment);
    if(!path)goto failed;
    d2k_path_run_free(w->path);free(w->application_experiment);free(w->application_stream);
    if(chunks!=w->chunks)free(w->chunks);
    if(actions!=w->actions)free(w->actions);
    w->action_capacity=capacity;
    w->path=path;w->application_experiment=experiment;w->application_stream=stream;
    w->chunks=chunks;w->actions=actions;w->stream.chunks=stream->count;w->stream.chunk_bytes=chunks;
    size_t position=w->domain.initial;
    w->domain=d2k_ordered_stream_domain(w->application_stream);
    w->domain.ctx=w;w->domain.step=application_step;w->domain.initial=position;
    w->ready=0;w->program_len=0;w->program[0]=0;w->reason[0]=0;w->direct=0;
    return 1;
failed:
    if(chunks!=w->chunks)free(chunks);
    if(actions!=w->actions)free(actions);
    free(stream);free(experiment);return -1;
}
int d2k_tls_path_session_add_action(d2k_tls_path_session *w,size_t bytes,int reverse)
{return append_action(w,bytes,reverse,NULL);}
static int initial_prefix(d2k_tls_path_session *w,const uint8_t *bytes,
    size_t length,size_t segment,unsigned mods,const d2k_payload_piece *pieces,size_t count) {
    if(!w || w->started || !w->application.accepted || !w->actions ||
       !w->experiment.offer_ts || w->whole>=w->stream.chunks ||
       w->actions[w->whole].prefix || !bytes || !length || length>UINT16_MAX ||
       !segment || segment>UINT16_MAX || mods>3)return 0;
    d2k_stream_prefix *prefix=pieces?d2k_stream_prefix_partition_new(bytes,length,segment,mods,
        w->trigger.len,pieces,count):d2k_stream_prefix_new(bytes,length,segment,mods);
    if(!prefix)return -1;
    w->actions[w->whole].prefix=prefix;
    w->initial_prefix=1;w->prefix_observing=1;
    return 1;
}
int d2k_tls_path_session_initial_prefix(d2k_tls_path_session *w,const uint8_t *bytes,
    size_t length,size_t segment,unsigned mods) {
    return initial_prefix(w,bytes,length,segment,mods,NULL,0);
}
int d2k_tls_path_session_initial_prefix_partition(d2k_tls_path_session *w,const uint8_t *bytes,
    size_t length,size_t segment,unsigned mods,const d2k_payload_piece *pieces,size_t count) {
    if(!pieces || !count)return 0;
    return initial_prefix(w,bytes,length,segment,mods,pieces,count);
}
int d2k_tls_path_session_add_prefix(d2k_tls_path_session *w,const uint8_t *bytes,
    size_t length,size_t segment,unsigned mods) {
    if(!w || !w->started || !w->application.accepted || w->status!=D2K_SYN_CLOSED ||
       !w->experiment.offer_ts || !bytes || !length || length>UINT16_MAX ||
       !segment || segment>UINT16_MAX || mods>3 || w->prefix_pending)return 0;
    d2k_stream_prefix *prefix=d2k_stream_prefix_new(bytes,length,segment,mods);
    if(!prefix)return -1;
    int rc=append_action(w,w->trigger.len,0,prefix);
    if(rc!=1)d2k_stream_prefix_free(prefix);
    else w->prefix_pending=w->stream.chunks;
    return rc;
}
static int refine_packet_token(d2k_tls_path_session *w)
{
    if(!w->application.token_question || w->token_cut || w->trigger.len<2 ||
       d2k_detect_stopped(w->experiment.cancel))return 0;
    size_t begin=(size_t)w->trigger.sni_off,length=(size_t)w->trigger.sni_len;
    int token_valid=w->trigger.sni_off>=0 && w->trigger.sni_len>=2 &&
        begin<w->trigger.len && length<=w->trigger.len-begin;
    size_t end=begin+length,count,witness=SIZE_MAX,sends=0;
    int whole=0,inside=0,question=0;
    const d2k_path_event *events=d2k_path_run_history(w->path,&count);
    for(size_t i=0;i<count;i++) {
        const d2k_path_event *event=&events[i];
        if(event->sample.conclusive!=D2K_SAMPLE_OBSERVED)return 0;
        if(event->action.kind==D2K_PATH_ACTION_OPEN){sends=0;whole=inside=0;}
        if(event->operation_available && event->operation.kind==D2K_EXPERIMENT_SEND_SLICE) {
            const d2k_experiment_operation *op=&event->operation;
            sends++;
            whole=op->payload_offset==0 && op->payload_length==w->trigger.len;
            inside|=token_valid && op->next_offset>begin && op->next_offset<end;
        }
        if(event->action.kind==D2K_PATH_ACTION_APPLICATION) {
            uint64_t output;int terminal;
            if(!d2k_path_run_output(w->path,event->sample.observation,&output,&terminal) ||
               w->application.accepted(w->application.context,output)!=0)return 0;
            /* A measured interior cut already asked this conditional question.
               Its failure is not a reason to enumerate nearby positions. */
            int kind=w->application.token_question(w->application.context,output);
            if((kind==1 || kind==2) && inside)return 0;
            if(sends==1 && whole && ((kind==1 && token_valid) || kind==2)){witness=i;question=kind;}
        }
    }
    if(witness==SIZE_MAX)return 0;
    /* Conditional parser model: a complete token is required inside one
       segment. Original-byte preservation permits a cut strictly inside it.
       Minimize the largest of the two pieces under that interval constraint.
       This predicts a distinguishing experiment, NOT a guaranteed bypass. */
    size_t cut=question==2 && !token_valid?(w->trigger.len+1)/2:w->trigger.len/2;
    if(token_valid) {
        if(cut<=begin)cut=begin+1;
        if(cut>=end)cut=end-1;
    }
    /* TLS acceptance does not exclude a delayed response to a visible token.
       Keep that hypothesis testable after a late application failure too.
       Without a parsed token, ask the neutral balanced-partition question.
       Neither choice asserts a cause or a successful transformation. */
    int rc=d2k_tls_path_session_add_chunk(w,cut);
    if(rc==1){w->token_cut=cut;w->token_witness=witness;w->token_pending=1;}
    return rc;
}
static int refine_packet_order(d2k_tls_path_session *w)
{
    if(!w->application.token_question || w->order_attempted || d2k_detect_stopped(w->experiment.cancel))return 0;
    size_t count,start=0,pieces=0,covered=0,witness=SIZE_MAX,first=0;
    const d2k_path_event *events=d2k_path_run_history(w->path,&count);
    int eligible=0;
    for(size_t i=0;i<count;i++) {
        const d2k_path_event *e=&events[i];
        if(e->sample.conclusive!=D2K_SAMPLE_OBSERVED)return 0;
        if(e->action.kind==D2K_PATH_ACTION_OPEN){start=i+1;pieces=covered=0;eligible=1;}
        else if(e->operation_available && e->operation.kind==D2K_EXPERIMENT_SEND_SLICE) {
            const d2k_experiment_operation *op=&e->operation;
            if(op->payload_offset!=covered || op->offset!=covered ||
               !op->payload_length || op->payload_length>w->trigger.len-covered ||
               op->next_offset!=covered+op->payload_length)eligible=0;
            if(eligible){covered+=op->payload_length;pieces++;}
        } else if(e->action.kind==D2K_PATH_ACTION_APPLICATION) {
            uint64_t value;int terminal;
            if(!d2k_path_run_output(w->path,e->sample.observation,&value,&terminal))return -1;
            int external_failure=w->response_only && w->response_feedback_pending && i+1==count;
            if(!external_failure && w->application.accepted(w->application.context,value)!=0)return 0;
            int question=external_failure?2:w->application.token_question(w->application.context,value);
            if(question!=1 && question!=2)return 0;
            if(eligible && pieces>1 && covered==w->trigger.len){witness=i;first=start;}
        } else if(e->action.kind!=D2K_PATH_ACTION_CLOSE)eligible=0;
    }
    if(witness==SIZE_MAX)return 0;
    size_t n=0;
    for(size_t i=first;i<witness;i++)if(events[i].operation_available &&
        events[i].operation.kind==D2K_EXPERIMENT_SEND_SLICE)n++;
    if(!n || n>SIZE_MAX/sizeof(size_t))return -1;
    size_t *lengths=malloc(n*sizeof *lengths),*word=malloc(n*sizeof *word);
    if(!lengths || !word){free(lengths);free(word);return -1;}
    size_t at=0;
    for(size_t i=witness;i>first;) {
        const d2k_path_event *e=&events[--i];
        if(e->operation_available && e->operation.kind==D2K_EXPERIMENT_SEND_SLICE)
            lengths[at++]=e->operation.payload_length;
    }
    /* Challenge order invariance with exactly the observed partition. This
       creates a question, not a claim that order caused the earlier failure. */
    for(size_t i=0;i<n;i++) {
        if(d2k_tls_path_session_add_action(w,lengths[i],1)<0){free(lengths);free(word);return -1;}
        size_t j;
        for(j=0;j<w->stream.chunks;j++)if(w->actions[j].reverse && w->actions[j].bytes==lengths[i])break;
        if(j==w->stream.chunks){free(lengths);free(word);return -1;}
        word[i]=j+1;
    }
    free(lengths);w->order_word=word;w->order_length=n;w->order_witness=witness;
    w->order_attempted=1;w->order_pending=1;w->ready=0;return 1;
}
static int refine_prefix_partition(d2k_tls_path_session *w)
{
    if(!w->application.token_question || d2k_detect_stopped(w->experiment.cancel))return 0;
    size_t count,start=0,pieces=0,covered=0,first=0,last=0;
    int eligible=0;const char *prefix_program=NULL;
    const d2k_path_event *events=d2k_path_run_history(w->path,&count);
    if(!count || events[count-1].action.kind!=D2K_PATH_ACTION_APPLICATION)return 0;
    for(size_t i=0;i<count;i++) {
        const d2k_path_event *e=&events[i];
        if(e->sample.conclusive!=D2K_SAMPLE_OBSERVED)return 0;
        if(e->action.kind==D2K_PATH_ACTION_OPEN) {
            start=i+1;pieces=covered=0;eligible=1;prefix_program=NULL;
        } else if(e->operation_available && e->operation.kind==D2K_EXPERIMENT_SEND_SLICE) {
            const d2k_experiment_operation *op=&e->operation;
            if(!op->payload_length || op->payload_offset>w->trigger.len ||
               op->payload_length>w->trigger.len-op->payload_offset ||
               op->payload_length>w->trigger.len-covered)eligible=0;
            if(eligible){pieces++;covered+=op->payload_length;}
        } else if(e->operation_available && e->operation.kind==D2K_EXPERIMENT_SEND) {
            eligible=0;
            if(e->operation.tls_prefix)prefix_program=e->operation.program;
        } else if(e->action.kind==D2K_PATH_ACTION_APPLICATION) {
            uint64_t value;int terminal;
            if(!d2k_path_run_output(w->path,e->sample.observation,&value,&terminal))return -1;
            if(w->application.accepted(w->application.context,value)!=0)return 0;
            int question=w->application.token_question(w->application.context,value);
            if(question!=1 && question!=2)return 0;
            if(eligible && pieces>1 && covered==w->trigger.len){first=start;last=i;}
        } else if(e->action.kind!=D2K_PATH_ACTION_CLOSE)eligible=0;
    }
    if(!last || !prefix_program)return 0;
    uint8_t *bytes=NULL;size_t length=0,segment=0;unsigned mods=0;char err[160];
    d2k_lower_status decoded=d2k_lower_tls_prefix_read(prefix_program,&bytes,&length,&segment,&mods,err,sizeof err);
    if(decoded!=D2K_LOWER_OK)return decoded==D2K_LOWER_ERROR?-1:0;
    size_t n=0;
    for(size_t i=first;i<last;i++)if(events[i].operation_available &&
        events[i].operation.kind==D2K_EXPERIMENT_SEND_SLICE)n++;
    if(n>SIZE_MAX/sizeof(d2k_payload_piece)){free(bytes);return -1;}
    d2k_payload_piece *partition=calloc(n,sizeof *partition);
    if(!partition){free(bytes);return -1;}
    size_t at=0;
    for(size_t i=first;i<last;i++)if(events[i].operation_available &&
        events[i].operation.kind==D2K_EXPERIMENT_SEND_SLICE) {
        const d2k_experiment_operation *op=&events[i].operation;
        partition[at++]=(d2k_payload_piece){op->payload_offset,op->payload_length,0};
    }
    /* Two owned failures do not prove compositional failure. Challenge that
       assumption by retaining the observed partition and prefix bytes together.
       The compiler rechecks coverage; only a new application result can accept it. */
    d2k_stream_prefix *prefix=d2k_stream_prefix_partition_new(bytes,length,segment,mods,
        w->trigger.len,partition,n);
    free(partition);free(bytes);
    if(!prefix)return -1;
    int rc=append_action(w,w->trigger.len,0,prefix);
    if(rc!=1)d2k_stream_prefix_free(prefix);
    else w->prefix_pending=w->stream.chunks;
    return rc;
}
static int refine_response_content(d2k_tls_path_session *w)
{
    if(!w->response_only || !w->experiment.offer_ts || w->response_content_phase>=2 ||
       !w->response_known || response_question(w,w->response_symbol)!=1 ||
       d2k_detect_stopped(w->experiment.cancel))return 0;
    uint8_t *masked=malloc(w->trigger.len);if(!masked)return -1;
    int changed=d2k_token_content_question(&w->trigger,masked,w->trigger.len);
    if(changed!=1){free(masked);return changed;}
    size_t segment=d2k_raw_segment_max();if(segment>w->trigger.len)segment=w->trigger.len;
    int added=0;
    while(!added && w->response_content_phase<2) {
        unsigned phase=w->response_content_phase++;
        /* Keep the timestamp envelope and original bytes constant. First
           question the envelope, then vary only the parsed name in its copy. */
        added=d2k_tls_path_session_add_prefix(w,phase?masked:w->trigger.payload,
            w->trigger.len,segment,0);
    }
    free(masked);return added;
}
static int application_follow(d2k_tls_path_session *w)
{
    size_t count,next;const d2k_path_event *events=d2k_path_run_history(w->path,&count);
    for(;w->seen<count;w->seen++) {
        size_t op=events[w->seen].sample.operation;
        if(op==w->stream.chunks+1 && w->probes<INT_MAX)w->probes++;
        if(events[w->seen].sample.conclusive!=D2K_SAMPLE_OBSERVED ||
           w->domain.step(w,w->domain.initial,op,&next)!=1)return -1;
        w->domain.initial=next;
    }
    return 0;
}
static d2k_syn_status application_next(d2k_tls_path_session *w,d2k_vres *out)
{
    d2k_syn_status result=D2K_SYN_ERROR;char err[200]={0};
    if(!w->started) {
        w->started=1;
        size_t bootstrap[]={w->stream.chunks+1,w->whole+1};
        for(size_t i=0;i<2;i++) {
            if(d2k_detect_stopped(w->experiment.cancel))goto done;
            int rc=d2k_path_run_step(w->path,bootstrap[i],err,sizeof err);
            if(application_follow(w) || rc!=1)goto done;
        }
    }
    if(w->response_only && w->token_pending) {
        size_t cut=0;
        while(cut<w->stream.chunks &&
              (w->actions[cut].reverse || w->actions[cut].prefix || w->actions[cut].bytes!=w->token_cut))cut++;
        if(cut==w->stream.chunks)goto done;
        /* Execute the inferred two-piece question directly. Replaying the
           known failing whole input adds no evidence about this boundary. */
        size_t question[]={w->stream.chunks+1,cut+1,w->whole+1};
        for(size_t i=0;i<3;i++) {
            if(d2k_detect_stopped(w->experiment.cancel))goto done;
            int rc=d2k_path_run_step(w->path,question[i],err,sizeof err);
            if(application_follow(w) || rc!=1)goto done;
        }
    }
    if(w->order_pending) {
        int rc=d2k_path_run_step(w->path,w->stream.chunks+1,err,sizeof err);
        if(application_follow(w) || rc!=1)goto done;
        for(size_t i=0;i<w->order_length;i++) {
            if(d2k_detect_stopped(w->experiment.cancel))goto done;
            rc=d2k_path_run_step(w->path,w->order_word[i],err,sizeof err);
            if(application_follow(w) || rc!=1)goto done;
        }
    }
    if(w->prefix_pending) {
        /* The caller supplied this concrete refinement question. Execute it
           before exploring unrelated undefined edges of the rebuilt model.
           OPEN remains an observed action, never a remote-state reset. */
        int rc=d2k_path_run_step(w->path,w->stream.chunks+1,err,sizeof err);
        if(application_follow(w) || rc!=1)goto done;
        if(d2k_detect_stopped(w->experiment.cancel))goto done;
        rc=d2k_path_run_step(w->path,w->prefix_pending,err,sizeof err);
        if(application_follow(w) || rc!=1)goto done;
        w->prefix_pending=0;w->prefix_observing=1;
    }
    for(;;) {
        if(d2k_detect_stopped(w->experiment.cancel))goto done;
        if(w->domain.initial==w->trigger.len || w->domain.initial==2*w->trigger.len+1) {
            int rc=d2k_path_run_step(w->path,w->stream.chunks+3,err,sizeof err);
            if(application_follow(w) || rc!=1)goto done;
        }
        size_t count;const d2k_path_event *events=d2k_path_run_history(w->path,&count);
        if(count && events[count-1].sample.operation==w->stream.chunks+3) {
            uint64_t symbol;int terminal;
            if(!d2k_path_run_output(w->path,events[count-1].sample.observation,&symbol,&terminal))goto done;
            int accepted=application_accepted(w,symbol);
            if(accepted<0 || accepted>1)goto done;
            if(accepted) {
                w->prefix_observing=0;
                w->token_pending=0;w->order_pending=0;
                *out=*w->application_program;
                result=w->probes==1 && !w->initial_prefix?D2K_SYN_DIRECT_RESPONSE:D2K_SYN_CANDIDATE;
                if(result==D2K_SYN_DIRECT_RESPONSE) {
                    out->program_len=0;out->program[0]=0;out->synthesis_generation=0;out->protocol_response=1;
                }
                snprintf(out->reason,sizeof out->reason,"%s",w->response_only?
                    "наблюдён ServerHello; требуется отдельная проверка приложения":
                    "наблюдён успех приложения в измерительном потоке");goto done;
            }
            if(w->response_only && w->probes==1 && !w->initial_prefix) {
                result=D2K_SYN_CLOSED;
                snprintf(err,sizeof err,"исходный TLS-ответ измерен; требуется различающий вопрос");
                goto done;
            }
            if(w->prefix_observing) {
                w->prefix_observing=0;result=D2K_SYN_CLOSED;
                snprintf(err,sizeof err,"измеренный вопрос с префиксом не дал успеха приложения");goto done;
            }
            if(w->order_pending) {
                w->order_pending=0;result=D2K_SYN_CLOSED;
                snprintf(err,sizeof err,"обратный порядок измеренных частей не дал успеха приложения");goto done;
            }
            if(w->token_pending && count-1>w->token_witness) {
                for(size_t i=count-1;i>0;) {
                    const d2k_path_event *event=&events[--i];
                    if(event->action.kind==D2K_PATH_ACTION_OPEN)break;
                    if(event->operation_available && event->operation.kind==D2K_EXPERIMENT_SEND_SLICE &&
                       event->operation.next_offset==w->token_cut) {
                        result=D2K_SYN_CLOSED;
                        w->token_pending=0;
                        snprintf(err,sizeof err,"опыт с новой границей пакетов не дал успеха приложения");
                        goto done;
                    }
                }
            }
        }
        d2k_synthesis_contract contract={w->domain,application_preserved,w,application_accepted};
        d2k_path_trial trial=d2k_path_run_trial(w->path,&contract,err,sizeof err);
        if(application_follow(w) || trial.status==D2K_TRIAL_ERROR || trial.status==D2K_TRIAL_UNCERTAIN)goto done;
        if(trial.status==D2K_TRIAL_NO_PATH) {
            size_t chosen;d2k_path_progress progress=d2k_path_run_advance(w->path,&w->domain,&chosen,err,sizeof err);
            if(application_follow(w))goto done;
            if(progress==D2K_PATH_NO_QUESTION) {
                if(w->domain.initial==0) {
                    /* Release an idle local connection before changing its
                       immutable operation schema. Keep the actual CLOSE in
                       chronology; no remote-state reset is implied. */
                    size_t after,closed_count;
                    d2k_input_domain local=d2k_ordered_stream_domain(w->application_stream);
                    if(local.step(local.ctx,0,w->stream.chunks+2,&after)!=1 ||
                       d2k_path_run_step(w->path,w->stream.chunks+2,err,sizeof err)!=1)goto done;
                    d2k_path_run_history(w->path,&closed_count);
                    if(closed_count!=w->seen+1)goto done;
                    w->seen=closed_count;w->domain.initial=after;
                }
                result=D2K_SYN_CLOSED;goto done;
            }
            if(progress!=D2K_PATH_ADVANCED)goto done;
        }
    }
done:
    out->probes=w->probes;out->verdict=D2K_V_INCONCLUSIVE;out->owns_search=1;
    if(result==D2K_SYN_ERROR || result==D2K_SYN_CLOSED) {
        out->program_len=0;out->program[0]=0;out->synthesis_generation=0;out->protocol_response=0;
        session_open_timeout(w,out,result);
        snprintf(out->reason,sizeof out->reason,"прикладной синтез: %s",err[0]?err:
            result==D2K_SYN_CLOSED?"нет нового вопроса в текущей модели":"отмена или неопределённый опыт");
    }
    w->ready=1;w->status=result;w->direct=out->protocol_response;
    w->program_len=out->program_len;memcpy(w->program,out->program,out->program_len+1);
    snprintf(w->reason,sizeof w->reason,"%s",out->reason);return result;
}
d2k_syn_status d2k_tls_path_session_next(d2k_tls_path_session *w,d2k_vres *out)
{
    if(!out)return D2K_SYN_ERROR;
    memset(out,0,sizeof *out);out->verdict=D2K_V_INCONCLUSIVE;out->owns_search=1;
    if(!w)return D2K_SYN_ERROR;
    if(w->ready)return session_result(w,out);
    if(w->response_feedback_pending) {
        w->status=D2K_SYN_CLOSED;
        int refined=refine_packet_order(w);
        w->response_feedback_pending=0;
        w->program_len=0;w->program[0]=0;w->direct=0;
        if(refined<=0) {
            w->ready=1;w->status=refined<0?D2K_SYN_ERROR:D2K_SYN_CLOSED;
            snprintf(w->reason,sizeof w->reason,"проверка приложения отвергла кандидат; %s",
                refined<0?"ошибка построения различающего опыта":"нет нового вопроса в текущей модели");
            return session_result(w,out);
        }
    }
    if(w->application.accepted) {
        for(;;) {
            d2k_syn_status result=application_next(w,out);
            if(result!=D2K_SYN_CLOSED)return result;
            int refined=refine_prefix_partition(w);
            if(!refined)refined=refine_packet_token(w);
            if(!refined)refined=refine_packet_order(w);
            if(!refined)refined=refine_response_content(w);
            if(!refined)return result;
            if(refined<0) {
                w->status=D2K_SYN_ERROR;
                snprintf(w->reason,sizeof w->reason,"не удалось расширить модель для различающего опыта");
                return session_result(w,out);
            }
        }
    }
    d2k_syn_status result=D2K_SYN_ERROR;
    d2k_tls_stream s=w->stream;
    d2k_experiment e=w->experiment;
    d2k_path_run *path=w->path;
    d2k_input_domain domain=w->domain;
    uint64_t generation=w->generation;
    size_t seen=w->seen,whole=w->whole;
    int probes=w->probes,candidate;
    char err[200]={0};
    if(d2k_detect_stopped(e.cancel)) {
        snprintf(err,sizeof err,"measurement cancelled before IO");goto done;
    }
    if(!w->started) {
        w->started=1;
    size_t bootstrap[]={s.chunks+1,whole,s.chunks};
    for(size_t i=0;i<3;i++) {
        if(d2k_detect_stopped(e.cancel)) {
            snprintf(err,sizeof err,"continuous measurement cancelled");goto done;
        }
        int rc=d2k_path_run_step(path,bootstrap[i],err,sizeof err);
        int followed=worker_follow(path,&domain,&seen,&probes);
        if(rc!=1 || followed)goto done;
    }
    candidate=d2k_path_run_tls_candidate(path,s.trigger,generation,out);
    if(candidate<0)goto done;
    if(candidate==1) {
        /* This was the unchanged original submission, not a synthesized fix. */
        out->program_len=0;out->program[0]=0;out->synthesis_generation=0;
        out->protocol_response=1;result=D2K_SYN_DIRECT_RESPONSE;
        snprintf(out->reason,sizeof out->reason,"прямой TLS-префикс; требуется проверка приложения");
        goto done;
    }
    if(d2k_path_run_step(path,s.chunks+2,err,sizeof err)!=1 ||
       worker_follow(path,&domain,&seen,&probes))goto done;
    }
    for(;;) {
        if(d2k_detect_stopped(e.cancel)) {
            snprintf(err,sizeof err,"continuous measurement cancelled");goto done;
        }
        d2k_synthesis_contract contract={candidate_domain(w,domain.initial),candidate_preserved,NULL,path_hello};
        d2k_path_trial trial=d2k_path_run_trial(path,&contract,err,sizeof err);
        if(worker_follow(path,&domain,&seen,&probes))goto done;
        if(trial.status==D2K_TRIAL_ERROR || trial.status==D2K_TRIAL_UNCERTAIN)goto done;
        if(trial.status==D2K_TRIAL_NO_PATH) {
            size_t chosen;
            d2k_path_progress progress=d2k_path_run_advance(path,&domain,&chosen,err,sizeof err);
            if(worker_follow(path,&domain,&seen,&probes))goto done;
            if(progress==D2K_PATH_NO_QUESTION) {
                result=D2K_SYN_CLOSED;
                snprintf(out->reason,sizeof out->reason,"нет нового вопроса в текущей модели и алфавите");
                goto done;
            }
            if(progress!=D2K_PATH_ADVANCED)goto done;
        }
        /* Successful local submissions do not answer a network question.
           Once the original message is complete, observe the peer before
           allowing model-predicted failure to close this experiment. */
        if(domain.initial==s.trigger->len) {
            size_t sent_count;
            const d2k_path_event *sent=d2k_path_run_history(path,&sent_count);
            if(sent_count && sent[sent_count-1].sample.operation<s.chunks) {
                int read=d2k_path_run_step(path,s.chunks,err,sizeof err);
                int followed=worker_follow(path,&domain,&seen,&probes);
                if(read!=1 || followed)goto done;
            }
        }
        candidate=d2k_path_run_tls_candidate(path,s.trigger,generation,out);
        if(candidate<0)goto done;
        if(candidate==1) {
            size_t monitor=current_rejection(w);
            if(monitor==w->rejection_count || !w->rejections[monitor].rejected) {
                result=D2K_SYN_CANDIDATE;goto done;
            }
            out->program_len=0;out->program[0]=0;out->synthesis_generation=0;
        }

        size_t count;
        const d2k_path_event *events=d2k_path_run_history(path,&count);
        /* A completed reply experiment retains its evidence. Start another
           connection explicitly instead of retrying an unlowerable episode. */
        if(count && events[count-1].sample.operation==s.chunks) {
            if(d2k_path_run_step(path,s.chunks+2,err,sizeof err)!=1 ||
               worker_follow(path,&domain,&seen,&probes))goto done;
        }
    }
done:
    if(!e.tls_input && (result==D2K_SYN_CANDIDATE || result==D2K_SYN_DIRECT_RESPONSE)) {
        /* Retain evidence, not an idle raw socket, while the application trial
           runs on its separate connection. CLOSE is part of the history. */
        if(d2k_path_run_step(path,s.chunks+2,err,sizeof err)!=1 ||
           worker_follow(path,&domain,&seen,&probes))result=D2K_SYN_ERROR;
        if(result!=D2K_SYN_ERROR && d2k_path_run_interrupt(path)!=1)
            result=D2K_SYN_ERROR;
    }
    out->probes=probes;
    if(result==D2K_SYN_ERROR) {
        out->program_len=0;out->program[0]=0;out->synthesis_generation=0;out->protocol_response=0;
        session_open_timeout(w,out,result);
        snprintf(out->reason,sizeof out->reason,"синтез не завершён: %.170s",err[0]?err:"локальная ошибка или неопределённый опыт");
    }
    w->seen=seen;w->probes=probes;w->domain=domain;
    w->ready=1;w->status=result;w->direct=out->protocol_response;
    w->program_len=out->program_len;memcpy(w->program,out->program,out->program_len+1);
    snprintf(w->reason,sizeof w->reason,"%s",out->reason);
    return result;
}
d2k_syn_status d2k_tls_path_work(const d2k_tls_stream *stream,const d2k_experiment *base,
    uint64_t generation,d2k_vres *out)
{
    d2k_tls_path_session *w=d2k_tls_path_session_new(stream,base,generation);
    d2k_syn_status result=d2k_tls_path_session_next(w,out);
    d2k_tls_path_session_free(w);return result;
}

int d2k_tls_path_session_add_chunk(d2k_tls_path_session *w,size_t bytes) {return d2k_tls_path_session_add_action(w,bytes,0);}
