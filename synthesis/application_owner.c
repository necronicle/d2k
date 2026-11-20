#include "application_owner.h"
#include "tls_decode.h"
#include "../core/include/d2k_plantlv.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
struct d2k_application_owner {
    d2k_verification_owner *verification;
    d2k_synthesis_feedback feedback;
    d2k_raw_tuple tuple;
    d2k_raw_transport transport;
    uint8_t remote[16];
    uint64_t experience,ordinal,read_ordinal;
    int64_t finished;
    uint32_t sent;
    int opened,closed,invalid,read,applied,io_failed;
    int scoped;
    uint32_t scope_offset;
    uint32_t after_offset,after_length;
    int after_applied;
    unsigned query_count;
    uint64_t query_raw_ordinal;
    int64_t query_finished;
    int query_terminal;
    unsigned http_count;
    d2k_https_phase http_phase;
    uint64_t http_raw_ordinal;
    uint32_t http_sent;
    uint8_t *http_request;
    size_t http_request_length;
    char *initial_program;
    uint8_t *input;
    size_t input_length;
    d2k_tls_decoder decoder;
    uint64_t first_tls_symbol;
    int first_tls_available;
    d2k_payload_piece *pieces;
    size_t piece_count,piece_at;
};
static const char piece_identity[]=D2K_RAW_TLS_IDENTITY;
static const char stream_identity[]=D2K_RAW_TLS_IDENTITY;
static int recorded_program_matches(const char *wire,const char *declared) {
    if(!wire || !declared)return 0;
    if(!strcmp(wire,declared))return 1;
    const char *id=strstr(wire,"\nid "),*other=strstr(declared,"\nid ");
    if(!id || !other || id-wire!=other-declared || strlen(id)<37 || strlen(other)<37 ||
       memcmp(id+4,"00000000000000000000000000000000\n",33) || other[36]!='\n')return 0;
    return !memcmp(wire,declared,(size_t)(id-wire)+4) && !strcmp(id+36,other+36);
}
d2k_application_owner *d2k_application_owner_recorded(const d2k_synthesis_feedback *id,
    int budget,d2k_raw_tape *t,const uint8_t *input,size_t length)
{
    if(!input || !length || length>D2K_TRIGGER_MAX)return NULL;
    const d2k_raw_tls_event *open=d2k_raw_tape_event(t,0),*event;
    if(!open || open->action!=D2K_RAW_TLS_OPEN || open->result)return NULL;
    size_t count=0;int read=0;
    for(size_t i=1;(event=d2k_raw_tape_event(t,i));i++) {
        if(event->action==D2K_RAW_TLS_SEND) {
            if(read || !event->length || count==length)return NULL;
            count++;
        } else if(event->action==D2K_RAW_TLS_READ)read=1;
        else return NULL;
    }
    if(!count)return NULL;
    if(count==1 && id && id->program) {
        event=d2k_raw_tape_event(t,1);
        if(event && recorded_program_matches(event->program,id->program)) {
            if(event->send_offset || event->length!=length || !event->bytes ||
               memcmp(event->bytes,input,length))return NULL;
            d2k_application_owner *owner=d2k_application_owner_new(id,open->experience,budget);
            if(!owner)return NULL;
            size_t program_length=strlen(event->program);
            owner->initial_program=malloc(program_length+1);
            if(!owner->initial_program){d2k_application_owner_free(owner);return NULL;}
            memcpy(owner->initial_program,event->program,program_length+1);
            d2k_raw_tls_sink sink=d2k_application_owner_sink(owner);
            if(d2k_raw_tape_bind(t,&sink)){d2k_application_owner_free(owner);return NULL;}
            return owner;
        }
    }
    d2k_payload_piece *pieces=malloc(count*sizeof *pieces);if(!pieces)return NULL;
    for(size_t i=0;i<count;i++) {
        event=d2k_raw_tape_event(t,i+1);
        pieces[i]=(d2k_payload_piece){event->send_offset,event->length,0};
    }
    d2k_application_owner *o=d2k_application_owner_partition(id,open->experience,budget,input,length,pieces,count);
    free(pieces);if(!o)return NULL;
    d2k_raw_tls_sink sink=d2k_application_owner_sink(o);
    if(d2k_raw_tape_bind(t,&sink)){d2k_application_owner_free(o);return NULL;}
    return o;
}
d2k_application_owner *d2k_application_owner_partition(const d2k_synthesis_feedback *id,
    uint64_t experience,int budget,const uint8_t *input,size_t length,
    const d2k_payload_piece *pieces,size_t count)
{
    if(!id || !id->program || !input || !length || length>D2K_TRIGGER_MAX ||
       !pieces || !count || count>length)return NULL;
    size_t covered=0;
    for(size_t i=0;i<count;i++) {
        if(pieces[i].offset>length || pieces[i].delay_us || !pieces[i].length ||
           pieces[i].length>length-pieces[i].offset || pieces[i].length>length-covered)return NULL;
        covered+=pieces[i].length;
    }
    if(covered!=length)return NULL;
    char *program=NULL,err[160];
    if(d2k_lower_partition(length,pieces,count,"tls",&program,err,sizeof err)!=D2K_LOWER_OK)return NULL;
    char *label=strstr(program,"\nid ");
    static const char hex[]="0123456789abcdef";
    for(size_t i=0;i<sizeof id->plan_id;i++) {
        label[4+2*i]=hex[id->plan_id[i]>>4];label[5+2*i]=hex[id->plan_id[i]&15];
    }
    int equal=!strcmp(program,id->program);free(program);if(!equal)return NULL;
    d2k_application_owner *o=d2k_application_owner_new(id,experience,budget);
    if(!o)return NULL;
    o->pieces=malloc(count*sizeof *pieces);o->input=malloc(length);
    if(!o->pieces || !o->input){d2k_application_owner_free(o);return NULL;}
    memcpy(o->pieces,pieces,count*sizeof *pieces);o->piece_count=count;
    memcpy(o->input,input,length);o->input_length=length;
    return o;
}
static int tuple_equal(const d2k_raw_tuple *a,const d2k_raw_tuple *b) {
    return a->family==b->family && a->local_port==b->local_port && a->remote_port==b->remote_port &&
        !memcmp(a->local,b->local,16) && !memcmp(a->remote,b->remote,16);
}
static int accept_event(void *ctx,const d2k_raw_tls_event *e) {
    d2k_application_owner *o=ctx;
    if(!o || !e)return -1;
    if(o->invalid || o->closed || e->experience!=o->experience || e->ordinal!=o->ordinal ||
       e->started_ms<o->finished || e->finished_ms<e->started_ms)goto invalid;
    if(!o->ordinal) {
        if(e->action!=D2K_RAW_TLS_OPEN)goto invalid;
        if(e->result) {o->closed=1;goto accepted;}
        if(!e->observation.connected || e->tuple.family!=o->feedback.family ||
           e->tuple.remote_port!=o->feedback.port || !e->tuple.local_port ||
           memcmp(e->tuple.remote,o->remote,o->feedback.family==6?16:4))goto invalid;
        o->tuple=e->tuple;o->opened=1;
        memcpy(o->feedback.flow.a_ip,e->tuple.local,16);
        memcpy(o->feedback.flow.b_ip,e->tuple.remote,16);
        o->feedback.flow.a_port=e->tuple.local_port;o->feedback.flow.b_port=e->tuple.remote_port;
        o->feedback.flow.family=e->tuple.family;o->feedback.flow.transport=6;
    } else {
        uint32_t expected=o->sent;
        if(e->action==D2K_RAW_TLS_SEND && o->pieces && o->piece_at<o->piece_count)
            expected=(uint32_t)o->pieces[o->piece_at].offset;
        if(!o->opened || !tuple_equal(&o->tuple,&e->tuple) || e->send_offset!=expected)goto invalid;
        if(e->action==D2K_RAW_TLS_SEND) {
            if(!e->program || !e->bytes || !e->length || e->length>UINT32_MAX-o->sent)goto invalid;
            if(o->pieces && o->piece_at<o->piece_count) {
                const d2k_payload_piece *piece=&o->pieces[o->piece_at];
                if(e->send_offset!=piece->offset || e->length!=piece->length ||
                   strcmp(e->program,piece_identity) ||
                   memcmp(e->bytes,o->input+piece->offset,piece->length))goto invalid;
            } else {
                const char *expected_program=o->scoped?
                    (o->sent==o->scope_offset?o->feedback.program:stream_identity):
                    (o->sent?(o->after_length && o->sent==o->after_offset?o->feedback.program:stream_identity):
                     (o->initial_program?o->initial_program:o->feedback.program));
                if(o->scoped && o->sent<o->scope_offset && e->length>o->scope_offset-o->sent)goto invalid;
                if(o->after_length && ((o->sent<o->after_offset && e->length>o->after_offset-o->sent) ||
                   (o->sent==o->after_offset && e->length!=o->after_length)))goto invalid;
                if(strcmp(e->program,expected_program))goto invalid;
            }
            if(e->result) {o->feedback.execution_refusal=1;o->io_failed=1;goto accepted;}
            if(!e->observation.sent || !e->observation.program_packets ||
               e->observation.program_packets!=e->observation.submitted_packets)goto invalid;
            if(o->pieces && o->piece_at<o->piece_count) {
                o->piece_at++;o->applied=o->piece_at==o->piece_count;
            } else if(!o->sent) {
                if(e->length>D2K_TRIGGER_MAX)goto invalid;
                o->input=malloc(e->length);if(!o->input)goto invalid;
                memcpy(o->input,e->bytes,e->length);o->input_length=e->length;
                o->applied=!o->scoped || !o->scope_offset;
            }
            if(o->scoped && o->sent==o->scope_offset)o->applied=1;
            if(o->after_length && o->sent==o->after_offset)o->after_applied=1;
            o->sent+=(uint32_t)e->length;
        } else if(e->action==D2K_RAW_TLS_READ) {
            if((!o->applied && !(o->pieces && o->sent) && !(o->scoped && o->input_length)) || (e->length && !e->bytes))goto invalid;
            if(!o->first_tls_available) {
                if(!o->decoder.observer && d2k_tls_decoder_begin(&o->decoder))goto invalid;
                int decoded=d2k_tls_decoder_read(&o->decoder,0,&e->observation,e->bytes,e->length,&o->first_tls_symbol);
                if(decoded<0)goto invalid;
                o->first_tls_available=decoded==2;
            }
            o->read=1;
            o->read_ordinal=o->ordinal+1;
            if(e->result && e->observation.kind!=D2K_RAW_OBS_RESPONSE_FIN &&
               (o->applied || e->observation.kind!=D2K_RAW_OBS_RESPONSE_TIMEOUT))o->io_failed=1;
            if(e->result && e->observation.kind!=D2K_RAW_OBS_RESPONSE_FIN &&
               e->observation.kind!=D2K_RAW_OBS_RESPONSE_TIMEOUT &&
               e->observation.kind!=D2K_RAW_OBS_RESPONSE_RESET)o->feedback.execution_refusal=1;
        } else if(e->action==D2K_RAW_TLS_CLOSE) {
            o->closed=1;
        } else goto invalid;
    }
accepted:
    if(e->action!=D2K_RAW_TLS_CLOSE)o->transport=e->observation.transport;
    o->ordinal++;o->finished=e->finished_ms;return 0;
invalid:
    o->invalid=1;return -1;
}
d2k_application_owner *d2k_application_owner_new(const d2k_synthesis_feedback *id,
    uint64_t experience,int budget) {
    if(!id || !experience)return NULL;
    d2k_application_owner *o=calloc(1,sizeof *o);if(!o)return NULL;
    o->verification=d2k_verification_new(id,budget);
    if(!o->verification){free(o);return NULL;}
    o->feedback=*d2k_verification_identity(o->verification);
    o->feedback.execution_refusal=0;
    if(inet_pton(id->family==6?AF_INET6:AF_INET,id->ip,o->remote)!=1) {
        d2k_application_owner_free(o);return NULL;
    }
    char why[160];uint32_t offset=0;
    o->scoped=d2k_plan_text_stream_offset(o->feedback.program,&offset,why,sizeof why)==1;
    o->scope_offset=offset;
    uint32_t cut=0;
    (void)d2k_plan_text_after_split(o->feedback.program,&o->after_offset,&o->after_length,&cut,why,sizeof why);
    o->experience=experience;return o;
}
void d2k_application_owner_free(d2k_application_owner *o) {
    if(o)free(o->http_request);
    if(o){d2k_verification_free(o->verification);d2k_tls_decoder_free(&o->decoder);free(o->pieces);free(o->input);free(o->initial_program);free(o);}
}
int d2k_application_owner_observe_http(d2k_application_owner *o,uint64_t generation,
    uint64_t experience,const d2k_https_observation *event,d2k_application_http_observation *out) {
    if(out)memset(out,0,sizeof *out);
    if(!o || !event || !out || generation!=o->feedback.generation || experience!=o->experience)return -1;
    if(o->feedback.doh || o->invalid || o->closed || !o->opened || !o->read ||
       (!o->applied && !(o->scoped && o->input_length)) || o->feedback.execution_refusal ||
       o->http_phase==D2K_HTTPS_EXCHANGE_END || !event->ordinal)return 0;
    if(event->phase==D2K_HTTPS_REQUEST_BEGIN) {
        if(o->io_failed || (o->http_phase && o->http_phase!=D2K_HTTPS_REQUEST_SENT) ||
           o->http_count==UINT_MAX || event->ordinal!=o->http_count+1 ||
           (o->http_count && o->ordinal<=o->http_raw_ordinal) ||
           !event->request || !event->request_length || event->request_length>D2K_TRIGGER_MAX || event->response)return 0;
        uint8_t *copy=malloc(event->request_length);if(!copy)return -1;
        memcpy(copy,event->request,event->request_length);
        free(o->http_request);o->http_request=copy;o->http_request_length=event->request_length;
        o->http_count=event->ordinal;o->http_sent=o->sent;
    } else if(event->phase==D2K_HTTPS_REQUEST_SENT) {
        if(o->io_failed || o->http_phase!=D2K_HTTPS_REQUEST_BEGIN || event->ordinal!=o->http_count ||
           o->ordinal<=o->http_raw_ordinal || o->sent<=o->http_sent || !event->request ||
           event->request_length!=o->http_request_length || event->response ||
           memcmp(event->request,o->http_request,event->request_length))return 0;
    } else if(event->phase==D2K_HTTPS_EXCHANGE_END) {
        const d2k_ver_result *r=event->response;
        if(!o->http_phase || event->ordinal!=o->http_count || event->request || event->request_length ||
           !r || r->doh_replies || r->local_refusal || r->local_limit || r->unsupported ||
           (r->body_complete && (o->http_phase!=D2K_HTTPS_REQUEST_SENT || o->io_failed ||
                                o->read_ordinal<=o->http_raw_ordinal)))return 0;
    } else return -1;
    o->http_phase=event->phase;o->http_raw_ordinal=o->ordinal;
    *out=(d2k_application_http_observation){d2k_verification_identity(o->verification),
        o->experience,o->ordinal,o->tuple,o->transport,o->sent,*event};
    return 1;
}
d2k_raw_tls_sink d2k_application_owner_sink(d2k_application_owner *o) {
    return o?(d2k_raw_tls_sink){o->experience,o,accept_event}:(d2k_raw_tls_sink){0};
}
int d2k_application_owner_end(const d2k_application_owner *o,const d2k_ver_result *r,d2k_application_end *end) {
    if(end)memset(end,0,sizeof *end);
    if(!o || !r || !end || !o->closed)return -1;
    int valid=!o->invalid && o->opened && o->applied && o->read &&
        (!o->after_length || o->after_applied) &&
        !o->feedback.execution_refusal && !r->local_refusal && !r->local_limit && !r->unsupported &&
        !(o->io_failed && r->budget==D2K_BUDGET_PASSED);
    *end=(d2k_application_end){d2k_verification_identity(o->verification),o->experience,o->ordinal,
        o->tuple,o->input,o->input_length,o->first_tls_symbol,valid,*r,0,0,o->transport};
    return 0;
}
int d2k_application_owner_observe(d2k_application_owner *o,uint64_t generation,
    uint64_t experience,const d2k_doh_observation *q,d2k_application_observation *out) {
    if(out)memset(out,0,sizeof *out);
    if(!o || !q || !out || generation!=o->feedback.generation || experience!=o->experience)return -1;
    if(o->invalid || o->closed || !o->opened || (!o->applied && !(o->scoped && o->input_length)) || !o->read ||
       o->query_terminal || o->feedback.execution_refusal ||
       o->ordinal<=o->query_raw_ordinal || q->ordinal!=o->query_count+1 ||
       q->ordinal>0x3fffffffU || q->stream_id!=2*q->ordinal-1 ||
       q->started_ms<o->query_finished || q->finished_ms<q->started_ms ||
       q->finished_ms<o->finished || q->response.budget_requests!=q->ordinal ||
       q->response.local_refusal || q->response.local_limit || q->response.unsupported ||
       (q->dns_valid && (o->io_failed || q->timed_out || q->response.status!=200 ||
        !q->response.body_complete || q->response.level!=D2K_VER_APPLICATION)))return 0;
    *out=(d2k_application_observation){d2k_verification_identity(o->verification),
        o->experience,o->ordinal,o->tuple,*q,o->input,o->input_length,o->first_tls_symbol,o->first_tls_available,o->transport};
    o->query_count=q->ordinal;o->query_raw_ordinal=o->ordinal;
    o->query_finished=q->finished_ms;o->query_terminal=!q->dns_valid;
    return 1;
}
d2k_verification_status d2k_application_owner_finish(d2k_application_owner *o,
    uint64_t generation,uint64_t experience,const d2k_ver_result *r) {
    if(!o || !r)return D2K_VF_ERROR;
    if(generation!=o->feedback.generation || experience!=o->experience)return D2K_VF_FOREIGN;
    if(o->invalid || !o->closed || !o->opened || !o->read || !o->applied ||
       (o->after_length && !o->after_applied) ||
       (o->io_failed && r->budget==D2K_BUDGET_PASSED))return D2K_VF_UNKNOWN;
    d2k_synthesis_feedback *f=&o->feedback;
    f->applied=o->applied;f->verification_available=1;f->events_lost=0;
    f->level=r->level;f->status=r->status;f->body_complete=r->body_complete;
    f->local_refusal=r->local_refusal;f->local_limit=r->local_limit;f->unsupported=r->unsupported;
    f->challenge=r->cloudflare_challenge;f->budget=r->budget;f->budget_uncountable=r->budget_uncountable;
    f->body_bytes=r->body_bytes;f->budget_need=r->budget_need;
    f->budget_packets=r->budget_packets;f->budget_requests=r->budget_requests;
    f->doh_replies=r->doh_replies;
    return d2k_verification_accept(o->verification,f);
}
