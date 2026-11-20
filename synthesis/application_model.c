#include "application_model.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
typedef struct {
    d2k_application_http_observation observation;
    uint8_t request[];
} http_record;
struct d2k_application_model {
    d2k_application_kind kind;
    d2k_verification_owner *identity;
    uint64_t experience;
    uint8_t remote[16];
    d2k_application_observation *history;
    d2k_sample *samples;
    size_t count;
    http_record **http;
    size_t http_count,http_capacity;
    d2k_hypothesis *hypothesis;
    d2k_transducer current;
    uint8_t *input;
    size_t input_length;
    d2k_application_end end;
    int finished;
};
static int identity_equal(const d2k_synthesis_feedback *a,const d2k_synthesis_feedback *b) {
    if(!a || !b || !a->target || !a->ip || !a->program || !a->resource)return 0;
    return a->generation==b->generation && a->search_id==b->search_id &&
        a->port==b->port && a->family==b->family && a->transport==b->transport &&
        a->shape==b->shape && a->by_addr==b->by_addr && a->doh==b->doh &&
        !strcmp(a->target,b->target) && !strcmp(a->ip,b->ip) &&
        !strcmp(a->program,b->program) && !strcmp(a->resource,b->resource) &&
        !memcmp(a->plan_id,b->plan_id,sizeof a->plan_id) &&
        !memcmp(a->trial_id,b->trial_id,sizeof a->trial_id);
}
static int tuple_equal(const d2k_raw_tuple *a,const d2k_raw_tuple *b) {
    return a->family==b->family && a->local_port==b->local_port && a->remote_port==b->remote_port &&
        !memcmp(a->local,b->local,16) && !memcmp(a->remote,b->remote,16);
}
static int http_result_equal(const d2k_ver_result *a,const d2k_ver_result *b) {
#define SAME(field) if(a->field!=b->field)return 0
    SAME(level);SAME(status);SAME(body_bytes);SAME(body_expected);SAME(body_complete);
    SAME(body_has_length);SAME(body_chunked);SAME(body_framing_valid);SAME(body_encoding);
    SAME(rx_tls_wire_bytes);SAME(rx_tls_record_missing);SAME(negotiated_tls);
    SAME(cloudflare_challenge);SAME(http_outcome);SAME(local_refusal);SAME(local_limit);SAME(unsupported);
#undef SAME
    return memchr(a->location,0,sizeof a->location) && memchr(b->location,0,sizeof b->location) &&
        !strcmp(a->location,b->location);
}
static d2k_application_model *model_new(const d2k_synthesis_feedback *id,uint64_t experience,
    d2k_application_kind kind) {
    if(!id || !experience || (kind==D2K_APPLICATION_DOH && !id->doh) ||
       (kind==D2K_APPLICATION_HTTPS && (id->doh || id->by_addr)))return NULL;
    d2k_application_model *m=calloc(1,sizeof *m);if(!m)return NULL;
    m->identity=d2k_verification_new(id,1);
    if(!m->identity || inet_pton(id->family==6?AF_INET6:AF_INET,id->ip,m->remote)!=1) {
        d2k_application_model_free(m);return NULL;
    }
    m->experience=experience;m->kind=kind;return m;
}
d2k_application_model *d2k_application_model_new(const d2k_synthesis_feedback *id,uint64_t experience) {
    return model_new(id,experience,D2K_APPLICATION_DOH);
}
d2k_application_model *d2k_application_model_new_https(const d2k_synthesis_feedback *id,uint64_t experience) {
    return model_new(id,experience,D2K_APPLICATION_HTTPS);
}
d2k_application_kind d2k_application_model_kind(const d2k_application_model *m) {
    return m?m->kind:D2K_APPLICATION_INVALID;
}
void d2k_application_model_free(d2k_application_model *m) {
    if(!m)return;
    d2k_verification_free(m->identity);d2k_hypothesis_free(m->hypothesis);
    for(size_t i=0;i<m->http_count;i++){free((void *)m->http[i]->observation.event.response);free(m->http[i]);}
    free(m->http);free(m->samples);free(m->history);free(m->input);free(m);
}
size_t d2k_application_model_http_count(const d2k_application_model *m) {return m?m->http_count:0;}
const d2k_application_http_observation *d2k_application_model_http_at(const d2k_application_model *m,size_t i) {
    return m && i<m->http_count?&m->http[i]->observation:NULL;
}
d2k_application_update d2k_application_model_add_http(d2k_application_model *m,const d2k_application_http_observation *o) {
    if(!m || !o)return D2K_APP_ERROR;
    if(m->finished || m->kind!=D2K_APPLICATION_HTTPS)return D2K_APP_REJECTED;
    const d2k_synthesis_feedback *id=d2k_verification_identity(m->identity);
    const d2k_https_observation *e=&o->event;
    if(!identity_equal(id,o->identity) || o->experience!=m->experience || !o->raw_ordinal ||
       o->tuple.family!=id->family || o->tuple.remote_port!=id->port || !o->tuple.local_port ||
       memcmp(o->tuple.remote,m->remote,id->family==6?16:4) || !e->ordinal ||
       e->request_length>D2K_TRIGGER_MAX)return D2K_APP_REJECTED;
    const d2k_application_http_observation *prev=m->http_count?&m->http[m->http_count-1]->observation:NULL;
    if(prev && (!tuple_equal(&prev->tuple,&o->tuple) || o->raw_ordinal<prev->raw_ordinal ||
       o->sent_bytes<prev->sent_bytes || prev->event.phase==D2K_HTTPS_EXCHANGE_END))return D2K_APP_REJECTED;
    if(e->phase==D2K_HTTPS_REQUEST_BEGIN) {
        if(!e->request || !e->request_length || e->response ||
           (!prev && e->ordinal!=1) || (prev && (prev->event.phase!=D2K_HTTPS_REQUEST_SENT ||
           prev->event.ordinal==UINT32_MAX || e->ordinal!=prev->event.ordinal+1 ||
           o->raw_ordinal<=prev->raw_ordinal)))return D2K_APP_REJECTED;
    } else if(e->phase==D2K_HTTPS_REQUEST_SENT) {
        if(!prev || prev->event.phase!=D2K_HTTPS_REQUEST_BEGIN || e->ordinal!=prev->event.ordinal ||
           o->raw_ordinal<=prev->raw_ordinal || o->sent_bytes<=prev->sent_bytes ||
           !e->request || e->response || e->request_length!=prev->event.request_length ||
           memcmp(e->request,prev->event.request,e->request_length))return D2K_APP_REJECTED;
    } else if(e->phase==D2K_HTTPS_EXCHANGE_END) {
        const d2k_ver_result *r=e->response;
        if(!prev || e->ordinal!=prev->event.ordinal || e->request || e->request_length || !r ||
           r->doh_replies || r->local_refusal || r->local_limit || r->unsupported ||
           (r->body_complete && (prev->event.phase!=D2K_HTTPS_REQUEST_SENT ||
                                o->raw_ordinal<=prev->raw_ordinal)))return D2K_APP_REJECTED;
    } else return D2K_APP_REJECTED;
    if(m->http_count==m->http_capacity) {
        size_t cap=m->http_capacity?m->http_capacity*2:4;
        if(cap<m->http_capacity || cap>SIZE_MAX/sizeof *m->http)return D2K_APP_ERROR;
        http_record **records=realloc(m->http,cap*sizeof *records);if(!records)return D2K_APP_ERROR;
        m->http=records;m->http_capacity=cap;
    }
    if(e->request_length>SIZE_MAX-sizeof(http_record))return D2K_APP_ERROR;
    http_record *record=calloc(1,sizeof *record+e->request_length);if(!record)return D2K_APP_ERROR;
    record->observation=*o;record->observation.identity=id;
    if(e->request_length){memcpy(record->request,e->request,e->request_length);record->observation.event.request=record->request;}
    if(e->response) {
        d2k_ver_result *copy=malloc(sizeof *copy);
        if(!copy){free(record);return D2K_APP_ERROR;}
        *copy=*e->response;record->observation.event.response=copy;
    }
    m->http[m->http_count++]=record;return D2K_APP_UNPREDICTED;
}
d2k_application_update d2k_application_model_add(d2k_application_model *m,const d2k_application_observation *o) {
    if(!m || !o)return D2K_APP_ERROR;
    if(m->finished || m->kind!=D2K_APPLICATION_DOH)return D2K_APP_REJECTED;
    const d2k_synthesis_feedback *id=d2k_verification_identity(m->identity);
    const d2k_doh_observation *q=&o->query;const d2k_ver_result *r=&q->response;
    if(!o->input || !o->input_length || o->input_length>D2K_TRIGGER_MAX ||
       (m->count && (m->input_length!=o->input_length || memcmp(m->input,o->input,o->input_length))) ||
       !identity_equal(o->identity,id) || o->experience!=m->experience ||
       o->tuple.family!=id->family || o->tuple.remote_port!=id->port || !o->tuple.local_port ||
       memcmp(o->tuple.remote,m->remote,id->family==6?16:4) || !o->raw_ordinal ||
       q->ordinal!=m->count+1 || q->ordinal>0x3fffffffU || q->stream_id!=2*q->ordinal-1 ||
       q->query_schema!=D2K_DOH_QUERY_SCHEMA_V1 || q->timeout_ms<=0 ||
       r->budget_requests!=q->ordinal || q->finished_ms<q->started_ms ||
       r->local_refusal || r->local_limit || r->unsupported ||
       (q->dns_valid && (q->timed_out || r->status!=200 || !r->body_complete || r->level!=D2K_VER_APPLICATION)))
        return D2K_APP_REJECTED;
    if(m->count) {
        const d2k_application_observation *prev=&m->history[m->count-1];
        if(!prev->query.dns_valid || !tuple_equal(&prev->tuple,&o->tuple) ||
           o->first_tls_available!=prev->first_tls_available ||
           (o->first_tls_available && o->first_tls_symbol!=prev->first_tls_symbol) ||
           q->timeout_ms!=prev->query.timeout_ms || q->query_schema!=prev->query.query_schema ||
           o->raw_ordinal<=prev->raw_ordinal || q->started_ms<prev->query.finished_ms)return D2K_APP_REJECTED;
    }
    uint64_t symbol=q->dns_valid?D2K_APP_REPLY_DNS:q->timed_out?D2K_APP_REPLY_TIMEOUT:
        !r->body_complete?D2K_APP_REPLY_INCOMPLETE:r->status==200?D2K_APP_REPLY_INVALID_DNS:
        D2K_APP_REPLY_HTTP+(unsigned)r->status;
    d2k_application_update update=D2K_APP_UNPREDICTED;
    if(m->hypothesis) {
        d2k_transition t={0};int rc=m->current.step(m->current.ctx,m->current.initial,0,&t);
        if(rc<0)return D2K_APP_ERROR;
        if(rc)update=t.observation==symbol?D2K_APP_MATCH:D2K_APP_COUNTEREXAMPLE;
    }
    size_t n=m->count+1;
    size_t prefix=o->first_tls_available?1:0;
    if(!n || n>SIZE_MAX-prefix || n>SIZE_MAX/sizeof(*m->history) || n+prefix>SIZE_MAX/sizeof(*m->samples))return D2K_APP_ERROR;
    d2k_application_observation *history=malloc(n*sizeof *history);
    d2k_sample *samples=malloc((n+prefix)*sizeof *samples);
    if(!history || !samples){free(history);free(samples);return D2K_APP_ERROR;}
    if(m->count){memcpy(history,m->history,m->count*sizeof *history);memcpy(samples,m->samples,(m->count+prefix)*sizeof *samples);}
    else if(prefix)samples[0]=(d2k_sample){1,o->first_tls_symbol,D2K_SAMPLE_OBSERVED};
    history[m->count]=*o;history[m->count].identity=id;
    samples[m->count+prefix]=(d2k_sample){0,symbol,D2K_SAMPLE_OBSERVED};
    d2k_hypothesis *h=NULL;d2k_transducer current;
    if(d2k_continuous_build(samples,n+prefix,3,&h,&current)!=1) {
        free(history);free(samples);return D2K_APP_ERROR;
    }
    if(!m->count) {
        m->input=malloc(o->input_length);
        if(!m->input){d2k_hypothesis_free(h);free(history);free(samples);return D2K_APP_ERROR;}
        memcpy(m->input,o->input,o->input_length);m->input_length=o->input_length;
    }
    history[m->count].input=m->input;history[m->count].input_length=m->input_length;
    free(m->history);free(m->samples);d2k_hypothesis_free(m->hypothesis);
    m->history=history;m->samples=samples;m->count=n;m->hypothesis=h;m->current=current;
    return update;
}
const d2k_application_observation *d2k_application_model_history(const d2k_application_model *m,size_t *n) {
    if(n)*n=m?m->count:0;
    return m?m->history:NULL;
}
d2k_transducer d2k_application_model_transducer(d2k_application_model *m) {
    return m && m->hypothesis?d2k_hypothesis_model(m->hypothesis):(d2k_transducer){0};
}
int d2k_application_model_finish(d2k_application_model *m,const d2k_application_end *end) {
    if(!m || !end || m->finished || end->experience!=m->experience ||
       !identity_equal(end->identity,d2k_verification_identity(m->identity)))return -1;
    if(m->kind==D2K_APPLICATION_HTTPS && end->result.doh_replies)return -1;
    if(m->http_count) {
        const d2k_application_http_observation *last=&m->http[m->http_count-1]->observation;
        if(!tuple_equal(&end->tuple,&last->tuple) || end->raw_ordinal<=last->raw_ordinal ||
           (end->network_evidence && end->result.body_complete && last->event.phase!=D2K_HTTPS_EXCHANGE_END))return -1;
        if(end->network_evidence && last->event.response &&
           !http_result_equal(last->event.response,&end->result))return -1;
    }
    if(end->input_length>D2K_TRIGGER_MAX || (end->input_length && !end->input))return -1;
    const d2k_synthesis_feedback *id=d2k_verification_identity(m->identity);
    if(end->network_evidence && (!end->input_length || !end->raw_ordinal ||
       end->tuple.family!=id->family || end->tuple.remote_port!=id->port || !end->tuple.local_port ||
       memcmp(end->tuple.remote,m->remote,id->family==6?16:4) ||
       end->result.local_refusal || end->result.local_limit || end->result.unsupported))return -1;
    if(m->count && (end->input_length!=m->input_length || memcmp(end->input,m->input,m->input_length) ||
       !tuple_equal(&end->tuple,&m->history[m->count-1].tuple) ||
       end->raw_ordinal<=m->history[m->count-1].raw_ordinal))return -1;
    uint8_t *input=NULL;
    if(!m->count && end->input_length) {
        input=malloc(end->input_length);if(!input)return -1;
        memcpy(input,end->input,end->input_length);
    }
    d2k_sample *samples=NULL;d2k_hypothesis *hypothesis=NULL;
    if(end->network_evidence) {
        size_t prefix=m->count?(m->history[0].first_tls_available?1:0):(end->first_tls_symbol?1:0);
        size_t progress=m->kind==D2K_APPLICATION_HTTPS;
        d2k_application_http_interval interval={0};
        d2k_application_model snapshot=*m;snapshot.end=*end;snapshot.finished=1;
        size_t transport=progress && d2k_application_model_http_interval(&snapshot,&interval) &&
            (interval.ack || interval.receipt);
        if(m->count>SIZE_MAX-prefix-progress-transport-1 ||
           m->count+prefix+progress+transport+1>SIZE_MAX/sizeof *samples) {free(input);return -1;}
        size_t total=m->count+prefix+progress+transport+1;
        samples=malloc(total*sizeof *samples);
        if(!samples){free(input);return -1;}
        if(m->count)memcpy(samples,m->samples,(m->count+prefix)*sizeof *samples);
        else if(prefix)samples[0]=(d2k_sample){1,end->first_tls_symbol,D2K_SAMPLE_OBSERVED};
        if(progress)samples[total-2-transport]=(d2k_sample){3,end->result.body_bytes,D2K_SAMPLE_OBSERVED};
        if(transport)samples[total-2]=(d2k_sample){4,
            interval.ack|((uint64_t)interval.receipt<<2),D2K_SAMPLE_OBSERVED};
        uint64_t symbol=(uint64_t)(uint32_t)end->result.level<<32 |
            (uint64_t)(uint32_t)end->result.status<<8 | !!end->result.body_complete;
        samples[total-1]=(d2k_sample){2,symbol,D2K_SAMPLE_TERMINAL};
        static const char context[]="one owned application experiment/v1";
        d2k_evidence *e=d2k_evidence_new(context,sizeof context,transport?5:progress?4:3);
        int ok=e && d2k_evidence_add(e,context,sizeof context,samples,total)==D2K_EVIDENCE_OK &&
            d2k_evidence_generalize(e,&hypothesis)==1;
        d2k_evidence_free(e);
        if(!ok){d2k_hypothesis_free(hypothesis);free(samples);free(input);return -1;}
    }
    if(input){m->input=input;m->input_length=end->input_length;}
    if(hypothesis) {
        free(m->samples);d2k_hypothesis_free(m->hypothesis);
        m->samples=samples;m->hypothesis=hypothesis;m->current=d2k_hypothesis_model(hypothesis);
    }
    m->end=*end;m->end.identity=d2k_verification_identity(m->identity);
    m->end.input=m->input;m->end.input_length=m->input_length;
    m->finished=1;
    return 0;
}
const d2k_application_end *d2k_application_model_end(const d2k_application_model *m) {
    return m && m->finished?&m->end:NULL;
}
int d2k_application_model_http_interval(const d2k_application_model *m,
    d2k_application_http_interval *out) {
    if(!out)return 0;
    memset(out,0,sizeof *out);
    const d2k_application_end *end=d2k_application_model_end(m);
    if(!end || m->kind!=D2K_APPLICATION_HTTPS || m->http_count<3 ||
       !end->network_evidence || end->result.body_complete || end->result.local_refusal ||
       end->result.local_limit || end->result.unsupported)return 0;
    const d2k_application_http_observation *begin=&m->http[m->http_count-3]->observation;
    const d2k_application_http_observation *sent=&m->http[m->http_count-2]->observation;
    const d2k_application_http_observation *finish=&m->http[m->http_count-1]->observation;
    if(begin->event.phase!=D2K_HTTPS_REQUEST_BEGIN || sent->event.phase!=D2K_HTTPS_REQUEST_SENT ||
       finish->event.phase!=D2K_HTTPS_EXCHANGE_END ||
       begin->event.ordinal!=sent->event.ordinal || sent->event.ordinal!=finish->event.ordinal ||
       !finish->event.response || finish->event.response->body_complete ||
       begin->sent_bytes<end->input_length || sent->sent_bytes<=begin->sent_bytes ||
       sent->sent_bytes>=UINT32_C(0x80000000) || finish->sent_bytes!=sent->sent_bytes ||
       finish->raw_ordinal<=sent->raw_ordinal)return 0;
    out->ordinal=finish->event.ordinal;out->offset=begin->sent_bytes;
    out->length=sent->sent_bytes-begin->sent_bytes;
    const d2k_raw_transport *a=&begin->transport,*b=&finish->transport;
    if(a->available && b->available && a->sent_end==begin->sent_bytes &&
       b->sent_end==finish->sent_bytes) {
        if(b->received_payload_bytes>=a->received_payload_bytes)
            out->receipt=b->received_payload_bytes==a->received_payload_bytes?1:2;
        if(a->ack_seen && b->ack_seen && a->acked_end<=a->sent_end &&
           b->acked_end<=b->sent_end && b->acked_end>=a->acked_end) {
            out->acked_bytes=b->acked_end>out->offset?b->acked_end-out->offset:0;
            out->ack=!out->acked_bytes?1:out->acked_bytes==out->length?3:2;
        }
    }
    return 1;
}
static uint64_t failed_ack_coverage(const d2k_application_observation *o) {
    unsigned coverage=o->query.dns_valid?0:d2k_application_ack_coverage(&o->transport);
    return coverage==2?D2K_APP_ACK_COVERED:coverage==1?D2K_APP_ACK_OUTSTANDING:0;
}
d2k_application_question d2k_application_model_question(const d2k_application_model *reference,
    const d2k_application_model *trial) {
    d2k_application_question q={D2K_APP_QUESTION_CONTEXT,0,0,0};
    if(!reference || !trial || reference->kind!=trial->kind ||
       reference->experience==trial->experience)return q;
    const d2k_synthesis_feedback *a=d2k_verification_identity(reference->identity);
    const d2k_synthesis_feedback *b=d2k_verification_identity(trial->identity);
    if(!memcmp(a->trial_id,b->trial_id,sizeof a->trial_id) ||
       a->generation!=b->generation || a->search_id!=b->search_id ||
       a->family!=b->family || a->port!=b->port || a->transport!=b->transport ||
       a->shape!=b->shape || a->by_addr!=b->by_addr || a->doh!=b->doh ||
       strcmp(a->ip,b->ip) || strcmp(a->target,b->target) || strcmp(a->resource,b->resource))return q;
    if(reference->kind==D2K_APPLICATION_HTTPS) {
        size_t shared=reference->http_count<trial->http_count?reference->http_count:trial->http_count;
        for(size_t i=0;i<shared;i++) {
            const d2k_https_observation *left=&reference->http[i]->observation.event;
            const d2k_https_observation *right=&trial->http[i]->observation.event;
            if(left->phase==D2K_HTTPS_EXCHANGE_END || right->phase==D2K_HTTPS_EXCHANGE_END)break;
            if(left->phase!=right->phase || left->ordinal!=right->ordinal ||
               left->request_length!=right->request_length ||
               memcmp(left->request,right->request,left->request_length))return q;
        }
    }
    if(!reference->count && reference->finished && reference->end.network_evidence &&
       reference->end.timeout_ms>0 && reference->end.result.level<D2K_VER_APPLICATION &&
       !reference->end.result.body_complete) {
        if((trial->count || trial->finished) && (reference->input_length!=trial->input_length ||
           memcmp(reference->input,trial->input,reference->input_length)))return q;
        q.reference=(uint64_t)(uint32_t)reference->end.result.level<<32 |
            (uint64_t)(uint32_t)reference->end.result.status<<8 | !!reference->end.result.body_complete;
        if(trial->count) {
            if(trial->history[0].query.timeout_ms!=reference->end.timeout_ms)return q;
            q.status=D2K_APP_CHANGED;q.ordinal=1;
            q.observed=trial->samples[trial->history[0].first_tls_available?1:0].observation;return q;
        }
        if(trial->finished) {
            if(trial->end.timeout_ms!=reference->end.timeout_ms || trial->end.hello_wire!=reference->end.hello_wire)return q;
            if(!trial->end.network_evidence){q.status=D2K_APP_TRIAL_ENDED;return q;}
            q.observed=(uint64_t)(uint32_t)trial->end.result.level<<32 |
                (uint64_t)(uint32_t)trial->end.result.status<<8 | !!trial->end.result.body_complete;
            if(reference->kind==D2K_APPLICATION_HTTPS && q.reference==q.observed &&
               reference->end.result.body_bytes!=trial->end.result.body_bytes) {
                q.reference=reference->end.result.body_bytes;
                q.observed=trial->end.result.body_bytes;
                q.status=D2K_APP_CHANGED;return q;
            }
            q.status=q.reference==q.observed && reference->end.first_tls_symbol==trial->end.first_tls_symbol?
                D2K_APP_REPRODUCED:D2K_APP_CHANGED;
            if(q.status==D2K_APP_REPRODUCED && reference->kind==D2K_APPLICATION_HTTPS) {
                d2k_application_http_interval left,right;
                if(d2k_application_model_http_interval(reference,&left) &&
                   d2k_application_model_http_interval(trial,&right) &&
                   left.ordinal==right.ordinal && left.offset==right.offset && left.length==right.length) {
                    if(left.ack && right.ack && left.ack!=right.ack) {
                        q.status=D2K_APP_CHANGED;q.ordinal=left.ordinal;
                        q.reference=D2K_APP_QUERY_ACK|left.ack;
                        q.observed=D2K_APP_QUERY_ACK|right.ack;
                    } else if(left.receipt && right.receipt && left.receipt!=right.receipt) {
                        q.status=D2K_APP_CHANGED;q.ordinal=left.ordinal;
                        q.reference=left.receipt==1?D2K_APP_RX_SILENT:D2K_APP_RX_PAYLOAD;
                        q.observed=right.receipt==1?D2K_APP_RX_SILENT:D2K_APP_RX_PAYLOAD;
                    }
                }
            }
            return q;
        }
        q.status=D2K_APP_ASK_SESSION;return q;
    }
    if(!reference->count || reference->history[reference->count-1].query.dns_valid) {
        q.status=D2K_APP_NO_WITNESS;return q;
    }
    if((trial->count || trial->finished) && (reference->input_length!=trial->input_length ||
        memcmp(reference->input,trial->input,reference->input_length)))return q;
    if(trial->finished && trial->end.network_evidence &&
       (trial->end.timeout_ms!=reference->history[0].query.timeout_ms ||
        (reference->finished && reference->end.hello_wire!=trial->end.hello_wire)))return q;
    size_t lp=reference->history[0].first_tls_available?1:0;
    size_t rp=trial->count && trial->history[0].first_tls_available?1:0;
    if(trial->count && lp!=rp)return q;
    if(trial->count &&
       (reference->history[0].query.query_schema!=trial->history[0].query.query_schema ||
        reference->history[0].query.timeout_ms!=trial->history[0].query.timeout_ms))return q;
    if(trial->count && lp && reference->samples[0].observation!=trial->samples[0].observation) {
        q.status=D2K_APP_CHANGED;q.reference=reference->samples[0].observation;
        q.observed=trial->samples[0].observation;return q;
    }
    for(size_t i=0;i<trial->count && i<reference->count;i++) {
        const d2k_doh_observation *left=&reference->history[i].query,*right=&trial->history[i].query;
        if(left->query_schema!=right->query_schema || left->timeout_ms!=right->timeout_ms)return q;
        if(reference->samples[i+lp].observation!=trial->samples[i+rp].observation) {
            q.status=D2K_APP_CHANGED;q.ordinal=(unsigned)i+1;
            q.reference=reference->samples[i+lp].observation;q.observed=trial->samples[i+rp].observation;return q;
        }
    }
    /* Compare response progress and transport after the prefix/context matched.
       Missing legacy telemetry is not evidence of different network behavior. */
    for(size_t i=0;i<trial->count && i<reference->count;i++) {
        unsigned body_left=d2k_application_response_progress(&reference->history[i].query.response);
        unsigned body_right=d2k_application_response_progress(&trial->history[i].query.response);
        if(body_left && body_right && body_left!=body_right) {
            q.status=D2K_APP_CHANGED;q.ordinal=(unsigned)i+1;
            q.reference=D2K_APP_HTTP_PROGRESS|body_left;q.observed=D2K_APP_HTTP_PROGRESS|body_right;return q;
        }
        uint64_t left=failed_ack_coverage(&reference->history[i]);
        uint64_t right=failed_ack_coverage(&trial->history[i]);
        if(left && right && left!=right) {
            q.status=D2K_APP_CHANGED;q.ordinal=(unsigned)i+1;
            q.reference=left;q.observed=right;return q;
        }
        unsigned rx_left=d2k_application_payload_receipt(reference->history,i+1);
        unsigned rx_right=d2k_application_payload_receipt(trial->history,i+1);
        if(rx_left && rx_right && rx_left!=rx_right) {
            q.status=D2K_APP_CHANGED;q.ordinal=(unsigned)i+1;
            q.reference=rx_left==1?D2K_APP_RX_SILENT:D2K_APP_RX_PAYLOAD;
            q.observed=rx_right==1?D2K_APP_RX_SILENT:D2K_APP_RX_PAYLOAD;return q;
        }
        unsigned ack_left=d2k_application_query_ack(reference->history,i+1);
        unsigned ack_right=d2k_application_query_ack(trial->history,i+1);
        if(ack_left && ack_right && ack_left!=ack_right) {
            q.status=D2K_APP_CHANGED;q.ordinal=(unsigned)i+1;
            q.reference=D2K_APP_QUERY_ACK|ack_left;
            q.observed=D2K_APP_QUERY_ACK|ack_right;return q;
        }
    }
    if(trial->count>=reference->count) {
        q.status=D2K_APP_REPRODUCED;q.ordinal=(unsigned)reference->count;
        q.reference=reference->samples[reference->count-1+lp].observation;q.observed=q.reference;return q;
    }
    q.status=trial->finished?D2K_APP_TRIAL_ENDED:D2K_APP_ASK_QUERY;q.ordinal=(unsigned)trial->count+1;
    q.reference=reference->samples[trial->count+lp].observation;return q;
}
