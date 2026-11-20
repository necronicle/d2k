#include "application_archive.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {FILE *file;int reading;uint64_t hash;unsigned version;} codec;
static int archive_proposal(FILE *,const d2k_synthesis_feedback *,int,size_t,
    unsigned,const d2k_inference_control *,d2k_application_model **,int);
int d2k_application_archive_transfer_proposal(FILE *f,const d2k_synthesis_feedback *target,
    int timeout,size_t wire,unsigned depth,const d2k_inference_control *control,
    d2k_application_model **out) {
    return archive_proposal(f,target,timeout,wire,depth,control,out,1);
}
int d2k_application_archive_proposal(FILE *f,const d2k_synthesis_feedback *target,
    int timeout,size_t wire,unsigned depth,const d2k_inference_control *control,
    d2k_application_model **out) {
    return archive_proposal(f,target,timeout,wire,depth,control,out,0);
}
static int archive_proposal(FILE *f,const d2k_synthesis_feedback *target,
    int timeout,size_t wire,unsigned depth,const d2k_inference_control *control,
    d2k_application_model **out,int transfer) {
    if(!out)return -1;
    *out=NULL;
    if(!f || ferror(f) || !target || !target->target || !target->ip ||
       !target->resource || !depth || timeout<=0 || !wire)return -1;
    fpos_t position;
    if(fgetpos(f,&position) || fseek(f,0,SEEK_SET))return -1;
    d2k_application_model *best=NULL,*record=NULL;
    int rc=0,stopped=0;
    for(;;) {
        if(d2k_inference_stopped(control)){stopped=1;break;}
        rc=d2k_application_archive_read(f,&record);
        if(rc!=1)break;
        const d2k_application_end *e=d2k_application_model_end(record);
        const d2k_synthesis_feedback *id=e?e->identity:NULL;
        size_t count=0;
        const d2k_application_observation *q=d2k_application_model_history(record,&count);
        int eligible=id && e->network_evidence &&
            e->timeout_ms==timeout && (transfer || e->hello_wire==wire) &&
            id->family==target->family && id->port==target->port &&
            id->transport==target->transport && id->shape==target->shape &&
            id->by_addr==target->by_addr && id->doh==target->doh &&
            !strcmp(id->target,target->target) && !strcmp(id->ip,target->ip) &&
            !strcmp(id->resource,target->resource) &&
            e->result.level==D2K_VER_APPLICATION && e->result.status==200 &&
            e->result.body_complete && !e->result.local_refusal &&
            !e->result.local_limit && !e->result.unsupported;
        if(eligible && target->doh) {
            eligible=d2k_application_model_kind(record)==D2K_APPLICATION_DOH && count>=depth &&
                e->result.doh_replies==count && e->result.budget_requests==count;
        } else if(eligible) {
            size_t http_count=d2k_application_model_http_count(record);
            const d2k_application_http_observation *last=http_count?
                d2k_application_model_http_at(record,http_count-1):NULL;
            eligible=d2k_application_model_kind(record)==D2K_APPLICATION_HTTPS && depth==1 &&
                !count && !e->result.doh_replies && http_count>=3 && last &&
                last->event.phase==D2K_HTTPS_EXCHANGE_END && last->event.response &&
                last->event.response->body_complete && last->event.response->status==200 &&
                last->event.response->body_bytes==e->result.body_bytes;
        }
        for(size_t i=0;eligible && target->doh && i<count;i++) {
            if(d2k_inference_stopped(control)){stopped=1;eligible=0;break;}
            eligible=q[i].query.dns_valid && !q[i].query.timed_out &&
                q[i].query.timeout_ms==timeout && q[i].query.response.status==200 &&
                q[i].query.response.body_complete && q[i].query.response.doh_replies==i+1;
        }
        if(eligible){d2k_application_model_free(best);best=record;record=NULL;}
        d2k_application_model_free(record);record=NULL;
        if(stopped)break;
    }
    if(fsetpos(f,&position))rc=-1;
    if(rc<0 || stopped){d2k_application_model_free(best);return rc<0?-1:0;}
    *out=best;return best?1:0;
}
int d2k_application_archive_contrast(FILE *f,const d2k_application_model *failed,
    unsigned depth,d2k_application_model **out) {
    if(!out)return -1;
    *out=NULL;
    const d2k_application_end *base=d2k_application_model_end(failed);
    size_t failures=0;
    const d2k_application_observation *history=d2k_application_model_history(failed,&failures);
    if(!f || ferror(f) || !base || !base->network_evidence || !depth ||
       base->result.local_refusal || base->result.local_limit || base->result.unsupported ||
       base->timeout_ms<=0 || depth<failures ||
       (failures?history[failures-1].query.dns_valid:
        base->result.body_complete || base->result.level>=D2K_VER_APPLICATION))return -1;
    fpos_t position;
    if(fgetpos(f,&position) || fseek(f,0,SEEK_SET))return -1;
    d2k_application_model *best=NULL,*record=NULL;int rc;
    while((rc=d2k_application_archive_read(f,&record))==1) {
        const d2k_application_end *e=d2k_application_model_end(record);
        size_t count=0;
        const d2k_application_observation *queries=d2k_application_model_history(record,&count);
        int eligible=e && e->network_evidence && count>=depth &&
            e->timeout_ms==base->timeout_ms && e->hello_wire==base->hello_wire &&
            e->result.level==D2K_VER_APPLICATION && e->result.status==200 &&
            e->result.body_complete && e->result.doh_replies==count &&
            e->result.budget_requests==count && !e->result.local_refusal &&
            !e->result.local_limit && !e->result.unsupported;
        for(size_t i=0;eligible && i<count;i++)
            eligible=queries[i].query.dns_valid && !queries[i].query.timed_out &&
                queries[i].query.timeout_ms==base->timeout_ms &&
                queries[i].query.response.doh_replies==i+1;
        if(eligible && d2k_application_model_question(failed,record).status==D2K_APP_CHANGED) {
            d2k_application_model_free(best);best=record;record=NULL;
        }
        d2k_application_model_free(record);record=NULL;
    }
    if(fsetpos(f,&position))rc=-1;
    if(rc<0){d2k_application_model_free(best);return -1;}
    *out=best;return best?1:0;
}
int d2k_application_archive_witness(FILE *f,const d2k_application_witness_context *c,
    d2k_application_model **out) {
    if(!out)return -1;
    *out=NULL;
    if(!f || ferror(f) || !c || !c->trial || !c->input || !c->input_length ||
       c->input_length>D2K_TRIGGER_MAX || c->timeout_ms<=0)return -1;
    size_t used=0;d2k_application_model_history(c->trial,&used);
    if(used || d2k_application_model_end(c->trial))return -1;
    fpos_t position;
    if(fgetpos(f,&position) || fseek(f,0,SEEK_SET))return -1;
    d2k_application_model *best=NULL,*record=NULL;size_t depth=0;
    int rc;
    while((rc=d2k_application_archive_read(f,&record))==1) {
        const d2k_application_end *e=d2k_application_model_end(record);
        size_t count=0;
        const d2k_application_observation *history=d2k_application_model_history(record,&count);
        if(e && e->network_evidence && !e->result.local_refusal &&
           !e->result.local_limit && !e->result.unsupported &&
           (!count || history[0].query.timeout_ms==c->timeout_ms) &&
           e->timeout_ms==c->timeout_ms && e->hello_wire==c->hello_wire &&
           e->input_length==c->input_length && !memcmp(e->input,c->input,c->input_length)) {
            d2k_application_question q=d2k_application_model_question(record,c->trial);
            if((q.status==D2K_APP_ASK_QUERY || q.status==D2K_APP_ASK_SESSION) &&
               (!best || count>=depth)) {
                d2k_application_model_free(best);best=record;record=NULL;depth=count;
            }
        }
        d2k_application_model_free(record);record=NULL;
    }
    if(fsetpos(f,&position))rc=-1;
    if(rc<0){d2k_application_model_free(best);return -1;}
    *out=best;return best?1:0;
}
static int bytes(codec *c,void *p,size_t n) {
    if(!n)return 1;
    if(!p)return 0;
    if((c->reading?fread(p,1,n,c->file):fwrite(p,1,n,c->file))!=n)return 0;
    const uint8_t *b=p;
    for(size_t i=0;i<n;i++){c->hash^=b[i];c->hash*=UINT64_C(1099511628211);}
    return 1;
}
static int number(codec *c,uint64_t *v) {
    uint8_t b[8];
    if(!c->reading)for(unsigned i=0;i<8;i++)b[i]=(uint8_t)(*v>>(8*i));
    if(!bytes(c,b,sizeof b))return 0;
    if(c->reading){*v=0;for(unsigned i=0;i<8;i++)*v|=(uint64_t)b[i]<<(8*i);}
    return 1;
}
static int signed_number(codec *c,int64_t *v) {
    uint64_t n=(uint64_t)*v;
    if(!number(c,&n))return 0;
    if(c->reading)*v=n>INT64_MAX?-1-(int64_t)(UINT64_MAX-n):(int64_t)n;
    return 1;
}
static int string(codec *c,char *s,size_t capacity) {
    uint64_t n=0;
    if(!c->reading) {
        const char *end=memchr(s,0,capacity);if(!end)return 0;
        n=(uint64_t)(end-s);
    }
    if(!number(c,&n) || n>=capacity || !bytes(c,s,(size_t)n))return 0;
    if(c->reading){if(memchr(s,0,(size_t)n))return 0;s[n]=0;}
    return 1;
}
#define U(x,limit) do {uint64_t v=(x);if(!number(c,&v) || v>(uint64_t)(limit))return 0;if(c->reading)(x)=v;} while(0)
#define I(x) do {int64_t v=(x);if(!signed_number(c,&v) || v<INT_MIN || v>INT_MAX)return 0;if(c->reading)(x)=(int)v;} while(0)
#define T(x) do {int64_t v=(x);if(!signed_number(c,&v))return 0;if(c->reading)(x)=v;} while(0)
#define B(x) do {if(!bytes(c,(x),sizeof(x)))return 0;} while(0)
#define S(x) do {if(!string(c,(x),sizeof(x)))return 0;} while(0)
static int result(codec *c,d2k_ver_result *r) {
    I(r->level);I(r->status);U(r->negotiated_tls,UINT16_MAX);
    U(r->rx_tls_wire_bytes,UINT64_MAX);U(r->rx_tls_record_missing,UINT32_MAX);
    U(r->body_bytes,UINT64_MAX);U(r->body_expected,UINT64_MAX);
    I(r->body_complete);I(r->body_has_length);I(r->body_chunked);
    I(r->body_framing_valid);I(r->body_encoding);S(r->location);
    I(r->cloudflare_challenge);I(r->http_outcome);S(r->http_evidence);
    U(r->local_port,UINT16_MAX);B(r->local_ip4);U(r->family,UINT8_MAX);B(r->local_addr);
    S(r->reason);I(r->name_ok);I(r->unsupported);I(r->local_refusal);
    I(r->ech_accepted);I(r->handshake_proof);I(r->replay_proof);I(r->local_limit);
    I(r->conn_close);I(r->budget);U(r->budget_need,UINT_MAX);
    U(r->budget_packets,UINT_MAX);U(r->budget_requests,UINT_MAX);U(r->doh_replies,UINT_MAX);
    S(r->budget_note);I(r->budget_uncountable);U(r->data_packets,UINT_MAX);
    U(r->n_resources,D2K_RESOURCE_COUNT);
    for(size_t i=0;i<r->n_resources;i++){S(r->resources[i].host);S(r->resources[i].path);}
    if(c->reading)r->fd=-1;
    return r->level>=D2K_VER_NOT_MEASURED && r->level<=D2K_VER_DENIED;
}
typedef struct {
    d2k_synthesis_feedback value;
    char target[256],ip[46],program[4096],resource[512];
} stored_identity;
static int identity(codec *c,stored_identity *s) {
    d2k_synthesis_feedback *id=&s->value;
    U(id->generation,UINT64_MAX);U(id->search_id,UINT64_MAX);
    S(s->target);S(s->ip);S(s->program);S(s->resource);
    id->target=s->target;id->ip=s->ip;id->program=s->program;id->resource=s->resource;
    I(id->doh);U(id->port,UINT16_MAX);U(id->by_addr,UINT8_MAX);
    U(id->family,UINT8_MAX);U(id->transport,UINT8_MAX);U(id->shape,UINT8_MAX);
    B(id->trial_id);B(id->plan_id);B(id->flow.a_ip);B(id->flow.b_ip);
    U(id->flow.family,UINT8_MAX);U(id->flow.transport,UINT8_MAX);
    U(id->flow.a_port,UINT16_MAX);U(id->flow.b_port,UINT16_MAX);
    I(id->applied);I(id->verification_available);I(id->events_lost);
    U(id->execution_refusal,UINT_MAX);I(id->level);I(id->status);I(id->body_complete);
    I(id->local_refusal);I(id->local_limit);I(id->unsupported);I(id->challenge);
    I(id->budget);I(id->budget_uncountable);U(id->body_bytes,UINT64_MAX);
    U(id->budget_need,UINT_MAX);U(id->budget_packets,UINT_MAX);U(id->budget_requests,UINT_MAX);
    if(c->version>=2){U(id->doh_replies,UINT_MAX);}
    return 1;
}
static int tuple(codec *c,d2k_raw_tuple *t) {
    U(t->family,UINT8_MAX);U(t->local_port,UINT16_MAX);U(t->remote_port,UINT16_MAX);
    B(t->local);B(t->remote);return 1;
}
static int transport(codec *c,d2k_raw_transport *t) {
    if(c->version<3){memset(t,0,sizeof *t);return 1;}
    U(t->received_packets,UINT64_MAX);U(t->received_payload_bytes,UINT64_MAX);
    U(t->ack_packets,UINT64_MAX);U(t->ack_advances,UINT64_MAX);
    U(t->sent_end,UINT32_MAX);U(t->acked_end,UINT32_MAX);
    U(t->peer_window_raw,UINT16_MAX);
    U(t->available,1);U(t->ack_seen,1);U(t->window_seen,1);
    return t->ack_advances<=t->ack_packets && t->ack_packets<=t->received_packets &&
        (!t->available || (t->sent_end<UINT32_C(0x80000000) && t->acked_end<=t->sent_end));
}
static int observation(codec *c,d2k_application_observation *o) {
    U(o->raw_ordinal,UINT64_MAX);if(!tuple(c,&o->tuple))return 0;
    U(o->first_tls_symbol,UINT64_MAX);I(o->first_tls_available);
    d2k_doh_observation *q=&o->query;
    U(q->ordinal,UINT_MAX);U(q->stream_id,UINT32_MAX);
    T(q->started_ms);T(q->finished_ms);I(q->dns_valid);I(q->timed_out);
    U(q->query_schema,UINT_MAX);I(q->timeout_ms);
    return result(c,&q->response) && transport(c,&o->transport);
}
static int terminal(codec *c,d2k_application_end *e) {
    U(e->raw_ordinal,UINT64_MAX);if(!tuple(c,&e->tuple))return 0;
    U(e->first_tls_symbol,UINT64_MAX);I(e->network_evidence);
    I(e->timeout_ms);U(e->hello_wire,SIZE_MAX);return result(c,&e->result) && transport(c,&e->transport);
}
static int http_observation(codec *c,d2k_application_http_observation *o,
    uint8_t **allocated,d2k_ver_result *response) {
    U(o->raw_ordinal,UINT64_MAX);U(o->sent_bytes,UINT32_MAX);
    if(!tuple(c,&o->tuple) || !transport(c,&o->transport))return 0;
    U(o->event.phase,D2K_HTTPS_EXCHANGE_END);U(o->event.ordinal,UINT_MAX);
    U(o->event.request_length,D2K_TRIGGER_MAX);
    if(c->reading && o->event.request_length) {
        *allocated=malloc(o->event.request_length);if(!*allocated)return 0;
        o->event.request=*allocated;
    }
    if(!bytes(c,(void *)o->event.request,o->event.request_length))return 0;
    uint64_t has_response=o->event.response!=NULL;
    if(!number(c,&has_response) || has_response>1)return 0;
    if(has_response) {
        if(!c->reading)*response=*o->event.response;
        if(!result(c,response))return 0;
        o->event.response=response;
    }
    return 1;
}
#undef U
#undef I
#undef T
#undef B
#undef S
static int copy_string(char *dst,size_t cap,const char *src) {
    if(!src)return 0;
    size_t n=strlen(src);if(n>=cap)return 0;
    memcpy(dst,src,n+1);return 1;
}
int d2k_application_archive_write(FILE *f,const d2k_application_model *m) {
    const d2k_application_end *e=d2k_application_model_end(m);
    if(!f || !e || !e->identity)return -1;
    stored_identity id={0};id.value=*e->identity;
    if(!copy_string(id.target,sizeof id.target,e->identity->target) ||
       !copy_string(id.ip,sizeof id.ip,e->identity->ip) ||
       !copy_string(id.program,sizeof id.program,e->identity->program) ||
       !copy_string(id.resource,sizeof id.resource,e->identity->resource))return -1;
    size_t count=0;const d2k_application_observation *history=d2k_application_model_history(m,&count);
    uint64_t experience=e->experience,input_length=e->input_length,n=count;
    codec c={f,0,UINT64_C(14695981039346656037),3};
    char magic[]="D2KAPP03";
    uint64_t kind=d2k_application_model_kind(m);
    if(kind!=D2K_APPLICATION_DOH && kind!=D2K_APPLICATION_HTTPS)return -1;
    if(kind==D2K_APPLICATION_HTTPS){c.version=4;magic[7]='4';}
    uint64_t http_count=d2k_application_model_http_count(m);
    if(http_count){if(kind!=D2K_APPLICATION_HTTPS)return -1;c.version=5;magic[7]='5';}
    if(!bytes(&c,magic,8) || (c.version>=4 && !number(&c,&kind)) ||
       !identity(&c,&id) || !number(&c,&experience) ||
       !number(&c,&input_length) || !bytes(&c,(void *)e->input,e->input_length) || !number(&c,&n))return -1;
    for(size_t i=0;i<count;i++) {
        d2k_application_observation o=history[i];if(!observation(&c,&o))return -1;
    }
    if(c.version>=5) {
        if(!number(&c,&http_count))return -1;
        for(size_t i=0;i<http_count;i++) {
            d2k_application_http_observation o=*d2k_application_model_http_at(m,i);
            uint8_t *unused=NULL;d2k_ver_result response;
            if(!http_observation(&c,&o,&unused,&response))return -1;
        }
    }
    d2k_application_end end=*e;
    if(!terminal(&c,&end))return -1;
    uint64_t hash=c.hash;
    return number(&c,&hash) && !ferror(f)?0:-1;
}
int d2k_application_archive_read(FILE *f,d2k_application_model **out) {
    if(!out)return -1;
    *out=NULL;if(!f)return -1;
    int first=fgetc(f);
    if(first==EOF)return ferror(f)?-1:0;
    if(ungetc(first,f)==EOF)return -1;
    codec c={f,1,UINT64_C(14695981039346656037),0};char magic[8];
    stored_identity id={0};uint64_t experience=0,input_length=0,count=0;
    uint8_t *input=NULL;d2k_application_model *m=NULL;
    if(!bytes(&c,magic,sizeof magic) || memcmp(magic,"D2KAPP0",7) ||
       (magic[7]<'1' || magic[7]>'5'))goto fail;
    c.version=(unsigned)(magic[7]-'0');
    uint64_t kind=D2K_APPLICATION_DOH;
    if(c.version>=4 && (!number(&c,&kind) ||
       (kind!=D2K_APPLICATION_DOH && kind!=D2K_APPLICATION_HTTPS)))goto fail;
    if(!identity(&c,&id) || !number(&c,&experience) || !number(&c,&input_length) ||
       input_length>D2K_TRIGGER_MAX)goto fail;
    if(input_length){input=malloc((size_t)input_length);if(!input)goto fail;}
    if(!bytes(&c,input,(size_t)input_length) || !number(&c,&count) || count>0x3fffffffU)goto fail;
    if(kind==D2K_APPLICATION_HTTPS && count)goto fail;
    m=kind==D2K_APPLICATION_HTTPS?d2k_application_model_new_https(&id.value,experience):
        d2k_application_model_new(&id.value,experience);
    if(!m)goto fail;
    for(uint64_t i=0;i<count;i++) {
        d2k_application_observation o={0};o.identity=&id.value;o.experience=experience;
        o.input=input;o.input_length=(size_t)input_length;
        if(!observation(&c,&o) || d2k_application_model_add(m,&o)<=0)goto fail;
    }
    if(c.version>=5) {
        uint64_t http_count=0;
        if(kind!=D2K_APPLICATION_HTTPS || !number(&c,&http_count))goto fail;
        for(uint64_t i=0;i<http_count;i++) {
            d2k_application_http_observation o={.identity=&id.value,.experience=experience};
            uint8_t *request=NULL;d2k_ver_result response={0};
            int ok=http_observation(&c,&o,&request,&response) && d2k_application_model_add_http(m,&o)>0;
            free(request);if(!ok)goto fail;
        }
    }
    d2k_application_end end={0};end.identity=&id.value;end.experience=experience;
    end.input=input;end.input_length=(size_t)input_length;
    if(!terminal(&c,&end))goto fail;
    uint64_t hash=c.hash,saved=0;
    if(!number(&c,&saved) || saved!=hash || d2k_application_model_finish(m,&end))goto fail;
    free(input);*out=m;return 1;
fail:
    free(input);d2k_application_model_free(m);return -1;
}
