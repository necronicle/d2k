#include "application_trial.h"
#include "../core/include/d2k_hello.h"
#include "../core/include/d2k_tls12.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
static int nonzero(const uint8_t *p,size_t n) {
    for(size_t i=0;i<n;i++)if(p[i])return 1;
    return 0;
}
typedef struct {
    d2k_application_owner *owner;
    uint64_t generation,experience;
    d2k_application_observer observe;
    void *ctx;
    d2k_application_model *model;
} application_observer_context;
static int observe_http(void *ctx,const d2k_https_observation *event) {
    application_observer_context *c=ctx;d2k_application_http_observation owned;
    if(d2k_application_owner_observe_http(c->owner,c->generation,c->experience,event,&owned)!=1)return -1;
    return d2k_application_model_add_http(c->model,&owned)>0?0:-1;
}
static int observe_query(void *ctx,const d2k_doh_observation *q) {
    application_observer_context *c=ctx;d2k_application_observation owned;
    if(d2k_application_owner_observe(c->owner,c->generation,c->experience,q,&owned)!=1)return -1;
    return c->observe(c->ctx,&owned);
}
static d2k_verification_status application_query(const d2k_synthesis_feedback *id,
    uint64_t experience,const d2k_experiment *network,const d2k_tls_probe_seed *seed,int timeout,size_t wire,
    d2k_application_observer observer,void *ctx,d2k_application_model *model,d2k_ver_result *out) {
    if(!out)return D2K_VF_ERROR;
    memset(out,0,sizeof *out);out->fd=-1;
    int https=model && d2k_application_model_kind(model)==D2K_APPLICATION_HTTPS;
    uint8_t remote[16]={0};
    if(!id || !network || !id->ip || !id->target || !*id->target || !id->resource ||
       id->resource[0]!='/' || (https?(id->doh || !seed || observer):!id->doh) ||
       id->by_addr || (id->shape!=D2K_SHAPE_MODERN && !(https && id->shape==D2K_SHAPE_LEGACY)) ||
       id->transport!=6 || (id->family!=4 && id->family!=6) || timeout<=0 ||
       id->family!=network->family || id->port!=network->port || !experience ||
       !nonzero(id->trial_id,sizeof id->trial_id) || !nonzero(id->plan_id,sizeof id->plan_id) ||
       inet_pton(id->family==6?AF_INET6:AF_INET,id->ip,remote)!=1 ||
       memcmp(remote,network->ip,id->family==6?16:4)) {
        out->local_refusal=1;snprintf(out->reason,sizeof out->reason,"application experiment context mismatch");
        return D2K_VF_UNKNOWN;
    }
    d2k_application_owner *owner=d2k_application_owner_new(id,experience,1);
    if(!owner){out->local_refusal=1;return D2K_VF_ERROR;}
    d2k_raw_tls_sink sink=d2k_application_owner_sink(owner);
    d2k_raw_tls *raw=d2k_raw_tls_open_observed(network,id->program,&sink,out->reason,sizeof out->reason);
    if(!raw){
        if(model) {
            d2k_application_end end;
            if(!d2k_application_owner_end(owner,out,&end)) {
                end.timeout_ms=timeout;end.hello_wire=wire;
                if(d2k_application_model_finish(model,&end))out->local_refusal=1;
            }
        }
        d2k_application_owner_free(owner);return D2K_VF_UNKNOWN;
    }
    out->level=D2K_VER_TRANSPORT;
    if(seed) {
        uint8_t *hello=malloc(D2K_TRIGGER_MAX);
        if(!hello){out->local_refusal=1;goto finish;}
        static const uint8_t alpn[]={2,'h','2'};
        static const uint8_t http_alpn[]={8,'h','t','t','p','/','1','.','1'};
        uint8_t random[32];size_t length=0;
        if(id->shape==D2K_SHAPE_LEGACY) {
            if(!d2k_tls_probe_seed_random(seed,random))
                length=d2k_tls12_probe_hello(random,id->target,wire,hello,D2K_TRIGGER_MAX);
        } else length=d2k_tls_probe_hello(seed,id->target,wire,https?http_alpn:alpn,
            https?sizeof http_alpn:sizeof alpn,hello,D2K_TRIGGER_MAX);
        int sent=length?d2k_raw_tls_prepare(raw,hello,length,out->reason,sizeof out->reason):-1;
        free(hello);
        if(sent) {out->local_refusal=1;goto finish;}
        const uint8_t *prefix=NULL;size_t received=0;
        if(d2k_raw_tls_prefix(raw,timeout,&prefix,&received,out->reason,sizeof out->reason)) {
            d2k_raw_observation observed;d2k_raw_tls_observation(raw,&observed);
            out->local_refusal=observed.kind==D2K_RAW_OBS_LOCAL || observed.kind==D2K_RAW_OBS_CANCELLED;
            goto finish;
        }
    }
    d2k_tls_io io=d2k_raw_tls_io(raw);
    application_observer_context observation={owner,id->generation,experience,observer,ctx,model};
    if(https && id->shape==D2K_SHAPE_LEGACY) {
        uint8_t random[32];
        if(d2k_tls_probe_seed_random(seed,random)){out->local_refusal=1;goto finish;}
        *out=d2k_verify_https12_observe_io(&io,random,id->target,id->resource,timeout,wire,0,observe_http,&observation);
    } else if(https)*out=d2k_verify_https_observe_io(&io,seed,id->target,id->resource,timeout,wire,0,observe_http,&observation);
    else if(observer)*out=d2k_verify_doh_observe_io(&io,seed,id->target,id->resource,timeout,wire,observe_query,&observation);
    else *out=seed?d2k_verify_doh_probe_io(&io,seed,id->target,id->resource,timeout,wire,0,NULL,NULL):
        d2k_verify_doh_io(&io,id->target,id->resource,timeout,wire,0,NULL,NULL);
finish:
    d2k_raw_tls_close(raw);
    if(model) {
        d2k_application_end end;
        if(d2k_application_owner_end(owner,out,&end))out->local_refusal=1;
        else {
            end.timeout_ms=timeout;end.hello_wire=wire;
            if(d2k_application_model_finish(model,&end))out->local_refusal=1;
        }
    }
    d2k_verification_status status=d2k_application_owner_finish(owner,id->generation,experience,out);
    d2k_application_owner_free(owner);return status;
}
d2k_verification_status d2k_application_https_learn(const d2k_synthesis_feedback *id,
    uint64_t experience,const d2k_experiment *network,const d2k_tls_probe_seed *seed,
    int timeout,size_t wire,d2k_application_model **history,d2k_ver_result *out) {
    if(history)*history=NULL;
    if(out){memset(out,0,sizeof *out);out->fd=-1;}
    if(!history || !out || !seed)return D2K_VF_ERROR;
    *history=d2k_application_model_new_https(id,experience);
    if(!*history){out->local_refusal=1;return D2K_VF_ERROR;}
    return application_query(id,experience,network,seed,timeout,wire,NULL,NULL,*history,out);
}
d2k_verification_status d2k_application_doh_query(const d2k_synthesis_feedback *id,
    uint64_t experience,const d2k_experiment *network,int timeout,size_t wire,d2k_ver_result *out) {
    return application_query(id,experience,network,NULL,timeout,wire,NULL,NULL,NULL,out);
}
d2k_verification_status d2k_application_doh_probe(const d2k_synthesis_feedback *id,
    uint64_t experience,const d2k_experiment *network,const d2k_tls_probe_seed *seed,
    int timeout,size_t wire,d2k_ver_result *out) {
    if(!seed) {
        if(out){memset(out,0,sizeof *out);out->fd=-1;out->local_refusal=1;}
        return D2K_VF_ERROR;
    }
    return application_query(id,experience,network,seed,timeout,wire,NULL,NULL,NULL,out);
}
d2k_verification_status d2k_application_doh_observe(const d2k_synthesis_feedback *id,
    uint64_t experience,const d2k_experiment *network,const d2k_tls_probe_seed *seed,
    int timeout,size_t wire,d2k_application_observer observer,void *ctx,d2k_ver_result *out) {
    if(!observer) {
        if(out){memset(out,0,sizeof *out);out->fd=-1;out->local_refusal=1;}
        return D2K_VF_ERROR;
    }
    return application_query(id,experience,network,seed,timeout,wire,observer,ctx,NULL,out);
}
typedef struct {
    d2k_application_model *model;
    d2k_application_decision decide;
    void *ctx;
} application_learning;
static int learn_query(void *ctx,const d2k_application_observation *o) {
    application_learning *l=ctx;
    d2k_application_update update=d2k_application_model_add(l->model,o);
    if(update==D2K_APP_ERROR || update==D2K_APP_REJECTED)return -1;
    return l->decide(l->ctx,l->model,update);
}
d2k_verification_status d2k_application_doh_learn(const d2k_synthesis_feedback *id,
    uint64_t experience,const d2k_experiment *network,const d2k_tls_probe_seed *seed,
    int timeout,size_t wire,d2k_application_decision decide,void *ctx,
    d2k_application_model **history,d2k_ver_result *out) {
    if(history)*history=NULL;
    if(!history || !out || !decide) {
        if(out){memset(out,0,sizeof *out);out->fd=-1;out->local_refusal=1;}
        return D2K_VF_ERROR;
    }
    *history=d2k_application_model_new(id,experience);
    if(!*history){memset(out,0,sizeof *out);out->fd=-1;out->local_refusal=1;return D2K_VF_ERROR;}
    application_learning l={*history,decide,ctx};
    return application_query(id,experience,network,seed,timeout,wire,learn_query,&l,*history,out);
}
typedef struct {
    const d2k_application_model *reference;
    d2k_application_question *question;
} application_comparison;
static int compare_query(void *ctx,d2k_application_model *model,d2k_application_update update) {
    (void)update;application_comparison *c=ctx;
    *c->question=d2k_application_model_question(c->reference,model);
    if(c->question->status==D2K_APP_QUESTION_CONTEXT || c->question->status==D2K_APP_NO_WITNESS)return -1;
    return c->question->status==D2K_APP_ASK_QUERY;
}
d2k_verification_status d2k_application_doh_compare(const d2k_application_model *reference,
    const d2k_synthesis_feedback *id,uint64_t experience,const d2k_experiment *network,
    const d2k_tls_probe_seed *seed,int timeout,size_t wire,d2k_application_model **history,
    d2k_application_question *question,d2k_ver_result *out) {
    if(history)*history=NULL;
    if(question)*question=(d2k_application_question){D2K_APP_QUESTION_CONTEXT,0,0,0};
    if(!history || !question || !out) return D2K_VF_ERROR;
    memset(out,0,sizeof *out);out->fd=-1;
    d2k_application_model *empty=d2k_application_model_new(id,experience);
    if(!empty){out->local_refusal=1;return D2K_VF_ERROR;}
    *question=d2k_application_model_question(reference,empty);
    d2k_application_model_free(empty);
    size_t n=0;const d2k_application_observation *events=d2k_application_model_history(reference,&n);
    const d2k_application_end *end=d2k_application_model_end(reference);
    int expected_timeout=n?events[0].query.timeout_ms:end?end->timeout_ms:0;
    if((question->status!=D2K_APP_ASK_QUERY && question->status!=D2K_APP_ASK_SESSION) ||
       expected_timeout!=timeout || (!n && (!end || end->hello_wire!=wire)) || !seed) {
        out->local_refusal=1;return D2K_VF_UNKNOWN;
    }
    size_t length=n?events[0].input_length:end->input_length;
    const uint8_t *expected=n?events[0].input:end->input;
    uint8_t *input=malloc(length);
    if(!input){out->local_refusal=1;return D2K_VF_ERROR;}
    static const uint8_t alpn[]={2,'h','2'};
    size_t actual=d2k_tls_probe_hello(seed,id->target,wire,alpn,sizeof alpn,input,length);
    int equal=actual==length && !memcmp(input,expected,length);
    free(input);
    if(!equal) {
        question->status=D2K_APP_QUESTION_CONTEXT;out->local_refusal=1;
        snprintf(out->reason,sizeof out->reason,"controlled ClientHello differs from failure witness");
        return D2K_VF_UNKNOWN;
    }
    application_comparison comparison={reference,question};
    d2k_verification_status status=d2k_application_doh_learn(id,experience,network,seed,timeout,wire,
        compare_query,&comparison,history,out);
    if(*history && (question->status==D2K_APP_ASK_QUERY || question->status==D2K_APP_ASK_SESSION))
        *question=d2k_application_model_question(reference,*history);
    return status;
}
