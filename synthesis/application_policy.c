#define _POSIX_C_SOURCE 200809L
#include "application_policy.h"
#include "../core/include/d2k_hello.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
int d2k_application_save(FILE *archive,const d2k_application_model *model,d2k_ver_result *result) {
    if(!archive)return 0;
    if(d2k_application_archive_write(archive,model)==0 && !fflush(archive) && !fsync(fileno(archive)))return 0;
    result->local_refusal=1;
    snprintf(result->reason,sizeof result->reason,"cannot persist owned application evidence");
    return -1;
}
int d2k_application_query_complete(const d2k_ver_result *);
int d2k_application_policy_sink(void *ctx,d2k_raw_tls_sink *sink) {
    d2k_application_policy *m=ctx;
    if(m->experience==UINT64_MAX || m->owner)return -1;
    d2k_application_model_free(m->model);m->model=NULL;
    m->reference=m->baseline_reference;m->evidence_error=0;
    free(m->program);m->program=NULL;
    memset(&m->result,0,sizeof m->result);m->result.fd=-1;
    memset(&m->comparison,0,sizeof m->comparison);
    m->qualified=0;m->completed_queries=0;
    d2k_raw_tape_free(m->tape);m->tape=d2k_raw_tape_new(++m->experience);
    *sink=d2k_raw_tape_sink(m->tape);return m->tape?0:-1;
}
static int measured_query(void *ctx,const d2k_doh_observation *query) {
    d2k_application_policy *m=ctx;d2k_application_observation owned;
    if(d2k_application_owner_observe(m->owner,m->generation,m->experience,query,&owned)!=1)return -1;
    d2k_application_update update=d2k_application_model_add(m->model,&owned);
    if(update==D2K_APP_ERROR || update==D2K_APP_REJECTED)return -1;
    m->comparison=d2k_application_model_question(m->reference,m->model);
    if(m->comparison.status==D2K_APP_QUESTION_CONTEXT || m->comparison.status==D2K_APP_NO_WITNESS)return -1;
    if(!query->dns_valid || !d2k_application_query_complete(&query->response))return 0;
    m->completed_queries=query->ordinal;
    return query->ordinal<m->required_queries || m->comparison.status==D2K_APP_ASK_QUERY;
}
int d2k_application_identify_trial(d2k_synthesis_feedback *id,char *program) {
    char *label=strstr(program,"\nid ");
    if(!label || strlen(label+4)<32 || d2k_t13_random(id->plan_id,sizeof id->plan_id) ||
       d2k_t13_random(id->trial_id,sizeof id->trial_id))return -1;
    static const char hex[]="0123456789abcdef";
    for(size_t i=0;i<sizeof id->plan_id;i++) {
        label[4+2*i]=hex[id->plan_id[i]>>4];label[5+2*i]=hex[id->plan_id[i]&15];
    }
    id->program=program;return 0;
}
int d2k_application_query_complete(const d2k_ver_result *r) {
    return r->level==D2K_VER_APPLICATION && r->status==200 && r->body_complete &&
        r->doh_replies && !r->local_refusal && !r->local_limit && !r->unsupported;
}
static int https_complete(const d2k_ver_result *r) {
    return r->level==D2K_VER_APPLICATION && r->status==200 && r->body_complete &&
        !r->doh_replies && !r->local_refusal && !r->local_limit && !r->unsupported;
}
static int measured_prepare(void *ctx,const char *program) {
    d2k_application_policy *m=ctx;
    size_t length=strlen(program);
    m->program=malloc(length+1);
    if(!m->program)return -1;
    memcpy(m->program,program,length+1);m->trial=*m->base;
    if(d2k_application_identify_trial(&m->trial,m->program))return -1;
    m->owner=d2k_application_owner_recorded(&m->trial,1,m->tape,m->input,m->input_length);
    if(m->owner)m->model=m->trial.doh?
        d2k_application_model_new(&m->trial,m->experience):
        d2k_application_model_new_https(&m->trial,m->experience);
    return m->owner && m->model?0:-1;
}
static int measured_http(void *ctx,const d2k_https_observation *event) {
    d2k_application_policy *m=ctx;d2k_application_http_observation owned;
    if(d2k_application_owner_observe_http(m->owner,m->generation,m->experience,event,&owned)!=1)return -1;
    return d2k_application_model_add_http(m->model,&owned)>0?0:-1;
}
static int measured_run(void *ctx,const d2k_tls_io *io) {
    d2k_application_policy *m=ctx;
    if(m->trial.doh)
        m->result=d2k_verify_doh_observe_io(io,m->seed,m->trial.target,m->trial.resource,
            m->timeout_ms,m->hello_wire,measured_query,m);
    else if(m->trial.shape==D2K_SHAPE_LEGACY) {
        uint8_t random[32];
        if(d2k_tls_probe_seed_random(m->seed,random))return -1;
        m->result=d2k_verify_https12_observe_io(io,random,m->trial.target,m->trial.resource,
            m->timeout_ms,m->hello_wire,0,measured_http,m);
    } else
        m->result=d2k_verify_https_observe_io(io,m->seed,m->trial.target,m->trial.resource,
            m->timeout_ms,m->hello_wire,0,measured_http,m);
    return 0;
}
static int measured_finish(void *ctx,uint64_t *symbol) {
    d2k_application_policy *m=ctx;int known=0,archive_failed=0;
    d2k_application_end end;
    if(m->evidence_error)goto done;
    if(!m->owner || !m->model || d2k_application_owner_end(m->owner,&m->result,&end))goto done;
    end.timeout_ms=m->timeout_ms;end.hello_wire=m->hello_wire;
    if(d2k_application_model_finish(m->model,&end))goto done;
    if(d2k_application_save(m->archive,m->model,&m->result)){archive_failed=1;goto done;}
    if(!end.network_evidence ||
       m->result.local_refusal || m->result.local_limit || m->result.unsupported)goto done;
    m->comparison=d2k_application_model_question(m->reference,m->model);
    if(m->comparison.status==D2K_APP_QUESTION_CONTEXT || m->comparison.status==D2K_APP_NO_WITNESS)goto done;
    m->qualified=m->trial.doh?
        d2k_application_query_complete(&m->result) && m->completed_queries>=m->required_queries:
        https_complete(&m->result);
    if(m->result.level<D2K_VER_NOT_MEASURED || m->result.level>D2K_VER_DENIED || m->result.level>15 ||
       m->result.status<0 || m->result.status>999)goto done;
    /* Session-local observation: exact validated DNS prefix in bits 0..31,
       level 32..35, incoming-payload class 36..37, HTTP progress 38..39,
       current query ACK coverage 40..41,
       HTTP status 48..57, body completeness 58, ACK class
       60..61, validated DNS reply or HTTP body progress 62, application contract met 63. These are not
       the archive/model terminal encoding; full evidence is saved above. */
    *symbol=(uint64_t)m->result.doh_replies |
        ((uint64_t)(unsigned)m->result.level<<32) |
        ((uint64_t)(unsigned)m->result.status<<48) |
        ((uint64_t)!!m->result.body_complete<<58);
    if(!m->qualified) {
        *symbol|=(uint64_t)d2k_application_response_progress(&m->result)<<38;
        *symbol|=(uint64_t)d2k_application_ack_coverage(&end.transport)<<60;
        if(m->trial.doh) {
            size_t count=0;
            const d2k_application_observation *history=d2k_application_model_history(m->model,&count);
            *symbol|=(uint64_t)d2k_application_payload_receipt(history,count)<<36;
            *symbol|=(uint64_t)d2k_application_query_ack(history,count)<<40;
        } else {
            d2k_application_http_interval interval;
            if(d2k_application_model_http_interval(m->model,&interval)) {
                *symbol|=(uint64_t)interval.receipt<<36;
                *symbol|=(uint64_t)interval.ack<<40;
            }
        }
    }
    if(m->result.doh_replies || (!m->trial.doh &&
       m->result.level>=D2K_VER_HANDSHAKE && m->result.level<=D2K_VER_APPLICATION && m->result.status==200 &&
       m->result.body_bytes))*symbol|=UINT64_C(1)<<62;
    if(m->qualified)*symbol|=UINT64_C(1)<<63;
    known=1;
done:
    d2k_application_owner_free(m->owner);m->owner=NULL;
    if(!known) {
        m->qualified=0;m->result.local_refusal=1;
        if(!archive_failed && !m->evidence_error)snprintf(m->result.reason,sizeof m->result.reason,"application trial lacks owned network evidence");
    }
    return known;
}
static int measured_accepted(void *ctx,uint64_t symbol) {
    (void)ctx;return !!(symbol&(UINT64_C(1)<<63));
}
static int measured_token_question(void *ctx,uint64_t symbol) {
    (void)ctx;
    if(measured_accepted(NULL,symbol))return 0;
    unsigned level=(unsigned)((symbol>>32)&UINT64_C(0xf));
    if(level==D2K_VER_TRANSPORT)return 1;
    unsigned status=(unsigned)((symbol>>48)&UINT64_C(0x3ff));
    if(!(symbol&(UINT64_C(1)<<58)) && (!status || status==200) &&
       level>=D2K_VER_HANDSHAKE && level<=D2K_VER_APPLICATION &&
       (symbol&(UINT64_C(1)<<62)) && (((symbol>>60)&3)==1 || ((symbol>>60)&3)==2))return 2;
    return 0;
}
d2k_tls_application d2k_application_policy_callbacks(d2k_application_policy *m) {
    return (d2k_tls_application){m,measured_prepare,measured_run,measured_finish,
        measured_accepted,measured_token_question};
}
void d2k_application_policy_destroy(d2k_application_policy *m) {
    if(!m)return;
    d2k_application_owner_free(m->owner);
    d2k_raw_tape_free(m->tape);d2k_application_model_free(m->model);
    d2k_application_model_free(m->witness);free(m->program);
    memset(m,0,sizeof *m);
}
int d2k_application_policy_init(d2k_application_policy *m,const d2k_synthesis_feedback *id,
    const d2k_application_model *reference,const d2k_tls_probe_seed *seed,
    const uint8_t *input,size_t length,uint64_t experience,int timeout,size_t wire,FILE *archive) {
    if(!m)return -1;
    memset(m,0,sizeof *m);
    const d2k_application_end *end=d2k_application_model_end(reference);
    if(!id || !id->target || !id->ip || !id->resource || !id->generation || !id->search_id ||
       id->by_addr || id->transport!=6 ||
       (id->shape!=D2K_SHAPE_MODERN && !(id->shape==D2K_SHAPE_LEGACY && !id->doh)) ||
       !seed || !input || !length || length>D2K_TRIGGER_MAX || !experience ||
       experience==UINT64_MAX || timeout<=0 || !end || !end->identity ||
       !end->network_evidence || end->result.local_refusal || end->result.local_limit ||
       end->result.unsupported || end->timeout_ms!=timeout || end->hello_wire!=wire ||
       end->input_length!=length || !end->input || memcmp(end->input,input,length))return -1;
    if(d2k_application_model_kind(reference)!=(id->doh?D2K_APPLICATION_DOH:D2K_APPLICATION_HTTPS))return -1;
    const d2k_synthesis_feedback *baseline=end->identity;
    if(baseline->generation!=id->generation || baseline->search_id!=id->search_id ||
       baseline->family!=id->family || baseline->transport!=id->transport ||
       baseline->port!=id->port || baseline->shape!=id->shape ||
       baseline->doh!=id->doh || baseline->by_addr!=id->by_addr ||
       strcmp(baseline->target,id->target) || strcmp(baseline->ip,id->ip) ||
       strcmp(baseline->resource,id->resource))return -1;
    size_t count=0;
    const d2k_application_observation *history=d2k_application_model_history(reference,&count);
    if(count ? history[count-1].query.dns_valid :
       (end->result.level>=D2K_VER_APPLICATION || end->result.body_complete))return -1;
    *m=(d2k_application_policy){.experience=experience,.generation=id->generation,
        .reference=reference,.baseline_reference=reference,.base=id,.seed=seed,
        .input=input,.input_length=length,.timeout_ms=timeout,.hello_wire=wire,.archive=archive,
        .required_queries=count?(unsigned)count:1};
    if(archive) {
        d2k_application_model *trial=id->doh?d2k_application_model_new(id,experience+1):
            d2k_application_model_new_https(id,experience+1);
        if(!trial)goto failed;
        d2k_application_witness_context context={trial,input,length,timeout,wire};
        int found=d2k_application_archive_witness(archive,&context,&m->witness);
        d2k_application_model_free(trial);
        if(found<0)goto failed;
        if(found) {
            size_t queries=0;d2k_application_model_history(m->witness,&queries);
            if(queries>UINT_MAX)goto failed;
            m->reference=m->baseline_reference=m->witness;
            if(queries>m->required_queries)m->required_queries=(unsigned)queries;
        }
    }
    return 0;
failed:
    d2k_application_policy_destroy(m);return -1;
}
