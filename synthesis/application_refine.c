#include "application_refine.h"
#include <stdlib.h>
#include <string.h>
static int query_decision(void *ctx,d2k_application_model *model,d2k_application_update update) {
    size_t count=0;const d2k_application_observation *history=d2k_application_model_history(model,&count);
    if(update==D2K_APP_ERROR || update==D2K_APP_REJECTED || !count || !history)return -1;
    const d2k_doh_observation *q=&history[count-1].query;
    return q->dns_valid && d2k_application_query_complete(&q->response) && q->ordinal<*(unsigned *)ctx;
}
int d2k_application_refine_step(d2k_prefix_refiner *refiner,const d2k_application_model *reference,
    uint64_t experience,const d2k_experiment *net,const d2k_tls_probe_seed *seed,
    unsigned depth,FILE *archive,d2k_application_model **out,d2k_ver_result *result) {
    if(out)*out=NULL;
    if(result){memset(result,0,sizeof *result);result->fd=-1;}
    if(!refiner || !net || !seed || !out || !result || !experience || !depth)return -1;
    const d2k_application_end *base=d2k_application_model_end(reference);
    int https=d2k_application_model_kind(reference)==D2K_APPLICATION_HTTPS;
    size_t count=0;const d2k_application_observation *history=d2k_application_model_history(reference,&count);
    if(!base || !base->identity || !base->network_evidence || base->experience==experience ||
       base->result.local_refusal || base->result.local_limit || base->result.unsupported ||
       base->timeout_ms<=0 || base->identity->shape!=D2K_SHAPE_MODERN ||
       (!!base->identity->doh)==https || (https?depth!=1 || base->result.body_complete:
       depth<count || (count?history[count-1].query.dns_valid:
       base->result.body_complete || base->result.level>=D2K_VER_APPLICATION)))return -1;
    if((net->family!=4 && net->family!=6) || net->family!=base->identity->family ||
       net->port!=base->identity->port || memcmp(net->ip,base->tuple.remote,net->family==6?16:4))return -1;
    uint8_t input[D2K_TRIGGER_MAX];static const uint8_t alpn[]={2,'h','2'};
    static const uint8_t http_alpn[]={8,'h','t','t','p','/','1','.','1'};
    size_t length=d2k_tls_probe_hello(seed,base->identity->target,base->hello_wire,
        https?http_alpn:alpn,https?sizeof http_alpn:sizeof alpn,input,sizeof input);
    if(!length || length!=base->input_length || !base->input || memcmp(input,base->input,length) ||
       d2k_detect_stopped(net->cancel))return -1;
    const char *proposal;uint64_t ticket;
    int available=d2k_prefix_refiner_next_plan(refiner,&ticket,&proposal);
    if(available!=1)return available;
    char *program=malloc(strlen(proposal)+1);if(!program)return -1;
    strcpy(program,proposal);d2k_synthesis_feedback identity=*base->identity;
    if(d2k_application_identify_trial(&identity,program)){free(program);return -1;}
    if(https)
        (void)d2k_application_https_learn(&identity,experience,net,seed,base->timeout_ms,
            base->hello_wire,out,result);
    else
        (void)d2k_application_doh_learn(&identity,experience,net,seed,base->timeout_ms,
            base->hello_wire,query_decision,&depth,out,result);
    free(program);
    const d2k_application_end *end=d2k_application_model_end(*out);
    if(!end || d2k_application_save(archive,*out,result) || !end->network_evidence ||
       result->local_refusal || result->local_limit || result->unsupported || result->cloudflare_challenge ||
       d2k_detect_stopped(net->cancel))return -1;
    d2k_application_question comparison=d2k_application_model_question(reference,*out);
    if(comparison.status==D2K_APP_QUESTION_CONTEXT || comparison.status==D2K_APP_NO_WITNESS)return -1;
    if(https) {
        int success=result->level==D2K_VER_APPLICATION && result->status==200 && result->body_complete;
        return d2k_prefix_refiner_feedback(refiner,ticket,success)==1?1:-1;
    }
    size_t observed=0;const d2k_application_observation *queries=d2k_application_model_history(*out,&observed);
    int success=d2k_application_query_complete(result) && observed>=depth;
    for(size_t i=0;success && i<observed;i++)success=queries[i].query.dns_valid;
    if(!success && observed && queries[observed-1].query.dns_valid)return -1;
    return d2k_prefix_refiner_feedback(refiner,ticket,success)==1?1:-1;
}
