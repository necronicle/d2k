#define _POSIX_C_SOURCE 200809L
#include "../synthesis/application_refine.h"
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
static volatile sig_atomic_t stopped;
static void halt(int sig){(void)sig;stopped=1;}
static int cancelled(void *ctx){(void)ctx;return stopped;}
static int decide(void *ctx,d2k_application_model *m,d2k_application_update update){
    size_t n=0;const d2k_application_observation *h=d2k_application_model_history(m,&n);
    if(update==D2K_APP_ERROR || update==D2K_APP_REJECTED || !h || !n)return -1;
    return h[n-1].query.dns_valid && d2k_application_query_complete(&h[n-1].query.response) && h[n-1].query.ordinal<*(unsigned *)ctx;
}
static int trial(d2k_synthesis_feedback *id,char *program,uint64_t experience,
    d2k_experiment *net,d2k_tls_probe_seed *seed,int timeout,size_t wire,unsigned depth,
    FILE *archive,d2k_application_model **out,d2k_ver_result *r){
    if(d2k_application_identify_trial(id,program))return -1;
    (void)d2k_application_doh_learn(id,experience,net,seed,timeout,wire,decide,&depth,out,r);
    const d2k_application_end *end=d2k_application_model_end(*out);
    if(!end || d2k_application_save(archive,*out,r) || !end->network_evidence ||
       r->local_refusal || r->local_limit || r->unsupported || stopped)return -1;
    printf("trial=%llu dns=%u requests=%u complete=%d\n",(unsigned long long)experience,r->doh_replies,r->budget_requests,r->body_complete);fflush(stdout);
    return d2k_application_query_complete(r) && r->doh_replies>=depth;
}
int main(int argc,char **argv){
    if(argc!=3)return 2;
    signal(SIGINT,halt);signal(SIGTERM,halt);
    int rc=2,fd=-1;FILE *source=fopen(argv[1],"rb"),*archive=NULL;
    d2k_application_model *old_failure=NULL,*old_success=NULL,*direct_model=NULL,*positive=NULL,*negative=NULL,*observed=NULL;
    d2k_tls_probe_seed *seed=NULL;d2k_prefix_refiner *refiner=NULL;
    char *positive_plan=NULL,*negative_plan=NULL;uint8_t *payload=NULL;
    if(!source || d2k_application_archive_read(source,&old_failure)!=1)goto done;
    size_t old_count=0;d2k_application_model_history(old_failure,&old_count);
    if(!old_count || old_count>UINT32_MAX || d2k_application_archive_contrast(source,old_failure,(unsigned)old_count,&old_success)!=1)goto done;
    const d2k_application_end *saved=d2k_application_model_end(old_success);
    unsigned depth=saved->result.doh_replies;size_t wire=saved->hello_wire;
    size_t bytes=0,segment=0;unsigned mods=0;char err[200];
    if(d2k_lower_tls_prefix_read(saved->identity->program,&payload,&bytes,&segment,&mods,err,sizeof err)!=D2K_LOWER_OK)goto done;
    free(payload);payload=NULL;
    positive_plan=malloc(strlen(saved->identity->program)+1);if(!positive_plan)goto done;strcpy(positive_plan,saved->identity->program);
    fd=open(argv[2],O_RDWR|O_CREAT|O_EXCL,0600);if(fd<0)goto done;
    archive=fdopen(fd,"w+b");if(!archive){close(fd);goto done;}
    d2k_detect_stop cancel={cancelled,NULL};
    d2k_experiment net={.family=saved->identity->family,.port=saved->identity->port,.mark=0x2f,.offer_ts=1,.connect_ms=saved->timeout_ms,.cancel=&cancel};
    if(inet_pton(net.family==6?AF_INET6:AF_INET,saved->identity->ip,net.ip)!=1)goto done;
    d2k_synthesis_feedback id={.generation=1,.search_id=1,.target=saved->identity->target,
        .ip=saved->identity->ip,.resource=saved->identity->resource,.doh=1,.family=net.family,
        .transport=6,.port=net.port,.shape=D2K_SHAPE_MODERN};
    seed=d2k_tls_probe_seed_new();if(!seed)goto done;
    char direct[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
    int status=trial(&id,direct,1,&net,seed,saved->timeout_ms,wire,depth,archive,&direct_model,&(d2k_ver_result){0});
    if(status<0)goto done;if(status){puts("direct healthy: no refinement");rc=1;goto done;}
    d2k_ver_result result;
    status=trial(&id,positive_plan,2,&net,seed,saved->timeout_ms,wire,depth,archive,&positive,&result);
    if(status<0)goto done;if(!status){puts("historical positive not reproduced: no refinement");rc=1;goto done;}
    uint8_t fake[D2K_TRIGGER_MAX];const uint8_t alpn[]={2,'h','2'};
    size_t generated=d2k_tls_probe_hello(seed,id.target,bytes,alpn,sizeof alpn,fake,sizeof fake);
    if(generated!=bytes || d2k_lower_tls_prefix(fake,generated,segment,mods,&negative_plan,err,sizeof err)!=D2K_LOWER_OK)goto done;
    status=trial(&id,negative_plan,3,&net,seed,saved->timeout_ms,wire,depth,archive,&negative,&result);
    if(status<0)goto done;if(status){puts("reference payload also works: no failed content contrast");rc=1;goto done;}
    if(d2k_application_model_question(negative,positive).status!=D2K_APP_CHANGED)goto done;
    refiner=d2k_prefix_refiner_new_plans(positive_plan,negative_plan);if(!refiner)goto done;
    for(uint64_t experience=4;!stopped;experience++) {
        d2k_application_model_free(observed);observed=NULL;
        status=d2k_application_refine_step(refiner,negative,experience,&net,seed,depth,archive,&observed,&result);
        printf("generated experience=%llu step=%d dns=%u requests=%u complete=%d local=%d\n",
            (unsigned long long)experience,status,result.doh_replies,result.budget_requests,result.body_complete,result.local_refusal);fflush(stdout);
        if(status!=1){rc=1;break;}
        if(d2k_application_query_complete(&result) && result.doh_replies>=depth){rc=0;break;}
        if(experience==UINT64_MAX)break;
    }
done:
    d2k_prefix_refiner_free(refiner);d2k_tls_probe_seed_free(seed);
    d2k_application_model_free(old_failure);d2k_application_model_free(old_success);
    d2k_application_model_free(direct_model);d2k_application_model_free(positive);
    d2k_application_model_free(negative);d2k_application_model_free(observed);
    free(payload);free(positive_plan);free(negative_plan);
    if(source)fclose(source);if(archive && fclose(archive))rc=2;return rc;
}
