#define _POSIX_C_SOURCE 200809L
#include "../synthesis/application_policy.h"
#include "../synthesis/lower.h"
#include "d2k_hello.h"
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

/* Diagnostic only: derive one contrast from the target, never install a plan. */
int main(int argc,char **argv){
    if(argc!=4 && !(argc==5 && !strcmp(argv[4],"--direct")))return 2;
    const char *parent=strchr(argv[2],'.');
    if(!parent || parent==argv[2] || !parent[1] || !strchr(parent+1,'.'))return 2;
    parent++;
    signal(SIGINT,halt);signal(SIGTERM,halt);
    d2k_detect_stop cancel={cancelled,NULL};
    d2k_experiment net={.family=4,.port=443,.mark=0x2f,.offer_ts=1,.connect_ms=5000,.cancel=&cancel};
    if(inet_pton(AF_INET,argv[1],net.ip)!=1)return 2;
    int fd=open(argv[3],O_RDWR|O_CREAT|O_EXCL,0600);if(fd<0)return 2;
    FILE *archive=fdopen(fd,"w+b");if(!archive){close(fd);return 2;}
    d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();
    d2k_tls_probe_seed *decoy=d2k_tls_probe_seed_new();
    char *compiled=NULL;int rc=2;
    if(!seed || !decoy)goto done;
    d2k_synthesis_feedback id={.generation=1,.search_id=1,.target=argv[2],.ip=argv[1],
        .resource="/dns-query",.doh=1,.family=4,.transport=6,.port=443,.shape=D2K_SHAPE_MODERN};
    char direct[]="d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\ninput tls-sni\nsegment 1400\norder forward\n";
    unsigned depth=10;
    for(unsigned i=0;i<(argc==5?1u:3u) && !stopped;i++){
        char *program=direct;
        if(i){
            uint8_t fake[1200];const uint8_t alpn[]={2,'h','2'};char err[200];
            size_t n=d2k_tls_probe_hello(decoy,i==1?argv[2]:parent,sizeof fake,alpn,sizeof alpn,fake,sizeof fake);
            if(n!=sizeof fake || d2k_lower_tls_prefix(fake,n,1400,3,&compiled,err,sizeof err)!=D2K_LOWER_OK)goto done;
            program=compiled;
        }
        if(d2k_application_identify_trial(&id,program))goto done;
        d2k_application_model *m=NULL;d2k_ver_result r={0};
        (void)d2k_application_doh_learn(&id,i+1,&net,seed,5000,1200,decide,&depth,&m,&r);
        const d2k_application_end *end=d2k_application_model_end(m);
        int owned=end && end->network_evidence;
        int saved=m && !d2k_application_save(archive,m,&r);
        int healthy=d2k_application_query_complete(&r) && r.doh_replies>=depth;
        printf("trial=%u kind=%s owned=%d dns=%u requests=%u complete=%d local=%d reason=%s\n",
            i+1,i==0?"direct":i==1?"full-name":"parent-name",owned,r.doh_replies,r.budget_requests,r.body_complete,r.local_refusal,r.reason);
        fflush(stdout);d2k_application_model_free(m);free(compiled);compiled=NULL;
        if(!saved || !owned || r.local_refusal || r.local_limit || r.unsupported || stopped)goto done;
        if(healthy){puts(i==0?"direct healthy: stop":"application success: stop");rc=0;goto done;}
    }
    if(!stopped)rc=1;
done:
    free(compiled);d2k_tls_probe_seed_free(decoy);d2k_tls_probe_seed_free(seed);
    if(fclose(archive))rc=2;return rc;
}
