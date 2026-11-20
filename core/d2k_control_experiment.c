#define _POSIX_C_SOURCE 200809L

#include "../synthesis/application_policy.h"
#include "d2k_hello.h"
#include "../synthesis/lower.h"
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
static volatile sig_atomic_t stop;
static void halt(int sig){(void)sig;stop=1;}
static int cancelled(void *p){(void)p;return stop;}
static int query(void *ctx,d2k_application_model *m,d2k_application_update u){
    size_t n=0;const d2k_application_observation *h=d2k_application_model_history(m,&n);
    if(u==D2K_APP_ERROR || u==D2K_APP_REJECTED || !h || !n)return -1;
    const d2k_doh_observation *q=&h[n-1].query;
    return q->dns_valid && d2k_application_query_complete(&q->response) && q->ordinal<*(unsigned *)ctx;
}
int main(int argc,char **argv){
    if(argc!=5)return 2;
    char plan[4096];
    int generated=!strncmp(argv[3],"hello:",6);
    if(!generated){
        FILE *p=fopen(argv[3],"rb");if(!p)return 2;
        size_t n=fread(plan,1,sizeof plan-1,p);
        int more=fgetc(p),bad=ferror(p);fclose(p);
        if(!n || more!=EOF || bad)return 2;plan[n]=0;
    }
    int fd=open(argv[4],O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return 2;
    FILE *archive=fdopen(fd,"wb");if(!archive){close(fd);return 2;}
    signal(SIGINT,halt);signal(SIGTERM,halt);
    d2k_detect_stop cancel={cancelled,NULL};
    d2k_experiment net={.family=4,.port=443,.mark=0x2f,.offer_ts=1,.connect_ms=5000,.cancel=&cancel};
    if(inet_pton(AF_INET,argv[1],net.ip)!=1)return 2;
    d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();if(!seed)return 2;
    if(generated){
        uint8_t fake[1200];const uint8_t alpn[]={2,'h','2'};
        d2k_tls_probe_seed *decoy=d2k_tls_probe_seed_new();if(!decoy)return 2;
        size_t length=d2k_tls_probe_hello(decoy,argv[3]+6,sizeof fake,alpn,sizeof alpn,fake,sizeof fake);
        d2k_tls_probe_seed_free(decoy);if(!length)return 2;
        char *compiled=NULL,why[256];
        if(d2k_lower_tls_prefix(fake,length,1400,3,&compiled,why,sizeof why)!=D2K_LOWER_OK){
            fprintf(stderr,"prefix compilation: %s\n",why);return 2;
        }
        if(strlen(compiled)>=sizeof plan){free(compiled);return 2;}
        memcpy(plan,compiled,strlen(compiled)+1);free(compiled);

    }
    d2k_synthesis_feedback id={.generation=1,.search_id=1,.target=argv[2],.ip=argv[1],
        .resource="/dns-query",.doh=1,.family=4,.transport=6,.port=443,.shape=D2K_SHAPE_MODERN};
    char direct[]="d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\ninput tls-sni\nsegment 1400\norder forward\n";
    char *programs[]={direct,plan};unsigned depth=10;int rc=0;
    for(unsigned i=0;i<2 && !stop;i++){
        if(d2k_application_identify_trial(&id,programs[i])){rc=2;break;}
        d2k_application_model *m=NULL;d2k_ver_result r;
        int status=d2k_application_doh_learn(&id,i+1,&net,seed,5000,1556,query,&depth,&m,&r);
        const d2k_application_end *end=d2k_application_model_end(m);
        if(!m || d2k_application_save(archive,m,&r)){d2k_application_model_free(m);rc=2;break;}
        printf("trial=%u status=%d owned=%d level=%d http=%d complete=%d dns=%u requests=%u local=%d reason=%s\n",
            i,status,end?end->network_evidence:0,r.level,r.status,r.body_complete,r.doh_replies,r.budget_requests,r.local_refusal,r.reason);
        fflush(stdout);d2k_application_model_free(m);
    }
    d2k_tls_probe_seed_free(seed);if(fclose(archive))rc=2;return rc;
}
