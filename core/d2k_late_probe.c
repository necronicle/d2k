#define _POSIX_C_SOURCE 200809L
#include "../synthesis/application_policy.h"
#include "../synthesis/application_late.h"
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
static volatile sig_atomic_t stop;
static void halt(int sig){(void)sig;stop=1;}
static int cancelled(void *p){(void)p;return stop;}
static int decide(void *ctx,d2k_application_model *m,d2k_application_update u){
 size_t n=0;const d2k_application_observation *h=d2k_application_model_history(m,&n);
 if(u==D2K_APP_ERROR || u==D2K_APP_REJECTED || !h || !n)return -1;
 return h[n-1].query.dns_valid && h[n-1].query.ordinal<*(unsigned *)ctx;
}
static int trial(d2k_synthesis_feedback *id,char *plan,unsigned experience,d2k_experiment *net,
 d2k_tls_probe_seed *seed,FILE *archive,d2k_application_model **m){
 unsigned depth=10;d2k_ver_result r={0};
 if(d2k_application_identify_trial(id,plan))return -1;
 (void)d2k_application_doh_learn(id,experience,net,seed,5000,1200,decide,&depth,m,&r);
 const d2k_application_end *e=d2k_application_model_end(*m);
 int owned=e && e->network_evidence;
 if(!*m || d2k_application_save(archive,*m,&r))return -1;
 printf("trial=%u owned=%d dns=%u requests=%u complete=%d local=%d reason=%s\n",experience,owned,r.doh_replies,r.budget_requests,r.body_complete,r.local_refusal,r.reason);fflush(stdout);
 if(!owned || r.local_refusal || r.local_limit || r.unsupported || stop)return -1;
 return d2k_application_query_complete(&r) && r.doh_replies>=depth;
}
int main(int argc,char **argv){
 if(argc!=4)return 2;
 signal(SIGINT,halt);signal(SIGTERM,halt);
 d2k_detect_stop cancel={cancelled,NULL};
 d2k_experiment net={.family=4,.port=443,.mark=0x2f,.offer_ts=1,.connect_ms=5000,.cancel=&cancel};
 if(inet_pton(AF_INET,argv[1],net.ip)!=1)return 2;
 int fd=open(argv[3],O_RDWR|O_CREAT|O_EXCL,0600);if(fd<0)return 2;
 FILE *archive=fdopen(fd,"w+b");if(!archive){close(fd);return 2;}
 int rc=2;char *plan=NULL;d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();d2k_application_model *base=NULL,*candidate=NULL;
 if(!seed)goto done;
 d2k_synthesis_feedback id={.generation=1,.search_id=1,.target=argv[2],.ip=argv[1],.resource="/dns-query",.doh=1,.family=4,.transport=6,.port=443,.shape=D2K_SHAPE_MODERN};
 char direct[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
 int status=trial(&id,direct,1,&net,seed,archive,&base);if(status<0)goto done;
 if(status){puts("direct healthy: stop");rc=0;goto done;}
 if(d2k_application_late_question(base,&plan)!=1)goto done;
 printf("question=failed-request-packetization\n%s",plan);fflush(stdout);
 status=trial(&id,plan,2,&net,seed,archive,&candidate);
 if(status<0)goto done;
 rc=status?0:1;
done:
 d2k_application_model_free(base);d2k_application_model_free(candidate);free(plan);d2k_tls_probe_seed_free(seed);if(fclose(archive))rc=2;return rc;
}
