#define _POSIX_C_SOURCE 200809L
#include "../synthesis/application_policy.h"
#include "../synthesis/token_content.h"
#include "d2k_hello.h"
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
static volatile sig_atomic_t stop;
static void halt(int sig){(void)sig;stop=1;}
static int cancelled(void *ctx){(void)ctx;return stop;}
/* Diagnostic contrast: replace the SNI extension's space with padding while
 * preserving record, handshake and extension-vector lengths. */
static int omit_name(uint8_t *b,size_t n){
    if(n<44 || !d2k_hello_complete(b,n))return -1;
    size_t p=43,off,len;
    size_t z=b[p++];if(z>n-p)return -1;p+=z;
    if(n-p<2)return -1;z=((size_t)b[p]<<8)|b[p+1];p+=2;
    if(z>n-p)return -1;p+=z;
    if(p==n)return -1;z=b[p++];if(z>n-p)return -1;p+=z;
    if(n-p<2)return -1;z=((size_t)b[p]<<8)|b[p+1];p+=2;
    if(z!=n-p)return -1;
    size_t dst=p,removed=0;int found=0;
    while(p<n){
        if(n-p<4)return -1;
        unsigned type=((unsigned)b[p]<<8)|b[p+1];
        z=((size_t)b[p+2]<<8)|b[p+3];if(z>n-p-4)return -1;
        if(type==0 || type==21){removed+=z+4;if(type==0)found++;}
        else {memmove(b+dst,b+p,z+4);dst+=z+4;}
        p+=z+4;
    }
    if(found!=1 || removed<4 || removed-4>65535)return -1;
    b[dst++]=0;b[dst++]=21;b[dst++]=(uint8_t)((removed-4)>>8);
    b[dst++]=(uint8_t)(removed-4);memset(b+dst,0,removed-4);
    return d2k_hello_complete(b,n) && d2k_hello_sni(b,n,&off,&len)!=0?0:-1;
}
static int observe(void *ctx,d2k_application_model *m,d2k_application_update u){
    size_t n=0;const d2k_application_observation *h=d2k_application_model_history(m,&n);
    if(u==D2K_APP_ERROR || u==D2K_APP_REJECTED || !h || !n)return -1;
    const d2k_doh_observation *q=&h[n-1].query;
    return q->dns_valid && d2k_application_query_complete(&q->response) && q->ordinal<*(unsigned *)ctx;
}
int main(int argc,char **argv){
    if(argc!=5)return 2;
    signal(SIGINT,halt);signal(SIGTERM,halt);
    int fd=open(argv[4],O_RDWR|O_CREAT|O_EXCL,0600);if(fd<0)return 2;
    FILE *archive=fdopen(fd,"w+b");if(!archive){close(fd);return 2;}
    d2k_detect_stop cancel={cancelled,NULL};
    d2k_experiment net={.family=4,.port=443,.mark=0x2f,.offer_ts=1,.connect_ms=5000,.cancel=&cancel,.reply_capacity=4096};
    if(inet_pton(AF_INET,argv[1],net.ip)!=1)return 2;
    d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();if(!seed)return 2;
    char direct[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
    d2k_synthesis_feedback id={.generation=1,.search_id=1,.target=argv[2],.ip=argv[1],.resource="/dns-query",.doh=1,.family=4,.transport=6,.port=443,.shape=D2K_SHAPE_MODERN};
    if(d2k_application_identify_trial(&id,direct))return 2;
    unsigned depth=20;d2k_application_model *baseline=NULL;d2k_ver_result result;
    (void)d2k_application_doh_learn(&id,1,&net,seed,5000,1200,observe,&depth,&baseline,&result);
    if(!baseline || d2k_application_save(archive,baseline,&result))return 2;
    printf("baseline dns=%u requests=%u local=%d reason=%s\n",result.doh_replies,result.budget_requests,result.local_refusal,result.reason);fflush(stdout);
    if(result.body_complete || result.local_refusal || stop)return 1;
    d2k_trigger tr={0};const uint8_t alpn[]={2,'h','2'};
    tr.len=d2k_tls_probe_hello(seed,id.target,1200,alpn,sizeof alpn,tr.payload,sizeof tr.payload);
    size_t off,len;if(!tr.len || d2k_hello_sni(tr.payload,tr.len,&off,&len))return 2;
    tr.sni_off=(int)off;tr.sni_len=(int)len;tr.accept=D2K_ACCEPT_SERVERHELLO;
    d2k_application_policy policy;
    if(d2k_application_policy_init(&policy,&id,baseline,seed,tr.payload,tr.len,1,5000,1200,archive))return 2;
    policy.required_queries=depth;
    net.tls_input=tr.payload;net.tls_input_length=tr.len;net.make_sink=d2k_application_policy_sink;net.sink_context=&policy;
    size_t whole=tr.len;d2k_tls_stream stream={&tr,&whole,1,5000,1};
    d2k_tls_application app=d2k_application_policy_callbacks(&policy);
    d2k_tls_path_session *w=d2k_tls_path_session_new_application(&stream,&net,1,&app);if(!w)return 2;
    d2k_vres out;d2k_syn_status status=d2k_tls_path_session_next(w,&out);
    printf("before prefix status=%d probes=%d reason=%s\n",status,out.probes,out.reason);fflush(stdout);
    if(status==D2K_SYN_CLOSED && !stop){
        uint8_t bytes[1200];size_t n;
        if(!strcmp(argv[3],"@input") || !strcmp(argv[3],"@without-sni")){
            n=tr.len;if(n>sizeof bytes)return 2;memcpy(bytes,tr.payload,n);
            if(!strcmp(argv[3],"@without-sni") && omit_name(bytes,n))return 2;
        }else {
            d2k_tls_probe_seed *decoy=d2k_tls_probe_seed_new();if(!decoy)return 2;
            int mask=!strncmp(argv[3],"@mask:",6);
            n=d2k_tls_probe_hello(decoy,mask?argv[3]+6:argv[3],1200,alpn,sizeof alpn,bytes,sizeof bytes);
            d2k_tls_probe_seed_free(decoy);
            if(mask) {
                d2k_trigger source={0};size_t start,count;
                if(!n || n>sizeof source.payload || d2k_hello_sni(bytes,n,&start,&count))return 2;
                memcpy(source.payload,bytes,n);source.len=n;
                source.sni_off=(int)start;source.sni_len=(int)count;
                if(d2k_token_content_question(&source,bytes,sizeof bytes)!=1)return 2;
            }
        }
        int added=d2k_tls_path_session_add_prefix(w,bytes,n,1400,3);
        printf("prefix added=%d\n",added);fflush(stdout);
        if(added==1)status=d2k_tls_path_session_next(w,&out);
    }
    printf("after status=%d probes=%d dns=%u local=%d program=%zu reason=%s\n",status,out.probes,policy.result.doh_replies,policy.result.local_refusal,out.program_len,out.reason);fflush(stdout);
    d2k_tls_path_session_free(w);d2k_application_policy_destroy(&policy);d2k_application_model_free(baseline);d2k_tls_probe_seed_free(seed);
    if(fclose(archive))return 2;return status==D2K_SYN_CANDIDATE?0:1;
}
