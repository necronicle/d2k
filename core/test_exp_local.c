/* Offline boundary tests: socketpair framing; no bind/listen or network. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_link.h"

static int local_socket(int,int,int);
static int local_bind(int,const struct sockaddr *,socklen_t);
static int local_sockname(int,struct sockaddr *,socklen_t *);
static int local_close(int);
static int local_connect(int,const struct sockaddr *,socklen_t);
static ssize_t local_recv(int,void *,size_t,int);
static int local_getsockopt(int,int,int,void *,socklen_t *);
#define connect local_connect
#define recv local_recv
#define getsockopt local_getsockopt
#define socket local_socket
#define bind local_bind
#define getsockname local_sockname
#define close local_close
#include "netarm.c"
#undef connect
#undef recv
#undef getsockopt
#undef socket
#undef bind
#undef getsockname
#undef close

static int control_open(const char *,char *,size_t);
static void control_close(int);
static int control_set(int,const char *,uint8_t,const char *,uint8_t,uint16_t,uint8_t,const uint8_t *,char *,size_t);
static int control_next(int,d2k_ev *,int,char *,size_t);
#define d2k_link_open control_open
#define d2k_link_close control_close
#define d2k_link_set_name_probe_trial control_set
#define d2k_link_next control_next
#include "exp_task.c"
#undef d2k_link_set_name_probe_trial
#undef d2k_link_next
#undef d2k_link_open
#undef d2k_link_close

static unsigned failures,events;
static int setup_mode,unlocked,receipt_mode;
static unsigned releases,reacquires;
static uint8_t current_trial[16];
static int socket_error;
static int own_success;
static unsigned socket_calls,closed,removed;
#define CHECK(c) do { if(!(c)) {fprintf(stderr,"line %d: %s\n",__LINE__,#c);failures++;} } while(0)
static void release_owner(void *ctx) {(void)ctx;CHECK(!unlocked);unlocked=1;releases++;}
static void reacquire_owner(void *ctx) {(void)ctx;CHECK(unlocked);unlocked=0;reacquires++;}
static int control_open(const char *path,char *err,size_t cap) {
    (void)path;(void)err;(void)cap;CHECK(setup_mode && unlocked);return 123;
}
static void control_close(int fd) {CHECK(setup_mode && fd==123);}
static int local_socket(int a,int b,int c) {(void)a;(void)b;(void)c;socket_calls++;if(socket_error){errno=socket_error;return -1;}return 123;}
static int local_bind(int fd,const struct sockaddr *a,socklen_t n) {(void)fd;(void)a;(void)n;return 0;}
static int local_sockname(int fd,struct sockaddr *a,socklen_t *n) {
    (void)fd;(void)n;((struct sockaddr_in *)a)->sin_port=htons(50123);return 0;
}
static int local_connect(int fd,const struct sockaddr *a,socklen_t n) {(void)fd;(void)a;(void)n;return 0;}
static ssize_t local_recv(int fd,void *b,size_t n,int flags) {(void)fd;(void)b;(void)n;(void)flags;errno=EAGAIN;return -1;}
static int local_getsockopt(int fd,int level,int option,void *v,socklen_t *n) {(void)fd;(void)level;(void)option;(void)n;*(int *)v=0;return 0;}
static int local_close(int fd) {(void)fd;closed++;return 0;}
static int control_set(int fd,const char *name,uint8_t tr,const char *hex,uint8_t shape,uint16_t port,uint8_t family,
                       const uint8_t *trial,char *err,size_t cap) {
    (void)fd;(void)name;(void)tr;(void)hex;(void)shape;(void)port;(void)family;(void)err;(void)cap;
    memcpy(current_trial,trial,16);events=0;return 0;
}
static int control_next(int fd,d2k_ev *ev,int wait,char *err,size_t cap) {
    (void)fd;(void)wait;(void)err;(void)cap;memset(ev,0,sizeof *ev);
    if(setup_mode) {CHECK(unlocked);ev->kind=D2K_EV_PROTO;ev->send_maxlen=1500;return 0;}
    if(receipt_mode) {
        if(receipt_mode==3)return -1;
        ev->kind=receipt_mode==2?D2K_EV_REFUSED:D2K_EV_APPLIED;
        memcpy(ev->trial_id,current_trial,16);
        if(receipt_mode==1 && !events++)ev->trial_id[15]^=1;
        return 0;
    }
    ev->kind=D2K_EV_ACK;ev->code=D2K_CMD_SET_NAME_PROBE;
    memcpy(ev->trial_id,current_trial,16);
    if(!events++) {ev->trial_id[15]^=1;ev->num=own_success?D2K_ACK_NO_ROOM:1u<<8;}
    else ev->num=own_success?1u<<8:D2K_ACK_NO_ROOM;
    return 0;
}
static int refused(void *ctx,const char *name,uint16_t port,const d2km_program *p,uint32_t e,char *err,size_t cap) {
    (void)ctx;(void)name;(void)port;(void)p;(void)e;snprintf(err,cap,"test executor full");errno=EPIPE;return -1;
}
static void cleanup(void *ctx,const char *name,uint16_t port,uint32_t e) {
    (void)ctx;CHECK(!strcmp(name,"blocked.example") && port==50123 && e==7);
    CHECK(!closed);removed++;errno=EIO;
}
static int diagnostic_arm(void *ctx,const d2km_arm_spec *spec,d2km_observation *obs,d2km_result *res) {
    (void)spec;d2k_exp_task *x=ctx;memset(obs,0,sizeof *obs);
    *res=(d2km_result){D2KM_R_LOCAL_FAIL,ENOBUFS};
    snprintf(x->arm.last_reason,sizeof x->arm.last_reason,"install: errno=55; test executor full");return 0;
}
int main(void) {
    alarm(20);
    /* Real encoder over socketpair: conditional DEL is the old exact key plus
       the complete trial token, with no bind or external socket. */
    int pipefd[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pipefd));
    uint8_t wire[64],token[16]={9};char wire_err[100]={0};
    CHECK(!d2k_link_del_name_probe_trial(pipefd[1],"x",6,1,htons(50000),4,token,wire_err,sizeof wire_err));
    ssize_t frame=read(pipefd[0],wire,sizeof wire);
    CHECK(frame==28 && wire[3]==24 && wire[5]==D2K_CMD_DEL_NAME_PROBE &&
        wire[6]==1 && wire[7]=='x' && wire[8]==1 && wire[9]==4 &&
        wire[10]==0xc3 && wire[11]==0x50 && !memcmp(wire+12,token,16));
    expctl cleanup_ctl={.fd=pipefd[1],.shape=1,.family=4};memcpy(cleanup_ctl.trial,token,16);
    plan_remove(&cleanup_ctl,"x",50000,77);
    frame=read(pipefd[0],wire,sizeof wire);
    CHECK(frame==28 && !memcmp(wire+12,token,16));
    memset(token,0,sizeof token);
    CHECK(d2k_link_del_name_probe_trial(pipefd[1],"x",6,1,htons(50000),4,token,wire_err,sizeof wire_err)<0);
    close(pipefd[0]);close(pipefd[1]);
    d2km_program program={.transport=D2KM_TCP,.protocol=D2KM_P_TLS13,.split_count=1};
    program.splits[0].anchor=D2KM_AT_PAYLOAD_START;program.splits[0].offset=1;
    strcpy(program.splits[0].why,"F1: observed boundary");
    expctl ctl={.fd=123,.shape=1,.family=4};char err[200]={0};
    CHECK(plan_install(&ctl,"blocked.example",50123,&program,7,err,sizeof err)==-1);
    CHECK(events==2 && strstr(err,"2")); /* D2K_ACK_NO_ROOM = 2 */
    own_success=1;
    CHECK(!plan_install(&ctl,"blocked.example",50123,&program,8,err,sizeof err) && events==2);

    receipt_mode=1;events=0;
    CHECK(plan_receipt_wire(&ctl,50123,8,err,sizeof err)==1 && events==2);
    receipt_mode=2;CHECK(!plan_receipt_wire(&ctl,50123,8,err,sizeof err));
    receipt_mode=3;CHECK(!plan_receipt_wire(&ctl,50123,8,err,sizeof err));
    receipt_mode=0;

    d2k_netarm arm={.family=4,.ip="192.0.2.1",.host="blocked.example",.port=443,.install=refused,.remove=cleanup};
    d2km_arm_spec spec={.kind=D2KM_ARM_EXCHANGE,.program=&program,.experiment=7};
    /* Two splits require the datapath, rather than native one-split I/O. */
    program.split_count=2;program.splits[1]=program.splits[0];program.splits[1].offset=2;
    d2km_net net=d2k_netarm_net(&arm);d2km_observation obs;d2km_result res={0};
    CHECK(net.run(net.ctx,&spec,&obs,&res)==0);
    CHECK(res.kind==D2KM_R_LOCAL_FAIL && strstr(arm.last_reason,"test executor full"));
    CHECK(res.value==EPIPE && obs.local_error==EPIPE);
    char expected[64];snprintf(expected,sizeof expected,"install: errno=%d;",EPIPE);
    CHECK(strstr(arm.last_reason,expected));
    CHECK(removed==1); /* accepted remotely but ACK lost: cleanup before port release */
    socket_error=EMFILE;
    CHECK(net.run(net.ctx,&spec,&obs,&res)==0 && res.kind==D2KM_R_LOCAL_FAIL && res.value==EMFILE);
    CHECK(strstr(arm.last_reason,"socket") && strstr(arm.last_reason,"errno="));
    /* The real task retries this local fault, with no box fact/counterexample. */
    static d2km_tls_hello h;
    h.record_version=0x0301;h.version=0x0303;h.ciphers_length=2;
    h.compression_length=1;h.compression_offset=2;h.arena_length=3;h.arena[1]=0x2f;
    assert(d2km_tls_put_ext(&h,0,NULL,0)==D2KM_TLS_OK);
    assert(d2km_tls_set_sni(&h,"blocked.example")==D2KM_TLS_OK);
    uint8_t hello[512];size_t hn=d2km_tls_build(&h,hello,sizeof hello);assert(hn);
    d2k_exp_options options={.host="blocked.example",.ip="192.0.2.1",.port=443,.family=4,
        .client_hello=hello,.client_hello_len=hn};
    d2k_exp_task *retry=d2k_exp_task_open(&options,NULL,NULL,&net,err,sizeof err);assert(retry);
    static d2km_task_report report;socket_calls=0;
    CHECK(d2k_exp_task_run(retry,&report)==D2KM_LOCAL_FAIL);
    CHECK(socket_calls==3 && report.runs==3 && report.experiments==1);
    CHECK(!d2k_exp_task_box(retry)->fact_count && !d2k_exp_task_box(retry)->counter_count);
    d2k_exp_task_close(retry);
    socket_error=0;
    retry=d2k_exp_task_open(&options,NULL,NULL,&net,err,sizeof err);assert(retry);
    retry->underlying=(d2km_net){.ctx=retry,.run=diagnostic_arm};
    CHECK(d2k_exp_task_run(retry,&report)==D2KM_LOCAL_FAIL);
    CHECK(strstr(report.reason,"install:") && strstr(report.reason,"errno=55"));
    d2k_exp_task_close(retry);

    /* A stalled/private PROTO handshake must not retain the catalog owner.
       All real task construction remains in place; only control I/O is replaced. */
    setup_mode=1;options.exp_control="/unused-offline-control";
    options.network_begin=release_owner;options.network_end=reacquire_owner;
    retry=d2k_exp_task_open(&options,NULL,NULL,NULL,err,sizeof err);assert(retry);
    CHECK(releases==1 && reacquires==1 && !unlocked);
    d2k_exp_task_close(retry);setup_mode=0;

    /* A TLS preparation error before any write is our failure, never REPLY.
       Real TLS parser/key setup; only the OS connection is simulated. */
    assert(d2km_tls_put_ext(&h,41,NULL,0)==D2KM_TLS_OK);
    hn=d2km_tls_build(&h,hello,sizeof hello);assert(hn);
    arm=(d2k_netarm){.family=4,.ip="192.0.2.1",.host="blocked.example",.port=443,.exchange_ms=100};
    spec=(d2km_arm_spec){.kind=D2KM_ARM_EXCHANGE,.hello=hello,.hello_length=hn};
    net=d2k_netarm_net(&arm);
    CHECK(!net.run(net.ctx,&spec,&obs,&res));
    CHECK(res.kind==D2KM_R_LOCAL_FAIL && obs.local_error);
    CHECK(strstr(arm.last_reason,"pre_shared_key") && strstr(arm.last_reason,"sent=0"));

    /* Experimental plans must use the datapath's separate ECH shape. */
    uint8_t versions[]={2,3,4},ech[]={0,0,1,0,1,7,0,0,0,1,42};
    assert(d2km_tls_put_ext(&h,43,versions,sizeof versions)==D2KM_TLS_OK);
    assert(d2km_tls_put_ext(&h,0xfe0d,ech,sizeof ech)==D2KM_TLS_OK);
    hn=d2km_tls_build(&h,hello,sizeof hello);assert(hn);
    options.client_hello_len=hn;
    retry=d2k_exp_task_open(&options,NULL,NULL,&net,err,sizeof err);assert(retry);
    CHECK(retry->control.shape==D2K_PLAN_SHAPE_ECH_TCP);
    d2k_exp_task_close(retry);

    char dir[]="/tmp/d2k26-local-XXXXXX",path[256];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/why",dir);d2km_journal journal;
    assert(d2km_journal_open(&journal,path,65536)==D2KM_WHY_OK);
    d2k_exp_task x={0};x.task.journal=&journal;
    x.underlying=(d2km_net){.ctx=&x,.run=diagnostic_arm};
    assert(!d2km_target_name(&x.context.target,"blocked.example"));
    x.context.transport=D2KM_TCP;x.context.protocol=D2KM_P_TLS13;x.context.family=D2KM_IPV4;
    spec.context=&x.context;
    CHECK(!run_arm(&x,&spec,&obs,&res));d2km_journal_close(&journal);
    FILE *f=fopen(path,"r");assert(f);char log[8192]={0};fread(log,1,sizeof log-1,f);fclose(f);
    CHECK(strstr(log,"install: errno=55; test executor full") && !x.arm.last_reason[0]);
    unlink(path);rmdir(dir);
    if(failures)return 1;
    puts("offline experiment ACK correlation, local failures, ordinary TLS why: ok");return 0;
}
