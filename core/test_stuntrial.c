#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "d2k_stuntrial.h"
#include "d2k_ctl.h"
#include "d2k_meas.h"

static int fails;
#define CHECK(c,m) do { if(!(c)) { fprintf(stderr,"FAIL: %s\n",m);fails++; } } while(0)
static int mark_ok(int fd,uint32_t mark) { (void)fd;return mark==0x2e?0:-1; }
static int read_all(int fd,uint8_t *b,size_t n) {
    while(n) { ssize_t r=read(fd,b,n);if(r<=0)return -1;b+=r;n-=(size_t)r; }return 0;
}
static size_t command(int fd,uint16_t want,uint8_t *body) {
    uint8_t h[6];if(read_all(fd,h,sizeof h))return 0;
    size_t n=((size_t)h[0]<<24)|((size_t)h[1]<<16)|((size_t)h[2]<<8)|h[3];
    CHECK(h[4]==(want>>8) && h[5]==(want&255),"correct trial command type");
    if(n<2 || n>256)return 0;
    return read_all(fd,body,n-2)?0:n-2;
}
static int bind_flow(int fd,const d2k_stun_flow *f) {
    if(f->family==4) {
        struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=f->source_port_be;
        memcpy(&a.sin_addr,f->source,4);return bind(fd,(void *)&a,sizeof a);
    }
    struct sockaddr_in6 a={0};a.sin6_family=AF_INET6;a.sin6_port=f->source_port_be;
    memcpy(&a.sin6_addr,f->source,16);return bind(fd,(void *)&a,sizeof a);
}
static void held(const d2k_stun_flow *f) {
    int fd=socket(f->family==4?AF_INET:AF_INET6,SOCK_DGRAM,0);
    CHECK(fd>=0 && bind_flow(fd,f)<0 && errno==EADDRINUSE,"uncertain trial retains exclusive source port");
    if(fd>=0)close(fd);
}
typedef struct {int fd,ok;uint16_t port;} server;
static void *reply(void *arg) {
    server *s=arg;struct pollfd p={s->fd,POLLIN,0};
    if(poll(&p,1,500)<=0)return NULL;
    uint8_t req[32],res[32]={0};struct sockaddr_storage peer;socklen_t len=sizeof peer;
    if(recvfrom(s->fd,req,sizeof req,0,(void *)&peer,&len)!=20)return NULL;
    s->ok=(peer.ss_family==AF_INET?((struct sockaddr_in *)&peer)->sin_port:
          ((struct sockaddr_in6 *)&peer)->sin6_port)==s->port;
    memcpy(res,req,20);res[0]=1;res[1]=1;res[3]=12;
    res[21]=0x20;res[23]=8;res[25]=1;res[26]=0x21;res[27]=0x13;
    res[28]=127^0x21;res[29]=0x12;res[30]=0xa4;res[31]=1^0x42;
    sendto(s->fd,res,sizeof res,0,(void *)&peer,len);return NULL;
}
static void run(int af,int mode) {
    int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"control socket pair");
    int fd=socket(af,SOCK_DGRAM,0);CHECK(fd>=0,"UDP server socket");
    struct sockaddr_storage a={0};socklen_t len;
    if(af==AF_INET) {struct sockaddr_in *v=(void *)&a;v->sin_family=af;inet_pton(af,"127.0.0.1",&v->sin_addr);len=sizeof *v;}
    else {struct sockaddr_in6 *v=(void *)&a;v->sin6_family=af;v->sin6_addr=in6addr_loopback;len=sizeof *v;}
    CHECK(!bind(fd,(void *)&a,len) && !getsockname(fd,(void *)&a,&len),"bind UDP service");
    uint16_t port=af==AF_INET?ntohs(((struct sockaddr_in *)&a)->sin_port):ntohs(((struct sockaddr_in6 *)&a)->sin6_port);
    d2k_stun_probe_opt opt={af==AF_INET?"127.0.0.1":"::1",port,100,0x2e};
    uint8_t id[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};char err[160];
    d2k_stun_trial *t=d2k_stun_trial_open(sv[0],&opt,"44324b5000010001000000020002000211030103000100",id,mode==3?1:1000,err,sizeof err);
    CHECK(t!=NULL,"open trial and reserve socket");if(!t){close(fd);close(sv[0]);close(sv[1]);return;}
    d2k_stun_flow flow=*d2k_stun_trial_flow(t);
    uint8_t set[256],del[256];size_t n=command(sv[1],D2K_CMD_SET_ADDR_PROBE,set);
    CHECK(n>58 && set[0]==flow.family && !memcmp(set+1,flow.source,16) &&
          !memcmp(set+17,flow.destination,16) && !memcmp(set+33,&flow.source_port_be,2) &&
          !memcmp(set+35,&flow.destination_port_be,2) && set[37]==17 && !memcmp(set+38,id,16),
          "installation uses exact reserved flow and trial");
    struct pollfd pending={fd,POLLIN,0};
    CHECK(!d2k_stun_trial_start(t) && poll(&pending,1,0)==0,"no payload before matching install ACK");
    CHECK(d2k_stun_trial_free(t)==-1,"cannot free unacknowledged trial");held(&flow);
    d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_SET_ADDR_PROBE;ack.num=0x100;
    memcpy(ack.trial_id,id,16);ack.trial_id[0]^=1;
    CHECK(!d2k_stun_trial_event(t,&ack) && !d2k_stun_trial_start(t),"foreign install ACK cannot start probe");
    ack.trial_id[0]^=1;
    if(mode==2) {
        ack.num=D2K_ACK_BAD_PLAN;
        CHECK(d2k_stun_trial_event(t,&ack)==-1 && !d2k_stun_trial_start(t),"own install refusal never probes");
        CHECK(!d2k_stun_trial_free(t),"explicit noninstallation permits release");
        CHECK(poll(&pending,1,0)==0,"refused trial emits no STUN");
        close(fd);close(sv[0]);close(sv[1]);return;
    }
    if(mode!=1 && mode!=4) {
        CHECK(d2k_stun_trial_event(t,&ack)==1,"own install ACK accepted");
        if(mode==3) {struct timespec pause={0,5000000};nanosleep(&pause,NULL);}
        d2k_stun_socket *socket=d2k_stun_trial_start(t);
        if(mode==3) CHECK(!socket,"expired install lease cannot authorize a late probe");
        else CHECK(socket!=NULL,"matching ACK authorizes reserved socket");
        if(socket) {
            CHECK(d2k_stun_trial_retire(t,sv[0],err,sizeof err)==-1 && d2k_stun_trial_free(t)==-1,
                  "running worker retains socket ownership");
            d2k_stun_trial *owner=t;
            CHECK(d2k_stun_trial_defer(&owner)==-1 && owner==t,
                  "worker ownership cannot be transferred while running");
            if(mode!=3) {
                server s={fd,0,flow.source_port_be};pthread_t worker;
                CHECK(!pthread_create(&worker,NULL,reply,&s),"UDP reply thread");
                d2k_stun_probe_res r=d2k_stun_probe_run(socket);pthread_join(worker,NULL);
                CHECK(r.status==D2K_STUN_BINDING_OK && s.ok,"candidate transaction uses reserved socket");
            }
            CHECK(!d2k_stun_trial_finished(t),"worker completion recorded before retirement");
        }
    }
    CHECK(d2k_stun_trial_retire(t,-1,err,sizeof err)==-1 && d2k_stun_trial_free(t)==-1,
          "failed cleanup write cannot release port");held(&flow);
    CHECK(!d2k_stun_trial_retire(t,sv[0],err,sizeof err),"retry removal command");
    n=command(sv[1],D2K_CMD_DEL_ADDR_PROBE,del);
    CHECK(n==54 && !memcmp(set,del,54),"delete uses only its own exact trial");
    CHECK(!d2k_stun_trial_event(t,&ack) && !d2k_stun_trial_start(t),"late install ACK cannot revive retired candidate");
    ack.code=D2K_CMD_DEL_ADDR_PROBE;ack.trial_id[0]^=1;
    CHECK(!d2k_stun_trial_event(t,&ack) && d2k_stun_trial_free(t)==-1,"foreign removal ACK cannot release port");
    ack.trial_id[0]^=1;ack.num=D2K_ACK_BAD_ARGS;
    CHECK(d2k_stun_trial_event(t,&ack)==-1 && d2k_stun_trial_free(t)==-1,"rejected removal retains port");held(&flow);
    CHECK(!d2k_stun_trial_retire(t,sv[0],err,sizeof err),"idempotent cleanup retry");
    CHECK(command(sv[1],D2K_CMD_DEL_ADDR_PROBE,del)==54,"cleanup retry sent");
    if(mode==4) {
        CHECK(!d2k_stun_trial_defer(&t) && !t && d2k_stun_trial_pending()==1,
              "cancel transfers ownership out of task without releasing port");
        held(&flow);
        CHECK(d2k_stun_trial_retry_pending(-1)==-1 && d2k_stun_trial_pending()==1,
              "disconnected cleanup retains process-owned socket");
        held(&flow);
        CHECK(!d2k_stun_trial_reap(&ack) && d2k_stun_trial_pending()==1,
              "negative delete ACK cannot reap abandoned trial");
        ack.num=0x100;ack.code=D2K_CMD_SET_ADDR_PROBE;
        CHECK(!d2k_stun_trial_reap(&ack),"late install ACK cannot reap abandoned trial");
        ack.code=D2K_CMD_DEL_ADDR_PROBE;ack.trial_id[0]^=1;
        CHECK(!d2k_stun_trial_reap(&ack),"foreign delete ACK cannot reap abandoned trial");
        held(&flow);
        CHECK(!d2k_stun_trial_retry_pending(sv[0]),"pending cleanup retries on current connection");
        CHECK(command(sv[1],D2K_CMD_DEL_ADDR_PROBE,del)==54 && !memcmp(set,del,54),
              "pending cleanup preserves exact flow and owner identity");
        ack.trial_id[0]^=1;
        CHECK(d2k_stun_trial_reap(&ack)==1 && !d2k_stun_trial_pending(),
              "own positive delete ACK releases process-owned socket");
        CHECK(!d2k_stun_trial_reap(&ack),"duplicate delete ACK harmless after release");
    } else {
    ack.num=0x100;CHECK(d2k_stun_trial_event(t,&ack)==1 && !d2k_stun_trial_free(t),"own removal ACK permits release");
    }
    int released=socket(af,SOCK_DGRAM,0);CHECK(released>=0 && !bind_flow(released,&flow),"port released only after removal proof");
    if(released>=0)close(released);
    close(fd);close(sv[0]);close(sv[1]);
}
int main(void) {
    d2k_mark_fn saved=d2k_mark_hook;d2k_mark_hook=mark_ok;
    for(int mode=0;mode<5;mode++){run(AF_INET,mode);run(AF_INET6,mode);}
    d2k_mark_hook=saved;
    if(fails)return 1;
    puts("STUN trial ownership: all checks passed");return 0;
}
