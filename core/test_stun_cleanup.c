#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_sched.h"
#include "d2k_stuntrial.h"
#include "d2k_meas.h"
#include "d2k_ctl.h"
static int fails;
#define CHECK(c,m) do {if(!(c)){fprintf(stderr,"FAIL: %s\n",m);fails++;}}while(0)
static int mark_ok(int fd,uint32_t m){(void)fd;return m==0x2e?0:-1;}
static int read_all(int fd,uint8_t *p,size_t n){
    while(n){struct pollfd q={fd,POLLIN,0};if(poll(&q,1,100)<=0)return -1;
        ssize_t r=read(fd,p,n);if(r<=0)return -1;p+=r;n-=(size_t)r;}return 0;
}
static int command(int fd,uint16_t want,const uint8_t *id){
    uint8_t h[6],b[256];if(read_all(fd,h,6))return -1;
    size_t n=((size_t)h[0]<<24)|((size_t)h[1]<<16)|((size_t)h[2]<<8)|h[3];
    if(n<56||n>sizeof b+2||h[4]!=(want>>8)||h[5]!=(want&255))return -1;
    return read_all(fd,b,n-2)||memcmp(b+38,id,16)?-1:0;
}
static void port_check(const d2k_stun_flow *f,int held){
    int fd=socket(AF_INET,SOCK_DGRAM,0);struct sockaddr_in a={0};
    a.sin_family=AF_INET;a.sin_port=f->source_port_be;memcpy(&a.sin_addr,f->source,4);
    int rc=bind(fd,(void *)&a,sizeof a);
    CHECK(held?(rc<0&&errno==EADDRINUSE):rc==0,"cancelled trial port ownership");close(fd);
}
int main(void){
    d2k_mark_fn saved=d2k_mark_hook;d2k_mark_hook=mark_ok;
    int sv[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,sv))return 2;
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2e);
    if(!s)return 2;
    d2k_stun_probe_opt opt={"127.0.0.1",39478,50,0x2e};uint8_t id[16]={47};char err[160];
    d2k_stun_trial *t=d2k_stun_trial_open(sv[0],&opt,
        "44324b5000010001000000020002000211030103000100",id,1000,err,sizeof err);
    if(!t)return 2;
    d2k_stun_flow flow=*d2k_stun_trial_flow(t);
    CHECK(!command(sv[1],D2K_CMD_SET_ADDR_PROBE,id),"exact installation sent");
    CHECK(!d2k_stun_trial_defer(&t)&&!t,"task cancellation transfers pending ownership");
    d2k_sched_tick(s,1000);
    CHECK(!command(sv[1],D2K_CMD_DEL_ADDR_PROBE,id),"scheduler retries deferred cleanup");
    CHECK(d2k_sched_active(s)==0,"cleanup consumes no measurement slot");
    port_check(&flow,1);
    d2k_sched_free(s);port_check(&flow,1);
    CHECK(d2k_stun_trial_pending()==1,"scheduler destruction preserves unacknowledged cleanup");
    close(sv[0]);close(sv[1]);
    if(socketpair(AF_UNIX,SOCK_STREAM,0,sv))return 2;
    s=d2k_sched_new(&cat,sv[0],0x2e);if(!s)return 2;
    d2k_sched_tick(s,5000);
    CHECK(!command(sv[1],D2K_CMD_DEL_ADDR_PROBE,id),"new scheduler retries on its control connection");
    d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_DEL_ADDR_PROBE;ack.num=0x100;
    memcpy(ack.trial_id,id,16);ack.trial_id[0]^=1;
    d2k_sched_event(s,&ack);port_check(&flow,1);
    ack.trial_id[0]^=1;d2k_sched_event(s,&ack);
    CHECK(d2k_stun_trial_pending()==0,"scheduler reaps only own deletion ACK");
    port_check(&flow,0);d2k_sched_free(s);close(sv[0]);close(sv[1]);
    /* If the scheduler integration is absent, clean the fixture explicitly. */
    d2k_stun_trial_reap(&ack);d2k_mark_hook=saved;
    if(fails)return 1;
    puts("STUN deferred scheduler cleanup: all checks passed");return 0;
}
