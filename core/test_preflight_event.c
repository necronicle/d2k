/* Preflight facts cross the control boundary without turning into scheduler proof.
 * socketpair only: no listener, router or network is used. */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_link.h"
#include "d2k_ctlsrv.h"

static int fails;
#define CHECK(x) do { if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);fails++;} } while(0)

static void send_event(int fd,uint16_t kind,const uint8_t *rest,size_t len) {
    uint8_t b[6+D2K_KEY_WIRE_LEN+D2K_CTL_PREFLIGHT_LEN+1]={0};
    size_t total=6+D2K_KEY_WIRE_LEN+len;uint32_t plen=(uint32_t)total-4;
    for(unsigned i=0;i<4;i++)b[i]=(uint8_t)(plen>>(24-8*i));
    b[4]=(uint8_t)(kind>>8);b[5]=(uint8_t)kind;
    b[6]=4;b[7]=1;b[23]=192;b[24]=168;b[25]=1;b[26]=3;
    b[39]=1;b[40]=0xbb;b[41]=0xc0;b[42]=1;b[43]=6;
    memcpy(b+6+D2K_KEY_WIRE_LEN,rest,len);
    CHECK(write(fd,b,total)==(ssize_t)total);
}

int main(void) {
    int sv[2];CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,sv)==0);
    if(fails)return 1;
    uint8_t r[D2K_CTL_PREFLIGHT_LEN+1]={0};
    r[0]=D2K_CLIENT_SIDE_HIGH;r[1]=1;r[2]=2;r[3]=3;r[4]=4;
    for(unsigned i=0;i<8;i++)r[5+i]=(uint8_t)(i+1);
    memset(r+13,0x81,D2K_PLAN_ID_LEN);memset(r+13+D2K_PLAN_ID_LEN,0xf2,D2K_TRIAL_ID_LEN);
    d2k_binding_context binding={0};binding.generation=42;binding.epoch[0]=0x90;
    d2k_ctl_binding_write(r+13+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN,&binding);
    const uint16_t kinds[]={D2K_EV_PREFLIGHT_START,D2K_EV_PREFLIGHT_HANDOVER,D2K_EV_PREFLIGHT_GAVE_UP};
    char err[256];d2k_ev ev;
    for(unsigned i=0;i<3;i++) {
        send_event(sv[1],kinds[i],r,D2K_CTL_PREFLIGHT_LEN);
        CHECK(d2k_link_next(sv[0],&ev,100,err,sizeof err)==0);
        CHECK(ev.kind==kinds[i] && ev.family==4 && ev.transport==6 && ev.low_port==443 && ev.high_port==49153);
        CHECK(ev.low_ip[0]==1 && ev.high_ip[0]==192 && ev.client_side==D2K_CLIENT_SIDE_HIGH);
        CHECK(ev.num==0x01020304 && ev.preflight_elapsed_ns==UINT64_C(0x0102030405060708));
        CHECK(ev.plan_id[0]==0x81 && ev.trial_id[0]==0xf2 && ev.execution_binding.generation==42 && ev.execution_binding.epoch[0]==0x90);
        CHECK(ev.execution_id==0);
    }
    for(unsigned n=0;n<D2K_CTL_PREFLIGHT_LEN;n++) {
        send_event(sv[1],kinds[0],r,n);
        CHECK(d2k_link_next(sv[0],&ev,100,err,sizeof err)==-1);
    }
    send_event(sv[1],kinds[0],r,D2K_CTL_PREFLIGHT_LEN+1);
    CHECK(d2k_link_next(sv[0],&ev,100,err,sizeof err)==-1);
    r[0]=0;send_event(sv[1],kinds[0],r,D2K_CTL_PREFLIGHT_LEN);
    CHECK(d2k_link_next(sv[0],&ev,100,err,sizeof err)==-1);
    r[0]=3;send_event(sv[1],kinds[0],r,D2K_CTL_PREFLIGHT_LEN);
    CHECK(d2k_link_next(sv[0],&ev,100,err,sizeof err)==-1);
    r[0]=D2K_CLIENT_SIDE_HIGH;
    r[13+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN+8]=255;
    send_event(sv[1],kinds[0],r,D2K_CTL_PREFLIGHT_LEN);
    CHECK(d2k_link_next(sv[0],&ev,100,err,sizeof err)==-1);
    close(sv[0]);close(sv[1]);
    if(fails)return 1;
    puts("preflight events: fields and malformed frames passed");return 0;
}
