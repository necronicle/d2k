/* No sockets: only the POSIX stream boundary is emulated. Production framing,
 * command restrictions, plan table and journal receipt routing are exercised. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "test_nat_stub.h"
#include "d2k_ctl.h"
#include "d2k_ctlsrv.h"

static struct {uint8_t input[4096],output[4096];size_t in,out;int closed,eof;} streams[16];
static int pending=2;
static int io_socket(int a,int b,int c) {(void)a;(void)b;(void)c;return 1;}
static int io_bind(int f,const struct sockaddr *a,socklen_t n) {(void)f;(void)a;(void)n;return 0;}
static int io_listen(int f,int n) {(void)f;(void)n;return 0;}
static int io_accept(int f,struct sockaddr *a,socklen_t *n) {(void)f;(void)a;(void)n;return pending++;}
static int io_close(int f) {assert(f>0 && f<16);streams[f].closed=1;return 0;}
static int io_unlink(const char *p) {(void)p;return 0;}
static int io_fcntl(int f,int op,...) {(void)f;(void)op;return 0;}
static ssize_t io_read(int f,void *p,size_t n) {
    assert(!streams[f].closed);
    if(!streams[f].in) {if(streams[f].eof)return 0;errno=EAGAIN;return -1;}
    if(n>streams[f].in)n=streams[f].in;
    memcpy(p,streams[f].input,n);streams[f].in-=n;
    memmove(streams[f].input,streams[f].input+n,streams[f].in);return (ssize_t)n;
}
static ssize_t io_write(int f,const void *p,size_t n) {
    assert(!streams[f].closed && streams[f].out+n<=sizeof streams[f].output);
    memcpy(streams[f].output+streams[f].out,p,n);streams[f].out+=n;return (ssize_t)n;
}
#define socket io_socket
#define bind io_bind
#define listen io_listen
#define accept io_accept
#define close io_close
#define unlink io_unlink
#define fcntl io_fcntl
#define read io_read
#define write io_write
#include "ctl.c"
#undef socket
#undef bind
#undef listen
#undef accept
#undef close
#undef unlink
#undef fcntl
#undef read
#undef write

static const uint8_t tiny[]={ 'D','2','K','P',0,1,0,1,0,0,0,1,1,3,0,1,0 };
static void command(d2k_ctl *peer,d2k_session *session,uint16_t type,const uint8_t id[16],uint16_t port) {
    uint8_t *p=streams[d2k_ctl_peer_fd(peer)].input;
    size_t n=6;
    p[n++]=1;p[n++]='x';p[n++]=1;p[n++]=4;
    p[n++]=(uint8_t)(port>>8);p[n++]=(uint8_t)port;
    memcpy(p+n,tiny,sizeof tiny);n+=sizeof tiny;
    memcpy(p+n,id,16);n+=16;
    size_t length=n-4;
    p[0]=p[1]=0;p[2]=(uint8_t)(length>>8);p[3]=(uint8_t)length;
    p[4]=(uint8_t)(type>>8);p[5]=(uint8_t)type;
    streams[d2k_ctl_peer_fd(peer)].in=n;
    d2k_ctlsrv cx={.ctl=peer,.sess=session};
    assert(d2k_ctl_poll(peer,d2k_ctlsrv_command_exp,&cx)==1);
}
static void remove_probe(d2k_ctl *peer,d2k_session *session,const uint8_t id[16],uint16_t port) {
    uint8_t *p=streams[d2k_ctl_peer_fd(peer)].input;
    memset(p,0,28);p[3]=24;p[5]=D2K_CMD_DEL_NAME_PROBE;
    p[6]=1;p[7]='x';p[8]=1;p[9]=4;p[10]=(uint8_t)(port>>8);p[11]=(uint8_t)port;
    memcpy(p+12,id,16);streams[d2k_ctl_peer_fd(peer)].in=28;
    d2k_ctlsrv cx={.ctl=peer,.sess=session};
    assert(d2k_ctl_poll(peer,d2k_ctlsrv_command_exp,&cx)==1);
}
static void receipt(d2k_ctl *mainctl,d2k_session *session,uint64_t *seen,const uint8_t id[16]) {
    d2k_key key={.family=4,.proto=6};
    d2k_journal_add_fate((d2k_journal *)d2k_session_journal(session),1,&key,
        D2K_JRN_PLAN_DONE,0,NULL,id);
    d2k_ctlsrv_pump(mainctl,session,seen);
}
int main(void) {
    D2K_TEST_NAT_NO_TABLE();
    char error[200];d2k_ctl *listener=d2k_ctl_open("/unused",error,sizeof error);assert(listener);
    d2k_ctl *a=d2k_ctl_accept_peer(listener),*b=d2k_ctl_accept_peer(listener);
    assert(a && b && !streams[2].closed && !streams[3].closed);
    d2k_ctlsrv_greet(a,1492);d2k_ctlsrv_greet(b,1492);
    assert(streams[2].out && streams[3].out);
    streams[2].out=streams[3].out=0;
    d2k_session *session=d2k_session_new(16,32);assert(session);
    uint8_t ia[16]={1},ib[16]={2},ic[16]={3};
    command(a,session,D2K_CMD_SET_NAME_PROBE,ia,50001);
    assert(streams[2].out && !streams[3].out);
    streams[2].out=0;
    command(b,session,D2K_CMD_SET_NAME_PROBE,ib,50002);
    assert(!streams[2].out && streams[3].out);
    assert(d2k_session_plan_count(session)==2);
    streams[3].out=0;
    remove_probe(b,session,ia,50001);assert(d2k_session_plan_count(session)==2);
    streams[3].out=0;
    uint64_t seen=0;
    receipt(NULL,session,&seen,ia);assert(streams[2].out && !streams[3].out);
    streams[2].out=0;
    receipt(NULL,session,&seen,ib);assert(!streams[2].out && streams[3].out);
    streams[3].out=0;
    /* A malformed zero trial must not capture ordinary production receipts. */
    uint8_t zero[16]={0};
    command(b,session,D2K_CMD_SET_NAME_PROBE,zero,50004);
    streams[2].out=streams[3].out=0;
    receipt(a,session,&seen,zero);
    assert(streams[2].out && !streams[3].out);streams[2].out=0;
    /* Closing one peer leaves another peer's proof/plan intact. */
    d2k_ctlsrv_forget_exp_ctl(a);d2k_ctl_close(a);
    d2k_ctl *c=d2k_ctl_accept_peer(listener);assert(c);
    command(c,session,D2K_CMD_SET_NAME_PROBE,ic,50003);streams[4].out=0;
    receipt(NULL,session,&seen,ia);assert(!streams[3].out && !streams[4].out);
    receipt(NULL,session,&seen,ib);assert(streams[3].out && !streams[4].out);
    streams[3].out=0;
    /* Many short experiments must not evict a still-running peer's receipt. */
    for(unsigned i=0;i<40;i++) {
        uint8_t next[16]={4};next[1]=(uint8_t)i;
        command(c,session,D2K_CMD_SET_NAME_PROBE,next,50004);
        remove_probe(c,session,next,50004);streams[4].out=0;
    }
    receipt(NULL,session,&seen,ib);assert(streams[3].out && !streams[4].out);
    streams[3].out=0;
    /* An exp peer cannot install production plans or a wildcard probe. */
    size_t plans=d2k_session_plan_count(session);
    command(c,session,D2K_CMD_SET_NAME,ic,50003);
    assert(d2k_session_plan_count(session)==plans);
    command(c,session,D2K_CMD_SET_NAME_PROBE,ic,0);
    assert(d2k_session_plan_count(session)==plans);
    d2k_ctlsrv_forget_exp_ctl(b);d2k_ctlsrv_forget_exp_ctl(c);
    d2k_ctl_close(b);d2k_ctl_close(c);d2k_ctl_close(listener);
    d2k_session_free(session);
    /* The production listener keeps rejecting a second controller. */
    listener=d2k_ctl_open("/unused",error,sizeof error);assert(listener);
    d2k_ctl_accept(listener);d2k_ctl_accept(listener);
    assert(streams[6].closed && !streams[5].closed);d2k_ctl_close(listener);
    puts("offline exp peers: independent ACK/receipt, reconnect, restrictions, singleton main: ok");
    return 0;
}
