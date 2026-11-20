#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_stunprobe.h"
#include "d2k_meas.h"

static int fails;
#define CHECK(c,m) do { if (!(c)) { fprintf(stderr,"FAIL: %s\n",m); fails++; } } while(0)
typedef struct { int fd, mode, received; uint16_t observed_port_be; uint8_t request_id[12]; } server;
static void *serve(void *arg) {
    server *s=arg;
    struct pollfd p={s->fd,POLLIN,0};
    if(poll(&p,1,400)<=0)return NULL;
    uint8_t req[256],out[64]={0};
    struct sockaddr_storage peer; socklen_t npeer=sizeof peer;
    ssize_t n=recvfrom(s->fd,req,sizeof req,0,(void *)&peer,&npeer);
    if(n!=20 || req[0]!=0 || req[1]!=1)return NULL;
    s->received++;
    memcpy(s->request_id,req+8,sizeof s->request_id);
    s->observed_port_be=peer.ss_family==AF_INET?((struct sockaddr_in *)&peer)->sin_port:
                                               ((struct sockaddr_in6 *)&peer)->sin6_port;
    if(s->mode==1)return NULL; /* silence */
    memcpy(out,req,20);out[0]=1;out[1]=1;
    /* Neither a bare success header nor malformed attributes prove Binding. */
    sendto(s->fd,out,20,0,(void *)&peer,npeer);
    out[3]=4;out[20]=0x80;out[21]=0x22;out[23]=8;
    sendto(s->fd,out,24,0,(void *)&peer,npeer);
    if(s->mode==2)return NULL;
    out[3]=12;out[20]=0;out[21]=0x20;out[22]=0;out[23]=8;
    out[24]=0;out[25]=1;
    unsigned port=54321u ^ 0x2112u;
    out[26]=(uint8_t)(port>>8);out[27]=(uint8_t)port;
    const uint8_t address[]={192^0x21,0^0x12,2^0xa4,1^0x42};
    memcpy(out+28,address,4);
    out[8]^=1;
    sendto(s->fd,out,32,0,(void *)&peer,npeer); /* alien transaction */
    out[8]^=1;
    sendto(s->fd,out,32,0,(void *)&peer,npeer);
    return NULL;
}
static int mark_fail(int fd,uint32_t mark) { (void)fd;(void)mark;errno=EPERM;return -1; }
static void run(int af,int mode,int refused_mark) {
    int fd=socket(af,SOCK_DGRAM,0);
    CHECK(fd>=0,"server socket");if(fd<0)return;
    struct sockaddr_storage addr;memset(&addr,0,sizeof addr);
    socklen_t len;
    if(af==AF_INET){struct sockaddr_in *a=(void *)&addr;a->sin_family=af;inet_pton(AF_INET,"127.0.0.1",&a->sin_addr);len=sizeof *a;}
    else {struct sockaddr_in6 *a=(void *)&addr;a->sin6_family=af;a->sin6_addr=in6addr_loopback;len=sizeof *a;}
    int rc=bind(fd,(void *)&addr,len);
    CHECK(rc==0,"bind loopback");if(rc){close(fd);return;}
    getsockname(fd,(void *)&addr,&len);
    uint16_t port=af==AF_INET?ntohs(((struct sockaddr_in *)&addr)->sin_port):ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
    server s={.fd=fd,.mode=mode};pthread_t thread;
    rc=pthread_create(&thread,NULL,serve,&s);CHECK(rc==0,"server thread");if(rc){close(fd);return;}
    d2k_mark_fn saved=d2k_mark_hook;
    if(refused_mark)d2k_mark_hook=mark_fail;
    d2k_stun_probe_opt opt={af==AF_INET?"127.0.0.1":"::1",port,100,refused_mark?123u:0u};
    d2k_stun_probe_res r=d2k_stun_probe(&opt);
    pthread_join(thread,NULL);close(fd);d2k_mark_hook=saved;
    if(refused_mark){CHECK(r.status==D2K_STUN_LOCAL_ERROR && !r.sent && !s.received,"failed mark must not emit a probe");return;}
    CHECK(r.sent && s.received==1,"one real request emitted");
    if(mode){CHECK(r.status==D2K_STUN_TIMEOUT,"silence or invalid reply is inconclusive timeout");}
    else {
        CHECK(r.status==D2K_STUN_BINDING_OK,"valid Binding response accepted");
        const uint8_t expected[]={192,0,2,1};
        CHECK(r.mapped_family==4 && r.mapped_port==54321 && !memcmp(r.mapped_ip,expected,4),"mapped endpoint decoded");
        CHECK(r.rejected==3,"bare, malformed and alien responses rejected before valid response");
    }
}
static void reserved(int af, int cancel) {
    int fd=socket(af,SOCK_DGRAM,0);
    CHECK(fd>=0,"reserved fixture socket");if(fd<0)return;
    struct sockaddr_storage a={0};socklen_t alen;
    if(af==AF_INET) {
        struct sockaddr_in *v=(void *)&a;v->sin_family=af;inet_pton(AF_INET,"127.0.0.1",&v->sin_addr);alen=sizeof *v;
    } else {
        struct sockaddr_in6 *v=(void *)&a;v->sin6_family=af;v->sin6_addr=in6addr_loopback;alen=sizeof *v;
    }
    CHECK(bind(fd,(void *)&a,alen)==0,"reserved fixture bind");
    CHECK(getsockname(fd,(void *)&a,&alen)==0,"reserved fixture endpoint");
    uint16_t port_be=af==AF_INET?((struct sockaddr_in *)&a)->sin_port:((struct sockaddr_in6 *)&a)->sin6_port;
    d2k_stun_probe_opt opt={af==AF_INET?"127.0.0.1":"::1",ntohs(port_be),100,0};
    d2k_stun_flow flow;d2k_stun_probe_res error;
    d2k_stun_socket *reserved_socket=d2k_stun_probe_open(&opt,&flow,&error);
    CHECK(reserved_socket!=NULL,"reserve exact STUN socket before trial installation");
    if(!reserved_socket){close(fd);return;}
    uint8_t expected[16]={0};inet_pton(af,opt.ip,expected);
    CHECK(flow.family==(af==AF_INET?4:6) && flow.source_port_be &&
          flow.destination_port_be==port_be && !memcmp(flow.destination,expected,16) &&
          !memcmp(flow.source,expected,16),"reservation exposes exact numeric flow");
    struct pollfd pending={fd,POLLIN,0};
    CHECK(poll(&pending,1,0)==0,"reservation must not emit before trial ACK");
    if(cancel) {
        d2k_stun_probe_close(reserved_socket);
        CHECK(poll(&pending,1,20)==0,"cancel before ACK emits no request");
    } else {
        server s={.fd=fd};pthread_t thread;
        int rc=pthread_create(&thread,NULL,serve,&s);CHECK(rc==0,"reserved server thread");
        if(!rc) {
            d2k_stun_probe_res r=d2k_stun_probe_run(reserved_socket);
            pthread_join(thread,NULL);
            CHECK(r.status==D2K_STUN_BINDING_OK && r.sent,"reserved socket validates Binding response");
            CHECK(s.observed_port_be==flow.source_port_be,"run uses reserved source port, not a replacement socket");
            server second={.fd=fd};
            rc=pthread_create(&thread,NULL,serve,&second);CHECK(rc==0,"second reserved transaction thread");
            if(!rc) {
                r=d2k_stun_probe_run(reserved_socket);pthread_join(thread,NULL);
                CHECK(r.status==D2K_STUN_BINDING_OK && second.observed_port_be==flow.source_port_be,
                      "second transaction retains reserved socket");
                CHECK(memcmp(s.request_id,second.request_id,sizeof s.request_id)!=0,
                      "each reserved transaction gets a fresh identity");
            }
        }
        d2k_stun_probe_close(reserved_socket);
    }
    /* The owner releases the reservation even when no request was sent. */
    int released=socket(af,SOCK_DGRAM,0);
    if(af==AF_INET) ((struct sockaddr_in *)&a)->sin_port=flow.source_port_be;
    else ((struct sockaddr_in6 *)&a)->sin6_port=flow.source_port_be;
    CHECK(released>=0 && bind(released,(void *)&a,alen)==0,"close releases reserved port");
    if(released>=0) close(released);
    close(fd);
}

int main(void){
    reserved(AF_INET,0);reserved(AF_INET6,0);reserved(AF_INET,1);reserved(AF_INET6,1);
    run(AF_INET,0,0);run(AF_INET6,0,0);run(AF_INET,1,0);run(AF_INET,2,0);run(AF_INET,0,1);
    d2k_stun_probe_opt bad={"not-an-ip",3478,100,0};
    d2k_stun_probe_res r=d2k_stun_probe(&bad);
    CHECK(r.status==D2K_STUN_LOCAL_ERROR && !r.sent,"invalid address is local error");
    if (fails) return 1;
    puts("STUN endpoint probe: all checks passed");
    return 0;
}
