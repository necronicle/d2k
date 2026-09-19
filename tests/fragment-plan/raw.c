/* Actual production raw sender, with conntrack enabled by the runner.
 * Isolated veth/server namespace; no router or outside target. */
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_raw.h"
#include "d2k_ipfrag.h"
#include "d2k_wire.h"
#include "d2k_session.h"
#include "d2k_nat.h"

int fragment_fixture(int shape,int fake,uint8_t *,size_t,size_t *);
int fragment_input(uint8_t *,size_t,size_t *);
static int fail_option;
int d2k_test_setsockopt(int fd,int level,int option,const void *value,socklen_t len) {
    if((fail_option==1 && level==IPPROTO_IP && option==IP_NODEFRAG) ||
       (fail_option==2 && level==SOL_SOCKET && option==SO_MARK)) {
        errno=EPERM;return -1;
    }
    return setsockopt(fd,level,option,value,len);
}
/* The runtime procfs lookup has unit tests. Here provide the tuple verified
 * by the real SNAT echo: the Docker kernel need not expose conntrack procfs. */
static int observed_nat(const char *path,uint8_t proto,uint32_t src,uint16_t sp,
    uint32_t dst,uint16_t dp,uint32_t *out,uint16_t *port) {
    (void)path;
    if(proto!=17 || src!=htonl(0x0a4e0002) || sp!=htons(54000) ||
       dst!=htonl(0x0a4d0002) || dp!=htons(54321))return -1;
    *out=htonl(0x0a4d0001);*port=htons(55000);return 0;
}

static int server_main(void) {
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(54321)};
    if(fd<0 || bind(fd,(void *)&addr,sizeof addr)){perror("server");return 1;}
    for(;;) {
        uint8_t b[1606];struct sockaddr_in peer;socklen_t n=sizeof peer;
        ssize_t got=recvfrom(fd,b+6,sizeof b-6,0,(void *)&peer,&n);
        if(got<0)return 1;
        memcpy(b,&peer.sin_addr.s_addr,4);memcpy(b+4,&peer.sin_port,2);
        if(sendto(fd,b,(size_t)got+6,0,(void *)&peer,n)!=got+6)return 1;
    }
}
static int receive_echo(int client,const uint8_t *payload,size_t len) {
    uint8_t b[1606];struct pollfd p={client,POLLIN,0};
    if(poll(&p,1,500)!=1)return 0;
    ssize_t got=recv(client,b,sizeof b,0);
    return got==(ssize_t)(len+6) && !memcmp(b,"\x0a\x4d\x00\x01\xd6\xd8",6) &&
           !memcmp(b+6,payload,len);
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"server"))return server_main();
    int cap=socket(AF_PACKET,SOCK_DGRAM|SOCK_NONBLOCK,htons(ETH_P_ALL));
    struct sockaddr_ll sa={0};sa.sll_family=AF_PACKET;
    sa.sll_protocol=htons(ETH_P_ALL);sa.sll_ifindex=(int)if_nametoindex("d2k-out");
    if(cap<0 || bind(cap,(struct sockaddr *)&sa,sizeof sa)) {perror("capture");return 1;}
    char err[256];d2k_raw *raw=d2k_raw_open(0,"d2k-out",err,sizeof err);
    if(!raw){fprintf(stderr,"raw: %s\n",err);return 1;}
    /* Establish a REAL SNAT mapping, then derive the fragment context from
       what the server actually observed. This is not a mocked NAT result. */
    int client=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK,0);
    struct sockaddr_in server={.sin_family=AF_INET,.sin_port=htons(54321)},
        local={.sin_family=AF_INET,.sin_port=htons(54000)};
    inet_pton(AF_INET,"10.77.0.2",&server.sin_addr);
    inet_pton(AF_INET,"10.78.0.2",&local.sin_addr);
    if(client<0 || bind(client,(void *)&local,sizeof local) || connect(client,(void *)&server,sizeof server)) {
        perror("UDP endpoints");return 1;
    }
    if(send(client,"seed",4,0)!=4){perror("seed");return 1;}
    if(!receive_echo(client,(const uint8_t *)"seed",4)) {
        fprintf(stderr,"real SNAT mapping not observed\n");return 1;
    }
    uint8_t src[]={10,77,0,1},dst[]={10,77,0,2},payload[1500];size_t payload_len=0;
    if(fragment_input(payload,sizeof payload,&payload_len))return 1;
    {
        d2k_ipfrag_plan p;d2k_ipfrag_span spans[3];uint8_t wire[1600];
        d2k_ipfrag_shape(1,&p);
        if(!d2k_udpfrag_build(src,dst,55000,54321,payload,payload_len,&p,0x1234,wire,sizeof wire,spans))return 1;
        d2k_raw *fault=d2k_raw_open(42,"d2k-out",err,sizeof err);
        if(!fault)return 1;
        for(fail_option=1;fail_option<=2;fail_option++) {
            if(d2k_raw_prepare(fault,wire,spans[0].len,err,sizeof err)==0 ||
               d2k_raw_send(fault,wire,spans[0].len,err,sizeof err)==0 || d2k_raw_sent(fault)) {
                fprintf(stderr,"fragment socket setup failure was ignored\n");return 1;
            }
        }
        fail_option=0;
        if(d2k_raw_prepare(fault,wire,spans[0].len,err,sizeof err))return 1;
        d2k_raw_close(fault);
        puts("NODEFRAG/mark setup failures: no send, no ordinary-socket fallback");
    }
    d2k_nat_hook=observed_nat;
    int fails=0;
    for(int fake=0;fake<2;fake++)for(int shape=1;shape<=4;shape++) {
        uint8_t tlv[2048],input[1600],wire[8192];size_t tn=0;
        if(fragment_fixture(shape,fake,tlv,sizeof tlv,&tn))return 1;
        d2k_plan *plan=NULL;
        if(d2k_plan_load(tlv,tn,&plan,err,sizeof err)){fprintf(stderr,"plan: %s\n",err);return 1;}
        d2k_session *session=d2k_session_new(64,64);
        d2k_session_set_hook(session,D2K_HOOK_POSTROUTING);
        d2k_session_set_plan(session,plan);
        d2k_conn conn={0};conn.src_ip=local.sin_addr.s_addr;conn.dst_ip=server.sin_addr.s_addr;
        conn.src_port=local.sin_port;conn.dst_port=server.sin_port;conn.ttl=64;conn.ip_id=0x1234;
        d2k_emit truth={.bytes=payload,.len=payload_len};
        size_t inlen=d2k_wire_build_udp(&conn,&truth,input,sizeof input);
        d2k_result result;
        d2k_session_packet(session,input,inlen,1000,wire,sizeof wire,&result);
        size_t start=fake?2:0,want=start+(shape<=2?2:3);
        if(!result.applied || result.n_out!=want || result.first_payload!=start ||
           result.verdict!=D2K_VERDICT_DROP){fprintf(stderr,"Plan/session mismatch: %s n=%zu\n",
                result.skipped?result.skipped:"no reason",result.n_out);return 1;}
        uint8_t *head=wire+result.out[start].off;
        unsigned id=(unsigned)head[4]*256+head[5];
        uint8_t expected[1600];d2k_ipfrag_plan p;d2k_ipfrag_span spans[3];
        d2k_ipfrag_shape(shape,&p);
        size_t n=d2k_udpfrag_build(src,dst,55000,54321,payload,payload_len,&p,
                                  (uint16_t)id,expected,sizeof expected,spans);
        for(size_t i=0;i<result.n_out;i++)if(d2k_raw_prepare(raw,wire+result.out[i].off,result.out[i].len,err,sizeof err)) {
            fprintf(stderr,"preflight: %s\n",err);return 1;
        }
        for(size_t i=0;i<result.n_out;i++) {
            if(result.out[i].delay_us || d2k_raw_send(raw,wire+result.out[i].off,result.out[i].len,err,sizeof err)) {
                fprintf(stderr,"send: %s\n",err);return 1;
            }
            d2k_session_sent(session,1100+i,&result.key,result.execution_id);
        }
        if(d2k_session_done(session))return 1;
        d2k_session_sent(session,1200,&result.key,result.execution_id);
        if(d2k_session_done(session)!=1)return 1;
        size_t got=0,got_fake=0;int mismatch=0;
        for(int round=0;round<20;round++) {
            struct pollfd fd={cap,POLLIN,0};if(poll(&fd,1,10)<=0)continue;
            for(;;) {
                uint8_t b[4096];struct sockaddr_ll from;socklen_t flen=sizeof from;
                ssize_t len=recvfrom(cap,b,sizeof b,0,(struct sockaddr *)&from,&flen);
                if(len<0)break;
                if(len<20 || from.sll_pkttype!=PACKET_OUTGOING || b[9]!=17 || memcmp(b+16,dst,4))continue;
                if(!((b[6]&0x3f) || b[7])) {
                    if(len==32 && !memcmp(b+28,"fake",4)) {
                        if(got || b[8]!=3 || memcmp(b+12,src,4) || b[20]!=0xd6 || b[21]!=0xd8)mismatch=1;
                        got_fake++;
                    }
                    continue;
                }
                if((unsigned)b[4]*256+b[5]!=id)continue;
                if(got>=n || (size_t)len!=spans[got].len ||
                   memcmp(b,expected+spans[got].off,(size_t)len))mismatch=1;
                got++;
            }
        }
        printf("fake %d shape %d: fragments=%zu/%zu fakes=%zu/%zu mismatch=%d\n",fake,shape,got,n,got_fake,start,mismatch);
        if(got!=n || got_fake!=start || mismatch)fails++;
        for(size_t i=0;i<start;i++)if(!receive_echo(client,(const uint8_t *)"fake",4)) {
            fprintf(stderr,"fake lost original client's NAT mapping\n");fails++;
        }
        int delivered=receive_echo(client,payload,payload_len);
        if(shape<=2 && !delivered){fprintf(stderr,"non-overlap UDP not delivered\n");fails++;}
        printf("fake %d shape %d: real NAT reply=%d\n",fake,shape,delivered);
        d2k_session_free(session);
    }
    d2k_raw_close(raw);close(cap);close(client);return fails?1:0;
}
