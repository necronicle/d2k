/* A real UDP socket -> NFQUEUE -> d2kd -> veth capture. Test-only endpoints. */
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_ipfrag.h"

int fragment_fixture(int,int,uint8_t *,size_t,size_t *);
int fragment_input(uint8_t *,size_t,size_t *);
static unsigned rd16(const uint8_t *b){return (unsigned)b[0]*256+b[1];}
static int echo(int fd,const uint8_t *p,size_t len) {
    struct pollfd f={fd,POLLIN,0};uint8_t b[1606];
    if(poll(&f,1,500)!=1)return 0;
    ssize_t n=recv(fd,b,sizeof b,0);
    return n==(ssize_t)(len+6) && !memcmp(b,"\x0a\x4d\x00\x01\xd6\xd8",6) && !memcmp(b+6,p,len);
}
int fragment_nfq_main(int argc,char **argv) {
    if(argc!=5)return 2;
    int shape=atoi(argv[2]),fake=atoi(argv[3]);
    if(shape<1 || shape>4 || fake<0 || fake>1)return 2;
    if(!strcmp(argv[1],"plan")) {
        uint8_t b[2048];size_t n=0;
        if(fragment_fixture(shape,fake,b,sizeof b,&n))return 1;
        FILE *f=fopen(argv[4],"wb");if(!f)return 1;
        int ok=fwrite(b,1,n,f)==n;return fclose(f)==0 && ok?0:1;
    }
    const char *mode=argv[4];
    int direct=!strcmp(mode,"mtu") || !strcmp(mode,"setupfail");
    int partial=!strcmp(mode,"partial");
    if(!direct && !partial && strcmp(mode,"ok"))return 2;
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK,0);
    struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(54000)},
        server={.sin_family=AF_INET,.sin_port=htons(54321)};
    inet_pton(AF_INET,"10.78.0.2",&local.sin_addr);inet_pton(AF_INET,"10.77.0.2",&server.sin_addr);
    if(fd<0 || bind(fd,(void *)&local,sizeof local) || connect(fd,(void *)&server,sizeof server)) {
        perror("client");return 1;
    }
    int ttl=64;if(setsockopt(fd,IPPROTO_IP,IP_TTL,&ttl,sizeof ttl))return 1;
    if(send(fd,"seed",4,0)!=4 || !echo(fd,(const uint8_t *)"seed",4)) {
        fprintf(stderr,"seed/SNAT did not work\n");return 1;
    }
    int cap=socket(AF_PACKET,SOCK_DGRAM|SOCK_NONBLOCK,htons(ETH_P_ALL));
    struct sockaddr_ll sa={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),
                           .sll_ifindex=(int)if_nametoindex("d2k-out")};
    if(cap<0 || bind(cap,(void *)&sa,sizeof sa))return 1;
    uint8_t payload[1500];size_t len=0;
    if(fragment_input(payload,sizeof payload,&len) || send(fd,payload,len,0)!=(ssize_t)len)return 1;
    uint8_t frames[3][1600];size_t lengths[3]={0};
    size_t nf=0,nfake=0,original=0;int bad=0;unsigned id=0;
    for(int round=0;round<30;round++) {
        struct pollfd wait={cap,POLLIN,0};if(poll(&wait,1,10)<=0)continue;
        for(;;) {
            uint8_t b[4096];struct sockaddr_ll from;socklen_t flen=sizeof from;
            ssize_t n=recvfrom(cap,b,sizeof b,0,(void *)&from,&flen);if(n<0)break;
            if(n<20 || from.sll_pkttype!=PACKET_OUTGOING || b[0]!=0x45 || b[9]!=17 ||
               memcmp(b+16,"\x0a\x4d\x00\x02",4))continue;
            if(memcmp(b+12,"\x0a\x4d\x00\x01",4))bad=1;
            if(rd16(b+6)&0x3fff) {
                if(nf>=3 || n>1600){bad=1;continue;}
                if(!nf)id=rd16(b+4);
                if(!id || rd16(b+4)!=id)bad=1;
                memcpy(frames[nf],b,(size_t)n);lengths[nf++]=(size_t)n;
            } else if(n==32 && !memcmp(b+28,"fake",4)) {
                if(nf || b[8]!=3 || rd16(b+20)!=55000)bad=1;
                nfake++;
            } else if(n==(ssize_t)(28+len) && !memcmp(b+28,payload,len)) {
                original++;
            } else {bad=1;}
        }
    }
    size_t wanted=direct?0:partial?1:shape<=2?2:3;
    size_t wanted_fake=direct?0:fake?2:0;
    if(nf!=wanted || nfake!=wanted_fake || original!=(size_t)direct)bad=1;
    if(nf) {
        d2k_ipfrag_plan p;d2k_ipfrag_span spans[3];uint8_t expected[1600];
        const uint8_t src[]={10,77,0,1},dst[]={10,77,0,2};
        d2k_ipfrag_shape(shape,&p);
        if(!d2k_udpfrag_build(src,dst,55000,54321,payload,len,&p,(uint16_t)id,expected,sizeof expected,spans))return 1;
        for(size_t i=0;i<nf;i++)if(lengths[i]!=spans[i].len ||
            memcmp(frames[i],expected+spans[i].off,lengths[i]))bad=1;
    }
    for(size_t i=0;i<wanted_fake;i++)if(!echo(fd,(const uint8_t *)"fake",4))bad=1;
    int replied=echo(fd,payload,len);
    if((direct || (!partial && shape<=2)) && !replied)bad=1;
    if(partial && replied)bad=1;
    printf("NFQUEUE mode=%s fake=%d shape=%d: fragments=%zu fakes=%zu original=%zu reply=%d bad=%d\n",
           mode,fake,shape,nf,nfake,original,replied,bad);
    close(fd);close(cap);return bad?1:0;
}
