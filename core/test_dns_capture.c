#include "d2k_dns_capture.h"
#include <assert.h>
#include <string.h>

static void put16(uint8_t *p,unsigned value) {p[0]=(uint8_t)(value>>8);p[1]=(uint8_t)value;}
static void put32(uint8_t *p,uint32_t value) {p[0]=value>>24;p[1]=value>>16;p[2]=value>>8;p[3]=value;}

static void exercise(int v6,int tcp) {
    static const uint8_t query[]={
        0,37,1,0,0,1,0,0,0,0,0,0,
        4,'_','s','v','c',7,'E','x','a','m','p','l','e',0,0,33,0,1
    };
    uint8_t packet[128]={0},dst[16],expected[16]={0};
    expected[0]=v6?0xfd:192;expected[v6?15:3]=1;
    size_t ip=v6?40:20,header=tcp?22:8;
    size_t total=ip+header+sizeof query;
    packet[0]=v6?0x60:0x45;packet[v6?6:9]=tcp?6:17;
    put16(packet+(v6?4:2),(unsigned)(v6?total-ip:total));
    memcpy(packet+(v6?24:16),expected,v6?16:4);put16(packet+ip+2,53);
    if(tcp) {packet[ip+12]=0x50;packet[ip+13]=0x18;put16(packet+ip+20,sizeof query);}
    else put16(packet+ip+4,(unsigned)(header+sizeof query));
    memcpy(packet+ip+header,query,sizeof query);
    char name[256];uint16_t type;int family;
    assert(d2k_dns_capture_question(packet,total,dst,&family,name,&type));
    assert(!strcmp(name,"_svc.Example")&&type==33&&family==(v6?6:4));
    assert(!memcmp(dst,expected,sizeof dst));
    assert(!d2k_dns_capture_question(packet,total-1,dst,&family,name,&type));
    packet[ip+header+2]=0x81;assert(!d2k_dns_capture_question(packet,total,dst,&family,name,&type));
    packet[ip+header+2]=1;put16(packet+ip+2,5353);
    assert(!d2k_dns_capture_question(packet,total,dst,&family,name,&type));
}

static size_t label(uint8_t *p,const char *part,size_t n) {p[0]=n;memcpy(p+1,part,n);return n+1;}
static size_t dns_response(uint8_t *p,int v6,int tcp,uint16_t qtype,int cname,int second,uint32_t ttl) {
    uint8_t dns[512]={0};size_t n=12;
    dns[2]=0x81;dns[3]=0x80;put16(dns+4,1);put16(dns+6,(cname?1:0)+1+(second!=0));
    n+=label(dns+n,"video",5);n+=label(dns+n,"example",7);dns[n++]=0;
    put16(dns+n,qtype);put16(dns+n+2,1);n+=4;
    size_t owner=12;
    if(cname) {
        dns[n++]=0xc0;dns[n++]=0x0c;put16(dns+n,5);put16(dns+n+2,1);put32(dns+n+4,ttl);n+=8;
        size_t rd=n;n+=2;owner=n;n+=label(dns+n,"media",5);n+=label(dns+n,"example",7);dns[n++]=0;
        put16(dns+rd,(uint16_t)(n-rd-2));
    }
    for(int i=0;i<1+(second!=0);i++) {
        dns[n++]=0xc0;dns[n++]=(uint8_t)owner;put16(dns+n,qtype);put16(dns+n+2,1);put32(dns+n+4,ttl);n+=8;
        size_t bytes=qtype==1?4:16;put16(dns+n,(uint16_t)bytes);n+=2;
        if(qtype==1) {dns[n]=192;dns[n+1]=0;dns[n+2]=2;dns[n+3]=8+i;}
        else {dns[n]=0x20;dns[n+1]=1;dns[n+2]=0xd;dns[n+3]=0xb8;dns[n+15]=8+i;}
        n+=bytes;
    }
    size_t ip=v6?40:20,header=tcp?22:8,total=ip+header+n;
    memset(p,0,total);p[0]=v6?0x60:0x45;p[v6?6:9]=tcp?6:17;
    put16(p+(v6?4:2),(unsigned)(v6?total-ip:total));
    const uint8_t resolver4[]={192,168,1,1},client4[]={198,51,100,7};
    if(v6) {p[8]=0xfd;p[8+15]=1;p[24]=0xfd;p[24+15]=2;}
    else {memcpy(p+12,resolver4,4);memcpy(p+16,client4,4);}
    put16(p+ip,53);put16(p+ip+2,41000);
    if(tcp) {p[ip+12]=0x50;p[ip+13]=0x18;put16(p+ip+20,(unsigned)n);memcpy(p+ip+22,dns,n);}
    else {put16(p+ip+4,(unsigned)(8+n));memcpy(p+ip+8,dns,n);}
    return total;
}

static void exercise_answer(int v6,int tcp) {
    uint8_t packet[1024];d2k_dns_answer answer;
    size_t total=dns_response(packet,v6,tcp,v6?28:1,1,1,30);
    int rc=d2k_dns_capture_answer(packet,total,&answer);
    assert(rc);
    assert(answer.family==(v6?6:4) && answer.count==2 && answer.ttl==30 && answer.type==(v6?28:1));
    assert(!strcmp(answer.name,"media.example"));
    assert(!strcmp(answer.question,"video.example"));
    if(v6) {assert(answer.server[0]==0xfd && answer.server[15]==1);assert(answer.client[0]==0xfd&&answer.client[15]==2);assert(answer.addresses[1][15]==9);}
    else {assert(!memcmp(answer.client,"\xc6\x33\x64\x07",4));assert(answer.addresses[0][3]==8&&answer.addresses[1][3]==9);}
    assert(!d2k_dns_capture_answer(packet,total-1,&answer));
    size_t dns=(v6?40:20)+(tcp?22:8);
    packet[dns+2]|=2; /* partial RRsets do not replace a learned set */
    assert(!d2k_dns_capture_answer(packet,total,&answer));
    packet[dns+2]&=~2;
    size_t last=total-(v6?28:16);
    packet[last+1]=18; /* unrelated RR owned by example */
    assert(d2k_dns_capture_answer(packet,total,&answer) && answer.count==1);
    put32(packet+dns+31+6,3);
    assert(d2k_dns_capture_answer(packet,total,&answer) && answer.ttl==3);
    packet[(v6?40:20)+(tcp?24:10)]=0; /* QR=0 is not an answer. */
    assert(!d2k_dns_capture_answer(packet,total,&answer));
}

int main(void) {
    for(int v6=0;v6<2;v6++)for(int tcp=0;tcp<2;tcp++) {exercise(v6,tcp);exercise_answer(v6,tcp);}
    return 0;
}
