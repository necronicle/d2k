#include <stdio.h>
#include <string.h>
#include "d2k_rawmeasure.h"
static int fails;
#define CHECK(x) do { if (!(x)) {printf("FAIL line %d: %s\n",__LINE__,#x);fails++;} } while(0)
static size_t packet(uint8_t *p,int proto,int reply,int len,uint32_t seq,int flags) {
    memset(p,0,4096);size_t h=proto==6?20:8,n=20+h+(size_t)len;
    p[0]=0x45;p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n;p[8]=64;p[9]=(uint8_t)proto;
    p[12]=reply?2:1;p[16]=reply?1:2;
    p[20]=reply?0x01:0x9c;p[21]=reply?0xbb:0x40;
    p[22]=reply?0x9c:0x01;p[23]=reply?0x40:0xbb;
    if(proto==6){p[24]=(uint8_t)(seq>>24);p[25]=(uint8_t)(seq>>16);p[26]=(uint8_t)(seq>>8);p[27]=(uint8_t)seq;p[32]=0x50;p[33]=(uint8_t)flags;}
    else {p[24]=(uint8_t)((h+len)>>8);p[25]=(uint8_t)(h+len);}
    memset(p+20+h,'x',(size_t)len);return n;
}
static size_t packet6(uint8_t *p,int proto,int reply,int len,uint32_t seq,int flags) {
    size_t n=packet(p,proto,reply,len,seq,flags),payload=n-20;
    memmove(p+40,p+20,payload);memset(p,0,40);
    p[0]=0x60;p[4]=(uint8_t)(payload>>8);p[5]=(uint8_t)payload;p[6]=(uint8_t)proto;p[7]=64;
    p[23]=reply?2:1;p[39]=reply?1:2;
    return n+20;
}
static d2k_ct_tuple tuple(int proto) {
    d2k_ct_tuple t={0};t.family=4;t.proto=(uint8_t)proto;t.src[0]=1;t.dst[0]=2;
    t.sport_be[0]=0x9c;t.sport_be[1]=0x40;t.dport_be[0]=1;t.dport_be[1]=0xbb;return t;
}
static void tcp_ack_progress(void) {
    const uint32_t starts[]={1000,0xfffffff0u};
    for(int family=4;family<=6;family+=2)for(size_t i=0;i<2;i++) {
        struct d2k_rawmeasure m;uint8_t p[4096];d2k_ct_tuple t=tuple(6);
        if(family==6){t.family=6;memset(t.src,0,16);memset(t.dst,0,16);t.src[15]=1;t.dst[15]=2;}
        size_t (*build)(uint8_t *,int,int,int,uint32_t,int)=family==6?packet6:packet;
        size_t off=family==6?40:20,n;uint32_t seq=starts[i];
        d2k_rawmeasure_init(&m,&t,50,1);
        n=build(p,6,0,100,seq,0x18);d2k_rawmeasure_feed(&m,50,p,n,0);
        n=build(p,6,1,0,7000,0x10);
        for(unsigned j=0;j<4;j++)p[off+8+j]=(uint8_t)(seq>>(24-8*j));
        d2k_rawmeasure_feed(&m,50,p,n,0);
        CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_PENDING);
        n=build(p,6,0,100,seq,0x18);d2k_rawmeasure_feed(&m,50,p,n,0);
        CHECK(m.server_packets==1 && m.exact_repeats==1);
        CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_REPEAT_SILENT);
        n=build(p,6,1,0,7000,0x10);uint32_t end=seq+100;
        for(unsigned j=0;j<4;j++)p[off+8+j]=(uint8_t)(end>>(24-8*j));
        d2k_rawmeasure_feed(&m,50,p,n,0);
        CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_SERVER_PRESENT);
        for(unsigned j=0;j<4;j++)p[off+8+j]=(uint8_t)(seq>>(24-8*j));
        d2k_rawmeasure_feed(&m,50,p,n,0);
        CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_SERVER_PRESENT);
        d2k_rawmeasure_init(&m,&t,51,1);
        d2k_rawmeasure_feed(&m,51,p,n,0); /* duplicate ACK before the sample */
        CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_PENDING);
        CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_UNINFORMATIVE);
        n=build(p,6,0,100,seq,0x18);d2k_rawmeasure_feed(&m,51,p,n,0);d2k_rawmeasure_feed(&m,51,p,n,0);
        CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_REPEAT_SILENT);
        n=build(p,6,1,0,7000,0x10);uint32_t partial=seq+50;
        for(unsigned j=0;j<4;j++)p[off+8+j]=(uint8_t)(partial>>(24-8*j));
        d2k_rawmeasure_feed(&m,51,p,n,0);
        CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_REPEAT_SILENT);
    }
}
/* Copy times are recorded facts: the gap is between the LAST two exact
   copies, a changed packet neither repeats nor moves them. */
static void repeat_timing(void) {
    for(int proto=6;proto<=17;proto+=11) {
        struct d2k_rawmeasure m;uint8_t p[4096];size_t n;d2k_ct_tuple t=tuple(proto);
        d2k_rawmeasure_init(&m,&t,60,1);n=packet(p,proto,0,100,5000,0x18);
        const uint64_t s=1000000000ull;
        CHECK(d2k_rawmeasure_feed(&m,60,p,n,10*s));
        CHECK(m.sample_ns==10*s && m.last_copy_ns==10*s && m.prev_copy_ns==10*s);
        CHECK(d2k_rawmeasure_feed(&m,60,p,n,74*s));
        CHECK(m.exact_repeats==1 && m.prev_copy_ns==10*s && m.last_copy_ns==74*s);
        CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_REPEAT_SILENT);
        CHECK(d2k_rawmeasure_feed(&m,60,p,n,202*s));
        CHECK(m.exact_repeats==2 && m.prev_copy_ns==74*s && m.last_copy_ns==202*s && m.sample_ns==10*s);
        p[n-1]='q';CHECK(d2k_rawmeasure_feed(&m,60,p,n,300*s));
        CHECK(m.changed && m.exact_repeats==2 && m.last_copy_ns==202*s);
        CHECK(d2k_rawmeasure_feed(&m,61,p,n,301*s)==0);
    }
}
int main(void) {
    repeat_timing();
    tcp_ack_progress();
    struct d2k_rawmeasure m;uint8_t p[4096],copy[4096];size_t n;d2k_ct_tuple t=tuple(6);
    d2k_rawmeasure_init(&m,&t,7,0);
    n=packet(p,6,0,100,1000,0x18);memcpy(copy,p,n);
    CHECK(d2k_rawmeasure_feed(&m,8,p,n,0)==0);CHECK(!m.client_packets);
    CHECK(d2k_rawmeasure_feed(&m,7,p,n,0)==1);CHECK(!memcmp(copy,p,n));
    CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_PENDING);
    CHECK(d2k_rawmeasure_feed(&m,7,p,n,0)==1);
    CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_REPEAT_SILENT);
    CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_REPEAT_SILENT);
    CHECK(m.sample_len==100 && m.exact_repeats==1);
    n=packet(p,6,1,0,0,0x10);p[30]=4;p[31]=0x4c; /* ACK1100 covers sample. */
    d2k_rawmeasure_feed(&m,7,p,n,0);
    CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_SERVER_PRESENT);
    d2k_rawmeasure_init(&m,&t,9,0);n=packet(p,6,0,0,0,0x10);
    d2k_rawmeasure_feed(&m,9,p,n,0);d2k_rawmeasure_feed(&m,9,p,n,0);
    CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_UNINFORMATIVE);
    n=packet(p,6,0,100,1000,0x18);d2k_rawmeasure_feed(&m,9,p,n,0);p[40]='y';d2k_rawmeasure_feed(&m,9,p,n,0);
    CHECK(m.exact_repeats==0);CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_UNINFORMATIVE);
    n=packet(p,6,0,100,1000,0x02);d2k_rawmeasure_feed(&m,9,p,n,0);
    CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_CLOSED);
    t=tuple(17);d2k_rawmeasure_init(&m,&t,10,0);n=packet(p,17,0,100,0,0);
    d2k_rawmeasure_feed(&m,10,p,n,0);d2k_rawmeasure_feed(&m,10,p,n,0);
    CHECK(m.exact_repeats==1);CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_UNINFORMATIVE);
    CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_UNINFORMATIVE);
    d2k_rawmeasure_init(&m,&t,11,1);d2k_rawmeasure_feed(&m,11,p,n,0);d2k_rawmeasure_feed(&m,11,p,n,0);
    CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_REPEAT_SILENT);
    CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_REPEAT_SILENT);
    d2k_rawmeasure_init(&m,&t,12,1);n=packet(p,17,0,2200,0,0);d2k_rawmeasure_feed(&m,12,p,n,0);
    CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_UNMEASURED);
    /* Foreign packets and malformed/fragmented packets must not pollute evidence. */
    t=tuple(6);d2k_rawmeasure_init(&m,&t,13,0);n=packet(p,6,0,100,1000,0x18);
    p[21]++;CHECK(!d2k_rawmeasure_feed(&m,13,p,n,0));p[21]--;
    CHECK(!d2k_rawmeasure_feed(&m,13,p,n-1,0));
    p[6]=0x20;CHECK(!d2k_rawmeasure_feed(&m,13,p,n,0));p[6]=0;
    p[32]=0x40;CHECK(!d2k_rawmeasure_feed(&m,13,p,n,0));p[32]=0x50;
    CHECK(m.client_packets==0 && !m.sampled);
    n=packet(p,6,0,100,1000,0x18);d2k_rawmeasure_feed(&m,13,p,n,0);d2k_rawmeasure_feed(&m,13,p,n,0);
    p[40]='z';d2k_rawmeasure_feed(&m,13,p,n,0);CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_UNINFORMATIVE);
    n=packet(p,6,1,0,0,0x04);d2k_rawmeasure_feed(&m,13,p,n,0);CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_CLOSED);
    t=tuple(17);d2k_rawmeasure_init(&m,&t,14,1);n=packet(p,17,0,100,0,0);
    p[25]--;CHECK(!d2k_rawmeasure_feed(&m,14,p,n,0));p[25]+=2;CHECK(!d2k_rawmeasure_feed(&m,14,p,n,0));
    CHECK(m.client_packets==0);
    for(int proto=6;proto<=17;proto+=11) {
        t=tuple(proto);t.family=6;memset(t.src,0,16);memset(t.dst,0,16);t.src[15]=1;t.dst[15]=2;
        d2k_rawmeasure_init(&m,&t,15,1);n=packet6(p,proto,0,100,0xfffffff0u,0x18);
        memcpy(copy,p,n);CHECK(d2k_rawmeasure_feed(&m,15,p,n,0));CHECK(d2k_rawmeasure_feed(&m,15,p,n,0));
        CHECK(!memcmp(copy,p,n));CHECK(d2k_rawmeasure_result(&m,0)==D2K_RM_REPEAT_SILENT);
        CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_REPEAT_SILENT);
        p[6]=44;CHECK(!d2k_rawmeasure_feed(&m,15,p,n,0));p[6]=(uint8_t)proto;
        p[39]=3;CHECK(!d2k_rawmeasure_feed(&m,15,p,n,0));p[39]=2;
        CHECK(m.client_packets==2);
        n=packet6(p,proto,1,4,100,0x18);
        if(proto==6)p[51]=84; /* wraparound ACK covers fffffff0 + 100. */
        CHECK(d2k_rawmeasure_feed(&m,15,p,n,0));
        CHECK(d2k_rawmeasure_result(&m,1)==D2K_RM_SERVER_PRESENT);
        d2k_rawmeasure_init(&m,&t,16,0);CHECK(!m.sampled && !m.exact_repeats);
        CHECK(!d2k_rawmeasure_feed(&m,15,p,n,0));CHECK(!m.server_packets);
    }
    puts(fails?"raw measurement FAILED":"raw measurement passed");return fails!=0;
}
