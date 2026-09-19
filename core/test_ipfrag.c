#include <stdio.h>
#include <string.h>
#include "d2k_ipfrag.h"
static int fails;
#define CHECK(x) do {if(!(x)){printf("FAIL %d %s\n",__LINE__,#x);fails++;}}while(0)
static unsigned rd16(const uint8_t *p){return (unsigned)p[0]*256+p[1];}
static unsigned sum(const uint8_t *p,size_t n) {
    unsigned s=0;for(size_t i=0;i<n;i+=2)s+=(unsigned)p[i]*256+(i+1<n?p[i+1]:0);
    while(s>>16)s=(s&65535)+(s>>16);
    return s;
}
int main(void) {
    uint8_t src[4]={10,0,0,1},dst[4]={93,184,216,34},payload[1200],out[4096];
    for(size_t i=0;i<sizeof payload;i++)payload[i]=(uint8_t)i;
    const size_t off[][3]={{0,8,0},{0,8,0},{0,8,24},{0,8,40}};
    const size_t len[][3]={{8,1200,0},{8,1200,0},{8,24,1184},{16,40,1168}};
    for(int shape=1;shape<=4;shape++) {
        d2k_ipfrag_plan p;d2k_ipfrag_span cuts[3],spans[3];
        CHECK(d2k_ipfrag_shape(shape,&p)==0);
        size_t n=d2k_ipfrag_cuts(1208,&p,cuts);
        CHECK(n==(shape<3?2u:3u));
        for(size_t i=0;i<n;i++)CHECK(cuts[i].off==off[shape-1][i] && cuts[i].len==len[shape-1][i]);
        n=d2k_udpfrag_build(src,dst,51234,443,payload,sizeof payload,&p,0x1234,out,sizeof out,spans);
        CHECK(n==(shape<3?2u:3u));
        uint8_t restored[1208]={0};
        for(size_t i=0;i<n;i++) {
            const uint8_t *f=out+spans[i].off;
            size_t logical=p.reverse?n-1-i:i;
            CHECK(f[0]==0x45 && f[8]==64 && f[9]==17 && rd16(f+4)==0x1234);
            CHECK(rd16(f+2)==spans[i].len && sum(f,20)==65535);
            CHECK((rd16(f+6)&8191)*8==cuts[logical].off);
            CHECK(!!(rd16(f+6)&8192)==(logical+1<n));
            memcpy(restored+cuts[logical].off,f+20,spans[i].len-20);
        }
        if(n) {
            CHECK(rd16(restored)==51234 && rd16(restored+2)==443 && rd16(restored+4)==1208);
            CHECK(!memcmp(restored+8,payload,sizeof payload));
            uint8_t pseudo[1220]={0};
            memcpy(pseudo,src,4);memcpy(pseudo+4,dst,4);pseudo[9]=17;pseudo[10]=4;pseudo[11]=184;
            memcpy(pseudo+12,restored,1208);CHECK(sum(pseudo,sizeof pseudo)==65535);
        }
        CHECK(d2k_udpfrag_build(src,dst,1,2,payload,sizeof payload,&p,0,out,sizeof out,spans)==0);
        memset(out,0xab,sizeof out);
        CHECK(d2k_udpfrag_build(src,dst,1,2,payload,sizeof payload,&p,1,out,27,spans)==0);
        CHECK(out[0]==0xab); /* no partial output on insufficient capacity */
    }
    d2k_ipfrag_plan p={.pos1=30};d2k_ipfrag_span cuts[3];
    CHECK(d2k_ipfrag_cuts(1208,&p,cuts)==2 && cuts[0].len==24);
    p.three=1;p.pos1=8;p.pos2=0;
    CHECK(d2k_ipfrag_cuts(1208,&p,cuts)==3 && cuts[1].len==24);
    CHECK(d2k_ipfrag_cuts(20,&p,cuts)==0);
    if(fails)return 1;
    puts("original IP fragments: passed");return 0;
}
