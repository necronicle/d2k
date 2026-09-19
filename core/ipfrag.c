/* Original quicprobe/frag.go C port; see THIRD_PARTY_NOTICES.md. */
#include <string.h>
#include "d2k_ipfrag.h"

int d2k_ipfrag_shape(int shape, d2k_ipfrag_plan *p) {
    if (!p || shape<1 || shape>4) return -1;
    memset(p,0,sizeof *p);
    p->pos1=8;
    p->reverse=shape>1;
    if(shape>=3) {
        p->three=1;p->overlap12=p->overlap23=8;
        p->pos1=shape==3?8:16;
        p->pos2=shape==3?32:48;
    }
    return 0;
}

size_t d2k_ipfrag_cuts(size_t total, const d2k_ipfrag_plan *p, d2k_ipfrag_span cuts[3]) {
    if(!p || !cuts || total>65515 || p->three>1 || p->reverse>1) return 0;
    size_t pos1=p->pos1 & ~(size_t)7;
    if(pos1<8)pos1=8;
    if(pos1>=total)return 0;
    if(!p->three) {
        cuts[0]=(d2k_ipfrag_span){0,pos1};
        cuts[1]=(d2k_ipfrag_span){pos1,total-pos1};
        return 2;
    }
    if(total<=24)return 0;
    size_t pos2=p->pos2?p->pos2:pos1+24;
    pos2&=~(size_t)7;
    size_t ov12=p->overlap12&~(size_t)7,ov23=p->overlap23&~(size_t)7;
    if(pos2<=pos1)pos2=pos1+8;
    if(pos2>=total)pos2=(total-8)&~(size_t)7;
    if(pos2<=pos1)return 0;
    if(ov12>pos1-8)ov12=pos1-8;
    if(ov23>pos2-8)ov23=pos2-8;
    size_t off2=pos1-ov12,off3=pos2-ov23;
    if(off3<=off2)off3=off2+8;
    if(off3>=total)off3=(total-8)&~(size_t)7;
    if(off3<=off2 || off3>=total)return 0;
    cuts[0]=(d2k_ipfrag_span){0,pos1};
    cuts[1]=(d2k_ipfrag_span){off2,pos2-off2};
    cuts[2]=(d2k_ipfrag_span){off3,total-off3};
    return 3;
}
static void wr16(uint8_t *p,uint16_t v){p[0]=(uint8_t)(v>>8);p[1]=(uint8_t)v;}
static uint32_t sum16(const uint8_t *p,size_t n,uint32_t sum) {
    for(size_t i=0;i<n;i+=2)sum+=(uint32_t)p[i]*256+(i+1<n?p[i+1]:0);
    return sum;
}
static uint16_t fold(uint32_t s){while(s>>16)s=(s&65535)+(s>>16);return (uint16_t)~s;}
size_t d2k_udpfrag_build_ex(const uint8_t src[4],const uint8_t dst[4],
    uint16_t sport,uint16_t dport,const uint8_t *payload,size_t len,
    const d2k_ipfrag_plan *p,uint16_t id,uint8_t ttl,uint8_t tos,
    uint8_t *out,size_t cap,d2k_ipfrag_span spans[3]) {
    if(!src || !dst || (!payload && len) || !out || !spans || !id || !ttl || len>65507)return 0;
    d2k_ipfrag_span cuts[3];
    size_t n=d2k_ipfrag_cuts(len+8,p,cuts),needed=0;
    if(!n)return 0;
    for(size_t i=0;i<n;i++)needed+=20+cuts[i].len;
    if(needed>cap)return 0;
    uint8_t udp[8]={0},ph[12]={0};
    wr16(udp,sport);wr16(udp+2,dport);wr16(udp+4,(uint16_t)(len+8));
    memcpy(ph,src,4);memcpy(ph+4,dst,4);ph[9]=17;wr16(ph+10,(uint16_t)(len+8));
    uint16_t checksum=fold(sum16(payload,len,sum16(udp,8,sum16(ph,12,0))));
    wr16(udp+6,checksum?checksum:0xffff);
    size_t used=0;
    for(size_t i=0;i<n;i++) {
        size_t ci=p->reverse?n-1-i:i;
        d2k_ipfrag_span c=cuts[ci];
        uint8_t *f=out+used;
        memset(f,0,20);f[0]=0x45;wr16(f+2,(uint16_t)(20+c.len));wr16(f+4,id);
        wr16(f+6,(uint16_t)(c.off/8 | (ci+1<n?0x2000:0)));
        f[1]=tos;f[8]=ttl;f[9]=17;memcpy(f+12,src,4);memcpy(f+16,dst,4);
        wr16(f+10,fold(sum16(f,20,0)));
        for(size_t j=0;j<c.len;j++) {
            size_t logical=c.off+j;
            f[20+j]=logical<8?udp[logical]:payload[logical-8];
        }
        spans[i]=(d2k_ipfrag_span){used,20+c.len};used+=20+c.len;
    }
    return n;
}

size_t d2k_udpfrag_build(const uint8_t src[4],const uint8_t dst[4],
    uint16_t sport,uint16_t dport,const uint8_t *payload,size_t len,
    const d2k_ipfrag_plan *p,uint16_t id,uint8_t *out,size_t cap,d2k_ipfrag_span spans[3]) {
    return d2k_udpfrag_build_ex(src,dst,sport,dport,payload,len,p,id,64,0,out,cap,spans);
}
