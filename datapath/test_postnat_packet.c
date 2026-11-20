#include <stdio.h>
#include <string.h>
#include "d2k_postnat_capture.h"

static int failed;
#define CHECK(x) do {if(!(x)){fprintf(stderr,"postnat:%d: %s\n",__LINE__,#x);failed++;}}while(0)
static size_t packet(uint8_t *p,int family,unsigned tag) {
    memset(p,0,96);
    size_t h=family==4?20:40,n=h+12;
    p[0]=family==4?0x45:0x60;
    if(family==4){p[2]=0;p[3]=(uint8_t)n;p[4]=0x12;p[5]=0x34;p[8]=64;p[9]=17;p[12]=10;p[15]=1;p[16]=10;p[19]=2;}
    else {p[5]=12;p[6]=17;p[7]=64;p[8]=0x20;p[9]=1;p[23]=1;p[24]=0x20;p[25]=1;p[39]=2;}
    p[h]=0xbe;p[h+1]=0xef;p[h+2]=0x11;p[h+3]=0x67;p[h+5]=12;
    p[h+8]=(uint8_t)tag;p[h+9]=0x00;p[h+10]=0xff;p[h+11]=0x7f;
    return n;
}
static void check_family(int family) {
    uint8_t a[96],b[96],bad[96];size_t n=packet(a,family,42),h=family==4?20:40;
    memcpy(b,a,n);
    size_t src=family==4?12:8,dst=family==4?16:24,alen=family==4?4:16;
    b[src+alen-1]=100;b[dst+alen-1]=9; /* SNAT + DNAT */
    b[h]=0xd6;b[h+1]=0xd9;b[h+2]=0x22;b[h+3]=0x33;
    d2k_ct_tuple original={0};CHECK(d2k_postnat_udp_tuple(a,n,&original));
    CHECK(original.family==family&&original.proto==17&&original.sport_be[0]==0xbe);
    d2k_ct_info ct={0};ct.reply_tuple_known=1;ct.reply_tuple.family=(uint8_t)family;ct.reply_tuple.proto=17;
    memcpy(ct.reply_tuple.src,b+dst,alen);memcpy(ct.reply_tuple.dst,b+src,alen);
    memcpy(ct.reply_tuple.sport_be,b+h+2,2);memcpy(ct.reply_tuple.dport_be,b+h,2);
    CHECK(d2k_postnat_udp_match(a,n,b,n,&ct));
    ct.reply_tuple_known=0;CHECK(!d2k_postnat_udp_match(a,n,b,n,&ct));ct.reply_tuple_known=1;
    ct.reply_tuple.dport_be[1]^=1;CHECK(!d2k_postnat_udp_match(a,n,b,n,&ct));ct.reply_tuple.dport_be[1]^=1;
    ct.reply_tuple.dst[alen-1]^=1;CHECK(!d2k_postnat_udp_match(a,n,b,n,&ct));ct.reply_tuple.dst[alen-1]^=1;
    memcpy(bad,b,n);bad[n-1]^=1;CHECK(!d2k_postnat_udp_match(a,n,bad,n,&ct));
    memcpy(bad,b,n);bad[family==4?5:3]^=1;CHECK(!d2k_postnat_udp_match(a,n,bad,n,&ct));
    for(size_t i=0;i<n;i++)CHECK(!d2k_postnat_udp_match(a,n,b,i,&ct));
    memcpy(bad,b,n);bad[h+5]--;CHECK(!d2k_postnat_udp_match(a,n,bad,n,&ct));
    if(family==4){memcpy(bad,b,n);bad[6]=0x20;CHECK(!d2k_postnat_udp_match(a,n,bad,n,&ct));}
    CHECK(!d2k_postnat_udp_match(a,n,b,n+1,&ct));
    CHECK(!d2k_postnat_udp_match(NULL,n,b,n,&ct));
}
int main(void) {
    check_family(4);check_family(6);
    if(!failed)puts("postnat packet: IPv4/IPv6 NAT identity, payload and bounds PASS");
    return failed?1:0;
}
