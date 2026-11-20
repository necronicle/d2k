#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "d2k_resend.h"

static int fails;
#define CHECK(x) do { if (!(x)) { printf("resend:%d: %s\n", __LINE__, #x); fails++; } } while (0)
static unsigned r16(const uint8_t *p) { return (unsigned)p[0]<<8 | p[1]; }
static uint32_t r32(const uint8_t *p) { return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }
static void w16(uint8_t *p, size_t n) { p[0]=(uint8_t)(n>>8); p[1]=(uint8_t)n; }
static void w32(uint8_t *p, uint32_t n) { p[0]=(uint8_t)(n>>24); p[1]=(uint8_t)(n>>16); p[2]=(uint8_t)(n>>8); p[3]=(uint8_t)n; }
/* Independent Internet checksum, including odd byte, for fixtures and checks. */
static unsigned sum(const uint8_t *p, size_t n, unsigned s) {
    for (size_t i=0; i<n; i++) s += (unsigned)p[i] << (i%2 ? 0 : 8);
    while (s>>16) s=(s&65535)+(s>>16);
    return s;
}
static unsigned tcp_sum(const uint8_t *p, size_t n, size_t ih) {
    unsigned s=(unsigned)(n-ih)+6;
    s=sum(p+((p[0]>>4)==6 ? 8 : 12), (p[0]>>4)==6 ? 32 : 8, s);
    return sum(p+ih,n-ih,s);
}
static size_t packet(uint8_t *p, int family, int opts, size_t data) {
    size_t ih=family==6 ? 40 : 20, th=opts ? 32 : 20, n=ih+th+data;
    memset(p,0,n);
    if (family==4) {
        p[0]=0x45; p[1]=0x2e; w16(p+2,n); w16(p+4,32100); w16(p+6,0x4000);
        p[8]=63; p[9]=6; p[12]=10; p[15]=1; p[16]=192; p[18]=2; p[19]=9;
        w16(p+10,~sum(p,ih,0));
    } else {
        p[0]=0x62; p[1]=0xe1; p[2]=0x23; p[3]=0x45;
        w16(p+4,n-40); p[6]=6; p[7]=63;
        p[8]=p[24]=0x20; p[9]=p[25]=1; p[23]=1; p[39]=2;
    }
    uint8_t *t=p+ih;
    w16(t,45000); w16(t+2,443); w32(t+4,0xffffffd0u); w32(t+8,1234567);
    t[12]=(uint8_t)(th<<2); t[13]=0x18; w16(t+14,62000);
    if (opts) { t[20]=t[21]=1; t[22]=8; t[23]=10; w32(t+24,0x10203040); w32(t+28,0x99887766); }
    for (size_t i=0; i<data; i++) p[ih+th+i]=(uint8_t)(i*71+13);
    w16(t+16,~tcp_sum(p,n,ih));
    return n;
}
typedef struct { uint8_t p[8][4096]; size_t n[8], count, attempts, fail_at; } wire;
static int emit(void *ctx,const uint8_t *p,size_t n) {
    wire *w=ctx;
    if (++w->attempts==w->fail_at) { errno=ENOBUFS; return -1; }
    if (w->count>=8 || n>sizeof w->p[0]) { errno=EMSGSIZE; return -1; }
    memcpy(w->p[w->count],p,n); w->n[w->count++]=n; return 0;
}
static void verify_split(int family, int ipopts) {
    uint8_t p[2048], original[2048], joined[1531];
    size_t n=packet(p,family,1,1531), ih=family==6 ? 40 : 20;
    if (ipopts) {
        memmove(p+ih+4,p+ih,n-ih); p[0]=0x46;
        p[20]=1; p[21]=1; p[22]=0; p[23]=0;
        n+=4; ih+=4; w16(p+2,n); p[10]=p[11]=0; w16(p+10,~sum(p,ih,0));
    }
    memcpy(original,p,n);
    wire w={0}; size_t sent=999;
    CHECK(d2k_resend_original(p,n,1492,emit,&w,&sent)==0);
    CHECK(sent==2 && w.count==2);
    CHECK(n==(family==6 ? 1603u : ipopts ? 1587u : 1583u));
    CHECK(!memcmp(p,original,n));
    size_t off=0, header=ih+32;
    for (size_t i=0; i<w.count; i++) {
        const uint8_t *q=w.p[i]; size_t len=w.n[i];
        CHECK(len<=1492 && len>header);
        CHECK(len==(i==0 ? 1492u : n-1492+header));
        CHECK(r32(q+ih+4)==(uint32_t)(0xffffffd0u+off));
        CHECK(q[ih+13]==(i+1==w.count ? 0x18 : 0x10));
        CHECK(!memcmp(q+ih,original+ih,4));
        CHECK(!memcmp(q+ih+8,original+ih+8,5));
        CHECK(!memcmp(q+ih+14,original+ih+14,2));
        CHECK(!memcmp(q+ih+18,original+ih+18,14));
        CHECK(tcp_sum(q,len,ih)==65535);
        if (family==4) {
            CHECK(r16(q+2)==len && sum(q,ih,0)==65535);
            CHECK(r16(q+4)==32100+i);
            CHECK(!memcmp(q,original,2) && !memcmp(q+6,original+6,4));
            CHECK(!memcmp(q+12,original+12,ih-12));
        } else {
            CHECK(r16(q+4)==len-40);
            CHECK(!memcmp(q,original,4) && !memcmp(q+6,original+6,ih-6));
        }
        size_t payload=len-header;
        if (payload<=sizeof joined-off) memcpy(joined+off,q+header,payload);
        off+=payload;
    }
    CHECK(off==1531 && !memcmp(joined,original+header,1531));
}
static void unchanged(void) {
    for (int f=4; f<=6; f+=2) {
        uint8_t p[2048]; size_t n=packet(p,f,1,100);
        size_t caps[]={n,n+1,0};
        for (size_t i=0;i<3;i++) {
            wire w={0}; size_t sent=0;
            CHECK(d2k_resend_original(p,n,caps[i],emit,&w,&sent)==0);
            CHECK(sent==1 && w.count==1 && w.n[0]==n && !memcmp(p,w.p[0],n));
        }
        /* A long original is also byte-exact when the path cap is unknown. */
        n=packet(p,f,1,1531);
        wire unlimited={0}; size_t unlimited_sent=0;
        CHECK(d2k_resend_original(p,n,0,emit,&unlimited,&unlimited_sent)==0);
        CHECK(unlimited_sent==1 && unlimited.n[0]==n && !memcmp(p,unlimited.p[0],n));
        /* FIN below cap keeps the old byte-exact path. */
        p[(f==6 ? 40 : 20)+13]|=1;
        wire w={0}; size_t sent=0;
        CHECK(d2k_resend_original(p,n,n,emit,&w,&sent)==0);
        CHECK(sent==1 && !memcmp(p,w.p[0],n));
    }
}
static void refusals_and_failure(void) {
    for (int f=4; f<=6; f+=2) {
        uint8_t p[2048]; size_t n=packet(p,f,1,1531), ih=f==6 ? 40 : 20;
        unsigned bad[]={1,4,2,32}; /* FIN, RST, SYN, URG cannot be split safely. */
        for (size_t i=0;i<4;i++) {
            wire w={0}; size_t sent=999;
            p[ih+13]=(uint8_t)(0x18|bad[i]);
            CHECK(d2k_resend_original(p,n,1492,emit,&w,&sent)==-1);
            CHECK(sent==0 && w.attempts==0);
        }
        p[ih+13]=0x18;
        size_t caps[]={ih+32,1};
        for (size_t i=0;i<2;i++) {
            wire w={0}; size_t sent=999;
            CHECK(d2k_resend_original(p,n,caps[i],emit,&w,&sent)==-1);
            CHECK(sent==0 && w.attempts==0);
        }
        wire w={.fail_at=2}; size_t sent=999;
        CHECK(d2k_resend_original(p,n,1492,emit,&w,&sent)==-1);
        CHECK(errno==ENOBUFS && sent==1 && w.count==1 && w.attempts==2);
        w=(wire){.fail_at=1}; sent=999;
        CHECK(d2k_resend_original(p,n,1492,emit,&w,&sent)==-1);
        CHECK(errno==ENOBUFS && sent==0 && w.attempts==1);
    }
}
/* IP_HDRINCL replaces a zero IPv4 ID in the kernel: every split output must
 * carry a nonzero, consecutive range, even when the input ID is near wrap. */
static void ids_and_boundaries(void) {
    uint8_t p[2048]; size_t n=packet(p,4,0,20);
    unsigned ids[]={0,65535};
    for (size_t i=0;i<2;i++) {
        w16(p+4,ids[i]);
        wire w={0}; size_t sent=0;
        CHECK(d2k_resend_original(p,n,47,emit,&w,&sent)==0);
        CHECK(sent==3 && w.count==3);
        for (size_t j=0;j<w.count;j++) {
            CHECK(r16(w.p[j]+4)==j+1);
            CHECK(w.n[j]==(j==2 ? 46u : 47u));
            CHECK(r32(w.p[j]+24)==(uint32_t)(0xffffffd0u+j*7));
            CHECK(tcp_sum(w.p[j],w.n[j],20)==65535);
        }
    }
    /* One byte above cap, no PSH, and a checksum-offload placeholder. */
    n=packet(p,4,0,21); p[33]=0x10; p[36]=p[37]=0;
    wire w={0}; size_t sent=0;
    CHECK(d2k_resend_original(p,n,60,emit,&w,&sent)==0);
    CHECK(sent==2 && w.n[0]==60 && w.n[1]==41);
    CHECK(w.p[0][33]==0x10 && w.p[1][33]==0x10);
    CHECK(tcp_sum(w.p[0],60,20)==65535 && tcp_sum(w.p[1],41,20)==65535);
}
static void unsupported(void) {
    uint8_t p[2048]; size_t sent=0;
    for (unsigned variant=0;variant<5;variant++) {
        size_t n=packet(p,4,1,1531); wire w={0};
        if (variant==0) p[6]|=0x20; /* first IP fragment */
        if (variant==1) p[7]=1;    /* later IP fragment */
        if (variant==2) p[9]=17;   /* UDP */
        if (variant==3) p[32]=0xf0, w16(p+2,70), n=70; /* truncated TCP options */
        if (variant==4) n--;       /* truncated IP payload */
        CHECK(d2k_resend_original(p,n,60,emit,&w,&sent)==-1);
        CHECK(sent==0 && w.attempts==0);
    }
}
static void ipv6_extensions(void) {
    uint8_t p[2048], original[2048], joined[1531];
    size_t n=packet(p,6,1,1531);
    memmove(p+48,p+40,n-40); memset(p+40,0,8);
    p[6]=60; p[40]=6; /* padding-only destination options */
    n+=8; w16(p+4,n-40); memcpy(original,p,n);
    wire w={0}; size_t sent=0;
    CHECK(d2k_resend_original(p,n,1492,emit,&w,&sent)==0);
    CHECK(sent==2 && w.count==2);
    size_t off=0;
    for (size_t i=0;i<w.count;i++) {
        CHECK(w.n[i]<=1492 && !memcmp(w.p[i]+6,original+6,42));
        CHECK(r16(w.p[i]+4)==w.n[i]-40);
        CHECK(tcp_sum(w.p[i],w.n[i],48)==65535);
        size_t data=w.n[i]-80;
        if (data<=sizeof joined-off) memcpy(joined+off,w.p[i]+80,data);
        off+=data;
    }
    CHECK(off==1531 && !memcmp(joined,original+80,1531));
    CHECK(!memcmp(p,original,n));
}

int main(void) {
    verify_split(4,0); verify_split(6,0); verify_split(4,1);
    unchanged(); refusals_and_failure();
    ids_and_boundaries(); unsupported(); ipv6_extensions();
    if (fails) return 1;
    puts("resend: MTU, exact bytes/options, sequence, checksums and failures passed"); return 0;
}
