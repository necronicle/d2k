/* §9.5 on the TLS stream of the actual experiment. Uses the shared HTTP/2
 * parser; no sockets, fixed names or independent TLS handshake here. */
#define _POSIX_C_SOURCE 200809L
#include "d2k_doh_contract.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef long (*read_fn)(void *,uint8_t *,size_t,int,char *,size_t);
typedef int (*write_fn)(void *,const uint8_t *,size_t,char *,size_t);
typedef struct { long (*packets)(void *); void *unused,*ctx; } budget_io;
static __thread uint8_t query[271];
static __thread size_t query_len;
static int64_t verify_now_ms(void) {
    struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
    return (int64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
static void budget_say(d2k_ver_result *r,int state,const char *fmt,...) {
    r->budget=state;va_list ap;va_start(ap,fmt);
    vsnprintf(r->reason,sizeof r->reason,fmt,ap);va_end(ap);
}
static size_t doh_base64url(const uint8_t *query,size_t query_len,char *out) {
    const char *abc="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t n=0;
    for(size_t i=0;i<query_len;i+=3) {
        size_t left=query_len-i;uint32_t v=(uint32_t)query[i]<<16;
        if(left>1)v|=(uint32_t)query[i+1]<<8;
        if(left>2)v|=query[i+2];
        out[n++]=abc[v>>18];out[n++]=abc[(v>>12)&63];
        if(left>1)out[n++]=abc[(v>>6)&63];
        if(left>2)out[n++]=abc[v&63];
    }
    out[n]=0;return n;
}
static int skip_name(const uint8_t *b,size_t n,size_t *p) {
    unsigned labels=0;
    while(*p<n && labels++<128) {
        unsigned z=b[(*p)++];if(!z)return 0;
        if((z&192)==192) {if(*p>=n)return -1;unsigned off=((z&63)<<8)|b[(*p)++];return off<n?0:-1;}
        if(z>63 || z>n-*p)return -1;
        *p+=z;
    }
    return -1;
}
static unsigned get16(const uint8_t *b) {return (unsigned)b[0]*256+b[1];}
static int doh_dns_valid(const uint8_t *query,size_t query_len,const uint8_t *b,size_t n,const char **why) {
    *why="DNS answer does not match the owner's query";
    if(n<query_len || memcmp(b,query,2) || !(b[2]&128) || (b[2]&0x7a) ||
       ((b[3]&15)!=0 && (b[3]&15)!=3) || get16(b+4)!=1 ||
       memcmp(b+12,query+12,query_len-12))return -1;
    size_t p=query_len;
    for(size_t section=0;section<3;section++)for(unsigned i=0;i<get16(b+6+2*section);i++) {
        if(skip_name(b,n,&p) || n-p<10)return -1;
        unsigned z=get16(b+p+8);p+=10;if(z>n-p)return -1;p+=z;
    }
    return p==n?0:-1;
}
static long no_packets(void *ctx) {(void)ctx;return 0;}
#define DOH_DEFAULT_QUESTION query,query_len
#include "doh_h2.inc"
#undef DOH_DEFAULT_QUESTION

int d2k_doh_query_name(const char *name) {
    if(!name || !*name || strlen(name)>253)return -1;
    memset(query,0,sizeof query);query[2]=1;query[5]=1;query_len=12;
    const char *p=name;
    while(*p) {
        const char *dot=strchr(p,'.');size_t z=dot?(size_t)(dot-p):strlen(p);
        if(!z || z>63)return -1;
        query[query_len++]=(uint8_t)z;
        for(size_t i=0;i<z;i++) {
            unsigned char c=(unsigned char)p[i];
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return -1;
            query[query_len++]=c;
        }
        if(!dot)break;
        p=dot+1;if(!*p)return -1;
    }
    query[query_len++]=0;query[query_len++]=0;query[query_len++]=1;query[query_len++]=0;query[query_len++]=1;
    return 0;
}
static long read_tls(void *t,uint8_t *b,size_t n,int wait,char *err,size_t cap) {
    return d2k_tls_read(t,b,n,wait,err,cap);
}
static int write_tls(void *t,const uint8_t *b,size_t n,char *err,size_t cap) {
    return d2k_tls_write(t,b,n,err,cap);
}
void d2k_doh_contract(d2k_tls *tls,const char *host,const char *path,const char *qname,int timeout,d2k_ver_result *r) {
    memset(r,0,sizeof *r);r->fd=-1;
    if(!tls || !host || !path || path[0]!='/' || d2k_doh_query_name(qname) || strcmp(d2k_tls_alpn(tls),"h2")) {
        r->local_refusal=1;snprintf(r->reason,sizeof r->reason,"DoH requires observed query name, path and negotiated h2");return;
    }
    budget_io bio={no_packets,NULL,NULL};char err[160]={0};r->level=D2K_VER_HANDSHAKE;
    request_doh_h2(read_tls,write_tls,tls,host,path,timeout,&bio,0,r,err,sizeof err);
}
d2km_result d2k_doh_result(const d2k_ver_result *r) {
    if(r->local_refusal || r->local_limit)return (d2km_result){D2KM_R_LOCAL_FAIL,0};
    if(r->level==D2K_VER_APPLICATION && r->doh_replies>=20 && r->budget==D2K_BUDGET_PASSED)return (d2km_result){D2KM_R_APP_OK,0};
    /* GOAWAY, EOF or invalid DNS are incomplete exchanges, not measured cuts. */
    if(r->budget==D2K_BUDGET_CUT)return (d2km_result){D2KM_R_CUT,r->doh_replies};
    /* No complete observation of the application contract. In particular
       REPLY would be inferred as a blocking signal by the TLS model. */
    return (d2km_result){D2KM_R_NOT_MEASURED,0};
}
