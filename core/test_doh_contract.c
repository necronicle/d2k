#define _POSIX_C_SOURCE 200809L
#include <time.h>
static long long fake_ms;
static int fake_clock(clockid_t id,struct timespec *t) {(void)id;t->tv_sec=fake_ms/1000;t->tv_nsec=(fake_ms%1000)*1000000;return 0;}
static int fake_sleep(const struct timespec *t,struct timespec *left) {(void)left;fake_ms+=t->tv_sec*1000+t->tv_nsec/1000000;return 0;}
#define clock_gettime fake_clock
#define nanosleep fake_sleep
#include "doh_contract.c"
#include <assert.h>
static uint8_t response[1024];static size_t size,pos;static unsigned replies;static int corrupt,short_session,goaway,timed_out;
long d2k_tls_read(d2k_tls *t,uint8_t *b,size_t n,int wait,char *err,size_t cap) {
    (void)t;(void)wait;(void)err;(void)cap;
    if(timed_out && replies>1) {fake_ms+=wait;return -1;}
    size_t z=size-pos;if(z>n)z=n;memcpy(b,response+pos,z);pos+=z;return (long)z;
}
int d2k_tls_write(d2k_tls *t,const uint8_t *b,size_t n,char *err,size_t cap) {
    (void)t;(void)err;(void)cap;
    if(n<9 || b[3]!=1)return 0;
    replies++;size=pos=0;if(short_session && replies>1)return 0;
    if(goaway && replies>1) {uint8_t close[]={0,0,8,7,0,0,0,0,0,0,0,0,1,0,0,0,0};memcpy(response,close,sizeof close);size=sizeof close;return 0;}
    uint8_t head[]={0,0,1,1,4,0,0,0,0,0x88};memcpy(head+5,b+5,4);memcpy(response,head,sizeof head);size=sizeof head;
    uint8_t data[9]={0,0,0,0,1,0,0,0,0};data[1]=(uint8_t)(query_len>>8);data[2]=(uint8_t)query_len;
    memcpy(data+5,b+5,4);memcpy(response+size,data,9);size+=9;
    memcpy(response+size,query,query_len);response[size+2]=0x81;response[size+3]=0x80;
    if(corrupt)response[size]^=1;
    size+=query_len;return 0;
}
const char *d2k_tls_alpn(const d2k_tls *t) {(void)t;return "h2";}
int main(void) {
    const char *host="tenant.gateway.example.test";d2k_ver_result r;
    assert(!d2k_doh_query_name(host));assert(query_len>30);
    char encoded[400];assert(doh_base64url(query,query_len,encoded)>40); /* catches old 40-byte buffer */
    d2k_doh_contract((d2k_tls *)1,host,"/dns-query",host,8000,&r);
    assert(r.level==D2K_VER_APPLICATION && r.doh_replies>=20 && fake_ms>=30000 && replies==20);
    fake_ms=0;replies=0;corrupt=1;
    d2k_doh_contract((d2k_tls *)1,host,"/dns-query",host,8000,&r);
    assert(r.level!=D2K_VER_APPLICATION && !r.doh_replies);
    corrupt=0;short_session=1;replies=0;
    d2k_doh_contract((d2k_tls *)1,host,"/dns-query",host,8000,&r);
    assert(r.level!=D2K_VER_APPLICATION && r.doh_replies==1);
    short_session=0;goaway=1;replies=0;
    d2k_doh_contract((d2k_tls *)1,host,"/dns-query",host,8000,&r);
    assert(r.doh_replies==1 && strstr(r.reason,"GOAWAY"));
    assert(d2k_doh_result(&r).kind==D2KM_R_NOT_MEASURED);
    goaway=0;timed_out=1;replies=0;
    d2k_doh_contract((d2k_tls *)1,host,"/dns-query",host,8000,&r);
    assert(r.doh_replies==1 && d2k_doh_result(&r).kind==D2KM_R_CUT);
    assert(d2k_doh_query_name("a..bad")<0);assert(d2k_doh_query_name("a/b")<0);
    puts("DoH owner name, exact DNS validation, 20 replies/30 seconds, partial failure: ok");return 0;
}
