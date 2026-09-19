#include <stdio.h>
#include <string.h>
#include "d2k_quic_arms.h"
#include "d2k_quichello.h"
#include "d2k_quic.h"
static int calls, fails, lose_base_mark;
static int fragment_calls;
static size_t first_prefix;
#define CHECK(x) do { if(!(x)) { printf("FAIL %d %s\n",__LINE__,#x); fails++; } } while(0)
static size_t resolve(const char *sni,char out[][D2K_QUIC_ADDR_LEN],size_t cap) {
    (void)sni;(void)out;(void)cap;return 0;
}
static d2k_tally answer(int n,int *sent) {
    d2k_tally t={0}; t.marked=1; if(sent)*sent=n;
    if(lose_base_mark && calls==0)t.marked=0;
    if(calls++==1) t.fail=n; else t.pass=n;
    return t;
}
static d2k_tally ask(const char *ip,uint16_t port,const uint8_t *pre,size_t len,
    d2k_hello msg,uint32_t wait,uint32_t mark,int n,uint32_t *rtt,int *ref,int *sent,uint8_t *ttl) {
    (void)ip;(void)port;(void)msg;(void)wait;(void)mark;
    if(pre && !first_prefix) first_prefix=len;
    if(rtt)*rtt=1;
    if(ref)*ref=0;
    if(ttl)*ttl=64;
    return answer(n,sent);
}
static d2k_tally copies(const char *ip,uint16_t port,const uint8_t *p,size_t l,int c,
    d2k_hello h,uint32_t w,uint32_t m,int n,int *sent) {
    (void)c; return ask(ip,port,p,l,h,w,m,n,NULL,NULL,sent,NULL);
}
static d2k_tally srcport(const char *ip,uint16_t port,int sp,d2k_hello h,uint32_t w,uint32_t m,int n,int *sent) {
    (void)sp;return ask(ip,port,NULL,0,h,w,m,n,NULL,NULL,sent,NULL);
}
static d2k_tally split(const char *ip,uint16_t port,d2k_hello h,const char *sni,uint32_t w,uint32_t m,int n,int *sent) {
    (void)sni;return ask(ip,port,NULL,0,h,w,m,n,NULL,NULL,sent,NULL);
}
static d2k_tally fragment(const char *ip,uint16_t port,int shape,d2k_hello h,uint32_t w,uint32_t m,int n,int *sent) {
    (void)ip;(void)port;(void)w;(void)m;
    char sni[256];
    CHECK(shape==1);
    CHECK(d2k_quic_sni(h.bytes,h.len,sni,sizeof sni)==0);
    CHECK(!strcmp(sni,fragment_calls%2==0?"neutral.example":"target.example"));
    fragment_calls++;
    d2k_tally t={0};t.pass=n;t.marked=1;*sent=n;return t;
}
int main(void) {
    d2k_quic_allow_local=1; d2k_quic_resolve_hook=resolve;
    d2k_quic_ask_hook=ask; d2k_quic_ask_copies_hook=copies; d2k_quic_ask_ttl_hook=copies;
    d2k_quic_ask_srcport_hook=srcport; d2k_quic_ask_split_hook=split;
    d2k_quic_fragment_hook=fragment;
    uint8_t tb[1500],cb[1500];size_t tn=0,cn=0;
    CHECK(d2k_quic_probe_initial("target.example",tb,sizeof tb,&tn)==0);
    CHECK(d2k_quic_probe_initial("neutral.example",cb,sizeof cb,&cn)==0);
    d2k_quic_arm arm;
    d2k_vres r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb,tn},(d2k_hello){cb,cn},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE);
    CHECK(first_prefix==1200); /* quic5 before properties' 16-byte junk */
    CHECK(arm.original && arm.len==1200 && arm.ttl==3 && arm.copies==6);
    CHECK(fragment_calls==2 && arm.frag_kind==1 && arm.frag_survives==D2K_PROP_YES);
    calls=0;first_prefix=0;lose_base_mark=1;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb,tn},(d2k_hello){cb,cn},99,&arm);
    CHECK(!r.marked && arm.kind==D2K_QA_FLAKY);
    if(fails)return 1;
    puts("original Run order: passed");return 0;
}
