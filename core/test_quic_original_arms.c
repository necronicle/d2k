#include <stdio.h>
#include <string.h>
#include "d2k_quic_arms.h"
static int fail, calls, mode;
static int no_budget(void *p) { (void)p; return 0; }
static int one_question(void *p) { (void)p; return calls<1; }
static d2k_quic_arm_question seen[32];
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n",__LINE__,#x); fail++; } } while(0)
static d2k_tally probe(const d2k_quic_arm_question *q, void *u, int *sent) {
    (void)u;
    seen[calls++]=*q;
    d2k_tally t={0}; t.marked=1;
    if (q->frag && mode!=5 && mode!=6) { *sent=0; t.err=t.fail=3; return t; }
    *sent=3;
    size_t unused;
    const uint8_t *rut=d2k_quic_original_blob(2,&unused,NULL);
    const uint8_t *def=d2k_quic_original_blob(3,&unused,NULL);
    int pass=mode==0 || mode==7;
    if(mode==2) pass=q->blob==rut && (q->copies==11 || q->ttl==8 || (q->copies==1 && !q->ttl));
    if(mode==3) pass=q->blob==def && (q->copies==11 || q->ttl==12);
    if(mode==4) pass=q->ttl==5;
    if(mode==6) pass=q->control || q->frag==3;
    if(mode==7)t.marked=0;
    if(pass)t.pass=3;else t.fail=3;
    return t;
}
int main(void) {
    char pool[2][D2K_QUIC_ADDR_LEN]={"127.0.0.1","127.0.0.2"};
    d2k_quic_arm_context c={.pool=pool,.n_pool=1,.next=1,.probe=probe,.marked=1};
    d2k_quic_arm r=d2k_quic_original_arms(&c);
    CHECK(r.original && r.kind==D2K_QA_TTL);
    CHECK(r.copies==6 && r.ttl==3 && r.probes==9);
    CHECK(r.len==1200 && strcmp(r.blob_name,"quic5")==0);
    CHECK(calls==4);
    if(calls==4) {
        CHECK(seen[0].copies==1 && seen[0].ttl==0);
        CHECK(seen[1].copies==6 && seen[1].ttl==0);
        CHECK(seen[2].copies==1 && seen[2].ttl==3);
        CHECK(seen[3].frag==1 && seen[3].control);
        for(int i=0;i<4;i++) CHECK(strcmp(seen[i].addr,pool[0])==0);
        CHECK(memcmp(r.bytes,seen[0].blob,r.len)==0);
    }
    CHECK(c.next==1); /* no residual: pinned address for every question */
    c.n_pool=2; c.next=1; c.residual=1; calls=0;
    r=d2k_quic_original_arms(&c);
    CHECK(calls==1 && c.next==2 && strcmp(seen[0].addr,pool[1])==0);
    CHECK(r.incomplete); /* exhaustion must not pretend the search completed */
    CHECK(r.trace[0].not_measured==0 && r.trace[1].not_measured==1);
    c.can_ask=no_budget; calls=0;
    r=d2k_quic_original_arms(&c);
    CHECK(calls==0 && r.probes==0 && r.incomplete);
    CHECK(r.n_trace==14 && r.trace[0].not_measured==2);
    c.can_ask=NULL;c.residual=0;c.n_pool=1;
    for(mode=2;mode<=7;mode++) {
        calls=0;c.marked=1;
        r=d2k_quic_original_arms(&c);
        CHECK(r.n_trace<=D2K_QUIC_ARM_STEPS);
        if(mode==2) {
            CHECK(!strcmp(r.blob_name,"quic_rutracker") && r.copies==11 && r.ttl==8);
            CHECK(calls==9 && r.probes==24);
        } else if(mode==3) {
            CHECK(!strcmp(r.blob_name,"fake_default_quic") && r.len==620);
            CHECK(r.copies==11 && r.ttl==12 && calls==14 && r.probes==39);
        } else if(mode==4) {
            CHECK(!strcmp(r.blob_name,"quic5") && r.copies==2 && r.ttl==5);
            CHECK(calls==12 && r.probes==33);
        } else if(mode==5) {
            CHECK(r.kind==D2K_QA_NOT_FOUND && !r.incomplete && r.len==0);
            CHECK(r.frag_survives==D2K_PROP_NO && calls==14 && r.probes==42);
        } else if(mode==6) {
            CHECK(r.kind==D2K_QA_FRAG && r.frag_kind==3 && r.frag_survives==D2K_PROP_YES);
            CHECK(calls==17 && r.probes==51);
        } else CHECK(r.kind==D2K_QA_FLAKY);
    }
    mode=0;calls=0;c.marked=1;c.can_ask=one_question;
    r=d2k_quic_original_arms(&c);
    CHECK(calls==1 && r.probes==3 && r.incomplete && r.copies==2);
    CHECK(r.trace[1].not_measured==2); /* same budget, checked between questions */
    if(fail) return 1;
    puts("original askArms: passed"); return 0;
}
