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
    if (q->frag && mode!=5 && mode!=6 && mode!=8) { *sent=0; t.err=t.fail=3; return t; }
    *sent=3;
    size_t unused;
    const uint8_t *rut=d2k_quic_original_blob(2,&unused,NULL);
    const uint8_t *def=d2k_quic_original_blob(3,&unused,NULL);
    int pass=mode==0 || mode==7;
    if(mode==2) pass=q->blob==rut && ((q->copies==11 && !q->ttl) || q->ttl==8 || (q->copies==1 && !q->ttl));
    if(mode==3) pass=q->blob==def && ((q->copies==11 && !q->ttl) || q->ttl==12);
    if(mode==4) pass=q->ttl==5;
    if(mode==6) pass=q->control || q->frag==3;
    if(mode==8) pass=q->control;
    if(mode==7)t.marked=0;
    if(mode==9) pass=q->blob==def && q->copies==1 && !q->ttl;
    if(pass)t.pass=3;else t.fail=3;
    return t;
}
static int data_calls;
static d2k_quic_arm_data complete(const d2k_quic_arm_question *q,void *u) {
    (void)u;
    CHECK(q->copies==1 && !q->ttl && !q->frag);
    data_calls++;
    d2k_quic_arm_data d={0};d.verdict=D2K_QAD_PASS;return d;
}
static void stop_after_complete(void) {
    char pool[1][D2K_QUIC_ADDR_LEN]={"127.0.0.1"};
    d2k_quic_arm_context c={.pool=pool,.n_pool=1,.probe=probe,.data=complete,.marked=1};
    mode=9;calls=data_calls=0;
    d2k_quic_arm r=d2k_quic_original_arms(&c);
    CHECK(calls==4 && data_calls==1);
    CHECK(r.kind==D2K_QA_COPIES && r.copies==1 && !r.ttl && !r.frag_kind);
    CHECK(!strcmp(r.blob_name,"fake_default_quic") && r.len==620);
    CHECK(r.probes==12 && r.n_trace==4 && !r.incomplete && c.marked);
    CHECK(r.trace[3].data==D2K_QAD_PASS);
    mode=0;calls=0;
}
int main(void) {
    stop_after_complete();
    char pool[2][D2K_QUIC_ADDR_LEN]={"127.0.0.1","127.0.0.2"};
    d2k_quic_arm_context c={.pool=pool,.n_pool=1,.next=1,.probe=probe,.marked=1};
    d2k_quic_arm r=d2k_quic_original_arms(&c);
    CHECK(r.original && r.kind==D2K_QA_COPIES);
    CHECK(r.copies==1 && r.ttl==0 && r.probes==3);
    CHECK(r.len==1200 && strcmp(r.blob_name,"quic5")==0);
    CHECK(calls==1);
    CHECK(seen[0].copies==1 && seen[0].ttl==0);
    CHECK(strcmp(seen[0].addr,pool[0])==0);
    CHECK(memcmp(r.bytes,seen[0].blob,r.len)==0);
    CHECK(c.next==1); /* no residual: pinned address for every question */
    c.n_pool=2; c.next=1; c.residual=1; calls=0;
    r=d2k_quic_original_arms(&c);
    CHECK(calls==1 && c.next==2 && strcmp(seen[0].addr,pool[1])==0);
    CHECK(!r.incomplete && r.n_trace==1); /* пригодное плечо найдено первым вопросом */
    CHECK(r.trace[0].not_measured==0);
    c.can_ask=no_budget; calls=0;
    r=d2k_quic_original_arms(&c);
    CHECK(calls==0 && r.probes==0 && r.incomplete);
    CHECK(r.n_trace==15 && r.trace[0].not_measured==2); /* шаг 1 длиннее на quic_initial_nofix */
    c.can_ask=NULL;c.residual=0;c.n_pool=1;
    for(mode=2;mode<=7;mode++) {
        calls=0;c.marked=1;
        r=d2k_quic_original_arms(&c);
        CHECK(r.n_trace<=D2K_QUIC_ARM_STEPS);
        if(mode==2) {
            CHECK(!strcmp(r.blob_name,"quic_rutracker") && r.copies==1 && r.ttl==0);
            CHECK(calls==3 && r.probes==9);
        } else if(mode==3) {
            CHECK(!strcmp(r.blob_name,"fake_default_quic") && r.len==620);
            CHECK(r.copies==11 && r.ttl==0 && calls==10 && r.probes==30); /* шаг 1 длиннее на quic_initial_nofix */
        } else if(mode==4) {
            CHECK(!strcmp(r.blob_name,"quic5") && r.copies==2 && r.ttl==5);
            CHECK(calls==12 && r.probes==36); /* шаг 1 длиннее на quic_initial_nofix */
            CHECK(seen[11].copies==2 && seen[11].ttl==5);
        } else if(mode==5) {
            CHECK(r.kind==D2K_QA_NOT_FOUND && !r.incomplete && r.len==0);
            CHECK(r.frag_survives==D2K_PROP_NO && calls==15 && r.probes==45);
        } else if(mode==6) {
            CHECK(r.kind==D2K_QA_FRAG && r.frag_kind==3 && r.frag_survives==D2K_PROP_YES);
            CHECK(calls==18 && r.probes==54);
        } else CHECK(r.kind==D2K_QA_FLAKY);
    }
    /* Longest ladder: no fake, no copies, no TTL, survival passes and every
       fragment shape is asked and fails. The Run budget (quicprobe.c) is
       derived from exactly this count. */
    mode=8;calls=0;c.marked=1;
    r=d2k_quic_original_arms(&c);
    CHECK(calls==(int)D2K_QUIC_ARM_QUESTIONS_MAX && r.n_trace==D2K_QUIC_ARM_QUESTIONS_MAX);
    CHECK(r.kind==D2K_QA_NOT_FOUND && !r.incomplete && r.frag_survives==D2K_PROP_YES);
    mode=0;calls=0;c.marked=1;c.can_ask=one_question;
    r=d2k_quic_original_arms(&c);
    CHECK(calls==1 && r.probes==3 && !r.incomplete && r.copies==1);
    CHECK(r.n_trace==1); /* пригодное плечо найдено первым вопросом */
    if(fail) return 1;
    puts("original askArms: passed"); return 0;
}
