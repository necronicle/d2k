/* Этапы 51, 53: владение поздней доставкой, асинхронные установка и снятие. */
#include <stdio.h>
#include <string.h>
#include "d2k_latewatch.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s\n", (m)); fails++; } } while (0)
#define S 1000000000ull

/* Подменённый исполнитель: заявки копятся, итоги отдаёт тест. */
static d2k_lw_req reqs[256];
static int n_reqs, queue_full;
static int acks_ok, acks_fail, notes, flags_on, flags_off;
static uint8_t last_ack_reason, last_note_code, last_ack_token[D2K_TRIAL_ID_LEN];
static char said[16384];
static int fake_submit(void *ctx, const d2k_lw_req *r) {
    (void)ctx;
    if (queue_full) return -1;
    reqs[n_reqs++] = *r;
    return 0;
}
static void fake_ack(void *ctx, int ok, uint8_t reason, const uint8_t token[D2K_TRIAL_ID_LEN]) {
    (void)ctx; if (ok) acks_ok++; else acks_fail++;
    last_ack_reason = reason; memcpy(last_ack_token, token, D2K_TRIAL_ID_LEN);
}
static void fake_flag(void *ctx, const d2k_ct_tuple *t, int on) { (void)ctx; (void)t; if (on) flags_on++; else flags_off++; }
static uint64_t fake_delivered(void *ctx) { (void)ctx; return 0; }
static void fake_note(void *ctx, const d2k_ct_tuple *t, uint8_t code, uint32_t repeats,
                      const uint8_t token[D2K_TRIAL_ID_LEN], uint64_t now) {
    (void)ctx; (void)t; (void)repeats; (void)token; (void)now; notes++; last_note_code = code;
}
static void fake_say(void *ctx, const char *line) {
    (void)ctx; size_t n = strlen(said); snprintf(said + n, sizeof said - n, "%s\n", line);
}
static const d2k_lw_ops OPS = {fake_submit, fake_ack, fake_flag, fake_delivered, fake_note, fake_say, NULL, 0x40000000u};
static void reset(d2k_lw *lw, int backend) {
    n_reqs = queue_full = acks_ok = acks_fail = notes = flags_on = flags_off = 0; said[0] = 0;
    d2k_lw_init(lw, &OPS);
    d2k_lw_start(lw, 1 * S);
    /* INIT, затем SWEEP — первыми. */
    if (n_reqs >= 1 && reqs[0].op == D2K_LWOP_INIT) {
        d2k_lw_done d; memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_INIT; d.slot = reqs[0].slot; d.gen = reqs[0].gen; d.rc = 0; d.backend = backend;
        d2k_lw_complete(lw, &d, 1 * S);
    }
    if (n_reqs >= 2 && reqs[1].op == D2K_LWOP_SWEEP && backend) {
        d2k_lw_done d; memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_SWEEP; d.gen = reqs[1].gen; d.rc = 0; d.dump_ok = 1;
        d2k_lw_complete(lw, &d, 1 * S);
    }
    n_reqs = 0;
}
/* Итог заявки i с кодом rc. */
static void deliver(d2k_lw *lw, int i, int rc, uint64_t now) {
    d2k_lw_done d; memset(&d, 0, sizeof d);
    d.op = reqs[i].op; d.orphan = reqs[i].orphan; d.slot = reqs[i].slot; d.gen = reqs[i].gen; d.t = reqs[i].t; d.rc = rc;
    d2k_lw_complete(lw, &d, now);
}
static int count_op(uint8_t op) { int c = 0; for (int i = 0; i < n_reqs; i++) c += reqs[i].op == op; return c; }
static int last_of(uint8_t op) { for (int i = n_reqs - 1; i >= 0; i--) if (reqs[i].op == op) return i; return -1; }
static d2k_ct_tuple tup(int k) {
    d2k_ct_tuple t; memset(&t, 0, sizeof t);
    t.family = 4; t.proto = 6; t.src[0] = 192; t.src[3] = (uint8_t)(60 + k); t.dst[0] = 1; t.dst[3] = 4;
    t.sport_be[0] = 0xaf; t.sport_be[1] = (uint8_t)k; t.dport_be[1] = 0xbb;
    return t;
}
static const uint8_t TOK[D2K_TRIAL_ID_LEN] = {1, 2, 3}, TOK2[D2K_TRIAL_ID_LEN] = {9, 9, 9};

/* Пакет данных клиента (TCP IPv4) потока t. */
static size_t data_pkt(uint8_t *o, const d2k_ct_tuple *t, uint32_t seq) {
    memset(o, 0, 41);
    o[0] = 0x45; o[3] = 41; o[8] = 64; o[9] = 6;
    memcpy(o + 12, t->src, 4); memcpy(o + 16, t->dst, 4);
    memcpy(o + 20, t->sport_be, 2); memcpy(o + 22, t->dport_be, 2);
    o[24] = (uint8_t)(seq >> 24); o[25] = (uint8_t)(seq >> 16); o[26] = (uint8_t)(seq >> 8); o[27] = (uint8_t)seq;
    o[32] = 0x50; o[33] = 0x18; o[40] = 'q';
    return 41;
}

#ifdef D2K_LW_RAW_MEASURE
static int raw_live, raw_prior, raw_ok, raw_fail, raw_notes;
static struct d2k_rawmeasure_report raw_result;
static int raw_identity(void *ctx,const struct d2k_rawmeasure_request *r,int *previous) {
    (void)ctx;(void)r;*previous=raw_prior;return raw_live;
}
static void raw_ack(void *ctx,int ok,uint8_t reason,const uint8_t token[16]) {
    (void)ctx;(void)reason;(void)token;if(ok)raw_ok++;else raw_fail++;
}
static void raw_note(void *ctx,const struct d2k_rawmeasure_report *r) {
    (void)ctx;CHECK(d2k_rawmeasure_report_valid(r),"invalid report from live observer");raw_notes++;raw_result=*r;
}
static void raw_reset(d2k_lw *lw) {
    reset(lw,D2K_LW_BACKEND_MARK);raw_live=1;raw_prior=raw_ok=raw_fail=raw_notes=0;
    d2k_lw_raw_ops ops={raw_identity,raw_ack,raw_note,NULL};d2k_lw_raw_hooks(lw,&ops);
}
#endif
static void test_raw_measure(void) {
#ifndef D2K_LW_RAW_MEASURE
    CHECK(0,"raw observation not connected to delivery ownership");
#else
    static d2k_lw lw;struct d2k_rawmeasure_request r={0};uint8_t packet[64];
    r.tuple=tup(3);r.epoch[0]=1;r.generation=7;r.token[0]=9;r.seconds=10;
    /* Slow TCP: preserve the first copy across acknowledged lease renewal. */
    r.seconds=120;
    raw_reset(&lw);d2k_lw_measure(&lw,&r,1*S);
    deliver(&lw,last_of(D2K_LWOP_INSTALL),0,2*S);
    r.renew=1;d2k_lw_measure(&lw,&r,62*S);r.renew=0;
    CHECK(d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),66*S),"slow sample missing");
    d2k_lw_tick(&lw,123*S,0);
    CHECK(!raw_notes,"slow sample discarded at original lease deadline");
    r.renew=1;d2k_lw_measure(&lw,&r,123*S);r.renew=0;
    CHECK(d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),194*S),"slow repeat missing after renewal");
    CHECK(raw_notes==1&&raw_result.code==D2K_RM_REPEAT_SILENT&&
          raw_result.client_data==2&&raw_result.repeat_gap_ms==128000,
          "renewal reset evidence or lost slow repeat");
    /* No heartbeat: sample must not extend the controller lease. */
    raw_reset(&lw);d2k_lw_measure(&lw,&r,1*S);
    deliver(&lw,last_of(D2K_LWOP_INSTALL),0,2*S);
    d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),66*S);
    d2k_lw_tick(&lw,122*S,0);
    CHECK(raw_notes==1&&raw_result.code==D2K_RM_UNINFORMATIVE,"lost renewal leaked observer");
    /* Empty renewals never postpone the acquisition deadline. */
    raw_reset(&lw);d2k_lw_measure(&lw,&r,1*S);
    deliver(&lw,last_of(D2K_LWOP_INSTALL),0,2*S);
    r.renew=1;d2k_lw_measure(&lw,&r,62*S);r.renew=0;d2k_lw_tick(&lw,122*S,0);
    CHECK(raw_notes==1,"empty observation renewed indefinitely");
    /* Renewal cannot create an observer after completion/restart. */
    raw_reset(&lw);r.renew=1;d2k_lw_measure(&lw,&r,1*S);r.renew=0;
    CHECK(raw_fail==1&&!n_reqs,"renewal created an absent observation");
    /* Different owner and changed lease cannot reset/extend this sample. */
    raw_reset(&lw);d2k_lw_measure(&lw,&r,1*S);
    deliver(&lw,last_of(D2K_LWOP_INSTALL),0,2*S);
    d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),66*S);
    r.token[0]++;d2k_lw_measure(&lw,&r,70*S);r.token[0]--;
    CHECK(raw_fail==1,"foreign owner displaced observation");
    r.renew=1;r.seconds=119;d2k_lw_measure(&lw,&r,71*S);r.seconds=120;r.renew=0;
    CHECK(raw_fail==2,"renewal changed observation terms");
    CHECK(d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),72*S),"foreign request destroyed sample");
    CHECK(raw_result.client_data==2&&raw_result.code==D2K_RM_REPEAT_SILENT,"foreign request reset evidence");
    raw_reset(&lw);d2k_lw_measure(&lw,&r,1*S);
    deliver(&lw,last_of(D2K_LWOP_INSTALL),0,2*S);
    r.renew=1;r.seconds=0;d2k_lw_measure(&lw,&r,3*S);
    CHECK(!lw.n_obs&&count_op(D2K_LWOP_CLEAR)==1,"cancel failed to clear own delivery");
    CHECK(flags_on==1&&!flags_off,"pending cleanup lost flow ownership");
    deliver(&lw,last_of(D2K_LWOP_CLEAR),0,4*S);
    CHECK(flags_off==1,"cancel cleanup retained idle flow ownership");
    r.renew=0;r.seconds=10;
    raw_reset(&lw);d2k_lw_measure(&lw,&r,10*S);
    CHECK(count_op(D2K_LWOP_INSTALL)==1&&!raw_ok,"raw ready before install");
    CHECK(!d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),11*S),"raw data counted before ready");
    deliver(&lw,last_of(D2K_LWOP_INSTALL),0,20*S);CHECK(raw_ok==1,"raw readiness missing");
    CHECK(d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),21*S),"raw client not observed");
    CHECK(d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),22*S),"raw repeat not observed");
    CHECK(raw_notes==1,"measured repeat waits unnecessarily for entire lease");
    d2k_lw_tick(&lw,29*S,0);
    d2k_lw_tick(&lw,30*S,0);
    CHECK(raw_notes==1&&raw_result.code==D2K_RM_REPEAT_SILENT&&raw_result.exact_repeats==1&&raw_result.request.generation==7,"raw facts/context lost");
    CHECK(count_op(D2K_LWOP_CLEAR)==1,"raw owner leaked after report");
    CHECK(raw_result.repeat_gap_ms==1000u&&raw_result.repeat_age_ms==0,
          "observed copy times (21 s, 22 s) not carried as repeat facts");
#ifdef D2K_RM_SAMPLE_DIGEST_LEN
    static const uint8_t q_digest[32]={0x8e,0x35,0xc2,0xcd,0x3b,0xf6,0x64,0x1b,0xdb,0x0e,0x20,0x50,0xb7,0x69,0x32,0xcb,0xb2,0xe6,0x03,0x4a,0x0d,0xda,0xcc,0x1d,0x9b,0xea,0x82,0xa6,0xba,0x57,0xf7,0xcf};
    CHECK(!memcmp(raw_result.sample_digest,q_digest,32),"result digest does not bind observed q payload");
#else
    CHECK(0,"measurement lost payload content identity");
#endif

    for(int progress=0;progress<2;progress++) {
        raw_reset(&lw);d2k_lw_measure(&lw,&r,10*S);
        deliver(&lw,last_of(D2K_LWOP_INSTALL),0,20*S);
        d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),21*S);
        data_pkt(packet,&r.tuple,7000);packet[3]=40;
        memcpy(packet+12,r.tuple.dst,4);memcpy(packet+16,r.tuple.src,4);
        memcpy(packet+20,r.tuple.dport_be,2);memcpy(packet+22,r.tuple.sport_be,2);
        packet[28]=packet[29]=packet[30]=0;packet[31]=(uint8_t)(99+progress);
        d2k_lw_packet(&lw,packet,40,22*S);
        CHECK(raw_notes==progress,"duplicate ACK prematurely ended observation");
        if(!progress)d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),23*S);
        CHECK(raw_notes==1 && raw_result.server_packets==1 &&
              (raw_result.flags&D2K_RM_TCP_ACK) && raw_result.tcp_ack==(uint32_t)(99+progress),
              "TCP ACK facts lost between observer and wire report");
        CHECK(raw_result.code==(progress?D2K_RM_SERVER_PRESENT:D2K_RM_REPEAT_SILENT),
              "TCP presence confused with cumulative ACK progress");
    }
    raw_reset(&lw);d2k_lw_measure(&lw,&r,10*S);raw_live=0;
    deliver(&lw,last_of(D2K_LWOP_INSTALL),0,20*S);
    CHECK(!raw_ok&&raw_fail==1&&!raw_notes&&count_op(D2K_LWOP_CLEAR)==1,"new connection inherited pending measurement");
    raw_reset(&lw);d2k_lw_measure(&lw,&r,10*S);deliver(&lw,last_of(D2K_LWOP_INSTALL),0,20*S);
    raw_live=0;CHECK(!d2k_lw_packet(&lw,packet,data_pkt(packet,&r.tuple,99),21*S),"new connection counted in ready measurement");
    CHECK(raw_fail==1&&!raw_notes&&count_op(D2K_LWOP_CLEAR)==1,"stale measurement not cancelled");
    raw_reset(&lw);d2k_lw_measure(&lw,&r,10*S);d2k_lw_peer_closed(&lw,11*S);
    deliver(&lw,last_of(D2K_LWOP_INSTALL),0,20*S);
    CHECK(!raw_ok&&!raw_fail&&!raw_notes&&count_op(D2K_LWOP_CLEAR)==1,"old controller got raw completion");
    deliver(&lw,last_of(D2K_LWOP_CLEAR),0,21*S);
    CHECK(flags_on==1&&flags_off==1,"controller disconnect retained flow ownership");
    raw_reset(&lw);d2k_lw_measure(&lw,&r,10*S);deliver(&lw,last_of(D2K_LWOP_INSTALL),-1,20*S);
    CHECK(!raw_ok&&raw_fail==1&&count_op(D2K_LWOP_CLEAR)==1,"uncertain raw install not refused/cleaned");
    raw_reset(&lw);raw_live=0;d2k_lw_measure(&lw,&r,10*S);
    CHECK(raw_fail==1&&!n_reqs,"stale request changed delivery");
    raw_reset(&lw);CHECK(!d2k_lw_trial_add(&lw,&r.tuple,100*S,10*S),"raw coexist trial");
    d2k_lw_measure(&lw,&r,11*S);deliver(&lw,last_of(D2K_LWOP_INSTALL),0,20*S);
    d2k_lw_tick(&lw,30*S,0);CHECK(raw_notes==1&&!count_op(D2K_LWOP_CLEAR),"raw expiration removed another owner's delivery");
    CHECK(flags_on==1&&!flags_off,"measurement completion released another live owner");
    d2k_lw_trial_del(&lw,&r.tuple,31*S);CHECK(count_op(D2K_LWOP_CLEAR)==1,"last owner removal did not clean");
    deliver(&lw,last_of(D2K_LWOP_CLEAR),0,32*S);
    CHECK(flags_off==1,"last owner cleanup retained flow ownership");
    raw_reset(&lw);d2k_lw_measure(&lw,&r,10*S);deliver(&lw,last_of(D2K_LWOP_INSTALL),0,20*S);
    d2k_lw_tick(&lw,29*S,0);CHECK(!raw_notes,"raw lease starts at request instead of readiness");
    d2k_lw_measure(&lw,&r,29*S);d2k_lw_tick(&lw,30*S,0);
    CHECK(raw_notes==1,"duplicate request extended measurement lease");
    r.tuple.proto=17;
    for (int history=0;history<2;history++) {
        raw_reset(&lw);raw_prior=history;
        d2k_lw_measure(&lw,&r,10*S);deliver(&lw,last_of(D2K_LWOP_INSTALL),0,20*S);
        memset(packet,0,sizeof packet);packet[0]=0x45;packet[3]=29;packet[9]=17;
        memcpy(packet+12,r.tuple.src,4);memcpy(packet+16,r.tuple.dst,4);
        memcpy(packet+20,r.tuple.sport_be,2);memcpy(packet+22,r.tuple.dport_be,2);packet[25]=9;packet[28]='q';
        CHECK(d2k_lw_packet(&lw,packet,29,21*S),"UDP not delivered to measurement");
        CHECK(d2k_lw_packet(&lw,packet,29,22*S),"UDP repeat not delivered");
        CHECK(raw_notes==1&&raw_result.code==(history?D2K_RM_REPEAT_SILENT:D2K_RM_UNINFORMATIVE),"UDP one-way ambiguity retained observation until lease expiry");
        CHECK(count_op(D2K_LWOP_CLEAR)==1,"terminal UDP result retained delivery owner");
        d2k_lw_tick(&lw,30*S,0);
        CHECK(raw_notes==1&&raw_result.code==(history?D2K_RM_REPEAT_SILENT:D2K_RM_UNINFORMATIVE),"UDP one-way duplicates treated as failure");
    }
    raw_reset(&lw);d2k_lw_measure(&lw,&r,10*S);deliver(&lw,last_of(D2K_LWOP_INSTALL),0,20*S);
    memcpy(packet+12,r.tuple.dst,4);memcpy(packet+16,r.tuple.src,4);
    memcpy(packet+20,r.tuple.dport_be,2);memcpy(packet+22,r.tuple.sport_be,2);
    packet[21]++;CHECK(!d2k_lw_packet(&lw,packet,29,21*S)&&!raw_notes,"foreign service reply completed measurement");packet[21]--;
    CHECK(d2k_lw_packet(&lw,packet,29,22*S)&&raw_notes==1&&raw_result.code==D2K_RM_SERVER_PRESENT,"own UDP reply not observed");

#endif
}

int main(void) {
    test_raw_measure();
    static d2k_lw lw;
    d2k_ct_tuple t = tup(1);
    uint8_t pkt[64];

    /* 1. Наблюдение: подтверждение и срок — от готовности установки; пакеты
          до неё не считаются; итог и снятие по сроку. */
    reset(&lw, D2K_LW_BACKEND_MARK);
    d2k_lw_observe(&lw, &t, 60, TOK, 10 * S);
    CHECK(count_op(D2K_LWOP_INSTALL) == 1 && acks_ok == 0 && acks_fail == 0, "наблюдение подтверждено до установки");
    CHECK(d2k_lw_packet(&lw, pkt, data_pkt(pkt, &t, 100), 11 * S) == 0, "пакет до готовности учтён в наблюдении");
    deliver(&lw, last_of(D2K_LWOP_INSTALL), 0, 20 * S);
    CHECK(acks_ok == 1 && !memcmp(last_ack_token, TOK, D2K_TRIAL_ID_LEN), "готовность не подтверждена своим токеном");
    d2k_lw_tick(&lw, 79 * S, 0);
    CHECK(notes == 0, "срок наблюдения отсчитан от запроса, а не от готовности");
    d2k_lw_tick(&lw, 80 * S, 0);
    CHECK(notes == 1 && last_note_code == D2K_LATEOBS_NOTHING && count_op(D2K_LWOP_CLEAR) == 1, "срок: итог или снятие");
    CHECK(!strstr(said, "снята"), "«снята» до подтверждения снятия");
    deliver(&lw, last_of(D2K_LWOP_CLEAR), 0, 81 * S);
    CHECK(d2k_lw_pending_clears(&lw) == 0 && lw.st.cleared == 1 && strstr(said, "снята"), "снятие не завершено");

    /* 2. Отмена во время установки: после итога установки — снятие. */
    reset(&lw, D2K_LW_BACKEND_MARK);
    CHECK(d2k_lw_trial_add(&lw, &t, 0, 10 * S) == 0, "опыт не принят");
    d2k_lw_trial_del(&lw, &t, 11 * S);
    CHECK(count_op(D2K_LWOP_CLEAR) == 0, "снятие ушло, пока установка в полёте");
    deliver(&lw, last_of(D2K_LWOP_INSTALL), 0, 12 * S);
    CHECK(count_op(D2K_LWOP_CLEAR) == 1, "отменённая установка не снята после итога");
    deliver(&lw, last_of(D2K_LWOP_CLEAR), 0, 13 * S);
    CHECK(d2k_lw_pending_clears(&lw) == 0, "отменённая установка: слот не освобождён");

    /* 3. Итог чужого поколения не принимается. */
    reset(&lw, D2K_LW_BACKEND_MARK);
    d2k_lw_observe(&lw, &t, 60, TOK, 10 * S);
    { int i = last_of(D2K_LWOP_INSTALL); reqs[i].gen += 99; deliver(&lw, i, 0, 11 * S); reqs[i].gen -= 99; }
    CHECK(acks_ok == 0, "итог чужого поколения подтвердил наблюдение");
    deliver(&lw, last_of(D2K_LWOP_INSTALL), 0, 12 * S);
    CHECK(acks_ok == 1, "итог своего поколения не принят");

    /* 4. Неясная установка (FAIL): отказ владельцу и снятие; сбой снятия — повтор. */
    reset(&lw, D2K_LW_BACKEND_MARK);
    d2k_lw_observe(&lw, &t, 60, TOK, 10 * S);
    deliver(&lw, last_of(D2K_LWOP_INSTALL), -1, 11 * S);
    CHECK(acks_fail == 1 && last_ack_reason == D2K_ACK_UNAVAILABLE && count_op(D2K_LWOP_CLEAR) == 1,
          "неясная установка: нет отказа или бит без хозяина");
    deliver(&lw, last_of(D2K_LWOP_CLEAR), -1, 12 * S);
    CHECK(d2k_lw_pending_clears(&lw) == 1 && lw.st.cleared == 0 && lw.st.clear_fail == 1, "сбой снятия не удержан");
    d2k_lw_tick(&lw, 12 * S + S / 2, 0);
    CHECK(count_op(D2K_LWOP_CLEAR) == 1, "повтор снятия раньше отката");
    d2k_lw_tick(&lw, 13 * S + 1, 0);
    CHECK(count_op(D2K_LWOP_CLEAR) == 2, "повтор снятия не сделан");
    deliver(&lw, last_of(D2K_LWOP_CLEAR), 0, 14 * S);
    CHECK(d2k_lw_pending_clears(&lw) == 0 && lw.st.cleared == 1, "повтор снятия не завершил");

    /* 5. Записи нет (GONE): отказ, снимать нечего. */
    reset(&lw, D2K_LW_BACKEND_RULES);
    d2k_lw_observe(&lw, &t, 60, TOK, 10 * S);
    deliver(&lw, last_of(D2K_LWOP_INSTALL), 1, 11 * S);
    CHECK(acks_fail == 1 && count_op(D2K_LWOP_CLEAR) == 0 && d2k_lw_pending_clears(&lw) == 0, "GONE: снятие или нет отказа");

    /* 6. Очередь исполнителя полна: установке — сразу отказ; снятию — повтор позже. */
    reset(&lw, D2K_LW_BACKEND_MARK);
    queue_full = 1;
    d2k_lw_observe(&lw, &t, 60, TOK, 10 * S);
    CHECK(acks_fail == 1 && lw.st.queue_full == 1, "полная очередь: отказ не сразу");
    CHECK(d2k_lw_trial_add(&lw, &t, 0, 10 * S) == -1, "полная очередь: опыт принят без установки");
    queue_full = 0;
    d2k_lw_trial_add(&lw, &t, 0, 11 * S);
    deliver(&lw, last_of(D2K_LWOP_INSTALL), 0, 12 * S);
    queue_full = 1;
    d2k_lw_trial_del(&lw, &t, 13 * S);
    CHECK(d2k_lw_pending_clears(&lw) == 1, "полная очередь: снятие потеряно");
    queue_full = 0;
    d2k_lw_tick(&lw, 15 * S, 0);
    CHECK(count_op(D2K_LWOP_CLEAR) == 1, "снятие не повторено после освобождения очереди");

    /* 7. Опыт и наблюдение одного кортежа: доставка уже есть — подтверждение
          сразу; снятие опыта её не трогает; конец наблюдения снимает. */
    reset(&lw, D2K_LW_BACKEND_MARK);
    d2k_lw_trial_add(&lw, &t, 0, 10 * S);
    deliver(&lw, last_of(D2K_LWOP_INSTALL), 0, 11 * S);
    d2k_lw_observe(&lw, &t, 60, TOK, 20 * S);
    CHECK(acks_ok == 1 && count_op(D2K_LWOP_INSTALL) == 1, "при готовой доставке наблюдение ждёт или ставит снова");
    d2k_lw_trial_del(&lw, &t, 21 * S);
    CHECK(count_op(D2K_LWOP_CLEAR) == 0, "снятие опыта сняло доставку наблюдения");
    d2k_lw_tick(&lw, 80 * S, 0);
    CHECK(notes == 1 && count_op(D2K_LWOP_CLEAR) == 1, "конец наблюдения не снял доставку");

    /* 8. Замена ждущего наблюдения: прежнему — отказ, новому — подтверждение. */
    reset(&lw, D2K_LW_BACKEND_MARK);
    d2k_lw_observe(&lw, &t, 60, TOK, 10 * S);
    d2k_lw_observe(&lw, &t, 60, TOK2, 11 * S);
    CHECK(acks_fail == 1 && !memcmp(last_ack_token, TOK, D2K_TRIAL_ID_LEN), "прежнему ждущему наблюдению нет отказа");
    deliver(&lw, last_of(D2K_LWOP_INSTALL), 0, 12 * S);
    CHECK(acks_ok == 1 && !memcmp(last_ack_token, TOK2, D2K_TRIAL_ID_LEN), "новое наблюдение не подтверждено");

    /* 9. Контроллер ушёл во время установки: подтверждения нет, затем снятие. */
    reset(&lw, D2K_LW_BACKEND_MARK);
    d2k_lw_observe(&lw, &t, 60, TOK, 10 * S);
    d2k_lw_tick(&lw, 11 * S, 1);
    deliver(&lw, last_of(D2K_LWOP_INSTALL), 0, 12 * S);
    CHECK(acks_ok == 0 && acks_fail == 0 && count_op(D2K_LWOP_CLEAR) == 1, "уход контроллера: подтверждение или нет снятия");

    /* 10. Способа нет (ни маски, ни правил): ждущим — отказ, новым — сразу. */
    reset(&lw, D2K_LW_BACKEND_NONE);
    d2k_lw_observe(&lw, &t, 60, TOK, 10 * S);
    CHECK(acks_fail == 1 && last_ack_reason == D2K_ACK_UNAVAILABLE && count_op(D2K_LWOP_INSTALL) == 0,
          "без способа наблюдение не отвергнуто сразу");
    {   /* заявка до итога INIT — отказ по его итогу */
        n_reqs = queue_full = acks_ok = acks_fail = 0;
        d2k_lw_init(&lw, &OPS);
        d2k_lw_start(&lw, 1 * S);
        int init = last_of(D2K_LWOP_INIT);
        d2k_lw_observe(&lw, &t, 60, TOK, 2 * S);
        CHECK(acks_fail == 0 && acks_ok == 0, "до выбора способа — преждевременный ответ");
        d2k_lw_done d; memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_INIT; d.gen = reqs[init].gen; d.backend = D2K_LW_BACKEND_NONE;
        d2k_lw_complete(&lw, &d, 3 * S);
        int inst = last_of(D2K_LWOP_INSTALL);
        if (inst >= 0) deliver(&lw, inst, -1, 4 * S);
        CHECK(acks_fail == 1 && acks_ok == 0, "способа не оказалось — ждущему наблюдению нет отказа");
    }

    /* 11. Уборка способа «метка»: сироты снимаются, кроме записи живого
           владельца; сбой — повтор; переполнение — следующий проход. */
    {
        n_reqs = queue_full = 0; said[0] = 0;
        d2k_lw_init(&lw, &OPS);
        d2k_lw_start(&lw, 1 * S);
        int init = last_of(D2K_LWOP_INIT), sw = last_of(D2K_LWOP_SWEEP);
        CHECK(init == 0 && sw == 1, "старт: не «способ, затем уборка»");
        d2k_lw_done d; memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_INIT; d.gen = reqs[init].gen; d.backend = D2K_LW_BACKEND_MARK;
        d2k_lw_complete(&lw, &d, 1 * S);
        d2k_ct_tuple own = tup(7);
        d2k_lw_trial_add(&lw, &own, 0, 2 * S);
        deliver(&lw, last_of(D2K_LWOP_INSTALL), 0, 2 * S);
        memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_SWEEP; d.gen = reqs[sw].gen; d.rc = 0; d.dump_ok = 1; d.over = 1;
        d.n = 3; d.list[0] = tup(20); d.list[1] = own; d.list[2] = tup(21);
        int before = n_reqs;
        d2k_lw_complete(&lw, &d, 3 * S);
        int orphan_clears = 0, own_cleared = 0;
        for (int i = before; i < n_reqs; i++) if (reqs[i].op == D2K_LWOP_CLEAR) {
            orphan_clears++;
            if (!memcmp(&reqs[i].t, &own, sizeof own)) own_cleared = 1;
        }
        CHECK(orphan_clears == 2 && !own_cleared, "уборка: сироты не сняты или снята запись живого владельца");
        CHECK(d2k_lw_sweep_pending(&lw), "уборка с переполнением названа законченной");
        deliver(&lw, before, -1, 4 * S);           /* сбой снятия сироты */
        deliver(&lw, before + 1, 0, 4 * S);
        d2k_lw_tick(&lw, 6 * S, 0);
        int again = last_of(D2K_LWOP_CLEAR);
        CHECK(again >= before + 2 && !memcmp(&reqs[again].t, &d.list[0], sizeof own), "снятие сироты не повторено");
        deliver(&lw, again, 0, 6 * S);
        d2k_lw_tick(&lw, 7 * S, 0);
        int sw2 = last_of(D2K_LWOP_SWEEP);
        CHECK(sw2 > sw, "переполнение: следующий проход уборки не начат");
        memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_SWEEP; d.gen = reqs[sw2].gen; d.rc = 0; d.dump_ok = 1; d.n = 1; d.list[0] = own;
        d2k_lw_complete(&lw, &d, 8 * S);
        CHECK(!d2k_lw_sweep_pending(&lw) && lw.st.swept == 2, "уборка не закончилась или счёт неверен");
    }

    /* 12. Уборка способа «правила»: свои цепочки очищаются; сбой — повтор. */
    {
        n_reqs = 0;
        d2k_lw_init(&lw, &OPS);
        d2k_lw_start(&lw, 1 * S);
        d2k_lw_done d; memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_INIT; d.gen = reqs[0].gen; d.backend = D2K_LW_BACKEND_RULES;
        d2k_lw_complete(&lw, &d, 1 * S);
        memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_SWEEP; d.gen = reqs[1].gen; d.rc = -1;
        d2k_lw_complete(&lw, &d, 2 * S);
        CHECK(d2k_lw_sweep_pending(&lw) && lw.st.sweep_fail == 1, "сбой очистки своих цепочек не удержан");
        d2k_lw_tick(&lw, 4 * S, 0);
        int sw2 = last_of(D2K_LWOP_SWEEP);
        CHECK(sw2 > 1, "очистка своих цепочек не повторена");
        memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_SWEEP; d.gen = reqs[sw2].gen; d.rc = 0;
        d2k_lw_complete(&lw, &d, 4 * S);
        CHECK(!d2k_lw_sweep_pending(&lw), "очистка своих цепочек не закончилась");
    }

    /* 13. Гонка уборки способа «правила» (находка ревью): очистка своих цепочек
           (-F) удалила бы правила, поставленные после её неудачного прохода.
           Барьер: пока способ не известен или стартовая очистка не прошла
           целиком (IPv4 и IPv6), установок нет — владельцы ждут; после неё —
           установка и подтверждение. Заявка, пришедшая до итога INIT, тоже ждёт. */
    {
        n_reqs = queue_full = acks_ok = acks_fail = 0;
        d2k_lw_init(&lw, &OPS);
        d2k_lw_start(&lw, 1 * S);
        d2k_lw_observe(&lw, &t, 60, TOK, 1 * S);            /* до итога INIT */
        CHECK(count_op(D2K_LWOP_INSTALL) == 0, "установка ушла до выбора способа (встанет за уборкой)");
        d2k_lw_done d; memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_INIT; d.gen = reqs[0].gen; d.backend = D2K_LW_BACKEND_RULES;
        d2k_lw_complete(&lw, &d, 2 * S);
        CHECK(count_op(D2K_LWOP_INSTALL) == 0, "установка ушла до стартовой очистки своих цепочек");
        memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_SWEEP; d.gen = reqs[1].gen; d.rc = -1;    /* IPv4 очищен, IPv6 — сбой */
        d2k_lw_complete(&lw, &d, 3 * S);
        d2k_ct_tuple t2 = tup(2);
        d2k_lw_observe(&lw, &t2, 60, TOK2, 3 * S);
        CHECK(count_op(D2K_LWOP_INSTALL) == 0 && acks_ok == 0 && acks_fail == 0,
              "после неудачной очистки установка ушла (повтор очистки удалит живые правила)");
        d2k_lw_tick(&lw, 5 * S, 0);
        int sw2 = last_of(D2K_LWOP_SWEEP);
        CHECK(sw2 > 1 && count_op(D2K_LWOP_INSTALL) == 0, "повтор очистки не начат или установки до него");
        memset(&d, 0, sizeof d);
        d.op = D2K_LWOP_SWEEP; d.gen = reqs[sw2].gen; d.rc = 0;
        d2k_lw_complete(&lw, &d, 5 * S);
        CHECK(count_op(D2K_LWOP_INSTALL) == 2, "после стартовой очистки ждущие установки не начаты");
        for (int i = 0; i < n_reqs; i++) if (reqs[i].op == D2K_LWOP_INSTALL) deliver(&lw, i, 0, 6 * S);
        CHECK(acks_ok == 2, "ждущие наблюдения не подтверждены после установки");
        d2k_lw_tick(&lw, 7 * S, 0);
        CHECK(count_op(D2K_LWOP_SWEEP) == 2, "очистка своих цепочек после готовности живых правил");
    }

    /* 14. Быстрое переподключение (находка ревью): A просит наблюдение, установка
           задерживается, A отключается, B подключается раньше такта. Отмена — сразу
           по событию отключения, не опросом раз в секунду; итог установки A не
           подтверждает ничего B, доставка A снимается; наблюдение B работает. */
    {
        reset(&lw, D2K_LW_BACKEND_MARK);
        d2k_lw_observe(&lw, &t, 60, TOK, 10 * S);         /* A */
        int ia = last_of(D2K_LWOP_INSTALL);
        d2k_lw_peer_closed(&lw, 10 * S + 1);               /* A ушёл; B подключился (тактов не было) */
        deliver(&lw, ia, 0, 10 * S + 2);                   /* установка A дошла */
        CHECK(acks_ok == 0 && acks_fail == 0, "итог установки прежнего подключения подтвердил новому контроллеру");
        CHECK(count_op(D2K_LWOP_CLEAR) == 1, "доставка прежнего подключения не снята");
        deliver(&lw, last_of(D2K_LWOP_CLEAR), 0, 10 * S + 3);
        d2k_ct_tuple tb = tup(3);
        d2k_lw_observe(&lw, &tb, 60, TOK2, 10 * S + 4);     /* B */
        deliver(&lw, last_of(D2K_LWOP_INSTALL), 0, 10 * S + 5);
        CHECK(acks_ok == 1 && !memcmp(last_ack_token, TOK2, D2K_TRIAL_ID_LEN), "наблюдение нового контроллера не подтверждено");
        CHECK(notes == 0, "итог наблюдения прежнего подключения ушёл новому");
    }

    puts(fails ? "поздняя доставка: ЕСТЬ ПРОВАЛЫ" : "поздняя доставка: все проверки прошли");
    return fails ? 1 : 0;
}
