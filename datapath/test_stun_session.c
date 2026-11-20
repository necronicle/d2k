/* STUN-only regression: intentionally contains no QUIC vectors or assertions. */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "d2k_journal.h"
#include "d2k_session.h"
#include "d2k_nat.h"

/* Synthetic tuples have no kernel conntrack entry. Model the confirmed
 * tuple explicitly for late-execution tests on both macOS and Linux. */
static unsigned confirmed_calls;
static int confirmed_tuple(const char *path,uint8_t proto,uint32_t src,uint16_t sport,
                           uint32_t dst,uint16_t dport,uint32_t *out,uint16_t *port) {
    (void)path;(void)proto;(void)dst;(void)dport;
    confirmed_calls++;*out=src;*port=sport;return 0;
}

static int fails;
#define CHECK(ok, msg) do { \
    if (!(ok)) { printf("FAIL: %s\n", msg); fails++; } \
} while (0)

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static size_t binding(uint8_t *p, uint16_t type, const uint8_t txid[12]) {
    memset(p, 0, 20);
    p[0] = (uint8_t)(type >> 8);
    p[1] = (uint8_t)type;
    p[4] = 0x21; p[5] = 0x12; p[6] = 0xa4; p[7] = 0x42;
    memcpy(p + 8, txid, 12);
    return 20;
}

static size_t binding_response(uint8_t *p, const uint8_t txid[12], int family) {
    binding(p, 0x0101, txid);
    size_t len = family == 6 ? 20 : 8;
    memset(p + 20, 0, 4 + len);
    wr16(p + 2, (uint16_t)(4 + len));
    wr16(p + 20, 0x0020); wr16(p + 22, (uint16_t)len);
    p[25] = family == 6 ? 2 : 1;
    wr16(p + 26, (uint16_t)(50000 ^ 0x2112));
    return 24 + len;
}

static uint16_t g_server_port = 3478;

static size_t udp_packet(uint8_t *p, int reverse, uint16_t client_port,
                         const uint8_t *payload, size_t payload_len) {
    size_t n = 28 + payload_len;
    memset(p, 0, n);
    p[0] = 0x45;
    wr16(p + 2, (uint16_t)n);
    p[8] = 64;
    p[9] = 17;
    if (!reverse) {
        memcpy(p + 12, "\xc0\xa8\x01\x43", 4);
        memcpy(p + 16, "\x01\x02\x03\x04", 4);
        wr16(p + 20, client_port);
        wr16(p + 22, g_server_port);
    } else {
        memcpy(p + 12, "\x01\x02\x03\x04", 4);
        memcpy(p + 16, "\xc0\xa8\x01\x43", 4);
        wr16(p + 20, g_server_port);
        wr16(p + 22, client_port);
    }
    wr16(p + 24, (uint16_t)(8 + payload_len));
    if (payload_len) { memcpy(p + 28, payload, payload_len); }
    return n;
}

static size_t journal_kind(const d2k_session *s, uint8_t kind, uint8_t code) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t found = 0;
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == kind && e->code == code) { found++; }
    }
    return found;
}

/* Объявленный голосом план (тот же, что plan_voice_declared в
   test_quic_session.c): REC_PROTO транспорт 17, протокол voice. */
static const uint8_t plan_voice[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 5,
    0x00, 0x02, 0x00, 0x02, 0x11, 0x03,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x00, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Задача 15: экран отдаёт датапату только первые 8 пакетов потока
   (S99d2k, connbytes 0:8), и разговор, шедший во время замера, к моменту
   установки опыта уже невидим. Опыт — клиент LAN + точка STUN-сервера +
   любой клиентский порт + trial ID: его получает первый Binding Request
   следующего потока того же клиента; другой клиент и истёкший lease — нет. */
static void live_trial(void) {
    const uint8_t txid[12] = {9,9,9,9,9,9,9,9,9,9,9,9};
    const uint8_t trial[D2K_TRIAL_ID_LEN] = {0x51,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    const uint64_t ms = 1000000ull;
    uint8_t req[20], resp[32], junk[40], pkt[96], outbuf[1024];
    d2k_result result;
    binding(req, 0x0001, txid);
    binding_response(resp, txid, 4);
    memset(junk, 0x80, sizeof junk);
    d2k_session *s = d2k_session_new(8, 32);
    CHECK(s != NULL, "live-trial session allocation");
    if (!s) { return; }
    d2k_nat_fn saved_nat=d2k_nat_hook;d2k_nat_hook=confirmed_tuple;confirmed_calls=0;
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    /* The call during measurement: only its first 8 packets are queued. */
    size_t n = udp_packet(pkt, 0, 64050, req, sizeof req);
    d2k_session_packet(s, pkt, n, 1 * ms, outbuf, sizeof outbuf, &result);
    for (int i = 0; i < 7; i++) {
        n = udp_packet(pkt, 0, 64050, junk, sizeof junk);
        d2k_session_packet(s, pkt, n, 2 * ms, outbuf, sizeof outbuf, &result);
    }
    d2k_addr_probe_flow f;
    memset(&f, 0, sizeof f);
    f.family = 4;
    memcpy(f.src_ip4, "\xc0\xa8\x01\x43", 4);
    memcpy(f.dst_ip4, "\x01\x02\x03\x04", 4);
    f.src_port_be = 0;
    f.dst_port_be = htons(3478);
    f.transport = 17;
    const uint64_t expires = 10 * ms + 120000 * ms;
    d2k_plan *p = NULL;
    char err[160];
    CHECK(d2k_plan_load(plan_voice, sizeof plan_voice, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_addr_probe(d2k_session_plans(s), &f, trial, 10 * ms,
                                     expires, p) == 0,
          "voice trial installs on client + STUN endpoint, any client port");
    /* Existing tuple exhausted the hello window before the candidate existed. */
    n=udp_packet(pkt,0,64050,req,sizeof req);
    d2k_session_packet(s,pkt,n,19*ms,outbuf,sizeof outbuf,&result);
    CHECK(result.applied,"new candidate must reach a repeated STUN request on existing tuple");
    n = udp_packet(pkt, 0, 64051, req, sizeof req);
    pkt[15] = 0x44;   /* another LAN client */
    d2k_session_packet(s, pkt, n, 20 * ms, outbuf, sizeof outbuf, &result);
    CHECK(!result.applied, "another LAN client does not get the voice trial");
    n = udp_packet(pkt, 0, 64052, req, sizeof req);
    d2k_session_packet(s, pkt, n, 30 * ms, outbuf, sizeof outbuf, &result);
    CHECK(result.applied && memcmp(result.trial_id, trial, sizeof trial) == 0,
          "next STUN flow of the same client gets the trial with its trial ID");
    d2k_result request_execution=result;
    /* Reinstall identical bytes as another trial before the old reply arrives. */
    uint8_t replacement_trial[D2K_TRIAL_ID_LEN];memcpy(replacement_trial,trial,sizeof trial);
    replacement_trial[0]^=0xff;p=NULL;
    CHECK(d2k_plantab_del_addr_probe(d2k_session_plans(s),&f,trial)>0,
          "retire own trial before replacement");
    CHECK(!d2k_plan_load(plan_voice,sizeof plan_voice,&p,err,sizeof err) &&
          !d2k_plantab_set_addr_probe(d2k_session_plans(s),&f,replacement_trial,
                                     31*ms,expires,p),"replace trial before response");
    n=udp_packet(pkt,0,64050,req,sizeof req);
    d2k_session_packet(s,pkt,n,32*ms,outbuf,sizeof outbuf,&result);
    CHECK(result.applied && !memcmp(result.trial_id,replacement_trial,16),
          "changed binding must reach existing STUN tuple with earlier plan");
    n = udp_packet(pkt, 1, 64052, resp, sizeof resp);
    d2k_session_set_hook(s, D2K_HOOK_FORWARD);
    d2k_session_packet(s, pkt, n, 40 * ms, outbuf, sizeof outbuf, &result);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    CHECK(journal_kind(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_STUN) == 1,
          "STUN response for our txid on the trial flow is protocol proof");
    {
        const d2k_journal *j=d2k_session_journal(s);int found=0;
        for(size_t i=0;i<d2k_journal_count(j);i++) {
            const d2k_jrn_entry *e=d2k_journal_at(j,i);
            if(e->kind!=D2K_JRN_EXCHANGE || e->code!=D2K_UDP_PROOF_STUN)continue;
            found=1;
            CHECK(e->execution_id==request_execution.execution_id &&
                  !memcmp(e->plan_id,request_execution.plan_id,16) &&
                  !memcmp(e->trial_id,trial,16) &&
                  d2k_binding_equal(&e->binding,&request_execution.binding),
                  "STUN proof must retain request execution, not replacement trial");
            CHECK(e->num==sizeof resp,"bound STUN proof retains response byte count");
        }
        CHECK(found,"request-bound STUN proof exists");
    }
    /* The earlier request sent without a plan must remain unbound. */
    n=udp_packet(pkt,1,64050,resp,sizeof resp);
    d2k_session_set_hook(s,D2K_HOOK_FORWARD);
    d2k_session_packet(s,pkt,n,41*ms,outbuf,sizeof outbuf,&result);
    {
        const d2k_journal *j=d2k_session_journal(s);int found=0;
        for(size_t i=0;i<d2k_journal_count(j);i++) {
            const d2k_jrn_entry *e=d2k_journal_at(j,i);
            if(e->kind==D2K_JRN_EXCHANGE && e->code==D2K_UDP_PROOF_STUN &&
               (e->key.low_port==htons(64050) || e->key.high_port==htons(64050))) {
                found=1;CHECK(!e->execution_id,"direct request rebound to later trial");
            }
        }
        CHECK(found,"late direct response still observed");
    }
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    n = udp_packet(pkt, 0, 64053, req, sizeof req);
    d2k_session_packet(s, pkt, n, expires + 1, outbuf, sizeof outbuf, &result);
    CHECK(!result.applied, "expired voice trial matches nothing");
    CHECK(confirmed_calls>0,"late STUN execution checked conntrack");
    d2k_nat_hook=saved_nat;
    d2k_session_free(s);
}

/* Задача 17, п.7: класс @discord-voice — только голос Дискорда: IP
   Discovery или STUN на медиапорты Дискорда (50000-50099, как
   DISCORD_MEDIA_PORT_RANGE и voice_ports в core/voice.c). Прочий STUN
   (например, 3478 к не-Discord адресу) имени не получает: его путь —
   адресный, по точке сервера и форме голоса/STUN (задача 16); выдумывать
   ему имя класса значило бы отдать ему чужой постоянный план. */
static void generic_stun(void) {
    const uint8_t txid[12] = {7,7,7,7,7,7,7,7,7,7,7,7};
    uint8_t req[20], pkt[96], outbuf[1024];
    d2k_result result;
    char err[160];
    binding(req, 0x0001, txid);

    d2k_session *s = d2k_session_new(8, 32);
    CHECK(s != NULL, "generic-STUN session allocation");
    if (!s) { return; }
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    d2k_plan *p = NULL;
    CHECK(d2k_plan_load(plan_voice, sizeof plan_voice, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_name_shaped(d2k_session_plans(s),
                                      (const uint8_t *)D2K_VOICE_CLASS,
                                      strlen(D2K_VOICE_CLASS), 1, p,
                                      D2K_PLAN_SHAPE_VOICE) == 0,
          "voice-class plan installs");
    g_server_port = 3478;
    size_t n = udp_packet(pkt, 0, 64061, req, sizeof req);
    d2k_session_packet(s, pkt, n, 1000, outbuf, sizeof outbuf, &result);
    CHECK(!result.applied,
          "STUN to a non-Discord port got the permanent @discord-voice plan");
    CHECK(d2k_session_hellos(s) == 0 && journal_kind(s, D2K_JRN_HELLO_SNI, 0) == 0,
          "STUN to a non-Discord port was named @discord-voice");

    /* Адресный STUN-путь: подтверждённое по точке сервера с формой голоса. */
    const uint8_t server[4] = {1, 2, 3, 4};
    p = NULL;
    CHECK(d2k_plan_load(plan_voice, sizeof plan_voice, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_addr_shaped(d2k_session_plans(s), server, 4, 1, p,
                                      D2K_PLAN_SHAPE_VOICE) == 0,
          "address STUN plan installs");
    n = udp_packet(pkt, 0, 64062, req, sizeof req);
    d2k_session_packet(s, pkt, n, 2000, outbuf, sizeof outbuf, &result);
    CHECK(result.applied, "STUN to a non-Discord port did not take its address-keyed plan");

    /* Медиапорт Дискорда остаётся в голосовом классе. */
    g_server_port = 50004;
    n = udp_packet(pkt, 0, 64063, req, sizeof req);
    d2k_session_packet(s, pkt, n, 3000, outbuf, sizeof outbuf, &result);
    CHECK(d2k_session_hellos(s) == 1 && journal_kind(s, D2K_JRN_HELLO_SNI, 0) == 1,
          "STUN to a Discord media port left the voice class");
    g_server_port = 3478;
    d2k_session_free(s);
}

static void stun_suspect_direction(void) {
    for (int planned=0;planned<2;planned++) {
    d2k_session *s = d2k_session_new(8, 32);
    CHECK(s != NULL, "STUN direction session");
    if (!s) { return; }
    uint8_t req[20], pkt[96], out[512];
    const uint8_t txid[12] = {1,2,3,4};
    d2k_result result;
    binding(req, 0x0001, txid);
    g_server_port = 55000; /* server is higher than client port */
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    d2k_session_set_udp_reverse_hook(s, 1);
    if (planned) {
        d2k_addr_probe_flow f={0};f.family=4;f.transport=17;
        memcpy(f.src_ip4,"\xc0\xa8\x01\x43",4);
        memcpy(f.dst_ip4,"\x01\x02\x03\x04",4);f.dst_port_be=htons(55000);
        uint8_t trial[16]={0x71};d2k_plan *p=NULL;char err[160];
        CHECK(!d2k_plan_load(plan_voice,sizeof plan_voice,&p,err,sizeof err) &&
              !d2k_plantab_set_addr_probe(d2k_session_plans(s),&f,trial,1,10000000000ull,p),
              "silence test trial installation");
    }
    size_t n = udp_packet(pkt, 0, 40000, req, sizeof req);
    d2k_session_packet(s, pkt, n, 1000000000ull, out, sizeof out, &result);
    d2k_result execution=result;
    CHECK(!!execution.applied==planned,"silence test actual execution");
    if(planned) {
        for(size_t i=0;i<(size_t)execution.n_out+1;i++)
            d2k_session_sent(s,1000000001ull+i,&execution.key,execution.execution_id);
    }
    d2k_session_packet(s, pkt, n, 2000000000ull, out, sizeof out, &result);
    CHECK(d2k_session_sweep(s, 5000000000ull) == 1,
          "unanswered repeated STUN request must generate suspicion");
    const d2k_journal *j = d2k_session_journal(s);
    int found = 0;
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == D2K_JRN_SUSPECT) {
            found++;
            CHECK(e->execution_id==execution.execution_id &&
                  !memcmp(e->trial_id,execution.trial_id,16) &&
                  !memcmp(e->plan_id,execution.plan_id,16),"silence lost observed execution identity");
            if(planned) CHECK(d2k_binding_equal(&e->binding,&execution.binding),
                              "silence lost observed binding");
            CHECK(e->d_client_side == D2K_CLIENT_SIDE_HIGH,
                  "STUN suspicion must identify observed client, not smaller port");
        }
    }
    CHECK(found == 1, "one STUN suspicion per flow");
    d2k_session_free(s);
    g_server_port = 3478;
    }
}

static void service_port_scope(void) {
    const uint8_t txid[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    uint8_t req[20], pkt[128], outbuf[2048];
    binding(req, 1, txid);
    for (unsigned family = 4; family <= 6; family += 2) {
        d2k_session *s = d2k_session_new(8, 32);
        CHECK(s != NULL, "service-scoped session");
        if (!s) continue;
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        const uint8_t server6[16] = {0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,1,2,3,4};
        const uint8_t server4[4] = {1,2,3,4};
        d2k_plan *plan = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_voice,sizeof plan_voice,&plan,err,sizeof err)==0 &&
              d2k_plantab_set_endpoint(d2k_session_plans(s),family==4?server4:server6,
                  family,htons(3478),1,plan,D2K_PLAN_SHAPE_VOICE)==0,
              "install STUN plan for exact service port");
        for (unsigned i = 0; i < 3; i++) {
            g_server_port = i == 1 ? 3479 : 3478;
            size_t n = udp_packet(pkt,0,64080+i,req,sizeof req);
            if (family == 6) {
                memmove(pkt+40,pkt+20,n-20);
                memset(pkt,0,40);
                pkt[0]=0x60; wr16(pkt+4,n-20); pkt[6]=17; pkt[7]=64;
                pkt[8]=0x20; pkt[9]=1; pkt[10]=0xd; pkt[11]=0xb8; pkt[23]=1;
                memcpy(pkt+24,server6,16);
                n+=20;
            }
            d2k_result r;
            d2k_session_packet(s,pkt,n,1000+i,outbuf,sizeof outbuf,&r);
            CHECK(r.applied==(i!=1),"STUN packet plan applies only to measured server port");
        }
        CHECK(d2k_session_hellos(s)==0,"service STUN never invents SNI");
        d2k_session_free(s);
    }
    g_server_port=3478;
}

static void controller_stun_trial(void) {
    const uint8_t txid[12]={1,2,3,4,5,6,7,8,9,10,11,12};
    const uint8_t trial[16]={7,6,5,4,3,2,1,1,2,3,4,5,6,7,8,9};
    uint8_t req[20],pkt[128],out[2048];binding(req,1,txid);
    for (unsigned family=4;family<=6;family+=2) {
      for (unsigned wildcard=0;wildcard<2;wildcard++) {
        d2k_session *s=d2k_session_new(8,32);
        CHECK(s!=NULL,"controller trial session");if(!s)continue;
        d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        g_server_port=3478;
        size_t n=udp_packet(pkt,0,64090,req,sizeof req);
        if(family==6) {
            memmove(pkt+40,pkt+20,n-20);memset(pkt,0,40);
            pkt[0]=0x60;wr16(pkt+4,n-20);pkt[6]=17;pkt[7]=64;
            pkt[8]=0x20;pkt[9]=1;pkt[10]=0xd;pkt[11]=0xb8;pkt[23]=1;
            memcpy(pkt+24,pkt+8,16);pkt[39]=2;n+=20;
        }
        d2k_addr_probe_flow f={0};f.family=family;f.transport=17;
        memcpy(family==6?f.src_ip6:f.src_ip4,pkt+(family==6?8:12),family==6?16:4);
        memcpy(family==6?f.dst_ip6:f.dst_ip4,pkt+(family==6?24:16),family==6?16:4);
        f.src_port_be=wildcard?0:htons(64090);f.dst_port_be=htons(3478);
        d2k_plan *plan=NULL;char err[160];
        CHECK(!d2k_plan_load(plan_voice,sizeof plan_voice,&plan,err,sizeof err) &&
              !d2k_plantab_set_addr_probe(d2k_session_plans(s),&f,trial,1,1000000,plan),
              "install controller exact trial or LAN wildcard trial");
        d2k_result r;
        d2k_session_packet_probe(s,pkt,n,100,out,sizeof out,&r);
        if(wildcard) CHECK(!r.applied,"controller STUN must not consume LAN wildcard trial");
        else CHECK(r.applied && !memcmp(r.trial_id,trial,sizeof trial),
                   "controller STUN exact trial executes with its identity");
        d2k_session_free(s);
      }
    }
}

static void binding_response_semantics(void) {
    const uint8_t txid[12] = {7};
    for (int c = 0; c < 11; c++) {
        uint8_t req[20], resp[64], pkt[128], out[512];
        binding(req, 1, txid);
        size_t len = binding_response(resp, txid, c == 7 ? 6 : 4);
        switch (c) {
        case 0: len = binding(resp, 0x0101, txid); break; /* no address */
        case 1: wr16(resp+20, 0x8022); break; /* SOFTWARE only */
        case 2: resp[25] = 3; break; /* unsupported address family */
        case 3: resp[25] = 2; break; /* IPv6 address truncated to IPv4 size */
        case 4: wr16(resp+2, 8); wr16(resp+22, 4); len=28; break;
        case 5: /* A valid address cannot excuse a malformed later attribute. */
            wr16(resp+2, 16); wr16(resp+32, 0x8022); wr16(resp+34, 8); len=36; break;
        case 8: /* Optional attribute and its padding before the address. */
            memmove(resp+28,resp+20,len-20);
            wr16(resp+20,0x8022);wr16(resp+22,1);memset(resp+24,0,4);
            len+=8;wr16(resp+2,(uint16_t)(len-20));break;
        case 9: resp[24]=0xff; break; /* Reserved byte is ignored by receivers. */
        case 10: resp[8]^=0xff; break; /* Valid body, foreign transaction. */
        default: break;
        }
        d2k_session *s = d2k_session_new(8,32);
        CHECK(s != NULL,"STUN semantic fixture allocation"); if(!s) continue;
        d2k_result r;
        size_t n=udp_packet(pkt,0,64100,req,sizeof req);
        d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        d2k_session_packet(s,pkt,n,1000,out,sizeof out,&r);
        n=udp_packet(pkt,1,64100,resp,len);
        d2k_session_set_hook(s,D2K_HOOK_FORWARD);
        d2k_session_packet(s,pkt,n,2000,out,sizeof out,&r);
        size_t proof=journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN);
        if(proof!=(size_t)(c>=6 && c<=9)) { printf("STUN semantic case %d proof=%zu\n",c,proof); fails++; }
        if (c < 6 || c == 10) {
            len=binding_response(resp,txid,4);
            n=udp_packet(pkt,1,64100,resp,len);
            d2k_session_packet(s,pkt,n,3000,out,sizeof out,&r);
            CHECK(journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN)==1,
                  "invalid response must not suppress later valid STUN proof");
        }
        d2k_session_free(s);
    }
}

static void repeated_trial_attribution(void) {
    d2k_session *s=d2k_session_new(16,64);CHECK(s!=NULL,"repeated trial session");if(!s)return;
    d2k_nat_fn saved_nat=d2k_nat_hook;d2k_nat_hook=confirmed_tuple;
    d2k_addr_probe_flow f={0};f.family=4;f.transport=17;f.dst_port_be=htons(3478);
    memcpy(f.src_ip4,"\xc0\xa8\x01\x43",4);memcpy(f.dst_ip4,"\x01\x02\x03\x04",4);
    uint8_t txid[12]={7},req[20],resp[32],pkt[96],out[1024],trial[16]={1};
    d2k_result r;d2k_plan *p=NULL;char err[160];
    binding(req,1,txid);binding_response(resp,txid,4);
    for(unsigned attempt=0;attempt<2;attempt++) {
        if(attempt) {
            CHECK(d2k_plantab_del_addr_probe(d2k_session_plans(s),&f,trial)>0,"retire first trial");
            trial[0]++;
        }
        CHECK(!d2k_plan_load(plan_voice,sizeof plan_voice,&p,err,sizeof err) &&
              !d2k_plantab_set_addr_probe(d2k_session_plans(s),&f,trial,1,10000000000ull,p),"install repeated trial");
        size_t n=udp_packet(pkt,0,42000,req,sizeof req);
        d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        d2k_session_packet(s,pkt,n,1000000000ull+attempt*1000000000ull,out,sizeof out,&r);
        CHECK(r.applied && !memcmp(r.trial_id,trial,16),"each distinct binding must execute on same transaction");
        for(size_t i=0;i<(size_t)r.n_out+1;i++)d2k_session_sent(s,1000000001ull+attempt*1000000000ull+i,&r.key,r.execution_id);
    }
    size_t n=udp_packet(pkt,1,42000,resp,sizeof resp);
    d2k_session_set_hook(s,D2K_HOOK_FORWARD);
    d2k_session_packet(s,pkt,n,2100000000ull,out,sizeof out,&r);
    const d2k_journal *j=d2k_session_journal(s);int found=0;
    for(size_t i=0;i<d2k_journal_count(j);i++) {
        const d2k_jrn_entry *e=d2k_journal_at(j,i);
        if(e->kind==D2K_JRN_EXCHANGE && e->code==D2K_UDP_PROOF_STUN) {
            found=1;CHECK(!e->execution_id,"ambiguous retransmission response credited to a candidate");
        }
    }
    CHECK(found,"ambiguous response must remain observable");
    d2k_nat_hook=saved_nat;
    d2k_session_free(s);
}

static void transaction_packet(d2k_session *s, unsigned id, int response, uint64_t ms) {
    uint8_t txid[12]={0},payload[32],pkt[96],out[1024];d2k_result result;
    txid[0]=(uint8_t)id;
    size_t len=response ? binding_response(payload,txid,4) : binding(payload,1,txid);
    size_t n=udp_packet(pkt,response,41000,payload,len);
    d2k_session_set_hook(s,response ? D2K_HOOK_FORWARD : D2K_HOOK_POSTROUTING);
    d2k_session_packet(s,pkt,n,ms*1000000ull,out,sizeof out,&result);
}

static void repeated_transactions(void) {
    d2k_session *s=d2k_session_new(16,128);
    CHECK(s!=NULL,"transaction session");if(!s)return;
    d2k_session_set_udp_reverse_hook(s,1);
    transaction_packet(s,1,0,1000);transaction_packet(s,1,1,1100);
    transaction_packet(s,2,0,10000);transaction_packet(s,2,0,10020);
    CHECK(!d2k_session_sweep(s,10030000000ull),"new transaction inherited old silence timer");
    transaction_packet(s,2,1,10040);
    CHECK(journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN)==2,"second transaction proof lost");
    transaction_packet(s,3,0,11000);transaction_packet(s,4,0,11010);
    transaction_packet(s,4,1,11020);transaction_packet(s,3,1,11030);
    CHECK(journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN)==4,"out-of-order replies lost");
    transaction_packet(s,3,1,11040);transaction_packet(s,99,1,11050);
    CHECK(journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN)==4,"duplicate or unsolicited response proved request");
    /* Recognition continues beyond the initial handshake parsing window. */
    for(unsigned id=5;id<24;id++) {
        transaction_packet(s,id,0,12000+id*100);
        transaction_packet(s,id,1,12020+id*100);
    }
    CHECK(journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN)==23,"later observed transactions lost beyond hello window");
    CHECK(!d2k_session_sweep(s,20000000000ull),"answered transactions triggered suspicion");
    transaction_packet(s,24,0,21000);transaction_packet(s,24,0,22000);
    transaction_packet(s,25,0,22010);transaction_packet(s,25,1,22020);
    CHECK(d2k_session_sweep(s,25000000000ull)==1,"unrelated reply hid silent transaction");
    d2k_session_free(s);

    s=d2k_session_new(16,128);CHECK(s!=NULL,"STUN error session");if(!s)return;
    d2k_session_set_udp_reverse_hook(s,1);
    transaction_packet(s,1,0,1000);transaction_packet(s,1,0,2000);
    {
        uint8_t txid[12]={1},payload[28]={0},pkt[96],out[1024];d2k_result result;
        binding(payload,0x0111,txid);wr16(payload+2,8);
        wr16(payload+20,0x0009);wr16(payload+22,4);payload[26]=4;payload[27]=1;
        size_t n=udp_packet(pkt,1,41000,payload,sizeof payload);
        d2k_session_set_hook(s,D2K_HOOK_FORWARD);
        d2k_session_packet(s,pkt,n,2100000000ull,out,sizeof out,&result);
    }
    CHECK(!d2k_session_sweep(s,5000000000ull),"matching STUN error called silence");
    CHECK(!journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN),"STUN error called success");
    d2k_session_free(s);

    s=d2k_session_new(16,128);CHECK(s!=NULL,"cache overflow session");if(!s)return;
    for(unsigned id=1;id<=D2K_STUN_REQUEST_SLOTS+1;id++)transaction_packet(s,id,0,1000+id);
    transaction_packet(s,1,1,1100);
    CHECK(!journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN),"evicted request fabricated proof");
    transaction_packet(s,D2K_STUN_REQUEST_SLOTS+1,1,1110);
    CHECK(journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN)==1,"retained request lost on overflow");
    d2k_session_free(s);
}

/* Долгий STUN-поток: молчание → восстановление → новое молчание. Подозрение
   относится к эпизоду молчания, а не к потоку навсегда: после доказанного
   ответа новая поломка того же потока обязана быть замечена снова (ТЗ §3.7,
   §9.7). Внутри одного эпизода второй неотвеченный запрос подозрения не
   дублирует. (Очередь 28.10, задание 04.) */
static void silence_after_recovery(void) {
    d2k_session *s=d2k_session_new(16,128);
    CHECK(s!=NULL,"recovery session");if(!s)return;
    d2k_session_set_udp_reverse_hook(s,1);
    transaction_packet(s,1,0,1000);transaction_packet(s,1,0,2000);
    CHECK(d2k_session_sweep(s,5000000000ull)==1,"first silence episode not reported");
    transaction_packet(s,2,0,6000);transaction_packet(s,2,0,7000);
    CHECK(!d2k_session_sweep(s,9500000000ull),"second unanswered request duplicated suspicion inside one episode");
    transaction_packet(s,3,0,10000);transaction_packet(s,3,1,10100);
    CHECK(journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN)==1,"recovery proof lost");
    CHECK(!d2k_session_sweep(s,13000000000ull),"stale requests of the told episode re-suspected after recovery");
    transaction_packet(s,4,0,20000);transaction_packet(s,4,0,21000);
    CHECK(d2k_session_sweep(s,25000000000ull)==1,"new silence after recovery hidden by per-flow flags");
    CHECK(journal_kind(s,D2K_JRN_SUSPECT,D2K_SUSPECT_SILENT)==2,"two silence episodes must give two suspicions");
    transaction_packet(s,5,0,26000);transaction_packet(s,5,0,27000);
    CHECK(!d2k_session_sweep(s,30000000000ull),"second episode duplicated suspicion");
    d2k_session_free(s);
}

int main(void) {
    silence_after_recovery();
    repeated_transactions();
    repeated_trial_attribution();
    binding_response_semantics();
    controller_stun_trial();
    service_port_scope();
    const uint8_t txid[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
    uint8_t req[20], resp[32], alien[12], pkt[64], outbuf[512];
    d2k_result result;
    binding(req, 0x0001, txid);
    binding_response(resp, txid, 4);
    memcpy(alien, txid, sizeof alien);
    alien[0] ^= 0xff;
    d2k_session *s = d2k_session_new(8, 32);
    CHECK(s != NULL, "session allocation");
    if (!s) { return 1; }

    g_server_port = 50004;   /* медиапорт Дискорда: голосовой класс */
    size_t n = udp_packet(pkt, 0, 64041, req, sizeof req);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    d2k_session_packet(s, pkt, n, 1000, outbuf, sizeof outbuf, &result);
    CHECK(d2k_session_hellos(s) == 1, "valid Binding Request is recognized");
    CHECK(journal_kind(s, D2K_JRN_HELLO_SNI, 0) == 1,
          "STUN request enters the voice-class observation path");

    binding(req, 0x0101, alien);
    n = udp_packet(pkt, 1, 64041, req, sizeof req);
    d2k_session_set_hook(s, D2K_HOOK_FORWARD);
    d2k_session_packet(s, pkt, n, 1100, outbuf, sizeof outbuf, &result);
    CHECK(journal_kind(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_STUN) == 0,
          "foreign transaction ID is not STUN proof");

    {
        uint8_t bad[24];
        binding(bad, 0x0101, txid);
        wr16(bad + 2, 4);
        wr16(bad + 20, 0x8022); /* SOFTWARE */
        wr16(bad + 22, 8);     /* value is missing */
        n = udp_packet(pkt, 1, 64041, bad, sizeof bad);
        d2k_session_packet(s, pkt, n, 1150, outbuf, sizeof outbuf, &result);
        CHECK(journal_kind(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_STUN) == 0,
              "malformed attributes with matching transaction ID are not proof");
    }

    n = udp_packet(pkt, 1, 64041, resp, sizeof resp);
    d2k_session_packet(s, pkt, n, 1200, outbuf, sizeof outbuf, &result);
    CHECK(journal_kind(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_STUN) == 1,
          "matching transaction ID proves a STUN exchange");
    d2k_session_free(s);
    g_server_port = 3478;

    s = d2k_session_new(8, 16);
    CHECK(s != NULL, "malformed-case session allocation");
    if (s) {
        uint8_t malformed[20] = {0};
        malformed[4] = 0x21; malformed[5] = 0x12;
        malformed[6] = 0xa4; malformed[7] = 0x42;
        n = udp_packet(pkt, 0, 64042, malformed, sizeof malformed);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 2000, outbuf, sizeof outbuf, &result);
        CHECK(d2k_session_hellos(s) == 0, "malformed STUN is not a voice request");
        d2k_session_free(s);
    }

    stun_suspect_direction();
    live_trial();
    generic_stun();

    if (fails) { return 1; }
    puts("STUN datapath proof: all checks passed");
    return 0;
}
