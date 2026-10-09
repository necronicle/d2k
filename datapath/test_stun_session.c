/* STUN-only regression: intentionally contains no QUIC vectors or assertions. */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "d2k_journal.h"
#include "d2k_session.h"
#include "test_nat_stub.h"

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
    uint8_t req[20], resp[20], junk[40], pkt[96], outbuf[1024];
    d2k_result result;
    binding(req, 0x0001, txid);
    binding(resp, 0x0101, txid);
    memset(junk, 0x80, sizeof junk);
    d2k_session *s = d2k_session_new(8, 32);
    CHECK(s != NULL, "live-trial session allocation");
    if (!s) { return; }
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
    n = udp_packet(pkt, 0, 64050, req, sizeof req);
    d2k_session_packet(s, pkt, n, 15*ms, outbuf, sizeof outbuf, &result);
    CHECK(!result.applied, "measured first-packet prefix must not be applied late to an already exposed flow");
    n = udp_packet(pkt, 0, 64051, req, sizeof req);
    pkt[15] = 0x44;   /* another LAN client */
    d2k_session_packet(s, pkt, n, 20 * ms, outbuf, sizeof outbuf, &result);
    CHECK(!result.applied, "another LAN client does not get the voice trial");
    n = udp_packet(pkt, 0, 64052, req, sizeof req);
    d2k_session_packet(s, pkt, n, 30 * ms, outbuf, sizeof outbuf, &result);
    CHECK(result.applied && memcmp(result.trial_id, trial, sizeof trial) == 0,
          "next STUN flow of the same client gets the trial with its trial ID");
    n = udp_packet(pkt, 1, 64052, resp, sizeof resp);
    d2k_session_set_hook(s, D2K_HOOK_FORWARD);
    d2k_session_packet(s, pkt, n, 40 * ms, outbuf, sizeof outbuf, &result);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    CHECK(journal_kind(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_STUN) == 1,
          "STUN response for our txid on the trial flow is protocol proof");
    n = udp_packet(pkt, 0, 64053, req, sizeof req);
    d2k_session_packet(s, pkt, n, expires + 1, outbuf, sizeof outbuf, &result);
    CHECK(!result.applied, "expired voice trial matches nothing");
    d2k_session_free(s);
}

static void discord_first_packet_trial(void) {
    uint8_t req[74]={0,1,0,70,0x22},pkt[128],out[1024];d2k_result r;
    const uint64_t ms=1000000ull;
    d2k_session *s=d2k_session_new(8,32);CHECK(s!=NULL,"Discord first-packet fixture");if(!s)return;
    g_server_port=50004;d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    for(unsigned i=0;i<3;i++) {
        size_t n=udp_packet(pkt,0,64097,req,sizeof req);
        d2k_session_packet(s,pkt,n,(1+i)*ms,out,sizeof out,&r);
    }
    d2k_addr_probe_flow f={0};f.family=4;f.transport=17;
    memcpy(f.src_ip4,"\xc0\xa8\x01\x43",4);memcpy(f.dst_ip4,"\x01\x02\x03\x04",4);
    f.dst_port_be=htons(50004);uint8_t trial[D2K_TRIAL_ID_LEN]={0x55};
    d2k_plan *p=NULL;char err[160];
    CHECK(!d2k_plan_load(plan_voice,sizeof plan_voice,&p,err,sizeof err) &&
          !d2k_plantab_set_addr_probe(d2k_session_plans(s),&f,trial,10*ms,120000*ms,p),
          "Discord first-packet trial install");
    size_t n=udp_packet(pkt,0,64097,req,sizeof req);
    d2k_session_packet(s,pkt,n,15*ms,out,sizeof out,&r);
    CHECK(!r.applied,"STUN-before-first-Discovery cannot prime an already exposed Discord tuple");
    n=udp_packet(pkt,0,64098,req,sizeof req);
    d2k_session_packet(s,pkt,n,20*ms,out,sizeof out,&r);
    CHECK(r.applied && !memcmp(r.trial_id,trial,sizeof trial),
          "late attempt must leave its trial available for a fresh Discord tuple");
    d2k_session_free(s);g_server_port=3478;
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

/* Later packets never enter NFQUEUE; only tuple counters advance. */
static uint64_t ct_out, ct_in;
static int ct_available = 1;
static int voice_ct(void *ctx, const d2k_ct_tuple *t, d2k_ct_info *info) {
    (void)ctx;
    CHECK(t->family == 4 && t->proto == 17 &&
          !memcmp(t->src, "\xc0\xa8\x01\x43", 4) &&
          !memcmp(t->dst, "\x01\x02\x03\x04", 4),
          "voice counter query preserves client/server direction");
    if (!ct_available) return -1;
    memset(info, 0, sizeof *info);
    info->orig_pkts = ct_out; info->reply_pkts = ct_in;
    return 0;
}
static void voice_late_cut(void) {
    const uint64_t sec = 1000000000ull;
    uint8_t req[20], resp[20], pkt[96], out[512], id[12] = {1};
    d2k_result result;
    binding(req, 1, id); binding(resp, 0x101, id);
    g_server_port = 50004;
    for (int scenario = 0; scenario < 7; scenario++) {
        d2k_session *s = d2k_session_new(8, 32);
        CHECK(s != NULL, "voice counter fixture"); if (!s) return;
        d2k_session_set_ct_query(s, voice_ct, NULL);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        size_t n = udp_packet(pkt, 0, 64080, req, sizeof req);
        if (scenario == 5) d2k_session_packet_probe(s, pkt, n, sec, out, sizeof out, &result);
        else d2k_session_packet(s, pkt, n, sec, out, sizeof out, &result);
        n = udp_packet(pkt, 1, 64080, resp, sizeof resp);
        d2k_session_set_hook(s, D2K_HOOK_FORWARD);
        d2k_session_packet(s, pkt, n, 2*sec, out, sizeof out, &result);
        ct_available = 1; ct_out = 12; ct_in = 12;
        d2k_session_sweep(s, 3*sec);
        ct_out = 14;
        d2k_session_sweep(s, 5*sec);
        CHECK(d2k_session_suspects(s) == 0, "short UDP loss must not trigger search");
        if (scenario == 1 || scenario == 6) ct_in = 18; /* healthy */
        if (scenario == 2) ct_available = 0; /* unknown */
        if (scenario == 3) { ct_out = 1; ct_in = 1; } /* restart */
        if (scenario == 4) ct_out = 14; /* idle caller */
        else if (scenario < 3) ct_out = 20;
        d2k_session_sweep(s, 10*sec);
        CHECK(d2k_session_suspects(s) == (scenario == 0 ? 1u : 0u),
              "voice late cut requires sustained outbound growth without replies");
        if(scenario==0)CHECK(journal_kind(s,D2K_JRN_SUSPECT,D2K_SUSPECT_VOICE_STALL)==1,
                             "late voice cut must differ from initial silence");
        d2k_session_sweep(s, 11*sec);
        CHECK(d2k_session_suspects(s) <= 1, "one suspicion per voice flow");
        if (scenario == 6) {
            ct_in = 30; ct_out = 30;
            d2k_session_sweep(s, 100*sec);
            CHECK(d2k_session_expire(s, 150*sec, 120*sec) == 0,
                  "active voice flow must survive the NFQUEUE observation window");
        }
        d2k_session_free(s);
    }
    ct_available = 1; g_server_port = 3478;
}

static void voice_media_window(void) {
    const uint64_t sec=1000000000ull;
    uint8_t id[12]={3},req[20],resp[20],media[24]={0x80,120},pkt[96],out[512];
    d2k_result r;binding(req,1,id);binding(resp,0x101,id);g_server_port=50004;
    for(int with_media=0;with_media<2;with_media++) {
        d2k_session *s=d2k_session_new(8,32);CHECK(s!=NULL,"media fixture");if(!s)return;
        d2k_session_set_ct_query(s,voice_ct,NULL);
        d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        size_t n=udp_packet(pkt,0,64085,req,20);d2k_session_packet(s,pkt,n,sec,out,sizeof out,&r);
        d2k_session_set_hook(s,D2K_HOOK_FORWARD);
        n=udp_packet(pkt,1,64085,resp,20);d2k_session_packet(s,pkt,n,2*sec,out,sizeof out,&r);
        if(with_media) {
            d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
            n=udp_packet(pkt,0,64085,media,sizeof media);d2k_session_packet(s,pkt,n,3*sec,out,sizeof out,&r);
            d2k_session_set_hook(s,D2K_HOOK_FORWARD);
            n=udp_packet(pkt,1,64085,media,sizeof media);d2k_session_packet(s,pkt,n,4*sec,out,sizeof out,&r);
        }
        ct_available=1;
        for(unsigned i=0;i<9;i++) {ct_out=20+10*i;ct_in=20+10*i;d2k_session_sweep(s,(5+5*i)*sec);}
        CHECK(journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_OBS_MEDIA_FLOW)==(with_media?1u:0u),
              "Discovery/STUN counters alone must not become media evidence");
        CHECK(journal_kind(s,D2K_JRN_EXCHANGE,D2K_UDP_OBS_STABLE)==(with_media?1u:0u),
              "stable observation requires media-shaped packets plus sustained tuple counters");
        d2k_session_free(s);
    }
    g_server_port=3478;
}

static void voice_limited_queue_window(void) {
    const uint64_t sec=1000000000ull;
    uint8_t id[12]={5},req[20],resp[20],media[24]={0x80,120},pkt[96],out[512];
    d2k_result r;binding(req,1,id);binding(resp,0x101,id);g_server_port=50004;
    for(int replies=0;replies<2;replies++) {
        d2k_session *s=d2k_session_new(8,32);CHECK(s!=NULL,"limited voice queue fixture");if(!s)return;
        d2k_session_set_ct_query(s,voice_ct,NULL);d2k_session_set_udp_reverse_hook(s,1);
        d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        size_t n=udp_packet(pkt,0,64090,req,20);d2k_session_packet(s,pkt,n,sec,out,sizeof out,&r);
        if(replies) {
            d2k_session_set_hook(s,D2K_HOOK_FORWARD);
            n=udp_packet(pkt,1,64090,resp,20);d2k_session_packet(s,pkt,n,2*sec,out,sizeof out,&r);
        }
        d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        for(unsigned i=0;i<4;i++) {
            n=udp_packet(pkt,0,64090,replies?media:req,replies?sizeof media:20);
            d2k_session_packet(s,pkt,n,(3+i)*sec,out,sizeof out,&r);
        }
        ct_available=1;ct_out=20;ct_in=replies?200:0;
        d2k_session_sweep(s,10*sec);
        CHECK(d2k_session_suspects(s)==(replies?0u:1u),
              "NFQUEUE window loss must not masquerade as voice silence; initial requests still need detection");
        if(!replies)CHECK(d2k_session_hellos(s)==1 && journal_kind(s,D2K_JRN_HELLO_SNI,0)==2,
                         "voice suspicion must replay its observed class for a restarted controller");

        d2k_session_free(s);
    }
    g_server_port=3478;
}

int main(void) {
    D2K_TEST_NAT_NO_TABLE();
    const uint8_t txid[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
    uint8_t req[20], resp[20], alien[12], pkt[64], outbuf[512];
    d2k_result result;
    binding(req, 0x0001, txid);
    binding(resp, 0x0101, txid);
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

    voice_late_cut();
    voice_media_window();
    voice_limited_queue_window();
    live_trial();
    discord_first_packet_trial();
    generic_stun();

    if (fails) { return 1; }
    puts("STUN datapath proof: all checks passed");
    return 0;
}
