/* Measured arm -> runtime strategy text -> canonical TLV -> real datapath actions.
 * Expected sends follow the raw measurement, including unsplit overlap.
 * D2K_TEST_LEGACY_BUILDER=1 reproduces the replaced builder's mismatches. */
#include "d2k_compose.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include "d2k_wire.h"
#include "d2k_session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static const char *case_name;
static int has_bytes(const uint8_t *haystack, size_t haystack_len,
                     const uint8_t *needle, size_t needle_len) {
    if (!needle_len || needle_len > haystack_len) { return 0; }
    for (size_t i = 0; i <= haystack_len - needle_len; i++)
        if (memcmp(haystack + i, needle, needle_len) == 0) { return 1; }
    return 0;
}
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "%s:%d: %s\n", case_name, __LINE__, #c); failures++; \
} } while (0)
#define BASE 10000u
typedef struct {
    uint32_t seq, delay;
    int32_t shift;
    unsigned kind, flags, ttl;
    size_t len;
    uint8_t bytes[8192];
} expected_send;
static expected_send expected[64];
static size_t count;

static void expect_send(unsigned kind, uint32_t seq, const uint8_t *pre, size_t pn,
                         const uint8_t *data, size_t dn, unsigned flags,
                         unsigned ttl, int32_t shift, uint32_t delay) {
    uint8_t whole[8192];
    CHECK(pn + dn <= sizeof whole);
    if (pn + dn > sizeof whole) { return; }
    if (pn) { memcpy(whole, pre, pn); }
    if (dn) { memcpy(whole + pn, data, dn); }
    for (size_t off = 0; off < pn + dn; ) {
        size_t n = pn + dn - off;
        if (n > D2K_ARM_SEGMENT_MAX) { n = D2K_ARM_SEGMENT_MAX; }
        CHECK(count < 64);
        if (count >= 64) { return; }
        expected_send *e = &expected[count++];
        e->seq = seq + (uint32_t)off; e->delay = off ? 0 : delay;
        e->kind = kind; e->flags = flags; e->ttl = ttl; e->shift = shift;
        e->len = n; memcpy(e->bytes, whole + off, n);
        off += n;
    }
}

/* built — вход, ПО КОТОРОМУ план собран: его длина задаёт байты, которые
   план несёт сам (тело приманки, приставка перекрытия). in — живой вход: от
   него считаются только якоря. У параметрического плана это РАЗНЫЕ входы, и
   путать их нельзя: приманка не пересобирается под каждое приветствие
   («captured strategy data»), а разрез идёт по имени ЭТОГО приветствия. */
static void reference_built(const d2k_arm *a, const d2k_arm_input *in,
                            const uint8_t *tr, const d2k_arm_input *built) {
    uint8_t fake[4096], overlap[2048];
    size_t n = in->trigger_len;
    size_t bn = built->trigger_len;
    unsigned reps = a->repeats ? a->repeats : 1;
    count = 0;
    unsigned flags = (a->badsum ? D2K_POISON_BADSUM : 0) | (a->md5 ? D2K_POISON_MD5 : 0) |
        (a->tcpts ? D2K_POISON_TCPTS_BACK : 0) | (a->ipidzero ? D2K_POISON_IPID_ZERO : 0);
    /* Как у сырого зонда (d2k_poison_has_fake): метка времени — тоже подделка. */
    int has_fake = !a->between && (a->badsum || a->md5 || a->ttl || a->seq_out || a->tcpts);
    if (has_fake) {
        memset(fake, 15, bn * 2);
        size_t cp = built->decoy_len < bn * 2 ? built->decoy_len : bn * 2;
        memcpy(fake, built->decoy, cp);
        for (unsigned i = 0; i < reps; i++) {
            expect_send(D2K_EMIT_FAKE, BASE, NULL, 0, fake, bn * 2, flags,
                        a->ttl, a->seq_out ? -66000 : 0, i ? a->gap_ms * 1000 : 0);
        }
    }
    if (a->between) {
        size_t mid = in->sni_off && in->sni_len > 1 ? in->sni_off : 1;
        expect_send(D2K_EMIT_PAYLOAD, BASE, NULL, 0, tr, mid, 0, 0, 0, 0);
        memset(fake, 15, n - mid);
        for (unsigned i = 0; i < reps; i++) {
            expect_send(D2K_EMIT_FAKE, BASE + (uint32_t)mid, NULL, 0, fake, n - mid,
                        a->badsum ? D2K_POISON_BADSUM : 0, a->ttl, 0, 0);
        }
        expect_send(D2K_EMIT_PAYLOAD, BASE + (uint32_t)mid, NULL, 0, tr + mid, n - mid,
                    0, 0, 0, 12000);
        return;
    }
    if (a->disorder_pos) {
        size_t cut = a->disorder_pos;
        expect_send(D2K_EMIT_PAYLOAD, BASE + (uint32_t)cut, NULL, 0,
                    tr + cut, n - cut, 0, 0, 0, 0);
        expect_send(D2K_EMIT_PAYLOAD, BASE, NULL, 0, tr, cut, 0, 0, 0, 0);
        return;
    }
    size_t ov = a->seqovl_hello ? built->decoy_len : a->seqovl;
    memset(overlap, 15, ov);
    memcpy(overlap, built->decoy, built->decoy_len < ov ? built->decoy_len : ov);
    if (a->disorder) {
        size_t mid = in->sni_off && in->sni_len > 1 ? in->sni_off + in->sni_len / 2 : n / 2;
        if (mid < 2) { mid = 2; } if (mid >= n) { mid = n - 1; }
        expect_send(D2K_EMIT_PAYLOAD, BASE + (uint32_t)mid, NULL, 0, tr + mid, n - mid,
                    0, 0, 0, has_fake ? 15000 : 0);
        expect_send(D2K_EMIT_PAYLOAD, BASE + 1, NULL, 0, tr + 1, mid - 1, 0, 0, 0, 12000);
        expect_send(D2K_EMIT_PAYLOAD, BASE - (uint32_t)ov, overlap, ov, tr, 1, 0, 0, 0, 12000);
    } else {
        expect_send(D2K_EMIT_PAYLOAD, BASE - (uint32_t)ov, overlap, ov, tr, n,
                    0, 0, 0, has_fake ? 15000 : 0);
    }
}

static void reference(const d2k_arm *a, const d2k_arm_input *in, const uint8_t *tr) {
    reference_built(a, in, tr, in);
}

static void run_case(const char *name, d2k_arm a, size_t n, size_t decoy_len) {
    uint8_t tr[2048], tlv[D2K_PLAN_TLV_MAX];
    char text[4096], err[200];
    d2k_arm_input in;
    d2k_plan *p = NULL;
    d2k_actions out;
    d2k_pkt pkt;
    size_t tlv_len = 0;
    case_name = name;
    memset(&in, 0, sizeof in); memset(&pkt, 0, sizeof pkt);
    in.trigger_len = n; in.sni_off = n / 3; in.sni_len = 11; in.decoy_len = decoy_len;
    for (size_t i = 0; i < n; i++) { tr[i] = (uint8_t)(i * 13 + 3); }
    for (size_t i = 0; i < decoy_len; i++) { in.decoy[i] = (uint8_t)(i * 23 + 5); }
    int rc = getenv("D2K_TEST_LEGACY_BUILDER")
        ? d2k_arm_plan(&a, D2K_SHAPE_MODERN, "decoy.example", 1500, text, sizeof text)
        : d2k_arm_plan_measured(&a, &in, text, sizeof text);
    CHECK(rc == 0); if (rc) { return; }
    int parametric = strstr(text, "input tls-sni") != NULL;
    /* ПЛЕЧО БЕЗ ПРИМАНКИ И БЕЗ ПЕРЕСТАНОВКИ НИ ОТ ЧЕГО ВО ВХОДЕ НЕ ЗАВИСИТ,
       кроме имени: ни одного числа, снятого с конкретного приветствия, в нём
       нет. Пришпиливать такой план к длине входа значит не применить его к
       ПЕРВОМУ СЕГМЕНТУ составного приветствия — а это ровно тот случай,
       который встретился в поле 18.09.2026 (1534 байта при MSS 1388, «план
       неприменим к этому пакету» на зонде подтверждения). */
    if (a.seqovl && !a.disorder && !a.between && !a.badsum && !a.md5 && !a.ttl && !a.seq_out) {
        CHECK(parametric);
    }
    if (a.seqovl_hello && a.disorder && !a.between &&
        !a.badsum && !a.md5 && !a.ttl && !a.seq_out) {
        CHECK(parametric);
        CHECK(strstr(text, "split sni_middle +0") != NULL);
    }
    if (parametric) {
        /* Packet metadata below models parsed SNI; provide its complete
           record/handshake envelope too. Full real profiles are tested below. */
        tr[0] = 0x16; tr[1] = 3; tr[2] = 1;
        tr[3] = (uint8_t)((n - 5) >> 8); tr[4] = (uint8_t)(n - 5);
        tr[5] = 1; tr[6] = 0;
        tr[7] = (uint8_t)((n - 9) >> 8); tr[8] = (uint8_t)(n - 9);
    }
    rc = d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tlv_len, err, sizeof err);
    if (rc) { fprintf(stderr, "%s\n", err); }
    CHECK(rc == 0); if (rc) { return; }
    /* Records must not pretend to be executable by the previous daemon. */
    if (!getenv("D2K_TEST_LEGACY_BUILDER")) {
        d2k_plan *old = NULL;
        uint8_t version = tlv[7]; tlv[7] = parametric ? 4 : 2;
        CHECK(d2k_plan_load(tlv, tlv_len, &old, err, sizeof err) != 0);
        d2k_plan_free(old); tlv[7] = version;
    }
    rc = d2k_plan_load(tlv, tlv_len, &p, err, sizeof err);
    if (rc) { fprintf(stderr, "%s\n", err); }
    CHECK(rc == 0); if (rc) { return; }
    pkt.seq = BASE; pkt.payload = tr; pkt.payload_len = n;
    pkt.have_sni = 1; pkt.sni_off = in.sni_off; pkt.sni_len = in.sni_len;
    rc = d2k_plan_apply(p, NULL, &pkt, &out);
    CHECK(rc == 0); if (rc) { d2k_plan_free(p); return; }
    reference(&a, &in, tr);
    CHECK(out.fate == D2K_ORIG_DROP);
    CHECK(out.n == count);
    CHECK(out.n <= D2K_RESULT_MAX);
    CHECK(d2k_plan_max_emit(p) <= (a.md5 ? 1460u : 1452u));
    for (size_t i = 0; i < out.n && i < count; i++) {
        const d2k_emit *e = &out.v[i]; const expected_send *x = &expected[i];
        CHECK(e->seq == x->seq && e->seq_shift == x->shift);
        CHECK(e->wire_profile == D2K_WIRE_DETECT_TCP);
        CHECK(e->delay_us == x->delay && e->kind == x->kind);
        CHECK(e->poison == x->flags && e->ttl == x->ttl);
        CHECK(e->pre_len + e->len == x->len);
        if (e->pre_len + e->len == x->len) {
            if (e->pre_len) { CHECK(memcmp(e->pre, x->bytes, e->pre_len) == 0); }
            if (e->len) { CHECK(memcmp(e->bytes, x->bytes + e->pre_len, e->len) == 0); }
        }
        /* Exercise the actual packet builder, not just action descriptors.
         * Random/source-flow header fields are not claimed donor-identical. */
        uint8_t wire[1600];
        d2k_conn conn = {0}; conn.ttl = 64; conn.window = 65535;
        size_t wn = d2k_wire_build(&conn, e, wire, sizeof wire);
        size_t hdr = 40 + ((x->flags & D2K_POISON_MD5) ? 20
                         : (x->flags & D2K_POISON_TCPTS_BACK) ? 12 : 0);
        CHECK(wn == hdr + x->len);
        if (wn == hdr + x->len) {
            CHECK(memcmp(wire + hdr, x->bytes, x->len) == 0);
            CHECK(wire[8] == (x->ttl ? x->ttl : 64));
            CHECK(d2k_wire_tcp_checksum_ok(wire, wn) == !(x->flags & D2K_POISON_BADSUM));
        }
    }
    d2k_actions_free(&out);
    /* НА БАЙТ КОРОЧЕ ОБЪЯВЛЕННОЙ ЗАПИСИ — ЭТО ПЕРВЫЙ СЕГМЕНТ, а не порча
       входа: приветствие длиннее сегмента обычное дело (1534 байта при MSS
       1388, поле 18.09.2026). Параметрический план считает свои смещения от
       имени и такой вход принимает; план с ИЗМЕРЕННЫМИ байтами — нет, они
       собраны под вход до байта. */
    pkt.payload_len--;
    CHECK((d2k_plan_apply(p, NULL, &pkt, &out) == 0) == parametric);
    d2k_actions_free(&out);
    pkt.payload_len++; pkt.sni_off++;
    CHECK((d2k_plan_apply(p, NULL, &pkt, &out) == 0) == parametric);
    d2k_actions_free(&out);
    if (parametric) {
        /* One plan, several different full inputs: no rebuilding the plan
           to accidentally make a literal offset look reusable. */
        static const char *names[] = {"a.co", "longer-target.example", "second.example"};
        for (size_t k = 0; k < sizeof names / sizeof names[0]; k++) {
            d2k_arm_input other = {0};
            CHECK(d2k_hello_from_profile(k == 0 ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN,
                  names[k], tr, sizeof tr, &other.trigger_len) == 0);
            CHECK(d2k_hello_sni(tr, other.trigger_len, &other.sni_off, &other.sni_len) == 0);
            /* The overlap is captured strategy data, not regenerated from
               the different verification ClientHello. */
            memcpy(other.decoy, in.decoy, in.decoy_len);
            other.decoy_len = in.decoy_len;
            pkt.payload_len = other.trigger_len;
            pkt.sni_off = other.sni_off; pkt.sni_len = other.sni_len;
            CHECK(d2k_plan_apply(p, NULL, &pkt, &out) == 0);
            reference_built(&a, &other, tr, &in);
            CHECK(out.n == count && out.fate == D2K_ORIG_DROP);
            for (size_t i = 0; i < out.n && i < count; i++) {
                const d2k_emit *e = &out.v[i]; const expected_send *x = &expected[i];
                CHECK(e->seq == x->seq && e->delay_us == x->delay);
                CHECK(e->wire_profile == D2K_WIRE_DETECT_TCP);
                /* Приставка перекрытия — часть посылки, а не отдельный
                   случай: ожидаемое хранит pre и данные одной строкой. */
                CHECK(e->pre_len + e->len == x->len);
                if (e->pre_len + e->len == x->len) {
                    if (e->pre_len) { CHECK(memcmp(e->pre, x->bytes, e->pre_len) == 0); }
                    if (e->len) { CHECK(memcmp(e->bytes, x->bytes + e->pre_len, e->len) == 0); }
                }
            }
            d2k_actions_free(&out);
            pkt.payload_len--;  /* первый сегмент того же приветствия */
            CHECK(d2k_plan_apply(p, NULL, &pkt, &out) == 0);
            d2k_actions_free(&out); pkt.payload_len++;
            pkt.have_sni = 0;
            CHECK(d2k_plan_apply(p, NULL, &pkt, &out) != 0);
            d2k_actions_free(&out); pkt.have_sni = 1;
        }
    }
    d2k_plan_free(p);
}

static void malformed(void) {
    static const char *bad[] = {
        "payload-pad 1 0 15", "payload-pad 1 2 256", "payload-pad 1 1 15 0102",
        "payload-pad 1 4 15 zz", "payload-pad 0 4 15", "payload-pad 1 65534 15",
        "payload-slice 2 1 0 1", "payload 1 01\npayload-slice 2 1 1 1",
        "payload 1 01\npayload-slice 2 1 0 0", "input 0 0 0", "input 10 9 2",
        "input 10 11 0", "input tls-sni extra", "input unknown",
        "input tls-sni", /* this fixture declares minexec=3 */
        "settle 0", "settle -1", "segment 0", "segment 65536"
        ,"payload-pad64 1 4 15 A", "payload-pad64 1 4 15 @@@@",
        "payload-pad64 1 4 15 AB==", "payload-pad64 1 4 15 AAA=AAAA",
        "payload-pad64 1 4 15 AA=A", "payload-pad64 1 1 15 AAAA"
    };
    char text[512], err[200]; uint8_t tlv[4096]; size_t len;
    case_name = "malformed measured text";
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        case_name = bad[i];
        snprintf(text, sizeof text, "d2k-plan 1 3\n%s\n", bad[i]);
        CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &len, err, sizeof err) != 0);
    }
    CHECK(d2k_plan_text_to_tlv("d2k-plan 1 2\nsegment 1400\n", tlv,
                              sizeof tlv, &len, err, sizeof err) != 0);
}

static void fallback_disorder_pos2(void) {
    char text[2048], err[200];
    uint8_t tlv[D2K_PLAN_TLV_MAX], payload[128], wire[256];
    size_t tlv_len = 0;
    d2k_plan *p = NULL;
    d2k_pkt pkt = {0};
    d2k_actions out = {0};
    case_name = "fallback disorder-pos2";

    CHECK(d2k_fallback_plan(5, D2K_SHAPE_MODERN, "disk.rzd.ru", 1492,
                            text, sizeof text) == 0);
    CHECK(strstr(text, "split payload_start +2\n") != NULL);
    CHECK(strstr(text, "order reverse\n") != NULL);
    CHECK(strstr(text, "split payload_start +1\n") == NULL);
    CHECK(strstr(text, "split sni_middle") == NULL);
    CHECK(strstr(text, "pace ") == NULL);
    if (!strstr(text, "split payload_start +2\n") ||
        !strstr(text, "order reverse\n") ||
        strstr(text, "split payload_start +1\n") ||
        strstr(text, "split sni_middle") || strstr(text, "pace ")) {
        return;
    }

    if (d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tlv_len,
                             err, sizeof err) != 0) { return; }
    CHECK(d2k_plan_load(tlv, tlv_len, &p, err, sizeof err) == 0);
    if (!p) { return; }
    for (size_t i = 0; i < sizeof payload; i++) { payload[i] = (uint8_t)i; }
    payload[0] = 0x16; payload[1] = 3; payload[2] = 3;
    payload[3] = 0; payload[4] = sizeof payload - 5;
    payload[5] = 1; payload[6] = 0; payload[7] = 0;
    payload[8] = sizeof payload - 9;
    pkt.seq = BASE; pkt.payload = payload; pkt.payload_len = sizeof payload;
    pkt.have_sni = 1; pkt.sni_off = 10; pkt.sni_len = 20;
    CHECK(d2k_plan_apply(p, NULL, &pkt, &out) == 0);
    CHECK(out.fate == D2K_ORIG_DROP && out.n == 2);
    if (out.n == 2) {
        CHECK(out.v[0].seq == BASE + 2 && out.v[0].len == 126 &&
              out.v[0].delay_us == 0 && out.v[0].kind == D2K_EMIT_PAYLOAD);
        CHECK(memcmp(out.v[0].bytes, payload + 2, 126) == 0);
        CHECK(out.v[1].seq == BASE && out.v[1].len == 2 &&
              out.v[1].delay_us == 0 && out.v[1].kind == D2K_EMIT_PAYLOAD);
        CHECK(memcmp(out.v[1].bytes, payload, 2) == 0);
        size_t n = d2k_wire_build(&(d2k_conn){.ttl=64,.window=65535},
                                  &out.v[0], wire, sizeof wire);
        CHECK(n == 40 + 126 && memcmp(wire + 40, payload + 2, 126) == 0);
        n = d2k_wire_build(&(d2k_conn){.ttl=64,.window=65535},
                           &out.v[1], wire, sizeof wire);
        CHECK(n == 40 + 2 && memcmp(wire + 40, payload, 2) == 0);
    }
    d2k_actions_free(&out);
    d2k_plan_free(p);
}

static void rx_volume_fake_sni_split(void) {
    char text[4096], err[200];
    uint8_t tlv[D2K_PLAN_TLV_MAX], payload[512], wire[2048];
    size_t tlv_len = 0;
    d2k_plan *p = NULL;
    d2k_pkt pkt = {0};
    d2k_actions out = {0};
    case_name = "RX-volume fake-SNI split ladder";

    /* Literal recovered capture: 8 x 675-byte fake, then split +2. */
    CHECK(d2k_rx_volume_plan(0, D2K_SHAPE_MODERN, 1492, text, sizeof text) == 0);
    CHECK(strstr(text, "input tls-sni\n") != NULL);
    CHECK(strstr(text, "fake payload=1 poison=1 repeats=8 gap_us=0 place=before tlsmod=rnd,dupsid\n") != NULL);
    CHECK(strstr(text, "wire tcp-template-v1\n") != NULL);
    CHECK(strstr(text, "poison 1 tcpts\n") != NULL);
    CHECK(strstr(text, "split payload_start +2\norder forward\n") != NULL);
    CHECK(strstr(text, "hcaptcha.com") == NULL); /* binary payload, not text */
    CHECK(strstr(text, "nodrop") == NULL);
    if (!strstr(text, "fake payload=1 poison=1 repeats=8 gap_us=0 place=before tlsmod=rnd,dupsid\n") ||
        !strstr(text, "split payload_start +2\norder forward\n")) { return; }
    static const unsigned expected_split[D2K_RX_VOLUME_PLAN_VARIANTS] = {2, 1, 3, 4, 5};
    for (unsigned i = 0; i < D2K_RX_VOLUME_PLAN_VARIANTS; i++) {
        char variant[4096], split[48];
        CHECK(d2k_rx_volume_plan(i, D2K_SHAPE_MODERN, 1492,
                                 variant, sizeof variant) == 0);
        snprintf(split, sizeof split, "split payload_start +%u\n", expected_split[i]);
        CHECK(strstr(variant, split) != NULL);
        CHECK(strstr(variant, "nodrop") == NULL);
    }
    CHECK(d2k_rx_volume_plan(0, D2K_SHAPE_LEGACY, 1492,
                             text, sizeof text) != 0);

    if (d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tlv_len,
                             err, sizeof err) != 0) { return; }
    CHECK(d2k_plan_load(tlv, tlv_len, &p, err, sizeof err) == 0);
    if (!p) { return; }

    /* Model a valid, complete TLS 1.3 ClientHello envelope. The session parser
       supplies SNI metadata, as it does for a live packet. */
    memset(payload, 0x5a, sizeof payload);
    payload[0] = 0x16; payload[1] = 3; payload[2] = 1;
    payload[3] = 1; payload[4] = 251;
    payload[5] = 1; payload[6] = 0; payload[7] = 1; payload[8] = 247;
    pkt.seq = BASE; pkt.payload = payload; pkt.payload_len = sizeof payload;
    pkt.have_sni = 1; pkt.sni_off = 100; pkt.sni_len = 18; pkt.is_tls13 = 1;
    payload[43] = 32;
    CHECK(d2k_plan_stream_input(p));
    for (size_t i = 0; i < 32; i++) { payload[44 + i] = (uint8_t)(0xc0 + i); }
    CHECK(d2k_plan_apply(p, NULL, &pkt, &out) == 0);
    CHECK(out.fate == D2K_ORIG_DROP && out.n == 10);
    if (out.n == 10) {
        d2k_conn conn = {.ttl=63,.window=2061,.tcp_options_len=12};
        const uint8_t options[] = {1,1,8,10,0,0,0x13,0x88,0,0,0x23,0x28};
        memcpy(conn.tcp_options, options, sizeof options);
        CHECK(out.v[0].kind == D2K_EMIT_FAKE && out.v[0].len == 675 &&
              (out.v[0].poison & D2K_POISON_TCPTS_BACK));
        static const uint8_t hcaptcha[] = "hcaptcha.com";
        CHECK(has_bytes(out.v[0].bytes, out.v[0].len,
                        hcaptcha, sizeof hcaptcha - 1));
        for (size_t i = 0; i < 8; i++) {
            CHECK(out.v[i].kind == D2K_EMIT_FAKE && out.v[i].len == 675 &&
                  out.v[i].seq == BASE && out.v[i].owned_bytes != NULL);
            CHECK(memcmp(out.v[i].bytes + 44, payload + 44, 32) == 0);
            CHECK(memcmp(out.v[i].bytes + 11, payload + 11, 32) != 0);
            CHECK(memcmp(out.v[i].bytes, out.v[0].bytes, 675) == 0);
            size_t wire_len = d2k_wire_build(&conn, &out.v[i], wire, sizeof wire);
            CHECK(wire_len == 727 && wire[32] == 0x80 &&
                  wire[42] == 8 && wire[43] == 10 && wire[46] == 0x0f && wire[47] == 0xa0);
        }
        CHECK(out.v[8].kind == D2K_EMIT_PAYLOAD && out.v[8].seq == BASE &&
              out.v[8].len == 2 && memcmp(out.v[8].bytes, payload, 2) == 0);
        CHECK(out.v[9].kind == D2K_EMIT_PAYLOAD && out.v[9].seq == BASE + 2 &&
              out.v[9].len == sizeof payload - 2 &&
              memcmp(out.v[9].bytes, payload + 2, sizeof payload - 2) == 0);
    }
    d2k_actions_free(&out);
    /* rnd/dupsid need random+SID from the first TCP segment, not the
       remaining record padding. The original segment must still be split. */
    pkt.payload_len = 128;
    CHECK(d2k_plan_apply(p, NULL, &pkt, &out) == 0);
    CHECK(out.fate == D2K_ORIG_DROP && out.n == 10);
    if (out.n == 10) {
        CHECK(out.v[8].len == 2 && out.v[9].len == 126);
        CHECK(memcmp(out.v[0].bytes + 44, payload + 44, 32) == 0);
    }
    d2k_actions_free(&out);
    pkt.payload_len = 43;
    CHECK(d2k_plan_apply(p, NULL, &pkt, &out) != 0);
    d2k_actions_free(&out);
    /* finland14001.discord.media, 04.10: the saved template plan must be
       executable on a legacy ClientHello too. Its applicability is then
       measured by the TLS 1.2 verifier, not rejected before any fake is sent.
       A different SID length leaves the fake template's SID intact. */
    uint8_t legacy[2048];
    size_t legacy_len = 0;
    case_name = "saved RX template on TLS 1.2";
    CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "finland14001.discord.media",
                                 legacy, sizeof legacy, &legacy_len) == 0);
    CHECK(d2k_hello_shape(legacy, legacy_len) == D2K_SHAPE_LEGACY);
    pkt.payload = legacy; pkt.payload_len = legacy_len; pkt.is_tls13 = 0;
    CHECK(d2k_hello_sni(legacy, legacy_len, &pkt.sni_off, &pkt.sni_len) == 0);
    CHECK(legacy[43] == 0);
    CHECK(d2k_plan_apply(p, NULL, &pkt, &out) == 0);
    CHECK(out.fate == D2K_ORIG_DROP && out.n == 10);
    if (out.n == 10) {
        for (size_t i = 0; i < 8; i++) {
            CHECK(out.v[i].kind == D2K_EMIT_FAKE && out.v[i].len == 675 &&
                  out.v[i].seq == BASE && out.v[i].bytes[43] == 32 &&
                  (out.v[i].poison & D2K_POISON_TCPTS_BACK));
            CHECK(memcmp(out.v[i].bytes, out.v[0].bytes, 675) == 0);
        }
        CHECK(out.v[8].len == 2 && out.v[8].seq == BASE &&
              memcmp(out.v[8].bytes, legacy, 2) == 0);
        CHECK(out.v[9].len == legacy_len - 2 && out.v[9].seq == BASE + 2 &&
              memcmp(out.v[9].bytes, legacy + 2, legacy_len - 2) == 0);
    }
    d2k_actions_free(&out);
    /* A TLS-shaped prefix with an invalid SID is still refused. */
    legacy[43] = 33;
    CHECK(d2k_plan_apply(p, NULL, &pkt, &out) != 0);
    d2k_actions_free(&out);
    d2k_plan_free(p);
}


/* Задача 37, I2: предел отправки. Сверка с НАСТОЯЩИМ шлюзом датапата
 * (d2k_plan_max_emit, ctlsrv.c): плечо строится при пределе тогда и только
 * тогда, когда его самая длинная посылка в предел помещается. Отказ — только
 * там, где датапат иначе ответил бы BAD_PLAN; урезания байт нет вовсе. */
static size_t measured_max_emit(const d2k_arm *a, const d2k_arm_input *in) {
    char text[8192], err[200];
    uint8_t tlv[D2K_PLAN_TLV_MAX];
    size_t tlv_len = 0, m = 0;
    d2k_plan *p = NULL;
    if (d2k_arm_plan_measured(a, in, text, sizeof text) != 0 ||
        d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tlv_len, err, sizeof err) != 0 ||
        d2k_plan_load(tlv, tlv_len, &p, err, sizeof err) != 0) { return 0; }
    m = d2k_plan_max_emit(p);
    d2k_plan_free(p);
    return m;
}

/* Самая длинная посылка ГОТОВОГО текста плана — тем же шлюзом датапата. */
static size_t text_max_emit(const char *text) {
    char err[200];
    uint8_t tlv[D2K_PLAN_TLV_MAX];
    size_t tlv_len = 0, m = 0;
    d2k_plan *p = NULL;
    if (d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tlv_len, err, sizeof err) != 0 ||
        d2k_plan_load(tlv, tlv_len, &p, err, sizeof err) != 0) { return 0; }
    m = d2k_plan_max_emit(p);
    d2k_plan_free(p);
    return m;
}

/* Поле 22.10.2026 (issue #5/#7): сегмент плана укладывается под предел канала.
 * При обычном канале (1500, 1492) — прежние 1400, тексты и идентификаторы
 * планов не меняются; при узком — короче, а не отказ: у человека с туннелем
 * (предел 1280) или LTE измеренных TCP-планов не было вовсе. */
static void segment_under_cap(void) {
    case_name = "segment-under-cap";
    CHECK(d2k_arm_segment(0) == 1400);
    CHECK(d2k_arm_segment(1500) == 1400);
    CHECK(d2k_arm_segment(1492) == 1400);
    CHECK(d2k_arm_segment(1472) == 1400);
    CHECK(d2k_arm_segment(1471) == 1399);
    CHECK(d2k_arm_segment(1280) == 1208);
    CHECK(d2k_arm_segment(72) == 0);
    CHECK(d2k_arm_segment(1) == 0);

    char text[8192];
    CHECK(d2k_rx_volume_plan_named(0, D2K_SHAPE_MODERN, 1492, "hcaptcha.com", text, sizeof text) == 0);
    CHECK(strstr(text, "\nsegment 1400\n") != NULL);
    CHECK(d2k_rx_volume_plan_named(0, D2K_SHAPE_MODERN, 1280, "hcaptcha.com", text, sizeof text) == 0);
    CHECK(strstr(text, "\nsegment 1208\n") != NULL);
    CHECK(text_max_emit(text) > 0 && text_max_emit(text) <= 1280);

    CHECK(d2k_tcp_split_plan(1558, 7, 0, 0, text, sizeof text) == 0);
    CHECK(strstr(text, "\nsegment 1400\n") != NULL);
    CHECK(d2k_tcp_split_plan(1558, 7, 0, 1280, text, sizeof text) == 0);
    CHECK(strstr(text, "\nsegment 1208\n") != NULL);
    CHECK(d2k_tcp_split_plan(1558, 7, 0, 72, text, sizeof text) != 0);

    /* Запасной сборщик: тело фальшивки он и прежде урезал по каналу (body_room),
       строки segment у такого плеча нет — посылка укладывается в предел; при
       пределе без сегмента плечо не задаётся. */
    d2k_arm fb;
    memset(&fb, 0, sizeof fb);
    fb.badsum = 1; fb.repeats = 2; fb.decoy_hello = 1;
    CHECK(d2k_arm_plan(&fb, D2K_SHAPE_MODERN, "example.com", 1280, text, sizeof text) == 0);
    CHECK(text_max_emit(text) > 0 && text_max_emit(text) <= 1280);
    CHECK(d2k_arm_plan(&fb, D2K_SHAPE_MODERN, "example.com", 72, text, sizeof text) != 0);
    /* Перестановка запасного списка несёт segment — и он под пределом. */
    memset(&fb, 0, sizeof fb);
    fb.disorder_pos = 7; fb.disorder = 1;
    CHECK(d2k_arm_plan(&fb, D2K_SHAPE_MODERN, "example.com", 1280, text, sizeof text) == 0);
    CHECK(strstr(text, "\nsegment 1208\n") != NULL);
    CHECK(d2k_arm_plan(&fb, D2K_SHAPE_MODERN, "example.com", 1500, text, sizeof text) == 0);
    CHECK(strstr(text, "\nsegment 1400\n") != NULL);
}

static void send_limit_cases(void) {
    static const size_t caps[] = { 1500, 1492, 1460, 1459, 1452, 1440, 1400, 1280, 600 };
    d2k_arm arms[8];
    memset(arms, 0, sizeof arms);
    arms[0].seqovl_hello = 1; arms[0].decoy_hello = 1;              /* seqovl-hello */
    arms[1].seqovl_hello = 1; arms[1].decoy_hello = 1; arms[1].disorder = 1;
    arms[2].badsum = 1; arms[2].repeats = 7;                        /* фальшивка 2n */
    arms[3].badsum = 1; arms[3].tcpts = 1; arms[3].repeats = 2;
    arms[4].disorder = 1;                                           /* без посылок плана */
    arms[5].seqovl = 336;
    arms[6].md5 = 1;
    arms[7].md5 = 1; arms[7].tcpts = 1; /* MD5 replaces, not adds TS */
    d2k_arm_input in;
    memset(&in, 0, sizeof in);
    in.trigger_len = 1558; in.sni_off = 500; in.sni_len = 11; in.decoy_len = 1534;
    for (size_t i = 0; i < in.decoy_len; i++) { in.decoy[i] = (uint8_t)(i * 7 + 1); }
    case_name = "send-limit";
    for (size_t ai = 0; ai < sizeof arms / sizeof arms[0]; ai++) {
        size_t need = measured_max_emit(&arms[ai], &in);
        char text[8192];
        /* Обычный канал: прежний сегмент 1400, посылка та же, что без предела. */
        CHECK(d2k_arm_plan_measured_cap(&arms[ai], &in, 1500, text, sizeof text) == 0);
        CHECK(strstr(text, "\nsegment 1400\n") != NULL);
        CHECK(text_max_emit(text) == need);
        for (size_t ci = 0; ci < sizeof caps / sizeof caps[0]; ci++) {
            /* Поле 22.10.2026: плечо задаётся при любом пределе, где есть сегмент,
               и его самая длинная посылка — по тому же шлюзу, что у датапата
               (d2k_plan_max_emit) — укладывается в предел. Прежде при пределе
               ниже самой длинной посылки плечо не задавалось вовсе. */
            int rc = d2k_arm_plan_measured_cap(&arms[ai], &in, caps[ci], text, sizeof text);
            CHECK(rc == 0);
            if (rc == 0) {
                /* Ноль — у плеча нет собственных посылок (чистая перестановка). */
                size_t m = text_max_emit(text);
                if (m > caps[ci]) {
                    fprintf(stderr, "send-limit: плечо %zu при пределе %zu — посылка %zu байт\n%s\n",
                            ai, caps[ci], m, text);
                }
                CHECK(m <= caps[ci]);
            }
        }
    }
}

static void md5_plan_contract(void) {
    char err[200], text[512];
    uint8_t tlv[D2K_PLAN_TLV_MAX]; size_t tn = 0;
    d2k_plan *p = NULL;
    case_name = "MD5 plan version and send size";
    const char *body = "proto tcp tls\nwire detect-tcp-v1\n"
        "payload-pad 1 1400 15\npoison 1 md5 tcpts\n"
        "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n"
        "segment 1400\norder forward\n";
    snprintf(text, sizeof text, "d2k-plan 1 12\n%s", body);
    int rc = d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tn, err, sizeof err);
    CHECK(rc == 0);
    if (rc == 0) {
        CHECK(d2k_plan_load(tlv, tn, &p, err, sizeof err) == 0);
        if (p) { CHECK(d2k_plan_max_emit(p) == 1460); }
        d2k_plan_free(p); p = NULL;
        tlv[7] = 11;
        CHECK(d2k_plan_load(tlv, tn, &p, err, sizeof err) != 0);
        d2k_plan_free(p);
    }
    snprintf(text, sizeof text, "d2k-plan 1 11\n%s", body);
    CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tn, err, sizeof err) != 0);
    CHECK(d2k_plan_text_to_tlv("d2k-plan 1 12\nproto udp quic\npoison 1 md5\n",
                              tlv, sizeof tlv, &tn, err, sizeof err) != 0);
    CHECK(d2k_plan_text_to_tlv("d2k-plan 1 12\nproto tcp tls\nwire tcp-template-v1\npoison 1 md5\n",
                              tlv, sizeof tlv, &tn, err, sizeof err) != 0);

    /* MD5+метка (md5ts) — отдельная гипотеза: minexec 15 и detect-tcp-v1.
       Заголовок на 8 байт шире MD5-одиночки (28 опций против 20). */
    const char *tsbody = "proto tcp tls\nwire detect-tcp-v1\n"
        "payload-pad 1 1400 15\npoison 1 md5ts\n"
        "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n"
        "segment 1400\norder forward\n";
    snprintf(text, sizeof text, "d2k-plan 1 15\n%s", tsbody);
    rc = d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tn, err, sizeof err);
    CHECK(rc == 0);
    if (rc == 0) {
        CHECK(d2k_plan_load(tlv, tn, &p, err, sizeof err) == 0);
        if (p) {
            CHECK(d2k_plan_max_emit(p) == 1468);   /* 1460 (md5) + 8 */
            /* Комбо требует метку потока даже на detect-tcp-v1 (не только
               tcp-template-v1): датапат откажет клиенту без метки. */
            CHECK(d2k_plan_flow_needs(p) & D2K_FLOW_NEED_TCPTS);
        }
        d2k_plan_free(p); p = NULL;
        /* Старый датапат (minexec 14) обязан отвергнуть TLV с md5ts. */
        tlv[7] = 14;
        CHECK(d2k_plan_load(tlv, tn, &p, err, sizeof err) != 0);
        d2k_plan_free(p); p = NULL;
    }
    /* Текстовая сторона: minexec 14, чужой профиль и UDP — все отказы. */
    snprintf(text, sizeof text, "d2k-plan 1 14\n%s", tsbody);
    CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tn, err, sizeof err) != 0);
    CHECK(d2k_plan_text_to_tlv("d2k-plan 1 15\nproto tcp tls\nwire tcp-template-v1\npoison 1 md5ts\n",
                              tlv, sizeof tlv, &tn, err, sizeof err) != 0);
    CHECK(d2k_plan_text_to_tlv("d2k-plan 1 15\nproto udp quic\npoison 1 md5ts\n",
                              tlv, sizeof tlv, &tn, err, sizeof err) != 0);
}

/* The raw sender replaces all TCP options with this exact malformed MD5
 * signature. Check IPv4/IPv6 and MD5+timestamp priority without a live flow. */
static void md5_wire(void) {
    const uint8_t options[20] = {19, 18, 0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0, 1, 1};
    uint8_t wire[128], data[] = {1, 2, 3};
    case_name = "raw MD5 wire header";
    for (int family = 4; family <= 6; family += 2) {
        for (unsigned ts = 0; ts < 2; ts++) {
            d2k_conn c = {0}; c.family = family;
            d2k_emit e = {0}; e.kind = D2K_EMIT_FAKE;
            e.wire_profile = D2K_WIRE_DETECT_TCP;
            e.poison = D2K_POISON_MD5 | (ts ? D2K_POISON_TCPTS_BACK : 0);
            e.bytes = data; e.len = sizeof data;
            size_t ip = family == 6 ? 40 : 20;
            size_t n = d2k_wire_build(&c, &e, wire, sizeof wire);
            CHECK(n == ip + 40 + sizeof data);
            if (n == ip + 40 + sizeof data) {
                CHECK(wire[ip + 12] == 0xa0);
                CHECK(memcmp(wire + ip + 20, options, sizeof options) == 0);
                CHECK(memcmp(wire + ip + 40, data, sizeof data) == 0);
                CHECK(d2k_wire_tcp_checksum_ok(wire, n));
            }
        }
    }
}

/* MD5-first + метка времени (D2K_POISON_MD5_TS): MD5 (kind 19, len 18) ПЕРВОЙ,
 * за ней РЕАЛЬНАЯ метка потока (kind 8, len 10), скопированная дословно из
 * опций соединения = 28 байт, добивки NOP не нужно. Проверяем точные
 * байты/порядок/длину/сумму на IPv4 и IPv6, нетривиальные TSval/TSecr, что
 * seq/нагрузка на месте, отказ при отсутствующей/кривой метке даже на
 * измеренном профиле, что MD5-одиночка осталась 20 байт и не читает опции
 * потока, и отказ вне detect-tcp-v1. Без живого потока. */
static void md5_ts_wire(void) {
    /* Согласованная метка в опциях соединения: NOP NOP + 08 0a + TSval + TSecr. */
    const uint8_t conn_opts[12] = {1, 1, 8, 10, 0x11, 0x22, 0x33, 0x44,
                                   0x55, 0x66, 0x77, 0x88};
    /* Ожидается: MD5(18) + та же опция метки (08 0a + те же восемь байт). */
    const uint8_t opt[28] = {19, 18, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0,
                             8, 10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t wire[128], data[] = {1, 2, 3};
    case_name = "raw MD5+timestamp wire header";
    for (int family = 4; family <= 6; family += 2) {
        d2k_conn c = {0}; c.family = family;
        memcpy(c.tcp_options, conn_opts, sizeof conn_opts);
        c.tcp_options_len = sizeof conn_opts;
        d2k_emit e = {0}; e.kind = D2K_EMIT_FAKE;
        e.wire_profile = D2K_WIRE_DETECT_TCP;
        e.poison = D2K_POISON_MD5_TS;
        e.seq = 4242; e.bytes = data; e.len = sizeof data;
        size_t ip = family == 6 ? 40 : 20;
        size_t n = d2k_wire_build(&c, &e, wire, sizeof wire);
        CHECK(n == ip + 20 + 28 + sizeof data);
        if (n == ip + 20 + 28 + sizeof data) {
            CHECK((wire[ip + 12] >> 4) == 12);        /* смещение данных 12 слов = 48 байт */
            CHECK(memcmp(wire + ip + 20, opt, sizeof opt) == 0);   /* метка дословно */
            CHECK(memcmp(wire + ip + 20 + 28, data, sizeof data) == 0);
            /* seq сохранён (4242 = 0x1092), сдвига нет. */
            CHECK(wire[ip + 4] == 0 && wire[ip + 5] == 0 &&
                  wire[ip + 6] == 0x10 && wire[ip + 7] == 0x92);
            CHECK(d2k_wire_tcp_checksum_ok(wire, n));
        }
    }
    /* Метка отсутствует или кривая — отказ ДАЖЕ на измеренном профиле. */
    {
        d2k_conn c = {0}; c.family = 4; c.tcp_options_len = 0;
        d2k_emit e = {0}; e.kind = D2K_EMIT_FAKE;
        e.wire_profile = D2K_WIRE_DETECT_TCP; e.poison = D2K_POISON_MD5_TS;
        e.bytes = data; e.len = sizeof data;
        CHECK(d2k_wire_build(&c, &e, wire, sizeof wire) == 0);
        const uint8_t no_ts[4] = {1, 1, 4, 2};   /* NOP NOP SACK-perm, метки нет */
        memcpy(c.tcp_options, no_ts, sizeof no_ts);
        c.tcp_options_len = sizeof no_ts;
        CHECK(d2k_wire_build(&c, &e, wire, sizeof wire) == 0);
    }
    /* MD5-одиночка не изменилась: 20 байт, добивка NOP (01 01), опции потока
       не читает (здесь их нет вовсе). */
    {
        d2k_conn c = {0}; c.family = 4;
        d2k_emit e = {0}; e.kind = D2K_EMIT_FAKE;
        e.wire_profile = D2K_WIRE_DETECT_TCP; e.poison = D2K_POISON_MD5;
        e.bytes = data; e.len = sizeof data;
        size_t n = d2k_wire_build(&c, &e, wire, sizeof wire);
        CHECK(n == 20 + 40 + sizeof data);   /* ip + (tcphdr 20 + opts 20) + data */
        CHECK(n && wire[20 + 20 + 18] == 1 && wire[20 + 20 + 19] == 1);
    }
    /* Вне detect-tcp-v1 комбо не собирается (у native опции клиента — своя
       ветка): отказ и на потоковом профиле, и на legacy, даже с меткой. */
    {
        d2k_conn c = {0}; c.family = 4;
        memcpy(c.tcp_options, conn_opts, sizeof conn_opts);
        c.tcp_options_len = sizeof conn_opts;
        d2k_emit e = {0}; e.kind = D2K_EMIT_FAKE; e.poison = D2K_POISON_MD5_TS;
        e.bytes = data; e.len = sizeof data;
        e.wire_profile = D2K_WIRE_TCP_TEMPLATE;
        CHECK(d2k_wire_build(&c, &e, wire, sizeof wire) == 0);
        e.wire_profile = 0;
        CHECK(d2k_wire_build(&c, &e, wire, sizeof wire) == 0);
    }
}

/* Плечо arm с md5_ts проходит весь конвейер: arm -> текст плана -> TLV. Текст
 * обязан нести minexec 15 и токен md5ts (а не md5-одиночку), и TLV обязан
 * принять его. Фальшивка «между» и совмещение с md5-одиночкой — отказ. */
static void md5_ts_arm(void) {
    d2k_arm a; d2k_arm_input in; char text[8192], err[200];
    uint8_t tlv[D2K_PLAN_TLV_MAX]; size_t tn = 0;
    case_name = "MD5+timestamp arm->plan->tlv";
    memset(&in, 0, sizeof in);
    in.trigger_len = 300; in.sni_off = 100; in.sni_len = 11; in.decoy_len = 300;
    for (size_t i = 0; i < in.decoy_len; i++) { in.decoy[i] = (uint8_t)(i * 3 + 1); }

    memset(&a, 0, sizeof a); a.md5_ts = 1; a.repeats = 1;
    CHECK(d2k_arm_plan_measured(&a, &in, text, sizeof text) == 0);
    CHECK(strstr(text, "d2k-plan 1 15") != NULL);
    CHECK(strstr(text, " md5ts") != NULL);
    CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tn, err, sizeof err) == 0);

    memset(&a, 0, sizeof a); a.md5_ts = 1; a.between = 1; a.repeats = 1;
    CHECK(d2k_arm_plan_measured(&a, &in, text, sizeof text) != 0);

    memset(&a, 0, sizeof a); a.md5 = 1; a.md5_ts = 1; a.repeats = 1;
    CHECK(d2k_arm_plan_measured(&a, &in, text, sizeof text) != 0);
}

/* БЕЛЫЙ СПИСОК ИМЁН ВСТРОЕН В БИНАРНИК (поле 10.10.2026). Как и приветствия
 * холодного старта, 266 имён-кандидатов не читаются файлом на роутере, а
 * генерируются из profiles/tcp1620_whitelist.txt в .inc core/Makefile'ом.
 * Доступ — через accessor, а не через путь к файлу. */
static void whitelist_names(void) {
    case_name = "network whitelist seed";
    size_t n = d2k_net_whitelist_count();
    CHECK(n == 266);
    const char *first = d2k_net_whitelist_name(0);
    const char *last = n ? d2k_net_whitelist_name(n - 1) : NULL;
    CHECK(first && !strcmp(first, "9gag.com"));
    CHECK(last && !strcmp(last, "zoho.com"));
    CHECK(d2k_net_whitelist_name(n) == NULL); /* за концом — NULL, не мусор */
    int shape_ok = 1;
    for (size_t i = 0; i < n; i++) {
        const char *s = d2k_net_whitelist_name(i);
        if (!(s && s[0] && !strchr(s, ' ') && !strchr(s, '"') && strchr(s, '.'))) {
            shape_ok = 0;
        }
    }
    CHECK(shape_ok);
}

/* ИМЯ ПРИМАНКИ RX-ЛЕСТНИЦЫ ЗАДАЁТСЯ (поле 10.10.2026): белое имя сети вместо
 * зашитого hcaptcha.com. Имя — в бинарном payload, не в тексте плана, поэтому
 * сверяем, что РАЗНЫЕ имена дают разный план, а обёртка по умолчанию равна
 * плану с hcaptcha.com. Пустое имя — отказ. */
/* ЗАМЫСЕЛ 2026-10-23, п. 5.2: ПОРЧА СОСТАВНОГО ПЛАНА — ИЗ ПЛЕЧА, НЕ ИЗ СТРОКИ.
 *
 * template_plan писал «poison 1 tcpts» литералом: план семейства C нёс метку
 * времени потому, что так написано в файле, а не потому, что это измерено на
 * этом клиенте. Клиенту без метки времени (ПК репортёра #7, поле 22.10.2026)
 * такой план датапат исполнить не может. Теперь порча берётся из d2k_arm:
 * множители (приманка ECH, серия ×8, разрез +2) те же, порча — та, что
 * измерена. Запасная лестница остаётся прежней программой с меткой. */
static void template_poison_from_arm(void) {
    char text[4096];
    uint8_t decoy[1024];
    size_t dlen = 0;
    d2k_arm a;
    d2k_arm_input in;
    case_name = "composite template poison from the measured arm";
    CHECK(d2k_white_decoy_hello("hcaptcha.com", decoy, sizeof decoy, &dlen) == 0);
    memset(&in, 0, sizeof in);
    in.trigger_len = 600; in.sni_off = 100; in.sni_len = 11;
    in.decoy_len = dlen;
    memcpy(in.decoy, decoy, dlen);

    /* Клиент с меткой времени: прежняя программа, байт в байт. */
    memset(&a, 0, sizeof a);
    a.tcpts = 1; a.decoy_hello = 1; a.repeats = 8; a.split_pos = 2;
    CHECK(d2k_arm_plan_measured_cap(&a, &in, 1492, text, sizeof text) == 0);
    CHECK(strstr(text, "wire tcp-template-v1\n") != NULL);
    CHECK(strstr(text, "poison 1 tcpts\n") != NULL);
    CHECK(strstr(text, "badsum") == NULL);
    CHECK(strstr(text, "fake payload=1 poison=1 repeats=8 gap_us=0 place=before tlsmod=rnd,dupsid\n") != NULL);
    CHECK(strstr(text, "split payload_start +2\norder forward\n") != NULL);

    /* Клиент без метки времени: ТОТ ЖЕ составной план, порча — битая сумма. */
    memset(&a, 0, sizeof a);
    a.badsum = 1; a.decoy_hello = 1; a.repeats = 8; a.split_pos = 2;
    CHECK(d2k_arm_plan_measured_cap(&a, &in, 1492, text, sizeof text) == 0);
    CHECK(strstr(text, "wire tcp-template-v1\n") != NULL);
    CHECK(strstr(text, "poison 1 badsum\n") != NULL);
    CHECK(strstr(text, "tcpts") == NULL);
    CHECK(strstr(text, "fake payload=1 poison=1 repeats=8 gap_us=0 place=before tlsmod=rnd,dupsid\n") != NULL);
    CHECK(strstr(text, "split payload_start +2\norder forward\n") != NULL);

    /* Запасная лестница — восстановленная программа поля, с меткой времени. */
    CHECK(d2k_rx_volume_plan(0, D2K_SHAPE_MODERN, 1492, text, sizeof text) == 0);
    CHECK(strstr(text, "poison 1 tcpts\n") != NULL);
    CHECK(strstr(text, "badsum") == NULL);
}

/* ЗАПАСНАЯ ЛЕСТНИЦА ПОД КЛИЕНТА (поле issue #7, 23.10.2026). Программа поля
 * держится на метке времени, а метку даёт КЛИЕНТ: у ПК на Windows её нет, и
 * датапат такой план исполнить не может — 13 отказов из 13 при работающих
 * телефонах. Для такого клиента та же программа идёт с TTL по измеренному
 * пути. Клиент с меткой получает прежний план БАЙТ В БАЙТ. */
static void rx_ladder_follows_client(void) {
    char with_ts[4096], no_ts[4096], legacy[4096];
    case_name = "RX ladder follows the client's TCP options";
    CHECK(d2k_rx_volume_plan_client(0, D2K_SHAPE_MODERN, 1492, "hcaptcha.com", 1,
                                    with_ts, sizeof with_ts) == 0);
    CHECK(d2k_rx_volume_plan_named(0, D2K_SHAPE_MODERN, 1492, "hcaptcha.com",
                                   legacy, sizeof legacy) == 0);
    /* Прежняя подпись и клиент с меткой — одно и то же, байт в байт. */
    CHECK(!strcmp(with_ts, legacy));
    CHECK(strstr(with_ts, "poison 1 tcpts\n") != NULL);
    CHECK(strstr(with_ts, "autottl") == NULL);
    CHECK(strstr(with_ts, "d2k-plan 1 8\n") != NULL);

    CHECK(d2k_rx_volume_plan_client(0, D2K_SHAPE_MODERN, 1492, "hcaptcha.com", 0,
                                    no_ts, sizeof no_ts) == 0);
    /* Клиент без метки: метки в плане нет, есть TTL по пути, minexec поднят. */
    CHECK(strstr(no_ts, "tcpts") == NULL);
    CHECK(strstr(no_ts, "poison 1 autottl=1,2-12\n") != NULL);
    CHECK(strstr(no_ts, "d2k-plan 1 13\n") != NULL);
    /* Множители программы те же: приманка, серия ×8, разрез. */
    CHECK(strstr(no_ts, "fake payload=1 poison=1 repeats=8 gap_us=0 place=before tlsmod=rnd,dupsid\n") != NULL);
    CHECK(strstr(no_ts, "split payload_start +2\norder forward\n") != NULL);
    CHECK(strstr(no_ts, "wire tcp-template-v1\n") != NULL);
    /* И такой план ДОЕЗЖАЕТ до исполнителя: это и есть закрытие issue #7. */
    uint8_t tlv[D2K_PLAN_TLV_MAX];
    size_t tn = 0;
    char err[200];
    d2k_plan *pl = NULL;
    CHECK(d2k_plan_text_to_tlv(no_ts, tlv, sizeof tlv, &tn, err, sizeof err) == 0);
    CHECK(d2k_plan_load(tlv, tn, &pl, err, sizeof err) == 0 && pl);
    /* Главное: плану НЕ нужна метка времени от потока, значит датапат его не
       отвергнет кодом FLOW_UNFIT, как отвергал прежний. */
    CHECK(pl && (d2k_plan_flow_needs(pl) & D2K_FLOW_NEED_TCPTS) == 0);
    d2k_plan_free(pl);
}

static void rx_volume_named(void) {
    case_name = "rx-volume named decoy";
    char def[4096], hc[4096], other[4096], empty[4096];
    CHECK(d2k_rx_volume_plan(0, D2K_SHAPE_MODERN, 1492, def, sizeof def) == 0);
    CHECK(d2k_rx_volume_plan_named(0, D2K_SHAPE_MODERN, 1492, "hcaptcha.com", hc, sizeof hc) == 0);
    CHECK(!strcmp(def, hc)); /* обёртка по умолчанию = hcaptcha.com */
    CHECK(d2k_rx_volume_plan_named(0, D2K_SHAPE_MODERN, 1492, "9gag.com", other, sizeof other) == 0);
    CHECK(strcmp(def, other) != 0); /* другое имя — другой план */
    CHECK(d2k_rx_volume_plan_named(0, D2K_SHAPE_MODERN, 1492, "", empty, sizeof empty) != 0);
    CHECK(d2k_rx_volume_plan_named(0, D2K_SHAPE_MODERN, 1492, NULL, empty, sizeof empty) != 0);
    /* Разрез и форма плана не зависят от имени. */
    CHECK(strstr(other, "split payload_start +2\norder forward\n") != NULL);
    CHECK(strstr(other, "poison 1 tcpts\n") != NULL);
}

int main(void) {
    template_poison_from_arm();
    rx_ladder_follows_client();
    whitelist_names();
    rx_volume_named();
    md5_plan_contract();
    md5_wire();
    md5_ts_wire();
    md5_ts_arm();
    malformed();
    fallback_disorder_pos2();
    rx_volume_fake_sni_split();
    send_limit_cases();
    segment_under_cap();
    d2k_arm a = {0};
    a.seqovl = 1; run_case("seqovl-1", a, 289, 0);
    a.seqovl = 0; a.badsum = 1; a.repeats = 2; a.gap_ms = 20;
    run_case("badsum-x2-g20", a, 289, 0);
    a.seqovl_hello = 1; a.decoy_hello = 1;
    run_case("captured-decoy-overlap", a, 289, 173);
    a.disorder = 1; run_case("fake-overlap-disorder", a, 1538, 1465);
    a.between = 1; a.repeats = 7; run_case("fake-between-priority", a, 1538, 1465);
    memset(&a, 0, sizeof a); a.disorder = 1; run_case("disorder", a, 1538, 0);
    memset(&a, 0, sizeof a); a.disorder = 1; a.disorder_pos = 2;
    run_case("disorder-pos2", a, 1538, 0);
    memset(&a, 0, sizeof a); a.seqovl_hello = 1; a.disorder = 1;
    run_case("captured-overlap-disorder-dynamic-sni", a, 289, 173);
    a.seqovl = 336; run_case("partial-captured-overlap", a, 1538, 500);
    memset(&a, 0, sizeof a); a.badsum = 1; a.repeats = 7;
    run_case("long-filler-not-64", a, 2048, 0);
    a.seqovl_hello = 1; a.decoy_hello = 1; a.disorder = 1;
    run_case("full-2048-decoy-in-4096-text-slot", a, 2048, 2048);
    a.seqovl_hello = 0; a.disorder = 0;
    a.tcpts = 1; a.ipidzero = 1; a.ttl = 8; a.seq_out = 1;
    run_case("fooling", a, 289, 0);
    /* §0.1 (поле 07.10.2026, s3.amazonaws.com): метка времени и окно seq —
       отдельные вопросы о свойствах; каждый прошедший — подделка с одним
       этим полем, без битой суммы, и обязан задаваться планом. */
    memset(&a, 0, sizeof a); a.repeats = 1; a.tcpts = 1; run_case("ts-alone", a, 289, 0);
    memset(&a, 0, sizeof a); a.repeats = 1; a.seq_out = 1; run_case("seq-out-alone", a, 289, 0);
    memset(&a, 0, sizeof a); a.md5 = 1;
    run_case("md5-alone", a, 289, 0);
    a.tcpts = 1; a.badsum = 1; a.repeats = 2;
    run_case("md5-ts-badsum-segmented", a, 2048, 681);
    if (failures) { fprintf(stderr, "measured: %d failures\n", failures); return 1; }
    puts("measured: exact bytes/lengths/seq/order/delays/fooling and input rejection passed");
    return 0;
}
