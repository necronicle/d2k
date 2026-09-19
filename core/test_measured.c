/* Measured arm -> text -> canonical TLV -> real datapath actions.
 * Expected sends follow detect/raw.c's branches, not the text builder.
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

static void reference(const d2k_arm *a, const d2k_arm_input *in, const uint8_t *tr) {
    uint8_t fake[4096], overlap[2048];
    size_t n = in->trigger_len;
    unsigned reps = a->repeats ? a->repeats : 1;
    count = 0;
    unsigned flags = (a->badsum ? D2K_POISON_BADSUM : 0) |
        (a->tcpts ? D2K_POISON_TCPTS_BACK : 0) | (a->ipidzero ? D2K_POISON_IPID_ZERO : 0);
    int has_fake = !a->between && (a->badsum || a->ttl || a->seq_out);
    if (has_fake) {
        memset(fake, 15, n * 2);
        size_t cp = in->decoy_len < n * 2 ? in->decoy_len : n * 2;
        memcpy(fake, in->decoy, cp);
        for (unsigned i = 0; i < reps; i++) {
            expect_send(D2K_EMIT_FAKE, BASE, NULL, 0, fake, n * 2, flags,
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
    size_t ov = a->seqovl_hello ? in->decoy_len : a->seqovl;
    memset(overlap, 15, ov);
    memcpy(overlap, in->decoy, in->decoy_len < ov ? in->decoy_len : ov);
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
    if (a.seqovl && !a.disorder && !a.between && !a.badsum && !a.ttl && !a.seq_out) {
        CHECK(parametric);
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
    CHECK(d2k_plan_max_emit(p) <= 1452);
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
        size_t hdr = 40 + ((x->flags & D2K_POISON_TCPTS_BACK) ? 12 : 0);
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
            pkt.payload_len = other.trigger_len;
            pkt.sni_off = other.sni_off; pkt.sni_len = other.sni_len;
            CHECK(d2k_plan_apply(p, NULL, &pkt, &out) == 0);
            reference(&a, &other, tr);
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

int main(void) {
    malformed();
    d2k_arm a = {0};
    a.seqovl = 1; run_case("seqovl-1", a, 289, 0);
    a.seqovl = 0; a.badsum = 1; a.repeats = 2; a.gap_ms = 20;
    run_case("badsum-x2-g20", a, 289, 0);
    a.seqovl_hello = 1; a.decoy_hello = 1;
    run_case("captured-decoy-overlap", a, 289, 173);
    a.disorder = 1; run_case("fake-overlap-disorder", a, 1538, 1465);
    a.between = 1; a.repeats = 7; run_case("fake-between-priority", a, 1538, 1465);
    memset(&a, 0, sizeof a); a.disorder = 1; run_case("disorder", a, 1538, 0);
    a.seqovl = 336; run_case("partial-captured-overlap", a, 1538, 500);
    memset(&a, 0, sizeof a); a.badsum = 1; a.repeats = 7;
    run_case("long-filler-not-64", a, 2048, 0);
    a.seqovl_hello = 1; a.decoy_hello = 1; a.disorder = 1;
    run_case("full-2048-decoy-in-4096-text-slot", a, 2048, 2048);
    a.seqovl_hello = 0; a.disorder = 0;
    a.tcpts = 1; a.ipidzero = 1; a.ttl = 8; a.seq_out = 1;
    run_case("fooling", a, 289, 0);
    if (failures) { fprintf(stderr, "measured: %d failures\n", failures); return 1; }
    puts("measured: exact bytes/lengths/seq/order/delays/fooling and input rejection passed");
    return 0;
}
