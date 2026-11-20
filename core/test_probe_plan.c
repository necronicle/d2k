/* The pre-unification schedule is a frozen compatibility oracle.
 * Include the property catalog itself, as detect/test_repeats.c does: new
 * questions automatically enter this test without a second handwritten list. */
#include "d2k_compose.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include "d2k_detect.h"
#include "../detect/props.c"
#include <stdio.h>
#include <string.h>

int d2k_arm_from_poison(const d2k_poison *, d2k_arm *, char *, size_t);
/* Scheduler reporting is unrelated to the pure bridge conversion. */
d2k_run_cache *d2k_sched_measure_cache(void) { return NULL; }
void d2k_sched_measure_trace(const char *line) { (void)line; }
void d2k_sched_progress_note(const char *q, int pass, int fail) {
    (void)q; (void)pass; (void)fail;
}
#ifndef D2K_SEND_MAX
#include "../detect/tests/legacy_sends.h"
#endif
static unsigned failures, cases, skipped;
#define BASE 10000u
#define REQUIRE(c) do { if (!(c)) { \
    fprintf(stderr, "%s len=%zu sni=%d:%d line=%d: %s\n", p.name, tr->len, \
            tr->sni_off, tr->sni_len, __LINE__, #c); failures++; goto done; \
} } while (0)

static void run_case(d2k_poison p, const d2k_trigger *tr, const uint8_t *decoy, size_t dn) {
    d2k_arm a;
    d2k_arm_input in = {0};
    d2k_sends sends;
    d2k_plan *plan = NULL;
    d2k_actions out = {0};
    d2k_pkt pkt = {0};
    uint8_t fake[2 * D2K_TRIGGER_MAX], seg[D2K_TRIGGER_MAX + 4096];
    uint8_t tlv[D2K_PLAN_TLV_MAX];
    char text[8192], err[200];
    size_t tn = 0, index = 0;
    /* C uses the recovered field program, not the historical padded fake.
       Its full text/TLV check is below; test_raw compares actual IP/TCP bytes
       at the probe sendto boundary against RX-plan execution. */
    if (!strcmp(p.name, "white-hello-ts")) return;
    if (p.decoy_hello) { p.decoy = decoy; p.decoy_len = dn; }
    if (p.seqovl_exact) { p.seqovl = (int)dn; }
    int bridge_rc = d2k_arm_from_poison(&p, &a, err, sizeof err);
    /* MD5 is now required to traverse the complete measured-plan path. */
    REQUIRE(!(p.md5 || p.md5_ts) || bridge_rc == 0);
    /* oob (срочный байт) выражается планом «oob sni_middle 0f» и исполняется
       датапатом (поле 10.10.2026): мост обязан его принять, а не отвергнуть. */
    REQUIRE(!p.oob || bridge_rc == 0);
    if (bridge_rc == -1) {
        if (cases == 0) { printf("skip %s: %s\n", p.name, err); }
        skipped++; return;
    }
    /* oob ставит URG-байт в середину ИМЕНИ: без имени в приветствии плана нет
       (как перекрытие до конца имени). Для безымянного входа — пропуск. */
    if (p.oob && (tr->sni_len <= 1 || tr->sni_off <= 0)) { skipped++; return; }
    in.trigger_len = tr->len; in.sni_off = tr->sni_off; in.sni_len = tr->sni_len;
    /* No decoy pointer means padding, including non-hello overlap probes. */
    in.decoy_len = p.decoy_len;
    if (p.decoy_len) { memcpy(in.decoy, p.decoy, p.decoy_len); }
    /* Larger triggers do not expand the existing owned-overlap contract.
       A non-representable overlap must refuse, not clamp its measured bytes. */
    if ((unsigned)p.seqovl > D2K_ARM_DECOY_MAX) {
        REQUIRE(d2k_arm_plan_measured(&a, &in, text, sizeof text) == -1);
        skipped++; goto done;
    }
    REQUIRE(d2k_poison_sends(tr, &p, fake, sizeof fake, seg, sizeof seg, &sends) == 0);
    REQUIRE(d2k_arm_plan_measured(&a, &in, text, sizeof text) == 0);
    REQUIRE(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tn, err, sizeof err) == 0);
    REQUIRE(d2k_plan_load(tlv, tn, &plan, err, sizeof err) == 0);
    pkt.seq = BASE; pkt.payload = tr->payload; pkt.payload_len = tr->len;
    pkt.have_sni = tr->sni_len > 0; pkt.sni_off = tr->sni_off; pkt.sni_len = tr->sni_len;
    REQUIRE(d2k_plan_apply(plan, NULL, &pkt, &out) == 0);
    REQUIRE(out.fate == D2K_ORIG_DROP);
    for (size_t i = 0; i < sends.n; i++) {
        const d2k_send *s = &sends.v[i];
        for (size_t off = 0; off < s->len; ) {
            size_t n = s->len - off;
            if (n > D2K_ARM_SEGMENT_MAX) { n = D2K_ARM_SEGMENT_MAX; }
            REQUIRE(index < out.n);
            const d2k_emit *e = &out.v[index++];
            /* Зеркало порчи: план обязан нести РОВНО те биты, что описаны в
               гипотезе — ни больше (иначе исполнение разойдётся с замером),
               ни меньше. tcp_ts_up добавлен 23.10.2026 отдельной осью. */
            unsigned flags = (s->poison.badsum ? D2K_POISON_BADSUM : 0) |
                (s->poison.tcp_ts ? D2K_POISON_TCPTS_BACK : 0) |
                (s->poison.tcp_ts_up ? D2K_POISON_TS_UP : 0) |
                (s->poison.ip_id_zero ? D2K_POISON_IPID_ZERO : 0) |
                (s->poison.md5 ? D2K_POISON_MD5 : 0) |
                (s->poison.md5_ts ? D2K_POISON_MD5_TS : 0);
            REQUIRE(e->seq == (uint32_t)(BASE + s->seq_off + (int64_t)off));
            REQUIRE(e->seq_shift == s->poison.seq_shift);
            REQUIRE(e->kind == (s->kind == D2K_SEND_FAKE ? D2K_EMIT_FAKE : D2K_EMIT_PAYLOAD));
            REQUIRE(e->wire_profile == D2K_WIRE_DETECT_TCP);
            REQUIRE(e->urgent == (s->kind == D2K_SEND_URG));
            REQUIRE(e->poison == flags && e->ttl == s->poison.ttl);
            REQUIRE(e->delay_us == (off ? 0u : (unsigned)s->delay_ms * 1000u));
            REQUIRE(e->pre_len + e->len == n);
            REQUIRE(!e->pre_len || memcmp(e->pre, s->bytes + off, e->pre_len) == 0);
            REQUIRE(!e->len || memcmp(e->bytes, s->bytes + off + e->pre_len, e->len) == 0);
            off += n;
        }
    }
    REQUIRE(index == out.n);
    /* tail_ms is a wait before reading, with no subsequent wire send. */
done:
    d2k_actions_free(&out); d2k_plan_free(plan);
}

int main(void) {
    static const size_t lengths[] = {512, 1400, 1401, 2048, 2049, D2K_TRIGGER_MAX};
    uint8_t decoy[681];
    int np;
    const d2k_poison *ps = d2k_poisons(&np);
    for (size_t i = 0; i < sizeof decoy; i++) { decoy[i] = (uint8_t)(i * 23 + 5); }
    for (size_t k = 0; k < sizeof lengths / sizeof lengths[0]; k++) {
        for (int named = 0; named < 2; named++) {
            d2k_trigger tr = {0};
            tr.len = lengths[k]; tr.sni_off = named ? (int)tr.len / 3 : 0;
            tr.sni_len = named ? 11 : 0;
            for (size_t i = 0; i < tr.len; i++) { tr.payload[i] = (uint8_t)(i * 13 + 3); }
            tr.payload[0] = 0x16; tr.payload[1] = 3; tr.payload[2] = 1;
            tr.payload[3] = (uint8_t)((tr.len - 5) >> 8); tr.payload[4] = (uint8_t)(tr.len - 5);
            tr.payload[5] = 1; tr.payload[6] = 0;
            tr.payload[7] = (uint8_t)((tr.len - 9) >> 8); tr.payload[8] = (uint8_t)(tr.len - 9);
            for (int i = 0; i < np; i++) { run_case(ps[i], &tr, decoy, sizeof decoy); }
            prop_probe pp[16]; int nq = prop_probes(pp, 16);
            for (int i = 0; i < nq; i++) {
                if (pp[i].set == SET_OVERLAP_SNI) {
                    if (!named) { continue; }
                    pp[i].p.seqovl = tr.sni_off + tr.sni_len;
                }
                run_case(pp[i].p, &tr, decoy, sizeof decoy);
            }
            cases++;
        }
    }
    /* СОСТАВНОЙ ПЛАН СЕМЕЙСТВА C СОБИРАЕТСЯ И ИСПОЛНЯЕТСЯ (поле 10.10.2026).
       Вопрос «ECH-приветствие под меткой» обязан дать ровно plan-680fbe00:
       fake под меткой времени, серия ×8, разрез настоящего приветствия +2,
       прямой порядок. Здесь сравниваются весь текст, TLV и каталожный ID;
       detect/test_raw.c независимо сравнивает полные runtime-пакеты. */
    {
        prop_probe pp[16];
        int nq = prop_probes(pp, 16), found = 0, i;
        d2k_trigger tr = {0};
        tr.len = 1400; tr.sni_off = 466; tr.sni_len = 11;
        for (size_t j = 0; j < tr.len; j++) { tr.payload[j] = (uint8_t)(j * 13 + 3); }
        tr.payload[0] = 0x16; tr.payload[1] = 3; tr.payload[2] = 1;
        for (i = 0; i < nq; i++) {
            d2k_poison p = pp[i].p;
            d2k_arm a;
            d2k_arm_input in = {0};
            char text[8192], err[200];
            if (strcmp(p.name, "white-hello-ts") != 0) { continue; }
            found = 1;
            p.decoy = decoy; p.decoy_len = sizeof decoy;
            in.trigger_len = tr.len; in.sni_off = tr.sni_off; in.sni_len = tr.sni_len;
            in.decoy_len = p.decoy_len; memcpy(in.decoy, p.decoy, p.decoy_len);
            if (d2k_arm_from_poison(&p, &a, err, sizeof err) != 0) {
                printf("семейство C: мост отверг приём: %s\n", err); failures++; break;
            }
            if (d2k_arm_plan_measured(&a, &in, text, sizeof text) != 0) {
                printf("семейство C: план не собрался\n"); failures++; break;
            }
            {
                char expected[8192];
                uint8_t got_tlv[D2K_PLAN_TLV_MAX], want_tlv[D2K_PLAN_TLV_MAX];
                size_t got_n = 0, want_n = 0;
                /* Real ECH seed: the complete serialized program, including ID. */
                if (d2k_white_decoy_hello("hcaptcha.com", in.decoy, sizeof in.decoy,
                                         &in.decoy_len) ||
                    d2k_arm_plan_measured(&a, &in, text, sizeof text) ||
                    d2k_rx_volume_plan(0, D2K_SHAPE_MODERN, 0, expected, sizeof expected) ||
                    d2k_plan_text_to_tlv(text, got_tlv, sizeof got_tlv, &got_n, err, sizeof err) ||
                    d2k_plan_text_to_tlv(expected, want_tlv, sizeof want_tlv, &want_n, err, sizeof err) ||
                    strcmp(text, expected) || got_n != want_n || memcmp(got_tlv, want_tlv, got_n)) {
                    fprintf(stderr, "семейство C: arm != plan-680fbe00 (text/TLV)\n"); failures++;
                }
                uint64_t hash = 1469598103934665603ULL;
                for (const char *c = text; *c; c++) { hash ^= (unsigned char)*c; hash *= 1099511628211ULL; }
                if ((uint32_t)hash != 0x680fbe00u) {
                    fprintf(stderr, "семейство C: неверный ID plan-%08x\n", (unsigned)(uint32_t)hash); failures++;
                }
            }
            if (!strstr(text, "poison 1 tcpts")) { printf("семейство C: нет «poison 1 tcpts»\n"); failures++; }
            if (!strstr(text, "fake payload=1 poison=1 repeats=8")) {
                printf("семейство C: нет серии ×8\n"); failures++;
            }
            if (!strstr(text, "split payload_start +2")) { printf("семейство C: нет разреза +2\n"); failures++; }
            if (!strstr(text, "order forward")) { printf("семейство C: нет прямого порядка\n"); failures++; }
        }
        if (!found) { printf("семейство C: вопрос «white-hello-ts» не найден\n"); failures++; }
    }
    prop_probe allq[16];
    int n_questions = prop_probes(allq, 16);
    printf("probe-plan: %u inputs, %d catalog hypotheses, %d questions, %u skipped, %u mismatches\n",
           cases, np, n_questions, skipped, failures);
    return failures ? 1 : 0;
}
