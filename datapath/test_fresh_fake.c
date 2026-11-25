#include "d2k_plan.h"
#include "d2k_plantlv.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_fake(int fresh) {
    uint8_t hello[48] = {22, 3, 3, 0, 43, 1, 0, 0, 39};
    hello[43] = 0;
    char hex[sizeof hello * 2 + 1];
    for (size_t i = 0; i < sizeof hello; i++)
        snprintf(hex + i * 2, sizeof hex - i * 2, "%02x", hello[i]);
    char plan_text[600];
    snprintf(plan_text, sizeof plan_text,
        "d2k-plan 1 %d\nid 00000000000000000000000000000000\n"
        "proto tcp tls\nwire tcp-template-v1\ninput 48 0 0\n"
        "payload 1 %s\nfake payload=1 poison=0 repeats=6 gap_us=0 "
        "place=before tlsmod=%s\norder forward\n",
        fresh ? 21 : 8, hex, fresh ? "rnd,dupsid,fresh" : "rnd,dupsid");
    uint8_t tlv[D2K_PLAN_TLV_MAX];
    size_t tlv_len = 0;
    char err[160];
    assert(d2k_plan_text_to_tlv(plan_text, tlv, sizeof tlv,
                                &tlv_len, err, sizeof err) == 0);
    if (fresh) {
        d2k_plan *rejected = NULL;
        tlv[7] = 20;
        assert(d2k_plan_load(tlv, tlv_len, &rejected, err, sizeof err) != 0);
        assert(rejected == NULL);
        tlv[7] = 21;
    }
    d2k_plan *plan = NULL;
    assert(d2k_plan_load(tlv, tlv_len, &plan, err, sizeof err) == 0);
    d2k_pkt packet = {.payload=hello, .payload_len=sizeof hello, .seq=1000};
    d2k_actions actions;
    assert(d2k_plan_apply(plan, NULL, &packet, &actions) == 0);
    assert(actions.n == 6 && actions.fate == D2K_ORIG_PASS);
    for (size_t i = 0; i < actions.n; i++) {
        const d2k_emit *emission = &actions.v[i];
        assert(emission->kind == D2K_EMIT_FAKE && emission->seq == packet.seq);
        assert(emission->len == sizeof hello);
        assert(!memcmp(emission->bytes, hello, 11));
        assert(!memcmp(emission->bytes + 43, hello + 43, sizeof hello - 43));
        if (i) {
            int same = !memcmp(emission->bytes + 11, actions.v[0].bytes + 11, 32);
            assert(same == !fresh);
        }
    }
    d2k_actions_free(&actions);
    d2k_plan_free(plan);
}

int main(void) {
    test_fake(0);
    test_fake(1);
    puts("fresh TLS fake repeats and legacy repeats PASS");
    return 0;
}
