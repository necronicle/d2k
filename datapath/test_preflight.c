/* Byte-level, socket-free regressions. Expectations below are hand-derived,
 * not emitted by preflight/wire helpers. Each named case catches its branch
 * being replaced with PASS, missing emission, or incorrect TCP fields. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "d2k_preflight.h"

static int failures;
#define REQUIRE(x)                                                                                 \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "%s:%d FAIL %s\n", __func__, __LINE__, #x);                            \
            return 0;                                                                              \
        }                                                                                          \
    } while (0)
static void w16(uint8_t *p, unsigned n) {
    p[0] = (uint8_t)(n >> 8);
    p[1] = (uint8_t)n;
}
static void w32(uint8_t *p, uint32_t n) {
    p[0] = n >> 24;
    p[1] = n >> 16;
    p[2] = n >> 8;
    p[3] = n;
}
static unsigned r16(const uint8_t *p) { return p[0] * 256u + p[1]; }
static uint32_t r32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static unsigned sum(const uint8_t *p, size_t n, unsigned s) {
    for (size_t i = 0; i < n; i++)
        s += (unsigned)p[i] << ((i & 1) ? 0 : 8);
    while (s >> 16)
        s = (s & 65535) + (s >> 16);
    return s;
}
static void checksums(uint8_t *p, size_t n) {
    size_t ip = (p[0] & 15) * 4;
    p[10] = p[11] = p[ip + 16] = p[ip + 17] = 0;
    w16(p + 10, ~sum(p, ip, 0));
    w16(p + ip + 16, ~sum(p + ip, n - ip, sum(p + 12, 8, 6 + (unsigned)(n - ip))));
}
static int valid(const uint8_t *p, size_t n) {
    size_t ip = (p[0] & 15) * 4;
    return r16(p + 2) == n && sum(p, ip, 0) == 65535 &&
           sum(p + ip, n - ip, sum(p + 12, 8, 6 + (unsigned)(n - ip))) == 65535;
}
static const uint8_t opts_plain[] = {2, 4, 5, 180, 1, 3, 3, 7};
static const uint8_t opts_ts[] = {2, 4,   5, 180, 4, 2, 1, 1, 8, 10, 0, 0,
                                  3, 232, 0, 0,   0, 0, 1, 3, 3, 7,  0, 0};
/* Minimal complete ClientHello, SNI a.example.com at offset 61. The second
 * level label example has midpoint offset 66 (midsld), not host midpoint. */
static const uint8_t hello[] = {
    22, 3, 1, 0,  69,  1,   0,   0,   65,   3,   3,   0,   0,   0,   0,   0,   0,  0,  0,
    0,  0, 0, 0,  0,   0,   0,   0,   0,    0,   0,   0,   0,   0,   0,   0,   0,  0,  0,
    0,  0, 0, 0,  0,   0,   0,   2,   0x13, 1,   1,   0,   0,   22,  0,   0,   0,  18, 0,
    16, 0, 0, 13, 'a', '.', 'e', 'x', 'a',  'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};

typedef struct {
    d2k_pf_table t;
    d2k_pf_out out;
    d2k_pf_params p;
    uint8_t syn[160], srv[256];
    d2k_pkt c, s;
} fixture;
static size_t packet(uint8_t *p, int server, unsigned port, uint8_t flags, uint32_t seq,
                     uint32_t ack, int ts, size_t data) {
    size_t ol = (flags & 2) ? (ts ? sizeof opts_ts : sizeof opts_plain) : (ts ? 12 : 0),
           n = 40 + ol + data;
    memset(p, 0, n);
    p[0] = 0x45;
    p[1] = 0x28;
    w16(p + 2, (unsigned)n);
    w16(p + 4, 0x1234);
    p[6] = 0x40;
    p[8] = 63;
    p[9] = 6;
    const uint8_t a[] = {10, 0, 0, 1}, b[] = {203, 0, 113, 9};
    memcpy(p + 12, server ? b : a, 4);
    memcpy(p + 16, server ? a : b, 4);
    w16(p + 20, server ? 443 : port);
    w16(p + 22, server ? port : 443);
    w32(p + 24, seq);
    w32(p + 28, ack);
    p[32] = (uint8_t)((20 + ol) / 4 << 4);
    p[33] = flags;
    w16(p + 34, 64240);
    if (flags & 2)
        memcpy(p + 40, ts ? opts_ts : opts_plain, ol);
    else if (ts) {
        p[40] = p[41] = 1;
        p[42] = 8;
        p[43] = 10;
        w32(p + 44, 5000);
        w32(p + 48, 1001);
    }
    memset(p + 40 + ol, 0x5a, data);
    checksums(p, n);
    return n;
}
static int setup(fixture *f, unsigned cap, int ts) {
    memset(f, 0, sizeof *f);
    REQUIRE(d2k_pf_table_init(&f->t, cap) == 1);
    f->p = (d2k_pf_params){.window = 7,
                           .wscale = 2,
                           .pieces = 3,
                           .hello_own = 1,
                           .timeout_ms = 137,
                           .hello = hello,
                           .hello_len = sizeof hello};
    f->c.wire = f->syn;
    f->c.wire_len = packet(f->syn, 0, 40000, 2, 100, 0, ts, 0);
    f->s.wire = f->srv;
    return 1;
}
static int stage(fixture *f, d2k_pf_stage want) {
    d2k_pf_stage got;
    return d2k_pf_get_stage(&f->t, &f->c, &got) && got == want;
}
static int start(fixture *f) {
    memset(f->out.original, 0xff, sizeof f->out.original);
    REQUIRE(d2k_pf_client_syn(&f->t, &f->c, &f->p, 1000000, &f->out) == PF_ACT_DROP);
    REQUIRE(f->out.count == 1);
    REQUIRE(f->out.original[0] == 0);
    REQUIRE(stage(f, PF_PROBE_SYN));
    return 1;
}
static int server(fixture *f, uint8_t flags, uint32_t seq, uint32_t ack, int ts, size_t n,
                  uint64_t now) {
    f->s.wire_len = packet(f->srv, 1, 40000, flags, seq, ack, ts, n);
    return d2k_pf_server_pkt(&f->t, &f->s, now, &f->out);
}
static int handshake(fixture *f, int ts) {
    REQUIRE(start(f));
    REQUIRE(server(f, 0x12, 700, 101, ts, 0, 2000000) == PF_ACT_DROP);
    REQUIRE(stage(f, PF_PROBE_DATA));
    return 1;
}
static int original(fixture *f, size_t i) {
    return f->out.original[i] == 1 && f->out.len[i] == f->c.wire_len &&
           !memcmp(f->out.packet[i], f->syn, f->c.wire_len);
}
static int emitted(fixture *f, size_t i, uint8_t flags, uint32_t seq, uint32_t ack, unsigned win,
                   int ts) {
    REQUIRE(i < f->out.count);
    REQUIRE(f->out.original[i] == 0);
    const uint8_t *p = f->out.packet[i];
    size_t n = f->out.len[i];
    REQUIRE(valid(p, n));
    REQUIRE(!memcmp(p + 12, f->syn + 12, 12));
    REQUIRE(p[33] == flags);
    REQUIRE(r32(p + 24) == seq);
    REQUIRE(r32(p + 28) == ack);
    REQUIRE(r16(p + 34) == win);
    REQUIRE((p[32] >> 4) == (ts ? 8 : 5));
    if (ts)
        REQUIRE(p[40] == 1 && p[41] == 1 && p[42] == 8 && p[43] == 10);
    return 1;
}
static int test_happy_path(void) {
    fixture f;
    REQUIRE(setup(&f, 2, 0));
    REQUIRE(handshake(&f, 0));
    REQUIRE(f.out.count == 2);
    REQUIRE(emitted(&f, 0, 16, 101, 701, 7, 0));
    REQUIRE(emitted(&f, 1, 24, 101, 701, 7, 0));
    REQUIRE(f.out.len[1] == 114);
    REQUIRE(!memcmp(f.out.packet[1] + 40, hello, sizeof hello));
    for (unsigned i = 0; i < 3; i++) {
        REQUIRE(server(&f, 24, 701 + i, 175, 0, 1, 3000000 + i) == PF_ACT_DROP);
        if (i < 2) {
            REQUIRE(f.out.count == 1);
            REQUIRE(emitted(&f, 0, 16, 175, 702 + i, 7, 0));
        } else {
            REQUIRE(f.out.count == 2);
            REQUIRE(emitted(&f, 0, 4, 175, 0, 7, 0));
            REQUIRE(original(&f, 1));
        }
    }
    REQUIRE(stage(&f, PF_RESYN));
    REQUIRE(server(&f, 18, 900, 101, 0, 0, 4000000) == PF_ACT_PASS);
    REQUIRE(f.out.count == 0 && stage(&f, PF_HANDOVER));
    REQUIRE(d2k_pf_client_syn(&f.t, &f.c, &f.p, 5000000, &f.out) == PF_ACT_PASS);
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_client_syn_retransmit_dropped(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    REQUIRE(handshake(&f, 0));
    REQUIRE(d2k_pf_client_syn(&f.t, &f.c, &f.p, 3000000, &f.out) == PF_ACT_DROP);
    REQUIRE(f.out.count == 2 && !f.out.original[0] && !f.out.original[1]);
    REQUIRE(d2k_pf_client_pkt(&f.t, &f.c, 3000000, &f.out) == PF_ACT_DROP);
    REQUIRE(f.out.count == 2 && !f.out.original[0] && !f.out.original[1]);
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_probe_syn_lost(void) {
    fixture f;
    uint8_t first[160];
    REQUIRE(setup(&f, 1, 0));
    REQUIRE(start(&f));
    size_t n = f.out.len[0];
    memcpy(first, f.out.packet[0], n);
    REQUIRE(valid(first, n));
    REQUIRE(first[33] == 2 && r16(first + 34) == 7 && first[44] == 3 && first[45] == 3 &&
            first[46] == 2 && first[47] == 0);
    REQUIRE(d2k_pf_client_syn(&f.t, &f.c, &f.p, 10000000, &f.out) == PF_ACT_DROP);
    REQUIRE(f.out.count == 1 && f.out.len[0] == n && !memcmp(first, f.out.packet[0], n));
    REQUIRE(d2k_pf_next_ns(&f.t) == 138000000);
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_server_rst_during_probe(void) {
    for (int data = 0; data < 2; data++) {
        fixture f;
        REQUIRE(setup(&f, 1, 0));
        if (data) {
            REQUIRE(handshake(&f, 0));
        } else {
            REQUIRE(start(&f));
        }
        REQUIRE(server(&f, 4, 701, 101, 0, 0, 3000000) == PF_ACT_DROP);
        REQUIRE(f.out.count == 1 && original(&f, 0) && stage(&f, PF_RESYN));
        REQUIRE(d2k_pf_client_syn(&f.t, &f.c, &f.p, 4000000, &f.out) == PF_ACT_PASS);
        REQUIRE(f.out.count == 0);
        d2k_pf_table_free(&f.t);
    }
    return 1;
}
static int test_stale_ack_reset_limit(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    REQUIRE(start(&f));
    REQUIRE(server(&f, 4, 701, 101, 0, 0, 3000000) == PF_ACT_DROP);
    REQUIRE(server(&f, 18, 700, 102, 0, 0, 4000000) == PF_ACT_DROP);
    REQUIRE(f.out.count == 0 && stage(&f, PF_RESYN));
    for (int i = 0; i < 7; i++) {
        REQUIRE(server(&f, 16, 701, 200 + (unsigned)i, 0, 0, 5000000) == PF_ACT_DROP);
        if (i < 5) {
            REQUIRE(f.out.count == 2);
            REQUIRE(emitted(&f, 0, 4, 200 + (unsigned)i, 0, 7, 0));
            REQUIRE(original(&f, 1));
        } else
            REQUIRE(f.out.count == 0);
    }
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_timeout_hands_over(void) {
    for (int data = 0; data < 2; data++) {
        fixture f;
        REQUIRE(setup(&f, 1, 0));
        if (data) {
            REQUIRE(handshake(&f, 0));
        } else {
            REQUIRE(start(&f));
        }
        d2k_pf_tick(&f.t, 137999999, &f.out);
        REQUIRE(f.out.count == 0);
        d2k_pf_tick(&f.t, 138000000, &f.out);
        REQUIRE(f.out.count == (data ? 2u : 1u));
        REQUIRE(original(&f, f.out.count - 1));
        if (data)
            REQUIRE(emitted(&f, 0, 4, 175, 0, 7, 0));
        REQUIRE(stage(&f, PF_GAVE_UP));
        REQUIRE(d2k_pf_next_ns(&f.t) == 0);
        d2k_pf_tick(&f.t, 200000000, &f.out);
        REQUIRE(f.out.count == 0);
        REQUIRE(d2k_pf_client_syn(&f.t, &f.c, &f.p, 200000000, &f.out) == PF_ACT_PASS);
        d2k_pf_table_free(&f.t);
    }
    return 1;
}
static int test_six_parallel_flows(void) {
    fixture f;
    REQUIRE(setup(&f, 6, 0));
    uint8_t syn[6][160];
    d2k_pkt c[6];
    for (unsigned i = 0; i < 6; i++) {
        c[i] = (d2k_pkt){.wire = syn[i],
                         .wire_len = packet(syn[i], 0, 40000 + i, 2, 100 + i, 0, 0, 0)};
        REQUIRE(d2k_pf_client_syn(&f.t, &c[i], &f.p, 1000000 + i, &f.out) == PF_ACT_DROP);
        REQUIRE(f.out.count == 1);
    }
    for (unsigned i = 0; i < 6; i++) {
        f.s.wire_len = packet(f.srv, 1, 40000 + i, 18, 700 + i, 101 + i, 0, 0);
        REQUIRE(d2k_pf_server_pkt(&f.t, &f.s, 2000000, &f.out) == PF_ACT_DROP);
        REQUIRE(f.out.count == 2 && r32(f.out.packet[0] + 24) == 101 + i);
    }
    unsigned handed = 0;
    while (d2k_pf_next_ns(&f.t)) {
        d2k_pf_tick(&f.t, 200000000, &f.out);
        REQUIRE(f.out.count > 0 && f.out.count <= 4);
        handed += (unsigned)f.out.count / 2;
    }
    REQUIRE(handed == 6);
    for (unsigned i = 0; i < 6; i++)
        REQUIRE(d2k_pf_client_syn(&f.t, &c[i], &f.p, 300000000, &f.out) == PF_ACT_PASS);
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_table_full_passes(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    REQUIRE(start(&f));
    uint8_t p[160];
    d2k_pkt c = {.wire = p, .wire_len = packet(p, 0, 40001, 2, 100, 0, 0, 0)};
    REQUIRE(d2k_pf_client_syn(&f.t, &c, &f.p, 2000000, &f.out) == PF_ACT_PASS);
    REQUIRE(f.out.count == 0 && f.t.full_passes == 1);
    REQUIRE(stage(&f, PF_PROBE_SYN));
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_matches_measured_shape(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    f.p.window = 1;
    f.p.wscale = 0;
    f.p.pieces = 6;
    REQUIRE(start(&f));
    const uint8_t *syn = f.out.packet[0];
    REQUIRE(valid(syn, f.out.len[0]));
    REQUIRE(syn[33] == 2 && r32(syn + 24) == 100 && r16(syn + 34) == 1 && syn[44] == 3 &&
            syn[45] == 3 && syn[46] == 0 && syn[47] == 0);
    REQUIRE(server(&f, 18, 700, 101, 0, 0, 2000000) == PF_ACT_DROP);
    REQUIRE(f.out.count == 2);
    REQUIRE(emitted(&f, 0, 16, 101, 701, 1, 0));
    REQUIRE(emitted(&f, 1, 24, 101, 701, 1, 0));
    /* ACK + contiguous hello; six data packets; five ACKs, RST, orig.
     * No open/openwin: every emitted window stays at measured W=1. */
    for (unsigned i = 0; i < 6; i++) {
        REQUIRE(server(&f, 24, 701 + i, 175, 0, 1, 3000000 + i) == PF_ACT_DROP);
        if (i < 5) {
            REQUIRE(f.out.count == 1);
            REQUIRE(emitted(&f, 0, 16, 175, 702 + i, 1, 0));
        } else {
            REQUIRE(f.out.count == 2);
            REQUIRE(emitted(&f, 0, 4, 175, 0, 1, 0));
            REQUIRE(original(&f, 1));
        }
    }
    REQUIRE(stage(&f, PF_RESYN));
    REQUIRE(server(&f, 18, 800, 101, 0, 0, 4000000) == PF_ACT_PASS);
    REQUIRE(stage(&f, PF_HANDOVER));
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_ts_kept_when_client_offers(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 1));
    REQUIRE(start(&f));
    const uint8_t *p = f.out.packet[0];
    REQUIRE(valid(p, f.out.len[0]));
    REQUIRE(f.out.len[0] == 64 && r32(p + 50) == 1000 && p[61] == 2 && p[44] == 4);
    REQUIRE(server(&f, 18, 700, 101, 1, 0, 2000000) == PF_ACT_DROP);
    for (size_t i = 0; i < 2; i++) {
        REQUIRE(emitted(&f, i, i ? 24 : 16, 101, 701, 7, 1));
        REQUIRE(r32(f.out.packet[i] + 44) == 1001 + i && r32(f.out.packet[i] + 48) == 1000);
    }
    REQUIRE(server(&f, 24, 701, 175, 1, 1, 3000000) == PF_ACT_DROP);
    REQUIRE(emitted(&f, 0, 16, 175, 702, 7, 1));
    REQUIRE(r32(f.out.packet[0] + 48) == 5000);
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_no_ts_when_client_omits(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    REQUIRE(handshake(&f, 1));
    for (size_t i = 0; i < 2; i++)
        REQUIRE(emitted(&f, i, i ? 24 : 16, 101, 701, 7, 0));
    d2k_pf_table_free(&f.t);
    return 1;
}
static size_t packet6(uint8_t *p, int server, uint8_t flags, uint32_t seq,
                      uint32_t ack, size_t data) {
    size_t n = packet(p, server, 40000, flags, seq, ack, 0, data) + 20;
    memmove(p + 40, p + 20, n - 40);
    memset(p, 0, 40);
    p[0] = 0x60;
    w16(p + 4, (unsigned)n - 40);
    p[6] = 6;
    p[7] = 63;
    const uint8_t a[16] = {0x20, 1, 0x0d, 0xb8, [15] = 1};
    const uint8_t b[16] = {0x20, 1, 0x0d, 0xb8, [15] = 2};
    memcpy(p + 8, server ? b : a, 16);
    memcpy(p + 24, server ? a : b, 16);
    w16(p + 56, 0);
    w16(p + 56, ~sum(p + 40, n - 40, sum(p + 8, 32, 6 + (unsigned)n - 40)));
    return n;
}
static int valid6(const uint8_t *p, size_t n) {
    return n >= 60 && p[0] == 0x60 && p[6] == 6 && r16(p + 4) == n - 40 &&
           sum(p + 40, n - 40, sum(p + 8, 32, 6 + (unsigned)n - 40)) == 65535;
}
static int test_ipv6_handover(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    f.p.pieces = 1;
    f.c.wire_len = packet6(f.syn, 0, 2, 100, 0, 0);
    REQUIRE(d2k_pf_client_syn(&f.t, &f.c, &f.p, 1000000, &f.out) == PF_ACT_DROP);
    REQUIRE(f.out.count == 1 && valid6(f.out.packet[0], f.out.len[0]));
    REQUIRE(memcmp(f.out.packet[0] + 8, f.syn + 8, 36) == 0);
    f.s.wire_len = packet6(f.srv, 1, 18, 700, 101, 0);
    REQUIRE(d2k_pf_server_pkt(&f.t, &f.s, 2000000, &f.out) == PF_ACT_DROP);
    REQUIRE(f.out.count == 2);
    for (size_t i = 0; i < f.out.count; i++)
        REQUIRE(valid6(f.out.packet[i], f.out.len[i]));
    f.s.wire_len = packet6(f.srv, 1, 24, 701, 175, 1);
    REQUIRE(d2k_pf_server_pkt(&f.t, &f.s, 3000000, &f.out) == PF_ACT_DROP);
    REQUIRE(f.out.count == 2 && f.out.packet[0][53] == 4);
    REQUIRE(valid6(f.out.packet[0], f.out.len[0]) && original(&f, 1));
    f.s.wire_len = packet6(f.srv, 1, 18, 800, 101, 0);
    REQUIRE(d2k_pf_server_pkt(&f.t, &f.s, 4000000, &f.out) == PF_ACT_PASS);
    REQUIRE(stage(&f, PF_HANDOVER));
    d2k_pf_table_free(&f.t);
    return 1;
}
/* A data-bearing ACK is not the stale bare ACK from the reference. */
static int test_resyn_data_is_not_stale_ack(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    REQUIRE(start(&f));
    REQUIRE(server(&f, 4, 701, 101, 0, 0, 3000000) == PF_ACT_DROP);
    REQUIRE(server(&f, 16, 701, 175, 0, 1, 4000000) == PF_ACT_DROP);
    REQUIRE(f.out.count == 0);
    d2k_pf_table_free(&f.t);
    return 1;
}
/* Both public client entry points must honor a tracked SYN retransmission. */
static int test_client_pkt_syn_retransmits(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    REQUIRE(start(&f));
    REQUIRE(d2k_pf_client_pkt(&f.t, &f.c, 2000000, &f.out) == PF_ACT_DROP);
    REQUIRE(f.out.count == 1 && f.out.packet[0][33] == 2);
    REQUIRE(server(&f, 4, 701, 101, 0, 0, 3000000) == PF_ACT_DROP);
    REQUIRE(d2k_pf_client_pkt(&f.t, &f.c, 4000000, &f.out) == PF_ACT_PASS);
    REQUIRE(f.out.count == 0);
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_partial_overlap_advances(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    f.p.pieces = 2;
    REQUIRE(handshake(&f, 0));
    REQUIRE(server(&f, 24, 701, 175, 0, 2, 3000000) == PF_ACT_DROP);
    REQUIRE(emitted(&f, 0, 16, 175, 703, 7, 0));
    REQUIRE(server(&f, 24, 701, 175, 0, 2, 4000000) == PF_ACT_DROP);
    REQUIRE(stage(&f, PF_PROBE_DATA));
    REQUIRE(emitted(&f, 0, 16, 175, 703, 7, 0));
    REQUIRE(server(&f, 24, 702, 175, 0, 2, 5000000) == PF_ACT_DROP);
    REQUIRE(f.out.count == 2 && stage(&f, PF_RESYN));
    REQUIRE(original(&f, 1));
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_unrelated_ack_not_counted(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    f.p.pieces = 1;
    REQUIRE(handshake(&f, 0));
    const uint32_t bad_ack[] = {100, 176, 175};
    for (unsigned i = 0; i < 3; i++) {
        REQUIRE(server(&f, i == 2 ? 8 : 24, 701, bad_ack[i], 0, 1, 3000000 + i) == PF_ACT_DROP);
        REQUIRE(f.out.count == 0 && stage(&f, PF_PROBE_DATA));
    }
    REQUIRE(server(&f, 24, 701, 175, 0, 1, 4000000) == PF_ACT_DROP);
    REQUIRE(f.out.count == 2 && stage(&f, PF_RESYN));
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_sequence_wrap(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    f.p.pieces = 2;
    w32(f.syn + 24, UINT32_MAX - 2);
    checksums(f.syn, f.c.wire_len);
    REQUIRE(start(&f));
    REQUIRE(server(&f, 18, UINT32_MAX - 1, UINT32_MAX - 1, 0, 0, 2000000) == PF_ACT_DROP);
    REQUIRE(emitted(&f, 0, 16, UINT32_MAX - 1, UINT32_MAX, 7, 0));
    REQUIRE(server(&f, 24, UINT32_MAX, 72, 0, 2, 3000000) == PF_ACT_DROP);
    REQUIRE(emitted(&f, 0, 16, 72, 1, 7, 0));
    REQUIRE(server(&f, 24, 0, 72, 0, 2, 4000000) == PF_ACT_DROP);
    REQUIRE(f.out.count == 2 && stage(&f, PF_RESYN));
    REQUIRE(emitted(&f, 0, 4, 72, 0, 7, 0));
    REQUIRE(original(&f, 1));
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_ip_options_and_owned_hello(void) {
    fixture f;
    uint8_t copy[sizeof hello];
    REQUIRE(setup(&f, 1, 0));
    memcpy(copy, hello, sizeof copy);
    f.p.hello = copy;
    f.p.hello_own = 0;
    memmove(f.syn + 24, f.syn + 20, f.c.wire_len - 20);
    f.c.wire_len += 4;
    f.syn[0] = 0x46;
    f.syn[20] = f.syn[21] = f.syn[22] = f.syn[23] = 1;
    w16(f.syn + 2, (unsigned)f.c.wire_len);
    checksums(f.syn, f.c.wire_len);
    REQUIRE(start(&f));
    REQUIRE(valid(f.out.packet[0], f.out.len[0]));
    memset(copy, 0, sizeof copy);
    f.p.window = 500;
    f.p.pieces = 99;
    REQUIRE(server(&f, 18, 700, 101, 0, 0, 2000000) == PF_ACT_DROP);
    REQUIRE(f.out.count == 2);
    for (size_t i = 0; i < 2; i++) {
        const uint8_t *p = f.out.packet[i];
        REQUIRE(valid(p, f.out.len[i]));
        REQUIRE(p[0] == 0x46 && !memcmp(p + 20, f.syn + 20, 4));
        REQUIRE(r16(p + 4) == 0x1235 + i && r16(p + 38) == 7);
    }
    REQUIRE(!memcmp(f.out.packet[1] + 44, hello, sizeof hello));
    for (unsigned i = 0; i < 3; i++)
        REQUIRE(server(&f, 24, 701 + i, 175, 0, 1, 3000000 + i) == PF_ACT_DROP);
    REQUIRE(f.out.count == 2 && original(&f, 1));
    d2k_pf_table_free(&f.t);
    return 1;
}
static int test_abort_returns_original(void) {
    for (int handshaken = 0; handshaken <= 1; handshaken++) {
        fixture f;
        REQUIRE(setup(&f, 1, 0));
        f.out.count = 3;
        d2k_pf_abort(&f.t, &f.c, &f.out);
        REQUIRE(f.out.count == 0);
        REQUIRE(handshaken ? handshake(&f, 0) : start(&f));
        memset(f.out.original, 0xff, sizeof f.out.original);
        d2k_pf_abort(&f.t, &f.c, &f.out);
        REQUIRE(stage(&f, PF_GAVE_UP));
        REQUIRE(f.out.count == (handshaken ? 2u : 1u));
        if (handshaken)
            REQUIRE(emitted(&f, 0, 4, 175, 0, 7, 0));
        REQUIRE(original(&f, handshaken ? 1 : 0));
        REQUIRE(d2k_pf_next_ns(&f.t) == 0);
        d2k_pf_abort(&f.t, &f.c, &f.out);
        REQUIRE(f.out.count == 0 && stage(&f, PF_GAVE_UP));
        d2k_pf_table_free(&f.t);
    }
    return 1;
}
static int test_abort_done_emits_nothing(void) {
    fixture f;
    REQUIRE(setup(&f, 1, 0));
    f.p.pieces = 1;
    REQUIRE(handshake(&f, 0));
    REQUIRE(server(&f, 24, 701, 175, 0, 1, 3000000) == PF_ACT_DROP);
    REQUIRE(stage(&f, PF_RESYN));
    REQUIRE(server(&f, 18, 900, 101, 0, 0, 4000000) == PF_ACT_PASS);
    REQUIRE(stage(&f, PF_HANDOVER));
    uint8_t p[256]; d2k_pkt client={.wire=p};
    client.wire_len=packet(p,0,40000,24,101,901,0,74);
    d2k_pf_complete(&f.t,&client,&f.out);
    REQUIRE(f.out.count==1 && f.out.clear[0]==2 && stage(&f,PF_DONE));
    d2k_pkt token={.wire=f.out.packet[0],.wire_len=f.out.len[0]};
    d2k_pf_output_sent(&f.t,&token,2);
    f.out.count = 3;
    d2k_pf_abort(&f.t, &f.c, &f.out);
    REQUIRE(f.out.count == 0 && stage(&f, PF_DONE));
    d2k_pf_table_free(&f.t);
    return 1;
}
/* A missing MSS/send-cap bound would emit an oversize ClientHello. */
static int segmented(size_t hello_len, unsigned mss, size_t cap, unsigned segments) {
    fixture f;
    uint8_t large[2000];
    for (size_t i=0;i<sizeof large;i++) large[i]=(uint8_t)i;
    REQUIRE(setup(&f,1,0));
    f.p.hello=large; f.p.hello_len=hello_len; f.p.send_cap=cap;
    REQUIRE(start(&f));
    f.s.wire_len=packet(f.srv,1,40000,18,700,101,0,0);
    w16(f.srv+42,mss); checksums(f.srv,f.s.wire_len);
    REQUIRE(d2k_pf_server_pkt(&f.t,&f.s,2000000,&f.out)==PF_ACT_DROP);
    REQUIRE(f.out.count==segments+1);
    REQUIRE(emitted(&f,0,16,101,701,7,0));
    size_t off=0;
    for (unsigned i=1;i<=segments;i++) {
        size_t n=f.out.len[i]-40;
        REQUIRE(n>0 && n<=mss && (!cap || n+40<=cap));
        REQUIRE(emitted(&f,i,24,101+(uint32_t)off,701,7,0));
        REQUIRE(!memcmp(f.out.packet[i]+40,large+off,n));
        off+=n;
    }
    REQUIRE(off==hello_len);
    /* Partial ACKs (no payload) are not response pieces. */
    REQUIRE(server(&f,16,701,101+mss,0,0,3000000)==PF_ACT_DROP);
    REQUIRE(!f.out.count && stage(&f,PF_PROBE_DATA));
    REQUIRE(server(&f,24,701,101+(uint32_t)hello_len,0,1,4000000)==PF_ACT_DROP);
    REQUIRE(f.out.count==1);
    d2k_pf_table_free(&f.t); return 1;
}
static int test_hello_segmented_by_mss(void) { return segmented(2000,1360,1500,2); }
static int test_hello_segmented_by_send_cap(void) { return segmented(2000,1360,1040,2); }
static int test_hello_small_single_segment(void) { return segmented(100,1360,1500,1); }
static int test_clear_mark_on_give_up(void) {
    fixture f; REQUIRE(setup(&f,1,0)); REQUIRE(start(&f));
    d2k_pf_tick(&f.t,138000000,&f.out);
    REQUIRE(f.out.count==1 && original(&f,0));
    REQUIRE(f.out.clear[0]==1);
    d2k_pf_table_free(&f.t); return 1;
}
static int test_clear_mark_after_client_hello(void) {
    fixture f; REQUIRE(setup(&f,1,0)); REQUIRE(start(&f));
    REQUIRE(server(&f,4,701,101,0,0,2000000)==PF_ACT_DROP);
    REQUIRE(!f.out.clear[0]); /* resyn is still watched */
    REQUIRE(server(&f,18,900,101,0,0,3000000)==PF_ACT_PASS);
    REQUIRE(stage(&f,PF_HANDOVER) && !f.out.count);
    uint8_t client[256]; d2k_pkt p={.wire=client};
    p.wire_len=packet(client,0,40000,16,101,901,0,0);
    d2k_pf_complete(&f.t,&p,&f.out); REQUIRE(!f.out.count);
    p.wire_len=packet(client,0,40000,24,101,901,0,74);
    REQUIRE(d2k_pf_client_pkt(&f.t,&p,4000000,&f.out)==PF_ACT_PASS);
    REQUIRE(stage(&f,PF_HANDOVER)); /* completion comes AFTER ordinary hello processing */
    d2k_pf_complete(&f.t,&p,&f.out);
    REQUIRE(f.out.count==1 && f.out.clear[0]==2 && !f.out.original[0]);
    REQUIRE(stage(&f,PF_DONE));
    d2k_pf_complete(&f.t,&p,&f.out); REQUIRE(!f.out.count);
    d2k_pf_table_free(&f.t); return 1;
}
static int test_hello_bounded_batches(void) {
    fixture f; uint8_t large[2000]; memset(large,0xab,sizeof large);
    REQUIRE(setup(&f,1,1)); f.p.hello=large; f.p.hello_len=sizeof large; f.p.send_cap=600;
    REQUIRE(start(&f));
    f.s.wire_len=packet(f.srv,1,40000,18,700,101,1,0);
    w16(f.srv+42,100); checksums(f.srv,f.s.wire_len);
    REQUIRE(d2k_pf_server_pkt(&f.t,&f.s,2000000,&f.out)==PF_ACT_DROP);
    REQUIRE(f.out.count==4);
    unsigned total=0; size_t off=0;
    do {
        for(size_t i=total ? 0 : 1;i<f.out.count;i++) {
            size_t n=f.out.len[i]-52;
            REQUIRE(n==100 && valid(f.out.packet[i],f.out.len[i]));
            REQUIRE(r32(f.out.packet[i]+24)==101+off);
            REQUIRE(!memcmp(f.out.packet[i]+52,large+off,n));
            off+=n; total++;
        }
        if (off==sizeof large) break;
        REQUIRE(d2k_pf_next_ns(&f.t)==2000000);
        d2k_pf_tick(&f.t,2000000,&f.out);
        REQUIRE(f.out.count && f.out.count<=4);
    } while(total<=20);
    REQUIRE(off==2000 && total==20 && d2k_pf_next_ns(&f.t)==138000000);
    d2k_pf_table_free(&f.t); return 1;
}
static int test_handover_timeout_only_clears(void) {
    fixture f; REQUIRE(setup(&f,1,0)); REQUIRE(start(&f));
    REQUIRE(server(&f,4,701,101,0,0,2000000)==PF_ACT_DROP);
    REQUIRE(server(&f,18,900,101,0,0,3000000)==PF_ACT_PASS);
    d2k_pf_tick(&f.t,138000000,&f.out);
    REQUIRE(f.out.count==1 && f.out.clear[0]==2 && !f.out.original[0]);
    REQUIRE(f.out.packet[0][33]==16 && r32(f.out.packet[0]+24)==101 && r32(f.out.packet[0]+28)==901);
    REQUIRE(valid(f.out.packet[0],f.out.len[0]) && d2k_pf_next_ns(&f.t));
    d2k_pkt token={.wire=f.out.packet[0],.wire_len=f.out.len[0]};
    d2k_pf_output_sent(&f.t,&token,2);
    REQUIRE(!d2k_pf_next_ns(&f.t));
    d2k_pf_table_free(&f.t); return 1;
}
static int test_response_needs_complete_hello_ack(void) {
    fixture f; REQUIRE(setup(&f,1,0)); f.p.pieces=1; REQUIRE(handshake(&f,0));
    REQUIRE(server(&f,24,701,102,0,1,3000000)==PF_ACT_DROP);
    REQUIRE(stage(&f,PF_PROBE_DATA));
    REQUIRE(server(&f,24,701,175,0,1,4000000)==PF_ACT_DROP);
    REQUIRE(stage(&f,PF_RESYN));
    d2k_pf_table_free(&f.t); return 1;
}
static int test_reset_cancels_pending_hello(void) {
    fixture f; uint8_t large[2000]; memset(large,0xab,sizeof large);
    REQUIRE(setup(&f,1,0)); f.p.hello=large; f.p.hello_len=sizeof large; f.p.send_cap=100;
    REQUIRE(handshake(&f,0)); REQUIRE(d2k_pf_next_ns(&f.t)==2000000);
    REQUIRE(server(&f,4,701,101,0,0,3000000)==PF_ACT_DROP);
    REQUIRE(stage(&f,PF_RESYN) && f.out.count==1 && original(&f,0));
    REQUIRE(d2k_pf_next_ns(&f.t)==138000000);
    d2k_pf_tick(&f.t,3000000,&f.out); REQUIRE(!f.out.count);
    d2k_pf_table_free(&f.t); return 1;
}
static int test_handover_expired_packet_passes(void) {
    for (int reply=0;reply<2;reply++) {
        fixture f; REQUIRE(setup(&f,1,0)); REQUIRE(start(&f));
        REQUIRE(server(&f,4,701,101,0,0,2000000)==PF_ACT_DROP);
        REQUIRE(server(&f,18,900,101,0,0,3000000)==PF_ACT_PASS);
        if(reply) {
            REQUIRE(server(&f,16,901,101,0,0,138000000)==PF_ACT_PASS);
        } else {
            uint8_t p[256]; d2k_pkt c={.wire=p};
            c.wire_len=packet(p,0,40000,24,101,901,0,74);
            REQUIRE(d2k_pf_client_pkt(&f.t,&c,138000000,&f.out)==PF_ACT_PASS);
        }
        REQUIRE(f.out.count==1 && f.out.clear[0]==2);
        d2k_pf_table_free(&f.t);
    }
    return 1;
}
/* Loss recovery belongs only to the owned probe, with one shared budget. */
static int test_probe_partial_ack_retry(void) {
    fixture f; REQUIRE(setup(&f,1,0)); REQUIRE(handshake(&f,0));
    REQUIRE(server(&f,16,701,121,0,0,3000000)==PF_ACT_DROP);
    for(unsigned i=0;i<3;i++)
        REQUIRE(server(&f,16,701,121,0,0,4000000+i)==PF_ACT_DROP);
    REQUIRE(f.out.count==2);
    REQUIRE(emitted(&f,0,16,175,701,7,0));
    REQUIRE(emitted(&f,1,24,121,701,7,0));
    REQUIRE(f.out.len[1]==40+sizeof hello-20);
    REQUIRE(!memcmp(f.out.packet[1]+40,hello+20,sizeof hello-20));
    REQUIRE(d2k_pf_next_ns(&f.t)==138000000);
    d2k_pf_table_free(&f.t); return 1;
}
static int test_probe_synack_retry(void) {
    fixture f; REQUIRE(setup(&f,1,0)); REQUIRE(handshake(&f,0));
    REQUIRE(server(&f,18,700,101,0,0,3000000)==PF_ACT_DROP);
    REQUIRE(f.out.count==2);
    REQUIRE(emitted(&f,0,16,101,701,7,0));
    REQUIRE(emitted(&f,1,24,101,701,7,0));
    REQUIRE(server(&f,18,701,101,0,0,4000000)==PF_ACT_DROP);
    REQUIRE(!f.out.count); /* a different server ISN is not this probe */
    d2k_pf_table_free(&f.t); return 1;
}
static int test_probe_retry_shared_budget(void) {
    fixture f; REQUIRE(setup(&f,1,0)); REQUIRE(handshake(&f,0));
    REQUIRE(d2k_pf_client_pkt(&f.t,&f.c,3000000,&f.out)==PF_ACT_DROP);
    REQUIRE(f.out.count==2);
    REQUIRE(server(&f,18,700,101,0,0,4000000)==PF_ACT_DROP);
    REQUIRE(f.out.count==2);
    REQUIRE(d2k_pf_client_pkt(&f.t,&f.c,5000000,&f.out)==PF_ACT_DROP);
    REQUIRE(!f.out.count);
    for(unsigned i=0;i<3;i++)
        REQUIRE(server(&f,16,701,101,0,0,6000000+i)==PF_ACT_DROP);
    REQUIRE(!f.out.count && d2k_pf_next_ns(&f.t)==138000000);
    d2k_pf_table_free(&f.t); return 1;
}
static int test_delayed_resyn_retries_cancel_on_handover(void) {
    fixture f; REQUIRE(setup(&f,1,0)); f.p.pieces=1;
    f.p.resyn_delay_ms=7; f.p.resyn_sends=3;
    REQUIRE(handshake(&f,0));
    REQUIRE(server(&f,24,701,175,0,1,3000000)==PF_ACT_DROP);
    REQUIRE(f.out.count==1 && emitted(&f,0,4,175,0,7,0));
    REQUIRE(stage(&f,PF_RESYN) && d2k_pf_next_ns(&f.t)==10000000);
    d2k_pf_tick(&f.t,9999999,&f.out); REQUIRE(!f.out.count);
    d2k_pf_tick(&f.t,10000000,&f.out); REQUIRE(f.out.count==1 && original(&f,0));
    REQUIRE(d2k_pf_next_ns(&f.t)==17000000);
    REQUIRE(server(&f,18,900,101,0,0,11000000)==PF_ACT_PASS);
    d2k_pf_tick(&f.t,17000000,&f.out); REQUIRE(!f.out.count);
    REQUIRE(d2k_pf_next_ns(&f.t)==138000000);
    d2k_pf_table_free(&f.t); return 1;
}
static int test_delayed_resyn_finite_stale_ack_budget(void) {
    fixture f; REQUIRE(setup(&f,1,0));
    f.p.resyn_delay_ms=7; f.p.resyn_sends=3; REQUIRE(handshake(&f,0));
    REQUIRE(server(&f,4,701,175,0,0,3000000)==PF_ACT_DROP);
    REQUIRE(!f.out.count && d2k_pf_next_ns(&f.t)==10000000);
    for(unsigned i=0;i<3;i++) {
        d2k_pf_tick(&f.t,10000000+i*7000000,&f.out);
        REQUIRE(f.out.count==1 && original(&f,0));
    }
    REQUIRE(d2k_pf_next_ns(&f.t)==138000000);
    REQUIRE(server(&f,16,701,175,0,0,30000000)==PF_ACT_DROP);
    REQUIRE(f.out.count==1 && emitted(&f,0,4,175,0,7,0));
    REQUIRE(d2k_pf_next_ns(&f.t)==138000000);
    d2k_pf_tick(&f.t,138000000,&f.out);
    REQUIRE(f.out.count==2 && original(&f,1) && f.out.clear[1]==1);
    REQUIRE(!d2k_pf_next_ns(&f.t));
    d2k_pf_table_free(&f.t); return 1;
}
static int test_delayed_resyn_drops_late_probe_synack(void) {
    fixture f; REQUIRE(setup(&f,1,0)); f.p.pieces=1;
    f.p.resyn_delay_ms=7; f.p.resyn_sends=3; REQUIRE(handshake(&f,0));
    REQUIRE(server(&f,24,701,175,0,1,3000000)==PF_ACT_DROP);
    /* Probe retransmissions cannot become the client's handshake. */
    REQUIRE(server(&f,18,700,101,0,0,4000000)==PF_ACT_DROP);
    REQUIRE(stage(&f,PF_RESYN));
    REQUIRE(server(&f,18,900,101,0,0,5000000)==PF_ACT_DROP);
    REQUIRE(stage(&f,PF_RESYN)); /* original SYN has not left yet */
    d2k_pf_tick(&f.t,10000000,&f.out); REQUIRE(f.out.count==1 && original(&f,0));
    /* The old probe SYN-ACK remains indistinguishable from a reused cookie ISN. */
    REQUIRE(server(&f,18,700,101,0,0,11000000)==PF_ACT_DROP);
    REQUIRE(stage(&f,PF_RESYN));
    REQUIRE(server(&f,18,900,101,0,0,12000000)==PF_ACT_PASS);
    REQUIRE(stage(&f,PF_HANDOVER));
    d2k_pf_table_free(&f.t); return 1;
}
static int test_delayed_resyn_coalesces_client_retransmission(void) {
    fixture f; REQUIRE(setup(&f,1,0)); f.p.resyn_delay_ms=7;f.p.resyn_sends=3;
    REQUIRE(handshake(&f,0));
    REQUIRE(server(&f,4,701,175,0,0,3000000)==PF_ACT_DROP);
    REQUIRE(d2k_pf_client_syn(&f.t,&f.c,&f.p,4000000,&f.out)==PF_ACT_DROP);
    REQUIRE(!f.out.count && d2k_pf_next_ns(&f.t)==10000000);
    REQUIRE(server(&f,18,900,101,0,0,5000000)==PF_ACT_DROP);
    REQUIRE(stage(&f,PF_RESYN));
    REQUIRE(d2k_pf_client_syn(&f.t,&f.c,&f.p,10000000,&f.out)==PF_ACT_PASS);
    REQUIRE(!f.out.count && d2k_pf_next_ns(&f.t)==17000000);
    d2k_pf_tick(&f.t,10000000,&f.out);REQUIRE(!f.out.count);
    d2k_pf_tick(&f.t,17000000,&f.out);REQUIRE(f.out.count==1 && original(&f,0));
    d2k_pf_tick(&f.t,24000000,&f.out);REQUIRE(f.out.count==1 && original(&f,0));
    REQUIRE(d2k_pf_next_ns(&f.t)==138000000);
    d2k_pf_table_free(&f.t);return 1;
}
static int test_late_pieces_preserve_reserved_handover_budget(void) {
    fixture f; REQUIRE(setup(&f,1,0)); f.p.pieces=1;
    f.p.resyn_delay_ms=7;f.p.resyn_sends=3;f.p.resyn_timeout_ms=21;
    REQUIRE(handshake(&f,0));REQUIRE(d2k_pf_next_ns(&f.t)==117000000);
    REQUIRE(server(&f,24,701,175,0,1,116999999)==PF_ACT_DROP);
    REQUIRE(f.out.count==1 && f.out.packet[0][33]==4 && stage(&f,PF_RESYN));
    for(unsigned i=0;i<3;i++) {
        d2k_pf_tick(&f.t,123999999+i*7000000,&f.out);
        REQUIRE(f.out.count==1 && original(&f,0));
    }
    REQUIRE(d2k_pf_next_ns(&f.t)==138000000);
    REQUIRE(server(&f,18,900,101,0,0,137500000)==PF_ACT_PASS);
    REQUIRE(stage(&f,PF_HANDOVER));d2k_pf_table_free(&f.t);return 1;
}
static int test_probe_cannot_consume_reserved_handover_budget(void) {
    fixture f; REQUIRE(setup(&f,1,0));f.p.pieces=1;
    f.p.resyn_delay_ms=7;f.p.resyn_sends=3;f.p.resyn_timeout_ms=21;
    REQUIRE(handshake(&f,0));
    REQUIRE(server(&f,24,701,175,0,1,117000000)==PF_ACT_DROP);
    REQUIRE(stage(&f,PF_GAVE_UP) && f.out.count==2 && original(&f,1) && f.out.clear[1]==1);
    REQUIRE(!d2k_pf_next_ns(&f.t));d2k_pf_table_free(&f.t);return 1;
}
static int test_preflight_budget_refuses_overflow_and_resource_excess(void) {
    fixture f;REQUIRE(setup(&f,1,0));
    REQUIRE(d2k_pf_client_syn(&f.t,&f.c,&f.p,UINT64_MAX-100,&f.out)==PF_ACT_PASS);
    REQUIRE(!f.out.count && !d2k_pf_next_ns(&f.t));
    f.p.timeout_ms=UINT32_MAX;
    REQUIRE(d2k_pf_client_syn(&f.t,&f.c,&f.p,1000000,&f.out)==PF_ACT_PASS);
    REQUIRE(!f.out.count && !d2k_pf_next_ns(&f.t));
    f.p.timeout_ms=137;f.p.resyn_timeout_ms=137;
    REQUIRE(d2k_pf_client_syn(&f.t,&f.c,&f.p,1000000,&f.out)==PF_ACT_PASS);
    REQUIRE(!f.out.count && !d2k_pf_next_ns(&f.t));
    d2k_pf_table_free(&f.t);return 1;
}
static int test_server_without_ts_disables_probe_ts(void) {
    fixture f;REQUIRE(setup(&f,1,1));REQUIRE(handshake(&f,0));
    REQUIRE(f.out.count==2);
    REQUIRE(emitted(&f,0,16,101,701,7,0));
    REQUIRE(emitted(&f,1,24,101,701,7,0));
    d2k_pf_table_free(&f.t);return 1;
}
static int test_reference_syn_inserts_measured_window_scale(void) {
    fixture f;REQUIRE(setup(&f,1,0));
    f.p.reference_hello=1;f.p.hello_own=0;f.p.pieces=1;
    f.syn[32]=0x60;w16(f.syn+2,44);f.c.wire_len=44;checksums(f.syn,44);
    REQUIRE(start(&f));
    REQUIRE(f.out.count==1 && f.out.len[0]==48);
    const uint8_t *syn=f.out.packet[0];
    REQUIRE(syn[32]>>4==7 && syn[40]==2 && syn[41]==4);
    REQUIRE(syn[44]==3 && syn[45]==3 && syn[46]==2);
    REQUIRE(valid(syn,48));d2k_pf_table_free(&f.t);return 1;
}
struct testcase {
    const char *name;
    int (*fn)(void);
};
#define CASE(x) {#x, x}
int main(int argc, char **argv) {
    const struct testcase tests[] = {CASE(test_preflight_budget_refuses_overflow_and_resource_excess),CASE(test_late_pieces_preserve_reserved_handover_budget),CASE(test_probe_cannot_consume_reserved_handover_budget),CASE(test_delayed_resyn_coalesces_client_retransmission), CASE(test_delayed_resyn_drops_late_probe_synack), CASE(test_delayed_resyn_retries_cancel_on_handover), CASE(test_delayed_resyn_finite_stale_ack_budget), CASE(test_probe_partial_ack_retry), CASE(test_probe_synack_retry), CASE(test_probe_retry_shared_budget), CASE(test_handover_expired_packet_passes), CASE(test_hello_bounded_batches), CASE(test_handover_timeout_only_clears), CASE(test_response_needs_complete_hello_ack), CASE(test_reset_cancels_pending_hello), CASE(test_clear_mark_on_give_up), CASE(test_clear_mark_after_client_hello), CASE(test_hello_segmented_by_mss), CASE(test_hello_segmented_by_send_cap),
                                     CASE(test_hello_small_single_segment), CASE(test_happy_path),
                                     CASE(test_abort_returns_original),
                                     CASE(test_abort_done_emits_nothing),
                                     CASE(test_client_syn_retransmit_dropped),
                                     CASE(test_probe_syn_lost),
                                     CASE(test_server_rst_during_probe),
                                     CASE(test_stale_ack_reset_limit),
                                     CASE(test_timeout_hands_over),
                                     CASE(test_six_parallel_flows),
                                     CASE(test_table_full_passes),
                                     CASE(test_matches_measured_shape),
                                     CASE(test_ts_kept_when_client_offers),
                                     CASE(test_no_ts_when_client_omits),
                                     CASE(test_ipv6_handover),
                                     CASE(test_resyn_data_is_not_stale_ack),
                                     CASE(test_client_pkt_syn_retransmits),
                                     CASE(test_partial_overlap_advances),
                                     CASE(test_unrelated_ack_not_counted),
                                     CASE(test_sequence_wrap),
                                     CASE(test_server_without_ts_disables_probe_ts),
                                     CASE(test_reference_syn_inserts_measured_window_scale),
                                     CASE(test_ip_options_and_owned_hello)};
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        if (argc > 1 && strcmp(argv[1], tests[i].name))
            continue;
        int ok = tests[i].fn();
        printf("%s %s\n", tests[i].name, ok ? "PASS" : "FAIL");
        failures += !ok;
    }
    return failures ? 1 : 0;
}
