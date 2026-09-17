#include <stdlib.h>
#include <string.h>
#include "d2k_hold.h"

typedef struct {
    size_t count;
    uint64_t deadline, revision;
    d2k_hold_info head;
    uint32_t ids[D2K_HOLD_IDS];
    size_t len[D2K_HOLD_IDS];
    uint8_t packets[D2K_HOLD_IDS][D2K_HOLD_PACKET];
} held;
struct d2k_hold { held slots[D2K_HOLD_SLOTS]; d2k_capture capture; d2k_hold_stats stats; };
static uint16_t r16(const uint8_t *p) { return (uint16_t)((unsigned)p[0] << 8 | p[1]); }
static uint32_t r32(const uint8_t *p) { return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }
static int same(const d2k_key *a, const d2k_key *b) {
    return a->proto == b->proto && a->low_ip == b->low_ip && a->high_ip == b->high_ip &&
           a->low_port == b->low_port && a->high_port == b->high_port;
}
int d2k_hold_parse(const uint8_t *p, size_t n, d2k_hold_info *v) {
    memset(v, 0, sizeof *v);
    if (!p || n < 40 || p[0] >> 4 != 4 || p[9] != 6 || (r16(p+6)&0x3fff)) { return 0; }
    v->ihl = (size_t)(p[0]&15)*4;
    if (v->ihl < 20 || v->ihl + 20 > n) { return 0; }
    const uint8_t *t = p + v->ihl;
    size_t th = (size_t)(t[12]>>4)*4;
    v->header = v->ihl + th;
    v->total = r16(p+2);
    if (th < 20 || v->total > n || v->total < v->header) { return 0; }
    v->payload = v->total - v->header;
    v->src_low = d2k_key_make(&v->key, 6, p+12, p+16, t, t+2);
    v->seq = r32(t+4); v->ack = r32(t+8); v->flags = t[13];
    memcpy(&v->dst_be, p+16, 4); memcpy(&v->sport_be, t, 2);
    return 1;
}
d2k_hold *d2k_hold_new(void) { return calloc(1, sizeof(d2k_hold)); }
void d2k_hold_free(d2k_hold *h) { free(h); }
static void release_slot(d2k_hold *h, held *s, d2k_hold_release release, void *ctx) {
    for (size_t j = 0; j < s->count; j++) {
        release(ctx, s->ids[j], s->packets[j], s->len[j]);
        h->stats.released++;
    }
    d2k_capture_forget(&h->capture, &s->head.key);
    h->stats.pending -= s->count;
    s->count = 0;
}
void d2k_hold_flush(d2k_hold *h, uint64_t now, uint64_t revision, int all,
                    d2k_hold_release release, void *ctx) {
    if (!h) { return; }
    for (size_t i = 0; i < D2K_HOLD_SLOTS; i++) {
        held *s = &h->slots[i];
        if (!s->count) { continue; }
        if (all || now >= s->deadline || revision != s->revision) {
            if (now >= s->deadline) {
                h->stats.timed_out++;
                /* СКОЛЬКО ПАКЕТОВ ТАК И ОСТАЛОСЬ ЛЕЖАТЬ. Один — второй
                   сегмент до очереди не дошёл; два и больше — дошёл, а разбор
                   приветствия его не собрал. Без этого числа обе причины
                   неразличимы (поле 17.09, зонд подтверждения). */
                h->stats.timed_out_pkts += s->count;
            }
            release_slot(h, s, release, ctx);
        }
    }
}
uint64_t d2k_hold_next(const d2k_hold *h) {
    uint64_t next = 0;
    if (h) for (size_t i = 0; i < D2K_HOLD_SLOTS; i++) {
        const held *s = &h->slots[i];
        if (s->count && (!next || s->deadline < next)) { next = s->deadline; }
    }
    return next;
}
void d2k_hold_get_stats(const d2k_hold *h, d2k_hold_stats *out) {
    memset(out, 0, sizeof *out);
    if (h) { *out = h->stats; }
}
size_t d2k_hold_verdicts(const uint32_t *ids, size_t count, uint32_t verdict,
                        int (*send)(void *, uint32_t, uint32_t), void *ctx) {
    size_t failed = 0;
    for (size_t i = 0; i < count; i++) {
        if (send(ctx, ids[i], verdict) != 0) { failed++; }
    }
    return failed;
}
int d2k_hold_feed(d2k_hold *h, uint32_t id, const uint8_t *p, size_t n,
                  uint64_t now, uint64_t revision, int allow_start,
                  d2k_hold_release release, void *ctx, d2k_hold_batch *batch) {
    memset(batch, 0, sizeof *batch);
    if (!h) { return 0; }
    d2k_hold_flush(h, now, revision, 0, release, ctx);
    d2k_hold_info v;
    if (!d2k_hold_parse(p, n, &v)) { return 0; }
    held *s = NULL, *vacant = NULL;
    for (size_t i = 0; i < D2K_HOLD_SLOTS; i++) {
        held *q = &h->slots[i];
        if (q->count && same(&q->head.key, &v.key)) { s = q; }
        if (!q->count && !vacant) { vacant = q; }
    }
    if (s && ((v.flags & 7) || (v.src_low != s->head.src_low && v.payload))) {
        release_slot(h, s, release, ctx);
        return 0;
    }
    if (!v.payload || (s && v.src_low != s->head.src_low)) { return 0; }
    if (!s) {
        if (!allow_start || p[v.header] != 22 || (v.flags & ~0x18) || !(v.flags&0x10)) { return 0; }
        if (v.payload >= 5 && 5u + r16(p + v.header + 3) <= v.payload) { return 0; }
        if (!vacant) { h->stats.full++; return 0; }
        s = vacant;
        s->head = v;
        s->revision = revision;
        s->deadline = now + D2K_HOLD_WAIT_NS;
        h->stats.started++;
    }
    if (s->count == D2K_HOLD_IDS || v.total > D2K_HOLD_PACKET ||
        (v.flags & ~0x18) || !(v.flags&0x10) || v.ack != s->head.ack) {
        if (s->count == D2K_HOLD_IDS) { h->stats.full++; }
        release_slot(h, s, release, ctx);
        release(ctx, id, p, v.total);
        h->stats.released++;
        return 1;
    }
    size_t k = s->count++;
    s->ids[k] = id; s->len[k] = v.total;
    memcpy(s->packets[k], p, v.total);
    h->stats.pending++;
    const uint8_t *hello;
    size_t hello_len;
    uint32_t hello_seq;
    int rc = d2k_capture_feed(&h->capture, &v.key, s->deadline, now, v.seq,
                              p + v.header, v.payload, &hello, &hello_len, &hello_seq);
    if (rc < 0) { release_slot(h, s, release, ctx); return 1; }
    if (!rc) { return 1; }
    batch->count = s->count;
    memcpy(batch->ids, s->ids, s->count * sizeof s->ids[0]);
    batch->len = s->head.header + hello_len;
    memcpy(batch->packet, s->packets[0], s->head.header);
    memcpy(batch->packet + s->head.header, hello, hello_len);
    batch->packet[2] = (uint8_t)(batch->len >> 8);
    batch->packet[3] = (uint8_t)batch->len;
    /* Sequence/ACK/context remain those of the held first packet. The
       synthetic IPv4/TCP checksums are intentionally not for transmission. */
    h->stats.pending -= s->count;
    h->stats.ready++;
    d2k_capture_forget(&h->capture, &v.key);
    s->count = 0;
    return 2;
}
