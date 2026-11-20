/* postnat_own.c — bounded asynchronous first-packet ownership. See the header.
 * Syscall-free: capture, conntrack queries and plan emission stay in the
 * caller, so every phase and failure path is exercised without a kernel. */
#include <stdlib.h>
#include <string.h>
#include "d2k_postnat_own.h"
#include "d2k_postnat_capture.h"   /* d2k_postnat_udp_tuple / _udp_match */
#include "d2k_packet.h"

/* NAT-invariant identity of a client datagram: the fields SNAT cannot change,
 * used to bind a captured post-NAT packet back to its owned original before a
 * mapping is known. The external source/port the kernel picks is excluded. */
typedef struct {
    uint8_t  family;
    uint8_t  dst[16];        /* server address */
    uint8_t  dport_be[2];    /* server port */
    uint16_t ip_id;          /* IPv4 identification */
    uint32_t flow_label;     /* IPv6 flow label */
    size_t   payload_off, payload_len;
} nat_key;

static int ownkey(const uint8_t *p, size_t n, nat_key *k) {
    d2k_packet_view v;
    if (!d2k_packet_parse(p, n, &v) || v.protocol != 17 || (v.fragment & 0x3fff) ||
        v.total != n || d2k_packet_u16(p + v.l4 + 4) != v.total - v.l4) { return 0; }
    memset(k, 0, sizeof *k);
    k->family = v.family;
    size_t a = v.family == 6 ? 16 : 4;
    memcpy(k->dst, v.dst.bytes, a);
    memcpy(k->dport_be, p + v.l4 + 2, 2);
    k->ip_id = v.ip_id;
    k->flow_label = v.flow_label;
    k->payload_off = v.l4 + 8;
    k->payload_len = v.total - v.l4 - 8;
    return 1;
}

/* Same client datagram, pre- and post-NAT: server endpoint, the kernel-stable
 * IPv4 id / IPv6 flow label, and the application payload are all unchanged. */
static int key_same(const nat_key *a, const uint8_t *ap, const nat_key *b, const uint8_t *bp) {
    return a->family == b->family && !memcmp(a->dst, b->dst, 16) &&
        !memcmp(a->dport_be, b->dport_be, 2) &&
        (a->family == 4 ? a->ip_id == b->ip_id : a->flow_label == b->flow_label) &&
        a->payload_len == b->payload_len &&
        !memcmp(ap + a->payload_off, bp + b->payload_off, a->payload_len);
}

typedef struct {
    int           used;
    int           abandoned;
    uint8_t      *orig;    size_t olen;    /* owned client original */
    uint8_t      *cap;     size_t clen;    /* retained post-NAT packet, or NULL */
    nat_key       key;                     /* of the original */
    d2k_ct_tuple  tuple;                   /* original 5-tuple, for the mapping query */
    d2k_postnat_identity id;
    int64_t       deadline_ns;
} own_slot;

struct d2k_postnat_own {
    own_slot *slots;
    size_t    n, used, max_len;
};

d2k_postnat_own *d2k_postnat_own_new(size_t slots, size_t max_len) {
    if (!slots || !max_len || max_len > 65575 || slots > (size_t)1 << 20) { return NULL; }
    d2k_postnat_own *o = calloc(1, sizeof *o);
    if (!o) { return NULL; }
    o->slots = calloc(slots, sizeof *o->slots);
    if (!o->slots) { free(o); return NULL; }
    o->n = slots; o->max_len = max_len;
    return o;
}

void d2k_postnat_own_free(d2k_postnat_own *o) {
    if (!o) { return; }
    for (size_t i = 0; i < o->n; i++) { free(o->slots[i].orig); free(o->slots[i].cap); }
    free(o->slots);
    free(o);
}

static int tuple_eq(const d2k_ct_tuple *a, const d2k_ct_tuple *b) {
    return a->family == b->family && a->proto == b->proto &&
        !memcmp(a->src, b->src, 16) && !memcmp(a->dst, b->dst, 16) &&
        !memcmp(a->sport_be, b->sport_be, 2) && !memcmp(a->dport_be, b->dport_be, 2);
}

static void drop(d2k_postnat_own *o, own_slot *s) {
    free(s->orig); free(s->cap);
    memset(s, 0, sizeof *s);
    o->used--;
}

int d2k_postnat_own_begin(d2k_postnat_own *o, const uint8_t *packet, size_t len,
                          const d2k_postnat_identity *id, int64_t deadline_ns) {
    if (!o || !packet || !id || !len) { return -1; }
    if (len > o->max_len) { return 0; }
    nat_key k;
    d2k_ct_tuple t;
    if (!ownkey(packet, len, &k) || !d2k_postnat_udp_tuple(packet, len, &t)) { return 0; }
    own_slot *free_slot = NULL;
    for (size_t i = 0; i < o->n; i++) {
        own_slot *s = &o->slots[i];
        if (!s->used) { if (!free_slot) { free_slot = s; } continue; }
        /* One owner per original flow: a retransmit of the same first datagram
           must not queue a second entry or a duplicate original. */
        if (tuple_eq(&s->tuple, &t) || key_same(&s->key,s->orig,&k,packet)) { return 0; }
    }
    if (!free_slot) { return 0; }
    uint8_t *copy = malloc(len);
    if (!copy) { return 0; }
    uint8_t *capture = malloc(o->max_len);
    if (!capture) { free(copy); return 0; }
    memcpy(copy, packet, len);
    free_slot->used = 1;
    free_slot->orig = copy; free_slot->olen = len;
    free_slot->cap = capture; free_slot->clen = 0;
    free_slot->key = k;
    free_slot->tuple = t;
    free_slot->id = *id;
    free_slot->deadline_ns = deadline_ns;
    o->used++;
    return 1;
}

int d2k_postnat_own_captured(d2k_postnat_own *o, const uint8_t *captured, size_t clen) {
    if (!o || !captured || !clen) { return -1; }
    if (clen > o->max_len) { return 0; }
    nat_key ck;
    if (!ownkey(captured, clen, &ck)) { return 0; }
    for (size_t i = 0; i < o->n; i++) {
        own_slot *s = &o->slots[i];
        if (!s->used || s->clen) { continue; }   /* only a waiting owner takes it */
        if (!key_same(&s->key, s->orig, &ck, captured)) { continue; }
        memcpy(s->cap, captured, clen);
        s->clen = clen;
        return 1;
    }
    return 0;
}

size_t d2k_postnat_own_resolve(d2k_postnat_own *o, d2k_postnat_query_fn query, void *qctx,
                               d2k_postnat_emit_fn emit, void *ectx) {
    if (!o || !query || !emit) { return 0; }
    size_t done = 0;
    for (size_t i = 0; i < o->n; i++) {
        own_slot *s = &o->slots[i];
        if (!s->used || s->abandoned || !s->clen) { continue; }
        d2k_ct_info map;
        memset(&map, 0, sizeof map);
        if (query(qctx, &s->tuple, &map) <= 0 || !map.reply_tuple_known) { continue; }
        if (!d2k_postnat_udp_match(s->orig, s->olen, s->cap, s->clen, &map)) { continue; }
        if (emit(ectx, s->orig, s->olen, s->cap, s->clen, &map, &s->id) != 1) continue;
        drop(o, s);
        done++;
    }
    return done;
}

static size_t sweep(d2k_postnat_own *o, d2k_postnat_keep_fn keep, void *kctx, int64_t now_ns,
                    int by_time, d2k_postnat_fallback_fn fb, void *fctx) {
    size_t gone = 0;
    for (size_t i = 0; i < o->n; i++) {
        own_slot *s = &o->slots[i];
        if (!s->used) { continue; }
        if (!s->abandoned &&
            (by_time ? s->deadline_ns > now_ns : (keep && keep(kctx, &s->id)))) { continue; }
        s->abandoned = 1;
        if (!fb || fb(fctx, s->orig, s->olen, s->clen ? s->cap : NULL, s->clen, &s->id) != 1) continue;
        drop(o, s);
        gone++;
    }
    return gone;
}

size_t d2k_postnat_own_expire(d2k_postnat_own *o, int64_t now_ns,
                              d2k_postnat_fallback_fn fb, void *fctx) {
    return o ? sweep(o, NULL, NULL, now_ns, 1, fb, fctx) : 0;
}

size_t d2k_postnat_own_clear(d2k_postnat_own *o, d2k_postnat_keep_fn keep, void *kctx,
                             d2k_postnat_fallback_fn fb, void *fctx) {
    return o ? sweep(o, keep, kctx, 0, 0, fb, fctx) : 0;
}

size_t d2k_postnat_own_pending(const d2k_postnat_own *o) { return o ? o->used : 0; }

int d2k_postnat_own_cancel(d2k_postnat_own *o, const uint8_t *p, size_t n) {
    d2k_ct_tuple t;
    if (!o || !d2k_postnat_udp_tuple(p, n, &t)) return 0;
    for (size_t i = 0; i < o->n; i++) {
        own_slot *s = &o->slots[i];
        if (s->used && !s->clen && tuple_eq(&s->tuple, &t)) { drop(o, s); return 1; }
    }
    return 0;
}
