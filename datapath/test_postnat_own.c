/* test_postnat_own.c — asynchronous first-packet ownership (task 63).
 * No kernel: captures and conntrack mappings are injected, so the own ->
 * captured (retained) -> resolve phases, timeout, plan replacement/deletion,
 * shutdown, the one-shot original and the "mapping not ready at capture time"
 * path are all exercised deterministically. */
#include <stdio.h>
#include <string.h>
#include "d2k_postnat_own.h"
#include "d2k_postnat_capture.h"
#include "d2k_packet.h"

static int fails;
#define CHECK(c) do { if(!(c)){fprintf(stderr,"postnat-own:%d: %s\n",__LINE__,#c);fails++;} } while(0)

#define SP_BASE 50000
#define EXT_ADDR 0x0a000002u
#define EBASE 51000

static size_t udp4(uint8_t *p, uint32_t src, uint32_t dst, uint16_t sport,
                   uint16_t dport, uint16_t ipid, size_t plen) {
    size_t tot = 28 + plen;
    memset(p, 0, tot);
    p[0] = 0x45; p[2] = (uint8_t)(tot >> 8); p[3] = (uint8_t)tot;
    p[4] = (uint8_t)(ipid >> 8); p[5] = (uint8_t)ipid;
    p[8] = 64; p[9] = 17;
    p[12] = (uint8_t)(src >> 24); p[13] = (uint8_t)(src >> 16); p[14] = (uint8_t)(src >> 8); p[15] = (uint8_t)src;
    p[16] = (uint8_t)(dst >> 24); p[17] = (uint8_t)(dst >> 16); p[18] = (uint8_t)(dst >> 8); p[19] = (uint8_t)dst;
    p[20] = (uint8_t)(sport >> 8); p[21] = (uint8_t)sport;
    p[22] = (uint8_t)(dport >> 8); p[23] = (uint8_t)dport;
    size_t ul = 8 + plen; p[24] = (uint8_t)(ul >> 8); p[25] = (uint8_t)ul;
    for (size_t i = 0; i < plen; i++) { p[28 + i] = (uint8_t)('A' + (i & 31)); }
    return tot;
}

static void reply_tuple(d2k_ct_tuple *r, uint32_t dst, uint16_t dport,
                        uint32_t ext, uint16_t eport) {
    memset(r, 0, sizeof *r);
    r->family = 4; r->proto = 17;
    r->src[0] = (uint8_t)(dst >> 24); r->src[1] = (uint8_t)(dst >> 16); r->src[2] = (uint8_t)(dst >> 8); r->src[3] = (uint8_t)dst;
    r->dst[0] = (uint8_t)(ext >> 24); r->dst[1] = (uint8_t)(ext >> 16); r->dst[2] = (uint8_t)(ext >> 8); r->dst[3] = (uint8_t)ext;
    r->sport_be[0] = (uint8_t)(dport >> 8); r->sport_be[1] = (uint8_t)dport;
    r->dport_be[0] = (uint8_t)(eport >> 8); r->dport_be[1] = (uint8_t)eport;
}

/* Tuple-keyed fake conntrack query: each client source port maps to its own
   external port, exactly as a real SNAT allocates. */
typedef struct { int available; int calls; } fake_ct;
static int q(void *ctx, const d2k_ct_tuple *orig, d2k_ct_info *out) {
    fake_ct *f = ctx; f->calls++;
    if (!f->available) { return 0; }
    uint16_t sport = (uint16_t)((orig->sport_be[0] << 8) | orig->sport_be[1]);
    uint16_t dport = (uint16_t)((orig->dport_be[0] << 8) | orig->dport_be[1]);
    uint32_t dst = ((uint32_t)orig->dst[0] << 24) | ((uint32_t)orig->dst[1] << 16) |
                   ((uint32_t)orig->dst[2] << 8) | orig->dst[3];
    reply_tuple(&out->reply_tuple, dst, dport, EXT_ADDR, (uint16_t)(EBASE + (sport - SP_BASE)));
    out->reply_tuple_known = 1;
    return 1;
}

typedef struct { int n; uint8_t last[2048]; size_t last_len; uint64_t last_gen; const d2k_ct_info *map; } emitlog;
static d2k_ct_info emit_map;
static d2k_postnat_identity emit_identity;
static int emitted(void *ctx, const uint8_t *o, size_t len, const uint8_t *captured, size_t clen, const d2k_ct_info *map,
                    const d2k_postnat_identity *id) {
    emitlog *e = ctx; e->n++;
    e->last_len = len > sizeof e->last ? sizeof e->last : len;
    memcpy(e->last, o, e->last_len); e->last_gen = id->generation;
    CHECK(captured && clen && d2k_postnat_udp_match(o,len,captured,clen,map));
    emit_map = *map; emit_identity = *id;
    if (id->generation == 1) {
    CHECK(emit_identity.binding.generation == 73 && emit_identity.binding.kind == D2K_BIND_FLOW);
    CHECK(emit_identity.binding.epoch[3] == 91 && emit_identity.key.proto == 17);
    CHECK(emit_identity.plan_id[7] == 93 && emit_identity.flow_epoch[9] == 94 && emit_identity.incarnation == 95);
    }
    return 1;
}
static int busy(void *ctx,const uint8_t *p,size_t n,const uint8_t *cap,size_t cn,
                const d2k_ct_info *map,const d2k_postnat_identity *id) {
    (void)id;(*(int *)ctx)++;
    CHECK(d2k_postnat_udp_match(p,n,cap,cn,map));
    return 0;
}
typedef struct { int n; uint8_t last[2048]; size_t last_len; int null_bytes; uint64_t last_gen; } fblog;
static int fellback(void *ctx, const uint8_t *orig, size_t olen, const uint8_t *cap, size_t len, const d2k_postnat_identity *id) {
    CHECK(orig && olen);
    fblog *f = ctx; f->n++; f->last_gen = id->generation;
    if (!cap || !len) { f->null_bytes++; f->last_len = 0; return 1; }
    f->last_len = len > sizeof f->last ? sizeof f->last : len;
    memcpy(f->last, cap, f->last_len);
    return 1;
}
static int fallback_busy(void *ctx,const uint8_t *orig,size_t olen,const uint8_t *p,size_t n,const d2k_postnat_identity *id) {
    (void)ctx;(void)id;CHECK(orig && olen && p && n);return 0;
}
static int keep_gen1(void *ctx, const d2k_postnat_identity *id) { (void)ctx; return id->generation == 1; }

int main(void) {
    const uint32_t CLI = 0x0a000001, SRV = 0x5db31ea0;
    const uint16_t SP = SP_BASE, DP = 443, IPID = 0x1234;
    d2k_postnat_identity id = {.generation=1,.epoch={7},.trial={9}};

    uint8_t orig[2048], cap[2048];
    size_t on = udp4(orig, CLI, SRV, SP, DP, IPID, 100);
    size_t cn = udp4(cap, EXT_ADDR, SRV, EBASE, DP, IPID, 100);     /* post-NAT: src -> EXT:EBASE */

    fake_ct f = {0};
    d2k_postnat_own *o = d2k_postnat_own_new(2, 2048);
    CHECK(o != NULL);

    /* --- begin: ownable, bounded, deduplicated ----------------------------- */
    id.binding.generation = 73; id.binding.kind = D2K_BIND_FLOW;
    id.binding.epoch[3] = 91; id.key.proto = 17;
    id.plan_id[7] = 93; id.flow_epoch[9] = 94; id.incarnation = 95;
    CHECK(d2k_postnat_own_begin(o, orig, on, &id, 1000) == 1);
    CHECK(d2k_postnat_own_cancel(o, orig, on) == 1);
    CHECK(d2k_postnat_own_pending(o) == 0);
    CHECK(d2k_postnat_own_begin(o, orig, on, &id, 1000) == 1);
    CHECK(d2k_postnat_own_begin(o, orig, on, &id, 1000) == 0);          /* dup flow */
    uint8_t ambiguous[2048];
    size_t an=udp4(ambiguous,CLI,SRV,(uint16_t)(SP+7),DP,IPID,100);
    CHECK(d2k_postnat_own_begin(o,ambiguous,an,&id,1000)==0);
    uint8_t o2[2048]; size_t o2n = udp4(o2, CLI, SRV, (uint16_t)(SP + 1), DP, (uint16_t)(IPID + 1), 100);
    CHECK(d2k_postnat_own_begin(o, o2, o2n, &id, 1000) == 1);
    uint8_t o3[2048]; size_t o3n = udp4(o3, CLI, SRV, (uint16_t)(SP + 2), DP, (uint16_t)(IPID + 2), 100);
    CHECK(d2k_postnat_own_begin(o, o3, o3n, &id, 1000) == 0);           /* bounded */
    uint8_t bad[28]; memset(bad, 0, sizeof bad); bad[0] = 0x45; bad[3] = 28; bad[9] = 6;
    CHECK(d2k_postnat_own_begin(o, bad, 28, &id, 1000) == 0);           /* not UDP */
    CHECK(d2k_postnat_own_begin(o, orig, on, NULL, 1000) == -1);
    CHECK(d2k_postnat_own_pending(o) == 2);

    /* --- resolve before capture does nothing: no packet to send yet -------- */
    f.available = 1;
    emitlog e = {0};
    CHECK(d2k_postnat_own_resolve(o, q, &f, emitted, &e) == 0 && e.n == 0);

    /* --- capture binds the post-NAT packet by NAT-invariant fields --------- */
    CHECK(d2k_postnat_own_captured(o, cap, cn) == 1);
    /* A second capture for the same owned flow is ignored (already retained). */
    CHECK(d2k_postnat_own_captured(o, cap, cn) == 0);
    /* A captured packet for no owned flow is dropped (different server port). */
    uint8_t stray[2048]; size_t sn = udp4(stray, EXT_ADDR, SRV, EBASE, (uint16_t)(DP + 7), IPID, 100);
    CHECK(d2k_postnat_own_captured(o, stray, sn) == 0);

    /* --- mapping not ready at capture time: entry is RETAINED, not lost ---- */
    f.available = 0;
    CHECK(d2k_postnat_own_resolve(o, q, &f, emitted, &e) == 0 && e.n == 0);
    CHECK(d2k_postnat_own_pending(o) == 2);         /* still held, awaiting mapping */

    /* --- mapping confirmed: emit the plan on the SAME original, once ------- */
    f.available = 1;
    int busy_calls=0;
    CHECK(d2k_postnat_own_resolve(o,q,&f,busy,&busy_calls)==0);
    CHECK(busy_calls==1 && d2k_postnat_own_pending(o)==2);
    CHECK(d2k_postnat_own_resolve(o, q, &f, emitted, &e) == 1);
    CHECK(e.n == 1 && e.last_len == on && !memcmp(e.last, orig, on));
    CHECK(e.last_gen == 1 && emit_map.reply_tuple_known);
    CHECK(emit_map.reply_tuple.dport_be[0] == (uint8_t)(EBASE >> 8) &&
          emit_map.reply_tuple.dport_be[1] == (uint8_t)EBASE);        /* external port in the map */
    CHECK(d2k_postnat_own_pending(o) == 1);         /* only o2 remains, uncaptured */
    CHECK(d2k_postnat_own_resolve(o, q, &f, emitted, &e) == 0 && e.n == 1);  /* exactly once */

    /* --- timeout before capture: fallback has no bytes to re-inject -------- */
    fblog fb = {0};
    CHECK(d2k_postnat_own_expire(o, 500, fellback, &fb) == 0);         /* not due */
    CHECK(d2k_postnat_own_expire(o, 1000, fellback, &fb) == 1);        /* o2, never captured */
    CHECK(fb.n == 1 && fb.null_bytes == 1 && fb.last_gen == 1);
    CHECK(d2k_postnat_own_pending(o) == 0);
    d2k_postnat_own_free(o);

    /* --- timeout after capture: fallback re-injects the post-NAT bytes ----- */
    o = d2k_postnat_own_new(2, 2048);
    CHECK(d2k_postnat_own_begin(o, orig, on, &id, 2000) == 1);
    CHECK(d2k_postnat_own_captured(o, cap, cn) == 1);
    f.available = 0;   /* mapping never confirms within the window */
    CHECK(d2k_postnat_own_resolve(o, q, &f, emitted, &e) == 0);
    fblog fb2 = {0};
    CHECK(d2k_postnat_own_expire(o,2000,fallback_busy,NULL)==0);
    CHECK(d2k_postnat_own_pending(o)==1);
    f.available=1;
    int before_expired=e.n;
    CHECK(d2k_postnat_own_resolve(o,q,&f,emitted,&e)==0);
    CHECK(e.n==before_expired && d2k_postnat_own_pending(o)==1);
    CHECK(d2k_postnat_own_clear(o,NULL,NULL,fallback_busy,NULL)==0);
    CHECK(d2k_postnat_own_pending(o)==1);
    CHECK(d2k_postnat_own_expire(o, 2000, fellback, &fb2) == 1);
    CHECK(fb2.n == 1 && fb2.null_bytes == 0 && fb2.last_len == cn && !memcmp(fb2.last, cap, cn));
    /* Consumed exactly once: nothing left to resolve or expire. */
    CHECK(d2k_postnat_own_resolve(o, q, &f, emitted, &e) == 0);
    CHECK(d2k_postnat_own_expire(o, 1 << 30, fellback, &fb2) == 0 && fb2.n == 1);
    d2k_postnat_own_free(o);

    /* --- clear: plan replacement/deletion drops non-matching identities ---- */
    o = d2k_postnat_own_new(4, 2048);
    d2k_postnat_identity g2 = {.generation=2,.epoch={7},.trial={9}};
    CHECK(d2k_postnat_own_begin(o, orig, on, &id, 10000) == 1);        /* gen 1 */
    CHECK(d2k_postnat_own_captured(o, cap, cn) == 1);
    CHECK(d2k_postnat_own_begin(o, o2, o2n, &g2, 10000) == 1);         /* gen 2 */
    fblog fb3 = {0};
    CHECK(d2k_postnat_own_clear(o, keep_gen1, NULL, fellback, &fb3) == 1);
    CHECK(fb3.n == 1 && fb3.last_gen == 2 && fb3.null_bytes == 1);     /* gen 2 never captured */
    CHECK(d2k_postnat_own_pending(o) == 1);
    /* Shutdown: keep==NULL re-injects everything still held (gen 1, captured). */
    fblog fb4 = {0};
    CHECK(d2k_postnat_own_clear(o, NULL, NULL, fellback, &fb4) == 1);
    CHECK(fb4.n == 1 && fb4.last_gen == 1 && fb4.null_bytes == 0 && fb4.last_len == cn);
    CHECK(d2k_postnat_own_pending(o) == 0);
    d2k_postnat_own_free(o);

    /* An invalidated binding must not revive while fallback is busy. */
    o=d2k_postnat_own_new(1,2048);
    CHECK(d2k_postnat_own_begin(o,orig,on,&id,10000)==1);
    CHECK(d2k_postnat_own_captured(o,cap,cn)==1);
    CHECK(d2k_postnat_own_clear(o,NULL,NULL,fallback_busy,NULL)==0);
    int before_cancel=e.n;
    CHECK(d2k_postnat_own_resolve(o,q,&f,emitted,&e)==0);
    CHECK(e.n==before_cancel && d2k_postnat_own_pending(o)==1);
    fblog cancelled={0};
    CHECK(d2k_postnat_own_clear(o,keep_gen1,NULL,fellback,&cancelled)==1);
    CHECK(cancelled.n==1 && d2k_postnat_own_pending(o)==0);
    d2k_postnat_own_free(o);

    if (fails) { printf("test_postnat_own: %d failure(s)\n", fails); return 1; }
    puts("test_postnat_own: all checks passed");
    return 0;
}
