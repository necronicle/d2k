/* Bounded ownership of NFQUEUE originals. No socket calls, no search policy.
 * Incomplete measured TCP inputs only; nothing is sent by this module.
 * Caller must release every ID in a READY batch with the final group verdict.
 */
#ifndef D2K_HOLD_H
#define D2K_HOLD_H
#include "d2k_capture.h"
#define D2K_HOLD_SLOTS 16
#define D2K_HOLD_IDS 8
#define D2K_HOLD_PACKET 1600
#define D2K_HOLD_HEADER 120
#define D2K_HOLD_WAIT_NS UINT64_C(100000000)

typedef struct {
    d2k_key key;
    int src_low;
    size_t ihl, header, total, payload;
    uint32_t seq, ack, dst_be;
    uint16_t sport_be;
    uint8_t flags;
} d2k_hold_info;
int d2k_hold_parse(const uint8_t *p, size_t n, d2k_hold_info *v);

typedef struct {
    size_t count;
    uint32_t ids[D2K_HOLD_IDS];
    size_t len;
    /* Synthetic view for session/Plan only. NEVER send this packet itself. */
    uint8_t packet[D2K_HOLD_HEADER + D2K_CAPTURE_BYTES];
} d2k_hold_batch;
typedef void (*d2k_hold_release)(void *ctx, uint32_t id, const uint8_t *p, size_t n);
typedef struct d2k_hold d2k_hold;
d2k_hold *d2k_hold_new(void);
void d2k_hold_free(d2k_hold *h); /* flush ALL first */
/* 0 PASS (caller owns current ID), 1 WAIT/RELEASED (module consumed ID),
 * 2 READY (caller owns exactly batch.ids, including current ID).
 * allow_start is a conservative plan prefilter, NOT execution authority.
 * Existing groups always consume tails even when allow_start is false.
 */
int d2k_hold_feed(d2k_hold *h, uint32_t id, const uint8_t *p, size_t n,
                  uint64_t now, uint64_t revision, int allow_start,
                  d2k_hold_release release, void *ctx, d2k_hold_batch *batch);
/* Release on timeout, revision change or all=1 (loss/shutdown). */
void d2k_hold_flush(d2k_hold *h, uint64_t now, uint64_t revision, int all,
                    d2k_hold_release release, void *ctx);
uint64_t d2k_hold_next(const d2k_hold *h);
/* timed_out_pkts — сколько ПАКЕТОВ лежало в слотах, отпущенных по таймауту.
   Отличает «второй сегмент не дошёл до очереди» (1) от «дошёл, а разбор не
   собрал» (2 и больше). Без этого числа обе причины выглядят одинаково:
   «начато=1 собрано=0 таймаутов=1». */
typedef struct { uint64_t started, ready, released, full, timed_out, timed_out_pkts;
                 size_t pending; } d2k_hold_stats;
void d2k_hold_get_stats(const d2k_hold *h, d2k_hold_stats *out);
/* Try ALL IDs even if one verdict fails. Zero alone acknowledges the
 * logical original group; caller must never report per-ID Plan completion. */
size_t d2k_hold_verdicts(const uint32_t *ids, size_t count, uint32_t verdict,
                        int (*send)(void *, uint32_t, uint32_t), void *ctx);
#endif
