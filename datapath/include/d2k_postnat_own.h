#ifndef D2K_POSTNAT_OWN_H
#define D2K_POSTNAT_OWN_H
#include <stddef.h>
#include <stdint.h>
#include "d2k_ctq.h"
#include "d2k_track.h"
#include "d2k_plans.h"

/* Asynchronous first-packet ownership (task 63).
 *
 * A fresh UDP flow with a fragment plan cannot be fragmented on its first
 * original: the kernel has not confirmed the conntrack/NAT entry until the
 * held datagram is released, so the external mapping is unknown and a guessed
 * one is forbidden. An app that sends only once never retries, so the plan
 * never applies. The daemon instead OWNS that first datagram: it tags it so
 * egress redirects it into the capture device (stolen, never delivered — no
 * duplicate original), reads it back post-NAT, and once the kernel mapping is
 * confirmed emits the still-owned plan on that same datagram.
 *
 * This table is the bounded, syscall-free state of that flow, in three phases:
 *   begin    — the original is owned and tagged for capture (awaiting capture);
 *   captured — the post-NAT packet came back from the TAP and is RETAINED
 *              (the steal happens once and never recurs, so a packet read
 *              before its mapping is confirmed must not be discarded);
 *   resolve  — the kernel mapping is now confirmed and exactly matches, so the
 *              plan is emitted on the original with that mapping.
 *
 * Every owned datagram leaves the wire exactly once and in exactly one way:
 *   - resolve -> emit: the plan is executed (fragments from the external tuple);
 *   - expire / clear -> fallback: after confirmed capture, re-inject the
 *                       original through ordinary conntrack/NAT. Reinjecting
 *                       captured external bytes can allocate a different port.
 *                       Before capture nothing may safely be re-injected.
 * Never emitted and re-injected both; never duplicated. The capture/mark
 * machinery, conntrack query and raw emission live in the caller.
 *
 * Capture binding is by NAT-invariant fields. A second original that cannot
 * be distinguished from a pending one before conntrack replies is rejected by
 * begin and must pass unchanged, without a capture mark. The mapping still
 * has to match exactly before emit can take ownership.
 */

/* Binds pending work to one plan execution. A plan hash alone is not enough:
 * a replaced or deleted plan of the same shape, or a stale binding generation,
 * must not adopt another flow's owned datagram. */
typedef struct {
    uint64_t generation;   /* runtime binding generation */
    uint8_t  epoch[16];    /* plan-table epoch */
    uint8_t  trial[16];    /* experiment/trial identity */
    d2k_binding_context binding;
    d2k_key key;
    uint8_t plan_id[16], flow_epoch[16];
    uint64_t incarnation;
    uint32_t owner_slot; /* caller-owned bounded sidecar */
} d2k_postnat_identity;

typedef struct d2k_postnat_own d2k_postnat_own;

/* Callbacks must not re-enter this table. */
typedef int  (*d2k_postnat_query_fn)(void *ctx, const d2k_ct_tuple *original_tuple,
                                     d2k_ct_info *out);
/* Return 1 only after taking responsibility for completion (including a
 * partially sent failed plan). Return 0 only if nothing was emitted or queued;
 * the table retains both packets for retry or unchanged fallback. Pointers
 * are borrowed for this call; an asynchronous sender must copy its inputs. */
typedef int (*d2k_postnat_emit_fn)(void *ctx, const uint8_t *original, size_t olen,
    const uint8_t *captured, size_t clen,
    const d2k_ct_info *mapping, const d2k_postnat_identity *id);
/* captured==NULL / clen==0: the entry was abandoned before its post-NAT packet
 * was captured, so nothing can be safely re-injected (rare; the caller logs).
 * Return 1 after taking ownership, 0 to retain for a later release attempt.
 * An unavailable sender must not discard the only captured copy. */
typedef int (*d2k_postnat_fallback_fn)(void *ctx,
    const uint8_t *original, size_t olen, const uint8_t *captured, size_t clen,
    const d2k_postnat_identity *id);
typedef int  (*d2k_postnat_keep_fn)(void *ctx, const d2k_postnat_identity *id);

/* Bounded: at most `slots` concurrent owned datagrams; `max_len` caps one
 * stored packet (at most 65575 bytes). NULL on bad args or allocation failure. */
d2k_postnat_own *d2k_postnat_own_new(size_t slots, size_t max_len);
void d2k_postnat_own_free(d2k_postnat_own *);

/* Begin owning one first datagram (a well-formed unfragmented UDP packet,
 * validated here). The original is copied. Returns:
 *   1  queued; the caller tags and accepts it so egress steals it into capture.
 *   0  not owned (queue full, already pending for this exact tuple, or not an
 *      ownable UDP datagram): the caller releases it unchanged — today's
 *      behaviour; nothing is held, nothing leaks.
 *  -1 invalid arguments. */
int d2k_postnat_own_begin(d2k_postnat_own *, const uint8_t *original, size_t len,
                          const d2k_postnat_identity *id, int64_t deadline_ns);

/* A post-NAT packet came back from the capture device. Bind it to its waiting
 * owned entry by the NAT-invariant fields (family, server address/port, IPv4
 * identification or IPv6 flow label, and the exact payload) and RETAIN a copy;
 * the external source the kernel chose is not needed yet. Returns 1 bound,
 * 0 no waiting owner (the caller drops it — it was stolen from egress and must
 * not be re-injected blindly), -1 on bad args. A second capture for an entry
 * already holding one is ignored (returns 0). */
int d2k_postnat_own_captured(d2k_postnat_own *, const uint8_t *captured, size_t clen);

/* For every entry that has its captured packet, query the kernel mapping (by
 * the original tuple) and, when the reply tuple is confirmed AND exactly
 * matches, emit the plan on the original and consume the entry. A query that
 * reports no confirmed mapping yet leaves the entry RETAINED for a later call
 * (missing reply is not proof of absence). Returns how many were emitted. */
size_t d2k_postnat_own_resolve(d2k_postnat_own *, d2k_postnat_query_fn query, void *qctx,
                               d2k_postnat_emit_fn emit, void *ectx);

/* Abandon entries past their deadline; each is handed to `fallback` (retained
 * original and post-NAT bytes, or captured=NULL if never captured). Only an
 * acknowledged fallback consumes the entry; otherwise it remains pending.
 * Once abandoned, it cannot execute a plan even if the mapping later arrives.
 * Returns how many were abandoned. */
size_t d2k_postnat_own_expire(d2k_postnat_own *, int64_t now_ns,
                              d2k_postnat_fallback_fn fallback, void *fctx);

/* Plan replacement/deletion, generation change or shutdown: abandon every
 * entry for which keep(id) is false (keep==NULL abandons all), each via
 * `fallback`. Returns the count accepted by fallback; a busy sender retains
 * ownership for retry. Without a fallback callback nothing is consumed. */
size_t d2k_postnat_own_clear(d2k_postnat_own *, d2k_postnat_keep_fn keep, void *kctx,
                             d2k_postnat_fallback_fn fallback, void *fctx);

/* Cancel ONLY when the marked verdict was not sent; kernel still owns it. */
int d2k_postnat_own_cancel(d2k_postnat_own *, const uint8_t *, size_t);
size_t d2k_postnat_own_pending(const d2k_postnat_own *);
#endif
