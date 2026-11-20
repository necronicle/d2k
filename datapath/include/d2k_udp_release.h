/* d2k_udp_release.h — bounded delayed verdict ownership for held UDP input. */
#ifndef D2K_UDP_RELEASE_H
#define D2K_UDP_RELEASE_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_track.h"
#include "d2k_udp_hold.h"

typedef struct d2k_udp_release d2k_udp_release;

typedef int (*d2k_udp_release_send)(void *ctx, uint32_t id, uint32_t verdict);
typedef void (*d2k_udp_release_done)(void *ctx, const d2k_key *key,
                                    uint64_t token, int complete, size_t sent);

d2k_udp_release *d2k_udp_release_new(size_t slots, size_t batch_size);
void d2k_udp_release_free(d2k_udp_release *q);

/* Takes ownership of a bounded batch until due_ns.  The caller retains the
 * NFQUEUE IDs when this returns non-zero. */
int d2k_udp_release_enqueue(d2k_udp_release *q, uint64_t due_ns,
                            const uint32_t *ids, const uint32_t *verdicts,
                            size_t count, const d2k_key *key, uint64_t token);

/* Attempts each due batch once, in due/arrival order. Successful IDs are
 * retired; only failed IDs/verdicts remain, retried no earlier than 10ms later.
 * No raw bytes are sent here. A failed slot does not block other due slots,
 * including a final flush at UINT64_MAX. Returns completed batch count; done
 * is called only after every ID succeeds, with cumulative successful count. */
size_t d2k_udp_release_flush(d2k_udp_release *q, uint64_t now_ns,
                             d2k_udp_release_send send, d2k_udp_release_done done,
                             void *ctx);

/* Terminal shutdown only, after the final flush: notify done(complete=0)
 * once per remaining batch, with its cumulative successful verdict count.
 * No verdict or packet is sent. The caller must close NFQUEUE to retire the
 * unresolved kernel IDs. Returns cancelled batch count; call before free. */
size_t d2k_udp_release_cancel(d2k_udp_release *q, d2k_udp_release_done done,
                              void *ctx);

/* Who releases each held original of a held UDP batch (tasks 42, 46).
 *
 * Every datagram after the first one reached conntrack while the head was
 * still queued, so it carries its own unconfirmed entry.  Released to the
 * kernel after the head (or after our raw fakes) it loses the insert and is
 * dropped (insert_failed/drop; router 02.10 and 03.10.2026: 61 of 61
 * increments).  So the tails never go back to the kernel when a raw path
 * exists: they are re-sent byte for byte right after the head, through the
 * entry the head (or the plan) has just confirmed, and their queued copies
 * are dropped.
 *
 * owned != 0: the plan took the head as its own last emit (fate drop): the
 * head's copy is dropped as well.
 * owned == 0: the head gets head_verdict (it is the one datagram whose entry
 * may still win), the tails are re-sent when can_resend.
 * can_resend == 0 (observe mode, no raw socket): old split, tails ACCEPT.
 * Returns how many originals the caller must re-send itself. */
size_t d2k_udp_replay_fates(size_t count, uint32_t head_verdict, int owned,
                            int can_resend, uint32_t *verdicts, uint8_t *resend);

/* Re-sends one original datagram verbatim through the raw path (or queues it
 * behind the plan's deferred emits).  Zero when it left or was queued. */
typedef int (*d2k_udp_resend)(void *ctx, const uint8_t *pkt, size_t len);

/* Releases a held batch in the only order that keeps every datagram: the
 * head's verdict first (nf_reinject confirms its entry inside that call), then
 * for each tail in arrival order its re-send and then the DROP of its queued
 * copy.  A tail whose re-send fails is ACCEPTed instead (fail open, logged by
 * the caller).  Every ID gets exactly one verdict; the head is never re-sent.
 * If the head's own verdict fails on an unowned batch, the head is still in
 * the queue and no entry was confirmed: the tails are not re-sent ahead of it
 * but ACCEPTed (the old behaviour).  An owned head already left as the plan's
 * emit, so its tails still follow it.
 * *verdict_failed is set when any verdict could not be sent; *resend_failed
 * counts tails that fell back to ACCEPT.  Returns the number of tails re-sent. */
size_t d2k_udp_release_batch(const d2k_udp_hold_batch *b, uint32_t head_verdict,
                             int owned, int can_resend,
                             d2k_udp_release_send verdict, d2k_udp_resend resend,
                             void *ctx, int *verdict_failed, size_t *resend_failed);

/* LATE TAILS — ONLY INSIDE THE CLASH WINDOW (task 46, review I2).
 *
 * Datagrams of a released flow that were already queued but not in its batch
 * (the head was ready alone: SNI in the first datagram, 0-RTT, a PTO repeat
 * right behind it) carry the same unconfirmed-entry clash.  Only datagrams
 * that reached conntrack before the head's entry was confirmed can clash:
 *   - every datagram read in the same NFQUEUE receive batch as the head's
 *     release was queued before its verdict (seq match), and
 *   - a datagram read later qualifies only within D2K_UDP_FOLLOW_NS of the
 *     moment the head left (or of the plan's deferred head, at_ns).
 * Field 03.10.2026: clashing tails reached conntrack +0.04..0.2 ms after the
 * head, while the head left ~1 ms after arrival; a 0-RTT at +2.06 ms (after the
 * head's confirm) passed on its own.  5 ms covers that plus the service's own
 * latency in reading the rest of the queue, and stays far below the client's
 * next flight (server RTT 40+ ms), which therefore goes the normal ACCEPT path
 * (its entry is confirmed, its conntrack accounting and routing untouched). */
#define D2K_UDP_FOLLOW_SLOTS 256
#define D2K_UDP_FOLLOW_NS UINT64_C(5000000)

typedef struct d2k_udp_follow d2k_udp_follow;
d2k_udp_follow *d2k_udp_follow_new(void);
void d2k_udp_follow_free(d2k_udp_follow *f);
/* Remembers the head's client tuple: released at now_ns (its own deferred
 * emit at at_ns when later), in receive batch seq.  A full table drops the
 * entry closest to expiry.  Non-zero for a non-UDP packet. */
int d2k_udp_follow_mark(d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                        uint64_t now_ns, uint64_t at_ns, uint64_t seq);
/* One when pkt is a whole (unfragmented) UDP datagram of a marked tuple in the
 * client's direction, read in the head's receive batch or inside the window.
 * seq 0 (D2K_UDP_SEQ_NONE: released with no read to follow) matches by time
 * only.  *at_ns (optional) gets the head's deferred emit time: a late tail is
 * queued behind it even once it is due (review M1, N3). */
int d2k_udp_follow_match(d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                         uint64_t now_ns, uint64_t seq, uint64_t *at_ns);

/* AGING (final review M-5).  An entry past its window and from an earlier
 * receive batch can never match again; matching expires such entries as it
 * scans, and an empty table answers without parsing the datagram at all.
 * d2k_udp_follow_age expires them without a datagram (seq: the next receive
 * batch's number, or 0 to expire only entries released with none). */
void d2k_udp_follow_age(d2k_udp_follow *f, uint64_t now_ns, uint64_t seq);
size_t d2k_udp_follow_live(const d2k_udp_follow *f);

/* A raw re-send refused by a full socket (EAGAIN/EWOULDBLOCK/ENOBUFS: the
 * socket never blocks the packet loop, final review M-3) is transient: that
 * copy is ACCEPTed, the flow keeps its entry, and it is only counted here. */
int d2k_udp_send_busy(int err);
uint64_t d2k_udp_follow_busy(const d2k_udp_follow *f);
/* Deferred re-sends refused because the deferred queue was full (ENOSPC from
 * send_at/send_at_owned): also transient, counted apart from a full socket. */
uint64_t d2k_udp_follow_queue_full(const d2k_udp_follow *f);
/* Flows whose re-send was refused for any other reason (resend_failed is
 * told only for the first D2K_UDP_REFUSED_LOG of them, final review M-7). */
#define D2K_UDP_REFUSED_LOG 16
uint64_t d2k_udp_follow_refused(const d2k_udp_follow *f);

/* THE SERVICE'S UDP OUTPUT, AS ONE TESTABLE PIECE (review M4).
 *
 * d2kd fills it with its NFQUEUE verdict, raw socket and deferred queue;
 * tests fill it with recorders.  can_resend == 0 (observe mode, no raw socket):
 * every datagram goes to the kernel as before. */
typedef struct {
    d2k_udp_release_send verdict;                                   /* (ctx, id, v) */
    int (*send_now)(void *ctx, const uint8_t *pkt, size_t len);      /* raw, now */
    int (*send_at)(void *ctx, uint64_t at_ns, const uint8_t *pkt, size_t len); /* behind deferred emits */
    /* Optional, preferred over send_at (review I-A m-2): queue the datagram
       behind the deferred emits WITH its NFQUEUE ID.  0 — taken: the caller
       gives no verdict, the owner calls d2k_udp_out_owned_emit when it emits
       it; -1 — refused (errno; ENOSPC: the queue is full), the copy is
       ACCEPTed now. */
    int (*send_at_owned)(void *ctx, uint64_t at_ns, const uint8_t *pkt, size_t len,
                         uint32_t id);
    void *ctx;
    d2k_udp_follow *follow;
    int can_resend;
    /* A queued datagram is re-sent raw only when its nfmark is 0 or this
       mark (the controller's own probe mark: no policy routing hangs on it,
       and Task 42 already re-sent its tails).  Any other mark may select a
       policy route (Keenetic 0xffffaaa -> table 4096 / VPN) that a raw send
       with d2k's own mark would bypass: such datagrams go to the kernel as
       before, clash or not (task 46 field round 2). */
    uint32_t neutral_mark;
    /* Optional (task 47): a mark no policy rule selects does not route the
       client either, so it is neutral too.  NULL: only 0 and neutral_mark. */
    int (*routed)(const void *routes, uint8_t ipver, uint32_t mark);
    const void *routes;
    /* Optional: told once per flow when a marked datagram kept the kernel
       path. */
    void (*marked)(void *ctx, const uint8_t *pkt, size_t len, uint32_t mark);
    /* Optional: issue verdict for id at at_ns, after the deferred emits due
       then (d2kd: the delayed-verdict ring, flushed after the scheduler).  A
       marked datagram behind a deferred planned head is ACCEPTed this way so
       it never reaches conntrack before the head (task 46 rereview4 I3). */
    int (*defer_verdict)(void *ctx, uint64_t at_ns, uint32_t id, uint32_t verdict);
    /* Optional: a raw re-send was refused (err = errno).  Told once per flow
       with the refused datagram, for the first D2K_UDP_REFUSED_LOG flows
       only; that flow's later datagrams are not retried and keep the kernel
       path (field 03.10: EACCES, no flow named).  A busy socket
       (d2k_udp_send_busy) is not a refusal: counted, never told. */
    void (*resend_failed)(void *ctx, const uint8_t *pkt, size_t len, int err);
} d2k_udp_out;

/* Releases a batch (d2k_udp_release_batch) with tails sent now when at_ns <=
 * now_ns, else queued at at_ns behind the plan's deferred emits, and marks the
 * flow for late tails.  Returns non-zero when a verdict failed. */
int d2k_udp_out_batch(const d2k_udp_out *o, const d2k_udp_hold_batch *b,
                      uint32_t head_verdict, int owned,
                      uint64_t at_ns, uint64_t now_ns, uint64_t seq);

/* A queued datagram that would otherwise be ACCEPTed: when it is a late tail
 * (d2k_udp_follow_match), re-send it (queued behind a deferred head) and DROP
 * its copy, or ACCEPT it if the re-send fails.  Returns 1 when it issued the
 * verdict (*verdict_failed set on failure), 0 when the caller keeps the ID. */
int d2k_udp_out_late(const d2k_udp_out *o, uint32_t id, const uint8_t *pkt,
                     size_t len, uint32_t mark, uint64_t now_ns, uint64_t seq,
                     int *verdict_failed);

/* The deferred queue emits a datagram it owns (send_at_owned): err 0 — the
 * raw send went out, DROP its copy; otherwise ACCEPT the copy (a busy err is
 * counted).  Exactly one verdict.  Returns -1 when the verdict failed. */
int d2k_udp_out_owned_emit(const d2k_udp_out *o, uint32_t id, int err);

/* 1 when a datagram with this nfmark may be re-sent raw (see neutral_mark). */
int d2k_udp_out_neutral(const d2k_udp_out *o, uint32_t mark, uint8_t ipver);

/* Absolute deadline of the earliest pending batch; zero when empty. */
uint64_t d2k_udp_release_next_ns(const d2k_udp_release *q);

#endif
