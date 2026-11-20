#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_udp_release.h"
#include "d2k_nl.h"

static int fails;
#define CHECK(x, m) do { if (!(x)) { fprintf(stderr, "udp_release:%d: %s\n", __LINE__, m); fails++; } } while (0)

static uint32_t seen_ids[8], seen_verdicts[8];
static size_t seen;
static uint64_t done_token;
static int done_complete;
static size_t done_calls;
static size_t done_sent;
static uint64_t done_tokens[4];
static int done_completes[4];
static size_t done_sent_counts[4];
static uint32_t fail_id;
static int fail_once, fail_always;

static int send_one(void *ctx, uint32_t id, uint32_t verdict) {
    (void)ctx;
    if (seen < sizeof seen_ids / sizeof seen_ids[0]) {
        seen_ids[seen] = id;
        seen_verdicts[seen] = verdict;
    }
    seen++;
    if (id == fail_id && (fail_once || fail_always)) {
        fail_once = 0;
        return -1;
    }
    return 0;
}

static void note_done(void *ctx, const d2k_key *key, uint64_t token,
                      int complete, size_t sent) {
    (void)ctx;
    CHECK(key && key->proto == 17 && key->low_ip == 1 && key->high_ip == 2 &&
          key->low_port == 3 && key->high_port == 4, "execution key lost");
    CHECK(sent == (complete ? 2u : sent), "sent count inconsistent");
    done_token = token;
    done_complete = complete;
    done_calls++;
    done_sent = sent;
    if (done_calls <= 4) {
        done_tokens[done_calls - 1] = token;
        done_completes[done_calls - 1] = complete;
        done_sent_counts[done_calls - 1] = sent;
    }
}

/* Задача 46: журнал вызовов выпуска пачки — вердикты ('v') и посылки ('s'). */
static char log_kind[32];
static uint32_t log_id[32], log_v[32];
static size_t log_len[32];
static uint8_t log_byte[32];
static size_t log_n;
static size_t resend_fail_at;
static uint32_t verdict_fail_id;

static int log_verdict(void *ctx, uint32_t id, uint32_t verdict) {
    (void)ctx;
    if (log_n < 32) { log_kind[log_n] = 'v'; log_id[log_n] = id; log_v[log_n] = verdict; }
    log_n++;
    return id == verdict_fail_id ? -1 : 0;
}

static int log_resend(void *ctx, const uint8_t *p, size_t n) {
    (void)ctx;
    if (log_n < 32) { log_kind[log_n] = 's'; log_len[log_n] = n; log_byte[log_n] = n ? p[0] : 0; }
    log_n++;
    size_t sends = 0;
    for (size_t i = 0; i < log_n && i < 32; i++) sends += log_kind[i] == 's';
    return (resend_fail_at && sends == resend_fail_at) ? -1 : 0;
}

static void build_udp4(uint8_t *p, uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport) {
    memset(p, 0, 40);
    p[0] = 0x45; p[2] = 0; p[3] = 40; p[8] = 64; p[9] = 17;
    p[12] = (uint8_t)(src >> 24); p[13] = (uint8_t)(src >> 16); p[14] = (uint8_t)(src >> 8); p[15] = (uint8_t)src;
    p[16] = (uint8_t)(dst >> 24); p[17] = (uint8_t)(dst >> 16); p[18] = (uint8_t)(dst >> 8); p[19] = (uint8_t)dst;
    p[20] = (uint8_t)(sport >> 8); p[21] = (uint8_t)sport;
    p[22] = (uint8_t)(dport >> 8); p[23] = (uint8_t)dport;
    p[24] = 0; p[25] = 20;
}

int main(void) {
    d2k_udp_release *q = d2k_udp_release_new(2, 4);
    uint32_t ids[] = {11, 12};
    uint32_t verdicts[] = {1, 0};
    d2k_key key = {.low_ip=1, .high_ip=2, .low_port=3, .high_port=4, .proto=17};
    CHECK(q != NULL, "allocation");
    CHECK(d2k_udp_release_enqueue(q, 100, ids, verdicts, 2, &key, 77) == 0,
          "delayed original batch accepted");
    CHECK(d2k_udp_release_next_ns(q) == 100,
          "next due time was not exposed");
    CHECK(d2k_udp_release_flush(q, 99, send_one, note_done, NULL) == 0,
          "batch released before its due time");
    CHECK(seen == 0, "early release escaped");
    CHECK(d2k_udp_release_next_ns(q) == 100,
          "early flush lost the pending due time");
    CHECK(d2k_udp_release_flush(q, 100, send_one, note_done, NULL) == 1,
          "due batch not released");
    CHECK(seen == 2 && seen_ids[0] == 11 && seen_ids[1] == 12,
          "original verdicts lost FIFO order");
    CHECK(seen_verdicts[0] == 1 && seen_verdicts[1] == 0,
          "original verdicts changed during release");
    CHECK(done_token == 77 && done_complete, "execution completion not reported");
    CHECK(d2k_udp_release_next_ns(q) == 0,
          "empty release queue still reports a deadline");

    seen = 0;
    done_calls = 0;
    fail_id = 12;
    fail_once = 1;
    CHECK(d2k_udp_release_enqueue(q, 200, ids, verdicts, 2, &key, 78) == 0,
          "second batch accepted");
    uint32_t other_ids[] = {21, 22};
    CHECK(d2k_udp_release_enqueue(q, 200, other_ids, verdicts, 2, &key, 79) == 0,
          "third batch accepted while capacity remains");
    CHECK(d2k_udp_release_flush(q, 200, send_one, note_done, NULL) == 1,
          "failed batch must stay owned, healthy batch must complete without HOL blocking");
    CHECK(done_calls == 1 && done_tokens[0] == 79 && done_completes[0] &&
          done_sent_counts[0] == 2,
          "partial send must not report completion before all IDs are retired");
    CHECK(seen == 4 && seen_ids[0] == 11 && seen_ids[1] == 12 &&
          seen_ids[2] == 21 && seen_ids[3] == 22,
          "a failed ID must not block other slots or be retried in the same flush");
    uint64_t retry = UINT64_C(10000000) + 200;
    CHECK(d2k_udp_release_next_ns(q) == retry, "failed verdict retry must be paced at 10ms");
    CHECK(d2k_udp_release_flush(q, retry - 1, send_one, note_done, NULL) == 0 && seen == 4,
          "retry before deadline would spin on a busy NFQUEUE socket");
    fail_id = 0;
    CHECK(d2k_udp_release_flush(q, retry, send_one, note_done, NULL) == 1,
          "failed NFQUEUE ID was forgotten instead of retried");
    CHECK(seen == 5 && seen_ids[4] == 12 && seen_verdicts[4] == 0,
          "only failed ID and original verdict must be retried, never accepted IDs");
    CHECK(done_calls == 2 && done_tokens[1] == 78 && done_completes[1] &&
          done_sent_counts[1] == 2,
          "completion must retain token and cumulative successful verdict count");
    CHECK(d2k_udp_release_enqueue(q, 300, ids, verdicts, 2, &key, 80) == 0,
          "fourth batch accepted while capacity remains");
    CHECK(d2k_udp_release_enqueue(q, 301, other_ids, verdicts, 2, &key, 81) == 0,
          "fifth batch accepted while capacity remains");
    CHECK(d2k_udp_release_enqueue(q, 302, ids, verdicts, 2, &key, 82) != 0,
          "queue overflow accepted silently");
    seen = done_calls = 0;
    fail_id = 12; fail_always = 1;
    CHECK(d2k_udp_release_flush(q, UINT64_MAX, send_one, note_done, NULL) == 1,
          "shutdown must attempt failed slot once and still complete healthy slot");
    CHECK(seen == 4 && done_calls == 1 && done_tokens[0] == 81 && done_completes[0],
          "UINT64_MAX flush must not spin or complete failed ownership");
    CHECK(d2k_udp_release_next_ns(q) == UINT64_MAX,
          "retry deadline must saturate instead of wrapping");
    CHECK(d2k_udp_release_flush(q, UINT64_MAX, send_one, note_done, NULL) == 0 &&
          seen == 5 && seen_ids[4] == 12 && done_calls == 1,
          "repeated final flush retries only the unresolved verdict once");
    CHECK(d2k_udp_release_cancel(q, note_done, NULL) == 1,
          "shutdown must explicitly cancel unresolved ownership");
    CHECK(done_calls == 2 && done_tokens[1] == 80 && !done_completes[1] &&
          done_sent_counts[1] == 1 && seen == 5,
          "cancel must report original token and partial count without sending anything");
    CHECK(d2k_udp_release_next_ns(q) == 0 &&
          d2k_udp_release_cancel(q, note_done, NULL) == 0 && done_calls == 2,
          "terminal cancellation must notify each batch exactly once");
    CHECK(d2k_udp_release_enqueue(q, 300, ids, verdicts, 2, &key, 83) == 0,
          "cancel must release bounded capacity");
    CHECK(d2k_udp_release_flush(q, UINT64_MAX, NULL, note_done, NULL) == 0 &&
          done_calls == 2, "missing sender must retain ownership without success callback");
    CHECK(d2k_udp_release_cancel(q, note_done, NULL) == 1 && done_calls == 3 &&
          done_tokens[2] == 83 && !done_completes[2] && done_sent_counts[2] == 0,
          "never-sent batch cancellation must report zero retired IDs");
    fail_always = 0; fail_id = 0;
    d2k_udp_release_free(q);

    /* Задача 42: план забрал первый оригинал — ни одна копия из очереди не
       уходит, хвосты повторно шлёт сам датапат следом за посылками плана. */
    {
        uint32_t v[3] = {9, 9, 9};
        uint8_t again[3] = {9, 9, 9};
        CHECK(d2k_udp_replay_fates(3, D2K_NF_DROP, 1, 1, v, again) == 2,
              "owned batch: both tails are re-sent by the datapath");
        CHECK(v[0] == D2K_NF_DROP && v[1] == D2K_NF_DROP && v[2] == D2K_NF_DROP,
              "owned batch: every queued copy is dropped");
        CHECK(!again[0] && again[1] && again[2],
              "the head is the plan's own emit, only tails are re-sent");
        /* Задача 46: хвосты идут за головой и БЕЗ плана. Голова получает свой
           вердикт ядру, хвосты — нашей сырой посылкой, копии снимаются. */
        CHECK(d2k_udp_replay_fates(3, D2K_NF_ACCEPT, 0, 1, v, again) == 2,
              "unowned batch: tails are re-sent after the head");
        CHECK(v[0] == D2K_NF_ACCEPT && v[1] == D2K_NF_DROP && v[2] == D2K_NF_DROP &&
              !again[0] && again[1] && again[2],
              "unowned batch: head ACCEPT, queued tail copies dropped");
        CHECK(d2k_udp_replay_fates(1, D2K_NF_ACCEPT, 0, 1, v, again) == 0 &&
              v[0] == D2K_NF_ACCEPT && !again[0],
              "a single datagram has no tail to re-send");
        CHECK(d2k_udp_replay_fates(2, D2K_NF_DROP, 0, 1, v, again) == 1 &&
              v[0] == D2K_NF_DROP && v[1] == D2K_NF_DROP && again[1],
              "a failed owner still re-sends its tails instead of losing them");
        CHECK(d2k_udp_replay_fates(3, D2K_NF_ACCEPT, 0, 0, v, again) == 0 &&
              v[0] == D2K_NF_ACCEPT && v[1] == D2K_NF_ACCEPT && v[2] == D2K_NF_ACCEPT &&
              !again[0] && !again[1] && !again[2],
              "without a raw path (observe) everything goes to the kernel");
    }

    /* Задача 46: порядок выпуска пачки — вердикт головы, затем каждый хвост
       нашей посылкой и снятие его копии; копия не уходит второй раз; отказ
       посылки — ACCEPT копии. */
    for (size_t count = 2; count <= 4; count++) {
        d2k_udp_hold_batch b;
        memset(&b, 0, sizeof b);
        b.count = count;
        for (size_t i = 0; i < count; i++) {
            b.ids[i] = (uint32_t)(40 + i);
            b.len[i] = 30 + i;
            memset(b.packets[i], (int)(0xA0 + i), b.len[i]);
        }
        log_n = 0;
        resend_fail_at = 0;
        int vfail = 0;
        size_t rfail = 9;
        CHECK(d2k_udp_release_batch(&b, D2K_NF_ACCEPT, 0, 1, log_verdict, log_resend,
                                    NULL, &vfail, &rfail) == count - 1,
              "unplanned batch: every tail re-sent");
        CHECK(!vfail && rfail == 0, "no failure reported on a clean release");
        CHECK(log_n == 1 + 2 * (count - 1), "one verdict per ID and one send per tail");
        CHECK(log_kind[0] == 'v' && log_id[0] == 40 && log_v[0] == D2K_NF_ACCEPT,
              "the head's verdict goes first");
        for (size_t i = 1; i < count; i++) {
            size_t a = 1 + 2 * (i - 1);
            CHECK(log_kind[a] == 's' && log_len[a] == 30 + i && log_byte[a] == 0xA0 + i,
                  "tail re-sent byte for byte, in arrival order, after the head");
            CHECK(log_kind[a + 1] == 'v' && log_id[a + 1] == 40 + i &&
                  log_v[a + 1] == D2K_NF_DROP,
                  "the re-sent tail's queued copy is dropped right after");
        }
    }
    {
        d2k_udp_hold_batch b;
        memset(&b, 0, sizeof b);
        b.count = 3;
        for (size_t i = 0; i < 3; i++) { b.ids[i] = (uint32_t)(50 + i); b.len[i] = 20; }
        log_n = 0;
        resend_fail_at = 2; /* the second re-send (tail #2) fails */
        int vfail = 0;
        size_t rfail = 0;
        CHECK(d2k_udp_release_batch(&b, D2K_NF_ACCEPT, 0, 1, log_verdict, log_resend,
                                    NULL, &vfail, &rfail) == 1 && rfail == 1,
              "one failed re-send is counted");
        CHECK(log_n == 5 && log_id[4] == 52 && log_v[4] == D2K_NF_ACCEPT,
              "a tail that could not be re-sent is released to the kernel");
        CHECK(log_id[2] == 51 && log_v[2] == D2K_NF_DROP,
              "the successfully re-sent tail is still dropped");
        resend_fail_at = 0;

        /* Owned batch: the head's copy is dropped too, tails follow the plan. */
        log_n = 0;
        CHECK(d2k_udp_release_batch(&b, D2K_NF_DROP, 1, 1, log_verdict, log_resend,
                                    NULL, &vfail, &rfail) == 2,
              "owned batch re-sends both tails");
        CHECK(log_kind[0] == 'v' && log_id[0] == 50 && log_v[0] == D2K_NF_DROP,
              "owned: the head copy is dropped, its bytes left as the plan's emit");
        CHECK(log_v[2] == D2K_NF_DROP && log_v[4] == D2K_NF_DROP,
              "owned: tail copies dropped");

        /* Observe mode: nothing re-sent, plain ACCEPT in order. */
        log_n = 0;
        CHECK(d2k_udp_release_batch(&b, D2K_NF_ACCEPT, 0, 0, log_verdict, log_resend,
                                    NULL, &vfail, &rfail) == 0 && log_n == 3,
              "without a raw path every copy gets its verdict");
        CHECK(log_kind[0] == 'v' && log_kind[1] == 'v' && log_kind[2] == 'v' &&
              log_v[1] == D2K_NF_ACCEPT && log_v[2] == D2K_NF_ACCEPT,
              "observe: no send, all ACCEPT");

        /* A failed verdict is reported, the rest still released. */
        log_n = 0;
        verdict_fail_id = 50;
        vfail = 0;
        (void)d2k_udp_release_batch(&b, D2K_NF_ACCEPT, 0, 1, log_verdict, log_resend,
                                    NULL, &vfail, &rfail);
        CHECK(vfail && log_n == 3 && log_kind[1] == 'v' && log_v[1] == D2K_NF_ACCEPT &&
              log_kind[2] == 'v' && log_v[2] == D2K_NF_ACCEPT && rfail == 2,
              "head verdict failed: tails ACCEPTed, never sent ahead of a queued head");
        verdict_fail_id = 0;
    }

    /* Задача 46: датаграммы потока, которые ядро поставило в очередь, пока
       голова ещё ждала, но которых не было в пачке (пришли позже её выпуска),
       идут тем же путём. Окно — по кортежу и направлению клиента. */
    {
        d2k_udp_follow *f = d2k_udp_follow_new();
        CHECK(f != NULL, "follow allocation");
        uint8_t a[40], rev[40], other[40], tcp[40], frag[40];
        build_udp4(a, 0xC0A80143u, 0x3990F8C0u, 50000, 443);
        build_udp4(rev, 0x3990F8C0u, 0xC0A80143u, 443, 50000);
        build_udp4(other, 0xC0A80143u, 0x3990F8C0u, 50001, 443);
        build_udp4(tcp, 0xC0A80143u, 0x3990F8C0u, 50000, 443);
        tcp[9] = 6;
        build_udp4(frag, 0xC0A80143u, 0x3990F8C0u, 50000, 443);
        frag[6] = 0x20; /* MF */
        CHECK(!d2k_udp_follow_match(f, a, sizeof a, 1000, 1, NULL), "nothing marked yet");
        CHECK(d2k_udp_follow_mark(f, a, sizeof a, 1000, 0, 1) == 0, "mark the released head");
        CHECK(d2k_udp_follow_match(f, a, sizeof a, 1000 + D2K_UDP_FOLLOW_NS - 1, 2, NULL),
              "a datagram of the same client flow inside the clash window follows the head");
        CHECK(d2k_udp_follow_match(f, a, sizeof a, 1000 + 10 * D2K_UDP_FOLLOW_NS, 1, NULL),
              "read in the head's own receive batch: queued before its verdict");
        CHECK(!d2k_udp_follow_match(f, rev, sizeof rev, 1001, 1, NULL),
              "the server's direction is never re-sent");
        CHECK(!d2k_udp_follow_match(f, other, sizeof other, 1001, 1, NULL),
              "another client port is another flow");
        CHECK(!d2k_udp_follow_match(f, tcp, sizeof tcp, 1001, 1, NULL), "TCP never matches");
        CHECK(!d2k_udp_follow_match(f, frag, sizeof frag, 1001, 1, NULL),
              "an IP fragment is not re-sent as a whole datagram");
        CHECK(!d2k_udp_follow_match(f, a, sizeof a, 1000 + D2K_UDP_FOLLOW_NS, 2, NULL),
              "a later batch past the window goes to the kernel");
        uint64_t at = 7;
        CHECK(d2k_udp_follow_mark(f, a, sizeof a, 2000, 2000 + 30000000, 3) == 0 &&
              d2k_udp_follow_match(f, a, sizeof a, 2000 + 30000000 + D2K_UDP_FOLLOW_NS - 1,
                                   4, &at) && at == 2000 + 30000000,
              "a deferred head: window counts from its emit, which is reported");
        for (uint16_t p = 0; p < 200; p++) {
            build_udp4(other, 0xC0A80143u, 0x3990F8C0u, (uint16_t)(1000 + p), 443);
            (void)d2k_udp_follow_mark(f, other, sizeof other, 5000, 0, 9);
        }
        CHECK(d2k_udp_follow_match(f, other, sizeof other, 5001, 10, NULL),
              "a full table still takes the newest head");
        /* Field 03.10 (EACCES on raw re-send): broadcast and multicast
           destinations are never followed — a raw socket may not send to a
           broadcast address, and no NAT clash exists for them. */
        uint8_t bc[40], mc[40];
        build_udp4(bc, 0xC0A80101u, 0xFFFFFFFFu, 3517, 3517);
        build_udp4(mc, 0xC0A80101u, 0xEFFFFFFAu, 3702, 3702);
        CHECK(d2k_udp_follow_mark(f, bc, sizeof bc, 6000, 0, 11) != 0 &&
              !d2k_udp_follow_match(f, bc, sizeof bc, 6000, 11, NULL),
              "limited broadcast is never followed");
        CHECK(d2k_udp_follow_mark(f, mc, sizeof mc, 6000, 0, 11) != 0 &&
              !d2k_udp_follow_match(f, mc, sizeof mc, 6000, 11, NULL),
              "multicast is never followed");
        d2k_udp_follow_free(f);
    }

    /* Final review M-5: the follow table ages.  Entries past the window and
       from an earlier receive batch are expired, and an empty table answers
       without parsing or scanning. */
    {
        d2k_udp_follow *f = d2k_udp_follow_new();
        uint8_t a[40], b2[40];
        build_udp4(a, 0xC0A80143u, 0x3990F8C0u, 50000, 443);
        build_udp4(b2, 0xC0A80143u, 0x3990F8C0u, 50001, 443);
        CHECK(d2k_udp_follow_live(f) == 0, "a new table is empty");
        (void)d2k_udp_follow_mark(f, a, sizeof a, 1000, 0, 1);
        (void)d2k_udp_follow_mark(f, b2, sizeof b2, 1000, 0, 1);
        (void)d2k_udp_follow_mark(f, a, sizeof a, 1001, 0, 1);   /* same flow again */
        CHECK(d2k_udp_follow_live(f) == 2, "two flows followed");
        CHECK(d2k_udp_follow_match(f, a, sizeof a, 1000 + 10 * D2K_UDP_FOLLOW_NS, 1, NULL) &&
              d2k_udp_follow_live(f) == 2, "the head's own batch still matches past the window");
        CHECK(!d2k_udp_follow_match(f, a, sizeof a, 1000 + 10 * D2K_UDP_FOLLOW_NS, 2, NULL),
              "a later batch past the window: no match");
        CHECK(d2k_udp_follow_live(f) == 0, "stale entries are expired by the scan");
        d2k_udp_follow_age(f, 0, 0);
        CHECK(d2k_udp_follow_live(f) == 0, "aging an empty table is a no-op");
        (void)d2k_udp_follow_mark(f, a, sizeof a, 5000, 0, 3);
        d2k_udp_follow_age(f, 5000 + D2K_UDP_FOLLOW_NS - 1, 4);
        CHECK(d2k_udp_follow_live(f) == 1, "inside the window: kept");
        d2k_udp_follow_age(f, 5000 + D2K_UDP_FOLLOW_NS, 4);
        CHECK(d2k_udp_follow_live(f) == 0, "past the window, later batch: aged out");
        d2k_udp_follow_free(f);
    }
    if (!fails) puts("UDP release: due ordering and bounded ownership passed");
    return fails != 0;
}
