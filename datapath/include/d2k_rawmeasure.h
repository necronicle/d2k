#ifndef D2K_RAWMEASURE_H
#define D2K_RAWMEASURE_H
#include <stddef.h>
#include <stdint.h>
#include "d2k_ctq.h"
/* Bounded evidence storage, not a search/probe budget. Larger samples are
 * explicitly unmeasured. No application request is synthesized or replayed. */
#define D2K_RAWMEASURE_SAMPLE 2048
struct d2k_rawmeasure {
    d2k_ct_tuple tuple;
    uint64_t generation;
    /* Monotonic times of the sampled copy and of the last two exact copies.
       Facts for the trial window, never a search budget. */
    uint64_t sample_ns, prev_copy_ns, last_copy_ns;
    uint32_t client_packets, server_packets, client_data, exact_repeats;
    uint32_t sample_seq, tcp_ack;
    uint16_t sample_len, smallest_data, largest_data;
    uint8_t sampled, oversized, changed, closed, previous_reply, tcp_ack_seen;
    uint8_t sample[D2K_RAWMEASURE_SAMPLE];
};
/* TCP serial arithmetic, including sequence wrap; half-space is ambiguous. */
static inline int d2k_rm_ack_covers(uint32_t ack,uint32_t seq,uint16_t len) {
    return len && (uint32_t)(ack-(seq+(uint32_t)len)) < UINT32_C(0x80000000);
}
enum d2k_rawmeasure_result {
    D2K_RM_PENDING, D2K_RM_SERVER_PRESENT, D2K_RM_REPEAT_SILENT,
    D2K_RM_UNINFORMATIVE, D2K_RM_CLOSED, D2K_RM_UNMEASURED
};
void d2k_rawmeasure_init(struct d2k_rawmeasure *, const d2k_ct_tuple *, uint64_t generation, int previous_reply);
/* Generation is supplied by the owning flow, never inferred from its 5-tuple.
 * 0 means foreign/unparseable, 1 means accounted. Always read-only. */
int d2k_rawmeasure_feed(struct d2k_rawmeasure *, uint64_t generation, const uint8_t *, size_t, uint64_t now_ns);
enum d2k_rawmeasure_result d2k_rawmeasure_result(const struct d2k_rawmeasure *, int expired);
#endif
