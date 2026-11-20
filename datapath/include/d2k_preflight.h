#ifndef D2K_PREFLIGHT_H
#define D2K_PREFLIGHT_H
#include "d2k_hold.h"

/* Fixed opt-in firewall contract, independent of the normal fake mark. */
#define D2K_PF_MARK 0x31u
#define D2K_PF_RELEASE_MARK 0x32u
#define D2K_PF_TOKEN_MARK 0x33u
#define D2K_PF_CONN_BIT 0x08000000u
#define D2K_PF_RELEASE_BIT 0x04000000u

typedef struct {
    uint16_t window;
    uint8_t wscale, pieces, hello_own;
    uint8_t reference_hello;
    uint32_t timeout_ms;
    uint32_t resyn_timeout_ms; /* reserved within timeout_ms for handover */
    uint16_t resyn_delay_ms; /* zero: legacy immediate handover */
    uint8_t resyn_sends; /* paired with delay; finite total timer sends */
    const uint8_t *hello;
    size_t hello_len;
    size_t send_cap; /* maximum whole raw IPv4 packet; zero uses IPv4 fallback MTU */
} d2k_pf_params;
typedef enum { PF_PROBE_SYN, PF_PROBE_DATA, PF_RESYN, PF_HANDOVER, PF_DONE, PF_GAVE_UP } d2k_pf_stage;
typedef enum { PF_ACT_PASS, PF_ACT_DROP } d2k_pf_verdict;
#define D2K_PF_OUT_MAX 4
#define D2K_PF_PACKET_MAX (D2K_HOLD_HEADER + D2K_CAPTURE_BYTES)
typedef struct d2k_pf_out {
    size_t count, len[D2K_PF_OUT_MAX];
    uint8_t clear[D2K_PF_OUT_MAX]; /* 1: release SYN via repeat; 2: consumed cleanup token */
    uint8_t original[D2K_PF_OUT_MAX]; /* 1 for owned client SYN, 0 for probe packets */
    uint8_t packet[D2K_PF_OUT_MAX][D2K_PF_PACKET_MAX];
} d2k_pf_out;
typedef struct d2k_pf_flow d2k_pf_flow;
typedef struct {
    d2k_pf_flow *flows;
    unsigned cap;
    uint64_t full_passes;
} d2k_pf_table;

/* init on a fresh table, free before re-init. Allocation only at init.
 * Inputs use pkt.wire/wire_len; payload fields keep their Plan semantics.
 * Each call replaces out; consume/copy it before the next call. No sending.
 * Caller has already authorized an endpoint-bound measured preflight plan.
 * hello bytes are copied at admission, hello_own is provenance, not a switch
 * to collect client data. Unsupported/invalid admission is fail-open.
 * Original SYN must have no data and fit D2K_HOLD_HEADER; hello <= capture.
 * Terminal entries suppress repeats of the same ISN until slot reuse.
 */
int d2k_pf_table_init(d2k_pf_table *, unsigned cap);
void d2k_pf_table_free(d2k_pf_table *);
d2k_pf_verdict d2k_pf_client_syn(d2k_pf_table *, const d2k_pkt *, const d2k_pf_params *, uint64_t,
                                 d2k_pf_out *);
d2k_pf_verdict d2k_pf_client_pkt(d2k_pf_table *, const d2k_pkt *, uint64_t, d2k_pf_out *);
d2k_pf_verdict d2k_pf_server_pkt(d2k_pf_table *, const d2k_pkt *, uint64_t, d2k_pf_out *);
/* A tick emits at most four packets, without losing other due flows. Drain
 * while next_ns <= now. Terminal slots with unsent cleanup still own a deadline. */
void d2k_pf_tick(d2k_pf_table *, uint64_t, d2k_pf_out *);
/* Report a successfully submitted cleanup token so its slot can be reused.
 * A failed cleanup retries on the measured timeout interval. */
void d2k_pf_output_sent(d2k_pf_table *, const d2k_pkt *, unsigned clear);
/* Caller has processed the whole real hello (including bounded capture). */
void d2k_pf_complete(d2k_pf_table *, const d2k_pkt *, d2k_pf_out *);
/* Local failure: return owned SYN; after handover emit cleanup only. */
void d2k_pf_abort(d2k_pf_table *, const d2k_pkt *, d2k_pf_out *);
uint64_t d2k_pf_next_ns(const d2k_pf_table *);
int d2k_pf_get_stage(const d2k_pf_table *, const d2k_pkt *, d2k_pf_stage *);
#endif
