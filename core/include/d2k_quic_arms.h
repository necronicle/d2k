#ifndef D2K_QUIC_ARMS_H
#define D2K_QUIC_ARMS_H
#include "d2k_quicprobe.h"

/* One question of the original askArms. Fragments use explicit donor shapes,
 * never the old midpoint substitute. frag: 0 normal, 1 pos8, 2 reverse pos8,
 * 3 tiny three-fragment overlap, 4 three-fragment overlap. */
typedef struct {
    const char *label;
    const char *addr;
    const uint8_t *blob;
    size_t blob_len;
    int copies, ttl, frag, control;
} d2k_quic_arm_question;
typedef d2k_tally (*d2k_quic_arm_probe_fn)(const d2k_quic_arm_question *, void *, int *);
typedef struct {
    const char (*pool)[D2K_QUIC_ADDR_LEN];
    size_t n_pool, next;
    int residual;
    d2k_quic_arm_probe_fn probe;
    void *user;
    int marked;
    int (*can_ask)(void *); /* shared Run budget; NULL for unbounded unit oracle */
    void *limit_user;
} d2k_quic_arm_context;

d2k_quic_arm d2k_quic_original_arms(d2k_quic_arm_context *ctx);
/* Immutable instrument data; NULL is not replaced with a similar packet. */
const uint8_t *d2k_quic_original_blob(size_t index, size_t *len, const char **name);
d2k_quic_arm d2k_quic_original_measure(d2k_quic_arm_context *ctx, uint16_t port,
    d2k_hello trigger, d2k_hello control, uint32_t wait_ms, uint32_t mark);
/* Exact original raw-IP shapes; independent from the legacy midpoint hook. */
typedef d2k_tally (*d2k_quic_fragment_fn)(const char *,uint16_t,int,d2k_hello,
    uint32_t,uint32_t,int,int *);
extern d2k_quic_fragment_fn d2k_quic_fragment_hook;
#endif
