#ifndef D2K_IPFRAG_H
#define D2K_IPFRAG_H
#include <stddef.h>
#include <stdint.h>

/* Port of quicprobe/frag.go. Positions are relative to the UDP HEADER,
 * not the QUIC payload. These are IP fragments, not split UDP messages. */
typedef struct {
    uint16_t pos1, pos2, overlap12, overlap23;
    uint8_t three, reverse;
} d2k_ipfrag_plan;
typedef struct { size_t off, len; } d2k_ipfrag_span;

/* Cuts in logical order; build emits them in requested transmission order. */
size_t d2k_ipfrag_cuts(size_t total, const d2k_ipfrag_plan *plan,
                     d2k_ipfrag_span cuts[3]);
/* Exact original askArms shapes 1..4; 0/unknown is not a fragment plan. */
int d2k_ipfrag_shape(int shape, d2k_ipfrag_plan *plan);
/* Concatenated complete IPv4 fragments in out; spans refer into out.
 * Returns 2/3, or 0 without emitting a partial result. Source/dest are
 * network-order bytes, ports/id host-order. id must be nonzero. */
size_t d2k_udpfrag_build(const uint8_t src[4], const uint8_t dst[4],
    uint16_t sport, uint16_t dport, const uint8_t *payload, size_t len,
    const d2k_ipfrag_plan *plan, uint16_t id, uint8_t *out, size_t cap,
    d2k_ipfrag_span spans[3]);
#endif
