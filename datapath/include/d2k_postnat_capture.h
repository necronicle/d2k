#ifndef D2K_POSTNAT_CAPTURE_H
#define D2K_POSTNAT_CAPTURE_H
#include <stddef.h>
#include <stdint.h>
#include "d2k_ctq.h"
typedef struct d2k_postnat_capture d2k_postnat_capture;
/* Linux egress capture. Only packets explicitly tagged with mark_bit are
 * redirected; opening this handle does not mark or release any packet. */
d2k_postnat_capture *d2k_postnat_capture_open(unsigned output_ifindex,
    uint32_t mark_bit, uint16_t priority, char *err, size_t cap);
int d2k_postnat_capture_fd(const d2k_postnat_capture *);
/* One complete supported L3 packet: 1 read, 0 would block or unrelated
 * control frame skipped, -1 error. Never returns a usable partial packet. */
int d2k_postnat_capture_read(d2k_postnat_capture *, uint8_t *packet,
    size_t capacity, size_t *length);
int d2k_postnat_capture_close(d2k_postnat_capture *, char *err, size_t cap);
/* Match only against the kernel reply tuple queried for THIS original.
 * Neither payload equality nor a destination alone identifies a NAT flow.
 * The caller owns the query sequence and plan/experiment generation. */
int d2k_postnat_udp_match(const uint8_t *original, size_t original_len,
    const uint8_t *captured, size_t captured_len, const d2k_ct_info *mapping);
int d2k_postnat_udp_tuple(const uint8_t *, size_t, d2k_ct_tuple *);
#endif
