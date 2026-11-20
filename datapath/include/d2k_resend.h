/* Return a TCP hello already taken from the kernel, within its path cap. */
#ifndef D2K_RESEND_H
#define D2K_RESEND_H
#include <stddef.h>
#include <stdint.h>

/* cap is the same per-destination raw-send limit used for plan execution.
 * Zero means unknown: send the original unchanged, as for a fitting packet.
 * Oversized FIN/RST and unsupported transport contexts fail before any send.
 * send returns 0 or -1 with errno; sent counts successful wire packets even
 * on partial failure. Input bytes are never changed. No socket operations. */
int d2k_resend_original(const uint8_t *packet, size_t len, size_t cap,
                        int (*send)(void *, const uint8_t *, size_t),
                        void *ctx, size_t *sent);
#endif
