#ifndef D2K_HTTP_TRACE_H
#define D2K_HTTP_TRACE_H
#include "d2k_session.h"

/* Observations after raw sends and the NFQUEUE verdict, never a new decision. */
typedef struct {
    int apply, output_failed, original_failed, original_pending, pending;
    uint8_t hook;
    uint32_t mark, outdev, verdict;
    size_t planned, sent, queued;
} d2k_http_trace_outcome;

/* Returns 0 for non-request packets. Does not print URL, cookies or headers. */
size_t d2k_http_trace(char *line, size_t cap, const uint8_t *packet, size_t len,
                      const d2k_result *result, const d2k_http_trace_outcome *outcome);

/* TLS client execution, using the same post-send observations as HTTP.
 * assembled_originals is zero for an unassembled packet. */
size_t d2k_tls_trace(char *line, size_t cap, const uint8_t *packet, size_t len,
                     const d2k_result *result, const d2k_http_trace_outcome *outcome,
                     size_t assembled_originals, int originals_owned);
#endif
