#ifndef D2K_PREFLIGHT_CANDIDATE_H
#define D2K_PREFLIGHT_CANDIDATE_H
#include <stdint.h>
/* A proposal backed by a repeated small-window response. It is not a
 * carry property or application proof; the composed program needs its own
 * exact-generation application trial before any persistent promotion. */
typedef struct {
    uint8_t present,window_scale,pieces;
    uint16_t window;
    uint32_t rtt_ms,response_bytes;
    char name[254];
} d2k_preflight_candidate;
#endif
