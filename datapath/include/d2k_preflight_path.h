#ifndef D2K_PREFLIGHT_PATH_H
#define D2K_PREFLIGHT_PATH_H
#include "d2k_session.h"
typedef struct {
    void *ctx;
    int (*drop)(void *, uint32_t id);
    int (*send)(void *, const uint8_t *, size_t, uint32_t mark);
} d2k_preflight_io;
/* 1: current queue ID consumed, 0: ordinary packet path. All output follows
 * successful DROP. -1: DROP failed, no raw packet was sent; caller logs it. */
int d2k_preflight_path_packet(d2k_session *, const uint8_t *, size_t, uint32_t,
                              uint64_t, const d2k_preflight_io *);
int d2k_preflight_path_packet_path(d2k_session *,const uint8_t *,size_t,uint32_t,
                              uint64_t,const d2k_preflight_io *,uint32_t path);
int d2k_preflight_path_complete(d2k_session *, const uint8_t *, size_t, uint64_t, const d2k_preflight_io *);
int d2k_preflight_path_complete_on(d2k_session *, const uint8_t *, size_t, uint64_t, const d2k_preflight_io *, uint32_t path);
int d2k_preflight_path_flush(d2k_session *, uint64_t, const d2k_preflight_io *);
int d2k_preflight_path_tick(d2k_session *, uint64_t, const d2k_preflight_io *);
#endif
