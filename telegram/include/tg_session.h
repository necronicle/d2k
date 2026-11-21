#ifndef D2K_TG_SESSION_H
#define D2K_TG_SESSION_H

#include "tg_identity.h"
#include "tg_wire.h"
#include "tg_ws.h"
#include <stddef.h>
#include <stdint.h>

#define TG_MUX_AUTHID 0x06u
#define TG_MUX_HELLO 0x07u
#define TG_MUX_HELLO_ACK 0x08u
#define TG_MUX_INFO 0x0au
#define TG_INFO_AUTH_OK 0u
#define TG_INFO_GOODBYE 4u
#define TG_REASON_PROTOCOL 1u
#define TG_SESSION_ERROR (-1)
#define TG_SESSION_V2_OK 0
#define TG_SESSION_FALLBACK_V1 1
#define TG_WS_PING_INTERVAL_MS 10000u
#define TG_WS_READ_TIMEOUT_MS 30000u
#define TG_MAX_RETRY_AFTER_SEC 5u

typedef struct {
    void *ctx;
    int (*send_binary)(void *ctx, const uint8_t *data, size_t len);
    /* Consume one complete message, copying at most cap bytes and returning its full length. */
    int (*read_binary_prefix)(void *ctx, uint8_t *dst, size_t cap, size_t *len);
} tg_session_io;

typedef struct {
    int64_t clock_offset;
    uint32_t window;
    uint32_t retry_after;
} tg_session_state;

int tg_session_authenticate_v2(const tg_session_io *io, const tg_identity *id,
                               const char *build, int64_t local_unix,
                               tg_session_state *state);
int tg_session_authenticate_v1(const tg_session_io *io, const tg_identity *id,
                               int64_t unix_time);
uint32_t tg_reconnect_delay_ms(unsigned consecutive_failures,
                               uint32_t retry_after_sec, int session_healthy,
                               double random_unit);
int tg_reconnect_needs_reregister(unsigned consecutive_fast_deaths);
int tg_session_ping_due(uint64_t last_ping_ms, uint64_t now_ms);
int tg_session_read_expired(uint64_t last_rx_ms, uint64_t now_ms);

#endif
