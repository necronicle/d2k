#ifndef D2K_TG_WIRE_H
#define D2K_TG_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define TG_MUX_HEADER_LEN 3u
#define TG_HELLO_ACK_FIXED_LEN 34u
#define TG_INFO_FIXED_LEN 5u
#define TG_AUTH_V2_LEN 104u

typedef struct {
    uint16_t stream_id;
    uint8_t type;
    const uint8_t *payload;
    size_t payload_len;
} tg_frame;

typedef struct {
    uint8_t version;
    int64_t server_unix;
    uint8_t nonce[16];
    uint8_t min_build[255];
    uint8_t min_build_len;
    uint32_t window;
    uint32_t capabilities;
} tg_hello_ack;

/* Returns encoded byte count, or 0 on invalid input/capacity. */
size_t tg_mux_encode(uint8_t *dst, size_t cap, uint16_t stream_id,
                     uint8_t type, const uint8_t *payload, size_t payload_len);
/* Payload borrows the input buffer and remains valid as long as it does. */
int tg_mux_decode(const uint8_t *src, size_t len, tg_frame *out);
int tg_connect_encode(uint8_t *dst, size_t cap, int address_family,
                      const uint8_t *address, uint16_t port, size_t *written);
int tg_hello_encode(uint8_t *dst, size_t cap, const char *build,
                    uint32_t capabilities, size_t *written);
int tg_hello_ack_decode(const uint8_t *src, size_t len, tg_hello_ack *out);
int tg_auth_v2_encode(uint8_t dst[TG_AUTH_V2_LEN], const uint8_t install_id[16],
                      uint64_t timestamp, const uint8_t nonce[16],
                      const uint8_t signature[64]);
int tg_window_encode(uint8_t dst[4], uint32_t credit);
int tg_window_decode(const uint8_t *src, size_t len, uint32_t *credit);
int tg_info_decode(const uint8_t *src, size_t len, uint8_t *kind,
                   uint32_t *arg, const uint8_t **text, size_t *text_len);
int tg_close_decode(const uint8_t *src, size_t len, uint8_t *reason,
                    const uint8_t **text, size_t *text_len);

#endif
