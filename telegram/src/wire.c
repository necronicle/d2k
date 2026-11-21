#include "tg_wire.h"

#include <arpa/inet.h>
#include <limits.h>
#include <string.h>

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get_u64(const uint8_t *p) {
    return ((uint64_t)get_u32(p) << 32) | get_u32(p + 4);
}

size_t tg_mux_encode(uint8_t *dst, size_t cap, uint16_t stream_id,
                     uint8_t type, const uint8_t *payload, size_t payload_len) {
    if (!dst || (payload_len && !payload) || payload_len > SIZE_MAX - 3 ||
        cap < payload_len + 3) return 0;
    dst[0] = (uint8_t)(stream_id >> 8);
    dst[1] = (uint8_t)stream_id;
    dst[2] = type;
    if (payload_len) memcpy(dst + 3, payload, payload_len);
    return payload_len + 3;
}

int tg_mux_decode(const uint8_t *src, size_t len, tg_frame *out) {
    if (!src || !out || len < TG_MUX_HEADER_LEN) return -1;
    out->stream_id = (uint16_t)(((uint16_t)src[0] << 8) | src[1]);
    out->type = src[2];
    out->payload = src + TG_MUX_HEADER_LEN;
    out->payload_len = len - TG_MUX_HEADER_LEN;
    return 0;
}

int tg_connect_encode(uint8_t *dst, size_t cap, int family,
                      const uint8_t *address, uint16_t port, size_t *written) {
    size_t addr_len;
    uint8_t kind;
    if (!dst || !address || !written || !port) return -1;
    if (family == AF_INET) { addr_len = 4; kind = 1; }
    else if (family == AF_INET6) { addr_len = 16; kind = 4; }
    else return -1;
    if (cap < addr_len + 3) return -1;
    dst[0] = kind;
    memcpy(dst + 1, address, addr_len);
    dst[addr_len + 1] = (uint8_t)(port >> 8);
    dst[addr_len + 2] = (uint8_t)port;
    *written = addr_len + 3;
    return 0;
}

int tg_hello_encode(uint8_t *dst, size_t cap, const char *build,
                    uint32_t capabilities, size_t *written) {
    size_t n;
    if (!dst || !build || !written) return -1;
    n = strlen(build);
    if (n > UINT8_MAX) n = UINT8_MAX;
    if (cap < n + 6) return -1;
    dst[0] = 2; dst[1] = (uint8_t)n;
    memcpy(dst + 2, build, n);
    put_u32(dst + 2 + n, capabilities);
    *written = n + 6;
    return 0;
}

int tg_hello_ack_decode(const uint8_t *src, size_t len, tg_hello_ack *out) {
    size_t n, expected;
    if (!src || !out || len < TG_HELLO_ACK_FIXED_LEN) return -1;
    n = src[25];
    expected = TG_HELLO_ACK_FIXED_LEN + n;
    if (len != expected) return -1;
    memset(out, 0, sizeof(*out));
    out->version = src[0];
    out->server_unix = (int64_t)get_u64(src + 1);
    memcpy(out->nonce, src + 9, sizeof(out->nonce));
    out->min_build_len = (uint8_t)n;
    memcpy(out->min_build, src + 26, n);
    out->window = get_u32(src + 26 + n);
    out->capabilities = get_u32(src + 30 + n);
    return 0;
}

int tg_auth_v2_encode(uint8_t dst[TG_AUTH_V2_LEN], const uint8_t install_id[16],
                      uint64_t timestamp, const uint8_t nonce[16],
                      const uint8_t signature[64]) {
    if (!dst || !install_id || !nonce || !signature) return -1;
    memcpy(dst, install_id, 16);
    for (size_t i = 0; i < 8; ++i) dst[16 + i] = (uint8_t)(timestamp >> (56 - 8*i));
    memcpy(dst + 24, nonce, 16);
    memcpy(dst + 40, signature, 64);
    return 0;
}

int tg_window_encode(uint8_t dst[4], uint32_t credit) {
    if (!dst) return -1;
    put_u32(dst, credit);
    return 0;
}

int tg_window_decode(const uint8_t *src, size_t len, uint32_t *credit) {
    if (!src || !credit || len != 4) return -1;
    *credit = get_u32(src);
    return 0;
}

int tg_info_decode(const uint8_t *src, size_t len, uint8_t *kind,
                   uint32_t *arg, const uint8_t **text, size_t *text_len) {
    if (!src || !kind || !arg || !text || !text_len || len < TG_INFO_FIXED_LEN) return -1;
    *kind = src[0];
    *arg = get_u32(src + 1);
    *text = src + TG_INFO_FIXED_LEN;
    *text_len = len - TG_INFO_FIXED_LEN;
    return 0;
}

int tg_close_decode(const uint8_t *src, size_t len, uint8_t *reason,
                    const uint8_t **text, size_t *text_len) {
    if (!reason || !text || !text_len || (len && !src)) return -1;
    if (len == 0) {
        *reason = 0;
        *text = NULL;
        *text_len = 0;
        return 0;
    }
    *reason = src[0];
    *text = src + 1;
    *text_len = len - 1;
    return 0;
}
