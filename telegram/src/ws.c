#include "tg_ws.h"

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static int valid_opcode(uint8_t opcode) {
    return opcode == TG_WS_BINARY || opcode == TG_WS_CLOSE ||
           opcode == TG_WS_PING || opcode == TG_WS_PONG;
}

int tg_ws_encode_client_frame(uint8_t *dst, size_t cap, uint8_t opcode,
                              const uint8_t *payload, size_t payload_len,
                              size_t *written) {
    size_t header, mask_off;
    uint8_t mask[4];
    if (!dst || !written || (payload_len && !payload) || !valid_opcode(opcode) ||
        payload_len > TG_WS_MAX_MESSAGE) return -1;
    if (opcode >= 8 && payload_len > 125) return -1;
    header = payload_len < 126 ? 2 : payload_len <= UINT16_MAX ? 4 : 10;
    if (payload_len > SIZE_MAX - header - 4 || cap < header + 4 + payload_len)
        return -1;
    if (RAND_bytes(mask, sizeof(mask)) != 1) return -1;
    dst[0] = (uint8_t)(0x80 | opcode);
    if (payload_len < 126) dst[1] = (uint8_t)(0x80 | payload_len);
    else if (payload_len <= UINT16_MAX) {
        dst[1] = 0x80 | 126;
        dst[2] = (uint8_t)(payload_len >> 8);
        dst[3] = (uint8_t)payload_len;
    } else {
        uint64_t n = (uint64_t)payload_len;
        dst[1] = 0x80 | 127;
        for (size_t i = 0; i < 8; ++i) dst[2 + i] = (uint8_t)(n >> (56 - 8*i));
    }
    mask_off = header - 2;
    memcpy(dst + 2 + mask_off, mask, sizeof(mask));
    for (size_t i = 0; i < payload_len; ++i)
        dst[header + 4 + i] = (uint8_t)(payload[i] ^ mask[i & 3]);
    *written = header + 4 + payload_len;
    return 0;
}

static size_t server_header_size(const uint8_t *src) {
    if ((src[0] & 0xf0) != 0x80 || (src[1] & 0x80) || !valid_opcode(src[0] & 15))
        return 0;
    if (src[1] < 126) return 2;
    return src[1] == 126 ? 4 : 10;
}

/* header is the complete validated header size returned by server_header_size. */
static int server_payload_size(const uint8_t *src, size_t header, size_t *size) {
    uint64_t n = src[1];
    if (header > 2) {
        n = 0;
        for (size_t i = 2; i < header; ++i) n = (n << 8) | src[i];
        if (n < 126 || (header == 10 && n <= UINT16_MAX)) return -1;
    }
    if (n > TG_WS_MAX_MESSAGE || ((src[0] & 15) >= 8 && n > 125)) return -1;
    *size = (size_t)n;
    return 0;
}

int tg_ws_decode_server_frame(const uint8_t *src, size_t len, size_t max_payload,
                              uint8_t *opcode, const uint8_t **payload,
                              size_t *payload_len, size_t *consumed) {
    if (!src || !opcode || !payload || !payload_len || !consumed || len < 2)
        return -1;
    size_t header = server_header_size(src), n;
    if (!header || len < header || server_payload_size(src, header, &n) != 0 ||
        n > max_payload || n > len - header) return -1;
    *opcode = src[0] & 15;
    *payload = src + header;
    *payload_len = (size_t)n;
    *consumed = header + (size_t)n;
    return 0;
}

static int ssl_read_all(SSL *ssl, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t n = 0;
        if (SSL_read_ex(ssl, buf + off, len - off, &n) != 1 || n == 0) return -1;
        off += n;
    }
    return 0;
}

static int ssl_write_all(SSL *ssl, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t n = 0;
        if (SSL_write_ex(ssl, buf + off, len - off, &n) != 1 || n == 0) return -1;
        off += n;
    }
    return 0;
}

static int header_has_token(const char *value, const char *token) {
    size_t want = strlen(token);
    while (*value) {
        while (*value == ' ' || *value == '\t' || *value == ',') ++value;
        const char *start = value;
        while (*value && *value != ',') ++value;
        const char *end = value;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
        if ((size_t)(end - start) == want && strncasecmp(start, token, want) == 0) return 1;
        if (*value) ++value;
    }
    return 0;
}

static int get_header(const char *response, const char *name, char *out, size_t cap) {
    const char *line = strstr(response, "\r\n");
    if (!line) return -1;
    line += 2;
    while (*line && !(line[0] == '\r' && line[1] == '\n')) {
        const char *end = strstr(line, "\r\n");
        const char *colon = strchr(line, ':');
        if (!end || !colon || colon >= end) return -1;
        if ((size_t)(colon - line) == strlen(name) && strncasecmp(line, name, strlen(name)) == 0) {
            const char *value = colon + 1;
            while (value < end && (*value == ' ' || *value == '\t')) ++value;
            size_t n = (size_t)(end - value);
            if (n >= cap) return -1;
            memcpy(out, value, n); out[n] = '\0';
            return 0;
        }
        line = end + 2;
    }
    return -1;
}

int tg_ws_upgrade(SSL *ssl, const char *host_header, const char *path) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t random[16], digest[SHA_DIGEST_LENGTH];
    char key[25], expected[32], response[16385], line[4096];
    unsigned int digest_len = 0;
    size_t used = 0;
    if (!ssl || !host_header || !*host_header || !path || path[0] != '/') return -1;
    if (strpbrk(host_header, "\r\n \t") || strpbrk(path, "\r\n \t")) return -1;
    if (RAND_bytes(random, sizeof(random)) != 1) return -1;
    int key_len = EVP_EncodeBlock((unsigned char *)key, random, sizeof(random));
    if (key_len != 24) return -1;
    key[24] = '\0';
    int n = snprintf(line, sizeof(line),
        "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
        path, host_header, key);
    if (n <= 0 || (size_t)n >= sizeof(line) || ssl_write_all(ssl, (uint8_t *)line, (size_t)n) != 0)
        return -1;
    while (used < sizeof(response)-1) {
        if (ssl_read_all(ssl, (uint8_t *)response + used, 1) != 0) return -1;
        ++used;
        if (used >= 4 && memcmp(response + used - 4, "\r\n\r\n", 4) == 0) break;
    }
    if (used == sizeof(response)-1) return -1;
    response[used] = '\0';
    if (strncmp(response, "HTTP/1.1 101 ", 13) != 0 && strncmp(response, "HTTP/1.0 101 ", 13) != 0)
        return -1;
    char upgrade[64], connection[128], accept[64];
    if (get_header(response, "Upgrade", upgrade, sizeof(upgrade)) != 0 ||
        strcasecmp(upgrade, "websocket") != 0 ||
        get_header(response, "Connection", connection, sizeof(connection)) != 0 ||
        !header_has_token(connection, "upgrade") ||
        get_header(response, "Sec-WebSocket-Accept", accept, sizeof(accept)) != 0)
        return -1;
    char source[128];
    n = snprintf(source, sizeof(source), "%s%s", key, guid);
    if (n <= 0 || (size_t)n >= sizeof(source) ||
        EVP_Digest(source, (size_t)n, digest, &digest_len, EVP_sha1(), NULL) != 1 ||
        digest_len != sizeof(digest)) return -1;
    n = EVP_EncodeBlock((unsigned char *)expected, digest, sizeof(digest));
    if (n != 28) return -1;
    expected[28] = '\0';
    return strcmp(accept, expected) == 0 ? 0 : -1;
}

static int write_frame(SSL *ssl, uint8_t opcode, const uint8_t *payload, size_t len) {
    size_t cap = len + 14, written = 0;
    uint8_t *frame = OPENSSL_malloc(cap);
    if (!frame) return -1;
    int rc = tg_ws_encode_client_frame(frame, cap, opcode, payload, len, &written);
    if (rc == 0) rc = ssl_write_all(ssl, frame, written);
    OPENSSL_clear_free(frame, cap);
    return rc;
}

int tg_ws_write_binary(SSL *ssl, const uint8_t *payload, size_t payload_len) {
    if (!ssl || (payload_len && !payload)) return -1;
    return write_frame(ssl, TG_WS_BINARY, payload, payload_len);
}

int tg_ws_read_binary_prefix(SSL *ssl, uint8_t *dst, size_t cap, size_t *payload_len) {
    uint8_t header[10], scratch[1024];
    if (!ssl || !dst || !payload_len) return -1;
    for (;;) {
        size_t n;
        if (ssl_read_all(ssl, header, 2) != 0) return -1;
        size_t hlen = server_header_size(header);
        if (!hlen || ssl_read_all(ssl, header + 2, hlen - 2) != 0 ||
            server_payload_size(header, hlen, &n) != 0) return -1;
        uint8_t opcode = header[0] & 15;
        if (opcode == TG_WS_BINARY) {
            size_t kept = n < cap ? n : cap;
            if (ssl_read_all(ssl, dst, kept) != 0) return -1;
            for (size_t remaining = n - kept; remaining; ) {
                size_t chunk = remaining < sizeof(scratch) ? remaining : sizeof(scratch);
                if (ssl_read_all(ssl, scratch, chunk) != 0) return -1;
                remaining -= chunk;
            }
            *payload_len = n;
            return 0;
        }
        /* Valid control frames contain at most 125 bytes. */
        if (ssl_read_all(ssl, scratch, n) != 0) return -1;
        if (opcode == TG_WS_CLOSE) {
            (void)write_frame(ssl, TG_WS_CLOSE, scratch, n);
            return -2;
        }
        if (opcode == TG_WS_PING && write_frame(ssl, TG_WS_PONG, scratch, n) != 0)
            return -1;
    }
}
