#include <stdio.h>
#include <string.h>
#include "d2k_capture.h"

static int fails;
#define CHECK(x) do { if (!(x)) { \
    printf("capture: line %d: %s\n", __LINE__, #x); fails++; } } while (0)
static d2k_capture c;
static d2k_key key = {.proto = 6, .low_port = 1234, .high_port = 443};
static const uint8_t *result;
static size_t result_len;
static uint32_t result_seq;
static int feed(uint64_t gen, uint64_t now, uint32_t seq, const uint8_t *b, size_t n) {
    return d2k_capture_feed(&c, &key, gen, now, seq, b, n,
                            &result, &result_len, &result_seq);
}
/* Only framing is this module's job. Full TLS parsing is tested at session. */
static void frame(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) { b[i] = (uint8_t)i; }
    b[0] = 22; b[1] = 3; b[2] = 1;
    b[3] = (uint8_t)((n - 5) >> 8); b[4] = (uint8_t)(n - 5);
    b[5] = 1; b[6] = 0;
    b[7] = (uint8_t)((n - 9) >> 8); b[8] = (uint8_t)(n - 9);
}

int main(void) {
    uint8_t b[D2K_CAPTURE_BYTES + 1], bad[D2K_CAPTURE_BYTES + 1];
    size_t n = 1544;
    frame(b, n);
    CHECK(feed(1, 1, 1000, b, n) == 1);
    CHECK(result_len == n && result_seq == 1000 && !memcmp(result, b, n));
    CHECK(feed(1, 2, 1000, b, n) == 0); /* one delivery */
    CHECK(result == NULL && result_len == 0);

    /* Every split including inside record/handshake headers; wraparound. */
    for (size_t cut = 1; cut < n; cut++) {
        memset(&c, 0, sizeof c);
        uint32_t seq = UINT32_MAX - 10;
        CHECK(feed(1, 1, seq, b, cut) == 0);
        CHECK(feed(1, 2, seq + (uint32_t)cut, b + cut, n - cut) == 1);
        CHECK(result_len == n && result_seq == seq && !memcmp(result, b, n));
    }
    memset(&c, 0, sizeof c);
    CHECK(feed(1, 1, 1000, b, 1) == 0);
    CHECK(feed(1, 2, 1100, b + 100, n - 100) == 0); /* gap, tail first */
    CHECK(feed(1, 3, 1050, b + 50, 100) == 0); /* matching overlap */
    CHECK(feed(1, 4, 1000, b, 50) == 1);
    CHECK(result_len == n && !memcmp(result, b, n));

    memset(&c, 0, sizeof c);
    CHECK(feed(1, 1, 1000, b, 100) == 0);
    memcpy(bad, b, n); bad[99] ^= 1;
    CHECK(feed(1, 2, 1050, bad + 50, 100) == -1);
    CHECK(feed(1, 3, 1000, b, n) == 0); /* poisoned capture cannot restart */
    CHECK(c.rejected == 1);
    CHECK(feed(2, 4, 1000, b, n) == 1); /* new flow generation */
    d2k_capture_forget(&c, &key);
    CHECK(feed(2, 5, 1000, b, n) == 1); /* explicit SYN/reset */

    memset(&c, 0, sizeof c);
    CHECK(feed(1, 1, 1000, b, 100) == 0);
    CHECK(feed(1, 2, 999, b, 100) == -1); /* before known head */
    memset(&c, 0, sizeof c);
    CHECK(feed(1, 1, 1000, b, 100) == 0);
    CHECK(feed(1, D2K_CAPTURE_TTL_NS + 1, 1100, b + 100, n - 100) == 0);
    CHECK(c.expired == 1 && c.completed == 0);
    /* A retransmit does not extend the absolute memory lease. */
    memset(&c, 0, sizeof c);
    CHECK(feed(1, 1, 1000, b, 100) == 0);
    CHECK(feed(1, D2K_CAPTURE_TTL_NS, 1000, b, 100) == 0);
    CHECK(feed(1, D2K_CAPTURE_TTL_NS + 1, 1100, b + 100, n - 100) == 0);
    CHECK(c.expired == 1);

    memset(&c, 0, sizeof c);
    for (size_t i = 0; i < D2K_CAPTURE_SLOTS; i++) {
        key.low_port = (uint16_t)(1000 + i);
        CHECK(feed(1, 1, 1000, b, 100) == 0);
    }
    key.low_port = 2000;
    CHECK(feed(1, 2, 1000, b, n) == -2);
    CHECK(c.full == 1);
    key.low_port = 1000;
    CHECK(feed(1, 3, 1100, b + 100, n - 100) == 1); /* no eviction */
    key.low_port = 2000;
    CHECK(feed(1, D2K_CAPTURE_TTL_NS + 1, 1000, b, n) == 1);

    memset(&c, 0, sizeof c);
    frame(b, D2K_CAPTURE_BYTES);
    CHECK(feed(1, 1, 1000, b, D2K_CAPTURE_BYTES) == 1);
    d2k_capture_forget(&c, &key);
    frame(b, sizeof b);
    CHECK(feed(1, 1, 1000, b, sizeof b) == -1);
    d2k_capture_forget(&c, &key);
    CHECK(feed(1, 1, 1000, b, 5) == -1); /* declared oversized record */
    d2k_capture_forget(&c, &key);
    frame(b, n); b[8] ^= 1;
    CHECK(feed(1, 1, 1000, b, n) == -1); /* multi-record/mismatched hello */
    d2k_capture_forget(&c, &key);
    frame(b, n);
    CHECK(feed(1, 1, 1000, b, n + 1) == -1); /* trailing data not a snapshot */
    d2k_capture_forget(&c, &key);
    b[1] = 2;
    CHECK(feed(1, 1, 1000, b, n) == -1);
    d2k_capture_forget(&c, &key);
    frame(b, n); b[5] = 2;
    CHECK(feed(1, 1, 1000, b, n) == -1);
    d2k_capture_forget(&c, &key);
    CHECK(feed(1, 1, 1000, b, 0) == 0);
    b[0] = 23;
    CHECK(feed(1, 1, 1000, b, n) == 0);
    frame(b, n); key.proto = 17;
    CHECK(feed(1, 1, 1000, b, n) == 0);
    if (fails) { return 1; }
    puts("capture: all checks passed");
    return 0;
}
