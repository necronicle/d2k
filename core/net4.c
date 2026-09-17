/* net4.c — контракт и обоснования в d2k_net4.h. */
#include <stdio.h>
#include <string.h>

#include "d2k_net4.h"

int d2k_ip4_parse(const char *s, uint32_t *out) {
    if (!s || !out) { return -1; }
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        if (*s < '0' || *s > '9') { return -1; }
        unsigned b = 0;
        int digits = 0;
        while (*s >= '0' && *s <= '9') {
            b = b * 10 + (unsigned)(*s - '0');
            if (++digits > 3 || b > 255) { return -1; }
            s++;
        }
        v = (v << 8) | b;
        if (i < 3) {
            if (*s != '.') { return -1; }
            s++;
        }
    }
    if (*s != '\0') { return -1; }
    /* Строка собиралась старшим байтом вперёд — это и есть сетевой порядок. */
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    memcpy(out, b, 4);
    return 0;
}

size_t d2k_ip4_text(uint32_t ip_net, char *out, size_t cap) {
    uint8_t b[4];
    memcpy(b, &ip_net, 4);
    int n = snprintf(out, cap, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    if (n < 0 || (size_t)n >= cap) { return 0; }
    return (size_t)n;
}

int d2k_ip4_private(uint32_t ip_net) {
    uint8_t b[4];
    memcpy(b, &ip_net, 4);
    uint32_t v = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
    return (v >> 24) == 127 ||                      /* 127/8 — петля */
           (v >> 24) == 10 ||                       /* 10/8 */
           (v & 0xfff00000u) == 0xac100000u ||      /* 172.16/12 */
           (v & 0xffff0000u) == 0xc0a80000u ||      /* 192.168/16 */
           (v & 0xffff0000u) == 0xa9fe0000u ||      /* 169.254/16 */
           (v & 0xffc00000u) == 0x64400000u ||      /* 100.64/10, RFC 6598 */
           v == 0;
}
