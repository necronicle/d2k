/* Шифры TLS 1.3 0x1302/0x1303: эталонные векторы стандартов. Реализация
 * дополнительно сверена с OpenSSL 3.6 на длинах 0..18000 и подменённых
 * тегах, а расписание ключей — полными рукопожатиями с живыми серверами. */
#include <stdio.h>
#include <string.h>
#include "d2k_suite.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void unhex(const char *h, uint8_t *o) { for (size_t i = 0; h[2*i]; i++) { unsigned v; sscanf(h + 2*i, "%2x", &v); o[i] = (uint8_t)v; } }
static int same(const uint8_t *b, const char *h) { uint8_t x[256]; unhex(h, x); return !memcmp(b, x, strlen(h) / 2); }

int main(void)
{
    uint8_t h[64];
    d2k_sha384((const uint8_t *)"abc", 3, h);
    CHECK(same(h, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
    d2k_sha512((const uint8_t *)"abc", 3, h);
    CHECK(same(h, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));

    /* NIST GCM, тесты 13 и 14: AES-256, нулевые ключ и IV. */
    d2k_suite s;
    CHECK(d2k_suite_of(0x1302, &s) == 0 && s.hash_len == 48 && s.key_len == 32);
    uint8_t key[32] = {0}, iv[12] = {0}, pt[16] = {0}, out[64], back[16];
    CHECK(d2k_suite_seal(&s, key, iv, NULL, 0, pt, 0, out) == 0);
    CHECK(same(out, "530f8afbc74536b9a963b4f1c4cb738b"));
    CHECK(d2k_suite_seal(&s, key, iv, NULL, 0, pt, 16, out) == 0);
    CHECK(same(out, "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"));
    CHECK(d2k_suite_open(&s, key, iv, NULL, 0, out, 32, back) == 0 && !memcmp(back, pt, 16));
    out[31] ^= 1;
    CHECK(d2k_suite_open(&s, key, iv, NULL, 0, out, 32, back) == -1);

    /* RFC 8439 §2.8.2: AEAD ChaCha20-Poly1305. */
    CHECK(d2k_suite_of(0x1303, &s) == 0 && s.hash_len == 32 && s.key_len == 32);
    const char *msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    uint8_t k2[32], n2[12], aad[12], ct[200], pt2[200];
    unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", k2);
    unhex("070000004041424344454647", n2);
    unhex("50515253c0c1c2c3c4c5c6c7", aad);
    size_t n = strlen(msg);
    CHECK(d2k_suite_seal(&s, k2, n2, aad, 12, (const uint8_t *)msg, n, ct) == 0);
    CHECK(same(ct, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"));
    CHECK(same(ct + n, "1ae10b594f09e26a7e902ecbd0600691"));
    CHECK(d2k_suite_open(&s, k2, n2, aad, 12, ct, n + 16, pt2) == 0 && !memcmp(pt2, msg, n));
    ct[0] ^= 1;
    CHECK(d2k_suite_open(&s, k2, n2, aad, 12, ct, n + 16, pt2) == -1);

    CHECK(d2k_suite_of(0x1304, &s) == -1);
    if (fails) return 1;
    puts("TLS 1.3 suites 0x1302/0x1303: standard vectors PASS");
    return 0;
}
