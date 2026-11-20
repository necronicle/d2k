/* SHA-3/SHAKE (FIPS 202) и ML-KEM-768 (FIPS 203).
 * Значения ML-KEM сняты с реализации, сверенной с OpenSSL 3.6 (ключи из
 * того же зерна байт в байт, шифрование и расшифровка в обе стороны,
 * неявный отказ); здесь они держат регрессию без внешней библиотеки. */
#include <stdio.h>
#include <string.h>
#include "d2k_keccak.h"
#include "d2k_mlkem.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static int hexeq(const uint8_t *b, size_t n, const char *hex)
{
    char s[3];
    for (size_t i = 0; i < n; i++) {
        snprintf(s, sizeof s, "%02x", b[i]);
        if (hex[2 * i] != s[0] || hex[2 * i + 1] != s[1]) return 0;
    }
    return hex[2 * n] == 0;
}

int main(void)
{
    uint8_t h[64], o[32];
    d2k_sha3_256((const uint8_t *)"", 0, h);
    CHECK(hexeq(h, 32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
    d2k_sha3_256((const uint8_t *)"abc", 3, h);
    CHECK(hexeq(h, 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
    d2k_sha3_512((const uint8_t *)"abc", 3, h);
    CHECK(hexeq(h, 64, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
    d2k_shake128((const uint8_t *)"", 0, o, 32);
    CHECK(hexeq(o, 32, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"));
    d2k_shake256((const uint8_t *)"", 0, o, 32);
    CHECK(hexeq(o, 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"));
    /* Потоковое выжимание равно разовому. */
    uint8_t a[400], b[400];
    d2k_shake128((const uint8_t *)"x", 1, a, 400);
    d2k_keccak k;
    d2k_keccak_init(&k, 168, 0x1F);
    d2k_keccak_absorb(&k, (const uint8_t *)"x", 1);
    for (int i = 0; i < 400; i += 7) d2k_keccak_squeeze(&k, b + i, 400 - i < 7 ? 400 - (size_t)i : 7);
    CHECK(!memcmp(a, b, 400));

    uint8_t seed[64], m[32];
    for (int i = 0; i < 64; i++) seed[i] = (uint8_t)i;
    for (int i = 0; i < 32; i++) m[i] = (uint8_t)(0xa0 + i);
    static uint8_t ek[1184], dk[2400], ct[1088], ss[32], ss2[32];
    d2k_mlkem768_keygen(seed, seed + 32, ek, dk);
    d2k_sha3_256(ek, 1184, h);
    CHECK(hexeq(h, 32, "a24e16d8f8f9383a95b77050f4d9fd2f5733eec1d63ef3c23ebf9918173669a7"));
    d2k_sha3_256(dk, 2400, h);
    CHECK(hexeq(h, 32, "1149f17c3c4ac6ab1e3e2d9d8bd0171355ac0fa31bb8855c48ceade874c0864b"));
    CHECK(d2k_mlkem768_encaps(ek, m, ct, ss) == 0);
    d2k_sha3_256(ct, 1088, h);
    CHECK(hexeq(h, 32, "60b53119fc5473dff3bd6616123adbfaba2cb3f29f8f5a9e6f445fdef2870402"));
    CHECK(hexeq(ss, 32, "d4ab9572cd7c68df84854e27a7ddbfc54f89c74cd96d93fa1db660275420153b"));
    d2k_mlkem768_decaps(dk, ct, ss2);
    CHECK(!memcmp(ss, ss2, 32));
    /* Подмена шифртекста — другой ключ (неявный отказ), не ошибка. */
    ct[100] ^= 0x10;
    d2k_mlkem768_decaps(dk, ct, ss2);
    CHECK(memcmp(ss, ss2, 32) != 0);
    /* Негодный ek (коэффициент >= q) отвергается. */
    ek[0] = 0xff; ek[1] = 0xff;
    CHECK(d2k_mlkem768_encaps(ek, m, ct, ss) == -1);
    if (fails) return 1;
    puts("SHA-3/SHAKE and ML-KEM-768 PASS");
    return 0;
}
