#include "d2k_keccak.h"

#include <string.h>

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const unsigned ROT[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

static uint64_t rol(uint64_t x, unsigned n)
{
    return n ? (x << n) | (x >> (64 - n)) : x;
}

static void keccakf(uint64_t a[25])
{
    for (int round = 0; round < 24; round++) {
        uint64_t c[5], d[5], b[25];
        for (int x = 0; x < 5; x++)
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; x++)
            d[x] = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);
        for (int i = 0; i < 25; i++)
            a[i] ^= d[i % 5];
        /* ρ и π: B[y, 2x+3y] = rot(A[x,y], r[x,y]) */
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(a[x + 5 * y], ROT[x + 5 * y]);
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        a[0] ^= RC[round];
    }
}

/* Состояние — 25 слов little-endian: байт i лежит в слове i/8, сдвиг 8*(i%8). */
static void xor_byte(uint64_t s[25], size_t i, uint8_t v)
{
    s[i / 8] ^= (uint64_t)v << (8 * (i % 8));
}

static uint8_t get_byte(const uint64_t s[25], size_t i)
{
    return (uint8_t)(s[i / 8] >> (8 * (i % 8)));
}

void d2k_keccak_init(d2k_keccak *k, size_t rate, uint8_t domain)
{
    memset(k, 0, sizeof(*k));
    k->rate = rate;
    k->domain = domain;
}

void d2k_keccak_absorb(d2k_keccak *k, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        xor_byte(k->s, k->pos++, p[i]);
        if (k->pos == k->rate) {
            keccakf(k->s);
            k->pos = 0;
        }
    }
}

void d2k_keccak_squeeze(d2k_keccak *k, uint8_t *out, size_t n)
{
    if (!k->squeezing) {
        xor_byte(k->s, k->pos, k->domain);
        xor_byte(k->s, k->rate - 1, 0x80);
        keccakf(k->s);
        k->pos = 0;
        k->squeezing = 1;
    }
    for (size_t i = 0; i < n; i++) {
        if (k->pos == k->rate) {
            keccakf(k->s);
            k->pos = 0;
        }
        out[i] = get_byte(k->s, k->pos++);
    }
}

static void once(size_t rate, uint8_t domain, const uint8_t *p, size_t n,
                 uint8_t *out, size_t m)
{
    d2k_keccak k;
    d2k_keccak_init(&k, rate, domain);
    d2k_keccak_absorb(&k, p, n);
    d2k_keccak_squeeze(&k, out, m);
}

void d2k_sha3_256(const uint8_t *p, size_t n, uint8_t out[32]) { once(136, 0x06, p, n, out, 32); }
void d2k_sha3_512(const uint8_t *p, size_t n, uint8_t out[64]) { once(72, 0x06, p, n, out, 64); }
void d2k_shake128(const uint8_t *p, size_t n, uint8_t *o, size_t m) { once(168, 0x1F, p, n, o, m); }
void d2k_shake256(const uint8_t *p, size_t n, uint8_t *o, size_t m) { once(136, 0x1F, p, n, o, m); }
