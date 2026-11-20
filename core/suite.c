#include "d2k_suite.h"
#include "d2k_crypto.h"

#include <string.h>

/* --- SHA-512 / SHA-384 (FIPS 180-4) --------------------------------------- */

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL,
};

static uint64_t ror64(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }

static void sha512_block(uint64_t h[8], const uint8_t b[128])
{
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = v << 8 | b[8 * i + j];
        w[i] = v;
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = hh + S1 + ch + K512[i] + w[i];
        uint64_t S0 = ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39);
        uint64_t mj = (a & bb) ^ (a & c) ^ (bb & c);
        uint64_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha512_family(const uint64_t iv[8], const uint8_t *p, size_t n,
                          uint8_t *out, size_t olen)
{
    uint64_t h[8];
    memcpy(h, iv, sizeof(h));
    size_t full = n / 128 * 128;
    for (size_t i = 0; i < full; i += 128) sha512_block(h, p + i);
    uint8_t last[256];
    size_t rem = n - full;
    memset(last, 0, sizeof(last));
    memcpy(last, p + full, rem);
    last[rem] = 0x80;
    size_t blocks = rem + 1 + 16 <= 128 ? 1 : 2;
    uint64_t bits = (uint64_t)n * 8;
    for (int j = 0; j < 8; j++) last[blocks * 128 - 1 - j] = (uint8_t)(bits >> (8 * j));
    for (size_t i = 0; i < blocks; i++) sha512_block(h, last + 128 * i);
    for (size_t i = 0; i < olen; i++) out[i] = (uint8_t)(h[i / 8] >> (56 - 8 * (i % 8)));
}

void d2k_sha512(const uint8_t *p, size_t n, uint8_t out[64])
{
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
    sha512_family(iv, p, n, out, 64);
}

void d2k_sha384(const uint8_t *p, size_t n, uint8_t out[48])
{
    static const uint64_t iv[8] = {
        0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,0x9159015a3070dd17ULL,0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL};
    sha512_family(iv, p, n, out, 48);
}

/* --- Шифр: хэш, HMAC, HKDF ------------------------------------------------- */

int d2k_suite_of(uint16_t id, d2k_suite *s)
{
    d2k_suite t = {id, 32, 16};
    if (id == 0x1302) { t.hash_len = 48; t.key_len = 32; }
    else if (id == 0x1303) { t.key_len = 32; }
    else if (id != 0x1301) return -1;
    if (s) *s = t;
    return 0;
}

void d2k_suite_hash(const d2k_suite *s, const uint8_t *p, size_t n, uint8_t *out)
{
    if (s->hash_len == 48) d2k_sha384(p, n, out);
    else d2k_sha256(p, n, out);
}

/* HMAC: блок 64 байта у SHA-256, 128 у SHA-384. Сообщение HMAC в TLS
   короткое (хэш, метка, контекст) — собираем внутренний ввод в буфер. */
void d2k_suite_hmac(const d2k_suite *s, const uint8_t *key, size_t klen,
                    const uint8_t *msg, size_t mlen, uint8_t *out)
{
    if (s->hash_len == 32) {
        d2k_hmac_sha256(key, klen, msg, mlen, out);
        return;
    }
    uint8_t k[128], ipad[128 + 512], opad[128 + 48], ih[48];
    memset(k, 0, sizeof(k));
    if (klen > 128) d2k_sha384(key, klen, k);
    else memcpy(k, key, klen);
    if (mlen > 512) mlen = 512;   /* вызовы в этом модуле короче */
    for (int i = 0; i < 128; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    memcpy(ipad + 128, msg, mlen);
    d2k_sha384(ipad, 128 + mlen, ih);
    memcpy(opad + 128, ih, 48);
    d2k_sha384(opad, 128 + 48, out);
}

void d2k_suite_extract(const d2k_suite *s, const uint8_t *salt, size_t slen,
                       const uint8_t *ikm, size_t ilen, uint8_t *out)
{
    uint8_t zero[D2K_HASH_MAX] = {0};
    if (!salt || !slen) { salt = zero; slen = s->hash_len; }
    d2k_suite_hmac(s, salt, slen, ikm, ilen, out);
}

int d2k_suite_expand_label(const d2k_suite *s, const uint8_t *secret,
                           const char *label, const uint8_t *ctx, size_t clen,
                           uint8_t *out, size_t olen)
{
    uint8_t info[2 + 1 + 255 + 1 + 255 + 1];
    size_t ll = strlen(label);
    if (6 + ll > 255 || clen > 255 || olen > 255 * s->hash_len) return -1;
    size_t p = 0;
    info[p++] = (uint8_t)(olen >> 8);
    info[p++] = (uint8_t)olen;
    info[p++] = (uint8_t)(6 + ll);
    memcpy(info + p, "tls13 ", 6); p += 6;
    memcpy(info + p, label, ll); p += ll;
    info[p++] = (uint8_t)clen;
    if (clen) { memcpy(info + p, ctx, clen); p += clen; }
    uint8_t t[D2K_HASH_MAX], in[D2K_HASH_MAX + sizeof(info) + 1];
    size_t tl = 0, done = 0;
    for (uint8_t c = 1; done < olen; c++) {
        memcpy(in, t, tl);
        memcpy(in + tl, info, p);
        in[tl + p] = c;
        d2k_suite_hmac(s, secret, s->hash_len, in, tl + p + 1, t);
        tl = s->hash_len;
        size_t k = olen - done < tl ? olen - done : tl;
        memcpy(out + done, t, k);
        done += k;
    }
    return 0;
}

/* --- AES-256 (FIPS 197) ----------------------------------------------------- */

static const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

static uint8_t xt(uint8_t a) { return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0)); }

typedef struct { uint8_t rk[15][16]; } aes256_ks;

static void aes256_expand(const uint8_t key[32], aes256_ks *ks)
{
    uint8_t w[240];
    memcpy(w, key, 32);
    uint8_t rcon = 1;
    for (int i = 8; i < 60; i++) {
        uint8_t t[4];
        memcpy(t, w + 4 * (i - 1), 4);
        if (i % 8 == 0) {
            uint8_t u = t[0];
            t[0] = (uint8_t)(SBOX[t[1]] ^ rcon); t[1] = SBOX[t[2]]; t[2] = SBOX[t[3]]; t[3] = SBOX[u];
            rcon = xt(rcon);
        } else if (i % 8 == 4) {
            for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];
        }
        for (int j = 0; j < 4; j++) w[4 * i + j] = (uint8_t)(w[4 * (i - 8) + j] ^ t[j]);
    }
    memcpy(ks->rk, w, 240);
}

static void aes256_block(const aes256_ks *ks, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ ks->rk[0][i];
    for (int r = 1; r <= 14; r++) {
        uint8_t t[16];
        for (int i = 0; i < 16; i++) t[i] = SBOX[s[i]];
        /* ShiftRows: столбцы по 4 байта, строка i сдвигается на i. */
        for (int c = 0; c < 4; c++)
            for (int rr = 0; rr < 4; rr++) s[4 * c + rr] = t[4 * ((c + rr) % 4) + rr];
        if (r != 14)
            for (int c = 0; c < 4; c++) {
                uint8_t *col = s + 4 * c, a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                uint8_t all = a0 ^ a1 ^ a2 ^ a3;
                col[0] ^= all ^ xt(a0 ^ a1);
                col[1] ^= all ^ xt(a1 ^ a2);
                col[2] ^= all ^ xt(a2 ^ a3);
                col[3] ^= all ^ xt(a3 ^ a0);
            }
        for (int i = 0; i < 16; i++) s[i] ^= ks->rk[r][i];
    }
    memcpy(out, s, 16);
}

void d2k_aes256_ecb(const uint8_t key[32], const uint8_t in[16], uint8_t out[16])
{
    aes256_ks ks;
    aes256_expand(key, &ks);
    aes256_block(&ks, in, out);
}

/* GCM на AES-256 (SP 800-38D): GHASH — общий с AES-128 (d2k_ghash_for_test). */
static void gcm256(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
                   size_t alen, const uint8_t *in, size_t n, uint8_t *out, int enc,
                   uint8_t tag[16])
{
    aes256_ks ks;
    aes256_expand(key, &ks);
    uint8_t h[16] = {0}, j0[16], ctr[16], ks_blk[16], s[16];
    aes256_block(&ks, h, h);
    memcpy(j0, nonce, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    const uint8_t *ct = enc ? out : in;
    memcpy(ctr, j0, 16);
    for (size_t i = 0; i < n; i += 16) {
        for (int k = 15; k >= 12; k--) if (++ctr[k]) break;
        aes256_block(&ks, ctr, ks_blk);
        size_t m = n - i < 16 ? n - i : 16;
        for (size_t k = 0; k < m; k++) out[i + k] = in[i + k] ^ ks_blk[k];
    }
    d2k_ghash_for_test(h, aad, alen, ct, n, s);
    aes256_block(&ks, j0, ks_blk);
    for (int k = 0; k < 16; k++) tag[k] = s[k] ^ ks_blk[k];
}

/* --- ChaCha20-Poly1305 (RFC 8439) ------------------------------------------ */

static uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

#define QR(a, b, c, d) \
    a += b; d ^= a; d = rol32(d, 16); c += d; b ^= c; b = rol32(b, 12); \
    a += b; d ^= a; d = rol32(d, 8);  c += d; b ^= c; b = rol32(b, 7)

void d2k_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                        uint8_t out[64])
{
    uint32_t s[16], x[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = le32(key + 4 * i);
    s[12] = counter;
    for (int i = 0; i < 3; i++) s[13 + i] = le32(nonce + 4 * i);
    memcpy(x, s, sizeof(x));
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]); QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]); QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + s[i];
        out[4 * i] = (uint8_t)v; out[4 * i + 1] = (uint8_t)(v >> 8);
        out[4 * i + 2] = (uint8_t)(v >> 16); out[4 * i + 3] = (uint8_t)(v >> 24);
    }
}

/* Poly1305: аккумулятор по модулю 2^130-5 в пяти 26-битных лимбах. */
void d2k_poly1305(const uint8_t key[32], const uint8_t *m, size_t n, uint8_t tag[16])
{
    uint32_t r0 = le32(key) & 0x3ffffff, r1 = (le32(key + 3) >> 2) & 0x3ffff03,
             r2 = (le32(key + 6) >> 4) & 0x3ffc0ff, r3 = (le32(key + 9) >> 6) & 0x3f03fff,
             r4 = (le32(key + 12) >> 8) & 0x00fffff;
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    while (n) {
        uint8_t blk[17] = {0};
        size_t k = n < 16 ? n : 16;
        memcpy(blk, m, k);
        blk[k] = 1;
        h0 += le32(blk) & 0x3ffffff;
        h1 += (le32(blk + 3) >> 2) & 0x3ffffff;
        h2 += (le32(blk + 6) >> 4) & 0x3ffffff;
        h3 += (le32(blk + 9) >> 6) & 0x3ffffff;
        h4 += (le32(blk + 12) >> 8) | ((uint32_t)blk[16] << 24);
        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;
        uint32_t c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        m += k; n -= k;
    }
    uint32_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff; h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    /* h - p: если не отрицательно — берём его. */
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);
    uint32_t mask = (g4 >> 31) - 1;   /* все единицы, если g4 >= 0 */
    h0 = (h0 & ~mask) | (g0 & mask); h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask); h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);
    uint64_t f0 = ((h0) | (h1 << 26)) + (uint64_t)le32(key + 16);
    uint64_t f1 = ((h1 >> 6) | (h2 << 20)) + (uint64_t)le32(key + 20) + (f0 >> 32);
    uint64_t f2 = ((h2 >> 12) | (h3 << 14)) + (uint64_t)le32(key + 24) + (f1 >> 32);
    uint64_t f3 = ((h3 >> 18) | (h4 << 8)) + (uint64_t)le32(key + 28) + (f2 >> 32);
    uint32_t w[4] = {(uint32_t)f0, (uint32_t)f1, (uint32_t)f2, (uint32_t)f3};
    for (int i = 0; i < 4; i++) {
        tag[4 * i] = (uint8_t)w[i]; tag[4 * i + 1] = (uint8_t)(w[i] >> 8);
        tag[4 * i + 2] = (uint8_t)(w[i] >> 16); tag[4 * i + 3] = (uint8_t)(w[i] >> 24);
    }
}

static void chacha_xor(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in,
                       size_t n, uint8_t *out)
{
    uint8_t ks[64];
    for (size_t i = 0; i < n; i += 64) {
        d2k_chacha20_block(key, (uint32_t)(1 + i / 64), nonce, ks);
        size_t m = n - i < 64 ? n - i : 64;
        for (size_t k = 0; k < m; k++) out[i + k] = in[i + k] ^ ks[k];
    }
}

static void chacha_tag(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
                       size_t alen, const uint8_t *ct, size_t n, uint8_t tag[16])
{
    uint8_t blk[64], otk[32];
    d2k_chacha20_block(key, 0, nonce, blk);
    memcpy(otk, blk, 32);
    /* aad ‖ pad16 ‖ ct ‖ pad16 ‖ len(aad) ‖ len(ct): потоком по 16 байт
       неудобно без контекста — собираем во временный буфер записи TLS. */
    static __thread uint8_t mac[16 + 16 + 18432 + 16 + 16];
    size_t p = 0;
    if (alen > 16 || n > 18432) { memset(tag, 0, 16); return; }
    memcpy(mac, aad, alen); p = alen;
    while (p % 16) mac[p++] = 0;
    memcpy(mac + p, ct, n); p += n;
    while (p % 16) mac[p++] = 0;
    for (int i = 0; i < 8; i++) mac[p + i] = (uint8_t)((uint64_t)alen >> (8 * i));
    for (int i = 0; i < 8; i++) mac[p + 8 + i] = (uint8_t)((uint64_t)n >> (8 * i));
    d2k_poly1305(otk, mac, p + 16, tag);
}

static int ct_eq16(const uint8_t *a, const uint8_t *b)
{
    uint8_t d = 0;
    for (int i = 0; i < 16; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

int d2k_suite_seal(const d2k_suite *s, const uint8_t *key, const uint8_t nonce[12],
                   const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
                   uint8_t *out)
{
    switch (s->id) {
    case 0x1301:
        return d2k_aes128_gcm_encrypt(key, nonce, aad, alen, in, n, out, out + n);
    case 0x1302:
        gcm256(key, nonce, aad, alen, in, n, out, 1, out + n);
        return 0;
    case 0x1303:
        if (alen > 16 || n > 18432) return -1;
        chacha_xor(key, nonce, in, n, out);
        chacha_tag(key, nonce, aad, alen, out, n, out + n);
        return 0;
    default:
        return -1;
    }
}

int d2k_suite_open(const d2k_suite *s, const uint8_t *key, const uint8_t nonce[12],
                   const uint8_t *aad, size_t alen, const uint8_t *ct, size_t n,
                   uint8_t *out)
{
    if (n < 16) return -1;
    size_t m = n - 16;
    uint8_t tag[16];
    switch (s->id) {
    case 0x1301:
        return d2k_aes128_gcm_decrypt(key, nonce, aad, alen, ct, n, out);
    case 0x1302: {
        /* Тег сверяется до публикации текста: считаем во временный буфер. */
        static __thread uint8_t tmp[18432];
        if (m > sizeof(tmp)) return -1;
        gcm256(key, nonce, aad, alen, ct, m, tmp, 0, tag);
        if (!ct_eq16(tag, ct + m)) return -1;
        memcpy(out, tmp, m);
        return 0;
    }
    case 0x1303:
        if (alen > 16 || m > 18432) return -1;
        chacha_tag(key, nonce, aad, alen, ct, m, tag);
        if (!ct_eq16(tag, ct + m)) return -1;
        chacha_xor(key, nonce, ct, m, out);
        return 0;
    default:
        return -1;
    }
}

/* --- Расписание ключей TLS 1.3 (RFC 8446 §7.1) ----------------------------- */

static int derive(const d2k_suite *s, const uint8_t *secret, const char *label,
                  const uint8_t *msgs, size_t n, uint8_t *out)
{
    uint8_t th[D2K_HASH_MAX];
    d2k_suite_hash(s, msgs, n, th);
    return d2k_suite_expand_label(s, secret, label, th, s->hash_len, out, s->hash_len);
}

int d2k_suite_schedule_hs(const d2k_suite *s, const uint8_t *ikm, size_t ilen,
                          const uint8_t *tr, size_t tlen,
                          uint8_t *c_hs, uint8_t *s_hs, uint8_t *hs)
{
    uint8_t zero[D2K_HASH_MAX] = {0}, early[D2K_HASH_MAX], derived[D2K_HASH_MAX],
            h[D2K_HASH_MAX];
    d2k_suite_extract(s, zero, s->hash_len, zero, s->hash_len, early);
    if (derive(s, early, "derived", NULL, 0, derived)) return -1;
    d2k_suite_extract(s, derived, s->hash_len, ikm, ilen, h);
    if (derive(s, h, "c hs traffic", tr, tlen, c_hs) || derive(s, h, "s hs traffic", tr, tlen, s_hs))
        return -1;
    if (hs) memcpy(hs, h, s->hash_len);
    return 0;
}

int d2k_suite_schedule_ap(const d2k_suite *s, const uint8_t *hs,
                          const uint8_t *tr, size_t tlen, uint8_t *c_ap, uint8_t *s_ap)
{
    uint8_t zero[D2K_HASH_MAX] = {0}, derived[D2K_HASH_MAX], master[D2K_HASH_MAX];
    if (derive(s, hs, "derived", NULL, 0, derived)) return -1;
    d2k_suite_extract(s, derived, s->hash_len, zero, s->hash_len, master);
    if (derive(s, master, "c ap traffic", tr, tlen, c_ap) || derive(s, master, "s ap traffic", tr, tlen, s_ap))
        return -1;
    return 0;
}

int d2k_suite_finished(const d2k_suite *s, const uint8_t *secret,
                       const uint8_t *tr, size_t tlen, uint8_t *out)
{
    uint8_t fk[D2K_HASH_MAX], th[D2K_HASH_MAX];
    if (d2k_suite_expand_label(s, secret, "finished", NULL, 0, fk, s->hash_len)) return -1;
    d2k_suite_hash(s, tr, tlen, th);
    d2k_suite_hmac(s, fk, s->hash_len, th, s->hash_len, out);
    return 0;
}

int d2k_suite_traffic(const d2k_suite *s, const uint8_t *secret, uint8_t *key,
                      uint8_t iv[12])
{
    if (d2k_suite_expand_label(s, secret, "key", NULL, 0, key, s->key_len) ||
        d2k_suite_expand_label(s, secret, "iv", NULL, 0, iv, 12))
        return -1;
    return 0;
}
