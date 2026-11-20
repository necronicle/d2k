/* ML-KEM-768, FIPS 203. Прямолинейная арифметика по модулю q без
 * Монтгомери: роутеру нужен один обмен на рукопожатие, скорость не узкое
 * место, а прозрачность против стандарта важнее. */
#include "d2k_mlkem.h"
#include "d2k_keccak.h"

#include <string.h>

#define N 256
#define Q 3329
#define K 3
#define ETA1 2
#define ETA2 2
#define DU 10
#define DV 4

typedef struct { int16_t c[N]; } poly;

/* zeta^BitRev7(i) mod q, zeta = 17 (FIPS 203 §4.3). */
static __thread int16_t zetas[128], gammas[128];
static __thread int tables_ready;

static unsigned bitrev7(unsigned x)
{
    unsigned r = 0;
    for (int i = 0; i < 7; i++)
        r |= ((x >> i) & 1u) << (6 - i);
    return r;
}

static int32_t powmod(int32_t b, unsigned e)
{
    int32_t r = 1;
    b %= Q;
    while (e) {
        if (e & 1u) r = (r * b) % Q;
        b = (b * b) % Q;
        e >>= 1;
    }
    return r;
}

static void tables(void)
{
    if (tables_ready)
        return;
    for (unsigned i = 0; i < 128; i++) {
        zetas[i] = (int16_t)powmod(17, bitrev7(i));
        gammas[i] = (int16_t)powmod(17, 2 * bitrev7(i) + 1);
    }
    tables_ready = 1;
}

static int16_t md(int32_t x)
{
    x %= Q;
    if (x < 0) x += Q;
    return (int16_t)x;
}

static void ntt(poly *f)
{
    unsigned i = 1;
    for (unsigned len = 128; len >= 2; len /= 2)
        for (unsigned start = 0; start < N; start += 2 * len) {
            int32_t z = zetas[i++];
            for (unsigned j = start; j < start + len; j++) {
                int16_t t = md(z * f->c[j + len]);
                f->c[j + len] = md(f->c[j] - t);
                f->c[j] = md(f->c[j] + t);
            }
        }
}

static void invntt(poly *f)
{
    unsigned i = 127;
    for (unsigned len = 2; len <= 128; len *= 2)
        for (unsigned start = 0; start < N; start += 2 * len) {
            int32_t z = zetas[i--];
            for (unsigned j = start; j < start + len; j++) {
                int16_t t = f->c[j];
                f->c[j] = md(t + f->c[j + len]);
                f->c[j + len] = md(z * (f->c[j + len] - t));
            }
        }
    for (unsigned j = 0; j < N; j++)
        f->c[j] = md(f->c[j] * 3303);   /* 128^-1 mod q */
}

/* h += f ∘ g в представлении NTT (алг. 11, 12). */
static void mul_acc(poly *h, const poly *f, const poly *g)
{
    for (unsigned i = 0; i < 128; i++) {
        int32_t a0 = f->c[2 * i], a1 = f->c[2 * i + 1];
        int32_t b0 = g->c[2 * i], b1 = g->c[2 * i + 1];
        int32_t gm = gammas[i];
        int32_t c0 = md(a0 * b0 + md(a1 * b1) * gm);
        int32_t c1 = md(a0 * b1 + a1 * b0);
        h->c[2 * i] = md(h->c[2 * i] + c0);
        h->c[2 * i + 1] = md(h->c[2 * i + 1] + c1);
    }
}

/* SampleNTT (алг. 7): rho‖j‖i → коэффициенты < q из потока SHAKE128. */
static void sample_ntt(poly *a, const uint8_t rho[32], uint8_t j, uint8_t i)
{
    d2k_keccak x;
    d2k_keccak_init(&x, 168, 0x1F);
    d2k_keccak_absorb(&x, rho, 32);
    d2k_keccak_absorb(&x, &j, 1);
    d2k_keccak_absorb(&x, &i, 1);
    unsigned n = 0;
    while (n < N) {
        uint8_t c[3];
        d2k_keccak_squeeze(&x, c, 3);
        int d1 = c[0] + 256 * (c[1] & 15);
        int d2 = (c[1] >> 4) + 16 * c[2];
        if (d1 < Q) a->c[n++] = (int16_t)d1;
        if (d2 < Q && n < N) a->c[n++] = (int16_t)d2;
    }
}

/* SamplePolyCBD_eta (алг. 8) из PRF_eta(s, b) = SHAKE256(s‖b, 64·eta). */
static void cbd(poly *f, const uint8_t s[32], uint8_t b, unsigned eta)
{
    uint8_t in[33], buf[64 * 3];
    memcpy(in, s, 32);
    in[32] = b;
    d2k_shake256(in, 33, buf, 64 * eta);
    for (unsigned i = 0; i < N; i++) {
        int x = 0, y = 0;
        for (unsigned j = 0; j < eta; j++) {
            unsigned bx = 2 * i * eta + j, by = 2 * i * eta + eta + j;
            x += (buf[bx / 8] >> (bx % 8)) & 1;
            y += (buf[by / 8] >> (by % 8)) & 1;
        }
        f->c[i] = md(x - y);
    }
}

/* ByteEncode_d / ByteDecode_d (алг. 5, 6). */
static void encode(uint8_t *out, const poly *f, unsigned d)
{
    memset(out, 0, 32 * d);
    unsigned bit = 0;
    for (unsigned i = 0; i < N; i++)
        for (unsigned b = 0; b < d; b++, bit++)
            out[bit / 8] |= (uint8_t)(((unsigned)f->c[i] >> b & 1u) << (bit % 8));
}

static void decode(poly *f, const uint8_t *in, unsigned d)
{
    unsigned bit = 0;
    for (unsigned i = 0; i < N; i++) {
        unsigned v = 0;
        for (unsigned b = 0; b < d; b++, bit++)
            v |= (unsigned)((in[bit / 8] >> (bit % 8)) & 1) << b;
        f->c[i] = (int16_t)(d == 12 ? v % Q : v);
    }
}

static void compress(poly *f, unsigned d)
{
    for (unsigned i = 0; i < N; i++) {
        uint32_t x = (uint32_t)f->c[i];
        f->c[i] = (int16_t)((((x << d) + Q / 2) / Q) & ((1u << d) - 1));
    }
}

static void decompress(poly *f, unsigned d)
{
    for (unsigned i = 0; i < N; i++) {
        uint32_t y = (uint32_t)f->c[i];
        f->c[i] = (int16_t)((y * Q + (1u << (d - 1))) >> d);
    }
}

static void matrix(poly a[K][K], const uint8_t rho[32])
{
    for (unsigned i = 0; i < K; i++)
        for (unsigned j = 0; j < K; j++)
            sample_ntt(&a[i][j], rho, (uint8_t)j, (uint8_t)i);
}

/* K-PKE.KeyGen (алг. 13). */
static void pke_keygen(const uint8_t d[32], uint8_t ek[1184], uint8_t dkp[1152])
{
    uint8_t in[33], g[64];
    memcpy(in, d, 32);
    in[32] = K;
    d2k_sha3_512(in, 33, g);
    const uint8_t *rho = g, *sigma = g + 32;
    static __thread poly a[K][K];
    poly s[K], e[K], t[K];
    matrix(a, rho);
    uint8_t nn = 0;
    for (unsigned i = 0; i < K; i++) cbd(&s[i], sigma, nn++, ETA1);
    for (unsigned i = 0; i < K; i++) cbd(&e[i], sigma, nn++, ETA1);
    for (unsigned i = 0; i < K; i++) { ntt(&s[i]); ntt(&e[i]); }
    for (unsigned i = 0; i < K; i++) {
        t[i] = e[i];
        for (unsigned j = 0; j < K; j++) mul_acc(&t[i], &a[i][j], &s[j]);
    }
    for (unsigned i = 0; i < K; i++) {
        encode(ek + 384 * i, &t[i], 12);
        encode(dkp + 384 * i, &s[i], 12);
    }
    memcpy(ek + 384 * K, rho, 32);
}

/* K-PKE.Encrypt (алг. 14). */
static void pke_encrypt(const uint8_t ek[1184], const uint8_t m[32],
                        const uint8_t r[32], uint8_t c[1088])
{
    static __thread poly a[K][K];
    poly t[K], y[K], e1[K], e2, u[K], v, mu;
    for (unsigned i = 0; i < K; i++) decode(&t[i], ek + 384 * i, 12);
    matrix(a, ek + 384 * K);
    uint8_t nn = 0;
    for (unsigned i = 0; i < K; i++) cbd(&y[i], r, nn++, ETA1);
    for (unsigned i = 0; i < K; i++) cbd(&e1[i], r, nn++, ETA2);
    cbd(&e2, r, nn, ETA2);
    for (unsigned i = 0; i < K; i++) ntt(&y[i]);
    for (unsigned i = 0; i < K; i++) {
        memset(&u[i], 0, sizeof(poly));
        for (unsigned j = 0; j < K; j++) mul_acc(&u[i], &a[j][i], &y[j]);
        invntt(&u[i]);
        for (unsigned n = 0; n < N; n++) u[i].c[n] = md(u[i].c[n] + e1[i].c[n]);
    }
    memset(&v, 0, sizeof(v));
    for (unsigned j = 0; j < K; j++) mul_acc(&v, &t[j], &y[j]);
    invntt(&v);
    decode(&mu, m, 1);
    decompress(&mu, 1);
    for (unsigned n = 0; n < N; n++) v.c[n] = md(v.c[n] + e2.c[n] + mu.c[n]);
    for (unsigned i = 0; i < K; i++) {
        compress(&u[i], DU);
        encode(c + 32 * DU * i, &u[i], DU);
    }
    compress(&v, DV);
    encode(c + 32 * DU * K, &v, DV);
}

/* K-PKE.Decrypt (алг. 15). */
static void pke_decrypt(const uint8_t dkp[1152], const uint8_t c[1088], uint8_t m[32])
{
    poly u[K], v, s, w;
    for (unsigned i = 0; i < K; i++) {
        decode(&u[i], c + 32 * DU * i, DU);
        decompress(&u[i], DU);
        ntt(&u[i]);
    }
    decode(&v, c + 32 * DU * K, DV);
    decompress(&v, DV);
    memset(&w, 0, sizeof(w));
    for (unsigned i = 0; i < K; i++) {
        decode(&s, dkp + 384 * i, 12);
        mul_acc(&w, &s, &u[i]);
    }
    invntt(&w);
    for (unsigned n = 0; n < N; n++) w.c[n] = md(v.c[n] - w.c[n]);
    compress(&w, 1);
    encode(m, &w, 1);
}

void d2k_mlkem768_keygen(const uint8_t d[32], const uint8_t z[32],
                         uint8_t ek[D2K_MLKEM768_EK], uint8_t dk[D2K_MLKEM768_DK])
{
    tables();
    pke_keygen(d, ek, dk);
    memcpy(dk + 1152, ek, 1184);
    d2k_sha3_256(ek, 1184, dk + 1152 + 1184);
    memcpy(dk + 1152 + 1184 + 32, z, 32);
}

/* Проверка модуля ek (FIPS 203 §7.2): ByteEncode12(ByteDecode12(t̂)) == t̂. */
static int ek_valid(const uint8_t ek[1184])
{
    uint8_t back[384];
    poly p;
    for (unsigned i = 0; i < K; i++) {
        decode(&p, ek + 384 * i, 12);
        encode(back, &p, 12);
        if (memcmp(back, ek + 384 * i, 384) != 0)
            return 0;
    }
    return 1;
}

int d2k_mlkem768_encaps(const uint8_t ek[D2K_MLKEM768_EK], const uint8_t m[32],
                        uint8_t ct[D2K_MLKEM768_CT], uint8_t ss[D2K_MLKEM768_SS])
{
    tables();
    if (!ek_valid(ek))
        return -1;
    uint8_t in[64], g[64];
    memcpy(in, m, 32);
    d2k_sha3_256(ek, 1184, in + 32);
    d2k_sha3_512(in, 64, g);
    pke_encrypt(ek, m, g + 32, ct);
    memcpy(ss, g, 32);
    return 0;
}

void d2k_mlkem768_decaps(const uint8_t dk[D2K_MLKEM768_DK],
                         const uint8_t ct[D2K_MLKEM768_CT],
                         uint8_t ss[D2K_MLKEM768_SS])
{
    tables();
    const uint8_t *dkp = dk, *ek = dk + 1152, *h = dk + 1152 + 1184,
                  *z = dk + 1152 + 1184 + 32;
    uint8_t m[32], in[64], g[64], kbar[32];
    static __thread uint8_t c2[1088], zc[32 + 1088];
    pke_decrypt(dkp, ct, m);
    memcpy(in, m, 32);
    memcpy(in + 32, h, 32);
    d2k_sha3_512(in, 64, g);
    memcpy(zc, z, 32);
    memcpy(zc + 32, ct, 1088);
    d2k_shake256(zc, sizeof(zc), kbar, 32);
    pke_encrypt(ek, m, g + 32, c2);
    /* Сравнение без раннего выхода. */
    uint8_t diff = 0;
    for (unsigned i = 0; i < 1088; i++)
        diff |= (uint8_t)(c2[i] ^ ct[i]);
    uint8_t mask = (uint8_t)-(uint8_t)(diff != 0);   /* 0xff — подмена */
    for (unsigned i = 0; i < 32; i++)
        ss[i] = (uint8_t)((g[i] & ~mask) | (kbar[i] & mask));
}
