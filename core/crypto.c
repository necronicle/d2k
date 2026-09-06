/* crypto.c — SHA-256, HMAC, HKDF, AES-128, AES-128-GCM.
 *
 * Ничего из этого не изобретено: SHA-256 — FIPS 180-4, HMAC — RFC 2104 /
 * FIPS 198-1, HKDF — RFC 5869, HKDF-Expand-Label — RFC 8446 §7.1, AES —
 * FIPS-197, GCM — NIST SP 800-38D. Проверка — vectors в test_crypto.c, не
 * чтение этого файла глазами.
 *
 * БЕЗ ТАБЛИЦ, ЗАВИСЯЩИХ ОТ СЕКРЕТА (см. d2k_crypto.h). Единственная таблица
 * во всём файле — sha256_k[64], константы раунда SHA-256: индекс там —
 * счётчик раунда 0..63, известный заранее и одинаковый для любого входа, а
 * не байт ключа или текста, поэтому к классу проблемы «кэш утекает секрет
 * через индекс» она отношения не имеет. AES S-box считается формулой (GF(2^8)
 * обращение через возведение в степень), MixColumns и ключевое расписание —
 * той же арифметикой через xtime, GHASH — побитовым сдвигом в GF(2^128):
 * ни одного обращения к памяти, где адрес зависел бы от секретного байта.
 */
#include <string.h>

#include "d2k_crypto.h"

/* ===================== GF(2^8): S-box AES без таблицы ===================== */

/* x*2 в GF(2^8) по модулю многочлена AES x^8+x^4+x^3+x+1 (0x11B). Без ветвлений
 * по значению a: перенос гасится маской, а не if'ом. */
static uint8_t xtime(uint8_t a) {
    uint8_t hi_mask = (uint8_t)(-(int)(a >> 7));
    return (uint8_t)((uint8_t)(a << 1) ^ (uint8_t)(hi_mask & 0x1B));
}

/* Умножение в GF(2^8), тем же способом, но для произвольного второго
 * операнда: 8 шагов сдвиг-и-условный-XOR по битам b, без таблиц и без
 * ветвления по значению a или b (маски вместо if). Нужно только для
 * S-box (возведение в степень) — MixColumns обходится одним xtime. */
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t lsb_mask = (uint8_t)(-(int)(b & 1u));
        p = (uint8_t)(p ^ (uint8_t)(a & lsb_mask));
        a = xtime(a);
        b = (uint8_t)(b >> 1);
    }
    return p;
}

/* S-box Rijndael без единой таблицы: обратный элемент GF(2^8) через x^254
 * (x^(-1) для x!=0; для x==0 степень тоже даёт 0 — ЭТО И ЕСТЬ соглашение
 * AES "обратный нуля — ноль", отдельной ветки не нужно), затем аффинное
 * преобразование FIPS-197 §5.1.1. 254 = 2+4+...+128, поэтому семь
 * возведений в квадрат и шесть умножений дают x^254; преобразование
 * s = inv ^ rotl(inv,1) ^ rotl(inv,2) ^ rotl(inv,3) ^ rotl(inv,4) ^ 0x63
 * сверено на S(0x01)=0x7c и S(0x00)=0x63 при выводе. */
static uint8_t sbox_byte(uint8_t x) {
    uint8_t x2   = gf_mul(x, x);
    uint8_t x4   = gf_mul(x2, x2);
    uint8_t x8   = gf_mul(x4, x4);
    uint8_t x16  = gf_mul(x8, x8);
    uint8_t x32  = gf_mul(x16, x16);
    uint8_t x64  = gf_mul(x32, x32);
    uint8_t x128 = gf_mul(x64, x64);
    uint8_t inv  = gf_mul(x2, x4);   /* x^6   */
    inv = gf_mul(inv, x8);           /* x^14  */
    inv = gf_mul(inv, x16);          /* x^30  */
    inv = gf_mul(inv, x32);          /* x^62  */
    inv = gf_mul(inv, x64);          /* x^126 */
    inv = gf_mul(inv, x128);         /* x^254 */

    uint8_t r1 = (uint8_t)((uint8_t)(inv << 1) | (uint8_t)(inv >> 7));
    uint8_t r2 = (uint8_t)((uint8_t)(inv << 2) | (uint8_t)(inv >> 6));
    uint8_t r3 = (uint8_t)((uint8_t)(inv << 3) | (uint8_t)(inv >> 5));
    uint8_t r4 = (uint8_t)((uint8_t)(inv << 4) | (uint8_t)(inv >> 4));
    return (uint8_t)(inv ^ r1 ^ r2 ^ r3 ^ r4 ^ 0x63);
}

/* ===================== AES-128: расписание ключа и прямой шифр ===================== */

typedef struct {
    uint8_t rk[11][16]; /* 11 раундовых ключей: начальный + 10 раундов Nr=10 */
} aes128_ks;

static void aes128_key_expand(const uint8_t key[16], aes128_ks *ks) {
    uint8_t w[44][4];
    for (int i = 0; i < 4; i++) {
        w[i][0] = key[4 * i];
        w[i][1] = key[4 * i + 1];
        w[i][2] = key[4 * i + 2];
        w[i][3] = key[4 * i + 3];
    }
    uint8_t rcon = 0x01; /* Rcon[1]; дальше удваивается xtime — FIPS-197 таблица 5 */
    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        memcpy(temp, w[i - 1], 4);
        if (i % 4 == 0) {
            uint8_t t0 = temp[0];
            temp[0] = sbox_byte(temp[1]); /* RotWord, затем SubWord */
            temp[1] = sbox_byte(temp[2]);
            temp[2] = sbox_byte(temp[3]);
            temp[3] = sbox_byte(t0);
            temp[0] = (uint8_t)(temp[0] ^ rcon);
            rcon = xtime(rcon);
        }
        for (int j = 0; j < 4; j++) {
            w[i][j] = (uint8_t)(w[i - 4][j] ^ temp[j]);
        }
    }
    for (int r = 0; r < 11; r++) {
        for (int c = 0; c < 4; c++) {
            memcpy(ks->rk[r] + 4 * c, w[4 * r + c], 4);
        }
    }
}

static void sub_bytes(uint8_t st[16]) {
    for (int i = 0; i < 16; i++) {
        st[i] = sbox_byte(st[i]);
    }
}

/* Строка r сдвигается влево на r позиций; состояние хранится по столбцам
 * (st[r+4c] — байт (row r, col c), FIPS-197 §3.4), поэтому новый st[r+4c] —
 * это старый st[r + 4*((c+r) mod 4)]. */
static void shift_rows(uint8_t st[16]) {
    uint8_t tmp[16];
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            tmp[r + 4 * c] = st[r + 4 * ((c + r) % 4)];
        }
    }
    memcpy(st, tmp, 16);
}

static void mix_columns(uint8_t st[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t *s = st + 4 * c;
        uint8_t s0 = s[0], s1 = s[1], s2 = s[2], s3 = s[3];
        s[0] = (uint8_t)(xtime(s0) ^ (uint8_t)(xtime(s1) ^ s1) ^ s2 ^ s3);
        s[1] = (uint8_t)(s0 ^ xtime(s1) ^ (uint8_t)(xtime(s2) ^ s2) ^ s3);
        s[2] = (uint8_t)(s0 ^ s1 ^ xtime(s2) ^ (uint8_t)(xtime(s3) ^ s3));
        s[3] = (uint8_t)((uint8_t)(xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3));
    }
}

static void add_round_key(uint8_t st[16], const uint8_t rk[16]) {
    for (int i = 0; i < 16; i++) {
        st[i] = (uint8_t)(st[i] ^ rk[i]);
    }
}

/* Cipher() из FIPS-197 §5.1: только прямой шифр, обратный (InvSubBytes и
 * т.д.) этому модулю не нужен нигде — см. d2k_crypto.h про CTR и защиту
 * заголовка. */
static void aes128_encrypt_block(const aes128_ks *ks, const uint8_t in[16], uint8_t out[16]) {
    uint8_t st[16];
    memcpy(st, in, 16);
    add_round_key(st, ks->rk[0]);
    for (int round = 1; round <= 9; round++) {
        sub_bytes(st);
        shift_rows(st);
        mix_columns(st);
        add_round_key(st, ks->rk[round]);
    }
    sub_bytes(st);
    shift_rows(st);
    add_round_key(st, ks->rk[10]);
    memcpy(out, st, 16);
}

void d2k_aes128_ecb(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    aes128_ks ks;
    aes128_key_expand(key, &ks);
    aes128_encrypt_block(&ks, in, out);
}

/* ===================== SHA-256 (FIPS 180-4) ===================== */

static uint32_t rotr32(uint32_t x, int n) {
    return (uint32_t)((x >> n) | (x << (32 - n)));
}

/* Первые 32 бита дробной части кубических корней первых 64 простых —
 * FIPS 180-4 §4.2.2. Индекс — номер раунда (0..63), фиксированный порядок,
 * от входа не зависит: к таблицам, о которых предупреждает шапка файла,
 * отношения не имеет. */
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

typedef struct {
    uint32_t h[8];
    uint8_t buf[64];
    size_t buf_len;
    uint64_t total_len; /* байты, для длины в битах в конце */
} sha256_ctx;

static void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int t = 0; t < 16; t++) {
        w[t] = ((uint32_t)block[4 * t] << 24) | ((uint32_t)block[4 * t + 1] << 16) |
               ((uint32_t)block[4 * t + 2] << 8) | (uint32_t)block[4 * t + 3];
    }
    for (int t = 16; t < 64; t++) {
        uint32_t s0 = rotr32(w[t - 15], 7) ^ rotr32(w[t - 15], 18) ^ (w[t - 15] >> 3);
        uint32_t s1 = rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = (uint32_t)(w[t - 16] + s0 + w[t - 7] + s1);
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int t = 0; t < 64; t++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = (uint32_t)(hh + s1 + ch + sha256_k[t] + w[t]);
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = (uint32_t)(s0 + maj);
        hh = g; g = f; f = e; e = (uint32_t)(d + t1);
        d = c; c = b; b = a; a = (uint32_t)(t1 + t2);
    }
    h[0] = (uint32_t)(h[0] + a); h[1] = (uint32_t)(h[1] + b);
    h[2] = (uint32_t)(h[2] + c); h[3] = (uint32_t)(h[3] + d);
    h[4] = (uint32_t)(h[4] + e); h[5] = (uint32_t)(h[5] + f);
    h[6] = (uint32_t)(h[6] + g); h[7] = (uint32_t)(h[7] + hh);
}

static void sha256_init(sha256_ctx *ctx) {
    static const uint32_t h0[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    memcpy(ctx->h, h0, sizeof h0);
    ctx->buf_len = 0;
    ctx->total_len = 0;
}

/* Потоковый вход произвольными кусками — то, что нужно HMAC, чтобы не
 * склеивать ключевую подкладку и сообщение в один буфер заранее. */
static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t n) {
    ctx->total_len += n;
    if (ctx->buf_len > 0) {
        size_t need = 64 - ctx->buf_len;
        size_t take = n < need ? n : need;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        n -= take;
        if (ctx->buf_len == 64) {
            sha256_compress(ctx->h, ctx->buf);
            ctx->buf_len = 0;
        }
    }
    while (n >= 64) {
        sha256_compress(ctx->h, data);
        data += 64;
        n -= 64;
    }
    if (n > 0) {
        memcpy(ctx->buf, data, n);
        ctx->buf_len = n;
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
    uint64_t bitlen = ctx->total_len * 8;
    /* Паддинг: 0x80, нули, 64-битная длина в битах (big-endian), до кратности
     * 64 байтам. buf_len < 64 всегда (update сбрасывает полный блок сразу),
     * поэтому 0x80 плюс 8 байт длины требуют один или два блока — не больше. */
    uint8_t tail[128];
    memset(tail, 0, sizeof tail);
    memcpy(tail, ctx->buf, ctx->buf_len);
    tail[ctx->buf_len] = 0x80;
    size_t pad_blocks = (ctx->buf_len + 1 + 8 <= 64) ? 1 : 2;
    size_t lenpos = pad_blocks * 64 - 8;
    for (int i = 0; i < 8; i++) {
        tail[lenpos + i] = (uint8_t)(bitlen >> (8 * (7 - i)));
    }
    for (size_t i = 0; i < pad_blocks; i++) {
        sha256_compress(ctx->h, tail + i * 64);
    }
    for (int i = 0; i < 8; i++) {
        out[4 * i]     = (uint8_t)(ctx->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(ctx->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(ctx->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)(ctx->h[i]);
    }
}

void d2k_sha256(const uint8_t *in, size_t n, uint8_t out[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, in, n);
    sha256_final(&ctx, out);
}

/* ===================== HMAC-SHA256 (RFC 2104 / FIPS 198-1) ===================== */

void d2k_hmac_sha256(const uint8_t *key, size_t klen,
                      const uint8_t *msg, size_t mlen, uint8_t out[32]) {
    uint8_t k0[64];
    memset(k0, 0, sizeof k0);
    if (klen > 64) {
        d2k_sha256(key, klen, k0); /* длинный ключ сжимается хэшем; хвост k0 остаётся нулевым */
    } else {
        memcpy(k0, key, klen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k0[i] ^ 0x36);
        opad[i] = (uint8_t)(k0[i] ^ 0x5c);
    }

    sha256_ctx ctx;
    uint8_t inner[32];
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, sizeof ipad);
    sha256_update(&ctx, msg, mlen);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, sizeof opad);
    sha256_update(&ctx, inner, sizeof inner);
    sha256_final(&ctx, out);
}

/* ===================== HKDF (RFC 5869) и HKDF-Expand-Label (RFC 8446 §7.1) ===================== */

void d2k_hkdf_extract(const uint8_t *salt, size_t slen,
                       const uint8_t *ikm, size_t ilen, uint8_t out[32]) {
    /* PRK = HMAC-Hash(salt, IKM): соль — КЛЮЧ HMAC, а не сообщение (RFC 5869
     * §2.2). Пустая соль (slen==0) сама по себе даёт корректный результат:
     * HMAC дополняет короткий ключ нулями до блока, и ноль байт нулями даёт
     * ту же дополненную строку, что и HashLen явных нулей — отдельной ветки
     * не нужно. */
    d2k_hmac_sha256(salt, slen, ikm, ilen, out);
}

int d2k_hkdf_expand_label(const uint8_t secret[32], const char *label,
                           uint8_t *out, size_t out_len) {
    /* HkdfLabel (RFC 8446 §7.1): length(2, big-endian) || len(full_label)(1)
     * || full_label || len(context)(1)=0. Контекст в этом модуле всегда пуст
     * (QUIC Initial его не использует, RFC 9001 §5.1). label — короткий
     * ASCII-литерал нашего же кода, но проверка длины — не на честном слове
     * вызывающего (ревью 2026-09-06: без неё strlen(label) > D2K_HKDF_LABEL_MAX
     * переполняет full_label ниже; воспроизведено меткой в 110 байт под
     * санитайзерами). Нарушение контракта — сразу отказ, ДО первого memcpy:
     * ни один из буферов ниже ещё не тронут. */
    size_t label_len = strlen(label);
    if (label_len > D2K_HKDF_LABEL_MAX) {
        return -1;
    }

    uint8_t full_label[6 + D2K_HKDF_LABEL_MAX];
    memcpy(full_label, "tls13 ", 6);
    memcpy(full_label + 6, label, label_len);
    size_t full_len = 6 + label_len;

    uint8_t info[2 + 1 + (6 + D2K_HKDF_LABEL_MAX) + 1];
    info[0] = (uint8_t)(out_len >> 8);
    info[1] = (uint8_t)(out_len);
    info[2] = (uint8_t)full_len;
    memcpy(info + 3, full_label, full_len);
    info[3 + full_len] = 0;
    size_t info_len = 3 + full_len + 1;

    /* HKDF-Expand (RFC 5869 §2.3): T(0) пуст, T(i) = HMAC(secret, T(i-1) ||
     * info || i). Для ключей QUIC N всегда 1 (out_len <= 32), но цикл общий —
     * это примитив общего назначения, а не однократная подстановка. */
    uint8_t t_prev[32];
    size_t t_prev_len = 0;
    size_t written = 0;
    uint8_t counter = 1;
    while (written < out_len) {
        uint8_t buf[32 + (2 + 1 + (6 + D2K_HKDF_LABEL_MAX) + 1) + 1];
        size_t buf_len = 0;
        memcpy(buf, t_prev, t_prev_len);
        buf_len += t_prev_len;
        memcpy(buf + buf_len, info, info_len);
        buf_len += info_len;
        buf[buf_len++] = counter;

        uint8_t t_cur[32];
        d2k_hmac_sha256(secret, 32, buf, buf_len, t_cur);

        size_t take = out_len - written;
        if (take > 32) {
            take = 32;
        }
        memcpy(out + written, t_cur, take);
        written += take;

        memcpy(t_prev, t_cur, 32);
        t_prev_len = 32;
        counter = (uint8_t)(counter + 1);
    }
    return 0;
}

/* ===================== GF(2^128) / GHASH (NIST SP 800-38D §6.3) ===================== */

/* Умножение в GF(2^128) строго по определению SP 800-38D §6.3: старший бит —
 * первый бит первого байта X, редуцирующий многочлен зашит как константа
 * R = 0xE1 || 0^120. 128 шагов "сдвиг вправо и, если вытолкнутый бит был
 * единицей, XOR с R" — ни одной таблицы, обращения к памяти не зависят от
 * значений X и Y. */
static void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
    uint8_t z[16];
    uint8_t v[16];
    memset(z, 0, 16);
    memcpy(v, y, 16);
    for (int i = 0; i < 128; i++) {
        uint8_t bit = (uint8_t)((x[i / 8] >> (7 - (i % 8))) & 1u);
        uint8_t bit_mask = (uint8_t)(-(int)bit);
        for (int j = 0; j < 16; j++) {
            z[j] = (uint8_t)(z[j] ^ (uint8_t)(v[j] & bit_mask));
        }
        uint8_t lsb_mask = (uint8_t)(-(int)(v[15] & 1u));
        for (int j = 15; j > 0; j--) {
            v[j] = (uint8_t)((uint8_t)(v[j] >> 1) | (uint8_t)(v[j - 1] << 7));
        }
        v[0] = (uint8_t)(v[0] >> 1);
        v[0] = (uint8_t)(v[0] ^ (uint8_t)(lsb_mask & 0xe1));
    }
    memcpy(out, z, 16);
}

/* GHASH_H(AAD || pad || C || pad || len(AAD)_64 || len(C)_64) — SP 800-38D
 * §6.4. Паддинг нулями до границы блока считается неявно: неполный последний
 * блок каждой части копируется в обнулённый 16-байтовый буфер. */
static void ghash(const uint8_t h[16], const uint8_t *aad, size_t aad_len,
                   const uint8_t *c, size_t c_len, uint8_t out[16]) {
    uint8_t y[16];
    uint8_t block[16];
    uint8_t prod[16];
    memset(y, 0, 16);

    size_t i;
    for (i = 0; i + 16 <= aad_len; i += 16) {
        for (int j = 0; j < 16; j++) {
            y[j] = (uint8_t)(y[j] ^ aad[i + j]);
        }
        gf128_mul(y, h, prod);
        memcpy(y, prod, 16);
    }
    if (i < aad_len) {
        memset(block, 0, 16);
        memcpy(block, aad + i, aad_len - i);
        for (int j = 0; j < 16; j++) {
            y[j] = (uint8_t)(y[j] ^ block[j]);
        }
        gf128_mul(y, h, prod);
        memcpy(y, prod, 16);
    }

    for (i = 0; i + 16 <= c_len; i += 16) {
        for (int j = 0; j < 16; j++) {
            y[j] = (uint8_t)(y[j] ^ c[i + j]);
        }
        gf128_mul(y, h, prod);
        memcpy(y, prod, 16);
    }
    if (i < c_len) {
        memset(block, 0, 16);
        memcpy(block, c + i, c_len - i);
        for (int j = 0; j < 16; j++) {
            y[j] = (uint8_t)(y[j] ^ block[j]);
        }
        gf128_mul(y, h, prod);
        memcpy(y, prod, 16);
    }

    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t c_bits = (uint64_t)c_len * 8;
    memset(block, 0, 16);
    for (int j = 0; j < 8; j++) {
        block[j] = (uint8_t)(aad_bits >> (8 * (7 - j)));
        block[8 + j] = (uint8_t)(c_bits >> (8 * (7 - j)));
    }
    for (int j = 0; j < 16; j++) {
        y[j] = (uint8_t)(y[j] ^ block[j]);
    }
    gf128_mul(y, h, prod);
    memcpy(out, prod, 16);
}

/* ===================== AES-128-GCM (NIST SP 800-38D) ===================== */

/* Инкремент младших 32 бит блока-счётчика, с переносом внутри них же
 * (SP 800-38D §6.2 inc32) — верхние 96 бит (nonce) не трогаются никогда. */
static void inc32(uint8_t block[16]) {
    for (int i = 15; i >= 12; i--) {
        block[i] = (uint8_t)(block[i] + 1);
        if (block[i] != 0) {
            break;
        }
    }
}

/* GCTR_K(icb, in) — поток AES-CTR: keystream = CIPH_K(текущий счётчик),
 * счётчик увеличивается inc32 после каждого блока. Вызывающий передаёт
 * ровно тот счётчик, с которого начинать (SP 800-38D различает J0 для тега и
 * inc32(J0) для данных — см. d2k_aes128_gcm_decrypt). */
static void gctr(const aes128_ks *ks, const uint8_t icb[16],
                  const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t cb[16];
    memcpy(cb, icb, 16);
    size_t i = 0;
    while (i < n) {
        uint8_t ks_block[16];
        aes128_encrypt_block(ks, cb, ks_block);
        size_t take = n - i;
        if (take > 16) {
            take = 16;
        }
        for (size_t j = 0; j < take; j++) {
            out[i + j] = (uint8_t)(in[i + j] ^ ks_block[j]);
        }
        i += take;
        inc32(cb);
    }
}

/* Сравнение тега за постоянное время: ранний выход по первому несовпавшему
 * байту превратил бы сравнение тега в оракул для подделки MAC по времени
 * ответа — тот же класс ошибки, от которого статья в шапке файла уже
 * предостерегает применительно к таблицам. */
static int consttime_eq16(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff = (uint8_t)(diff | (uint8_t)(a[i] ^ b[i]));
    }
    return diff == 0;
}

int d2k_aes128_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct, size_t ct_len, uint8_t *out) {
    if (ct_len < 16) {
        /* Короче тега — гарантированно не пакет с тегом, а не обрывок
         * предположительно нашего: обрывок ещё МОГ БЫ донести тег позже,
         * а здесь "позже" уже некуда — вызывающий отдал всё, что было. */
        return -1;
    }
    size_t pt_len = ct_len - 16;
    const uint8_t *tag_in = ct + pt_len;

    aes128_ks ks;
    aes128_key_expand(key, &ks);

    uint8_t zero_block[16];
    uint8_t h[16];
    memset(zero_block, 0, 16);
    aes128_encrypt_block(&ks, zero_block, h); /* H = CIPH_K(0^128), SP 800-38D §6.4 */

    /* |IV| = 96 бит всегда (QUIC, RFC 9001 §5.3): J0 = IV || 0^31 || 1 —
     * упрощённый случай SP 800-38D §7.1, без прохода GHASH по самому IV. */
    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

    uint8_t s[16];
    ghash(h, aad, aad_len, ct, pt_len, s); /* по шифротексту — расшифровывать для этого не нужно */

    uint8_t t[16];
    gctr(&ks, j0, s, 16, t); /* T = MSB_128(GCTR_K(J0, S)) — счётчик тега САМ J0, без инкремента */

    if (!consttime_eq16(t, tag_in)) {
        /* Тег не сошёлся: out не трогаем вовсе, чтобы у вызывающего не было
         * способа случайно использовать непроверенный текст, забыв про код
         * возврата (см. контракт в d2k_crypto.h). */
        return -1;
    }

    uint8_t icb[16];
    memcpy(icb, j0, 16);
    inc32(icb); /* данные шифруются начиная со счётчика 2: J0 занят под тег */
    gctr(&ks, icb, ct, pt_len, out);
    return 0;
}
