/* Шифры TLS 1.3 по выбору сервера (RFC 8446 §B.4).
 *
 * Форма клиента (ТЗ §4.3, §11.1) предлагает свой порядок шифров, и сервер
 * выбирает по нему: Safari ставит первым 0x1302, Chrome — 0x1301, Firefox —
 * 0x1301 и 0x1303. Чтобы рукопожатие на форме клиента завершалось, нужны
 * все три:
 *   0x1301 TLS_AES_128_GCM_SHA256
 *   0x1302 TLS_AES_256_GCM_SHA384
 *   0x1303 TLS_CHACHA20_POLY1305_SHA256
 * Здесь — хэш, HMAC, HKDF, AEAD и расписание ключей TLS 1.3 с параметром
 * «шифр». Стандарты: FIPS 180-4, FIPS 197, SP 800-38D, RFC 5869, RFC 8439. */
#ifndef D2K_SUITE_H
#define D2K_SUITE_H

#include <stddef.h>
#include <stdint.h>

#define D2K_HASH_MAX 48
#define D2K_AEAD_KEY_MAX 32

typedef struct {
    uint16_t id;
    size_t hash_len;   /* 32 или 48 */
    size_t key_len;    /* 16 или 32 */
} d2k_suite;

/* 0 — шифр поддержан, -1 — нет. */
int d2k_suite_of(uint16_t id, d2k_suite *);

void d2k_sha384(const uint8_t *, size_t, uint8_t out[48]);
void d2k_sha512(const uint8_t *, size_t, uint8_t out[64]);
/* Хэш шифра (SHA-256 или SHA-384). */
void d2k_suite_hash(const d2k_suite *, const uint8_t *, size_t, uint8_t *out);
void d2k_suite_hmac(const d2k_suite *, const uint8_t *key, size_t klen,
                    const uint8_t *msg, size_t mlen, uint8_t *out);
void d2k_suite_extract(const d2k_suite *, const uint8_t *salt, size_t slen,
                       const uint8_t *ikm, size_t ilen, uint8_t *out);
int d2k_suite_expand_label(const d2k_suite *, const uint8_t *secret,
                           const char *label, const uint8_t *ctx, size_t clen,
                           uint8_t *out, size_t olen);

/* AEAD записи TLS 1.3: тег 16 байт в конце out/ct. 0 — успех; open: -1 —
 * тег не сошёлся, out не тронут. */
int d2k_suite_seal(const d2k_suite *, const uint8_t *key, const uint8_t nonce[12],
                   const uint8_t *aad, size_t alen, const uint8_t *in, size_t n,
                   uint8_t *out);
int d2k_suite_open(const d2k_suite *, const uint8_t *key, const uint8_t nonce[12],
                   const uint8_t *aad, size_t alen, const uint8_t *ct, size_t n,
                   uint8_t *out);

/* Расписание ключей TLS 1.3 (RFC 8446 §7.1) для шифра; секреты — hash_len байт. */
int d2k_suite_schedule_hs(const d2k_suite *, const uint8_t *ikm, size_t ilen,
                          const uint8_t *tr, size_t tlen,
                          uint8_t *c_hs, uint8_t *s_hs, uint8_t *hs);
int d2k_suite_schedule_ap(const d2k_suite *, const uint8_t *hs,
                          const uint8_t *tr, size_t tlen, uint8_t *c_ap, uint8_t *s_ap);
int d2k_suite_finished(const d2k_suite *, const uint8_t *secret,
                       const uint8_t *tr, size_t tlen, uint8_t *out);
int d2k_suite_traffic(const d2k_suite *, const uint8_t *secret, uint8_t *key,
                      uint8_t iv[12]);

/* Примитивы для проверки по стандартам. */
void d2k_aes256_ecb(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]);
void d2k_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                        uint8_t out[64]);
void d2k_poly1305(const uint8_t key[32], const uint8_t *msg, size_t n, uint8_t tag[16]);

#endif
