/* SHA-3 и SHAKE по FIPS 202 — для ML-KEM (FIPS 203).
 *
 * Губка Keccak-f[1600]: поглощение блоками rate байт, разделитель домена
 * (0x06 для SHA-3, 0x1F для SHAKE), выжимание. Потоковый SHAKE нужен
 * выборке матрицы ML-KEM: она читает поток, пока не наберёт коэффициенты. */
#ifndef D2K_KECCAK_H
#define D2K_KECCAK_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t s[25];
    size_t rate;       /* байт в блоке: 168 SHAKE128, 136 SHAKE256/SHA3-256, 72 SHA3-512 */
    size_t pos;        /* позиция в текущем блоке (поглощение или выжимание) */
    uint8_t domain;    /* 0x06 SHA-3, 0x1F SHAKE */
    int squeezing;
} d2k_keccak;

void d2k_keccak_init(d2k_keccak *, size_t rate, uint8_t domain);
void d2k_keccak_absorb(d2k_keccak *, const uint8_t *, size_t);
/* Первый вызов закрывает поглощение; дальше — продолжение потока. */
void d2k_keccak_squeeze(d2k_keccak *, uint8_t *, size_t);

void d2k_sha3_256(const uint8_t *, size_t, uint8_t out[32]);
void d2k_sha3_512(const uint8_t *, size_t, uint8_t out[64]);
void d2k_shake128(const uint8_t *, size_t, uint8_t *, size_t);
void d2k_shake256(const uint8_t *, size_t, uint8_t *, size_t);

#endif
