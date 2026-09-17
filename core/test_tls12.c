/* test_tls12.c — проверка клиента TLS 1.2 без сети.
 *
 * Сетевую часть проверяет лаборатория: там есть настоящий сервер и настоящая
 * коробка. Здесь проверяется то, что на живом сервере проявляется ОДНОЙ
 * строкой «метка не сошлась» и ищется потом часами: развёртка ключей.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_tls12.h"

static int fails;

static void check(int ok, const char *what) {
    if (!ok) { printf("ПРОВАЛ: %s\n", what); fails++; }
}

/* ВЕКТОР ИЗ ПЕРВОИСТОЧНИКА, А НЕ ИЗ СВОЕГО ЖЕ ВЫВОДА.
 *
 * PRF на SHA-256 (RFC 5246 §5) проверяется опубликованным вектором для
 * TLS 1.2: если сверять с тем, что напечатала своя же реализация, тест
 * подтвердит любую ошибку, лишь бы она была устойчивой. */
static void test_prf_vector(void) {
    static const unsigned char secret[16] = {
        0x9b,0xbe,0x43,0x6b,0xa9,0x40,0xf0,0x17,0xb1,0x76,0x52,0x84,0x9a,0x71,0xdb,0x35
    };
    static const unsigned char seed[16] = {
        0xa0,0xba,0x9f,0x93,0x6c,0xda,0x31,0x18,0x27,0xa6,0xf7,0x96,0xff,0xd5,0x19,0x8c
    };
    static const unsigned char want[100] = {
        0xe3,0xf2,0x29,0xba,0x72,0x7b,0xe1,0x7b,0x8d,0x12,0x26,0x20,0x55,0x7c,0xd4,0x53,
        0xc2,0xaa,0xb2,0x1d,0x07,0xc3,0xd4,0x95,0x32,0x9b,0x52,0xd4,0xe6,0x1e,0xdb,0x5a,
        0x6b,0x30,0x17,0x91,0xe9,0x0d,0x35,0xc9,0xc9,0xa4,0x6b,0x4e,0x14,0xba,0xf9,0xaf,
        0x0f,0xa0,0x22,0xf7,0x07,0x7d,0xef,0x17,0xab,0xfd,0x37,0x97,0xc0,0x56,0x4b,0xab,
        0x4f,0xbc,0x91,0x66,0x6e,0x9d,0xef,0x9b,0x97,0xfc,0xe3,0x4f,0x79,0x67,0x89,0xba,
        0xa4,0x80,0x82,0xd1,0x22,0xee,0x42,0xc5,0xa7,0x2e,0x5a,0x51,0x10,0xff,0xf7,0x01,
        0x87,0x34,0x7b,0x66
    };
    unsigned char got[100];
    d2k_tls12_prf_for_test(secret, sizeof secret, "test label", seed, sizeof seed,
                           got, sizeof got);
    check(memcmp(got, want, sizeof want) == 0,
          "PRF не сошёлся с опубликованным вектором — ключи будут неверны, "
          "а проявится это «меткой, которая не сошлась» на живом сервере");
}

/* Длина запрашивается любая, а не кратная блоку хеша: последний блок
   обрезается, и ошибка здесь дала бы верные первые 32 байта и мусор дальше —
   то есть верный client_write_key при неверной соли. */
static void test_prf_partial_block(void) {
    static const unsigned char secret[4] = {1, 2, 3, 4};
    static const unsigned char seed[4] = {5, 6, 7, 8};
    unsigned char full[64], part[40];
    d2k_tls12_prf_for_test(secret, sizeof secret, "key expansion", seed, sizeof seed,
                           full, sizeof full);
    d2k_tls12_prf_for_test(secret, sizeof secret, "key expansion", seed, sizeof seed,
                           part, sizeof part);
    check(memcmp(full, part, sizeof part) == 0,
          "короткая развёртка PRF не совпала с началом длинной");
}

int main(void) {
    printf("TLS 1.2: проверки без сети\n");
    test_prf_vector();
    test_prf_partial_block();
    if (fails) { printf("TLS 1.2: ПРОВАЛОВ %d\n", fails); return 1; }
    printf("TLS 1.2: все проверки прошли\n");
    return 0;
}
