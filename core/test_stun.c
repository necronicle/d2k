/* test_stun.c — STUN Binding против ОФИЦИАЛЬНЫХ векторов RFC 5769.
 *
 * Векторы взяты у RFC, а не собраны здесь же тем кодом, который они проверяют:
 * самодельный вектор доказывает только внутреннюю согласованность разбора со
 * сборкой и молча пропускает общую ошибку в обоих. Тот же принцип, что у
 * test_quic.c (RFC 9001 A.2 и RFC 9369 A.2).
 *
 * MESSAGE-INTEGRITY и FINGERPRINT в векторах присутствуют и НЕ проверяются
 * разбором (см. d2k_stun.h — почему). В тесте они нужны другим: это настоящие
 * атрибуты переменной длины ПЕРЕД и ПОСЛЕ искомого, и разбор обязан пройти
 * мимо них по объявленным длинам, а не найти адрес случайно.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_stun.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* RFC 5769 §2.1 — Sample Request. */
static const uint8_t vec_request[] = {
    0x00,0x01,0x00,0x58, 0x21,0x12,0xa4,0x42,
    0xb7,0xe7,0xa7,0x01, 0xbc,0x34,0xd6,0x86, 0xfa,0x87,0xdf,0xae,
    0x80,0x22,0x00,0x10, 0x53,0x54,0x55,0x4e, 0x20,0x74,0x65,0x73,
    0x74,0x20,0x63,0x6c, 0x69,0x65,0x6e,0x74,
    0x00,0x24,0x00,0x04, 0x6e,0x00,0x01,0xff,
    0x80,0x29,0x00,0x08, 0x93,0x2f,0xf9,0xb1, 0x51,0x26,0x3b,0x36,
    0x00,0x06,0x00,0x09, 0x65,0x76,0x74,0x6a, 0x3a,0x68,0x36,0x76,
    0x59,0x20,0x20,0x20,
    0x00,0x08,0x00,0x14, 0x9a,0xea,0xa7,0x0c, 0xbf,0xd8,0xcb,0x56,
    0x78,0x1e,0xf2,0xb5, 0xb2,0xd3,0xf2,0x49, 0xc1,0xb5,0x71,0xa2,
    0x80,0x28,0x00,0x04, 0xe5,0x7a,0x3b,0xcf
};

/* RFC 5769 §2.2 — Sample IPv4 Response: 192.0.2.1:32853. */
static const uint8_t vec_v4[] = {
    0x01,0x01,0x00,0x3c, 0x21,0x12,0xa4,0x42,
    0xb7,0xe7,0xa7,0x01, 0xbc,0x34,0xd6,0x86, 0xfa,0x87,0xdf,0xae,
    0x80,0x22,0x00,0x0b, 0x74,0x65,0x73,0x74, 0x20,0x76,0x65,0x63,
    0x74,0x6f,0x72,0x20,
    0x00,0x20,0x00,0x08, 0x00,0x01,0xa1,0x47, 0xe1,0x12,0xa6,0x43,
    0x00,0x08,0x00,0x14, 0x2b,0x91,0xf5,0x99, 0xfd,0x9e,0x90,0xc3,
    0x8c,0x74,0x89,0xf9, 0x2a,0xf9,0xba,0x53, 0xf0,0x6b,0xe7,0xd7,
    0x80,0x28,0x00,0x04, 0xc0,0x7d,0x4c,0x96
};

/* RFC 5769 §2.3 — Sample IPv6 Response:
   2001:db8:1234:5678:11:2233:4455:6677, порт 32853. */
static const uint8_t vec_v6[] = {
    0x01,0x01,0x00,0x48, 0x21,0x12,0xa4,0x42,
    0xb7,0xe7,0xa7,0x01, 0xbc,0x34,0xd6,0x86, 0xfa,0x87,0xdf,0xae,
    0x80,0x22,0x00,0x0b, 0x74,0x65,0x73,0x74, 0x20,0x76,0x65,0x63,
    0x74,0x6f,0x72,0x20,
    0x00,0x20,0x00,0x14, 0x00,0x02,0xa1,0x47,
    0x01,0x13,0xa9,0xfa, 0xa5,0xd3,0xf1,0x79, 0xbc,0x25,0xf4,0xb5,
    0xbe,0xd2,0xb9,0xd9,
    0x00,0x08,0x00,0x14, 0xa3,0x82,0x95,0x4e, 0x4b,0xe6,0x7b,0xf1,
    0x17,0x84,0xc9,0x7c, 0x82,0x92,0xc2,0x75, 0xbf,0xe3,0xed,0x41,
    0x80,0x28,0x00,0x04, 0xc8,0xfb,0x0b,0x4c
};

static const uint8_t vec_txid[D2K_STUN_TXID_LEN] = {
    0xb7,0xe7,0xa7,0x01, 0xbc,0x34,0xd6,0x86, 0xfa,0x87,0xdf,0xae
};

int main(void) {
    uint8_t ip[16];
    int family = -1;
    uint16_t port = 0;

    /* --- RFC 5769 §2.2: адрес IPv4 из-под трёх чужих атрибутов ---------- */
    {
        memset(ip, 0, sizeof ip);
        CHECK(d2k_stun_parse_response(vec_v4, sizeof vec_v4, vec_txid,
                                      ip, &family, &port) == 0,
              "вектор §2.2 не признан ответом на наш запрос");
        CHECK(family == 4, "семейство адреса не IPv4");
        CHECK(ip[0] == 192 && ip[1] == 0 && ip[2] == 2 && ip[3] == 1,
              "адрес не 192.0.2.1 — XOR-MAPPED-ADDRESS разобран неверно");
        CHECK(port == 32853, "порт не 32853");
    }

    /* --- RFC 5769 §2.3: IPv6 ксорится ключом из метки И идентификатора --- */
    {
        static const uint8_t want[16] = {
            0x20,0x01,0x0d,0xb8, 0x12,0x34,0x56,0x78,
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77
        };
        memset(ip, 0, sizeof ip);
        family = -1;
        CHECK(d2k_stun_parse_response(vec_v6, sizeof vec_v6, vec_txid,
                                      ip, &family, &port) == 0,
              "вектор §2.3 не признан ответом");
        CHECK(family == 6, "семейство адреса не IPv6");
        CHECK(memcmp(ip, want, sizeof want) == 0,
              "адрес IPv6 не совпал: ключ ксора — метка И идентификатор транзакции, не одна метка");
        CHECK(port == 32853, "порт IPv6-ответа не 32853");
    }

    /* --- ЧУЖОЙ ОТВЕТ НЕ ДОКАЗЫВАЕТ НИЧЕГО -------------------------------
     * Датаграммный сокет принимает всё, что прилетело на порт. Без сверки
     * идентификатора за «путь жив» сошёл бы посторонний сервис. */
    {
        uint8_t alien[D2K_STUN_TXID_LEN];
        memcpy(alien, vec_txid, sizeof alien);
        alien[0] ^= 0xff;
        CHECK(d2k_stun_parse_response(vec_v4, sizeof vec_v4, alien,
                                      ip, &family, &port) != 0,
              "чужой идентификатор транзакции сошёл за наш ответ");
    }

    /* --- ЗАПРОС — НЕ ОТВЕТ ----------------------------------------------
     * Свой же запрос, вернувшийся эхом (петля, кривой NAT), не доказательство. */
    CHECK(d2k_stun_parse_response(vec_request, sizeof vec_request, vec_txid,
                                  ip, &family, &port) != 0,
          "Binding Request сошёл за Binding Response");

    /* --- битый вход: отказ, а не догадка -------------------------------- */
    {
        uint8_t bad[sizeof vec_v4];

        CHECK(d2k_stun_parse_response(vec_v4, D2K_STUN_HDR_LEN - 1, vec_txid,
                                      ip, &family, &port) != 0,
              "пакет короче заголовка принят");

        memcpy(bad, vec_v4, sizeof bad);
        bad[4] ^= 0xff; /* магическая метка */
        CHECK(d2k_stun_parse_response(bad, sizeof bad, vec_txid, ip, &family, &port) != 0,
              "без магической метки пакет принят за STUN");

        memcpy(bad, vec_v4, sizeof bad);
        bad[2] = 0xff; bad[3] = 0xff; /* объявленная длина атрибутов больше пакета */
        CHECK(d2k_stun_parse_response(bad, sizeof bad, vec_txid, ip, &family, &port) != 0,
              "объявленная длина атрибутов больше пакета — принято");

        /* Длина ОДНОГО атрибута уводит за границу: разбор обязан
           остановиться, а не читать за буфером. Адреса тогда нет, но ответ
           наш — это не отказ (см. d2k_stun.h). */
        memcpy(bad, vec_v4, sizeof bad);
        bad[22] = 0xff; bad[23] = 0xf0; /* длина SOFTWARE */
        family = -1;
        (void)d2k_stun_parse_response(bad, sizeof bad, vec_txid, ip, &family, &port);
        CHECK(family == 0 || family == -1,
              "адрес «найден» за границей объявленных атрибутов");
    }

    /* --- ОТВЕТ БЕЗ АДРЕСА — ВСЁ РАВНО ОТВЕТ -----------------------------
     * Для оракула достаточно самого факта: датаграмма дошла и вернулась с
     * нашим идентификатором. Требовать адрес значило бы объявить живой путь
     * мёртвым из-за необязательного атрибута. */
    {
        uint8_t bare[D2K_STUN_HDR_LEN];
        memcpy(bare, vec_v4, sizeof bare);
        bare[2] = 0; bare[3] = 0;
        family = -1;
        CHECK(d2k_stun_parse_response(bare, sizeof bare, vec_txid, ip, &family, &port) == 0,
              "ответ без атрибутов не признан ответом");
        CHECK(family == 0, "адреса не было, а семейство выставлено");
    }

    /* --- сборка запроса: свой идентификатор на каждый вызов -------------- */
    {
        uint8_t a[D2K_STUN_HDR_LEN], b[D2K_STUN_HDR_LEN];
        uint8_t ta[D2K_STUN_TXID_LEN], tb[D2K_STUN_TXID_LEN];
        CHECK(d2k_stun_request(a, sizeof a, ta) == D2K_STUN_HDR_LEN,
              "запрос не собрался");
        CHECK(a[0] == 0x00 && a[1] == 0x01, "тип не Binding Request");
        CHECK(a[2] == 0 && a[3] == 0, "у запроса объявлены атрибуты, которых нет");
        CHECK(a[4] == 0x21 && a[5] == 0x12 && a[6] == 0xa4 && a[7] == 0x42,
              "нет магической метки STUN");
        CHECK(memcmp(a + 8, ta, D2K_STUN_TXID_LEN) == 0,
              "идентификатор в пакете не тот, что выдан вызывающему");

        CHECK(d2k_stun_request(b, sizeof b, tb) == D2K_STUN_HDR_LEN, "второй запрос не собрался");
        CHECK(memcmp(ta, tb, D2K_STUN_TXID_LEN) != 0,
              "два запроса с одним идентификатором — ответ на прошлый вопрос сойдёт за ответ на этот");

        CHECK(d2k_stun_request(a, D2K_STUN_HDR_LEN - 1, ta) == 0,
              "запрос втиснут в буфер, куда он не помещается");
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("STUN Binding (векторы RFC 5769): все проверки прошли\n");
    return 0;
}
