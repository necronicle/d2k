/* stun.c — контракт и все обоснования в d2k_stun.h.
 *
 * Разбор идёт СТРОГО по объявленным длинам и с выравниванием атрибутов в
 * четыре байта (RFC 5389 §15). Гадать здесь нечего и нельзя: атрибут
 * неизвестного типа пропускается по СВОЕЙ длине, а длина, уводящая за
 * границу, прекращает обход насовсем — ровно та же дисциплина, что у разбора
 * кадров QUIC (core/quic.c, collect_crypto_frames).
 */
#include <string.h>

#include "d2k_stun.h"
#include "d2k_tls13core.h"

#define STUN_BINDING_REQUEST  0x0001u
#define STUN_BINDING_RESPONSE 0x0101u
#define STUN_MAGIC            0x2112a442u
#define ATTR_XOR_MAPPED_ADDR  0x0020u

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

size_t d2k_stun_request(uint8_t *out, size_t cap, uint8_t txid[D2K_STUN_TXID_LEN]) {
    if (!out || !txid || cap < D2K_STUN_HDR_LEN) { return 0; }
    /* Идентификатор — СВОЙ на каждый вызов и из того же источника
       случайности, что и всё остальное в проекте (d2k_t13_random): второй
       генератор завёл бы второе место, где «случайность» может оказаться
       предсказуемой, и разошёлся бы с первым незаметно. */
    if (d2k_t13_random(txid, D2K_STUN_TXID_LEN) != 0) { return 0; }

    out[0] = (uint8_t)(STUN_BINDING_REQUEST >> 8);
    out[1] = (uint8_t)(STUN_BINDING_REQUEST & 0xff);
    out[2] = 0;  /* атрибутов нет: Binding Request их не требует (RFC 5389 §7.1) */
    out[3] = 0;
    out[4] = (uint8_t)(STUN_MAGIC >> 24);
    out[5] = (uint8_t)(STUN_MAGIC >> 16);
    out[6] = (uint8_t)(STUN_MAGIC >> 8);
    out[7] = (uint8_t)(STUN_MAGIC);
    memcpy(out + 8, txid, D2K_STUN_TXID_LEN);
    return D2K_STUN_HDR_LEN;
}

/* XOR-MAPPED-ADDRESS (RFC 5389 §15.2): адрес и порт поксорены с магической
   меткой — затем, чтобы их не правил NAT, переписывающий адреса не только в
   заголовке, но и в теле пакета. Для IPv6 ключ ксора длиннее: метка И
   идентификатор транзакции (то есть 16 байт), и перепутать их с одной меткой
   значит получить осмысленно выглядящий, но неверный адрес. */
static int parse_xor_mapped(const uint8_t *a, size_t len,
                            const uint8_t txid[D2K_STUN_TXID_LEN],
                            uint8_t *ip, int *family, uint16_t *port) {
    if (len < 8) { return -1; }
    uint16_t p = (uint16_t)(rd16(a + 2) ^ (uint16_t)(STUN_MAGIC >> 16));
    if (a[1] == 0x01) {
        uint32_t v = rd32(a + 4) ^ STUN_MAGIC;
        ip[0] = (uint8_t)(v >> 24);
        ip[1] = (uint8_t)(v >> 16);
        ip[2] = (uint8_t)(v >> 8);
        ip[3] = (uint8_t)v;
        *family = 4;
        *port = p;
        return 0;
    }
    if (a[1] == 0x02) {
        if (len < 20) { return -1; }
        uint8_t key[16];
        key[0] = (uint8_t)(STUN_MAGIC >> 24);
        key[1] = (uint8_t)(STUN_MAGIC >> 16);
        key[2] = (uint8_t)(STUN_MAGIC >> 8);
        key[3] = (uint8_t)STUN_MAGIC;
        memcpy(key + 4, txid, D2K_STUN_TXID_LEN);
        for (size_t i = 0; i < 16; i++) {
            ip[i] = (uint8_t)(a[4 + i] ^ key[i]);
        }
        *family = 6;
        *port = p;
        return 0;
    }
    return -1; /* неизвестное семейство — не выдумывать адрес */
}

int d2k_stun_parse_response(const uint8_t *p, size_t n,
                            const uint8_t txid[D2K_STUN_TXID_LEN],
                            uint8_t *ip, int *family, uint16_t *port) {
    if (!p || !txid || !ip || !family || !port) { return -1; }
    *family = 0;
    *port = 0;
    if (n < D2K_STUN_HDR_LEN) { return -1; }
    if (rd16(p) != STUN_BINDING_RESPONSE) { return -1; }
    if (rd32(p + 4) != STUN_MAGIC) { return -1; }
    /* СВЕРКА ИДЕНТИФИКАТОРА — см. d2k_stun.h: без неё за доказательство
       «путь жив» сойдёт любой пакет, прилетевший на порт. */
    if (memcmp(p + 8, txid, D2K_STUN_TXID_LEN) != 0) { return -1; }

    size_t attrs = rd16(p + 2);
    if (D2K_STUN_HDR_LEN + attrs > n) { return -1; }

    const uint8_t *b = p + D2K_STUN_HDR_LEN;
    size_t left = attrs;
    while (left >= 4) {
        uint16_t typ = rd16(b);
        size_t ln = rd16(b + 2);
        if (4 + ln > left) { break; } /* длина уводит за объявленные атрибуты — дальше гадать нельзя */
        if (typ == ATTR_XOR_MAPPED_ADDR) {
            /* Как ParseBindingResponse оригинала: отсутствующий адрес
               допустим, но ошибка присутствующего XOR-MAPPED-ADDRESS
               должна дойти до оракула, а не стать успешным ответом. */
            return parse_xor_mapped(b + 4, ln, txid, ip, family, port);
        }
        size_t step = 4 + ln;
        size_t pad = ln % 4;
        if (pad) { step += 4 - pad; }
        if (step > left) { break; }
        b += step;
        left -= step;
    }
    /* Ответ есть, адреса в нём нет. Для оракула этого довольно: датаграмма
       дошла и вернулась с нашим идентификатором. */
    return 0;
}
