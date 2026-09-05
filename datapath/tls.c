/* tls.c — разбор ClientHello ради якорей, и только ради них.
 *
 * Ни одного «предположим»: каждое поле читается только после проверки, что оно
 * целиком помещается в переданные байты. Вход приходит из сети, и коробка по
 * ту сторону вполне может прислать запись, у которой объявленная длина больше
 * фактической — это не редкость, а обычный приём.
 *
 * Разбор останавливается на первой несостыковке и оставляет уже найденное
 * невыданным: наполовину разобранное расширение не даёт права на смещение.
 */
#include <string.h>

#include "d2k_tls.h"

#define REC_HDR      5
#define HS_HDR       4
#define TLS_HANDSHAKE 0x16
#define HS_CLIENT_HELLO 0x01
#define EXT_SERVER_NAME 0x0000
#define SNI_HOST_NAME   0x00

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

/* Читает длину поля с однобайтовым префиксом и двигает смещение.
 * Возвращает 0, если поле целиком помещается. */
static int skip_u8_vec(const uint8_t *b, size_t len, size_t *off) {
    if (*off + 1 > len) {
        return -1;
    }
    size_t n = b[*off];
    if (*off + 1 + n > len) {
        return -1;
    }
    *off += 1 + n;
    return 0;
}

static int skip_u16_vec(const uint8_t *b, size_t len, size_t *off) {
    if (*off + 2 > len) {
        return -1;
    }
    size_t n = rd16(b + *off);
    if (*off + 2 + n > len) {
        return -1;
    }
    *off += 2 + n;
    return 0;
}

/* Ищет имя в блоке расширений. Возвращает 0 и заполняет смещение, если имя
 * найдено и целиком помещается. */
static int find_sni(const uint8_t *b, size_t exts_off, size_t exts_end,
                    size_t *sni_off, size_t *sni_len) {
    size_t off = exts_off;
    while (off + 4 <= exts_end) {
        uint16_t type = rd16(b + off);
        size_t elen = rd16(b + off + 2);
        off += 4;
        if (off + elen > exts_end) {
            /* Объявленная длина расширения выходит за блок: дальше читать
               нечего и нельзя. */
            return -1;
        }
        if (type == EXT_SERVER_NAME) {
            size_t p = off;
            if (p + 2 > off + elen) {
                return -1;
            }
            size_t list_len = rd16(b + p);
            p += 2;
            if (p + list_len > off + elen) {
                return -1;
            }
            size_t list_end = p + list_len;
            while (p + 3 <= list_end) {
                uint8_t nt = b[p];
                size_t nlen = rd16(b + p + 1);
                p += 3;
                if (p + nlen > list_end) {
                    return -1;
                }
                if (nt == SNI_HOST_NAME) {
                    if (nlen == 0) {
                        /* Пустое имя — это не имя. */
                        return -1;
                    }
                    *sni_off = p;
                    *sni_len = nlen;
                    return 0;
                }
                p += nlen;
            }
            return -1;
        }
        off += elen;
    }
    return -1;
}

int d2k_tls_parse(const uint8_t *b, size_t len, d2k_tls_info *out) {
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (!b || len < 3) {
        return 0;
    }

    /* Запись TLS: тип, версия, длина. Версия проверяется грубо — 0x03xx: этого
       достаточно, чтобы отличить запись от HTTP, и недостаточно, чтобы
       ошибиться на редком клиенте. */
    if (b[1] != 0x03) {
        return 0;
    }
    out->is_tls_record = 1;
    out->record_type = b[0];

    if (len < REC_HDR) {
        return 0;
    }
    size_t rec_len = rd16(b + 3);
    if (REC_HDR + rec_len <= len) {
        out->have_record_end = 1;
        out->record_end = REC_HDR + rec_len;
    }
    /* Запись не помещается целиком — дальше не идём: разбирать рукопожатие по
       обрывку значит выдать смещение, которое может уехать при доборе
       следующего сегмента. */
    if (!out->have_record_end) {
        return 0;
    }

    if (out->record_type != TLS_HANDSHAKE) {
        return 0;
    }
    size_t end = out->record_end;
    size_t off = REC_HDR;
    if (off + HS_HDR > end) {
        return 0;
    }
    if (b[off] != HS_CLIENT_HELLO) {
        return 0;
    }
    size_t hs_len = (size_t)b[off + 1] << 16 | (size_t)b[off + 2] << 8 | b[off + 3];
    off += HS_HDR;
    if (off + hs_len > end) {
        return 0;
    }
    size_t hs_end = off + hs_len;

    out->is_client_hello = 1;
    out->have_hello_middle = 1;
    out->hello_middle = off + hs_len / 2;

    /* client_version и random. */
    if (off + 2 + 32 > hs_end) {
        return 0;
    }
    off += 2 + 32;

    if (skip_u8_vec(b, hs_end, &off) != 0) {   /* legacy_session_id */
        return 0;
    }
    if (skip_u16_vec(b, hs_end, &off) != 0) {  /* cipher_suites */
        return 0;
    }
    if (skip_u8_vec(b, hs_end, &off) != 0) {   /* compression_methods */
        return 0;
    }

    if (off + 2 > hs_end) {
        /* Расширений нет вовсе — законный ClientHello, просто без имени. */
        return 0;
    }
    size_t exts_len = rd16(b + off);
    off += 2;
    if (off + exts_len > hs_end) {
        /* Объявленная длина блока расширений больше, чем есть. Имя не
           выдаётся: разбор дальше был бы чтением за пределами записи. */
        return 0;
    }

    size_t so = 0, sl = 0;
    if (find_sni(b, off, off + exts_len, &so, &sl) == 0) {
        out->have_sni = 1;
        out->sni_off = so;
        out->sni_len = sl;
    }
    return 0;
}
