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
#define HS_SERVER_HELLO 0x02
/* Минимальное тело ServerHello (RFC 8446 §4.1.3): legacy_version 2 +
 * random 32 + длина legacy_session_id_echo 1 + cipher_suite 2 +
 * legacy_compression_method 1. Пустой сессии соответствует ровно 38. */
#define SERVER_HELLO_MIN_BODY 38
#define EXT_SERVER_NAME 0x0000
#define EXT_SUPPORTED_VERSIONS 0x002b
#define TLS13_VERSION   0x0304
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
/* Объявляет ли приветствие TLS 1.3 — расширение supported_versions со
 * значением 0x0304 (RFC 8446 §4.2.1).
 *
 * Тот же признак, по которому форму приветствия различает контроллер
 * (d2k_hello_shape, core/hello.c: have_tls13 → MODERN, иначе LEGACY).
 * Считается ЗДЕСЬ, а не приносится извне, потому что нужен на ПАКЕТНОМ пути:
 * датапат обязан знать форму приветствия, чтобы не применять к браузеру план,
 * подтверждённый на приветствии другой формы (0009, U5). Переносить ради
 * этого core/hello.c в датапат незачем — признак читается из тех же
 * расширений, что уже разбираются ради имени. */
static int has_tls13(const uint8_t *b, size_t exts_off, size_t exts_end) {
    size_t off = exts_off;
    while (off + 4 <= exts_end) {
        uint16_t type = rd16(b + off);
        size_t elen = rd16(b + off + 2);
        off += 4;
        if (off + elen > exts_end) {
            return 0;
        }
        if (type == EXT_SUPPORTED_VERSIONS) {
            if (elen < 1) { return 0; }
            size_t list_len = b[off];
            size_t p = off + 1;
            if (p + list_len > off + elen) { return 0; }
            for (size_t q = p; q + 2 <= p + list_len; q += 2) {
                if (rd16(b + q) == TLS13_VERSION) { return 1; }
            }
            return 0;
        }
        off += elen;
    }
    return 0;
}

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
    if (out->record_type != TLS_HANDSHAKE) {
        return 0;
    }

    /* Запись может не влезть в один сегмент — и у браузера она НЕ ВЛЕЗАЕТ.
     *
     * Приветствие curl — три сотни байт. Приветствие браузера — полторы
     * тысячи и больше: GREASE, ALPN, набивка. На PPPoE это не помещается в
     * MSS и приходит двумя сегментами. Ранняя редакция требовала запись
     * целиком и потому не узнавала браузер вовсе: на живой линии 2079
     * записей рукопожатия прошли мимо, а проверял я curl'ом, у которого всё
     * влезало.
     *
     * Разбираем столько, сколько пришло. Каждое поле всё равно проверяется по
     * границе доступного, поэтому обрывок просто остановит разбор там, где
     * данные кончились. Имя при этом обычно уже прочитано: расширения идут
     * после наборов шифров, а набивка — последней.
     *
     * Чего НЕ делаем: не выдаём конец записи. Он за пределами сегмента, и
     * якорь, который на него опирается, обязан остаться невычислимым —
     * иначе план порежет поток не там, где договаривались (§2.5). */
    /* Две границы, и путать их нельзя.
     *
     *   claimed  — конец записи по её собственному заголовку. Это ОБЕЩАНИЕ
     *              отправителя, и внутренние поля обязаны в него укладываться;
     *   avail    — сколько байт реально пришло.
     *
     * Поле, не влезающее в avail, — обрывок: остальное придёт следующим
     * сегментом. Поле, не влезающее в claimed, — противоречие: запись спорит
     * сама с собой, и доверять её разметке нельзя. Из одного пакета эти
     * случаи различаются только так, и различать их обязательно: иначе либо
     * теряется каждый браузер, либо принимается любая подделка. */
    const size_t claimed = REC_HDR + rec_len;
    const size_t avail = len;
    size_t end = claimed < avail ? claimed : avail;

    size_t off = REC_HDR;
    if (off + HS_HDR > end) {
        return 0;
    }
    if (b[off] == HS_SERVER_HELLO) {
        /* ОТВЕТ СЕРВЕРА. Дальше не разбираем: якоря считаются по НАШЕМУ
           приветствию, а обратному направлению от этого модуля нужен ровно
           один факт — сервер поздоровался.
 
           ЧТО ЭТО ЗА УРОВЕНЬ СВИДЕТЕЛЬСТВА, честно. Тело ServerHello здесь не
           читается ни на байт: проверяются заголовок записи, тип сообщения и
           согласованность ДВУХ ОБЪЯВЛЕННЫХ длин. Это признак сообщения, а не
           разбор полного валидного ServerHello, и выдавать его за второе
           нельзя.

           Донорская приёмка (acceptServerHello, z2k-detect/internal/classify/
           trigger.go:67-70) слабее: ей хватает шести байт и тела она тоже не
           смотрит. Наши три условия сверх неё — пришедший заголовок
           рукопожатия, обещанное под него место и отсутствие самопротиворечия
           записи — сужают приём, а не расширяют.

           Нижняя граница длины не выдумана: ServerHello по RFC 8446 §4.1.3
           несёт legacy_version 2 + random 32 + legacy_session_id_echo (1 байт
           длины) + cipher_suite 2 + legacy_compression_method 1, то есть не
           меньше 38 байт тела. Рукопожатие нулевой или явно недостаточной
           длины ServerHello'ом быть не может, и признавать его ответом
           сервера — обманывать приёмку вопроса. */
        size_t sh_len = (size_t)b[off + 1] << 16 | (size_t)b[off + 2] << 8 | b[off + 3];
        if (sh_len >= SERVER_HELLO_MIN_BODY && off + HS_HDR + sh_len <= claimed) {
            out->is_server_hello = 1;
        }
        return 0;
    }
    if (b[off] != HS_CLIENT_HELLO) {
        return 0;
    }
    size_t hs_len = (size_t)b[off + 1] << 16 | (size_t)b[off + 2] << 8 | b[off + 3];
    off += HS_HDR;
    if (off + hs_len > claimed) {
        /* Рукопожатие не влезает даже в собственную запись. */
        return 0;
    }
    size_t hs_end = off + hs_len;
    if (hs_end <= avail) {
        out->have_hello_middle = 1;
        out->hello_middle = off + hs_len / 2;
    } else {
        /* Продолжается в следующем сегменте: читаем до конца пришедшего,
           середина приветствия якорем служить не может. */
        hs_end = avail;
    }

    out->is_client_hello = 1;

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
    if (off + exts_len > claimed) {
        /* Блок расширений не влезает даже в объявленную запись: разметке
           доверять нельзя, имя не выдаём. */
        return 0;
    }
    size_t exts_end = off + exts_len;
    if (exts_end > hs_end) {
        /* Влезает в запись, но не в пришедшее: у браузера блок заканчивается
           набивкой в следующем сегменте. Читаем до конца пришедшего — имя
           обычно уже здесь, потому что server_name клиенты кладут в начало
           блока, а набивку в конец. */
        exts_end = hs_end;
        out->exts_truncated = 1;
    }

    /* ФОРМУ ОБЪЯВЛЯЕМ ТОЛЬКО ПО ПОЛНОМУ БЛОКУ РАСШИРЕНИЙ.
       has_tls13 возвращает ноль и когда расширения нет, и когда блок
       оборван, — а это разные вещи. У браузера supported_versions вполне
       может приехать ВТОРЫМ сегментом вслед за server_name из первого, и
       тогда «признака не нашли» значит «ещё не всё пришло», а не «клиент не
       умеет TLS 1.3». Пересборки потока у нас нет по проекту, так что случай
       штатный, а не редкий.

       Уверенный ответ на оборванном блоке — это выдуманный замер: он уехал
       бы в форму приветствия, а оттуда в каталог и в ограничение применения
       (§2.4, «не измерено» ≠ «нет»). */
    if (!out->exts_truncated) {
        out->is_tls13 = has_tls13(b, off, exts_end);
    }

    size_t so = 0, sl = 0;
    if (find_sni(b, off, exts_end, &so, &sl) == 0) {
        out->have_sni = 1;
        out->sni_off = so;
        out->sni_len = sl;
    }
    return 0;
}
