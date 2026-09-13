/* h3.c — HTTP/3 ровно настолько, чтобы получить код ответа. Контракт и
 * границы — в d2k_h3.h.
 *
 * Числа переменной длины здесь ТЕ ЖЕ, что в QUIC (RFC 9114 §16 ссылается на
 * RFC 9000 §16), поэтому берутся из core/quicwire.c, а не пишутся заново.
 * Префиксные целые QPACK (RFC 7541 §5.1) — другое кодирование, и оно своё:
 * N-битный префикс внутри байта, а не два старших бита на ширину.
 */
#include <string.h>

#include "d2k_h3.h"
#include "d2k_quicwire.h"

/* Типы кадров HTTP/3 (RFC 9114 §7.2). */
#define H3_DATA     0x00
#define H3_HEADERS  0x01
#define H3_SETTINGS 0x04

size_t d2k_h3_control(uint8_t *out, size_t cap) {
    if (!out || cap < 3) { return 0; }
    size_t o = 0;
    out[o++] = 0x00;   /* тип однонаправленного потока: управляющий */
    out[o++] = H3_SETTINGS;
    out[o++] = 0x00;   /* длина ноль: все умолчания нас устраивают */
    return o;
}

/* Префиксное целое QPACK/HPACK: n бит в первом байте, дальше семибитные
 * продолжения (RFC 7541 §5.1). */
static size_t prefix_int(uint8_t *out, size_t cap, uint8_t prefix_bits,
                         uint8_t flags, uint64_t value) {
    uint8_t max = (uint8_t)((1u << prefix_bits) - 1u);
    if (cap < 1) { return 0; }
    if (value < max) {
        out[0] = (uint8_t)(flags | (uint8_t)value);
        return 1;
    }
    out[0] = (uint8_t)(flags | max);
    size_t o = 1;
    value -= max;
    while (value >= 128) {
        if (o >= cap) { return 0; }
        out[o++] = (uint8_t)((value & 0x7f) | 0x80);
        value >>= 7;
    }
    if (o >= cap) { return 0; }
    out[o++] = (uint8_t)value;
    return o;
}

static int prefix_int_read(const uint8_t *p, size_t n, uint8_t prefix_bits,
                           uint64_t *out, size_t *used) {
    if (n < 1) { return -1; }
    uint8_t max = (uint8_t)((1u << prefix_bits) - 1u);
    uint64_t v = (uint64_t)(p[0] & max);
    size_t o = 1;
    if (v == max) {
        uint64_t m = 0;
        for (;;) {
            if (o >= n) { return -1; }
            uint8_t b = p[o++];
            v += (uint64_t)(b & 0x7f) << m;
            if ((b & 0x80) == 0) { break; }
            m += 7;
            if (m > 56) { return -1; }
        }
    }
    *out = v;
    *used = o;
    return 0;
}

size_t d2k_h3_request(const char *host, const char *path, uint8_t *out, size_t cap) {
    if (!out || !host) { return 0; }
    if (!path || !path[0]) { path = "/"; }
    size_t hlen = strlen(host);
    if (hlen == 0 || hlen > 255) { return 0; }

    uint8_t sec[512];
    size_t o = 0;
    /* Префикс секции: Required Insert Count = 0, Delta Base = 0. Ноль здесь
       значит «динамическая таблица не используется» — мы её и не объявляли. */
    sec[o++] = 0x00;
    sec[o++] = 0x00;
    /* Индексные поля статической таблицы (RFC 9204 приложение A):
       17 — :method GET, 23 — :scheme https, 1 — :path /. Признак «индексное
       поле, статическая таблица» — старшие два бита 11, шесть бит под номер. */
    o += prefix_int(sec + o, sizeof sec - o, 6, 0xc0, 17);
    o += prefix_int(sec + o, sizeof sec - o, 6, 0xc0, 23);
    o += prefix_int(sec + o, sizeof sec - o, 6, 0xc0, 1);
    /* :authority — имя из статической таблицы (номер 0), значение своё,
       без сжатия: поле «литерал со ссылкой на имя», признак 01, бит N=1
       (статическая), четыре бита под номер. */
    o += prefix_int(sec + o, sizeof sec - o, 4, 0x50, 0);
    o += prefix_int(sec + o, sizeof sec - o, 7, 0x00, hlen);  /* длина, без Хаффмана */
    if (o + hlen > sizeof sec) { return 0; }
    memcpy(sec + o, host, hlen); o += hlen;
    /* Путь, отличный от "/", едет литералом со ссылкой на имя :path (номер 1).
       Для "/" уже хватило индексного поля выше. */
    if (strcmp(path, "/") != 0) {
        size_t plen = strlen(path);
        if (plen > 255) { return 0; }
        o += prefix_int(sec + o, sizeof sec - o, 4, 0x50, 1);
        o += prefix_int(sec + o, sizeof sec - o, 7, 0x00, plen);
        if (o + plen > sizeof sec) { return 0; }
        memcpy(sec + o, path, plen); o += plen;
    }

    size_t r = 0;
    if (cap < 1) { return 0; }
    out[r++] = H3_HEADERS;
    r += d2k_qw_varint_write(out + r, cap - r, o);
    if (r + o > cap) { return 0; }
    memcpy(out + r, sec, o); r += o;
    return r;
}

/* Код Хаффмана цифры — пять бит со значением самой цифры (RFC 7541
 * приложение B: '0'..'9' это 0x0..0x9 длиной 5). Трёхзначный статус это
 * пятнадцать бит, добитые единицами до двух байт. Полная таблица Хаффмана
 * здесь не нужна и не пишется: всё, что мы декодируем, — три цифры. */
static int huff_status(const uint8_t *v, size_t n, int *status) {
    if (n != 2) { return -1; }
    uint32_t bits = (uint32_t)v[0] << 8 | v[1];
    int val = 0;
    for (int i = 0; i < 3; i++) {
        uint32_t code = (bits >> (11 - 5 * i)) & 0x1f;
        if (code > 9) { return -1; }
        val = val * 10 + (int)code;
    }
    *status = val;
    return 0;
}

/* Статусы, которые статическая таблица QPACK хранит целиком (RFC 9204
 * приложение A). Литерал со ссылкой на имя :status тоже поддержан ниже. */
static int static_status(uint64_t idx, int *status) {
    switch (idx) {
    case 24: *status = 103; return 0;
    case 25: *status = 200; return 0;
    case 26: *status = 304; return 0;
    case 27: *status = 404; return 0;
    case 28: *status = 503; return 0;
    case 63: *status = 100; return 0;
    case 64: *status = 204; return 0;
    case 65: *status = 206; return 0;
    case 66: *status = 302; return 0;
    case 67: *status = 400; return 0;
    case 68: *status = 403; return 0;
    case 69: *status = 421; return 0;
    case 70: *status = 425; return 0;
    case 71: *status = 500; return 0;
    default: return -1;
    }
}

/* Номера статической таблицы, у которых ИМЯ — :status. Нужны, чтобы принять
 * литерал со ссылкой на имя: сервер вправе прислать любой код, а в таблице
 * лежат только четырнадцать. */
static int name_is_status(uint64_t idx) {
    return idx == 24 || idx == 25 || idx == 26 || idx == 27 || idx == 28 ||
           (idx >= 63 && idx <= 71);
}

static int decode_section(const uint8_t *p, size_t n, int *status) {
    size_t i = 0;
    uint64_t v = 0; size_t w = 0;
    /* Префикс секции: два префиксных целых. */
    if (prefix_int_read(p + i, n - i, 8, &v, &w) != 0) { return -1; }
    i += w;
    if (i >= n) { return -1; }
    if (prefix_int_read(p + i, n - i, 7, &v, &w) != 0) { return -1; }
    i += w;

    while (i < n) {
        uint8_t b = p[i];
        if (b & 0x80) {
            /* Индексное поле. Бит 0x40 — статическая таблица; динамическую мы
               не объявляли, и ссылка на неё это ошибка сервера, а не наша
               догадка. */
            if (prefix_int_read(p + i, n - i, 6, &v, &w) != 0) { return -1; }
            i += w;
            if ((b & 0x40) && static_status(v, status) == 0) { return 0; }
        } else if ((b & 0xc0) == 0x40) {
            /* Литерал со ссылкой на имя. */
            int is_static = (b & 0x10) != 0;
            if (prefix_int_read(p + i, n - i, 4, &v, &w) != 0) { return -1; }
            i += w;
            uint64_t name_idx = v;
            if (i >= n) { return -1; }
            int huff = (p[i] & 0x80) != 0;
            uint64_t vlen = 0;
            if (prefix_int_read(p + i, n - i, 7, &vlen, &w) != 0) { return -1; }
            i += w;
            if (vlen > n - i) { return -1; }
            if (is_static && name_is_status(name_idx)) {
                if (huff) {
                    if (huff_status(p + i, (size_t)vlen, status) == 0) { return 0; }
                } else if (vlen == 3) {
                    *status = (p[i] - '0') * 100 + (p[i + 1] - '0') * 10 + (p[i + 2] - '0');
                    return 0;
                }
            }
            i += (size_t)vlen;
        } else if ((b & 0xe0) == 0x20) {
            /* Изменение ёмкости динамической таблицы — нам оно безразлично. */
            if (prefix_int_read(p + i, n - i, 5, &v, &w) != 0) { return -1; }
            i += w;
        } else {
            /* Литерал с ЛИТЕРАЛЬНЫМ именем: пропускаем имя и значение. */
            uint64_t nlen = 0;
            if (prefix_int_read(p + i, n - i, 3, &nlen, &w) != 0) { return -1; }
            i += w;
            if (nlen > n - i) { return -1; }
            i += (size_t)nlen;
            if (i >= n) { return -1; }
            uint64_t vlen = 0;
            if (prefix_int_read(p + i, n - i, 7, &vlen, &w) != 0) { return -1; }
            i += w;
            if (vlen > n - i) { return -1; }
            i += (size_t)vlen;
        }
    }
    return -1;
}

int d2k_h3_status(const uint8_t *buf, size_t n, int *status) {
    if (!buf || !status) { return -1; }
    size_t i = 0;
    while (i < n) {
        uint64_t type = 0, len = 0; size_t w = 0;
        if (d2k_qw_varint_read(buf + i, n - i, &type, &w) != 0) { return -1; }
        i += w;
        if (d2k_qw_varint_read(buf + i, n - i, &len, &w) != 0) { return -1; }
        i += w;
        if (len > n - i) { return -1; }   /* кадр не доехал целиком */
        if (type == H3_HEADERS) {
            return decode_section(buf + i, (size_t)len, status);
        }
        /* Прочие кадры (в том числе неизвестные и grease) пропускаются по
           длине — ровно это и требует RFC 9114 §9. */
        i += (size_t)len;
    }
    return -1;
}
