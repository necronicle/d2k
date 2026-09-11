/* x25519.c — обмен ключами X25519 (RFC 7748).
 *
 * ЗАЧЕМ. Проба на блокировку по объёму (core/volume.c) обязана качать объём
 * ВНУТРИ настоящей TLS-сессии: коробка считает байты установленного потока, а
 * не мусор на 443-м порту, и сервер мусорную сессию оборвёт сам — измерять
 * станет нечего. Настоящая сессия требует обмена ключами, а TLS 1.3 на живой
 * линии сегодня это X25519 практически всегда.
 *
 * РЕАЛИЗАЦИЯ — КЛАССИЧЕСКАЯ ЛЕСТНИЦА МОНТГОМЕРИ в поле 2^255-19, представление
 * radix-16 (16 «конечностей» по 16 бит в int64), как в TweetNaCl (Bernstein,
 * Janssen, Lange, Schwabe; public domain). Взята она, а не переизобретена: у
 * этого кода единственное в своём роде сочетание — он короток настолько, что
 * читается целиком, и при этом постоянен по времени (нет ни одной ветки по
 * секретным данным, обмен местами делает маска). Писать своё здесь означало бы
 * рисковать утечкой по времени ради строк, которые всё равно повторили бы
 * ту же лестницу.
 *
 * ПОСТОЯНСТВО ПО ВРЕМЕНИ здесь не паранойя и не украшение: секрет живёт ровно
 * одну пробу, но он же защищает сессию, внутри которой мы гоняем объём, а
 * сессия идёт по линии, где стоит коробка, которая эту линию слушает.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <string.h>

#include "d2k_crypto.h"

typedef int64_t gf[16];

static const gf gf_121665 = { 0xDB41, 1 };

static void car25519(gf o) {
    for (int i = 0; i < 16; i++) {
        int64_t c = o[i] >> 16;
        o[i] -= c << 16;
        if (i < 15) {
            o[i + 1] += c;
        } else {
            o[0] += 38 * c;
        }
    }
}

/* Обмен a и b по маске: b==1 меняет, b==0 нет. Ветки по секрету здесь быть не
   должно — отсюда маска, а не if. */
static void sel25519(gf p, gf q, int b) {
    int64_t mask = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n) {
    gf m, t;
    memcpy(t, n, sizeof t);
    car25519(t); car25519(t); car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xFFED;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xFFFF;
        }
        m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
        int b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xFFFF;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xFF);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n) {
    for (int i = 0; i < 16; i++) {
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7FFF; /* старший бит игнорируется — RFC 7748 §5 */
}

static void A(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) { o[i] = a[i] + b[i]; } }
static void Z(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) { o[i] = a[i] - b[i]; } }

static void M(gf o, const gf a, const gf b) {
    int64_t t[31];
    for (int i = 0; i < 31; i++) { t[i] = 0; }
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) { t[i + j] += a[i] * b[j]; }
    }
    for (int i = 0; i < 15; i++) { t[i] += 38 * t[i + 16]; }
    memcpy(o, t, 16 * sizeof(int64_t));
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a) { M(o, a, a); }

/* Обращение через возведение в степень p-2: та же лестница, никаких ветвей. */
static void inv25519(gf o, const gf i) {
    gf c;
    memcpy(c, i, sizeof c);
    for (int a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) { M(c, c, i); }
    }
    memcpy(o, c, sizeof c);
}

int d2k_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    if (!out || !scalar || !point) { return -1; }
    uint8_t z[32];
    gf x, a, b, c, d, e, f;
    memcpy(z, scalar, 32);
    /* Прижатие скаляра — RFC 7748 §5: три младших бита в ноль, старший в ноль,
       бит 254 в единицу. Без него результат не тот, и это не мелочь. */
    z[31] = (uint8_t)((z[31] & 127) | 64);
    z[0] &= 248;

    unpack25519(x, point);
    for (int i = 0; i < 16; i++) { b[i] = x[i]; d[i] = 0; a[i] = 0; c[i] = 0; }
    a[0] = 1; d[0] = 1;

    for (int i = 254; i >= 0; i--) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, gf_121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    M(a, a, c);
    pack25519(out, a);

    /* Нулевой общий секрет означает точку малого порядка на той стороне —
       законный отказ, а не «ключ ноль»: RFC 8446 §7.4.2 требует прервать
       рукопожатие, а не продолжать с предсказуемым секретом. */
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) { acc = (uint8_t)(acc | out[i]); }
    return acc == 0 ? -1 : 0;
}

int d2k_x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    static const uint8_t base[32] = { 9 };
    if (!out || !scalar) { return -1; }
    uint8_t z[32];
    memcpy(z, scalar, 32);
    /* Умножение на базовую точку не может дать ноль при прижатом скаляре,
       поэтому проверка из d2k_x25519 здесь не применима — и её отсутствие
       названо, а не забыто. */
    gf x, a, b, c, d, e, f;
    z[31] = (uint8_t)((z[31] & 127) | 64);
    z[0] &= 248;
    unpack25519(x, base);
    for (int i = 0; i < 16; i++) { b[i] = x[i]; d[i] = 0; a[i] = 0; c[i] = 0; }
    a[0] = 1; d[0] = 1;
    for (int i = 254; i >= 0; i--) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r); sel25519(c, d, r);
        A(e, a, c); Z(a, a, c); A(c, b, d); Z(b, b, d);
        S(d, e); S(f, a); M(a, c, a); M(c, b, e);
        A(e, a, c); Z(a, a, c); S(b, a); Z(c, d, f);
        M(a, c, gf_121665); A(a, a, d); M(c, c, a);
        M(a, d, f); M(d, b, x); S(b, e);
        sel25519(a, b, r); sel25519(c, d, r);
    }
    inv25519(c, c);
    M(a, a, c);
    pack25519(out, a);
    return 0;
}
