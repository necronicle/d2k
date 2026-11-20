#include "d2km_tls.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define EXT_SNI 0
#define EXT_PADDING 21
#define EXT_PSK 41
#define EXT_KEY_SHARE 51

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static void wr16(uint8_t *p, size_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

d2km_tls_code d2km_tls_parse(const uint8_t *b, size_t n, d2km_tls_hello *h)
{
    if (b == NULL || h == NULL)
        return D2KM_TLS_MALFORMED;
    if (n < 5)
        return D2KM_TLS_SHORT;
    if (b[0] != 0x16)
        return D2KM_TLS_NOT_HELLO;
    size_t rec = rd16(b + 3);
    if (rec > D2KM_TLS_MAX)
        return D2KM_TLS_TOO_BIG;
    if (n < 5 + rec)
        return D2KM_TLS_SHORT;
    if (rec < 4 || b[5] != 0x01)
        return D2KM_TLS_NOT_HELLO;
    size_t hs = (size_t)b[6] << 16 | (size_t)b[7] << 8 | b[8];
    if (hs + 4 != rec)
        return D2KM_TLS_MALFORMED;
    memset(h, 0, offsetof(d2km_tls_hello, arena));
    h->record_version = rd16(b + 1);
    const uint8_t *p = b + 9, *end = b + 5 + rec;
    if (end - p < 35)
        return D2KM_TLS_MALFORMED;
    h->version = rd16(p);
    memcpy(h->random, p + 2, 32);
    p += 34;
    h->session_id_length = *p++;
    if (h->session_id_length > 32 || end - p < h->session_id_length + 2)
        return D2KM_TLS_MALFORMED;
    memcpy(h->session_id, p, h->session_id_length);
    p += h->session_id_length;
    size_t cl = rd16(p);
    p += 2;
    if (cl < 2 || (cl & 1) || (size_t)(end - p) < cl + 1)
        return D2KM_TLS_MALFORMED;
    h->ciphers_offset = 0;
    h->ciphers_length = (uint16_t)cl;
    memcpy(h->arena, p, cl);
    p += cl;
    size_t ml = *p++;
    if (ml < 1 || (size_t)(end - p) < ml)
        return D2KM_TLS_MALFORMED;
    h->compression_offset = (uint16_t)cl;
    h->compression_length = (uint8_t)ml;
    memcpy(h->arena + cl, p, ml);
    p += ml;
    size_t a = cl + ml;
    if (p == end) {
        h->arena_length = a;
        return D2KM_TLS_OK;
    }
    if (end - p < 2)
        return D2KM_TLS_MALFORMED;
    size_t el = rd16(p);
    p += 2;
    if ((size_t)(end - p) != el)
        return D2KM_TLS_MALFORMED;
    while (p < end) {
        if (end - p < 4)
            return D2KM_TLS_MALFORMED;
        uint16_t type = rd16(p);
        size_t len = rd16(p + 2);
        p += 4;
        if ((size_t)(end - p) < len)
            return D2KM_TLS_MALFORMED;
        for (size_t i = 0; i < h->ext_count; i++)
            if (h->ext[i].type == type)
                return D2KM_TLS_MALFORMED;   /* RFC 8446 §4.2: повтор запрещён */
        if (h->ext_count >= D2KM_TLS_EXT_MAX)
            return D2KM_TLS_TOO_BIG;
        h->ext[h->ext_count].type = type;
        h->ext[h->ext_count].length = (uint16_t)len;
        h->ext[h->ext_count].offset = (uint16_t)a;
        h->ext_count++;
        memcpy(h->arena + a, p, len);
        a += len;
        p += len;
    }
    h->arena_length = a;
    return D2KM_TLS_OK;
}

/* Длина тела ClientHello без заголовка рукопожатия. */
static size_t body_length(const d2km_tls_hello *h)
{
    size_t n = 2 + 32 + 1 + (size_t)h->session_id_length + 2 +
               (size_t)h->ciphers_length + 1 + (size_t)h->compression_length;
    if (h->ext_count) {
        n += 2;
        for (size_t i = 0; i < h->ext_count; i++)
            n += 4 + (size_t)h->ext[i].length;
    }
    return n;
}

size_t d2km_tls_build(const d2km_tls_hello *h, uint8_t *out, size_t cap)
{
    size_t body = body_length(h);
    size_t total = 5 + 4 + body;
    if (body + 4 > D2KM_TLS_MAX || out == NULL || cap < total)
        return 0;
    uint8_t *p = out;
    p[0] = 0x16;
    wr16(p + 1, h->record_version);
    wr16(p + 3, body + 4);
    p[5] = 0x01;
    p[6] = (uint8_t)(body >> 16);
    p[7] = (uint8_t)(body >> 8);
    p[8] = (uint8_t)body;
    p += 9;
    wr16(p, h->version);
    memcpy(p + 2, h->random, 32);
    p += 34;
    *p++ = h->session_id_length;
    memcpy(p, h->session_id, h->session_id_length);
    p += h->session_id_length;
    wr16(p, h->ciphers_length);
    memcpy(p + 2, h->arena + h->ciphers_offset, h->ciphers_length);
    p += 2 + h->ciphers_length;
    *p++ = h->compression_length;
    memcpy(p, h->arena + h->compression_offset, h->compression_length);
    p += h->compression_length;
    if (h->ext_count) {
        size_t el = body_length(h) - (size_t)(p + 2 - (out + 9));
        wr16(p, el);
        p += 2;
        for (size_t i = 0; i < h->ext_count; i++) {
            wr16(p, h->ext[i].type);
            wr16(p + 2, h->ext[i].length);
            memcpy(p + 4, h->arena + h->ext[i].offset, h->ext[i].length);
            p += 4 + h->ext[i].length;
        }
    }
    return (size_t)(p - out);
}

static long find_ext(const d2km_tls_hello *h, uint16_t type)
{
    for (size_t i = 0; i < h->ext_count; i++)
        if (h->ext[i].type == type)
            return (long)i;
    return -1;
}

/* SNI: list_len(2) name_type(1)=0 name_len(2) name. */
static d2km_tls_code sni_name(const d2km_tls_hello *h, const uint8_t **name,
                              size_t *n, size_t *in_ext)
{
    long i = find_ext(h, EXT_SNI);
    if (i < 0)
        return D2KM_TLS_ABSENT;
    const uint8_t *d = h->arena + h->ext[i].offset;
    size_t len = h->ext[i].length;
    if (len < 5 || rd16(d) != len - 2)
        return D2KM_TLS_MALFORMED;
    size_t p = 2;
    while (p + 3 <= len) {
        uint8_t t = d[p];
        size_t l = rd16(d + p + 1);
        if (p + 3 + l > len)
            return D2KM_TLS_MALFORMED;
        if (t == 0) {
            *name = d + p + 3;
            *n = l;
            *in_ext = p + 3;
            return D2KM_TLS_OK;
        }
        p += 3 + l;
    }
    return D2KM_TLS_ABSENT;
}

d2km_tls_code d2km_tls_sni(const d2km_tls_hello *h, char *out, size_t cap)
{
    const uint8_t *name;
    size_t n, at;
    d2km_tls_code c = sni_name(h, &name, &n, &at);
    if (c != D2KM_TLS_OK)
        return c;
    if (out == NULL || cap <= n)
        return D2KM_TLS_TOO_BIG;
    memcpy(out, name, n);
    out[n] = '\0';
    return D2KM_TLS_OK;
}

/* Пересобирает арену: расширение type заменяется данными data (если
 * data_present), удаляется (если drop), или добавляется (перед
 * pre_shared_key, который по RFC 8446 обязан быть последним). */
static d2km_tls_code rebuild(d2km_tls_hello *h, uint16_t type, int drop,
                             const uint8_t *data, size_t n)
{
    d2km_tls_hello *t = malloc(sizeof(*t));
    if (t == NULL)
        return D2KM_TLS_TOO_BIG;
    memcpy(t, h, offsetof(d2km_tls_hello, arena));
    size_t a = 0;
    memcpy(t->arena, h->arena + h->ciphers_offset, h->ciphers_length);
    t->ciphers_offset = 0;
    a += h->ciphers_length;
    memcpy(t->arena + a, h->arena + h->compression_offset, h->compression_length);
    t->compression_offset = (uint16_t)a;
    a += h->compression_length;
    t->ext_count = 0;
    /* Существующее расширение заменяется на своём месте, новое — вставляется. */
    int placed = drop || find_ext(h, type) >= 0;
    for (size_t i = 0; i <= h->ext_count; i++) {
        int at_psk = i < h->ext_count && h->ext[i].type == EXT_PSK;
        if (!placed && (i == h->ext_count || at_psk)) {
            if (t->ext_count >= D2KM_TLS_EXT_MAX || a + n > D2KM_TLS_MAX) {
                free(t);
                return D2KM_TLS_TOO_BIG;
            }
            t->ext[t->ext_count].type = type;
            t->ext[t->ext_count].length = (uint16_t)n;
            t->ext[t->ext_count].offset = (uint16_t)a;
            if (n)
                memcpy(t->arena + a, data, n);
            a += n;
            t->ext_count++;
            placed = 1;
        }
        if (i == h->ext_count)
            break;
        const d2km_tls_ext *e = &h->ext[i];
        if (e->type == type) {
            if (drop)
                continue;
            /* Замена на месте. */
            if (a + n > D2KM_TLS_MAX) {
                free(t);
                return D2KM_TLS_TOO_BIG;
            }
            t->ext[t->ext_count].type = type;
            t->ext[t->ext_count].length = (uint16_t)n;
            t->ext[t->ext_count].offset = (uint16_t)a;
            if (n)
                memcpy(t->arena + a, data, n);
            a += n;
            t->ext_count++;
            placed = 1;
            continue;
        }
        if (a + e->length > D2KM_TLS_MAX) {
            free(t);
            return D2KM_TLS_TOO_BIG;
        }
        t->ext[t->ext_count] = *e;
        t->ext[t->ext_count].offset = (uint16_t)a;
        memcpy(t->arena + a, h->arena + e->offset, e->length);
        a += e->length;
        t->ext_count++;
    }
    t->arena_length = a;
    if (body_length(t) + 4 > D2KM_TLS_MAX) {
        free(t);
        return D2KM_TLS_TOO_BIG;
    }
    memcpy(h, t, offsetof(d2km_tls_hello, arena) + a);
    free(t);
    return D2KM_TLS_OK;
}

d2km_tls_code d2km_tls_put_ext(d2km_tls_hello *h, uint16_t type,
                               const uint8_t *data, size_t n)
{
    if (h == NULL || n > 0xffff || (data == NULL && n))
        return D2KM_TLS_MALFORMED;
    return rebuild(h, type, 0, data, n);
}

d2km_tls_code d2km_tls_drop_ext(d2km_tls_hello *h, uint16_t type)
{
    if (h == NULL)
        return D2KM_TLS_MALFORMED;
    if (find_ext(h, type) < 0)
        return D2KM_TLS_ABSENT;
    return rebuild(h, type, 1, NULL, 0);
}

d2km_tls_code d2km_tls_set_sni(d2km_tls_hello *h, const char *name)
{
    if (h == NULL || name == NULL)
        return D2KM_TLS_MALFORMED;
    size_t n = strlen(name);
    if (n == 0 || n > 255)
        return D2KM_TLS_MALFORMED;
    if (find_ext(h, EXT_SNI) < 0)
        return D2KM_TLS_ABSENT;
    uint8_t d[5 + 255];
    wr16(d, n + 3);
    d[2] = 0;
    wr16(d + 3, n);
    memcpy(d + 5, name, n);
    return rebuild(h, EXT_SNI, 0, d, n + 5);
}

d2km_tls_code d2km_tls_pad_to(d2km_tls_hello *h, size_t total)
{
    if (h == NULL)
        return D2KM_TLS_MALFORMED;
    if (find_ext(h, EXT_PADDING) >= 0) {
        d2km_tls_code c = d2km_tls_drop_ext(h, EXT_PADDING);
        if (c != D2KM_TLS_OK)
            return c;
    }
    size_t now = 9 + body_length(h);
    size_t cost = 4 + (h->ext_count ? 0 : 2);
    if (total < now + cost)
        return D2KM_TLS_ABSENT;
    size_t k = total - now - cost;
    if (total - 5 > D2KM_TLS_MAX || k > 0xffff)
        return D2KM_TLS_TOO_BIG;
    uint8_t *zeros = calloc(1, k ? k : 1);
    if (zeros == NULL)
        return D2KM_TLS_TOO_BIG;
    d2km_tls_code c = rebuild(h, EXT_PADDING, 0, zeros, k);
    free(zeros);
    return c;
}

void d2km_rng_seed(d2km_rng *r, uint64_t seed)
{
    r->state = seed;
}

uint64_t d2km_rng_next(d2km_rng *r)
{
    uint64_t z = (r->state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

void d2km_rng_fill(d2km_rng *r, uint8_t *p, size_t n)
{
    while (n) {
        uint64_t v = d2km_rng_next(r);
        for (int i = 0; i < 8 && n; i++, n--) {
            *p++ = (uint8_t)v;
            v >>= 8;
        }
    }
}

d2km_tls_code d2km_tls_refresh(d2km_tls_hello *h, d2km_rng *r)
{
    if (h == NULL || r == NULL)
        return D2KM_TLS_MALFORMED;
    d2km_rng_fill(r, h->random, 32);
    d2km_rng_fill(r, h->session_id, h->session_id_length);
    long i = find_ext(h, EXT_KEY_SHARE);
    if (i < 0)
        return D2KM_TLS_OK;
    uint8_t *d = h->arena + h->ext[i].offset;
    size_t len = h->ext[i].length;
    if (len < 2 || rd16(d) != len - 2)
        return D2KM_TLS_MALFORMED;
    size_t p = 2;
    while (p < len) {
        if (p + 4 > len)
            return D2KM_TLS_MALFORMED;
        size_t kl = rd16(d + p + 2);
        if (p + 4 + kl > len)
            return D2KM_TLS_MALFORMED;
        d2km_rng_fill(r, d + p + 4, kl);
        p += 4 + kl;
    }
    return D2KM_TLS_OK;
}

static size_t ext_block_offset(const d2km_tls_hello *h)
{
    return 9 + 2 + 32 + 1 + (size_t)h->session_id_length + 2 +
           (size_t)h->ciphers_length + 1 + (size_t)h->compression_length;
}

d2km_tls_code d2km_tls_sni_span(const d2km_tls_hello *h, uint32_t *off,
                                uint32_t *len)
{
    const uint8_t *name;
    size_t n, at;
    d2km_tls_code c = sni_name(h, &name, &n, &at);
    if (c != D2KM_TLS_OK)
        return c;
    size_t p = ext_block_offset(h) + 2;
    for (size_t i = 0; i < h->ext_count; i++) {
        if (h->ext[i].type == EXT_SNI) {
            if (off != NULL)
                *off = (uint32_t)(p + 4 + at);
            if (len != NULL)
                *len = (uint32_t)n;
            return D2KM_TLS_OK;
        }
        p += 4 + h->ext[i].length;
    }
    return D2KM_TLS_ABSENT;
}

size_t d2km_tls_bounds(const d2km_tls_hello *h, uint32_t *out, size_t cap)
{
    size_t k = 0;
    uint32_t v[8 + D2KM_TLS_EXT_MAX + 2];
    size_t p = 0;
    v[k++] = 5;                       /* заголовок рукопожатия */
    v[k++] = 9;                       /* версия */
    v[k++] = 11;                      /* Random */
    p = 43;
    v[k++] = (uint32_t)p;             /* session_id */
    p += 1 + h->session_id_length;
    v[k++] = (uint32_t)p;             /* наборы шифров */
    p += 2 + h->ciphers_length;
    v[k++] = (uint32_t)p;             /* сжатие */
    p += 1 + h->compression_length;
    if (h->ext_count) {
        v[k++] = (uint32_t)p;         /* блок расширений */
        p += 2;
        for (size_t i = 0; i < h->ext_count; i++) {
            v[k++] = (uint32_t)p;
            p += 4 + h->ext[i].length;
        }
    }
    uint32_t so, sl;
    if (d2km_tls_sni_span(h, &so, &sl) == D2KM_TLS_OK) {
        v[k++] = so;
        v[k++] = so + sl;
    }
    for (size_t i = 0; i < k && out != NULL && i < cap; i++)
        out[i] = v[i];
    return k;
}
