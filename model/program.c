#include "d2km_program.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char *const anchor_names[D2KM_ANCHOR_END] = {
    [D2KM_AT_PAYLOAD_START] = "payload_start",
    [D2KM_AT_SNI_START] = "sni_start",
    [D2KM_AT_SNI_END] = "sni_end",
    [D2KM_AT_HELLO_MIDDLE] = "hello_middle",
    [D2KM_AT_RECORD_END] = "record_end",
    [D2KM_AT_SNI_MIDDLE] = "sni_middle",
};

const char *d2km_anchor_name(d2km_anchor a)
{
    return (a >= 0 && a < D2KM_ANCHOR_END) ? anchor_names[a] : NULL;
}

static int has_why(const char *w)
{
    return w[0] != '\0' && memchr(w, '\0', D2KM_WHY_MAX) != NULL;
}

static const char *proto_word(const d2km_program *p)
{
    switch (p->protocol) {
    case D2KM_P_TLS12:
    case D2KM_P_TLS13:
        return p->transport == D2KM_TCP ? "tcp tls" : NULL;
    case D2KM_P_QUIC1:
    case D2KM_P_QUIC2:
    case D2KM_P_HTTP3:
        return p->transport == D2KM_UDP ? "udp quic" : NULL;
    case D2KM_P_HTTP11:
        return p->transport == D2KM_TCP ? "tcp http" : NULL;
    case D2KM_P_STUN:
        return p->transport == D2KM_UDP ? "udp voice" : NULL;
    default:
        return NULL;
    }
}

d2km_program_check_code d2km_program_check(const d2km_program *p)
{
    if (p == NULL)
        return D2KM_PC_EMPTY;
    if (proto_word(p) == NULL)
        return D2KM_PC_BAD_PROTOCOL;
    if (p->payload_count > D2KM_PROG_PAYLOADS || p->fake_count > D2KM_PROG_FAKES ||
        p->split_count > D2KM_PROG_SPLITS)
        return D2KM_PC_BAD_VALUE;
    if (p->fake_count == 0 && p->split_count == 0)
        return D2KM_PC_EMPTY;
    for (size_t i = 0; i < p->payload_count; i++) {
        const d2km_payload *pl = &p->payloads[i];
        if (pl->length == 0 || pl->length > D2KM_PROG_PAYLOAD_MAX)
            return D2KM_PC_BAD_PAYLOAD;
        if (!has_why(pl->why))
            return D2KM_PC_NO_WHY;
    }
    for (size_t i = 0; i < p->fake_count; i++) {
        const d2km_fake *f = &p->fakes[i];
        if (f->payload >= p->payload_count)
            return D2KM_PC_BAD_PAYLOAD;
        if (f->repeats == 0 || f->between > 1)
            return D2KM_PC_BAD_VALUE;
        if (!has_why(f->why))
            return D2KM_PC_NO_WHY;
        /* Фальшивка обязана не дойти до сервера или быть им отвергнута. */
        const d2km_poison *z = &f->poison;
        if (!z->ttl && !z->badsum && !z->md5 && !z->tcpts && !z->seqshift)
            return D2KM_PC_SERVER_ACCEPTS;
        if (p->transport == D2KM_UDP && (z->badsum || z->md5 || z->tcpts || z->seqshift))
            return D2KM_PC_BAD_VALUE;   /* у UDP этих полей нет */
        if (f->between && p->split_count == 0)
            return D2KM_PC_BAD_VALUE;   /* «между частями» без разреза */
    }
    for (size_t i = 0; i < p->split_count; i++) {
        if (d2km_anchor_name(p->splits[i].anchor) == NULL)
            return D2KM_PC_BAD_VALUE;
        if (!has_why(p->splits[i].why))
            return D2KM_PC_NO_WHY;
    }
    if (p->reverse && (p->split_count == 0 || !has_why(p->order_why)))
        return p->split_count ? D2KM_PC_NO_WHY : D2KM_PC_BAD_VALUE;
    return D2KM_PC_OK;
}

#include <stdarg.h>

/* Писатель текста; заодно потоково считает FNV-1a 64 по всем байтам. */
typedef struct {
    char *out;
    size_t cap, len;
    uint64_t hash;
} sink;

static void put(sink *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void put(sink *s, const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    size_t k = (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1;
    if (s->out != NULL && s->len + k < s->cap)
        memcpy(s->out + s->len, buf, k);
    for (size_t i = 0; i < k; i++) {
        s->hash ^= (uint8_t)buf[i];
        s->hash *= 1099511628211ULL;
    }
    s->len += k;
}

static void put_hex(sink *s, const uint8_t *b, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        char two[3] = {hx[b[i] >> 4], hx[b[i] & 15], 0};
        put(s, "%s", two);
    }
}

/* Тело плана без заголовка и id — по нему считается хэш. */
static size_t body(const d2km_program *p, sink *s)
{
    size_t start = s->len;
    put(s, "proto %s\n", proto_word(p));
    for (size_t i = 0; i < p->fake_count; i++)
        if (p->fakes[i].poison.md5) {
            put(s, "wire detect-tcp-v1\n");
            break;
        }
    for (size_t i = 0; i < p->payload_count; i++) {
        put(s, "payload %zu ", i + 1);
        put_hex(s, p->payloads[i].bytes, p->payloads[i].length);
        put(s, "\n");
    }
    for (size_t i = 0; i < p->fake_count; i++) {
        const d2km_poison *z = &p->fakes[i].poison;
        put(s, "poison %zu", i + 1);
        if (z->badsum) put(s, " badsum");
        if (z->tcpts) put(s, " tcpts");
        if (z->md5) put(s, " md5");
        if (z->ttl) put(s, " ttl=%u", (unsigned)z->ttl);
        if (z->seqshift) put(s, " seqshift=%" PRId32, z->seqshift);
        put(s, "\n");
    }
    for (size_t i = 0; i < p->split_count; i++)
        put(s, "split %s %d\n", d2km_anchor_name(p->splits[i].anchor),
            (int)p->splits[i].offset);
    for (size_t i = 0; i < p->fake_count; i++) {
        const d2km_fake *f = &p->fakes[i];
        put(s, "fake payload=%u poison=%zu repeats=%u gap_us=%" PRIu32 " place=%s\n",
            (unsigned)f->payload + 1, i + 1, (unsigned)f->repeats, f->gap_us,
            f->between ? "between" : "before");
    }
    put(s, "order %s\n", p->reverse ? "reverse" : "forward");
    return s->len - start;
}

uint64_t d2km_program_hash(const d2km_program *p)
{
    if (d2km_program_check(p) != D2KM_PC_OK)
        return 0;
    sink s = {.hash = 1469598103934665603ULL};
    body(p, &s);
    return s.hash ? s.hash : 1;
}

size_t d2km_program_text(const d2km_program *p, char *out, size_t cap)
{
    if (d2km_program_check(p) != D2KM_PC_OK || out == NULL || cap == 0)
        return 0;
    uint64_t h = d2km_program_hash(p);
    sink s = {.out = out, .cap = cap};
    put(&s, "d2k-plan 1 13\n");
    put(&s, "id %016" PRIx64 "%016" PRIx64 "\n", h, ~h);
    body(p, &s);
    if (s.len >= cap) {
        out[0] = '\0';
        return 0;
    }
    out[s.len] = '\0';
    return s.len;
}
