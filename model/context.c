#define _POSIX_C_SOURCE 200809L
#include "d2km_context.h"

#include <string.h>

uint64_t d2km_fnv1a64(const uint8_t *p, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static int name_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
           c == '_';
}

int d2km_target_name(d2km_target *t, const char *name)
{
    if (t == NULL || name == NULL)
        return -1;
    size_t n = strlen(name);
    if (n > 0 && name[n - 1] == '.')
        n--;
    if (n == 0 || n > D2KM_NAME_MAX)
        return -1;
    char buf[D2KM_NAME_MAX + 1];
    size_t label = 0;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        if (c == '.') {
            if (label == 0)
                return -1;
            label = 0;
        } else {
            if (!name_char(c) || ++label > 63)
                return -1;
        }
        buf[i] = c;
    }
    if (label == 0)
        return -1;
    buf[n] = '\0';
    memset(t, 0, sizeof(*t));
    t->has_name = 1;
    memcpy(t->name, buf, n + 1);
    return 0;
}

int d2km_target_address(d2km_target *t, d2km_family f, const uint8_t *addr,
                        uint16_t port)
{
    if (t == NULL || addr == NULL || port == 0 ||
        (f != D2KM_IPV4 && f != D2KM_IPV6))
        return -1;
    memset(t, 0, sizeof(*t));
    t->family = f;
    memcpy(t->addr, addr, f == D2KM_IPV4 ? 4 : 16);
    t->port = port;
    return 0;
}

int d2km_name_suffix_match(const char *name, const char *suffix)
{
    if (name == NULL || suffix == NULL)
        return 0;
    size_t n = strlen(name), s = strlen(suffix);
    if (s == 0 || s > n)
        return 0;
    if (memcmp(name + n - s, suffix, s) != 0)
        return 0;
    return n == s || name[n - s - 1] == '.';
}

int d2km_form_set(d2km_form *f, const uint8_t *hello, size_t hello_length,
                  const uint16_t *segments, size_t segment_count,
                  const uint8_t *tcp_options, size_t tcp_options_length,
                  int ech, int grease)
{
    if (f == NULL || (hello == NULL && hello_length) ||
        hello_length > UINT32_MAX || segment_count > D2KM_SEGMENTS_MAX ||
        (segments == NULL && segment_count) ||
        tcp_options_length > D2KM_TCP_OPTIONS_MAX ||
        (tcp_options == NULL && tcp_options_length))
        return -1;
    size_t sum = 0;
    for (size_t i = 0; i < segment_count; i++) {
        if (segments[i] == 0)
            return -1;
        sum += segments[i];
    }
    /* Сегментация описывает те же байты приветствия: сумма обязана совпасть. */
    if (segment_count && sum != hello_length)
        return -1;
    memset(f, 0, sizeof(*f));
    f->hello_length = (uint32_t)hello_length;
    f->hello_print = d2km_fnv1a64(hello, hello_length);
    f->segment_count = (uint8_t)segment_count;
    if (segment_count)
        memcpy(f->segments, segments, segment_count * sizeof(*segments));
    f->tcp_options_length = (uint8_t)tcp_options_length;
    if (tcp_options_length)
        memcpy(f->tcp_options, tcp_options, tcp_options_length);
    f->ech = ech != 0;
    f->grease = grease != 0;
    return 0;
}

static int protocol_transport(d2km_protocol p, d2km_transport t)
{
    switch (p) {
    case D2KM_P_TLS12:
    case D2KM_P_TLS13:
    case D2KM_P_HTTP11:
    case D2KM_P_HTTP2:
        return t == D2KM_TCP;
    case D2KM_P_QUIC1:
    case D2KM_P_QUIC2:
    case D2KM_P_HTTP3:
    case D2KM_P_STUN:
        return t == D2KM_UDP;
    case D2KM_P_DNS:
        return t == D2KM_TCP || t == D2KM_UDP;
    default:
        return 0;
    }
}

int d2km_context_valid(const d2km_context *c)
{
    if (c == NULL)
        return -1;
    if (c->family != D2KM_IPV4 && c->family != D2KM_IPV6)
        return -1;
    if (!protocol_transport(c->protocol, c->transport))
        return -1;
    if (c->target.has_name) {
        size_t n = strnlen(c->target.name, sizeof(c->target.name));
        if (n == 0 || n > D2KM_NAME_MAX)
            return -1;
    } else {
        if (c->target.port == 0 || c->target.family != c->family)
            return -1;
    }
    if (c->transport == D2KM_UDP && c->form.tcp_options_length)
        return -1;
    if (c->form.segment_count > D2KM_SEGMENTS_MAX ||
        c->form.tcp_options_length > D2KM_TCP_OPTIONS_MAX)
        return -1;
    if (strnlen(c->path.ifname, sizeof(c->path.ifname)) == sizeof(c->path.ifname))
        return -1;
    return 0;
}

static int target_equal(const d2km_target *a, const d2km_target *b)
{
    if (a->has_name != b->has_name)
        return 0;
    if (a->has_name)
        return strcmp(a->name, b->name) == 0;
    size_t n = a->family == D2KM_IPV4 ? 4 : 16;
    return a->family == b->family && a->port == b->port &&
           memcmp(a->addr, b->addr, n) == 0;
}

unsigned d2km_context_diff(const d2km_context *a, const d2km_context *b)
{
    unsigned d = 0;
    if (!target_equal(&a->target, &b->target) || a->transport != b->transport ||
        a->protocol != b->protocol || a->family != b->family ||
        a->path.mtu != b->path.mtu ||
        strncmp(a->path.ifname, b->path.ifname, sizeof(a->path.ifname)) != 0)
        d |= D2KM_CTX_OTHER;
    if (a->form.hello_length != b->form.hello_length ||
        a->form.hello_print != b->form.hello_print)
        d |= D2KM_FORM_HELLO;
    if (a->form.segment_count != b->form.segment_count ||
        memcmp(a->form.segments, b->form.segments,
               a->form.segment_count * sizeof(a->form.segments[0])) != 0)
        d |= D2KM_FORM_SEGMENTS;
    if (a->form.tcp_options_length != b->form.tcp_options_length ||
        memcmp(a->form.tcp_options, b->form.tcp_options,
               a->form.tcp_options_length) != 0)
        d |= D2KM_FORM_TCP_OPTIONS;
    if (a->form.ech != b->form.ech)
        d |= D2KM_FORM_ECH;
    if (a->form.grease != b->form.grease)
        d |= D2KM_FORM_GREASE;
    return d;
}

int d2km_context_compatible(const d2km_context *a, const d2km_context *b,
                            unsigned unread)
{
    if (a == NULL || b == NULL)
        return 0;
    unsigned d = d2km_context_diff(a, b);
    return (d & ~(unread & D2KM_FORM_ALL)) == 0;
}

/* Писатель с отсечкой по cap: длина считается всегда. */
typedef struct {
    uint8_t *out;
    size_t cap, len;
} writer;

static void put(writer *w, const void *p, size_t n)
{
    if (w->len + n <= w->cap && w->out != NULL)
        memcpy(w->out + w->len, p, n);
    w->len += n;
}

static void put8(writer *w, unsigned v)
{
    uint8_t b = (uint8_t)v;
    put(w, &b, 1);
}

static void put16(writer *w, unsigned v)
{
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    put(w, b, 2);
}

static void put32(writer *w, uint32_t v)
{
    put16(w, v >> 16);
    put16(w, v & 0xffff);
}

static void put64(writer *w, uint64_t v)
{
    put32(w, (uint32_t)(v >> 32));
    put32(w, (uint32_t)v);
}

size_t d2km_context_encode(const d2km_context *c, uint8_t *out, size_t cap)
{
    writer w = {out, cap, 0};
    put8(&w, 1);   /* версия формата записи */
    put8(&w, c->target.has_name ? 1u : 0u);
    if (c->target.has_name) {
        size_t n = strnlen(c->target.name, sizeof(c->target.name));
        put8(&w, (unsigned)n);
        put(&w, c->target.name, n);
    } else {
        put8(&w, c->target.family);
        put(&w, c->target.addr, c->target.family == D2KM_IPV4 ? 4 : 16);
        put16(&w, c->target.port);
    }
    put8(&w, c->transport);
    put8(&w, c->protocol);
    put8(&w, c->family);
    put32(&w, c->form.hello_length);
    put64(&w, c->form.hello_print);
    put8(&w, c->form.segment_count);
    for (unsigned i = 0; i < c->form.segment_count && i < D2KM_SEGMENTS_MAX; i++)
        put16(&w, c->form.segments[i]);
    put8(&w, c->form.tcp_options_length);
    put(&w, c->form.tcp_options,
        c->form.tcp_options_length <= D2KM_TCP_OPTIONS_MAX
            ? c->form.tcp_options_length : 0);
    put8(&w, c->form.ech);
    put8(&w, c->form.grease);
    size_t n = strnlen(c->path.ifname, sizeof(c->path.ifname));
    put8(&w, (unsigned)n);
    put(&w, c->path.ifname, n);
    put16(&w, c->path.mtu);
    return w.len;
}

const char *d2km_protocol_name(d2km_protocol p)
{
    static const char *const names[D2KM_PROTOCOL_END] = {
        [D2KM_P_TLS12] = "TLS1.2", [D2KM_P_TLS13] = "TLS1.3",
        [D2KM_P_QUIC1] = "QUICv1", [D2KM_P_QUIC2] = "QUICv2",
        [D2KM_P_HTTP11] = "HTTP/1.1", [D2KM_P_HTTP2] = "HTTP/2",
        [D2KM_P_HTTP3] = "HTTP/3", [D2KM_P_STUN] = "STUN", [D2KM_P_DNS] = "DNS",
    };
    return (p > 0 && p < D2KM_PROTOCOL_END) ? names[p] : NULL;
}
