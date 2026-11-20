#define _POSIX_C_SOURCE 200809L
#include "d2k_appget.h"
#include "d2km_check.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void fail(d2k_app_result *r, d2k_app_state st, const char *why)
{
    r->state = st;
    snprintf(r->reason, sizeof(r->reason), "%s", why);
}

/* --- HTTP/1.1 --------------------------------------------------------------- */

#define H1_MAX (1u << 20)   /* буфер разбора: 1 МиБ — главная страница и больше */

static void get_h1(d2k_tls *t, const char *host, const char *path, int64_t end,
                   d2k_app_result *r)
{
    char req[1400];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n"
                     "Accept-Encoding: identity\r\nConnection: close\r\n\r\n", path, host);
    char err[160] = "";
    if (n < 0 || (size_t)n >= sizeof(req)) { fail(r, D2K_APP_LOCAL, "запрос длиннее буфера"); return; }
    if (d2k_tls_write(t, (const uint8_t *)req, (size_t)n, err, sizeof(err)) != 0) {
        fail(r, D2K_APP_CUT, err[0] ? err : "запрос не ушёл");
        return;
    }
    uint8_t *buf = malloc(H1_MAX);
    if (!buf) { fail(r, D2K_APP_LOCAL, "нет памяти"); return; }
    size_t len = 0;
    int closed = 0;
    d2km_http_response hr;
    for (;;) {
        d2km_http_state st = d2km_http1_response(buf, len, closed, &hr);
        r->status = hr.status;
        r->body_bytes = hr.body_bytes;
        if (st == D2KM_HTTP_COMPLETE || st == D2KM_HTTP_CUT || st == D2KM_HTTP_MALFORMED) {
            if (hr.location && hr.location_length < sizeof(r->location)) {
                memcpy(r->location, hr.location, hr.location_length);
                r->location[hr.location_length] = '\0';
            }
            if (st == D2KM_HTTP_COMPLETE) { r->state = D2K_APP_COMPLETE; snprintf(r->reason, sizeof r->reason, "полный ответ HTTP/1.1"); }
            else if (st == D2KM_HTTP_CUT) fail(r, D2K_APP_CUT, "поток закрыт до конца ответа HTTP/1.1");
            else fail(r, D2K_APP_MALFORMED, "ответ не HTTP/1.x");
            break;
        }
        if (len == H1_MAX) { fail(r, D2K_APP_LOCAL, "ответ длиннее буфера разбора"); break; }
        int64_t left = end - now_ms();
        if (left <= 0) { fail(r, D2K_APP_TIMEOUT, "ответ HTTP/1.1 не закончился к сроку"); break; }
        long got = d2k_tls_read(t, buf + len, H1_MAX - len, (int)left, err, sizeof(err));
        if (got > 0) len += (size_t)got;
        else if (got == 0) closed = 1;
        else { closed = 1; }
    }
    free(buf);
}

/* --- HTTP/2 (RFC 9113) с минимальным HPACK (RFC 7541) ---------------------- */

typedef struct {
    d2k_tls *t;
    uint8_t buf[16384];
    size_t pos, len;
    int64_t end;
    int eof;
} h2io;

static int h2_read(h2io *io, uint8_t *out, size_t n)
{
    while (n) {
        if (io->pos == io->len) {
            int64_t left = io->end - now_ms();
            if (left <= 0) return -2;
            char err[120];
            long z = d2k_tls_read(io->t, io->buf, sizeof(io->buf), (int)left, err, sizeof(err));
            if (z <= 0) { io->eof = 1; return now_ms() >= io->end - 10 ? -2 : -1; }
            io->pos = 0;
            io->len = (size_t)z;
        }
        size_t z = io->len - io->pos;
        if (z > n) z = n;
        memcpy(out, io->buf + io->pos, z);
        out += z; n -= z; io->pos += z;
    }
    return 0;
}

static int h2_frame(h2io *io, uint8_t type, uint8_t flags, uint32_t sid,
                    const uint8_t *p, size_t n)
{
    uint8_t b[9 + 2048];
    if (n > 2048) return -1;
    b[0] = (uint8_t)(n >> 16); b[1] = (uint8_t)(n >> 8); b[2] = (uint8_t)n;
    b[3] = type; b[4] = flags;
    b[5] = (uint8_t)(sid >> 24); b[6] = (uint8_t)(sid >> 16); b[7] = (uint8_t)(sid >> 8); b[8] = (uint8_t)sid;
    if (n) memcpy(b + 9, p, n);
    char err[120];
    return d2k_tls_write(io->t, b, 9 + n, err, sizeof(err));
}

static int hp_int(const uint8_t *b, size_t n, size_t *p, unsigned prefix, uint32_t *out)
{
    if (*p >= n) return -1;
    uint32_t mask = (1u << prefix) - 1, v = b[(*p)++] & mask;
    if (v < mask) { *out = v; return 0; }
    for (unsigned sh = 0; sh <= 28; sh += 7) {
        if (*p >= n) return -1;
        unsigned c = b[(*p)++];
        v += (uint32_t)(c & 127) << sh;
        if (!(c & 128)) { *out = v; return 0; }
    }
    return -1;
}

static int hp_str(const uint8_t *b, size_t n, size_t *p, const uint8_t **v, size_t *len, int *huff)
{
    if (*p >= n) return -1;
    *huff = (b[*p] & 128) != 0;
    uint32_t z;
    if (hp_int(b, n, p, 7, &z) || z > n - *p) return -1;
    *v = b + *p; *len = z; *p += z;
    return 0;
}

/* Код Хаффмана HPACK для цифр (RFC 7541 прил. B): 0..2 — 5 бит, 3..9 — 6. */
static int huff_status(const uint8_t *v, size_t n)
{
    if (n < 2 || n > 3) return -1;
    uint32_t bits = 0;
    for (size_t i = 0; i < n; i++) bits = bits << 8 | v[i];
    int total = (int)n * 8, pos = 0, status = 0;
    for (int i = 0; i < 3; i++) {
        if (total - pos < 5) return -1;
        unsigned c = (bits >> (total - pos - 5)) & 31;
        if (c <= 2) { status = status * 10 + (int)c; pos += 5; continue; }
        if (total - pos < 6) return -1;
        c = (bits >> (total - pos - 6)) & 63;
        if (c < 25 || c > 31) return -1;
        status = status * 10 + (int)c - 22;
        pos += 6;
    }
    int rem = total - pos;
    if (rem >= 8 || (bits & ((1u << rem) - 1)) != ((1u << rem) - 1)) return -1;
    return status;
}

/* :status из блока заголовков. Ссылки на динамическую таблицу (> 61) —
   не :status: его сервер шлёт статическим индексом или литералом. */
static int hp_status(const uint8_t *b, size_t n, int *status)
{
    static const int codes[] = {200, 204, 206, 304, 400, 404, 500};
    size_t p = 0;
    while (p < n) {
        unsigned tag = b[p];
        uint32_t idx;
        if (tag & 128) {
            if (hp_int(b, n, &p, 7, &idx) || !idx) return -1;
            if (idx >= 8 && idx <= 14 && !*status) *status = codes[idx - 8];
            continue;
        }
        if ((tag & 224) == 32) {   /* смена размера динамической таблицы */
            if (hp_int(b, n, &p, 5, &idx)) return -1;
            continue;
        }
        if (hp_int(b, n, &p, (tag & 64) ? 6 : 4, &idx)) return -1;
        /* Индексы 8..14 статической таблицы — все с именем :status. */
        int is_status = idx >= 8 && idx <= 14, huff;
        const uint8_t *v;
        size_t z;
        if (!idx) {
            if (hp_str(b, n, &p, &v, &z, &huff)) return -1;
            is_status = !huff && z == 7 && !memcmp(v, ":status", 7);
        }
        if (hp_str(b, n, &p, &v, &z, &huff)) return -1;
        if (is_status && !*status) {
            int s = huff ? huff_status(v, z)
                         : (z == 3 ? (v[0] - '0') * 100 + (v[1] - '0') * 10 + (v[2] - '0') : -1);
            if (s < 100 || s > 599) return -1;
            *status = s;
        }
    }
    return 0;
}

static size_t hp_put_str(uint8_t *b, const char *s)
{
    size_t n = strlen(s), p = 0;
    if (n < 127) b[p++] = (uint8_t)n;
    else {
        b[p++] = 127;
        size_t left = n - 127;
        while (left >= 128) { b[p++] = (uint8_t)(left | 128); left >>= 7; }
        b[p++] = (uint8_t)left;
    }
    memcpy(b + p, s, n);
    return p + n;
}

static void put32(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v;
}

static void get_h2(d2k_tls *t, const char *host, const char *path, int64_t end,
                   d2k_app_result *r)
{
    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    h2io *io = calloc(1, sizeof(*io));
    if (!io) { fail(r, D2K_APP_LOCAL, "нет памяти"); return; }
    io->t = t;
    io->end = end;
    r->http2 = 1;
    char err[120];
    /* SETTINGS: без динамической таблицы и push, окно потока 16 МиБ;
       окно соединения — WINDOW_UPDATE. Тело мы не храним, нам не жалко. */
    uint8_t set[18];
    set[0] = 0; set[1] = 1; put32(set + 2, 0);            /* HEADER_TABLE_SIZE */
    set[6] = 0; set[7] = 2; put32(set + 8, 0);            /* ENABLE_PUSH */
    set[12] = 0; set[13] = 4; put32(set + 14, 1u << 24);  /* INITIAL_WINDOW_SIZE */
    uint8_t wu[4];
    put32(wu, (1u << 24) - 65535u);
    uint8_t hb[1400];
    size_t hn = 0;
    if (strlen(host) > 255 || strlen(path) > 1000) { fail(r, D2K_APP_LOCAL, "имя или путь длиннее буфера"); free(io); return; }
    hb[hn++] = 0x82;                         /* :method GET */
    hb[hn++] = 0x87;                         /* :scheme https */
    hb[hn++] = 0x04; hn += hp_put_str(hb + hn, path);   /* :path, без индексации */
    hb[hn++] = 0x01; hn += hp_put_str(hb + hn, host);   /* :authority */
    hb[hn++] = 0x00; hn += hp_put_str(hb + hn, "accept");
    hn += hp_put_str(hb + hn, "*/*");
    if (d2k_tls_write(t, (const uint8_t *)preface, sizeof(preface) - 1, err, sizeof(err)) ||
        h2_frame(io, 4, 0, 0, set, sizeof(set)) || h2_frame(io, 8, 0, 0, wu, 4) ||
        h2_frame(io, 1, 5, 1, hb, hn)) {
        fail(r, D2K_APP_CUT, "запрос HTTP/2 не ушёл");
        free(io);
        return;
    }
    static __thread uint8_t frame[16384], headers[16384];
    size_t hlen = 0;
    int open_headers = 0, seen = 0;
    uint64_t unacked = 0;
    for (;;) {
        uint8_t h[9];
        int rc = h2_read(io, h, 9);
        if (rc) { fail(r, rc == -2 ? D2K_APP_TIMEOUT : D2K_APP_CUT, "поток HTTP/2 оборвался до END_STREAM"); break; }
        size_t z = (size_t)h[0] << 16 | (size_t)h[1] << 8 | h[2];
        unsigned type = h[3], flags = h[4];
        uint32_t id = (uint32_t)(h[5] & 127) << 24 | (uint32_t)h[6] << 16 | (uint32_t)h[7] << 8 | h[8];
        if (z > sizeof(frame)) { fail(r, D2K_APP_MALFORMED, "кадр HTTP/2 больше объявленного предела"); break; }
        rc = h2_read(io, frame, z);
        if (rc) { fail(r, rc == -2 ? D2K_APP_TIMEOUT : D2K_APP_CUT, "поток HTTP/2 оборвался внутри кадра"); break; }
        if (open_headers && (type != 9 || id != 1)) { fail(r, D2K_APP_MALFORMED, "CONTINUATION нарушен"); break; }
        if (type == 4) { if (!(flags & 1)) h2_frame(io, 4, 1, 0, NULL, 0); continue; }
        if (type == 6) { if (!(flags & 1) && z == 8) h2_frame(io, 6, 1, 0, frame, 8); continue; }
        if (type == 7) { fail(r, D2K_APP_CUT, "GOAWAY до конца ответа"); break; }
        if (id != 1) continue;   /* WINDOW_UPDATE/PRIORITY соединения и чужие потоки */
        if (type == 3) { fail(r, D2K_APP_CUT, "RST_STREAM до конца ответа"); break; }
        size_t off = 0, stop = z;
        if ((type == 0 || type == 1) && (flags & 8)) { if (!z || frame[0] >= z) { fail(r, D2K_APP_MALFORMED, "набивка кадра"); break; } off = 1; stop -= frame[0]; }
        if (type == 1 && (flags & 32)) { if (stop - off < 5) { fail(r, D2K_APP_MALFORMED, "приоритет"); break; } off += 5; }
        if (type == 1 || type == 9) {
            if (stop - off > sizeof(headers) - hlen) { fail(r, D2K_APP_LOCAL, "заголовки длиннее буфера"); break; }
            memcpy(headers + hlen, frame + off, stop - off);
            hlen += stop - off;
            open_headers = !(flags & 4);
            if (!open_headers) {
                int st = 0;
                if (hp_status(headers, hlen, &st)) { fail(r, D2K_APP_MALFORMED, "HPACK не разобран"); break; }
                hlen = 0;
                if (!seen && st >= 200) { r->status = st; seen = 1; }
                if (flags & 1) {
                    if (seen) { r->state = D2K_APP_COMPLETE; snprintf(r->reason, sizeof r->reason, "полный ответ HTTP/2"); }
                    else fail(r, D2K_APP_MALFORMED, "поток закрыт без окончательного статуса");
                    break;
                }
            }
            continue;
        }
        if (type == 0) {
            if (!seen) { fail(r, D2K_APP_MALFORMED, "DATA до заголовков"); break; }
            r->body_bytes += stop - off;
            unacked += z;
            if (flags & 1) { r->state = D2K_APP_COMPLETE; snprintf(r->reason, sizeof r->reason, "полный ответ HTTP/2"); break; }
            /* Окно соединения возвращается по ходу: иначе сервер встанет на
               64 КиБ, и обрыв был бы нашей виной, а не сети. */
            if (unacked >= 32768) {
                put32(wu, (uint32_t)unacked);
                h2_frame(io, 8, 0, 0, wu, 4);
                unacked = 0;
            }
        }
    }
    free(io);
}

void d2k_app_get(d2k_tls *t, const char *host, const char *path, int deadline_ms,
                 d2k_app_result *r)
{
    memset(r, 0, sizeof(*r));
    if (!t || !host || !path || path[0] != '/') { fail(r, D2K_APP_LOCAL, "нет сессии, имени или пути"); return; }
    int64_t end = now_ms() + (deadline_ms > 0 ? deadline_ms : 10000);
    if (strcmp(d2k_tls_alpn(t), "h2") == 0) get_h2(t, host, path, end, r);
    else get_h1(t, host, path, end, r);
}
