#include "d2km_check.h"

#include <string.h>

static int lower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

static int ieq(const uint8_t *a, size_t an, const char *b)
{
    size_t bn = strlen(b);
    if (an != bn)
        return 0;
    for (size_t i = 0; i < an; i++)
        if (lower(a[i]) != lower((unsigned char)b[i]))
            return 0;
    return 1;
}

/* Позиция CRLFCRLF от start или 0, если её нет. Возвращает индекс за ним. */
static size_t header_end(const uint8_t *b, size_t n, size_t start)
{
    for (size_t i = start; i + 3 < n; i++)
        if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n')
            return i + 4;
    return 0;
}

static const uint8_t *trim(const uint8_t *p, size_t *n)
{
    while (*n && (p[0] == ' ' || p[0] == '\t')) {
        p++;
        (*n)--;
    }
    while (*n && (p[*n - 1] == ' ' || p[*n - 1] == '\t'))
        (*n)--;
    return p;
}

/* Разбор одного блока статуса и заголовков [s, e). */
static int parse_head(const uint8_t *b, size_t s, size_t e, d2km_http_response *r)
{
    /* "HTTP/1.x SSS" */
    if (e - s < 12 || memcmp(b + s, "HTTP/1.", 7) != 0 || b[s + 8] != ' ')
        return -1;
    int st = 0;
    for (int i = 0; i < 3; i++) {
        uint8_t c = b[s + 9 + (size_t)i];
        if (c < '0' || c > '9')
            return -1;
        st = st * 10 + (c - '0');
    }
    if (st < 100 || (e - s > 12 && b[s + 12] != ' ' && b[s + 12] != '\r'))
        return -1;
    r->status = st;
    r->chunked = 0;
    r->has_length = 0;
    r->content_length = 0;
    r->location = NULL;
    r->location_length = 0;
    size_t i = s;
    while (i + 1 < e && !(b[i] == '\r' && b[i + 1] == '\n'))
        i++;
    i += 2;   /* за статусной строкой */
    while (i + 2 <= e) {
        size_t ls = i;
        while (i < e && !(b[i] == '\r' && i + 1 < e && b[i + 1] == '\n'))
            i++;
        size_t le = i;
        i += 2;
        if (le == ls)
            break;   /* пустая строка: конец заголовков */
        size_t colon = ls;
        while (colon < le && b[colon] != ':')
            colon++;
        if (colon == le || colon == ls)
            return -1;
        const uint8_t *name = b + ls;
        size_t name_n = colon - ls;
        size_t vn = le - colon - 1;
        const uint8_t *v = trim(b + colon + 1, &vn);
        if (ieq(name, name_n, "content-length")) {
            if (vn == 0)
                return -1;
            uint64_t len = 0;
            for (size_t k = 0; k < vn; k++) {
                if (v[k] < '0' || v[k] > '9' || len > (UINT64_MAX - 9) / 10)
                    return -1;
                len = len * 10 + (uint64_t)(v[k] - '0');
            }
            if (r->has_length && r->content_length != len)
                return -1;   /* разные длины — неоднозначное сообщение */
            r->has_length = 1;
            r->content_length = len;
        } else if (ieq(name, name_n, "transfer-encoding")) {
            /* chunked — последнее кодирование списка. */
            size_t k = vn;
            while (k > 0 && v[k - 1] != ',')
                k--;
            size_t tn = vn - k;
            const uint8_t *t = trim(v + k, &tn);
            r->chunked = ieq(t, tn, "chunked");
        } else if (ieq(name, name_n, "location")) {
            r->location = v;
            r->location_length = vn;
        }
    }
    return 0;
}

static int hexval(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = (uint8_t)lower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Тело chunked от p. 1 — закончено (end — за последним CRLF), 0 — данных
 * мало, -1 — ошибка грамматики. */
static int chunked_body(const uint8_t *b, size_t n, size_t p, size_t *end,
                        uint64_t *body)
{
    *body = 0;
    for (;;) {
        uint64_t size = 0;
        size_t digits = 0;
        while (p < n && hexval(b[p]) >= 0) {
            if (size > (UINT64_MAX >> 4))
                return -1;
            size = (size << 4) | (uint64_t)hexval(b[p]);
            p++;
            digits++;
        }
        if (p >= n)
            return 0;
        if (digits == 0)
            return -1;
        while (p < n && b[p] != '\r')   /* расширения chunk */
            p++;
        if (p + 1 >= n)
            return 0;
        if (b[p + 1] != '\n')
            return -1;
        p += 2;
        if (size == 0) {
            /* Трейлеры до пустой строки. */
            for (;;) {
                if (p + 1 >= n)
                    return 0;
                if (b[p] == '\r' && b[p + 1] == '\n') {
                    *end = p + 2;
                    return 1;
                }
                while (p + 1 < n && !(b[p] == '\r' && b[p + 1] == '\n'))
                    p++;
                if (p + 1 >= n)
                    return 0;
                p += 2;
            }
        }
        if (size > n - p) {
            *body += n - p;
            return 0;
        }
        p += (size_t)size;
        *body += size;
        if (p + 1 >= n)
            return 0;
        if (b[p] != '\r' || b[p + 1] != '\n')
            return -1;
        p += 2;
    }
}

d2km_http_state d2km_http1_response(const uint8_t *b, size_t n, int closed,
                                    d2km_http_response *r)
{
    d2km_http_response tmp;
    if (r == NULL)
        r = &tmp;
    memset(r, 0, sizeof(*r));
    if (b == NULL && n)
        return D2KM_HTTP_MALFORMED;
    size_t s = 0;
    for (;;) {
        /* Уже первые байты, не совпавшие с "HTTP/", — не HTTP. */
        size_t pre = n - s < 5 ? n - s : 5;
        if (pre && memcmp(b + s, "HTTP/", pre) != 0)
            return D2KM_HTTP_MALFORMED;
        size_t e = header_end(b, n, s);
        if (e == 0)
            return closed ? D2KM_HTTP_CUT : D2KM_HTTP_INCOMPLETE;
        if (parse_head(b, s, e, r) != 0)
            return D2KM_HTTP_MALFORMED;
        if (r->status >= 100 && r->status < 200) {
            s = e;   /* промежуточный ответ, ждём окончательный */
            continue;
        }
        r->header_bytes = e;
        if (r->status == 204 || r->status == 304) {
            r->message_bytes = e;
            return D2KM_HTTP_COMPLETE;
        }
        if (r->chunked) {
            size_t end = 0;
            int c = chunked_body(b, n, e, &end, &r->body_bytes);
            if (c < 0)
                return D2KM_HTTP_MALFORMED;
            if (c == 0)
                return closed ? D2KM_HTTP_CUT : D2KM_HTTP_INCOMPLETE;
            r->message_bytes = end;
            return D2KM_HTTP_COMPLETE;
        }
        uint64_t avail = n - e;
        if (r->has_length) {
            if (avail >= r->content_length) {
                r->body_bytes = r->content_length;
                r->message_bytes = e + (size_t)r->content_length;
                return D2KM_HTTP_COMPLETE;
            }
            r->body_bytes = avail;
            return closed ? D2KM_HTTP_CUT : D2KM_HTTP_INCOMPLETE;
        }
        /* Без длины и без chunked тело кончается закрытием потока. */
        r->body_bytes = avail;
        if (closed) {
            r->message_bytes = n;
            return D2KM_HTTP_COMPLETE;
        }
        return D2KM_HTTP_INCOMPLETE;
    }
}

/* Хост в Location: "scheme://host[:port]/..." → host; относительный — пусто. */
static const uint8_t *location_host(const d2km_http_response *r, size_t *hn)
{
    *hn = 0;
    if (r->location == NULL)
        return NULL;
    const uint8_t *p = r->location;
    size_t n = r->location_length;
    size_t i = 0;
    while (i + 2 < n && !(p[i] == ':' && p[i + 1] == '/' && p[i + 2] == '/'))
        i++;
    if (i + 2 >= n) {
        if (n >= 2 && p[0] == '/' && p[1] == '/')
            i = 0;      /* "//host/path" */
        else
            return p;   /* относительный путь: тот же хост */
    } else {
        i += 1;
    }
    i += 2;
    size_t h = i;
    while (i < n && p[i] != '/' && p[i] != '?' && p[i] != '#')
        i++;
    /* Отбросить userinfo и порт: сравниваем имя хоста. */
    size_t at = h;
    for (size_t k = h; k < i; k++)
        if (p[k] == '@')
            at = k + 1;
    size_t end = i;
    if (at < end && p[at] != '[') {
        for (size_t k = at; k < end; k++)
            if (p[k] == ':') {
                end = k;
                break;
            }
    }
    *hn = end - at;
    return p + at;
}

int d2km_http_spoofed(const d2km_http_response *d, const d2km_http_response *ref)
{
    if (d == NULL || ref == NULL)
        return 1;
    if (d->status != ref->status)
        return 1;
    if ((d->location == NULL) != (ref->location == NULL))
        return 1;
    if (d->location == NULL)
        return 0;
    size_t an, bn;
    const uint8_t *a = location_host(d, &an);
    const uint8_t *b = location_host(ref, &bn);
    if (an != bn)
        return 1;
    for (size_t i = 0; i < an; i++)
        if (lower(a[i]) != lower(b[i]))
            return 1;
    return 0;
}

int d2km_volume_success(const d2km_http_response *r, d2km_http_state st,
                        uint64_t cut_threshold)
{
    return r != NULL && st == D2KM_HTTP_COMPLETE &&
           r->message_bytes > cut_threshold;
}

/* Конец имени в вопросе DNS без сжатия. 0 — ошибка. */
static size_t dns_name_end(const uint8_t *m, size_t n, size_t p)
{
    size_t total = 0;
    while (p < n) {
        uint8_t l = m[p];
        if (l == 0)
            return p + 1;
        if (l & 0xC0)
            return 0;   /* в вопросе ссылки назад некуда указывать */
        total += (size_t)l + 1;
        if (total > 255)
            return 0;
        p += (size_t)l + 1;
    }
    return 0;
}

int d2km_dns_reply_valid(const uint8_t *q, size_t qn, const uint8_t *r, size_t rn)
{
    if (q == NULL || r == NULL || qn < 12 || rn < 12)
        return 0;
    if (q[0] != r[0] || q[1] != r[1])
        return 0;
    if (!(r[2] & 0x80) || ((r[2] >> 3) & 0x0F) != 0)
        return 0;
    unsigned rcode = r[3] & 0x0F;
    if (rcode != 0 && rcode != 3)
        return 0;
    unsigned qd = (unsigned)(q[4] << 8 | q[5]), rd = (unsigned)(r[4] << 8 | r[5]);
    if (qd == 0 || qd != rd)
        return 0;
    size_t pq = 12, pr = 12;
    for (unsigned k = 0; k < qd; k++) {
        size_t eq = dns_name_end(q, qn, pq), er = dns_name_end(r, rn, pr);
        if (eq == 0 || er == 0 || eq - pq != er - pr || eq + 4 > qn || er + 4 > rn)
            return 0;
        for (size_t i = 0; i < eq - pq; i++)
            if (lower(q[pq + i]) != lower(r[pr + i]))
                return 0;
        if (memcmp(q + eq, r + er, 4) != 0)
            return 0;
        pq = eq + 4;
        pr = er + 4;
    }
    return 1;
}

d2km_dns_session_verdict d2km_dns_session_judge(const d2km_dns_session *s)
{
    if (s == NULL)
        return D2KM_DNS_SESSION_PARTIAL;
    if (s->valid_replies >= D2KM_DNS_SESSION_REPLIES &&
        s->last_reply_ms >= s->first_reply_ms &&
        s->last_reply_ms - s->first_reply_ms >= D2KM_DNS_SESSION_MS)
        return D2KM_DNS_SESSION_SUCCESS;
    if (s->unanswered_while_open)
        return D2KM_DNS_SESSION_CUT;
    return D2KM_DNS_SESSION_PARTIAL;
}

int d2km_stun_binding_success(const uint8_t *q, size_t qn, const uint8_t *r, size_t rn)
{
    static const uint8_t cookie[4] = {0x21, 0x12, 0xA4, 0x42};
    if (q == NULL || r == NULL || qn < 20 || rn < 20)
        return 0;
    if (q[0] != 0x00 || q[1] != 0x01 || r[0] != 0x01 || r[1] != 0x01)
        return 0;
    size_t len = (size_t)(r[2] << 8 | r[3]);
    if (len != rn - 20 || (len & 3) != 0)
        return 0;
    if (memcmp(r + 4, cookie, 4) != 0 || memcmp(q + 4, cookie, 4) != 0)
        return 0;
    if (memcmp(q + 8, r + 8, 12) != 0)
        return 0;
    size_t p = 20;
    int mapped = 0;
    while (p + 4 <= rn) {
        unsigned type = (unsigned)(r[p] << 8 | r[p + 1]);
        size_t alen = (size_t)(r[p + 2] << 8 | r[p + 3]);
        size_t padded = (alen + 3) & ~(size_t)3;
        if (padded > rn - p - 4)
            return 0;
        if ((type == 0x0020 || type == 0x0001 || type == 0x8020) && alen >= 8)
            mapped = 1;
        p += 4 + padded;
    }
    return p == rn && mapped;
}

d2km_app_level d2km_h3_level(int handshake_done, int response_complete)
{
    if (!handshake_done)
        return D2KM_LEVEL_NONE;
    return response_complete ? D2KM_LEVEL_APPLICATION : D2KM_LEVEL_HANDSHAKE;
}
