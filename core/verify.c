/* verify.c — зонд, читающий начало прикладного ответа. См. d2k_verify.h:
 * почему внешний тип записи 23 доказательством не является и почему повтор
 * снятого чужого приветствия рукопожатия не завершает.
 *
 * СОБИРАЕТСЯ ИЗ ГОТОВОГО, А НЕ ПИШЕТСЯ ЗАНОВО, и обе половины взяты не ради
 * экономии строк:
 *
 * 1. Обращение — d2k_props_contact (compose.c). Её две оговорки —
 *    «непомеченное» и «сокет закрывает вызывающий» — это ровно те условия,
 *    без которых измерение перестаёт измерять (см. её doc-комментарий и
 *    docs/field/2026-09-11-first-c-ask.md). Второе обращение к цели,
 *    написанное здесь рядом, разошлось бы с ним в мелочи, которая стоила бы
 *    измерения, — а расходятся такие копии молча.
 *
 * 2. Рукопожатие — d2k_tls13 (tls13.c), свой клиент TLS 1.3 на X25519 и
 *    AES-128-GCM, проверенный на живых серверах. Ключ у него СВОЙ, поэтому
 *    он может довести рукопожатие до конца и заговорить внутри сессии;
 *    снятое приветствие цели этого не может в принципе.
 *
 * ЧТО ЗДЕСЬ НЕ ПРОВЕРЯЕТСЯ: подлинность сервера. Предмет измерения — коробка
 * на линии. Поэтому результат НЕ доказывает доступность настоящего сайта:
 * HTTP мог вернуть посредник. Это ограничение нельзя переносить с объёмного
 * измерителя на достоверность обхода без отдельной проверки подлинности.
 */
/* В составном тесте (test_verify_http.c включает quicconn.c, затем этот файл)
   системные заголовки уже прочитаны, и glibc с 2026 задаёт _POSIX_C_SOURCE
   сам, другим значением: голый #define стал переопределением под -Werror
   (CI 22.10.2026). Отдельной единицей трансляции файл задаёт его как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdarg.h>
#include <netinet/in.h>

#include "d2k_compose_internal.h" /* d2k_props_contact — общее обращение к цели */
#include "d2k_h3.h"
#include "d2k_quicconn.h"
#include "d2k_quicprobe.h" /* D2K_QUIC_ARM_DATA_BYTES, d2k_quic_arm_data_judge */
#include "d2k_tls13.h"
#include "d2k_tls12.h"
#include "d2k_verify.h"
#include "d2k_dns_upstreams.h"
#include "d2k_domain.h"
#include "d2k_meas.h"

static int64_t verify_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static unsigned dns16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }

/* Decode compression with an explicit jump budget; cursor follows the
 * original encoded name, never a compression pointer's destination. */
static int ech_dns_name(const uint8_t *b, size_t n, size_t *cursor,
                         char out[256]) {
    size_t p = *cursor, used = 0, after = 0;
    unsigned jumps = 0;
    while (p < n) {
        unsigned c = b[p++];
        if (!c) {
            if (!after) after = p;
            out[used] = 0; *cursor = after; return 0;
        }
        if ((c & 0xc0) == 0xc0) {
            if (p >= n || ++jumps > 16) return -1;
            if (!after) after = p + 1;
            p = ((size_t)(c & 63) << 8) | b[p];
            continue;
        }
        if (c > 63 || c > n - p || used + c + (used != 0) > 253) return -1;
        if (used) out[used++] = '.';
        for (unsigned j = 0; j < c; j++) {
            unsigned v = b[p++];
            if (v >= 'A' && v <= 'Z') v += 'a' - 'A';
            if (!((v >= 'a' && v <= 'z') || (v >= '0' && v <= '9') || v == '-')) return -1;
            out[used++] = (char)v;
        }
    }
    return -1;
}

int d2k_ech_resolve(const char *origin, uint32_t mark, d2k_ech_config *config) {
    if (!origin || !config || !origin[0] || strlen(origin) > 253) return -1;
    char expected[256];
    uint8_t query[512] = {0}, reply[4096];
    if (d2k_t13_random(query, 2)) return -1;
    query[2] = 1; query[5] = 1;
    size_t p = 12, name_len = strlen(origin), at = 0;
    for (size_t i = 0; i < name_len; i++) {
        unsigned c = (unsigned char)origin[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        expected[i] = (char)c;
    }
    expected[name_len] = 0;
    while (at < name_len) {
        size_t end = at;
        while (end < name_len && expected[end] != '.') end++;
        size_t l = end - at;
        if (!l || l > 63 || p + l + 1 >= sizeof query) return -1;
        for (size_t i = at; i < end; i++) {
            unsigned c = (unsigned char)expected[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return -1;
        }
        query[p++] = (uint8_t)l; memcpy(query + p, expected + at, l); p += l;
        at = end + 1;
    }
    query[p++] = 0; query[p++] = 0; query[p++] = 65; query[p++] = 0; query[p++] = 1;
    char resolver[64] = "127.0.0.1", line[256], parsed[64];
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (f) {
        while (fgets(line, sizeof line, f)) {
            if (sscanf(line, "nameserver %63s", parsed) == 1) {
                snprintf(resolver, sizeof resolver, "%s", parsed); break;
            }
        }
        fclose(f);
    }
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    struct sockaddr_in *v4 = (struct sockaddr_in *)&ss;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&ss;
    int af; socklen_t sl;
    if (inet_pton(AF_INET, resolver, &v4->sin_addr) == 1) {
        af = AF_INET; sl = sizeof *v4; v4->sin_family = AF_INET; v4->sin_port = htons(53);
    } else if (inet_pton(AF_INET6, resolver, &v6->sin6_addr) == 1) {
        af = AF_INET6; sl = sizeof *v6; v6->sin6_family = AF_INET6; v6->sin6_port = htons(53);
    } else return -1;
    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
#ifdef SO_MARK
    if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof mark)) { close(fd); return -1; }
#else
    (void)mark;
#endif
    if (connect(fd, (struct sockaddr *)&ss, sl) || send(fd, query, p, 0) != (ssize_t)p) {
        close(fd); return -1;
    }
    struct pollfd pf = {fd, POLLIN, 0};
    int ready = poll(&pf, 1, 1500);
    ssize_t received = ready > 0 ? recv(fd, reply, sizeof reply, 0) : -1;
    close(fd);
    if (received < 12) return -1;
    size_t n = (size_t)received;
    if (memcmp(query, reply, 2) || !(reply[2] & 0x80) ||
        (reply[2] & 0x7a) || (reply[3] & 15) || dns16(reply + 4) != 1) return -1;
    p = 12; char owner[256];
    if (ech_dns_name(reply, n, &p, owner) || strcmp(owner, expected) ||
        p + 4 > n || dns16(reply + p) != 65 || dns16(reply + p + 2) != 1) return -1;
    p += 4;
    unsigned count = dns16(reply + 6);
    if (count > 64) return -1;
    for (unsigned i = 0; i < count; i++) {
        if (ech_dns_name(reply, n, &p, owner) || p + 10 > n) return -1;
        unsigned type = dns16(reply + p), cls = dns16(reply + p + 2);
        size_t end = p + 10 + dns16(reply + p + 8); p += 10;
        if (end > n) return -1;
        if (type != 65 || cls != 1 || strcmp(owner, expected)) { p = end; continue; }
        if (end - p < 3 || !dns16(reply + p)) { p = end; continue; }
        p += 2; char target[256];
        if (ech_dns_name(reply, n, &p, target) || p > end) return -1;
        if (target[0] && strcmp(target, expected)) { p = end; continue; }
        int last = -1, found = 0, compatible = 1;
        d2k_ech_config candidate;
        while (p < end) {
            if (end - p < 4) return -1;
            unsigned key = dns16(reply + p); size_t l = dns16(reply + p + 2); p += 4;
            if ((int)key <= last || l > end - p) return -1;
            last = (int)key;
            if (key == 3 && (l != 2 || dns16(reply + p) != 443)) compatible = 0;
            if (key == 5 && !d2k_ech_config_parse(reply + p, l, &candidate)) found = 1;
            p += l;
        }
        if (found && compatible) { *config = candidate; return 0; }
    }
    return -1;
}

/* RFC 9112 §4, RFC 9110 §15.2. Записи TLS не являются границами HTTP.
   Нужны окончательные заголовки И полное тело по framing: один HTTP 200 не
   означает, что страница загрузилась (на RuTracker тело обрывалось около
   24 КБ при уже полученных заголовках). Происхождение страницы и цепочка
   сертификата здесь всё ещё не проверяются. */
/* Ищет CRLFCRLF в ПАМЯТИ, а не строковыми функциями: ответ содержит нулевые
   байты, и strstr останавливается на первом из них. */
static const uint8_t *find_hdr_end(const uint8_t *b, size_t n) {
    for (size_t i = 0; i + 3 < n; i++) {
        if (b[i] == 13 && b[i + 1] == 10 && b[i + 2] == 13 && b[i + 3] == 10) {
            return b + i;
        }
    }
    return NULL;
}

/* Конец ПЕРВОЙ строки (CRLF) в памяти, либо NULL. */
static const uint8_t *find_eol(const uint8_t *b, size_t n) {
    for (size_t i = 0; i + 1 < n; i++) {
        if (b[i] == 13 && b[i + 1] == 10) { return b + i; }
    }
    return NULL;
}

static uint8_t lower_ascii(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + ('a' - 'A')) : c;
}

static int span_eq_ascii_ci(const uint8_t *p, size_t n, const char *s) {
    size_t m = strlen(s);
    if (n != m) { return 0; }
    for (size_t i = 0; i < n; i++) {
        if (lower_ascii(p[i]) != (uint8_t)s[i]) { return 0; }
    }
    return 1;
}

/* Cloudflare marks every challenge page with this response header. Checking
   the exact marker is safer than treating every HTTP error as a blocked page:
   some legitimate endpoints return 404/403 while still proving that the
   request reached the intended application. */
static int has_cf_challenge(const uint8_t *buf, size_t hdr_len,
                           const uint8_t *status_eol) {
    size_t pos = (size_t)(status_eol - buf) + 2;
    while (pos < hdr_len) {
        const uint8_t *line = buf + pos;
        const uint8_t *eol = find_eol(line, hdr_len - pos);
        size_t line_len = eol ? (size_t)(eol - line) : hdr_len - pos;
        const uint8_t *colon = memchr(line, ':', line_len);
        if (colon && span_eq_ascii_ci(line, (size_t)(colon - line), "cf-mitigated")) {
            size_t off = (size_t)(colon - line) + 1;
            size_t end = line_len;
            while (off < end && (line[off] == ' ' || line[off] == '\t')) { off++; }
            while (end > off && (line[end - 1] == ' ' || line[end - 1] == '\t')) { end--; }
            if (span_eq_ascii_ci(line + off, end - off, "challenge")) { return 1; }
        }
        if (!eol) { break; }
        pos += line_len + 2;
    }
    return 0;
}

/* Код окончательного ответа HTTP (тело и framing возвращаются отдельно),
 * либо 0 — «полных заголовков нет».
 *
 * НОЛЬ В ТЕЛЕ БОЛЬШЕ НИЧЕГО НЕ РЕШАЕТ. Здесь стояло `if (memchr(...0...)) break;`
 * — разбор бросался, едва во ВХОДЯЩИХ байтах попадался нулевой. Тело ответа
 * его содержит сплошь и рядом, и зонд выбрасывал полноценный ответ вместе с
 * кандидатом, который его добыл.
 *
 * Замерено на живой линии 14.09.2026: i.ytimg.com отдаёт
 * «HTTP/1.1 404 Not Found» в первом же чтении (1378 байт, конец заголовков на
 * месте), нулевой байт лежит на смещении 386 — в ТЕЛЕ. Клиент в ту же секунду
 * получал 404 за 0,16 с, а зонд докладывал «нет полных заголовков
 * окончательного HTTP-ответа» и объявлял рабочий план негодным. Так за ночь
 * терялись найденные обходы (0010, R2: ложный ответ о свойствах DPI).
 *
 * Заголовки HTTP нулевого байта содержать не вправе, поэтому проверка на него
 * осталась — но только ДО конца заголовков, где она и означает «ответ битый».
 */
/* Чтение прикладных данных отдано вызывающему функцией: разбор ответа один и
   тот же, а сессия под ним бывает и 1.3, и 1.2 (d2k_tls12.h — зачем второй
   клиент). Второй экземпляр этого разбора рядом означал бы, что находка
   14.09 про нулевой байт в теле живёт в одном из них и не живёт в другом. */
typedef long (*read_fn)(void *sess, uint8_t *buf, size_t cap, int wait_ms,
                        char *err, size_t errcap);

static long read13(void *sess, uint8_t *buf, size_t cap, int wait_ms,
                   char *err, size_t errcap) {
    return d2k_tls_read((d2k_tls *)sess, buf, cap, wait_ms, err, errcap);
}

static long read12(void *sess, uint8_t *buf, size_t cap, int wait_ms,
                   char *err, size_t errcap) {
    return d2k_tls12_read((d2k_tls12 *)sess, buf, cap, wait_ms, err, errcap);
}

typedef struct {
    uint8_t *data;
    size_t cap, len;
    int overflow;
    unsigned content_type_count;
    int dns_content_type;
} body_capture;

typedef struct {
    read_fn rd;
    void *sess;
    uint8_t *buf;
    size_t used, pos;
    int64_t until;
    char *err;
    size_t errcap;
    d2k_resource_scan *scan;
    body_capture *capture;
    int local_limit; /* отказ по нашему пределу (строка chunk длиннее буфера) */
    uint8_t prefix[4096];
    size_t prefix_len;
} body_stream;

/* Причина обрыва чтения тела, если сам TLS её не назвал. */
static void body_read_reason(body_stream *s, long n) {
    if (s->err && s->errcap && !s->err[0]) {
        snprintf(s->err, s->errcap, "%s", n == 0 ? "сервер закрыл соединение посреди тела"
                                                : "ошибка чтения TLS в теле");
    }
}
static void body_say(body_stream *s, const char *msg) {
    if (s->err && s->errcap) snprintf(s->err, s->errcap, "%s", msg);
}

static void body_feed(body_stream *s, const uint8_t *p, size_t n) {
    size_t take = sizeof s->prefix - s->prefix_len;
    if (take > n) take = n;
    memcpy(s->prefix + s->prefix_len, p, take);
    s->prefix_len += take;
    if (s->capture) {
        size_t copy = s->capture->cap - s->capture->len;
        if (copy > n) copy = n;
        memcpy(s->capture->data + s->capture->len, p, copy);
        s->capture->len += copy;
        if (copy < n) s->capture->overflow = 1;
    }
    d2k_resource_feed(s->scan, p, n);
}

/* Следующий байт из уже прочитанной части ответа либо из TLS. */
static int body_byte(body_stream *s, uint8_t *out) {
    if (s->pos == s->used) {
        int64_t left = s->until - verify_now_ms();
        if (left <= 0) { snprintf(s->err, s->errcap, "тайм-аут чтения тела"); return -1; }
        if (s->err && s->errcap) s->err[0] = '\0';
        long n = s->rd(s->sess, s->buf, 8192, (int)left, s->err, s->errcap);
        if (n <= 0) { body_read_reason(s, n); return n == 0 ? -1 : (int)n; }
        s->used = (size_t)n;
        s->pos = 0;
    }
    *out = s->buf[s->pos++];
    return 1;
}

static int body_exact(body_stream *s, uint64_t n, uint64_t *bytes) {
    while (n) {
        if (s->pos == s->used) {
            int64_t left = s->until - verify_now_ms();
            if (left <= 0) { snprintf(s->err, s->errcap, "тайм-аут чтения тела"); return -1; }
            if (s->err && s->errcap) s->err[0] = '\0';
            long got = s->rd(s->sess, s->buf, 8192, (int)left, s->err, s->errcap);
            if (got <= 0) { body_read_reason(s, got); return -1; }
            s->used = (size_t)got;
            s->pos = 0;
        }
        size_t take = s->used - s->pos;
        if ((uint64_t)take > n) { take = (size_t)n; }
        body_feed(s, s->buf + s->pos, take);
        s->pos += take;
        n -= take;
        *bytes += take;
    }
    return 0;
}

static int body_line(body_stream *s, char *line, size_t cap) {
    size_t n = 0;
    int cr = 0;
    for (;;) {
        uint8_t c;
        int r = body_byte(s, &c);
        if (r <= 0) { return -1; }
        if (cr) {
            if (c != '\n') { body_say(s, "chunked: после CR нет LF"); return -1; }
            line[n] = '\0';
            return 0;
        }
        if (c == '\r') { cr = 1; continue; }
        if (c == '\n') { body_say(s, "chunked: строка оканчивается LF без CR"); return -1; }
        if (n + 1 >= cap) {
            s->local_limit = 1;
            char m[96];
            snprintf(m, sizeof m, "chunked: строка длиннее %zu байт (наш предел)", cap - 1);
            body_say(s, m);
            return -1;
        }
        line[n++] = (char)c;
    }
}

/* Читает тело целиком по Content-Length, chunked или закрытию TLS. Для
   chunked тело и framing считаются раздельно; размер чанка проверяется до
   сложения, а завершение требует нулевого чанка и конца trailers. */
static int read_http_body(body_stream *s, int status, int has_length,
                          uint64_t length, int chunked,
                          uint64_t *body_bytes, uint64_t *body_expected) {
    *body_bytes = 0;
    *body_expected = has_length ? length : 0;
    if (status == 204 || status == 304) { return 1; }
    if (has_length) {
        uint64_t already = (uint64_t)(s->used - s->pos);
        if (already > length) { already = length; }
        body_feed(s, s->buf + s->pos, (size_t)already);
        s->pos += (size_t)already;
        *body_bytes = already;
        if (already < length && body_exact(s, length - already, body_bytes) != 0) { return 0; }
        return 1;
    }
    if (chunked) {
        char line[128];
        for (;;) {
            if (body_line(s, line, sizeof line) != 0) { return 0; }
            uint64_t chunk = 0;
            size_t i = 0, digits = 0;
            while (line[i] && line[i] != ';') {
                unsigned char c = (unsigned char)line[i++];
                unsigned v;
                if (c >= '0' && c <= '9') { v = c - '0'; }
                else if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; }
                else if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; }
                else { body_say(s, "chunked: размер не шестнадцатеричный"); return 0; }
                if (chunk > (UINT64_MAX - v) / 16) { body_say(s, "chunked: размер вне диапазона"); return 0; }
                chunk = chunk * 16 + v;
                digits++;
            }
            if (!digits) { body_say(s, "chunked: пустой размер чанка"); return 0; }
            if (UINT64_MAX - *body_bytes < chunk) { body_say(s, "chunked: тело вне диапазона"); return 0; }
            if (chunk == 0) {
                do {
                    if (body_line(s, line, sizeof line) != 0) { return 0; }
                } while (line[0]);
                *body_expected = *body_bytes;
                return 1;
            }
            if (body_exact(s, chunk, body_bytes) != 0) { return 0; }
            uint8_t a, b;
            if (body_byte(s, &a) != 1 || body_byte(s, &b) != 1 || a != '\r' || b != '\n') {
                body_say(s, "chunked: после данных чанка нет CRLF");
                return 0;
            }
        }
    }
    /* Без явного framing RFC 9112 использует закрытие соединения как конец
       тела. Читаем до close_notify; timeout/RST — неполная страница. */
    *body_bytes = (uint64_t)(s->used - s->pos);
    body_feed(s, s->buf + s->pos, s->used - s->pos);
    s->pos = s->used;
    for (;;) {
        int64_t left = s->until - verify_now_ms();
        if (left <= 0) { snprintf(s->err, s->errcap, "тайм-аут чтения тела"); return 0; }
        if (s->err && s->errcap) s->err[0] = '\0';
        long got = s->rd(s->sess, s->buf, 8192, (int)left, s->err, s->errcap);
        if (got == 0) { *body_expected = *body_bytes; return 1; }
        if (got < 0) { body_read_reason(s, got); return 0; }
        if (UINT64_MAX - *body_bytes < (uint64_t)got) { body_say(s, "тело вне диапазона"); return 0; }
        body_feed(s, s->buf, (size_t)got);
        *body_bytes += (uint64_t)got;
    }
}

static int read_status_buf(uint8_t *buf, size_t capacity,
                          read_fn rd, void *sess, int wait_ms,
                          int *cloudflare_challenge, uint64_t *body_bytes,
                          uint64_t *body_expected, int *body_complete,
                          int *body_has_length, int *body_chunked,
                          int *body_framing_valid, int *body_encoding,
                          char *location, size_t location_cap,
                          d2k_resource *resources, size_t *n_resources,
                          d2k_http_reply_result *http_reply, int *local_limit,
                          int *conn_close, body_capture *capture, char *err, size_t errcap);
static int read_status_buf(uint8_t *buf, size_t capacity,
                          read_fn rd, void *sess, int wait_ms,
                          int *cloudflare_challenge, uint64_t *body_bytes,
                          uint64_t *body_expected, int *body_complete,
                          int *body_has_length, int *body_chunked,
                          int *body_framing_valid, int *body_encoding,
                          char *location, size_t location_cap,
                          d2k_resource *resources, size_t *n_resources,
                          d2k_http_reply_result *http_reply, int *local_limit,
                          int *conn_close, body_capture *capture, char *err, size_t errcap) {
    size_t used = 0;
    if (local_limit) { *local_limit = 0; }
    if (conn_close) { *conn_close = 0; }
    if (err && errcap) { err[0] = '\0'; }
    *http_reply = (d2k_http_reply_result){D2K_HTTP_NEUTRAL, ""};
    if (n_resources) *n_resources = 0;
    if (cloudflare_challenge) { *cloudflare_challenge = 0; }
    if (body_bytes) { *body_bytes = 0; }
    if (body_expected) { *body_expected = 0; }
    if (body_complete) { *body_complete = 0; }
    if (body_has_length) { *body_has_length = 0; }
    if (body_chunked) { *body_chunked = 0; }
    if (body_framing_valid) { *body_framing_valid = 0; }
    if (body_encoding) { *body_encoding = 0; }
    if (location && location_cap) { location[0] = '\0'; }
    int64_t until = verify_now_ms() + (wait_ms > 0 ? wait_ms : 8000);
    for (;;) {
        const uint8_t *end = find_hdr_end(buf, used);
        if (end) {
            size_t hdr_len = (size_t)(end - buf);
            /* Ноль ВНУТРИ заголовков — ответ битый, а не «ещё не всё». */
            if (memchr(buf, 0, hdr_len)) {
                snprintf(err, errcap, "в заголовках ответа нулевой байт");
                return 0;
            }
            /* With no header fields, the status line's CRLF is the first
             * half of CRLFCRLF. Include it in the line search, but keep
             * the body excluded from the header/NUL validation above. */
            const uint8_t *eol = find_eol(buf, hdr_len + 2);
            if (!eol) {
                snprintf(err, errcap, "в заголовках ответа нет строки статуса");
                return 0;
            }
            size_t line_len = (size_t)(eol - buf);
            if (line_len < 13 || memcmp(buf, "HTTP/1.", 7) != 0 ||
                (buf[7] != '0' && buf[7] != '1') || buf[8] != ' ' ||
                buf[9] < '1' || buf[9] > '5' || buf[10] < '0' || buf[10] > '9' ||
                buf[11] < '0' || buf[11] > '9' || buf[12] != ' ') {
                snprintf(err, errcap, "строка статуса не HTTP/1.x с кодом 100-599");
                return 0;
            }
            for (size_t p = 13; p < line_len; p++) {
                if ((buf[p] < 32 && buf[p] != '\t') || buf[p] == 127) {
                    snprintf(err, errcap, "в строке статуса управляющий символ");
                    return 0;
                }
            }
            int code = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + buf[11] - '0';
            if (code >= 200) {
                /* Legal denial is established by valid final headers/status,
                   independently of malformed body framing below. */
                if (code == 451)
                    *http_reply = d2k_http_reply_classify(code, NULL, 0, NULL, 0, 0);
                if (cloudflare_challenge) {
                    *cloudflare_challenge = has_cf_challenge(buf, hdr_len, eol);
                }
                int has_length = 0, chunked = 0, framing_valid = 1;
                int transfer_encoding_seen = 0;
                int encoding = 0;
                int encoding_seen = 0;
                int location_seen = 0;
                int html = 0;
                int conn_token_close = 0, conn_token_keep = 0;
                uint64_t length = 0;
                size_t pos = (size_t)(eol - buf) + 2;
                while (pos < hdr_len) {
                    const uint8_t *line = buf + pos;
                    const uint8_t *le = find_eol(line, hdr_len - pos);
                    size_t ln = le ? (size_t)(le - line) : hdr_len - pos;
                    const uint8_t *colon = memchr(line, ':', ln);
                    if (colon) {
                        size_t kn = (size_t)(colon - line), v = kn + 1;
                        while (v < ln && (line[v] == ' ' || line[v] == '\t')) { v++; }
                        if (span_eq_ascii_ci(line, kn, "content-type")) {
                            size_t end = v;
                            while (end < ln && line[end] != ';' && line[end] != ' ') end++;
                            html = span_eq_ascii_ci(line + v, end - v, "text/html");
                            if (capture) {
                                size_t tail=ln;
                                while (tail>v && (line[tail-1]==' ' || line[tail-1]=='\t'))tail--;
                                capture->content_type_count++;
                                capture->dns_content_type=span_eq_ascii_ci(line+v,tail-v,"application/dns-message");
                            }
                        } else if (span_eq_ascii_ci(line, kn, "content-length")) {
                            uint64_t x = 0; size_t digits = 0;
                            while (v < ln && line[v] >= '0' && line[v] <= '9') {
                                unsigned d = (unsigned)(line[v++] - '0');
                                if (x > (UINT64_MAX - d) / 10) {
                                    snprintf(err, errcap, "Content-Length вне диапазона");
                                    return code;
                                }
                                x = x * 10 + d; digits++;
                            }
                            while (v < ln && (line[v] == ' ' || line[v] == '\t')) { v++; }
                            if (!digits || v != ln || (has_length && x != length)) {
                                snprintf(err, errcap, "Content-Length неоднозначный или не число");
                                return code;
                            }
                            has_length = 1; length = x;
                        } else if (span_eq_ascii_ci(line, kn, "transfer-encoding")) {
                            size_t end = ln;
                            while (end > v && (line[end - 1] == ' ' || line[end - 1] == '\t')) { end--; }
                            if (transfer_encoding_seen++ ||
                                !span_eq_ascii_ci(line + v, end - v, "chunked")) {
                                framing_valid = 0;
                            } else { chunked = 1; }
                        } else if (span_eq_ascii_ci(line, kn, "content-encoding")) {
                            size_t end = ln;
                            while (end > v && (line[end - 1] == ' ' || line[end - 1] == '\t')) { end--; }
                            /* Multiple Content-Encoding fields are a coding
                               stack, not interchangeable aliases. This small
                               verifier does not decode stacks; keep them
                               explicitly unknown so the volume matcher cannot
                               confuse them with a plain or one-layer gzip body. */
                            if (encoding_seen++) { encoding = 2; }
                            else if (span_eq_ascii_ci(line + v, end - v, "gzip")) { encoding = 1; }
                            else if (span_eq_ascii_ci(line + v, end - v, "identity")) { encoding = 0; }
                            else { encoding = 2; }
                        } else if (span_eq_ascii_ci(line, kn, "connection")) {
                            /* Список токенов через запятую (RFC 9110 §7.6.1). */
                            size_t a = v;
                            while (a < ln) {
                                while (a < ln && (line[a] == ' ' || line[a] == '\t' || line[a] == ',')) a++;
                                size_t b = a;
                                while (b < ln && line[b] != ',') b++;
                                size_t e = b;
                                while (e > a && (line[e - 1] == ' ' || line[e - 1] == '\t')) e--;
                                if (span_eq_ascii_ci(line + a, e - a, "close")) conn_token_close = 1;
                                if (span_eq_ascii_ci(line + a, e - a, "keep-alive")) conn_token_keep = 1;
                                a = b;
                            }
                        } else if (span_eq_ascii_ci(line, kn, "location") && location && location_cap) {
                            int duplicate = location_seen++;
                            if (duplicate) framing_valid = 0;
                            size_t end = ln;
                            while (end > v && (line[end - 1] == ' ' || line[end - 1] == '\t')) { end--; }
                            size_t value_len = end - v;
                            if (!duplicate && value_len < location_cap) {
                                int safe = 1;
                                for (size_t k = v; k < end; k++) {
                                    if (line[k] < 0x21 || line[k] == 0x7f) { safe = 0; break; }
                                }
                                if (safe) {
                                    memcpy(location, line + v, value_len);
                                    location[value_len] = '\0';
                                }
                            }
                        }
                    }
                    if (!le) { break; }
                    pos += ln + 2;
                }
                body_stream bs;
                memset(&bs, 0, sizeof bs);
                bs.rd = rd; bs.sess = sess; bs.buf = buf;
                bs.used = used; bs.pos = hdr_len + 4;
                bs.until = until; bs.err = err; bs.errcap = errcap;
                bs.capture = capture;
                d2k_resource_scan scan = {0};
                if (html && encoding == 0 && code >= 200 && code < 300 &&
                    (!cloudflare_challenge || !*cloudflare_challenge)) bs.scan = &scan;
                uint64_t got = 0, expected = 0;
                /* Ambiguous framing must never be accepted as a complete
                   response: intermediaries disagree about TE vs CL and can
                   otherwise make a truncated body look whole. */
                if (has_length && chunked) {
                    snprintf(err, errcap, "Content-Length вместе с Transfer-Encoding: chunked");
                } else if (!framing_valid) {
                    snprintf(err, errcap, "неоднозначный Transfer-Encoding или Location");
                }
                int complete = framing_valid && !(has_length && chunked) &&
                    read_http_body(&bs, code, has_length, length,
                                   chunked, &got, &expected);
                if (!complete && err[0] == '\0') {
                    snprintf(err, errcap, "тело не дочитано по HTTP framing");
                }
                if (local_limit && bs.local_limit) { *local_limit = 1; }
                if (body_bytes) { *body_bytes = got; }
                if (body_expected) { *body_expected = expected; }
                if (body_complete) { *body_complete = complete; }
                if (body_has_length) { *body_has_length = has_length; }
                if (body_chunked) { *body_chunked = chunked; }
                if (body_framing_valid) {
                    *body_framing_valid = framing_valid && !(has_length && chunked);
                }
                if (body_encoding) { *body_encoding = encoding; }
                /* Конец keep-alive: явный close, HTTP/1.0 без keep-alive или
                   тело до закрытия соединения (нет ни длины, ни chunked). */
                if (conn_close) {
                    *conn_close = conn_token_close || (buf[7] == '0' && !conn_token_keep) ||
                        (!has_length && !chunked && code != 204 && code != 304);
                }
                *http_reply = d2k_http_reply_classify(code, location, encoding,
                    bs.prefix, bs.prefix_len, got + (complete ? 0 : 1));
                if (complete && bs.scan && resources && n_resources) {
                    memcpy(resources, scan.refs, sizeof scan.refs);
                    *n_resources = scan.count;
                }
                return code;
            }
            if (code == 101) { /* upgrade не запрашивали */
                snprintf(err, errcap, "сервер прислал 101 Switching Protocols без запроса");
                return 0;
            }
            /* Промежуточный ответ (1xx) — отбрасываем его вместе с
               заголовками и ждём окончательного. */
            size_t consumed = hdr_len + 4;
            memmove(buf, buf + consumed, used - consumed);
            used -= consumed;
            continue;
        }
        if (used >= capacity - 1) {
            if (local_limit) { *local_limit = 1; }
            snprintf(err, errcap, "заголовки ответа длиннее %d байт", D2K_VERIFY_HEADER_LIMIT);
            return 0;
        }
        int64_t left = until - verify_now_ms();
        if (left <= 0) {
            snprintf(err, errcap, "тайм-аут ожидания заголовков ответа%s",
                     used ? " (пришла только их часть)" : " (ничего не пришло)");
            return 0;
        }
        err[0] = '\0';
        long got = rd(sess, buf + used, capacity - 1 - used, (int)left, err, errcap);
        if (got <= 0) {
            if (!err[0]) {
                if (got == 0) {
                    snprintf(err, errcap, "сервер закрыл соединение до конца заголовков ответа%s",
                             used ? " (пришла только их часть)" : " (ничего не пришло)");
                } else {
                    snprintf(err, errcap, "ошибка чтения TLS до конца заголовков ответа");
                }
            }
            return 0;
        }
        used += (size_t)got;
    }
}

static int read_status_rd(read_fn rd, void *sess, int wait_ms,
                          int *cloudflare_challenge, uint64_t *body_bytes,
                          uint64_t *body_expected, int *body_complete,
                          int *body_has_length, int *body_chunked,
                          int *body_framing_valid, int *body_encoding,
                          char *location, size_t location_cap,
                          d2k_resource *resources, size_t *n_resources,
                          d2k_http_reply_result *http_reply, int *local_limit,
                          int *conn_close, body_capture *capture, char *err, size_t errcap) {
    /* Буфер на куче: заголовки Meta ~8,4 КБ не влезали в прежние 8 КБ на
       стеке (задача 44). Тело читается теми же 8192 байтами с начала. */
    size_t capacity = D2K_VERIFY_HEADER_LIMIT + 1;
    uint8_t *buf = malloc(capacity);
    if (!buf) {
        *http_reply = (d2k_http_reply_result){D2K_HTTP_NEUTRAL, ""};
        if (n_resources) *n_resources = 0;
        if (local_limit) *local_limit = 1;
        snprintf(err, errcap, "не хватило памяти под заголовки ответа");
        return 0;
    }
    int code_out = read_status_buf(buf, capacity, rd, sess, wait_ms,
        cloudflare_challenge, body_bytes, body_expected, body_complete,
        body_has_length, body_chunked, body_framing_valid, body_encoding,
        location, location_cap, resources, n_resources, http_reply,
        local_limit, conn_close, capture, err, errcap);
    free(buf);
    return code_out;
}

void d2k_http_read_response(d2k_http_read_fn rd, void *ctx, int wait_ms,
                            d2k_http_read_result *r, char *err, size_t cap) {
    memset(r, 0, sizeof *r);
    r->status = read_status_rd(rd, ctx, wait_ms, NULL, &r->body_bytes,
        NULL, &r->complete, NULL, NULL, NULL, NULL,
        r->location, sizeof r->location, NULL, NULL, &r->reply,
        &r->local_limit, &r->connection_close, NULL, err, cap);
}

d2k_ver_result d2k_verify_probe(const char *ip, uint16_t port, const char *sni,
                                int deadline_ms, size_t hello_wire) {
    return d2k_verify_probe_on(-1, ip, port, sni, deadline_ms, hello_wire);
}

/* use_fd — УЖЕ ЗАНЯТЫЙ сокет (d2k_props_bind), чей местный порт вызывающий
   назвал датапату заранее, чтобы пробный план достался только этому потоку.
   Меньше нуля — создать свой, тогда это в точности d2k_verify_probe. */
typedef int (*write_fn)(void *sess, const uint8_t *buf, size_t len,
                        char *err, size_t errcap);

static int write13(void *sess, const uint8_t *buf, size_t len,
                   char *err, size_t errcap) {
    return d2k_tls_write((d2k_tls *)sess, buf, len, err, errcap);
}

static int write12(void *sess, const uint8_t *buf, size_t len,
                   char *err, size_t errcap) {
    return d2k_tls12_write((d2k_tls12 *)sess, buf, len, err, errcap);
}

/* Resolve only same-origin HTTPS redirects. A redirect to a different host
   starts a different measurement target and must not be credited to this one. */
static int redirect_path(const char *location, const char *host,
                         char *path, size_t path_cap) {
    if (!location || !location[0] || !host || !host[0] || !path || path_cap < 2) { return 0; }
    const char *p = location;
    if (strlen(p) >= 8 && span_eq_ascii_ci((const uint8_t *)p, 8, "https://")) {
        p += 8;
        const char *authority = p;
        while (*p && *p != '/' && *p != '?' && *p != '#') { p++; }
        size_t authority_len = (size_t)(p - authority);
        size_t host_len = strlen(host);
        int same = authority_len == host_len &&
                   span_eq_ascii_ci((const uint8_t *)authority, authority_len, host);
        if (!same && authority_len == host_len + 4 &&
            span_eq_ascii_ci((const uint8_t *)authority, host_len, host) &&
            memcmp(authority + host_len, ":443", 4) == 0) { same = 1; }
        if (!same) { return 0; }
        if (*p == '?') {
            if (path_cap < strlen(p) + 2) { return 0; }
            path[0] = '/'; strcpy(path + 1, p);
            return 1;
        }
        if (*p != '/') { p = "/"; }
    } else if (*p != '/') {
        return 0;
    }
    size_t n = strlen(p);
    if (n == 0 || n >= path_cap || p[0] != '/') { return 0; }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c <= 0x20 || c == 0x7f || c == '#') { return 0; }
    }
    memcpy(path, p, n + 1);
    return 1;
}

/* A complete redirect is an application response from the measured host,
   not proof that its destination loaded. Never follow a different origin. */
static int https_redirect_response(int code, const char *location) {
    if (code != 301 && code != 302 && code != 303 && code != 307 && code != 308) return 0;
    if (!location || strlen(location) < 9 ||
        !span_eq_ascii_ci((const uint8_t *)location, 8, "https://")) return 0;
    const char *p = location + 8;
    int host_chars = 0;
    for (; *p && *p != '/' && *p != '?' && *p != '#'; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9')) host_chars++;
        else if (c != '.' && c != '-' && c != ':' && c != '[' && c != ']') return 0;
    }
    if (!host_chars) return 0;
    for (; *p; p++) if ((unsigned char)*p <= 0x20 || (unsigned char)*p == 0x7f) return 0;
    return 1;
}

/* --- проверка бюджета потока (задача 55, d2k_verify.h) ------------------ */

/* Бюджет зондов этого потока исполнения. Поточная переменная, а не параметр:
   подписи зондов — крючки планировщика и тестов, а бюджет нужен ровно одному
   звонящему — испытанию кандидата (worker_run, JOB_VERIFY). */
static __thread unsigned g_verify_budget;
void d2k_verify_budget_set(unsigned budget_packets) { g_verify_budget = budget_packets; }
unsigned d2k_verify_budget_get(void) { return g_verify_budget; }

/* ФОРМА ПРИВЕТСТВИЯ КЛИЕНТА ДЛЯ ЗОНДА QUIC (задача 66) — поточная настройка,
   как и бюджет выше: подписи крючков зонда не меняются. Ставится на время
   одной проверки и снимается сразу после. Ноль — как раньше, своё
   минимальное приветствие в одной датаграмме. */
static __thread d2k_quic_form g_verify_quic_form;
static __thread int g_verify_quic_form_set;
/* Прибор поля читает тело HTTP/3 до FIN (d2k_verify_quic_read_all_set); зонд
   плеча — до предела этапа данных. Поточная настройка, как форма. */
static __thread int g_verify_quic_read_all;
void d2k_verify_quic_read_all_set(int on) { g_verify_quic_read_all = on ? 1 : 0; }
void d2k_verify_quic_form_set(const d2k_quic_form *f) {
    if (f && f->n) { g_verify_quic_form = *f; g_verify_quic_form_set = 1; }
    else { g_verify_quic_form_set = 0; }
}

/* Почему TCP_INFO, а не счёт в зонде: зонд видит записи TLS и байты, а
   коробка считает ПАКЕТЫ (поле 04.10: от байтов порог не зависит). Сегменты
   с данными знает только ядро: data_segs_in/out (Linux 4.6+, роутеры на 4.9)
   — ровно «пакеты с данными обеих сторон» из замера, с повторами и без
   чистых ACK. Раскладка struct tcp_info — своя копия начала uapi
   <linux/tcp.h> (смещения 152/156), а не заголовок библиотеки: у musl и
   glibc разных лет поля названы и доступны по-разному. Ответ короче 160
   байт — старое ядро, считать нечем. */
long d2k_verify_tcp_data_packets(int fd) {
#ifdef __linux__
    uint8_t info[256];
    socklen_t len = sizeof info;
    memset(info, 0, sizeof info);
    if (fd < 0 || getsockopt(fd, IPPROTO_TCP, 11 /* TCP_INFO */, info, &len) != 0 || len < 160)
        return -1;
    uint32_t in = 0, out = 0;
    memcpy(&in, info + 152, 4);
    memcpy(&out, info + 156, 4);
    return (long)in + (long)out;
#else
    (void)fd;
    return -1;
#endif
}
d2k_verify_packets_fn d2k_verify_packets_hook = d2k_verify_tcp_data_packets;

/* Счёт пакетов и «сервер закрыл поток» — подменяемы ради теста без сокетов. */
typedef struct {
    long (*packets)(void *ctx);   /* пакеты с данными обеих сторон, <0 — не считается */
    int  (*peer_spoke)(void *ctx); /* после неудачи чтения: 1 — сервер закрыл/сбросил, 0 — молчит */
    void *ctx;
} budget_io;

static void budget_say(d2k_ver_result *r, int outcome, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void budget_say(d2k_ver_result *r, int outcome, const char *fmt, ...) {
    va_list ap;
    r->budget = outcome;
    va_start(ap, fmt);
    vsnprintf(r->budget_note, sizeof r->budget_note, fmt, ap);
    va_end(ap);
}

/* Чтение с запоминанием законного конца потока (close_notify): после него
   сокет может ещё не показать FIN, а молчанием коробки это не является. */
/* Заодно помнит, чем кончилось последнее чтение: отказ (n < 0) и сколько
   байт ответа пришло. Молчание коробки — это отказ чтения по истечении
   срока; битый ответ, тревога TLS, наш предел приходят раньше срока или без
   отказа чтения и обрывом не считаются (ревью M-2). */
typedef struct { read_fn rd; void *sess; int eof, failed; uint64_t bytes; } eof_reader;
static long read_eof(void *ctx, uint8_t *buf, size_t cap, int wait_ms, char *err, size_t errcap) {
    eof_reader *e = ctx;
    long n = e->rd(e->sess, buf, cap, wait_ms, err, errcap);
    if (n == 0) e->eof = 1;
    e->failed = n < 0;
    if (n > 0) e->bytes += (uint64_t)n;
    return n;
}

/* Тот же запрос на том же потоке, пока поток не перенесёт 2 × бюджет пакетов
   с данными. Каждый ответ обязан прийти целиком: «сервер ответил на каждый
   запрос». Молчание (тайм-аут без закрытия) — обрыв коробкой; закрытие или
   сброс сервером раньше порога — «не применимо». Повтор без роста счётчика
   пакетов — тоже «не применимо»: счёт сломан, а не коробка пропустила. */
static void budget_tcp(read_fn rd, write_fn wr, void *sess, const budget_io *io,
                       const char *req, size_t req_len, int deadline_ms,
                       unsigned budget, int conn_close, d2k_ver_result *r) {
    unsigned need = budget * 2;
    r->budget_need = need;
    r->budget_requests = 1;
    long last = -1;
    char err[160];
    for (;;) {
        long pk = io->packets(io->ctx);
        if (pk < 0) {
            r->budget_uncountable = 1;
            budget_say(r, D2K_BUDGET_NOT_APPLICABLE,
                       "пакеты потока не считаются (нет TCP_INFO data_segs) — бюджет не проверен");
            return;
        }
        r->budget_packets = (unsigned)pk;
        if ((unsigned long)pk >= need) {
            budget_say(r, D2K_BUDGET_PASSED, "поток перенёс %ld пакетов с данными из нужных %u "
                       "за %u запросов, сервер ответил на каждый", pk, need, r->budget_requests);
            return;
        }
        if (conn_close) {
            budget_say(r, D2K_BUDGET_NOT_APPLICABLE, "сервер закрывает keep-alive после %u-го "
                       "ответа, на %ld пакетах из %u — бюджет не проверен", r->budget_requests, pk, need);
            return;
        }
        if (last >= 0 && pk <= last) {
            budget_say(r, D2K_BUDGET_NOT_APPLICABLE, "счётчик пакетов не растёт (%ld) — бюджет не проверен", pk);
            return;
        }
        last = pk;
        eof_reader er = { rd, sess, 0, 0, 0 };
        err[0] = '\0';
        int64_t asked = verify_now_ms();
        int wrote = wr(sess, (const uint8_t *)req, req_len, err, sizeof err);
        r->budget_requests++;
        int code = 0, complete = 0, cc = 0, ll = 0, chal = 0, a = 0, b = 0, c = 0, enc = 0;
        uint64_t got = 0, expected = 0;
        d2k_http_reply_result hr;
        if (wrote == 0) {
            code = read_status_rd(read_eof, &er, deadline_ms, &chal, &got, &expected, &complete,
                                  &a, &b, &c, &enc, NULL, 0, NULL, NULL, &hr, &ll, &cc,
                                  NULL, err, sizeof err);
        }
        if (wrote != 0 || !code || !complete) {
            long now = io->packets(io->ctx);
            if (now >= 0) r->budget_packets = (unsigned)now;
            /* Срок ожидания прошёл целиком (с допуском на ход часов). */
            int silent = er.failed && verify_now_ms() - asked >= (int64_t)deadline_ms - 20;
            if (wrote != 0 || er.eof || io->peer_spoke(io->ctx)) {
                budget_say(r, D2K_BUDGET_NOT_APPLICABLE, "сервер закрыл поток на %u-м запросе, "
                           "%u пакетов из %u — бюджет не проверен: %.60s",
                           r->budget_requests, r->budget_packets, need, err);
            } else if (ll || !silent) {
                budget_say(r, D2K_BUDGET_NOT_APPLICABLE, "повтор %u не измерен (%s): %.60s — "
                           "бюджет не проверен", r->budget_requests,
                           ll ? "наш предел" : "ответ битый или отказ TLS, не молчание", err);
            } else {
                budget_say(r, D2K_BUDGET_CUT, "сервер замолчал посреди повторов: %u-й запрос, "
                           "поток перенёс %u пакетов с данными из нужных %u: %.60s",
                           r->budget_requests, r->budget_packets, need, err);
            }
            return;
        }
        conn_close = cc;
    }
}

/* Сервер что-то сделал с потоком (FIN/RST): сокет читаем без ожидания. Тишина
   коробки — сокет не читаем. Вызывается после неудачного чтения. */
static int fd_peer_spoke(void *ctx) {
    int fd = *(int *)ctx;
    struct pollfd p;
    p.fd = fd; p.events = POLLIN; p.revents = 0;
    return poll(&p, 1, 0) > 0 && (p.revents & (POLLIN | POLLHUP | POLLERR));
}
static long fd_packets(void *ctx) { return d2k_verify_packets_hook(*(int *)ctx); }

/* Explicit diagnostic fetches may carry a signed origin-form request target.
 * Automatic stylesheet witnesses retain their separate restricted policy. */
#define FETCH_TARGET_MAX 8192
static int fetch_target_ok(const char *path) {
    if (!path || path[0] != '/' || path[1] == '/') return 0;
    for (size_t i = 0; i <= FETCH_TARGET_MAX; i++) {
        unsigned char c = (unsigned char)path[i];
        if (!c) return i > 0;
        if (c <= 32 || c >= 127 || c == '#' || c == '\\') return 0;
    }
    return 0;
}

#include "dns_question_wire.inc"

static const uint8_t doh_query[] = {
    0x00,0x00,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,0x00,0x01,0x00,0x01
};

static size_t doh_base64url(const uint8_t *question,size_t length,char *out) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t at = 0;
    for (size_t i = 0; i < length; i += 3) {
        size_t left = length - i;
        uint32_t v = (uint32_t)question[i] << 16;
        if (left > 1) v |= (uint32_t)question[i + 1] << 8;
        if (left > 2) v |= question[i + 2];
        out[at++] = alphabet[(v >> 18) & 63];
        out[at++] = alphabet[(v >> 12) & 63];
        if (left > 1) out[at++] = alphabet[(v >> 6) & 63];
        if (left > 2) out[at++] = alphabet[v & 63];
    }
    out[at] = 0;
    return at;
}

static int doh_skip_rr(const uint8_t *b, size_t n, size_t *p) {
    char owner[256];
    if (ech_dns_name(b, n, p, owner) != 0 || n - *p < 10) return -1;
    size_t rdlen = dns16(b + *p + 8);
    *p += 10;
    if (rdlen > n - *p) return -1;
    *p += rdlen;
    return 0;
}

static int doh_dns_valid(const uint8_t *question,size_t question_len,const uint8_t *b,size_t n,const char **why) {
    if (n < 12) { *why = "short DNS header"; return -1; }
    if (memcmp(b, question, 2) != 0) { *why = "DNS ID does not match query"; return -1; }
    if (!(b[2] & 0x80) || (b[2] & 0x7a)) {
        *why = "DNS response is not an un truncated standard-query answer";
        return -1;
    }
    unsigned rcode = b[3] & 15;
    if (rcode != 0 && rcode != 3) { *why = "DNS RCODE is not NOERROR or NXDOMAIN"; return -1; }
    if (dns16(b + 4) != 1 || n < question_len ||
        memcmp(b + 12, question + 12, question_len - 12) != 0) {
        *why = "DNS question does not match the request";
        return -1;
    }
    size_t p = question_len;
    for (size_t section = 0; section < 3; section++) {
        unsigned count = dns16(b + 6 + section * 2);
        for (unsigned i = 0; i < count; i++) {
            if (doh_skip_rr(b, n, &p) != 0) { *why = "malformed DNS resource record"; return -1; }
        }
    }
    if (p != n) { *why = "trailing bytes after DNS message"; return -1; }
    return 0;
}

static void request_doh_question(read_fn rd, write_fn wr, void *sess, const char *host,
                        const char *endpoint_path,const uint8_t *question,size_t question_len,
                        int deadline_ms,int tls12,
                        d2k_ver_result *r, char *err, size_t errcap) {
    char encoded[400], target[FETCH_TARGET_MAX + 1];
    doh_base64url(question,question_len,encoded);
    int tn = snprintf(target, sizeof target, "%s%sdns=%s", endpoint_path,
                      strchr(endpoint_path, '?') ? "&" : "?", encoded);
    if (!fetch_target_ok(endpoint_path) || tn <= 0 || (size_t)tn >= sizeof target ||
        !fetch_target_ok(target)) {
        r->local_refusal = 1;
        snprintf(r->reason, sizeof r->reason, "invalid or oversized DoH endpoint path");
        return;
    }
    char req[FETCH_TARGET_MAX + 1024];
    int n = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/dns-message\r\n"
        "Accept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n", target, host);
    if (n <= 0 || (size_t)n >= sizeof req) {
        r->local_refusal = 1;
        snprintf(r->reason, sizeof r->reason, "DoH request does not fit request buffer");
        return;
    }
    if (wr(sess, (const uint8_t *)req, (size_t)n, err, errcap) != 0) {
        snprintf(r->reason, sizeof r->reason, "DoH request failed: %.150s", err);
        return;
    }
    uint8_t *body = malloc(65535);
    if (!body) {
        r->local_limit = 1;
        snprintf(r->reason, sizeof r->reason, "not enough memory for DNS message");
        return;
    }
    body_capture capture = { .data=body, .cap=65535 };
    d2k_http_reply_result http_reply;
    r->status = read_status_rd(rd, sess, deadline_ms, NULL, &r->body_bytes,
        &r->body_expected, &r->body_complete, &r->body_has_length,
        &r->body_chunked, &r->body_framing_valid, &r->body_encoding,
        r->location, sizeof r->location, NULL, NULL, &http_reply,
        &r->local_limit, &r->conn_close, &capture, err, errcap);
    r->http_outcome = http_reply.outcome;
    snprintf(r->http_evidence, sizeof r->http_evidence, "%s", http_reply.evidence);
    if (r->status != 200) {
        snprintf(r->reason, sizeof r->reason, "DoH HTTP status %d", r->status);
    } else if (!r->body_complete) {
        snprintf(r->reason, sizeof r->reason, "incomplete DoH HTTP body: %.100s", err);
    } else if (r->peer_authenticated &&
        (capture.content_type_count!=1 || !capture.dns_content_type ||
         !r->body_framing_valid || r->body_encoding)) {
        r->dns_reply_rejected=1;
        snprintf(r->reason, sizeof r->reason, "DoH HTTP response has the wrong media type or framing");
    } else if (capture.overflow || r->body_bytes > 65535) {
        r->dns_reply_rejected=1;
        snprintf(r->reason, sizeof r->reason, "DNS message exceeds 65535 bytes");
    } else {
        const char *why = NULL;
        if (doh_dns_valid(question,question_len,body,capture.len,&why) != 0) {
            r->dns_reply_rejected=1;
            snprintf(r->reason, sizeof r->reason, "invalid DoH response: %s", why);
        } else if (tls12) {
            r->unsupported = 1;
            r->level = D2K_VER_HANDSHAKE;
            snprintf(r->reason, sizeof r->reason,
                "DoH TLS 1.2 HTTP/1.1 reply is not durable HTTP/2 proof; unsupported");
        } else {
            r->level = D2K_VER_APPLICATION;
            snprintf(r->reason, sizeof r->reason,
                "matching DoH reply (%zu DNS bytes)", capture.len);
        }
    }
    free(body);
}

static void request_doh(read_fn rd,write_fn wr,void *session,const char *authority,
    const char *path,int timeout,int tls12,d2k_ver_result *r,char *err,size_t errcap) {
    request_doh_question(rd,wr,session,authority,path,doh_query,sizeof doh_query,timeout,tls12,r,err,errcap);
}

static void request_doh_h1_session(const d2k_doh_tls_session *session,const char *authority,
    const char *path,const uint8_t *question,size_t question_len,int timeout,d2k_ver_result *r) {
    enum { replies_required=20, minimum_span_ms=30000 };
    const int64_t start=verify_now_ms();
    for (unsigned i=0;i<replies_required;i++) {
        int64_t due=start+((int64_t)i*minimum_span_ms+replies_required-2)/(replies_required-1);
        int64_t remaining;
        while ((remaining=due-verify_now_ms())>0) {
            struct timespec wait={remaining/1000,(remaining%1000)*1000000L};
            if (nanosleep(&wait,NULL) && errno!=EINTR) {
                r->local_refusal=1;
                snprintf(r->reason,sizeof r->reason,"DoH HTTP/1.1 verification pacing failed");
                return;
            }
        }
        r->budget_requests++;
        r->level=D2K_VER_HANDSHAKE;
        r->status=r->body_complete=0;
        char err[160]={0};
        int64_t began=verify_now_ms();
        request_doh_question(session->io.read,session->io.write,session->io.context,authority,path,
            question,question_len,timeout,0,r,err,sizeof err);
        if (r->level!=D2K_VER_APPLICATION) {
            if (r->conn_close && r->body_complete)r->dns_session_ended=1;
            if (!r->dns_reply_rejected && !r->dns_session_ended &&
                verify_now_ms()-began>=timeout && (r->status==0 || r->status==200))
                r->budget=D2K_BUDGET_CUT;
            return;
        }
        r->doh_replies++;
        r->level=D2K_VER_HANDSHAKE;
        if (r->conn_close && i+1<replies_required) {
            r->dns_session_ended=1;
            snprintf(r->reason,sizeof r->reason,"DoH HTTP/1.1 peer closed its session after %u replies",r->doh_replies);
            return;
        }
    }
    int64_t elapsed=verify_now_ms()-start;
    if (elapsed<minimum_span_ms)return;
    r->level=D2K_VER_APPLICATION;
    r->budget=D2K_BUDGET_PASSED;
    snprintf(r->reason,sizeof r->reason,"DoH HTTP/1.1: %u matching DNS replies on one connection over %lld ms",
        r->doh_replies,(long long)elapsed);
}

static void request_page_budget(read_fn rd, write_fn wr, void *sess,
                                const char *host, int encoding,
                                const char *initial_path,
                                int deadline_ms, int tls12,
                                const budget_io *io, unsigned budget,
                                d2k_ver_result *r, char *err, size_t errcap, int explicit_fetch);
/* Без проверки бюджета — прежнее чтение одного ответа (тесты разбора). */
static void request_complete_page(read_fn rd, write_fn wr, void *sess,
                                  const char *host, int encoding,
                                  const char *initial_path,
                                  int deadline_ms, int tls12,
                                  d2k_ver_result *r, char *err, size_t errcap)
    __attribute__((unused));
static void request_complete_page(read_fn rd, write_fn wr, void *sess,
                                  const char *host, int encoding,
                                  const char *initial_path,
                                  int deadline_ms, int tls12,
                                  d2k_ver_result *r, char *err, size_t errcap) {
    request_page_budget(rd, wr, sess, host, encoding, initial_path, deadline_ms, tls12,
                        NULL, 0, r, err, errcap, 0);
}

static void request_page_budget(read_fn rd, write_fn wr, void *sess,
                                const char *host, int encoding,
                                const char *initial_path,
                                int deadline_ms, int tls12,
                                const budget_io *io, unsigned budget,
                                d2k_ver_result *r, char *err, size_t errcap, int explicit_fetch) {
    char path[FETCH_TARGET_MAX + 1] = "/";
    if (initial_path) {
        if (!fetch_target_ok(initial_path)) {
            r->local_refusal = 1;
            snprintf(r->reason, sizeof r->reason, "недопустимый или слишком длинный путь HTTP-запроса");
            return;
        }
        memcpy(path, initial_path, strlen(initial_path) + 1);
    }
    const char *accept_encoding = encoding == 1 ? "gzip" :
                                  encoding == 2 ? "gzip, deflate" : "identity";
    for (int redirects = 0; redirects <= 3; redirects++) {
        char req[FETCH_TARGET_MAX + 1024];
        int n = snprintf(req, sizeof req,
                         "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                         "Accept: */*\r\nAccept-Encoding: %s\r\nConnection: keep-alive\r\n\r\n",
                         path, host, accept_encoding);
        if (n <= 0 || (size_t)n >= sizeof req) {
            snprintf(r->reason, sizeof r->reason, "запрос не собрался: путь/имя слишком длинные");
            return;
        }
        if (wr(sess, (const uint8_t *)req, (size_t)n, err, errcap) != 0) {
            snprintf(r->reason, sizeof r->reason, "запрос не ушёл: %.150s", err);
            return;
        }
        r->location[0] = '\0';
        d2k_http_reply_result http_reply;
        int code = read_status_rd(rd, sess, deadline_ms,
                                  &r->cloudflare_challenge, &r->body_bytes,
                                  &r->body_expected, &r->body_complete,
                                  &r->body_has_length, &r->body_chunked,
                                  &r->body_framing_valid, &r->body_encoding, r->location,
                                  sizeof r->location, r->resources, &r->n_resources,
                                  &http_reply, &r->local_limit, &r->conn_close, NULL, err, errcap);
        r->status = code;
        r->http_outcome = http_reply.outcome;
        snprintf(r->http_evidence, sizeof r->http_evidence, "%s", http_reply.evidence);
        if (r->cloudflare_challenge) { r->level = D2K_VER_CHALLENGE; return; }
        /* HTTP 451 — ОТКАЗ САЙТА ТОЛЬКО ОТ САЙТА (24.10.2026).
         *
         * Код 451 сам по себе не говорит, КТО ответил, а решение по нему
         * тяжёлое: поиск закрывается и цель молчит час. Кто ответил, говорит
         * сертификат: имя в нём сверено с запрошенным (r->name_ok, выставлен
         * до этого чтения). Совпало — внутри TLS отвечал владелец имени, и
         * «юридический отказ сервиса» утверждать можно. Не совпало или
         * сертификата не было — отвечал кто угодно, и по §2.4 это «не
         * измерено», а не отказ сайта.
         *
         * Поле 24.10.2026, x-minus.pro: 451 приходил С РОУТЕРА под уже
         * поставленным планом, с ПУСТЫМ телом по HTTP/2, а с эталонного VPS
         * тот же адрес отдавал 200 и 14 822 байта. Цель не открылась ни в
         * одном из шести кругов: поиск останавливался на 451 как на отказе
         * сайта и уходил отдыхать на час.
         *
         * Заглушка блокировки (D2K_HTTP_BLOCKED) этой проверки не требует:
         * её опознают по собственной подписи, а не по одному коду. */
        if (http_reply.outcome == D2K_HTTP_LEGAL_DENIAL && r->name_ok != 1) {
            r->http_outcome = D2K_HTTP_NEUTRAL;
            snprintf(r->http_evidence, sizeof r->http_evidence, "HTTP 451 без имени");
            snprintf(r->reason, sizeof r->reason,
                     "HTTP %d, но собеседник не подтвердил имя сертификатом (%s) — "
                     "отказом сайта это не считаю",
                     code, r->name_ok == 0 ? "имя чужое" : "сертификата не было");
            return;
        }
        if (http_reply.outcome == D2K_HTTP_BLOCKED ||
            http_reply.outcome == D2K_HTTP_LEGAL_DENIAL) {
            r->level = http_reply.outcome == D2K_HTTP_BLOCKED ?
                D2K_VER_BLOCKPAGE : D2K_VER_DENIED;
            snprintf(r->reason, sizeof r->reason, "HTTP отказ: %s", http_reply.evidence);
            return;
        }
        if (code >= 300 && code < 400) {
            char next[sizeof path];
            if (r->body_framing_valid && redirects < 3 &&
                redirect_path(r->location, host, next, sizeof next)) {
                if (initial_path && !(explicit_fetch ? fetch_target_ok(next) : d2k_resource_path_ok(next))) {
                    r->level = D2K_VER_HANDSHAKE;
                    snprintf(r->reason, sizeof r->reason, "stylesheet перенаправлен не на ресурс; не подтверждено");
                    return;
                }
                memcpy(path, next, strlen(next) + 1);
                continue;
            }
            if (!initial_path && r->body_complete &&
                https_redirect_response(code, r->location) &&
                !redirect_path(r->location, host, next, sizeof next)) {
                r->level = D2K_VER_APPLICATION;
                snprintf(r->reason, sizeof r->reason,
                         "HTTP %d, HTTPS redirect получен полностью (%llu байт); цель перехода не проверялась",
                         code, (unsigned long long)r->body_bytes);
                if (io && budget)
                    budget_tcp(rd, wr, sess, io, req, (size_t)n, deadline_ms, budget, r->conn_close, r);
                return;
            }
            r->level = D2K_VER_HANDSHAKE;
            snprintf(r->reason, sizeof r->reason,
                     "HTTP %d redirect не является подтверждением страницы этой цели", code);
            return;
        }
        if (code && r->body_complete) {
            r->level = D2K_VER_APPLICATION;
            snprintf(r->reason, sizeof r->reason,
                     "HTTP %d, тело загружено полностью (%llu байт)%s", code,
                     (unsigned long long)r->body_bytes, tls12 ? " по TLS 1.2" : "");
            if (io && budget)
                budget_tcp(rd, wr, sess, io, req, (size_t)n, deadline_ms, budget, r->conn_close, r);
        } else if (code) {
            snprintf(r->reason, sizeof r->reason,
                     "HTTP %d, тело оборвалось (%llu/%llu байт): %.80s", code,
                     (unsigned long long)r->body_bytes,
                     (unsigned long long)r->body_expected, err);
        } else {
            snprintf(r->reason, sizeof r->reason,
                     "нет полных заголовков окончательного HTTP-ответа: %.100s", err);
        }
        return;
    }
    r->level = D2K_VER_HANDSHAKE;
    snprintf(r->reason, sizeof r->reason, "превышена глубина same-origin redirect");
}

/* Set the measurement mark before connect(). SO_MARK applied to a connected
   socket can leave the route selected without that mark, so baseline probes
   must prepare the socket first and pass its already-bound fd to the shared
   connection helper. */
static int verify_contact(int use_fd, const char *ip, uint16_t port,
                          uint32_t mark, uint8_t family, uint8_t *local_addr,
                          uint16_t *local_port, int *out_fd) {
    int fd = use_fd;
    if (mark) {
        if (fd < 0 && d2k_props_bind_family(family, &fd, NULL) != 0) { return -1; }
        if (d2k_mark_hook(fd, mark) != 0) {
            close(fd);
            return -2;
        }
    }
    return d2k_props_contact_on_family(fd, ip, port, (d2k_hello){NULL, 0, NULL, 0, 0, 0}, family,
                                local_addr, local_port, out_fd);
}

#include "doh_h2.inc"

static d2k_ver_result verify_probe13_internal(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms,
                                        size_t hello_wire, int encoding, uint32_t mark,
                                        const char *path, const d2k_ech_config *ech,
                                        int explicit_fetch) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;   /* не смотрели — «сказать нечего», а не «нет» (§2.4) */
    if (path && !(explicit_fetch ? fetch_target_ok(path) : d2k_resource_path_ok(path))) {
        if (use_fd >= 0) close(use_fd);
        r.local_refusal = 1;
        snprintf(r.reason, sizeof r.reason, "%s", explicit_fetch ?
                 "недопустимый или слишком длинный путь HTTP-запроса" : "недопустимый путь stylesheet-пробы");
        return r;
    }
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    const char *host = (sni && sni[0]) ? sni : ip;
    if (!host || !host[0]) { return r; }
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p <= 32 || *p == 127) {
            snprintf(r.reason, sizeof r.reason, "недопустимый символ в имени HTTP");
            return r;
        }
    }

    /* Байты приветствия сюда НЕ передаются: рукопожатие ведёт d2k_tls13,
       своим ключом, и чужой ClientHello перед ним был бы мусором в начале
       потока. Пустое приветствие d2k_props_contact принимает намеренно —
       нужны от неё ровно непомеченный сокет, открытый наружу, и местные
       адрес с портом. */
    r.family = ip && strchr(ip, ':') ? 6 : 4;
    int contact = verify_contact(use_fd, ip, port, mark, r.family,
                                 r.local_addr, &r.local_port, &r.fd);
    if (contact != 0) {
        if (contact == -2) {
            r.local_refusal = 1;
            snprintf(r.reason, sizeof r.reason, "метка измерительного сокета не поставилась");
        } else {
            snprintf(r.reason, sizeof r.reason, "нет TCP");
        }
        return r;
    }
    r.level = D2K_VER_TRANSPORT;
    if (r.family == 4) memcpy(r.local_ip4, r.local_addr, 4);
    snprintf(r.reason, sizeof r.reason, "транспорт встал, рукопожатия нет");

    char err[160];
    err[0] = '\0';
    d2k_tls *t = NULL;
    int tls_rc = ech ? d2k_tls_connect_ech(r.fd, sni, ech, deadline_ms,
                                          hello_wire, &t, err, sizeof err)
                     : d2k_tls_connect(r.fd, sni, deadline_ms, hello_wire, &t, err, sizeof err);
    if (tls_rc != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TLS: %.150s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    r.name_ok = d2k_tls_peer_name(t);
    r.ech_accepted = d2k_tls_ech_accepted(t);
    snprintf(r.reason, sizeof r.reason, "рукопожатие завершено, приложение молчит");

    budget_io io = { fd_packets, fd_peer_spoke, &r.fd };
    r.negotiated_tls=d2k_tls_version(t);
    uint64_t wire_before=d2k_tls_rx_wire_bytes(t);
    request_page_budget(read13, write13, t, host, encoding, path,
                        deadline_ms, 0, &io, g_verify_budget, &r, err, sizeof err, explicit_fetch);
    r.rx_tls_wire_bytes=d2k_tls_rx_wire_bytes(t)-wire_before;
    r.rx_tls_record_missing=d2k_tls_rx_record_missing(t);
    long dp = d2k_verify_packets_hook(r.fd);
    r.data_packets = dp > 0 ? (unsigned)dp : 0;
    /* Сессию освобождаем, сокет — нет: d2k_tls_free владения им не берёт
       (d2k_tls13.h), а закрыть его здесь значило бы послать FIN и потерять
       ячейку потока в датапате раньше, чем вызывающий свяжет с ней событие. */
    d2k_tls_free(t);
    return r;
}

static d2k_ver_result verify_probe13_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int encoding,
    uint32_t mark, const char *path) {
    return verify_probe13_internal(use_fd, ip, port, sni, deadline_ms,
                                   hello_wire, encoding, mark, path, NULL, 0);
}

static void ech_http_denial(d2k_ver_result *r) {
    if (r->status == 429 && r->level != D2K_VER_DENIED && r->level != D2K_VER_BLOCKPAGE) {
        /* A rate limit is not permission to hammer the origin. Other 4xx are
           the application's own answer through ECH (field 04.10: the witness
           cdn.discordapp.com answers 403 at "/"), and a Cloudflare challenge
           is recognised by its own markers before this point. */
        r->level = D2K_VER_CHALLENGE;
        snprintf(r->reason, sizeof r->reason, "ECH origin ответил HTTP %d; подбор не должен усиливать отказ сервера", r->status);
    }
}

d2k_ver_result d2k_verify_probe_ech_on(int use_fd, const char *ip, uint16_t port,
    const char *origin, const d2k_ech_config *config, int deadline_ms,
    size_t hello_wire, uint32_t mark, const char *path) {
    if (!config || !origin || !origin[0]) {
        d2k_ver_result r;
        memset(&r, 0, sizeof r); r.fd = -1; r.name_ok = -1;
        if (use_fd >= 0) close(use_fd);
        snprintf(r.reason, sizeof r.reason, "нет ECH-конфигурации/origin; опыт не состоялся");
        return r;
    }
    d2k_ver_result r = verify_probe13_internal(use_fd, ip, port, origin, deadline_ms,
                                               hello_wire, 0, mark, path, config, 0);
    ech_http_denial(&r);
    return r;
}

d2k_ver_result d2k_verify_probe_ech_origin_on(int use_fd, const char *ip,
    uint16_t port, const char *outer_name, const char *origin, int deadline_ms,
    size_t hello_wire, uint32_t dns_mark, const char *path) {
    d2k_ech_config config;
    if (!outer_name || !origin || d2k_ech_resolve(origin, dns_mark, &config) ||
        strcmp(outer_name, config.public_name)) {
        d2k_ver_result r;
        memset(&r, 0, sizeof r); r.fd = -1; r.name_ok = -1;
        if (use_fd >= 0) close(use_fd);
        snprintf(r.reason, sizeof r.reason, "ECH witness/config не совпали; опыт не состоялся");
        return r;
    }
    return d2k_verify_probe_ech_on(use_fd, ip, port, origin, &config, deadline_ms,
                                  hello_wire, use_fd < 0 ? dns_mark : 0, path);
}

/* ПОВТОР СНЯТОГО ECH-ПРИВЕТСТВИЯ КЛИЕНТА — см. d2k_verify.h. Доказательство
   той же природы, что вопрос классификатора (trigger.go: ServerHello на
   байты клиента), только на потоке с пробным планом. Дальше ServerHello
   дело не идёт по устройству: закрытого ключа клиента нет (шапка
   d2k_verify.h), поэтому граница названа в reason и в replay_proof. */
d2k_ver_result d2k_verify_replay_on(int use_fd, const char *ip, uint16_t port,
    const uint8_t *hello, size_t hello_len, int deadline_ms) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;
    snprintf(r.reason, sizeof r.reason, "повтор не начинался");
    if (!hello || hello_len < 6 || !ip || !ip[0]) {
        if (use_fd >= 0) close(use_fd);
        snprintf(r.reason, sizeof r.reason, "нет снятого приветствия клиента — повторять нечего");
        return r;
    }
    r.family = strchr(ip, ':') ? 6 : 4;
    if (d2k_props_contact_on_family(use_fd, ip, port, (d2k_hello){hello, hello_len, NULL, 0, 0, 0},
                                    r.family, r.local_addr, &r.local_port, &r.fd) != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TCP для повтора приветствия клиента");
        return r;
    }
    if (r.family == 4) memcpy(r.local_ip4, r.local_addr, 4);
    r.level = D2K_VER_TRANSPORT;
    r.budget = D2K_BUDGET_NOT_APPLICABLE;
    snprintf(r.budget_note, sizeof r.budget_note,
             "повтор приветствия клиента: без его ключей поток не продолжить");
    uint8_t buf[16];
    size_t have = 0;
    int64_t until = verify_now_ms() + (deadline_ms > 0 ? deadline_ms : 3000);
    /* ServerHello узнаётся по шести байтам, тревога — по семи. */
    while (have < 7 && !(have >= 6 && buf[0] == 22)) {
        int64_t left = until - verify_now_ms();
        if (left <= 0) break;
        struct pollfd pf = {r.fd, POLLIN, 0};
        int pr = poll(&pf, 1, (int)left);
        if (pr <= 0) break;
        ssize_t n = recv(r.fd, buf + have, sizeof buf - have, 0);
        if (n <= 0) break;
        have += (size_t)n;
    }
    if (have >= 6 && buf[0] == 22 && buf[1] == 3 && buf[5] == 2) {
        r.level = D2K_VER_HANDSHAKE;
        r.replay_proof = 1;
        snprintf(r.reason, sizeof r.reason,
                 "ServerHello на повтор приветствия клиента: уровень рукопожатия, "
                 "прикладной не измерен");
    } else if (have >= 7 && buf[0] == 21) {
        snprintf(r.reason, sizeof r.reason,
                 "на повтор приветствия клиента сервер ответил тревогой %u", (unsigned)buf[6]);
    } else if (have > 0) {
        snprintf(r.reason, sizeof r.reason,
                 "на повтор приветствия клиента пришло %zu байт не ServerHello (тип записи %u)",
                 have, (unsigned)buf[0]);
    } else {
        snprintf(r.reason, sizeof r.reason,
                 "на повтор приветствия клиента ответа нет (тишина или обрыв)");
    }
    return r;
}

d2k_ver_result d2k_verify_probe_on(int use_fd, const char *ip, uint16_t port,
                                   const char *sni, int deadline_ms,
                                   size_t hello_wire) {
    return verify_probe13_on(use_fd, ip, port, sni, deadline_ms, hello_wire, 2, 0, NULL);
}

/* ФОРМА КЛИЕНТА — И КРИТЕРИЙ ОРИГИНАЛА (задача 37, F3; D2K_SPEC §4, §7).
   Классификатор шлёт снимок клиента байт в байт и засчитывает ServerHello
   (trigger.go); зонд подтверждения прежде всегда предлагал http/1.1 и ждал
   HTTP-ответа. Для MQTT поверх TLS (edge-mqtt-fallback, поле 02.10.2026)
   сервер отвечал тревогой 120 на каждое испытание, то есть «приветствие
   прошло коробку, а зонд спросил не тот протокол». Здесь зонд предлагает
   ALPN клиента и останавливается на завершённом рукопожатии: свой
   прикладной обмен на чужом протоколе мы не ведём и его не выдумываем. */
d2k_ver_result d2k_verify_probe_alpn_on(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms, size_t hello_wire,
                                        const uint8_t *alpn_list, size_t alpn_len) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    if ((alpn_len && !alpn_list) || alpn_len > 256 || !ip || !ip[0]) {
        if (use_fd >= 0) close(use_fd);
        return r;
    }
    r.family = strchr(ip, ':') ? 6 : 4;
    int contact = verify_contact(use_fd, ip, port, 0, r.family,
                                 r.local_addr, &r.local_port, &r.fd);
    if (contact != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TCP");
        return r;
    }
    r.level = D2K_VER_TRANSPORT;
    if (r.family == 4) memcpy(r.local_ip4, r.local_addr, 4);
    snprintf(r.reason, sizeof r.reason, "транспорт встал, рукопожатия нет");
    char err[160];
    err[0] = '\0';
    d2k_tls *t = NULL;
    if (d2k_tls_connect_alpn(r.fd, sni, deadline_ms, hello_wire, alpn_list, alpn_len,
                             &t, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TLS (ALPN клиента): %.140s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    r.handshake_proof = 1;
    r.negotiated_tls=d2k_tls_version(t);
    r.name_ok = d2k_tls_peer_name(t);
    snprintf(r.reason, sizeof r.reason, "%s",
             alpn_len ? "рукопожатие TLS с ALPN клиента завершено; протокол клиента не HTTP — "
                        "прикладной уровень не измерен"
                      : "рукопожатие TLS без ALPN, как у клиента, завершено — "
                        "прикладной уровень не измерен");
    d2k_tls_free(t);
    return r;
}

/* ТО ЖЕ САМОЕ, НО ПО TLS 1.2 — и это не «вторая проба», а та же проба другим
   протоколом. Зовётся там, где КЛИЕНТ старой формы: подтверждать его обход
   современным рукопожатием значит записывать план под форму, которой у него
   нет, и он такого плана не получит вовсе (MVP_CHECKLIST, пункт 3).

   Приветствие зонд собирает сам и добивает до длины клиентского — ровно как
   зонд 1.3 и по той же причине. Почему не профиль старого клиента, сказано в
   шапке d2k_tls12.h: он предлагает шифрнаборы, которых зонд не умеет, и
   сервер выбирал бы именно их. */
static d2k_ver_result verify_probe12_internal(int use_fd, const char *ip, uint16_t port,
                                             const char *sni, int deadline_ms,
                                             size_t hello_wire, int encoding,
                                             uint32_t mark, const char *path,
                                             int explicit_fetch, int doh) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;
    if (path && !(explicit_fetch ? fetch_target_ok(path) : d2k_resource_path_ok(path))) {
        if (use_fd >= 0) close(use_fd);
        r.local_refusal = 1;
        snprintf(r.reason, sizeof r.reason, "%s", explicit_fetch ?
                 "недопустимый или слишком длинный путь HTTP-запроса" : "недопустимый путь stylesheet-пробы");
        return r;
    }
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    const char *host = (sni && sni[0]) ? sni : ip;
    if (!host || !host[0]) { return r; }
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p <= 32 || *p == 127) {
            snprintf(r.reason, sizeof r.reason, "недопустимый символ в имени HTTP");
            return r;
        }
    }

    r.family = ip && strchr(ip, ':') ? 6 : 4;
    int contact = verify_contact(use_fd, ip, port, mark, r.family,
                                 r.local_addr, &r.local_port, &r.fd);
    if (contact != 0) {
        if (contact == -2) {
            r.local_refusal = 1;
            snprintf(r.reason, sizeof r.reason, "метка измерительного сокета не поставилась");
        } else {
            snprintf(r.reason, sizeof r.reason, "нет TCP");
        }
        return r;
    }
    r.level = D2K_VER_TRANSPORT;
    if (r.family == 4) memcpy(r.local_ip4, r.local_addr, 4);
    snprintf(r.reason, sizeof r.reason, "транспорт встал, рукопожатия нет");

    char err[160];
    err[0] = '\0';
    d2k_tls12 *t = NULL;
    if (d2k_tls12_connect(r.fd, sni, deadline_ms, hello_wire, &t, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TLS 1.2: %.140s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    r.name_ok = d2k_tls12_peer_name(t);
    snprintf(r.reason, sizeof r.reason, "рукопожатие 1.2 завершено, приложение молчит");

    budget_io io = { fd_packets, fd_peer_spoke, &r.fd };
    r.negotiated_tls=0x0303;
    uint64_t wire_before=d2k_tls12_rx_wire_bytes(t);
    if (doh) {
        request_doh(read12, write12, t, host, path, deadline_ms, 1, &r, err, sizeof err);
    } else {
        request_page_budget(read12, write12, t, host, encoding, path,
                            deadline_ms, 1, &io, g_verify_budget, &r, err, sizeof err, explicit_fetch);
    }
    r.rx_tls_wire_bytes=d2k_tls12_rx_wire_bytes(t)-wire_before;
    r.rx_tls_record_missing=d2k_tls12_rx_record_missing(t);
    long dp = d2k_verify_packets_hook(r.fd);
    r.data_packets = dp > 0 ? (unsigned)dp : 0;
    d2k_tls12_free(t);
    return r;
}

d2k_ver_result d2k_verify_probe12_handshake_on(int use_fd, const char *ip, uint16_t port,
                                               const char *sni, int deadline_ms,
                                               size_t hello_wire) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    if (!ip || !ip[0]) {
        if (use_fd >= 0) close(use_fd);
        return r;
    }
    r.family = strchr(ip, ':') ? 6 : 4;
    int contact = verify_contact(use_fd, ip, port, 0, r.family,
                                 r.local_addr, &r.local_port, &r.fd);
    if (contact != 0) {
        if (contact == -2) {
            r.local_refusal = 1;
            snprintf(r.reason, sizeof r.reason, "метка измерительного сокета не поставилась");
        } else {
            snprintf(r.reason, sizeof r.reason, "нет TCP");
        }
        return r;
    }
    r.level = D2K_VER_TRANSPORT;
    if (r.family == 4) memcpy(r.local_ip4, r.local_addr, 4);
    snprintf(r.reason, sizeof r.reason, "транспорт встал, рукопожатия нет");
    char err[160];
    err[0] = '\0';
    d2k_tls12 *t = NULL;
    if (d2k_tls12_connect(r.fd, (sni && sni[0]) ? sni : "", deadline_ms, hello_wire,
                          &t, err, sizeof err) != 0) {
        /* alert сервера, обрыв, только 1.3, чужой набор шифров — всё сюда,
           с причиной клиента 1.2; это отказ, а не половина успеха. */
        snprintf(r.reason, sizeof r.reason, "нет TLS 1.2 (без имени): %.130s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    r.handshake_proof = 1;
    r.negotiated_tls = 0x0303;
    r.name_ok = d2k_tls12_peer_name(t);
    snprintf(r.reason, sizeof r.reason,
             "рукопожатие TLS 1.2 без имени завершено; приложение и сертификат не проверены");
    d2k_tls12_free(t);
    return r;
}

d2k_ver_result d2k_verify_probe12_on(int use_fd, const char *ip, uint16_t port,
                                     const char *sni, int deadline_ms,
                                     size_t hello_wire) {
    return verify_probe12_internal(use_fd, ip, port, sni, deadline_ms,
                                   hello_wire, 2, 0, NULL, 0, 0);
}

d2k_ver_result d2k_verify_probe_identity_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12) {
    if (tls12) return verify_probe12_internal(use_fd, ip, port, sni, deadline_ms,
                                             hello_wire, 0, 0, NULL, 0, 0);
    return verify_probe13_on(use_fd, ip, port, sni, deadline_ms, hello_wire, 0, 0, NULL);
}

d2k_ver_result d2k_verify_probe_gzip_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12) {
    if (tls12) return verify_probe12_internal(use_fd, ip, port, sni, deadline_ms,
                                             hello_wire, 1, 0, NULL, 0, 0);
    return verify_probe13_on(use_fd, ip, port, sni, deadline_ms, hello_wire, 1, 0, NULL);
}

d2k_ver_result d2k_verify_probe_baseline(const char *ip, uint16_t port,
                                         const char *sni, int deadline_ms,
                                         size_t hello_wire, int tls12,
                                         int encoding, uint32_t mark) {
    if (encoding != 0 && encoding != 1) {
        d2k_ver_result r;
        memset(&r, 0, sizeof r);
        r.fd = -1;
        r.name_ok = -1;
        snprintf(r.reason, sizeof r.reason, "неподдерживаемый режим сжатия");
        return r;
    }
    if (tls12) {
        return verify_probe12_internal(-1, ip, port, sni, deadline_ms,
                                       hello_wire, encoding, mark, NULL, 0, 0);
    }
    return verify_probe13_on(-1, ip, port, sni, deadline_ms,
                             hello_wire, encoding, mark, NULL);
}

d2k_ver_result d2k_verify_probe_path_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12,
    int encoding, uint32_t mark, const char *path) {
    if (encoding < 0 || encoding > 2) {
        d2k_ver_result r = {0}; r.fd = -1; r.name_ok = -1;
        if (use_fd >= 0) close(use_fd);
        snprintf(r.reason, sizeof r.reason, "неподдерживаемое сжатие");
        return r;
    }
    return tls12 ? verify_probe12_internal(use_fd, ip, port, sni, deadline_ms,
                                            hello_wire, encoding, mark, path, 0, 0)
                 : verify_probe13_on(use_fd, ip, port, sni, deadline_ms,
                                       hello_wire, encoding, mark, path);
}

d2k_ver_result d2k_verify_fetch_tcp_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12,
    uint32_t mark, const char *path) {
    return tls12 ? verify_probe12_internal(use_fd, ip, port, sni, deadline_ms,
                                            hello_wire, 0, mark, path, 1, 0)
                 : verify_probe13_internal(use_fd, ip, port, sni, deadline_ms,
                                            hello_wire, 0, mark, path, NULL, 1);
}

void d2k_verify_close(d2k_ver_result *r) {
    if (r && r->fd >= 0) {
        close(r->fd);
        r->fd = -1;
    }
}

/* --- то же самое, но по QUIC --------------------------------------------- */

d2k_ver_result d2k_verify_probe_quic(const char *ip, uint16_t port, const char *sni,
                                     int deadline_ms, size_t hello_wire) {
    return d2k_verify_probe_quic_on(-1, ip, port, sni, deadline_ms, hello_wire);
}

/* ЭТАП «РУКОПОЖАТИЕ ПРОШЛО, ПРИЛОЖЕНИЕ МОЛЧИТ» — СВОЕЙ СТРОКОЙ (задача 42).
   Поле 02.10.2026 (задача 33): на части адресов поток обрывается на пути
   сразу после рукопожатия, и прежняя строка «кода ответа HTTP/3 нет»
   читалась как дефект датапата. Это честный отрицательный исход проверки, и
   его этап называется прямо: получено got байт ответа, после запроса пришло
   wire байт датаграмм (ноль — сервер замолчал совсем). closed — причина, если
   соединение закрылось. */
static void quic_app_silent(d2k_ver_result *r, size_t got, uint64_t wire,
                            const char *closed) {
    if (closed) {
        snprintf(r->reason, sizeof r->reason,
                 "рукопожатие прошло, приложение молчит, получено %zu байт; "
                 "соединение закрыто: %.40s", got, closed);
    } else {
        snprintf(r->reason, sizeof r->reason,
                 "рукопожатие прошло, приложение молчит, получено %zu байт "
                 "(после запроса пришло %llu байт)", got, (unsigned long long)wire);
    }
}

/* Чтение заголовков ответа HTTP/3 из потока 0 до целого кадра HEADERS.
   recv отдаёт n>0 байт, 0 — пока ничего, <0 — соединение закрыто. Возвращает
   1, если буфер cap заполнен, а кадр HEADERS так и не разобран: это НАШ
   предел, а не поведение линии. Выделено из зонда ради теста без сокетов. */
typedef long (*h3_recv_fn)(void *ctx, uint8_t *buf, size_t cap, char *err,
                           size_t errcap);
static int h3_read_headers(h3_recv_fn recv, void *ctx, uint8_t *rx, size_t cap,
                           int64_t until, size_t *got, int *status, int *closed,
                           char *err, size_t errcap) {
    *got = 0; *status = 0; *closed = 0;
    while (*got < cap && verify_now_ms() < until) {
        long n = recv(ctx, rx + *got, cap - *got, err, errcap);
        if (n < 0) { *closed = 1; break; }
        if (n > 0) { *got += (size_t)n; }
        int st = 0;
        if (*got > 0 && d2k_h3_status(rx, *got, &st) == 0) { *status = st; break; }
    }
    return *status == 0 && *got >= cap;
}

typedef struct { d2k_qc *c; } quic_recv_ctx;
/* Куски по 200 мс безопасны: срок повтора запроса живёт в соединении
   (d2k_qc_stream_recv), а не в куске. */
static long quic_recv_chunk(void *ctx, uint8_t *buf, size_t cap, char *err,
                            size_t errcap) {
    uint64_t sid = 0;
    return d2k_qc_stream_recv(((quic_recv_ctx *)ctx)->c, &sid, buf, cap, 200,
                              err, errcap);
}
typedef void (*h3_progress_fn)(void *ctx, uint64_t *bytes, int *complete);
static void quic_recv_progress(void *ctx, uint64_t *bytes, int *complete) {
    d2k_qc_app_progress(((quic_recv_ctx *)ctx)->c, bytes, complete);
}

/* Тело ответа HTTP/3 после заголовков. Зонду плеча достаточно
   D2K_QUIC_ARM_DATA_BYTES — лишние байты не храним; прибор поля
   (g_verify_quic_read_all) читает до FIN в рамках срока: его вопрос —
   «страница целиком?», и предел этапа данных ответом на него не является
   (поле 24.10.2026, h3-1024: www.cloudflare.com прислал 139 КБ, остановка на
   32 КиБ считалась обрывом). Возвращает closed. Выделено ради теста без сокетов. */
static int quic_read_body(h3_recv_fn recv, h3_progress_fn progress, void *ctx, int closed,
                          int64_t until, int full_response, uint64_t *bytes, int *complete,
                          char *err, size_t errcap) {
    uint64_t cap = (full_response || g_verify_quic_read_all) ? 0 : D2K_QUIC_ARM_DATA_BYTES;
    progress(ctx, bytes, complete);
    while (!closed && !*complete && (!cap || *bytes < cap) && verify_now_ms() < until) {
        uint8_t sink[4096];
        if (recv(ctx, sink, sizeof sink, err, errcap) < 0) { closed = 1; }
        progress(ctx, bytes, complete);
    }
    return closed;
}

/* БЮДЖЕТ ПО QUIC: тот же порог по датаграммам обеих сторон (поле 04.10:
   25 у QUIC так же, как у TCP). Повтор — НОВЫЙ двунаправленный поток той же
   связи (номер +4) с тем же запросом; незаконченный ответ сперва дочитывается.
   Молчание дольше deadline_ms — обрыв; закрытие связи сервером — «не
   применимо». Ввод-вывод подменяем ради теста без сокетов. */
typedef struct {
    int  (*request)(void *ctx, uint64_t sid, char *err, size_t errcap);
    h3_recv_fn recv;
    void (*progress)(void *ctx, uint64_t *bytes, int *complete);
    long (*packets)(void *ctx);
    void *ctx;
} quic_budget_io;

static void budget_quic(const quic_budget_io *io, int deadline_ms, unsigned budget,
                        d2k_ver_result *r) {
    /* ПОРОГ ПЕРЕЙДЁН — ЕЩЁ НЕ ПРОЙДЕН: одно правило с этапом данных поиска
       (d2k_qbudget, core/include/d2k_quicprobe.h). Прежде здесь хватало числа
       датаграмм, и при заглушённом исходящем направлении бюджет «проходил»
       одними повторами полёта сервера — то есть ПОДТВЕРЖДАЛСЯ план, который
       ничего не делает. Оба известных цензора QUIC роняют пакеты только в
       исходящую сторону (FOCI 2026(2) §3; USENIX Sec 25), поэтому входящие
       датаграммы живостью связи не являются. */
    d2k_qbudget bg;
    d2k_qbudget_init(&bg, budget);
    unsigned need = bg.need;
    r->budget_need = need;
    r->budget_requests = 1;
    uint64_t sid = 0;
    long asked_at = -1;
    /* РАЗНЫЕ байты ответа за всю проверку: io->progress считает их внутри
       одного потока, поэтому при переходе на следующий запрос счёт
       продолжается с done — иначе величина не монотонна и «ответ вырос»
       нечем проверить. */
    uint64_t done = 0;
    char err[160];
    err[0] = '\0';
    int wait = deadline_ms > 0 ? deadline_ms : 5000;
    for (;;) {
        long pk = io->packets(io->ctx);
        if (pk < 0) {
            r->budget_uncountable = 1;
            budget_say(r, D2K_BUDGET_NOT_APPLICABLE, "датаграммы связи не считаются — бюджет не проверен");
            return;
        }
        r->budget_packets = (unsigned)pk;
        uint64_t bytes = 0;
        int complete = 0;
        io->progress(io->ctx, &bytes, &complete);
        if (d2k_qbudget_grew(&bg, (uint64_t)pk, done + bytes, r->status ? r->status : 200)) {
            budget_say(r, D2K_BUDGET_PASSED, "связь перенесла %ld датаграмм из нужных %u за %u "
                       "запросов HTTP/3, сервер ответил на каждый", pk, need, r->budget_requests);
            return;
        }
        if (complete) {
            if (asked_at >= 0 && pk <= asked_at) {
                budget_say(r, D2K_BUDGET_NOT_APPLICABLE, "счётчик датаграмм не растёт (%ld) — бюджет не проверен", pk);
                return;
            }
            asked_at = pk;
            /* Ответ дошёл целиком: его байты уходят в общий счёт, дальше
               io->progress считает со нуля по новому потоку. */
            done += bytes;
            sid += 4;
            r->budget_requests++;
            if (io->request(io->ctx, sid, err, sizeof err) != 0) {
                budget_say(r, D2K_BUDGET_NOT_APPLICABLE, "запрос HTTP/3 %u не ушёл: %.60s — бюджет не проверен",
                           r->budget_requests, err);
                return;
            }
            uint8_t hdr[4096];
            size_t got = 0;
            int status = 0, closed = 0;
            (void)h3_read_headers(io->recv, io->ctx, hdr, sizeof hdr, verify_now_ms() + wait,
                                  &got, &status, &closed, err, sizeof err);
            long now = io->packets(io->ctx);
            if (now >= 0) r->budget_packets = (unsigned)now;
            if (closed) {
                budget_say(r, D2K_BUDGET_NOT_APPLICABLE, "сервер закрыл связь на %u-м запросе, %u "
                           "датаграмм из %u — бюджет не проверен: %.60s", r->budget_requests,
                           r->budget_packets, need, err);
                return;
            }
            if (!status && got) {
                /* Байты пришли, а кадр HEADERS не разобран — не молчание. */
                budget_say(r, D2K_BUDGET_NOT_APPLICABLE, "ответ HTTP/3 на %u-й запрос не разобран "
                           "(%zu байт) — бюджет не проверен", r->budget_requests, got);
                return;
            }
            if (!status) {
                budget_say(r, D2K_BUDGET_CUT, "сервер замолчал посреди повторов: %u-й запрос HTTP/3, "
                           "связь перенесла %u датаграмм из нужных %u", r->budget_requests,
                           r->budget_packets, need);
                return;
            }
            continue;
        }
        /* Ответ ещё идёт — это и есть «сервер отвечает»; ждём следующих байт. */
        int64_t until = verify_now_ms() + wait;
        int moved = 0;
        while (!moved && verify_now_ms() < until) {
            uint8_t sink[4096];
            long n = io->recv(io->ctx, sink, sizeof sink, err, sizeof err);
            if (n < 0) {
                long now = io->packets(io->ctx);
                if (now >= 0) r->budget_packets = (unsigned)now;
                budget_say(r, D2K_BUDGET_NOT_APPLICABLE, "сервер закрыл связь посреди ответа, %u "
                           "датаграмм из %u — бюджет не проверен: %.60s", r->budget_packets, need, err);
                return;
            }
            /* ДВИНУЛСЯ ОТВЕТ, А НЕ СЧЁТЧИК ДАТАГРАММ. Прежде здесь годилось
               любое изменение числа датаграмм связи, и повтор полёта сервера
               при заглушённом исходящем направлении выдавал «ответ идёт»
               бесконечно — ожидание не истекало, и выше объявлялся пройденный
               бюджет. Чужие датаграммы (управляющий поток сервера, таблицы
               QPACK) ответом тоже не являются, поэтому мера одна: РАЗНЫЕ
               байты ответа. */
            uint64_t grew = 0;
            int done_now = 0;
            io->progress(io->ctx, &grew, &done_now);
            if (n > 0 || grew != bytes || done_now != complete) moved = 1;
        }
        if (!moved) {
            budget_say(r, D2K_BUDGET_CUT, "сервер замолчал посреди ответа на %u-й запрос HTTP/3, "
                       "связь перенесла %ld датаграмм из нужных %u", r->budget_requests, pk, need);
            return;
        }
    }
}

typedef struct { d2k_qc *c; const char *host, *path; } quic_budget_ctx;
static int qb_request(void *ctx, uint64_t sid, char *err, size_t errcap) {
    quic_budget_ctx *q = ctx;
    uint8_t req[512];
    size_t rn = d2k_h3_request(q->host, q->path, req, sizeof req);
    if (!rn) { snprintf(err, errcap, "запрос HTTP/3 не собрался"); return -1; }
    return d2k_qc_stream_send(q->c, sid, req, rn, 1, err, errcap);
}
static long qb_recv(void *ctx, uint8_t *buf, size_t cap, char *err, size_t errcap) {
    uint64_t sid = 0;
    return d2k_qc_stream_recv(((quic_budget_ctx *)ctx)->c, &sid, buf, cap, 200, err, errcap);
}
static void qb_progress(void *ctx, uint64_t *bytes, int *complete) {
    d2k_qc_app_progress(((quic_budget_ctx *)ctx)->c, bytes, complete);
}
static long qb_packets(void *ctx) {
    uint64_t tx = 0, rx = 0;
    d2k_qc_datagrams(((quic_budget_ctx *)ctx)->c, &tx, &rx);
    return (long)(tx + rx);
}

/* use_fd — УЖЕ ЗАНЯТЫЙ сокет UDP (d2k_props_bind_udp), под чей местный порт
   поставлен пробный план. Меньше единицы — завести свой. */
d2k_ver_result d2k_verify_probe_quic_on(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms,
                                        size_t hello_wire) {
    return d2k_verify_probe_quic_path_on(use_fd, ip, port, sni, deadline_ms, hello_wire, "/");
}

/* То же по пути path — известному большому ресурсу цели (задача 39, раунд 1:
   select_resource_path теперь и для QUIC). NULL или пусто — «/». */
d2k_ver_result d2k_verify_probe_quic_path_on(int use_fd, const char *ip, uint16_t port,
                                             const char *sni, int deadline_ms,
                                             size_t hello_wire, const char *path) {
    /* Метки НЕТ намеренно — ровно по той же причине, что у TCP-зонда: к
       помеченному пакету поставленный план не применится, и зонд мерил бы
       линию БЕЗ обхода, считая, что мерит с обходом. */
    return d2k_verify_probe_quic_path_mark_on(use_fd, ip, port, sni, deadline_ms,
                                            hello_wire, 0, path);
}

/* The full-response caller and the field read-all switch share one drain. */
static void quic_read_response(d2k_qc *c, int64_t until, int full_response,
                               int *closed, uint64_t *bytes, int *complete,
                               char *err, size_t errcap) {
    quic_recv_ctx ctx = { c };
    *closed = quic_read_body(quic_recv_chunk, quic_recv_progress, &ctx, *closed,
                            until, full_response, bytes, complete, err, errcap);
}

static d2k_ver_result verify_quic_response(int full_response, int use_fd, const char *ip, uint16_t port,
                                                 const char *sni, int deadline_ms,
                                                 size_t hello_wire, uint32_t mark,
                                                 const char *path) {
    if (!path || !path[0]) path = "/";
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    const char *host = (sni && sni[0]) ? sni : ip;
    if (!host || !host[0]) { return r; }
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p <= 32 || *p == 127) {
            snprintf(r.reason, sizeof r.reason, "недопустимый символ в имени");
            return r;
        }
    }

    d2k_qc_opts o;
    memset(&o, 0, sizeof o);
    o.ip = ip;
    o.port = port ? port : 443;
    o.sni = sni;
    o.alpn = "h3";
    o.deadline_ms = deadline_ms > 0 ? deadline_ms : 5000;
    o.pad_to = hello_wire;
    /* Форма клиента, если её поставили на этот поток: приветствие того же
       вида, каким ходит человек (задача 66). */
    o.form = g_verify_quic_form_set ? &g_verify_quic_form : NULL;
    o.use_fd = use_fd;
    o.mark = mark;

    d2k_qc *c = NULL;
    char err[200];
    err[0] = '\0';
    int qc_rc = d2k_qc_connect(&o, &c, err, sizeof err);
    if (qc_rc != 0) {
        if (qc_rc == -2) {
            r.local_refusal = 1;
            snprintf(r.reason, sizeof r.reason, "%s", err);
        } else {
            /* Транспорт у QUIC не «встал» отдельно от рукопожатия: датаграмма
               уходит всегда, и отличить «ушла в никуда» от «ушла и не понравилась»
               можно только по тому, ответил ли сервер хоть чем-то. Оба случая для
               нас — «не измерено», и приписывать им уровень транспорта значило бы
               дописать доказательство. */
            snprintf(r.reason, sizeof r.reason, "рукопожатия нет: %.150s", err);
        }
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    /* QUIC v1 всегда TLS 1.3 (RFC 9001 §4). Выставляется строго после завершения рукопожатия. */
    r.negotiated_tls = 0x0304;
    r.name_ok = d2k_qc_peer_name(c);
    d2k_qc_local_addr(c, r.local_addr, &r.family, &r.local_port);
    if (r.family == 4) memcpy(r.local_ip4, r.local_addr, 4);
    r.fd = d2k_qc_fd(c);
    snprintf(r.reason, sizeof r.reason, "рукопожатие завершено, приложение молчит");

    /* Управляющий поток обязателен: без SETTINGS сервер вправе не отвечать
       вовсе, и молчание записалось бы блокировкой. */
    uint8_t ctl[16];
    size_t cn = d2k_h3_control(ctl, sizeof ctl);
    if (cn == 0 || d2k_qc_stream_send(c, 2, ctl, cn, 0, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "управляющий поток не ушёл: %.140s", err);
        r.fd = d2k_qc_release(c);
        return r;
    }
    /* Пауза между управляющим потоком и вопросом. Измерено 13.09.2026 на
       живых серверах: без неё отвечает только один стек из четырёх — сервер
       обязан увидеть SETTINGS раньше запроса, а за это же время доезжает его
       NEW_CONNECTION_ID и меняется адрес ответа. */
    {
        uint64_t sid = 0;
        uint8_t drop[2048];
        (void)d2k_qc_stream_recv(c, &sid, drop, sizeof drop, 400, err, sizeof err);
    }

    uint8_t req[512];
    size_t rn = d2k_h3_request(host, path, req, sizeof req);
    if (rn == 0 || d2k_qc_stream_send(c, 0, req, rn, 1, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "запрос не ушёл: %.150s", err);
        r.fd = d2k_qc_release(c);
        return r;
    }

    /* Буфер ответа на куче: заголовки HTTP/3 края Meta бывают длиннее 8 КБ,
       а d2k_h3_status берёт кадр HEADERS только целиком (задача 44). */
    uint8_t *rx = malloc(D2K_VERIFY_HEADER_LIMIT);
    if (!rx) {
        r.local_limit = 1;
        snprintf(r.reason, sizeof r.reason, "не хватило памяти под заголовки ответа HTTP/3");
        r.fd = d2k_qc_release(c);
        return r;
    }
    size_t got = 0;
    int closed = 0;
    uint64_t wire_before = d2k_qc_rx_wire_bytes(c);
    int64_t until = verify_now_ms() + (deadline_ms > 0 ? deadline_ms : 5000);
    quic_recv_ctx rctx = { c };
    int h3_status = 0;
    int headers_too_long = h3_read_headers(quic_recv_chunk, &rctx, rx,
        D2K_VERIFY_HEADER_LIMIT, until, &got, &h3_status, &closed, err, sizeof err);
    free(rx);
    if (h3_status != 0) {
        r.status = h3_status;
        if (h3_status == 451) {
            /* Та же сверка, что по TCP: кто ответил 451, говорит сертификат
               (см. request_page_budget). name_ok по QUIC выставлен сразу
               после рукопожатия. */
            if (r.name_ok == 1) {
                r.level = D2K_VER_DENIED;
                r.http_outcome = D2K_HTTP_LEGAL_DENIAL;
                snprintf(r.http_evidence, sizeof r.http_evidence, "HTTP 451");
                snprintf(r.reason, sizeof r.reason, "HTTP отказ: HTTP 451");
            } else {
                r.http_outcome = D2K_HTTP_NEUTRAL;
                snprintf(r.http_evidence, sizeof r.http_evidence, "HTTP 451 без имени");
                snprintf(r.reason, sizeof r.reason,
                         "HTTP 451, но собеседник не подтвердил имя сертификатом (%s) — "
                         "отказом сайта это не считаю",
                         r.name_ok == 0 ? "имя чужое" : "сертификата не было");
            }
        }
    }
    /* ЗАГОЛОВКИ — ЕЩЁ НЕ ПРИЛОЖЕНИЕ (задача 39). Поле 02.10.2026 (задача 33):
       после фальшивки линия пропускает рукопожатие и первые килобайты, а
       дальше поток обрывается. Приложение доказано, когда ответ пришёл
       ЦЕЛИКОМ (FIN и все байты до него без дыр — FIN под прикладными ключами
       коробке не подделать) или когда через линию прошло не меньше
       D2K_QUIC_ARM_DATA_BYTES данных ответа. Поток, вставший без полного
       ответа ниже порога, — обрыв.
       Чтение продолжается в том же сроке; лишние байты не храним. */
    if (r.status != 0 && r.level != D2K_VER_DENIED) {
        uint64_t bytes = 0;
        int complete = 0;
        quic_read_response(c, until, full_response, &closed, &bytes, &complete, err, sizeof err);
        r.body_bytes = bytes;
        r.body_complete = complete;
        /* То же правило, что у этапа данных плеча (d2k_quic_arm_data_judge). */
        if ((!full_response || complete) &&
            d2k_quic_arm_data_judge(1, r.status, bytes, complete) == D2K_QAD_PASS) {
            r.level = D2K_VER_APPLICATION;
            snprintf(r.reason, sizeof r.reason,
                     "заголовки HTTP/3 получены, статус %d, данных %llu байт%s", r.status,
                     (unsigned long long)bytes, complete ? ", ответ целиком" : "");
            if (g_verify_budget) {
                quic_budget_ctx qc = { c, host, path };
                quic_budget_io qio = { qb_request, qb_recv, qb_progress, qb_packets, &qc };
                budget_quic(&qio, deadline_ms, g_verify_budget, &r);
            }
        } else if (full_response) {
            snprintf(r.reason, sizeof r.reason,
                     "HTTP/3 статус %d, принято %llu байт, полный ответ не получен%s%.60s",
                     r.status, (unsigned long long)bytes,
                     closed ? ": " : "", closed ? err : "");
        } else {
            if (g_verify_quic_read_all) {
                snprintf(r.reason, sizeof r.reason,
                         "заголовки HTTP/3 получены (статус %d), поток оборван на %llu байт "
                         "до конца ответа%s%.60s", r.status, (unsigned long long)bytes,
                         closed ? ": " : "", closed ? err : "");
            } else {
                snprintf(r.reason, sizeof r.reason,
                         "заголовки HTTP/3 получены (статус %d), поток оборван на %llu байт "
                         "до %u и до конца ответа%s%.60s", r.status, (unsigned long long)bytes,
                         D2K_QUIC_ARM_DATA_BYTES, closed ? ": " : "", closed ? err : "");
            }
        }
    } else if (headers_too_long) {
        r.local_limit = 1;
        snprintf(r.reason, sizeof r.reason,
                 "заголовки ответа HTTP/3 длиннее %d байт", D2K_VERIFY_HEADER_LIMIT);
    } else if (r.level != D2K_VER_DENIED) {
        quic_app_silent(&r, got, d2k_qc_rx_wire_bytes(c) - wire_before,
                        closed ? err : NULL);
    }
    /* Сокет остаётся ОТКРЫТЫМ до d2k_verify_close — по той же причине, что у
       TCP-зонда: закрытие удаляет ячейку потока в датапате раньше, чем придёт
       событие применения плана. */
    r.fd = d2k_qc_release(c);
    return r;
}

/* Keep the scheduler's measured data-stage criterion separate from a fetch. */
d2k_ver_result d2k_verify_probe_quic_path_mark_on(int use_fd, const char *ip, uint16_t port,
                                                 const char *sni, int deadline_ms,
                                                 size_t hello_wire, uint32_t mark,
                                                 const char *path) {
    return verify_quic_response(0, use_fd, ip, port, sni, deadline_ms, hello_wire, mark, path);
}

d2k_ver_result d2k_verify_fetch_quic_on(int use_fd, const char *ip, uint16_t port,
                                      const char *sni, int deadline_ms,
                                      size_t hello_wire, uint32_t mark,
                                      const char *path) {
    return verify_quic_response(1, use_fd, ip, port, sni, deadline_ms, hello_wire, mark, path);
}

static long uncounted_transport(void *ctx) {(void)ctx;return -1;}
typedef struct {
    d2k_tls *tls;
    uint64_t before;
    d2k_doh_observer observer;
    void *ctx;
} doh_tls_observer;
static int observe_doh_tls(void *ctx,const d2k_doh_observation *observation) {
    doh_tls_observer *w=ctx;
    d2k_doh_observation current=*observation;
    current.response.rx_tls_wire_bytes=d2k_tls_rx_wire_bytes(w->tls)-w->before;
    current.response.rx_tls_record_missing=d2k_tls_rx_record_missing(w->tls);
    return w->observer(w->ctx,&current);
}
typedef struct {
    void *tls;
    int legacy;
    d2k_https_observer observer;
    void *context;
    unsigned ordinal;
    int refused;
} https_watch;
static int https_notify(https_watch *w,d2k_https_phase phase,const uint8_t *request,
    size_t length,const d2k_ver_result *response) {
    d2k_https_observation event={phase,w->ordinal,request,length,response};
    if(w->refused)return -1;
    if(w->observer && w->observer(w->context,&event)){w->refused=1;return -1;}
    return 0;
}
static long https_read(void *context,uint8_t *bytes,size_t length,int wait,char *err,size_t cap) {
    https_watch *w=context;
    return w->legacy?read12(w->tls,bytes,length,wait,err,cap):read13(w->tls,bytes,length,wait,err,cap);
}
static int https_write(void *context,const uint8_t *bytes,size_t length,char *err,size_t cap) {
    https_watch *w=context;w->ordinal++;
    if(https_notify(w,D2K_HTTPS_REQUEST_BEGIN,bytes,length,NULL))return -1;
    if(w->legacy?write12(w->tls,bytes,length,err,cap):write13(w->tls,bytes,length,err,cap))return -1;
    return https_notify(w,D2K_HTTPS_REQUEST_SENT,bytes,length,NULL);
}
static d2k_ver_result verify_https_owned(const d2k_tls_io *transport,const d2k_tls_probe_seed *seed,
    const uint8_t random[32],
    const char *host,const char *path,int timeout,size_t wire,int encoding,
    d2k_https_observer observer,void *context) {
    d2k_ver_result r={0};r.fd=-1;r.name_ok=-1;
    int valid_host=host && *host && strlen(host)<=253;
    if(valid_host)for(const unsigned char *p=(const unsigned char *)host;*p;p++) {
        if(!((*p>='a' && *p<='z') || (*p>='A' && *p<='Z') ||
             (*p>='0' && *p<='9') || *p=='.' || *p=='-' || *p=='_')) {
            valid_host=0;break;
        }
    }
    if(!transport || !transport->read || !transport->write || (!seed && !random) || !valid_host ||
       (path && !fetch_target_ok(path)) || timeout<=0 || encoding<0 || encoding>2) {
        r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"invalid owned HTTPS transport, seed or target");return r;
    }
    r.level=D2K_VER_TRANSPORT;
    static const uint8_t alpn[]={8,'h','t','t','p','/','1','.','1'};
    d2k_tls *tls=NULL;d2k_tls12 *tls12=NULL;char err[160]={0};
    int legacy=random!=NULL;
    int failed=legacy?d2k_tls12_connect_probe(transport,random,host,timeout,wire,&tls12,err,sizeof err):
        d2k_tls_connect_probe(transport,seed,host,timeout,wire,alpn,sizeof alpn,&tls,err,sizeof err);
    if(failed) {
        snprintf(r.reason,sizeof r.reason,"нет TLS на измерительном транспорте: %.120s",err);
        return r;
    }
    r.level=D2K_VER_HANDSHAKE;r.name_ok=legacy?d2k_tls12_peer_name(tls12):d2k_tls_peer_name(tls);
    r.negotiated_tls=legacy?0x0303:d2k_tls_version(tls);
    uint64_t before=legacy?d2k_tls12_rx_wire_bytes(tls12):d2k_tls_rx_wire_bytes(tls);
    https_watch watch={.tls=legacy?(void *)tls12:(void *)tls,.legacy=legacy,.observer=observer,.context=context};
    request_page_budget(https_read,https_write,&watch,host,encoding,path,timeout,legacy,NULL,0,
        &r,err,sizeof err,1);
    r.rx_tls_wire_bytes=(legacy?d2k_tls12_rx_wire_bytes(tls12):d2k_tls_rx_wire_bytes(tls))-before;
    r.rx_tls_record_missing=legacy?d2k_tls12_rx_record_missing(tls12):d2k_tls_rx_record_missing(tls);
    if(https_notify(&watch,D2K_HTTPS_EXCHANGE_END,NULL,0,&r)) {
        r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"owned HTTPS observer refused evidence");
    }
    if(legacy)d2k_tls12_free(tls12);else d2k_tls_free(tls);
    return r;
}
d2k_ver_result d2k_verify_https_observe_io(const d2k_tls_io *transport,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int timeout,size_t wire,int encoding,d2k_https_observer observer,void *context) {
    return verify_https_owned(transport,seed,NULL,host,path,timeout,wire,encoding,observer,context);
}
d2k_ver_result d2k_verify_https12_observe_io(const d2k_tls_io *transport,const uint8_t random[32],
    const char *host,const char *path,int timeout,size_t wire,int encoding,d2k_https_observer observer,void *context) {
    return verify_https_owned(transport,NULL,random,host,path,timeout,wire,encoding,observer,context);
}
d2k_ver_result d2k_verify_https_probe_io(const d2k_tls_io *transport,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int timeout,size_t wire,int encoding) {
    return d2k_verify_https_observe_io(transport,seed,host,path,timeout,wire,encoding,NULL,NULL);
}
static d2k_ver_result verify_doh_io(const d2k_tls_io *transport,const d2k_tls_probe_seed *seed,const char *host,const char *path,
    int timeout,size_t wire,unsigned budget,long (*packets)(void *),void *ctx,
    d2k_doh_observer observer,void *observer_ctx) {
    d2k_ver_result r={0};r.fd=-1;
    if(!transport || !transport->read || !transport->write || !host || !*host ||
       !path || !fetch_target_ok(path) || timeout<=0 ||
       budget>UINT32_MAX/2 || (budget && !packets)) {
        r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"invalid DoH transport, target or packet counter");return r;
    }
    r.level=D2K_VER_TRANSPORT;
    char err[160]={0};d2k_tls *tls=NULL;
    static const uint8_t alpn[]={2,'h','2'};
    int rc=seed?d2k_tls_connect_probe(transport,seed,host,timeout,wire,alpn,sizeof alpn,&tls,err,sizeof err):
        d2k_tls_connect_io(transport,host,timeout,wire,alpn,sizeof alpn,&tls,err,sizeof err);
    if(rc) {
        snprintf(r.reason,sizeof r.reason,"нет TLS на измерительном транспорте: %.120s",err);
        return r;
    }
    r.level=D2K_VER_HANDSHAKE;r.name_ok=d2k_tls_peer_name(tls);
    r.negotiated_tls=d2k_tls_version(tls);
    uint64_t before=d2k_tls_rx_wire_bytes(tls);
    budget_io counter={packets?packets:uncounted_transport,NULL,ctx};
    doh_tls_observer watcher={tls,before,observer,observer_ctx};
    request_doh_h2_observed(read13,write13,tls,host,path,timeout,&counter,budget,&r,err,sizeof err,
        observer?observe_doh_tls:NULL,observer?&watcher:NULL);
    r.rx_tls_wire_bytes=d2k_tls_rx_wire_bytes(tls)-before;
    r.rx_tls_record_missing=d2k_tls_rx_record_missing(tls);
    if(packets) {
        long count=packets(ctx);
        if(count>=0)r.data_packets=(unsigned)count;
        else if(r.budget!=D2K_BUDGET_PASSED)r.budget_uncountable=1;
    }
    d2k_tls_free(tls);return r;
}
d2k_ver_result d2k_verify_doh_io(const d2k_tls_io *io,const char *host,const char *path,
    int timeout,size_t wire,unsigned budget,long (*packets)(void *),void *ctx) {
    return verify_doh_io(io,NULL,host,path,timeout,wire,budget,packets,ctx,NULL,NULL);
}
d2k_ver_result d2k_verify_doh_probe_io(const d2k_tls_io *io,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int timeout,size_t wire,unsigned budget,long (*packets)(void *),void *ctx) {
    if(!seed) {
        d2k_ver_result r={0};r.fd=-1;r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"controlled TLS probe seed missing");return r;
    }
    return verify_doh_io(io,seed,host,path,timeout,wire,budget,packets,ctx,NULL,NULL);
}
d2k_ver_result d2k_verify_doh_observe_io(const d2k_tls_io *io,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int timeout,size_t wire,d2k_doh_observer observer,void *ctx) {
    if(!observer) {
        d2k_ver_result r={0};r.fd=-1;r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"DoH observer missing");return r;
    }
    return verify_doh_io(io,seed,host,path,timeout,wire,0,NULL,NULL,observer,ctx);
}

static d2k_doh_tls_open_fn doh_tls_open;

void d2k_verify_doh_set_tls(d2k_doh_tls_open_fn open_tls) {
    doh_tls_open = open_tls;
}

static d2k_dot_probe_fn dot_probe;
static d2k_plain_dns_probe_fn plain_dns_probe;

void d2k_verify_plain_dns_set_probe(d2k_plain_dns_probe_fn probe) {
    plain_dns_probe=probe;
}

d2k_ver_result d2k_verify_plain_dns_on(const char *ip,uint16_t port,uint8_t transport,
    const char *question,uint16_t type,int timeout,uint32_t mark) {
    if (plain_dns_probe)return plain_dns_probe(ip,port,transport,question,type,timeout,mark);
    d2k_ver_result r={.fd=-1,.name_ok=-1,.unsupported=1};
    snprintf(r.reason,sizeof r.reason,"plain DNS verifier unavailable");
    return r;
}

void d2k_verify_dot_set_probe(d2k_dot_probe_fn probe) {
    dot_probe=probe;
}

d2k_ver_result d2k_verify_dot_question_on(int fd,const char *ip,uint16_t port,const char *host,
    int timeout,uint16_t version,uint32_t mark,const char *qname,uint16_t qtype) {
    d2k_ver_result r={.fd=-1,.name_ok=-1};
    uint8_t address[16];
    char name[256];
    int af=ip && strchr(ip,':') ? AF_INET6 : AF_INET;
    if (!ip || inet_pton(af,ip,address)!=1 || !host ||
        (inet_pton(AF_INET,host,address)!=1 && inet_pton(AF_INET6,host,address)!=1 &&
            d2k_domain_normalize(host,name)) ||
        !port || timeout<=0 || (version && version!=0x0303 && version!=0x0304)) {
        if (fd>=0) close(fd);
        r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"invalid DoT endpoint");
        return r;
    }
    if (!dot_probe) {
        if (fd>=0) close(fd);
        r.unsupported=1;
        snprintf(r.reason,sizeof r.reason,"authenticated DoT verifier unavailable");
        return r;
    }
    r.family=af==AF_INET6 ? 6 : 4;
    int contact=verify_contact(fd,ip,port,mark,r.family,r.local_addr,&r.local_port,&r.fd);
    if (contact) {
        r.local_refusal=contact==-2;
        snprintf(r.reason,sizeof r.reason,"%s",r.local_refusal ?
            "cannot set DoT socket mark" : "DoT TCP connection failed");
        return r;
    }
    if (r.family==4) memcpy(r.local_ip4,r.local_addr,4);
    r.level=D2K_VER_TRANSPORT;
    dot_probe(r.fd,host,version,timeout,qname,qtype,&r);
    long packets=d2k_verify_packets_hook(r.fd);
    r.data_packets=packets>0 ? (unsigned)packets : 0;
    return r;
}

d2k_ver_result d2k_verify_dot_on(int fd,const char *ip,uint16_t port,const char *host,
    int timeout,uint16_t version,uint32_t mark) {
    return d2k_verify_dot_question_on(fd,ip,port,host,timeout,version,mark,NULL,0);
}

d2k_ver_result d2k_verify_doh_question_on(int fd,const char *ip,uint16_t port,const char *host,
    int timeout,size_t wire,int tls12,uint32_t mark,const char *path,
    const char *qname,uint16_t qtype) {
    /* The authenticated client uses its own ClientHello. Only receipts on
       this socket can attest to a candidate applied to this verification. */
    (void)wire;
    d2k_ver_result r = {.fd=-1, .name_ok=-1};
    uint8_t address[16];
    char identity[256], authority[262];
    int ip_family = ip && strchr(ip, ':') ? AF_INET6 : AF_INET;
    int name_family = host && strchr(host, ':') ? AF_INET6 : AF_INET;
    int invalid = !path || !ip || !host || !port || timeout<=0 ||
        !fetch_target_ok(path) || inet_pton(ip_family,ip,address)!=1;
    if (!invalid) {
        invalid = inet_pton(name_family,host,address)==1
            ? inet_ntop(name_family,address,identity,sizeof identity)==NULL
            : d2k_domain_normalize(host,identity)!=0;
    }
    if (invalid || d2k_dns_http_authority(identity,port,authority,sizeof authority)) {
        if (fd>=0) close(fd);
        r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"invalid DoH endpoint");
        return r;
    }
    if (!doh_tls_open) {
        if (fd>=0) close(fd);
        r.unsupported=1;
        snprintf(r.reason,sizeof r.reason,"authenticated DoH TLS backend unavailable");
        return r;
    }
    char question_name[256];
    uint8_t question[272];
    if (!qname) {
        qtype=d2k_dns_probe_question_name(host,question_name);
        qname=question_name;
    }
    size_t question_len=qtype ? dns_encode_question(qname,qtype,0,question,sizeof question) : 0;
    if (!question_len) {
        if(fd>=0)close(fd);
        r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"DoH endpoint has no valid DNS question");
        return r;
    }
    r.family=ip_family==AF_INET6 ? 6 : 4;
    int contact=verify_contact(fd,ip,port,mark,r.family,r.local_addr,&r.local_port,&r.fd);
    if (contact) {
        r.local_refusal=contact==-2;
        snprintf(r.reason,sizeof r.reason,"%s",r.local_refusal ? "cannot set DoH socket mark" : "DoH TCP connection failed");
        return r;
    }
    if (r.family==4) memcpy(r.local_ip4,r.local_addr,4);
    r.level=D2K_VER_TRANSPORT;
    uint16_t version=tls12<0 ? 0 : tls12 ? 0x0303 : 0x0304;
    d2k_doh_tls_session session={0};
    d2k_doh_tls_status status=doh_tls_open(r.fd,host,version,timeout,&session);
    if (status!=D2K_DOH_TLS_OK) {
        r.peer_auth_failed=status==D2K_DOH_TLS_AUTH;
        r.local_refusal=status==D2K_DOH_TLS_LOCAL;
        r.unsupported=status==D2K_DOH_TLS_PROTOCOL;
        const char *why=r.peer_auth_failed ? "DoH TLS certificate or identity rejected" :
            r.local_refusal ? "DoH TLS local trust setup failed" :
            r.unsupported ? "DoH TLS protocol or HTTP ALPN rejected" :
            "DoH TLS connection interrupted";
        snprintf(r.reason,sizeof r.reason,"%s",why);
        return r;
    }
    r.level=D2K_VER_HANDSHAKE;
    r.name_ok=1;
    r.peer_authenticated=1;
    r.negotiated_tls=session.tls_version;
    r.doh_http_version=session.http_version;
    snprintf(r.reason,sizeof r.reason,"DoH TLS authenticated; DNS response pending");
    char err[160]={0};
    budget_io counters={fd_packets,fd_peer_spoke,&r.fd};
    if (session.http_version==1)
        request_doh_h1_session(&session,authority,path,question,question_len,timeout,&r);
    else if (session.http_version==2)
        request_doh_h2_question(session.io.read,session.io.write,session.io.context,authority,path,
            question,question_len,timeout,&counters,g_verify_budget,&r,err,sizeof err,NULL,NULL);
    else {
        r.unsupported=1;
        snprintf(r.reason,sizeof r.reason,"DoH HTTP protocol was not negotiated");
    }
    long packets=d2k_verify_packets_hook(r.fd);
    r.data_packets=packets>0 ? (unsigned)packets : 0;
    session.release(session.io.context);
    return r;
}

d2k_ver_result d2k_verify_doh_on(int fd,const char *ip,uint16_t port,const char *host,
    int timeout,size_t wire,int tls12,uint32_t mark,const char *path) {
    return d2k_verify_doh_question_on(fd,ip,port,host,timeout,wire,tls12,mark,path,NULL,0);
}

d2k_ver_result d2k_verify_preflight_on(int fd,const char *ip,uint16_t port,const char *host,
    int timeout,size_t wire,int tls12) {
    (void)wire;
    d2k_ver_result r={.fd=-1,.name_ok=-1};
    uint8_t address[16];
    int family=ip&&strchr(ip,':')?6:4;
    if(!ip||!host||!*host||!port||timeout<=0||(tls12!=0&&tls12!=1)||
        inet_pton(family==6?AF_INET6:AF_INET,ip,address)!=1) {
        if(fd>=0)close(fd);
        r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"invalid preflight endpoint");return r;
    }
    if(!doh_tls_open) {
        if(fd>=0)close(fd);
        r.unsupported=1;
        snprintf(r.reason,sizeof r.reason,"authenticated preflight TLS backend unavailable");return r;
    }
    int contact=verify_contact(fd,ip,port,0,family,r.local_addr,&r.local_port,&r.fd);
    if(contact) {
        r.local_refusal=contact==-2;
        snprintf(r.reason,sizeof r.reason,"%s",r.local_refusal?"cannot set preflight socket mark":"preflight TCP connection failed");
        return r;
    }
    if(family==4)memcpy(r.local_ip4,r.local_addr,4);
    r.family=family;r.level=D2K_VER_TRANSPORT;
    d2k_doh_tls_session session={0};
    uint16_t version=tls12?0x0303:0x0304;
    d2k_doh_tls_status status=doh_tls_open(r.fd,host,version,timeout,&session);
    if(status!=D2K_DOH_TLS_OK) {
        r.peer_auth_failed=status==D2K_DOH_TLS_AUTH;
        r.local_refusal=status==D2K_DOH_TLS_LOCAL;
        r.unsupported=status==D2K_DOH_TLS_PROTOCOL;
        snprintf(r.reason,sizeof r.reason,"%s",r.peer_auth_failed?"preflight TLS certificate or identity rejected":
            r.local_refusal?"preflight TLS local trust setup failed":
            r.unsupported?"preflight TLS protocol or HTTP ALPN rejected":"preflight TLS connection interrupted");
        return r;
    }
    r.level=D2K_VER_HANDSHAKE;r.name_ok=1;r.peer_authenticated=1;
    r.negotiated_tls=session.tls_version;r.http_version=session.http_version;
    char authority[262],err[160]={0};
    if(d2k_dns_http_authority(host,port,authority,sizeof authority)) {
        r.local_refusal=1;r.level=D2K_VER_TRANSPORT;
        snprintf(r.reason,sizeof r.reason,"invalid preflight HTTP authority");
    } else if(session.http_version==1) {
        budget_io counters={fd_packets,fd_peer_spoke,&r.fd};
        request_page_budget(session.io.read,session.io.write,session.io.context,authority,0,"/",
            timeout,0,&counters,0,&r,err,sizeof err,0);
    } else if(session.http_version==2) {
        static const uint8_t preface[]="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        static const uint8_t settings[]={0,1,0,0,0,0,0,2,0,0,0,0};
        if(session.io.write(session.io.context,preface,sizeof preface-1,err,sizeof err)) {
            r.level=D2K_VER_HANDSHAKE;
        } else {
            doh_h2_io io={0};io.read=session.io.read;io.write=session.io.write;
            io.session=session.io.context;io.wait_ms=timeout;
            if(dh2_frame(&io,4,0,0,settings,sizeof settings,err,sizeof err) ||
                dh2_get(&io,1,authority,"/",&r,err,sizeof err)) {
                r.level=D2K_VER_HANDSHAKE;r.body_complete=0;
                snprintf(r.reason,sizeof r.reason,"preflight HTTP/2 exchange incomplete: %.100s",err);
            } else {
                r.level=D2K_VER_APPLICATION;
                snprintf(r.reason,sizeof r.reason,"authenticated preflight HTTP/2 response complete");
            }
        }
    } else {
        r.unsupported=1;r.level=D2K_VER_HANDSHAKE;
        snprintf(r.reason,sizeof r.reason,"preflight HTTP protocol was not negotiated");
    }
    long packets=d2k_verify_packets_hook(r.fd);
    r.data_packets=packets>0?(unsigned)packets:0;
    session.release(session.io.context);
    return r;
}
