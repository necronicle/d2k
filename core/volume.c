/* volume.c — направленные измерения объёма. См. d2k_volume.h.
 *
 * ЛЕСТНИЦА ИСХОДЯЩЕГО ОБЪЁМА: десять запросов по одному соединению, со второго
 * — с мусорным заголовком. Мусор в заголовке остаётся единственным способом
 * накачать соединение СВОИМ объёмом, не завися от того, что отдаёт мишень.
 *
 * Отдельная RX-пара identity/gzip ниже измеряет тело ответа и требует двух
 * совпавших обрывов плюс полного gzip-контроля. Направления не смешиваются:
 * TX-ступень и RX-обрыв возвращаются отдельными полями и попадают в каталог
 * под разными видами приметы.
 */
/* Файл включают и как текст в составные тесты — после системных заголовков,
   где glibc (с 2026) уже задал _POSIX_C_SOURCE сам: голый #define там —
   переопределение под -Werror (CI 22.10.2026). Отдельной единицей трансляции
   значение задаётся как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp — имя подсказки против предъявляемого SNI */
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"   /* d2k_mark_hook — метка ставится тем же путём, что везде */
#include "d2k_catalog.h" /* общий допуск для сопоставления RX-объёмов */
#include "d2k_tls13.h"
#include "d2k_tls12.h"
#include "d2k_volume.h"
#include "d2k_verify.h"

/* Восемь секунд на подключение и на рукопожатие — из пробы донора
   (z2k-detect/internal/tcp16), замер на этой линии. */
#define CONNECT_MS   8000
#define HANDSHAKE_MS 8000

/* Пауза между запросами. Без неё десять запросов уходят одной очередью, и
   коробка видит поток иначе, чем видит его браузер: вердикт плывёт. */
#define CHUNK_DELAY_MS 50
#define RESPONSE_PROBE_GAP_MS 500

/* Ожидание ответа считается от ИЗМЕРЕННОГО RTT, а не берётся с потолка. Живой
   ответ приходит за один RTT; «нет ответа» — это неподходящее имя, на котором
   коробка молчит, и с фиксированным потолком каждый мимо-кандидат стоил бы
   полные секунды. Нижняя граница защищает от слишком оптимистичного замера на
   первом пакете, верхняя — от линии с большим RTT. */
#define READ_MIN_MS  1500
#define READ_MAX_MS  12000

/* A partial encrypted record is visible even before the first HTTP header.
   This is suspicion, not a verdict. Unknown versions, replayed hellos and
   local limits cannot establish the application record context. */
static int rx_wire_partial(const d2k_ver_result *r) {
    return r && r->level == D2K_VER_HANDSHAKE && r->name_ok == 1 &&
        !r->status && !r->replay_proof && !r->local_limit &&
        (r->negotiated_tls == 0x0303 || r->negotiated_tls == 0x0304) &&
        r->rx_tls_record_missing &&
        r->rx_tls_wire_bytes >= (uint64_t)D2K_VOL_MIN_KB * 1024;
}

int d2k_volume_rx_partial(const d2k_ver_result *r) {
    return rx_wire_partial(r) || (r && r->status >= 200 && r->status < 300 && !r->body_complete &&
        r->body_encoding == 0 && r->body_framing_valid &&
        r->body_has_length != r->body_chunked &&
        r->body_bytes >= (uint64_t)D2K_VOL_MIN_KB * 1024 &&
        (!r->body_has_length || r->body_expected > r->body_bytes));
}

/* ДВА ИЗМЕРЕНИЯ ГОВОРЯТ ОБ ОДНОМ. Оба оборваны, оба в ОДНОМ домене
   (ciphertext либо HTTP-тело), и контекст домена совпал: согласованная версия
   TLS для записи, HTTP framing для тела. Байты здесь не сравниваются — это
   дело d2k_volume_rx_evidence, которое и держит допуск. */
int d2k_volume_rx_pair_agrees(const d2k_ver_result *a, const d2k_ver_result *b) {
    if (!a || !b || !d2k_volume_rx_partial(a) || !d2k_volume_rx_partial(b)) { return 0; }
    if (rx_wire_partial(a) != rx_wire_partial(b)) { return 0; }
    if (rx_wire_partial(a)) { return a->negotiated_tls == b->negotiated_tls; }
    return a->body_has_length == b->body_has_length && a->body_chunked == b->body_chunked;
}

/* ОДНО ИЗМЕРЕНИЕ ОБОРВАЛОСЬ, ВТОРОЕ ДОШЛО ДО КОНЦА — РАСХОЖДЕНИЕ, А НЕ
   ОПРОВЕРЖЕНИЕ. Поле 12.10.2026, www.tampermonkey.net: /style.css с VPS —
   30182 байта, с линии — 15963, восемь прогонов подряд байт в байт, молча,
   без RST и FIN сервера. RX-зонд при этом видел «identity-1 partial=15627;
   identity-2 HTTP 200 body=22094 complete=1» и возвращался ни с чем: три
   эпизода подряд печатали «позднее закрытие не подтвердилось парными
   измерениями» и уходили в покой на десять минут.

   Дошедший повтор — шум линии, и вердикт по нему не выносится так же, как не
   выносится по одному обрыву (§«подозрение не равно блокировке»). Поэтому
   заказывается ТРЕТИЙ identity-прогон, и пара считается сошедшейся только
   если обрыв подтвердился на нём: вердикт всё равно стоит на ДВУХ обрывах.

   Поводом служит именно противоречие, а не всякая несошедшаяся пара: ответ
   завершился кодом 2xx и САМ прошёл измеряемую полосу, то есть сказал о
   полосе «прошла». Пустое измерение (нет TCP, нет статуса) не противоречит
   ничему, а завершённый ответ меньше полосы — непроверенный бюджет
   (rx_short), и лишнего прогона ни то, ни другое не заказывает. */
int d2k_volume_rx_needs_repeat(const d2k_ver_result *a, const d2k_ver_result *b) {
    if (!a || !b) { return 0; }
    if (!d2k_volume_rx_partial(a) || d2k_volume_rx_partial(b)) { return 0; }
    return b->status >= 200 && b->status < 300 && b->body_complete &&
           b->body_framing_valid &&
           b->body_bytes >= (uint64_t)D2K_VOL_MIN_KB * 1024;
}

int d2k_volume_rx_evidence(const d2k_ver_result *a,
                           const d2k_ver_result *b,
                           const d2k_ver_result *gzip,
                           d2k_vol_result *out) {
    const uint64_t min_bytes = (uint64_t)D2K_VOL_MIN_KB * 1024;
    if (!a || !b || !gzip || !out) { return 0; }
    if (rx_wire_partial(a) || rx_wire_partial(b)) {
        if (!rx_wire_partial(a) || !rx_wire_partial(b) ||
            a->negotiated_tls != b->negotiated_tls ||
            gzip->negotiated_tls != a->negotiated_tls ||
            gzip->level != D2K_VER_APPLICATION || gzip->name_ok != 1 ||
            gzip->local_limit || gzip->status < 200 || gzip->status >= 300 ||
            !gzip->body_complete || !gzip->body_framing_valid ||
            gzip->body_encoding != 1 || !gzip->body_bytes ||
            !gzip->rx_tls_wire_bytes || gzip->rx_tls_record_missing ||
            gzip->rx_tls_wire_bytes >= a->rx_tls_wire_bytes ||
            gzip->rx_tls_wire_bytes >= b->rx_tls_wire_bytes) return 0;
        uint64_t lo = a->rx_tls_wire_bytes < b->rx_tls_wire_bytes
            ? a->rx_tls_wire_bytes : b->rx_tls_wire_bytes;
        uint64_t hi = a->rx_tls_wire_bytes > b->rx_tls_wire_bytes
            ? a->rx_tls_wire_bytes : b->rx_tls_wire_bytes;
        if (hi - lo > (uint64_t)D2K_VOLUME_SLACK * 1024) return 0;
        out->rx_cut = 1; out->rx_wire_basis = 1;
        uint64_t kb = (lo + (hi - lo) / 2) / 1024;
        out->rx_at_kb = kb > INT_MAX ? INT_MAX : (int)kb;
        out->rx_expected_kb = 0; out->rx_compressed_complete = 1;
        unsigned pa = a->data_packets, pb = b->data_packets;
        unsigned pk = pa && pb ? (pa < pb ? pa : pb) : (pa ? pa : pb);
        out->rx_cut_packets = pk > INT_MAX ? INT_MAX : (int)pk;
        snprintf(out->reason, sizeof out->reason,
            "TLS RX дважды оборвался внутри записи около %d КБ; меньший gzip завершился",
            out->rx_at_kb);
        return 1;
    }
    if (a->status < 200 || a->status >= 300 || b->status < 200 || b->status >= 300 ||
        a->body_complete || b->body_complete || a->body_encoding != 0 ||
        !a->body_framing_valid || !b->body_framing_valid ||
        b->body_encoding != 0 || a->body_bytes < min_bytes || b->body_bytes < min_bytes ||
        a->body_has_length != b->body_has_length || a->body_chunked != b->body_chunked ||
        (!a->body_has_length && !a->body_chunked) ||
        (a->body_has_length && a->body_chunked)) { return 0; }
    if (a->body_has_length && (a->body_expected <= a->body_bytes ||
                               b->body_expected <= b->body_bytes)) { return 0; }
    uint64_t delta = a->body_bytes > b->body_bytes
                   ? a->body_bytes - b->body_bytes : b->body_bytes - a->body_bytes;
    if (gzip->status < 200 || gzip->status >= 300 || !gzip->body_framing_valid ||
        gzip->body_encoding != 1 || gzip->body_bytes == 0) { return 0; }
    /* ДВЕ ПРИМЕТЫ ОДНОГО И ТОГО ЖЕ: ОБРЫВ ПО БАЙТАМ И ОБРЫВ ПО ПАКЕТАМ.
       Байтовая — identity рвётся, а gzip той же страницы, меньший по
       объёму, доходит. Пакетная (поле 04.10, task-55-facts §1.2: Cloudflare
       режет поток после ~25 пакетов с данными обеих сторон, 25–27 в 18/18
       потоках, при 5,9–29,6 КБ): gzip, которому самому нужно больше
       бюджета, рвётся тоже, но на ТОМ ЖЕ числе пакетов. rua.gr 04.10:
       identity 22229/22280, gzip 20817 не дошёл — прежнее правило читало
       это как «блока нет». Пакеты считает ядро (TCP_INFO data_segs); не
       посчитаны все три — остаётся только байтовое правило. */
    int packet_budget = 0;
    if (!gzip->body_complete) {
        unsigned pa = a->data_packets, pb = b->data_packets, pg = gzip->data_packets;
        unsigned lo = pa, hi = pa;
        if (!pa || !pb || !pg) { return 0; }
        if (pb < lo) lo = pb;
        if (pb > hi) hi = pb;
        if (pg < lo) lo = pg;
        if (pg > hi) hi = pg;
        if (hi - lo > D2K_VOLUME_PACKET_SLACK) { return 0; }
        packet_budget = 1;
    }
    /* Байтовый допуск — только байтовой примете. При пакетной байты одного
       бюджета законно расходятся (25–27 пакетов при 5,9–29,6 КБ; поле
       17.10.2026, rua.gr: 18187/22292 байт на 26/26/26 пакетах). */
    if (!packet_budget && delta > (uint64_t)D2K_VOLUME_SLACK * 1024) { return 0; }

    out->rx_cut = 1; out->rx_wire_basis = 0;
    uint64_t midpoint = (a->body_bytes < b->body_bytes ? a->body_bytes : b->body_bytes)
                      + delta / 2;
    uint64_t cut_kb = midpoint / 1024;
    out->rx_at_kb = cut_kb > INT_MAX ? INT_MAX : (int)cut_kb;
    out->rx_expected_kb = 0;
    if (a->body_has_length && a->body_expected <= (uint64_t)INT_MAX * 1024) {
        out->rx_expected_kb = (int)(a->body_expected / 1024);
    }
    out->rx_compressed_complete = !packet_budget;
    /* Бюджет потока коробки (задача 55): пакеты с данными обеих сторон, на
       которых identity оборвался. Из двух посчитанных — меньший: коробка
       режет не позже него. Не посчитан ни один — 0, бюджета не выдумываем.
       При пакетной примете в счёт идёт и обрыв gzip. */
    unsigned pa = a->data_packets, pb = b->data_packets;
    unsigned pk = pa && pb ? (pa < pb ? pa : pb) : (pa ? pa : pb);
    if (packet_budget && gzip->data_packets < pk) { pk = gzip->data_packets; }
    out->rx_cut_packets = pk > INT_MAX ? INT_MAX : (int)pk;
    if (packet_budget) {
        snprintf(out->reason, sizeof out->reason,
                 "identity (около %d КБ) и gzip оборвались на одном бюджете: ~%u пакетов "
                 "с данными на поток", out->rx_at_kb, pk);
    } else if (out->rx_expected_kb > 0) {
        snprintf(out->reason, sizeof out->reason,
                 "identity-тело повторно оборвалось около %d/%d КБ; gzip завершился",
                 out->rx_at_kb, out->rx_expected_kb);
    } else {
        snprintf(out->reason, sizeof out->reason,
                 "chunked identity-тело повторно оборвалось около %d КБ; gzip завершился",
                 out->rx_at_kb);
    }
    return 1;
}

const char *d2k_vol_verdict_name(d2k_vol_verdict v) {
    switch (v) {
    case D2K_VOL_CUT:    return "обрыв по объёму";
    case D2K_VOL_PASSED: return "объём прошёл";
    case D2K_VOL_SHORT:  return "объём не набран — вердикта нет";
    default:             return "мишень не ответила";
    }
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void nap_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    (void)nanosleep(&ts, NULL);
}

/* Ограниченная по времени отправка открытого запроса. *sent_out — сколько
   байт этого запроса действительно ушло в ядро, и при неудаче тоже: объём
   лестницы считается по отправленному, а не по номеру ступени. */
/* Неблокирующий режим — флагом самого дескриптора, а не MSG_DONTWAIT: флага
   recv/send нет в чистом POSIX, и -std=c99 его не даёт (macOS). Прежние флаги
   возвращаются на место. */
static int nonblock_begin(int fd, int *saved, char *err, size_t cap) {
    *saved = fcntl(fd, F_GETFL, 0);
    if (*saved < 0 || (!(*saved & O_NONBLOCK) && fcntl(fd, F_SETFL, *saved | O_NONBLOCK) < 0)) {
        snprintf(err, cap, "неблокирующий режим: %s", strerror(errno));
        return -1;
    }
    return 0;
}
static void nonblock_end(int fd, int saved) {
    if (saved >= 0 && !(saved & O_NONBLOCK)) (void)fcntl(fd, F_SETFL, saved);
}

static int volume_send_plain_nb(int fd, const char *data, size_t len,
                                int timeout_ms, size_t *sent_out, char *err, size_t cap) {
    size_t sent = 0;
    const int64_t deadline = now_ms() + timeout_ms;
    *sent_out = 0;
    while (sent < len) {
        *sent_out = sent;
        const int64_t left = deadline - now_ms();
        if (left <= 0) {
            snprintf(err, cap, "таймаут отправки: %zu/%zu байт", sent, len);
            return -1;
        }
        struct pollfd p = { .fd = fd, .events = POLLOUT };
        int ready = poll(&p, 1, left > INT_MAX ? INT_MAX : (int)left);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            snprintf(err, cap, "ожидание отправки: %s", strerror(errno));
            return -1;
        }
        if (!ready) continue;
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            snprintf(err, cap, "соединение закрыто при отправке: %zu/%zu байт", sent, len);
            return -1;
        }
        if (!(p.revents & POLLOUT)) continue;
        int flags = 0;
#ifdef MSG_NOSIGNAL
        flags |= MSG_NOSIGNAL;
#endif
        ssize_t n = send(fd, data + sent, len - sent, flags);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) {
            snprintf(err, cap, "отправлено %zu/%zu байт: %s", sent, len,
                     n < 0 ? strerror(errno) : "соединение закрыто");
            return -1;
        }
        sent += (size_t)n;
    }
    *sent_out = sent;
    return 0;
}
static int volume_send_plain(int fd, const char *data, size_t len,
                             int timeout_ms, size_t *sent_out, char *err, size_t cap) {
    int saved;
    *sent_out = 0;
    if (nonblock_begin(fd, &saved, err, cap) != 0) return -1;
    int rc = volume_send_plain_nb(fd, data, len, timeout_ms, sent_out, err, cap);
    nonblock_end(fd, saved);
    return rc;
}

static int clamp_ms(int64_t v, int lo, int hi) {
    if (v < lo) { return lo; }
    if (v > hi) { return hi; }
    return (int)v;
}

/* Набивка: печатные символы, потому что она едет в ЗАГОЛОВКЕ HTTP, а туда
   произвольные байты класть нельзя — сервер отверг бы запрос, и мы мерили бы
   это вместо блока. Из /dev/urandom, а не постоянная строка: одинаковый мусор
   в десяти запросах коробка вправе схлопнуть как повтор. */
static void fill_pad(char *out, size_t n) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    FILE *f = fopen("/dev/urandom", "rb");
    for (size_t i = 0; i < n; i++) {
        int c = f ? fgetc(f) : -1;
        if (c < 0) { c = (int)(i * 31 + 7); }
        out[i] = alphabet[(unsigned)c % (sizeof alphabet - 1)];
    }
    if (f) { fclose(f); }
}

static int connect_bounded(const char *ip, uint16_t port, uint32_t mark,
                           char *reason, size_t cap) {
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int family;
    memset(&addr, 0, sizeof addr);
    struct sockaddr_in *a4 = (struct sockaddr_in *)&addr;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&addr;
    if (inet_pton(AF_INET, ip, &a4->sin_addr) == 1) {
        family = AF_INET; a4->sin_family = AF_INET;
        a4->sin_port = htons(port); addrlen = sizeof *a4;
    } else if (inet_pton(AF_INET6, ip, &a6->sin6_addr) == 1) {
        family = AF_INET6; a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port); addrlen = sizeof *a6;
    } else {
        snprintf(reason, cap, "адрес \"%s\" не разбирается", ip);
        return -1;
    }
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) { snprintf(reason, cap, "сокет: %s", strerror(errno)); return -1; }
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    if (mark != 0 && d2k_mark_hook(fd, mark) != 0) {
        /* Метка не поставилась — проба пойдёт ПО ОБЩИМ ПРАВИЛАМ, то есть
           через уже поставленный план. Это меряло бы работу плана, а не линию,
           и молча так делать нельзя. */
        snprintf(reason, cap, "метка 0x%x не поставилась: %s", (unsigned)mark, strerror(errno));
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        snprintf(reason, cap, "неблокирующий режим: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, addrlen) != 0) {
        if (errno != EINPROGRESS) {
            snprintf(reason, cap, "нет TCP: %s", strerror(errno));
            close(fd);
            return -1;
        }
        struct pollfd p;
        p.fd = fd; p.events = POLLOUT; p.revents = 0;
        if (poll(&p, 1, CONNECT_MS) <= 0) {
            snprintf(reason, cap, "нет TCP: не подключились за %d мс", CONNECT_MS);
            close(fd);
            return -1;
        }
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0 || soerr != 0) {
            snprintf(reason, cap, "нет TCP: %s", strerror(soerr ? soerr : errno));
            close(fd);
            return -1;
        }
    }
    (void)fcntl(fd, F_SETFL, flags);
    return fd;
}

/* A server refusal or an explicit connection close is not a volume cut.
   Per response: HTTP/1.1 stays open unless "Connection: close"; HTTP/1.0
   stays open only with an explicit "keep-alive" token. 1xx (except 101) is
   informational and is followed by the final response of the same request. */
typedef struct {
    char line[4096];
    size_t used;
    int status;
    int http10;
    int close_token, keepalive_token;
} volume_head;

static void head_connection_tokens(volume_head *h, const char *p) {
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        const char *begin = p;
        while (*p && *p != ',') p++;
        const char *end = p;
        while (end > begin && (end[-1] == ' ' || end[-1] == '\t')) end--;
        if (end - begin == 5 && !strncasecmp(begin, "close", 5)) h->close_token = 1;
        if (end - begin == 10 && !strncasecmp(begin, "keep-alive", 10)) h->keepalive_token = 1;
    }
}

/* 0: need more, 1: final reusable response head, -2: unsuitable for the probe. */
static int volume_head_feed(volume_head *h, unsigned char c,
                            char *reason, size_t cap) {
    if (c != '\n') {
        if (!c || h->used + 1 >= sizeof h->line) {
            snprintf(reason, cap, "заголовок ответа не пригоден для замера");
            return -2;
        }
        h->line[h->used++] = (char)c;
        return 0;
    }
    if (h->used && h->line[h->used - 1] == '\r') h->used--;
    h->line[h->used] = '\0';
    if (!h->status) {
        const char *s = h->line;
        if (h->used < 12 ||
            (strncmp(s, "HTTP/1.1 ", 9) && strncmp(s, "HTTP/1.0 ", 9)) ||
            s[9] < '1' || s[9] > '5' ||
            s[10] < '0' || s[10] > '9' ||
            s[11] < '0' || s[11] > '9' ||
            (h->used > 12 && s[12] != ' ')) {
            snprintf(reason, cap, "ответ не является корректным HTTP/1.x");
            return -2;
        }
        h->status = (s[9] - '0') * 100 + (s[10] - '0') * 10 + s[11] - '0';
        h->http10 = s[7] == '0';
        h->close_token = h->keepalive_token = 0;
    } else if (!h->used) {
        if (h->status < 200 && h->status != 101) {
            /* Informational: the final response of this request follows. */
            h->status = 0;
            h->http10 = h->close_token = h->keepalive_token = 0;
            return 0;
        }
        int closes = h->close_token || (h->http10 && !h->keepalive_token);
        if (h->status == 101 || h->status >= 400 || closes) {
            snprintf(reason, cap, "HTTP %d%s: продолжение объёмной пробы невозможно",
                     h->status, closes ? ", соединение закрывается сервером" : "");
            return -2;
        }
        return 1;
    } else if (!strncasecmp(h->line, "Connection:", 11)) {
        head_connection_tokens(h, h->line + 11);
    }
    h->used = 0;
    return 0;
}

/* СЕРВЕР ЗАКРЫЛ ПОТОК САМ (FIN) — НЕ ОБРЫВ ПО ОБЪЁМУ. TLS-слой сворачивает FIN
   на границе записи в ту же ошибку чтения, что RST и тишину; различает их
   ядро: CLOSE_WAIT — пришёл FIN собеседника, а мы ещё не закрыли; после RST —
   CLOSED, при тишине — ESTABLISHED. Раскладка — начало struct tcp_info Linux
   (TCP_INFO, состояние в первом байте, CLOSE_WAIT = 8) и tcp_connection_info
   Darwin (TCP_CONNECTION_INFO 0x106, CLOSE_WAIT = 5), без библиотечных
   заголовков разных лет (тот же приём, что d2k_verify_tcp_data_packets).
   1 — FIN, 0 — нет, -1 — ядро не сказало (прежняя классификация). */
static int volume_peer_fin(int fd) {
#if defined(__linux__) || defined(__APPLE__)
    uint8_t info[256];
    socklen_t len = sizeof info;
    memset(info, 0, sizeof info);
#if defined(__linux__)
    const int opt = 11, close_wait = 8;
#else
    const int opt = 0x106, close_wait = 5;
#endif
    if (fd < 0 || getsockopt(fd, IPPROTO_TCP, opt, info, &len) != 0 || len < 1) return -1;
    return info[0] == close_wait;
#else
    (void)fd;
    return -1;
#endif
}

/* 0: reusable response, -1: transport failure, -2: unsuitable HTTP. */
static int drain_head_tls(d2k_tls *t, d2k_tls12 *t12, int fd, int wait_ms,
                          char *reason, size_t cap) {
    volume_head head = {0};
    int64_t deadline = now_ms() + wait_ms;
    for (;;) {
        int64_t left = deadline - now_ms();
        if (left <= 0) { snprintf(reason, cap, "ответа нет"); return -1; }
        uint8_t c;
        long r = t12 ? d2k_tls12_read(t12, &c, 1, (int)left, reason, cap)
                     : d2k_tls_read(t, &c, 1, (int)left, reason, cap);
        if (r <= 0) {
            if (r == 0) {
                snprintf(reason, cap, "сервер завершил TLS до полного HTTP-ответа; причина неизвестна");
                return -2;
            }
            if (volume_peer_fin(fd) == 1) {
                snprintf(reason, cap, "сервер закрыл соединение (FIN) без полного HTTP-ответа");
                return -2;
            }
            return -1;
        }
        int parsed = volume_head_feed(&head, c, reason, cap);
        if (parsed) return parsed > 0 ? 0 : parsed;
    }
}

static int drain_head_plain_nb(int fd, int wait_ms, char *reason, size_t cap) {
    volume_head head = {0};
    int64_t deadline = now_ms() + wait_ms;
    for (;;) {
        int64_t left = deadline - now_ms();
        if (left <= 0) { snprintf(reason, cap, "ответа нет"); return -1; }
        struct pollfd p;
        p.fd = fd; p.events = POLLIN; p.revents = 0;
        int pr = poll(&p, 1, left > INT_MAX ? INT_MAX : (int)left);
        if (pr < 0 && errno == EINTR) continue;
        if (pr < 0) {
            snprintf(reason, cap, "ожидание ответа: %s", strerror(errno));
            return -1;
        }
        if (!pr) continue;
        if (p.revents & POLLNVAL) {
            snprintf(reason, cap, "сокет ответа закрыт");
            return -1;
        }
        /* POLLHUP can accompany unread response bytes. Drain them first. */
        if (!(p.revents & (POLLIN | POLLHUP | POLLERR))) continue;
        uint8_t c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (p.revents & (POLLHUP | POLLERR)) {
                snprintf(reason, cap, "соединение закрыто без полного ответа");
                return -2;
            }
            continue;
        }
        if (r == 0) {
            snprintf(reason, cap, "сервер закрыл соединение (FIN) без полного ответа");
            return -2;
        }
        if (r < 0) {
            snprintf(reason, cap, "чтение: %s", strerror(errno));
            return -1;
        }
        int parsed = volume_head_feed(&head, c, reason, cap);
        if (parsed) return parsed > 0 ? 0 : parsed;
    }
}

static int drain_head_plain(int fd, int wait_ms, char *reason, size_t cap) {
    int saved;
    /* Local descriptor failure says nothing about the path. */
    if (nonblock_begin(fd, &saved, reason, cap) != 0) return -2;
    int rc = drain_head_plain_nb(fd, wait_ms, reason, cap);
    nonblock_end(fd, saved);
    return rc;
}

/* ДРУГОЙ ПУБЛИЧНЫЙ ПУТЬ ТОГО ЖЕ ИМЕНИ, КОГДА МЕРИТЬ БЫЛО НЕЧЕМ.
   Поле 12.10.2026: на «/» style.sndcdn.com отдаёт завершённый 403 с телом 243
   байта, api-v2.soundcloud.com — 401 с пустым телом (то же и с VPS: так
   отвечает сам сервер, это не блок), а НАСТОЯЩИЙ ресурс того же имени
   режется — /css/soehne-*.css: 301328 байт с VPS против 15985 с линии.

   РАЗМЕР РЕСУРСА ЗАРАНЕЕ НЕИЗВЕСТЕН: подсказка даёт только путь, поэтому
   «обещает объём больше полосы» по ней заявить нельзя — объём выясняет само
   измерение. Условие повтора — не обещанный объём, а то, что мерить было
   нечем: ответ ЗАВЕРШЁН и меньше полосы, то есть про обрыв не сказал ничего.

   Имя подсказки обязано совпасть с предъявляемым SNI: адрес и имя у зонда
   свои, и чужой хост мы спросили бы не у того сервера; цель из подсказки не
   выдумывается. Путь проверяет тот же строгий d2k_resource_path_ok — только
   публичный .css, без запросов и токенов. Путь, который только что мерили,
   пропускаем: повторять его нечем. */
static int resource_retry_path(const d2k_ver_result *a, const char *sni,
                               const char *path, char *out, size_t cap) {
    if (!a || !sni || !sni[0] || !out || !cap) return 0;
    out[0] = '\0';
    size_t n = a->n_resources > D2K_RESOURCE_COUNT ? D2K_RESOURCE_COUNT : a->n_resources;
    for (size_t i = 0; i < n; i++) {
        const d2k_resource *r = &a->resources[i];
        if (!r->host[0] || strcasecmp(r->host, sni) != 0) { continue; }
        if (!d2k_resource_path_ok(r->path)) { continue; }
        if (path && !strcmp(path, r->path)) { continue; }
        if (strlen(r->path) >= cap) { continue; }
        snprintf(out, cap, "%s", r->path);
        return 1;
    }
    return 0;
}

/* ОТВЕТ НЕ НАЧАЛСЯ — МЕРИТЬ БЫЛО НЕЧЕМ (поле 17.10.2026, rua.gr, вход без
   ECH). TLS согласован, а на GET не пришло ни одного полного заголовка: с
   роутера так 2 замера из 5 подряд, остальные identity резались на ~23 КБ, и
   так же пустым приходил gzip-контроль сошедшейся пары. Об обрыве такой ответ
   не говорит ничего; один повтор того же вопроса по названной причине, не
   перебор. */
static d2k_ver_result rx_probe(d2k_vol_result *res, const char *ip, uint16_t port, const char *sni,
                               size_t hello_wire, int tls12, int encoding,
                               uint32_t mark, const char *path) {
    res->probes++;
    d2k_ver_result r = d2k_verify_probe_path_on(-1, ip, port, sni, 6000,
                                                  hello_wire, tls12, encoding, mark, path);
    /* Тот же шум — и ответ, вставший раньше полосы (поле 17.10.2026, LR-rx8-1:
       «HTTP 200, тело 4497/0, complete=0»): ни обрыва в полосе, ни отрицания. */
    int early = r.status >= 200 && r.status < 300 && !r.body_complete &&
                r.body_bytes < (uint64_t)D2K_VOL_MIN_KB * 1024;
    if ((r.status == 0 || early) && r.level == D2K_VER_HANDSHAKE && r.name_ok == 1 &&
        (r.negotiated_tls == 0x0303 || r.negotiated_tls == 0x0304) &&
        !r.local_limit && !d2k_volume_rx_partial(&r)) {
        d2k_verify_close(&r);
        nap_ms(RESPONSE_PROBE_GAP_MS);
        res->probes++;
        r = d2k_verify_probe_path_on(-1, ip, port, sni, 6000,
                                     hello_wire, tls12, encoding, mark, path);
    }
    return r;
}

/* Входящее измерение — другой вопрос, чем лестница исходящих HEAD выше.
   Ищем воспроизводимую асимметрию: два identity-ответа с одним framing видом
   обрываются на близком объёме, а gzip-представление той же страницы доходит
   до конца. Chunked ответы допустимы: у них полного размера заранее нет.
   Ответ без Content-Length и без chunked framing не классифицируем — там
   локальный timeout нельзя отличить от конца/медленной отдачи. Все сокеты
   помечены measure_mark и не проходят через пробуемый план.

   Возвращает 1, только если мерить было нечем (ответ завершён и меньше
   полосы) И тот же ответ назвал другой публичный путь этого имени: он
   копируется в retry. Повтором распоряжается probe_response_volume. */
static int measure_response_volume(d2k_vol_result *res, const char *ip,
                                   uint16_t port, const char *sni, int tls12,
                                   size_t hello_wire, uint32_t mark, const char *path,
                                   char *retry, size_t retry_cap) {
    if (!res || !ip || !sni || !sni[0] || port == 80) { return 0; }
    d2k_ver_result a = rx_probe(res, ip, port, sni, hello_wire, tls12, 0, mark, path);
    res->rx_tls_unavailable = a.level == D2K_VER_TRANSPORT && a.status == 0;
    if (a.body_complete && a.status >= 200 && a.status < 300 &&
        a.http_outcome != D2K_HTTP_BLOCKED && a.http_outcome != D2K_HTTP_LEGAL_DENIAL) {
        res->rx_direct_complete = a.level == D2K_VER_APPLICATION;
        memcpy(res->resources, a.resources, sizeof res->resources);
        res->n_resources = a.n_resources;
    }
    snprintf(res->rx_reason, sizeof res->rx_reason,
             "identity-1 HTTP %d, тело %llu/%llu, complete=%d, TLS=%04x wire=%llu missing=%u: %.60s",
             a.status, (unsigned long long)a.body_bytes,
             (unsigned long long)a.body_expected, a.body_complete, a.negotiated_tls,
             (unsigned long long)a.rx_tls_wire_bytes, a.rx_tls_record_missing, a.reason);
    if (!d2k_volume_rx_partial(&a)) {
        /* ЗАВЕРШЁННЫЙ ОТВЕТ МЕНЬШЕ ПОЛОСЫ — БЮДЖЕТ НЕ ПРОВЕРЕН. Отличаем
           «обрыв не воспроизвёлся» от «мерить было нечем»: ответ дошёл до
           конца, но до D2K_VOL_MIN_KB ему не хватило объёма, поэтому про
           обрыв он не говорит ничего. Страница отказа доступа (401/403) и
           просто короткий документ попадают сюда одинаково. */
        if (a.status > 0 && a.body_complete &&
            a.body_bytes < (uint64_t)D2K_VOL_MIN_KB * 1024) {
            res->rx_short = 1;
            res->rx_short_bytes = a.body_bytes;
            if (retry && retry_cap &&
                resource_retry_path(&a, sni, path, retry, retry_cap)) {
                d2k_verify_close(&a);
                return 1;
            }
        } else if ((a.status == 0 || !a.body_complete) &&
                   !res->rx_direct_complete && !res->rx_tls_unavailable && !a.local_limit) {
            /* ОТВЕТ НЕ НАЧАЛСЯ ИЛИ НЕ ДОШЁЛ ДО ПОЛНЫХ ЗАГОЛОВКОВ (поле 19.10.2026,
             * mailsuite.com): статус 0 или обрыв до заголовков при согласованном TLS.
             * Бюджет не проверен, и выдавать это за «проходит напрямую» нельзя. */
            res->rx_unmeasured = 1;
        }
        d2k_verify_close(&a);
        return 0;
    }
    if (rx_wire_partial(&a)) res->rx_partial_wire_bytes = a.rx_tls_wire_bytes;
    else res->rx_partial_bytes = a.body_bytes;
    nap_ms(RESPONSE_PROBE_GAP_MS);
    d2k_ver_result b = rx_probe(res, ip, port, sni, hello_wire, tls12, 0, mark, path);
    snprintf(res->rx_reason, sizeof res->rx_reason,
             "identity-1 partial=%llu/%llu TLS=%04x wire=%llu missing=%u; "
             "identity-2 HTTP %d body=%llu complete=%d TLS=%04x wire=%llu missing=%u: %.40s",
             (unsigned long long)a.body_bytes, (unsigned long long)a.body_expected,
             a.negotiated_tls, (unsigned long long)a.rx_tls_wire_bytes, a.rx_tls_record_missing,
             b.status, (unsigned long long)b.body_bytes, b.body_complete,
             b.negotiated_tls, (unsigned long long)b.rx_tls_wire_bytes, b.rx_tls_record_missing,
             b.reason);
    const char *settled_by_third = "";
    if (!d2k_volume_rx_pair_agrees(&a, &b)) {
        if (!d2k_volume_rx_needs_repeat(&a, &b)) {
            d2k_verify_close(&a);
            d2k_verify_close(&b);
            return 0;
        }
        /* Повтор дошёл до конца, пройдя полосу: измерения РАСХОДЯТСЯ. Судит
           третий identity-прогон того же домена — см. d2k_volume_rx_needs_repeat. */
        nap_ms(RESPONSE_PROBE_GAP_MS);
        d2k_ver_result c = rx_probe(res, ip, port, sni, hello_wire, tls12, 0, mark, path);
        int agreed = d2k_volume_rx_pair_agrees(&a, &c);
        snprintf(res->rx_reason, sizeof res->rx_reason,
                 "identity-1 partial=%llu wire=%llu; identity-2 HTTP %d body=%llu "
                 "дошёл до конца; identity-3 HTTP %d body=%llu wire=%llu missing=%u: "
                 "обрыв подтверждён=%d",
                 (unsigned long long)a.body_bytes,
                 (unsigned long long)a.rx_tls_wire_bytes, b.status,
                 (unsigned long long)b.body_bytes, c.status,
                 (unsigned long long)c.body_bytes,
                 (unsigned long long)c.rx_tls_wire_bytes,
                 c.rx_tls_record_missing, agreed);
        d2k_verify_close(&b);
        if (!agreed) {
            d2k_verify_close(&a);
            d2k_verify_close(&c);
            return 0;
        }
        b = c;
        /* Журнал обязан показывать, что пару решило ТРЕТЬЕ измерение, иначе
           строку gzip-шага не отличить от сошедшейся с первого раза пары. */
        settled_by_third = "; пару решил identity-3";
    }
    nap_ms(RESPONSE_PROBE_GAP_MS);
    d2k_ver_result gz = rx_probe(res, ip, port, sni, hello_wire, tls12, 1, mark, path);
    snprintf(res->rx_reason, sizeof res->rx_reason,
             "identity %llu/%llu (пакетов %u/%u); gzip HTTP %d, тело %llu, complete=%d, "
             "encoding=%d, пакетов %u; TLS RX wire=%llu/%llu/%llu missing=%u/%u/%u%s",
             (unsigned long long)a.body_bytes, (unsigned long long)b.body_bytes,
             a.data_packets, b.data_packets,
             gz.status, (unsigned long long)gz.body_bytes, gz.body_complete, gz.body_encoding,
             gz.data_packets, (unsigned long long)a.rx_tls_wire_bytes,
             (unsigned long long)b.rx_tls_wire_bytes, (unsigned long long)gz.rx_tls_wire_bytes,
             a.rx_tls_record_missing, b.rx_tls_record_missing, gz.rx_tls_record_missing,
             settled_by_third);
    (void)d2k_volume_rx_evidence(&a, &b, &gz, res);
    /* ПУТЬ ИЗМЕРЕНИЯ ИДЁТ НАВЕРХ ПОЛЕМ, А НЕ ТОЛЬКО СТРОКОЙ ЖУРНАЛА. Обрыв
       доказан на том пути, который спрашивал ЭТОТ замер (у повтора он свой —
       из подсказки): кандидата и следующий эпизод надо отправить туда же,
       иначе «/» того же хоста отдаст короткий 403 и подтвердить план объёмом
       будет нечем. Умолчательный «/» не называем — его знает вызывающий. */
    if (res->rx_cut && path && path[0]) {
        snprintf(res->measured_path, sizeof res->measured_path, "%s", path);
    }
    d2k_verify_close(&a);
    d2k_verify_close(&b);
    d2k_verify_close(&gz);
    return 0;
}

/* ОДИН ПОВТОР ПО НАЗВАННОЙ ПРИЧИНЕ: на первом пути мерить было нечем. Не
   лестница — повторное измерение само либо входит в полосу, либо честно
   возвращает тот же непроверенный бюджет; третий путь спрашивать не о чем,
   это был бы перебор вместо замера. */
static void probe_response_volume(d2k_vol_result *res, const char *ip,
                                  uint16_t port, const char *sni, int tls12,
                                  size_t hello_wire, uint32_t mark, const char *path) {
    /* TX outcome is final here; RX evidence may rewrite reason below. */
    snprintf(res->tx_reason, sizeof res->tx_reason, "%s", res->reason);
    char retry[sizeof ((d2k_resource *)0)->path];
    retry[0] = '\0';
    if (!measure_response_volume(res, ip, port, sni, tls12, hello_wire, mark, path,
                                 retry, sizeof retry)) { return; }
    uint64_t was = res->rx_short_bytes;
    res->rx_short = 0;
    res->rx_short_bytes = 0;
    res->rx_unmeasured = 0;
    nap_ms(RESPONSE_PROBE_GAP_MS);
    (void)measure_response_volume(res, ip, port, sni, tls12, hello_wire, mark, retry,
                                  NULL, 0);
    /* ПОВТОР НЕ ДОШЁЛ ДО TLS — БЮДЖЕТ ТАК И НЕ ПРОВЕРЕН. Непроверенный
       бюджет первого ответа остаётся в силе: он сказал правду о себе, а
       повтор не сказал ничего. Без этого один неудавшийся повтор отменял бы
       честный rx_short и возвращался ложным «обрыв не воспроизвёлся».
       Завершённый ответ повтора ВЫШЕ полосы — наоборот, настоящее
       отрицательное измерение: его не подменяем. */
    if ((res->rx_tls_unavailable || res->rx_unmeasured) && !res->rx_cut && !res->rx_short) {
        res->rx_short = 1;
        res->rx_short_bytes = was;
        res->rx_unmeasured = 0;
    }
    /* Журнал обязан называть путь повтора: иначе обрыв прочитают как обрыв
       на «/», которого там не было. Причина складывается в два приёма и с
       явными границами — целиком она в буфер не влезает (gcc ловит это как
       format-truncation, цель cross). */
    char lead[104], measured[sizeof res->rx_reason];
    snprintf(lead, sizeof lead, "повтор по %.40s (было %llu байт)",
             retry, (unsigned long long)was);
    snprintf(measured, sizeof measured, "%s", res->rx_reason);
    snprintf(res->rx_reason, sizeof res->rx_reason, "%.102s: %.150s", lead, measured);
}

static d2k_vol_result volume_probe_path(const char *ip, uint16_t port, const char *sni,
                                int plain, int tls12, size_t hello_wire,
                                uint32_t mark, const char *path);
d2k_vol_result d2k_volume_probe_path(const char *ip, uint16_t port, const char *sni,
                                int plain, int tls12, size_t hello_wire,
                                uint32_t mark, const char *path) {
    d2k_vol_result res = volume_probe_path(ip, port, sni, plain, tls12, hello_wire, mark, path);
    /* No RX measurement ran (plain HTTP, no address): reason is the TX outcome. */
    if (!res.tx_reason[0]) snprintf(res.tx_reason, sizeof res.tx_reason, "%s", res.reason);
    return res;
}
static d2k_vol_result volume_probe_path(const char *ip, uint16_t port, const char *sni,
                                int plain, int tls12, size_t hello_wire,
                                uint32_t mark, const char *path) {
    d2k_vol_result res;
    memset(&res, 0, sizeof res);
    res.verdict = D2K_VOL_UNREACHABLE;
    snprintf(res.reason, sizeof res.reason, "проба не начиналась");
    if (!ip || !ip[0]) {
        snprintf(res.reason, sizeof res.reason, "адрес цели не задан");
        return res;
    }

    int64_t started = now_ms();
    res.probes++;
    int fd = connect_bounded(ip, port, mark, res.reason, sizeof res.reason);
    if (fd < 0) { return res; }

    d2k_tls *tls = NULL;
    d2k_tls12 *tls_legacy = NULL;
    if (!plain) {
        char err[160];
        const char *name = (sni && sni[0]) ? sni : NULL;
        int handshake = tls12
            ? d2k_tls12_connect(fd, name, HANDSHAKE_MS, hello_wire,
                                &tls_legacy, err, sizeof err)
            : d2k_tls_connect(fd, name, HANDSHAKE_MS, hello_wire,
                              &tls, err, sizeof err);
        if (handshake != 0) {
            /* Причина обрезается по месту, а не тянет за собой размер буфера:
               «нет TLS: » плюс хвост — читателю нужна суть, а не полный текст
               чужой ошибки (gcc ловит это как format-truncation, цель cross). */
            snprintf(res.reason, sizeof res.reason, "нет TLS: %.140s", err);
            close(fd);
            /* TX handshake failure is not a result of the independent
               GET-body measurement, which uses the client's own context. */
            probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark, path);
            return res;
        }
    }
    res.rtt_ms = (int)(now_ms() - started);

    const char *host = (sni && sni[0]) ? sni : ip;
    char pad[D2K_VOL_CHUNK + 1];
    pad[D2K_VOL_CHUNK] = '\0';
    /* Отправленный объём — сумма байт запросов, действительно ушедших в
       соединение (открытый текст запроса; служебные байты записей TLS сюда
       не входят), а не номер ступени, умноженный на размер набивки. */
    uint64_t sent_bytes = 0;

    /* Пока RTT не измерен на самом запросе — ждём по потолку. */
    int read_timeout = READ_MAX_MS;

    for (int i = 0; i < D2K_VOL_STEPS; i++) {
        char req[D2K_VOL_CHUNK + 512];
        int n;
        if (i == 0) {
            n = snprintf(req, sizeof req,
                         "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                         "Connection: keep-alive\r\n\r\n", host);
        } else {
            /* Своя набивка каждому запросу: одинаковую коробка вправе схлопнуть
               как повтор (см. fill_pad). */
            fill_pad(pad, D2K_VOL_CHUNK);
            n = snprintf(req, sizeof req,
                         "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                         "Connection: keep-alive\r\nX-Pad: %s\r\n\r\n", host, pad);
        }
        if (n <= 0 || (size_t)n >= sizeof req) {
            snprintf(res.reason, sizeof res.reason, "запрос не поместился");
            if (tls) { d2k_tls_free(tls); }
            if (tls_legacy) { d2k_tls12_free(tls_legacy); }
            close(fd);
            if (!plain) {
                probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark, path);
            }
            return res;
        }

        int64_t req_start = now_ms();
        char err[160];
        int bad = 0;
        if (i > 0 && volume_peer_fin(fd) == 1) {
            /* Сервер закрыл соединение между ответами, не объявив этого:
               следующий запрос получил бы RST от самого сервера, и он
               выглядел бы как обрыв. Это его политика, а не объём. */
            snprintf(res.reason, sizeof res.reason,
                     "сервер закрыл соединение (FIN) после ответа %d", i);
            bad = 2;
        } else if (tls || tls_legacy) {
            int written = tls_legacy
                ? d2k_tls12_write(tls_legacy, (const uint8_t *)req, (size_t)n, err, sizeof err)
                : d2k_tls_write(tls, (const uint8_t *)req, (size_t)n, err, sizeof err);
            if (written != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                /* No complete request: the next response is not owed. How much
                   of it left is unknown, so it is not counted. */
                bad = 2;
            } else {
                sent_bytes += (uint64_t)n;
                int response = drain_head_tls(tls, tls_legacy, fd, read_timeout, err, sizeof err);
                if (response != 0) {
                    snprintf(res.reason, sizeof res.reason, "%s", err);
                    bad = response == -2 ? 2 : 1;
                }
            }
        } else {
            size_t sent_now = 0;
            int failed = volume_send_plain(fd, req, (size_t)n, read_timeout, &sent_now,
                                           err, sizeof err);
            sent_bytes += (uint64_t)sent_now;
            if (failed != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                bad = 2;
            } else {
                int response = drain_head_plain(fd, read_timeout, err, sizeof err);
                if (response != 0) {
                    snprintf(res.reason, sizeof res.reason, "%s", err);
                    bad = response == -2 ? 2 : 1;
                }
            }
        }
        if (bad) {
            res.at_kb = sent_bytes / 1024 > INT_MAX ? INT_MAX : (int)(sent_bytes / 1024);
            if (bad == 2) {
                /* Server policy, protocol change, an incomplete request and
                   local parser limits cannot establish an on-path volume cutoff. */
                res.verdict = D2K_VOL_SHORT;
            } else if (i == 0) {
                /* Умерли на первом же запросе — мишень недоступна, а не блок. */
                res.verdict = D2K_VOL_UNREACHABLE;
            } else if (sent_bytes >= (uint64_t)D2K_VOL_MIN_KB * 1024) {
                res.verdict = D2K_VOL_CUT;
            } else {
                res.verdict = D2K_VOL_SHORT;
            }
            if (tls) { d2k_tls_free(tls); }
            if (tls_legacy) { d2k_tls12_free(tls_legacy); }
            close(fd);
            if (!plain) {
                probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark, path);
            }
            return res;
        }
        if (i == 0) {
            /* RTT известен — дальше ждём втрое дольше него, в разумных
               границах: «нет ответа» распознаётся втрое быстрее прежнего. */
            read_timeout = clamp_ms((now_ms() - req_start) * 3, READ_MIN_MS, READ_MAX_MS);
        }
        nap_ms(CHUNK_DELAY_MS);
    }

    res.verdict = D2K_VOL_PASSED;
    res.at_kb = sent_bytes / 1024 > INT_MAX ? INT_MAX : (int)(sent_bytes / 1024);
    snprintf(res.reason, sizeof res.reason, "лестница пройдена целиком");
    if (tls) { d2k_tls_free(tls); }
    if (tls_legacy) { d2k_tls12_free(tls_legacy); }
    close(fd);
    if (!plain) {
        probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark, path);
    }
    return res;
}

d2k_vol_result d2k_volume_probe(const char *ip, uint16_t port, const char *sni,
    int plain, int tls12, size_t hello_wire, uint32_t mark) {
    return d2k_volume_probe_path(ip, port, sni, plain, tls12, hello_wire, mark, NULL);
}
