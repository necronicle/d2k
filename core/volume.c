/* volume.c — проба на блокировку по объёму. См. d2k_volume.h.
 *
 * ЛЕСТНИЦА ИСХОДЯЩЕГО ОБЪЁМА: десять запросов по одному соединению, со второго
 * — с мусорным заголовком. Мусор в заголовке остаётся единственным способом
 * накачать соединение СВОИМ объёмом, не завися от того, что отдаёт мишень.
 *
 * Направление накачки здесь одно — исходящее. У Go-стороны есть и входящее
 * (PumpIn: один запрос и чтение тела), и оно там нужно, чтобы выяснить, за
 * каким направлением коробка вообще следит. Здесь его нет НАМЕРЕННО, и это
 * названо, а не забыто: входящее направление меряет ещё и мишень (её скорость,
 * её длину документа, её готовность отдать сорок килобайт), а планировщику
 * нужен ответ про линию. Понадобится — добавится отдельным параметром, а не
 * тихо подмешается в этот.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"   /* d2k_mark_hook — метка ставится тем же путём, что везде */
#include "d2k_tls13.h"
#include "d2k_volume.h"

/* Восемь секунд на подключение и на рукопожатие — из пробы донора
   (z2k-detect/internal/tcp16), замер на этой линии. */
#define CONNECT_MS   8000
#define HANDSHAKE_MS 8000

/* Пауза между запросами. Без неё десять запросов уходят одной очередью, и
   коробка видит поток иначе, чем видит его браузер: вердикт плывёт. */
#define CHUNK_DELAY_MS 50

/* Ожидание ответа считается от ИЗМЕРЕННОГО RTT, а не берётся с потолка. Живой
   ответ приходит за один RTT; «нет ответа» — это неподходящее имя, на котором
   коробка молчит, и с фиксированным потолком каждый мимо-кандидат стоил бы
   полные секунды. Нижняя граница защищает от слишком оптимистичного замера на
   первом пакете, верхняя — от линии с большим RTT. */
#define READ_MIN_MS  1500
#define READ_MAX_MS  12000

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
    int fd = socket(AF_INET, SOCK_STREAM, 0);
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

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        snprintf(reason, cap, "адрес \"%s\" не разбирается", ip);
        close(fd);
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        snprintf(reason, cap, "неблокирующий режим: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
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

/* Читает заголовки ответа до пустой строки. 0 — прочитано, -1 — обрыв. */
static int drain_head_tls(d2k_tls *t, int wait_ms, char *reason, size_t cap) {
    char line[4096];
    size_t n = 0;
    int seen_cr = 0;
    for (;;) {
        uint8_t c;
        long r = d2k_tls_read(t, &c, 1, wait_ms, reason, cap);
        if (r <= 0) {
            if (r == 0) { snprintf(reason, cap, "соединение закрыто"); }
            return -1;
        }
        if (c == '\n') {
            if (n == 0 || (n == 1 && seen_cr)) { return 0; } /* пустая строка */
            n = 0;
            seen_cr = 0;
            continue;
        }
        seen_cr = (c == '\r');
        if (n + 1 < sizeof line) { line[n++] = (char)c; }
    }
}

static int drain_head_plain(int fd, int wait_ms, char *reason, size_t cap) {
    size_t n = 0;
    int seen_cr = 0;
    int64_t deadline = now_ms() + wait_ms;
    for (;;) {
        if (now_ms() >= deadline) { snprintf(reason, cap, "ответа нет"); return -1; }
        struct pollfd p;
        p.fd = fd; p.events = POLLIN; p.revents = 0;
        int pr = poll(&p, 1, (int)(deadline - now_ms()));
        if (pr <= 0) { snprintf(reason, cap, "ответа нет"); return -1; }
        uint8_t c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r <= 0) {
            snprintf(reason, cap, r == 0 ? "соединение закрыто" : "чтение: %s", strerror(errno));
            return -1;
        }
        if (c == '\n') {
            if (n == 0 || (n == 1 && seen_cr)) { return 0; }
            n = 0; seen_cr = 0;
            continue;
        }
        seen_cr = (c == '\r');
        n++;
    }
}

d2k_vol_result d2k_volume_probe(const char *ip, uint16_t port, const char *sni,
                                int plain, uint32_t mark) {
    d2k_vol_result res;
    memset(&res, 0, sizeof res);
    res.verdict = D2K_VOL_UNREACHABLE;
    snprintf(res.reason, sizeof res.reason, "проба не начиналась");
    if (!ip || !ip[0]) {
        snprintf(res.reason, sizeof res.reason, "адрес цели не задан");
        return res;
    }

    int64_t started = now_ms();
    int fd = connect_bounded(ip, port, mark, res.reason, sizeof res.reason);
    if (fd < 0) { return res; }

    d2k_tls *tls = NULL;
    if (!plain) {
        char err[160];
        if (d2k_tls_connect(fd, (sni && sni[0]) ? sni : NULL, HANDSHAKE_MS,
                            &tls, err, sizeof err) != 0) {
            /* Причина обрезается по месту, а не тянет за собой размер буфера:
               «нет TLS: » плюс хвост — читателю нужна суть, а не полный текст
               чужой ошибки (gcc ловит это как format-truncation, цель cross). */
            snprintf(res.reason, sizeof res.reason, "нет TLS: %.140s", err);
            close(fd);
            return res;
        }
    }
    res.rtt_ms = (int)(now_ms() - started);

    const char *host = (sni && sni[0]) ? sni : ip;
    static char pad[D2K_VOL_CHUNK + 1];
    fill_pad(pad, D2K_VOL_CHUNK);
    pad[D2K_VOL_CHUNK] = '\0';

    /* Пока RTT не измерен на самом запросе — ждём по потолку. */
    int read_timeout = READ_MAX_MS;

    for (int i = 0; i < D2K_VOL_STEPS; i++) {
        static char req[D2K_VOL_CHUNK + 512];
        int n;
        if (i == 0) {
            n = snprintf(req, sizeof req,
                         "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                         "Connection: keep-alive\r\n\r\n", host);
        } else {
            n = snprintf(req, sizeof req,
                         "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                         "Connection: keep-alive\r\nX-Pad: %s\r\n\r\n", host, pad);
        }
        if (n <= 0) { break; }

        int sent_kb = i * D2K_VOL_CHUNK / 1024;
        int64_t req_start = now_ms();
        char err[160];
        int bad = 0;
        if (tls) {
            if (d2k_tls_write(tls, (const uint8_t *)req, (size_t)n, err, sizeof err) != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                bad = 1;
            } else if (drain_head_tls(tls, read_timeout, err, sizeof err) != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                bad = 1;
            }
        } else {
            ssize_t w = send(fd, req, (size_t)n, 0);
            if (w != n) {
                snprintf(res.reason, sizeof res.reason, "запрос не ушёл: %s", strerror(errno));
                bad = 1;
            } else if (drain_head_plain(fd, read_timeout, err, sizeof err) != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                bad = 1;
            }
        }
        if (bad) {
            res.at_kb = sent_kb;
            if (i == 0) {
                /* Умерли на первом же запросе — мишень недоступна, а не блок. */
                res.verdict = D2K_VOL_UNREACHABLE;
            } else if (sent_kb >= D2K_VOL_MIN_KB) {
                res.verdict = D2K_VOL_CUT;
            } else {
                res.verdict = D2K_VOL_SHORT;
            }
            if (tls) { d2k_tls_free(tls); }
            close(fd);
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
    res.at_kb = D2K_VOL_STEPS * D2K_VOL_CHUNK / 1024;
    snprintf(res.reason, sizeof res.reason, "лестница пройдена целиком");
    if (tls) { d2k_tls_free(tls); }
    close(fd);
    return res;
}
