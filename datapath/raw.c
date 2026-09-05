/* raw.c — сырой сокет для отправки собственных пакетов. Только Linux. */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include "d2k_raw.h"

struct d2k_raw {
    int      fd;
    uint32_t limits;
    uint64_t sent;
    uint64_t errors;
};

static void say(char *err, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void say(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

d2k_raw *d2k_raw_open(uint32_t mark, char *err, size_t errcap) {
    d2k_raw *r = calloc(1, sizeof *r);
    if (!r) {
        say(err, errcap, "нет памяти");
        return NULL;
    }
    /* Пределы объявляются сразу и не зависят от успеха настроек: их задаёт
       сам способ отправки, а не наша конфигурация. */
    r->limits = D2K_RAW_CANT_IPID | D2K_RAW_CANT_IPSUM;

    r->fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (r->fd < 0) {
        say(err, errcap, "socket(SOCK_RAW): %s", strerror(errno));
        free(r);
        return NULL;
    }

    /* Для IPPROTO_RAW включено по умолчанию; ставим явно, чтобы намерение
       читалось в коде, а не выводилось из номера протокола. */
    int one = 1;
    if (setsockopt(r->fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof one) < 0) {
        say(err, errcap, "IP_HDRINCL: %s", strerror(errno));
        close(r->fd);
        free(r);
        return NULL;
    }

    if (mark != 0) {
#ifdef SO_MARK
        if (setsockopt(r->fd, SOL_SOCKET, SO_MARK, &mark, sizeof mark) < 0) {
            /* Отказ здесь смертелен, и это не перестраховка: §5.5 говорит, что
               неудача установки метки — явное снижение достоверности, если
               исключение обхода не гарантировано. Работать без метки, делая
               вид, что собственные пакеты не вернутся в свою же очередь,
               нельзя. */
            say(err, errcap, "SO_MARK=%u: %s", mark, strerror(errno));
            close(r->fd);
            free(r);
            return NULL;
        }
#else
        say(err, errcap, "SO_MARK не поддержан сборкой, а метка запрошена");
        close(r->fd);
        free(r);
        return NULL;
#endif
    }

    return r;
}

void d2k_raw_close(d2k_raw *r) {
    if (!r) {
        return;
    }
    if (r->fd >= 0) {
        close(r->fd);
    }
    free(r);
}

uint32_t d2k_raw_limits(const d2k_raw *r) {
    return r ? r->limits : (D2K_RAW_CANT_IPID | D2K_RAW_CANT_IPSUM);
}

int d2k_raw_send(d2k_raw *r, const uint8_t *pkt, size_t len,
                 char *err, size_t errcap) {
    if (!r || !pkt || len < 20) {
        say(err, errcap, "нечего отправлять");
        return -1;
    }
    if ((pkt[0] >> 4) != 4) {
        say(err, errcap, "сырой сокет умеет только IPv4");
        return -1;
    }

    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = 0;                      /* для сырого сокета не используется */
    memcpy(&to.sin_addr.s_addr, pkt + 16, 4);

    for (;;) {
        ssize_t n = sendto(r->fd, pkt, len, 0, (struct sockaddr *)&to, sizeof to);
        if (n >= 0) {
            if ((size_t)n != len) {
                r->errors++;
                say(err, errcap, "отправлено %zd из %zu байт", n, len);
                return -1;
            }
            r->sent++;
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        r->errors++;
        say(err, errcap, "sendto: %s", strerror(errno));
        return -1;
    }
}

uint64_t d2k_raw_sent(const d2k_raw *r) {
    return r ? r->sent : 0;
}

uint64_t d2k_raw_errors(const d2k_raw *r) {
    return r ? r->errors : 0;
}
