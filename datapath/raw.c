/* raw.c — сырой сокет для отправки собственных пакетов. Только Linux. */

/* struct ifreq и флаги IFF_* — часть BSD-наследия, и под -std=c99 glibc их
   прячет: строгий ANSI-режим определяет __STRICT_ANSI__ и выключает
   _DEFAULT_SOURCE, которого в обычной сборке хватает по умолчанию. Объявляем
   его сами, иначе чужой компилятор в гейте (cc -std=c99) видит net/if.h без
   ifreq и IFF_UP. Ставится ДО первого include: после первого включения
   features.h переключать набор поздно. */
#define _DEFAULT_SOURCE 1

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "d2k_raw.h"

struct d2k_raw {
    int      fd;
    uint32_t limits;
    size_t   maxlen;
    uint64_t sent;
    uint64_t errors;
};

/* MTU одного интерфейса по имени. 0 — не узнали.
 *
 * Отдельным сокетом AF_INET/SOCK_DGRAM, а не сырым: ioctl SIOCGIFMTU не
 * требует привилегий, и заводить его на сыром сокете значило бы связать
 * чтение MTU с успехом открытия сырого — а оно нужно и тогда, когда сырой
 * не открылся. */
static unsigned if_mtu(const char *name) {
    if (!name || !*name) {
        return 0;
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        return 0;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", name);
    unsigned mtu = 0;
    if (ioctl(s, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu > 0) {
        mtu = (unsigned)ifr.ifr_mtu;
    }
    close(s);
    return mtu;
}

/* Предел длины посылки: MTU названного интерфейса, а при NULL — НАИМЕНЬШИЙ
 * MTU среди поднятых, кроме loopback. Обоснование выбора и его цена — в
 * шапке d2k_raw_open (d2k_raw.h). Не узнали ничего — D2K_RAW_MTU_FALLBACK:
 * отправлять вслепую нельзя, иначе вернётся ровно та картина, ради которой
 * предел и заведён.
 *
 * Loopback исключён намеренно: его MTU 65536 не наименьший, но интерфейс с
 * MTU 65536 в выборке «наименьшего» безвреден, а вот стенд, гоняющий всё
 * через петлю, получил бы предел, которого на линии нет. */
static size_t pick_maxlen(const char *ifname) {
    if (ifname && *ifname) {
        unsigned m = if_mtu(ifname);
        return m ? (size_t)m : (size_t)D2K_RAW_MTU_FALLBACK;
    }
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0 || !list) {
        return (size_t)D2K_RAW_MTU_FALLBACK;
    }
    unsigned best = 0;
    for (struct ifaddrs *a = list; a; a = a->ifa_next) {
        if (!a->ifa_name) {
            continue;
        }
        if (!(a->ifa_flags & IFF_UP) || (a->ifa_flags & IFF_LOOPBACK)) {
            continue;
        }
        unsigned m = if_mtu(a->ifa_name);
        if (m > 0 && (best == 0 || m < best)) {
            best = m;
        }
    }
    freeifaddrs(list);
    return best ? (size_t)best : (size_t)D2K_RAW_MTU_FALLBACK;
}

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

d2k_raw *d2k_raw_open(uint32_t mark, const char *ifname, char *err, size_t errcap) {
    d2k_raw *r = calloc(1, sizeof *r);
    if (!r) {
        say(err, errcap, "нет памяти");
        return NULL;
    }
    /* Пределы объявляются сразу и не зависят от успеха настроек: их задаёт
       сам способ отправки, а не наша конфигурация. */
    r->limits = D2K_RAW_CANT_IPID | D2K_RAW_CANT_IPSUM;
    /* Один раз при старте — см. шапку в d2k_raw.h про цену этого выбора. */
    r->maxlen = pick_maxlen(ifname);

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

size_t d2k_raw_maxlen(const d2k_raw *r) {
    /* Никогда не ноль: ноль означал бы «предел не объявлен», и вызывающий
       перестал бы проверять длину вовсе. */
    return (r && r->maxlen) ? r->maxlen : (size_t)D2K_RAW_MTU_FALLBACK;
}

int d2k_raw_send(d2k_raw *r, const uint8_t *pkt, size_t len,
                 char *err, size_t errcap) {
    if (!r || !pkt || len < 20) {
        say(err, errcap, "нечего отправлять");
        errno = EINVAL;
        return -1;
    }
    if ((pkt[0] >> 4) != 4) {
        say(err, errcap, "сырой сокет умеет только IPv4");
        errno = EAFNOSUPPORT;
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
                errno = EIO;
                return -1;
            }
            r->sent++;
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        int failure = errno;
        r->errors++;
        if (failure == EMSGSIZE && len > D2K_RAW_MTU_FLOOR) {
            /* ПРЕДЕЛ ПРИШЁЛ ЗАМЕРОМ, А НЕ ИЗ КОНФИГУРАЦИИ.
               Объявленный предел взят с интерфейса при старте, а настоящий
               принадлежит МАРШРУТУ и может быть меньше: туннель, PPPoE,
               PMTU по пути. Ядро только что сказало ровно одно достоверное
               число — эта длина не проходит. Опускаем предел под неё, чтобы
               следующий такой план отвергался ЗАРАНЕЕ (d2k_plan_fits), а не
               упирался в ядро посреди исполнения.
               Пол нужен, чтобы единичный сбой не сделал предел бессмысленно
               маленьким и не отключил весь обход: ниже минимального MTU IPv4
               спускаться некуда. Обратно предел сам не растёт — для этого
               нужен новый замер, а не оптимизм. */
            size_t lowered = len - 1;
            if (lowered < r->maxlen) {
                r->maxlen = lowered;
                say(err, errcap,
                    "sendto: %s; предел длины опущен до %zu по ответу ядра",
                    strerror(failure), r->maxlen);
                errno = failure;
                return -1;
            }
        }
        say(err, errcap, "sendto: %s", strerror(failure));
        errno = failure;
        return -1;
    }
}

uint64_t d2k_raw_sent(const d2k_raw *r) {
    return r ? r->sent : 0;
}

uint64_t d2k_raw_errors(const d2k_raw *r) {
    return r ? r->errors : 0;
}
