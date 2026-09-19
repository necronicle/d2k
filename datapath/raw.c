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

/* Сколько маршрутов помним. Шестнадцать — не «разумное число», а следствие
 * того, что здесь кэшируется: предел ОДНОГО направления, и направлений у
 * домашнего роутера ровно столько, сколько провайдеров и туннелей, то есть
 * единицы. Кольцо вытесняет старое, потому что промах стоит трёх системных
 * вызовов без единого пакета, а переполнение не должно отказывать. */
#define ROUTE_CACHE 16

typedef struct {
    uint8_t ip[4];
    size_t  mtu;    /* 0 — ячейка пуста */
} route_entry;

struct d2k_raw {
    int      fd;
    int      fragment_fd;
    uint32_t limits;
    size_t   maxlen;
    uint64_t sent;
    uint64_t errors;
    uint32_t mark;
    int      maxlen_declared;  /* предел назван оператором (--iface), а не угадан */
    route_entry route[ROUTE_CACHE];
    size_t   route_next;
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

/* MTU МАРШРУТА к адресу, а не интерфейса. 0 — не узнали.
 *
 * Почему это вообще нужно. Наименьший MTU среди поднятых интерфейсов —
 * оценка ЗАНИЖЕННАЯ и общая на все направления сразу: поднявшийся туннель с
 * MTU 1280 опустит предел для трафика, который через него не идёт, а маршрут
 * с PMTU меньше любого локального интерфейса не опустит его вовсе — и
 * упрётся в ядро уже на отправке (EMSGSIZE), то есть ПОСРЕДИ исполнения
 * плана.
 *
 * Почему это не противоречит прежнему решению (шапка d2k_raw.h). Там
 * отвергнут запрос маршрута НА ПАКЕТНОМ ПУТИ — ради числа, меняющегося раз в
 * жизни соединения. Здесь запрос идёт РАЗ НА НАПРАВЛЕНИЕ и кладётся в кольцо;
 * на пакетном пути остаётся сравнение чисел.
 *
 * Пакетов не отправляется ни одного: connect на UDP — местный поиск маршрута,
 * а IP_MTU отдаёт то, что ядро о нём знает, включая свежий PMTU. Метка
 * ставится та же, что и на исходящих: сокет ничего не шлёт, но правило
 * firewall может смотреть и на создание — пусть видит своё.
 *
 * Порт 443 не значит ничего: у UDP connect не спрашивает согласия адресата, а
 * маршрут от порта не зависит. Ноль там был бы отвергнут ядром как
 * недопустимый адресат. */
static size_t route_mtu(uint32_t mark, const uint8_t dst[4]) {
#ifdef IP_MTU
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { return 0; }
#ifdef SO_MARK
    if (mark) { (void)setsockopt(s, SOL_SOCKET, SO_MARK, &mark, sizeof mark); }
#else
    (void)mark;
#endif
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(443);
    memcpy(&to.sin_addr.s_addr, dst, 4);
    size_t got = 0;
    if (connect(s, (struct sockaddr *)&to, sizeof to) == 0) {
        int mtu = 0;
        socklen_t sl = sizeof mtu;
        if (getsockopt(s, IPPROTO_IP, IP_MTU, &mtu, &sl) == 0 && mtu > 0) {
            got = (size_t)mtu;
        }
    }
    close(s);
    return got;
#else
    (void)mark; (void)dst;
    return 0;   /* нет IP_MTU — нет и ответа; врать нечем */
#endif
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
    r->fragment_fd = -1;
    /* Один раз при старте — см. шапку в d2k_raw.h про цену этого выбора. */
    r->maxlen = pick_maxlen(ifname);
    r->mark = mark;
    /* НАЗВАННЫЙ предел и УГАДАННЫЙ — разные вещи, и маршрут разрешено
       противопоставлять только второму. Оператор, указавший интерфейс,
       ОБЪЯВИЛ предел; перепрыгнуть его ответом маршрута значило бы сделать
       флаг рекомендацией. Наименьший MTU среди поднятых — не объявление, а
       оценка: она ошибается в обе стороны (туннель к другой цели опускает
       предел всем; маршрут с меньшим PMTU не опускает никому), и уточнять её
       маршрутом не только можно, но и нужно. */
    r->maxlen_declared = (ifname && *ifname) ? 1 : 0;

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
    if (r->fragment_fd >= 0) close(r->fragment_fd);
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

/* Ответ маршрута против общего предела: см. maxlen_declared выше. */
static size_t blend(const d2k_raw *r, size_t route, size_t cap_all) {
    if (r->maxlen_declared) { return route < cap_all ? route : cap_all; }
    return route;
}

size_t d2k_raw_route_maxlen(d2k_raw *r, const uint8_t dst[4]) {
    size_t cap_all = d2k_raw_maxlen(r);
    if (!r || !dst) { return cap_all; }
    for (size_t i = 0; i < ROUTE_CACHE; i++) {
        if (r->route[i].mtu && memcmp(r->route[i].ip, dst, 4) == 0) {
            return blend(r, r->route[i].mtu, cap_all);
        }
    }
    size_t m = route_mtu(r->mark, dst);
    if (m < (size_t)D2K_RAW_MTU_FLOOR) {
        /* Ответа нет или он бессмысленно мал. Запоминать такое нельзя: пустая
           ячейка честнее выдуманного числа, а ниже минимума IPv4 маршрутов не
           бывает. Общий предел остаётся в силе. */
        return cap_all;
    }
    route_entry *e = &r->route[r->route_next % ROUTE_CACHE];
    r->route_next++;
    memcpy(e->ip, dst, 4);
    e->mtu = m;
    return blend(r, m, cap_all);
}

int d2k_raw_prepare(d2k_raw *r, const uint8_t *pkt, size_t len,
                    char *err, size_t errcap) {
    if (!r || !pkt || len<20) {errno=EINVAL;return -1;}
    if (!((pkt[6]&0x3f) || pkt[7])) return 0;
    if (pkt[0]!=0x45 || pkt[9]!=17 || !(pkt[4] || pkt[5])) {
        say(err,errcap,"неподдержанный контекст IP-фрагмента");errno=EINVAL;return -1;
    }
    if (r->fragment_fd>=0) return 0;
    /* Ordinary packets must keep normal conntrack/NAT. A separate socket
       prevents defrag from undoing the measured order/overlaps. Fragment
       addresses/UDP checksum were translated from the client's tuple by
       session.c. Never fall back to the ordinary socket on failure. */
    int fd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW),one=1;
    if(fd<0) {say(err,errcap,"fragment socket: %s",strerror(errno));return -1;}
    if(setsockopt(fd,IPPROTO_IP,IP_HDRINCL,&one,sizeof one)<0) goto bad;
#ifdef IP_NODEFRAG
    if(setsockopt(fd,IPPROTO_IP,IP_NODEFRAG,&one,sizeof one)<0) goto bad;
#else
    errno=ENOPROTOOPT;goto bad;
#endif
    if(r->mark) {
#ifdef SO_MARK
        if(setsockopt(fd,SOL_SOCKET,SO_MARK,&r->mark,sizeof r->mark)<0) goto bad;
#else
        errno=ENOPROTOOPT;goto bad;
#endif
    }
    r->fragment_fd=fd;return 0;
bad: {
    int saved=errno;close(fd);errno=saved;
    say(err,errcap,"fragment socket setup: %s",strerror(errno));return -1;
    }
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
    if(d2k_raw_prepare(r,pkt,len,err,errcap)<0) {r->errors++;return -1;}
    int fd=((pkt[6]&0x3f) || pkt[7])?r->fragment_fd:r->fd;

    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = 0;                      /* для сырого сокета не используется */
    memcpy(&to.sin_addr.s_addr, pkt + 16, 4);

    for (;;) {
        ssize_t n = sendto(fd, pkt, len, 0, (struct sockaddr *)&to, sizeof to);
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
            /* Ячейка маршрута опускается ВСЕГДА, даже если cap_all предел уже
               ниже: ядро сказало про ЭТО направление, и следующий план к нему
               обязан считаться с ответом, а не с общей оценкой. */
            for (size_t i = 0; i < ROUTE_CACHE; i++) {
                if (r->route[i].mtu && memcmp(r->route[i].ip, pkt + 16, 4) == 0) {
                    if (lowered < r->route[i].mtu) { r->route[i].mtu = lowered; }
                    break;
                }
            }
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
