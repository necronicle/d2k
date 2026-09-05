/* nfq.c — системные вызовы вокруг очереди. Только Linux.
 *
 * Отличие от замерщика этапа 0: настройка очереди идёт с NLM_F_ACK и ответ
 * ЧИТАЕТСЯ. Замерщик на Go молча копил пакеты, потому что посылал неверный тип
 * атрибута, получал EINVAL и не смотрел на него. «Отправили» и «ядро приняло»
 * — разные события, и различать их обязательно.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <poll.h>

#include "d2k_nfq.h"
#include "d2k_nl.h"

struct d2k_nfq {
    int      fd;
    uint16_t queue;
    uint32_t seq;
    uint64_t lost;
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

static int nl_write(int fd, const uint8_t *msg, size_t len) {
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    for (;;) {
        ssize_t n = sendto(fd, msg, len, 0, (struct sockaddr *)&sa, sizeof sa);
        if (n >= 0) {
            return (size_t)n == len ? 0 : -1;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
}

/* Ждёт подтверждения на запрос с NLM_F_ACK.
 * 0 — ядро приняло, -1 — отвергло либо ответа нет. */
static int await_ack(int fd, uint32_t seq, char *err, size_t errcap) {
    uint8_t buf[4096];
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;

    for (int tries = 0; tries < 8; tries++) {
        int pr = poll(&pfd, 1, 1000);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            say(err, errcap, "poll при ожидании подтверждения: %s", strerror(errno));
            return -1;
        }
        if (pr == 0) {
            say(err, errcap, "ядро не подтвердило настройку очереди за секунду");
            return -1;
        }
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            say(err, errcap, "recv при ожидании подтверждения: %s", strerror(errno));
            return -1;
        }

        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_iter_init(&it, buf, (size_t)n);
        while (d2k_nl_next(&it, &m)) {
            int32_t e = 0;
            if (d2k_nl_errno(&m, &e) != 0) {
                continue;   /* не наш ответ — ждём дальше */
            }
            if (m.seq != seq) {
                continue;
            }
            if (e == 0) {
                return 0;
            }
            say(err, errcap, "ядро отвергло настройку очереди: %s", strerror(-e));
            return -1;
        }
    }
    say(err, errcap, "подтверждение настройки очереди не пришло");
    return -1;
}

static int send_and_ack(d2k_nfq *q, const uint8_t *msg, size_t len, uint32_t seq,
                        char *err, size_t errcap) {
    if (len == 0) {
        say(err, errcap, "сообщение настройки не собралось");
        return -1;
    }
    if (nl_write(q->fd, msg, len) != 0) {
        say(err, errcap, "отправка настройки: %s", strerror(errno));
        return -1;
    }
    return await_ack(q->fd, seq, err, errcap);
}

d2k_nfq *d2k_nfq_open(const d2k_nfq_cfg *cfg, char *err, size_t errcap) {
    if (!cfg) {
        say(err, errcap, "нет настроек очереди");
        return NULL;
    }
    d2k_nfq *q = calloc(1, sizeof *q);
    if (!q) {
        say(err, errcap, "нет памяти");
        return NULL;
    }
    q->queue = cfg->queue;
    q->seq = 1;

    q->fd = socket(AF_NETLINK, SOCK_RAW, D2K_NETLINK_NETFILTER);
    if (q->fd < 0) {
        say(err, errcap, "socket(NETLINK_NETFILTER): %s", strerror(errno));
        free(q);
        return NULL;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    /* nl_pid = 0: адрес назначает ядро. Свой номер выбирать нельзя — на
       роутере рядом живёт nfqws соседнего продукта, и совпадение адреса
       развело бы два процесса по одному сокету. */
    if (bind(q->fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        say(err, errcap, "bind netlink: %s", strerror(errno));
        close(q->fd);
        free(q);
        return NULL;
    }

    if (cfg->rcvbuf > 0) {
        int v = cfg->rcvbuf;
        /* Неудача не смертельна: маленький буфер означает больше потерь, а не
           неработающую очередь. Потери всё равно видны через ENOBUFS. */
        (void)setsockopt(q->fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
    }

    uint8_t msg[256];
    uint32_t seq;
    size_t n;

    /* PF_BIND намеренно не посылается: с ядра 3.8 команда — пустышка, а
       целевое ядро 4.9. Замерщик этапа 0 обходился без неё на настоящем
       устройстве. */

    seq = q->seq++;
    n = d2k_nl_cfg_cmd(msg, sizeof msg, cfg->queue, seq,
                       D2K_NFQNL_CFG_CMD_BIND, AF_INET);
    if (send_and_ack(q, msg, n, seq, err, errcap) != 0) {
        close(q->fd);
        free(q);
        return NULL;
    }

    uint32_t flags = cfg->fail_open ? D2K_NFQA_CFG_F_FAIL_OPEN : 0;
    /* Маска перечисляет флаги, которыми мы вообще распоряжаемся. GSO указан в
       маске и НЕ указан в значении: он должен быть выключен явно. С GSO ядро
       отдаёт склеенный суперпакет, а это не то, что уйдёт на провод, — резать
       его по границам сегментов мы не умеем и делать вид не будем. */
    uint32_t mask = D2K_NFQA_CFG_F_FAIL_OPEN | D2K_NFQA_CFG_F_GSO;

    seq = q->seq++;
    n = d2k_nl_cfg_params(msg, sizeof msg, cfg->queue, seq,
                          cfg->copy_range, D2K_NFQNL_COPY_PACKET,
                          cfg->maxlen, flags, mask);
    if (send_and_ack(q, msg, n, seq, err, errcap) != 0) {
        close(q->fd);
        free(q);
        return NULL;
    }

    return q;
}

void d2k_nfq_close(d2k_nfq *q) {
    if (!q) {
        return;
    }
    if (q->fd >= 0) {
        uint8_t msg[256];
        size_t n = d2k_nl_cfg_cmd(msg, sizeof msg, q->queue, q->seq++,
                                  D2K_NFQNL_CFG_CMD_UNBIND, AF_INET);
        /* Ответ не ждём: мы закрываемся, и закрытие сокета отвяжет очередь в
           любом случае. Отвязка послана из вежливости к ядру. */
        if (n) {
            (void)nl_write(q->fd, msg, n);
        }
        close(q->fd);
    }
    free(q);
}

int d2k_nfq_fd(const d2k_nfq *q) {
    return q ? q->fd : -1;
}

ssize_t d2k_nfq_recv(d2k_nfq *q, uint8_t *buf, size_t cap, char *err, size_t errcap) {
    if (!q || !buf || cap == 0) {
        say(err, errcap, "нет буфера для чтения");
        return -1;
    }
    ssize_t n = recv(q->fd, buf, cap, 0);
    if (n >= 0) {
        return n;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return 0;
    }
    if (errno == ENOBUFS) {
        /* Ядро не успело отдать — сообщения потеряны. Сокет жив, читать
           дальше можно, но часть трафика мы не видели. */
        q->lost++;
        return -2;
    }
    say(err, errcap, "recv из очереди: %s", strerror(errno));
    return -1;
}

int d2k_nfq_verdict(d2k_nfq *q, uint32_t pkt_id, uint32_t verdict,
                    char *err, size_t errcap) {
    if (!q) {
        return -1;
    }
    uint8_t msg[64];
    size_t n = d2k_nl_verdict(msg, sizeof msg, q->queue, q->seq++, pkt_id, verdict);
    if (n == 0) {
        say(err, errcap, "вердикт не собрался");
        return -1;
    }
    if (nl_write(q->fd, msg, n) != 0) {
        say(err, errcap, "отправка вердикта: %s", strerror(errno));
        return -1;
    }
    return 0;
}

uint64_t d2k_nfq_lost(const d2k_nfq *q) {
    return q ? q->lost : 0;
}
