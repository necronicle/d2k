/* ctl.c — управляющий сокет. Переносимый POSIX: AF_UNIX есть и на маке,
 * поэтому модуль проверяется настоящим сокетом, а не подделкой. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include "d2k_ctl.h"

#define HDR 6u

/* Кольцо исходящих — обоснование размера у поля out в struct d2k_ctl. */
#define D2K_CTL_OUT_RING 65536u

struct d2k_ctl {
    int      lfd;
    int      pfd;
    char     path[108];

    /* КОЛЬЦО ИСХОДЯЩИХ КАДРОВ, а не место под один.
     *
     * Здесь был буфер ровно на один недописанный кадр: пока хвост не ушёл,
     * каждое новое событие терялось. Оправдание было «очередь значит память
     * без предела» — оно неверно: у кольца фиксированного размера предел
     * ничуть не хуже, просто больше.
     *
     * Цена той экономии, замерено на роутере владельца 13.09.2026: датапат
     * потерял 173 уведомления за одно окно сводки, и ровно из-за этого
     * контроллер 269 раз сказал «зонд прошёл, а применения этого плана к его
     * потоку не было — не засчитано». То есть двести шестьдесят девять раз
     * НАЙДЕННЫЙ рабочий обход выбрасывался, потому что доказательство его
     * применения не доехало по каналу.
     *
     * Размер выведен из этого же замера: всплеск в 173 кадра при обменном
     * кадре в 26 байт, приветствии с именем до 280 и снимке формы до двух
     * килобайт даёт от 4,5 до 48 КиБ. 64 КиБ покрывают наблюдённый всплеск
     * целиком; на роутере это +3 % к RSS датапата (2,1 МиБ).
     *
     * Кадр кладётся ЦЕЛИКОМ или не кладётся вовсе: половина кадра в потоке
     * рассинхронизировала бы разбор у контроллера навсегда. */
    uint8_t  out[D2K_CTL_OUT_RING];
    size_t   out_head;   /* куда писать следующий байт */
    size_t   out_used;   /* сколько байт ждут отправки */

    /* Приёмный буфер: команда может прийти по кускам. */
    uint8_t  in[D2K_CTL_FRAME_MAX + HDR];
    size_t   in_len;

    uint64_t dropped;
    uint64_t sent;
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

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    return (fl < 0) ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

d2k_ctl *d2k_ctl_open(const char *path, char *err, size_t errcap) {
    if (!path || !*path) {
        say(err, errcap, "путь управляющего сокета пуст");
        return NULL;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof sa.sun_path) {
        say(err, errcap, "путь сокета длиннее %zu байт", sizeof sa.sun_path - 1);
        return NULL;
    }
    strcpy(sa.sun_path, path);

    d2k_ctl *c = calloc(1, sizeof *c);
    if (!c) {
        say(err, errcap, "нет памяти");
        return NULL;
    }
    c->pfd = -1;
    snprintf(c->path, sizeof c->path, "%s", path);

    c->lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (c->lfd < 0) {
        say(err, errcap, "socket(AF_UNIX): %s", strerror(errno));
        free(c);
        return NULL;
    }
    /* Файл сокета после SIGKILL остаётся и мешает следующему запуску. §5.5
       требует описанного пути восстановления — вот он. Убираем ТОЛЬКО свой
       путь, заданный настройкой: снимать чужой файл по догадке нельзя. */
    (void)unlink(path);
    if (bind(c->lfd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        say(err, errcap, "bind %s: %s", path, strerror(errno));
        close(c->lfd);
        free(c);
        return NULL;
    }
    if (listen(c->lfd, 1) < 0 || set_nonblock(c->lfd) < 0) {
        say(err, errcap, "listen %s: %s", path, strerror(errno));
        close(c->lfd);
        (void)unlink(path);
        free(c);
        return NULL;
    }
    return c;
}

void d2k_ctl_close(d2k_ctl *c) {
    if (!c) {
        return;
    }
    if (c->pfd >= 0) {
        close(c->pfd);
    }
    if (c->lfd >= 0) {
        close(c->lfd);
        (void)unlink(c->path);
    }
    free(c);
}

int d2k_ctl_listen_fd(const d2k_ctl *c) { return c ? c->lfd : -1; }
int d2k_ctl_peer_fd(const d2k_ctl *c)   { return c ? c->pfd : -1; }

void d2k_ctl_accept(d2k_ctl *c) {
    if (!c || c->lfd < 0) {
        return;
    }
    int fd = accept(c->lfd, NULL, NULL);
    if (fd < 0) {
        return;
    }
    if (c->pfd >= 0) {
        /* Второй контроллер отвергается. Пустить двоих значит позволить им
           ставить противоречащие планы, не зная друг о друге. */
        close(fd);
        return;
    }
    if (set_nonblock(fd) < 0) {
        close(fd);
        return;
    }
    c->pfd = fd;
    c->out_head = c->out_used = 0;
    c->in_len = 0;
    /* Версию протокола объявляет d2k_ctlsrv_greet, а не этот файл: раскладка
       тела события (ключ потока впереди) — знание ПРОТОКОЛА команд, а
       d2k_ctl.c протокольно-независим по устройству. Вызывающий обязан
       позвать greet сразу после accept. */
}

static void drop_peer(d2k_ctl *c) {
    if (c->pfd >= 0) {
        close(c->pfd);
        c->pfd = -1;
    }
    c->out_head = c->out_used = 0;
    c->in_len = 0;
}

void d2k_ctl_flush(d2k_ctl *c) {
    if (!c || c->pfd < 0 || c->out_used == 0) {
        return;
    }
    while (c->out_used > 0) {
        size_t tail = (c->out_head + D2K_CTL_OUT_RING - c->out_used) % D2K_CTL_OUT_RING;
        /* За один write уходит только СПЛОШНОЙ кусок: кольцо переносится
           через край, а write об этом не знает. Остаток допишется следующим
           оборотом цикла либо следующим вызовом. */
        size_t run = D2K_CTL_OUT_RING - tail;
        if (run > c->out_used) { run = c->out_used; }
        ssize_t n = write(c->pfd, c->out + tail, run);
        if (n > 0) {
            c->out_used -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;   /* допишем в следующий раз */
        }
        drop_peer(c);
        return;
    }
}

void d2k_ctl_event(d2k_ctl *c, uint16_t type, const uint8_t *body, size_t len) {
    if (!c || c->pfd < 0 || len > D2K_CTL_FRAME_MAX - 2) {
        if (c) {
            c->dropped++;
        }
        return;
    }
    /* Сперва освобождаем место тем, что уже можно дописать. */
    d2k_ctl_flush(c);

    size_t plen = 2 + len;
    size_t need = HDR + len;
    if (need > D2K_CTL_OUT_RING - c->out_used) {
        /* Места нет даже после дописывания — кадр теряется ЦЕЛИКОМ и
           считается. Половина кадра сломала бы разбор у контроллера. */
        c->dropped++;
        return;
    }

    uint8_t hdr[HDR];
    hdr[0] = (uint8_t)(plen >> 24);
    hdr[1] = (uint8_t)(plen >> 16);
    hdr[2] = (uint8_t)(plen >> 8);
    hdr[3] = (uint8_t)plen;
    hdr[4] = (uint8_t)(type >> 8);
    hdr[5] = (uint8_t)type;

    for (size_t i = 0; i < HDR; i++) {
        c->out[c->out_head] = hdr[i];
        c->out_head = (c->out_head + 1) % D2K_CTL_OUT_RING;
    }
    for (size_t i = 0; i < len; i++) {
        c->out[c->out_head] = body[i];
        c->out_head = (c->out_head + 1) % D2K_CTL_OUT_RING;
    }
    c->out_used += need;
    c->sent++;
    d2k_ctl_flush(c);
}

int d2k_ctl_poll(d2k_ctl *c,
                 void (*cb)(void *ctx, uint16_t type, const uint8_t *body, size_t len),
                 void *ctx) {
    if (!c || c->pfd < 0) {
        return 0;
    }
    for (;;) {
        ssize_t n = read(c->pfd, c->in + c->in_len, sizeof c->in - c->in_len);
        if (n > 0) {
            c->in_len += (size_t)n;
            break;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        drop_peer(c);
        return -1;
    }

    int done = 0;
    size_t off = 0;
    while (c->in_len - off >= HDR) {
        const uint8_t *h = c->in + off;
        uint32_t plen = (uint32_t)h[0] << 24 | (uint32_t)h[1] << 16 |
                        (uint32_t)h[2] << 8 | h[3];
        if (plen < 2 || plen > D2K_CTL_FRAME_MAX) {
            /* Кадр с невозможной длиной. Дальше по потоку идти нельзя:
               следующий заголовок пришлось бы искать по выдуманному
               смещению. Рвём соединение — контроллер переподключится. */
            drop_peer(c);
            return -1;
        }
        if (c->in_len - off < HDR - 2 + plen) {
            break;   /* кадр ещё не целиком */
        }
        uint16_t type = (uint16_t)((uint16_t)h[4] << 8 | h[5]);
        if (cb) {
            cb(ctx, type, h + HDR, plen - 2);
        }
        off += HDR - 2 + plen;
        done++;
    }
    if (off > 0) {
        memmove(c->in, c->in + off, c->in_len - off);
        c->in_len -= off;
    }
    if (c->in_len == sizeof c->in) {
        /* Буфер полон, а целого кадра нет: длина в заголовке не сходится с
           тем, что приходит. */
        drop_peer(c);
        return -1;
    }
    return done;
}

uint64_t d2k_ctl_dropped(const d2k_ctl *c) { return c ? c->dropped : 0; }
uint64_t d2k_ctl_sent(const d2k_ctl *c)    { return c ? c->sent : 0; }
