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

struct d2k_ctl {
    int      lfd;
    int      pfd;
    char     path[108];

    /* Хвост одного недописанного кадра. Больше одного не бывает: пока хвост
       не ушёл, новые события теряются. Предел памяти отсюда известен. */
    uint8_t  out[D2K_CTL_FRAME_MAX + HDR];
    size_t   out_len;
    size_t   out_off;

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
    c->out_len = c->out_off = 0;
    c->in_len = 0;
}

static void drop_peer(d2k_ctl *c) {
    if (c->pfd >= 0) {
        close(c->pfd);
        c->pfd = -1;
    }
    c->out_len = c->out_off = 0;
    c->in_len = 0;
}

void d2k_ctl_flush(d2k_ctl *c) {
    if (!c || c->pfd < 0 || c->out_off >= c->out_len) {
        return;
    }
    for (;;) {
        ssize_t n = write(c->pfd, c->out + c->out_off, c->out_len - c->out_off);
        if (n > 0) {
            c->out_off += (size_t)n;
            if (c->out_off >= c->out_len) {
                c->out_len = c->out_off = 0;
                c->sent++;
            }
            return;
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
    /* Хвост прошлого кадра ещё не ушёл — это событие теряется. Ставить его в
       очередь значит заводить память без предела. */
    d2k_ctl_flush(c);
    if (c->out_off < c->out_len) {
        c->dropped++;
        return;
    }

    size_t plen = 2 + len;
    c->out[0] = (uint8_t)(plen >> 24);
    c->out[1] = (uint8_t)(plen >> 16);
    c->out[2] = (uint8_t)(plen >> 8);
    c->out[3] = (uint8_t)plen;
    c->out[4] = (uint8_t)(type >> 8);
    c->out[5] = (uint8_t)type;
    if (len) {
        memcpy(c->out + HDR, body, len);
    }
    c->out_len = HDR + len;
    c->out_off = 0;
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
