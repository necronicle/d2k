/* link.c — связь с датапатом по управляющему сокету (см. d2k_link.h).
 *
 * Клиентская сторона AF_UNIX-сокета, который слушает датапат (d2k_ctl.h,
 * datapath/ctl.c). Кадр читается по длине, поля — побайтно, тем же приёмом,
 * что put_key в datapath/ctlsrv.c: наложение структуры на буфер здесь
 * запрещено по той же причине (выравнивание, дыра, непереносимость на
 * MIPS/ARM).
 *
 * Один статический буфер на приём И на отправку, не два и не на стеке:
 *   - не на стеке — 64 КБ (D2K_CTL_FRAME_MAX) на стеке трогать незачем на
 *     mipsel-роутере, где размер стека потока не гарантирован щедрым;
 *   - один на оба направления — модуль обслуживает РОВНО ОДНО подключение в
 *     ОДНОМ потоке (тот же инвариант, что и у самого датапата: "датапат
 *     обслуживает одного хозяина, а не является сервером общего
 *     пользования", d2k_ctl.h), поэтому приём и отправка никогда не идут
 *     параллельно, и делить память незачем.
 * Не реентерабельно относительно другого потока ОС — не для этого протокола
 * писалось. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "d2k_link.h"
/* Единственный источник D2K_KEY_WIRE_LEN — см. большой комментарий у него в
 * datapath/include/d2k_ctlsrv.h про то, почему это не sizeof(d2k_key) и не
 * литерал. Заголовок тянет за собой d2k_raw.h/d2k_session.h/d2k_plan.h/
 * d2k_plans.h транзитивно, но отсюда не зовётся ни одна их функция —
 * используется только сам #define, поэтому лишней линковки с датапатом не
 * образуется (компилируется декларация, не вызывается символ). */
#include "d2k_ctlsrv.h"

#define HDR 6u /* [длина u32 BE][тип u16 BE] — как в datapath/ctl.c */

static uint8_t g_scratch[D2K_CTL_FRAME_MAX + HDR];

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

/* Ждёт данные на fd не дольше ms миллисекунд — та же семантика, что у
 * poll(2): отрицательное ms — ждать неограниченно, 0 — не ждать вовсе.
 * Возвращает 0 (таймаут), >0 (есть что читать) или -1 (ошибка, причина в
 * err). */
static int wait_readable(int fd, int ms, char *err, size_t errcap) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    for (;;) {
        pfd.revents = 0;
        int pr = poll(&pfd, 1, ms);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            say(err, errcap, "poll: %s", strerror(errno));
            return -1;
        }
        return pr;
    }
}

/* Дочитывает РОВНО n байт или отказывает. Once начатое чтение кадра не
 * ограничено wait_ms заново (см. d2k_link_next в d2k_link.h про то, почему):
 * на локальном сокете между двумя нашими же процессами кадр, начавший
 * приходить и не дописанный, — это порванное соединение, а не тайм-аут. */
static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR) {
            continue;
        }
        return -1; /* 0 — собеседник закрылся; <0 — ошибка сокета */
    }
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(fd, buf + sent, n - sent, 0);
        if (w > 0) {
            sent += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/* Разбирает hex в out (не более outcap байт). Нечётная длина — забота
 * вызывающего (проверяется отдельно, чтобы дать её причину в err точнее, чем
 * общее "недопустимый символ"). Возвращает число разобранных байт, или -1,
 * если встретился недопустимый символ либо байт не поместился в outcap. */
static long hex_decode(const char *hex, uint8_t *out, size_t outcap) {
    size_t n = 0;
    while (hex[0] && hex[1]) {
        int hi = hex_nibble((unsigned char)hex[0]);
        int lo = hex_nibble((unsigned char)hex[1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        if (n >= outcap) {
            return -1;
        }
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return (long)n;
}

int d2k_link_open(const char *sock_path, char *err, size_t errcap) {
    if (!sock_path || !*sock_path) {
        say(err, errcap, "путь управляющего сокета пуст");
        return -1;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof sa.sun_path) {
        say(err, errcap, "путь сокета длиннее %zu байт", sizeof sa.sun_path - 1);
        return -1;
    }
    strcpy(sa.sun_path, sock_path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        say(err, errcap, "socket(AF_UNIX): %s", strerror(errno));
        return -1;
    }
    /* AF_UNIX: connect() ставится в очередь listen()'а сразу, ответа
     * accept() на другой стороне не ждёт — гонки со стендом, который ещё не
     * дошёл до цикла с accept(), здесь нет (см. комментарий в d2k_link.h). */
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        say(err, errcap, "connect %s: %s", sock_path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

void d2k_link_close(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

int d2k_link_next(int fd, d2k_ev *out, int wait_ms, char *err, size_t errcap) {
    if (!out) {
        say(err, errcap, "нет места для события");
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (fd < 0) {
        say(err, errcap, "сокет не открыт");
        return -1;
    }

    int pr = wait_readable(fd, wait_ms, err, errcap);
    if (pr < 0) {
        return -1;
    }
    if (pr == 0) {
        return 1; /* тайм-аут: событие — сообщение, а не обязательство */
    }

    uint8_t hdr[HDR];
    if (read_exact(fd, hdr, sizeof hdr) != 0) {
        say(err, errcap, "заголовок кадра не дочитался: соединение закрылось");
        return -1;
    }
    uint32_t plen = (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 |
                    (uint32_t)hdr[2] << 8 | hdr[3];
    uint16_t type = (uint16_t)((uint16_t)hdr[4] << 8 | hdr[5]);
    if (plen < 2 || plen > (uint32_t)D2K_CTL_FRAME_MAX) {
        say(err, errcap, "кадр с невозможной длиной %u", (unsigned)plen);
        return -1;
    }
    size_t body_len = (size_t)plen - 2;
    if (read_exact(fd, g_scratch, body_len) != 0) {
        say(err, errcap, "тело кадра не дочиталось целиком: соединение закрылось");
        return -1;
    }
    if (body_len < D2K_KEY_WIRE_LEN) {
        say(err, errcap, "кадр короче ключа потока (%zu байт)", body_len);
        return -1;
    }

    out->kind = type;
    memcpy(out->low_ip, g_scratch + 0, 4);
    memcpy(out->high_ip, g_scratch + 4, 4);
    out->low_port = (uint16_t)((uint16_t)g_scratch[8] << 8 | g_scratch[9]);
    out->high_port = (uint16_t)((uint16_t)g_scratch[10] << 8 | g_scratch[11]);
    out->transport = g_scratch[12]; /* см. большой комментарий в d2k_link.h */

    const uint8_t *rest = g_scratch + D2K_KEY_WIRE_LEN;
    size_t rlen = body_len - D2K_KEY_WIRE_LEN;

    switch (type) {
    case D2K_EV_HELLO:
        if (rlen < 1) {
            say(err, errcap, "приветствие без длины имени");
            return -1;
        }
        {
            /* namelen — один байт, поэтому не больше 255, а name[256] с
               запасом на NUL хватает без дополнительной проверки границы. */
            size_t nl = rest[0];
            if (rlen < 1 + nl) {
                say(err, errcap, "имя короче объявленной длины");
                return -1;
            }
            memcpy(out->name, rest + 1, nl);
            out->name[nl] = '\0';
        }
        break;
    case D2K_EV_SUSPECT:
        if (rlen < 1) {
            say(err, errcap, "подозрение без кода причины");
            return -1;
        }
        out->code = rest[0];
        /* Подробности необязательны по длине, но датапат их шлёт всегда
           (ctlsrv.c, D2K_JRN_SUSPECT: код плюс пять байт). Проверяем длину, а
           не предполагаем её: событие без подробностей — законный вход
           (старый датапат), и терять из-за него весь разбор нельзя. */
        if (rlen >= 6) {
            out->ttl = rest[1];
            out->ref_ttl = rest[2];
            out->tos = rest[3];
            out->ipid = (uint16_t)((uint16_t)rest[4] << 8 | rest[5]);
        }
        break;
    case D2K_EV_EXCHANGE:
        if (rlen < 6) {
            say(err, errcap, "обмен короче типа записи и длины");
            return -1;
        }
        out->code = rest[0]; /* тип ПЕРВОЙ TLS-записи — липкое поле, НЕ порог успеха (см. d2k_link.h) */
        out->seen_types = rest[1]; /* маска встреченных типов — вход d2k_ev_has_appdata */
        out->num = (uint32_t)rest[2] << 24 | (uint32_t)rest[3] << 16 |
                   (uint32_t)rest[4] << 8 | rest[5];
        break;
    case D2K_EV_SHAPE:
        if (rlen > sizeof out->shape) {
            say(err, errcap, "форма приветствия длиннее буфера (%zu байт)", rlen);
            return -1;
        }
        memcpy(out->shape, rest, rlen);
        out->shape_len = rlen;
        break;
    case D2K_EV_ACK:
        if (rlen < 4) {
            say(err, errcap, "подтверждение короче типа команды, признака успеха и причины");
            return -1;
        }
        out->code = (uint16_t)((uint16_t)rest[0] << 8 | rest[1]);
        out->num = (uint32_t)rest[2] << 8 | rest[3]; /* (ok<<8)|reason, см. d2k_link.h */
        break;
    case D2K_EV_APPLIED:
    case D2K_EV_REFUSED:
    default:
        /* Только ключ (APPLIED/REFUSED) либо вид события, которого этот
           модуль пока не разбирает глубже, — событие сообщение, а не
           обязательство: незнакомый вид не повод отказывать, ключ и kind уже
           разобраны. */
        break;
    }
    return 0;
}

int d2k_link_set_name(int fd, const char *name, uint8_t transport,
                      const char *plan_text, char *err, size_t errcap) {
    if (fd < 0) {
        say(err, errcap, "сокет не открыт");
        return -1;
    }
    if (!name || !*name) {
        say(err, errcap, "имя цели пусто");
        return -1;
    }
    size_t nl = strlen(name);
    if (nl > 255) {
        say(err, errcap, "имя цели длиной %zu байт длиннее 255", nl);
        return -1;
    }
    if (transport != 6 && transport != 17) {
        /* Проверяется, но НЕ едет отдельным полем на проводе — см. большой
           комментарий у d2k_link_set_name в d2k_link.h про то, почему у
           SET_NAME сегодня нет места под транспорт. */
        say(err, errcap, "транспорт %u не 6 (TCP) и не 17 (UDP)", (unsigned)transport);
        return -1;
    }
    if (!plan_text) {
        plan_text = "";
    }
    size_t hexlen = strlen(plan_text);
    if (hexlen % 2 != 0) {
        say(err, errcap, "план не hex: нечётное число символов (%zu)", hexlen);
        return -1;
    }
    size_t plan_cap = sizeof g_scratch - HDR - 1 - nl;
    if (hexlen / 2 > plan_cap) {
        say(err, errcap, "план длиннее предела кадра");
        return -1;
    }

    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl;
    memcpy(g_scratch + o, name, nl);
    o += nl;
    long planlen = hex_decode(plan_text, g_scratch + o, sizeof g_scratch - o);
    if (planlen < 0) {
        say(err, errcap, "план не hex: недопустимый символ");
        return -1;
    }
    o += (size_t)planlen;

    size_t body_len = o - HDR;
    if (body_len > (size_t)D2K_CTL_FRAME_MAX - 2) {
        /* То же ограничение, что и в d2k_ctl_poll на приёме: кадр длиннее
           предела датапат не разберёт, а порвёт соединение как "врущую
           длину" — лучше отказать здесь, не тратя единственное подключение. */
        say(err, errcap, "команда длиннее предела кадра");
        return -1;
    }
    uint32_t plen = (uint32_t)(2 + body_len);
    g_scratch[0] = (uint8_t)(plen >> 24);
    g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);
    g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_SET_NAME >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_SET_NAME;

    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда SET_NAME не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* Общее тело ARM_SHAPE и DEL_NAME: на проводе они отличаются ТОЛЬКО кодом
   команды (d2k_ctl.h — у обеих тело "длина имени u8, имя"), и держать две
   копии одного кадра значило бы заводить второе место, где можно разойтись
   с протоколом. */
static int send_name_only(int fd, uint16_t cmd, const char *what,
                          const char *name, char *err, size_t errcap) {
    if (fd < 0) {
        say(err, errcap, "сокет не открыт");
        return -1;
    }
    if (!name) {
        name = "";
    }
    size_t nl = strlen(name);
    if (nl > 255) {
        say(err, errcap, "имя цели длиной %zu байт длиннее 255", nl);
        return -1;
    }

    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl;
    memcpy(g_scratch + o, name, nl);
    o += nl;

    size_t body_len = o - HDR;
    uint32_t plen = (uint32_t)(2 + body_len);
    g_scratch[0] = (uint8_t)(plen >> 24);
    g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);
    g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(cmd >> 8);
    g_scratch[5] = (uint8_t)cmd;

    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда %s не отправилась: %s", what, strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_arm_shape(int fd, const char *name, char *err, size_t errcap) {
    return send_name_only(fd, D2K_CMD_ARM_SHAPE, "ARM_SHAPE", name, err, errcap);
}

int d2k_link_del_name(int fd, const char *name, char *err, size_t errcap) {
    return send_name_only(fd, D2K_CMD_DEL_NAME, "DEL_NAME", name, err, errcap);
}


int d2k_ev_has_appdata(const d2k_ev *ev) {
    /* §8: успех — прикладной обмен, а не тип ПЕРВОЙ записи (code — липкое
     * поле, см. большой комментарий у seen_types в d2k_link.h) и не любые
     * вернувшиеся байты. Зеркало Go-донора HasAppData: маска, а не
     * сравнение с одним значением — иначе uint8_t seen_types молча
     * продвинулся бы до uint16_t и сравнился с типом записи, что почти
     * всегда даёт ложь без единого предупреждения компилятора (см. большой
     * комментарий у объявления в d2k_link.h). ev == NULL — не событие,
     * прикладных данных в нём нет по определению, а не неопределённое
     * поведение. */
    if (!ev) {
        return 0;
    }
    return (ev->seen_types & (uint8_t)(1u << (D2K_TLS_APPLICATION_DATA - 20))) != 0 ? 1 : 0;
}
