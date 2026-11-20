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

static __thread uint8_t g_scratch[D2K_CTL_FRAME_MAX + HDR];

/* Absence is unknown, a truncated extension is malformed. This context is
 * still cannot by itself establish live/application success. */
static int execution_context(d2k_ev *out, const uint8_t *p, size_t n) {
    if (!n) return 0;
    if (n != D2K_CTL_EXECUTION_LEN ||
        d2k_ctl_binding_read(&out->execution_binding,p+8,D2K_CTL_BINDING_LEN)) return -1;
    for (unsigned b=0;b<8;b++) out->execution_id=(out->execution_id<<8)|p[b];
    return 0;
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
    /* A disconnected local daemon is an I/O error, not permission to kill
       its caller with SIGPIPE. Do not change process-wide signal policy. */
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#elif defined(SO_NOSIGPIPE)
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one) != 0) { return -1; }
#endif
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(fd, buf + sent, n - sent, flags);
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

int d2k_link_peer_closed(int fd) {
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int pr;
    do {
        pr = poll(&pfd, 1, 0);
    } while (pr < 0 && errno == EINTR);
    if (pr < 0) {
        return -1;
    }
    if (pr == 0) {
        return 0;
    }
    if (pfd.revents & POLLNVAL) {
        errno = EBADF;
        return -1;
    }
    return (pfd.revents & (POLLHUP | POLLERR)) ? 1 : 0;
}

int d2k_link_greeting(int fd, int wait_ms, d2k_ev *out, char *err, size_t errcap) {
    d2k_ev local;
    if (!out) { out = &local; }
    int rc = d2k_link_next(fd, out, wait_ms, err, errcap);
    if (rc > 0) {
        say(err, errcap, "датапат не прислал приветствие за %d мс", wait_ms);
        return -1;
    }
    if (rc < 0) { return -1; }
    if (out->kind != D2K_EV_PROTO) {
        say(err, errcap, "первое событие датапата не приветствие (тип 0x%04x)", (unsigned)out->kind);
        return -1;
    }
    if (out->num != D2K_CTL_PROTO_VERSION) {
        say(err, errcap, "несовместимое приветствие датапата: версия провода %u, нужна %u — "
            "обновите d2kd, d2kc и d2kask вместе, из одного дерева",
            (unsigned)out->num, (unsigned)D2K_CTL_PROTO_VERSION);
        return -1;
    }
    if (strcmp(out->release_id, D2K_RELEASE_ID) != 0) {
        say(err, errcap, "несовместимое приветствие датапата: выпуск «%s», нужен «%s»",
            out->release_id, D2K_RELEASE_ID);
        return -1;
    }
    return 0;
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
    return d2k_link_decode(type,g_scratch,body_len,out,err,errcap);
}

int d2k_link_decode(uint16_t type,const uint8_t *body,size_t body_len,d2k_ev *out,char *err,size_t errcap) {
    if(!out || !body)return -1;
    memset(out,0,sizeof *out);
    if (body_len < D2K_KEY_WIRE_LEN) {
        say(err, errcap, "кадр короче ключа потока (%zu байт)", body_len);
        return -1;
    }

    out->kind = type;
    if (body[0] != 4 && body[0] != 6) {
        say(err, errcap, "неизвестное семейство ключа потока: %u", body[0]);
        return -1;
    }
    out->family = body[0];
    if (out->family == 4) {
        for (size_t i = 4; i < 16; ++i) {
            if (body[1 + i] || body[17 + i]) {
                say(err, errcap, "ненулевой хвост IPv4-адреса в ключе потока");
                return -1;
            }
        }
    }
    memcpy(out->low_ip, body + 1, 16);
    memcpy(out->high_ip, body + 17, 16);
    out->low_port = (uint16_t)((uint16_t)body[33] << 8 | body[34]);
    out->high_port = (uint16_t)((uint16_t)body[35] << 8 | body[36]);
    out->transport = body[37];

    const uint8_t *rest = body + D2K_KEY_WIRE_LEN;
    size_t rlen = body_len - D2K_KEY_WIRE_LEN;

    if(type==D2K_EV_OWNED_EXCHANGE) {
        if(rlen!=8+24 && rlen!=8+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN+D2K_CTL_EXECUTION_LEN+24)return -1;
        const uint8_t *identity=rest+rlen-24;
        memcpy(out->flow_epoch,identity,16);
        for(unsigned i=0;i<8;i++)out->flow_incarnation=(out->flow_incarnation<<8)|identity[16+i];
        if(!out->flow_incarnation || !d2k_rm_nonzero(out->flow_epoch,16))return -1;
        rlen-=24;type=D2K_EV_EXCHANGE;out->kind=type;
    }
    if (type==D2K_EV_RAW_SUSPECT || type==D2K_EV_RAW_FLOW) {
        int birth=type==D2K_EV_RAW_FLOW;
        if (!birth && rlen!=11+24 && rlen!=11+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN+D2K_CTL_EXECUTION_LEN+24) return -1;
        if (birth && (rlen!=25 || !rest[0] || rest[0]>D2K_CLIENT_SIDE_HIGH)) return -1;
        if (!birth && (rest[7]!=D2K_LINK_SHAPE_RAW || !rest[10] || rest[10]>D2K_CLIENT_SIDE_HIGH)) return -1;
        const uint8_t *identity=rest+rlen-24;
        memcpy(out->flow_epoch,identity,16);
        for(unsigned i=0;i<8;i++)out->flow_incarnation=(out->flow_incarnation<<8)|identity[16+i];
        if (!out->flow_incarnation || !d2k_rm_nonzero(out->flow_epoch,16)) return -1;
        rlen-=24;type=birth?D2K_EV_FLOW:D2K_EV_SUSPECT;out->kind=type;
    }

    switch (type) {
    case D2K_EV_PREFLIGHT_START:
    case D2K_EV_PREFLIGHT_HANDOVER:
    case D2K_EV_PREFLIGHT_GAVE_UP:
        if(rlen!=D2K_CTL_PREFLIGHT_LEN || !rest[0] || rest[0]>D2K_CLIENT_SIDE_HIGH) return -1;
        out->client_side=rest[0];
        out->num=(uint32_t)rest[1]<<24 | (uint32_t)rest[2]<<16 | (uint32_t)rest[3]<<8 | rest[4];
        for(unsigned i=0;i<8;i++) out->preflight_elapsed_ns=(out->preflight_elapsed_ns<<8)|rest[5+i];
        memcpy(out->plan_id,rest+13,D2K_PLAN_ID_LEN);
        memcpy(out->trial_id,rest+13+D2K_PLAN_ID_LEN,D2K_TRIAL_ID_LEN);
        if(d2k_ctl_binding_read(&out->execution_binding,rest+13+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN,D2K_CTL_BINDING_LEN)) return -1;
        break;
    case D2K_EV_RAW_MEASURE: {
        if (d2k_rawmeasure_report_read(&out->raw_measure,rest,rlen)) return -1;
        const d2k_ct_tuple *t=&out->raw_measure.request.tuple;
        uint16_t sp=(uint16_t)((uint16_t)t->sport_be[0]<<8|t->sport_be[1]);
        uint16_t dp=(uint16_t)((uint16_t)t->dport_be[0]<<8|t->dport_be[1]);
        if (out->family!=t->family || out->transport!=t->proto) return -1;
        int forward=!memcmp(out->low_ip,t->src,16)&&!memcmp(out->high_ip,t->dst,16)&&
                    out->low_port==sp&&out->high_port==dp;
        int reverse=!memcmp(out->low_ip,t->dst,16)&&!memcmp(out->high_ip,t->src,16)&&
                    out->low_port==dp&&out->high_port==sp;
        if (!forward && !reverse) return -1;
        break;
    }

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
            if(rlen!=1+nl && rlen!=2+nl)return -1;
            if(rlen==2+nl) {
                if(rest[1+nl]>D2K_CLIENT_SIDE_HIGH)return -1;
                out->client_side=rest[1+nl];
            }
        }
        break;
    case D2K_EV_HTTP_RESPONSE:
    case D2K_EV_HTTP_PORTAL:
        if(out->kind==D2K_EV_HTTP_RESPONSE) {
            if(rlen<18)return -1;
            rlen-=18;const uint8_t *meta=rest+rlen;
            out->live_http_status=(uint16_t)((unsigned)meta[0]<<8|meta[1]);
            for(unsigned i=0;i<8;i++) {
                out->live_body_bytes=(out->live_body_bytes<<8)|meta[2+i];
                out->live_request_no=(out->live_request_no<<8)|meta[10+i];
            }
            if(!out->live_request_no || rest[0]<1 || rest[0]>4 || out->live_http_status>599 ||
               (rest[0]==1 && out->live_http_status<200))return -1;
        }
        if (rlen < 2 || rlen < 2u + rest[1]) {
            say(err, errcap, "вставка HTTP без признака или с обрезанным именем");
            return -1;
        }
        out->code = rest[0];
        memcpy(out->name, rest + 2, rest[1]);
        out->name[rest[1]] = '\0';
        {
            size_t off = 2u + rest[1];
            if(out->kind==D2K_EV_HTTP_RESPONSE && rlen<off+50+D2K_CTL_BINDING_LEN)return -1;
            if (rlen != off && rlen < off + 50) {
                say(err, errcap, "вставка HTTP с обрезанным контекстом исполнения");
                return -1;
            }
            if (rlen >= off + 50) {
                size_t path_len = (size_t)rest[off + 48] << 8 | rest[off + 49];
                if(out->kind==D2K_EV_HTTP_RESPONSE && rlen!=off+50+path_len+D2K_CTL_BINDING_LEN)return -1;
                if (path_len >= sizeof out->live_http_path || (rlen != off + 50 + path_len && rlen != off + 50 + path_len + D2K_CTL_BINDING_LEN)) {
                    say(err, errcap, "вставка HTTP с обрезанным контекстом запроса");
                    return -1;
                }
                for (size_t i = 0; i < 8; i++)
                    out->live_execution = (out->live_execution << 8) | rest[off + i];
                memcpy(out->plan_id, rest + off + 8, 16);
                memcpy(out->trial_id, rest + off + 24, 16);
                for (size_t i = 0; i < 8; i++)
                    out->live_request_ms = (out->live_request_ms << 8) | rest[off + 40 + i];
                memcpy(out->live_http_path, rest + off + 50, path_len);
                out->live_http_path[path_len] = '\0';
                if(rlen==off+50+path_len+D2K_CTL_BINDING_LEN &&
                   d2k_ctl_binding_read(&out->execution_binding,rest+off+50+path_len,D2K_CTL_BINDING_LEN))return -1;
            }
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
        if (rlen >= 7) {
            /* Применялся ли план к этому потоку. Отсутствие байта — «не
               сказано», и менять по нему смысл подозрения нельзя. */
            out->planned = rest[6];
        }
        if (rlen >= 8) out->client_shape = rest[7];
        /* v12: число при записи, u16 BE (D2K_SUSPECT_TCP_STALL — оценка
           пакетов с данными). Нет байт — ноль, «не сказано». */
        if (rlen >= 10) out->num = (uint32_t)rest[8] << 8 | rest[9];
        if (rlen >= 11) {
            if (rest[10] > D2K_CLIENT_SIDE_HIGH) {
                say(err, errcap, "invalid observed client endpoint");
                return -1;
            }
            out->client_side = rest[10];
        }
        if (rlen > 11) {
            if (rlen != 11 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN + D2K_CTL_EXECUTION_LEN ||
                execution_context(out, rest + 11 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN,
                                  D2K_CTL_EXECUTION_LEN)) {
                say(err,errcap,"malformed SUSPECT execution context"); return -1;
            }
            memcpy(out->plan_id,rest+11,D2K_PLAN_ID_LEN);
            memcpy(out->trial_id,rest+11+D2K_PLAN_ID_LEN,D2K_TRIAL_ID_LEN);
        }
        break;
    case D2K_EV_STATS:
        /* Счётчики необязательны по длине: старый датапат их не слал вовсе, и
           терять из-за этого разбор события нельзя. */
        if (rlen >= 8) {
            out->dropped = (uint32_t)rest[0] << 24 | (uint32_t)rest[1] << 16 |
                           (uint32_t)rest[2] << 8  | rest[3];
            out->sent    = (uint32_t)rest[4] << 24 | (uint32_t)rest[5] << 16 |
                           (uint32_t)rest[6] << 8  | rest[7];
        }
        break;
    case D2K_EV_EXCHANGE:
        if (rlen < 6) {
            say(err, errcap, "обмен короче типа записи и длины");
            return -1;
        }
        out->code = rest[0]; /* тип ПЕРВОЙ TLS-записи — липкое поле, НЕ порог успеха (см. d2k_link.h) */
        out->seen_types = rest[1]; /* маска встреченных типов — вход d2k_ev_outer_appdata */
        out->num = (uint32_t)rest[2] << 24 | (uint32_t)rest[3] << 16 |
                   (uint32_t)rest[4] << 8 | rest[5];
        /* ПРИЁМКА ВОПРОСА. Байт необязателен по длине — тем же приёмом, что
           идентификатор плана и счётчики выше: старый датапат его не слал, и
           терять из-за этого разбор события нельзя. Нет байта — ноль, то есть
           «сервер не отвечал ServerHello», и это честный ответ: приёмка
           требует ДОКАЗАТЕЛЬСТВА, а не отсутствия опровержения. */
        if (rlen >= 7) {
            out->server_hello = rest[6];
        }
        /* ПРИМЕНЯЛСЯ ЛИ ПЛАН К ЭТОМУ ОБМЕНУ — тем же опциональным приёмом,
           что server_hello: нет байта — ноль (D2K_LINK_PLANNED_UNKNOWN), и
           гашения замера по неизвестному обмену не будет. */
        if (rlen >= 8) {
            out->planned = rest[7];
        }
        /* Optional immutable request context. Legacy/unbound events remain
           unknown; a partial context must never be treated as unbound. */
        if (rlen > 8) {
            if (rlen != 8 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN + D2K_CTL_EXECUTION_LEN ||
                execution_context(out, rest + 8 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN,
                                  D2K_CTL_EXECUTION_LEN)) {
                say(err,errcap,"malformed EXCHANGE execution context"); return -1;
            }
            memcpy(out->plan_id,rest+8,D2K_PLAN_ID_LEN);
            memcpy(out->trial_id,rest+8+D2K_PLAN_ID_LEN,D2K_TRIAL_ID_LEN);
        }
        break;
    case D2K_EV_CLIENT_TCP:
        /* Набор опций TCP клиента перед его SHAPE (замысел 2026-10-23,
           п. 5.1). Нулевая длина — известный пустой набор; длиннее заголовка
           TCP не бывает — отказ, а не усечение. */
        if (rlen > sizeof out->tcp_options) {
            say(err, errcap, "набор опций TCP клиента длиннее 40 байт (%zu)", rlen);
            return -1;
        }
        memcpy(out->tcp_options, rest, rlen);
        out->tcp_options_len = rlen;
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
        if (rlen >= 4 + D2K_TRIAL_ID_LEN) {
            memcpy(out->trial_id, rest + 4, D2K_TRIAL_ID_LEN);
        }
        if (out->code == D2K_CMD_DEL_ADDR_PROBE && rest[2] == 1) {
            uint8_t any = 0;
            for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) any |= out->trial_id[i];
            if (rlen != 4 + D2K_TRIAL_ID_LEN || !any) {
                say(err, errcap, "подтверждение снятия адресного опыта без его идентификатора");
                return -1;
            }
        }
        if((out->code==D2K_CMD_SET_NAME_BOUND || out->code==D2K_CMD_SET_ENDPOINT_BOUND || out->code==D2K_CMD_SET_PREFLIGHT_TRIAL ||
            out->code==D2K_CMD_SET_PREFLIGHT_LEASE || out->code==D2K_CMD_SET_DNS_ENDPOINT) &&
           (rlen!=4+D2K_TRIAL_ID_LEN+D2K_CTL_BINDING_LEN ||
            d2k_ctl_binding_read(&out->execution_binding,rest+4+D2K_TRIAL_ID_LEN,D2K_CTL_BINDING_LEN))) return -1;
        break;
    case D2K_EV_APPLIED:
        /* Новый код подтверждения исполнения требует полный ID. Старый
           PREPARED (0x0003) — отдельное событие, не доказательство. */
        if (rlen < D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN) {
            say(err, errcap, "исполнение без полного Plan ID/trial ID");
            return -1;
        }
        memcpy(out->plan_id, rest, D2K_PLAN_ID_LEN);
        if (rlen >= D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN) {
            memcpy(out->trial_id, rest + D2K_PLAN_ID_LEN, D2K_TRIAL_ID_LEN);
        }
        if (execution_context(out, rest + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN,
                              rlen - D2K_PLAN_ID_LEN - D2K_TRIAL_ID_LEN)) {
            say(err, errcap, "повреждён контекст исполнения APPLIED");
            return -1;
        }
        break;
    case D2K_EV_PROTO:
        if (rlen > 6) {
            unsigned len = rest[6];
            if (!len || len > 64 || rlen != 7u + len) { return -1; }
            for (unsigned i = 0; i < len; i++) {
                unsigned char c = rest[7+i];
                int alnum = (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9');
                if (!alnum && !(i && (c=='.'||c=='_'||c=='-'))) { return -1; }
            }
            memcpy(out->release_id, rest+7, len);
        }
        /* ВЕРСИЯ ПРОВОДА. Короче двух байт — версия не объявлена, и это не
           повод считать, что всё в порядке: контроллер обязан отказаться
           работать так же, как при чужой версии. */
        if (rlen >= 2) {
            out->num = (uint32_t)rest[0] << 8 | rest[1];
        }
        /* Предел отправки — четыре байта следом. Его может не быть: старый
           датапат слал только версию, и терять из-за этого разбор события
           нельзя. Нет байтов — ноль, то есть «предел не объявлен». */
        if (rlen >= 6) {
            out->send_maxlen = (uint32_t)rest[2] << 24 | (uint32_t)rest[3] << 16 |
                               (uint32_t)rest[4] << 8 | rest[5];
        }
        break;
    case D2K_EV_REFUSED:
        /* КОД ПРИЧИНЫ, если он приехал. Байт необязателен по длине по той же
           причине, что идентификатор плана выше: старый датапат слал один
           ключ, и терять из-за этого разбор события нельзя. Нет байта — ноль,
           то есть «причина не кодирована», и это честный ответ, а не выдумка.

           Ради этого байта событие и переделывали: без него локальный отказ
           отправки приходил контроллеру неотличимо от «коробка не поддалась»,
           и наша поломка записывалась свойством чужого устройства
           (docs/decisions/0006-proof-boundaries.md). */
        if (rlen >= 1) {
            out->code = rest[0];
        }
        if (rlen < 1 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN) {
            say(err, errcap, "отказ без полного Plan ID/trial ID");
            return -1;
        }
        memcpy(out->plan_id, rest + 1, D2K_PLAN_ID_LEN);
        memcpy(out->trial_id, rest + 1 + D2K_PLAN_ID_LEN, D2K_TRIAL_ID_LEN);
        if (rlen > 1+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN)
            out->client_shape = rest[1+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN];
        if (rlen > 2+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN &&
            execution_context(out, rest + 2+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN,
                              rlen - 2-D2K_PLAN_ID_LEN-D2K_TRIAL_ID_LEN)) {
            say(err, errcap, "повреждён контекст исполнения REFUSED");
            return -1;
        }
        break;
    case D2K_EV_LATE_OBS:
        /* Этап 49: итог наблюдения, сторона, повторы, токен — все обязательны. */
        if (rlen != 4 + D2K_TRIAL_ID_LEN || rest[0] > D2K_LATEOBS_UNAVAILABLE || rest[1] > D2K_CLIENT_SIDE_HIGH) {
            say(err, errcap, "повреждён итог позднего наблюдения");
            return -1;
        }
        out->code = rest[0];
        out->client_side = rest[1];
        out->num = (uint32_t)rest[2] << 8 | rest[3];
        memcpy(out->trial_id, rest + 4, D2K_TRIAL_ID_LEN);
        break;
    case D2K_EV_FLOW:
        /* Этап 42: сторона клиента необязательна по длине; вне диапазона —
           порча, а не «не известна». */
        if (rlen >= 1) {
            if (rest[0] > D2K_CLIENT_SIDE_HIGH) {
                say(err, errcap, "invalid observed client endpoint");
                return -1;
            }
            out->client_side = rest[0];
        }
        break;
    default:
        /* Вид события, которого этот модуль пока не разбирает глубже, —
           событие сообщение, а не обязательство: незнакомый вид не повод
           отказывать, ключ и kind уже разобраны. */
        break;
    }
    return 0;
}

int d2k_link_set_name(int fd, const char *name, uint8_t transport,
                      const char *plan_text, uint8_t shape, char *err, size_t errcap) {
    return d2k_link_set_name_probe(fd, name, transport, plan_text, shape, 0, err, errcap);
}

/* Ноль в sport_be означает постоянный SET_NAME. Ненулевой порт делает команду пробной
   (D2K_CMD_SET_NAME_PROBE): такой план достанется ровно одному потоку. */
int d2k_link_set_name_probe(int fd, const char *name, uint8_t transport,
                            const char *plan_text, uint8_t shape,
                            uint16_t sport_be, char *err, size_t errcap) {
    return d2k_link_set_name_family(fd, name, transport, plan_text, shape,
                                    sport_be, 4, err, errcap);
}

static int send_name_plan(int fd, const char *name, uint8_t transport,
                             const char *plan_text, uint8_t shape,
                             uint16_t sport_be, uint8_t family,
                             char *err, size_t errcap, uint16_t cmd,
                             const uint8_t *area_id) {
    if (family != 4 && family != 6) {
        say(err, errcap, "семейство адресов должно быть 4 или 6");
        return -1;
    }
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
    size_t extra = sport_be ? 2u : 0u;                  /* местный порт, если пробный */
    size_t seq_len = (cmd == D2K_CMD_SET_SUFFIX || cmd == D2K_CMD_SET_NAME_PROBE || cmd == D2K_CMD_SET_NAME_BOUND)
                         ? D2K_TRIAL_ID_LEN : 0;
    size_t plan_cap = sizeof g_scratch - HDR - 3 - nl - extra - seq_len;
    if (hexlen / 2 > plan_cap) {
        say(err, errcap, "план длиннее предела кадра");
        return -1;
    }

    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl;
    memcpy(g_scratch + o, name, nl);
    o += nl;
    /* ФОРМА ПРИВЕТСТВИЯ — байтом ПЕРЕД планом, а не после.
       Длина плана в теле не объявлена: план это «всё, что осталось». Поле
       после него было бы съедено как часть плана. */
    g_scratch[o++] = shape;
    g_scratch[o++] = family;
    if (sport_be) {
        memcpy(g_scratch + o, &sport_be, 2);
        o += 2;
    }
    long planlen = hex_decode(plan_text, g_scratch + o, sizeof g_scratch - o);
    if (planlen < 0) {
        say(err, errcap, "план не hex: недопустимый символ");
        return -1;
    }
    o += (size_t)planlen;
    if (seq_len) {
        memset(g_scratch+o, 0, seq_len);
        if (area_id) memcpy(g_scratch+o, area_id, seq_len);
        o += seq_len;
    }

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
    g_scratch[4] = (uint8_t)(cmd >> 8);
    g_scratch[5] = (uint8_t)cmd;

    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда SET_NAME не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_set_name_family(int fd, const char *name, uint8_t transport,
    const char *plan_text, uint8_t shape, uint16_t sport_be, uint8_t family,
    char *err, size_t errcap) {
    return send_name_plan(fd, name, transport, plan_text, shape, sport_be, family,
        err, errcap, sport_be ? D2K_CMD_SET_NAME_PROBE : D2K_CMD_SET_NAME, NULL);
}

int d2k_link_set_name_bound(int fd,const char *name,uint8_t transport,
    const char *plan_text,uint8_t shape,uint8_t family,const uint8_t token[16],char *err,size_t cap) {
    if(!token)return -1;
    return send_name_plan(fd,name,transport,plan_text,shape,0,family,err,cap,D2K_CMD_SET_NAME_BOUND,token);
}

int d2k_link_del_name_bound(int fd,const char *name,uint8_t transport,
    const d2k_binding_context *binding,char *err,size_t cap) {
    if(fd<0 || !name || !*name || strlen(name)>255 || (transport!=6 && transport!=17) ||
       !d2k_binding_known(binding) || binding->kind!=D2K_BIND_NAME || binding->temporary) return -1;
    size_t nl=strlen(name),o=HDR;
    g_scratch[o++]=(uint8_t)nl;memcpy(g_scratch+o,name,nl);o+=nl;
    g_scratch[o++]=transport;d2k_ctl_binding_write(g_scratch+o,binding);o+=D2K_CTL_BINDING_LEN;
    uint32_t n=(uint32_t)(o-4);
    for(unsigned i=0;i<4;i++)g_scratch[i]=(uint8_t)(n>>(24-8*i));
    g_scratch[4]=D2K_CMD_DEL_NAME_BOUND>>8;g_scratch[5]=(uint8_t)D2K_CMD_DEL_NAME_BOUND;
    if(write_all(fd,g_scratch,o)) {say(err,cap,"conditional name delete failed: %s",strerror(errno));return -1;}
    return 0;
}

int d2k_link_set_name_probe_trial(int fd, const char *name, uint8_t transport,
    const char *plan_text, uint8_t shape, uint16_t sport_be, uint8_t family,
    const uint8_t trial_id[D2K_TRIAL_ID_LEN], char *err, size_t errcap) {
    if (!sport_be) {
        say(err, errcap, "пробная установка без местного порта");
        return -1;
    }
    return send_name_plan(fd, name, transport, plan_text, shape, sport_be, family,
        err, errcap, D2K_CMD_SET_NAME_PROBE, trial_id);
}

static int area_context_valid(uint8_t transport, uint8_t shape, uint8_t family) {
    return (family == 4 || family == 6) &&
        ((transport == 6 && (shape == 1 || shape == 2 || shape == 6)) ||
         (transport == 17 && shape == 3));
}

int d2k_link_set_suffix_family(int fd, const char *name, uint8_t transport,
    const char *plan_text, uint8_t shape, uint8_t family, char *err, size_t errcap) {
    if (!area_context_valid(transport, shape, family)) {
        say(err, errcap, "неверный контекст семейства доменов"); return -1;
    }
    return send_name_plan(fd, name, transport, plan_text, shape, 0, family,
        err, errcap, D2K_CMD_SET_SUFFIX, NULL);
}

int d2k_link_set_https(int fd, const char *name, uint32_t ttl_s, char *err, size_t errcap) {
    size_t nl = name ? strlen(name) : 0;
    if (fd < 0 || nl == 0 || nl > 253) {
        say(err, errcap, "имя для HTTPS пусто или длиннее 253");
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl; memcpy(g_scratch + o, name, nl); o += nl;
    g_scratch[o++] = (uint8_t)(ttl_s >> 24); g_scratch[o++] = (uint8_t)(ttl_s >> 16);
    g_scratch[o++] = (uint8_t)(ttl_s >> 8); g_scratch[o++] = (uint8_t)ttl_s;
    uint32_t plen = (uint32_t)(o - HDR + 2);
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_SET_HTTPS >> 8); g_scratch[5] = (uint8_t)D2K_CMD_SET_HTTPS;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "SET_HTTPS не отправился: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_set_raw_probe(int fd,const struct d2k_rawmeasure_report *r,const uint8_t trial[16],
    uint32_t lease_ms,const char *plan_hex,char *err,size_t errcap) {
    if(fd<0||!d2k_rawmeasure_report_valid(r)||r->code!=D2K_RM_REPEAT_SILENT||
       !trial||!d2k_rm_nonzero(trial,16)||!lease_ms||lease_ms>D2K_ADDR_PROBE_LEASE_MAX_MS||
       !plan_hex||!*plan_hex) {say(err,errcap,"invalid measured trial context, lease or program");return -1;}
    const size_t fixed=D2K_RM_REPORT_LEN+20;
    if(d2k_rawmeasure_report_write(g_scratch+HDR,D2K_RM_REPORT_LEN,r))return -1;
    memcpy(g_scratch+HDR+D2K_RM_REPORT_LEN,trial,16);
    d2k_rm_put32(g_scratch+HDR+D2K_RM_REPORT_LEN+16,lease_ms);
    long n=hex_decode(plan_hex,g_scratch+HDR+fixed,sizeof g_scratch-HDR-fixed);
    if(n<=0||fixed+(size_t)n>D2K_CTL_FRAME_MAX-2) {say(err,errcap,"invalid or oversized measured trial program");return -1;}
    uint32_t plen=(uint32_t)(2+fixed+(size_t)n);d2k_rm_put32(g_scratch,plen);
    g_scratch[4]=(uint8_t)(D2K_CMD_SET_RAW_PROBE>>8);g_scratch[5]=(uint8_t)D2K_CMD_SET_RAW_PROBE;
    if(write_all(fd,g_scratch,HDR+fixed+(size_t)n)) {say(err,errcap,"measured trial send failed: %s",strerror(errno));return -1;}
    return 0;
}

int d2k_link_raw_measure(int fd, const struct d2k_rawmeasure_request *request,
                         char *err, size_t errcap) {
    if (fd < 0 || d2k_rawmeasure_request_write(g_scratch + HDR, D2K_RM_REQUEST_LEN, request) != 0) {
        say(err, errcap, "RAW_MEASURE: invalid connection identity or observation lease");
        return -1;
    }
    uint32_t plen = 2 + D2K_RM_REQUEST_LEN;
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_RAW_MEASURE >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_RAW_MEASURE;
    if (write_all(fd, g_scratch, HDR + D2K_RM_REQUEST_LEN) != 0) {
        say(err, errcap, "RAW_MEASURE send failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_late_observe(int fd, const d2k_ct_tuple *t, uint8_t seconds,
                          const uint8_t token[D2K_TRIAL_ID_LEN], char *err, size_t errcap) {
    if (fd < 0 || !t || !token || t->proto != 6 || (t->family != 4 && t->family != 6) || !seconds || seconds > 120) {
        say(err, errcap, "наблюдение позднего потока: неверный кортеж или срок");
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = t->family;
    g_scratch[o++] = t->proto;
    memset(g_scratch + o, 0, 32);
    memcpy(g_scratch + o, t->src, t->family == 6 ? 16 : 4); o += 16;
    memcpy(g_scratch + o, t->dst, t->family == 6 ? 16 : 4); o += 16;
    memcpy(g_scratch + o, t->sport_be, 2); o += 2;
    memcpy(g_scratch + o, t->dport_be, 2); o += 2;
    g_scratch[o++] = seconds;
    memcpy(g_scratch + o, token, D2K_TRIAL_ID_LEN); o += D2K_TRIAL_ID_LEN;
    uint32_t plen = (uint32_t)(o - HDR + 2);
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_LATE_OBSERVE >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_LATE_OBSERVE;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "LATE_OBSERVE не отправился: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_set_stall_budgets(int fd, const uint16_t *b, size_t n, char *err, size_t errcap) {
    if (fd < 0 || n > D2K_STALL_BUDGETS_MAX || (n && !b)) {
        say(err, errcap, "бюджетов потока больше %d или нет сокета", D2K_STALL_BUDGETS_MAX);
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) {
        if (!b[i]) { say(err, errcap, "нулевой бюджет потока"); return -1; }
        g_scratch[o++] = (uint8_t)(b[i] >> 8);
        g_scratch[o++] = (uint8_t)b[i];
    }
    uint32_t plen = (uint32_t)(o - HDR + 2);
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_SET_STALL_BUDGETS >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_SET_STALL_BUDGETS;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "SET_STALL_BUDGETS не отправился: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int send_area_key(int fd, uint16_t cmd, const char *name,
    uint8_t transport, uint8_t shape, uint8_t family, char *err, size_t errcap,
    const uint8_t *area_id) {
    if (fd < 0 || !name || !*name || strlen(name) > 253 ||
        !area_context_valid(transport, shape, family)) {
        say(err, errcap, "неверный ключ семейства доменов"); return -1;
    }
    size_t nl = strlen(name), o = HDR;
    g_scratch[o++] = (uint8_t)nl; memcpy(g_scratch+o, name, nl); o += nl;
    g_scratch[o++] = transport; g_scratch[o++] = shape; g_scratch[o++] = family;
    memset(g_scratch+o, 0, D2K_TRIAL_ID_LEN);
    if (area_id) memcpy(g_scratch+o, area_id, D2K_TRIAL_ID_LEN);
    o += D2K_TRIAL_ID_LEN;
    uint32_t plen = (uint32_t)(o-HDR+2);
    g_scratch[0] = (uint8_t)(plen>>24); g_scratch[1] = (uint8_t)(plen>>16);
    g_scratch[2] = (uint8_t)(plen>>8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(cmd>>8); g_scratch[5] = (uint8_t)cmd;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда семейства не отправилась: %s", strerror(errno)); return -1;
    }
    return 0;
}

int d2k_link_del_suffix_family(int fd, const char *name, uint8_t transport,
    uint8_t shape, uint8_t family, char *err, size_t errcap) {
    return send_area_key(fd, D2K_CMD_DEL_SUFFIX, name, transport, shape, family, err, errcap, NULL);
}
int d2k_link_set_bypass_family(int fd, const char *name, uint8_t transport,
    uint8_t shape, uint8_t family, char *err, size_t errcap) {
    return send_area_key(fd, D2K_CMD_SET_BYPASS, name, transport, shape, family, err, errcap, NULL);
}
int d2k_link_del_bypass_family(int fd, const char *name, uint8_t transport,
    uint8_t shape, uint8_t family, char *err, size_t errcap) {
    return send_area_key(fd, D2K_CMD_DEL_BYPASS, name, transport, shape, family, err, errcap, NULL);
}

int d2k_link_area_identified(int fd, uint16_t cmd, const char *name,
    uint8_t transport, uint8_t shape, uint8_t family, const char *plan_text,
    const uint8_t id[D2K_TRIAL_ID_LEN], char *err, size_t errcap) {
    if (!id || !area_context_valid(transport, shape, family)) return -1;
    if (cmd == D2K_CMD_SET_SUFFIX)
        return send_name_plan(fd, name, transport, plan_text, shape, 0, family,
            err, errcap, cmd, id);
    if (cmd != D2K_CMD_DEL_SUFFIX && cmd != D2K_CMD_SET_BYPASS && cmd != D2K_CMD_DEL_BYPASS)
        return -1;
    return send_area_key(fd, cmd, name, transport, shape, family, err, errcap, id);
}


/* Форма адресной привязки (v7): только измеренный протокол — TLS 1.3/1.2,
   ECH, QUIC, STUN/голос. Ноль и дедушкино право означали бы «подходит всем
   протоколам IP» (задача 16, D2K_SPEC §5); такая команда не собирается. */
/* Форма RAW (8) — доказанный путь без протокола (этапы 12/16); датапат её
   принимает (ctlsrv.c addr_shape_valid) и кладёт только на потоки без
   распознанного протокола. Дедушкино право и ноль по-прежнему не едут. */
static int addr_shape_ok(uint8_t shape) {
    return shape == 1 || shape == 2 || shape == D2K_LINK_SHAPE_QUIC ||
           shape == D2K_LINK_SHAPE_VOICE || shape == D2K_LINK_SHAPE_ECH_TCP ||
           shape == D2K_LINK_SHAPE_RAW;
}

int d2k_link_set_addr(int fd, const uint8_t ip4[4], uint8_t shape,
                      const char *plan_text, char *err, size_t errcap) {
    return d2k_link_set_addr_family(fd, ip4, 4, shape, plan_text, err, errcap);
}

static int link_set_address(int fd, const uint8_t *ip4, uint8_t family,
    uint8_t shape, uint16_t port_be, uint16_t cmd, const char *plan_text,
    const uint8_t *token,uint16_t dns_length,char *err,size_t errcap) {
    int dns=cmd==D2K_CMD_SET_DNS_ENDPOINT;
    int gate = cmd == D2K_CMD_SET_PREFLIGHT_TRIAL;
    int endpoint = cmd == D2K_CMD_SET_ENDPOINT || cmd == D2K_CMD_SET_ENDPOINT_BOUND || dns || gate;
    if (cmd == D2K_CMD_SET_ENDPOINT_BOUND && !token) return -1;
    if (endpoint && !port_be) {
        say(err, errcap, "service port is required");
        return -1;
    }
    if (fd < 0 || (family != 4 && family != 6)) {
        say(err, errcap, "сокет не открыт");
        return -1;
    }
    if (!ip4) {
        say(err, errcap, "адрес цели не задан");
        return -1;
    }
    if ((!dns && !addr_shape_ok(shape)) || (dns && (dns_length<17 || dns_length>274))) {
        say(err, errcap, "у адресной привязки нет формы протокола (%u)", (unsigned)shape);
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

    size_t o = HDR;
    g_scratch[o++] = family;
    memset(g_scratch + o, 0, 16);
    memcpy(g_scratch + o, ip4, family == 6 ? 16 : 4);
    o += 16;
    g_scratch[o++] = shape;
    if (endpoint) {
        memcpy(g_scratch + o, &port_be, 2);
        o += 2;
    }
    if (gate) {
        memcpy(g_scratch + o, &dns_length, 2);
        o += 2;
    } else if (dns) {
        g_scratch[o++]=(uint8_t)(dns_length>>8);
        g_scratch[o++]=(uint8_t)dns_length;
    }
    size_t tail = token ? D2K_TRIAL_ID_LEN : 0;
    long planlen = hex_decode(plan_text, g_scratch + o, sizeof g_scratch - o - tail);
    if (planlen < 0) {
        say(err, errcap, "план не hex: недопустимый символ");
        return -1;
    }
    o += (size_t)planlen;

    if (token) { memcpy(g_scratch + o,token,D2K_TRIAL_ID_LEN); o += D2K_TRIAL_ID_LEN; }

    size_t body_len = o - HDR;
    if (body_len > (size_t)D2K_CTL_FRAME_MAX - 2) {
        say(err, errcap, "команда длиннее предела кадра");
        return -1;
    }
    uint32_t plen = (uint32_t)(2 + body_len);
    g_scratch[0] = (uint8_t)(plen >> 24);
    g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);
    g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(cmd >> 8);
    g_scratch[5] = (uint8_t)cmd;

    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда адресной привязки не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_set_addr_family(int fd, const uint8_t *ip, uint8_t family,
    uint8_t shape, const char *plan_text, char *err, size_t errcap) {
    return link_set_address(fd, ip, family, shape, 0, D2K_CMD_SET_ADDR, plan_text, NULL,0,err, errcap);
}

int d2k_link_set_endpoint(int fd, const uint8_t *ip, uint8_t family,
    uint16_t port_be, uint8_t shape, const char *plan_text, char *err, size_t errcap) {
    return link_set_address(fd, ip, family, shape, port_be, D2K_CMD_SET_ENDPOINT, plan_text, NULL,0,err, errcap);
}

int d2k_link_set_dns_endpoint(int fd,const uint8_t *ip,uint8_t family,uint16_t port,
    uint16_t wire_length,const char *plan,const uint8_t request[D2K_TRIAL_ID_LEN],char *err,size_t cap) {
    if (!request)return -1;
    return link_set_address(fd,ip,family,D2K_LINK_SHAPE_DNS,port,D2K_CMD_SET_DNS_ENDPOINT,
        plan,request,wire_length,err,cap);
}

int d2k_link_set_endpoint_bound(int fd, const uint8_t *ip, uint8_t family,
    uint16_t port_be, uint8_t shape, const char *plan_text,
    const uint8_t token[D2K_TRIAL_ID_LEN], char *err, size_t errcap) {
    return link_set_address(fd,ip,family,shape,port_be,D2K_CMD_SET_ENDPOINT_BOUND,
                            plan_text,token,0,err,errcap);
}

int d2k_link_set_preflight_trial(int fd,const uint8_t *ip,uint8_t family,uint16_t port,uint16_t sport,
    uint8_t shape,const char *plan,const uint8_t token[D2K_TRIAL_ID_LEN],char *err,size_t errcap) {
    if (!sport || !token) return -1;
    return link_set_address(fd,ip,family,shape,port,D2K_CMD_SET_PREFLIGHT_TRIAL,plan,token,sport,err,errcap);
}

static int lease_command(uint16_t command,int fd,const d2k_pf_scope *scope,uint32_t lease_ms,
    const char *plan_hex,const uint8_t id[16],char *err,size_t cap) {
    if(fd<0||!scope||!id)return -1;
    size_t name_len=strlen(scope->name);
    if(!name_len||name_len>253)return -1;
    size_t o=HDR;
    g_scratch[o++]=scope->family;memset(g_scratch+o,0,16);memcpy(g_scratch+o,scope->client,scope->family==6?16:4);o+=16;
    memset(g_scratch+o,0,16);memcpy(g_scratch+o,scope->server,scope->family==6?16:4);o+=16;
    g_scratch[o++]=scope->shape;
    for(unsigned i=0;i<4;i++)g_scratch[o++]=(uint8_t)(scope->path>>(24-8*i));
    memcpy(g_scratch+o,&scope->server_port,2);o+=2;
    for(unsigned i=0;i<4;i++)g_scratch[o++]=(uint8_t)(lease_ms>>(24-8*i));
    g_scratch[o++]=(uint8_t)(name_len>>8);g_scratch[o++]=(uint8_t)name_len;
    memcpy(g_scratch+o,scope->name,name_len);o+=name_len;memcpy(g_scratch+o,id,16);o+=16;
    if(plan_hex) {
        long n=hex_decode(plan_hex,g_scratch+o,sizeof g_scratch-o);
        if(n<0){say(err,cap,"preflight lease plan is not hex");return -1;}o+=(size_t)n;
    }
    size_t body=o-HDR;if(body+2>D2K_CTL_FRAME_MAX){say(err,cap,"preflight lease frame too long");return -1;}
    uint32_t wire=(uint32_t)body+2;for(unsigned i=0;i<4;i++)g_scratch[i]=(uint8_t)(wire>>(24-8*i));
    g_scratch[4]=command>>8;g_scratch[5]=command&255;
    if(write_all(fd,g_scratch,o)){say(err,cap,"preflight lease command: %s",strerror(errno));return -1;}
    return 0;
}
int d2k_link_set_preflight_lease(int fd,const d2k_pf_scope *scope,uint32_t lease_ms,
    const char *plan,const uint8_t id[16],char *err,size_t cap) {
    return lease_command(D2K_CMD_SET_PREFLIGHT_LEASE,fd,scope,lease_ms,plan,id,err,cap);
}
int d2k_link_del_preflight_lease(int fd,const d2k_pf_scope *scope,const uint8_t id[16],char *err,size_t cap) {
    return lease_command(D2K_CMD_DEL_PREFLIGHT_LEASE,fd,scope,0,NULL,id,err,cap);
}

static int endpoint_trial_command(uint16_t command,int fd,const uint8_t *ip,uint8_t family,
    uint16_t port,uint8_t shape,const uint8_t trial[16],char *err,size_t cap) {
    uint8_t any=0;
    if(!trial)return -1;
    for(unsigned i=0;i<16;i++)any|=trial[i];
    if(fd<0 || !ip || (family!=4 && family!=6) || !port || !addr_shape_ok(shape) || !any)return -1;
    size_t o=HDR;
    g_scratch[o++]=family;memset(g_scratch+o,0,16);memcpy(g_scratch+o,ip,family==6?16:4);o+=16;
    g_scratch[o++]=shape;memcpy(g_scratch+o,&port,2);o+=2;
    memcpy(g_scratch+o,trial,16);o+=16;
    uint32_t n=(uint32_t)o-4;
    for(unsigned i=0;i<4;i++)g_scratch[i]=(uint8_t)(n>>(24-8*i));
    g_scratch[4]=command>>8;g_scratch[5]=command&255;
    if(write_all(fd,g_scratch,o)){say(err,cap,"endpoint trial cleanup: %s",strerror(errno));return -1;}
    return 0;
}

int d2k_link_del_endpoint_trial(int fd,const uint8_t *ip,uint8_t family,uint16_t port,
    uint8_t shape,const uint8_t trial[16],char *err,size_t cap) {
    return endpoint_trial_command(D2K_CMD_DEL_ENDPOINT_TRIAL,fd,ip,family,port,shape,trial,err,cap);
}
int d2k_link_commit_endpoint_trial(int fd,const uint8_t *ip,uint8_t family,uint16_t port,
    uint8_t shape,const uint8_t trial[16],char *err,size_t cap) {
    return endpoint_trial_command(D2K_CMD_COMMIT_ENDPOINT_TRIAL,fd,ip,family,port,shape,trial,err,cap);
}

/* Адреса — 4 байта для IPv4 и 16 для IPv6: параметры объявлены указателями,
   а не [4], иначе GCC видит чтение 16 байт за границей объявленного массива. */
static int addr_probe_flow_bytes(uint8_t *p, const uint8_t *src_ip4, uint16_t src_port_be,
                                 const uint8_t *dst_ip4, uint16_t dst_port_be,
                                 uint8_t transport, uint8_t family) {
    /* src_port_be 0 — голосовой опыт на любой клиентский порт (задача 15). */
    if (!src_ip4 || !dst_ip4 || !dst_port_be || (transport != 6 && transport != 17) || (transport==6 && !src_port_be) ||
        (family != 4 && family != 6)) { return -1; }
    memset(p, 0, 38);
    p[0] = family;
    memcpy(p + 1, src_ip4, family == 6 ? 16 : 4);
    memcpy(p + 17, dst_ip4, family == 6 ? 16 : 4);
    memcpy(p + 33, &src_port_be, 2);
    memcpy(p + 35, &dst_port_be, 2);
    p[37] = transport;
    return 0;
}

int d2k_link_set_addr_probe(int fd, const uint8_t src_ip4[4], uint16_t src_port_be,
                            const uint8_t dst_ip4[4], uint16_t dst_port_be,
                            uint8_t transport, const uint8_t trial_id[D2K_TRIAL_ID_LEN],
                            uint32_t lease_ms, const char *plan_hex,
                            char *err, size_t errcap) {
    return d2k_link_set_addr_probe_family(fd, src_ip4, src_port_be, dst_ip4,
        dst_port_be, transport, 4, trial_id, lease_ms, plan_hex, err, errcap);
}

static int link_set_flow_probe(uint16_t command,int fd, const uint8_t *src_ip4, uint16_t src_port_be,
    const uint8_t *dst_ip4, uint16_t dst_port_be, uint8_t transport, uint8_t family,
    const uint8_t trial_id[D2K_TRIAL_ID_LEN], uint32_t lease_ms,
    const char *plan_hex,uint16_t dns_length,const uint8_t *digest,char *err,size_t errcap) {
    int dns=command==D2K_CMD_SET_DNS_PROBE;
    const char *command_name=dns ? "SET_DNS_PROBE" : "SET_ADDR_PROBE";
    if ((!dns && transport!=17) || (dns && (!src_port_be || !digest ||
         dns_length<(transport==6 ? 19 : 17) || dns_length>274)) || fd < 0 || !trial_id || !lease_ms || lease_ms > D2K_ADDR_PROBE_LEASE_MAX_MS || !plan_hex ||
        addr_probe_flow_bytes(g_scratch + HDR, src_ip4, src_port_be,
                              dst_ip4, dst_port_be, transport, family) != 0) {
        say(err, errcap, "аргументы %s негодны", command_name);
        return -1;
    }
    uint8_t any = 0;
    for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) { any |= trial_id[i]; }
    if (!any) { say(err, errcap, "trial_id не может быть нулевым"); return -1; }
    size_t o = HDR + D2K_ADDR_PROBE_FLOW_WIRE_LEN;
    memcpy(g_scratch + o, trial_id, D2K_TRIAL_ID_LEN); o += D2K_TRIAL_ID_LEN;
    g_scratch[o++] = (uint8_t)(lease_ms >> 24);
    g_scratch[o++] = (uint8_t)(lease_ms >> 16);
    g_scratch[o++] = (uint8_t)(lease_ms >> 8);
    g_scratch[o++] = (uint8_t)lease_ms;
    if (dns) {
        g_scratch[o++]=(uint8_t)(dns_length>>8);
        g_scratch[o++]=(uint8_t)dns_length;
        memcpy(g_scratch+o,digest,32);o+=32;
    }
    size_t hexlen = strlen(plan_hex);
    if (hexlen & 1u) { say(err, errcap, "план %s не hex", command_name); return -1; }
    long decoded = hex_decode(plan_hex, g_scratch + o, sizeof g_scratch - o);
    if (decoded < 0) { say(err, errcap, "план %s не hex", command_name); return -1; }
    o += (size_t)decoded;
    size_t body_len = o - HDR;
    if (body_len > (size_t)D2K_CTL_FRAME_MAX - 2) { say(err, errcap, "%s длиннее кадра", command_name); return -1; }
    uint32_t plen = (uint32_t)(2 + body_len);
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(command >> 8); g_scratch[5] = (uint8_t)command;
    if (write_all(fd, g_scratch, o) != 0) { say(err, errcap, "%s: %s", command_name, strerror(errno)); return -1; }
    return 0;
}

int d2k_link_set_addr_probe_family(int fd,const uint8_t *src,uint16_t sport,
    const uint8_t *dst,uint16_t dport,uint8_t transport,uint8_t family,
    const uint8_t trial[16],uint32_t lease,const char *plan,char *err,size_t cap) {
    return link_set_flow_probe(D2K_CMD_SET_ADDR_PROBE,fd,src,sport,dst,dport,
        transport,family,trial,lease,plan,0,NULL,err,cap);
}

int d2k_link_set_dns_probe(int fd,const uint8_t *src,uint16_t sport,
    const uint8_t *dst,uint16_t dport,uint8_t transport,uint8_t family,
    const uint8_t trial[16],uint32_t lease,const char *plan,uint16_t length,
    const uint8_t digest[32],char *err,size_t cap) {
    return link_set_flow_probe(D2K_CMD_SET_DNS_PROBE,fd,src,sport,dst,dport,
        transport,family,trial,lease,plan,length,digest,err,cap);
}

int d2k_link_del_addr_probe(int fd, const uint8_t src_ip4[4], uint16_t src_port_be,
                            const uint8_t dst_ip4[4], uint16_t dst_port_be,
                            uint8_t transport, const uint8_t trial_id[D2K_TRIAL_ID_LEN],
                            char *err, size_t errcap) {
    return d2k_link_del_addr_probe_family(fd, src_ip4, src_port_be, dst_ip4,
        dst_port_be, transport, 4, trial_id, err, errcap);
}

int d2k_link_del_addr_probe_family(int fd, const uint8_t *src_ip4, uint16_t src_port_be,
    const uint8_t *dst_ip4, uint16_t dst_port_be, uint8_t transport, uint8_t family,
    const uint8_t trial_id[D2K_TRIAL_ID_LEN], char *err, size_t errcap) {
    if (fd < 0 || !trial_id || addr_probe_flow_bytes(g_scratch + HDR, src_ip4,
        src_port_be, dst_ip4, dst_port_be, transport, family) != 0) {
        say(err, errcap, "аргументы DEL_ADDR_PROBE негодны"); return -1;
    }
    uint8_t any = 0;
    for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) { any |= trial_id[i]; }
    if (!any) { say(err, errcap, "trial_id не может быть нулевым"); return -1; }
    size_t o = HDR + 38;
    memcpy(g_scratch + o, trial_id, D2K_TRIAL_ID_LEN); o += D2K_TRIAL_ID_LEN;
    uint32_t plen = (uint32_t)(2 + o - HDR);
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_DEL_ADDR_PROBE >> 8); g_scratch[5] = (uint8_t)D2K_CMD_DEL_ADDR_PROBE;
    if (write_all(fd, g_scratch, o) != 0) { say(err, errcap, "DEL_ADDR_PROBE: %s", strerror(errno)); return -1; }
    return 0;
}

int d2k_link_arm_shape(int fd, const char *name, uint8_t transport,
                       char *err, size_t errcap) {
    return d2k_link_arm_shape_family(fd, name, transport, 4, err, errcap);
}

int d2k_link_arm_shape_family(int fd, const char *name, uint8_t transport,
                              uint8_t family, char *err, size_t errcap) {
    return d2k_link_arm_shape_request(fd, name, transport, family, NULL, err, errcap);
}

int d2k_link_fence(int fd,const uint8_t token[16],char *err,size_t cap) {
    if(fd<0 || !token)return -1;
    uint8_t frame[6+3+16]={0};frame[3]=sizeof frame-4;
    frame[4]=D2K_CMD_ARM_SHAPE>>8;frame[5]=(uint8_t)D2K_CMD_ARM_SHAPE;
    /* len(name)=0, transport=0, family=0: rejected before session mutation. */
    memcpy(frame+9,token,16);
    if(write_all(fd,frame,sizeof frame)) {say(err,cap,"control fence failed: %s",strerror(errno));return -1;}
    return 0;
}

int d2k_link_arm_shape_request(int fd, const char *name, uint8_t transport,
                              uint8_t family, const uint8_t request_id[16],
                              char *err, size_t errcap) {
    /* Своё тело, а не send_name_only: за именем едет ТРАНСПОРТ. Снимок
       приветствия датапат хранит отдельно на транспорт, и без этого байта он
       отдал бы QUIC-задаче байты TLS (d2k_session_want_shape). */
    if (fd < 0 || (family != 4 && family != 6) || (transport != 6 && transport != 17)) {
        say(err, errcap, "сокет не открыт");
        return -1;
    }
    if (!name) { name = ""; }
    size_t nl = strlen(name);
    if (nl > 255) {
        say(err, errcap, "имя цели длиной %zu байт длиннее 255", nl);
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl;
    memcpy(g_scratch + o, name, nl);
    o += nl;
    g_scratch[o++] = transport;
    g_scratch[o++] = family;

    if (request_id) {
        uint8_t any = 0;
        for (size_t i = 0; i < 16; i++) any |= request_id[i];
        if (!any) { say(err, errcap, "snapshot request ID is zero"); return -1; }
        memcpy(g_scratch + o, request_id, 16);
        o += 16;
    }

    size_t body_len = o - HDR;
    uint32_t plen = (uint32_t)(2 + body_len);
    g_scratch[0] = (uint8_t)(plen >> 24);
    g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);
    g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_ARM_SHAPE >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_ARM_SHAPE;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда ARM_SHAPE не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_del_name_family(int fd, const char *name, uint8_t transport,
                             uint8_t shape, uint8_t family,
                             char *err, size_t errcap) {
    /* v9: ключ постоянной записи целиком — имя, транспорт, форма, семейство.
       Пробы этой командой не снимаются (задача 21). */
    if (fd < 0 || !name || (family != 4 && family != 6) ||
        (transport != 6 && transport != 17) || shape == 0) {
        say(err, errcap, "сокет, транспорт, форма или семейство снятия не заданы");
        return -1;
    }
    size_t nl = strlen(name);
    if (nl == 0 || nl > 255) {
        say(err, errcap, "недопустимая длина имени снятия");
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl;
    memcpy(g_scratch + o, name, nl); o += nl;
    g_scratch[o++] = transport;
    g_scratch[o++] = shape;
    g_scratch[o++] = family;
    uint32_t plen = (uint32_t)(2 + (o - HDR));
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);  g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_DEL_NAME >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_DEL_NAME;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда DEL_NAME не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_del_name_probe(int fd, const char *name, uint8_t transport,
                            uint8_t shape, uint16_t sport_be,
                            char *err, size_t errcap) {
    return d2k_link_del_name_probe_family(fd, name, transport, shape, sport_be, 4, err, errcap);
}

static int del_name_probe_if(int fd,const char *name,uint8_t transport,
                            uint8_t shape,uint16_t sport_be,uint8_t family,
                            const uint8_t *trial,char *err,size_t errcap) {
    (void)transport; /* transport is represented by the wire shape */
    if (fd < 0 || !name || sport_be == 0 || (family != 4 && family != 6)) {
        say(err, errcap, "сокет, имя или порт пробного плана не задан");
        return -1;
    }
    size_t nl = strlen(name);
    if (nl == 0 || nl > 255) {
        say(err, errcap, "недопустимая длина имени пробного плана");
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl;
    memcpy(g_scratch + o, name, nl); o += nl;
    g_scratch[o++] = shape;
    g_scratch[o++] = family;
    memcpy(g_scratch + o, &sport_be, 2); o += 2;
    if(trial) {memcpy(g_scratch+o,trial,D2K_TRIAL_ID_LEN);o+=D2K_TRIAL_ID_LEN;}
    uint32_t plen = (uint32_t)(2 + (o - HDR));
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);  g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_DEL_NAME_PROBE >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_DEL_NAME_PROBE;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "DEL_NAME_PROBE не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_del_name_probe_family(int fd,const char *name,uint8_t transport,
                                  uint8_t shape,uint16_t sport_be,uint8_t family,
                                  char *err,size_t errcap) {
    return del_name_probe_if(fd,name,transport,shape,sport_be,family,NULL,err,errcap);
}

int d2k_link_del_name_probe_trial(int fd,const char *name,uint8_t transport,
    uint8_t shape,uint16_t sport_be,uint8_t family,const uint8_t trial[D2K_TRIAL_ID_LEN],
    char *err,size_t errcap) {
    uint8_t any=0;
    if(trial)for(size_t i=0;i<D2K_TRIAL_ID_LEN;i++)any|=trial[i];
    if(!any || !shape || (transport!=6 && transport!=17)) {
        say(err,errcap,"conditional probe cleanup requires trial, shape and transport");return -1;
    }
    return del_name_probe_if(fd,name,transport,shape,sport_be,family,trial,err,errcap);
}

int d2k_link_del_addr(int fd, const uint8_t ip4[4], uint8_t shape,
                      char *err, size_t errcap) {
    return d2k_link_del_addr_family(fd, ip4, 4, shape, err, errcap);
}

int d2k_link_del_addr_family(int fd, const uint8_t *ip4, uint8_t family,
    uint8_t shape, char *err, size_t errcap) {
    if (fd < 0 || !ip4 || (family != 4 && family != 6)) {
        say(err, errcap, "сокет не открыт или адрес цели не задан");
        return -1;
    }
    if (!addr_shape_ok(shape)) {
        say(err, errcap, "у адресной привязки нет формы протокола (%u)", (unsigned)shape);
        return -1;
    }
    uint8_t frame[HDR + 18] = {0, 0, 0, 20,
        (uint8_t)(D2K_CMD_DEL_ADDR >> 8), (uint8_t)D2K_CMD_DEL_ADDR};
    frame[HDR] = family;
    memcpy(frame + HDR + 1, ip4, family == 6 ? 16 : 4);
    frame[HDR + 17] = shape;
    if (write_all(fd, frame, sizeof frame) != 0) {
        say(err, errcap, "команда DEL_ADDR не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}


int d2k_link_del_endpoint(int fd, const uint8_t *ip, uint8_t family,
    uint16_t port_be, uint8_t shape, char *err, size_t errcap) {
    if (fd < 0 || !ip || (family != 4 && family != 6) || !port_be || shape == D2K_LINK_SHAPE_RAW || !addr_shape_ok(shape)) {
        say(err, errcap, "invalid service endpoint");
        return -1;
    }
    uint8_t frame[HDR + 20] = {0, 0, 0, 22,
        (uint8_t)(D2K_CMD_DEL_ENDPOINT >> 8), (uint8_t)D2K_CMD_DEL_ENDPOINT};
    frame[HDR] = family;
    memcpy(frame + HDR + 1, ip, family == 6 ? 16 : 4);
    frame[HDR + 17] = shape;
    memcpy(frame + HDR + 18, &port_be, 2);
    if (write_all(fd, frame, sizeof frame) != 0) {
        say(err, errcap, "DEL_ENDPOINT: %s", strerror(errno));
        return -1;
    }
    return 0;
}


static int link_del_endpoint_transport(int fd,const uint8_t *ip,uint8_t family,
    uint16_t port_be,uint8_t transport,uint8_t shape,char *err,size_t errcap) {
    if (fd < 0 || !ip || (family != 4 && family != 6) || !port_be ||
        (transport != 6 && transport != 17)) {
        say(err, errcap, "invalid service transport or endpoint");
        return -1;
    }
    uint8_t frame[HDR + 21] = {0, 0, 0, 23,
        (uint8_t)(D2K_CMD_DEL_ENDPOINT >> 8), (uint8_t)D2K_CMD_DEL_ENDPOINT};
    frame[HDR] = family;
    memcpy(frame + HDR + 1, ip, family == 6 ? 16 : 4);
    frame[HDR + 17] = shape;
    memcpy(frame + HDR + 18, &port_be, 2);
    frame[HDR + 20] = transport;
    if (write_all(fd, frame, sizeof frame) != 0) {
        say(err, errcap, "DEL_ENDPOINT: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_del_raw_endpoint(int fd,const uint8_t *ip,uint8_t family,
    uint16_t port,uint8_t transport,char *err,size_t cap) {
    return link_del_endpoint_transport(fd,ip,family,port,transport,D2K_LINK_SHAPE_RAW,err,cap);
}

int d2k_link_del_dns_endpoint(int fd,const uint8_t *ip,uint8_t family,
    uint16_t port,uint8_t transport,char *err,size_t cap) {
    return link_del_endpoint_transport(fd,ip,family,port,transport,D2K_LINK_SHAPE_DNS,err,cap);
}

int d2k_ev_outer_appdata(const d2k_ev *ev) {
    /* ВНЕШНИЙ тип записи, а не тип ПЕРВОЙ записи (code — липкое поле, см.
     * большой комментарий у seen_types в d2k_link.h) и не любые вернувшиеся
     * байты. Внешним типом 23 в TLS 1.3 едет и второй полёт рукопожатия
     * (RFC 8446 §5.2), поэтому ответ этой функции — наблюдение уровня 2
     * (§4.2), а порог каталога живёт в планировщике (см. объявление в
     * d2k_link.h). Зеркало Go-донора HasAppData: маска, а не сравнение с
     * одним значением — иначе uint8_t seen_types молча продвинулся бы до
     * uint16_t и сравнился с типом записи, что почти всегда даёт ложь без
     * единого предупреждения компилятора. ev == NULL — не событие, внешнего
     * типа 23 в нём нет по определению, а не неопределённое поведение. */
    if (!ev) {
        return 0;
    }
    return (ev->seen_types & (uint8_t)(1u << (D2K_TLS_APPLICATION_DATA - 20))) != 0 ? 1 : 0;
}
