/* Файл включают и как текст в составные тесты — после системных заголовков,
   где glibc (с 2026) уже задал _POSIX_C_SOURCE сам: голый #define там —
   переопределение под -Werror (CI 22.10.2026). Отдельной единицей трансляции
   значение задаётся как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* SO_MARK — НЕ POSIX, и под строгим _POSIX_C_SOURCE библиотека его ПРЯЧЕТ.
 * Молча: #ifdef не срабатывает, компилятор не ругается, метка просто не
 * ставится ни на одном зонде — и замер меряет наш же обход поверх коробки.
 * Та же причина и то же лекарство, что в core/meas.c и datapath/raw.c.
 * Ловится это только счётчиком iptables, то есть уже на роутере. */
#define _DEFAULT_SOURCE 1

/* classify.c — дерево зондов: перенос internal/classify/classify.go (Run,
 * measure, once, splitOffsets, sweepPoisons) на C, дословно.
 *
 * Постановка та же, что в эталоне, и повторять её здесь незачем — она
 * записана в шапке пакета classify и в D2K_SPEC.md §1. Коротко: DPI это
 * функция «байты соединения → пропустить или убить», её зондируют напрямую,
 * меняя ТОЛЬКО способ записи одного и того же триггера, и из формы отклика
 * читают структуру матчера.
 *
 * ТЕКСТЫ ВЕРДИКТОВ И ИМЕНА НАБЛЮДЕНИЙ — ЧАСТЬ КОНТРАКТА. Они сверяются с
 * выводом эталона побайтно (см. tests/compare.sh), поэтому переписывать их
 * «покрасивее» нельзя: расхождение здесь — дефект переноса.
 */
#include "d2k_detect.h"
#include "d2k_preflight_probe.h"

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_MARK
#define SO_MARK 36
#endif
/* Роутеры — Linux: без TIOCOUTQ вопрос neutral-ack молча выродился бы в
 * «не наблюдается», и замер вернулся бы к перебору по таймаутам (задача 54).
 * Пусть это будет видно в день сборки, а не в поле. */
#if defined(__linux__) && !defined(TIOCOUTQ)
#error "TIOCOUTQ не определён: подтверждение данных (neutral-ack) не наблюдается"
#endif
#if defined(__APPLE__) && !defined(SO_NWRITE)
#define SO_NWRITE 0x1024 /* скрыт строгим _POSIX_C_SOURCE */
#endif

const char *d2k_verdict_name(d2k_verdict_t v)
{
    switch (v) {
    case D2K_DV_CLEAR:        return "clear";
    case D2K_DV_PREFIX:       return "prefix";
    case D2K_DV_WHOLE_PACKET: return "whole_packet";
    case D2K_DV_OPAQUE:       return "opaque";
    case D2K_DV_INCONCLUSIVE: return "inconclusive";
    case D2K_DV_ADDRESS:      return "address";
    case D2K_DV_POISONABLE:   return "poisonable";
    case D2K_DV_FLAKY:        return "flaky";
    case D2K_DV_UNREACHABLE:  return "unreachable";
    case D2K_DV_RESPONSE_GATE: return "response_gate";
    case D2K_DV_RESPONSE:     return "response";
    default:                 return "";
    }
}

const char *d2k_resp_name(d2k_resp_verdict v)
{
    switch (v) {
    case D2K_RESP_CLEAR:   return "clear";
    case D2K_RESP_BLOCKED: return "blocked";
    case D2K_RESP_FLAKY:   return "flaky";
    default:               return "not_applicable";
    }
}

int64_t d2k_clock_offset_ms;

int64_t d2k_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000L) + d2k_clock_offset_ms;
}
/* Ширина закреплена при сборке: кросс-сборка под mipsel упадёт здесь, если
 * часы снова станут long. */
typedef char d2k_now_ms_is_64bit[sizeof(d2k_now_ms()) == 8 ? 1 : -1];

void d2k_sleep_ms(int ms)
{
    struct timespec ts;
    if (ms <= 0) {
        return;
    }
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}
int d2k_sleep_us(uint32_t us)
{
    struct timespec left={.tv_sec=us/1000000u,.tv_nsec=(long)(us%1000000u)*1000L};
    while(nanosleep(&left,&left))if(errno!=EINTR)return -1;
    return 0;
}

/* Доказательством прохода считается ТОЛЬКО то, что назвал триггер.
 * Пустой ответ доказательством НЕ является ни при каком accept. */
size_t d2k_trigger_prefix_size(const d2k_trigger *t)
{
    switch (t->accept) {
    case D2K_ACCEPT_SERVERHELLO: return 6;
    case D2K_ACCEPT_TLSRECORD: return 3;
    default: return 1;
    }
}

int d2k_trigger_accepts(
const d2k_trigger *t, const uint8_t *b, size_t n)
{
    switch (t->accept) {
    case D2K_ACCEPT_SERVERHELLO:
        /* Фатальный алерт сюда не годится, хотя это тоже ответ: его
         * инжектируют и сами коробки, и засчитав его за успех мы объявили бы
         * блокировку обходом. */
        return n >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x02;
    case D2K_ACCEPT_TLSRECORD:
        /* Сервер, отвечающий отказом на незнакомое имя, — это всё равно
         * сервер, до которого дошли. Тишина означает, что не дошло ничего. */
        return n >= 3 && (b[0] == 0x16 || b[0] == 0x15) && b[1] == 0x03;
    default:
        return n > 0;
    }
}

const char *d2k_trigger_sni(const d2k_trigger *t)
{
    static const char pfx[] = "tls:";
    size_t n = sizeof(pfx) - 1;
    if (strlen(t->name) > n && strncmp(t->name, pfx, n) == 0) {
        return t->name + n;
    }
    return "";
}

int d2k_detect_stopped(const d2k_detect_stop *c)
{
    return c && c->fn && c->fn(c->ctx);
}

void d2k_opts_defaults(d2k_opts *o)
{
    if (o->repeats <= 0) {
        /* Вердикт выносится только при единогласии: одна случайная потеря
         * пакета иначе назначила бы границу сигнатуры не туда. */
        o->repeats = 3;
    }
    if (o->timeout_ms <= 0) {
        /* Блокировка проявляется молчанием, поэтому это НИЖНЯЯ граница
         * длительности каждого неудачного зонда. */
        o->timeout_ms = 6000;
    }
    if (o->write_gap_ms <= 0) {
        o->write_gap_ms = 60;
    }
    if (o->long_gap_ms <= 0) {
        o->long_gap_ms = 700;
    }
    if (o->mark == 0) {
        o->mark = D2K_BYPASS_MARK;
    }
}

int d2k_opts_acceptable(const d2k_opts *o, const d2k_poison *p)
{
    if (!o->accept) {
        return 1;
    }
    return o->accept(p, o->accept_ctx);
}

int d2k_opts_skipped(const d2k_opts *o, const char *name)
{
    int i;
    for (i = 0; i < o->nskip; i++) {
        if (strcmp(o->skip[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

d2k_obs *d2k_trace_add(d2k_result *res, const char *probe)
{
    d2k_obs *o;
    size_t n;
    /* The live observer records every completed observation. Once the
     * diagnostic array fills, reuse its last slot without stale labels/counts. */
    o = res->ntrace >= D2K_TRACE_MAX
        ? &res->trace[D2K_TRACE_MAX - 1] : &res->trace[res->ntrace++];
    memset(o, 0, sizeof(*o));
    /* Копия с явной границей, а не snprintf: имя зонда приходит из разных
     * мест (гипотеза, свойство, собранный кандидат), длину его ни один
     * анализатор не выводит, и -Werror=format-truncation на mipsel-gcc
     * останавливал сборку на ровном месте. Обрезка здесь по построению
     * невозможна — имена короче поля, — но полагаться на это молча нельзя. */
    n = strlen(probe);
    if (n >= sizeof(o->probe)) {
        n = sizeof(o->probe) - 1;
    }
    memcpy(o->probe, probe, n);
    o->probe[n] = '\0';
    return o;
}

/* Наблюдение закончено: записано в трассу и объявлено наружу. Одна функция на
 * все пять мест, где зонды заканчиваются, — иначе очередное место молча
 * осталось бы без строки, и «тишина в журнале» опять значила бы два разных
 * состояния. */
static void obs_done(const d2k_opts *opt, const d2k_obs *o)
{
    if (opt->on_obs) {
        opt->on_obs(opt->on_obs_ctx, o);
    }
}

void d2k_note(d2k_result *res, const char *fmt, ...)
{
    va_list ap;
    if (res->nnotes >= D2K_NOTES_MAX) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(res->notes[res->nnotes], sizeof(res->notes[0]), fmt, ap);
    va_end(ap);
    res->nnotes++;
}

/* noteGapLoss предупреждает, что найденный приём опирался на ПАУЗУ между
 * копиями фальшивки, а движок такую паузу выразить не умеет.
 *
 * Проверено по первоисточнику форка: у функции fake аргумента задержки нет,
 * число копий разворачивается в плотный цикл rawsend_rep без ожидания, а delay
 * есть только у send — и та откладывает копию НАСТОЯЩЕГО пакета.
 *
 * Молчать нельзя: собственный замер показал, что порог копий зависит от паузы
 * (порог 7 оказался артефактом нулевой паузы, при 20 мс хватает двух). */
static void note_gap_loss(d2k_result *res, const d2k_poison *p)
{
    if (p->gap_ms <= 0) {
        return;
    }
    d2k_note(res,
             "приём сработал с паузой %d мс между копиями фальшивки, а движок паузу выразить "
             "не умеет: в строке копии идут вплотную. Если обход не встанет — дело может быть "
             "именно в этом", p->gap_ms);
}

/* splitOffsets превращает список точек разреза в куски. Точки вне (0, len)
 * отбрасываются: разрез в нуле и в конце — это не разрез. */
typedef struct { int from, to; } d2k_span;

int d2k_split_offsets(const int *cuts, int ncuts, int n, d2k_span *out, int cap)
{
    int cl[8];
    int k = 0, i, j, prev = 0, used = 0;

    for (i = 0; i < ncuts && k < (int)(sizeof(cl) / sizeof(cl[0])); i++) {
        if (cuts[i] > 0 && cuts[i] < n) {
            cl[k++] = cuts[i];
        }
    }
    for (i = 1; i < k; i++) { /* сортировка вставками: точек единицы */
        int v = cl[i];
        for (j = i - 1; j >= 0 && cl[j] > v; j--) {
            cl[j + 1] = cl[j];
        }
        cl[j + 1] = v;
    }
    for (i = 0; i < k; i++) {
        if (cl[i] == prev) {
            continue;
        }
        if (used < cap) {
            out[used].from = prev;
            out[used].to = cl[i];
            used++;
        }
        prev = cl[i];
    }
    if (used < cap) {
        out[used].from = prev;
        out[used].to = n;
        used++;
    }
    return used;
}

/* Соединение для сокетных зондов. Та же метка, что и на сырых: сокетные зонды
 * (целиком, разрез, контроль) обязаны идти мимо десинка ровно так же, иначе
 * половина дерева меряет одно, половина другое. */
static int dial_marked_mode(const char *host, const char *port, int timeout_ms,
                       uint32_t mark, char *err, size_t errcap, int require_mark)
{
    struct addrinfo hints, *ai = NULL, *p;
    int fd = -1, rc;

    if (errcap) err[0] = '\0';
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = strchr(host, ':') ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, port, &hints, &ai);
    if (rc != 0 || !ai) {
        snprintf(err, errcap, "dial tcp: %s", gai_strerror(rc));
        return -1;
    }
    for (p = ai; p; p = p->ai_next) {
        int mk = (int)mark;
        int one = 1;
        int fl;
        struct pollfd pfd;
        int soerr = 0;
        socklen_t sl = sizeof(soerr);

        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int marked = setsockopt(fd, SOL_SOCKET, SO_MARK, &mk, sizeof(mk));
        if (require_mark && mark && marked != 0) {
            snprintf(err, errcap, "transport control: SO_MARK: %s", strerror(errno));
            close(fd); freeaddrinfo(ai); return -1;
        }
        /* Без этого ядро склеит наши записи в один сегмент, и весь замер
         * превратится в измерение самого себя. */
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        fl = fcntl(fd, F_GETFL, 0);
        (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            (void)fcntl(fd, F_SETFL, fl);
            freeaddrinfo(ai);
            return fd;
        }
        if (errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        if (poll(&pfd, 1, timeout_ms) <= 0) {
            snprintf(err, errcap, "dial tcp %s:%s: i/o timeout", host, port);
            close(fd);
            fd = -1;
            continue;
        }
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) {
            snprintf(err, errcap, "dial tcp %s:%s: %s", host, port,
                     strerror(soerr ? soerr : errno));
            close(fd);
            fd = -1;
            continue;
        }
        (void)fcntl(fd, F_SETFL, fl);
        freeaddrinfo(ai);
        return fd;
    }
    freeaddrinfo(ai);
    if (err[0] == '\0') {
        snprintf(err, errcap, "dial tcp %s:%s: %s", host, port, strerror(errno));
    }
    return -1;
}

/* Правило «наш срок или ответ линии» — одно на все места. Шапка у
   объявления в d2k_detect.h. */
int d2k_dial_deadline_err(const char *err)
{
    if (!err || !err[0]) {
        return 0;
    }
    return strncmp(err, "dial tcp ", 9) == 0 && strstr(err, ": i/o timeout") != NULL;
}

static int dial_marked(const char *host, const char *port, int timeout_ms,
                       uint32_t mark, char *err, size_t errcap)
{
    return dial_marked_mode(host, port, timeout_ms, mark, err, errcap, 0);
}

/* One connection: write the trigger, then wait for its reply. A raw connect
 * timeout additionally returns the actual numeric peer, before any trigger
 * was sent, so transport recovery cannot switch to a new DNS answer. */
static int once_probe(const char *host, const char *port, const d2k_trigger *tr,
                      const d2k_opts *opt, const int *cuts, int ncuts, int gap_ms,
                      char *err, size_t errcap, char *raw_peer, size_t peer_cap)
{
    d2k_span sp[8];
    int nsp, i, fd;
    uint8_t buf[4096]; /* private to this measurement, not another worker's reply */
    ssize_t n;
    struct pollfd pfd;
    int64_t deadline;

    err[0] = '\0';
    /* A split is a measured bypass, not a suggestion to the kernel about
     * write boundaries. Execute the same packet program that sched exports.
     * no_raw/unsupported platforms retain socket diagnostics only. */
    if (ncuts > 0 && !opt->no_raw && d2k_raw_supported()) {
        uint8_t ip[16];
        uint8_t family = strchr(host, ':') ? 6 : 4;
        if (ncuts != 1 || !cuts || cuts[0] <= 0 || (size_t)cuts[0] >= tr->len) {
            snprintf(err, errcap, "split runtime: invalid cut");
            return -1;
        }
        if (inet_pton(family == 6 ? AF_INET6 : AF_INET, host, ip) != 1) {
            struct addrinfo hints = {0}, *ai = NULL;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_family = AF_UNSPEC;
            int rc = getaddrinfo(host, port, &hints, &ai);
            if (rc || !ai) {
                snprintf(err, errcap, "split runtime: resolve target: %s", gai_strerror(rc));
                return -1;
            }
            family = ai->ai_family == AF_INET6 ? 6 : 4;
            if (family == 6)
                memcpy(ip, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, 16);
            else
                memcpy(ip, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, 4);
            freeaddrinfo(ai);
        }
        if (!inet_ntop(family == 6 ? AF_INET6 : AF_INET, ip, raw_peer, (socklen_t)peer_cap)) {
            snprintf(err, errcap, "split runtime: peer address: %s", strerror(errno));
            return -1;
        }
        d2k_poison split = {0};
        snprintf(split.name, sizeof split.name, "tcp-split");
        split.split_pos = cuts[0]; split.gap_ms = gap_ms;
        return d2k_raw_probe_poison_family(ip, family, (uint16_t)strtoul(port, NULL, 10),
            tr, &split, opt->timeout_ms, opt->mark, &opt->cancel, err, errcap);
    }
    fd = dial_marked(host, port, opt->timeout_ms, opt->mark, err, errcap);
    if (fd < 0) {
        return -1;
    }
    deadline = d2k_now_ms() + opt->timeout_ms;

    nsp = d2k_split_offsets(cuts, ncuts, (int)tr->len, sp, 8);
    for (i = 0; i < nsp; i++) {
        size_t off = (size_t)sp[i].from;
        size_t want = (size_t)(sp[i].to - sp[i].from);
        while (want > 0) {
            ssize_t w = d2k_send_nosig(fd, tr->payload + off, want);
            if (w <= 0) {
                snprintf(err, errcap, "write: %s", strerror(errno));
                close(fd);
                return -1;
            }
            off += (size_t)w;
            want -= (size_t)w;
        }
        if (sp[i].to < (int)tr->len) {
            if (d2k_now_ms() + gap_ms > deadline) {
                snprintf(err, errcap, "context deadline exceeded");
                close(fd);
                return -1;
            }
            /* Донор ждёт паузу на select вместе с ctx.Done(): отменённый
               замер не должен досиживать её до конца. Пауза бывает и 700 мс
               (проверка на пересборку), а кусков в зонде несколько. */
            if (d2k_detect_stopped(&opt->cancel)) {
                snprintf(err, errcap, "context canceled");
                close(fd);
                return -1;
            }
            d2k_sleep_ms(gap_ms);
        }
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    size_t have = 0, minimum = d2k_trigger_prefix_size(tr);
    while (have < minimum) {
        if (d2k_detect_stopped(&opt->cancel)) {
            snprintf(err, errcap, "context canceled");
            close(fd); return -1;
        }
        int64_t left = deadline - d2k_now_ms();
        if (left <= 0) { close(fd); return 0; }
        int ready = poll(&pfd, 1, left > 100 ? 100 : (int)left);
        if (ready < 0) {
            if (errno == EINTR) continue;
            snprintf(err, errcap, "poll: %s", strerror(errno));
            close(fd); return -1;
        }
        if (!ready) continue;
        n = recv(fd, buf + have, sizeof buf - have, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (errno == ECONNRESET) { close(fd); return 0; }
            snprintf(err, errcap, "recv: %s", strerror(errno));
            close(fd); return -1;
        }
        if (!n) { close(fd); return 0; }
        have += (size_t)n;
    }
    close(fd);
    return d2k_trigger_accepts(tr, buf, have);

}

/* Неподтверждённых сервером байт в очереди отправки; -1 — не наблюдается.
 * Linux: TIOCOUTQ (= SIOCOUTQ для TCP) — write_seq - snd_una, то же число,
 * что столбец tx_queue в /proc/net/tcp. Константа берётся из заголовков
 * libc своей архитектуры (на MIPS она другая). macOS: SO_NWRITE — байты в
 * буфере отправки, которые TCP держит до подтверждения. */
static int unacked_bytes(int fd)
{
#if defined(__linux__) && defined(TIOCOUTQ)
    int n = 0;
    if (ioctl(fd, TIOCOUTQ, &n) != 0) {
        return -1;
    }
    return n;
#elif defined(__APPLE__)
    int n = 0;
    socklen_t sl = sizeof(n);
    if (getsockopt(fd, SOL_SOCKET, SO_NWRITE, &n, &sl) != 0) {
        return -1;
    }
    return n;
#else
    (void)fd;
    return -1;
#endif
}

int d2k_probe_data_ack(const char *host, const char *port, const d2k_opts *opt,
                       char *err, size_t errcap)
{
    /* Строчная «x»: не тип записи TLS (0x14..0x18), не первая буква метода
     * HTTP — у коробки нет сигнатуры, по которой его резать. Именно этим
     * байтом снят полевой замер 04.10 (см. отчёт задачи 54). */
    static const uint8_t neutral[1] = {'x'};
    struct pollfd pfd;
    int64_t deadline;
    int fd;

    err[0] = '\0';
#if !(defined(__linux__) && defined(TIOCOUTQ)) && !defined(__APPLE__)
    (void)host; (void)port; (void)opt;
    snprintf(err, errcap, "подтверждение данных на этой платформе не наблюдается");
    return -2;
#else
    fd = dial_marked(host, port, opt->timeout_ms, opt->mark, err, errcap);
    if (fd < 0) {
        return -1;
    }
    if (unacked_bytes(fd) < 0) {
        snprintf(err, errcap, "очередь отправки не читается: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (d2k_send_nosig(fd, neutral, sizeof(neutral)) != (ssize_t)sizeof(neutral)) {
        snprintf(err, errcap, "write: %s", strerror(errno));
        close(fd);
        return -1;
    }
    deadline = d2k_now_ms() + opt->timeout_ms;
    for (;;) {
        int left;
        int q = unacked_bytes(fd);
        if (q == 0) {
            close(fd);
            return 1; /* TCP сервера байт принял */
        }
        if (q < 0) {
            snprintf(err, errcap, "очередь отправки не читается: %s", strerror(errno));
            close(fd);
            return -1;
        }
        left = (int)(deadline - d2k_now_ms());
        if (left <= 0) {
            break;
        }
        if (d2k_detect_stopped(&opt->cancel)) {
            snprintf(err, errcap, "context canceled");
            close(fd);
            return -1;
        }
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        /* Любое событие — данные, FIN, RST (свой или вброшенный) — это уже не
         * тишина адреса. Вывод о блоке адреса делается только из тишины. */
        if (poll(&pfd, 1, left < 20 ? left : 20) > 0) {
            close(fd);
            return 1;
        }
    }
    close(fd);
    return 0;
#endif
}

/* Место вызова подменяемо стендом (test_repeats.c): петля ядра подтверждает
 * любой байт, и тишину адреса на ней не изобразить. */
#ifndef D2K_DATA_ACK_PROBE
#define D2K_DATA_ACK_PROBE d2k_probe_data_ack
#endif
int D2K_DATA_ACK_PROBE(const char *host, const char *port, const d2k_opts *opt,
                       char *err, size_t errcap);

typedef struct {
    int  pass, fail;
    int  has_err;
    char err[160];
} d2k_tally;

/* Store only actual input bytes, not the unused 16 KiB buffer capacity. */
static size_t cache_trigger_pack(unsigned char *dst, const d2k_trigger *tr) {
    unsigned char *p = dst;
    if (tr->len > sizeof tr->payload || tr->client_tcp_options_len > sizeof tr->client_tcp_options)
        return 0;
#define PACK_FIELD(field) do { memcpy(p, &tr->field, sizeof tr->field); p += sizeof tr->field; } while (0)
    PACK_FIELD(name); PACK_FIELD(len); PACK_FIELD(sni_off); PACK_FIELD(sni_len);
    PACK_FIELD(accept); PACK_FIELD(client_tcp_known); PACK_FIELD(client_tcp_options_len);
#undef PACK_FIELD
    memcpy(p, tr->payload, tr->len); p += tr->len;
    memcpy(p, tr->client_tcp_options, tr->client_tcp_options_len); p += tr->client_tcp_options_len;
    return (size_t)(p - dst);
}

/* measure гоняет один зонд Repeats раз и записывает наблюдение в трассу.
 *
 * until_pass — остановиться на первом проходе. Это для вопроса, исход
 * которого решает ОДИН проход (контроль: «ответил ли хоть раз»): дальнейшие
 * повторы его уже не изменят. База и разрез идут все повторы — их исход
 * различает «ни разу», «частично» и «всегда». */
static d2k_tally measure(const char *host, const char *port, const d2k_trigger *tr,
                         const d2k_opts *opt, const char *name,
                         const int *cuts, int ncuts, int gap_ms, d2k_result *res,
                         int until_pass)
{
    d2k_tally t;
    d2k_obs *obs;
    int i;
    char err[160];

    memset(&t, 0, sizeof(t));
    obs = d2k_trace_add(res, name);
    for (i = 0; i < ncuts && i < 4; i++) {
        obs->cuts[obs->ncuts++] = cuts[i];
    }
    obs->delay_ms = gap_ms;
    struct measure_key {
        char kind[8], name[160];
        int cuts[4], ncuts, gap, until_pass;
    } key;
    memset(&key, 0, sizeof key);
    memcpy(key.kind, "measure", 7);
    snprintf(key.name, sizeof key.name, "%s", name);
    key.ncuts = ncuts; key.gap = gap_ms; key.until_pass = until_pass;
    unsigned char input[sizeof(d2k_trigger)];
    size_t input_len = cache_trigger_pack(input, tr);
    for (i = 0; i < ncuts && i < 4; i++) key.cuts[i] = cuts[i];
    d2k_run_entry *cached = input_len ? d2k_run_cache_get(opt->run_cache, &key, sizeof key, input, input_len) : NULL;
    if (cached) {
        t.pass = obs->pass = cached->pass; t.fail = obs->fail = cached->fail;
        obs->seeded = 1;
        obs_done(opt, obs);
        return t;
    }

    if (opt->seed_whole && ncuts == 0 && strcmp(name, "whole") == 0 &&
        opt->seed_repeats == opt->repeats &&
        !d2k_dial_deadline_err(opt->seed_err)) {
        /* База уже спрошена этим же триггером (см. d2k_opts.seed_whole). */
        t.pass = opt->seed_pass;
        t.fail = opt->seed_fail;
        if (opt->seed_err[0]) {
            t.has_err = 1;
            snprintf(t.err, sizeof(t.err), "%s", opt->seed_err);
            snprintf(obs->err, sizeof(obs->err), "%s", opt->seed_err);
        }
        obs->pass = t.pass;
        obs->fail = t.fail;
        obs_done(opt, obs);
        return t;
    }

    for (i = 0; i < opt->repeats; i++) {
        int rc;
        if (d2k_detect_stopped(&opt->cancel)) {
            break;
        }
        char raw_peer[INET6_ADDRSTRLEN] = "";
        rc = once_probe(host, port, tr, opt, cuts, ncuts, gap_ms, err, sizeof(err),
                        raw_peer, sizeof raw_peer);
        res->probes++;
        if (rc == D2K_RAW_CONNECT_TIMEOUT) {
            /* The trigger was never sent: this is not one of its repeats.
             * Compare a fresh kernel TCP handshake, then retry this unsent
             * trial once. A second raw failure leaves the question unknown;
             * never retry a negative reply after sending the trigger. */
            d2k_obs *transport = d2k_trace_add(res, "transport:raw-connect");
            transport->fail = 1;
            snprintf(transport->err, sizeof transport->err, "%s", err);
            obs_done(opt, transport);
            if (!d2k_detect_stopped(&opt->cancel)) {
                d2k_obs *control = d2k_trace_add(res, "transport:tcp-control");
                int fd = dial_marked_mode(raw_peer, port, opt->timeout_ms, opt->mark,
                                          err, sizeof err, 1);
                res->probes++;
                if (fd >= 0) { control->pass = 1; close(fd); }
                else {
                    control->fail = 1;
                    snprintf(control->err, sizeof control->err, "%s", err);
                }
                obs_done(opt, control);
                if (fd >= 0 && !d2k_detect_stopped(&opt->cancel)) {
                    rc = once_probe(raw_peer, port, tr, opt, cuts, ncuts, gap_ms, err, sizeof err,
                                    raw_peer, sizeof raw_peer);
                    res->probes++;
                    if (rc == D2K_RAW_CONNECT_TIMEOUT) {
                        transport = d2k_trace_add(res, "transport:raw-connect-retry");
                        transport->fail = 1;
                        snprintf(transport->err, sizeof transport->err, "%s", err);
                        obs_done(opt, transport);
                    }
                }
            }
            if (rc == D2K_RAW_CONNECT_TIMEOUT) {
                t.has_err = 1;
                snprintf(t.err, sizeof t.err, "%s", err);
                snprintf(obs->err, sizeof obs->err, "%s", err);
                break;
            }
        }
        if (rc < 0) {
            t.fail++;
            if (!t.has_err) {
                t.has_err = 1;
                snprintf(t.err, sizeof(t.err), "%s", err);
                snprintf(obs->err, sizeof(obs->err), "%s", err);
            }
        } else if (rc > 0) {
            t.pass++;
            if (until_pass) {
                break;
            }
        } else {
            t.fail++;
        }
    }
    obs->pass = t.pass;
    obs->fail = t.fail;
    if (input_len && !t.has_err && !d2k_detect_stopped(&opt->cancel) &&
        (t.pass + t.fail == opt->repeats || (until_pass && t.pass > 0))) {
        d2k_run_cache_put(opt->run_cache, &key, sizeof key, input, input_len, t.pass, t.fail);
    }
    obs_done(opt, obs);
    return t;
}

/* --- отравление ---------------------------------------------------------- */

/* Подставляет приманку перед зондом: для гипотез с decoy="hello" ею служит
 * контрольное приветствие, а при seqovlExact длина перекрытия берётся РАВНОЙ
 * длине приманки — в него ложится целое приветствие, без набивки и обрезки. */
static void bind_decoy(d2k_poison *p, const d2k_opts *opt)
{
    if (!p->decoy_hello) {
        return;
    }
    const d2k_trigger *d = d2k_opts_decoy(opt);
    p->decoy = d->payload;
    p->decoy_len = d->len;
    if (p->seqovl_exact) {
        p->seqovl = (int)d->len;
    }
}

/* Вопрос о свойствах уже получил на эту гипотезу ответ сети (задача 49 для
 * дублей самого списка, решение владельца 03.10: трассу не повторяем). */
static int answered_by_props(const d2k_result *res, const d2k_poison *p)
{
    int k;
    for (k = 0; k < res->nanswered; k++) {
        if (d2k_poison_same(&res->answered[k], p)) { return 1; }
    }
    return 0;
}

/* --- самопроверка сырого слоя: раз на процесс --------------------------- */

/* Самопроверка проверяет НАШ сырой слой — своё рукопожатие, свои суммы,
 * придержанное ядро, — а не цель: до сырого перебора дерево доходит только
 * когда обычное TCP-соединение с целью уже установилось (база без ошибки
 * соединения). Поэтому прошедшая самопроверка — свойство процесса на этом
 * роутере, и повторять её у каждой цели незачем. Поле 02.10.2026: три зонда
 * самопроверки из восемнадцати на YouTube.
 *
 * Кэш снимается по сроку и по серии подряд идущих локальных ошибок сырых
 * зондов (rc<0): слой мог сломаться после проверки (правило, маршрут,
 * интерфейс). Ключ — семейство адресов: сырой IPv6 — другие сокеты и другой
 * путь. Классификаторы работают в разных потоках одновременно — отсюда
 * мьютекс. Провал самопроверки не кэшируется: он ведёт себя как прежде. */
#define D2K_SELFTEST_TTL_MS   (10L * 60L * 1000L)
#define D2K_RAW_ERR_STREAK    3

static pthread_mutex_t g_selftest_mu = PTHREAD_MUTEX_INITIALIZER;
/* Слот на (семейство, предлагает ли клиент метку времени): слой ручается за
   ТУ форму потока, которой идут вопросы, и кэш одной формы не отвечает за
   другую (ревью ветки, находка 7). */
static int  g_selftest_ok[4];
static int64_t g_selftest_at[4];
static int  g_raw_err_streak[4];

static int fam_ix(uint8_t family) { return family == 6 ? 1 : 0; }
/* Набор С МЕТКОЙ остаётся в прежних слотах 0/1 (это и прежнее поведение, и
   набор клиента, чей профиль не снят), набор без метки — в 2/3. */
static int self_ix(uint8_t family, int offer_ts) {
    return fam_ix(family) + (offer_ts ? 0 : 2);
}

/* Возраст кэшированной самопроверки в мс или -1, если кэша нет. */
static int64_t selftest_cached_age(uint8_t family, int offer_ts)
{
    int64_t age = -1;
    int k = self_ix(family, offer_ts);
    pthread_mutex_lock(&g_selftest_mu);
    if (g_selftest_ok[k]) {
        int64_t d = d2k_now_ms() - g_selftest_at[k];
        if (d >= 0 && d < D2K_SELFTEST_TTL_MS) {
            age = d;
        } else {
            g_selftest_ok[k] = 0;
        }
    }
    pthread_mutex_unlock(&g_selftest_mu);
    return age;
}

static void selftest_store(uint8_t family, int offer_ts, int ok)
{
    int k = self_ix(family, offer_ts);
    pthread_mutex_lock(&g_selftest_mu);
    g_selftest_ok[k] = ok;
    g_selftest_at[k] = d2k_now_ms();
    g_raw_err_streak[k] = 0;
    pthread_mutex_unlock(&g_selftest_mu);
}

void d2k_raw_note_rc(d2k_result *res, uint8_t family, int rc)
{
    int k = fam_ix(family);
    if (rc < 0) {
        res->raw_probes_err++;
    } else {
        /* Ответ или тишина ПОСЛЕ нашего рукопожатия — слой работает. */
        res->raw_probes_ok++;
    }
    pthread_mutex_lock(&g_selftest_mu);
    if (rc < 0) {
        /* Серия локальных ОТКАЗОВ ЗОНДА говорит «сырой слой сломан», и это не
           зависит от набора опций: гасим кэш обоих наборов этого семейства
           (ревью ветки, находка 7). Счёт серии — один на семейство, как и был. */
        if (++g_raw_err_streak[k] >= D2K_RAW_ERR_STREAK) {
            g_selftest_ok[self_ix(family, 1)] = 0;
            g_selftest_ok[self_ix(family, 0)] = 0;
        }
    } else {
        g_raw_err_streak[k] = 0;
    }
    pthread_mutex_unlock(&g_selftest_mu);
}

/* Самопроверка как таковая. Засчитывается по одному успеху, поэтому первый
 * успех её и заканчивает; до провала доходит только после всех повторов. */
static int raw_selftest(const uint8_t *ip, uint8_t family, uint16_t pnum,
                        const d2k_opts *opt, d2k_result *res, int offer_ts)
{
    char err[160];
    int i;
    d2k_obs *obs = d2k_trace_add(res, "raw-selftest");
    for (i = 0; i < opt->repeats; i++) {
        int rc;
        if (d2k_detect_stopped(&opt->cancel)) { break; }
        rc = d2k_raw_probe_handshake_as(ip, family, pnum, opt->timeout_ms, opt->mark,
                                        &opt->cancel, offer_ts, err, sizeof(err));
        res->probes++;
        if (rc < 0) {
            obs->fail++;
            if (obs->err[0] == '\0') {
                snprintf(obs->err, sizeof(obs->err), "%s", err);
            }
        } else if (rc > 0) {
            obs->pass++;
            break;
        } else {
            obs->fail++;
        }
    }
    obs_done(opt, obs);
    selftest_store(family, offer_ts, obs->pass > 0);
    return obs->pass > 0;
}

/* Кэшированная самопроверка под сомнением: в этом прогоне ни один сырой
 * зонд не дошёл даже до рукопожатия. Тогда слой перепроверяется сейчас же,
 * а не следующей целью: иначе отказы своего слоя записались бы в свойства
 * коробки — ровно то, от чего самопроверка и защищает. */
static int raw_doubted(const d2k_result *res)
{
    return res->raw_selftest_cached && res->raw_probes_ok == 0 && res->raw_probes_err >= 2;
}

/* 1 — слой исправен, перебор продолжается; 0 — слой сломан: прогон
 * заканчивается так же, как при проваленной самопроверке в начале. */
static int raw_recheck(const uint8_t *ip, uint8_t family, uint16_t pnum,
                       const d2k_opts *opt, d2k_result *res, const d2k_dprops *props0,
                       int offer_ts)
{
    res->raw_selftest_cached = 0;
    if (raw_selftest(ip, family, pnum, opt, res, offer_ts)) {
        return 1;
    }
    /* Ответы, снятые со сломанного слоя, о коробке ничего не говорят. */
    res->props = *props0;
    res->raw_usable = 0;
    res->raw_selftest_failed = 1;
    return 0;
}

/* sweepPoisons перебирает гипотезы отравления и возвращает первую сработавшую.
 *
 * Порядок в poisons() не случайный: сначала то, что не требует знания
 * топологии, потом перебор TTL. TTL идёт последним не только по цене —
 * сработавшее значение попутно называет хоп, на котором стоит коробка. */
/* Exact run input, including control/decoy bytes and TCP profile. The cache
 * belongs to one scheduler task; task reset supplies the generation boundary. */
static void bind_run_cache(const char *addr, const d2k_trigger *tr, d2k_opts *opt) {
    struct context {
        char addr[192];
        int repeats, timeout, gap, long_gap, no_raw, vouched, cross;
        uint32_t mark;
    } c;
    if (!opt->run_cache) return;
    memset(&c, 0, sizeof c);
    snprintf(c.addr, sizeof c.addr, "%s", addr);
    c.repeats = opt->repeats; c.timeout = opt->timeout_ms;
    c.gap = opt->write_gap_ms; c.long_gap = opt->long_gap_ms;
    c.mark = opt->mark; c.no_raw = opt->no_raw;
    c.vouched = opt->control_vouched; c.cross = opt->cross_check_tls12;
    unsigned char *bytes = malloc(sizeof c + 4 * sizeof(d2k_trigger));
    if (!bytes) { d2k_run_cache_clear(opt->run_cache); return; }
    memcpy(bytes, &c, sizeof c);
    size_t used = sizeof c;
    const d2k_trigger *inputs[] = {tr, &opt->control, &opt->decoy, &opt->white};
    for (size_t i = 0; i < 4; i++) {
        size_t n = cache_trigger_pack(bytes + used, inputs[i]);
        if (!n) { free(bytes); d2k_run_cache_clear(opt->run_cache); return; }
        used += n;
    }
    if (opt->run_cache->context &&
        (opt->run_cache->context_len != used ||
         memcmp(opt->run_cache->context, bytes, used))) {
        opt->nknown = 0;
    }
    (void)d2k_run_cache_bind(opt->run_cache, bytes, used);
    free(bytes);
}
static int candidate_replay(const d2k_opts *opt, const d2k_poison *p, d2k_obs *obs) {
    d2k_poison key = *p;
    key.decoy = NULL;
    d2k_run_entry *e = d2k_run_cache_get(opt->run_cache, &key, sizeof key,
                                         p->decoy, p->decoy_len);
    if (!e) return 0;
    obs->pass = e->pass; obs->fail = e->fail; obs->seeded = 1;
    return 1;
}
static void candidate_save(const d2k_opts *opt, const d2k_poison *p, const d2k_obs *obs) {
    if (obs->seeded || obs->err[0] || d2k_detect_stopped(&opt->cancel) ||
        (obs->fail == 0 && obs->pass != opt->repeats)) return;
    d2k_poison key = *p;
    key.decoy = NULL;
    d2k_run_cache_put(opt->run_cache, &key, sizeof key, p->decoy, p->decoy_len,
                      obs->pass, obs->fail);
}

static int sweep_poisons(const char *host, const char *port, const d2k_trigger *tr,
                         const d2k_opts *opt, d2k_result *res, d2k_poison *hit)
{
    struct addrinfo hints, *ai = NULL;
    uint8_t ip4[16] = {0};
    uint8_t family;
    uint16_t pnum;
    const d2k_poison *list;
    int n, i, k;
    char err[160];
    d2k_poison cands[8];
    int ncands;
    d2k_dprops props0;
    int64_t age;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = strchr(host, ':') ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &ai) != 0 || !ai) {
        return 0;
    }
    family = ai->ai_family == AF_INET6 ? 6 : 4;
    if (family == 6) {
        memcpy(ip4, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, 16);
        pnum = ntohs(((struct sockaddr_in6 *)ai->ai_addr)->sin6_port);
    } else {
        memcpy(ip4, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, 4);
        pnum = ntohs(((struct sockaddr_in *)ai->ai_addr)->sin_port);
    }
    freeaddrinfo(ai);
    if (pnum == 0) {
        return 0;
    }

    /* САМОПРОВЕРКА СЫРОГО СЛОЯ. Свой TCP — это своё рукопожатие, свои
     * контрольные суммы и придержанное ядро; сломайся любая из этих частей, и
     * ВСЕ зонды дали бы «тишину», а мы прочитали бы её как «отравить не
     * удалось». Поэтому сперва гоняем по тому же пути безобидную нагрузку без
     * всякой отравы. */
    age = selftest_cached_age(family, d2k_trigger_offers_ts(tr));
    if (age >= 0) {
        /* Строка в трассе — чтобы читающий видел, что самопроверку не
         * пропустили, а взяли из кэша, и что зондов она не стоила. */
        d2k_obs *obs = d2k_trace_add(res, "raw-selftest:кэш");
        snprintf(obs->err, sizeof(obs->err),
                 "прошла %ld с назад в этом процессе, зондов не было", (long)(age / 1000));
        obs_done(opt, obs);
        res->raw_selftest_cached = 1;
    } else if (!raw_selftest(ip4, family, pnum, opt, res, d2k_trigger_offers_ts(tr))) {
        res->raw_usable = 0;
        res->raw_selftest_failed = 1;
        return 0;
    }
    res->raw_usable = 1;

    /* Если правило подавления ядерного RST не встало, отрицательные исходы
     * сырых зондов ничего не значат: RST мог прилететь от нашего же ядра.
     * Сказать об этом обязаны — иначе своя поломка читается как свойство сети. */
    if (d2k_raw_rst_fail_count() != res->rst_fail_base) {
        d2k_obs *o = d2k_trace_add(res, "внимание:правило подавления RST не встало");
        snprintf(o->err, sizeof(o->err),
                 "iptables отверг вставку; отрицательные исходы сырых зондов недостоверны");
    }

    /* СВОЙСТВА СПЕРВА, СТРАТЕГИЯ — ИЗ НИХ. Шесть вопросов вместо девяноста
     * попыток. Перебор ниже остаётся, но уже запасным путём. */
    props0 = res->props;
    if (opt->only[0] == '\0') {
        if (d2k_run_properties_family(ip4, family, pnum, tr, opt, res, hit)) {
            if (d2k_opts_acceptable(opt, hit)) {
                snprintf(res->path, sizeof(res->path), "свойство");
                return 1;
            }
        }
        if (raw_doubted(res) &&
            !raw_recheck(ip4, family, pnum, opt, res, &props0, d2k_trigger_offers_ts(tr))) {
            return 0;
        }
        {
            const d2k_trigger *d = d2k_opts_decoy(opt);
            ncands = d2k_compose_from_props(&res->props, d->payload, d->len, cands, 8);
        }
        for (k = 0; k < ncands; k++) {
            d2k_obs *obs;
            int pass = 0, done = 0;
            if (d2k_detect_stopped(&opt->cancel)) {
                break;
            }
            if (!d2k_poison_supports_family(&cands[k], family) ||
                d2k_opts_skipped(opt, cands[k].name)) {
                continue;
            }
            obs = d2k_trace_add(res, cands[k].name);
            obs->delay_ms = cands[k].gap_ms;
            /* Единогласие: первый провал решает исход, остальные повторы
             * его не изменят. */
            int replayed = candidate_replay(opt, &cands[k], obs);
            if (replayed) { pass = obs->pass; done = pass + obs->fail; }
            for (i = 0; !replayed && i < opt->repeats; i++) {
                if (d2k_detect_stopped(&opt->cancel)) break;
                err[0] = '\0';
                int rc = d2k_raw_probe_poison_family(ip4, family, pnum, tr, &cands[k], opt->timeout_ms,
                                              opt->mark, &opt->cancel, err, sizeof(err));
                res->probes++;
                done++;
                d2k_raw_note_rc(res, family, rc);
                if (rc <= 0) {
                    if (rc < 0) {
                        snprintf(obs->err, sizeof(obs->err), "%s", err[0] ? err : "local probe failure");
                    }
                    break;
                }
                pass++;
            }
            obs->pass = pass;
            obs->fail = done - pass;
            candidate_save(opt, &cands[k], obs);
            obs_done(opt, obs);
            if (raw_doubted(res) &&
            !raw_recheck(ip4, family, pnum, opt, res, &props0, d2k_trigger_offers_ts(tr))) {
                return 0;
            }
            if (pass == opt->repeats && d2k_opts_acceptable(opt, &cands[k])) {
                *hit = cands[k];
                res->composed = 1;
                snprintf(res->path, sizeof(res->path), "собрано");
                return 1;
            }
        }
    }

    list = d2k_poisons(&n);
    for (i = 0; i < n; i++) {
        d2k_poison p = list[i];
        d2k_obs *obs;
        char pname[128];
        int r;

        if (d2k_detect_stopped(&opt->cancel)) {
            break;
        }
        if (opt->only[0] != '\0' && strcmp(p.name, opt->only) != 0) {
            continue;
        }
        if (!d2k_poison_supports_family(&p, family) ||
            (p.disorder_pos > 0 && (size_t)p.disorder_pos >= tr->len) ||
            d2k_opts_skipped(opt, p.name) ||
            !d2k_trigger_allows_poison(tr, &p)) { /* как клиент: без метки — без tcpts */
            continue;
        }
        bind_decoy(&p, opt);
        if (answered_by_props(res, &p)) {
            continue;
        }
        snprintf(pname, sizeof(pname), "poison:%s", p.name);
        obs = d2k_trace_add(res, pname);
        obs->delay_ms = p.gap_ms;
        /* Единогласие (см. ниже): первый провал решает исход гипотезы. */
        int replayed = candidate_replay(opt, &p, obs);
        for (r = 0; !replayed && r < opt->repeats; r++) {
            if (d2k_detect_stopped(&opt->cancel)) break;
            err[0] = '\0';
            int rc = d2k_raw_probe_poison_family(ip4, family, pnum, tr, &p, opt->timeout_ms, opt->mark,
                                          &opt->cancel, err, sizeof(err));
            res->probes++;
            d2k_raw_note_rc(res, family, rc);
            if (rc < 0) {
                obs->fail++;
                if (obs->err[0] == '\0') {
                    snprintf(obs->err, sizeof(obs->err), "%s", err);
                }
                break;
            } else if (rc > 0) {
                obs->pass++;
            } else {
                obs->fail++;
                break;
            }
        }
        candidate_save(opt, &p, obs);
        obs_done(opt, obs);
        if (raw_doubted(res) &&
            !raw_recheck(ip4, family, pnum, opt, res, &props0, d2k_trigger_offers_ts(tr))) {
            return 0;
        }
        /* Единогласие обязательно: одна случайная удача назначила бы
         * стратегией то, что не работает. */
        if (obs->pass == opt->repeats) {
            d2k_note_props_hit(&res->props, &list[i]);
            if (!d2k_opts_acceptable(opt, &list[i])) {
                continue;
            }
            if (res->path[0] == '\0') {
                snprintf(res->path, sizeof(res->path), "перебор");
            }
            *hit = p;
            return 1;
        }
        d2k_note_props_miss(&res->props, &list[i]);
    }
    return 0;
}

/* crossCheckTLS12 — поиск приёма, общего для обоих приветствий TLS.
 *
 * НЕ ПЕРЕНЕСЕНО. Здесь стоит честная заглушка, а не тихий no-op: режим
 * «both» стоит минуты и обещает покрытие старых устройств, и выдать
 * непроверенное за проверенное — ровно та ошибка, от которой защищает
 * CoversTLS12 = «не измерено» в эталоне. Вызов из CLI запрещён до переноса. */
static void cross_check_tls12(d2k_result *res, const d2k_opts *opt, const char *poison_name)
{
    (void)poison_name;
    if (!opt->cross_check_tls12) {
        return;
    }
    res->covers_tls12 = D2K_TRI_UNSET;
    d2k_note(res, "покрытие старого приветствия TLS 1.2 НЕ ПРОВЕРЕНО: режим ещё не перенесён");
}

/* Run прогоняет дерево зондов по адресу addr ("host:port"). */
static int measure_response_gate(const char *addr, const char *host, const d2k_trigger *tr,
                                 const d2k_opts *opt, d2k_result *res)
{
    uint8_t gate_ip[16];
    if (d2k_detect_stopped(&opt->cancel) || opt->no_raw || !d2k_raw_supported() ||
        tr->accept != D2K_ACCEPT_SERVERHELLO ||
        (inet_pton(AF_INET, host, gate_ip) != 1 &&
         (!opt->preflight_ipv6 || inet_pton(AF_INET6, host, gate_ip) != 1)))
        return 0;
    unsigned long before = d2k_raw_dial_count();
    int gate;
    int from_known = d2k_preflight_known(&opt->known, &res->preflight, &gate);
    /* A negative result in the catalog does not identify the alternate
     * ClientHello, so it cannot rule out the candidate supplied now. */
    if (from_known && !gate && opt->preflight_auto)
        from_known = 0;
    if (!from_known) gate = d2k_probe_preflight(addr, tr, opt, &res->preflight);
    res->probes += (int)(d2k_raw_dial_count() - before);
    d2k_obs *o = d2k_trace_add(res, "response-gate");
    o->pass = gate == 1; o->fail = gate == 0;
    o->from_known = from_known;
    if (gate < 0) snprintf(o->err, sizeof o->err, "опыт response-gate не завершён");
    if (gate == 3) snprintf(o->err,sizeof o->err,"перенос напрямую не подтверждён; кандидат для составного испытания");
    if (gate == 0 && res->preflight.reason[0])
        snprintf(o->err, sizeof o->err, "%.*s", (int)sizeof o->err-1, res->preflight.reason);
    obs_done(opt, o);
    if (gate == 2) {
        res->verdict = D2K_DV_FLAKY;
        snprintf(res->reason, sizeof res->reason,
                 "свежая прямая сырая проба получила ответ после тихой базы — вопросы прекращены");
        return 1;
    }
    if(gate==3) {
        res->verdict=D2K_DV_INCONCLUSIVE;
        snprintf(res->reason,sizeof res->reason,
            "малое окно дало ответ (%u байт); перенос напрямую не подтверждён — только кандидат для проверки с исходящей программой",
            res->preflight.candidate.response_bytes);
        return 1;
    }
    if (gate == 0 && res->preflight.reason[0]) {
        size_t used = strlen(res->reason);
        snprintf(res->reason + used, sizeof res->reason - used, "; %s",res->preflight.reason);
    }
    if (gate == 1) {
        res->verdict = D2K_DV_RESPONSE_GATE;
        snprintf(res->reason, sizeof res->reason,
                 "обычный ответ молчит (ACK %u/%zu); окно %u и перенос через RST после %u кусков проверены",
                 res->preflight.baseline_acked,tr->len,
                 res->preflight.window, res->preflight.pieces_needed);
        return 1;
    }
    return 0;
}

void d2k_classify_run(const char *addr, const d2k_trigger *tr,
                      d2k_opts *opt, d2k_result *res)
{
    char host[160], port[16];
    const char *colon;
    int64_t start;
    d2k_tally base, one, lng, last;
    int cut1[1];
    int reass;
    int lo, hi;

    d2k_opts_defaults(opt);
    bind_run_cache(addr, tr, opt);
    start = d2k_now_ms();
    memset(res, 0, sizeof(*res));
    /* Отложенные снятия правил подавления RST — перед пачкой зондов, а не
     * только перед следующей вставкой: прогон без сырого слоя или простой
     * d2kc иначе держал бы неснятое правило часами (ревью detect, I2). */
    d2k_raw_flush_pending();
    res->rst_fail_base = d2k_raw_rst_fail_count();
    res->raw_dial_base = d2k_raw_dial_count();
    snprintf(res->target, sizeof(res->target), "%s", addr);
    res->repeats = opt->repeats;
    res->trigger_len = (int)tr->len;
    res->reassembles = D2K_TRI_UNSET;
    res->covers_tls12 = D2K_TRI_UNSET;

    /* Цель проверяем ДО зондов. Пустой или неразобранный адрес давал уверенный
     * вердикт «режут по адресу» — на пустоте молчит всё, и инструмент честно
     * сообщал бы о блокировке там, где ошибся оператор. Врать так нельзя. */
    colon = strrchr(addr, ':');
    if (!colon || colon == addr || colon[1] == '\0') {
        res->verdict = D2K_DV_FLAKY;
        snprintf(res->reason, sizeof(res->reason), "адрес не разобран, ожидается host:port");
        goto done;
    }
    if ((size_t)(colon - addr) >= sizeof(host)) {
        res->verdict = D2K_DV_FLAKY;
        snprintf(res->reason, sizeof(res->reason), "адрес не разобран, ожидается host:port");
        goto done;
    }
    memcpy(host, addr, (size_t)(colon - addr));
    host[colon - addr] = '\0';
    if (host[0] == '[') {
        size_t n = strlen(host);
        if (n < 3 || host[n - 1] != ']') {
            res->verdict = D2K_DV_FLAKY;
            snprintf(res->reason, sizeof(res->reason), "адрес IPv6 не разобран");
            goto done;
        }
        memmove(host, host + 1, n - 2);
        host[n - 2] = '\0';
    }
    if (strchr(host, '%')) {
        res->verdict = D2K_DV_FLAKY;
        snprintf(res->reason, sizeof(res->reason), "локальная область IPv6 не является целью замера");
        goto done;
    }
    snprintf(port, sizeof(port), "%s", colon + 1);
    {
        struct in6_addr a6;
        if (!opt->allow_loopback && inet_pton(AF_INET6, host, &a6) == 1 &&
            (IN6_IS_ADDR_LOOPBACK(&a6) || IN6_IS_ADDR_UNSPECIFIED(&a6))) {
            res->verdict = D2K_DV_FLAKY;
            snprintf(res->reason, sizeof(res->reason),
                     "цель указывает на localhost — мерить нечего, проверь как резолвится имя");
            goto done;
        }
        struct in_addr a;
        if (!opt->allow_loopback && inet_pton(AF_INET, host, &a) == 1) {
            uint32_t v = ntohl(a.s_addr);
            if ((v >> 24) == 127 || v == 0) {
                res->verdict = D2K_DV_FLAKY;
                snprintf(res->reason, sizeof(res->reason),
                         "цель указывает на localhost — мерить нечего, проверь как резолвится имя");
                goto done;
            }
        }
    }
    if (tr->len < 2) {
        res->verdict = D2K_DV_FLAKY;
        snprintf(res->reason, sizeof(res->reason), "триггер короче двух байт — резать нечего");
        goto done;
    }

    /* 1. БАЗА. Триггер целиком, одной записью. Если проходит — блокировки по
     * содержимому нет, и всё остальное дерево не имеет смысла. */
    base = measure(host, port, tr, opt, "whole", NULL, 0, opt->write_gap_ms, res, 0);
    if (base.has_err && base.pass == 0 && d2k_dial_deadline_err(base.err)) {
        /* ОДИН ПЕРЕСПРОС ПО НАЗВАННОЙ ПРИЧИНЕ, А НЕ ПЕРЕБОР СРОКОВ. Истёк
           НАШ срок — значит опыта не было; прежде чем говорить о цели хоть
           что-нибудь, спрашиваем ещё раз с удвоенным сроком. Число не
           выдумано и не подогнано: поле 12.10.2026, flibusta.is — установка
           соединения с роутера заняла 3,1 с, 0 с и 7,16 с в трёх попытках
           подряд, то есть успех лежит ЗА нашими 6000 мс, но внутри их
           удвоения. Повтор один: если и его не хватило, цель отвечает
           медленнее любого разумного срока, и это надо называть, а не
           продолжать удваивать (§«искусственных бюджетов не вводить»). */
        d2k_opts slow = *opt;
        slow.timeout_ms = opt->timeout_ms > 0 ? opt->timeout_ms * 2 : 12000;
        slow.seed_whole = 0;
        base = measure(host, port, tr, &slow, "whole", NULL, 0, slow.write_gap_ms, res, 0);
    }
    if (base.has_err && base.pass == 0) {
        if (d2k_dial_deadline_err(base.err)) {
            /* НАШ срок, а не слова о линии: замер не состоялся, и называть
               это «до цели нет транспорта» нельзя — тот вердикт означает
               «кандидатов нет», и планы по цели перестают строиться вовсе
               (core/sched.c). Поле 12.10: цель отвечала за 7,16 с при нашем
               сроке 6 с, и 218 поисков подряд закончились ничем. */
            res->verdict = D2K_DV_FLAKY;
            res->dial_deadline = 1;
            snprintf(res->reason, sizeof(res->reason),
                     "наш срок на подключение %d мс истёк — замер не состоялся: %.160s",
                     opt->timeout_ms, base.err);
        } else {
            res->verdict = D2K_DV_UNREACHABLE;
            snprintf(res->reason, sizeof(res->reason), "нет TCP до цели: %s", base.err);
        }
        goto done;
    }
    if (base.pass == opt->repeats) {
        /* Запрос проходит. Но это ещё не «обходить нечего»: у TLS 1.2
         * сертификат сервера идёт открытым текстом, и коробка может пропустить
         * запрос, а убить ОТВЕТ. Замер одного направления объявил бы такой
         * домен чистым, и вердикт был бы противоположен правде. */
        const char *sni;
        res->verdict = D2K_DV_CLEAR;
        snprintf(res->reason, sizeof(res->reason), "триггер проходит как есть — обходить нечего");
        sni = d2k_trigger_sni(tr);
        if (sni[0] != '\0') {
            d2k_probe_response(host, port, sni, opt, &res->response);
            res->has_response = 1;
            res->probes += 2 * opt->repeats;
            if (res->response.verdict == D2K_RESP_BLOCKED) {
                res->verdict = D2K_DV_RESPONSE;
                snprintf(res->reason, sizeof(res->reason), "%s", res->response.reason);
            } else if (res->response.verdict == D2K_RESP_NOT_APPLICABLE ||
                       res->response.verdict == D2K_RESP_FLAKY) {
                /* «Не проверено» обязано быть видно. Молча оставить «чисто»
                 * значило бы выдать непроверенное за проверенное. */
                char tail[400];
                snprintf(tail, sizeof(tail), " (ответное направление: %s)", res->response.reason);
                strncat(res->reason, tail, sizeof(res->reason) - strlen(res->reason) - 1);
            }
        } else if (tr->accept == D2K_ACCEPT_SERVERHELLO) {
            /* TLS-триггер без пригодного SNI: ответное направление спросить
             * нечем. Вердикт донора («чисто») сохраняем, но непроверенное
             * обязано быть видно (D2K_SPEC §9.9). */
            strncat(res->reason, " (ответное направление не проверено: нет SNI)",
                    sizeof(res->reason) - strlen(res->reason) - 1);
        }
        goto done;
    }
    if (base.pass > 0) {
        res->verdict = D2K_DV_FLAKY;
        snprintf(res->reason, sizeof(res->reason),
                 "база не воспроизводится: %d прошло из %d", base.pass, opt->repeats);
        goto done;
    }

    /* 2. РЕЗАТЬ ВООБЩЕ ПОМОГАЕТ? Разрез после первого байта — самый агрессивный
     * из возможных: в первом сегменте остаётся один байт. Если и он не
     * проходит, никакая точка разреза не пройдёт тем более. */
    cut1[0] = 1;
    one = measure(host, port, tr, opt, "split", cut1, 1, opt->write_gap_ms, res, 0);
    if (one.has_err) {
        res->verdict = D2K_DV_FLAKY;
        snprintf(res->reason, sizeof(res->reason), "ошибка замера разреза: %s", one.err);
        goto done;
    }
    if (one.pass == 0) {
        /* Automatic response measurement has its own ACK/silence baseline.
         * Ask after the cheap split control and before outbound fallbacks. */
        if (opt->preflight_auto && measure_response_gate(addr, host, tr, opt, res))
            goto gate_finished;
        /* 2а. КОНТРОЛЬ. Разрез не спас — но прежде чем говорить «пересборка»,
         * надо исключить, что содержимое вообще ни при чём. */
        int control_ok = 1;
        d2k_poison hit;
        if (opt->control.len > 0) {
            /* Контроль засчитывается по ОДНОМУ проходу (control_ok ниже), так
             * что после первого прохода повторы его не изменят. */
            d2k_tally ctl = measure(host, port, &opt->control, opt, "control", NULL, 0,
                                    opt->write_gap_ms, res, 1);
            control_ok = ctl.pass > 0;
        }
        /* МОЛЧАНИЕ КОНТРОЛЯ — НЕ ПОВОД ЗАКОНЧИТЬ.
         *
         * Раньше здесь стоял ранний возврат, и он оказался тупиком. Поле
         * 2026-08-28, googlevideo: тот фронтенд обслуживает ТОЛЬКО имена
         * *.googlevideo.com, а они все под блокировкой — безобидного имени для
         * контроля не существует в природе, и инструмент отказывался мерить
         * цель, которую наш же обход берёт 10 раз из 10.
         *
         * Перебор гипотез при этом полезен сам по себе: сработавшая отрава
         * ДОКАЗЫВАЕТ, что решение принимается по содержимому. Поэтому идём
         * дальше, а вердикт без базы просто не будет утверждать лишнего. */
        if (!control_ok) {
            /* 2б. ПРИНИМАЕТ ЛИ АДРЕС ДАННЫЕ ВООБЩЕ (задача 54). Молчание
             * контроля без поручительства двусмысленно: сервер может не
             * обслуживать имя приманки (googlevideo). Но подтверждение байта
             * даёт TCP сервера, а не его приложение: на googlevideo
             * нейтральный байт подтверждается, хотя и контроль, и триггер
             * молчат (поле 04.10, 74.125.153.92). А если не подтверждается и
             * он — данные к адресу режутся целиком, и перебор отрав (девяносто
             * гипотез по тайм-ауту) спрашивал бы то, на что ответ уже есть:
             * десинк меняет вид байт, но доставить их туда, куда не доходит
             * ни один, не может. Поле 04.10, cdn.cookielaw.org: 104.18.86.0/24
             * не подтверждает ни приветствия, ни одного байта, замер
             * перебором не укладывался в срок задачи и шёл по кругу. */
            d2k_obs *obs = d2k_trace_add(res, "neutral-ack");
            char aerr[160];
            int i, observed = 1;
            for (i = 0; i < opt->repeats; i++) {
                int rc;
                if (d2k_detect_stopped(&opt->cancel)) {
                    observed = 0;
                    break;
                }
                aerr[0] = '\0';
                rc = D2K_DATA_ACK_PROBE(host, port, opt, aerr, sizeof(aerr));
                if (rc == -2) {
                    observed = 0;
                    snprintf(obs->err, sizeof(obs->err), "%s", aerr);
                    break;
                }
                res->probes++;
                if (rc < 0) {
                    /* Локальная ошибка — не свойство адреса. */
                    observed = 0;
                    obs->fail++;
                    snprintf(obs->err, sizeof(obs->err), "%s", aerr);
                    break;
                }
                if (rc > 0) {
                    obs->pass++;
                    break; /* одного подтверждения достаточно: данные доходят */
                }
                obs->fail++;
            }
            obs_done(opt, obs);
            if (observed && obs->pass == 0 && obs->fail == opt->repeats) {
                res->verdict = D2K_DV_ADDRESS;
                snprintf(res->reason, sizeof(res->reason),
                         "рукопожатие проходит, но сервер не подтвердил ни одного нейтрального "
                         "байта (0 из %d): данные к адресу режутся целиком, содержимое ни при "
                         "чём — обходить содержимым нечего", opt->repeats);
                goto done;
            }
        }
        memset(&hit, 0, sizeof(hit));
        if (!opt->no_raw && d2k_raw_supported()) {
            if (sweep_poisons(host, port, tr, opt, res, &hit)) {
                res->verdict = D2K_DV_POISONABLE;
                res->boundary = 0;
                res->hit = hit;
                res->has_hit = 1;
                d2k_strategy_for_poison(&hit, res->strategy, sizeof(res->strategy));
                note_gap_loss(res, &hit);
                snprintf(res->reason, sizeof(res->reason),
                         "поток пересобирается, но буфер травится: коробка глотает «%s», "
                         "сервер выбрасывает", hit.name);
                cross_check_tls12(res, opt, hit.name);
                goto done;
            }
        }
        if (!control_ok) {
            if (opt->control_vouched) {
                res->verdict = D2K_DV_ADDRESS;
                snprintf(res->reason, sizeof(res->reason),
                         "молчит и контроль на имени, за которое ручается оператор, и ни одна "
                         "гипотеза не сработала — похоже на блок по адресу");
            } else {
                res->verdict = D2K_DV_INCONCLUSIVE;
                snprintf(res->reason, sizeof(res->reason),
                         "контроль не ответил и отравить не удалось: базы нет, отличить блок по "
                         "адресу от нехватки гипотез нельзя");
            }
            goto done;
        }
        res->verdict = D2K_DV_OPAQUE;
        snprintf(res->reason, sizeof(res->reason),
                 "разрез не помогает, контроль проходит, отравить буфер не удалось — содержимое "
                 "важно, но чем брать, зондами не нашли");
        if (!res->raw_usable) {
            snprintf(res->reason, sizeof(res->reason),
                     "разрез не помогает, контроль проходит; сырые зонды НЕ РАБОТАЮТ "
                     "(самопроверка не прошла) — про отравление вывода нет");
        }
        if (opt->no_raw || !d2k_raw_supported()) {
            snprintf(res->reason, sizeof(res->reason),
                     "разрез не помогает, а контроль проходит: решение по содержимому, поток "
                     "пересобирается — сырые зонды выключены или недоступны");
        }
        goto done;
    }
    if (one.pass != opt->repeats) {
        res->verdict = D2K_DV_FLAKY;
        snprintf(res->reason, sizeof(res->reason),
                 "разрез pos=1 не воспроизводится: %d из %d", one.pass, opt->repeats);
        goto done;
    }

    /* 3. ЕСТЬ ЛИ БУФЕР ПЕРЕСБОРКИ. Тот же разрез, но с паузой в сотни
     * миллисекунд. Коробка без буфера ведёт себя так же; коробка с буфером и
     * таймаутом успевает склеить сегменты и снова опознать сигнатуру. */
    lng = measure(host, port, tr, opt, "split-long", cut1, 1, opt->long_gap_ms, res, 0);
    if (lng.has_err) {
        res->verdict = D2K_DV_FLAKY;
        snprintf(res->reason, sizeof(res->reason), "ошибка замера разреза: %s", lng.err);
        goto done;
    }
    reass = lng.pass == 0;
    res->reassembles = reass ? D2K_TRI_TRUE : D2K_TRI_FALSE;
    res->props.reassembles = res->reassembles;

    /* 4. ГРАНИЦА СИГНАТУРЫ — двоичным поиском. Инвариант: pos=1 проходит,
     * а какая-то позиция правее уже нет. Ищем ПЕРВУЮ непроходящую. */
    lo = 1;
    hi = (int)tr->len;
    {
        int c[1];
        c[0] = (int)tr->len - 1;
        last = measure(host, port, tr, opt, "split", c, 1, opt->write_gap_ms, res, 0);
    }
    if (last.has_err) {
        res->verdict = D2K_DV_FLAKY;
        snprintf(res->reason, sizeof(res->reason), "ошибка замера разреза: %s", last.err);
        goto done;
    }
    if (last.pass == opt->repeats) {
        res->verdict = D2K_DV_WHOLE_PACKET;
        snprintf(res->reason, sizeof(res->reason),
                 "проходит любой разрез — матчер требует пакет целиком");
        res->split_pos = 1;
        d2k_strategy_for(1, res->strategy, sizeof(res->strategy));
        cross_check_tls12(res, opt, "");
        goto done;
    }
    hi = (int)tr->len - 1;
    while (hi - lo > 1) {
        int mid = (lo + hi) / 2;
        int c[1];
        d2k_tally m;
        c[0] = mid;
        m = measure(host, port, tr, opt, "split", c, 1, opt->write_gap_ms, res, 0);
        if (m.has_err) {
            res->verdict = D2K_DV_FLAKY;
            snprintf(res->reason, sizeof(res->reason), "ошибка замера разреза: %s", m.err);
            goto done;
        }
        if (m.pass == opt->repeats) {
            lo = mid;
        } else if (m.pass == 0) {
            hi = mid;
        } else {
            res->verdict = D2K_DV_FLAKY;
            snprintf(res->reason, sizeof(res->reason),
                     "разрез pos=%d не воспроизводится: %d из %d", mid, m.pass, opt->repeats);
            goto done;
        }
    }

    res->verdict = D2K_DV_PREFIX;
    res->boundary = hi;
    res->split_pos = 1;
    d2k_strategy_for(1, res->strategy, sizeof(res->strategy));
    snprintf(res->reason, sizeof(res->reason),
             "префиксный матчер: сигнатура кончается на байте %d, разрез левее её ломает", hi);
    cross_check_tls12(res, opt, "");
    if (reass) {
        char tail[160];
        snprintf(tail, sizeof(tail),
                 "; при паузе %dms блок возвращается — у коробки есть буфер пересборки",
                 opt->long_gap_ms);
        strncat(res->reason, tail, sizeof(res->reason) - strlen(res->reason) - 1);
    }

done:
    if (!opt->preflight_auto && opt->control_vouched &&
        (res->verdict == D2K_DV_OPAQUE || res->verdict == D2K_DV_INCONCLUSIVE) &&
        measure_response_gate(addr, host, tr, opt, res))
        goto gate_finished;
    if (res->preflight.reason[0]) {
        size_t used = strlen(res->reason);
        snprintf(res->reason + used, sizeof(res->reason) - used, "; %s", res->preflight.reason);
    }

gate_finished:
    /* Пометка ставится ОДИН раз и в конце: флаг отмены липкий (см. заголовок),
     * а проверять его в каждой точке выхода значило бы двадцать шансов забыть
     * одну. Брошенный замер не выдаётся за измеренный нигде. */
    if (d2k_detect_stopped(&opt->cancel)) {
        res->stopped = 1;
    }
    res->duration_ms = (long)(d2k_now_ms() - start);
}

/* Linux глушит SIGPIPE флагом на вызов; на macOS его нет — там опция сокета.
 * В main дополнительно стоит SIG_IGN, но библиотечный код не должен зависеть
 * от того, кто его вызвал. */
ssize_t d2k_send_nosig(int fd, const void *buf, size_t len)
{
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
#ifdef SO_NOSIGPIPE
    {
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    }
#endif
    return send(fd, buf, len, flags);
}
