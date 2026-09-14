#define _POSIX_C_SOURCE 200809L
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
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_MARK
#define SO_MARK 36
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

long d2k_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

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

/* Доказательством прохода считается ТОЛЬКО то, что назвал триггер.
 * Пустой ответ доказательством НЕ является ни при каком accept. */
int d2k_trigger_accepts(const d2k_trigger *t, const uint8_t *b, size_t n)
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
    if (res->ntrace >= D2K_TRACE_MAX) {
        return &res->trace[D2K_TRACE_MAX - 1];
    }
    o = &res->trace[res->ntrace++];
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
static int dial_marked(const char *host, const char *port, int timeout_ms,
                       char *err, size_t errcap)
{
    struct addrinfo hints, *ai = NULL, *p;
    int fd = -1, rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, port, &hints, &ai);
    if (rc != 0 || !ai) {
        snprintf(err, errcap, "dial tcp: %s", gai_strerror(rc));
        return -1;
    }
    for (p = ai; p; p = p->ai_next) {
        int mark = D2K_BYPASS_MARK;
        int one = 1;
        int fl;
        struct pollfd pfd;
        int soerr = 0;
        socklen_t sl = sizeof(soerr);

        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
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

/* once — одно соединение: пишем триггер по кускам, ждём ответ.
 * Возврат: 1 прошло, 0 не прошло, -1 ошибка зонда. */
static int once_probe(const char *host, const char *port, const d2k_trigger *tr,
                      const d2k_opts *opt, const int *cuts, int ncuts, int gap_ms,
                      char *err, size_t errcap)
{
    d2k_span sp[8];
    int nsp, i, fd;
    static uint8_t buf[4096];
    ssize_t n;
    struct pollfd pfd;
    long deadline;

    err[0] = '\0';
    fd = dial_marked(host, port, opt->timeout_ms, err, errcap);
    if (fd < 0) {
        return -1;
    }
    deadline = d2k_now_ms() + opt->timeout_ms;

    nsp = d2k_split_offsets(cuts, ncuts, (int)tr->len, sp, 8);
    for (i = 0; i < nsp; i++) {
        size_t off = (size_t)sp[i].from;
        size_t want = (size_t)(sp[i].to - sp[i].from);
        while (want > 0) {
            ssize_t w = send(fd, tr->payload + off, want, 0);
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
            d2k_sleep_ms(gap_ms);
        }
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    {
        int left = (int)(deadline - d2k_now_ms());
        if (left < 0) {
            left = 0;
        }
        /* Тишина и обрыв — это и есть «убито». Ошибкой зонда не считаем:
         * иначе блокировка выглядела бы как неисправность инструмента. */
        if (poll(&pfd, 1, left) <= 0) {
            close(fd);
            return 0;
        }
    }
    n = recv(fd, buf, sizeof(buf), 0);
    close(fd);
    if (n <= 0) {
        return 0;
    }
    return d2k_trigger_accepts(tr, buf, (size_t)n);
}

typedef struct {
    int  pass, fail;
    int  has_err;
    char err[160];
} d2k_tally;

/* measure гоняет один зонд Repeats раз и записывает наблюдение в трассу. */
static d2k_tally measure(const char *host, const char *port, const d2k_trigger *tr,
                         const d2k_opts *opt, const char *name,
                         const int *cuts, int ncuts, int gap_ms, d2k_result *res)
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

    for (i = 0; i < opt->repeats; i++) {
        int rc = once_probe(host, port, tr, opt, cuts, ncuts, gap_ms, err, sizeof(err));
        res->probes++;
        if (rc < 0) {
            t.fail++;
            if (!t.has_err) {
                t.has_err = 1;
                snprintf(t.err, sizeof(t.err), "%s", err);
                snprintf(obs->err, sizeof(obs->err), "%s", err);
            }
        } else if (rc > 0) {
            t.pass++;
        } else {
            t.fail++;
        }
    }
    obs->pass = t.pass;
    obs->fail = t.fail;
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
    p->decoy = opt->control.payload;
    p->decoy_len = opt->control.len;
    if (p->seqovl_exact) {
        p->seqovl = (int)opt->control.len;
    }
}

/* sweepPoisons перебирает гипотезы отравления и возвращает первую сработавшую.
 *
 * Порядок в poisons() не случайный: сначала то, что не требует знания
 * топологии, потом перебор TTL. TTL идёт последним не только по цене —
 * сработавшее значение попутно называет хоп, на котором стоит коробка. */
static int sweep_poisons(const char *host, const char *port, const d2k_trigger *tr,
                         const d2k_opts *opt, d2k_result *res, d2k_poison *hit)
{
    struct addrinfo hints, *ai = NULL;
    uint8_t ip4[4];
    uint16_t pnum;
    const d2k_poison *list;
    int n, i, k;
    char err[160];
    d2k_poison cands[8];
    int ncands;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &ai) != 0 || !ai) {
        return 0;
    }
    memcpy(ip4, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, 4);
    pnum = ntohs(((struct sockaddr_in *)ai->ai_addr)->sin_port);
    freeaddrinfo(ai);
    if (pnum == 0) {
        return 0;
    }

    /* САМОПРОВЕРКА СЫРОГО СЛОЯ. Свой TCP — это своё рукопожатие, свои
     * контрольные суммы и придержанное ядро; сломайся любая из этих частей, и
     * ВСЕ зонды дали бы «тишину», а мы прочитали бы её как «отравить не
     * удалось». Поэтому сперва гоняем по тому же пути безобидную нагрузку без
     * всякой отравы. */
    {
        d2k_obs *obs = d2k_trace_add(res, "raw-selftest");
        for (i = 0; i < opt->repeats; i++) {
            int rc = d2k_raw_probe_handshake(ip4, pnum, opt->timeout_ms, err, sizeof(err));
            res->probes++;
            if (rc < 0) {
                obs->fail++;
                if (obs->err[0] == '\0') {
                    snprintf(obs->err, sizeof(obs->err), "%s", err);
                }
            } else if (rc > 0) {
                obs->pass++;
            } else {
                obs->fail++;
            }
        }
        if (obs->pass == 0) {
            res->raw_usable = 0;
            return 0;
        }
    }
    res->raw_usable = 1;

    /* Если правило подавления ядерного RST не встало, отрицательные исходы
     * сырых зондов ничего не значат: RST мог прилететь от нашего же ядра.
     * Сказать об этом обязаны — иначе своя поломка читается как свойство сети. */
    if (d2k_raw_rst_rule_failed()) {
        d2k_obs *o = d2k_trace_add(res, "внимание:правило подавления RST не встало");
        snprintf(o->err, sizeof(o->err),
                 "iptables отверг вставку; отрицательные исходы сырых зондов недостоверны");
    }

    /* СВОЙСТВА СПЕРВА, СТРАТЕГИЯ — ИЗ НИХ. Шесть вопросов вместо девяноста
     * попыток. Перебор ниже остаётся, но уже запасным путём. */
    if (opt->only[0] == '\0') {
        if (d2k_run_properties(ip4, pnum, tr, opt, res, hit)) {
            if (d2k_opts_acceptable(opt, hit)) {
                snprintf(res->path, sizeof(res->path), "свойство");
                return 1;
            }
        }
        ncands = d2k_compose_from_props(&res->props, opt->control.payload,
                                        opt->control.len, cands, 8);
        for (k = 0; k < ncands; k++) {
            d2k_obs *obs;
            int pass = 0;
            if (d2k_opts_skipped(opt, cands[k].name)) {
                continue;
            }
            obs = d2k_trace_add(res, cands[k].name);
            obs->delay_ms = cands[k].gap_ms;
            for (i = 0; i < opt->repeats; i++) {
                int rc = d2k_raw_probe_poison(ip4, pnum, tr, &cands[k],
                                              opt->timeout_ms, err, sizeof(err));
                res->probes++;
                if (rc > 0) {
                    pass++;
                }
            }
            obs->pass = pass;
            obs->fail = opt->repeats - pass;
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

        if (opt->only[0] != '\0' && strcmp(p.name, opt->only) != 0) {
            continue;
        }
        if (d2k_opts_skipped(opt, p.name)) {
            continue;
        }
        snprintf(pname, sizeof(pname), "poison:%s", p.name);
        obs = d2k_trace_add(res, pname);
        obs->delay_ms = p.gap_ms;
        bind_decoy(&p, opt);
        for (r = 0; r < opt->repeats; r++) {
            int rc = d2k_raw_probe_poison(ip4, pnum, tr, &p, opt->timeout_ms, err, sizeof(err));
            res->probes++;
            if (rc < 0) {
                obs->fail++;
                if (obs->err[0] == '\0') {
                    snprintf(obs->err, sizeof(obs->err), "%s", err);
                }
            } else if (rc > 0) {
                obs->pass++;
            } else {
                obs->fail++;
            }
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
void d2k_classify_run(const char *addr, const d2k_trigger *tr,
                      d2k_opts *opt, d2k_result *res)
{
    char host[160], port[16];
    const char *colon;
    long start;
    d2k_tally base, one, lng, last;
    int cut1[1];
    int reass;
    int lo, hi;

    d2k_opts_defaults(opt);
    start = d2k_now_ms();
    memset(res, 0, sizeof(*res));
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
    snprintf(port, sizeof(port), "%s", colon + 1);
    {
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
    base = measure(host, port, tr, opt, "whole", NULL, 0, opt->write_gap_ms, res);
    if (base.has_err && base.pass == 0) {
        res->verdict = D2K_DV_UNREACHABLE;
        snprintf(res->reason, sizeof(res->reason), "нет TCP до цели: %s", base.err);
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
    one = measure(host, port, tr, opt, "split", cut1, 1, opt->write_gap_ms, res);
    if (one.pass == 0) {
        /* 2а. КОНТРОЛЬ. Разрез не спас — но прежде чем говорить «пересборка»,
         * надо исключить, что содержимое вообще ни при чём. */
        int control_ok = 1;
        d2k_poison hit;
        if (opt->control.len > 0) {
            d2k_tally ctl = measure(host, port, &opt->control, opt, "control", NULL, 0,
                                    opt->write_gap_ms, res);
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
    lng = measure(host, port, tr, opt, "split-long", cut1, 1, opt->long_gap_ms, res);
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
        last = measure(host, port, tr, opt, "split", c, 1, opt->write_gap_ms, res);
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
        m = measure(host, port, tr, opt, "split", c, 1, opt->write_gap_ms, res);
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
    res->duration_ms = d2k_now_ms() - start;
}
