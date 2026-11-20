/* test_tree.c — стенд соответствия: поддельная коробка на петле.
 *
 * Перенос classify_test.go эталона. Смысл стенда — проверить ДЕРЕВО: порядок
 * вопросов, условия переходов и вердикты, не выходя в сеть. Живая линия
 * сверяется иначе (tests/compare.sh на роутере) и доказывает другое: что тот
 * же алгоритм на той же коробке даёт тот же ответ, что и эталон. Одно другое
 * не заменяет — стенд ловит переходы, поле ловит физику.
 *
 * СЫРОЙ СЛОЙ ЗДЕСЬ ВЫКЛЮЧЕН НАРОЧНО. Перебор отравлений против петли — это
 * девяносто гипотез по таймауту каждая, минуты на прогон, и меряет он свои же
 * сокеты, а не коробку. Вердикт от этого не меняется: ветка «пересборка»
 * заканчивается одним и тем же opaque, только с честной оговоркой, что про
 * отравление вывода нет.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
/* Same in-translation-unit approach as test_repeats; only raw I/O is
 * scripted for the socket-free scenarios. Old socket scenarios are unchanged. */
#define d2k_raw_probe_handshake_as tree_handshake
#define d2k_raw_probe_poison_family tree_poison
#define d2k_raw_supported tree_raw_supported
#define d2k_probe_preflight tree_preflight
#include "classify.c"
#undef d2k_raw_probe_handshake_as
#undef d2k_raw_probe_poison_family
#undef d2k_raw_supported
#undef d2k_probe_preflight
#include "d2k_preflight_probe.h"
int d2k_raw_supported(void);
int d2k_raw_probe_handshake_as(const uint8_t *,uint8_t,uint16_t,int,uint32_t,
    const d2k_detect_stop *,int,char *,size_t);
int d2k_raw_probe_poison_family(const uint8_t *,uint8_t,uint16_t,const d2k_trigger *,
    const d2k_poison *,int,uint32_t,const d2k_detect_stop *,char *,size_t);
int d2k_probe_preflight(const char *,const d2k_trigger *,const d2k_opts *,d2k_preflight_meas *);
static int tree_script, tree_gate_calls;
int tree_raw_supported(void) {return tree_script ? 1 : d2k_raw_supported();}
int tree_handshake(const uint8_t *ip,uint8_t f,uint16_t p,int t,uint32_t m,
    const d2k_detect_stop *c,int ts,char *e,size_t n)
{ return tree_script ? 1 : d2k_raw_probe_handshake_as(ip,f,p,t,m,c,ts,e,n); }
int tree_poison(const uint8_t *ip,uint8_t f,uint16_t p,const d2k_trigger *tr,
    const d2k_poison *po,int t,uint32_t m,const d2k_detect_stop *c,char *e,size_t n)
{
    if(tree_script) return !strcmp(po->name,"tcp-split") ?
        (tree_script==1 && po->split_pos<4) : tree_script==2;
    return d2k_raw_probe_poison_family(ip,f,p,tr,po,t,m,c,e,n);
}
int tree_preflight(const char *a,const d2k_trigger *tr,const d2k_opts *o,d2k_preflight_meas *m)
{
    if(!tree_script)return d2k_probe_preflight(a,tr,o,m);
    tree_gate_calls++;m->response_gate=m->carry_over_rst=1;m->pieces_needed=3;return 1;
}
#include "d2k_detect.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Полезная нагрузка теста: первые sig_len байт играют роль открытой сигнатуры. */
static const char PAYLOAD[] = "WA\x06\x03SIGNATURE-AND-THEN-SOME-PAYLOAD-BYTES";
#define PAYLOAD_LEN (sizeof(PAYLOAD) - 1)

static int fails;

static void fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("  ПРОВАЛ: ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    fails++;
}

int d2k_resp_handshake12(const char *host, const char *port, const char *sni,
                         const d2k_opts *opt);

typedef enum { M_PREFIX, M_WHOLE, M_REASM, M_CLEAR, M_DEAF,
                M_RST_AFTER_FIRST, M_RST_AT_ONCE } dpi_mode;

typedef struct {
    int      fd;
    dpi_mode mode;
    int      sig_len;
    pthread_t thread;
    int stopping;
} fake_dpi;

typedef struct {
    fake_dpi d;
    int       fd;
} conn_job;

/* КАЖДОЕ СОЕДИНЕНИЕ — В СВОЁМ ПОТОКЕ, и это не украшение.
 *
 * Заблокированное соединение по замыслу молчит две секунды. Если обслуживать
 * их по очереди, приём следующего откладывается на это время — а клиент к
 * тому моменту уже записал ОБА куска разреза, и они лежат в буфере ядра
 * слипшимися. Первый же recv отдаёт коробке всю нагрузку целиком, разрез
 * «не срабатывает», и дерево уходит в opaque на коробке, которая на самом
 * деле префиксная. Стенд при этом не падает и ничего не сообщает: он просто
 * меряет сам себя. */
static void *conn_thread(void *arg)
{
    conn_job *j = arg;
    fake_dpi snapshot = j->d;
    fake_dpi *d = &snapshot;
    int c = j->fd;
    uint8_t buf[4096];
    uint8_t all[8192];
    size_t alen;
    ssize_t n;
    int blocked = 0;

    if (d->mode == M_RST_AFTER_FIRST || d->mode == M_RST_AT_ONCE) {
        struct linger lg = {1, 0};
        if (d->mode == M_RST_AFTER_FIRST)
            (void)recv(c, buf, sizeof(buf), 0);
        (void)setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        close(c);
        free(j);
        return NULL;
    }
    struct timeval tv;

    free(j);
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    n = recv(c, buf, sizeof(buf), 0);
    if (n <= 0) {
        close(c);
        return NULL;
    }
    memcpy(all, buf, (size_t)n);
    alen = (size_t)n;

    switch (d->mode) {
    case M_PREFIX:
        blocked = n >= d->sig_len && memcmp(buf, PAYLOAD, (size_t)d->sig_len) == 0;
        break;
    case M_WHOLE:
        blocked = (size_t)n == PAYLOAD_LEN && memcmp(buf, PAYLOAD, PAYLOAD_LEN) == 0;
        break;
    case M_REASM: {
        /* Дочитываем остаток и ищем сигнатуру в склейке. */
        size_t i;
        tv.tv_sec = 0;
        tv.tv_usec = 300000;
        (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        for (;;) {
            ssize_t m = recv(c, buf, sizeof(buf), 0);
            if (m <= 0) {
                break;
            }
            if (alen + (size_t)m <= sizeof(all)) {
                memcpy(all + alen, buf, (size_t)m);
                alen += (size_t)m;
            }
        }
        for (i = 0; i + (size_t)d->sig_len <= alen; i++) {
            if (memcmp(all + i, PAYLOAD, (size_t)d->sig_len) == 0) {
                blocked = 1;
                break;
            }
        }
        break;
    }
    case M_CLEAR:
        blocked = 0;
        break;
    case M_RST_AFTER_FIRST:
    case M_RST_AT_ONCE:
        break; /* обслужены выше */
    case M_DEAF:
        /* Режет всё подряд: имитация блока по адресу. */
        blocked = 1;
        break;
    }
    if (blocked) {
        /* Блокировка — это молчание, а не отказ. */
        d2k_sleep_ms(2000);
        close(c);
        return NULL;
    }
    (void)send(c, "\x16\x03\x03\x00\x04\x02\x00\x00\x00", 9, 0); /* ServerHello-shaped */
    close(c);
    return NULL;
}

static void *dpi_thread(void *arg)
{
    fake_dpi *d = arg;
    while (!__atomic_load_n(&d->stopping, __ATOMIC_ACQUIRE)) {
        pthread_t th;
        conn_job *j;
        struct pollfd pf = {d->fd, POLLIN, 0};
        int ready = poll(&pf, 1, 50);
        if (ready == 0 || (ready < 0 && errno == EINTR)) continue;
        if (ready < 0 || !(pf.revents & POLLIN)) return NULL;
        int c = accept(d->fd, NULL, NULL);
        if (c < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            return NULL;
        }
        (void)fcntl(c, F_SETFL, fcntl(c, F_GETFL, 0) & ~O_NONBLOCK);
        j = malloc(sizeof(*j));
        if (!j) {
            close(c);
            continue;
        }
        memset(&j->d, 0, sizeof j->d);
        j->d.mode = d->mode; j->d.sig_len = d->sig_len;
        j->fd = c;
        if (pthread_create(&th, NULL, conn_thread, j) != 0) {
            close(c);
            free(j);
            continue;
        }
        pthread_detach(th);
    }
    return NULL;
}

static int fake_dpi_start_family(fake_dpi *d, dpi_mode mode, int sig_len,
                                  char *addr, size_t cap, int family)
{
    struct sockaddr_storage sa;
    socklen_t sl = sizeof(sa);
    int one = 1;

    memset(d, 0, sizeof(*d));
    d->mode = mode;
    d->sig_len = sig_len;
    d->fd = socket(family, SOCK_STREAM, 0);
    if (d->fd < 0) {
        return -1;
    }
    (void)setsockopt(d->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    socklen_t alen;
    if (family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&sa;
        v6->sin6_family = AF_INET6; v6->sin6_addr = in6addr_loopback;
        alen = sizeof *v6;
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&sa;
        v4->sin_family = AF_INET; v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        alen = sizeof *v4;
    }
    if (bind(d->fd, (struct sockaddr *)&sa, alen) != 0) {
        return -1;
    }
    if (listen(d->fd, 16) != 0) {
        return -1;
    }
    if (getsockname(d->fd, (struct sockaddr *)&sa, &sl) != 0) {
        return -1;
    }
    if (family == AF_INET6)
        snprintf(addr, cap, "[::1]:%u", (unsigned)ntohs(((struct sockaddr_in6 *)&sa)->sin6_port));
    else
        snprintf(addr, cap, "127.0.0.1:%u", (unsigned)ntohs(((struct sockaddr_in *)&sa)->sin_port));
    if (fcntl(d->fd, F_SETFL, fcntl(d->fd, F_GETFL, 0) | O_NONBLOCK) < 0) return -1;
    if (pthread_create(&d->thread, NULL, dpi_thread, d) != 0) {
        return -1;
    }
    return 0;
}

static int fake_dpi_start(fake_dpi *d, dpi_mode mode, int sig_len, char *addr, size_t cap)
{
    return fake_dpi_start_family(d, mode, sig_len, addr, cap, AF_INET);
}

static void fake_dpi_stop(fake_dpi *d)
{
    __atomic_store_n(&d->stopping, 1, __ATOMIC_RELEASE);
    pthread_join(d->thread, NULL);
    close(d->fd);
}

static void fast_opts(d2k_opts *o)
{
    memset(o, 0, sizeof(*o));
    /* Поддельная коробка живёт на loopback — защиту от неверно
     * разрезолвившегося имени здесь снимаем осознанно. */
    o->allow_loopback = 1;
    o->repeats = 2;
    o->timeout_ms = 900;
    o->write_gap_ms = 10;
    o->long_gap_ms = 40;
    o->no_raw = 1;
}

static void trig(d2k_trigger *t)
{
    memset(t, 0, sizeof(*t));
    snprintf(t->name, sizeof(t->name), "test");
    memcpy(t->payload, PAYLOAD, PAYLOAD_LEN);
    t->len = PAYLOAD_LEN;
    t->accept = D2K_ACCEPT_ANY;
}

static void ctl_trig(d2k_trigger *t)
{
    static const char ctl[] = "BENIGN-CONTROL-PAYLOAD";
    memset(t, 0, sizeof(*t));
    snprintf(t->name, sizeof(t->name), "ctl");
    memcpy(t->payload, ctl, sizeof(ctl) - 1);
    t->len = sizeof(ctl) - 1;
    t->accept = D2K_ACCEPT_ANY;
}

static void run_on(dpi_mode mode, int sig_len, d2k_opts *opt, d2k_result *res)
{
    fake_dpi d;
    char addr[64];
    d2k_trigger t;

    trig(&t);
    if (fake_dpi_start(&d, mode, sig_len, addr, sizeof(addr)) != 0) {
        fail("стенд не поднялся");
        memset(res, 0, sizeof(*res));
        return;
    }
    d2k_classify_run(addr, &t, opt, res);
    fake_dpi_stop(&d);
}

static void dump_trace(const d2k_result *res)
{
    int i;
    for (i = 0; i < res->ntrace; i++) {
        printf("    %-12s cuts=%d пауза=%d прошло=%d не прошло=%d %s\n",
               res->trace[i].probe, res->trace[i].ncuts ? res->trace[i].cuts[0] : -1,
               res->trace[i].delay_ms, res->trace[i].pass, res->trace[i].fail,
               res->trace[i].err);
    }
}

static void test_prefix_matcher_finds_boundary(void)
{
    d2k_opts opt;
    d2k_result res;
    fast_opts(&opt);
    run_on(M_PREFIX, 4, &opt, &res);
    if (res.verdict != D2K_DV_PREFIX) {
        fail("вердикт = %s (%s), ждали prefix", d2k_verdict_name(res.verdict), res.reason);
        dump_trace(&res);
        return;
    }
    /* Сигнатура длиной 4: разрез на 1..3 её ломает, на 4 и правее — нет. */
    if (res.boundary != 4) {
        fail("граница = %d, ждали 4", res.boundary);
    }
    if (res.split_pos != 1) {
        fail("SplitPos = %d, ждали 1", res.split_pos);
    }
    if (res.strategy[0] == '\0') {
        fail("стратегия не заполнена");
    }
}

static void test_prefix_boundary_deeper_signature(void)
{
    d2k_opts opt;
    d2k_result res;
    fast_opts(&opt);
    run_on(M_PREFIX, 9, &opt, &res);
    if (res.verdict != D2K_DV_PREFIX) {
        fail("вердикт = %s (%s), ждали prefix", d2k_verdict_name(res.verdict), res.reason);
        return;
    }
    if (res.boundary != 9) {
        fail("граница = %d, ждали 9", res.boundary);
    }
}

static void test_whole_packet_matcher(void)
{
    d2k_opts opt;
    d2k_result res;
    fast_opts(&opt);
    run_on(M_WHOLE, 0, &opt, &res);
    if (res.verdict != D2K_DV_WHOLE_PACKET) {
        fail("вердикт = %s (%s), ждали whole_packet", d2k_verdict_name(res.verdict), res.reason);
        return;
    }
    if (res.split_pos != 1) {
        fail("SplitPos = %d, ждали 1", res.split_pos);
    }
}

static void test_reassembling_box_is_opaque(void)
{
    d2k_opts opt;
    d2k_result res;
    fast_opts(&opt);
    run_on(M_REASM, 4, &opt, &res);
    if (res.verdict != D2K_DV_OPAQUE) {
        fail("вердикт = %s (%s), ждали opaque", d2k_verdict_name(res.verdict), res.reason);
        return;
    }
    if (res.strategy[0] != '\0') {
        fail("для непрозрачной коробки стратегия предлагаться не должна, а стоит «%s»",
             res.strategy);
    }
}

static void test_clear_tls_without_sni_says_unchecked(void)
{
    d2k_opts opt;
    d2k_result res;
    d2k_trigger t;
    fake_dpi d;
    char addr[64];

    fast_opts(&opt);
    trig(&t);
    t.name[0] = '\0';
    t.accept = D2K_ACCEPT_SERVERHELLO;
    if (fake_dpi_start(&d, M_CLEAR, 0, addr, sizeof(addr)) != 0) {
        fail("стенд не поднялся");
        return;
    }
    d2k_classify_run(addr, &t, &opt, &res);
    fake_dpi_stop(&d);
    if (res.verdict != D2K_DV_CLEAR) {
        fail("вердикт = %s (%s), ждали clear", d2k_verdict_name(res.verdict), res.reason);
        return;
    }
    if (!strstr(res.reason, "ответное направление не проверено: нет SNI")) {
        fail("«чисто» без SNI не говорит, что ответ не проверен: %s", res.reason);
    }
}

static void test_clear_target_stops_early(void)
{
    d2k_opts opt;
    d2k_result res;
    fast_opts(&opt);
    run_on(M_CLEAR, 0, &opt, &res);
    if (res.verdict != D2K_DV_CLEAR) {
        fail("вердикт = %s (%s), ждали clear", d2k_verdict_name(res.verdict), res.reason);
        return;
    }
    /* Смысл ранней остановки: если резать нечего, дерево дальше не идёт.
     * Зонд ответного направления сюда не приходит — у сырого триггера имени
     * нет, и спрашивать про сертификат не о чем. */
    if (res.probes != 2) {
        fail("зондов = %d, ждали ровно 2 (только база)", res.probes);
    }
}

static void test_unreachable_target(void)
{
    d2k_opts opt;
    d2k_result res;
    d2k_trigger t;
    fast_opts(&opt);
    trig(&t);
    d2k_classify_run("127.0.0.1:1", &t, &opt, &res);
    if (res.verdict != D2K_DV_UNREACHABLE) {
        fail("вердикт = %s (%s), ждали unreachable", d2k_verdict_name(res.verdict), res.reason);
    }
}

/* НАШ ИСТЁКШИЙ СРОК — НЕ «ДО ЦЕЛИ НЕТ ТРАНСПОРТА» (задача 19).
 *
 * Поле 12.10.2026, flibusta.is: с роутера `curl` отдаёт 200 с адреса
 * 179.43.150.83, а установка соединения занимает 3,1 с (отказ), 0 с (отказ) и
 * 7,16 с (успех) в трёх попытках подряд. Срок зонда — 6000 мс, поэтому замер
 * не состаивался НИ РАЗУ: поиск 218 раз подряд писал «до цели нет транспорта»
 * и уходил на десять минут. Слова неверные: транспорт есть, не хватило НАШЕГО
 * срока. Вердикт при этом попадал в корзину, где «кандидатов нет и это не
 * бедность перебора» (core/sched.c около 4601), то есть планы не строились
 * вовсе.
 *
 * Отказ сети (ECONNREFUSED у теста выше) — другое дело: это ОТВЕТ, и он
 * остаётся unreachable. Здесь же очередь приёма заполнена, SYN отбрасывается
 * ядром, и подключение именно ВИСНЕТ — ровно то, что в поле. */
static void test_our_dial_deadline_is_not_unreachable(void)
{
    /* Правило проверяется ЧИСТО, без сокета, и вот почему. Нужен ВИСНУЩИЙ
       connect, то есть молчание в ответ на SYN. Заполненная очередь приёма на
       macOS даёт не молчание, а RST («Connection reset by peer»), и это ОТВЕТ
       линии — для него unreachable как раз верен. Стенд, который на этой
       машине не воспроизводит нужное явление, доказывал бы не то; поэтому
       правило вынесено отдельной функцией и спрашивается напрямую. */
    if (!d2k_dial_deadline_err("dial tcp 179.43.150.83:443: i/o timeout")) {
        fail("истёкший срок подключения не узнан как НАШ");
    }
    if (d2k_dial_deadline_err("dial tcp 127.0.0.1:1: Connection refused")) {
        fail("отказ порта принят за наш срок — это ОТВЕТ линии");
    }
    if (d2k_dial_deadline_err("dial tcp 127.0.0.1:1: Connection reset by peer")) {
        fail("сброс принят за наш срок — это ОТВЕТ линии");
    }
    if (d2k_dial_deadline_err("dial tcp: Name or service not known")) {
        fail("отказ разрешения имени принят за наш срок");
    }
    if (d2k_dial_deadline_err("") || d2k_dial_deadline_err(NULL)) {
        fail("пустая ошибка принята за наш срок");
    }
    /* И ОТВЕТ ЛИНИИ ПО-ПРЕЖНЕМУ unreachable: 127.0.0.1:1 отвечает отказом
       порта, то есть говорит о линии, а не о нашем времени. Эту границу
       держит отдельная проверка выше (test_unreachable_target). */
}

static void test_reassembling_box_with_control_stays_opaque(void)
{
    d2k_opts opt;
    d2k_result res;
    int i, saw_control = 0;
    fast_opts(&opt);
    ctl_trig(&opt.control);
    run_on(M_REASM, 4, &opt, &res);
    if (res.verdict != D2K_DV_OPAQUE) {
        fail("вердикт = %s (%s), ждали opaque", d2k_verdict_name(res.verdict), res.reason);
        return;
    }
    for (i = 0; i < res.ntrace; i++) {
        /* Контроль засчитывается по одному проходу и на нём останавливается:
         * дальнейшие повторы исход не меняют (Task 35). */
        if (strcmp(res.trace[i].probe, "control") == 0 && res.trace[i].pass == 1 &&
            res.trace[i].fail == 0) {
            saw_control = 1;
        }
    }
    if (!saw_control) {
        fail("контрольный зонд не отработал или не прошёл");
    }
}

/* Коробка глушит ВСЁ на этом адресе, включая безобидное. Содержимое ни при
 * чём, и предлагать стратегию тут — врать человеку. */
static void test_address_block_is_not_called_opaque(void)
{
    d2k_opts opt;
    d2k_result res;
    fast_opts(&opt);
    ctl_trig(&opt.control);
    /* За контрольное имя ручается оператор — только тогда молчание контроля
     * означает блок по адресу, а не «сервер не отдаёт это имя». */
    opt.control_vouched = 1;
    run_on(M_DEAF, 0, &opt, &res);
    if (res.verdict != D2K_DV_ADDRESS) {
        fail("вердикт = %s (%s), ждали address", d2k_verdict_name(res.verdict), res.reason);
        return;
    }
    if (res.strategy[0] != '\0') {
        fail("для блока по адресу стратегия предлагаться не должна, стоит «%s»", res.strategy);
    }
}

/* Без поручительства за контроль вердикт «режут по адресу» выноситься НЕ
 * должен. Поле 2026-08-28, googlevideo: контроль со случайным именем получил
 * тишину, инструмент объявил блок по адресу — а тот же адрес с нашим обходом
 * отдавал ServerHello за 292 мс. Утверждение было противоположно правде. */
static void test_address_needs_vouched_control(void)
{
    d2k_opts opt;
    d2k_result res;
    fast_opts(&opt);
    ctl_trig(&opt.control);
    run_on(M_DEAF, 0, &opt, &res);
    if (res.verdict != D2K_DV_INCONCLUSIVE) {
        fail("вердикт = %s (%s), ждали inconclusive", d2k_verdict_name(res.verdict), res.reason);
        return;
    }
    if (res.strategy[0] != '\0') {
        fail("без базы стратегия предлагаться не должна, стоит «%s»", res.strategy);
    }
}

/* Задача 54: вопрос «принимает ли адрес данные» на настоящем сокете. Коробка
 * M_DEAF молчит на любое содержимое, но её TCP байт подтверждает — это и
 * отличает «содержимое режут везде» (googlevideo) от тишины адреса. Тишину
 * адреса петля изобразить не может (ядро подтверждает всё) — это поле. */
static void test_neutral_ack_on_real_socket(void)
{
    fake_dpi d;
    char addr[64], host[64], *colon;
    char err[160];
    d2k_opts opt;
    d2k_result res;
    int rc, i, seen = 0;
    fast_opts(&opt);
    if (fake_dpi_start(&d, M_DEAF, 0, addr, sizeof(addr)) != 0) {
        fail("стенд не поднялся");
        return;
    }
    snprintf(host, sizeof(host), "%s", addr);
    colon = strrchr(host, ':');
    *colon = '\0';
    rc = d2k_probe_data_ack(host, colon + 1, &opt, err, sizeof(err));
    if (rc != 1) {
        fail("нейтральный байт на петле не подтверждён: rc=%d (%s)", rc, err);
    }
    /* Через дерево: контроль молчит, байт подтверждён — вердикт прежний
     * (без поручительства «блок адреса» не утверждается), вопрос в трассе. */
    ctl_trig(&opt.control);
    {
        d2k_trigger t;
        trig(&t);
        d2k_classify_run(addr, &t, &opt, &res);
    }
    for (i = 0; i < res.ntrace; i++) {
        if (strcmp(res.trace[i].probe, "neutral-ack") == 0 && res.trace[i].pass == 1 &&
            res.trace[i].fail == 0) {
            seen = 1;
        }
    }
    if (!seen) {
        fail("в трассе нет подтверждённого нейтрального байта");
        dump_trace(&res);
    }
    if (res.verdict != D2K_DV_INCONCLUSIVE) {
        fail("подтверждённый байт: вердикт %s, ждали inconclusive", d2k_verdict_name(res.verdict));
    }
    fake_dpi_stop(&d);
    /* Никто не слушает — нет TCP: это ошибка зонда, не тишина адреса. */
    rc = d2k_probe_data_ack("127.0.0.1", "1", &opt, err, sizeof(err));
    if (rc != -1) {
        fail("закрытый порт: rc=%d, ждали -1", rc);
    }
}

/* БРОШЕННЫЙ ЗАМЕР НЕ ВЫДАЁТСЯ ЗА ИЗМЕРЕННЫЙ.
 *
 * Отмена нужна не ради красоты: без неё остановка службы и истёкший срок
 * задачи ждали окончания перебора — десятки минут (стенд транзита 17.09).
 * Но важнее самого прерывания то, ЧТО остаётся в результате: дерево пройдено
 * не до конца, и любой его вердикт утверждал бы больше, чем известно.
 * Поэтому проверяем два факта, а не один: зондов стало меньше И результат
 * помечен брошенным. */
static int stop_now(void *ctx) { return *(int *)ctx; }

static void test_stopped_run_is_marked_and_short(void)
{
    d2k_opts opt;
    d2k_result res, full;
    int flag = 1;

    /* Сперва — сколько зондов стоит ПОЛНЫЙ прогон на этой же коробке, чтобы
       сравнение шло с измеренным числом, а не с придуманным. */
    fast_opts(&opt);
    run_on(M_PREFIX, 4, &opt, &full);

    fast_opts(&opt);
    opt.cancel.fn = stop_now;
    opt.cancel.ctx = &flag;
    run_on(M_PREFIX, 4, &opt, &res);

    if (!res.stopped) {
        fail("брошенный замер не помечен — его вердикт неотличим от измеренного");
    }
    if (res.probes >= full.probes) {
        fail("отмена не сократила прогон: зондов %d, полный прогон %d",
             res.probes, full.probes);
    }
    if (res.strategy[0] != '\0') {
        fail("брошенный замер предложил стратегию «%s»", res.strategy);
    }
}

/* Отмена ПОСРЕДИ прогона: база успевает пройти, дальше дерево бросают. */
static int stop_after_base(void *ctx)
{
    int *seen = ctx;
    return (*seen)++ >= 4;
}

static void test_stop_midway_keeps_what_was_measured(void)
{
    d2k_opts opt;
    d2k_result res;
    int seen = 0;
    int i, saw_whole = 0;

    fast_opts(&opt);
    opt.cancel.fn = stop_after_base;
    opt.cancel.ctx = &seen;
    run_on(M_PREFIX, 4, &opt, &res);

    if (!res.stopped) {
        fail("замер, брошенный посреди дерева, не помечен");
    }
    /* Измеренное остаётся в трассе: бросили — не значит стёрли. */
    for (i = 0; i < res.ntrace; i++) {
        if (strcmp(res.trace[i].probe, "whole") == 0) { saw_whole = 1; }
    }
    if (!saw_whole) {
        fail("трасса брошенного замера потеряла то, что успели измерить");
    }
}

static void test_loopback_guard_rejects_misresolved_target(void)
{
    d2k_opts opt;
    d2k_result res;
    d2k_trigger t;
    memset(&opt, 0, sizeof(opt));
    opt.repeats = 1;
    trig(&t);
    d2k_classify_run("127.0.0.1:443", &t, &opt, &res);
    if (res.verdict != D2K_DV_FLAKY) {
        fail("вердикт = %s (%s), ждали flaky", d2k_verdict_name(res.verdict), res.reason);
    }
}

/* Настоящие места отправки при SIGPIPE по умолчанию: пир сбросил соединение
 * после первого сегмента / сразу. Процесс обязан дожить, исход — обычный отказ. */
static void test_epipe_survives_at_real_send_sites(void)
{
    fake_dpi d;
    char addr[64], host[64];
    const char *colon;
    d2k_opts opt;
    d2k_result res;
    d2k_trigger t;
    int i;
    void (*old)(int) = signal(SIGPIPE, SIG_DFL);

    fast_opts(&opt);
    trig(&t);
    if (fake_dpi_start(&d, M_RST_AFTER_FIRST, 0, addr, sizeof addr) != 0) {
        fail("стенд не поднялся");
        return;
    }
    d2k_classify_run(addr, &t, &opt, &res); /* многосегментные разрезы */
    if (res.verdict == D2K_DV_CLEAR)
        fail("сброс после первого сегмента не может быть CLEAR");
    fake_dpi_stop(&d);

    if (fake_dpi_start(&d, M_RST_AT_ONCE, 0, addr, sizeof addr) != 0) {
        fail("стенд не поднялся");
        return;
    }
    colon = strrchr(addr, ':');
    snprintf(host, sizeof host, "%.*s", (int)(colon - addr), addr);
    for (i = 0; i < 100; i++) {
        if (d2k_resp_handshake12(host, colon + 1, "example.com", &opt) != 0)
            fail("сброшенный пир не может дать ServerHelloDone");
        d2k_sleep_ms(1);
    }
    fake_dpi_stop(&d);
    signal(SIGPIPE, old);
}

static void test_epipe_and_fresh_neutral(void)
{
    int sv[2];
    char a[64], b[64];
    ssize_t w;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        fail("socketpair");
    close(sv[1]);
    /* без SIG_IGN в тесте: гибель процесса от SIGPIPE и есть провал */
    w = d2k_send_nosig(sv[0], "x", 1);
    w = d2k_send_nosig(sv[0], "x", 1);
    if (w >= 0)
        fail("send на закрытый пир обязан вернуть ошибку");
    close(sv[0]);
    d2k_neutral_sni(a, sizeof a);
    d2k_neutral_sni(b, sizeof b);
    if (strcmp(a, b) == 0)
        fail("нейтральное имя обязано быть свежим: %s", a);
    if (strlen(a) != strlen("z0123456789.example.com") || a[0] != 'z')
        fail("формат нейтрального имени: %s", a);
}

/* Ответ базы, уже снятый отдельно (задача 32 d2k): полный прогон не задаёт
 * "whole" второй раз, а вердикт и граница — те же, что без подсказки. */
static void test_seeded_base_matches_unseeded(void)
{
    static const dpi_mode modes[] = {M_PREFIX, M_WHOLE, M_CLEAR};
    size_t i;
    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        d2k_opts opt, seeded;
        d2k_result a, b;
        const d2k_obs *wa = NULL, *wb = NULL;
        int k;
        fast_opts(&opt);
        run_on(modes[i], 4, &opt, &a);
        for (k = 0; k < a.ntrace; k++) if (!strcmp(a.trace[k].probe, "whole")) { wa = &a.trace[k]; break; }
        if (!wa) { fail("seed: нет наблюдения whole в прогоне без подсказки"); continue; }
        fast_opts(&seeded);
        seeded.seed_whole = 1;
        seeded.seed_repeats = opt.repeats;
        seeded.seed_pass = wa->pass;
        seeded.seed_fail = wa->fail;
        snprintf(seeded.seed_err, sizeof(seeded.seed_err), "%s", wa->err);
        run_on(modes[i], 4, &seeded, &b);
        for (k = 0; k < b.ntrace; k++) if (!strcmp(b.trace[k].probe, "whole")) { wb = &b.trace[k]; break; }
        if (b.verdict != a.verdict || b.boundary != a.boundary)
            fail("seed: вердикт %s/граница %d расходится с прогоном без подсказки (%s/%d)",
                 d2k_verdict_name(b.verdict), b.boundary, d2k_verdict_name(a.verdict), a.boundary);
        if (b.probes != a.probes - opt.repeats)
            fail("seed: зондов %d, ждали %d — база спрошена второй раз", b.probes,
                 a.probes - opt.repeats);
        if (!wb || wb->pass != wa->pass || wb->fail != wa->fail)
            fail("seed: в трассе нет ответа базы");
    }
}


/* Seeded baseline and cancellation keep these guards socket-free. The raw
 * model in test_preflight additionally exercises the same tree with raw enabled. */
static int gate_cancelled;
static int gate_stop(void *ctx) {(void)ctx;return gate_cancelled;}
static void gate_stop_after_base(void *ctx,const d2k_obs *o)
{(void)ctx;if(!strcmp(o->probe,"whole"))gate_cancelled=1;}
static void test_response_gate_needs_vouched_control(void)
{
    d2k_opts o={0};d2k_result r;d2k_trigger t;char err[100];
    if(d2k_trigger_tls("guard.example",1,&t,err,sizeof err)) {fail("TLS fixture");return;}
    o.repeats=o.seed_repeats=1;o.seed_whole=1;o.seed_fail=1;
    o.control_vouched=0;o.on_obs=gate_stop_after_base;
    o.cancel.fn=gate_stop;gate_cancelled=0;
    d2k_classify_run("198.51.100.7:443",&t,&o,&r);
    if(r.verdict==D2K_DV_RESPONSE_GATE || r.preflight.response_gate)
        fail("response gate requires vouched control");
    for(int i=0;i<r.ntrace;i++) if(!strcmp(r.trace[i].probe,"response-gate"))
        fail("unvouched target must not enter gate questions");
}
static void test_healthy_target_not_probed(void)
{
    d2k_opts o={0};d2k_result r;d2k_trigger t;char err[100];
    if(d2k_trigger_tls("guard.example",1,&t,err,sizeof err)) {fail("TLS fixture");return;}
    /* Captured hello has no diagnostic tls:name label, as with an IP context. */
    snprintf(t.name,sizeof t.name,"captured");
    o.repeats=o.seed_repeats=1;o.seed_whole=1;o.seed_pass=1;o.control_vouched=1;
    d2k_classify_run("198.51.100.7:443",&t,&o,&r);
    if(r.verdict!=D2K_DV_CLEAR || r.preflight.response_gate || r.probes!=0 || r.ntrace!=1)
        fail("healthy target must stop before gate questions");
}

/* A premature gate masks both successful cheap branches. Script the raw
 * transport, keeping the actual measure/sweep/verdict tree under test. */
static void gate_tree_scenario(int scenario,d2k_verdict_t expected,const char *name)
{
    d2k_opts o={0};d2k_result r;d2k_trigger t;char err[100];
    if(d2k_trigger_tls("guard.example",1,&t,err,sizeof err)) {fail("TLS fixture");return;}
    o.repeats=o.seed_repeats=1;o.seed_whole=1;o.seed_fail=1;
    o.control_vouched=1;o.timeout_ms=20;
    snprintf(o.only,sizeof o.only,"badsum");
    tree_script=scenario;tree_gate_calls=0;
    d2k_classify_run("198.51.100.7:443",&t,&o,&r);
    int traces=0;for(int i=0;i<r.ntrace;i++)traces+=!strcmp(r.trace[i].probe,"response-gate");
    int asked=scenario==3;
    if(r.verdict!=expected || tree_gate_calls!=asked || traces!=asked)
        fail("%s: verdict=%s calls=%d traces=%d",name,d2k_verdict_name(r.verdict),tree_gate_calls,traces);
    else printf("%s: PASS\n",name);
    tree_script=0;
}
static void test_gate_after_split_success_not_asked(void)
{gate_tree_scenario(1,D2K_DV_PREFIX,__func__);}
static void test_gate_after_poison_success_not_asked(void)
{gate_tree_scenario(2,D2K_DV_POISONABLE,__func__);}
static void test_gate_asked_when_tree_opaque(void)
{gate_tree_scenario(3,D2K_DV_RESPONSE_GATE,__func__);}

int main(int argc,char **argv)
{
    test_gate_after_split_success_not_asked();
    test_gate_after_poison_success_not_asked();
    test_gate_asked_when_tree_opaque();
    test_response_gate_needs_vouched_control();
    test_healthy_target_not_probed();
    if(argc==2 && !strcmp(argv[1],"--response-gate-only")) {
        printf("response gate tree guards: %s\n",fails ? "FAIL" : "PASS");
        return fails ? 1 : 0;
    }
    test_epipe_and_fresh_neutral();
    test_epipe_survives_at_real_send_sites();
    {
        fake_dpi d;
        char addr[64];
        d2k_trigger t;
        d2k_opts opt;
        d2k_result res;
        trig(&t); fast_opts(&opt);
        if (fake_dpi_start_family(&d, M_CLEAR, 0, addr, sizeof addr, AF_INET6) != 0)
            return 1;
        d2k_classify_run(addr, &t, &opt, &res);
        if (res.verdict != D2K_DV_CLEAR || res.probes != 2)
            fail("IPv6 clear target must follow the same two-probe baseline");
        opt.allow_loopback = 0;
        d2k_classify_run(addr, &t, &opt, &res);
        if (res.verdict != D2K_DV_FLAKY || res.probes != 0)
            fail("IPv6 loopback guard must reject before probing");
        fake_dpi_stop(&d);
    }
    printf("перенос: дерево на поддельной коробке\n");
    test_prefix_matcher_finds_boundary();
    test_prefix_boundary_deeper_signature();
    test_whole_packet_matcher();
    test_reassembling_box_is_opaque();
    test_clear_target_stops_early();
    test_clear_tls_without_sni_says_unchecked();
    test_unreachable_target();
    test_our_dial_deadline_is_not_unreachable();
    test_reassembling_box_with_control_stays_opaque();
    test_address_block_is_not_called_opaque();
    test_address_needs_vouched_control();
    test_neutral_ack_on_real_socket();
    test_loopback_guard_rejects_misresolved_target();
    test_stopped_run_is_marked_and_short();
    test_stop_midway_keeps_what_was_measured();
    test_seeded_base_matches_unseeded();
    if (fails) {
        printf("перенос: ПРОВАЛОВ %d\n", fails);
        return 1;
    }
    printf("перенос: дерево совпадает с эталоном\n");
    return 0;
}
