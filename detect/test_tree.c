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
#include "d2k_detect.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
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

typedef enum { M_PREFIX, M_WHOLE, M_REASM, M_CLEAR, M_DEAF } dpi_mode;

typedef struct {
    int      fd;
    dpi_mode mode;
    int      sig_len;
} fake_dpi;

typedef struct {
    fake_dpi *d;
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
    fake_dpi *d = j->d;
    int c = j->fd;
    uint8_t buf[4096];
    uint8_t all[8192];
    size_t alen;
    ssize_t n;
    int blocked = 0;
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
    (void)send(c, "SERVER-ANSWER", 13, 0);
    close(c);
    return NULL;
}

static void *dpi_thread(void *arg)
{
    fake_dpi *d = arg;
    for (;;) {
        pthread_t th;
        conn_job *j;
        int c = accept(d->fd, NULL, NULL);
        if (c < 0) {
            return NULL;
        }
        j = malloc(sizeof(*j));
        if (!j) {
            close(c);
            continue;
        }
        j->d = d;
        j->fd = c;
        if (pthread_create(&th, NULL, conn_thread, j) != 0) {
            close(c);
            free(j);
            continue;
        }
        pthread_detach(th);
    }
}

static int fake_dpi_start(fake_dpi *d, dpi_mode mode, int sig_len, char *addr, size_t cap)
{
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    pthread_t th;
    int one = 1;

    memset(d, 0, sizeof(*d));
    d->mode = mode;
    d->sig_len = sig_len;
    d->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (d->fd < 0) {
        return -1;
    }
    (void)setsockopt(d->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(d->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        return -1;
    }
    if (listen(d->fd, 16) != 0) {
        return -1;
    }
    if (getsockname(d->fd, (struct sockaddr *)&sa, &sl) != 0) {
        return -1;
    }
    snprintf(addr, cap, "127.0.0.1:%u", (unsigned)ntohs(sa.sin_port));
    if (pthread_create(&th, NULL, dpi_thread, d) != 0) {
        return -1;
    }
    pthread_detach(th);
    return 0;
}

static void fake_dpi_stop(fake_dpi *d)
{
    shutdown(d->fd, SHUT_RDWR);
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
        if (strcmp(res.trace[i].probe, "control") == 0 && res.trace[i].pass == opt.repeats) {
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

int main(void)
{
    printf("перенос: дерево на поддельной коробке\n");
    test_prefix_matcher_finds_boundary();
    test_prefix_boundary_deeper_signature();
    test_whole_packet_matcher();
    test_reassembling_box_is_opaque();
    test_clear_target_stops_early();
    test_unreachable_target();
    test_reassembling_box_with_control_stays_opaque();
    test_address_block_is_not_called_opaque();
    test_address_needs_vouched_control();
    test_loopback_guard_rejects_misresolved_target();
    if (fails) {
        printf("перенос: ПРОВАЛОВ %d\n", fails);
        return 1;
    }
    printf("перенос: дерево совпадает с эталоном\n");
    return 0;
}
