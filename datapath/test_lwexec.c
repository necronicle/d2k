#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
/* Этап 53: исполнитель не задерживает цикл пакетов. */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "d2k_lwexec.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s\n", (m)); fails++; } } while (0)

static double now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* Подменённый способ: каждая операция «висит» block_ms (iptables -w, ядро). */
static volatile int block_ms;
static volatile int ran;
static void slow_run(void *ctx, const d2k_lw_req *req, d2k_lw_done *done) {
    (void)ctx;
    if (block_ms) usleep((useconds_t)block_ms * 1000);
    done->rc = req->op == D2K_LWOP_CLEAR ? 1 : 0;
    ran++;
}

int main(void) {
    /* 1. Операции по 300 мс: цикл кладёт и забирает без ожидания. */
    block_ms = 300;
    d2k_lwexec *ex = d2k_lwexec_start(slow_run, NULL, 4);
    CHECK(ex != NULL, "исполнитель не запущен");
    d2k_lw_req r; memset(&r, 0, sizeof r);
    double worst = 0;
    int accepted = 0, refused = 0;
    for (int i = 0; i < 6; i++) {
        r.op = (uint8_t)(i % 2 ? D2K_LWOP_CLEAR : D2K_LWOP_INSTALL); r.slot = (uint16_t)i; r.gen = (uint64_t)i + 1;
        double a = now_ms();
        if (d2k_lwexec_submit(ex, &r) == 0) accepted++; else refused++;
        double d = now_ms() - a; if (d > worst) worst = d;
    }
    CHECK(accepted == 4 && refused == 2, "переполнение очереди не отказывает (или очередь шире ёмкости)");
    d2k_lw_done got[8]; int n = 0;
    double t0 = now_ms();
    while (n < 4 && now_ms() - t0 < 5000) {
        double a = now_ms();
        if (d2k_lwexec_poll(ex, &got[n])) n++;
        double d = now_ms() - a; if (d > worst) worst = d;
        usleep(1000);                               /* «пакеты» между опросами */
    }
    CHECK(worst < 20.0, "submit/poll ждали исполнителя (цикл пакетов задерживается)");
    CHECK(n == 4 && got[0].slot == 0 && got[3].slot == 3 && got[0].gen == 1 && got[1].rc == 1,
          "итоги потеряны или не по порядку заявок");
    CHECK(d2k_lwexec_pending(ex) == 0, "после всех итогов исполнитель числит заявки");
    CHECK(d2k_lwexec_stop(ex, 1000) == 0, "остановка свободного исполнителя не завершилась");

    /* 2. Зависший исполнитель (операция 10 с): остановка не ждёт дольше срока. */
    block_ms = 10000; ran = 0;
    ex = d2k_lwexec_start(slow_run, NULL, 4);
    r.op = D2K_LWOP_CLEAR; r.slot = 9;
    CHECK(d2k_lwexec_submit(ex, &r) == 0, "заявка не принята");
    usleep(50000);
    double a = now_ms();
    int st = d2k_lwexec_stop(ex, 300);
    double d = now_ms() - a;
    CHECK(st == -1 && d < 800.0, "остановка с зависшим исполнителем ждала дольше срока или назвала его завершённым");

    puts(fails ? "исполнитель: ЕСТЬ ПРОВАЛЫ" : "исполнитель: все проверки прошли");
    return fails ? 1 : 0;
}
