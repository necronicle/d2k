#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* Этап 53: нехватка памяти при запуске исполнителя (находка ревью) — запуск
   отказывает, а не принимает заявки, которые некому исполнить. lwexec.c
   собран с -Dcalloc=fault_calloc: отказывает calloc номер fail_at. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "d2k_lwexec.h"

static int fails, calls, fail_at;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s\n", (m)); fails++; } } while (0)
void *fault_calloc(size_t n, size_t sz);
void *fault_calloc(size_t n, size_t sz) {
    if (++calls == fail_at) return NULL;
    return calloc(n, sz);
}
static void run(void *ctx, const d2k_lw_req *req, d2k_lw_done *done) { (void)ctx; (void)req; done->rc = 0; }

int main(void) {
    for (fail_at = 1; fail_at <= 6; fail_at++) {
        calls = 0;
        d2k_lwexec *ex = d2k_lwexec_start(run, NULL, 4);
        if (!ex) continue;                       /* отказ запуска — честно */
        d2k_lw_req r; memset(&r, 0, sizeof r); r.op = D2K_LWOP_INSTALL;
        CHECK(d2k_lwexec_submit(ex, &r) == 0, "исправный исполнитель не принял заявку");
        d2k_lw_done d; int got = 0;
        for (int i = 0; i < 2000 && !got; i++) { got = d2k_lwexec_poll(ex, &d); if (!got) { struct timespec ts = {0, 1000000}; nanosleep(&ts, NULL); } }
        CHECK(got, "запущенный исполнитель принял заявку и не исполнил (поток вышел без памяти)");
        CHECK(d2k_lwexec_stop(ex, 1000) == 0, "остановка");
    }
    puts(fails ? "исполнитель без памяти: ЕСТЬ ПРОВАЛЫ" : "исполнитель без памяти: все проверки прошли");
    return fails ? 1 : 0;
}
