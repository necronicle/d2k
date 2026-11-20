#define _POSIX_C_SOURCE 200809L
/* Исполнитель медленных операций поздней доставки (этап 53), см.
   include/d2k_lwexec.h. Под замком — только копирование заявок и итогов. */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "d2k_lwexec.h"

struct d2k_lwexec {
    pthread_t th;
    pthread_mutex_t mu;
    pthread_cond_t cv;          /* заявка пришла / место под итог / остановка */
    pthread_cond_t exited_cv;
    d2k_lwexec_run_fn run;
    void *ctx;
    size_t cap;
    d2k_lw_req *req;            /* кольцо заявок */
    size_t rq_head, rq_n;
    d2k_lw_done *done;          /* кольцо итогов */
    size_t dn_head, dn_n;
    size_t busy;                /* исполняется сейчас (0/1) */
    int stopping, exited;
    d2k_lw_done *scratch;       /* итог в работе: выделен до запуска потока */
};

static void *worker(void *arg) {
    d2k_lwexec *ex = arg;
    d2k_lw_done *out = ex->scratch;
    /* Сигналы — главному потоку (останов службы); ожидания исполнителя
       (waitpid, ядро) ими не прерываются. */
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);
    pthread_mutex_lock(&ex->mu);
    for (;;) {
        while (!ex->stopping && !ex->rq_n) pthread_cond_wait(&ex->cv, &ex->mu);
        if (ex->stopping) break;
        d2k_lw_req r = ex->req[ex->rq_head];
        ex->rq_head = (ex->rq_head + 1) % ex->cap;
        ex->rq_n--;
        ex->busy = 1;
        pthread_mutex_unlock(&ex->mu);

        memset(out, 0, sizeof *out);
        out->op = r.op; out->orphan = r.orphan; out->slot = r.slot; out->gen = r.gen; out->t = r.t;
        out->rc = -1;
        ex->run(ex->ctx, &r, out);          /* может ждать: ядро, iptables -w */

        pthread_mutex_lock(&ex->mu);
        /* Итог не теряется: нет места — ждём, пока цикл заберёт (ждёт поток
           исполнителя, не цикл пакетов). */
        while (!ex->stopping && ex->dn_n == ex->cap) pthread_cond_wait(&ex->cv, &ex->mu);
        ex->busy = 0;
        if (ex->stopping) break;
        ex->done[(ex->dn_head + ex->dn_n) % ex->cap] = *out;
        ex->dn_n++;
    }
    ex->exited = 1;
    pthread_cond_broadcast(&ex->exited_cv);
    pthread_mutex_unlock(&ex->mu);
    return NULL;
}

d2k_lwexec *d2k_lwexec_start(d2k_lwexec_run_fn run, void *ctx, size_t qcap) {
    if (!run || !qcap) return NULL;
    d2k_lwexec *ex = calloc(1, sizeof *ex);
    if (!ex) return NULL;
    /* Всё, что нужно потоку, — до его запуска: поток без памяти принимал бы
       заявки, которые некому исполнить (находка ревью, этап 53). */
    ex->req = calloc(qcap, sizeof *ex->req);
    ex->done = calloc(qcap, sizeof *ex->done);
    ex->scratch = calloc(1, sizeof *ex->scratch);
    if (!ex->req || !ex->done || !ex->scratch) goto fail_mem;
    ex->run = run; ex->ctx = ctx; ex->cap = qcap;
    if (pthread_mutex_init(&ex->mu, NULL) != 0) goto fail_mem;
    if (pthread_cond_init(&ex->cv, NULL) != 0) goto fail_mu;
    if (pthread_cond_init(&ex->exited_cv, NULL) != 0) goto fail_cv;
    if (pthread_create(&ex->th, NULL, worker, ex) != 0) goto fail_ecv;
    return ex;
fail_ecv:
    pthread_cond_destroy(&ex->exited_cv);
fail_cv:
    pthread_cond_destroy(&ex->cv);
fail_mu:
    pthread_mutex_destroy(&ex->mu);
fail_mem:
    free(ex->req); free(ex->done); free(ex->scratch); free(ex);
    return NULL;
}

int d2k_lwexec_submit(d2k_lwexec *ex, const d2k_lw_req *req) {
    if (!ex || !req) return -1;
    pthread_mutex_lock(&ex->mu);
    /* Ёмкость — заявки в очереди плюс исполняемая: больше cap не ждёт никто.
       Вышедший поток заявок не берёт. */
    int ok = !ex->stopping && !ex->exited && ex->rq_n + ex->busy < ex->cap;
    if (ok) {
        ex->req[(ex->rq_head + ex->rq_n) % ex->cap] = *req;
        ex->rq_n++;
        pthread_cond_broadcast(&ex->cv);
    }
    pthread_mutex_unlock(&ex->mu);
    return ok ? 0 : -1;
}

int d2k_lwexec_poll(d2k_lwexec *ex, d2k_lw_done *out) {
    if (!ex || !out) return 0;
    pthread_mutex_lock(&ex->mu);
    int got = ex->dn_n > 0;
    if (got) {
        *out = ex->done[ex->dn_head];
        ex->dn_head = (ex->dn_head + 1) % ex->cap;
        ex->dn_n--;
        pthread_cond_broadcast(&ex->cv);
    }
    pthread_mutex_unlock(&ex->mu);
    return got;
}

size_t d2k_lwexec_pending(d2k_lwexec *ex) {
    if (!ex) return 0;
    pthread_mutex_lock(&ex->mu);
    size_t n = ex->rq_n + ex->busy;
    pthread_mutex_unlock(&ex->mu);
    return n;
}

int d2k_lwexec_stop(d2k_lwexec *ex, int timeout_ms) {
    if (!ex) return 0;
    pthread_mutex_lock(&ex->mu);
    ex->stopping = 1;
    pthread_cond_broadcast(&ex->cv);
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += timeout_ms / 1000;
    dl.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
    while (!ex->exited) {
        if (pthread_cond_timedwait(&ex->exited_cv, &ex->mu, &dl) == ETIMEDOUT) break;
    }
    int exited = ex->exited;
    pthread_mutex_unlock(&ex->mu);
    if (!exited) {
        /* Поток висит в операции: бросаем его; память остаётся за ним —
           освободить её под живым потоком нельзя. */
        pthread_detach(ex->th);
        return -1;
    }
    pthread_join(ex->th, NULL);
    pthread_mutex_destroy(&ex->mu);
    pthread_cond_destroy(&ex->cv);
    pthread_cond_destroy(&ex->exited_cv);
    free(ex->req); free(ex->done); free(ex->scratch); free(ex);
    return 0;
}
