#ifndef D2K_LWEXEC_H
#define D2K_LWEXEC_H

#include <stddef.h>
#include <stdint.h>
#include "d2k_ctq.h"

/* ИСПОЛНИТЕЛЬ МЕДЛЕННЫХ ОПЕРАЦИЙ ПОЗДНЕЙ ДОСТАВКИ (этап 53).
 *
 * Цикл NFQUEUE не ждёт ни ctnetlink (метка, перечисление, проверка маски), ни
 * iptables (правила точного кортежа, блокировка xtables): всё это делает
 * отдельный поток. Цикл кладёт заявку в ограниченную очередь (submit) и на
 * каждом шаге без ожидания забирает готовые итоги (poll). Под замком только
 * копирование заявки/итога — ввода-вывода под замком нет.
 *
 * Полная очередь — отказ submit (вызывающий решает: отказ владельцу или
 * повтор позже), не ожидание. Остановка ждёт поток не дольше срока; зависший
 * поток (iptables -w, ядро) бросается — его остатки уберёт следующий старт. */

enum {
    D2K_LWOP_INIT = 1,      /* выбор способа: проверка маски / свои цепочки */
    D2K_LWOP_INSTALL,       /* поставить доставку кортежу */
    D2K_LWOP_CLEAR,         /* снять доставку кортежу */
    D2K_LWOP_SWEEP          /* уборка остатков прежнего экземпляра */
};

/* Итог операции: как D2K_LW_MARK_* (0 OK, 1 GONE — записи/правила нет, -1 FAIL). */

#define D2K_LW_SWEEP_LIST 256

typedef struct {
    uint8_t op;
    uint8_t orphan;          /* снятие сироты уборки, не слота */
    uint16_t slot;
    uint64_t gen;
    d2k_ct_tuple t;
} d2k_lw_req;

typedef struct {
    uint8_t op;
    uint8_t orphan;
    uint16_t slot;
    uint64_t gen;
    d2k_ct_tuple t;
    int rc;
    /* INIT: выбранный способ (D2K_LW_BACKEND_*). */
    int backend;
    /* SWEEP: перечисление полное; записей больше списка; найденные кортежи. */
    int dump_ok, over;
    size_t n;
    d2k_ct_tuple list[D2K_LW_SWEEP_LIST];
} d2k_lw_done;

enum { D2K_LW_BACKEND_NONE = 0, D2K_LW_BACKEND_MARK = 1, D2K_LW_BACKEND_RULES = 2 };

/* Исполнение одной заявки в потоке исполнителя (может ждать сколько угодно). */
typedef void (*d2k_lwexec_run_fn)(void *ctx, const d2k_lw_req *req, d2k_lw_done *done);

typedef struct d2k_lwexec d2k_lwexec;

/* qcap — ёмкость каждой очереди (заявок и итогов). NULL — нет памяти/потока. */
d2k_lwexec *d2k_lwexec_start(d2k_lwexec_run_fn run, void *ctx, size_t qcap);
/* 0 — принята; -1 — очередь полна или исполнитель остановлен. Не ждёт. */
int  d2k_lwexec_submit(d2k_lwexec *ex, const d2k_lw_req *req);
/* 1 — итог взят в *out; 0 — итогов нет. Не ждёт. */
int  d2k_lwexec_poll(d2k_lwexec *ex, d2k_lw_done *out);
/* Сколько заявок ждёт или исполняется. */
size_t d2k_lwexec_pending(d2k_lwexec *ex);
/* Остановка: 0 — поток завершён и память освобождена; -1 — поток не вышел за
 * timeout_ms (завис в операции) — брошен, память остаётся за ним. При -1 ctx
 * по-прежнему принадлежит брошенному потоку: его нельзя освобождать, а его
 * дескрипторы закрывать — поток может ещё их использовать. */
int  d2k_lwexec_stop(d2k_lwexec *ex, int timeout_ms);

#endif
