#ifndef D2K_DIAGNOSTICS_H
#define D2K_DIAGNOSTICS_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
/* Observer only: callback on the controller thread, never influences verdicts. */
typedef struct {
    uint64_t id;
    int64_t elapsed_ms, queue_ms, probe_units;
    unsigned family, trigger, shape;
    const char *target, *protocol, *outcome, *reason, *ip, *path, *kind;
    /* ПРИЧИНА САМОГО ИТОГА, задаваемая в точке его объявления (23.10.2026).
     *
     * reason выше — последняя фраза классификатора, и она про ЦЕЛЬ, а не про
     * итог. В диагностике владельца 23.10 они противоречили друг другу в 18
     * событиях из 61: «probe-confirmed» с текстом «замер брошен, о цели не
     * сказано ничего», «failed» с текстом «дальнейшие вопросы не нужны».
     * Поле отдельное именно поэтому: фразу классификатора терять не надо — она
     * полезный контекст, — но итог обязан объяснять себя сам. */
    const char *outcome_reason;
    /* ИДЕНТИЧНОСТЬ РЕШЕНИЯ. Пусто — решения нет (итог без плана). Без них
     * «own-plan подтверждён» по одиннадцати именам не сверить с каталогом:
     * какой план и какая коробка — из события не узнать. */
    const char *plan_id, *box_id;
} d2k_diag_event;
typedef void (*d2k_diag_observer)(void *, const d2k_diag_event *);
/* Requested allocation sizes, not allocator overhead or resident pages.
 * Cumulative counters belong to the scheduler lifetime, even with history off. */
typedef struct {
    uint64_t workers_started, workers_joined, worker_join_errors;
    uint64_t worker_start_while_live; /* запуск при неприсоединённом прежнем потоке */
    uint64_t worker_args_allocated, worker_args_freed, worker_args_live, worker_args_live_bytes;
    uint64_t http_records_capacity, http_records_bytes, http_queue_capacity, http_queue_bytes;
    uint64_t http_failures, http_failures_bytes;
    uint64_t task_madvise_calls, task_madvise_successes, task_madvise_requested_bytes;
    uint64_t task_madvise_last_errno;
    uint64_t catalog_boxes_bytes, catalog_plans_bytes, catalog_bindings_bytes;
} d2k_diag_memory;
typedef struct {
    d2k_diag_memory memory;
    uint64_t boxes, bindings, plans, observations, active, queued, tasks, snapshots, http_records, http_queued;
} d2k_diag_counts;
typedef struct d2k_diag d2k_diag;
d2k_diag *d2k_diag_new(void);
void d2k_diag_free(d2k_diag *d);
size_t d2k_diag_bytes(const d2k_diag *d);
size_t d2k_diag_event_count(const d2k_diag *d);
size_t d2k_diag_sample_count(const d2k_diag *d);
void d2k_diag_record(d2k_diag *d,const d2k_diag_event *e);
void d2k_diag_sample(d2k_diag *d,int64_t mono_ms,const d2k_diag_counts *c,const char *proc,const char *run);
int d2k_diag_write(const d2k_diag *d,FILE *f);
#endif
