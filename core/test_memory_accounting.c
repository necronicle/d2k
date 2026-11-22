/* Real scheduler lifecycle; no network. OS failures are injected after a
 * real join, so the legacy ignored-error path cannot strand a test worker. */
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdlib.h>

static int refuse_allocation;
static void *test_calloc(size_t count, size_t size) {
    return refuse_allocation ? NULL : calloc(count, size);
}
#include <sys/mman.h>
int accounting_join(pthread_t, void **);
int accounting_create(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *);
int accounting_madvise(void *,size_t,int);
#define D2K_TEST_PAGE_RELEASE 1
#define pthread_create accounting_create
#define pthread_join accounting_join
#define madvise accounting_madvise
#define calloc test_calloc
#include "sched.c"
#undef calloc
#include "test_task_slots.h"
#undef pthread_create
#undef pthread_join
#undef madvise
#include <assert.h>
static int join_error, page_error, hold_arg, release_arg;
static pthread_mutex_t arg_mu=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t arg_cv=PTHREAD_COND_INITIALIZER;
static void *(*held_entry)(void *);
static void *last_arg;
static void *held_worker(void *arg) {
    pthread_mutex_lock(&arg_mu);
    while(!release_arg)pthread_cond_wait(&arg_cv,&arg_mu);
    pthread_mutex_unlock(&arg_mu);
    return held_entry(arg);
}
int accounting_create(pthread_t *th,const pthread_attr_t *attr,void *(*entry)(void *),void *arg) {
    last_arg=arg;
    if(!hold_arg)return pthread_create(th,attr,entry,arg);
    held_entry=entry;
    return pthread_create(th,attr,held_worker,arg);
}
int accounting_join(pthread_t th, void **value) {
    int rc=pthread_join(th,value);
    return rc ? rc : join_error;
}
int accounting_madvise(void *addr,size_t bytes,int advice) {
    assert(addr && bytes && advice==MADV_DONTNEED);
    assert((uintptr_t)addr%(size_t)sysconf(_SC_PAGESIZE)==0);
    if(page_error){errno=page_error;return -1;}
    return 0;
}
static d2k_stun_probe_res no_network(const d2k_stun_probe_opt *opt) {
    (void)opt; d2k_stun_probe_res r={0};return r;
}
static int refuse_spawn(void) {return -1;}
static d2k_diag_counts counts(d2k_sched *s) {
    d2k_diag_counts c={0};d2k_sched_diagnostic_counts(s,&c);return c;
}
int main(void) {
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0);assert(s);
    assert(sizeof s->tasks <= SCHED_MAX_TASKS * sizeof(void *));
    assert(s->task_count == 0 && measure_slots(s) == SCHED_MEASURE_SLOTS);
    refuse_allocation = 1;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = task_free_slot(s);
        assert(t && s->task_count == i + 1);
        t->state = T_WATCHING;
    }
    assert(!task_free_slot(s) && !measure_slots(s));
    s->tasks[3]->state = T_FREE;
    assert(task_free_slot(s) == s->tasks[3] && measure_slots(s) == 1);
    refuse_allocation = 0;
    d2k_sched_stun_hook=no_network;
    for(int batch=0;batch<3;batch++) {
        for(int i=0;i<SCHED_MAX_TASKS;i++) {
            task *t=test_task_at(s, i); task_reset(s,t);
            strcpy(t->ip,"192.0.2.1");t->family=4;t->port=3478;
            assert(start_worker(s,t,JOB_STUN)==0);
            /* Аргумент — постоянный слот задачи, а не выделение на каждый
               поток: память не переходит между потоками через malloc/free. */
            assert(last_arg==(void *)&((task_slot *)t)->worker);
        }
        for(int i=0;i<SCHED_MAX_TASKS;i++) join_worker(test_task_at(s, i));
        d2k_diag_counts c=counts(s);
        assert(c.memory.workers_started==(uint64_t)(batch+1)*SCHED_MAX_TASKS);
        assert(c.memory.workers_joined==c.memory.workers_started);
        assert(c.memory.worker_args_allocated==c.memory.worker_args_freed);
        assert(c.memory.worker_args_live==0 && c.memory.worker_args_live_bytes==0);
        assert(c.memory.worker_join_errors==0);
    }
    /* Delay entry of one real pthread to measure an owned, not yet freed,
       argument deterministically. */
    hold_arg=1;assert(!start_worker(s,test_task_at(s, 0),JOB_STUN));
    d2k_diag_counts held=counts(s);
    assert(held.memory.worker_args_live==1);
    assert(held.memory.worker_args_live_bytes==sizeof(worker_arg));
    pthread_mutex_lock(&arg_mu);release_arg=1;pthread_cond_signal(&arg_cv);pthread_mutex_unlock(&arg_mu);
    join_worker(test_task_at(s, 0));hold_arg=0;
    held=counts(s);assert(held.memory.worker_args_live==0 && held.memory.worker_args_live_bytes==0);
    /* Повторный запуск на задаче с живым (завершившимся, но не присоединённым)
       потоком сначала присоединяет прежний: иначе его стек и слот остаются
       навсегда, а аргумент нового потока затирает ещё не прочитанный. */
    release_arg=0;hold_arg=1;
    assert(!start_worker(s,test_task_at(s, 1),JOB_STUN));
    pthread_mutex_lock(&arg_mu);release_arg=1;pthread_cond_signal(&arg_cv);pthread_mutex_unlock(&arg_mu);
    hold_arg=0;
    d2k_diag_counts ov=counts(s);
    assert(!start_worker(s,test_task_at(s, 1),JOB_STUN));
    held=counts(s);
    assert(held.memory.workers_joined==ov.memory.workers_joined+1);
    assert(held.memory.worker_start_while_live==ov.memory.worker_start_while_live+1);
    join_worker(test_task_at(s, 1));
    held=counts(s);
    assert(held.memory.workers_started==held.memory.workers_joined);
    assert(held.memory.worker_args_live==0);
    d2k_diag_counts before=counts(s);
    d2k_sched_spawn_hook=refuse_spawn;
    assert(start_worker(s,test_task_at(s, 0),JOB_STUN)==-1);
    d2k_sched_spawn_hook=NULL;
    d2k_diag_counts after=counts(s);
    assert(after.memory.workers_started==before.memory.workers_started);
    assert(after.memory.worker_args_allocated==before.memory.worker_args_allocated+1);
    assert(after.memory.worker_args_freed==before.memory.worker_args_freed+1);
    assert(after.memory.worker_args_live==0);
    assert(start_worker(s,test_task_at(s, 0),JOB_STUN)==0);
    join_error=EINVAL; join_worker(test_task_at(s, 0)); join_error=0;
    after=counts(s);
    assert(after.memory.worker_join_errors==1);
    assert(after.memory.workers_started==after.memory.workers_joined+1);
    /* The pre-existing behavior clears th_live even on join failure. */
    assert(!test_task_at(s, 0)->th_live);
    before=counts(s); task_reset(s,test_task_at(s, 0)); after=counts(s);
    assert(after.memory.task_madvise_calls==before.memory.task_madvise_calls+1);
    assert(after.memory.task_madvise_successes==before.memory.task_madvise_successes+1);
    assert(after.memory.task_madvise_requested_bytes>before.memory.task_madvise_requested_bytes);
    assert(after.memory.task_madvise_last_errno==0);
    before=after;page_error=ENOMEM;task_reset(s,test_task_at(s, 0));after=counts(s);
    assert(after.memory.task_madvise_calls==before.memory.task_madvise_calls+1);
    assert(after.memory.task_madvise_successes==before.memory.task_madvise_successes);
    assert(after.memory.task_madvise_requested_bytes>before.memory.task_madvise_requested_bytes);
    assert(after.memory.task_madvise_last_errno==ENOMEM);
    page_error=0;
    /* Loader allocation is geometric; logical count alone undercounts it.
       Duplicate keys deliberately keep the original local-cap growth policy. */
    char file[]="/tmp/d2k-accounting-catalog-XXXXXX",err[160];
    int fd=mkstemp(file);assert(fd>=0);FILE *f=fdopen(fd,"w");assert(f);
    fputs("{\"boxes\":[{\"id\":\"memory-box\",\"plans\":[{\"id\":\"p\",\"text\":\"x\"}],\"bindings\":[{\"target\":\"a.example\"}],\"bindings\":[{\"target\":\"b.example\"}]}]}",f);
    assert(!fclose(f));assert(!d2k_catalog_load(file,&cat,err,sizeof err));unlink(file);
    after=counts(s);
    assert(cat.cap_boxes==4 && cat.boxes[0].cap_plans==4 && cat.boxes[0].cap_binds==2);
    assert(after.memory.catalog_boxes_bytes==4*sizeof(d2k_cat_box));
    assert(after.memory.catalog_plans_bytes==4*sizeof(d2k_cat_plan));
    assert(after.memory.catalog_bindings_bytes==2*sizeof(d2k_cat_binding));
    cat.boxes[0].n_binds--; /* removal retains the allocation */
    after=counts(s);assert(after.bindings==1);
    assert(after.memory.catalog_bindings_bytes==2*sizeof(d2k_cat_binding));
    assert(box_ensure(&cat,"second-box"));after=counts(s);
    assert(cat.cap_boxes==2 && after.memory.catalog_boxes_bytes==2*sizeof(d2k_cat_box));
    d2k_sched_free(s);d2k_catalog_free(&cat);
    assert(cat.cap_boxes==0);
    puts("worker ownership, join errors, task pages and catalog capacity PASS");
    return 0;
}
