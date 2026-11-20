#ifndef D2K_SHADOW_H
#define D2K_SHADOW_H
#include "d2k_shadow_queue.h"
#include "d2k_exp_task.h"
#include <string.h>
/* Resource bound, not a search budget. Full tables fail closed: an active
 * cooldown is never evicted to make room for another target. */
#define D2K_SHADOW_DEDUP_MAX 512u
typedef struct {
    struct { d2k_shadow_record target; uint64_t until; int used; } entries[D2K_SHADOW_DEDUP_MAX];
    uint64_t dropped;
} d2k_shadow_dedup;
int d2k_shadow_dedup_load(const char *path,d2k_shadow_dedup *,uint64_t now);
int d2k_shadow_dedup_save(const char *path,const d2k_shadow_dedup *,uint64_t now);
/* Exact task ownership; another form/address/port has its own trial stream. */
int d2k_shadow_same_context(const d2k_shadow_record *,const d2k_shadow_record *);
int d2k_shadow_admit(d2k_shadow_dedup *,const d2k_shadow_record *,uint64_t now);
/* Pure admission rejection for an already known exact context, never table full. */
int d2k_shadow_obsolete(const d2k_shadow_dedup *,const d2k_shadow_record *,uint64_t now);
static inline unsigned d2k_shadow_queue_rank(void *ctx,const d2k_shadow_record *r)
{
    const d2k_shadow_dedup *d=ctx;
    /* Fairness is about targets awaiting their first DIRECT, not proof that
       different forms are compatible. Each form keeps its own task/bytes.
       Durable admission history also survives watchdog restarts. */
    for(size_t i=0;i<D2K_SHADOW_DEDUP_MAX;i++) {
        const d2k_shadow_record *e=&d->entries[i].target;
        if(d->entries[i].used && e->family==r->family && e->port==r->port &&
           (e->protocol?e->protocol:2)==(r->protocol?r->protocol:2) &&
           !strcmp(e->host,r->host))return 1;
    }
    return 0;
}
void d2k_shadow_complete(d2k_shadow_dedup *,const d2k_shadow_record *,uint64_t now,
                         const d2km_task_report *);
int d2k_shadow_log(const char *path,const d2k_shadow_record *,uint64_t now,
                    const d2km_task_report *);
/* A single sequential task plus summary; injected_net shares all assembly
 * with the real marked netarm and permits network-free simulator tests. */
int d2k_shadow_pick_names(const d2k_shadow_recent *,const d2k_shadow_recent *,
                           const d2k_shadow_record *,uint64_t now,
                           d2k_shadow_record *chosen,char *reason,size_t cap);
int d2k_shadow_pick_name(const d2k_shadow_recent *,const d2k_shadow_record *,uint64_t now,
                          d2k_shadow_record *chosen,char *reason,size_t cap);
int d2k_shadow_run(const d2k_shadow_record *,const d2k_exp_options *,d2km_store *,
                    d2km_journal *,const d2km_net *injected_net,const char *log,
                    d2km_task_report *);
#endif
