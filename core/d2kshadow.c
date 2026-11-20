/* Resource-bounded observer of live controller suspicions. It never installs a
 * production binding: only the experimental control socket is available. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2k_shadow.h"
#include "d2k_shadow_workers.h"
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static int failed;
static void stop(int sig) { (void)sig;stopping=1; }
static void usage(void)
{
    fprintf(stderr,"d2kshadow [--queue PATH] [--form PATH] [--store PATH]\n"
        "  [--journal PATH] [--log PATH] [--exp-control PATH] [--daemon-log PATH]\n");
}
typedef struct { const char *path;d2km_store *store; } checkpoint;
static int knowledge_checkpoint(void *arg) {
    checkpoint *c=arg;d2km_store_error err={0};
    if(d2km_store_save(c->path,c->store,&err)==D2KM_STORE_OK)return 0;
    fprintf(stderr,"d2kshadow: DEGRADED не сохранён до DIRECT: %s\n",err.reason);return -1;
}
typedef struct {
    pthread_mutex_t mutex;
    d2km_store *catalog;
    d2k_shadow_dedup *dedup;
    d2km_journal *journal;
    const char *queue,*store_path,*form,*legacy_form,*exp,*log,*seen;
} owner_state;
static uint64_t monotonic_ms(void) {
    struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000+(uint64_t)ts.tv_nsec/1000000;
}
typedef struct {
    pthread_t thread;int active,done;d2k_shadow_record record;owner_state *owner;
    unsigned id,arms;uint64_t started,network_started,network_ms;
} worker_slot;
typedef struct {owner_state *owner;worker_slot *slots;} prune_state;
static int obsolete_record(void *ctx,const d2k_shadow_record *r) {
    prune_state *p=ctx;
    /* A dispatched worker may not have copied its bytes yet. */
    for(unsigned i=0;i<D2K_SHADOW_WORKERS_MAX;i++)
        if(p->slots[i].active && r->snapshot && p->slots[i].record.snapshot==r->snapshot)return 0;
    int discard=d2k_shadow_obsolete(p->owner->dedup,r,(uint64_t)time(NULL));
    if(discard)fprintf(stderr,"d2kshadow: discard host=%s ip=%s port=%u family=%u protocol=%u form=%016llx signal_time=%llu snapshot=%016llx why=durable-admission-reject; queued signal cannot wake this exact context\n",
        r->host,r->ip,(unsigned)r->port,(unsigned)r->family,(unsigned)r->protocol,
        (unsigned long long)r->form_key,(unsigned long long)r->time,(unsigned long long)r->snapshot);
    return discard;
}
static void network_begin(void *p) {
    worker_slot *slot=p;slot->network_started=monotonic_ms();slot->arms++;
    pthread_mutex_unlock(&slot->owner->mutex);
}
static void network_end(void *p) {
    worker_slot *slot=p;slot->network_ms+=monotonic_ms()-slot->network_started;
    pthread_mutex_lock(&slot->owner->mutex);
}
static void *work(void *p) {
    worker_slot *slot=p;owner_state *s=slot->owner;
    pthread_mutex_lock(&s->mutex);
    d2k_shadow_record *r=&slot->record;
    d2km_task_report *report=calloc(1,sizeof *report);
    if(!report) {failed=1;stopping=1;slot->done=1;pthread_mutex_unlock(&s->mutex);return NULL;}
    checkpoint durable={.path=s->store_path,.store=s->catalog};
    d2k_exp_options options={.host=r->host,.ip=r->ip,.form=r->protocol==1?s->legacy_form:s->form,
        .shadow_queue=s->queue,.exp_control=s->exp,.port=r->port,.family=r->family,.mark=0x2f,.cancel=&stopping,
        .knowledge_changed=knowledge_checkpoint,.knowledge_changed_ctx=&durable,
        .network_begin=network_begin,.network_end=network_end,.network_ctx=slot,
        .shared_experiment=&s->catalog->next_experiment,.shared_fact=&s->catalog->next_fact};
    (void)d2k_shadow_run(r,&options,s->catalog,s->journal,NULL,s->log,report);
    d2km_store_error error={0};
    if(d2km_store_save(s->store_path,s->catalog,&error)!=D2KM_STORE_OK) {
        fprintf(stderr,"d2kshadow: хранилище не сохранено: %s\n",error.reason);failed=1;stopping=1;
    }
    uint64_t now=(uint64_t)time(NULL);d2k_shadow_complete(s->dedup,r,now,report);
    if(d2k_shadow_dedup_save(s->seen,s->dedup,now)) {
        fprintf(stderr,"d2kshadow: не сохранён итог отсрочки; опыты остановлены\n");failed=1;stopping=1;
    }
    fprintf(stderr,"d2kshadow: finish worker=%u time=%llu host=%s form=%016llx elapsed_ms=%llu network_ms=%llu network_sections=%u outcome=%s\n",
        slot->id,(unsigned long long)now,r->host,(unsigned long long)r->form_key,
        (unsigned long long)(monotonic_ms()-slot->started),(unsigned long long)slot->network_ms,
        slot->arms,d2km_outcome_name(report->outcome));
    free(report);slot->done=1;pthread_mutex_unlock(&s->mutex);return NULL;
}
static uint64_t available_memory(void) {
#ifdef __linux__
    FILE *f=fopen("/proc/meminfo","r");if(!f)return 0;
    char line[256];unsigned long long kb=0;
    while(fgets(line,sizeof line,f))if(sscanf(line,"MemAvailable: %llu kB",&kb)==1)break;
    fclose(f);return kb>UINT64_MAX/1024?UINT64_MAX:(uint64_t)kb*1024;
#else
    /* Lifecycle/offline tests admit one worker by memory; no router
       estimate is inferred from a desktop's physical memory. */
    return 2*d2k_exp_task_memory();
#endif
}
int main(int argc,char **argv)
{
    const char *queue="/tmp/d2k/shadow.queue",*form="/opt/d2k/files/modern.hex",*legacy_form="/opt/d2k/files/legacy.hex";
    const char *store_path="/opt/d2k/state/shadow.d2km",*journal_path="/opt/d2k/log/shadow-why.jsonl";
    const char *log="/opt/d2k/log/shadow.log",*exp="/opt/d2k/run/d2kd-exp.sock",*daemon_log=NULL;
    if((argc-1)%2) { usage();return 2; }
    for(int i=1;i+1<argc;i+=2) {
        if(!strcmp(argv[i],"--queue"))queue=argv[i+1];
        else if(!strcmp(argv[i],"--form"))form=argv[i+1];
        else if(!strcmp(argv[i],"--legacy-form"))legacy_form=argv[i+1];
        else if(!strcmp(argv[i],"--store"))store_path=argv[i+1];
        else if(!strcmp(argv[i],"--journal"))journal_path=argv[i+1];
        else if(!strcmp(argv[i],"--log"))log=argv[i+1];
        else if(!strcmp(argv[i],"--exp-control"))exp=argv[i+1];
        else if(!strcmp(argv[i],"--daemon-log"))daemon_log=argv[i+1];
        else { usage();return 2; }
    }
    if(daemon_log && !freopen(daemon_log,"a",stderr))return 1;
    setvbuf(stderr,NULL,_IOLBF,0);
    struct sigaction sa={0};sa.sa_handler=stop;sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM,&sa,NULL);sigaction(SIGINT,&sa,NULL);signal(SIGPIPE,SIG_IGN);
    char seen[1024],lock_path[1024];
    if(snprintf(seen,sizeof seen,"%s.seen",queue)>=(int)sizeof seen ||
       snprintf(lock_path,sizeof lock_path,"%s.consumer",queue)>=(int)sizeof lock_path) {
        fprintf(stderr,"d2kshadow: путь очереди слишком длинный\n");return 2;
    }
    int owner=open(lock_path,O_RDWR|O_CREAT|O_NONBLOCK|O_NOFOLLOW,0600);
    struct stat lock_stat;
    struct flock owner_lock={.l_type=F_WRLCK,.l_whence=SEEK_SET};
    if(owner<0 || fstat(owner,&lock_stat) || !S_ISREG(lock_stat.st_mode) || fcntl(owner,F_SETLK,&owner_lock)) {
        fprintf(stderr,"d2kshadow: потребитель очереди уже работает или блокировка недоступна\n");
        if(owner>=0)close(owner);
        return 1;
    }
    /* Keep the daemon as the sole catalog owner; every target shares the
     * same learned catalog while the current task/box is separately owned. */
    d2km_store *catalog=calloc(1,sizeof *catalog);
    d2k_shadow_dedup *dedup=calloc(1,sizeof *dedup);
    if(!catalog || !dedup) { free(catalog);free(dedup);return 1; }
    if(d2k_shadow_dedup_load(seen,dedup,(uint64_t)time(NULL))) {
        fprintf(stderr,"d2kshadow: состояние отсрочек негодно; опыты не запускаются\n");
        free(dedup);free(catalog);close(owner);return 1;
    }
    d2km_store_init(catalog);d2km_store_error se={0};
    int load_failed=d2km_store_load(store_path,catalog,&se)!=D2KM_STORE_OK;
    char load_reason[sizeof se.reason];snprintf(load_reason,sizeof load_reason,"%s",load_failed?se.reason:"");
    if(load_failed)fprintf(stderr,"d2kshadow: хранилище %s: %s; пустое знание\n",store_path,se.reason);
    d2km_journal journal;
    if(d2km_journal_open(&journal,journal_path,1u<<20)) {
        fprintf(stderr,"d2kshadow: журнал почему недоступен: %s\n",journal_path);
        free(catalog);free(dedup);return 1;
    }
    d2k_shadow_reader reader={.rank=d2k_shadow_queue_rank,.rank_ctx=dedup};uint64_t malformed=0,errors=0,full=0;
    fprintf(stderr,"d2kshadow: тень с раздельными сетевыми плечами, очередь %s; только опыты через %s\n",queue,exp);
    owner_state state={.mutex=PTHREAD_MUTEX_INITIALIZER,.catalog=catalog,.dedup=dedup,.journal=&journal,
        .queue=queue,.store_path=store_path,.form=form,.legacy_form=legacy_form,.exp=exp,.log=log,.seen=seen,
        };
    worker_slot slots[D2K_SHADOW_WORKERS_MAX]={0};
    prune_state pruning={&state,slots};reader.discard=obsolete_record;reader.discard_ctx=&pruning;
    long cpus=sysconf(_SC_NPROCESSORS_ONLN);if(cpus<1)cpus=1;
#ifndef __linux__
    cpus=1;
#endif
    fprintf(stderr,"d2kshadow: network workers <=%u, declared=%zu bytes, reserve=one task; sole catalog owner\n",
        D2K_SHADOW_WORKERS_MAX,d2k_exp_task_memory());
    uint64_t last_cleanup=0,last_prune=0;
    while(1) {
        pthread_mutex_lock(&state.mutex);
        if(stopping) {pthread_mutex_unlock(&state.mutex);break;}
        unsigned active=0;worker_slot *slot=NULL;
        for(unsigned i=0;i<D2K_SHADOW_WORKERS_MAX;i++) {
            if(slots[i].active && slots[i].done) {
                pthread_join(slots[i].thread,NULL);slots[i].active=slots[i].done=0;
            }
            if(slots[i].active)active++;
            else if(!slot)slot=&slots[i];
        }
        uint64_t prune_now=(uint64_t)time(NULL);
        if(prune_now!=last_prune) {
            (void)d2k_shadow_queue_prune(queue,&reader);last_prune=prune_now;
        }
        if(!slot || !d2k_shadow_worker_admit(available_memory(),d2k_exp_task_memory(),(unsigned)cpus,active)) {
            pthread_mutex_unlock(&state.mutex);struct timespec delay={.tv_nsec=20000000};nanosleep(&delay,NULL);continue;
        }
        uint64_t clock_now=(uint64_t)time(NULL);
        if(clock_now<last_cleanup || clock_now-last_cleanup>=60) {
            (void)d2k_shadow_snapshot_cleanup(queue,clock_now);last_cleanup=clock_now;
        }
        d2k_shadow_record r;
        int n=d2k_shadow_queue_next(queue,&r,&reader);
        if(reader.malformed!=malformed || reader.errors!=errors) {
            malformed=reader.malformed;errors=reader.errors;
            fprintf(stderr,"d2kshadow: очередь malformed=%llu errors=%llu\n",
                (unsigned long long)malformed,(unsigned long long)errors);
        }
        if(n!=1) { pthread_mutex_unlock(&state.mutex);struct timespec delay={.tv_sec=1};nanosleep(&delay,NULL);continue; }
        uint64_t now=(uint64_t)time(NULL);
        int owned=0;
        for(unsigned i=0;i<D2K_SHADOW_WORKERS_MAX;i++)
            if(slots[i].active && d2k_shadow_same_context(&slots[i].record,&r))owned=1;
        if(owned) {
            /* A later client signal can wake the target after completion;
               no second task may concurrently measure the same context. */
            d2k_shadow_snapshot_remove(queue,&r);pthread_mutex_unlock(&state.mutex);continue;
        }
        if(!d2k_shadow_admit(dedup,&r,now)) {
            if(dedup->dropped!=full) {
                full=dedup->dropped;
                fprintf(stderr,"d2kshadow: таблица отсрочек полна; потерь=%llu\n",(unsigned long long)full);
            }
            d2k_shadow_snapshot_remove(queue,&r);
            pthread_mutex_unlock(&state.mutex);continue;
        }
        /* Persist admission first: a watchdog restart cannot erase the
           cooldown of an interrupted task and immediately repeat it. */
        if(d2k_shadow_dedup_save(seen,dedup,now)) {
            d2k_shadow_snapshot_remove(queue,&r);
            fprintf(stderr,"d2kshadow: не сохранена отсрочка; опыты не запускаются\n");
            failed=1;stopping=1;pthread_mutex_unlock(&state.mutex);break;
        }
        if(load_failed) {
            d2km_context ctx={0};d2km_target_name(&ctx.target,r.host);
            ctx.transport=D2KM_TCP;ctx.protocol=D2KM_P_TLS13;ctx.family=(d2km_family)r.family;
            d2km_why why={.task=&ctx,.step=D2KM_STEP_OWN,.reason=load_reason};
            if(d2km_journal_append(&journal,&why,NULL)!=D2KM_WHY_OK)
                fprintf(stderr,"d2kshadow: не записалась причина отказа загрузки\n");
            load_failed=0;
        }
        slot->record=r;slot->owner=&state;slot->active=1;slot->id=(unsigned)(slot-slots);
        slot->started=monotonic_ms();slot->network_ms=0;slot->arms=0;
        pthread_attr_t attr;pthread_attr_init(&attr);pthread_attr_setstacksize(&attr,1024u*1024u);
        int rc=pthread_create(&slot->thread,&attr,work,slot);pthread_attr_destroy(&attr);
        if(rc) {
            slot->active=0;d2k_shadow_snapshot_remove(queue,&r);
            fprintf(stderr,"d2kshadow: LOCAL_FAIL worker creation: %s\n",strerror(rc));failed=1;stopping=1;
        } else fprintf(stderr,"d2kshadow: start worker=%u time=%llu active=%u host=%s form=%016llx priority=%u queued_seconds=%llu why=owner>degradation>first-target>additional-form,FIFO-signal\n",
            slot->id,(unsigned long long)now,active+1,r.host,(unsigned long long)r.form_key,
            (unsigned)r.priority,(unsigned long long)(now>=r.time?now-r.time:0));
        pthread_mutex_unlock(&state.mutex);
    }
    for(unsigned i=0;i<D2K_SHADOW_WORKERS_MAX;i++)if(slots[i].active)pthread_join(slots[i].thread,NULL);
    pthread_mutex_destroy(&state.mutex);
    d2km_journal_close(&journal);free(dedup);free(catalog);
    close(owner);fprintf(stderr,"d2kshadow: остановлен\n");return failed?1:0;
}
