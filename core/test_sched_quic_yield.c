/* Production scheduler + real QUIC question loop; no network sockets. */
/* nanosleep ниже объявлена только при этом макросе: под -std=c99 без него
   чужой компилятор отказывает (gcc-warn), а местный clang молчит — тот же
   приём, что в test_quic_arms.c и test_quicprobe.c. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
int yield_spawn(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *);
#define pthread_create yield_spawn
#include "sched.c"
#include "test_task_slots.h"
#undef pthread_create
#include "d2k_quic_arms.h"

static pthread_mutex_t test_mu=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t test_cv=PTHREAD_COND_INITIALIZER;
static int fails,first,release_first,done,tcp_started,probes,early_probe;
static d2k_quic_arm result,paused_result;
static int mode,data_entered,release_data,benign_calls;
static uint32_t paused_total;
#define CHECK(x) do { if(!(x)){fprintf(stderr,"yield:%d: %s\n",__LINE__,#x);fails++;} } while(0)
int yield_spawn(pthread_t *th,const pthread_attr_t *attr,void *(*fn)(void *),void *arg) {
    (void)th;(void)attr;(void)fn;(void)arg;
    pthread_mutex_lock(&test_mu);tcp_started++;pthread_mutex_unlock(&test_mu);
    return EAGAIN; /* observe TCP admission without running a network worker */
}
static d2k_tally probe(const d2k_quic_arm_question *q,void *u,int *sent) {
    (void)u;*sent=3;
    pthread_mutex_lock(&test_mu);
    probes++;
    if(q->benign)benign_calls++;
    if(probes==1){first=1;pthread_cond_broadcast(&test_cv);while(!release_first)pthread_cond_wait(&test_cv,&test_mu);}
    else if(mode!=2 && mode!=3 && !tcp_started)early_probe++;
    pthread_mutex_unlock(&test_mu);
    return mode==1 && q->benign?(d2k_tally){.pass=3,.marked=1}:(d2k_tally){.fail=3,.marked=1};
}
static d2k_quic_arm_data data(const d2k_quic_arm_question *q,void *u) {
    (void)q;(void)u;
    pthread_mutex_lock(&test_mu);data_entered=1;pthread_cond_broadcast(&test_cv);
    while(!release_data)pthread_cond_wait(&test_cv,&test_mu);
    pthread_mutex_unlock(&test_mu);
    return (d2k_quic_arm_data){.verdict=D2K_QAD_CUT};
}
static void pause_spent(void *u,uint32_t ms){(void)u;paused_total+=ms;}
static void *questions(void *p) {
    d2k_sched *s=p;g_progress_sink=(progress_sink){s,test_task_at(s, 0)};
    const char pool[1][D2K_QUIC_ADDR_LEN]={"192.0.2.1"};
    d2k_quic_arm_context c={.pool=pool,.n_pool=1,.probe=probe,.marked=1,.data=mode==1?data:NULL,.spent=pause_spent};
    result=d2k_quic_strategy_arms(&c);
    pthread_mutex_lock(&test_mu);done=1;pthread_cond_broadcast(&test_cv);pthread_mutex_unlock(&test_mu);
    return NULL;
}
static task *target(d2k_sched *s,int index,int transport,task_state state) {
    task *t=test_task_at(s, index);
    snprintf(t->name,sizeof t->name,"yield%d.example",index);
    strcpy(t->ip,"192.0.2.1");t->port=443;t->family=4;t->transport=(uint8_t)transport;
    t->shape_armed=1;t->state=state;t->started_ms=100;t->queued_ms=100;
    t->prop_fd=t->prop_q=t->prop_bound_fd=t->probe_fd=t->ver.fd=t->c_fd=-1;
    return t;
}
static void scenario(int selected) {
    mode=selected;first=release_first=done=tcp_started=probes=early_probe=0;
    data_entered=release_data=benign_calls=0;paused_total=0;
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);
    CHECK(s!=NULL);if(!s)return;
    s->clock_seen=1;s->now_ms=100;s->meas_limit=2;
    task *q=target(s,0,17,T_ASKING);q->job=JOB_CLASSIFY;
    q->worker_owner=s;
    CHECK(pthread_create(&q->th,NULL,questions,s)==0);q->th_live=1;
    pthread_mutex_lock(&test_mu);while(!first)pthread_cond_wait(&test_cv,&test_mu);pthread_mutex_unlock(&test_mu);
    target(s,2,17,T_ASKING); /* all measurement slots are occupied */
    if(mode!=2)target(s,1,6,T_QUEUED);
    d2k_sched_tick(s,1000);
    pthread_mutex_lock(&test_mu);release_first=1;pthread_cond_broadcast(&test_cv);pthread_mutex_unlock(&test_mu);
    if(mode==1){
        pthread_mutex_lock(&test_mu);while(!data_entered)pthread_cond_wait(&test_cv,&test_mu);pthread_mutex_unlock(&test_mu);
        d2k_sched_tick(s,1100);CHECK(tcp_started==0);CHECK(!q->quic_parked);
        pthread_mutex_lock(&test_mu);release_data=1;pthread_cond_broadcast(&test_cv);pthread_mutex_unlock(&test_mu);
    }
    if(mode==3 || mode==5){
        int waiting=0;
        for(int i=0;i<1000 && !waiting;i++){
            pthread_mutex_lock(&s->mu);waiting=q->quic_yield_waiting;pthread_mutex_unlock(&s->mu);
            struct timespec nap={0,1000000};nanosleep(&nap,NULL);
        }
        CHECK(waiting);
        if(mode==5){
            test_task_at(s, 1)->queued_ms=test_task_at(s, 2)->started_ms=700000;
            d2k_sched_tick(s,700000);
            CHECK(q->state==T_ASKING && q->quic_parked);
            CHECK(tcp_started==1);
            quic_yield_tick(s,700250);
            CHECK(q->started_ms>700250-SCHED_TASK_LIFE_MS);
        }
        join_worker(q);
        CHECK(done);
        if(mode==3)CHECK(probes==1 && result.incomplete);
        q->state=T_FREE;test_task_at(s, 1)->state=T_FREE;test_task_at(s, 2)->state=T_FREE;
        d2k_sched_free(s);d2k_catalog_free(&cat);return;
    }
    int held_tcp=0;int64_t now_ms=1100;
    for(int i=0;i<1000;i++){
        d2k_sched_tick(s,now_ms+=10);
        if(tcp_started && !held_tcp){
            /* Keep the admitted TCP slot busy: QUIC cannot resume yet. */
            target(s,1,6,T_ASKING);held_tcp=1;
            for(int j=0;j<10;j++){
                d2k_sched_tick(s,now_ms+=10);
                struct timespec nap={0,1000000};nanosleep(&nap,NULL);
            }
            pthread_mutex_lock(&test_mu);CHECK(probes==1);pthread_mutex_unlock(&test_mu);
            /* Wait until the worker really sits in the yield wait before the
               clock jumps. Ten fixed 1 ms naps were enough on a laptop and not
               under ASan on a CI runner (12.10.2026): the tick below met a
               worker still moving and line "state==T_ASKING && quic_parked"
               failed once. Same bounded wait as modes 3 and 5 already use. */
            {
                int waiting=0;
                for(int k=0;k<1000 && !waiting;k++){
                    pthread_mutex_lock(&s->mu);waiting=q->quic_yield_waiting;pthread_mutex_unlock(&s->mu);
                    if(!waiting){struct timespec nap={0,1000000};nanosleep(&nap,NULL);}
                }
                CHECK(waiting);
            }
            CHECK(q->quic_parked);
            if(mode==0){
                now_ms+=SCHED_TASK_LIFE_MS+100;
                test_task_at(s, 1)->started_ms=test_task_at(s, 2)->started_ms=now_ms;
                d2k_sched_tick(s,now_ms);
                CHECK(q->state==T_ASKING && q->quic_parked);
            }
            if(mode==4){
                join_worker(q);CHECK(done && probes==1 && result.incomplete);
                q->state=test_task_at(s, 1)->state=test_task_at(s, 2)->state=T_FREE;
                d2k_sched_free(s);d2k_catalog_free(&cat);return;
            }
            test_task_at(s, 1)->state=T_FREE;
            /* One TCP admission earns the suspended search its next turn,
               even if more TCP is queued. No starvation of saved work. */
            target(s,3,6,T_QUEUED);
            quic_yield_tick(s,now_ms+=SCHED_START_GAP_MS);
            CHECK(!q->quic_parked && test_task_at(s, 3)->state==T_QUEUED);
            test_task_at(s, 3)->state=T_FREE;
        }
        pthread_mutex_lock(&test_mu);int finished=done;pthread_mutex_unlock(&test_mu);
        if(finished)break;
        struct timespec nap={0,1000000};nanosleep(&nap,NULL);
    }
    pthread_mutex_lock(&test_mu);int finished=done;pthread_mutex_unlock(&test_mu);
    CHECK(finished);CHECK(tcp_started==(mode==2?0:1));CHECK(early_probe==0);
    join_worker(q);
    CHECK(probes>1 && result.kind==D2K_QA_NOT_FOUND && !result.incomplete);
    CHECK(result.probes==probes*3 && benign_calls==1);
    if(mode==0)paused_result=result;
    if(mode==2)CHECK(!memcmp(&paused_result,&result,sizeof result));
    CHECK(mode==2?paused_total==0:paused_total>0);
    q->state=T_FREE;test_task_at(s, 2)->state=T_FREE;d2k_sched_free(s);d2k_catalog_free(&cat);
}
int main(void){
    /* ГЕРМЕТИЧНО: лимит слотов здесь обязан остаться 2. Планировщик на каждом
       тике пересчитывает его по РЕАЛЬНЫМ CPU и памяти машины (AIMD в
       measure_limit_update). На macOS /proc нет, ресурсы «неизвестны», и
       лимит стоит на SCHED_DEFAULT_ACTIVE_MEASUREMENTS = 2. На Linux-раннере
       CI ресурсы читаются по-настоящему, свободного процессора много, и тик
       поднимал лимит до 3 — у припаркованного QUIC появлялся слот, и
       утверждение «поиск остался припаркованным» падало в каждом прогоне
       (12.10.2026: и в обычной сборке, и под ASan). Тест проверяет порядок
       уступки слота, а не реакцию на нагрузку — её проверяет test_sched
       своими заглушками. */
    d2k_sched_cpu_hook = NULL;
    d2k_sched_mem_hook = NULL;
    d2k_sched_ct_hook = NULL;

    for(int i=0;i<6;i++)scenario(i);
    printf("QUIC question yield: %d failures\n",fails);return fails?1:0;
}
