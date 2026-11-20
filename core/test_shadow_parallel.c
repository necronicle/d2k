#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2k_shadow.h"
#include "d2k_shadow_workers.h"
#include "d2km_sim.h"
#include "d2k_mlkem.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static pthread_mutex_t model=PTHREAD_MUTEX_INITIALIZER,netmu=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t both=PTHREAD_COND_INITIALIZER;
enum { TEST_WORKERS=4 };
static unsigned arrived;
static d2km_store store;
static d2km_journal journal;
static char logpath[512];
typedef struct {d2km_sim sim;d2km_net net;d2k_shadow_record r;unsigned calls;uint32_t ids[256];size_t count;} test_worker;
static void unlock_model(void *p) {(void)p;pthread_mutex_unlock(&model);}
static void lock_model(void *p) {(void)p;pthread_mutex_lock(&model);}
static void hybrid_keys(unsigned salt) {
    uint8_t seed[64],m[32],ek[1184],dk[2400],ct[1088],sent[32],received[32];
    for(unsigned round=0;round<20;round++) {
        for(unsigned i=0;i<sizeof seed;i++)seed[i]=(uint8_t)(salt+i+round);
        for(unsigned i=0;i<sizeof m;i++)m[i]=(uint8_t)(salt+2*i+round);
        d2k_mlkem768_keygen(seed,seed+32,ek,dk);
        assert(!d2k_mlkem768_encaps(ek,m,ct,sent));
        d2k_mlkem768_decaps(dk,ct,received);assert(!memcmp(sent,received,32));
    }
}
static int network(void *p,const d2km_arm_spec *a,d2km_observation *o,d2km_result *r) {
    test_worker *w=p;uint8_t hello[D2KM_TLS_MAX];assert(a->hello_length<=sizeof hello);
    memcpy(hello,a->hello,a->hello_length);
    pthread_mutex_lock(&netmu);
    int first=!w->calls++;
    if(first) {arrived++;pthread_cond_broadcast(&both);while(arrived<TEST_WORKERS)pthread_cond_wait(&both,&netmu);}
    pthread_mutex_unlock(&netmu);
    if(first)hybrid_keys((unsigned)w->r.host[7]);
    assert(!memcmp(hello,a->hello,a->hello_length));
    if(!w->count || w->ids[w->count-1]!=a->experiment) {assert(w->count<256);w->ids[w->count++]=a->experiment;}
    return w->net.run(w->net.ctx,a,o,r);
}
static void *run(void *p) {
    test_worker *w=p;d2km_task_report *report=calloc(1,sizeof *report);assert(report);
    uint8_t options_bytes[4]={3,3,(uint8_t)w->r.form_key,1};
    d2k_exp_options options={.tcp_options=options_bytes,.tcp_options_len=4,.host=w->r.host,.ip=w->r.ip,.port=443,.family=4,.form="profiles/modern.hex",
        .pass_name="passes.test",.network_begin=unlock_model,.network_end=lock_model,
        .shared_experiment=&store.next_experiment,.shared_fact=&store.next_fact};
    d2km_net net={w,network};pthread_mutex_lock(&model);
    assert(!d2k_shadow_run(&w->r,&options,&store,&journal,&net,logpath,report));
    assert(report->outcome==D2KM_APPLIED);pthread_mutex_unlock(&model);free(report);return NULL;
}
int main(void) {
    alarm(15);
    assert(!d2k_shadow_worker_capacity(999,1000,4));assert(!d2k_shadow_worker_capacity(1999,1000,4));
    assert(d2k_shadow_worker_capacity(2000,1000,4)==1);assert(d2k_shadow_worker_capacity(99999,1000,2)==4);
    assert(d2k_shadow_worker_capacity(99999,1000,99)==4);
    d2k_shadow_record a={.port=443,.family=4,.protocol=2,.form_key=1};
    strcpy(a.host,"same.example");strcpy(a.ip,"192.0.2.1");
    d2k_shadow_record b=a;
    assert(d2k_shadow_same_context(&a,&b));
    b.degradation=1;b.knowledge=9;assert(d2k_shadow_same_context(&a,&b));
    b=a;
    b.form_key=2;assert(!d2k_shadow_same_context(&a,&b));
    b=a;b.port=8443;assert(d2k_shadow_same_context(&a,&b));
    b=a;strcpy(b.ip,"192.0.2.2");assert(d2k_shadow_same_context(&a,&b));
    b=a;b.protocol=1;assert(!d2k_shadow_same_context(&a,&b));
    unsigned active=0;
    while(d2k_shadow_worker_admit(2000,1000,4,active))active++;
    assert(active==1); /* reserve admissions before a thread allocates anything */
    assert(!d2k_shadow_worker_admit(1999,1000,4,0));
    assert(!d2k_shadow_worker_admit(99999,1000,4,4));
    char dir[]="/tmp/shadow-parallel-XXXXXX",why[512];assert(mkdtemp(dir));
    snprintf(logpath,sizeof logpath,"%s/log",dir);snprintf(why,sizeof why,"%s/why",dir);
    d2km_store_init(&store);assert(!d2km_journal_open(&journal,why,1u<<20));
    test_worker workers[TEST_WORKERS]={0};pthread_t threads[TEST_WORKERS];
    pthread_attr_t attr;assert(!pthread_attr_init(&attr));
    /* ASan redzones inflate each frame; the production worker still uses 1 MiB. */
#if defined(__SANITIZE_ADDRESS__)
    assert(!pthread_attr_setstacksize(&attr,4u*1024u*1024u));
#else
    assert(!pthread_attr_setstacksize(&attr,1024u*1024u));
#endif
    for(unsigned i=0;i<TEST_WORKERS;i++) {
        workers[i].sim=(d2km_sim){.blocked_suffix="example",.reads_name=1,.reassembles=0,.box_hop=5,.server_hop=12};
        workers[i].net=d2km_sim_net(&workers[i].sim);
        workers[i].r=(d2k_shadow_record){.time=100,.port=443,.family=4,.signal=2};
        strcpy(workers[i].r.host,"blocked.example");workers[i].r.form_key=i+1;strcpy(workers[i].r.ip,"192.0.2.1");
        assert(!pthread_create(&threads[i],&attr,run,&workers[i]));
    }
    assert(!pthread_attr_destroy(&attr));
    for(unsigned i=0;i<TEST_WORKERS;i++)assert(!pthread_join(threads[i],NULL));
    assert(arrived==TEST_WORKERS && store.knowledge.count==TEST_WORKERS);
    for(unsigned i=0;i<TEST_WORKERS;i++)for(unsigned j=i+1;j<TEST_WORKERS;j++)
        for(size_t a=0;a<workers[i].count;a++)for(size_t b=0;b<workers[j].count;b++)assert(workers[i].ids[a]!=workers[j].ids[b]);
    d2km_journal_close(&journal);unlink(why);unlink(logpath);assert(!rmdir(dir));
    puts("parallel network arms, serialized knowledge, disjoint IDs, memory reserve: ok");return 0;
}
