/* Controller observer opt-in tests; no sockets or worker threads. */
#define _DARWIN_C_SOURCE
#define pthread_create shadow_thread_create
#include "sched.c"
#include "test_task_slots.h"
#undef pthread_create
#include <assert.h>
#include "d2k_shadow.h"
#include "d2k_shadow_workers.h"
int shadow_thread_create(pthread_t *t,const pthread_attr_t *a,void *(*fn)(void *),void *arg)
{ (void)t;(void)a;(void)fn;(void)arg;return EAGAIN; }
/* Fresh events reproduce the wire: HELLO has only a name, EXCHANGE no
 * direction or shape, and FLOW supplies the observed client endpoint. */
static d2k_ev wire_event(uint16_t kind,uint16_t client_port,uint16_t server_port)
{
    d2k_ev e={0};e.kind=kind;e.transport=6;e.family=4;
    e.low_port=client_port;e.high_port=server_port;
    inet_pton(AF_INET,"192.168.1.2",e.low_ip);inet_pton(AF_INET,"192.0.2.5",e.high_ip);
    if(kind==D2K_EV_FLOW || kind==D2K_EV_SUSPECT)e.client_side=D2K_CLIENT_SIDE_LOW;
    if(kind==D2K_EV_SUSPECT) {e.code=D2K_SUSPECT_SILENT;e.client_shape=D2K_SHAPE_MODERN;}
    if(kind==D2K_EV_EXCHANGE) {
        e.code=23;e.seen_types=8;e.num=100;e.planned=D2K_LINK_PLANNED_NO;
        e.flow_epoch[0]=7;e.flow_incarnation=42;
    }
    return e;
}
static void reviewed_flow(const char *which)
{
    char dir[]="/tmp/d2k-shadow-review-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/queue",dir);d2k_catalog catalog={0};
    d2k_sched *s=d2k_sched_new(&catalog,-1,0x2d);assert(s);s->now_ms=1000;s->clock_seen=1;s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,path));
    uint16_t cp=50000,sp=!strcmp(which,"R5")?60000:443;
    d2k_ev flow=wire_event(D2K_EV_FLOW,cp,sp),hello=wire_event(D2K_EV_HELLO,cp,sp);
    flow.flow_epoch[0]=7;flow.flow_incarnation=42;
    strcpy(hello.name,"current.example.com");d2k_sched_event(s,&flow);d2k_sched_event(s,&hello);
    d2k_ev exchange=wire_event(D2K_EV_EXCHANGE,cp,sp);
    if(!strcmp(which,"R2")) {
        d2k_ev options=wire_event(D2K_EV_CLIENT_TCP,cp,sp);d2k_sched_event(s,&options);
        d2k_ev shape=wire_event(D2K_EV_SHAPE,cp,sp);shape.shape[0]=22;shape.shape_len=1;
        d2k_sched_event(s,&shape);assert(shadow_flow(s,&shape)->hello_len);
        flow.flow_epoch[0]=7;flow.flow_incarnation=43;d2k_sched_event(s,&flow);
        exchange.flow_incarnation=43;d2k_sched_event(s,&exchange);
        assert(!s->shadow_recent.count); /* new flow before HELLO has no old name */
        hello.name[0]=0;d2k_sched_event(s,&hello);d2k_sched_event(s,&shape);d2k_sched_event(s,&exchange);
        assert(!s->shadow_recent.count); /* nameless HELLO cannot retain old named target */
        d2k_ev suspect=wire_event(D2K_EV_SUSPECT,cp,sp);d2k_sched_event(s,&suspect);
        d2k_shadow_reader rd={0};d2k_shadow_record r;
        assert(!d2k_shadow_queue_next(path,&r,&rd));
    } else {
        d2k_sched_event(s,&exchange);assert(s->shadow_recent.count==1);
        const d2k_shadow_record *e=&s->shadow_recent.entries[0];assert(!strcmp(e->host,hello.name));
        if(!strcmp(which,"R5")) {
            assert(e->port==sp && !strcmp(e->ip,"192.0.2.5"));
            d2k_ev suspect=wire_event(D2K_EV_SUSPECT,cp,sp);d2k_sched_event(s,&suspect);
            d2k_shadow_reader rd={0};d2k_shadow_record r;
            assert(d2k_shadow_queue_next(path,&r,&rd)==1 && r.history_time);
            assert(r.port==sp && !strcmp(r.ip,"192.0.2.5"));
        }
        /* A second direct TLS connection can contribute a shape, but its
           prior absence above cannot disqualify clean source observations. */
        d2k_ev second=wire_event(D2K_EV_FLOW,cp+1,sp);d2k_sched_event(s,&second);
        second=wire_event(D2K_EV_HELLO,cp+1,sp);strcpy(second.name,"second.example.net");d2k_sched_event(s,&second);
        second=wire_event(D2K_EV_CLIENT_TCP,cp+1,sp);second.tcp_options[0]=1;second.tcp_options_len=1;d2k_sched_event(s,&second);
        second=wire_event(D2K_EV_SHAPE,cp+1,sp);second.shape[0]=22;second.shape_len=1;d2k_sched_event(s,&second);
        second=wire_event(D2K_EV_EXCHANGE,cp+1,sp);d2k_sched_event(s,&second);assert(s->shadow_recent.count==2);
        if(!strcmp(which,"R5")) {
            second=wire_event(D2K_EV_FLOW,cp+2,sp);second.client_side=0;d2k_sched_event(s,&second);
            second=wire_event(D2K_EV_HELLO,cp+2,sp);strcpy(second.name,"unknown.example.org");d2k_sched_event(s,&second);
            second=wire_event(D2K_EV_EXCHANGE,cp+2,sp);d2k_sched_event(s,&second);
            assert(s->shadow_recent.count==2); /* unknown direction cannot invent a server */
        }
    }
    assert(!d2k_sched_set_shadow(s,NULL));d2k_sched_free(s);d2k_catalog_free(&catalog);
    char recent[600];snprintf(recent,sizeof recent,"%s.recent",path);unlink(recent);unlink(path);assert(!rmdir(dir));
}
static void option_observation(void)
{
    char dir[]="/tmp/d2k-shadow-options-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/queue",dir);d2k_catalog catalog={0};
    d2k_sched *s=d2k_sched_new(&catalog,-1,0x2d);assert(s);s->now_ms=1000;s->clock_seen=1;s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,path));d2k_shadow_reader rd={0};d2k_shadow_record r;
    for(int observed=0;observed<2;observed++) {
        d2k_ev e=wire_event(D2K_EV_FLOW,50000,443);d2k_sched_event(s,&e);
        e=wire_event(D2K_EV_HELLO,50000,443);strcpy(e.name,"options.example.com");d2k_sched_event(s,&e);
        if(observed) {e=wire_event(D2K_EV_CLIENT_TCP,50000,443);d2k_sched_event(s,&e);} /* known-empty */
        e=wire_event(D2K_EV_SHAPE,50000,443);e.shape[0]=22;e.shape_len=1;d2k_sched_event(s,&e);
        e=wire_event(D2K_EV_SUSPECT,50000,443);d2k_sched_event(s,&e);
        assert(d2k_shadow_queue_next(path,&r,&rd)==1);
        if(observed) {
            d2k_shadow_snapshot snapshot;assert(r.snapshot && !d2k_shadow_snapshot_read(path,&r,&snapshot));
            assert(!snapshot.options_len);d2k_shadow_snapshot_remove(path,&r);
        } else assert(!r.snapshot); /* missing options are unknown, not known-empty */
    }
    assert(!d2k_sched_set_shadow(s,NULL));d2k_sched_free(s);d2k_catalog_free(&catalog);unlink(path);assert(!rmdir(dir));
}
static void options_before_hello(void)
{
    char dir[]="/tmp/shadow-early-options-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);d2k_catalog cat={0};
    d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,path));
    d2k_ev e=wire_event(D2K_EV_FLOW,50000,443);d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_CLIENT_TCP,50000,443);e.tcp_options_len=1;e.tcp_options[0]=1;d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_HELLO,50000,443);strcpy(e.name,"early.example");d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_SHAPE,50000,443);e.shape[0]=22;e.shape_len=1;d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_SUSPECT,50000,443);d2k_sched_event(s,&e);
    d2k_shadow_reader rd={0};d2k_shadow_record r;d2k_shadow_snapshot snap;
    assert(d2k_shadow_queue_next(path,&r,&rd)==1 && r.snapshot);
    assert(!d2k_shadow_snapshot_read(path,&r,&snap) && snap.options_len==1 && snap.options[0]==1);
    d2k_shadow_snapshot_remove(path,&r);d2k_sched_free(s);d2k_catalog_free(&cat);unlink(path);assert(!rmdir(dir));
}
/* Real TLS gets HELLO, not the RAW-only FLOW event. Direction must travel
 * on that greeting; a missing direction must still fail closed. */
static void ordinary_tls(void)
{
    char dir[]="/tmp/shadow-tls-XXXXXX",path[512],recent[540];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/queue",dir);snprintf(recent,sizeof recent,"%s.recent",path);
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);
    s->meas_limit=0;assert(!d2k_sched_set_shadow(s,path));
    d2k_ev h=wire_event(D2K_EV_HELLO,50000,443);strcpy(h.name,"live.example.net");
    uint8_t frame[512]={0};size_t n=6;
    frame[4]=(uint8_t)(D2K_EV_HELLO>>8);frame[5]=(uint8_t)D2K_EV_HELLO;
    frame[n++]=4;memcpy(frame+n,h.low_ip,16);n+=16;memcpy(frame+n,h.high_ip,16);n+=16;
    frame[n++]=(uint8_t)(h.low_port>>8);frame[n++]=(uint8_t)h.low_port;
    frame[n++]=(uint8_t)(h.high_port>>8);frame[n++]=(uint8_t)h.high_port;frame[n++]=6;
    frame[n++]=(uint8_t)strlen(h.name);memcpy(frame+n,h.name,strlen(h.name));n+=strlen(h.name);
    frame[n++]=D2K_CLIENT_SIDE_LOW;size_t body=n-4;
    frame[0]=(uint8_t)(body>>24);frame[1]=(uint8_t)(body>>16);frame[2]=(uint8_t)(body>>8);frame[3]=(uint8_t)body;
    char err[160];assert(!d2k_link_decode(D2K_EV_HELLO,frame+6,n-6,&h,err,sizeof err));
    assert(h.client_side==D2K_CLIENT_SIDE_LOW);
    d2k_ev old;
    assert(!d2k_link_decode(D2K_EV_HELLO,frame+6,n-7,&old,err,sizeof err));
    assert(!old.client_side); /* legacy peer cannot supply evidence of direction */
    d2k_sched_event(s,&old);
    d2k_ev legacy_exchange=wire_event(D2K_EV_EXCHANGE,50000,443);
    d2k_sched_event(s,&legacy_exchange);assert(!s->shadow_recent.count);
    frame[n-1]=3;assert(d2k_link_decode(D2K_EV_HELLO,frame+6,n-6,&old,err,sizeof err)<0);
    frame[n-1]=D2K_CLIENT_SIDE_LOW;
    d2k_sched_event(s,&h);
    d2k_ev e=wire_event(D2K_EV_EXCHANGE,50000,443);d2k_sched_event(s,&e);
    assert(s->shadow_recent.count==1);
    assert(!strcmp(s->shadow_recent.entries[0].ip,"192.0.2.5"));
    d2k_sched_free(s);d2k_catalog_free(&cat);unlink(recent);assert(!rmdir(dir));
}
static void synthesis_only(void)
{
    char dir[]="/tmp/synth-only-XXXXXX",path[512];assert(mkdtemp(dir));snprintf(path,sizeof path,"%s/q",dir);
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);s->meas_limit=0;
    assert(d2k_sched_set_synthesis_only(s,1)<0);
    assert(!d2k_sched_set_shadow(s,path));assert(!d2k_sched_set_newchain(s,"/missing-empty-newchain"));
    assert(!d2k_sched_set_synthesis_only(s,1));
    s->n_force=1;strcpy(s->force_suffixes[0],"example.net");
    d2k_ev e=wire_event(D2K_EV_HELLO,50000,443);e.client_side=D2K_CLIENT_SIDE_LOW;
    strcpy(e.name,"force.example.net");d2k_sched_event(s,&e);
    assert(!task_of(s,e.name,6,4));
    d2k_shadow_reader rd={0};d2k_shadow_record r;assert(!d2k_shadow_queue_next(path,&r,&rd));
    /* Owner HELLO waits for the bytes/options belonging to this flow. */
    e.kind=D2K_EV_CLIENT_TCP;d2k_sched_event(s,&e);
    e.kind=D2K_EV_SHAPE;e.shape[0]=22;e.shape_len=1;d2k_sched_event(s,&e);
    assert(d2k_shadow_queue_next(path,&r,&rd)==1 && !strcmp(r.host,"force.example.net"));
    d2k_shadow_snapshot_remove(path,&r);
    e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.client_shape=D2K_SHAPE_MODERN;
    d2k_sched_event(s,&e);assert(!task_of(s,e.name,6,4));
    task *t=test_task_at(s, 0);strcpy(t->name,"old.example");t->transport=6;t->family=4;t->state=T_PLANNING;
    assert(start_worker(s,t,JOB_CLASSIFY)<0);assert(!start_search(s,t));task_done(s,t);
    /* Owner DNS admission does not depend on force-targets or a suspicion. */
    s->n_doh=1;strcpy(s->doh[0].host,"tenant.gateway.example.test");
    strcpy(s->doh[0].ip,"192.0.2.5");strcpy(s->doh[0].path,"/dns-query");s->doh[0].port=443;
    e=wire_event(D2K_EV_HELLO,50001,443);e.client_side=D2K_CLIENT_SIDE_LOW;strcpy(e.name,s->doh[0].host);
    d2k_sched_event(s,&e);
    e.kind=D2K_EV_CLIENT_TCP;d2k_sched_event(s,&e);
    e.kind=D2K_EV_SHAPE;e.shape[0]=22;e.shape_len=1;d2k_sched_event(s,&e);
    assert(d2k_shadow_queue_next(path,&r,&rd)==1 && !strcmp(r.host,e.name));
    assert(!strcmp(r.doh_path,"/dns-query") && r.priority==2);
    d2k_shadow_snapshot_remove(path,&r);
    static d2km_knowledge k;k.context.target.has_name=1;k.context.family=D2KM_IPV4;
    k.context.protocol=D2KM_P_TLS13;k.hash=123;strcpy(k.context.target.name,s->doh[0].host);
    strcpy(k.why,"HTTP complete response");assert(!newchain_contract(s,&k));
    assert(d2km_application_proof(k.why,sizeof k.why,&k.context,k.hash,"doh-contract-v1 path=/dns-query replies>=20 span>=30000ms"));
    assert(newchain_contract(s,&k));
    k.hash++;assert(!newchain_contract(s,&k));k.hash--;
    strcpy(k.context.target.name,"donor.example");
    assert(d2km_application_proof(k.why,sizeof k.why,&k.context,k.hash,"doh-contract-v1 path=/dns-query replies>=20 span>=30000ms"));
    strcpy(k.context.target.name,s->doh[0].host);assert(!newchain_contract(s,&k));
    strcpy(k.why,"doh-contract-v1 path=/other replies>=20 span>=30000ms");assert(!newchain_contract(s,&k));
    /* A configured endpoint is not an observed greeting (§4.3/§4.5). */
    assert(!d2k_sched_set_synthesis_only(s,0));assert(!d2k_sched_set_synthesis_only(s,1));
    assert(!d2k_shadow_queue_next(path,&r,&rd));
    s->newchain.count=1;
    d2k_newchain_value *active=&s->newchain.entries[0].active;
    strcpy(active->name,s->doh[0].host);active->family=4;active->shape=D2K_SHAPE_MODERN;
    d2k_sched_event(s,&e);assert(!d2k_shadow_queue_next(path,&r,&rd));
    e.kind=D2K_EV_HELLO;d2k_sched_event(s,&e);
    e.kind=D2K_EV_CLIENT_TCP;d2k_sched_event(s,&e);
    e.kind=D2K_EV_SHAPE;d2k_sched_event(s,&e);
    e.kind=D2K_EV_SUSPECT;e.client_shape=D2K_SHAPE_MODERN;e.code=D2K_SUSPECT_SILENT;e.planned=D2K_LINK_PLANNED_NO;
    d2k_sched_event(s,&e);
    assert(d2k_shadow_queue_next(path,&r,&rd)==1 && r.snapshot && r.form_key && !r.degradation);
    d2k_shadow_snapshot_remove(path,&r); /* unplanned form is not hidden by broad ownership */
    cat.groups=calloc(1,sizeof *cat.groups);assert(cat.groups);cat.groups->disk_fd=cat.groups->derived_fd=-1;
    cat.groups->n_observations=1;
    d2k_group_observation *o=&cat.groups->observations[0];
    strcpy(o->name,"old-direct.example");o->evidence=D2K_GROUP_DIRECT_CLEAR;
    o->key=(d2k_group_key){.transport=6,.family=4,.shape=D2K_SHAPE_MODERN};
    assert(d2k_sched_sync(s)==0 && !s->sync_active && !s->n_areas && !s->sync_sent);
    d2k_sched_free(s);d2k_catalog_free(&cat);unlink(path);assert(!rmdir(dir));
}
static void snapshot_pressure(void)
{
    char dir[]="/tmp/shadow-pressure-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);d2k_catalog cat={0};
    d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,path));d2k_shadow_record owned={0};d2k_shadow_reader rd={0};
    for(unsigned i=0;i<D2K_SHADOW_SNAPSHOT_BUDGET_UNITS+8;i++) {
        uint16_t cp=(uint16_t)(51000+i);
        d2k_ev e=wire_event(D2K_EV_HELLO,cp,443);e.client_side=D2K_CLIENT_SIDE_LOW;
        snprintf(e.name,sizeof e.name,"form%u.example",i);d2k_sched_event(s,&e);
        e.kind=D2K_EV_CLIENT_TCP;d2k_sched_event(s,&e);
        e.kind=D2K_EV_SHAPE;e.shape[0]=22;e.shape_len=1;d2k_sched_event(s,&e);
        assert(shadow_flow(s,&e)->hello_len);
        if(!i) {
            e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.client_shape=D2K_SHAPE_MODERN;
            d2k_sched_event(s,&e);assert(d2k_shadow_queue_next(path,&owned,&rd)==1 && owned.snapshot);
        }
    }
    d2k_shadow_snapshot snap;assert(!d2k_shadow_snapshot_read(path,&owned,&snap));
    d2k_sched_free(s);d2k_catalog_free(&cat);
    assert(!d2k_shadow_snapshot_read(path,&owned,&snap)); /* queued ownership survives ring cleanup */
    d2k_shadow_snapshot_remove(path,&owned);unlink(path);assert(!rmdir(dir));
}
/* The queue can fill before its storage declaration. A retained greeting
 * must survive and be queued once a record is consumed. */
static void queued_snapshot_pressure(void)
{
    char dir[]="/tmp/shadow-queued-pressure-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);d2k_catalog cat={0};
    d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,path));
    d2k_shadow_record records[D2K_SHADOW_SNAPSHOT_BUDGET_UNITS+1];d2k_shadow_reader rd={0};
    uint8_t full_hello[D2K_SHADOW_HELLO_MAX]={22},full_opts[40]={1};
    unsigned queued=0;
    for(;queued<D2K_SHADOW_SNAPSHOT_BUDGET_UNITS;queued++) {
        d2k_shadow_record r={.time=(uint64_t)time(NULL),.family=4,.port=443};
        snprintf(r.host,sizeof r.host,"queued%u.example",queued);strcpy(r.ip,"192.0.2.5");
        full_hello[1]=(uint8_t)queued;
        assert(!d2k_shadow_snapshot_write(path,&r,full_hello,sizeof full_hello,full_opts,sizeof full_opts,r.time));
        if(d2k_shadow_queue_append(&s->shadow,&r)!=1) {
            d2k_shadow_snapshot_remove(path,&r);break;
        }
    }
    assert(queued>32 && queued<D2K_SHADOW_SNAPSHOT_BUDGET_UNITS);
    d2k_ev e=wire_event(D2K_EV_HELLO,52500,443);e.client_side=D2K_CLIENT_SIDE_LOW;
    strcpy(e.name,"waiting.example");d2k_sched_event(s,&e);
    e.kind=D2K_EV_CLIENT_TCP;e.tcp_options[0]=1;e.tcp_options_len=1;d2k_sched_event(s,&e);
    e.kind=D2K_EV_SHAPE;e.shape[0]=22;e.shape[1]=32;e.shape_len=2;d2k_sched_event(s,&e);
    d2k_shadow_record blocked={0};
    assert(!d2k_shadow_snapshot_write(path,&blocked,e.shape,2,NULL,0,(uint64_t)time(NULL)));
    d2k_shadow_snapshot_remove(path,&blocked);
    assert(d2k_shadow_queue_next(path,&records[0],&rd)==1);
    d2k_shadow_snapshot_remove(path,&records[0]);
    e.kind=D2K_EV_SUSPECT;e.client_shape=D2K_SHAPE_MODERN;e.code=D2K_SUSPECT_SILENT;d2k_sched_event(s,&e);
    for(unsigned i=1;i<=queued;i++) {
        assert(d2k_shadow_queue_next(path,&records[i],&rd)==1);
        d2k_shadow_snapshot snap;assert(records[i].snapshot);
        assert(!d2k_shadow_snapshot_read(path,&records[i],&snap));
        assert(snap.hello[1]==(i<queued?(uint8_t)i:32) && snap.options[0]==1);
        assert(snap.hello_len==(i<queued?sizeof full_hello:2));
        assert(snap.options_len==(i<queued?sizeof full_opts:1));
        d2k_shadow_snapshot_remove(path,&records[i]);
    }
    d2k_sched_free(s);d2k_catalog_free(&cat);unlink(path);assert(!rmdir(dir));
}
/* Field F: 32 small queued forms exhausted a file-count cap, leaving the
 * following 76 tasks with NO_RESOURCES despite ~200 MiB MemAvailable. */
static void field_f_snapshot_burst(void)
{
    char dir[]="/tmp/shadow-field-f-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);d2k_catalog cat={0};
    d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,path));
    for(unsigned i=0;i<108;i++) {
        d2k_ev e=wire_event(D2K_EV_HELLO,(uint16_t)(54000+i),443);
        e.client_side=D2K_CLIENT_SIDE_LOW;
        snprintf(e.name,sizeof e.name,"burst%u.example",i);d2k_sched_event(s,&e);
        e.kind=D2K_EV_CLIENT_TCP;e.tcp_options[0]=1;e.tcp_options_len=1;d2k_sched_event(s,&e);
        e.kind=D2K_EV_SHAPE;e.shape[0]=22;e.shape[1]=(uint8_t)i;e.shape_len=1500;d2k_sched_event(s,&e);
        e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.client_shape=D2K_SHAPE_MODERN;d2k_sched_event(s,&e);
    }
    d2k_shadow_reader rd={0};unsigned kept=0,refused=0;
    for(unsigned i=0;i<108;i++) {
        d2k_shadow_record r;d2k_shadow_snapshot snap;
        assert(d2k_shadow_queue_next(path,&r,&rd)==1);
        if(r.snapshot_errno==ENOSPC)refused++;
        else {
            assert(r.snapshot && !r.snapshot_errno && !d2k_shadow_snapshot_read(path,&r,&snap));
            uint8_t expected[1500]={22};expected[1]=(uint8_t)i;
            assert(snap.hello_len==sizeof expected && !memcmp(snap.hello,expected,sizeof expected));
            assert(snap.options_len==1 && snap.options[0]==1);
            kept++;d2k_shadow_snapshot_remove(path,&r);
        }
    }
    fprintf(stderr,"field F snapshot burst: kept=%u NO_RESOURCES=%u\n",kept,refused);
    assert(kept==108 && !refused);
    d2k_sched_free(s);d2k_catalog_free(&cat);unlink(path);assert(!rmdir(dir));
}
/* Repeated flows with one observed form need one queued task/snapshot;
 * a transport/greeting difference still needs a separate task. */
static void repeated_queued_form(void)
{
    char dir[]="/tmp/shadow-repeat-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);d2k_catalog cat={0};
    d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,path));
    for(unsigned i=0;i<3;i++) {
        d2k_ev e=wire_event(D2K_EV_HELLO,(uint16_t)(53000+i),443);e.client_side=D2K_CLIENT_SIDE_LOW;
        strcpy(e.name,"repeat.example");d2k_sched_event(s,&e);
        e.kind=D2K_EV_CLIENT_TCP;d2k_sched_event(s,&e);
        e.kind=D2K_EV_SHAPE;e.shape[0]=22;e.shape[1]=(uint8_t)(i==2);e.shape_len=2;d2k_sched_event(s,&e);
        e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.client_shape=D2K_SHAPE_MODERN;d2k_sched_event(s,&e);
    }
    d2k_shadow_record first,second;d2k_shadow_reader rd={0};
    assert(d2k_shadow_queue_next(path,&first,&rd)==1);
    assert(d2k_shadow_queue_next(path,&second,&rd)==1);
    assert(first.form_key && second.form_key && first.form_key!=second.form_key);
    d2k_shadow_snapshot_remove(path,&first);d2k_shadow_snapshot_remove(path,&second);
    assert(!d2k_shadow_queue_next(path,&first,&rd));
    d2k_sched_free(s);d2k_catalog_free(&cat);unlink(path);assert(!rmdir(dir));
}
/* H's producer stream: known clean contexts must not queue hundreds of
 * household suspicions before the first unmeasured targets. */
static void h_flow(d2k_sched *s,unsigned cp,const char *name,unsigned port,unsigned form)
{
    d2k_ev e=wire_event(D2K_EV_FLOW,(uint16_t)cp,(uint16_t)port);
    e.flow_epoch[0]=7;e.flow_incarnation=cp;d2k_sched_event(s,&e);
    e.kind=D2K_EV_HELLO;snprintf(e.name,sizeof e.name,"%s",name);d2k_sched_event(s,&e);
    e.kind=D2K_EV_CLIENT_TCP;e.tcp_options_len=1;e.tcp_options[0]=1;d2k_sched_event(s,&e);
    e.kind=D2K_EV_SHAPE;e.shape_len=6;e.shape[0]=22;e.shape[1]=3;e.shape[2]=3;
    e.shape[4]=1;e.shape[5]=(uint8_t)form;d2k_sched_event(s,&e);
}
static void field_h_clean_admission(void)
{
    char dir[]="/tmp/shadow-field-h-XXXXXX",path[512],recent[540];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);snprintf(recent,sizeof recent,"%s.recent",path);
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,path));
    for(unsigned form=1;form<=3;form++) {
        h_flow(s,50000+form,"house.example",443,form);
        d2k_ev e=wire_event(D2K_EV_EXCHANGE,(uint16_t)(50000+form),443);
        e.flow_incarnation=50000+form;d2k_sched_event(s,&e);
    }
    /* Restart retains context evidence; legacy context-free caches cannot
       produce this result (covered separately in clean_scope). */
    d2k_sched_free(s);s=d2k_sched_new(&cat,-1,0x2d);assert(s);s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,path));
    for(unsigned i=0;i<300;i++) {
        h_flow(s,51000+i,"house.example",443,1+i%3);
        d2k_ev e=wire_event(D2K_EV_SUSPECT,(uint16_t)(51000+i),443);
        e.planned=D2K_LINK_PLANNED_NO;
        e.flow_epoch[0]=7;e.flow_incarnation=51000+i;d2k_sched_event(s,&e);
    }
    assert(s->shadow.written==0); /* fails on H: clean observations never gate admission */
    /* Force rule still enters DIRECT even for a context that was clean. */
    s->n_force=1;strcpy(s->force_suffixes[0],"house.example");
    h_flow(s,52000,"house.example",443,1);
    d2k_ev forced=wire_event(D2K_EV_SUSPECT,52000,443);forced.planned=D2K_LINK_PLANNED_NO;
    forced.flow_epoch[0]=7;forced.flow_incarnation=52000;d2k_sched_event(s,&forced);
    d2k_shadow_reader rd={0};d2k_shadow_record r;
    assert(d2k_shadow_queue_next(path,&r,&rd)==1 && r.priority==2 && r.snapshot);
    d2k_shadow_snapshot_remove(path,&r);
    d2k_sched_free(s);d2k_catalog_free(&cat);unlink(recent);unlink(path);assert(!rmdir(dir));
}
/* Virtual time substitutes ONLY the network service clock. Producer,
 * persisted queue, worker capacity and daemon rank are production code.
 * H durations: slow task 219 s, successful OWN task 21 s, window 300 s.
 * The resulting count is scheduler evidence, not a network prediction. */
static void field_h_throughput(int require_fixed)
{
    char dir[]="/tmp/shadow-h-window-XXXXXX",path[512],recent[540];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);snprintf(recent,sizeof recent,"%s.recent",path);
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,path));
    for(unsigned form=1;form<=3;form++) {
        h_flow(s,50000+form,"house.example",443,form);
        d2k_ev e=wire_event(D2K_EV_EXCHANGE,(uint16_t)(50000+form),443);
        e.flow_incarnation=50000+form;d2k_sched_event(s,&e);
    }
    for(unsigned i=0;i<307+22;i++) {
        char name[80];unsigned form;
        if(i<307) {strcpy(name,"house.example");form=i<300?1+i%3:4+i-300;}
        else {snprintf(name,sizeof name,"target%u.example",i-307);form=1;}
        h_flow(s,51000+i,name,443,form);
        d2k_ev e=wire_event(D2K_EV_SUSPECT,(uint16_t)(51000+i),443);
        e.planned=D2K_LINK_PLANNED_NO;
        e.flow_epoch[0]=7;e.flow_incarnation=51000+i;d2k_sched_event(s,&e);
    }
    unsigned queued=(unsigned)s->shadow.written,now=0,done=0,first=0,admitted=0;
    unsigned finish[4]={0};int target_slot[4]={0};
    d2k_shadow_dedup *history=calloc(1,sizeof *history);assert(history);
    d2k_shadow_reader rd={.rank=d2k_shadow_queue_rank,.rank_ctx=history};
    unsigned capacity=d2k_shadow_worker_capacity(187172u*1024u,3562672,2);
    while(now<=300) {
        for(unsigned i=0;i<capacity;i++) {
            if(finish[i] && finish[i]<=now) {done++;first+=(unsigned)target_slot[i];finish[i]=0;}
            if(!finish[i]) {
                d2k_shadow_record r;
                if(d2k_shadow_queue_next(path,&r,&rd)==1) {
                    int is_target=strncmp(r.host,"target",6)==0;
                    assert(admitted<D2K_SHADOW_DEDUP_MAX);
                    history->entries[admitted].used=1;history->entries[admitted++].target=r;
                    finish[i]=now+(is_target?21:219);target_slot[i]=is_target;
                    d2k_shadow_snapshot_remove(path,&r);
                }
            }
        }
        unsigned next=301;for(unsigned i=0;i<capacity;i++)if(finish[i] && finish[i]<next)next=finish[i];
        now=next;
    }
    printf("H-window seconds=300 signals=329 queued=%u workers=%u outcomes=%u first_target_outcomes=%u\n",queued,capacity,done,first);
    if(require_fixed) {assert(queued==29 && capacity==4 && done==23 && first==22);}
    d2k_shadow_record r;while(d2k_shadow_queue_next(path,&r,&rd)==1)d2k_shadow_snapshot_remove(path,&r);
    free(history);d2k_sched_free(s);d2k_catalog_free(&cat);unlink(recent);unlink(path);assert(!rmdir(dir));
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"h-metric")) {field_h_throughput(0);return 0;}
    if(argc==2) {if(!strcmp(argv[1],"field-f"))field_f_snapshot_burst();else if(!strcmp(argv[1],"repeat"))repeated_queued_form();else if(!strcmp(argv[1],"queued-pressure"))queued_snapshot_pressure();else if(!strcmp(argv[1],"options"))option_observation();else reviewed_flow(argv[1]);
        printf("shadow review %s: ok\n",argv[1]);return 0;}
    field_h_throughput(1);
    field_h_clean_admission();
    field_f_snapshot_burst();
    repeated_queued_form();
    queued_snapshot_pressure();
    synthesis_only();
    options_before_hello();
    snapshot_pressure();
    ordinary_tls();
    reviewed_flow("R1");reviewed_flow("R2");reviewed_flow("R5");option_observation();
    char dir[]="/tmp/d2k-shadow-sched-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/queue",dir);d2k_catalog catalog={0};
    d2k_sched *s=d2k_sched_new(&catalog,-1,0x2d);assert(s);s->now_ms=1000;s->clock_seen=1;s->meas_limit=0;
    d2k_ev e=wire_event(D2K_EV_FLOW,50000,443);d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_HELLO,50000,443);strcpy(e.name,"blocked.example.com");d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_SUSPECT,50000,443);d2k_sched_event(s,&e);assert(access(path,F_OK)!=0);
    assert(sizeof s->shadow_flows == sizeof(void *));
    assert(!s->shadow_flows);
    assert(!d2k_sched_shadow_dropped(s));assert(!d2k_sched_set_shadow(s,path));
    assert(s->shadow_flows);
    e=wire_event(D2K_EV_FLOW,50000,443);d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_HELLO,50000,443);strcpy(e.name,"blocked.example.com");d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_SUSPECT,50000,443);d2k_sched_event(s,&e);
    d2k_shadow_reader rd={0};d2k_shadow_record record;
    assert(d2k_shadow_queue_next(path,&record,&rd)==1);
    assert(!strcmp(record.host,"blocked.example.com") && !strcmp(record.ip,"192.0.2.5"));
    assert(record.port==443 && !record.snapshot);
    /* Exact tuple owns bytes/options even when another same-name flow's
       events arrive between its snapshot and its suspicion. */
    for(unsigned flow=0;flow<2;flow++) {
        uint16_t cp=(uint16_t)(50000+flow);
        e=wire_event(D2K_EV_FLOW,cp,443);d2k_sched_event(s,&e);
        e=wire_event(D2K_EV_HELLO,cp,443);strcpy(e.name,"blocked.example.com");d2k_sched_event(s,&e);
        e=wire_event(D2K_EV_CLIENT_TCP,cp,443);e.tcp_options[0]=(uint8_t)(1+flow);e.tcp_options_len=1;d2k_sched_event(s,&e);
        e=wire_event(D2K_EV_SHAPE,cp,443);uint8_t greeting[]={22,3,3,0,1,1};
        memcpy(e.shape,greeting,sizeof greeting);e.shape[5]+=(uint8_t)flow;e.shape_len=sizeof greeting;d2k_sched_event(s,&e);
    }
    e=wire_event(D2K_EV_SUSPECT,50000,443);d2k_sched_event(s,&e);
    assert(d2k_shadow_queue_next(path,&record,&rd)==1 && record.snapshot);
    d2k_shadow_snapshot snapshot;assert(!d2k_shadow_snapshot_read(path,&record,&snapshot));
    assert(snapshot.hello[5]==1 && snapshot.options_len==1 && snapshot.options[0]==1);
    d2k_shadow_snapshot_remove(path,&record);
    e=wire_event(D2K_EV_EXCHANGE,50001,443);d2k_sched_event(s,&e);assert(s->shadow_recent.count==1);
    e=wire_event(D2K_EV_SUSPECT,50000,443);d2k_sched_event(s,&e);
    assert(!d2k_shadow_queue_next(path,&record,&rd)); /* ownership already transferred; no missing-form duplicate */
    e=wire_event(D2K_EV_FLOW,50002,443);d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_HELLO,50002,443);strcpy(e.name,"reject.example.net");d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_EXCHANGE,50002,443);e.code=22;e.seen_types=0;e.server_hello=1;
    d2k_sched_event(s,&e);assert(s->shadow_recent.count==1);
    e=wire_event(D2K_EV_EXCHANGE,50002,443);e.planned=D2K_LINK_PLANNED_YES;d2k_sched_event(s,&e);assert(s->shadow_recent.count==1);
    e.planned=D2K_LINK_PLANNED_UNKNOWN;d2k_sched_event(s,&e);assert(s->shadow_recent.count==1);
    e.planned=D2K_LINK_PLANNED_NO;e.num=0;d2k_sched_event(s,&e);assert(s->shadow_recent.count==1);
    e=wire_event(D2K_EV_SUSPECT,50002,443);d2k_sched_event(s,&e);assert(d2k_shadow_queue_next(path,&record,&rd)==1);
    e=wire_event(D2K_EV_EXCHANGE,50002,443);d2k_sched_event(s,&e);assert(s->shadow_recent.count==1);
    /* Exact server port and current target, plus HTTP/UDP exclusion. */
    e=wire_event(D2K_EV_FLOW,50003,8443);d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_HELLO,50003,8443);strcpy(e.name,"port.example.net");d2k_sched_event(s,&e);
    e=wire_event(D2K_EV_SUSPECT,50003,8443);d2k_sched_event(s,&e);
    assert(d2k_shadow_queue_next(path,&record,&rd)==1 && !record.history_time);
    e.client_shape=D2K_LINK_SHAPE_HTTP;d2k_sched_event(s,&e);assert(!d2k_shadow_queue_next(path,&record,&rd));
    e.client_shape=D2K_SHAPE_MODERN;e.transport=17;d2k_sched_event(s,&e);assert(!d2k_shadow_queue_next(path,&record,&rd));
    e=wire_event(D2K_EV_SUSPECT,50999,443);d2k_sched_event(s,&e);assert(!d2k_shadow_queue_next(path,&record,&rd));
    assert(!d2k_sched_set_shadow(s,NULL));assert(!s->shadow_flows);d2k_sched_free(s);d2k_catalog_free(&catalog);
    char recent[600];snprintf(recent,sizeof recent,"%s.recent",path);unlink(recent);unlink(path);assert(!rmdir(dir));
    puts("shadow scheduler: ok");return 0;
}
