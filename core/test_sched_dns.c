/* Scheduler integration with stubbed DNS exchanges. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <poll.h>
int dns_thread_create(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *);
#define d2k_verify_doh_on dns_test_verify
#define d2k_verify_dot_on dot_test_verify
#define d2k_verify_plain_dns_on plain_test_verify
#define pthread_create dns_thread_create
#define D2K_SCHED_DNS_TEST 1
#include "sched.c"
#undef pthread_create
#undef d2k_verify_doh_on
#undef d2k_verify_dot_on
#undef d2k_verify_plain_dns_on
#include <assert.h>
static unsigned started, dot_calls;
static uint32_t dot_mark;
static uint16_t dot_version;
static d2k_ver_result dot_result;
static unsigned plain_transports;
static int expect_recent;
static int real_workers;
static d2k_ver_result prepare_plain_trial(const char *ip,uint16_t port,uint8_t transport,
    const char *question,uint16_t type,int timeout,uint32_t mark,d2k_plain_dns_request *request);
static void run_plain_trial(const d2k_plain_dns_request *request,int timeout,
    int (*allowed)(void *),void *context,d2k_ver_result *result);
int dns_thread_create(pthread_t *t,const pthread_attr_t *a,void *(*f)(void *),void *v) {
    started++;
    return real_workers ? pthread_create(t,a,f,v) : EAGAIN;
}
/* The cached program works only for marked verifier traffic; ordinary
 * router DNS is still excluded until recovery admission is published. */
d2k_ver_result dns_test_verify(int fd,const char *ip,uint16_t port,const char *name,
    int timeout,size_t wire,int tls12,uint32_t mark,const char *path) {
    (void)fd;(void)ip;(void)port;(void)name;(void)timeout;(void)wire;(void)tls12;(void)path;
    d2k_ver_result r={.fd=-1};
    if(mark) {r.level=D2K_VER_APPLICATION;r.budget=D2K_BUDGET_PASSED;r.doh_replies=20;r.body_complete=1;r.peer_authenticated=1;}
    return r;
}
d2k_ver_result dot_test_verify(int fd,const char *ip,uint16_t port,const char *name,
    int timeout,uint16_t version,uint32_t mark) {
    (void)fd;(void)timeout;
    assert(!strcmp(ip,"2001:db8::52") && port==853 && !strcmp(name,"dot.example.test"));
    dot_calls++;dot_mark=mark;dot_version=version;
    return dot_result;
}
d2k_ver_result plain_test_verify(const char *ip,uint16_t port,uint8_t transport,
    const char *question,uint16_t type,int timeout,uint32_t mark) {
    (void)timeout;
    assert(!strcmp(ip,"192.0.2.53") && port==53 && !mark);
    if (expect_recent)
        assert(type==33 && !strcmp(question,"_svc.example"));
    else
        assert(type==12 && !strcmp(question,"53.2.0.192.in-addr.arpa"));
    plain_transports|=transport==6 ? 1 : transport==17 ? 2 : 0;
    return (d2k_ver_result){.fd=-1,.level=D2K_VER_APPLICATION,.budget=D2K_BUDGET_PASSED,
        .doh_replies=1,.body_complete=1};
}
static void write_file(const char *path,const char *body) {
    FILE *f=fopen(path,"w");assert(f && fputs(body,f)>=0 && !fclose(f));
}
static void plain_health_thread(const char *configuration) {
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);
    s->clock_seen=1;s->now_ms=1000;
    write_file(configuration,"upstream udp://192.0.2.53\n");
    assert(d2k_sched_doh_discover(s,configuration,NULL)==1);
    real_workers=1;
    doh_health_tick(s);
    real_workers=0;
    task *t=dns_task_of(s,s->doh);
    assert(t && t->th_live);
    struct pollfd wake={.fd=s->wake[0],.events=POLLIN};
    assert(poll(&wake,1,3000)==1 && doh_health_complete(s,t));
    assert(t->state==T_WATCHING && s->doh[0].plain_outcome==1);
    char notification;
    assert(read(wake.fd,&notification,1)==1);
    s->now_ms=s->doh[0].next_ms;
    real_workers=1;
    doh_health_tick(s);
    real_workers=0;
    assert(t->th_live && poll(&wake,1,3000)==1);
    write_file(configuration,"upstream tcp://192.0.2.53\n");
    assert(d2k_sched_doh_discover(s,configuration,NULL)==1);
    assert(doh_health_complete(s,t) && t->state==T_FREE && !s->doh[0].plain_outcome);
    d2k_sched_free(s);d2k_catalog_free(&cat);
}
static void plain_health_timeout(const char *configuration) {
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);
    s->clock_seen=1;s->now_ms=1000;
    write_file(configuration,"upstream udp://192.0.2.53\n");
    assert(d2k_sched_doh_discover(s,configuration,NULL)==1);
    d2k_sched_dns_observe_question(s,"first.example",28,s->now_ms);
    doh_health_tick(s);
    doh_target *d=s->doh;
    task *t=dns_task_of(s,d);assert(t && t->dns_qtype==28);
    d2k_ver_result timeout={.fd=-1,.level=D2K_VER_TRANSPORT,.budget=D2K_BUDGET_CUT,.dns_query_bytes=31};
    t->state=T_DOH_HEALTH;t->res_ready=1;t->ver=timeout;t->ver.dns_query_bytes=0;
    assert(doh_health_complete(s,t) && d->next_ms>s->now_ms);
    t->state=T_DOH_HEALTH;t->res_ready=1;t->ver=timeout;
    assert(doh_health_complete(s,t) && d->next_ms==s->now_ms);
    d2k_sched_dns_observe_question(s,"second.example",1,s->now_ms+1);
    s->now_ms++;
    doh_health_tick(s);
    assert(t->dns_qtype==28 && !strcmp(t->dns_question,"first.example"));
    t->state=T_DOH_HEALTH;t->res_ready=1;t->ver=timeout;t->ver.dns_reply_rejected=1;
    assert(doh_health_complete(s,t) && d->next_ms>s->now_ms);
    s->now_ms=d->next_ms;
    doh_health_tick(s);
    assert(t->dns_qtype==1 && !strcmp(t->dns_question,"second.example"));
    t->state=T_DOH_HEALTH;t->res_ready=1;t->ver=timeout;
    assert(doh_health_complete(s,t) && d->next_ms==s->now_ms);
    doh_health_tick(s);
    t->state=T_DOH_HEALTH;t->res_ready=1;t->ver=timeout;
    assert(doh_health_complete(s,t) && d->next_ms>s->now_ms);
    s->now_ms=d->next_ms;
    doh_health_tick(s);
    t->state=T_DOH_HEALTH;t->res_ready=1;t->ver=timeout;
    assert(doh_health_complete(s,t) && d->next_ms>s->now_ms);
    d2k_sched_free(s);d2k_catalog_free(&cat);
}
static unsigned trial_runs;
static d2k_ver_result prepare_plain_trial(const char *ip,uint16_t port,uint8_t transport,
    const char *question,uint16_t type,int timeout,uint32_t mark,d2k_plain_dns_request *request) {
    (void)timeout;
    assert(!strcmp(ip,"192.0.2.53") && port==53 && (transport==6 || transport==17) && mark==0x2d);
    assert(!strcmp(question,"53.2.0.192.in-addr.arpa") && type==12);
    request->transport=transport;
    request->length=35;
    request->wire_digest[0]=1;
    int fd=open("/dev/null",O_RDONLY);
    assert(fd>=0);
    return (d2k_ver_result){.fd=fd,.level=D2K_VER_TRANSPORT,.family=4,.local_port=32000,
        .local_ip4={192,0,2,1},.local_addr={192,0,2,1}};
}
static void run_plain_trial(const d2k_plain_dns_request *request,int timeout,
    int (*allowed)(void *),void *context,d2k_ver_result *result) {
    (void)timeout;
    assert(allowed(context));
    trial_runs++;
    result->level=D2K_VER_APPLICATION;result->doh_replies=1;result->body_complete=1;
    result->budget=D2K_BUDGET_PASSED;
    result->dns_query_bytes=(uint16_t)(request->length+(request->transport==6 ? 2 : 0));
    result->budget_requests=request->transport==6 ? 1 : 2;
}
static void plain_exact_trial(const char *configuration,int expire,uint8_t transport) {
    int control[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,control));
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,control[0],0x2d);assert(s);
    d2k_sched_set_plain_trial(s,prepare_plain_trial,run_plain_trial);
    s->clock_seen=1;s->now_ms=1000;
    write_file(configuration,transport==6 ? "upstream tcp://192.0.2.53\n" : "upstream udp://192.0.2.53\n");
    assert(d2k_sched_doh_discover(s,configuration,NULL)==1);
    doh_health_tick(s);
    task *t=dns_task_of(s,s->doh);assert(t);
    for (int i=0;i<2;i++) {
        t->state=T_DOH_HEALTH;t->res_ready=1;
        t->ver=(d2k_ver_result){.fd=-1,.family=4,.local_addr={192,0,2,1},
            .level=D2K_VER_TRANSPORT,.budget=D2K_BUDGET_CUT,.dns_query_bytes=transport==6?37:35};
        real_workers=i;
        assert(doh_health_complete(s,t));
        real_workers=0;
    }
    assert(t->state==T_DNS_PLAIN_TRIAL && t->th_live);
    struct pollfd wake={.fd=s->wake[0],.events=POLLIN};
    assert(poll(&wake,1,3000)==1);
    plain_trial_tick(s,t);
    char byte;assert(read(wake.fd,&byte,1)==1);
    struct pollfd link={.fd=control[1],.events=POLLIN};
    trial_runs=0;
    assert(poll(&link,1,500)==1);
    uint8_t packet[512];ssize_t length=read(link.fd,packet,sizeof packet);
    assert(length>98 && packet[5]==0x9c && !memcmp(packet+44,t->addr_probe_trial_id,16));
    d2k_ev event={.kind=D2K_EV_ACK,.code=D2K_CMD_SET_DNS_PROBE,.num=1u<<8};
    assert(!d2k_sched_event(s,&event) && !trial_runs && !t->trial_acked);
    uint8_t trial[D2K_TRIAL_ID_LEN];memcpy(trial,t->addr_probe_trial_id,sizeof trial);
    if (expire) {
        s->now_ms=t->trial_until_ms;
        plain_trial_tick(s,t);
        assert(!trial_runs && t->state==T_WATCHING && t->ver.fd==-1 && !s->doh[0].recovery);
        assert(poll(&link,1,500)==1);
        length=read(link.fd,packet,sizeof packet);
        assert(length==60 && packet[5]==D2K_CMD_DEL_ADDR_PROBE && !memcmp(packet+44,trial,sizeof trial));
        memcpy(event.trial_id,trial,sizeof trial);
        assert(!d2k_sched_event(s,&event) && !t->trial_acked);
        d2k_sched_free(s);d2k_catalog_free(&cat);close(control[0]);close(control[1]);
        return;
    }
    memcpy(event.trial_id,t->addr_probe_trial_id,16);
    assert(!d2k_sched_event(s,&event) && t->trial_acked);
    assert(read(wake.fd,&byte,1)==1);
    real_workers=1;plain_trial_tick(s,t);real_workers=0;
    assert(poll(&wake,1,3000)==1);
    plain_trial_tick(s,t);
    assert(trial_runs==1 && t->state==T_DNS_PLAIN_TRIAL && !cat.n_boxes &&
        !d2k_sched_plain_dns_revision(s));
    event.kind=D2K_EV_APPLIED;event.family=4;event.transport=transport;event.low_port=32000;event.high_port=53;
    memcpy(event.low_ip,t->ver_flow.a_ip,4);memcpy(event.high_ip,t->ver_flow.b_ip,4);
    memcpy(event.plan_id,t->ver_plan_id,16);
    event.execution_id=1;
    event.execution_binding=(d2k_binding_context){.kind=D2K_BIND_FLOW,.temporary=1,.family=4,
        .shape=D2K_LINK_SHAPE_RAW,.generation=1,.epoch={1}};
    event.low_port=32001;
    assert(!d2k_sched_event(s,&event) && !t->ver_ok);
    event.low_port=32000;
    assert(!d2k_sched_event(s,&event) && t->ver_ok);
    plain_trial_tick(s,t);
    assert(t->state==T_WATCHING && !t->trial_installed && cat.n_boxes==1);
    assert(d2k_sched_plain_dns_revision(s)==cat.revision && cat.revision);
    assert(d2k_sched_dns_save_pending(s,0));
    assert(!d2k_sched_dns_save_pending(s,cat.revision));
    assert(cat.boxes[0].n_binds==1);
    d2k_cat_binding *saved=cat.boxes[0].binds;
    assert(saved->shape==D2K_CAT_SHAPE_DNS && saved->dns_query_bytes==(transport==6 ? 37 : 35));
    assert(saved->transport==transport && saved->server_port==53 && saved->family==4 &&
           saved->verified_by==D2K_VERBY_PROBE && saved->budget==D2K_CAT_BUDGET_PASSED);
    assert(!strcmp(saved->target,"192.0.2.53") && !strcmp(saved->dns_address,saved->target) &&
           !strcmp(saved->dns_name,saved->target) && !saved->dns_authenticated &&
           !saved->dns_dot && !saved->probe_path[0]);
    char catalog_path[]="/tmp/d2k-dns-proof-XXXXXX",err[160];
    int catalog_fd=mkstemp(catalog_path);assert(catalog_fd>=0);close(catalog_fd);
    assert(d2k_catalog_save_atomic(&cat,catalog_path,err,sizeof err)==0);
    saved->dns_authenticated=1;
    assert(d2k_catalog_save_atomic(&cat,catalog_path,err,sizeof err)<0);
    saved->dns_authenticated=0;
    saved->dns_query_bytes=16;
    assert(d2k_catalog_save_atomic(&cat,catalog_path,err,sizeof err)<0);
    d2k_catalog restored={0};
    assert(!d2k_catalog_load(catalog_path,&restored,err,sizeof err));
    assert(restored.n_boxes==1 && restored.boxes[0].n_binds==1 &&
        restored.boxes[0].binds[0].transport==transport &&
        restored.boxes[0].binds[0].dns_query_bytes==(transport==6 ? 37 : 35));
    d2k_catalog_free(&restored);unlink(catalog_path);
    assert(poll(&link,1,500)==1);
    length=read(link.fd,packet,sizeof packet);
    assert(length==60 && packet[5]==D2K_CMD_DEL_ADDR_PROBE && !memcmp(packet+44,trial,sizeof trial));
    d2k_sched_free(s);d2k_catalog_free(&cat);close(control[0]);close(control[1]);
}
static void plain_health(const char *configuration,const char *routes) {
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);
    s->clock_seen=1;s->now_ms=1000;s->meas_limit=0;
    write_file(configuration,"upstream udp://192.0.2.53\nupstream tcp://192.0.2.53\n");
    assert(d2k_sched_doh_discover(s,configuration,NULL)==2);
    doh_health_tick(s);
    for (size_t i=0;i<2;i++) {
        doh_target *d=s->doh+i;
        task *t=dns_task_of(s,d);
        assert(t && t->dns_plain==d->plain && !encrypted_dns_task(t));
        worker_arg worker={.s=s,.t=t,.use_fd=-1};
        t->job=JOB_DOH_HEALTH;t->state=T_DOH_HEALTH;
        s->memory.worker_args_allocated++;worker_run(&worker);
        assert(doh_health_complete(s,t) && d->plain_outcome==1 && t->state==T_WATCHING);
    }
    assert(plain_transports==3 && d2k_sched_dns_routes(s,routes)==0);
    d2k_sched_dns_observe_question(s,"never-forward.example",1,s->now_ms);
    assert(!s->recent_dns_qtype);
    write_file(configuration,"upstream udp://192.0.2.53\n");
    assert(d2k_sched_doh_discover(s,configuration,NULL)==1);
    d2k_sched_dns_observe_question(s,"_svc.Example.",33,s->now_ms);
    d2k_sched_dns_observe_question(s,"bad..example",1,s->now_ms+1);
    task *t=dns_task_of(s,s->doh);
    dns_pick_question(s,t,s->now_ms+100);
    expect_recent=1;
    worker_arg worker={.s=s,.t=t,.use_fd=-1};
    t->job=JOB_DOH_HEALTH;t->state=T_DOH_HEALTH;
    s->memory.worker_args_allocated++;worker_run(&worker);
    assert(doh_health_complete(s,t) && s->doh[0].plain_outcome==1);
    expect_recent=0;
    dns_pick_question(s,t,s->now_ms+3600000);
    assert(t->dns_qtype==0 && !t->dns_question[0]);
    d2k_sched_free(s);d2k_catalog_free(&cat);
}
static void plain_saved_restart(const char *configuration,const char *routes,int degrade) {
    int control[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,control));
    d2k_catalog cat={0};
    const char *text="d2k-plan 1 7\nid 00000000000000000000000000000000\nproto udp quic\nipfrag 1\n";
    assert(!bind_confirmed(&cat,"plain-dns","plan-saved",text,"dns","192.0.2.53","service",
        17,4,D2K_CAT_SHAPE_DNS,53,D2K_VERBY_PROBE,D2K_INPUT_PROFILE,100,NULL,NULL,NULL));
    d2k_cat_binding *b=cat.boxes[0].binds;
    b->budget=D2K_CAT_BUDGET_PASSED;b->dns_port=53;b->dns_query_bytes=35;
    strcpy(b->dns_name,b->target);strcpy(b->dns_address,b->target);
    d2k_sched *s=d2k_sched_new(&cat,control[0],0x2d);assert(s);
    s->clock_seen=1;s->now_ms=1000;
    write_file(configuration,"upstream udp://192.0.2.53\nupstream tcp://192.0.2.53\n");
    assert(d2k_sched_doh_discover(s,configuration,NULL)==2);
    assert(d2k_sched_dns_routes(s,routes)==0);
    if (degrade) {
        s->plain_dns_revision=cat.revision;
        plain_dns_reconcile(s);
        struct pollfd pending={.fd=control[1],.events=POLLIN};
        assert(poll(&pending,1,0)==0);
        d2k_sched_plain_dns_saved(s,cat.revision);
    }
    plain_dns_reconcile(s);
    struct pollfd link={.fd=control[1],.events=POLLIN};
    uint8_t packet[512];ssize_t length;
    assert(poll(&link,1,500)==1);
    length=read(link.fd,packet,sizeof packet);
    assert(length>44 && packet[5]==D2K_CMD_SET_DNS_ENDPOINT && packet[27]==35);
    assert(d2k_sched_dns_routes(s,routes)==0);
    d2k_ev ack={.kind=D2K_EV_ACK,.code=D2K_CMD_SET_DNS_ENDPOINT,.num=1u<<8,
        .execution_binding={.generation=1,.epoch={1},.kind=D2K_BIND_ADDR,.shape=D2K_LINK_SHAPE_DNS,.family=4}};
    assert(!d2k_sched_event(s,&ack) && d2k_sched_dns_routes(s,routes)==0);
    memcpy(ack.trial_id,packet+length-16,16);
    assert(!d2k_sched_event(s,&ack) && d2k_sched_dns_routes(s,routes)==1);
    FILE *out=fopen(routes,"r");assert(out);
    char row[180];assert(fgets(row,sizeof row,out) && !strcmp(row,"192.0.2.53 192.0.2.53 53 udp\n"));fclose(out);
    if (degrade) {
        doh_target *d=s->doh;
        assert(d->plain==17);
        for (int i=0;i<2;i++) {
            if(i)d2k_sched_dns_routed(s,routes);
            for(int j=0;j<2;j++) {
                s->now_ms=d->next_ms;
                doh_health_tick(s);
                task *t=dns_task_of(s,d);assert(t);
                t->state=T_DOH_HEALTH;t->res_ready=1;
                t->ver=(d2k_ver_result){.fd=-1,.family=4,.local_addr={192,0,2,1},
                    .level=D2K_VER_TRANSPORT,.budget=D2K_BUDGET_CUT,.dns_query_bytes=35};
                assert(doh_health_complete(s,t));
            }
            assert((b->recheck_since!=0)==i);
        }
    } else {
        write_file(configuration,"upstream tcp://192.0.2.53\n");
        assert(d2k_sched_doh_discover(s,configuration,NULL)==1);
    }
    assert(d2k_sched_dns_routes(s,routes)==0);
    plain_dns_reconcile(s);
    assert(poll(&link,1,500)==1);
    length=read(link.fd,packet,sizeof packet);
    assert(length==27 && packet[5]==D2K_CMD_DEL_ENDPOINT && packet[26]==17);
    d2k_sched_free(s);d2k_catalog_free(&cat);close(control[0]);close(control[1]);
}
static void dot_health_and_recovery(const char *configuration,const char *routes) {
    d2k_catalog cat={0};
    d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);
    s->clock_seen=1;s->now_ms=1000;s->meas_limit=0;
    write_file(configuration,"upstream tls://[2001:db8::52]:853@dot.example.test\n");
    assert(d2k_sched_doh_discover(s,configuration,NULL)==1);
    doh_target *d=s->doh;
    assert(d->dot && !d->path[0]);
    doh_health_tick(s);
    task *t=dns_task_of(s,d);assert(t && t->dns_dot && t->family==6);
    worker_arg worker={.s=s,.t=t,.use_fd=-1};
    dot_result=(d2k_ver_result){.fd=-1,.level=D2K_VER_APPLICATION,.peer_authenticated=1,
        .budget=D2K_BUDGET_PASSED,.doh_replies=20,.body_complete=1,.negotiated_tls=0x0303};
    t->state=T_DOH_HEALTH;
    real_workers=1;
    assert(start_worker(s,t,JOB_DOH_HEALTH)==0);
    real_workers=0;
    struct pollfd wake={.fd=s->wake[0],.events=POLLIN};
    assert(poll(&wake,1,3000)==1);
    assert(doh_health_complete(s,t) && d->health_ok==1 && !d->recovery);
    assert(dot_calls==1 && dot_mark==0 && dot_version==0);
    dot_result=(d2k_ver_result){.fd=-1,.level=D2K_VER_HANDSHAKE,
        .peer_authenticated=1,.dns_reply_rejected=1,.budget_requests=1};
    t->state=T_DOH_HEALTH;s->memory.worker_args_allocated++;worker_run(&worker);
    assert(doh_health_complete(s,t) && d->health_ok==1 && !d->recovery);
    dot_result.dns_reply_rejected=0;dot_result.budget=D2K_BUDGET_CUT;
    dot_result.negotiated_tls=0x0303;
    t->state=T_DOH_HEALTH;s->memory.worker_args_allocated++;worker_run(&worker);
    assert(doh_health_complete(s,t) && d->recovery && t->state==T_QUEUED &&
        t->dns_dot && t->trigger_shape==D2K_SHAPE_LEGACY);
    assert(d2k_sched_dns_routes(s,routes)==1);
    d2k_ver_result v=verify_encrypted_dns(t,-1,0,1,s->measure_mark,0);
    assert(v.budget==D2K_BUDGET_CUT && dot_version==0x0303 && dot_mark==s->measure_mark);
    write_file(configuration,"upstream https://[2001:db8::52]:853/dns-query\n");
    assert(d2k_sched_doh_discover(s,configuration,NULL)==1 && !s->doh[0].dot);
    assert(t->state==T_FREE && d2k_sched_dns_routes(s,routes)==0);
    d2k_sched_free(s);d2k_catalog_free(&cat);
}
static void count_ordinary_health_reports(void *ctx, const char *line) {
    unsigned *count = ctx;
    if (strstr(line, "проверка DoH по фактическому пути роутера прошла")) ++*count;
}

static void configured_dns_with_force_rule(const char *configuration,const char *addresses,const char *owner) {
    write_file(configuration,"upstream https://dns.owner.test/private-query\n");
    write_file(addresses,"dns.owner.test 192.0.2.18 443\n");
    write_file(owner,"owner.test\n");
    for (int observed=0;observed<=1;observed++) {
        d2k_catalog catalog={0};
        d2k_sched *s=d2k_sched_new(&catalog,-1,0x2d);
        assert(s);
        unsigned healthy_reports=0;
        d2k_sched_set_say(s,count_ordinary_health_reports,&healthy_reports);
        s->clock_seen=1;s->now_ms=1000;s->meas_limit=0;
        assert(d2k_sched_force_load(s,owner)==1);
        assert(d2k_sched_doh_discover(s,configuration,addresses)==1);
        if (observed)
            force_remember(s,"dns.owner.test","192.0.2.18",443,6,4,0);
        unsigned before=started;
        force_tick(s);
        doh_health_tick(s);
        task *t=dns_task_of(s,&s->doh[0]);
        assert(t && t->state==T_WATCHING && started==before+1);
        t->state=T_DOH_HEALTH;t->res_ready=1;
        t->ver=(d2k_ver_result){.fd=-1,.level=D2K_VER_APPLICATION,.budget=D2K_BUDGET_PASSED,
            .body_complete=1,.peer_authenticated=1,.doh_replies=20};
        assert(doh_health_complete(s,t));
        force_tick(s);
        assert(t->state==T_WATCHING && !s->doh[0].recovery && s->doh[0].health_ok==1);
        assert(!queued_pick(s));
        s->now_ms=s->doh[0].next_ms;
        doh_health_tick(s);
        assert(started==before+2);
        t->state=T_DOH_HEALTH;t->res_ready=1;
        t->ver=(d2k_ver_result){.fd=-1,.level=D2K_VER_HANDSHAKE,.peer_authenticated=1,
            .budget=D2K_BUDGET_CUT,.budget_requests=5,.doh_replies=4,.doh_http_version=2};
        assert(doh_health_complete(s,t));
        force_tick(s);
        doh_health_tick(s);
        assert(s->doh[0].recovery && queued_pick(s)==t && queued_measurements(s)==1);
        assert(t->dns_expected_http==2 && t->port==443 && !strcmp(t->ip,"192.0.2.18"));
        assert(!strcmp(t->doh_path,"/private-query"));
        assert(healthy_reports==1);
        /* Deliver two ordinary-route health results after the incident. */
        for (unsigned i=0;i<2;i++) {
            t->state=T_DOH_HEALTH;t->res_ready=1;
            t->ver=(d2k_ver_result){.fd=-1,.level=D2K_VER_APPLICATION,.budget=D2K_BUDGET_PASSED,
                .body_complete=1,.peer_authenticated=1,.doh_replies=20,.doh_http_version=2};
            assert(doh_health_complete(s,t));
            assert(healthy_reports==2 && !s->doh[0].recovery);
        }
        d2k_sched_free(s);d2k_catalog_free(&catalog);
    }
}
static int no_counters(const d2k_ct_tuple *t,d2k_ct_info *out) {
    (void)t; (void)out; return -1;
}

static void repeat_connection(void) {
    d2k_catalog c={0};
    d2k_sched *s=d2k_sched_new(&c,-1,0); assert(s);
    d2k_sched_set_ct_query(s,no_counters);
    s->now_ms=1000;
    d2k_ev ev={.kind=D2K_EV_FLOW,.family=4,.transport=6,
        .client_side=D2K_CLIENT_SIDE_LOW,.low_port=50000,.high_port=443};
    assert(inet_pton(AF_INET,"192.0.2.3",ev.low_ip)==1);
    assert(inet_pton(AF_INET,"198.51.100.17",ev.high_ip)==1);
    assert(!d2k_sched_event(s,&ev));
    assert(s->flowwatch[0].used && !s->flowwatch[0].known_service[0]);

    d2k_dns_answer a={.type=1,.count=1,.ttl=30};
    strcpy(a.question,"video.example");
    memcpy(a.addresses[0],ev.high_ip,4);
    d2k_sched_dns_observe_answer(s,&a,s->now_ms);
    ev.low_port++;
    assert(!d2k_sched_event(s,&ev));
    assert(!strcmp(s->flowwatch[1].known_service,"video.example"));
    assert(!s->flowwatch[0].known_service[0]);

    /* A first named connection also teaches the endpoint when DNS was unseen. */
    ev.kind=D2K_EV_HELLO;
    ev.high_ip[3]++;
    strcpy(ev.name,"download.example");
    assert(!d2k_sched_event(s,&ev));
    ev.kind=D2K_EV_FLOW; ev.name[0]=0; ev.low_port++;
    assert(!d2k_sched_event(s,&ev));
    assert(!strcmp(s->flowwatch[3].known_service,"download.example"));
    ev.high_port++;
    assert(!d2k_sched_event(s,&ev));
    assert(!s->flowwatch[4].known_service[0]);
    char path[]="/tmp/d2k-address-history-XXXXXX";
    int fd=mkstemp(path); assert(fd>=0); close(fd);
    flowwatch_tick(s,6000);
    assert(!d2k_sched_write_live(s,path,NULL));
    FILE *f=fopen(path,"r"); assert(f);
    char line[2048]; int unknown=0,known=0;
    while (fgets(line,sizeof line,f)) {
        if (!strstr(line,"\"target\": \"198.51.100.17\"")) continue;
        assert(strstr(line,"\"flows\": 1"));
        if (strstr(line,"\"known_service\": \"video.example\"")) known++;
        else unknown++;
    }
    assert(!ferror(f) && unknown==1 && known==1);
    fclose(f); unlink(path);
    d2k_sched_free(s); d2k_catalog_free(&c);
}

static void learned_service_address(void) {
    d2k_catalog c={0};
    d2k_sched *s=d2k_sched_new(&c,-1,0); assert(s);
    d2k_dns_answer answer={.family=6,.type=1,.count=1,.ttl=30};
    strcpy(answer.question,"video.example");
    assert(inet_pton(AF_INET,"192.0.2.17",answer.addresses[0])==1);
    uint8_t ip[16]; memcpy(ip,answer.addresses[0],16);
    assert(!known_service_name(s,ip,4,6,443,1000));
    d2k_sched_dns_observe_answer(s,&answer,1000);
    assert(!strcmp(known_service_name(s,ip,4,6,443,1001),"video.example"));
    /* Different clients can cache different answers for the same name. */
    answer.addresses[0][3]=18;
    d2k_sched_dns_observe_answer(s,&answer,1001);
    assert(known_service_name(s,ip,4,6,443,1002));
    assert(known_service_name(s,answer.addresses[0],4,6,443,1002));
    memcpy(answer.addresses[0],ip,16);
    strcpy(answer.question,"another.example"); answer.ttl=5;
    d2k_sched_dns_observe_answer(s,&answer,1002);
    assert(!known_service_name(s,ip,4,6,443,1003));
    assert(!strcmp(known_service_name(s,ip,4,6,443,6002),"video.example"));
    assert(!known_service_name(s,ip,4,6,443,31000));
    answer.type=28; answer.ttl=30; strcpy(answer.question,"download.example");
    assert(inet_pton(AF_INET6,"2001:db8::17",answer.addresses[0])==1);
    d2k_sched_dns_observe_answer(s,&answer,32000);
    assert(!strcmp(known_service_name(s,answer.addresses[0],6,6,443,32001),"download.example"));
    answer.ttl=0; d2k_sched_dns_observe_answer(s,&answer,32002);
    assert(!known_service_name(s,answer.addresses[0],6,6,443,32002));
    d2k_sched_free(s); d2k_catalog_free(&c);
}

static void automatic_preflight_lease(void) {
    int control[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM,0,control));
    d2k_catalog c={0};
    uint8_t hello[4096]; size_t hello_len=0; char plan[16384],err[200];
    d2k_box_props props={0};
    props.response_gate=props.gate_carry=props.gate_hello_own=D2K_PROP_YES;
    props.gate_window=7; props.gate_pieces=9; props.gate_rtt_ms=231;
    assert(!d2k_hello_from_profile(D2K_SHAPE_MODERN,"video.example",hello,sizeof hello,&hello_len));
    assert(d2k_compose_preflight_from_props(&props,NULL,0,4,6,hello,hello_len,
        plan,sizeof plan,err,sizeof err)==1);
    assert(!bind_confirmed(&c,"gate","gate-plan",plan,"tls","198.51.100.17","service",
        6,4,D2K_SHAPE_MODERN,443,D2K_VERBY_PROBE,0,1000,NULL,&props,NULL));
    strcpy(c.boxes[0].binds[0].preflight_name,"video.example");
    d2k_sched *s=d2k_sched_new(&c,control[0],0); assert(s);
    d2k_dns_answer answer={.family=4,.type=1,.count=1,.ttl=30};
    strcpy(answer.question,"video.example");
    assert(inet_pton(AF_INET,"192.168.1.9",answer.client)==1);
    assert(inet_pton(AF_INET,"198.51.100.17",answer.addresses[0])==1);

    d2k_sched_dns_observe_answer_path(s,&answer,1000,7);
    struct pollfd ready={.fd=control[1],.events=POLLIN};
    assert(poll(&ready,1,500)==1);
    uint8_t packet[32768]; ssize_t n=read(control[1],packet,sizeof packet);
    assert(n>80 && packet[4]==0 && packet[5]==D2K_CMD_SET_PREFLIGHT_LEASE);
    const uint8_t *body=packet+6;
    assert(body[0]==4 && !memcmp(body+1,answer.client,4) &&
        !memcmp(body+17,answer.addresses[0],4) && body[33]==D2K_SHAPE_MODERN &&
        d2k_rm_get32(body+34)==7 && body[38]==1 && body[39]==187 &&
        d2k_rm_get32(body+40)==30000 && body[44]==0 && body[45]==13 &&
        !memcmp(body+46,"video.example",13));
    uint8_t lease_id[16]; memcpy(lease_id,body+59,16);

    d2k_ev ack={.kind=D2K_EV_ACK,.code=D2K_CMD_SET_PREFLIGHT_LEASE,.num=0};
    memcpy(ack.trial_id,lease_id,16); d2k_sched_event(s,&ack);
    assert(!s->preflight_leases[0].active && !s->preflight_leases[0].pending);

    d2k_sched_dns_observe_answer_path(s,&answer,1100,7);
    assert(poll(&ready,1,500)==1); n=read(control[1],packet,sizeof packet); assert(n>80);
    body=packet+6; memcpy(lease_id,body+59,16);
    ack.num=1u<<8; memcpy(ack.trial_id,lease_id,16); d2k_sched_event(s,&ack);
    assert(s->preflight_leases[0].active && !s->preflight_leases[0].pending);

    d2k_dns_answer conflict=answer; strcpy(conflict.question,"other.example");
    d2k_sched_dns_observe_answer_path(s,&conflict,1200,7);
    assert(poll(&ready,1,500)==1); n=read(control[1],packet,sizeof packet);
    assert(n>60 && packet[5]==D2K_CMD_DEL_PREFLIGHT_LEASE);
    assert(poll(&ready,1,20)==0); /* Ambiguous name: no replacement lease. */

    d2k_sched_free(s); close(control[0]); close(control[1]);
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,control));
    s=d2k_sched_new(&c,control[0],0); assert(s);
    ready.fd=control[1];
    assert(poll(&ready,1,20)==0); /* Catalog alone never replays a lease. */
    d2k_sched_dns_observe_answer_path(s,&answer,2000,7);
    assert(poll(&ready,1,500)==1); /* A fresh DNS association reactivates it. */
    n=read(control[1],packet,sizeof packet);assert(n>80);
    d2k_ev named={.kind=D2K_EV_HELLO,.family=4,.transport=6,
        .client_side=D2K_CLIENT_SIDE_LOW,.client_shape=D2K_SHAPE_MODERN,
        .low_port=50123,.high_port=443};
    strcpy(named.name,"video.example");
    inet_pton(AF_INET,"192.168.1.10",named.low_ip);
    memcpy(named.high_ip,answer.addresses[0],16);s->now_ms=2100;
    preflight_observe_named_path(s,&named,7);
    assert(poll(&ready,1,500)==1);n=read(control[1],packet,sizeof packet);
    assert(n>80&&packet[5]==D2K_CMD_SET_PREFLIGHT_LEASE);
    assert(!memcmp(packet+7,named.low_ip,16));
    strcpy(named.name,"other.example");
    preflight_observe_named_path(s,&named,7);
    assert(poll(&ready,1,500)==1);n=read(control[1],packet,sizeof packet);
    assert(n>60&&packet[5]==D2K_CMD_DEL_PREFLIGHT_LEASE);
    assert(poll(&ready,1,20)==0);
    d2k_sched_free(s); d2k_catalog_free(&c); close(control[0]); close(control[1]);
}

static void named_flow_address_history(void) {
    d2k_catalog c={0};d2k_sched *s=d2k_sched_new(&c,-1,0);assert(s);
    s->now_ms=1000;
    d2k_ev e={.kind=D2K_EV_HELLO,.family=6,.transport=6,
        .client_side=D2K_CLIENT_SIDE_LOW,.client_shape=D2K_SHAPE_MODERN,
        .low_port=50123,.high_port=443};
    strcpy(e.name,"video.example");
    assert(inet_pton(AF_INET6,"2001:db8:1::9",e.low_ip)==1);
    assert(inet_pton(AF_INET6,"2001:db8:2::17",e.high_ip)==1);
    /* No IPv6 DNS query is required to learn a real IPv6 client flow. */
    preflight_observe_named_path(s,&e,7);
    assert(s->dns_names[0].family==6&&s->dns_names[0].client_family==6);
    assert(s->dns_names[0].path==7&&!memcmp(s->dns_names[0].client,e.low_ip,16));
    assert(!strcmp(known_service_name(s,e.high_ip,6,6,443,1000),"video.example"));
    assert(!known_service_name(s,e.high_ip,6,6,443,601000));
    e.client_shape=D2K_LINK_SHAPE_ECH_TCP;strcpy(e.name,"outer.example");
    preflight_observe_named_path(s,&e,7);
    assert(!strcmp(s->dns_names[0].name,"video.example"));
    d2k_sched_free(s);d2k_catalog_free(&c);
}

static void journal_driven_dns(void) {
    char config[]="/tmp/d2k-journal-dns-XXXXXX", addresses[]="/tmp/d2k-journal-addresses-XXXXXX";
    int fd=mkstemp(config);assert(fd>=0);close(fd);
    fd=mkstemp(addresses);assert(fd>=0);close(fd);
    write_file(config,"upstream https://gw.example.com/dns-query\n");
    write_file(addresses,"");
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);
    assert(d2k_sched_doh_discover(s,config,addresses)==1);
    d2k_ev suspect={.family=4,.transport=6,.client_side=D2K_CLIENT_SIDE_LOW,
        .low_port=50001,.high_port=443};
    assert(inet_pton(AF_INET,"192.0.2.55",suspect.high_ip)==1);
    assert(force_doh_suspect(s,&suspect,"gw.example.com"));
    assert(!force_doh_suspect(s,&suspect,"other.example.com"));
    unsigned before=started;
    d2k_sched_tick(s,1000);d2k_sched_tick(s,6000);
    assert(started==before); /* No timer-initiated DNS work. */
    assert(d2k_sched_dns_journal_error(s,"unrelated.org")==0);
    assert(d2k_sched_dns_journal_error(s,"gw.example.com")==1);
    d2k_sched_tick(s,7000);assert(started==before);
    /* Router bootstrap survives the resolver outage that triggered recovery. */
    write_file(config,"upstream https://gw.example.com/dns-query\n"
        "static_a = other.example.com 192.0.2.99 0\n"
        "static_a = gw.example.com 192.0.2.55 0\n");
    assert(d2k_sched_doh_discover(s,config,addresses)==1);
    assert(!strcmp(s->doh[0].ip,"192.0.2.55"));
    d2k_sched_tick(s,7100);
    assert(started==before+1);
    cat.boxes=calloc(1,sizeof *cat.boxes);assert(cat.boxes);cat.n_boxes=cat.cap_boxes=1;
    d2k_cat_box *box=cat.boxes;
    box->binds=calloc(1,sizeof *box->binds);assert(box->binds);box->n_binds=box->cap_binds=1;
    box->plans=calloc(1,sizeof *box->plans);assert(box->plans);box->n_plans=box->cap_plans=1;
    d2k_cat_binding *b=box->binds;
    strcpy(b->kind,"service");strcpy(b->target,"192.0.2.55");strcpy(b->dns_address,"192.0.2.55");
    strcpy(b->dns_name,"gw.example.com");strcpy(b->probe_path,"/dns-query");
    strcpy(b->plan_id,"confirmed-dns-plan");b->server_port=b->dns_port=443;
    b->transport=6;b->family=4;b->level=3;b->confirmed=1;b->enabled=b->dns_authenticated=1;
    b->budget=D2K_CAT_BUDGET_PASSED;
    strcpy(box->plans[0].id,"confirmed-dns-plan");box->plans[0].enabled=1;
    box->plans[0].text=strdup("proto tls\n");assert(box->plans[0].text);
    assert(d2k_sched_dns_journal_error(s,"another.example.com")==0);
    d2k_sched_tick(s,8000);assert(started==before+1);
    write_file(config,"upstream https://gw.example.com/dns-query\n"
        "static_a = gw.example.com 192.0.2.55 0\n"
        "static_a = gw.example.com 192.0.2.56 0\n");
    assert(d2k_sched_doh_discover(s,config,addresses)==2);
    assert(d2k_sched_dns_journal_error(s,"gw.example.com")==1);
    for(size_t i=0;i<s->n_doh;i++)
        assert(s->doh[i].journal_pending==(!strcmp(s->doh[i].ip,"192.0.2.56")));
    d2k_sched_tick(s,8100);assert(started==before+2);
    d2k_sched_free(s);d2k_catalog_free(&cat);
    unlink(config);unlink(addresses);
}

static void family_fallback_proof(void) {
    char path[]="/tmp/d2k-family-proof-XXXXXX";
    int fd=mkstemp(path);assert(fd>=0);close(fd);unlink(path);
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);assert(s);
    s->clock_seen=1;s->now_ms=1000;s->meas_limit=0;
    d2k_sched_family_path(s,path);
    d2k_dns_answer a={.family=4,.type=1,.count=1,.ttl=60,
        .client={192,0,2,2},.addresses={{8,47,69,0}}};
    snprintf(a.question,sizeof a.question,"ru.numista.com");
    snprintf(a.name,sizeof a.name,"ru.numista.com");
    d2k_sched_dns_observe_answer(s,&a,1000);
    assert(s->family_a[0].expires_ms>61000);
    task *t=task_free_slot(s);assert(t);
    t->state=T_FAMILY_PROBE;t->job=JOB_FAMILY_PROBE;
    t->family=6;t->transport=6;t->port=443;
    t->started_ms=1000;t->res_ready=1;t->ver.fd=-1;
    t->ver.level=D2K_VER_HANDSHAKE;t->ver.peer_authenticated=1;
    t->family_ipv4_count=1;
    snprintf(t->name,sizeof t->name,"ru.numista.com");
    snprintf(t->family_ipv4[0],sizeof t->family_ipv4[0],"8.47.69.0");
    d2k_sched_tick(s,2000);
    assert(access(path,F_OK)!=0); /* TLS alone cannot trigger DNS policy. */
    t=task_free_slot(s);assert(t);
    t->state=T_FAMILY_PROBE;t->job=JOB_FAMILY_PROBE;
    t->family=6;t->transport=6;t->port=443;
    t->started_ms=3000;t->res_ready=1;t->ver.fd=-1;
    t->ver.level=D2K_VER_APPLICATION;t->ver.peer_authenticated=1;
    t->ver.name_ok=1;t->ver.body_complete=1;
    t->family_ipv4_count=1;
    snprintf(t->name,sizeof t->name,"ru.numista.com");
    snprintf(t->family_ipv4[0],sizeof t->family_ipv4[0],"8.47.69.0");
    d2k_sched_tick(s,4000);
    d2k_dns_family_rule rules[4];size_t count=0;
    assert(d2k_dns_family_load(path,rules,4,&count,time(NULL))==0 && count==1);
    assert(!strcmp(rules[0].name,"ru.numista.com") && rules[0].client_family==4 &&
           !memcmp(rules[0].client,a.client,4));
    unlink(path);d2k_sched_free(s);d2k_catalog_free(&cat);
}

int main(void) {
    family_fallback_proof();
    journal_driven_dns();
    named_flow_address_history();
    repeat_connection();
    learned_service_address();
    automatic_preflight_lease();
    char automatic[]="/tmp/d2k-dns-config-XXXXXX",addresses[]="/tmp/d2k-dns-addresses-XXXXXX",owner[]="/tmp/d2k-dns-owner-XXXXXX";
    int fd=mkstemp(automatic);assert(fd>=0);close(fd);fd=mkstemp(addresses);assert(fd>=0);close(fd);
    fd=mkstemp(owner);assert(fd>=0);close(fd);
    char routes[]="/tmp/d2k-dns-routes-XXXXXX";fd=mkstemp(routes);assert(fd>=0);close(fd);
    d2k_catalog catalog={0};d2k_sched *s=d2k_sched_new(&catalog,-1,0x2d);assert(s);
    s->clock_seen=1;s->now_ms=1000;s->meas_limit=0;
    write_file(owner,"owner.example.test 443 /owner-query 192.0.2.9\n");
    assert(d2k_sched_doh_load(s,owner)==1);
    write_file(automatic,"dns_server = 127.0.0.1 # https://unlisted.example.test:8443/private/dns-query?account=fixture\n");
    write_file(addresses,"unlisted.example.test 192.0.2.8 8443\n");
    assert(d2k_sched_doh_discover(s,automatic,addresses)==2);
    doh_target *d=doh_find(s,"unlisted.example.test");assert(d && d->port==8443);
    assert(!strcmp(d->path,"/private/dns-query?account=fixture") && !strcmp(d->ip,"192.0.2.8"));
    assert(doh_find(s,"owner.example.test") && !force_name(s,"unlisted.example.test"));
    d->next_ms=9000;d->health_ok=3;
    assert(d2k_sched_doh_discover(s,automatic,addresses)==2);
    d=doh_find(s,"unlisted.example.test");assert(d->next_ms==9000 && d->health_ok==3);
    d->next_ms=0;doh_health_tick(s);
    task *t=task_of(s,"unlisted.example.test",6,4);
    assert(t && t->port==8443 && !strcmp(t->ip,"192.0.2.8") && !strcmp(t->doh_path,d->path));
    assert(started); /* Actual existing health worker was requested. */
    worker_arg health={.s=s,.t=t,.use_fd=-1};t->job=JOB_DOH_HEALTH;
    s->memory.worker_args_allocated++;worker_run(&health);
    assert(doh_health_complete(s,t));
    assert(t->state==T_QUEUED && d->recovery); /* A marked-only success cannot hide broken real DNS. */
    write_file(automatic,"upstream https://bad..example.test/dns-query\n");
    assert(d2k_sched_doh_discover(s,automatic,addresses)<0 && s->n_doh==2);
    assert(doh_find(s,"unlisted.example.test"));
    write_file(automatic,"upstream https://waiting.example.test/dns-query\n");
    assert(d2k_sched_doh_discover(s,automatic,addresses)==2);
    d=doh_find(s,"waiting.example.test");assert(d && !d->ip[0]);
    d2k_ev observed={.kind=D2K_EV_HELLO,.family=4,.transport=6,.client_side=D2K_CLIENT_SIDE_LOW,
        .low_port=31000,.high_port=443};
    strcpy(observed.name,"waiting.example.test");
    assert(inet_pton(AF_INET,"192.0.2.42",observed.high_ip)==1);
    observed.client_side=D2K_CLIENT_SIDE_UNKNOWN;
    assert(d2k_sched_event(s,&observed)==0 && !d->ip[0]);
    observed.client_side=D2K_CLIENT_SIDE_LOW;
    assert(d2k_sched_event(s,&observed)==0 && !strcmp(d->ip,"192.0.2.42"));
    assert(d2k_sched_doh_discover(s,automatic,addresses)==2);
    d=doh_find(s,"waiting.example.test");assert(!strcmp(d->ip,"192.0.2.42"));
    d->ip[0]=0; /* Remaining unresolved endpoints do not launch fake-address probes. */
    unsigned before=started;doh_health_tick(s);assert(started==before);
    assert(!doh_find(s,"unlisted.example.test") && doh_find(s,"owner.example.test"));
    write_file(automatic,"");assert(d2k_sched_doh_discover(s,automatic,addresses)==1);
    assert(s->n_doh==1 && doh_find(s,"owner.example.test"));
    write_file(automatic,"upstream https://shared.example.test/first\nupstream https://shared.example.test/second\n");
    write_file(addresses,"shared.example.test 2001:db8::53 443\n");
    assert(d2k_sched_doh_discover(s,automatic,addresses)==3);
    before=started;doh_health_tick(s);assert(started==before+2);
    unsigned paths=0;
    for(size_t i=0;i<s->task_count;i++) {
        task *q=s->tasks[i];
        if(q->state!=T_FREE && !strcmp(q->name,"shared.example.test")) {
            assert(q->family==6 && !strcmp(q->ip,"2001:db8::53"));
            if(!strcmp(q->doh_path,"/first"))paths|=1;
            if(!strcmp(q->doh_path,"/second"))paths|=2;
        }
    }
    assert(paths==3 && !doh_find(s,"shared.example.test")); /* TLS name alone cannot select a path. */
    t=dns_task_of(s,&s->doh[1]);assert(t);
    char resource[sizeof t->doh_path];snprintf(resource,sizeof resource,"%s",t->doh_path);
    task *other=task_free_slot(s);assert(other);task_reset(s,other);
    strcpy(other->name,"ordinary.example.test");other->state=T_PLANNING;other->transport=6;other->family=4;
    task *waiting=task_free_slot(s);assert(waiting);task_reset(s,waiting);
    strcpy(waiting->name,"waiting-work.example.test");waiting->state=T_QUEUED;waiting->queued_event=0;
    t->state=T_DOH_HEALTH;t->res_ready=1;
    t->ver=(d2k_ver_result){.fd=-1,.level=D2K_VER_HANDSHAKE,.peer_authenticated=1,
        .budget=D2K_BUDGET_CUT,.budget_uncountable=1,.budget_requests=2,.doh_replies=1};
    assert(doh_health_complete(s,t));
    assert(s->doh[1].recovery);
    assert(other->state==T_PLANNING && waiting->state==T_QUEUED);
    assert(queued_pick(s)); /* DNS failure does not cancel or monopolize other work. */
    assert(d2k_sched_dns_routes(s,routes)==0);
    FILE *rf=fopen(routes,"r");assert(rf && fgetc(rf)==EOF);fclose(rf); /* The other resource on this tuple has no failed-path evidence. */
    assert(t->state==T_QUEUED && !strcmp(t->doh_path,resource) && !strcmp(t->measure_path,resource));
    write_file(addresses,"shared.example.test not-an-address 443\n");
    assert(d2k_sched_doh_discover(s,automatic,addresses)<0 && s->n_doh==3);
    s->doh[2].recovery=1;dns_task_of(s,&s->doh[2])->state=T_QUEUED;
    assert(d2k_sched_dns_routes(s,routes)==1);
    rf=fopen(routes,"r");char route[512];assert(rf && fgets(route,sizeof route,rf));fclose(rf);
    assert(!strcmp(route,"shared.example.test 2001:db8::53 443 tcp\n"));
    /* A policy/auth response never opens a path repair search. */
    t=dns_task_of(s,&s->doh[2]);assert(t);t->state=T_DOH_HEALTH;t->res_ready=1;
    t->ver.fd=-1;t->ver.status=403;t->ver.level=D2K_VER_HANDSHAKE;
    s->doh[2].recovery=0;assert(doh_health_complete(s,t));
    assert(t->state==T_WATCHING && !s->doh[2].recovery);
    t->state=T_DOH_HEALTH;t->res_ready=1;
    t->ver=(d2k_ver_result){.fd=-1,.level=D2K_VER_TRANSPORT,.peer_auth_failed=1};
    s->doh[2].recovery=1;
    assert(doh_health_complete(s,t) && t->state==T_WATCHING && !s->doh[2].recovery);
    assert(s->doh[2].health_ok==0);
    write_file(automatic,"upstream https://durable.example.test/private-query\n");
    write_file(addresses,"durable.example.test 192.0.2.51 443\n");
    assert(d2k_sched_doh_discover(s,automatic,addresses)==2);
    catalog.boxes=calloc(1,sizeof *catalog.boxes);assert(catalog.boxes);catalog.n_boxes=catalog.cap_boxes=1;
    d2k_cat_box *box=catalog.boxes;strcpy(box->id,"dns-proof");
    box->binds=calloc(1,sizeof *box->binds);assert(box->binds);box->n_binds=box->cap_binds=1;
    box->plans=calloc(1,sizeof *box->plans);assert(box->plans);box->n_plans=box->cap_plans=1;
    d2k_cat_binding *bd=box->binds;
    strcpy(bd->kind,"service");strcpy(bd->target,"192.0.2.51");bd->server_port=443;strcpy(bd->dns_name,"durable.example.test");strcpy(bd->plan_id,"dns-plan");
    strcpy(bd->probe_path,"/private-query");bd->transport=6;bd->family=4;bd->level=3;bd->enabled=1;
    bd->budget=D2K_CAT_BUDGET_PASSED;bd->shape=1;bd->confirmed=1;
    strcpy(box->plans[0].id,"dns-plan");strcpy(box->plans[0].proto,"tls");
    box->plans[0].text=strdup("proto tls\n");assert(box->plans[0].text);box->plans[0].enabled=1;
    assert(d2k_sched_dns_routes(s,routes)==0); /* Generic HTTP witness is insufficient. */
    bd->dns_port=443;strcpy(bd->dns_address,"192.0.2.51");
    assert(d2k_sched_dns_routes(s,routes)==0); /* Old DoH proof lacks TLS authentication. */
    bd->dns_authenticated=1;
    assert(d2k_sched_dns_routes(s,routes)==1);
    bd->recheck_since=1;assert(d2k_sched_dns_routes(s,routes)==0);bd->recheck_since=0;
    strcpy(bd->dns_address,"192.0.2.52");assert(d2k_sched_dns_routes(s,routes)==0);
    strcpy(bd->dns_address,"192.0.2.51");bd->dns_port=8443;assert(d2k_sched_dns_routes(s,routes)==0);
    bd->dns_port=443;strcpy(bd->probe_path,"/other");assert(d2k_sched_dns_routes(s,routes)==0);
    strcpy(bd->probe_path,"/private-query");
    /* The catalog round trip and a new scheduler retain exact DNS scope. */
    char err[160];assert(d2k_catalog_save(&catalog,owner,err,sizeof err)==0);
    d2k_catalog restored={0};assert(d2k_catalog_load(owner,&restored,err,sizeof err)==0);
    write_file(addresses,"");
    d2k_sched *again=d2k_sched_new(&restored,-1,0x2d);assert(again);
    assert(d2k_sched_doh_discover(again,automatic,addresses)==1);
    assert(d2k_sched_dns_journal_error(again,"durable.example.test")==0);
    assert(d2k_sched_dns_routes(again,routes)==1);
    assert(!strcmp(again->doh[0].ip,"192.0.2.51"));
    write_file(addresses,"durable.example.test 192.0.2.51 443\ndurable.example.test 2001:db8::51 443\n");
    assert(d2k_sched_doh_discover(again,automatic,addresses)==2);
    assert(again->n_doh==2 && strcmp(again->doh[0].ip,again->doh[1].ip));
    before=started;again->clock_seen=1;again->now_ms=1000;doh_health_tick(again);
    assert(started==before+2);
    d2k_sched_free(again);d2k_catalog_free(&restored);
    d2k_sched_free(s);d2k_catalog_free(&catalog);
    configured_dns_with_force_rule(automatic,addresses,owner);
    dot_health_and_recovery(automatic,routes);
    plain_health(automatic,routes);
    plain_health_thread(automatic);
    plain_health_timeout(automatic);
    plain_exact_trial(automatic,0,6);
    plain_exact_trial(automatic,1,6);
    plain_exact_trial(automatic,0,17);
    plain_saved_restart(automatic,routes,0);
    plain_saved_restart(automatic,routes,1);
    unlink(routes);unlink(automatic);unlink(addresses);unlink(owner);
    puts("DNS scheduler: configured DoH, DoT, DNS/UDP and DNS/TCP health; exact endpoint and atomic refresh");
}
