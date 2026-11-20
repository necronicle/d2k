#define d2k_verify_doh_on routing_doh_verify
#include "sched.c"
#include <assert.h>
static d2k_vol_result counted_volume(const char *ip, uint16_t port, const char *name,
                                    int plain, int legacy, size_t wire, uint32_t mark) {
    (void)ip; (void)port; (void)name; (void)plain; (void)legacy; (void)wire; (void)mark;
    d2k_vol_result result = {0};
    result.probes = 3;
    result.rx_short = 1;
    return result;
}
static d2k_vol_result counted_volume_path(const char *ip, uint16_t port, const char *name,
    int plain, int legacy, size_t wire, uint32_t mark, const char *path) {
    assert(path && !strcmp(path, "/observed"));
    d2k_vol_result result = counted_volume(ip, port, name, plain, legacy, wire, mark);
    result.probes = 2;
    return result;
}
typedef struct {
    d2k_verification_owner *owner;
    int calls,released;
} continuation;
static int application_calls,application_closed,application_direct,direct_checks;
static d2k_ver_result direct_result;
static int deeper_script;
static unsigned last_horizon;
d2k_ver_result routing_doh_verify(int fd,const char *ip,uint16_t port,const char *name,int timeout,
    size_t wire,int legacy,uint32_t mark,const char *path) {
    assert(fd==-1 && ip && port==443 && name && timeout>0 && wire && !legacy && mark==0x2f && path);
    direct_checks++;
    if(deeper_script && direct_checks>1)return (d2k_ver_result){.fd=-1,.level=D2K_VER_APPLICATION,
        .status=200,.body_complete=1,.peer_authenticated=1,
        .doh_replies=20,.budget_requests=20,.budget=D2K_BUDGET_PASSED};
    return direct_result;
}
static d2k_vres forbidden_tcp_base(const char *ip,uint16_t port,d2k_hello tr,d2k_hello ctl,
    uint32_t mark,int repeats,uint32_t gap,uint32_t wait,const volatile sig_atomic_t *stop,
    const d2k_sched_tcp_extra *extra) {
    (void)ip;(void)port;(void)tr;(void)ctl;(void)mark;(void)repeats;(void)gap;(void)wait;(void)stop;(void)extra;
    assert(!"known DoH failure escaped to legacy baseline");return (d2k_vres){0};
}
static int route_application(const d2k_application_request *r,size_t wire,int timeout,
    uint32_t mark,const volatile sig_atomic_t *stop,d2k_vres *out) {
    assert(r->doh && (r->doh_failure_query==6 || r->doh_failure_query==9) && r->shape==D2K_SHAPE_MODERN && wire && timeout>0);
    last_horizon=r->doh_failure_query;
    assert(mark==0x2f && stop && !*stop);application_calls++;
    memset(out,0,sizeof *out);out->owns_search=1;out->verdict=D2K_V_INCONCLUSIVE;
    out->probes=2;out->protocol_response=application_direct;return !application_closed;
}
static void release_continuation(void *ctx) {((continuation *)ctx)->released++;}
static int report_continuation(void *ctx,const d2k_synthesis_feedback *event,
    d2k_verification_status outcome) {
    continuation *c=ctx;c->calls++;
    assert(outcome==D2K_VF_NOT_MET && event->budget_requests==5 && event->doh_replies==4);
    d2k_verification_status actual=d2k_verification_accept(c->owner,event);
    return actual==D2K_VF_NOT_MET?1:actual==D2K_VF_DUPLICATE?0:-1;
}
typedef struct {d2k_sched *scheduler;task *job;continuation *expected;} resume_context;
static void *resumed_worker(void *arg) {
    resume_context *c=arg;g_progress_sink=(progress_sink){c->scheduler,c->job};
    uint64_t generation=0;
    assert(d2k_sched_synthesis_take(release_continuation,&generation)==c->expected && generation==9);
    assert(!c->job->synthesis_context && !c->job->synthesis_feedback);
    assert(d2k_sched_synthesis_retain(generation,c->expected,release_continuation,report_continuation)==1);
    g_progress_sink=(progress_sink){0};return NULL;
}
static void *foreign_thread(void *arg) {
    d2k_application_request request;
    (void)arg;assert(d2k_sched_application_request(&request)==0);
    assert(!request.search_id && !request.target[0]);return NULL;
}
int main(void) {
    {
        int sockets[2];
        assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sockets));
        d2k_catalog catalog = {0};
        d2k_sched *sched = d2k_sched_new(&catalog, sockets[0], 0x2d);
        assert(sched);
        for (size_t i = 0; i < 2; i++) {
            task *target = &sched->tasks[i];
            target->transport = 6; target->family = 4; target->port = 443;
            target->rx_volume_only = 1;
            snprintf(target->name, sizeof target->name, "snapshot-%zu.example", i);
            assert(launch_task(sched, target));
            assert(target->state == T_SHAPE_WAIT && target->shape_request_pending);
            assert(!target->th_live);
        }
        d2k_ev ack = {.kind=D2K_EV_ACK, .code=D2K_CMD_ARM_SHAPE, .num=256};
        d2k_sched_event(sched, &ack);
        assert(sched->tasks[0].shape_request_pending && sched->tasks[1].shape_request_pending);
        memcpy(ack.trial_id, sched->tasks[1].shape_request_id, 16);
        d2k_sched_event(sched, &ack);
        assert(sched->tasks[0].shape_request_pending && !sched->tasks[1].shape_request_pending);
        sched->tasks[1].shape_armed = 0;
        assert(launch_task(sched, &sched->tasks[1]));
        d2k_sched_event(sched, &ack);
        assert(sched->tasks[1].shape_request_pending);
        d2k_sched_vol_fn saved_volume = d2k_sched_vol_hook;
        d2k_sched_vol_hook = counted_volume;
        memcpy(ack.trial_id, sched->tasks[1].shape_request_id, 16);
        d2k_sched_event(sched, &ack);
        d2k_sched_tick(sched, 1);
        assert(sched->tasks[0].state == T_SHAPE_WAIT && !sched->tasks[0].th_live);
        assert(sched->tasks[1].th_live);
        sched->tasks[2].state = T_ASKING;
        sched->tasks[3].state = T_ASKING;
        d2k_sched_tick(sched, 2001);
        assert(sched->tasks[0].state == T_QUEUED && !sched->tasks[0].th_live);
        sched->tasks[2].state = T_FREE;
        sched->tasks[3].state = T_FREE;
        d2k_sched_free(sched);
        d2k_sched_vol_hook = saved_volume;
        d2k_catalog_free(&catalog);
        close(sockets[0]); close(sockets[1]);
    }
    {
        d2k_sched *sched = calloc(1, sizeof *sched);
        task *target = calloc(1, sizeof *target);
        assert(sched && target && !pthread_mutex_init(&sched->mu, NULL));
        d2k_sched_vol_fn saved = d2k_sched_vol_hook;
        d2k_sched_vol_hook = counted_volume;
        uint8_t bytes[5] = {0x16, 3, 3, 0, 0};
        d2k_hello hello = {.bytes=bytes, .len=sizeof bytes};
        target->port = 443;
        target->ask_base = target->ask_probes = 4;
        worker_volume(sched, target, hello);
        assert(target->ask_probes == 7);
        worker_volume(sched, target, hello);
        assert(target->ask_probes == 7);
        ask_settle(target, 2);
        assert(target->ask_probes == 9);
        d2k_sched_vol_path_fn saved_path = d2k_sched_vol_path_hook;
        d2k_sched_vol_path_hook = counted_volume_path;
        target->vol_done = 0;
        snprintf(target->measure_alt, sizeof target->measure_alt, "/observed");
        worker_volume(sched, target, hello);
        assert(target->ask_probes == 14);
        worker_volume(sched, target, hello);
        assert(target->ask_probes == 14);
        d2k_sched_vol_path_hook = saved_path;
        d2k_sched_vol_hook = saved;
        pthread_mutex_destroy(&sched->mu);
        free(target); free(sched);
    }
    {
        d2k_catalog catalog={0};
        assert(!bind_confirmed(&catalog,"box","old-plan","old","tls","target.example",
            "name",6,4,D2K_SHAPE_MODERN,0,D2K_VERBY_PROBE,D2K_INPUT_CLIENT,1,NULL,NULL,NULL));
        catalog.boxes[0].binds[0].budget=1;
        assert(!bind_confirmed(&catalog,"box","old-plan","old","tls","target.example",
            "name",6,4,D2K_SHAPE_MODERN,0,D2K_VERBY_PROBE,D2K_INPUT_PROFILE,2,NULL,NULL,NULL));
        assert(catalog.boxes[0].binds[0].input==D2K_INPUT_CLIENT);
        assert(catalog.boxes[0].binds[0].budget==1);
        assert(!bind_confirmed(&catalog,"box","new-plan","new","tls","target.example",
            "name",6,4,D2K_SHAPE_MODERN,0,D2K_VERBY_PROBE,D2K_INPUT_PROFILE,3,NULL,NULL,NULL));
        assert(catalog.boxes[0].binds[0].input==D2K_INPUT_PROFILE);
        assert(!catalog.boxes[0].binds[0].budget);
        assert(!bind_confirmed(&catalog,"box","new-plan","new","tls","target.example",
            "name",6,4,D2K_SHAPE_MODERN,0,0,0,4,NULL,NULL,NULL));
        assert(catalog.boxes[0].binds[0].input==D2K_INPUT_PROFILE);
        assert(catalog.boxes[0].binds[0].verified_by==D2K_VERBY_PROBE);
        assert(!bind_confirmed(&catalog,"box","third-plan","third","tls","target.example",
            "name",6,4,D2K_SHAPE_MODERN,0,0,0,5,NULL,NULL,NULL));
        assert(!catalog.boxes[0].binds[0].input && !catalog.boxes[0].binds[0].verified_by);
        d2k_catalog_free(&catalog);
    }
    d2k_application_request request;
    memset(&request,0xff,sizeof request);
    assert(d2k_sched_application_request(&request)==0 && !request.search_id);
    assert(d2k_sched_application_request(NULL)==-1);
    d2k_sched *s=calloc(1,sizeof *s);task *t=calloc(1,sizeof *t);assert(s && t);
    assert(!pthread_mutex_init(&s->mu,NULL));
    t->report_id=42;t->port=443;t->transport=6;t->family=4;t->asked_shape=D2K_SHAPE_MODERN;
    t->doh_failure_query=6;
    strcpy(t->name,"dns.example");strcpy(t->ip,"192.0.2.7");strcpy(t->doh_path,"/dns-query");
    g_progress_sink=(progress_sink){s,t};
    t->trig_snapped=1;
    assert(record_input(t)==D2K_INPUT_CLIENT);
    t->res.generated_input=1;
    assert(record_input(t)==D2K_INPUT_PROFILE);
    t->own_first=2;
    assert(record_input(t)==D2K_INPUT_TRANSFER);
    t->own_first=0;t->res.generated_input=0;t->trig_snapped=0;
    assert(record_input(t)==D2K_INPUT_PROFILE);
    assert(d2k_sched_application_request(&request)==1);
    assert(request.search_id==42 && request.doh && request.port==443);
    assert(request.doh_failure_query==6);
    assert(request.family==4 && request.transport==6 && request.shape==D2K_SHAPE_MODERN);
    assert(!strcmp(request.target,"dns.example") && !strcmp(request.resource,"/dns-query"));
    d2k_ev control={.family=4,.transport=6,.server_hello=1,
        .planned=D2K_LINK_PLANNED_NO,.num=32768,.flow_incarnation=19,
        .low_port=443,.high_port=50123};
    control.flow_epoch[0]=7;control.low_ip[0]=192;control.high_ip[0]=10;
    note_direct_control(s,&control,"control.example");
    assert(d2k_sched_application_request(&request)==1);
    assert(!strcmp(request.control.name,"control.example") && request.control.incarnation==19);
    assert(request.control.bytes==32768 && request.control.epoch[0]==7);
    control.planned=D2K_LINK_PLANNED_YES;
    note_direct_control(s,&control,"planned.example");
    control.planned=D2K_LINK_PLANNED_NO;control.flow_incarnation=0;
    note_direct_control(s,&control,"unowned.example");
    assert(d2k_sched_application_request(&request)==1 && !strcmp(request.control.name,"control.example"));
    t->family=6;assert(d2k_sched_application_request(&request)==1 && !request.control.name[0]);
    t->family=4;
    control.flow_incarnation=20;
    note_direct_control(s,&control,"dns.example");
    assert(d2k_sched_application_request(&request)==1 && !strcmp(request.control.name,"control.example"));
    control.num++;
    note_direct_control(s,&control,"dns.example");
    assert(d2k_sched_application_request(&request)==1 && !strcmp(request.control.name,"control.example"));
    control.family=6;control.flow_incarnation=21;
    note_direct_control(s,&control,"ipv6.example");
    assert(d2k_sched_application_request(&request)==1 && !strcmp(request.control.name,"control.example"));
    control.family=4;control.flow_incarnation=22;
    note_direct_control(s,&control,"new-control.example");
    assert(d2k_sched_application_request(&request)==1 && !strcmp(request.control.name,"new-control.example"));
    assert(d2k_sched_application_request(&request)==1);
    pthread_t thread;assert(!pthread_create(&thread,NULL,foreign_thread,NULL));
    assert(!pthread_join(thread,NULL));
    strcpy(t->doh_path,"/new-query");assert(!strcmp(request.resource,"/dns-query"));
    t->stop=1;assert(!d2k_sched_application_request(&request) && !request.search_id);
    t->stop=0;t->doh_path[0]=0;t->by_addr=1;t->transport=17;t->asked_shape=0;
    strcpy(t->measure_path,"/unrelated");
    assert(d2k_sched_application_request(&request)==1 && request.by_addr && request.transport==17);
    assert(!request.resource[0] && !request.doh);
    assert(!request.doh_failure_query);
    t->by_addr=0;t->transport=6;
    assert(d2k_sched_application_request(&request)==1 && !strcmp(request.resource,"/unrelated"));
    t->ech_offer=1;strcpy(t->ech_origin,"origin.example");
    assert(d2k_sched_application_request(&request)==1 && request.ech);
    assert(!strcmp(request.ech_origin,"origin.example"));
    strcpy(t->doh_path,"/dns-query");strcpy(t->plans[0],"candidate");
    t->trial_installed=1;t->synthesis_generation=9;t->next_plan=t->n_plans=1;
    t->trial_shape=D2K_SHAPE_MODERN;t->ver_ok=1;
    t->trial_ack_id[0]=2;t->synthesis_ver_trial_id[0]=2;t->ver_plan_id[0]=3;
    t->ver_flow.family=4;t->ver_flow.transport=6;t->ver_flow.a_port=50000;t->ver_flow.b_port=443;
    assert(inet_pton(AF_INET,t->ip,t->ver_flow.b_ip)==1);
    t->ver=(d2k_ver_result){.level=D2K_VER_APPLICATION,.status=0,.body_complete=0,
        .local_port=50000,.budget=D2K_BUDGET_CUT,.budget_need=50,.budget_packets=24,
        .budget_requests=5,.doh_replies=4};
    d2k_synthesis_feedback identity={.generation=9,.search_id=42,.target=t->name,.ip=t->ip,
        .resource=t->doh_path,.program=t->plans[0],.doh=1,.port=443,.family=4,.transport=6,
        .shape=D2K_SHAPE_MODERN};
    identity.plan_id[0]=3;
    t->synthesis_owner=d2k_verification_new(&identity,1);assert(t->synthesis_owner);
    assert(synthesis_report(s,t,0)==D2K_VF_NOT_MET);
    continuation c={.owner=d2k_verification_new(&identity,1)};assert(c.owner);
    assert(d2k_sched_synthesis_retain(9,&c,release_continuation,report_continuation)==1);
    assert(d2k_sched_synthesis_retain(9,&c,release_continuation,report_continuation)==0);
    assert(synthesis_report(s,t,1)==D2K_VF_NOT_MET && c.calls==1 && t->synthesis_resume_pending==1);
    t->synthesis_resume_pending=0;
    assert(synthesis_report(s,t,1)==D2K_VF_NOT_MET && c.calls==2 && !t->synthesis_resume_pending);
    resume_context resumption={s,t,&c};
    assert(!pthread_create(&thread,NULL,resumed_worker,&resumption));
    assert(!pthread_join(thread,NULL));
    assert(t->synthesis_context==&c && !c.released);
    strcpy(t->doh_path,"/changed-query");
    uint64_t generation=99;
    assert(!d2k_sched_synthesis_take(release_continuation,&generation) && !generation);
    assert(c.released==1 && !t->synthesis_context && !t->synthesis_feedback);
    d2k_verification_free(c.owner);
    uint8_t hello[4096];size_t hello_length=0;
    assert(!d2k_hello_from_profile(D2K_SHAPE_MODERN,"dns.example",hello,sizeof hello,&hello_length));
    d2k_hello trigger={.bytes=hello,.len=hello_length};
    assert(!pipe(s->wake));s->measure_mark=0x2f;t->ech_offer=0;
    d2k_sched_application_synthesis_hook=route_application;
    assert(worker_doh_synthesis(s,t,trigger)==1 && application_calls==1 && t->res_ready && t->res.owns_search);
    t->vol.rx_cut=1;t->doh_trial=1;
    verdict_to_plans(s,t,&t->res);
    assert(t->doh_synthesis_owned && !t->n_plans);
    application_closed=1;t->res_ready=0;
    assert(worker_doh_synthesis(s,t,trigger)==0 && application_calls==2 && !t->res_ready);
    t->ech_offer=1;
    assert(!worker_doh_synthesis(s,t,trigger) && application_calls==2);t->ech_offer=0;
    t->doh_failure_query=0;
    assert(!worker_doh_synthesis(s,t,trigger) && application_calls==2);
    char wake;assert(read(s->wake[0],&wake,1)==1);
    application_closed=0;t->doh_failure_query=6;t->doh_checked=1;
    t->own_first=1;t->rx_volume_only=1;t->family_reuse=1;t->job=JOB_CLASSIFY;t->res_ready=0;
    d2k_sched_tcp_fn saved_base=d2k_sched_tcp_base_hook;d2k_sched_tcp_base_hook=forbidden_tcp_base;
    worker_arg *worker=calloc(1,sizeof *worker);assert(worker);
    worker->s=s;worker->t=t;worker->trig_len=hello_length;memcpy(worker->trig,hello,hello_length);
    assert(!pthread_create(&thread,NULL,worker_run,worker));
    assert(!pthread_join(thread,NULL));
    free(worker);
    assert(read(s->wake[0],&wake,1)==1);
    assert(application_calls==3 && t->res_ready && t->doh_synthesis_owned && t->res.owns_search);
    assert(t->vol.rx_cut && !t->n_plans);
    d2k_sched_tcp_base_hook=saved_base;
    application_direct=1;
    for(int variant=0;variant<7;variant++) {
        direct_result=(d2k_ver_result){.fd=-1,.level=D2K_VER_APPLICATION,.status=200,
            .body_complete=1,.peer_authenticated=1,
            .doh_replies=20,.budget_requests=20,.budget=D2K_BUDGET_PASSED};
        if(variant==1)direct_result.budget=D2K_BUDGET_CUT;
        if(variant==2)direct_result.local_refusal=1;
        if(variant==3)direct_result.doh_replies=0;
        if(variant==4)direct_result.status=503;
        if(variant==5)direct_result.peer_authenticated=0;
        if(variant==6)direct_result.doh_replies=direct_result.budget_requests=19;
        t->res_ready=0;t->doh_trial=1;t->vol.rx_cut=1;
        assert(worker_doh_synthesis(s,t,trigger)==1 && t->res_ready);
        assert(direct_checks==variant+1 && t->res.probes==3);
        assert(t->res.verdict==(variant?D2K_V_INCONCLUSIVE:D2K_V_CLEAR));
        if(!variant)assert(!t->doh_trial && !t->vol.rx_cut && t->vol.rx_direct_complete);
        else assert(t->doh_trial && t->vol.rx_cut && !t->vol.rx_direct_complete);
        assert(read(s->wake[0],&wake,1)==1);
    }
    deeper_script=1;direct_checks=application_calls=0;
    direct_result=(d2k_ver_result){.fd=-1,.level=D2K_VER_APPLICATION,.status=0,
        .peer_authenticated=1,.doh_replies=8,.budget_requests=9,.budget_packets=24,.budget=D2K_BUDGET_CUT};
    assert(worker_doh_synthesis(s,t,trigger)==1);
    assert(direct_checks==2 && application_calls==2 && last_horizon==9 && t->doh_failure_query==9);
    assert(t->res.verdict==D2K_V_CLEAR && t->res.probes==6);
    assert(read(s->wake[0],&wake,1)==1);
    for(int variant=0;variant<4;variant++) {
        direct_checks=application_calls=0;t->doh_failure_query=6;
        direct_result=(d2k_ver_result){.fd=-1,.level=D2K_VER_APPLICATION,.status=0,
            .peer_authenticated=1,.doh_replies=8,.budget_requests=9,.budget_packets=24,.budget=D2K_BUDGET_CUT};
        if(variant==0){direct_result.budget_requests=6;direct_result.doh_replies=5;}
        if(variant==1)direct_result.doh_replies=7;
        if(variant==2)direct_result.local_refusal=1;
        if(variant==3)direct_result.peer_authenticated=0;
        assert(worker_doh_synthesis(s,t,trigger)==1);
        assert(direct_checks==1 && application_calls==1 && last_horizon==6 && t->doh_failure_query==6);
        assert(t->res.verdict==D2K_V_INCONCLUSIVE && t->res.probes==3);
        assert(read(s->wake[0],&wake,1)==1);
    }
    d2k_sched_application_synthesis_hook=NULL;close(s->wake[0]);close(s->wake[1]);
    d2k_verification_free(t->synthesis_owner);t->synthesis_owner=NULL;
    g_progress_sink=(progress_sink){0};assert(!pthread_mutex_destroy(&s->mu));free(t);free(s);
    return 0;
}
