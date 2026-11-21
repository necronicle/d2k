/* Offline forced admission and continuation policy: no sockets or workers. */
#define pthread_create force_thread_create
#include "sched.c"
#include "test_task_slots.h"
#undef pthread_create
int force_thread_create(pthread_t *t,const pthread_attr_t *a,void *(*f)(void *),void *v) {
    (void)t;(void)a;(void)f;(void)v;return EAGAIN;
}
static int fails;
#define CHECK(x) do { if(!(x)){fprintf(stderr,"force:%d: %s\n",__LINE__,#x);fails++;} }while(0)
static void config(d2k_sched *s,const char *body,int expected) {
    char p[]="/tmp/d2k-force-XXXXXX";int fd=mkstemp(p);CHECK(fd>=0);
    CHECK(write(fd,body,strlen(body))==(ssize_t)strlen(body));close(fd);
    CHECK(d2k_sched_force_load(s,p)==expected);unlink(p);
}
static d2k_ev event(const char *name) {
    d2k_ev e={0};e.kind=D2K_EV_HELLO;e.transport=6;e.family=4;
    e.low_port=443;e.high_port=41000;
    inet_pton(AF_INET,"192.0.2.53",e.low_ip);
    inet_pton(AF_INET,"192.0.2.1",e.high_ip);
    snprintf(e.name,sizeof e.name,"%s",name);return e;
}
int main(void) {
    d2k_catalog c={0};d2k_sched *s=d2k_sched_new(&c,-1,0x2d);CHECK(s);if(!s)return 1;
    s->now_ms=1000;s->clock_seen=1;s->meas_limit=0;
    config(s," # owner\ngateway.example.test # DoH\n",1);
    CHECK(force_name(s,"gateway.example.test"));
    CHECK(force_name(s,"TENANT.GATEWAY.EXAMPLE.TEST."));
    CHECK(!force_name(s,"evilgateway.example.test"));
    CHECK(!force_name(s,"gateway.example.test.evil"));
    config(s,"invalid..name\n",-1);
    config(s,"-invalid.example\n",-1);
    config(s,"invalid-.example\n",-1);
    CHECK(force_name(s,"gateway.example.test")); /* atomic failed reload */
    d2k_ev e=event("ordinary.example");d2k_sched_event(s,&e);
    CHECK(!task_of(s,e.name,6,4));
    e=event("tenant.gateway.example.test");e.client_shape=D2K_SHAPE_MODERN;d2k_sched_event(s,&e);
    task *t=task_of(s,e.name,6,4);CHECK(t && t->state==T_QUEUED);
    if(t) {
        CHECK(t->trigger_shape==D2K_SHAPE_MODERN);
        CHECK(t->trigger_code==0); /* explicit policy, not invented suspicion */
        s->cooldowns[0].used=1;strcpy(s->cooldowns[0].name,e.name);
        s->cooldowns[0].transport=6;s->cooldowns[0].family=4;
        s->cooldowns[0].until_ms=999999;s->cooldowns[0].exhausted=1;
        CHECK(!cooldown_blocks(s,e.name,6,4,0,NULL));
        strcpy(s->cooldowns[1].name,"ordinary.example");s->cooldowns[1]=s->cooldowns[0];
        strcpy(s->cooldowns[1].name,"ordinary.example");
        CHECK(cooldown_blocks(s,"ordinary.example",6,4,0,NULL));
        task *q=test_task_at(s, 1);task_reset(s,q);strcpy(q->name,"ordinary.example");
        q->transport=6;q->family=4;q->state=T_QUEUED;q->queued_ms=1;
        CHECK(queued_pick(s)==t);
        t->state=T_RESTING;t->rest_until_ms=999999;
        t->tried[0]=12345;t->n_tried=1;t->doh_failure_query=2;
        t->vol.rx_cut=1;
        force_tick(s);
        t=task_of(s,e.name,6,4);
        CHECK(t && t->state==T_QUEUED && t->n_tried==1 && t->tried[0]==12345);
        CHECK(t && t->doh_failure_query==2 && t->vol.rx_cut);
        task_reset(s,q);task_reset(s,t);
    }
    /* Client suspicion does not start a configured DNS recovery search. */
    e=event("tenant.gateway.example.test");d2k_sched_event(s,&e);
    t=task_of(s,"tenant.gateway.example.test",6,4);
    if(t) {
        t->state=T_WATCHING;strcpy(t->doh_path,"/dns-query");
        CHECK(!fill_hellos(s,t));
        e=event(t->name);e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;
        e.planned=D2K_LINK_PLANNED_NO;
        on_suspect_as(s,&e,t->name,0);
        CHECK(t->job!=JOB_DOH_HEALTH && t->state==T_WATCHING);
        t->state=T_QUEUED;
    }
    /* Packet counters are optional for a repeatable protocol query cut. */
    d2k_ver_result cut={0};cut.level=D2K_VER_HANDSHAKE;cut.status=0;
    cut.doh_replies=1;cut.budget_requests=2;cut.budget=D2K_BUDGET_CUT;
    cut.budget_uncountable=1;
    CHECK(doh_measured_cut(&cut));
    cut.doh_replies=0;CHECK(!doh_measured_cut(&cut));
    /* An unnamed connection to an observed address admits the known service,
       without assigning that service name to the client's flow. */
    e=event("");e.kind=D2K_EV_FLOW;d2k_sched_event(s,&e);
    CHECK(task_of(s,"tenant.gateway.example.test",6,4));
    /* A second known address is its own measured endpoint. */
    e=event("tenant.gateway.example.test");
    inet_pton(AF_INET,"162.159.36.5",e.low_ip);d2k_sched_event(s,&e);
    unsigned endpoints=0;
    for(size_t i=0;i<s->task_count;i++)
        if(s->tasks[i]->state==T_QUEUED && force_name(s,s->tasks[i]->name))endpoints++;
    CHECK(endpoints==2);
    task *first=task_of(s,"tenant.gateway.example.test",6,4);
    if(first) { first->state=T_WATCHING;strcpy(first->doh_path,"/dns-query"); }
    e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.planned=D2K_LINK_PLANNED_YES;
    on_suspect_as(s,&e,e.name,0);
    endpoints=0;
    for(size_t i=0;i<s->task_count;i++)
        if(s->tasks[i]->state!=T_FREE && force_name(s,s->tasks[i]->name))endpoints++;
    CHECK(endpoints==2 && first && first->state==T_WATCHING);
    for(size_t i=0;i<s->task_count;i++)task_reset(s,s->tasks[i]);
    /* A cold watcher remains idle until the Keenetic journal reports failure. */
    const char *host="tenant.gateway.example.test";
    CHECK(!bind_confirmed(&c,"force-box","force-plan","tcp split pos=1","tls",
        host,"name",6,4,D2K_SHAPE_MODERN,0,D2K_VERBY_PROBE,D2K_INPUT_PROFILE,100,NULL,NULL,NULL));
    s->n_doh=1;strcpy(s->doh[0].host,host);strcpy(s->doh[0].path,"/dns-query");
    strcpy(s->doh[0].ip,"192.0.2.53");s->doh[0].port=443;
    s->n_forced=1;
    force_tick(s);t=task_of(s,host,6,4);
    CHECK(!t);
    CHECK(d2k_sched_dns_journal_error(s,host)==0); /* durable solution */
    CHECK(!task_of(s,host,6,4));
    s->n_force=0;d2k_sched_free(s);d2k_catalog_free(&c);
    return fails?1:0;
}
