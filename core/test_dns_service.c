/* Native confirmation sink and real catalog sync, without network. */
#define _POSIX_C_SOURCE 200809L
#define d2k_link_set_endpoint dns_install
#define d2k_link_del_name_family dns_remove_name
#define d2k_link_del_endpoint dns_remove_endpoint
#include "sched.c"
#include "test_task_slots.h"
#include <assert.h>
static unsigned installs,deletes,endpoint_deletes;
static uint8_t installed[2][16];
int dns_install(int fd,const uint8_t *ip,uint8_t family,uint16_t port,uint8_t shape,
    const char *plan,char *err,size_t cap) {
    (void)fd;(void)plan;(void)err;(void)cap;
    assert(family==4 && ntohs(port)==8443 && shape==D2K_SHAPE_MODERN);
    assert(installs<2);memcpy(installed[installs++],ip,4);return 0;
}
int dns_remove_name(int fd,const char *name,uint8_t transport,uint8_t shape,uint8_t family,char *e,size_t cap) {
    (void)fd;(void)e;(void)cap;assert(!strcmp(name,"resolver.test") && transport==6 && family==4);
    assert(shape==D2K_SHAPE_MODERN);deletes++;return 0;
}
int dns_remove_endpoint(int fd,const uint8_t *ip,uint8_t family,uint16_t port,uint8_t shape,char *e,size_t cap) {
    (void)fd;(void)e;(void)cap;uint8_t expected[4];assert(inet_pton(AF_INET,"192.0.2.51",expected)==1);
    assert(family==4 && !memcmp(ip,expected,4) && ntohs(port)==8443 && shape==D2K_SHAPE_MODERN);
    endpoint_deletes++;return 0;
}
static task *prepare(d2k_sched *s,unsigned slot,const char *ip,unsigned byte) {
    task *t=test_task_at(s, slot);task_reset(s,t);t->state=T_VERIFY_WAIT;
    strcpy(t->name,"resolver.test");strcpy(t->ip,ip);t->family=4;t->transport=6;t->port=8443;
    strcpy(t->doh_path,"/private-query?account=fixture");strcpy(t->measure_path,t->doh_path);
    snprintf(t->plans[0],sizeof t->plans[0],"d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\npayload 1 %02x\npoison 1 badsum\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\n",byte);
    t->n_plans=t->next_plan=1;t->ver_ok=1;t->ver.level=D2K_VER_APPLICATION;
    t->ver.body_complete=1;t->ver.doh_replies=20;t->ver.budget=D2K_BUDGET_PASSED;
    t->ver.peer_authenticated=1;
    t->ver.doh_http_version=2;
    t->group_block_proven=1;return t;
}
static void colliding_service_routes(void) {
    d2k_catalog c={0};d2k_sched *s=d2k_sched_new(&c,-1,0x2e);assert(s);
    for(unsigned i=0;i<2;i++) {
        task *t=prepare(s,i,"192.0.2.51",i+4);
        snprintf(t->name,sizeof t->name,"resolver%u.test",i);
        snprintf(t->box_id,sizeof t->box_id,"box-collision-%u",i);
        verify_confirm(s,t,1000+i*1000);
    }
    s->n_doh=2;
    for(unsigned i=0;i<2;i++) {
        doh_target *d=s->doh+i;snprintf(d->host,sizeof d->host,"resolver%u.test",i);
        strcpy(d->ip,"192.0.2.51");d->port=8443;strcpy(d->path,"/private-query?account=fixture");
    }
    assert(newer_target_binding(&c,c.boxes[0].binds));
    assert(!dns_saved_route(s,s->doh) && dns_saved_route(s,s->doh+1));
    char plan[40];
    assert(!own_first_plans(s,test_task_at(s, 0),0) && own_first_plans(s,test_task_at(s, 1),0)==1);
    assert(!bound_plan_here(s,test_task_at(s, 0),D2K_SHAPE_MODERN,plan));
    assert(bound_plan_here(s,test_task_at(s, 1),D2K_SHAPE_MODERN,plan));
    char file[]="/tmp/d2k-dns-collision-XXXXXX";int fd=mkstemp(file);assert(fd>=0);close(fd);
    assert(!d2k_sched_dns_routes(s,file));unlink(file);
    d2k_sched_free(s);d2k_catalog_free(&c);
}
static void dot_keeps_service_identity(void) {
    d2k_catalog c={0};d2k_sched *s=d2k_sched_new(&c,-1,0x2e);assert(s);
    task *t=prepare(s,0,"192.0.2.51",1);
    t->dns_dot=1;t->ver.doh_http_version=0;t->doh_path[0]=0;t->measure_path[0]=0;
    verify_confirm(s,t,1000);
    assert(d2k_sched_dns_save_pending(s,0));
    char file[]="/tmp/d2k-dot-proof-XXXXXX",error[160];
    int fd=mkstemp(file);assert(fd>=0);close(fd);
    assert(!d2k_catalog_save_atomic(&c,file,error,sizeof error));
    d2k_catalog loaded={0};
    assert(!d2k_catalog_load(file,&loaded,error,sizeof error));
    d2k_sched *again=d2k_sched_new(&loaded,-1,0x2e);assert(again);
    doh_target target={.host="resolver.test",.ip="192.0.2.51",.port=8443,.dot=1};
    assert(dns_saved_route(again,&target));
    target.dot=0;
    assert(!dns_saved_route(again,&target));
    strcpy(target.path,"/dns-query");
    assert(!dns_saved_route(again,&target));
    unlink(file);
    d2k_sched_free(again);d2k_catalog_free(&loaded);
    d2k_sched_free(s);d2k_catalog_free(&c);
}
int main(void) {
    colliding_service_routes();
    dot_keeps_service_identity();
    d2k_catalog c={0};d2k_sched *s=d2k_sched_new(&c,-1,0x2e);assert(s);
    s->clock_seen=1;s->wall_base_s=1700000000;s->now_ms=1000;
    task *a=prepare(s,0,"192.0.2.51",1),*b=prepare(s,1,"192.0.2.52",2);
    /* Real prior name knowledge must be retained but cease shadowing IP keys. */
    assert(!bind_confirmed(&c,"legacy","legacy-plan",a->plans[0],"tls","resolver.test","name",
        6,4,D2K_SHAPE_MODERN,0,D2K_VERBY_PROBE,D2K_INPUT_PROFILE,1,NULL,NULL,NULL));
    assert(!d2k_sched_dns_save_pending(s,0));
    verify_confirm(s,a,1000);
    assert(d2k_sched_dns_save_pending(s,0));
    char file[]="/tmp/d2k-dns-service-XXXXXX",err[200];
    int fd=mkstemp(file);assert(fd>=0);close(fd);
    assert(!d2k_catalog_save_atomic(&c,file,err,sizeof err));
    uint64_t first_saved=c.revision;
    assert(!d2k_sched_dns_save_pending(s,first_saved));
    verify_confirm(s,b,1001);
    assert(d2k_sched_dns_save_pending(s,first_saved));
    assert(!d2k_sched_dns_save_pending(s,c.revision));
    size_t services=0,active_names=0;char ids[2][40]={{0}};
    for(size_t i=0;i<c.n_boxes;i++)for(size_t j=0;j<c.boxes[i].n_binds;j++) {
        d2k_cat_binding *x=c.boxes[i].binds+j;
        if(!strcmp(x->kind,"name") && x->enabled && !x->recheck_since)active_names++;
        if(!strcmp(x->kind,"service")) {
            assert(services<2);strcpy(ids[services++],x->plan_id);
            assert(x->server_port==8443 && x->dns_port==8443 && x->dns_authenticated &&
                x->budget==D2K_CAT_BUDGET_PASSED);
            char expected[40];uint8_t wire_id[16];
            plan_ident(!strcmp(x->target,"192.0.2.51")?a->plans[0]:b->plans[0],expected,sizeof expected,wire_id);
            assert(!strcmp(x->plan_id,expected) && !strcmp(x->dns_name,"resolver.test"));
            assert(!strcmp(x->target,x->dns_address) && !strcmp(x->probe_path,a->doh_path));
        }
    }
    if(services!=2){fprintf(stderr,"DNS promotions retained %zu exact services, expected2\n",services);return 1;}
    assert(!active_names);assert(strcmp(ids[0],ids[1]));assert(deletes==1);
    for(unsigned mode=0;mode<6;mode++) {
        task *unproven=prepare(s,2,"192.0.2.99",3);
        if(mode==0)unproven->ver_ok=0;
        if(mode==1)unproven->ver.doh_replies=19;
        if(mode==2)unproven->ver.budget=D2K_BUDGET_CUT;
        if(mode==3)unproven->ver.body_complete=0;
        if(mode==4)unproven->ver.peer_authenticated=0;
        if(mode==5)unproven->dns_expected_http=1;
        uint64_t before=c.revision;verify_confirm(s,unproven,1002);
        assert(c.revision==before && unproven->state==T_PLANNING);task_done(s,unproven);
    }

    assert(!c.groups || !c.groups->n_observations);
    char bound[40];
    assert(own_first_plans(s,a,0)==1 && bound_plan_here(s,a,D2K_SHAPE_MODERN,bound));
    assert(!strcmp(bound,ids[0]) || !strcmp(bound,ids[1]));
    a->port++;assert(!own_first_plans(s,a,0) && !bound_plan_here(s,a,D2K_SHAPE_MODERN,bound));a->port--;

    assert(!d2k_sched_sync(s));while(s->sync_active)d2k_sched_sync_step(s);
    assert(installs==2 && memcmp(installed[0],installed[1],4));
    assert(!d2k_catalog_save_atomic(&c,file,err,sizeof err));d2k_catalog restored={0};
    assert(!d2k_catalog_load(file,&restored,err,sizeof err));
    d2k_sched *again=d2k_sched_new(&restored,-1,0x2e);assert(again);
    const char *config="upstream https://resolver.test:8443/private-query?account=fixture\n";
    FILE *f=fopen(file,"w");assert(f);assert(fputs(config,f)>=0);assert(!fclose(f));
    assert(d2k_sched_doh_discover(again,file,NULL)==2);
    assert(d2k_sched_dns_routes(again,file)==2);
    d2k_cat_binding *legacy_service=NULL;
    for(size_t i=0;i<restored.n_boxes;i++)for(size_t j=0;j<restored.boxes[i].n_binds;j++) {
        d2k_cat_binding *binding=restored.boxes[i].binds+j;
        if(binding->dns_authenticated)legacy_service=binding;
    }
    assert(legacy_service);
    legacy_service->dns_authenticated=0;
    assert(d2k_sched_dns_routes(again,file)==1);
    installs=0;assert(!d2k_sched_sync(again));while(again->sync_active)d2k_sched_sync_step(again);
    assert(installs==1); /* An older catalog claim is data, not permission. */
    legacy_service->dns_authenticated=1;
    for(size_t i=0;i<again->n_doh;i++) {
        doh_target *d=again->doh+i;assert(dns_saved_route(again,d));
        d->http_version=1;assert(!dns_saved_route(again,d));
        d->http_version=2;assert(dns_saved_route(again,d));d->http_version=0;
        d->port++;assert(!dns_saved_route(again,d));d->port--;
        char saved[sizeof d->host];strcpy(saved,d->host);strcpy(d->host,"other.test");
        assert(!dns_saved_route(again,d));strcpy(d->host,saved);
        strcat(d->path,"x");assert(!dns_saved_route(again,d));d->path[strlen(d->path)-1]=0;
    }
    installs=0;assert(!d2k_sched_sync(again));while(again->sync_active)d2k_sched_sync_step(again);
    assert(installs==2);
    task *direct=prepare(again,0,"192.0.2.51",1);
    uint64_t before_retirement=restored.revision;
    forget_clear_target_bindings(again,direct,2000);
    assert(d2k_sched_dns_save_pending(again,before_retirement));
    assert(endpoint_deletes==1);
    for(size_t i=0;i<again->n_doh;i++)
        assert(dns_saved_route(again,again->doh+i)==(strcmp(again->doh[i].ip,"192.0.2.51")!=0));
    d2k_sched_free(again);d2k_catalog_free(&restored);d2k_sched_free(s);d2k_catalog_free(&c);unlink(file);
    puts("DNS service: two independent promotions, retired legacy shadow, exact sync and durable endpoint proofs PASS");return 0;
}
