#define _POSIX_C_SOURCE 200809L
#include "sched.c"
#include <poll.h>
static int fails;
#define CHECK(c,m) do {if(!(c)){fprintf(stderr,"FAIL: %s\n",m);fails++;}}while(0)
static int mark_ok(int fd,uint32_t m){(void)fd;return m==0x2e?0:-1;}
static void catalog(d2k_catalog *c,int family) {
    c->n_boxes=1;c->boxes=calloc(1,sizeof *c->boxes);
    d2k_cat_box *b=c->boxes;b->n_plans=b->n_binds=1;
    b->plans=calloc(1,sizeof *b->plans);b->binds=calloc(1,sizeof *b->binds);
    d2k_cat_plan *p=b->plans;strcpy(p->id,"own-stun");strcpy(p->proto,"voice");p->enabled=1;
    p->text=strdup("d2k-plan 1 1\nid 00000000000000000000000000000000\nproto udp voice\npayload 1 00\npoison 1 badsum\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\n");
    d2k_cat_binding *bd=b->binds;strcpy(bd->kind,"service");strcpy(bd->target,family==4?"127.0.0.1":"::1");
    strcpy(bd->plan_id,p->id);bd->family=(uint8_t)family;bd->server_port=39478;bd->transport=17;
    bd->shape=D2K_LINK_SHAPE_VOICE;bd->level=3;bd->enabled=1;bd->confirmed=100;bd->verified_by=D2K_VERBY_STUN;
}
static task *baseline(d2k_sched *s,int family,d2k_stun_probe_status status){
    task *t=&s->tasks[0];t->state=T_STUN_MEASURE;t->stun_target=1;t->by_addr=1;
    t->family=(uint8_t)family;t->transport=17;t->port=39478;
    strcpy(t->ip,family==4?"127.0.0.1":"::1");snprintf(t->name,sizeof t->name,"stun/[%s]:%u",t->ip,t->port);
    t->stun_res.status=status;t->stun_res.sent=status!=D2K_STUN_LOCAL_ERROR;
    t->stun_res.marked=1;t->stun_res.mapped_family=status==D2K_STUN_BINDING_OK?4:0;
    return t;
}
static void run(int family,int mode){
    int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"control pair");
    d2k_catalog c={0};catalog(&c,family);d2k_cat_binding *bd=c.boxes[0].binds;
    if(mode==4)bd->server_port++;
    if(mode==5)bd->family=family==4?6:4;
    if(mode==6)bd->shape=D2K_LINK_SHAPE_QUIC;
    if(mode==7)bd->level=2;
    if(mode==8)strcpy(bd->kind,"addr");
    if(mode==9)bd->verified_by=D2K_VERBY_CLIENT;
    if(mode==12 && family==6)strcpy(bd->target,"0:0:0:0:0:0:0:1");
    if(mode==10)strcpy(c.boxes[0].plans[0].proto,"quic");
    if(mode==11){char *v=strstr(c.boxes[0].plans[0].text,"udp voice");memcpy(v,"udp quic ",9);}
    d2k_sched *s=d2k_sched_new(&c,sv[0],0x2e);CHECK(s!=NULL,"scheduler");
    if(!s)return;
    task *t=baseline(s,family,mode<4?(d2k_stun_probe_status)mode:D2K_STUN_TIMEOUT);
    stun_finish(s,t,100);
    struct pollfd q={sv[1],POLLIN,0};int pending=poll(&q,1,0)>0;
    CHECK(pending==(mode==D2K_STUN_TIMEOUT||mode==12),"only inconclusive timeout with relevant own service plan starts exact trial");
    CHECK(d2k_sched_active(s)==((mode==D2K_STUN_TIMEOUT||mode==12)?1:0),"candidate participates in scheduler admission");
    CHECK(c.revision==0 && bd->confirmed==100,"fresh probe cannot promote or revoke application binding");
    d2k_ev cleanup={0};cleanup.kind=D2K_EV_ACK;cleanup.code=D2K_CMD_DEL_ADDR_PROBE;cleanup.num=0x100;
    memcpy(cleanup.trial_id,t->stun_trial_id,16);
    d2k_sched_free(s);d2k_stun_trial_reap(&cleanup);
    d2k_catalog_free(&c);close(sv[0]);close(sv[1]);
}
static char messages[8192];
static int worker_calls, worker_mode;
static d2k_stun_probe_status worker_status;
static void collect(void *ctx,const char *line){
    (void)ctx;size_t n=strlen(messages);snprintf(messages+n,sizeof messages-n,"%s\n",line);
}
static d2k_stun_probe_res run_probe(d2k_stun_socket *socket){
    CHECK(socket!=NULL,"worker receives borrowed reserved socket");worker_calls++;
    d2k_stun_probe_res r={0};r.status=worker_status;r.sent=r.marked=1;
    r.mapped_family=worker_status==D2K_STUN_BINDING_OK?4:0;
    if(worker_mode==18)r.marked=0;
    if(worker_mode==19)r.sent=0;
    if(worker_mode==20)r.mapped_family=0;
    return r;
}
static d2k_ev applied(task *t){
    d2k_ev e={0};const d2k_stun_flow *f=d2k_stun_trial_flow(t->stun_trial);
    e.kind=D2K_EV_APPLIED;e.family=f->family;e.transport=17;
    memcpy(e.low_ip,f->source,16);memcpy(e.high_ip,f->destination,16);
    e.low_port=ntohs(f->source_port_be);e.high_port=ntohs(f->destination_port_be);
    memcpy(e.trial_id,t->stun_trial_id,16);memcpy(e.plan_id,t->stun_plan_id,16);
    e.execution_id=91;e.execution_binding.generation=3;e.execution_binding.epoch[0]=4;
    e.execution_binding.kind=D2K_BIND_FLOW;e.execution_binding.temporary=1;
    e.execution_binding.family=f->family;e.execution_binding.shape=D2K_LINK_SHAPE_VOICE;
    return e;
}
static void experiment(int family,int mode){
    int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"experiment control pair");
    d2k_catalog c={0};catalog(&c,family);d2k_sched *s=d2k_sched_new(&c,sv[0],0x2e);
    if(!s){fails++;return;}messages[0]=0;worker_calls=0;worker_mode=mode;
    worker_status=mode==9?D2K_STUN_TIMEOUT:D2K_STUN_BINDING_OK;
    d2k_sched_set_say(s,collect,NULL);task *t=baseline(s,family,D2K_STUN_TIMEOUT);
    stun_finish(s,t,100);CHECK(t->stun_trial!=NULL,"candidate owns reserved socket");
    if(!t->stun_trial){d2k_sched_free(s);d2k_catalog_free(&c);close(sv[0]);close(sv[1]);return;}
    d2k_ev e=applied(t),ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_SET_ADDR_PROBE;ack.num=0x100;
    memcpy(ack.trial_id,t->stun_trial_id,16);
    d2k_ev cleanup=ack;cleanup.code=D2K_CMD_DEL_ADDR_PROBE;
    ack.trial_id[0]^=1;d2k_sched_event(s,&ack);d2k_sched_tick(s,101);
    CHECK(worker_calls==0 && t->state==T_STUN_ACK,"foreign ACK never authorizes payload");
    ack.trial_id[0]^=1;
    if(mode==11){d2k_sched_tick(s,100+SCHED_VERIFY_STEP_MS);}
    else {
        if(mode==12)ack.num=D2K_ACK_BAD_PLAN;
        d2k_sched_event(s,&ack);d2k_sched_tick(s,102);
        if(mode==12)CHECK(worker_calls==0 && t->state==T_FREE,"install NAK causes no network probe");
        else if(mode==13){task_done(s,t);}
        else {
            CHECK(t->state==T_STUN_PROBE,"own ACK starts asynchronous candidate worker");
            join_worker(t);
            CHECK(worker_calls==1,"one candidate transaction on owned socket");
            if(mode==2)e.low_port++;
            if(mode==3)e.trial_id[0]^=1;
            if(mode==4)e.plan_id[0]^=1;
            if(mode==5)e.execution_binding.generation=0;
            if(mode==6)memset(e.execution_binding.epoch,0,16);
            if(mode==7)e.execution_binding.shape=D2K_LINK_SHAPE_QUIC;
            if(mode==8)e.kind=D2K_EV_REFUSED;
            if(mode==14)e.family=family==4?6:4;
            if(mode==15)e.transport=6;
            if(mode==16)e.execution_binding.temporary=0;
            if(mode==17)e.execution_id=0;
            if(mode!=1)d2k_sched_event(s,&e);
            if(mode==10){e.execution_binding.generation++;d2k_sched_event(s,&e);}
            d2k_sched_tick(s,103);
            if(mode==1){
                CHECK(t->state==T_STUN_PROOF,"Binding response alone cannot confirm candidate");
                /* Reverse canonical endpoint order is still the same exact flow. */
                uint8_t tmp[16];memcpy(tmp,e.low_ip,16);memcpy(e.low_ip,e.high_ip,16);memcpy(e.high_ip,tmp,16);
                uint16_t port=e.low_port;e.low_port=e.high_port;e.high_port=port;
                d2k_sched_event(s,&e);d2k_sched_tick(s,104);
            }
            if(t->state==T_STUN_PROOF)d2k_sched_tick(s,103+SCHED_VERIFY_STEP_MS);
        }
    }
    CHECK(t->state==T_FREE && d2k_sched_active(s)==0,"completion or abort releases measurement slot");
    CHECK((strstr(messages,"корректный Binding-ответ и исполнение")!=NULL)==(mode==0||mode==1),
          "only exact execution plus strict response proves candidate Binding exchange");
    CHECK(c.revision==0 && c.boxes[0].binds[0].confirmed==100,"candidate never rewrites application evidence");
    d2k_sched_event(s,&cleanup);
    CHECK(d2k_stun_trial_pending()==0,"own removal ACK releases deferred trial");
    d2k_sched_free(s);d2k_catalog_free(&c);close(sv[0]);close(sv[1]);
}
static void measured_followup(int mode){
    int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"followup control pair");
    d2k_catalog c={0};catalog(&c,4);
    d2k_sched *s=d2k_sched_new(&c,sv[0],0x2e);
    if(!s){fails++;close(sv[0]);close(sv[1]);d2k_catalog_free(&c);return;}
    task *t=baseline(s,4,D2K_STUN_TIMEOUT);
    static const uint8_t request[20]={0,1,0,0,0x21,0x12,0xa4,0x42,1};
    memcpy(t->stun_res.request,request,sizeof request);
    t->stun_res.request_length=sizeof request;
    worker_calls=0;worker_mode=0;worker_status=D2K_STUN_TIMEOUT;
    stun_finish(s,t,100);
    CHECK(t->stun_trial!=NULL,"measured direct timeout starts own service trial");
    if(!t->stun_trial)goto cleanup;
    d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_SET_ADDR_PROBE;ack.num=0x100;
    memcpy(ack.trial_id,t->stun_trial_id,16);
    d2k_ev retired=ack;retired.code=D2K_CMD_DEL_ADDR_PROBE;
    d2k_sched_event(s,&ack);d2k_sched_tick(s,101);join_worker(t);
    d2k_ev e=applied(t);
    d2k_sched_tick(s,102);
    CHECK(t->state==T_STUN_PROOF && !t->stun_fragment_attempted,
          "timeout alone waits for execution evidence before next question");
    if(mode==1)e.kind=D2K_EV_REFUSED;
    if(mode==2)e.trial_id[0]^=1;
    d2k_sched_event(s,&e);d2k_sched_tick(s,103);
    if(mode==0){
        CHECK(t->state==T_STUN_ACK && t->stun_fragment_attempted,
              "owned executed timeout opens generated fragmentation question");
        CHECK(memcmp(t->stun_trial_id,retired.trial_id,16)!=0,
              "next question has independent trial identity");
        CHECK(worker_calls==1,"next question cannot send before its own install ACK");
        d2k_ev second=retired;memcpy(second.trial_id,t->stun_trial_id,16);
        task_done(s,t);d2k_sched_event(s,&second);
    }else{
        if(t->state==T_STUN_PROOF)d2k_sched_tick(s,102+SCHED_VERIFY_STEP_MS);
        CHECK(t->state==T_FREE,"refusal or foreign execution cannot authorize followup");
    }
    d2k_sched_event(s,&retired);
    CHECK(!d2k_stun_trial_pending(),"both trial leases retire independently");
cleanup:
    d2k_sched_free(s);d2k_catalog_free(&c);close(sv[0]);close(sv[1]);
}
static void client_confirmation(int family,int mode){
    int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"client control pair");
    d2k_catalog c={0};catalog(&c,family);
    d2k_sched *s=d2k_sched_new(&c,sv[0],0x2e);
    if(!s){fails++;close(sv[0]);close(sv[1]);d2k_catalog_free(&c);return;}
    task *t=baseline(s,family,D2K_STUN_TIMEOUT);
    t->trigger_shape=D2K_LINK_SHAPE_VOICE;
    t->trigger_flow.family=family;t->trigger_flow.transport=17;
    inet_pton(family==6?AF_INET6:AF_INET,t->ip,t->trigger_flow.a_ip);
    inet_pton(family==6?AF_INET6:AF_INET,family==6?"::2":"127.0.0.2",t->trigger_flow.b_ip);
    t->trigger_flow.a_port=t->port;t->trigger_flow.b_port=49001;
    snprintf(t->plans[0],sizeof t->plans[0],"%s",c.boxes[0].plans[0].text);t->n_plans=1;
    CHECK(stun_client_start(s,t,100),"diagnostic solution can be tried on original client tuple");
    CHECK(t->state==T_STUN_CLIENT && !c.revision,"installation alone never saves client success");
    d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_SET_ADDR_PROBE;ack.num=0x100;
    memcpy(ack.trial_id,t->addr_probe_trial_id,16);
    if(mode!=2)d2k_sched_event(s,&ack);
    d2k_ev e={0};e.kind=D2K_EV_EXCHANGE;e.code=D2K_UDP_PROOF_STUN;
    e.planned=D2K_LINK_PLANNED_YES;e.transport=17;e.family=family;
    memcpy(e.low_ip,t->trigger_flow.a_ip,16);memcpy(e.high_ip,t->trigger_flow.b_ip,16);
    e.low_port=t->trigger_flow.a_port;e.high_port=t->trigger_flow.b_port;
    memcpy(e.trial_id,t->addr_probe_trial_id,16);memcpy(e.plan_id,t->ver_plan_id,16);
    e.execution_id=71;e.execution_binding.kind=D2K_BIND_FLOW;
    e.execution_binding.temporary=1;e.execution_binding.family=family;
    e.execution_binding.shape=D2K_LINK_SHAPE_VOICE;
    e.execution_binding.epoch[0]=1;e.execution_binding.generation=1;
    if(mode==1)e.trial_id[0]^=1;
    if(mode==3)e.code=0;
    if(mode==7)e.high_port++;
    d2k_sched_event(s,&e);d2k_sched_tick(s,101);
    CHECK(!c.revision && t->state==T_STUN_CLIENT,"even typed early reply waits for exact execution completion");
    e.kind=mode==5?D2K_EV_REFUSED:D2K_EV_APPLIED;
    if(mode==4)e.execution_binding.generation++;
    if(mode==6)e.execution_id++;
    d2k_sched_event(s,&e);d2k_sched_tick(s,102);
    if(mode==0 || mode>=8) {
        CHECK(t->state==T_VOICE_INSTALL && !c.revision,
              "client protocol success waits for permanent installation ACK");
        d2k_ev installed={0};installed.kind=D2K_EV_ACK;
        installed.code=D2K_CMD_SET_ENDPOINT_BOUND;
        installed.num=mode==8?D2K_ACK_NO_ROOM:0x100;
        memcpy(installed.trial_id,t->voice_install_token,16);
        installed.execution_binding=e.execution_binding;
        installed.execution_binding.kind=D2K_BIND_ADDR;
        installed.execution_binding.temporary=0;
        if(mode==9)installed.trial_id[0]^=1;
        d2k_sched_event(s,&installed);d2k_sched_tick(s,103);
    }
    CHECK((t->state==T_WATCHING)==(mode==0),"only matching client reply, DONE, binding and install ACK confirm solution");
    if(mode!=0){
        CHECK(!c.revision,"foreign, generic, refused or incomplete evidence cannot update catalog");
        d2k_sched_tick(s,100+D2K_ADDR_PROBE_LEASE_MAX_MS);
        CHECK(t->state==T_FREE,"unconfirmed client experiment expires");
    }
    d2k_sched_free(s);d2k_catalog_free(&c);close(sv[0]);close(sv[1]);
}
int main(void){
    d2k_mark_fn saved=d2k_mark_hook;d2k_mark_hook=mark_ok;
    for(int family=4;family<=6;family+=2)for(int mode=0;mode<13;mode++)run(family,mode);
    d2k_sched_stun_run_fn saved_run=d2k_sched_stun_run_hook;
    d2k_sched_stun_run_hook=run_probe;
    for(int family=4;family<=6;family+=2)for(int mode=0;mode<21;mode++)experiment(family,mode);
    for(int mode=0;mode<3;mode++)measured_followup(mode);
    for(int family=4;family<=6;family+=2)
        for(int mode=0;mode<10;mode++)client_confirmation(family,mode);
    d2k_sched_stun_run_hook=saved_run;
    d2k_mark_hook=saved;
    if(fails)return 1;
    puts("STUN candidate scheduler: all checks passed");return 0;
}
