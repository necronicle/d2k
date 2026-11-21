/* Gate lifecycle: real scheduler + socketpair; no bind/listen or network. */
#define _POSIX_C_SOURCE 200809L
#define D2K_SCHED_DNS_TEST 1
#include "sched.c"
#include "test_task_slots.h"
#include <poll.h>
static int fails;
#define CHECK(c,m) do {if(!(c)){fprintf(stderr,"FAIL: %s\n",m);fails++;}}while(0)
static char logbuf[8192];
static void logger(void *ctx,const char *line){(void)ctx;size_t n=strlen(logbuf);snprintf(logbuf+n,sizeof logbuf-n,"%s\n",line);}
static uint8_t wire[32768];static size_t wirelen;
static void drain_gate(int fd){for(;;){struct pollfd p={fd,POLLIN,0};if(poll(&p,1,0)<=0)break;ssize_t n=read(fd,wire+wirelen,sizeof wire-wirelen);if(n<=0)break;wirelen+=(size_t)n;}}
static const uint8_t *command(unsigned cmd,size_t *len){const uint8_t *found=NULL;for(size_t o=0;o+6<=wirelen;){size_t n=d2k_rm_get32(wire+o);if(n<2||o+4+n>wirelen)break;if((((unsigned)wire[o+4]<<8)|wire[o+5])==cmd){found=wire+o+6;*len=n-2;}o+=n+4;}return found;}
static int no_bind(uint8_t tr,uint8_t fam,int *fd,uint16_t *port){int sv[2];(void)tr;(void)fam;if(socketpair(AF_UNIX,SOCK_STREAM,0,sv))return -1;close(sv[1]);*fd=sv[0];*port=htons(41008);return 0;}
static int marks;static uint32_t last_mark;
static int mark_ok(int fd,uint32_t m){(void)fd;marks++;last_mark=m;return 0;}
static int mark_refuse(int fd,uint32_t m){mark_ok(fd,m);return -1;}
static d2k_box_props gate_props(void){d2k_box_props p={0};p.response_gate=p.gate_carry=p.gate_hello_own=D2K_PROP_YES;p.gate_window=7;p.gate_pieces=9;p.gate_rtt_ms=231;return p;}
typedef struct {int sv[2];d2k_catalog c;d2k_sched *s;task *t;} fixture;
static fixture setup(void){fixture f={0};CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,f.sv),"socketpair");f.s=d2k_sched_new(&f.c,f.sv[0],0);return f;}
static void init(fixture *f){f->s->cat=&f->c;f->t=test_task_at(f->s, 0);task *t=f->t;task_reset(f->s,t);t->state=T_ASKING;t->family=4;t->transport=6;t->port=443;strcpy(t->ip,"192.0.2.8");strcpy(t->name,"video.example");t->trigger_code=D2K_SUSPECT_SILENT;t->trigger_shape=D2K_SHAPE_MODERN;t->trigger_planned=D2K_LINK_PLANNED_NO;t->started_ms=1000;
    CHECK(!d2k_hello_from_profile(D2K_SHAPE_MODERN,t->name,t->trig,sizeof t->trig,&t->trig_len),"hello fixture");t->trig_snapped=1;t->res.verdict=D2K_V_RESPONSE_GATE;t->res.box_props=gate_props();t->res_ready=1;wirelen=0;logbuf[0]=0;d2k_sched_set_say(f->s,logger,NULL);}
static void finish(fixture *f){d2k_sched_free(f->s);d2k_catalog_free(&f->c);close(f->sv[0]);close(f->sv[1]);}
static void step(fixture *f,int64_t ms){d2k_sched_tick(f->s,ms);drain_gate(f->sv[1]);}
static int installed(fixture *f,d2k_ev *ack){step(f,1100);size_t n=0;const uint8_t *b=command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n);CHECK(b&&n>36,"gate must install endpoint bound");if(!b||n<36)return 0;CHECK(b[0]==4&&b[1]==192&&b[4]==8&&b[18]==1&&b[19]==187,"gate endpoint has IPv4 address and port 443");memset(ack,0,sizeof *ack);ack->kind=D2K_EV_ACK;ack->code=D2K_CMD_SET_PREFLIGHT_TRIAL;ack->num=0x100;memcpy(ack->trial_id,b+n-16,16);ack->execution_binding.temporary=1;ack->execution_binding.kind=D2K_BIND_ADDR;ack->execution_binding.family=4;ack->execution_binding.shape=D2K_SHAPE_MODERN;ack->execution_binding.generation=8;ack->execution_binding.epoch[0]=3;return 1;}
static int probe_calls, classify_calls, reply_complete=1, classify_gate;
static d2k_ver_level reply_level=D2K_VER_APPLICATION;
static int reply_auth=1,reply_auth_failed,reply_http=2;
static d2k_ver_result gate_ver(int fd,const char *ip,uint16_t port,uint8_t tr,const char *sni,int wait,size_t n,uint8_t shape) {
    (void)ip;(void)port;(void)tr;(void)sni;(void)wait;(void)n;(void)shape;
    probe_calls++;if(fd>=0)close(fd);d2k_ver_result r={0};r.fd=-1;r.level=reply_level;
    r.family=4;r.local_ip4[0]=198;r.local_ip4[1]=51;r.local_ip4[2]=100;r.local_ip4[3]=8;
    memcpy(r.local_addr,r.local_ip4,4);r.local_port=41008;r.status=reply_level==D2K_VER_APPLICATION?200:0;
    r.body_complete=reply_complete;r.peer_authenticated=reply_auth;
    r.peer_auth_failed=reply_auth_failed;r.http_version=reply_http;
    r.negotiated_tls=shape==D2K_SHAPE_LEGACY?0x0303:0x0304;return r;
}
static d2k_vres gate_classify(const char *ip,uint16_t port,d2k_hello h,d2k_hello ctl,uint32_t mark,int repeats,uint32_t gap,uint32_t wait,const volatile sig_atomic_t *stop,const d2k_sched_tcp_extra *extra) {
    (void)ip;(void)port;(void)h;(void)ctl;(void)mark;(void)repeats;(void)gap;(void)wait;(void)stop;
    CHECK(!extra || !extra->known || extra->known->response_gate==D2K_PROP_UNKNOWN,"failed gate reuse cannot suppress fresh gate questions");
    classify_calls++;d2k_vres r={0};r.verdict=classify_gate?D2K_V_RESPONSE_GATE:D2K_V_INCONCLUSIVE;if(classify_gate)r.box_props=gate_props();return r;
}
static d2k_ev gate_wire_event(fixture *f,const d2k_ev *ack,unsigned kind) {
    d2k_ev e={0};e.kind=kind;e.family=4;e.transport=6;e.low_port=443;e.high_port=41008;
    inet_pton(AF_INET,f->t->ip,e.low_ip);inet_pton(AF_INET,"198.51.100.8",e.high_ip);
    e.execution_binding=ack->execution_binding;memcpy(e.trial_id,ack->trial_id,16);
    char id[40];plan_ident(f->t->plans[0],id,sizeof id,e.plan_id);return e;
}
static void returned(fixture *f){join_worker(f->t);CHECK(f->t->res_ready,"ordinary verifier returned");}
static void test_gate_application_and_execution(void) {
    for(int mode=0;mode<10;mode++) {
        fixture f=setup();init(&f);d2k_ev a;
        reply_level=mode==0?D2K_VER_HANDSHAKE:D2K_VER_APPLICATION;reply_complete=mode!=1;
        reply_auth=mode!=7;reply_auth_failed=mode==8;reply_http=mode==9?0:2;
        if(installed(&f,&a)) {
            d2k_sched_event(f.s,&a);step(&f,1200);returned(&f);
            d2k_ev e=gate_wire_event(&f,&a,D2K_EV_PREFLIGHT_HANDOVER);
            if(mode==2)e.trial_id[0]^=1;
            if(mode==3)e.execution_binding.generation++;
            if(mode==4)e.high_ip[3]++;
            if(mode==5)e.plan_id[0]^=1;
            d2k_sched_event(f.s,&e);step(&f,1300);
            size_t commit_len=0;
            CHECK((command(D2K_CMD_COMMIT_ENDPOINT_TRIAL,&commit_len)!=NULL)==(mode==6),
                "invalid TLS/application proof reached promotion");
            CHECK(!f.s->confirms,"even app proof must await promotion ACK");
            if(mode==6){d2k_ev commit=a;commit.code=D2K_CMD_COMMIT_ENDPOINT_TRIAL;d2k_sched_event(f.s,&commit);step(&f,1400);}
            CHECK((f.s->confirms==1)==(mode==6),"only complete application + exact plan/trial/binding/flow confirms gate");
            if(mode==6 && f.c.n_boxes && f.c.boxes[0].n_binds){CHECK(f.c.n_boxes && f.c.boxes[0].n_binds==1,"gate confirmed catalog binding");d2k_cat_binding *b=&f.c.boxes[0].binds[0];CHECK(!strcmp(b->kind,"service")&&!strcmp(b->target,"192.0.2.8")&&b->server_port==443&&!strcmp(b->preflight_name,"video.example"),"confirmed gate retains endpoint and verified name");
                wirelen=0;setenv("D2K_PREFLIGHT","0",1);d2k_sched_sync(f.s);
                while(d2k_sched_sync_step(f.s)>0){}drain_gate(f.sv[1]);size_t offlen=0;
                CHECK(!command(D2K_CMD_SET_PREFLIGHT_TRIAL,&offlen)&&!command(D2K_CMD_SET_ENDPOINT_BOUND,&offlen)&&!command(D2K_CMD_SET_ENDPOINT,&offlen),"disabled gate catalog replay cannot install preflight");
                setenv("D2K_PREFLIGHT","1",1);}
        }
        finish(&f);
    }
    reply_level=D2K_VER_APPLICATION;reply_complete=1;
    reply_auth=1;reply_auth_failed=0;reply_http=2;
}
static void test_partial_gate_keeps_ordinary_trials_first(void) {
    fixture f=setup();init(&f);
    f.t->res.verdict=D2K_V_INCONCLUSIVE;
    f.t->res.box_props=(d2k_box_props){.response_gate=D2K_PROP_YES};
    f.t->res.gate_candidate=(d2k_preflight_candidate){.present=1,.window=1,.window_scale=1,
        .pieces=1,.rtt_ms=173,.response_bytes=2,.name="observed.example"};
    step(&f,1100);
    CHECK(f.t->state==T_PLANNING && f.t->n_plans>0,"partial gate must retain an explicit ordinary fallback queue");
    CHECK(f.t->res.box_props.gate_carry!=D2K_PROP_YES,"a partial gate is not a positive carry property");
    size_t n=0;CHECK(!command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n),"partial evidence alone cannot start a preflight application");
    step(&f,1200);
    CHECK(command(D2K_CMD_SET_NAME_PROBE,&n)!=NULL,"ordinary outgoing candidate must be tried first");
    CHECK(!command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n),"no preflight before ordinary application fails");
    CHECK(!f.s->confirms,"candidate admission cannot confirm anything");
    f.t->trial_acked=1;reply_level=D2K_VER_TRANSPORT;
    step(&f,1300);returned(&f);reply_level=D2K_VER_APPLICATION;
    f.t->ver_seen=1;
    f.t->ver_early[0]=(d2k_flowkey){.family=4,.transport=6,.a_port=41008,.b_port=443};
    inet_pton(AF_INET,"198.51.100.8",f.t->ver_early[0].a_ip);
    inet_pton(AF_INET,"192.0.2.8",f.t->ver_early[0].b_ip);
    step(&f,1400);
    CHECK(f.t->gate_combined && command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n),
          "ordinary executed application failure must reach a composed trial through the scheduler");
    CHECK(f.t->res.gate_candidate.present && f.t->res.box_props.gate_carry!=D2K_PROP_YES,
          "ordinary verifier must retain the original evidence without fabricating carry");
    finish(&f);
}
static void test_gate_marks_owned_verifier(void) {
    for(int refuse=0;refuse<2;refuse++) {
        fixture f=setup();init(&f);f.s->mark=0x2d;marks=0;last_mark=0;
        d2k_sched_mark_hook=refuse?mark_refuse:mark_ok;
        step(&f,1100);size_t n=0;
        CHECK(marks==1 && last_mark==0x2d,"preflight verifier must receive the controller queue mark");
        CHECK((command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n)!=NULL)==!refuse,
              "mark failure must prevent installing a preflight trial");
        if(refuse)CHECK(f.t->probe_fd<0,"failed verifier mark releases reserved socket");
        finish(&f);
    }
    d2k_sched_mark_hook=mark_ok;
}
static void test_combined_gate_requires_both_executions(void) {
    for(int mode=0;mode<7;mode++) {
        fixture f=setup();init(&f);
        f.t->state=T_PLANNING;f.t->n_plans=2;f.t->next_plan=1;f.t->n_known=0;f.t->probes=1;
        strcpy(f.t->plans[0],"d2k-plan 1 5\nproto tcp tls\nwire detect-tcp-v1\ninput tls-sni\nsplit payload_start +1\norder forward\n");
        strcpy(f.t->plans[1],"d2k-plan 1 5\nproto tcp tls\nwire detect-tcp-v1\ninput tls-sni\nsplit sni_middle +0\norder reverse\n");
        f.t->res.verdict=D2K_V_INCONCLUSIVE;f.t->res.box_props=(d2k_box_props){.response_gate=D2K_PROP_YES};
        f.t->res.gate_candidate=(d2k_preflight_candidate){.present=1,.window=1,.window_scale=1,
            .pieces=1,.rtt_ms=173,.response_bytes=2,.name="observed.example"};
        f.t->ver.level=D2K_VER_TRANSPORT;f.t->ver_dropped0=f.s->dropped_seen;
        CHECK(!gate_try_composed(f.s,f.t,0),"missing ordinary execution cannot open a composed trial");
        CHECK(gate_try_composed(f.s,f.t,1),"failed ordinary application may open a composed trial");
        CHECK(f.t->probes==2 && f.t->res.box_props.gate_carry!=D2K_PROP_YES,
              "composed trial spends budget without fabricating a carry property");
        CHECK(strstr(f.t->plans[0],"handover apply") && strstr(f.t->plans[0],"origin=fallback"),
              "trial preserves explicit composition and fallback origin");
        d2k_ev a;
        if(installed(&f,&a)) {
            reply_level=D2K_VER_APPLICATION;reply_complete=mode!=6;
            d2k_sched_event(f.s,&a);step(&f,1200);returned(&f);
            d2k_ev hand=gate_wire_event(&f,&a,D2K_EV_PREFLIGHT_HANDOVER);
            d2k_ev app=gate_wire_event(&f,&a,D2K_EV_APPLIED);app.execution_id=42;
            if(mode==3)app.execution_binding.generation++;
            if(mode==5)app.plan_id[0]^=1;
            if(mode==4)d2k_sched_event(f.s,&app); /* either order is legal */
            if(mode!=2)d2k_sched_event(f.s,&hand);
            if(mode!=1 && mode!=4)d2k_sched_event(f.s,&app);
            step(&f,1300);size_t n=0;
            int valid=mode==0 || mode==4;
            CHECK((command(D2K_CMD_COMMIT_ENDPOINT_TRIAL,&n)!=NULL)==valid,
                  "combined promotion needs exact handover AND outgoing execution AND complete HTTP");
            if(valid) {
                d2k_ev commit=a;commit.code=D2K_CMD_COMMIT_ENDPOINT_TRIAL;
                d2k_sched_event(f.s,&commit);step(&f,1400);
                CHECK(f.s->confirms==1,"a verified composed program promotes only after commit ACK");
            } else {
                if(f.t->gate_active)gate_failed(f.s,f.t,"incomplete combined proof");
                CHECK(f.t->state==T_PLANNING && f.t->n_plans==2 && f.t->next_plan==1,
                      "failed composition restores the remaining ordinary queue");
                CHECK(!f.s->confirms,"partial combined proof cannot confirm");
            }
        }
        finish(&f);
    }
    reply_complete=1;reply_level=D2K_VER_APPLICATION;
}
static void test_gate_cleanup_and_refusal(void) {
    for(int mode=0;mode<5;mode++) {
        fixture f=setup();init(&f);d2k_ev a;
        if(installed(&f,&a)) {
            if(mode==0){a.num=0;d2k_sched_event(f.s,&a);step(&f,1200);}
            else if(mode==4){step(&f,1100+SCHED_VERIFY_STEP_MS);}
            else {
                d2k_sched_event(f.s,&a);step(&f,1200);returned(&f);
                d2k_ev e=gate_wire_event(&f,&a,mode==1?D2K_EV_REFUSED:D2K_EV_PREFLIGHT_GAVE_UP);
                if(mode==3)e.high_ip[3]++;
                d2k_sched_event(f.s,&e);step(&f,1300);
            }
            drain_gate(f.sv[1]);size_t n=0;const uint8_t *b=command(D2K_CMD_DEL_ENDPOINT_TRIAL,&n);
            CHECK((b!=NULL)==(mode!=3),"only own failed or unacknowledged candidate is retired");
            if(b)CHECK(n==36&&!memcmp(b+20,a.trial_id,16)&&b[0]==4&&b[18]==1&&b[19]==187,"cleanup retains endpoint and unique installation token");
            CHECK(!command(D2K_CMD_DEL_NAME,&n)&&!command(D2K_CMD_DEL_ADDR,&n)&&!command(D2K_CMD_DEL_ENDPOINT,&n),"failure cannot issue broad deletion");
            CHECK(!f.s->confirms,"failure never confirms gate");
        }
        finish(&f);
    }
}
static void test_gate_reuse_failure_remeasures(void){fixture f=setup();init(&f);f.t->gate_reuse=0;d2k_ev a;if(installed(&f,&a)){f.t->gate_reuse=1;a.num=0;classify_calls=0;d2k_sched_event(f.s,&a);step(&f,1200);returned(&f);CHECK(classify_calls==1,"failed own gate starts fresh measurement");CHECK(!f.t->n_plans,"failed own gate never builds fallback");}finish(&f);}
static void test_gate_live_suspect_to_classifier(void) {
    fixture f=setup();init(&f);d2k_ev e={0};e.kind=D2K_EV_HELLO;e.family=4;e.transport=6;
    e.low_port=443;e.high_port=41008;inet_pton(AF_INET,"192.0.2.8",e.low_ip);
    inet_pton(AF_INET,"198.51.100.8",e.high_ip);strcpy(e.name,"video.example");
    task_reset(f.s,f.t);classify_calls=0;classify_gate=1;
    d2k_sched_event(f.s,&e);d2k_ev shape=e;shape.kind=D2K_EV_SHAPE;
    CHECK(!d2k_hello_from_profile(D2K_SHAPE_MODERN,e.name,shape.shape,sizeof shape.shape,&shape.shape_len),"live snapshot fixture");
    d2k_sched_event(f.s,&shape);step(&f,1000);
    CHECK(classify_calls==0,"healthy live TLS hello never starts classification");
    e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.name[0]=0;
    e.client_shape=D2K_SHAPE_MODERN;e.planned=D2K_LINK_PLANNED_NO;
    d2k_sched_event(f.s,&e);
    task *t=task_of(f.s,"video.example",6,4);CHECK(t,"live silent TLS opens ordinary task");
    if(t){f.t=t;join_worker(t);step(&f,1100);size_t n=0;
        CHECK(classify_calls==1,"silent suspicion invokes ordinary classifier once");
        CHECK(command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n),"ordinary gate verdict installs endpoint plan");
        CHECK(f.c.n_boxes&&f.c.boxes[0].n_props&&f.c.boxes[0].props[0].p.gate_pieces==9,"classifier gate measurements reach box_props_learn");
        char hex[8193];for(size_t i=0;i<shape.shape_len;i++)snprintf(hex+2*i,3,"%02x",shape.shape[i]);
        CHECK(strstr(t->plans[0],hex),"own gate probe uses captured target ClientHello");
    }
    classify_gate=0;finish(&f);
}
static void test_gate_plan_bound_by_endpoint(void){fixture f=setup();init(&f);d2k_ev a;installed(&f,&a);size_t n=0;CHECK(!command(D2K_CMD_SET_NAME_PROBE,&n),"gate cannot be an SNI probe");finish(&f);}
static void test_gate_success_needs_app_reply(void){fixture f=setup();init(&f);d2k_ev a;if(installed(&f,&a)){d2k_sched_event(f.s,&a);d2k_ev e={0};e.kind=D2K_EV_PREFLIGHT_HANDOVER;e.family=4;e.transport=6;e.low_port=443;inet_pton(AF_INET,f.t->ip,e.low_ip);e.high_port=41008;e.execution_binding=a.execution_binding;memcpy(e.trial_id,a.trial_id,16);d2k_sched_event(f.s,&e);CHECK(f.s->confirms==0,"HANDOVER is not DONE");}finish(&f);}
static void test_gate_no_carry_no_plan(void){fixture f=setup();init(&f);f.t->res.verdict=D2K_V_RESPONSE;f.t->res.box_props.gate_carry=D2K_PROP_NO;step(&f,1100);size_t n=0;CHECK(!command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n)&&!command(D2K_CMD_SET_NAME_PROBE,&n),"negative carry has no plan");CHECK(!cooldown_find(f.s,"video.example",6,4),"negative carry cannot penalize other questions");finish(&f);}
static void test_gate_uses_measured_hello_without_catalog_name(void){fixture f=setup();init(&f);f.t->res.box_props.gate_hello_own=D2K_PROP_NO;strcpy(f.t->res.gate_probe_name,"measured.example");d2k_ev a;if(installed(&f,&a)){CHECK(strstr(f.t->plans[0],"hello=white name=measured.example"),"measured white name reaches the plan");uint8_t h[4096];size_t n=0;CHECK(!d2k_white_decoy_hello("measured.example",h,sizeof h,&n),"white fixture hello");char hex[8193];for(size_t i=0;i<n;i++)snprintf(hex+2*i,3,"%02x",h[i]);CHECK(strstr(f.t->plans[0],hex),"payload is generated white hello");}finish(&f);}
static void test_gate_white_without_name_no_plan(void){fixture f=setup();init(&f);f.t->res.box_props.gate_hello_own=D2K_PROP_NO;step(&f,1100);size_t n=0;CHECK(!command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n),"alternate hello without measured name has no plan");CHECK(strstr(logbuf,"не сохранено имя измеренного пробного приветствия"),"missing white name must be logged");finish(&f);}
static void test_preflight_off_no_gate_plans(void){setenv("D2K_PREFLIGHT","0",1);fixture f=setup();init(&f);step(&f,1100);size_t n=0;CHECK(!command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n)&&!f.t->n_plans,"disabled gate spends no trial");finish(&f);setenv("D2K_PREFLIGHT","1",1);}
static void test_healthy_no_gate(void){fixture f=setup();init(&f);f.t->res.verdict=D2K_V_CLEAR;memset(&f.t->res.box_props,0,sizeof f.t->res.box_props);step(&f,1100);size_t n=0;CHECK(!command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n),"healthy target has no gate plan");finish(&f);}
static void test_own_box_solution_checked_first(void){fixture f=setup();init(&f);task *t=f.t;t->state=T_FREE;t->fp.method=D2K_FP_METHOD;t->fp.n_sig=1;strcpy(t->fp.sig[0].kind,"silent");d2k_cat_box *b=box_ensure(&f.c,"saved-gate");b->fp=t->fp;b->n_props=1;b->props[0].p=gate_props();b->props[0].p.client_shape=t->trigger_shape;t->res_ready=0;CHECK(launch_or_queue(f.s,t),"launch saved gate");drain_gate(f.sv[1]);size_t n=0;CHECK(command(D2K_CMD_SET_PREFLIGHT_TRIAL,&n),"saved compatible gate checked before measurement");CHECK(!t->th_live,"reuse must not start classifier");finish(&f);}
static void test_gate_gave_up_removes_only_own_candidate(void){fixture f=setup();init(&f);d2k_ev a;if(installed(&f,&a)){d2k_sched_event(f.s,&a);d2k_ev e={0};e.kind=D2K_EV_PREFLIGHT_GAVE_UP;e.family=4;e.transport=6;e.low_port=443;e.high_port=41008;inet_pton(AF_INET,f.t->ip,e.low_ip);e.execution_binding=a.execution_binding;memcpy(e.trial_id,a.trial_id,16);char id[40];plan_ident(f.t->plans[0],id,sizeof id,e.plan_id);e.trial_id[0]^=1;d2k_sched_event(f.s,&e);CHECK(!f.t->ver_unsent_seen,"foreign gave up ignored");e.trial_id[0]^=1;d2k_sched_event(f.s,&e);CHECK(f.t->ver_unsent_seen==1,"own gave up retained until exact verifier flow is known");}finish(&f);}
static void test_preflight_default_enabled(void){unsetenv("D2K_PREFLIGHT");fixture f=setup();init(&f);d2k_ev ack;CHECK(installed(&f,&ack),"default controller must run a measured response gate");finish(&f);setenv("D2K_PREFLIGHT","1",1);}
static void test_direct_application_retires_exact_gate(void) {
    fixture f=setup();
    init(&f);
    task *t=f.t;
    d2k_box_props props=gate_props();
    char plan[16384],err[160];
    CHECK(d2k_compose_preflight_from_props(&props,NULL,0,4,6,t->trig,t->trig_len,
        plan,sizeof plan,err,sizeof err)==1,"compose saved gate fixture");
    CHECK(!bind_confirmed(&f.c,"gate","gate-plan",plan,"tls",t->ip,"service",6,4,
        D2K_SHAPE_MODERN,t->port,D2K_VERBY_PROBE,0,1000,NULL,NULL,NULL),"save gate for exact endpoint");
    CHECK(!bind_confirmed(&f.c,"gate","gate-plan",plan,"tls",t->ip,"service",6,4,
        D2K_SHAPE_MODERN,8443,D2K_VERBY_PROBE,0,1000,NULL,NULL,NULL),"save gate for adjacent port");
    d2k_cat_box *box=&f.c.boxes[0];
    snprintf(box->binds[0].preflight_name,sizeof box->binds[0].preflight_name,"%s",t->name);
    snprintf(box->binds[1].preflight_name,sizeof box->binds[1].preflight_name,"%s",t->name);

    forget_clear_target_bindings(f.s,t,1200);
    drain_gate(f.sv[1]);
    size_t n=0;
    CHECK(!box->binds[0].recheck_since && !command(D2K_CMD_DEL_ENDPOINT,&n),
          "handshake alone cannot retire a saved gate");

    t->vol.rx_direct_complete=1;
    strcpy(t->name,"neighbour.example");
    forget_clear_target_bindings(f.s,t,1300);
    drain_gate(f.sv[1]);
    CHECK(!box->binds[0].recheck_since && !command(D2K_CMD_DEL_ENDPOINT,&n),
          "direct proof for a different virtual host cannot retire the gate");
    strcpy(t->name,"video.example");
    forget_clear_target_bindings(f.s,t,1400);
    drain_gate(f.sv[1]);
    const uint8_t *b=command(D2K_CMD_DEL_ENDPOINT,&n);
    CHECK(b && n==20 && b[0]==4 && b[1]==192 && b[4]==8 &&
          b[17]==D2K_SHAPE_MODERN && b[18]==1 && b[19]==187,
          "direct application proof retires only the matching gate endpoint");
    CHECK(box->n_binds==2 && box->binds[0].recheck_since && !box->binds[1].recheck_since,
          "first direct success preserves exactly the retired binding for recheck");

    forget_clear_target_bindings(f.s,t,1500);
    CHECK(box->n_binds==2,"repeated handling of the same observation retains knowledge");
    forget_clear_target_bindings(f.s,t,1400+SCHED_RECHECK_GAP_MS);
    CHECK(box->n_binds==1 && box->binds[0].server_port==8443,
          "second independent direct success forgets only its endpoint");
    finish(&f);
}

static void test_response_candidate_admitted_to_full_queue(void) {
    fixture f=setup();
    init(&f);
    f.t->trigger_shape=D2K_LINK_SHAPE_ECH_TCP;
    f.s->meas_limit=1;
    f.s->clock_seen=1;
    f.s->now_ms=1200;
    f.s->event_sequence=SCHED_MAX_QUEUED_MEASUREMENTS+1;
    test_task_at(f.s, 1)->state=T_ASKING;
    for (unsigned i=0;i<SCHED_MAX_QUEUED_MEASUREMENTS;i++) {
        task *q=test_task_at(f.s, i+2);
        q->state=T_QUEUED;
        q->transport=6;q->family=4;q->trigger_code=D2K_SUSPECT_RST;
        q->queued_ms=1100;q->queued_event=i+1;
        snprintf(q->name,sizeof q->name,"waiting-%u.example",i);
    }
    test_task_at(f.s, 2)->hot_event=1;
    task *last=test_task_at(f.s, SCHED_MAX_QUEUED_MEASUREMENTS+1);
    last->hot_event=2;
    task *victim=test_task_at(f.s, SCHED_MAX_QUEUED_MEASUREMENTS);
    f.t->state=T_FREE;
    launch_or_queue(f.s,f.t);
    CHECK(f.t->state==T_QUEUED,"response candidate was dropped with a full queue");
    CHECK(queued_measurements(f.s)==SCHED_MAX_QUEUED_MEASUREMENTS,"admission changed the queue cap");
    CHECK(test_task_at(f.s, 1)->state==T_ASKING && last->state==T_QUEUED && victim->state==T_FREE,
          "admission must only replace a waiting, uncorroborated suspicion");
    CHECK(queued_pick(f.s)==f.t,"response candidate did not get the next measurement slot");
    test_task_at(f.s, 1)->state=T_FREE;
    classify_calls=0;
    classify_gate=1;
    CHECK(queued_release(f.s,1300)==1,"newly admitted measurement was not released");
    returned(&f);
    step(&f,1400);
    size_t length=0;
    CHECK(classify_calls==1 && command(D2K_CMD_SET_PREFLIGHT_TRIAL,&length),
          "admitted measurement did not reach the response trial");
    classify_gate=0;
    finish(&f);
}

static void test_gate_catalog_commit_transaction(void) {
    for(int mode=0;mode<3;mode++) {
        fixture f=setup();init(&f);d2k_ev a;
        char box[40];box_id_for(f.s,f.t,f.t->plans[0],box,sizeof box);
        if(mode==1)CHECK(!bind_confirmed(&f.c,box,"old-plan",f.t->plans[0],"tls",f.t->ip,
            "service",6,4,D2K_SHAPE_MODERN,443,D2K_VERBY_PROBE,0,1000,NULL,NULL,NULL),"old catalog fixture");
        if(installed(&f,&a)) {
            d2k_sched_event(f.s,&a);step(&f,1200);returned(&f);
            if(mode==0)f.s->cat=NULL;
            d2k_ev e=gate_wire_event(&f,&a,D2K_EV_PREFLIGHT_HANDOVER);d2k_sched_event(f.s,&e);step(&f,1300);
            size_t n=0;
            if(mode==0) {
                CHECK(!command(D2K_CMD_COMMIT_ENDPOINT_TRIAL,&n),"catalog failure must precede and prevent promotion");
                CHECK(command(D2K_CMD_DEL_ENDPOINT_TRIAL,&n),"failed catalog save still retires its trial");
            } else {
                CHECK(command(D2K_CMD_COMMIT_ENDPOINT_TRIAL,&n),"verified catalog state reaches commit");
                d2k_cat_binding *bd=f.c.boxes[0].n_binds?&f.c.boxes[0].binds[0]:NULL;
                CHECK(bd && strcmp(bd->plan_id,"old-plan"),"new catalog state must be visible before commit");
                d2k_ev commit=a;commit.code=D2K_CMD_COMMIT_ENDPOINT_TRIAL;commit.num=0;
                d2k_sched_event(f.s,&commit);step(&f,1400);
                bd=f.c.boxes[0].n_binds?&f.c.boxes[0].binds[0]:NULL;
                if(mode==1)CHECK(bd&&!strcmp(bd->plan_id,"old-plan"),"commit refusal did not restore previous catalog binding");
                else CHECK(!bd,"commit refusal left an unapplied catalog binding");
            }
        }
        f.s->cat=&f.c;finish(&f);
    }
}
static void test_gate_dns_lease_ack_transaction(void) {
    for(int accept=0;accept<2;accept++) {
        fixture f=setup();init(&f);
        d2k_dns_answer answer={.family=4,.type=1,.count=1,.ttl=30};
        strcpy(answer.question,f.t->name);inet_pton(AF_INET,"192.168.1.9",answer.client);
        inet_pton(AF_INET,f.t->ip,answer.addresses[0]);
        d2k_sched_dns_observe_answer_path(f.s,&answer,1000,7);
        d2k_ev a;
        if(installed(&f,&a)) {
            d2k_sched_event(f.s,&a);step(&f,1200);returned(&f);
            d2k_ev e=gate_wire_event(&f,&a,D2K_EV_PREFLIGHT_HANDOVER);
            d2k_sched_event(f.s,&e);step(&f,1300);
            size_t n=0,commit_n=0;const uint8_t *lease=command(D2K_CMD_SET_PREFLIGHT_LEASE,&n);
            CHECK(lease&&n>70,"verified gate with fresh DNS did not request a lease");
            CHECK(!command(D2K_CMD_COMMIT_ENDPOINT_TRIAL,&commit_n),"endpoint committed before lease ACK");
            d2k_ev premature=a;premature.code=D2K_CMD_COMMIT_ENDPOINT_TRIAL;
            d2k_sched_event(f.s,&premature);step(&f,1325);
            CHECK(!f.s->confirms,"commit ACK was accepted before the commit command");
            if(lease&&n>62) {
                uint16_t names=(uint16_t)(lease[44]<<8|lease[45]);
                d2k_ev lease_ack={.kind=D2K_EV_ACK,.code=D2K_CMD_SET_PREFLIGHT_LEASE,
                    .num=accept?(1u<<8):0};
                CHECK(46u+names+16u<=n,"lease ID outside command");
                if(46u+names+16u<=n)memcpy(lease_ack.trial_id,lease+46+names,16);
                d2k_sched_event(f.s,&lease_ack);step(&f,1350);
            }
            if(!accept) {
                CHECK(!command(D2K_CMD_COMMIT_ENDPOINT_TRIAL,&commit_n),"refused lease reached endpoint commit");
                CHECK(!f.s->confirms&&(!f.c.n_boxes||!f.c.boxes[0].n_binds),
                    "refused lease became catalog APPLIED");
            } else {
                CHECK(command(D2K_CMD_COMMIT_ENDPOINT_TRIAL,&commit_n),"accepted lease did not reach endpoint commit");
                d2k_ev commit=a;commit.code=D2K_CMD_COMMIT_ENDPOINT_TRIAL;
                d2k_sched_event(f.s,&commit);step(&f,1400);
                CHECK(f.s->confirms==1&&f.c.n_boxes,"accepted lease and endpoint were not confirmed");
            }
        }
        finish(&f);
    }
}
int main(void){setenv("D2K_PREFLIGHT","1",1);d2k_sched_bind_hook=no_bind;d2k_sched_mark_hook=mark_ok;d2k_sched_ver_hook=gate_ver;d2k_sched_preflight_ver_hook=gate_ver;d2k_sched_tcp_hook=gate_classify;test_gate_marks_owned_verifier();test_combined_gate_requires_both_executions();test_partial_gate_keeps_ordinary_trials_first();test_gate_dns_lease_ack_transaction();test_gate_catalog_commit_transaction();test_preflight_default_enabled();test_response_candidate_admitted_to_full_queue();test_direct_application_retires_exact_gate();test_gate_live_suspect_to_classifier();test_gate_application_and_execution();test_gate_cleanup_and_refusal();test_gate_reuse_failure_remeasures();test_gate_plan_bound_by_endpoint();test_gate_success_needs_app_reply();test_gate_no_carry_no_plan();test_gate_uses_measured_hello_without_catalog_name();test_gate_white_without_name_no_plan();test_preflight_off_no_gate_plans();test_healthy_no_gate();test_own_box_solution_checked_first();test_gate_gave_up_removes_only_own_candidate();if(fails){fprintf(stderr,"gate failures: %d\n",fails);return 1;}puts("scheduler gate: all checks passed");return 0;}
