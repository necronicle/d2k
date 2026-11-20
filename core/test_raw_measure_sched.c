#define _POSIX_C_SOURCE 200809L
#include "sched.c"
#include <poll.h>
static int fails;
#define CHECK(c,m) do {if(!(c)){fprintf(stderr,"FAIL: %s\n",m);fails++;}}while(0)
static int read_request(int fd,struct d2k_rawmeasure_request *r) {
    uint8_t frame[6+D2K_RM_REQUEST_LEN];size_t at=0;
    while(at<sizeof frame){struct pollfd p={fd,POLLIN,0};if(poll(&p,1,100)<=0)return -1;
        ssize_t n=read(fd,frame+at,sizeof frame-at);if(n<=0)return -1;at+=(size_t)n;}
    if(frame[4]!=(D2K_CMD_RAW_MEASURE>>8)||frame[5]!=(D2K_CMD_RAW_MEASURE&255))return -1;
    return d2k_rawmeasure_request_read(r,frame+6,D2K_RM_REQUEST_LEN);
}
static int raw_ct_fixture(const d2k_ct_tuple *tuple,d2k_ct_info *info) {
    (void)tuple;memset(info,0,sizeof *info);return 0;
}
static void raw_proof_identity_test(void) {
    for(int transport=6;transport<=17;transport+=11) for(int variant=0;variant<8;variant++) {
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2e);
        CHECK(s!=NULL,"proof scheduler allocation");if(!s)continue;
        task *t=task_free_slot(s);task_reset(s,t);t->state=T_RAW_TRIAL;t->raw=1;
        t->family=4;t->transport=(uint8_t)transport;t->port=7777;t->by_addr=1;
        strcpy(t->name,"1.0.0.0");strcpy(t->ip,"1.0.0.0");
        t->ver_plan_id[0]=7;t->trial_ack_id[0]=8;t->addr_probe_trial_id[0]=8;
        t->trigger_flow.family=4;t->trigger_flow.transport=(uint8_t)transport;
        t->trigger_flow.a_ip[0]=1;t->trigger_flow.b_ip[0]=192;
        t->trigger_flow.a_port=7777;t->trigger_flow.b_port=49001;
        d2k_ev event={0};event.kind=D2K_EV_APPLIED;event.family=4;event.transport=(uint8_t)transport;
        event.low_ip[0]=1;event.high_ip[0]=192;event.low_port=7777;event.high_port=49001;
        event.plan_id[0]=7;event.trial_id[0]=8;event.execution_id=99;
        event.planned=D2K_LINK_PLANNED_YES;
        event.code=D2K_RAW_PROOF_ECHO;
        if(variant>=5) {
            event.kind=D2K_EV_EXCHANGE;if(variant==7)event.execution_id=98;
            on_exchange(s,&event);CHECK(t->state==T_RAW_TRIAL&&!s->confirms,"early reply promoted before send completion");
            event.execution_id=99;
            if(variant==6){event.kind=D2K_EV_REFUSED;event.code=7;d2k_sched_event(s,&event);}
            event.kind=D2K_EV_APPLIED;
        }
        on_applied(s,&event);
        if(variant==5||variant==6) {
            CHECK(variant==5 ? t->state==T_WATCHING&&s->confirms==1 : t->state==T_FREE&&!s->confirms,
                  "early reply lost after completion or survived local failure");
            d2k_sched_free(s);d2k_catalog_free(&cat);continue;
        }
        CHECK(t->state==T_RAW_WATCH,"own application did not start watch");
        event.kind=D2K_EV_EXCHANGE;
        if(variant==0)event.execution_id=98;
        if(variant==1)event.execution_id=0;
        if(variant==2)event.plan_id[0]^=1;
        if(variant==3)event.trial_id[0]^=1;
        on_exchange(s,&event);
        CHECK(variant>=4 ? s->confirms==1 : s->confirms==0&&t->state==T_RAW_WATCH,
              "RAW exchange accepted foreign execution/plan/trial or rejected exact proof");
        d2k_sched_free(s);d2k_catalog_free(&cat);
    }
}
static void raw_proof_kind_test(void) {
    const uint16_t codes[] = {0, D2K_UDP_PROOF_STUN, 23, 63,
                              D2K_RAW_PROOF_ECHO, D2K_RAW_PROOF_PROGRESS, 66};
    for (int transport = 6; transport <= 17; transport += 11)
    for (int early = 0; early < 2; early++)
    for (size_t k = 0; k < sizeof codes / sizeof codes[0]; k++) {
        d2k_catalog cat = {0};
        d2k_sched *s = d2k_sched_new(&cat, -1, 0x2e);
        CHECK(s != NULL, "proof kind scheduler allocation");
        if (!s) continue;
        task *t = task_free_slot(s); task_reset(s, t);
        t->state = T_RAW_TRIAL; t->raw = 1; t->by_addr = 1;
        t->family = 4; t->transport = (uint8_t)transport; t->port = 7777;
        strcpy(t->name, "1.0.0.0"); strcpy(t->ip, "1.0.0.0");
        t->ver_plan_id[0] = 7; t->trial_ack_id[0] = 8;
        t->addr_probe_trial_id[0] = 8;
        t->trigger_flow.family = 4; t->trigger_flow.transport = (uint8_t)transport;
        t->trigger_flow.a_ip[0] = 1; t->trigger_flow.b_ip[0] = 192;
        t->trigger_flow.a_port = 7777; t->trigger_flow.b_port = 49001;
        d2k_ev e = {0};
        e.family = 4; e.transport = (uint8_t)transport;
        e.low_ip[0] = 1; e.high_ip[0] = 192;
        e.low_port = 7777; e.high_port = 49001;
        e.plan_id[0] = 7; e.trial_id[0] = 8; e.execution_id = 99;
        e.planned = D2K_LINK_PLANNED_YES; e.client_shape = D2K_LINK_SHAPE_RAW;
        e.code = codes[k];
        if (early) { e.kind = D2K_EV_EXCHANGE; on_exchange(s, &e); }
        e.kind = D2K_EV_APPLIED; on_applied(s, &e);
        if (!early) { e.kind = D2K_EV_EXCHANGE; on_exchange(s, &e); }
        int valid = codes[k] == D2K_RAW_PROOF_ECHO || codes[k] == D2K_RAW_PROOF_PROGRESS;
        CHECK(valid ? s->confirms == 1 : !s->confirms && t->state == T_RAW_WATCH,
              "RAW confirmation accepted an unproven response or lost valid path proof");
        d2k_sched_free(s); d2k_catalog_free(&cat);
    }
}
static ssize_t next_frame(int fd,uint8_t *frame,size_t cap) {
    struct pollfd p={fd,POLLIN,0};return poll(&p,1,100)>0 ? read(fd,frame,cap) : -1;
}
static void raw_candidate_cycle_test(void) {
    for(int family=4;family<=6;family+=2) for(int tr=6;tr<=17;tr+=11) {
        int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"cycle socket");
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2e);
        CHECK(s!=NULL,"cycle scheduler");if(!s){close(sv[0]);close(sv[1]);continue;}
        d2k_ev e={0};e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;
        e.family=(uint8_t)family;e.transport=(uint8_t)tr;e.client_shape=D2K_LINK_SHAPE_RAW;
        e.client_side=D2K_CLIENT_SIDE_HIGH;e.low_ip[0]=1;e.high_ip[0]=192;
        e.low_port=7777;e.high_port=49001;e.flow_epoch[0]=7;e.flow_incarnation=1234;
        raw_suspect(s,&e);struct d2k_rawmeasure_request request={0};
        CHECK(!read_request(sv[1],&request),"cycle measure not requested");
        d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_RAW_MEASURE;ack.num=0x100;
        memcpy(ack.trial_id,request.token,16);d2k_sched_event(s,&ack);
        d2k_ev result={0};result.kind=D2K_EV_RAW_MEASURE;result.raw_measure.request=request;
        result.raw_measure.code=D2K_RM_REPEAT_SILENT;result.raw_measure.sample_len=20;
        result.raw_measure.smallest_data=20;result.raw_measure.largest_data=20;
        result.raw_measure.client_data=2;result.raw_measure.exact_repeats=1;result.raw_measure.sample_digest[0]=1;
        if(tr==17)result.raw_measure.flags=D2K_RM_PRIOR_REPLY;
        d2k_sched_event(s,&result);
        char ip[INET6_ADDRSTRLEN];inet_ntop(family==6?AF_INET6:AF_INET,e.low_ip,ip,sizeof ip);
        task *t=task_of(s,ip,(uint8_t)tr,(uint8_t)family);
        CHECK(t&&t->state==T_RAW_MEASURED,"cycle result not consumed");
        if(!t){d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);continue;}
        raw_measured_try(s,t);uint8_t frame[4096];ssize_t n=next_frame(sv[1],frame,sizeof frame);
        CHECK(n>(ssize_t)(6+D2K_RM_REPORT_LEN+20)&&frame[5]==D2K_CMD_SET_RAW_PROBE,"cycle guarded candidate absent");
        CHECK(t->state==T_RAW_TRIAL&&!cat.n_boxes,"cycle candidate prematurely confirmed");
        CHECK(strstr(t->plans[0],tr==6?"split payload_start +10":"ipfrag 1")!=NULL,"cycle candidate form wrong");
        ack.code=D2K_CMD_SET_RAW_PROBE;memcpy(ack.trial_id,t->addr_probe_trial_id,16);
        d2k_sched_event(s,&ack);CHECK(t->state==T_RAW_TRIAL&&!cat.n_boxes,"ACK promoted candidate");
        e.kind=D2K_EV_APPLIED;e.execution_id=991;memcpy(e.plan_id,t->ver_plan_id,16);
        memcpy(e.trial_id,t->addr_probe_trial_id,16);e.planned=D2K_LINK_PLANNED_YES;
        d2k_sched_event(s,&e);CHECK(t->state==T_RAW_WATCH&&!cat.n_boxes,"application not tracked or promoted alone");
        e.kind=D2K_EV_EXCHANGE;e.code=D2K_RAW_PROOF_ECHO;e.execution_id=990;d2k_sched_event(s,&e);
        CHECK(t->state==T_RAW_WATCH&&!cat.n_boxes,"stale measured execution promoted");
        e.execution_id=991;d2k_sched_event(s,&e);
        CHECK(t->state==T_WATCHING&&s->confirms==1&&cat.n_boxes==1,"exact measured reply did not confirm path");
        if(cat.n_boxes)CHECK(cat.boxes[0].n_binds==1&&cat.boxes[0].binds[0].server_port==7777&&
           cat.boxes[0].binds[0].transport==tr&&cat.boxes[0].binds[0].shape==D2K_LINK_SHAPE_RAW,
           "path proof escaped service/transport/shape scope");
        n=next_frame(sv[1],frame,sizeof frame);
        CHECK(n==60&&frame[5]==D2K_CMD_DEL_ADDR_PROBE&&frame[43]==tr,"confirmed candidate not retired exactly");
        e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.planned=D2K_LINK_PLANNED_NO;e.flow_incarnation++;
        e.execution_id=0;memset(e.plan_id,0,16);memset(e.trial_id,0,16);
        raw_suspect(s,&e);
        CHECK(!read_request(sv[1],&request),"own catalog plan skipped measurement or used legacy port-only trial");
        ack.code=D2K_CMD_RAW_MEASURE;memcpy(ack.trial_id,request.token,16);d2k_sched_event(s,&ack);
        result.raw_measure.request=request;d2k_sched_event(s,&result);
        t=task_of(s,ip,(uint8_t)tr,(uint8_t)family);
        CHECK(t&&t->state==T_RAW_MEASURED,"catalog retry not bound to new measurement");
        if(t&&t->state==T_RAW_MEASURED) {
            raw_measured_try(s,t);n=next_frame(sv[1],frame,sizeof frame);
            CHECK(n>(ssize_t)(6+D2K_RM_REPORT_LEN+20)&&frame[5]==D2K_CMD_SET_RAW_PROBE,
                  "catalog retry escaped guarded command");
            CHECK(!strcmp(t->raw_plan_id,cat.boxes[0].plans[0].id),"catalog candidate not reused first");
            e.kind=D2K_EV_REFUSED;e.code=7;e.execution_id=0;
            memcpy(e.plan_id,t->ver_plan_id,16);memcpy(e.trial_id,t->addr_probe_trial_id,16);
            e.trial_id[0]^=1;d2k_sched_event(s,&e);CHECK(t->state==T_RAW_TRIAL,"foreign local failure retired candidate");
            memcpy(e.trial_id,t->addr_probe_trial_id,16);d2k_sched_event(s,&e);
            CHECK(t->state==T_FREE&&cat.n_boxes==1&&s->confirms==1,"local execution refusal ignored or changed confirmed knowledge");
        }
        d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);
    }
}
static void raw_late_dispatch_test(void) {
    for(int tr=6;tr<=17;tr+=11) {
        int sv[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,sv)){CHECK(0,"late socket");return;}
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2e);if(!s)return;
        s->ct_query=raw_ct_fixture;s->now_ms=100000;
        d2k_ev e={0};e.kind=D2K_EV_FLOW;e.family=4;e.transport=(uint8_t)tr;
        e.low_ip[0]=1;e.high_ip[0]=192;e.low_port=7777;e.high_port=49001;
        e.client_side=D2K_CLIENT_SIDE_HIGH;e.flow_epoch[0]=9;e.flow_incarnation=123;
        flowwatch_add(s,&e,NULL,1);flow_watch *w=&s->flowwatch[0];
        w->had_reply=1;w->sil_steps=SCHED_FLOWWATCH_STALL_STEPS;w->sil_orig=10;w->orig_pkts=13;
        d2k_ct_info ci={0};ci.orig_pkts=13;ci.tcp_state_known=1;ci.tcp_state=D2K_CT_TCP_ESTABLISHED;
        CHECK(late_silence_due(w,&ci,s->now_ms),"raw late packet observation not eligible");
        ci.orig_pkts=10;CHECK(!late_silence_due(w,&ci,s->now_ms),"idle stream started observation");ci.orig_pkts=13;
        w->had_reply=0;CHECK(!late_silence_due(w,&ci,s->now_ms),"one-way stream treated as late stall");w->had_reply=1;
        late_observe_ask(s,w);struct d2k_rawmeasure_request r={0};
        CHECK(!read_request(sv[1],&r),"raw late dispatch used redundant TCP-only observation");
        CHECK(w->obs_asked_ms&&!memcmp(w->obs_token,r.token,16),"late request owner not retained");
        d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_RAW_MEASURE;ack.num=0;
        memcpy(ack.trial_id,r.token,16);d2k_sched_event(s,&ack);
        CHECK(!w->obs_asked_ms&&w->obs_fails==1&&w->rearm_ms>s->now_ms,"raw late refusal did not rearm with backoff");
        CHECK(!late_silence_due(w,&ci,s->now_ms),"failed observation immediately repeated");
        task *old=calloc(1,sizeof *old);CHECK(old!=NULL,"late duplicate context");
        if(old){old->raw_measure_request=r;raw_measure_watch_done(s,old,-1);free(old);}
        CHECK(w->obs_fails==1,"duplicate terminal observation doubled backoff");
        d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);
    }
}
static void raw_parallel_scope_test(void) {
    for(int variant=0;variant<6;variant++) {
        int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"parallel socket");
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2e);
        d2k_ev e={0};e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.family=4;e.transport=6;
        e.client_shape=D2K_LINK_SHAPE_RAW;e.client_side=D2K_CLIENT_SIDE_HIGH;
        e.low_ip[0]=1;e.high_ip[0]=192;e.low_port=7777;e.high_port=49001;
        e.flow_epoch[0]=1;e.flow_incarnation=1;
        if(variant==5)for(size_t i=0;i<SCHED_MAX_TASKS;i++)s->tasks[i].state=T_WATCHING;
        raw_suspect(s,&e);struct d2k_rawmeasure_request first={0},second={0};
        CHECK(!read_request(sv[1],&first),"first parallel measurement absent");
        task *old=task_of(s,"1.0.0.0",6,4);CHECK(old!=NULL,"parallel first task absent");
        if(!old){d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);continue;}
        if(variant==5){d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);continue;}
        old->state=variant%2?T_RAW_WATCH:T_RAW_TRIAL;
        if(variant>=3) {
            old->trial_installed=1;old->addr_probe_identity_valid=1;old->addr_probe_trial_id[0]=55;
            memcpy(old->addr_probe_src_ip,first.tuple.src,16);memcpy(old->addr_probe_dst_ip,first.tuple.dst,16);
            memcpy(&old->addr_probe_src_port_be,first.tuple.sport_be,2);
            memcpy(&old->addr_probe_dst_port_be,first.tuple.dport_be,2);
        }
        raw_suspect(s,&e);struct pollfd poller={sv[1],POLLIN,0};
        CHECK(poll(&poller,1,10)==0,"same active measured trial duplicated");
        if(variant==0)e.low_port++;
        if(variant==1)e.high_ip[3]++;
        if(variant==2)e.high_port++;
        if(variant==3)e.flow_incarnation++;
        if(variant==4)e.flow_epoch[0]++;
        raw_suspect(s,&e);
        if(variant>=3) {
            uint8_t frame[60]={0};struct pollfd p={sv[1],POLLIN,0};
            ssize_t n=poll(&p,1,100)>0?recv(sv[1],frame,sizeof frame,MSG_WAITALL):-1;
            CHECK(n==60&&frame[5]==D2K_CMD_DEL_ADDR_PROBE&&frame[43]==6&&frame[44]==55,
                  "replacement generation did not retire exact owned trial");
        }
        CHECK(!read_request(sv[1],&second),"active RAW trial blocked another service/client/incarnation");
        CHECK(second.generation==e.flow_incarnation&&!memcmp(second.epoch,e.flow_epoch,16),"new RAW identity lost");
        if(variant<3)CHECK(old->state==(variant%2?T_RAW_WATCH:T_RAW_TRIAL),"neighbor request cancelled owned trial");
        d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);
    }
}
static void raw_cooldown_scope_test(void) {
    for(int variant=0;variant<4;variant++) {
        int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"cooldown socket");
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2e);s->now_ms=1000;
        d2k_ev e={0};e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.family=4;e.transport=17;
        e.client_shape=D2K_LINK_SHAPE_RAW;e.client_side=D2K_CLIENT_SIDE_HIGH;
        e.low_ip[0]=1;e.high_ip[0]=192;e.low_port=7777;e.high_port=49001;
        e.flow_epoch[0]=1;e.flow_incarnation=1;
        raw_suspect(s,&e);struct d2k_rawmeasure_request r={0};
        CHECK(!read_request(sv[1],&r),"cooldown first measurement absent");
        task *t=task_of(s,"1.0.0.0",17,4);CHECK(t!=NULL,"cooldown task absent");
        if(t){cooldown_record(s,t,2);task_done(s,t);}
        raw_suspect(s,&e);struct pollfd p={sv[1],POLLIN,0};
        CHECK(poll(&p,1,10)==0,"same failed incarnation ignored cooldown");
        if(variant==0)e.low_port++;
        if(variant==1)e.high_ip[3]++;
        if(variant==3)e.flow_epoch[0]++;else e.flow_incarnation++;
        raw_suspect(s,&e);
        CHECK(!read_request(sv[1],&r),"RAW cooldown escaped failed incarnation");
        d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);
    }
}
static void raw_oneway_diagnostic_test(void) {
    int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"one-way socket");
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2e);
    d2k_ev e={0};e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.family=4;e.transport=17;
    e.client_shape=D2K_LINK_SHAPE_RAW;e.client_side=D2K_CLIENT_SIDE_HIGH;
    e.low_ip[0]=1;e.high_ip[0]=192;e.low_port=7777;e.high_port=49001;e.flow_epoch[0]=1;e.flow_incarnation=1;
    raw_suspect(s,&e);struct d2k_rawmeasure_request r={0};CHECK(!read_request(sv[1],&r),"one-way measure absent");
    d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_RAW_MEASURE;ack.num=0x100;
    memcpy(ack.trial_id,r.token,16);d2k_sched_event(s,&ack);
    d2k_ev result={0};result.kind=D2K_EV_RAW_MEASURE;result.raw_measure.request=r;
    result.raw_measure.code=D2K_RM_UNINFORMATIVE;result.raw_measure.sample_len=20;
    result.raw_measure.smallest_data=20;result.raw_measure.largest_data=20;
    result.raw_measure.client_data=2;result.raw_measure.exact_repeats=1;result.raw_measure.sample_digest[0]=1;
    d2k_sched_event(s,&result);
    CHECK(!task_of(s,"1.0.0.0",17,4)&&!cat.n_boxes,"one-way result kept active task or candidate");
    CHECK(s->unknowns[0].used&&!strcmp(s->unknowns[0].reason,"reply-unknown"),"unknown response expectation lacks exact diagnostic code");
    struct pollfd p={sv[1],POLLIN,0};CHECK(poll(&p,1,10)==0,"one-way diagnostic installed a candidate");
    d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);
}
static void raw_concurrent_completion_test(void) {
    for(int family=4;family<=6;family+=2)for(int tr=6;tr<=17;tr+=11) {
        int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"concurrent proof socket");
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2e);
        d2k_ev e[2];memset(e,0,sizeof e);task *owned[2]={0};uint8_t frame[4096];
        for(unsigned k=0;k<2;k++) {
            e[k].kind=D2K_EV_SUSPECT;e[k].code=D2K_SUSPECT_SILENT;e[k].family=(uint8_t)family;e[k].transport=(uint8_t)tr;
            e[k].client_shape=D2K_LINK_SHAPE_RAW;e[k].client_side=D2K_CLIENT_SIDE_HIGH;
            e[k].low_ip[0]=1;e[k].high_ip[0]=192;e[k].high_ip[3]=(uint8_t)k;
            e[k].low_port=(uint16_t)(7777+k);e[k].high_port=49001;e[k].flow_epoch[0]=1;e[k].flow_incarnation=k+1;
            raw_suspect(s,&e[k]);struct d2k_rawmeasure_request r={0};CHECK(!read_request(sv[1],&r),"parallel request absent");
            d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_RAW_MEASURE;ack.num=0x100;
            memcpy(ack.trial_id,r.token,16);d2k_sched_event(s,&ack);
            d2k_ev result={0};result.kind=D2K_EV_RAW_MEASURE;result.raw_measure.request=r;
            result.raw_measure.code=D2K_RM_REPEAT_SILENT;result.raw_measure.sample_len=20;
            result.raw_measure.smallest_data=20;result.raw_measure.largest_data=20;
            result.raw_measure.client_data=2;result.raw_measure.exact_repeats=1;result.raw_measure.sample_digest[0]=1;
            if(tr==17)result.raw_measure.flags=D2K_RM_PRIOR_REPLY;
            d2k_sched_event(s,&result);
            for(size_t i=0;i<SCHED_MAX_TASKS;i++)if(s->tasks[i].state==T_RAW_MEASURED&&
                !memcmp(s->tasks[i].raw_measure_request.token,r.token,16))owned[k]=&s->tasks[i];
            CHECK(owned[k]!=NULL,"parallel measurement owner absent");
            if(!owned[k])continue;
            raw_measured_try(s,owned[k]);CHECK(next_frame(sv[1],frame,sizeof frame)>0,"parallel candidate missing");
            ack.code=D2K_CMD_SET_RAW_PROBE;memcpy(ack.trial_id,owned[k]->addr_probe_trial_id,16);d2k_sched_event(s,&ack);
            e[k].kind=D2K_EV_EXCHANGE;e[k].code=D2K_RAW_PROOF_ECHO;e[k].planned=D2K_LINK_PLANNED_YES;e[k].execution_id=100+k;
            memcpy(e[k].plan_id,owned[k]->ver_plan_id,16);memcpy(e[k].trial_id,owned[k]->addr_probe_trial_id,16);
        }
        if(owned[0]&&owned[1]) {
            d2k_ev wrong=e[1];memcpy(wrong.trial_id,owned[0]->addr_probe_trial_id,16);
            d2k_sched_event(s,&wrong);wrong.kind=D2K_EV_APPLIED;d2k_sched_event(s,&wrong);
            CHECK(!s->confirms&&owned[0]->state==T_RAW_TRIAL&&owned[1]->state==T_RAW_TRIAL,"crossed parallel evidence consumed");
            d2k_sched_event(s,&e[1]);e[1].kind=D2K_EV_APPLIED;d2k_sched_event(s,&e[1]);
            CHECK(s->confirms==1&&owned[0]->state==T_RAW_TRIAL&&owned[1]->state==T_WATCHING,"second completion altered first task");
            CHECK(next_frame(sv[1],frame,60)==60&&frame[5]==D2K_CMD_DEL_ADDR_PROBE&&frame[43]==tr&&
                  !memcmp(frame+44,e[1].trial_id,16),"parallel cleanup removed another trial");
            e[0].kind=D2K_EV_APPLIED;d2k_sched_event(s,&e[0]);e[0].kind=D2K_EV_EXCHANGE;d2k_sched_event(s,&e[0]);
            CHECK(s->confirms==2&&owned[0]->state==T_WATCHING,"first completion lost after second");
            CHECK(next_frame(sv[1],frame,60)==60&&frame[5]==D2K_CMD_DEL_ADDR_PROBE&&
                  !memcmp(frame+44,e[0].trial_id,16),"first cleanup lost trial identity");
            CHECK(cat.n_boxes==1&&cat.boxes[0].n_binds==2,"parallel path evidence not persisted independently");
            if(cat.n_boxes==1&&cat.boxes[0].n_binds==2) {
                CHECK(cat.boxes[0].binds[0].server_port!=cat.boxes[0].binds[1].server_port,"parallel service scopes collapsed");
                CHECK(cat.boxes[0].binds[0].transport==tr&&cat.boxes[0].binds[1].family==family,"parallel transport/family changed");
            }
        }
        d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);
    }
}
/* Frames the controller sent since the last call, split by the 4-byte length. */
typedef struct { uint16_t type; size_t len; uint8_t body[4096]; } sent_frame;
static size_t sent_frames(int fd,sent_frame *out,size_t cap) {
    static uint8_t buf[65536];static size_t have;size_t n=0;
    for(;;){struct pollfd p={fd,POLLIN,0};if(poll(&p,1,0)<=0)break;
        ssize_t r=read(fd,buf+have,sizeof buf-have);if(r<=0)break;have+=(size_t)r;}
    while(have>=6) {
        size_t len=(size_t)buf[0]<<24|(size_t)buf[1]<<16|(size_t)buf[2]<<8|buf[3];
        if(have<4+len)break;
        if(n<cap&&len-2<=sizeof out[n].body){out[n].type=(uint16_t)(buf[4]<<8|buf[5]);out[n].len=len-2;
            memcpy(out[n].body,buf+6,len-2);n++;}
        memmove(buf,buf+4+len,have-4-len);have-=4+len;
    }
    return n;
}
/* Slow TCP retransmission (RTO backoff): the measured repeat came 64 s after
   its copy, so the next one is due up to 128 s later. The trial must outlive
   it, each datapath lease must stay within the per-command maximum and be
   renewed without a gap, and a renewal must carry the identical evidence,
   trial and plan. variant 0: retransmission arrives at +128 s and confirms;
   1: none arrives — trial ends no-retry, bounded; 2: renewal refused — own
   context ends unknown, not no-retry; 3: renewal never acknowledged; 4: renewal
   refusal after execution leaves the executed trial's verdict intact. */
static void raw_slow_retransmission_test(void) {
    for(int variant=0;variant<7;variant++) {
        int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"slow socket");
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2e);
        CHECK(s!=NULL,"slow scheduler");if(!s){close(sv[0]);close(sv[1]);continue;}
        const int64_t T0=1000000;d2k_sched_tick(s,T0-1000);
        d2k_ev e={0};e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;e.family=4;e.transport=6;
        e.client_shape=D2K_LINK_SHAPE_RAW;e.client_side=D2K_CLIENT_SIDE_HIGH;
        e.low_ip[0]=1;e.high_ip[0]=192;e.low_port=7777;e.high_port=49001;
        e.flow_epoch[0]=5;e.flow_incarnation=77;
        raw_suspect(s,&e);struct d2k_rawmeasure_request request={0};
        CHECK(!read_request(sv[1],&request),"slow measure absent");
        d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_RAW_MEASURE;ack.num=0x100;
        memcpy(ack.trial_id,request.token,16);d2k_sched_event(s,&ack);
        d2k_ev result={0};result.kind=D2K_EV_RAW_MEASURE;result.raw_measure.request=request;
        result.raw_measure.code=D2K_RM_REPEAT_SILENT;result.raw_measure.sample_len=20;
        result.raw_measure.smallest_data=20;result.raw_measure.largest_data=20;result.raw_measure.sample_seq=4000;
        result.raw_measure.client_data=2;result.raw_measure.exact_repeats=1;result.raw_measure.sample_digest[0]=1;
        result.raw_measure.repeat_gap_ms=variant==5?0:64000;result.raw_measure.repeat_age_ms=0;
        d2k_sched_event(s,&result);
        task *t=task_of(s,"1.0.0.0",6,4);CHECK(t&&t->state==T_RAW_MEASURED,"slow result not consumed");
        if(!t){d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);continue;}
        sent_frame f[16];uint8_t first[sizeof f[0].body];size_t first_len=0;
        int64_t lease_end=0,pending_end=0,pending_at=0;int installs=0,renewals=0,gap=0,changed=0,late_ack=0;
        uint8_t trial[16]={0};int executed=0,deleted=0;
        int64_t applied_at=variant==4?T0+100000:T0+128000,last=T0+300000,ended=0;
        for(int64_t now=T0;now<=last;now+=1000) {
            if(variant==6 && now==T0+1000)now=T0+121000; /* scheduler pause past lease */
            d2k_sched_tick(s,now);
            size_t n=sent_frames(sv[1],f,16);
            for(size_t k=0;k<n;k++) {
                if(f[k].type==D2K_CMD_DEL_ADDR_PROBE)deleted++;
                if(f[k].type!=D2K_CMD_SET_RAW_PROBE)continue;
                uint32_t lease=d2k_rm_get32(f[k].body+D2K_RM_REPORT_LEN+16);
                CHECK(lease&&lease<=D2K_ADDR_PROBE_LEASE_MAX_MS,"trial lease beyond per-command maximum");
                if(!installs++){memcpy(first,f[k].body,f[k].len);first_len=f[k].len;
                    memcpy(trial,f[k].body+D2K_RM_REPORT_LEN,16);}
                else {
                    renewals++;
                    /* Lease bytes may differ; report, trial and plan must not. */
                    if(f[k].len!=first_len||memcmp(f[k].body,first,D2K_RM_REPORT_LEN+16)||
                       memcmp(f[k].body+D2K_RM_REPORT_LEN+20,first+D2K_RM_REPORT_LEN+20,first_len-D2K_RM_REPORT_LEN-20))changed=1;
                }
                pending_end=now+lease;pending_at=now;
                if(variant==5)continue; /* initial install never acknowledged */
                if(variant==4&&renewals==1){late_ack=1;continue;} /* acknowledged after execution */
                if(variant==3&&renewals==1)continue;              /* never acknowledged */
                ack.code=D2K_CMD_SET_RAW_PROBE;ack.num=(variant==2&&renewals==1)?0x003:0x100;
                memcpy(ack.trial_id,trial,16);d2k_sched_event(s,&ack);
                if(ack.num==0x100&&pending_end>lease_end)lease_end=pending_end;
            }
            (void)pending_at;
            if(t->state!=T_RAW_TRIAL&&t->state!=T_RAW_WATCH){ended=now;break;}
            if(t->state==T_RAW_TRIAL&&now<applied_at&&lease_end<=now)gap=1;
            if(variant==0||variant==4) if(now==applied_at) {
                e.kind=D2K_EV_APPLIED;e.execution_id=4242;memcpy(e.plan_id,t->ver_plan_id,16);
                memcpy(e.trial_id,trial,16);e.planned=D2K_LINK_PLANNED_YES;d2k_sched_event(s,&e);
                executed=t->state==T_RAW_WATCH;
                if(variant==4&&late_ack){ack.code=D2K_CMD_SET_RAW_PROBE;ack.num=0x003;
                    memcpy(ack.trial_id,trial,16);d2k_sched_event(s,&ack);}
                e.kind=D2K_EV_EXCHANGE;e.code=D2K_RAW_PROOF_ECHO;d2k_sched_event(s,&e);
            }
        }
        {size_t n=sent_frames(sv[1],f,16);for(size_t k=0;k<n;k++)if(f[k].type==D2K_CMD_DEL_ADDR_PROBE)deleted++;}
        CHECK(installs==1+renewals&&!changed,"renewal changed evidence, trial or plan");
        if(variant==6)CHECK(!renewals,"expired lease revived after scheduler pause");
        if(variant==0||variant==4) {
            CHECK(executed,"slow retransmission not owned by live trial");
            CHECK(!gap,"datapath lease lapsed before slow retransmission");
            CHECK(renewals>=1,"trial outliving one lease was not renewed");
            CHECK(t->state==T_WATCHING&&s->confirms==1,"slow retransmission did not confirm path");
        } else {
            CHECK(t->state==T_FREE&&!cat.n_boxes&&!s->confirms,"slow trial context leaked or promoted");
            CHECK(deleted>=1,"slow trial not retired from datapath");
            const char *why=s->unknowns[0].used?s->unknowns[0].reason:"";
            if(variant==1) {
                CHECK(ended>T0+128000,"trial expired before a slow TCP retransmission was due");
                CHECK(ended&&ended<last,"silent trial window unbounded");
                CHECK(!strcmp(why,"no-retry"),"bounded silent window not reported no-retry");
                CHECK(!gap,"datapath lease lapsed inside the trial window");
            } else CHECK(strcmp(why,"no-retry")&&strcmp(why,"plan-silent")&&why[0],
                         "lost renewal reported as client/server behaviour");
        }
        d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);
    }
}
/* The window is a function of reported facts only. */
static void raw_window_derivation_test(void) {
    struct d2k_rawmeasure_report r={0};r.request.seconds=120;r.exact_repeats=1;
    r.request.tuple.proto=6;
    CHECK(raw_trial_window_ms(&r)==SCHED_RAW_TRIAL_MS,"untimed report changed the legacy window");
    r.repeat_gap_ms=64000;CHECK(raw_trial_window_ms(&r)==SCHED_RAW_TRIAL_MS+128000,"TCP window not two measured intervals");
    r.repeat_age_ms=30000;CHECK(raw_trial_window_ms(&r)==SCHED_RAW_TRIAL_MS+98000,"elapsed age not subtracted");
    r.repeat_age_ms=500000;CHECK(raw_trial_window_ms(&r)==SCHED_RAW_TRIAL_MS,"age beyond due time not clamped");
    r.repeat_age_ms=0;r.repeat_gap_ms=UINT32_MAX;
    CHECK(raw_trial_window_ms(&r)==SCHED_RAW_TRIAL_MS+270000,"interval not bounded by its observation lease");
    r.request.tuple.proto=17;r.repeat_gap_ms=64000;
    CHECK(raw_trial_window_ms(&r)==SCHED_RAW_TRIAL_MS+64000,"UDP assumed TCP backoff");
    CHECK(raw_trial_lease_ms(SCHED_RAW_TRIAL_MS+128000)==D2K_ADDR_PROBE_LEASE_MAX_MS&&raw_trial_lease_ms(5000)==5000&&
          raw_trial_lease_ms(-3)==1,"per-command lease not bounded");
}
static void raw_observation_renewal_test(void) {
    for(int mode=0;mode<4;mode++) {
        int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"observation socket");
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2e);
        if(!s){close(sv[0]);close(sv[1]);continue;}
        s->now_ms=1000000;
        d2k_ev e={0};e.kind=D2K_EV_SUSPECT;e.code=D2K_SUSPECT_SILENT;
        e.family=4;e.transport=6;e.client_shape=D2K_LINK_SHAPE_RAW;
        e.client_side=D2K_CLIENT_SIDE_HIGH;e.low_ip[0]=1;e.high_ip[0]=192;
        e.low_port=7777;e.high_port=49001;e.flow_epoch[0]=7;e.flow_incarnation=1234;
        raw_suspect(s,&e);
        struct d2k_rawmeasure_request r={0},renew={0};
        CHECK(!read_request(sv[1],&r)&&!r.renew,"initial request marked renewal");
        d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_RAW_MEASURE;ack.num=0x100;
        memcpy(ack.trial_id,r.token,16);d2k_sched_event(s,&ack);
        task *t=task_of(s,"1.0.0.0",6,4);
        CHECK(t&&t->state==T_RAW_MEASURE_OBSERVE,"observation readiness");
        if(!t){d2k_sched_free(s);close(sv[0]);close(sv[1]);continue;}
        d2k_sched_tick(s,1060000);
        CHECK(!read_request(sv[1],&renew)&&renew.renew,"renew-only command missing");
        renew.renew=0;
        uint8_t a[D2K_RM_REQUEST_LEN],b[D2K_RM_REQUEST_LEN];
        CHECK(!d2k_rawmeasure_request_write(a,sizeof a,&r)&&
              !d2k_rawmeasure_request_write(b,sizeof b,&renew)&&!memcmp(a,b,sizeof a),
              "renewal changed identity or terms");
        if(mode==1) {
            d2k_sched_tick(s,1120000);
            CHECK(t->state==T_FREE,"lost renewal ACK leaked observation task");
        } else if(mode==2) {
            ack.num=0;d2k_sched_event(s,&ack);
            CHECK(t->state==T_FREE,"refused renewal leaked observation task");
        } else {
            d2k_sched_event(s,&ack);
            d2k_sched_tick(s,1120000);CHECK(!read_request(sv[1],&renew)&&renew.renew,"second renewal missing");
            d2k_sched_event(s,&ack);
            d2k_sched_tick(s,1180000);CHECK(!read_request(sv[1],&renew)&&renew.renew,"third renewal missing");
            CHECK(t->state==T_RAW_MEASURE_OBSERVE,"old120s deadline lost slow sample");
            if(mode==0) {
                d2k_ev result={0};result.kind=D2K_EV_RAW_MEASURE;
                result.raw_measure.request=r;result.raw_measure.code=D2K_RM_REPEAT_SILENT;
                result.raw_measure.sample_len=20;result.raw_measure.smallest_data=20;
                result.raw_measure.largest_data=20;result.raw_measure.sample_digest[0]=1;
                result.raw_measure.client_data=2;result.raw_measure.exact_repeats=1;
                result.raw_measure.repeat_gap_ms=128000;
                d2k_sched_event(s,&result);
                CHECK(t->state==T_RAW_MEASURED,"slow measurement not consumed");
                ack.num=0;d2k_sched_event(s,&ack);
                CHECK(t->state==T_RAW_MEASURED,"late renewal refusal destroyed completed evidence");
            } else {
                d2k_sched_event(s,&ack);
                d2k_sched_tick(s,1240000);CHECK(!read_request(sv[1],&renew),"fourth renewal missing");
                d2k_sched_event(s,&ack);d2k_sched_tick(s,1270000);
                CHECK(t->state==T_FREE,"acknowledged heartbeats extended phase deadline forever");
            }
        }
        d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);
    }
}
int main(void) {
    raw_observation_renewal_test();
    raw_window_derivation_test();
    raw_slow_retransmission_test();
    raw_concurrent_completion_test();
    raw_oneway_diagnostic_test();
    raw_cooldown_scope_test();
    raw_parallel_scope_test();
    raw_proof_identity_test();
    raw_proof_kind_test();
    raw_candidate_cycle_test();
    raw_late_dispatch_test();
    int sv[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,sv))return 2;
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2e);if(!s)return 2;
    d2k_ev ev={0};ev.kind=D2K_EV_SUSPECT;ev.code=D2K_SUSPECT_SILENT;ev.family=4;ev.transport=6;
    ev.client_shape=D2K_LINK_SHAPE_RAW;ev.client_side=D2K_CLIENT_SIDE_HIGH;ev.planned=D2K_LINK_PLANNED_NO;
    ev.low_ip[0]=1;ev.high_ip[0]=192;ev.low_port=7777;ev.high_port=49001;
    ev.flow_epoch[0]=9;ev.flow_incarnation=123;
    raw_suspect(s,&ev);
    struct d2k_rawmeasure_request request={0};
    CHECK(!read_request(sv[1],&request),"empty catalog did not start exact-flow measurement");
#ifdef D2K_SCHED_RAW_MEASUREMENT
    CHECK(request.tuple.src[0]==192&&request.tuple.dst[0]==1&&request.generation==123&&request.epoch[0]==9,"measurement changed client or incarnation");
    task *t=task_of(s,"1.0.0.0",6,4);CHECK(t&&t->state==T_RAW_MEASURE_ACK,"measurement pending state missing");
    raw_suspect(s,&ev);struct pollfd p={sv[1],POLLIN,0};CHECK(poll(&p,1,10)==0,"duplicate suspicion launched another measure");
    d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_RAW_MEASURE;ack.num=0x100;
    memcpy(ack.trial_id,request.token,16);ack.trial_id[0]^=1;d2k_sched_event(s,&ack);
    CHECK(t&&t->state==T_RAW_MEASURE_ACK,"foreign ACK activated measurement");
    memcpy(ack.trial_id,request.token,16);d2k_sched_event(s,&ack);
    CHECK(t&&t->state==T_RAW_MEASURE_OBSERVE,"own readiness ACK ignored");
    d2k_ev result={0};result.kind=D2K_EV_RAW_MEASURE;result.raw_measure.request=request;
    result.raw_measure.code=D2K_RM_SERVER_PRESENT;result.raw_measure.server_packets=1;
    result.raw_measure.flags=D2K_RM_TCP_ACK;result.raw_measure.sample_len=20;
    result.raw_measure.smallest_data=20;result.raw_measure.largest_data=20;
    result.raw_measure.client_data=1;result.raw_measure.sample_digest[0]=1;
    result.raw_measure.sample_seq=1000;result.raw_measure.tcp_ack=1000;
    d2k_sched_event(s,&result);
    CHECK(t&&t->state==T_RAW_MEASURE_OBSERVE,"duplicate ACK falsely ended observation");
    result.raw_measure.tcp_ack=1020;

    result.raw_measure.request.generation++;d2k_sched_event(s,&result);
    CHECK(t&&t->state==T_RAW_MEASURE_OBSERVE,"foreign incarnation completed measurement");
    result.raw_measure.request=request;d2k_sched_event(s,&result);
    CHECK(t&&t->state==T_FREE&&!cat.n_boxes,"server traffic promoted a strategy or left search running");
    CHECK(poll(&p,1,10)==0,"healthy direct response installed a candidate");
    ev.flow_incarnation++;raw_suspect(s,&ev);CHECK(!read_request(sv[1],&request),"new incarnation not measured");
    t=task_of(s,"1.0.0.0",6,4);memcpy(ack.trial_id,request.token,16);ack.num=0;
    d2k_sched_event(s,&ack);CHECK(t&&t->state==T_FREE&&!cat.n_boxes,"local refusal judged as strategy failure");
    ev.flow_incarnation++;raw_suspect(s,&ev);CHECK(!read_request(sv[1],&request),"repeat experiment did not start");
    t=task_of(s,"1.0.0.0",6,4);memcpy(ack.trial_id,request.token,16);ack.num=0x100;d2k_sched_event(s,&ack);
    memset(&result,0,sizeof result);result.kind=D2K_EV_RAW_MEASURE;result.raw_measure.request=request;
    result.raw_measure.code=D2K_RM_REPEAT_SILENT;result.raw_measure.client_data=2;result.raw_measure.exact_repeats=1;
    result.raw_measure.sample_digest[0]=1;
    result.raw_measure.sample_len=20;result.raw_measure.smallest_data=20;result.raw_measure.largest_data=20;
    result.raw_measure.request.tuple.dport_be[1]^=1;d2k_sched_event(s,&result);
    CHECK(t&&t->state==T_RAW_MEASURE_OBSERVE,"neighbor service facts consumed");
    result.raw_measure.request=request;result.raw_measure.request.epoch[0]^=1;d2k_sched_event(s,&result);
    CHECK(t&&t->state==T_RAW_MEASURE_OBSERVE,"old daemon epoch facts consumed");
    result.raw_measure.request=request;d2k_sched_event(s,&result);
    CHECK(t&&t->state==T_RAW_MEASURED&&t->raw_measure_report.sample_len==20&&!cat.n_boxes,"measured facts discarded or promoted without a trial");

#ifdef D2K_SCHED_RAW_CANDIDATE
    raw_measured_try(s,t);
    uint8_t frame[4096];struct pollfd candidate_poll={sv[1],POLLIN,0};
    CHECK(poll(&candidate_poll,1,100)>0,"measured candidate command absent");
    ssize_t bytes=next_frame(sv[1],frame,sizeof frame);
    CHECK(bytes>(ssize_t)(6+D2K_RM_REPORT_LEN+20) && frame[4]==0 && frame[5]==D2K_CMD_SET_RAW_PROBE,
          "measured trial used legacy unguarded command");
    struct d2k_rawmeasure_report sent_report={0};
    CHECK(bytes>(ssize_t)(6+D2K_RM_REPORT_LEN) && !d2k_rawmeasure_report_read(&sent_report,frame+6,D2K_RM_REPORT_LEN) &&
          sent_report.request.generation==request.generation,"candidate lost measurement generation");
    CHECK(t->state==T_RAW_TRIAL && t->addr_probe_identity_valid && !cat.n_boxes,
          "candidate installed as success or lost cleanup identity");
    CHECK(strstr(t->plans[0],"split payload_start +10")!=NULL,"split not derived from measured payload length");
    ack.code=D2K_CMD_SET_RAW_PROBE;ack.num=0;memcpy(ack.trial_id,t->addr_probe_trial_id,16);
    ack.trial_id[0]^=1;d2k_sched_event(s,&ack);CHECK(t->state==T_RAW_TRIAL,"foreign refusal ended candidate");
    memcpy(ack.trial_id,t->addr_probe_trial_id,16);d2k_sched_event(s,&ack);
    CHECK(t->state==T_FREE&&!cat.n_boxes,"own local refusal not retired without promotion");
    CHECK(poll(&candidate_poll,1,100)>0,"refusal did not clean own candidate");
    bytes=poll(&candidate_poll,1,100)>0 ? read(sv[1],frame,sizeof frame) : -1;
    CHECK(bytes==60&&frame[5]==D2K_CMD_DEL_ADDR_PROBE&&frame[6+37]==6,"TCP cleanup lost transport or exact tuple");
#else
    CHECK(0,"measured candidate construction not connected");
#endif
    if(t)task_done(s,t);
    s->ct_query=raw_ct_fixture;s->now_ms=100000;
    ev.kind=D2K_EV_FLOW;flowwatch_add(s,&ev,NULL,1);
    flow_watch *w=NULL;
    for(size_t i=0;i<SCHED_FLOWWATCH_SLOTS;i++)if(s->flowwatch[i].used){w=&s->flowwatch[i];break;}
    CHECK(w!=NULL,"raw FLOW missing watch");
    if(w) {
        w->sil_ms=70000;late_silence(s,w,2);
        CHECK(!read_request(sv[1],&request),"late raw silence did not start measured continuation");
        CHECK(request.generation==ev.flow_incarnation&&!memcmp(request.epoch,ev.flow_epoch,16),"late measurement lost flow identity");
        t=task_of(s,"1.0.0.0",6,4);if(t)task_done(s,t);
        flowwatch_conn_reset(w,100001);flowwatch_target(s,w,NULL);
        late_silence(s,w,2);
        CHECK(poll(&p,1,10)==0,"counter reset reused stale flow identity");
    }

#endif
    d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);
    if(fails)return 1;
    puts("raw measurement scheduler passed");return 0;
}
