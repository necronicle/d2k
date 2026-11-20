#define main scheduler_existing_main
#include "test_sched.c"
#undef main

static void catalogue(d2k_catalog *cat,int service_port,int same,int transport) {
    memset(cat,0,sizeof *cat);cat->boxes=calloc(1,sizeof *cat->boxes);cat->n_boxes=1;
    d2k_cat_box *b=cat->boxes;strcpy(b->id,"raw-own-box");
    b->plans=calloc(1,sizeof *b->plans);b->binds=calloc(1,sizeof *b->binds);b->n_plans=b->n_binds=1;
    d2k_cat_plan *p=b->plans;strcpy(p->id,"raw-own-plan");strcpy(p->proto,"tls");p->enabled=1;
    p->text=strdup(same?"d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\nsplit payload_start +10\norder forward\n":
        "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\norder forward\n");
    if(transport==17) {
        free(p->text);strcpy(p->proto,"quic");
        p->text=strdup(same?"d2k-plan 1 7\nid 00000000000000000000000000000000\nproto udp quic\nipfrag 1\n":
            "d2k-plan 1 7\nid 00000000000000000000000000000000\nproto udp quic\norder forward\n");
    }
    d2k_cat_binding *d=b->binds;
    strcpy(d->kind,"service");strcpy(d->target,"127.0.0.1");strcpy(d->plan_id,p->id);
    d->server_port=(uint16_t)service_port;d->transport=(uint8_t)transport;d->family=4;d->shape=D2K_LINK_SHAPE_RAW;
    d->enabled=1;d->level=3;d->confirmed=42;d->verified_by=D2K_VERBY_CLIENT;
}
static void refreshed_measurement(d2k_sched *s,int transport,unsigned len,int same_bytes,int expected) {
    struct d2k_rawmeasure_request request={0};int found=0;
    for(size_t off=0;off+6<=sent_len;) {
        const uint8_t *p=sentbuf+off;
        size_t n=((size_t)p[0]<<24)|((size_t)p[1]<<16)|((size_t)p[2]<<8)|p[3];
        if(n<2||n>sent_len-off-4)break;
        if(p[4]==0&&p[5]==D2K_CMD_RAW_MEASURE&&n==2+D2K_RM_REQUEST_LEN) {
            struct d2k_rawmeasure_request r;
            if(!d2k_rawmeasure_request_read(&r,p+6,D2K_RM_REQUEST_LEN)&&!r.renew){request=r;found++;}
        }
        off+=4+n;
    }
    CHECK(found==expected,"failed plan did not request a fresh measurement");
    if(found!=expected)return;
    d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_RAW_MEASURE;ack.num=0x100;
    memcpy(ack.trial_id,request.token,16);d2k_sched_event(s,&ack);
    d2k_ev result={0};result.kind=D2K_EV_RAW_MEASURE;result.raw_measure.request=request;
    result.raw_measure.code=D2K_RM_REPEAT_SILENT;result.raw_measure.sample_len=(uint16_t)len;
    result.raw_measure.smallest_data=result.raw_measure.largest_data=(uint16_t)len;
    result.raw_measure.client_data=2;result.raw_measure.exact_repeats=1;result.raw_measure.sample_digest[0]=same_bytes?1:2;
    if(transport==17)result.raw_measure.flags=D2K_RM_PRIOR_REPLY;
    d2k_sched_event(s,&result);spin(s,3);drain();
}
int main(void) {
    d2k_sched_mark_hook=stub_mark;d2k_sched_spawn_hook=stub_spawn;
    d2k_sched_cpu_hook=stub_cpu;d2k_sched_mem_hook=stub_mem;d2k_sched_ct_hook=stub_ct;
    int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"raw refine socketpair");
    drain_fd=sv[1];fcntl(drain_fd,F_SETFL,fcntl(drain_fd,F_GETFL,0)|O_NONBLOCK);g_server_port=443;
    for(int tr=6;tr<=17;tr+=11)for(int variant=0;variant<7;variant++) {
        const char *derived=tr==6?"raw-split-10":"raw-udp-fragment";
        d2k_catalog cat;catalogue(&cat,variant==0?8443:443,variant==3||variant==6,tr);
        d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2d);CHECK(s,"scheduler");if(!s)continue;
        d2k_sched_set_say(s,collect_say,NULL);forget_sent();saidbuf[0]=0;
        d2k_ev su=ev_suspect((uint8_t)tr,40700);su.code=D2K_SUSPECT_SILENT;su.client_shape=D2K_LINK_SHAPE_RAW;
        su.client_side=D2K_CLIENT_SIDE_HIGH;su.planned=D2K_LINK_PLANNED_NO;
        raw_measured_suspect_fixture(s,&su);spin(s,3);drain();
        CHECK(sent_command_count(D2K_CMD_SET_RAW_PROBE,NULL,0)==1,"first candidate installed once");
        if(!variant) {
            CHECK(said(derived)&&!said("проверяю raw-own-plan"),"service plan from a different server port was reused");
        } else {
            CHECK(said("проверяю raw-own-plan"),"matching service plan not tried first");
            d2k_ev old=ev_applied((uint8_t)tr,40700);old.execution_id=40700;
            if(variant==4){d2k_ev refused=old;refused.kind=D2K_EV_REFUSED;refused.code=1;d2k_sched_event(s,&refused);spin(s,2);}
            else if(variant!=2){d2k_sched_event(s,&old);spin(s,2);}
            g_now_ms+=45000;d2k_sched_tick(s,g_now_ms);drain();spin(s,3);
            CHECK(sent_command_count(D2K_CMD_SET_RAW_PROBE,NULL,0)==1,"stale measurement was reused before re-observation");
            if(variant==1||variant==3||variant==5||variant==6)
                refreshed_measurement(s,tr,(variant==3||variant==6)?20:18,variant==3,2);
            if(variant==1 || variant==5 || variant==6) {
                CHECK(sent_command_count(D2K_CMD_SET_RAW_PROBE,NULL,0)==2,"failed own plan did not reach measured construction");
                CHECK(said(tr==6?(variant==6?"raw-split-10":"raw-split-9"):derived),"refinement didn't use refreshed packet geometry");
                d2k_ev stale=ev_exchange((uint8_t)tr,40700,0);stale.execution_id=old.execution_id;
                memcpy(stale.plan_id,old.plan_id,16);memcpy(stale.trial_id,old.trial_id,16);stale.planned=D2K_LINK_PLANNED_YES;
                stale.code=D2K_RAW_PROOF_PROGRESS;
                d2k_sched_event(s,&stale);spin(s,2);
                CHECK(!said("ПОДТВЕРЖДЕНО продолжением клиента"),"old trial confirmed the new candidate");
                d2k_ev applied=ev_applied((uint8_t)tr,40700);applied.execution_id=40701;
                d2k_sched_event(s,&applied);spin(s,2);
                if(variant==5) {
                    d2k_ev reply=ev_exchange((uint8_t)tr,40700,0);reply.execution_id=applied.execution_id;
                    memcpy(reply.plan_id,applied.plan_id,16);memcpy(reply.trial_id,applied.trial_id,16);
                    reply.planned=D2K_LINK_PLANNED_YES;d2k_sched_event(s,&reply);spin(s,2);
                    CHECK(!said("ПОДТВЕРЖДЕНО продолжением клиента"),"uncorrelated reply confirmed the derived trial");
                    reply.code=D2K_RAW_PROOF_PROGRESS;
                    d2k_sched_event(s,&reply);spin(s,2);
                    CHECK(said("ПОДТВЕРЖДЕНО продолжением клиента"),"matching reply did not confirm the derived trial");
                }
                g_now_ms+=45000;d2k_sched_tick(s,g_now_ms);drain();spin(s,3);
                if(variant!=5)refreshed_measurement(s,tr,variant==6?20:18,0,3);
                CHECK(sent_command_count(D2K_CMD_SET_RAW_PROBE,NULL,0)==2,"no new evidence still produced more hypotheses");
                if(variant!=5)CHECK(!d2k_sched_active(s),"silent derived candidate did not finish unknown");
            } else CHECK(sent_command_count(D2K_CMD_SET_RAW_PROBE,NULL,0)==1,
                         "unexecuted or identical own plan was retried as a new hypothesis");
            CHECK(cat.boxes[0].binds[0].enabled,"trial retirement disabled the confirmed service binding");
        }
        d2k_sched_free(s);drain();d2k_catalog_free(&cat);
    }
    close(sv[0]);close(sv[1]);drain_fd=-1;
    if(!fails)puts("RAW refine: service scope, own-plan failure, measured construction, stale proof and stop PASS");
    return fails?1:0;
}
