#define _POSIX_C_SOURCE 200809L
#include "sched.c"
static int failures;
#define CHECK(c,m) do{if(!(c)){fprintf(stderr,"FAIL case=%d code=%u: %s\n",which,code,m);failures++;}}while(0)
static void run(int which,unsigned code){
    int silence=code==D2K_SUSPECT_SILENT+256;
    d2k_catalog catalog={0};
    /* Настоящий конструктор: mutex/cond/wake-пара инициализированы, link_fd=-1 —
       случайная запись в канал падает с EBADF, а не уходит в stdin. */
    d2k_sched *s=d2k_sched_new(&catalog,-1,0);if(!s){failures++;return;}
    task *t=&s->tasks[0];strcpy(t->name,D2K_LINK_VOICE_CLASS);t->state=T_VOICE_TRIAL;t->family=4;t->transport=17;
    t->ver_plan_id[0]=0x51;t->addr_probe_identity_valid=1;
    t->addr_probe_trial_id[0]=0x72;t->addr_probe_dst_port_be=htons(3478);
    t->addr_probe_src_ip[0]=1;t->addr_probe_dst_ip[0]=2;
    d2k_ev applied={0};applied.kind=D2K_EV_APPLIED;applied.family=4;applied.transport=17;
    applied.low_ip[0]=1;applied.high_ip[0]=2;applied.low_port=50000;applied.high_port=3478;
    applied.plan_id[0]=0x51;applied.trial_id[0]=0x72;applied.execution_id=17;
    applied.execution_binding.generation=9;applied.execution_binding.kind=D2K_BIND_FLOW;
    applied.execution_binding.family=4;applied.execution_binding.shape=D2K_PLAN_SHAPE_VOICE;
    applied.execution_binding.temporary=1;applied.execution_binding.epoch[0]=0x91;
    d2k_ev good=applied;good.kind=D2K_EV_EXCHANGE;good.code=(uint8_t)code;
    if(which==15){applied.execution_id=0;memset(&applied.execution_binding,0,sizeof applied.execution_binding);}
    on_applied(s,&applied);
    CHECK(t->state==T_VOICE_WATCH,"APPLIED selects expected flow");
    d2k_ev reply=good;
    switch(which){
    case 1:reply.trial_id[0]++;break;
    case 2:reply.plan_id[0]++;break;
    case 3:reply.execution_id++;break;
    case 4:reply.execution_binding.generation++;break;
    case 5:reply.execution_binding.epoch[0]++;break;
    case 6:reply.execution_binding.kind=D2K_BIND_ADDR;break;
    case 7:reply.execution_binding.family=6;break;
    case 8:reply.execution_binding.shape=D2K_PLAN_SHAPE_QUIC;break;
    case 9:reply.execution_binding.temporary=0;break;
    case 10:reply.execution_id=0;break;
    case 11:memset(&reply.execution_binding,0,sizeof reply.execution_binding);break;
    case 12:reply.low_port++;break;
    case 13:reply.code=D2K_UDP_PROOF_NONE;break;
    case 14:reply.family=6;break;
    default:break;
    }
    if(silence){
        reply.kind=D2K_EV_SUSPECT;reply.code=D2K_SUSPECT_SILENT;
        strcpy(reply.name,D2K_LINK_VOICE_CLASS);remember(s,&reply);
        on_suspect(s,&reply);
        CHECK(t->voice_silent==(which==0),"only matching silence may reject candidate");
        if(which>0 && which!=15){
            good.kind=D2K_EV_SUSPECT;good.code=D2K_SUSPECT_SILENT;
            on_suspect(s,&good);
            CHECK(t->voice_silent,"foreign silence must not suppress matching silence");
        }
        d2k_sched_free(s);return;
    }
    on_exchange(s,&reply);
    CHECK(t->voice_proven==(which==0),"only matched request context proves candidate");
    CHECK(t->voice_answered==(which==0 || which==13),"foreign proof must not advance WATCH");
    if(which>0 && which!=15){
        on_exchange(s,&good);
        CHECK(t->voice_proven,"foreign reply must not suppress later valid proof");
    }
    d2k_sched_free(s);
}
int main(void){
    for(int i=0;i<16;i++){run(i,D2K_UDP_PROOF_STUN);run(i,D2K_UDP_PROOF_VOICE_DISCOVERY);}
    for(int i=0;i<12;i++)run(i,D2K_SUSPECT_SILENT+256);
    run(15,D2K_SUSPECT_SILENT+256);
    if(failures)return 1;
    puts("UDP request proof context: 45 cases passed");return 0;
}
