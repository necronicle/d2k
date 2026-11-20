/* Local socketpair only: no bind/listen and no host network changes.
 * Include the transport to attach an already-connected test peer without
 * adding a production API solely for testing. Commands and ACKs are real. */
#include "ctl.c"
#include "d2k_ctlsrv.h"
#include <arpa/inet.h>
#include <sys/socket.h>

static int fails;
#define CHECK(c,m) do {if(!(c)){printf("FAIL: %s\n",m);fails++;}}while(0)
static const uint8_t preflight[]={ 'D','2','K','P',0,1,0,18,0,0,0,3,
    0,2,0,2,6,1, 1,0x14,0,11, 0,7,3,9,1,0,0,9,96,0,1, 0,0x10,0,5,0,1,0x16,3,1 };

static void command_ack(d2k_ctlsrv *cx,int peer,uint16_t cmd,uint8_t family,int expected) {
    uint8_t b[256]={0},a[256];size_t n;
    int endpoint=cmd==D2K_CMD_SET_ENDPOINT_BOUND || cmd==D2K_CMD_SET_ENDPOINT;
    if(endpoint) {
        b[0]=family;b[1]=192;b[2]=0;b[3]=2;b[4]=1;
        if(family==6){memset(b+1,0,16);b[1]=0x20;b[2]=1;b[16]=1;}
        b[17]=D2K_PLAN_SHAPE_MODERN;b[18]=1;b[19]=0xbb;n=20;
    } else {b[0]=9;memcpy(b+1,"x.example",9);b[10]=D2K_PLAN_SHAPE_MODERN;b[11]=family;n=12;}
    memcpy(b+n,preflight,sizeof preflight);n+=sizeof preflight;
    if(cmd==D2K_CMD_SET_ENDPOINT_BOUND || cmd==D2K_CMD_SET_NAME_BOUND) {
        memset(b+n,0x5a,D2K_TRIAL_ID_LEN);n+=D2K_TRIAL_ID_LEN;
    }
    d2k_ctlsrv_command(cx,cmd,b,n);
    ssize_t got=recv(peer,a,sizeof a,0);
    size_t off=6+D2K_KEY_WIRE_LEN;
    CHECK(got>=(ssize_t)(off+4),"ACK missing");
    if(got<(ssize_t)(off+4))return;
    CHECK(((unsigned)a[4]*256+a[5])==D2K_EV_ACK,"not an ACK");
    CHECK(a[off+2]==(expected==D2K_ACK_OK) && a[off+3]==expected,"wrong executor ACK result");
    if(cmd==D2K_CMD_SET_ENDPOINT_BOUND || cmd==D2K_CMD_SET_NAME_BOUND)
        CHECK(!memcmp(a+off+4,b+n-D2K_TRIAL_ID_LEN,D2K_TRIAL_ID_LEN),"request identity lost on ACK");
}
#ifndef D2K_TEST_EXEC17
static void test_preflight_event_pump(d2k_ctl *ctl,int peer,d2k_session *s) {
    /* The accessor is const for production readers; this test injects facts
     * into the session-owned, mutable journal to exercise the real serializer. */
    d2k_journal *j=(d2k_journal *)d2k_session_journal(s);
    d2k_key key;uint8_t low[4]={1,2,3,4},high[4]={192,168,1,3};
    uint8_t lp[2]={1,0xbb},hp[2]={0xc0,1};
    d2k_key_make(&key,6,low,high,lp,hp);
    uint8_t plan[D2K_PLAN_ID_LEN],trial[D2K_TRIAL_ID_LEN];
    memset(plan,0x81,sizeof plan);memset(trial,0xf2,sizeof trial);
    d2k_binding_context binding={0};binding.generation=UINT64_C(0x102030405060708);
    binding.kind=D2K_BIND_ADDR;binding.family=4;binding.shape=D2K_PLAN_SHAPE_MODERN;
    for(unsigned i=0;i<16;i++)binding.epoch[i]=(uint8_t)(0xa0+i);
    const uint8_t kinds[]={D2K_JRN_PREFLIGHT_START,D2K_JRN_PREFLIGHT_HANDOVER,D2K_JRN_PREFLIGHT_GAVE_UP};
    const uint16_t events[]={D2K_EV_PREFLIGHT_START,D2K_EV_PREFLIGHT_HANDOVER,D2K_EV_PREFLIGHT_GAVE_UP};
    uint64_t seen=0;
    for(unsigned i=0;i<3;i++) {
        uint64_t elapsed=UINT64_C(0x1122334455667788)+i;
        d2k_journal_add_preflight(j,100+i,&key,kinds[i],0x01020304,elapsed,
            D2K_CLIENT_SIDE_HIGH,plan,trial,&binding);
        d2k_ctlsrv_pump(ctl,s,&seen);
        uint8_t actual[6+D2K_KEY_WIRE_LEN+D2K_CTL_PREFLIGHT_LEN+1];
        ssize_t got=recv(peer,actual,sizeof actual,0);
        uint8_t expected[6+D2K_KEY_WIRE_LEN+D2K_CTL_PREFLIGHT_LEN]={0};
        size_t n=sizeof expected;uint32_t plen=(uint32_t)n-4;
        for(unsigned b=0;b<4;b++)expected[b]=(uint8_t)(plen>>(24-8*b));
        expected[4]=(uint8_t)(events[i]>>8);expected[5]=(uint8_t)events[i];
        expected[6]=4;memcpy(expected+7,low,4);memcpy(expected+23,high,4);
        memcpy(expected+39,lp,2);memcpy(expected+41,hp,2);expected[43]=6;
        size_t o=6+D2K_KEY_WIRE_LEN;
        expected[o++]=D2K_CLIENT_SIDE_HIGH;
        expected[o++]=1;expected[o++]=2;expected[o++]=3;expected[o++]=4;
        for(unsigned b=0;b<8;b++)expected[o++]=(uint8_t)(elapsed>>(56-8*b));
        memcpy(expected+o,plan,sizeof plan);o+=sizeof plan;
        memcpy(expected+o,trial,sizeof trial);o+=sizeof trial;
        /* Golden wire context, independent of the production binding writer. */
        for(unsigned b=0;b<8;b++)expected[o++]=(uint8_t)(binding.generation>>(56-8*b));
        expected[o++]=D2K_BIND_ADDR;expected[o++]=4;expected[o++]=D2K_PLAN_SHAPE_MODERN;expected[o++]=0;
        memcpy(expected+o,binding.epoch,16);o+=16;
        CHECK(o==n && got==(ssize_t)n && !memcmp(actual,expected,n),"preflight pump changed wire fact/identity");
        d2k_ctlsrv_pump(ctl,s,&seen);
        CHECK(recv(peer,actual,sizeof actual,0)==-1 && (errno==EAGAIN || errno==EWOULDBLOCK),"preflight fact emitted twice");
    }
    puts("test_preflight_event_pump");
}
#endif
int main(void) {
    int pair[2];
    if(socketpair(AF_UNIX,SOCK_STREAM,0,pair)){perror("socketpair");return 1;}
    fcntl(pair[1],F_SETFL,O_NONBLOCK);
    d2k_ctl ctl={0};ctl.lfd=-1;ctl.pfd=pair[0];
    d2k_session *s=d2k_session_new(16,64);
    if(!s)return 1;
    d2k_ctlsrv cx={.sess=s,.ctl=&ctl,.now_ns=1};
#ifdef D2K_TEST_EXEC17
    /* test_preflight_minexec_17_rejected: executor's BAD_PLAN reaches core;
       never ACK_OK/APPLIED, even for a correctly bound request. */
    command_ack(&cx,pair[1],D2K_CMD_SET_ENDPOINT_BOUND,4,D2K_ACK_BAD_PLAN);
    CHECK(cx.ok_cmds==0 && cx.bad_cmds==1,"exec17 reported applied");
    puts("test_preflight_minexec_17_rejected");
#else
    command_ack(&cx,pair[1],D2K_CMD_SET_NAME_BOUND,4,D2K_ACK_BAD_ARGS);
    command_ack(&cx,pair[1],D2K_CMD_SET_NAME,4,D2K_ACK_BAD_ARGS);
    command_ack(&cx,pair[1],D2K_CMD_SET_ENDPOINT,4,D2K_ACK_BAD_ARGS);
    command_ack(&cx,pair[1],D2K_CMD_SET_ENDPOINT_BOUND,6,D2K_ACK_OK);
    command_ack(&cx,pair[1],D2K_CMD_SET_ENDPOINT_BOUND,4,D2K_ACK_OK);
    CHECK(cx.ok_cmds==2 && cx.bad_cmds==3,"unexpected install counters");
    uint8_t address6[16]={0x20,1,[15]=1}, trial[16];
    memset(trial,0x5a,sizeof trial);
    d2k_plantab *tab=d2k_session_plans(s);
    CHECK(d2k_plantab_commit_endpoint_trial(tab,address6,6,htons(443),D2K_PLAN_SHAPE_MODERN,trial)==1,
          "IPv6 trial cannot be promoted for its full address");
    CHECK(d2k_plantab_find_target_endpoint_tr(tab,NULL,0,address6,6,1,
          D2K_PLAN_SHAPE_MODERN,0,htons(443),6)!=NULL,"IPv6 endpoint unavailable after promotion");
    address6[15]=2;
    CHECK(d2k_plantab_find_target_endpoint_tr(tab,NULL,0,address6,6,1,
          D2K_PLAN_SHAPE_MODERN,0,htons(443),6)==NULL,"IPv6 plan matched a neighbouring address");
    puts("test_preflight_plan_is_endpoint_bound (control)");
    test_preflight_event_pump(&ctl,pair[1],s);
#endif
    d2k_session_free(s);close(pair[0]);close(pair[1]);
    printf("preflight control: %d failures\n",fails);return fails?1:0;
}
