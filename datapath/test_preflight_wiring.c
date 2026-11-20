/* Socket-free tests of actual session preflight admission and owned output. */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "d2k_session.h"
#include "d2k_preflight.h"
#include "d2k_preflight_path.h"
#include "d2k_plantlv.h"
#include "d2k_provider_ips.h"
#include "d2k_hello.h"
#include <time.h>
static const uint8_t hello[] = {
    22, 3, 1, 0,  69,  1,   0,   0,   65,   3,   3,   0,   0,   0,   0,   0,   0,  0,  0,
    0,  0, 0, 0,  0,   0,   0,   0,   0,    0,   0,   0,   0,   0,   0,   0,   0,  0,  0,
    0,  0, 0, 0,  0,   0,   0,   2,   0x13, 1,   1,   0,   0,   22,  0,   0,   0,  18, 0,
    16, 0, 0, 13, 'a', '.', 'e', 'x', 'a',  'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
static int fails;
#define CHECK(x) do { if(!(x)) {fprintf(stderr,"%s:%d FAIL %s\n",__func__,__LINE__,#x);fails++;} } while(0)
static void w16(uint8_t *p,unsigned v){p[0]=v>>8;p[1]=v;}
static void w32(uint8_t *p,unsigned v){p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v;}
static size_t packet(uint8_t *p,int server,unsigned flags,unsigned seq,unsigned ack,size_t data){
    memset(p,0,256);p[0]=0x45;p[8]=64;p[9]=6;w16(p+2,40+data);
    const uint8_t c[]={192,168,1,9},s[]={192,0,2,1};
    memcpy(p+12,server?s:c,4);memcpy(p+16,server?c:s,4);
    w16(p+20,server?443:45678);w16(p+22,server?45678:443);
    w32(p+24,seq);w32(p+28,ack);p[32]=0x50;p[33]=flags;w16(p+34,64240);
    memset(p+40,0xa5,data);return 40+data;
}
static d2k_session *setup_hello_timing(int enabled,size_t hello_len,int timed,int permanent){
    d2k_session *s=d2k_session_new(16,64);CHECK(s);
    uint8_t tlv[8192];size_t n=0;char err[200],text[10000];
    size_t off=(size_t)snprintf(text,sizeof text,"d2k-plan 1 %u\nproto tcp tls\nid 0102030405060708090a0b0c0d0e0f10\npayload 1 ",timed?19u:18u);
    for(size_t i=0;i<hello_len;i++) off+=(size_t)snprintf(text+off,sizeof text-off,"%02x",i==0 ? 0x16 : i==1 ? 3 : i==2 ? 1 : 0xaa);
    (void)snprintf(text+off,sizeof text-off,"\npreflight window=7 wscale=2 pieces=2 hello=own timeout=1370 data=1%s\n",timed?" resyn_delay=60 resyn_sends=6 resyn_timeout=500":"");
    CHECK(d2k_plan_text_to_tlv(text,tlv,sizeof tlv,&n,err,sizeof err)==0);
    d2k_plan *p=NULL;CHECK(d2k_plan_load(tlv,n,&p,err,sizeof err)==0);CHECK(p);
    uint8_t addr[4]={192,0,2,1},token[16]={1};
    int installed=permanent ?
        d2k_plantab_set_endpoint(d2k_session_plans(s),addr,4,htons(443),1,p,D2K_PLAN_SHAPE_MODERN) :
        d2k_plantab_set_endpoint_trial_port(d2k_session_plans(s),addr,4,htons(443),htons(45678),1,p,D2K_PLAN_SHAPE_MODERN,token);
    CHECK(installed==0);
    CHECK(d2k_session_set_preflight(s,enabled)==0);
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);return s;
}
static d2k_session *setup_hello(int enabled,size_t len){return setup_hello_timing(enabled,len,0,0);}
static d2k_session *setup(int enabled){return setup_hello(enabled,3);}
static void test_provider_ip_preflight(void){
    d2k_provider_ips ips={0};d2k_dns_answer a={.type=1,.count=1,.ttl=30};
    strcpy(a.question,"rr2---sn-4g5ednrs.googlevideo.com");
    a.addresses[0][0]=192;a.addresses[0][1]=0;a.addresses[0][2]=2;a.addresses[0][3]=1;
    uint64_t now=(uint64_t)time(NULL);
    CHECK(d2k_provider_ips_observe(&ips,&a,now));
    const char *path="/tmp/d2k-preflight-provider-test";
    CHECK(!d2k_provider_ips_save(&ips,path,now));
    d2k_session *s=d2k_session_new(16,64);CHECK(s);
    CHECK(!d2k_session_set_preflight(s,1));
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    uint8_t p[256];size_t n=packet(p,0,2,100,0,0);d2k_pf_out o;
    CHECK(!d2k_session_preflight_packet(s,p,n,10,&o));
    CHECK(!d2k_session_provider_ips_load(s,path,now));
    p[19]=2;CHECK(!d2k_session_preflight_packet(s,p,n,10,&o));
    p[19]=1;w16(p+22,80);CHECK(!d2k_session_preflight_packet(s,p,n,10,&o));
    w16(p+22,443);
    CHECK(d2k_session_preflight_packet(s,p,n,10,&o));
    CHECK(o.count==1);
    n=packet(p,1,0x12,900,101,0);
    CHECK(d2k_session_preflight_packet(s,p,n,20,&o));
    CHECK(o.count==2);
    CHECK(o.len[1]>40 && o.len[1]-40<=536);
    CHECK(d2k_hello_complete(o.packet[1]+40,o.len[1]-40));
    d2k_session_free(s);remove(path);
}
static void test_syn_matches_endpoint_plan(void){
    d2k_session *s=setup(1);uint8_t p[256];size_t n=packet(p,0,2,100,0,0);d2k_pf_out o;
    p[19]=2;CHECK(!d2k_session_preflight_packet(s,p,n,10,&o));CHECK(!o.count);
    p[19]=1;w16(p+22,444);CHECK(!d2k_session_preflight_packet(s,p,n,10,&o));
    w16(p+22,443);p[0]=0x60;CHECK(!d2k_session_preflight_packet(s,p,n,10,&o));p[0]=0x45;
    d2k_session_set_hook(s,D2K_HOOK_PREROUTING);
    CHECK(!d2k_session_preflight_packet(s,p,n,10,&o));
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    CHECK(d2k_session_preflight_packet(s,p,n,10,&o));CHECK(o.count==1);
    CHECK(o.len[0]>=40&&o.packet[0][34]==0&&o.packet[0][35]==7);
    d2k_session_free(s);puts("test_syn_matches_endpoint_plan");
}
static void test_preflight_switch_off(void){
    d2k_session *s=setup(0);uint8_t p[256],buf[32768];size_t n=packet(p,0,2,100,0,0);d2k_pf_out o;d2k_result r;
    CHECK(!d2k_session_preflight_packet(s,p,n,10,&o));
    d2k_session_packet(s,p,n,10,buf,sizeof buf,&r);CHECK(r.verdict==D2K_VERDICT_ACCEPT&&r.n_out==0);
    CHECK(!d2k_session_preflight_next_ns(s));CHECK(d2k_session_preflight_calls(s)==0);
    d2k_session_free(s);puts("test_preflight_switch_off");
}
static void test_original_syn_owned_and_resent(void){
    d2k_session *s=setup(1);uint8_t p[256],orig[256];size_t n=packet(p,0,2,100,0,0);memcpy(orig,p,n);d2k_pf_out o;
    CHECK(d2k_session_preflight_packet(s,p,n,100,&o)); /* daemon must NF_DROP this ID */
    uint64_t due=d2k_session_preflight_next_ns(s);CHECK(due==1370000100);
    d2k_session_preflight_tick(s,due,&o);
    CHECK(o.count==1&&o.len[0]==n&&memcmp(o.packet[0],orig,n)==0);
    CHECK(!d2k_session_preflight_next_ns(s));d2k_session_free(s);puts("test_original_syn_owned_and_resent");
}
static void test_server_probe_packets_dropped(void){
    d2k_session *s=setup(1);uint8_t p[256];size_t n=packet(p,0,2,100,0,0);d2k_pf_out o;
    CHECK(d2k_session_preflight_packet(s,p,n,10,&o));
    d2k_session_set_hook(s,D2K_HOOK_PREROUTING);
    n=packet(p,1,0x12,900,101,0);CHECK(d2k_session_preflight_packet(s,p,n,20,&o));CHECK(o.count==2);
    CHECK(o.len[1]==43&&memcmp(o.packet[1]+40,"\x16\x03\x01",3)==0);
    n=packet(p,1,0x18,901,104,10);CHECK(d2k_session_preflight_packet(s,p,n,30,&o));CHECK(o.count==1);
    n=packet(p,1,0x18,911,104,10);CHECK(d2k_session_preflight_packet(s,p,n,40,&o));CHECK(o.count==2);
    n=packet(p,1,0x12,990,101,0);CHECK(!d2k_session_preflight_packet(s,p,n,50,&o));
    d2k_session_free(s);puts("test_server_probe_packets_dropped");
}
static void test_timer_drives_tick(void){
    d2k_session *s=setup(1);uint8_t p[256];size_t n=packet(p,0,2,100,0,0);d2k_pf_out o;
    CHECK(d2k_session_preflight_packet(s,p,n,100,&o));
    uint64_t due=d2k_session_preflight_next_ns(s);CHECK(due&&due<2000000100);
    d2k_session_preflight_tick(s,due-1,&o);CHECK(!o.count);
    d2k_session_preflight_tick(s,due,&o);CHECK(o.count==1);d2k_session_free(s);puts("test_timer_drives_tick");
}
static void test_events_emitted(void){
    for(int timeout=0;timeout<2;timeout++){
        d2k_session *s=setup(1);uint8_t p[256];d2k_pf_out o;
        size_t n=packet(p,0,2,100,0,0);CHECK(d2k_session_preflight_packet(s,p,n,100,&o));
        if(timeout) d2k_session_preflight_tick(s,1370000100,&o);
        else {
            d2k_session_set_hook(s,D2K_HOOK_PREROUTING);
            n=packet(p,1,0x12,900,101,0);CHECK(d2k_session_preflight_packet(s,p,n,200,&o));
            n=packet(p,1,0x18,901,104,10);CHECK(d2k_session_preflight_packet(s,p,n,300,&o));
            n=packet(p,1,0x18,911,104,10);CHECK(d2k_session_preflight_packet(s,p,n,400,&o));
            CHECK(d2k_journal_count(d2k_session_journal(s))==1); /* not sent yet */
            d2k_session_preflight_original_sent(s,o.packet[o.count-1],o.len[o.count-1],400);
        }
        const d2k_journal *j=d2k_session_journal(s);CHECK(d2k_journal_count(j)==2);
        const d2k_jrn_entry *start=d2k_journal_at(j,0),*end=d2k_journal_at(j,1);
        CHECK(start&&start->kind==D2K_JRN_PREFLIGHT_START&&start->num==2&&start->preflight_elapsed_ns==0);
        CHECK(end&&end->kind==(timeout?D2K_JRN_PREFLIGHT_GAVE_UP:D2K_JRN_PREFLIGHT_HANDOVER));
        CHECK(end&&end->num==2&&end->preflight_elapsed_ns==(timeout?1370000000u:300u));
        CHECK(start&&end&&d2k_key_equal(&start->key,&end->key)&&start->d_client_side==D2K_CLIENT_SIDE_HIGH);
        CHECK(start&&end&&d2k_binding_equal(&start->binding,&end->binding));
        CHECK(start&&end&&!memcmp(start->plan_id,end->plan_id,16)&&end->plan_id[15]==16);
        const uint8_t trial_id[16] = {1};
        CHECK(start && !memcmp(start->trial_id, trial_id, sizeof trial_id));
        CHECK(end && !memcmp(end->trial_id, trial_id, sizeof trial_id));
        d2k_session_free(s);
    }
    puts("test_events_emitted");
}
static void test_session_syn_path(void){
    d2k_session *s=setup(1);uint8_t p[256],buf[32768];d2k_result r;size_t n=packet(p,0,2,100,0,0);
    d2k_session_packet(s,p,n,100,buf,sizeof buf,&r);
    CHECK(r.verdict==D2K_VERDICT_DROP&&r.n_out==1);CHECK(!r.applied);
    d2k_session_free(s);puts("test_session_syn_path");
}
typedef struct { unsigned dropped,sent; uint8_t packet[256];size_t len; uint32_t mark; } io_record;
static int io_drop(void *v,uint32_t id){io_record *r=v;CHECK(id==123);CHECK(!r->sent);r->dropped++;return 0;}
static int io_send(void *v,const uint8_t *p,size_t n,uint32_t mark){io_record *r=v;r->mark=mark;CHECK(r->dropped==1);r->sent++;if(n<=sizeof r->packet){memcpy(r->packet,p,n);r->len=n;}return 0;}
static void test_daemon_ownership_adapter(void){
    d2k_session *s=setup(1);io_record r={0};d2k_preflight_io io={&r,io_drop,io_send};
    uint8_t p[256];size_t n=packet(p,0,2,100,0,0);
    CHECK(d2k_preflight_path_packet(s,p,n,123,100,&io)==1);CHECK(r.dropped==1&&r.sent==1);
    CHECK(d2k_preflight_path_tick(s,1370000100,&io)==0);CHECK(r.sent==2);
    CHECK(r.len==n&&!memcmp(r.packet,p,n));d2k_session_free(s);
    puts("test_daemon_ownership_adapter");
}
static int failing_send(void *v,const uint8_t *p,size_t n,uint32_t mark){io_record *r=v;r->mark=mark;CHECK(r->dropped==1);r->sent++;if(r->sent==1)return -1;if(n<=sizeof r->packet){memcpy(r->packet,p,n);r->len=n;}return 0;}
static int failing_drop(void *v,uint32_t id){(void)v;(void)id;return -1;}
static void test_send_failure_returns_original(void){
    d2k_session *s=setup(1);io_record r={0};d2k_preflight_io io={&r,io_drop,failing_send};
    uint8_t p[256];size_t n=packet(p,0,2,100,0,0);
    CHECK(d2k_preflight_path_packet(s,p,n,123,100,&io)==1);
    CHECK(r.sent==2&&r.len==n&&!memcmp(p,r.packet,n));
    CHECK(!d2k_session_preflight_next_ns(s));
    const d2k_journal *j=d2k_session_journal(s);const d2k_jrn_entry *e=d2k_journal_at(j,d2k_journal_count(j)-1);
    CHECK(e&&e->kind==D2K_JRN_PREFLIGHT_GAVE_UP);d2k_session_free(s);
    s=setup(1);memset(&r,0,sizeof r);io=(d2k_preflight_io){&r,failing_drop,io_send};
    CHECK(d2k_preflight_path_packet(s,p,n,123,100,&io)==-1);CHECK(!r.sent);
    CHECK(!d2k_session_preflight_next_ns(s));d2k_session_free(s);
    puts("test_send_failure_returns_original");
}
static void test_shutdown_returns_owned_syn(void){
    d2k_session *s=setup(1);io_record r={0};d2k_preflight_io io={&r,io_drop,io_send};
    uint8_t p[256];size_t n=packet(p,0,2,100,0,0);
    CHECK(d2k_preflight_path_packet(s,p,n,123,100,&io)==1);
    CHECK(d2k_preflight_path_flush(s,200,&io)==0);
    CHECK(r.sent==2&&r.len==n&&!memcmp(p,r.packet,n));
    CHECK(!d2k_session_preflight_next_ns(s));d2k_session_free(s);
    puts("test_shutdown_returns_owned_syn");
}
static int reset_failing_send(void *v,const uint8_t *p,size_t n,uint32_t mark){
    io_record *r=v;r->mark=mark;r->sent++;if(p[33]&4)return -1;
    if(n<=sizeof r->packet){memcpy(r->packet,p,n);r->len=n;}return 0;
}
static void test_reset_failure_still_releases_original(void){
    d2k_session *s=setup(1);uint8_t p[256],orig[256];d2k_pf_out o;
    size_t n=packet(p,0,2,100,0,0);memcpy(orig,p,n);CHECK(d2k_session_preflight_packet(s,p,n,100,&o));
    n=packet(p,1,0x12,900,101,0);CHECK(d2k_session_preflight_packet(s,p,n,200,&o));
    io_record r={0};d2k_preflight_io io={&r,NULL,reset_failing_send};
    CHECK(d2k_preflight_path_tick(s,1370000100,&io)==-1);
    CHECK(r.sent==2&&r.len==40&&!memcmp(r.packet,orig,40));
    CHECK(!d2k_session_preflight_next_ns(s));d2k_session_free(s);
    puts("test_reset_failure_still_releases_original");
}
static void test_preflight_not_payload_program(void){
    d2k_session *s=setup(0);uint8_t addr[4]={192,0,2,1};
    const d2k_plan *p=d2k_plantab_find_target_endpoint_tr(d2k_session_plans(s),NULL,0,addr,4,100,
        D2K_PLAN_SHAPE_MODERN,htons(45678),htons(443),6);
    CHECK(p);uint8_t payload[]={22,3,1,0,1,1};d2k_pkt in={0};d2k_actions actions;
    in.payload=payload;in.payload_len=sizeof payload;
    CHECK(d2k_plan_apply(p,NULL,&in,&actions)<0);CHECK(actions.refuse_why&&strstr(actions.refuse_why,"preflight"));
    uint8_t wire[256],outbuf[32768];d2k_result result;
    size_t n=packet(wire,0,2,100,0,0);
    d2k_session_packet(s,wire,n,100,outbuf,sizeof outbuf,&result);
    n=packet(wire,0,0x18,101,901,sizeof hello);memcpy(wire+40,hello,sizeof hello);
    d2k_session_packet(s,wire,n,200,outbuf,sizeof outbuf,&result);
    CHECK(!result.applied&&result.n_out==0&&result.verdict==D2K_VERDICT_ACCEPT);
    const d2k_journal *j=d2k_session_journal(s);
    for(size_t i=0;i<d2k_journal_count(j);i++) CHECK(d2k_journal_at(j,i)->kind!=D2K_JRN_PLAN_APPLIED);
    d2k_session_free(s);puts("test_preflight_not_payload_program");
}
static void test_failed_reset_does_not_duplicate_released_syn(void){
    d2k_session *s=setup(1);uint8_t p[256],orig[256];d2k_pf_out o;
    size_t n=packet(p,0,2,100,0,0);memcpy(orig,p,n);CHECK(d2k_session_preflight_packet(s,p,n,100,&o));
    n=packet(p,1,0x12,900,101,0);CHECK(d2k_session_preflight_packet(s,p,n,200,&o));
    n=packet(p,1,0x18,901,104,10);CHECK(d2k_session_preflight_packet(s,p,n,300,&o));
    io_record r={0};d2k_preflight_io io={&r,io_drop,reset_failing_send};
    n=packet(p,1,0x18,911,104,10);
    CHECK(d2k_preflight_path_packet(s,p,n,123,400,&io)==1);
    CHECK(r.sent==2&&r.len==40&&!memcmp(r.packet,orig,40));
    CHECK(d2k_session_preflight_next_ns(s));
    const d2k_journal *j=d2k_session_journal(s);CHECK(d2k_journal_count(j)==2);
    CHECK(d2k_journal_at(j,1)->kind==D2K_JRN_PREFLIGHT_HANDOVER);
    d2k_session_free(s);puts("test_failed_reset_does_not_duplicate_released_syn");
}
static int fifth_send_fails(void *v,const uint8_t *p,size_t n,uint32_t mark) {
    io_record *r=v; r->sent++; r->mark=mark;
    if(r->sent==5) return -1;
    if(n<=sizeof r->packet){memcpy(r->packet,p,n);r->len=n;}
    return 0;
}
static void test_tick_send_failure_releases_syn(void) {
    d2k_session *s=setup_hello(1,2000); uint8_t p[256],syn[256];d2k_pf_out out;
    size_t n=packet(syn,0,2,100,0,0);
    d2k_session_preflight_send_cap(s,100);
    CHECK(d2k_session_preflight_packet(s,syn,n,100,&out));
    io_record r={0};d2k_preflight_io io={&r,io_drop,fifth_send_fails};
    n=packet(p,1,18,900,101,0);
    CHECK(d2k_preflight_path_packet(s,p,n,123,200,&io)==1);
    CHECK(r.sent==4 && r.mark==D2K_PF_MARK);
    CHECK(d2k_preflight_path_tick(s,200,&io)==-1);
    CHECK(!d2k_session_preflight_next_ns(s));
    CHECK(r.sent==7 && r.mark==D2K_PF_RELEASE_MARK && r.len==40 && !memcmp(r.packet,syn,40));
    d2k_session_free(s);puts("test_tick_send_failure_releases_syn");
}
/* Real segmented ClientHello; no stream plan exists to activate holding. */
static const uint8_t real_hello[]={
    22, 3, 1, 0,  69,  1,   0,   0,   65,   3,   3,   0,   0,   0,   0,   0,   0,  0,  0,
    0,  0, 0, 0,  0,   0,   0,   0,   0,    0,   0,   0,   0,   0,   0,   0,   0,  0,  0,
    0,  0, 0, 0,  0,   0,   0,   2,   0x13, 1,   1,   0,   0,   22,  0,   0,   0,  18, 0,
    16, 0, 0, 13, 'a', '.', 'e', 'x', 'a',  'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
static void handover_client(d2k_session *s,io_record *r,d2k_preflight_io *io) {
    uint8_t p[256],syn[256];d2k_pf_out out; uint8_t buf[32768];d2k_result result;
    size_t n=packet(syn,0,2,100,0,0);
    CHECK(d2k_preflight_path_packet(s,syn,n,123,100,io)==1 && r->mark==D2K_PF_MARK);
    n=packet(p,1,4,900,101,0);CHECK(d2k_session_preflight_packet(s,p,n,200,&out));
    d2k_session_observe_tcp(s,syn,40,200);
    n=packet(p,1,18,900,101,0);CHECK(!d2k_session_preflight_packet(s,p,n,300,&out));
    d2k_session_packet(s,p,n,300,buf,sizeof buf,&result);
}
static size_t client_hello_part(d2k_session *s,uint8_t *p,size_t off,size_t len,uint64_t now) {
    uint8_t buf[32768]; d2k_result result;
    size_t n=packet(p,0,24,101+(unsigned)off,901,len);
    memcpy(p+40,real_hello+off,len);
    d2k_session_packet(s,p,n,now,buf,sizeof buf,&result);
    return n;
}
static void test_cleanup_marks_reach_sender(void) {
    d2k_session *s=setup(1); uint8_t p[256];
    io_record r={0}; d2k_preflight_io io={&r,io_drop,io_send};
    handover_client(s,&r,&io);
    size_t n=client_hello_part(s,p,0,20,400);
    CHECK(!d2k_preflight_path_complete(s,p,n,400,&io));
    CHECK(r.sent==1 && d2k_session_preflight_next_ns(s));
    n=client_hello_part(s,p,20,sizeof real_hello-20,500);
    CHECK(!d2k_preflight_path_complete_on(s,p,n,500,&io,8));
    CHECK(r.sent==1 && d2k_session_preflight_next_ns(s));
    CHECK(!d2k_preflight_path_complete(s,p,n,500,&io));
    CHECK(r.sent==2 && r.mark==D2K_PF_TOKEN_MARK && r.packet[33]==16 && r.len==40);
    CHECK(!d2k_preflight_path_complete(s,p,n,500,&io) && r.sent==2);
    CHECK(!d2k_session_preflight_next_ns(s));
    d2k_session_free(s); puts("test_cleanup_marks_reach_sender / real_hello_segmented");
}
static int token_send_fails(void *v,const uint8_t *p,size_t n,uint32_t mark) {
    if(mark==D2K_PF_TOKEN_MARK) return -1;
    return io_send(v,p,n,mark);
}
static void test_cleanup_token_retry(void) {
    d2k_session *s=setup(1);uint8_t p[256];io_record r={0};
    d2k_preflight_io io={&r,io_drop,io_send}; handover_client(s,&r,&io);
    size_t n=client_hello_part(s,p,0,sizeof real_hello,400);
    io.send=token_send_fails;
    CHECK(d2k_preflight_path_complete(s,p,n,400,&io)==-1);
    CHECK(d2k_session_preflight_next_ns(s));
    io.send=io_send;
    CHECK(!d2k_preflight_path_tick(s,1370000100,&io));
    CHECK(r.sent==2 && r.mark==D2K_PF_TOKEN_MARK && !d2k_session_preflight_next_ns(s));
    d2k_session_free(s);puts("test_cleanup_token_retry");
}
static void test_plan19_delayed_handover_wiring(void) {
    d2k_session *s=setup_hello_timing(1,3,1,0);uint8_t p[256];d2k_pf_out o;
    size_t n=packet(p,0,2,100,0,0);
    CHECK(d2k_session_preflight_packet(s,p,n,100,&o));
    n=packet(p,1,18,900,101,0);CHECK(d2k_session_preflight_packet(s,p,n,200,&o));
    n=packet(p,1,24,901,104,1);CHECK(d2k_session_preflight_packet(s,p,n,300,&o));
    n=packet(p,1,24,902,104,1);CHECK(d2k_session_preflight_packet(s,p,n,400,&o));
    CHECK(o.count==1 && o.packet[0][33]==4);
    CHECK(d2k_session_preflight_next_ns(s)==60000400);
    d2k_session_preflight_tick(s,60000400,&o);
    CHECK(o.count==1 && o.original[0] && o.packet[0][33]==2);
    d2k_session_preflight_original_sent(s,o.packet[0],o.len[0],60000400);
    d2k_session_preflight_tick(s,120000400,&o);
    CHECK(o.count==1 && o.original[0]);
    d2k_session_preflight_original_sent(s,o.packet[0],o.len[0],120000400);
    CHECK(d2k_journal_count(d2k_session_journal(s))==2); /* retries do not duplicate handover evidence */
    n=packet(p,1,18,990,101,0);CHECK(!d2k_session_preflight_packet(s,p,n,130000400,&o));
    d2k_session_preflight_tick(s,180000400,&o);CHECK(!o.count);
    d2k_session_free(s);puts("test_plan19_delayed_handover_wiring");
}
static void test_permanent_preflight_does_not_guess_syn_context(void) {
    d2k_session *s=setup_hello_timing(1,3,0,1);uint8_t p[256];size_t n=packet(p,0,2,100,0,0);d2k_pf_out o;
    CHECK(!d2k_session_preflight_packet(s,p,n,10,&o));
    CHECK(!o.count && !d2k_session_preflight_calls(s));
    d2k_session_free(s);puts("test_permanent_preflight_does_not_guess_syn_context");
}
static const uint8_t lease_wire[]={'D','2','K','P',0,1,0,18,0,0,0,3,0,2,0,2,6,1,1,0x14,0,11,0,7,3,9,1,0,0,9,96,0,1,0,0x10,0,5,0,1,0x16,3,1};
static d2k_session *lease_session(d2k_pf_scope *scope) {
    d2k_session *s=d2k_session_new(16,64);CHECK(s&&d2k_session_set_preflight(s,1)==0);
    if(!s)return NULL;
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    d2k_plan *plan=NULL;char err[200];CHECK(!d2k_plan_load(lease_wire,sizeof lease_wire,&plan,err,sizeof err));
    memset(scope,0,sizeof *scope);scope->family=4;scope->shape=D2K_PLAN_SHAPE_MODERN;
    scope->server_port=htons(443);scope->path=7;scope->client[0]=192;scope->client[1]=168;
    scope->client[2]=1;scope->client[3]=9;scope->server[0]=192;scope->server[2]=2;scope->server[3]=1;
    strcpy(scope->name,"video.example");uint8_t id[16]={9};
    CHECK(!d2k_session_set_preflight_lease(s,scope,10,10000,id,plan));return s;
}
static void test_lease_syn_requires_exact_context(void) {
    d2k_pf_scope scope;
    uint8_t p[256];
    size_t n = packet(p, 0, 2, 100, 0, 0);
    d2k_pf_out out;

    d2k_session *s = lease_session(&scope);
    if (!s) return;
    CHECK(d2k_session_find_preflight_lease(s, &scope, 11) != NULL);
    CHECK(d2k_session_preflight_packet_path(s, p, n, 11, &out, 7));
    CHECK(out.count == 1);
    const d2k_jrn_entry *start = d2k_journal_at(d2k_session_journal(s), 0);
    const d2k_plan *lease_plan = d2k_session_find_preflight_lease(s, &scope, 11);
    const d2k_binding_context *lease_binding =
        d2k_session_preflight_lease_binding(s, lease_plan);
    const uint8_t lease_id[16] = {9};
    CHECK(d2k_journal_count(d2k_session_journal(s)) == 1);
    CHECK(start && start->kind == D2K_JRN_PREFLIGHT_START);
    CHECK(start && !memcmp(start->trial_id, lease_id, sizeof lease_id));
    CHECK(start && lease_binding && d2k_binding_equal(&start->binding, lease_binding));
    d2k_session_free(s);

    s = lease_session(&scope);
    CHECK(!d2k_session_preflight_packet_path(s, p, n, 11, &out, 8));
    CHECK(out.count == 0 && d2k_session_preflight_calls(s) == 0);
    d2k_session_free(s);

    s = lease_session(&scope);
    p[15] = 10;
    CHECK(!d2k_session_preflight_packet_path(s, p, n, 11, &out, 7));
    CHECK(out.count == 0 && d2k_session_preflight_calls(s) == 0);
    d2k_session_free(s);
    p[15] = 9;

    s = lease_session(&scope);
    d2k_pf_scope other = scope;
    other.shape = D2K_PLAN_SHAPE_LEGACY;
    uint8_t second[16] = {10};
    d2k_plan *plan = NULL;
    char err[200];
    CHECK(!d2k_plan_load(lease_wire, sizeof lease_wire, &plan, err, sizeof err));
    CHECK(!d2k_session_set_preflight_lease(s, &other, 12, 10000, second, plan));
    CHECK(!d2k_session_preflight_packet_path(s, p, n, 12, &out, 7));
    CHECK(out.count == 0 && d2k_session_preflight_calls(s) == 0);
    d2k_session_free(s);

    s = lease_session(&scope);
    other = scope;
    strcpy(other.name, "other.example");
    plan = NULL;
    CHECK(!d2k_plan_load(lease_wire, sizeof lease_wire, &plan, err, sizeof err));
    CHECK(!d2k_session_set_preflight_lease(s, &other, 12, 10000, second, plan));
    CHECK(d2k_session_find_preflight_lease(s, &scope, 12));
    CHECK(d2k_session_find_preflight_lease(s, &other, 12));
    CHECK(!d2k_session_preflight_packet_path(s, p, n, 12, &out, 7));
    CHECK(out.count == 0 && d2k_session_preflight_calls(s) == 0);
    CHECK(d2k_journal_count(d2k_session_journal(s)) == 0);
    d2k_session_free(s);

    s = lease_session(&scope);
    CHECK(!d2k_session_preflight_packet_path(s, p, n, 10000, &out, 7));
    CHECK(out.count == 0 && d2k_session_preflight_calls(s) == 0);
    d2k_session_free(s);
    puts("test_lease_syn_requires_exact_context");
}

static void test_unscoped_trial_leaves_syn_alone(void) {
    d2k_session *s = setup(1);
    uint8_t server[4] = {192, 0, 2, 2};
    uint8_t token[16] = {11};
    d2k_plan *plan = NULL;
    char err[200];
    CHECK(!d2k_plan_load(lease_wire, sizeof lease_wire, &plan, err, sizeof err));
    CHECK(!d2k_plantab_set_endpoint_trial(d2k_session_plans(s), server, 4,
        htons(443), 1, plan, D2K_PLAN_SHAPE_MODERN, token));
    uint8_t p[256];
    size_t n = packet(p, 0, 2, 100, 0, 0);
    memcpy(p + 16, server, sizeof server);
    d2k_pf_out out;
    CHECK(!d2k_session_preflight_packet_path(s, p, n, 10, &out, 7));
    CHECK(!out.count && !d2k_session_preflight_calls(s));
    d2k_session_free(s);
    puts("test_unscoped_trial_leaves_syn_alone");
}

static void test_owned_flow_stays_on_its_path(void) {
    d2k_session *s = setup(1);
    uint8_t p[256];
    size_t n = packet(p, 0, 2, 100, 0, 0);
    d2k_pf_out out;
    CHECK(d2k_session_preflight_packet_path(s, p, n, 10, &out, 7));
    CHECK(out.count == 1);
    uint64_t calls = d2k_session_preflight_calls(s);
    CHECK(!d2k_session_preflight_packet_path(s, p, n, 11, &out, 8));
    CHECK(out.count == 0);
    n = packet(p, 1, 0x12, 900, 101, 0);
    d2k_session_set_hook(s, D2K_HOOK_FORWARD);
    CHECK(!d2k_session_preflight_packet_path(s, p, n, 12, &out, 8));
    CHECK(out.count == 0);
    CHECK(!d2k_session_preflight_packet_path(s, p, n, 13, &out, 0));
    CHECK(out.count == 0);
    CHECK(d2k_session_preflight_calls(s) == calls);
    CHECK(d2k_session_preflight_packet_path(s, p, n, 14, &out, 7));
    CHECK(out.count == 2);
    d2k_session_free(s);
    puts("test_owned_flow_stays_on_its_path");
}
static const char combined_text[]="d2k-plan 1 20\nproto tcp tls\nid 0102030405060708090a0b0c0d0e0f10\n"
        "payload 1 160301\npreflight window=7 wscale=2 pieces=2 hello=own timeout=1370 data=1\n"
        "handover apply\nwire tcp-template-v1\ninput tls-sni\nsplit payload_start +1\norder forward\n";
static void test_combined_abort_releases_without_admission(void) {
    for(int mode=0;mode<3;mode++) {
        d2k_session *s=d2k_session_new(16,64);CHECK(s);
        uint8_t tlv[2048],p[256],buf[32768];size_t tn=0;char err[200];d2k_plan *plan=NULL;
        CHECK(!d2k_plan_text_to_tlv(combined_text,tlv,sizeof tlv,&tn,err,sizeof err));
        CHECK(!d2k_plan_load(tlv,tn,&plan,err,sizeof err));
        uint8_t ip[]={192,0,2,1},token[16]={1};
        CHECK(!d2k_plantab_set_endpoint_trial_port(d2k_session_plans(s),ip,4,htons(443),htons(45678),1,plan,D2K_PLAN_SHAPE_LEGACY,token));
        CHECK(!d2k_session_set_preflight(s,1));d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        io_record sent={0};d2k_preflight_io io={&sent,mode==2?failing_drop:io_drop,mode==0?failing_send:io_send};
        size_t n=packet(p,0,2,100,0,0);
        CHECK(d2k_preflight_path_packet(s,p,n,123,100,&io)==(mode==2?-1:1));
        if(mode==1)CHECK(!d2k_preflight_path_flush(s,200,&io));
        if(mode==2)CHECK(!sent.sent);
        else CHECK(sent.sent==2 && sent.len==n && !memcmp(sent.packet,p,n));
        CHECK(!d2k_session_preflight_next_ns(s));
        n=packet(p,0,0x18,101,991,sizeof hello);memcpy(p+40,hello,sizeof hello);
        d2k_result r;d2k_session_packet_probe(s,p,n,600,buf,sizeof buf,&r);
        CHECK(!r.applied && !r.n_out);
        const d2k_journal *j=d2k_session_journal(s);
        for(size_t k=0;k<d2k_journal_count(j);k++)
            CHECK(d2k_journal_at(j,k)->kind!=D2K_JRN_PREFLIGHT_HANDOVER);
        d2k_session_free(s);
    }
}
static void test_composed_outgoing_needs_own_handover(void) {
    const char *text=combined_text;
    for(int mode=0;mode<5;mode++) {
        int owned=mode!=0;
        d2k_session *s=d2k_session_new(16,64);CHECK(s);
        uint8_t tlv[2048],p[256],buf[32768];size_t tn=0;char err[200];d2k_plan *plan=NULL;
        CHECK(!d2k_plan_text_to_tlv(text,tlv,sizeof tlv,&tn,err,sizeof err));
        CHECK(!d2k_plan_load(tlv,tn,&plan,err,sizeof err));
        uint8_t ip[]={192,0,2,1},token[16]={1};
        CHECK(!d2k_plantab_set_endpoint_trial_port(d2k_session_plans(s),ip,4,htons(443),htons(45678),1,plan,D2K_PLAN_SHAPE_LEGACY,token));
        CHECK(!d2k_session_set_preflight(s,1));d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        d2k_pf_out out;d2k_result result;size_t n=packet(p,0,2,100,0,0);
        if(owned) {
            CHECK(d2k_session_preflight_packet(s,p,n,100,&out));
            n=packet(p,1,0x12,900,101,0);CHECK(d2k_session_preflight_packet(s,p,n,200,&out));
            n=packet(p,1,0x18,901,104,10);CHECK(d2k_session_preflight_packet(s,p,n,300,&out));
            n=packet(p,1,0x18,911,104,10);CHECK(d2k_session_preflight_packet(s,p,n,400,&out));
            n=packet(p,1,0x12,990,101,0);CHECK(!d2k_session_preflight_packet(s,p,n,500,&out));
        }
        if(mode==2 || mode==3) {
            CHECK(d2k_plantab_del_endpoint_trial(d2k_session_plans(s),ip,4,htons(443),D2K_PLAN_SHAPE_LEGACY,token)==1);
            char replacement[1024];snprintf(replacement,sizeof replacement,"%s",text);
            if(mode==3)strstr(replacement,"0102030405")[0]='f';
            CHECK(!d2k_plan_text_to_tlv(replacement,tlv,sizeof tlv,&tn,err,sizeof err));
            plan=NULL;CHECK(!d2k_plan_load(tlv,tn,&plan,err,sizeof err));
            CHECK(!d2k_plantab_set_endpoint_trial_port(d2k_session_plans(s),ip,4,htons(443),htons(45678),2,plan,D2K_PLAN_SHAPE_LEGACY,token));
        }
        n=packet(p,0,2,100,0,0);d2k_session_observe_tcp(s,p,n,550);
        if(mode==4)d2k_session_set_packet_path(s,9);
        n=packet(p,0,0x18,101,991,sizeof hello);memcpy(p+40,hello,sizeof hello);
        d2k_session_packet_probe(s,p,n,600,buf,sizeof buf,&result);
        if(mode==1) {
            if(!result.applied)fprintf(stderr,"combined skip: %s\n",result.skipped?result.skipped:"");
            CHECK(result.applied && result.n_out==2 && result.verdict==D2K_VERDICT_DROP);
            if(result.n_out==2) {
                CHECK(result.out[0].len==41 && result.out[1].len==40+sizeof hello-1);
                CHECK(!memcmp(buf+result.out[0].off+40,hello,1));
                CHECK(!memcmp(buf+result.out[1].off+40,hello+1,sizeof hello-1));
                CHECK(!memcmp(buf+result.out[0].off+24,(uint8_t[]){0,0,0,101},4));
                CHECK(!memcmp(buf+result.out[1].off+24,(uint8_t[]){0,0,0,102},4));
            }
        } else CHECK(!result.applied && !result.n_out);
        d2k_session_free(s);
    }
}
static void test_combined_client_lease_and_retry(void) {
    for(int mode=0;mode<5;mode++) {
        d2k_session *s=d2k_session_new(16,64);CHECK(s);
        CHECK(!d2k_session_set_preflight(s,1));
        d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);d2k_session_set_packet_path(s,7);
        uint8_t tlv[2048],p[256],buf[32768],id[16]={1};size_t tn=0;char err[200];d2k_plan *plan=NULL;
        CHECK(!d2k_plan_text_to_tlv(combined_text,tlv,sizeof tlv,&tn,err,sizeof err));
        CHECK(!d2k_plan_load(tlv,tn,&plan,err,sizeof err));
        d2k_pf_scope scope={.family=4,.client={192,168,1,9},.server={192,0,2,1},
            .shape=D2K_PLAN_SHAPE_LEGACY,.server_port=htons(443),.path=7,.name="a.example.com"};
        CHECK(!d2k_session_set_preflight_lease(s,&scope,1,mode==1?599:5000,id,plan));
        d2k_pf_out out;d2k_result r;size_t n=packet(p,0,2,100,0,0);
        CHECK(d2k_session_preflight_packet_path(s,p,n,100,&out,7));
        n=packet(p,1,0x12,900,101,0);CHECK(d2k_session_preflight_packet_path(s,p,n,200,&out,7));
        n=packet(p,1,0x18,901,104,10);CHECK(d2k_session_preflight_packet_path(s,p,n,300,&out,7));
        n=packet(p,1,0x18,911,104,10);CHECK(d2k_session_preflight_packet_path(s,p,n,400,&out,7));
        n=packet(p,1,0x12,990,101,0);CHECK(!d2k_session_preflight_packet_path(s,p,n,500,&out,7));
        if(mode==2) {
            plan=NULL;CHECK(!d2k_plan_load(tlv,tn,&plan,err,sizeof err));
            CHECK(!d2k_session_set_preflight_lease(s,&scope,501,5000,id,plan));
        }
        n=packet(p,0,2,100,0,0);d2k_session_observe_tcp(s,p,n,550);
        n=packet(p,0,0x18,101,991,sizeof hello);memcpy(p+40,hello,sizeof hello);
        if(mode==3)p[101]='b'; /* a different SNI on the same IP */
        d2k_session_packet(s,p,n,600,buf,sizeof buf,&r);
        if(mode==0 || mode==4) {
            CHECK(r.applied && r.n_out==2 && r.binding.generation && !memcmp(r.trial_id,id,16));
            for(size_t i=0;i<=r.n_out;i++)d2k_session_sent(s,610+i,&r.key,r.execution_id);
            io_record delivered={.dropped=1}; /* SYN DROP was honored above. */
            d2k_preflight_io io={&delivered,io_drop,io_send};
            CHECK(!d2k_preflight_path_complete_on(s,p,n,620,&io,7));
            CHECK(delivered.sent==1 && delivered.mark==D2K_PF_TOKEN_MARK);
            CHECK(!d2k_session_preflight_next_ns(s));
            if(mode==4) {
                /* Same tuple, new TCP incarnation: its early data cannot
                 * borrow the completed connection's outgoing admission. */
                n=packet(p,0,2,2000,0,0);
                CHECK(d2k_session_preflight_packet_path(s,p,n,650,&out,7));
                d2k_session_observe_tcp(s,p,n,660);
                n=packet(p,0,0x18,2001,991,sizeof hello);memcpy(p+40,hello,sizeof hello);
            }
            d2k_session_packet(s,p,n,700,buf,sizeof buf,&r);
            if(mode==0)CHECK(r.applied && r.n_out==2 && r.replay_tls_bytes==sizeof hello);
            else CHECK(!r.applied && !r.n_out);
        } else CHECK(!r.applied && !r.n_out);
        d2k_session_free(s);
    }
}
int main(void){test_provider_ip_preflight();test_combined_abort_releases_without_admission();test_combined_client_lease_and_retry();test_composed_outgoing_needs_own_handover();test_unscoped_trial_leaves_syn_alone();test_owned_flow_stays_on_its_path();test_lease_syn_requires_exact_context();test_permanent_preflight_does_not_guess_syn_context();test_plan19_delayed_handover_wiring();test_cleanup_token_retry();test_tick_send_failure_releases_syn();test_cleanup_marks_reach_sender();test_failed_reset_does_not_duplicate_released_syn();test_preflight_not_payload_program();test_reset_failure_still_releases_original();test_shutdown_returns_owned_syn();test_send_failure_returns_original();test_daemon_ownership_adapter();test_events_emitted();test_session_syn_path();test_syn_matches_endpoint_plan();test_preflight_switch_off();test_original_syn_owned_and_resent();test_server_probe_packets_dropped();test_timer_drives_tick();printf("wiring: %d failures\n",fails);return !!fails;}
