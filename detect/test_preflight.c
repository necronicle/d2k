/* Test-only response-gate peer. Real raw.c episodes and Plan executor;
 * socket/routing/rule boundaries are memory doubles, never network traffic.
 * No bind/listen, host firewall commands or product preflight implementation.
 * This models a hypothesis; it is not evidence about a field DPI. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define D2K_RAW_UNIT_TEST 1
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
static ssize_t box_sendto(int,const void *,size_t,int,const struct sockaddr *,socklen_t);
static ssize_t box_recvfrom(int,void *,size_t,int,struct sockaddr *,socklen_t *);
static int box_socket(int,int,int);
static int box_setsockopt(int,int,int,const void *,socklen_t);
static int box_bind(int,const struct sockaddr *,socklen_t);
static int box_connect(int,const struct sockaddr *,socklen_t);
static int box_getsockname(int,struct sockaddr *,socklen_t *);
static FILE *box_popen(const char *,const char *);
#define popen box_popen
#define pclose fclose
#define socket box_socket
#define setsockopt box_setsockopt
#define bind box_bind
#define connect box_connect
#define getsockname box_getsockname
#define sendto box_sendto
#define recvfrom box_recvfrom
#include <stdint.h>
#include "d2k_detect.h"
static int64_t box_now_ms(void);
#define d2k_now_ms box_now_ms
#include "raw.c"
#undef d2k_now_ms
#undef popen
#undef pclose
#undef socket
#undef setsockopt
#undef bind
#undef connect
#undef getsockname
#undef sendto
#undef recvfrom
#include <fcntl.h>
#include "d2k_hello.h"
#include "d2k_wire.h"
#include "d2k_preflight_probe.h"
static int64_t clock_offset;
static unsigned handover_waits;
int probe_sleep_us(uint32_t us) {
    if (us==60000) handover_waits++;
    clock_offset+=us/1000;return 0;
}
static unsigned syn_rtt = 2;
static int peer_timestamps;
static unsigned data_options_len;
static uint8_t data_options[40];
/* Only peer events advance model time; host scheduling cannot change RTT. */
static int64_t box_now_ms(void) { return clock_offset; }
static unsigned small_syns, white_sent, own_sent, largest_k;
static size_t flight_limit=47;
static uint8_t realistic_flight[5125];
static const uint8_t *flight;
static unsigned all_syns, baseline_syns;
static int vary_carry;
static int measurement_active;
static int fin_on_reply, classifier_fixture;
static int event_timeout;
static int measured_event(d2k_raw_episode *ep,int timeout,const d2k_detect_stop *stop,
    uint8_t *buf,size_t cap,d2k_raw_packet_event *ev,d2k_raw_observation *obs)
{ event_timeout=timeout; return d2k_raw_episode_event(ep,timeout,stop,buf,cap,ev,obs); }
#define d2k_raw_episode_event measured_event
#define d2k_now_ms box_now_ms
#define d2k_sleep_us probe_sleep_us
#include "preflight.c"
#undef d2k_sleep_us
#undef d2k_now_ms
#undef d2k_raw_episode_event

static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"preflight:%d: %s\n",__LINE__,#c); failures++; } } while (0)
typedef struct {
    int carry_over_rst;
    unsigned need_pieces, max_window;
    int own_hello_passes;
} fake_box_cfg;
typedef struct {
    uint8_t local[4], remote[4];
    uint16_t sport, dport;
    int used, passed, small_used;
    unsigned pieces;
    uint32_t isn;
    unsigned handover_syns;
} fake_box_flow;
static fake_box_cfg cfg;
static fake_box_flow flows[16384], *flow;
/* Complete TLS 1.2 ServerHello, used only as a recognizable first flight. */
static const uint8_t server_hello[47] = {
    0x16,3,3,0,42, 2,0,0,38, 3,3,
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
    0,0xc0,0x2f,0
};
static const char own_name[]="client.example", white_name[]="white.example";
static const char *accepted_alternate=white_name;
static const char *reference_alternate;
static uint8_t local_ip[4]={192,0,2,1};
static uint32_t client_next, server_next;
static unsigned window, scale;
static int offered_ws;
static uint8_t peer_synack[64];
static size_t peer_synack_len;
static int syn_pending, ack_pending, hello_ready, eligible;
static int silent_baseline_ack;
static int carry_requires_unacked_piece;
static int carry_requires_same_isn;
static int delayed_handover_synack;
static unsigned receive_timeout_ms;
static size_t response_at, response_acked, wire_packets;
static const char direct_plan[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";

static fake_box_flow *lookup(const uint8_t *p)
{
    for(size_t i=0;i<16384;i++) {
        fake_box_flow *f=&flows[i];
        if(f->used && !memcmp(f->local,p+12,4) && !memcmp(f->remote,p+16,4) &&
           f->sport==rd16(p+20) && f->dport==rd16(p+22)) return f;
    }
    for(size_t i=0;i<16384;i++) if(!flows[i].used) {
        fake_box_flow *f=&flows[i]; f->used=1;
        memcpy(f->local,p+12,4); memcpy(f->remote,p+16,4);
        f->sport=rd16(p+20); f->dport=rd16(p+22); return f;
    }
    CHECK(0); return NULL;
}
/* The permission belongs to the four-tuple, not the raw episode or its ISN.
 * Small-window pieces cross a closed gate; K such pieces open it fully. */
static int response_allowed(void)
{
    return (flow->passed && (!vary_carry || baseline_syns%2)) || (eligible && window>0 && window<=cfg.max_window);
}
static void response_piece(void)
{
    if(eligible && window>0 && window<=cfg.max_window) {
        flow->pieces++;
        if(flow->pieces>=cfg.need_pieces) flow->passed=1;
    }
}
static void reset_flow(void)
{
    flow->pieces=0;
    if(!cfg.carry_over_rst) flow->passed=0;
}

static ssize_t box_sendto(int fd,const void *buf,size_t n,int flags,
                         const struct sockaddr *addr,socklen_t alen)
{
    (void)fd;(void)flags;(void)addr;(void)alen;
    const uint8_t *p=buf;
    CHECK(n>=40 && (p[0]>>4)==4);
    if(n<40) {errno=EINVAL;return -1;}
    CHECK(d2k_wire_tcp_checksum_ok(p,n)); wire_packets++;
    size_t h=20+(p[32]>>4)*4;
    CHECK(h<=n); if(h>n) return -1;
    flow=lookup(p); if(!flow) return -1;
    if(p[33]&TCP_RST) { if(flow->pieces>largest_k)largest_k=flow->pieces; reset_flow(); hello_ready=0; return (ssize_t)n; }
    if(p[33]&TCP_SYN) {
        if(flow->small_used && rd16(p+34)==65535)flow->handover_syns++;
        if(carry_requires_same_isn && flow->isn!=rd32(p+24))flow->passed=0;
        flow->isn=rd32(p+24);
        /* SYN starts fresh TCP coordinates, preserving only box permission. */
        all_syns++;
        if(measurement_active && rd16(p+34)==65535 && !flow->small_used) baseline_syns++;
        if(rd16(p+34)==1) {
            if(measurement_active)CHECK(!flow->small_used);
            flow->small_used=1;small_syns++;
        }
        flow->pieces=0; response_at=response_acked=0;
        hello_ready=eligible=ack_pending=0; syn_pending=1;
        client_next=rd32(p+24)+1; server_next=7001; scale=0;offered_ws=0;
        for(size_t i=40;i<h;) {
            unsigned kind=p[i]; if(!kind) break;
            if(kind==1) {i++;continue;}
            if(i+1>=h || p[i+1]<2 || i+p[i+1]>h) break;
            if(kind==3 && p[i+1]==3) {scale=p[i+2];offered_ws=1;}
            i+=p[i+1];
        }
        CHECK(scale<=14);
        if(measurement_active && reference_alternate && rd16(p+34)==1)
            CHECK(offered_ws && scale==1);
    } else {
        window=(unsigned)rd16(p+34)<<scale;
        if(n>h) {
            data_options_len=(unsigned)(h-40);
            memcpy(data_options,p+40,data_options_len);
            size_t off=0,len=0;
            /* Test inputs are single-segment complete ClientHellos. */
            int parsed=d2k_hello_sni(p+h,n-h,&off,&len)==0;
            int own=parsed && len==strlen(own_name) && !memcmp(p+h+off,own_name,len);
            int white=parsed && len==strlen(white_name) && !memcmp(p+h+off,white_name,len);
            if(!classifier_fixture)CHECK(parsed && (own || white));
            if(white) white_sent++;
            if(own) own_sent++;
            int alternate=parsed && len==strlen(accepted_alternate) &&
                          !memcmp(p+h+off,accepted_alternate,len);
            eligible=alternate || (own && cfg.own_hello_passes);
            hello_ready=1; ack_pending=!(silent_baseline_ack && !flow->small_used);
            client_next=rd32(p+24)+(uint32_t)(n-h);
        } else if((p[33]&TCP_ACK) && rd32(p+28)>=7001) {
            response_acked=(size_t)(rd32(p+28)-7001);
            if(carry_requires_unacked_piece && flow->pieces>=cfg.need_pieces)
                flow->passed=0;
        }
    }
    return (ssize_t)n;
}
static ssize_t box_recvfrom(int fd,void *buf,size_t cap,int flags,
                           struct sockaddr *addr,socklen_t *alen)
{
    (void)fd;(void)flags;(void)addr;(void)alen;
    if(!flow) {errno=EAGAIN;return -1;}
    uint8_t tcpflags=TCP_ACK; const uint8_t *data=NULL; size_t take=0;
    uint32_t seq=server_next;
    if(syn_pending && delayed_handover_synack && flow->small_used &&
       flow->handover_syns && flow->handover_syns<4) {
        clock_offset+=10;errno=EAGAIN;return -1;
    }
    if(syn_pending) {clock_offset+=syn_rtt;syn_pending=0; tcpflags|=TCP_SYN; seq=7000;}
    else if(ack_pending) ack_pending=0; /* Hello ACK crosses even a closed gate. */
    else if(hello_ready && response_at<flight_limit && response_acked==response_at && response_allowed()) {
        take=flight_limit-response_at;
        if(take>window) take=window;
        if(!take) {errno=EAGAIN;return -1;}
        data=flight+response_at; response_at+=take; server_next+=(uint32_t)take;
        response_piece();
    } else {clock_offset+=6000;errno=EAGAIN;return -1;}
    if(take && window>1 && fin_on_reply) tcpflags|=TCP_FIN;
    d2k_poison none={0};
    /* Both peers must offer WS: server shift 0 governs our receive window;
     * the client's offered shift governs the response sender above. */
    static const uint8_t peer_ws[]={1,3,3,0};
    static const uint8_t peer_ws_ts[]={1,3,3,0,1,1,8,10,0,0,4,210,0,0,0,1};
    int negotiate=(tcpflags&TCP_SYN) && offered_ws;
    size_t n=build_ipv4_tcp_window(buf,cap,flow->remote,flow->local,
        flow->dport,flow->sport,seq,client_next,tcpflags,data,take,&none,
        negotiate?(peer_timestamps?peer_ws_ts:peer_ws):NULL,
        negotiate?(peer_timestamps?sizeof peer_ws_ts:sizeof peer_ws):0,65535);
    if(tcpflags&TCP_SYN) {
        CHECK(n<=sizeof peer_synack);
        if(n<=sizeof peer_synack) {memcpy(peer_synack,buf,n);peer_synack_len=n;}
    }
    return (ssize_t)n;
}
static int box_socket(int domain,int type,int proto)
{ (void)type;(void)proto;CHECK(domain==AF_INET);return open("/dev/null",O_RDONLY); }
static int box_setsockopt(int fd,int level,int name,const void *v,socklen_t n)
{
    (void)fd;(void)n;
    if(level==SOL_SOCKET && name==SO_RCVTIMEO) {
        const struct timeval *tv=v;
        receive_timeout_ms=(unsigned)(tv->tv_sec*1000+tv->tv_usec/1000);
    }
    return 0;
}
static int box_bind(int fd,const struct sockaddr *a,socklen_t n)
{ (void)fd;(void)a;(void)n;CHECK(0);return -1; }
static int box_connect(int fd,const struct sockaddr *a,socklen_t n)
{ (void)fd;(void)a;(void)n;return 0; }
static int box_getsockname(int fd,struct sockaddr *a,socklen_t *n)
{
    (void)fd; struct sockaddr_in local={0}; local.sin_family=AF_INET;
    memcpy(&local.sin_addr,local_ip,4);memcpy(a,&local,sizeof local);*n=sizeof local;return 0;
}
/* raw.c's initial sweep uses popen directly, outside the rule hook. Supply
 * an empty in-memory rules listing too, so even this read cannot spawn a shell. */
static FILE *box_popen(const char *cmd,const char *mode)
{
    CHECK(strstr(cmd,"-S OUTPUT")!=NULL && !strcmp(mode,"r"));
    return tmpfile();
}
static int box_rule(const char *cmd) { (void)cmd;return 0; }
static void fixture(int carry,int own)
{
    cfg=(fake_box_cfg){carry,3,1,own}; memset(flows,0,sizeof flows);flow=NULL;
    silent_baseline_ack=0;
    carry_requires_unacked_piece=0;
    carry_requires_same_isn=0;
    delayed_handover_synack=0;
    memcpy(local_ip,(uint8_t[]){192,0,2,1},4);wire_packets=0;
    d2k_raw_rule_hook=box_rule;
    all_syns=0;baseline_syns=0;vary_carry=0;handover_waits=0;measurement_active=0;flight=server_hello;classifier_fixture=0;
    small_syns=white_sent=own_sent=largest_k=0;flight_limit=47;fin_on_reply=0; clock_offset=0;syn_rtt=2;event_timeout=0;
}
static d2k_raw_episode *open_at(uint16_t sport,uint16_t win,int wscale,const uint8_t ip[4],uint16_t port)
{
    d2k_raw_shape shape={.sport=sport,.syn_window=win,.syn_wscale=(int8_t)wscale,.data_window=win};
    char err[200]="";d2k_raw_observation obs;
    d2k_raw_episode *ep=d2k_raw_episode_open_shaped(ip,4,port,20,0,0,&shape,NULL,err,sizeof err,&obs);
    CHECK(ep!=NULL);CHECK(obs.connected);
    if(!ep) fprintf(stderr,"open: %s\n",err);
    return ep;
}
static d2k_raw_episode *open_probe(uint16_t sport,uint16_t win)
{ return open_at(sport,win,0,(uint8_t[]){198,51,100,7},443); }
static void send_hello(d2k_raw_episode *ep,const char *name)
{
    char err[200];d2k_trigger tr;d2k_raw_observation obs;
    CHECK(d2k_trigger_tls(name,1,&tr,err,sizeof err)==0);
    CHECK(d2k_raw_episode_send(ep,0,(uint32_t)tr.len,&tr,direct_plan,NULL,err,sizeof err,&obs)==0);
    uint8_t b[128];d2k_raw_packet_event event;
    CHECK(d2k_raw_episode_event(ep,10,NULL,b,sizeof b,&event,&obs)==0);
    CHECK(event.flags==TCP_ACK && event.payload_len==0 && event.ack_in_sent_range);
    CHECK(event.ack_offset==tr.len && obs.transport.acked_end==tr.len);
}
static void silence(d2k_raw_episode *ep)
{
    uint8_t b[128];size_t have=999;d2k_raw_observation obs;
    CHECK(d2k_raw_episode_read(ep,10,NULL,b,sizeof b,&have,1,&obs)==-1);
    CHECK(have==0 && obs.kind==D2K_RAW_OBS_RESPONSE_TIMEOUT && obs.response_bytes==0);
}
static void piece(d2k_raw_episode *ep,size_t offset,size_t len)
{
    uint8_t b[128];d2k_raw_packet_event event;
    CHECK(d2k_raw_episode_event(ep,10,NULL,b,sizeof b,&event,NULL)==0);
    CHECK(event.payload_len==len && event.sequence_offset==offset && event.ack_in_sent_range);
    CHECK(!memcmp(b,server_hello+offset,len));
}
static void full_hello(d2k_raw_episode *ep)
{
    uint8_t b[128];size_t have=0;d2k_raw_observation obs;
    CHECK(d2k_raw_episode_read(ep,10,NULL,b,sizeof b,&have,sizeof server_hello,&obs)==0);
    CHECK(have==sizeof server_hello && !memcmp(b,server_hello,sizeof server_hello));
}
static void reset(d2k_raw_episode *ep)
{ CHECK(d2k_raw_episode_reset(ep)==0);d2k_raw_episode_free(ep); }

static void test_fake_box_blocks_big_window(void)
{
    fixture(1,1);d2k_raw_episode *ep=open_probe(41234,65535);if(!ep)return;
    send_hello(ep,own_name);silence(ep);
    reset(ep);
}
static void test_fake_box_passes_after_pieces(void)
{
    for(unsigned k=0;k<=3;k++) {
        fixture(1,1);d2k_raw_episode *ep=open_probe(41234,1);if(!ep)continue;
        send_hello(ep,own_name);
        for(unsigned i=0;i<k;i++)piece(ep,i,1);
        reset(ep);
        ep=open_probe(41234,65535);if(!ep)continue;
        send_hello(ep,own_name);
        if(k==3)full_hello(ep);else silence(ep);
        reset(ep);
    }
}
static void test_fake_box_rst_clears_when_no_carry(void)
{
    fixture(0,1);d2k_raw_episode *ep=open_probe(41234,1);if(!ep)return;
    send_hello(ep,own_name);for(unsigned i=0;i<3;i++)piece(ep,i,1);
    CHECK(d2k_raw_episode_set_window(ep,65535)==0);
    /* Remaining flight in the already permitted connection can be read. */
    piece(ep,3,1); /* ACK advertises the newly selected window. */
    uint8_t b[128];size_t have;
    CHECK(d2k_raw_episode_read(ep,10,NULL,b,sizeof b,&have,43,NULL)==0);
    CHECK(have==43 && !memcmp(b,server_hello+4,43));
    reset(ep);ep=open_probe(41234,65535);if(!ep)return;
    send_hello(ep,own_name);silence(ep);reset(ep);
}
static void test_fake_box_other_port_not_inherited(void)
{
    fixture(1,1);d2k_raw_episode *ep=open_probe(41234,1);if(!ep)return;
    send_hello(ep,own_name);for(unsigned i=0;i<3;i++)piece(ep,i,1);reset(ep);
    ep=open_probe(41235,65535);if(!ep)return;
    send_hello(ep,own_name);silence(ep);reset(ep);
    ep=open_probe(41234,65535);if(!ep)return;
    send_hello(ep,own_name);full_hello(ep);reset(ep);
}
static void test_fake_box_white_name_only(void)
{
    fixture(1,0);d2k_raw_episode *ep=open_probe(41234,1);if(!ep)return;
    send_hello(ep,own_name);silence(ep);reset(ep);
    ep=open_probe(41234,65535);if(!ep)return;
    send_hello(ep,own_name);silence(ep);reset(ep);
    ep=open_probe(41234,1);if(!ep)return;
    send_hello(ep,white_name);for(unsigned i=0;i<3;i++)piece(ep,i,1);reset(ep);
    ep=open_probe(41234,65535);if(!ep)return;
    send_hello(ep,own_name);full_hello(ep);reset(ep);
}
static void test_fake_box_window_scale_and_disabled_pieces(void)
{
    for(int disabled=0;disabled<=1;disabled++) {
        fixture(1,1);cfg.max_window=disabled?0:2;
        d2k_raw_episode *ep=open_at(41234,2,1,(uint8_t[]){198,51,100,7},443);
        if(!ep)continue;
        send_hello(ep,own_name);silence(ep);reset(ep); /* effective window 4 */
        ep=open_at(41234,1,1,(uint8_t[]){198,51,100,7},443);if(!ep)continue;
        send_hello(ep,own_name);
        if(disabled)silence(ep);
        else {
            piece(ep,0,2);
            CHECK(d2k_raw_episode_set_window(ep,2)==0);
            piece(ep,2,2); /* next ACK changes effective window to 4 */
            silence(ep); /* only two qualifying pieces; still closed */
        }
        reset(ep);
    }
}
static void test_fake_box_other_addresses_not_inherited(void)
{
    fixture(1,1);d2k_raw_episode *ep=open_probe(41234,1);if(!ep)return;
    send_hello(ep,own_name);for(unsigned i=0;i<3;i++)piece(ep,i,1);reset(ep);
    ep=open_at(41234,65535,0,(uint8_t[]){198,51,100,8},443);if(!ep)return;
    send_hello(ep,own_name);silence(ep);reset(ep);
    ep=open_at(41234,65535,0,(uint8_t[]){198,51,100,7},444);if(!ep)return;
    send_hello(ep,own_name);silence(ep);reset(ep);
    local_ip[3]=2;ep=open_probe(41234,65535);if(!ep)return;
    send_hello(ep,own_name);silence(ep);reset(ep);
    local_ip[3]=1;ep=open_probe(41234,65535);if(!ep)return;
    send_hello(ep,own_name);full_hello(ep);reset(ep);
}
static void test_fake_box_negotiates_window_scale(void)
{
    fixture(1,1);peer_synack_len=0;
    d2k_raw_episode *ep=open_at(41234,1,1,(uint8_t[]){198,51,100,7},443);
    if(!ep)return;
    static const uint8_t peer_ws[]={1,3,3,0};
    CHECK(peer_synack_len==44 && !memcmp(peer_synack+40,peer_ws,sizeof peer_ws));
    reset(ep);
}

/* These assertions catch missing gate evidence, nonminimal K, RST state
 * loss, wrong hello source, unbounded K after exhausted flight, and fixed waits. */
static int measure_gate(d2k_preflight_meas *m,int vouched)
{
    d2k_opts o={0}; d2k_trigger t; char err[100];
    o.timeout_ms=20;o.control_vouched=vouched;
    CHECK(d2k_trigger_tls(own_name,1,&t,err,sizeof err)==0);
    CHECK(d2k_trigger_tls(white_name,1,&o.white,err,sizeof err)==0);
    o.white.accept=D2K_ACCEPT_TLSRECORD;
    snprintf(o.white.name,sizeof o.white.name,"white"); /* bridge_input contract */
    measurement_active=1;
    int rc=d2k_probe_preflight("198.51.100.7:443",&t,&o,m);
    printf("measurement carry=%d need=%u own=%d flight=%zu rc=%d K=%u probes=%u total=%u small=%u max=%u rtt=%u reason=%s\n",
        cfg.carry_over_rst,cfg.need_pieces,cfg.own_hello_passes,flight_limit,rc,
        m->pieces_needed,m->probes,all_syns,small_syns,largest_k,m->rtt_ms,m->reason);
    measurement_active=0;
    CHECK(m->probes==all_syns-m->baseline_probes);
    return rc;
}
static void test_gate_found_and_measured(void)
{
    fixture(1,1);d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);
    CHECK(m.response_gate==1 && m.pieces_pass==1 && m.window==1);
    CHECK(m.pieces_needed==3 && m.carry_over_rst==1 && m.rtt_ms==2);
    CHECK(small_syns==8 && largest_k==4);
}
static void test_gate_measures_delayed_handover(void)
{
    fixture(1,1);d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);
    CHECK(handover_waits==small_syns && handover_waits>0);
}
static void test_gate_requires_repeat_evidence(void)
{
    fixture(1,1);d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);
    CHECK(baseline_syns==2 && small_syns==8);
}
static void test_silent_ack_does_not_preclude_carry_experiment(void)
{
    fixture(1,1);silent_baseline_ack=1;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);
    CHECK(m.carry_over_rst && m.pieces_needed==3);
    fixture(0,1);silent_baseline_ack=1;
    CHECK(measure_gate(&m,1)==0);
    CHECK(!m.carry_over_rst);
    fixture(1,1);silent_baseline_ack=1;cfg.max_window=0;
    CHECK(measure_gate(&m,1)==0);
    CHECK(!m.response_gate && !m.pieces_pass && !m.carry_over_rst);
}
static void test_handover_retries_like_executor(void)
{
    fixture(1,1);cfg.need_pieces=1;delayed_handover_synack=1;
    d2k_trigger tr;d2k_opts opt={.timeout_ms=6000,.control_vouched=1};
    d2k_preflight_meas m;char err[100];
    CHECK(d2k_trigger_tls(own_name,1,&tr,err,sizeof err)==0);
    CHECK(d2k_probe_preflight("198.51.100.7:443",&tr,&opt,&m)==1);
    CHECK(m.carry_over_rst && m.rtt_ms==2);
    CHECK(receive_timeout_ms>0 && receive_timeout_ms<=60);
}
static void test_handover_replays_original_syn_sequence(void)
{
    fixture(1,1);cfg.need_pieces=1;carry_requires_same_isn=1;
    d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);
    CHECK(m.carry_over_rst && m.pieces_needed==1);
}
static void test_rst_follows_selected_piece_without_extra_ack(void)
{
    fixture(1,1);cfg.need_pieces=1;carry_requires_unacked_piece=1;
    d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);
    CHECK(m.carry_over_rst && m.pieces_needed==1);
}
static void test_gate_conflicting_repeats_do_not_apply(void)
{
    fixture(1,1);vary_carry=1;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==-1);
    CHECK(baseline_syns==4 && !m.carry_over_rst && !m.pieces_needed);
    CHECK(strstr(m.reason,"conflicting")!=NULL);
}
static void test_carry_lost_on_rst_no_plan(void)
{
    fixture(0,1);d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==0);
    CHECK(m.response_gate==1 && m.pieces_pass==1 && m.carry_over_rst==0);
    CHECK(m.pieces_needed==0);
}
static void test_pieces_blocked(void)
{
    fixture(1,1);cfg.max_window=0;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==0);CHECK(m.response_gate==1 && m.pieces_pass==0);
}
static void test_own_hello_preferred(void)
{
    fixture(1,1);d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);CHECK(m.hello_own==1 && !m.white_name[0] && white_sent==0);
}
static void test_k_stops_at_full_flight(void)
{
    fixture(0,1);cfg.need_pieces=100;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==0);
    CHECK(largest_k==47 && small_syns==14 && !m.carry_over_rst);
}
static void test_white_name_used_when_own_fails(void)
{
    fixture(1,0);d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);
    CHECK(m.hello_own==0 && !strcmp(m.white_name,white_name) && white_sent==8);
}
static void test_preflight_preserves_negotiated_timestamps(void)
{
    fixture(1,1);peer_timestamps=1;data_options_len=0;
    uint8_t ip[16]={198,51,100,7};d2k_opts opt={.timeout_ms=20};
    d2k_raw_observation obs;d2k_trigger tr;char err[100];
    CHECK(d2k_trigger_tls(own_name,1,&tr,err,sizeof err)==0);
    d2k_raw_episode *ep=pf_open(ip,4,443,0,1,1,1,&opt,&obs);
    CHECK(ep!=NULL);
    if(ep) {
        CHECK(pf_send(ep,&tr,&opt)==0);
        static const uint8_t expected[]={1,1,8,10,0,0,0,1,0,0,4,210};
        CHECK(data_options_len==sizeof expected && !memcmp(data_options,expected,sizeof expected));
        CHECK(pf_close(ep)==0);
    }
    peer_timestamps=0;
}
static void test_rtt_drives_timeouts(void)
{
    fixture(1,1);syn_rtt=200;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);CHECK(m.rtt_ms==200 && event_timeout==1600);
    fixture(1,1);syn_rtt=700;
    CHECK(measure_gate(&m,1)==1);CHECK(m.rtt_ms==700 && event_timeout==5000);
}
static void test_gate_without_vouch_sends_nothing(void)
{
    fixture(1,1);d2k_preflight_meas m;
    CHECK(measure_gate(&m,0)==0);CHECK(!m.response_gate && wire_packets==0);
}
static void test_gate_healthy_sends_no_small_probe(void)
{
    fixture(1,1);cfg.max_window=65535;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==2);CHECK(!m.response_gate && small_syns==0 && white_sent==0);
}


static void test_serverhello_with_fin_proves_carry(void)
{
    fixture(1,1);fin_on_reply=1;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);CHECK(m.carry_over_rst==1 && m.pieces_needed==3);
}
static void test_truncated_flight_is_incomplete(void)
{
    fixture(0,1);flight_limit=46;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==-1);CHECK(!m.carry_over_rst && !m.pieces_needed);
}
static void test_more_than_reference_pieces(void)
{
    fixture(1,1);cfg.need_pieces=9;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);CHECK(m.pieces_needed==9 && largest_k==16);
}
static void test_classifier_returns_gate(void)
{
    fixture(1,1);classifier_fixture=1;d2k_trigger t;d2k_opts o={0};d2k_result r;char err[100];
    CHECK(d2k_trigger_tls(own_name,1,&t,err,sizeof err)==0);
    snprintf(o.only,sizeof o.only,"model-no-poison");
    o.preflight_auto=1;o.timeout_ms=20;o.repeats=1;
    o.seed_whole=1;o.seed_repeats=1;o.seed_fail=1;
    d2k_classify_run("198.51.100.7:443",&t,&o,&r);
    CHECK(r.verdict==D2K_DV_RESPONSE_GATE && r.preflight.pieces_needed==3);
}


static void test_classifier_measures_alternative_hello(void)
{
    fixture(1,0);
    classifier_fixture=1;
    d2k_trigger trigger;
    d2k_opts opt={0};
    d2k_result result;
    char err[100];
    CHECK(d2k_trigger_tls(own_name,1,&trigger,err,sizeof err)==0);
    CHECK(d2k_trigger_tls(white_name,1,&opt.white,err,sizeof err)==0);
    opt.white.accept=D2K_ACCEPT_TLSRECORD;
    opt.response_probe_name=white_name;
    snprintf(opt.only,sizeof opt.only,"model-no-poison");
    opt.preflight_auto=1;
    opt.timeout_ms=20;
    opt.repeats=1;
    opt.seed_whole=1;
    opt.seed_repeats=1;
    opt.seed_fail=1;
    opt.known.response_gate=D2K_PROP_YES;
    opt.known.gate_carry=D2K_PROP_NO;
    opt.known.gate_hello_own=D2K_PROP_YES;
    d2k_classify_run("198.51.100.7:443",&trigger,&opt,&result);
    CHECK(result.verdict==D2K_DV_RESPONSE_GATE);
    CHECK(!result.preflight.hello_own && result.preflight.pieces_needed==3);
    CHECK(!strcmp(result.preflight.white_name,white_name));
}

static void test_automatic_gate_checks_second_probe_name(void)
{
    static const char observed[]="recent-direct.example";
    fixture(1,0);
    classifier_fixture=1;
    cfg.need_pieces=1;
    cfg.max_window=2;
    accepted_alternate=reference_alternate=observed;
    d2k_opts opt={.preflight_auto=1,.timeout_ms=20,.response_probe_name=observed};
    d2k_trigger trigger;
    d2k_preflight_meas result;
    char err[100];
    CHECK(d2k_trigger_tls(own_name,1,&trigger,err,sizeof err)==0);
    CHECK(d2k_trigger_tls(white_name,1,&opt.white,err,sizeof err)==0);
    measurement_active=1;
    CHECK(d2k_probe_preflight("198.51.100.7:443",&trigger,&opt,&result)==1);
    measurement_active=0;
    CHECK(!result.hello_own && result.pieces_needed==1);
    CHECK(result.window_scale==1);
    CHECK(!strcmp(result.white_name,accepted_alternate));
    CHECK(small_syns==2);
    CHECK(result.probes+result.baseline_probes==all_syns);
    accepted_alternate=white_name;
    reference_alternate=NULL;
}

static void test_automatic_gate_without_observed_name(void)
{
    fixture(1,0);
    classifier_fixture=1;
    cfg.need_pieces=1;
    d2k_opts opt={.preflight_auto=1,.timeout_ms=20};
    d2k_trigger trigger;
    d2k_preflight_meas result;
    char err[100];
    CHECK(d2k_trigger_tls(own_name,1,&trigger,err,sizeof err)==0);
    CHECK(d2k_trigger_tls(white_name,1,&opt.white,err,sizeof err)==0);
    measurement_active=1;
    CHECK(d2k_probe_preflight("198.51.100.7:443",&trigger,&opt,&result)==0);
    measurement_active=0;
    CHECK(result.response_gate && !result.carry_over_rst);
    CHECK(!result.white_name[0] && !white_sent && own_sent==all_syns);
}
static void test_failed_direct_carry_retains_combined_candidate(void)
{
    fixture(0,0);classifier_fixture=1;cfg.need_pieces=1;cfg.max_window=2;
    d2k_opts opt={.preflight_auto=1,.preflight_combined=1,.timeout_ms=20,
        .response_probe_name=white_name};
    d2k_trigger tr;d2k_preflight_meas m;char err[100];
    CHECK(!d2k_trigger_tls(own_name,1,&tr,err,sizeof err));
    CHECK(d2k_probe_preflight("198.51.100.7:443",&tr,&opt,&m)==3);
    CHECK(m.candidate.present && m.candidate.window==1 && m.candidate.window_scale==1 &&
          m.candidate.pieces==1 && m.candidate.rtt_ms==2 && m.candidate.response_bytes==2);
    CHECK(!strcmp(m.candidate.name,white_name) && !m.carry_over_rst && !m.pieces_needed);
    CHECK(small_syns==2); /* bounded repeated reference, no general K search */
    fixture(0,0);classifier_fixture=1;cfg.need_pieces=1;cfg.max_window=0;
    CHECK(d2k_probe_preflight("198.51.100.7:443",&tr,&opt,&m)==0);
    CHECK(!m.candidate.present && !m.carry_over_rst);
}

static int stop_gate;
static int stop_gate_check(void *ctx) {(void)ctx;return stop_gate;}
static void stop_after_gate(void *ctx,const d2k_obs *o)
{(void)ctx;if(!strcmp(o->probe,"response-gate"))stop_gate=1;}
static void test_classifier_fresh_direct_reply_stops(void)
{
    fixture(1,1);cfg.max_window=65535;classifier_fixture=1;
    d2k_trigger t;d2k_opts o={0};d2k_result r;char err[100];
    CHECK(d2k_trigger_tls(own_name,1,&t,err,sizeof err)==0);
    snprintf(o.only,sizeof o.only,"model-no-poison");
    o.control_vouched=1;o.timeout_ms=20;o.repeats=1;
    o.seed_whole=1;o.seed_repeats=1;o.seed_fail=1;
    stop_gate=0;o.cancel.fn=stop_gate_check;o.on_obs=stop_after_gate;
    d2k_classify_run("198.51.100.7:443",&t,&o,&r);
    CHECK(r.verdict==D2K_DV_FLAKY && !r.preflight.response_gate);
    CHECK(r.ntrace>2 && !strcmp(r.trace[r.ntrace-1].probe,"response-gate"));
    CHECK(small_syns==0 && white_sent==0);
}

/* 125-byte record containing a 116-byte ServerHello, then a 5000-byte
 * certificate record. This exposes scanning the flight instead of the hello. */
static void realistic(void)
{
    memcpy(realistic_flight,server_hello,sizeof server_hello);
    realistic_flight[4]=120;realistic_flight[8]=116;
    realistic_flight[125]=0x16;realistic_flight[126]=3;realistic_flight[127]=3;
    realistic_flight[128]=0x13;realistic_flight[129]=0x83;
    flight=realistic_flight;flight_limit=sizeof realistic_flight;
}
/* Integer ceil(log2(n)) for the positive K and L bounds below. */
static unsigned ceil_log2(unsigned n)
{
    unsigned bits=0;
    for(unsigned remaining=n-1;remaining;remaining>>=1)++bits;
    return bits;
}
static void test_k_search_logarithmic(void)
{
    fixture(1,1);realistic();cfg.need_pieces=6;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==1);CHECK(m.pieces_needed==6);
    /* удвоение + деление пополам, два соединения на опыт */
    CHECK(m.probes<=2*(4*ceil_log2(cfg.need_pieces)+2));
    printf("connections K6: total=%u questions23=%u small=%u max=%u\n",all_syns,all_syns-1,small_syns,largest_k);
}
static void test_no_carry_stops_at_serverhello(void)
{
    fixture(0,1);realistic();d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==0);CHECK(!m.carry_over_rst);
    CHECK(strstr(m.reason,"ServerHello")!=NULL);
    /* L: TLS record header + payload containing ServerHello. */
    const unsigned L=5+((unsigned)flight[3]<<8)+flight[4];
    /* удвоение + деление пополам, два соединения на опыт */
    CHECK(largest_k==125 && m.probes<=4*(ceil_log2(L)+1));
    printf("connections no-carry: total=%u questions23=%u small=%u max=%u\n",all_syns,all_syns-1,small_syns,largest_k);
}
static void test_need_pieces_above_serverhello_is_no_carry(void)
{
    fixture(1,1);realistic();cfg.need_pieces=126;d2k_preflight_meas m;
    CHECK(measure_gate(&m,1)==0);CHECK(!m.carry_over_rst && !m.pieces_needed);
    CHECK(strstr(m.reason,"ServerHello")!=NULL);
    /* L: TLS record header + payload containing ServerHello. */
    const unsigned L=5+((unsigned)flight[3]<<8)+flight[4];
    /* удвоение + деление пополам, два соединения на опыт */
    CHECK(largest_k==125 && m.probes<=4*(ceil_log2(L)+1));
    printf("connections above-hello: total=%u questions23=%u small=%u max=%u\n",all_syns,all_syns-1,small_syns,largest_k);
}

#define RUN(fn) do {int before=failures;fn();printf("%s: %s\n",#fn,failures==before?"PASS":"FAIL");}while(0)
int main(void)
{
    RUN(test_preflight_preserves_negotiated_timestamps);
    RUN(test_k_search_logarithmic);
    RUN(test_no_carry_stops_at_serverhello);
    RUN(test_need_pieces_above_serverhello_is_no_carry);
    RUN(test_fake_box_blocks_big_window);
    RUN(test_fake_box_passes_after_pieces);
    RUN(test_fake_box_rst_clears_when_no_carry);
    RUN(test_fake_box_other_port_not_inherited);
    RUN(test_fake_box_white_name_only);
    RUN(test_fake_box_window_scale_and_disabled_pieces);
    RUN(test_fake_box_other_addresses_not_inherited);
    RUN(test_fake_box_negotiates_window_scale);
    RUN(test_serverhello_with_fin_proves_carry);
    RUN(test_truncated_flight_is_incomplete);
    RUN(test_more_than_reference_pieces);
    RUN(test_classifier_returns_gate);
    RUN(test_classifier_measures_alternative_hello);
    RUN(test_automatic_gate_checks_second_probe_name);
    RUN(test_automatic_gate_without_observed_name);
    RUN(test_failed_direct_carry_retains_combined_candidate);
    RUN(test_classifier_fresh_direct_reply_stops);
    RUN(test_gate_found_and_measured);
    RUN(test_gate_requires_repeat_evidence);
    RUN(test_silent_ack_does_not_preclude_carry_experiment);
    RUN(test_rst_follows_selected_piece_without_extra_ack);
    RUN(test_handover_replays_original_syn_sequence);
    RUN(test_handover_retries_like_executor);
    RUN(test_gate_conflicting_repeats_do_not_apply);
    RUN(test_gate_measures_delayed_handover);
    RUN(test_carry_lost_on_rst_no_plan);
    RUN(test_pieces_blocked);
    RUN(test_own_hello_preferred);
    RUN(test_k_stops_at_full_flight);
    RUN(test_white_name_used_when_own_fails);
    RUN(test_rtt_drives_timeouts);
    RUN(test_gate_without_vouch_sends_nothing);
    RUN(test_gate_healthy_sends_no_small_probe);
    d2k_raw_flush_pending();
    printf("preflight: %d failure(s)\n",failures);return failures?1:0;
}
