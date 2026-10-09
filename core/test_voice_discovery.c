#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_voice_discovery.h"

static int calls, mode, fail;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); fail++; } } while (0)
static int alive(const char *p,uint32_t ip,uint16_t port,uint32_t src,uint16_t sport) {
    (void)p;(void)ip;(void)port;(void)src;(void)sport; return D2K_VOICE_ANSWERS;
}
static int resolve(const char *h,uint32_t *ip,uint16_t *p) {(void)h;(void)ip;(void)p;return -1;}
typedef struct { int fd, kind; } server;
static void *respond(void *arg) {
    server *s=arg;
    unsigned count=s->kind==1?13:s->kind==2?1:D2K_DISCOVERY_EXCHANGES + (s->kind==5 ? 1 : 0);
    uint8_t previous[4]={0};
    for(unsigned i=0;i<count;i++) {
        struct pollfd p={s->fd,POLLIN,0};
        if(poll(&p,1,2000)<=0)break;
        struct sockaddr_in a; socklen_t alen=sizeof a;
        uint8_t b[128]; ssize_t n=recvfrom(s->fd,b,sizeof b,0,(void*)&a,&alen);
        if(n!=74)continue;
        CHECK(b[0]==0 && b[1]==1 && b[2]==0 && b[3]==70);
        if(i)CHECK(memcmp(previous,b+4,4)!=0);
        memcpy(previous,b+4,4);
        if(s->kind==1 && i==12)break;
        if(s->kind==5 && i==7)continue;
        b[1]=2;memcpy(b+8,"127.0.0.1",10);b[72]=0x12;b[73]=0x34;
        if(s->kind==2)b[4]^=1;
        (void)sendto(s->fd,b,74,0,(void*)&a,alen);
    }
    return NULL;
}
static d2k_discovery_result probe(uint32_t ip, uint16_t port,
    const uint8_t *prefix, size_t len, uint32_t wait, uint32_t mark) {
    (void)ip; (void)port; (void)wait; (void)mark;
    calls++;
    d2k_discovery_result r = {0};
    r.marked = 1;
    r.sent = prefix || mode == 1 ? D2K_DISCOVERY_EXCHANGES : 13;
    r.received = prefix || mode == 1 ? D2K_DISCOVERY_EXCHANGES : 12;
    if (prefix) CHECK(len == 20 && prefix[0] == 0 && prefix[1] == 1 && prefix[4] == 0x21);
    if (mode == 2) r.received = 0;
    if (mode == 7 && !prefix) { r.received = 0; r.sent = 3; }
    if (mode == 9 && prefix && calls == 1) r.received = 12;
    if (mode == 8 && !prefix) { r.received = calls == 1 ? 1 : 0; r.sent = r.received + 3; }
    if (mode == 3 && calls == 2) r.received = 11;
    if (mode == 4) r.error = 1;
    if (mode == 5) r.marked = 0;
    if (mode == 6 && prefix) r.received = 12;
    return r;
}
int main(void) {
    d2k_discovery_probe_fn real=d2k_discovery_probe_hook;
    d2k_discovery_probe_hook = probe;
    d2k_voice_opt o = {0}; o.mark = 47;
    d2k_voice_res r;
    for (mode = 0; mode <= 6; mode++) {
        memset(&r, 0, sizeof r); r.ip = 1; r.port = 19298; r.marked = 1; calls = 0;
        int handled = d2k_voice_discovery_search(&o, &r);
        if (mode == 0) { CHECK(handled); CHECK(r.verdict == D2K_VOICE_BLOCKED); CHECK(r.arm_len == 20); CHECK(r.arm_copies == 1); CHECK(calls == 6); }
        if (mode == 1) { CHECK(handled); CHECK(r.verdict == D2K_VOICE_CLEAR); CHECK(!r.arm_len); CHECK(calls == 1); }
        if (mode == 2) { CHECK(!handled); CHECK(!r.arm_len); }
        if (mode == 3) { CHECK(handled); CHECK(r.verdict == D2K_VOICE_FLAKY); CHECK(!r.arm_len); }
        if (mode == 4 || mode == 5) { CHECK(handled); CHECK(r.verdict == D2K_VOICE_UNMEASURED); CHECK(!r.arm_len); }
        if (mode == 6) { CHECK(handled); CHECK(!r.arm_len); CHECK(r.verdict != D2K_VOICE_CLEAR); }
    }
    uint8_t known[20]={0,1,0,0,0x21,0x12,0xa4,0x42};
    mode=0;calls=0;o.known_discovery_prefix=known;
    memset(&r,0,sizeof r);r.marked=1;
    CHECK(d2k_voice_discovery_search(&o,&r));
    CHECK(r.verdict==D2K_VOICE_CLEAR && !r.arm_len && calls==3);
    o.known_discovery_prefix=NULL;
    mode=0;calls=0;known[19]=0x77;o.candidate_discovery_prefix=known;
    memset(&r,0,sizeof r);r.marked=1;
    CHECK(d2k_voice_discovery_search(&o,&r));
    CHECK(r.verdict==D2K_VOICE_BLOCKED && calls==6 &&
          r.discovery_verified && !memcmp(r.arm_bytes,known,20));
    mode=7;calls=0;
    memset(&r,0,sizeof r);r.marked=1;
    CHECK(d2k_voice_discovery_search(&o,&r));
    CHECK(r.verdict==D2K_VOICE_BLOCKED && r.discovery_verified && calls==6 &&
          !memcmp(r.arm_bytes,known,20));
    mode=8;calls=0;
    memset(&r,0,sizeof r);r.marked=1;
    CHECK(d2k_voice_discovery_search(&o,&r));
    CHECK(r.verdict==D2K_VOICE_BLOCKED && r.discovery_verified && calls==6);
    o.candidate_discovery_prefix=NULL;
    mode=6;calls=0;o.known_discovery_prefix=known;
    memset(&r,0,sizeof r);r.marked=1;
    CHECK(d2k_voice_discovery_search(&o,&r));
    CHECK(r.known_prefix_failed && !r.arm_len);
    mode=9;calls=0;
    memset(&r,0,sizeof r);r.marked=1;
    CHECK(d2k_voice_discovery_search(&o,&r));
    CHECK(r.verdict==D2K_VOICE_FLAKY && !r.known_prefix_failed && !r.arm_len);

    o.known_discovery_prefix=NULL;

    char plan[512]="d2k-plan 1 1\nid 00000000000000000000000000000000\nproto udp voice\npayload 1 000100002112a44265d1f10b0547ecf2025dafb8\npoison 1\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\npace 15000\n";
    CHECK(d2k_voice_discovery_prefix(plan,known));
    CHECK(!memcmp(known,"\x00\x01\x00\x00\x21\x12\xa4\x42",8));
    strcat(plan,"delay 1000\n");
    CHECK(!d2k_voice_discovery_prefix(plan,known));
    uint8_t response[74] = {0,2,0,70,1,2,3,4};
    memcpy(response+8,"192.0.2.1",10); response[72]=0x12; response[73]=0x34;
    CHECK(d2k_discovery_response(response,74,response+4));
    response[7]++; uint8_t ssrc[4]={1,2,3,4};
    CHECK(!d2k_discovery_response(response,74,ssrc));
    response[7]--; response[1]=1; CHECK(!d2k_discovery_response(response,74,ssrc));
    response[1]=2; response[3]=69; CHECK(!d2k_discovery_response(response,74,ssrc));
    response[3]=70; CHECK(!d2k_discovery_response(response,73,ssrc));
    memset(response+8,'x',64); CHECK(!d2k_discovery_response(response,74,ssrc));
    /* Historical [ASSURED] cannot clear a measured late cut. */
    mode=0;calls=0;o.discovery=1;o.ip=inet_addr("192.0.2.42");o.port=19298;o.ct_path="/dev/null";
    d2k_voice_alive_hook=alive;d2k_voice_resolve_hook=resolve;
    r=d2k_voice_run(&o);
    CHECK(r.verdict==D2K_VOICE_BLOCKED && r.discovery_verified && r.arm_len==20);
    CHECK(calls==6);
    mode=2;calls=0;r=d2k_voice_run(&o);
    CHECK(r.verdict==D2K_VOICE_NO_ORACLE && !r.arm_len);
    /* Real UDP socket and strict response correlation, not just hooks. */
    for(int ix=0;ix<4;ix++) {
        int kind = ix == 3 ? 5 : ix;
        server s={socket(AF_INET,SOCK_DGRAM,0),kind}; CHECK(s.fd>=0);
        struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_addr.s_addr=inet_addr("127.0.0.1");
        CHECK(bind(s.fd,(void*)&a,sizeof a)==0);socklen_t len=sizeof a;
        CHECK(getsockname(s.fd,(void*)&a,&len)==0);
        pthread_t th;CHECK(pthread_create(&th,NULL,respond,&s)==0);
        d2k_discovery_result q=real(a.sin_addr.s_addr,ntohs(a.sin_port),NULL,0,150,0);
        pthread_join(th,NULL);close(s.fd);
        CHECK(!q.error && !q.marked);
        CHECK(q.received==((kind==0 || kind==5)?D2K_DISCOVERY_EXCHANGES:kind==1?12u:0u));
    }
    return fail != 0;
}
