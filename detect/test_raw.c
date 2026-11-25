/* Exercise the actual raw-layer helpers without raw sockets, iptables or
 * network traffic. Only recvfrom is replaced, with two in-memory packets.
 * This runs the helper code on the host; cross/runtime Linux checks remain
 * separate from these deterministic ownership/wire-format assertions. */
/* Те же макросы, что в начале raw.c: системные заголовки ниже идут раньше
   его текста, и без них glibc прячет kill/nanosleep/srandom. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define D2K_RAW_UNIT_TEST 1
#include "../datapath/test_runtime_trace.h"
#include <sys/socket.h>
#include <sys/types.h>
static ssize_t raw_test_sendto(int, const void *, size_t, int,
                               const struct sockaddr *, socklen_t);
ssize_t raw_test_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static int raw_test_socket(int, int, int);
static int raw_test_setsockopt(int, int, int, const void *, socklen_t);
static int raw_test_bind(int, const struct sockaddr *, socklen_t);
static int raw_test_connect(int, const struct sockaddr *, socklen_t);
static int raw_test_getsockname(int, struct sockaddr *, socklen_t *);
#define recvfrom raw_test_recvfrom
#define sendto raw_test_sendto
#define socket raw_test_socket
#define setsockopt raw_test_setsockopt
#define bind raw_test_bind
#define connect raw_test_connect
#define getsockname raw_test_getsockname
#define d2k_sleep_ms runtime_sleep_ms
#define d2k_sleep_us runtime_sleep_us
#include "raw.c"
#undef d2k_sleep_us
#undef d2k_sleep_ms
#undef recvfrom
#undef sendto
#undef socket
#undef setsockopt
#undef bind
#undef connect
#undef getsockname
/* Legacy fixture builders keep existing tests unchanged while production
 * builders now accept the connection's advertised window explicitly. */
static size_t build_ipv4_tcp(uint8_t *pkt,size_t cap,const uint8_t src[4],const uint8_t dst[4],
    uint16_t sport,uint16_t dport,uint32_t seq,uint32_t ack,uint8_t flags,
    const uint8_t *payload,size_t plen,const d2k_poison *p,const uint8_t *extra,size_t extralen)
{
    return build_ipv4_tcp_window(pkt,cap,src,dst,sport,dport,seq,ack,flags,
        payload,plen,p,extra,extralen,65535);
}
static size_t build_ip_tcp(uint8_t *pkt,size_t cap,uint8_t family,const uint8_t *src,const uint8_t *dst,
    uint16_t sport,uint16_t dport,uint32_t seq,uint32_t ack,uint8_t flags,
    const uint8_t *payload,size_t plen,const d2k_poison *p,const uint8_t *extra,size_t extralen)
{
    return build_ip_tcp_window(pkt,cap,family,src,dst,sport,dport,seq,ack,flags,
        payload,plen,p,extra,extralen,65535);
}
#include <fcntl.h>
#include "d2k_wire.h"
#include "d2k_compose.h"
#include "d2k_plantlv.h"
#include "../synthesis/experiment.c"
#include "../synthesis/raw_tls.c"
#include "../synthesis/raw_tape.c"
#include "../synthesis/application_owner.h"
#include "../synthesis/path_run.c"
#include "../synthesis/path_work.c"
#include "../synthesis/learner.h"
#include "../synthesis/lower.h"
#include "../synthesis/stream.h"
#include "../synthesis/session.h"
#include "../synthesis/observation.c"
#include "../synthesis/tls_observe.c"
#include "../synthesis/tls_decode.c"
int d2k_arm_from_poison(const d2k_poison *, d2k_arm *, char *, size_t);
/* Fixed entropy at the OS boundary, shared by both real executor calls. */
static FILE *runtime_entropy(const char *path, const char *mode) {
    if (strcmp(path, "/dev/urandom")) return fopen(path, mode);
    FILE *f = tmpfile();
    if (!f) return NULL;
    for (int i = 0; i < 128; i++) fputc((i * 17 + 3) & 255, f);
    rewind(f); return f;
}
#define fopen runtime_entropy
#define wr16 apply_wr16
#include "../datapath/plan_apply.c"
#undef fopen
#undef wr16

#ifndef D2K_SEND_MAX
#include "tests/legacy_sends.h"
#endif
#define WORKERS 16
#define PORTS_PER_WORKER 128
static uint16_t ports[WORKERS][PORTS_PER_WORKER];
static uint8_t incoming[2][128];
static size_t incoming_len[2];
static unsigned incoming_noise;
static int reorder_first;
static int fragment_mode, fragment_next, fragment_count = 2;
static int packet_event_input;
static uint8_t incoming_src[2][16];
static uint8_t outgoing[512][4096];
static size_t outgoing_len[512];
static size_t outgoing_count;
static size_t fail_send_at;
static unsigned pending_delay, outgoing_delay[512];
void runtime_sleep_ms(int ms) { pending_delay += (unsigned)ms * 1000u; }
int runtime_sleep_us(uint32_t us) {pending_delay+=us;return 0;}

static int shape_track, shape_rst_blocked, shape_rst_seen;
static unsigned char shape_rules[65536];
static int shape_delete_fail, shape_insert_fail;
static int failures;
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "raw:%d: %s\n", __LINE__, #c); failures++; \
} } while (0)

static ssize_t raw_test_sendto(int fd, const void *buf, size_t len, int flags,
                               const struct sockaddr *addr, socklen_t alen)
{
    (void)fd; (void)flags; (void)addr; (void)alen;
    if (shape_track && len >= 40 && (((const uint8_t *)buf)[33] & TCP_RST)) {
        shape_rst_seen++;
        shape_rst_blocked += shape_rules[rd16((const uint8_t *)buf + 20)] != 0;
    }
    if (fail_send_at && outgoing_count == fail_send_at) { errno = EIO; return -1; }
    if (outgoing_count >= 512 || len > sizeof outgoing[0]) { return -1; }
    memcpy(outgoing[outgoing_count], buf, len);
    outgoing_delay[outgoing_count] = pending_delay; pending_delay = 0;
    outgoing_len[outgoing_count++] = len;
    if (outgoing_count == 2) srandom(12345); /* entropy boundary after handshake */
    return (ssize_t)len;
}

static void test_disorder_pos2_emits_exact_reverse_segments(void)
{
    raw_conn c;
    d2k_trigger tr;
    static const uint8_t bytes[] = {0x16, 0x03, 0x01, 0xaa, 0xbb, 0xcc};
    memset(&c, 0, sizeof c); memset(&tr, 0, sizeof tr);
    c.family = 4; c.send_fd = 1; c.seq = 1000; c.ack = 900;
    c.sport = 41000; c.dport = 443; c.src[0] = 192; c.dst[0] = 198;
    memcpy(c.src + 1, (uint8_t[]){0, 2, 1}, 3);
    memcpy(c.dst + 1, (uint8_t[]){51, 100, 7}, 3);
    memcpy(tr.payload, bytes, sizeof bytes); tr.len = sizeof bytes;
    outgoing_count = 0; memset(outgoing_len, 0, sizeof outgoing_len);
    {
        /* Замороженный список прежнего отправителя проверяет raw_send,
           оставшийся для рукопожатия и прямого контроля. Обходный
           runtime через Plan проверяется отдельно ниже. */
        d2k_poison p;
        d2k_sends pl;
        uint8_t fk[64], sg[64];
        size_t i;
        memset(&p, 0, sizeof p);
        snprintf(p.name, sizeof p.name, "disorder-pos2");
        p.disorder = 1; p.disorder_pos = 2;
        CHECK(d2k_poison_sends(&tr, &p, fk, sizeof fk, sg, sizeof sg, &pl) == 0);
        CHECK(pl.n == 2 && pl.v[0].delay_ms == 0 && pl.v[1].delay_ms == 0 && pl.tail_ms == 0);
        for (i = 0; i < pl.n; i++) {
            c.seq = (uint32_t)(1000 + pl.v[i].seq_off);
            CHECK(raw_send(&c, pl.v[i].bytes, pl.v[i].len, (uint8_t)(TCP_PSH | TCP_ACK),
                           &pl.v[i].poison) == 0);
        }
    }
    CHECK(outgoing_count == 2);
    if (outgoing_count == 2) {
        CHECK(rd32(outgoing[0] + 24) == 1002 && outgoing_len[0] == 44 &&
              memcmp(outgoing[0] + 40, bytes + 2, 4) == 0);
        CHECK(rd32(outgoing[1] + 24) == 1000 && outgoing_len[1] == 42 &&
              memcmp(outgoing[1] + 40, bytes, 2) == 0);
        CHECK((outgoing[0][33] & TCP_PSH) && (outgoing[1][33] & TCP_PSH));
    }
}

/* raw_dial harness: sockets are /dev/null descriptors (no root, no
 * network); the receive socket answers our own SYN with a SYN-ACK. */
static int dial_recv_fd = -1;
static int dial_silent, payload_recv_error, payload_silent, payload_ack;
static const uint8_t *episode_reply;
static size_t episode_reply_len,episode_reply_at,episode_reply_chunk;
static int episode_reply_fin,episode_fin_sent;
static int64_t episode_chunk_elapsed_ms;
static size_t learning_peer_bytes,learning_peer_connections;
static size_t learning_peer_drift_at;
static size_t learning_peer_local_at;
static int learning_peer_allow_whole;
static size_t dial_drop_syns; /* сколько первых SYN «теряет путь» */
static int mock_family = AF_INET;
static int peer_timestamps = 1;
static int raw_test_socket(int domain, int type, int proto)
{
    int fd = open("/dev/null", O_RDONLY);
    mock_family = domain;
    if (fd >= 0 && type == SOCK_RAW && proto == IPPROTO_TCP) {
        dial_recv_fd = fd;
        if(learning_peer_bytes) {
            outgoing_count=0;episode_reply_at=0;++learning_peer_connections;
        }
    }
    return fd;
}
static int raw_test_setsockopt(int fd, int lvl, int name, const void *v, socklen_t n)
{ (void)fd; (void)lvl; (void)name; (void)v; (void)n; return 0; }
static int raw_test_bind(int fd, const struct sockaddr *a, socklen_t n)
{ (void)fd; (void)a; (void)n; return 0; }
static int raw_test_connect(int fd, const struct sockaddr *a, socklen_t n)
{ (void)fd; (void)a; (void)n; return 0; }
static int raw_test_getsockname(int fd, struct sockaddr *a, socklen_t *n)
{
    struct sockaddr_in local = {0};
    (void)fd;
    if (mock_family == AF_INET6) {
        struct sockaddr_in6 v6 = {0};
        v6.sin6_family = AF_INET6;
        memcpy(&v6.sin6_addr, (uint8_t[]){0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}, 16);
        memcpy(a, &v6, sizeof v6); *n = sizeof v6; return 0;
    }
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(0xc0000201); /* 192.0.2.1 */
    memcpy(a, &local, sizeof local);
    *n = sizeof local;
    return 0;
}

static char rule_cmds[4][192];
static int rule_count;
static int rule_rc;
static int test_rule_hook(const char *cmd)
{
    if (rule_count < 4) { snprintf(rule_cmds[rule_count], sizeof rule_cmds[0], "%s", cmd); }
    rule_count++;
    return rule_rc;
}

ssize_t raw_test_recvfrom(int fd, void *buf, size_t len, int flags,
                         struct sockaddr *addr, socklen_t *alen)
{
    (void)flags;
    if (fd >= 0 && fd == dial_recv_fd && packet_event_input) {
        if (incoming_len[0]>len) {errno=EMSGSIZE;return -1;}
        memcpy(buf,incoming[0],incoming_len[0]);return (ssize_t)incoming_len[0];
    }
    if (fd >= 0 && fd == dial_recv_fd) {

        if(learning_peer_local_at && learning_peer_connections>=learning_peer_local_at && outgoing_count>=3) {
            errno=EIO;return -1;
        }

        if (payload_silent && outgoing_count > 2) { errno=EAGAIN;return -1; }
        if (dial_silent || (payload_recv_error && outgoing_count >= 3)) {
            errno = dial_silent ? dial_silent : EIO; return -1;
        }
        d2k_poison none = {0};
        const uint8_t *syn = outgoing[0];
        size_t n;
        if (outgoing_count == 0) { return -1; }
        if (outgoing_count <= dial_drop_syns) { errno = EAGAIN; return -1; }
        uint8_t packet[128];
        int ipv6 = (syn[0] >> 4) == 6;
        size_t iplen = ipv6 ? 40 : 20;
        n = build_ip_tcp(packet, sizeof packet, ipv6 ? 6 : 4,
                         syn + (ipv6 ? 24 : 16), syn + (ipv6 ? 8 : 12),
                         rd16(syn + iplen + 2), rd16(syn + iplen),
                         7000, rd32(syn + iplen + 4) + 1, TCP_SYN | TCP_ACK,
                         NULL, 0, &none, (uint8_t[]){1,1,8,10,0,0,0x23,0x28,0,0,0,1},
                         peer_timestamps ? 12 : 0);
        if (!n) return -1;
        size_t learning_fragments=0;
        if(learning_peer_bytes && outgoing_count>=2) {
            size_t total=0;
            for(size_t i=2;i<outgoing_count;i++) {
                const uint8_t *p=outgoing[i];size_t ihl=(p[0]&15)*4;
                size_t header=ihl+(p[ihl+12]>>4)*4;
                if(outgoing_len[i]>header) {total+=outgoing_len[i]-header;++learning_fragments;}
            }
            if(total<learning_peer_bytes){errno=EAGAIN;return -1;}
        }
        if (outgoing_count > 2) {
            packet[iplen + 13] = payload_ack ? TCP_ACK : TCP_RST;
            wr32(packet+iplen+4,7001);
            if(payload_ack) {
                wr32(packet+iplen+8,rd32(syn+iplen+4)+5);
            }
            if(episode_reply && (!learning_peer_bytes || learning_fragments>1 || learning_peer_allow_whole) &&
               (!learning_peer_drift_at || learning_peer_connections<learning_peer_drift_at)) {
                if(episode_reply_at==episode_reply_len && (!episode_reply_fin || episode_fin_sent)){errno=EAGAIN;return -1;}
                size_t take=episode_reply_len-episode_reply_at;
                if(take>episode_reply_chunk)take=episode_reply_chunk;
                int fin=episode_reply_fin && episode_reply_at+take==episode_reply_len;
                n=build_ip_tcp(packet,sizeof packet,ipv6?6:4,
                    syn+(ipv6?24:16),syn+(ipv6?8:12),rd16(syn+iplen+2),rd16(syn+iplen),
                    7001+(uint32_t)episode_reply_at,rd32(syn+iplen+4)+5,TCP_ACK|(fin?TCP_FIN:0),
                    episode_reply+episode_reply_at,take,&none,NULL,0);
                episode_reply_at+=take;
                if(fin)episode_fin_sent=1;
                d2k_clock_offset_ms+=episode_chunk_elapsed_ms;
            }
        }

        if (ipv6) {
            struct sockaddr_in6 peer = {0};
            peer.sin6_family = AF_INET6; memcpy(&peer.sin6_addr, syn + 24, 16);
            memcpy(addr, &peer, sizeof peer); *alen = sizeof peer;
            n -= 40;
            if (n > len) return -1;
            memcpy(buf, packet + 40, n);
        } else {
            if (n > len) return -1;
            memcpy(buf, packet, n);
        }
        return (ssize_t)n;
    }
    if (fd == 0 && fragment_mode) {
        if (fragment_next >= fragment_count) { errno = EAGAIN; return -1; }
        size_t n = incoming_len[fragment_next];
        if (n > len) { errno = EMSGSIZE; return -1; }
        memcpy(buf, incoming[fragment_next++], n);
        return (ssize_t)n;
    }
    if (fd == 0 && reorder_first) {

        /* Later server data arrives before the start of the reply. */
        reorder_first = 0;
        if (incoming_len[1] > len) { return -1; }
        memcpy(buf, incoming[1], incoming_len[1]);
        return (ssize_t)incoming_len[1];
    }
    if (fd < 0 || fd > 1 || incoming_len[fd] > len) { return -1; }
    memcpy(buf, incoming[fd], incoming_len[fd]);
    if (incoming_noise) {
        struct timespec pause = {0, 3000000};
        incoming_noise--;
        ((uint8_t *)buf)[12] ^= 1; /* IPv4 packet from an unrelated peer */
        nanosleep(&pause, NULL);
    }
    if (addr && alen && *alen >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 peer = {0};
        peer.sin6_family = AF_INET6;
        memcpy(&peer.sin6_addr, incoming_src[fd], 16);
        memcpy(addr, &peer, sizeof peer);
        *alen = sizeof peer;
    }
    return (ssize_t)incoming_len[fd];
}

static void test_checksum_matches_original(void)
{
    uint8_t src[] = {192, 0, 2, 1}, dst[] = {198, 51, 100, 7};
    uint8_t *tcp = malloc(65535), *ph = calloc(1, 12 + 65535);
    const size_t sizes[] = {20, 21, 40, 333, 1448, 2048, 65535};
    CHECK(tcp && ph);
    if (!tcp || !ph) { free(tcp); free(ph); return; }
    for (size_t i = 0; i < 65535; i++) { tcp[i] = (uint8_t)(i * 37u + 19u); }
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        size_t n = sizes[k];
        memcpy(ph, src, 4); memcpy(ph + 4, dst, 4);
        ph[9] = 6;
        wr16(ph + 10, (uint16_t)n);
        memcpy(ph + 12, tcp, n);
        ph[28] = ph[29] = 0;
        CHECK(tcp_checksum(src, dst, tcp, n) == checksum(ph, n + 12));
    }
    free(tcp); free(ph);
}

static void test_receive_is_owned_by_connection(void)
{
    raw_conn c[2];
    d2k_poison p;
    const uint8_t *first = NULL, *second = NULL;
    size_t len;
    uint8_t flags;
    uint32_t seq, ack;
    memset(c, 0, sizeof c); memset(&p, 0, sizeof p);
    for (int i = 0; i < 2; i++) {
        uint8_t body[4] = {(uint8_t)(0xa0 + i), 2, 3, 4};
        c[i].buffers = malloc(sizeof(*c[i].buffers));
        CHECK(c[i].buffers != NULL);
        if (!c[i].buffers) { exit(2); }
        c[i].send_fd = -1; c[i].recv_fd = i;
        c[i].sport = (uint16_t)(35000 + i); c[i].dport = 443;
        c[i].src[0] = 192; c[i].dst[0] = 198;
        incoming_len[i] = build_ipv4_tcp(incoming[i], sizeof incoming[i],
            c[i].dst, c[i].src, c[i].dport, c[i].sport, 1, 2, TCP_ACK,
            body, sizeof body, &p, NULL, 0);
        CHECK(incoming_len[i] > 0);
    }
    CHECK(raw_recv(&c[0], &flags, &seq, &ack, &first, &len, d2k_now_ms() + 1000, NULL) == 0 && len == 4);
    CHECK(raw_recv(&c[1], &flags, &seq, &ack, &second, &len, d2k_now_ms() + 1000, NULL) == 0 && len == 4);
    CHECK(first && second && first != second);
    CHECK(first && first[0] == 0xa0); /* must survive the OTHER receive */
    CHECK(second && second[0] == 0xa1);
    for (int i = 0; i < 2; i++) {
        c[i].recv_fd = -1; /* mock identifiers are not owned OS descriptors */
        raw_close(&c[i]);
        CHECK(c[i].buffers == NULL);
    }
}

/* A stream of unrelated packets must not reset the probe deadline. The old
 * raw_recv loop consumed all 20 and accepted a response after the deadline. */
static void test_unrelated_packets_do_not_extend_deadline(void)
{
    raw_conn c = {0};
    d2k_poison p = {0};
    uint8_t body[] = {1, 2, 3}, result[16];
    size_t result_len = 0;
    c.family = 4; c.recv_fd = 0; c.sport = 35000; c.dport = 443;
    c.src[0] = 192; c.dst[0] = 198;
    c.buffers = malloc(sizeof *c.buffers);
    CHECK(c.buffers != NULL);
    if (!c.buffers) return;
    incoming_len[0] = build_ipv4_tcp(incoming[0], sizeof incoming[0],
        c.dst, c.src, c.dport, c.sport, 1, 2, TCP_ACK,
        body, sizeof body, &p, NULL, 0);
    incoming_noise = 20;
    CHECK(raw_read_payload(&c, 5, NULL, result, sizeof result, &result_len, 1) == -1);
    CHECK(result_len == 0);
    CHECK(c.observed.kind == D2K_RAW_OBS_RESPONSE_TIMEOUT);
    incoming_noise = 0;
    free(c.buffers);
}

/* Поле 14.10.2026, fost.club: сервер ответил полностью (4874 байта), но
 * сегмент 1441:2881 пришёл раньше 1:1441, и зонд взял его за начало ответа:
 * TLS-записи там нет — «нет» и сброс. Начало ответа — сегмент с номером,
 * следующим за SYN сервера (c->ack), а не первый пришедший. */
static void test_negotiated_ack_timestamps(void)
{
    for(int timestamps=0;timestamps<2;timestamps++) {
        raw_conn c={0};d2k_poison none={0};
        c.family=4;c.sport=35000;c.dport=443;c.seq=123;c.ack=456;
        c.src[0]=192;c.dst[0]=198;
        if(timestamps) {
            memcpy(c.tcp_options,(uint8_t[]){1,1,8,10,0,0,0,1,0,0,4,210},12);
            c.tcp_options_len=12;
        }
        outgoing_count=0;
        CHECK(!raw_send(&c,NULL,0,TCP_ACK,&none));
        CHECK(outgoing_count==1);
        CHECK((outgoing[0][32]>>4)==(timestamps?8:5));
        if(timestamps)CHECK(!memcmp(outgoing[0]+40,c.tcp_options,12));
        CHECK(rd32(outgoing[0]+24)==123 && rd32(outgoing[0]+28)==456);
    }
    outgoing_count=0;
}
static void test_reordered_reply_reads_from_stream_start(void)
{
    raw_conn c = {0};
    d2k_poison p = {0};
    uint8_t start[] = {0x16, 0x03, 0x03, 0x00, 0x7a}, later[] = {0x41, 0x42, 0x43};
    uint8_t result[16];
    size_t result_len = 0;
    c.family = 4; c.recv_fd = 0; c.sport = 35000; c.dport = 443;
    c.src[0] = 192; c.dst[0] = 198;
    c.ack = 1001;
    c.buffers = malloc(sizeof *c.buffers);
    CHECK(c.buffers != NULL);
    if (!c.buffers) return;
    incoming_len[0] = build_ipv4_tcp(incoming[0], sizeof incoming[0],
        c.dst, c.src, c.dport, c.sport, 1001, 2, TCP_ACK,
        start, sizeof start, &p, NULL, 0);
    incoming_len[1] = build_ipv4_tcp(incoming[1], sizeof incoming[1],
        c.dst, c.src, c.dport, c.sport, 1001 + 1440, 2, TCP_ACK,
        later, sizeof later, &p, NULL, 0);
    reorder_first = 1;
    outgoing_count=0;
    CHECK(raw_read_payload(&c, 1000, NULL, result, sizeof result, &result_len, 1) == 0);
    CHECK(outgoing_count==1 && rd32(outgoing[0]+28)==1001);
    CHECK(result_len == sizeof start && result[0] == 0x16);
    CHECK(c.observed.kind == D2K_RAW_OBS_RESPONSE_BYTES && c.observed.response_bytes == sizeof start);
    incoming_len[0]=build_ipv4_tcp(incoming[0],sizeof incoming[0],
        c.dst,c.src,c.dport,c.sport,1001,2,TCP_ACK|TCP_FIN,
        start,sizeof start,&p,NULL,0);
    CHECK(raw_read_payload(&c,5,NULL,result,sizeof result,&result_len,1)==-1);
    CHECK(!result_len && c.observed.kind==D2K_RAW_OBS_RESPONSE_FIN && c.ack==1007);
    reorder_first = 0;
    incoming_len[1] = 0;
    free(c.buffers);
}

static void test_reordered_reply_retains_tail(void)
{
    for(int wrap=0;wrap<2;wrap++)for(int small=0;small<2;small++) {
        raw_conn c={0};d2k_poison none={0};
        c.family=4;c.recv_fd=0;c.sport=35000;c.dport=443;
        c.src[0]=192;c.dst[0]=198;c.ack=wrap?UINT32_MAX-2:1001;
        uint32_t begin=c.ack;
        c.buffers=malloc(sizeof *c.buffers);CHECK(c.buffers);if(!c.buffers)return;
        const uint8_t bytes[]="abcdefgh";uint8_t result[8];size_t have=0;
        incoming_len[0]=build_ipv4_tcp(incoming[0],sizeof incoming[0],
            c.dst,c.src,c.dport,c.sport,begin+4,2,TCP_ACK|TCP_FIN,
            bytes+4,4,&none,NULL,0);
        incoming_len[1]=build_ipv4_tcp(incoming[1],sizeof incoming[1],
            c.dst,c.src,c.dport,c.sport,begin,2,TCP_ACK,
            bytes,4,&none,NULL,0);
        fragment_mode=1;fragment_next=0;outgoing_count=0;
        size_t total=0;
        while(total<sizeof result) {
            size_t cap=small?1:sizeof result-total;
            int rc=raw_read_payload(&c,10,NULL,result+total,cap,&have,cap);
            CHECK(rc==0);if(rc || !have)break;
            total+=have;
        }
        CHECK(total==8 && !memcmp(result,bytes,8));
        CHECK(c.rx_fin && c.ack==begin+9);
        fragment_mode=0;free(c.buffers);
    }
}

static void test_fragmented_reply_prefix(void)
{
    const uint8_t reply[] = {0x16, 3, 3, 0, 70, 2};
    d2k_poison none = {0};
    for (size_t cut = 1; cut < sizeof reply; cut++) {
        raw_conn c = {0};
        uint8_t result[16] = {0}; size_t have = 0;
        c.family = 4; c.recv_fd = 0; c.send_fd = 1;
        c.sport = 35000; c.dport = 443;
        c.src[0] = 192; c.dst[0] = 198; c.ack = UINT32_MAX - 2;
        c.buffers = calloc(1, sizeof *c.buffers);
        CHECK(c.buffers != NULL); if (!c.buffers) return;
        incoming_len[0] = build_ipv4_tcp(incoming[0], sizeof incoming[0],
            c.dst, c.src, c.dport, c.sport, c.ack, 2, TCP_ACK,
            reply, cut, &none, NULL, 0);
        incoming_len[1] = build_ipv4_tcp(incoming[1], sizeof incoming[1],
            c.dst, c.src, c.dport, c.sport, c.ack + (uint32_t)cut, 2, TCP_ACK,
            reply + cut, sizeof reply - cut, &none, NULL, 0);
        fragment_mode = 1; fragment_next = 0; outgoing_count = 0;
        CHECK(raw_read_payload(&c, 30, NULL, result, sizeof result, &have, sizeof reply) == 0);
        CHECK(have == sizeof reply && !memcmp(result, reply, sizeof reply));
        fragment_mode = 0;
        free(c.buffers);
    }
}

static void test_stale_reset_does_not_abort_reply(void)
{
    const uint32_t starts[]={1001,0};
    const uint8_t body[]={0x16,3,3,0,1,2};
    d2k_poison none={0};
    for(size_t i=0;i<sizeof starts/sizeof starts[0];i++) {
        raw_conn c={0};uint8_t result[16];size_t have=0;
        c.family=4;c.recv_fd=0;c.send_fd=1;c.sport=35000;c.dport=443;
        c.src[0]=192;c.dst[0]=198;c.ack=starts[i];
        c.buffers=calloc(1,sizeof *c.buffers);
        CHECK(c.buffers!=NULL);if(!c.buffers)return;
        incoming_len[0]=build_ipv4_tcp(incoming[0],sizeof incoming[0],
            c.dst,c.src,c.dport,c.sport,c.ack-1,2,TCP_RST|TCP_ACK,
            NULL,0,&none,NULL,0);
        incoming_len[1]=build_ipv4_tcp(incoming[1],sizeof incoming[1],
            c.dst,c.src,c.dport,c.sport,c.ack,2,TCP_ACK,
            body,sizeof body,&none,NULL,0);
        fragment_mode=1;fragment_next=0;fragment_count=2;outgoing_count=0;
        CHECK(raw_read_payload(&c,30,NULL,result,sizeof result,&have,sizeof body)==0);
        CHECK(have==sizeof body && !memcmp(result,body,sizeof body));
        CHECK(c.observed.kind==D2K_RAW_OBS_RESPONSE_BYTES);
        CHECK(c.ack==starts[i]+sizeof body);
        incoming_len[0]=build_ipv4_tcp(incoming[0],sizeof incoming[0],
            c.dst,c.src,c.dport,c.sport,c.ack,2,TCP_RST|TCP_ACK,
            NULL,0,&none,NULL,0);
        fragment_next=0;fragment_count=1;
        CHECK(raw_read_payload(&c,30,NULL,result,sizeof result,&have,1)==-1);
        CHECK(!have && c.observed.kind==D2K_RAW_OBS_RESPONSE_RESET);
        fragment_mode=0;fragment_count=2;free(c.buffers);
    }
}

static void test_partial_reply_timeout(void)
{
    raw_conn c = {0}; d2k_poison none = {0};
    uint8_t prefix[] = {0x16, 3, 3}, result[16] = {0}; size_t have = 0;
    c.family = 4; c.recv_fd = 0; c.send_fd = 1;
    c.sport = 35000; c.dport = 443; c.src[0] = 192; c.dst[0] = 198;
    c.ack = 1001; c.buffers = calloc(1, sizeof *c.buffers);
    CHECK(c.buffers != NULL); if (!c.buffers) return;
    incoming_len[0] = build_ipv4_tcp(incoming[0], sizeof incoming[0],
        c.dst, c.src, c.dport, c.sport, c.ack, 2, TCP_ACK,
        prefix, sizeof prefix, &none, NULL, 0);
    fragment_mode = 1; fragment_next = 0; fragment_count = 1; outgoing_count = 0;
    CHECK(raw_read_payload(&c, 15, NULL, result, sizeof result, &have, 6) == -1);
    CHECK(have == sizeof prefix && !memcmp(prefix, result, sizeof prefix));
    CHECK(c.observed.kind == D2K_RAW_OBS_RESPONSE_TIMEOUT);
    CHECK(c.observed.response_bytes == sizeof prefix);
    CHECK(outgoing_count == 1 && rd32(outgoing[0] + 28) == 1004);
    fragment_mode = 0; fragment_count = 2;
    free(c.buffers);
}

static void *allocate_ports(void *arg)


{
    int i = *(int *)arg;
    for (int k = 0; k < PORTS_PER_WORKER; k++) { ports[i][k] = next_source_port(); }
    return NULL;
}

static void test_concurrent_ports_are_unique(void)
{
    pthread_t threads[WORKERS];
    int ids[WORKERS];
    uint8_t seen[25000] = {0};
    for (int i = 0; i < WORKERS; i++) {
        ids[i] = i;
        if (pthread_create(&threads[i], NULL, allocate_ports, &ids[i])) { exit(2); }
    }
    for (int i = 0; i < WORKERS; i++) { pthread_join(threads[i], NULL); }
    for (int i = 0; i < WORKERS; i++) {
        for (int k = 0; k < PORTS_PER_WORKER; k++) {
            unsigned p = ports[i][k];
            CHECK(p >= 30000 && p < 55000);
            if (p >= 30000 && p < 55000) { CHECK(!seen[p - 30000]++); }
        }
    }
}

/* Compare the TWO real packet encoders. Only the random IP ID and its
 * dependent IPv4 checksum are normalized; all TCP bytes must match. */
static void test_datapath_matches_raw_headers(void)
{
    uint8_t src[] = {192,0,2,1}, dst[] = {198,51,100,7};
    uint8_t body[1400], a[1600], b[1600];
    for (size_t i = 0; i < sizeof body; i++) { body[i] = (uint8_t)(i * 17); }
    for (unsigned flags = 0; flags < 64; flags++) {
        d2k_poison p = {0}; d2k_emit e = {0}; d2k_conn c = {0};
        p.badsum = !!(flags & 1); p.tcp_ts = !!(flags & 2);
        p.md5 = !!(flags & 32);
        p.ip_id_zero = !!(flags & 4); p.ttl = flags & 8 ? 8 : 0;
        e.poison = (uint8_t)((flags & 7) | (p.md5 ? D2K_POISON_MD5 : 0)); e.ttl = (uint8_t)p.ttl;
        e.seq = 123456; e.seq_shift = flags & 16 ? -66000 : 0;
        e.wire_profile = D2K_WIRE_DETECT_TCP;
        e.pre = body; e.pre_len = 101; e.bytes = body + 101; e.len = 1299;
        memcpy(&c.src_ip, src, 4); memcpy(&c.dst_ip, dst, 4);
        uint8_t ports[] = {0x9c,0x40,0x01,0xbb};
        memcpy(&c.src_port, ports, 2); memcpy(&c.dst_port, ports + 2, 2);
        c.ack = 7654321; c.window = 77; c.ttl = 11; c.ip_id = 900;
        size_t an = build_ipv4_tcp(a, sizeof a, src, dst, 40000, 443,
            e.seq + (uint32_t)e.seq_shift, c.ack, TCP_PSH | TCP_ACK,
            body, sizeof body, &p, NULL, 0);
        size_t bn = d2k_wire_build(&c, &e, b, sizeof b);
        CHECK(an > 0 && an == bn);
        CHECK(checksum(b, 20) == 0);
        if (p.ip_id_zero) { CHECK(b[4] == 0 && b[5] == 0); }
        /* IP IDs are per-send random draws, not an arm parameter. */
        memcpy(a + 4, b + 4, 2); a[10] = a[11] = 0;
        wr16(a + 10, checksum(a, 20));
        CHECK(an == bn && memcmp(a, b, an) == 0);
    }
}

static void sweep_noop(void) {}

/* Donor suppressKernelRST: a failed iptables insert (no binary, nft-only
 * router) is a LOCAL defect. The probe continues, flagged; it must not turn
 * into a failed self-check and an "opaque, nothing to bypass" verdict. */
static void test_dial_survives_missing_rst_rule(void)
{
    static const uint8_t dst[4] = {198, 51, 100, 7};
    raw_conn c;
    char err[160] = "";
    pthread_once(&g_sweep_once, sweep_noop); /* never touch a real firewall */
    d2k_raw_rule_hook = test_rule_hook;

    rule_rc = 0; rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    CHECK(c.rule_up == 1);
    CHECK(rule_count == 1 && strstr(rule_cmds[0], "iptables -w -I OUTPUT") != NULL);
    raw_close(&c);
    CHECK(rule_count == 2 && strstr(rule_cmds[1], "iptables -w -D OUTPUT") != NULL);
    unsigned long fails0 = d2k_raw_rst_fail_count();
    {
        /* Задача 49: правило несёт pid владельца, снимается той же формой;
           замок xtables ждётся (-w), а не проигрывается молча. */
        char own[48];
        snprintf(own, sizeof own, "--comment d2k-rst:%ld ", (long)getpid());
        CHECK(strstr(rule_cmds[0], own) != NULL && strstr(rule_cmds[1], own) != NULL);
    }

    rule_rc = 256; rule_count = 0; outgoing_count = 0; dial_recv_fd = -1; err[0] = '\0';
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    CHECK(c.rule_up == 0);
    CHECK(outgoing_count == 2); /* SYN and the final ACK: probe went on */
    raw_close(&c);
    /* Отказ с комментарием → одна попытка без него (прошивка без xt_comment),
       тоже отказ: ничего не встало, снимать нечего. */
    CHECK(rule_count == 2); /* nothing installed, nothing to delete */
    /* Отказ считается, а не взводит флаг навсегда: прогон сравнивает счётчик
       со своим стартом, поэтому прошлый отказ не метит будущие прогоны. */
    CHECK(d2k_raw_rst_fail_count() == fails0 + 1); /* still reaches the verdict trace */

    outgoing_count = 0; dial_recv_fd = -1;
    CHECK(d2k_raw_probe_handshake_family(dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 1);
    d2k_raw_rule_hook = raw_rule_system;
}

/* ЗАДАЧА 49: СНЯТИЕ НЕ ТЕРЯЕТСЯ. Поле 03.10: в OUTPUT висели правила
 * --sport 39842/39408/39354 и 40750 без единого идущего поиска — удаление не
 * удалось (замок xtables у NDM/сторожа), и о нём забыли. Неснятое правило
 * повторяется сразу и потом перед каждой следующей правкой правил. */
static int exit_pipe_fd = -1;
static int exit_hook(const char *cmd)
{
    size_t n = strlen(cmd);
    if (write(exit_pipe_fd, cmd, n) < 0 || write(exit_pipe_fd, "\n", 1) < 0) return -1;
    return 0;
}
static int del_fail_left;
static int del_fail_code = 4 << 8;
static int check_code = 1 << 8; /* -C: правила нет */
static int flaky_del_hook(const char *cmd)
{
    test_rule_hook(cmd);
    if (strstr(cmd, " -C OUTPUT")) return check_code;
    if (strstr(cmd, " -D OUTPUT") && del_fail_left > 0) { del_fail_left--; return del_fail_code; }
    return 0;
}

static void test_failed_release_is_retried(void)
{
    static const uint8_t dst[4] = {198, 51, 100, 8};
    raw_conn c;
    char err[160] = "";
    pthread_once(&g_sweep_once, sweep_noop);
    d2k_raw_rule_hook = flaky_del_hook;

    /* Отказ один раз: повтор тут же, правило снято. */
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1; del_fail_left = 1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    raw_close(&c);
    CHECK(rule_count == 3 && strstr(rule_cmds[1], " -D OUTPUT") && strstr(rule_cmds[2], " -D OUTPUT"));

    /* Отказ дважды: правило запомнено и снимается перед следующей вставкой. */
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1; del_fail_left = 2;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    uint16_t leaked = c.sport;
    raw_close(&c);
    CHECK(rule_count == 3);
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    char want[64];
    snprintf(want, sizeof want, "-D OUTPUT -p tcp --sport %u ", (unsigned)leaked);
    CHECK(rule_count == 2 && strstr(rule_cmds[0], want) != NULL &&
          strstr(rule_cmds[1], " -I OUTPUT") != NULL);
    raw_close(&c);

    /* Ревью 49, Important 1: с -w отказ удаления — почти всегда «правила
       нет» (exit 1: NDM перестроил netfilter). Такое не повторяется ни
       сразу, ни потом — иначе каждая вставка вечно гоняла бы заведомо
       неудачный -D под общим мьютексом. */
    del_fail_code = 1 << 8;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1; del_fail_left = 100;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    raw_close(&c);
    /* -I, -D (exit 1) и -C, подтвердивший отсутствие (финальное ревью, I2). */
    CHECK(rule_count == 3 && strstr(rule_cmds[2], " -C OUTPUT") != NULL);
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1; del_fail_left = 0;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    CHECK(rule_count == 1 && strstr(rule_cmds[0], " -I OUTPUT") != NULL);
    raw_close(&c);

    /* Прочий отказ повторяется, но ограниченно: после RST_RELEASE_ATTEMPTS
       попыток запись бросается, и вставки больше не тянут за собой -D. */
    del_fail_code = 4 << 8;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1; del_fail_left = 1000;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    raw_close(&c);
    for (int round = 0; round < RST_RELEASE_ATTEMPTS + 2; round++) {
        rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
        CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
        c.rule_up = 0; /* только вставка: смотрим, сколько -D идёт перед ней */
        raw_close(&c);
    }
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    CHECK(rule_count == 1 && strstr(rule_cmds[0], " -I OUTPUT") != NULL);
    c.rule_up = 0;
    raw_close(&c);
    del_fail_left = 0;
    /* Брошенная на ходу запись не потеряна: её снимет выход процесса. */
    CHECK(d2k_raw_pending_count() == 1);
    retry_pending_releases(1);
    CHECK(d2k_raw_pending_count() == 0);
    d2k_raw_rule_hook = raw_rule_system;
}

/* Модель одного правила в OUTPUT для проверок жизненного цикла. */
static int m_up, m_kill_ins, m_kill_commits, m_del_generic_left;
static int model_hook(const char *cmd)
{
    test_rule_hook(cmd);
    if (strstr(cmd, " -I OUTPUT")) {
        if (!m_kill_ins || m_kill_commits) m_up = 1;
        return m_kill_ins ? D2K_RAW_RULE_KILLED : 0;
    }
    if (strstr(cmd, " -D OUTPUT")) {
        if (m_del_generic_left > 0) { m_del_generic_left--; return 1 << 8; } /* OTHER_PROBLEM */
        if (m_up) { m_up = 0; return 0; }
        return 1 << 8; /* Bad rule */
    }
    if (strstr(cmd, " -C OUTPUT")) return m_up ? 0 : 1 << 8;
    return 0;
}

/* Финальное ревью detect, I2. */
static void test_rule_lifecycle_has_no_leaks(void)
{
    static const uint8_t dst[4] = {198, 51, 100, 9};
    raw_conn c;
    char err[160] = "";
    pthread_once(&g_sweep_once, sweep_noop);
    d2k_raw_rule_hook = model_hook;
    size_t pend0 = d2k_raw_pending_count();

    /* 1. Вставку убили по сроку, но iptables успел зафиксировать правило:
          правило снимается сразу, хотя rule_up = 0 и raw_close его не тронет. */
    m_up = 0; m_kill_ins = 1; m_kill_commits = 1; m_del_generic_left = 0;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    unsigned long f0 = d2k_raw_rst_fail_count();
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    CHECK(c.rule_up == 0 && m_up == 0);
    CHECK(d2k_raw_rst_fail_count() == f0 + 1);
    CHECK(rule_count == 2 && strstr(rule_cmds[1], " -D OUTPUT") != NULL);
    raw_close(&c);
    CHECK(d2k_raw_pending_count() == pend0);

    /* 2. Убитая вставка без фиксации: -D отвечает exit 1, -C подтверждает
          отсутствие — запись не копится. */
    m_up = 0; m_kill_ins = 1; m_kill_commits = 0;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    CHECK(rule_count == 3 && strstr(rule_cmds[2], " -C OUTPUT") != NULL);
    raw_close(&c);
    CHECK(d2k_raw_pending_count() == pend0 && m_up == 0);

    /* 3. -D отвечает exit 1 по общей ошибке, а правило стоит (-C = 0): на
          слово не верим, запись остаётся в отложенных... */
    m_kill_ins = 0; m_del_generic_left = 2;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    CHECK(c.rule_up == 1 && m_up == 1);
    raw_close(&c);
    CHECK(m_up == 1 && d2k_raw_pending_count() == pend0 + 1);
    /* ...и снимается без новой вставки — перед следующей пачкой зондов. */
    rule_count = 0;
    d2k_raw_flush_pending();
    CHECK(m_up == 0 && d2k_raw_pending_count() == pend0);
    CHECK(rule_count == 1 && strstr(rule_cmds[0], " -D OUTPUT") != NULL);
    /* Пустой список — ни одной команды. */
    rule_count = 0;
    d2k_raw_flush_pending();
    CHECK(rule_count == 0);

    /* 4. Выход процесса снимает отложенное (atexit). Ребёнок оставляет одно
          неснятое правило и выходит; его команды пишутся в канал. */
    {
        int p[2];
        CHECK(pipe(p) == 0);
        fflush(NULL);
        pid_t pid = fork();
        if (pid == 0) {
            close(p[0]);
            m_up = 0; m_kill_ins = 0; m_del_generic_left = 4;
            dial_recv_fd = -1; outgoing_count = 0;
            if (raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) != 0) _exit(3);
            raw_close(&c);
            if (d2k_raw_pending_count() != pend0 + 1) _exit(4);
            exit_pipe_fd = p[1];
            d2k_raw_rule_hook = exit_hook;
            exit(0);
        }
        close(p[1]);
        char buf[512];
        size_t got = 0;
        ssize_t n;
        while (got < sizeof buf - 1 && (n = read(p[0], buf + got, sizeof buf - 1 - got)) > 0) got += (size_t)n;
        buf[got] = '\0';
        close(p[0]);
        int st = 0;
        CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
        CHECK(strstr(buf, " -D OUTPUT") != NULL);
    }
    m_del_generic_left = 0;
    d2k_raw_rule_hook = raw_rule_system;
}

/* Финальное ревью detect, I1: счётчики отказов правила и сырых соединений —
 * потока. Отказ вставки в соседнем рабочем потоке не метит этот прогон. */
static unsigned long other_fail_delta, other_dial_delta;
static void *failing_worker(void *arg)
{
    static const uint8_t dst[4] = {198, 51, 100, 10};
    raw_conn c;
    char err[160] = "";
    (void)arg;
    unsigned long f0 = d2k_raw_rst_fail_count(), d0 = d2k_raw_dial_count();
    rule_rc = 2 << 8; rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    if (raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0) raw_close(&c);
    other_fail_delta = d2k_raw_rst_fail_count() - f0;
    other_dial_delta = d2k_raw_dial_count() - d0;
    rule_rc = 0;
    return NULL;
}

static void test_rst_failures_are_per_thread(void)
{
    pthread_t th;
    pthread_once(&g_sweep_once, sweep_noop);
    d2k_raw_rule_hook = test_rule_hook;
    unsigned long mine_f = d2k_raw_rst_fail_count(), mine_d = d2k_raw_dial_count();
    CHECK(pthread_create(&th, NULL, failing_worker, NULL) == 0);
    pthread_join(th, NULL);
    CHECK(other_fail_delta == 1 && other_dial_delta == 1);
    CHECK(d2k_raw_rst_fail_count() == mine_f && d2k_raw_dial_count() == mine_d);
    d2k_raw_rule_hook = raw_rule_system;
}

/* Финальное ревью detect, M7: часы — 64 бита. Аптайм за 24,8 и 49,7 сутками
 * не ломает ни срок команды правила, ни ожидание ответа. */
static void test_clock_survives_long_uptime(void)
{
    int64_t saved = d2k_clock_offset_ms;
    d2k_clock_offset_ms = (int64_t)50 * 24 * 3600 * 1000; /* > 2^32 мс */
    CHECK(d2k_now_ms() > (int64_t)4294967296LL);
    int dl = g_rule_deadline_ms;
    g_rule_deadline_ms = 300;
    int64_t t0 = d2k_now_ms();
    CHECK(raw_rule_system("exit 0") == 0); /* не убита сразу */
    CHECK(raw_rule_system("exec sleep 30") == D2K_RAW_RULE_KILLED);
    CHECK(d2k_now_ms() - t0 >= 300 && d2k_now_ms() - t0 < 3000);
    g_rule_deadline_ms = dl;
    d2k_clock_offset_ms = (int64_t)0x7fffffffLL - 50; /* у самой границы long32 */
    t0 = d2k_now_ms();
    CHECK(raw_rule_system("exit 0") == 0);
    CHECK(d2k_now_ms() >= t0);
    d2k_clock_offset_ms = saved;
}

/* Ревью 49 (решение 3): голый -w ждёт замок без срока, а ждём мы под общим
 * мьютексом сырого слоя. Команда правила идёт со своим сроком: зависшая
 * убивается, и вызов возвращает отказ, а не держит все рабочие потоки. */
static void test_rule_command_is_bounded(void)
{
    int saved = g_rule_deadline_ms;
    g_rule_deadline_ms = 200;
    int64_t t0 = d2k_now_ms();
    int rc = raw_rule_system("exec sleep 30");
    int64_t took = d2k_now_ms() - t0;
    CHECK(rc != 0 && took < 3000);
    CHECK(raw_rule_system("exit 0") == 0);
    CHECK(raw_rule_system("exit 1") != 0);
    /* Ребёнок не наследует дескрипторы процесса (сокеты, NFQUEUE, журналы
       d2kc): открытый без CLOEXEC канал в команде правила не виден. */
    {
        int p[2];
        CHECK(pipe(p) == 0);
        char probe[64];
        snprintf(probe, sizeof probe, "test -e /dev/fd/%d", p[1]);
        CHECK(raw_rule_system(probe) != 0);
        close(p[0]); close(p[1]);
    }
    g_rule_deadline_ms = saved;
}

/* Прошивка без xt_comment (поле 03.10.2026, Keenetic mipsel 3.4_kn: в lsmod нет
 * xt_comment). Правило с комментарием отвергается — ставится старая форма без
 * него, снимается той же формой, и дальше процесс сразу ставит её. */
static int nocomment_hook(const char *cmd)
{
    if (rule_count < 4) { snprintf(rule_cmds[rule_count], sizeof rule_cmds[0], "%s", cmd); }
    rule_count++;
    return strstr(cmd, "--comment") ? 256 : 0;
}

static void test_rule_without_comment_module(void)
{
    static const uint8_t dst[4] = {198, 51, 100, 9};
    raw_conn c;
    char err[160] = "";
    pthread_once(&g_sweep_once, sweep_noop);
    d2k_raw_rule_hook = nocomment_hook;
    unsigned long fails0 = d2k_raw_rst_fail_count();
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    CHECK(c.rule_up == 1);
    CHECK(rule_count == 2 && strstr(rule_cmds[0], "--comment") && !strstr(rule_cmds[1], "--comment") &&
          strstr(rule_cmds[1], "-I OUTPUT"));
    raw_close(&c);
    CHECK(rule_count == 3 && strstr(rule_cmds[2], "-D OUTPUT") && !strstr(rule_cmds[2], "--comment"));
    CHECK(d2k_raw_rst_fail_count() == fails0); /* the rule did go in */
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    CHECK(c.rule_up == 1 && rule_count == 1 && !strstr(rule_cmds[0], "--comment"));
    raw_close(&c);
    d2k_raw_rule_hook = raw_rule_system;
}

/* OpenWrt без iptables (25.12, 07.10.2026): S99d2k экспортирует D2K_FW=nft,
 * и правило — элемент множества inet d2k_rst с таймаутом. После kill -9
 * элемент истекает сам; уборки по владельцу и запасной формы без комментария
 * (это про xt_comment) здесь нет. */
static int nft_del_rc, nft_get_rc;
static int nft_hook(const char *cmd)
{
    test_rule_hook(cmd);
    if (strstr(cmd, "delete element")) return nft_del_rc;
    if (strstr(cmd, "get element")) return nft_get_rc;
    return rule_rc;
}

static void test_rule_through_nft(void)
{
    static const uint8_t dst[4] = {198, 51, 100, 10};
    raw_conn c;
    char err[160] = "", want[96];
    uint16_t sport;
    pthread_once(&g_sweep_once, sweep_noop);
    d2k_raw_rule_hook = nft_hook;
    CHECK(setenv("D2K_FW", "nft", 1) == 0);

    rule_rc = 0; nft_del_rc = 0; nft_get_rc = 1 << 8;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    sport = c.sport;
    CHECK(c.rule_up == 1 && rule_count == 1);
    /* Ключ — кортеж зонда, а не один порт (ревью 07.10): элемент другого
       процесса с тем же портом к другой цели не задевается. */
    snprintf(want, sizeof want, "nft add element inet d2k_rst rst4 { %u . 198.51.100.10 . 443 timeout 300s }", (unsigned)sport);
    CHECK(strstr(rule_cmds[0], want) != NULL);
    CHECK(strstr(rule_cmds[0], "iptables") == NULL);
    raw_close(&c);
    snprintf(want, sizeof want, "nft delete element inet d2k_rst rst4 { %u . 198.51.100.10 . 443 }", (unsigned)sport);
    CHECK(rule_count == 2 && strstr(rule_cmds[1], want) != NULL);

    /* Элемент уже истёк: delete отказал, get подтвердил отсутствие — в
       отложенные снятия ничего не попадает. */
    nft_del_rc = 1 << 8;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    raw_close(&c);
    CHECK(rule_count == 3 && strstr(rule_cmds[2], "nft get element inet d2k_rst rst4 { ") != NULL);
    CHECK(d2k_raw_pending_count() == 0);

    /* Вставка отвергнута (нет таблицы): одна попытка, зонд идёт дальше. */
    unsigned long fails0 = d2k_raw_rst_fail_count();
    rule_rc = 1 << 8;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, 1, err, sizeof err) == 0);
    CHECK(c.rule_up == 0 && rule_count == 1);
    raw_close(&c);
    CHECK(rule_count == 1);
    CHECK(d2k_raw_rst_fail_count() == fails0 + 1);
    rule_rc = 0;

    /* IPv6 — своё множество, адрес в нотации nft. */
    {
        rst_key k6 = { .sport = 31000, .dport = 443, .family = 6,
                       .dst = {0x20, 0x01, 0x0d, 0xb8, [15] = 1} };
        rule_count = 0;
        CHECK(rst_rule_cmd_form("-I", &k6, 1) == 0);
        CHECK(strstr(rule_cmds[0], "nft add element inet d2k_rst rst6 { 31000 . 2001:db8::1 . 443 timeout 300s }") != NULL);
    }

    CHECK(unsetenv("D2K_FW") == 0);
    d2k_raw_rule_hook = raw_rule_system;
}

static void test_runtime_equals_datapath(const d2k_poison *hyp, size_t length, uint8_t family)
{
    d2k_trigger tr = {0};
    d2k_poison p = {0};
    uint8_t decoy[2048], tlv[D2K_PLAN_TLV_MAX], packet[4096];
    size_t dn = 0, tn = 0;
    char text[8192], err[200];
    d2k_plan *plan = NULL;
    d2k_actions actions = {0};
    d2k_pkt in = {0};
    d2k_conn conn = {0};
    CHECK(d2k_white_decoy_hello("hcaptcha.com", decoy, sizeof decoy, &dn) == 0);
    memcpy(tr.payload, decoy, dn); tr.len = length;
    tr.payload[3] = (uint8_t)((length - 5) >> 8); tr.payload[4] = (uint8_t)(length - 5);
    for (size_t i = 0; i < tr.payload[43]; i++) tr.payload[44 + i] = (uint8_t)(0x80 + i);
    tr.payload[6] = 0; tr.payload[7] = (uint8_t)((length - 9) >> 8); tr.payload[8] = (uint8_t)(length - 9); tr.sni_off = 100; tr.sni_len = 11;
    strcpy(p.name, "white-hello-ts");
    p.tcp_ts = 1; p.decoy_hello = 1; p.repeats = 8; p.split_pos = 2;
    p.decoy = decoy; p.decoy_len = dn;
    if (hyp) {
        p = *hyp;
        if (p.decoy_hello || p.seqovl_exact) { p.decoy = decoy; p.decoy_len = dn; }
        if (p.seqovl_exact) p.seqovl = (int)dn;
    }
    outgoing_count = 0; pending_delay = 0;
    pthread_once(&g_sweep_once, sweep_noop);
    d2k_raw_rule_hook = test_rule_hook; rule_rc = 0;
    /* No socket or firewall call escapes the harness. Invoke the production
       probe entry point, including its real send loop and raw_sendto. */
    const uint8_t ip4[] = {198,51,100,7};
    const uint8_t ip6[] = {0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,7};
    int probe_rc = d2k_raw_probe_poison_family(family == 6 ? ip6 : ip4, family, 443, &tr, &p,
                               100, 0, NULL, err, sizeof err);
    if (probe_rc && peer_timestamps) fprintf(stderr, "runtime %s len=%zu: rc=%d %s packets=%zu\n", p.name, length, probe_rc, err, outgoing_count);
    if (!peer_timestamps && (!hyp || hyp->md5_ts)) {
        CHECK(probe_rc == -1); CHECK(outgoing_count == 2);
        dial_recv_fd = -1;
        return; /* No TS: refuse locally, never fall back to another sender. */
    }
    CHECK(probe_rc == 0);
    if (hyp && !strcmp(p.name, "tcp-split")) {
        snprintf(text, sizeof text,
            "d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\n"
            "wire detect-tcp-v1\nsegment %u\nsplit payload_start +%d\norder forward\npace %u\n",
            (unsigned)D2K_ARM_SEGMENT_MAX, p.split_pos, (unsigned)p.gap_ms * 1000u);
    } else if (hyp) {
        d2k_arm arm;
        d2k_arm_input input = {0};
        CHECK(d2k_arm_from_poison(&p, &arm, err, sizeof err) == 0);
        input.trigger_len = tr.len; input.sni_off = tr.sni_off; input.sni_len = tr.sni_len;
        input.decoy_len = p.decoy_len;
        if (p.decoy_len) memcpy(input.decoy, p.decoy, p.decoy_len);
        CHECK(d2k_arm_plan_measured(&arm, &input, text, sizeof text) == 0);
    } else {
        CHECK(d2k_rx_volume_plan(0, D2K_SHAPE_MODERN, 0, text, sizeof text) == 0);
    }
    CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tn, err, sizeof err) == 0);
    CHECK(d2k_plan_load(tlv, tn, &plan, err, sizeof err) == 0);
    if (!plan || outgoing_count < 3) { failures++; goto done; }
    size_t iplen = family == 6 ? 40 : 20;
    in.seq = rd32(outgoing[0] + iplen + 4) + 1;
    in.payload = tr.payload; in.payload_len = tr.len;
    in.have_sni = 1; in.sni_off = tr.sni_off; in.sni_len = tr.sni_len;
    CHECK(d2k_plan_apply(plan, NULL, &in, &actions) == 0);
    memcpy(&conn.src_ip, outgoing[0] + 12, 4); memcpy(&conn.dst_ip, outgoing[0] + 16, 4);
    if (family == 6) {
        memcpy(conn.src_ip6, outgoing[0] + 8, 16); memcpy(conn.dst_ip6, outgoing[0] + 24, 16);
    }
    memcpy(&conn.src_port, outgoing[0] + iplen, 2); memcpy(&conn.dst_port, outgoing[0] + iplen + 2, 2);
    conn.family = family; conn.ack = 7001; conn.window = 65535; conn.ttl = 64;
    /* The raw connection offered TS=1 in its SYN; template traffic carries
       that negotiated option, fake TS is 1-1000. */
    memcpy(conn.tcp_options, (uint8_t[]){1,1,8,10,0,0,0,1,0,0,0x23,0x28}, 12);
    conn.tcp_options_len = 12;
    CHECK(outgoing_count == actions.n + 2);
    srandom(12345);
    for (size_t i = 0; i < actions.n && i + 2 < outgoing_count; i++) {
        size_t n = d2k_wire_build(&conn, &actions.v[i], packet, sizeof packet);
        d2k_test_packet measured = {outgoing[i+2], outgoing_len[i+2], outgoing_delay[i+2]};
        d2k_test_packet applied = {packet, n, actions.v[i].delay_us};
        CHECK(d2k_test_packet_equal(&measured, &applied));
        if (actions.v[i].poison & D2K_POISON_MD5_TS) {
            const uint8_t *tcp = measured.bytes + iplen;
            CHECK((tcp[12] >> 4) == 12 && tcp[20] == 19 && tcp[21] == 18);
            CHECK(!memcmp(tcp + 38, conn.tcp_options + 2, 10));
        }
    }
done:
    d2k_actions_free(&actions); d2k_plan_free(plan);
    dial_recv_fd = -1;
}

static void test_generated_program_execution(void) {
    d2k_trigger tr = {0};
    char program[256],err[160];
    d2k_raw_observation obs;
    tr.len=100;
    for(size_t i=0;i<tr.len;i++)tr.payload[i]=(uint8_t)i;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    payload_recv_error=1;
    for(unsigned cut=13;cut<80;cut+=29) {
        snprintf(program,sizeof program,
            "d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +%u\norder forward\n",cut);
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;
        CHECK(d2k_raw_probe_program((uint8_t[]){198,51,100,7},4,443,&tr,
            program,5,0,NULL,err,sizeof err,&obs)==-1);
        if(!obs.sent) fprintf(stderr, "generated program refused: %s\n",err);
        CHECK(obs.connected && obs.sent && obs.kind==D2K_RAW_OBS_LOCAL);
        CHECK(obs.program_packets==2 && obs.submitted_packets==2);
        CHECK(outgoing_count==4);
        if(outgoing_count==4) {
            size_t ihl=(outgoing[2][0]&15)*4;
            size_t off=ihl+(outgoing[2][ihl+12]>>4)*4;
            CHECK(outgoing_len[2]-off==cut);
            CHECK(!memcmp(outgoing[2]+off,tr.payload,cut));
            ihl=(outgoing[3][0]&15)*4;off=ihl+(outgoing[3][ihl+12]>>4)*4;
            CHECK(outgoing_len[3]-off==tr.len-cut);
            CHECK(!memcmp(outgoing[3]+off,tr.payload+cut,tr.len-cut));
        }
    }
    outgoing_count=0;dial_recv_fd=-1;fail_send_at=3;
    CHECK(d2k_raw_probe_program((uint8_t[]){198,51,100,7},4,443,&tr,
        program,5,0,NULL,err,sizeof err,&obs)==-1);
    CHECK(obs.connected && !obs.sent && obs.kind==D2K_RAW_OBS_LOCAL);
    CHECK(obs.program_packets==2 && obs.submitted_packets==1);
    CHECK(outgoing_count==3);
    CHECK(strstr(err,"send packet 2/2") && strstr(err,strerror(EIO)));
    fail_send_at=0;
    outgoing_count=0;dial_recv_fd=-1;
    CHECK(d2k_raw_probe_program
((uint8_t[]){198,51,100,7},4,443,&tr,
        "not a program",5,0,NULL,err,sizeof err,&obs)==-1);
    CHECK(obs.connected && !obs.sent && obs.kind==D2K_RAW_OBS_LOCAL);
    CHECK(outgoing_count==2);
    CHECK(obs.program_packets==0 && obs.submitted_packets==0);
    tr.len=1556;
    for(size_t i=0;i<tr.len;i++)tr.payload[i]=(uint8_t)i;
    const char *direct="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
    for(unsigned cap=900;cap<=1400;cap+=500) {
        d2k_raw_set_segment_max(cap);
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;
        CHECK(d2k_raw_probe_program((uint8_t[]){198,51,100,7},4,443,&tr,
            direct,5,0,NULL,err,sizeof err,&obs)==-1);
        CHECK(obs.connected && obs.sent && obs.program_packets==2 && obs.submitted_packets==2);
        size_t copied=0;uint32_t first_seq=0;
        for(size_t i=2;i<outgoing_count;i++) {
            size_t ihl=(outgoing[i][0]&15)*4;
            size_t off=ihl+(outgoing[i][ihl+12]>>4)*4;
            size_t length=outgoing_len[i]-off;
            if(i==2)first_seq=rd32(outgoing[i]+ihl+4);
            CHECK(length<=cap && copied+length<=tr.len);
            CHECK(rd32(outgoing[i]+ihl+4)==first_seq+copied);
            if(copied+length<=tr.len)CHECK(!memcmp(outgoing[i]+off,tr.payload+copied,length));
            copied+=length;
        }
        CHECK(copied==tr.len);
    }
    d2k_raw_set_segment_max(0);
    payload_recv_error=0;
}

static int stream_read_fixture(void *ctx,size_t input,const d2k_raw_observation *obs,
                               const uint8_t *bytes,size_t n,uint64_t *out) {
    CHECK(input==1);
    return d2k_tls_decoder_read(ctx,input,obs,bytes,n,out);
}
static void test_learning_session_context(void)
{
    d2k_vres *candidate=calloc(1,sizeof *candidate);CHECK(candidate!=NULL);
    if(!candidate)return;
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    size_t chunk=4;d2k_tls_stream spec={&tr,&chunk,1,5,1};
    uint8_t reply[32];d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
        .reply=reply,.reply_capacity=sizeof reply};
    const char initial[]="controlled mock peer reset epoch";
    d2k_tls_learning *learning=d2k_tls_learning_new(&spec,&base,7,initial,sizeof initial);
    CHECK(learning!=NULL);if(!learning){free(candidate);return;}
    CHECK(d2k_tls_learning_prepare(learning,candidate)==D2K_SYN_EXPERIMENT);
    CHECK(!candidate->program_len && candidate->verdict==D2K_V_INCONCLUSIVE);
    outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    d2k_learning_round round;char err[160];
    CHECK(d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err)==D2K_L_OBSERVED);
    CHECK(round.requested==2 && round.completed==2 && round.execution==D2K_EXPERIMENT_TERMINAL && outgoing_count==3);
    char *plan=NULL;d2k_syn_result result=d2k_tls_learning_propose(learning,&plan,err,sizeof err);
    CHECK(result.status==D2K_SYN_EXPERIMENT && !plan);d2k_syn_result_free(&result);free(plan);
    outgoing_count=0;dial_recv_fd=-1;base.port=444;
    CHECK(d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err)==D2K_L_CONTEXT);
    CHECK(!outgoing_count && !round.completed);
    base.port=443;tr.payload[0]='z';
    CHECK(d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err)==D2K_L_CONTEXT);
    CHECK(!outgoing_count);tr.payload[0]='a';
    CHECK(d2k_tls_learning_step(learning,&spec,&base,"other reset",12,&round,err,sizeof err)==D2K_L_CONTEXT);
    CHECK(!outgoing_count);
    size_t directed[]={0,0,1};
    CHECK(d2k_tls_learning_request(learning,directed,3)==D2K_L_QUESTION);
    directed[0]=1;
    base.port=444;
    CHECK(d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err)==D2K_L_CONTEXT);
    CHECK(!outgoing_count);
    base.port=443;
    uint8_t alert[]={21,3,3,0,2,2,40};
    episode_reply=alert;episode_reply_len=sizeof alert;episode_reply_chunk=sizeof alert;episode_reply_at=0;
    CHECK(d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err)==D2K_L_OBSERVED);
    CHECK(round.requested==3 && round.completed==3 && round.execution==D2K_EXPERIMENT_TERMINAL);
    CHECK(outgoing_count==5);
    if(outgoing_count==5)for(size_t i=0;i<2;i++) {
        const uint8_t *p=outgoing[i+2];size_t ihl=(p[0]&15)*4,at=ihl+(p[ihl+12]>>4)*4;
        size_t offset=i?4:0,len=i?2:4;
        CHECK(outgoing_len[i+2]-at==len && !memcmp(p+at,tr.payload+offset,len));
    }
    result=d2k_tls_learning_propose(learning,&plan,err,sizeof err);
    CHECK(result.status!=D2K_SYN_CANDIDATE && !plan);
    d2k_syn_result_free(&result);free(plan);episode_reply=NULL;
    d2k_tls_learning_free(learning);free(candidate);
}
static void test_learning_candidate_result(void)
{
  for(int retry=0;retry<2;retry++) {
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    size_t chunk=4;d2k_tls_stream spec={&tr,&chunk,1,5,1};
    uint8_t reply[128];d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
        .reply=reply,.reply_capacity=sizeof reply};
    const char initial[]="controlled mock reset";
    d2k_tls_learning *learning=d2k_tls_learning_new(&spec,&base,8,initial,sizeof initial);
    d2k_vres *candidate=calloc(1,sizeof *candidate);CHECK(learning && candidate);
    if(!learning || !candidate){d2k_tls_learning_free(learning);free(candidate);return;}
    size_t word[]={0,0,1};
    CHECK(d2k_tls_learning_request(learning,word,3)==D2K_L_QUESTION);
    uint8_t hello[61]={22,3,3,0,42,2,0,0,38,3,3};size_t hello_len=47;
    hello[44]=0xc0;hello[45]=0x2f;
    if(retry) {
        static const uint8_t random[32]={
            0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
            0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
        memcpy(hello+11,random,sizeof random);hello_len=sizeof hello;
        hello[4]=56;hello[8]=52;hello[44]=0x13;hello[45]=1;
        memcpy(hello+47,(uint8_t[]){0,12,0,43,0,2,3,4,0,51,0,2,0,29},14);
        d2k_tls_observer *observer=d2k_tls_observer_new();CHECK(observer!=NULL);
        size_t used=0;d2k_tls_response response=d2k_tls_observer_feed(observer,hello,hello_len,&used);
        CHECK(response.kind==D2K_TLS_OBS_HELLO && response.retry && used==hello_len);
        d2k_tls_observer_free(observer);
    }
    episode_reply=hello;episode_reply_len=hello_len;episode_reply_chunk=hello_len;episode_reply_at=0;
    outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    d2k_learning_round round;char err[160];
    CHECK(d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err)==D2K_L_OBSERVED);
    CHECK(round.completed==3 && round.execution==D2K_EXPERIMENT_TERMINAL);
    d2k_syn_status prepared=d2k_tls_learning_prepare(learning,candidate);
    if(retry)CHECK(prepared!=D2K_SYN_CANDIDATE && !candidate->program_len);
    else {
        CHECK(prepared==D2K_SYN_CANDIDATE);
        CHECK(candidate->program_len && candidate->program_len==strlen(candidate->program));
        CHECK(strstr(candidate->program,"split payload_start +4\n")!=NULL);
    }
    CHECK(candidate->verdict==D2K_V_INCONCLUSIVE && candidate->owns_search && !candidate->have_arm && !candidate->marked);
    episode_reply=NULL;d2k_tls_learning_free(learning);free(candidate);
  }
}
static int learning_cancel(void *ctx) { return *(int *)ctx; }
static void test_tls_read_deadline(void)
{
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    size_t chunk=6;d2k_tls_stream spec={&tr,&chunk,1,250,1};
    uint8_t reply[128];d2k_tls_decoder decoder={0};
    d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
        .reply=reply,.reply_capacity=sizeof reply,.read_to_terminal=1,
        .decoder_context=&decoder,.begin_decode=d2k_tls_decoder_begin,.decode=d2k_tls_decoder_read};
    uint8_t alert[]={21,3,3,0,2,2,40};
    episode_reply=alert;episode_reply_len=sizeof alert;episode_reply_chunk=2;episode_reply_at=0;
    outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    int64_t old_offset=d2k_clock_offset_ms;episode_chunk_elapsed_ms=100;
    size_t word[]={0,1,1},completed=0;d2k_sample samples[3];d2k_raw_observation last;char err[160];
    CHECK(d2k_tls_stream_run(&spec,&base,word,3,samples,&completed,&last,err,sizeof err)==D2K_EXPERIMENT_TERMINAL);
    CHECK(completed==3);
    d2k_tls_response response={0};int timeout=0,reset=0;
    CHECK(d2k_tls_symbol_read(samples[1].observation,&response,&timeout,&reset)==1);
    CHECK(response.kind==D2K_TLS_OBS_MORE && timeout && !reset && samples[1].conclusive==D2K_SAMPLE_OBSERVED);
    CHECK(d2k_tls_symbol_read(samples[2].observation,&response,&timeout,&reset)==1);
    CHECK(response.kind==D2K_TLS_OBS_ALERT && response.alert_description==40 && !timeout && !reset);
    episode_chunk_elapsed_ms=0;d2k_clock_offset_ms=old_offset;
    episode_reply=NULL;d2k_tls_decoder_free(&decoder);
}
static void test_learning_reference_guard(void)
{
    for(int drift=0;drift<4;drift++) {
        d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
        size_t chunk=4;d2k_tls_stream spec={&tr,&chunk,1,5,1};
        uint8_t reply[128];d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
            .reply=reply,.reply_capacity=sizeof reply};
        const char initial[]="controlled reference guard fixture";
        d2k_tls_learning *learning=d2k_tls_learning_new(&spec,&base,12,initial,sizeof initial);
        CHECK(learning!=NULL);if(!learning)return;
        uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
        episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=sizeof hello;
        learning_peer_bytes=tr.len;learning_peer_connections=0;learning_peer_drift_at=0;
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
        payload_ack=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        size_t reference[]={0,0,1},question[]={0,1};
        CHECK(d2k_tls_learning_guard(learning,reference,3)==-1); /* not measured */
        CHECK(d2k_tls_learning_request(learning,reference,3)==D2K_L_QUESTION);
        d2k_learning_round round;char err[160];
        CHECK(d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err)==D2K_L_OBSERVED);
        CHECK(d2k_tls_learning_guard(learning,reference,1)==-1); /* send-only is no control */
        CHECK(d2k_tls_learning_guard(learning,reference,3)==0);
        reference[0]=99; /* owned control word */
        if(!drift)episode_reply_chunk=3; /* Same ServerHello, different TCP segmentation. */
        CHECK(d2k_tls_learning_request(learning,question,2)==D2K_L_QUESTION);
        learning_peer_drift_at=drift==1?2:drift==2?4:0;
        learning_peer_local_at=drift==3?2:0;
        d2k_learner_status status=d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err);
        d2k_learner_status expected=drift==3?D2K_L_INCONCLUSIVE:drift?D2K_L_CONTEXT:D2K_L_OBSERVED;
        CHECK(status==expected);
        CHECK(learning_peer_connections==(drift==1 || drift==3?2:4));
        if(drift) {
            size_t before=learning_peer_connections;
            CHECK(d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err)==expected);
            CHECK(learning_peer_connections==before);
            char *plan=NULL;d2k_syn_result r=d2k_tls_learning_propose(learning,&plan,err,sizeof err);
            CHECK(r.status==D2K_SYN_ERROR && !plan);d2k_syn_result_free(&r);free(plan);
        }
        d2k_tls_learning_free(learning);learning_peer_bytes=learning_peer_drift_at=learning_peer_local_at=0;episode_reply=NULL;
    }
}
static int learning_test_watchdog(void *ctx) {
    (void)ctx;return learning_peer_connections>128;
}
static void test_learning_worker_candidate(void)
{
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    size_t chunks[]={6,4};d2k_tls_stream spec={&tr,chunks,2,5,1};
    uint8_t reply[128];d2k_detect_stop cancel={learning_test_watchdog,NULL};
    d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
        .reply=reply,.reply_capacity=sizeof reply,.cancel=&cancel};
    const char initial[]="controlled mock peer explicitly reset on each connection";
    d2k_vres *out=calloc(1,sizeof *out);CHECK(out!=NULL);if(!out)return;
    uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
    episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=sizeof hello;
    learning_peer_bytes=tr.len;learning_peer_connections=0;
    outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
    payload_ack=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    d2k_syn_status result=d2k_tls_learning_work(&spec,&base,11,initial,sizeof initial,out);
    if(result!=D2K_SYN_CANDIDATE)fprintf(stderr,"worker candidate: status=%d connections=%zu reason=%s\n",result,learning_peer_connections,out->reason);
    CHECK(result==D2K_SYN_CANDIDATE && out->program_len);
    CHECK(out->synthesis_generation==11);
    CHECK(strstr(out->program,"split payload_start +4\n")!=NULL);
    CHECK(out->verdict==D2K_V_INCONCLUSIVE && out->probes==(int)learning_peer_connections);
    int learning_probes=out->probes;
    if(out->program_len) {
        d2k_experiment_operation ops[]={
            {.kind=D2K_EXPERIMENT_SEND,.trigger=&tr,.program=out->program,.offset=0,.next_offset=6},
            {.kind=D2K_EXPERIMENT_READ,.timeout_ms=5,.minimum=1}};
        d2k_tls_decoder decoder={0};base.operations=ops;base.operation_count=2;
        base.decoder_context=&decoder;base.begin_decode=d2k_tls_decoder_begin;base.decode=d2k_tls_decoder_read;
        size_t word[]={0,1},completed=0;d2k_sample samples[2];d2k_raw_observation last;char err[160];
        CHECK(d2k_experiment_run(&base,word,2,samples,&completed,&last,err,sizeof err)==D2K_EXPERIMENT_TERMINAL);
        d2k_tls_response response={0};int timeout=0,reset=0;
        CHECK(completed==2 && d2k_tls_symbol_read(samples[1].observation,&response,&timeout,&reset)==1);
        CHECK(response.kind==D2K_TLS_OBS_HELLO && !timeout && !reset);
        CHECK(outgoing_count==5);
        if(outgoing_count==5)for(size_t i=0;i<2;i++) {
            const uint8_t *p=outgoing[i+2];size_t ihl=(p[0]&15)*4,at=ihl+(p[ihl+12]>>4)*4;
            size_t offset=i?4:0,len=i?2:4;
            CHECK(outgoing_len[i+2]-at==len && !memcmp(p+at,tr.payload+offset,len));
        }
        d2k_tls_decoder_free(&decoder);
    }
    fprintf(stderr,"worker inference: %d experiments, exact Plan replay checked (mock peer)\n",learning_probes);
    learning_peer_bytes=0;episode_reply=NULL;free(out);
}
static void test_retained_continuous_session(void)
{
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    size_t chunks[]={6,4,2};d2k_tls_stream spec={&tr,chunks,3,5,1};
    uint8_t reply[128];d2k_detect_stop cancel={learning_test_watchdog,NULL};
    d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
        .reply=reply,.reply_capacity=sizeof reply,.cancel=&cancel};
    uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
    episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=sizeof hello;
    learning_peer_bytes=6;learning_peer_connections=0;learning_peer_allow_whole=0;
    outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
    payload_ack=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    d2k_tls_path_session *session=d2k_tls_path_session_new(&spec,&base,177);
    CHECK(session!=NULL);if(!session)return;
    CHECK(!learning_peer_connections); /* creation owns data, performs no IO */
    CHECK(d2k_tls_path_session_matches(session,&spec,&base));
    base.port=444;CHECK(!d2k_tls_path_session_matches(session,&spec,&base));base.port=443;
    base.mark=1;CHECK(!d2k_tls_path_session_matches(session,&spec,&base));base.mark=0;
    chunks[1]=3;CHECK(!d2k_tls_path_session_matches(session,&spec,&base));chunks[1]=4;
    memset(tr.payload,'x',tr.len);chunks[1]=1;base.port=1;
    d2k_vres first,again;
    CHECK(d2k_tls_path_session_next(session,&first)==D2K_SYN_CANDIDATE);
    CHECK(first.synthesis_generation==177 && strstr(first.program,"split payload_start +4"));
    size_t history_count=0;
    const d2k_path_event *history=d2k_tls_path_session_history(session,&history_count);
    CHECK(history && history_count>3);
    int saw_bytes=0;
    for(size_t i=0;i<history_count;i++)if(history[i].operation_available && history[i].operation.trigger) {
        CHECK(!memcmp(history[i].operation.trigger->payload,"abcdef",6));saw_bytes=1;
    }
    CHECK(saw_bytes);
    size_t connections=learning_peer_connections;
    CHECK(d2k_tls_path_session_next(session,&again)==D2K_SYN_CANDIDATE);
    CHECK(learning_peer_connections==connections && first.probes==again.probes);
    CHECK(first.program_len==again.program_len && !strcmp(first.program,again.program));
    size_t after=0;d2k_tls_path_session_history(session,&after);CHECK(after==history_count);
    CHECK(d2k_tls_path_session_disposition(session,178,first.program,D2K_VF_NOT_MET)==0);
    CHECK(d2k_tls_path_session_disposition(session,177,first.program,D2K_VF_UNKNOWN)==0);
    CHECK(d2k_tls_path_session_disposition(session,177,first.program,D2K_VF_APP_NOT_MET)==0);
    CHECK(d2k_tls_path_session_next(session,&again)==D2K_SYN_CANDIDATE);
    CHECK(!strcmp(first.program,again.program) && learning_peer_connections==connections);
    CHECK(d2k_tls_path_session_disposition(session,177,first.program,D2K_VF_NOT_MET)==1);
    d2k_tls_path_session_history(session,&after);CHECK(after==history_count);
    CHECK(d2k_tls_path_session_disposition(session,177,first.program,D2K_VF_NOT_MET)==0);
    d2k_syn_status next=d2k_tls_path_session_next(session,&again);
    if(next!=D2K_SYN_CANDIDATE)fprintf(stderr,"resumed: %d %s\n",next,again.reason);
    CHECK(next==D2K_SYN_CANDIDATE && strcmp(first.program,again.program));
    history=d2k_tls_path_session_history(session,&after);CHECK(after>history_count);
    if(after>history_count)CHECK(history[history_count].interval_start);
    d2k_tls_path_session_free(session);
    learning_peer_bytes=0;episode_reply=NULL;
}
typedef struct {d2k_raw_tape *last;uint64_t count;} tape_factory;
static int new_episode_tape(void *ctx,d2k_raw_tls_sink *sink)
{
    tape_factory *factory=ctx;
    if(factory->last) {
        const d2k_raw_tls_event *last=NULL,*event;
        for(size_t i=0;(event=d2k_raw_tape_event(factory->last,i));i++)last=event;
        CHECK(last && (last->action==D2K_RAW_TLS_CLOSE ||
            (last->action==D2K_RAW_TLS_OPEN && last->result)));
    }
    d2k_raw_tape_free(factory->last);
    factory->last=d2k_raw_tape_new(++factory->count);
    *sink=d2k_raw_tape_sink(factory->last);return factory->last?0:-1;
}
typedef struct {tape_factory factory;int ran,finished,uncertain;} application_macro_fixture;
static int macro_prefix(void *ctx,size_t op,const d2k_raw_observation *raw,
    const uint8_t *bytes,size_t length,uint64_t *out)
{(void)op;(void)raw;(void)bytes;*out=42;return length?(*(int *)ctx?2:1):0;}
static int macro_run(void *ctx,const d2k_tls_io *io)
{
    application_macro_fixture *f=ctx;f->ran++;
    char err[80];uint8_t received[3];size_t before=outgoing_count;
    CHECK(!io->write(io->context,(const uint8_t *)"abcdef",6,err,sizeof err));
    CHECK(outgoing_count==before);
    CHECK(io->read(io->context,received,3,5,err,sizeof err)==3 && !memcmp(received,"xyz",3));
    return 0;
}
static int macro_finish(void *ctx,uint64_t *output)
{
    application_macro_fixture *f=ctx;f->finished++;
    const d2k_raw_tls_event *last=NULL,*event;
    for(size_t i=0;(event=d2k_raw_tape_event(f->factory.last,i));i++)last=event;
    CHECK(f->ran==1 && last && last->action==D2K_RAW_TLS_CLOSE);
    *output=42;return !f->uncertain;
}
static void test_application_macro(void)
{
    for(int uncertain=0;uncertain<2;uncertain++) {
        application_macro_fixture f={.uncertain=uncertain};
        d2k_trigger tr={0};memcpy(tr.payload,"abcdef",6);tr.len=6;
        const char identity[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
        d2k_experiment_operation ops[]={
            {.kind=D2K_EXPERIMENT_SEND,.trigger=&tr,.program=identity,.next_offset=6},
            {.kind=D2K_EXPERIMENT_READ,.timeout_ms=5,.minimum=1}};
        uint8_t scratch[8],peer[]="xyz";
        d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
            .operations=ops,.operation_count=2,.reply=scratch,.reply_capacity=sizeof scratch,
            .decode=macro_prefix,.decoder_context=&f.uncertain,.tls_input=tr.payload,.tls_input_length=tr.len,
            .make_sink=new_episode_tape,.sink_context=&f.factory};
        d2k_path_application app={&f,macro_run,macro_finish,NULL};
        d2k_path_run *path=d2k_path_run_new_application(&e,&app);CHECK(path);
        if(!path)continue;
        episode_reply=peer;episode_reply_len=3;episode_reply_chunk=3;episode_reply_at=0;
        learning_peer_bytes=0;outgoing_count=0;dial_recv_fd=-1;pending_delay=0;
        payload_recv_error=0;fail_send_at=0;payload_ack=0;payload_silent=0;
        d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        char err[160];
        CHECK(d2k_path_run_step(path,2,err,sizeof err)==1);
        CHECK(d2k_path_run_step(path,0,err,sizeof err)==1);
        CHECK(d2k_path_run_step(path,1,err,sizeof err)==1);
        CHECK(d2k_path_run_step(path,4,err,sizeof err)==!uncertain);
        CHECK(f.ran==1 && f.finished==1);
        size_t count;const d2k_path_event *history=d2k_path_run_history(path,&count);
        CHECK(count==4 && history[3].sample.operation==4);
        d2k_sample projected={0};
        CHECK(d2k_path_event_project(&history[0],3,1,&projected)==1);
        CHECK(projected.operation==3);
        CHECK(d2k_path_event_project(&history[1],3,1,&projected)==1);
        CHECK(projected.operation==0);
        CHECK(d2k_path_event_project(&history[2],3,1,&projected)==1);
        CHECK(projected.operation==1);
        CHECK(d2k_path_event_project(&history[3],3,1,&projected)==1);
        CHECK(projected.operation==5 && projected.conclusive==history[3].sample.conclusive);
        CHECK(projected.observation==history[3].sample.observation);
        CHECK(history[3].sample.operation==4);
        projected.operation=77;
        CHECK(d2k_path_event_project(&history[3],3,0,&projected)==0 && projected.operation==77);
        CHECK(d2k_path_event_project(&history[2],1,1,&projected)==0 && projected.operation==77);
        CHECK(d2k_path_event_project(&history[0],SIZE_MAX,1,&projected)==-1);
        d2k_path_event malformed=history[0];
        malformed.action.index=1;
        CHECK(d2k_path_event_project(&malformed,3,1,&projected)==-1);
        malformed.action.kind=D2K_PATH_ACTION_INVALID;
        CHECK(d2k_path_event_project(&malformed,3,1,&projected)==-1);
        CHECK(projected.operation==77);
        if(!uncertain)CHECK(history[2].sample.observation!=history[3].sample.observation);
        d2k_hypothesis *h=NULL;d2k_transducer current;
        CHECK(d2k_path_run_model(path,&h,&current)==!uncertain);
        if(h){CHECK(current.operations==5);d2k_hypothesis_free(h);}
        d2k_experiment_operation extended_ops[4]={ops[0],ops[1],ops[1],ops[1]};
        extended_ops[2].timeout_ms=7;
        extended_ops[3].timeout_ms=9;
        d2k_experiment extended=e;extended.operations=extended_ops;extended.operation_count=3;
        size_t before_extension=outgoing_count;
        d2k_path_run *extended_path=d2k_path_run_extend(path,&extended);
        CHECK(extended_path && outgoing_count==before_extension);
        if(extended_path) {
            size_t extended_count;
            const d2k_path_event *eh=d2k_path_run_history(extended_path,&extended_count);
            CHECK(extended_count==count && eh[0].sample.operation==3 && eh[3].sample.operation==5);
            CHECK(eh[3].sample.observation==history[3].sample.observation);
            CHECK(eh[3].sample.conclusive==history[3].sample.conclusive);
            h=NULL;
            CHECK(d2k_path_run_model(extended_path,&h,&current)==!uncertain);
            if(h){CHECK(current.operations==6);d2k_hypothesis_free(h);}
            outgoing_count=0;dial_recv_fd=-1;episode_reply_at=0;
            CHECK(d2k_path_run_step(extended_path,3,err,sizeof err)==1);
            CHECK(!d2k_path_run_extend(extended_path,&extended));
            CHECK(d2k_path_run_step(extended_path,0,err,sizeof err)==1);
            CHECK(d2k_path_run_step(extended_path,2,err,sizeof err)==1);
            CHECK(d2k_path_run_step(extended_path,4,err,sizeof err)==1);
            CHECK(d2k_path_run_interrupt(extended_path)==1);
            d2k_experiment further=extended;further.operation_count=4;
            before_extension=outgoing_count;
            d2k_path_run *further_path=d2k_path_run_extend(extended_path,&further);
            CHECK(further_path && before_extension==outgoing_count);
            if(further_path) {
                size_t further_count;
                const d2k_path_event *fh=d2k_path_run_history(further_path,&further_count);
                CHECK(further_count==8 && further_path->interval_begin==8);
                CHECK(fh[0].sample.operation==4 && fh[3].sample.operation==6);
                CHECK(fh[6].sample.operation==2 && fh[7].sample.operation==5);
                CHECK(!further_path->pending.length && !further_path->pending_prefix);
                CHECK(!!further_path->saved==!uncertain);
                if(further_path->saved) {
                    d2k_transducer saved=d2k_hypothesis_model(further_path->saved->hypothesis);
                    CHECK(saved.operations==7);
                }
                d2k_path_run_free(further_path);
            }
            d2k_path_run_free(extended_path);
        }
        CHECK(history[0].sample.operation==2 && history[3].sample.operation==4);
        extended_ops[0].next_offset++;
        CHECK(!d2k_path_run_extend(path,&extended));
        extended_ops[0]=ops[0];extended.port=8443;
        CHECK(!d2k_path_run_extend(path,&extended));
        CHECK(d2k_path_run_step(path,4,err,sizeof err)<0);
        outgoing_count=0;dial_recv_fd=-1;episode_reply_at=0;
        CHECK(d2k_path_run_step(path,2,err,sizeof err)==1);
        d2k_path_run_free(path);d2k_raw_tape_free(f.factory.last);
    }
    episode_reply=NULL;
}
typedef struct {tape_factory factory;int runs,split,healthy,uncertain,reject_split,token_ineligible,require_reverse,packet_question,server_refusal,require_prefix,prefix_run,named_packet,require_mixed,mixed_runs,require_overlap,overlap_runs;const uint8_t *input;size_t input_length;const uint64_t *outcomes;size_t outcome_count;} application_worker_fixture;
static int worker_application_prepare(void *ctx,const char *program)
{
    application_worker_fixture *f=ctx;
    if(strstr(program,"poison 1 tcpts") && !f->prefix_run)f->prefix_run=f->runs+1;
    if(f->require_mixed) {
        f->split = strstr(program,"order emissions=0,2,1\n") != NULL;
        return 0;
    }
    if(f->require_overlap) {
        f->split = strstr(program,"seqovl payload=1 poison=0\n") != NULL &&
            strstr(program,"split payload_start +53\n") != NULL;
        return 0;
    }
    if(f->require_prefix){f->split=strstr(program,"poison 1 tcpts")!=NULL;
        if(f->require_prefix==2)f->split=f->split && strstr(program,"split payload_start +62\n")!=NULL;
        return 0;}
    f->split=strstr(program,f->packet_question && !f->named_packet?"split payload_start +3\n":"split payload_start +2\n")!=NULL;if(f->require_reverse)f->split=f->split && strstr(program,"order reverse")!=NULL;return 0;
}
static int worker_application_run(void *ctx,const d2k_tls_io *io)
{
    application_worker_fixture *f=ctx;f->runs++;
    char err[80];uint8_t response[47];
    CHECK(!io->write(io->context,f->input?f->input:(const uint8_t *)"abcdef",f->input?f->input_length:6,err,sizeof err));
    if(f->require_mixed && f->split) {
        f->mixed_runs++;
        const size_t offsets[]={0,63,62},lengths[]={62,104,1};
        CHECK(outgoing_count==5);
        if(outgoing_count==5)for(size_t i=0;i<3;i++) {
            const uint8_t *p=outgoing[i+2];size_t ihl=(p[0]&15)*4;
            size_t header=ihl+(p[ihl+12]>>4)*4;
            CHECK(d2k_wire_tcp_checksum_ok(p,outgoing_len[i+2]));
            CHECK(rd32(p+ihl+4)==rd32(outgoing[0]+24)+1+offsets[i]);
            CHECK(outgoing_len[i+2]-header==lengths[i]);
            CHECK(!memcmp(p+header,f->input+offsets[i],lengths[i]));
        }
    }
    if(f->require_overlap && f->split) {
        f->overlap_runs++;
        const size_t offsets[]={0,1,53},lengths[]={2,52,114};
        CHECK(outgoing_count==5);
        if(outgoing_count==5)for(size_t i=0;i<3;i++) {
            const uint8_t *p=outgoing[i+2];size_t ihl=(p[0]&15)*4;
            size_t header=ihl+(p[ihl+12]>>4)*4;
            CHECK(d2k_wire_tcp_checksum_ok(p,outgoing_len[i+2]));
            CHECK(rd32(p+ihl+4)==rd32(outgoing[0]+24)+1+offsets[i]-(i==0));
            CHECK(outgoing_len[i+2]-header==lengths[i]);
            if(i==0)CHECK(p[header]==0 && p[header+1]==f->input[0]);
            else CHECK(!memcmp(p+header,f->input+offsets[i],lengths[i]));
        }
    }
    CHECK(io->read(io->context,response,sizeof response,5,err,sizeof err)==sizeof response);
    return 0;
}
static int worker_application_finish(void *ctx,uint64_t *out)
{
    application_worker_fixture *f=ctx;
    if(f->outcomes){*out=f->outcomes[(size_t)f->runs<=f->outcome_count?(size_t)f->runs-1:f->outcome_count-1];return 1;}
    *out=f->server_refusal && f->runs>1?9:f->healthy || (f->split && !f->reject_split)?42:7;return !f->uncertain;
}
static int worker_application_accepted(void *ctx,uint64_t value)
{(void)ctx;return value==42;}
static int worker_token_question(void *ctx,uint64_t value)
{application_worker_fixture *f=ctx;return f->packet_question && value==7?2:!f->token_ineligible && value==7;}
static void test_application_prefix_extension(void) {
    for(int mode=0;mode<9;mode++){
    d2k_trigger tr={0};tr.len=167;tr.sni_off=61;tr.sni_len=2;
    uint8_t *b=tr.payload;b[0]=22;b[1]=3;b[2]=3;b[4]=162;b[5]=1;b[8]=158;b[9]=b[10]=3;
    b[45]=2;b[46]=0x13;b[47]=1;b[48]=1;b[51]=115;b[55]=7;b[57]=5;b[60]=2;b[61]=b[62]='a';b[64]=21;b[66]=100;
    uint8_t fake[63];memcpy(fake,b,sizeof fake);fake[4]=58;fake[8]=54;fake[51]=11;fake[61]='b';
    application_worker_fixture f={.token_ineligible=1,.require_prefix=1,.input=tr.payload,.input_length=tr.len};
    const uint64_t stable[]={7,7,7,7,7},changed[]={7,7,7,8,7};
    if(mode==1 || mode==2){f.packet_question=1;f.outcomes=mode==1?stable:changed;f.outcome_count=5;}
    if(mode==4)f.reject_split=1;
    if(mode>=5){f.packet_question=1;f.require_prefix=2;f.reject_split=mode==6 || mode==8;}
    size_t whole=tr.len;d2k_tls_stream stream={&tr,&whole,1,5,1};
    int cancelled=0;d2k_detect_stop cancel={learning_test_watchdog,&cancelled};
    d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,.offer_ts=1,
        .reply_capacity=128,.cancel=&cancel,.tls_input=tr.payload,.tls_input_length=tr.len,
        .make_sink=new_episode_tape,.sink_context=&f.factory};
    uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
    episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=sizeof hello;
    learning_peer_bytes=tr.len;learning_peer_connections=0;learning_peer_allow_whole=1;
    outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
    payload_ack=0;payload_silent=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;peer_timestamps=1;
    d2k_tls_application app={&f,worker_application_prepare,worker_application_run,
        worker_application_finish,worker_application_accepted,worker_token_question,0};
    d2k_tls_path_session *w=d2k_tls_path_session_new_application(&stream,&e,103,&app);CHECK(w);if(!w)return;
    if((mode>=3 && mode<5) || mode>=7) {
        if(mode>=7) {
            d2k_payload_piece pieces[]={{0,62,0},{62,tr.len-62,0}};
            CHECK(d2k_tls_path_session_initial_prefix_partition(w,fake,sizeof fake,1400,0,pieces,2)==1);
        } else CHECK(d2k_tls_path_session_initial_prefix(w,fake,sizeof fake,1400,0)==1);
        CHECK(!outgoing_count && !f.runs);
        CHECK(!d2k_tls_path_session_initial_prefix(w,fake,sizeof fake,1400,0));
        memset(fake,0,sizeof fake);
        d2k_vres initial;
        d2k_syn_status expected=mode==3 || mode==7?D2K_SYN_CANDIDATE:D2K_SYN_CLOSED;
        CHECK(d2k_tls_path_session_next(w,&initial)==expected);
        CHECK(f.runs==1 && f.prefix_run==1 && !initial.protocol_response);
        if(mode==3 || mode==7)CHECK(initial.program_len && strstr(initial.program,"poison 1 tcpts"));
        else CHECK(!initial.program_len);
        CHECK(!d2k_tls_path_session_initial_prefix(w,fake,sizeof fake,1400,0));
        CHECK(d2k_tls_path_session_next(w,&initial)==expected && f.runs==1);
        goto prefix_done;
    }
    CHECK(!d2k_tls_path_session_add_prefix(w,fake,sizeof fake,1400,0));
    d2k_vres result;CHECK(d2k_tls_path_session_next(w,&result)==D2K_SYN_CLOSED);
    int runs_before=f.runs;
    size_t before,after;d2k_tls_path_session_history(w,&before);size_t packets=outgoing_count;
    CHECK(d2k_tls_path_session_add_prefix(w,fake,sizeof fake,1400,0)==1);
    CHECK(!d2k_tls_path_session_add_prefix(w,fake,sizeof fake,1400,0));
    CHECK(!d2k_tls_path_session_add_action(w,whole,0));
    d2k_tls_path_session_history(w,&after);CHECK(before==after && packets==outgoing_count && f.runs==runs_before);
    memset(fake,0,sizeof fake);
    d2k_syn_status status=d2k_tls_path_session_next(w,&result);
    CHECK(f.prefix_run==runs_before+1);
    if(mode==5){CHECK(status==D2K_SYN_CANDIDATE && result.program_len);
        CHECK(strstr(result.program,"split payload_start +62\n") && strstr(result.program,"poison 1 tcpts"));
        CHECK(f.runs==runs_before+2);}
    else if(mode){CHECK(status==D2K_SYN_CLOSED && !result.program_len);
        CHECK(f.runs==runs_before+((mode==1 || mode==6)?2:1));}
    else {CHECK(status==D2K_SYN_CANDIDATE);CHECK(f.runs==2 && strstr(result.program,"poison 1 tcpts") && result.program_len);}
    if(!mode){CHECK(!d2k_tls_path_session_add_prefix(w,fake,sizeof fake,1400,0));}
    int runs_after=f.runs;
    CHECK(d2k_tls_path_session_next(w,&result)==status && f.runs==runs_after);
prefix_done:
    d2k_tls_path_session_free(w);d2k_raw_tape_free(f.factory.last);
    learning_peer_bytes=0;learning_peer_allow_whole=0;episode_reply=NULL;
    }
}
static void test_application_mixed_order(void)
{
    d2k_trigger tr={0};tr.len=167;tr.sni_off=61;tr.sni_len=2;
    uint8_t *b=tr.payload;b[0]=22;b[1]=3;b[2]=3;b[4]=162;b[5]=1;b[8]=158;b[9]=b[10]=3;
    b[45]=2;b[46]=0x13;b[47]=1;b[48]=1;b[51]=115;b[55]=7;b[57]=5;b[60]=2;
    b[61]=b[62]='a';b[64]=21;b[66]=100;
    size_t whole=tr.len;
    d2k_tls_stream spec={&tr,&whole,1,5,1};
    for (int mode=0;mode<5;mode++) {
        application_worker_fixture f={.require_mixed=mode!=4,.require_overlap=mode==4,
            .input=b,.input_length=tr.len,
            .reject_split=mode==1 || mode==3,.healthy=mode==2};
        int cancelled=0;d2k_detect_stop cancel={learning_test_watchdog,&cancelled};
        d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
            .reply_capacity=128,.cancel=&cancel,.tls_input=b,.tls_input_length=tr.len,
            .make_sink=new_episode_tape,.sink_context=&f.factory};
        uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
        episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=sizeof hello;
        learning_peer_bytes=tr.len;learning_peer_connections=0;learning_peer_allow_whole=1;
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
        payload_ack=0;payload_silent=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        d2k_tls_application app={&f,worker_application_prepare,worker_application_run,
            worker_application_finish,worker_application_accepted,worker_token_question,mode!=3};
        d2k_tls_path_session *w=d2k_tls_path_session_new_application(&spec,&base,105,&app);CHECK(w);
        if (!w) continue;
        d2k_vres out;d2k_syn_status got=d2k_tls_path_session_next(w,&out);
        d2k_syn_status expected=mode==0 || mode==4?D2K_SYN_CANDIDATE:
            mode==2?D2K_SYN_DIRECT_RESPONSE:D2K_SYN_CLOSED;
        if(got!=expected)fprintf(stderr,"mixed status mode=%d got=%d expected=%d runs=%d probes=%d reason=%s\n",mode,got,expected,f.runs,out.probes,out.reason);
        CHECK(got==expected);
        CHECK(!strcmp(out.arm_path,mode==4?"fallback":mode==0?"composition":""));
        if (!(f.runs==(mode==2?1:mode==3?3:mode==1 || mode==4?5:4) && out.probes==(mode==2?1:mode==3?4:mode==1 || mode==4?6:5)))
            fprintf(stderr,"mixed mode=%d runs=%d probes=%d status=%d\n",mode,f.runs,out.probes,got);
        CHECK(f.runs==(mode==2?1:mode==3?3:mode==1 || mode==4?5:4));
        CHECK(out.probes==(mode==2?1:mode==3?4:mode==1 || mode==4?6:5));
        CHECK(f.mixed_runs==(mode==0 || mode==1));
        CHECK(f.overlap_runs==(mode==4));
        if (mode==0 && got==expected) {
            CHECK(strstr(out.program,"split payload_start +62\n"));
            CHECK(strstr(out.program,"split payload_start +63\n"));
            CHECK(strstr(out.program,"order emissions=0,2,1\n"));
            CHECK(strstr(out.program,"input 167 61 2\n"));
            uint8_t alt[167];
            memcpy(alt,b,52);
            memcpy(alt+52,b+63,104);
            memcpy(alt+156,b+52,11);
            size_t alt_off=0,alt_len=0;
            CHECK(!d2k_hello_sni(alt,sizeof alt,&alt_off,&alt_len));
            CHECK(alt_off==165 && alt_len==2 && alt[alt_off]=='a');
            uint8_t tlv[D2K_PLAN_TLV_MAX];size_t tlv_len=0;char err[160];
            d2k_plan *plan=NULL;
            CHECK(!d2k_plan_text_to_tlv(out.program,tlv,sizeof tlv,&tlv_len,err,sizeof err));
            CHECK(!d2k_plan_load(tlv,tlv_len,&plan,err,sizeof err));
            if(plan) {
                d2k_pkt in={.payload=b,.payload_len=sizeof alt,.seq=1000,
                    .have_sni=1,.sni_off=61,.sni_len=2,.emit_original=1};
                d2k_actions actions={0};
                CHECK(!d2k_plan_apply(plan,NULL,&in,&actions));
                d2k_actions_free(&actions);
                in.payload=alt;in.sni_off=alt_off;
                CHECK(d2k_plan_apply(plan,NULL,&in,&actions)<0 && !actions.n);
                d2k_actions_free(&actions);d2k_plan_free(plan);
            }
        } else if (mode==4) {
            CHECK(strstr(out.program,"payload 1 00\n"));
            CHECK(strstr(out.program,"seqovl payload=1 poison=0\n"));
            CHECK(strstr(out.program,"split payload_start +1\n"));
            CHECK(strstr(out.program,"split payload_start +53\n"));
            CHECK(strstr(out.program,"input 167 61 2\n"));
        } else CHECK(!out.program_len);
        int runs=f.runs;
        CHECK(d2k_tls_path_session_next(w,&out)==got && f.runs==runs);
        CHECK(!strcmp(out.arm_path,mode==4?"fallback":mode==0?"composition":""));
        d2k_tls_path_session_free(w);d2k_raw_tape_free(f.factory.last);
    }
    learning_peer_bytes=0;learning_peer_allow_whole=0;episode_reply=NULL;
}

static void test_application_worker(void)
{
    for(int mode=0;mode<16;mode++) {
        application_worker_fixture f={.healthy=mode==1 || mode==6,.uncertain=mode==2 || mode==7,
            .reject_split=mode==5 || mode==13,.token_ineligible=mode==9 || mode==10,.require_reverse=mode==10 || mode==11,.packet_question=mode>=12,.server_refusal=mode==14,.named_packet=mode==15};
        d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
        if(mode>=4 && mode<12){tr.sni_off=1;tr.sni_len=mode==8?8:2;}
        if(mode==15){tr.sni_off=1;tr.sni_len=2;}
        size_t chunks[]={6,4,2};d2k_tls_stream spec={&tr,chunks,mode>=4?1:mode==3?2:3,5,1};
        int cancelled=0;d2k_detect_stop cancel={learning_test_watchdog,&cancelled};
        d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
            .reply_capacity=128,.cancel=&cancel,.tls_input=tr.payload,.tls_input_length=tr.len,
            .make_sink=new_episode_tape,.sink_context=&f.factory};
        uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
        episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=sizeof hello;
        learning_peer_bytes=6;learning_peer_connections=0;learning_peer_allow_whole=1;
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
        payload_ack=0;payload_silent=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        d2k_tls_application app={&f,worker_application_prepare,worker_application_run,
            worker_application_finish,worker_application_accepted,worker_token_question,0};
        d2k_tls_path_session *w=d2k_tls_path_session_new_application(&spec,&base,103,&app);CHECK(w);
        d2k_vres out;d2k_syn_status result=d2k_tls_path_session_next(w,&out);
        if(mode==3) {
            CHECK(result==D2K_SYN_CLOSED);
            size_t old_count;d2k_tls_path_session_history(w,&old_count);
            int old_runs=f.runs;
            CHECK(d2k_tls_path_session_add_chunk(w,4)==0);
            CHECK(d2k_tls_path_session_add_chunk(w,0)==0);
            CHECK(d2k_tls_path_session_add_chunk(w,7)==0);
            CHECK(d2k_tls_path_session_add_chunk(w,2)==1);
            CHECK(d2k_tls_path_session_add_action(w,5,0)==1);
            CHECK(w->actions[w->stream.chunks-1].bytes==5);
            CHECK(f.runs==old_runs);
            size_t retained;d2k_tls_path_session_history(w,&retained);
            CHECK(retained==old_count);
            result=d2k_tls_path_session_next(w,&out);
            CHECK(result==D2K_SYN_CANDIDATE && f.runs>old_runs);
            CHECK(d2k_tls_path_session_add_chunk(w,3)==0);
        }
        if(mode==10) {
            CHECK(result==D2K_SYN_CLOSED);
            size_t before,after;d2k_tls_path_session_history(w,&before);
            int runs=f.runs;
            CHECK(d2k_tls_path_session_add_action(w,2,1)==1);
            d2k_tls_path_session_history(w,&after);CHECK(before==after && runs==f.runs);
            result=d2k_tls_path_session_next(w,&out);
            CHECK(result==D2K_SYN_CANDIDATE && strstr(out.program,"order reverse"));
        }
        if(mode==12)CHECK(result==D2K_SYN_CANDIDATE && f.runs==2 && strstr(out.program,"split payload_start +3\n"));
        if(mode==15)CHECK(result==D2K_SYN_CANDIDATE && f.runs==2 && strstr(out.program,"split payload_start +2\n"));
        if(mode==13)CHECK(result==D2K_SYN_CLOSED && f.runs==3);
        if(mode==14)CHECK(result==D2K_SYN_CLOSED && f.runs==2 && !w->order_attempted);
        if(mode==11)CHECK(result==D2K_SYN_CANDIDATE && f.runs==3 && strstr(out.program,"order reverse"));
        if(mode==4)CHECK(result==D2K_SYN_CANDIDATE && f.runs==2 && strstr(out.program,"split payload_start +2\n"));
        if(mode==5)CHECK(result==D2K_SYN_CLOSED && f.runs==3);
        if(mode==8 || mode==9)CHECK(result==D2K_SYN_CLOSED && f.runs==1 && !w->token_cut);
        if(mode==5 || mode==11) {
            size_t count;const d2k_path_event *history=d2k_tls_path_session_history(w,&count);
            CHECK(w->order_attempted && !w->order_pending && w->order_witness<count);
            size_t first=w->order_witness;
            while(first && history[first-1].action.kind!=D2K_PATH_ACTION_OPEN)first--;
            d2k_payload_piece original[8];size_t n=0;
            for(size_t i=first;i<w->order_witness;i++)if(history[i].operation_available) {
                const d2k_experiment_operation *op=&history[i].operation;
                CHECK(n<8);if(n<8)original[n++]=(d2k_payload_piece){op->payload_offset,op->payload_length,0};
            }
            size_t at=w->order_witness+1;
            while(at<count && history[at].action.kind!=D2K_PATH_ACTION_OPEN)at++;
            size_t reversed=0;
            for(at++;at<count && history[at].action.kind!=D2K_PATH_ACTION_APPLICATION;at++) {
                if(!history[at].operation_available)continue;
                const d2k_experiment_operation *op=&history[at].operation;
                CHECK(reversed<n);
                if(reversed<n)CHECK(op->payload_offset==original[n-1-reversed].offset &&
                    op->payload_length==original[n-1-reversed].length);
                reversed++;
            }
            CHECK(n>1 && reversed==n);
        }
        if(mode==4 || mode==5) {
            size_t proof_count;const d2k_path_event *proof=d2k_tls_path_session_history(w,&proof_count);
            CHECK(w->token_cut==2 && w->token_witness<proof_count);
            CHECK(!w->token_pending);
            CHECK(proof[w->token_witness].action.kind==D2K_PATH_ACTION_APPLICATION);
        }
        if(mode==0 || mode==3) {
            if(result!=D2K_SYN_CANDIDATE)fprintf(stderr,"app worker result=%d runs=%d reason=%s\n",result,f.runs,out.reason);
            CHECK(result==D2K_SYN_CANDIDATE && f.runs>2 && strstr(out.program,"split payload_start +2\n"));
            CHECK(w->rejection_count==1 && !w->rejections[0].rejected);
            printf("application synthesis: %d trials, direct and candidate app failures retained, split +2 succeeds without rejection trie (mock peer)\n",f.runs);
        } else if(mode==1 || mode==6)CHECK(result==D2K_SYN_DIRECT_RESPONSE && f.runs==1 && out.probes==1);
        else if(mode==2 || mode==7)CHECK(result==D2K_SYN_ERROR && f.runs==1);
        size_t count,failures=0,successes=0;const d2k_path_event *events=d2k_tls_path_session_history(w,&count);
        for(size_t i=0;i<count;i++)if(events[i].sample.operation==w->stream.chunks+3 && events[i].sample.conclusive) {
            uint64_t value=0;int terminal=0;
            CHECK(d2k_path_run_output(w->path,events[i].sample.observation,&value,&terminal));
            failures+=value==7;successes+=value==42;
        }
        if(mode==0 || mode==3)CHECK(failures>=2 && successes==1);
        int before=f.runs;CHECK(d2k_tls_path_session_next(w,&out)==result && f.runs==before);
        if(mode==6) {
            /* Independent stronger application experiment. Its failure must
               not inherit the first epoch's accepted symbol or imply a
               packet-local token parser failure. Peer/application outcomes
               are simulated; path inference and raw executor are real. */
            application_worker_fixture stronger={.token_ineligible=1};
            d2k_experiment next_base=base;next_base.sink_context=&stronger.factory;
            d2k_tls_application next_app=app;next_app.context=&stronger;
            size_t old_count;const d2k_path_event *old=d2k_tls_path_session_history(w,&old_count);
            CHECK(old_count && successes==1);
            size_t old_observation=old[old_count-1].sample.observation;
            d2k_tls_path_session *next=d2k_tls_path_session_new_application(&spec,&next_base,103,&next_app);
            CHECK(next);
            d2k_vres later;
            CHECK(d2k_tls_path_session_next(next,&later)==D2K_SYN_CLOSED);
            CHECK(stronger.runs==1 && !later.program_len && !next->token_cut);
            CHECK(d2k_tls_path_session_next(w,&out)==D2K_SYN_DIRECT_RESPONSE && f.runs==before);
            size_t retained;old=d2k_tls_path_session_history(w,&retained);
            CHECK(retained==old_count && old[retained-1].sample.observation==old_observation);
            uint64_t value;int terminal;
            CHECK(d2k_path_run_output(w->path,old_observation,&value,&terminal) && value==42);
            d2k_tls_path_session_free(next);d2k_raw_tape_free(stronger.factory.last);
        }
        d2k_tls_path_session_free(w);d2k_raw_tape_free(f.factory.last);
    }
    learning_peer_bytes=0;learning_peer_allow_whole=0;episode_reply=NULL;
}
static void test_response_worker(void)
{
    for(int mode=0;mode<4;mode++) {
        d2k_trigger tr={0};tr.len=6;tr.sni_off=1;tr.sni_len=4;
        memcpy(tr.payload,"abcdef",6);
        if(mode==3) {
            memset(&tr,0,sizeof tr);size_t off,len;
            CHECK(!d2k_hello_from_profile(D2K_SHAPE_MODERN,"blocked.example",tr.payload,sizeof tr.payload,&tr.len));
            CHECK(!d2k_hello_sni(tr.payload,tr.len,&off,&len));
            tr.sni_off=(int)off;tr.sni_len=(int)len;
        }
        size_t whole=tr.len;d2k_tls_stream stream={&tr,&whole,1,5,1};
        int cancelled=mode==2;d2k_detect_stop stop={learning_cancel,&cancelled};
        d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,
            .connect_ms=50,.reply_capacity=128,.cancel=&stop};
        if(mode==3)base.offer_ts=1;
        uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
        episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=7;
        if(mode==3)episode_reply=NULL;
        learning_peer_bytes=tr.len;learning_peer_connections=0;learning_peer_allow_whole=mode==1;
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;
        fail_send_at=0;payload_ack=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        d2k_tls_path_session *w=d2k_tls_path_session_new_response(&stream,&base,301);
        CHECK(w);d2k_vres out;
        d2k_syn_status status=d2k_tls_path_session_next(w,&out);
        if(mode==3) {
            if(status!=D2K_SYN_CLOSED || out.probes!=7)
                fprintf(stderr,"response content: status=%d probes=%d reason=%s\n",status,out.probes,out.reason);
            CHECK(status==D2K_SYN_CLOSED && out.probes==7 && !out.program_len);
            CHECK(w->response_content_phase==2);
            CHECK(!memcmp(w->trigger.payload,tr.payload,tr.len));
        }
        else if(mode==2)CHECK(status==D2K_SYN_ERROR && !learning_peer_connections);
        else if(mode==1)CHECK(status==D2K_SYN_DIRECT_RESPONSE && out.probes==1 && !out.program_len);
        else {
            if(status!=D2K_SYN_CANDIDATE || out.probes!=2)
                fprintf(stderr,"response worker: status=%d probes=%d connections=%zu reason=%s\n",status,out.probes,learning_peer_connections,out.reason);
            CHECK(status==D2K_SYN_CANDIDATE && out.probes==2);
            CHECK(strstr(out.program,"split payload_start +3\n"));
        }
        CHECK(out.verdict==D2K_V_INCONCLUSIVE && !out.base_blocked);
        if(mode<2)CHECK(strstr(out.reason,"ServerHello"));
        CHECK(!d2k_tls_path_session_tls_io(w).context);
        if(mode==0) {
            size_t count;const d2k_path_event *events=d2k_tls_path_session_history(w,&count);
            CHECK(count>0);size_t observed=events[count-1].sample.observation;
            uint64_t value;int terminal;
            CHECK(d2k_path_run_output(w->path,observed,&value,&terminal));
            CHECK(path_hello(NULL,value)==1);
            size_t packets=outgoing_count;
            CHECK(!d2k_tls_path_session_disposition(w,302,out.program,D2K_VF_NOT_MET));
            CHECK(!d2k_tls_path_session_disposition(w,301,out.program,D2K_VF_UNKNOWN));
            CHECK(!d2k_tls_path_session_disposition(w,301,out.program,D2K_VF_APP_NOT_MET));
            CHECK(d2k_tls_path_session_disposition(w,301,out.program,D2K_VF_NOT_MET)==1);
            CHECK(outgoing_count==packets);
            CHECK(d2k_path_run_output(w->path,observed,&value,&terminal));
            CHECK(path_hello(NULL,value)==1);
            CHECK(d2k_tls_path_session_next(w,&out)==D2K_SYN_CANDIDATE);
            CHECK(strstr(out.program,"order reverse") && out.probes==3);
            CHECK(d2k_tls_path_session_disposition(w,301,out.program,D2K_VF_NOT_MET)==1);
            CHECK(d2k_tls_path_session_next(w,&out)==D2K_SYN_CLOSED && !out.program_len);
        }
        d2k_tls_path_session_free(w);
    }
    learning_peer_bytes=0;learning_peer_allow_whole=0;episode_reply=NULL;
}
static void test_continuous_worker(void)
{
    for(int capture=0;capture<2;capture++)
    for(int direct=0;direct<4;direct++) {
        d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
        size_t chunks[]={6,4};d2k_tls_stream spec={&tr,chunks,2,5,1};
        uint8_t reply[128];int cancelled=direct==2;
        d2k_detect_stop cancel={direct==2?learning_cancel:learning_test_watchdog,&cancelled};
        d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
            .reply=reply,.reply_capacity=sizeof reply,.cancel=&cancel};
        tape_factory factory={0};
        if(capture){base.tls_input=tr.payload;base.tls_input_length=tr.len;
            base.make_sink=new_episode_tape;base.sink_context=&factory;}
        uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
        episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=sizeof hello;
        learning_peer_bytes=6;learning_peer_connections=0;learning_peer_allow_whole=direct==1;
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=direct==3?2:0;
        payload_ack=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        d2k_vres out;
        d2k_tls_path_session *held=d2k_tls_path_session_new(&spec,&base,103);
        CHECK(held);
        d2k_syn_status result=d2k_tls_path_session_next(held,&out);
        if(direct>=2) {
            CHECK(result==D2K_SYN_ERROR && !out.program_len && !out.protocol_response);
            if(direct==2)CHECK(!learning_peer_connections);
        } else if(direct) {
            CHECK(result==D2K_SYN_DIRECT_RESPONSE && out.protocol_response && !out.program_len);
            CHECK(learning_peer_connections==1);
        } else {
            if(result!=D2K_SYN_CANDIDATE)fprintf(stderr,"continuous worker: %d %s connections=%zu\n",result,out.reason,learning_peer_connections);
            CHECK(result==D2K_SYN_CANDIDATE && out.synthesis_generation==103);
            CHECK(strstr(out.program,"split payload_start +4")!=NULL);
        }
        CHECK(out.verdict==D2K_V_INCONCLUSIVE && !out.base_blocked);
        CHECK(out.probes==(int)learning_peer_connections);
        d2k_tls_io io=d2k_tls_path_session_tls_io(held);
        d2k_application_owner *owner=NULL;
        CHECK(!!io.context==(capture && direct<2));
        if(io.context) {
            const d2k_raw_tls_event *opening=d2k_raw_tape_event(factory.last,0);
            CHECK(opening && opening->action==D2K_RAW_TLS_OPEN && opening->experience==factory.count);
            char program[4096];
            snprintf(program,sizeof program,"%s",direct?
                D2K_RAW_TLS_IDENTITY:out.program);
            char *label=strstr(program,"\nid ");CHECK(label);if(label)label[5]='1';
            d2k_synthesis_feedback id={.generation=103,.search_id=3,.target="dns.example",
                .ip="198.51.100.7",.resource="/dns-query",.port=443,.family=4,.transport=6,.doh=1,.program=program};
            id.plan_id[0]=1;id.trial_id[0]=2;
            owner=d2k_application_owner_recorded(&id,1,factory.last,tr.payload,tr.len);
            CHECK(owner!=NULL);
            size_t before=outgoing_count;uint8_t got[sizeof hello];
            CHECK(!io.write(io.context,tr.payload,tr.len,(char *)reply,sizeof reply));
            CHECK(outgoing_count==before);
            CHECK(io.read(io.context,got,sizeof got,5,(char *)reply,sizeof reply)==sizeof got);
            CHECK(!memcmp(got,hello,sizeof got));
            CHECK(!d2k_tls_path_session_tls_io(held).context);
            CHECK(!d2k_tls_path_session_disposition(held,103,out.program,D2K_VF_NOT_MET));
        }
        d2k_tls_path_session_free(held);
        if(owner) {
            d2k_ver_result observed={.level=D2K_VER_TRANSPORT};d2k_application_end end;
            CHECK(!d2k_application_owner_end(owner,&observed,&end));
            CHECK(end.network_evidence && end.experience==factory.count && end.input_length==tr.len &&
                !memcmp(end.input,tr.payload,tr.len));
        }
        if(capture && direct<2)CHECK(factory.count==(uint64_t)out.probes);
        d2k_raw_tape_free(factory.last);
        d2k_application_owner_free(owner);
    }
    fail_send_at=0;learning_peer_allow_whole=0;learning_peer_bytes=0;episode_reply=NULL;
}
static void test_learning_worker_stops(void)
{
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    size_t chunk=4;d2k_tls_stream spec={&tr,&chunk,1,5,1};
    uint8_t reply[128];int cancelled=1;
    d2k_detect_stop cancel={learning_cancel,&cancelled};
    d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
        .reply=reply,.reply_capacity=sizeof reply,.cancel=&cancel};
    const char initial[]="controlled mock reset";
    d2k_vres *out=calloc(1,sizeof *out);CHECK(out!=NULL);if(!out)return;
    outgoing_count=0;dial_recv_fd=-1;
    CHECK(d2k_tls_learning_work(&spec,&base,10,initial,sizeof initial,out)==D2K_SYN_ERROR);
    CHECK(!outgoing_count && !out->program_len && out->verdict==D2K_V_INCONCLUSIVE && !out->probes);
    cancelled=0;fail_send_at=1;payload_recv_error=0;pending_delay=0;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    CHECK(d2k_tls_learning_work(&spec,&base,10,initial,sizeof initial,out)==D2K_SYN_ERROR);
    CHECK(!out->program_len && out->verdict==D2K_V_INCONCLUSIVE);
    fail_send_at=0;free(out);
}
static void test_learning_worker_direct(void)
{
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    size_t chunk=4;d2k_tls_stream spec={&tr,&chunk,1,5,1}; /* whole-send added by worker */
    uint8_t reply[128];d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
        .reply=reply,.reply_capacity=sizeof reply};
    const char initial[]="controlled mock direct response";
    d2k_vres *out=calloc(1,sizeof *out);CHECK(out!=NULL);if(!out)return;
    uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
    episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=sizeof hello;
    learning_peer_bytes=6;learning_peer_connections=0;learning_peer_allow_whole=1;
    outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    CHECK(d2k_tls_learning_work(&spec,&base,13,initial,sizeof initial,out)==D2K_SYN_DIRECT_RESPONSE);
    CHECK(learning_peer_connections==1 && out->probes==1 && !out->program_len);
    CHECK(out->protocol_response);
    CHECK(out->verdict==D2K_V_INCONCLUSIVE && !out->have_arm && !out->base_blocked);
    CHECK(chunk==4 && spec.chunks==1);
    learning_peer_allow_whole=0;learning_peer_connections=0;learning_peer_local_at=2;
    CHECK(d2k_tls_learning_work(&spec,&base,14,initial,sizeof initial,out)==D2K_SYN_ERROR);
    CHECK(learning_peer_connections==2 && out->probes==2 && !out->program_len && !out->base_blocked);
    learning_peer_local_at=0;
    learning_peer_bytes=0;learning_peer_allow_whole=0;episode_reply=NULL;free(out);
}
static void test_learning_prepared_counterexample(void)
{
    d2k_trigger tr={0};tr.len=10;memcpy(tr.payload,"abcdefghij",10);
    size_t chunk=4;d2k_tls_stream spec={&tr,&chunk,1,5,1};
    uint8_t reply[128];d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
        .reply=reply,.reply_capacity=sizeof reply};
    const char initial[]="controlled mock reset";
    d2k_tls_learning *learning=d2k_tls_learning_new(&spec,&base,9,initial,sizeof initial);
    d2k_vres *candidate=calloc(1,sizeof *candidate);CHECK(learning && candidate);
    if(!learning || !candidate){d2k_tls_learning_free(learning);free(candidate);return;}
    uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
    size_t words[2][3]={{0,1,0},{0,0,1}};
    d2k_learning_round round;char err[160];
    for(size_t i=0;i<2;i++) {
        CHECK(d2k_tls_learning_request(learning,words[i],i+2)==D2K_L_QUESTION);
        episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=sizeof hello;episode_reply_at=0;
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
        d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        CHECK(d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err)==D2K_L_OBSERVED);
    }
    /* Prefix successes predict a full-input path. It is still unmeasured. */
    CHECK(d2k_tls_learning_prepare(learning,candidate)==D2K_SYN_EXPERIMENT);
    CHECK(!candidate->program_len && candidate->verdict==D2K_V_INCONCLUSIVE);
    uint8_t alert[]={21,3,3,0,2,2,40};
    episode_reply=alert;episode_reply_len=sizeof alert;episode_reply_chunk=sizeof alert;episode_reply_at=0;
    outgoing_count=0;dial_recv_fd=-1;
    CHECK(d2k_tls_learning_step(learning,&spec,&base,initial,sizeof initial,&round,err,sizeof err)==D2K_L_OBSERVED);
    CHECK(round.requested==4 && round.completed==4 && round.execution==D2K_EXPERIMENT_TERMINAL);
    CHECK(d2k_tls_learning_prepare(learning,candidate)!=D2K_SYN_CANDIDATE);
    CHECK(!candidate->program_len);
    episode_reply=NULL;d2k_tls_learning_free(learning);free(candidate);
}
static void test_stateful_stream_word(void)
{
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    size_t chunk=4;d2k_tls_stream spec={&tr,&chunk,1,5,1};
    uint8_t reply[32];d2k_tls_decoder decoder={0};
    d2k_experiment base={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,.offer_ts=1,
        .reply=reply,.reply_capacity=sizeof reply,.decoder_context=&decoder,
        .begin_decode=d2k_tls_decoder_begin,.decode=stream_read_fixture};
    uint8_t alert[]={21,3,3,0,2,2,40};const size_t word[]={0,0,1,1};
    episode_reply=alert;episode_reply_len=sizeof alert;episode_reply_chunk=4;episode_reply_at=0;
    outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    d2k_sample trace[4];size_t completed;d2k_raw_observation obs;char err[160];
    CHECK(d2k_tls_stream_run(&spec,&base,word,4,trace,&completed,&obs,err,sizeof err)==D2K_EXPERIMENT_TERMINAL);
    CHECK(completed==4 && outgoing_count==6 && trace[3].conclusive==D2K_SAMPLE_TERMINAL);
    for(size_t i=0;i<4;i++)CHECK(trace[i].operation==word[i]);
    if(outgoing_count==6)for(size_t i=0;i<2;i++) {
        const uint8_t *p=outgoing[i+2];size_t ihl=(p[0]&15)*4,at=ihl+(p[ihl+12]>>4)*4;
        size_t offset=i?4:0,len=i?2:4;
        CHECK(rd32(p+ihl+4)==rd32(outgoing[0]+24)+1+offset);
        CHECK(outgoing_len[i+2]-at==len && !memcmp(p+at,tr.payload+offset,len));
        CHECK((p[ihl+12]>>4)==8 && !memcmp(p+ihl+20,outgoing[1]+40,12));
    }
    const size_t invalid[]={0,0,0};outgoing_count=0;dial_recv_fd=-1;episode_reply_at=0;
    CHECK(d2k_tls_stream_run(&spec,&base,invalid,3,trace,&completed,&obs,err,sizeof err)==D2K_EXPERIMENT_ERROR);
    CHECK(!outgoing_count && !completed);
    episode_reply=NULL;d2k_tls_decoder_free(&decoder);
}
typedef struct {size_t count,fail_at;d2k_raw_tls_event events[8];uint8_t data[8][128];} tls_trace;
static int record_tls_trace(void *ctx,const d2k_raw_tls_event *event) {
    tls_trace *t=ctx;CHECK(t->count<8);if(t->count>=8)return -1;
    CHECK(event->experience==91 && event->ordinal==t->count);
    CHECK(event->finished_ms>=event->started_ms);
    t->events[t->count]=*event;
    CHECK(event->length<=sizeof t->data[0]);
    if(event->length<=sizeof t->data[0] && event->length)
        memcpy(t->data[t->count],event->bytes,event->length);
    t->count++;return t->fail_at && event->ordinal==t->fail_at?-1:0;
}
static void test_raw_tls_late_scope(void) {
    const char plan[]="d2k-plan 1 16\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nstream-offset 6\nsplit payload_start +2\norder forward\n";
    d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50};
    for(int cross=0;cross<2;cross++) {
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
        learning_peer_bytes=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        tls_trace trace={0};d2k_raw_tls_sink sink={91,&trace,record_tls_trace};
        char err[160];d2k_raw_tls *t=d2k_raw_tls_open_observed(&e,plan,&sink,err,sizeof err);
        CHECK(t!=NULL);if(!t)continue;
        d2k_tls_io io=d2k_raw_tls_io(t);
        int rc=io.write(io.context,(const uint8_t *)"abcdefg",cross?7:6,err,sizeof err);
        CHECK((rc==0)==!cross);
        if(!cross) {
            CHECK(!io.write(io.context,(const uint8_t *)"ghij",4,err,sizeof err));
            CHECK(!io.write(io.context,(const uint8_t *)"kl",2,err,sizeof err));
            CHECK(outgoing_count==6);
            if(outgoing_count==6) {
                size_t sizes[]={6,2,2,2},offsets[]={0,6,8,10};
                for(size_t i=0;i<4;i++) {
                    const uint8_t *p=outgoing[i+2];size_t ihl=(p[0]&15)*4,at=ihl+(p[ihl+12]>>4)*4;
                    CHECK(outgoing_len[i+2]-at==sizes[i]);
                    CHECK(rd32(p+ihl+4)==rd32(outgoing[0]+24)+1+offsets[i]);
                    CHECK(!memcmp(p+at,&"abcdefghijkl"[offsets[i]],sizes[i]));
                }
            }
        } else CHECK(outgoing_count==2);
        d2k_raw_tls_close(t);
    }
}
static void test_raw_tls_transport(void)
{
    const char plan[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +2\norder forward\n";
    d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,.offer_ts=1};
    uint8_t reply[]={1,2,3,4,5,6,7,8,9};
    episode_reply=reply;episode_reply_len=sizeof reply;episode_reply_chunk=sizeof reply;episode_reply_at=0;
    outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
    learning_peer_bytes=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    tls_trace trace={0};d2k_raw_tls_sink sink={91,&trace,record_tls_trace};
    char err[160]={0};d2k_raw_tls *t=d2k_raw_tls_open_observed(&e,plan,&sink,err,sizeof err);
    CHECK(t!=NULL);if(!t){episode_reply=NULL;return;}
    d2k_tls_io io=d2k_raw_tls_io(t);
    CHECK(io.write(io.context,(const uint8_t *)"abcdef",6,err,sizeof err)==0);
    CHECK(io.write(io.context,(const uint8_t *)"ghij",4,err,sizeof err)==0);
    CHECK(outgoing_count==5);
    if(outgoing_count==5) {
        CHECK((outgoing[4][32]>>4)==8);
        CHECK(!memcmp(outgoing[4]+40,outgoing[1]+40,12));
        const size_t sizes[]={2,4,4},offsets[]={0,2,6};
        for(size_t i=0;i<3;i++) {
            const uint8_t *p=outgoing[i+2];size_t ihl=(p[0]&15)*4,at=ihl+(p[ihl+12]>>4)*4;
            CHECK(outgoing_len[i+2]-at==sizes[i]);
            CHECK(rd32(p+ihl+4)==rd32(outgoing[0]+24)+1+offsets[i]);
            CHECK(!memcmp(p+at,&"abcdefghij"[offsets[i]],sizes[i]));
        }
    }
    uint8_t got[sizeof reply];
    for(size_t i=0;i<sizeof got;i++)CHECK(io.read(io.context,got+i,1,5,err,sizeof err)==1);
    CHECK(!memcmp(got,reply,sizeof reply));
    CHECK(episode_reply_at==sizeof reply);
    CHECK(trace.count==4 && trace.events[0].action==D2K_RAW_TLS_OPEN);
    CHECK(trace.events[0].tuple.family==4 && trace.events[0].tuple.remote_port==443);
    CHECK(!memcmp(trace.events[0].tuple.remote,e.ip,4));
    CHECK(trace.events[0].tuple.local_port==rd16(outgoing[0]+20));
    CHECK(!memcmp(&trace.events[0].tuple,&trace.events[3].tuple,sizeof trace.events[0].tuple));
    CHECK(trace.events[1].action==D2K_RAW_TLS_SEND && trace.events[1].send_offset==0);
    CHECK(trace.events[2].send_offset==6 && trace.events[2].length==4);
    CHECK(trace.events[3].action==D2K_RAW_TLS_READ && trace.events[3].length==sizeof reply);
    CHECK(!memcmp(trace.data[1],"abcdef",6) && !memcmp(trace.data[3],reply,sizeof reply));
    CHECK(io.read(io.context,got,1,5,err,sizeof err)<0);
    d2k_raw_observation obs;d2k_raw_tls_observation(t,&obs);
    CHECK(obs.kind==D2K_RAW_OBS_RESPONSE_TIMEOUT);
    CHECK(io.write(io.context,(const uint8_t *)"x",1,err,sizeof err)<0);
    d2k_raw_tls_close(t);
    CHECK(trace.count==6 && trace.events[4].observation.kind==D2K_RAW_OBS_RESPONSE_TIMEOUT &&
          trace.events[5].action==D2K_RAW_TLS_CLOSE);
    memset(&trace,0,sizeof trace);trace.fail_at=1;
    outgoing_count=0;dial_recv_fd=-1;episode_reply_at=0;
    t=d2k_raw_tls_open_observed(&e,plan,&sink,err,sizeof err);CHECK(t!=NULL);
    if(t) {
        io=d2k_raw_tls_io(t);
        CHECK(io.write(io.context,(const uint8_t *)"abcdef",6,err,sizeof err)<0);
        d2k_raw_tls_observation(t,&obs);CHECK(obs.kind==D2K_RAW_OBS_LOCAL);
        size_t sends=outgoing_count;
        CHECK(io.write(io.context,(const uint8_t *)"x",1,err,sizeof err)<0);
        CHECK(io.read(io.context,got,1,5,err,sizeof err)<0);
        CHECK(outgoing_count==sends && trace.count==2);
        d2k_raw_tls_close(t);
    }
    int cancelled=0;d2k_detect_stop cancel={learning_cancel,&cancelled};e.cancel=&cancel;
    outgoing_count=0;dial_recv_fd=-1;episode_reply_at=0;
    t=d2k_raw_tls_open(&e,plan,err,sizeof err);CHECK(t!=NULL);
    if(t) {
        io=d2k_raw_tls_io(t);
        CHECK(io.write(io.context,(const uint8_t *)"abcdef",6,err,sizeof err)==0);
        CHECK(io.read(io.context,got,1,5,err,sizeof err)==1 && got[0]==reply[0]);
        cancelled=1;
        CHECK(io.read(io.context,got,1,5,err,sizeof err)<0);
        d2k_raw_tls_observation(t,&obs);CHECK(obs.kind==D2K_RAW_OBS_CANCELLED);
        CHECK(io.write(io.context,(const uint8_t *)"x",1,err,sizeof err)<0);
        d2k_raw_tls_close(t);
    }
    for(int empty=0;empty<2;empty++) {
        e.cancel=NULL;episode_reply_fin=1;episode_fin_sent=0;
        episode_reply_len=empty?0:sizeof reply;episode_reply_at=0;
        outgoing_count=0;dial_recv_fd=-1;
        t=d2k_raw_tls_open(&e,plan,err,sizeof err);CHECK(t!=NULL);
        if(t) {
            io=d2k_raw_tls_io(t);
            CHECK(io.write(io.context,(const uint8_t *)"abcdef",6,err,sizeof err)==0);
            if(!empty) {
                for(size_t i=0;i<sizeof got;i++)CHECK(io.read(io.context,got+i,1,5,err,sizeof err)==1);
                CHECK(!memcmp(got,reply,sizeof reply));
            }
            CHECK(io.read(io.context,got,1,5,err,sizeof err)==0);
            d2k_raw_tls_observation(t,&obs);CHECK(obs.kind==D2K_RAW_OBS_RESPONSE_FIN);
            d2k_raw_tls_close(t);
        }
    }
    for(size_t minimum=1;minimum<=16;minimum+=15) {
        uint8_t alert[]={21,3,3,0,2,2,40},readbuf[32];
        d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
        d2k_experiment_operation ops[]={
            {.kind=D2K_EXPERIMENT_SEND,.trigger=&tr,.program=plan,.next_offset=6},
            {.kind=D2K_EXPERIMENT_READ,.timeout_ms=5,.minimum=minimum}};
        d2k_tls_decoder decoder={0};
        e.operations=ops;e.operation_count=2;e.reply=readbuf;e.reply_capacity=sizeof readbuf;
        e.begin_decode=d2k_tls_decoder_begin;e.decode=d2k_tls_decoder_read;e.decoder_context=&decoder;
        episode_reply=alert;episode_reply_len=sizeof alert;episode_reply_chunk=sizeof alert;
        episode_reply_at=0;episode_reply_fin=1;episode_fin_sent=0;outgoing_count=0;dial_recv_fd=-1;
        size_t word[]={0,1},completed=0;d2k_sample samples[2];
        CHECK(d2k_experiment_run(&e,word,2,samples,&completed,&obs,err,sizeof err)==D2K_EXPERIMENT_TERMINAL);
        CHECK(completed==2 && samples[1].conclusive==D2K_SAMPLE_TERMINAL);
        CHECK(d2k_tls_symbol_closed(samples[1].observation));
        d2k_tls_decoder_free(&decoder);
    }
    episode_reply_fin=episode_fin_sent=0;episode_reply=NULL;
}
static void test_raw_tls_prepared(void)
{
    const char plan[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
    d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50};
    uint8_t reply[]={1,2,3,4,5,6};
    for(int mismatch=0;mismatch<2;mismatch++) {
        episode_reply=reply;episode_reply_len=sizeof reply;episode_reply_chunk=3;episode_reply_at=0;
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
        learning_peer_bytes=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        char err[160]={0};d2k_raw_tls *t=d2k_raw_tls_open(&e,plan,err,sizeof err);CHECK(t!=NULL);
        if(!t)continue;
        CHECK(!d2k_raw_tls_prepare(t,(const uint8_t *)"hello",5,err,sizeof err));
        const uint8_t *prefix=NULL;size_t length=0;
        CHECK(!d2k_raw_tls_prefix(t,5,&prefix,&length,err,sizeof err));
        CHECK(length==3 && !memcmp(prefix,reply,3));
        CHECK(!d2k_raw_tls_prefix(t,5,&prefix,&length,err,sizeof err));
        CHECK(length==6 && !memcmp(prefix,reply,6));
        size_t before=outgoing_count;d2k_tls_io io=d2k_raw_tls_io(t);
        int rc=io.write(io.context,(const uint8_t *)(mismatch?"jello":"hello"),5,err,sizeof err);
        CHECK((rc==0)==!mismatch && outgoing_count==before);
        uint8_t got[6];
        if(!mismatch) {
            CHECK(io.read(io.context,got,sizeof got,5,err,sizeof err)==6);
            CHECK(!memcmp(got,reply,6));
            CHECK(!io.write(io.context,(const uint8_t *)"later",5,err,sizeof err));
            CHECK(outgoing_count==before+1);
        } else CHECK(io.read(io.context,got,sizeof got,5,err,sizeof err)<0);
        d2k_raw_tls_close(t);
    }
    episode_reply=NULL;
}
static void test_slice_word(void)
{
    const char plan[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    d2k_experiment_operation ops[]={
        {.kind=D2K_EXPERIMENT_SEND_SLICE,.trigger=&tr,.program=plan,.offset=0,.next_offset=2,.payload_offset=0,.payload_length=2},
        {.kind=D2K_EXPERIMENT_SEND_SLICE,.trigger=&tr,.program=plan,.offset=2,.next_offset=6,.payload_offset=2,.payload_length=4}};
    d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,.operations=ops,.operation_count=2};
    size_t word[]={0,1},completed=0;d2k_sample samples[2];d2k_raw_observation obs;char err[160];
    outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    CHECK(d2k_experiment_run(&e,word,2,samples,&completed,&obs,err,sizeof err)==D2K_EXPERIMENT_COMPLETE);
    CHECK(completed==2 && outgoing_count==4);
    if(outgoing_count==4)for(size_t i=0;i<2;i++) {
        const uint8_t *packet=outgoing[i+2];size_t ihl=(packet[0]&15)*4;
        size_t at=ihl+(packet[ihl+12]>>4)*4;
        CHECK(outgoing_len[i+2]-at==ops[i].payload_length);
        CHECK(!memcmp(packet+at,tr.payload+ops[i].payload_offset,ops[i].payload_length));
        CHECK(rd32(packet+ihl+4)==rd32(outgoing[0]+24)+1+ops[i].offset);
    }
    CHECK(tr.len==6 && !memcmp(tr.payload,"abcdef",6));
    ops[1].payload_offset=SIZE_MAX;outgoing_count=0;dial_recv_fd=-1;
    CHECK(d2k_experiment_run(&e,word,2,samples,&completed,&obs,err,sizeof err)==D2K_EXPERIMENT_ERROR);
    CHECK(!outgoing_count && !completed);
}
static void test_lowered_partition_wire(void)
{
    d2k_trigger tr={0};tr.len=20;for(size_t i=0;i<tr.len;i++)tr.payload[i]=(uint8_t)i;
    d2k_payload_piece forward[]={{0,3,0},{3,4,17},{7,13,17}};
    d2k_payload_piece reverse[]={{7,13,0},{3,4,17},{0,3,17}};
    for(int reversed=0;reversed<2;reversed++) {
        d2k_payload_piece *pieces=reversed?reverse:forward;
        char *program=NULL,err[256];d2k_raw_observation obs;
        CHECK(d2k_lower_partition(tr.len,pieces,3,"tls",&program,err,sizeof err)==D2K_LOWER_OK);
        if(!program)continue;
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
        d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        d2k_raw_episode *ep=d2k_raw_episode_open((uint8_t[]){198,51,100,7},4,443,
            50,0,0,NULL,err,sizeof err,&obs);
        CHECK(ep!=NULL);if(!ep){free(program);continue;}
        uint32_t base=rd32(outgoing[0]+24)+1;
        CHECK(!d2k_raw_episode_send(ep,0,(uint32_t)tr.len,&tr,program,NULL,err,sizeof err,&obs));
        CHECK(outgoing_count==5 && obs.submitted_packets==3);
        if(outgoing_count==5)for(size_t i=0;i<3;i++) {
            const uint8_t *packet=outgoing[i+2];size_t ihl=(packet[0]&15)*4;
            size_t offset=ihl+(packet[ihl+12]>>4)*4;
            CHECK(rd32(packet+ihl+4)==base+pieces[i].offset);
            CHECK(outgoing_len[i+2]-offset==pieces[i].length);
            CHECK(!memcmp(packet+offset,tr.payload+pieces[i].offset,pieces[i].length));
            CHECK(outgoing_delay[i+2]==pieces[i].delay_us);
        }
        d2k_raw_episode_free(ep);free(program);
    }
}
static void test_prefix_program_export(void) {
    d2k_trigger tr={0};tr.len=167;tr.sni_off=61;tr.sni_len=2;
    uint8_t *b=tr.payload;b[0]=22;b[1]=3;b[2]=3;b[4]=162;b[5]=1;b[8]=158;b[9]=b[10]=3;
    b[45]=2;b[46]=0x13;b[47]=1;b[48]=1;b[51]=115;b[55]=7;b[57]=5;b[60]=2;b[61]=b[62]='a';b[64]=21;b[66]=100;
    uint8_t fake[63];memcpy(fake,b,sizeof fake);fake[4]=58;fake[8]=54;fake[51]=11;fake[61]='b';
    d2k_stream_program *prefix=d2k_stream_prefix_new(fake,sizeof fake,64,0);CHECK(prefix);if(!prefix)return;
    d2k_stream_action action={.bytes=tr.len,.program=prefix};
    d2k_ordered_stream stream={&tr,&action,1,50,1};d2k_tls_decoder decoder={0};
    d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,.offer_ts=1,
        .operation_context=&stream,.resolve_operation=d2k_ordered_stream_operation,
        .operation_prefix_equal=d2k_ordered_stream_prefix_equal,.operation_count=2,
        .tls_input=tr.payload,.tls_input_length=tr.len,.reply_capacity=128,
        .decoder_context=&decoder,.begin_decode=d2k_tls_decoder_begin,.decode=d2k_tls_decoder_read};
    outgoing_count=0;dial_recv_fd=-1;dial_silent=0;payload_recv_error=0;fail_send_at=0;peer_timestamps=1;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;char err[200];
    d2k_path_run *path=d2k_path_run_new(&e);CHECK(path);
    if(path) {
        CHECK(d2k_path_run_step(path,2,err,sizeof err)==1);
        CHECK(d2k_path_run_step(path,1,err,sizeof err)==1);
        d2k_vres result;
        CHECK(d2k_path_run_tls_input_program(path,&tr,71,&result)==1);
        CHECK(result.program_len && !strcmp(result.program,d2k_stream_program_text(prefix)));
        CHECK(result.verdict==D2K_V_INCONCLUSIVE && !result.protocol_response);
        CHECK(d2k_path_run_tls_candidate(path,&tr,71,&result)==0);
        d2k_experiment_operation *recorded=&path->events[1].operation;
        recorded->tls_program=NULL;
        CHECK(d2k_path_run_tls_input_program(path,&tr,71,&result)==0);
        recorded->tls_program=prefix;recorded->program="foreign program";
        CHECK(d2k_path_run_tls_input_program(path,&tr,71,&result)==0);
        recorded->program=d2k_stream_program_text(prefix);recorded->next_offset--;
        CHECK(d2k_path_run_tls_input_program(path,&tr,71,&result)==0);
        recorded->next_offset++;
        d2k_path_run_free(path);
    }
    d2k_tls_decoder_free(&decoder);d2k_stream_program_free(prefix);
}
static void test_reverse_partition_tls_continuation(void) {
    d2k_trigger tr={0};tr.len=4;memcpy(tr.payload,"abcd",4);
    d2k_stream_action action={.bytes=2,.reverse=1};
    d2k_ordered_stream stream={&tr,&action,1,50,1};
    d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
        .operation_context=&stream,.resolve_operation=d2k_ordered_stream_operation,
        .operation_prefix_equal=d2k_ordered_stream_prefix_equal,.operation_count=2,
        .tls_input=tr.payload,.tls_input_length=4};
    outgoing_count=0;dial_recv_fd=-1;dial_silent=0;payload_recv_error=0;fail_send_at=0;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;
    d2k_raw_observation obs;char err[160];
    d2k_experiment_channel *c=d2k_experiment_open(&e,&obs,err,sizeof err);CHECK(c);
    if(!c)return;
    size_t word[]={1,1},done=0;d2k_sample trace[2];
    CHECK(d2k_experiment_continue(c,word,2,trace,&done,&obs,err,sizeof err)==D2K_EXPERIMENT_COMPLETE);
    CHECK(done==2 && outgoing_count==4);
    uint32_t base=rd32(outgoing[0]+24)+1;
    CHECK(rd32(outgoing[2]+24)==base+2 && rd32(outgoing[3]+24)==base);
    d2k_tls_io io=d2k_experiment_tls_io(c);CHECK(io.context);
    if(io.context) {
        CHECK(!io.write(io.context,tr.payload,4,err,sizeof err));CHECK(outgoing_count==4);
        CHECK(!io.write(io.context,(const uint8_t *)"next",4,err,sizeof err));
        CHECK(outgoing_count==5 && rd32(outgoing[4]+24)==base+4);
    }
    d2k_experiment_close(c);
}
static void test_episode_preserves_connection(void)
{
    const char late[] = "d2k-plan 1 16\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nstream-offset 4\nsplit payload_start +2\norder forward\n";
    const char plan[] = "d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +2\norder forward\n";
    d2k_trigger tr={0}; tr.len=4; memcpy(tr.payload,"abcd",4);
    char err[160]; d2k_raw_observation obs;
    outgoing_count=0; dial_recv_fd=-1; payload_recv_error=0; fail_send_at=0;
    d2k_raw_rule_hook=test_rule_hook; rule_rc=0; dial_silent=0;
    d2k_raw_episode *ep=d2k_raw_episode_open((uint8_t[]){198,51,100,7},4,443,
        50,0,0,NULL,err,sizeof err,&obs);
    CHECK(ep!=NULL); if(!ep) return;
    CHECK(outgoing_count==2 && obs.connected);
    CHECK(obs.transport.available && !obs.transport.received_packets);
    uint32_t base=rd32(outgoing[0]+24)+1;
    CHECK(d2k_raw_episode_send(ep,0,4,&tr,plan,NULL,err,sizeof err,&obs)==0);
    uint8_t reply[16];size_t have=99;
    dial_silent=EAGAIN;
    CHECK(d2k_raw_episode_read(ep,5,NULL,reply,sizeof reply,&have,6,&obs)==-1);
    CHECK(obs.kind==D2K_RAW_OBS_RESPONSE_TIMEOUT && have==0);
    CHECK(obs.transport.available && obs.transport.sent_end==4 && !obs.transport.ack_seen);
    dial_silent=0;
    CHECK(d2k_raw_episode_send(ep,4,8,&tr,late,NULL,err,sizeof err,&obs)==0);

    CHECK(outgoing_count==6);
    CHECK(rd32(outgoing[2]+24)==base && rd32(outgoing[4]+24)==base+4);
    CHECK(rd16(outgoing[2]+20)==rd16(outgoing[4]+20));
    fail_send_at=7;
    CHECK(d2k_raw_episode_send(ep,8,12,&tr,plan,NULL,err,sizeof err,&obs)==-1);
    CHECK(obs.submitted_packets==1 && obs.program_packets==2 && !obs.sent);
    fail_send_at=0;
    CHECK(d2k_raw_episode_send(ep,12,16,&tr,plan,NULL,err,sizeof err,&obs)==-1);
    CHECK(outgoing_count==7);
    d2k_raw_episode_free(ep);
    outgoing_count=0;dial_recv_fd=-1;
    ep=d2k_raw_episode_open((uint8_t[]){198,51,100,7},4,443,
        50,0,0,NULL,err,sizeof err,&obs);
    CHECK(ep!=NULL);if(!ep) return;
    CHECK(d2k_raw_episode_send(ep,0,4,&tr,plan,NULL,err,sizeof err,&obs)==0);
    payload_recv_error=1;
    CHECK(d2k_raw_episode_read(ep,5,NULL,reply,sizeof reply,&have,6,&obs)==-2);
    CHECK(obs.kind==D2K_RAW_OBS_LOCAL);
    CHECK(d2k_raw_episode_send(ep,4,8,&tr,plan,NULL,err,sizeof err,&obs)==-1);
    CHECK(outgoing_count==4);
    payload_recv_error=0;d2k_raw_episode_free(ep);
}


static void test_transport_progress_bounds(void)
{
    raw_conn c={0};uint8_t tcp[20]={0};
    c.transport.available=1;c.transport_base=UINT32_MAX-7;
    c.transport.sent_end=20;tcp[13]=TCP_ACK;
    wr32(tcp+8,c.transport_base+12);wr16(tcp+14,17);
    raw_transport_receive(&c,tcp,9);
    CHECK(c.observed.transport.acked_end==12 && c.transport.ack_advances==1);
    CHECK(c.transport.window_seen && c.transport.peer_window_raw==17);
    raw_transport_receive(&c,tcp,9);
    CHECK(c.transport.ack_advances==1 && c.transport.received_payload_bytes==18);
    wr32(tcp+8,c.transport_base+21);wr16(tcp+14,0);
    raw_transport_receive(&c,tcp,0);
    CHECK(c.transport.acked_end==12 && c.transport.peer_window_raw==17);
    wr32(tcp+8,c.transport_base-1);
    raw_transport_receive(&c,tcp,0);
    CHECK(c.transport.acked_end==12);
    wr32(tcp+8,c.transport_base+20);
    raw_transport_receive(&c,tcp,0);
    CHECK(c.transport.acked_end==20 && c.transport.ack_advances==2);
    CHECK(c.transport.window_seen && c.transport.peer_window_raw==0);
    tcp[13]=TCP_RST|TCP_ACK;wr16(tcp+14,100);
    raw_transport_receive(&c,tcp,0);
    CHECK(c.transport.ack_packets==5 && c.transport.received_packets==6);
    CHECK(c.transport.peer_window_raw==0);
    c.transport.received_packets=UINT64_MAX;c.transport.received_payload_bytes=UINT64_MAX-1;
    raw_transport_receive(&c,tcp,3);
    CHECK(c.transport.received_packets==UINT64_MAX && c.transport.received_payload_bytes==UINT64_MAX);
}

static void test_episode_packet_events(void)
{
    char err[160];d2k_raw_observation obs;d2k_raw_packet_event ev={0};
    uint8_t reply[32];d2k_poison none={0};
    outgoing_count=0;dial_recv_fd=-1;dial_silent=0;payload_recv_error=0;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;
    d2k_raw_episode *ep=d2k_raw_episode_open((uint8_t[]){198,51,100,7},4,443,
        50,0,0,NULL,err,sizeof err,&obs);
    CHECK(ep!=NULL);if(!ep)return;
    raw_conn *c=&ep->conn;
    incoming_len[0]=build_ipv4_tcp(incoming[0],sizeof incoming[0],c->dst,c->src,
        c->dport,c->sport,c->ack,c->seq,TCP_ACK,NULL,0,&none,NULL,0);
    packet_event_input=1;
    CHECK(d2k_raw_episode_event(ep,10,NULL,reply,sizeof reply,&ev,&obs)==0);
    CHECK(obs.kind==D2K_RAW_OBS_RESPONSE_ACK && ev.payload_len==0);
    CHECK(ev.ack_offset==0 && ev.ack_in_sent_range);
    CHECK(obs.transport.received_packets==1 && obs.transport.ack_packets==1 && obs.transport.ack_seen);
    const uint8_t body[]={0x16,3,3};
    incoming_len[0]=build_ipv4_tcp(incoming[0],sizeof incoming[0],c->dst,c->src,
        c->dport,c->sport,c->ack,c->seq+100,TCP_ACK,body,sizeof body,&none,NULL,0);
    CHECK(d2k_raw_episode_event(ep,10,NULL,reply,sizeof reply,&ev,&obs)==0);
    CHECK(obs.kind==D2K_RAW_OBS_RESPONSE_BYTES && ev.payload_len==sizeof body);
    CHECK(!ev.ack_in_sent_range && ev.ack_offset==100);
    CHECK(obs.transport.received_packets==2 && obs.transport.received_payload_bytes==3);
    CHECK(obs.transport.acked_end==0 && obs.transport.ack_advances==0);
    CHECK(ev.sequence_offset==0 && !memcmp(reply,body,sizeof body));
    CHECK(c->ack==7001);
    incoming_len[0]=build_ipv4_tcp(incoming[0],sizeof incoming[0],c->dst,c->src,
        c->dport,c->sport,c->ack,c->seq,TCP_ACK,body,sizeof body,&none,NULL,0);
    CHECK(d2k_raw_episode_event(ep,10,NULL,reply,sizeof reply,&ev,&obs)==0);
    CHECK(ev.ack_in_sent_range && c->ack==7004);

    incoming_len[0]=build_ipv4_tcp(incoming[0],sizeof incoming[0],c->dst,c->src,
        c->dport,c->sport,c->ack,c->seq,TCP_FIN|TCP_ACK,NULL,0,&none,NULL,0);
    CHECK(d2k_raw_episode_event(ep,10,NULL,reply,sizeof reply,&ev,&obs)==0);
    CHECK(obs.kind==D2K_RAW_OBS_RESPONSE_FIN && ev.sequence_offset==3);
    CHECK(d2k_raw_episode_event(ep,10,NULL,reply,sizeof reply,&ev,&obs)==-2);
    packet_event_input=0;d2k_raw_episode_free(ep);
}

static int decode_wait(void *ctx,size_t op,const d2k_raw_observation *obs,
                       const uint8_t *bytes,size_t n,uint64_t *output)
{
    (void)ctx;(void)op;(void)bytes;
    if(obs->kind!=D2K_RAW_OBS_RESPONSE_TIMEOUT || n) return 0;
    *output=17;return 1;
}
static int path_protocol_step(void *ctx,size_t state,size_t op,size_t *next)
{
    (void)ctx;
    if(state==0 && op==4) { *next=1; return 1; }
    if(state==1 && op==0) { *next=2; return 1; }
    if(state==2 && op==2) { *next=2; return 1; }
    if(state==2 && op==5) { *next=0; return 1; }
    return 0;
}
typedef struct {uint64_t output[5];} ambiguous_path;
static int ambiguous_path_step(void *ctx,size_t state,size_t op,d2k_transition *out)
{
    ambiguous_path *p=ctx;
    static const size_t operations[]={4,0,2,2,5};
    size_t pos=state%5,branch=state/5;
    if(op!=operations[pos])return 0;
    out->next=branch*5+(pos+1)%5;
    out->observation=p->output[pos];
    if(branch && pos==2)out->observation=p->output[0];
    return 1;
}
static int path_preserved(void *ctx,size_t state)
{ (void)ctx;return state==2; }
static int path_not_preserved(void *ctx,size_t state)
{ (void)ctx;(void)state;return 0; }
static int path_accept_symbol(void *ctx,uint64_t observation)
{ return observation==*(uint64_t *)ctx; }
static void test_adaptive_stream_channel(void)
{
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    size_t chunk=2;d2k_tls_stream stream={&tr,&chunk,1,20,1};
    d2k_tls_decoder decoder={0};uint8_t reply[128];char err[200];
    d2k_experiment e={.family=4,.port=443,.connect_ms=10,.operation_count=2,
        .resolve_operation=d2k_tls_stream_operation,.operation_context=&stream,
        .reply=reply,.reply_capacity=sizeof reply,.decoder_context=&decoder,
        .begin_decode=d2k_tls_decoder_begin,.decode=d2k_tls_decoder_read,.read_to_terminal=1};
    e.ip[0]=127;e.ip[3]=1;
    uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
    episode_reply=hello;episode_reply_len=sizeof hello;episode_reply_chunk=sizeof hello;
    for(int round=0;round<2;round++) {
        episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
        d2k_path_run *path=d2k_path_run_new(&e);CHECK(path!=NULL);if(!path)break;
        CHECK(d2k_path_run_step(path,2,err,sizeof err)==1);
        d2k_input_domain domain=d2k_tls_stream_path_domain(&stream);
        domain.initial=0;
        for(int i=0;i<3;i++) {
            size_t chosen=SIZE_MAX,next=0;
            if(i==0) {
                CHECK(d2k_path_run_advance(path,&domain,&chosen,err,sizeof err)==D2K_PATH_ADVANCED);
                CHECK(chosen==0);
            } else {
                chosen=0;CHECK(d2k_path_run_step(path,chosen,err,sizeof err)==1);
            }
            CHECK(domain.step(domain.ctx,domain.initial,chosen,&next)==1);
            domain.initial=next;
        }
        size_t wire_bytes=0,wire_pieces=0;
        for(size_t packet=0;packet<outgoing_count;packet++) {
            size_t ip_header=(outgoing[packet][0]&15)*4;
            size_t header=ip_header+(outgoing[packet][ip_header+12]>>4)*4;
            if(header>=outgoing_len[packet])continue;
            size_t payload=outgoing_len[packet]-header;
            CHECK(payload==2 && wire_bytes+payload<=tr.len);
            if(wire_bytes+payload<=tr.len)
                CHECK(!memcmp(outgoing[packet]+header,tr.payload+wire_bytes,payload));
            wire_bytes+=payload;wire_pieces++;
        }
        CHECK(wire_bytes==6 && wire_pieces==3);
        size_t count=0;const d2k_path_event *events=d2k_path_run_history(path,&count);
        CHECK(count==4);
        for(int i=0;i<3;i++) {
            CHECK(events[i+1].operation_available);
            CHECK(events[i+1].operation.payload_offset==(size_t)i*2);
            CHECK(events[i+1].operation.payload_length==2);
        }
        CHECK(d2k_path_run_step(path,1,err,sizeof err)==1);
        d2k_vres candidate;
        CHECK(d2k_path_run_tls_candidate(path,&tr,101,&candidate)==1);
        CHECK(candidate.program_len && candidate.synthesis_generation==101);
        CHECK(strstr(candidate.program,"split payload_start +2")!=NULL);
        CHECK(strstr(candidate.program,"split payload_start +4")!=NULL);
        d2k_path_run_free(path);
    }
    d2k_tls_decoder_free(&decoder);episode_reply=NULL;episode_reply_len=episode_reply_at=0;
}
static void test_path_candidate_export(void)
{
    static const char identity[]=D2K_RAW_TLS_IDENTITY;
    for(int mode=0;mode<8;mode++) {
        d2k_trigger tr={0};tr.len=4;memcpy(tr.payload,"abcd",4);
        d2k_experiment_operation ops[]={
            {.kind=D2K_EXPERIMENT_SEND_SLICE,.trigger=&tr,.program=identity,
             .offset=0,.next_offset=2,.payload_offset=0,.payload_length=2},
            {.kind=D2K_EXPERIMENT_SEND_SLICE,.trigger=&tr,.program=identity,
             .offset=2,.next_offset=4,.payload_offset=2,.payload_length=2},
            {.kind=D2K_EXPERIMENT_READ,.minimum=1,.timeout_ms=20}};
        if(mode==5) { ops[1].offset=ops[1].payload_offset=0;ops[1].next_offset=2; }
        if(mode==6)ops[1].program="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +1\norder forward\n";
        if(mode==7)ops[1].program="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
        d2k_tls_decoder decoder={0};uint8_t reply[128];
        d2k_experiment e={.family=4,.port=443,.connect_ms=10,.operations=ops,
            .operation_count=3,.reply=reply,.reply_capacity=sizeof reply,
            .decoder_context=&decoder,.begin_decode=d2k_tls_decoder_begin,
            .decode=d2k_tls_decoder_read,.read_to_terminal=1};
        e.ip[0]=127;e.ip[3]=1;
        uint8_t hello[47]={22,3,3,0,42,2,0,0,38,3,3};hello[44]=0xc0;hello[45]=0x2f;
        uint8_t alert[]={21,3,3,0,2,2,40};
        episode_reply=mode==2?alert:hello;episode_reply_len=mode==2?sizeof alert:sizeof hello;
        episode_reply_chunk=sizeof hello;episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
        d2k_path_run *path=d2k_path_run_new(&e);char err[200];d2k_vres result;
        CHECK(path!=NULL);if(!path)continue;
        CHECK(d2k_path_run_step(path,3,err,sizeof err)==1);
        CHECK(d2k_path_run_step(path,0,err,sizeof err)==1);
        if(mode!=1)CHECK(d2k_path_run_step(path,1,err,sizeof err)==1);
        CHECK(d2k_path_run_step(path,2,err,sizeof err)==1);
        if(mode==3)CHECK(d2k_path_run_step(path,4,err,sizeof err)==1);
        size_t packets_before=outgoing_count;
        int rc=d2k_path_run_tls_candidate(path,&tr,mode==4?0:71,&result);
        CHECK(outgoing_count==packets_before);
        CHECK(result.verdict==D2K_V_INCONCLUSIVE);
        CHECK(mode==0?rc==1:rc!=1);
        if(mode==0) {
            CHECK(result.program_len>0 && result.synthesis_generation==71);
            CHECK(strstr(result.program,"split payload_start +2")!=NULL);
        } else CHECK(!result.program_len);
        d2k_path_run_free(path);d2k_tls_decoder_free(&decoder);
    }
    episode_reply=NULL;episode_reply_len=episode_reply_at=0;
}
static int decode_stream_prefix(void *ctx,size_t op,const d2k_raw_observation *raw,
    const uint8_t *bytes,size_t n,uint64_t *out)
{
    (void)ctx;(void)op;(void)raw;(void)bytes;*out=n;return n?2:0;
}
static void test_experiment_tls_continuation(void)
{
    const char plan[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
    uint8_t peer[80];for(size_t i=0;i<sizeof peer;i++)peer[i]=(uint8_t)i;
    for(int mode=0;mode<4;mode++) {
        d2k_trigger tr={0};memcpy(tr.payload,"hello",5);tr.len=mode==2?4:5;
        d2k_experiment_operation ops[]={
            {.kind=D2K_EXPERIMENT_SEND,.trigger=&tr,.program=plan,.next_offset=(uint32_t)tr.len},
            {.kind=D2K_EXPERIMENT_READ,.timeout_ms=5,.minimum=1}};
        uint8_t tiny[2];d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
            .operations=ops,.operation_count=2,.reply=tiny,.reply_capacity=sizeof tiny,
            .decode=decode_stream_prefix,.tls_input=(const uint8_t *)"hello",.tls_input_length=5};
        tls_trace captured={0};d2k_raw_tls_sink sink={91,&captured,record_tls_trace};
        if(!mode || mode==3)e.sink=&sink;
        if(mode==3)captured.fail_at=2;
        episode_reply=peer;episode_reply_len=sizeof peer;episode_reply_chunk=sizeof peer;episode_reply_at=0;
        outgoing_count=0;dial_recv_fd=-1;pending_delay=0;payload_recv_error=0;fail_send_at=0;
        payload_silent=0;learning_peer_bytes=0;d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
        char err[160];d2k_raw_observation raw;size_t done=0,word[]={0,1};d2k_sample samples[2];
        d2k_experiment_channel *c=d2k_experiment_open(&e,&raw,err,sizeof err);CHECK(c);
        if(!c)continue;
        CHECK(!d2k_experiment_tls_io(c).context);
        CHECK(d2k_experiment_continue(c,word,2,samples,&done,&raw,err,sizeof err)==
            (mode==3?D2K_EXPERIMENT_ERROR:D2K_EXPERIMENT_TERMINAL));
        d2k_tls_io io=d2k_experiment_tls_io(c);
        if(!mode) {
            CHECK(captured.count==3);
            CHECK(captured.events[0].action==D2K_RAW_TLS_OPEN);
            CHECK(captured.events[1].action==D2K_RAW_TLS_SEND && captured.events[1].length==5);
            CHECK(captured.events[2].action==D2K_RAW_TLS_READ && captured.events[2].length==80);
            CHECK(!memcmp(captured.data[2],peer,sizeof peer));
        }
        if(mode>=2)CHECK(!io.context);
        else {
            CHECK(io.context);
            if(io.context) {
                size_t before=outgoing_count;uint8_t got[80];
                int rc=io.write(io.context,(const uint8_t *)(mode?"jello":"hello"),5,err,sizeof err);
                CHECK((rc==0)==!mode && outgoing_count==before);
                if(!mode) {
                    CHECK(io.read(io.context,got,3,5,err,sizeof err)==3);
                    CHECK(io.read(io.context,got+3,77,5,err,sizeof err)==77);
                    CHECK(!memcmp(got,peer,sizeof got));
                    CHECK(!io.write(io.context,(const uint8_t *)"next",4,err,sizeof err));
                    CHECK(captured.count==4 && captured.events[3].action==D2K_RAW_TLS_SEND &&
                        captured.events[3].send_offset==5 && !memcmp(captured.data[3],"next",4));
                } else CHECK(io.read(io.context,got,sizeof got,5,err,sizeof err)<0);
            }
        }
        d2k_experiment_close(c);
        if(!mode)CHECK(captured.count==5 && captured.events[4].action==D2K_RAW_TLS_CLOSE &&
            captured.events[4].send_offset==9);
    }
    episode_reply=NULL;
}
static void test_experiment_word(void)
{
    d2k_observations *observations=d2k_observations_new();
    CHECK(observations!=NULL);if(!observations)return;
    const char plan[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +2\norder forward\n";
    d2k_trigger tr={0};tr.len=4;memcpy(tr.payload,"abcd",4);
    d2k_experiment_operation ops[]={
        {.kind=D2K_EXPERIMENT_SEND,.trigger=&tr,.program=plan,.offset=0,.next_offset=4},
        {.kind=D2K_EXPERIMENT_SEND,.trigger=&tr,.program=plan,.offset=4,.next_offset=8},
        {.kind=D2K_EXPERIMENT_READ,.timeout_ms=3,.minimum=6},
        {.kind=D2K_EXPERIMENT_PACKET,.timeout_ms=3}};
    uint8_t reply[16];d2k_sample samples[3];size_t completed;
    d2k_raw_observation last;char err[160];
    d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,.connect_ms=50,
        .operations=ops,.operation_count=4,.reply=reply,.reply_capacity=sizeof reply,
        .decode=decode_wait,.decode_packet=d2k_observations_decode,.decoder_context=observations};
    const size_t word[]={0,1,2};
    payload_silent=1;
    outgoing_count=0;dial_recv_fd=-1;payload_recv_error=0;fail_send_at=0;
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=0;
    CHECK(d2k_experiment_run(&e,word,3,samples,&completed,&last,err,sizeof err)
          ==D2K_EXPERIMENT_COMPLETE);
    CHECK(completed==3 && samples[2].conclusive && samples[2].observation==17);
    CHECK(outgoing_count==6);
    outgoing_count=0;dial_recv_fd=-1;fail_send_at=5;
    CHECK(d2k_experiment_run(&e,word,3,samples,&completed,&last,err,sizeof err)
          ==D2K_EXPERIMENT_INCONCLUSIVE);
    CHECK(completed==1 && samples[0].conclusive && !samples[1].conclusive);
    CHECK(outgoing_count==5 && last.submitted_packets==1);
    fail_send_at=0;payload_silent=0;
    outgoing_count=0;dial_recv_fd=-1;
    CHECK(d2k_experiment_run(&e,word,3,samples,&completed,&last,err,sizeof err)
          ==D2K_EXPERIMENT_INCONCLUSIVE);
    CHECK(completed==2 && !samples[2].conclusive && outgoing_count==6);
    outgoing_count=0;dial_recv_fd=-1;
    const size_t ack_word[]={0,3};payload_ack=1;
    CHECK(d2k_experiment_run(&e,ack_word,2,samples,&completed,&last,err,sizeof err)
          ==D2K_EXPERIMENT_COMPLETE);
    CHECK(completed==2 && samples[1].conclusive);
    const d2k_observed_packet *observed=d2k_observations_get(observations,samples[1].observation);
    CHECK(observed && observed->kind==D2K_RAW_OBS_RESPONSE_ACK &&
          observed->packet.ack_offset==4 && observed->packet.ack_in_sent_range);
    CHECK(outgoing_count==4 && last.kind==D2K_RAW_OBS_RESPONSE_ACK);
    payload_ack=0;outgoing_count=0;dial_recv_fd=-1;
    const size_t bad_word[]={0,99};

    CHECK(d2k_experiment_run(&e,bad_word,2,samples,&completed,&last,err,sizeof err)
          ==D2K_EXPERIMENT_ERROR);
    CHECK(completed==0 && outgoing_count==0);
    CHECK(d2k_experiment_run(&e,NULL,0,NULL,&completed,&last,err,sizeof err)
          ==D2K_EXPERIMENT_COMPLETE);
    CHECK(completed==0 && outgoing_count==0);

    payload_silent=1;outgoing_count=0;dial_recv_fd=-1;
    d2k_experiment_channel *channel=d2k_experiment_open(&e,&last,err,sizeof err);
    CHECK(channel!=NULL);
    if(channel) {
        CHECK(outgoing_count==2);
        CHECK(d2k_experiment_continue(channel,word,1,samples,&completed,&last,err,sizeof err)==D2K_EXPERIMENT_COMPLETE);
        CHECK(completed==1 && outgoing_count==4);
        CHECK(d2k_experiment_continue(channel,word+1,2,samples,&completed,&last,err,sizeof err)==D2K_EXPERIMENT_COMPLETE);
        CHECK(completed==2 && outgoing_count==6);
        CHECK(rd16(outgoing[2]+20)==rd16(outgoing[4]+20));
        CHECK(rd32(outgoing[4]+24)==rd32(outgoing[2]+24)+4);
        payload_silent=0;payload_recv_error=1;
        CHECK(d2k_experiment_continue(channel,word+2,1,samples,&completed,&last,err,sizeof err)==D2K_EXPERIMENT_INCONCLUSIVE);
        payload_recv_error=0;
        CHECK(d2k_experiment_continue(channel,word,1,samples,&completed,&last,err,sizeof err)==D2K_EXPERIMENT_ERROR);
        CHECK(outgoing_count==6);
        d2k_experiment_close(channel);
    }
    payload_silent=0;
    d2k_observations_free(observations);
    d2k_tls_decoder tls={0};
    e.decoder_context=&tls;e.begin_decode=d2k_tls_decoder_begin;e.decode=d2k_tls_decoder_read;
    e.tls_input=tr.payload;e.tls_input_length=tr.len;
    ops[2].minimum=1;
    uint8_t alert[]={21,3,3,0,2,2,40};
    const size_t tls_word[]={0,2,2,1};d2k_sample tls_samples[4];
    const char context[]="mock TCP peer/resettable/first TLS response/v1";
    d2k_evidence *evidence=d2k_evidence_new(context,sizeof context,e.operation_count);
    CHECK(evidence!=NULL);
    episode_reply=alert;episode_reply_len=sizeof alert;episode_reply_chunk=4;
    e.offer_ts=1;
    episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
    channel=d2k_experiment_open(&e,&last,err,sizeof err);
    CHECK(channel!=NULL);
    if(channel) {
        CHECK(d2k_experiment_continue(channel,tls_word,2,tls_samples,&completed,
              &last,err,sizeof err)==D2K_EXPERIMENT_COMPLETE);
        CHECK(completed==2 && tls_samples[1].conclusive==D2K_SAMPLE_OBSERVED);
        CHECK(d2k_experiment_continue(channel,tls_word+2,1,tls_samples,&completed,
              &last,err,sizeof err)==D2K_EXPERIMENT_TERMINAL);
        CHECK(completed==1 && tls_samples[0].conclusive==D2K_SAMPLE_TERMINAL);
        size_t packets_before=outgoing_count;
        CHECK(d2k_experiment_continue(channel,tls_word,1,tls_samples,&completed,
              &last,err,sizeof err)==D2K_EXPERIMENT_ERROR);
        CHECK(!completed && outgoing_count==packets_before);
        d2k_tls_io io=d2k_experiment_tls_io(channel);
        CHECK(io.context && io.write && io.read);
        if(io.context) {
            uint8_t retained[7];
            d2k_raw_observation delivery;
            CHECK(!d2k_experiment_tls_read_observation(&io,&delivery));
            d2k_tls_io foreign=io;foreign.write=NULL;
            CHECK(!d2k_experiment_tls_read_observation(&foreign,&delivery));
            CHECK(!io.write(io.context,tr.payload,tr.len,err,sizeof err));
            CHECK(outgoing_count==packets_before);
            CHECK(io.read(io.context,retained,sizeof retained,5,err,sizeof err)==7);
            CHECK(d2k_experiment_tls_read_observation(&io,&delivery)==1);
            CHECK(delivery.kind==D2K_RAW_OBS_RESPONSE_BYTES);
            CHECK(!memcmp(retained,alert,sizeof alert));
            CHECK(!io.write(io.context,(const uint8_t *)"next",4,err,sizeof err));
            CHECK(rd32(outgoing[outgoing_count-1]+24)==rd32(outgoing[0]+24)+1+4);
            CHECK((outgoing[outgoing_count-1][32]>>4)==8);
            CHECK(!memcmp(outgoing[outgoing_count-1]+40,outgoing[1]+40,12));
            CHECK(!d2k_experiment_tls_io(channel).context);
        }
        d2k_experiment_close(channel);
    }
    d2k_path_run *path=d2k_path_run_new(&e);
    CHECK(path!=NULL);
    if(path) {
        for(int connection=0;connection<2;connection++) {
            episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
            CHECK(d2k_path_run_step(path,4,err,sizeof err)==1);
            CHECK(d2k_path_run_step(path,0,err,sizeof err)==1);
            CHECK(d2k_path_run_step(path,2,err,sizeof err)==1);
            CHECK(d2k_path_run_step(path,2,err,sizeof err)==1);
            CHECK(d2k_path_run_step(path,0,err,sizeof err)==-1);
            CHECK(d2k_path_run_step(path,5,err,sizeof err)==1);
        }
        size_t count=0;
        const d2k_path_event *history=d2k_path_run_history(path,&count);
        CHECK(count==10);
        uint64_t value=0;int terminal=0;
        CHECK(history[3].sample.conclusive==D2K_SAMPLE_OBSERVED);
        CHECK(d2k_path_run_output(path,history[3].sample.observation,&value,&terminal));
        CHECK(terminal && history[3].sample.observation==history[8].sample.observation);
        CHECK(history[0].sample.operation==4 && history[4].sample.operation==5);
        CHECK(history[5].sample.operation==4 && history[9].sample.operation==5);
        d2k_sample grown[10];
        for(size_t i=0;i<count;i++)CHECK(d2k_path_event_project(&history[i],5,0,&grown[i])==1);
        CHECK(grown[0].operation==5 && grown[4].operation==6);
        CHECK(grown[5].operation==5 && grown[9].operation==6);
        d2k_hypothesis *grown_h=NULL;d2k_transducer grown_model;
        CHECK(d2k_continuous_build(grown,count,7,&grown_h,&grown_model)==1);
        if(grown_h) {
            d2k_transition unseen={0};
            CHECK(grown_model.step(grown_model.ctx,grown_model.initial,4,&unseen)==0);
            d2k_hypothesis_free(grown_h);
        }
        d2k_synthesis_contract target={{NULL,3,0,6,path_protocol_step},path_preserved,
            &value,path_accept_symbol};
        d2k_syn_result proposed;
        size_t packets_before_query=outgoing_count;
        CHECK(d2k_path_run_synthesize(path,&target,&proposed)==1);
        CHECK(proposed.status==D2K_SYN_CANDIDATE);
        CHECK(outgoing_count==packets_before_query);
        d2k_syn_result_free(&proposed);
        target.preserved=path_not_preserved;
        CHECK(d2k_path_run_synthesize(path,&target,&proposed)==1);
        CHECK(proposed.status!=D2K_SYN_CANDIDATE);
        d2k_syn_result_free(&proposed);
        d2k_hypothesis *path_model=NULL;
        d2k_transducer current_path;
        CHECK(d2k_path_run_model(path,&path_model,&current_path)==1);
        if(path_model) {
            d2k_transducer m=d2k_hypothesis_model(path_model);
            size_t state=m.initial;
            for(size_t event=0;event<count;event++) {
                d2k_transition t={0};
                CHECK(m.step(m.ctx,state,history[event].sample.operation,&t)==1);
                CHECK(t.observation==history[event].sample.observation);
                state=t.next;
            }
            CHECK(state==current_path.initial);
            d2k_hypothesis_free(path_model);path_model=NULL;
        }
        target.preserved=path_preserved;
        episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
        CHECK(d2k_path_run_model(path,&path_model,&current_path)==1);
        ambiguous_path alternatives;
        for(size_t i=0;i<5;i++)alternatives.output[i]=history[i].sample.observation;
        CHECK(alternatives.output[2]!=alternatives.output[0]);
        d2k_transducer ambiguous={&alternatives,10,0,6,ambiguous_path_step};
        unsigned char possible[10]={0};
        d2k_path_trial trial=d2k_path_run_trial_belief(path,&ambiguous,possible,&target,err,sizeof err);
        CHECK(trial.status==D2K_TRIAL_ERROR && outgoing_count==0);
        possible[0]=possible[5]=1;
        trial=d2k_path_run_trial_belief(path,&ambiguous,possible,&target,err,sizeof err);
        d2k_hypothesis_free(path_model);path_model=NULL;
        CHECK(trial.status==D2K_TRIAL_OBSERVED_PREDICATE && trial.selection==D2K_SYN_CANDIDATE);
        CHECK(trial.begin==10 && trial.end>trial.begin);
        CHECK(d2k_path_run_step(path,5,err,sizeof err)==1);
        alert[6]=42;episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
        trial=d2k_path_run_trial(path,&target,err,sizeof err);
        CHECK(trial.status==D2K_TRIAL_COUNTEREXAMPLE && trial.selection==D2K_SYN_CANDIDATE);
        CHECK(trial.end>trial.begin && trial.prediction_changed);
        history=d2k_path_run_history(path,&count);
        uint64_t actual_output=0;
        CHECK(d2k_path_run_output(path,history[trial.end-1].sample.observation,&actual_output,&terminal));
        CHECK(actual_output!=value && terminal);
        CHECK(d2k_path_run_model(path,&path_model,&current_path)==1);
        d2k_hypothesis_free(path_model);path_model=NULL;
        alert[6]=40;
        CHECK(d2k_path_run_step(path,5,err,sizeof err)==1);
        size_t before_unknown=0;
        d2k_path_run_history(path,&before_unknown);
        episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
        CHECK(d2k_path_run_step(path,4,err,sizeof err)==1);
        CHECK(d2k_path_run_step(path,0,err,sizeof err)==1);
        payload_recv_error=1;
        CHECK(d2k_path_run_step(path,2,err,sizeof err)==0);
        payload_recv_error=0;
        CHECK(d2k_path_run_step(path,5,err,sizeof err)==1);
        episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
        CHECK(d2k_path_run_step(path,4,err,sizeof err)==1);
        CHECK(d2k_path_run_step(path,5,err,sizeof err)==1);
        history=d2k_path_run_history(path,&count);
        CHECK(count==before_unknown+6 && history[before_unknown+2].sample.conclusive==D2K_SAMPLE_UNKNOWN);
        size_t before_trial=outgoing_count;
        trial=d2k_path_run_trial(path,&target,err,sizeof err);
        CHECK(trial.status==D2K_TRIAL_UNCERTAIN && trial.begin==trial.end);
        CHECK(outgoing_count==before_trial);
        CHECK(d2k_path_run_synthesize(path,&target,&proposed)==0 && !proposed.length);
        CHECK(d2k_path_run_model(path,&path_model,&current_path)==0 && !path_model);
        d2k_alternatives uncertain=d2k_path_run_alternatives(path,NULL);
        CHECK(uncertain.status==D2K_ALTERNATIVES_UNKNOWN && !uncertain.word.length);
        d2k_alternatives_free(&uncertain);
        d2k_input_domain allowed={NULL,3,0,6,path_protocol_step};
        size_t action=SIZE_MAX;
        size_t before=outgoing_count;
        CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_UNCERTAIN);
        CHECK(outgoing_count==before && action==SIZE_MAX);
        CHECK(d2k_path_run_interrupt(path)==1);
        CHECK(outgoing_count==before);
        d2k_state_question old_question=d2k_path_run_relocate(path,&allowed);
        CHECK(old_question.status==D2K_QUESTION_UNKNOWN);
        d2k_state_question_free(&old_question);
        history=d2k_path_run_history(path,&count);
        CHECK(count==before_unknown+6);
        CHECK(d2k_path_run_model(path,&path_model,&current_path)==1);
        d2k_transition unobserved={0};
        CHECK(current_path.step(current_path.ctx,current_path.initial,4,&unobserved)==0);
        d2k_hypothesis_free(path_model);path_model=NULL;
        episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
        CHECK(d2k_path_run_step(path,4,err,sizeof err)==1);
        CHECK(d2k_path_run_interrupt(path)==0);
        history=d2k_path_run_history(path,&count);
        CHECK(history[count-1].interval_start);
        CHECK(history[before_unknown+2].sample.conclusive==D2K_SAMPLE_UNKNOWN);
        CHECK(d2k_path_run_step(path,5,err,sizeof err)==1);
        CHECK(d2k_path_run_model(path,&path_model,&current_path)==1);
        d2k_hypothesis_free(path_model);
        d2k_path_run_free(path);
        path=d2k_path_run_new(&e);CHECK(path!=NULL);
        if(path) {
            for(int i=0;i<2;i++) {
                episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
                CHECK(d2k_path_run_step(path,4,err,sizeof err)==1);
                CHECK(d2k_path_run_step(path,0,err,sizeof err)==1);
                CHECK(d2k_path_run_step(path,2,err,sizeof err)==1);
                CHECK(d2k_path_run_step(path,2,err,sizeof err)==1);
                CHECK(d2k_path_run_step(path,5,err,sizeof err)==1);
            }
            CHECK(d2k_path_run_interrupt(path)==1);
            before=outgoing_count;
            old_question=d2k_path_run_relocate(path,&allowed);
            /* Closed local context already locates this learned fixture;
               no extra state-distinguishing probe is justified. */
            CHECK(!old_question.word.length);
            CHECK(outgoing_count==before);
            CHECK(d2k_path_run_interrupt(path)==1);
            d2k_state_question repeated=d2k_path_run_relocate(path,&allowed);
            CHECK(repeated.status==old_question.status && repeated.word.length==old_question.word.length);
            if(repeated.word.length && repeated.word.length==old_question.word.length)
                CHECK(!memcmp(repeated.word.operations,old_question.word.operations,
                              repeated.word.length*sizeof *repeated.word.operations));
            CHECK(outgoing_count==before);
            d2k_state_question_free(&repeated);
            d2k_state_question_free(&old_question);
            episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
            trial=d2k_path_run_trial(path,&target,err,sizeof err);
            CHECK(trial.reused_model && trial.selection==D2K_SYN_CANDIDATE);
            CHECK(trial.status==D2K_TRIAL_OBSERVED_PREDICATE);
            d2k_path_run_free(path);
        }
    }
    path=d2k_path_run_new(&e);
    CHECK(path!=NULL);
    if(path) {
        episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
        d2k_input_domain allowed={NULL,3,0,6,path_protocol_step};
        size_t action=SIZE_MAX;
        allowed.initial=1;
        CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_NO_QUESTION);
        CHECK(action==SIZE_MAX && outgoing_count==0);
        allowed.initial=0;
        CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_ADVANCED);
        CHECK(action==4 && outgoing_count==2);
        allowed.initial=1;
        CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_ADVANCED);
        CHECK(action==0 && outgoing_count==4);
        allowed.initial=2;
        CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_ADVANCED);
        CHECK(action==2);
        CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_ADVANCED);
        CHECK(action==2);
        size_t before=outgoing_count;
        allowed.initial=1;
        CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_NO_QUESTION);
        CHECK(action==SIZE_MAX && outgoing_count==before);
        allowed.initial=2;
        CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_ADVANCED);
        CHECK(action==5 && outgoing_count==before);
        d2k_path_run_free(path);
    }
    for(int pending_case=0;pending_case<3;pending_case++) {
        path=d2k_path_run_new(&e);
        CHECK(path!=NULL);if(!path)continue;
        episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
        CHECK(d2k_path_run_step(path,4,err,sizeof err)==1);
        /* Seed a two-step question to isolate executor retention from the
           separately tested model/pair selector. Prefix predicts SEND=0. */
        path->pending.operations=malloc(2*sizeof(size_t));
        path->pending_prefix=malloc(sizeof(uint64_t));
        CHECK(path->pending.operations && path->pending_prefix);
        if(!path->pending.operations || !path->pending_prefix) {
            d2k_path_run_free(path);continue;
        }
        path->pending.length=2;
        path->pending.operations[0]=0;path->pending.operations[1]=2;
        path->pending_prefix[0]=pending_case==1?UINT64_MAX:0;
        path->pending_count=path->count;
        d2k_input_domain allowed={NULL,3,1,6,path_protocol_step};
        size_t action=SIZE_MAX;
        CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_ADVANCED);
        CHECK(action==0 && outgoing_count==4);
        if(pending_case==1) CHECK(!path->pending.length);
        else CHECK(path->pending.length==2 && path->pending_at==1);
        if(pending_case==0) {
            allowed.initial=2;
            CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_ADVANCED);
            CHECK(action==2 && !path->pending.length);
        } else if(pending_case==2) {
            CHECK(d2k_path_run_step(path,5,err,sizeof err)==1);
            allowed.initial=0;dial_recv_fd=-1;outgoing_count=0;
            CHECK(d2k_path_run_advance(path,&allowed,&action,err,sizeof err)==D2K_PATH_ADVANCED);
            CHECK(action==4);
        }
        d2k_path_run_free(path);
    }
    for(int repeat=0;repeat<2;repeat++) {
        episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
        CHECK(d2k_experiment_run(&e,tls_word,4,tls_samples,&completed,&last,err,sizeof err)
              ==D2K_EXPERIMENT_TERMINAL);
        CHECK(completed==3 && !tls_samples[3].conclusive && outgoing_count==6);
        d2k_tls_response response;int timeout,reset;
        CHECK(d2k_tls_symbol_read(tls_samples[1].observation,&response,&timeout,&reset)==1);
        CHECK(response.kind==D2K_TLS_OBS_MORE && !timeout && !reset);
        CHECK(d2k_tls_symbol_read(tls_samples[2].observation,&response,&timeout,&reset)==1);
        CHECK(response.kind==D2K_TLS_OBS_ALERT && response.alert_description==40 && !timeout && !reset);
        CHECK(d2k_evidence_add(evidence,context,sizeof context,tls_samples,completed)==D2K_EVIDENCE_OK);
    }
    d2k_hypothesis *learned=NULL;
    CHECK(d2k_evidence_generalize(evidence,&learned)==1 && learned);
    if(learned) {
        d2k_transducer model=d2k_hypothesis_model(learned);size_t state=model.initial;
        for(size_t i=0;i<completed;i++) {
            d2k_transition transition={0};
            CHECK(model.step(model.ctx,state,tls_samples[i].operation,&transition)==tls_samples[i].conclusive);
            CHECK(transition.observation==tls_samples[i].observation);state=transition.next;
        }
        d2k_hypothesis_free(learned);learned=NULL;
    }
    /* A changed answer to the identical word invalidates deterministic
       learning under this context; it must not silently replace evidence. */
    alert[6]=42;episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
    CHECK(d2k_experiment_run(&e,tls_word,4,tls_samples,&completed,&last,err,sizeof err)
          ==D2K_EXPERIMENT_TERMINAL);
    CHECK(d2k_evidence_add(evidence,context,sizeof context,tls_samples,completed)==D2K_EVIDENCE_CONFLICT);
    CHECK(d2k_evidence_generalize(evidence,&learned)==0 && !learned);
    d2k_evidence_free(evidence);
    /* Now let the learner generate every word; no prewritten word list. */
    alert[6]=40;e.operation_count=3;
    d2k_input_domain domain=d2k_first_response_domain(&e);
    const char learning_context[]="mock peer/resettable/TLS initial response/domain-v1";
    d2k_learner *learner=d2k_learner_new_in(learning_context,sizeof learning_context,
                                         e.operation_count,&domain);
    CHECK(learner!=NULL);
    if(learner) {
        d2k_learning_question question;
        for(size_t round=1;round<=3;round++) {
            CHECK(d2k_learner_next(learner,&question)==D2K_L_QUESTION);
            CHECK(question.length==round && question.operations[0]==0);
            for(size_t i=1;i<question.length;i++)CHECK(question.operations[i]==2);
            episode_reply_at=0;outgoing_count=0;dial_recv_fd=-1;
            d2k_sample *trace=calloc(question.length,sizeof *trace);CHECK(trace!=NULL);
            if(!trace)break;
            int rc=d2k_experiment_run(&e,question.operations,question.length,trace,
                                      &completed,&last,err,sizeof err);
            CHECK(rc==(round==3?D2K_EXPERIMENT_TERMINAL:D2K_EXPERIMENT_COMPLETE));
            CHECK(d2k_learner_submit(learner,question.generation,learning_context,
                sizeof learning_context,trace,completed)==D2K_L_OBSERVED);
            free(trace);
        }
        CHECK(d2k_learner_next(learner,&question)==D2K_L_CLOSED);
        d2k_learner_free(learner);
    }
    episode_reply=NULL;d2k_tls_decoder_free(&tls);
}

static void test_plan_rejection_has_error(void) {
    d2k_trigger tr = {0};
    d2k_poison p = {0};
    char err[160] = "sentinel";
    tr.len = 675;
    strcpy(p.name, "invalid-decoy");
    outgoing_count = 0; pending_delay = 0;
    p.tcp_ts = 1; p.decoy_hello = 1; p.repeats = 8; p.split_pos = 2;
    p.decoy_len = D2K_ARM_DECOY_MAX + 1;
    CHECK(d2k_raw_probe_poison((uint8_t[]){198,51,100,7}, 443, &tr, &p, 100, 0, NULL, err, sizeof err) == -1);
    CHECK(err[0] && strcmp(err, "sentinel"));
    strcpy(err, "sentinel"); p.decoy_len = 1; p.decoy = NULL;
    outgoing_count = 0; pending_delay = 0;
    CHECK(d2k_raw_probe_poison((uint8_t[]){198,51,100,7}, 443, &tr, &p, 100, 0, NULL, err, sizeof err) == -1);
    CHECK(err[0] && strcmp(err, "sentinel"));
}

/* A handshake timeout is distinguishable from a local runtime failure and
 * must escape both public entry points without sending any trigger. */
static void test_connect_timeout_is_not_a_trigger_result(void) {
    d2k_raw_observation observed;
    d2k_trigger tr = {0}; d2k_poison poison = {0};
    tr.payload[0] = 1; tr.payload[1] = 2; tr.len = 2;
    poison.split_pos = 1;
    d2k_raw_rule_hook = test_rule_hook;
    rule_rc = 0; dial_silent = EAGAIN;
    for (int family = 4; family <= 6; family += 2) {
        uint8_t ip[16] = {198, 51, 100, 1}; char err[160] = "";
        if (family == 6) { memset(ip, 0, sizeof ip); ip[0] = 0x20; ip[1] = 1; ip[15] = 1; }
        outgoing_count = 0; dial_recv_fd = -1;
        CHECK(d2k_raw_probe_handshake_family(ip, (uint8_t)family, 443, 1, 0x2d,
              NULL, err, sizeof err) == -2);
        CHECK(outgoing_count == 1);
        outgoing_count = 0; dial_recv_fd = -1;
        CHECK(d2k_raw_probe_observed(ip, (uint8_t)family, 443, &tr, &poison,
              1, 0x2d, NULL, err, sizeof err, &observed) == -2);
        CHECK(outgoing_count == 1);
        CHECK(observed.kind == D2K_RAW_OBS_CONNECT_TIMEOUT && !observed.connected && !observed.sent);
        dial_silent = EIO;
        outgoing_count = 0; dial_recv_fd = -1;
        CHECK(d2k_raw_probe_observed(ip, (uint8_t)family, 443, &tr, &poison,
              1, 0x2d, NULL, err, sizeof err, &observed) == -1);
        CHECK(outgoing_count == 1);
        CHECK(observed.kind == D2K_RAW_OBS_LOCAL && !observed.connected && !observed.sent);
        dial_silent = 0; payload_recv_error = 1; strcpy(poison.name, "none");
        outgoing_count = 0; dial_recv_fd = -1;
        CHECK(d2k_raw_probe_observed(ip, (uint8_t)family, 443, &tr, &poison,
              5, 0x2d, NULL, err, sizeof err, &observed) == -1);
        CHECK(outgoing_count >= 3);
        CHECK(observed.kind == D2K_RAW_OBS_LOCAL && observed.connected && observed.sent);
        payload_recv_error = 0; dial_silent = EAGAIN;
    }
    dial_silent = 0;
}

/* Поле 15.10.2026, flibusta.is: путь до сервера эпизодами теряет SYN
 * (17-19 % и до половины в эпизоде около минуты; от триггера не зависит —
 * 10 циклов с контролем). Сырой зонд слал SYN ОДИН раз и ждал весь срок:
 * каждая потеря становилась «SYN-ACK не пришёл», и замер бросался — до
 * отравления меткой времени, которым флибуста открывается, он не доходил ни
 * разу. TCP ядра (и браузер) повторяют SYN по RFC 6298: через 1 с, затем
 * удваивая. Сырой стек обязан вести себя так же, тем же номером. */
/* A failed OPEN is not a measured negative application response. */
static void test_synthesis_open_timeout(void) {
    d2k_raw_rule_hook=test_rule_hook;rule_rc=0;dial_silent=EAGAIN;
    outgoing_count=0;dial_recv_fd=-1;payload_recv_error=0;
    d2k_trigger tr={0};tr.len=6;memcpy(tr.payload,"abcdef",6);
    size_t whole=6;d2k_tls_stream stream={&tr,&whole,1,5,1};
    uint8_t reply[128];d2k_experiment e={.ip={198,51,100,7},.family=4,.port=443,
        .connect_ms=5,.reply=reply,.reply_capacity=sizeof reply};
    d2k_tls_path_session *w=d2k_tls_path_session_new_response(&stream,&e,177);
    CHECK(w!=NULL);
    if(w) {
        d2k_vres out;CHECK(d2k_tls_path_session_next(w,&out)==D2K_SYN_ERROR);
        size_t count=0;const d2k_path_event *history=d2k_tls_path_session_history(w,&count);
        CHECK(count==1 && history[0].action.kind==D2K_PATH_ACTION_OPEN &&
            history[0].raw.kind==D2K_RAW_OBS_CONNECT_TIMEOUT);
        CHECK(out.verdict==D2K_V_FLAKY && out.dial_deadline==1);
        CHECK(!out.program_len && !out.protocol_response);
        CHECK(d2k_tls_path_session_next(w,&out)==D2K_SYN_ERROR);
        CHECK(out.verdict==D2K_V_FLAKY && out.dial_deadline==1);
        d2k_tls_path_session_free(w);
    }
    dial_silent=0;
}

static void test_lost_syn_is_retransmitted(void) {
    d2k_raw_rule_hook = test_rule_hook;
    rule_rc = 0; dial_silent = 0; payload_recv_error = 0;
    uint8_t ip[16] = {198, 51, 100, 1}; char err[160] = "";
    outgoing_count = 0; dial_recv_fd = -1; dial_drop_syns = 1;
    int rc = d2k_raw_probe_handshake_family(ip, 4, 443, 2500, 0x2d, NULL, err, sizeof err);
    CHECK(rc == 1);
    CHECK(outgoing_count >= 2);
    if (outgoing_count >= 2) {
        CHECK((outgoing[0][33] & (TCP_SYN | TCP_ACK)) == TCP_SYN);
        CHECK((outgoing[1][33] & (TCP_SYN | TCP_ACK)) == TCP_SYN);
        CHECK(rd32(outgoing[0] + 24) == rd32(outgoing[1] + 24));
    }
    /* Короткий срок — повтора нет: RTO начинается с секунды. */
    outgoing_count = 0; dial_recv_fd = -1; dial_drop_syns = 1;
    CHECK(d2k_raw_probe_handshake_family(ip, 4, 443, 300, 0x2d, NULL, err, sizeof err) == -2);
    CHECK(outgoing_count == 1);
    dial_drop_syns = 0;
}

/* ЗАМЫСЕЛ 2026-10-23, п. 5.1: ЗОНД ЗДОРОВАЕТСЯ НАБОРОМ ОПЦИЙ КЛИЕНТА.
 * Поле issue #7 (22.10.2026): план с меткой времени подтверждён зондом, у
 * которого метка в SYN стояла литералом, а ПК репортёра метку не предлагает —
 * план ему не исполняется. Зонд обязан предлагать метку только тогда, когда её
 * несёт клиент, чьё приветствие он повторяет; набор не снят — прежний набор. */
static int tcp_has_ts(const uint8_t *pkt) {
    size_t ihl = (size_t)(pkt[0] & 15) * 4;
    const uint8_t *t = pkt + ihl;
    size_t hlen = (size_t)(t[12] >> 4) * 4;
    for (size_t off = 20; off < hlen;) {
        uint8_t kind = t[off];
        if (!kind) break;
        if (kind == 1) { off++; continue; }
        if (off + 2 > hlen || t[off + 1] < 2 || t[off + 1] > hlen - off) break;
        if (kind == 8 && t[off + 1] == 10) return 1;
        off += t[off + 1];
    }
    return 0;
}
static void test_syn_follows_client_tcp_profile(void) {
    d2k_raw_rule_hook = test_rule_hook;
    rule_rc = 0; dial_silent = 0; payload_recv_error = 0; dial_drop_syns = 0;
    uint8_t ip[16] = {198, 51, 100, 1}; char err[160] = "";
    d2k_trigger tr; memset(&tr, 0, sizeof tr);
    static const uint8_t rec[] = {0x16, 0x03, 0x01, 0x00, 0x03, 1, 2, 3};
    memcpy(tr.payload, rec, sizeof rec); tr.len = sizeof rec; tr.accept = D2K_ACCEPT_ANY;
    d2k_poison none; memset(&none, 0, sizeof none); snprintf(none.name, sizeof none.name, "none");

    /* Клиент без метки времени (ПК репортёра): SYN без метки, данные без опций. */
    tr.client_tcp_known = 1; tr.client_tcp_options_len = 0;
    peer_timestamps = 0; outgoing_count = 0; dial_recv_fd = -1;
    (void)d2k_raw_probe_poison_family(ip, 4, 443, &tr, &none, 2500, 0x2d, NULL, err, sizeof err);
    CHECK(outgoing_count >= 3);
    if (outgoing_count >= 3) {
        CHECK((outgoing[0][33] & (TCP_SYN | TCP_ACK)) == TCP_SYN);
        CHECK(!tcp_has_ts(outgoing[0]));
        CHECK(((outgoing[0][32] >> 4) * 4) % 4 == 0 && (outgoing[0][32] >> 4) >= 5);
        CHECK(!tcp_has_ts(outgoing[2]) && (outgoing[2][32] >> 4) == 5);
    }
    CHECK(!d2k_trigger_offers_ts(&tr));
    /* Клиент с меткой (NOP NOP TS в данных): SYN предлагает метку. */
    memcpy(tr.client_tcp_options, (uint8_t[]){1, 1, 8, 10, 0, 1, 2, 3, 0, 0, 0, 0}, 12);
    tr.client_tcp_options_len = 12;
    peer_timestamps = 1; outgoing_count = 0; dial_recv_fd = -1;
    (void)d2k_raw_probe_poison_family(ip, 4, 443, &tr, &none, 2500, 0x2d, NULL, err, sizeof err);
    CHECK(outgoing_count >= 3);
    if (outgoing_count >= 3) { CHECK(tcp_has_ts(outgoing[0])); }
    CHECK(d2k_trigger_offers_ts(&tr));
    /* Набор не снят: прежний набор, с меткой. */
    tr.client_tcp_known = 0; tr.client_tcp_options_len = 0;
    outgoing_count = 0; dial_recv_fd = -1;
    (void)d2k_raw_probe_poison_family(ip, 4, 443, &tr, &none, 2500, 0x2d, NULL, err, sizeof err);
    CHECK(outgoing_count >= 1 && tcp_has_ts(outgoing[0]));
    CHECK(d2k_trigger_offers_ts(&tr));
    /* Приём «метка времени назад» клиенту без метки не задаётся. */
    d2k_poison ts; memset(&ts, 0, sizeof ts); ts.tcp_ts = 1;
    tr.client_tcp_known = 1; tr.client_tcp_options_len = 0;
    CHECK(!d2k_trigger_allows_poison(&tr, &ts) && d2k_trigger_allows_poison(&tr, &none));
    tr.client_tcp_known = 0;
    CHECK(d2k_trigger_allows_poison(&tr, &ts));

    /* НАБОР ОПЦИЙ КЛИЕНТА НЕ СНЯТ — СПРАШИВАЕМ СВОЙ СТЕК, А НЕ УГАДЫВАЕМ.
     *
     * Поле 23.10.2026 (`cand-32e84f2-nots-1`, rutracker.org 16:31:44):
     * составной вопрос семейства C прошёл 2/2, план из него построен, и его
     * отверг датапат причиной 6 — испытательный поток зонда идёт обычным
     * сокетом и метку не несёт, потому что её нет у локального стека.
     * Ответ «метка есть» при неизвестном клиенте был догадкой, и она стоила
     * цели всех её планов: «выведенные планы исчерпаны (зондов 1)».
     *
     * Правило: клиент известен — решает он; не известен — решает стек, чьим
     * сокетом зонд и пойдёт. На роутере с включённой меткой это то же самое,
     * что прежде, поэтому обычный случай не меняется. */
    tr.client_tcp_known = 0; tr.client_tcp_options_len = 0;
    d2k_trigger_host_ts_override(0);
    CHECK(!d2k_trigger_offers_ts(&tr)); /* стек без метки, клиент не известен */
    CHECK(!d2k_trigger_allows_poison(&tr, &ts)); /* приём с меткой не задаётся */
    d2k_trigger_host_ts_override(1);
    CHECK(d2k_trigger_offers_ts(&tr)); /* стек с меткой — как прежде */
    CHECK(d2k_trigger_allows_poison(&tr, &ts)); /* приём доступен */
    /* Известный клиент сильнее стека: он и есть тот, для кого мы мерим. */
    tr.client_tcp_known = 1; tr.client_tcp_options_len = 0;
    d2k_trigger_host_ts_override(1);
    CHECK(!d2k_trigger_offers_ts(&tr)); /* клиент сильнее стека */
    d2k_trigger_host_ts_override(-1);
    peer_timestamps = 1;
}

/* These exercise the real episode sender; only OS socket/rule boundaries
 * are replaced. Literal header expectations catch lost shape parameters. */
static int shaped_rule_hook(const char *cmd)
{
    const char *s = strstr(cmd, "--sport ");
    if (!s) return 0;
    unsigned port = (unsigned)strtoul(s + 8, NULL, 10);
    CHECK(port <= 65535);
    if (port > 65535) return 2 << 8;
    if (strstr(cmd, " -I ")) {
        if (shape_insert_fail) return 3 << 8;
        shape_rules[port]++;
    } else if (strstr(cmd, " -D ")) {
        if (shape_delete_fail) return 2 << 8;
        CHECK(shape_rules[port] == 1);
        if (shape_rules[port]) shape_rules[port]--;
    } else if (strstr(cmd, " -C ")) return shape_rules[port] ? 0 : 1 << 8;
    return 0;
}
static d2k_raw_episode *shaped_open(const d2k_raw_shape *shape, int ts)
{
    char err[200] = "";
    outgoing_count = 0; dial_recv_fd = -1;
    dial_silent = payload_silent = payload_recv_error = 0;
    episode_reply = NULL; peer_timestamps = 1;
    d2k_raw_rule_hook = shaped_rule_hook;
    return d2k_raw_episode_open_shaped((uint8_t[]){198,51,100,7},4,443,
        100,0,ts,shape,NULL,err,sizeof err,NULL);
}
static void shaped_send(d2k_raw_episode *ep)
{
    char err[200]; d2k_trigger tr = {0};
    memcpy(tr.payload, "test", 4); tr.len = 4;
    CHECK(d2k_raw_episode_send(ep,0,4,&tr,"d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n",NULL,err,sizeof err,NULL) == 0);
}
static void test_shaped_syn_carries_window_and_scale(void)
{
    for (int ts = 0; ts <= 1; ts++) {
        d2k_raw_shape shape = {.syn_window=1,.syn_wscale=1};
        d2k_raw_episode *ep = shaped_open(&shape,ts);
        CHECK(ep != NULL);
        if (!ep) continue;
        CHECK(rd16(outgoing[0]+34) == 1);
        static const uint8_t plain[] = {2,4,5,172,1,3,3,1,1,1,4,2};
        static const uint8_t timed[] = {2,4,5,172,4,2,8,10,0,0,0,1,0,0,0,0,1,3,3,1};
        CHECK(outgoing_len[0] == (ts ? 60u : 52u));
        CHECK(!memcmp(outgoing[0]+40,ts ? timed : plain,ts ? sizeof timed : sizeof plain));
        CHECK(d2k_wire_tcp_checksum_ok(outgoing[0],outgoing_len[0]));
        d2k_raw_episode_free(ep);
    }
}
static void test_shaped_sport_is_used(void)
{
    d2k_raw_shape shape = {.sport=41234,.syn_wscale=-1};
    d2k_raw_episode *ep = shaped_open(&shape,1);
    CHECK(ep != NULL);
    if (!ep) return;
    shaped_send(ep);
    for (size_t i=0;i<outgoing_count;i++) CHECK(rd16(outgoing[i]+20) == 41234);
    CHECK(outgoing[0][59] == 7 && rd16(outgoing[0]+34) == 65535);
    size_t sent = outgoing_count;
    char err[200];
    d2k_raw_episode *other = d2k_raw_episode_open_shaped((uint8_t[]){198,51,100,8},4,443,
        100,0,1,&shape,NULL,err,sizeof err,NULL);
    CHECK(other == NULL && outgoing_count == sent);
    d2k_raw_episode_free(other);
    d2k_raw_episode_free(ep);
}
static void test_data_window_in_acks(void)
{
    d2k_raw_shape shape = {.data_window=1,.syn_wscale=0};
    d2k_raw_episode *ep = shaped_open(&shape,1);
    CHECK(ep != NULL);
    if (!ep) return;
    CHECK(outgoing[0][59] == 0);
    CHECK(rd16(outgoing[1]+34) == 1);
    shaped_send(ep);
    CHECK(rd16(outgoing[2]+34) == 1);
    static const uint8_t reply[] = {1,2,3,4};
    episode_reply=reply;episode_reply_len=4;episode_reply_at=0;episode_reply_chunk=2;
    uint8_t buf[16]; d2k_raw_packet_event event;
    CHECK(d2k_raw_episode_event(ep,100,NULL,buf,sizeof buf,&event,NULL) == 0);
    CHECK(event.payload_len == 2 && rd16(outgoing[outgoing_count-1]+34) == 1);
    CHECK(d2k_raw_episode_set_window(ep,32) == 0);
    CHECK(d2k_raw_episode_event(ep,100,NULL,buf,sizeof buf,&event,NULL) == 0);
    CHECK(event.payload_len == 2 && rd16(outgoing[outgoing_count-1]+34) == 32);
    for (size_t i=0;i<outgoing_count;i++) CHECK(d2k_wire_tcp_checksum_ok(outgoing[i],outgoing_len[i]));
    episode_reply=NULL; d2k_raw_episode_free(ep);
}
static void test_explicit_rst_leaves_wire(void)
{
    d2k_raw_shape shape = {.sport=41234,.syn_wscale=-1};
    d2k_raw_episode *ep = shaped_open(&shape,1);
    CHECK(ep != NULL);
    if (!ep) return;
    shaped_send(ep);
    payload_ack=1;
    uint8_t buf[16];d2k_raw_packet_event event;d2k_raw_observation observed;
    CHECK(d2k_raw_episode_event(ep,100,NULL,buf,sizeof buf,&event,&observed) == 0);
    CHECK(event.ack_in_sent_range && observed.transport.acked_end == 4);
    payload_ack=0;
    CHECK(shape_rules[41234] == 1);
    uint32_t end = rd32(outgoing[0]+24)+1+observed.transport.acked_end;
    shape_track=1;shape_rst_seen=shape_rst_blocked=0;
    CHECK(d2k_raw_episode_reset(ep) == 0);
    CHECK(shape_rst_seen == 1 && shape_rst_blocked == 0);
    CHECK(outgoing[outgoing_count-1][33] == TCP_RST);
    CHECK(rd32(outgoing[outgoing_count-1]+24) == end);
    CHECK(d2k_wire_tcp_checksum_ok(outgoing[outgoing_count-1],outgoing_len[outgoing_count-1]));
    CHECK(d2k_raw_episode_reset(ep) == -1);
    shape_track=0;d2k_raw_episode_free(ep);
}
static void test_same_sport_twice_after_rst(void)
{
    d2k_raw_shape shape = {.sport=41234,.syn_wscale=-1};
    d2k_raw_episode *first = shaped_open(&shape,1);
    CHECK(first != NULL);
    if (!first) return;
    CHECK(d2k_raw_episode_reset(first) == 0);
    d2k_raw_episode *second = shaped_open(&shape,1);
    CHECK(second != NULL);
    CHECK(rd16(outgoing[0]+20) == 41234);
    d2k_raw_episode_free(first);
    CHECK(shape_rules[41234] == 1);
    d2k_raw_episode_free(second);
    CHECK(shape_rules[41234] == 0);
}
static void test_shaped_reset_failure_cleanup(void)
{
    for (int mode=0;mode<3;mode++) {
        d2k_raw_shape shape = {.sport=41234,.syn_wscale=-1};
        d2k_raw_episode *ep=shaped_open(&shape,1);
        CHECK(ep != NULL); if(!ep) continue;
        size_t before=outgoing_count;
        shape_track=1;shape_rst_seen=shape_rst_blocked=0;
        if(mode==0) shape_delete_fail=1;
        if(mode==1) fail_send_at=outgoing_count;
        if(mode==2) shape_insert_fail=1;
        CHECK(d2k_raw_episode_reset(ep) == -1);
        CHECK(shape_rst_blocked == 0);
        if(mode<2) CHECK(outgoing_count == before);
        shape_delete_fail=shape_insert_fail=0;fail_send_at=0;shape_track=0;
        d2k_raw_episode_free(ep);d2k_raw_flush_pending();
        CHECK(shape_rules[41234] == 0 && d2k_raw_pending_count() == 0);
    }
    CHECK(d2k_raw_episode_reset(NULL) == -1);
    CHECK(d2k_raw_episode_set_window(NULL,32) == -1);
}
#define RUN_SHAPED(test) do { int before=failures; test(); \
    printf("%s: %s\n", #test, before==failures ? "PASS" : "FAIL"); } while(0)

int main(void)
{
    RUN_SHAPED(test_shaped_syn_carries_window_and_scale);
    RUN_SHAPED(test_shaped_sport_is_used);
    RUN_SHAPED(test_data_window_in_acks);
    RUN_SHAPED(test_explicit_rst_leaves_wire);
    RUN_SHAPED(test_same_sport_twice_after_rst);
    RUN_SHAPED(test_shaped_reset_failure_cleanup);
    d2k_raw_rule_hook=test_rule_hook;
    {
        uint8_t src[16] = {0x20, 1}, dst[16] = {0x20, 1};
        src[15] = 1; dst[15] = 2;
        uint8_t packet[256], body[] = {1, 2, 3};
        d2k_poison p = {0};
        size_t n = build_ip_tcp(packet, sizeof packet, 6, src, dst, 1000, 443,
                                42, 43, TCP_ACK, body, sizeof body, &p, NULL, 0);
        CHECK(n == 63 && packet[0] == 0x60 && packet[6] == 6);
        CHECK(memcmp(packet + 8, src, 16) == 0 && memcmp(packet + 24, dst, 16) == 0);
        CHECK(d2k_wire_tcp_checksum_ok(packet, n));
        raw_conn conn = {0};
        conn.family = 6; conn.recv_fd = 0; conn.sport = 443; conn.dport = 1000;
        conn.buffers = malloc(sizeof *conn.buffers);
        CHECK(conn.buffers != NULL);
        if (!conn.buffers) return 1;
        memcpy(conn.dst, src, 16);
        memcpy(incoming_src[0], src, 16);
        memcpy(incoming[0], packet + 40, n - 40); incoming_len[0] = n - 40;
        uint8_t flags;
        uint32_t seq, ack;
        const uint8_t *received = NULL;
        size_t received_len = 0;
        CHECK(raw_recv(&conn, &flags, &seq, &ack, &received, &received_len, d2k_now_ms() + 1000, NULL) == 0);
        CHECK(flags == TCP_ACK && seq == 42 && ack == 43);
        CHECK(received_len == sizeof body && memcmp(received, body, sizeof body) == 0);
        free(conn.buffers);
        p.badsum = 1;
        n = build_ip_tcp(packet, sizeof packet, 6, src, dst, 1000, 443,
                         42, 43, TCP_ACK, body, sizeof body, &p, NULL, 0);
        CHECK(n == 63 && !d2k_wire_tcp_checksum_ok(packet, n));
        p.ip_id_zero = 1;
        CHECK(build_ip_tcp(packet, sizeof packet, 6, src, dst, 1000, 443,
                            42, 43, TCP_ACK, body, sizeof body, &p, NULL, 0) == 0);
    }
    {
        static const size_t sizes[] = {675, 1400, 1401, 2048, 2049, D2K_TRIGGER_MAX};
        int count = 0;
        const d2k_poison *ps = d2k_poisons(&count);
        for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
            for (uint8_t family = 4; family <= 6; family += 2) {
                test_runtime_equals_datapath(NULL, sizes[k], family);
                d2k_poison split = {0};
                strcpy(split.name, "tcp-split"); split.split_pos = 1; split.gap_ms = 12;
                test_runtime_equals_datapath(&split, sizes[k], family);
                for (int i = 0; i < count; i++) {
                    if (!ps[i].syn_data && d2k_poison_supports_family(&ps[i], family))
                        test_runtime_equals_datapath(&ps[i], sizes[k], family);
                }
            }
        }
        peer_timestamps = 0;
        test_runtime_equals_datapath(NULL, 675, 4);
        test_runtime_equals_datapath(NULL, 675, 6);
        d2k_poison md5ts = {0};
        strcpy(md5ts.name, "md5ts"); md5ts.md5_ts = 1;
        test_runtime_equals_datapath(&md5ts, 675, 4);
        test_runtime_equals_datapath(&md5ts, 675, 6);
        peer_timestamps = 1;
        test_runtime_equals_datapath(&md5ts, 675, 4);
        test_runtime_equals_datapath(&md5ts, 675, 6);
        printf("runtime equality: family C + %d catalog hypotheses, 6 lengths, IPv4/IPv6, complete packets and delays\n", count - 1);
    }
    test_connect_timeout_is_not_a_trigger_result();
    test_synthesis_open_timeout();
    test_lost_syn_is_retransmitted();
    test_syn_follows_client_tcp_profile();
    test_generated_program_execution();
    test_prefix_program_export();
    test_reverse_partition_tls_continuation();
    test_episode_preserves_connection();
    test_lowered_partition_wire();
    test_slice_word();
    test_stateful_stream_word();
    test_raw_tls_transport();
    test_raw_tls_late_scope();
    test_raw_tls_prepared();
    test_application_macro();
    test_application_prefix_extension();
    test_application_worker();
    test_application_mixed_order();
    test_experiment_tls_continuation();
    test_learning_session_context();
    test_learning_candidate_result();
    test_learning_worker_stops();
    test_learning_worker_direct();
    test_retained_continuous_session();
    test_continuous_worker();
    test_response_worker();
    test_learning_worker_candidate();
    test_learning_reference_guard();
    test_tls_read_deadline();
    test_learning_prepared_counterexample();
    test_transport_progress_bounds();
    test_stale_reset_does_not_abort_reply();
    test_episode_packet_events();
    test_adaptive_stream_channel();
    test_path_candidate_export();
    test_experiment_word();
    test_plan_rejection_has_error();
    test_concurrent_ports_are_unique();
    test_checksum_matches_original();
    test_receive_is_owned_by_connection();
    test_unrelated_packets_do_not_extend_deadline();
    test_reordered_reply_reads_from_stream_start();
    test_negotiated_ack_timestamps();
    test_fragmented_reply_prefix();
    test_reordered_reply_retains_tail();
    test_partial_reply_timeout();
    test_datapath_matches_raw_headers();
    test_disorder_pos2_emits_exact_reverse_segments();
    test_dial_survives_missing_rst_rule();
    test_failed_release_is_retried();
    test_rule_command_is_bounded();
    test_rule_without_comment_module();
    test_rule_through_nft();
    test_rule_lifecycle_has_no_leaks();
    test_rst_failures_are_per_thread();
    test_clock_survives_long_uptime();
    /* Ни одной отложенной записи на выходе: atexit не должен звать iptables. */
    CHECK(d2k_raw_pending_count() == 0);
    d2k_raw_rule_hook = test_rule_hook;
    if (failures) { return 1; }
    puts("raw: checksum, connection-owned receives and concurrent ports passed (no network)");
    return 0;
}
