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
#include "raw.c"
#undef recvfrom
#undef sendto
#undef socket
#undef setsockopt
#undef bind
#undef connect
#undef getsockname
#include <fcntl.h>
#include "d2k_wire.h"

#define WORKERS 16
#define PORTS_PER_WORKER 128
static uint16_t ports[WORKERS][PORTS_PER_WORKER];
static uint8_t incoming[2][128];
static size_t incoming_len[2];
static unsigned incoming_noise;
static uint8_t incoming_src[2][16];
static uint8_t outgoing[4][2048];
static size_t outgoing_len[4];
static size_t outgoing_count;
static int failures;
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "raw:%d: %s\n", __LINE__, #c); failures++; \
} } while (0)

static ssize_t raw_test_sendto(int fd, const void *buf, size_t len, int flags,
                               const struct sockaddr *addr, socklen_t alen)
{
    (void)fd; (void)flags; (void)addr; (void)alen;
    if (outgoing_count >= 4 || len > sizeof outgoing[0]) { return -1; }
    memcpy(outgoing[outgoing_count], buf, len);
    outgoing_len[outgoing_count++] = len;
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
    CHECK(raw_send_disorder_pos(&c, &tr, 1000, 2) == 0);
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
static int raw_test_socket(int domain, int type, int proto)
{
    int fd = open("/dev/null", O_RDONLY);
    (void)domain;
    if (fd >= 0 && type == SOCK_RAW && proto == IPPROTO_TCP) { dial_recv_fd = fd; }
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
    if (fd >= 0 && fd == dial_recv_fd) {
        d2k_poison none = {0};
        const uint8_t *syn = outgoing[0];
        size_t n;
        if (outgoing_count == 0) { return -1; }
        n = build_ipv4_tcp(buf, len, syn + 16, syn + 12, rd16(syn + 22), rd16(syn + 20),
                           7000, rd32(syn + 24) + 1, TCP_SYN | TCP_ACK,
                           NULL, 0, &none, NULL, 0);
        return n ? (ssize_t)n : -1;
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
    CHECK(raw_read_payload(&c, 5, NULL, result, sizeof result, &result_len) == -1);
    CHECK(result_len == 0);
    incoming_noise = 0;
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
    for (unsigned flags = 0; flags < 32; flags++) {
        d2k_poison p = {0}; d2k_emit e = {0}; d2k_conn c = {0};
        p.badsum = !!(flags & 1); p.tcp_ts = !!(flags & 2);
        p.ip_id_zero = !!(flags & 4); p.ttl = flags & 8 ? 8 : 0;
        e.poison = (uint8_t)(flags & 7); e.ttl = (uint8_t)p.ttl;
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
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
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
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
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
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    raw_close(&c);
    CHECK(rule_count == 3 && strstr(rule_cmds[1], " -D OUTPUT") && strstr(rule_cmds[2], " -D OUTPUT"));

    /* Отказ дважды: правило запомнено и снимается перед следующей вставкой. */
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1; del_fail_left = 2;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    uint16_t leaked = c.sport;
    raw_close(&c);
    CHECK(rule_count == 3);
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
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
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    raw_close(&c);
    /* -I, -D (exit 1) и -C, подтвердивший отсутствие (финальное ревью, I2). */
    CHECK(rule_count == 3 && strstr(rule_cmds[2], " -C OUTPUT") != NULL);
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1; del_fail_left = 0;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    CHECK(rule_count == 1 && strstr(rule_cmds[0], " -I OUTPUT") != NULL);
    raw_close(&c);

    /* Прочий отказ повторяется, но ограниченно: после RST_RELEASE_ATTEMPTS
       попыток запись бросается, и вставки больше не тянут за собой -D. */
    del_fail_code = 4 << 8;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1; del_fail_left = 1000;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    raw_close(&c);
    for (int round = 0; round < RST_RELEASE_ATTEMPTS + 2; round++) {
        rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
        CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
        c.rule_up = 0; /* только вставка: смотрим, сколько -D идёт перед ней */
        raw_close(&c);
    }
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
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
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    CHECK(c.rule_up == 0 && m_up == 0);
    CHECK(d2k_raw_rst_fail_count() == f0 + 1);
    CHECK(rule_count == 2 && strstr(rule_cmds[1], " -D OUTPUT") != NULL);
    raw_close(&c);
    CHECK(d2k_raw_pending_count() == pend0);

    /* 2. Убитая вставка без фиксации: -D отвечает exit 1, -C подтверждает
          отсутствие — запись не копится. */
    m_up = 0; m_kill_ins = 1; m_kill_commits = 0;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    CHECK(rule_count == 3 && strstr(rule_cmds[2], " -C OUTPUT") != NULL);
    raw_close(&c);
    CHECK(d2k_raw_pending_count() == pend0 && m_up == 0);

    /* 3. -D отвечает exit 1 по общей ошибке, а правило стоит (-C = 0): на
          слово не верим, запись остаётся в отложенных... */
    m_kill_ins = 0; m_del_generic_left = 2;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
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
            if (raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) != 0) _exit(3);
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
    if (raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0) raw_close(&c);
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
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    CHECK(c.rule_up == 1);
    CHECK(rule_count == 2 && strstr(rule_cmds[0], "--comment") && !strstr(rule_cmds[1], "--comment") &&
          strstr(rule_cmds[1], "-I OUTPUT"));
    raw_close(&c);
    CHECK(rule_count == 3 && strstr(rule_cmds[2], "-D OUTPUT") && !strstr(rule_cmds[2], "--comment"));
    CHECK(d2k_raw_rst_fail_count() == fails0); /* the rule did go in */
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
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
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    sport = c.sport;
    CHECK(c.rule_up == 1 && rule_count == 1);
    snprintf(want, sizeof want, "nft add element inet d2k_rst rst4 { %u timeout 300s }", (unsigned)sport);
    CHECK(strstr(rule_cmds[0], want) != NULL);
    CHECK(strstr(rule_cmds[0], "iptables") == NULL);
    raw_close(&c);
    snprintf(want, sizeof want, "nft delete element inet d2k_rst rst4 { %u }", (unsigned)sport);
    CHECK(rule_count == 2 && strstr(rule_cmds[1], want) != NULL);

    /* Элемент уже истёк: delete отказал, get подтвердил отсутствие — в
       отложенные снятия ничего не попадает. */
    nft_del_rc = 1 << 8;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    raw_close(&c);
    CHECK(rule_count == 3 && strstr(rule_cmds[2], "nft get element inet d2k_rst rst4 { ") != NULL);
    CHECK(d2k_raw_pending_count() == 0);

    /* Вставка отвергнута (нет таблицы): одна попытка, зонд идёт дальше. */
    unsigned long fails0 = d2k_raw_rst_fail_count();
    rule_rc = 1 << 8;
    rule_count = 0; outgoing_count = 0; dial_recv_fd = -1;
    CHECK(raw_dial(&c, dst, 4, 443, 200, 0x2d, NULL, err, sizeof err) == 0);
    CHECK(c.rule_up == 0 && rule_count == 1);
    raw_close(&c);
    CHECK(rule_count == 1);
    CHECK(d2k_raw_rst_fail_count() == fails0 + 1);
    rule_rc = 0;

    /* IPv6 — своё множество. */
    rule_count = 0;
    CHECK(rst_rule_cmd_form("-I", 31000, 6, 1) == 0);
    CHECK(strstr(rule_cmds[0], "nft add element inet d2k_rst rst6 { 31000 timeout 300s }") != NULL);

    CHECK(unsetenv("D2K_FW") == 0);
    d2k_raw_rule_hook = raw_rule_system;
}

int main(void)
{
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
    test_concurrent_ports_are_unique();
    test_checksum_matches_original();
    test_receive_is_owned_by_connection();
    test_unrelated_packets_do_not_extend_deadline();
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
