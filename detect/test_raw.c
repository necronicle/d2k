/* Exercise the actual raw-layer helpers without raw sockets, iptables or
 * network traffic. Only recvfrom is replaced, with two in-memory packets.
 * This runs the helper code on the host; cross/runtime Linux checks remain
 * separate from these deterministic ownership/wire-format assertions. */
#define _DARWIN_C_SOURCE 1
#define D2K_RAW_UNIT_TEST 1
#define recvfrom raw_test_recvfrom
#include "raw.c"
#undef recvfrom

#define WORKERS 16
#define PORTS_PER_WORKER 128
static uint16_t ports[WORKERS][PORTS_PER_WORKER];
static uint8_t incoming[2][128];
static size_t incoming_len[2];
static int failures;
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "raw:%d: %s\n", __LINE__, #c); failures++; \
} } while (0)

ssize_t raw_test_recvfrom(int fd, void *buf, size_t len, int flags,
                         struct sockaddr *addr, socklen_t *alen)
{
    (void)flags; (void)addr; (void)alen;
    if (fd < 0 || fd > 1 || incoming_len[fd] > len) { return -1; }
    memcpy(buf, incoming[fd], incoming_len[fd]);
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
    CHECK(raw_recv(&c[0], &flags, &seq, &ack, &first, &len) == 0 && len == 4);
    CHECK(raw_recv(&c[1], &flags, &seq, &ack, &second, &len) == 0 && len == 4);
    CHECK(first && second && first != second);
    CHECK(first && first[0] == 0xa0); /* must survive the OTHER receive */
    CHECK(second && second[0] == 0xa1);
    for (int i = 0; i < 2; i++) {
        c[i].recv_fd = -1; /* mock identifiers are not owned OS descriptors */
        raw_close(&c[i]);
        CHECK(c[i].buffers == NULL);
    }
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

int main(void)
{
    test_concurrent_ports_are_unique();
    test_checksum_matches_original();
    test_receive_is_owned_by_connection();
    if (failures) { return 1; }
    puts("raw: checksum, connection-owned receives and concurrent ports passed (no network)");
    return 0;
}
