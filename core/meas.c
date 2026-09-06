#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"

/* Ждать ответа дольше этого незачем: человек уже ушёл со страницы. */
#define WAIT_CEIL_MS 5000

static void nap_us(uint32_t us) {
    struct timespec ts = { (time_t)(us / 1000000u), (long)(us % 1000000u) * 1000L };
    (void)nanosleep(&ts, NULL);
}

int d2k_meas_once(const char *ip, uint16_t port, d2k_hello h,
                  const size_t *cuts, size_t n_cuts,
                  uint32_t gap_us, uint32_t wait_ms,
                  uint32_t mark, int *marked_out) {
    if (!ip || !h.bytes || h.len == 0) { return -1; }
    if (marked_out) { *marked_out = (mark == 0); }
    if (wait_ms == 0 || wait_ms > WAIT_CEIL_MS) { wait_ms = WAIT_CEIL_MS; }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }

#ifdef SO_MARK
    if (mark != 0) {
        int m = (int)mark;
        if (setsockopt(fd, SOL_SOCKET, SO_MARK, &m, sizeof m) == 0) {
            if (marked_out) { *marked_out = 1; }
        }
    }
#endif
    int one = 1;
    /* Без этого куски склеятся в один сегмент, и опыт про место разреза
       перестанет быть опытом про место разреза. */
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

    struct timeval tv = { (time_t)(wait_ms / 1000u), (suseconds_t)(wait_ms % 1000u) * 1000 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct timeval ctv = { 8, 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &ctv, sizeof ctv);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }

    size_t prev = 0;
    for (size_t i = 0; i <= n_cuts; i++) {
        size_t end = (i < n_cuts) ? cuts[i] : h.len;
        if (end > h.len) { end = h.len; }
        if (end <= prev) { continue; }
        if (send(fd, h.bytes + prev, end - prev, 0) < 0) {
            /* Сброс на записи — это «убито», а не сбой опыта. */
            close(fd);
            return 0;
        }
        prev = end;
        if (prev < h.len && gap_us > 0) { nap_us(gap_us); }
    }

    uint8_t buf[512];
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    close(fd);
    return n > 0 ? 1 : 0;
}

d2k_tally d2k_meas(const char *ip, uint16_t port, d2k_hello h,
                   const size_t *cuts, size_t n_cuts,
                   uint32_t gap_us, uint32_t wait_ms,
                   uint32_t mark, int repeats) {
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    if (repeats <= 0) { repeats = 3; }
    for (int i = 0; i < repeats; i++) {
        int marked = 0;
        int r = d2k_meas_once(ip, port, h, cuts, n_cuts, gap_us, wait_ms, mark, &marked);
        /* Метка серии — И по всем дозвонам: один непомеченный делает серию
           непомеченной. */
        if (!marked) { t.marked = 0; }
        if (r < 0) { t.err++; t.fail++; continue; }
        if (r == 1) { t.pass++; } else { t.fail++; }
    }
    return t;
}
