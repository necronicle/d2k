#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_quicconn.h"
#include "d2k_compose_internal.h"

static int hook_called;
static int first_hook(int fd, const uint8_t *p, size_t n, void *u) {
    (void)fd; (void)p; (void)n; (void)u; hook_called++; return 0;
}

int main(void) {
    int server = socket(AF_INET6, SOCK_DGRAM, 0);
    assert(server >= 0);
    struct sockaddr_in6 a = {0};
    a.sin6_family = AF_INET6; a.sin6_addr = in6addr_loopback;
    assert(bind(server, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t len = sizeof a;
    assert(getsockname(server, (struct sockaddr *)&a, &len) == 0);
    int probe = -1;
    uint16_t sport = 0;
    assert(d2k_props_bind_udp_family(6, &probe, &sport) == 0);
    d2k_qc_opts o = {0};
    o.ip = "::1"; o.port = ntohs(a.sin6_port); o.sni = "ipv6.example";
    o.use_fd = probe; o.deadline_ms = 80;
    d2k_qc *c = NULL;
    char err[200];
    /* No responder: transmission is not handshake/application success. */
    assert(d2k_qc_connect(&o, &c, err, sizeof err) != 0 && c == NULL);
    uint8_t packet[2048];
    struct sockaddr_in6 peer = {0};
    len = sizeof peer;
    assert(fcntl(server, F_SETFL, O_NONBLOCK) == 0);
    ssize_t n = recvfrom(server, packet, sizeof packet, 0,
                         (struct sockaddr *)&peer, &len);
    assert(n >= 1200 && (packet[0] & 0xc0) == 0xc0);
    assert(peer.sin6_family == AF_INET6 && peer.sin6_port == sport);
    assert(memcmp(&peer.sin6_addr, &in6addr_loopback, 16) == 0);
    while (recv(server, packet, sizeof packet, 0) > 0) {}
    /* An Initial that cannot be serialized never reaches the peer. It is a
       local refusal, including the first-send hook path, not network evidence. */
    for (int scenario = 0; scenario < 4; scenario++) {
        assert(d2k_props_bind_udp_family(6, &probe, &sport) == 0);
        o.use_fd = probe;
        o.pad_to = scenario < 2 ? 1556 : 4096;
        o.first_send = (scenario & 1) ? first_hook : NULL;
        assert(d2k_qc_connect(&o, &c, err, sizeof err) == -2 && c == NULL);
        assert(hook_called == 0);
        assert(recv(server, packet, sizeof packet, 0) < 0 &&
               (errno == EAGAIN || errno == EWOULDBLOCK));
        assert(fcntl(probe, F_GETFD) == -1 && errno == EBADF);
    }
    close(server);
    puts("QUIC IPv6: Initial sent on reserved native tuple; silence is not success");
    return 0;
}
