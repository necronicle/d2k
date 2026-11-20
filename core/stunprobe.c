#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "d2k_stunprobe.h"
#include "d2k_stun.h"
#include "d2k_meas.h"

static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) { return 0; }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int network_error(int error) {
    return error == ECONNREFUSED || error == EHOSTUNREACH ||
           error == ENETUNREACH || error == ECONNRESET;
}

struct d2k_stun_socket {
    int fd, marked;
    uint32_t wait_ms;
};

void d2k_stun_probe_close(d2k_stun_socket *socket) {
    if (!socket) return;
    if (socket->fd >= 0) close(socket->fd);
    free(socket);
}

d2k_stun_socket *d2k_stun_probe_open(const d2k_stun_probe_opt *opt,
    d2k_stun_flow *flow, d2k_stun_probe_res *error_out) {
    d2k_stun_probe_res local;
    d2k_stun_probe_res *r = error_out ? error_out : &local;
    memset(r, 0, sizeof *r);
    r->error = EINVAL;
    if (flow) memset(flow, 0, sizeof *flow);
    if (!opt || !opt->ip || !opt->port || !opt->wait_ms ||
        opt->wait_ms > INT_MAX || !flow) return NULL;
    struct sockaddr_storage peer;
    memset(&peer, 0, sizeof peer);
    struct sockaddr_in *v4 = (void *)&peer;
    struct sockaddr_in6 *v6 = (void *)&peer;
    socklen_t peer_len;
    int af;
    if (inet_pton(AF_INET, opt->ip, &v4->sin_addr) == 1) {
        af = AF_INET;
        v4->sin_family = af;
        v4->sin_port = htons(opt->port);
        peer_len = sizeof *v4;
    } else if (inet_pton(AF_INET6, opt->ip, &v6->sin6_addr) == 1) {
        af = AF_INET6;
        v6->sin6_family = af;
        v6->sin6_port = htons(opt->port);
        peer_len = sizeof *v6;
    } else { return NULL; }


    uint64_t start = now_ms();
    d2k_stun_socket *reserved = calloc(1, sizeof *reserved);
    if (!reserved) { r->error = ENOMEM; return NULL; }
    reserved->fd = socket(af, SOCK_DGRAM, 0);
    reserved->wait_ms = opt->wait_ms;
    int fd = reserved->fd;
    if (fd < 0) { r->error = errno; goto fail; }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        r->error = errno;
        goto fail;
    }
    if (opt->mark) {
        if (d2k_mark_hook(fd, opt->mark)) { r->error = errno; goto fail; }
        reserved->marked = r->marked = 1;
    }
    if (connect(fd, (void *)&peer, peer_len)) {
        r->error = errno;
        if (network_error(r->error)) r->status = D2K_STUN_NETWORK_ERROR;
        goto fail;
    }
    struct sockaddr_storage source;
    socklen_t source_len = sizeof source;
    memset(&source, 0, sizeof source);
    if (getsockname(fd, (void *)&source, &source_len)) { r->error = errno; goto fail; }
    if (source.ss_family != af) { r->error = EAFNOSUPPORT; goto fail; }
    if (af == AF_INET) {
        const struct sockaddr_in *v = (const void *)&source;
        flow->family = 4;
        memcpy(flow->source, &v->sin_addr, 4);
        memcpy(flow->destination, &v4->sin_addr, 4);
        flow->source_port_be = v->sin_port;
        flow->destination_port_be = v4->sin_port;
    } else {
        const struct sockaddr_in6 *v = (const void *)&source;
        flow->family = 6;
        memcpy(flow->source, &v->sin6_addr, 16);
        memcpy(flow->destination, &v6->sin6_addr, 16);
        flow->source_port_be = v->sin6_port;
        flow->destination_port_be = v6->sin6_port;
    }
    if (!flow->source_port_be) { r->error = EADDRNOTAVAIL; goto fail; }
    r->error = 0;
    r->elapsed_ms = (uint32_t)(now_ms() - start);
    return reserved;
fail:
    d2k_stun_probe_close(reserved);
    memset(flow, 0, sizeof *flow);
    r->elapsed_ms = (uint32_t)(now_ms() - start);
    return NULL;
}

d2k_stun_probe_res d2k_stun_probe_run(d2k_stun_socket *socket) {
    d2k_stun_probe_res r;
    memset(&r, 0, sizeof r);
    r.error = EINVAL;
    if (!socket || socket->fd < 0) return r;
    int fd = socket->fd;
    r.marked = socket->marked;
    uint8_t req[D2K_STUN_HDR_LEN], txid[D2K_STUN_TXID_LEN];
    if (!d2k_stun_request(req, sizeof req, txid)) { r.error = EIO; return r; }
    memcpy(r.request,req,sizeof req);r.request_length=sizeof req;
    uint64_t start = now_ms();
    ssize_t sent;
    do { sent = send(fd, req, sizeof req, 0); } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)sizeof req) {
        r.error = sent < 0 ? errno : EIO;
        if (network_error(r.error)) { r.status = D2K_STUN_NETWORK_ERROR; }
        goto done;
    }
    r.sent = 1;
    r.error = 0;
    r.status = D2K_STUN_TIMEOUT;
    for (;;) {
        uint64_t elapsed = now_ms() - start;
        if (elapsed >= socket->wait_ms) { break; }
        struct pollfd p = {fd, POLLIN, 0};
        int rc = poll(&p, 1, (int)(socket->wait_ms - elapsed));
        if (rc == 0) { break; }
        if (rc < 0 && errno == EINTR) { continue; }
        if (rc < 0) { r.error = errno; r.status = D2K_STUN_LOCAL_ERROR; break; }
        uint8_t buf[2048], mapped[16] = {0};
        struct iovec iov = {buf, sizeof buf};
        struct msghdr msg;
        memset(&msg, 0, sizeof msg);
        msg.msg_iov = &iov; msg.msg_iovlen = 1;
        ssize_t n = recvmsg(fd, &msg, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) { continue; }
        if (n < 0) {
            r.error = errno;
            r.status = network_error(r.error) ? D2K_STUN_NETWORK_ERROR : D2K_STUN_LOCAL_ERROR;
            break;
        }
        int family = 0;
        uint16_t port = 0;
        if (!(msg.msg_flags & MSG_TRUNC) &&
            d2k_stun_parse_response(buf, (size_t)n, txid, mapped, &family, &port) == 0 &&
            family != 0) {
            r.status = D2K_STUN_BINDING_OK;
            memcpy(r.mapped_ip, mapped, sizeof mapped);
            r.mapped_family = family;
            r.mapped_port = port;
            break;
        }
        unsigned code=0;
        if(!(msg.msg_flags & MSG_TRUNC) &&
           !d2k_stun_parse_error(buf,(size_t)n,txid,&code)) {
            r.status=D2K_STUN_PROTOCOL_ERROR;r.protocol_error=code;break;
        }
        r.rejected++;
    }
done:
    r.elapsed_ms = (uint32_t)(now_ms() - start);
    return r;
}

d2k_stun_probe_res d2k_stun_probe(const d2k_stun_probe_opt *opt) {
    uint64_t start = now_ms();
    d2k_stun_flow flow;
    d2k_stun_probe_res r;
    d2k_stun_socket *socket = d2k_stun_probe_open(opt, &flow, &r);
    if (socket) {
        r = d2k_stun_probe_run(socket);
        d2k_stun_probe_close(socket);
    }
    r.elapsed_ms = (uint32_t)(now_ms() - start);
    return r;
}
