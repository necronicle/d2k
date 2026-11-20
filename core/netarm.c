#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include "d2k_netarm.h"
#include "d2k_doh_contract.h"
#include "d2k_appget.h"
#include "d2k_tls13.h"
#include "d2km_tls.h"

#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static d2km_result R(d2km_result_kind k, int64_t v)
{
    d2km_result r = {k, v};
    return r;
}

typedef struct {
    struct sockaddr_storage ss;
    socklen_t len;
} addr;

static int resolve(const d2k_netarm *n, addr *a)
{
    memset(a, 0, sizeof(*a));
    if (n->family == 6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&a->ss;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons(n->port);
        if (inet_pton(AF_INET6, n->ip, &s->sin6_addr) != 1) return -1;
        a->len = sizeof(*s);
    } else {
        struct sockaddr_in *s = (struct sockaddr_in *)&a->ss;
        s->sin_family = AF_INET;
        s->sin_port = htons(n->port);
        if (inet_pton(AF_INET, n->ip, &s->sin_addr) != 1) return -1;
        a->len = sizeof(*s);
    }
    return 0;
}

static int set_ttl(int fd, int family, int ttl)
{
    if (family == 6)
        return setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
    return setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}

/* Неблокирующее подключение с пределом. 0 — подключено, иначе исход. */
static int tcp_connect(int fd, const addr *a, int ms, d2km_result *res, int64_t *rtt)
{
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int64_t t0 = now_ms();
    int rc = connect(fd, (const struct sockaddr *)&a->ss, a->len);
    if (rc != 0 && errno != EINPROGRESS) {
        *res = errno == ECONNREFUSED ? R(D2KM_R_RST, 0)
             : (errno == EHOSTUNREACH || errno == ENETUNREACH) ? R(D2KM_R_ICMP, errno)
             : R(D2KM_R_LOCAL_FAIL, errno);
        return -1;
    }
    if (rc != 0) {
        struct pollfd p = {fd, POLLOUT, 0};
        int pr;
        do pr = poll(&p, 1, ms); while (pr < 0 && errno == EINTR);
        if (pr == 0) { *res = R(D2KM_R_SYN_SILENT, 0); return -1; }
        int e = 0;
        socklen_t el = sizeof(e);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el);
        if (pr < 0 || e) {
            *res = e == ECONNREFUSED ? R(D2KM_R_RST, 0)
                 : (e == EHOSTUNREACH || e == ENETUNREACH) ? R(D2KM_R_ICMP, e)
                 : e == ETIMEDOUT ? R(D2KM_R_SYN_SILENT, 0)
                 : R(D2KM_R_LOCAL_FAIL, e);
            return -1;
        }
    }
    *rtt = now_ms() - t0;
    fcntl(fd, F_SETFL, fl);
    return 0;
}

/* После неудачи на установленном потоке: сброс, закрытие сервером или
   тишина — по сокету, не по тексту ошибки. */
static d2km_result after_failure(int fd, int64_t started, int limit_ms, uint64_t got)
{
    int last = d2k_tls_last_read_errno();
    if (last == ECONNRESET) return R(D2KM_R_RST, 0);
    if (last == -1) return R(D2KM_R_RST, 1);
    if (last == ETIMEDOUT)
        return got ? R(D2KM_R_CUT, (int64_t)(got / 1024)) : R(D2KM_R_HELLO_SILENT, 0);
    int e = 0;
    socklen_t el = sizeof(e);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el);
    if (e == ECONNRESET) return R(D2KM_R_RST, 0);
    uint8_t b;
    ssize_t r = recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT);
    if (r < 0 && errno == ECONNRESET) return R(D2KM_R_RST, 0);
    if (r == 0) return R(D2KM_R_RST, 1);   /* закрыто без ответа: value 1 — FIN, не RST */
    if (now_ms() - started >= limit_ms - 50)
        return got ? R(D2KM_R_CUT, (int64_t)(got / 1024)) : R(D2KM_R_HELLO_SILENT, 0);
    return R(D2KM_R_REPLY, 0);   /* сервер ответил, но обмен не сложился */
}

/* СОБСТВЕННЫЙ РАЗРЕЗ. На своём потоке разрез делает сам отправитель:
   приветствие уходит двумя сегментами (TCP_NODELAY, два send). Датапат для
   этого не нужен; он нужен фальшивкам и потокам клиентов. */
typedef struct {
    int fd;
    size_t split_at;   /* 0 — без разреза */
    int first_done;
    size_t sent,received;
    int write_error;
} split_io;

static int sio_write(void *c, const uint8_t *b, size_t n, char *err, size_t cap)
{
    split_io *io = c;
    size_t at = (!io->first_done && io->split_at > 0 && io->split_at < n) ? io->split_at : 0;
    io->first_done = 1;
    size_t parts[2] = {at ? at : n, at ? n - at : 0};
    const uint8_t *p = b;
    for (int i = 0; i < 2 && parts[i]; i++) {
        size_t left = parts[i];
        while (left) {
            ssize_t w = send(io->fd, p, left, 0);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) { io->write_error=errno?errno:EIO;snprintf(err, cap, "send: %s", strerror(errno)); return -1; }
            io->sent+=(size_t)w;
            p += w; left -= (size_t)w;
        }
    }
    return 0;
}

static long sio_read(void *c, uint8_t *b, size_t cap, int wait_ms, char *err, size_t ecap)
{
    split_io *io = c;
    struct pollfd p = {io->fd, POLLIN, 0};
    int pr;
    do pr = poll(&p, 1, wait_ms); while (pr < 0 && errno == EINTR);
    if (pr == 0) { errno = ETIMEDOUT; snprintf(err, ecap, "срок"); return -1; }
    ssize_t r = recv(io->fd, b, cap, 0);
    if(r>0)io->received+=(size_t)r;
    if (r < 0) snprintf(err, ecap, "recv: %s", strerror(errno));
    return (long)r;
}

/* Смещение якоря разреза в записи с приветствием (как его вычисляет датапат). */
static long anchor_pos(const uint8_t *hello, size_t n, const d2km_split *sp)
{
    static __thread d2km_tls_hello h;
    uint32_t so = 0, sl = 0;
    int has_sni = d2km_tls_parse(hello, n, &h) == D2KM_TLS_OK && d2km_tls_sni_span(&h, &so, &sl) == D2KM_TLS_OK;
    long base;
    switch (sp->anchor) {
    case D2KM_AT_PAYLOAD_START: base = 0; break;
    case D2KM_AT_SNI_START: if (!has_sni) return -1; base = so; break;
    case D2KM_AT_SNI_END: if (!has_sni) return -1; base = (long)(so + sl); break;
    case D2KM_AT_SNI_MIDDLE: if (!has_sni) return -1; base = (long)(so + sl / 2); break;
    case D2KM_AT_HELLO_MIDDLE: base = (long)(n / 2); break;
    case D2KM_AT_RECORD_END: base = (long)n; break;
    default: return -1;
    }
    long at = base + sp->offset;
    return at > 0 && (size_t)at < n ? at : -1;
}

static int native_only(const d2km_program *p)
{
    return p && p->fake_count == 0 && p->split_count == 1 && !p->reverse;
}

/* A failed local operation is a structured observation. Returning -1 would
   bypass the task's three-local-failures rule and stop after the first fault. */
static int local_failure(d2k_netarm *n,d2km_observation *obs,d2km_result *res,
                         const char *phase,int code,const char *detail)
{
    *res=R(D2KM_R_LOCAL_FAIL,code);
    obs->local_error=code?code:-1;
    snprintf(n->last_reason,sizeof n->last_reason,"%s: errno=%d; %.130s",phase,code,
        detail?detail:(code?strerror(code):"local operation failed"));
    return 0;
}

static int run(void *ctx, const d2km_arm_spec *a, d2km_observation *obs, d2km_result *res)
{
    d2k_netarm *n = ctx;
    memset(obs, 0, sizeof(*obs));
    n->last_reason[0]=0;
    if (a->reference) {   /* опорной точки нет — нет и замера */
        *res = R(D2KM_R_NOT_MEASURED, 0);
        return 0;
    }
    addr ad;
    if (resolve(n, &ad) != 0) return local_failure(n,obs,res,"address",EINVAL,NULL);
    int fd = socket(n->family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return local_failure(n,obs,res,"socket",errno,NULL);
#ifdef SO_MARK
    /* Поток с пробным планом обязан пройти датапат: у него своя метка. */
    uint32_t mark = (a->program && !native_only(a->program) && n->probe_mark) ? n->probe_mark : n->mark;
    if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
        int saved=errno;
        close(fd);
        return local_failure(n,obs,res,"SO_MARK",saved,NULL);
    }
#endif
    uint16_t lport = 0;
    int planned = 0;
    const char *pname = a->context && a->context->target.name[0] ? a->context->target.name : n->host;
    long split_at = 0;
    if (a->program && native_only(a->program) && a->kind == D2KM_ARM_EXCHANGE) {
        split_at = anchor_pos(a->hello, a->hello_length, &a->program->splits[0]);
        if (split_at <= 0) { close(fd); return local_failure(n,obs,res,"split anchor",EINVAL,NULL); }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    } else if (a->program) {
        if (!n->install) { close(fd); return local_failure(n,obs,res,"install",0,"executor unavailable"); }
        struct sockaddr_storage lb;
        memset(&lb, 0, sizeof(lb));
        lb.ss_family = n->family == 6 ? AF_INET6 : AF_INET;
        socklen_t ll = n->family == 6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
        if (bind(fd, (struct sockaddr *)&lb, ll) != 0 ||
            getsockname(fd, (struct sockaddr *)&lb, &ll) != 0) {
            int saved=errno;
            close(fd);
            return local_failure(n,obs,res,"probe bind/getsockname",saved,NULL);
        }
        lport = ntohs(n->family == 6 ? ((struct sockaddr_in6 *)&lb)->sin6_port
                                     : ((struct sockaddr_in *)&lb)->sin_port);
        char err[160]={0};
        errno=0;
        if (n->install(n->plan_ctx, pname, lport, a->program, a->experiment, err, sizeof(err)) != 0) {
            int saved=errno;
            /* The SET may have succeeded remotely even when its ACK was
               lost. Release only this trial's name/shape/family/local port
               while the socket still reserves that port. */
            if(n->remove)n->remove(n->plan_ctx,pname,lport,a->experiment);
            close(fd);
            return local_failure(n,obs,res,"install",saved,err);
        }
        planned = 1;
    }
    int64_t rtt = 0, t0 = now_ms();
    obs->sent_packets = 1;
    if (a->kind == D2KM_ARM_PATH_SERVER) {
        set_ttl(fd, n->family, a->ttl);
        if (tcp_connect(fd, &ad, n->connect_ms, res, &rtt) == 0)
            *res = R(D2KM_R_APP_OK, 0);   /* SYN дошёл: сервер ответил */
        else if (res->kind == D2KM_R_ICMP)
            /* ICMP «время истекло» и тишина значат одно — SYN не дошёл до
               сервера; маршрутизаторы ограничивают частоту ICMP, и различать
               их значит принять шум за границу (поле 08.11, instagram). */
            *res = R(D2KM_R_SYN_SILENT, 0);
    } else if (tcp_connect(fd, &ad, n->connect_ms, res, &rtt) == 0) {
        if (a->kind == D2KM_ARM_PATH_BOX) {
            /* Приветствие с малым TTL на установленном потоке. Реакция
               коробки приходит быстрее ответа сервера: окно — три RTT
               подключения (туда-обратно до сервера с запасом на его
               обработку), не меньше 200 мс на дробность таймеров. */
            set_ttl(fd, n->family, a->ttl);
            ssize_t w = send(fd, a->hello, a->hello_length, 0);
            if (w < 0) {
                *res = errno == ECONNRESET ? R(D2KM_R_RST, 0) : R(D2KM_R_LOCAL_FAIL, errno);
            } else {
                int wait = (int)(rtt * 3 > 200 ? rtt * 3 : 200);
                struct pollfd p = {fd, POLLIN, 0};
                int pr = poll(&p, 1, wait);
                uint8_t b[64];
                ssize_t r = pr > 0 ? recv(fd, b, sizeof(b), MSG_DONTWAIT) : -1;
                if (pr > 0 && r < 0 && errno == ECONNRESET) *res = R(D2KM_R_RST, 0);
                else if (pr > 0 && r == 0) *res = R(D2KM_R_RST, 1);
                else if (pr > 0 && r > 0) *res = R(D2KM_R_REPLY, 0);
                else *res = R(D2KM_R_HELLO_SILENT, 0);
            }
        } else {
            d2k_tls *t = NULL;
            char err[200] = "";
            int64_t hs0 = now_ms();
            split_io sio = {.fd=fd,.split_at=(size_t)split_at};
            d2k_tls_io io = {&sio, sio_read, sio_write};
            if (d2k_tls_connect_form(-1, &io, n->host, a->hello, a->hello_length,
                                     n->exchange_ms, &t, err, sizeof(err)) != 0) {
                if(!sio.sent || sio.write_error) {
                    char detail[160];snprintf(detail,sizeof detail,"sent=%zu received=%zu; %.100s",sio.sent,sio.received,err);
                    (void)local_failure(n,obs,res,"TLS prepare/write",sio.write_error,detail);
                } else {
                    /* TLS handshake bytes are not application body bytes. */
                    *res = after_failure(fd, hs0, n->exchange_ms, 0);
                    snprintf(n->last_reason,sizeof n->last_reason,"handshake: result=%s sent=%zu received=%zu; %.100s",
                        d2km_result_name(res->kind),sio.sent,sio.received,err);
                }
            } else {
                if(n->doh_path) {
                    d2k_ver_result vr;
                    d2k_doh_contract(t,n->host,n->doh_path,n->dns_name?n->dns_name:n->host,n->exchange_ms,&vr);
                    obs->application_bytes=vr.body_bytes;
                    *res=d2k_doh_result(&vr);
                    snprintf(n->last_reason,sizeof n->last_reason,"%.199s",vr.reason);
                } else {
                d2k_app_result ar;
                d2k_app_get(t, n->host, n->path ? n->path : "/", n->exchange_ms, &ar);
                obs->application_bytes = ar.body_bytes;
                switch (ar.state) {
                case D2K_APP_COMPLETE: *res = R(D2KM_R_APP_OK, 0); break;
                case D2K_APP_CUT:
                case D2K_APP_TIMEOUT: *res = R(D2KM_R_CUT, (int64_t)(ar.body_bytes / 1024)); break;
                case D2K_APP_MALFORMED: *res = R(D2KM_R_REPLY, 0); break;
                default: *res = R(D2KM_R_LOCAL_FAIL, 0); break;
                }
                snprintf(n->last_reason,sizeof n->last_reason,"application: result=%s bytes=%llu; %.100s",
                    d2km_result_name(res->kind),(unsigned long long)ar.body_bytes,ar.reason);
                }
                d2k_tls_free(t);
            }
        }
    }
    obs->elapsed_ms = (uint32_t)(now_ms() - t0);
    if (res->kind == D2KM_R_RST) obs->rsts = 1;
    if (res->kind == D2KM_R_LOCAL_FAIL) {
        obs->local_error = res->value?(int)res->value:-1;
        if(!n->last_reason[0])
            (void)local_failure(n,obs,res,"connect/transport",(int)res->value,NULL);
    }
    /* Без квитанции исполнение не засчитывается (§8.3): исход плеча с
       программой без подтверждённого исполнения — не ответ коробки. */
    if (planned && res->kind != D2KM_R_LOCAL_FAIL) {
        char note[160] = "";
        fprintf(stderr,"experiment E%u host=%s phase=before-receipt result=%s reason=%s\n",
            a->experiment,n->host,d2km_result_name(res->kind),n->last_reason);
        int ok = n->receipt ? n->receipt(n->plan_ctx, lport, a->experiment, note, sizeof(note)) : 0;
        if (ok != 1) {
            char before[sizeof n->last_reason];snprintf(before,sizeof before,"%s",n->last_reason);
            const char *wire=d2km_result_name(res->kind);
            *res = R(D2KM_R_LOCAL_FAIL, 0);
            obs->local_error = -1;
            snprintf(n->last_reason,sizeof n->last_reason,"receipt: %.60s; wire=%s; %.80s",note,wire,before);
        }
    }
    if (planned && n->remove) n->remove(n->plan_ctx, pname, lport, a->experiment);
    close(fd);
    return 0;
}

d2km_net d2k_netarm_net(d2k_netarm *n)
{
    d2km_net net = {n, run};
    return net;
}
