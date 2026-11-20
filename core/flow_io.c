#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "d2k_flow_io.h"
#include "d2k_meas.h"
struct numeric_attempt {
    const struct d2k_flow_open_options *options;
    struct d2k_flow_open_result *result;int64_t deadline,last;
};
static int64_t numeric_clock(void) {
    struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts))return -1;
    return (int64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
static int numeric_check(struct numeric_attempt *a) {
    if(a->options->allowed(a->options->guard_context)!=1) {
        a->result->status=D2K_FLOW_OPEN_CANCELLED;a->result->error=ECANCELED;return -1;
    }
    int64_t now=numeric_clock();
    if(now<a->last){a->result->status=D2K_FLOW_OPEN_LOCAL;a->result->error=EIO;return -1;}
    a->last=now;
    if(now>=a->deadline){a->result->status=D2K_FLOW_OPEN_TIMEOUT;a->result->error=ETIMEDOUT;return -1;}
    return 0;
}
static void numeric_error(struct numeric_attempt *a,int error) {
    a->result->error=error;
    switch(error) {
    case ETIMEDOUT:a->result->status=D2K_FLOW_OPEN_TIMEOUT;break;
    case ECONNREFUSED:case ECONNRESET:case ECONNABORTED:case EHOSTUNREACH:
    case ENETUNREACH:case ENETDOWN:a->result->status=D2K_FLOW_OPEN_NETWORK;break;
    default:a->result->status=D2K_FLOW_OPEN_LOCAL;break;
    }
}
enum d2k_flow_open_status d2k_flow_open_numeric(const struct d2k_flow_open_options *o,
    struct d2k_flow_open_result *r) {
    if(!r)return D2K_FLOW_OPEN_LOCAL;
    memset(r,0,sizeof *r);r->fd=-1;r->status=D2K_FLOW_OPEN_LOCAL;r->error=EINVAL;
    if(!o || !o->address || !o->port || !o->allowed ||
        (o->transport!=6 && o->transport!=17) || !o->timeout_ms || o->timeout_ms>600000 ||
        !o->guard_interval_ms || o->guard_interval_ms>o->timeout_ms)return r->status;
    struct sockaddr_storage peer={0};socklen_t peer_size;int af;
    struct sockaddr_in *v4=(void *)&peer;
    if(inet_pton(AF_INET,o->address,&v4->sin_addr)==1) {
        af=AF_INET;v4->sin_family=af;v4->sin_port=htons(o->port);peer_size=sizeof *v4;
    } else {
        struct sockaddr_in6 *v6=(void *)&peer;
        memset(&peer,0,sizeof peer);
        if(inet_pton(AF_INET6,o->address,&v6->sin6_addr)!=1)return r->status;
        af=AF_INET6;v6->sin6_family=af;v6->sin6_port=htons(o->port);peer_size=sizeof *v6;
    }
    int64_t start=numeric_clock();
    if(start<0 || start>INT64_MAX-o->timeout_ms){r->error=EIO;return r->status;}
    struct numeric_attempt attempt={o,r,start+o->timeout_ms,start};
    if(numeric_check(&attempt))return r->status;
    int fd=socket(af,o->transport==6?SOCK_STREAM:SOCK_DGRAM,0);
    if(fd<0){r->error=errno;return r->status;}
    int flags=fcntl(fd,F_GETFL,0);
    if(flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK) || fcntl(fd,F_SETFD,FD_CLOEXEC)) {
        r->error=errno;goto fail;
    }
    if(o->mark) {
        if(!d2k_mark_hook){r->error=ENOSYS;goto fail;}
        errno=0;
        if(d2k_mark_hook(fd,o->mark)) {r->error=errno?errno:EPERM;goto fail;}
    }
    if(numeric_check(&attempt))goto fail;
    if(connect(fd,(void *)&peer,peer_size)) {
        if(errno!=EINPROGRESS && errno!=EALREADY){numeric_error(&attempt,errno);goto fail;}
        for(;;) {
            if(numeric_check(&attempt))goto fail;
            int timeout=(int)(attempt.deadline-attempt.last);
            if((uint32_t)timeout>o->guard_interval_ms)timeout=(int)o->guard_interval_ms;
            struct pollfd p={fd,POLLOUT,0};int ready=poll(&p,1,timeout);
            if(ready<0 && errno==EINTR)continue;
            if(ready<0){r->error=errno;goto fail;}
            if(!ready)continue;
            if(numeric_check(&attempt))goto fail;
            int error=0;socklen_t size=sizeof error;
            if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)){r->error=errno;goto fail;}
            if(error){numeric_error(&attempt,error);goto fail;}
            break;
        }
    }
    if(numeric_check(&attempt))goto fail;
    struct sockaddr_storage source={0};socklen_t source_size=sizeof source;
    if(getsockname(fd,(void *)&source,&source_size) || source.ss_family!=af) {
        r->error=errno?errno:EAFNOSUPPORT;goto fail;
    }
    if(af==AF_INET) {
        const struct sockaddr_in *s=(const void *)&source;
        memcpy(r->source,&s->sin_addr,4);memcpy(r->destination,&v4->sin_addr,4);
        r->source_port=ntohs(s->sin_port);
    } else {
        const struct sockaddr_in6 *s=(const void *)&source,*d=(const void *)&peer;
        memcpy(r->source,&s->sin6_addr,16);memcpy(r->destination,&d->sin6_addr,16);
        r->source_port=ntohs(s->sin6_port);
    }
    if(!r->source_port){r->error=EADDRNOTAVAIL;goto fail;}
    if(numeric_check(&attempt))goto fail;
    r->fd=fd;r->error=0;r->family=af==AF_INET?4:6;r->transport=(uint8_t)o->transport;
    r->destination_port=o->port;r->status=D2K_FLOW_OPEN_OK;return r->status;
fail:
    close(fd);return r->status;
}
