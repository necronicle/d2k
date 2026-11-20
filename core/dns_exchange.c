#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "d2k_dns_exchange.h"
#include "d2k_dns_message.h"
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
struct run {
    int fd;const struct d2k_dns_exchange_options *options;
    struct d2k_dns_exchange_result *result;int64_t deadline,last;
};
static int64_t clock_ms(void) {
    struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts))return -1;
    return (int64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
static int fail(struct run *run,enum d2k_dns_exchange_status status,int error) {
    run->result->status=status;run->result->error=error;return -1;
}
static int io_error(struct run *run,int error) {
    /* Kernel resource/descriptor/policy failures are local observations, not
     * evidence that the remote DNS service failed. */
    switch(error) {
    case ETIMEDOUT:return fail(run,D2K_DNS_EXCHANGE_TIMEOUT,error);
    case ECONNRESET:case ECONNREFUSED:case ECONNABORTED:case EHOSTUNREACH:
    case ENETUNREACH:case ENETDOWN:case EPIPE:case ENOTCONN:
        return fail(run,D2K_DNS_EXCHANGE_NETWORK,error);
    default:return fail(run,D2K_DNS_EXCHANGE_LOCAL,error);
    }
}
static int check(struct run *run) {
    if(run->options->allowed && run->options->allowed(run->options->guard_context)!=1) {
        run->result->cancelled=1;return fail(run,D2K_DNS_EXCHANGE_LOCAL,ECANCELED);
    }
    int64_t now=clock_ms();
    if(now<run->last)return fail(run,D2K_DNS_EXCHANGE_LOCAL,EIO);
    run->last=now;
    if(now>=run->deadline)return fail(run,D2K_DNS_EXCHANGE_TIMEOUT,ETIMEDOUT);
    return 0;
}
static int ready(struct run *run,short events) {
    for(;;) {
        if(check(run))return -1;
        int timeout=(int)(run->deadline-run->last);
        if(run->options->allowed && (uint32_t)timeout>run->options->guard_interval_ms)
            timeout=(int)run->options->guard_interval_ms;
        struct pollfd p={run->fd,events,0};int rc=poll(&p,1,timeout);
        if(rc>0) {
            if(p.revents&POLLNVAL)return fail(run,D2K_DNS_EXCHANGE_LOCAL,EBADF);
            return check(run);
        }
        if(rc<0 && errno!=EINTR)return fail(run,D2K_DNS_EXCHANGE_LOCAL,errno);
    }
}
static int write_bytes(struct run *run,const uint8_t *p,size_t n,int datagram) {
    while(n) {
        if(ready(run,POLLOUT))return -1;
        int flags=MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
        flags|=MSG_NOSIGNAL;
#endif
        ssize_t sent=send(run->fd,p,n,flags);
        if(sent<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK))continue;
        if(sent<=0)return io_error(run,sent<0?errno:EPIPE);
        run->result->sent+=(size_t)sent;
        if(datagram && (size_t)sent!=n)return fail(run,D2K_DNS_EXCHANGE_NETWORK,EIO);
        p+=sent;n-=(size_t)sent;
    }
    return check(run);
}
static int read_exact(struct run *run,uint8_t *p,size_t n) {
    while(n) {
        size_t remaining=run->options->max_received_bytes-run->result->received;
        if(!remaining)return fail(run,D2K_DNS_EXCHANGE_LOCAL,ENOBUFS);
        if(ready(run,POLLIN))return -1;
        size_t wanted=n<remaining?n:remaining;
        ssize_t got=recv(run->fd,p,wanted,MSG_DONTWAIT);
        if(got<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK))continue;
        if(got<=0)return io_error(run,got<0?errno:ECONNRESET);
        run->result->received+=(size_t)got;p+=got;n-=(size_t)got;
    }
    return check(run);
}
size_t d2k_dns_probe_frame(uint8_t transport,const uint8_t *question,size_t length,
    uint8_t out[D2K_DNS_PROBE_WIRE_MAX]) {
    if ((transport!=6 && transport!=17) || !question || !out || !length ||
        length>D2K_DNS_PROBE_QUESTION_MAX)return 0;
    size_t prefix=transport==6 ? 2 : 0;
    if (prefix) {
        out[0]=(uint8_t)(length>>8);
        out[1]=(uint8_t)length;
    }
    memcpy(out+prefix,question,length);
    return prefix+length;
}
enum d2k_dns_exchange_status d2k_dns_exchange(int fd,const struct d2k_dns_exchange_options *o,
    const uint8_t *question,size_t n,uint8_t *answer,size_t cap,struct d2k_dns_exchange_result *r) {
    if(!r)return D2K_DNS_EXCHANGE_LOCAL;
    memset(r,0,sizeof *r);r->status=D2K_DNS_EXCHANGE_LOCAL;r->error=EINVAL;
    if(!o || fd<0 || !answer || cap<12 || cap>UINT16_MAX ||
        !o->timeout_ms || o->timeout_ms>600000 || !o->max_received_bytes ||
        (o->allowed && (!o->guard_interval_ms || o->guard_interval_ms>o->timeout_ms)) ||
        (o->transport!=6 && o->transport!=17) || d2k_dns_question_valid(question,n))return r->status;
    int type=0;socklen_t type_size=sizeof type;
    struct sockaddr_storage peer;socklen_t peer_size=sizeof peer;
    if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&type_size) || getpeername(fd,(void *)&peer,&peer_size)) {
        r->error=errno;return r->status;
    }
    if(type!=(o->transport==6?SOCK_STREAM:SOCK_DGRAM)){r->error=EPROTOTYPE;return r->status;}
    int64_t start=clock_ms();if(start<0){r->error=EIO;return r->status;}
    struct run run={fd,o,r,start+o->timeout_ms,start};
#if !defined(MSG_NOSIGNAL) && defined(SO_NOSIGPIPE)
    int previous=0,one=1;socklen_t previous_size=sizeof previous;
    if(getsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&previous,&previous_size) ||
        setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof one)){r->error=errno;return r->status;}
#elif !defined(MSG_NOSIGNAL)
    r->error=ENOTSUP;return r->status;
#endif
    uint8_t frame[D2K_DNS_PROBE_WIRE_MAX];
    size_t frame_size=d2k_dns_probe_frame((uint8_t)o->transport,question,n,frame);
    if(frame_size) {
        if(write_bytes(&run,frame,frame_size,o->transport==17))goto done;
    } else if(o->transport==6) {
        /* RFC1035 §4.2.2: TCP prefixes the exact DNS message with its length. */
        uint8_t length[2]={(uint8_t)(n>>8),(uint8_t)n};
        if(write_bytes(&run,length,sizeof length,0))goto done;
        if(write_bytes(&run,question,n,0))goto done;
    } else if(write_bytes(&run,question,n,1))goto done;
    for(;;) {
        size_t length=0;
        if(o->transport==6) {
            uint8_t prefix[2];if(read_exact(&run,prefix,2))goto done;
            length=(size_t)prefix[0]*256+prefix[1];
            if(length>cap){fail(&run,D2K_DNS_EXCHANGE_LOCAL,ENOBUFS);goto done;}
            if(read_exact(&run,answer,length))goto done;
        } else {
            size_t remaining=o->max_received_bytes-r->received;
            if(!remaining){fail(&run,D2K_DNS_EXCHANGE_LOCAL,ENOBUFS);goto done;}
            if(ready(&run,POLLIN))goto done;
            struct iovec iov={answer,cap<remaining?cap:remaining};
            struct msghdr message={0};message.msg_iov=&iov;message.msg_iovlen=1;
            ssize_t got=recvmsg(fd,&message,MSG_DONTWAIT);
            if(got<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK))continue;
            if(got<0){io_error(&run,errno);goto done;}
            length=(size_t)got;r->received+=length;
            if(message.msg_flags&MSG_TRUNC){fail(&run,D2K_DNS_EXCHANGE_LOCAL,ENOBUFS);goto done;}
        }
        if(check(&run))goto done;
        /* A delayed datagram/stream reply for another transaction is not the
         * answer and does not consume an unbounded receive resource. */
        if(length>=2 && memcmp(answer,question,2)){r->rejected++;continue;}
        const char *reason=NULL;
        if(d2k_dns_answer_matches(question,n,answer,length,&reason)) {
            fail(&run,D2K_DNS_EXCHANGE_PROTOCOL,EPROTO);goto done;
        }
        r->status=D2K_DNS_EXCHANGE_OK;r->error=0;r->answer_length=length;break;
    }
done:
#if !defined(MSG_NOSIGNAL) && defined(SO_NOSIGPIPE)
    if(setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&previous,sizeof previous)) {
        r->status=D2K_DNS_EXCHANGE_LOCAL;r->error=errno;r->answer_length=0;
    }
#endif
    return r->status;
}
