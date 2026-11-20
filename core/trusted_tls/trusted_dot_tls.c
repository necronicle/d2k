#define _POSIX_C_SOURCE 200809L
#include "d2k_trusted_dot.h"
#include "d2k_dns_message.h"
#include "d2k_dns_upstreams.h"
#include "d2k_verify.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
static int64_t monotonic_ms(void *context) {
    (void)context;struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC,&ts))return -1;
    return (int64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
static int stopped(void *context) {
    const struct d2k_trusted_dot_options *o=context;
    return o->cancelled && o->cancelled(o->control_context);
}
struct dot_wait {const struct d2k_trusted_dot_options *options;uint32_t quantum;};
static int wait_stopped(void *context) {
    return stopped((void *)((struct dot_wait *)context)->options);
}
static int wait_ms(void *context,uint32_t ms) {
    struct dot_wait *control=context;
    int64_t start=monotonic_ms(NULL);
    if(start<0)return -1;
    for(;;) {
        if(wait_stopped(context))return -1;
        int64_t now=monotonic_ms(NULL);
        if(now<start)return -1;
        if((uint64_t)(now-start)>=ms)return 0;
        uint32_t left=ms-(uint32_t)(now-start);
        /* Cancellation polling is bounded by the caller's IO budget. */
        if(left>control->quantum)left=control->quantum;
        struct timespec delay={(time_t)(left/1000),(long)(left%1000)*1000000L};
        if(nanosleep(&delay,NULL) && errno!=EINTR)return -1;
    }
}
static enum d2k_trusted_tls_status dot_check(int fd,const struct d2k_trusted_tls_stream *stream,
    const struct d2k_trusted_dot_options *o,struct d2k_dot_result *r) {
    if(!r)return D2K_TRUSTED_TLS_INVALID;
    memset(r,0,sizeof *r);r->name_ok=-1;
    uint8_t question[512];
    if(!o || (!stream && fd<0) || !o->host || !*o->host || !o->query_type ||
        !d2k_dns_question(o->query_name,o->query_type,o->query_id,question,sizeof question) ||
        o->io_timeout_ms<=0 || o->max_duration_ms<30000 || o->max_duration_ms>600000) {
        r->local_refusal=1;return D2K_TRUSTED_TLS_INVALID;
    }
    const struct d2k_trusted_dot_options snapshot=*o;o=&snapshot;
    int64_t start=monotonic_ms(NULL);
    if(start<0 || stopped((void *)o)) {
        r->local_refusal=1;r->cancelled=stopped((void *)o);
        return stream && r->cancelled?D2K_TRUSTED_TLS_CANCELLED:D2K_TRUSTED_TLS_LOCAL;
    }
    int timeout=o->io_timeout_ms;
    if(timeout>o->max_duration_ms)timeout=o->max_duration_ms;
    struct d2k_trusted_tls_options tls_options={o->host,o->ca_file,o->version,timeout,NULL,0};
    d2k_trusted_tls *tls=NULL;
    enum d2k_trusted_tls_status status=stream?d2k_trusted_tls_connect_stream(stream,&tls_options,&tls):
        d2k_trusted_tls_connect(fd,&tls_options,&tls);
    if(status!=D2K_TRUSTED_TLS_OK) {
        r->local_refusal=status==D2K_TRUSTED_TLS_LOCAL || status==D2K_TRUSTED_TLS_INVALID ||
            status==D2K_TRUSTED_TLS_CANCELLED || status==D2K_TRUSTED_TLS_LIMIT;
        r->cancelled=status==D2K_TRUSTED_TLS_CANCELLED;
        return status;
    }
    d2k_tls_io channel;int64_t now=monotonic_ms(NULL);
    if(now<start || now-start>o->max_duration_ms-30000 ||
        d2k_trusted_tls_io(tls,&channel))r->local_refusal=1;
    else {
        uint32_t quantum=(uint32_t)o->io_timeout_ms;
        if(stream && stream->guard_interval_ms<quantum)quantum=stream->guard_interval_ms;
        struct dot_wait control={o,quantum};
        struct d2k_dot_io io={channel,monotonic_ms,wait_ms,&control,wait_stopped};
        d2k_dot_contract_io(&io,o->query_name,o->query_type,o->query_id,o->io_timeout_ms,
            o->max_duration_ms-(int)(now-start),r);
    }
    r->name_ok=r->peer_authenticated=r->handshake_ok=1;
    r->negotiated_tls=d2k_trusted_tls_version(tls);
    if(stream)status=d2k_trusted_tls_last_status(tls);
    if(stopped((void *)o))status=D2K_TRUSTED_TLS_CANCELLED;
    if(status==D2K_TRUSTED_TLS_LOCAL || status==D2K_TRUSTED_TLS_CANCELLED || status==D2K_TRUSTED_TLS_LIMIT) {
        r->application_ok=0;r->local_refusal=1;r->cancelled=status==D2K_TRUSTED_TLS_CANCELLED;
    }
    d2k_trusted_tls_free(tls);return status;
}
enum d2k_trusted_tls_status d2k_trusted_dot_check(int fd,
    const struct d2k_trusted_dot_options *o,struct d2k_dot_result *r) {
    return dot_check(fd,NULL,o,r);
}
struct stream_scope {struct d2k_trusted_tls_stream stream;struct d2k_trusted_dot_options options;};
static int stream_cancelled(void *context) {
    struct stream_scope *s=context;
    return s->stream.allowed(s->stream.context)!=1 || stopped(&s->options);
}
static int stream_allowed(void *context){return !stream_cancelled(context);}
static long stream_read(void *context,uint8_t *p,size_t n,int wait) {
    struct stream_scope *s=context;return s->stream.read(s->stream.context,p,n,wait);
}
static long stream_write(void *context,const uint8_t *p,size_t n,int wait) {
    struct stream_scope *s=context;return s->stream.write(s->stream.context,p,n,wait);
}
enum d2k_trusted_tls_status d2k_trusted_dot_check_stream(const struct d2k_trusted_tls_stream *stream,
    const struct d2k_trusted_dot_options *o,struct d2k_dot_result *r) {
    if(!stream || !o || !stream->read || !stream->write || !stream->allowed ||
       !stream->max_duration_ms || stream->max_duration_ms>600000 ||
       !stream->guard_interval_ms || stream->guard_interval_ms>INT_MAX) {
        if(r){memset(r,0,sizeof *r);r->name_ok=-1;r->local_refusal=1;}
        return D2K_TRUSTED_TLS_INVALID;
    }
    struct stream_scope scope={*stream,*o};
    struct d2k_trusted_dot_options bound_options=*o;
    bound_options.cancelled=stream_cancelled;bound_options.control_context=&scope;
    struct d2k_trusted_tls_stream bound_stream=*stream;
    bound_stream.context=&scope;bound_stream.read=stream_read;bound_stream.write=stream_write;
    bound_stream.allowed=stream_allowed;
    if(o->max_duration_ms>0 && bound_stream.max_duration_ms>(uint32_t)o->max_duration_ms)
        bound_stream.max_duration_ms=(uint32_t)o->max_duration_ms;
    return dot_check(-1,&bound_stream,&bound_options,r);
}

void d2k_dot_trusted_probe(int fd, const char *host, uint16_t version,
    int timeout,const char *qname,uint16_t qtype,d2k_ver_result *r) {
    /* Allow 30 seconds for the actual series, plus a bounded handshake and
       one full final-query interval. */
    int budget = timeout > 60000 ? 150000 : 30010 + 2 * timeout;
    char question[256];
    if (!qname) {
        qtype=d2k_dns_probe_question_name(host,question);
        qname=qtype ? question : NULL;
    }
    struct d2k_trusted_dot_options opts = {
        .host=host, .ca_file=d2k_trusted_tls_ca_file(), .query_name=qname,
        .query_type=qtype, .version=version, .io_timeout_ms=timeout, .max_duration_ms=budget
    };
    struct d2k_dot_result result;
    enum d2k_trusted_tls_status status=d2k_trusted_dot_check(fd,&opts,&result);
    r->peer_authenticated=result.peer_authenticated;
    r->peer_auth_failed=status==D2K_TRUSTED_TLS_AUTH;
    r->local_refusal=result.local_refusal;
    r->unsupported=status==D2K_TRUSTED_TLS_PROTOCOL;
    r->dns_reply_rejected=result.protocol_failure;
    r->budget_requests=result.queries;
    r->doh_replies=result.replies;
    r->negotiated_tls=result.negotiated_tls;
    if (result.peer_authenticated) {
        r->name_ok=1;
        r->level=D2K_VER_HANDSHAKE;
    }
    if (result.application_ok && result.peer_authenticated) {
        r->level=D2K_VER_APPLICATION;
        r->body_complete=1;
        r->budget=D2K_BUDGET_PASSED;
        snprintf(r->reason,sizeof r->reason,"DoT: %u matching DNS replies on one connection over %llu ms",
            result.replies,(unsigned long long)result.elapsed_ms);
        return;
    }
    if (result.timed_out || result.network_failure)
        r->budget=D2K_BUDGET_CUT;
    const char *why=r->peer_auth_failed ? "TLS certificate or identity rejected" :
        r->local_refusal ? "local trust or probe setup failed" :
        r->unsupported ? "TLS protocol rejected" :
        r->dns_reply_rejected ? "authenticated resolver rejected or returned an invalid DNS reply" :
        "connection or DNS exchange interrupted";
    snprintf(r->reason,sizeof r->reason,"DoT: %s",why);
}
