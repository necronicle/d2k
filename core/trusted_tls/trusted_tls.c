#define _POSIX_C_SOURCE 200809L
#include "d2k_trusted_tls.h"
#include "d2k_domain.h"
#include "d2k_verify.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct d2k_trusted_tls {
    SSL_CTX *ctx; SSL *ssl;
    int fd, flags, timeout_ms;
    int stream_mode;
    struct d2k_trusted_tls_stream stream;
    int64_t lifetime_end,operation_end,last_clock;
    enum d2k_trusted_tls_status status;
    char alpn[256];
};
static int64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static enum d2k_trusted_tls_status stream_check(d2k_trusted_tls *t) {
    if(!t->stream_mode)return D2K_TRUSTED_TLS_OK;
    if(t->status!=D2K_TRUSTED_TLS_OK)return t->status;
    for(int pass=0;pass<2;pass++) {
        int64_t now=now_ms();
        if(now<0 || now<t->last_clock)return t->status=D2K_TRUSTED_TLS_LOCAL;
        t->last_clock=now;
        if(now>=t->lifetime_end)return t->status=D2K_TRUSTED_TLS_LIMIT;
        if(now>=t->operation_end)return t->status=D2K_TRUSTED_TLS_TIMEOUT;
        if(!pass && t->stream.allowed(t->stream.context)!=1)
            return t->status=D2K_TRUSTED_TLS_CANCELLED;
    }
    return D2K_TRUSTED_TLS_OK;
}
static int stream_transfer(BIO *bio,char *out,const char *in,int n) {
    d2k_trusted_tls *t=BIO_get_data(bio);
    BIO_clear_retry_flags(bio);
    if(!t || n<=0 || stream_check(t)!=D2K_TRUSTED_TLS_OK)return -1;
    int64_t end=t->operation_end<t->lifetime_end?t->operation_end:t->lifetime_end;
    int64_t remaining=end-t->last_clock;
    if(remaining>t->stream.guard_interval_ms)remaining=t->stream.guard_interval_ms;
    errno=0;
    long got=in?t->stream.write(t->stream.context,(const uint8_t *)in,(size_t)n,(int)remaining):
        t->stream.read(t->stream.context,(uint8_t *)out,(size_t)n,(int)remaining);
    int error=errno;
    if(stream_check(t)!=D2K_TRUSTED_TLS_OK)return -1;
    if(got>n || got < -1) {t->status=D2K_TRUSTED_TLS_LOCAL;return -1;}
    if(got<0) {
        if(error==EAGAIN || error==EWOULDBLOCK || error==EINTR || error==ETIMEDOUT) {
            if(in)BIO_set_retry_write(bio);else BIO_set_retry_read(bio);
        } else if(error==ECANCELED)t->status=D2K_TRUSTED_TLS_CANCELLED;
        else if(error==ENOMEM || error==ENOBUFS || error==EINVAL || error==EBADF || error==EIO ||
                  error==EMFILE || error==ENFILE || error==ENOSYS || error==ENOTSUP ||
                  error==EACCES || error==EPERM)t->status=D2K_TRUSTED_TLS_LOCAL;
        else t->status=D2K_TRUSTED_TLS_NETWORK;
        return -1;
    }
    if(!got && in){t->status=D2K_TRUSTED_TLS_NETWORK;return -1;}
    return (int)got;
}
static int stream_read(BIO *b,char *p,int n){return stream_transfer(b,p,NULL,n);}
static int stream_write(BIO *b,const char *p,int n){return stream_transfer(b,NULL,p,n);}
static int stream_create(BIO *b){BIO_set_init(b,1);BIO_set_data(b,NULL);return 1;}
static int stream_destroy(BIO *b){if(b)BIO_set_data(b,NULL);return 1;}
static long stream_control(BIO *b,int command,long arg,void *p) {
    (void)b;(void)arg;(void)p;return command==BIO_CTRL_FLUSH?1:0;
}
static BIO_METHOD *stream_method;
static pthread_once_t stream_once=PTHREAD_ONCE_INIT;
static void stream_initialize(void) {
    int index=BIO_get_new_index();if(index<0)return;
    BIO_METHOD *method=BIO_meth_new(index|BIO_TYPE_SOURCE_SINK,"d2k-owned-stream");
    if(!method)return;
    if(!BIO_meth_set_read(method,stream_read) || !BIO_meth_set_write(method,stream_write) ||
       !BIO_meth_set_ctrl(method,stream_control) || !BIO_meth_set_create(method,stream_create) ||
       !BIO_meth_set_destroy(method,stream_destroy)) {BIO_meth_free(method);return;}
    stream_method=method;
}
static enum d2k_trusted_tls_status wait_for(d2k_trusted_tls *t, int error, int64_t end) {
    if(t->stream_mode && stream_check(t)!=D2K_TRUSTED_TLS_OK)return t->status;
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
        return D2K_TRUSTED_TLS_NETWORK;
    if(t->stream_mode) {
        /* A callback may return EAGAIN immediately. Bound retry CPU use while
         * retaining one-millisecond cancellation/deadline responsiveness. */
        struct timespec pause={0,1000000};
        if(nanosleep(&pause,NULL) && errno!=EINTR)return D2K_TRUSTED_TLS_LOCAL;
        return stream_check(t);
    }
    for (;;) {
        int64_t now = now_ms();
        if (now < 0) return D2K_TRUSTED_TLS_LOCAL;
        if (now >= end) return D2K_TRUSTED_TLS_TIMEOUT;
        int64_t remaining = end - now;
        struct pollfd p = {t->fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, 0};
        int rc = poll(&p, 1, remaining > INT_MAX ? INT_MAX : (int)remaining);
        if (rc > 0) return p.revents & POLLNVAL ? D2K_TRUSTED_TLS_LOCAL : D2K_TRUSTED_TLS_OK;
        if (!rc) return D2K_TRUSTED_TLS_TIMEOUT;
        if (errno != EINTR) return D2K_TRUSTED_TLS_LOCAL;
    }
}
/* A TLS library may write during reads/handshake too. Suppress only a newly
 * generated SIGPIPE in this thread, preserving caller signal disposition. */
struct pipe_guard { sigset_t old, set; int pending, active; };
static int pipe_begin(struct pipe_guard *g) {
    memset(g, 0, sizeof(*g)); sigemptyset(&g->set); sigaddset(&g->set, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &g->set, &g->old)) return -1;
    g->active = 1;
    sigset_t pending;
    if (sigpending(&pending)) return -1;
    g->pending = sigismember(&pending, SIGPIPE);
    return 0;
}
static void pipe_end(struct pipe_guard *g) {
    if (!g->active) return;
    sigset_t pending;
    if (!g->pending && !sigpending(&pending) && sigismember(&pending, SIGPIPE)) {
        int signal_number;
        (void)sigwait(&g->set, &signal_number);
    }
    (void)pthread_sigmask(SIG_SETMASK, &g->old, NULL);
}
void d2k_trusted_tls_free(d2k_trusted_tls *t) {
    if (!t) return;
    SSL_free(t->ssl); SSL_CTX_free(t->ctx);
    if (t->flags >= 0) (void)fcntl(t->fd, F_SETFL, t->flags);
    free(t);
}
static int valid_alpn(const uint8_t *p, size_t n) {
    if ((!p && n) || n > UINT_MAX) return 0;
    for (size_t i = 0; i < n;) {
        size_t z = p[i++];
        if (!z || z > n - i) return 0;
        i += z;
    }
    return 1;
}
static enum d2k_trusted_tls_status connect_transport(int fd,
    const struct d2k_trusted_tls_stream *stream,const struct d2k_trusted_tls_options *o,
    d2k_trusted_tls **out) {
    if (!out) return D2K_TRUSTED_TLS_INVALID;
    *out = NULL;
    if (!o || (fd < 0 && !stream) || !o->host || o->timeout_ms <= 0 ||
        (o->version && o->version != TLS1_2_VERSION && o->version != TLS1_3_VERSION) ||
        !valid_alpn(o->alpn, o->alpn_len)) return D2K_TRUSTED_TLS_INVALID;
    const struct d2k_trusted_tls_options options=*o;o=&options;
    if(stream && (!stream->read || !stream->write || !stream->allowed ||
        !stream->max_duration_ms || stream->max_duration_ms>600000 ||
        !stream->guard_interval_ms || stream->guard_interval_ms>INT_MAX))return D2K_TRUSTED_TLS_INVALID;
    unsigned char address[16];
    int ip = inet_pton(AF_INET, o->host, address) == 1 ||
        inet_pton(AF_INET6, o->host, address) == 1;
    char normalized[256];
    if (!ip && d2k_domain_normalize(o->host, normalized)) return D2K_TRUSTED_TLS_INVALID;
    const char *name = ip ? o->host : normalized;
    d2k_trusted_tls *t = calloc(1, sizeof(*t));
    if (!t) return D2K_TRUSTED_TLS_LOCAL;
    t->fd = fd; t->flags = -1; t->timeout_ms = o->timeout_ms;
    enum d2k_trusted_tls_status status = D2K_TRUSTED_TLS_LOCAL;
    struct pipe_guard guard = {0};
    int64_t start=now_ms();
    if(start<0 || start>INT64_MAX-o->timeout_ms)goto fail;
    t->operation_end=start+o->timeout_ms;
    if(stream) {
        if(start>INT64_MAX-stream->max_duration_ms)goto fail;
        t->stream_mode=1;t->stream=*stream;t->last_clock=start;
        t->lifetime_end=start+stream->max_duration_ms;
        status=stream_check(t);if(status!=D2K_TRUSTED_TLS_OK)goto fail;
        status=D2K_TRUSTED_TLS_LOCAL;
    } else {
        t->flags = fcntl(fd, F_GETFL);
        if (t->flags < 0) goto fail;
    }
    t->ctx = SSL_CTX_new(TLS_client_method());
    int minimum = o->version ? o->version : TLS1_2_VERSION;
    int maximum = o->version ? o->version : TLS1_3_VERSION;
    if (!t->ctx || !SSL_CTX_set_min_proto_version(t->ctx, minimum) ||
        !SSL_CTX_set_max_proto_version(t->ctx, maximum)) goto fail;
    SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER, NULL);
    if (!(o->ca_file ? SSL_CTX_load_verify_locations(t->ctx, o->ca_file, NULL)
                    : SSL_CTX_set_default_verify_paths(t->ctx))) goto fail;
    t->ssl = SSL_new(t->ctx);
    if (!t->ssl) goto fail;
    if(stream) {
        if(pthread_once(&stream_once,stream_initialize) || !stream_method)goto fail;
        BIO *bio=BIO_new(stream_method);if(!bio)goto fail;
        BIO_set_data(bio,t);SSL_set_bio(t->ssl,bio,bio);
    } else if(!SSL_set_fd(t->ssl,fd))goto fail;
    X509_VERIFY_PARAM *parameters = SSL_get0_param(t->ssl);
    X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (ip) {
        if (!X509_VERIFY_PARAM_set1_ip_asc(parameters, name)) goto fail;
    } else if (!X509_VERIFY_PARAM_set1_host(parameters, name, 0) ||
        !SSL_set_tlsext_host_name(t->ssl, name)) goto fail;
    if (o->alpn_len && SSL_set_alpn_protos(t->ssl, o->alpn, (unsigned)o->alpn_len)) goto fail;
    if (!stream && fcntl(fd, F_SETFL, t->flags | O_NONBLOCK)) goto fail;
    if (pipe_begin(&guard)) goto fail;
    for (;;) {
        if(stream_check(t)!=D2K_TRUSTED_TLS_OK){status=t->status;goto fail;}
        ERR_clear_error();
        int rc = SSL_connect(t->ssl);
        int code=rc==1?SSL_ERROR_NONE:SSL_get_error(t->ssl,rc);
        if(stream_check(t)!=D2K_TRUSTED_TLS_OK){status=t->status;goto fail;}
        if (rc == 1) break;
        if (SSL_get_verify_result(t->ssl) != X509_V_OK) {
            status = D2K_TRUSTED_TLS_AUTH; goto fail;
        }
        status = wait_for(t, code, t->operation_end);
        if (status != D2K_TRUSTED_TLS_OK) goto fail;
    }
    const unsigned char *selected; unsigned length;
    SSL_get0_alpn_selected(t->ssl, &selected, &length);
    if ((o->alpn_len && !length) || length >= sizeof t->alpn) {
        status = D2K_TRUSTED_TLS_PROTOCOL; goto fail;
    }
    if (length) memcpy(t->alpn, selected, length);
    t->alpn[length] = 0;
    pipe_end(&guard); *out = t; return D2K_TRUSTED_TLS_OK;
fail:
    pipe_end(&guard); d2k_trusted_tls_free(t); return status;
}
enum d2k_trusted_tls_status d2k_trusted_tls_connect(int fd,
    const struct d2k_trusted_tls_options *o,d2k_trusted_tls **out) {
    return connect_transport(fd,NULL,o,out);
}
enum d2k_trusted_tls_status d2k_trusted_tls_connect_stream(
    const struct d2k_trusted_tls_stream *s,const struct d2k_trusted_tls_options *o,d2k_trusted_tls **out) {
    if(!s){if(out)*out=NULL;return D2K_TRUSTED_TLS_INVALID;}
    return connect_transport(-1,s,o,out);
}
enum d2k_trusted_tls_status d2k_trusted_tls_last_status(const d2k_trusted_tls *t) {
    return t?t->status:D2K_TRUSTED_TLS_INVALID;
}
static long tls_read(void *context, uint8_t *bytes, size_t cap, int wait_ms,
                      char *error, size_t error_cap) {
    d2k_trusted_tls *t = context;
    int64_t start = now_ms();
    struct pipe_guard guard = {0};
    if (!bytes || !cap || wait_ms <= 0 || start < 0 || pipe_begin(&guard)) {
        pipe_end(&guard); return -1;
    }
    enum d2k_trusted_tls_status status = D2K_TRUSTED_TLS_NETWORK;
    t->operation_end=start+wait_ms;
    for (;;) {
        if(stream_check(t)!=D2K_TRUSTED_TLS_OK){status=t->status;break;}
        ERR_clear_error();
        int rc = SSL_read(t->ssl, bytes, cap > INT_MAX ? INT_MAX : (int)cap);
        int code=rc>0?SSL_ERROR_NONE:SSL_get_error(t->ssl,rc);
        if(stream_check(t)!=D2K_TRUSTED_TLS_OK){status=t->status;break;}
        if (rc > 0) {pipe_end(&guard); return rc;}
        if (code == SSL_ERROR_ZERO_RETURN) {pipe_end(&guard); return 0;}
        status = wait_for(t, code, start + wait_ms);
        if (status != D2K_TRUSTED_TLS_OK) break;
    }
    t->status=status;
    if (error && error_cap) snprintf(error, error_cap, "TLS read status=%d%s",status,
        status==D2K_TRUSTED_TLS_TIMEOUT?" timeout":"");
    pipe_end(&guard); return -1;
}
static int tls_write(void *context, const uint8_t *bytes, size_t n,
                      char *error, size_t error_cap) {
    d2k_trusted_tls *t = context;
    int64_t start = now_ms();
    struct pipe_guard guard = {0};
    if ((!bytes && n) || start < 0 || pipe_begin(&guard)) {pipe_end(&guard); return -1;}
    size_t done = 0;
    t->operation_end=start+t->timeout_ms;
    while (done < n) {
        enum d2k_trusted_tls_status status=stream_check(t);
        if(status!=D2K_TRUSTED_TLS_OK)goto write_failed;
        ERR_clear_error();
        int rc = SSL_write(t->ssl, bytes + done, n - done > INT_MAX ? INT_MAX : (int)(n - done));
        int code=rc>0?SSL_ERROR_NONE:SSL_get_error(t->ssl,rc);
        status=stream_check(t);
        if(status!=D2K_TRUSTED_TLS_OK)goto write_failed;
        if (rc > 0) {done += (size_t)rc; continue;}
        status=wait_for(t,code,t->operation_end);
        if(status==D2K_TRUSTED_TLS_OK)continue;
write_failed:
        t->status=status;
        if(error && error_cap)snprintf(error,error_cap,"TLS write status=%d",status);
        pipe_end(&guard);return -1;
    }
    pipe_end(&guard); return 0;
}
int d2k_trusted_tls_io(d2k_trusted_tls *t, d2k_tls_io *io) {
    if (!t || !io) return -1;
    *io = (d2k_tls_io){t, tls_read, tls_write}; return 0;
}
const char *d2k_trusted_tls_alpn(const d2k_trusted_tls *t) { return t ? t->alpn : ""; }
uint16_t d2k_trusted_tls_version(const d2k_trusted_tls *t) {
    return t ? (uint16_t)SSL_version(t->ssl) : 0;
}

const char *d2k_trusted_tls_ca_file(void) {
    const char *file = getenv("SSL_CERT_FILE");
    if (file && *file) return file;
    if (getenv("SSL_CERT_DIR")) return NULL;
    static const char *const locations[] = {
        "/opt/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem"
    };
    for (size_t i = 0; i < sizeof locations / sizeof *locations; i++)
        if (access(locations[i], R_OK) == 0) return locations[i];
    return NULL;
}

static void release_doh_tls(void *context) {
    d2k_trusted_tls_free(context);
}

d2k_doh_tls_status d2k_doh_trusted_tls_open(int fd, const char *host,
    uint16_t version, int timeout, d2k_doh_tls_session *session) {
    static const uint8_t alpn[] = {2, 'h', '2', 8, 'h','t','t','p','/','1','.','1'};
    struct d2k_trusted_tls_options options = {
        host, d2k_trusted_tls_ca_file(), version, timeout, alpn, sizeof alpn
    };
    d2k_trusted_tls *tls;
    switch (d2k_trusted_tls_connect(fd, &options, &tls)) {
    case D2K_TRUSTED_TLS_OK: {
        const char *negotiated=d2k_trusted_tls_alpn(tls);
        uint8_t http=!strcmp(negotiated,"h2") ? 2 : !strcmp(negotiated,"http/1.1") ? 1 : 0;
        if (http &&
            !d2k_trusted_tls_io(tls, &session->io)) {
            session->release = release_doh_tls;
            session->http_version = http;
            session->tls_version = d2k_trusted_tls_version(tls);
            return D2K_DOH_TLS_OK;
        }
        d2k_trusted_tls_free(tls);
        return D2K_DOH_TLS_PROTOCOL;
    }
    case D2K_TRUSTED_TLS_AUTH:
        return D2K_DOH_TLS_AUTH;
    case D2K_TRUSTED_TLS_NETWORK:
    case D2K_TRUSTED_TLS_TIMEOUT:
        return D2K_DOH_TLS_NETWORK;
    case D2K_TRUSTED_TLS_PROTOCOL:
        return D2K_DOH_TLS_PROTOCOL;
    default:
        return D2K_DOH_TLS_LOCAL;
    }
}
