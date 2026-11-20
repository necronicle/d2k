#ifndef D2K_TRUSTED_TLS_H
#define D2K_TRUSTED_TLS_H
#include "d2k_tls13.h"
typedef struct d2k_trusted_tls d2k_trusted_tls;
enum d2k_trusted_tls_status {
    D2K_TRUSTED_TLS_OK, D2K_TRUSTED_TLS_INVALID, D2K_TRUSTED_TLS_LOCAL,
    D2K_TRUSTED_TLS_NETWORK, D2K_TRUSTED_TLS_TIMEOUT, D2K_TRUSTED_TLS_AUTH,
    D2K_TRUSTED_TLS_PROTOCOL, D2K_TRUSTED_TLS_CANCELLED, D2K_TRUSTED_TLS_LIMIT
};
struct d2k_trusted_tls_options {
    const char *host, *ca_file; /* NULL CA uses the platform trust store. */
    int version, timeout_ms;   /* 0 negotiates TLS 1.2–1.3, or pin 0x0303/0x0304. */
    const uint8_t *alpn; size_t alpn_len; /* Wire length-prefixed list. */
};
/* Connected socket is borrowed, never closed. No DNS lookup or bypass choice.
 * Restores descriptor flags on failure/free. This is a separate client form;
 * its success does not establish facts for an observed client's TLS form. */
enum d2k_trusted_tls_status d2k_trusted_tls_connect(int,
    const struct d2k_trusted_tls_options *, d2k_trusted_tls **);
/* Borrowed ordered transport. Callbacks return partial byte counts, read0
 * means EOF. -1 with EAGAIN/EWOULDBLOCK/EINTR/ETIMEDOUT means retry within
 * the outer TLS deadline; other errors are terminal. Each call must respect
 * its supplied wait_ms. No callback closes the transport. Only allowed==1
 * permits IO. Callbacks/control values are copied; context remains borrowed
 * and must stay valid until TLS free.
 * This authenticates the native TLS form, not an arbitrary captured form. */
struct d2k_trusted_tls_stream {
    void *context;
    long (*read)(void *,uint8_t *,size_t,int wait_ms);
    long (*write)(void *,const uint8_t *,size_t,int wait_ms);
    int (*allowed)(void *);
    uint32_t max_duration_ms,guard_interval_ms;
};
enum d2k_trusted_tls_status d2k_trusted_tls_connect_stream(
    const struct d2k_trusted_tls_stream *,const struct d2k_trusted_tls_options *,d2k_trusted_tls **);
enum d2k_trusted_tls_status d2k_trusted_tls_last_status(const d2k_trusted_tls *);
int d2k_trusted_tls_io(d2k_trusted_tls *, d2k_tls_io *);
const char *d2k_trusted_tls_alpn(const d2k_trusted_tls *);
uint16_t d2k_trusted_tls_version(const d2k_trusted_tls *);
void d2k_trusted_tls_free(d2k_trusted_tls *);
const char *d2k_trusted_tls_ca_file(void);
#endif
