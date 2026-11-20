#ifndef D2K_TLS_OBSERVE_H
#define D2K_TLS_OBSERVE_H
#include <stddef.h>
#include <stdint.h>
typedef enum { D2K_TLS_OBS_MORE, D2K_TLS_OBS_HELLO, D2K_TLS_OBS_ALERT,
    D2K_TLS_OBS_OTHER, D2K_TLS_OBS_MALFORMED, D2K_TLS_OBS_LOCAL } d2k_tls_response_kind;
typedef struct {
    d2k_tls_response_kind kind;
    uint16_t version,cipher;
    uint8_t compression,alert_level,alert_description;
    int retry;
} d2k_tls_response;
typedef struct d2k_tls_observer d2k_tls_observer;
d2k_tls_observer *d2k_tls_observer_new(void);
void d2k_tls_observer_free(d2k_tls_observer *);
/* Contiguous stream bytes, starting at the first server TLS record. Caller
 * owns TCP reassembly. consumed leaves subsequent messages for the verifier.
 * HELLO validates framing/field lengths only, never authenticity, negotiated
 * compatibility with ClientHello, Finished, or application success. */
d2k_tls_response d2k_tls_observer_feed(d2k_tls_observer *,const uint8_t *,size_t,size_t *consumed);
#endif
