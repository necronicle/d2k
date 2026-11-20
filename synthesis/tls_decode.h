#ifndef D2K_TLS_DECODE_H
#define D2K_TLS_DECODE_H
#include "experiment.h"
#include "tls_observe.h"
typedef struct {
    d2k_tls_observer *observer;
    d2k_tls_response response;
    int terminal;
} d2k_tls_decoder;
/* Zero-initialize before first begin/free. One decoder per experiment runner.
 * Attach begin and read callbacks to begin_decode and decode respectively.
 * Symbols describe the first TLS response, not a successful TLS session. */
int d2k_tls_decoder_begin(void *);
void d2k_tls_decoder_free(d2k_tls_decoder *);
int d2k_tls_decoder_read(void *,size_t,const d2k_raw_observation *,
                         const uint8_t *,size_t,uint64_t *);
int d2k_tls_symbol_read(uint64_t,d2k_tls_response *,int *timeout,int *reset);
int d2k_tls_symbol_closed(uint64_t);
#endif
