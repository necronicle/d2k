#ifndef D2K_RAW_TLS_H
#define D2K_RAW_TLS_H
#define D2K_RAW_TLS_IDENTITY "d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\norder forward\n"
#include "experiment.h"
#include "../core/include/d2k_tls13.h"
typedef struct d2k_raw_tls d2k_raw_tls;
typedef enum { D2K_RAW_TLS_OPEN,D2K_RAW_TLS_SEND,D2K_RAW_TLS_READ,D2K_RAW_TLS_CLOSE } d2k_raw_tls_action;
typedef struct {
    uint64_t experience,ordinal;
    int64_t started_ms,finished_ms;
    d2k_raw_tls_action action;
    uint32_t send_offset;
    int result,wait_ms;
    d2k_raw_observation observation;
    d2k_raw_tuple tuple;
    const uint8_t *bytes;
    size_t length;
    const char *program;
} d2k_raw_tls_event;
/* Synchronous evidence sink. Pointers are borrowed only during callback.
 * Return zero when recorded; failure seals the transport as a local error.
 * experience must be nonzero and unique in the consumer's evidence scope.
 * READ is one backend read, not each delivery from the TLS buffer. CLOSE
 * denotes local release, never proof of remote reset. */
typedef struct d2k_raw_tls_sink {
    uint64_t experience;
    void *context;
    int (*record)(void *,const d2k_raw_tls_event *);
} d2k_raw_tls_sink;
d2k_raw_tls *d2k_raw_tls_open_observed(const d2k_experiment *,const char *,
    const d2k_raw_tls_sink *,char *,size_t);
/* Owns one raw connection and copies the plan. An unscoped plan applies once
 * to the first write. A stream-offset plan applies to the write at that exact
 * offset; other writes use identity. Crossing the boundary is a local refusal,
 * never an implicit split or an approximate application of the plan.
 * Cancellation descriptor is copied, callback context borrowed. Returned IO
 * remains valid until close. TLS must be freed before this transport. */
d2k_raw_tls *d2k_raw_tls_open(const d2k_experiment *,const char *,char *,size_t);
d2k_tls_io d2k_raw_tls_io(d2k_raw_tls *);
/* Send the controlled first record once, then optionally inspect response
 * prefixes before handing this SAME stream to TLS. TLS's first write must
 * exactly match prepared bytes; it is acknowledged locally, never resent.
 * Prefix bytes remain queued for TLS and each backend read is recorded once.
 * Prefix call appends one read under caller's remaining deadline. */
int d2k_raw_tls_prepare(d2k_raw_tls *,const uint8_t *,size_t,char *,size_t);
int d2k_raw_tls_prefix(d2k_raw_tls *,int,const uint8_t **,size_t *,char *,size_t);
void d2k_raw_tls_observation(const d2k_raw_tls *,d2k_raw_observation *);
void d2k_raw_tls_close(d2k_raw_tls *);
#endif
