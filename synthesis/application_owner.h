#ifndef D2K_APPLICATION_OWNER_H
#define D2K_APPLICATION_OWNER_H
#include "raw_tls.h"
#include "verification.h"
#include "lower.h"
#include "raw_tape.h"
typedef struct d2k_application_owner d2k_application_owner;
/* Copies immutable verification identity. Actual flow comes from OPEN,
 * application evidence from finish; neither is inferred from a plan hash.
 * Unscoped plans transform only the first input. A stream-offset plan instead
 * transforms the SEND at that exact offset; all other SENDs must be identity.
 * Crossing that boundary is rejected. Earlier query observations may be
 * retained, but end/finish cannot confirm a scoped plan never executed. */
d2k_application_owner *d2k_application_owner_new(const d2k_synthesis_feedback *,uint64_t,int);
/* Bind an exact identity-slice execution to its exact lowered whole-input
   plan. Copies input and pieces. Forward and reverse complete partitions are supported with
   no explicit pacing; unsupported schedules are rejected. */
d2k_application_owner *d2k_application_owner_partition(const d2k_synthesis_feedback *,
    uint64_t,int,const uint8_t *,size_t,const d2k_payload_piece *,size_t);
/* Recover either one exact whole-input SEND under the declared plan, or a
   partition of identity SENDs whose compiled plan matches the declaration.
   Validate recorded submission, input bytes and connection ownership,
   then bind/replay that connection's events. Returned owner receives future
   tape events; free it only after channel close. No network IO. */
d2k_application_owner *d2k_application_owner_recorded(const d2k_synthesis_feedback *,
    int,d2k_raw_tape *,const uint8_t *,size_t);
void d2k_application_owner_free(d2k_application_owner *);
d2k_raw_tls_sink d2k_application_owner_sink(d2k_application_owner *);
typedef struct {
    const d2k_synthesis_feedback *identity;
    uint64_t experience,raw_ordinal;
    d2k_raw_tuple tuple;
    d2k_doh_observation query;
    const uint8_t *input;
    size_t input_length;
    uint64_t first_tls_symbol;
    int first_tls_available;
    d2k_raw_transport transport;
} d2k_application_observation;
typedef struct {
    const d2k_synthesis_feedback *identity;
    uint64_t experience,raw_ordinal;
    d2k_raw_tuple tuple;
    const uint8_t *input;
    size_t input_length;
    uint64_t first_tls_symbol;
    int network_evidence;
    d2k_ver_result result;
    int timeout_ms;
    size_t hello_wire;
    d2k_raw_transport transport;
} d2k_application_end;
typedef struct {
    const d2k_synthesis_feedback *identity;
    uint64_t experience,raw_ordinal;
    d2k_raw_tuple tuple;
    d2k_raw_transport transport;
    uint32_t sent_bytes;
    d2k_https_observation event;
} d2k_application_http_observation;
/* Borrowed synchronous snapshot. 1 owned, 0 insufficient/inconsistent events,
 * -1 foreign identity or invalid argument. SENT requires actual raw submission
 * after matching BEGIN. Neither event proves receipt by the application. */
int d2k_application_owner_observe_http(d2k_application_owner *,uint64_t,uint64_t,
    const d2k_https_observation *,d2k_application_http_observation *);
int d2k_application_owner_end(const d2k_application_owner *,const d2k_ver_result *,d2k_application_end *);
/* 1: owned observation (including network failure), 0: insufficient evidence,
 * -1: foreign/invalid arguments. Identity and exact first-write input are
 * borrowed until owner destruction. Input is before plan transformation.
 * Acceptance is not a censorship diagnosis or an application success verdict. */
int d2k_application_owner_observe(d2k_application_owner *,uint64_t,uint64_t,
    const d2k_doh_observation *,d2k_application_observation *);
d2k_verification_status d2k_application_owner_finish(d2k_application_owner *,uint64_t,uint64_t,
    const d2k_ver_result *);
#endif
