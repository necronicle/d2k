#ifndef D2K_TRUSTED_DOT_H
#define D2K_TRUSTED_DOT_H
#include "d2k_trusted_tls.h"
struct d2k_dot_result {
    unsigned queries,replies;
    uint64_t elapsed_ms;
    int application_ok,local_refusal,network_failure,protocol_failure,timed_out,cancelled;
    int peer_authenticated,handshake_ok,name_ok;
    uint16_t negotiated_tls;
};
struct d2k_dot_io {
    d2k_tls_io channel;
    int64_t (*now_ms)(void *);
    int (*wait_ms)(void *,uint32_t);
    void *clock_context;
    int (*cancelled)(void *);
};
/* RFC7858 length-framed DNS; D2K_SPEC §11.5 requires20 correct replies on
 * this single session over30seconds. IO alone never establishes peer identity.
 * Durations are caller budgets; expiry/cancellation cannot establish a fact. */
void d2k_dot_contract_io(const struct d2k_dot_io *,const char *,uint16_t,uint16_t,
    int io_timeout_ms,int max_duration_ms,struct d2k_dot_result *);
struct d2k_trusted_dot_options {
    const char *host,*ca_file,*query_name;
    uint16_t query_type,query_id;
    int version,io_timeout_ms,max_duration_ms;
    int (*cancelled)(void *);
    void *control_context;
};
/* Borrowed connected fd; verified TLS channel, no lookup/provider changes.
 * The total caller budget includes handshake. This client's health cannot
 * establish health of another TLS form. */
enum d2k_trusted_tls_status d2k_trusted_dot_check(int,
    const struct d2k_trusted_dot_options *,struct d2k_dot_result *);
/* Same authenticated session/contract over an explicit owned byte stream.
 * Transport guard and task cancellation both fence handshake, IO and waits;
 * local resource/cancellation/lifetime failures remain local outcomes. */
enum d2k_trusted_tls_status d2k_trusted_dot_check_stream(
    const struct d2k_trusted_tls_stream *,const struct d2k_trusted_dot_options *,struct d2k_dot_result *);
#endif
