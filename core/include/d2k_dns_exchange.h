#ifndef D2K_DNS_EXCHANGE_H
#define D2K_DNS_EXCHANGE_H
#include <stddef.h>
#include <stdint.h>
#define D2K_DNS_PROBE_QUESTION_MAX 272u
#define D2K_DNS_PROBE_WIRE_MAX (D2K_DNS_PROBE_QUESTION_MAX + 2u)

/* Encodes the exact bytes submitted by a short DNS exchange. */
size_t d2k_dns_probe_frame(uint8_t transport,const uint8_t *question,size_t length,
    uint8_t out[D2K_DNS_PROBE_WIRE_MAX]);
enum d2k_dns_exchange_status {
    D2K_DNS_EXCHANGE_OK,D2K_DNS_EXCHANGE_LOCAL,D2K_DNS_EXCHANGE_TIMEOUT,
    D2K_DNS_EXCHANGE_NETWORK,D2K_DNS_EXCHANGE_PROTOCOL
};
struct d2k_dns_exchange_options {
    int transport; /* Explicit6 TCP or17 UDP, never inferred from port. */
    uint32_t timeout_ms,guard_interval_ms;
    int (*allowed)(void *); /* Exactly1; caller owns DNS/lease/cancel guard. */
    void *guard_context;
    size_t max_received_bytes;
};
struct d2k_dns_exchange_result {
    enum d2k_dns_exchange_status status;
    size_t sent,received,answer_length;
    unsigned rejected;
    int error,cancelled;
};
/* Borrowed connected socket; no lookup, retry policy, protocol fallback or
 * descriptor close/flag change. The caller owns marking/isolation and query.
 * Exact one-question IN form only; unsupported forms refuse before sending.
 * Answer length is valid only for OK. Bytes/counters survive failed checks.
 * Failure does not resynchronize a stream; caller retires its own flow. */
enum d2k_dns_exchange_status d2k_dns_exchange(int,const struct d2k_dns_exchange_options *,
    const uint8_t *,size_t,uint8_t *,size_t,struct d2k_dns_exchange_result *);
#endif
