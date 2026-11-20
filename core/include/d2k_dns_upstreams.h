#ifndef D2K_DNS_UPSTREAMS_H
#define D2K_DNS_UPSTREAMS_H
#include <stddef.h>
#include <stdint.h>

enum d2k_dns_transport { D2K_DNS_PLAIN, D2K_DNS_TLS, D2K_DNS_HTTPS, D2K_DNS_TCP,
    D2K_DNS_QUIC };
enum d2k_dns_parse_result {
    D2K_DNS_PARSE_OK, D2K_DNS_PARSE_INVALID, D2K_DNS_PARSE_LIMIT, D2K_DNS_PARSE_LOCAL
};
typedef struct {
    enum d2k_dns_transport transport;
    char host[254];             /* TLS/HTTP identity; never replaced by bootstrap. */
    uint16_t port;
    char path[1024];            /* Opaque owner path/query; may be sensitive. */
    char address[64];           /* Explicit numeric bootstrap, or empty. */
} d2k_dns_endpoint;

/* Neutral configuration parsing only: no network IO, health verdict or choice.
 * Outputs (including count) are unchanged on rejection/resource exhaustion.
 * Endpoint equality includes bootstrap; callers retain source provenance. */
int d2k_dns_endpoint_parse(const char *, enum d2k_dns_transport, d2k_dns_endpoint *);
int d2k_dns_endpoint_equal(const d2k_dns_endpoint *, const d2k_dns_endpoint *);
/* HTTPS authority from canonical configured identity and explicit port,
 * independently of bootstrap. RFC3986 §3.2.2 brackets IPv6; HTTPS's default
 * port443 may be omitted. Output stays unchanged on refusal. */
int d2k_dns_http_authority(const char *,uint16_t,char *,size_t);
/* Server identity used when no matching recent client question is available.
 * For a numeric address, the question is PTR for that address. Returns qtype. */
uint16_t d2k_dns_probe_question_name(const char *,char [256]);
int d2k_dns_upstreams_parse(const char *, size_t, d2k_dns_endpoint *, size_t, size_t *);
int d2k_dns_owner_targets_parse(const char *, size_t, d2k_dns_endpoint *, size_t, size_t *);
/* Explicit numeric bootstrap resolvers are separate dependencies, never a
 * replacement for the encrypted upstream's identity or application contract. */
int d2k_dns_bootstrap_parse(const char *, size_t, d2k_dns_endpoint *, size_t, size_t *);
#endif
