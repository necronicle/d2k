#ifndef D2K_DNS_FAMILY_H
#define D2K_DNS_FAMILY_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char name[256];
    uint8_t client[16];
    uint8_t client_family;
    int64_t expires_unix;
} d2k_dns_family_rule;
typedef struct {
    char name[256];
    uint8_t client[16],server[16],family,dnssec;
    uint16_t client_port,id,qtype;
} d2k_dns_family_request;

/* The reply can omit EDNS/DNSSEC flags when served from a router cache.
 * Only a seen, ordinary AAAA or HTTPS request may authorize a matching reply. */
int d2k_dns_family_request_parse(const uint8_t *packet,size_t length,
    const d2k_dns_family_rule *rule,d2k_dns_family_request *out);
int d2k_dns_family_response_matches(const uint8_t *packet,size_t length,
    const d2k_dns_family_request *request);

/* 1: changed, 0: leave the packet untouched, -1: invalid arguments. */
int d2k_dns_family_rewrite(uint8_t *packet,size_t *length,size_t capacity,
    const d2k_dns_family_rule *rule,int64_t now_unix,int ordinary_request_seen);
/* Atomically written controller file: expiry family client-address exact-name. */
int d2k_dns_family_load(const char *path,d2k_dns_family_rule *rules,size_t capacity,
    size_t *count,int64_t now_unix);

#endif
