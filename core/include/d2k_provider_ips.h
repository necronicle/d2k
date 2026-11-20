#ifndef D2K_PROVIDER_IPS_H
#define D2K_PROVIDER_IPS_H
#include <stddef.h>
#include <stdint.h>
#include "d2k_dns_capture.h"

#define D2K_PROVIDER_IPS_MAX 2048
typedef struct {
    uint8_t address[16], family, provider;
    uint64_t expires;
} d2k_provider_ip;
typedef struct {
    d2k_provider_ip entries[D2K_PROVIDER_IPS_MAX];
    size_t count;
    int dirty;
} d2k_provider_ips;

int d2k_provider_ips_observe(d2k_provider_ips *, const d2k_dns_answer *, uint64_t now);
int d2k_provider_ips_has(const d2k_provider_ips *, const uint8_t *, int family, uint64_t now);
int d2k_provider_ips_load(d2k_provider_ips *, const char *, uint64_t now);
int d2k_provider_ips_save(d2k_provider_ips *, const char *, uint64_t now);
#endif
