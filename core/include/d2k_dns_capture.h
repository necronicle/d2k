#ifndef D2K_DNS_CAPTURE_H
#define D2K_DNS_CAPTURE_H
#include <stddef.h>
#include <stdint.h>
typedef void (*d2k_dns_capture_fn)(void *,const char *,uint16_t);
#define D2K_DNS_ANSWER_MAX_ADDR 8
typedef struct {
    int family;
    uint32_t ingress;
    uint8_t client[16],server[16];
    char question[256],name[256];
    uint16_t type;
    size_t count;
    uint8_t addresses[D2K_DNS_ANSWER_MAX_ADDR][16];
    uint32_t ttl;
} d2k_dns_answer;
typedef void (*d2k_dns_capture_answer_fn)(void *,const d2k_dns_answer *);
struct d2k_dns_capture;
/* Observe complete DNS questions addressed to a local resolver on a LAN bridge. */
struct d2k_dns_capture *d2k_dns_capture_open(void);
void d2k_dns_capture_drain(struct d2k_dns_capture *,int64_t,d2k_dns_capture_fn,void *);
void d2k_dns_capture_drain_full(struct d2k_dns_capture *,int64_t,d2k_dns_capture_fn,
    d2k_dns_capture_answer_fn,void *);
void d2k_dns_capture_free(struct d2k_dns_capture *);
/* Parsers for whole IP frames. Never retain the packet. */
int d2k_dns_capture_question(const uint8_t *,size_t,uint8_t [16],int *,
    char [256],uint16_t *);
int d2k_dns_capture_answer(const uint8_t *,size_t,d2k_dns_answer *);
#endif
