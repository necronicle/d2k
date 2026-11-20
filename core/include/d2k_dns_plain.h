#ifndef D2K_DNS_PLAIN_H
#define D2K_DNS_PLAIN_H
#include "d2k_dns_exchange.h"
#include "d2k_verify.h"

typedef struct {
    uint8_t question[D2K_DNS_PROBE_QUESTION_MAX];
    size_t length;
    uint8_t transport;
    uint8_t wire_digest[32];
} d2k_plain_dns_request;

typedef d2k_ver_result (*d2k_plain_prepare_fn)(const char *,uint16_t,uint8_t,
    const char *,uint16_t,int,uint32_t,d2k_plain_dns_request *);
typedef void (*d2k_plain_run_fn)(const d2k_plain_dns_request *,int,
    int (*)(void *),void *,d2k_ver_result *);

/* Opens the exact TCP/UDP flow but submits no DNS bytes. The caller can
 * install and confirm an isolated candidate on this flow before exchange. */
d2k_ver_result d2k_plain_dns_prepare(const char *,uint16_t,uint8_t,const char *,
    uint16_t,int,uint32_t,d2k_plain_dns_request *);
/* Uses and retains the prepared descriptor. Caller releases it. After a
 * failed stream exchange the descriptor must not be reused. */
void d2k_plain_dns_run(const d2k_plain_dns_request *,int,d2k_ver_result *);
/* Checks permission before sending and while waiting. Return exactly one
 * from allowed while the flow is owned and its lease remains valid. */
void d2k_plain_dns_run_guarded(const d2k_plain_dns_request *,int,
    int (*allowed)(void *),void *,d2k_ver_result *);
/* For UDP, submit a direct question with a distinct transaction ID on the
 * same socket before the candidate. An answer to that question ends the trial. */
void d2k_plain_dns_run_trial(const d2k_plain_dns_request *,int,
    int (*allowed)(void *),void *,d2k_ver_result *);
#endif
