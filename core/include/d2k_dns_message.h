#ifndef D2K_DNS_MESSAGE_H
#define D2K_DNS_MESSAGE_H
#include <stddef.h>
#include <stdint.h>
/* One IN question; all name/type/id values come from the caller. */
size_t d2k_dns_question(const char *,uint16_t,uint16_t,uint8_t *,size_t);
int d2k_dns_question_valid(const uint8_t *,size_t);
int d2k_dns_answer_matches(const uint8_t *,size_t,const uint8_t *,size_t,const char **);
enum d2k_dns_address_status {
    D2K_DNS_ADDRESS_OK,D2K_DNS_ADDRESS_INVALID,D2K_DNS_ADDRESS_LIMIT,D2K_DNS_ADDRESS_LOCAL
};
struct d2k_dns_address {uint8_t family,address[16];uint32_t ttl;};
/* Bound on requested temporary allocations for record/output bounds; SIZE_MAX on
 * overflow. Caller accounts its own input/output storage separately. */
size_t d2k_dns_address_memory_bound(size_t max_records,size_t capacity);
/* Bootstrap data only: matching A/AAAA answer records after a unique CNAME
 * chain; no unrelated/additional glue. TTL is the chain/RRset minimum; zero
 * remains zero, and an encoded sign bit is normalized per RFC2181 §8.
 * Caller supplies record/output resource bounds. Output/count commit only on
 * OK; a valid negative/empty answer commits zero addresses, never a guess. */
enum d2k_dns_address_status d2k_dns_answer_addresses(const uint8_t *,size_t,
    const uint8_t *,size_t,struct d2k_dns_address *,size_t,size_t *,size_t max_records);
/* out has at least4*((length+2)/3)+1 bytes. */
size_t d2k_dns_base64url(const uint8_t *,size_t,char *);
#endif
