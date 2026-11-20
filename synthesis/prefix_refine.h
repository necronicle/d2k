#ifndef D2K_PREFIX_REFINE_H
#define D2K_PREFIX_REFINE_H
#include <stddef.h>
#include <stdint.h>
/* Local proposal generator for two same-length measured payloads. Caller owns
 * evidence admission, exact protocol context and live application validation.
 * A prior positive is only a starting hypothesis, never a health verdict.
 * No network IO, stored domain names or plan pool. */
typedef struct d2k_prefix_refiner d2k_prefix_refiner;
d2k_prefix_refiner *d2k_prefix_refiner_new(const uint8_t *,const uint8_t *,size_t);
/* Exact single-prefix compiler plans only. Segment size, modifiers and payload
 * lengths must match so refinement changes content alone. Evidence admission
 * remains caller-owned; plan text alone never establishes a measured contrast. */
d2k_prefix_refiner *d2k_prefix_refiner_new_plans(const char *,const char *);
/* As above, retaining an identical measured original partition in both plans. */
d2k_prefix_refiner *d2k_prefix_refiner_new_partition_plans(const char *,const char *,size_t);
/* Borrow the compiled pending plan until consumed feedback/free. */
int d2k_prefix_refiner_next_plan(d2k_prefix_refiner *,uint64_t *,const char **);
void d2k_prefix_refiner_free(d2k_prefix_refiner *);
/* Borrow immutable proposal until feedback/free. Repeated calls return the
 * same ticket/bytes. 1 proposal, 0 every remaining single-byte substitution
 * was tried, -1 invalid/local failure. Closure is local, not global minimality. */
int d2k_prefix_refiner_next(d2k_prefix_refiner *,uint64_t *,const uint8_t **,size_t *);
/* Ticket binds feedback to the pending payload. Outcome 1 observed application
 * success, 0 observed failure, -1 inconclusive (retain pending question).
 * Caller must validate trial/flow/generation ownership BEFORE calling.
 * 1 consumed, 0 stale/unknown, -1 invalid. */
int d2k_prefix_refiner_feedback(d2k_prefix_refiner *,uint64_t,int);
/* Current hypothesis, not a deployment-ready solution. */
const uint8_t *d2k_prefix_refiner_hypothesis(const d2k_prefix_refiner *,size_t *);
#endif
