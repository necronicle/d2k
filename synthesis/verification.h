#ifndef D2K_SYNTHESIS_VERIFICATION_H
#define D2K_SYNTHESIS_VERIFICATION_H
#include "../core/include/d2k_sched.h"
typedef struct d2k_verification_owner d2k_verification_owner;
#include "verification_status.h"
/* Own immutable identity for one candidate's separate HTTP/DoH application
 * verification. Requires explicit resource, nonzero episode/search IDs and
 * exact program. Plan ID may be unspecified (all zero); text still must match.
 * Does NOT splice verification-connection results into raw path history.
 * OBSERVED means this app criterion in this trial, not universal reliability;
 * NOT_MET does not diagnose censorship. QUERY_OBSERVED records one verified
 * DoH answer without claiming the required flow-volume criterion. */
d2k_verification_owner *d2k_verification_new(const d2k_synthesis_feedback *,int require_budget);
void d2k_verification_free(d2k_verification_owner *);
const d2k_synthesis_feedback *d2k_verification_identity(const d2k_verification_owner *);
d2k_verification_status d2k_verification_accept(d2k_verification_owner *,const d2k_synthesis_feedback *);
#endif
