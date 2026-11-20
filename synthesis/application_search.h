#ifndef D2K_APPLICATION_SEARCH_H
#define D2K_APPLICATION_SEARCH_H
#include "application_policy.h"
typedef struct d2k_application_search d2k_application_search;
/* Named modern DoH or modern/legacy HTTPS. Copies task/transport context, owns seed, baseline,
 * policy and path session. Caller owns archive and cancellation callback ctx.
 * Creation has no IO. Candidate is still subject to controller verification.
 * next caches candidates. Owned failed verification triggers one remeasurement;
 * a submitted failed request can generate a composed late partition retaining
 * its measured hello plan. A deeper failed DNS query otherwise creates a
 * separate immutable application epoch.
 * Prior epochs remain owned and are not interpreted as remote reset evidence. */
d2k_application_search *d2k_application_search_new(const d2k_application_request *,
    const d2k_experiment *,uint64_t,int,size_t,FILE *);
d2k_syn_status d2k_application_search_next(d2k_application_search *,d2k_vres *);
/* Before next(): load one own historical prefix proposal, copying its bytes.
 * No network IO or promotion. FILE remains caller-owned and may be closed on
 * return. A supported proposal replaces any prior one; none/error preserves it.
 * The normal current-experience verifier must establish success.
 * 1 loaded, 0 no compatible supported proposal, -1 local error/already started. */
int d2k_application_search_history(d2k_application_search *,FILE *);
int d2k_application_search_matches(const d2k_application_search *,const d2k_application_request *,
    const d2k_experiment *,uint64_t,int,size_t);
void d2k_application_search_free(d2k_application_search *);
/* Queue a failed controller verification as a request for an owned follow-up
 * experiment, never as an observation in the protocol model. 1 new request,
 * 0 foreign/duplicate/ineligible, -1 contradictory evidence/local failure. */
int d2k_application_search_feedback(d2k_application_search *,const d2k_synthesis_feedback *,
    d2k_verification_status);
const d2k_synthesis_feedback *d2k_application_search_pending_failure(const d2k_application_search *);
/* Execute at most once for the pending failure. Returned history is borrowed
 * from search; 1 owned trace, 0 no request, -1 local/ownership failure.
 * Does not classify censorship or promote a candidate. */
int d2k_application_search_remeasure(d2k_application_search *,const d2k_application_model **);
#endif
