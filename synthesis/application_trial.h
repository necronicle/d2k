#ifndef D2K_APPLICATION_TRIAL_H
#define D2K_APPLICATION_TRIAL_H
#include "application_owner.h"
#include "application_model.h"
/* One owned TLS1.3/HTTP2 DNS query through the initial-record transformation.
 * Identity must describe this generated modern TLS probe, not a captured
 * foreign handshake. Does not install plans, confirm sustained flow health,
 * or mutate a learning session. Successful query yields QUERY_OBSERVED. */
d2k_verification_status d2k_application_doh_query(const d2k_synthesis_feedback *,
    uint64_t,const d2k_experiment *,int,size_t,d2k_ver_result *);
d2k_verification_status d2k_application_doh_probe(const d2k_synthesis_feedback *,
    uint64_t,const d2k_experiment *,const d2k_tls_probe_seed *,int,size_t,d2k_ver_result *);
typedef int (*d2k_application_observer)(void *,const d2k_application_observation *);
d2k_verification_status d2k_application_doh_observe(const d2k_synthesis_feedback *,
    uint64_t,const d2k_experiment *,const d2k_tls_probe_seed *,int,size_t,
    d2k_application_observer,void *,d2k_ver_result *);
/* The decision sees the updated model, not a stale pre-query snapshot.
 * Return 1/0/-1 to continue/stop/refuse. Caller owns returned history even on
 * transport failure. No default repetition policy or application promotion. */
typedef int (*d2k_application_decision)(void *,d2k_application_model *,d2k_application_update);
/* One HTTP/1.1 exchange over an owned TLS1.3 experiment. Returns a typed
 * terminal model even for measured failure; no DNS query or volume claim. */
d2k_verification_status d2k_application_https_learn(const d2k_synthesis_feedback *,
    uint64_t,const d2k_experiment *,const d2k_tls_probe_seed *,int,size_t,
    d2k_application_model **,d2k_ver_result *);
d2k_verification_status d2k_application_doh_learn(const d2k_synthesis_feedback *,
    uint64_t,const d2k_experiment *,const d2k_tls_probe_seed *,int,size_t,
    d2k_application_decision,void *,d2k_application_model **,d2k_ver_result *);
d2k_verification_status d2k_application_doh_compare(const d2k_application_model *,
    const d2k_synthesis_feedback *,uint64_t,const d2k_experiment *,const d2k_tls_probe_seed *,
    int,size_t,d2k_application_model **,d2k_application_question *,d2k_ver_result *);
#endif
