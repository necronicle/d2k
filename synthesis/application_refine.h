#ifndef D2K_APPLICATION_REFINE_H
#define D2K_APPLICATION_REFINE_H
#include "application_policy.h"
#include "prefix_refine.h"
/* Execute one pending content question with the owned DoH or modern HTTPS verifier.
 * reference must be a completed owned failure. Seed/input/probe context must
 * match it exactly; DoH horizon cannot be shorter than its failed query;
 * HTTPS uses depth 1 and a complete successful HTTP response. Creates
 * fresh trial/plan identity, persists the actual trace before feeding back.
 * Caller owns returned model; network/seed/reference/refiner/archive borrowed.
 * 1 observed result consumed, 0 no question, -1 inconclusive/local failure
 * (pending proposal retained). No binding installation or health promotion.
 * No concurrent access; caller supplies a fresh nonzero experience number. */
int d2k_application_refine_step(d2k_prefix_refiner *,const d2k_application_model *,
    uint64_t,const d2k_experiment *,const d2k_tls_probe_seed *,unsigned,FILE *,
    d2k_application_model **,d2k_ver_result *);
#endif
