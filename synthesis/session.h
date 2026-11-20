#ifndef D2K_SYNTHESIS_SESSION_H
#define D2K_SYNTHESIS_SESSION_H
#include "context.h"
#include "learner.h"
#include "joint.h"
#include "../core/include/d2k_verdict.h"
typedef struct d2k_tls_learning d2k_tls_learning;
typedef struct {
    uint64_t question_generation;
    size_t requested,completed;
    d2k_experiment_status execution;
    d2k_raw_observation last;
} d2k_learning_round;
/* Caller has already admitted comparable initial conditions. This module
 * does not infer blocking or remote reset from silence/a fresh connection.
 * Owns copied input/alphabet/context; does not install plans or alter DNS. */
d2k_tls_learning *d2k_tls_learning_new(const d2k_tls_stream *,const d2k_experiment *,
    uint64_t generation,const void *initial,size_t);
void d2k_tls_learning_free(d2k_tls_learning *);
/* Arm an already measured word containing a response read. Replay before
 * and after each subsequent question; admit it only if both controls match.
 * Matching controls detect some drift, not proof of hidden-state reset.
 * Returns 0 on success, -1 if not an exact recorded usable control. */
int d2k_tls_learning_guard(d2k_tls_learning *,const size_t *,size_t);
d2k_learner_status d2k_tls_learning_step(d2k_tls_learning *,const d2k_tls_stream *,
    const d2k_experiment *,const void *initial,size_t,d2k_learning_round *,char *,size_t);
/* Model candidate only. Non-NULL *plan also requires successful lowering.
 * Caller frees result and plan and must re-execute/verify application before
 * confirmation. Session generation is the generation supplied at creation. */
d2k_syn_result d2k_tls_learning_propose(d2k_tls_learning *,char **plan,char *,size_t);
/* Queue the word returned by synthesis for the next step. Does not execute
 * or confirm a plan. Already measured words return CLOSED. */
d2k_learner_status d2k_tls_learning_request(d2k_tls_learning *,const size_t *,size_t);
/* Called between completed rounds. EXPERIMENT queues the next step;
 * CANDIDATE exports measured prefix behavior to the scheduler's ordinary
 * application verifier. Never returns CLEAR or claims application success.
 * Admission of blocking/comparable conditions remains the caller's duty. */
d2k_syn_status d2k_tls_learning_prepare(d2k_tls_learning *,d2k_vres *);
/* Blocking worker loop over admitted experiments. Caller must first exclude
 * healthy direct traffic and establish comparable initial conditions.
 * Starts with full original submission + READ; DIRECT_RESPONSE requests
 * application verification without synthesis. Otherwise brackets subsequent
 * questions by that measured control. Matching controls do not prove reset.
 * Stops on candidate, model closure, cancellation, context/local failure or
 * inconsistent evidence; no fallback catalog and no installation here. */
d2k_syn_status d2k_tls_learning_work(const d2k_tls_stream *,const d2k_experiment *,
    uint64_t,const void *,size_t,d2k_vres *);
#endif
