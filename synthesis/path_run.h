#ifndef D2K_PATH_RUN_H
#define D2K_PATH_RUN_H
#include "experiment.h"
#include "continuous.h"
#include "alternatives.h"
#include "state_question.h"
#include "joint.h"
#include "../core/include/d2k_verdict.h"
typedef struct d2k_path_run d2k_path_run;
typedef enum {
    D2K_PATH_ACTION_INVALID=0, D2K_PATH_ACTION_EXPERIMENT,
    D2K_PATH_ACTION_OPEN, D2K_PATH_ACTION_CLOSE, D2K_PATH_ACTION_APPLICATION
} d2k_path_action_kind;
typedef struct {
    d2k_path_action_kind kind;
    size_t index;
} d2k_path_action;
typedef struct {
    d2k_sample sample;
    int64_t started_ms,finished_ms;
    d2k_raw_observation raw;
    d2k_experiment_operation operation;
    int operation_available;
    int interval_start;
    d2k_path_action action;
} d2k_path_event;
/* Reproject a recorded action into a larger dense alphabet without changing
 * its observation or the original history. Experiment indices are stable
 * only within the SAME append-only operation schema: existing descriptors,
 * resolver semantics and application contract must not change. This is not
 * permission to reinterpret an action or mutate a live channel's schema.
 * Output IDs remain scoped to the original history. Missing actions return
 * 0; malformed input -1; success 1. Failure leaves out unchanged. */
int d2k_path_event_project(const d2k_path_event *,size_t operations,
    int application,d2k_sample *out);
/* Borrows immutable experiment configuration. Input alphabet is its existing
 * operations followed by OPEN at operation_count and CLOSE at count+1.
 * Output IDs are local to this history: resolve them before persisting or
 * comparing models from different histories. No connection is a reset. */
d2k_path_run *d2k_path_run_new(const d2k_experiment *);
typedef struct {
    void *context;
    /* Continue the supplied live TLS IO; return zero after running the trial.
       Do not close the channel. The runner closes it before finish(), even
       after a failed run. No reentrant path access from either callback. */
    int (*run)(void *,const d2k_tls_io *);
    /* Finalize owned evidence after CLOSE: 1 classified network observation,
       0 uncertainty, -1 local failure. Always release per-trial resources. */
    int (*finish)(void *,uint64_t *);
    /* Optional local preparation before IO transfer; finish also cleans up
       after a failed preparation or unavailable IO. */
    int (*prepare)(void *,const d2k_path_run *);
} d2k_path_application;
/* Adds operation_count+2 = application continuation plus actual release.
   Only outputs from that action may satisfy a synthesis goal in this mode.
   Requires controlled tls_input; callbacks/context outlive the path. */
d2k_path_run *d2k_path_run_new_application(const d2k_experiment *,const d2k_path_application *);
/* Closed-channel append-only alphabet extension. Returns an independent path
 * view with reprojected evidence and rebuilt interval models, no pending word
 * and no IO; source is unchanged. New experiment is borrowed and immutable.
 * Old static operations must be unchanged, or immutable pure resolver contexts
 * must be identical or certified by operation_prefix_equal. Transport, decoder and app
 * contracts cannot change. Unknown samples and observation gaps are retained.
 * NULL on incompatibility/allocation failure. Shared callback contexts mean
 * source and result must not be driven concurrently. This mechanism does not
 * select new actions or establish their utility, equivalence or success. */
d2k_path_run *d2k_path_run_extend(const d2k_path_run *,const d2k_experiment *);
void d2k_path_run_free(d2k_path_run *);
/* Borrow the current channel for TLS continuation. No new connection or
   history entry. Caller must release TLS before freeing the path; further
   model operations are unavailable because these IO events are not yet in
   this raw observation alphabet. */
d2k_tls_io d2k_path_run_tls_io(d2k_path_run *);
/* Mark a gap in observation while no local channel is held. Retain all events,
 * but infer current state only from subsequent uninterrupted observations.
 * This is not a network reset; the new origin has unknown remote state.
 * Completed conclusive intervals retain one immutable learned model; repeated
 * marking at the same boundary is a no-op. Allocation failure leaves the
 * interval unchanged. 1 marked, 0 channel still held, -1 error. No IO. */
int d2k_path_run_interrupt(d2k_path_run *);
/* Use earlier uninterrupted intervals as provisional hypotheses. Re-locate
 * from every state using the current interval, never the old tail state.
 * Returns a question only, not proof that any hypothesis describes the path.
 * Unknown/incompatible earlier models do not constrain current inference. */
d2k_state_question d2k_path_run_relocate(const d2k_path_run *,const d2k_input_domain *);
/* Executes exactly one action. 1: recorded conclusive action, 0: recorded
 * uncertainty, -1: invalid action/allocation failure before network IO.
 * A connection-ending response is an ordinary path observation with its
 * terminal flag preserved in the output dictionary. Only CLOSE is then legal.
 * CLOSE denotes local resource release, not an acknowledged remote FIN. */
int d2k_path_run_step(d2k_path_run *,size_t,char *,size_t);
const d2k_path_event *d2k_path_run_history(const d2k_path_run *,size_t *);
int d2k_path_run_output(const d2k_path_run *,uint64_t,uint64_t *,int *);
/* Provisional action/output model of the current uninterrupted interval;
 * earlier intervals remain available through history, without asserting a
 * known transition across their boundaries. Timestamps are
 * retained in events but not inferred as timed transitions by this function.
 * Output IDs retain the history-local dictionary semantics. No network IO. */
int d2k_path_run_model(const d2k_path_run *,d2k_hypothesis **,d2k_transducer *);
/* Read-only disagreement query. The caller supplies its current action domain;
 * a returned word is a proposal, never automatically transmitted. */
d2k_alternatives d2k_path_run_alternatives(const d2k_path_run *,const d2k_input_domain *);
typedef enum { D2K_PATH_ERROR=-1,D2K_PATH_NO_QUESTION=0,
    D2K_PATH_ADVANCED=1,D2K_PATH_UNCERTAIN=2 } d2k_path_progress;
/* Select and execute one action, then let the caller consume the observation.
 * Keep a multi-action question while its predicted prefix agrees. Discard
 * on unexpected/unknown output, external history change or inapplicability.
 * Required domain supplies protocol/byte-ownership applicability at current
 * state; it is intersected with actual channel lifecycle. Prefer a known
 * disagreement, otherwise explore an undefined model edge. Unknown history
 * stops execution. NO_QUESTION is not application success or equivalence.
 * No concurrent access to path or domain during the call. Caller must update
 * domain state from each result before continuing. chosen is SIZE_MAX if no
 * action was selected. This does not authorize a production search by itself. */
d2k_path_progress d2k_path_run_advance(d2k_path_run *,const d2k_input_domain *,
    size_t *chosen,char *,size_t);
/* Goal-directed query from current chronological state. Contract uses raw
 * decoded output values, not history-local IDs. Intersects protocol domain
 * with channel lifecycle, including predicted connection-ending responses.
 * 1 search result, 0 uncertain history, -1 error. No IO; CANDIDATE is only
 * a model prediction and still requires execution/application confirmation. */
int d2k_path_run_synthesize(const d2k_path_run *,const d2k_synthesis_contract *,d2k_syn_result *);
typedef enum { D2K_TRIAL_ERROR=-1,D2K_TRIAL_NO_PATH=0,D2K_TRIAL_MEASURED=1,
    D2K_TRIAL_COUNTEREXAMPLE=2,D2K_TRIAL_OBSERVED_PREDICATE=3,D2K_TRIAL_UNCERTAIN=4
} d2k_trial_status;
typedef struct {
    d2k_trial_status status;
    d2k_syn_status selection;
    size_t begin,end; /* history interval [begin,end), local to this path */
    int prediction_changed;
    int reused_model;
} d2k_path_trial;
/* Synthesize and execute a finite goal-directed word in current context.
 * Stop at contradictory/unknown observation; retain actual events for model
 * refinement. OBSERVED_PREDICATE means ONLY the supplied predicate and input
 * preservation were observed; a TLS prefix predicate is not application proof.
 * Does not install a binding or set controller DONE. No concurrent mutation
 * of path/contract; callbacks must be pure. Supersedes pending exploration. */
d2k_path_trial d2k_path_run_trial(d2k_path_run *,const d2k_synthesis_contract *,char *,size_t);
/* Execute against an immutable hypothesis and initial possible-state bitmap.
 * Observation IDs must belong to this path's dictionary. Filter states after
 * every actual response; stop on undefined predictions or contradiction.
 * Candidate and observed predicate still require application verification. */
d2k_path_trial d2k_path_run_trial_belief(d2k_path_run *,const d2k_transducer *,
    const unsigned char *,const d2k_synthesis_contract *,char *,size_t);
/* Export the current measured TCP episode as a TLS candidate for the
 * controller application verifier. Requires the standard TLS decoder, full
 * original payload partition and non-HRR ServerHello. No IO or binding.
 * Only identity SEND_SLICE emissions are currently lowerable; no approximation
 * of packet mutations or response-dependent sends. A closed/uncertain episode
 * cannot export. generation belongs to the caller, which must also match the
 * experiment endpoint and trigger to its controller task. 1 candidate, 0 no
 * representable evidence, -1 invalid/local error. Never returns CLEAR/DONE. */
int d2k_path_run_tls_candidate(const d2k_path_run *,const d2k_trigger *,
    uint64_t generation,d2k_vres *);
/* Exact-input compilation before application execution, no success claim. */
int d2k_path_run_tls_input_program(const d2k_path_run *,const d2k_trigger *,uint64_t,d2k_vres *);
#endif
