#ifndef D2K_LEARNER_H
#define D2K_LEARNER_H
#include "evidence.h"
typedef struct d2k_learner d2k_learner;
typedef enum { D2K_L_ERROR=-1,D2K_L_OBSERVED=0,D2K_L_QUESTION=1,
    D2K_L_CLOSED=2,D2K_L_CONFLICT=3,D2K_L_INCONCLUSIVE=4,D2K_L_STALE=5,
    D2K_L_CONTEXT=6 } d2k_learner_status;
typedef struct {
    uint64_t generation;
    const size_t *operations;
    size_t length;
    unsigned predicted,terminal;
    uint64_t observation;
} d2k_learning_question;
d2k_learner *d2k_learner_new(const void *,size_t,size_t operations);
/* Domain descriptor is copied; its ctx must remain immutable and alive.
 * Its semantics/version must be included in the evidence context. */
d2k_learner *d2k_learner_new_in(const void *,size_t,size_t,const d2k_input_domain *);
void d2k_learner_free(d2k_learner *);
/* Owned model snapshot: 1 constructed, 0 unavailable (pending/conflict/
 * inconclusive), -1 allocation/argument error. */
int d2k_learner_snapshot(const d2k_learner *,d2k_hypothesis **);
/* Exact recorded trace, never inferred transitions. 1 complete, 0 unknown,
 * -1 invalid/unavailable. Output is usable only on return 1. */
int d2k_learner_trace(const d2k_learner *,const size_t *,size_t,d2k_sample *);
/* Exact context includes the alphabet/decoder version and established reset
 * conditions. A new socket alone is not proof of equivalent initial state. */
d2k_learner_status d2k_learner_seed(d2k_learner *,const void *,size_t,const d2k_sample *,size_t);
/* Returned question storage remains owned by learner until submit/free.
 * Repeated next while pending returns the same generation, not a new trial.
 * CLOSED only means this finite abstraction offers no unmeasured transition. */
d2k_learner_status d2k_learner_next(d2k_learner *,d2k_learning_question *);
/* Schedule a synthesis-selected, not yet fully measured word. Copies it;
 * next/submit retain the usual generation and context checks. CLOSED means
 * this word is already recorded, not that learning is complete. */
d2k_learner_status d2k_learner_request(d2k_learner *,const size_t *,size_t);
/* Admit only the completed prefix of this exact question. An incomplete,
 * nonterminal execution stops further automatic querying; new external
 * evidence via seed is required before trying again. No retry budget. */
d2k_learner_status d2k_learner_submit(d2k_learner *,uint64_t,const void *,size_t,
                                    const d2k_sample *,size_t);
#endif
