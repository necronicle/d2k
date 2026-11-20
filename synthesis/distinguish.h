#ifndef D2K_DISTINGUISH_H
#define D2K_DISTINGUISH_H
#include "cancel.h"
#include <stddef.h>
#include <stdint.h>
typedef struct { size_t next; uint64_t observation; } d2k_transition;
/* 1 = known transition, 2 = terminal transition (do not extend this word),
 * 0 = unmodelled, -1 = evaluator failure.
 * Model instances must share operation and observation semantics. */
typedef struct {
    void *ctx;
    size_t states, initial, operations;
    int (*step)(void *, size_t, size_t, d2k_transition *);
} d2k_transducer;
typedef struct {
    void *ctx;
    size_t states,initial,operations;
    /* 1: applicable in this experiment, set next; 0: outside its domain;
       -1: error. Describes experiment semantics, not a strategy list. */
    int (*step)(void *,size_t,size_t,size_t *next);
} d2k_input_domain;
typedef enum { D2K_DIST_ERROR=-1, D2K_DIST_EQUIVALENT=0,
    D2K_DIST_WITNESS=1, D2K_DIST_INCOMPLETE=2 } d2k_dist_status;
typedef struct {
    d2k_dist_status status;
    size_t *operations, length;
    uint64_t left_observation, right_observation;
    unsigned known_outputs; /* bit 0: left, bit 1: right, at final operation */
    unsigned terminal_outputs; /* corresponding known output ends the word */
} d2k_distinction;
/* Shortest distinguishing input over the supplied finite alphabets/models.
 * Unknown transitions prevent an equivalence claim. No depth cutoff or
 * strategy list. INCOMPLETE prefers a shortest question with a prediction
 * from one model that can be refuted; if none exists, it returns a shortest
 * path to a transition unknown to both. Neither is a proven distinction.
 * Known-output bits identify available predictions.
 * A witness requires a reproducible initial/reset context. */
d2k_distinction d2k_distinguish(const d2k_transducer *, const d2k_transducer *);
/* Equivalence/closure is relative to this domain only. */
d2k_distinction d2k_distinguish_in(const d2k_transducer *,const d2k_transducer *,const d2k_input_domain *);
void d2k_distinction_free(d2k_distinction *);
/* Copy model predictions for every input BEFORE the last in a question.
 * 1 success (owned array, NULL for length <=1), 0 unknown, -1 invalid/error.
 * A terminal prefix cannot be continued and is rejected. */
int d2k_question_prefix(const d2k_transducer *,const size_t *,size_t,uint64_t **);
d2k_distinction d2k_distinguish_in_controlled(const d2k_transducer *,const d2k_transducer *,const d2k_input_domain *,const d2k_inference_control *);
#endif
