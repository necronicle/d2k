#ifndef D2K_INFERENCE_H
#define D2K_INFERENCE_H
#include <stddef.h>
#include <stdint.h>
/* A hypothesis is a model, not a traffic transformation. IDs are allocated
 * by the model learner. Outcomes must encode protocol-level observations. */
typedef struct { size_t *ids; size_t count; uint64_t epoch; } d2k_belief;
typedef struct { const size_t *operations; size_t length; } d2k_input_word;
/* 1: predicts outcome; 0: model cannot predict; -1: evaluator error. */
typedef int (*d2k_predict)(void *, size_t, const d2k_input_word *, uint64_t *);
typedef enum { D2K_LEARN_ERROR=-1, D2K_LEARN_UNCHANGED=0,
               D2K_LEARN_REFINED=1, D2K_LEARN_CONTRADICTION=2,
               D2K_LEARN_STALE=3 } d2k_learn_status;
typedef struct { size_t index, guaranteed_eliminations; } d2k_question;
/* Minimax partition, no assumed probabilities. Unknown predictions belong
 * to every possible result bucket; they never count as eliminated. */
int d2k_choose_question(const d2k_belief *, const d2k_input_word *, size_t,
                        d2k_predict, void *, d2k_question *);
/* Inconclusive samples eliminate nothing. Contradiction preserves the old
 * belief and requests model-class expansion instead of inventing certainty. */
d2k_learn_status d2k_observe(d2k_belief *, uint64_t epoch,
    const d2k_input_word *, int conclusive, uint64_t outcome, d2k_predict, void *);
#endif
