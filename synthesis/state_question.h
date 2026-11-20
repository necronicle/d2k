#ifndef D2K_STATE_QUESTION_H
#define D2K_STATE_QUESTION_H
#include "tracking.h"
typedef enum {
    D2K_QUESTION_ERROR=-1, D2K_QUESTION_LOCATED=0,
    D2K_QUESTION_DISTINGUISH=1, D2K_QUESTION_EXPLORE=2,
    D2K_QUESTION_INDISTINGUISHABLE=3, D2K_QUESTION_UNKNOWN=4,
    D2K_QUESTION_CONTRADICTION=5, D2K_QUESTION_TERMINAL=6
} d2k_question_status;
typedef struct {
    d2k_question_status status;
    size_t prefix,possible,left,right;
    d2k_distinction word;
} d2k_state_question;
/* Recompute possible current states from chronological evidence, then select
 * a shortest known distinction between a pair, or an unknown edge to explore.
 * LOCATED is relative to this hypothesis; INDISTINGUISHABLE to this domain.
 * Neither asserts identification of the real network. The domain starts at
 * the CURRENT experiment state, not at the start of the historical trace.
 * Returned sequence is a proposal, not permission to transmit it blindly:
 * stop on terminal/unexpected observations and re-evaluate history. A third
 * possible state may terminate before this pair's distinguishing suffix.
 * Model and domain must remain immutable during the call. */
d2k_state_question d2k_question_after(const d2k_transducer *,
    const d2k_sample *,size_t,const d2k_input_domain *);
/* Initial bitmap has the same local-context semantics as d2k_track_from. */
d2k_state_question d2k_question_after_from(const d2k_transducer *,const unsigned char *,
    const d2k_sample *,size_t,const d2k_input_domain *);
void d2k_state_question_free(d2k_state_question *);
d2k_state_question d2k_question_after_from_controlled(const d2k_transducer *,const unsigned char *,
    const d2k_sample *,size_t,const d2k_input_domain *,const d2k_inference_control *);
#endif
