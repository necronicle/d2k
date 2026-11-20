#ifndef D2K_ALTERNATIVES_H
#define D2K_ALTERNATIVES_H
#include "evidence.h"
typedef enum { D2K_ALTERNATIVES_ERROR=-1,D2K_ALTERNATIVES_NONE=0,
    D2K_ALTERNATIVES_QUESTION=1,D2K_ALTERNATIVES_UNKNOWN=2 } d2k_alternative_status;
typedef struct {
    d2k_alternative_status status;
    size_t left_anchor,right_anchor;
    d2k_distinction word;
    uint64_t *prefix_observations; /* word.length-1 common predictions, owned */
} d2k_alternatives;
/* Candidate hypotheses identify the current end of ONE chronological trace
 * with an earlier prefix state. Reject identifications contradicted by any
 * observed suffix. Find a shortest known disagreement between two surviving
 * hypotheses, both positioned after the complete history (no reset).
 * NONE means no known disagreement within this finite hypothesis class/domain;
 * it is not equivalence or completeness. Unknown transitions cannot witness
 * disagreement. Domain describes applicability at the CURRENT experiment state.
 * Models must share one context/output dictionary; timing not modeled here. */
d2k_alternatives d2k_continuous_alternatives(const d2k_sample *,size_t,size_t,
    const d2k_input_domain *);
void d2k_alternatives_free(d2k_alternatives *);
d2k_alternatives d2k_continuous_alternatives_controlled(const d2k_sample *,size_t,size_t,const d2k_input_domain *,const d2k_inference_control *);
#endif
