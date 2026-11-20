#ifndef D2K_JOINT_H
#define D2K_JOINT_H
#include "distinguish.h"
#include "search.h"
#include "cancel.h"
typedef struct {
    d2k_input_domain endpoint;
    /* 1: original application input preserved in this state; 0: incomplete
       or changed; -1: model error. Uses endpoint.ctx. */
    int (*preserved)(void *,size_t);
    void *observation_context;
    /* 1: target protocol response, 0: not established, -1: decoder error.
       A model-predicted response is never a field verification. */
    int (*accepted)(void *,uint64_t);
} d2k_synthesis_contract;
/* Search product of learned behavior and endpoint semantics. UNKNOWN edges
 * yield experiments; a complete input plus predicted response yields a
 * candidate word requiring real execution and application verification. */
d2k_syn_result d2k_joint_search(const d2k_transducer *,const d2k_synthesis_contract *);
/* Common open-loop word for a nonempty bitmap of possible model states.
 * Candidate requires preserved input and accepted response in EVERY state
 * on the final action. Unknown edges yield experiments, never success.
 * Endpoint transitions must not depend on observed output. No network IO. */
d2k_syn_result d2k_joint_search_belief(const d2k_transducer *,const unsigned char *,
    const d2k_synthesis_contract *);
/* Preserve separate endpoint states when responses differ between hypotheses.
 * Feedback semantics match d2k_joint_search_feedback; every represented branch
 * must allow each action. The returned word remains open-loop, not a policy. */
d2k_syn_result d2k_joint_search_belief_feedback(const d2k_transducer *,const unsigned char *,
    const d2k_synthesis_contract *,int (*)(void *,size_t,uint64_t,size_t *),void *);
/* Optional observed-output update of endpoint's next state, before goal
 * evaluation. 1 updated/applicable, 0 impossible transition, -1 error.
 * Enables lifecycle state to depend on a predicted connection-ending reply. */
d2k_syn_result d2k_joint_search_feedback(const d2k_transducer *,const d2k_synthesis_contract *,
    int (*)(void *,size_t,uint64_t,size_t *),void *);
d2k_syn_result d2k_joint_search_feedback_controlled(const d2k_transducer *,const d2k_synthesis_contract *,
    int (*)(void *,size_t,uint64_t,size_t *),void *,const d2k_inference_control *);
d2k_syn_result d2k_joint_search_belief_feedback_controlled(const d2k_transducer *,const unsigned char *,
    const d2k_synthesis_contract *,int (*)(void *,size_t,uint64_t,size_t *),void *,const d2k_inference_control *);
#endif
