#ifndef D2K_CONTINUOUS_H
#define D2K_CONTINUOUS_H
#include "evidence.h"
/* Infer from ONE uninterrupted history. Root means its observed beginning,
 * never a reproducible network reset. current is the hypothesis positioned
 * AFTER that history; its lifetime is owned by the returned hypothesis.
 * 1 built, 0 unknown observation prevents alignment, -1 invalid/error.
 * Connection termination must be encoded in observations, not SAMPLE_TERMINAL.
 * Predictions remain provisional; timing, route/context changes and local
 * failures must be represented by the caller, not silently discarded. */
int d2k_continuous_build(const d2k_sample *,size_t,size_t,
    d2k_hypothesis **,d2k_transducer *current);
/* Shortest path from current state to an unknown transition, within domain.
 * Known cycles alone do not generate questions. Domain is positioned at the
 * current state. INCOMPLETE carries the question; EQUIVALENT means only no
 * reachable unknown edge in this hypothesis/domain, NOT network equivalence.
 * This explores missing transitions; testing/refuting inferred transitions
 * requires competing hypotheses or synthesis-directed application trials. */
d2k_distinction d2k_continuous_question(const d2k_transducer *,const d2k_input_domain *);
d2k_distinction d2k_continuous_question_controlled(const d2k_transducer *,const d2k_input_domain *,const d2k_inference_control *);
int d2k_continuous_build_controlled(const d2k_sample *,size_t,size_t,d2k_hypothesis **,d2k_transducer *,const d2k_inference_control *);
#endif
