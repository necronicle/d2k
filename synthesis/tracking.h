#ifndef D2K_TRACKING_H
#define D2K_TRACKING_H
#include "evidence.h"
typedef enum {
    D2K_TRACK_ERROR=-1, D2K_TRACK_MATCH=0,
    D2K_TRACK_CONTRADICTION=1, D2K_TRACK_UNKNOWN=2
} d2k_tracking_status;
typedef struct {
    d2k_tracking_status status;
    size_t prefix, possible;
    unsigned char *states;
    int terminal;
} d2k_tracking;
/* Check one chronological trace from every possible initial model state.
 * MATCH means consistency with this model, not equivalence with the network.
 * states is an owned bitmap of possible tail states, valid only on MATCH.
 * prefix counts observations through the first contradiction/uncertainty,
 * or the complete trace on MATCH. Unknown reachable edges may lead outside
 * the model, so no later contradiction is asserted past such an edge.
 * Terminal is termination of this modeled system, not an implicit TCP reset.
 * Represent connection boundaries as inputs when modeling a persistent path.
 * The model must remain immutable throughout this call. */
d2k_tracking d2k_track(const d2k_transducer *,const d2k_sample *,size_t);
/* Restrict initial possibilities by an independently justified local-context
 * bitmap. NULL means all states; an empty bitmap is an error, not proof. */
d2k_tracking d2k_track_from(const d2k_transducer *,const unsigned char *,const d2k_sample *,size_t);
void d2k_tracking_free(d2k_tracking *);
d2k_tracking d2k_track_from_controlled(const d2k_transducer *,const unsigned char *,const d2k_sample *,size_t,const d2k_inference_control *);
#endif
