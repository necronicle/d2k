#ifndef D2K_EVIDENCE_H
#define D2K_EVIDENCE_H
#include "distinguish.h"
#include "cancel.h"
typedef struct d2k_evidence d2k_evidence;
enum { D2K_SAMPLE_UNKNOWN=0, D2K_SAMPLE_OBSERVED=1, D2K_SAMPLE_TERMINAL=2 };
typedef struct { size_t operation; uint64_t observation; int conclusive; } d2k_sample;
typedef enum { D2K_EVIDENCE_ERROR=-1, D2K_EVIDENCE_OK=0,
    D2K_EVIDENCE_CONTEXT=1, D2K_EVIDENCE_CONFLICT=2 } d2k_evidence_status;
/* Exact opaque context bytes must include endpoint/protocol, experiment
 * generation, reset conditions and operation/observation schema versions.
 * This is a prefix model of evidence, not an inferred hidden-state machine. */
d2k_evidence *d2k_evidence_new(const void *,size_t,size_t operations);
void d2k_evidence_free(d2k_evidence *);
d2k_evidence_status d2k_evidence_add(d2k_evidence *,const void *,size_t,
                                    const d2k_sample *,size_t);
/* Snapshot valid until next add/free. Unseen or contradictory edges return
 * unknown. Observed edges are empirical predictions, not universal proofs. */
d2k_transducer d2k_evidence_model(d2k_evidence *);
typedef struct d2k_hypothesis d2k_hypothesis;
/* Hypothesize equality of two prefix states, close deterministic successor
 * equalities, and reject any observed output contradiction. Returns 1 on
 * construction, 0 if evidence refutes it or contains conflicting traces,
 * -1 on invalid input/allocation failure. The snapshot owns its storage. */
int d2k_evidence_merge(const d2k_evidence *,size_t,size_t,d2k_hypothesis **);
/* Greedy, provisional state merging from evidence only. Requires a shared
 * observed input before proposing a merge; successor closure must preserve
 * every observed output. Not a minimality or equivalence proof. Conflict
 * returns 0, allocation/argument error -1, constructed snapshot 1. */
int d2k_evidence_generalize(const d2k_evidence *, d2k_hypothesis **);
/* Cancellation returns -1 and no partial hypothesis; source evidence survives.
 * Control is borrowed only during this call, never retained by a snapshot. */
int d2k_evidence_generalize_controlled(const d2k_evidence *,d2k_hypothesis **,const d2k_inference_control *);
int d2k_evidence_merge_controlled(const d2k_evidence *,size_t,size_t,d2k_hypothesis **,const d2k_inference_control *);
d2k_transducer d2k_hypothesis_model(d2k_hypothesis *);
void d2k_hypothesis_free(d2k_hypothesis *);
#endif
