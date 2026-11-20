#ifndef D2K_SYNTHESIS_SEARCH_H
#define D2K_SYNTHESIS_SEARCH_H
#include <stddef.h>
#include <stdint.h>
/* States denote joint protocol/filter states, not individual observations.
 * The model provider must keep observationally ambiguous states distinct. */
typedef enum { D2K_SYN_UNKNOWN, D2K_SYN_EDGE, D2K_SYN_INVALID, D2K_SYN_EDGE_ERROR } d2k_syn_edge_kind;
typedef struct { d2k_syn_edge_kind kind; size_t next; } d2k_syn_edge;
typedef struct {
    void *ctx;
    size_t states, operations, initial;
    d2k_syn_edge (*step)(void *, size_t, size_t);
    /* 1 = target predicate established in model; 0 = not established;
       -1 = evaluation failure. No error may become a successful candidate. */
    int (*goal)(void *, size_t);
} d2k_syn_model;
typedef enum {
    D2K_SYN_ERROR = -1,
    D2K_SYN_CLOSED = 0,
    D2K_SYN_EXPERIMENT = 1,
    D2K_SYN_CANDIDATE = 2,
    D2K_SYN_DIRECT = 3,
    /* Worker observed direct protocol response; application still unverified.
       Not produced by model search and not equivalent to CLEAR/DONE. */
    D2K_SYN_DIRECT_RESPONSE = 4
} d2k_syn_status;
typedef struct {
    d2k_syn_status status;
    size_t *operations;
    size_t length;
    size_t unresolved_state;
} d2k_syn_result;
/* Caller supplies operation semantics; there are no stored strategies.
 * CANDIDATE is valid only in the supplied model, never field confirmation.
 * CLOSED means exhausted current model/alphabet, never universal impossibility.
 * A model must remain immutable throughout this call. */
d2k_syn_result d2k_syn_search(const d2k_syn_model *);
void d2k_syn_result_free(d2k_syn_result *);
#endif
