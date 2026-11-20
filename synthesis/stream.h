#ifndef D2K_STREAM_H
#define D2K_STREAM_H
#include "experiment.h"
#include "lower.h"
typedef struct {
    const d2k_trigger *trigger;
    const size_t *chunk_bytes;
    size_t chunks;
    int read_timeout_ms;
    size_t read_minimum;
} d2k_tls_stream;
/* Inputs 0..chunks-1 send up to chunk_bytes[input] next original bytes;
 * input chunks reads. Chunk sizes are model parameters, not stored plans.
 * Domain state is the number of original bytes submitted, not delivered. */
d2k_input_domain d2k_tls_stream_domain(const d2k_tls_stream *);
int d2k_tls_stream_preserved(void *,size_t);
/* Pure resolver for adaptive d2k_experiment channels; operation_context is the
   immutable stream, operation_count=chunks+1. No O(payload*alphabet) table. */
int d2k_tls_stream_operation(void *,size_t,size_t,d2k_experiment_operation *,size_t *);

typedef struct {
    d2k_experiment_operation *operations;
    size_t *indices,length;
    d2k_payload_piece *pieces;
    size_t piece_count;
    int complete,read_before_complete;
} d2k_stream_word;
int d2k_tls_stream_resolve(const d2k_tls_stream *,const size_t *,size_t,d2k_stream_word *);
void d2k_stream_word_free(d2k_stream_word *);
d2k_lower_status d2k_tls_stream_lower(const d2k_tls_stream *,const size_t *,size_t,
                                      char **,char *,size_t);
/* Connection/decoder from base; sequence comes from stream. Observations and
 * decoder callbacks retain original model input IDs, not expanded positions. */
d2k_experiment_status d2k_tls_stream_run(const d2k_tls_stream *,const d2k_experiment *,
    const size_t *,size_t,d2k_sample *,size_t *,d2k_raw_observation *,char *,size_t);
/* Local payload/lifecycle domain for path_run: SENDs, READ, OPEN, CLOSE.
 * Update domain.initial with each executed transition. CLOSED is not preserved;
 * OPEN resets only submitted-byte position, never the learned filter model. */
d2k_input_domain d2k_tls_stream_path_domain(const d2k_tls_stream *);
int d2k_tls_stream_path_preserved(void *,size_t);
/* Extended domain: final input chunks+3 continues the controlled application
   and releases the connection. Requires all original bytes. Only its completed
   state satisfies the application contract; acceptance still depends on the
   measured application output. OPEN after completion resets local position,
   never remote/model state. The executor must implement this macro action. */
d2k_input_domain d2k_tls_stream_application_domain(const d2k_tls_stream *);
int d2k_tls_stream_application_preserved(void *,size_t);
/* Append-only primitive numbering: READ=0, SEND(i)=i+1. Lifecycle indices
   follow operation_count as before. Immutable snapshots may append sizes
   without changing existing actions; trigger object must remain immutable. */
int d2k_tls_stream_stable_operation(void *,size_t,size_t,d2k_experiment_operation *,size_t *);
int d2k_tls_stream_prefix_equal(const void *,size_t,const void *,size_t);
d2k_input_domain d2k_tls_stream_stable_application_domain(const d2k_tls_stream *);
/* Immutable append-only action descriptors. Direction is chosen by the first
 * send and cannot change within that input. State tracks local byte coverage,
 * not peer delivery or filter reset. READ=0, SEND(i)=i+1. */
typedef struct d2k_stream_prefix d2k_stream_prefix;
/* Immutable compiled operation, owned by caller until all histories using it
 * are freed. Constructor copies content into the compiled program. */
d2k_stream_prefix *d2k_stream_prefix_new(const uint8_t *,size_t,size_t,unsigned);
d2k_stream_prefix *d2k_stream_prefix_partition_new(const uint8_t *,size_t,size_t,unsigned,
    size_t,const d2k_payload_piece *,size_t);
void d2k_stream_prefix_free(d2k_stream_prefix *);
const char *d2k_stream_prefix_program(const d2k_stream_prefix *);
typedef struct {size_t bytes;int reverse;const d2k_stream_prefix *prefix;} d2k_stream_action;

typedef struct {
    const d2k_trigger *trigger;
    const d2k_stream_action *actions;
    size_t count;
    int read_timeout_ms;
    size_t read_minimum;
} d2k_ordered_stream;
int d2k_ordered_stream_operation(void *,size_t,size_t,d2k_experiment_operation *,size_t *);
int d2k_ordered_stream_prefix_equal(const void *,size_t,const void *,size_t);
d2k_input_domain d2k_ordered_stream_domain(const d2k_ordered_stream *);
int d2k_ordered_stream_preserved(void *,size_t);
#endif
