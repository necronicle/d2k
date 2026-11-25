#ifndef D2K_EXPERIMENT_H
#define D2K_EXPERIMENT_H
#include "evidence.h"
#include "../detect/include/d2k_detect.h"
#include "../core/include/d2k_tls13.h"
struct d2k_raw_tls_sink;
struct d2k_stream_program;
typedef enum { D2K_EXPERIMENT_SEND, D2K_EXPERIMENT_READ, D2K_EXPERIMENT_PACKET,
               D2K_EXPERIMENT_SEND_SLICE } d2k_experiment_kind;
typedef struct {
    d2k_experiment_kind kind;
    const d2k_trigger *trigger;
    const char *program;
    uint32_t offset, next_offset;
    int timeout_ms;
    size_t minimum;
    /* SEND_SLICE takes these bytes from trigger; offset/next_offset remain
       explicit TCP sequence coordinates. Original trigger is never mutated. */
    size_t payload_offset,payload_length;
    const struct d2k_stream_program *tls_program;
} d2k_experiment_operation;
typedef struct {
    uint8_t ip[16], family;
    uint16_t port;
    uint32_t mark;
    int connect_ms, offer_ts;
    const d2k_detect_stop *cancel;
    const d2k_experiment_operation *operations;
    size_t operation_count;
    /* Pure local endpoint transition. Resolves an input symbol using bytes
       already submitted on THIS connection; never a filter-state/reset claim.
       Return 1 allowed, 0 invalid, -1 error. Borrowed referenced storage must
       remain immutable for the channel/history lifetime. Optional; when set,
       operations may be NULL. Each new connection starts at state zero. */
    void *operation_context;
    int (*resolve_operation)(void *,size_t,size_t,d2k_experiment_operation *,size_t *);

    uint8_t *reply;
    size_t reply_capacity;
    void *decoder_context;
    /* Optional per-word decoder reset, after validation and before network IO.
       Return 0 on success. This does not assert that the network was reset. */
    int (*begin_decode)(void *);
    /* Return 1 for an observation, 2 for a terminal observation,
       0 for unclassified, -1 for error.
       Timeout is an observation of a bounded wait, never a blocking verdict. */
    int (*decode)(void *, size_t, const d2k_raw_observation *,
                  const uint8_t *, size_t, uint64_t *);
    int (*decode_packet)(void *, size_t, const d2k_raw_observation *,
                         const d2k_raw_packet_event *, const uint8_t *, size_t, uint64_t *);
    /* READ feeds successive chunks to decode under ONE deadline until it
       returns terminal or the wait ends. Does not alter PACKET observations. */
    int read_to_terminal;
    /* Optional controlled TLS first write. Retain consumed stream bytes for
       continuation on this connection. Storage stays immutable until close. */
    const uint8_t *tls_input;
    size_t tls_input_length;
    /* Single-channel event sink, including subsequent TLS IO. The caller owns
       the unique experience identity and must not reuse it for another OPEN. */
    const struct d2k_raw_tls_sink *sink;
    /* Optional alternative to sink: allocate a distinct sink/experience for
       each opened connection before network IO. Return zero on success.
       Context and issued sinks must outlive their channels. */
    int (*make_sink)(void *,struct d2k_raw_tls_sink *);
    void *sink_context;
    /* Pure proof for immutable resolver snapshots: existing input indices
       retain their meaning at EVERY local state, not just observed states.
       Return 1 equivalent prefix, 0 incompatible, -1 invalid. */
    int (*operation_prefix_equal)(const void *,size_t,const void *,size_t);
} d2k_experiment;
/* Domain for a first-response question: one complete trigger submission,
 * then reads. Plan contents remain arbitrary. Experiments with subsequent
 * sends/retransmissions must supply their own domain. e must remain alive. */
d2k_input_domain d2k_first_response_domain(const d2k_experiment *e);

typedef enum { D2K_EXPERIMENT_ERROR=-1, D2K_EXPERIMENT_COMPLETE=0,
    D2K_EXPERIMENT_INCONCLUSIVE=1, D2K_EXPERIMENT_TERMINAL=2 } d2k_experiment_status;
typedef struct d2k_experiment_channel d2k_experiment_channel;
/* Explicit TCP lifetime for adaptive questions. open initializes the decoder
 * once; continue preserves both TCP and decoder state. The descriptor and its
 * referenced storage must remain alive and unchanged until close. An uncertain
 * or terminal execution seals the channel against further operations.
 * close releases local resources; it proves neither remote close nor filter
 * reset. Callers modeling multiple connections must record these boundaries.
 * Opening failures are reported in the raw observation, not as payload samples. */
d2k_experiment_channel *d2k_experiment_open(const d2k_experiment *,
    d2k_raw_observation *,char *,size_t);
d2k_experiment_status d2k_experiment_continue(d2k_experiment_channel *,
    const size_t *,size_t,d2k_sample *,size_t *,d2k_raw_observation *,char *,size_t);
void d2k_experiment_close(d2k_experiment_channel *);
/* Transfers channel IO to TLS after all controlled input bytes were submitted.
   The first TLS write must match tls_input and is not sent again. No new TCP
   connection is opened. TLS must be freed before channel close. Empty IO means
   the transcript cannot support continuation; ownership remains unchanged. */
d2k_tls_io d2k_experiment_tls_io(d2k_experiment_channel *);
/* Typed result of the last read through this borrowed IO. Buffered delivery
   is BYTES, EOF is FIN; local failures never become network timeouts.
   Valid only until channel close. Returns 0 for foreign IO or before a read. */
int d2k_experiment_tls_read_observation(const d2k_tls_io *,d2k_raw_observation *);
/* Last attempted operation in continue(), including failed wire execution;
   false if validation failed before IO. Copies the borrowed descriptor. */
int d2k_experiment_last_operation(const d2k_experiment_channel *,d2k_experiment_operation *);

/* Executes the word on one connection. completed counts its conclusive prefix.
   SEND output 0 means complete socket submission, not remote acceptance.
   No evidence is committed here: caller must establish matching context and
   repeatable initial conditions before using the trace for model learning. */
d2k_experiment_status d2k_experiment_run(const d2k_experiment *,
    const size_t *, size_t, d2k_sample *, size_t *, d2k_raw_observation *, char *, size_t);
#endif
