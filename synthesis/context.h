#ifndef D2K_CONTEXT_H
#define D2K_CONTEXT_H
#include "stream.h"
typedef struct {uint8_t *bytes;size_t length;} d2k_learning_context;
/* Canonical byte encoding, never pointer identity or struct padding/hash.
 * initial identifies the externally established route/reset conditions;
 * generation and decoder_schema identify this experiment and interpretation.
 * This records those conditions; it cannot establish a remote reset itself. */
int d2k_tls_stream_context(const d2k_tls_stream *,const d2k_experiment *,
    uint64_t generation,uint64_t decoder_schema,const void *initial,size_t,
    d2k_learning_context *);
void d2k_learning_context_free(d2k_learning_context *);
#endif
