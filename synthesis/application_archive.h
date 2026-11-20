#ifndef D2K_APPLICATION_ARCHIVE_H
#define D2K_APPLICATION_ARCHIVE_H
#include "application_model.h"
#include <stdio.h>
/* Portable, versioned completed-experience records. No descriptors or native
 * struct layouts are stored. Caller owns file locking, flush/fsync and atomic
 * publication; a failed write must not be published as a complete record.
 * Read: 1 complete validated model, 0 clean EOF, -1 invalid/truncated/IO error.
 * A recovered record is historical evidence, never a fresh health verdict. */
int d2k_application_archive_write(FILE *,const d2k_application_model *);
int d2k_application_archive_read(FILE *,d2k_application_model **);
/* Historical proposal only. Generation/search/flow/seed may differ; target,
 * protocol, resource and probe shape must match. Returns an owned historical
 * record, never a verification result. Caller must remeasure in a fresh owned
 * experience before using its program. Reads one record at a time and restores
 * FILE position. 1 proposal, 0 none/cancelled, -1 invalid archive/context/IO. */
int d2k_application_archive_proposal(FILE *,const d2k_synthesis_feedback *,
    int,size_t,unsigned,const d2k_inference_control *,d2k_application_model **);
/* Proposal for revalidation with a different ClientHello length. All endpoint,
 * protocol, resource, timeout and success-depth checks remain. Historical input
 * and identities are returned unchanged. Caller must establish that the program
 * can be re-instantiated for the new input; this is never comparison evidence. */
int d2k_application_archive_transfer_proposal(FILE *,const d2k_synthesis_feedback *,
    int,size_t,unsigned,const d2k_inference_control *,d2k_application_model **);
typedef struct {
    const d2k_application_model *trial;
    const uint8_t *input;
    size_t input_length;
    int timeout_ms;
    size_t hello_wire;
} d2k_application_witness_context;
/* Select the deepest failed query in this search and exact probe context.
 * Trial must be empty. Stream position is restored; models are read one at a
 * time. Returned model is owned by caller. 1 witness, 0 none, -1 local error.
 * Does not infer blocking, merge connections, or accept a historical success. */
int d2k_application_archive_witness(FILE *,const d2k_application_witness_context *,
    d2k_application_model **);
/* Latest owned successful contrast to a completed failure, in its exact
 * search/protocol/input/probe context and through the requested query depth.
 * Streams records individually and restores FILE position. Caller owns result.
 * Historical contrast only: not a causal verdict, candidate or current health.
 * 1 found, 0 none, -1 invalid input/archive/IO. */
int d2k_application_archive_contrast(FILE *,const d2k_application_model *,unsigned,
    d2k_application_model **);
#endif
