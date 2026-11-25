#ifndef D2K_PATH_WORK_H
#define D2K_PATH_WORK_H
#include "stream.h"
#include "path_run.h"
#include "verification_status.h"
/* Worker for an admitted measurement request. Keeps chronological observations
   across connections; OPEN is not reset evidence. Application verification
   interrupts current-state inference without discarding the earlier history.
   A direct TLS prefix returns
   immediately for controller application verification. Otherwise synthesized
   candidates require full original input, representable emissions and observed
   TLS prefix. Never returns CLEAR or diagnoses blocking from timeout/reset.
   No stored plan pool or probe budget. Cancellation is inherited from base.
   Does not install a binding. Current action grammar is stream slices/reads;
   CLOSED is relative to this grammar/model, not universal impossibility. */
d2k_syn_status d2k_tls_path_work(const d2k_tls_stream *,const d2k_experiment *,
    uint64_t generation,d2k_vres *);
typedef struct d2k_tls_path_session d2k_tls_path_session;
typedef struct {
    void *context;
    int (*prepare)(void *,const char *);
    int (*run)(void *,const d2k_tls_io *);
    int (*finish)(void *,uint64_t *);
    int (*accepted)(void *,uint64_t);
    /* Optional: owned outcome is consistent with failure before completing
       TLS. Enables a conditional packet-local SNI parser question, not a
       censorship verdict. 1 token-local question, 2 token-independent balanced
       packetization question, 0 not eligible, -1 unknown. */
    int (*token_question)(void *,uint64_t);
    /* Composition of a measured TCP partition is enabled for ordinary HTTPS
       application trials. DNS/DoH keeps its existing recovery path. */
    int allow_mixed_order;
} d2k_tls_application;
/* Application-led chronological learning: each complete input is followed by
   an owned application trial and actual release. Failure updates the model,
   not the legacy rejected-partition trie. Current grammar is direction-consistent slices
   followed by the fixed application experiment; no mid-input reads/pacing.
   With token_question enabled, a measured whole-input failure and parsed SNI
   interval can generate an interior cut from a packet-local parser hypothesis.
   Failure of that question ends this refinement branch, without nearby-cut
   enumeration or a universal impossibility/censorship claim. */
d2k_tls_path_session *d2k_tls_path_session_new_application(const d2k_tls_stream *,
    const d2k_experiment *,uint64_t,const d2k_tls_application *);
/* Refine packet boundaries using typed TLS response observations on the same
   connection. ServerHello is only a candidate, never application success.
   No HTTP resource or hidden name is invented. */
d2k_tls_path_session *d2k_tls_path_session_new_response(const d2k_tls_stream *,
    const d2k_experiment *,uint64_t);
/* Owns trigger, operation parameters, reply storage, decoder and chronological
   history. Cancellation descriptor is copied; its callback context remains
   borrowed and must outlive the session. Creation performs no network IO.
   next returns the same pending result without repeating IO until its
   disposition is implemented by the controller continuation path. With a
   controlled base.tls_input, it retains the measured connection for TLS IO;
   otherwise it releases it and marks the gap before separate verification.
   A single-channel base.sink is rejected: this worker may open several
   experiments, each of which requires a distinct evidence identity. */
d2k_tls_path_session *d2k_tls_path_session_new(const d2k_tls_stream *,
    const d2k_experiment *,uint64_t);
void d2k_tls_path_session_free(d2k_tls_path_session *);
d2k_syn_status d2k_tls_path_session_next(d2k_tls_path_session *,d2k_vres *);
const d2k_path_event *d2k_tls_path_session_history(const d2k_tls_path_session *,size_t *);
/* Controller supplies the result of its exact verification owner. Only NOT_MET
   for the current generation/program excludes that measured partition in this
   session's application context. APP_NOT_MET denotes a complete nonaccepted
   application response, not evidence against the packet partition, and does
   not resume synthesis. UNKNOWN/foreign/duplicate also changes nothing.
   No network IO, no fabricated event in raw history. 1 accepted, 0 ignored,
   -1 allocation/inconsistent recorded episode. Not a censorship diagnosis. */
int d2k_tls_path_session_disposition(d2k_tls_path_session *,uint64_t,const char *,
    d2k_verification_status);
/* Exact input/transport/observation configuration, excluding reply-buffer
   address and generation. No IO. Used before resuming a retained session. */
int d2k_tls_path_session_matches(const d2k_tls_path_session *,const d2k_tls_stream *,
    const d2k_experiment *);
int d2k_tls_path_session_probes(const d2k_tls_path_session *);
int d2k_tls_path_session_resumable(const d2k_tls_path_session *);
/* Extend an application session stopped at CLOSED after an actual released
   trial. Keeps all evidence, no IO; resumes model-guided selection. Caller
   supplies the refinement parameter; this API does not invent its rationale.
   1 added, 0 duplicate/inapplicable, -1 local failure. */
int d2k_tls_path_session_add_chunk(d2k_tls_path_session *,size_t);
/* Append a distinct direction/size action. Existing evidence keeps its exact
   meaning; caller must supply the measurement-based reason for this action. */
int d2k_tls_path_session_add_action(d2k_tls_path_session *,size_t,int reverse);
/* Append a generated prefix operation after model closure. Copies bytes into
 * an immutable owned program; no IO. Caller supplies measured rationale and
 * content. Offered timestamps are necessary, not proof of remote rejection.
 * The next continuation executes this question before generic exploration;
 * only one prefix question may be pending. Existing evidence is retained and
 * a failed trial may still lead to model questions, not an automatic closure.
 * Result still requires application validation. 1 added,0 ineligible/duplicate,
 * -1 allocation/compilation failure. Does not import or enumerate plans. */
int d2k_tls_path_session_add_prefix(d2k_tls_path_session *,const uint8_t *,size_t,size_t,unsigned);
/* Before any IO/history: replace the bootstrap whole-input action by one
 * explicit prefix question. Copies bytes; does not import old proof. A first
 * transformed success is CANDIDATE, never DIRECT_RESPONSE. A failed application
 * answer closes this question without exploring unrelated actions. */
int d2k_tls_path_session_initial_prefix(d2k_tls_path_session *,const uint8_t *,size_t,size_t,unsigned);
/* Same fresh application verification, preserving the full historical partition. */
int d2k_tls_path_session_initial_prefix_partition(d2k_tls_path_session *,const uint8_t *,
    size_t,size_t,unsigned,const d2k_payload_piece *,size_t);
/* Opt in at creation with base.tls_input matching the stream trigger exactly.
   On a returned candidate/direct prefix, borrow the original experiment IO.
   Session owns the socket until free; free the TLS client first. Such a session
   cannot resume inference from unrecorded application IO. */
d2k_tls_io d2k_tls_path_session_tls_io(d2k_tls_path_session *);
#endif
