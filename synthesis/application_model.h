#ifndef D2K_APPLICATION_MODEL_H
#define D2K_APPLICATION_MODEL_H
#include "application_owner.h"
#include "continuous.h"
typedef struct d2k_application_model d2k_application_model;
typedef enum {D2K_APPLICATION_INVALID=0,D2K_APPLICATION_DOH=1,
    D2K_APPLICATION_HTTPS=2} d2k_application_kind;
typedef enum {D2K_APP_ERROR=-1,D2K_APP_REJECTED=0,D2K_APP_UNPREDICTED=1,
    D2K_APP_MATCH=2,D2K_APP_COUNTEREXAMPLE=3} d2k_application_update;
enum {D2K_APP_REPLY_DNS=1,D2K_APP_REPLY_TIMEOUT=2,D2K_APP_REPLY_INCOMPLETE=3,
    D2K_APP_REPLY_INVALID_DNS=4,D2K_APP_REPLY_HTTP=1024};
/* Single owned experience: operation 1 is its measured first TLS response,
 * operation 0 is a fixed DoH query, operation 2 completes the exchange and
 * releases this connection. HTTPS operation 3 records measured HTTP body bytes
 * before termination; operation 4, when available, records the last submitted
 * request's ACK class in bits 0..1 and received-payload class in bits 2..3.
 * Both are observation projections, not extra IO requests.
 * Its terminal output encodes verifier level<<32,
 * HTTP status<<8 and body-complete bit; full result remains in end snapshot.
 * This terminal state describes the owned experiment, not reset of the path.
 * Learns an untimed outcome
 * projection, retaining full observations for later timing/content refinement.
 * A prediction match is not a health verdict; a mismatch is not proof of DPI.
 * Different connections cannot be appended or treated as resets. */
d2k_application_model *d2k_application_model_new(const d2k_synthesis_feedback *,uint64_t);
/* HTTPS records its own completed/failed exchange through model_finish.
 * DoH query observations cannot be appended to this model. */
d2k_application_model *d2k_application_model_new_https(const d2k_synthesis_feedback *,uint64_t);
d2k_application_kind d2k_application_model_kind(const d2k_application_model *);
/* Copies phase evidence and borrowed request/response contents. Historical
 * entries remain valid until model_free; terminal models reject further adds. */
d2k_application_update d2k_application_model_add_http(d2k_application_model *,const d2k_application_http_observation *);
size_t d2k_application_model_http_count(const d2k_application_model *);
const d2k_application_http_observation *d2k_application_model_http_at(const d2k_application_model *,size_t);
void d2k_application_model_free(d2k_application_model *);
d2k_application_update d2k_application_model_add(d2k_application_model *,const d2k_application_observation *);
int d2k_application_model_finish(d2k_application_model *,const d2k_application_end *);
const d2k_application_end *d2k_application_model_end(const d2k_application_model *);
typedef struct {
    uint32_t ordinal,offset,length;
    unsigned ack,receipt;
    uint32_t acked_bytes;
} d2k_application_http_interval;
/* Last failed, fully submitted HTTP request on an owned connection. ACK:
 * 0 unknown, 1 none, 2 partial, 3 complete. Receipt: 0 unknown, 1 silent,
 * 2 payload observed. Neither observation proves application delivery. */
int d2k_application_model_http_interval(const d2k_application_model *,
    d2k_application_http_interval *);
const d2k_application_observation *d2k_application_model_history(const d2k_application_model *,size_t *);
/* Borrowed provisional model at historical origin, valid until add/free. */
d2k_transducer d2k_application_model_transducer(d2k_application_model *);
typedef enum {D2K_APP_QUESTION_CONTEXT=-1,D2K_APP_NO_WITNESS=0,
    D2K_APP_ASK_QUERY=1,D2K_APP_CHANGED=2,D2K_APP_REPRODUCED=3,
    D2K_APP_TRIAL_ENDED=4,D2K_APP_ASK_SESSION=5} d2k_application_question_status;
/* Tagged comparison witnesses: same application failure, different observed
 * cumulative ACK coverage. These are neither application success nor causes. */
/* 0 unknown, 1 outstanding bytes, 2 observed ACK covers all submitted bytes.
 * This projection is observational; it does not authenticate a peer or assert
 * delivery to the application. Keep fixed for a learning session's lifetime. */
static inline unsigned d2k_application_ack_coverage(const d2k_raw_transport *t) {
    if(!t || !t->available || !t->ack_seen || !t->sent_end ||
       t->sent_end>=UINT32_C(0x80000000) || t->acked_end>t->sent_end)return 0;
    return t->acked_end==t->sent_end?2u:1u;
}
#define D2K_APP_ACK_OUTSTANDING (UINT64_C(0x4000000000000000) | UINT64_C(1))
#define D2K_APP_ACK_COVERED (UINT64_C(0x4000000000000000) | UINT64_C(2))
/* ACK coverage of bytes submitted since the preceding query snapshot:
 * 0 unknown, 1 none, 2 partial, 3 complete. ACKs covering older traffic do
 * not count as progress of this query. Not proof of endpoint authenticity. */
static inline unsigned d2k_application_query_ack(
    const d2k_application_observation *history,size_t count) {
    if(!history || count<2 || history[count-1].query.dns_valid)return 0;
    const d2k_raw_transport *before=&history[count-2].transport;
    const d2k_raw_transport *after=&history[count-1].transport;
    if(!before->available || !after->available || !before->ack_seen || !after->ack_seen ||
       before->sent_end>=UINT32_C(0x80000000) || after->sent_end>=UINT32_C(0x80000000) ||
       before->acked_end>before->sent_end || after->acked_end>after->sent_end ||
       after->sent_end<=before->sent_end || after->acked_end<before->acked_end)return 0;
    if(after->acked_end<=before->sent_end)return 1;
    return after->acked_end==after->sent_end?3u:2u;
}
#define D2K_APP_QUERY_ACK UINT64_C(0x0800000000000000)
/* Failed query interval: 0 unknown, 1 no incoming payload observed,
 * 2 incoming payload observed (including possible retransmissions).
 * Requires a preceding query snapshot on this same owned connection. */
static inline unsigned d2k_application_payload_receipt(
    const d2k_application_observation *history,size_t count) {
    if(!history || count<2 || history[count-1].query.dns_valid)return 0;
    const d2k_raw_transport *before=&history[count-2].transport;
    const d2k_raw_transport *after=&history[count-1].transport;
    if(!before->available || !after->available ||
       after->received_payload_bytes<before->received_payload_bytes)return 0;
    return after->received_payload_bytes==before->received_payload_bytes?1u:2u;
}
#define D2K_APP_RX_SILENT (UINT64_C(0x2000000000000000) | UINT64_C(1))
/* Incomplete HTTP response: unknown/no final headers, headers without DATA,
 * or some DATA. Bytes are evidence of progress, never message completion. */
static inline unsigned d2k_application_response_progress(const d2k_ver_result *r) {
    if(!r || r->body_complete || r->status<200 || r->status>599 ||
       r->local_refusal || r->local_limit || r->unsupported)return 0;
    return r->body_bytes?2u:1u;
}
#define D2K_APP_HTTP_PROGRESS UINT64_C(0x1000000000000000)
#define D2K_APP_RX_PAYLOAD (UINT64_C(0x2000000000000000) | UINT64_C(2))
typedef struct {
    d2k_application_question_status status;
    unsigned ordinal;
    uint64_t reference,observed;
} d2k_application_question;
/* Compare a separate owned trial with a previously observed terminal failure.
 * Plan/trial/flow may differ; endpoint, resource, protocol and search generation
 * must agree. ASK_QUERY follows only the unresolved prefix of that witness.
 * CHANGED is an observed difference, not causal proof or sustained health.
 * Ordinal zero denotes a session-level difference (TLS, terminal outcome or
 * HTTPS body-byte progress), rather than an indexed DNS query.
 * Does not merge independent histories or presume a network-state reset. */
d2k_application_question d2k_application_model_question(const d2k_application_model *,
    const d2k_application_model *);
#endif
