#include "application_search.h"
#include "application_late.h"
#include "token_content.h"
#include "lower.h"
#include "../core/include/d2k_hello.h"
#include "../core/include/d2k_tls12.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <limits.h>
struct d2k_application_search {
    struct d2k_application_search *child;
    int seed_borrowed,baseline_borrowed;
    d2k_application_request request;
    d2k_experiment network;
    d2k_detect_stop cancel;
    d2k_synthesis_feedback identity;
    d2k_tls_probe_seed *seed;
    d2k_trigger trigger;
    size_t whole,wire;
    int timeout,started;
    FILE *archive;
    d2k_application_model *baseline;
    d2k_application_policy policy;
    d2k_tls_path_session *path;
    d2k_syn_status status;
    d2k_vres result;
    d2k_verification_owner *candidate_owner;
    d2k_synthesis_feedback pending_failure;
    int pending,feedback_fault;
    d2k_application_model *followup;
    d2k_synthesis_feedback followup_identity;
    char *followup_program;
    int followup_attempted,followup_status;
    d2k_application_model *late_observation;
    char *late_program;
    uint8_t *historical_prefix;
    size_t historical_length,historical_segment;
    unsigned historical_mods,historical_queries;
    d2k_payload_piece *historical_pieces;
    size_t historical_piece_count,historical_input_length;
};
static size_t application_hello(const d2k_application_search *s,const char *name,
    uint8_t *bytes,size_t capacity) {
    if(s->request.shape==D2K_SHAPE_LEGACY) {
        uint8_t random[32];
        return d2k_tls_probe_seed_random(s->seed,random)?0:
            d2k_tls12_probe_hello(random,name,s->wire,bytes,capacity);
    }
    static const uint8_t doh_alpn[]={2,'h','2'};
    static const uint8_t http_alpn[]={8,'h','t','t','p','/','1','.','1'};
    return d2k_tls_probe_hello(s->seed,name,s->wire,
        s->request.doh?doh_alpn:http_alpn,
        s->request.doh?sizeof doh_alpn:sizeof http_alpn,bytes,capacity);
}
int d2k_application_search_history(d2k_application_search *s,FILE *f) {
    if(!s || !f || s->started)return -1;
    if(!s->network.offer_ts || d2k_detect_stopped(s->network.cancel))return 0;
    d2k_inference_control control={s->cancel.fn,s->cancel.ctx};
    d2k_application_model *record=NULL;
    unsigned depth=s->request.doh_failure_query?s->request.doh_failure_query:1;
    int found=d2k_application_archive_transfer_proposal(f,&s->identity,s->timeout,s->wire,
        depth,&control,&record);
    if(found!=1)return found;
    const d2k_application_end *end=d2k_application_model_end(record);
    uint8_t *bytes=NULL;size_t length=0,segment=0;unsigned mods=0;char err[160];
    d2k_lower_status decoded=end && end->identity?
        d2k_lower_tls_prefix_read(end->identity->program,&bytes,&length,&segment,&mods,err,sizeof err):
        D2K_LOWER_INVALID;
    d2k_payload_piece *pieces=NULL;size_t count=0;
    if(decoded==D2K_LOWER_UNSUPPORTED && end->input_length)
        decoded=d2k_lower_tls_prefix_partition_read(end->identity->program,end->input_length,
            &bytes,&length,&segment,&mods,&pieces,&count,err,sizeof err);
    int loaded=0;
    if(decoded==D2K_LOWER_OK && !d2k_detect_stopped(s->network.cancel)) {
        size_t cap=d2k_raw_segment_max();
        if(segment>cap)segment=cap;
        free(s->historical_prefix);
        free(s->historical_pieces);
        s->historical_prefix=bytes;s->historical_length=length;
        s->historical_segment=segment;s->historical_mods=mods;
        s->historical_queries=end->result.doh_replies;bytes=NULL;loaded=1;
        s->historical_pieces=pieces;s->historical_piece_count=count;
        s->historical_input_length=end->input_length;pieces=NULL;
    }
    free(bytes);free(pieces);d2k_application_model_free(record);
    return decoded==D2K_LOWER_ERROR?-1:loaded;
}
int d2k_application_search_feedback(d2k_application_search *s,const d2k_synthesis_feedback *e,
    d2k_verification_status outcome) {
    if(s && s->child) {
        if(e && s->candidate_owner && e->generation==s->pending_failure.generation &&
           e->search_id==s->pending_failure.search_id &&
           !memcmp(e->trial_id,s->pending_failure.trial_id,sizeof e->trial_id)) {
            d2k_verification_status old=d2k_verification_accept(s->candidate_owner,e);
            if(old==D2K_VF_CONFLICT || old==D2K_VF_ERROR){s->feedback_fault=1;return -1;}
            return 0;
        }
        return d2k_application_search_feedback(s->child,e,outcome);
    }
    if(!s || !e || outcome!=D2K_VF_NOT_MET || s->status!=D2K_SYN_CANDIDATE)return 0;
    if(s->feedback_fault)return -1;
    if(!s->candidate_owner) {
        d2k_synthesis_feedback identity=s->identity;
        identity.program=s->result.program;
        memset(identity.plan_id,0,sizeof identity.plan_id);
        s->candidate_owner=d2k_verification_new(&identity,1);
        if(!s->candidate_owner){s->feedback_fault=1;return -1;}
    }
    d2k_verification_status actual=d2k_verification_accept(s->candidate_owner,e);
    if(actual==D2K_VF_CONFLICT || actual==D2K_VF_ERROR) {
        s->pending=0;s->feedback_fault=1;return -1;
    }
    if(actual!=D2K_VF_NOT_MET || s->pending)return 0;
    const d2k_synthesis_feedback *identity=d2k_verification_identity(s->candidate_owner);
    s->pending_failure=*e;
    s->pending_failure.target=identity->target;s->pending_failure.ip=identity->ip;
    s->pending_failure.resource=identity->resource;s->pending_failure.program=identity->program;
    s->pending=1;return 1;
}
const d2k_synthesis_feedback *d2k_application_search_pending_failure(const d2k_application_search *s) {
    if(s && s->child)return d2k_application_search_pending_failure(s->child);
    return s && s->pending && !s->feedback_fault?&s->pending_failure:NULL;
}
static int followup_query(void *ctx,d2k_application_model *model,d2k_application_update update) {
    d2k_application_search *s=ctx;
    if(update==D2K_APP_ERROR || update==D2K_APP_REJECTED)return -1;
    size_t n=0;const d2k_application_observation *q=d2k_application_model_history(model,&n);
    if(!q || !n)return -1;
    if(!q[n-1].query.dns_valid || !d2k_application_query_complete(&q[n-1].query.response))return 0;
    return q[n-1].query.ordinal<s->pending_failure.budget_requests;
}
int d2k_application_search_remeasure(d2k_application_search *s,const d2k_application_model **out) {
    if(s && s->child)return d2k_application_search_remeasure(s->child,out);
    if(out)*out=NULL;
    if(!s || !out || s->feedback_fault)return -1;
    if(!s->pending)return 0;
    if(s->followup_attempted) {
        *out=s->followup;return s->followup_status;
    }
    s->followup_attempted=1;s->followup_status=-1;
    if(d2k_detect_stopped(s->network.cancel) || s->policy.experience==UINT64_MAX)return -1;
    size_t length=strlen(s->result.program);
    s->followup_program=malloc(length+1);
    if(!s->followup_program)return -1;
    memcpy(s->followup_program,s->result.program,length+1);
    s->followup_identity=s->identity;
    if(d2k_application_identify_trial(&s->followup_identity,s->followup_program))return -1;
    d2k_experiment network=s->network;
    network.tls_input=NULL;network.tls_input_length=0;
    network.make_sink=NULL;network.sink_context=NULL;
    d2k_ver_result result;
    if(s->request.doh)
        (void)d2k_application_doh_learn(&s->followup_identity,++s->policy.experience,
            &network,s->seed,s->timeout,s->wire,followup_query,s,&s->followup,&result);
    else
        (void)d2k_application_https_learn(&s->followup_identity,++s->policy.experience,
            &network,s->seed,s->timeout,s->wire,&s->followup,&result);
    if(s->result.probes<INT_MAX)s->result.probes++;
    *out=s->followup;
    const d2k_application_end *end=d2k_application_model_end(s->followup);
    if(!s->followup || d2k_application_save(s->archive,s->followup,&result) || !end ||
       !end->network_evidence || result.local_refusal || result.local_limit ||
       result.unsupported || d2k_detect_stopped(s->network.cancel))return -1;
    s->followup_status=1;return 1;
}
static int start_path(d2k_application_search *s,uint64_t experience) {
    if(d2k_application_policy_init(&s->policy,&s->identity,s->baseline,s->seed,
       s->trigger.payload,s->trigger.len,experience,s->timeout,s->wire,s->archive))return -1;
    if(s->policy.required_queries<s->request.doh_failure_query)
        s->policy.required_queries=s->request.doh_failure_query;
    if(s->policy.required_queries<s->historical_queries)
        s->policy.required_queries=s->historical_queries;
    s->whole=s->trigger.len;
    d2k_tls_stream stream={&s->trigger,&s->whole,1,s->timeout,1};
    s->network.tls_input=s->trigger.payload;s->network.tls_input_length=s->trigger.len;
    s->network.make_sink=d2k_application_policy_sink;s->network.sink_context=&s->policy;
    d2k_tls_application application=d2k_application_policy_callbacks(&s->policy);
    s->path=d2k_tls_path_session_new_application(&stream,&s->network,s->identity.generation,&application);
    return s->path?0:-1;
}
static int late_query(void *ctx,d2k_application_model *model,d2k_application_update update) {
    const unsigned *required=ctx;size_t count=0;
    const d2k_application_observation *h=d2k_application_model_history(model,&count);
    if(update==D2K_APP_ERROR || update==D2K_APP_REJECTED || !count || !h)return -1;
    return h[count-1].query.dns_valid && d2k_application_query_complete(&h[count-1].query.response) &&
        h[count-1].query.ordinal<*required;
}
static void ask_prefix_content(d2k_application_search *s) {
    if(s->status!=D2K_SYN_CLOSED || !s->network.offer_ts)return;
    uint8_t *masked=malloc(s->trigger.len);if(!masked)goto local;
    int changed=d2k_token_content_question(&s->trigger,masked,s->trigger.len);
    if(changed<0){free(masked);goto local;}
    if(!changed){free(masked);return;}
    /* Same framing, timestamp operation and original input: first measure the
       prefix envelope itself, then change only its parsed name bytes. Neither
       prior failure nor a timestamp offer proves endpoint rejection. The owned
       application verifier decides whether either concrete question worked. */
    for(unsigned phase=0;phase<2 && s->status==D2K_SYN_CLOSED;phase++) {
        if(d2k_detect_stopped(s->network.cancel)){free(masked);goto local;}
        size_t segment=d2k_raw_segment_max();
        if(segment>s->trigger.len)segment=s->trigger.len;
        int added=d2k_tls_path_session_add_prefix(s->path,phase?masked:s->trigger.payload,
            s->trigger.len,segment,0);
        if(added<0){free(masked);goto local;}
        if(added)s->status=d2k_tls_path_session_next(s->path,&s->result);
    }
    free(masked);return;
local:
    s->status=D2K_SYN_ERROR;s->result.program[0]=0;s->result.program_len=0;
    snprintf(s->result.reason,sizeof s->result.reason,"prefix content question unavailable or cancelled");
}
static void ask_control_content(d2k_application_search *s) {
    const d2k_application_control *c=&s->request.control;
    unsigned epoch=0;
    for(size_t i=0;i<sizeof c->epoch;i++)epoch|=c->epoch[i];
    if(s->status!=D2K_SYN_CLOSED || !s->network.offer_ts || !epoch ||
       !c->incarnation || !c->bytes || !c->low_port || !c->high_port ||
       c->transport!=6 || c->family!=s->request.family ||
       !memchr(c->name,0,sizeof c->name) || !c->name[0] ||
       !strcmp(c->name,s->request.target))return;
    for(const unsigned char *p=(const unsigned char *)c->name;*p;p++)
        if(!((*p>='a' && *p<='z') || (*p>='A' && *p<='Z') ||
             (*p>='0' && *p<='9') || *p=='.' || *p=='-'))return;
    uint8_t *prefix=malloc(sizeof s->trigger.payload);
    if(!prefix)goto local;
    size_t n=application_hello(s,c->name,prefix,sizeof s->trigger.payload);
    if(!n || d2k_detect_stopped(s->network.cancel)){free(prefix);goto local;}
    size_t segment=d2k_raw_segment_max();if(segment>n)segment=n;
    int added=d2k_tls_path_session_add_prefix(s->path,prefix,n,segment,0);
    free(prefix);
    if(added<0)goto local;
    if(added)s->status=d2k_tls_path_session_next(s->path,&s->result);
    return;
local:
    s->status=D2K_SYN_ERROR;s->result.program[0]=0;s->result.program_len=0;
    snprintf(s->result.reason,sizeof s->result.reason,"passive control content question unavailable or cancelled");
}
static int ask_late_question_from(d2k_application_search *s,const d2k_application_model *reference,int composed) {
    unsigned char *seen=NULL;
    char fault[256]="question unavailable or local resources exhausted";
    if(s->status!=D2K_SYN_CLOSED || s->late_program)return 0;
    int question=composed?d2k_application_late_composed_question(reference,&s->late_program):
        d2k_application_late_question(reference,&s->late_program);
    if(!question)return 0;
    s->result.program[0]=0;s->result.program_len=0;s->result.have_arm=0;
    snprintf(s->result.reason,sizeof s->result.reason,"measured late request partition did not meet the application contract");
    size_t reference_count=0;
    (void)d2k_application_model_history(reference,&reference_count);
    unsigned required=s->policy.required_queries;
    if(reference_count>UINT_MAX)goto local;
    if(required<reference_count)required=(unsigned)reference_count;
    seen=calloc(D2K_LATE_SEEN_BYTES,1);if(!seen)goto local;
    for(;;) {
    if(d2k_detect_stopped(s->network.cancel)) {
        snprintf(fault,sizeof fault,"cancelled");goto local;
    }
    if(question<0 || s->policy.experience==UINT64_MAX)goto local;
    d2k_synthesis_feedback id=s->identity;
    if(d2k_application_identify_trial(&id,s->late_program))goto local;
    d2k_experiment net=s->network;
    net.tls_input=NULL;net.tls_input_length=0;net.make_sink=NULL;net.sink_context=NULL;
    d2k_ver_result result;
    if(s->request.doh)
        (void)d2k_application_doh_learn(&id,++s->policy.experience,&net,s->seed,s->timeout,s->wire,
            late_query,&required,&s->late_observation,&result);
    else
        (void)d2k_application_https_learn(&id,++s->policy.experience,&net,s->seed,s->timeout,s->wire,
            &s->late_observation,&result);
    if(s->result.probes<INT_MAX)s->result.probes++;
    const d2k_application_end *end=d2k_application_model_end(s->late_observation);
    if(!end) {
        snprintf(fault,sizeof fault,"trial has no completed owned model: %.160s",result.reason);goto local;
    }
    int archive_failed=d2k_application_save(s->archive,s->late_observation,&result);
    if(archive_failed || result.local_refusal || result.local_limit || result.unsupported) {
        snprintf(fault,sizeof fault,"local refusal=%d limit=%d unsupported=%d: %.160s",
            result.local_refusal,result.local_limit,result.unsupported,result.reason);goto local;
    }
    if(d2k_detect_stopped(s->network.cancel)) {
        snprintf(fault,sizeof fault,"cancelled");goto local;
    }
    if(!end->network_evidence) {
        snprintf(fault,sizeof fault,"trial has no owned network evidence: %.160s",result.reason);goto local;
    }
    d2k_application_question comparison=d2k_application_model_question(reference,s->late_observation);
    if(comparison.status==D2K_APP_QUESTION_CONTEXT || comparison.status==D2K_APP_NO_WITNESS) {
        snprintf(fault,sizeof fault,"comparison context=%d",comparison.status);goto local;
    }
    if(s->request.doh?(d2k_application_query_complete(&result) && result.doh_replies>=required):
       result.level==D2K_VER_APPLICATION && result.status==200 && result.body_complete) {
        size_t length=strlen(s->late_program);
        if(!length || length>=sizeof s->result.program)goto local;
        int probes=s->result.probes;
        memset(&s->result,0,sizeof s->result);
        s->result.verdict=D2K_V_INCONCLUSIVE;s->result.owns_search=1;
        s->result.probes=probes;s->result.synthesis_generation=s->identity.generation;
        memcpy(s->result.program,s->late_program,length+1);s->result.program_len=length;
        /* The diagnostic witness proposes a plan; the controller still owes
           an independent exact-flow application trial and complete DONE.
           A new program cannot inherit feedback ownership from the old one. */
        d2k_verification_free(s->candidate_owner);s->candidate_owner=NULL;
        memset(&s->pending_failure,0,sizeof s->pending_failure);s->pending=0;
        d2k_application_model_free(s->followup);s->followup=NULL;
        free(s->followup_program);s->followup_program=NULL;
        memset(&s->followup_identity,0,sizeof s->followup_identity);
        s->followup_attempted=s->followup_status=0;
        s->status=D2K_SYN_CANDIDATE;
        snprintf(s->result.reason,sizeof s->result.reason,
            "measured late request partition met the diagnostic application contract; exact-flow controller verification required");
        free(seen);return 1;
    }
    char *next=NULL;
    int refined=composed?d2k_application_late_composed_refine(reference,s->late_observation,seen,D2K_LATE_SEEN_BYTES,&next):
        d2k_application_late_refine(reference,s->late_observation,seen,D2K_LATE_SEEN_BYTES,&next);
    if(refined<0)goto local;
    if(!refined){free(seen);return 1;}
    d2k_application_model_free(s->late_observation);s->late_observation=NULL;
    free(s->late_program);s->late_program=next;
    }
local:
    free(seen);
    s->status=D2K_SYN_ERROR;
    snprintf(s->result.reason,sizeof s->result.reason,
        "late application question lacks owned execution evidence: %s",fault);
    return 1;
}
static void ask_late_question(d2k_application_search *s) {
    (void)ask_late_question_from(s,s->baseline,0);
}
static int refine_application(d2k_application_search *s) {
    const d2k_application_model *trace=NULL;
    if(d2k_application_search_remeasure(s,&trace)!=1)return -1;
    size_t n=0;const d2k_application_observation *history=d2k_application_model_history(trace,&n);
    /* A new horizon is justified only by an actual deeper failed query.
       Healthy reproduction or an already-covered failure needs another
       hypothesis, not a new epoch running the same question forever. */
    const d2k_application_end *end=d2k_application_model_end(trace);
    if((end && end->result.body_complete) || (history && n && history[n-1].query.dns_valid))return 2;
    d2k_syn_status previous=s->status;
    s->status=D2K_SYN_CLOSED;
    if(ask_late_question_from(s,trace,1)) {
        s->pending=0;return 3;
    }
    s->status=previous;
    if(!history || n<=s->policy.required_queries)return 0;
    d2k_experiment network=s->network;
    network.tls_input=NULL;network.tls_input_length=0;network.make_sink=NULL;network.sink_context=NULL;
    d2k_application_search *child=d2k_application_search_new(&s->request,&network,
        s->identity.generation,s->timeout,s->wire,s->archive);
    if(!child)return -1;
    child->seed=s->seed;child->seed_borrowed=1;
    child->baseline=s->followup;child->baseline_borrowed=1;
    child->trigger=s->trigger;child->started=1;
    if(d2k_t13_random(child->identity.trial_id,sizeof child->identity.trial_id) ||
       start_path(child,s->policy.experience)) {
        d2k_application_search_free(child);return -1;
    }
    s->child=child;
    child->status=d2k_tls_path_session_next(child->path,&child->result);
    ask_prefix_content(child);
    ask_control_content(child);
    ask_late_question(child);
    return 1;
}
static const char direct[]="d2k-plan 1 8\nid 00000000000000000000000000000001\nproto tcp tls\nwire tcp-template-v1\norder forward\n";
static int first_query(void *ctx,d2k_application_model *model,d2k_application_update update) {
    d2k_application_search *s=ctx;
    if(update==D2K_APP_ERROR || update==D2K_APP_REJECTED)return -1;
    size_t count=0;const d2k_application_observation *history=d2k_application_model_history(model,&count);
    if(!history || !count)return -1;
    const d2k_doh_observation *q=&history[count-1].query;
    if(!q->dns_valid || !d2k_application_query_complete(&q->response))return 0;
    return q->ordinal<s->request.doh_failure_query;
}
int d2k_application_search_matches(const d2k_application_search *s,const d2k_application_request *r,
    const d2k_experiment *e,uint64_t generation,int timeout,size_t wire) {
    if(!s || !r || !e)return 0;
    /* Control is a frozen proposal source copied at creation. Unrelated live
       traffic must not reset a retained target experience or alter its input. */
    const d2k_application_request *a=&s->request;
    return s->identity.generation==generation && s->timeout==timeout && s->wire==wire &&
        a->search_id==r->search_id && a->port==r->port && a->family==r->family &&
        a->transport==r->transport && a->shape==r->shape && a->by_addr==r->by_addr &&
        a->doh==r->doh && a->ech==r->ech && a->doh_failure_query==r->doh_failure_query &&
        !strncmp(a->target,r->target,sizeof a->target) && !strncmp(a->ip,r->ip,sizeof a->ip) &&
        !strncmp(a->resource,r->resource,sizeof a->resource) &&
        !strncmp(a->ech_origin,r->ech_origin,sizeof a->ech_origin) &&
        s->network.family==e->family && s->network.port==e->port &&
        !memcmp(s->network.ip,e->ip,sizeof e->ip) && s->network.mark==e->mark &&
        s->network.connect_ms==e->connect_ms && s->network.offer_ts==e->offer_ts &&
        ((!s->network.cancel && !e->cancel) || (s->network.cancel && e->cancel &&
          s->cancel.fn==e->cancel->fn && s->cancel.ctx==e->cancel->ctx)) &&
        !e->sink && !e->make_sink && !e->tls_input && !e->operations && !e->operation_count &&
        !e->resolve_operation && !e->decode && !e->decode_packet;
}
d2k_application_search *d2k_application_search_new(const d2k_application_request *r,
    const d2k_experiment *network,uint64_t generation,int timeout,size_t wire,FILE *archive) {
    uint8_t ip[16]={0};
    if(!r || !network || !generation || !r->search_id || r->ech || r->by_addr ||
       (!r->doh && r->doh_failure_query) ||
       r->transport!=6 || (r->shape!=D2K_SHAPE_MODERN && !(r->shape==D2K_SHAPE_LEGACY && !r->doh)) || timeout<=0 || !wire ||
       !memchr(r->target,0,sizeof r->target) || !r->target[0] ||
       !memchr(r->ip,0,sizeof r->ip) || !memchr(r->resource,0,sizeof r->resource) ||
       r->resource[0]!='/' || (r->family!=4 && r->family!=6) ||
       inet_pton(r->family==6?AF_INET6:AF_INET,r->ip,ip)!=1 ||
       r->family!=network->family || r->port!=network->port || !r->port ||
       memcmp(ip,network->ip,r->family==6?16:4) || network->sink || network->make_sink ||
       network->tls_input || network->operations || network->operation_count ||
       network->resolve_operation || network->decode || network->decode_packet)return NULL;
    d2k_application_search *s=calloc(1,sizeof *s);if(!s)return NULL;
    s->request=*r;s->timeout=timeout;s->wire=wire;s->archive=archive;
    s->network=(d2k_experiment){.family=network->family,.port=network->port,
        .mark=network->mark,.connect_ms=network->connect_ms,.offer_ts=network->offer_ts,
        .reply_capacity=4096};
    memcpy(s->network.ip,network->ip,sizeof s->network.ip);
    if(network->cancel){s->cancel=*network->cancel;s->network.cancel=&s->cancel;}
    s->identity=(d2k_synthesis_feedback){.generation=generation,.search_id=r->search_id,
        .target=s->request.target,.ip=s->request.ip,.resource=s->request.resource,.program=direct,
        .doh=r->doh,.family=r->family,.transport=6,.port=r->port,.shape=r->shape};
    s->identity.plan_id[sizeof s->identity.plan_id-1]=1;
    s->status=D2K_SYN_ERROR;s->result.verdict=D2K_V_INCONCLUSIVE;s->result.owns_search=1;
    return s;
}
d2k_syn_status d2k_application_search_next(d2k_application_search *s,d2k_vres *out) {
    if(!out)return D2K_SYN_ERROR;
    memset(out,0,sizeof *out);out->verdict=D2K_V_INCONCLUSIVE;out->owns_search=1;
    if(!s)return D2K_SYN_ERROR;
    if(s->feedback_fault) {
        snprintf(out->reason,sizeof out->reason,"contradictory application verification evidence");
        return D2K_SYN_ERROR;
    }
    if(s->pending && !s->child) {
        int refined=refine_application(s);
        if(refined==3){*out=s->result;out->generated_input=1;return s->status;}
        if(refined!=1) {
            snprintf(out->reason,sizeof out->reason,refined<0?
                "owned follow-up unavailable":refined==2?"owned follow-up did not reproduce the application failure":"follow-up does not justify a deeper application contract");
            out->probes=s->result.probes;
            return refined!=0?D2K_SYN_ERROR:D2K_SYN_CLOSED;
        }
    }
    if(s->child) {
        d2k_syn_status status=d2k_application_search_next(s->child,out);
        out->probes=out->probes>INT_MAX-s->result.probes?INT_MAX:out->probes+s->result.probes;
        return status;
    }
    if(s->started){*out=s->result;out->generated_input=1;return s->status;}
    s->started=1;
    if(d2k_detect_stopped(s->network.cancel)) {
        snprintf(s->result.reason,sizeof s->result.reason,"application synthesis cancelled before IO");goto done;
    }
    s->seed=d2k_tls_probe_seed_new();
    if(!s->seed || d2k_t13_random(s->identity.trial_id,sizeof s->identity.trial_id))goto local;
    s->trigger.len=application_hello(s,s->request.target,s->trigger.payload,sizeof s->trigger.payload);
    size_t offset=0,length=0;
    if(!s->trigger.len || d2k_hello_sni(s->trigger.payload,s->trigger.len,&offset,&length))goto local;
    s->trigger.sni_off=(int)offset;s->trigger.sni_len=(int)length;
    s->trigger.accept=D2K_ACCEPT_SERVERHELLO;
    snprintf(s->trigger.name,sizeof s->trigger.name,"tls:%s",s->request.target);
    d2k_ver_result result;
    if(s->request.doh)
        (void)d2k_application_doh_learn(&s->identity,1,&s->network,s->seed,s->timeout,s->wire,
            first_query,s,&s->baseline,&result);
    else
        (void)d2k_application_https_learn(&s->identity,1,&s->network,s->seed,s->timeout,s->wire,
            &s->baseline,&result);
    s->result.probes=1;
    const d2k_application_end *baseline=d2k_application_model_end(s->baseline);
    if(d2k_application_save(s->archive,s->baseline,&result))goto local;
    if(d2k_detect_stopped(s->network.cancel) || !baseline || !baseline->network_evidence ||
       result.local_refusal || result.local_limit || result.unsupported)goto local;
    if(d2k_application_query_complete(&result) || result.body_complete) {
        s->status=D2K_SYN_DIRECT_RESPONSE;s->result.protocol_response=1;
        snprintf(s->result.reason,sizeof s->result.reason,"direct application response: %.300s",result.reason);
        goto done;
    }
    if(start_path(s,1))goto local;
    int prior_probes=0;
    if(s->historical_prefix && (!s->historical_pieces || s->historical_input_length==s->trigger.len)) {
        int added=s->historical_pieces?
            d2k_tls_path_session_initial_prefix_partition(s->path,s->historical_prefix,
                s->historical_length,s->historical_segment,s->historical_mods,
                s->historical_pieces,s->historical_piece_count):
            d2k_tls_path_session_initial_prefix(s->path,s->historical_prefix,
                s->historical_length,s->historical_segment,s->historical_mods);
        if(added!=1)goto local;
        s->status=d2k_tls_path_session_next(s->path,&s->result);
        if(s->status!=D2K_SYN_CLOSED) {
            if(s->result.probes<INT_MAX)s->result.probes++;
            goto done;
        }
        prior_probes=s->result.probes;
        uint64_t experience=s->policy.experience;
        d2k_tls_path_session_free(s->path);s->path=NULL;
        d2k_application_policy_destroy(&s->policy);
        if(start_path(s,experience))goto local;
    }
    s->status=d2k_tls_path_session_next(s->path,&s->result);
    ask_prefix_content(s);
    ask_control_content(s);
    s->result.probes=s->result.probes>INT_MAX-prior_probes?INT_MAX:s->result.probes+prior_probes;
    if(s->result.probes<INT_MAX)s->result.probes++;
    ask_late_question(s);
    goto done;
local:
    s->status=D2K_SYN_ERROR;
    snprintf(s->result.reason,sizeof s->result.reason,"application synthesis lacks owned compatible evidence or local resources");
done:
    *out=s->result;out->generated_input=1;return s->status;
}
void d2k_application_search_free(d2k_application_search *s) {
    if(!s)return;
    d2k_application_search_free(s->child);
    d2k_tls_path_session_free(s->path);d2k_application_policy_destroy(&s->policy);
    d2k_verification_free(s->candidate_owner);
    d2k_application_model_free(s->followup);free(s->followup_program);
    d2k_application_model_free(s->late_observation);free(s->late_program);
    free(s->historical_prefix);
    free(s->historical_pieces);
    if(!s->baseline_borrowed)d2k_application_model_free(s->baseline);
    if(!s->seed_borrowed)d2k_tls_probe_seed_free(s->seed);
    free(s);
}
