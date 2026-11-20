#include "application_trial.h"
#include "../core/include/d2k_hello.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
static int mode,opens,changed_hello,prepared_calls,prefix_calls,http_mode;
int d2k_tls_probe_seed_random(const d2k_tls_probe_seed *seed,uint8_t out[32]) {
    (void)seed;(void)out;assert(!"TLS 1.2 is outside this TLS 1.3 fixture");return -1;
}
size_t d2k_tls12_probe_hello(const uint8_t random[32],const char *host,size_t wire,
    uint8_t *out,size_t cap) {
    (void)random;(void)host;(void)wire;(void)out;(void)cap;
    assert(!"TLS 1.2 is outside this TLS 1.3 fixture");return 0;
}
d2k_ver_result d2k_verify_https12_observe_io(const d2k_tls_io *io,const uint8_t random[32],
    const char *host,const char *path,int wait,size_t wire,int encoding,
    d2k_https_observer observer,void *ctx) {
    (void)io;(void)random;(void)host;(void)path;(void)wait;(void)wire;(void)encoding;(void)observer;(void)ctx;
    assert(!"TLS 1.2 is outside this TLS 1.3 fixture");
    return (d2k_ver_result){.local_refusal=1};
}
size_t d2k_tls_probe_hello(const d2k_tls_probe_seed *seed,const char *host,size_t wire,
    const uint8_t *alpn,size_t alpn_length,uint8_t *out,size_t cap) {
    assert(seed && !strcmp(host,"dns.example") && wire==1200);
    assert(cap>=3);
    assert(http_mode?(alpn_length==9 && !memcmp(alpn,"\10http/1.1",9)):
        (alpn_length==3 && !memcmp(alpn,"\2h2",3)));
    memcpy(out,changed_hello?"abd":"abc",3);return 3;
}
static unsigned observations;
static int learn_decision(void *ctx,d2k_application_model *m,d2k_application_update update) {
    unsigned *calls=ctx;(*calls)++;
    size_t n=0;const d2k_application_observation *history=d2k_application_model_history(m,&n);
    assert(n==*calls && history[n-1].query.ordinal==n);
    assert(update==(n<3?D2K_APP_UNPREDICTED:D2K_APP_MATCH));
    return update!=D2K_APP_MATCH;
}
static int owned_observer(void *ctx,const d2k_application_observation *o) {
    assert(ctx==&observations);observations++;
    assert(o->experience==19 && o->identity->generation==7);
    assert(o->tuple.local_port==50000 && o->raw_ordinal==3);
    assert(o->query.dns_valid && o->query.ordinal==1);return 0;
}
struct d2k_raw_tls {d2k_raw_tls_sink sink;d2k_raw_tls_event e;const char *plan;int prepared,prefetched;uint8_t prefix[3];};
d2k_raw_tls *d2k_raw_tls_open_observed(const d2k_experiment *n,const char *plan,
    const d2k_raw_tls_sink *sink,char *err,size_t cap) {
    (void)err;(void)cap;opens++;
    d2k_raw_tls *r=calloc(1,sizeof *r);assert(r);r->sink=*sink;r->plan=plan;
    r->e.experience=sink->experience;r->e.action=D2K_RAW_TLS_OPEN;
    r->e.tuple.family=n->family;r->e.tuple.remote_port=n->port;r->e.tuple.local_port=50000;
    memcpy(r->e.tuple.remote,n->ip,16);r->e.tuple.local[0]=10;r->e.observation.connected=1;
    assert(!sink->record(sink->context,&r->e));return r;
}
static int send_bytes(void *ctx,const uint8_t *b,size_t n,char *err,size_t cap) {
    (void)err;(void)cap;d2k_raw_tls *r=ctx;
    if(r->prepared){assert(n==3 && !memcmp(b,"abc",3));r->prepared=0;return 0;}
    static const char identity[]="d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\norder forward\n";
    r->e.ordinal++;r->e.action=D2K_RAW_TLS_SEND;
    r->e.program=r->e.send_offset?identity:r->plan;r->e.bytes=b;r->e.length=n;
    r->e.observation.sent=1;r->e.observation.program_packets=r->e.observation.submitted_packets=1;
    int rc=r->sink.record(r->sink.context,&r->e);r->e.send_offset+=(uint32_t)n;return rc;
}
static long read_bytes(void *ctx,uint8_t *b,size_t cap,int wait,char *err,size_t ec) {
    (void)wait;(void)err;(void)ec;d2k_raw_tls *r=ctx;assert(cap>=3);memcpy(b,"abc",3);
    if(r->prefetched){r->prefetched=0;return 3;}
    r->e.ordinal++;r->e.action=D2K_RAW_TLS_READ;r->e.program=NULL;r->e.bytes=b;r->e.length=3;
    r->e.observation.kind=D2K_RAW_OBS_RESPONSE_BYTES;
    static const uint8_t hello[55]={[0]=22,[1]=3,[2]=3,[4]=50,[5]=2,[8]=46,[9]=3,[10]=3,
        [44]=0x13,[45]=1,[48]=6,[50]=43,[52]=2,[53]=3,[54]=4};
    if(r->e.send_offset==3){r->e.bytes=hello;r->e.length=sizeof hello;}
    if(mode==2)r->e.tuple.local_port++;
    return r->sink.record(r->sink.context,&r->e)?-1:3;
}
d2k_tls_io d2k_raw_tls_io(d2k_raw_tls *r) {return (d2k_tls_io){r,read_bytes,send_bytes};}
int d2k_raw_tls_prepare(d2k_raw_tls *r,const uint8_t *bytes,size_t length,char *err,size_t cap) {
    prepared_calls++;int rc=send_bytes(r,bytes,length,err,cap);if(!rc)r->prepared=1;return rc;
}
int d2k_raw_tls_prefix(d2k_raw_tls *r,int wait,const uint8_t **bytes,size_t *length,char *err,size_t cap) {
    prefix_calls++;long n=read_bytes(r,r->prefix,sizeof r->prefix,wait,err,cap);
    if(n<0)return -1;r->prefetched=1;*bytes=r->prefix;*length=(size_t)n;return 0;
}
void d2k_raw_tls_observation(const d2k_raw_tls *r,d2k_raw_observation *out) {*out=r->e.observation;}
void d2k_raw_tls_close(d2k_raw_tls *r) {
    r->e.ordinal++;r->e.action=D2K_RAW_TLS_CLOSE;r->e.bytes=NULL;r->e.length=0;
    (void)r->sink.record(r->sink.context,&r->e);free(r);
}
d2k_ver_result d2k_verify_doh_io(const d2k_tls_io *io,const char *host,const char *path,
    int wait,size_t wire,unsigned budget,long (*packets)(void *),void *ctx) {
    (void)ctx;assert(!strcmp(host,"dns.example") && !strcmp(path,"/dns-query"));
    assert(wait==25 && wire==1200 && !budget && !packets);
    uint8_t b[4];char err[16];assert(!io->write(io->context,(const uint8_t *)"abc",3,err,sizeof err));
    (void)io->read(io->context,b,sizeof b,wait,err,sizeof err);
    d2k_ver_result r={0};r.fd=-1;r.level=D2K_VER_APPLICATION;r.status=mode==3?503:200;
    r.body_complete=1;r.budget=D2K_BUDGET_PASSED;r.budget_requests=1;r.local_refusal=mode==1;
    return r;
}
int main(void) {
    d2k_synthesis_feedback id={0};id.generation=7;id.search_id=3;id.target="dns.example";
    id.ip="192.0.2.7";id.resource="/dns-query";id.program="program";id.doh=1;
    id.family=4;id.transport=6;id.port=443;id.shape=D2K_SHAPE_MODERN;id.plan_id[0]=1;id.trial_id[0]=2;
    d2k_experiment n={.family=4,.port=443,.ip={192,0,2,7}};d2k_ver_result result;
    for(mode=0;mode<4;mode++) {
        d2k_verification_status expected=mode==0?D2K_VF_QUERY_OBSERVED:
            mode==3?D2K_VF_APP_NOT_MET:D2K_VF_UNKNOWN;
        assert(d2k_application_doh_query(&id,19,&n,25,1200,&result)==expected);
    }
    for(mode=0;mode<3;mode++) {
        observations=0;
        assert(d2k_application_doh_observe(&id,19,&n,NULL,25,1200,owned_observer,&observations,&result)==D2K_VF_UNKNOWN);
        assert(observations==(mode==0?1u:0u));
    }
    mode=0;observations=0;d2k_application_model *history=NULL;
    assert(d2k_application_doh_learn(&id,19,&n,NULL,25,1200,learn_decision,&observations,&history,&result)==D2K_VF_UNKNOWN);
    assert(history && observations==3 && result.budget_requests==3);
    size_t length=0;const d2k_application_observation *records=d2k_application_model_history(history,&length);
    assert(length==3 && records[2].identity->generation==7);
    assert(records[2].input_length==3 && !memcmp(records[2].input,"abc",3));
    assert(records[0].first_tls_available && records[0].first_tls_symbol==records[2].first_tls_symbol);
    d2k_transducer learned=d2k_application_model_transducer(history);d2k_transition edge;
    assert(learned.step(learned.ctx,learned.initial,1,&edge)==1);
    assert(edge.observation==records[0].first_tls_symbol);
    size_t after_tls=edge.next;
    assert(learned.step(learned.ctx,after_tls,0,&edge)==1 && edge.observation==D2K_APP_REPLY_DNS);
    size_t replay=after_tls;
    for(size_t i=0;i<length;i++){assert(learned.step(learned.ctx,replay,0,&edge)==1);replay=edge.next;}
    assert(learned.step(learned.ctx,replay,2,&edge)==2);
    assert(edge.observation==(((uint64_t)D2K_VER_APPLICATION<<32)|((uint64_t)200<<8)|1));
    d2k_application_model *comparison=NULL;d2k_application_question question;
    d2k_synthesis_feedback next=id;next.trial_id[0]=5;
    int before_compare=opens;
    const d2k_tls_probe_seed *seed=(const d2k_tls_probe_seed *)&next;
    assert(d2k_application_doh_compare(history,&next,20,&n,seed,25,1200,&comparison,&question,&result)==D2K_VF_UNKNOWN);
    assert(opens==before_compare && !comparison && question.status==D2K_APP_NO_WITNESS);
    d2k_application_observation failure=records[2];failure.query.ordinal=4;failure.query.stream_id=7;
    failure.raw_ordinal+=3;failure.query.response.budget_requests=4;
    failure.query.dns_valid=0;failure.query.timed_out=1;failure.query.response.body_complete=0;
    d2k_application_model *reference=d2k_application_model_new(&id,19);assert(reference);
    for(size_t i=0;i<length;i++)assert(d2k_application_model_add(reference,&records[i])>0);
    assert(d2k_application_model_add(reference,&failure)==D2K_APP_COUNTEREXAMPLE);
    assert(d2k_application_model_add(history,&failure)==D2K_APP_REJECTED);
    d2k_application_model_free(history);history=reference;
    before_compare=opens;changed_hello=1;
    assert(d2k_application_doh_compare(history,&next,20,&n,seed,25,1200,&comparison,&question,&result)==D2K_VF_UNKNOWN);
    assert(!comparison && opens==before_compare && result.local_refusal && question.status==D2K_APP_QUESTION_CONTEXT);
    changed_hello=0;
    assert(d2k_application_doh_compare(history,&next,20,&n,seed,25,1200,&comparison,&question,&result)==D2K_VF_UNKNOWN);
    assert(comparison && question.status==D2K_APP_CHANGED && question.ordinal==4);
    assert(prepared_calls==1 && prefix_calls==1);
    assert(result.budget_requests==4 && result.budget!=D2K_BUDGET_PASSED);
    d2k_application_model_free(comparison);
    d2k_application_model_free(history);
    mode=4;observations=0;history=NULL;
    assert(d2k_application_doh_learn(&id,19,&n,NULL,25,1200,learn_decision,&observations,&history,&result)==D2K_VF_UNKNOWN);
    assert(history && observations==0);
    d2k_application_model_history(history,&length);assert(length==0);
    const d2k_application_end *end=d2k_application_model_end(history);
    assert(end && end->network_evidence && end->input_length==3 && !memcmp(end->input,"abc",3));
    assert(end->first_tls_symbol && end->result.level==D2K_VER_TRANSPORT && !end->result.budget_requests);
    learned=d2k_application_model_transducer(history);
    assert(learned.states && learned.step(learned.ctx,learned.initial,1,&edge)==1);
    assert(edge.observation==end->first_tls_symbol);
    assert(learned.step(learned.ctx,edge.next,2,&edge)==2);
    assert(edge.observation==((uint64_t)D2K_VER_TRANSPORT<<32));
    size_t closed=edge.next;
    for(size_t op=0;op<3;op++)assert(learned.step(learned.ctx,closed,op,&edge)==0);
    mode=0;comparison=NULL;
    before_compare=opens;
    assert(d2k_application_doh_compare(history,&next,20,&n,seed,26,1200,&comparison,&question,&result)==D2K_VF_UNKNOWN);
    assert(opens==before_compare && !comparison && result.local_refusal);
    assert(d2k_application_doh_compare(history,&next,20,&n,seed,25,1200,&comparison,&question,&result)==D2K_VF_UNKNOWN);
    assert(comparison && question.status==D2K_APP_CHANGED && result.budget_requests==1);
    d2k_application_model_free(comparison);
    mode=4;comparison=NULL;next.trial_id[0]++;
    assert(d2k_application_doh_compare(history,&next,21,&n,seed,25,1200,&comparison,&question,&result)==D2K_VF_UNKNOWN);
    assert(comparison && question.status==D2K_APP_REPRODUCED && !result.budget_requests);
    d2k_application_model_free(comparison);
    d2k_application_model_free(history);
    mode=1;observations=0;history=NULL;
    assert(d2k_application_doh_learn(&id,19,&n,NULL,25,1200,learn_decision,&observations,&history,&result)==D2K_VF_UNKNOWN);
    end=d2k_application_model_end(history);
    assert(end && !end->network_evidence && end->result.local_refusal && observations==0);
    assert(!d2k_application_model_transducer(history).states);
    d2k_application_model_free(history);
    http_mode=1;mode=0;next=id;next.doh=0;next.trial_id[0]=9;history=NULL;
    (void)d2k_application_https_learn(&next,22,&n,seed,25,1200,&history,&result);
    end=d2k_application_model_end(history);
    assert(end && end->network_evidence && end->result.body_complete && !end->result.doh_replies);
    assert(d2k_application_model_kind(history)==D2K_APPLICATION_HTTPS);
    assert(d2k_application_model_http_count(history)==3);
    assert(d2k_application_model_http_at(history,0)->event.phase==D2K_HTTPS_REQUEST_BEGIN);
    assert(d2k_application_model_http_at(history,1)->sent_bytes>
        d2k_application_model_http_at(history,0)->sent_bytes);
    assert(end->input_length==3 && !memcmp(end->input,"abc",3));
    d2k_application_model_free(history);http_mode=0;
    n.port=444;int before=opens;
    assert(d2k_application_doh_query(&id,19,&n,25,1200,&result)==D2K_VF_UNKNOWN);
    assert(opens==before && result.local_refusal);return 0;
}
d2k_ver_result d2k_verify_https_probe_io(const d2k_tls_io *io,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int wait,size_t wire,int encoding) {
    assert(seed && !encoding && http_mode);
    d2k_ver_result r=d2k_verify_doh_io(io,host,path,wait,wire,0,NULL,NULL);
    if(mode==5){r.level=D2K_VER_HANDSHAKE;r.body_complete=0;}
    if(mode==7){r.level=D2K_VER_HANDSHAKE;r.body_complete=0;r.body_bytes=16384;}
    if(mode==6){r.cloudflare_challenge=1;r.level=D2K_VER_CHALLENGE;}
    r.budget=D2K_BUDGET_NOT_CHECKED;r.budget_requests=0;r.doh_replies=0;return r;
}
d2k_ver_result d2k_verify_https_observe_io(const d2k_tls_io *io,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int wait,size_t wire,int encoding,
    d2k_https_observer observer,void *ctx) {
    d2k_ver_result r=d2k_verify_https_probe_io(io,seed,host,path,wait,wire,encoding);
    static const uint8_t request[]="GET /dns-query HTTP/1.1\r\n\r\n";
    d2k_https_observation event={.phase=D2K_HTTPS_REQUEST_BEGIN,.ordinal=1,
        .request=request,.request_length=sizeof request-1};
    uint8_t bytes[4];char err[80];
    if(observer(ctx,&event))goto refused;
    if(io->write(io->context,request,sizeof request-1,err,sizeof err))goto refused;
    event.phase=D2K_HTTPS_REQUEST_SENT;
    if(observer(ctx,&event))goto refused;
    (void)io->read(io->context,bytes,sizeof bytes,wait,err,sizeof err);
    event=(d2k_https_observation){.phase=D2K_HTTPS_EXCHANGE_END,.ordinal=1,.response=&r};
    if(observer(ctx,&event))goto refused;
    return r;
refused:
    r.local_refusal=1;return r;
}
d2k_ver_result d2k_verify_doh_probe_io(const d2k_tls_io *io,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int wait,size_t wire,unsigned budget,long (*packets)(void *),void *ctx) {
    assert(seed);return d2k_verify_doh_io(io,host,path,wait,wire,budget,packets,ctx);
}
d2k_ver_result d2k_verify_doh_observe_io(const d2k_tls_io *io,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int wait,size_t wire,d2k_doh_observer observer,void *ctx) {
    (void)seed;
    if(mode==4) {
        d2k_ver_result r=d2k_verify_doh_io(io,host,path,wait,wire,0,NULL,NULL);
        r.level=D2K_VER_TRANSPORT;r.status=0;r.body_complete=0;
        r.budget_requests=0;r.budget=D2K_BUDGET_NOT_APPLICABLE;return r;
    }
    for(unsigned i=1;i<=4;i++) {
        d2k_ver_result r=d2k_verify_doh_io(io,host,path,wait,wire,0,NULL,NULL);
        r.budget=D2K_BUDGET_NOT_APPLICABLE;r.budget_requests=i;
        d2k_doh_observation q={0};q.ordinal=i;q.stream_id=2*i-1;q.dns_valid=1;q.response=r;
        q.query_schema=D2K_DOH_QUERY_SCHEMA_V1;q.timeout_ms=wait;
        int next=observer(ctx,&q);
        if(next<0)r.local_refusal=1;
        if(next<=0)return r;
    }
    assert(0);return (d2k_ver_result){0};
}
