#define main application_main
#include "d2kapplication.c"
#undef main
#include <assert.h>
#include <unistd.h>
#include "../synthesis/application_search.h"
#include "../synthesis/lower.h"
struct d2k_tls_probe_seed {int unused;};
static struct d2k_tls_probe_seed fixed;
int d2k_tls_probe_seed_random(const d2k_tls_probe_seed *seed,uint8_t out[32]) {
    (void)seed;(void)out;assert(!"legacy TLS must use a dedicated fixture");return -1;
}
size_t d2k_tls12_probe_hello(const uint8_t random[32],const char *host,size_t wire,
    uint8_t *out,size_t cap) {
    (void)random;(void)host;(void)wire;(void)out;(void)cap;
    assert(!"legacy TLS must use a dedicated fixture");return 0;
}
d2k_ver_result d2k_verify_https12_observe_io(const d2k_tls_io *io,const uint8_t random[32],
    const char *host,const char *path,int wait,size_t wire,int encoding,
    d2k_https_observer observer,void *ctx) {
    (void)io;(void)random;(void)host;(void)path;(void)wait;(void)wire;(void)encoding;(void)observer;(void)ctx;
    assert(!"legacy TLS must use a dedicated fixture");return (d2k_ver_result){.local_refusal=1};
}
int d2k_detect_stopped(const d2k_detect_stop *stop) {return stop && stop->fn && stop->fn(stop->ctx);}
static int mode,queries,searches,application_sessions,confirmation_queries,http_fixture;
struct d2k_application_model {d2k_application_end end;d2k_application_observation history[3];size_t count;int https;};
static int models;
static d2k_raw_transport finish_transport;
static int archive_records,archive_fail_at;
static int witness_selections;
static char *historical_program;
static int historical_added;
static int historical_partition_added;
static unsigned route_segment=1400;
static int content_prefixes;
unsigned d2k_raw_segment_max(void){return route_segment;}
int d2k_application_archive_transfer_proposal(FILE *f,const d2k_synthesis_feedback *id,
    int timeout,size_t wire,unsigned depth,const d2k_inference_control *control,
    d2k_application_model **out) {
    (void)control;
    assert(f && id->generation==9 && timeout==5000 && wire==1200 && depth==1);
    *out=NULL;if(!historical_program)return 0;
    *out=calloc(1,sizeof **out);assert(*out);models++;
    static d2k_synthesis_feedback old;
    old=*id;old.generation=2;old.search_id=3;old.program=historical_program;
    (*out)->end.identity=&old;(*out)->end.result.doh_replies=1;
    (*out)->end.input_length=1200;
    return 1;
}
int d2k_application_archive_witness(FILE *f,const d2k_application_witness_context *c,
    d2k_application_model **out) {
    assert(f && c && c->trial && c->input_length==1200 && c->timeout_ms==5000 && c->hello_wire==1200);
    witness_selections++;*out=NULL;
    if(mode==18)return -1;
    if(mode!=16 && mode!=17)return 0;
    *out=calloc(1,sizeof **out);assert(*out);models++;
    (*out)->count=3;(*out)->end.network_evidence=1;(*out)->end.result.budget_requests=3;
    return 1;
}
int d2k_application_archive_write(FILE *f,const d2k_application_model *m) {
    assert(f && m);archive_records++;
    if(archive_records==archive_fail_at)return -1;
    return fputs("owned experiment\n",f)<0?-1:0;
}
struct d2k_raw_tape {uint64_t experience;};
struct d2k_application_owner {uint64_t experience,generation;};
static int tapes,owners;
d2k_raw_tape *d2k_raw_tape_new(uint64_t experience) {
    d2k_raw_tape *t=malloc(sizeof *t);assert(t);t->experience=experience;tapes++;return t;
}
void d2k_raw_tape_free(d2k_raw_tape *t){if(t){tapes--;free(t);}}
d2k_raw_tls_sink d2k_raw_tape_sink(d2k_raw_tape *t){return (d2k_raw_tls_sink){.experience=t->experience};}
d2k_application_owner *d2k_application_owner_recorded(const d2k_synthesis_feedback *id,int budget,
    d2k_raw_tape *t,const uint8_t *input,size_t length) {
    assert(t && length==1200 && input[0]==0x42 && budget==1 && id->plan_id[0]==0x31);
    if(mode==9)return NULL;
    d2k_application_owner *o=malloc(sizeof *o);assert(o);owners++;
    *o=(d2k_application_owner){t->experience,id->generation};return o;
}
void d2k_application_owner_free(d2k_application_owner *o){if(o){owners--;free(o);}}
int d2k_application_owner_observe(d2k_application_owner *o,uint64_t generation,uint64_t experience,
    const d2k_doh_observation *q,d2k_application_observation *out) {
    assert(o && o->experience==experience && o->generation==generation && q->ordinal>=1 && q->ordinal<=3);
    *out=(d2k_application_observation){.experience=experience,.query=*q};return 1;
}
int d2k_application_owner_end(const d2k_application_owner *o,const d2k_ver_result *r,d2k_application_end *end) {
    assert(o);*end=(d2k_application_end){.experience=o->experience,.network_evidence=mode!=12,.result=*r,.transport=finish_transport};return 0;
}
d2k_application_model *d2k_application_model_new(const d2k_synthesis_feedback *id,uint64_t experience) {
    assert(id && experience);d2k_application_model *m=calloc(1,sizeof *m);assert(m);models++;return m;
}
d2k_application_kind d2k_application_model_kind(const d2k_application_model *m) {
    assert(m);return m->https?D2K_APPLICATION_HTTPS:D2K_APPLICATION_DOH;
}
int d2k_application_model_http_interval(const d2k_application_model *m,d2k_application_http_interval *out) {
    (void)m;memset(out,0,sizeof *out);return 0;
}
d2k_application_model *d2k_application_model_new_https(const d2k_synthesis_feedback *id,uint64_t experience) {
    assert(http_fixture && !id->doh);
    d2k_application_model *m=d2k_application_model_new(id,experience);m->https=1;return m;
}
d2k_ver_result d2k_verify_https_probe_io(const d2k_tls_io *io,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int timeout,size_t wire,int encoding) {
    assert(http_fixture && io->context && seed==&fixed && !strcmp(host,"dns.example") &&
        !strcmp(path,"/page") && timeout==5000 && wire==1200 && !encoding);
    queries++;
    return mode==5?(d2k_ver_result){.level=D2K_VER_HANDSHAKE,.status=200}:
        (d2k_ver_result){.level=D2K_VER_APPLICATION,.status=200,.body_complete=1};
}
int d2k_application_owner_observe_http(d2k_application_owner *owner,uint64_t generation,
    uint64_t experience,const d2k_https_observation *event,d2k_application_http_observation *out) {
    assert(http_fixture && owner && owner->generation==generation && owner->experience==experience);
    *out=(d2k_application_http_observation){.experience=experience,.event=*event};return 1;
}
d2k_application_update d2k_application_model_add_http(d2k_application_model *model,
    const d2k_application_http_observation *event) {
    assert(http_fixture && model->https && event->experience);return D2K_APP_UNPREDICTED;
}
d2k_ver_result d2k_verify_https_observe_io(const d2k_tls_io *io,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int timeout,size_t wire,int encoding,
    d2k_https_observer observer,void *ctx) {
    d2k_ver_result r=d2k_verify_https_probe_io(io,seed,host,path,timeout,wire,encoding);
    d2k_https_observation event={.phase=D2K_HTTPS_EXCHANGE_END,.ordinal=1,.response=&r};
    assert(!observer(ctx,&event));return r;
}
d2k_application_update d2k_application_model_add(d2k_application_model *m,const d2k_application_observation *o) {
    assert(m && o->experience && m->count<3);m->history[m->count++]=*o;return D2K_APP_UNPREDICTED;
}
const d2k_application_observation *d2k_application_model_history(const d2k_application_model *m,size_t *count) {
    *count=m?m->count:0;return m?m->history:NULL;
}
int d2k_application_model_finish(d2k_application_model *m,const d2k_application_end *end) {
    assert(m && end->timeout_ms==5000 && end->hello_wire==1200);m->end=*end;return 0;
}
d2k_application_question d2k_application_model_question(const d2k_application_model *reference,
    const d2k_application_model *trial) {
    assert(reference && trial && reference!=trial);
    if(mode==16 || mode==17)assert(reference->count==3);
    return (d2k_application_question){mode==5?D2K_APP_REPRODUCED:D2K_APP_CHANGED,mode>=13?0:1,0,0};
}
void d2k_application_model_free(d2k_application_model *m){if(m){models--;free(m);}}
const d2k_application_end *d2k_application_model_end(const d2k_application_model *m){return m?&m->end:NULL;}
int d2k_t13_random(uint8_t *b,size_t n){memset(b,0x31,n);return 0;}
d2k_tls_probe_seed *d2k_tls_probe_seed_new(void){return &fixed;}
void d2k_tls_probe_seed_free(d2k_tls_probe_seed *s){assert(!s || s==&fixed);}
void d2k_raw_flush_pending(void){}
size_t d2k_tls_probe_hello(const d2k_tls_probe_seed *s,const char *name,size_t wire,
    const uint8_t *alpn,size_t an,uint8_t *out,size_t cap) {
    assert(s==&fixed && (!strcmp(name,"dns.example") || (mode==105 && !strcmp(name,"ctl.example"))) && wire==1200);
    assert(http_fixture?(an==9 && !memcmp(alpn,"\10http/1.1",9)):(an==3 && alpn[1]=='h'));
    assert(cap>=1200);memset(out,0x42,1200);
    if(mode==105){out[0]=22;out[3]=4;out[4]=171;out[5]=1;memcpy(out+200,name,11);}
    return 1200;
}
int d2k_hello_sni(const uint8_t *b,size_t n,size_t *off,size_t *len) {
    assert(n==1200 && b[0]==(mode==105?22:0x42));*off=200;*len=11;return 0;
}
d2k_verification_status d2k_application_doh_probe(const d2k_synthesis_feedback *id,
    uint64_t experience,const d2k_experiment *network,const d2k_tls_probe_seed *seed,
    int timeout,size_t wire,d2k_ver_result *r) {
    assert(seed==&fixed && experience && timeout==5000 && wire==1200 && network->mark==0x2f);
    queries++;memset(r,0,sizeof *r);r->fd=-1;
    if(queries==1 && mode && mode!=20 && mode!=21 && mode!=100 && mode!=101 && mode!=102) {
        r->level=mode==2?D2K_VER_APPLICATION:D2K_VER_TRANSPORT;
        r->body_complete=mode==2;r->status=mode==2?503:0;r->local_refusal=mode==3;
        return mode==2?D2K_VF_APP_NOT_MET:D2K_VF_UNKNOWN;
    }
    if(queries>1)assert(strstr(id->program,mode==102 && queries==3?"split payload_start +17":(mode>=100 && mode<=102)?"split payload_start +75":"split payload_start +1") && id->plan_id[0]==0x31);
    if(mode==5 || mode==8){r->level=D2K_VER_TRANSPORT;return D2K_VF_UNKNOWN;}
    r->level=D2K_VER_APPLICATION;r->status=200;r->body_complete=1;r->doh_replies=mode==14?3:1;r->budget_requests=mode==14?3:1;return D2K_VF_QUERY_OBSERVED;
}
d2k_verification_status d2k_application_doh_learn(const d2k_synthesis_feedback *id,
    uint64_t experience,const d2k_experiment *network,const d2k_tls_probe_seed *seed,
    int timeout,size_t wire,d2k_application_decision decide,void *ctx,
    d2k_application_model **history,d2k_ver_result *out) {
    (void)d2k_application_doh_probe(id,experience,network,seed,timeout,wire,out);
    *history=calloc(1,sizeof **history);assert(*history);models++;
    (*history)->end.network_evidence=mode!=3 && mode!=6;
    (*history)->end.input_length=1200;
    static uint8_t original_input[1200];memset(original_input,0x42,sizeof original_input);
    if(mode==105){original_input[0]=22;original_input[3]=4;original_input[4]=171;original_input[5]=1;memcpy(original_input+200,"dns.example",11);}
    (*history)->end.input=original_input;(*history)->end.identity=id;
    (*history)->end.experience=experience;(*history)->end.timeout_ms=timeout;
    (*history)->end.hello_wire=wire;
    int replay=queries>1;
    for(unsigned ordinal=1;out->level==D2K_VER_APPLICATION && out->status==200;ordinal++) {
        assert(ordinal<=3);
        out->budget_requests=ordinal;out->doh_replies=ordinal;
        if(((replay && (mode==13 || mode==17)) || mode==20 || ((mode>=100 && mode<=102) && (!replay || mode==100 || mode==102))) && ordinal==3) {
            out->level=D2K_VER_HANDSHAKE;out->body_complete=0;out->status=0;out->doh_replies=2;
        }
        d2k_application_observation observed={.experience=experience,.query={
            .ordinal=ordinal,.dns_valid=out->body_complete,.response=*out}};
        if((mode>=100 && mode<=102)){observed.transport.available=1;observed.transport.sent_end=1200+150*ordinal;}
        if(mode==102 && replay) {
            observed.transport.ack_seen=1;
            observed.transport.acked_end=ordinal<3?observed.transport.sent_end:queries==2?1517:1575;
        }
        d2k_application_model_add(*history,&observed);
        if(replay)confirmation_queries++;
        int again=decide(ctx,*history,D2K_APP_UNPREDICTED);
        assert(again== (((replay && (mode==13 || mode==14 || mode==16 || mode==17 || mode==19)) || mode==20 || mode==21 || (mode>=100 && mode<=102)) && ordinal<3));
        if(!again)break;
    }
    (*history)->end.result=*out;
    if(replay && (mode==15 || mode==19))(*history)->end.network_evidence=0;
    if(!replay && (mode==13 || mode==14)) {
        (*history)->end.result.budget_requests=3;(*history)->count=3;
        for(unsigned i=0;i<3;i++) {
            (*history)->history[i].query.ordinal=i+1;
            (*history)->history[i].query.dns_valid=i<2;
            (*history)->history[i].query.timed_out=i==2;
        }
    }
    return D2K_VF_UNKNOWN;
}
d2k_verification_status d2k_application_doh_compare(const d2k_application_model *reference,
    const d2k_synthesis_feedback *id,uint64_t experience,const d2k_experiment *network,
    const d2k_tls_probe_seed *seed,int timeout,size_t wire,d2k_application_model **history,
    d2k_application_question *question,d2k_ver_result *out) {
    assert(reference && reference->end.network_evidence && reference->end.input_length==1200);
    (void)d2k_application_doh_probe(id,experience,network,seed,timeout,wire,out);
    *history=calloc(1,sizeof **history);assert(*history);models++;
    *question=(d2k_application_question){(mode==5 || mode==8)?D2K_APP_REPRODUCED:D2K_APP_CHANGED,1,0,0};
    return D2K_VF_UNKNOWN;
}
d2k_syn_status d2k_tls_path_work(const d2k_tls_stream *s,const d2k_experiment *e,
    uint64_t generation,d2k_vres *out) {
    searches++;assert(s->trigger->len==1200 && s->trigger->payload[0]==0x42 && generation);
    assert(e->reply_capacity==4096 && s->chunks==1 && s->chunk_bytes[0]==s->trigger->len);
    out->probes=5;
    snprintf(out->program,sizeof out->program,"d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +1\norder forward\n");
    out->program_len=strlen(out->program);
    return mode==4?D2K_SYN_DIRECT_RESPONSE:D2K_SYN_CANDIDATE;
}
struct d2k_tls_path_session {d2k_tls_stream stream;d2k_experiment network;uint64_t generation;d2k_tls_application policy;int initial_prefix;};
static int sessions;
int d2k_tls_path_session_initial_prefix(d2k_tls_path_session *w,const uint8_t *b,size_t n,size_t segment,unsigned mods) {
    assert((mode==103 || mode==104) && w && n==4 && !memcmp(b,"abcd",4) && segment==route_segment && mods==3);
    assert(!historical_added && searches==0 && queries==1);
    historical_added++;w->initial_prefix=1;return 1;
}
int d2k_tls_path_session_initial_prefix_partition(d2k_tls_path_session *w,const uint8_t *b,
    size_t n,size_t segment,unsigned mods,const d2k_payload_piece *pieces,size_t count) {
    assert(count==2 && pieces[0].offset==105 && pieces[0].length==1095 &&
        pieces[1].offset==0 && pieces[1].length==105);
    historical_partition_added++;
    return d2k_tls_path_session_initial_prefix(w,b,n,segment,mods);
}
int d2k_tls_path_session_add_prefix(d2k_tls_path_session *w,const uint8_t *b,size_t n,size_t segment,unsigned mods) {
    if(mode==105){assert(w && n==1200 && b[0]==22 && !mods);
        assert(segment==(route_segment<1200?route_segment:1200));
        if(content_prefixes==2)assert(!memcmp(b+200,"ctl.example",11));
        content_prefixes++;return 1;}
    if(mode==103 || mode==104) {
        assert(w && n==4 && !memcmp(b,"abcd",4) && segment==1400 && mods==3);
        historical_added++;return 1;
    }
    (void)w;(void)b;(void)n;(void)segment;(void)mods;
    assert(!"synthetic non-TLS fixtures must not generate content questions");return -1;
}
d2k_tls_path_session *d2k_tls_path_session_new(const d2k_tls_stream *s,const d2k_experiment *e,uint64_t generation) {
    assert(e->tls_input_length==s->trigger->len && !memcmp(e->tls_input,s->trigger->payload,e->tls_input_length));
    d2k_tls_path_session *w=malloc(sizeof *w);assert(w);sessions++;
    *w=(d2k_tls_path_session){.stream=*s,.network=*e,.generation=generation};return w;
}
d2k_tls_path_session *d2k_tls_path_session_new_application(const d2k_tls_stream *s,
    const d2k_experiment *e,uint64_t generation,const d2k_tls_application *policy) {
    d2k_tls_path_session *w=d2k_tls_path_session_new(s,e,generation);
    assert(policy && policy->prepare && policy->run && policy->finish && policy->accepted);
    w->policy=*policy;application_sessions++;return w;
}
d2k_syn_status d2k_tls_path_session_next(d2k_tls_path_session *w,d2k_vres *out) {
    if(mode==105){searches++;out->probes=searches;return D2K_SYN_CLOSED;}
    if((mode==103 || mode==104) && !w->initial_prefix) {
        searches++;out->probes=1;return D2K_SYN_CLOSED;
    }
    if((mode>=100 && mode<=102)){searches++;out->probes=5;return D2K_SYN_CLOSED;}
    for(int attempt=0;attempt<(mode==10?2:1);attempt++) {
        assert(w->network.make_sink);d2k_raw_tls_sink sink;
        assert(!w->network.make_sink(w->network.sink_context,&sink));
        d2k_syn_status proposed=d2k_tls_path_work(&w->stream,&w->network,w->generation,out);
        if(!w->policy.run)return proposed;
        int ready=!w->policy.prepare(w->policy.context,out->program);
        d2k_tls_io io={.context=mode==7?NULL:w};
        int ran=ready && io.context?w->policy.run(w->policy.context,&io):-1;
        uint64_t symbol=0;
        int finished=w->policy.finish(w->policy.context,&symbol);
        if(ran || finished!=1)return D2K_SYN_ERROR;
        if(w->policy.accepted(w->policy.context,symbol))return proposed;
    }
    return D2K_SYN_CLOSED;
}
d2k_tls_io d2k_tls_path_session_tls_io(d2k_tls_path_session *w) {
    return (d2k_tls_io){.context=mode==7?NULL:w};
}
void d2k_tls_path_session_free(d2k_tls_path_session *w){if(w){sessions--;free(w);}}
d2k_ver_result d2k_verify_doh_observe_io(const d2k_tls_io *io,const d2k_tls_probe_seed *seed,
    const char *host,const char *path,int timeout,size_t wire,d2k_doh_observer observer,void *ctx) {
    assert(io->context && sessions>=1 && seed==&fixed && !strcmp(host,"dns.example") &&
        !strcmp(path,"/dns-query") && timeout==5000 && wire==1200);
    queries++;d2k_ver_result r={.fd=-1,.level=D2K_VER_TRANSPORT};
    if(mode!=5 && mode!=104 && !(mode==10 && queries==2)) {r.level=D2K_VER_APPLICATION;r.status=200;r.body_complete=1;r.doh_replies=mode!=11;r.budget_requests=1;}
    for(unsigned ordinal=1;r.level==D2K_VER_APPLICATION;ordinal++) {
        assert(ordinal<=3);
        r.budget_requests=ordinal;if(r.doh_replies)r.doh_replies=ordinal;
        d2k_doh_observation q={.ordinal=ordinal,.stream_id=ordinal*2-1,.dns_valid=r.doh_replies!=0,.response=r};
        int again=observer(ctx,&q);
        assert(again==((mode==13 || mode==14 || mode==16 || mode==17 || mode==20 || mode==22) && ordinal<3));
        if(!again)break;
    }
    return r;
}
static void policy_contract_is_frozen(void) {
    uint8_t input[1200];memset(input,0x42,sizeof input);
    d2k_synthesis_feedback id={.generation=7,.search_id=8,.target="dns.example",.ip="192.0.2.7",
        .resource="/dns-query",.program="direct",.doh=1,.port=443,.family=4,.transport=6,.shape=D2K_SHAPE_MODERN};
    d2k_application_model reference={0};reference.end=(d2k_application_end){
        .identity=&id,.experience=9,.input=input,.input_length=sizeof input,.network_evidence=1,
        .timeout_ms=5000,.hello_wire=1200,.result={.level=D2K_VER_TRANSPORT}};
    FILE *archive=tmpfile();assert(archive);
    d2k_application_policy policy={0};mode=1;witness_selections=0;
    assert(!d2k_application_policy_init(&policy,&id,&reference,&fixed,input,sizeof input,9,5000,1200,archive));
    assert(witness_selections==1 && policy.required_queries==1);
    mode=16;
    d2k_raw_tls_sink sink;
    assert(!d2k_application_policy_sink(&policy,&sink));
    d2k_tls_application callbacks=d2k_application_policy_callbacks(&policy);
    assert(!callbacks.prepare(callbacks.context,"d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\norder forward\n"));
    assert(witness_selections==1 && policy.required_queries==1 && policy.reference==&reference);
    d2k_application_policy_destroy(&policy);
    assert(!d2k_application_policy_init(&policy,&id,&reference,&fixed,input,sizeof input,10,5000,1200,archive));
    assert(witness_selections==2 && policy.required_queries==3 && policy.reference!=&reference);
    const d2k_application_model *selected=policy.reference;
    assert(!d2k_application_policy_sink(&policy,&sink));
    assert(policy.reference==selected && policy.required_queries==3);
    d2k_application_policy_destroy(&policy);fclose(archive);
    assert(!models && !tapes && !owners);
}
static void policy_rejects_foreign_or_healthy_context(void) {
    uint8_t input[1200];memset(input,0x42,sizeof input);
    d2k_synthesis_feedback id={.generation=7,.search_id=8,.target="dns.example",.ip="192.0.2.7",
        .resource="/dns-query",.program="direct",.doh=1,.port=443,.family=4,.transport=6,.shape=D2K_SHAPE_MODERN};
    d2k_application_model reference={0};reference.end=(d2k_application_end){
        .identity=&id,.experience=9,.input=input,.input_length=sizeof input,.network_evidence=1,
        .timeout_ms=2500,.hello_wire=1200,.result={.level=D2K_VER_TRANSPORT}};
    d2k_application_policy policy={0};
    for(int variant=0;variant<7;variant++) {
        d2k_synthesis_feedback changed=id;int timeout=2500;
        if(variant==0)changed.search_id++;
        if(variant==1)changed.resource="/different";
        if(variant==2)changed.by_addr=1;
        if(variant==3)changed.shape=D2K_SHAPE_LEGACY;
        if(variant==4)timeout=5000;
        if(variant==5)reference.end.result.local_refusal=1;
        if(variant==6){reference.count=1;reference.history[0].query.dns_valid=1;}
        assert(d2k_application_policy_init(&policy,&changed,&reference,&fixed,input,sizeof input,
            9,timeout,1200,NULL)==-1);
        d2k_application_policy_destroy(&policy);
        reference.end.result.local_refusal=0;reference.count=0;
    }
    assert(!d2k_application_policy_init(&policy,&id,&reference,&fixed,input,sizeof input,
        9,2500,1200,NULL));
    d2k_raw_tls_sink sink;
    assert(!d2k_application_policy_sink(&policy,&sink));
    assert(sink.experience==10);
    d2k_application_policy_destroy(&policy);assert(!tapes && !models && !owners);
}
static void policy_retains_transport_failure_distinction(void) {
    uint64_t symbols[3]={0};mode=0;
    for(unsigned i=0;i<3;i++) {
        d2k_application_model reference={0};
        d2k_application_policy p={.trial={.doh=1},.reference=&reference,.timeout_ms=5000,.hello_wire=1200,.required_queries=5};
        p.owner=calloc(1,sizeof *p.owner);assert(p.owner);owners++;
        p.model=calloc(1,sizeof *p.model);assert(p.model);models++;
        p.result.level=D2K_VER_HANDSHAKE;p.result.status=200;p.result.doh_replies=4;
        finish_transport=(d2k_raw_transport){.available=i!=0,.ack_seen=1,.sent_end=100,.acked_end=i==2?100:80};
        d2k_tls_application cb=d2k_application_policy_callbacks(&p);
        assert(cb.finish(cb.context,&symbols[i])==1);
        assert(!cb.accepted(cb.context,symbols[i]));
        d2k_application_policy_destroy(&p);
    }
    assert(symbols[0]!=symbols[1] && symbols[1]!=symbols[2] && symbols[0]!=symbols[2]);
    finish_transport=(d2k_raw_transport){0};assert(!owners && !models);
    for(unsigned i=0;i<4;i++) {
        d2k_application_model reference={0};
        d2k_application_policy p={.trial={.doh=1},.reference=&reference,.timeout_ms=5000,.hello_wire=1200,.required_queries=5};
        p.owner=calloc(1,sizeof *p.owner);assert(p.owner);owners++;
        p.model=calloc(1,sizeof *p.model);assert(p.model);models++;
        p.model->count=2;
        p.model->history[0].transport=(d2k_raw_transport){.available=1,.ack_seen=1,.sent_end=200,.acked_end=200};
        p.model->history[1].transport=(d2k_raw_transport){.available=i!=0,.ack_seen=1,.sent_end=400,.acked_end=i==3?400:i==2?300:200};
        p.result.level=D2K_VER_HANDSHAKE;p.result.status=200;p.result.doh_replies=4;
        finish_transport=p.model->history[1].transport;
        uint64_t symbol=0;d2k_tls_application cb=d2k_application_policy_callbacks(&p);
        assert(cb.finish(cb.context,&symbol)==1);
        assert(((symbol>>40)&3)==i && !cb.accepted(cb.context,symbol));
        if(i)assert(cb.token_question(cb.context,symbol)==2);
        d2k_application_policy_destroy(&p);
    }
    finish_transport=(d2k_raw_transport){0};assert(!owners && !models);
}
static void policy_retains_dns_prefix_length(void) {
    const unsigned replies[]={1,4,1,UINT_MAX};
    uint64_t symbols[4]={0};mode=0;
    d2k_application_model reference={0};
    d2k_application_policy p={.trial={.doh=1},.reference=&reference,.timeout_ms=5000,.hello_wire=1200,.required_queries=5};
    d2k_tls_application cb=d2k_application_policy_callbacks(&p);
    for(size_t i=0;i<4;i++) {
        p.owner=calloc(1,sizeof *p.owner);assert(p.owner);owners++;
        p.model=calloc(1,sizeof *p.model);assert(p.model);models++;
        p.result=(d2k_ver_result){.level=D2K_VER_HANDSHAKE,.status=200,.doh_replies=replies[i]};
        finish_transport=(d2k_raw_transport){.available=1,.ack_seen=1,.sent_end=100,.acked_end=100};
        assert(cb.finish(cb.context,&symbols[i])==1);
        assert(!cb.accepted(cb.context,symbols[i]));
        assert(cb.token_question(cb.context,symbols[i])==2);
        d2k_application_model_free(p.model);p.model=NULL;
    }
    assert(symbols[0]!=symbols[1] && symbols[0]==symbols[2]);
    assert(symbols[3]!=symbols[0] && symbols[3]!=symbols[1]);
    d2k_application_policy_destroy(&p);
    finish_transport=(d2k_raw_transport){0};assert(!owners && !models);
}
static void policy_retains_received_payload_class(void) {
    uint64_t symbols[3]={0};mode=0;
    finish_transport=(d2k_raw_transport){.available=1,.ack_seen=1,.sent_end=100,.acked_end=100};
    for(unsigned i=0;i<3;i++) {
        d2k_application_model reference={0};
        d2k_application_policy p={.trial={.doh=1},.reference=&reference,.timeout_ms=5000,.hello_wire=1200,.required_queries=5};
        p.owner=calloc(1,sizeof *p.owner);assert(p.owner);owners++;
        p.model=calloc(1,sizeof *p.model);assert(p.model);models++;
        p.model->count=2;
        p.model->history[0].transport=(d2k_raw_transport){.available=1,.received_payload_bytes=100};
        p.model->history[1].transport=(d2k_raw_transport){.available=i!=0,.received_payload_bytes=i==2?142:100};
        p.result=(d2k_ver_result){.level=D2K_VER_HANDSHAKE,.status=200,.doh_replies=1};
        d2k_tls_application cb=d2k_application_policy_callbacks(&p);
        assert(cb.finish(cb.context,&symbols[i])==1);
        assert(!cb.accepted(cb.context,symbols[i]));
        assert(cb.token_question(cb.context,symbols[i])==2);
        d2k_application_policy_destroy(&p);
    }
    assert(symbols[0]!=symbols[1] && symbols[1]!=symbols[2] && symbols[0]!=symbols[2]);
    finish_transport=(d2k_raw_transport){0};
    assert(!owners && !models);
}
static int stop_after_first_late(void *ctx) {(void)ctx;return queries>=2;}
static void automatic_late_question_after_closure(void) {
    for(mode=100;mode<=102;mode++) {
        queries=searches=0;
        d2k_application_request r={.search_id=7,.port=443,.family=4,.transport=6,.shape=D2K_SHAPE_MODERN,.doh=1,.doh_failure_query=3};
        strcpy(r.target,"dns.example");strcpy(r.ip,"192.0.2.7");strcpy(r.resource,"/dns-query");
        d2k_experiment net={.family=4,.port=443,.connect_ms=5000,.mark=0x2f};assert(inet_pton(AF_INET,r.ip,net.ip)==1);
        d2k_application_search *s=d2k_application_search_new(&r,&net,9,5000,1200,NULL);assert(s);
        d2k_vres out;d2k_syn_status expected=mode!=101?D2K_SYN_CLOSED:D2K_SYN_CANDIDATE;
        assert(d2k_application_search_next(s,&out)==expected);
        assert(!out.have_arm);
        if(mode==101) {
            assert(out.program_len==strlen(out.program) && out.program_len &&
                   strstr(out.program,"stream-offset") && strstr(out.program,"split payload_start +75"));
            assert(out.synthesis_generation==9 && out.owns_search && out.generated_input &&
                   out.verdict==D2K_V_INCONCLUSIVE && !out.protocol_response);
        } else assert(!out.program_len && !out.program[0]);
        assert(queries==(mode==102?3:2) && searches==1);
        if(mode==101)assert(strstr(out.reason,"controller verification required"));
        assert(d2k_application_search_next(s,&out)==expected && queries==(mode==102?3:2) && searches==1);
        if(mode==101) {
            d2k_synthesis_feedback feedback={.generation=9,.search_id=7,
                .target="dns.example",.ip="192.0.2.7",.resource="/dns-query",
                .program=out.program,.doh=1,.port=443,.family=4,.transport=6,
                .shape=D2K_SHAPE_MODERN,.applied=1,.verification_available=1,
                .level=D2K_VER_APPLICATION,.budget=D2K_BUDGET_CUT,
                .budget_need=50,.budget_packets=24,.budget_requests=5,.doh_replies=4};
            feedback.trial_id[0]=4;feedback.plan_id[0]=3;
            feedback.flow.family=4;feedback.flow.transport=6;
            feedback.flow.a_port=50000;feedback.flow.b_port=443;
            assert(inet_pton(AF_INET,feedback.ip,feedback.flow.b_ip)==1);
            assert(d2k_application_search_feedback(s,&feedback,D2K_VF_NOT_MET)==1);
            const d2k_synthesis_feedback *pending=d2k_application_search_pending_failure(s);
            assert(pending && !strcmp(pending->program,out.program));
        }
        d2k_application_search_free(s);assert(!sessions && !models && !owners && !tapes);
    }
    for(int failure=0;failure<2;failure++) {
        mode=102;queries=searches=archive_records=0;
        archive_fail_at=failure?2:0;
        d2k_application_request r={.search_id=7,.port=443,.family=4,.transport=6,.shape=D2K_SHAPE_MODERN,.doh=1,.doh_failure_query=3};
        strcpy(r.target,"dns.example");strcpy(r.ip,"192.0.2.7");strcpy(r.resource,"/dns-query");
        d2k_detect_stop stop={stop_after_first_late,NULL};
        d2k_experiment net={.family=4,.port=443,.connect_ms=5000,.mark=0x2f,.cancel=failure?NULL:&stop};
        assert(inet_pton(AF_INET,r.ip,net.ip)==1);
        FILE *archive=tmpfile();assert(archive);
        d2k_application_search *s=d2k_application_search_new(&r,&net,9,5000,1200,archive);assert(s);
        d2k_vres out;
        assert(d2k_application_search_next(s,&out)==D2K_SYN_ERROR);
        assert(queries==2 && !out.program_len && !out.program[0] && !out.have_arm);
        assert(strstr(out.reason,failure?"cannot persist owned application evidence":"cancelled"));
        assert(d2k_application_search_next(s,&out)==D2K_SYN_ERROR && queries==2);
        d2k_application_search_free(s);fclose(archive);
        assert(!sessions && !models && !owners && !tapes);
        archive_fail_at=0;
    }
    mode=queries=searches=0;
}
static void historical_prefix_requires_current_application_success(void) {
    char err[160];
    for(unsigned composite=0;composite<2;composite++) {
    d2k_payload_piece pieces[]={{105,1095,0},{0,105,0}};
    assert((composite?d2k_lower_tls_prefix_partition((const uint8_t *)"abcd",4,1400,3,1200,pieces,2,
        &historical_program,err,sizeof err):d2k_lower_tls_prefix((const uint8_t *)"abcd",4,1400,3,
        &historical_program,err,sizeof err))==D2K_LOWER_OK);
    for(unsigned variant=0;variant<3;variant++) {
        mode=variant==0?0:variant==1?103:104;
        route_segment=variant==1?900:1400;
        queries=searches=historical_added=archive_records=0;
        historical_partition_added=0;
        d2k_application_request r={.search_id=7,.port=443,.family=4,.transport=6,.shape=D2K_SHAPE_MODERN,.doh=1};
        strcpy(r.target,"dns.example");strcpy(r.ip,"192.0.2.7");strcpy(r.resource,"/dns-query");
        d2k_experiment net={.family=4,.port=443,.mark=0x2f,.connect_ms=5000,.offer_ts=1};
        assert(inet_pton(AF_INET,r.ip,net.ip)==1);
        d2k_application_search *s=d2k_application_search_new(&r,&net,9,5000,1200,NULL);assert(s);
        FILE *f=tmpfile();assert(f);
        assert(d2k_application_search_history(s,f)==1 && !queries && !searches);
        assert(d2k_application_search_history(s,f)==1 && !queries && !searches);
        char *valid_program=historical_program;historical_program="unsupported program";
        assert(d2k_application_search_history(s,f)==0 && !queries && !searches);
        historical_program=valid_program;
        fclose(f);
        d2k_vres out;
        d2k_syn_status got=d2k_application_search_next(s,&out);
        if(!variant)assert(got==D2K_SYN_DIRECT_RESPONSE && !historical_added && queries==1 && !searches);
        else if(variant==1)assert(got==D2K_SYN_CANDIDATE && historical_added==1 && queries==2 && searches==1);
        else assert(got!=D2K_SYN_CANDIDATE && historical_added==1 && queries>1);
        assert(historical_partition_added==(int)(composite && variant));
        int before=queries;
        assert(d2k_application_search_next(s,&out)==got && queries==before && historical_added==(variant!=0));
        assert(d2k_application_search_history(s,NULL)==-1);
        d2k_application_search_free(s);
        assert(!models && !sessions && !owners && !tapes);
    }
    free(historical_program);historical_program=NULL;mode=0;route_segment=1400;
    }
}
static void content_prefix_respects_route(void) {
    for(unsigned cap=900;cap<=1400;cap+=500) {
      for(unsigned variant=0;variant<4;variant++) {
        mode=105;route_segment=cap;queries=searches=content_prefixes=0;
        d2k_application_request r={.search_id=7,.port=443,.family=4,.transport=6,.shape=D2K_SHAPE_MODERN,.doh=1};
        strcpy(r.target,"dns.example");strcpy(r.ip,"192.0.2.7");strcpy(r.resource,"/dns-query");
        if(variant) {
            strcpy(r.control.name,"ctl.example");r.control.family=variant==3?6:4;
            r.control.transport=6;r.control.incarnation=19;r.control.bytes=32768;
            r.control.epoch[0]=variant==2?0:7;r.control.low_port=443;r.control.high_port=50123;
        }
        d2k_experiment net={.family=4,.port=443,.connect_ms=5000,.mark=0x2f,.offer_ts=1};
        assert(inet_pton(AF_INET,r.ip,net.ip)==1);
        d2k_application_search *s=d2k_application_search_new(&r,&net,9,5000,1200,NULL);assert(s);
        if(variant==1)strcpy(r.control.name,"new.example");
        d2k_vres out;assert(d2k_application_search_next(s,&out)==D2K_SYN_CLOSED);
        assert(content_prefixes==(variant==1?3:2));
        d2k_application_search_free(s);assert(!sessions && !models && !owners && !tapes);
        if(variant==1) {
            mode=0;queries=searches=content_prefixes=0;
            s=d2k_application_search_new(&r,&net,9,5000,1200,NULL);assert(s);
            assert(d2k_application_search_next(s,&out)==D2K_SYN_DIRECT_RESPONSE);
            assert(!searches && !content_prefixes);
            d2k_application_search_free(s);assert(!sessions && !models && !owners && !tapes);
        }
      }
    }
    mode=0;route_segment=1400;
}
static void https_search_uses_application_context(void) {
    http_fixture=1;
    for(mode=0;mode<=5;mode++) {
        if(mode==4)continue;
        queries=searches=0;
        d2k_application_request r={.search_id=7,.port=443,.family=4,.transport=6,.shape=D2K_SHAPE_MODERN};
        strcpy(r.target,"dns.example");strcpy(r.ip,"192.0.2.7");strcpy(r.resource,"/page");
        d2k_experiment net={.family=4,.port=443,.connect_ms=5000,.mark=0x2f};
        assert(inet_pton(AF_INET,r.ip,net.ip)==1);
        d2k_application_search *s=d2k_application_search_new(&r,&net,9,5000,1200,NULL);assert(s);
        d2k_vres out;d2k_syn_status got=d2k_application_search_next(s,&out);
        assert(got==((mode==0 || mode==2)?D2K_SYN_DIRECT_RESPONSE:
            mode==1?D2K_SYN_CANDIDATE:mode==3?D2K_SYN_ERROR:D2K_SYN_CLOSED));
        assert(searches==((mode==1 || mode==5)?1:0));
        assert(queries==((mode==1 || mode==5)?2:1));
        int before=queries;assert(d2k_application_search_next(s,&out)==got && queries==before);
        if(mode==1) {
            d2k_synthesis_feedback feedback={.generation=9,.search_id=7,.target="dns.example",
                .ip="192.0.2.7",.resource="/page",.program=out.program,.family=4,.transport=6,
                .port=443,.shape=D2K_SHAPE_MODERN,.applied=1,.verification_available=1,
                .level=D2K_VER_APPLICATION,.status=200,.budget=D2K_BUDGET_CUT,
                .budget_need=50,.budget_packets=24,.budget_requests=1};
            feedback.trial_id[0]=4;feedback.plan_id[0]=3;
            feedback.flow.family=4;feedback.flow.transport=6;
            feedback.flow.a_port=50000;feedback.flow.b_port=443;
            assert(inet_pton(AF_INET,feedback.ip,feedback.flow.b_ip)==1);
            assert(d2k_application_search_feedback(s,&feedback,D2K_VF_NOT_MET)==1);
            const d2k_application_model *again=NULL,*same=NULL;
            assert(d2k_application_search_remeasure(s,&again)==1);
            assert(again && again->https && !again->end.result.doh_replies && queries==before+1);
            assert(d2k_application_search_remeasure(s,&same)==1 && same==again && queries==before+1);
            assert(d2k_application_search_next(s,&out)==D2K_SYN_CLOSED && queries==before+1);
        }
        d2k_application_search_free(s);assert(!models && !sessions && !owners && !tapes);
    }
    http_fixture=mode=queries=searches=0;
}
d2k_verification_status d2k_application_https_learn(const d2k_synthesis_feedback *id,
    uint64_t experience,const d2k_experiment *network,const d2k_tls_probe_seed *seed,
    int timeout,size_t wire,d2k_application_model **history,d2k_ver_result *out) {
    assert(http_fixture && !id->doh && !strcmp(id->resource,"/page") && seed==&fixed &&
        network->mark==0x2f && experience && timeout==5000 && wire==1200);
    queries++;*out=(d2k_ver_result){.fd=-1,.level=D2K_VER_HANDSHAKE};
    if(mode==0 || mode==2)*out=(d2k_ver_result){.fd=-1,.level=D2K_VER_APPLICATION,
        .status=mode==2?503:200,.body_complete=1};
    if(mode==3)out->local_refusal=1;
    *history=d2k_application_model_new_https(id,experience);
    static uint8_t input[1200];memset(input,0x42,sizeof input);
    (*history)->end=(d2k_application_end){.identity=id,.experience=experience,
        .input=input,.input_length=1200,.network_evidence=mode!=3,
        .timeout_ms=timeout,.hello_wire=wire,.result=*out};
    return D2K_VF_UNKNOWN;
}
int main(void) {
    https_search_uses_application_context();
    content_prefix_respects_route();
    historical_prefix_requires_current_application_success();
    {
        mode=100;queries=searches=0;
        char *args[]={"d2kapplication","192.0.2.7","dns.example","/dns-query","--search","--through-query","3"};
        assert(application_main(7,args)==1);
        assert(queries==(mode==102?3:2) && searches==1 && !sessions && !models && !owners && !tapes);
        mode=queries=searches=0;
    }
    automatic_late_question_after_closure();
    policy_retains_received_payload_class();
    policy_retains_dns_prefix_length();
    policy_retains_transport_failure_distinction();
    policy_rejects_foreign_or_healthy_context();
    policy_contract_is_frozen();
    char *depth_args[]={"probe","192.0.2.7","dns.example","/dns-query","--through-query","3",NULL};
    mode=21;queries=searches=application_sessions=confirmation_queries=0;
    assert(application_main(6,depth_args)==0 && queries==1 && !searches);
    const char *bad_depth[]={"0","-1","3junk","1073741824","999999999999999999999"};
    for(size_t i=0;i<sizeof bad_depth/sizeof bad_depth[0];i++) {
        depth_args[5]=(char *)bad_depth[i];queries=0;
        assert(application_main(6,depth_args)==2 && !queries);
    }
    d2k_tls_application policy=d2k_application_policy_callbacks(NULL);
    assert(policy.token_question(NULL,(uint64_t)D2K_VER_TRANSPORT<<32));
    assert(!policy.token_question(NULL,(uint64_t)D2K_VER_HANDSHAKE<<32));
    assert(!policy.token_question(NULL,(uint64_t)D2K_VER_APPLICATION<<32));
    assert(!policy.token_question(NULL,((uint64_t)D2K_VER_TRANSPORT<<32)|(UINT64_C(1)<<63)));
    uint64_t late=((uint64_t)D2K_VER_HANDSHAKE<<32)|(UINT64_C(1)<<62)|(UINT64_C(2)<<60);
    assert(policy.token_question(NULL,late)==2);
    assert(policy.token_question(NULL,late|(UINT64_C(200)<<48))==2);
    assert(!policy.token_question(NULL,late|(UINT64_C(1)<<58)));
    assert(!policy.token_question(NULL,late|(UINT64_C(403)<<48)));
    assert(!policy.token_question(NULL,late|(UINT64_C(429)<<48)));
    assert(!policy.token_question(NULL,late|(UINT64_C(503)<<48)));

    assert(!policy.token_question(NULL,late|(UINT64_C(1)<<63)));
    assert(!policy.token_question(NULL,late&~(UINT64_C(1)<<62)));
    assert(policy.token_question(NULL,(late&~(UINT64_C(3)<<60))|(UINT64_C(1)<<60))==2);
    char *args[]={"probe","192.0.2.7","dns.example","/dns-query","--measure",NULL};
    for(mode=0;mode<16;mode++) {
        queries=searches=application_sessions=confirmation_queries=0;interrupted=0;
        int rc=application_main(5,args);
        assert(rc==((mode==0 || mode==1 || mode==4 || mode==10 || mode==14)?0:1));
        assert(searches==(mode==10?2:(mode==1 || mode==4 || mode==5 || mode==7 || mode==8 || mode==9 || mode>=11)?1:0));
        assert(application_sessions==(searches!=0));
        assert(confirmation_queries==((mode==13 || mode==14)?3:(mode==1 || mode==10 || mode==15)?1:0));
        assert(queries==(mode==10?4:(mode==1 || mode==8 || mode>=13)?3:(mode==4 || mode==5 || mode==11 || mode==12)?2:1));
        assert(models==0 && sessions==0 && tapes==0 && owners==0);
    }
    char path[]="/tmp/d2k-app-archive-XXXXXX";
    int fd=mkstemp(path);assert(fd>=0);close(fd);assert(!unlink(path));
    char *archived[]={"probe","192.0.2.7","dns.example","/dns-query","--measure","--archive",path,NULL};
    mode=10;queries=searches=application_sessions=confirmation_queries=archive_records=0;
    assert(application_main(7,archived)==0);
    assert(archive_records==4 && models==0 && sessions==0 && tapes==0 && owners==0);
    queries=0;
    assert(application_main(7,archived)==2 && queries==0);
    assert(!unlink(path));
    for(int failure=1;failure<=4;failure++) {
        if(failure==3)continue;
        archive_fail_at=failure;queries=searches=application_sessions=confirmation_queries=archive_records=0;
        assert(application_main(7,archived)==1);
        assert(archive_records==failure);
        assert(searches==(failure==1?0:failure==2?1:2));
        assert(models==0 && sessions==0 && tapes==0 && owners==0);
        assert(!unlink(path));
    }
    archive_fail_at=0;
    for(mode=16;mode<=18;mode++) {
        queries=searches=application_sessions=confirmation_queries=archive_records=witness_selections=0;
        assert(application_main(7,archived)==(mode==16?0:mode==18?2:1));
        assert(witness_selections==1 && confirmation_queries==(mode==18?0:3));
        assert(archive_records==(mode==18?1:3));
        assert(queries==(mode==18?1:3));
        assert(models==0 && sessions==0 && tapes==0 && owners==0);
        assert(!unlink(path));
    }
    mode=1;queries=searches=application_sessions=confirmation_queries=0;
    d2k_application_request request={.search_id=7,.port=443,.family=4,.transport=6,
        .shape=D2K_SHAPE_MODERN,.doh=1};
    strcpy(request.target,"dns.example");strcpy(request.ip,"192.0.2.7");strcpy(request.resource,"/dns-query");
    d2k_experiment network={.family=4,.port=443,.mark=0x2f,.connect_ms=5000};
    assert(inet_pton(AF_INET,request.ip,network.ip)==1);
    d2k_application_search *search=d2k_application_search_new(&request,&network,9,5000,1200,NULL);
    assert(search && !queries && !searches);
    assert(d2k_application_search_matches(search,&request,&network,9,5000,1200));
    strcpy(request.control.name,"new.example");request.control.epoch[0]=8;
    request.control.incarnation=31;request.control.bytes=99999;
    assert(d2k_application_search_matches(search,&request,&network,9,5000,1200));
    memset(&request.control,0,sizeof request.control);
    assert(!d2k_application_search_matches(search,&request,&network,10,5000,1200));
    assert(!d2k_application_search_matches(search,&request,&network,9,6000,1200));
    network.mark++;
    assert(!d2k_application_search_matches(search,&request,&network,9,5000,1200));network.mark--;
    request.resource[1]='x';
    assert(!d2k_application_search_matches(search,&request,&network,9,5000,1200));request.resource[1]='d';
    memset(&request,0,sizeof request);memset(&network,0,sizeof network);
    d2k_vres candidate;
    assert(d2k_application_search_next(search,&candidate)==D2K_SYN_CANDIDATE);
    assert(candidate.generated_input);
    assert(queries==(mode==102?3:2) && searches==1 && candidate.program_len>0);
    assert(d2k_application_search_next(search,&candidate)==D2K_SYN_CANDIDATE);
    assert(queries==(mode==102?3:2) && searches==1);
    d2k_synthesis_feedback feedback={.generation=9,.search_id=7,.target="dns.example",.ip="192.0.2.7",
        .resource="/dns-query",.program=candidate.program,.doh=1,.port=443,.family=4,.transport=6,
        .shape=D2K_SHAPE_MODERN,.applied=1,.verification_available=1,.level=D2K_VER_APPLICATION,
        .status=0,.budget=D2K_BUDGET_CUT,.budget_need=50,.budget_packets=24,.budget_requests=5,.doh_replies=4};
    feedback.trial_id[0]=4;feedback.plan_id[0]=3;
    feedback.flow.family=4;feedback.flow.transport=6;feedback.flow.a_port=50000;feedback.flow.b_port=443;
    assert(inet_pton(AF_INET,feedback.ip,feedback.flow.b_ip)==1);
    feedback.generation++;
    assert(!d2k_application_search_feedback(search,&feedback,D2K_VF_NOT_MET));feedback.generation--;
    d2k_synthesis_feedback foreign=feedback;foreign.resource="/other";
    assert(!d2k_application_search_feedback(search,&foreign,D2K_VF_NOT_MET));
    foreign=feedback;foreign.search_id++;
    assert(!d2k_application_search_feedback(search,&foreign,D2K_VF_NOT_MET));
    foreign=feedback;foreign.program="other plan";
    assert(!d2k_application_search_feedback(search,&foreign,D2K_VF_NOT_MET));
    foreign=feedback;foreign.applied=0;foreign.trial_id[0]=5;
    assert(!d2k_application_search_feedback(search,&foreign,D2K_VF_NOT_MET));
    assert(!d2k_application_search_pending_failure(search));
    assert(d2k_application_search_feedback(search,&feedback,D2K_VF_NOT_MET)==1);
    const d2k_synthesis_feedback *pending=d2k_application_search_pending_failure(search);
    assert(pending && pending->budget_requests==5 && pending->doh_replies==4);
    assert(!d2k_application_search_feedback(search,&feedback,D2K_VF_NOT_MET));
    assert(queries==(mode==102?3:2) && searches==1);
    feedback.doh_replies=3;
    assert(d2k_application_search_feedback(search,&feedback,D2K_VF_NOT_MET)==-1);
    assert(!d2k_application_search_pending_failure(search));
    d2k_application_search_free(search);
    assert(models==0 && sessions==0 && tapes==0 && owners==0);
    request=(d2k_application_request){.search_id=7,.port=443,.family=4,.transport=6,
        .shape=D2K_SHAPE_MODERN,.doh=1};
    strcpy(request.target,"dns.example");strcpy(request.ip,"192.0.2.7");strcpy(request.resource,"/dns-query");
    network=(d2k_experiment){.family=4,.port=443,.mark=0x2f,.connect_ms=5000};
    assert(inet_pton(AF_INET,request.ip,network.ip)==1);
    const int direct_modes[]={0,2,3,6};
    request.doh_failure_query=3;
    for(mode=20;mode<=22;mode++) {
        queries=searches=application_sessions=confirmation_queries=0;
        search=d2k_application_search_new(&request,&network,9,5000,1200,NULL);assert(search);
        assert(d2k_application_search_next(search,&candidate)==(mode==21?D2K_SYN_DIRECT_RESPONSE:D2K_SYN_CANDIDATE));
        assert(queries==(mode==21?1:2) && searches==(mode==21?0:1));
        d2k_application_search_free(search);assert(!models && !sessions && !tapes && !owners);
    }
    request.doh_failure_query=0;
    mode=1;queries=searches=application_sessions=confirmation_queries=0;
    search=d2k_application_search_new(&request,&network,9,5000,1200,NULL);assert(search);
    const d2k_application_model *followup=NULL;
    assert(d2k_application_search_remeasure(search,&followup)==0 && !followup && !queries);
    assert(d2k_application_search_next(search,&candidate)==D2K_SYN_CANDIDATE);
    feedback.program=candidate.program;feedback.budget_requests=3;feedback.doh_replies=2;
    assert(d2k_application_search_feedback(search,&feedback,D2K_VF_NOT_MET)==1);
    mode=13;
    assert(d2k_application_search_remeasure(search,&followup)==1 && followup);
    assert(queries==3 && confirmation_queries==3 && searches==1);
    assert(followup->count==3 && !followup->end.result.body_complete);
    const d2k_application_model *same=NULL;
    assert(d2k_application_search_remeasure(search,&same)==1 && same==followup && queries==3);
    mode=14;
    assert(d2k_application_search_next(search,&candidate)==D2K_SYN_CANDIDATE);
    assert(queries==4 && searches==2 && sessions==2 && confirmation_queries==3);
    assert(followup->count==3 && !followup->history[2].query.dns_valid);
    assert(!d2k_application_search_pending_failure(search));
    assert(!d2k_application_search_feedback(search,&feedback,D2K_VF_NOT_MET));
    assert(!d2k_application_search_pending_failure(search));
    int cumulative=candidate.probes;
    assert(d2k_application_search_next(search,&candidate)==D2K_SYN_CANDIDATE);
    assert(queries==4 && candidate.probes==cumulative);
    d2k_application_search_free(search);assert(!models && !sessions && !tapes && !owners);
    for(int variant=0;variant<4;variant++) {
        mode=1;queries=searches=application_sessions=confirmation_queries=archive_records=0;
        FILE *archive=tmpfile();assert(archive);
        search=d2k_application_search_new(&request,&network,9,5000,1200,archive);assert(search);
        assert(d2k_application_search_next(search,&candidate)==D2K_SYN_CANDIDATE);
        feedback.program=candidate.program;
        assert(d2k_application_search_feedback(search,&feedback,D2K_VF_NOT_MET)==1);
        mode=variant==3?5:variant==1?19:14;
        if(variant==2)archive_fail_at=archive_records+1;
        assert(d2k_application_search_remeasure(search,&followup)==(variant==1 || variant==2?-1:1));
        assert(queries==3 && confirmation_queries==(variant==3?0:3) && searches==1);
        assert(followup && followup->count==(variant==3?0:3));
        assert(d2k_application_search_remeasure(search,&same)==(variant==1 || variant==2?-1:1) && same==followup && queries==3);
        assert(d2k_application_search_next(search,&candidate)==(variant==3?D2K_SYN_CLOSED:D2K_SYN_ERROR) && !candidate.program_len);
        if(!variant)assert(strstr(candidate.reason,"did not reproduce"));
        assert(d2k_application_search_next(search,&candidate)==(variant==3?D2K_SYN_CLOSED:D2K_SYN_ERROR));
        assert(queries==3 && searches==1 && confirmation_queries==(variant==3?0:3));
        d2k_application_search_free(search);fclose(archive);archive_fail_at=0;
        assert(!models && !sessions && !tapes && !owners);
    }
    for(size_t i=0;i<sizeof direct_modes/sizeof direct_modes[0];i++) {
        mode=direct_modes[i];queries=searches=application_sessions=confirmation_queries=0;
        search=d2k_application_search_new(&request,&network,9,5000,1200,NULL);assert(search);
        assert(d2k_application_search_next(search,&candidate)==
            ((mode==0 || mode==2)?D2K_SYN_DIRECT_RESPONSE:D2K_SYN_ERROR));
        assert(queries==1 && !searches && !application_sessions);
        assert(candidate.program_len==0 && candidate.verdict==D2K_V_INCONCLUSIVE);
        d2k_application_search_free(search);assert(!models && !sessions && !tapes && !owners);
    }
    d2k_detect_stop stop={cancelled,NULL};network.cancel=&stop;interrupted=1;queries=0;
    search=d2k_application_search_new(&request,&network,9,5000,1200,NULL);assert(search);
    memset(&stop,0,sizeof stop);
    assert(d2k_application_search_next(search,&candidate)==D2K_SYN_ERROR && !queries);
    d2k_application_search_free(search);interrupted=0;network.cancel=NULL;
    request.ech=1;assert(!d2k_application_search_new(&request,&network,9,5000,1200,NULL));
    request.ech=0;network.ip[3]++;
    assert(!d2k_application_search_new(&request,&network,9,5000,1200,NULL));
    return 0;
}
