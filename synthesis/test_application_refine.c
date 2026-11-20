#include "application_refine.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
static const uint8_t input[]={22,3,1,0,1,1};
static int mode,calls,bad_seed,http_case;static unsigned serial=20;
size_t d2k_tls_probe_hello(const d2k_tls_probe_seed *seed,const char *name,size_t wire,
    const uint8_t *alpn,size_t alpn_length,uint8_t *out,size_t cap) {
    (void)seed;(void)name;(void)wire;
    if(http_case)assert(alpn_length==9 && !memcmp(alpn,"\10http/1.1",9));
    assert(cap>=sizeof input);memcpy(out,input,sizeof input);out[5]+=(uint8_t)bad_seed;return sizeof input;
}
int d2k_detect_stopped(const d2k_detect_stop *stop){return stop && stop->fn && stop->fn(stop->ctx);}
int d2k_application_query_complete(const d2k_ver_result *r){return r->level==D2K_VER_APPLICATION && r->status==200 && r->body_complete && r->doh_replies && !r->local_refusal;}
int d2k_application_save(FILE *f,const d2k_application_model *m,d2k_ver_result *r){(void)f;(void)m;(void)r;return mode==5?-1:0;}
int d2k_application_identify_trial(d2k_synthesis_feedback *id,char *program){
    id->trial_id[0]=(uint8_t)++serial;id->plan_id[0]=(uint8_t)serial;id->program=program;return 0;
}
static d2k_application_model *series(d2k_synthesis_feedback id,uint64_t exp,unsigned depth,
    unsigned fail,int owned,d2k_application_decision decide,void *ctx,d2k_ver_result *result) {
    d2k_application_model *m=d2k_application_model_new(&id,exp);assert(m);
    d2k_application_observation o={.identity=&id,.experience=exp,.input=input,.input_length=sizeof input};
    o.tuple.family=4;o.tuple.local_port=50000;o.tuple.remote_port=443;o.tuple.remote[0]=192;o.tuple.remote[2]=2;o.tuple.remote[3]=7;
    o.first_tls_available=1;o.first_tls_symbol=42;
    for(unsigned i=1;i<=depth;i++){
        o.raw_ordinal=3*i;o.query.ordinal=i;o.query.stream_id=2*i-1;o.query.query_schema=D2K_DOH_QUERY_SCHEMA_V1;o.query.timeout_ms=25;
        o.query.dns_valid=i!=fail;o.query.timed_out=i==fail;o.query.response=(d2k_ver_result){.level=D2K_VER_APPLICATION,.status=200,.body_complete=i!=fail,.budget_requests=i,.doh_replies=i-(i==fail)};
        d2k_application_update update=d2k_application_model_add(m,&o);assert(update>0);
        int again=decide?decide(ctx,m,update):1;
        if(!again || i==fail)break;
    }
    d2k_application_end end={.identity=&id,.experience=exp,.raw_ordinal=o.raw_ordinal+1,.tuple=o.tuple,.input=input,.input_length=sizeof input,
        .first_tls_symbol=42,.network_evidence=owned,.result=o.query.response,.timeout_ms=25,.hello_wire=1200};
    assert(!d2k_application_model_finish(m,&end));*result=end.result;return m;
}
d2k_verification_status d2k_application_doh_learn(const d2k_synthesis_feedback *id,uint64_t exp,
    const d2k_experiment *net,const d2k_tls_probe_seed *seed,int timeout,size_t wire,
    d2k_application_decision decide,void *ctx,d2k_application_model **out,d2k_ver_result *result) {
    (void)net;(void)seed;assert(timeout==25 && wire==1200);calls++;
    d2k_synthesis_feedback copy=*id;if(mode==3)copy.target="foreign.example";
    *out=series(copy,exp,mode==4?1:3,mode==1?2:0,mode!=2,decide,ctx,result);return D2K_VF_UNKNOWN;
}
static d2k_application_model *http_series(d2k_synthesis_feedback id,uint64_t exp,int complete,int owned,
    d2k_ver_result *result) {
    d2k_application_model *m=d2k_application_model_new_https(&id,exp);assert(m);
    d2k_application_end end={.identity=&id,.experience=exp,.raw_ordinal=4,.input=input,.input_length=sizeof input,
        .first_tls_symbol=42,.network_evidence=owned,.timeout_ms=25,.hello_wire=1200,
        .tuple={.family=4,.local_port=50000,.remote_port=443,.remote={192,0,2,7}},
        .result={.level=complete?D2K_VER_APPLICATION:D2K_VER_HANDSHAKE,.status=200,
            .body_complete=complete,.body_expected=8,.body_bytes=complete?8:2}};
    if(mode==4)end.result.cloudflare_challenge=1;
    const uint8_t request[]="GET /page HTTP/1.1\r\n\r\n";
    d2k_application_http_observation o={.identity=&id,.experience=exp,.raw_ordinal=1,
        .tuple=end.tuple,.sent_bytes=6,.event={.phase=D2K_HTTPS_REQUEST_BEGIN,.ordinal=1,
            .request=request,.request_length=sizeof request-1}};
    assert(d2k_application_model_add_http(m,&o)>0);
    o.raw_ordinal++;o.sent_bytes=30;o.event.phase=D2K_HTTPS_REQUEST_SENT;
    assert(d2k_application_model_add_http(m,&o)>0);
    o.raw_ordinal++;o.event=(d2k_https_observation){.phase=D2K_HTTPS_EXCHANGE_END,.ordinal=1,.response=&end.result};
    assert(d2k_application_model_add_http(m,&o)>0);
    assert(!d2k_application_model_finish(m,&end));*result=end.result;return m;
}
d2k_verification_status d2k_application_https_learn(const d2k_synthesis_feedback *id,uint64_t exp,
    const d2k_experiment *net,const d2k_tls_probe_seed *seed,int timeout,size_t wire,
    d2k_application_model **out,d2k_ver_result *result) {
    (void)net;(void)seed;assert(http_case && timeout==25 && wire==1200);calls++;
    d2k_synthesis_feedback copy=*id;if(mode==3)copy.target="foreign.example";
    *out=http_series(copy,exp,mode!=1,mode!=2,result);return D2K_VF_UNKNOWN;
}
int main(void) {
    d2k_synthesis_feedback id={.generation=7,.search_id=3,.target="dns.example",.ip="192.0.2.7",.resource="/dns-query",.program="baseline",.doh=1,.family=4,.transport=6,.port=443,.shape=D2K_SHAPE_MODERN};
    id.trial_id[0]=1;id.plan_id[0]=1;d2k_ver_result result;
    d2k_application_model *base=series(id,1,2,2,1,NULL,NULL,&result);
    d2k_experiment net={.family=4,.port=443,.ip={192,0,2,7}};
    for(mode=0;mode<6;mode++) {
        char *a,*b,err[200];assert(!d2k_lower_tls_prefix((uint8_t[]){1,2,3,4},4,1400,0,&a,err,sizeof err));
        assert(!d2k_lower_tls_prefix((uint8_t[]){0,0,0,0},4,1400,0,&b,err,sizeof err));
        d2k_prefix_refiner *r=d2k_prefix_refiner_new_plans(a,b);assert(r);free(a);free(b);
        const char *plan;uint64_t before,after;assert(d2k_prefix_refiner_next_plan(r,&before,&plan)==1);
        d2k_application_model *observed=NULL;
        calls=0;bad_seed=1;
        d2k_application_model *healthy=series(id,3,3,0,1,NULL,NULL,&result);
        assert(d2k_application_refine_step(r,healthy,2,&net,(const d2k_tls_probe_seed *)&net,3,NULL,&observed,&result)==-1 && !calls && !observed);
        d2k_application_model_free(healthy);
        assert(d2k_application_refine_step(r,base,2,&net,(const d2k_tls_probe_seed *)&net,3,NULL,&observed,&result)==-1 && !calls && !observed);
        bad_seed=0;
        net.port=80;
        assert(d2k_application_refine_step(r,base,2,&net,(const d2k_tls_probe_seed *)&net,3,NULL,&observed,&result)==-1 && !calls && !observed);
        net.port=443;
        int status=d2k_application_refine_step(r,base,2,&net,(const d2k_tls_probe_seed *)&net,3,NULL,&observed,&result);
        assert(calls==1 && status==(mode<2?1:-1));
        assert(d2k_prefix_refiner_next_plan(r,&after,&plan)==1);
        assert(mode<2?after!=before:after==before);
        d2k_application_model_free(observed);d2k_prefix_refiner_free(r);
    }
    d2k_application_model_free(base);
    http_case=1;mode=0;id.doh=0;id.resource="/page";
    base=http_series(id,1,0,1,&result);
    for(mode=0;mode<6;mode++) {
        char *a,*b,err[200];assert(!d2k_lower_tls_prefix((uint8_t[]){1,2,3,4},4,1400,0,&a,err,sizeof err));
        assert(!d2k_lower_tls_prefix((uint8_t[]){0,0,0,0},4,1400,0,&b,err,sizeof err));
        d2k_prefix_refiner *r=d2k_prefix_refiner_new_plans(a,b);assert(r);free(a);free(b);
        const char *plan;uint64_t before,after;assert(d2k_prefix_refiner_next_plan(r,&before,&plan)==1);
        d2k_application_model *observed=NULL;calls=0;
        int status=d2k_application_refine_step(r,base,2,&net,(const d2k_tls_probe_seed *)&net,1,NULL,&observed,&result);
        assert(calls==1 && status==(mode<2?1:-1));
        assert(d2k_prefix_refiner_next_plan(r,&after,&plan)==1);
        assert(mode<2?after!=before:after==before);
        d2k_application_model_free(observed);d2k_prefix_refiner_free(r);
    }
    d2k_application_model_free(base);return 0;
}
