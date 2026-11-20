#include "application_model.h"
#include <assert.h>
#include <string.h>
static void comparison_checks_context_before_tls_difference(void) {
    d2k_synthesis_feedback a={0};a.generation=7;a.search_id=3;
    a.target="dns.example";a.ip="192.0.2.7";a.resource="/dns-query";
    a.program="baseline";a.doh=1;a.family=4;a.transport=6;a.port=443;
    a.trial_id[0]=1;a.plan_id[0]=1;
    d2k_synthesis_feedback b=a;b.trial_id[0]=2;b.plan_id[0]=2;b.program="candidate";
    uint8_t input[]={22,3,1,0,1,1};
    d2k_application_observation o={0};o.identity=&a;o.experience=1;
    o.input=input;o.input_length=sizeof input;o.raw_ordinal=3;
    o.tuple.family=4;o.tuple.local_port=50000;o.tuple.remote_port=443;
    o.tuple.remote[0]=192;o.tuple.remote[2]=2;o.tuple.remote[3]=7;
    o.first_tls_available=1;o.first_tls_symbol=10;
    o.query.ordinal=1;o.query.stream_id=1;o.query.query_schema=D2K_DOH_QUERY_SCHEMA_V1;
    o.query.timeout_ms=25;o.query.timed_out=1;o.query.response.budget_requests=1;
    d2k_application_model *reference=d2k_application_model_new(&a,1);assert(reference);
    assert(d2k_application_model_add(reference,&o)>0);
    o.identity=&b;o.experience=2;o.first_tls_symbol=11;
    for(int same_timeout=0;same_timeout<2;same_timeout++) {
        o.query.timeout_ms=same_timeout?25:50;
        d2k_application_model *trial=d2k_application_model_new(&b,2);assert(trial);
        assert(d2k_application_model_add(trial,&o)>0);
        d2k_application_question q=d2k_application_model_question(reference,trial);
        assert(q.status==(same_timeout?D2K_APP_CHANGED:D2K_APP_QUESTION_CONTEXT));
        if(same_timeout)assert(q.ordinal==0 && q.reference==10 && q.observed==11);
        d2k_application_model_free(trial);
    }
    for(int variant=0;variant<3;variant++) {
        d2k_application_model *trial=d2k_application_model_new(&b,2);assert(trial);
        uint8_t different_input[]={22,3,1,0,1,2};
        d2k_application_end end={0};end.identity=&b;end.experience=2;
        end.raw_ordinal=4;end.tuple=o.tuple;end.network_evidence=1;
        end.input=variant==1?different_input:input;end.input_length=sizeof input;
        end.timeout_ms=variant==0?50:25;end.hello_wire=1200;
        end.result.level=D2K_VER_TRANSPORT;
        assert(d2k_application_model_finish(trial,&end)==0);
        d2k_application_question q=d2k_application_model_question(reference,trial);
        assert(q.status==(variant==2?D2K_APP_TRIAL_ENDED:D2K_APP_QUESTION_CONTEXT));
        d2k_application_model_free(trial);
    }
    d2k_application_model_free(reference);
}
static void comparison_distinguishes_ack_progress(void) {
    d2k_synthesis_feedback a={.generation=7,.search_id=3,.target="dns.example",
        .ip="192.0.2.7",.resource="/dns-query",.program="baseline",.doh=1,
        .family=4,.transport=6,.port=443};
    a.trial_id[0]=1;a.plan_id[0]=1;
    d2k_synthesis_feedback b=a;b.trial_id[0]=2;b.plan_id[0]=2;
    uint8_t input[]={22,3,1,0,1,1};
    d2k_application_observation o={.identity=&a,.experience=1,.input=input,
        .input_length=sizeof input,.raw_ordinal=3};
    o.tuple.family=4;o.tuple.local_port=50000;o.tuple.remote_port=443;
    o.tuple.remote[0]=192;o.tuple.remote[2]=2;o.tuple.remote[3]=7;
    o.query.ordinal=1;o.query.stream_id=1;o.query.query_schema=D2K_DOH_QUERY_SCHEMA_V1;
    o.query.timeout_ms=25;o.query.timed_out=1;o.query.response.budget_requests=1;
    o.transport.available=1;o.transport.ack_seen=1;
    o.transport.sent_end=100;o.transport.acked_end=80;
    d2k_application_model *reference=d2k_application_model_new(&a,1);assert(reference);
    assert(d2k_application_model_add(reference,&o)>0);
    for(int mode=0;mode<4;mode++) {
        o.identity=&b;o.experience=2;o.transport.available=mode!=2;
        o.transport.acked_end=mode==0?100:80;
        if(mode==3)o.transport.sent_end=0;
        d2k_application_model *trial=d2k_application_model_new(&b,2);assert(trial);
        assert(d2k_application_model_add(trial,&o)>0);
        d2k_application_question q=d2k_application_model_question(reference,trial);
        assert(q.status==(mode==0?D2K_APP_CHANGED:D2K_APP_REPRODUCED));
        if(mode==0)assert(q.ordinal==1 && q.reference!=q.observed);
        d2k_application_model_free(trial);
    }
    d2k_application_model_free(reference);
}
static void comparison_distinguishes_received_payload(void) {
    d2k_synthesis_feedback a={.generation=7,.search_id=3,.target="dns.example",
        .ip="192.0.2.7",.resource="/dns-query",.program="baseline",.doh=1,
        .family=4,.transport=6,.port=443};
    a.trial_id[0]=1;a.plan_id[0]=1;
    uint8_t input[]={22,3,1,0,1,1};
    for(int mode=0;mode<6;mode++) {
        d2k_application_model *models[2]={0};
        for(unsigned side=0;side<2;side++) {
            d2k_synthesis_feedback id=a;id.trial_id[0]+=side;
            models[side]=d2k_application_model_new(&id,side+1);assert(models[side]);
            d2k_application_observation o={.identity=&id,.experience=side+1,.input=input,
                .input_length=sizeof input,.raw_ordinal=3};
            o.tuple.family=4;o.tuple.local_port=50000+side;o.tuple.remote_port=443;
            o.tuple.remote[0]=192;o.tuple.remote[2]=2;o.tuple.remote[3]=7;
            o.query.ordinal=1;o.query.stream_id=1;o.query.query_schema=D2K_DOH_QUERY_SCHEMA_V1;
            o.query.timeout_ms=25;o.query.response.budget_requests=1;
            o.query.dns_valid=1;o.query.response.body_complete=1;o.query.response.doh_replies=1;
            o.query.response.status=200;o.query.response.level=D2K_VER_APPLICATION;
            o.transport.available=1;o.transport.received_payload_bytes=100;
            if(mode==5) {
                o.transport.ack_seen=1;o.transport.sent_end=200;o.transport.acked_end=200;
            }
            assert(d2k_application_model_add(models[side],&o)>0);
            o.raw_ordinal++;o.query.ordinal=2;o.query.stream_id=3;
            o.query.response.budget_requests=2;o.query.dns_valid=0;
            o.query.response.body_complete=0;o.query.timed_out=1;
            if(mode==5) {
                o.transport.sent_end=400;o.transport.acked_end=side?300:200;
            }
            if(side){
                o.transport.received_payload_bytes=mode==0?142:mode==3?99:100;
                if(mode==2)o.transport.available=0;
                if(mode==4)o.query.response.body_bytes=61;
            }
            assert(d2k_application_model_add(models[side],&o)>0);
        }
        d2k_application_question q=d2k_application_model_question(models[0],models[1]);
        assert(q.status==((mode==0 || mode==4 || mode==5)?D2K_APP_CHANGED:D2K_APP_REPRODUCED));
        if(mode==0)assert(q.ordinal==2 && q.reference!=q.observed);
        d2k_application_model_free(models[0]);d2k_application_model_free(models[1]);
    }
}
int main(void) {
    d2k_application_observation ack_history[2]={0};
    ack_history[0].transport=(d2k_raw_transport){.available=1,.ack_seen=1,.sent_end=200,.acked_end=100};
    ack_history[1].transport=(d2k_raw_transport){.available=1,.ack_seen=1,.sent_end=400,.acked_end=200};
    assert(d2k_application_query_ack(ack_history,2)==1);
    ack_history[1].transport.acked_end=300;
    assert(d2k_application_query_ack(ack_history,2)==2);
    ack_history[1].transport.acked_end=400;
    assert(d2k_application_query_ack(ack_history,2)==3);
    ack_history[1].transport.acked_end=401;
    assert(!d2k_application_query_ack(ack_history,2));
    ack_history[1].transport.acked_end=99;
    assert(!d2k_application_query_ack(ack_history,2));
    ack_history[1].transport.acked_end=300;ack_history[0].transport.available=0;
    assert(!d2k_application_query_ack(ack_history,2));
    assert(!d2k_application_query_ack(ack_history,1));
    comparison_distinguishes_received_payload();
    comparison_distinguishes_ack_progress();
    comparison_checks_context_before_tls_difference();
    d2k_synthesis_feedback id={0};id.generation=7;id.search_id=3;
    id.target="dns.example";id.ip="192.0.2.7";id.resource="/dns-query";
    id.program="first plan";id.doh=1;id.family=4;id.transport=6;id.port=443;
    id.plan_id[0]=1;id.trial_id[0]=2;
    d2k_application_model *m=d2k_application_model_new(&id,19);assert(m);
    d2k_application_observation o={0};o.identity=&id;o.experience=19;
    uint8_t input[]={22,3,1,0,1,1};o.input=input;o.input_length=sizeof input;
    o.tuple.family=4;o.tuple.local_port=50000;o.tuple.remote_port=443;
    o.tuple.remote[0]=192;o.tuple.remote[2]=2;o.tuple.remote[3]=7;
    o.query.dns_valid=1;o.query.response.status=200;o.query.response.body_complete=1;
    o.query.response.level=D2K_VER_APPLICATION;
    o.query.query_schema=D2K_DOH_QUERY_SCHEMA_V1;o.query.timeout_ms=25;
    for(unsigned i=1;i<=4;i++) {
        o.raw_ordinal=3*i;o.query.ordinal=i;o.query.stream_id=2*i-1;
        o.query.response.budget_requests=i;o.query.started_ms=10*i;o.query.finished_ms=10*i+1;
        if(i==2) {
            d2k_application_observation wrong=o;wrong.tuple.local_port++;
            assert(d2k_application_model_add(m,&wrong)==D2K_APP_REJECTED);
            d2k_synthesis_feedback foreign=id;foreign.program="another plan";wrong=o;wrong.identity=&foreign;
            assert(d2k_application_model_add(m,&wrong)==D2K_APP_REJECTED);
            wrong=o;wrong.query.started_ms=0;
            assert(d2k_application_model_add(m,&wrong)==D2K_APP_REJECTED);
            wrong=o;wrong.query.timeout_ms=50;
            assert(d2k_application_model_add(m,&wrong)==D2K_APP_REJECTED);
            uint8_t changed[]={22,3,1,0,1,2};wrong=o;wrong.input=changed;
            assert(d2k_application_model_add(m,&wrong)==D2K_APP_REJECTED);
        }
        if(i==4){o.query.dns_valid=0;o.query.timed_out=1;o.query.response.body_complete=0;}
        d2k_application_update u=d2k_application_model_add(m,&o);
        assert(u==(i<=2?D2K_APP_UNPREDICTED:i==3?D2K_APP_MATCH:D2K_APP_COUNTEREXAMPLE));
    }
    size_t n=0;const d2k_application_observation *history=d2k_application_model_history(m,&n);
    assert(n==4 && history[3].query.timed_out && history[0].query.dns_valid);
    assert(history[0].identity!=&id && !strcmp(history[0].identity->program,"first plan"));
    assert(history[0].input!=input && !memcmp(history[0].input,input,sizeof input));
    d2k_transducer model=d2k_application_model_transducer(m);
    size_t state=model.initial;
    for(unsigned i=0;i<4;i++) {
        d2k_transition t={0};assert(model.step(model.ctx,state,0,&t)==1);
        assert(t.observation==(i==3?D2K_APP_REPLY_TIMEOUT:D2K_APP_REPLY_DNS));state=t.next;
    }
    assert(d2k_application_model_add(m,&o)==D2K_APP_REJECTED);
    o.experience=20;assert(d2k_application_model_add(m,&o)==D2K_APP_REJECTED);
    d2k_synthesis_feedback next=id;next.program="new measured plan";next.plan_id[0]=3;next.trial_id[0]=4;
    d2k_application_model *trial=d2k_application_model_new(&next,20);assert(trial);
    d2k_application_question question=d2k_application_model_question(m,trial);
    assert(question.status==D2K_APP_ASK_QUERY && question.ordinal==1);
    o.identity=&next;o.experience=20;o.query.dns_valid=1;o.query.timed_out=0;o.query.response.body_complete=1;
    for(unsigned i=1;i<=4;i++) {
        o.query.ordinal=i;o.query.stream_id=2*i-1;o.query.response.budget_requests=i;
        o.query.started_ms=100*i;o.query.finished_ms=100*i+1;o.raw_ordinal=3*i;
        assert(d2k_application_model_add(trial,&o)>0);
        question=d2k_application_model_question(m,trial);
        assert(question.status==(i<4?D2K_APP_ASK_QUERY:D2K_APP_CHANGED));
        assert(question.ordinal==(i<4?i+1:4));
    }
    assert(question.reference==D2K_APP_REPLY_TIMEOUT && question.observed==D2K_APP_REPLY_DNS);
    assert(d2k_application_model_question(trial,m).status==D2K_APP_NO_WITNESS);
    assert(d2k_application_model_question(m,m).status==D2K_APP_QUESTION_CONTEXT);
    d2k_application_model_free(trial);
    trial=d2k_application_model_new(&next,21);assert(trial);
    o.experience=21;o.query.ordinal=1;o.query.stream_id=1;o.query.response.budget_requests=1;
    uint8_t other_input[]={22,3,1,0,1,2};o.input=other_input;
    assert(d2k_application_model_add(trial,&o)==D2K_APP_UNPREDICTED);
    assert(d2k_application_model_question(m,trial).status==D2K_APP_QUESTION_CONTEXT);
    d2k_application_model_free(trial);o.input=input;
    d2k_application_model_free(m);
    m=d2k_application_model_new(&id,19);assert(m);
    o.identity=&id;o.experience=19;o.query.ordinal=1;o.query.stream_id=1;o.query.response.budget_requests=1;
    o.query.response.local_refusal=1;
    assert(d2k_application_model_add(m,&o)==D2K_APP_REJECTED);
    d2k_application_model_history(m,&n);assert(n==0);
    d2k_application_model_free(m);return 0;
}
