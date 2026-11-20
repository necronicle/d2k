#include "application_archive.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static d2k_application_end end_for(d2k_synthesis_feedback *id,uint64_t experience,int complete) {
    static const uint8_t input[]={22,3,1,0,1,1};
    d2k_application_end e={0};e.identity=id;e.experience=experience;e.raw_ordinal=4;
    e.input=input;e.input_length=sizeof input;e.timeout_ms=25;e.hello_wire=1200;
    e.network_evidence=1;e.tuple.family=4;e.tuple.local_port=50000+(unsigned)experience;
    e.tuple.remote_port=443;e.tuple.remote[0]=192;e.tuple.remote[2]=2;e.tuple.remote[3]=7;
    e.first_tls_symbol=10;e.result.status=200;e.result.body_complete=complete;
    e.result.body_expected=8;e.result.body_bytes=complete?8:2;
    e.result.level=complete?D2K_VER_APPLICATION:D2K_VER_HANDSHAKE;
    return e;
}
static d2k_application_model *http_failure(d2k_synthesis_feedback *id,uint64_t experience,
    unsigned ack,uint64_t received,int variant) {
    d2k_application_model *m=d2k_application_model_new_https(id,experience);assert(m);
    d2k_application_end end=end_for(id,experience,0);
    if(variant==10)end.result.body_bytes=4;
    uint8_t request[]="GET /page HTTP/1.1\r\n\r\n";
    if(variant==5 || variant==10)request[5]='X';
    d2k_application_http_observation o={.identity=id,.experience=experience,.raw_ordinal=1,
        .tuple=end.tuple,.sent_bytes=100,.transport={.available=1,.ack_seen=1,
            .sent_end=100,.acked_end=100,.received_payload_bytes=500},
        .event={.phase=D2K_HTTPS_REQUEST_BEGIN,.ordinal=1,.request=request,
            .request_length=sizeof request-1}};
    assert(d2k_application_model_add_http(m,&o)>0);
    o.raw_ordinal=2;o.sent_bytes=140;o.transport.sent_end=140;
    o.event.phase=D2K_HTTPS_REQUEST_SENT;
    assert(d2k_application_model_add_http(m,&o)>0);
    o.raw_ordinal=3;o.transport.acked_end=ack;o.transport.received_payload_bytes=received;
    if(variant==1)o.transport.ack_seen=0;
    if(variant==2)o.transport.available=0;
    if(variant==3)o.transport.sent_end=141;
    if(variant==4)o.sent_bytes=141;
    o.event=(d2k_https_observation){.phase=D2K_HTTPS_EXCHANGE_END,.ordinal=1,.response=&end.result};
    assert(d2k_application_model_add_http(m,&o)>0);
    assert(!d2k_application_model_finish(m,&end));
    return m;
}
static void http_transport_comparison(void) {
    d2k_synthesis_feedback a={.generation=7,.search_id=3,.target="www.example.com",
        .ip="192.0.2.7",.resource="/page",.program="baseline",.family=4,.transport=6,.port=443};
    a.trial_id[0]=1;a.plan_id[0]=1;
    d2k_synthesis_feedback b=a;b.trial_id[0]=2;b.plan_id[0]=2;b.program="candidate";
    d2k_application_model *base=http_failure(&a,1,100,500,0);
    d2k_application_http_interval interval;
    assert(d2k_application_model_http_interval(base,&interval));
    assert(interval.offset==100 && interval.length==40 && interval.ordinal==1);
    assert(interval.ack==1 && interval.acked_bytes==0 && interval.receipt==1);
    d2k_transducer observed=d2k_application_model_transducer(base);d2k_transition step;
    assert(observed.step(observed.ctx,observed.initial,1,&step)==1);
    assert(observed.step(observed.ctx,step.next,3,&step)==1);
    assert(observed.step(observed.ctx,step.next,4,&step)==1 && step.observation==(1u|(1u<<2)));
    assert(observed.step(observed.ctx,step.next,2,&step)==2);
    for(int variant=0;variant<11;variant++) {
        unsigned ack=variant==6?141:variant==7?99:variant==8?140:120;
        uint64_t received=variant==9?510:500;
        if(variant==9)ack=100;
        d2k_application_model *trial=http_failure(&b,2,ack,received,variant);
        int valid=d2k_application_model_http_interval(trial,&interval);
        assert(valid==(variant!=4));
        if(valid) {
            unsigned expected=(variant>=1 && variant<=3) || variant==6 || variant==7?0:
                variant==8?3:variant==9?1:2;
            assert(interval.ack==expected);
        }
        d2k_application_question q=d2k_application_model_question(base,trial);
        assert(q.status==(variant==5 || variant==10?D2K_APP_QUESTION_CONTEXT:
            variant==0 || variant==8 || variant==9?D2K_APP_CHANGED:D2K_APP_REPRODUCED));
        if(variant==0)assert(q.reference==(D2K_APP_QUERY_ACK|1) && q.observed==(D2K_APP_QUERY_ACK|2));
        if(variant==9)assert(q.reference==D2K_APP_RX_SILENT && q.observed==D2K_APP_RX_PAYLOAD);
        d2k_application_model_free(trial);
    }
    d2k_application_model_free(base);
}
int main(void) {
    http_transport_comparison();
    d2k_synthesis_feedback a={.generation=7,.search_id=3,.target="www.example.com",
        .ip="192.0.2.7",.resource="/page",.program="baseline",.family=4,.transport=6,.port=443};
    a.trial_id[0]=1;a.plan_id[0]=1;
    d2k_synthesis_feedback b=a;b.trial_id[0]=2;b.plan_id[0]=2;b.program="candidate";
    assert(!d2k_application_model_new(&a,1));
    d2k_application_model *failed=d2k_application_model_new_https(&a,1);assert(failed);
    d2k_application_model *passed=d2k_application_model_new_https(&b,2);assert(passed);
    d2k_application_end f=end_for(&a,1,0),p=end_for(&b,2,1);
    uint8_t request[]="GET /page HTTP/1.1\r\n\r\n";
    d2k_application_http_observation http={.identity=&a,.experience=1,.raw_ordinal=1,
        .tuple=f.tuple,.sent_bytes=100,.event={.phase=D2K_HTTPS_REQUEST_BEGIN,.ordinal=1,
            .request=request,.request_length=sizeof request-1}};
    assert(d2k_application_model_add_http(failed,&http)==D2K_APP_UNPREDICTED);
    request[0]='X';
    assert(d2k_application_model_http_at(failed,0)->event.request[0]=='G');
    request[0]='G';http.raw_ordinal=2;http.sent_bytes=140;http.event.phase=D2K_HTTPS_REQUEST_SENT;
    assert(d2k_application_model_add_http(failed,&http)==D2K_APP_UNPREDICTED);
    assert(d2k_application_model_add_http(failed,&http)==D2K_APP_REJECTED);
    http.raw_ordinal=3;http.event=(d2k_https_observation){.phase=D2K_HTTPS_EXCHANGE_END,
        .ordinal=1,.response=&f.result};
    assert(d2k_application_model_add_http(failed,&http)==D2K_APP_UNPREDICTED);
    assert(d2k_application_model_http_count(failed)==3);
    f.result.body_bytes=99;
    assert(d2k_application_model_http_at(failed,2)->event.response->body_bytes==2);
    assert(d2k_application_model_finish(failed,&f)==-1);
    f.result.body_bytes=2;
    d2k_application_observation dns={.identity=&a,.experience=1};
    assert(d2k_application_model_add(failed,&dns)==D2K_APP_REJECTED);
    assert(d2k_application_model_finish(failed,&f)==0);
    p.result.doh_replies=1;
    assert(d2k_application_model_finish(passed,&p)==-1);
    p.result.doh_replies=0;
    assert(d2k_application_model_finish(passed,&p)==0);
    d2k_application_question q=d2k_application_model_question(failed,passed);
    assert(q.status==D2K_APP_CHANGED);
    d2k_application_model *partial=d2k_application_model_new_https(&b,3);assert(partial);
    d2k_application_end more=end_for(&b,3,0);more.result.body_bytes=4;
    assert(!d2k_application_model_finish(partial,&more));
    q=d2k_application_model_question(failed,partial);
    assert(q.status==D2K_APP_CHANGED && q.reference==2 && q.observed==4);
    d2k_transducer model=d2k_application_model_transducer(partial);d2k_transition edge;
    assert(model.step(model.ctx,model.initial,1,&edge)==1);
    assert(model.step(model.ctx,edge.next,3,&edge)==1 && edge.observation==4);
    assert(model.step(model.ctx,edge.next,2,&edge)==2);
    d2k_application_model_free(partial);
    FILE *archive=tmpfile();assert(archive);
    assert(d2k_application_archive_write(archive,failed)==0);
    rewind(archive);char magic[8];assert(fread(magic,1,8,archive)==8 && !memcmp(magic,"D2KAPP05",8));
    rewind(archive);d2k_application_model *restored=NULL;
    assert(d2k_application_archive_read(archive,&restored)==1 && restored);
    assert(d2k_application_model_kind(restored)==D2K_APPLICATION_HTTPS);
    assert(d2k_application_model_http_count(restored)==3);
    const d2k_application_http_observation *saved=d2k_application_model_http_at(restored,1);
    assert(saved && saved->sent_bytes==140 && saved->event.phase==D2K_HTTPS_REQUEST_SENT);
    assert(saved->event.request_length==sizeof request-1 && !memcmp(saved->event.request,request,sizeof request-1));
    saved=d2k_application_model_http_at(restored,2);
    assert(saved->event.response->body_bytes==2 && !saved->event.response->body_complete);
    const d2k_application_end *e=d2k_application_model_end(restored);
    assert(e && !e->identity->doh && !e->result.body_complete && e->result.body_bytes==2);
    assert(!strcmp(e->identity->resource,"/page"));
    model=d2k_application_model_transducer(restored);
    assert(model.step(model.ctx,model.initial,1,&edge)==1);
    assert(model.step(model.ctx,edge.next,3,&edge)==1 && edge.observation==2);
    q=d2k_application_model_question(restored,passed);assert(q.status==D2K_APP_CHANGED);
    FILE *v4=tmpfile();assert(v4 && !d2k_application_archive_write(v4,passed));
    rewind(v4);assert(fread(magic,1,8,v4)==8 && !memcmp(magic,"D2KAPP04",8));
    rewind(v4);d2k_application_model *old=NULL;
    assert(d2k_application_archive_read(v4,&old)==1 && !d2k_application_model_http_count(old));
    d2k_application_model_free(old);fclose(v4);
    a.doh=1;assert(!d2k_application_model_new_https(&a,3));
    d2k_application_model_free(restored);d2k_application_model_free(failed);
    d2k_application_model_free(passed);fclose(archive);
    puts("HTTPS model: copied HTTP history, owned comparison, v4/v5 archive roundtrip pass");
    return 0;
}
