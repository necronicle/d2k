#include "application_owner.h"
#include "tls_decode.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static void partition_owner(void)
{
    d2k_synthesis_feedback id={.generation=7,.search_id=3,.target="dns.example",.ip="192.0.2.7",
        .port=443,.family=4,.transport=6,.doh=1,.resource="/dns-query"};
    id.plan_id[0]=1;id.trial_id[0]=2;
    id.program="d2k-plan 1 8\nid 01000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\nsplit payload_start +2\norder forward\n";
    static const char identity[]="d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\norder forward\n";
    const uint8_t input[]={1,2,3,4};d2k_payload_piece pieces[]={{0,2,0},{2,2,0}};
    d2k_raw_tape *tape=d2k_raw_tape_new(19);assert(tape);
    d2k_raw_tls_sink tape_sink=d2k_raw_tape_sink(tape);
    d2k_raw_tls_event saved={.experience=19,.action=D2K_RAW_TLS_OPEN};
    saved.tuple.family=4;saved.tuple.local_port=50000;saved.tuple.remote_port=443;
    saved.tuple.remote[0]=192;saved.tuple.remote[2]=2;saved.tuple.remote[3]=7;saved.observation.connected=1;
    assert(!tape_sink.record(tape_sink.context,&saved));
    for(size_t i=0;i<2;i++) {
        saved.ordinal++;saved.action=D2K_RAW_TLS_SEND;saved.program=identity;
        saved.bytes=input+2*i;saved.length=2;saved.send_offset=(uint32_t)(2*i);
        saved.observation.sent=1;saved.observation.program_packets=saved.observation.submitted_packets=1;
        assert(!tape_sink.record(tape_sink.context,&saved));
    }
    d2k_synthesis_feedback wrong=id;wrong.program=identity;
    assert(!d2k_application_owner_recorded(&wrong,1,tape,input,4));
    d2k_application_owner *recorded=d2k_application_owner_recorded(&id,1,tape,input,4);
    assert(recorded);
    assert(!d2k_application_owner_recorded(&id,1,tape,input,4));
    saved.ordinal++;saved.action=D2K_RAW_TLS_CLOSE;saved.send_offset=4;saved.bytes=NULL;saved.length=0;
    assert(!tape_sink.record(tape_sink.context,&saved));
    d2k_application_owner_free(recorded);d2k_raw_tape_free(tape);
    for(int bad=0;bad<3;bad++) {
        d2k_application_owner *o=d2k_application_owner_partition(&id,19,1,input,4,pieces,2);
        assert(o);d2k_raw_tls_sink sink=d2k_application_owner_sink(o);
        d2k_raw_tls_event e={.experience=19,.action=D2K_RAW_TLS_OPEN};
        e.tuple.family=4;e.tuple.local_port=50000;e.tuple.remote_port=443;
        e.tuple.remote[0]=192;e.tuple.remote[2]=2;e.tuple.remote[3]=7;e.observation.connected=1;
        assert(!sink.record(sink.context,&e));
        e.ordinal++;e.action=D2K_RAW_TLS_SEND;e.program=identity;e.bytes=input;e.length=2;
        e.observation.sent=1;e.observation.program_packets=e.observation.submitted_packets=1;
        if(bad==1)e.length=4;
        int rc=sink.record(sink.context,&e);assert((rc==0)==(bad!=1));
        if(!rc) {
            e.ordinal++;e.action=D2K_RAW_TLS_READ;e.send_offset=2;e.bytes=NULL;e.length=0;
            e.program=NULL;e.result=-1;e.observation.kind=D2K_RAW_OBS_RESPONSE_TIMEOUT;
            assert(!sink.record(sink.context,&e));
            d2k_doh_observation q={.ordinal=1,.stream_id=1,.dns_valid=1};
            q.response.level=D2K_VER_APPLICATION;q.response.status=200;
            q.response.body_complete=1;q.response.budget_requests=1;
            d2k_application_observation observed;
            assert(d2k_application_owner_observe(o,7,19,&q,&observed)==0);
            e.ordinal++;e.action=D2K_RAW_TLS_SEND;e.program=identity;e.length=2;e.result=0;
            e.send_offset=2;e.bytes=bad==2?input:input+2;
            rc=sink.record(sink.context,&e);assert((rc==0)==(bad!=2));
            if(!rc) {
                e.ordinal++;e.action=D2K_RAW_TLS_READ;e.send_offset=4;e.program=NULL;
                uint8_t hello[55]={22,3,3,0,50,2,0,0,46,3,3};
                hello[44]=0x13;hello[45]=1;hello[48]=6;hello[50]=43;
                hello[52]=2;hello[53]=3;hello[54]=4;
                e.bytes=hello;e.length=sizeof hello;
            e.observation.transport=(d2k_raw_transport){.available=1,.received_packets=4,.sent_end=3,.acked_end=3,.ack_seen=1};e.observation.kind=D2K_RAW_OBS_RESPONSE_BYTES;
                assert(!sink.record(sink.context,&e));
                assert(d2k_application_owner_observe(o,7,19,&q,&observed)==1);
                assert(observed.input_length==4 && observed.input!=input && !memcmp(observed.input,input,4));
                assert(!strcmp(observed.identity->program,id.program));
            }
        }
        d2k_application_owner_free(o);
    }
    pieces[0].length=1;pieces[1].offset=1;pieces[1].length=3;
    assert(!d2k_application_owner_partition(&id,19,1,input,4,pieces,2));
}
static void reverse_partition_owner(void) {
    d2k_synthesis_feedback id={.generation=7,.search_id=3,.target="dns.example",.ip="192.0.2.7",
        .port=443,.family=4,.transport=6,.doh=1,.resource="/dns-query"};
    id.plan_id[0]=1;id.trial_id[0]=2;
    id.program="d2k-plan 1 8\nid 01000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\nsplit payload_start +2\norder reverse\n";
    const char identity[]="d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\norder forward\n";
    const uint8_t input[]={1,2,3,4};
    for(int bad=0;bad<3;bad++) {
        d2k_payload_piece pieces[]={{2,2,0},{0,2,0}};
        d2k_application_owner *o=d2k_application_owner_partition(&id,19,1,input,4,pieces,2);
        assert(o);d2k_raw_tls_sink sink=d2k_application_owner_sink(o);
        d2k_raw_tls_event e={.experience=19,.action=D2K_RAW_TLS_OPEN};
        e.tuple.family=4;e.tuple.local_port=50000;e.tuple.remote_port=443;
        e.tuple.remote[0]=192;e.tuple.remote[2]=2;e.tuple.remote[3]=7;e.observation.connected=1;
        assert(!sink.record(sink.context,&e));
        for(size_t i=0;i<2;i++) {
            e.ordinal++;e.action=D2K_RAW_TLS_SEND;e.send_offset=pieces[i].offset;
            e.program=identity;e.bytes=input+pieces[i].offset;e.length=2;
            e.observation.sent=1;e.observation.program_packets=e.observation.submitted_packets=1;
            if(bad && i==1){if(bad==1)e.send_offset=2;else e.bytes=input+2;}
            int rc=sink.record(sink.context,&e);assert((rc==0)==(!bad || !i));
        }
        if(!bad) {
            e.ordinal++;e.action=D2K_RAW_TLS_CLOSE;e.send_offset=4;e.bytes=NULL;e.length=0;
            assert(!sink.record(sink.context,&e));
        }
        d2k_application_owner_free(o);
    }
}
static void recorded_program_owner(void) {
    const uint8_t input[]={1,2,3,4},other[]={1,2,3,5};
    d2k_synthesis_feedback id={.generation=7,.search_id=3,.target="dns.example",.ip="192.0.2.7",
        .port=443,.family=4,.transport=6,.doh=1,.resource="/dns-query"};
    id.plan_id[0]=1;id.trial_id[0]=2;
    id.program="d2k-plan 1 8\nid 01000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\ninput tls-sni\nsegment 1400\npayload 1 deadbeef\npoison 1 tcpts\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\n";
    char canonical[512];snprintf(canonical,sizeof canonical,"%s",id.program);
    memset(strstr(canonical,"\nid ")+4,'0',32);
    for(int bad=0;bad<9;bad++) {
        if(bad==8)strstr(canonical,"payload 1 ")[10]='c';
        d2k_raw_tape *t=d2k_raw_tape_new(19);assert(t);
        d2k_raw_tls_sink sink=d2k_raw_tape_sink(t);
        d2k_raw_tls_event e={.experience=19,.action=D2K_RAW_TLS_OPEN};
        e.tuple.family=4;e.tuple.local_port=50000;e.tuple.remote_port=443;
        e.tuple.remote[0]=192;e.tuple.remote[2]=2;e.tuple.remote[3]=7;e.observation.connected=1;
        assert(!sink.record(sink.context,&e));
        e.ordinal=1;e.action=D2K_RAW_TLS_SEND;e.program=bad==3?"foreign":bad>=7?canonical:id.program;
        e.bytes=bad==1?other:input;e.length=bad==4?3:4;e.send_offset=bad==2?1:0;
        e.observation.sent=bad==5?0:1;
        e.observation.program_packets=2;e.observation.submitted_packets=bad==6?1:2;
        assert(!sink.record(sink.context,&e));
        d2k_application_owner *o=d2k_application_owner_recorded(&id,1,t,input,sizeof input);
        assert(!!o==(bad==0 || bad==7));
        if(o) {
            assert(!d2k_application_owner_recorded(&id,1,t,input,sizeof input));
            e.ordinal++;e.action=D2K_RAW_TLS_CLOSE;e.bytes=NULL;e.length=0;e.send_offset=4;
            assert(!sink.record(sink.context,&e));
            d2k_ver_result r={.level=D2K_VER_TRANSPORT};d2k_application_end end;
            assert(!d2k_application_owner_end(o,&r,&end));
            assert(end.input_length==sizeof input && !memcmp(end.input,input,sizeof input));
            assert(!end.network_evidence);
        }
        d2k_application_owner_free(o);d2k_raw_tape_free(t);
    }
}
static void late_program_must_match_contract(void) {
    const char identity[]="d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\norder forward\n";
    d2k_synthesis_feedback id={.generation=7,.search_id=3,.target="dns.example",.ip="192.0.2.7",
        .port=443,.family=4,.transport=6,.doh=1,.resource="/dns-query",.program="initial plan"};
    id.plan_id[0]=1;id.trial_id[0]=2;
    for(int foreign=0;foreign<2;foreign++) {
        d2k_application_owner *o=d2k_application_owner_new(&id,19,1);assert(o);
        d2k_raw_tls_sink sink=d2k_application_owner_sink(o);
        d2k_raw_tls_event e={.experience=19,.action=D2K_RAW_TLS_OPEN};
        e.tuple.family=4;e.tuple.local_port=50000;e.tuple.remote_port=443;
        e.tuple.remote[0]=192;e.tuple.remote[2]=2;e.tuple.remote[3]=7;e.observation.connected=1;
        assert(!sink.record(sink.context,&e));
        const uint8_t bytes[]={1,2,3};
        e.ordinal++;e.action=D2K_RAW_TLS_SEND;e.program=id.program;e.bytes=bytes;e.length=sizeof bytes;
        e.observation.sent=1;e.observation.program_packets=e.observation.submitted_packets=1;
        assert(!sink.record(sink.context,&e));
        e.ordinal++;e.send_offset=sizeof bytes;e.program=foreign?id.program:identity;
        int rc=sink.record(sink.context,&e);
        assert((rc==0)==!foreign);
        if(foreign){e.program=identity;assert(sink.record(sink.context,&e)<0);}
        d2k_application_owner_free(o);
    }
}
static void scoped_late_program_owner(void) {
    const char identity[]="d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\norder forward\n";
    d2k_synthesis_feedback id={.generation=7,.search_id=3,.target="dns.example",.ip="192.0.2.7",
        .port=443,.family=4,.transport=6,.doh=1,.resource="/dns-query",
        .program="d2k-plan 1 16\nid 01000000000000000000000000000000\nproto tcp tls\nstream-offset 3\nsplit payload_start +1\norder forward\n"};
    id.plan_id[0]=1;id.trial_id[0]=2;
    for(int mode=0;mode<4;mode++) {
        d2k_application_owner *o=d2k_application_owner_new(&id,19,1);assert(o);
        d2k_raw_tls_sink sink=d2k_application_owner_sink(o);
        d2k_raw_tls_event e={.experience=19,.action=D2K_RAW_TLS_OPEN};
        e.tuple.family=4;e.tuple.local_port=50000;e.tuple.remote_port=443;
        e.tuple.remote[0]=192;e.tuple.remote[2]=2;e.tuple.remote[3]=7;e.observation.connected=1;
        assert(!sink.record(sink.context,&e));
        const uint8_t bytes[]={1,2,3,4};
        e.ordinal++;e.action=D2K_RAW_TLS_SEND;e.program=identity;e.bytes=bytes;e.length=mode==3?4:3;
        e.observation.sent=1;e.observation.program_packets=e.observation.submitted_packets=1;
        int rc=sink.record(sink.context,&e);assert((rc==0)==(mode!=3));
        if(mode!=3) {
            e.ordinal++;e.action=D2K_RAW_TLS_READ;e.program=NULL;e.send_offset=3;e.length=0;e.bytes=NULL;
            e.observation.kind=D2K_RAW_OBS_RESPONSE_BYTES;
            assert(!sink.record(sink.context,&e));
            d2k_doh_observation q={.ordinal=1,.stream_id=1,.dns_valid=1};
            q.response=(d2k_ver_result){.level=D2K_VER_APPLICATION,.status=200,.body_complete=1,.budget_requests=1};
            d2k_application_observation observation;
            assert(d2k_application_owner_observe(o,7,19,&q,&observation)==1);
            if(mode!=1) {
                e.ordinal++;e.action=D2K_RAW_TLS_SEND;e.program=mode==2?identity:id.program;e.bytes=bytes;e.length=3;
                rc=sink.record(sink.context,&e);assert((rc==0)==(mode==0));
            }
            if(mode<2) {
                e.ordinal++;e.action=D2K_RAW_TLS_CLOSE;e.send_offset=mode==0?6:3;e.bytes=NULL;e.length=0;
                assert(!sink.record(sink.context,&e));
                d2k_application_end end;assert(!d2k_application_owner_end(o,&q.response,&end));
                assert(end.network_evidence==(mode==0));
            }
        }
        d2k_application_owner_free(o);
    }
}
static void http_boundaries_owned(void) {
    static const char program[]="d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\norder forward\n";
    d2k_synthesis_feedback id={.generation=7,.search_id=3,.target="example.com",.ip="192.0.2.7",
        .port=443,.family=4,.transport=6,.resource="/page",.program=program};
    d2k_application_owner *o=d2k_application_owner_new(&id,19,1);assert(o);
    d2k_raw_tls_sink sink=d2k_application_owner_sink(o);
    d2k_raw_tls_event e={.experience=19,.action=D2K_RAW_TLS_OPEN};
    e.tuple.family=4;e.tuple.local_port=50000;e.tuple.remote_port=443;
    e.tuple.remote[0]=192;e.tuple.remote[2]=2;e.tuple.remote[3]=7;e.observation.connected=1;
    assert(!sink.record(sink.context,&e));
    const uint8_t bytes[]={1,2,3};
    e.ordinal++;e.action=D2K_RAW_TLS_SEND;e.program=program;e.bytes=bytes;e.length=3;
    e.observation.sent=1;e.observation.program_packets=e.observation.submitted_packets=1;
    assert(!sink.record(sink.context,&e));
    e.ordinal++;e.action=D2K_RAW_TLS_READ;e.program=NULL;e.send_offset=3;
    static const uint8_t hello[55]={[0]=22,[1]=3,[2]=3,[4]=50,[5]=2,[8]=46,[9]=3,[10]=3,
        [44]=0x13,[45]=1,[48]=6,[50]=43,[52]=2,[53]=3,[54]=4};
    e.bytes=hello;e.length=sizeof hello;e.observation.kind=D2K_RAW_OBS_RESPONSE_BYTES;
    assert(!sink.record(sink.context,&e));
    const uint8_t request[]="GET /page HTTP/1.1\r\n\r\n";
    d2k_https_observation event={.phase=D2K_HTTPS_REQUEST_BEGIN,.ordinal=1,
        .request=request,.request_length=sizeof request-1};
    d2k_application_http_observation owned;
    assert(d2k_application_owner_observe_http(o,8,19,&event,&owned)==-1);
    assert(d2k_application_owner_observe_http(o,7,20,&event,&owned)==-1);
    assert(d2k_application_owner_observe_http(o,7,19,&event,&owned)==1);
    assert(owned.sent_bytes==3 && owned.raw_ordinal==3 && owned.tuple.local_port==50000);
    assert(d2k_application_owner_observe_http(o,7,19,&event,&owned)==0);
    event.phase=D2K_HTTPS_REQUEST_SENT;
    assert(d2k_application_owner_observe_http(o,7,19,&event,&owned)==0);
    e.ordinal++;e.action=D2K_RAW_TLS_SEND;e.program=D2K_RAW_TLS_IDENTITY;e.bytes=bytes;e.length=3;
    assert(!sink.record(sink.context,&e));
    event.request=(const uint8_t *)"GET /evil HTTP/1.1\r\n\r\n";
    assert(d2k_application_owner_observe_http(o,7,19,&event,&owned)==0);
    event.request=request;
    assert(d2k_application_owner_observe_http(o,7,19,&event,&owned)==1);
    assert(owned.sent_bytes==6 && owned.raw_ordinal==4 && owned.identity->generation==7);
    d2k_ver_result response={.level=D2K_VER_APPLICATION,.status=200,.body_complete=1};
    event=(d2k_https_observation){.phase=D2K_HTTPS_EXCHANGE_END,.ordinal=1,.response=&response};
    assert(d2k_application_owner_observe_http(o,7,19,&event,&owned)==0);
    e.ordinal++;e.action=D2K_RAW_TLS_READ;e.program=NULL;e.send_offset=6;
    assert(!sink.record(sink.context,&e));
    assert(d2k_application_owner_observe_http(o,7,19,&event,&owned)==1);
    assert(owned.raw_ordinal==5 && owned.event.response->body_complete);
    assert(d2k_application_owner_observe_http(o,7,19,&event,&owned)==0);
    d2k_application_owner_free(o);
}
int main(void) {
    http_boundaries_owned();
    scoped_late_program_owner();
    late_program_must_match_contract();
    recorded_program_owner();
    reverse_partition_owner();
    partition_owner();
    d2k_synthesis_feedback id={0};
    id.generation=7;id.search_id=3;id.target="dns.example";id.ip="192.0.2.7";
    id.port=443;id.family=4;id.transport=6;id.doh=1;id.resource="/dns-query";
    id.program="exact first plan";id.plan_id[0]=1;id.trial_id[0]=2;
    for(int mode=0;mode<7;mode++) {
        d2k_application_owner *o=d2k_application_owner_new(&id,19,1);assert(o);
        d2k_raw_tls_sink sink=d2k_application_owner_sink(o);
        d2k_raw_tls_event e={0};e.experience=19;e.action=D2K_RAW_TLS_OPEN;
        e.tuple.family=4;e.tuple.local_port=50000;e.tuple.remote_port=443;
        e.tuple.remote[0]=192;e.tuple.remote[2]=2;e.tuple.remote[3]=7;
        e.tuple.local[0]=10;e.tuple.local[3]=1;e.observation.connected=1;
        assert(!sink.record(sink.context,&e));
        e.ordinal=1;e.action=D2K_RAW_TLS_SEND;e.program=id.program;
        const uint8_t bytes[]={1,2,3};e.bytes=bytes;e.length=sizeof bytes;
        e.observation.sent=1;e.observation.program_packets=2;e.observation.submitted_packets=2;
        if(mode==1)e.ordinal++;
        if(mode==2)e.tuple.local_port++;
        if(mode==3)e.program="foreign plan";
        if(mode==4)e.observation.submitted_packets=1;
        int rc=sink.record(sink.context,&e);
        assert((rc==0)==(mode==0 || mode>=5));
        if(!rc) {
            e.ordinal=2;e.action=D2K_RAW_TLS_READ;e.program=NULL;e.send_offset=3;
            e.observation.kind=D2K_RAW_OBS_RESPONSE_BYTES;
            uint8_t hello[55]={22,3,3,0,50,2,0,0,46,3,3};
            hello[44]=0x13;hello[45]=1;hello[48]=6;hello[50]=43;
            hello[52]=2;hello[53]=3;hello[54]=4;
            e.bytes=hello;e.length=sizeof hello;
            e.observation.transport=(d2k_raw_transport){.available=1,.received_packets=4,.sent_end=3,.acked_end=3,.ack_seen=1};
            if(mode==6){e.result=-2;e.observation.kind=D2K_RAW_OBS_LOCAL;}
            assert(!sink.record(sink.context,&e));
            d2k_doh_observation query={0};query.ordinal=1;query.stream_id=1;
            query.dns_valid=1;query.response.status=200;query.response.body_complete=1;
            query.response.level=D2K_VER_APPLICATION;query.response.budget_requests=1;
            d2k_application_observation owned={0};
            assert(d2k_application_owner_observe(o,8,19,&query,&owned)==-1);
            assert(d2k_application_owner_observe(o,7,20,&query,&owned)==-1);
            assert(d2k_application_owner_observe(o,7,19,&query,&owned)==
                (mode==6?0:1));
            if(mode!=6) {
                assert(owned.transport.available && owned.transport.received_packets==4 && owned.transport.acked_end==3);
                assert(owned.experience==19 && owned.raw_ordinal==3);
                assert(owned.tuple.local_port==50000 && owned.identity->generation==7);
                assert(owned.input_length==sizeof bytes && owned.input!=bytes);
                assert(!memcmp(owned.input,bytes,sizeof bytes));
                d2k_tls_response response;int timeout,reset;
                assert(owned.first_tls_available && d2k_tls_symbol_read(owned.first_tls_symbol,&response,&timeout,&reset)==1);
                assert(response.kind==D2K_TLS_OBS_HELLO && response.version==0x304 && !timeout && !reset);
                assert(!strcmp(owned.identity->program,id.program));
                assert(d2k_application_owner_observe(o,7,19,&query,&owned)==0);
                query.ordinal=2;query.stream_id=3;query.response.budget_requests=2;
                query.dns_valid=0;query.timed_out=1;query.response.body_complete=0;
                assert(d2k_application_owner_observe(o,7,19,&query,&owned)==0);
                if(mode==5) {
                    e.ordinal++;e.result=-1;e.observation.kind=D2K_RAW_OBS_RESPONSE_TIMEOUT;
                    e.bytes=NULL;e.length=0;
                    assert(!sink.record(sink.context,&e));
                    assert(d2k_application_owner_observe(o,7,19,&query,&owned)==1);
                    assert(owned.query.timed_out && !owned.query.dns_valid);
                }
            }
            e.ordinal++;e.action=D2K_RAW_TLS_CLOSE;e.bytes=NULL;e.length=0;e.result=0;
            e.observation=(d2k_raw_observation){0};
            assert(!sink.record(sink.context,&e));
        }
        d2k_ver_result r={0};r.level=D2K_VER_APPLICATION;r.status=200;r.body_complete=1;
        r.budget=D2K_BUDGET_PASSED;r.budget_need=50;r.budget_packets=52;r.budget_requests=9;
        assert(d2k_application_owner_finish(o,8,19,&r)==D2K_VF_FOREIGN);
        if(mode==5)r.local_refusal=1;
        if(mode==6){r.body_complete=0;r.budget=D2K_BUDGET_CUT;r.budget_packets=24;}
        assert(d2k_application_owner_finish(o,7,19,&r)==(mode==0?D2K_VF_OBSERVED:D2K_VF_UNKNOWN));
        if(mode==0) {
            d2k_application_end end;
            assert(!d2k_application_owner_end(o,&r,&end));
            assert(end.transport.available && end.transport.received_packets==4 && end.transport.acked_end==3);
        }
        if(mode==0)assert(d2k_application_owner_finish(o,7,19,&r)==D2K_VF_DUPLICATE);
        d2k_application_owner_free(o);
    }
    return 0;
}
