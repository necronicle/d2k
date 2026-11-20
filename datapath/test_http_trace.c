#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "d2k_http_trace.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { fprintf(stderr,"FAIL: %s\n",m); fails++; } } while (0)

int main(void) {
    const char request[]="GET /private-path HTTP/1.1\r\nHost: example.com\r\nCookie: secret-cookie\r\n\r\n";
    for(int family=4;family<=6;family+=2) {
        d2k_conn conn={0};conn.family=(uint8_t)family;conn.ttl=64;
        conn.src_port=htons(53001);conn.dst_port=htons(80);
        inet_pton(AF_INET,"192.0.2.1",&conn.src_ip);inet_pton(AF_INET,"198.51.100.2",&conn.dst_ip);
        inet_pton(AF_INET6,"2001:db8::1",conn.src_ip6);inet_pton(AF_INET6,"2001:db8::2",conn.dst_ip6);
        d2k_emit emit={0};emit.kind=D2K_EMIT_PAYLOAD;emit.bytes=(const uint8_t *)request;emit.len=sizeof request-1;emit.seq=1234;
        uint8_t packet[1024];size_t n=d2k_wire_build(&conn,&emit,packet,sizeof packet);
        char line[1600]={0};d2k_result result={0};result.applied=1;result.execution_id=42;result.plan_id[0]=0xab;
        d2k_http_trace_outcome outcome={.apply=1,.hook=4,.planned=1,.pending=1,.verdict=1};
        CHECK(d2k_http_trace(line,sizeof line,packet,n,&result,&outcome)>0,"request trace present before delayed completion");
        CHECK(strstr(line,"status=PENDING")&&strstr(line,"execution=42")&&strstr(line,"plan=ab00"),"prepared is not reported as completed");
        outcome.pending=0;outcome.sent=1;
        CHECK(d2k_http_trace(line,sizeof line,packet,n,&result,&outcome)>0,"completed request trace");
        CHECK(strstr(line,"status=COMPLETE")&&strstr(line,"raw_sent=1")&&strstr(line,"original=ACCEPT"),"raw send and original verdict both visible");
        CHECK(strstr(line,"example.com")&&!strstr(line,"secret-cookie")&&!strstr(line,"private-path"),"trace exposes no request secrets");
        outcome.original_pending=1;
        d2k_http_trace(line,sizeof line,packet,n,&result,&outcome);
        CHECK(strstr(line,"status=PENDING")&&strstr(line,"original=PENDING"),"queued original is not an issued verdict");
        outcome.original_pending=0;
        outcome.original_failed=1;
        d2k_http_trace(line,sizeof line,packet,n,&result,&outcome);
        CHECK(strstr(line,"status=FAILED")&&strstr(line,"original=FAILED"),"verdict failure cannot claim completion");
        outcome.original_failed=0;outcome.output_failed=1;
        d2k_http_trace(line,sizeof line,packet,n,&result,&outcome);
        CHECK(strstr(line,"status=FAILED"),"raw failure cannot claim completion");
        outcome.output_failed=0;result.applied=0;result.skipped="no HTTP plan";
        d2k_http_trace(line,sizeof line,packet,n,&result,&outcome);
        CHECK(strstr(line,"status=SKIPPED")&&strstr(line,"no HTTP plan"),"selection failure is visible");
        outcome.apply=0;result.applied=1;
        d2k_http_trace(line,sizeof line,packet,n,&result,&outcome);
        CHECK(strstr(line,"status=OBSERVE"),"observation is not completion");
        packet[(family==6?40:20)+3]=81;
        CHECK(!d2k_http_trace(line,sizeof line,packet,n,&result,&outcome),"other ports not logged as HTTP80");

        /* Same TLS record as a prefix and as an assembled input. The trace
         * must describe ownership, execution identity and send outcome,
         * without treating prepared packets as application success. */
        uint8_t hello[1556]={0x16,0x03,0x01,0x06,0x0f,0x01};
        uint8_t tls_packet[2048];
        conn.dst_port=htons(443);
        emit.bytes=hello;emit.len=1396;
        n=d2k_wire_build(&conn,&emit,tls_packet,sizeof tls_packet);
        memset(&result,0,sizeof result);
        result.applied=1;result.execution_id=42;result.plan_id[0]=0xab;
        result.trial_id[0]=0xcd;result.binding.generation=7;
        outcome=(d2k_http_trace_outcome){.apply=1,.hook=4,.planned=2,.sent=2,.verdict=0};
        CHECK(d2k_tls_trace(line,sizeof line,tls_packet,n,&result,&outcome,0,0)>0,
              "TLS prefix has an execution trace");
        CHECK(strstr(line,"input=PREFIX")&&strstr(line,"bytes=1396")&&strstr(line,"record_bytes=1556"),
              "partial TLS input is named explicitly");
        CHECK(strstr(line,"hold=NONE")&&strstr(line,"plan=ab00")&&strstr(line,"trial=cd00")&&
              strstr(line,"execution=42")&&strstr(line,"generation=7"),
              "TLS trace identifies the actual plan, trial and generation");
        CHECK(strstr(line,"status=COMPLETE")&&strstr(line,"raw_sent=2")&&strstr(line,"application=UNKNOWN"),
              "completed packet execution does not claim application success");
        outcome.sent=1;
        d2k_tls_trace(line,sizeof line,tls_packet,n,&result,&outcome,0,0);
        CHECK(strstr(line,"status=INCOMPLETE"),"missing send evidence is not completion");
        outcome.output_failed=1;outcome.sent=1;
        d2k_tls_trace(line,sizeof line,tls_packet,n,&result,&outcome,0,0);
        CHECK(strstr(line,"status=FAILED")&&!strstr(line,"status=COMPLETE"),
              "partial raw send cannot report completed TLS execution");
        outcome.output_failed=0;outcome.sent=1;outcome.pending=1;outcome.queued=1;
        d2k_tls_trace(line,sizeof line,tls_packet,n,&result,&outcome,0,0);
        CHECK(strstr(line,"status=PENDING")&&strstr(line,"queued=1"),
              "deferred TLS output is pending");
        outcome.pending=0;outcome.queued=0;outcome.sent=2;
        emit.len=sizeof hello;
        n=d2k_wire_build(&conn,&emit,tls_packet,sizeof tls_packet);
        d2k_tls_trace(line,sizeof line,tls_packet,n,&result,&outcome,2,1);
        CHECK(strstr(line,"input=RECORD")&&strstr(line,"hold=ASSEMBLED")&&
              strstr(line,"originals=2")&&strstr(line,"owned=1"),
              "assembled local input is not reported as unheld");
        outcome.original_failed=1;
        d2k_tls_trace(line,sizeof line,tls_packet,n,&result,&outcome,2,1);
        CHECK(strstr(line,"status=FAILED")&&strstr(line,"original=FAILED"),
              "original disposition failure cannot report completion");
        outcome.original_failed=0;result.applied=0;result.skipped="no matching plan";
        d2k_tls_trace(line,sizeof line,tls_packet,n,&result,&outcome,0,0);
        CHECK(strstr(line,"status=SKIPPED")&&strstr(line,"plan=-")&&strstr(line,"no matching plan"),
              "missing TLS plan does not acquire an execution identity");
        outcome.apply=0;result.applied=1;
        d2k_tls_trace(line,sizeof line,tls_packet,n,&result,&outcome,0,0);
        CHECK(strstr(line,"status=OBSERVE"),"observe mode is not TLS execution");
        CHECK(!d2k_tls_trace(line,sizeof line,tls_packet,10,&result,&outcome,0,0),
              "truncated packet cannot acquire an execution trace");
    }
    fprintf(stderr,"HTTP/TLS execution trace: %d failures\n",fails);
    return fails?1:0;
}
