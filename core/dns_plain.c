#define _POSIX_C_SOURCE 200809L
#include "d2k_dns_exchange.h"
#include "d2k_crypto.h"
#include "d2k_dns_message.h"
#include "d2k_dns_plain.h"
#include "d2k_flow_io.h"
#include "d2k_tls13core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int allowed(void *context) {
    (void)context;
    return 1;
}

d2k_ver_result d2k_plain_dns_prepare(const char *ip,uint16_t port,uint8_t transport,
    const char *question,uint16_t type,int timeout,uint32_t mark,d2k_plain_dns_request *out) {
    d2k_ver_result r={.fd=-1,.name_ok=-1};
    d2k_plain_dns_request request={.transport=transport};
    uint16_t id;
    if (!out || !type || timeout<=0 || timeout>600000 ||
        d2k_t13_random((uint8_t *)&id,sizeof id) ||
        !(request.length=d2k_dns_question(question,type,id,request.question,sizeof request.question))) {
        r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"plain DNS local question or probe setup failed");
        return r;
    }
    uint8_t wire[D2K_DNS_PROBE_WIRE_MAX];
    size_t wire_size=d2k_dns_probe_frame(transport,request.question,request.length,wire);
    if (!wire_size) {
        r.local_refusal=1;
        snprintf(r.reason,sizeof r.reason,"unsupported plain DNS probe transport");
        return r;
    }
    d2k_sha256(wire,wire_size,request.wire_digest);
    uint32_t interval=timeout<100 ? (uint32_t)timeout : 100;
    struct d2k_flow_open_options open={
        ip,port,transport,mark,(uint32_t)timeout,interval,allowed,NULL
    };
    struct d2k_flow_open_result flow;
    enum d2k_flow_open_status status=d2k_flow_open_numeric(&open,&flow);
    if (status!=D2K_FLOW_OPEN_OK) {
        r.local_refusal=status==D2K_FLOW_OPEN_LOCAL || status==D2K_FLOW_OPEN_CANCELLED;
        r.budget=status==D2K_FLOW_OPEN_TIMEOUT ? D2K_BUDGET_CUT : D2K_BUDGET_NOT_APPLICABLE;
        snprintf(r.reason,sizeof r.reason,"plain DNS %s failed before query (errno %d)",
            r.local_refusal ? "local setup" : "connection",flow.error);
        return r;
    }
    r.level=D2K_VER_TRANSPORT;
    r.family=flow.family;r.local_port=flow.source_port;r.fd=flow.fd;
    memcpy(r.local_addr,flow.source,sizeof r.local_addr);
    if (flow.family==4)memcpy(r.local_ip4,flow.source,sizeof r.local_ip4);
    *out=request;
    snprintf(r.reason,sizeof r.reason,"plain DNS socket prepared, query not submitted");
    return r;
}

void d2k_plain_dns_run(const d2k_plain_dns_request *request,int timeout,d2k_ver_result *r) {
    d2k_plain_dns_run_guarded(request,timeout,NULL,NULL,r);
}

void d2k_plain_dns_run_guarded(const d2k_plain_dns_request *request,int timeout,
    int (*permitted)(void *),void *context,d2k_ver_result *r) {
    if (!r)return;
    if (!request || r->fd<0 || r->level!=D2K_VER_TRANSPORT || r->budget_requests ||
        timeout<=0 || timeout>600000 || !request->length ||
        request->length>sizeof request->question ||
        (request->transport!=6 && request->transport!=17)) {
        r->local_refusal=1;
        snprintf(r->reason,sizeof r->reason,"plain DNS exchange has no valid prepared request");
        return;
    }
    uint8_t *answer=malloc(UINT16_MAX);
    if (!answer) {
        r->local_limit=1;
        snprintf(r->reason,sizeof r->reason,"plain DNS answer buffer allocation failed");
        return;
    }
    uint8_t transport=request->transport;
    uint32_t interval=timeout<100 ? (uint32_t)timeout : 100;
    struct d2k_dns_exchange_options opts={
        transport,(uint32_t)timeout,interval,permitted,context,UINT16_MAX
    };
    struct d2k_dns_exchange_result result;
    enum d2k_dns_exchange_status exchange=d2k_dns_exchange(r->fd,&opts,request->question,request->length,
        answer,UINT16_MAX,&result);
    free(answer);
    size_t expected=request->length+(transport==6 ? 2 : 0);
    r->budget_requests=1;
    if (result.sent==expected)r->dns_query_bytes=(uint16_t)expected;
    if (exchange==D2K_DNS_EXCHANGE_OK) {
        r->level=D2K_VER_APPLICATION;
        r->body_complete=1;r->body_bytes=result.answer_length;
        r->doh_replies=1;r->budget=D2K_BUDGET_PASSED;
        snprintf(r->reason,sizeof r->reason,"DNS %s: reply matched the requested name, type and ID",
            transport==17 ? "UDP" : "TCP");
    } else {
        r->dns_reply_rejected=exchange==D2K_DNS_EXCHANGE_PROTOCOL;
        r->local_refusal=exchange==D2K_DNS_EXCHANGE_LOCAL;
        r->budget=exchange==D2K_DNS_EXCHANGE_TIMEOUT ? D2K_BUDGET_CUT : D2K_BUDGET_NOT_APPLICABLE;
        const char *why=r->dns_reply_rejected ? "invalid or refused DNS reply" :
            r->local_refusal ? "local probe error" : "no matching DNS reply";
        snprintf(r->reason,sizeof r->reason,"DNS %s: %s (errno %d)",
            transport==17 ? "UDP" : "TCP",why,result.error);
    }
}

void d2k_plain_dns_run_trial(const d2k_plain_dns_request *request,int timeout,
    int (*permitted)(void *),void *context,d2k_ver_result *r) {
    if (!r)return;
    if (!request || request->transport!=17 || timeout>600000) {
        d2k_plain_dns_run_guarded(request,timeout,permitted,context,r);
        return;
    }
    if (timeout<2) {
        r->local_refusal=1;
        snprintf(r->reason,sizeof r->reason,"plain DNS UDP trial has no time for a direct control");
        return;
    }
    /* A distinct ID keeps the first datagram outside the installed digest
       and prevents a late direct reply from becoming candidate evidence. */
    d2k_plain_dns_request direct=*request;
    direct.question[0]^=1;
    d2k_ver_result baseline=*r;
    int control_ms=timeout/2;
    d2k_plain_dns_run_guarded(&direct,control_ms,permitted,context,&baseline);
    if (baseline.budget!=D2K_BUDGET_CUT || baseline.dns_query_bytes!=request->length ||
        baseline.dns_reply_rejected || baseline.local_refusal || baseline.local_limit) {
        *r=baseline;
        return;
    }
    d2k_plain_dns_run_guarded(request,timeout-control_ms,permitted,context,r);
    r->budget_requests+=baseline.budget_requests;
}

d2k_ver_result d2k_plain_dns_probe(const char *ip,uint16_t port,uint8_t transport,
    const char *question,uint16_t type,int timeout,uint32_t mark) {
    d2k_plain_dns_request request;
    d2k_ver_result r=d2k_plain_dns_prepare(ip,port,transport,question,type,timeout,mark,&request);
    if (r.fd>=0)d2k_plain_dns_run(&request,timeout,&r);
    return r;
}
