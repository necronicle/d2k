#include "verification.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
typedef struct verification_record {
    d2k_synthesis_feedback value;
    struct verification_record *next;
} verification_record;
struct d2k_verification_owner {
    d2k_synthesis_feedback identity;
    char target[256],ip[INET6_ADDRSTRLEN],program[4096],resource[512];
    uint8_t address[16];
    int require_budget,conflict;
    verification_record *records;
};
static int present(const uint8_t *bytes,size_t n)
{ for(size_t i=0;i<n;i++) if(bytes[i])return 1;return 0; }
static int copy(char *dst,size_t cap,const char *src)
{
    size_t n;
    if(!src || !(n=strlen(src)) || n>=cap) return 0;
    memcpy(dst,src,n+1);return 1;
}
d2k_verification_owner *d2k_verification_new(const d2k_synthesis_feedback *e,int budget)
{
    d2k_verification_owner *o;
    if(!e || !e->generation || !e->search_id || !e->port ||
       (e->family!=4 && e->family!=6) || e->transport!=6) return NULL;
    o=calloc(1,sizeof(*o));if(!o)return NULL;
    if(!copy(o->target,sizeof o->target,e->target) || !copy(o->ip,sizeof o->ip,e->ip) ||
       !copy(o->program,sizeof o->program,e->program) ||
       !copy(o->resource,sizeof o->resource,e->resource) ||
       inet_pton(e->family==6?AF_INET6:AF_INET,e->ip,o->address)!=1) {free(o);return NULL;}
    o->identity=*e;o->identity.target=o->target;o->identity.ip=o->ip;
    o->identity.program=o->program;o->identity.resource=o->resource;
    o->require_budget=budget || e->doh;
    return o;
}
void d2k_verification_free(d2k_verification_owner *o)
{
    if(!o)return;
    while(o->records) { verification_record *r=o->records;o->records=r->next;free(r); }
    free(o);
}
const d2k_synthesis_feedback *d2k_verification_identity(const d2k_verification_owner *o)
{ return o?&o->identity:NULL; }
static int same(const d2k_synthesis_feedback *a,const d2k_synthesis_feedback *b)
{
#define EQ(field) if(a->field!=b->field)return 0
    EQ(applied);EQ(verification_available);EQ(events_lost);EQ(execution_refusal);
    EQ(level);EQ(status);EQ(body_complete);EQ(local_refusal);EQ(local_limit);EQ(unsupported);
    EQ(challenge);EQ(budget);EQ(budget_uncountable);EQ(body_bytes);
    EQ(budget_need);EQ(budget_packets);EQ(budget_requests);EQ(doh_replies);
    EQ(flow.family);EQ(flow.transport);EQ(flow.a_port);EQ(flow.b_port);
#undef EQ
    return !memcmp(a->plan_id,b->plan_id,sizeof a->plan_id) &&
        !memcmp(a->flow.a_ip,b->flow.a_ip,sizeof a->flow.a_ip) &&
        !memcmp(a->flow.b_ip,b->flow.b_ip,sizeof a->flow.b_ip);
}
d2k_verification_status d2k_verification_accept(d2k_verification_owner *o,
    const d2k_synthesis_feedback *e)
{
    const d2k_synthesis_feedback *id;
    verification_record *r;
    size_t iplen;
    if(!o || !e)return D2K_VF_ERROR;
    id=&o->identity;
    if(e->generation!=id->generation || e->search_id!=id->search_id ||
       e->port!=id->port || e->family!=id->family || e->transport!=id->transport ||
       e->shape!=id->shape || e->by_addr!=id->by_addr || e->doh!=id->doh ||
       !e->target || !e->ip || !e->program || !e->resource ||
       strcmp(e->target,id->target) || strcmp(e->ip,id->ip) ||
       strcmp(e->program,id->program) || strcmp(e->resource,id->resource) ||
       (present(id->plan_id,sizeof id->plan_id) && memcmp(id->plan_id,e->plan_id,sizeof id->plan_id)))
        return D2K_VF_FOREIGN;
    if(o->conflict)return D2K_VF_CONFLICT;
    if(!present(e->trial_id,sizeof e->trial_id) || !present(e->plan_id,sizeof e->plan_id))
        return D2K_VF_UNKNOWN;
    for(r=o->records;r;r=r->next) if(!memcmp(r->value.trial_id,e->trial_id,sizeof e->trial_id)) {
        if(same(&r->value,e))return D2K_VF_DUPLICATE;
        o->conflict=1;return D2K_VF_CONFLICT;
    }
    r=malloc(sizeof(*r));if(!r)return D2K_VF_ERROR;
    r->value=*e;
    r->value.target=id->target;r->value.ip=id->ip;
    r->value.program=id->program;r->value.resource=id->resource;
    r->next=o->records;o->records=r;
    iplen=e->family==6?16:4;
    int flow_matches=e->flow.family==e->family && e->flow.transport==e->transport &&
        e->flow.a_port && e->flow.b_port &&
        ((e->flow.a_port==e->port && !memcmp(e->flow.a_ip,o->address,iplen)) ||
         (e->flow.b_port==e->port && !memcmp(e->flow.b_ip,o->address,iplen)));
    if(!e->verification_available || !e->applied || !flow_matches || e->events_lost ||
       e->execution_refusal || e->local_refusal || e->local_limit || e->unsupported ||
       e->challenge || e->budget_uncountable || e->level!=D2K_VER_APPLICATION)
        return D2K_VF_UNKNOWN;
    if(e->body_complete && (e->status<200 || e->status>=300))
        return D2K_VF_APP_NOT_MET;
    if(e->budget==D2K_BUDGET_CUT) {
        int missing_doh_reply=e->doh && e->status==0 && !e->body_complete &&
            e->budget_requests>1 && e->doh_replies==e->budget_requests-1;
        int response_status=e->status>=200 && e->status<300 && (!e->doh || e->status==200);
        if(!e->budget_need || !e->budget_packets || !e->budget_requests ||
           (!response_status && !missing_doh_reply))
            return D2K_VF_UNKNOWN;
        return D2K_VF_NOT_MET;
    }
    if(!e->body_complete)return D2K_VF_UNKNOWN;
    if(e->doh && e->status==200 && e->budget==D2K_BUDGET_PASSED &&
       !e->budget_need && e->budget_requests==1)return D2K_VF_QUERY_OBSERVED;
    if(o->require_budget && (e->budget!=D2K_BUDGET_PASSED || !e->budget_need ||
        e->budget_packets<e->budget_need || (e->doh && !e->budget_requests)))return D2K_VF_UNKNOWN;
    return D2K_VF_OBSERVED;
}
