#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "d2k_preflight_lease.h"
#include "d2k_plan.h"

static int fails;
#define CHECK(c,m) do{if(!(c)){fprintf(stderr,"%s:%d FAIL %s\n",__func__,__LINE__,m);fails++;}}while(0)
static d2k_plan *plan(void) {
    const uint8_t b[]={'D','2','K','P',0,1,0,18,0,0,0,3,0,2,0,2,6,1,1,0x14,0,11,0,7,3,9,1,0,0,9,96,0,1,0,0x10,0,5,0,1,0x16,3,1};
    d2k_plan *p=NULL;char err[200];CHECK(!d2k_plan_load(b,sizeof b,&p,err,sizeof err),"fixture plan");return p;
}
static d2k_pf_scope scope(void) {
    d2k_pf_scope s={0};s.family=4;s.shape=D2K_PLAN_SHAPE_MODERN;s.server_port=htons(443);s.path=7;
    s.client[0]=192;s.client[1]=168;s.client[2]=1;s.client[3]=9;
    s.server[0]=192;s.server[2]=2;s.server[3]=8;strcpy(s.name,"video.example");return s;
}
int main(void) {
    d2k_pf_lease_table t;CHECK(!d2k_pf_lease_init(&t,2),"init");
    d2k_pf_scope s=scope();uint8_t one[16]={1},two[16]={2};
    d2k_plan *first=plan();CHECK(!d2k_pf_lease_set(&t,&s,100,1000,one,first),"install");
    CHECK(d2k_pf_lease_find(&t,&s,999)==first,"matching lease");
    d2k_pf_scope unknown = s;
    unknown.name[0] = 0;
    CHECK(!d2k_pf_lease_match(&t,&unknown,999),"a missing name cannot select a lease");
    unknown = s;
    unknown.shape = D2K_PLAN_SHAPE_LEGACY;
    CHECK(!d2k_pf_lease_match(&t,&unknown,999),"a different TLS shape cannot select a lease");
    CHECK(d2k_pf_lease_match(&t,&s,999) != NULL,"observed exact context selects lease");

    d2k_pf_scope other=s;
    other.client[3]++;CHECK(!d2k_pf_lease_find(&t,&other,999),"other client");
    other=s;other.server[3]++;CHECK(!d2k_pf_lease_find(&t,&other,999),"other server");
    other=s;other.server_port=htons(8443);CHECK(!d2k_pf_lease_find(&t,&other,999),"other port");
    other=s;other.shape=D2K_PLAN_SHAPE_LEGACY;CHECK(!d2k_pf_lease_find(&t,&other,999),"other shape");
    other=s;other.path=8;CHECK(!d2k_pf_lease_find(&t,&other,999),"other path");
    other=s;strcpy(other.name,"other.example");CHECK(!d2k_pf_lease_find(&t,&other,999),"other name");
    other=s;other.family=6;CHECK(!d2k_pf_lease_find(&t,&other,999),"other family");
    CHECK(d2k_pf_lease_find(&t,&s,999)==first,"mismatches kept the live lease");
    CHECK(d2k_pf_lease_find(&t,&s,1000)==NULL,"expiry is exact");
    CHECK(!d2k_pf_lease_find(&t,&s,100),"expired lease stays deleted");
    d2k_plan *second=plan();CHECK(!d2k_pf_lease_set(&t,&s,900,2000,two,second),"renew");
    CHECK(d2k_pf_lease_find(&t,&s,1999)==second,"renewed plan");
    CHECK(!d2k_pf_lease_del(&t,&s,one),"old ID cannot delete renewal");
    CHECK(d2k_pf_lease_find(&t,&s,1999)==second,"wrong deletion preserved");
    const d2k_binding_context *binding=d2k_pf_lease_binding(&t,second);
    CHECK(binding&&binding->family==4&&binding->shape==D2K_PLAN_SHAPE_MODERN&&binding->temporary,"lease binding identity");
    CHECK(d2k_pf_lease_del(&t,&s,two)==1,"owner delete");
    CHECK(!d2k_pf_lease_find(&t,&s,1999),"deleted lease");
    d2k_pf_scope other_client=s;other_client.client[3]++;
    CHECK(!d2k_pf_lease_set(&t,&s,100,2000,one,plan()),"first association");
    CHECK(!d2k_pf_lease_set(&t,&other_client,100,2000,two,plan()),"second client");
    d2k_pf_scope full=s;full.client[3]+=2;
    CHECK(d2k_pf_lease_set(&t,&full,100,2000,one,plan())==-1,"full table must not evict knowledge");
    d2k_pf_lease_invalidate(&t,&s);d2k_pf_lease_invalidate(&t,&other_client);
    CHECK(!d2k_pf_lease_find(&t,&s,1000)&&!d2k_pf_lease_find(&t,&other_client,1000),"association invalidation");
    CHECK(!d2k_pf_lease_set(&t,&s,2100,2300,one,plan()),"first lease expires first");
    CHECK(!d2k_pf_lease_set(&t,&other_client,2100,2500,two,plan()),"second lease stays active");
    CHECK(!d2k_pf_lease_set(&t,&full,2300,2700,one,plan()),"expired capacity is reusable at deadline");
    CHECK(d2k_pf_lease_find(&t,&other_client,2300)!=NULL,"reclaim kept unrelated live lease");
    d2k_pf_lease_free(&t);
    if(fails)return 1;puts("preflight lease table: all checks passed");return 0;
}
