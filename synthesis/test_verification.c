#include "verification.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    d2k_synthesis_feedback e={0};
    e.generation=7;e.search_id=11;e.target="dns.example";e.ip="192.0.2.7";
    e.program="exact program";e.resource="/dns-query";e.doh=1;
    e.port=443;e.family=4;e.transport=6;e.shape=2;
    e.plan_id[0]=3;e.trial_id[0]=4;
    e.flow.family=4;e.flow.transport=6;e.flow.a_port=50000;e.flow.b_port=443;
    e.flow.b_ip[0]=192;e.flow.b_ip[2]=2;e.flow.b_ip[3]=7;
    e.applied=e.verification_available=e.body_complete=1;
    e.level=D2K_VER_APPLICATION;e.status=200;e.budget=D2K_BUDGET_PASSED;
    e.budget_need=50;e.budget_packets=52;e.budget_requests=11;
    d2k_synthesis_feedback original=e;
    d2k_verification_owner *owner=d2k_verification_new(&e,1);assert(owner);
    e.generation++;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_FOREIGN);e.generation--;
    e.resource="/different";
    assert(d2k_verification_accept(owner,&e)==D2K_VF_FOREIGN);e.resource="/dns-query";
    assert(d2k_verification_accept(owner,&e)==D2K_VF_OBSERVED);
    assert(d2k_verification_accept(owner,&e)==D2K_VF_DUPLICATE);
    e.status=503;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_CONFLICT);
    e.trial_id[0]++;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_CONFLICT);
    d2k_verification_free(owner);
    e=original;owner=d2k_verification_new(&e,1);assert(owner);
    e.budget_need=0;e.budget_packets=0;e.budget_requests=1;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_QUERY_OBSERVED);
    d2k_verification_free(owner);
    for(int mismatch=0;mismatch<8;mismatch++) {
        e=original;owner=d2k_verification_new(&e,1);assert(owner);
        switch(mismatch) {
        case 0:e.search_id++;break;
        case 1:e.target="other.example";break;
        case 2:e.program="different exact program";break;
        case 3:e.shape++;break;
        case 4:e.transport=17;break;
        case 5:e.by_addr=1;break;
        case 6:e.plan_id[0]++;break;
        case 7:e.doh=0;break;
        }
        assert(d2k_verification_accept(owner,&e)==D2K_VF_FOREIGN);
        d2k_verification_free(owner);
    }
    e=original;owner=d2k_verification_new(&e,1);assert(owner);
    e.flow.b_ip[3]++;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_UNKNOWN);
    d2k_verification_free(owner);
    e=original;owner=d2k_verification_new(&e,1);assert(owner);
    e.applied=0;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_UNKNOWN);
    e.trial_id[0]++;e.applied=1;e.budget=D2K_BUDGET_NOT_CHECKED;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_UNKNOWN);
    e.trial_id[0]++;e.budget=D2K_BUDGET_PASSED;e.status=503;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_APP_NOT_MET);
    e.trial_id[0]++;e.status=403;e.budget=D2K_BUDGET_CUT;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_APP_NOT_MET);
    e.trial_id[0]++;e.status=200;e.body_complete=0;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_NOT_MET);
    e.body_complete=1;
    e.trial_id[0]++;e.status=200;e.local_refusal=1;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_UNKNOWN);
    d2k_verification_free(owner);
    for(int missing=0;missing<5;missing++) {
        e=original;owner=d2k_verification_new(&e,1);assert(owner);
        e.budget=D2K_BUDGET_CUT;e.body_complete=0;
        switch(missing) {
        case 0:e.budget_need=0;break;
        case 1:e.budget_packets=0;break;
        case 2:e.budget_requests=0;break;
        case 3:e.status=0;break;
        case 4:e.status=503;break;
        }
        assert(d2k_verification_accept(owner,&e)==D2K_VF_UNKNOWN);
        d2k_verification_free(owner);
    }
    e=original;e.budget=D2K_BUDGET_CUT;e.status=0;e.body_complete=0;
    e.budget_requests=5;e.doh_replies=4;
    owner=d2k_verification_new(&e,1);assert(owner);
    assert(d2k_verification_accept(owner,&e)==D2K_VF_NOT_MET);
    e.doh_replies=3;
    assert(d2k_verification_accept(owner,&e)==D2K_VF_CONFLICT);
    d2k_verification_free(owner);
    for(int invalid=0;invalid<6;invalid++) {
        e=original;e.budget=D2K_BUDGET_CUT;e.status=0;e.body_complete=0;
        e.budget_requests=5;e.doh_replies=4;
        switch(invalid) {
        case 0:e.doh_replies=0;break;
        case 1:e.doh_replies=5;break;
        case 2:e.doh_replies=3;break;
        case 3:e.body_complete=1;break;
        case 4:e.doh=0;break;
        case 5:e.budget_requests=0;break;
        }
        owner=d2k_verification_new(&e,1);assert(owner);
        assert(d2k_verification_accept(owner,&e)!=D2K_VF_NOT_MET);
        d2k_verification_free(owner);
    }
    puts("verification: exact ownership, app budget, uncertainty, duplicate and conflict pass");
    return 0;
}
