#include "evidence.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    const char ctx[]="terminal schema v1";
    d2k_evidence *a=d2k_evidence_new(ctx,sizeof ctx,1);
    d2k_evidence *b=d2k_evidence_new(ctx,sizeof ctx,1);assert(a && b);
    d2k_sample end={0,42,D2K_SAMPLE_TERMINAL},more={0,42,D2K_SAMPLE_OBSERVED};
    assert(d2k_evidence_add(a,ctx,sizeof ctx,&end,1)==D2K_EVIDENCE_OK);
    assert(d2k_evidence_add(b,ctx,sizeof ctx,&more,1)==D2K_EVIDENCE_OK);
    d2k_transducer am=d2k_evidence_model(a),bm=d2k_evidence_model(b);
    d2k_transition t;
    assert(am.step(am.ctx,0,0,&t)==2 && t.observation==42);
    d2k_distinction d=d2k_distinguish(&am,&am);
    assert(d.status==D2K_DIST_EQUIVALENT);d2k_distinction_free(&d);
    d=d2k_distinguish(&am,&bm);
    assert(d.status==D2K_DIST_WITNESS && d.length==1 && d.terminal_outputs==1);
    d2k_distinction_free(&d);
    d2k_hypothesis *h=NULL;
    assert(d2k_evidence_merge(a,0,1,&h)==0 && !h);
    assert(d2k_evidence_generalize(a,&h)==1);
    d2k_transducer hm=d2k_hypothesis_model(h);
    assert(hm.step(hm.ctx,hm.initial,0,&t)==2);
    d2k_hypothesis_free(h);
    d2k_sample invalid[]={end,more};
    assert(d2k_evidence_add(a,ctx,sizeof ctx,invalid,2)==D2K_EVIDENCE_ERROR);
    assert(d2k_evidence_add(a,ctx,sizeof ctx,&more,1)==D2K_EVIDENCE_CONFLICT);
    h=NULL;assert(d2k_evidence_generalize(a,&h)==0 && !h);
    d2k_evidence_free(a);d2k_evidence_free(b);
    puts("terminal evidence: no continuation, no unsafe merge, termination witness and conflict PASS");
}
