#include "evidence.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    const char context[]="endpoint:443/tls/epoch7/reset1/schema1";
    d2k_evidence *a=d2k_evidence_new(context,sizeof(context),3);
    d2k_evidence *b=d2k_evidence_new(context,sizeof(context),3);
    assert(a && b);
    d2k_sample trace[]={{2,10,1},{0,20,1},{1,30,1}};
    assert(d2k_evidence_add(a,context,sizeof(context),trace,3)==D2K_EVIDENCE_OK);
    trace[2].observation=31;
    assert(d2k_evidence_add(b,context,sizeof(context),trace,3)==D2K_EVIDENCE_OK);
    d2k_transducer am=d2k_evidence_model(a),bm=d2k_evidence_model(b);
    d2k_distinction d=d2k_distinguish(&am,&bm);
    assert(d.status==D2K_DIST_WITNESS && d.length==3 && d.operations[0]==2 &&
           d.operations[1]==0 && d.operations[2]==1);
    d2k_distinction_free(&d);
    assert(d2k_evidence_add(a,context,sizeof(context),trace,3)==D2K_EVIDENCE_CONFLICT);
    am=d2k_evidence_model(a);
    d=d2k_distinguish(&am,&bm);assert(d.status==D2K_DIST_INCOMPLETE);d2k_distinction_free(&d);
    size_t old=am.states;
    assert(d2k_evidence_add(a,"other",6,trace,3)==D2K_EVIDENCE_CONTEXT);
    trace[0].operation=0;trace[0].conclusive=0;
    assert(d2k_evidence_add(a,context,sizeof(context),trace,3)==D2K_EVIDENCE_OK);
    am=d2k_evidence_model(a);assert(am.states==old);
    trace[0].conclusive=1;trace[2].operation=99;
    assert(d2k_evidence_add(a,context,sizeof(context),trace,3)==D2K_EVIDENCE_ERROR);
    am=d2k_evidence_model(a);assert(am.states==old);
    d2k_evidence_free(a);d2k_evidence_free(b);
    puts("evidence -> model -> distinguishing experiment: pass");
}
