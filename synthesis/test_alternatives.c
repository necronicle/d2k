#include "alternatives.h"
#include <assert.h>
#include <stdio.h>
static int only_one(void *ctx,size_t state,size_t op,size_t *next)
{ (void)ctx; (void)state; *next=0; return op==1; }
static int two_step(void *ctx,size_t state,size_t op,size_t *next)
{
    (void)ctx;
    if(state==0 && op==0) { *next=1; return 1; }
    if(state==1 && op==1) { *next=1; return 1; }
    return 0;
}
int main(void)
{
    d2k_sample trace[]={{0,0,1},{0,1,1},{1,0,1},{0,0,1}};
    d2k_alternatives q=d2k_continuous_alternatives(trace,3,2,NULL);
    assert(q.status==D2K_ALTERNATIVES_QUESTION);
    assert(q.word.status==D2K_DIST_WITNESS && q.word.length==1);
    assert(q.word.operations[0]==0 && q.word.known_outputs==3);
    assert(q.word.left_observation!=q.word.right_observation);
    /* Both candidates explain the same history; answer 0 refutes the one
       predicting 1. That merge must be rejected on extended evidence. */
    const char ctx[]="one chronological origin";
    d2k_evidence *e=d2k_evidence_new(ctx,sizeof ctx,2);
    assert(e && d2k_evidence_add(e,ctx,sizeof ctx,trace,4)==D2K_EVIDENCE_OK);
    d2k_hypothesis *bad=NULL;
    size_t anchor=q.word.left_observation==1?q.left_anchor:q.right_anchor;
    assert(d2k_evidence_merge(e,3,anchor,&bad)==0 && !bad);
    d2k_evidence_free(e);
    d2k_alternatives_free(&q);
    d2k_input_domain domain={NULL,1,0,2,only_one};
    q=d2k_continuous_alternatives(trace,3,2,&domain);
    assert(q.status==D2K_ALTERNATIVES_NONE && !q.word.length);
    d2k_alternatives_free(&q);
    trace[1].conclusive=0;
    q=d2k_continuous_alternatives(trace,3,2,NULL);
    assert(q.status==D2K_ALTERNATIVES_UNKNOWN && !q.word.length);
    d2k_alternatives_free(&q);
    q=d2k_continuous_alternatives(NULL,0,2,NULL);
    assert(q.status==D2K_ALTERNATIVES_NONE);
    d2k_alternatives_free(&q);
    d2k_sample longer[]={{0,0,1},{1,0,1},{0,0,1},{1,1,1},{2,0,1}};
    d2k_input_domain two={NULL,2,0,3,two_step};
    q=d2k_continuous_alternatives(longer,5,3,&two);
    assert(q.status==D2K_ALTERNATIVES_QUESTION && q.word.length==2);
    assert(q.word.operations[0]==0 && q.word.operations[1]==1);
    assert(q.prefix_observations && q.prefix_observations[0]==0);
    d2k_alternatives_free(&q);
    puts("alternatives: shared history, differing prediction, merge refutation and uncertainty pass");
    return 0;
}
