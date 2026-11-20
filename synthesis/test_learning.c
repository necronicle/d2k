#include "evidence.h"
#include <assert.h>
#include <stdio.h>
static void replay(d2k_transducer m,const d2k_sample *s,size_t n) {
    size_t state=m.initial;
    for(size_t i=0;i<n;i++) {
        d2k_transition t;
        assert(m.step(m.ctx,state,s[i].operation,&t)==1);
        assert(t.observation==s[i].observation);state=t.next;
    }
}
int main(void) {
    const char ctx[]="reset-context-1";
    d2k_evidence *e=d2k_evidence_new(ctx,sizeof ctx,2);assert(e);
    d2k_sample ab[]={{0,0,1},{1,0,1}},bb[]={{1,0,1},{1,1,1}};
    assert(d2k_evidence_add(e,ctx,sizeof ctx,ab,2)==D2K_EVIDENCE_OK);
    assert(d2k_evidence_add(e,ctx,sizeof ctx,bb,2)==D2K_EVIDENCE_OK);
    d2k_hypothesis *h=NULL;
    /* Prefix a and prefix b disagree on suffix b. */
    assert(d2k_evidence_merge(e,1,3,&h)==0 && !h);
    /* Root and prefix a are currently compatible; closing equal successors
       yields a loop and predicts unobserved aa -> 0,0. */
    assert(d2k_evidence_merge(e,0,1,&h)==1 && h);
    d2k_hypothesis_free(h); h=NULL;
    assert(d2k_evidence_generalize(e,&h)==1 && h);
    d2k_transducer m=d2k_hypothesis_model(h);

    replay(m,ab,2);replay(m,bb,2);
    d2k_sample aa[]={{0,0,1},{0,0,1}};replay(m,aa,2);
    d2k_transducer measured=d2k_evidence_model(e);
    d2k_distinction question=d2k_distinguish(&measured,&m);
    assert(question.status==D2K_DIST_INCOMPLETE && question.length==2);
    assert(question.known_outputs==2 && question.right_observation==0);
    assert(question.operations[0]==0 && question.operations[1]==0);
    /* Execute the generated word; this fixture supplies a counterexample. */
    for(size_t i=0;i<question.length;i++) aa[i].operation=question.operations[i];
    d2k_distinction_free(&question);
    /* A new experiment refutes precisely this merge, not the whole alphabet. */

    aa[1].observation=1;
    assert(d2k_evidence_add(e,ctx,sizeof ctx,aa,2)==D2K_EVIDENCE_OK);
    measured=d2k_evidence_model(e);
    question=d2k_distinguish(&measured,&m);
    assert(question.status==D2K_DIST_WITNESS && question.length==2);
    assert(question.known_outputs==3 && question.left_observation==1 &&
           question.right_observation==0);
    d2k_distinction_free(&question);
    d2k_hypothesis *revised=NULL;

    assert(d2k_evidence_merge(e,0,1,&revised)==0 && !revised);
    assert(d2k_evidence_generalize(e,&revised)==1);
    replay(d2k_hypothesis_model(revised),aa,2);
    replay(d2k_hypothesis_model(revised),ab,2);
    replay(d2k_hypothesis_model(revised),bb,2);
    /* Published hypotheses are immutable snapshots. */
    aa[1].observation=0;replay(m,aa,2);
    assert(d2k_evidence_add(e,ctx,sizeof ctx,aa,2)==D2K_EVIDENCE_CONFLICT);
    d2k_hypothesis *conflicted=NULL;
    assert(d2k_evidence_generalize(e,&conflicted)==0 && !conflicted);
    d2k_hypothesis_free(h);d2k_hypothesis_free(revised);d2k_evidence_free(e);
    e=d2k_evidence_new(ctx,sizeof ctx,2);assert(e);
    assert(d2k_evidence_generalize(e,&h)==1);
    m=d2k_hypothesis_model(h);
    d2k_transition t;
    assert(m.states==1 && m.step(m.ctx,m.initial,0,&t)==0);
    d2k_hypothesis_free(h);d2k_evidence_free(e);

    e=d2k_evidence_new(ctx,sizeof ctx,1);assert(e);
    d2k_sample loop[]={{0,7,1},{0,7,1},{0,7,1}};
    assert(d2k_evidence_add(e,ctx,sizeof ctx,loop,3)==D2K_EVIDENCE_OK);
    assert(d2k_evidence_merge(e,0,1,&h)==1);
    m=d2k_hypothesis_model(h);
    assert(m.states==1 && m.initial==0);
    assert(m.step(m.ctx,0,0,&t)==1 && t.next==0 && t.observation==7);
    replay(m,loop,3);
    d2k_hypothesis_free(h);d2k_evidence_free(e);

    puts("learned merge: trace consistency, inferred loop and counterexample refinement pass");
}
