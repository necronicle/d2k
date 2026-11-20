#include "learner.h"
#include <assert.h>
#include <stdio.h>
static int first_response(void *ctx,size_t state,size_t op,size_t *next) {
    (void)ctx;
    if(!state && !op){*next=1;return 1;}
    if(state==1 && op==1){*next=1;return 1;}
    return 0;
}
int main(void) {
    const char ctx[]="reset/alphabet/decoder-v1";
    d2k_learner *l=d2k_learner_new(ctx,sizeof ctx,2);assert(l);
    d2k_sample ab[]={{0,0,1},{1,0,1}},bb[]={{1,0,1},{1,1,1}};
    assert(d2k_learner_seed(l,ctx,sizeof ctx,ab,2)==D2K_L_OBSERVED);
    assert(d2k_learner_seed(l,ctx,sizeof ctx,bb,2)==D2K_L_OBSERVED);
    size_t recorded_word[]={0,1},unrecorded_word[]={0,0};d2k_sample recorded[2];
    assert(d2k_learner_trace(l,recorded_word,2,recorded)==1);
    assert(recorded[0].operation==0 && recorded[1].observation==0 && recorded[1].conclusive==1);
    assert(d2k_learner_trace(l,unrecorded_word,2,recorded)==0);
    d2k_learning_question q,again;
    assert(d2k_learner_next(l,&q)==D2K_L_QUESTION);
    assert(q.length==2 && q.operations[0]==0 && q.operations[1]==0 && q.predicted && !q.observation);
    assert(d2k_learner_next(l,&again)==D2K_L_QUESTION && again.generation==q.generation);
    d2k_sample aa[]={{0,0,1},{0,1,1}};
    assert(d2k_learner_submit(l,q.generation+1,ctx,sizeof ctx,aa,2)==D2K_L_STALE);
    assert(d2k_learner_submit(l,q.generation,"other",6,aa,2)==D2K_L_CONTEXT);
    assert(d2k_learner_submit(l,q.generation,ctx,sizeof ctx,ab,2)==D2K_L_ERROR);
    uint64_t previous=q.generation;
    assert(d2k_learner_submit(l,q.generation,ctx,sizeof ctx,aa,2)==D2K_L_OBSERVED);
    assert(d2k_learner_submit(l,previous,ctx,sizeof ctx,aa,2)==D2K_L_STALE);
    assert(d2k_learner_next(l,&q)==D2K_L_QUESTION && q.generation>previous);
    assert(!(q.length==2 && q.operations[0]==0 && q.operations[1]==0));
    assert(d2k_learner_submit(l,q.generation,ctx,sizeof ctx,NULL,0)==D2K_L_INCONCLUSIVE);
    assert(d2k_learner_next(l,&q)==D2K_L_INCONCLUSIVE);
    aa[1].observation=0;
    assert(d2k_learner_seed(l,ctx,sizeof ctx,aa,2)==D2K_L_CONFLICT);
    assert(d2k_learner_next(l,&q)==D2K_L_CONFLICT);
    d2k_learner_free(l);
    l=d2k_learner_new(ctx,sizeof ctx,1);assert(l);
    assert(d2k_learner_next(l,&q)==D2K_L_QUESTION && q.length==1 && !q.predicted);
    d2k_sample terminal={q.operations[0],42,D2K_SAMPLE_TERMINAL};
    assert(d2k_learner_submit(l,q.generation,ctx,sizeof ctx,&terminal,1)==D2K_L_OBSERVED);
    assert(d2k_learner_next(l,&q)==D2K_L_CLOSED);
    d2k_learner_free(l);
    d2k_input_domain domain={NULL,2,0,2,first_response};
    l=d2k_learner_new_in(ctx,sizeof ctx,2,&domain);assert(l);
    d2k_sample send={0,0,1},bad={1,0,1};
    assert(d2k_learner_seed(l,ctx,sizeof ctx,&bad,1)==D2K_L_ERROR);
    assert(d2k_learner_seed(l,ctx,sizeof ctx,&send,1)==D2K_L_OBSERVED);
    assert(d2k_learner_next(l,&q)==D2K_L_QUESTION);
    assert(q.length==2 && q.operations[0]==0 && q.operations[1]==1);
    d2k_sample reply[]={{0,0,1},{1,42,D2K_SAMPLE_TERMINAL}};
    assert(d2k_learner_submit(l,q.generation,ctx,sizeof ctx,reply,2)==D2K_L_OBSERVED);
    assert(d2k_learner_next(l,&q)==D2K_L_CLOSED);
    d2k_learner_free(l);
    l=d2k_learner_new(ctx,sizeof ctx,2);assert(l);
    ab[1].observation=0;
    assert(d2k_learner_seed(l,ctx,sizeof ctx,ab,2)==D2K_L_OBSERVED);
    assert(d2k_learner_seed(l,ctx,sizeof ctx,bb,2)==D2K_L_OBSERVED);
    size_t chosen[]={1,0},other[]={0,0},invalid[]={2};
    assert(d2k_learner_request(l,invalid,1)==D2K_L_ERROR);
    assert(d2k_learner_request(l,chosen,2)==D2K_L_QUESTION);
    chosen[0]=0; /* Request owns the exact word. */
    assert(d2k_learner_request(l,other,2)==D2K_L_STALE);
    assert(d2k_learner_next(l,&q)==D2K_L_QUESTION);
    assert(q.length==2 && q.operations[0]==1 && q.operations[1]==0);
    d2k_sample ba[]={{1,0,1},{0,7,D2K_SAMPLE_TERMINAL}};
    assert(d2k_learner_submit(l,q.generation,ctx,sizeof ctx,ba,2)==D2K_L_OBSERVED);
    size_t known[]={1,0},past_terminal[]={1,0,1};
    assert(d2k_learner_request(l,known,2)==D2K_L_CLOSED);
    assert(d2k_learner_request(l,past_terminal,3)==D2K_L_ERROR);
    d2k_learner_free(l);
    l=d2k_learner_new_in(ctx,sizeof ctx,2,&domain);assert(l);
    size_t outside[]={1},inside[]={0,1};
    assert(d2k_learner_request(l,outside,1)==D2K_L_ERROR);
    assert(d2k_learner_request(l,inside,2)==D2K_L_QUESTION);
    assert(d2k_learner_next(l,&q)==D2K_L_QUESTION && q.length==2);
    assert(d2k_learner_submit(l,q.generation,ctx,sizeof ctx,NULL,0)==D2K_L_INCONCLUSIVE);
    assert(d2k_learner_request(l,inside,2)==D2K_L_INCONCLUSIVE);
    d2k_learner_free(l);
    puts("learner: generated query, counterexample, stale/context gates, inconclusive stop and terminal closure PASS");
}
