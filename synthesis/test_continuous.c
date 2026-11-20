#include "continuous.h"
#include <assert.h>
#include <stdio.h>
static void check_trace(d2k_hypothesis *h,const d2k_sample *trace,size_t n)
{
    d2k_transducer m=d2k_hypothesis_model(h);
    size_t state=m.initial,i;
    for(i=0;i<n;i++) {
        d2k_transition t;
        assert(m.step(m.ctx,state,trace[i].operation,&t)==1);
        assert(t.observation==trace[i].observation);
        state=t.next;
    }
}
static int frontier_step(void *ctx,size_t state,size_t op,d2k_transition *t)
{
    int mode=*(int *)ctx;
    if(mode==3) return -1;
    if(state==1 && op==1 && mode!=1) return 0;
    t->observation=0; t->next=op==0?1:state;
    return mode==2?2:1;
}
static int only_zero(void *ctx,size_t state,size_t op,size_t *next)
{ (void)ctx; (void)state; *next=0; return op==0; }
static void frontier(void)
{
    int mode=0;
    d2k_transducer m={&mode,2,0,2,frontier_step};
    d2k_distinction q=d2k_continuous_question(&m,NULL);
    assert(q.status==D2K_DIST_INCOMPLETE && q.length==2);
    assert(q.operations[0]==0 && q.operations[1]==1);
    d2k_distinction_free(&q);
    d2k_input_domain domain={NULL,1,0,2,only_zero};
    q=d2k_continuous_question(&m,&domain);
    assert(q.status==D2K_DIST_EQUIVALENT && !q.length);
    d2k_distinction_free(&q);
    mode=1;
    q=d2k_continuous_question(&m,NULL);
    assert(q.status==D2K_DIST_EQUIVALENT && !q.length);
    d2k_distinction_free(&q);
    mode=2;
    q=d2k_continuous_question(&m,NULL);
    assert(q.status==D2K_DIST_EQUIVALENT && !q.length);
    d2k_distinction_free(&q);
    mode=3;
    q=d2k_continuous_question(&m,NULL);
    assert(q.status==D2K_DIST_ERROR);
    d2k_distinction_free(&q);
}
int main(void)
{
    d2k_sample trace[]={{0,0,1},{0,0,1},{0,1,1}};
    d2k_hypothesis *h=NULL,*revised=NULL;
    d2k_transducer current,changed;
    assert(d2k_continuous_build(trace,2,2,&h,&current)==1);
    check_trace(h,trace,2);
    d2k_transition prediction;
    assert(current.step(current.ctx,current.initial,0,&prediction)==1);
    assert(prediction.observation==0);
    d2k_distinction q=d2k_continuous_question(&current,NULL);
    assert(q.status==D2K_DIST_INCOMPLETE && q.length==1);
    assert(q.operations[0]==1 && q.known_outputs==0);
    d2k_distinction_free(&q);
    assert(d2k_continuous_build(trace,3,2,&revised,&changed)==1);
    check_trace(revised,trace,3);
    assert(current.step(current.ctx,current.initial,0,&prediction)==1 && prediction.observation==0);
    d2k_hypothesis_free(revised);revised=NULL;
    trace[1].conclusive=0;
    assert(d2k_continuous_build(trace,3,2,&revised,&changed)==0 && !revised);
    trace[1].conclusive=2;
    assert(d2k_continuous_build(trace,3,2,&revised,&changed)==-1 && !revised);
    d2k_hypothesis_free(h);
    assert(d2k_continuous_build(NULL,0,2,&h,&current)==1);
    q=d2k_continuous_question(&current,NULL);
    assert(q.status==D2K_DIST_INCOMPLETE && q.known_outputs==0);
    d2k_distinction_free(&q);d2k_hypothesis_free(h);
    frontier();
    puts("continuous: history, counterexample, uncertainty and cycle-safe frontier pass");
    return 0;
}
