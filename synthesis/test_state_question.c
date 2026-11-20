#include "state_question.h"
#include <assert.h>
#include <stdio.h>
static int step(void *ctx,size_t s,size_t op,d2k_transition *t)
{
    int mode=*(int *)ctx;
    if(mode==2 && op==1 && s==1) return 0;
    t->next=op ? 1-s:s;
    t->observation=op ? 10+(mode==1?0:s):0;
    return mode==3?2:1;
}
static int control_only(void *ctx,size_t s,size_t op,size_t *next)
{ (void)ctx; (void)s; *next=0; return op==0; }
static int delayed(void *ctx,size_t s,size_t op,d2k_transition *t)
{
    (void)ctx; t->next=s; t->observation=0;
    if(op==2) t->observation=s<2?7:8;
    else if(op==0) t->next=s<2?s+2:s;
    else if(s>=2) t->observation=s;
    return 1;
}
static void multistep(void)
{
    d2k_transducer m={NULL,4,0,3,delayed};
    d2k_sample history[3]={{2,7,1},{0,0,1},{1,3,1}};
    d2k_state_question q=d2k_question_after(&m,history,1,NULL);
    assert(q.status==D2K_QUESTION_DISTINGUISH && q.word.length==2);
    assert(q.word.operations[0]==0 && q.word.operations[1]==1);
    d2k_state_question_free(&q);
    q=d2k_question_after(&m,history,2,NULL);
    assert(q.status==D2K_QUESTION_DISTINGUISH && q.word.length==1);
    assert(q.word.operations[0]==1);
    d2k_state_question_free(&q);
    q=d2k_question_after(&m,history,3,NULL);
    assert(q.status==D2K_QUESTION_LOCATED);
    d2k_state_question_free(&q);
}
int main(void)
{
    int mode=0;
    d2k_transducer m={&mode,2,0,2,step};
    d2k_sample trace[]={{0,0,1},{1,11,1}};
    d2k_state_question q=d2k_question_after(&m,trace,1,NULL);
    assert(q.status==D2K_QUESTION_DISTINGUISH && q.possible==2);
    assert(q.word.length==1 && q.word.operations[0]==1);
    assert(q.left==0 && q.right==1 && q.word.known_outputs==3);
    d2k_state_question_free(&q);
    q=d2k_question_after(&m,trace,2,NULL);
    assert(q.status==D2K_QUESTION_LOCATED && q.possible==1 && !q.word.length);
    d2k_state_question_free(&q);
    { d2k_input_domain d={NULL,1,0,2,control_only};
      q=d2k_question_after(&m,trace,1,&d);
      assert(q.status==D2K_QUESTION_INDISTINGUISHABLE && q.possible==2);
      d2k_state_question_free(&q); }
    mode=1;
    q=d2k_question_after(&m,trace,1,NULL);
    assert(q.status==D2K_QUESTION_INDISTINGUISHABLE);
    d2k_state_question_free(&q);
    q=d2k_question_after(&m,trace,2,NULL);
    assert(q.status==D2K_QUESTION_CONTRADICTION && q.prefix==2);
    d2k_state_question_free(&q);
    mode=2;
    unsigned char initial[]={1,0};
    q=d2k_question_after_from(&m,initial,trace,1,NULL);
    assert(q.status==D2K_QUESTION_LOCATED && q.possible==1 && !q.word.length);
    d2k_state_question_free(&q);
    initial[0]=0;
    q=d2k_question_after_from(&m,initial,trace,1,NULL);
    assert(q.status==D2K_QUESTION_ERROR);d2k_state_question_free(&q);
    initial[1]=1;
    q=d2k_question_after_from(&m,initial,trace,2,NULL);
    assert(q.status==D2K_QUESTION_UNKNOWN);d2k_state_question_free(&q);
    q=d2k_question_after(&m,trace,1,NULL);
    assert(q.status==D2K_QUESTION_EXPLORE && q.word.known_outputs==1);
    d2k_state_question_free(&q);
    q=d2k_question_after(&m,trace,2,NULL);
    assert(q.status==D2K_QUESTION_UNKNOWN && !q.word.length);
    d2k_state_question_free(&q);
    mode=3; trace[0].conclusive=2;
    q=d2k_question_after(&m,trace,1,NULL);
    assert(q.status==D2K_QUESTION_TERMINAL && !q.word.length);
    d2k_state_question_free(&q);
    multistep();
    puts("state question: history, distinction, domain, uncertainty and terminal pass");
    return 0;
}
