#include "continuous.h"
#include "alternatives.h"
#include "state_question.h"
#include "joint.h"
#include <assert.h>
#include <stdio.h>
typedef struct {unsigned calls,after;} counter;
static int stop(void *ctx){counter *c=ctx;return ++c->calls>=c->after;}
static int step(void *ctx,size_t state,size_t op,d2k_transition *out){
    (void)ctx;(void)op;out->next=(state+1)%100;out->observation=1;return 1;
}
static int four_states(void *ctx,size_t state,size_t op,d2k_transition *out){
    (void)ctx;(void)op;out->next=(state+1)%4;out->observation=state;return 1;
}
static int advance_input(void *ctx,size_t state,size_t op,size_t *next){
    (void)ctx;(void)op;*next=(state+1)%8;return 1;
}
static int never_accept(void *ctx,uint64_t value){(void)ctx;(void)value;return 0;}
static int input_preserved(void *ctx,size_t state){(void)ctx;(void)state;return 1;}
static void singleton_cost(void){
    d2k_transducer m={NULL,4,0,1,four_states};
    unsigned char initial[]={0,0,1,0};
    d2k_synthesis_contract contract={{NULL,8,0,1,advance_input},input_preserved,NULL,never_accept};
    counter c={0,~0u};d2k_inference_control control={stop,&c};
    d2k_syn_result r=d2k_joint_search_belief_feedback_controlled(&m,initial,&contract,NULL,NULL,&control);
    assert(r.status==D2K_SYN_CLOSED);
    unsigned belief_calls=c.calls;d2k_syn_result_free(&r);
    m.initial=2;c=(counter){0,~0u};
    r=d2k_joint_search_feedback_controlled(&m,&contract,NULL,NULL,&control);
    assert(r.status==D2K_SYN_CLOSED);
    /* One known state must not incur the scan of every subset bitmap for
       each edge. Allow the initial bitmap scan in addition to graph work. */
    assert(belief_calls<=c.calls+m.states+2);
    d2k_syn_result_free(&r);
}
static void joint_cancellation(void){
    d2k_transducer m={NULL,4,0,1,four_states};
    unsigned char initial[]={1,1,0,0};
    d2k_synthesis_contract contract={{NULL,8,0,1,advance_input},input_preserved,NULL,never_accept};
    for(int belief=0;belief<2;belief++){
        counter c={0,~0u};d2k_inference_control control={stop,&c};
        d2k_syn_result r=belief?
            d2k_joint_search_belief_feedback_controlled(&m,initial,&contract,NULL,NULL,&control):
            d2k_joint_search_feedback_controlled(&m,&contract,NULL,NULL,&control);
        assert(r.status==D2K_SYN_CLOSED && !r.operations);
        unsigned calls=c.calls;assert(calls>1);d2k_syn_result_free(&r);
        for(unsigned n=1;n<=calls;n++){
            c=(counter){0,n};
            r=belief?d2k_joint_search_belief_feedback_controlled(&m,initial,&contract,NULL,NULL,&control):
                d2k_joint_search_feedback_controlled(&m,&contract,NULL,NULL,&control);
            assert(r.status==D2K_SYN_ERROR && !r.operations && !r.length && c.calls==n);
            d2k_syn_result_free(&r);
        }
    }
}
static void relocation_cancellation(void){
    d2k_transducer m={NULL,4,0,1,four_states};
    counter c={0,~0u};d2k_inference_control control={stop,&c};
    d2k_state_question q=d2k_question_after_from_controlled(&m,NULL,NULL,0,NULL,&control);
    assert(q.status==D2K_QUESTION_DISTINGUISH && q.word.length==1);
    unsigned calls=c.calls;d2k_state_question_free(&q);
    for(unsigned n=1;n<=calls;n++){
        c=(counter){0,n};
        q=d2k_question_after_from_controlled(&m,NULL,NULL,0,NULL,&control);
        assert(q.status==D2K_QUESTION_ERROR && !q.word.operations && c.calls==n);
        d2k_state_question_free(&q);
    }
    d2k_sample trace[]={{0,0,D2K_SAMPLE_OBSERVED},{0,1,D2K_SAMPLE_OBSERVED},{0,2,D2K_SAMPLE_OBSERVED}};
    c=(counter){0,~0u};
    d2k_tracking t=d2k_track_from_controlled(&m,NULL,trace,3,&control);
    assert(t.status==D2K_TRACK_MATCH && t.possible==1 && t.states[3]);
    calls=c.calls;d2k_tracking_free(&t);
    for(unsigned n=1;n<=calls;n++){
        c=(counter){0,n};t=d2k_track_from_controlled(&m,NULL,trace,3,&control);
        assert(t.status==D2K_TRACK_ERROR && !t.states && !t.possible && c.calls==n);
        d2k_tracking_free(&t);
    }
    t=d2k_track_from(&m,NULL,trace,3);
    assert(t.status==D2K_TRACK_MATCH && t.possible==1 && t.states[3]);d2k_tracking_free(&t);
}
int main(void){
    singleton_cost();
    joint_cancellation();
    relocation_cancellation();
    const char context[]="cancel-test";
    d2k_evidence *e=d2k_evidence_new(context,sizeof context,2);assert(e);
    d2k_sample trace[24];for(size_t i=0;i<24;i++)trace[i]=(d2k_sample){i%2,i%3,D2K_SAMPLE_OBSERVED};
    assert(d2k_evidence_add(e,context,sizeof context,trace,24)==D2K_EVIDENCE_OK);
    for(unsigned n=1;n<=40;n++){
        counter c={0,n};d2k_inference_control control={stop,&c};d2k_hypothesis *h=NULL;
        assert(d2k_evidence_generalize_controlled(e,&h,&control)==-1 && !h && c.calls==n);
    }
    d2k_hypothesis *h=NULL;assert(d2k_evidence_generalize(e,&h)==1 && h);d2k_hypothesis_free(h);
    counter c={0,5};d2k_inference_control control={stop,&c};
    assert(d2k_evidence_merge_controlled(e,0,2,&h,&control)==-1 && !h);
    d2k_evidence_free(e);
    c=(counter){0,20};d2k_transducer current={0};
    assert(d2k_continuous_build_controlled(trace,24,2,&h,&current,&control)==-1 && !h && !current.states);
    assert(d2k_continuous_build(trace,24,2,&h,&current)==1);d2k_hypothesis_free(h);
    c=(counter){0,20};d2k_alternatives a=d2k_continuous_alternatives_controlled(trace,24,2,NULL,&control);
    assert(a.status==D2K_ALTERNATIVES_ERROR && !a.word.operations && !a.prefix_observations);d2k_alternatives_free(&a);
    d2k_transducer large={NULL,SIZE_MAX/2,0,1,step};
    d2k_distinction sparse=d2k_distinguish(&large,&large);
    assert(sparse.status==D2K_DIST_EQUIVALENT && !sparse.operations);
    d2k_distinction_free(&sparse);
    c=(counter){0,20};d2k_transducer m={NULL,100,0,1,step};
    d2k_distinction d=d2k_distinguish_in_controlled(&m,&m,NULL,&control);
    assert(d.status==D2K_DIST_ERROR && !d.operations && c.calls==20);d2k_distinction_free(&d);
    for(unsigned n=1;n<=201;n++) {
        c=(counter){0,n};
        d=d2k_continuous_question_controlled(&m,NULL,&control);
        assert(d.status==D2K_DIST_ERROR && !d.operations && c.calls==n);
        d2k_distinction_free(&d);
    }
    d=d2k_continuous_question(&m,NULL);
    assert(d.status==D2K_DIST_EQUIVALENT && !d.operations);
    d2k_distinction_free(&d);
    puts("inference cancellation releases partial models and preserves evidence");return 0;
}
