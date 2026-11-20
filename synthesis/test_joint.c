#include "joint.h"
#include "evidence.h"
#include "learner.h"
#include "lower.h"
#include "stream.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static int endpoint(void *ctx,size_t state,size_t op,size_t *next) {
    (void)ctx;
    if(state==0 && op==0){*next=1;return 1;}
    if(state==1 && op==1){*next=2;return 1;}
    if(state==0 && op==3){*next=2;return 1;}
    if(op==2){*next=state;return 1;}
    return 0;
}
static int preserved(void *ctx,size_t state){(void)ctx;return state==2;}
static int accepted(void *ctx,uint64_t value){(void)ctx;return value==42;}
static int app_accepted(void *ctx,uint64_t value){(void)ctx;return value==99;}
static void application_goal(void)
{
    /* Controlled deterministic fixture with an explicit common origin. This
       reset assumption is for this unit fixture, not for network connections. */
    const char context[]="unit/application goal/resettable peer";
    d2k_evidence *e=d2k_evidence_new(context,sizeof context,6);assert(e);
    d2k_sample prefix[]={{3,0,1},{1,0,1},{2,42,1}};
    d2k_trigger input={0};input.len=3;memcpy(input.payload,"abc",3);
    size_t chunks[]={1,3};d2k_tls_stream stream={&input,chunks,2,10,1};
    d2k_synthesis_contract contract={d2k_tls_stream_application_domain(&stream),
        d2k_tls_stream_application_preserved,NULL,app_accepted};
    assert(d2k_evidence_add(e,context,sizeof context,prefix,3)==D2K_EVIDENCE_OK);
    d2k_hypothesis *h=NULL;assert(d2k_evidence_generalize(e,&h)==1);
    d2k_transducer model=d2k_hypothesis_model(h);
    d2k_syn_result result=d2k_joint_search(&model,&contract);
    assert(result.status==D2K_SYN_EXPERIMENT); /* ServerHello cannot satisfy it. */
    d2k_syn_result_free(&result);d2k_hypothesis_free(h);
    d2k_sample fail[]={{3,0,1},{1,0,1},{2,42,1},{5,7,2}};
    assert(d2k_evidence_add(e,context,sizeof context,fail,4)==D2K_EVIDENCE_OK);
    assert(d2k_evidence_generalize(e,&h)==1);model=d2k_hypothesis_model(h);
    result=d2k_joint_search(&model,&contract);
    assert(result.status!=D2K_SYN_CANDIDATE && result.status!=D2K_SYN_ERROR);
    d2k_syn_result_free(&result);d2k_hypothesis_free(h);
    d2k_sample pass[]={{3,0,1},{0,0,1},{0,0,1},{0,0,1},{2,42,1},{5,99,2}};
    assert(d2k_evidence_add(e,context,sizeof context,pass,6)==D2K_EVIDENCE_OK);
    assert(d2k_evidence_generalize(e,&h)==1);model=d2k_hypothesis_model(h);
    result=d2k_joint_search(&model,&contract);
    assert(result.status==D2K_SYN_CANDIDATE && result.length==6);
    assert(result.operations[0]==3 && result.operations[1]==0 && result.operations[2]==0 &&
        result.operations[3]==0 && result.operations[4]==2 && result.operations[5]==5);
    d2k_syn_result_free(&result);d2k_hypothesis_free(h);d2k_evidence_free(e);
}
static int broken(void *ctx,uint64_t value){(void)ctx;(void)value;return -1;}
static int feedback_error(void *ctx,size_t op,uint64_t observation,size_t *state)
{ (void)ctx;(void)op;(void)observation;(void)state;return -1; }
static int feedback_reset(void *ctx,size_t op,uint64_t observation,size_t *state)
{ (void)ctx;(void)op;(void)observation;*state=0;return 1; }
int main(void) {
    application_goal();
    const char context[]="reset/model/partition semantics v1";
    d2k_evidence *e=d2k_evidence_new(context,sizeof context,4);assert(e);
    d2k_sample direct[]={{3,0,1},{2,7,2}},partial[]={{0,0,1},{2,42,2}};
    d2k_sample composed[]={{0,0,1},{1,0,1},{2,42,2}};
    assert(d2k_evidence_add(e,context,sizeof context,direct,2)==D2K_EVIDENCE_OK);
    assert(d2k_evidence_add(e,context,sizeof context,partial,2)==D2K_EVIDENCE_OK);
    d2k_synthesis_contract c={{NULL,3,0,4,endpoint},preserved,NULL,accepted};
    d2k_hypothesis *h=NULL;assert(d2k_evidence_generalize(e,&h)==1);
    d2k_transducer m=d2k_hypothesis_model(h);
    d2k_syn_result r=d2k_joint_search(&m,&c);
    assert(r.status==D2K_SYN_EXPERIMENT); /* partial response is not enough */
    d2k_syn_result_free(&r);d2k_hypothesis_free(h);
    assert(d2k_evidence_add(e,context,sizeof context,composed,3)==D2K_EVIDENCE_OK);
    assert(d2k_evidence_generalize(e,&h)==1);m=d2k_hypothesis_model(h);
    r=d2k_joint_search(&m,&c);
    assert(r.status==D2K_SYN_CANDIDATE && r.length==3);
    assert(r.operations[0]==0 && r.operations[1]==1 && r.operations[2]==2);
    d2k_syn_result rejected=d2k_joint_search_feedback(&m,&c,feedback_error,NULL);
    assert(rejected.status==D2K_SYN_ERROR);d2k_syn_result_free(&rejected);
    rejected=d2k_joint_search_feedback(&m,&c,feedback_reset,NULL);
    assert(rejected.status!=D2K_SYN_CANDIDATE && rejected.status!=D2K_SYN_ERROR);
    d2k_syn_result_free(&rejected);
    d2k_payload_piece operations[]={{0,2,0},{2,2,0},{0,0,0},{0,4,0}};
    d2k_payload_piece word[]={operations[r.operations[0]],operations[r.operations[1]]};
    char *plan=NULL,err[160];
    assert(d2k_lower_partition(4,word,2,"tls",&plan,err,sizeof err)==D2K_LOWER_OK);
    assert(strstr(plan,"split payload_start +2\n"));free(plan);d2k_syn_result_free(&r);
    c.accepted=broken;r=d2k_joint_search(&m,&c);
    assert(r.status==D2K_SYN_ERROR);d2k_syn_result_free(&r);
    d2k_hypothesis_free(h);d2k_evidence_free(e);
    /* Infer a repeatable transition from shorter observations. The candidate
       below has NEVER been observed: three next-byte actions then a read.
       Endpoint state prevents accepting the measured one/two-byte prefixes. */
    d2k_learner *learner=d2k_learner_new(context,sizeof context,2);assert(learner);
    d2k_sample short_reply[]={{0,0,1},{1,42,2}};
    d2k_sample longer_reply[]={{0,0,1},{0,0,1},{1,42,2}};
    assert(d2k_learner_seed(learner,context,sizeof context,short_reply,2)==D2K_L_OBSERVED);
    assert(d2k_learner_seed(learner,context,sizeof context,longer_reply,3)==D2K_L_OBSERVED);
    assert(d2k_learner_snapshot(learner,&h)==1);m=d2k_hypothesis_model(h);
    d2k_trigger original={0};original.len=3;memcpy(original.payload,"abc",3);
    size_t chunk=1;d2k_tls_stream stream={&original,&chunk,1,10,1};
    c=(d2k_synthesis_contract){d2k_tls_stream_domain(&stream),d2k_tls_stream_preserved,NULL,accepted};
    r=d2k_joint_search(&m,&c);
    assert(r.status==D2K_SYN_CANDIDATE && r.length==4);
    assert(r.operations[0]==0 && r.operations[1]==0 && r.operations[2]==0 && r.operations[3]==1);
    plan=NULL;
    assert(d2k_tls_stream_lower(&stream,r.operations,r.length,&plan,err,sizeof err)==D2K_LOWER_OK);
    assert(strstr(plan,"split payload_start +1\n") && strstr(plan,"split payload_start +2\n"));
    free(plan);
    assert(d2k_learner_request(learner,r.operations,r.length)==D2K_L_QUESTION);
    d2k_learning_question question;
    assert(d2k_learner_next(learner,&question)==D2K_L_QUESTION);
    assert(question.length==r.length && !memcmp(question.operations,r.operations,r.length*sizeof(size_t)));
    assert(question.predicted && question.terminal && question.observation==42);
    d2k_syn_result_free(&r);d2k_hypothesis_free(h);
    /* The experiment contradicts the inferred loop. Refinement must remove
       this candidate; an unexplored prefix may still request measurement. */
    d2k_sample counterexample[]={{0,0,1},{0,0,1},{0,0,1},{1,7,2}};
    assert(d2k_learner_submit(learner,question.generation,context,sizeof context,counterexample,4)==D2K_L_OBSERVED);
    assert(d2k_learner_snapshot(learner,&h)==1);m=d2k_hypothesis_model(h);
    r=d2k_joint_search(&m,&c);
    assert(r.status!=D2K_SYN_CANDIDATE && r.status!=D2K_SYN_DIRECT && r.status!=D2K_SYN_ERROR);
    d2k_syn_result_free(&r);d2k_hypothesis_free(h);d2k_learner_free(learner);
    puts("joint: learned response plus complete payload, unknown experiment, lowering and evaluator error PASS");
}
