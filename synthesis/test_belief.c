#include "joint.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static int step(void *ctx,size_t s,size_t op,d2k_transition *t)
{
    int mode=*(int *)ctx;
    if(mode==2 && s==1)return 0;
    if(mode==3)return -1;
    t->next=mode==4 && op==1?0:s;
    t->observation=(op==0?s==0:mode!=4)?7:0;
    if(mode==1 && s==1)t->observation=0;
    return mode==1 && s==1?2:1;
}
static int allowed(void *ctx,size_t s,size_t op,size_t *n)
{(void)ctx;(void)s;(void)op;*n=0;return 1;}
static int preserved(void *ctx,size_t s){(void)s;return *(int *)ctx;}
static int accepted(void *ctx,uint64_t value){(void)ctx;return value==7;}
static int response_step(void *ctx,size_t s,size_t op,d2k_transition *t)
{(void)ctx;t->next=0;t->observation=op?7:10+s;return 1;}
static int lifecycle(void *ctx,size_t s,size_t op,size_t *n)
{(void)ctx;*n=op?3:1;return (s==0 && op==0) || (s==1 && op==1);}
static int complete(void *ctx,size_t s){(void)ctx;return s==3;}
static int feedback(void *ctx,size_t op,uint64_t response,size_t *next)
{
    int mode=*(int *)ctx;
    if(mode<0)return -1;
    if(mode && !op && response==(mode==2?10u:11u))*next=2;
    return 1;
}
static void response_branches(void)
{
    int mode=0;unsigned char states[]={1,1};
    d2k_transducer m={NULL,2,0,2,response_step};
    d2k_synthesis_contract c={{NULL,4,0,2,lifecycle},complete,NULL,accepted};
    d2k_syn_result r=d2k_joint_search_belief_feedback(&m,states,&c,feedback,&mode);
    assert(r.status==D2K_SYN_CANDIDATE && r.length==2);d2k_syn_result_free(&r);
    mode=1;r=d2k_joint_search_belief_feedback(&m,states,&c,feedback,&mode);
    assert(r.status==D2K_SYN_CLOSED);d2k_syn_result_free(&r);
    mode=2;r=d2k_joint_search_belief_feedback(&m,states,&c,feedback,&mode);
    assert(r.status==D2K_SYN_CLOSED);d2k_syn_result_free(&r);
    mode=-1;r=d2k_joint_search_belief_feedback(&m,states,&c,feedback,&mode);
    assert(r.status==D2K_SYN_ERROR);d2k_syn_result_free(&r);
}
int main(void)
{
    response_branches();
    for(int mode=0;mode<=4;mode++)for(int keep=0;keep<=1;keep++)for(size_t s=0;s<2;s++) {
        d2k_transducer model={&mode,2,s,2,step};
        d2k_synthesis_contract contract={{&keep,1,0,2,allowed},preserved,NULL,accepted};
        unsigned char one[]={s==0,s==1};
        d2k_syn_result graph=d2k_joint_search(&model,&contract);
        d2k_syn_result belief=d2k_joint_search_belief(&model,one,&contract);
        assert(graph.status==belief.status && graph.length==belief.length);
        assert(!graph.length || !memcmp(graph.operations,belief.operations,graph.length*sizeof(size_t)));
        d2k_syn_result_free(&graph);d2k_syn_result_free(&belief);
    }
    int mode=0,keep=1;
    d2k_transducer m={&mode,2,0,2,step};
    d2k_synthesis_contract c={{&keep,1,0,2,allowed},preserved,NULL,accepted};
    unsigned char states[]={1,1};
    d2k_syn_result r=d2k_joint_search_belief(&m,states,&c);
    assert(r.status==D2K_SYN_CANDIDATE && r.length==1 && r.operations[0]==1);
    d2k_syn_result_free(&r);
    mode=4;r=d2k_joint_search_belief(&m,states,&c);
    assert(r.status==D2K_SYN_CANDIDATE && r.length==2 && r.operations[0]==1 && r.operations[1]==0);
    d2k_syn_result_free(&r);
    mode=2;r=d2k_joint_search_belief(&m,states,&c);
    assert(r.status==D2K_SYN_EXPERIMENT);d2k_syn_result_free(&r);
    mode=3;r=d2k_joint_search_belief(&m,states,&c);
    assert(r.status==D2K_SYN_ERROR);d2k_syn_result_free(&r);
    mode=1;r=d2k_joint_search_belief(&m,states,&c);
    assert(r.status==D2K_SYN_CLOSED);d2k_syn_result_free(&r);
    mode=0;keep=0;r=d2k_joint_search_belief(&m,states,&c);
    assert(r.status==D2K_SYN_CLOSED);d2k_syn_result_free(&r);
    states[0]=states[1]=0;r=d2k_joint_search_belief(&m,states,&c);
    assert(r.status==D2K_SYN_ERROR);d2k_syn_result_free(&r);
    puts("belief: common transformation, two-step synthesis, unknown and preservation pass");
}
