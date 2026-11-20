#include "tracking.h"
#include <assert.h>
#include <stdio.h>

static int step(void *ctx,size_t s,size_t op,d2k_transition *t)
{
    int mode=*(int *)ctx;
    if(mode==2 && s==1) return 0;
    if(mode==3) return -1;
    t->next=op ? 1-s:s;
    t->observation=op ? (uint64_t)(10+(mode==1 ? 0:s)):0;
    return mode==4 ? 2:1;
}
static void exhaustive(void)
{
    int mode=0;
    d2k_transducer m={&mode,2,0,2,step};
    size_t word,outputs,i,s;
    for(word=0;word<16;word++) for(outputs=0;outputs<16;outputs++) {
        d2k_sample trace[4];
        unsigned char expected[2]={0,0};
        size_t count=0;
        d2k_tracking r;
        for(i=0;i<4;i++) {
            trace[i].operation=(word>>i)&1;
            trace[i].observation=trace[i].operation ? 10+((outputs>>i)&1):0;
            trace[i].conclusive=1;
        }
        for(s=0;s<2;s++) {
            size_t state=s;
            for(i=0;i<4;i++) {
                d2k_transition t;
                assert(step(&mode,state,trace[i].operation,&t)==1);
                if(t.observation!=trace[i].observation) break;
                state=t.next;
            }
            if(i==4 && !expected[state]) { expected[state]=1; count++; }
        }
        r=d2k_track(&m,trace,4);
        assert(r.status==(count ? D2K_TRACK_MATCH:D2K_TRACK_CONTRADICTION));
        if(count) {
            assert(r.possible==count);
            assert(r.states[0]==expected[0] && r.states[1]==expected[1]);
        }
        d2k_tracking_free(&r);
    }
}
int main(void)
{
    const char context[]="merged-loop";
    d2k_evidence *e=d2k_evidence_new(context,sizeof context,1);assert(e);
    d2k_sample loop[]={{0,7,1},{0,7,1},{0,7,1}};
    assert(d2k_evidence_add(e,context,sizeof context,loop,3)==D2K_EVIDENCE_OK);
    d2k_hypothesis *h=NULL;
    assert(d2k_evidence_merge(e,0,1,&h)==1);
    d2k_transducer learned=d2k_hypothesis_model(h);
    d2k_tracking relocated=d2k_track(&learned,loop,1);
    assert(relocated.status==D2K_TRACK_MATCH && relocated.possible==1);
    d2k_tracking_free(&relocated);d2k_hypothesis_free(h);d2k_evidence_free(e);
    int mode=0;
    d2k_transducer m={&mode,2,0,2,step};
    d2k_sample trace[]={{0,0,1},{1,11,1},{0,0,1},{1,10,1},{0,0,1}};
    d2k_tracking r=d2k_track(&m,trace,5);
    assert(r.status==D2K_TRACK_MATCH && r.prefix==5 && r.possible==1);
    assert(r.states[1] && !r.states[0]);
    d2k_tracking_free(&r);
    mode=1;
    r=d2k_track(&m,trace,5);
    assert(r.status==D2K_TRACK_CONTRADICTION && r.prefix==2);
    d2k_tracking_free(&r);
    mode=2;
    r=d2k_track(&m,trace,5);
    assert(r.status==D2K_TRACK_UNKNOWN && r.prefix==1 && !r.states);
    d2k_tracking_free(&r);
    unsigned char initial[]={1,0};
    r=d2k_track_from(&m,initial,trace,1);
    assert(r.status==D2K_TRACK_MATCH && r.possible==1 && r.states[0]);
    d2k_tracking_free(&r);
    initial[0]=0;r=d2k_track_from(&m,initial,trace,1);
    assert(r.status==D2K_TRACK_ERROR);
    mode=3;
    r=d2k_track(&m,trace,5);
    assert(r.status==D2K_TRACK_ERROR);
    mode=0;
    r=d2k_track(&m,NULL,0);
    assert(r.status==D2K_TRACK_MATCH && r.possible==2);
    d2k_tracking_free(&r);
    trace[0].conclusive=0;
    r=d2k_track(&m,trace,5);
    assert(r.status==D2K_TRACK_UNKNOWN && r.prefix==1);
    trace[0].conclusive=2;
    r=d2k_track(&m,trace,5);
    assert(r.status==D2K_TRACK_ERROR);
    mode=4;
    r=d2k_track(&m,trace,1);
    assert(r.status==D2K_TRACK_MATCH && r.terminal && r.possible==2);
    d2k_tracking_free(&r);
    trace[0].conclusive=1;
    r=d2k_track(&m,trace,1);
    assert(r.status==D2K_TRACK_CONTRADICTION && r.prefix==1);
    d2k_tracking_free(&r);
    trace[0].operation=2;
    r=d2k_track(&m,trace,1);
    assert(r.status==D2K_TRACK_ERROR);
    exhaustive();
    puts("tracking: persistent states, contradictions, uncertainty and exhaustive traces pass");
    return 0;
}
