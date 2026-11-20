#include "alternatives.h"
#include <string.h>
#include <stdlib.h>

void d2k_alternatives_free(d2k_alternatives *q)
{
    if(!q) return;
    d2k_distinction_free(&q->word);
    free(q->prefix_observations);
    memset(q,0,sizeof(*q)); q->status=D2K_ALTERNATIVES_ERROR;
}
static int candidate(const d2k_evidence *e,const d2k_sample *trace,size_t n,
    size_t anchor,d2k_hypothesis **out,d2k_transducer *current,const d2k_inference_control *control)
{
    int rc=d2k_evidence_merge_controlled(e,n,anchor,out,control);
    if(rc!=1) return rc;
    *current=d2k_hypothesis_model(*out);
    for(size_t i=0;i<n;i++) {
        d2k_transition t;
        if(current->step(current->ctx,current->initial,trace[i].operation,&t)!=1 ||
           t.observation!=trace[i].observation || t.next>=current->states) {
            d2k_hypothesis_free(*out); *out=NULL; return -1;
        }
        current->initial=t.next;
    }
    return 1;
}
d2k_alternatives d2k_continuous_alternatives_controlled(const d2k_sample *trace,size_t n,
    size_t operations,const d2k_input_domain *domain,const d2k_inference_control *control)
{
    const char ctx[]="one chronological origin/alternatives/v1";
    d2k_alternatives q={.status=D2K_ALTERNATIVES_ERROR,
        .left_anchor=SIZE_MAX,.right_anchor=SIZE_MAX};
    d2k_evidence *e=NULL;
    d2k_hypothesis *left=NULL,*right=NULL;
    int unknown=0;
    if(d2k_inference_stopped(control))return q;
    if(!operations || (n && !trace) ||
       (domain && (!domain->step || !domain->states ||
        domain->initial>=domain->states || domain->operations!=operations))) return q;
    for(size_t i=0;i<n;i++) {
        if(trace[i].operation>=operations ||
           (trace[i].conclusive!=D2K_SAMPLE_OBSERVED && trace[i].conclusive!=D2K_SAMPLE_UNKNOWN))
            return q;
        if(!trace[i].conclusive) unknown=1;
    }
    if(unknown) { q.status=D2K_ALTERNATIVES_UNKNOWN; return q; }
    e=d2k_evidence_new(ctx,sizeof(ctx),operations);
    if(!e || d2k_evidence_add(e,ctx,sizeof(ctx),trace,n)!=D2K_EVIDENCE_OK) goto error;
    for(size_t a=0;a<n;a++) {
        d2k_transducer lm;
        int rc=candidate(e,trace,n,a,&left,&lm,control);
        if(rc<0) goto error;
        if(!rc) continue;
        for(size_t b=a+1;b<n;b++) {
            d2k_transducer rm;
            d2k_distinction d;
            rc=candidate(e,trace,n,b,&right,&rm,control);
            if(rc<0) goto error;
            if(!rc) continue;
            d=d2k_distinguish_in_controlled(&lm,&rm,domain,control);
            d2k_hypothesis_free(right); right=NULL;
            if(d.status==D2K_DIST_ERROR) { d2k_distinction_free(&d); goto error; }
            if(d.status==D2K_DIST_WITNESS && (!q.word.length || d.length<q.word.length)) {
                uint64_t *prefix=NULL;
                if(d2k_question_prefix(&lm,d.operations,d.length,&prefix)!=1) {
                    d2k_distinction_free(&d); goto error;
                }
                free(q.prefix_observations); q.prefix_observations=prefix;
                d2k_distinction_free(&q.word); q.word=d;
                memset(&d,0,sizeof(d)); q.left_anchor=a; q.right_anchor=b;
            }
            d2k_distinction_free(&d);
            if(q.word.length==1) goto success;
        }
        d2k_hypothesis_free(left); left=NULL;
    }
success:
    q.status=q.word.length?D2K_ALTERNATIVES_QUESTION:D2K_ALTERNATIVES_NONE;
    goto done;
error:
    d2k_alternatives_free(&q);
done:
    d2k_hypothesis_free(left); d2k_hypothesis_free(right); d2k_evidence_free(e);
    return q;
}

d2k_alternatives d2k_continuous_alternatives(const d2k_sample *t,size_t n,size_t ops,const d2k_input_domain *d) { return d2k_continuous_alternatives_controlled(t,n,ops,d,NULL); }
