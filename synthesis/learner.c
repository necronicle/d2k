#include "learner.h"
#include <stdlib.h>
#include <string.h>
struct d2k_learner {
    d2k_evidence *evidence;
    d2k_distinction pending;
    uint64_t generation;
    int waiting,conflict,inconclusive;
    d2k_input_domain domain;
};
d2k_learner *d2k_learner_new_in(const void *ctx,size_t len,size_t operations,const d2k_input_domain *domain) {
    if(domain && (!domain->step || !domain->states || domain->initial>=domain->states ||
                  domain->operations!=operations))return NULL;
    d2k_learner *l=calloc(1,sizeof *l);if(!l)return NULL;
    if(domain)l->domain=*domain;
    l->evidence=d2k_evidence_new(ctx,len,operations);
    if(!l->evidence){free(l);return NULL;}return l;
}
d2k_learner *d2k_learner_new(const void *ctx,size_t len,size_t operations) {
    return d2k_learner_new_in(ctx,len,operations,NULL);
}
void d2k_learner_free(d2k_learner *l) {
    if(!l)return;
    d2k_distinction_free(&l->pending);d2k_evidence_free(l->evidence);free(l);
}
int d2k_learner_snapshot(const d2k_learner *l,d2k_hypothesis **out) {
    if(!out)return -1;
    *out=NULL;
    if(!l)return -1;
    if(l->waiting || l->conflict || l->inconclusive)return 0;
    return d2k_evidence_generalize(l->evidence,out);
}
int d2k_learner_trace(const d2k_learner *l,const size_t *word,size_t n,d2k_sample *out) {
    if(!l || !word || !out || !n || l->conflict || l->inconclusive)return -1;
    d2k_transducer exact=d2k_evidence_model(l->evidence);size_t state=exact.initial;
    for(size_t i=0;i<n;i++) {
        if(word[i]>=exact.operations)return -1;
        d2k_transition t;int rc=exact.step(exact.ctx,state,word[i],&t);
        if(rc<0 || rc>2 || (rc==2 && i+1<n))return -1;
        if(!rc)return 0;
        out[i]=(d2k_sample){word[i],t.observation,rc};state=t.next;
    }
    return 1;
}
static d2k_learner_status admit(d2k_learner *l,const void *ctx,size_t len,
                               const d2k_sample *samples,size_t n,int *novel) {
    *novel=0;
    if(n && !samples)return D2K_L_ERROR;
    if(l->domain.step) {
        size_t domain_state=l->domain.initial;
        for(size_t i=0;i<n && samples[i].conclusive;i++) {
            size_t next=0;
            if(samples[i].operation>=l->domain.operations ||
               l->domain.step(l->domain.ctx,domain_state,samples[i].operation,&next)!=1 ||
               next>=l->domain.states)return D2K_L_ERROR;
            domain_state=next;
        }
    }
    d2k_transducer model=d2k_evidence_model(l->evidence);size_t state=model.initial;
    for(size_t i=0;i<n && samples[i].conclusive;i++) {
        d2k_transition t;int rc=model.step(model.ctx,state,samples[i].operation,&t);
        if(rc==0){*novel=1;break;}
        if(rc<0 || rc!=samples[i].conclusive || t.observation!=samples[i].observation)break;
        state=t.next;
    }
    d2k_evidence_status rc=d2k_evidence_add(l->evidence,ctx,len,samples,n);
    if(rc==D2K_EVIDENCE_CONTEXT)return D2K_L_CONTEXT;
    if(rc==D2K_EVIDENCE_ERROR)return D2K_L_ERROR;
    if(rc==D2K_EVIDENCE_CONFLICT){l->conflict=1;return D2K_L_CONFLICT;}
    return D2K_L_OBSERVED;
}
d2k_learner_status d2k_learner_seed(d2k_learner *l,const void *ctx,size_t len,
                                   const d2k_sample *samples,size_t n) {
    if(!l)return D2K_L_ERROR;
    if(l->waiting)return D2K_L_STALE;
    if(l->conflict)return D2K_L_CONFLICT;
    int novel=0;d2k_learner_status rc=admit(l,ctx,len,samples,n,&novel);
    if(rc==D2K_L_OBSERVED && novel)l->inconclusive=0;
    return rc;
}
d2k_learner_status d2k_learner_next(d2k_learner *l,d2k_learning_question *q) {
    if(q)memset(q,0,sizeof *q);
    if(!l || !q)return D2K_L_ERROR;
    if(l->conflict)return D2K_L_CONFLICT;
    if(l->inconclusive)return D2K_L_INCONCLUSIVE;
    if(!l->waiting) {
        if(l->generation==UINT64_MAX)return D2K_L_ERROR;
        d2k_hypothesis *hypothesis=NULL;
        int rc=d2k_evidence_generalize(l->evidence,&hypothesis);
        if(rc<0)return D2K_L_ERROR;
        if(!rc){l->conflict=1;return D2K_L_CONFLICT;}
        d2k_transducer exact=d2k_evidence_model(l->evidence),inferred=d2k_hypothesis_model(hypothesis);
        l->pending=d2k_distinguish_in(&exact,&inferred,l->domain.step?&l->domain:NULL);
        d2k_hypothesis_free(hypothesis);
        if(l->pending.status==D2K_DIST_EQUIVALENT) {
            d2k_distinction_free(&l->pending);return D2K_L_CLOSED;
        }
        if(l->pending.status!=D2K_DIST_INCOMPLETE || !l->pending.length) {
            d2k_distinction_free(&l->pending);return D2K_L_ERROR;
        }
        l->waiting=1;++l->generation;
    }
    q->generation=l->generation;q->operations=l->pending.operations;q->length=l->pending.length;
    q->predicted=!!(l->pending.known_outputs&2);
    q->terminal=!!(l->pending.terminal_outputs&2);
    q->observation=l->pending.right_observation;
    return D2K_L_QUESTION;
}
d2k_learner_status d2k_learner_request(d2k_learner *l,const size_t *word,size_t n) {
    if(!l || !word || !n || n>SIZE_MAX/sizeof *word)return D2K_L_ERROR;
    if(l->conflict)return D2K_L_CONFLICT;
    if(l->inconclusive)return D2K_L_INCONCLUSIVE;
    if(l->waiting)return D2K_L_STALE;
    if(l->generation==UINT64_MAX)return D2K_L_ERROR;
    d2k_transducer exact=d2k_evidence_model(l->evidence);
    size_t state=exact.initial,domain_state=l->domain.initial;
    int unknown=0;
    for(size_t i=0;i<n;i++) {
        if(word[i]>=exact.operations)return D2K_L_ERROR;
        if(l->domain.step) {
            size_t next;
            if(l->domain.step(l->domain.ctx,domain_state,word[i],&next)!=1 ||
               next>=l->domain.states)return D2K_L_ERROR;
            domain_state=next;
        }
        if(!unknown) {
            d2k_transition t;int rc=exact.step(exact.ctx,state,word[i],&t);
            if(rc<0 || rc>2 || (rc==2 && i+1<n))return D2K_L_ERROR;
            if(!rc)unknown=1;
            else state=t.next;
        }
    }
    if(!unknown)return D2K_L_CLOSED;
    d2k_hypothesis *h=NULL;
    if(d2k_evidence_generalize(l->evidence,&h)!=1)return D2K_L_ERROR;
    d2k_distinction pending={.status=D2K_DIST_INCOMPLETE,.length=n};
    pending.operations=malloc(n*sizeof *word);
    if(!pending.operations){d2k_hypothesis_free(h);return D2K_L_ERROR;}
    memcpy(pending.operations,word,n*sizeof *word);
    d2k_transducer model=d2k_hypothesis_model(h);state=model.initial;
    for(size_t i=0;i<n;i++) {
        d2k_transition t;int rc=model.step(model.ctx,state,word[i],&t);
        if(rc<0 || rc>2) {
            d2k_hypothesis_free(h);d2k_distinction_free(&pending);return D2K_L_ERROR;
        }
        if(!rc)break;
        if(i+1==n) {
            pending.known_outputs=2;pending.right_observation=t.observation;
            if(rc==2)pending.terminal_outputs=2;
        }
        if(rc==2)break;
        state=t.next;
    }
    d2k_hypothesis_free(h);l->pending=pending;l->waiting=1;++l->generation;
    return D2K_L_QUESTION;
}
d2k_learner_status d2k_learner_submit(d2k_learner *l,uint64_t generation,
    const void *ctx,size_t len,const d2k_sample *samples,size_t n) {
    if(!l)return D2K_L_ERROR;
    if(!l->waiting || generation!=l->generation)return D2K_L_STALE;
    if(n>l->pending.length || (n && !samples))return D2K_L_ERROR;
    for(size_t i=0;i<n;i++)
        if(samples[i].operation!=l->pending.operations[i] ||
           (samples[i].conclusive!=D2K_SAMPLE_OBSERVED && samples[i].conclusive!=D2K_SAMPLE_TERMINAL))
            return D2K_L_ERROR;
    int novel=0;d2k_learner_status rc=admit(l,ctx,len,samples,n,&novel);
    if(rc==D2K_L_ERROR || rc==D2K_L_CONTEXT)return rc;
    int complete=n==l->pending.length || (n && samples[n-1].conclusive==D2K_SAMPLE_TERMINAL);
    d2k_distinction_free(&l->pending);l->waiting=0;
    if(rc==D2K_L_CONFLICT)return rc;
    if(!complete || !novel){l->inconclusive=1;return D2K_L_INCONCLUSIVE;}
    return D2K_L_OBSERVED;
}
