#include "inference.h"
#include <stdlib.h>
#include <stdint.h>
int d2k_choose_question(const d2k_belief *b, const d2k_input_word *q, size_t n,
                        d2k_predict predict, void *ctx, d2k_question *out)
{
    if (!b || !b->count || !b->ids || !predict || !out || (n && !q) ||
        b->count > SIZE_MAX/sizeof(uint64_t)) return -1;
    uint64_t *values=malloc(b->count*sizeof(*values));
    if (!values) return -1;
    out->index=SIZE_MAX; out->guaranteed_eliminations=0;
    for(size_t i=0;i<n;i++) {
        size_t known=0,unknown=0,worst=0;
        if(q[i].length && !q[i].operations) { free(values); return -1; }
        for(size_t j=0;j<b->count;j++) {
            uint64_t value=0;
            int rc=predict(ctx,b->ids[j],&q[i],&value);
            if(rc<0) { free(values); return -1; }
            if(!rc) unknown++; else values[known++]=value;
        }
        for(size_t j=0;j<known;j++) {
            size_t bucket=unknown;
            for(size_t k=0;k<known;k++) bucket+=values[k]==values[j];
            if(bucket>worst) worst=bucket;
        }
        if(!known) worst=unknown;
        size_t gain=b->count-worst;
        if(gain>out->guaranteed_eliminations ||
           (gain && gain==out->guaranteed_eliminations &&
            q[i].length<q[out->index].length)) {
            out->index=i; out->guaranteed_eliminations=gain;
        }
    }
    free(values);
    return out->index!=SIZE_MAX;
}
d2k_learn_status d2k_observe(d2k_belief *b, uint64_t epoch,
    const d2k_input_word *q, int conclusive, uint64_t outcome,
    d2k_predict predict, void *ctx)
{
    if(!b || !b->count || !b->ids || !q || !predict ||
       (q->length && !q->operations) || b->count>SIZE_MAX/sizeof(size_t))
        return D2K_LEARN_ERROR;
    if(epoch!=b->epoch) return D2K_LEARN_STALE;
    if(!conclusive) return D2K_LEARN_UNCHANGED;
    size_t *keep=malloc(b->count*sizeof(*keep)),n=0;
    if(!keep) return D2K_LEARN_ERROR;
    for(size_t i=0;i<b->count;i++) {
        uint64_t value=0;
        int rc=predict(ctx,b->ids[i],q,&value);
        if(rc<0) { free(keep); return D2K_LEARN_ERROR; }
        if(!rc || value==outcome) keep[n++]=b->ids[i];
    }
    if(!n) { free(keep); return D2K_LEARN_CONTRADICTION; }
    if(n==b->count) { free(keep); return D2K_LEARN_UNCHANGED; }
    for(size_t i=0;i<n;i++) b->ids[i]=keep[i];
    b->count=n;
    free(keep);
    return D2K_LEARN_REFINED;
}
