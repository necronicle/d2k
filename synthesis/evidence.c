#include "evidence.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef struct {
    size_t parent,operation;
    uint64_t observation;
    int conflict,terminal;
} node;
struct d2k_evidence {
    unsigned char *context;
    size_t context_len,operations,count,capacity;
    node *nodes;
};
d2k_evidence *d2k_evidence_new(const void *context,size_t len,size_t operations) {
    if(!context || !len || !operations) return NULL;
    d2k_evidence *e=calloc(1,sizeof(*e));
    if(!e) return NULL;
    e->context=malloc(len); e->nodes=calloc(1,sizeof(node));
    if(!e->context || !e->nodes) { d2k_evidence_free(e); return NULL; }
    memcpy(e->context,context,len);e->context_len=len;e->operations=operations;
    e->count=e->capacity=1;
    return e;
}
void d2k_evidence_free(d2k_evidence *e) {
    if(!e) return;
    free(e->context);free(e->nodes);free(e);
}
static size_t child(const d2k_evidence *e,size_t parent,size_t op) {
    for(size_t i=1;i<e->count;i++)
        if(e->nodes[i].parent==parent && e->nodes[i].operation==op) return i;
    return SIZE_MAX;
}
d2k_evidence_status d2k_evidence_add(d2k_evidence *e,const void *context,size_t len,
                                     const d2k_sample *samples,size_t n) {
    if(!e || !context || (n && !samples)) return D2K_EVIDENCE_ERROR;
    if(len!=e->context_len || memcmp(e->context,context,len)) return D2K_EVIDENCE_CONTEXT;
    int ended=0;
    for(size_t i=0;i<n;i++) {
        if(samples[i].operation>=e->operations || samples[i].conclusive<0 ||
           samples[i].conclusive>D2K_SAMPLE_TERMINAL ||
           (ended && samples[i].conclusive))return D2K_EVIDENCE_ERROR;
        if(samples[i].conclusive==D2K_SAMPLE_TERMINAL)ended=1;
    }
    if(n>SIZE_MAX-e->count || e->count+n>SIZE_MAX/sizeof(node)) return D2K_EVIDENCE_ERROR;
    size_t need=e->count+n;
    if(need>e->capacity) {
        node *p=realloc(e->nodes,need*sizeof(node));
        if(!p) return D2K_EVIDENCE_ERROR;
        e->nodes=p;e->capacity=need;
    }
    size_t state=0;
    for(size_t i=0;i<n;i++) {
        /* Once an observation is unavailable, subsequent states cannot be
         * identified in this deterministic prefix abstraction. */
        if(!samples[i].conclusive) break;
        size_t next=child(e,state,samples[i].operation);
        if(next==SIZE_MAX) {
            next=e->count++;
            e->nodes[next]=(node){state,samples[i].operation,samples[i].observation,0,
                                 samples[i].conclusive==D2K_SAMPLE_TERMINAL};
        } else if(e->nodes[next].conflict || e->nodes[next].observation!=samples[i].observation ||
                  e->nodes[next].terminal!=(samples[i].conclusive==D2K_SAMPLE_TERMINAL)) {
            e->nodes[next].conflict=1;
            return D2K_EVIDENCE_CONFLICT;
        }
        state=next;
        if(e->nodes[next].terminal)break;
    }
    return D2K_EVIDENCE_OK;
}
static int step(void *ctx,size_t state,size_t operation,d2k_transition *out) {
    d2k_evidence *e=ctx;
    if(!e || !out || state>=e->count || operation>=e->operations) return -1;
    size_t next=child(e,state,operation);
    if(next==SIZE_MAX || e->nodes[next].conflict) return 0;
    out->next=next;out->observation=e->nodes[next].observation;
    return e->nodes[next].terminal?2:1;
}
d2k_transducer d2k_evidence_model(d2k_evidence *e) {
    if(!e) return (d2k_transducer){0};
    return (d2k_transducer){e,e->count,0,e->operations,step};
}

typedef struct { size_t from,to,operation; uint64_t observation; int terminal; } hypothesis_edge;
struct d2k_hypothesis {
    size_t states,initial,operations,count;
    hypothesis_edge *edges;
};
static size_t representative(size_t *parent,size_t s) {
    size_t root=s;
    while(parent[root]!=root) root=parent[root];
    while(parent[s]!=s) { size_t next=parent[s];parent[s]=root;s=next; }
    return root;
}
static int unify(size_t *parent,size_t a,size_t b) {
    a=representative(parent,a);b=representative(parent,b);
    if(a==b) return 0;
    if(a<b) parent[b]=a;else parent[a]=b;
    return 1;
}
static int close_merges(const d2k_evidence *e,size_t *parent,const d2k_inference_control *control)
{
    int changed;
    do {
        changed=0;
        for(size_t i=0;i<e->count;i++)for(size_t j=i+1;j<e->count;j++) {
            if(d2k_inference_stopped(control))return -1;
            if(representative(parent,i)==representative(parent,j) &&
               e->nodes[i].terminal!=e->nodes[j].terminal)return 0;
        }
        for(size_t i=1;i<e->count;i++) for(size_t j=i+1;j<e->count;j++) {
            if(d2k_inference_stopped(control))return -1;
            const node *a=&e->nodes[i],*b=&e->nodes[j];
            if(a->operation!=b->operation ||
               representative(parent,a->parent)!=representative(parent,b->parent)) continue;
            if(a->observation!=b->observation) return 0;
            changed|=unify(parent,i,j);
        }
    } while(changed);
    return 1;
}
static int shares_observed_input(const d2k_evidence *e,size_t *parent,size_t a,size_t b,const d2k_inference_control *control)
{
    for(size_t i=1;i<e->count;i++) {
        if(d2k_inference_stopped(control))return -1;
        if(representative(parent,e->nodes[i].parent)!=a) continue;
        for(size_t j=1;j<e->count;j++)
            if(representative(parent,e->nodes[j].parent)==b &&
               e->nodes[i].operation==e->nodes[j].operation) return 1;
    }
    return 0;
}
static int build_hypothesis(const d2k_evidence *e,size_t left,size_t right,
                            int automatic,d2k_hypothesis **out,const d2k_inference_control *control)
{
    if(!out) return -1;
    *out=NULL;
    if(d2k_inference_stopped(control))return -1;
    if(!e || left>=e->count || right>=e->count || e->count>SIZE_MAX/sizeof(size_t)) return -1;
    for(size_t i=1;i<e->count;i++) if(e->nodes[i].conflict) return 0;
    size_t *parent=malloc(e->count*sizeof(size_t));
    if(!parent) return -1;
    for(size_t i=0;i<e->count;i++) parent[i]=i;
    if(automatic) {
        size_t *trial=malloc(e->count*sizeof(size_t));
        if(!trial) {free(parent);return -1;}
        for(size_t i=0;i<e->count;i++) for(size_t j=i+1;j<e->count;j++) {
            if(d2k_inference_stopped(control)){free(trial);free(parent);return -1;}
            size_t a=representative(parent,i),b=representative(parent,j);
            if(a==b)continue;
            int shared=shares_observed_input(e,parent,a,b,control);
            if(shared<0){free(trial);free(parent);return -1;}
            if(!shared)continue;
            memcpy(trial,parent,e->count*sizeof(size_t));
            unify(trial,a,b);
            int closed=close_merges(e,trial,control);
            if(closed<0){free(trial);free(parent);return -1;}
            if(closed)memcpy(parent,trial,e->count*sizeof(size_t));
        }
        free(trial);
    } else {
        unify(parent,left,right);
        int closed=close_merges(e,parent,control);
        if(closed!=1){free(parent);return closed;}
    }
    d2k_hypothesis *h=calloc(1,sizeof(*h));
    if(!h || e->count>SIZE_MAX/sizeof(hypothesis_edge)) {free(h);free(parent);return -1;}
    h->edges=malloc(e->count*sizeof(*h->edges));
    if(!h->edges) {free(h);free(parent);return -1;}
    size_t *dense=malloc(e->count*sizeof *dense);
    if(!dense){d2k_hypothesis_free(h);free(parent);return -1;}
    for(size_t i=0;i<e->count;i++)dense[i]=SIZE_MAX;
    for(size_t i=0;i<e->count;i++) {
        size_t root=representative(parent,i);
        if(dense[root]==SIZE_MAX)dense[root]=h->states++;
    }
    h->initial=dense[representative(parent,0)];h->operations=e->operations;
    for(size_t i=1;i<e->count;i++) {
        if(d2k_inference_stopped(control)){free(dense);free(parent);d2k_hypothesis_free(h);return -1;}
        size_t from=dense[representative(parent,e->nodes[i].parent)];
        size_t to=dense[representative(parent,i)];
        int found=0;
        for(size_t j=0;j<h->count;j++)
            if(h->edges[j].from==from && h->edges[j].operation==e->nodes[i].operation) {found=1;break;}
        if(!found) h->edges[h->count++]=(hypothesis_edge){from,to,e->nodes[i].operation,
            e->nodes[i].observation,e->nodes[i].terminal};
    }
    free(dense);free(parent);*out=h;return 1;
}
static int hypothesis_step(void *ctx,size_t state,size_t op,d2k_transition *out) {
    d2k_hypothesis *h=ctx;
    if(!h || !out || state>=h->states || op>=h->operations) return -1;
    for(size_t i=0;i<h->count;i++) if(h->edges[i].from==state && h->edges[i].operation==op) {
        out->next=h->edges[i].to;out->observation=h->edges[i].observation;
        return h->edges[i].terminal?2:1;
    }
    return 0;
}
d2k_transducer d2k_hypothesis_model(d2k_hypothesis *h) {
    if(!h) return (d2k_transducer){0};
    return (d2k_transducer){h,h->states,h->initial,h->operations,hypothesis_step};
}
void d2k_hypothesis_free(d2k_hypothesis *h) {
    if(!h) return;
    free(h->edges);free(h);
}

int d2k_evidence_merge(const d2k_evidence *e,size_t left,size_t right,d2k_hypothesis **out)
{
    return build_hypothesis(e,left,right,0,out,NULL);
}
int d2k_evidence_generalize(const d2k_evidence *e,d2k_hypothesis **out)
{
    return build_hypothesis(e,0,0,1,out,NULL);
}
int d2k_evidence_generalize_controlled(const d2k_evidence *e,d2k_hypothesis **out,const d2k_inference_control *control) {
    return build_hypothesis(e,0,0,1,out,control);
}
int d2k_evidence_merge_controlled(const d2k_evidence *e,size_t a,size_t b,d2k_hypothesis **out,const d2k_inference_control *control) {
    return build_hypothesis(e,a,b,0,out,control);
}
