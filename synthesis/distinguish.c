#include "distinguish.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t left,right,domain,parent,via;
} pair_node;
typedef struct {
    pair_node *nodes;
    size_t count,capacity,*slots,slot_count;
} pair_graph;

static size_t pair_hash(size_t a,size_t b,size_t c)
{
    size_t h=a;
    h^=b+(size_t)0x9e3779b9+(h<<6)+(h>>2);
    h^=c+(size_t)0x9e3779b9+(h<<6)+(h>>2);
    return h;
}

static int pair_insert(pair_graph *g,size_t a,size_t b,size_t c,
    size_t parent,size_t via,const d2k_inference_control *control)
{
    if(!g->slot_count || g->count>=g->slot_count/2) {
        size_t cap=g->slot_count?g->slot_count*2:16;
        if(cap<g->slot_count || cap>SIZE_MAX/sizeof(size_t))return 0;
        size_t *slots=calloc(cap,sizeof(*slots));
        if(!slots)return 0;
        for(size_t i=0;i<g->count;i++) {
            if(d2k_inference_stopped(control)){free(slots);return 0;}
            pair_node n=g->nodes[i];
            size_t at=pair_hash(n.left,n.right,n.domain)&(cap-1);
            while(slots[at]) {
                if(d2k_inference_stopped(control)){free(slots);return 0;}
                at=(at+1)&(cap-1);
            }
            slots[at]=i+1;
        }
        free(g->slots);g->slots=slots;g->slot_count=cap;
    }
    size_t at=pair_hash(a,b,c)&(g->slot_count-1);
    while(g->slots[at]) {
        if(d2k_inference_stopped(control))return 0;
        pair_node n=g->nodes[g->slots[at]-1];
        if(n.left==a && n.right==b && n.domain==c)return 1;
        at=(at+1)&(g->slot_count-1);
    }
    if(g->count==g->capacity) {
        size_t cap=g->capacity?g->capacity*2:16;
        if(cap<g->capacity || cap>SIZE_MAX/sizeof(pair_node))return 0;
        pair_node *nodes=realloc(g->nodes,cap*sizeof(*nodes));
        if(!nodes)return 0;
        g->nodes=nodes;g->capacity=cap;
    }
    g->nodes[g->count]=(pair_node){a,b,c,parent,via};
    g->slots[at]=++g->count;
    return 1;
}

static int set_sequence(d2k_distinction *out, size_t pair,
                        size_t op,const pair_graph *g)
{
    size_t n=1;
    for(size_t p=pair;p;p=g->nodes[p].parent) ++n;
    if(n>SIZE_MAX/sizeof(size_t)) return 0;
    out->operations=malloc(n*sizeof(*out->operations));
    if(!out->operations) return 0;
    out->length=n; out->operations[--n]=op;
    for(size_t p=pair;p;p=g->nodes[p].parent) out->operations[--n]=g->nodes[p].via;
    return 1;
}

d2k_distinction d2k_distinguish_in_controlled(const d2k_transducer *l,const d2k_transducer *r,
                                 const d2k_input_domain *domain,const d2k_inference_control *control)
{
    d2k_distinction out={.status=D2K_DIST_ERROR};
    if(d2k_inference_stopped(control))return out;
    if(!l || !r || !l->step || !r->step || !l->states || !r->states ||
       l->initial>=l->states || r->initial>=r->states ||
       l->operations!=r->operations) return out;
    if(domain && (!domain->step || !domain->states || domain->initial>=domain->states ||
                  domain->operations!=l->operations))return out;
    size_t domain_states=domain?domain->states:1;
    pair_graph graph={0};
    size_t head=0;
    if(!pair_insert(&graph,l->initial,r->initial,domain?domain->initial:0,0,0,control))goto done;
    size_t frontier=SIZE_MAX, frontier_op=0;
    d2k_transition frontier_a={0}, frontier_b={0};
    unsigned frontier_known=0,frontier_terminal=0;
    while(head<graph.count) {
        if(d2k_inference_stopped(control))goto done;
        size_t pair=head++;
        pair_node node=graph.nodes[pair];
        for(size_t op=0;op<l->operations;op++) {
            if(d2k_inference_stopped(control))goto done;
            size_t domain_next=0;
            if(domain) {
                int allowed=domain->step(domain->ctx,node.domain,op,&domain_next);
                if(allowed<0 || allowed>1 || (allowed && domain_next>=domain_states))goto done;
                if(!allowed)continue;
            }
            d2k_transition a={0},b={0};
            int ar=l->step(l->ctx,node.left,op,&a);
            int br=r->step(r->ctx,node.right,op,&b);
            if(ar<0 || br<0 || ar>2 || br>2) goto done;
            if((ar && a.next>=l->states) || (br && b.next>=r->states)) goto done;
            if(!ar || !br) {
                if(frontier==SIZE_MAX || (!frontier_known && (ar || br))) {
                    frontier=pair; frontier_op=op;
                    frontier_a=a; frontier_b=b;
                    frontier_known=(ar?1u:0u)|(br?2u:0u);
                    frontier_terminal=(ar==2?1u:0u)|(br==2?2u:0u);
                }
                continue;
            }

            if(a.observation!=b.observation || ar!=br) {
                if(!set_sequence(&out,pair,op,&graph)) goto done;
                out.known_outputs=3;
                out.terminal_outputs=(ar==2?1u:0u)|(br==2?2u:0u);
                out.left_observation=a.observation; out.right_observation=b.observation;
                out.status=D2K_DIST_WITNESS; goto done;
            }
            if(ar==2)continue;
            if(!pair_insert(&graph,a.next,b.next,domain_next,pair,op,control))goto done;
        }
    }
    if(frontier!=SIZE_MAX) {
        if(!set_sequence(&out,frontier,frontier_op,&graph)) goto done;
        out.left_observation=frontier_a.observation;
        out.right_observation=frontier_b.observation;
        out.known_outputs=frontier_known;
        out.terminal_outputs=frontier_terminal;
        out.status=D2K_DIST_INCOMPLETE;
    } else out.status=D2K_DIST_EQUIVALENT;

done:
    free(graph.nodes); free(graph.slots);
    return out;
}
d2k_distinction d2k_distinguish(const d2k_transducer *l,const d2k_transducer *r) {
    return d2k_distinguish_in(l,r,NULL);
}
void d2k_distinction_free(d2k_distinction *d) {
    if(!d) return;
    free(d->operations); memset(d,0,sizeof(*d));
}
int d2k_question_prefix(const d2k_transducer *m,const size_t *word,size_t n,uint64_t **out)
{
    uint64_t *values=NULL;
    size_t state;
    if(out) *out=NULL;
    if(!m || !m->step || !out || !m->states || m->initial>=m->states ||
       (n && !word) || n>SIZE_MAX/sizeof(*values)) return -1;
    for(size_t i=0;i<n;i++) if(word[i]>=m->operations) return -1;
    if(n<=1) return 1;
    values=malloc((n-1)*sizeof(*values));
    if(!values) return -1;
    state=m->initial;
    for(size_t i=0;i+1<n;i++) {
        d2k_transition t;
        int rc=m->step(m->ctx,state,word[i],&t);
        if(rc!=1 || t.next>=m->states) {
            free(values); return rc==0?0:-1;
        }
        values[i]=t.observation; state=t.next;
    }
    *out=values; return 1;
}

d2k_distinction d2k_distinguish_in(const d2k_transducer *l,const d2k_transducer *r,const d2k_input_domain *d) { return d2k_distinguish_in_controlled(l,r,d,NULL); }
