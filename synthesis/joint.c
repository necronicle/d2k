#include "joint.h"
typedef struct {
    const d2k_transducer *learned;
    const d2k_synthesis_contract *contract;
    size_t success;
    int (*feedback)(void *,size_t,uint64_t,size_t *);
    void *feedback_context;
    const d2k_inference_control *control;
} joint;
static int goal(void *ctx,size_t state) {return state==((joint *)ctx)->success;}
static d2k_syn_edge step(void *ctx,size_t state,size_t op) {
    joint *j=ctx;const d2k_input_domain *d=&j->contract->endpoint;
    d2k_syn_edge error={D2K_SYN_EDGE_ERROR,0};
    if(d2k_inference_stopped(j->control))return error;
    if(state>=j->success || op>=d->operations)return error;
    size_t next=0;
    int allowed=d->step(d->ctx,state%d->states,op,&next);
    if(allowed<0 || allowed>1 || (allowed && next>=d->states))return error;
    if(!allowed)return (d2k_syn_edge){D2K_SYN_INVALID,0};
    d2k_transition t={0};
    int known=j->learned->step(j->learned->ctx,state/d->states,op,&t);
    if(known<0 || known>2 || (known && t.next>=j->learned->states))return error;
    if(!known)return (d2k_syn_edge){D2K_SYN_UNKNOWN,0};
    if(j->feedback) {
        int rc=j->feedback(j->feedback_context,op,t.observation,&next);
        if(rc<0 || rc>1 || (rc && next>=d->states))return error;
        if(!rc)return (d2k_syn_edge){D2K_SYN_INVALID,0};
    }
    int response=j->contract->accepted(j->contract->observation_context,t.observation);
    if(response<0 || response>1)return error;
    if(response) {
        int complete=j->contract->preserved(d->ctx,next);
        if(complete<0 || complete>1)return error;
        if(complete)return (d2k_syn_edge){D2K_SYN_EDGE,j->success};
    }
    if(known==2)return (d2k_syn_edge){D2K_SYN_INVALID,0};
    return (d2k_syn_edge){D2K_SYN_EDGE,t.next*d->states+next};
}
d2k_syn_result d2k_joint_search_feedback_controlled(const d2k_transducer *m,const d2k_synthesis_contract *c,
    int (*feedback)(void *,size_t,uint64_t,size_t *),void *feedback_context,const d2k_inference_control *control) {
    d2k_syn_result error={.status=D2K_SYN_ERROR};
    if(d2k_inference_stopped(control))return error;
    if(!m || !c || !m->states || !m->step || m->initial>=m->states ||
       !c->endpoint.states || !c->endpoint.step || c->endpoint.initial>=c->endpoint.states ||
       c->endpoint.operations!=m->operations || !c->accepted || !c->preserved ||
       m->states>(SIZE_MAX-1)/c->endpoint.states)return error;
    joint j={m,c,m->states*c->endpoint.states,feedback,feedback_context,control};
    d2k_syn_model product={&j,j.success+1,m->operations,
        m->initial*c->endpoint.states+c->endpoint.initial,step,goal};
    return d2k_syn_search(&product);
}
d2k_syn_result d2k_joint_search_feedback(const d2k_transducer *m,const d2k_synthesis_contract *c,
    int (*feedback)(void *,size_t,uint64_t,size_t *),void *ctx) {
    return d2k_joint_search_feedback_controlled(m,c,feedback,ctx,NULL);
}
d2k_syn_result d2k_joint_search(const d2k_transducer *m,const d2k_synthesis_contract *c) {
    return d2k_joint_search_feedback(m,c,NULL,NULL);
}

#include <stdlib.h>
#include <string.h>
typedef struct {
    unsigned char *states;
    size_t parent,operation;
} belief_node;
static d2k_syn_result belief_word(const belief_node *nodes,size_t at,size_t op,d2k_syn_status status)
{
    d2k_syn_result r={.status=D2K_SYN_ERROR};
    size_t count=1;
    for(size_t i=at;i;i=nodes[i].parent)count++;
    if(count>SIZE_MAX/sizeof(size_t))return r;
    r.operations=malloc(count*sizeof *r.operations);
    if(!r.operations)return r;
    r.length=count;r.unresolved_state=at;r.status=status;
    r.operations[--count]=op;
    for(size_t i=at;i;i=nodes[i].parent)r.operations[--count]=nodes[i].operation;
    return r;
}
d2k_syn_result d2k_joint_search_belief_feedback_controlled(const d2k_transducer *m,const unsigned char *initial,
    const d2k_synthesis_contract *c,int (*feedback)(void *,size_t,uint64_t,size_t *),void *feedback_context,
    const d2k_inference_control *control)
{
    d2k_syn_result r={.status=D2K_SYN_ERROR};
    if(d2k_inference_stopped(control))return r;
    if(!m || !initial || !c || !m->states || !m->operations || !m->step ||
       !c->endpoint.states || c->endpoint.initial>=c->endpoint.states ||
       !c->endpoint.step || c->endpoint.operations!=m->operations || !c->preserved || !c->accepted)return r;
    if(m->states>SIZE_MAX/c->endpoint.states)return r;
    size_t width=c->endpoint.states,total=m->states*width,active=0,sole=0;
    for(size_t i=0;i<m->states;i++) {
        if(d2k_inference_stopped(control))return r;
        active+=!!initial[i];
        if(initial[i])sole=i;
    }
    if(!active)return r;
    if(active==1) {
        d2k_transducer known=*m;
        known.initial=sole;
        return d2k_joint_search_feedback_controlled(&known,c,feedback,feedback_context,control);
    }
    belief_node *nodes=calloc(1,sizeof *nodes);
    unsigned char *next=malloc(total);
    size_t count=0,frontier=SIZE_MAX,question=SIZE_MAX;
    if(!nodes || !next)goto done;
    nodes[0].states=calloc(total,1);
    if(!nodes[0].states)goto done;
    for(size_t i=0;i<m->states;i++)nodes[0].states[i*width+c->endpoint.initial]=!!initial[i];
    count=1;
    for(size_t head=0;head<count;head++)for(size_t op=0;op<m->operations;op++) {
        if(d2k_inference_stopped(control))goto done;
        int all=1,unknown=0,terminal=0,invalid=0;
        memset(next,0,total);
        for(size_t s=0;s<total;s++) {
            if(d2k_inference_stopped(control))goto done;
            if(!nodes[head].states[s])continue;
            size_t endpoint=0;
            int allowed=c->endpoint.step(c->endpoint.ctx,s%width,op,&endpoint);
            if(allowed<0 || allowed>1 || (allowed && endpoint>=width))goto done;
            if(!allowed){invalid=1;continue;}
            d2k_transition t={0};
            int known=m->step(m->ctx,s/width,op,&t);
            if(known<0 || known>2 || (known && t.next>=m->states))goto done;
            if(!known){unknown=1;continue;}
            if(feedback) {
                int rc=feedback(feedback_context,op,t.observation,&endpoint);
                if(rc<0 || rc>1 || (rc && endpoint>=width))goto done;
                if(!rc){invalid=1;continue;}
            }
            int accept=c->accepted(c->observation_context,t.observation);
            if(accept<0 || accept>1)goto done;
            int preserved=accept?c->preserved(c->endpoint.ctx,endpoint):0;
            if(preserved<0 || preserved>1)goto done;
            all=all && accept && preserved;
            terminal|=known==2;next[t.next*width+endpoint]=1;
        }
        if(invalid)continue;
        if(unknown) {
            if(frontier==SIZE_MAX){frontier=head;question=op;}
            continue;
        }
        if(all) {
            r=belief_word(nodes,head,op,D2K_SYN_CANDIDATE);goto done;
        }
        if(terminal)continue;
        size_t at;
        for(at=0;at<count;at++) {
            if(d2k_inference_stopped(control))goto done;
            if(!memcmp(nodes[at].states,next,total))break;
        }
        if(at<count)continue;
        if(count>=SIZE_MAX/sizeof *nodes)goto done;
        unsigned char *copy=malloc(total);
        if(!copy)goto done;
        memcpy(copy,next,total);
        belief_node *grown=realloc(nodes,(count+1)*sizeof *nodes);
        if(!grown){free(copy);goto done;}
        nodes=grown;nodes[count++]=(belief_node){copy,head,op};
    }
    if(frontier!=SIZE_MAX)r=belief_word(nodes,frontier,question,D2K_SYN_EXPERIMENT);
    else r.status=D2K_SYN_CLOSED;
done:
    for(size_t i=0;i<count;i++)free(nodes[i].states);
    free(nodes);free(next);return r;
}
d2k_syn_result d2k_joint_search_belief_feedback(const d2k_transducer *m,const unsigned char *initial,
    const d2k_synthesis_contract *c,int (*feedback)(void *,size_t,uint64_t,size_t *),void *ctx) {
    return d2k_joint_search_belief_feedback_controlled(m,initial,c,feedback,ctx,NULL);
}
d2k_syn_result d2k_joint_search_belief(const d2k_transducer *m,const unsigned char *initial,
    const d2k_synthesis_contract *c)
{return d2k_joint_search_belief_feedback(m,initial,c,NULL,NULL);}
