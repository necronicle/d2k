#include "continuous.h"
#include <string.h>
#include <stdlib.h>

int d2k_continuous_build_controlled(const d2k_sample *trace,size_t n,size_t operations,
    d2k_hypothesis **out,d2k_transducer *current,const d2k_inference_control *control)
{
    static const char anchor[]="single chronological origin/v1";
    d2k_evidence *e;
    d2k_hypothesis *h=NULL;
    d2k_transducer m;
    size_t i,state;
    int unknown=0,rc;
    if(out) *out=NULL;
    if(current) memset(current,0,sizeof(*current));
    if(d2k_inference_stopped(control))return -1;
    if(!out || !current || !operations || (n && !trace)) return -1;
    for(i=0;i<n;i++) {
        if(trace[i].operation>=operations ||
           (trace[i].conclusive!=D2K_SAMPLE_UNKNOWN && trace[i].conclusive!=D2K_SAMPLE_OBSERVED))
            return -1;
        if(trace[i].conclusive==D2K_SAMPLE_UNKNOWN) unknown=1;
    }
    if(unknown) return 0;
    e=d2k_evidence_new(anchor,sizeof(anchor),operations);
    if(!e) return -1;
    rc=d2k_evidence_add(e,anchor,sizeof(anchor),trace,n)==D2K_EVIDENCE_OK
        ?d2k_evidence_generalize_controlled(e,&h,control):-1;
    d2k_evidence_free(e);
    if(rc!=1) { d2k_hypothesis_free(h); return -1; }
    m=d2k_hypothesis_model(h); state=m.initial;
    for(i=0;i<n;i++) {
        d2k_transition t;
        if(m.step(m.ctx,state,trace[i].operation,&t)!=1 || t.next>=m.states ||
           t.observation!=trace[i].observation) {
            d2k_hypothesis_free(h); return -1;
        }
        state=t.next;
    }
    m.initial=state; *current=m; *out=h;
    return 1;
}
d2k_distinction d2k_continuous_question_controlled(const d2k_transducer *current,
    const d2k_input_domain *domain,const d2k_inference_control *control)
{
    d2k_distinction q={.status=D2K_DIST_ERROR};
    size_t ds=domain?domain->states:1,count,start,head=0,tail=0;
    size_t *parent=NULL,*via=NULL,*queue=NULL;
    if(d2k_inference_stopped(control)) return q;
    if(!current || !current->step || !current->states || !current->operations ||
       current->initial>=current->states || !ds ||
       (domain && (!domain->step || domain->initial>=ds ||
                   domain->operations!=current->operations)) ||
       current->states>SIZE_MAX/ds) return q;
    count=current->states*ds;
    if(count>SIZE_MAX/sizeof(size_t)) return q;
    parent=malloc(count*sizeof(*parent));
    via=malloc(count*sizeof(*via));
    queue=malloc(count*sizeof(*queue));
    if(!parent || !via || !queue) goto done;
    for(size_t i=0;i<count;i++) {
        if(d2k_inference_stopped(control)) goto done;
        parent[i]=SIZE_MAX;
    }
    start=current->initial*ds+(domain?domain->initial:0);
    parent[start]=start; queue[tail++]=start;
    while(head<tail) {
        size_t state=queue[head++];
        for(size_t op=0;op<current->operations;op++) {
            if(d2k_inference_stopped(control)) goto done;
            size_t dn=0;
            d2k_transition t={0};
            int rc;
            if(domain) {
                rc=domain->step(domain->ctx,state%ds,op,&dn);
                if(rc<0 || rc>1 || (rc && dn>=ds)) goto done;
                if(!rc) continue;
            }
            rc=current->step(current->ctx,state/ds,op,&t);
            if(rc<0 || rc>2 || (rc && t.next>=current->states)) goto done;
            if(!rc) {
                size_t n=1,pos;
                for(size_t p=state;p!=start;p=parent[p]) n++;
                if(n>SIZE_MAX/sizeof(*q.operations)) goto done;
                q.operations=malloc(n*sizeof(*q.operations));
                if(!q.operations) goto done;
                q.length=n; pos=n; q.operations[--pos]=op;
                for(size_t p=state;p!=start;p=parent[p]) q.operations[--pos]=via[p];
                q.status=D2K_DIST_INCOMPLETE;
                goto done;
            }
            if(rc==2) continue;
            size_t next=t.next*ds+dn;
            if(parent[next]==SIZE_MAX) {
                parent[next]=state; via[next]=op; queue[tail++]=next;
            }
        }
    }
    q.status=D2K_DIST_EQUIVALENT;
done:
    free(parent); free(via); free(queue);
    return q;
}

d2k_distinction d2k_continuous_question(const d2k_transducer *current,
    const d2k_input_domain *domain)
{
    return d2k_continuous_question_controlled(current,domain,NULL);
}

int d2k_continuous_build(const d2k_sample *t,size_t n,size_t ops,d2k_hypothesis **h,d2k_transducer *m) { return d2k_continuous_build_controlled(t,n,ops,h,m,NULL); }
