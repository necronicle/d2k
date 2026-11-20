#include "tracking.h"
#include <stdlib.h>
#include <string.h>

void d2k_tracking_free(d2k_tracking *r)
{
    if(!r) return;
    free(r->states);
    memset(r,0,sizeof(*r));
    r->status=D2K_TRACK_ERROR;
}

d2k_tracking d2k_track_from_controlled(const d2k_transducer *m,const unsigned char *initial,const d2k_sample *trace,size_t n,const d2k_inference_control *control)
{
    d2k_tracking r={D2K_TRACK_ERROR,0,0,NULL,0};
    unsigned char *current=NULL,*next=NULL;
    size_t i,s;
    if(d2k_inference_stopped(control))return r;
    if(!m || !m->states || !m->operations || !m->step || (n && !trace))
        return r;
    for(i=0;i<n;i++) {
        if(d2k_inference_stopped(control))return r;
        if(trace[i].operation>=m->operations ||
           trace[i].conclusive<D2K_SAMPLE_UNKNOWN ||
           trace[i].conclusive>D2K_SAMPLE_TERMINAL ||
           (trace[i].conclusive==D2K_SAMPLE_TERMINAL && i!=n-1))
            return r;
    }
    current=malloc(m->states);
    next=malloc(m->states);
    if(!current || !next) goto done;
    for(s=0;s<m->states;s++) {
        if(d2k_inference_stopped(control))goto done;
        current[s]=initial?!!initial[s]:1;r.possible+=current[s];
    }
    if(!r.possible)goto done;
    for(i=0;i<n;i++) {
        int unknown=0;
        r.prefix=i+1;
        if(trace[i].conclusive==D2K_SAMPLE_UNKNOWN) {
            r.status=D2K_TRACK_UNKNOWN;
            goto done;
        }
        memset(next,0,m->states);
        r.possible=0;
        for(s=0;s<m->states;s++) {
            if(d2k_inference_stopped(control))goto done;
            if(!current[s])continue;
            d2k_transition t={0,0};
            int rc=m->step(m->ctx,s,trace[i].operation,&t);
            if(rc==0) { unknown=1; continue; }
            if((rc!=1 && rc!=2) || t.next>=m->states) goto done;
            if(rc!=trace[i].conclusive || t.observation!=trace[i].observation)
                continue;
            if(!next[t.next]) { next[t.next]=1; r.possible++; }
        }
        if(unknown) { r.status=D2K_TRACK_UNKNOWN; goto done; }
        if(!r.possible) { r.status=D2K_TRACK_CONTRADICTION; goto done; }
        { unsigned char *swap=current; current=next; next=swap; }
    }
    r.status=D2K_TRACK_MATCH;
    r.terminal=n && trace[n-1].conclusive==D2K_SAMPLE_TERMINAL;
    r.states=current;
    current=NULL;
done:
    free(current);
    free(next);
    if(r.status!=D2K_TRACK_MATCH) r.possible=0;
    return r;
}
d2k_tracking d2k_track_from(const d2k_transducer *m,const unsigned char *initial,const d2k_sample *trace,size_t n)
{return d2k_track_from_controlled(m,initial,trace,n,NULL);}
d2k_tracking d2k_track(const d2k_transducer *m,const d2k_sample *trace,size_t n)
{return d2k_track_from(m,NULL,trace,n);}
