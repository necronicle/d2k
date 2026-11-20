#include "state_question.h"
#include <string.h>

void d2k_state_question_free(d2k_state_question *q)
{
    if(!q) return;
    d2k_distinction_free(&q->word);
    memset(q,0,sizeof(*q));
    q->status=D2K_QUESTION_ERROR;
}

static int prefer(const d2k_distinction *candidate,const d2k_distinction *best)
{
    if(candidate->status!=D2K_DIST_WITNESS && candidate->status!=D2K_DIST_INCOMPLETE)
        return 0;
    if(!best->length) return 1;
    if(candidate->status!=best->status)
        return candidate->status==D2K_DIST_WITNESS;
    if(candidate->status==D2K_DIST_INCOMPLETE &&
       !!candidate->known_outputs!=!!best->known_outputs)
        return !!candidate->known_outputs;
    return candidate->length<best->length;
}

d2k_state_question d2k_question_after_from_controlled(const d2k_transducer *m,const unsigned char *initial,
    const d2k_sample *trace,size_t n,const d2k_input_domain *domain,const d2k_inference_control *control)
{
    d2k_state_question q={.status=D2K_QUESTION_ERROR,.left=SIZE_MAX,.right=SIZE_MAX};
    d2k_tracking tracked;
    size_t a,b;
    if(!m || (domain && (!domain->step || !domain->states ||
        domain->initial>=domain->states || domain->operations!=m->operations)))
        return q;
    tracked=d2k_track_from_controlled(m,initial,trace,n,control);
    q.prefix=tracked.prefix;
    q.possible=tracked.possible;
    if(tracked.status==D2K_TRACK_ERROR) goto done;
    if(tracked.status==D2K_TRACK_UNKNOWN) { q.status=D2K_QUESTION_UNKNOWN; goto done; }
    if(tracked.status==D2K_TRACK_CONTRADICTION) {
        q.status=D2K_QUESTION_CONTRADICTION; goto done;
    }
    if(tracked.terminal) { q.status=D2K_QUESTION_TERMINAL; goto done; }
    if(tracked.possible==1) { q.status=D2K_QUESTION_LOCATED; goto done; }
    for(a=0;a<m->states;a++) {
        if(d2k_inference_stopped(control))goto cancelled;
        if(!tracked.states[a])continue;
        for(b=a+1;b<m->states;b++) {
            if(d2k_inference_stopped(control))goto cancelled;
            if(!tracked.states[b])continue;
            d2k_transducer left=*m,right=*m;
            d2k_distinction candidate;
            left.initial=a; right.initial=b;
            candidate=d2k_distinguish_in_controlled(&left,&right,domain,control);
            if(candidate.status==D2K_DIST_ERROR) {
                d2k_distinction_free(&candidate);
                d2k_distinction_free(&q.word);
                q.left=q.right=SIZE_MAX;
                goto done;
            }
            if(prefer(&candidate,&q.word)) {
                d2k_distinction_free(&q.word);
                q.word=candidate;
                memset(&candidate,0,sizeof(candidate));
                q.left=a; q.right=b;
            }
            d2k_distinction_free(&candidate);
        }
    }
    q.status=!q.word.length ? D2K_QUESTION_INDISTINGUISHABLE:
        q.word.status==D2K_DIST_WITNESS ? D2K_QUESTION_DISTINGUISH:D2K_QUESTION_EXPLORE;
    goto done;
cancelled:
    d2k_state_question_free(&q);
done:
    d2k_tracking_free(&tracked);
    return q;
}
d2k_state_question d2k_question_after_from(const d2k_transducer *m,const unsigned char *initial,
    const d2k_sample *trace,size_t n,const d2k_input_domain *domain)
{return d2k_question_after_from_controlled(m,initial,trace,n,domain,NULL);}
d2k_state_question d2k_question_after(const d2k_transducer *m,
    const d2k_sample *trace,size_t n,const d2k_input_domain *domain)
{return d2k_question_after_from(m,NULL,trace,n,domain);}
