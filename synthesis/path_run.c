#include "path_run.h"
#include "lower.h"
#include "stream.h"
#include "tls_decode.h"
#include "raw_tls.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct { uint64_t value; int terminal,application; } path_output;
int d2k_path_event_project(const d2k_path_event *event,size_t operations,
    int application,d2k_sample *out)
{
    if(!event || !out || !operations || (application!=0 && application!=1) ||
       operations>SIZE_MAX-2-(size_t)application)return -1;
    size_t index;
    switch(event->action.kind) {
    case D2K_PATH_ACTION_EXPERIMENT:
        index=event->action.index;
        if(index>=operations)return 0;
        break;
    case D2K_PATH_ACTION_OPEN:
        if(event->action.index)return -1;
        index=operations;break;
    case D2K_PATH_ACTION_CLOSE:
        if(event->action.index)return -1;
        index=operations+1;break;
    case D2K_PATH_ACTION_APPLICATION:
        if(event->action.index)return -1;
        if(!application)return 0;
        index=operations+2;break;
    default:return -1;
    }
    *out=event->sample;out->operation=index;return 1;
}
typedef struct saved_model {
    d2k_hypothesis *hypothesis;
    unsigned char *closed_states;
    struct saved_model *next;
} saved_model;
struct d2k_path_run {
    const d2k_experiment *experiment;
    d2k_experiment_channel *channel;
    int sealed,tls_owned;
    d2k_path_event *events;
    path_output *outputs;
    size_t count,capacity,output_count,output_capacity;
    size_t interval_begin;
    saved_model *saved,*saved_tail;
    d2k_distinction pending;
    uint64_t *pending_prefix;
    size_t pending_at,pending_count;
    d2k_path_application application;
};
static size_t path_operations(const d2k_path_run *p)
{return p->experiment->operation_count+2+!!p->application.run;}
static d2k_inference_control path_control(const d2k_path_run *p)
{
    const d2k_detect_stop *stop=p->experiment->cancel;
    return stop?(d2k_inference_control){stop->fn,stop->ctx}:(d2k_inference_control){0};
}
static void forget_question(d2k_path_run *p);
d2k_tls_io d2k_path_run_tls_io(d2k_path_run *p)
{
    if(!p || p->tls_owned || p->application.run)return (d2k_tls_io){0};
    d2k_tls_io io=d2k_experiment_tls_io(p->channel);
    if(io.context){p->tls_owned=1;p->sealed=1;forget_question(p);}
    return io;
}
static void forget_question(d2k_path_run *p)
{
    d2k_distinction_free(&p->pending);
    free(p->pending_prefix); p->pending_prefix=NULL;
    p->pending_at=0; p->pending_count=0;
}
int d2k_path_run_interrupt(d2k_path_run *p)
{
    if(!p)return -1;
    if(p->channel)return 0;
    if(p->count==p->interval_begin)return 1;
    d2k_hypothesis *h=NULL;d2k_transducer current;
    int rc=d2k_path_run_model(p,&h,&current);
    if(rc<0)return -1;
    if(rc==1) {
        saved_model *saved=malloc(sizeof *saved);
        if(!saved){d2k_hypothesis_free(h);return -1;}
        d2k_transducer model=d2k_hypothesis_model(h);
        unsigned char *closed=calloc(model.states,1);
        if(!closed){free(saved);d2k_hypothesis_free(h);return -1;}
        size_t state=model.initial;int is_closed=1;
        closed[state]=1;
        for(size_t i=p->interval_begin;i<p->count;i++) {
            d2k_transition t={0};const d2k_sample *sample=&p->events[i].sample;
            if(model.step(model.ctx,state,sample->operation,&t)!=1 ||
               t.next>=model.states || t.observation!=sample->observation) {
                free(closed);free(saved);d2k_hypothesis_free(h);return -1;
            }
            if(sample->operation==p->experiment->operation_count)is_closed=0;
            if(sample->operation==p->experiment->operation_count+1 ||
               (p->application.run && sample->operation==p->experiment->operation_count+2))is_closed=1;
            state=t.next;if(is_closed)closed[state]=1;
        }
        *saved=(saved_model){h,closed,NULL};
        if(p->saved_tail)p->saved_tail->next=saved;else p->saved=saved;
        p->saved_tail=saved;
    }
    forget_question(p);
    p->interval_begin=p->count;
    return 1;
}

static void *reserve(void *array,size_t *capacity,size_t used,size_t item)
{
    size_t n;
    void *p;
    if(used<*capacity) return array;
    if(used==SIZE_MAX || used+1>SIZE_MAX/item) return NULL;
    n=*capacity && *capacity<=SIZE_MAX/2 ? *capacity*2:16;
    if(n<=used || n>SIZE_MAX/item) n=used+1;
    p=realloc(array,n*item);
    if(!p) return NULL;
    *capacity=n; return p;
}

d2k_path_run *d2k_path_run_new(const d2k_experiment *e)
{
    d2k_path_run *p;
    if(!e || (!e->operations && !e->resolve_operation) || !e->operation_count || e->operation_count>SIZE_MAX-2)
        return NULL;
    p=calloc(1,sizeof(*p));
    if(p) p->experiment=e;
    return p;
}
d2k_path_run *d2k_path_run_new_application(const d2k_experiment *e,const d2k_path_application *app)
{
    if(!e || !e->tls_input || !e->tls_input_length || e->operation_count>SIZE_MAX-3 ||
       !app || !app->run || !app->finish)return NULL;
    d2k_path_run *p=d2k_path_run_new(e);if(p)p->application=*app;return p;
}
static int same_operation(const d2k_experiment_operation *a,const d2k_experiment_operation *b)
{
    return a->kind==b->kind && a->trigger==b->trigger &&
        a->offset==b->offset && a->next_offset==b->next_offset &&
        a->timeout_ms==b->timeout_ms && a->minimum==b->minimum &&
        a->payload_offset==b->payload_offset && a->payload_length==b->payload_length && a->tls_prefix==b->tls_prefix &&
        ((!a->program && !b->program) ||
         (a->program && b->program && !strcmp(a->program,b->program)));
}
static int extension_compatible(const d2k_experiment *a,const d2k_experiment *b)
{
    if(!a || !b || b->operation_count<=a->operation_count ||
       a->family!=b->family || memcmp(a->ip,b->ip,sizeof a->ip) ||
       a->port!=b->port || a->mark!=b->mark || a->connect_ms!=b->connect_ms ||
       a->offer_ts!=b->offer_ts || a->cancel!=b->cancel ||
       a->reply_capacity!=b->reply_capacity || a->decoder_context!=b->decoder_context ||
       a->begin_decode!=b->begin_decode || a->decode!=b->decode ||
       a->decode_packet!=b->decode_packet || a->read_to_terminal!=b->read_to_terminal ||
       a->tls_input!=b->tls_input || a->tls_input_length!=b->tls_input_length ||
       a->sink!=b->sink || a->make_sink!=b->make_sink || a->sink_context!=b->sink_context ||
       a->resolve_operation!=b->resolve_operation ||
       a->operation_prefix_equal!=b->operation_prefix_equal)return 0;
    if(a->resolve_operation) {
        if(a->operation_context==b->operation_context)return 1;
        return a->operation_prefix_equal &&
            a->operation_prefix_equal(a->operation_context,a->operation_count,
                b->operation_context,b->operation_count)==1;
    }
    if(a->operation_context!=b->operation_context)return 0;
    if(!a->operations || !b->operations)return 0;
    for(size_t i=0;i<a->operation_count;i++)
        if(!same_operation(&a->operations[i],&b->operations[i]))return 0;
    return 1;
}
d2k_path_run *d2k_path_run_extend(const d2k_path_run *p,const d2k_experiment *e)
{
    if(!p || p->channel || p->tls_owned || !extension_compatible(p->experiment,e))return NULL;
    d2k_path_run *q=p->application.run?d2k_path_run_new_application(e,&p->application):d2k_path_run_new(e);
    if(!q)return NULL;
    if(p->count>SIZE_MAX/sizeof *q->events || p->output_count>SIZE_MAX/sizeof *q->outputs)goto failed;
    if(p->count) {
        q->events=malloc(p->count*sizeof *q->events);
        if(!q->events)goto failed;
        q->capacity=p->count;
    }
    if(p->output_count) {
        q->outputs=malloc(p->output_count*sizeof *q->outputs);
        if(!q->outputs)goto failed;
        memcpy(q->outputs,p->outputs,p->output_count*sizeof *q->outputs);
        q->output_count=q->output_capacity=p->output_count;
    }
    for(size_t i=0;i<p->count;i++) {
        if(i && p->events[i].interval_start && d2k_path_run_interrupt(q)!=1)goto failed;
        q->events[i]=p->events[i];
        if(d2k_path_event_project(&p->events[i],e->operation_count,!!p->application.run,
            &q->events[i].sample)!=1)goto failed;
        q->count++;
    }
    if(p->count && p->interval_begin==p->count && d2k_path_run_interrupt(q)!=1)goto failed;
    if(q->interval_begin!=p->interval_begin)goto failed;
    return q;
failed:
    d2k_path_run_free(q);return NULL;
}
void d2k_path_run_free(d2k_path_run *p)
{
    if(!p) return;
    d2k_experiment_close(p->channel);
    forget_question(p);
    while(p->saved) {
        saved_model *next=p->saved->next;
        d2k_hypothesis_free(p->saved->hypothesis);free(p->saved->closed_states);
        free(p->saved);p->saved=next;
    }
    free(p->events); free(p->outputs); free(p);
}
const d2k_path_event *d2k_path_run_history(const d2k_path_run *p,size_t *n)
{
    if(n) *n=p?p->count:0;
    return p?p->events:NULL;
}
int d2k_path_run_output(const d2k_path_run *p,uint64_t id,uint64_t *value,int *terminal)
{
    if(!p || id>=p->output_count || !value || !terminal) return 0;
    *value=p->outputs[id].value; *terminal=p->outputs[id].terminal;
    return 1;
}
static d2k_sample *path_trace(const d2k_path_run *p)
{
    d2k_sample *trace;
    size_t count=p->count-p->interval_begin;
    if(count>SIZE_MAX/sizeof(*trace)) return NULL;
    trace=malloc((count?count:1)*sizeof(*trace));
    if(trace) for(size_t i=p->interval_begin;i<p->count;i++) {
        if(d2k_path_event_project(&p->events[i],p->experiment->operation_count,
            !!p->application.run,&trace[i-p->interval_begin])!=1) {
            free(trace);return NULL;
        }
    }
    return trace;
}
d2k_alternatives d2k_path_run_alternatives(const d2k_path_run *p,const d2k_input_domain *domain)
{
    d2k_alternatives q={.status=D2K_ALTERNATIVES_ERROR};
    d2k_sample *trace;
    if(!p || p->tls_owned) return q;
    trace=path_trace(p);
    if(!trace) return q;
    d2k_inference_control control={0};
    if(p->experiment->cancel){control.cancelled=p->experiment->cancel->fn;control.context=p->experiment->cancel->ctx;}
    q=d2k_continuous_alternatives_controlled(trace,p->count-p->interval_begin,path_operations(p),domain,&control);
    free(trace);
    return q;
}
int d2k_path_run_model(const d2k_path_run *p,d2k_hypothesis **h,d2k_transducer *current)
{
    d2k_sample *trace=NULL;
    int rc;
    if(h) *h=NULL;
    if(current) memset(current,0,sizeof(*current));
    if(!p || p->tls_owned || !h || !current || p->count>SIZE_MAX/sizeof(*trace)) return -1;
    trace=path_trace(p);
    if(!trace) return -1;
    d2k_inference_control control={0};
    if(p->experiment->cancel){control.cancelled=p->experiment->cancel->fn;control.context=p->experiment->cancel->ctx;}
    rc=d2k_continuous_build_controlled(trace,p->count-p->interval_begin,path_operations(p),h,current,&control);
    free(trace);
    return rc;
}
d2k_state_question d2k_path_run_relocate(const d2k_path_run *p,const d2k_input_domain *domain)
{
    d2k_state_question best={.status=D2K_QUESTION_UNKNOWN};
    if(!p || p->tls_owned) {best.status=D2K_QUESTION_ERROR;return best;}
    if(!p->interval_begin)return best;
    d2k_sample *recent=path_trace(p);
    if(!recent) {best.status=D2K_QUESTION_ERROR;return best;}
    d2k_inference_control control={0};
    if(p->experiment->cancel) {
        control.cancelled=p->experiment->cancel->fn;
        control.context=p->experiment->cancel->ctx;
    }
    for(const saved_model *saved=p->saved;saved;saved=saved->next) {
            d2k_transducer m=d2k_hypothesis_model(saved->hypothesis);
            d2k_state_question q=d2k_question_after_from_controlled(&m,saved->closed_states,
                recent,p->count-p->interval_begin,domain,&control);
            if(q.status==D2K_QUESTION_ERROR) {d2k_state_question_free(&q);goto error;}
            int useful=q.status==D2K_QUESTION_DISTINGUISH || q.status==D2K_QUESTION_EXPLORE;
            int better=!best.word.length ||
                (q.status==D2K_QUESTION_DISTINGUISH && best.status!=D2K_QUESTION_DISTINGUISH) ||
                (q.status==best.status && q.word.length<best.word.length);
            if(useful && q.word.length && better) {
                d2k_state_question_free(&best);best=q;memset(&q,0,sizeof q);
            }
            d2k_state_question_free(&q);
    }
    free(recent);return best;
error:
    free(recent);d2k_state_question_free(&best);return best;
}
int d2k_path_run_step(d2k_path_run *p,size_t op,char *err,size_t cap)
{
    d2k_path_event event={0};
    d2k_sample sample={0};
    size_t count=0,i,open;
    void *storage;
    int known=0,terminal=0,application=0;
    if(err && cap) err[0]=0;
    if(!p || p->tls_owned || !err || !cap) return -1;
    open=p->experiment->operation_count;
    application=p->application.run && op==open+2;
    if(op>=path_operations(p) || (op==open && p->channel) ||
       (op!=open && !p->channel) || (op<open && p->sealed)) {
        snprintf(err,cap,"invalid path lifecycle action"); return -1;
    }
    /* Reserve before side effects so no executed event is lost on allocation failure. */
    storage=reserve(p->events,&p->capacity,p->count,sizeof(*p->events));
    if(!storage) goto allocation_failed;
    p->events=storage;
    storage=reserve(p->outputs,&p->output_capacity,p->output_count,sizeof(*p->outputs));
    if(!storage) goto allocation_failed;
    p->outputs=storage;
    event.sample.operation=op;
    event.action.kind=op<open?D2K_PATH_ACTION_EXPERIMENT:
        op==open?D2K_PATH_ACTION_OPEN:
        application?D2K_PATH_ACTION_APPLICATION:D2K_PATH_ACTION_CLOSE;
    event.action.index=op<open?op:0;
    event.started_ms=d2k_now_ms();
    if(op==open) {
        p->channel=d2k_experiment_open(p->experiment,&event.raw,err,cap);
        known=p->channel!=NULL;
        p->sealed=0;
    } else if(op==open+1) {
        d2k_experiment_close(p->channel); p->channel=NULL;
        p->sealed=0; known=1;
    } else if(application) {
        int prepared=!p->application.prepare || !p->application.prepare(p->application.context,p);
        d2k_tls_io io=prepared?d2k_experiment_tls_io(p->channel):(d2k_tls_io){0};
        p->tls_owned=1;
        int ran=io.context?p->application.run(p->application.context,&io):-1;
        d2k_experiment_close(p->channel);p->channel=NULL;p->sealed=0;
        int finished=p->application.finish(p->application.context,&sample.observation);
        p->tls_owned=0;known=ran==0 && finished==1;
        if(!known)snprintf(err,cap,"application continuation lacks conclusive owned evidence");
    } else {
        d2k_experiment_status rc=d2k_experiment_continue(p->channel,&op,1,
            &sample,&count,&event.raw,err,cap);
        event.operation_available=d2k_experiment_last_operation(p->channel,&event.operation);
        known=count==1 && (rc==D2K_EXPERIMENT_COMPLETE || rc==D2K_EXPERIMENT_TERMINAL);
        terminal=known && sample.conclusive==D2K_SAMPLE_TERMINAL;
        if(rc!=D2K_EXPERIMENT_COMPLETE) p->sealed=1;
    }
    event.finished_ms=d2k_now_ms();
    if(known) {
        for(i=0;i<p->output_count;i++)
            if(p->outputs[i].value==sample.observation && p->outputs[i].terminal==terminal &&
               p->outputs[i].application==application) break;
        if(i==p->output_count) {
            p->outputs[i]=(path_output){sample.observation,terminal,application};
            p->output_count++;
        }
        event.sample.observation=i;
        event.sample.conclusive=D2K_SAMPLE_OBSERVED;
    }
    event.interval_start=p->count==p->interval_begin;
    p->events[p->count++]=event;
    return known;
allocation_failed:
    snprintf(err,cap,"path history allocation failed"); return -1;
}

typedef struct {
    const d2k_input_domain *protocol;
    size_t open;
    int application;
} path_domain;
static int path_domain_step(void *ctx,size_t state,size_t op,size_t *next)
{
    path_domain *d=ctx;
    size_t connection=state%3,protocol_next=0,connection_next=connection;
    int rc;
    if(op==d->open) {
        if(connection!=0) return 0;
        connection_next=1;
    } else if(op==d->open+1 || (d->application && op==d->open+2)) {
        if(connection==0) return 0;
        connection_next=0;
    } else {
        if(op>d->open || connection!=1) return 0;
    }
    rc=d->protocol->step(d->protocol->ctx,state/3,op,&protocol_next);
    if(rc<0 || rc>1 || (rc && protocol_next>=d->protocol->states)) return -1;
    if(!rc) return 0;
    *next=protocol_next*3+connection_next;
    return 1;
}
d2k_path_progress d2k_path_run_advance(d2k_path_run *p,const d2k_input_domain *protocol,
    size_t *chosen,char *err,size_t cap)
{
    d2k_alternatives alternatives;
    d2k_distinction question={0};
    uint64_t *prefix=NULL;
    d2k_hypothesis *h=NULL;
    d2k_transducer current;
    int rc;
    size_t op,next;
    if(chosen) *chosen=SIZE_MAX;
    if(err && cap) err[0]=0;
    if(!p || p->tls_owned || !protocol || !chosen || !err || !cap || !protocol->step ||
       !protocol->states || protocol->states>SIZE_MAX/3 ||
       protocol->initial>=protocol->states ||
       protocol->operations!=path_operations(p)) return D2K_PATH_ERROR;
    path_domain context={protocol,p->experiment->operation_count,!!p->application.run};
    d2k_input_domain domain={&context,protocol->states*3,
        protocol->initial*3+(p->channel?(p->sealed?2:1):0),protocol->operations,path_domain_step};
    if(p->pending.length && p->pending_count!=p->count) forget_question(p);
    if(p->pending.length) {
        op=p->pending.operations[p->pending_at];
        rc=path_domain_step(&context,domain.initial,op,&next);
        if(rc==1) goto execute;
        forget_question(p);
        if(rc<0) return D2K_PATH_ERROR;
    }
    d2k_state_question past=d2k_path_run_relocate(p,&domain);
    if(past.status==D2K_QUESTION_ERROR) {
        d2k_state_question_free(&past);return D2K_PATH_ERROR;
    }
    if(past.word.length) {
        op=past.word.operations[0];
        d2k_state_question_free(&past);
        rc=path_domain_step(&context,domain.initial,op,&next);
        if(rc!=1)return D2K_PATH_ERROR;
        *chosen=op;
        rc=d2k_path_run_step(p,op,err,cap);
        return rc==1?D2K_PATH_ADVANCED:rc==0?D2K_PATH_UNCERTAIN:D2K_PATH_ERROR;
    }
    d2k_state_question_free(&past);
    alternatives=d2k_path_run_alternatives(p,&domain);
    if(alternatives.status==D2K_ALTERNATIVES_UNKNOWN) {
        d2k_alternatives_free(&alternatives); return D2K_PATH_UNCERTAIN;
    }
    if(alternatives.status==D2K_ALTERNATIVES_ERROR) {
        d2k_alternatives_free(&alternatives); return D2K_PATH_ERROR;
    }
    if(alternatives.status==D2K_ALTERNATIVES_QUESTION) {
        question=alternatives.word;
        memset(&alternatives.word,0,sizeof(alternatives.word));
        prefix=alternatives.prefix_observations;
        alternatives.prefix_observations=NULL;
    }
    d2k_alternatives_free(&alternatives);
    if(!question.length) {
        rc=d2k_path_run_model(p,&h,&current);
        if(rc!=1) return rc==0?D2K_PATH_UNCERTAIN:D2K_PATH_ERROR;
        d2k_inference_control control={0};
        if(p->experiment->cancel) {
            control.cancelled=p->experiment->cancel->fn;
            control.context=p->experiment->cancel->ctx;
        }
        question=d2k_continuous_question_controlled(&current,&domain,&control);
        if(question.length && d2k_question_prefix(&current,question.operations,
            question.length,&prefix)!=1) {
            d2k_distinction_free(&question);d2k_hypothesis_free(h);
            return D2K_PATH_ERROR;
        }
        d2k_hypothesis_free(h);
        if(question.status==D2K_DIST_ERROR) {
            d2k_distinction_free(&question); return D2K_PATH_ERROR;
        }
    }
    if(!question.length) {
        free(prefix);
        d2k_distinction_free(&question); return D2K_PATH_NO_QUESTION;
    }
    op=question.operations[0];
    if(path_domain_step(&context,domain.initial,op,&next)!=1) {
        free(prefix);d2k_distinction_free(&question);return D2K_PATH_ERROR;
    }
    p->pending=question; p->pending_prefix=prefix;
    p->pending_at=0; p->pending_count=p->count;
execute:
    *chosen=op;
    rc=d2k_path_run_step(p,op,err,cap);
    if(rc!=1 || p->pending_at+1==p->pending.length ||
       p->events[p->count-1].sample.observation!=p->pending_prefix[p->pending_at]) {
        forget_question(p);
    } else {
        p->pending_at++; p->pending_count=p->count;
    }
    return rc==1?D2K_PATH_ADVANCED:rc==0?D2K_PATH_UNCERTAIN:D2K_PATH_ERROR;
}

typedef struct {
    path_domain domain;
    const d2k_path_run *path;
    const d2k_synthesis_contract *contract;
} path_goal;
static int goal_domain_step(void *ctx,size_t state,size_t op,size_t *next)
{ return path_domain_step(&((path_goal *)ctx)->domain,state,op,next); }
static int goal_preserved(void *ctx,size_t state)
{
    path_goal *g=ctx;
    return g->contract->preserved(g->contract->endpoint.ctx,state/3);
}
static int goal_accepted(void *ctx,uint64_t id)
{
    path_goal *g=ctx;
    uint64_t output;int terminal;
    if(!d2k_path_run_output(g->path,id,&output,&terminal)) return -1;
    if(g->path->application.run && !g->path->outputs[id].application)return 0;
    return g->contract->accepted(g->contract->observation_context,output);
}
static int goal_feedback(void *ctx,size_t op,uint64_t id,size_t *state)
{
    path_goal *g=ctx;
    uint64_t output;int terminal;
    if(!d2k_path_run_output(g->path,id,&output,&terminal)) return -1;
    if(g->domain.application && op==g->domain.open+2)
        return !terminal && g->path->outputs[id].application?1:-1;
    if(op>=g->domain.open) return terminal || output!=0?-1:1;
    if(terminal) *state=(*state/3)*3+2;
    return 1;
}
int d2k_path_run_synthesize(const d2k_path_run *p,const d2k_synthesis_contract *contract,
    d2k_syn_result *out)
{
    d2k_hypothesis *h=NULL;
    d2k_transducer current;
    int rc;
    if(out) *out=(d2k_syn_result){.status=D2K_SYN_ERROR};
    if(!p || p->tls_owned || !contract || !out || !contract->preserved || !contract->accepted ||
       !contract->endpoint.step || !contract->endpoint.states ||
       contract->endpoint.states>SIZE_MAX/3 ||
       contract->endpoint.initial>=contract->endpoint.states ||
       contract->endpoint.operations!=path_operations(p)) return -1;
    rc=d2k_path_run_model(p,&h,&current);
    if(rc!=1) return rc;
    path_goal goal={{&contract->endpoint,p->experiment->operation_count,!!p->application.run},p,contract};
    d2k_synthesis_contract combined={
        {&goal,contract->endpoint.states*3,
         contract->endpoint.initial*3+(p->channel?(p->sealed?2:1):0),
         contract->endpoint.operations,goal_domain_step},
        goal_preserved,&goal,goal_accepted};
    d2k_inference_control control=path_control(p);
    *out=d2k_joint_search_feedback_controlled(&current,&combined,goal_feedback,&goal,&control);
    d2k_hypothesis_free(h);
    return out->status==D2K_SYN_ERROR?-1:1;
}

d2k_path_trial d2k_path_run_trial_belief(d2k_path_run *p,const d2k_transducer *model,
    const unsigned char *initial,const d2k_synthesis_contract *contract,char *err,size_t cap)
{
    d2k_path_trial trial={.status=D2K_TRIAL_ERROR,.selection=D2K_SYN_ERROR};
    d2k_syn_result word={.status=D2K_SYN_ERROR};
    unsigned char *states=NULL,*following=NULL;
    size_t domain_state;
    int rc;
    if(err && cap) err[0]=0;
    if(!p || p->tls_owned || !err || !cap || !model || !initial || !model->states || !model->step ||
       !contract || !contract->preserved || !contract->accepted ||
       !contract->endpoint.step || !contract->endpoint.states ||
       contract->endpoint.states>SIZE_MAX/3 ||
       contract->endpoint.initial>=contract->endpoint.states ||
       contract->endpoint.operations!=path_operations(p) ||
       model->operations!=contract->endpoint.operations)return trial;
    trial.begin=trial.end=p->count;
    domain_state=contract->endpoint.initial*3+(p->channel?(p->sealed?2:1):0);
    path_goal goal={{&contract->endpoint,p->experiment->operation_count,!!p->application.run},p,contract};
    d2k_synthesis_contract combined={
        {&goal,contract->endpoint.states*3,domain_state,contract->endpoint.operations,goal_domain_step},
        goal_preserved,&goal,goal_accepted};
    d2k_inference_control control=path_control(p);
    word=d2k_joint_search_belief_feedback_controlled(model,initial,&combined,goal_feedback,&goal,&control);
    if(word.status==D2K_SYN_ERROR)goto done;
    trial.selection=word.status;
    if(word.status==D2K_SYN_CLOSED || !word.length) {
        trial.status=D2K_TRIAL_NO_PATH; goto done;
    }
    if(word.status!=D2K_SYN_CANDIDATE && word.status!=D2K_SYN_EXPERIMENT) goto done;
    states=malloc(model->states);following=malloc(model->states);
    if(!states || !following)goto done;
    memcpy(states,initial,model->states);
    forget_question(p);
    for(size_t i=0;i<word.length;i++) {
        size_t op=word.operations[i],next;
        int unknown=0,matched=0;
        for(size_t s=0;s<model->states;s++)if(states[s]) {
            d2k_transition t={0};int known=model->step(model->ctx,s,op,&t);
            if(known<0 || known>2 || (known && t.next>=model->states))goto done;
            if(!known)unknown=1;
        }
        if(path_domain_step(&goal.domain,domain_state,op,&next)!=1) goto done;
        rc=d2k_path_run_step(p,op,err,cap);
        trial.end=p->count;
        if(rc!=1) { if(!rc) trial.status=D2K_TRIAL_UNCERTAIN; goto done; }
        uint64_t observed=p->events[p->count-1].sample.observation;
        memset(following,0,model->states);
        for(size_t s=0;s<model->states;s++)if(states[s]) {
            d2k_transition t={0};int known=model->step(model->ctx,s,op,&t);
            if(known==D2K_SAMPLE_OBSERVED && t.observation==observed) {
                following[t.next]=1;matched=1;
            }
        }
        trial.prediction_changed=!matched && !unknown;
        if(goal_feedback(&goal,op,observed,&next)!=1) goto done;
        int accepted=goal_accepted(&goal,observed);
        if(accepted<0 || accepted>1) goto done;
        if(accepted) {
            int preserved=goal_preserved(&goal,next);
            if(preserved<0 || preserved>1) goto done;
            if(preserved) { trial.status=D2K_TRIAL_OBSERVED_PREDICATE; goto done; }
        }
        if(trial.prediction_changed) { trial.status=D2K_TRIAL_COUNTEREXAMPLE; goto done; }
        if(unknown) {
            trial.status=D2K_TRIAL_MEASURED; goto done;
        }
        unsigned char *swap=states;states=following;following=swap;
        domain_state=next;
    }
    trial.status=D2K_TRIAL_MEASURED;
done:
    free(states);free(following);d2k_syn_result_free(&word);
    return trial;
}
static int saved_candidate(const d2k_path_run *p,const d2k_synthesis_contract *contract,
    d2k_transducer *out,unsigned char **states)
{
    *out=(d2k_transducer){0};*states=NULL;
    if(!p->interval_begin)return 0;
    if(!contract || !contract->endpoint.states || contract->endpoint.states>SIZE_MAX/3 ||
       contract->endpoint.initial>=contract->endpoint.states || !contract->endpoint.step ||
       !contract->accepted || !contract->preserved ||
       contract->endpoint.operations!=path_operations(p))return -1;
    d2k_sample *recent=path_trace(p);
    if(!recent)return -1;
    path_goal goal={{&contract->endpoint,p->experiment->operation_count,!!p->application.run},p,contract};
    d2k_synthesis_contract combined={
        {&goal,contract->endpoint.states*3,
         contract->endpoint.initial*3+(p->channel?(p->sealed?2:1):0),
         contract->endpoint.operations,goal_domain_step},goal_preserved,&goal,goal_accepted};
    for(const saved_model *saved=p->saved;saved;saved=saved->next) {
            d2k_transducer model=d2k_hypothesis_model(saved->hypothesis);
            d2k_tracking track=d2k_track_from(&model,saved->closed_states,recent,p->count-p->interval_begin);
            int error=track.status==D2K_TRACK_ERROR;
            if(track.status==D2K_TRACK_MATCH && !track.terminal) {
                d2k_inference_control control=path_control(p);
                d2k_syn_result word=d2k_joint_search_belief_feedback_controlled(&model,track.states,
                    &combined,goal_feedback,&goal,&control);
                int candidate=word.status==D2K_SYN_CANDIDATE;
                error=word.status==D2K_SYN_ERROR;
                d2k_syn_result_free(&word);
                if(candidate) {
                    *out=model;*states=track.states;track.states=NULL;
                    d2k_tracking_free(&track);free(recent);return 1;
                }
            }
            d2k_tracking_free(&track);
            if(error){free(recent);return -1;}
    }
    free(recent);return 0;
}
d2k_path_trial d2k_path_run_trial(d2k_path_run *p,const d2k_synthesis_contract *contract,
    char *err,size_t cap)
{
    d2k_path_trial trial={.status=D2K_TRIAL_ERROR,.selection=D2K_SYN_ERROR};
    d2k_hypothesis *h=NULL;d2k_transducer model;
    if(err && cap)err[0]=0;
    if(!p || p->tls_owned || !err || !cap)return trial;
    trial.begin=trial.end=p->count;
    unsigned char *saved_states=NULL;
    int saved=saved_candidate(p,contract,&model,&saved_states);
    if(saved<0)return trial;
    if(saved) {
        trial=d2k_path_run_trial_belief(p,&model,saved_states,contract,err,cap);
        trial.reused_model=1;
        free(saved_states);return trial;
    }
    int rc=d2k_path_run_model(p,&h,&model);
    if(rc!=1){if(!rc)trial.status=D2K_TRIAL_UNCERTAIN;return trial;}
    unsigned char *initial=calloc(model.states,1);
    if(initial) {
        initial[model.initial]=1;
        trial=d2k_path_run_trial_belief(p,&model,initial,contract,err,cap);
    }
    free(initial);d2k_hypothesis_free(h);return trial;
}

static int tls_input_program(const d2k_path_run *p,const d2k_trigger *trigger,
    uint64_t generation,d2k_vres *out,int require_hello)
{
    static const char identity[]=D2K_RAW_TLS_IDENTITY;
    size_t start,n=0,total=0;
    int saw_read=0,saw_hello=0,rc=0;
    d2k_payload_piece *pieces=NULL;
    char *text=NULL,err[200]={0};
    const char *prefix_program=NULL;
    if(!out)return -1;
    memset(out,0,sizeof *out);out->verdict=D2K_V_INCONCLUSIVE;out->owns_search=1;
    if(!p || p->tls_owned || !trigger || !trigger->len || trigger->len>sizeof trigger->payload || !generation)
        return -1;
    snprintf(out->reason,sizeof out->reason,"синтез: нет полного переносимого опыта TLS");
    const d2k_experiment *e=p->experiment;
    if(!p->channel || !p->count || e->decode!=d2k_tls_decoder_read ||
       e->begin_decode!=d2k_tls_decoder_begin || e->decode_packet)return 0;
    start=p->count;
    while(start && p->events[start-1].sample.operation!=e->operation_count)start--;
    if(!start)return 0;
    start--;
    if(p->count-start>SIZE_MAX/sizeof *pieces)return -1;
    pieces=calloc(p->count-start,sizeof *pieces);
    if(!pieces)return -1;
    for(size_t i=start;i<p->count;i++) {
        const d2k_sample *sample=&p->events[i].sample;
        if(sample->conclusive!=D2K_SAMPLE_OBSERVED)goto done;
        if(i==start)continue;
        if(sample->operation>=e->operation_count)goto done;
        if(!p->events[i].operation_available)goto done;
        const d2k_experiment_operation *op=&p->events[i].operation;
        if(op->kind==D2K_EXPERIMENT_SEND) {
            const char *compiled=d2k_stream_prefix_program(op->tls_prefix);
            if(saw_read || n || total || op->trigger!=trigger || op->offset ||
               op->next_offset!=trigger->len || !compiled || !op->program ||
               strcmp(compiled,op->program))goto done;
            prefix_program=compiled;n=1;total=trigger->len;
        } else if(op->kind==D2K_EXPERIMENT_SEND_SLICE) {
            if(saw_read || op->trigger!=trigger || !op->program || strcmp(op->program,identity) ||
               !op->payload_length || op->payload_offset>trigger->len ||
               op->payload_length>trigger->len-op->payload_offset ||
               op->offset!=op->payload_offset ||
               op->next_offset!=op->payload_offset+op->payload_length ||
               total>trigger->len-op->payload_length)goto done;
            pieces[n++]=(d2k_payload_piece){op->payload_offset,op->payload_length,0};
            total+=op->payload_length;
        } else if(op->kind==D2K_EXPERIMENT_READ) {
            uint64_t value;int terminal,timeout,reset;
            d2k_tls_response response;
            saw_read=1;
            if(total!=trigger->len || !d2k_path_run_output(p,sample->observation,&value,&terminal) ||
               d2k_tls_symbol_read(value,&response,&timeout,&reset)<0)goto done;
            if(response.kind==D2K_TLS_OBS_HELLO && !response.retry && !timeout && !reset && !d2k_tls_symbol_closed(value))
                saw_hello=1;
        } else goto done;
    }
    if((require_hello && !saw_hello) || total!=trigger->len)goto done;
    if(prefix_program) {
        size_t length=strlen(prefix_program);
        text=malloc(length+1);if(!text){rc=-1;goto done;}
        memcpy(text,prefix_program,length+1);
    } else {
        d2k_lower_status lowered=d2k_lower_partition(trigger->len,pieces,n,"tls",&text,err,sizeof err);
        if(lowered!=D2K_LOWER_OK) {
            snprintf(out->reason,sizeof out->reason,"синтез: опыт не выражен программой: %.160s",err);
            rc=lowered==D2K_LOWER_ERROR?-1:0;goto done;
        }
    }
    size_t len=strlen(text);

    if(len>=sizeof out->program) {
        snprintf(out->reason,sizeof out->reason,"синтез: программа не помещается в передачу контроллеру");
        goto done;
    }
    memcpy(out->program,text,len+1);out->program_len=len;out->synthesis_generation=generation;
    snprintf(out->reason,sizeof out->reason,"%s",require_hello?
        "синтез: измерен TLS-префикс; требуется испытание приложения":
        "скомпилирован полный измерительный вход; результат приложения ещё неизвестен");
    rc=1;
done:
    free(text);free(pieces);return rc;
}
int d2k_path_run_tls_candidate(const d2k_path_run *p,const d2k_trigger *t,uint64_t g,d2k_vres *out)
{return tls_input_program(p,t,g,out,1);}
int d2k_path_run_tls_input_program(const d2k_path_run *p,const d2k_trigger *t,uint64_t g,d2k_vres *out)
{return tls_input_program(p,t,g,out,0);}
