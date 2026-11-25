#include "stream.h"
#include "raw_tls.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static const char identity[]=D2K_RAW_TLS_IDENTITY;
static int valid(const d2k_tls_stream *s) {
    if(!s || !s->trigger || !s->trigger->len || s->trigger->len>sizeof s->trigger->payload ||
       s->trigger->len>UINT32_MAX || !s->chunks || s->chunks==SIZE_MAX || !s->chunk_bytes ||
       s->read_timeout_ms<=0 || !s->read_minimum)return 0;
    for(size_t i=0;i<s->chunks;i++)if(!s->chunk_bytes[i])return 0;
    return 1;
}
static int stream_step(void *ctx,size_t state,size_t op,size_t *next) {
    const d2k_tls_stream *s=ctx;
    if(!next || !valid(s) || state>s->trigger->len || op>s->chunks)return -1;
    if(op==s->chunks){*next=state;return 1;}
    if(state==s->trigger->len)return 0;
    size_t take=s->chunk_bytes[op],left=s->trigger->len-state;
    if(take>left)take=left;
    *next=state+take;return 1;
}
int d2k_tls_stream_operation(void *ctx,size_t state,size_t input,
    d2k_experiment_operation *op,size_t *next)
{
    const d2k_tls_stream *s=ctx;
    if(!op || !next)return -1;
    memset(op,0,sizeof *op);
    int rc=stream_step(ctx,state,input,next);
    if(rc!=1)return rc;
    if(input==s->chunks) {
        op->kind=D2K_EXPERIMENT_READ;op->minimum=s->read_minimum;op->timeout_ms=s->read_timeout_ms;
    } else {
        op->kind=D2K_EXPERIMENT_SEND_SLICE;op->trigger=s->trigger;op->program=identity;
        op->offset=(uint32_t)state;op->next_offset=(uint32_t)*next;
        op->payload_offset=state;op->payload_length=*next-state;
    }
    return 1;
}
int d2k_tls_stream_stable_operation(void *ctx,size_t state,size_t input,
    d2k_experiment_operation *op,size_t *next)
{
    const d2k_tls_stream *s=ctx;
    if(!valid(s) || input>s->chunks)return -1;
    return d2k_tls_stream_operation(ctx,state,input?input-1:s->chunks,op,next);
}
int d2k_tls_stream_prefix_equal(const void *left,size_t left_count,
    const void *right,size_t right_count)
{
    const d2k_tls_stream *a=left,*b=right;
    if(!valid(a) || !valid(b) || left_count!=a->chunks+1 || right_count!=b->chunks+1)return -1;
    if(b->chunks<a->chunks || a->trigger!=b->trigger ||
       a->read_timeout_ms!=b->read_timeout_ms || a->read_minimum!=b->read_minimum)return 0;
    return !memcmp(a->chunk_bytes,b->chunk_bytes,a->chunks*sizeof *a->chunk_bytes);
}
d2k_input_domain d2k_tls_stream_domain(const d2k_tls_stream *s) {
    if(!valid(s))return (d2k_input_domain){0};
    return (d2k_input_domain){(void *)s,s->trigger->len+1,0,s->chunks+1,stream_step};
}
int d2k_tls_stream_preserved(void *ctx,size_t state) {
    const d2k_tls_stream *s=ctx;
    if(!valid(s) || state>s->trigger->len)return -1;
    return state==s->trigger->len;
}
void d2k_stream_word_free(d2k_stream_word *w) {
    if(!w)return;
    free(w->operations);free(w->indices);free(w->pieces);memset(w,0,sizeof *w);
}
int d2k_tls_stream_resolve(const d2k_tls_stream *s,const size_t *word,size_t n,d2k_stream_word *w) {
    if(!w)return -1;
    memset(w,0,sizeof *w);
    if(!valid(s) || (n && !word) || n>SIZE_MAX/sizeof *w->operations ||
       n>SIZE_MAX/sizeof *w->indices || n>SIZE_MAX/sizeof *w->pieces)return -1;
    if(n) {
        w->operations=calloc(n,sizeof *w->operations);w->indices=malloc(n*sizeof *w->indices);
        w->pieces=malloc(n*sizeof *w->pieces);
        if(!w->operations || !w->indices || !w->pieces)goto fail;
    }
    size_t state=0;
    for(size_t i=0;i<n;i++) {
        size_t next=0;if(stream_step((void *)s,state,word[i],&next)!=1)goto fail;
        w->indices[i]=i;d2k_experiment_operation *op=&w->operations[i];
        if(word[i]==s->chunks) {
            op->kind=D2K_EXPERIMENT_READ;op->minimum=s->read_minimum;op->timeout_ms=s->read_timeout_ms;
            if(state<s->trigger->len)w->read_before_complete=1;
        } else {
            op->kind=D2K_EXPERIMENT_SEND_SLICE;op->trigger=s->trigger;op->program=identity;
            op->offset=(uint32_t)state;op->next_offset=(uint32_t)next;
            op->payload_offset=state;op->payload_length=next-state;
            w->pieces[w->piece_count++]=(d2k_payload_piece){state,next-state,0};
        }
        state=next;
    }
    w->length=n;w->complete=state==s->trigger->len;return 0;
fail:
    d2k_stream_word_free(w);return -1;
}
d2k_lower_status d2k_tls_stream_lower(const d2k_tls_stream *s,const size_t *word,size_t n,
                                     char **text,char *err,size_t cap) {
    if(text)*text=NULL;
    if(err && cap)err[0]=0;
    if(!text || !err || !cap)return D2K_LOWER_ERROR;
    d2k_stream_word w;
    if(d2k_tls_stream_resolve(s,word,n,&w)) {
        snprintf(err,cap,"cannot resolve stream word");return D2K_LOWER_ERROR;
    }
    d2k_lower_status status;
    if(!w.complete) {
        snprintf(err,cap,"stream word omits original payload bytes");status=D2K_LOWER_INVALID;
    } else if(w.read_before_complete) {
        snprintf(err,cap,"Plan cannot encode response-dependent waits between payload pieces");
        status=D2K_LOWER_UNSUPPORTED;
    } else status=d2k_lower_partition(s->trigger->len,w.pieces,w.piece_count,"tls",text,err,cap);
    d2k_stream_word_free(&w);return status;
}

static int stream_path_step(void *ctx,size_t state,size_t input,size_t *next)
{
    const d2k_tls_stream *s=ctx;
    if(!valid(s) || !next || s->chunks>SIZE_MAX-3 ||
       state>s->trigger->len+1 || input>s->chunks+2)return -1;
    size_t closed=s->trigger->len+1;
    if(input==s->chunks+1) {
        if(state!=closed)return 0;
        *next=0;return 1;
    }
    if(state==closed)return 0;
    if(input==s->chunks+2) {*next=closed;return 1;}
    return stream_step(ctx,state,input,next);
}
d2k_input_domain d2k_tls_stream_path_domain(const d2k_tls_stream *s)
{
    if(!valid(s) || s->chunks>SIZE_MAX-3)return (d2k_input_domain){0};
    return (d2k_input_domain){(void *)s,s->trigger->len+2,s->trigger->len+1,
        s->chunks+3,stream_path_step};
}
int d2k_tls_stream_path_preserved(void *ctx,size_t state)
{
    const d2k_tls_stream *s=ctx;
    if(!valid(s) || state>s->trigger->len+1)return -1;
    return state==s->trigger->len;
}
static int application_path_step(void *ctx,size_t state,size_t op,size_t *next)
{
    const d2k_tls_stream *s=ctx;
    if(!valid(s) || !next || s->chunks>SIZE_MAX-4 || state>s->trigger->len+2 ||
       op>s->chunks+3)return -1;
    if(op==s->chunks+3) {
        if(state!=s->trigger->len)return 0;
        *next=s->trigger->len+2;return 1;
    }
    if(state==s->trigger->len+2) {
        if(op!=s->chunks+1)return 0;
        *next=0;return 1;
    }
    return stream_path_step(ctx,state,op,next);
}
d2k_input_domain d2k_tls_stream_application_domain(const d2k_tls_stream *s)
{
    if(!valid(s) || s->chunks>SIZE_MAX-4)return (d2k_input_domain){0};
    return (d2k_input_domain){(void *)s,s->trigger->len+3,s->trigger->len+1,
        s->chunks+4,application_path_step};
}
int d2k_tls_stream_application_preserved(void *ctx,size_t state)
{
    const d2k_tls_stream *s=ctx;
    if(!valid(s) || state>s->trigger->len+2)return -1;
    return state==s->trigger->len+2;
}
static int stable_application_step(void *ctx,size_t state,size_t input,size_t *next)
{
    const d2k_tls_stream *s=ctx;
    if(!valid(s))return -1;
    size_t mapped=input<=s->chunks?(input?input-1:s->chunks):input;
    return application_path_step(ctx,state,mapped,next);
}
d2k_input_domain d2k_tls_stream_stable_application_domain(const d2k_tls_stream *s)
{
    d2k_input_domain d=d2k_tls_stream_application_domain(s);
    if(d.states)d.step=stable_application_step;
    return d;
}

struct d2k_stream_program {char *program;size_t total;};
d2k_stream_program *d2k_stream_prefix_new(const uint8_t *bytes,size_t length,size_t segment,unsigned mods) {
    d2k_stream_program *p=calloc(1,sizeof *p);if(!p)return NULL;
    char error[160];
    if(d2k_lower_tls_prefix(bytes,length,segment,mods,&p->program,error,sizeof error)!=D2K_LOWER_OK) {
        free(p);return NULL;
    }
    return p;
}
d2k_stream_program *d2k_stream_prefix_partition_new(const uint8_t *bytes,size_t length,
    size_t segment,unsigned mods,size_t total,const d2k_payload_piece *pieces,size_t count) {
    d2k_stream_program *p=calloc(1,sizeof *p);if(!p)return NULL;
    char error[160];
    if(d2k_lower_tls_prefix_partition(bytes,length,segment,mods,total,pieces,count,
        &p->program,error,sizeof error)!=D2K_LOWER_OK) {free(p);return NULL;}
    p->total=total;return p;
}
static d2k_lower_status compile_partition(size_t total,const d2k_payload_piece *pieces,
    size_t count,size_t sni_offset,size_t sni_length,const uint8_t *overlap,size_t overlap_length,
    d2k_stream_program **out) {
    if(!out)return D2K_LOWER_ERROR;
    *out=NULL;
    d2k_stream_program *program=calloc(1,sizeof *program);
    if(!program)return D2K_LOWER_ERROR;
    char error[160];
    d2k_lower_status status=overlap_length ?
        d2k_lower_partition_overlap_observed(total,pieces,count,"tls",sni_offset,sni_length,
            overlap,overlap_length,&program->program,error,sizeof error) :
        d2k_lower_partition_observed(total,pieces,count,"tls",sni_offset,sni_length,
            &program->program,error,sizeof error);
    if(status!=D2K_LOWER_OK) {free(program);return status;}
    program->total=total;
    *out=program;
    return status;
}
d2k_lower_status d2k_stream_partition_compile(size_t total,const d2k_payload_piece *pieces,
    size_t count,size_t sni_offset,size_t sni_length,d2k_stream_program **out) {
    return compile_partition(total,pieces,count,sni_offset,sni_length,NULL,0,out);
}
d2k_lower_status d2k_stream_partition_overlap_compile(size_t total,const d2k_payload_piece *pieces,
    size_t count,size_t sni_offset,size_t sni_length,const uint8_t *overlap,size_t overlap_length,
    d2k_stream_program **out) {
    if (!overlap || !overlap_length) return D2K_LOWER_INVALID;
    return compile_partition(total,pieces,count,sni_offset,sni_length,overlap,overlap_length,out);
}
void d2k_stream_program_free(d2k_stream_program *p){if(p){free(p->program);free(p);}}
const char *d2k_stream_program_text(const d2k_stream_program *p){return p?p->program:NULL;}
static int ordered_valid(const d2k_ordered_stream *s) {
    if(!s || !s->trigger || !s->trigger->len || s->trigger->len>D2K_TRIGGER_MAX ||
       s->trigger->len>(SIZE_MAX-4)/2 || !s->actions || !s->count ||
       s->count>SIZE_MAX-4 || s->read_timeout_ms<=0 || !s->read_minimum)return 0;
    for(size_t i=0;i<s->count;i++)
        if(!s->actions[i].bytes || (s->actions[i].reverse!=0 && s->actions[i].reverse!=1) ||
           (s->actions[i].program && (s->actions[i].reverse || s->actions[i].bytes!=s->trigger->len ||
            (s->actions[i].program->total && s->actions[i].program->total!=s->trigger->len))))return 0;
    return 1;
}
int d2k_ordered_stream_operation(void *ctx,size_t state,size_t input,
    d2k_experiment_operation *op,size_t *next) {
    const d2k_ordered_stream *s=ctx;
    if(!op || !next || !ordered_valid(s) || input>s->count)return -1;
    memset(op,0,sizeof *op);
    size_t width=s->trigger->len+1;
    if(state>=2*width || state==width)return -1;
    int reverse=state>=width;size_t used=state%width;
    if(!input) {
        op->kind=D2K_EXPERIMENT_READ;op->minimum=s->read_minimum;
        op->timeout_ms=s->read_timeout_ms;*next=state;return 1;
    }
    const d2k_stream_action *action=&s->actions[input-1];
    if(action->program) {
        if(state)return 0;
        op->kind=D2K_EXPERIMENT_SEND;op->trigger=s->trigger;
        op->program=d2k_stream_program_text(action->program);op->tls_program=action->program;
        op->next_offset=(uint32_t)s->trigger->len;*next=s->trigger->len;return 1;
    }
    if(used==s->trigger->len || (used && reverse!=action->reverse))return 0;
    size_t length=action->bytes,left=s->trigger->len-used;
    if(length>left)length=left;
    size_t offset=action->reverse?left-length:used;
    op->kind=D2K_EXPERIMENT_SEND_SLICE;op->trigger=s->trigger;op->program=identity;
    op->offset=(uint32_t)offset;op->next_offset=(uint32_t)(offset+length);
    op->payload_offset=offset;op->payload_length=length;
    *next=used+length+(action->reverse?width:0);return 1;
}
static int ordered_step(void *ctx,size_t state,size_t input,size_t *next) {
    const d2k_ordered_stream *s=ctx;
    if(!next || !ordered_valid(s) || input>s->count+3)return -1;
    size_t width=s->trigger->len+1,closed=2*width,finished=closed+1;
    if(state>finished || state==width)return -1;
    if(input==s->count+1) {
        if(state!=closed && state!=finished)return 0;
        *next=0;return 1;
    }
    if(state==closed || state==finished)return 0;
    if(input==s->count+2){*next=closed;return 1;}
    if(input==s->count+3) {
        if(state%width!=s->trigger->len)return 0;
        *next=finished;return 1;
    }
    d2k_experiment_operation op;
    return d2k_ordered_stream_operation(ctx,state,input,&op,next);
}
d2k_input_domain d2k_ordered_stream_domain(const d2k_ordered_stream *s) {
    if(!ordered_valid(s))return (d2k_input_domain){0};
    size_t closed=2*(s->trigger->len+1);
    return (d2k_input_domain){(void *)s,closed+2,closed,s->count+4,ordered_step};
}
int d2k_ordered_stream_preserved(void *ctx,size_t state) {
    const d2k_ordered_stream *s=ctx;
    if(!ordered_valid(s) || state>2*(s->trigger->len+1)+1)return -1;
    return state==2*(s->trigger->len+1)+1;
}
int d2k_ordered_stream_prefix_equal(const void *left,size_t left_count,
    const void *right,size_t right_count) {
    const d2k_ordered_stream *a=left,*b=right;
    if(!ordered_valid(a) || !ordered_valid(b) || left_count!=a->count+1 ||
       right_count!=b->count+1)return -1;
    if(a->trigger!=b->trigger || b->count<a->count ||
       a->read_timeout_ms!=b->read_timeout_ms || a->read_minimum!=b->read_minimum)return 0;
    for(size_t i=0;i<a->count;i++)if(a->actions[i].bytes!=b->actions[i].bytes ||
        a->actions[i].reverse!=b->actions[i].reverse || a->actions[i].program!=b->actions[i].program)return 0;
    return 1;
}
