#include "raw_tape.h"
#include <stdlib.h>
#include <string.h>
typedef struct saved_event {
    struct saved_event *next;
    d2k_raw_tls_event event;
    uint8_t data[];
} saved_event;
struct d2k_raw_tape {
    uint64_t experience,count;
    int64_t finished;
    int invalid,closed,bound;
    saved_event *head,*tail;
    d2k_raw_tls_sink consumer;
};
static void release_events(d2k_raw_tape *t) {
    while(t->head){saved_event *next=t->head->next;free(t->head);t->head=next;}
    t->tail=NULL;
}
static int record(void *ctx,const d2k_raw_tls_event *e) {
    d2k_raw_tape *t=ctx;
    if(!t || !e)return -1;
    if(t->invalid || t->closed || e->experience!=t->experience || e->ordinal!=t->count ||
       t->count==UINT64_MAX || e->started_ms<t->finished || e->finished_ms<e->started_ms ||
       (!t->count && e->action!=D2K_RAW_TLS_OPEN) ||
       (t->count && e->action==D2K_RAW_TLS_OPEN) ||
       e->action<D2K_RAW_TLS_OPEN || e->action>D2K_RAW_TLS_CLOSE ||
       (e->length && !e->bytes))goto invalid;
    if(t->bound) {
        if(t->consumer.record(t->consumer.context,e))goto invalid;
    } else {
        size_t program=e->program?strlen(e->program)+1:0;
        if(e->length>SIZE_MAX-sizeof(saved_event) ||
           program>SIZE_MAX-sizeof(saved_event)-e->length)goto invalid;
        saved_event *s=malloc(sizeof *s+e->length+program);if(!s)goto invalid;
        s->next=NULL;s->event=*e;
        if(e->length){memcpy(s->data,e->bytes,e->length);s->event.bytes=s->data;}
        else s->event.bytes=NULL;
        if(program){memcpy(s->data+e->length,e->program,program);s->event.program=(char *)s->data+e->length;}
        if(t->tail)t->tail->next=s;else t->head=s;t->tail=s;
    }
    t->count++;t->finished=e->finished_ms;
    t->closed=e->action==D2K_RAW_TLS_CLOSE || (e->action==D2K_RAW_TLS_OPEN && e->result);
    return 0;
invalid:
    t->invalid=1;return -1;
}
d2k_raw_tape *d2k_raw_tape_new(uint64_t experience) {
    if(!experience)return NULL;
    d2k_raw_tape *t=calloc(1,sizeof *t);if(t)t->experience=experience;return t;
}
void d2k_raw_tape_free(d2k_raw_tape *t){if(t){release_events(t);free(t);}}
d2k_raw_tls_sink d2k_raw_tape_sink(d2k_raw_tape *t) {
    return t?(d2k_raw_tls_sink){t->experience,t,record}:(d2k_raw_tls_sink){0};
}
const d2k_raw_tls_event *d2k_raw_tape_event(const d2k_raw_tape *t,size_t at) {
    if(!t || t->invalid || t->bound)return NULL;
    const saved_event *s=t->head;
    while(s && at){s=s->next;at--;}
    return s?&s->event:NULL;
}
int d2k_raw_tape_bind(d2k_raw_tape *t,const d2k_raw_tls_sink *s) {
    if(!t || t->invalid || t->bound || !t->count || !s || !s->record ||
       s->experience!=t->experience || s->context==t)return -1;
    for(saved_event *e=t->head;e;e=e->next)if(s->record(s->context,&e->event)) {
        t->invalid=1;return -1;
    }
    t->consumer=*s;t->bound=1;release_events(t);return 0;
}
