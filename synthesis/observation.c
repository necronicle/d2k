#include "observation.h"
#include <stdlib.h>
#include <string.h>
typedef struct observed_entry {
    struct observed_entry *next;
    uint64_t id;
    d2k_observed_packet value;
    uint8_t data[];
} observed_entry;
struct d2k_observations { observed_entry *head; uint64_t count; };
d2k_observations *d2k_observations_new(void) {
    return calloc(1,sizeof(d2k_observations));
}
void d2k_observations_free(d2k_observations *d) {
    if(!d)return;
    while(d->head) { observed_entry *p=d->head;d->head=p->next;free(p); }
    free(d);
}
const d2k_observed_packet *d2k_observations_get(const d2k_observations *d,uint64_t id) {
    if(d && id)for(observed_entry *p=d->head;p;p=p->next)
        if(p->id==id)return &p->value;
    return NULL;
}
int d2k_observations_decode(void *ctx,size_t operation,const d2k_raw_observation *o,
    const d2k_raw_packet_event *e,const uint8_t *bytes,size_t n,uint64_t *id) {
    d2k_observations *d=ctx;
    (void)operation;
    if(id)*id=0;
    if(!d || !o || !e || !id || (n && !bytes))return -1;
    switch(o->kind) {
    case D2K_RAW_OBS_RESPONSE_TIMEOUT:
        if(n || e->payload_len || e->flags || e->sequence_offset ||
           e->ack_offset || e->ack_in_sent_range)return -1;
        break;
    case D2K_RAW_OBS_RESPONSE_RESET:
    case D2K_RAW_OBS_RESPONSE_BYTES:
    case D2K_RAW_OBS_RESPONSE_ACK:
    case D2K_RAW_OBS_RESPONSE_FIN:
    case D2K_RAW_OBS_RESPONSE_PACKET:
        if(e->payload_len!=n)return -1;
        break;
    default:return 0;
    }
    for(observed_entry *p=d->head;p;p=p->next) {
        const d2k_observed_packet *v=&p->value;
        if(v->kind==o->kind && v->length==n && v->packet.flags==e->flags &&
           v->packet.sequence_offset==e->sequence_offset &&
           v->packet.ack_offset==e->ack_offset &&
           v->packet.ack_in_sent_range==!!e->ack_in_sent_range &&
           (!n || !memcmp(v->bytes,bytes,n))) { *id=p->id;return 1; }
    }
    if(n>SIZE_MAX-sizeof(observed_entry) || d->count==UINT64_MAX)return -1;
    observed_entry *p=calloc(1,sizeof *p+n);
    if(!p)return -1;
    p->id=++d->count;p->value.kind=o->kind;p->value.packet=*e;
    p->value.packet.ack_in_sent_range=!!e->ack_in_sent_range;
    p->value.length=n;p->value.bytes=n?p->data:NULL;
    if(n)memcpy(p->data,bytes,n);
    p->next=d->head;d->head=p;*id=p->id;
    return 1;
}
