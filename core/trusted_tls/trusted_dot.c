#include "d2k_trusted_dot.h"
#include "d2k_dns_message.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
struct dot_watch {
    const struct d2k_dot_io *io;
    struct d2k_dot_result *result;
    int64_t started,deadline,last;
};
static int64_t current(struct dot_watch *w) {
    if(w->io->cancelled && w->io->cancelled(w->io->clock_context)) {
        w->result->cancelled=w->result->local_refusal=1;return -1;
    }
    int64_t now=w->io->now_ms(w->io->clock_context);
    if(now<w->last) {w->result->local_refusal=1;return -1;}
    w->last=now;
    w->result->elapsed_ms=(uint64_t)(now-w->started);
    if(now>=w->deadline) {w->result->local_refusal=1;return -1;}
    return now;
}
static int exact(struct dot_watch *w,uint8_t *bytes,size_t n,int timeout) {
    int64_t now=current(w);if(now<0)return -1;
    int64_t end=now+timeout;if(end>w->deadline)end=w->deadline;
    while(n) {
        now=current(w);if(now<0)return -1;
        if(now>=end) {w->result->timed_out=1;return -1;}
        char error[160];
        long got=w->io->channel.read(w->io->channel.context,bytes,n,(int)(end-now),error,sizeof error);
        int64_t after=current(w);if(after<0)return -1;
        if(after>=end) {w->result->timed_out=1;return -1;}
        if(got<=0) {w->result->network_failure=1;return -1;}
        if((size_t)got>n) {w->result->local_refusal=1;return -1;}
        bytes+=got;n-=(size_t)got;
    }
    return 0;
}
void d2k_dot_contract_io(const struct d2k_dot_io *io,const char *name,uint16_t type,
    uint16_t id,int timeout,int duration,struct d2k_dot_result *r) {
    if(!r)return;
    memset(r,0,sizeof *r);r->name_ok=-1;
    uint8_t question[514];
    size_t n=d2k_dns_question(name,type,id,question+2,sizeof question-2);
    if(!io || !io->channel.read || !io->channel.write || !io->now_ms || !io->wait_ms ||
        !type || !n || timeout<=0 || duration<30000 || duration>600000) {
        r->local_refusal=1;return;
    }
    int64_t start=io->now_ms(io->clock_context);
    if(start<0 || start>INT64_MAX-duration) {r->local_refusal=1;return;}
    struct dot_watch w={io,r,start,start+duration,start};
    /* RFC1035 §4.2.2: two-octet size and maximum DNS message size. */
    uint8_t *answer=malloc(UINT16_MAX);
    if(!answer){r->local_refusal=1;return;}
    question[0]=(uint8_t)(n>>8);question[1]=(uint8_t)n;
    while(r->replies<20) {
        if(current(&w)<0)break;
        /* RFC1035 §4.1.1: correlate each outstanding transaction separately;
         * an old response must not count again on this sustained session. */
        uint16_t transaction=(uint16_t)(id+r->queries);
        question[2]=(uint8_t)(transaction>>8);question[3]=(uint8_t)transaction;
        char error[160];
        if(io->channel.write(io->channel.context,question,n+2,error,sizeof error)) {
            r->network_failure=1;break;
        }
        r->queries++;
        uint8_t prefix[2];
        if(exact(&w,prefix,sizeof prefix,timeout))break;
        size_t length=(size_t)prefix[0]*256+prefix[1];
        if(length<12) {r->protocol_failure=1;break;}
        if(exact(&w,answer,length,timeout))break;
        const char *reason=NULL;
        if(d2k_dns_answer_matches(question+2,n,answer,length,&reason)) {
            r->protocol_failure=1;break;
        }
        r->replies++;
        int64_t now=current(&w);if(now<0)break;
        if(r->replies==20) {
            r->application_ok=r->elapsed_ms>=30000;break;
        }
        /* Product contract §11.5:19 intervals spanning at least30seconds. */
        uint64_t offset=((uint64_t)r->replies*30000+18)/19;
        uint64_t elapsed=(uint64_t)(now-start);
        if(offset>elapsed) {
            uint64_t wait=offset-elapsed;
            if(wait>=(uint64_t)(w.deadline-now) ||
                io->wait_ms(io->clock_context,(uint32_t)wait)) {
                r->local_refusal=1;break;
            }
        }
    }
    if(current(&w)<0)r->application_ok=0;
    free(answer);
}
