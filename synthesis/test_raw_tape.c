#include "raw_tape.h"
#include <assert.h>
#include <string.h>
typedef struct {unsigned n;int reject;} receiver;
static int accept(void *ctx,const d2k_raw_tls_event *e) {
    receiver *r=ctx;assert(e->ordinal==r->n && e->experience==17);
    if(e->action==D2K_RAW_TLS_SEND) {
        assert(e->length==3 && !memcmp(e->bytes,"abc",3));
        assert(!strcmp(e->program,"original"));
    }
    r->n++;return r->reject?-1:0;
}
int main(void) {
    for(int rejected=0;rejected<2;rejected++) {
        d2k_raw_tape *t=d2k_raw_tape_new(17);assert(t);
        d2k_raw_tls_sink in=d2k_raw_tape_sink(t);assert(in.record);
        d2k_raw_tls_event e={.experience=17,.action=D2K_RAW_TLS_OPEN};
        assert(!in.record(in.context,&e));
        char bytes[]="abc",program[]="original";
        e.ordinal++;e.action=D2K_RAW_TLS_SEND;e.bytes=(uint8_t *)bytes;e.length=3;e.program=program;
        assert(!in.record(in.context,&e));
        memset(bytes,'x',3);memset(program,'y',8);
        const d2k_raw_tls_event *saved=d2k_raw_tape_event(t,1);
        assert(saved && !memcmp(saved->bytes,"abc",3) && !strcmp(saved->program,"original"));
        receiver r={.reject=rejected};d2k_raw_tls_sink out={17,&r,accept},foreign=out;foreign.experience++;
        assert(d2k_raw_tape_bind(t,&foreign)<0 && !r.n);
        assert((d2k_raw_tape_bind(t,&out)==0)==!rejected);
        assert(d2k_raw_tape_bind(t,&out)<0);
        e.ordinal++;e.action=D2K_RAW_TLS_CLOSE;e.bytes=NULL;e.length=0;e.program=NULL;
        assert((in.record(in.context,&e)==0)==!rejected);
        assert(in.record(in.context,&e)<0);
        assert(r.n==(rejected?1:3));
        d2k_raw_tape_free(t);
    }
    assert(!d2k_raw_tape_new(0));return 0;
}
