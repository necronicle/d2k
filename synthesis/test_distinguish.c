#include "distinguish.h"
#include <assert.h>
#include <stdio.h>
typedef struct { int variant, unknown; } fixture;
static int step(void *ctx,size_t s,size_t op,d2k_transition *t) {
    fixture *f=ctx;
    if(f->unknown && s==1 && op==1) return 0;
    t->next=op==0?1:0;
    t->observation=s==1 && op==1 ? (uint64_t)f->variant : 0;
    return 1;
}
static int predictive_step(void *ctx,size_t s,size_t op,d2k_transition *t) {
    int inferred=*(int *)ctx;
    if(s==0 && op==1){t->next=1;t->observation=0;return 1;}
    if(s==1 && op==0 && inferred){t->next=1;t->observation=7;return 1;}
    return 0;
}
static int send_read(void *ctx,size_t state,size_t op,size_t *next) {
    (void)ctx;
    if(state==0 && op==0){*next=1;return 1;}
    if(state==1 && op==1){*next=2;return 1;}
    return 0;
}
static int loop_output(void *ctx,size_t state,size_t op,d2k_transition *t) {
    (void)state;t->next=0;t->observation=op==1?(uint64_t)*(int *)ctx:0;return 1;
}
static int persistent_peer(void *ctx,size_t state,size_t op,d2k_transition *t) {
    (void)ctx;
    if(state>1 || op>1)return -1;
    /* A control leaves state unchanged and hides it. A full experiment
       observes and changes persistent state across connection boundaries. */
    t->observation=op?10+state:0;t->next=op?1-state:state;return 1;
}
static void equal_controls_do_not_home(void) {
    size_t state=0;uint64_t results[2];
    for(size_t trial=0;trial<2;trial++) {
        d2k_transition before,query,after;
        assert(persistent_peer(NULL,state,0,&before)==1 && before.observation==0);
        assert(persistent_peer(NULL,before.next,1,&query)==1);
        assert(persistent_peer(NULL,query.next,0,&after)==1 && after.observation==0);
        results[trial]=query.observation;state=after.next;
    }
    assert(results[0]!=results[1]); /* Both bracket checks passed. */
    d2k_transducer first={NULL,2,0,2,persistent_peer},second=first;second.initial=1;
    d2k_distinction question=d2k_distinguish(&first,&second);
    assert(question.status==D2K_DIST_WITNESS && question.length==1);
    assert(question.operations[0]==1 && question.left_observation!=question.right_observation);
    d2k_distinction_free(&question);
}
static int large_step(void *ctx,size_t state,size_t op,d2k_transition *t) {
    (void)op;
    size_t offset=SIZE_MAX-1001;
    assert(state>=offset && state<offset+1000);
    size_t n=state-offset;
    t->next=offset+(n+1)%1000;
    t->observation=n==999?(uint64_t)*(int *)ctx:0;
    return 1;
}
static int large_domain(void *ctx,size_t state,size_t op,size_t *next) {
    (void)ctx;(void)op;
    assert(state==SIZE_MAX-1);
    *next=state;return 1;
}
static void sparse_product(void) {
    int a=0,b=1;
    d2k_transducer l={&a,SIZE_MAX,SIZE_MAX-1001,1,large_step},r=l;
    r.ctx=&b;
    d2k_input_domain domain={NULL,SIZE_MAX,SIZE_MAX-1,1,large_domain};
    d2k_distinction d=d2k_distinguish_in(&l,&r,&domain);
    assert(d.status==D2K_DIST_WITNESS && d.length==1000);
    assert(d.known_outputs==3 && d.left_observation==0 && d.right_observation==1);
    for(size_t i=0;i<d.length;i++)assert(d.operations[i]==0);
    d2k_distinction_free(&d);
    b=0;
    d=d2k_distinguish_in(&l,&r,&domain);
    assert(d.status==D2K_DIST_EQUIVALENT && !d.operations);
    d2k_distinction_free(&d);
}
int main(void) {
    sparse_product();
    equal_controls_do_not_home();
    fixture a={0,0},b={1,0};
    d2k_transducer l={&a,2,0,2,step},r={&b,2,0,2,step};
    d2k_distinction d=d2k_distinguish(&l,&r);
    assert(d.status==D2K_DIST_WITNESS && d.length==2);
    assert(d.operations[0]==0 && d.operations[1]==1);
    assert(d.left_observation==0 && d.right_observation==1 && d.known_outputs==3);
    d2k_distinction_free(&d);
    b.variant=0;
    d=d2k_distinguish(&l,&r); assert(d.status==D2K_DIST_EQUIVALENT); d2k_distinction_free(&d);
    b.unknown=1;
        d=d2k_distinguish(&l,&r); assert(d.status==D2K_DIST_INCOMPLETE);
    assert(d.length==2 && d.operations[0]==0 && d.operations[1]==1);
    assert(d.known_outputs==1 && d.left_observation==0);
    d2k_distinction_free(&d);

    a.unknown=1;
    d=d2k_distinguish(&l,&r);
    assert(d.status==D2K_DIST_INCOMPLETE && d.length==2 && d.known_outputs==0);
    d2k_distinction_free(&d);
    b.unknown=0;
    d=d2k_distinguish(&l,&r);
    assert(d.status==D2K_DIST_INCOMPLETE && d.length==2 && d.known_outputs==2);
    d2k_distinction_free(&d);
    r.operations=3;

    d=d2k_distinguish(&l,&r); assert(d.status==D2K_DIST_ERROR); d2k_distinction_free(&d);
    int measured=0,inferred=1;
    l=(d2k_transducer){&measured,2,0,2,predictive_step};
    r=(d2k_transducer){&inferred,2,0,2,predictive_step};
    d=d2k_distinguish(&l,&r);
    assert(d.status==D2K_DIST_INCOMPLETE && d.known_outputs==2 && d.length==2);
    assert(d.operations[0]==1 && d.operations[1]==0 && d.right_observation==7);
    d2k_distinction_free(&d);
    l=(d2k_transducer){&measured,1,0,2,loop_output};
    r=(d2k_transducer){&inferred,1,0,2,loop_output};
    d2k_input_domain domain={NULL,3,0,2,send_read};
    d=d2k_distinguish_in(&l,&r,&domain);
    assert(d.status==D2K_DIST_WITNESS && d.length==2);
    assert(d.operations[0]==0 && d.operations[1]==1);
    d2k_distinction_free(&d);
    puts("distinguishing sequence: witness, cycles, incomplete model and alphabet checks pass");
}
