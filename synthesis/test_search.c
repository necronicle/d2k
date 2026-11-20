#include "search.h"
#include <assert.h>
#include <stdio.h>
typedef struct { d2k_syn_edge edges[5][3]; int goal; size_t calls; } fixture;
static d2k_syn_edge step(void *ctx, size_t state, size_t op) {
    fixture *f = ctx; ++f->calls; return f->edges[state][op];
}
static int goal(void *ctx, size_t state) { return (int)state == ((fixture *)ctx)->goal; }
static int failing_goal(void *ctx, size_t state) {
    return (int)state==((fixture *)ctx)->goal ? -1 : 0;
}
int main(void) {
    fixture f = {.goal = 4};
    for (size_t s=0;s<5;s++) for(size_t op=0;op<3;op++)
        f.edges[s][op].kind=D2K_SYN_INVALID;
    d2k_syn_model m={&f,5,3,0,step,goal};
    f.edges[0][2]=(d2k_syn_edge){D2K_SYN_EDGE,1};
    f.edges[1][0]=(d2k_syn_edge){D2K_SYN_EDGE,2};
    f.edges[2][1]=(d2k_syn_edge){D2K_SYN_UNKNOWN,0};
    d2k_syn_result r=d2k_syn_search(&m);
    assert(r.status==D2K_SYN_EXPERIMENT && r.length==3);
    assert(r.operations[0]==2 && r.operations[1]==0 && r.operations[2]==1);
    d2k_syn_result_free(&r);
    /* An observation refines the model; it does not select a stored recipe. */
    f.edges[2][1]=(d2k_syn_edge){D2K_SYN_EDGE,4};
    r=d2k_syn_search(&m);
    assert(r.status==D2K_SYN_CANDIDATE && r.length==3);
    d2k_syn_result_free(&r);
    /* A counterexample removes the unsupported transition. */
    f.edges[2][1]=(d2k_syn_edge){D2K_SYN_INVALID,0};
    f.edges[2][2]=(d2k_syn_edge){D2K_SYN_EDGE,0};
    r=d2k_syn_search(&m); assert(r.status==D2K_SYN_CLOSED); d2k_syn_result_free(&r);
    f.goal=0; f.calls=0;
    r=d2k_syn_search(&m); assert(r.status==D2K_SYN_DIRECT && !f.calls); d2k_syn_result_free(&r);
    f.goal=4; f.edges[0][0]=(d2k_syn_edge){D2K_SYN_EDGE,99};
    r=d2k_syn_search(&m); assert(r.status==D2K_SYN_ERROR); d2k_syn_result_free(&r);
    m.goal=failing_goal;f.goal=0;
    r=d2k_syn_search(&m); assert(r.status==D2K_SYN_ERROR); d2k_syn_result_free(&r);
    f.goal=1;f.edges[0][0]=(d2k_syn_edge){D2K_SYN_INVALID,0};
    r=d2k_syn_search(&m); assert(r.status==D2K_SYN_ERROR); d2k_syn_result_free(&r);
    puts("synthesis model search: pass");
}
