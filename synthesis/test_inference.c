#include "inference.h"
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
static int predict(void *ctx,size_t model,const d2k_input_word *q,uint64_t *v) {
    int *unknown=ctx;
    if(*unknown && model==3) return 0;
    *v=q->operations[0]==0 ? 0 : q->operations[0]==1 ? model/2 : model%2;
    return 1;
}
int main(void) {
    size_t ids[]={0,1,2,3},ops[]={0,1,2}; int unknown=0;
    d2k_belief b={ids,4,7};
    d2k_input_word q[]={{ops,1},{ops+1,1},{ops+2,1}};
    d2k_question chosen;
    assert(d2k_choose_question(&b,q,3,predict,&unknown,&chosen)==1);
    assert(chosen.index==1 && chosen.guaranteed_eliminations==2);
    assert(d2k_observe(&b,6,q+1,1,0,predict,&unknown)==D2K_LEARN_STALE && b.count==4);
    assert(d2k_observe(&b,7,q+1,0,0,predict,&unknown)==D2K_LEARN_UNCHANGED && b.count==4);
    assert(d2k_observe(&b,7,q+1,1,8,predict,&unknown)==D2K_LEARN_CONTRADICTION && b.count==4);
    unknown=1;
    assert(d2k_choose_question(&b,q,3,predict,&unknown,&chosen)==1);
    assert(chosen.guaranteed_eliminations==1);
    assert(d2k_observe(&b,7,q+1,1,0,predict,&unknown)==D2K_LEARN_REFINED);
    assert(b.count==3 && ids[0]==0 && ids[1]==1 && ids[2]==3);
    assert(d2k_choose_question(&b,q,1,predict,&unknown,&chosen)==0);
    puts("inference: partition, unknown, inconclusive, stale and contradiction pass");
}
