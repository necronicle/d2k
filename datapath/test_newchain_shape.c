/* Actual production control commands and plan-table lookup, no sockets. */
#include "d2k_ctlsrv.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static const uint8_t plan[]={'D','2','K','P',0,1,0,1,0,0,0,2,
    0,2,0,2,6,1,1,3,0,1,0};
static void install(d2k_ctlsrv *cx,uint16_t command,uint8_t shape,uint8_t family) {
    const char *name="bound.example";size_t len=strlen(name);uint8_t body[128]={0};
    body[0]=(uint8_t)len;memcpy(body+1,name,len);body[len+1]=shape;body[len+2]=family;
    memcpy(body+len+3,plan,sizeof plan);size_t n=len+3+sizeof plan;
    if(command==D2K_CMD_SET_NAME_BOUND) {memset(body+n,0x71,16);n+=16;}
    uint64_t good=cx->ok_cmds;d2k_ctlsrv_command(cx,command,body,n);assert(cx->ok_cmds==good+1);
}
static const d2k_plan *find(d2k_plantab *table,uint8_t shape,uint8_t family) {
    return d2k_plantab_find_target(table,(const uint8_t *)"bound.example",13,NULL,family,2,shape,0);
}
int main(void) {
    for(unsigned family=4;family<=6;family+=2) {
        d2k_session *s=d2k_session_new(16,0);assert(s);d2k_ctlsrv cx={.sess=s,.now_ns=1};
        d2k_plantab *table=d2k_session_plans(s);
        install(&cx,D2K_CMD_SET_NAME,D2K_PLAN_SHAPE_MODERN,(uint8_t)family);
        assert(find(table,D2K_PLAN_SHAPE_ECH_TCP,(uint8_t)family)); /* legacy GREASE behavior */
        install(&cx,D2K_CMD_SET_NAME_BOUND,D2K_PLAN_SHAPE_MODERN,(uint8_t)family);
        const d2k_plan *plain=find(table,D2K_PLAN_SHAPE_MODERN,(uint8_t)family);assert(plain);
        assert(!find(table,D2K_PLAN_SHAPE_ECH_TCP,(uint8_t)family)); /* bound proof is exact */
        assert(!find(table,D2K_PLAN_SHAPE_LEGACY,(uint8_t)family));
        install(&cx,D2K_CMD_SET_NAME_BOUND,D2K_PLAN_SHAPE_ECH_TCP,(uint8_t)family);
        const d2k_plan *ech=find(table,D2K_PLAN_SHAPE_ECH_TCP,(uint8_t)family);assert(ech && ech!=plain);
        assert(find(table,D2K_PLAN_SHAPE_MODERN,(uint8_t)family)==plain);
        assert(!find(table,D2K_PLAN_SHAPE_MODERN,family==4?6:4));
        d2k_session_free(s);
    }
    puts("bound TLS shape exactness, ECH coexistence, legacy fallback: ok");return 0;
}
