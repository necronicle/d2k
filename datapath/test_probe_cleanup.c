/* Real table + command decoder, no socket or network. */
#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "d2k_ctlsrv.h"
#include "d2k_plans.h"

static const uint8_t tiny[]={
    'D','2','K','P',0,1,0,1,0,0,0,1,0x01,0x03,0,1,0
};
static unsigned removed;
static void hook(void *ctx,const uint8_t *name,size_t n,uint8_t tr,uint8_t family,uint16_t port,
                  uint64_t expires,int installed) {
    (void)ctx;(void)expires;
    assert(n==1 && name[0]=='x' && tr==6 && family==4 && port==htons(50000) && !installed);
    removed++;
}
static d2k_plan *plan(void) {
    d2k_plan *p=NULL;char err[100];assert(!d2k_plan_load(tiny,sizeof tiny,&p,err,sizeof err));return p;
}
int main(void) {
    d2k_session *s=d2k_session_new(16,0);assert(s);
    d2k_plantab *t=d2k_session_plans(s);assert(t);
    uint8_t a[16]={1},b[16]={2};const uint8_t *name=(const uint8_t *)"x";
    d2k_plan *production=plan(),*own=plan(),*family=plan(),*port=plan(),*address=plan();
    uint8_t ip[4]={192,0,2,1};
    assert(!d2k_plantab_set_addr_shaped(t,ip,4,0,address,1));
    assert(!d2k_plantab_set_name_family(t,name,1,0,production,1,0,4));
    assert(!d2k_plantab_set_name_trial(t,name,1,0,own,1,htons(50000),4,a));
    assert(!d2k_plantab_set_name_trial(t,name,1,0,family,1,htons(50000),6,b));
    assert(!d2k_plantab_set_name_trial(t,name,1,0,port,1,htons(50001),4,b));
    d2k_ctlsrv cx={.sess=s,.name_probe_hook=hook};
    uint8_t body[22]={1,'x',1,4};uint16_t sport=htons(50000);memcpy(body+4,&sport,2);
    memcpy(body+6,b,16);
    d2k_ctlsrv_command_exp(&cx,D2K_CMD_DEL_NAME_PROBE,body,sizeof body);
    assert(d2k_plantab_find_family(t,name,1,0,0,1,sport,4)==own && !removed);
    /* Recycled local port is not ownership: a stale/foreign token cannot
       remove the previous generation or its late-delivery tracking. */
    memcpy(body+6,a,16);
    d2k_ctlsrv_command_exp(&cx,D2K_CMD_DEL_NAME_PROBE,body,sizeof body-1);
    assert(d2k_plantab_find_family(t,name,1,0,0,1,sport,4)==own && !removed);
    memset(body+6,0,16);
    d2k_ctlsrv_command_exp(&cx,D2K_CMD_DEL_NAME_PROBE,body,sizeof body);
    assert(d2k_plantab_find_family(t,name,1,0,0,1,sport,4)==own && !removed);
    memcpy(body+6,a,16);
    body[2]=2;
    d2k_ctlsrv_command_exp(&cx,D2K_CMD_DEL_NAME_PROBE,body,sizeof body);
    assert(d2k_plantab_find_family(t,name,1,0,0,1,sport,4)==own && !removed);
    body[2]=1;body[3]=6;
    d2k_ctlsrv_command_exp(&cx,D2K_CMD_DEL_NAME_PROBE,body,sizeof body);
    assert(d2k_plantab_find_family(t,name,1,0,0,1,sport,6)==family && !removed);
    body[3]=4;
    uint16_t other_port=htons(50001);memcpy(body+4,&other_port,2);
    d2k_ctlsrv_command_exp(&cx,D2K_CMD_DEL_NAME_PROBE,body,sizeof body);
    assert(d2k_plantab_find_family(t,name,1,0,0,1,other_port,4)==port && !removed);
    memcpy(body+4,&sport,2);
    d2k_ctlsrv_command_exp(&cx,D2K_CMD_DEL_NAME_PROBE,body,sizeof body);
    assert(d2k_plantab_find_family(t,name,1,0,0,1,sport,4)==production);
    assert(removed==1);
    assert(d2k_plantab_find_target(t,NULL,0,ip,4,0,1,0)==address);
    assert(d2k_plantab_find_family(t,name,1,0,0,1,sport,6)==family);
    assert(d2k_plantab_find_family(t,name,1,0,0,1,htons(50001),4)==port);
    /* A repeated exact delete is idempotent and must not drop production. */
    d2k_ctlsrv_command_exp(&cx,D2K_CMD_DEL_NAME_PROBE,body,sizeof body);
    assert(removed==1 && d2k_plantab_find_family(t,name,1,0,0,1,sport,4)==production);
    /* Legacy no-token commands retain their old exact port semantics. */
    assert(!d2k_plantab_set_name_trial(t,name,1,0,plan(),2,htons(50000),4,a));
    body[2]=2;
    cx.name_probe_hook=NULL;
    d2k_ctlsrv_command(&cx,D2K_CMD_DEL_NAME_PROBE,body,6);
    assert(d2k_plantab_find_family(t,name,1,0,0,2,sport,4)==NULL);
    d2k_session_free(s);
    puts("conditional name probe cleanup preserves foreign token/type/shape/family/port: ok");return 0;
}
