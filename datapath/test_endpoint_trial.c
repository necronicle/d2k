/* Real endpoint command decoder, no listener or network. */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "d2k_ctlsrv.h"
#include "d2k_ctl.h"
static int fails;
#define CHECK(c,m) do{if(!(c)){fprintf(stderr,"FAIL: %s\n",m);fails++;}}while(0)
static const uint8_t tiny[]={'D','2','K','P',0,1,0,18,0,0,0,3,0,2,0,2,6,1,1,0x14,0,11,0,7,3,9,1,0,0,9,96,0,1,0,0x10,0,5,0,1,0x16,3,1};
int main(void){
    d2k_ctlsrv cx={0};cx.sess=d2k_session_new(8,0);CHECK(cx.sess,"session");if(!cx.sess)return 1;
    uint8_t set[20+sizeof tiny+16]={0},del[36]={0};set[0]=4;set[1]=192;set[3]=2;set[4]=8;
    set[17]=D2K_PLAN_SHAPE_MODERN;set[18]=1;set[19]=187;memcpy(set+20,tiny,sizeof tiny);set[20+sizeof tiny]=9;
    d2k_ctlsrv_command(&cx,D2K_CMD_SET_ENDPOINT_BOUND,set,sizeof set);
    CHECK(cx.ok_cmds==1 && cx.installed_binding.temporary,"bound preflight is a staged endpoint candidate");
    d2k_plantab *t=d2k_session_plans(cx.sess);
#define FIND() d2k_plantab_find_target_endpoint(t,NULL,0,set+1,4,1,D2K_PLAN_SHAPE_MODERN,0,htons(443))
    const d2k_plan *p=FIND();CHECK(p,"endpoint present");uint8_t trial[16];d2k_plantab_trial(t,p,trial);CHECK(trial[0]==9,"decoder binds runtime token");
    memcpy(del,set,20);del[20]=8;d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT_TRIAL,del,sizeof del);CHECK(FIND()==p,"foreign token preserved");
    del[20]=9;del[19]++;d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT_TRIAL,del,sizeof del);CHECK(FIND()==p,"other port preserved");del[19]--;
    for(size_t n=0;n<sizeof del;n++){uint64_t bad=cx.bad_cmds;d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT_TRIAL,del,n);CHECK(cx.bad_cmds==bad+1,"truncated deletion rejected");CHECK(FIND()==p,"truncated deletion preserved owner");}
    del[0]=6;d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT_TRIAL,del,sizeof del);CHECK(FIND()==p,"IPv6 deletion rejected");del[0]=4;
    del[20]=0;d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT_TRIAL,del,sizeof del);CHECK(FIND()==p,"zero token rejected");del[20]=9;
    d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT_TRIAL,del,sizeof del);CHECK(!FIND(),"own generation removed");
    d2k_ctlsrv_command(&cx,D2K_CMD_SET_ENDPOINT_BOUND,set,sizeof set);p=FIND();
    del[20]=8;d2k_ctlsrv_command(&cx,D2K_CMD_COMMIT_ENDPOINT_TRIAL,del,sizeof del);
    d2k_binding_context binding={0};d2k_plantab_binding(t,p,&binding);CHECK(binding.temporary,"foreign commit preserves candidate");
    del[20]=9;d2k_ctlsrv_command(&cx,D2K_CMD_COMMIT_ENDPOINT_TRIAL,del,sizeof del);
    d2k_plantab_binding(t,p,&binding);CHECK(!binding.temporary,"matching commit promotes endpoint candidate");
    d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT_TRIAL,del,sizeof del);CHECK(FIND()==p,"late cleanup preserves promoted owner");
    d2k_plantab_clear_probes(t);CHECK(FIND()==p,"promoted endpoint survives disconnect");
    d2k_session_free(cx.sess);
    if(fails)return 1;
    puts("endpoint trial decoder: all checks passed");
    return 0;
}
