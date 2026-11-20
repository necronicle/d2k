#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "d2k_ctlsrv.h"
#include "d2k_ctl.h"
#include "d2k_preflight_lease.h"

static const uint8_t tiny[]={'D','2','K','P',0,1,0,18,0,0,0,3,0,2,0,2,6,1,1,0x14,0,11,0,7,3,9,1,0,0,9,96,0,1,0,0x10,0,5,0,1,0x16,3,1};
#define FAIL() do{fprintf(stderr,"%s:%d FAIL\n",__func__,__LINE__);return 1;}while(0)
int main(void) {
    d2k_ctlsrv cx={0};cx.sess=d2k_session_new(8,0);
    if(!cx.sess||d2k_session_set_preflight(cx.sess,1))return 2;
    d2k_pf_scope scope={0};scope.family=4;scope.shape=D2K_PLAN_SHAPE_MODERN;
    scope.server_port=htons(443);scope.path=7;scope.client[0]=192;scope.client[1]=168;scope.client[3]=9;
    scope.server[0]=192;scope.server[2]=2;scope.server[3]=8;strcpy(scope.name,"video.example");
    uint8_t command[1024]={0};size_t n=0;
    command[n++]=4;memcpy(command+n,scope.client,16);n+=16;memcpy(command+n,scope.server,16);n+=16;
    command[n++]=scope.shape;command[n++]=0;command[n++]=0;command[n++]=0;command[n++]=7;
    uint16_t port=htons(443);memcpy(command+n,&port,2);n+=2;
    command[n++]=0;command[n++]=0;command[n++]=1;command[n++]=0; /* 256 ms */
    size_t name_len=strlen(scope.name);command[n++]=0;command[n++]=(uint8_t)name_len;
    memcpy(command+n,scope.name,name_len);n+=name_len;
    uint8_t id[16]={9};memcpy(command+n,id,16);n+=16;memcpy(command+n,tiny,sizeof tiny);n+=sizeof tiny;
    d2k_ctlsrv_command(&cx,D2K_CMD_SET_PREFLIGHT_LEASE,command,n);
    const d2k_plan *installed=d2k_session_find_preflight_lease(cx.sess,&scope,100);
    if(cx.ok_cmds!=1||!cx.installed_binding.temporary||cx.installed_binding.shape!=D2K_PLAN_SHAPE_MODERN)FAIL();
    if(!installed)FAIL();
    command[name_len+46+0]^=1; /* wrong lease ID */
    d2k_ctlsrv_command(&cx,D2K_CMD_DEL_PREFLIGHT_LEASE,command,46+name_len+16);
    if(d2k_session_find_preflight_lease(cx.sess,&scope,100)!=installed)FAIL();
    command[name_len+46]^=1;d2k_ctlsrv_command(&cx,D2K_CMD_DEL_PREFLIGHT_LEASE,command,46+name_len+16);
    if(d2k_session_find_preflight_lease(cx.sess,&scope,100))FAIL();
    d2k_ctlsrv_command(&cx,D2K_CMD_SET_PREFLIGHT_LEASE,command,n-1);
    if(!cx.bad_cmds)FAIL();
    d2k_session_free(cx.sess);puts("preflight lease control: all checks passed");return 0;
}
