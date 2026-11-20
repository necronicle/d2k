#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>
#include "server.c"
#include <assert.h>
static void put(const char *p,const char *s){FILE*f=fopen(p,"w");assert(f);assert(fputs(s,f)>=0);assert(!fclose(f));}
static void request(d2k_panel_config *cfg,const char *method,const char *headers,int code,const char *expected){
 int sv[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));char req[1024];
 snprintf(req,sizeof req,"%s /api/policies HTTP/1.1\r\nHost: localhost\r\n%s\r\n",method,headers);
 assert(write(sv[1],req,strlen(req))==(ssize_t)strlen(req));
 assert(!d2k_panel_handle_fd(sv[0],cfg));char answer[32768];ssize_t n=read(sv[1],answer,sizeof answer-1);assert(n>0);answer[n]=0;
 char status[32];snprintf(status,sizeof status,"HTTP/1.1 %d",code);assert(strstr(answer,status));assert(strstr(answer,expected));assert(!strstr(answer,"private fixture"));
 close(sv[0]);close(sv[1]);
}
int main(void){
 const char marked[]="d2kd\0--only-mark\0" "0x00ab/0xffffffff\0";
 assert(policy_argv_matches(marked,sizeof marked-1,"00ab"));
 assert(!policy_argv_matches(marked,sizeof marked-1,"ff"));
 assert(!policy_argv_matches(marked,sizeof marked-1,NULL));
 const char all[]="d2kd\0--queue\0" "4\0";
 assert(policy_argv_matches(all,sizeof all-1,NULL));

 char dir[]="/tmp/d2k-policy-XXXXXX";assert(mkdtemp(dir));
 char path[512];snprintf(path,sizeof path,"%s/config",dir);
 put(path,"# owner\nTG_RELAY_SECRET='private fixture'\nKEENETIC_POLICY=\"Old policy\"\nMODE=apply\n");
 char selected[256];assert(policy_config_read(path,selected,sizeof selected)==0);assert(!strcmp(selected,"Old policy"));
 assert(!chmod(path,0640));
 assert(policy_config_save(path,"Policy7")==0);
 struct stat mode;assert(!stat(path,&mode));assert((mode.st_mode&0777)==0640);
 FILE*f=fopen(path,"r");assert(f);char raw[1024];size_t n=fread(raw,1,sizeof raw-1,f);raw[n]=0;fclose(f);
 assert(strstr(raw,"TG_RELAY_SECRET='private fixture'\n"));assert(strstr(raw,"MODE=apply\n"));
 assert(policy_config_read(path,selected,sizeof selected)==0&&!strcmp(selected,"Policy7"));
 assert(policy_config_save(path,"$(bad)")<0);
 assert(policy_config_save(path,"")==0);assert(policy_config_read(path,selected,sizeof selected)==0&&!selected[0]);
 policy_item items[64];size_t count=0;
 char list[]="policy, name = Policy7, description = Work <devices>:\n mark: 00ab\npolicy, name = Policy8:\n mark: ff\n";
 assert(policy_parse(list,items,&count)==0&&count==2);assert(!strcmp(items[0].name,"Work <devices>"));assert(!strcmp(items[0].id,"Policy7"));
 char owrt[]="route.203\t203\t20000/0xff0000\nmark.10000.ff0000\t0x10000/0xff0000\t10000/0xff0000\n";
 assert(!policy_openwrt_parse(owrt,items,&count)&&count==2);
 assert(!strcmp(items[1].id,"mark.10000.ff0000"));
 const char masked[]="d2kd\0--only-mark\0" "0x10000/0xff0000\0";
 assert(policy_argv_matches(masked,sizeof masked-1,items[1].mark));
 assert(!policy_argv_matches(masked,sizeof masked-1,items[0].mark));
 assert(!policy_argv_matches(masked,sizeof masked-1,"10000/0xffffffff"));
 char bad_mask[]="route.203\t203\t20000/0xffffffffff";
 assert(policy_openwrt_parse(bad_mask,items,&count)<0);
 put(path,"KEENETIC_POLICY='broken\n");assert(policy_config_read(path,selected,sizeof selected)<0);
 put(path,"MODE=apply\nTG_RELAY_SECRET='private fixture'\nKEENETIC_POLICY=''\n");
 char ndmc[512],service[512];snprintf(ndmc,sizeof ndmc,"%s/ndmc",dir);snprintf(service,sizeof service,"%s/service",dir);
 put(ndmc,"#!/bin/sh\n[ \"$1\" = -c ] && [ \"$2\" = 'show ip policy' ] || exit 1\nprintf '%s\\n' 'policy, name = Policy7, description = Work <devices>:' ' mark: 00ab' 'policy, name = D2Ktest:' ' mark: 10'\n");
 assert(!chmod(ndmc,0700));put(service,"#!/bin/sh\n[ \"$1\" = engine-restart ] || exit 2\nexit 1\n");assert(!chmod(service,0700));
 const char *old=getenv("PATH");char saved[4096];snprintf(saved,sizeof saved,"%s",old?old:"");assert(!setenv("PATH",dir,1));
 d2k_panel_config cfg={.config_path=path,.service_path=service,.control_enabled=1};
 request(&cfg,"GET","",200,"Work <devices>");
 request(&cfg,"POST","X-D2K-Policy: Policy7\r\n",403,"false");
 request(&cfg,"POST","Origin: http://localhost\r\nX-D2K-Policy: Missing\r\n",409,"false");
 request(&cfg,"POST","Origin: http://localhost\r\nX-D2K-Policy: $(bad)\r\n",400,"false");
 assert(!policy_config_read(path,selected,sizeof selected)&&!selected[0]);
 request(&cfg,"POST","Origin: http://localhost\r\nX-D2K-Policy: D2Ktest\r\n",202,"running");
 assert(!policy_config_read(path,selected,sizeof selected)&&!strcmp(selected,"D2Ktest"));
 while(action_pid){struct timespec t={.tv_nsec=10000000};nanosleep(&t,NULL);d2k_panel_control_tick();}
 request(&cfg,"GET","",200,"\"apply_state\":\"failed\"");
 put(service,"#!/bin/sh\nexit 0\n");
 request(&cfg,"POST","Origin: http://localhost\r\nX-D2K-Policy: \r\n",202,"running");
 while(action_pid){struct timespec t={.tv_nsec=10000000};nanosleep(&t,NULL);d2k_panel_control_tick();}
 assert(!policy_config_read(path,selected,sizeof selected)&&!selected[0]);
 request(&cfg,"GET","",200,"\"apply_state\":\"done\"");
 put(ndmc,"#!/bin/sh\nexit 1\n");request(&cfg,"POST","Origin: http://localhost\r\nX-D2K-Policy: D2Ktest\r\n",503,"false");
 assert(!policy_config_read(path,selected,sizeof selected)&&!selected[0]);
 assert(!setenv("PATH",saved,1));unlink(ndmc);unlink(service);
 unlink(path);rmdir(dir);puts("policy config/parser PASS");
}
