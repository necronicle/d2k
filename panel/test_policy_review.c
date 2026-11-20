#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>
#include "server.c"
#include <assert.h>
static void put(const char*p,const char*s){FILE*f=fopen(p,"w");assert(f);assert(fputs(s,f)>=0);assert(!fclose(f));}
int main(int argc,char **argv){
 assert(argc==2);char dir[]="/tmp/d2k-policy-review-XXXXXX";assert(mkdtemp(dir));char config[512],ndmc[512],pidfile[512];
 snprintf(config,sizeof config,"%s/config",dir);snprintf(ndmc,sizeof ndmc,"%s/ndmc",dir);snprintf(pidfile,sizeof pidfile,"%s/helper.pid",dir);
 if(!strcmp(argv[1],"export")){
  const char *prefixes[]={"KEENETIC_POLICY=","  export KEENETIC_POLICY=","\texport\tKEENETIC_POLICY\t="};
  for(size_t i=0;i<sizeof prefixes/sizeof prefixes[0];i++){
   char before[1024],expected[1024],choice[256],actual[1024];
   snprintf(before,sizeof before,"# owner\nEXTRA='unchanged'\n%s'Policy7'\nMODE=apply\n",prefixes[i]);put(config,before);
   int readrc=policy_config_read(config,choice,sizeof choice);assert(!readrc&&!strcmp(choice,"Policy7"));
   assert(!policy_config_save(config,"D2Ktest"));
   snprintf(expected,sizeof expected,"# owner\nEXTRA='unchanged'\n%s'D2Ktest'\nMODE=apply\n",prefixes[i]);
   FILE*f=fopen(config,"r");assert(f);size_t n=fread(actual,1,sizeof actual-1,f);fclose(f);actual[n]=0;assert(!strcmp(actual,expected));
   assert(!policy_config_read(config,choice,sizeof choice)&&!strcmp(choice,"D2Ktest"));
  }
 }else if(!strcmp(argv[1],"layout")){
  const char *layouts[]={"EXTRA='first\nKEENETIC_POLICY=private-value\nlast'\nKEENETIC_POLICY='Policy7'\n","EXTRA=first\\\nKEENETIC_POLICY=private-value\nKEENETIC_POLICY='Policy7'\n","cat <<'EOF'\nKEENETIC_POLICY=private-value\nEOF\nKEENETIC_POLICY='Policy7'\n"};
  for(size_t i=0;i<sizeof layouts/sizeof layouts[0];i++){put(config,layouts[i]);char choice[256];int readrc=policy_config_read(config,choice,sizeof choice);int saverc=policy_config_save(config,"D2Ktest");FILE*f=fopen(config,"r");assert(f);char raw[1024];size_t n=fread(raw,1,sizeof raw-1,f);fclose(f);raw[n]=0;assert(readrc<0&&saverc<0);assert(!strcmp(raw,layouts[i]));}
 }else if(!strcmp(argv[1],"collision")){
  policy_item collision[3]={ {.id="Policy7",.name="D2Ktest",.mark="aa"}, {.id="D2Ktest",.name="Work",.mark="bb"}, {.id="Policy8",.name="Work",.mark="cc"} };
  const policy_item *exact=policy_resolve(collision,3,"D2Ktest");assert(exact&&!strcmp(exact->mark,"bb"));
  assert(!policy_resolve(collision,3,"Work"));assert(!policy_resolve(collision,3,"Missing"));
  put(config,"KEENETIC_POLICY='D2Ktest'\n");
  put(ndmc,"#!/bin/sh\nprintf '%s\\n' 'policy, name = Policy7, description = D2Ktest:' ' mark: aa' 'policy, name = D2Ktest, description = Work:' ' mark: bb'\n");assert(!chmod(ndmc,0700));assert(!setenv("PATH",dir,1));
  int sv[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));d2k_panel_config cfg={.config_path=config};assert(!api_policies(sv[0],&cfg,"","GET"));char response[8192];ssize_t n=read(sv[1],response,sizeof response-1);assert(n>0);response[n]=0;assert(strstr(response,"\"selected_id\":\"D2Ktest\""));close(sv[0]);close(sv[1]);
 }else if(!strcmp(argv[1],"cleanup")){
  char script[1024];snprintf(script,sizeof script,"#!/bin/sh\n/bin/sleep 30 &\necho $! > '%s'\nexit 0\n",pidfile);put(ndmc,script);assert(!chmod(ndmc,0700));assert(!setenv("PATH",dir,1));
  policy_item items[POLICY_MAX];size_t count=0;long long start=monotonic_ms();assert(policy_list(NULL,-1,items,&count)<0);assert(monotonic_ms()-start<2500);
  FILE*f=fopen(pidfile,"r");assert(f);long pid=0;assert(fscanf(f,"%ld",&pid)==1);fclose(f);int alive=1;for(int i=0;i<100;i++){if(kill((pid_t)pid,0)<0&&errno==ESRCH){alive=0;break;}struct timespec pause={.tv_nsec=10000000};nanosleep(&pause,NULL);}if(alive)kill((pid_t)pid,SIGKILL);assert(!alive);unlink(pidfile);
 }else assert(0);
 unlink(config);unlink(ndmc);rmdir(dir);puts("policy review regression PASS");
}
