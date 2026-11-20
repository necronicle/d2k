#include "application_late.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static int native_profile;
static d2k_application_model *model(int variant){
 d2k_synthesis_feedback id={.generation=1,.search_id=1,.trial_id={1},.plan_id={1},.target="dns.example",.ip="192.0.2.7",.resource="/dns-query",.doh=1,.family=4,.transport=6,.port=443,
 .program="d2k-plan 1 5\nid 0123456789abcdef0123456789abcdef\nproto tcp tls\nwire detect-tcp-v1\norder forward\n"};
 if(variant==6)id.program="d2k-plan 1 5\nid 0123456789abcdef0123456789abcdef\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +1\norder forward\n";
 unsigned experience=variant>=14?2:1;
 if(variant>=14) {
  id.trial_id[0]=2;
  id.program=variant==16?
   "d2k-plan 1 16\nid 0123456789abcdef0123456789abcdef\nproto tcp tls\nwire detect-tcp-v1\nstream-offset 100\ninput 150 0 0\nsplit payload_start +17\norder forward\n":
   "d2k-plan 1 16\nid 0123456789abcdef0123456789abcdef\nproto tcp tls\nwire detect-tcp-v1\nstream-offset 100\ninput 150 0 0\nsplit payload_start +75\norder forward\n";
  if(variant==17)id.target="other.example";
  if(variant==18)id.program="foreign program";
  if(variant==20)id.program="d2k-plan 1 17\nid 0123456789abcdef0123456789abcdef\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +1\norder forward\ninput 6 0 0\nafter-split 100 150 75\n";
  if(variant==21)id.program="d2k-plan 1 17\nid 0123456789abcdef0123456789abcdef\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +2\norder forward\ninput 6 0 0\nafter-split 100 150 75\n";
 }
 char native_program[1024];
 const char *wire=strstr(id.program,"wire detect-tcp-v1\n");
 if(native_profile && wire) {
  int n=snprintf(native_program,sizeof native_program,"%.*swire tcp-template-v1\n%s",
      (int)(wire-id.program),id.program,wire+strlen("wire detect-tcp-v1\n"));
  assert(n>0 && (size_t)n<sizeof native_program);
  if(!strncmp(native_program,"d2k-plan 1 5\n",13))native_program[11]='8';
  id.program=native_program;
 }
 d2k_application_model *m=d2k_application_model_new(&id,experience);assert(m);
 uint8_t input[]={22,3,1,0,1,1};
 d2k_application_observation o={.identity=&id,.experience=experience,.input=input,.input_length=sizeof input,.raw_ordinal=1};
 o.tuple.family=4;o.tuple.local_port=50000;o.tuple.remote_port=443;o.tuple.remote[0]=192;o.tuple.remote[2]=2;o.tuple.remote[3]=7;
 o.query.query_schema=D2K_DOH_QUERY_SCHEMA_V1;o.query.timeout_ms=10;
 for(unsigned i=1;i<=2;i++){
  o.raw_ordinal++;o.query.ordinal=i;o.query.stream_id=i*2-1;o.query.dns_valid=i==1 || variant==1;o.query.timed_out=!o.query.dns_valid;
  o.query.response=(d2k_ver_result){.level=D2K_VER_APPLICATION,.status=200,.body_complete=o.query.dns_valid,.budget_requests=i,.doh_replies=i-o.query.timed_out};
  o.transport.available=variant!=3;o.transport.sent_end=i==1?100:variant==4?99:variant==5?101:250;
  if(variant>=8) {
   o.transport.ack_seen=!(variant==13 && i==1);
   o.transport.acked_end=i==1?100:variant==8 || variant==13?117:variant==9?100:variant==11?101:variant==12?249:250;
   if(i==2 && variant>=14)o.transport.acked_end=variant==14 || variant>=17?117:175;
   if(variant==19)o.transport.ack_seen=0;
  }
  assert(d2k_application_model_add(m,&o)>0);
 }
 d2k_application_end e={.identity=&id,.experience=experience,.raw_ordinal=4,.tuple=o.tuple,.input=input,.input_length=sizeof input,.network_evidence=variant!=2,.result=o.query.response,.timeout_ms=10,.hello_wire=1200};
 if(variant==7)e.result.doh_replies=0;
 assert(!d2k_application_model_finish(m,&e));return m;
}
int main(void){
 for(native_profile=0;native_profile<2;native_profile++) {
 for(int i=0;i<14;i++){
  d2k_application_model *m=model(i);char *p=NULL;int rc=d2k_application_late_question(m,&p);
  assert(rc==(i==0 || i>=8?1:0));
  if(p){
   const char *cut=i==8?"split payload_start +17\n":i==11?"split payload_start +1\n":i==12?"split payload_start +149\n":"split payload_start +75\n";
   assert(strstr(p,"stream-offset 100\n") && strstr(p,"input 150 0 0\n") && strstr(p,cut));free(p);
  }
  d2k_application_model_free(m);
 }
 char *p=NULL;assert(d2k_application_late_question(NULL,&p)==0);
 unsigned char seen[D2K_LATE_SEEN_BYTES]={0};
 d2k_application_model *base=model(0),*trial=model(14);
 assert(d2k_application_late_refine(base,trial,seen,sizeof seen,&p)==1);
 assert(strstr(p,"split payload_start +17\n"));free(p);p=NULL;
 assert(d2k_application_late_refine(base,trial,seen,sizeof seen,&p)==0 && !p);
 d2k_application_model_free(trial);trial=model(16);
 assert(d2k_application_late_refine(base,trial,seen,sizeof seen,&p)==0 && !p);
 d2k_application_model_free(trial);trial=model(15);memset(seen,0,sizeof seen);
 assert(d2k_application_late_refine(base,trial,seen,sizeof seen,&p)==0 && !p);
 d2k_application_model_free(trial);
 for(int i=17;i<=19;i++) {
  trial=model(i);memset(seen,0,sizeof seen);
  assert(d2k_application_late_refine(base,trial,seen,sizeof seen,&p)==0 && !p);
  d2k_application_model_free(trial);
 }
 d2k_application_model_free(base);
 base=model(6);
 assert(d2k_application_late_composed_question(base,&p)==1);
 assert(strstr(p,"split payload_start +1\n") && strstr(p,"after-split 100 150 75\n"));
 free(p);p=NULL;trial=model(20);memset(seen,0,sizeof seen);
 assert(d2k_application_late_composed_refine(base,trial,seen,sizeof seen,&p)==1);
 assert(strstr(p,"split payload_start +1\n") && strstr(p,"after-split 100 150 17\n"));
 free(p);p=NULL;
 assert(d2k_application_late_composed_refine(base,trial,seen,sizeof seen,&p)==0 && !p);
 d2k_application_model_free(trial);trial=model(21);memset(seen,0,sizeof seen);
 assert(d2k_application_late_composed_refine(base,trial,seen,sizeof seen,&p)==0 && !p);
 d2k_application_model_free(trial);d2k_application_model_free(base);
 }
 return 0;
}
