#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static void composed_input(const char *wire) {
 char text[512];snprintf(text,sizeof text,"d2k-plan 1 17\nid 00000000000000000000000000000000\nproto tcp tls\nwire %s\ninput 4 0 0\nsplit payload_start +1\norder reverse\nafter-split 10 6 2\n",wire);
 uint8_t tlv[D2K_PLAN_TLV_MAX],bytes[]={1,2,3,4,5,6};size_t n;char err[200];
 uint32_t offset,length,cut;
 char first[512];snprintf(first,sizeof first,"d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire %s\ninput 4 0 0\nsplit payload_start +1\norder reverse\n",wire);
 char *composed=NULL;
 assert(!d2k_plan_text_compose_after_split(first,4,0,0,10,6,2,&composed,err,sizeof err));
 assert(!strcmp(composed,text));free(composed);composed=NULL;
 assert(d2k_plan_text_compose_after_split(first,5,0,0,10,6,2,&composed,err,sizeof err)<0 && !composed);
 assert(d2k_plan_text_compose_after_split(text,4,0,0,20,6,2,&composed,err,sizeof err)<0 && !composed);
 assert(d2k_plan_text_after_split(text,&offset,&length,&cut,err,sizeof err)==1);
 assert(offset==10 && length==6 && cut==2);
 assert(!d2k_plan_text_to_tlv(text,tlv,sizeof tlv,&n,err,sizeof err));
 d2k_plan *p=NULL;assert(!d2k_plan_load(tlv,n,&p,err,sizeof err));
 assert(d2k_plan_after_split(p,&offset,&length,&cut)==1);
 d2k_pkt in={.payload=bytes,.payload_len=4,.have_stream_offset=1,.stream_offset=0,.emit_original=1};
 d2k_actions out;
 assert(!d2k_plan_apply(p,NULL,&in,&out) && out.n==2);
 assert(out.v[0].len==3 && !memcmp(out.v[0].bytes,bytes+1,3));
 assert(out.v[1].len==1 && out.v[1].bytes[0]==1);d2k_actions_free(&out);
 in.stream_offset=10;in.payload_len=6;
 assert(!d2k_plan_apply(p,NULL,&in,&out) && out.n==2);
 assert(out.v[0].len==2 && !memcmp(out.v[0].bytes,bytes,2));
 assert(out.v[1].len==4 && !memcmp(out.v[1].bytes,bytes+2,4));d2k_actions_free(&out);
 in.stream_offset=11;in.payload=bytes+1;in.payload_len=5;in.after_split_retry=1;
 assert(!d2k_plan_apply(p,NULL,&in,&out) && out.n==2);
 assert(out.v[0].len==1 && out.v[0].bytes[0]==2);
 assert(out.v[1].len==4 && !memcmp(out.v[1].bytes,bytes+2,4));d2k_actions_free(&out);
 in.after_split_retry=0;in.payload=bytes;
 in.stream_offset=9;
 assert(d2k_plan_apply(p,NULL,&in,&out)<0 && !out.n);d2k_actions_free(&out);
 in.stream_offset=10;in.payload_len=5;
 assert(d2k_plan_apply(p,NULL,&in,&out)<0 && !out.n);d2k_actions_free(&out);
 in.have_stream_offset=0;
 assert(d2k_plan_apply(p,NULL,&in,&out)<0 && !out.n);d2k_actions_free(&out);
 d2k_plan_free(p);
 tlv[7]=16;
 assert(d2k_plan_load(tlv,n,&p,err,sizeof err)<0 && !p);
}
int main(void){
 composed_input("detect-tcp-v1");
 composed_input("tcp-template-v1");
 const char *text="d2k-plan 1 16\nid 00000000000000000000000000000000\nproto tcp tls\nstream-offset 1534\nsplit payload_start +2\norder forward\n";
 uint8_t tlv[D2K_PLAN_TLV_MAX];size_t n;char err[200];
 assert(!d2k_plan_text_to_tlv(text,tlv,sizeof tlv,&n,err,sizeof err));
 d2k_plan *p=NULL;assert(!d2k_plan_load(tlv,n,&p,err,sizeof err));
 uint8_t bytes[]={1,2,3,4};d2k_pkt in={.payload=bytes,.payload_len=sizeof bytes};d2k_actions out;
 assert(d2k_plan_apply(p,NULL,&in,&out)<0);assert(!out.n);d2k_actions_free(&out);
 in.have_stream_offset=1;in.stream_offset=1533;
 assert(d2k_plan_apply(p,NULL,&in,&out)<0);assert(!out.n);d2k_actions_free(&out);
 in.stream_offset=1534;in.seq=40000;
 assert(!d2k_plan_apply(p,NULL,&in,&out));assert(out.n==2);
 assert(out.v[0].len==2 && out.v[1].len==2);
 assert(!memcmp(out.v[0].bytes,bytes,2) && !memcmp(out.v[1].bytes,bytes+2,2));
 d2k_actions_free(&out);
 char invalid[512];snprintf(invalid,sizeof invalid,"%sstream-offset 1534\n",text);
 assert(d2k_plan_text_to_tlv(invalid,tlv,sizeof tlv,&n,err,sizeof err)<0);
 strcpy(invalid,text);strstr(invalid,"1 16")[3]='5';
 assert(d2k_plan_text_to_tlv(invalid,tlv,sizeof tlv,&n,err,sizeof err)<0);
 snprintf(invalid,sizeof invalid,"d2k-plan 1 16\nproto tcp tls\nstream-offset 2147483648\norder forward\n");
 assert(d2k_plan_text_to_tlv(invalid,tlv,sizeof tlv,&n,err,sizeof err)<0);
 snprintf(invalid,sizeof invalid,"d2k-plan 1 16\nproto udp quic\nstream-offset 1\norder forward\n");
 assert(d2k_plan_text_to_tlv(invalid,tlv,sizeof tlv,&n,err,sizeof err)<0);
 d2k_plan_free(p);puts("stream offset guard passed");return 0;
}
