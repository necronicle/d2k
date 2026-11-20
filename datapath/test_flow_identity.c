#include <stdio.h>
#include <string.h>
#include "d2k_track.h"
static int fail;
#define CHECK(x) do {if(!(x)){printf("FAIL %d: %s\n",__LINE__,#x);fail++;}} while(0)
int main(void) {
 d2k_key k={0};k.proto=6;k.low_ip=1;k.high_ip=2;k.low_port=123;k.high_port=443;
 d2k_table *t=d2k_track_new(8);if(!t)return 2;
 d2k_flow *f=d2k_track_get(t,&k,10);if(!f)return 2;
 CHECK(f->incarnation!=0);uint64_t first=f->incarnation;uint8_t epoch[16];memcpy(epoch,f->flow_epoch,16);
 uint8_t zero[16]={0};CHECK(memcmp(epoch,zero,16)!=0);
 CHECK(d2k_track_get(t,&k,20)->incarnation==first);
 d2k_track_new_connection(f);CHECK(f->incarnation!=first);CHECK(!memcmp(f->flow_epoch,epoch,16));
 uint64_t second=f->incarnation;d2k_track_remove(t,&k);f=d2k_track_get(t,&k,10);
 CHECK(f->incarnation!=first && f->incarnation!=second);CHECK(!memcmp(f->flow_epoch,epoch,16));
 d2k_track_free(t);t=d2k_track_new(8);if(!t)return 2;f=d2k_track_get(t,&k,10);if(!f)return 2;
 CHECK(memcmp(f->flow_epoch,epoch,16)!=0);d2k_track_free(t);
 puts(fail?"flow identity FAILED":"flow identity passed");return fail!=0;
}
