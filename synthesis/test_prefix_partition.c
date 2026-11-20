#include "lower.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    uint8_t original[20]={22,3,3,0,15,1,0,0,11};
    for(size_t i=9;i<sizeof original;i++)original[i]=(uint8_t)i;
    uint8_t prefix[]={22,3,3,0,1,0};
    for(size_t cut=1;cut<sizeof original;cut++)for(int reverse=0;reverse<2;reverse++) {
        d2k_payload_piece pieces[2]={{0,cut,0},{cut,sizeof original-cut,0}};
        if(reverse){d2k_payload_piece swap=pieces[0];pieces[0]=pieces[1];pieces[1]=swap;}
        char *text=NULL,err[200];uint8_t tlv[D2K_PLAN_TLV_MAX];size_t length;
        assert(d2k_lower_tls_prefix_partition(prefix,sizeof prefix,1400,0,
            sizeof original,pieces,2,&text,err,sizeof err)==D2K_LOWER_OK);
        assert(!d2k_plan_text_to_tlv(text,tlv,sizeof tlv,&length,err,sizeof err));
        d2k_plan *plan=NULL;assert(!d2k_plan_load(tlv,length,&plan,err,sizeof err));
        d2k_pkt in={.payload=original,.payload_len=sizeof original,.seq=UINT32_MAX-4,
            .have_sni=1,.sni_off=10,.sni_len=5,.emit_original=1};
        d2k_actions out;
        assert(!d2k_plan_apply(plan,NULL,&in,&out));
        assert(out.fate==D2K_ORIG_DROP && out.n==3);
        assert(out.v[0].kind==D2K_EMIT_FAKE && out.v[0].len==sizeof prefix);
        assert(!memcmp(out.v[0].bytes,prefix,sizeof prefix));
        for(size_t i=0;i<2;i++) {
            assert(out.v[i+1].kind==D2K_EMIT_PAYLOAD && !out.v[i+1].poison);
            assert(out.v[i+1].len==pieces[i].length);
            assert(out.v[i+1].seq==in.seq+(uint32_t)pieces[i].offset);
            assert(!memcmp(out.v[i+1].bytes,original+pieces[i].offset,pieces[i].length));
        }
        d2k_actions_free(&out);d2k_plan_free(plan);free(text);
    }
    puts("prefix partition: every boundary, both orders, exact bytes and sequence wrap PASS");
}
