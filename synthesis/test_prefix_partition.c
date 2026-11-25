#include "lower.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void check_partition(const uint8_t *original, size_t total,
                            const d2k_payload_piece *pieces, size_t count) {
    const uint8_t prefix[]={22,3,3,0,1,0};
    char *text=NULL,err[200];uint8_t tlv[D2K_PLAN_TLV_MAX];size_t length;
    assert(d2k_lower_tls_prefix_partition(prefix,sizeof prefix,1400,0,
        total,pieces,count,&text,err,sizeof err)==D2K_LOWER_OK);
    assert(!d2k_plan_text_to_tlv(text,tlv,sizeof tlv,&length,err,sizeof err));
    d2k_plan *plan=NULL;assert(!d2k_plan_load(tlv,length,&plan,err,sizeof err));
    d2k_pkt in={.payload=original,.payload_len=total,.seq=UINT32_MAX-4,
        .have_sni=1,.sni_off=10,.sni_len=5,.emit_original=1};
    d2k_actions out;
    assert(!d2k_plan_apply(plan,NULL,&in,&out));
    assert(out.fate==D2K_ORIG_DROP && out.n==count+1);
    assert(out.v[0].kind==D2K_EMIT_FAKE && out.v[0].len==sizeof prefix);
    assert(!memcmp(out.v[0].bytes,prefix,sizeof prefix));
    for(size_t i=0;i<count;i++) {
        assert(out.v[i+1].kind==D2K_EMIT_PAYLOAD && !out.v[i+1].poison);
        assert(out.v[i+1].len==pieces[i].length);
        assert(out.v[i+1].delay_us==pieces[i].delay_us);
        assert(out.v[i+1].seq==in.seq+(uint32_t)pieces[i].offset);
        assert(!memcmp(out.v[i+1].bytes,original+pieces[i].offset,pieces[i].length));
    }
    d2k_actions_free(&out);
    if (strstr(text,"order emissions=")) {
        in.payload_len = total - 1;
        assert(d2k_plan_apply(plan,NULL,&in,&out) != 0);
        assert(out.n == 0 && out.fate == D2K_ORIG_PASS);
        d2k_actions_free(&out);
    }
    d2k_plan_free(plan);free(text);
}

static void check_overlap(void) {
    uint8_t original[20] = {22,3,3,0,15,1,0,0,11};
    for (size_t i=9;i<sizeof original;i++) original[i]=(uint8_t)i;
    d2k_payload_piece pieces[]={{0,1,0},{1,7,0},{8,12,0}};
    const uint8_t overlap=0;
    char *text=NULL,err[160];
    assert(d2k_lower_partition_overlap_observed(sizeof original,pieces,3,"tls",
        10,5,&overlap,1,&text,err,sizeof err)==D2K_LOWER_OK);
    uint8_t tlv[D2K_PLAN_TLV_MAX];size_t size=0;
    assert(!d2k_plan_text_to_tlv(text,tlv,sizeof tlv,&size,err,sizeof err));
    d2k_plan *plan=NULL;
    assert(!d2k_plan_load(tlv,size,&plan,err,sizeof err));
    d2k_pkt input={.payload=original,.payload_len=sizeof original,.seq=1000,
        .have_sni=1,.sni_off=10,.sni_len=5,.emit_original=1};
    d2k_actions output;
    assert(!d2k_plan_apply(plan,NULL,&input,&output));
    assert(output.fate==D2K_ORIG_DROP && output.n==3);
    for(size_t i=0;i<3;i++) {
        const d2k_emit *e=&output.v[i];
        assert(e->kind==D2K_EMIT_PAYLOAD);
        assert(e->seq==1000+pieces[i].offset-(i==0));
        assert(e->len==pieces[i].length);
        assert(!memcmp(e->bytes,original+pieces[i].offset,e->len));
        assert(e->pre_len==(i==0));
        if(i==0)assert(e->pre[0]==0);
    }
    d2k_actions_free(&output);
    d2k_plan_free(plan);
    free(text);
}

int main(void) {
    check_overlap();
    uint8_t original[20]={22,3,3,0,15,1,0,0,11};
    for(size_t i=9;i<sizeof original;i++)original[i]=(uint8_t)i;
    for(size_t cut=1;cut<sizeof original;cut++) {
        d2k_payload_piece a={0,cut,0}, b={cut,sizeof original-cut,0};
        check_partition(original,sizeof original,(d2k_payload_piece[]){a,b},2);
        check_partition(original,sizeof original,(d2k_payload_piece[]){b,a},2);
    }
    for (size_t first = 1; first+1 < sizeof original; first++) {
        for (size_t second = first+1; second < sizeof original; second++) {
            const d2k_payload_piece parts[] = {
                {0,first,0}, {first,second-first,0}, {second,sizeof original-second,0}};
            for (size_t i = 0; i < 3; i++) {
                for (size_t j = 0; j < 3; j++) {
                    if (i == j) continue;
                    d2k_payload_piece ordered[] = {parts[i],parts[j],parts[3-i-j]};
                    if (j != 1) {
                        ordered[1].delay_us = 17;
                        ordered[2].delay_us = 17;
                    }
                    check_partition(original,sizeof original,ordered,3);
                }
            }
        }
    }
    puts("prefix partition: every boundary and order, exact bytes and sequence wrap PASS");
}
