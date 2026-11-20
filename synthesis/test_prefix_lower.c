#include "lower.h"
#include "prefix_refine.h"
#include "d2k_plantlv.h"
#include "d2k_wire.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned rd32(const uint8_t *p){return (unsigned)p[0]<<24|(unsigned)p[1]<<16|(unsigned)p[2]<<8|p[3];}
int main(void){
    uint8_t original[167]={22,3,3,0,162,1,0,0,158,3,3};
    original[45]=2;original[46]=0x13;original[47]=1;original[48]=1;
    original[51]=115;original[55]=7;original[57]=5;original[60]=2;original[61]=original[62]='a';
    original[64]=21;original[66]=100;
    uint8_t prefix[63];memcpy(prefix,original,sizeof prefix);
    prefix[4]=58;prefix[8]=54;prefix[51]=11;prefix[61]='b';
    char *text=NULL,err[256];uint8_t tlv[D2K_PLAN_TLV_MAX];size_t size=0;
    assert(d2k_lower_tls_prefix(prefix,sizeof prefix,64,0,&text,err,sizeof err)==D2K_LOWER_OK);
    uint8_t reference[sizeof prefix];memcpy(reference,prefix,sizeof reference);
    reference[61]='c';reference[62]='d';char *other=NULL;
    assert(d2k_lower_tls_prefix(reference,sizeof reference,64,0,&other,err,sizeof err)==D2K_LOWER_OK);
    d2k_prefix_refiner *refiner=d2k_prefix_refiner_new_plans(text,other);assert(refiner);
    const char *proposal;uint64_t ticket;
    assert(d2k_prefix_refiner_next_plan(refiner,&ticket,&proposal)==1);
    assert(!d2k_plan_text_to_tlv(proposal,tlv,sizeof tlv,&size,err,sizeof err));
    prefix[61]='c'; /* Only the first differing byte is replaced in this question. */
    d2k_prefix_refiner_free(refiner);free(other);free(text);
    d2k_plan *plan=NULL;assert(!d2k_plan_load(tlv,size,&plan,err,sizeof err));
    d2k_pkt in={.payload=original,.payload_len=sizeof original,.seq=100,.have_sni=1,
        .sni_off=61,.sni_len=2,.emit_original=1};
    d2k_actions actions;int applied=d2k_plan_apply(plan,NULL,&in,&actions);if(applied)fprintf(stderr,"refusal: %s\n",actions.refuse_why);assert(!applied);
    assert(actions.n==4 && actions.fate==D2K_ORIG_DROP);
    d2k_conn conn={.ttl=64,.window=32000,.tcp_options_len=12,
        .tcp_options={1,1,8,10,0,0,7,208,0,0,0,77}};
    size_t covered=0;
    for(size_t i=0;i<actions.n;i++){
        const d2k_emit *e=&actions.v[i];uint8_t packet[512];
        size_t n=d2k_wire_build(&conn,e,packet,sizeof packet);
        assert(n && d2k_wire_tcp_checksum_ok(packet,n));
        assert(rd32(packet+44)==(i?2000:1000));
        if(!i){assert(e->kind==D2K_EMIT_FAKE && e->len==sizeof prefix && !memcmp(e->bytes,prefix,sizeof prefix));}
        else{assert(e->kind==D2K_EMIT_PAYLOAD && e->seq==100+covered);
            assert(e->len<=sizeof original-covered && !memcmp(e->bytes,original+covered,e->len));covered+=e->len;}
    }
    assert(covered==sizeof original);
    conn.tcp_options_len=0;uint8_t packet[512];assert(!d2k_wire_build(&conn,&actions.v[0],packet,sizeof packet));
    d2k_actions_free(&actions);d2k_plan_free(plan);
    assert(d2k_lower_tls_prefix(prefix,sizeof prefix,0,0,&text,err,sizeof err)==D2K_LOWER_INVALID && !text);
    assert(d2k_lower_tls_prefix(prefix,sizeof prefix,64,4,&text,err,sizeof err)==D2K_LOWER_INVALID && !text);
    assert(d2k_lower_tls_prefix(prefix,SIZE_MAX,64,0,&text,err,sizeof err)==D2K_LOWER_INVALID && !text);
    for(unsigned mods=1;mods<4;mods++){
        assert(d2k_lower_tls_prefix(prefix,sizeof prefix,64,mods,&text,err,sizeof err)==D2K_LOWER_OK);
        assert(!d2k_plan_text_to_tlv(text,tlv,sizeof tlv,&size,err,sizeof err));free(text);
        assert(!d2k_plan_load(tlv,size,&plan,err,sizeof err));
        assert(!d2k_plan_apply(plan,NULL,&in,&actions));d2k_actions_free(&actions);d2k_plan_free(plan);
    }
    return 0;
}
