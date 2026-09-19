/* Separate translation unit: core verdict and datapath verdict are distinct
 * public types. Exercise the real measured-result -> text -> TLV producer. */
#include <string.h>
#include "d2k_quicprobe.h"
#include "d2k_quichello.h"
#include "d2k_plantlv.h"

int fragment_fixture(int shape,int fake,uint8_t *tlv,size_t cap,size_t *len) {
    d2k_quic_arm a={0};a.original=1;a.frag_kind=shape;a.frag_survives=D2K_PROP_YES;
    a.kind=fake?D2K_QA_TTL:D2K_QA_FRAG;
    if(fake){a.ttl=3;a.copies=2;a.len=4;memcpy(a.bytes,"fake",4);}
    char text[1024],err[200];
    if(d2k_quic_arm_plan(&a,a.bytes,a.len,text,sizeof text))return -1;
    return d2k_plan_text_to_tlv(text,tlv,cap,len,err,sizeof err);
}
int fragment_input(uint8_t *p,size_t cap,size_t *len) {
    return d2k_quic_probe_initial("fragment.example",p,cap,len);
}
