#include <string.h>
#include "d2k_postnat_capture.h"
#include "d2k_packet.h"

static int udp(const uint8_t *p, size_t n, d2k_packet_view *v) {
    return d2k_packet_parse(p,n,v) && v->protocol==17 &&
        !(v->fragment&0x3fff) && v->total==n &&
        d2k_packet_u16(p+v->l4+4)==v->total-v->l4;
}
int d2k_postnat_udp_tuple(const uint8_t *p,size_t n,d2k_ct_tuple *out) {
    d2k_packet_view v;
    if(!out || !udp(p,n,&v))return 0;
    d2k_ct_tuple t={0}; t.family=v.family; t.proto=17;
    size_t a=v.family==6?16:4;
    memcpy(t.src,v.src.bytes,a);memcpy(t.dst,v.dst.bytes,a);
    memcpy(t.sport_be,p+v.l4,2);memcpy(t.dport_be,p+v.l4+2,2);
    *out=t;return 1;
}
int d2k_postnat_udp_match(const uint8_t *p,size_t n,const uint8_t *c,size_t cn,
    const d2k_ct_info *mapping) {
    d2k_packet_view a,b;
    if(!mapping || !mapping->reply_tuple_known || !udp(p,n,&a) || !udp(c,cn,&b) ||
       a.family!=b.family || a.total-a.l4!=b.total-b.l4)return 0;
    const d2k_ct_tuple *r=&mapping->reply_tuple;
    size_t alen=a.family==6?16:4;
    if(r->family!=a.family || r->proto!=17 ||
       memcmp(b.src.bytes,r->dst,alen) || memcmp(b.dst.bytes,r->src,alen) ||
       memcmp(c+b.l4,r->dport_be,2) || memcmp(c+b.l4+2,r->sport_be,2))return 0;
    /* NAT may change addresses, ports and checksums, but cannot change the
       application's datagram. IP identifiers distinguish adjacent packets. */
    if((a.family==4 && a.ip_id!=b.ip_id) ||
       (a.family==6 && a.flow_label!=b.flow_label))return 0;
    return memcmp(p+a.l4+8,c+b.l4+8,a.total-a.l4-8)==0;
}
