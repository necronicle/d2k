#include <string.h>
#include "d2k_rawmeasure.h"
#include "d2k_packet.h"
static void increment(uint32_t *n) { if (*n != UINT32_MAX) ++*n; }
void d2k_rawmeasure_init(struct d2k_rawmeasure *m, const d2k_ct_tuple *t, uint64_t gen, int previous_reply) {
    memset(m,0,sizeof *m);m->tuple=*t;m->generation=gen;m->previous_reply=previous_reply!=0;
}
static int side(const d2k_ct_tuple *t,const d2k_packet_view *v,const uint8_t *h) {
    size_t n=t->family==6?16:4;
    if(v->family!=t->family || v->protocol!=t->proto)return 0;
    if(!memcmp(v->src.bytes,t->src,n)&&!memcmp(v->dst.bytes,t->dst,n)&&
       !memcmp(h,t->sport_be,2)&&!memcmp(h+2,t->dport_be,2))return 1;
    if(!memcmp(v->src.bytes,t->dst,n)&&!memcmp(v->dst.bytes,t->src,n)&&
       !memcmp(h,t->dport_be,2)&&!memcmp(h+2,t->sport_be,2))return 2;
    return 0;
}
int d2k_rawmeasure_feed(struct d2k_rawmeasure *m,uint64_t gen,const uint8_t *p,size_t n,uint64_t now_ns) {
    d2k_packet_view v;
    if(!m || !gen || gen!=m->generation || !d2k_packet_parse(p,n,&v) ||
       (v.protocol!=6 && v.protocol!=17) || (v.fragment&0x3fffu))return 0;
    const uint8_t *h=p+v.l4;size_t header=8;
    if(v.protocol==6){header=(size_t)(h[12]>>4)*4;if(header<20||header>v.total-v.l4)return 0;}
    else if(d2k_packet_u16(h+4)!=v.total-v.l4)return 0;
    int direction=side(&m->tuple,&v,h);if(!direction)return 0;
    if(v.protocol==6 && (h[13]&0x07u))m->closed=1; /* FIN/SYN/RST: no continuation experiment */
    if(direction==2){
        increment(&m->server_packets);
        if(v.protocol==6 && (h[13]&0x10u)) {
            uint32_t ack=(uint32_t)h[8]<<24|(uint32_t)h[9]<<16|(uint32_t)h[10]<<8|h[11];
            if(!m->tcp_ack_seen || (ack!=m->tcp_ack &&
               (uint32_t)(ack-m->tcp_ack)<UINT32_C(0x80000000)))m->tcp_ack=ack;
            m->tcp_ack_seen=1;
        }
        return 1;
    }
    increment(&m->client_packets);
    size_t len=v.total-v.l4-header;if(!len)return 1;
    increment(&m->client_data);
    if(!m->smallest_data || len<m->smallest_data)m->smallest_data=(uint16_t)len;
    if(len>m->largest_data)m->largest_data=(uint16_t)len;
    if(len>D2K_RAWMEASURE_SAMPLE){m->oversized=1;return 1;}
    uint32_t seq=v.protocol==6?((uint32_t)h[4]<<24|(uint32_t)h[5]<<16|(uint32_t)h[6]<<8|h[7]):0;
    const uint8_t *data=h+header;
    if(!m->sampled){m->sampled=1;m->sample_len=(uint16_t)len;m->sample_seq=seq;memcpy(m->sample,data,len);
        m->sample_ns=m->prev_copy_ns=m->last_copy_ns=now_ns;return 1;}
    if(m->sample_len==len && m->sample_seq==seq && !memcmp(m->sample,data,len)) {
        increment(&m->exact_repeats);m->prev_copy_ns=m->last_copy_ns;m->last_copy_ns=now_ns;
    } else m->changed=1;
    return 1;
}
enum d2k_rawmeasure_result d2k_rawmeasure_result(const struct d2k_rawmeasure *m,int expired) {
    if(m->closed)return D2K_RM_CLOSED;
    /* A reverse TCP packet can be a duplicate ACK for the missing bytes.
     * Keep its existence, but only cumulative delivery ends this observation. */
    if(m->server_packets && (m->tuple.proto==17 ||
       (m->tcp_ack_seen && d2k_rm_ack_covers(m->tcp_ack,m->sample_seq,m->sample_len))))
        return D2K_RM_SERVER_PRESENT;
    /* Once a matching repetition is observed, waiting for lease expiry adds
       no fact to this result. It remains a suspicion, never a DPI verdict.
       UDP additionally requires prior reply evidence in the same flow. */
    if(m->exact_repeats && !m->changed && !m->oversized &&
       (!m->server_packets || m->tuple.proto==17 || m->tcp_ack_seen)) {
        if(m->tuple.proto==6 || m->previous_reply)return D2K_RM_REPEAT_SILENT;
        /* Unknown one-way UDP has no demonstrated response expectation.
           More identical datagrams cannot establish one. Release observation
           as inconclusive instead of occupying delivery until lease expiry. */
        return D2K_RM_UNINFORMATIVE;
    }
    if(!expired)return D2K_RM_PENDING;
    if(m->oversized)return D2K_RM_UNMEASURED;
    return D2K_RM_UNINFORMATIVE;
}
