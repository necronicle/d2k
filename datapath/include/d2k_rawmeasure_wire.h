#ifndef D2K_RAWMEASURE_WIRE_H
#define D2K_RAWMEASURE_WIRE_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "d2k_ctq.h"
#include "d2k_rawmeasure.h"
/* Original directed tuple(38), table epoch(16), incarnation(8), token(16),
 * observation seconds(1). Explicit network order, never C struct layout. */
#define D2K_RM_REQUEST_LEN 79u
/* Existing observation completion grace; shared by both lifecycle peers. */
#define D2K_RM_GRACE_S 15u
struct d2k_rawmeasure_request {
    d2k_ct_tuple tuple;
    uint8_t epoch[16];
    uint64_t generation;
    uint8_t token[16];
    uint8_t seconds, renew; /* v28: high bit is renew-only; zero seconds cancels own observation. */
};
static inline int d2k_rm_nonzero(const uint8_t *p,size_t n) {
    uint8_t any=0;for(size_t i=0;i<n;i++)any|=p[i];return any!=0;
}
static inline int d2k_rawmeasure_request_valid(const struct d2k_rawmeasure_request *r) {
    if(!r || (r->tuple.family!=4&&r->tuple.family!=6) ||
       (r->tuple.proto!=6&&r->tuple.proto!=17) || !r->generation ||
       r->renew>1 || (!r->seconds&&!r->renew) || r->seconds>120 || !d2k_rm_nonzero(r->epoch,16) ||
       !d2k_rm_nonzero(r->token,16) || !d2k_rm_nonzero(r->tuple.sport_be,2) ||
       !d2k_rm_nonzero(r->tuple.dport_be,2))return 0;
    if(r->tuple.family==4 && (d2k_rm_nonzero(r->tuple.src+4,12)||d2k_rm_nonzero(r->tuple.dst+4,12)))return 0;
    return 1;
}
static inline int d2k_rawmeasure_request_write(uint8_t *p,size_t n,const struct d2k_rawmeasure_request *r) {
    if(!p || n!=D2K_RM_REQUEST_LEN || !d2k_rawmeasure_request_valid(r))return -1;
    p[0]=r->tuple.family;p[1]=r->tuple.proto;
    memcpy(p+2,r->tuple.src,16);memcpy(p+18,r->tuple.dst,16);
    memcpy(p+34,r->tuple.sport_be,2);memcpy(p+36,r->tuple.dport_be,2);
    memcpy(p+38,r->epoch,16);
    for(unsigned i=0;i<8;i++)p[54+i]=(uint8_t)(r->generation>>(56-8*i));
    memcpy(p+62,r->token,16);p[78]=(uint8_t)(r->seconds|(r->renew?128:0));return 0;
}
static inline int d2k_rawmeasure_request_read(struct d2k_rawmeasure_request *out,const uint8_t *p,size_t n) {
    if(!out || !p || n!=D2K_RM_REQUEST_LEN)return -1;
    struct d2k_rawmeasure_request r;memset(&r,0,sizeof r);
    r.tuple.family=p[0];r.tuple.proto=p[1];
    memcpy(r.tuple.src,p+2,16);memcpy(r.tuple.dst,p+18,16);
    memcpy(r.tuple.sport_be,p+34,2);memcpy(r.tuple.dport_be,p+36,2);
    memcpy(r.epoch,p+38,16);
    for(unsigned i=0;i<8;i++)r.generation=(r.generation<<8)|p[54+i];
    memcpy(r.token,p+62,16);r.seconds=p[78]&127;r.renew=p[78]>>7;
    if(!d2k_rawmeasure_request_valid(&r))return -1;
    *out=r;return 0;
}
/* Final observation facts, not an application-success verdict. TCP presence
 * requires cumulative ACK coverage of the sampled bytes; duplicate ACKs
 * remain counted and carry their exact value without claiming progress. The full
 * request binds them to an exact connection, controller lease and epoch. */
/* v27: + interval between the last two exact copies and its age at report
 * (ms, monotonic, saturating). Zero without an exact repeat. */
#define D2K_RM_REPORT_LEN 147u
#define D2K_RM_SAMPLE_DIGEST_LEN 32u
#define D2K_RM_PRIOR_REPLY 1u
#define D2K_RM_CHANGED 2u
#define D2K_RM_OVERSIZED 4u
#define D2K_RM_TCP_ACK 8u
struct d2k_rawmeasure_report {
    struct d2k_rawmeasure_request request;
    uint8_t code, flags;
    uint8_t sample_digest[D2K_RM_SAMPLE_DIGEST_LEN];
    uint16_t sample_len, smallest_data, largest_data;
    uint32_t sample_seq, client_data, exact_repeats, server_packets, tcp_ack;
    uint32_t repeat_gap_ms, repeat_age_ms;
};
static inline uint32_t d2k_rm_ms(uint64_t ns) {
    uint64_t ms=ns/1000000u;return ms>UINT32_MAX?UINT32_MAX:(uint32_t)ms;
}
static inline int d2k_rawmeasure_report_valid(const struct d2k_rawmeasure_report *r) {
    if (!r || !d2k_rawmeasure_request_valid(&r->request) || r->request.renew ||
        r->code < D2K_RM_SERVER_PRESENT || r->code > D2K_RM_UNMEASURED ||
        (r->flags & ~15u) || r->sample_len > D2K_RAWMEASURE_SAMPLE ||
        r->smallest_data > r->largest_data) return 0;
    if (!!r->sample_len != !!d2k_rm_nonzero(r->sample_digest,D2K_RM_SAMPLE_DIGEST_LEN)) return 0;
    if (!r->client_data && (r->sample_len || r->smallest_data || r->largest_data || r->exact_repeats)) return 0;
    if (!r->exact_repeats && (r->repeat_gap_ms || r->repeat_age_ms)) return 0;
    if (r->client_data && (!r->smallest_data || !r->largest_data)) return 0;
    if (r->sample_len && (r->sample_len < r->smallest_data || r->sample_len > r->largest_data)) return 0;
    /* Saturated counters may coincide; otherwise one packet owns the sample. */
    if (r->exact_repeats && (!r->sample_len || r->exact_repeats > r->client_data ||
        (r->exact_repeats == r->client_data && r->client_data != UINT32_MAX))) return 0;
    if (!!(r->flags & D2K_RM_OVERSIZED) != (r->largest_data > D2K_RAWMEASURE_SAMPLE)) return 0;
    int tcp=r->request.tuple.proto==6, ack=(r->flags&D2K_RM_TCP_ACK)!=0;
    if((ack && (!tcp || !r->server_packets)) || (!ack && r->tcp_ack))return 0;
    int progress=r->server_packets && (!tcp ||
        (ack && d2k_rm_ack_covers(r->tcp_ack,r->sample_seq,r->sample_len)));
    if ((r->code == D2K_RM_UNINFORMATIVE || r->code == D2K_RM_UNMEASURED) && progress) return 0;
    if (r->code == D2K_RM_SERVER_PRESENT && !progress) return 0;
    if (r->code == D2K_RM_REPEAT_SILENT &&
        (!r->exact_repeats || progress || (r->server_packets && (!tcp || !ack)) ||
         (r->flags & (D2K_RM_CHANGED|D2K_RM_OVERSIZED)) ||
         (r->request.tuple.proto == 17 && !(r->flags & D2K_RM_PRIOR_REPLY)))) return 0;
    if (r->code == D2K_RM_UNMEASURED && !(r->flags & D2K_RM_OVERSIZED)) return 0;
    return 1;
}
static inline void d2k_rm_put32(uint8_t *p, uint32_t v) {
    for (unsigned i=0;i<4;i++) p[i]=(uint8_t)(v>>(24-8*i));
}
static inline uint32_t d2k_rm_get32(const uint8_t *p) {
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
}
static inline int d2k_rawmeasure_report_write(uint8_t *p,size_t n,const struct d2k_rawmeasure_report *r) {
    if (!p || n!=D2K_RM_REPORT_LEN || !d2k_rawmeasure_report_valid(r)) return -1;
    if (d2k_rawmeasure_request_write(p,D2K_RM_REQUEST_LEN,&r->request)) return -1;
    p[79]=r->code;p[80]=r->flags;
    p[81]=(uint8_t)(r->sample_len>>8);p[82]=(uint8_t)r->sample_len;
    p[83]=(uint8_t)(r->smallest_data>>8);p[84]=(uint8_t)r->smallest_data;
    p[85]=(uint8_t)(r->largest_data>>8);p[86]=(uint8_t)r->largest_data;
    d2k_rm_put32(p+87,r->sample_seq);d2k_rm_put32(p+91,r->client_data);
    d2k_rm_put32(p+95,r->exact_repeats);d2k_rm_put32(p+99,r->server_packets);
    memcpy(p+103,r->sample_digest,D2K_RM_SAMPLE_DIGEST_LEN);
    d2k_rm_put32(p+135,r->tcp_ack);
    d2k_rm_put32(p+139,r->repeat_gap_ms);d2k_rm_put32(p+143,r->repeat_age_ms);
    return 0;
}
static inline int d2k_rawmeasure_report_read(struct d2k_rawmeasure_report *out,const uint8_t *p,size_t n) {
    if (!out || !p || n!=D2K_RM_REPORT_LEN) return -1;
    struct d2k_rawmeasure_report r;memset(&r,0,sizeof r);
    if (d2k_rawmeasure_request_read(&r.request,p,D2K_RM_REQUEST_LEN)) return -1;
    r.code=p[79];r.flags=p[80];
    r.sample_len=(uint16_t)((uint16_t)p[81]<<8|p[82]);
    r.smallest_data=(uint16_t)((uint16_t)p[83]<<8|p[84]);
    r.largest_data=(uint16_t)((uint16_t)p[85]<<8|p[86]);
    r.sample_seq=d2k_rm_get32(p+87);r.client_data=d2k_rm_get32(p+91);
    r.exact_repeats=d2k_rm_get32(p+95);r.server_packets=d2k_rm_get32(p+99);
    memcpy(r.sample_digest,p+103,D2K_RM_SAMPLE_DIGEST_LEN);
    r.tcp_ack=d2k_rm_get32(p+135);
    r.repeat_gap_ms=d2k_rm_get32(p+139);r.repeat_age_ms=d2k_rm_get32(p+143);
    if (!d2k_rawmeasure_report_valid(&r)) return -1;
    *out=r;return 0;
}
#endif
