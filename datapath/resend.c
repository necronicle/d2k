#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "d2k_packet.h"
#include "d2k_resend.h"

static void w16(uint8_t *p, size_t n) {
    p[0]=(uint8_t)(n>>8); p[1]=(uint8_t)n;
}
static void w32(uint8_t *p, uint32_t n) {
    p[0]=(uint8_t)(n>>24); p[1]=(uint8_t)(n>>16);
    p[2]=(uint8_t)(n>>8); p[3]=(uint8_t)n;
}
static uint32_t sum16(const uint8_t *p, size_t n, uint32_t s) {
    while (n>=2) { s+=((uint32_t)p[0]<<8)|p[1]; p+=2; n-=2; }
    if (n) s+=(uint32_t)*p<<8;
    return s;
}
static uint16_t checksum(uint32_t s) {
    while (s>>16) s=(s&0xffffu)+(s>>16);
    return (uint16_t)~s;
}

int d2k_resend_original(const uint8_t *p, size_t n, size_t cap,
                        int (*send)(void *, const uint8_t *, size_t),
                        void *ctx, size_t *sent) {
    if (sent) *sent=0;
    if (!p || !n || !send || !sent) { errno=EINVAL; return -1; }
    /* Preserve the old byte-for-byte path, including offloaded checksums. */
    if (!cap || n<=cap) {
        if (send(ctx,p,n)!=0) return -1;
        *sent=1; return 0;
    }
    d2k_packet_view ip;
    if (!d2k_packet_parse(p,n,&ip) || ip.protocol!=6 || ip.total!=n ||
        (ip.fragment&0x3fffu)) { errno=EINVAL; return -1; }
    const uint8_t *tcp=p+ip.l4;
    size_t th=(size_t)(tcp[12]>>4)*4, header=ip.l4+th;
    if (th<20 || header>=n) { errno=EINVAL; return -1; }
    /* FIN/RST do not belong to a hello. SYN consumes sequence space; URG
     * needs pointer adjustment. None can be silently treated as data. */
    if (tcp[13]&(0x01u|0x04u|0x02u|0x20u)) { errno=EOPNOTSUPP; return -1; }
    if (cap<=header) { errno=EMSGSIZE; return -1; }
    size_t payload=n-header, chunk=cap-header;
    uint32_t seq=(uint32_t)tcp[4]<<24 | (uint32_t)tcp[5]<<16 |
                 (uint32_t)tcp[6]<<8 | tcp[7];
    size_t pieces=1+(payload-1)/chunk;
    uint16_t first_id=ip.ip_id;
    /* IP_HDRINCL replaces ID zero. Keep a consecutive nonzero range so the
     * socket cannot turn a wrapped/zero ID into an unrelated or duplicate ID.
     * IPv4's total-length bound ensures pieces < 65536 even at one byte. */
    if (ip.family==4 && (!first_id || pieces-1>(size_t)(UINT16_MAX-first_id))) first_id=1;
    uint8_t *out=malloc(cap);
    if (!out) { errno=ENOMEM; return -1; }
    /* Only one segment buffer is needed; the original remains owned by hold. */
    for (size_t off=0; off<payload;) {
        size_t data=payload-off;
        if (data>chunk) data=chunk;
        size_t len=header+data;
        memcpy(out,p,header);
        memcpy(out+header,p+header+off,data);
        w32(out+ip.l4+4,seq+(uint32_t)off);
        if (off+data<payload) out[ip.l4+13]&=(uint8_t)~0x08u;
        if (ip.family==4) {
            w16(out+2,len);
            w16(out+4,(uint16_t)(first_id+*sent));
            out[10]=out[11]=0;
            w16(out+10,checksum(sum16(out,ip.l4,0)));
        } else {
            w16(out+4,len-40);
        }
        size_t tcp_len=len-ip.l4;
        uint32_t pseudo=(uint32_t)tcp_len+6;
        pseudo=sum16(out+(ip.family==6 ? 8 : 12),ip.family==6 ? 32 : 8,pseudo);
        out[ip.l4+16]=out[ip.l4+17]=0;
        w16(out+ip.l4+16,checksum(sum16(out+ip.l4,tcp_len,pseudo)));
        if (send(ctx,out,len)!=0) {
            int saved=errno; free(out); errno=saved; return -1;
        }
        (*sent)++;
        off+=data;
    }
    free(out);
    return 0;
}
