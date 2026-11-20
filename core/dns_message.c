#include "d2k_dns_message.h"
#include <stdlib.h>
#include <string.h>
static unsigned dns16(const uint8_t *p) {return (unsigned)p[0]<<8|p[1];}
/* Canonical wire name, retaining label lengths and arbitrary octets. ASCII
 * letters compare without case; compression pointers never change cursor's
 * original message position. Expansion and traversal are bounded by DNS size. */
static int dns_name(const uint8_t *bytes,size_t n,size_t *cursor,uint8_t out[255],size_t *out_length) {
    size_t p=*cursor,after=0,used=0,steps=0;
    while(p<n&&steps++<=n) {
        unsigned label=bytes[p++];
        if(!label) {
            if(used>=255)return -1;
            out[used++]=0;*out_length=used;*cursor=after?after:p;return 0;
        }
        if((label&192)==192) {
            if(p>=n)return -1;
            size_t target=((size_t)(label&63)<<8)|bytes[p];
            /* RFC1035 §4.1.4: a prior name occurrence, outside the header. */
            if(target<12 || target>=p-1)return -1;
            if(!after)after=p+1;
            p=target;continue;
        }
        if(label>63||label>n-p||used+label+1>=255)return -1;
        out[used++]=(uint8_t)label;
        for(unsigned i=0;i<label;i++) {
            uint8_t c=bytes[p++];if(c>='A'&&c<='Z')c=(uint8_t)(c+'a'-'A');out[used++]=c;
        }
    }
    return -1;
}
#include "dns_question_wire.inc"
size_t d2k_dns_question(const char *name,uint16_t type,uint16_t id,uint8_t *out,size_t cap) {
    return dns_encode_question(name,type,id,out,cap);
}
int d2k_dns_question_valid(const uint8_t *q,size_t n) {
    if(!q || n<17 || n>UINT16_MAX || (q[2]&0xf8) || dns16(q+4)!=1 ||
        dns16(q+6) || dns16(q+8) || dns16(q+10))return -1;
    uint8_t name[255];size_t length=0,at=12;
    if(dns_name(q,n,&at,name,&length) || at+4!=n || !dns16(q+at) || dns16(q+at+2)!=1)
        return -1;
    return 0;
}
size_t d2k_dns_base64url(const uint8_t *query,size_t n,char *out) {
    static const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t at=0;
    for(size_t i=0;i<n;i+=3) {
        size_t left=n-i;uint32_t v=(uint32_t)query[i]<<16;
        if(left>1)v|=(uint32_t)query[i+1]<<8;
        if(left>2)v|=query[i+2];
        out[at++]=alphabet[(v>>18)&63];out[at++]=alphabet[(v>>12)&63];
        if(left>1)out[at++]=alphabet[(v>>6)&63];
        if(left>2)out[at++]=alphabet[v&63];
    }
    out[at]=0;return at;
}
static int doh_skip_rr(const uint8_t *b, size_t n, size_t *p) {
    uint8_t owner[255];size_t length;
    if (dns_name(b,n,p,owner,&length) != 0 || n - *p < 10) return -1;
    size_t rdlen = dns16(b + *p + 8);
    *p += 10;
    if (rdlen > n - *p) return -1;
    *p += rdlen;
    return 0;
}

int d2k_dns_answer_matches(const uint8_t *query, size_t qn, const uint8_t *b, size_t n, const char **why) {
    if (!why) return -1;
    if (!query || !b || qn < 12 || n < 12) { *why = "short DNS header"; return -1; }
    if (memcmp(b, query, 2) != 0) { *why = "DNS ID does not match query"; return -1; }
    if (!(b[2] & 0x80) || (b[2] & 0x7a)) {
        *why = "DNS response is not an un truncated standard-query answer";
        return -1;
    }
    unsigned rcode = b[3] & 15;
    if (rcode != 0 && rcode != 3) { *why = "DNS RCODE is not NOERROR or NXDOMAIN"; return -1; }
    if(qn<17||(query[2]&0xf8)||dns16(query+4)!=1||dns16(b+4)!=1) {*why="DNS question count differs";return -1;}
    size_t qp=12,p=12,ql=0,rl=0;uint8_t qname[255],rname[255];
    if(dns_name(query,qn,&qp,qname,&ql)||dns_name(b,n,&p,rname,&rl)||ql!=rl||memcmp(qname,rname,ql)||
       qp+4!=qn||p+4>n||memcmp(query+qp,b+p,4)) {*why="DNS question differs";return -1;}
    p+=4;
    for (size_t section = 0; section < 3; section++) {
        unsigned count = dns16(b + 6 + section * 2);
        for (unsigned i = 0; i < count; i++) {
            if (doh_skip_rr(b, n, &p) != 0) { *why = "malformed DNS resource record"; return -1; }
        }
    }
    if (p != n) { *why = "trailing bytes after DNS message"; return -1; }
    return 0;
}
struct address_rr {
    uint8_t owner[255],target[255];size_t owner_length,target_length;
    unsigned type,klass;uint32_t ttl;size_t offset,length;
};
size_t d2k_dns_address_memory_bound(size_t records,size_t capacity) {
    size_t bound=capacity<records?capacity:records;
    if(records>SIZE_MAX/sizeof(struct address_rr) || bound>SIZE_MAX/sizeof(struct d2k_dns_address))return SIZE_MAX;
    size_t bytes=records*sizeof(struct address_rr),output=bound*sizeof(struct d2k_dns_address);
    return output>SIZE_MAX-bytes?SIZE_MAX:bytes+output;
}
static uint32_t dns32(const uint8_t *p) {
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
}
static int same_name(const uint8_t *a,size_t an,const uint8_t *b,size_t bn) {
    return an==bn && !memcmp(a,b,an);
}
enum d2k_dns_address_status d2k_dns_answer_addresses(const uint8_t *q,size_t qn,
    const uint8_t *b,size_t n,struct d2k_dns_address *out,size_t capacity,size_t *count,
    size_t max_records) {
    if(!count || (capacity && !out) || capacity>SIZE_MAX/sizeof *out ||
        d2k_dns_question_valid(q,qn) || !b || n<12 || n>UINT16_MAX)
        return D2K_DNS_ADDRESS_INVALID;
    unsigned type=dns16(q+qn-4);
    if(type!=1 && type!=28)return D2K_DNS_ADDRESS_INVALID; /* RFC1035 A; RFC3596 AAAA. */
    size_t total=(size_t)dns16(b+6)+dns16(b+8)+dns16(b+10);
    if(total>max_records)return D2K_DNS_ADDRESS_LIMIT;
    const char *reason=NULL;
    if(d2k_dns_answer_matches(q,qn,b,n,&reason))return D2K_DNS_ADDRESS_INVALID;
    if((b[3]&15)==3 || !dns16(b+6)){*count=0;return D2K_DNS_ADDRESS_OK;}
    size_t records=dns16(b+6);
    if(records>SIZE_MAX/sizeof(struct address_rr))return D2K_DNS_ADDRESS_LIMIT;
    struct address_rr *rr=calloc(records,sizeof *rr);
    size_t bound=capacity<records?capacity:records;
    struct d2k_dns_address *pending=bound?calloc(bound,sizeof *pending):NULL;
    enum d2k_dns_address_status status=D2K_DNS_ADDRESS_INVALID;
    if(!rr || (bound && !pending)){status=D2K_DNS_ADDRESS_LOCAL;goto done;}
    uint8_t current[255];size_t current_length=0,p=12;
    if(dns_name(b,n,&p,current,&current_length))goto done;
    p+=4;
    for(size_t i=0;i<records;i++) {
        struct address_rr *r=rr+i;
        if(dns_name(b,n,&p,r->owner,&r->owner_length) || n-p<10)goto done;
        r->type=dns16(b+p);r->klass=dns16(b+p+2);r->ttl=dns32(b+p+4);
        /* RFC2181 §8: an encoded sign bit makes the received TTL zero. */
        if(r->ttl&UINT32_C(0x80000000))r->ttl=0;
        r->length=dns16(b+p+8);p+=10;r->offset=p;
        if(r->length>n-p)goto done;
        p+=r->length;
        if(r->klass!=1)continue;
        if((r->type==1 && r->length!=4) || (r->type==28 && r->length!=16))goto done;
        if(r->type==5) {
            size_t at=r->offset;
            if(dns_name(b,n,&at,r->target,&r->target_length) || at!=p)goto done;
        }
    }
    uint32_t chain_ttl=UINT32_MAX;
    for(size_t hops=0;hops<=records;hops++) {
        const struct address_rr *alias=NULL;int address_present=0;
        uint32_t alias_ttl=UINT32_MAX,rrset_ttl=chain_ttl;
        for(size_t i=0;i<records;i++) {
            const struct address_rr *r=rr+i;
            if(r->klass!=1 || !same_name(current,current_length,r->owner,r->owner_length))continue;
            if(r->type==1 || r->type==28)address_present=1;
            /* RFC2181 §5.2: configured resolver RRset uses its lowest TTL. */
            if(r->type==type && r->ttl<rrset_ttl)rrset_ttl=r->ttl;
            if(r->type!=5)continue;
            if(alias && !same_name(alias->target,alias->target_length,r->target,r->target_length))goto done;
            alias=r;if(r->ttl<alias_ttl)alias_ttl=r->ttl;
        }
        if(alias) {
            /* RFC1034 §3.6.2: CNAME identifies one canonical name. */
            if(address_present)goto done;
            memcpy(current,alias->target,alias->target_length);current_length=alias->target_length;
            if(alias_ttl<chain_ttl)chain_ttl=alias_ttl;
            continue;
        }
        size_t used=0;
        for(size_t i=0;i<records;i++) {
            const struct address_rr *r=rr+i;
            if(r->klass!=1 || r->type!=type ||
                !same_name(current,current_length,r->owner,r->owner_length))continue;
            size_t at;
            for(at=0;at<used;at++)if(!memcmp(pending[at].address,b+r->offset,r->length))break;
            uint32_t life=rrset_ttl;
            if(at<used){if(life<pending[at].ttl)pending[at].ttl=life;continue;}
            if(used==bound){status=D2K_DNS_ADDRESS_LIMIT;goto done;}
            pending[used].family=type==1?4:6;pending[used].ttl=life;
            memcpy(pending[used].address,b+r->offset,r->length);used++;
        }
        if(used)memcpy(out,pending,used*sizeof *out);
        *count=used;status=D2K_DNS_ADDRESS_OK;goto done;
    }
    /* More alias transitions than answer records implies a cycle. */
done:
    free(pending);free(rr);return status;
}
