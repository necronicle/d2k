#include "d2k_dns_family.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned rd16(const uint8_t *p) {return (unsigned)p[0]*256u+p[1];}
static void wr16(uint8_t *p,unsigned v) {p[0]=(uint8_t)(v>>8);p[1]=(uint8_t)v;}

enum { DNS_AAAA=28, DNS_OPT=41, DNS_HTTPS=65 };
enum { SVC_MANDATORY=0, SVC_IPV6HINT=6 };

static uint32_t sum_bytes(uint32_t sum,const uint8_t *p,size_t n) {
    while(n>=2){sum+=rd16(p);p+=2;n-=2;}
    if(n)sum+=(unsigned)p[0]<<8;
    return sum;
}
static uint16_t checksum(uint32_t sum) {
    while(sum>>16)sum=(sum&0xffffu)+(sum>>16);
    return (uint16_t)~sum;
}

static int dns_name_skip(const uint8_t *d,size_t size,size_t *at) {
    size_t p=*at;
    for(unsigned labels=0;labels<128;labels++) {
        if(p>=size)return 0;
        unsigned n=d[p++];
        if((n&0xc0u)==0xc0u) {
            if(p>=size || (((n&0x3fu)<<8)|d[p])>=size)return 0;
            *at=p+1;return 1;
        }
        if(n&0xc0u)return 0;
        if(!n){*at=p;return 1;}
        if(n>63 || n>size-p)return 0;
        p+=n;
    }
    return 0;
}
static int same_question(const uint8_t *d,size_t size,size_t *at,const char *name) {
    size_t p=*at,j=0;
    for(unsigned labels=0;labels<128;labels++) {
        if(p>=size)return 0;
        unsigned n=d[p++];
        if(!n) {
            if(!j || name[j] || size-p<4 || rd16(d+p+2)!=1)return 0;
            unsigned type=rd16(d+p);
            if(type!=DNS_AAAA && type!=DNS_HTTPS)return 0;
            *at=p+4;return 1;
        }
        if(n>63 || n>size-p || j+n+1>=256)return 0;
        if(j) {if(name[j++]!='.')return 0;}
        for(unsigned k=0;k<n;k++) {
            unsigned a=d[p++],b=(unsigned char)name[j++];
            if(a>='A'&&a<='Z')a+=32;
            if(b>='A'&&b<='Z')b+=32;
            if(a!=b)return 0;
        }
    }
    return 0;
}

static int udp_dns(const uint8_t *packet,size_t size,uint8_t *family,
    size_t *ip_len,const uint8_t **udp,const uint8_t **dns,size_t *dns_len) {
    if(size>=20 && (packet[0]>>4)==4) {
        *family=4;*ip_len=(packet[0]&15u)*4u;
        if(*ip_len<20||*ip_len>size||rd16(packet+2)!=size||
           (rd16(packet+6)&0x3fffu)||packet[9]!=17)return 0;
    } else if(size>=40 && (packet[0]>>4)==6) {
        *family=6;*ip_len=40;
        if(40u+rd16(packet+4)!=size||packet[6]!=17)return 0;
    } else return 0;
    if(size-*ip_len<20||rd16(packet+*ip_len+4)!=size-*ip_len)return 0;
    *udp=packet+*ip_len;
    *dns=*udp+8;
    *dns_len=size-*ip_len-8;
    return 1;
}

int d2k_dns_family_request_parse(const uint8_t *packet,size_t length,
    const d2k_dns_family_rule *rule,d2k_dns_family_request *out) {
    if(!packet||!rule||!out||!rule->name[0])return -1;
    uint8_t family;size_t ip_len,dns_len;const uint8_t *udp,*dns;
    if(!udp_dns(packet,length,&family,&ip_len,&udp,&dns,&dns_len)||
       family!=rule->client_family||rd16(udp+2)!=53||
       memcmp(packet+(family==4?12:8),rule->client,family==4?4:16))return 0;
    unsigned flags=rd16(dns+2);
    if((flags&0x8000u)||(flags&0x7a00u)||rd16(dns+4)!=1||
       rd16(dns+6)||rd16(dns+8)||rd16(dns+10)>1)return 0;
    size_t pos=12;
    if(!same_question(dns,dns_len,&pos,rule->name))return 0;
    uint16_t qtype=(uint16_t)rd16(dns+pos-4);
    int dnssec=(flags&0x0010u)!=0; /* CD in the original request */
    if(rd16(dns+10)) {
        if(!dns_name_skip(dns,dns_len,&pos)||dns_len-pos<10||rd16(dns+pos)!=41)return 0;
        dnssec|=(rd16(dns+pos+6)&0x8000u)!=0; /* EDNS DO */
        unsigned rlen=rd16(dns+pos+8);pos+=10;
        if(rlen>dns_len-pos)return 0;
        pos+=rlen;
    }
    if(pos!=dns_len)return 0;
    memset(out,0,sizeof *out);
    out->family=family;out->dnssec=(uint8_t)dnssec;
    out->client_port=(uint16_t)rd16(udp);out->id=(uint16_t)rd16(dns);
    out->qtype=qtype;
    memcpy(out->client,packet+(family==4?12:8),family==4?4:16);
    memcpy(out->server,packet+(family==4?16:24),family==4?4:16);
    snprintf(out->name,sizeof out->name,"%s",rule->name);
    return 1;
}

int d2k_dns_family_response_matches(const uint8_t *packet,size_t length,
    const d2k_dns_family_request *request) {
    if(!packet||!request)return 0;
    uint8_t family;size_t ip_len,dns_len;const uint8_t *udp,*dns;
    if(!udp_dns(packet,length,&family,&ip_len,&udp,&dns,&dns_len)||
       family!=request->family||rd16(udp)!=53||
       rd16(udp+2)!=request->client_port||rd16(dns)!=request->id||
       !(dns[2]&0x80)||rd16(dns+4)!=1)return 0;
    size_t width=family==4?4:16;
    if(memcmp(packet+(family==4?12:8),request->server,width)||
       memcmp(packet+(family==4?16:24),request->client,width))return 0;
    size_t pos=12;
    return same_question(dns,dns_len,&pos,request->name) &&
        rd16(dns+pos-4)==request->qtype;
}

typedef struct {
    size_t rdlength;
    size_t offset;
    size_t length;
} dns_hint_removal;

/* Only direct ServiceMode using the question name is covered by the lease.
 * The remaining SvcParams are opaque. Preserve the whole response when the
 * hint is mandatory or the service points to a different name. */
static int https_hint(const uint8_t *dns,size_t start,size_t end,dns_hint_removal *hint) {
    if(end-start<3 || !rd16(dns+start) || dns[start+2]!=0)return 0;
    unsigned previous=0;
    for(size_t at=start+3;at<end;) {
        if(end-at<4)return 0;
        unsigned key=rd16(dns+at),length=rd16(dns+at+2);
        size_t value=at+4;
        if(length>end-value || (at!=start+3 && key<=previous))return 0;
        if(key==SVC_MANDATORY) {
            if(!length || length%2)return 0;
            for(size_t p=value;p<value+length;p+=2)
                if(rd16(dns+p)==SVC_IPV6HINT)return 0;
        } else if(key==SVC_IPV6HINT) {
            if(!length || length%16)return 0;
            hint->offset=at;
            hint->length=4+length;
        }
        previous=key;
        at=value+length;
    }
    return 1;
}

static size_t rewrite_https(uint8_t *dns,size_t length,size_t question_end,
    unsigned answers,unsigned additional) {
    if(rd16(dns+2)&0x0030u)return 0; /* Preserve AD/CD and signed data. */
    dns_hint_removal removals[64];
    size_t count=0,pos=question_end;
    const size_t question_name_len=question_end-12-4;
    for(unsigned i=0;i<answers;i++) {
        size_t owner=pos;
        if(!dns_name_skip(dns,length,&pos) || length-pos<10)return 0;
        size_t owner_len=pos-owner;
        /* Only allow pointers to the question, whose offset never changes. */
        if(!(owner_len==2 && rd16(dns+owner)==0xc00c) &&
           !(owner_len==question_name_len && !memcmp(dns+owner,dns+12,owner_len)))return 0;
        if(rd16(dns+pos)!=DNS_HTTPS || rd16(dns+pos+2)!=1)return 0;
        unsigned rlen=rd16(dns+pos+8);
        dns_hint_removal hint={.rdlength=pos+8};
        pos+=10;
        if(rlen>length-pos || !https_hint(dns,pos,pos+rlen,&hint))return 0;
        if(hint.length)removals[count++]=hint;
        pos+=rlen;
    }
    if(additional) {
        /* The only extra record we can relocate unchanged is an unsigned OPT. */
        if(length-pos<11 || dns[pos]!=0 || rd16(dns+pos+1)!=DNS_OPT ||
           (rd16(dns+pos+7)&0x8000u) || rd16(dns+pos+9)!=length-pos-11)return 0;
        pos=length;
    }
    if(pos!=length || !count)return 0;
    /* Later records move first so the offsets we have yet to use stay valid. */
    while(count) {
        const dns_hint_removal *hint=&removals[--count];
        size_t tail=hint->offset+hint->length;
        wr16(dns+hint->rdlength,rd16(dns+hint->rdlength)-hint->length);
        memmove(dns+hint->offset,dns+tail,length-tail);
        length-=hint->length;
    }
    return length;
}

int d2k_dns_family_rewrite(uint8_t *packet,size_t *length,size_t capacity,
    const d2k_dns_family_rule *rule,int64_t now_unix,int ordinary_request_seen) {
    if(!packet||!length||!rule||*length>capacity)return -1;
    if(!ordinary_request_seen||!rule->name[0] || (rule->client_family!=4&&rule->client_family!=6) ||
       rule->expires_unix<=now_unix)return 0;
    size_t size=*length,ip_len;uint8_t family,protocol;
    if(size>=20 && (packet[0]>>4)==4) {
        family=4;ip_len=(packet[0]&15u)*4u;
        if(ip_len<20||ip_len>size||rd16(packet+2)!=size||
           (rd16(packet+6)&0x3fffu))return 0;
        protocol=packet[9];
    } else if(size>=40 && (packet[0]>>4)==6) {
        family=6;ip_len=40;
        if(40u+rd16(packet+4)!=size)return 0;
        protocol=packet[6];
    } else return 0;
    if(family!=rule->client_family||protocol!=17||
       memcmp(packet+(family==4?16:24),rule->client,family==4?4:16))return 0;
    size_t udp_len=size-ip_len;
    if(udp_len<20||rd16(packet+ip_len)!=53||rd16(packet+ip_len+4)!=udp_len)return 0;
    uint8_t *udp=packet+ip_len,*dns=udp+8;
    size_t dns_len=udp_len-8;
    unsigned flags=rd16(dns+2);
    if((flags&0x8000u)==0 || (flags&0x7fffu)&(0x7800u|0x0200u|0x000fu))return 0;
    if(rd16(dns+4)!=1||!rd16(dns+6)||rd16(dns+8)||rd16(dns+10)>1)return 0;
    size_t pos=12;
    if(!same_question(dns,dns_len,&pos,rule->name))return 0;
    size_t question_end=pos;
    unsigned answers=rd16(dns+6),additional=rd16(dns+10);
    if(answers>64)return 0;
    size_t new_dns_len;
    if(rd16(dns+question_end-4)==DNS_HTTPS) {
        new_dns_len=rewrite_https(dns,dns_len,question_end,answers,additional);
        if(!new_dns_len)return 0;
    } else {
        for(unsigned i=0;i<answers+additional;i++) {
            if(!dns_name_skip(dns,dns_len,&pos)||dns_len-pos<10)return 0;
            unsigned type=rd16(dns+pos),rlen=rd16(dns+pos+8);
            pos+=10;
            if(rlen>dns_len-pos)return 0;
            if(i>=answers && type!=DNS_OPT)return 0;
            pos+=rlen;
        }
        if(pos!=dns_len)return 0;
        new_dns_len=question_end;
        dns[3]&=(uint8_t)~0x30u; /* no AD or CD on synthesized NODATA */
        memset(dns+6,0,6); /* ANCOUNT, NSCOUNT, ARCOUNT */
    }
    size_t new_size=ip_len+8+new_dns_len;
    wr16(udp+4,8u+new_dns_len);
    udp[6]=udp[7]=0;
    if(family==4) {
        wr16(packet+2,new_size);
        packet[10]=packet[11]=0;
        wr16(packet+10,checksum(sum_bytes(0,packet,ip_len)));
    } else wr16(packet+4,new_size-40);
    uint32_t sum=0;
    if(family==4) {
        sum=sum_bytes(sum,packet+12,8);
        sum+=17u+((unsigned)(new_size-ip_len));
    } else {
        sum=sum_bytes(sum,packet+8,32);
        sum+=(unsigned)(new_size-ip_len)+17u;
    }
    sum=sum_bytes(sum,udp,new_size-ip_len);
    unsigned cs=checksum(sum);
    wr16(udp+6,cs?cs:0xffffu);
    *length=new_size;
    return 1;
}

int d2k_dns_family_load(const char *path,d2k_dns_family_rule *rules,size_t capacity,
    size_t *count,int64_t now_unix) {
    if(!path||!rules||!count)return -1;
    *count=0;
    FILE *f=fopen(path,"r");
    if(!f)return -1;
    char line[512];int bad=0;
    while(fgets(line,sizeof line,f)) {
        if(!strchr(line,'\n')&&!feof(f)){bad=1;break;}
        if(line[0]=='#'||line[0]=='\n')continue;
        long long until=0;unsigned family=0;char address[64],name[256],extra[2];
        if(sscanf(line,"%lld %u %63s %255s %1s",&until,&family,address,name,extra)!=4 ||
           (family!=4&&family!=6)||until<=0){bad=1;break;}
        size_t n=strlen(name);
        if(!n||n>253||name[0]=='.'||name[n-1]=='.'||strstr(name,"..")){bad=1;break;}
        for(size_t i=0;i<n;i++) {
            unsigned char c=(unsigned char)name[i];
            if(c>='A'&&c<='Z')name[i]=(char)(c+32);
            else if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='.')){bad=1;break;}
        }
        if(bad)break;
        if(until<=now_unix)continue;
        if(*count>=capacity){bad=1;break;}
        d2k_dns_family_rule *r=&rules[(*count)++];
        memset(r,0,sizeof *r);
        r->client_family=(uint8_t)family;
        r->expires_unix=until;
        memcpy(r->name,name,n+1);
        if(inet_pton(family==4?AF_INET:AF_INET6,address,r->client)!=1){bad=1;break;}
    }
    if(ferror(f))bad=1;
    fclose(f);
    if(bad){*count=0;return -1;}
    return 0;
}
