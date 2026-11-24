#include "d2k_dns_family.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t answer(uint8_t *p,const char *name,int dnssec) {
    memset(p,0,512);
    p[0]=0x45;p[8]=64;p[9]=17;
    p[12]=192;p[13]=168;p[14]=1;p[15]=1;
    p[16]=192;p[17]=168;p[18]=1;p[19]=2;
    p[20]=0;p[21]=53;p[22]=0xd4;p[23]=0x31;
    uint8_t *d=p+28;
    d[0]=0x12;d[1]=0x34;d[2]=0x81;d[3]=dnssec?0xa0:0x80;
    d[4]=0;d[5]=1;d[6]=0;d[7]=1;
    d[10]=0;d[11]=dnssec?1:0;
    size_t n=12;
    const char *s=name;
    while(*s) {
        const char *dot=strchr(s,'.');
        size_t part=dot?(size_t)(dot-s):strlen(s);
        d[n++]=(uint8_t)part;memcpy(d+n,s,part);n+=part;
        if(!dot)break;
        s=dot+1;
    }
    d[n++]=0;d[n++]=0;d[n++]=28;d[n++]=0;d[n++]=1;
    d[n++]=0xc0;d[n++]=12;d[n++]=0;d[n++]=28;d[n++]=0;d[n++]=1;
    d[n++]=0;d[n++]=0;d[n++]=0;d[n++]=60;
    d[n++]=0;d[n++]=16;
    for(int i=0;i<16;i++)d[n++]=(uint8_t)i;
    if(dnssec) {
        d[7]=2; /* cached signed answer, even if the new query omitted DO */
        d[n++]=0xc0;d[n++]=12;d[n++]=0;d[n++]=46;d[n++]=0;d[n++]=1;
        d[n++]=0;d[n++]=0;d[n++]=0;d[n++]=60;
        d[n++]=0;d[n++]=2;d[n++]=0xaa;d[n++]=0xbb;
        d[n++]=0;d[n++]=0;d[n++]=41;d[n++]=4;d[n++]=208;
        d[n++]=0;d[n++]=0;d[n++]=0x80;d[n++]=0;
        d[n++]=0;d[n++]=0;
    }
    size_t len=28+n;
    p[2]=(uint8_t)(len>>8);p[3]=(uint8_t)len;
    p[24]=(uint8_t)((n+8)>>8);p[25]=(uint8_t)(n+8);
    return len;
}

static size_t question(uint8_t *p,const char *name,int dnssec,int cd) {
    memset(p,0,512);
    p[0]=0x45;p[8]=64;p[9]=17;
    p[12]=192;p[13]=168;p[14]=1;p[15]=2;
    p[16]=192;p[17]=168;p[18]=1;p[19]=1;
    p[20]=0xd4;p[21]=0x31;p[22]=0;p[23]=53;
    uint8_t *d=p+28;
    d[0]=0x12;d[1]=0x34;d[2]=1;d[3]=cd?0x10:0;
    d[4]=0;d[5]=1;d[10]=0;d[11]=dnssec?1:0;
    size_t n=12;const char *s=name;
    while(*s) {
        const char *dot=strchr(s,'.');
        size_t part=dot?(size_t)(dot-s):strlen(s);
        d[n++]=(uint8_t)part;memcpy(d+n,s,part);n+=part;
        if(!dot)break;
        s=dot+1;
    }
    d[n++]=0;d[n++]=0;d[n++]=28;d[n++]=0;d[n++]=1;
    if(dnssec) {
        d[n++]=0;d[n++]=0;d[n++]=41;d[n++]=4;d[n++]=208;
        d[n++]=0;d[n++]=0;d[n++]=0x80;d[n++]=0;
        d[n++]=0;d[n++]=0;
    }
    size_t len=28+n;
    p[2]=(uint8_t)(len>>8);p[3]=(uint8_t)len;
    p[24]=(uint8_t)((n+8)>>8);p[25]=(uint8_t)(n+8);
    return len;
}

static unsigned sum16(const uint8_t *p,size_t n,unsigned sum) {
    for(size_t i=0;i+1<n;i+=2)sum+=(unsigned)p[i]*256u+p[i+1];
    if(n&1)sum+=(unsigned)p[n-1]*256u;
    while(sum>>16)sum=(sum&65535u)+(sum>>16);
    return sum;
}

static void https_hints(const d2k_dns_family_rule *rule) {
    const char *name=rule->name;
    const uint8_t prefix[]={0,1,0,                    /* ServiceMode, TargetName . */
        0,1,0,3,2,'h','2',                           /* alpn */
        0,4,0,4,192,0,2,7,                          /* ipv4hint */
        0,5,0,4,0,2,0xfe,0x0d};                     /* opaque ech value */
    const uint8_t hint[]={0,6,0,16,0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,7};
    uint8_t pkt[512],query[512],copy[512];
    size_t qlen=question(query,name,0,0);
    query[qlen-3]=65;
    d2k_dns_family_request req;
    assert(d2k_dns_family_request_parse(query,qlen,rule,&req)==1);
    size_t len=answer(pkt,name,0);
    assert(!d2k_dns_family_response_matches(pkt,len,&req));

    size_t rr=qlen, rdata=rr+12;
    pkt[qlen-3]=65;
    pkt[rr+3]=65;
    memcpy(pkt+rdata,prefix,sizeof prefix);
    memcpy(pkt+rdata+sizeof prefix,hint,sizeof hint);
    pkt[rr+11]=sizeof prefix+sizeof hint;
    len=rdata+sizeof prefix+sizeof hint;
    pkt[3]=(uint8_t)len;pkt[25]=(uint8_t)(len-20);
    assert(d2k_dns_family_response_matches(pkt,len,&req));
    memcpy(copy,pkt,len);
    size_t original=len;
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,rule,1000,1)==1);
    assert(len==rdata+sizeof prefix && pkt[rr+11]==sizeof prefix);
    assert(pkt[28+7]==1 && !memcmp(pkt+rdata,prefix,sizeof prefix));
    assert(sum16(pkt,20,0)==65535u);
    unsigned pseudo=sum16(pkt+12,8,17u+(unsigned)(len-20));
    assert(sum16(pkt+20,len-20,pseudo)==65535u);
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,rule,1000,1)==0);

    /* Preserve authenticated data and responses that were not authorized. */
    memcpy(pkt,copy,original);len=original;pkt[31]|=0x20;
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,rule,1000,1)==0);
    assert(len==original && pkt[31]==(copy[31]|0x20));
    memcpy(pkt,copy,original);
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,rule,1000,0)==0);
    assert(len==original && !memcmp(pkt,copy,len));

    /* Both compressed owners still refer to the original question. */
    const uint8_t opt[]={0,0,41,4,0xd0,0,0,0,0,0,0};
    size_t rr_len=original-rr;
    memcpy(pkt+len,pkt+rr,rr_len);
    len+=rr_len;
    memcpy(pkt+len,opt,sizeof opt);
    len+=sizeof opt;
    pkt[35]=2;pkt[39]=1;
    pkt[3]=(uint8_t)len;pkt[25]=(uint8_t)(len-20);
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,rule,1000,1)==1);
    size_t second=rdata+sizeof prefix;
    assert(pkt[35]==2 && pkt[39]==1);
    assert(pkt[second]==0xc0 && pkt[second+1]==12);
    assert(!memcmp(pkt+second+12,prefix,sizeof prefix));
    assert(len==second+12+sizeof prefix+sizeof opt);
    assert(!memcmp(pkt+len-sizeof opt,opt,sizeof opt));

    /* ipv6hint listed in mandatory cannot be removed in isolation. */
    memcpy(pkt,copy,original);len=original;
    const uint8_t mandatory[]={0,0,0,2,0,6};
    memmove(pkt+rdata+3+sizeof mandatory,pkt+rdata+3,len-rdata-3);
    memcpy(pkt+rdata+3,mandatory,sizeof mandatory);
    len+=sizeof mandatory;pkt[rr+11]+=sizeof mandatory;
    pkt[3]=(uint8_t)len;pkt[25]=(uint8_t)(len-20);
    memcpy(copy,pkt,len);original=len;
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,rule,1000,1)==0);
    assert(len==original && !memcmp(pkt,copy,len));
}

int main(void) {
    uint8_t pkt[512],copy[512];
    d2k_dns_family_rule rule={.name="ru.numista.com",.client={192,168,1,2},
        .client_family=4,.expires_unix=2000};
    https_hints(&rule);
    d2k_dns_family_request req;
    size_t qlen=question(pkt,"ru.numista.com",0,0);
    assert(d2k_dns_family_request_parse(pkt,qlen,&rule,&req)==1 && !req.dnssec);
    size_t rlen=answer(pkt,"ru.numista.com",0);
    assert(d2k_dns_family_response_matches(pkt,rlen,&req));
    qlen=question(pkt,"ru.numista.com",1,0);
    assert(d2k_dns_family_request_parse(pkt,qlen,&rule,&req)==1 && req.dnssec);
    rlen=answer(pkt,"ru.numista.com",0); /* router cache can omit DO and RRSIG */
    assert(d2k_dns_family_response_matches(pkt,rlen,&req));
    qlen=question(pkt,"ru.numista.com",0,1);
    assert(d2k_dns_family_request_parse(pkt,qlen,&rule,&req)==1 && req.dnssec);
    qlen=question(pkt,"other.example",0,0);
    assert(d2k_dns_family_request_parse(pkt,qlen,&rule,&req)==0);
    size_t len=answer(pkt,"ru.numista.com",0),original=len;
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,&rule,1000,1)==1);
    assert(len<original && pkt[2]*256u+pkt[3]==len);
    assert(pkt[28+6]==0 && pkt[28+7]==0 && pkt[28+3]==0x80);
    assert(sum16(pkt,20,0)==65535u);
    unsigned pseudo=sum16(pkt+12,8,17u+(unsigned)(len-20));
    assert(sum16(pkt+20,len-20,pseudo)==65535u);

    len=answer(pkt,"ru.numista.com",0);original=len;
    memmove(pkt+40,pkt+20,len-20);
    memset(pkt,0,40);pkt[0]=0x60;pkt[6]=17;pkt[7]=64;
    pkt[8]=0x20;pkt[9]=1;pkt[23]=1;
    pkt[24]=0x20;pkt[25]=1;pkt[39]=2;
    len+=20;pkt[4]=(uint8_t)((len-40)>>8);pkt[5]=(uint8_t)(len-40);
    rule.client_family=6;memset(rule.client,0,16);
    rule.client[0]=0x20;rule.client[1]=1;rule.client[15]=2;
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,&rule,1000,1)==1);
    assert(len<original+20 && pkt[4]*256u+pkt[5]==len-40);
    pseudo=sum16(pkt+8,32,(unsigned)(len-40)+17u);
    assert(sum16(pkt+40,len-40,pseudo)==65535u);
    rule.client_family=4;memset(rule.client,0,16);
    rule.client[0]=192;rule.client[1]=168;rule.client[2]=1;rule.client[3]=2;

    len=answer(pkt,"other.example",0);memcpy(copy,pkt,len);original=len;
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,&rule,1000,1)==0);
    assert(len==original && !memcmp(pkt,copy,len));

    len=answer(pkt,"ru.numista.com",1);memcpy(copy,pkt,len);original=len;
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,&rule,1000,0)==0);
    assert(len==original && !memcmp(pkt,copy,len));
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,&rule,1000,1)==1);
    assert(pkt[28+6]==0 && pkt[28+7]==0 && (pkt[28+3]&0x30)==0);

    len=answer(pkt,"ru.numista.com",0);memcpy(copy,pkt,len);original=len;
    assert(d2k_dns_family_rewrite(pkt,&len,sizeof pkt,&rule,2000,1)==0);
    assert(len==original && !memcmp(pkt,copy,len));
    puts("dns family packet tests passed");
    return 0;
}
