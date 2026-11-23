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

int main(void) {
    uint8_t pkt[512],copy[512];
    d2k_dns_family_rule rule={.name="ru.numista.com",.client={192,168,1,2},
        .client_family=4,.expires_unix=2000};
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
