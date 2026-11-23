/* Keenetic journal is an observation source. The scheduler alone decides
 * whether a configured DNS service still needs a recovery experiment. */
#include "d2k_domain.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include "../runtime/d2k_json_reader.h"

typedef struct { uint64_t last,first; int ready; } dns_journal_cursor;
typedef struct { char names[16][256]; size_t count; } dns_journal_hits;

static int dns_journal_domain(const char *event,char base[256]) {
    if(!strstr(event,"error") && !strstr(event,"failed") &&
       !strstr(event,"timed out") && !strstr(event,"unexpectedly"))return 0;
    const char *url=strstr(event,"https://");
    size_t scheme=8;
    if(!url){url=strstr(event,"tls://");scheme=6;}
    if(!url){url=strstr(event,"quic://");scheme=7;}
    if(!url)return 0;
    const char *host=url+scheme;
    size_t n=0;
    while(host[n] && host[n]!='/' && host[n]!=':' && host[n]!='"' &&
          host[n]!='?' && !isspace((unsigned char)host[n]))n++;
    if(!n || n>253)return 0;
    char name[256];memcpy(name,host,n);name[n]=0;
    return d2k_domain_base(name,base)==0;
}
static int journal_field(json_reader object,const char *key,json_reader *field) {
    const char *start;
    size_t len;
    if(!json_member(object,key,&start,&len))return 0;
    *field=(json_reader){.p=start,.end=start+len};
    return 1;
}

/* RCI strings have already passed JSON validation. Only ASCII is significant
 * to the proxy names, URI authority and diagnostic phrases. */
static int journal_text(json_reader field,char *out,size_t cap) {
    if(field.p==field.end || *field.p++!='"')return 0;
    const char *end=field.end-1;
    while(field.p<end) {
        unsigned char c=*field.p++;
        if(c=='\\') {
            c=*field.p++;
            if(c=='u') {
                char hex[5]={0};
                memcpy(hex,field.p,4);field.p+=4;
                long code=strtol(hex,NULL,16);
                c=code>0 && code<128 ? (unsigned char)code : ' ';
            } else if(c!='"' && c!='/' && c!='\\')c=' ';
        }
        if(cap<=1)return 0;
        *out++=(char)c;cap--;
    }
    *out=0;
    return 1;
}
static void journal_observe(json_reader entry,dns_journal_hits *hits) {
    json_reader ident,msg,label,body;
    char source[64],severity[2],event[4096],base[256];
    if(!journal_field(entry,"ident",&ident) || !journal_text(ident,source,sizeof source))return;
    source[strcspn(source,"[")]=0;
    if(!journal_field(entry,"message",&msg) || !journal_field(msg,"label",&label) ||
       !journal_text(label,severity,sizeof severity) || (*severity!='W' && *severity!='E') ||
       !journal_field(msg,"message",&body) || !journal_text(body,event,sizeof event))return;
    if(strcmp(source,"https-dns-proxy") && strcmp(source,"tls-dns-proxy") &&
       strcmp(source,"quic-dns-proxy") && !strstr(event,"https-dns-proxy:") &&
       !strstr(event,"tls-dns-proxy:") && !strstr(event,"quic-dns-proxy:"))return;
    if(!dns_journal_domain(event,base))return;
    for(size_t i=0;i<hits->count;i++)if(!strcmp(hits->names[i],base))return;
    if(hits->count<sizeof hits->names/sizeof hits->names[0])
        strcpy(hits->names[hits->count++],base);
}

/* The log object is keyed by numeric record ID. Object member order is
 * immaterial. Publish only after validating the entire response. */
static int dns_journal_parse(const char *data,size_t size,dns_journal_cursor *cursor,
                             dns_journal_hits *hits) {
    json_reader root={.p=data,.end=data+size},log;
    dns_journal_hits found={0};
    dns_journal_cursor next={.ready=1,.first=UINT64_MAX};
    if(!json_valid_object(data,data+size) || !journal_field(root,"log",&log) ||
       *log.p++!='{')return -1;
    json_ws(&log);
    while(*log.p!='}') {
        if(*log.p++!='"' || !isdigit((unsigned char)*log.p))return -1;
        uint64_t id=0;
        while(isdigit((unsigned char)*log.p)) {
            unsigned digit=(unsigned)(*log.p++-'0');
            if(id>(UINT64_MAX-digit)/10)return -1;
            id=id*10+digit;
        }
        if(*log.p++!='"')return -1;
        json_ws(&log);
        if(*log.p++!=':')return -1;
        json_ws(&log);
        const char *start=log.p;
        if(*start!='{' || json_value(&log))return -1;
        if(id<next.first)next.first=id;
        if(id>next.last)next.last=id;
        if(cursor->ready && id>cursor->last)
            journal_observe((json_reader){.p=start,.end=log.p},&found);
        json_ws(&log);
        if(*log.p==','){log.p++;json_ws(&log);}
    }
    *cursor=next;
    *hits=found;
    return 0;
}
