/* Keenetic journal is an observation source. The scheduler alone decides
 * whether a configured DNS service still needs a recovery experiment. */
#include "d2k_domain.h"
#include <ctype.h>
#include <stdint.h>

typedef struct { uint64_t last; int ready; } dns_journal_cursor;
typedef struct { char names[16][256]; size_t count; } dns_journal_hits;

static uint64_t dns_journal_hash(const char *text) {
    uint64_t h=UINT64_C(14695981039346656037);
    for(const unsigned char *p=(const unsigned char *)text;*p;p++) {
        h^=*p;h*=UINT64_C(1099511628211);
    }
    return h;
}
static const char *dns_journal_clean(const char *line) {
    while(*line==' '||*line=='\t')line++;
    while((unsigned char)*line==27 && line[1]=='[') {
        line+=2;
        while(*line && *line!='K' && *line!='m')line++;
        if(*line)line++;
    }
    return line;
}
static int dns_journal_start(const char *line) {
    line=dns_journal_clean(line);
    return (line[0]=='I'||line[0]=='W'||line[0]=='E') && line[1]==' ' && line[2]=='[';
}
static int dns_journal_domain(const char *event,char base[256]) {
    if(!event || (event[0]!='W' && event[0]!='E') ||
       (!strstr(event,"https-dns-proxy:") && !strstr(event,"tls-dns-proxy:") &&
        !strstr(event,"quic-dns-proxy:")) ||
       (!strstr(event,"error") && !strstr(event,"failed") &&
        !strstr(event,"timed out") && !strstr(event,"unexpectedly")))return 0;
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
static void dns_journal_event(dns_journal_cursor *cursor,const char *event,
    int *found,uint64_t *last,dns_journal_hits *hits) {
    if(!event[0])return;
    uint64_t hash=dns_journal_hash(event);
    *last=hash;
    if(cursor->ready && !*found) {
        if(hash==cursor->last)*found=1;
        return;
    }
    if(!cursor->ready)return;
    char base[256];
    if(!dns_journal_domain(event,base))return;
    for(size_t i=0;i<hits->count;i++)if(!strcmp(hits->names[i],base))return;
    if(hits->count<sizeof hits->names/sizeof hits->names[0])
        snprintf(hits->names[hits->count++],sizeof hits->names[0],"%s",base);
}
/* First snapshot establishes the cursor. A vanished anchor (journal rollover)
 * establishes a new cursor without replaying old messages as fresh failures. */
static int dns_journal_scan(FILE *f,dns_journal_cursor *cursor,dns_journal_hits *hits) {
    if(!f||!cursor||!hits)return -1;
    dns_journal_cursor next=*cursor;
    dns_journal_hits found_hits={0};
    char line[1024],event[4096]={0};size_t used=0,lines=0;
    int found=0;uint64_t last=0;
    while(fgets(line,sizeof line,f)) {
        if(++lines>30000)return -1;
        if(dns_journal_start(line)) {
            dns_journal_event(cursor,event,&found,&last,&found_hits);
            used=0;event[0]=0;
        }
        const char *piece=dns_journal_clean(line);
        size_t n=strcspn(piece,"\r\n");
        if(n>sizeof event-used-1)n=sizeof event-used-1;
        memcpy(event+used,piece,n);used+=n;event[used]=0;
    }
    if(ferror(f))return -1;
    dns_journal_event(cursor,event,&found,&last,&found_hits);
    if(last){next.last=last;next.ready=1;}
    *cursor=next;
    if(found)*hits=found_hits;
    return 0;
}
