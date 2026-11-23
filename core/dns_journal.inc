/* Keenetic journal is an observation source. The scheduler alone decides
 * whether a configured DNS service still needs a recovery experiment. */
#include "d2k_domain.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include "../runtime/d2k_json_reader.h"

typedef struct { uint64_t last,first,anchor; int ready,text_mode; } dns_journal_cursor;
typedef struct { char names[16][256]; size_t count; } dns_journal_hits;

static int journal_failure(const char *event) {
    return strstr(event,"error") || strstr(event,"failed") ||
           strstr(event,"timed out") || strstr(event,"unexpectedly");
}
static int journal_uri_domain(const char *event,char base[256]) {
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
static int dns_journal_domain(const char *event,char base[256]) {
    return journal_failure(event) && journal_uri_domain(event,base);
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
static void journal_add(dns_journal_hits *hits,const char *base) {
    for(size_t i=0;i<hits->count;i++)if(!strcmp(hits->names[i],base))return;
    if(hits->count<sizeof hits->names/sizeof hits->names[0])
        strcpy(hits->names[hits->count++],base);
}
/* The CLI folds long lines and changes whitespace. Hash the same printable
 * record in both formats so a change of reader can keep its position. */
static uint64_t journal_hash(const char *text) {
    uint64_t h=UINT64_C(14695981039346656037);
    for(const unsigned char *p=(const unsigned char *)text;*p;p++)
        if(!isspace(*p)){h^=*p;h*=UINT64_C(1099511628211);}
    return h;
}
static uint64_t journal_rci_anchor(json_reader entry) {
    json_reader msg,field;
    char stamp[48],source[128],label[4],body[4096],line[4352];
    if(!journal_field(entry,"timestamp",&field) || !journal_text(field,stamp,sizeof stamp) ||
       !journal_field(entry,"ident",&field) || !journal_text(field,source,sizeof source) ||
       !journal_field(entry,"message",&msg) || !journal_field(msg,"label",&field) ||
       !journal_text(field,label,sizeof label) || !journal_field(msg,"message",&field) ||
       !journal_text(field,body,sizeof body))return 0;
    snprintf(line,sizeof line,"%s [%s] %s: %s",label,stamp,source,body);
    return journal_hash(line);
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
    journal_add(hits,base);
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
    uint64_t matched=0;int anchor_found=0;
    json_reader newest={0};
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
        json_reader entry={.p=start,.end=log.p};
        if(!newest.p || id>=next.last){next.last=id;newest=entry;}
        if(cursor->text_mode && cursor->anchor && journal_rci_anchor(entry)==cursor->anchor &&
           (!anchor_found || id>matched)) {
            matched=id;anchor_found=1;
        }
        if(cursor->ready && !cursor->text_mode && id>cursor->last)
            journal_observe(entry,&found);
        json_ws(&log);
        if(*log.p==','){log.p++;json_ws(&log);}
    }
    if(cursor->text_mode && anchor_found) {
        dns_journal_cursor from={.ready=1,.last=matched};
        int rc=dns_journal_parse(data,size,&from,hits);
        if(!rc)*cursor=from;
        return rc;
    }
    if(cursor->text_mode && !anchor_found && cursor->anchor)return 1;
    if(newest.p)next.anchor=journal_rci_anchor(newest);
    *cursor=next;
    *hits=found;
    return 0;
}

static int journal_proxy(const char *tag,size_t len) {
    const char *pid=memchr(tag,'[',len);
    if(pid)len=(size_t)(pid-tag);
    static const char *const names[]={"https-dns-proxy","tls-dns-proxy","quic-dns-proxy"};
    for(size_t i=0;i<sizeof names/sizeof names[0];i++)
        if(strlen(names[i])==len && !memcmp(tag,names[i],len))return 1;
    return 0;
}

/* OpenWrt procd tags stderr with the instance PID. Some https-dns-proxy
 * diagnostics omit the resolver URL. Read -r only from that same executable. */
static int journal_instance_domain(const char *tag,const char *colon,char base[256]) {
    const char *pid=memchr(tag,'[',(size_t)(colon-tag));
    if(!pid || colon-pid<3 || colon[-1]!=']' || colon-pid>12)return 0;
    const char *digits=pid+1;
    for(const char *p=digits;p<colon-1;p++)if(!isdigit((unsigned char)*p))return 0;
    char path[64],args[4096];
    snprintf(path,sizeof path,"/proc/%.*s/cmdline",(int)(colon-1-digits),digits);
    FILE *f=fopen(path,"rb");if(!f)return 0;
    size_t n=fread(args,1,sizeof args,f);
    int valid=feof(f) && !ferror(f);fclose(f);
    if(!valid || !n || args[n-1])return 0;
    const char *name=strrchr(args,'/');
    if(strcmp(name ? name+1 : args,"https-dns-proxy"))return 0;
    for(const char *p=args+strlen(args)+1;p<args+n;p+=strlen(p)+1) {
        if(strcmp(p,"-r") || p+3>=args+n)continue;
        p+=3;
        return !strncmp(p,"https://",8) && journal_uri_domain(p,base);
    }
    return 0;
}

static int openwrt_event(const char *line,char base[256]) {
    char priority[40];int pos=0;
    if(sscanf(line,"%*s %*s %*u %*s %*u %39s %n",priority,&pos)!=1 || !pos)return 0;
    char *level=strchr(priority,'.');
    int syslog_error=level && (!strcmp(level,".warn") || !strcmp(level,".warning") ||
        !strcmp(level,".err") || !strcmp(level,".error") || !strcmp(level,".crit") ||
        !strcmp(level,".alert") || !strcmp(level,".emerg"));
    const char *tag=line+pos,*colon=strchr(tag,':');
    if(!colon || !journal_proxy(tag,(size_t)(colon-tag)))return 0;
    const char *body=colon+1;
    while(*body==' ')body++;
    /* procd assigns stdout a syslog priority independent of the proxy's own. */
    if(body[0]=='[' && body[1] && body[2]==']') {
        if(!strchr("WEF",body[1]))return 0;
    } else if(!syslog_error)return 0;
    if(dns_journal_domain(body,base))return 1;
    if(!journal_failure(body))return 0;
    return journal_instance_domain(tag,colon,base);
}

/* ndmc folds both at word boundaries and inside URLs. Prefer an intact
 * authority across the fold, then retry with the whitespace restored. */
static int journal_cli_domain(const char *line,char base[256]) {
    if(!strchr(line,'\t'))return dns_journal_domain(line,base);
    char joined[8192],words[8192];
    size_t used=0,n=strlen(line);
    if(n>=sizeof words)return 0;
    for(size_t i=0;i<n;i++) {
        words[i]=line[i]=='\t' ? ' ' : line[i];
        if(line[i]!='\t')joined[used++]=line[i];
    }
    joined[used]=0;words[n]=0;
    if(!journal_failure(words) && !journal_failure(joined))return 0;
    return journal_uri_domain(joined,base) || journal_uri_domain(words,base);
}

static void journal_text_record(const char *line,int openwrt,const dns_journal_cursor *cursor,
                                int *after,uint64_t *last,dns_journal_hits *hits) {
    *last=journal_hash(line);
    if(cursor->anchor && *last==cursor->anchor){*after=1;hits->count=0;return;}
    if(!*after)return;
    char base[256];
    if(openwrt) {
        if(openwrt_event(line,base))journal_add(hits,base);
    } else if((*line=='W' || *line=='E') && (strstr(line,"https-dns-proxy:") ||
              strstr(line,"tls-dns-proxy:") || strstr(line,"quic-dns-proxy:")) &&
              journal_cli_domain(line,base))journal_add(hits,base);
}

static int journal_scan_text(FILE *f,int openwrt,dns_journal_cursor *cursor,dns_journal_hits *hits) {
    dns_journal_hits found={0};
    uint64_t last=0;
    int after=cursor->ready && !cursor->anchor,overflow=0;
    char line[8192],event[8192]="";
    size_t used=0;
    while(fgets(line,sizeof line,f)) {
        char *p=line;
        while(!strncmp(p,"\033[K",3))p+=3;
        size_t n=strcspn(p,"\r\n");p[n]=0;
        if(!*p)continue;
        if(openwrt){journal_text_record(p,1,cursor,&after,&last,&found);continue;}
        if(p[1]==' ' && p[2]=='[') {
            if(used && !overflow)journal_text_record(event,0,cursor,&after,&last,&found);
            used=0;overflow=0;
        } else {
            if(!used || !isspace((unsigned char)*p))continue;
            while(*p==' ' || *p=='\t')p++;
            if(used+1>=sizeof event){overflow=1;continue;}
            event[used++]='\t';
        }
        n=strlen(p);
        if(n>=sizeof event-used){overflow=1;continue;}
        memcpy(event+used,p,n+1);used+=n;
    }
    if(ferror(f))return -1;
    if(used && !overflow)journal_text_record(event,0,cursor,&after,&last,&found);
    if(!openwrt && !last)return -1;
    int lost=cursor->anchor && !after;
    *cursor=(dns_journal_cursor){.anchor=last,.ready=1,.text_mode=1};
    *hits=found;
    return lost ? 1 : 0;
}
