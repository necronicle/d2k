#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "d2k_provider_ips.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static int suffix(const char *name,const char *domain) {
    size_t n=strlen(name), d=strlen(domain);
    if(n && name[n-1]=='.') n--;
    return n>=d && !strncasecmp(name+n-d,domain,d) &&
        (n==d || name[n-d-1]=='.');
}
/* Z2K's DNS pool includes only rr cache hosts under c.youtube/gvt1. */
static int cache_cluster(const char *name,const char *domain) {
    size_t n=strlen(name),d=strlen(domain);
    if(n && name[n-1]=='.')n--;
    if(n<=d+1 || strncasecmp(name+n-d,domain,d) || name[n-d-1]!='.')return 0;
    size_t prefix=n-d-1,i=0;
    if(i>=prefix || (name[i]!='r' && name[i]!='R'))return 0;
    i++;
    if(i<prefix && (name[i]=='r' || name[i]=='R'))i++;
    size_t digits=i;
    while(i<prefix && name[i]>='0' && name[i]<='9')i++;
    if(i==digits)return 0;
    if(i+3<=prefix && !strncmp(name+i,"---",3))i+=3;
    else if(i<prefix && name[i]=='.')i++;
    else return 0;
    if(i+3>prefix || strncasecmp(name+i,"sn-",3))return 0;
    i+=3;
    if(i==prefix)return 0;
    for(;i<prefix;i++)
        if(!((name[i]>='a'&&name[i]<='z') ||
             (name[i]>='A'&&name[i]<='Z') ||
             (name[i]>='0'&&name[i]<='9') || name[i]=='-'))return 0;
    return 1;
}
static int provider(const char *name) {
    if(suffix(name,"googlevideo.com") || cache_cluster(name,"c.youtube.com"))return 1;
    if(cache_cluster(name,"gvt1.com"))return 2;
    return 0;
}
static size_t address_size(int family) {return family==4?4u:family==6?16u:0u;}
int d2k_provider_ips_observe(d2k_provider_ips *ips,const d2k_dns_answer *a,uint64_t now) {
    if(!ips||!a||!a->count||a->count>D2K_DNS_ANSWER_MAX_ADDR||!a->ttl)return 0;
    int kind=provider(a->question);
    if(!kind)kind=provider(a->name);
    int family=a->type==1?4:a->type==28?6:0;
    size_t len=address_size(family);
    if(!kind||!len)return 0;
    int changed=0;
    for(size_t i=0;i<a->count;i++) {
        size_t slot=ips->count;
        for(size_t j=0;j<ips->count;j++)
            if(ips->entries[j].family==family &&
               !memcmp(ips->entries[j].address,a->addresses[i],len)) {slot=j;break;}
        if(slot==ips->count) {
            if(slot==D2K_PROVIDER_IPS_MAX) {
                for(size_t j=0;j<ips->count;j++)
                    if(ips->entries[j].expires<=now) {slot=j;break;}
            }
            if(slot==D2K_PROVIDER_IPS_MAX)continue;
            if(slot==ips->count)ips->count++;
        }
        d2k_provider_ip *e=&ips->entries[slot];
        memset(e,0,sizeof *e);
        memcpy(e->address,a->addresses[i],len);
        e->family=(uint8_t)family;e->provider=(uint8_t)kind;
        e->expires=now>UINT64_MAX-3600?UINT64_MAX:now+3600;
        changed=1;
    }
    if(changed)ips->dirty=1;
    return changed;
}
int d2k_provider_ips_has(const d2k_provider_ips *ips,const uint8_t *address,int family,uint64_t now) {
    if(!ips||!address)return 0;
    size_t len=address_size(family);
    if(!len)return 0;
    for(size_t i=0;i<ips->count;i++)
        if(ips->entries[i].family==family && ips->entries[i].expires>now &&
           !memcmp(ips->entries[i].address,address,len))return 1;
    return 0;
}
int d2k_provider_ips_load(d2k_provider_ips *ips,const char *path,uint64_t now) {
    if(!ips||!path)return -1;
    FILE *f=fopen(path,"r");
    if(!f)return -1;
    d2k_provider_ips *fresh=calloc(1,sizeof *fresh);
    if(!fresh){fclose(f);return -1;}
    char line[256];
    int ok=fgets(line,sizeof line,f) && !strcmp(line,"d2k-provider-ips 1\n");
    while(ok && fgets(line,sizeof line,f)) {
        unsigned long long expires;unsigned family,kind;char address[INET6_ADDRSTRLEN],extra;
        if(sscanf(line,"%llu %u %u %45s %c",&expires,&family,&kind,address,&extra)!=4 ||
           (family!=4&&family!=6) || (kind!=1&&kind!=2)) {ok=0;break;}
        if(expires<=now)continue;
        if(fresh->count==D2K_PROVIDER_IPS_MAX){ok=0;break;}
        d2k_provider_ip *e=&fresh->entries[fresh->count];
        if(inet_pton(family==4?AF_INET:AF_INET6,address,e->address)!=1){ok=0;break;}
        e->expires=expires;e->family=family;e->provider=kind;
        fresh->count++;
    }
    if(ferror(f))ok=0;
    fclose(f);
    if(ok)*ips=*fresh;
    free(fresh);
    return ok?0:-1;
}
int d2k_provider_ips_save(d2k_provider_ips *ips,const char *path,uint64_t now) {
    if(!ips||!path)return -1;
    size_t n=strlen(path);
    char *tmp=malloc(n+12);
    if(!tmp)return -1;
    memcpy(tmp,path,n);memcpy(tmp+n,".tmp.XXXXXX",12);
    int fd=mkstemp(tmp);
    if(fd<0){free(tmp);return -1;}
    FILE *f=fdopen(fd,"w");
    if(!f){close(fd);unlink(tmp);free(tmp);return -1;}
    int ok=fputs("d2k-provider-ips 1\n",f)>=0;
    for(size_t i=0;ok&&i<ips->count;i++) {
        const d2k_provider_ip *e=&ips->entries[i];
        if(e->expires<=now)continue;
        char address[INET6_ADDRSTRLEN];
        if(!inet_ntop(e->family==4?AF_INET:AF_INET6,e->address,address,sizeof address) ||
           fprintf(f,"%llu %u %u %s\n",(unsigned long long)e->expires,e->family,e->provider,address)<0)ok=0;
    }
    if(ok && fflush(f))ok=0;
    if(ok && fsync(fd))ok=0;
    if(fclose(f))ok=0;
    if(ok && rename(tmp,path))ok=0;
    if(!ok)unlink(tmp);
    else ips->dirty=0;
    free(tmp);
    return ok?0:-1;
}
