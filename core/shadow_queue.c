#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2k_shadow_queue.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

static size_t form_u16(const uint8_t *p) {return (size_t)p[0]*256u+p[1];}
/* Only per-connection freshness is erased. Extension order, groups, lengths,
 * ECH presence/content, ciphers and transport options remain observations. */
uint64_t d2k_shadow_form_key(const uint8_t *hello,size_t hn,const uint8_t *options,size_t on)
{
    if(!hello || !hn || hn>D2K_SHADOW_HELLO_MAX || on>40 || (on && !options))return 0;
    uint8_t canonical[D2K_SHADOW_HELLO_MAX],tcp[40];memcpy(canonical,hello,hn);
    if(hn>=44 && hello[0]==22 && 5u+form_u16(hello+3)==hn && hello[5]==1) {
        memset(canonical+11,0,32);size_t p=44,sl=hello[43];
        if(sl<=hn-p) {
            memset(canonical+p,0,sl);p+=sl;
            if(p+2<=hn) {size_t n=form_u16(hello+p);p+=2;if(n<=hn-p)p+=n;else p=hn;}
            if(p<hn) {size_t n=hello[p++];if(n<=hn-p)p+=n;else p=hn;}
            if(p+2<=hn && form_u16(hello+p)==hn-p-2) {
                p+=2;
                while(p+4<=hn) {
                    size_t type=form_u16(hello+p),n=form_u16(hello+p+2);p+=4;
                    if(n>hn-p)break;
                    if(type==51 && n>=2 && form_u16(hello+p)==n-2) {
                        size_t q=p+2,end=p+n;
                        while(q+4<=end) {
                            size_t k=form_u16(hello+q+2);q+=4;
                            if(k>end-q)break;
                            memset(canonical+q,0,k);q+=k;
                        }
                    }
                    p+=n;
                }
            }
        }
    }
    if(on)memcpy(tcp,options,on);
    for(size_t p=0;p<on;) {
        unsigned kind=tcp[p];if(!kind)break;if(kind==1) {p++;continue;}
        if(on-p<2 || tcp[p+1]<2 || tcp[p+1]>on-p)break;
        size_t n=tcp[p+1];if(kind==8 && n==10)memset(tcp+p+2,0,8);p+=n;
    }
    uint64_t h=UINT64_C(14695981039346656037);
    for(size_t i=0;i<hn;i++)h=(h^canonical[i])*UINT64_C(1099511628211);
    h=(h^(uint8_t)on)*UINT64_C(1099511628211);
    for(size_t i=0;i<on;i++)h=(h^tcp[i])*UINT64_C(1099511628211);
    return h?h:1;
}

int d2k_shadow_record_normalize(d2k_shadow_record *r)
{
    if(!r || r->snapshot_errno<0 || r->protocol>2 || r->degradation>1 || r->priority>2 ||
       !memchr(r->doh_path,0,sizeof r->doh_path))return -1;
    if(r->doh_path[0]) {
        if(r->doh_path[0]!='/' || r->doh_path[1]=='/')return -1;
        for(const unsigned char *p=(const unsigned char *)r->doh_path;*p;p++)
            if(*p<=32 || *p>=127 || *p=='#' || *p=='\\')return -1;
    }
    if(r->degradation && (!r->knowledge || !r->program_hash || !r->protocol ||
       !d2k_binding_known(&r->binding) || r->binding.kind!=D2K_BIND_NAME || r->binding.temporary ||
       r->binding.family!=r->family || (r->protocol==1?r->binding.shape!=2:(r->binding.shape!=1 && r->binding.shape!=D2K_PLAN_SHAPE_ECH_TCP))))return -1;
    if(!memchr(r->history_name,0,sizeof r->history_name))return -1;
    if(r->history_name[0]) {
        d2k_shadow_record h=*r;h.history_time=0;h.history_name[0]=0;
        strcpy(h.host,r->history_name);
        if(d2k_shadow_record_normalize(&h))return -1;
        strcpy(r->history_name,h.host);
    } else if(r->history_time)return -1;
    size_t n = strnlen(r->host, sizeof r->host);
    if (!n || n >= sizeof r->host || !r->port || (r->family != 4 && r->family != 6)) return -1;
    if (r->host[n-1] == '.') r->host[--n] = 0;
    if (!n) return -1;
    size_t label = 0;
    for (size_t i=0;i<n;i++) {
        unsigned char c=(unsigned char)r->host[i];
        if (c=='.') { if (!label || label>63) return -1; label=0; }
        else {
            if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_')) return -1;
            r->host[i]=(char)tolower(c); label++;
        }
    }
    if (!label || label>63 || !memchr(r->ip,0,sizeof r->ip)) return -1;
    uint8_t addr[16]; char ip[sizeof r->ip];
    int af=r->family==6?AF_INET6:AF_INET;
    if (inet_pton(af,r->ip,addr)!=1 || !inet_ntop(af,addr,ip,sizeof ip)) return -1;
    strcpy(r->ip,ip); return 0;
}

int d2k_shadow_writer_set(d2k_shadow_writer *w, const char *path)
{
    if (!w) return -1;
    if (path && strlen(path)>=sizeof w->path) return -1;
    snprintf(w->path,sizeof w->path,"%s",path?path:"");
    w->limit=D2K_SHADOW_QUEUE_MAX; return 0;
}

static int queue_open(const char *path)
{
    int fd=open(path,O_RDWR|O_CREAT|O_APPEND|O_NONBLOCK|O_NOFOLLOW,0600);
    if(fd<0)return -1;
    struct stat st;
    if(fstat(fd,&st) || !S_ISREG(st.st_mode)) { close(fd);errno=EINVAL;return -1; }
    return fd;
}
static int try_lock(int fd)
{
    struct flock lk={.l_type=F_WRLCK,.l_whence=SEEK_SET};
    return fcntl(fd,F_SETLK,&lk);
}

int d2k_shadow_queue_append(d2k_shadow_writer *w,const d2k_shadow_record *record)
{
    if(!w)return -1;
    if(!w->path[0])return 0;
    if(!record) { w->dropped++;return -1; }
    d2k_shadow_record r=*record;
    if(d2k_shadow_record_normalize(&r)) { w->dropped++;return -1; }
    char line[D2K_SHADOW_RECORD_MAX];
    /* Reserve one leading separator for a torn last append from a crash. */
    char epoch[33];for(unsigned i=0;i<16;i++)snprintf(epoch+2*i,3,"%02x",r.binding.epoch[i]);
    int n=snprintf(line+1,sizeof line-1,"%" PRIu64 "\t%s\t%s\t%u\t%u\t%u\t%" PRIu64 "\t%" PRIu64 "\t%s\t%u\t%u\t%u\t%" PRIu64 "\t%" PRIu64 "\t%s\t%u\t%u\t%s\t%" PRIu64 "\t%d\n",
        r.time,r.host,r.ip,(unsigned)r.port,(unsigned)r.family,(unsigned)r.signal,
        r.snapshot,r.history_time,r.history_name[0]?r.history_name:"-",(unsigned)r.degradation,(unsigned)r.protocol,r.knowledge,
        r.program_hash,r.binding.generation,epoch,(unsigned)r.binding.shape,(unsigned)r.priority,r.doh_path[0]?r.doh_path:"-",r.form_key,r.snapshot_errno);
    if(n<0 || (size_t)n>=sizeof line-1) { w->dropped++;return -1; }
    int fd=queue_open(w->path);
    if(fd<0) { w->dropped++;return -1; }
    int ok=0;
    if(!try_lock(fd)) {
        struct stat st;
        char last='\n';
        if(!fstat(fd,&st) && st.st_size>=0 &&
           (!st.st_size || pread(fd,&last,1,st.st_size-1)==1)) {
            size_t extra=last!='\n';
            size_t length=(size_t)n+extra;
            size_t limit=w->limit?w->limit:D2K_SHADOW_QUEUE_MAX;
            if(limit>D2K_SHADOW_QUEUE_MAX)limit=D2K_SHADOW_QUEUE_MAX;
            if((uint64_t)st.st_size<=limit && length<=limit-(size_t)st.st_size) {
                line[0]='\n';
                /* Exactly one O_APPEND write; never retry a partial write. */
                ok=write(fd,line+(extra?0:1),length)==(ssize_t)length;
            }
        }
    }
    close(fd);
    if(ok) { w->written++;return 1; }
    w->dropped++;return -1;
}

static int parse(char *line,d2k_shadow_record *r)
{
    char *fields[20],*p=line;size_t count=0;
    while(count<20) {
        fields[count++]=p;char *tab=strchr(p,'\t');
        if(!tab)break;
        if(count==20)return -1;
        *tab=0;p=tab+1;
    }
    if((count!=6 && count!=9 && count!=16 && count!=18 && count!=19 && count!=20) || strchr(p,'\t'))return -1;
    uint64_t v[6]={0}; const unsigned at[]={0,3,4,5,6,7};
    for(size_t i=0;i<(count>=9?6u:4u);i++) {
        const char *s=fields[at[i]];
        if(!*s)return -1;
        for(const char *c=s;*c;c++)if(*c<'0'||*c>'9')return -1;
        char *end;errno=0;unsigned long long x=strtoull(s,&end,10);
        if(errno || *end)return -1;
        v[i]=(uint64_t)x;
    }
    if(!v[1] || v[1]>65535 || v[2]>255 || v[3]>65535 ||
       strlen(fields[1])>=sizeof r->host || strlen(fields[2])>=sizeof r->ip)return -1;
    memset(r,0,sizeof *r);r->time=v[0];r->port=(uint16_t)v[1];
    r->family=(uint8_t)v[2];r->signal=(uint16_t)v[3];r->snapshot=v[4];r->history_time=v[5];
    strcpy(r->host,fields[1]);strcpy(r->ip,fields[2]);
    if(count>=9 && strcmp(fields[8],"-")) {
        d2k_shadow_record h=*r;h.history_time=0;
        if(strlen(fields[8])>=sizeof h.host)return -1;
        strcpy(h.host,fields[8]);if(d2k_shadow_record_normalize(&h))return -1;
        strcpy(r->history_name,h.host);
    }
    if(r->history_time && !r->history_name[0])return -1;
    if(count>=16) {
        uint64_t extra[5];for(size_t i=0;i<5;i++) {
            char *end;errno=0;extra[i]=strtoull(fields[9+i],&end,10);
            if(errno || !*fields[9+i] || *end || fields[9+i][0]=='-')return -1;
        }
        if(extra[0]>1 || extra[1]>2 || extra[2]>UINT32_MAX || strlen(fields[14])!=32)return -1;
        r->degradation=(uint8_t)extra[0];r->protocol=(uint8_t)extra[1];r->knowledge=(uint32_t)extra[2];r->program_hash=extra[3];
        r->binding.generation=extra[4];r->binding.kind=r->degradation?D2K_BIND_NAME:0;r->binding.family=r->family;
        for(unsigned i=0;i<16;i++) {
            char byte[3]={fields[14][2*i],fields[14][2*i+1],0},*end;
            unsigned long b=strtoul(byte,&end,16);if(*end || b>255)return -1;r->binding.epoch[i]=(uint8_t)b;
        }
        char *end;unsigned long shape=strtoul(fields[15],&end,10);if(*end || shape>255)return -1;
        r->binding.shape=(uint8_t)shape;
    }
    if(count>=18) {
        char *end;unsigned long priority=strtoul(fields[16],&end,10);
        if(*end || priority>2 || strlen(fields[17])>=sizeof r->doh_path)return -1;
        r->priority=(uint8_t)priority;
        if(strcmp(fields[17],"-")) {
            if(fields[17][0]!='/' || fields[17][1]=='/')return -1;
            for(const unsigned char *c=(const unsigned char *)fields[17];*c;c++)if(*c<=32 || *c>=127 || *c=='#' || *c=='\\')return -1;
            strcpy(r->doh_path,fields[17]);
        }
    }
    if(count>=19) {
        char *end;errno=0;unsigned long long key=strtoull(fields[18],&end,10);
        if(errno || !*fields[18] || *end || fields[18][0]=='-')return -1;
        r->form_key=(uint64_t)key;
    }
    if(count==20) {
        char *end;errno=0;long code=strtol(fields[19],&end,10);
        if(errno || !*fields[19] || *end || code<0 || code>INT_MAX)return -1;
        r->snapshot_errno=(int)code;
    }
    return d2k_shadow_record_normalize(r);
}

int d2k_shadow_queue_pending(const char *path,const d2k_shadow_record *record)
{
    if(!path || !record || !record->form_key)return 0;
    d2k_shadow_record r=*record;if(d2k_shadow_record_normalize(&r))return -1;
    int fd=queue_open(path);if(fd<0)return -1;
    if(try_lock(fd)) {close(fd);return 0;}
    struct stat st;char data[D2K_SHADOW_QUEUE_MAX+1];
    if(fstat(fd,&st) || st.st_size<0 || (uint64_t)st.st_size>D2K_SHADOW_QUEUE_MAX ||
       (st.st_size && pread(fd,data,(size_t)st.st_size,0)!=st.st_size)) {close(fd);return -1;}
    close(fd);size_t len=(size_t)st.st_size,used=0;
    while(used<len) {
        char *nl=memchr(data+used,'\n',len-used);if(!nl)break;
        size_t bytes=(size_t)(nl-data)-used;char line[D2K_SHADOW_RECORD_MAX];
        if(bytes<sizeof line && !memchr(data+used,0,bytes)) {
            memcpy(line,data+used,bytes);line[bytes]=0;d2k_shadow_record e;
            if(!parse(line,&e) && e.snapshot && !e.snapshot_errno && e.form_key==r.form_key &&
               e.priority>=r.priority && (r.priority!=2 || e.time>=r.time) &&
               e.family==r.family && e.port==r.port && (e.protocol?e.protocol:2)==(r.protocol?r.protocol:2) &&
               !strcmp(e.host,r.host) && !strcmp(e.ip,r.ip) && !strcmp(e.doh_path,r.doh_path) &&
               e.degradation==r.degradation && (!r.degradation ||
               (e.knowledge==r.knowledge && e.program_hash==r.program_hash && d2k_binding_equal(&e.binding,&r.binding))))return 1;
        }
        used=(size_t)(nl-data)+1;
    }
    return 0;
}

static int queue_take(const char *path,d2k_shadow_record *r,d2k_shadow_reader *stats)
{
    if(!path || !stats)return -1;
    int fd=queue_open(path);
    if(fd<0) { stats->errors++;return -1; }
    if(try_lock(fd)) {
        int busy=errno==EAGAIN || errno==EACCES;close(fd);
        if(!busy)stats->errors++;
        return busy?0:-1;
    }
    struct stat st;
    if(fstat(fd,&st) || st.st_size<0 || (uint64_t)st.st_size>D2K_SHADOW_QUEUE_MAX) {
        /* Never truncate an unexpectedly large/unowned file. */
        stats->errors++;close(fd);return -1;
    }
    char data[D2K_SHADOW_QUEUE_MAX+1];size_t len=(size_t)st.st_size;
    if(len && pread(fd,data,len,0)!=(ssize_t)len) { stats->errors++;close(fd);return -1; }
    uint64_t discarded[D2K_SHADOW_QUEUE_MAX/D2K_SHADOW_SNAPSHOT_RECORD_MIN+1u];size_t drops=0,discarded_rows=0;
    size_t used=0,kept=0,selected=0,selected_bytes=0;int found=0;
    while(used<len) {
        char *nl=memchr(data+used,'\n',len-used);
        size_t end=nl?(size_t)(nl-data):len,bytes=end-used;
        char line[D2K_SHADOW_RECORD_MAX];d2k_shadow_record candidate;
        int valid=nl && bytes<sizeof line && !memchr(data+used,0,bytes);
        if(valid) {memcpy(line,data+used,bytes);line[bytes]=0;valid=!parse(line,&candidate);}
        int discard=valid && stats->discard && stats->discard(stats->discard_ctx,&candidate);
        if(discard && candidate.snapshot && drops==sizeof discarded/sizeof discarded[0]) {
            /* Fail closed if a future parser accepts an even shorter row. */
            stats->errors++;discard=0;
        }
        if(!valid)stats->malformed++;
        else if(discard) {
            discarded_rows++;
            if(candidate.snapshot)discarded[drops++]=candidate.snapshot;
        } else {
            unsigned rank=stats->rank?stats->rank(stats->rank_ctx,&candidate):0;
            unsigned old_rank=found && stats->rank?stats->rank(stats->rank_ctx,r):0;
            if(r && (!found || candidate.priority>r->priority ||
               (candidate.priority==r->priority && (rank<old_rank ||
                (rank==old_rank && candidate.time<r->time))))) {
                *r=candidate;selected=kept;selected_bytes=bytes+1;found=1;
            }
            memmove(data+kept,data+used,bytes+1);kept+=bytes+1;
        }
        used=end+(nl?1:0);
    }
    if(found) {memmove(data+selected,data+selected+selected_bytes,kept-selected-selected_bytes);kept-=selected_bytes;}
    /* Compact under the same inode lock, preserving order within priority. */
    int failed=0;
    if(len!=kept) {
        int flags=fcntl(fd,F_GETFL);
        if(flags<0 || fcntl(fd,F_SETFL,flags&~O_APPEND))failed=1;
        if(!failed && kept && pwrite(fd,data,kept,0)!=(ssize_t)kept)failed=1;
        if(!failed && ftruncate(fd,(off_t)kept))failed=1;
    }
    /* Publish compaction before releasing any bytes. A shared reference in
       the retained queue or the dispatched record continues to own its file. */
    if(!failed)for(size_t i=0;i<drops;i++) {
        int referenced=found && r->snapshot==discarded[i];size_t at=0;
        while(!referenced && at<kept) {
            char *nl=memchr(data+at,'\n',kept-at);if(!nl)break;
            size_t bytes=(size_t)(nl-data)-at;char line[D2K_SHADOW_RECORD_MAX];
            memcpy(line,data+at,bytes);line[bytes]=0;d2k_shadow_record other;
            if(!parse(line,&other) && other.snapshot==discarded[i])referenced=1;
            at=(size_t)(nl-data)+1;
        }
        if(!referenced) {
            d2k_shadow_record dead={.snapshot=discarded[i]};d2k_shadow_snapshot_remove(path,&dead);
        }
    }
    close(fd);
    if(failed) { stats->errors++;return -1; }
    return r?found:(int)discarded_rows;
}
int d2k_shadow_queue_next(const char *path,d2k_shadow_record *r,d2k_shadow_reader *stats)
{ return r?queue_take(path,r,stats):-1; }
int d2k_shadow_queue_prune(const char *path,d2k_shadow_reader *stats)
{ return queue_take(path,NULL,stats); }

/* Each queue owns only its .snap-<16 hex digits> namespace. A resource cap
 * permits losing a form, never borrowing another flow's bytes. */
static int snap_path(const char *queue,uint64_t key,char path[1024])
{
    return !key || snprintf(path,1024,"%s.snap-%016" PRIx64,queue,key)>=1024?-1:0;
}
static int recent_time(uint64_t stamp,uint64_t now)
{ return stamp && stamp<=now && now-stamp<=D2K_SHADOW_HOUR; }
static int snapshot_header(int fd,uint64_t *stamp,size_t *hn,size_t *on)
{
    uint8_t h[24];struct stat st;
    if(fstat(fd,&st) || !S_ISREG(st.st_mode) || pread(fd,h,sizeof h,0)!=(ssize_t)sizeof h ||
       memcmp(h,"D2KSNAP1",8))return -1;
    *stamp=0;*hn=0;*on=0;
    for(unsigned i=0;i<8;i++)*stamp=(*stamp<<8)|h[8+i];
    for(unsigned i=0;i<4;i++) { *hn=(*hn<<8)|h[16+i];*on=(*on<<8)|h[20+i]; }
    return !*hn || *hn>D2K_SHADOW_HELLO_MAX || *on>40 ||
        st.st_size!=(off_t)(24+*hn+*on)?-1:0;
}
static uint64_t snapshot_pages(uint64_t bytes,uint64_t page)
{ return bytes/page+(bytes%page!=0); }
static int scan_snapshots(const char *queue,uint64_t now,int cleanup,unsigned *removed,
                          uint64_t *page,uint64_t *pages)
{
    char dir[512],prefix[600];const char *slash=strrchr(queue,'/');
    size_t dn=slash?(size_t)(slash-queue):1;
    if(dn>=sizeof dir) {errno=ENAMETOOLONG;return -1;}
    if(slash) { if(!dn)strcpy(dir,"/");else { memcpy(dir,queue,dn);dir[dn]=0; } }
    else strcpy(dir,".");
    snprintf(prefix,sizeof prefix,"%s.snap-",slash?slash+1:queue);
    DIR *d=opendir(dir);if(!d)return -1;
    if(pages) {
        struct statvfs fs;
        if(fstatvfs(dirfd(d),&fs)) {int saved=errno;closedir(d);errno=saved;return -1;}
        *page=fs.f_frsize?fs.f_frsize:fs.f_bsize;
        if(!*page) {closedir(d);errno=EINVAL;return -1;}
    }
    struct dirent *e;unsigned count=0;
    while((e=readdir(d))) {
        size_t pn=strlen(prefix);
        if(strncmp(e->d_name,prefix,pn))continue;
        int temporary=!strcmp(e->d_name+pn,"tmp");
        if(!temporary && strlen(e->d_name)!=pn+16)continue;
        int valid=1;for(unsigned i=0;!temporary && i<16;i++)if(!isxdigit((unsigned char)e->d_name[pn+i]))valid=0;
        if(!valid)continue;
        char path[1024];if(snprintf(path,sizeof path,"%s/%s",dir,e->d_name)>=(int)sizeof path)continue;
        int fd=open(path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW);uint64_t stamp=0;size_t hn=0,on=0;
        int bad=fd<0?1:snapshot_header(fd,&stamp,&hn,&on);struct stat st;
        int stated=fd>=0 && !fstat(fd,&st);
        int aged=stated && st.st_mtime>=0 && now>(uint64_t)st.st_mtime &&
            now-(uint64_t)st.st_mtime>D2K_SHADOW_HOUR;
        if(fd>=0)close(fd);
        if(cleanup && ((!bad && stamp<=now && now-stamp>D2K_SHADOW_HOUR) || (bad && aged))) {
            if(!unlink(path)) { (*removed)++;continue; }
        }
        if(pages) {
            /* Charge filesystem allocation units (tmpfs memory on the
             * router). Unreadable/nonregular entries cost a maximum form;
             * malformed or empty files never
             * become free slots. Never touch another queue's namespace. */
            uint64_t bytes=stated && S_ISREG(st.st_mode) && st.st_size>0?
                (uint64_t)st.st_size:24u+D2K_SHADOW_HELLO_MAX+40u;
            uint64_t cost=snapshot_pages(bytes,*page);
            *pages=cost>UINT64_MAX-*pages?UINT64_MAX:*pages+cost;
        }
        count++;
    }
    closedir(d);return count;
}
unsigned d2k_shadow_snapshot_cleanup(const char *queue,uint64_t now)
{ unsigned removed=0;if(queue && *queue)(void)scan_snapshots(queue,now,1,&removed,NULL,NULL);return removed; }
static int snapshot_write(const char *queue,d2k_shadow_record *r,const uint8_t *hello,size_t hn,
                               const uint8_t *options,size_t on,uint64_t now)
{
    if(!queue || !*queue || !r)return -1;
    r->snapshot=0;r->snapshot_errno=0;
    r->form_key=d2k_shadow_form_key(hello,hn,options,on);
    if(!r->form_key) {r->snapshot_errno=EINVAL;errno=EINVAL;return -1;}
    uint64_t page=0,pages=0;
    unsigned removed=0;int count=scan_snapshots(queue,now,1,&removed,&page,&pages);
    if(count<0)return -1;
    uint64_t budget=D2K_SHADOW_SNAPSHOT_BUDGET_UNITS*snapshot_pages(24u+D2K_SHADOW_HELLO_MAX+40u,page);
    uint64_t needed=snapshot_pages(24u+hn+on,page);
    if(pages>budget || needed>budget-pages) {errno=ENOSPC;return -1;}
    uint64_t key=0;int random=open("/dev/urandom",O_RDONLY);
    if(random<0)return -1;
    ssize_t got=read(random,&key,sizeof key);close(random);
    if(got!=(ssize_t)sizeof key || !key)return -1;
    char path[1024],tmp[1040];if(snap_path(queue,key,path))return -1;
    /* The controller is the only snapshot producer. A fixed temporary file
       bounds disk use even if it repeatedly dies before publication. */
    snprintf(tmp,sizeof tmp,"%s.snap-tmp",queue);
    int fd=open(tmp,O_WRONLY|O_CREAT|O_TRUNC|O_NONBLOCK|O_NOFOLLOW,0600);if(fd<0)return -1;
    struct stat temporary_stat;
    if(fstat(fd,&temporary_stat) || !S_ISREG(temporary_stat.st_mode)) {close(fd);return -1;}
    uint8_t header[24]={0};memcpy(header,"D2KSNAP1",8);
    uint64_t stamp=now;size_t a=hn,b=on;
    for(int i=7;i>=0;i--) { header[8+i]=(uint8_t)stamp;stamp>>=8; }
    for(int i=3;i>=0;i--) {header[16+i]=(uint8_t)a;a>>=8;header[20+i]=(uint8_t)b;b>>=8;}
    int bad=write(fd,header,24)!=24 || write(fd,hello,hn)!=(ssize_t)hn ||
        (on && write(fd,options,on)!=(ssize_t)on);
    if(close(fd))bad=1;
    /* Publish without replacing an already owned record, even in the
       unlikely event of a random-key collision. */
    if(!bad && link(tmp,path))bad=1;
    unlink(tmp);
    if(bad)return -1;
    r->snapshot=key;return 0;
}
int d2k_shadow_snapshot_write(const char *queue,d2k_shadow_record *r,const uint8_t *hello,size_t hn,
                               const uint8_t *options,size_t on,uint64_t now)
{
    errno=0;
    int rc=snapshot_write(queue,r,hello,hn,options,on,now);
    if(rc && r) {r->snapshot_errno=errno?errno:EIO;errno=r->snapshot_errno;}
    return rc;
}
int d2k_shadow_snapshot_read(const char *queue,const d2k_shadow_record *r,d2k_shadow_snapshot *out)
{
    char path[1024];if(!queue || !r || !out || snap_path(queue,r->snapshot,path))return -1;
    memset(out,0,sizeof *out);int fd=open(path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW);if(fd<0)return -1;
    uint64_t stamp;size_t hn,on;int bad=snapshot_header(fd,&stamp,&hn,&on);
    if(!bad)bad=pread(fd,out->hello,hn,24)!=(ssize_t)hn ||
        (on && pread(fd,out->options,on,(off_t)(24+hn))!=(ssize_t)on);
    close(fd);if(bad)return -1;
    if(r->form_key && r->form_key!=d2k_shadow_form_key(out->hello,hn,out->options,on))return -1;
    out->hello_len=hn;out->options_len=on;return 0;
}
void d2k_shadow_snapshot_remove(const char *queue,const d2k_shadow_record *r)
{ char path[1024];if(queue && *queue && r && !snap_path(queue,r->snapshot,path))unlink(path); }
void d2k_shadow_recent_note(d2k_shadow_recent *recent,const d2k_shadow_record *record,uint64_t now)
{
    if(!recent || !record || recent->count>D2K_SHADOW_RECENT_MAX)return;
    d2k_shadow_record r=*record;if(d2k_shadow_record_normalize(&r) || !recent_time(r.time,now))return;
    size_t n=0;
    for(size_t i=0;i<recent->count;i++) {
        const d2k_shadow_record *e=&recent->entries[i];
        if(!recent_time(e->time,now))continue;
        if(e->port==r.port && e->family==r.family && e->protocol==r.protocol &&
           e->form_key==r.form_key && !strcmp(e->ip,r.ip) && !strcmp(e->host,r.host)) {
            if(e->time>r.time || (e->time==r.time && e->signal>r.signal))r=*e;
        } else recent->entries[n++]=*e;
    }
    if(n==D2K_SHADOW_RECENT_MAX) {
        size_t oldest=0;
        for(size_t i=1;i<n;i++)if(recent->entries[i].time<recent->entries[oldest].time)oldest=i;
        if(r.time<recent->entries[oldest].time) {recent->count=n;return;}
        memmove(recent->entries+oldest,recent->entries+oldest+1,(n-oldest-1)*sizeof r);n--;
    }
    r.snapshot=r.history_time=0;r.history_name[0]=0;recent->entries[n++]=r;recent->count=n;
}
int d2k_shadow_recent_clean(const d2k_shadow_recent *recent,const d2k_shadow_record *r,uint64_t now)
{
    if(!recent || recent->count>D2K_SHADOW_RECENT_MAX || r->priority || r->degradation ||
       !r->form_key || !r->protocol || !r->clean_source)return 0;
    for(size_t i=0;i<recent->count;i++) {
        const d2k_shadow_record *e=&recent->entries[i];
        if(recent_time(e->time,now) && e->time<=r->time && e->clean_source &&
           e->clean_source!=r->clean_source && e->form_key==r->form_key &&
           e->protocol==r->protocol && e->family==r->family && e->port==r->port &&
           !strcmp(e->host,r->host) && !strcmp(e->ip,r->ip))return 1;
    }
    return 0;
}
int d2k_shadow_recent_save(const char *queue,const char *producer,const d2k_shadow_recent *recent,uint64_t now)
{
    if(!queue || !producer || !recent || recent->count>D2K_SHADOW_RECENT_MAX)return -1;
    char path[1024],tmp[1040];if(strcmp(producer,"recent") && strcmp(producer,"direct"))return -1;
    if(snprintf(path,sizeof path,"%s.%s",queue,producer)>=(int)sizeof path)return -1;
    /* One producer owns each suffix; fixed temporary names cannot accumulate
       across watchdog restarts. Readers see only the atomically renamed file. */
    snprintf(tmp,sizeof tmp,"%s.new",path);
    int fd=open(tmp,O_WRONLY|O_CREAT|O_TRUNC|O_NONBLOCK|O_NOFOLLOW,0600);if(fd<0)return -1;
    struct stat temporary_stat;
    if(fstat(fd,&temporary_stat) || !S_ISREG(temporary_stat.st_mode)) {close(fd);return -1;}
    FILE *f=fdopen(fd,"w");if(!f) {close(fd);unlink(tmp);return -1;}
    int bad=fputs("D2KRECENT2\n",f)==EOF;
    for(size_t i=0;i<recent->count && !bad;i++) {
        d2k_shadow_record r=recent->entries[i];
        if(!recent_time(r.time,now))continue;
        if(d2k_shadow_record_normalize(&r)) {bad=1;break;}
        if(fprintf(f,"%" PRIu64 "\t%s\t%s\t%u\t%u\t%u\t%u\t%" PRIu64 "\t%" PRIu64 "\n",r.time,r.host,r.ip,
                   (unsigned)r.port,(unsigned)r.family,(unsigned)r.signal,(unsigned)r.protocol,
                   r.form_key,r.clean_source)<0)bad=1;
    }
    if(fclose(f))bad=1;
    if(!bad && rename(tmp,path))bad=1;
    if(bad)unlink(tmp);
    return bad?-1:0;
}
int d2k_shadow_recent_load(const char *queue,const char *producer,d2k_shadow_recent *recent,uint64_t now)
{
    if(!queue || !producer || !recent)return -1;
    memset(recent,0,sizeof *recent);char path[1024];
    if(strcmp(producer,"recent") && strcmp(producer,"direct"))return -1;
    if(snprintf(path,sizeof path,"%s.%s",queue,producer)>=(int)sizeof path)return -1;
    int fd=open(path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW);if(fd<0)return errno==ENOENT?0:-1;
    struct stat st;
    if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<0 ||
       (uint64_t)st.st_size>D2K_SHADOW_RECENT_MAX*D2K_SHADOW_RECORD_MAX+32u) {close(fd);return -1;}
    FILE *f=fdopen(fd,"r");if(!f) {close(fd);return -1;}
    char line[D2K_SHADOW_RECORD_MAX];int bad=!fgets(line,sizeof line,f);
    int version=!bad && !strcmp(line,"D2KRECENT2\n")?2:1;
    if(!bad && version==1 && strcmp(line,"D2KRECENT1\n"))bad=1;
    size_t lines=0;
    while(!bad && fgets(line,sizeof line,f)) {
        char *nl=strchr(line,'\n');d2k_shadow_record r;
        if(!nl || ++lines>D2K_SHADOW_RECENT_MAX) {bad=1;break;}
        *nl=0;
        if(version==1) {if(parse(line,&r)) {bad=1;break;}}
        else {
            unsigned port,family,signal,protocol;unsigned long long stamp,form,source;int end=0;
            memset(&r,0,sizeof r);
            if(sscanf(line,"%llu\t%253s\t%45s\t%u\t%u\t%u\t%u\t%llu\t%llu%n",
                &stamp,r.host,r.ip,&port,&family,&signal,&protocol,&form,&source,&end)!=9 ||
                line[end] || port>65535 || family>255 || signal>65535 || protocol>2) {bad=1;break;}
            r.time=stamp;r.port=(uint16_t)port;r.family=(uint8_t)family;r.signal=(uint16_t)signal;
            r.protocol=(uint8_t)protocol;r.form_key=form;r.clean_source=source;
            if(d2k_shadow_record_normalize(&r)) {bad=1;break;}
        }
        d2k_shadow_recent_note(recent,&r,now);
    }
    if(ferror(f))bad=1;
    fclose(f);if(bad)memset(recent,0,sizeof *recent);
    return bad?-1:0;
}
