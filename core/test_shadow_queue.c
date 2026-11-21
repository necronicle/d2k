#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2k_shadow_queue.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

static d2k_shadow_record target(void)
{
    d2k_shadow_record r = {.time = 123, .port = 443, .family = 4, .signal = 2};
    strcpy(r.host, "Blocked.Example."); strcpy(r.ip, "192.0.2.1"); return r;
}
static unsigned dispatched(void *ctx,const d2k_shadow_record *r)
{ return !strcmp((const char *)ctx,r->host); }
static int obsolete(void *ctx,const d2k_shadow_record *r)
{ (void)ctx;return r->time<200; }
static void reclaim_unexecutable(void)
{
    char dir[]="/tmp/shadow-prune-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);d2k_shadow_writer w={0};assert(!d2k_shadow_writer_set(&w,path));
    d2k_shadow_record r=target(),dead,live,out;d2k_shadow_snapshot snap;
    uint8_t hello[]={22,3,3,0,1,1};
    assert(!d2k_shadow_snapshot_write(path,&r,hello,sizeof hello,NULL,0,123));dead=r;
    assert(d2k_shadow_queue_append(&w,&r)==1);
    r.time=201;hello[5]=2;assert(!d2k_shadow_snapshot_write(path,&r,hello,sizeof hello,NULL,0,201));live=r;
    assert(d2k_shadow_queue_append(&w,&r)==1);
    /* A discarded row sharing a live reference cannot delete its bytes. */
    r.time=124;assert(d2k_shadow_queue_append(&w,&r)==1);
    d2k_shadow_reader rd={.discard=obsolete};
    assert(d2k_shadow_queue_prune(path,&rd)==2);
    assert(d2k_shadow_snapshot_read(path,&dead,&snap)<0);
    assert(!d2k_shadow_snapshot_read(path,&live,&snap));
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.time==201);
    d2k_shadow_snapshot_remove(path,&live);unlink(path);assert(!rmdir(dir));
}
static void queue_sized_snapshot_storage(void)
{
    char dir[]="/tmp/shadow-storage-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);d2k_shadow_writer w={0};assert(!d2k_shadow_writer_set(&w,path));
    d2k_shadow_reader rd={0};d2k_shadow_record r=target(),out;
    uint8_t hello[D2K_SHADOW_HELLO_MAX]={22},opts[40]={1};
    /* 256 distinct queued forms fit 64 KiB; even maximal forms need storage. */
    for(unsigned i=0;i<256;i++) {
        r.time=100+i;hello[1]=(uint8_t)i;
        assert(!d2k_shadow_snapshot_write(path,&r,hello,sizeof hello,opts,sizeof opts,100));
        assert(d2k_shadow_queue_append(&w,&r)==1);
    }
    unsigned n=0;while(d2k_shadow_queue_next(path,&out,&rd)==1) {d2k_shadow_snapshot_remove(path,&out);n++;}
    assert(n==256);unlink(path);assert(!rmdir(dir));
}
static void legacy_ipv6_prune(void)
{
    char dir[]="/tmp/shadow-ipv6-prune-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);FILE *f=fopen(path,"w");assert(f);
    /* Valid legacy IPv6 references are just 19 bytes, shorter than IPv4. */
    for(unsigned i=0;i<3000;i++)assert(fputs("0\ta\t::\t1\t6\t0\t1\t0\t-\n",f)>=0);
    assert(!fclose(f));d2k_shadow_reader rd={.discard=obsolete};
    assert(d2k_shadow_queue_prune(path,&rd)==3000);
    struct stat st;assert(!stat(path,&st) && !st.st_size && !rd.malformed);
    unlink(path);assert(!rmdir(dir));
}
static void first_targets(void)
{
    char dir[]="/tmp/shadow-fair-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);d2k_shadow_writer w={0};assert(!d2k_shadow_writer_set(&w,path));
    d2k_shadow_record r=target(),out;r.form_key=1;r.time=100;
    strcpy(r.host,"house.example");assert(d2k_shadow_queue_append(&w,&r)==1);
    r.form_key=2;r.time=101;assert(d2k_shadow_queue_append(&w,&r)==1);
    strcpy(r.host,"first.example");r.time=102;assert(d2k_shadow_queue_append(&w,&r)==1);
    r.priority=1;r.time=103;assert(d2k_shadow_queue_append(&w,&r)==1);
    r.priority=2;r.time=104;assert(d2k_shadow_queue_append(&w,&r)==1);
    r.priority=0;r.time=99;strcpy(r.host,"earlier.example");assert(d2k_shadow_queue_append(&w,&r)==1);
    d2k_shadow_reader rd={.rank=dispatched,.rank_ctx="house.example"};
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.priority==2);
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.priority==1);
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && !strcmp(out.host,"earlier.example"));
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && !strcmp(out.host,"first.example"));
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.form_key==1 && out.time==100);
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.form_key==2 && out.time==101);
    unlink(path);assert(!rmdir(dir));
}
static void clean_scope(void)
{
    char dir[]="/tmp/shadow-clean-scope-XXXXXX",path[512],recent_path[540];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);snprintf(recent_path,sizeof recent_path,"%s.recent",path);
    d2k_shadow_recent recent={0},loaded={0};d2k_shadow_record clean=target();
    clean.time=100;clean.form_key=77;clean.protocol=2;clean.clean_source=1;clean.signal=0;
    assert(!d2k_shadow_record_normalize(&clean));
    d2k_shadow_recent_note(&recent,&clean,100);
    d2k_shadow_record r=clean;r.signal=2;r.time=101;r.clean_source=2;
    assert(d2k_shadow_recent_clean(&recent,&r,101));
    for(unsigned which=0;which<11;which++) {
        d2k_shadow_record x=r;
        switch(which) {
        case 0:x.form_key=0;break;case 1:x.form_key++;break;
        case 2:x.protocol=1;break;case 3:x.protocol=0;break;
        case 4:x.family=6;break;case 5:x.port++;break;
        case 6:strcpy(x.host,"other.example");break;case 7:strcpy(x.ip,"192.0.2.9");break;
        case 8:x.priority=2;break;case 9:x.degradation=1;break;
        case 10:x.clean_source=1;break; /* own later cut is not independent evidence */
        }
        assert(!d2k_shadow_recent_clean(&recent,&x,101));
    }
    assert(!d2k_shadow_recent_clean(&recent,&r,3701));
    assert(!d2k_shadow_recent_save(path,"recent",&recent,101));
    assert(!d2k_shadow_recent_load(path,"recent",&loaded,101));
    assert(d2k_shadow_recent_clean(&loaded,&r,101));
    clean.form_key++;d2k_shadow_recent_note(&recent,&clean,101);assert(recent.count==2);
    assert(!d2k_shadow_recent_save(path,"recent",&recent,101));
    assert(!d2k_shadow_recent_load(path,"recent",&loaded,101) && loaded.count==2);
    FILE *f=fopen(recent_path,"w");assert(f);
    fputs("D2KRECENT1\n100\tblocked.example\t192.0.2.1\t443\t4\t0\n",f);fclose(f);
    assert(!d2k_shadow_recent_load(path,"recent",&loaded,101) && loaded.count==1);
    assert(!d2k_shadow_recent_clean(&loaded,&r,101)); /* legacy name source isn't context evidence */
    unlink(recent_path);assert(!rmdir(dir));
}
int main(void)
{
    legacy_ipv6_prune();
    reclaim_unexecutable();
    queue_sized_snapshot_storage();
    clean_scope();
    first_targets();
    char dir[] = "/tmp/d2k-shadow-XXXXXX", path[512]; assert(mkdtemp(dir));
    snprintf(path, sizeof path, "%s/queue", dir);
    d2k_shadow_writer w = {0}; d2k_shadow_record r = target(), out;
    /* Disabled controller observer does not create a queue. */
    assert(d2k_shadow_queue_append(&w, &r) == 0); assert(access(path, F_OK) != 0);
    assert(d2k_shadow_writer_set(&w, path) == 0);
    assert(d2k_shadow_queue_append(&w, &r) == 1); assert(w.written == 1);
    d2k_shadow_reader rd = {0};
    assert(d2k_shadow_queue_next(path, &out, &rd) == 1);
    assert(!strcmp(out.host, "blocked.example") && !strcmp(out.ip, r.ip));
    assert(out.port == 443 && out.family == 4 && out.signal == 2 && out.time == 123);
    struct stat st; assert(stat(path, &st) == 0 && st.st_size == 0);
    assert(d2k_shadow_queue_next(path, &out, &rd) == 0);
    { FILE *old=fopen(path,"a");assert(old);fputs("123\tblocked.example\t192.0.2.1\t443\t4\t2\n",old);fclose(old);
      assert(d2k_shadow_queue_next(path,&out,&rd)==1 && !out.form_key && !out.snapshot); }
    /* Owners and degradation wakeups do not sit behind the site's round;
       records of the same priority retain their arrival order. */
    for(unsigned i=0;i<4;i++) {
        d2k_shadow_record x=target();x.time=200+i;x.priority=i==1?2:i==2?1:0;
        if(x.priority==2)strcpy(x.doh_path,"/dns-query?owner=1");
        assert(d2k_shadow_queue_append(&w,&x)==1);
    }
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.time==201 && out.priority==2 && !strcmp(out.doh_path,"/dns-query?owner=1"));
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.time==202 && out.priority==1);
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.time==200);
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.time==203);
    assert(!d2k_shadow_queue_next(path,&out,&rd));
    w.limit = 1; assert(d2k_shadow_queue_append(&w, &r) == -1 && w.dropped == 1);
    w.limit = D2K_SHADOW_QUEUE_MAX;
    int fd = open(path, O_WRONLY|O_APPEND); assert(fd >= 0);
    assert(write(fd, "bad line\npartial", 16) == 16); close(fd);
    assert(d2k_shadow_queue_append(&w, &r) == 1);
    assert(d2k_shadow_queue_next(path, &out, &rd) == 1 && rd.malformed == 2);
    fd = open(path, O_WRONLY|O_APPEND); assert(fd >= 0);
    assert(write(fd, "torn", 4) == 4); close(fd);
    assert(d2k_shadow_queue_next(path, &out, &rd) == 0 && rd.malformed == 3);
    assert(stat(path, &st) == 0 && st.st_size == 0);
    /* A different process holding the reader lock never stalls d2kc. */
    int ready[2], done[2]; assert(pipe(ready) == 0 && pipe(done) == 0);
    pid_t pid = fork(); assert(pid >= 0);
    if (!pid) {
        close(ready[0]); close(done[1]);
        int lockfd = open(path, O_RDWR); assert(lockfd >= 0);
        struct flock lk = {.l_type=F_WRLCK,.l_whence=SEEK_SET};
        assert(fcntl(lockfd,F_SETLK,&lk) == 0);
        assert(write(ready[1], "x", 1) == 1); char x;
        assert(read(done[0], &x, 1) == 1); close(lockfd); _exit(0);
    }
    close(ready[1]); close(done[0]); char x; assert(read(ready[0], &x, 1) == 1);
    assert(d2k_shadow_queue_append(&w, &r) == -1 && w.dropped == 2);
    assert(write(done[1], "x", 1) == 1); int status; assert(waitpid(pid,&status,0)==pid && status==0);
    close(ready[0]);close(done[1]);
    /* Writer and reader reclaim the same inode under a nonblocking lock. */
    pid = fork(); assert(pid >= 0);
    if (!pid) {
        d2k_shadow_writer child={0}; assert(!d2k_shadow_writer_set(&child,path));
        for (unsigned i=0;i<200;i++) { r.time=1000+i; (void)d2k_shadow_queue_append(&child,&r); }
        _exit((int)child.written); /* <= 200 */
    }
    unsigned read_count=0; int finished=0;
    while (!finished) {
        int n=d2k_shadow_queue_next(path,&out,&rd); assert(n>=0);
        if(n==1)read_count++;
        if(waitpid(pid,&status,WNOHANG)==pid)finished=1;
    }
    while(d2k_shadow_queue_next(path,&out,&rd)==1)read_count++;
    assert(WIFEXITED(status) && read_count==(unsigned)WEXITSTATUS(status));
    assert(stat(path,&st)==0 && st.st_size==0);
    r=target();strcpy(r.host,"injected\nname");assert(d2k_shadow_queue_append(&w,&r)==-1);
    /* Bounded atomic sidecars and independently published observations. */
    r=target(); uint8_t hello[]={22,3,3,0,1,1}, opts[]={1,1};
    d2k_shadow_snapshot snap={0};
    assert(!d2k_shadow_snapshot_write(path,&r,hello,sizeof hello,opts,sizeof opts,100));
    assert(r.form_key); /* a queued snapshot carries its context identity */
    assert(r.snapshot && !d2k_shadow_snapshot_read(path,&r,&snap));
    assert(snap.hello_len==sizeof hello && snap.options_len==2 && !memcmp(snap.hello,hello,sizeof hello));
    /* A crash may leave the old staging name linked to the published form. */
    char published[600],staging[600];
    snprintf(published,sizeof published,"%s.snap-%016llx",path,(unsigned long long)r.snapshot);
    snprintf(staging,sizeof staging,"%s.snap-tmp",path);
    assert(!link(published,staging));
    d2k_shadow_record next=r;
    assert(!d2k_shadow_snapshot_write(path,&next,opts,sizeof opts,NULL,0,100));
    assert(!d2k_shadow_snapshot_read(path,&r,&snap) && !memcmp(snap.hello,hello,sizeof hello));
    d2k_shadow_snapshot_remove(path,&next);
    unlink(staging);
    r.priority=2;
    assert(d2k_shadow_queue_append(&w,&r)==1);
    d2k_shadow_record later=r;later.time++;
    assert(!d2k_shadow_queue_pending(path,&later)); /* keep a new owner wakeup */
    assert(d2k_shadow_queue_pending(path,&r)==1);
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.snapshot==r.snapshot);
    assert(out.form_key==r.form_key);
    d2k_shadow_snapshot_remove(path,&r);assert(d2k_shadow_snapshot_read(path,&r,&snap)<0);
    assert(d2k_shadow_snapshot_write(path,&r,hello,D2K_SHADOW_HELLO_MAX+1,opts,2,100)<0);
    /* Oversized owned/corrupt files must still consume the resource cap.
       Sparse length avoids thousands of files/scans in this boundary test;
       real maximum-sized queued forms are exercised separately above. */
    char guard[600];snprintf(guard,sizeof guard,"%s.snap-0000000000000001",path);
    fd=open(guard,O_WRONLY|O_CREAT,0600);assert(fd>=0);
    assert(!ftruncate(fd,(off_t)D2K_SHADOW_QUEUE_MAX*D2K_SHADOW_HELLO_MAX));
    struct timespec stamp[2]={{100,0},{100,0}};assert(!futimens(fd,stamp));close(fd);
    assert(d2k_shadow_snapshot_write(path,&r,hello,sizeof hello,opts,2,100)<0);
    assert(r.form_key==d2k_shadow_form_key(hello,sizeof hello,opts,2));
    assert(d2k_shadow_snapshot_cleanup(path,3701)==1);
    assert(!d2k_shadow_snapshot_write(path,&r,hello,sizeof hello,opts,2,100));
    char owned[600];snprintf(owned,sizeof owned,"%s.snap-%016llx",path,(unsigned long long)r.snapshot);
    fd=open(owned,O_WRONLY|O_TRUNC);assert(fd>=0);assert(write(fd,"broken",6)==6);close(fd);
    assert(d2k_shadow_snapshot_read(path,&r,&snap)<0);d2k_shadow_snapshot_remove(path,&r);
    char tmp[600],foreign[600];snprintf(tmp,sizeof tmp,"%s.snap-tmp",path);
    snprintf(foreign,sizeof foreign,"%s.snap-someone-else",path);
    fd=open(tmp,O_WRONLY|O_CREAT,0600);assert(fd>=0);struct timespec old[2]={{100,0},{100,0}};
    assert(!futimens(fd,old));close(fd);fd=open(foreign,O_WRONLY|O_CREAT,0600);assert(fd>=0);close(fd);
    char orphan[600];snprintf(orphan,sizeof orphan,"%s.snap-tmp-AbC123",path);
    fd=open(orphan,O_WRONLY|O_CREAT,0600);assert(fd>=0);assert(!futimens(fd,old));close(fd);
    assert(d2k_shadow_snapshot_cleanup(path,3701)==2 && !access(foreign,F_OK));unlink(foreign);
    r=target();strcpy(r.history_name,"inject\nline");r.history_time=100;
    assert(d2k_shadow_queue_append(&w,&r)==-1);

    d2k_shadow_recent recent={0}, loaded={0};r=target();r.time=100;
    d2k_shadow_recent_note(&recent,&r,100);
    assert(!d2k_shadow_recent_save(path,"recent",&recent,100));
    assert(!d2k_shadow_recent_load(path,"recent",&loaded,100) && loaded.count==1);
    assert(!d2k_shadow_recent_load(path,"recent",&loaded,3701) && !loaded.count);
    /* R3: read/merge order cannot replace a newer observation/provenance. */
    d2k_shadow_recent duplicate={0};d2k_shadow_record fresh=target();fresh.time=4990;
    fresh.signal=0;d2k_shadow_record stale=fresh;stale.time=1500;stale.signal=1;
    d2k_shadow_recent_note(&duplicate,&fresh,5000);d2k_shadow_recent_note(&duplicate,&stale,5000);
    assert(duplicate.count==1 && duplicate.entries[0].time==4990 && duplicate.entries[0].signal==0);
    memset(&duplicate,0,sizeof duplicate);d2k_shadow_recent_note(&duplicate,&stale,5000);
    d2k_shadow_recent_note(&duplicate,&fresh,5000);
    assert(duplicate.count==1 && duplicate.entries[0].time==4990 && duplicate.entries[0].signal==0);
    for(unsigned i=0;i<D2K_SHADOW_RECENT_MAX+10;i++) {
        snprintf(r.host,sizeof r.host,"h%u.example.com",i);d2k_shadow_recent_note(&recent,&r,100);
    }
    assert(recent.count==D2K_SHADOW_RECENT_MAX);
    assert(!d2k_shadow_recent_save(path,"recent",&recent,100));
    assert(!d2k_shadow_recent_load(path,"recent",&loaded,100) && loaded.count==D2K_SHADOW_RECENT_MAX);
    char recent_path[600];snprintf(recent_path,sizeof recent_path,"%s.recent",path);unlink(recent_path);
    unlink(path);rmdir(dir);puts("shadow queue: ok");return 0;
}
