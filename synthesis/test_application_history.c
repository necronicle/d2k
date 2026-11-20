#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include "application_history.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
typedef struct {int value,calls;} selection;
static int load(void *ctx,FILE *f) {
    selection *s=ctx;s->calls++;
    int c=fgetc(f);
    if(c=='!')return -1;
    if(c<'1' || c>'9')return 0;
    s->value=c-'0';return 1;
}
static int stopped(void *ctx){return *(int *)ctx;}
static void record(const char *path,const char *body,time_t modified) {
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);assert(fd>=0);
    assert(write(fd,body,strlen(body))==(ssize_t)strlen(body));
    struct timespec times[2]={{modified,0},{modified,0}};
    assert(!futimens(fd,times));assert(!close(fd));
}
int main(void) {
    char directory[]="/tmp/d2k-history-scan-XXXXXX";assert(mkdtemp(directory));
    char catalog[512],older[512],newer[512],broken[512],foreign[512],link[512],fifo[512],empty[512];
    snprintf(catalog,sizeof catalog,"%s/catalog",directory);
    snprintf(older,sizeof older,"%s/catalog.application-aaaaaa",directory);
    snprintf(newer,sizeof newer,"%s/catalog.application-bbbbbb",directory);
    snprintf(broken,sizeof broken,"%s/catalog.application-cccccc",directory);
    snprintf(foreign,sizeof foreign,"%s/foreign.application-dddddd",directory);
    snprintf(link,sizeof link,"%s/catalog.application-eeeeee",directory);
    snprintf(fifo,sizeof fifo,"%s/catalog.application-ffffff",directory);
    snprintf(empty,sizeof empty,"%s/catalog.application-gggggg",directory);
    record(newer,"2",200);record(older,"1",100);record(broken,"!",300);
    record(foreign,"9",400);record(empty,"",500);
    assert(!symlink(foreign,link));assert(!mkfifo(fifo,0600));
    selection chosen={0};d2k_history_scan_stats stats;
    assert(d2k_application_history_scan(catalog,load,&chosen,NULL,&stats)==1);
    assert(chosen.value==2 && stats.rejected==1);
    int cancel=1;d2k_inference_control control={stopped,&cancel};
    int calls=chosen.calls;
    assert(d2k_application_history_scan(catalog,load,&chosen,&control,&stats)==-1);
    assert(errno==ECANCELED && chosen.calls==calls && chosen.value==2);
    assert(!unlink(newer));
    chosen=(selection){0};
    assert(d2k_application_history_scan(catalog,load,&chosen,NULL,&stats)==1 && chosen.value==1);
    assert(!unlink(older));assert(!unlink(broken));assert(!unlink(foreign));
    assert(!unlink(link));assert(!unlink(fifo));assert(!unlink(empty));
    chosen=(selection){0};
    assert(d2k_application_history_scan(catalog,load,&chosen,NULL,&stats)==0 && !chosen.calls);
    assert(!rmdir(directory));
    assert(d2k_application_history_scan(catalog,load,&chosen,NULL,&stats)==0);
    return 0;
}
