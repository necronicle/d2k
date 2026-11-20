#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include "application_history.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static struct timespec modified(const struct stat *st) {
#ifdef __APPLE__
    return st->st_mtimespec;
#else
    return st->st_mtim;
#endif
}
int d2k_application_history_scan(const char *catalog,int (*load)(void *,FILE *),void *ctx,
    const d2k_inference_control *control,d2k_history_scan_stats *stats) {
    if(stats)memset(stats,0,sizeof *stats);
    if(!catalog || !*catalog || !load){errno=EINVAL;return -1;}
    const char *slash=strrchr(catalog,'/'),*base=slash?slash+1:catalog;
    if(!*base){errno=EINVAL;return -1;}
    size_t directory_len=slash?(slash==catalog?1:(size_t)(slash-catalog)):1;
    char *directory=malloc(directory_len+1);if(!directory)return -1;
    memcpy(directory,slash?catalog:".",directory_len);directory[directory_len]=0;
    DIR *dir=opendir(directory);int saved=errno;free(directory);
    if(!dir){errno=saved;return saved==ENOENT?0:-1;}
    static const char suffix[]=".application-";
    size_t base_len=strlen(base),suffix_len=sizeof suffix-1;
    int selected=0,rc=0;struct timespec newest={0};
    for(;;) {
        if(d2k_inference_stopped(control)){errno=ECANCELED;rc=-1;break;}
        errno=0;struct dirent *entry=readdir(dir);
        if(!entry){if(errno)rc=-1;break;}
        const char *name=entry->d_name;size_t length=strlen(name);
        if(length<base_len || length-base_len!=suffix_len+6 ||
           memcmp(name,base,base_len) || memcmp(name+base_len,suffix,suffix_len))continue;
        int valid=1;
        for(size_t i=length-6;i<length;i++) {
            unsigned char c=(unsigned char)name[i];
            if(!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9')))valid=0;
        }
        if(!valid)continue;
        int fd=openat(dirfd(dir),name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
        if(fd<0)continue;
        struct stat st;
        if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_size<=0) {
            close(fd);continue;
        }
        struct timespec at=modified(&st);
        if(selected && (at.tv_sec<newest.tv_sec ||
           (at.tv_sec==newest.tv_sec && at.tv_nsec<newest.tv_nsec))) {close(fd);continue;}
        FILE *f=fdopen(fd,"rb");if(!f){close(fd);rc=-1;break;}
        if(stats && stats->opened<UINT64_MAX)stats->opened++;
        int found=load(ctx,f);fclose(f);
        if(found==1){selected=1;newest=at;}
        else if(found<0 && stats && stats->rejected<UINT64_MAX)stats->rejected++;
    }
    saved=errno;closedir(dir);errno=saved;
    return rc<0?-1:selected;
}
