/* Daemon lifecycle, persistence and setup failure without creating sockets:
 * an absent form fails before experimental control/netarm initialization. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2k_shadow_queue.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char queue[512],store[512],journal[512],logfile[512],diagnostic[512],seen[520],lockfile[520];
static void pause_briefly(void) { struct timespec ts={.tv_nsec=20000000};nanosleep(&ts,NULL); }
static pid_t launch(void)
{
    pid_t child=fork();assert(child>=0);
    if(!child) {
        execl("./d2kshadow","d2kshadow","--queue",queue,"--form","/missing-shadow-form.hex",
            "--store",store,"--journal",journal,"--log",logfile,"--daemon-log",diagnostic,
            "--exp-control","/missing-shadow-exp.sock",(char *)NULL);
        _exit(127);
    }
    return child;
}
static unsigned lines(void)
{
    FILE *f=fopen(logfile,"r");if(!f)return 0;
    unsigned n=0;char line[4096];
    while(fgets(line,sizeof line,f)) { assert(strstr(line,"outcome=FORM_NOT_REPRODUCED") && strstr(line,"state=WAIT") && strstr(line,"form=not-client") && strstr(line,"reason="));n++; }
    fclose(f);return n;
}
static void wait_lines(unsigned expected)
{
    for(unsigned i=0;i<250 && lines()<expected;i++)pause_briefly();
    assert(lines()==expected);
}
static void stop_child(pid_t child)
{
    assert(!kill(child,SIGTERM));int status=0;
    for(unsigned i=0;i<250;i++) {
        pid_t done=waitpid(child,&status,WNOHANG);
        if(done==child) { assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);return; }
        assert(done==0);pause_briefly();
    }
    kill(child,SIGKILL);waitpid(child,&status,0);assert(!"daemon ignored TERM");
}
int main(void)
{
    char dir[]="/tmp/d2k-shadow-daemon-XXXXXX";assert(mkdtemp(dir));
    snprintf(queue,sizeof queue,"%s/queue",dir);snprintf(store,sizeof store,"%s/store",dir);
    snprintf(journal,sizeof journal,"%s/why",dir);snprintf(logfile,sizeof logfile,"%s/log",dir);
    snprintf(diagnostic,sizeof diagnostic,"%s/diagnostic",dir);
    snprintf(seen,sizeof seen,"%s.seen",queue);snprintf(lockfile,sizeof lockfile,"%s.consumer",queue);
    d2k_shadow_writer writer={0};assert(!d2k_shadow_writer_set(&writer,queue));
    d2k_shadow_record r={.time=(uint64_t)time(NULL),.port=443,.family=4,.signal=2};
    strcpy(r.host,"blocked.example");strcpy(r.ip,"192.0.2.1");
    uint8_t bad[]={1,2,3};d2k_shadow_snapshot snapshot;
    assert(!d2k_shadow_snapshot_write(queue,&r,bad,sizeof bad,NULL,0,r.time));
    assert(d2k_shadow_queue_append(&writer,&r)==1);
    pid_t child=launch();wait_lines(1);
    for(unsigned i=0;i<250 && access(seen,F_OK);i++)pause_briefly();
    assert(!access(seen,F_OK));
    /* Concurrent daemon is rejected before any task. */
    pid_t duplicate=launch();int status;assert(waitpid(duplicate,&status,0)==duplicate);
    assert(WIFEXITED(status)&&WEXITSTATUS(status)==1);
    stop_child(child);
    assert(d2k_shadow_snapshot_read(queue,&r,&snapshot)<0); /* setup failure consumes form */
    FILE *f=fopen(seen,"r");assert(f);char line[512];
    assert(fgets(line,sizeof line,f)&&!strcmp(line,"D2KSHADOW1\n"));
    assert(fgets(line,sizeof line,f));unsigned long long until=0;
    assert(sscanf(line,"%llu",&until)==1);fclose(f);
    assert(until>=r.time+3600 && until<=r.time+3610); /* WAIT missing client form */
    /* Restart does not convert a duplicate suspicion into new experiments. */
    child=launch();r.time=(uint64_t)time(NULL);
    assert(!d2k_shadow_snapshot_write(queue,&r,bad,sizeof bad,NULL,0,r.time));
    assert(d2k_shadow_queue_append(&writer,&r)==1);
    struct stat st;int empty=0;
    for(unsigned i=0;i<250;i++) {
        assert(!stat(queue,&st));if(st.st_size==0) { empty=1;break; }pause_briefly();
    }
    assert(empty && lines()==1);stop_child(child);
    assert(d2k_shadow_snapshot_read(queue,&r,&snapshot)<0); /* skipped dedup consumes form */
    /* Existing malformed state fails closed, retaining catalog and logs. */
    f=fopen(seen,"w");assert(f);fputs("broken\n",f);fclose(f);
    child=launch();assert(waitpid(child,&status,0)==child);
    assert(WIFEXITED(status)&&WEXITSTATUS(status)==1 && lines()==1);
    unlink(queue);unlink(store);unlink(journal);unlink(logfile);unlink(diagnostic);unlink(seen);unlink(lockfile);
    assert(!rmdir(dir));puts("shadow daemon lifecycle: ok");return 0;
}
