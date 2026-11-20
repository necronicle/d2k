#include "d2k_tls13.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int fails;
#define CHECK(x) do { if(!(x)){fprintf(stderr,"SH records:%d: %s\n",__LINE__,#x);fails++;} } while(0)
typedef struct { int fd; unsigned reads,writes; uint8_t hello[4096];size_t hello_len; } transport;
static long stream_read(void *ctx,uint8_t *b,size_t n,int wait,char *err,size_t cap)
{
    transport *t=ctx;(void)err;(void)cap;CHECK(wait>0);t->reads++;
    return read(t->fd,b,n>3?3:n);
}
static int stream_write(void *ctx,const uint8_t *b,size_t n,char *err,size_t cap)
{
    transport *t=ctx;(void)err;(void)cap;t->writes++;
    CHECK(n>5 && b[0]==22);
    if(n<=sizeof t->hello){memcpy(t->hello,b,n);t->hello_len=n;}
    return write(t->fd,b,n)==(ssize_t)n?0:-1;
}
static void record(int fd,const uint8_t *p,size_t n)
{
    uint8_t h[]={22,3,3,(uint8_t)(n>>8),(uint8_t)n};
    CHECK(write(fd,h,sizeof h)==(ssize_t)sizeof h);
    CHECK(write(fd,p,n)==(ssize_t)n);
}
int main(void)
{
    {
        d2k_tls_io invalid={0};d2k_tls *tls=NULL;char err[256]={0};
        CHECK(d2k_tls_connect_io(&invalid,"example.test",300,0,NULL,0,&tls,err,sizeof err)<0);
        CHECK(!tls && err[0]);
        CHECK(d2k_tls_connect_io(NULL,"example.test",300,0,NULL,0,&tls,err,sizeof err)<0);
        CHECK(!tls && err[0]);
    }
    /* Structurally complete SH, TLS1.3 selected, deliberately unsupported
       cipher. Every fragmentation must reach the same cipher rejection. */
    uint8_t sh[50]={2,0,0,46,3,3};
    sh[38]=0;sh[39]=0x13;sh[40]=2;sh[41]=0;
    sh[42]=0;sh[43]=6;sh[44]=0;sh[45]=43;sh[46]=0;sh[47]=2;
    sh[48]=3;sh[49]=4;
    d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();CHECK(seed!=NULL);
    uint8_t first[4096];size_t first_len=0;
    uint8_t prepared[4096];size_t prepared_len=d2k_tls_probe_hello(seed,"example.test",1200,NULL,0,prepared,sizeof prepared);
    CHECK(prepared_len==1200);
    for(int repeat=0;repeat<2 && seed;repeat++) {
        int fd[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,fd));
        record(fd[1],sh,sizeof sh);shutdown(fd[1],SHUT_WR);
        transport t={.fd=fd[0]};d2k_tls_io io={&t,stream_read,stream_write};
        char err[256]={0};d2k_tls *tls=NULL;
        CHECK(d2k_tls_connect_probe(&io,seed,"example.test",300,1200,NULL,0,&tls,err,sizeof err)<0);
        CHECK(strstr(err,"0x1302")!=NULL && t.hello_len==1200);
        CHECK(t.hello_len==prepared_len && !memcmp(t.hello,prepared,prepared_len));
        if(!repeat){memcpy(first,t.hello,t.hello_len);first_len=t.hello_len;}
        else CHECK(first_len==t.hello_len && !memcmp(first,t.hello,first_len));
        d2k_tls_free(tls);close(fd[0]);close(fd[1]);
    }
    d2k_tls_probe_seed_free(seed);
    for(int custom=0;custom<2;custom++)for(size_t cut=0;cut<sizeof sh;cut++) {
        int fd[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,fd));
        if(cut) {record(fd[1],sh,cut);record(fd[1],sh+cut,sizeof sh-cut);}
        else record(fd[1],sh,sizeof sh);
        shutdown(fd[1],SHUT_WR);
        char err[256]={0};d2k_tls *tls=NULL;
        transport t={.fd=fd[0]};d2k_tls_io io={&t,stream_read,stream_write};
        if(custom) {
            CHECK(d2k_tls_connect_io(&io,"example.test",300,0,NULL,0,&tls,err,sizeof err)<0);
            CHECK(t.writes==1 && t.reads>1);
        } else CHECK(d2k_tls_connect(fd[0],"example.test",300,0,&tls,err,sizeof err)<0);
        CHECK(strstr(err,"0x1302")!=NULL);
        d2k_tls_free(tls);close(fd[0]);close(fd[1]);
    }
    /* A complete record is not necessarily a complete handshake message.
       The cipher field is present, but one declared message byte is absent. */
    {
        int fd[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,fd));
        record(fd[1],sh,sizeof sh-1);shutdown(fd[1],SHUT_WR);
        char err[256]={0};d2k_tls *tls=NULL;
        CHECK(d2k_tls_connect(fd[0],"example.test",300,0,&tls,err,sizeof err)<0);
        CHECK(err[0] && !strstr(err,"0x1302"));
        d2k_tls_free(tls);close(fd[0]);close(fd[1]);
    }
    puts(fails?
"SH record fragmentation failed":"SH record fragmentation reaches cipher parser: OK");
    return fails?1:0;
}
