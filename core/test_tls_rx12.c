/* Local encrypted-record fixture, not a TLS1.2 handshake implementation. */
#include "tls12.c"
#include <stdio.h>
#include <pthread.h>
typedef struct { int fd; const uint8_t *p; size_t n; int failed; } sender;
static void *serve_record(void *arg) { sender *s=arg;char err[80];s->failed=write_all(s->fd,s->p,s->n,err,sizeof err);shutdown(s->fd,SHUT_WR);return NULL; }
static int fails;
#define CHECK(x) do { if(!(x)){fprintf(stderr,"TLS12 RX:%d: %s\n",__LINE__,#x);fails++;} } while(0)
int main(void) {
    for(int mode=0;mode<4;mode++) {
        int fd[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,fd));
        d2k_tls12 *t=calloc(1,sizeof *t);t->fd=fd[0];CHECK(!suite12_of(0xc02f,t));
        uint8_t wire[16389]={23,3,3,0x40,0}, plain[16360], nonce[12]={0},aad[13],tag[16];
        memset(plain,'x',sizeof plain);aad_of(0,REC_APPDATA,sizeof plain,aad);
        CHECK(!d2k_aes128_gcm_encrypt(t->s_key,nonce,aad,sizeof aad,plain,sizeof plain,wire+13,tag));
        memcpy(wire+13+sizeof plain,tag,16);
        if(mode==1)wire[sizeof wire-1]^=1;
        size_t n=mode==0?14005:mode==2?3:sizeof wire;
        sender srv={fd[1],wire,n,0};pthread_t th;CHECK(!pthread_create(&th,NULL,serve_record,&srv));
        uint8_t out[16384];memset(out,0xa5,sizeof out);char err[160];
        uint64_t before=d2k_tls12_rx_wire_bytes(t);
        long got=d2k_tls12_read(t,out,sizeof out,200,err,sizeof err);
        CHECK(d2k_tls12_rx_wire_bytes(t)-before==n);
        CHECK(d2k_tls12_rx_record_missing(t)==(mode==0?2384u:0u));
        if(mode==3)CHECK(got==(long)sizeof plain&&!memcmp(out,plain,sizeof plain));
        else CHECK(got<0&&out[0]==0xa5);
        pthread_join(th,NULL);CHECK(!srv.failed);
        d2k_tls12_free(t);close(fd[0]);close(fd[1]);
    }
    puts(fails?"TLS12 RX failed":"TLS12 RX partial/header/bad-tag/full: OK");return fails?1:0;
}
