#define _POSIX_C_SOURCE 200809L
#include "../synthesis/application_policy.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#ifndef SO_MARK
#define SO_MARK 36
#endif
static volatile sig_atomic_t stop;
static void halt(int sig){(void)sig;stop=1;}
static int cancelled(void *ctx){(void)ctx;return stop;}
static int decision(void *ctx,d2k_application_model *m,d2k_application_update u){
 size_t n=0;const d2k_application_observation *h=d2k_application_model_history(m,&n);
 if(u==D2K_APP_ERROR || u==D2K_APP_REJECTED || !h || !n)return -1;
 return h[n-1].query.dns_valid && h[n-1].query.ordinal<*(unsigned *)ctx;
}
typedef struct {int fd,first;const uint8_t *hello;size_t length;} socket_io;
static int ready(int fd,short events,int64_t end){
 while(!stop){
  int64_t left=end-d2k_now_ms();if(left<=0)return 0;
  struct pollfd p={fd,events,0};int rc=poll(&p,1,left>100?100:(int)left);
  if(rc<0 && errno!=EINTR)return -1;
  if(rc>0)return (p.revents&(events|POLLHUP|POLLERR))?1:-1;
 }
 return -1;
}
static long socket_read(void *ctx,uint8_t *buf,size_t cap,int wait,char *err,size_t ec){
 socket_io *s=ctx;int64_t end=d2k_now_ms()+wait;
 while(!stop){
  if(ready(s->fd,POLLIN,end)<=0)break;
  ssize_t n=recv(s->fd,buf,cap,0);
  if(n>=0)return n;
  if(errno!=EINTR && errno!=EAGAIN && errno!=EWOULDBLOCK)break;
 }
 snprintf(err,ec,"kernel TCP receive failed or timed out");return -1;
}
static int socket_write(void *ctx,const uint8_t *buf,size_t n,char *err,size_t ec){
 socket_io *s=ctx;
 if(!s->first){
  if(n!=s->length || memcmp(buf,s->hello,n)){snprintf(err,ec,"kernel first input mismatch");return -1;}
  s->first=1;
 }
 size_t at=0;int64_t end=d2k_now_ms()+5000;
 while(at<n && !stop){
  if(ready(s->fd,POLLOUT,end)<=0)break;
  ssize_t z=send(s->fd,buf+at,n-at,0);
  if(z>0)at+=(size_t)z;
  else if(z==0 || (errno!=EINTR && errno!=EAGAIN && errno!=EWOULDBLOCK))break;
 }
 if(at==n)return 0;
 snprintf(err,ec,"kernel TCP send incomplete");return -1;
}
typedef struct {unsigned depth;int64_t delay_ms;} timing_control;
static int observe(void *ctx,const d2k_doh_observation *o){
 timing_control *control=ctx;
 printf("kernel query=%u dns=%d http=%d complete=%d timeout=%d tls=%llu missing=%u reason=%s\n",o->ordinal,o->dns_valid,o->response.status,o->response.body_complete,o->timed_out,(unsigned long long)o->response.rx_tls_wire_bytes,o->response.rx_tls_record_missing,o->response.reason);fflush(stdout);
 if(o->dns_valid && o->ordinal==1 && control->delay_ms>0){
  int64_t until=d2k_now_ms()+control->delay_ms;
  printf("kernel measured_pause_ms=%lld\n",(long long)control->delay_ms);fflush(stdout);
  while(!stop && d2k_now_ms()<until){int64_t left=until-d2k_now_ms();if(left<=0)break;if(left>50)left=50;struct timespec ts={0,left*1000000};nanosleep(&ts,NULL);}
 }
 return !stop && o->dns_valid && o->ordinal<control->depth;
}
int main(int argc,char **argv){
 if(argc!=4 && argc!=5 && argc!=6)return 2;
 int timed=argc==6 && !strcmp(argv[5],"--measured-pause");
 if(argc==6 && !timed)return 2;
 unsigned source_port=0;
 if(argc>=5){char *end=NULL;errno=0;unsigned long p=strtoul(argv[4],&end,10);if(errno || !*argv[4] || *end || !p || p>65535)return 2;source_port=(unsigned)p;}
 signal(SIGINT,halt);signal(SIGTERM,halt);signal(SIGPIPE,SIG_IGN);
 d2k_detect_stop cancel={cancelled,NULL};
 d2k_experiment net={.family=4,.port=443,.mark=0x2f,.offer_ts=1,.connect_ms=5000,.cancel=&cancel};
 if(inet_pton(AF_INET,argv[1],net.ip)!=1)return 2;
 int fd=open(argv[3],O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return 2;
 FILE *archive=fdopen(fd,"wb");if(!archive){close(fd);return 2;}
 int rc=2,sock=-1;d2k_application_model *m=NULL;d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();if(!seed)goto done;
 d2k_synthesis_feedback id={.generation=1,.search_id=1,.target=argv[2],.ip=argv[1],.resource="/dns-query",.doh=1,.family=4,.transport=6,.port=443,.shape=D2K_SHAPE_MODERN};
 char direct[]="d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\ninput tls-sni\nsegment 1400\norder forward\n";
 unsigned depth=10;d2k_ver_result r={0};
 if(d2k_application_identify_trial(&id,direct))goto done;
 (void)d2k_application_doh_learn(&id,1,&net,seed,5000,1200,decision,&depth,&m,&r);
 const d2k_application_end *end=d2k_application_model_end(m);
 if(!end || !end->network_evidence || d2k_application_save(archive,m,&r) || r.local_refusal || r.local_limit || r.unsupported || stop)goto done;
 printf("raw dns=%u complete=%d reason=%s\n",r.doh_replies,r.body_complete,r.reason);fflush(stdout);
 if(d2k_application_query_complete(&r) && r.doh_replies>=depth){puts("raw direct healthy: stop");rc=0;goto done;}
 timing_control control={depth,0};
 if(timed){
  size_t count=0;const d2k_application_observation *h=d2k_application_model_history(m,&count);
  if(count<2 || h[count-1].query.dns_valid || !h[0].query.dns_valid)goto done;
  control.delay_ms=h[count-1].query.started_ms-h[0].query.started_ms;
  if(control.delay_ms<=0)goto done;
 }
 uint8_t hello[1200];const uint8_t alpn[]={2,'h','2'};
 if(d2k_tls_probe_hello(seed,argv[2],sizeof hello,alpn,sizeof alpn,hello,sizeof hello)!=sizeof hello || end->input_length!=sizeof hello || memcmp(hello,end->input,sizeof hello))goto done;
 sock=socket(AF_INET,SOCK_STREAM,0);if(sock<0)goto done;
 unsigned mark=0x2f;if(setsockopt(sock,SOL_SOCKET,SO_MARK,&mark,sizeof mark))goto done;
 if(source_port){struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons((uint16_t)source_port)};if(bind(sock,(struct sockaddr *)&local,sizeof local))goto done;}
 if(fcntl(sock,F_SETFL,O_NONBLOCK)<0)goto done;
 struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(443)};memcpy(&address.sin_addr,net.ip,4);
 if(connect(sock,(struct sockaddr *)&address,sizeof address)<0 && errno!=EINPROGRESS)goto done;
 if(ready(sock,POLLOUT,d2k_now_ms()+5000)<=0)goto done;
 int error=0;socklen_t z=sizeof error;if(getsockopt(sock,SOL_SOCKET,SO_ERROR,&error,&z) || error)goto done;
 socket_io ctx={sock,0,hello,sizeof hello};d2k_tls_io io={&ctx,socket_read,socket_write};
 r=d2k_verify_doh_observe_io(&io,seed,argv[2],"/dns-query",5000,1200,observe,&control);
 printf("kernel same_hello=%d dns=%u complete=%d reason=%s\n",ctx.first,r.doh_replies,r.body_complete,r.reason);fflush(stdout);
 rc=!stop && ctx.first && d2k_application_query_complete(&r) && r.doh_replies>=depth?0:1;
done:
 if(sock>=0)close(sock);d2k_application_model_free(m);d2k_tls_probe_seed_free(seed);if(fclose(archive))rc=2;return rc;
}
