/* Файл включают и как текст в составные тесты — после системных заголовков,
   где glibc (с 2026) уже задал _POSIX_C_SOURCE сам: голый #define там —
   переопределение под -Werror (CI 22.10.2026). Отдельной единицей трансляции
   значение задаётся как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "d2k_udpruntime.h"
#include "d2k_plantlv.h"
#include "d2k_ipfrag.h"
#include "d2k_ip6frag_send.h"
#include "d2k_meas.h"
#include "d2k_tls13core.h"

static uint32_t udp_next_fragment_id(void){
    static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
    static uint32_t id;static int seeded;uint32_t result=0;
    pthread_mutex_lock(&lock);
    if(!seeded){if(d2k_t13_random((uint8_t *)&id,sizeof id))goto done;seeded=1;}
    if(!(uint16_t)++id)++id;
    result=id;
 done: pthread_mutex_unlock(&lock);return result;
}

void d2k_udp_batch_free(d2k_udp_batch *b){if(b){free(b->bytes);memset(b,0,sizeof *b);}}
int d2k_udp_plan_build(const char *text,const d2k_conn *c,uint32_t id,
    const uint8_t *payload,size_t len,d2k_udp_batch *out) {
    uint8_t *tlv=NULL;d2k_plan *p=NULL;d2k_actions acts={0};int rc=-1;
    size_t tn=0;char err[256];
    if(!out)return -1;
    memset(out,0,sizeof *out);
    if(!text || !c || !payload || !len)return -1;
    tlv=malloc(D2K_PLAN_TLV_MAX);out->bytes=malloc(D2K_UDP_BATCH_BYTES);
    if(!tlv || !out->bytes)goto done;
    if(d2k_plan_text_to_tlv(text,tlv,D2K_PLAN_TLV_MAX,&tn,err,sizeof err) ||
       d2k_plan_load(tlv,tn,&p,err,sizeof err))goto done;
    if(d2k_plan_transport(p)!=17)goto done;
    d2k_pkt in={0};in.payload=payload;in.payload_len=len;in.own_after_fakes=1;
    if(d2k_plan_apply(p,NULL,&in,&acts) || acts.fate==D2K_ORIG_HOLD)goto done;
    unsigned payloads=0;
    for(size_t i=0;i<acts.n;i++) {
        d2k_emit *e=&acts.v[i];size_t n=0,made=0;d2k_ipfrag_span spans[3];
        if(e->kind==D2K_EMIT_PAYLOAD && ++payloads>1)goto done;
        /* SOCK_DGRAM owns the ordinary IP header: it cannot honour IPID
           poison. Refuse before any prefix rather than silently lose it. */
        if(e->poison & D2K_POISON_IPID_ZERO)goto done;
        if(e->ipfrag) {
            d2k_ipfrag_plan shape;
            if(e->kind!=D2K_EMIT_PAYLOAD || e->pre_len || e->seq_shift || e->ack_shift ||
               e->poison || e->wire_profile || d2k_ipfrag_shape(e->ipfrag,&shape))goto done;
            if(c->family==6)n=d2k_udpfrag6_build_ex(c->src_ip6,c->dst_ip6,
                ntohs(c->src_port),ntohs(c->dst_port),e->bytes,e->len,&shape,id,
                c->ttl,c->traffic_class,c->flow_label,out->bytes+out->used,
                D2K_UDP_BATCH_BYTES-out->used,spans);
            else n=d2k_udpfrag_build_ex((const uint8_t *)&c->src_ip,(const uint8_t *)&c->dst_ip,
                ntohs(c->src_port),ntohs(c->dst_port),e->bytes,e->len,&shape,(uint16_t)id,
                c->ttl,c->traffic_class,out->bytes+out->used,D2K_UDP_BATCH_BYTES-out->used,spans);
            if(n)made=spans[n-1].off+spans[n-1].len;
        }else{
            made=d2k_wire_build_udp(c,e,out->bytes+out->used,D2K_UDP_BATCH_BYTES-out->used);
            if(made){n=1;spans[0]=(d2k_ipfrag_span){0,made};}
        }
        if(!made || out->n+n>D2K_UDP_BATCH_MAX)goto done;
        for(size_t k=0;k<n;k++){
            out->v[out->n].off=out->used+spans[k].off;
            out->v[out->n].len=spans[k].len;
            out->v[out->n].delay_us=k?0:e->delay_us;
            out->v[out->n].fragment=!!e->ipfrag;out->n++;
        }
        out->used+=made;
    }
    /* A pass-original plan still sends its original exactly once. */
    if(acts.fate==D2K_ORIG_PASS){
        d2k_emit e={0};e.kind=D2K_EMIT_PAYLOAD;e.bytes=payload;e.len=len;
        if(out->n>=D2K_UDP_BATCH_MAX)goto done;
        size_t n=d2k_wire_build_udp(c,&e,out->bytes+out->used,D2K_UDP_BATCH_BYTES-out->used);
        if(!n)goto done;
        out->v[out->n].off=out->used;out->v[out->n].len=n;out->n++;out->used+=n;
    }
    if(!out->n)goto done;
    rc=0;
done:
    free(tlv);d2k_plan_free(p);d2k_actions_free(&acts);
    if(rc)d2k_udp_batch_free(out);
    return rc;
}

typedef struct {
    int fd;
#ifdef __linux__
    d2k_ip6frag_sender six;
#endif
} udp_raw_sink;
static void udp_raw_init(udp_raw_sink *s){
    memset(s,0,sizeof *s);s->fd=-1;
#ifdef __linux__
    d2k_ip6frag_sender_init(&s->six);
#endif
}
static void udp_raw_close(udp_raw_sink *s){
    if(s->fd>=0)close(s->fd);
#ifdef __linux__
    d2k_ip6frag_sender_close(&s->six);
#endif
}
static int udp_raw_prepare(udp_raw_sink *s,const uint8_t *p,size_t n,uint32_t mark){
#ifndef __linux__
    (void)s;(void)p;(void)n;(void)mark;return -1;
#else
    if(p[0]>>4==6)return d2k_ip6frag_prepare(&s->six,p,n,mark);
    if(s->fd<0){
        s->fd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);int one=1;
        if(s->fd<0 || setsockopt(s->fd,IPPROTO_IP,IP_HDRINCL,&one,sizeof one))return -1;
#ifdef IP_NODEFRAG
        if(setsockopt(s->fd,IPPROTO_IP,IP_NODEFRAG,&one,sizeof one))return -1;
#else
        return -1;
#endif
        if(mark && d2k_mark_hook(s->fd,mark))return -1;
    }
    return 0;
#endif
}
static int udp_raw_send(udp_raw_sink *s,const uint8_t *p,size_t n,uint32_t mark){
#ifndef __linux__
    (void)s;(void)p;(void)n;(void)mark;return -1;
#else
    if(p[0]>>4==6)return d2k_ip6frag_send(&s->six,p,n,mark)==(ssize_t)n?0:-1;
    struct sockaddr_in dst={0};dst.sin_family=AF_INET;memcpy(&dst.sin_addr,p+16,4);
    return sendto(s->fd,p,n,0,(struct sockaddr *)&dst,sizeof dst)==(ssize_t)n?0:-1;
#endif
}
/* Private I/O seams: production uses the functions above; the runtime test
 * includes this unit and captures the sink without raw privileges. */
static int (*udp_prepare_io)(udp_raw_sink *,const uint8_t *,size_t,uint32_t)=udp_raw_prepare;
static int (*udp_send_io)(udp_raw_sink *,const uint8_t *,size_t,uint32_t)=udp_raw_send;
static uint32_t (*udp_fragment_id_io)(void)=udp_next_fragment_id;

/* No fragment-to-datagram fallback: a raw preparation failure is UNSENT. */
int d2k_udp_plan_send(int fd,const char *text,const uint8_t *payload,size_t len,uint32_t mark){
    struct sockaddr_storage local,peer;socklen_t sl=sizeof local,pl=sizeof peer;
    d2k_conn c={0};d2k_udp_batch b={0};int rc=-1,ttl=0;
    udp_raw_sink raw;udp_raw_init(&raw);
    if(getsockname(fd,(struct sockaddr *)&local,&sl) || getpeername(fd,(struct sockaddr *)&peer,&pl))goto done;
    int family=peer.ss_family,level=family==AF_INET6?IPPROTO_IPV6:IPPROTO_IP;
    int hop=family==AF_INET6?IPV6_UNICAST_HOPS:IP_TTL;socklen_t tl=sizeof ttl;
    if(getsockopt(fd,level,hop,&ttl,&tl) || ttl<=0 || ttl>255)goto done;
    c.ttl=(uint8_t)ttl;
    if(family==AF_INET6){
        struct sockaddr_in6 *a=(void *)&local,*z=(void *)&peer;c.family=6;
        memcpy(c.src_ip6,&a->sin6_addr,16);memcpy(c.dst_ip6,&z->sin6_addr,16);
        c.src_port=a->sin6_port;c.dst_port=z->sin6_port;
    }else if(family==AF_INET){
        struct sockaddr_in *a=(void *)&local,*z=(void *)&peer;c.family=4;
        c.src_ip=a->sin_addr.s_addr;c.dst_ip=z->sin_addr.s_addr;c.src_port=a->sin_port;c.dst_port=z->sin_port;
    }else goto done;
    uint32_t id=udp_fragment_id_io();if(!id)goto done;
    if(d2k_udp_plan_build(text,&c,id,payload,len,&b))goto done;
    for(size_t i=0;i<b.n;i++)if(b.v[i].fragment &&
        udp_prepare_io(&raw,b.bytes+b.v[i].off,b.v[i].len,mark))goto done;
    rc=0;
    for(size_t i=0;i<b.n;i++){
        const uint8_t *p=b.bytes+b.v[i].off;size_t n=b.v[i].len;
        if(b.v[i].delay_us){struct timespec wait={b.v[i].delay_us/1000000,(b.v[i].delay_us%1000000)*1000};
            int slept;
            do{slept=nanosleep(&wait,&wait);}while(slept && errno==EINTR);
            if(slept){rc=-1;break;}
        }
        if(b.v[i].fragment){
            if(udp_send_io(&raw,p,n,mark)){rc=-1;break;}
        }else{
            size_t off=family==AF_INET6?48:28;int want=family==AF_INET6?p[7]:p[8];
            if(n<off || setsockopt(fd,level,hop,&want,sizeof want) || send(fd,p+off,n-off,0)!=(ssize_t)(n-off)){
                rc=errno==ECONNREFUSED?-2:-1;break;
            }
        }
    }
    /* Restore even after a failed prefix send. */
    if(setsockopt(fd,level,hop,&ttl,sizeof ttl))rc=-1;
done:
    udp_raw_close(&raw);
    d2k_udp_batch_free(&b);return rc;
}
