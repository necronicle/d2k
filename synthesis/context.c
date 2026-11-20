#include "context.h"
#include <stdlib.h>
#include <string.h>
typedef struct {uint8_t *bytes;size_t at,cap;int failed;} encoder;
static void bytes(encoder *e,const void *p,size_t n) {
    if(e->failed || n>e->cap-e->at){e->failed=1;return;}
    if(n)memcpy(e->bytes+e->at,p,n);
    e->at+=n;
}
static void number(encoder *e,uint64_t value) {
    uint8_t b[8];for(size_t i=0;i<8;i++)b[7-i]=(uint8_t)(value>>(i*8));bytes(e,b,8);
}
static void vector(encoder *e,const void *p,size_t n) {number(e,n);bytes(e,p,n);}
static int extend(size_t *n,size_t extra) {if(extra>SIZE_MAX-*n)return -1;*n+=extra;return 0;}
void d2k_learning_context_free(d2k_learning_context *c) {
    if(c){free(c->bytes);memset(c,0,sizeof *c);}
}
int d2k_tls_stream_context(const d2k_tls_stream *s,const d2k_experiment *e,
    uint64_t generation,uint64_t decoder_schema,const void *initial,size_t initial_len,
    d2k_learning_context *out) {
    if(!out)return -1;
    memset(out,0,sizeof *out);
    if(!s || !e || !generation || !decoder_schema || !initial || !initial_len ||
       (e->family!=4 && e->family!=6) || !e->port || e->connect_ms<=0 ||
       !d2k_tls_stream_domain(s).states || s->read_minimum>e->reply_capacity)return -1;
    const d2k_trigger *tr=s->trigger;
    const char *end=memchr(tr->name,0,sizeof tr->name);
    if(!end || tr->client_tcp_options_len>sizeof tr->client_tcp_options || tr->sni_off<0 ||
       tr->sni_len<0 || (size_t)tr->sni_off>tr->len || (size_t)tr->sni_len>tr->len-(size_t)tr->sni_off ||
       s->chunks>SIZE_MAX/8)return -1;
    size_t name_len=(size_t)(end-tr->name),cap=256;
    if(extend(&cap,tr->len) || extend(&cap,name_len) || extend(&cap,tr->client_tcp_options_len) ||
       extend(&cap,s->chunks*8) || extend(&cap,initial_len))return -1;
    uint8_t *storage=malloc(cap);if(!storage)return -1;
    encoder enc={storage,0,cap,0};
    static const char schema[]="D2K/TLS-STREAM-CONTEXT/2";
    bytes(&enc,schema,sizeof schema);
    number(&enc,generation);number(&enc,decoder_schema);
    number(&enc,e->family);bytes(&enc,e->ip,e->family==4?4:16);
    number(&enc,e->port);number(&enc,e->mark);number(&enc,(unsigned)e->connect_ms);
    number(&enc,!!e->offer_ts);number(&enc,(unsigned)s->read_timeout_ms);
    number(&enc,s->read_minimum);number(&enc,e->reply_capacity);
    number(&enc,!!e->read_to_terminal);
    vector(&enc,tr->name,name_len);vector(&enc,tr->payload,tr->len);
    number(&enc,(unsigned)tr->sni_off);number(&enc,(unsigned)tr->sni_len);
    number(&enc,tr->accept);number(&enc,!!tr->client_tcp_known);
    vector(&enc,tr->client_tcp_options,tr->client_tcp_options_len);
    number(&enc,s->chunks);for(size_t i=0;i<s->chunks;i++)number(&enc,s->chunk_bytes[i]);
    vector(&enc,initial,initial_len);
    if(enc.failed){free(storage);return -1;}
    out->bytes=storage;out->length=enc.at;return 0;
}
