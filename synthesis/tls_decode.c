#include "tls_decode.h"
#include <string.h>
int d2k_tls_decoder_begin(void *ctx) {
    d2k_tls_decoder *d=ctx;if(!d)return -1;
    d2k_tls_observer_free(d->observer);memset(d,0,sizeof *d);
    d->observer=d2k_tls_observer_new();return d->observer?0:-1;
}
void d2k_tls_decoder_free(d2k_tls_decoder *d) {
    if(d){d2k_tls_observer_free(d->observer);memset(d,0,sizeof *d);}
}
static uint64_t symbol(const d2k_tls_response *r,int timeout,int reset,int closed) {
    return UINT64_C(1)<<63 | (uint64_t)!!reset<<62 | (uint64_t)!!timeout<<61 |
        (uint64_t)!!closed<<60 |
        (uint64_t)r->kind<<57 | (uint64_t)!!r->retry<<56 |
        (uint64_t)r->alert_description<<48 | (uint64_t)r->alert_level<<40 |
        (uint64_t)r->compression<<32 | (uint64_t)r->cipher<<16 | r->version;
}
int d2k_tls_symbol_read(uint64_t s,d2k_tls_response *r,int *timeout,int *reset) {
    if(!r || !timeout || !reset)return -1;
    memset(r,0,sizeof *r);*timeout=*reset=0;
    unsigned kind=(unsigned)((s>>57)&7);
    if(!(s>>63) || kind>D2K_TLS_OBS_MALFORMED)return 0;
    r->kind=(d2k_tls_response_kind)kind;r->version=(uint16_t)s;r->cipher=(uint16_t)(s>>16);
    r->compression=(uint8_t)(s>>32);r->alert_level=(uint8_t)(s>>40);
    r->alert_description=(uint8_t)(s>>48);r->retry=(int)((s>>56)&1);
    *timeout=(int)((s>>61)&1);*reset=(int)((s>>62)&1);return 1;
}
int d2k_tls_symbol_closed(uint64_t s) {
    d2k_tls_response r;int timeout,reset;
    return d2k_tls_symbol_read(s,&r,&timeout,&reset)==1 && ((s>>60)&1);
}
int d2k_tls_decoder_read(void *ctx,size_t op,const d2k_raw_observation *obs,
                        const uint8_t *bytes,size_t n,uint64_t *out) {
    d2k_tls_decoder *d=ctx;(void)op;
    if(out)*out=0;
    if(!d || !d->observer || !obs || !out || (n && !bytes))return -1;
    if(d->terminal)return 0;
    int timeout=obs->kind==D2K_RAW_OBS_RESPONSE_TIMEOUT;
    int reset=obs->kind==D2K_RAW_OBS_RESPONSE_RESET;
    int closed=obs->kind==D2K_RAW_OBS_RESPONSE_FIN;
    if(!timeout && !reset && !closed && obs->kind!=D2K_RAW_OBS_RESPONSE_BYTES)return 0;
    size_t used=0;
    if(n)d->response=d2k_tls_observer_feed(d->observer,bytes,n,&used);
    if(d->response.kind==D2K_TLS_OBS_LOCAL)return -1;
    *out=symbol(&d->response,timeout,reset,closed);
    d->terminal=reset || closed || d->response.kind!=D2K_TLS_OBS_MORE;
    return d->terminal?2:1;
}
