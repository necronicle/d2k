#include "tls_observe.h"
#include <stdlib.h>
#include <string.h>
struct d2k_tls_observer {
    d2k_tls_response result;
    uint8_t record[5],handshake[4],alert[2],*body;
    size_t record_have,record_left,handshake_have,body_have,body_len,alert_have;
};
static unsigned u16(const uint8_t *p) {return (unsigned)p[0]*256+p[1];}
d2k_tls_observer *d2k_tls_observer_new(void) {return calloc(1,sizeof(d2k_tls_observer));}
void d2k_tls_observer_free(d2k_tls_observer *o) {if(o){free(o->body);free(o);}}
static d2k_tls_response_kind hello(d2k_tls_observer *o) {
    const uint8_t *p=o->body;size_t n=o->body_len;
    if(n<38 || p[34]>32 || (size_t)p[34]+38>n)return D2K_TLS_OBS_MALFORMED;
    o->result.version=(uint16_t)u16(p);
    if(p[0]!=3 || p[1]<1 || p[1]>3)return D2K_TLS_OBS_MALFORMED;
    size_t off=35+p[34];o->result.cipher=(uint16_t)u16(p+off);
    o->result.compression=p[off+2];off+=3;
    if(off<n) {
        if(n-off<2 || u16(p+off)!=n-off-2)return D2K_TLS_OBS_MALFORMED;
        off+=2;uint8_t seen[8192]={0};
        while(off<n) {
            if(n-off<4)return D2K_TLS_OBS_MALFORMED;
            unsigned type=u16(p+off);size_t len=u16(p+off+2);off+=4;
            if(len>n-off || (seen[type/8]&(1u<<(type%8))))return D2K_TLS_OBS_MALFORMED;
            seen[type/8]|=(uint8_t)(1u<<(type%8));
            if(type==43) {
                if(len!=2)return D2K_TLS_OBS_MALFORMED;
                o->result.version=(uint16_t)u16(p+off);
            }
            off+=len;
        }
    }
    if(o->result.version==0x304 && (u16(p)!=0x303 || o->result.compression))
        return D2K_TLS_OBS_MALFORMED;
    static const uint8_t retry[32]={
        0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
    o->result.retry=!memcmp(p+2,retry,sizeof retry);
    if(o->result.retry && o->result.version!=0x304)return D2K_TLS_OBS_MALFORMED;
    return D2K_TLS_OBS_HELLO;
}
d2k_tls_response d2k_tls_observer_feed(d2k_tls_observer *o,const uint8_t *p,size_t n,size_t *used) {
    if(used)*used=0;
    if(!o || !used || (n && !p))return (d2k_tls_response){.kind=D2K_TLS_OBS_LOCAL};
    while(*used<n && o->result.kind==D2K_TLS_OBS_MORE) {
        if(o->record_have<5) {
            o->record[o->record_have++]=p[(*used)++];
            if(o->record_have<5)continue;
            o->record_left=u16(o->record+3);
            if(o->record[1]!=3 || o->record[2]<1 || o->record[2]>3 ||
               !o->record_left || o->record_left>16384) {
                o->result.kind=D2K_TLS_OBS_MALFORMED;break;
            }
            if(o->record[0]!=22 && o->record[0]!=21) {
                o->result.kind=D2K_TLS_OBS_OTHER;break;
            }
            if(o->record[0]==21 && (o->handshake_have || o->record_left%2)) {
                o->result.kind=D2K_TLS_OBS_MALFORMED;break;
            }
            continue;
        }
        uint8_t b=p[(*used)++];--o->record_left;
        if(o->record[0]==21) {
            o->alert[o->alert_have++]=b;
            if(o->alert_have==2) {
                o->result.alert_level=o->alert[0];o->result.alert_description=o->alert[1];
                o->result.kind=(o->alert[0]==1 || o->alert[0]==2)?D2K_TLS_OBS_ALERT:D2K_TLS_OBS_MALFORMED;
            }
        } else if(o->handshake_have<4) {
            o->handshake[o->handshake_have++]=b;
            if(o->handshake_have==4) {
                o->body_len=(size_t)o->handshake[1]*65536+u16(o->handshake+2);
                if(o->handshake[0]!=2)o->result.kind=D2K_TLS_OBS_OTHER;
                /* ServerHello vectors: fixed 38, session ID <=32,
                   extensions length 2 and body <=65535 (RFC 5246/8446). */
                else if(o->body_len<38 || o->body_len>38+32+2+65535)
                    o->result.kind=D2K_TLS_OBS_MALFORMED;
                else if(!(o->body=malloc(o->body_len)))o->result.kind=D2K_TLS_OBS_LOCAL;
            }
        } else {
            o->body[o->body_have++]=b;
            if(o->body_have==o->body_len)o->result.kind=hello(o);
        }
        if(!o->record_left)o->record_have=0;
    }
    return o->result;
}
