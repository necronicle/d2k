#include "tls_observe.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static size_t record(uint8_t *out,const uint8_t *p,size_t n) {
    out[0]=22;out[1]=3;out[2]=3;out[3]=(uint8_t)(n>>8);out[4]=(uint8_t)n;
    memcpy(out+5,p,n);return n+5;
}
int main(void) {
    uint8_t sh[50]={2,0,0,46,3,3};
    sh[39]=0x13;sh[40]=1;sh[43]=6;sh[45]=43;sh[47]=2;sh[48]=3;sh[49]=4;
    uint8_t wire[64];size_t used;
    for(size_t split=1;split<sizeof sh;split++) {
        size_t n=record(wire,sh,split);n+=record(wire+n,sh+split,sizeof sh-split);
        for(size_t chunk=1;chunk<=n;chunk++) {
            d2k_tls_observer *o=d2k_tls_observer_new();assert(o);
            size_t pos=0;d2k_tls_response r={0};
            while(pos<n) {
                size_t take=n-pos;if(take>chunk)take=chunk;
                r=d2k_tls_observer_feed(o,wire+pos,take,&used);
                assert(used==take);pos+=used;
                assert(r.kind==(pos==n?D2K_TLS_OBS_HELLO:D2K_TLS_OBS_MORE));
            }
            assert(r.version==0x304 && r.cipher==0x1301 && !r.retry);
            d2k_tls_observer_free(o);
        }
    }
    d2k_tls_observer *o=d2k_tls_observer_new();assert(o);
    size_t n=record(wire,sh,sizeof sh);
    d2k_tls_response r=d2k_tls_observer_feed(o,wire,n-1,&used);
    assert(r.kind==D2K_TLS_OBS_MORE && used==n-1);d2k_tls_observer_free(o);
    sh[38]=33;n=record(wire,sh,sizeof sh);o=d2k_tls_observer_new();assert(o);
    r=d2k_tls_observer_feed(o,wire,n,&used);assert(r.kind==D2K_TLS_OBS_MALFORMED);
    d2k_tls_observer_free(o);
    uint8_t alert[]={21,3,3,0,2,2,40,99};o=d2k_tls_observer_new();assert(o);
    r=d2k_tls_observer_feed(o,alert,sizeof alert,&used);
    assert(r.kind==D2K_TLS_OBS_ALERT && used==7 && r.alert_level==2 && r.alert_description==40);
    d2k_tls_observer_free(o);
    /* TLS 1.2 ServerHello has no mandatory extensions vector. */
    sh[38]=0;sh[3]=38;sh[39]=0;sh[40]=0x2f;
    n=record(wire,sh,42);o=d2k_tls_observer_new();assert(o);
    r=d2k_tls_observer_feed(o,wire,n,&used);
    assert(r.kind==D2K_TLS_OBS_HELLO && r.version==0x303 && r.cipher==0x2f);
    d2k_tls_observer_free(o);
    /* Repeated extensions are invalid even when their values agree. */
    sh[3]=52;sh[43]=12;memcpy(wire,sh,50);memcpy(wire+50,sh+44,6);
    uint8_t duplicated[64];n=record(duplicated,wire,56);
    o=d2k_tls_observer_new();assert(o);
    r=d2k_tls_observer_feed(o,duplicated,n,&used);
    assert(r.kind==D2K_TLS_OBS_MALFORMED);d2k_tls_observer_free(o);
    /* Declared allocation bound follows the protocol vectors. */
    uint8_t huge[]={22,3,3,0,4,2,255,255,255};
    o=d2k_tls_observer_new();assert(o);
    r=d2k_tls_observer_feed(o,huge,sizeof huge,&used);
    assert(r.kind==D2K_TLS_OBS_MALFORMED);d2k_tls_observer_free(o);
    puts("TLS observer: byte and record fragmentation, incomplete hello, invalid vector and alert PASS");
}
