#include "tls_decode.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    d2k_tls_decoder d={0};assert(!d2k_tls_decoder_begin(&d));
    uint8_t alert[]={21,3,3,0,2,2,40};uint64_t symbol;
    d2k_raw_observation obs={.kind=D2K_RAW_OBS_RESPONSE_TIMEOUT};
    assert(d2k_tls_decoder_read(&d,0,&obs,alert,4,&symbol)==1);
    d2k_tls_response r;int timeout,reset;
    assert(d2k_tls_symbol_read(symbol,&r,&timeout,&reset)==1);
    assert(r.kind==D2K_TLS_OBS_MORE && timeout && !reset);
    obs.kind=D2K_RAW_OBS_RESPONSE_BYTES;
    assert(d2k_tls_decoder_read(&d,1,&obs,alert+4,3,&symbol)==2);
    assert(d2k_tls_symbol_read(symbol,&r,&timeout,&reset)==1);
    assert(r.kind==D2K_TLS_OBS_ALERT && r.alert_description==40 && !timeout);
    assert(d2k_tls_decoder_read(&d,1,&obs,alert,7,&symbol)==0 && !symbol);
    assert(!d2k_tls_decoder_begin(&d));
    assert(d2k_tls_decoder_read(&d,1,&obs,alert+4,3,&symbol)==1);
    assert(d2k_tls_symbol_read(symbol,&r,&timeout,&reset)==1 && r.kind==D2K_TLS_OBS_MORE);
    obs.kind=D2K_RAW_OBS_LOCAL;
    assert(d2k_tls_decoder_read(&d,1,&obs,NULL,0,&symbol)==0 && !symbol);
    obs.kind=D2K_RAW_OBS_RESPONSE_RESET;
    assert(d2k_tls_decoder_read(&d,1,&obs,NULL,0,&symbol)==2);
    assert(d2k_tls_symbol_read(symbol,&r,&timeout,&reset)==1 && reset);
    assert(!d2k_tls_symbol_read(0,&r,&timeout,&reset));
    assert(!d2k_tls_decoder_begin(&d));
    obs.kind=D2K_RAW_OBS_RESPONSE_FIN;
    assert(d2k_tls_decoder_read(&d,0,&obs,alert,4,&symbol)==2);
    assert(d2k_tls_symbol_read(symbol,&r,&timeout,&reset)==1);
    assert(r.kind==D2K_TLS_OBS_MORE && !timeout && !reset && d2k_tls_symbol_closed(symbol));
    assert(!d2k_tls_symbol_closed(0));
    d2k_tls_decoder_free(&d);d2k_tls_decoder_free(&d);
    puts("TLS decode: partial bytes at timeout, terminal alert, reset and episode isolation PASS");
}
