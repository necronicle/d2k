#include "observation.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    d2k_observations *d=d2k_observations_new(); assert(d);
    d2k_raw_observation o={.kind=D2K_RAW_OBS_RESPONSE_ACK};
    d2k_raw_packet_event e={.flags=16,.ack_offset=4,.ack_in_sent_range=1};
    uint64_t a=0,b=0,c=0;
    assert(d2k_observations_decode(d,0,&o,&e,NULL,0,&a)==1 && a);
    assert(d2k_observations_decode(d,1,&o,&e,NULL,0,&b)==1 && a==b);
    e.ack_offset=5;
    assert(d2k_observations_decode(d,0,&o,&e,NULL,0,&b)==1 && a!=b);
    e.ack_in_sent_range=0;
    assert(d2k_observations_decode(d,0,&o,&e,NULL,0,&c)==1 && b!=c);
    uint8_t bytes[]={1,2,3};
    e.payload_len=3;o.kind=D2K_RAW_OBS_RESPONSE_BYTES;
    assert(d2k_observations_decode(d,0,&o,&e,bytes,3,&a)==1);
    bytes[1]=9;
    assert(d2k_observations_decode(d,0,&o,&e,bytes,3,&b)==1 && a!=b);
    assert(d2k_observations_get(d,a)->bytes[1]==2);
    assert(d2k_observations_get(d,a)->length==3);
    assert(d2k_observations_decode(d,0,&o,&e,bytes,2,&b)==-1 && b==0);
    o.kind=D2K_RAW_OBS_LOCAL;
    assert(d2k_observations_decode(d,0,&o,&e,bytes,3,&b)==0 && b==0);
    o.kind=D2K_RAW_OBS_CANCELLED;
    assert(d2k_observations_decode(d,0,&o,&e,bytes,3,&b)==0);
    o.kind=D2K_RAW_OBS_ACCEPTED;
    assert(d2k_observations_decode(d,0,&o,&e,bytes,3,&b)==0);
    memset(&e,0,sizeof e);o.kind=D2K_RAW_OBS_RESPONSE_TIMEOUT;
    assert(d2k_observations_decode(d,0,&o,&e,NULL,0,&a)==1);
    assert(d2k_observations_decode(d,0,&o,&e,NULL,0,&b)==1 && a==b);
    assert(d2k_observations_get(d,a)->kind==D2K_RAW_OBS_RESPONSE_TIMEOUT);
    assert(!d2k_observations_get(d,0) && !d2k_observations_get(d,UINT64_MAX));
    d2k_observations_free(d);puts("observation: exact packet symbols, owned bytes and local-error exclusion PASS");
}
