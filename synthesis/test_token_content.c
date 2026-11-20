#include "token_content.h"
#include <assert.h>
#include <string.h>
int main(void) {
    d2k_trigger t={.len=80,.sni_off=61,.sni_len=11};
    t.payload[0]=22;t.payload[3]=0;t.payload[4]=75;t.payload[5]=1;
    memcpy(t.payload+61,"dns.example",11);uint8_t out[80];
    assert(d2k_token_content_question(&t,out,sizeof out)==1);
    assert(!memcmp(out+61,"aaa.aaaaaaa",11));
    assert(!memcmp(out,t.payload,61) && !memcmp(out+72,t.payload+72,8));
    assert(!memcmp(t.payload+61,"dns.example",11));
    memcpy(t.payload,out,80);assert(d2k_token_content_question(&t,out,sizeof out)==0);
    t.payload[61]='x';t.payload[4]=74;assert(d2k_token_content_question(&t,out,sizeof out)==0);
    t.payload[4]=75;t.sni_len=21;assert(d2k_token_content_question(&t,out,sizeof out)==0);
    t.sni_len=11;t.payload[61]=0;assert(d2k_token_content_question(&t,out,sizeof out)==0);
    assert(d2k_token_content_question(&t,out,79)==-1);
    return 0;
}
