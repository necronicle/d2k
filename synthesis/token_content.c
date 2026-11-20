#include "token_content.h"
#include <string.h>
int d2k_token_content_question(const d2k_trigger *t,uint8_t *out,size_t cap) {
    if(!t || !out || cap<t->len)return -1;
    if(t->len<9 || t->len>sizeof t->payload || t->payload[0]!=22 || t->payload[5]!=1 ||
       (size_t)5+((size_t)t->payload[3]<<8)+t->payload[4]!=t->len ||
       t->sni_off<9 || t->sni_len<1 || (size_t)t->sni_off>=t->len ||
       (size_t)t->sni_len>t->len-(size_t)t->sni_off)return 0;
    size_t off=(size_t)t->sni_off,n=(size_t)t->sni_len;int changed=0;
    for(size_t i=0;i<n;i++) {
        uint8_t c=t->payload[off+i];
        if(c!='.' && c!='-' && !((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9')))return 0;
        if(c!='.' && c!='-' && c!='a')changed=1;
    }
    if(!changed)return 0;
    memcpy(out,t->payload,t->len);
    for(size_t i=0;i<n;i++)if(out[off+i]!='.' && out[off+i]!='-')out[off+i]='a';
    return 1;
}
