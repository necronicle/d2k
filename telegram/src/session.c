#include "tg_session.h"

#include <stdlib.h>
#include <string.h>

static void put_u64(uint8_t *p, uint64_t v) {
    for(size_t i=0;i<8;i++)p[i]=(uint8_t)(v>>(56-8*i));
}

static int decode_id(const char hex[33],uint8_t id[16]) {
    if(!hex || strlen(hex)!=32)return -1;
    for(size_t i=0;i<16;i++) {
        int hi,lo; char a=hex[i*2],b=hex[i*2+1];
        hi=a>='0'&&a<='9'?a-'0':a>='a'&&a<='f'?a-'a'+10:-1;
        lo=b>='0'&&b<='9'?b-'0':b>='a'&&b<='f'?b-'a'+10:-1;
        if(hi<0||lo<0)return -1;
        id[i]=(uint8_t)((hi<<4)|lo);
    }
    return 0;
}

static int send_mux(const tg_session_io *io,uint8_t type,const uint8_t *payload,size_t len) {
    if(!io||!io->send_binary)return -1;
    size_t cap=len+TG_MUX_HEADER_LEN; uint8_t *frame=malloc(cap?cap:1);
    if(!frame)return -1;
    size_t n=tg_mux_encode(frame,cap,0,type,payload,len);
    int rc=n?io->send_binary(io->ctx,frame,n):-1;
    free(frame); return rc;
}

int tg_session_authenticate_v2(const tg_session_io *io,const tg_identity *id,
                               const char *build,int64_t local_unix,
                               tg_session_state *state) {
    uint8_t hello[261],auth_payload[TG_AUTH_V2_LEN],signed_data[40];
    uint8_t signature[64],id_bytes[16]; size_t hello_len=0;
    tg_frame frame;
    tg_hello_ack ack;
    uint8_t ack_message[TG_MUX_HEADER_LEN + TG_HELLO_ACK_FIXED_LEN + UINT8_MAX];
    uint8_t info_prefix[TG_MUX_HEADER_LEN + TG_INFO_FIXED_LEN];
    size_t message_len;
    if(!io||!io->send_binary||!io->read_binary_prefix||!id||!id->private_key||!state||
       tg_hello_encode(hello,sizeof(hello),build,0,&hello_len)!=0 ||
       decode_id(id->install_id_hex,id_bytes)!=0)return TG_SESSION_ERROR;
    memset(state,0,sizeof(*state));
    if(send_mux(io,TG_MUX_HELLO,hello,hello_len)!=0)return TG_SESSION_ERROR;
    if (io->read_binary_prefix(io->ctx,ack_message,sizeof(ack_message),&message_len)!=0 ||
        message_len>sizeof(ack_message) || tg_mux_decode(ack_message,message_len,&frame)!=0 ||
        frame.stream_id!=0 || frame.type!=TG_MUX_HELLO_ACK ||
        tg_hello_ack_decode(frame.payload,frame.payload_len,&ack)!=0)
        return TG_SESSION_ERROR;
    if(ack.version!=2)return TG_SESSION_FALLBACK_V1;
    state->clock_offset=ack.server_unix-local_unix;
    state->window=ack.window;
    int64_t corrected=local_unix+state->clock_offset;
    memcpy(signed_data,id_bytes,16); put_u64(signed_data+16,(uint64_t)corrected);
    memcpy(signed_data+24,ack.nonce,16);
    if(tg_identity_sign(id,signed_data,sizeof(signed_data),signature)!=0 ||
       tg_auth_v2_encode(auth_payload,id_bytes,(uint64_t)corrected,ack.nonce,signature)!=0 ||
       send_mux(io,TG_MUX_AUTHID,auth_payload,sizeof(auth_payload))!=0) return TG_SESSION_ERROR;
    /* INFO can carry arbitrary trailing text. Authentication only consumes kind and arg. */
    if (io->read_binary_prefix(io->ctx,info_prefix,sizeof(info_prefix),&message_len)!=0 ||
        message_len<sizeof(info_prefix) || message_len>TG_WS_MAX_MESSAGE ||
        tg_mux_decode(info_prefix,sizeof(info_prefix),&frame)!=0 ||
        frame.stream_id!=0 || frame.type!=TG_MUX_INFO)
        return TG_SESSION_ERROR;
    uint8_t kind; uint32_t arg; const uint8_t *text; size_t text_len;
    if(tg_info_decode(frame.payload,frame.payload_len,&kind,&arg,&text,&text_len)!=0)
        return TG_SESSION_ERROR;
    if(kind==TG_INFO_AUTH_OK)return TG_SESSION_V2_OK;
    if(kind==TG_INFO_GOODBYE && arg==TG_REASON_PROTOCOL)return TG_SESSION_FALLBACK_V1;
    if(kind==1)state->retry_after=arg>TG_MAX_RETRY_AFTER_SEC?TG_MAX_RETRY_AFTER_SEC:arg;
    return TG_SESSION_ERROR;
}

int tg_session_authenticate_v1(const tg_session_io *io,const tg_identity *id,
                               int64_t unix_time) {
    uint8_t payload[88],id_bytes[16],signature[64];
    if(!io||!id||!id->private_key||decode_id(id->install_id_hex,id_bytes)!=0)return -1;
    memcpy(payload,id_bytes,16); put_u64(payload+16,(uint64_t)unix_time);
    if(tg_identity_sign(id,payload,24,signature)!=0)return -1;
    memcpy(payload+24,signature,64);
    return send_mux(io,TG_MUX_AUTHID,payload,sizeof(payload));
}

uint32_t tg_reconnect_delay_ms(unsigned failures,uint32_t retry_after,
                               int healthy,double random_unit) {
    uint32_t base;
    if(random_unit<0.0)random_unit=0.0;
    if(random_unit>1.0)random_unit=1.0;
    if(retry_after) {
        if(retry_after>TG_MAX_RETRY_AFTER_SEC)retry_after=TG_MAX_RETRY_AFTER_SEC;
        base=retry_after*1000u;
    } else if(healthy) base=1000u;
    else if(failures>=10)base=120000u;
    else if(failures>=5)base=30000u;
    else if(failures>=3)base=10000u;
    else base=3000u;
    return (uint32_t)((double)base*(0.7+random_unit*0.6));
}

int tg_reconnect_needs_reregister(unsigned fast_deaths) { return fast_deaths>=3; }
int tg_session_ping_due(uint64_t last,uint64_t now) { return now>=last && now-last>=TG_WS_PING_INTERVAL_MS; }
int tg_session_read_expired(uint64_t last,uint64_t now) { return now>=last && now-last>=TG_WS_READ_TIMEOUT_MS; }
