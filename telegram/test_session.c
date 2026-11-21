#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "tg_session.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef NDEBUG
#error "Session regressions require active assertions (compile with -UNDEBUG)"
#endif

typedef struct {
    uint8_t replies[2][TG_MUX_HEADER_LEN + TG_HELLO_ACK_FIXED_LEN + UINT8_MAX]; size_t reply_len[2]; size_t reply_count; size_t next_reply;
    size_t read_cap[2];
    uint8_t sent[2][256]; size_t sent_len[2]; size_t send_count;
} fake_io;

static int fake_send(void *ctx,const uint8_t *data,size_t len) {
    fake_io *f=ctx; assert(f->send_count<2 && len<=sizeof(f->sent[0]));
    memcpy(f->sent[f->send_count],data,len); f->sent_len[f->send_count++]=len; return 0;
}
static int fake_read(void *ctx,uint8_t *dst,size_t cap,size_t *len) {
    fake_io *f=ctx; if(f->next_reply>=f->reply_count)return -1;
    size_t i=f->next_reply++, n=f->reply_len[i];
    f->read_cap[i]=cap;
    size_t copied=n<cap?n:cap;
    assert(copied<=sizeof(f->replies[i]));
    memcpy(dst,f->replies[i],copied); *len=n; return 0;
}
static void fake_add_frame(fake_io *f,uint8_t type,const uint8_t *payload,size_t len) {
    size_t n=tg_mux_encode(f->replies[f->reply_count],sizeof(f->replies[0]),0,type,payload,len);
    assert(n); f->reply_len[f->reply_count++]=n;
}
static void make_ack(uint8_t *out,size_t *len,uint64_t server_time,const uint8_t nonce[16]) {
    out[0]=2; for(size_t i=0;i<8;i++)out[1+i]=(uint8_t)(server_time>>(56-8*i));
    memcpy(out+9,nonce,16); out[25]=0; out[26]=0;out[27]=0;out[28]=0;out[29]=0;
    out[30]=0;out[31]=0;out[32]=0;out[33]=0; *len=34;
}

static void test_v2_success_clock_and_signature(void) {
    char path[]="/tmp/d2k-tg-session-id"; unlink(path);
    tg_identity id; fake_io f={0}; tg_session_io io={.ctx=&f,.send_binary=fake_send,.read_binary_prefix=fake_read};
    tg_session_state state; uint8_t ack[64],nonce[16],info[]={0,0,0,0,0}; size_t ack_len;
    for(size_t i=0;i<16;i++)nonce[i]=(uint8_t)(0x80+i);
    make_ack(ack,&ack_len,1000,nonce); fake_add_frame(&f,TG_MUX_HELLO_ACK,ack,ack_len);
    fake_add_frame(&f,TG_MUX_INFO,info,sizeof(info));
    assert(tg_identity_load_or_mint(path,&id)==0);
    assert(tg_session_authenticate_v2(&io,&id,"build-test",900,&state)==TG_SESSION_V2_OK);
    fprintf(stderr,"auth receive capacity: ACK=%zu INFO=%zu bytes\n",f.read_cap[0],f.read_cap[1]);
    assert(f.read_cap[0]<=TG_MUX_HEADER_LEN+TG_HELLO_ACK_FIXED_LEN+UINT8_MAX);
    assert(f.read_cap[1]<=TG_MUX_HEADER_LEN+TG_INFO_FIXED_LEN);
    assert(state.clock_offset==100 && state.window==0 && f.send_count==2);
    tg_frame hello,auth; assert(tg_mux_decode(f.sent[0],f.sent_len[0],&hello)==0);
    assert(hello.stream_id==0 && hello.type==TG_MUX_HELLO && hello.payload[0]==2);
    assert(tg_mux_decode(f.sent[1],f.sent_len[1],&auth)==0);
    assert(auth.type==TG_MUX_AUTHID && auth.payload_len==TG_AUTH_V2_LEN);
    uint8_t pub[32]; assert(tg_identity_public_key(&id,pub)==0);
    assert(memcmp(auth.payload+24,nonce,16)==0);
    assert(tg_identity_verify(pub,auth.payload,40,auth.payload+40)==0);
    tg_identity_cleanup(&id); unlink(path);
}

static void test_auth_message_lengths(void) {
    char path[]="/tmp/d2k-tg-session-id"; unlink(path);
    tg_identity id; fake_io f={0};
    tg_session_io io={.ctx=&f,.send_binary=fake_send,.read_binary_prefix=fake_read};
    tg_session_state state;
    uint8_t nonce[16]={0}, ack[TG_HELLO_ACK_FIXED_LEN + UINT8_MAX]={0};
    size_t n;
    make_ack(ack,&n,1000,nonce);
    ack[25]=UINT8_MAX;
    fake_add_frame(&f,TG_MUX_HELLO_ACK,ack,sizeof(ack));
    uint8_t retry[]={1,0,0,0,42};
    fake_add_frame(&f,TG_MUX_INFO,retry,sizeof(retry));
    f.reply_len[1]=TG_WS_MAX_MESSAGE;
    assert(tg_identity_load_or_mint(path,&id)==0);
    assert(tg_session_authenticate_v2(&io,&id,"b",1000,&state)==TG_SESSION_ERROR);
    assert(state.retry_after==TG_MAX_RETRY_AFTER_SEC && f.send_count==2);

    f.next_reply=f.send_count=0;
    f.reply_len[0]++;
    assert(tg_session_authenticate_v2(&io,&id,"b",1000,&state)==TG_SESSION_ERROR);
    assert(f.send_count==1);

    f.next_reply=f.send_count=0;
    f.reply_len[0]--;
    f.reply_len[1]=TG_MUX_HEADER_LEN+TG_INFO_FIXED_LEN-1;
    assert(tg_session_authenticate_v2(&io,&id,"b",1000,&state)==TG_SESSION_ERROR);
    assert(state.retry_after==0);
    tg_identity_cleanup(&id); unlink(path);
}

static void test_protocol_fallback_only(void) {
    char path[]="/tmp/d2k-tg-session-id"; unlink(path);
    tg_identity id; fake_io f={0}; tg_session_io io={.ctx=&f,.send_binary=fake_send,.read_binary_prefix=fake_read};
    tg_session_state state; uint8_t ack[64],nonce[16]={0}; size_t n;
    make_ack(ack,&n,1000,nonce); fake_add_frame(&f,TG_MUX_HELLO_ACK,ack,n);
    uint8_t goodbye[]={TG_INFO_GOODBYE,0,0,0,TG_REASON_PROTOCOL,'n','o'};
    fake_add_frame(&f,TG_MUX_INFO,goodbye,sizeof(goodbye));
    assert(tg_identity_load_or_mint(path,&id)==0);
    assert(tg_session_authenticate_v2(&io,&id,"b",1000,&state)==TG_SESSION_FALLBACK_V1);
    assert(f.send_count==2);
    tg_identity_cleanup(&id); unlink(path);

    memset(&f,0,sizeof(f)); io.ctx=&f; make_ack(ack,&n,1000,nonce); fake_add_frame(&f,TG_MUX_HELLO_ACK,ack,n);
    uint8_t denied[]={TG_INFO_GOODBYE,0,0,0,8}; fake_add_frame(&f,TG_MUX_INFO,denied,sizeof(denied));
    assert(tg_identity_load_or_mint(path,&id)==0);
    assert(tg_session_authenticate_v2(&io,&id,"b",1000,&state)==TG_SESSION_ERROR);
    assert(f.send_count==2);
    tg_identity_cleanup(&id); unlink(path);
}

static void test_v1_auth_vector_and_reconnect_policy(void) {
    char path[]="/tmp/d2k-tg-session-id"; unlink(path);
    tg_identity id; fake_io f={0}; tg_session_io io={.ctx=&f,.send_binary=fake_send,.read_binary_prefix=fake_read};
    assert(tg_identity_load_or_mint(path,&id)==0);
    assert(tg_session_authenticate_v1(&io,&id,1234)==0);
    tg_frame auth; assert(tg_mux_decode(f.sent[0],f.sent_len[0],&auth)==0);
    assert(auth.type==TG_MUX_AUTHID && auth.payload_len==88);
    uint8_t pub[32]; assert(tg_identity_public_key(&id,pub)==0);
    assert(tg_identity_verify(pub,auth.payload,24,auth.payload+24)==0);
    /* x87 retains extended precision until the integer cast; 0.7 * 3000
     * may truncate to 2099, just as the upper bound below can be 12999. */
    uint32_t low_jitter = tg_reconnect_delay_ms(1,0,0,0.0);
    assert(low_jitter >= 2099 && low_jitter <= 2100);
    assert(tg_reconnect_delay_ms(3,0,0,1.0)>=12999 && tg_reconnect_delay_ms(3,0,0,1.0)<=13000);
    uint32_t retry_jitter = tg_reconnect_delay_ms(10,99,0,0.5);
    uint32_t healthy_jitter = tg_reconnect_delay_ms(10,0,1,0.5);
    assert(retry_jitter >= 4999 && retry_jitter <= 5000);
    assert(healthy_jitter >= 999 && healthy_jitter <= 1000);
    assert(!tg_reconnect_needs_reregister(2) && tg_reconnect_needs_reregister(3));
    assert(tg_session_ping_due(0,10000) && !tg_session_ping_due(1,10000));
    assert(tg_session_read_expired(0,30000) && !tg_session_read_expired(1,30000));
    tg_identity_cleanup(&id); unlink(path);
}

int main(void) {
    test_v2_success_clock_and_signature(); test_auth_message_lengths(); test_protocol_fallback_only();
    test_v1_auth_vector_and_reconnect_policy(); puts("session tests: ok"); return 0;
}
