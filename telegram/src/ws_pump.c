#define _POSIX_C_SOURCE 200809L
#include "tg_ws.h"

#include <fcntl.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TG_WS_PUMP_TX_LIMIT (4u*1024u*1024u)
struct tg_ws_tx_frame { struct tg_ws_tx_frame *next; uint8_t *bytes; size_t len,offset,allocated; };

static void release_frames(tg_ws_pump *p,tg_ws_tx_frame *frame) {
    while(frame){tg_ws_tx_frame *next=frame->next;p->tx_memory_bytes-=frame->allocated+sizeof(*frame);
        OPENSSL_clear_free(frame->bytes,frame->allocated);free(frame);frame=next;}
}

int tg_ws_pump_init(tg_ws_pump *p,SSL *ssl) {
    if(!p||!ssl)return -1;
    memset(p,0,sizeof(*p));p->ssl=ssl;p->fd=SSL_get_fd(ssl);
    if(p->fd<0)return -1;
    p->rx_cap=TG_WS_RX_BASE;p->rx=malloc(p->rx_cap);if(!p->rx)return -1;
    int flags=fcntl(p->fd,F_GETFL,0);
    if(flags<0||fcntl(p->fd,F_SETFL,flags|O_NONBLOCK)<0){free(p->rx);memset(p,0,sizeof(*p));return -1;}
    return 0;
}

void tg_ws_pump_destroy(tg_ws_pump *p) {
    if(!p) { return; }
    release_frames(p,p->tx_head);free(p->rx);memset(p,0,sizeof(*p));p->fd=-1;
}

static int queue_opcode(tg_ws_pump *p,uint8_t opcode,const uint8_t *data,size_t len) {
    if(!p||p->failed||p->closed||(!data&&len)||len>TG_WS_MAX_MESSAGE)return -1;
    size_t alloc=len+14,written=0;
    if(p->tx_memory_bytes>TG_WS_PUMP_TX_LIMIT||
       alloc+sizeof(tg_ws_tx_frame)>TG_WS_PUMP_TX_LIMIT-p->tx_memory_bytes)return -1;
    tg_ws_tx_frame *f=calloc(1,sizeof(*f));if(!f)return -1;
    f->bytes=OPENSSL_malloc(alloc);if(!f->bytes){free(f);return -1;}
    if(tg_ws_encode_client_frame(f->bytes,alloc,opcode,data,len,&written)!=0){OPENSSL_clear_free(f->bytes,alloc);free(f);return -1;}
    f->len=written;f->allocated=alloc;
    if(p->tx_tail) { p->tx_tail->next=f; }
    else { p->tx_head=f; }
    p->tx_tail=f;p->tx_bytes+=written;
    p->tx_memory_bytes+=alloc+sizeof(*f);
    return 0;
}

int tg_ws_pump_queue_binary(tg_ws_pump *p,const uint8_t *data,size_t len){return queue_opcode(p,TG_WS_BINARY,data,len);}
int tg_ws_pump_queue_ping(tg_ws_pump *p,const uint8_t *data,size_t len){return queue_opcode(p,TG_WS_PING,data,len);}
int tg_ws_pump_fd(const tg_ws_pump *p){return p?p->fd:-1;}
short tg_ws_pump_events(const tg_ws_pump *p){
    if(!p||p->failed||p->closed)return 0;
    short events=POLLIN;
    if(p->tx_head||p->read_wants_write)events|=POLLOUT;
    return events;
}

/* Returns 0 for an incomplete frame, 1 for a complete one and -1 for invalid. */
static int complete_frame(const uint8_t *b,size_t len,size_t *total) {
    if(len<2)return 0;
    if((b[0]&0x70)||(b[0]&0x80)==0||(b[1]&0x80))return -1;
    uint8_t op=b[0]&15;
    if(op!=TG_WS_BINARY&&op!=TG_WS_CLOSE&&op!=TG_WS_PING&&op!=TG_WS_PONG)return -1;
    uint64_t n;size_t header;
    if((b[1]&127)<126){n=b[1]&127;header=2;}
    else if((b[1]&127)==126){if(len<4)return 0;n=((uint64_t)b[2]<<8)|b[3];if(n<126)return -1;header=4;}
    else{if(len<10)return 0;if(b[2]&0x80)return -1;n=0;for(size_t i=0;i<8;i++)n=(n<<8)|b[2+i];if(n<=UINT16_MAX)return -1;header=10;}
    if(n>TG_WS_MAX_MESSAGE||(op>=8&&(n>125||(b[0]&0x80)==0))||n>SIZE_MAX-header)return -1;
    *total=header+(size_t)n;return len>=*total?1:0;
}

static int dispatch_frames(tg_ws_pump *p,tg_ws_message_cb callback,void *ctx) {
    while(p->rx_len){size_t total=0;int ready=complete_frame(p->rx,p->rx_len,&total);
        if(ready<0) { return -1; }
        if(ready==0) { return 0; }
        uint8_t op;const uint8_t *data;size_t len,used;
        if(tg_ws_decode_server_frame(p->rx,total,TG_WS_MAX_MESSAGE,&op,&data,&len,&used)!=0||used!=total)return -1;
        if(op==TG_WS_PING){if(queue_opcode(p,TG_WS_PONG,data,len)!=0)return -1;}
        else if(op==TG_WS_CLOSE){memmove(p->rx,p->rx+total,p->rx_len-total);p->rx_len-=total;p->closed=1;return 0;}
        else if(op==TG_WS_BINARY&&callback&&callback(ctx,data,len)!=0)return -1;
        memmove(p->rx,p->rx+total,p->rx_len-total);p->rx_len-=total;
    }
    return 0;
}

/* БУФЕР ПРИЁМА ПО ПОТРЕБНОСТИ. Раньше он сразу занимал предел сообщения
   (2 МиБ) на всё время жизни соединения: после первого большого кадра эти
   страницы оставались в памяти процесса навсегда, на каждом соединении.
   Теперь буфер растёт вдвое, пока не вместит кадр (не больше предела), и
   возвращается к исходному размеру, как только разобранных данных в нём нет. */
static int rx_grow(tg_ws_pump *p) {
    size_t limit=(size_t)TG_WS_MAX_MESSAGE+10;
    if(p->rx_cap>=limit)return -1;
    size_t cap=p->rx_cap*2<limit?p->rx_cap*2:limit;
    uint8_t *rx=realloc(p->rx,cap);if(!rx)return -1;
    p->rx=rx;p->rx_cap=cap;return 0;
}

static void rx_shrink(tg_ws_pump *p) {
    if(p->rx_len||p->rx_cap<=TG_WS_RX_BASE)return;
    uint8_t *rx=malloc(TG_WS_RX_BASE);if(!rx)return; /* нет памяти — оставить как есть */
    free(p->rx);p->rx=rx;p->rx_cap=TG_WS_RX_BASE;
}

static int flush_tx(tg_ws_pump *p) {
    p->write_wants_read=0;
    while(p->tx_head){tg_ws_tx_frame *f=p->tx_head;size_t n=0;
        int rc=SSL_write_ex(p->ssl,f->bytes+f->offset,f->len-f->offset,&n);
        if(rc!=1){int error=SSL_get_error(p->ssl,rc);
            if(error==SSL_ERROR_WANT_READ){p->write_wants_read=1;return 0;}
            if(error==SSL_ERROR_WANT_WRITE)return 0;
            p->failed=1;return -1;
        }
        if(!n){p->failed=1;return -1;}f->offset+=n;p->tx_bytes-=n;
        if(f->offset==f->len){p->tx_head=f->next;if(!p->tx_head)p->tx_tail=NULL;f->next=NULL;release_frames(p,f);}
    }
    return 0;
}

int tg_ws_pump_process(tg_ws_pump *p,short revents,tg_ws_message_cb callback,void *ctx) {
    if(!p||p->failed)return -1;
    if(revents&(POLLERR|POLLNVAL)){p->failed=1;return -1;}
    if((revents&POLLOUT)||p->tx_head||p->write_wants_read)if(flush_tx(p)!=0)return -1;
    if((revents&POLLIN)||p->read_wants_write||SSL_pending(p->ssl)>0){
        p->read_wants_write=0;
        for(;;){
            if(p->rx_len==p->rx_cap&&rx_grow(p)!=0){p->failed=1;return -1;}
            size_t n=0;int rc=SSL_read_ex(p->ssl,p->rx+p->rx_len,p->rx_cap-p->rx_len,&n);
            if(rc!=1){int error=SSL_get_error(p->ssl,rc);
                if(error==SSL_ERROR_WANT_READ)break;
                if(error==SSL_ERROR_WANT_WRITE){p->read_wants_write=1;break;}
                if(error==SSL_ERROR_ZERO_RETURN){p->closed=1;return 0;}
                p->failed=1;return -1;
            }
            if(!n){p->failed=1;return -1;}p->rx_len+=n;
            if(dispatch_frames(p,callback,ctx)!=0){p->failed=1;return -1;}
            rx_shrink(p);
            if(p->closed)return 0;
        }
    }
    if(revents&POLLHUP)p->closed=1;
    return p->failed?-1:0;
}
