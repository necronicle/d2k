#ifndef D2K_TG_WS_H
#define D2K_TG_WS_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <poll.h>

#define TG_WS_MAX_MESSAGE (2u * 1024u * 1024u)
/* Исходный буфер приёма. Кадры MTProto обычно укладываются в него; буфер
   растёт только под больший кадр (до TG_WS_MAX_MESSAGE) и сжимается обратно,
   когда разобранных данных в нём не осталось. */
#define TG_WS_RX_BASE (16u * 1024u)
#define TG_WS_BINARY 0x2u
#define TG_WS_CLOSE 0x8u
#define TG_WS_PING 0x9u
#define TG_WS_PONG 0xau

int tg_ws_encode_client_frame(uint8_t *dst, size_t cap, uint8_t opcode,
                              const uint8_t *payload, size_t payload_len,
                              size_t *written);
int tg_ws_decode_server_frame(const uint8_t *src, size_t len, size_t max_payload,
                              uint8_t *opcode, const uint8_t **payload,
                              size_t *payload_len, size_t *consumed);
int tg_ws_upgrade(SSL *ssl, const char *host_header, const char *path);
int tg_ws_write_binary(SSL *ssl, const uint8_t *payload, size_t payload_len);
/* Returns 0 for one binary message, -2 for a clean peer close, -1 on protocol/I/O error. */
int tg_ws_read_binary(SSL *ssl, uint8_t *dst, size_t cap, size_t *payload_len);

typedef struct tg_ws_tx_frame tg_ws_tx_frame;
typedef struct {
    /* tx_bytes is remaining wire data; tx_memory_bytes retains the full
     * buffer and node charges until free, excluding allocator metadata. */
    SSL *ssl; int fd; uint8_t *rx; size_t rx_len,rx_cap,tx_bytes,tx_memory_bytes;
    tg_ws_tx_frame *tx_head,*tx_tail; int failed,closed,read_wants_write,write_wants_read;
} tg_ws_pump;
typedef int (*tg_ws_message_cb)(void *ctx,const uint8_t *payload,size_t payload_len);
int tg_ws_pump_init(tg_ws_pump *pump,SSL *ssl);
void tg_ws_pump_destroy(tg_ws_pump *pump);
int tg_ws_pump_queue_binary(tg_ws_pump *pump,const uint8_t *payload,size_t payload_len);
int tg_ws_pump_queue_ping(tg_ws_pump *pump,const uint8_t *payload,size_t payload_len);
int tg_ws_pump_fd(const tg_ws_pump *pump);
short tg_ws_pump_events(const tg_ws_pump *pump);
int tg_ws_pump_process(tg_ws_pump *pump,short revents,tg_ws_message_cb callback,void *ctx);

#endif
