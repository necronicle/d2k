/* Прикладная проверка (D2K_SPEC.md §9): контракты успеха по протоколам.
 *
 * Здесь только суждение по уже полученным байтам и событиям; сеть ведёт
 * исполнитель опыта. Прикладной успех — только уровень APPLICATION.
 * «Пришёл ServerHello», «план установлен», рост входящих байтов успехом
 * не являются. */
#ifndef D2KM_CHECK_H
#define D2KM_CHECK_H

#include <stddef.h>
#include <stdint.h>

/* §9.1, уровни результата хранятся раздельно. */
typedef enum {
    D2KM_LEVEL_NONE = 0,
    D2KM_LEVEL_TRANSPORT,   /* соединение установлено / датаграммы ходят */
    D2KM_LEVEL_HANDSHAKE,   /* TLS или QUIC завершены */
    D2KM_LEVEL_APPLICATION  /* результат по контракту протокола */
} d2km_app_level;

typedef enum {
    D2KM_HTTP_COMPLETE = 1,   /* статус, заголовки и тело целиком */
    D2KM_HTTP_INCOMPLETE,     /* данных пока не хватает */
    D2KM_HTTP_CUT,            /* поток закрыт до конца тела */
    D2KM_HTTP_MALFORMED       /* не HTTP/1.x или нарушение грамматики */
} d2km_http_state;

typedef struct {
    int status;
    int chunked;
    int has_length;
    uint64_t content_length;
    uint64_t body_bytes;          /* полезные байты тела (без разметки chunked) */
    size_t header_bytes;          /* длина статусной строки и заголовков с CRLFCRLF */
    size_t message_bytes;         /* длина всего сообщения, если оно закончено */
    const uint8_t *location;      /* значение Location или NULL */
    size_t location_length;
} d2km_http_response;

/* Разбирает ответ HTTP/1.x на запрос GET. closed — сервер закрыл поток
 * (FIN): только так заканчивается тело без длины и без chunked. Тело
 * отсутствует у 1xx, 204, 304. Ответы 1xx пропускаются до окончательного. */
d2km_http_state d2km_http1_response(const uint8_t *buf, size_t n, int closed,
                                    d2km_http_response *out);

/* §9.2, подмена: статус, Location или хост Location отличаются от ответа
 * на тот же запрос через опорную точку. 1 — подмена, 0 — нет. */
int d2km_http_spoofed(const d2km_http_response *direct,
                      const d2km_http_response *reference);

/* §9.2, класс «объёмный обрыв»: полный ответ объёмом больше порога. */
int d2km_volume_success(const d2km_http_response *, d2km_http_state,
                        uint64_t cut_threshold);

/* §9.5: правильный DNS-ответ на запрос — тот же ID, QR=1, opcode 0,
 * совпадающий вопрос (имя без учёта регистра, тип, класс), RCODE NOERROR
 * или NXDOMAIN. Сообщения — в формате DNS (без длины TCP). */
int d2km_dns_reply_valid(const uint8_t *query, size_t qn,
                         const uint8_t *reply, size_t rn);

/* §9.5, итог долгой сессии DoH или DoT в одном соединении. */
typedef enum {
    D2KM_DNS_SESSION_SUCCESS = 1,  /* >=20 правильных ответов за >=30 с */
    D2KM_DNS_SESSION_CUT,          /* запрос без ответа при открытом соединении */
    D2KM_DNS_SESSION_PARTIAL       /* серия короче контракта: наблюдённый факт, не успех */
} d2km_dns_session_verdict;

#define D2KM_DNS_SESSION_REPLIES 20
#define D2KM_DNS_SESSION_MS 30000u

typedef struct {
    uint32_t valid_replies;
    uint64_t first_reply_ms, last_reply_ms;
    int unanswered_while_open;   /* запрос ушёл, ответа нет до таймаута, соединение открыто */
    int closed_by_protocol;      /* GOAWAY / штатное закрытие: не обрыв */
} d2km_dns_session;

d2km_dns_session_verdict d2km_dns_session_judge(const d2km_dns_session *);

/* §9.7: успешный ответ на свой Binding Request — Binding Success
 * (0x0101), magic cookie, тот же transaction id, длина сходится, есть
 * XOR-MAPPED-ADDRESS или MAPPED-ADDRESS. */
int d2km_stun_binding_success(const uint8_t *request, size_t qn,
                              const uint8_t *reply, size_t rn);

/* §9.3: QUIC и HTTP/3 — рукопожатие завершено И ответ полный. Повторы
 * сервера и любые входящие байты без этого успехом не являются. */
d2km_app_level d2km_h3_level(int quic_handshake_done, int response_complete);

#endif
