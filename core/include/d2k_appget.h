/* Прикладная проверка на сессии TLS (D2K_SPEC.md §9.2): GET и полный ответ.
 *
 * Протокол — тот, что сервер выбрал по ALPN формы клиента: h2 или http/1.1
 * (без ALPN — http/1.1). Успех — статус, заголовки и тело целиком: у HTTP/1.1
 * по Content-Length, chunked или закрытию; у HTTP/2 по END_STREAM потока.
 * Тело считается, не хранится (у HTTP/1.1 — в пределах буфера разбора). */
#ifndef D2K_APPGET_H
#define D2K_APPGET_H

#include <stdint.h>
#include "d2k_tls13.h"

typedef enum {
    D2K_APP_COMPLETE = 1,   /* полный ответ — прикладной успех по §9.2 */
    D2K_APP_CUT,            /* поток оборвался до конца ответа */
    D2K_APP_TIMEOUT,        /* ответ не закончился к сроку */
    D2K_APP_MALFORMED,      /* ответ нарушает грамматику HTTP */
    D2K_APP_LOCAL           /* наш предел или ошибка записи: не ответ сети */
} d2k_app_state;

typedef struct {
    d2k_app_state state;
    int http2;              /* говорили по HTTP/2 */
    int status;             /* :status / статус ответа; 0 — не получен */
    uint64_t body_bytes;    /* полученные байты тела */
    char location[256];     /* Location (HTTP/1.1); для сверки подмены (§9.2) */
    char reason[160];
} d2k_app_result;

/* GET path у host на установленной сессии. deadline_ms — на весь ответ. */
void d2k_app_get(d2k_tls *t, const char *host, const char *path, int deadline_ms,
                 d2k_app_result *r);

#endif
