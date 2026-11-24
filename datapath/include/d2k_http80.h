/* d2k_http80.h — вставка провайдера в открытый HTTP (порт 80), задача 51.
 *
 * Поле 03.10.2026 (ER-Telecom, захват на ppp0): клиент шлёт `GET /`, и через
 * 0,7 мс при RTT сервера ~98 мс приходит `HTTP/1.1 302 Moved Temporarily`,
 * `Location: http://lawfilter.ertelecom.ru…` с FIN — дважды; настоящий сервер
 * не отвечает. Ответ, пришедший раньше, чем сервер физически мог ответить,
 * сервером не послан.
 *
 * Модуль видит начальное окно и весь последующий HTTP-поток в обе стороны.
 * Он узнаёт вставку по трём признакам сразу:
 *   1. ответ — 30x с Location на хост блокировки (метки как в
 *      d2k_httpup_portal_location), и этот хост не равен Host запроса;
 *   2. ответ стоит на ожидаемом клиентом seq (ACK текущего запроса) и
 *      подтверждает ровно конец запроса (ack);
 *   3. ответ пришёл раньше половины RTT, замеренного этим же потоком
 *      (SYN → SYN/ACK). Половина — запас на разброс: настоящий ответ не
 *      может прийти быстрее, чем запрос дошёл до сервера и вернулся.
 *
 * Что делать с узнанной вставкой, решает знание об HTTPS имени (таблица,
 * которую наполняет контроллер). HTTPS подтверждён — вместо вставки клиент
 * получает 307 на https://тот же host+path с FIN в том же TCP-потоке (точные
 * seq/ack, суммы пересчитаны), серверу уходит RST, остальные пакеты сервера
 * по потоку снимаются. Не подтверждён или неизвестен — вставка проходит как
 * есть: клиента не задерживаем и тупика не создаём.
 *
 * Модуль переносим: ни сокетов, ни часов, время приходит аргументом.
 */
#ifndef D2K_HTTP80_H
#define D2K_HTTP80_H

#include <stddef.h>
#include <stdint.h>
#include "d2k_plans.h"

#define D2K_HTTP80_PASS    0   /* пакет идёт как шёл */
#define D2K_HTTP80_DROP    1   /* снять: копия вставки, её FIN, поздний сервер */
#define D2K_HTTP80_REPLACE 2   /* выпустить вместо пакета out[0..len) */

/* Сколько потоков порта 80 помним одновременно и сколько имён с HTTPS. */
#define D2K_HTTP80_FLOWS 128
#define D2K_HTTP80_NAMES 256
/* Путь запроса длиннее не храним: такой поток не переводим на https. */
#define D2K_HTTP80_TARGET_MAX 1024
/* Исход «обрыв»: ответ с заявленной длиной встал раньше конца. */
#define D2K_HTTP80_CUT 4
/* Клиентский запрос завершён, но до первого байта HTTP пришёл RST. */
#define D2K_HTTP80_RESET_BEFORE_RESPONSE 5
/* Запрос повторён после RTT, а ответа по потоку ещё не было. */
#define D2K_HTTP80_RETRY_BEFORE_RESPONSE 6
/* Тишина, после которой недокачанный ответ считается оборванным: не меньше
   этого и не меньше трёх RTT потока. */
#define D2K_HTTP80_CUT_MIN_NS (2ull * 1000000000ull)
/* Поток без движения дольше этого забывается. */
#define D2K_HTTP80_IDLE_NS (60ull * 1000000000ull)

typedef struct d2k_http80 d2k_http80;

typedef struct {
    int action;            /* D2K_HTTP80_* */
    int response;          /* 1: complete framing, 2: unknown, 3: portal (no timing claim),
                              4: fixed-length body cut, 5: RST before HTTP response,
                              6: client retry before HTTP response */
    unsigned status;       /* final HTTP status, if observed */
    uint64_t body_bytes;    /* observed body excluding chunk framing */
    uint64_t request_no;    /* request ordinal within this observed connection */
    int injection;         /* ЭТОТ пакет — первая узнанная вставка запроса */
    int answered;          /* 307 ушёл клиенту (ставит d2k_http80_swap) */
    size_t flow;           /* REPLACE: чей поток (для d2k_http80_swap) */
    size_t len;            /* REPLACE: длина пакета в out */
    size_t rst_len;        /* REPLACE: длина RST к серверу в rst (0 — не собран) */
    uint8_t family;        /* 4 или 6 */
    uint8_t client[16], server[16];
    uint16_t client_port, server_port;   /* хостовый порядок */
    uint64_t rtt_ns;       /* SYN → SYN/ACK этого потока */
    uint64_t reply_ns;     /* запрос → ответ */
    d2k_binding_context binding;
    uint64_t execution_id; /* completed live request execution, else zero */
    uint64_t request_ms;   /* monotonic request start; identity is the binding */
    uint8_t plan_id[16], trial_id[16];
    char request_path[D2K_HTTP80_TARGET_MAX]; /* safe GET path, empty = reproduction gap */
    char host[256];        /* Host запроса (без :80) */
    char portal[256];      /* хост из Location вставки */
} d2k_http80_res;

typedef struct {
    uint64_t requests;     /* разобранных запросов GET/HEAD */
    uint64_t injections;   /* узнанных вставок, без повторного счёта ретрансляции */
    uint64_t answered;     /* из них заменено на 307 */
    uint64_t swap_failed;  /* вердикт с заменой не принят — ушла вставка */
    uint64_t dropped;      /* снятых пакетов сервера после замены */
    uint64_t evicted;      /* потоков, вытесненных из полной таблицы */
    /* Нагрузка клиента к :80, по которой вставку здесь не узнать (поле
       04.10.2026: портал в браузере при «запросов +0» не отличался от
       «запроса не было»). Пакеты, не запросы. */
    uint64_t untracked;    /* поток без SYN в таблице: открыт до запуска, вытеснен, простоял */
    uint64_t unparsed;     /* не распознаны request line и полный Host в начальном сегменте */
    uint64_t later;        /* после первой нагрузки потока: keep-alive, тело, хвост запроса */
} d2k_http80_stats;

d2k_http80 *d2k_http80_new(void);
void d2k_http80_free(d2k_http80 *h);

/* Имя, у которого HTTPS подтверждён, до expires_ns (монотонные часы).
 * expires_ns == 0 убирает имя. Сравнение без учёта регистра, точка в конце
 * не значима. 0 — принято, -1 — имя негодно. Полная таблица вытесняет
 * запись с самым ранним сроком. */
int d2k_http80_set_https(d2k_http80 *h, const char *name, size_t len, uint64_t expires_ns);
int d2k_http80_https(const d2k_http80 *h, const char *host, uint64_t now_ns);

/* Один пакет из очереди (IPv4/IPv6, целиком, с заголовком IP). Решение и
 * подробности — в r. out/rst — буферы для пакета-замены и RST к серверу. */
/* kstamp_ns — метка приёма пакета ядром (NFQA_TIMESTAMP), 0 — нет. Если она
 * есть у SYN, SYN/ACK, запроса и ответа, RTT и задержка ответа считаются по
 * ней: задержка очереди и самого d2kd в замер не входит (ревью M1). Иначе —
 * по now_ns, как раньше. */
void d2k_http80_packet(d2k_http80 *h, const uint8_t *pkt, size_t len, uint64_t now_ns,
                       uint64_t kstamp_ns,
                       uint8_t *out, size_t out_cap, uint8_t *rst, size_t rst_cap,
                       d2k_http80_res *r);

/* Call only after all sends and the original verdict completed. The tuple
 * and request sequence must still match the observed request. */
void d2k_http80_executed(d2k_http80 *h, const uint8_t *pkt, size_t len,
    uint64_t now_ns, uint64_t execution_id,
    const uint8_t plan_id[16], const uint8_t trial_id[16], const d2k_binding_context *);

/* ОБРЫВ ОТВЕТА БЕЗ ПОРТАЛА (поле 15.10.2026, media5.cdnbase.com: 33120 из
 * 106050 байт, ни портала, ни RST). Ответ с заявленной длиной
 * (Content-Length), у которого ни байты сервера, ни ACK клиента не двигаются
 * дольше max(3·RTT, D2K_HTTP80_CUT_MIN_NS), отдаётся в cb с response=4 —
 * один раз, без плана тоже. ACK клиента — второй свидетель: под PPE Keenetic
 * тело ответа после ~30 пакетов идёт мимо очереди. Закрытие клиентом до
 * конца тела сообщается сразу, через d2k_http80_packet. Возвращает число
 * сообщённых обрывов. */
size_t d2k_http80_sweep(d2k_http80 *h, uint64_t now_ns,
                        void (*cb)(void *ctx, const d2k_http80_res *r), void *ctx);
/* Finalize a response observation after this original packet's NFQUEUE
 * verdict. Any failed/non-ACCEPT delivery invalidates the response witness. */
void d2k_http80_delivered(d2k_http80 *,const uint8_t *,size_t,int accepted,d2k_http80_res *);

/* Исполнение REPLACE (ревью I3) — обязательный второй шаг. Пока его не было,
 * поток ничьим не считается: ни RST, ни снятия копий. Порядок:
 *   verdict_payload(out) — ядро выпускает 307 вместо вставки;
 *   удалось → поток «отвечен», send_rst(rst), дальше сервер снимается; 1;
 *   не удалось → verdict_accept() выпускает вставку как есть, поток остаётся
 *   «вставка пропущена» (копия пройдёт, RST не идёт); 0.
 * Отказ ядра ВНУТРИ вердикта (nfqnl_mangle → NF_DROP, только при нехватке
 * памяти) отсюда не виден: ядро о нём не сообщает. */
typedef struct {
    int (*verdict_payload)(void *ctx, const uint8_t *pkt, size_t len);
    int (*verdict_accept)(void *ctx);
    int (*send_rst)(void *ctx, const uint8_t *pkt, size_t len);
    void *ctx;
} d2k_http80_io;
int d2k_http80_swap(d2k_http80 *h, d2k_http80_res *r, const uint8_t *out, const uint8_t *rst,
                    const d2k_http80_io *io);

d2k_http80_stats d2k_http80_get_stats(const d2k_http80 *h);

/* ЗАПРОС HTTP КАК ВХОД ПЛАНА (задача 51, шаг 4). 1 — нагрузка начинается
 * запросом (метод — заглавные буквы: GET, HEAD, POST…; keep-alive, поле
 * 04.10.2026) в origin-form с версией HTTP/1.x, и в ней есть ровно
 * одна строка «Host:» целиком (до CRLF) с именем по синтаксису DNS и,
 * быть может, портом :80. host_off и host_len — где в нагрузке имя (без
 * порта и точки в конце): от него считаются разрезы плана, им же ищется
 * план. Остальной заголовок может быть в следующих сегментах. 0 — не наш
 * вход: пакет идёт как есть. */
int d2k_http_hello(const uint8_t *p, size_t n, size_t *host_off, size_t *host_len);

/* То же с границей запроса — для следующих запросов соединения keep-alive.
 * head_len — длина заголовка с пустой строкой, 0 — заголовок не кончился в
 * этом сегменте. end_known — конец запроса (заголовок + тело по одному
 * Content-Length) известен: следующий запрос начнётся через end байт от
 * начала этого. Нет при chunked/любом Transfer-Encoding, Upgrade, двух или
 * негодном Content-Length, незаконченном заголовке. */
typedef struct {
    size_t host_off, host_len;
    size_t head_len;
    int end_known;
    uint64_t end;
} d2k_http_req;
int d2k_http_request(const uint8_t *p, size_t n, d2k_http_req *r);

#endif /* D2K_HTTP80_H */
