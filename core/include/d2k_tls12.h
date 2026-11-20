/* d2k_tls12.h — минимальный клиент TLS 1.2 для ЗОНДА ПОДТВЕРЖДЕНИЯ.
 *
 * ЗАЧЕМ ОН ЕСТЬ. Замер идёт приветствием КЛИЕНТА, а подтверждал найденное до
 * сих пор только зонд TLS 1.3. Когда клиент старый — телевизор, приставка,
 * прошивка десятилетней давности, — формы расходятся: план записывался под
 * форму зонда, и тому клиенту, который и заставил нас искать, он по ключу
 * формы не доставался вовсе. Оговорка в журнале это называет, но не лечит;
 * лечит зонд, говорящий ТЕМ ЖЕ протоколом (MVP_CHECKLIST, пункт 3).
 *
 * ПРИВЕТСТВИЕ ЗОНДА собирается без supported_versions и добивается до
 * клиентской длины (want_wire). В режиме формы d2k_tls_connect_form клиент
 * 1.3 передаёт сюда транскрипт отправленного приветствия и ответ сервера 1.2:
 * чужие random/key_share предварительно заменены на собственные.
 *
 * ШИФРНАБОРЫ: ECDHE + AES128-GCM-SHA256 (c02b/c02f), AES256-GCM-SHA384
 * (c02c/c030), ChaCha20-Poly1305-SHA256 (cca9/cca8). Обмен — X25519 или
 * secp256r1. Примитивы общие с suite.c; расписание и запись — TLS 1.2.
 * Полевое основание 11.11.2026: форма Chrome предлагает c030, сервер flibusta.is
 * выбирает его, а прежний зонд отказывал до прикладной проверки. EMS формы
 * учитывается по RFC 7627. Неподдержанные шифр/группа дают явный отказ о
 * возможностях зонда, не о коробке.
 *
 * ЧЕГО НЕ ПРОВЕРЯЕТ: подпись в ServerKeyExchange, цепочку доверия и Finished
 * сервера. Причина та же, что у клиента 1.3, и названа там же: предмет
 * измерения — коробка на линии, а не подлинность сервера. Имя из сертификата
 * сверяется (d2k_t13_cert_name_ok, общая с 1.3 реализация): терминирующая
 * коробка со страницей блокировки обязана быть отличима от рабочего обхода.
 */
#ifndef D2K_TLS12_H
#define D2K_TLS12_H

#include <stddef.h>
#include <stdint.h>
#include "d2k_tls13.h"

typedef struct d2k_tls12 d2k_tls12;

/* Поднимает сессию поверх УЖЕ ПОДКЛЮЧЁННОГО сокета fd. sni — имя в
 * приветствии и для сверки сертификата (пустое — без расширения имени).
 * want_wire — проводная длина, до которой добивается приветствие (0 — не
 * добивать); смысл тот же, что у клиента 1.3.
 *
 * Владения сокетом НЕ берёт. 0 — сессия установлена, -1 — отказ с причиной в
 * err (заполняется всегда и по-человечески). */
int d2k_tls12_connect(int fd, const char *sni, int deadline_ms, size_t want_wire,
                      d2k_tls12 **out, char *err, size_t errcap);
/* Owned measurement transport, with a fixed ClientHello random for one
 * experiment series. No socket IO or transport ownership on this path. */
size_t d2k_tls12_probe_hello(const uint8_t random[32],const char *,size_t,uint8_t *,size_t);
int d2k_tls12_connect_probe(const d2k_tls_io *,const uint8_t random[32],const char *,
    int,size_t,d2k_tls12 **,char *,size_t);

/* Продолжение после приветствия 1.3 (с предложенной 1.2), на которое сервер
 * ответил 1.2: c_random и ch_msg (сообщение без заголовка записи) — того
 * приветствия, srv — уже прочитанные открытые байты рукопожатия сервера с
 * ServerHello. Тот же контракт, что у d2k_tls12_connect. */
int d2k_tls12_resume(int fd, const char *sni, int deadline_ms,
                     const uint8_t c_random[32], const uint8_t *ch_msg, size_t ch_len,
                     const uint8_t *srv, size_t srv_len,
                     d2k_tls12 **out, char *err, size_t errcap);
/* Как d2k_tls12_resume, но запись и чтение — через транспорт io. */
int d2k_tls12_resume_io(const d2k_tls_io *io, const char *sni, int deadline_ms,
                        const uint8_t c_random[32], const uint8_t *ch_msg, size_t ch_len,
                        const uint8_t *srv, size_t srv_len,
                        d2k_tls12 **out, char *err, size_t errcap);
/* Шлёт n байт прикладными данными. 0 или -1 с причиной. */
int d2k_tls12_write(d2k_tls12 *t, const uint8_t *buf, size_t n,
                    char *err, size_t errcap);

/* Читает прикладные данные. Больше нуля — сколько прочитано, 0 — конец,
 * -1 — отказ с причиной. */
long d2k_tls12_read(d2k_tls12 *t, uint8_t *buf, size_t cap, int wait_ms,
                    char *err, size_t errcap);

/* Совпало ли имя в сертификате: 1 да, 0 НЕТ, -1 сказать нечего. */
/* Consumed TLS record bytes (including headers); missing is declared body only. */
uint64_t d2k_tls12_rx_wire_bytes(const d2k_tls12 *t);
uint32_t d2k_tls12_rx_record_missing(const d2k_tls12 *t);

int d2k_tls12_peer_name(const d2k_tls12 *t);
/* ALPN, выбранный сервером; пустая строка — не выбран. */
const char *d2k_tls12_alpn(const d2k_tls12 *);

void d2k_tls12_free(d2k_tls12 *t);

/* PRF наружу ТОЛЬКО для проверки по вектору (RFC 5246 §5, P_SHA256).
 * Выведено отдельно по той же причине, что d2k_ghash_for_test: ошибка здесь
 * не падает и не видна — она даёт «метка не сошлась» на живом сервере, и
 * искать её пришлось бы в сети вместо стола. */
void d2k_tls12_prf_for_test(const uint8_t *secret, size_t slen, const char *label,
                            const uint8_t *seed, size_t seed_len,
                            uint8_t *out, size_t out_len);

/* Только для теста гонки: вызывается между сборкой ClientHello и отправкой.
 * По умолчанию NULL. Позволяет детерминированно развести две сборки во
 * времени и убедиться, что у соединений нет общего буфера. */
extern void (*d2k_tls12_test_barrier)(void);

#endif /* D2K_TLS12_H */
