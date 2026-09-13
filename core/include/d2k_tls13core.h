/* d2k_tls13core.h — ЯДРО TLS 1.3 БЕЗ ТРАНСПОРТА.
 *
 * ЗАЧЕМ. Рукопожатие TLS 1.3 у TCP и у QUIC ОДНО И ТО ЖЕ: те же сообщения,
 * тот же транскрипт, то же расписание ключей, та же проверка имени в
 * сертификате. Разное у них только то, ЧЕМ эти сообщения везут: записи TLS
 * поверх потока — у одного, кадры CRYPTO поверх датаграмм — у другого.
 *
 * До этого файла всё ядро жило внутри core/tls13.c, сросшееся с сокетом и
 * записями. Зонду подтверждения QUIC оно нужно целиком — и скопировать его
 * туда нельзя (§2.5: второй реализации быть не должно). Поэтому ядро вынесено
 * сюда, а tls13.c остался тем, чем он и был: слоем записей поверх сокета.
 *
 * ЧТО СЮДА НЕ ПЕРЕЕХАЛО И ПОЧЕМУ. Ключи записей (traffic_keys) остались у
 * TLS: у QUIC ключи выводятся своими метками (RFC 9001 §5.1, см.
 * d2k_qw_keys_from_secret), и обобщать две трёхстрочные функции одним
 * параметром-меткой дороже, чем оставить их врозь.
 *
 * ШИФРНАБОР ОДИН: TLS_AES_128_GCM_SHA256, X25519. Это не «пока» — см. шапку
 * d2k_tls13.h: поддерживается ровно одна связка, и всё здесь написано под
 * тридцатидвухбайтовые секреты SHA-256.
 */
#ifndef D2K_TLS13CORE_H
#define D2K_TLS13CORE_H

#include <stddef.h>
#include <stdint.h>

/* Типы сообщений рукопожатия, которые этот модуль различает. */
#define D2K_T13_CLIENT_HELLO 1
#define D2K_T13_SERVER_HELLO 2
#define D2K_T13_ENCRYPTED_EXT 8
#define D2K_T13_CERTIFICATE 11
#define D2K_T13_FINISHED     20

/* Случайные байты. Единственный источник энтропии в ядре: на закрытый ключ,
 * на random приветствия и на идентификаторы соединения QUIC. 0 — успех. */
int d2k_t13_random(uint8_t *b, size_t n);

/* Derive-Secret(secret, label, Transcript-Hash(msgs)) — RFC 8446 §7.1.
 * msgs может быть пустым (NULL, 0): тогда хешируется пустая строка. */
int d2k_t13_derive_secret(const uint8_t secret[32], const char *label,
                          const uint8_t *msgs, size_t n, uint8_t out[32]);

/* Расписание до секретов РУКОПОЖАТИЯ: из общего секрета X25519 и транскрипта
 * «ClientHello..ServerHello». hs_out — секрет уровня Handshake, он нужен
 * дальше для прикладного расписания. 0 — успех. */
int d2k_t13_schedule_hs(const uint8_t shared[32], const uint8_t *tr, size_t tr_len,
                        uint8_t c_hs[32], uint8_t s_hs[32], uint8_t hs_out[32]);

/* Расписание до ПРИКЛАДНЫХ секретов: из секрета рукопожатия и транскрипта
 * «ClientHello..серверный Finished». 0 — успех. */
int d2k_t13_schedule_ap(const uint8_t hs[32], const uint8_t *tr, size_t tr_len,
                        uint8_t c_ap[32], uint8_t s_ap[32]);

/* MAC сообщения Finished для стороны, чей секрет уровня передан (RFC 8446
 * §4.4.4). 0 — успех. */
int d2k_t13_finished_mac(const uint8_t secret[32], const uint8_t *tr, size_t tr_len,
                         uint8_t out[32]);

/* Опции сборки ClientHello. Всё, чем отличаются приветствия TCP и QUIC,
 * собрано здесь — иначе отличия расползлись бы по двум сборщикам. */
typedef struct {
    const char *sni;          /* имя; NULL или пустое — без расширения имени */
    const uint8_t *pub;       /* 32 байта открытого ключа X25519 */
    const uint8_t *random;    /* 32 байта случайного */
    size_t session_id_len;    /* 32 у TLS поверх TCP, 0 у QUIC (RFC 9001 §8.4) */
    const char *alpn;         /* "http/1.1", "h3"; NULL — без ALPN */
    const uint8_t *extra;     /* готовые байты дополнительных расширений */
    size_t extra_len;         /* туда едет quic_transport_parameters (0x0039) */
    /* Добить СООБЩЕНИЕ рукопожатия расширением padding (RFC 7685) до этой
       длины. Считается БЕЗ заголовка записи: у QUIC записей нет вовсе, и
       считать их в общем ядре значило бы зашить сюда чужой транспорт.
       0 — не добивать. */
    size_t pad_to;
} d2k_t13_ch_opts;

/* Собирает ClientHello. Возвращает длину сообщения или 0 при отказе. */
size_t d2k_t13_ch_build(const d2k_t13_ch_opts *o, uint8_t *out, size_t cap);

/* Разбирает ServerHello ровно до общего ключа. Возвращает 0 и указатель на
 * 32 байта ключа X25519 сервера внутри sh; -1 с причиной в err.
 *
 * Полным разбором это не притворяется: от ServerHello нужен ровно один смысл
 * — общий ключ, — и делать вид, что проверено что-то ещё, было бы враньём в
 * пользу себе. */
int d2k_t13_sh_parse(const uint8_t *sh, size_t sh_len, const uint8_t **peer_key,
                     char *err, size_t errcap);

/* Идёт по флайту сообщений рукопожатия, лежащих подряд без заголовков
 * записей. *off — позиция, с которой продолжать (на входе и на выходе).
 * Возвращает 1 и заполняет type/body/blen для очередного сообщения, 0 —
 * сообщений больше нет либо остаток обрезан. */
int d2k_t13_flight_next(const uint8_t *buf, size_t len, size_t *off,
                        uint8_t *type, const uint8_t **body, size_t *blen);

/* Совпало ли имя, которым представился сервер, с тем, что мы спросили:
 * 1 — да, 0 — НЕТ, -1 — сказать нечего. Разбирает сообщение Certificate
 * (TLS 1.3, RFC 8446 §4.4.2) и сверяет subjectAltName/dNSName листового
 * сертификата.
 *
 * Это НЕ проверка подлинности: цепочка не строится, доверенных корней нет,
 * самоподписанный сертификат с нужным именем ответ 1 получит. Уровень
 * доказательства от неё не растёт (§4.2). */
int d2k_t13_cert_name_ok(const uint8_t *body, size_t len, const char *host);

#endif /* D2K_TLS13CORE_H */
