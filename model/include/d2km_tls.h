/* Грамматика TLS ClientHello и генератор сообщений (D2K_SPEC.md §7.3, §11.2).
 *
 * Сообщение — дерево полей по RFC 8446 / RFC 5246: запись, рукопожатие,
 * версия, Random, session_id, наборы шифров, сжатие, расширения. Сборка
 * пересчитывает все длины. Свободные поля фальшивки заполняются своим
 * генератором случайных чисел; зерно пишется в запись «почему», и сообщение
 * воспроизводимо. Результат всегда разбирается обратно и сверяется.
 * Готовых байтов приветствий здесь нет: исходная форма — приветствие
 * клиента. */
#ifndef D2KM_TLS_H
#define D2KM_TLS_H

#include <stddef.h>
#include <stdint.h>

#define D2KM_TLS_MAX 16384          /* предел полезной нагрузки записи TLS */
#define D2KM_TLS_EXT_MAX 64

/* Номера полей воздействия (d2km_action.field) для TLS ClientHello. */
enum {
    D2KM_TLS_F_SNI = 1,             /* имя в server_name */
    D2KM_TLS_F_RECORD_VERSION,      /* версия в заголовке записи */
    D2KM_TLS_F_RANDOM,
    D2KM_TLS_F_SESSION_ID,
    D2KM_TLS_F_CIPHERS,
    D2KM_TLS_F_EXT_ORDER,
    D2KM_TLS_F_EXT = 0x100          /* | тип расширения: наличие расширения */
};

typedef struct {
    uint16_t type;
    uint16_t length;
    uint16_t offset;                /* в arena */
} d2km_tls_ext;

typedef struct {
    uint16_t record_version;        /* 0x0301 у большинства клиентов */
    uint16_t version;               /* legacy_version */
    uint8_t random[32];
    uint8_t session_id_length;
    uint8_t session_id[32];
    uint16_t ciphers_length;
    uint16_t ciphers_offset;        /* в arena */
    uint8_t compression_length;
    uint16_t compression_offset;
    size_t ext_count;
    d2km_tls_ext ext[D2KM_TLS_EXT_MAX];
    size_t arena_length;
    uint8_t arena[D2KM_TLS_MAX];
} d2km_tls_hello;

typedef enum {
    D2KM_TLS_OK = 0,
    D2KM_TLS_SHORT,        /* данных не хватает (приветствие в нескольких сегментах) */
    D2KM_TLS_NOT_HELLO,    /* не запись handshake/ClientHello */
    D2KM_TLS_MALFORMED,    /* длины или поля нарушают грамматику */
    D2KM_TLS_TOO_BIG,      /* больше предела */
    D2KM_TLS_ABSENT        /* требуемого поля или расширения нет */
} d2km_tls_code;

/* Разбирает запись TLS с одним ClientHello (заголовок записи 5 байт). */
d2km_tls_code d2km_tls_parse(const uint8_t *buf, size_t n, d2km_tls_hello *);
/* Собирает запись; возвращает длину или 0 при переполнении cap. */
size_t d2km_tls_build(const d2km_tls_hello *, uint8_t *out, size_t cap);

/* Имя server_name (host_name) — копия с нулём; ABSENT, если нет. */
d2km_tls_code d2km_tls_sni(const d2km_tls_hello *, char *out, size_t cap);

/* Изменения по грамматике. Каждое пересобирает дерево и оставляет его
 * корректным. */
d2km_tls_code d2km_tls_set_sni(d2km_tls_hello *, const char *name);
d2km_tls_code d2km_tls_drop_ext(d2km_tls_hello *, uint16_t type);
/* Добавляет или заменяет расширение type с данными data[0..n). */
d2km_tls_code d2km_tls_put_ext(d2km_tls_hello *, uint16_t type,
                               const uint8_t *data, size_t n);
/* Расширение padding (RFC 7685) такой длины, чтобы вся запись стала total
 * байт. ABSENT/TOO_BIG, если это невозможно. */
d2km_tls_code d2km_tls_pad_to(d2km_tls_hello *, size_t total);

/* Генератор случайных чисел фальшивок: splitmix64, зерно — в «почему». */
typedef struct { uint64_t state; } d2km_rng;
void d2km_rng_seed(d2km_rng *, uint64_t seed);
uint64_t d2km_rng_next(d2km_rng *);
void d2km_rng_fill(d2km_rng *, uint8_t *, size_t);

/* Поля, которые у нового соединения по грамматике обязаны быть новыми:
 * Random, session_id (той же длины), открытые ключи key_share (те же группы
 * и длины). Заполняются генератором. Используется и прямым контролем
 * (§4.3), и фальшивкой (§7.3). */
d2km_tls_code d2km_tls_refresh(d2km_tls_hello *, d2km_rng *);

/* Границы полей в собранной записи (смещения начала каждого поля и
 * расширения, начало и конец имени SNI). Пишет не больше cap, возвращает
 * число. Для позиций разреза (§6.5). */
size_t d2km_tls_bounds(const d2km_tls_hello *, uint32_t *out, size_t cap);

/* Смещение и длина имени SNI в собранной записи. ABSENT, если имени нет. */
d2km_tls_code d2km_tls_sni_span(const d2km_tls_hello *, uint32_t *offset,
                                uint32_t *length);

#endif
