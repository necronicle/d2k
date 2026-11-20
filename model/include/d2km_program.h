/* Программа обхода (D2K_SPEC.md §2.4, §7.2, §7.4, §8.2).
 *
 * Программа — что исполнитель делает с потоком: какие байты посылает, с
 * какой порчей, в каком порядке, где режет. Каждый элемент несёт запись
 * «почему» (§7.4); элемент без неё — ошибка проверки, и кандидат не
 * испытывается. Байты фальшивок строит генератор по грамматике (§7.3), здесь
 * они только хранятся. Исполнителю не оставлено выбора: нет значений «по
 * умолчанию», нет подбора TTL исполнителем (autottl) и изменения байтов
 * исполнителем (tlsmod) — всё число и всё содержимое заданы программой.
 *
 * Перевод в текст плана — язык, который сейчас понимает датапат
 * (core/plantlv.c). Хэш программы — от её содержания. */
#ifndef D2KM_PROGRAM_H
#define D2KM_PROGRAM_H

#include "d2km_context.h"

#define D2KM_PROG_PAYLOADS 4
#define D2KM_PROG_PAYLOAD_MAX 2048
#define D2KM_PROG_FAKES 4
#define D2KM_PROG_SPLITS 4
#define D2KM_WHY_MAX 512

/* Якоря разреза в сообщении клиента (их вычисляет исполнитель по разбору
 * того же сообщения, а не по числу из таблицы). */
typedef enum {
    D2KM_AT_PAYLOAD_START = 0,
    D2KM_AT_SNI_START,
    D2KM_AT_SNI_END,
    D2KM_AT_HELLO_MIDDLE,
    D2KM_AT_RECORD_END,
    D2KM_AT_SNI_MIDDLE,
    D2KM_ANCHOR_END
} d2km_anchor;

/* Порча пакета фальшивки: почему сервер её не примет. */
typedef struct {
    uint8_t ttl;          /* 0 — TTL не меняется */
    uint8_t badsum;       /* неверная контрольная сумма TCP */
    uint8_t md5;          /* опция TCP MD5 */
    uint8_t tcpts;        /* устаревшая метка времени TCP */
    int32_t seqshift;     /* сдвиг seq; 0 — нет */
} d2km_poison;

typedef struct {
    uint16_t length;
    uint8_t bytes[D2KM_PROG_PAYLOAD_MAX];
    char why[D2KM_WHY_MAX];
} d2km_payload;

typedef struct {
    uint8_t payload;      /* индекс в payloads */
    d2km_poison poison;
    uint8_t repeats;      /* число копий, >= 1 */
    uint32_t gap_us;      /* пауза между копиями */
    uint8_t between;      /* 0 — до оригинала, 1 — между частями разреза */
    char why[D2KM_WHY_MAX];
} d2km_fake;

typedef struct {
    d2km_anchor anchor;
    int16_t offset;
    char why[D2KM_WHY_MAX];
} d2km_split;

typedef struct {
    d2km_transport transport;
    d2km_protocol protocol;
    size_t payload_count;
    d2km_payload payloads[D2KM_PROG_PAYLOADS];
    size_t fake_count;
    d2km_fake fakes[D2KM_PROG_FAKES];
    size_t split_count;
    d2km_split splits[D2KM_PROG_SPLITS];
    uint8_t reverse;              /* части разреза в обратном порядке */
    char order_why[D2KM_WHY_MAX]; /* обязательна, если reverse */
    uint64_t seed;                /* зерно генератора байтов (§7.3) */
} d2km_program;

typedef enum {
    D2KM_PC_OK = 0,
    D2KM_PC_EMPTY,             /* программа ничего не делает */
    D2KM_PC_NO_WHY,            /* элемент без записи «почему» */
    D2KM_PC_BAD_PAYLOAD,       /* ссылка на несуществующую нагрузку, пустая нагрузка */
    D2KM_PC_SERVER_ACCEPTS,    /* у фальшивки нет причины, по которой сервер её не примет */
    D2KM_PC_BAD_VALUE,         /* значение вне грамматики языка плана */
    D2KM_PC_BAD_PROTOCOL       /* протокол не переводится в план */
} d2km_program_check_code;

const char *d2km_anchor_name(d2km_anchor);
d2km_program_check_code d2km_program_check(const d2km_program *);

/* Текст плана для core/plantlv.c. id плана — из хэша содержания. Возвращает
 * длину текста (без нуля) или 0, если программа не прошла проверку или cap
 * мал. Записи «почему» в план не входят: они — в журнале (§12). */
size_t d2km_program_text(const d2km_program *, char *out, size_t cap);

/* Хэш содержания программы (без записей «почему»). Одинаковые действия —
 * одинаковый хэш; хэш опыт не идентифицирует (§10.1). */
uint64_t d2km_program_hash(const d2km_program *);

#endif
