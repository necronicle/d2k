/* plantlv.c — человеческий текст плана в байты провода.
 *
 * ЗАЧЕМ. d2k_compose (compose.c) выдаёт план ТЕКСТОМ — тем самым, что лежит в
 * catalog.json и что показывает панель. Датапат принимает план ТОЛЬКО байтами
 * TLV (D2K_CMD_SET_NAME, datapath/plan_parse.c). До этого модуля мост между
 * ними был только на Go-стороне (internal/plan: ParseText + MarshalTLV), и
 * планировщик на C физически не мог поставить ни одного собранного плана:
 * d2k_link_set_name отвергала текст как «не hex». Найдено первым же прогоном
 * test_sched — привязки не появлялись, потому что кандидаты не вставали.
 *
 * ПОЧЕМУ ПАРСЕР, А НЕ ВТОРОЙ СБОРЩИК. Соблазн был обратный: научить d2k_compose
 * выдавать сразу и текст, и TLV. Это завело бы ДВЕ формы одного плана, растущие
 * рядом, — и первое же расхождение между ними означало бы, что в каталоге
 * записано одно, а на провод ушло другое. Здесь текст — единственный источник:
 * что записано, то и едет. §2.5 («измеренное совпадает с исполняемым») требует
 * именно этого.
 *
 * ЭТАЛОН — GO-СТОРОНА, ДОСЛОВНО. Грамматика — internal/plan/text.go (Text и
 * ParseText), раскладка записей и ИХ ПОРЯДОК — internal/plan/tlv.go
 * (MarshalTLV). Порядок записей не косметика: датапат читает их подряд, а
 * круг «текст → TLV → текст» на Go-стороне сверяется побайтово. Отдельно
 * унаследовано то, на чём ревью 11.09 уже спотыкалось: recOrder пишется
 * БЕЗУСЛОВНО, `if` стоит только перед recGuard — план без заданного порядка
 * всё равно несёт запись со значением 0 (forward).
 *
 * НЕИЗВЕСТНАЯ ДИРЕКТИВА — ОТКАЗ, А НЕ ПРОПУСК. Дословно по тому же правилу,
 * что и на Go-стороне (комментарий у ParseText): молчаливый пропуск дал бы
 * план, отличный от записанного, и «проверенная стратегия» перестала бы быть
 * той, которую проверяли.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "d2k_plantlv.h"

enum {
    REC_ID      = 0x0001,
    REC_PROTO   = 0x0002,
    REC_PAYLOAD = 0x0010,
    REC_POISON  = 0x0011,
    REC_SPLIT   = 0x0100,
    REC_FAKE    = 0x0101,
    REC_SEQOVL  = 0x0102,
    REC_ORDER   = 0x0103,
    REC_GUARD   = 0x0104,
    REC_PACE    = 0x0105,
    REC_INPUT   = 0x0106,
    REC_SETTLE  = 0x0107,
    REC_SEGMENT = 0x0108,
    REC_WIRE    = 0x0109
};

/* Пределы одного плана. Не выдуманы: столько же держит датапат в разобранном
   плане (datapath/plan_parse.c, счётчики scan), и принять здесь больше значило
   бы собрать кадр, который тот же датапат отвергнет. */
#define MAX_PAYLOADS 8
#define MAX_POISONS  8
#define MAX_SPLITS   8
#define MAX_FAKES    8
#define MAX_SEQOVLS  4

typedef struct {
    uint16_t id;
    uint8_t *bytes;
    size_t   len;
} pl_payload;

typedef struct {
    uint16_t id;
    uint8_t  ttl;
    uint8_t  flags;
    int32_t  seq_shift;
} pl_poison;

typedef struct { uint16_t anchor; int16_t offset; } pl_split;
typedef struct {
    uint16_t payload_id, poison_id;
    uint8_t  repeats, placement;
    uint32_t gap_us;
} pl_fake;
typedef struct { uint16_t payload_id, poison_id; } pl_seqovl;

typedef struct {
    uint16_t   schema, minexec;
    uint8_t    id[16];
    uint8_t    transport, proto;
    pl_payload payloads[MAX_PAYLOADS]; size_t n_payloads;
    pl_poison  poisons[MAX_POISONS];   size_t n_poisons;
    pl_split   splits[MAX_SPLITS];     size_t n_splits;
    pl_fake    fakes[MAX_FAKES];       size_t n_fakes;
    pl_seqovl  seqovls[MAX_SEQOVLS];   size_t n_seqovls;
    uint8_t    order;
    uint8_t    guards;
    uint32_t   pace_us;   /* 0 — записи нет */
    uint32_t   input_len, input_sni_off, input_sni_len, settle_us, segment_size;
    uint8_t    wire_profile;
} pl_plan;

static int b64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') { return c - 'A'; }
    if (c >= 'a' && c <= 'z') { return c - 'a' + 26; }
    if (c >= '0' && c <= '9') { return c - '0' + 52; }
    return c == '+' ? 62 : c == '/' ? 63 : -1;
}

static int parse_base64(const char *s, uint8_t **out, size_t *len) {
    size_t n = strlen(s), used = 0;
    *out = NULL; *len = 0;
    if (!n) { return 0; }
    if (n % 4) { return -1; }
    uint8_t *b = malloc(n / 4 * 3);
    if (!b) { return -1; }
    for (size_t i = 0; i < n; i += 4) {
        int a = b64_value((unsigned char)s[i]), c = b64_value((unsigned char)s[i+1]);
        int d = b64_value((unsigned char)s[i+2]), e = b64_value((unsigned char)s[i+3]);
        if (a < 0 || c < 0) { goto bad; }
        b[used++] = (uint8_t)((a << 2) | (c >> 4));
        if (s[i+2] == '=') {
            if (s[i+3] != '=' || i + 4 != n || (c & 15)) { goto bad; }
            break;
        }
        if (d < 0) { goto bad; }
        b[used++] = (uint8_t)((c << 4) | (d >> 2));
        if (s[i+3] == '=') {
            if (i + 4 != n || (d & 3)) { goto bad; }
            break;
        }
        if (e < 0) { goto bad; }
        b[used++] = (uint8_t)((d << 6) | e);
    }
    *out = b; *len = used; return 0;
bad:
    free(b); return -1;
}

static void say(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) { return; }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

static int hex_nib(int c) {
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/* Разбирает шестнадцатеричное слово в свежевыделенный буфер. Пустое слово —
   законный ноль байт (Go: hex.DecodeString("") даёт пустой срез). */
static int parse_hex(const char *s, uint8_t **out, size_t *out_len,
                     char *err, size_t errcap) {
    size_t n = strlen(s);
    if (n % 2 != 0) {
        say(err, errcap, "нечётное число шестнадцатеричных цифр (%zu)", n);
        return -1;
    }
    uint8_t *b = NULL;
    if (n > 0) {
        b = malloc(n / 2);
        if (!b) { say(err, errcap, "не хватило памяти на %zu байт", n / 2); return -1; }
    }
    for (size_t i = 0; i < n; i += 2) {
        int hi = hex_nib((unsigned char)s[i]), lo = hex_nib((unsigned char)s[i + 1]);
        if (hi < 0 || lo < 0) {
            free(b);
            say(err, errcap, "не шестнадцатеричная цифра в позиции %zu", i);
            return -1;
        }
        b[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *out = b;
    *out_len = n / 2;
    return 0;
}

static int anchor_by_name(const char *s, uint16_t *out) {
    /* Те же шесть имён и те же номера, что anchorNames (internal/plan/text.go)
       и AnchorSNIMiddle=5 (plan.go). */
    static const struct { const char *n; uint16_t v; } a[] = {
        { "payload_start", 0 }, { "sni_start", 1 }, { "sni_end", 2 },
        { "hello_middle", 3 }, { "record_end", 4 }, { "sni_middle", 5 },
    };
    for (size_t i = 0; i < sizeof a / sizeof a[0]; i++) {
        if (strcmp(a[i].n, s) == 0) { *out = a[i].v; return 0; }
    }
    return -1;
}

/* Режет строку на слова по пробелам. Возвращает число слов. */
static size_t split_fields(char *line, char **f, size_t cap) {
    size_t n = 0;
    char *p = line;
    while (*p && n < cap) {
        while (*p == ' ' || *p == '\t') { p++; }
        if (!*p) { break; }
        f[n++] = p;
        while (*p && *p != ' ' && *p != '\t') { p++; }
        if (*p) { *p++ = '\0'; }
    }
    return n;
}

/* Разбирает "ключ=значение" и сверяет ключ. */
static int kv_u32(const char *field, const char *key, unsigned long *out) {
    size_t kl = strlen(key);
    if (strncmp(field, key, kl) != 0 || field[kl] != '=') { return -1; }
    const char *v = field + kl + 1;
    if (!*v) { return -1; }
    char *end = NULL;
    unsigned long val = strtoul(v, &end, 10);
    if (!end || *end != '\0') { return -1; }
    *out = val;
    return 0;
}

/* Разбирает голое десятичное число. Отдельно от kv_u32: у pace значение
   идёт без ключа, и притворяться, что "ключ=значение" тут есть, значило бы
   принимать "pace pace=12000". */
static int str_u32(const char *sv, unsigned long *out) {
    if (!sv || *sv < '0' || *sv > '9') { return -1; }
    char *end = NULL;
    errno = 0;
    unsigned long val = strtoul(sv, &end, 10);
    if (errno == ERANGE || val > UINT32_MAX || !end || *end != '\0') { return -1; }
    *out = val;
    return 0;
}

static void plan_free(pl_plan *p) {
    for (size_t i = 0; i < p->n_payloads; i++) { free(p->payloads[i].bytes); }
    memset(p, 0, sizeof *p);
}

static int parse_text(const char *text, pl_plan *p, char *err, size_t errcap) {
    memset(p, 0, sizeof *p);
    int seen_header = 0;
    size_t lineno = 0;
    const char *cur = text;

    while (*cur) {
        const char *nl = strchr(cur, '\n');
        size_t len = nl ? (size_t)(nl - cur) : strlen(cur);
        lineno++;
        char line[8192];
        if (len >= sizeof line) {
            say(err, errcap, "строка %zu длиннее %zu байт", lineno, sizeof line - 1);
            plan_free(p);
            return -1;
        }
        memcpy(line, cur, len);
        line[len] = '\0';
        cur = nl ? nl + 1 : cur + len;

        char *t = line;
        while (*t == ' ' || *t == '\t' || *t == '\r') { t++; }
        size_t tl = strlen(t);
        while (tl > 0 && (t[tl - 1] == ' ' || t[tl - 1] == '\t' || t[tl - 1] == '\r')) {
            t[--tl] = '\0';
        }
        if (*t == '\0' || *t == '#') { continue; }

        char *f[8];
        size_t nf = split_fields(t, f, 8);
        if (nf == 0) { continue; }

        if (strcmp(f[0], "d2k-plan") == 0) {
            if (nf != 3) { say(err, errcap, "строка %zu: d2k-plan ждёт два числа", lineno); goto bad; }
            p->schema = (uint16_t)strtoul(f[1], NULL, 10);
            p->minexec = (uint16_t)strtoul(f[2], NULL, 10);
            seen_header = 1;
        } else if (strcmp(f[0], "id") == 0) {
            if (nf != 2) { say(err, errcap, "строка %zu: id ждёт одно слово", lineno); goto bad; }
            uint8_t *b = NULL; size_t bl = 0;
            char why[80];
            if (parse_hex(f[1], &b, &bl, why, sizeof why) != 0 || bl != 16) {
                free(b);
                say(err, errcap, "строка %zu: id обязан быть 16 байтами в hex", lineno);
                goto bad;
            }
            memcpy(p->id, b, 16);
            free(b);
        } else if (strcmp(f[0], "proto") == 0) {
            if (nf != 3) { say(err, errcap, "строка %zu: proto ждёт транспорт и протокол", lineno); goto bad; }
            if (strcmp(f[1], "tcp") == 0) { p->transport = 6; }
            else if (strcmp(f[1], "udp") == 0) { p->transport = 17; }
            else { say(err, errcap, "строка %zu: неизвестный транспорт \"%s\"", lineno, f[1]); goto bad; }
            if (strcmp(f[2], "unknown") == 0) { p->proto = 0; }
            else if (strcmp(f[2], "tls") == 0) { p->proto = 1; }
            else if (strcmp(f[2], "quic") == 0) { p->proto = 2; }
            else { say(err, errcap, "строка %zu: неизвестный протокол \"%s\"", lineno, f[2]); goto bad; }
        } else if (strcmp(f[0], "payload") == 0) {
            if (nf < 2 || nf > 3) { say(err, errcap, "строка %zu: payload ждёт номер и байты", lineno); goto bad; }
            if (p->n_payloads >= MAX_PAYLOADS) { say(err, errcap, "строка %zu: приманок больше %d", lineno, MAX_PAYLOADS); goto bad; }
            pl_payload *v = &p->payloads[p->n_payloads];
            v->id = (uint16_t)strtoul(f[1], NULL, 10);
            char why[80];
            if (parse_hex(nf == 3 ? f[2] : "", &v->bytes, &v->len, why, sizeof why) != 0) {
                say(err, errcap, "строка %zu: нагрузка: %s", lineno, why);
                goto bad;
            }
            p->n_payloads++;
        } else if (strcmp(f[0], "payload-pad") == 0 || strcmp(f[0], "payload-pad64") == 0) {
            unsigned long id, len, fill;
            uint8_t *prefix = NULL;
            size_t prefix_len = 0;
            char why[80];
            if ((nf != 4 && nf != 5) || p->n_payloads >= MAX_PAYLOADS ||
                str_u32(f[1], &id) || id == 0 || id > 65535 ||
                str_u32(f[2], &len) || len == 0 || len > 65533 ||
                str_u32(f[3], &fill) || fill > 255) {
                say(err, errcap, "строка %zu: payload-pad ждёт id длину байт [hex-префикс]", lineno);
                goto bad;
            }
            int bad_prefix = strcmp(f[0], "payload-pad64") == 0
                ? parse_base64(nf == 5 ? f[4] : "", &prefix, &prefix_len)
                : parse_hex(nf == 5 ? f[4] : "", &prefix, &prefix_len, why, sizeof why);
            if (bad_prefix) {
                snprintf(why, sizeof why, "некорректное кодирование префикса");
                say(err, errcap, "строка %zu: payload-pad: %s", lineno, why); goto bad;
            }
            if (prefix_len > len) {
                free(prefix); say(err, errcap, "payload-pad не обрезает префикс"); goto bad;
            }
            pl_payload *v = &p->payloads[p->n_payloads];
            v->bytes = malloc((size_t)len);
            if (!v->bytes) { free(prefix); say(err, errcap, "нет памяти для payload-pad"); goto bad; }
            v->id = (uint16_t)id; v->len = (size_t)len;
            memset(v->bytes, (int)fill, v->len);
            if (prefix_len) { memcpy(v->bytes, prefix, prefix_len); }
            free(prefix);
            p->n_payloads++;
        } else if (strcmp(f[0], "payload-slice") == 0) {
            unsigned long id, source, off, len;
            const pl_payload *src = NULL;
            if (nf != 5 || p->n_payloads >= MAX_PAYLOADS ||
                str_u32(f[1], &id) || !id || id > 65535 ||
                str_u32(f[2], &source) || str_u32(f[3], &off) ||
                str_u32(f[4], &len) || !len || len > 65533) {
                say(err, errcap, "payload-slice ждёт id source offset length"); goto bad;
            }
            for (size_t j = 0; j < p->n_payloads; j++) {
                if (p->payloads[j].id == source) { src = &p->payloads[j]; break; }
            }
            if (!src || off > src->len || len > src->len - off) {
                say(err, errcap, "payload-slice выходит за исходные байты"); goto bad;
            }
            pl_payload *v = &p->payloads[p->n_payloads];
            v->bytes = malloc((size_t)len);
            if (!v->bytes) { say(err, errcap, "нет памяти для payload-slice"); goto bad; }
            v->id = (uint16_t)id; v->len = (size_t)len;
            memcpy(v->bytes, src->bytes + off, v->len);
            p->n_payloads++;
        } else if (strcmp(f[0], "wire") == 0) {
            if (nf != 2 || strcmp(f[1], "detect-tcp-v1")) {
                say(err, errcap, "неизвестный wire profile"); goto bad;
            }
            p->wire_profile = 1;
        } else if (strcmp(f[0], "input") == 0) {
            unsigned long len, off, snilen;
            if (nf != 4 || str_u32(f[1], &len) || !len || len > 65535 ||
                str_u32(f[2], &off) || str_u32(f[3], &snilen) ||
                off > len || snilen > len - off) {
                say(err, errcap, "input ждёт длину нагрузки и границы имени"); goto bad;
            }
            p->input_len = (uint32_t)len;
            p->input_sni_off = (uint32_t)off;
            p->input_sni_len = (uint32_t)snilen;
        } else if (strcmp(f[0], "settle") == 0 || strcmp(f[0], "segment") == 0) {
            unsigned long u;
            if (nf != 2 || str_u32(f[1], &u) || !u) {
                say(err, errcap, "%s ждёт положительное число", f[0]); goto bad;
            }
            if (strcmp(f[0], "segment") == 0) {
                if (u > 65535) { say(err, errcap, "segment больше 65535"); goto bad; }
                p->segment_size = (uint32_t)u;
            } else { p->settle_us = (uint32_t)u; }
        } else if (strcmp(f[0], "poison") == 0) {
            if (nf < 2) { say(err, errcap, "строка %zu: poison без номера", lineno); goto bad; }
            if (p->n_poisons >= MAX_POISONS) { say(err, errcap, "строка %zu: порч больше %d", lineno, MAX_POISONS); goto bad; }
            pl_poison *v = &p->poisons[p->n_poisons];
            memset(v, 0, sizeof *v);
            v->id = (uint16_t)strtoul(f[1], NULL, 10);
            for (size_t i = 2; i < nf; i++) {
                unsigned long u;
                if (strcmp(f[i], "badsum") == 0) { v->flags |= 1u << 0; }
                else if (strcmp(f[i], "tcpts") == 0) { v->flags |= 1u << 1; }
                else if (strcmp(f[i], "ipidzero") == 0) { v->flags |= 1u << 2; }
                else if (kv_u32(f[i], "ttl", &u) == 0) { v->ttl = (uint8_t)u; }
                else if (strncmp(f[i], "seqshift=", 9) == 0) {
                    v->seq_shift = (int32_t)strtol(f[i] + 9, NULL, 10);
                } else {
                    say(err, errcap, "строка %zu: неизвестный признак порчи \"%s\"", lineno, f[i]);
                    goto bad;
                }
            }
            p->n_poisons++;
        } else if (strcmp(f[0], "split") == 0) {
            if (nf != 3) { say(err, errcap, "строка %zu: split ждёт якорь и смещение", lineno); goto bad; }
            if (p->n_splits >= MAX_SPLITS) { say(err, errcap, "строка %zu: разрезов больше %d", lineno, MAX_SPLITS); goto bad; }
            pl_split *v = &p->splits[p->n_splits];
            if (anchor_by_name(f[1], &v->anchor) != 0) {
                say(err, errcap, "строка %zu: неизвестный якорь \"%s\"", lineno, f[1]);
                goto bad;
            }
            v->offset = (int16_t)strtol(f[2], NULL, 10);
            p->n_splits++;
        } else if (strcmp(f[0], "fake") == 0) {
            if (nf != 6) { say(err, errcap, "строка %zu: fake ждёт пять параметров", lineno); goto bad; }
            if (p->n_fakes >= MAX_FAKES) { say(err, errcap, "строка %zu: фальшивок больше %d", lineno, MAX_FAKES); goto bad; }
            pl_fake *v = &p->fakes[p->n_fakes];
            memset(v, 0, sizeof *v);
            unsigned long u;
            if (kv_u32(f[1], "payload", &u) != 0) { say(err, errcap, "строка %zu: fake без payload=", lineno); goto bad; }
            v->payload_id = (uint16_t)u;
            if (kv_u32(f[2], "poison", &u) != 0) { say(err, errcap, "строка %zu: fake без poison=", lineno); goto bad; }
            v->poison_id = (uint16_t)u;
            if (kv_u32(f[3], "repeats", &u) != 0) { say(err, errcap, "строка %zu: fake без repeats=", lineno); goto bad; }
            v->repeats = (uint8_t)u;
            if (kv_u32(f[4], "gap_us", &u) != 0) { say(err, errcap, "строка %zu: fake без gap_us=", lineno); goto bad; }
            v->gap_us = (uint32_t)u;
            if (strcmp(f[5], "place=before") == 0) { v->placement = 0; }
            else if (strcmp(f[5], "place=between") == 0) { v->placement = 1; }
            else { say(err, errcap, "строка %zu: неизвестное место \"%s\"", lineno, f[5]); goto bad; }
            p->n_fakes++;
        } else if (strcmp(f[0], "seqovl") == 0) {
            if (nf != 3) { say(err, errcap, "строка %zu: seqovl ждёт payload= и poison=", lineno); goto bad; }
            if (p->n_seqovls >= MAX_SEQOVLS) { say(err, errcap, "строка %zu: перекрытий больше %d", lineno, MAX_SEQOVLS); goto bad; }
            pl_seqovl *v = &p->seqovls[p->n_seqovls];
            unsigned long u;
            if (kv_u32(f[1], "payload", &u) != 0) { say(err, errcap, "строка %zu: seqovl без payload=", lineno); goto bad; }
            v->payload_id = (uint16_t)u;
            if (kv_u32(f[2], "poison", &u) != 0) { say(err, errcap, "строка %zu: seqovl без poison=", lineno); goto bad; }
            v->poison_id = (uint16_t)u;
            p->n_seqovls++;
        } else if (strcmp(f[0], "order") == 0) {
            if (nf != 2) { say(err, errcap, "строка %zu: order ждёт одно слово", lineno); goto bad; }
            if (strcmp(f[1], "forward") == 0) { p->order = 0; }
            else if (strcmp(f[1], "reverse") == 0) { p->order = 1; }
            else { say(err, errcap, "строка %zu: неизвестный порядок \"%s\"", lineno, f[1]); goto bad; }
        } else if (strcmp(f[0], "pace") == 0) {
            /* Разнос посылок нагрузки во времени, микросекунды. Ноль
               запрещён: «pace 0» и отсутствие строки означали бы одно и то
               же, а директива, ничего не меняющая, — это способ написать
               план, который читается не так, как исполняется. */
            if (nf != 2) { say(err, errcap, "строка %zu: pace ждёт одно число", lineno); goto bad; }
            {
                unsigned long u = 0;
                if (str_u32(f[1], &u) != 0 || u == 0) {
                    say(err, errcap, "строка %zu: pace ждёт положительное число микросекунд", lineno);
                    goto bad;
                }
                p->pace_us = (uint32_t)u;
            }
        } else if (strcmp(f[0], "guard") == 0) {
            if (nf != 2) { say(err, errcap, "строка %zu: guard ждёт одно слово", lineno); goto bad; }
            if (strcmp(f[1], "rst_alien") == 0) { p->guards |= 1u << 0; }
            else { say(err, errcap, "строка %zu: неизвестная защита \"%s\"", lineno, f[1]); goto bad; }
        } else {
            /* §2.5: неизвестная директива — отказ, а не пропуск. */
            say(err, errcap, "строка %zu: неизвестная директива \"%s\"", lineno, f[0]);
            goto bad;
        }
    }

    if (!seen_header) {
        say(err, errcap, "нет заголовка d2k-plan");
        goto bad;
    }
    if ((p->input_len || p->settle_us || p->segment_size) && p->minexec < 3) {
        say(err, errcap, "input/settle/segment требуют minexec=3"); goto bad;
    }
    if (p->wire_profile && (p->minexec < 4 || p->transport != 6)) {
        say(err, errcap, "wire detect-tcp-v1 требует minexec=4 и proto tcp"); goto bad;
    }
    return 0;
bad:
    plan_free(p);
    return -1;
}

/* --- сборка TLV ---------------------------------------------------------- */

typedef struct { uint8_t *b; size_t cap, pos; int bad; } wbuf;

static void put(wbuf *w, const uint8_t *b, size_t n) {
    if (w->bad || w->pos + n > w->cap) { w->bad = 1; return; }
    if (n) { memcpy(w->b + w->pos, b, n); }
    w->pos += n;
}
static void put_u8(wbuf *w, uint8_t v) { put(w, &v, 1); }
static void put_u16(wbuf *w, uint16_t v) { uint8_t t[2] = { (uint8_t)(v >> 8), (uint8_t)v }; put(w, t, 2); }
static void put_u32(wbuf *w, uint32_t v) {
    uint8_t t[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    put(w, t, sizeof t);
}
static void put_rec(wbuf *w, uint16_t typ, const uint8_t *v, size_t n) {
    if (n > 0xFFFFu) { w->bad = 1; return; }
    put_u16(w, typ);
    put_u16(w, (uint16_t)n);
    put(w, v, n);
}

int d2k_plan_text_to_tlv(const char *text, uint8_t *out, size_t cap,
                         size_t *out_len, char *err, size_t errcap) {
    if (err && errcap) { err[0] = '\0'; }
    if (!text || !out || !out_len) {
        say(err, errcap, "нечего переводить: пустые аргументы");
        return -1;
    }
    pl_plan p;
    if (parse_text(text, &p, err, errcap) != 0) { return -1; }

    /* Порядок записей — ДОСЛОВНО из MarshalTLV (internal/plan/tlv.go):
       ID, PROTO, приманки, порчи, разрезы, фальшивки, перекрытия, ORDER, и
       только при ненулевых защитах — GUARD. */
    wbuf w = { out, cap, 0, 0 };
    size_t n_records = 2 + p.n_payloads + p.n_poisons + p.n_splits +
                       p.n_fakes + p.n_seqovls + 1 + (p.pace_us ? 1u : 0u) +
                       (p.guards ? 1u : 0u) + (p.input_len ? 1u : 0u) + (p.settle_us ? 1u : 0u) +
                       (p.segment_size ? 1u : 0u) + (p.wire_profile ? 1u : 0u);
    if (n_records > 0xFFFFu) {
        plan_free(&p);
        say(err, errcap, "слишком много записей (%zu)", n_records);
        return -1;
    }

    const uint8_t magic[4] = { 'D', '2', 'K', 'P' };
    put(&w, magic, 4);
    put_u16(&w, p.schema);
    put_u16(&w, p.minexec);
    put_u16(&w, 0); /* флаги — обязаны быть 0 (datapath/plan_parse.c) */
    put_u16(&w, (uint16_t)n_records);

    put_rec(&w, REC_ID, p.id, sizeof p.id);
    uint8_t pr[2] = { p.transport, p.proto };
    put_rec(&w, REC_PROTO, pr, sizeof pr);

    for (size_t i = 0; i < p.n_payloads; i++) {
        /* Заголовок записи пишем сами: значение — номер плюс байты, и
           собирать под него временный буфер значило бы копировать приманку
           дважды (тот же довод, что у tlv_rec в compose.c). */
        if (p.payloads[i].len > 0xFFFFu - 2) { w.bad = 1; break; }
        put_u16(&w, REC_PAYLOAD);
        put_u16(&w, (uint16_t)(2 + p.payloads[i].len));
        put_u16(&w, p.payloads[i].id);
        put(&w, p.payloads[i].bytes, p.payloads[i].len);
    }
    for (size_t i = 0; i < p.n_poisons; i++) {
        uint8_t v[8];
        v[0] = (uint8_t)(p.poisons[i].id >> 8); v[1] = (uint8_t)p.poisons[i].id;
        v[2] = p.poisons[i].ttl;
        v[3] = p.poisons[i].flags;
        uint32_t ss = (uint32_t)p.poisons[i].seq_shift;
        v[4] = (uint8_t)(ss >> 24); v[5] = (uint8_t)(ss >> 16);
        v[6] = (uint8_t)(ss >> 8);  v[7] = (uint8_t)ss;
        put_rec(&w, REC_POISON, v, sizeof v);
    }
    for (size_t i = 0; i < p.n_splits; i++) {
        uint16_t off = (uint16_t)p.splits[i].offset;
        uint8_t v[4] = { (uint8_t)(p.splits[i].anchor >> 8), (uint8_t)p.splits[i].anchor,
                         (uint8_t)(off >> 8), (uint8_t)off };
        put_rec(&w, REC_SPLIT, v, sizeof v);
    }
    for (size_t i = 0; i < p.n_fakes; i++) {
        uint8_t v[10];
        v[0] = (uint8_t)(p.fakes[i].payload_id >> 8); v[1] = (uint8_t)p.fakes[i].payload_id;
        v[2] = (uint8_t)(p.fakes[i].poison_id >> 8);  v[3] = (uint8_t)p.fakes[i].poison_id;
        v[4] = p.fakes[i].repeats;
        v[5] = p.fakes[i].placement;
        v[6] = (uint8_t)(p.fakes[i].gap_us >> 24); v[7] = (uint8_t)(p.fakes[i].gap_us >> 16);
        v[8] = (uint8_t)(p.fakes[i].gap_us >> 8);  v[9] = (uint8_t)p.fakes[i].gap_us;
        put_rec(&w, REC_FAKE, v, sizeof v);
    }
    for (size_t i = 0; i < p.n_seqovls; i++) {
        uint8_t v[4] = { (uint8_t)(p.seqovls[i].payload_id >> 8), (uint8_t)p.seqovls[i].payload_id,
                         (uint8_t)(p.seqovls[i].poison_id >> 8),  (uint8_t)p.seqovls[i].poison_id };
        put_rec(&w, REC_SEQOVL, v, sizeof v);
    }
    /* БЕЗУСЛОВНО — см. шапку файла. */
    put_u8(&w, (uint8_t)(REC_ORDER >> 8)); put_u8(&w, (uint8_t)REC_ORDER);
    put_u16(&w, 1);
    put_u8(&w, p.order);
    /* PACE — ПОСЛЕ ORDER и ДО GUARD. Место в ряду не косметика: датапат
       читает записи подряд, и порядок обязан быть один и тот же у сборщика и
       у разбора (см. шапку файла). */
    if (p.pace_us) {
        uint8_t v[4] = { (uint8_t)(p.pace_us >> 24), (uint8_t)(p.pace_us >> 16),
                         (uint8_t)(p.pace_us >> 8),  (uint8_t)p.pace_us };
        put_rec(&w, REC_PACE, v, sizeof v);
    }
    if (p.input_len) {
        put_u16(&w, REC_INPUT); put_u16(&w, 12);
        put_u32(&w, p.input_len); put_u32(&w, p.input_sni_off); put_u32(&w, p.input_sni_len);
    }
    if (p.settle_us) {
        put_u16(&w, REC_SETTLE); put_u16(&w, 4); put_u32(&w, p.settle_us);
    }
    if (p.segment_size) {
        put_u16(&w, REC_SEGMENT); put_u16(&w, 4); put_u32(&w, p.segment_size);
    }
    if (p.wire_profile) { put_rec(&w, REC_WIRE, &p.wire_profile, 1); }
    if (p.guards) {
        put_rec(&w, REC_GUARD, &p.guards, 1);
    }

    plan_free(&p);
    if (w.bad) {
        say(err, errcap, "план не помещается в %zu байт", cap);
        return -1;
    }
    *out_len = w.pos;
    return 0;
}

int d2k_plan_text_to_hex(const char *text, char *out, size_t cap,
                         char *err, size_t errcap) {
    uint8_t raw[D2K_PLAN_TLV_MAX];
    size_t n = 0;
    if (d2k_plan_text_to_tlv(text, raw, sizeof raw, &n, err, errcap) != 0) { return -1; }
    if (cap < 2 * n + 1) {
        say(err, errcap, "на hex нужно %zu байт, дано %zu", 2 * n + 1, cap);
        return -1;
    }
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[raw[i] >> 4];
        out[2 * i + 1] = digits[raw[i] & 0x0F];
    }
    out[2 * n] = '\0';
    return 0;
}
