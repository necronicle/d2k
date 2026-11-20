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
#include "../datapath/include/d2k_capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "d2k_plantlv.h"
#include "../datapath/include/d2k_preflight_plan.h"

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
    REC_WIRE    = 0x0109,
    REC_INPUT_TLS = 0x010a,
    REC_DELAY   = 0x010b,
    REC_IPFRAG  = 0x010c,
    REC_OOB     = 0x010d,
    REC_UDPLEN  = 0x010e,
    REC_QSPLIT  = 0x010f,
    REC_QDENY   = 0x0110,
    REC_AUTOTTL = 0x0111,
    REC_STREAM_OFFSET = 0x0112,
    REC_AFTER_SPLIT = 0x0113,
    REC_PREFLIGHT = 0x0114,
    REC_PREFLIGHT_RESYN = 0x0115,
    REC_HANDOVER_APPLY = 0x0116
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
    int32_t  ack_shift;
    /* autottl=<delta>,<min>-<max> в строке порчи: TTL считает датапат по TTL
       ответной стороны потока (ip_autottl документации zapret2). */
    uint8_t  autottl;
    int8_t   autottl_delta;
    uint8_t  autottl_min;
    uint8_t  autottl_max;
} pl_poison;

typedef struct { uint16_t anchor; int16_t offset; } pl_split;
typedef struct {
    uint16_t payload_id, poison_id;
    uint8_t  repeats, placement;
    uint32_t gap_us;
    uint8_t  tls_mod;
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
    uint32_t   delay_us;
    uint8_t    wire_profile;
    uint8_t    input_tls;
    uint8_t    has_stream_offset;
    uint32_t   stream_offset;
    uint32_t   after_offset,after_length,after_cut;
    uint8_t preflight, pf_wscale, pf_pieces, pf_hello_own;
    uint16_t pf_window, pf_data;
    uint8_t pf_handover_apply;
    uint32_t pf_timeout_ms;
    uint32_t pf_resyn_timeout_ms;
    uint16_t pf_resyn_delay_ms;
    uint8_t pf_resyn_sends;
    char pf_name[254];
    uint8_t    ipfrag;
    uint8_t    oob_enabled;
    uint16_t   oob_anchor;
    uint8_t    oob_byte;
    uint16_t   udplen;    /* 0 — записи нет */
    uint8_t    qsplit;    /* 0 — записи нет; 1 — кадры CRYPTO, хвост первым */
    uint8_t    qdeny;     /* 0 — записи нет; 1 — QUIC для имени не пропускается */
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
        { "sld_middle", 6 },
    };
    for (size_t i = 0; i < sizeof a / sizeof a[0]; i++) {
        if (strcmp(a[i].n, s) == 0) { *out = a[i].v; return 0; }
    }
    return -1;
}

/* Режет строку на слова по пробелам. Возвращает число слов или -1, если слов
   больше cap: молча отбросить хвост значило бы исполнить не то, что записано. */
static int split_fields(char *line, char **f, size_t cap) {
    size_t n = 0;
    char *p = line;
    for (;;) {
        while (*p == ' ' || *p == '\t') { p++; }
        if (!*p) { break; }
        if (n >= cap) { return -1; }
        f[n++] = p;
        while (*p && *p != ' ' && *p != '\t') { p++; }
        if (*p) { *p++ = '\0'; }
    }
    return (int)n;
}

/* Строгое беззнаковое десятичное число: только цифры, без знака, пробела и
   хвоста, не больше max. Единственный путь числа из текста плана в поле. */
static int parse_uint(const char *s, unsigned long max, unsigned long *out) {
    if (!s || *s < '0' || *s > '9') { return -1; }
    char *end = NULL;
    errno = 0;
    unsigned long val = strtoul(s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\0' || val > max) { return -1; }
    *out = val;
    return 0;
}

/* Знаковое число с необязательным "+"/"-" в пределах [lo, hi]. */
static int parse_int(const char *s, long lo, long hi, long *out) {
    int neg = 0;
    unsigned long mag;
    if (s && (*s == '+' || *s == '-')) { neg = (*s == '-'); s++; }
    unsigned long lim = neg ? (unsigned long)(-(lo + 1)) + 1ul : (unsigned long)hi;
    if (parse_uint(s, lim, &mag) != 0) { return -1; }
    *out = neg ? (long)(0 - mag) : (long)mag;
    return 0;
}

/* Разбирает "ключ=значение" и сверяет ключ. */
static int kv_u32(const char *field, const char *key, unsigned long max, unsigned long *out) {
    size_t kl = strlen(key);
    if (strncmp(field, key, kl) != 0 || field[kl] != '=') { return -1; }
    return parse_uint(field + kl + 1, max, out);
}

/* Голое десятичное число (pace и др.). Отдельно от kv_u32: у pace значение
   идёт без ключа, и притворяться, что "ключ=значение" тут есть, значило бы
   принимать "pace pace=12000". */
static int str_u32(const char *sv, unsigned long *out) {
    return parse_uint(sv, UINT32_MAX, out);
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
        char line[2 * D2K_CAPTURE_BYTES + 32];
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

        char *f[12];
        int nfi = split_fields(t, f, 12);
        if (nfi < 0) { say(err, errcap, "строка %zu: слов больше 8", lineno); goto bad; }
        size_t nf = (size_t)nfi;
        if (nf == 0) { continue; }

        if (strcmp(f[0], "d2k-plan") == 0) {
            if (nf != 3) { say(err, errcap, "строка %zu: d2k-plan ждёт два числа", lineno); goto bad; }
            unsigned long sc, mx;
            if (parse_uint(f[1], 65535, &sc) || parse_uint(f[2], 65535, &mx)) {
                say(err, errcap, "строка %zu: d2k-plan ждёт два числа 0..65535", lineno); goto bad;
            }
            p->schema = (uint16_t)sc;
            p->minexec = (uint16_t)mx;
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
            /* Голос Дискорда: первый пакет потока — запрос IP Discovery. */
            else if (strcmp(f[2], "voice") == 0) { p->proto = 3; }
            /* Открытый HTTP (задача 51, шаг 4): вход — запрос, имя — Host. */
            else if (strcmp(f[2], "http") == 0) { p->proto = 4; }
            else { say(err, errcap, "строка %zu: неизвестный протокол \"%s\"", lineno, f[2]); goto bad; }
        } else if (strcmp(f[0], "payload") == 0) {
            if (nf < 2 || nf > 3) { say(err, errcap, "строка %zu: payload ждёт номер и байты", lineno); goto bad; }
            if (p->n_payloads >= MAX_PAYLOADS) { say(err, errcap, "строка %zu: приманок больше %d", lineno, MAX_PAYLOADS); goto bad; }
            pl_payload *v = &p->payloads[p->n_payloads];
            unsigned long pid;
            char why[80];
            if (parse_uint(f[1], 65535, &pid)) {
                say(err, errcap, "строка %zu: номер нагрузки вне 0..65535", lineno); goto bad;
            }
            v->id = (uint16_t)pid;
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
            if (nf != 2 || (strcmp(f[1], "detect-tcp-v1") && strcmp(f[1], "tcp-template-v1"))) {
                say(err, errcap, "неизвестный wire profile"); goto bad;
            }
            p->wire_profile = strcmp(f[1], "tcp-template-v1") == 0 ? 2 : 1;
            if (p->wire_profile == 2 && p->minexec < 8) {
                say(err, errcap, "tcp-template-v1 требует minexec=8"); goto bad;
            }
        } else if (strcmp(f[0], "after-split") == 0) {
            unsigned long offset,length,cut;
            if(nf!=4 || p->after_length || str_u32(f[1],&offset) ||
               str_u32(f[2],&length) || str_u32(f[3],&cut) || !offset ||
               offset>=0x80000000UL || length<2 || length>65535 ||
               length>=0x80000000UL-offset || !cut || cut>=length || cut>32767) {
                say(err,errcap,"after-split requires unique TCP offset, length and interior cut");goto bad;
            }
            p->after_offset=(uint32_t)offset;p->after_length=(uint32_t)length;p->after_cut=(uint32_t)cut;
        } else if (strcmp(f[0], "stream-offset") == 0) {
            unsigned long offset;
            if(nf!=2 || p->has_stream_offset || str_u32(f[1],&offset) || offset>=0x80000000UL) {
                say(err,errcap,"stream-offset requires one unambiguous TCP offset");goto bad;
            }
            p->has_stream_offset=1;p->stream_offset=(uint32_t)offset;
        } else if (strcmp(f[0], "input") == 0) {
            if (nf == 2 && strcmp(f[1], "tls-sni") == 0) {
                p->input_tls = 1;
                continue;
            }
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
            unsigned long pid;
            if (parse_uint(f[1], 65535, &pid)) {
                say(err, errcap, "строка %zu: номер порчи вне 0..65535", lineno); goto bad;
            }
            v->id = (uint16_t)pid;
            for (size_t i = 2; i < nf; i++) {
                unsigned long u;
                if (strcmp(f[i], "badsum") == 0) { v->flags |= 1u << 0; }
                else if (strcmp(f[i], "tcpts") == 0) { v->flags |= 1u << 1; }
                else if (strcmp(f[i], "ipidzero") == 0) { v->flags |= 1u << 2; }
                else if (strcmp(f[i], "md5") == 0) { v->flags |= 1u << 3; }
                else if (strcmp(f[i], "tsup") == 0) { v->flags |= 1u << 4; }
                else if (strcmp(f[i], "md5ts") == 0) { v->flags |= 1u << 5; }
                else if (strncmp(f[i], "autottl=", 8) == 0) {
                    /* Формат документации: delta,min-max. Дельта со знаком. */
                    int d = 0; unsigned lo = 0, hi = 0;
                    if (sscanf(f[i] + 8, "%d,%u-%u", &d, &lo, &hi) != 3 ||
                        d < -128 || d > 127 || lo > 255 || hi > 255 ||
                        (hi && lo > hi)) {
                        say(err, errcap, "строка %zu: autottl ждёт delta,min-max \"%s\"",
                            lineno, f[i]);
                        goto bad;
                    }
                    v->autottl = 1;
                    v->autottl_delta = (int8_t)d;
                    v->autottl_min = (uint8_t)lo;
                    v->autottl_max = (uint8_t)hi;
                }
                else if (strncmp(f[i], "ttl=", 4) == 0) {
                    if (kv_u32(f[i], "ttl", 255, &u) != 0) {
                        say(err, errcap, "строка %zu: ttl вне 0..255 \"%s\"", lineno, f[i]); goto bad;
                    }
                    v->ttl = (uint8_t)u;
                } else if (strncmp(f[i], "ackshift=", 9) == 0) {
                    long sh;
                    if (parse_int(f[i]+9, INT32_MIN, INT32_MAX, &sh) != 0) {
                        say(err, errcap, "ackshift outside int32"); goto bad;
                    }
                    v->ack_shift = (int32_t)sh;
                } else if (strncmp(f[i], "seqshift=", 9) == 0) {
                    long sh;
                    if (parse_int(f[i] + 9, INT32_MIN, INT32_MAX, &sh) != 0) {
                        say(err, errcap, "строка %zu: seqshift вне int32 \"%s\"", lineno, f[i]); goto bad;
                    }
                    v->seq_shift = (int32_t)sh;
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
            long off;
            if (parse_int(f[2], INT16_MIN, INT16_MAX, &off) != 0) {
                say(err, errcap, "строка %zu: смещение split вне int16 \"%s\"", lineno, f[2]); goto bad;
            }
            v->offset = (int16_t)off;
            p->n_splits++;
        } else if (strcmp(f[0], "oob") == 0) {
            uint16_t anchor = 0;
            uint8_t *byte = NULL;
            size_t byte_len = 0;
            char why[96];
            if (nf != 3 || p->oob_enabled || anchor_by_name(f[1], &anchor) != 0 ||
                parse_hex(f[2], &byte, &byte_len, why, sizeof why) != 0 || byte_len != 1) {
                free(byte);
                say(err, errcap, "строка %zu: oob ждёт один якорь и ровно один байт hex", lineno);
                goto bad;
            }
            p->oob_enabled = 1;
            p->oob_anchor = anchor;
            p->oob_byte = byte[0];
            free(byte);
        } else if (strcmp(f[0], "fake") == 0) {
            if (nf != 6 && nf != 7) { say(err, errcap, "строка %zu: fake ждёт параметры и необязательный tlsmod=", lineno); goto bad; }
            if (p->n_fakes >= MAX_FAKES) { say(err, errcap, "строка %zu: фальшивок больше %d", lineno, MAX_FAKES); goto bad; }
            pl_fake *v = &p->fakes[p->n_fakes];
            memset(v, 0, sizeof *v);
            unsigned long u;
            if (kv_u32(f[1], "payload", 65535, &u) != 0) { say(err, errcap, "строка %zu: fake без payload=", lineno); goto bad; }
            v->payload_id = (uint16_t)u;
            if (kv_u32(f[2], "poison", 65535, &u) != 0) { say(err, errcap, "строка %zu: fake без poison=", lineno); goto bad; }
            v->poison_id = (uint16_t)u;
            if (kv_u32(f[3], "repeats", 255, &u) != 0) { say(err, errcap, "строка %zu: fake без repeats=", lineno); goto bad; }
            v->repeats = (uint8_t)u;
            if (kv_u32(f[4], "gap_us", UINT32_MAX, &u) != 0) { say(err, errcap, "строка %zu: fake без gap_us=", lineno); goto bad; }
            v->gap_us = (uint32_t)u;
            if (strcmp(f[5], "place=before") == 0) { v->placement = 0; }
            else if (strcmp(f[5], "place=between") == 0) { v->placement = 1; }
            else { say(err, errcap, "строка %zu: неизвестное место \"%s\"", lineno, f[5]); goto bad; }
            if (nf == 7) {
                if (strcmp(f[6], "tlsmod=rnd,dupsid") == 0) { v->tls_mod = 3; }
                else if (strcmp(f[6], "tlsmod=rnd") == 0) { v->tls_mod = 1; }
                else if (strcmp(f[6], "tlsmod=dupsid") == 0) { v->tls_mod = 2; }
                else { say(err, errcap, "строка %zu: неизвестный tlsmod \"%s\"", lineno, f[6]); goto bad; }
                if (p->minexec < 8) { say(err, errcap, "строка %zu: tlsmod требует minexec=8", lineno); goto bad; }
            }
            p->n_fakes++;
        } else if (strcmp(f[0], "seqovl") == 0) {
            if (nf != 3) { say(err, errcap, "строка %zu: seqovl ждёт payload= и poison=", lineno); goto bad; }
            if (p->n_seqovls >= MAX_SEQOVLS) { say(err, errcap, "строка %zu: перекрытий больше %d", lineno, MAX_SEQOVLS); goto bad; }
            pl_seqovl *v = &p->seqovls[p->n_seqovls];
            unsigned long u;
            if (kv_u32(f[1], "payload", 65535, &u) != 0) { say(err, errcap, "строка %zu: seqovl без payload=", lineno); goto bad; }
            v->payload_id = (uint16_t)u;
            if (kv_u32(f[2], "poison", 65535, &u) != 0) { say(err, errcap, "строка %zu: seqovl без poison=", lineno); goto bad; }
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
        } else if (strcmp(f[0], "ipfrag") == 0) {
            unsigned long u=0;
            if (nf != 2 || p->ipfrag || str_u32(f[1], &u) != 0 || u<1 || u>4) {
                say(err,errcap,"ipfrag ждёт одну форму 1..4"); goto bad;
            }
            p->ipfrag=(uint8_t)u;
        } else if (strcmp(f[0], "udplen") == 0) {
            /* УДЛИНИТЬ ДАТАГРАММУ на N нулевых байт — zapret udplen
               increment=N (донор compose: increment=100). Только рост:
               сокращение донор не ставит никогда. Ноль запрещён по той же
               причине, что у pace. */
            unsigned long u = 0;
            if (nf != 2 || p->udplen || parse_uint(f[1], 65535, &u) != 0 || u == 0) {
                say(err, errcap, "строка %zu: udplen ждёт одно число 1..65535", lineno); goto bad;
            }
            p->udplen = (uint16_t)u;
        } else if (strcmp(f[0], "quicsplit") == 0) {
            /* РАЗРЕЗ CLIENTHELLO НА КАДРЫ CRYPTO внутри того же Initial
               (задача 40, d2k_quic_initial_split_crypto). Форма одна: 1 —
               два кадра, хвост первым; другие формы не мерились. */
            unsigned long u = 0;
            if (nf != 2 || p->qsplit || parse_uint(f[1], 1, &u) != 0 || u != 1) {
                say(err, errcap, "строка %zu: quicsplit ждёт форму 1", lineno); goto bad;
            }
            p->qsplit = (uint8_t)u;
        } else if (strcmp(f[0], "quicdeny") == 0) {
            /* QUIC ДЛЯ ИМЕНИ НЕ ПРОПУСКАЕТСЯ (задача 50, раунд 2): не
               воздействие — датаграммы клиента снимаются, клиент уходит на
               TCP. Форма одна. */
            unsigned long u = 0;
            if (nf != 2 || p->qdeny || parse_uint(f[1], 1, &u) != 0 || u != 1) {
                say(err, errcap, "строка %zu: quicdeny ждёт форму 1", lineno); goto bad;
            }
            p->qdeny = (uint8_t)u;
        } else if (strcmp(f[0], "delay") == 0) {
            /* ВЫДЕРЖКА ПЕРЕД ПЕРВОЙ ПОСЫЛКОЙ НАГРУЗКИ, микросекунды. Ни pace,
               ни settle её не выражают: первый задерживает посылки ПОСЛЕ
               первой, второй — первую, но лишь когда перед ней уже что-то
               ушло. Ноль запрещён по той же причине, что у pace. */
            if (nf != 2) { say(err, errcap, "строка %zu: delay ждёт одно число", lineno); goto bad; }
            {
                unsigned long u = 0;
                if (str_u32(f[1], &u) != 0 || u == 0) {
                    say(err, errcap, "строка %zu: delay ждёт положительное число микросекунд", lineno);
                    goto bad;
                }
                p->delay_us = (uint32_t)u;
            }
        } else if (strcmp(f[0], "handover") == 0) {
            if(nf!=2 || strcmp(f[1],"apply") || p->pf_handover_apply) {
                say(err,errcap,"handover expects one apply directive");goto bad;
            }
            p->pf_handover_apply=1;
        } else if (strcmp(f[0], "preflight") == 0) {
            unsigned seen=0;
            if(p->preflight) {say(err,errcap,"duplicate preflight");goto bad;}
            p->preflight=1;
            for(size_t i=1;i<nf;i++) {
                char *eq=strchr(f[i],'='); unsigned bit=0; unsigned long u=0;
                if(!eq) {say(err,errcap,"preflight expects key=value");goto bad;}
                *eq++=0;
                if(!strcmp(f[i],"window")) {
                    bit=1;if(parse_uint(eq,65535,&u)||!u)goto pf_bad;p->pf_window=(uint16_t)u;
                } else if(!strcmp(f[i],"wscale")) {
                    bit=2;if(parse_uint(eq,14,&u))goto pf_bad;p->pf_wscale=(uint8_t)u;
                } else if(!strcmp(f[i],"pieces")) {
                    bit=4;if(parse_uint(eq,255,&u)||!u)goto pf_bad;p->pf_pieces=(uint8_t)u;
                } else if(!strcmp(f[i],"hello")) {
                    bit=8;if(strcmp(eq,"own") && strcmp(eq,"white"))goto pf_bad;
                    p->pf_hello_own=!strcmp(eq,"own");
                } else if(!strcmp(f[i],"timeout")) {
                    bit=16;if(parse_uint(eq,D2K_PF_EXEC_MAX_TIMEOUT_MS,&u)||u<1000)goto pf_bad;p->pf_timeout_ms=(uint32_t)u;
                } else if(!strcmp(f[i],"data")) {
                    bit=64;if(parse_uint(eq,65535,&u)||!u)goto pf_bad;p->pf_data=(uint16_t)u;
                } else if(!strcmp(f[i],"resyn_delay")) {
                    bit=128;if(parse_uint(eq,4999,&u)||!u)goto pf_bad;p->pf_resyn_delay_ms=(uint16_t)u;
                } else if(!strcmp(f[i],"resyn_timeout")) {
                    bit=512;if(parse_uint(eq,D2K_PF_EXEC_MAX_TIMEOUT_MS,&u)||!u)goto pf_bad;p->pf_resyn_timeout_ms=(uint32_t)u;
                } else if(!strcmp(f[i],"resyn_sends")) {
                    bit=256;if(parse_uint(eq,255,&u)||!u)goto pf_bad;p->pf_resyn_sends=(uint8_t)u;
                } else if(!strcmp(f[i],"name")) {
                    bit=32;size_t len=strlen(eq);
                    if(!len || len>=sizeof p->pf_name)goto pf_bad;
                    if(!d2k_pf_name_valid((const uint8_t *)eq,len))goto pf_bad;
                    memcpy(p->pf_name,eq,len+1);
                } else goto pf_bad;
                if(seen&bit)goto pf_bad;
                seen|=bit;continue;
            pf_bad:
                say(err,errcap,"invalid or duplicate preflight parameter");goto bad;
            }
            if((seen&127u)!=(p->pf_hello_own?95u:127u) ||
               ((seen&896u) && ((seen&896u)!=896u || p->minexec<19 ||
                 p->pf_resyn_timeout_ms>=p->pf_timeout_ms ||
                 p->pf_resyn_timeout_ms<(uint64_t)p->pf_resyn_delay_ms*p->pf_resyn_sends)) ||
               (p->minexec<19 && p->pf_timeout_ms>5000)) {
                say(err,errcap,"preflight needs window/wscale/pieces/hello/timeout/data and name only for white");goto bad;
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
    if(p->pf_handover_apply && (!p->preflight || p->minexec<20)) {
        say(err,errcap,"handover apply requires preflight and minexec=20");goto bad;
    }
    if(p->preflight && (p->minexec<18 || p->transport!=6 || p->proto!=1)) {
        say(err,errcap,"preflight requires TCP/TLS and minexec=18");goto bad;
    }
    if(p->preflight && !p->pf_handover_apply && (
       p->n_payloads!=1 || p->n_poisons || p->n_splits || p->n_fakes || p->n_seqovls ||
       p->order || p->guards || p->pace_us || p->input_len || p->settle_us || p->segment_size ||
       p->wire_profile || p->input_tls || p->has_stream_offset || p->after_length ||
       p->delay_us || p->ipfrag || p->oob_enabled || p->udplen || p->qsplit || p->qdeny)) {
        say(err,errcap,"preflight requires minexec=18 and a standalone TCP/TLS plan");goto bad;
    }
    if(p->preflight) {
        const pl_payload *hello=NULL;
        for(size_t i=0;i<p->n_payloads;i++)if(p->payloads[i].id==p->pf_data)hello=&p->payloads[i];
        if(!hello || !hello->len || hello->len>D2K_CAPTURE_BYTES) {
            say(err,errcap,"preflight needs its referenced hello payload, 1..4096 bytes");goto bad;
        }
    }
    for (size_t i=0; i<p->n_poisons; i++) {
        if (p->poisons[i].ack_shift && (p->minexec<14 || p->transport!=6)) {
            say(err,errcap,"ackshift requires minexec=14 and TCP"); goto bad;
        }
    }
    if(p->has_stream_offset && (p->minexec<16 || p->transport!=6)) {
        say(err,errcap,"stream-offset requires TCP and minexec=16");goto bad;
    }
    if(p->after_length && (p->minexec<17 || p->transport!=6 || p->proto!=1 ||
       p->has_stream_offset || !p->input_len || p->input_len>p->after_offset ||
       (p->wire_profile!=1 && p->wire_profile!=2))) {
        say(err,errcap,"after-split requires minexec=17, exact first input and a TCP wire profile");goto bad;
    }
    if (p->input_tls && (p->minexec < 5 || p->transport != 6)) {
        say(err, errcap, "input tls-sni требует TCP и minexec=5"); goto bad;
    }
    if (p->oob_enabled && (p->minexec < 8 || p->transport != 6 || p->proto != 1 ||
        !p->input_tls || !p->wire_profile || p->n_splits || p->n_seqovls || p->n_fakes ||
        p->ipfrag || p->pace_us || p->settle_us || p->delay_us)) {
        say(err, errcap, "oob требует minexec=8, измеренный TCP/TLS-вход и отдельный план"); goto bad;
    }
    if ((p->input_len || p->settle_us || p->segment_size) && p->minexec < 3) {
        say(err, errcap, "input/settle/segment требуют minexec=3"); goto bad;
    }
    if (p->delay_us && p->minexec < 6) {
        say(err, errcap, "выдержка перед посылкой требует minexec=6"); goto bad;
    }
    if (p->ipfrag && (p->minexec<7 || p->transport!=17 || p->n_splits ||
        p->n_seqovls || p->order || p->input_len || p->input_tls ||
        p->settle_us || p->segment_size || p->wire_profile || p->guards)) {
        say(err,errcap,"ipfrag требует minexec=7 и UDP без TCP-операций"); goto bad;
    }
    if (p->udplen && (p->minexec < 9 || p->transport != 17 || p->ipfrag ||
        p->n_splits || p->n_seqovls || p->order || p->input_len || p->input_tls ||
        p->settle_us || p->segment_size || p->wire_profile || p->guards || p->oob_enabled)) {
        say(err, errcap, "udplen требует minexec=9 и UDP без фрагментации и TCP-операций"); goto bad;
    }
    if (p->qsplit && (p->minexec < 10 || p->transport != 17 || p->ipfrag || p->udplen ||
        p->n_splits || p->n_seqovls || p->order || p->input_len || p->input_tls ||
        p->settle_us || p->segment_size || p->wire_profile || p->guards || p->oob_enabled)) {
        say(err, errcap, "quicsplit требует minexec=10 и UDP без фрагментации, удлинения и TCP-операций"); goto bad;
    }
    if (p->qdeny && (p->minexec < 11 || p->transport != 17 || p->ipfrag || p->udplen ||
        p->qsplit || p->n_payloads || p->n_poisons || p->n_splits || p->n_fakes ||
        p->n_seqovls || p->order || p->input_len || p->input_tls || p->settle_us ||
        p->segment_size || p->wire_profile || p->guards || p->oob_enabled || p->pace_us ||
        p->delay_us)) {
        say(err, errcap, "quicdeny требует minexec=11, UDP и план без воздействий"); goto bad;
    }
    for (size_t i = 0; i < p->n_poisons; i++) {
        if ((p->poisons[i].flags & (1u << 3)) &&
            (p->minexec < 12 || p->transport != 6 || p->wire_profile != 1)) {
            say(err, errcap, "md5 требует minexec=12 и wire detect-tcp-v1 TCP"); goto bad;
        }
        if ((p->poisons[i].flags & (1u << 5)) &&
            (p->minexec < 15 || p->transport != 6 || p->wire_profile != 1)) {
            say(err, errcap, "md5ts требует minexec=15 и wire detect-tcp-v1 TCP"); goto bad;
        }
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

int d2k_plan_text_requires_endpoint(const char *text, char *err, size_t cap) {
    pl_plan p;
    if(!text || parse_text(text,&p,err,cap))return -1;
    int required=p.preflight;plan_free(&p);return required;
}
int d2k_plan_text_compose_preflight(const char *preflight,const char *outgoing,
    char **out,char *err,size_t errcap) {
    if(out)*out=NULL;
    if(!out || !preflight || !outgoing) {say(err,errcap,"missing composition input");return -1;}
    pl_plan pf={0},tx={0};char *joined=NULL;
    if(parse_text(preflight,&pf,err,errcap) || parse_text(outgoing,&tx,err,errcap))goto bad;
    if(!pf.preflight || pf.pf_handover_apply || tx.preflight || tx.transport!=6 || tx.proto!=1) {
        say(err,errcap,"composition requires standalone preflight and ordinary TCP/TLS program");goto bad;
    }
    const pl_payload *hello=NULL;
    for(size_t i=0;i<pf.n_payloads;i++)if(pf.payloads[i].id==pf.pf_data)hello=&pf.payloads[i];
    if(!hello || tx.n_payloads==MAX_PAYLOADS) {say(err,errcap,"no room for preflight hello payload");goto bad;}
    unsigned id;
    for(id=1;id<=MAX_PAYLOADS+1;id++) {
        size_t i;for(i=0;i<tx.n_payloads;i++)if(tx.payloads[i].id==id)break;
        if(i==tx.n_payloads)break;
    }
    size_t base_len=strlen(outgoing),extra=2*hello->len+sizeof pf.pf_name+512;
    if(base_len>SIZE_MAX-extra) {say(err,errcap,"composition too large");goto bad;}
    size_t size=base_len+extra,pos=0;
    joined=malloc(size);
    if(!joined) {say(err,errcap,"composition allocation failed");goto bad;}
    unsigned version=tx.minexec>20?tx.minexec:20;
    if(pf.minexec>version)version=pf.minexec;
    pos=(size_t)snprintf(joined,size,"d2k-plan 1 %u\nid 00000000000000000000000000000000\nproto tcp tls\n",version);
    for(const char *cur=outgoing;*cur;) {
        const char *end=strchr(cur,'\n');if(!end)end=cur+strlen(cur);
        const char *s=cur;while(s<end && isspace((unsigned char)*s))s++;
        size_t len=(size_t)(end-s);
        int header=(len>=8 && !memcmp(s,"d2k-plan",8) && (len==8 || isspace((unsigned char)s[8]))) ||
            (len>=5 && !memcmp(s,"proto",5) && (len==5 || isspace((unsigned char)s[5]))) ||
            (len>=2 && !memcmp(s,"id",2) && (len==2 || isspace((unsigned char)s[2])));
        if(!header) {size_t n=(size_t)(end-cur);memcpy(joined+pos,cur,n);pos+=n;joined[pos++]='\n';}
        cur=*end?end+1:end;
    }
    pos+=(size_t)snprintf(joined+pos,size-pos,
        "handover apply\npreflight window=%u wscale=%u pieces=%u hello=%s%s%s timeout=%u data=%u",
        pf.pf_window,pf.pf_wscale,pf.pf_pieces,pf.pf_hello_own?"own":"white",
        pf.pf_hello_own?"":" name=",pf.pf_hello_own?"":pf.pf_name,pf.pf_timeout_ms,id);
    if(pf.pf_resyn_delay_ms)pos+=(size_t)snprintf(joined+pos,size-pos,
        " resyn_delay=%u resyn_sends=%u resyn_timeout=%u",pf.pf_resyn_delay_ms,pf.pf_resyn_sends,pf.pf_resyn_timeout_ms);
    pos+=(size_t)snprintf(joined+pos,size-pos,"\npayload %u ",id);
    static const char digits[]="0123456789abcdef";
    for(size_t i=0;i<hello->len;i++) {joined[pos++]=digits[hello->bytes[i]>>4];joined[pos++]=digits[hello->bytes[i]&15];}
    joined[pos++]='\n';joined[pos]=0;
    pl_plan check;
    if(parse_text(joined,&check,err,errcap))goto bad;
    plan_free(&check);plan_free(&pf);plan_free(&tx);*out=joined;return 0;
bad:
    free(joined);plan_free(&pf);plan_free(&tx);return -1;
}
int d2k_plan_text_stream_offset(const char *text,uint32_t *offset,char *err,size_t cap) {
    if(offset)*offset=0;
    if(!text || !offset){say(err,cap,"missing plan or offset output");return -1;}
    pl_plan p;
    if(parse_text(text,&p,err,cap))return -1;
    int scoped=p.has_stream_offset;*offset=p.stream_offset;plan_free(&p);return scoped;
}
int d2k_plan_text_after_split(const char *text,uint32_t *offset,uint32_t *length,
    uint32_t *cut,char *err,size_t cap) {
    if(!text || !offset || !length || !cut){say(err,cap,"missing composed plan output");return -1;}
    *offset=*length=*cut=0;
    pl_plan p;
    if(parse_text(text,&p,err,cap))return -1;
    *offset=p.after_offset;*length=p.after_length;*cut=p.after_cut;
    int found=p.after_length!=0;plan_free(&p);return found;
}
int d2k_plan_text_compose_after_split(const char *text,uint32_t first_length,
    uint32_t sni_offset,uint32_t sni_length,
    uint32_t offset,uint32_t length,uint32_t cut,char **out,char *err,size_t cap) {
    if(out)*out=NULL;
    if(!text || !out || !first_length || sni_offset>first_length ||
       sni_length>first_length-sni_offset || strncmp(text,"d2k-plan 1 ",11)) {
        say(err,cap,"missing canonical first-input plan");return -1;
    }
    const char *body=strchr(text,'\n');
    if(!body || strstr(body,"\nd2k-plan ")) {
        say(err,cap,"ambiguous first-input plan header");return -1;
    }
    pl_plan p;
    if(parse_text(text,&p,err,cap))return -1;
    int compatible=p.schema==1 && p.minexec<=17 && p.transport==6 && p.proto==1 &&
        (p.wire_profile==1 || p.wire_profile==2) && !p.has_stream_offset && !p.after_length &&
        (!p.input_len || (p.input_len==first_length && p.input_sni_len==sni_length &&
                         (!sni_length || p.input_sni_off==sni_offset)));
    int add_input=!p.input_len;
    plan_free(&p);
    if(!compatible) {say(err,cap,"first-input plan cannot be composed without changing its contract");return -1;}
    size_t old_length=strlen(body);
    if(old_length>SIZE_MAX-192) {say(err,cap,"composed plan too large");return -1;}
    size_t size=old_length+192;
    char *program=malloc(size);
    if(!program) {say(err,cap,"cannot allocate composed plan");return -1;}
    char input[64]={0};
    if(add_input)snprintf(input,sizeof input,"input %u %u %u\n",first_length,sni_offset,sni_length);
    int n=snprintf(program,size,"d2k-plan 1 17%s%s%safter-split %u %u %u\n",
        body,old_length && body[old_length-1]=='\n'?"":"\n",input,offset,length,cut);
    uint8_t *tlv=malloc(D2K_PLAN_TLV_MAX);size_t written=0;
    int valid=n>0 && (size_t)n<size && tlv &&
        !d2k_plan_text_to_tlv(program,tlv,D2K_PLAN_TLV_MAX,&written,err,cap);
    if(!tlv)say(err,cap,"cannot validate composed plan");
    free(tlv);
    if(!valid){free(program);return -1;}
    *out=program;return 0;
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
    /* У каждой порчи с autottl есть своя запись REC_AUTOTTL — считаем их. */
    size_t n_autottl = 0;
    for (size_t i = 0; i < p.n_poisons; i++) { n_autottl += p.poisons[i].autottl ? 1u : 0u; }
    size_t n_records = 2 + n_autottl + p.n_payloads + p.n_poisons + p.n_splits +
                       p.n_fakes + p.n_seqovls + 1 + (p.pace_us ? 1u : 0u) +
                       (p.guards ? 1u : 0u) + (p.input_len ? 1u : 0u) + (p.settle_us ? 1u : 0u) +
                       (p.segment_size ? 1u : 0u) + (p.wire_profile ? 1u : 0u) +
                       (p.input_tls ? 1u : 0u) + (p.has_stream_offset ? 1u : 0u) + (p.after_length ? 1u : 0u) + (p.delay_us ? 1u : 0u) +
                       (p.ipfrag ? 1u : 0u) + (p.oob_enabled ? 1u : 0u) +
                       (p.udplen ? 1u : 0u) + (p.qsplit ? 1u : 0u) + (p.qdeny ? 1u : 0u) + (p.preflight ? 1u : 0u) + (p.pf_resyn_delay_ms ? 1u : 0u) + (p.pf_handover_apply ? 1u : 0u);
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
        uint8_t v[12];
        v[0] = (uint8_t)(p.poisons[i].id >> 8); v[1] = (uint8_t)p.poisons[i].id;
        v[2] = p.poisons[i].ttl;
        v[3] = p.poisons[i].flags;
        uint32_t ss = (uint32_t)p.poisons[i].seq_shift;
        v[4] = (uint8_t)(ss >> 24); v[5] = (uint8_t)(ss >> 16);
        v[6] = (uint8_t)(ss >> 8);  v[7] = (uint8_t)ss;
        uint32_t as = (uint32_t)p.poisons[i].ack_shift;
        v[8]=(uint8_t)(as>>24); v[9]=(uint8_t)(as>>16);
        v[10]=(uint8_t)(as>>8); v[11]=(uint8_t)as;
        put_rec(&w, REC_POISON, v, as ? 12 : 8);
        /* Своей записью СРАЗУ ЗА порчей, на которую ссылается: разбор ищет
           порчу по id и висячую ссылку отвергает. */
        if (p.poisons[i].autottl) {
            uint8_t a[5] = { v[0], v[1], (uint8_t)p.poisons[i].autottl_delta,
                             p.poisons[i].autottl_min, p.poisons[i].autottl_max };
            put_rec(&w, REC_AUTOTTL, a, sizeof a);
        }
    }
    for (size_t i = 0; i < p.n_splits; i++) {
        uint16_t off = (uint16_t)p.splits[i].offset;
        uint8_t v[4] = { (uint8_t)(p.splits[i].anchor >> 8), (uint8_t)p.splits[i].anchor,
                         (uint8_t)(off >> 8), (uint8_t)off };
        put_rec(&w, REC_SPLIT, v, sizeof v);
    }
    for (size_t i = 0; i < p.n_fakes; i++) {
        uint8_t v[11];
        v[0] = (uint8_t)(p.fakes[i].payload_id >> 8); v[1] = (uint8_t)p.fakes[i].payload_id;
        v[2] = (uint8_t)(p.fakes[i].poison_id >> 8);  v[3] = (uint8_t)p.fakes[i].poison_id;
        v[4] = p.fakes[i].repeats;
        v[5] = p.fakes[i].placement;
        v[6] = (uint8_t)(p.fakes[i].gap_us >> 24); v[7] = (uint8_t)(p.fakes[i].gap_us >> 16);
        v[8] = (uint8_t)(p.fakes[i].gap_us >> 8);  v[9] = (uint8_t)p.fakes[i].gap_us;
        v[10] = p.fakes[i].tls_mod;
        put_rec(&w, REC_FAKE, v, p.fakes[i].tls_mod ? sizeof v : sizeof v - 1);
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
    if (p.input_tls) { put_u16(&w, REC_INPUT_TLS); put_u16(&w, 0); }
    if(p.has_stream_offset) {put_u16(&w,REC_STREAM_OFFSET);put_u16(&w,4);put_u32(&w,p.stream_offset);}
    if(p.after_length) {put_u16(&w,REC_AFTER_SPLIT);put_u16(&w,12);put_u32(&w,p.after_offset);put_u32(&w,p.after_length);put_u32(&w,p.after_cut);}
    if (p.delay_us) {
        put_u16(&w, REC_DELAY); put_u16(&w, 4); put_u32(&w, p.delay_us);
    }
    if (p.wire_profile) { put_rec(&w, REC_WIRE, &p.wire_profile, 1); }
    if (p.ipfrag) { put_rec(&w, REC_IPFRAG, &p.ipfrag, 1); }
    if (p.pf_handover_apply) { put_rec(&w, REC_HANDOVER_APPLY, &p.pf_handover_apply, 1); }
    if (p.udplen) { put_u16(&w, REC_UDPLEN); put_u16(&w, 2); put_u16(&w, p.udplen); }
    if (p.qsplit) { put_rec(&w, REC_QSPLIT, &p.qsplit, 1); }
    if (p.qdeny) { put_rec(&w, REC_QDENY, &p.qdeny, 1); }
    if(p.preflight) {
        /* W:u16, S:u8, K:u8, own:u8, timeout:u32, payload id:u16, white name bytes (no NUL). */
        size_t name_len=strlen(p.pf_name);
        put_u16(&w,REC_PREFLIGHT);put_u16(&w,(uint16_t)(11+name_len));
        put_u16(&w,p.pf_window);put_u8(&w,p.pf_wscale);put_u8(&w,p.pf_pieces);
        put_u8(&w,p.pf_hello_own);put_u32(&w,p.pf_timeout_ms);put_u16(&w,p.pf_data);
        put(&w,(const uint8_t *)p.pf_name,name_len);
    }
    if(p.pf_resyn_delay_ms) {
        put_u16(&w,REC_PREFLIGHT_RESYN);put_u16(&w,7);
        put_u16(&w,p.pf_resyn_delay_ms);put_u8(&w,p.pf_resyn_sends);
        put_u32(&w,p.pf_resyn_timeout_ms);
    }
    if (p.oob_enabled) {
        uint8_t v[3] = { (uint8_t)(p.oob_anchor >> 8), (uint8_t)p.oob_anchor, p.oob_byte };
        put_rec(&w, REC_OOB, v, sizeof v);
    }
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
