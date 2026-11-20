#define _POSIX_C_SOURCE 200809L
#include "d2km_store.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

size_t d2km_application_proof(char *out,size_t cap,const d2km_context *c,uint64_t hash,const char *contract) {
    if(!out || !cap || !c || !c->target.has_name || !contract)return 0;
    int n=snprintf(out,cap,"application-v1 target=%s family=%u protocol=%u ech=%u hash=%llu %s",
        c->target.name,(unsigned)c->family,(unsigned)c->protocol,(unsigned)c->form.ech,
        (unsigned long long)hash,contract);
    return n>0 && (size_t)n<cap?(size_t)n:0;
}

/* Явные поля и числа фиксированной разрядности: файл переносим между
 * 32/64 бит, little/big endian и не содержит padding структур C.
 * Строка: тип + десятичные числа + hex байтов/UTF-8 ('-' — пусто).
 * end содержит FNV всего тела: обрезка и битая строка отвергают ВСЁ.
 * FNV здесь — контроль повреждения, не криптографическая подпись. */
#define STORE_LINE_MAX (D2KM_KNOWLEDGE_WHY_MAX * 2 + 4096)
typedef struct {
    int reading, fd;
    FILE *file;
    char line[STORE_LINE_MAX];
    size_t length, position, lineno;
    uint64_t hash;
    d2km_store_code code;
} codec;

static void bad(codec *c, d2km_store_code code)
{
    if (c->code == D2KM_STORE_OK) c->code = code;
}
static void hash_line(codec *c)
{
    for (size_t i = 0; i < c->length; i++) {
        c->hash ^= (uint8_t)c->line[i]; c->hash *= UINT64_C(1099511628211);
    }
}
static int write_all(int fd, const char *b, size_t n)
{
    while (n) {
        ssize_t r = write(fd, b, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { if (!r) errno = EIO; return -1; }
        b += r; n -= (size_t)r;
    }
    return 0;
}
static void append(codec *c, const char *b, size_t n)
{
    if (c->code) return;
    if (n >= sizeof(c->line) - c->length) { bad(c, D2KM_STORE_NO_RESOURCES); return; }
    memcpy(c->line + c->length, b, n); c->length += n; c->line[c->length] = 0;
}
static void begin(codec *c, const char *tag)
{
    if (c->code) return;
    c->position = 0; c->length = 0; c->lineno++;
    if (c->reading) {
        /* fgets/strlen alone would silently accept an embedded NUL. */
        int ch;
        while ((ch = fgetc(c->file)) != EOF && ch != '\n') {
            if (ch == 0 || c->length + 2 >= sizeof(c->line)) { bad(c, D2KM_STORE_INVALID); return; }
            c->line[c->length++] = (char)ch;
        }
        if (ch != '\n') { bad(c, ferror(c->file) ? D2KM_STORE_IO : D2KM_STORE_INVALID); return; }
        c->line[c->length++] = '\n'; c->line[c->length] = 0;
        size_t n = strlen(tag);
        if (c->length <= n || memcmp(c->line, tag, n) ||
            (c->line[n] != ' ' && c->line[n] != '\n')) { bad(c, D2KM_STORE_INVALID); return; }
        c->position = n;
    } else append(c, tag, strlen(tag));
}
static void end(codec *c, int hashed)
{
    if (c->code) return;
    if (c->reading) {
        if (c->position + 1 != c->length || c->line[c->position] != '\n') bad(c, D2KM_STORE_INVALID);
    } else {
        append(c, "\n", 1);
        if (!c->code && write_all(c->fd, c->line, c->length)) bad(c, D2KM_STORE_IO);
    }
    if (!c->code && hashed) hash_line(c);
}
static const char *token(codec *c, size_t *n)
{
    *n = 0;
    if (c->code) return "";
    if (c->line[c->position] != ' ') { bad(c, D2KM_STORE_INVALID); return ""; }
    size_t start = ++c->position;
    while (c->position < c->length && c->line[c->position] != ' ' && c->line[c->position] != '\n') c->position++;
    *n = c->position - start;
    if (!*n) bad(c, D2KM_STORE_INVALID);
    return c->line + start;
}
static uint64_t number(codec *c, uint64_t value, uint64_t max)
{
    if (c->code) return 0;
    if (!c->reading) {
        if (value > max) { bad(c, D2KM_STORE_INVALID); return 0; }
        char b[32]; int n = snprintf(b, sizeof b, " %" PRIu64, value);
        if (n > 0) append(c, b, (size_t)n);
        return value;
    }
    size_t n; const char *p = token(c, &n); uint64_t v = 0;
    for (size_t i = 0; i < n && !c->code; i++) {
        if (p[i] < '0' || p[i] > '9') { bad(c, D2KM_STORE_INVALID); break; }
        unsigned d = (unsigned)(p[i] - '0');
        if (d > max || v > (max - d) / 10) { bad(c, D2KM_STORE_INVALID); break; }
        v = v * 10 + d;
    }
    return v;
}
#define N(v, type, max) do { uint64_t z_ = number(c, (uint64_t)(v), (max)); if (c->reading) (v) = (type)z_; } while (0)
/* Отдельная знаковая запись: в том числе INT64_MIN, без abs overflow. */
static int64_t signed_number(codec *c, int64_t value, int64_t min, int64_t max)
{
    if (c->code) return 0;
    if (!c->reading) {
        if (value < min || value > max) { bad(c, D2KM_STORE_INVALID); return 0; }
        char b[32]; int n = snprintf(b, sizeof b, " %" PRId64, value);
        if (n > 0) append(c, b, (size_t)n);
        return value;
    }
    size_t n; const char *p = token(c, &n);
    int neg = n && *p == '-'; size_t i = neg ? 1u : 0u;
    uint64_t limit = neg ? (uint64_t)(-(min + 1)) + 1 : (uint64_t)max, v = 0;
    if (i == n) bad(c, D2KM_STORE_INVALID);
    for (; i < n && !c->code; i++) {
        if (p[i] < '0' || p[i] > '9') { bad(c, D2KM_STORE_INVALID); break; }
        unsigned d = (unsigned)(p[i] - '0');
        if (d > limit || v > (limit - d) / 10) { bad(c, D2KM_STORE_INVALID); break; }
        v = v * 10 + d;
    }
    return neg ? -(int64_t)(v - (v != 0)) - (v != 0) : (int64_t)v;
}
#define S(v, type, min, max) do { int64_t z_ = signed_number(c, (int64_t)(v), (min), (max)); if (c->reading) (v) = (type)z_; } while (0)
static int unhex(char x)
{
    if (x >= '0' && x <= '9') return x - '0';
    if (x >= 'a' && x <= 'f') return x - 'a' + 10;
    return -1;
}
static size_t bytes(codec *c, void *data, size_t n, size_t cap, int variable)
{
    if (c->code) return 0;
    uint8_t *b = data;
    if (c->reading) {
        size_t k; const char *p = token(c, &k);
        if (k == 1 && *p == '-') k = 0;
        if ((k & 1) || k / 2 > cap || (!variable && k / 2 != n)) { bad(c, D2KM_STORE_INVALID); return 0; }
        for (size_t i = 0; i < k / 2; i++) {
            int a = unhex(p[2 * i]), z = unhex(p[2 * i + 1]);
            if (a < 0 || z < 0) { bad(c, D2KM_STORE_INVALID); return 0; }
            b[i] = (uint8_t)(a * 16 + z);
        }
        return k / 2;
    }
    if (n > cap) { bad(c, D2KM_STORE_NO_RESOURCES); return 0; }
    append(c, n ? " " : " -", n ? 1 : 2);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n && !c->code; i++) {
        char two[2] = {hex[b[i] >> 4], hex[b[i] & 15]}; append(c, two, 2);
    }
    return n;
}
static void string(codec *c, char *p, size_t cap)
{
    size_t n = 0;
    if (!c->reading) {
        const char *e = memchr(p, 0, cap);
        if (!e) { bad(c, D2KM_STORE_INVALID); return; }
        n = (size_t)(e - p);
    }
    n = bytes(c, p, n, cap - 1, 1);
    if (c->reading && !c->code) {
        if (memchr(p, 0, n)) bad(c, D2KM_STORE_INVALID);
        p[n] = 0;
    }
}
static void count(codec *c, size_t *p, size_t max)
{
    uint64_t v = number(c, *p, UINT64_MAX);
    if (v > max) bad(c, D2KM_STORE_NO_RESOURCES);
    if (c->reading && !c->code) *p = (size_t)v;
}
static void target(codec *c, d2km_target *t)
{
    N(t->has_name, int, 1); string(c, t->name, sizeof t->name);
    N(t->family, d2km_family, 6); bytes(c, t->addr, 16, 16, 0); N(t->port, uint16_t, UINT16_MAX);
}
static void context(codec *c, d2km_context *x)
{
    target(c, &x->target);
    N(x->transport, d2km_transport, 17); N(x->protocol, d2km_protocol, D2KM_PROTOCOL_END - 1);
    N(x->family, d2km_family, 6);
    N(x->form.hello_length, uint32_t, UINT32_MAX); N(x->form.hello_print, uint64_t, UINT64_MAX);
    N(x->form.segment_count, uint8_t, D2KM_SEGMENTS_MAX);
    for (size_t i = 0; i < D2KM_SEGMENTS_MAX; i++) N(x->form.segments[i], uint16_t, UINT16_MAX);
    N(x->form.tcp_options_length, uint8_t, D2KM_TCP_OPTIONS_MAX);
    bytes(c, x->form.tcp_options, D2KM_TCP_OPTIONS_MAX, D2KM_TCP_OPTIONS_MAX, 0);
    N(x->form.ech, uint8_t, 1); N(x->form.grease, uint8_t, 1);
    string(c, x->path.ifname, sizeof x->path.ifname); N(x->path.mtu, uint16_t, UINT16_MAX);
    if (!c->code && d2km_context_valid(x)) bad(c, D2KM_STORE_INVALID);
}
static void result(codec *c, d2km_result *r)
{
    N(r->kind, d2km_result_kind, D2KM_RESULT_END - 1); S(r->value, int64_t, INT64_MIN, INT64_MAX);
}
static void arm(codec *c, d2km_arm *a)
{
    N(a->has_action, int, 1); N(a->action.op, d2km_operator, D2KM_OPERATOR_END - 1);
    N(a->action.field, uint32_t, UINT32_MAX); S(a->action.value, int64_t, INT64_MIN, INT64_MAX);
    N(a->has_expected, int, 1); result(c, &a->expected);
    if (!c->code && a->has_action && a->action.op == 0) bad(c, D2KM_STORE_INVALID);
}
static void fact(codec *c, d2km_fact *f)
{
    begin(c, "fact"); N(f->id, uint32_t, UINT32_MAX); N(f->kind, d2km_fact_kind, D2KM_FACT_KIND_END - 1);
    N(f->level, d2km_fact_level, D2KM_LEVEL_ESTABLISHED); context(c, &f->context);
    arm(c, &f->a); arm(c, &f->b); result(c, &f->ra); result(c, &f->rb);
    N(f->numeric, int, 1); N(f->invariant, int, 1); count(c, &f->source_count, D2KM_FACT_SOURCES_MAX);
    for (size_t i = 0; i < f->source_count && !c->code; i++) {
        N(f->sources[i], uint32_t, UINT32_MAX);
        if (!f->sources[i]) bad(c, D2KM_STORE_INVALID);
    }
    N(f->model_version, uint32_t, UINT32_MAX); end(c, 1);
    if (!c->code && (!f->id || !f->kind || !f->level || !f->source_count || !f->ra.kind ||
        (f->level == D2KM_LEVEL_ESTABLISHED && !f->rb.kind))) bad(c, D2KM_STORE_INVALID);
}
static void box(codec *c, d2km_box *b)
{
    begin(c, "box"); N(b->id, uint32_t, UINT32_MAX); N(b->version, uint32_t, UINT32_MAX);
    count(c, &b->fact_count, D2KM_BOX_FACTS_MAX); count(c, &b->counter_count, D2KM_BOX_COUNTER_MAX);
    count(c, &b->target_count, D2KM_BOX_TARGETS_MAX);
    for (size_t i = 0; i < D2KM_HYPOTHESIS_END; i++) N(b->hypotheses[i], uint8_t, D2KM_HYP_CONFIRMED);
    end(c, 1);
    if (!b->id) bad(c, D2KM_STORE_INVALID);
    for (size_t i = 0; i < b->fact_count && !c->code; i++) {
        fact(c, &b->facts[i]);
        if (b->facts[i].model_version > b->version) bad(c, D2KM_STORE_INVALID);
        for (size_t j = 0; j < i; j++) if (b->facts[i].id == b->facts[j].id) bad(c, D2KM_STORE_INVALID);
    }
    for (size_t i = 0; i < b->counter_count && !c->code; i++) {
        d2km_counterexample *x = &b->counters[i]; begin(c, "counter");
        N(x->candidate, uint64_t, UINT64_MAX); N(x->experiment, uint32_t, UINT32_MAX);
        N(x->receipt, uint64_t, UINT64_MAX); result(c, &x->result); target(c, &x->target); context(c, &x->context); end(c, 1);
        if (!d2km_target_equal(&x->target, &x->context.target)) bad(c, D2KM_STORE_INVALID);
        if (!x->candidate || !x->experiment || !d2km_result_is_network(x->result)) bad(c, D2KM_STORE_INVALID);
    }
    for (size_t i = 0; i < b->target_count && !c->code; i++) { begin(c, "target"); target(c, &b->targets[i]); end(c, 1); }
}
static void program(codec *c, d2km_program *p)
{
    begin(c, "program"); N(p->transport, d2km_transport, 17); N(p->protocol, d2km_protocol, D2KM_PROTOCOL_END - 1);
    N(p->seed, uint64_t, UINT64_MAX); N(p->reverse, uint8_t, 1);
    count(c, &p->payload_count, D2KM_PROG_PAYLOADS); count(c, &p->fake_count, D2KM_PROG_FAKES);
    count(c, &p->split_count, D2KM_PROG_SPLITS); string(c, p->order_why, sizeof p->order_why); end(c, 1);
    for (size_t i = 0; i < p->payload_count && !c->code; i++) {
        d2km_payload *x = &p->payloads[i]; begin(c, "payload");
        N(x->length, uint16_t, D2KM_PROG_PAYLOAD_MAX); bytes(c, x->bytes, x->length, D2KM_PROG_PAYLOAD_MAX, 0);
        string(c, x->why, sizeof x->why); end(c, 1);
    }
    for (size_t i = 0; i < p->fake_count && !c->code; i++) {
        d2km_fake *x = &p->fakes[i]; begin(c, "fake"); N(x->payload, uint8_t, D2KM_PROG_PAYLOADS - 1);
        N(x->poison.ttl, uint8_t, UINT8_MAX); N(x->poison.badsum, uint8_t, 1);
        N(x->poison.md5, uint8_t, 1); N(x->poison.tcpts, uint8_t, 1); S(x->poison.seqshift, int32_t, INT32_MIN, INT32_MAX);
        N(x->repeats, uint8_t, UINT8_MAX); N(x->gap_us, uint32_t, UINT32_MAX); N(x->between, uint8_t, 1);
        string(c, x->why, sizeof x->why); end(c, 1);
    }
    for (size_t i = 0; i < p->split_count && !c->code; i++) {
        d2km_split *x = &p->splits[i]; begin(c, "split"); N(x->anchor, d2km_anchor, D2KM_ANCHOR_END - 1);
        S(x->offset, int16_t, INT16_MIN, INT16_MAX); string(c, x->why, sizeof x->why); end(c, 1);
    }
    if (!c->code && d2km_program_check(p) != D2KM_PC_OK) bad(c, D2KM_STORE_INVALID);
}
static void knowledge(codec *c, d2km_knowledge *k)
{
    begin(c, "knowledge"); N(k->id, uint32_t, UINT32_MAX); N(k->hash, uint64_t, UINT64_MAX);
    context(c, &k->context); N(k->binding, d2km_binding, D2KM_BIND_ADDRESS);
    N(k->experiment, uint32_t, UINT32_MAX); N(k->model_version, uint32_t, UINT32_MAX);
    N(k->box, uint32_t, UINT32_MAX); N(k->last_success_ms, uint64_t, UINT64_MAX);
    count(c, &k->history_count, D2KM_KNOWLEDGE_HISTORY_MAX); end(c, 1);
    program(c, &k->program);
    for (size_t i = 0; i < k->history_count && !c->code; i++) {
        d2km_knowledge_history *h = &k->history[i]; begin(c, "history");
        N(h->time_ms, uint64_t, UINT64_MAX); N(h->previous_hash, uint64_t, UINT64_MAX);
        N(h->experiment, uint32_t, UINT32_MAX); N(h->outcome, d2km_outcome, D2KM_OUTCOME_END - 1); end(c, 1);
        if (h->outcome != D2KM_APPLIED && h->outcome != D2KM_DEGRADED) bad(c, D2KM_STORE_INVALID);
    }
    begin(c, "why"); string(c, k->why, sizeof k->why); end(c, 1);
    if (!c->code && (!k->id || !k->experiment || !k->box || !k->why[0] ||
        k->hash != d2km_program_hash(&k->program) || k->program.protocol != k->context.protocol ||
        k->program.transport != k->context.transport || k->binding == D2KM_BIND_NONE ||
        (k->binding == D2KM_BIND_NAME && !k->context.target.has_name))) bad(c, D2KM_STORE_INVALID);
}
static void contents(codec *c, d2km_store *s)
{
    begin(c, "meta"); N(s->next_experiment, uint32_t, UINT32_MAX); N(s->next_fact, uint32_t, UINT32_MAX);
    count(c, &s->boxes.count, D2KM_STORE_BOXES_MAX); count(c, &s->knowledge.count, D2KM_STORE_KNOWLEDGE_MAX); end(c, 1);
    if (!s->next_experiment || !s->next_fact) bad(c, D2KM_STORE_INVALID);
    for (size_t i = 0; i < s->boxes.count && !c->code; i++) {
        box(c, &s->boxes.entries[i]);
        for (size_t j = 0; j < i; j++) if (s->boxes.entries[i].id == s->boxes.entries[j].id) bad(c, D2KM_STORE_INVALID);
    }
    for (size_t i = 0; i < s->knowledge.count && !c->code; i++) {
        d2km_knowledge *k = &s->knowledge.entries[i]; knowledge(c, k);
        int found = 0;
        for (size_t j = 0; j < s->boxes.count; j++)
            if (s->boxes.entries[j].id == k->box && k->model_version <= s->boxes.entries[j].version) found = 1;
        if (!found) bad(c, D2KM_STORE_INVALID);
        for (size_t j = 0; j < i; j++) if (k->id == s->knowledge.entries[j].id) bad(c, D2KM_STORE_INVALID);
    }
    uint64_t expected = c->hash;
    begin(c, "end"); uint64_t got = number(c, expected, UINT64_MAX); end(c, 0);
    if (got != expected) bad(c, D2KM_STORE_INVALID);
    if (c->reading && !c->code && fgetc(c->file) != EOF) bad(c, D2KM_STORE_INVALID);
    if (c->reading && ferror(c->file)) bad(c, D2KM_STORE_IO);
}
void d2km_store_init(d2km_store *s)
{
    memset(s, 0, sizeof(*s)); s->next_experiment = 1; s->next_fact = 1;
}
static d2km_store_code error(d2km_store_error *e, d2km_store_code code, size_t line, int errnum)
{
    if (e) {
        e->line = line;
        const char *why = code == D2KM_STORE_VERSION ? "неизвестная версия хранилища" :
            code == D2KM_STORE_NO_RESOURCES ? "NO_RESOURCES: предел памяти каталога" :
            code == D2KM_STORE_INVALID ? "битая строка или несогласованные данные хранилища" : "ошибка файла хранилища";
        if (code == D2KM_STORE_OK) e->reason[0] = 0;
        else if (code == D2KM_STORE_IO) snprintf(e->reason, sizeof e->reason, "%s: %s", why, strerror(errnum));
        else snprintf(e->reason, sizeof e->reason, "%s (строка %zu)", why, line);
    }
    return code;
}
d2km_store_code d2km_store_load(const char *path, d2km_store *out, d2km_store_error *e)
{
    if (!path || !out) return error(e, D2KM_STORE_INVALID, 0, 0);
    FILE *f = fopen(path, "r");
    if (!f) return error(e, D2KM_STORE_IO, 0, errno);
    d2km_store *staged = calloc(1, sizeof *staged);
    if (!staged) { fclose(f); return error(e, D2KM_STORE_NO_RESOURCES, 0, 0); }
    codec c = {.reading = 1, .file = f, .hash = UINT64_C(1469598103934665603)};
    begin(&c, "d2km-store"); uint64_t version = number(&c, 1, UINT64_MAX); end(&c, 0);
    if (!c.code && version != 1) bad(&c, D2KM_STORE_VERSION);
    if (!c.code) contents(&c, staged);
    int saved = errno;
    if (fclose(f)) { bad(&c, D2KM_STORE_IO); saved = errno; }
    if (!c.code) *out = *staged;
    free(staged);
    return error(e, c.code, c.lineno, saved);
}
d2km_store_code d2km_store_save(const char *path, const d2km_store *s, d2km_store_error *e)
{
    if (!path || !*path || !s) return error(e, D2KM_STORE_INVALID, 0, 0);
    size_t n = strlen(path);
    if (n > SIZE_MAX - 12) return error(e, D2KM_STORE_NO_RESOURCES, 0, 0);
    char *tmp = malloc(n + 12);
    if (!tmp) return error(e, D2KM_STORE_NO_RESOURCES, 0, 0);
    snprintf(tmp, n + 12, "%s.XXXXXX", path);
    int fd = mkstemp(tmp), saved = errno;
    if (fd < 0) { free(tmp); return error(e, D2KM_STORE_IO, 0, saved); }
    codec c = {.fd = fd, .hash = UINT64_C(1469598103934665603)};
    if (fchmod(fd, 0600)) bad(&c, D2KM_STORE_IO);
    begin(&c, "d2km-store"); (void)number(&c, 1, UINT64_MAX); end(&c, 0);
    /* Codec в режиме записи не меняет ни одного поля const-модели. */
    if (!c.code) contents(&c, (d2km_store *)s);
    saved = errno;
    if (!c.code && fsync(fd)) { bad(&c, D2KM_STORE_IO); saved = errno; }
    /* close вызывается и после отказов записи/fsync; fd не остаётся открыт. */
    if (close(fd)) { bad(&c, D2KM_STORE_IO); saved = errno; }
    if (!c.code && rename(tmp, path)) { bad(&c, D2KM_STORE_IO); saved = errno; }
    if (c.code) unlink(tmp);
    free(tmp);
    return error(e, c.code, c.lineno, saved);
}
