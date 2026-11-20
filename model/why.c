#define _POSIX_C_SOURCE 200809L
#include "d2km_why.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const step_names[D2KM_STEP_END] = {
    [D2KM_STEP_SUSPECT] = "suspect",
    [D2KM_STEP_DIRECT] = "direct",
    [D2KM_STEP_OWN] = "own",
    [D2KM_STEP_QUESTION] = "question",
    [D2KM_STEP_EXPERIMENT] = "experiment",
    [D2KM_STEP_SYNTH] = "synth",
    [D2KM_STEP_TRIAL] = "trial",
    [D2KM_STEP_CHECK] = "check",
    [D2KM_STEP_KNOWLEDGE] = "knowledge",
    [D2KM_STEP_WATCH] = "watch",
};

const char *d2km_step_name(d2km_step s)
{
    return (s > 0 && s < D2KM_STEP_END) ? step_names[s] : NULL;
}

d2km_why_check_code d2km_why_check(const d2km_why *w)
{
    if (w == NULL || w->task == NULL)
        return D2KM_WHY_NO_TASK;
    if (d2km_step_name(w->step) == NULL)
        return D2KM_WHY_BAD_STEP;
    if (w->reason == NULL || w->reason[0] == '\0')
        return D2KM_WHY_NO_REASON;
    if (w->outcome != 0 && !d2km_outcome_valid(w->outcome))
        return D2KM_WHY_BAD_OUTCOME;
    /* Синтез без кода итога — построен кандидат: у каждого действия и
     * числа должно быть происхождение. */
    if (w->step == D2KM_STEP_SYNTH && w->outcome == 0 &&
        (w->derivation == NULL || w->derivation_count == 0))
        return D2KM_WHY_NO_DERIVATION;
    for (size_t i = 0; i < w->derivation_count; i++)
        if (w->derivation[i] == NULL || w->derivation[i][0] == '\0')
            return D2KM_WHY_NO_DERIVATION;
    return D2KM_WHY_OK;
}

typedef struct {
    char *out;
    size_t cap, len;
} sink;

static void raw(sink *s, const char *p, size_t n)
{
    if (s->out != NULL && s->len < s->cap) {
        size_t room = s->cap - s->len;
        memcpy(s->out + s->len, p, n < room ? n : room);
    }
    s->len += n;
}

static void lit(sink *s, const char *p)
{
    raw(s, p, strlen(p));
}

/* Одно число по формату. Длинный текст вокруг числа пишется через lit():
 * буфер рассчитан на короткий формат, и обрезка здесь — ошибка вызова. */
static void fmt(sink *s, const char *f, uint64_t v)
{
    char b[96];
    int n = snprintf(b, sizeof(b), f, v);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof(b))
        n = (int)sizeof(b) - 1;
    raw(s, b, (size_t)n);
}

static void str(sink *s, const char *p)
{
    if (p == NULL) {
        lit(s, "null");
        return;
    }
    lit(s, "\"");
    for (; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            char e[2] = {'\\', (char)c};
            raw(s, e, 2);
        } else if (c == '\n') {
            lit(s, "\\n");
        } else if (c < 0x20) {
            fmt(s, "\\u%04" PRIx64, c);
        } else {
            raw(s, (const char *)&c, 1);
        }
    }
    lit(s, "\"");
}

static void target(sink *s, const d2km_target *t)
{
    if (t->has_name) {
        str(s, t->name);
        return;
    }
    char b[64];
    int n;
    if (t->family == D2KM_IPV4) {
        n = snprintf(b, sizeof(b), "\"%u.%u.%u.%u:%u\"", t->addr[0], t->addr[1],
                     t->addr[2], t->addr[3], (unsigned)t->port);
    } else {
        n = snprintf(b, sizeof(b),
                     "\"[%x:%x:%x:%x:%x:%x:%x:%x]:%u\"",
                     (t->addr[0] << 8) | t->addr[1], (t->addr[2] << 8) | t->addr[3],
                     (t->addr[4] << 8) | t->addr[5], (t->addr[6] << 8) | t->addr[7],
                     (t->addr[8] << 8) | t->addr[9], (t->addr[10] << 8) | t->addr[11],
                     (t->addr[12] << 8) | t->addr[13], (t->addr[14] << 8) | t->addr[15],
                     (unsigned)t->port);
    }
    if (n > 0)
        raw(s, b, (size_t)n);
}

static void task(sink *s, const d2km_context *c)
{
    lit(s, "{\"target\":");
    target(s, &c->target);
    lit(s, ",\"transport\":");
    lit(s, c->transport == D2KM_UDP ? "\"udp\"" : "\"tcp\"");
    lit(s, ",\"protocol\":");
    str(s, d2km_protocol_name(c->protocol));
    fmt(s, ",\"family\":%" PRIu64, (uint64_t)c->family);
    fmt(s, ",\"form\":{\"hello_length\":%" PRIu64, c->form.hello_length);
    fmt(s, ",\"hello_print\":\"%016" PRIx64 "\"", c->form.hello_print);
    lit(s, ",\"segments\":[");
    for (unsigned i = 0; i < c->form.segment_count && i < D2KM_SEGMENTS_MAX; i++)
        fmt(s, i ? ",%" PRIu64 : "%" PRIu64, c->form.segments[i]);
    lit(s, "],\"tcp_options\":[");
    for (unsigned i = 0;
         i < c->form.tcp_options_length && i < D2KM_TCP_OPTIONS_MAX; i++)
        fmt(s, i ? ",%" PRIu64 : "%" PRIu64, c->form.tcp_options[i]);
    fmt(s, "],\"ech\":%" PRIu64, c->form.ech);
    fmt(s, ",\"grease\":%" PRIu64 "}", c->form.grease);
    char ifname[D2KM_IFNAME_MAX + 1];
    memcpy(ifname, c->path.ifname, D2KM_IFNAME_MAX);
    ifname[D2KM_IFNAME_MAX] = '\0';
    lit(s, ",\"path\":{\"if\":");
    str(s, ifname);
    fmt(s, ",\"mtu\":%" PRIu64 "}}", c->path.mtu);
}

static void experiment(sink *s, const d2km_experiment *e)
{
    static const char *const kinds[] = {NULL, "direct", "question", "trial"};
    fmt(s, "{\"id\":\"E%" PRIu64 "\"", e->id);
    lit(s, ",\"kind\":");
    str(s, (e->kind >= D2KM_E_DIRECT && e->kind <= D2KM_E_TRIAL) ? kinds[e->kind] : NULL);
    if (e->arm.has_action) {
        lit(s, ",\"operator\":");
        str(s, d2km_operator_name(e->arm.action.op));
        fmt(s, ",\"field\":%" PRIu64, e->arm.action.field);
        char b[32];
        int n = snprintf(b, sizeof(b), ",\"value\":%lld", (long long)e->arm.action.value);
        if (n > 0)
            raw(s, b, (size_t)n);
    }
    lit(s, ",\"hypotheses\":[");
    for (size_t i = 0; i < e->prediction_count && i < D2KM_HYPOTHESES_MAX; i++) {
        if (i)
            lit(s, ",");
        str(s, d2km_hypothesis_name(e->predictions[i].hypothesis));
    }
    lit(s, "]");
    if (e->kind == D2KM_E_QUESTION && e->control.has_expected) {
        lit(s, ",\"predictions\":[");
        for (size_t i = 0; i < e->prediction_count && i < D2KM_HYPOTHESES_MAX; i++) {
            if (i) lit(s, ",");
            lit(s, "{\"hypothesis\":");
            str(s, d2km_hypothesis_name(e->predictions[i].hypothesis));
            lit(s, ",\"result\":");
            str(s, d2km_result_name(e->predictions[i].predicted.kind));
            char value[48];
            int count = snprintf(value, sizeof(value), ",\"value\":%" PRId64 "}", e->predictions[i].predicted.value);
            if (count > 0) raw(s, value, (size_t)count);
        }
        lit(s, "],\"control\":{\"expected\":");
        str(s, d2km_result_name(e->control.expected.kind));
        char value[48];
        int count = snprintf(value, sizeof(value), ",\"value\":%" PRId64 "}", e->control.expected.value);
        if (count > 0) raw(s, value, (size_t)count);
    }
    if (e->candidate)
        fmt(s, ",\"candidate\":\"%016" PRIx64 "\"", e->candidate);
    lit(s, "}");
}

size_t d2km_why_format(const d2km_why *w, uint64_t id, char *out, size_t cap)
{
    sink s = {out, cap, 0};
    fmt(&s, "{\"id\":\"W%" PRIu64 "\"", id);
    fmt(&s, ",\"time\":%" PRIu64, w->time_ms);
    lit(&s, ",\"task\":");
    task(&s, w->task);
    lit(&s, ",\"step\":");
    str(&s, d2km_step_name(w->step));
    lit(&s, ",\"experiment\":");
    if (w->experiment != NULL)
        experiment(&s, w->experiment);
    else
        lit(&s, "null");
    lit(&s, ",\"observations\":");
    str(&s, w->observations);
    lit(&s, ",\"facts\":[");
    for (size_t i = 0; i < w->fact_count; i++)
        fmt(&s, i ? ",\"F%" PRIu64 "\"" : "\"F%" PRIu64 "\"", w->facts[i]);
    lit(&s, "],\"derivation\":[");
    for (size_t i = 0; i < w->derivation_count; i++) {
        if (i)
            lit(&s, ",");
        str(&s, w->derivation[i]);
    }
    lit(&s, "],\"outcome\":");
    str(&s, w->outcome ? d2km_outcome_name(w->outcome) : NULL);
    lit(&s, ",\"reason\":");
    str(&s, w->reason);
    lit(&s, ",\"links\":[");
    for (size_t i = 0; i < w->link_count; i++)
        fmt(&s, i ? ",\"W%" PRIu64 "\"" : "\"W%" PRIu64 "\"", w->links[i]);
    lit(&s, "]}\n");
    if (out != NULL && cap > 0)
        out[s.len < cap ? s.len : cap - 1] = '\0';
    return s.len;
}

static int read_all(int fd, char **buf, size_t *len)
{
    struct stat st;
    if (fstat(fd, &st) != 0)
        return -1;
    size_t n = (size_t)st.st_size;
    char *b = malloc(n + 1);
    if (b == NULL)
        return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = pread(fd, b + got, n - got, (off_t)got);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0) {
            free(b);
            return -1;
        }
        got += (size_t)r;
    }
    b[n] = '\0';
    *buf = b;
    *len = n;
    return 0;
}

/* Номер последней записи: последнее вхождение "id":"W<n>" в начале строки. */
static uint64_t last_id(const char *b, size_t n)
{
    static const char key[] = "{\"id\":\"W";
    size_t k = sizeof(key) - 1;
    for (size_t i = n; i-- > 0;) {
        if ((i == 0 || b[i - 1] == '\n') && n - i > k && memcmp(b + i, key, k) == 0) {
            uint64_t v = 0;
            for (size_t j = i + k; j < n && b[j] >= '0' && b[j] <= '9'; j++)
                v = v * 10 + (uint64_t)(b[j] - '0');
            return v;
        }
    }
    return 0;
}

static int write_all(int fd, const char *p, size_t n)
{
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

int d2km_journal_open(d2km_journal *j, const char *path, uint64_t limit)
{
    if (j == NULL || path == NULL || limit < 4096 ||
        strlen(path) + 5 > sizeof(j->path)) {
        errno = EINVAL;
        return -1;
    }
    memset(j, 0, sizeof(*j));
    j->fd = open(path, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (j->fd < 0)
        return -1;
    strcpy(j->path, path);
    j->limit = limit;
    char *b;
    size_t n;
    if (read_all(j->fd, &b, &n) != 0) {
        int e = errno;
        close(j->fd);
        j->fd = -1;
        errno = e;
        return -1;
    }
    /* Оборванная последняя строка (сбой питания) отрезается: запись либо
     * целая, либо её нет. */
    size_t keep = n;
    while (keep > 0 && b[keep - 1] != '\n')
        keep--;
    if (keep != n && ftruncate(j->fd, (off_t)keep) != 0) {
        int e = errno;
        free(b);
        close(j->fd);
        j->fd = -1;
        errno = e;
        return -1;
    }
    j->next_id = last_id(b, keep) + 1;
    j->size = keep;
    free(b);
    return 0;
}

/* Оставляет самые новые целые строки суммарно не больше limit/2. */
static int compact(d2km_journal *j)
{
    char *b;
    size_t n;
    if (read_all(j->fd, &b, &n) != 0)
        return -1;
    size_t budget = (size_t)(j->limit / 2), from = n;
    while (from > 0) {
        size_t start = from - 1;   /* from-1 — '\n' предыдущей строки */
        while (start > 0 && b[start - 1] != '\n')
            start--;
        if (n - start > budget)
            break;
        from = start;
    }
    char tmp[sizeof(j->path) + 4];
    snprintf(tmp, sizeof(tmp), "%s.tmp", j->path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(b);
        return -1;
    }
    if (write_all(fd, b + from, n - from) != 0 || fsync(fd) != 0 ||
        close(fd) != 0 || rename(tmp, j->path) != 0) {
        int e = errno;
        unlink(tmp);
        free(b);
        errno = e;
        return -1;
    }
    free(b);
    close(j->fd);
    j->fd = open(j->path, O_RDWR | O_APPEND);
    if (j->fd < 0)
        return -1;
    j->size = n - from;
    return 0;
}

int d2km_journal_append(d2km_journal *j, const d2km_why *w, uint64_t *id)
{
    d2km_why_check_code c = d2km_why_check(w);
    if (c != D2KM_WHY_OK)
        return (int)c;
    if (j == NULL || j->fd < 0)
        return -1;
    uint64_t wid = j->next_id;
    size_t len = d2km_why_format(w, wid, NULL, 0);
    char *line = malloc(len + 1);
    if (line == NULL)
        return -1;
    d2km_why_format(w, wid, line, len + 1);
    if (j->size + len > j->limit && compact(j) != 0) {
        free(line);
        return -1;
    }
    if (write_all(j->fd, line, len) != 0) {
        free(line);
        return -1;
    }
    free(line);
    j->size += len;
    j->next_id = wid + 1;
    if (id != NULL)
        *id = wid;
    return D2KM_WHY_OK;
}

void d2km_journal_close(d2km_journal *j)
{
    if (j != NULL && j->fd >= 0) {
        close(j->fd);
        j->fd = -1;
    }
}
