#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2km_why.h"
#include "fixture.h"
#include "test.h"
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static d2km_why base(const d2km_context *c, const char *reason)
{
    d2km_why w;
    memset(&w, 0, sizeof(w));
    w.time_ms = 1731000000000ULL;
    w.task = c;
    w.step = D2KM_STEP_DIRECT;
    w.reason = reason;
    return w;
}

static size_t file_size(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 ? (size_t)st.st_size : 0;
}

static char *slurp(const char *p)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    static char b[1 << 16];
    size_t n = fread(b, 1, sizeof(b) - 1, f);
    fclose(f);
    b[n] = 0;
    return b;
}

int main(void)
{
    d2km_context c;
    fixture_context(&c);
    d2km_why w = base(&c, "прямой контроль: \"RST\"\nдва прогона");
    char out[4096];

    /* Проверка обязательных полей. */
    CHECK(d2km_why_check(&w) == D2KM_WHY_OK);
    d2km_why x = w; x.task = NULL;          CHECK(d2km_why_check(&x) == D2KM_WHY_NO_TASK);
    x = w; x.reason = "";                   CHECK(d2km_why_check(&x) == D2KM_WHY_NO_REASON);
    x = w; x.step = 0;                      CHECK(d2km_why_check(&x) == D2KM_WHY_BAD_STEP);
    x = w; x.outcome = (d2km_outcome)99;    CHECK(d2km_why_check(&x) == D2KM_WHY_BAD_OUTCOME);
    /* §7.4: кандидат без происхождения не записывается. */
    x = w; x.step = D2KM_STEP_SYNTH;        CHECK(d2km_why_check(&x) == D2KM_WHY_NO_DERIVATION);
    x.outcome = D2KM_REQ_CONFLICT;          CHECK(d2km_why_check(&x) == D2KM_WHY_OK);
    const char *der[] = {"TTL 5: F12 (E40), сервер на хопе 11 (F13)", ""};
    x.outcome = 0; x.derivation = der; x.derivation_count = 2;
    CHECK(d2km_why_check(&x) == D2KM_WHY_NO_DERIVATION);
    x.derivation_count = 1;                 CHECK(d2km_why_check(&x) == D2KM_WHY_OK);

    /* Формат: строка JSON, экранирование, перевод строки в конце. */
    size_t n = d2km_why_format(&w, 5, out, sizeof(out));
    CHECK(n < sizeof(out) && strlen(out) == n && out[n - 1] == '\n');
    CHECK(strchr(out, '\n') == out + n - 1);   /* одна строка */
    CHECK(strncmp(out, "{\"id\":\"W5\",\"time\":1731000000000,\"task\"", 38) == 0);
    CHECK(strstr(out, "\\\"RST\\\"\\nдва") != NULL);
    CHECK(strstr(out, "\"target\":\"example.com\"") != NULL);
    CHECK(strstr(out, "\"protocol\":\"TLS1.3\"") != NULL);
    CHECK(strstr(out, "\"experiment\":null") != NULL);
    CHECK(strstr(out, "\"outcome\":null") != NULL);
    CHECK(strstr(out, "\"step\":\"direct\"") != NULL);

    /* Длина без буфера равна длине с буфером; обрезка завершает нулём. */
    CHECK(d2km_why_format(&w, 5, NULL, 0) == n);
    char small[10];
    CHECK(d2km_why_format(&w, 5, small, sizeof(small)) == n);
    CHECK(small[9] == 0 && strncmp(small, "{\"id\":\"W5", 9) == 0);

    /* Опыт, факты, ссылки, код итога, адресная цель. */
    d2km_experiment e;
    memset(&e, 0, sizeof(e));
    e.id = 40; e.kind = D2KM_E_QUESTION; e.context = c;
    e.arm.has_action = 1; e.arm.action.op = D2KM_OP_LIMIT_DELIVERY; e.arm.action.value = -3;
    e.prediction_count = 2;
    e.predictions[0].hypothesis = D2KM_H_HELLO_NAME;
    e.predictions[1].hypothesis = D2KM_H_ADDR_AFTER_HELLO;
    uint32_t facts[] = {12, 13};
    uint64_t links[] = {3, 4};
    d2km_context ac = c;
    const uint8_t a4[4] = {10, 0, 0, 1};
    d2km_target_address(&ac.target, D2KM_IPV4, a4, 3478);
    w.task = &ac; w.step = D2KM_STEP_EXPERIMENT; w.experiment = &e;
    w.facts = facts; w.fact_count = 2; w.links = links; w.link_count = 2;
    w.outcome = D2KM_CONFLICTING; w.observations = "rst=1 receipt=R9";
    d2km_why_format(&w, 6, out, sizeof(out));
    CHECK(strstr(out, "\"target\":\"10.0.0.1:3478\"") != NULL);
    CHECK(strstr(out, "\"experiment\":{\"id\":\"E40\",\"kind\":\"question\",\"operator\":\"limit_delivery\",\"field\":0,\"value\":-3,\"hypotheses\":[\"hello_name\",\"addr_after_hello\"]}") != NULL);
    CHECK(strstr(out, "\"facts\":[\"F12\",\"F13\"]") != NULL);
    CHECK(strstr(out, "\"links\":[\"W3\",\"W4\"]") != NULL);
    CHECK(strstr(out, "\"outcome\":\"CONFLICTING\"") != NULL);
    ac.family = D2KM_IPV6;
    const uint8_t a6[16] = {0x2a, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    d2km_target_address(&ac.target, D2KM_IPV6, a6, 443);
    d2km_why_format(&w, 6, out, sizeof(out));
    CHECK(strstr(out, "\"target\":\"[2a01:0:0:0:0:0:0:1]:443\"") != NULL);

    /* Журнал: номера, переживание перезапуска, оборванная строка, вытеснение. */
    const char *tmpd = getenv("TMPDIR");
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/d2km-why-XXXXXX", tmpd && *tmpd ? tmpd : "/tmp");
    CHECK(mkdtemp(dir) != NULL);
    char path[600];
    snprintf(path, sizeof(path), "%s/why.jsonl", dir);

    d2km_journal j;
    CHECK(d2km_journal_open(&j, path, 1000) == -1);   /* предел меньше 4 КиБ */
    CHECK(d2km_journal_open(&j, path, 8192) == 0);
    d2km_why r = base(&c, "запись");
    uint64_t id = 0;
    CHECK(d2km_journal_append(&j, &r, &id) == D2KM_WHY_OK && id == 1);
    CHECK(d2km_journal_append(&j, &r, &id) == D2KM_WHY_OK && id == 2);
    d2km_why bad = r; bad.reason = NULL;
    CHECK(d2km_journal_append(&j, &bad, &id) == D2KM_WHY_NO_REASON && id == 2);
    d2km_journal_close(&j);

    /* Перезапуск: номер продолжается. Оборванный хвост отрезается. */
    int fd = open(path, O_WRONLY | O_APPEND);
    CHECK(fd >= 0 && write(fd, "{\"id\":\"W3\",\"tim", 15) == 15);
    close(fd);
    CHECK(d2km_journal_open(&j, path, 8192) == 0);
    CHECK(d2km_journal_append(&j, &r, &id) == D2KM_WHY_OK && id == 3);
    char *all = slurp(path);
    CHECK(all && strstr(all, "\"tim{") == NULL);
    int lines = 0;
    for (char *p = all; p && *p; p++) lines += *p == '\n';
    CHECK(lines == 3);

    /* Вытеснение: файл не растёт за предел, номера не повторяются,
     * последняя запись на месте, самая первая вытеснена. */
    for (int i = 0; i < 200; i++)
        CHECK(d2km_journal_append(&j, &r, &id) == D2KM_WHY_OK);
    CHECK(id == 203);
    CHECK(file_size(path) <= 8192);
    all = slurp(path);
    CHECK(all && strstr(all, "{\"id\":\"W203\"") != NULL);
    CHECK(all && strstr(all, "{\"id\":\"W1\",") == NULL);
    CHECK(all && all[0] == '{');
    d2km_journal_close(&j);
    CHECK(d2km_journal_open(&j, path, 8192) == 0 && j.next_id == 204);
    d2km_journal_close(&j);
    unlink(path);
    rmdir(dir);
    DONE("test_why");
}
