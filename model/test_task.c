#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2km_task.h"
#include "d2km_sim.h"
#include "fixture.h"
#include "test.h"
#include <stdlib.h>
#include <unistd.h>

static size_t w16(uint8_t *p, size_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2; }

static size_t hello(uint8_t *out, const char *sni)
{
    uint8_t e[256]; size_t n = strlen(sni);
    w16(e, 0); w16(e + 2, n + 5); w16(e + 4, n + 3); e[6] = 0; w16(e + 7, n);
    memcpy(e + 9, sni, n);
    size_t el = 9 + n;
    uint8_t body[512]; size_t b = 0;
    b += w16(body + b, 0x0303);
    memset(body + b, 0x11, 32); b += 32;
    body[b++] = 0;
    b += w16(body + b, 2); b += w16(body + b, 0x1301);
    body[b++] = 1; body[b++] = 0;
    b += w16(body + b, el); memcpy(body + b, e, el); b += el;
    out[0] = 0x16; w16(out + 1, 0x0301); w16(out + 3, b + 4);
    out[5] = 1; out[6] = 0; w16(out + 7, b);
    memcpy(out + 9, body, b);
    return 9 + b;
}

static d2km_box box;
static d2km_task_report rep;

static const char *history;
static const char *audit_path;
static unsigned audit_fields;
static int combination_model;
static int intermediate_reaction;
static int retry_combo_model;
static unsigned ttl_combo_question_ok, ttl_combo_trial_failed;
static unsigned header1_groups;
static uint32_t header1_experiment;
static d2km_net underlying;
static size_t max_sends_cfg;
static int special_run(void *, const d2km_arm_spec *, d2km_observation *, d2km_result *);

static d2km_outcome go(d2km_sim *sim, const char *sni, d2km_journal *j)
{
    static uint8_t h[512];
    static d2km_context c;
    fixture_context(&c);
    d2km_target_name(&c.target, sni);
    size_t n = hello(h, sni);
    d2km_box_init(&box, 1);
    d2km_net net = d2km_sim_net(sim);
    if (combination_model || intermediate_reaction || audit_path) { underlying = net; net.run = special_run; }
    d2km_tls_task t = {.net = &net, .box = &box, .journal = j, .context = &c, .hello = h,
                       .hello_length = n, .pass_name = "passes.example", .alive_history = history,
                       .seed = 42, .max_sends = max_sends_cfg, .next_experiment = 1, .next_fact = 1};
    return d2km_tls_task_run(&t, &rep);
}


static const d2km_fact *fact_field(uint32_t field, int numeric)
{
    for (size_t i = 0; i < box.fact_count; i++) {
        const d2km_fact *f = &box.facts[i];
        if (d2km_fact_usable(f) && f->numeric == numeric && f->b.has_action &&
            f->b.action.field == field) return f;
    }
    return NULL;
}

/* Дополнительная модель: смена реакции до APP_OK и необходимость
 * сочетания — отдельные свойства, не таблица готовых стратегий. */
static int special_run(void *ctx, const d2km_arm_spec *a, d2km_observation *obs, d2km_result *res)
{
    (void)ctx;
    if (audit_path && ((a->context && !strcmp(a->context->target.name, "passes.example")) ||
        (a->program && a->program->fake_count && strstr(a->program->fakes[0].why, "вопрос:")) ||
        (a->program && a->program->split_count && strstr(a->program->splits[0].why, "вопрос D")))) {
        FILE *log = fopen(audit_path, "r");
        char line[8192], id[40];
        snprintf(id, sizeof(id), "\"id\":\"E%u\"", a->experiment);
        int found = 0;
        while (log && fgets(line, sizeof(line), log))
            if (strstr(line, id) && strstr(line, "\"kind\":\"question\"")) {
                CHECK(strstr(line, "\"predictions\":[") && strstr(line, "\"control\":{") &&
                    strstr(line, "критерий"));
                if (strstr(line, "\"field\":131076")) audit_fields |= 1;
                if (strstr(line, "\"field\":131077")) audit_fields |= 2;
                if (strstr(line, "\"field\":131075")) audit_fields |= 4;
                if (strstr(line, "\"field\":131078")) audit_fields |= 8;
                found = 1;
            }
        if (log) fclose(log);
        CHECK(found); /* запись существует уже при входе в net.run */
    }
    d2km_arm_spec spec = *a;
    static d2km_program copy;
    int original = 0;
    static d2km_tls_hello parsed;
    char name[256];
    if (a->kind == D2KM_ARM_EXCHANGE &&
        d2km_tls_parse(a->hello, a->hello_length, &parsed) == D2KM_TLS_OK &&
        d2km_tls_sni(&parsed, name, sizeof(name)) == D2KM_TLS_OK)
        original = !strcmp(name, "blocked.example");
    if (combination_model && original && a->program && !a->program->split_count) {
        copy = *a->program;
        copy.fake_count = 0;
        spec.program = &copy;
    }
    int rc = underlying.run(underlying.ctx, &spec, obs, res);
    if (combination_model && original && a->program && a->program->split_count &&
        !a->program->fake_count && a->program->splits[0].anchor == D2KM_AT_PAYLOAD_START)
        res->kind = D2KM_R_HELLO_SILENT;
    if (retry_combo_model && original && a->program && a->program->split_count) {
        const d2km_program *program = a->program;
        if (program->splits[0].anchor != D2KM_AT_PAYLOAD_START || program->splits[0].offset != 1)
            res->kind = D2KM_R_RST;
        else if (!program->fake_count) {
            if (header1_experiment != a->experiment) {
                header1_experiment = a->experiment;
                header1_groups++;
            }
        } else if (program->fakes[0].poison.ttl) {
            if (strstr(program->fakes[0].why, "вопрос:")) ttl_combo_question_ok++;
            else { res->kind = D2KM_R_RST; ttl_combo_trial_failed++; }
        }
    }
    if (intermediate_reaction && original && a->program && a->program->fake_count &&
        a->program->fakes[0].repeats >= 2 && a->program->fakes[0].repeats < 8)
        res->kind = D2KM_R_HELLO_SILENT;
    return rc;
}

static void extensions(void)
{
    const unsigned bounds[] = {2, 3, 7, 8, 127, 128, 254, 255};
    for (size_t i = 0; i < sizeof(bounds) / sizeof(bounds[0]); i++) {
        d2km_sim s = {.blocked_suffix = "blocked.example", .reads_name = 1,
            .reassembles = 1, .box_hop = 2, .server_hop = 10, .min_copies = bounds[i]};
        CHECK(go(&s, "blocked.example", NULL) == D2KM_APPLIED);
        CHECK(rep.program.fakes[0].poison.ttl == 2 && rep.program.fakes[0].repeats == bounds[i]);
        const d2km_fact *f = fact_field(D2KM_FIELD_FAKE_COPIES, 1);
        CHECK(f != NULL);
        if (f) {
            CHECK(f->a.action.value == (int64_t)bounds[i] - 1 && f->b.action.value == (int64_t)bounds[i]);
            CHECK(f->source_count == 3 && f->rb.kind == D2KM_R_APP_OK);
            char id[32]; snprintf(id, sizeof(id), "F%u", f->id);
            CHECK(strstr(rep.program.fakes[0].why, id) != NULL);
        }
        CHECK(rep.experiments < 100);
    }
    d2km_sim transport = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .ignores_low_ttl = 1};
    CHECK(go(&transport, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.fakes[0].poison.tcpts && rep.program.fakes[0].poison.ttl == 0);
    const d2km_fact *safe = fact_field(D2KM_FIELD_SPOIL, 0);
    CHECK(safe && safe->invariant && safe->kind == D2KM_F_PATH && safe->b.action.value == 1);
    CHECK(fact_field(D2KM_TLS_F_SNI, 0) != NULL); /* B не понижает разбор имени */
    if (safe) CHECK(d2km_fact_unread_form(safe) == 0 && !strcmp(safe->context.target.name, "passes.example"));
    d2km_sim md5 = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .ignores_low_ttl = 1, .checks = 1};
    CHECK(go(&md5, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.fakes[0].poison.md5 && !rep.program.fakes[0].poison.tcpts);
    d2km_sim header = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .ignores_low_ttl = 1,
        .checks = 7, .header_split_relief = 1};
    CHECK(go(&header, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.fake_count == 0 && rep.program.split_count == 1 &&
        rep.program.splits[0].anchor == D2KM_AT_PAYLOAD_START && rep.program.splits[0].offset == 1);
    CHECK(fact_field(D2KM_FIELD_RECORD, 0) != NULL);
    d2km_sim accepts = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .ignores_low_ttl = 1, .server_accepts = 7};
    CHECK(go(&accepts, "blocked.example", NULL) == D2KM_MODEL_INCOMPLETE);
    CHECK(strstr(rep.reason, "порчи") && strstr(rep.reason, "копий") && strstr(rep.reason, "разрезом"));
    size_t rejects = 0;
    for (size_t i = 0; i < box.fact_count; i++)
        if (box.facts[i].b.action.field == D2KM_FIELD_SPOIL) {
            CHECK(!box.facts[i].invariant && box.facts[i].rb.kind != D2KM_R_APP_OK);
            rejects++;
        }
    CHECK(rejects == 3 && rep.experiments < 100);
    combination_model = 1;
    d2km_sim combo = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10};
    char dir[] = "/tmp/d2km-audit-XXXXXX", path[128];
    CHECK(mkdtemp(dir) != NULL);
    snprintf(path, sizeof(path), "%s/why.jsonl", dir);
    d2km_journal journal;
    CHECK(d2km_journal_open(&journal, path, 1 << 20) == 0);
    audit_path = path; audit_fields = 0;
    CHECK(go(&combo, "blocked.example", &journal) == D2KM_APPLIED);
    CHECK(audit_fields == 15);
    audit_path = NULL;
    d2km_journal_close(&journal);
    unlink(path); rmdir(dir);
    CHECK(rep.program.fake_count == 1 && rep.program.split_count == 1 &&
        rep.program.splits[0].anchor == D2KM_AT_PAYLOAD_START && rep.program.splits[0].offset == 1);
    const d2km_fact *joined = fact_field(D2KM_FIELD_FAKE_SPLIT, 0);
    CHECK(joined != NULL);
    if (joined) {
        CHECK(joined->a.action.value == D2KM_COMBO_VALUE(0, 1, 0) &&
            joined->b.action.value == D2KM_COMBO_VALUE(0, 1, 1) && joined->source_count == 3);
        char id[32]; snprintf(id, sizeof(id), "F%u", joined->id);
        CHECK(strstr(rep.program.splits[0].why, id) != NULL);
    }
    /* TTL-сочетание не помогает: следующий безопасный R всё ещё
       должен получить собственный вопрос, а не быть потерянным. */
    d2km_sim transport_combo = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .ignores_low_ttl = 1};
    CHECK(go(&transport_combo, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.fake_count == 1 && rep.program.fakes[0].poison.tcpts && rep.program.split_count == 1);
    /* Регрессия D: APP_OK вопроса сочетания не гарантирует успеха
       испытания. Его провал оставляет tcpts на той же позиции незаданным. */
    retry_combo_model = 1;
    ttl_combo_question_ok = 0; ttl_combo_trial_failed = 0;
    header1_groups = 0; header1_experiment = 0;
    d2km_sim retry_combo = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10};
    CHECK(go(&retry_combo, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.fake_count == 1 && rep.program.fakes[0].poison.tcpts &&
        rep.program.split_count == 1 && rep.program.splits[0].anchor == D2KM_AT_PAYLOAD_START &&
        rep.program.splits[0].offset == 1);
    CHECK(ttl_combo_question_ok == 2 && ttl_combo_trial_failed == 2 && header1_groups == 1);
    retry_combo_model = 0;
    combination_model = 0;
    intermediate_reaction = 1;
    d2km_sim changing = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .min_copies = 8};
    CHECK(go(&changing, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.fakes[0].repeats == 8);
    const d2km_fact *threshold = fact_field(D2KM_FIELD_FAKE_COPIES, 1);
    CHECK(threshold && threshold->ra.kind == D2KM_R_HELLO_SILENT && threshold->rb.kind == D2KM_R_APP_OK);
    intermediate_reaction = 0;

    /* Поле 11.11: исполнитель делает не больше 26 посылок за исполнение,
       план длиннее отвергает целиком. Поиск копий не выходит за предел. */
    max_sends_cfg = 26;
    d2km_sim within = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .min_copies = 8};
    CHECK(go(&within, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.fakes[0].repeats == 8 && within.max_repeats_seen <= 26);
    d2km_sim beyond = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .min_copies = 40};
    CHECK(go(&beyond, "blocked.example", NULL) != D2KM_APPLIED);
    CHECK(beyond.max_repeats_seen <= 26);
    CHECK(rep.outcome == D2KM_MODEL_INCOMPLETE);
    max_sends_cfg = 0;

    /* Поле 11.11: единичные локальные сбои (ядро не приняло пакет длиннее
       MTU) останавливали путь цели. Они — не ответ коробки (§5.2). */
    d2km_sim sometimes = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .min_copies = 4, .local_fail_every = 5};
    CHECK(go(&sometimes, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.fakes[0].repeats == 4);
    d2km_sim broken = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .local_fail_every = 1};
    CHECK(go(&broken, "blocked.example", NULL) == D2KM_LOCAL_FAIL);
    CHECK(broken.runs == D2KM_LOCAL_FAILS_MAX);

    /* Поле 11.11, flibusta.is: свой сервер, сертификата на пропускаемое имя
       нет — с ним сервер отвечает (reply), а не прикладным успехом. Живость
       и «коробка читает имя» доказаны без внешнего сервиса (§4.3 п. 1). */
    d2km_sim own = {.blocked_suffix = "blocked.example", .cert_suffix = "blocked.example",
        .reads_name = 1, .reassembles = 1, .box_hop = 2, .server_hop = 10, .reference_down = 1};
    CHECK(go(&own, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.fake_count == 1 && rep.program.fakes[0].poison.ttl == 2);
    CHECK(fact_field(D2KM_FIELD_SPOIL, 0) == NULL);   /* порча не проверяема — не используется */

    /* Поле 11.11: badsum у Cloudflare — то отвергается, то нет. Неустойчивый
       ответ B — не факт и не остановка пути: порча просто не используется. */
    d2km_sim flaky = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10, .ignores_low_ttl = 1,
        .server_flaky = 7};
    d2km_outcome fo = go(&flaky, "blocked.example", NULL);
    CHECK(fo != D2KM_CONFLICTING);
    CHECK(fact_field(D2KM_FIELD_SPOIL, 0) == NULL ||
          !fact_field(D2KM_FIELD_SPOIL, 0)->invariant);

    /* Поле 11.11, IPv6 к Cloudflare: коробка глушит приветствие (тишина).
       Хоп коробки по TTL не измерить — способ TTL исключён, обход фальшивкой
       с порчей транспорта, которую сервер отвергает. */
    d2km_sim silent = {.blocked_suffix = "blocked.example", .reads_name = 1, .silent_box = 1,
        .reassembles = 1, .box_hop = 2, .server_hop = 10};
    { d2km_outcome so = go(&silent, "blocked.example", NULL); if (so != D2KM_APPLIED) fprintf(stderr, "silent: %s %s\n", d2km_outcome_name(so), rep.reason); CHECK(so == D2KM_APPLIED); }
    CHECK(rep.program.fake_count == 1 && rep.program.fakes[0].poison.ttl == 0 &&
          rep.program.fakes[0].poison.tcpts);
    CHECK(strstr(rep.program.fakes[0].why, "F") != NULL);
}

/* Сквозной путь двух целей; fixture-форма одинакова, отличается только цель.
 * Это позволяет отдельно проверить факт-кандидат, без подмены совместимости. */
static d2km_store catalog, restored;
static int own_fault_kind;
static unsigned own_fault_runs;
static d2km_family saved_family = D2KM_IPV4;
static int saved_form, saved_path;
static const char *saved_contract;
static int own_run(void *ctx, const d2km_arm_spec *a, d2km_observation *obs, d2km_result *result)
{
    (void)ctx;
    int rc = underlying.run(underlying.ctx, a, obs, result);
    if (a->program && own_fault_kind) {
        own_fault_runs++;
        if (own_fault_kind == D2KM_R_RST)
            result->kind = own_fault_runs & 1u ? D2KM_R_RST : D2KM_R_HELLO_SILENT;
        else result->kind = (d2km_result_kind)own_fault_kind;
    }
    return rc;
}
static d2km_outcome saved(d2km_sim *sim, const char *name, d2km_store *store, d2km_journal *j)
{
    uint8_t h[512]; d2km_context c; fixture_context(&c);
    c.family = saved_family;
    if (saved_form) c.form.grease = 1;
    if (saved_path) strcpy(c.path.ifname, "other0");
    CHECK(d2km_target_name(&c.target, name) == 0);
    size_t n = hello(h, name);
    d2km_box_init(&box, 100);
    d2km_net net = d2km_sim_net(sim);
    if (own_fault_kind) { underlying = net; net.run = own_run; }
    d2km_tls_task t = {.net = &net, .box = &box, .boxes = &store->boxes,
        .knowledge = &store->knowledge, .journal = j, .context = &c, .hello = h,
        .hello_length = n, .pass_name = "passes.example", .seed = 42,
        .application_proof = saved_contract,
        .next_experiment = store->next_experiment, .next_fact = store->next_fact};
    d2km_outcome o = d2km_tls_task_run(&t, &rep);
    store->next_experiment = t.next_experiment; store->next_fact = t.next_fact;
    return o;
}
static void own_knowledge(void)
{
    d2km_store_init(&catalog);
    d2km_sim first = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 0, .box_hop = 2, .server_hop = 10};
    CHECK(saved(&first, "a.blocked.example", &catalog, NULL) == D2KM_APPLIED);
    CHECK(!rep.from_own && rep.questions > 0);
    CHECK(catalog.knowledge.count == 1 && catalog.boxes.count == 1);
    if (catalog.knowledge.count != 1) return;
    d2km_knowledge original = catalog.knowledge.entries[0];
    CHECK(original.hash == d2km_program_hash(&rep.program));
    CHECK(original.experiment && original.model_version && original.box && original.last_success_ms);
    CHECK(original.binding == D2KM_BIND_NAME && !strcmp(original.context.target.name, "a.blocked.example"));
    CHECK(strstr(original.why, "derivation") && strstr(original.why, "прикладной"));
    char dir[] = "/tmp/d2km-own-XXXXXX", path[128], log[128];
    CHECK(mkdtemp(dir) != NULL); snprintf(path, sizeof path, "%s/store", dir);
    snprintf(log, sizeof log, "%s/why", dir);
    d2km_store_error err;
    CHECK(d2km_store_save(path, &catalog, &err) == D2KM_STORE_OK);
    CHECK(d2km_store_load(path, &restored, &err) == D2KM_STORE_OK);
    d2km_journal journal; CHECK(d2km_journal_open(&journal, log, 1 << 20) == 0);
    d2km_sim second = first; second.runs = 0;
    CHECK(saved(&second, "b.blocked.example", &restored, &journal) == D2KM_APPLIED);
    CHECK(rep.from_own && rep.questions == 0 && rep.experiments == 3 && rep.runs == 6);
    CHECK(restored.knowledge.count == 2 && restored.boxes.count == 1);
    CHECK(d2km_program_hash(&rep.program) == original.hash);
    CHECK(!d2km_box_has_target(&restored.boxes.entries[0], &restored.knowledge.entries[1].context.target));
    CHECK(!strcmp(restored.knowledge.entries[1].context.target.name, "b.blocked.example"));
    CHECK(restored.knowledge.entries[1].box == original.box);
    d2km_journal_close(&journal);
    FILE *f = fopen(log, "r"); char all[32768] = {0};
    if (f) { size_t n = fread(all, 1, sizeof all - 1, f); all[n] = 0; fclose(f); }
    CHECK(strstr(all, "своё знание: запись K1, коробка B1"));
    CHECK(strstr(all, "\"step\":\"own\"") && !strstr(all, "\"step\":\"question\""));

    /* Другая коробка собирает разрез: OWN_FAIL, контрпример, свои вопросы.
       Старая B1 остаётся целой; противоречащий факт порождает B2. */
    d2km_box old = restored.boxes.entries[0];
    d2km_sim other = first; other.reassembles = 1; other.runs = 0;
    CHECK(saved(&other, "c.blocked.example", &restored, NULL) == D2KM_APPLIED);
    CHECK(!rep.from_own && rep.questions > 0 && rep.program.fake_count == 1);
    CHECK(restored.boxes.count == 2 && restored.knowledge.count == 3);
    CHECK(memcmp(&old, &restored.boxes.entries[0], sizeof old) == 0);
    CHECK(d2km_box_tried(&box, original.hash, &restored.knowledge.entries[2].context.target));
    CHECK(restored.knowledge.entries[2].box != original.box);
    /* Прямой успех никогда не исполняет знание и не добавляет записей. */
    size_t count = restored.knowledge.count;
    CHECK(saved(&other, "open.example", &restored, NULL) == D2KM_DIRECT_OK);
    CHECK(rep.experiments == 1 && restored.knowledge.count == count);
    unlink(path); unlink(log); rmdir(dir);
}

/* Each new target validates the program itself. Its archive needs the root
 * derivation and its own validation, not every intermediate target's trial. */
static void own_archive_chain(void)
{
    d2km_sim sim = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 0, .box_hop = 2, .server_hop = 10};
    d2km_store_init(&catalog);
    char dir[] = "/tmp/d2km-archive-chain-XXXXXX", path[128], log[128];
    CHECK(mkdtemp(dir) != NULL);
    snprintf(path, sizeof path, "%s/store", dir);
    snprintf(log, sizeof log, "%s/why", dir);
    d2km_journal journal;
    CHECK(d2km_journal_open(&journal, log, 4096) == 0);
    CHECK(saved(&sim, "root.blocked.example", &catalog, &journal) == D2KM_APPLIED);
    if (!catalog.knowledge.count) return;
    char root[D2KM_KNOWLEDGE_WHY_MAX];
    const char *end = strchr(catalog.knowledge.entries[0].why, '\n');
    CHECK(end != NULL);
    if (!end) return;
    size_t root_length = (size_t)(end + 1 - catalog.knowledge.entries[0].why);
    memcpy(root, catalog.knowledge.entries[0].why, root_length); root[root_length] = 0;
    /* A metadata-looking string is still reason text. It must survive root
     * copying, including escaped quotes, backslashes and a newline. */
    d2km_why extra = {.task = &catalog.knowledge.entries[0].context,
        .step = D2KM_STEP_EXPERIMENT,
        .reason = "literal {\"step\":\"knowledge\"}, backslash \\ and newline\n"};
    char extra_record[1600];
    size_t extra_length = d2km_why_format(&extra, 123456, extra_record, sizeof extra_record);
    CHECK(extra_length < sizeof extra_record);
    size_t used = strlen(catalog.knowledge.entries[0].why);
    CHECK(used + extra_length < sizeof catalog.knowledge.entries[0].why);
    memcpy(catalog.knowledge.entries[0].why + used, extra_record, extra_length + 1);
    unsigned long long root_id = 0;
    CHECK(sscanf(root, "{\"id\":\"W%llu\"", &root_id) == 1 && root_id != 0);
    char link[80]; snprintf(link, sizeof link, "\"links\":[\"W%llu\"]", root_id);
    uint64_t hash = catalog.knowledge.entries[0].hash;
    size_t maximum_archive = 0;
    d2km_store_error error;
    for (unsigned i = 0; i < 20; i++) {
        /* Select the immediately preceding target so the test cannot pass by
         * repeatedly copying the short original archive on timestamp ties. */
        for (size_t j = 0; j < catalog.knowledge.count; j++)
            catalog.knowledge.entries[j].last_success_ms = j + 1;
        d2km_knowledge source = catalog.knowledge.entries[catalog.knowledge.count - 1];
        char name[100]; snprintf(name, sizeof name, "chain%02u.blocked.example", i);
        d2km_outcome outcome = saved(&sim, name, &catalog, &journal);
        if (outcome != D2KM_APPLIED)
            fprintf(stderr, "archive transfer %u: %s (%s), source archive=%zu\n",
                i + 1, d2km_outcome_name(outcome), rep.reason, strlen(source.why));
        CHECK(outcome == D2KM_APPLIED);
        if (outcome != D2KM_APPLIED) break;
        CHECK(rep.from_own && rep.questions == 0 && rep.experiments == 3 && rep.runs == 6);
        CHECK(!memcmp(&source, &catalog.knowledge.entries[i], sizeof source));
        const d2km_knowledge *current = &catalog.knowledge.entries[catalog.knowledge.count - 1];
        CHECK(current->hash == hash && strstr(current->why, root));
        CHECK(strstr(current->why, extra_record) && strstr(current->why, link));
        CHECK(strstr(current->why, name));
        if (i) CHECK(!strstr(current->why, source.context.target.name));
        size_t length = strlen(current->why);
        if (!maximum_archive) maximum_archive = length;
        /* E/W decimal identifiers grow; target validation history must not. */
        CHECK(length <= maximum_archive + 64);
        CHECK(d2km_store_save(path, &catalog, &error) == D2KM_STORE_OK);
        CHECK(d2km_store_load(path, &restored, &error) == D2KM_STORE_OK);
        CHECK(!memcmp(current, &restored.knowledge.entries[restored.knowledge.count - 1], sizeof *current));
        catalog = restored;
    }
    CHECK(catalog.knowledge.count == 21);
    d2km_journal_close(&journal);
    unlink(path); unlink(log); rmdir(dir);
}

/* Field G: a new form of the same name must validate its existing program
 * before asking the box again. No box model is available in this regression. */
static void own_second_form(void)
{
    d2km_sim sim = {.blocked_suffix="blocked.example", .reads_name=1,
        .reassembles=0, .box_hop=2, .server_hop=10};
    d2km_store_init(&catalog);
    CHECK(saved(&sim,"a.blocked.example",&catalog,NULL)==D2KM_APPLIED);
    d2km_knowledge first=catalog.knowledge.entries[0];
    catalog.boxes.count=0;
    saved_form=1;
    CHECK(saved(&sim,"a.blocked.example",&catalog,NULL)==D2KM_APPLIED);
    CHECK(rep.from_own && rep.questions==0 && rep.runs==6);
    CHECK(catalog.knowledge.count==2);
    CHECK(!memcmp(&first,&catalog.knowledge.entries[0],sizeof first));
    CHECK(catalog.knowledge.entries[1].context.form.grease==1);
    /* A failure on the second form cannot degrade the first form. */
    restored=catalog;restored.knowledge.count=1;restored.boxes.count=0;
    own_fault_kind=D2KM_R_LOCAL_FAIL;
    CHECK(saved(&sim,"a.blocked.example",&restored,NULL)==D2KM_LOCAL_FAIL);
    CHECK(!memcmp(&first,&restored.knowledge.entries[0],sizeof first));
    own_fault_kind=0;
    d2km_sim different=sim;different.reassembles=1;
    restored=catalog;restored.knowledge.count=1;restored.boxes.count=0;
    CHECK(saved(&different,"a.blocked.example",&restored,NULL)==D2KM_APPLIED);
    CHECK(!rep.from_own && rep.questions>0);
    CHECK(!memcmp(&first,&restored.knowledge.entries[0],sizeof first));
    saved_form=0;
}

static void own_archive_contract(void)
{
    d2km_sim sim = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 0, .box_hop = 2, .server_hop = 10};
    d2km_store_init(&catalog);
    saved_contract = "doh-contract-v1 path=/dns-query replies>=20 span>=30000ms";
    CHECK(saved(&sim, "a.blocked.example", &catalog, NULL) == D2KM_APPLIED);
    CHECK(strstr(catalog.knowledge.entries[0].why, saved_contract));
    d2km_knowledge source = catalog.knowledge.entries[0];
    saved_contract = NULL;
    CHECK(saved(&sim, "b.blocked.example", &catalog, NULL) == D2KM_APPLIED);
    CHECK(rep.from_own && !strstr(catalog.knowledge.entries[1].why, "doh-contract-v1"));
    CHECK(!memcmp(&source, &catalog.knowledge.entries[0], sizeof source));
    saved_contract = "doh-contract-v1 path=/other replies>=20 span>=30000ms";
    CHECK(saved(&sim, "b.blocked.example", &catalog, NULL) == D2KM_APPLIED);
    const d2km_knowledge *current = &catalog.knowledge.entries[1];
    char proof[1200];
    CHECK(d2km_application_proof(proof, sizeof proof, &current->context, current->hash, saved_contract));
    CHECK(strstr(current->why, proof));
    CHECK(!strstr(current->why, "path=/dns-query"));
    saved_contract = NULL;
}

static void own_edges(void)
{
    d2km_sim sim = {.blocked_suffix = "blocked.example", .reads_name = 1,
        .reassembles = 0, .box_hop = 2, .server_hop = 10};
    d2km_store_init(&catalog);
    CHECK(saved(&sim, "a.blocked.example", &catalog, NULL) == D2KM_APPLIED);
    d2km_knowledge initial = catalog.knowledge.entries[0];
    /* Внешний ведущий мог восстановить только наборы, а не свои счётчики.
       Источники фактов и испытаний не получают повторно старые E/F. */
    restored = catalog; restored.next_experiment = 1; restored.next_fact = 1;
    CHECK(saved(&sim, "b.blocked.example", &restored, NULL) == D2KM_APPLIED);
    CHECK(restored.knowledge.entries[1].experiment > initial.experiment);
    CHECK(restored.next_fact > catalog.next_fact);
    /* Повторное OWN и перезапуск сохраняют ВСЁ исходное обоснование. */
    restored = catalog;
    char proof[D2KM_KNOWLEDGE_WHY_MAX]; strcpy(proof, initial.why);
    for (int i = 0; i < 12; i++) {
        CHECK(saved(&sim, "a.blocked.example", &restored, NULL) == D2KM_APPLIED);
        CHECK(rep.from_own && strstr(restored.knowledge.entries[0].why, proof));
    }
    char dir[] = "/tmp/d2km-own-repeat-XXXXXX", path[128];
    CHECK(mkdtemp(dir) != NULL); snprintf(path, sizeof path, "%s/store", dir);
    d2km_store_error err;
    CHECK(d2km_store_save(path, &restored, &err) == D2KM_STORE_OK);
    CHECK(d2km_store_load(path, &restored, &err) == D2KM_STORE_OK);
    CHECK(strstr(restored.knowledge.entries[0].why, proof));
    unlink(path); rmdir(dir);
    /* IPv6 имеет собственную привязку. Её отказ не отменяет рабочий IPv4.
       Точная запись испытывается даже без общей коробки-кандидата. */
    restored = catalog;
    restored.knowledge.entries[1] = initial;
    restored.knowledge.entries[1].id = 2;
    restored.knowledge.entries[1].context.family = D2KM_IPV6;
    restored.knowledge.count = 2;
    d2km_sim different = sim; different.reassembles = 1;
    saved_family = D2KM_IPV6;
    CHECK(saved(&different, "a.blocked.example", &restored, NULL) == D2KM_APPLIED);
    CHECK(!rep.from_own);
    saved_family = D2KM_IPV4;
    CHECK(saved(&sim, "a.blocked.example", &restored, NULL) == D2KM_APPLIED);
    CHECK(rep.from_own && rep.questions == 0 && rep.program.split_count == 1);
    for (int variant = 0; variant < 2; variant++) {
        restored = catalog; restored.knowledge.count = 2;
        restored.knowledge.entries[1] = initial; restored.knowledge.entries[1].id = 2;
        if (variant == 0) {
            saved_form = 1; restored.knowledge.entries[1].context.form.grease = 1;
        } else {
            saved_path = 1; strcpy(restored.knowledge.entries[1].context.path.ifname, "other0");
        }
        CHECK(saved(&different, "a.blocked.example", &restored, NULL) == D2KM_APPLIED);
        CHECK(!rep.from_own);
        saved_form = saved_path = 0;
        CHECK(saved(&sim, "a.blocked.example", &restored, NULL) == D2KM_APPLIED);
        CHECK(rep.from_own && rep.questions == 0 && rep.program.split_count == 1);
    }
    /* Ресурс отрицательного знания не должен мешать DIRECT_OK. */
    restored = catalog; restored.boxes.count = 2;
    restored.boxes.entries[1] = restored.boxes.entries[0]; restored.boxes.entries[1].id = 2;
    for (size_t i = 0; i < 33; i++) {
        d2km_counterexample cex = {.candidate = i + 1, .experiment = (uint32_t)i + 100,
            .result = {.kind = D2KM_R_RST}};
        CHECK(d2km_target_name(&cex.target, "open.example") == 0);
        cex.context = initial.context; cex.context.target = cex.target;
        CHECK(d2km_box_add_counter(&restored.boxes.entries[i / 32], &cex) == D2KM_BOX_OK);
    }
    CHECK(saved(&sim, "open.example", &restored, NULL) == D2KM_DIRECT_OK);
    CHECK(rep.experiments == 1);
    /* Точное имя важнее свежего знания другой цели. На новой цели — наоборот. */
    catalog.knowledge.count = 2;
    catalog.knowledge.entries[1] = initial;
    d2km_knowledge *fresh = &catalog.knowledge.entries[1];
    fresh->id = 2; fresh->program.splits[0].offset = 2;
    fresh->hash = d2km_program_hash(&fresh->program);
    CHECK(d2km_target_name(&fresh->context.target, "z.blocked.example") == 0);
    catalog.knowledge.entries[0].last_success_ms = 1;
    fresh->last_success_ms = UINT64_MAX;
    restored = catalog;
    CHECK(saved(&sim, "a.blocked.example", &restored, NULL) == D2KM_APPLIED);
    CHECK(rep.from_own && rep.program.splits[0].offset == 1 && restored.knowledge.count == 2);
    restored = catalog;
    CHECK(saved(&sim, "new.blocked.example", &restored, NULL) == D2KM_APPLIED);
    CHECK(rep.from_own && rep.program.splits[0].offset == 2);
    /* Этот hash уже опровергнут на данной цели: пробуется другой. */
    restored = catalog;
    d2km_counterexample ce = {.candidate = fresh->hash, .experiment = 100,
        .receipt = 101, .result = {.kind = D2KM_R_RST}};
    CHECK(d2km_target_name(&ce.target, "new.blocked.example") == 0);
    ce.context = initial.context; ce.context.target = ce.target;
    CHECK(d2km_box_add_counter(&restored.boxes.entries[0], &ce) == D2KM_BOX_OK);
    CHECK(saved(&sim, "new.blocked.example", &restored, NULL) == D2KM_APPLIED);
    CHECK(rep.from_own && rep.program.splits[0].offset == 1);
    /* Версия TLS и семейство не объединяются в одну привязку. */
    for (int mode = 0; mode < 2; mode++) {
        restored = catalog; restored.knowledge.count = 1;
        if (!mode) {
            restored.knowledge.entries[0].context.protocol = D2KM_P_TLS12;
            restored.knowledge.entries[0].program.protocol = D2KM_P_TLS12;
        } else restored.knowledge.entries[0].context.family = D2KM_IPV6;
        restored.knowledge.entries[0].hash = d2km_program_hash(&restored.knowledge.entries[0].program);
        CHECK(saved(&sim, "new.blocked.example", &restored, NULL) == D2KM_APPLIED);
        CHECK(!rep.from_own && rep.questions > 0);
    }
    /* Кандидат отвергнут базовым плечом — его знание не испытывается. */
    restored = catalog; restored.knowledge.count = 1;
    restored.boxes.entries[0].facts[0].ra.kind = D2KM_R_APP_OK;
    CHECK(saved(&sim, "new.blocked.example", &restored, NULL) == D2KM_APPLIED);
    CHECK(!rep.from_own && rep.questions > 0 && restored.boxes.count == 2);
    /* Ошибки измерения OWN не становятся отрицательным знанием. */
    const int failures[] = {D2KM_R_LOCAL_FAIL, D2KM_R_NOT_MEASURED, D2KM_R_RST};
    const d2km_outcome want[] = {D2KM_LOCAL_FAIL, D2KM_NOT_MEASURED, D2KM_CONFLICTING};
    for (size_t i = 0; i < sizeof failures / sizeof failures[0]; i++) {
        restored = catalog; restored.knowledge.count = 1;
        own_fault_kind = failures[i]; own_fault_runs = 0;
        CHECK(saved(&sim, "a.blocked.example", &restored, NULL) == want[i]);
        CHECK(rep.state == D2KM_T_WAIT && !rep.from_own && rep.questions == 0);
        CHECK(box.counter_count == 0 && restored.knowledge.entries[0].history_count == 0);
        own_fault_kind = 0;
    }
    /* Подтверждённая деградация и замена сохраняют hash ПРЕЖНЕЙ программы. */
    restored = catalog; restored.knowledge.count = 1;
    d2km_sim other = sim; other.reassembles = 1;
    CHECK(saved(&other, "a.blocked.example", &restored, NULL) == D2KM_APPLIED);
    CHECK(!rep.from_own && restored.knowledge.count == 1 && restored.boxes.count == 2);
    const d2km_knowledge *changed = &restored.knowledge.entries[0];
    CHECK(changed->hash != initial.hash && changed->history_count == 2);
    CHECK(changed->history[0].outcome == D2KM_DEGRADED && changed->history[0].previous_hash == initial.hash);
    CHECK(changed->history[1].outcome == D2KM_APPLIED && changed->history[1].previous_hash == initial.hash);
    restored = catalog; restored.knowledge.count = 1;
    restored.knowledge.entries[0].history_count = D2KM_KNOWLEDGE_HISTORY_MAX;
    for (size_t i = 0; i < D2KM_KNOWLEDGE_HISTORY_MAX; i++)
        restored.knowledge.entries[0].history[i] = (d2km_knowledge_history){
            .time_ms = i + 1, .previous_hash = i + 100, .experiment = 1, .outcome = D2KM_APPLIED};
    CHECK(saved(&other, "a.blocked.example", &restored, NULL) == D2KM_APPLIED);
    changed = &restored.knowledge.entries[0];
    CHECK(changed->history_count == D2KM_KNOWLEDGE_HISTORY_MAX && changed->history[0].previous_hash == 102);
    CHECK(changed->history[D2KM_KNOWLEDGE_HISTORY_MAX - 2].outcome == D2KM_DEGRADED &&
        changed->history[D2KM_KNOWLEDGE_HISTORY_MAX - 1].outcome == D2KM_APPLIED);
    /* Исчерпание каталога даёт WAIT, а не ложное «знание записано». */
    restored = catalog;
    restored.knowledge.count = D2KM_STORE_KNOWLEDGE_MAX;
    for (size_t i = 0; i < restored.knowledge.count; i++) {
        restored.knowledge.entries[i] = initial;
        restored.knowledge.entries[i].id = (uint32_t)i + 1;
    }
    CHECK(saved(&sim, "new.blocked.example", &restored, NULL) == D2KM_NO_RESOURCES);
    CHECK(rep.state == D2KM_T_WAIT && !rep.from_own && restored.knowledge.count == D2KM_STORE_KNOWLEDGE_MAX);
    /* Повтор после провала: контрпример пережил новый запуск, hash пропущен. */
    restored = catalog; restored.knowledge.count = 1;
    ce.candidate = initial.hash;
    CHECK(d2km_target_name(&ce.target, "new.blocked.example") == 0);
    ce.context = initial.context; ce.context.target = ce.target;
    CHECK(d2km_box_add_counter(&restored.boxes.entries[0], &ce) == D2KM_BOX_OK);
    CHECK(saved(&sim, "new.blocked.example", &restored, NULL) == D2KM_APPLIED);
    CHECK(!rep.from_own && rep.program.fake_count == 1);
    CHECK(restored.boxes.count == 1 && restored.boxes.entries[0].version > catalog.boxes.entries[0].version);
    CHECK(memcmp(&restored.boxes.entries[0].facts[0], &catalog.boxes.entries[0].facts[0],
        sizeof(d2km_fact)) == 0); /* согласованное продолжение сохраняет прежний факт */
}

int main(void)
{
    /* 1. Коробка читает имя и не собирает сегменты — достаточно разреза. */
    d2km_sim s1 = {.blocked_suffix = "blocked.example", .reads_name = 1, .reassembles = 0, .box_hop = 5, .server_hop = 11, .server_down = 0, .reference_down = 0, .flaky_every = 0, .late_cut = 0};
    CHECK(go(&s1, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.state == D2KM_T_APPLIED);
    CHECK(rep.program.split_count == 1 && rep.program.fake_count == 0);
    CHECK(strstr(rep.program.splits[0].why, "F") != NULL);
    CHECK(rep.runs < 40);   /* вопросы, а не перебор */

    /* 2. Коробка собирает сегменты — фальшивка с TTL = хоп коробки. */
    d2km_sim s2 = {.blocked_suffix = "blocked.example", .reads_name = 1, .reassembles = 1, .box_hop = 5, .server_hop = 11, .server_down = 0, .reference_down = 0, .flaky_every = 0, .late_cut = 0};
    CHECK(go(&s2, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.fake_count == 1 && rep.program.fakes[0].poison.ttl == 5);
    CHECK(rep.program.split_count == 0);
    CHECK(d2km_program_check(&rep.program) == D2KM_PC_OK);
    /* Хопы найдены поиском, не перебором 1..255. */
    CHECK(rep.runs < 120);

    /* 3. Коробка на хопе сервера — фальшивку, видимую коробке, получит и
       сервер: требования несовместимы, задача ждёт. */
    d2km_sim s3 = {.blocked_suffix = "blocked.example", .reads_name = 1, .reassembles = 1, .box_hop = 11, .server_hop = 11, .server_down = 0, .reference_down = 0, .flaky_every = 0, .late_cut = 0};
    CHECK(go(&s3, "blocked.example", NULL) == D2KM_REQ_CONFLICT);
    CHECK(rep.state == D2KM_T_WAIT);

    /* 4. Цель не блокируется — обходить нечего, вопросов нет. */
    d2km_sim s4 = {.blocked_suffix = "blocked.example", .reads_name = 1, .reassembles = 1, .box_hop = 5, .server_hop = 11, .server_down = 0, .reference_down = 0, .flaky_every = 0, .late_cut = 0};
    CHECK(go(&s4, "open.example", NULL) == D2KM_DIRECT_OK);
    CHECK(rep.state == D2KM_T_CLOSED && rep.experiments == 1);

    /* 5. Сервер лежит — не «блок», не «обход». */
    d2km_sim s5 = {.blocked_suffix = "blocked.example", .reads_name = 1, .reassembles = 1, .box_hop = 5, .server_hop = 11, .server_down = 1, .reference_down = 0, .flaky_every = 0, .late_cut = 0};
    CHECK(go(&s5, "blocked.example", NULL) == D2KM_SERVER_DOWN);
    CHECK(rep.state == D2KM_T_CLOSED);

    /* 6. Опорная точка недоступна, но сервер сам доказал, что жив (другое
       имя даёт полный ответ): внешний сервис не нужен, обход найден. */
    d2km_sim s6 = {.blocked_suffix = "blocked.example", .reads_name = 1, .reassembles = 0, .box_hop = 5, .server_hop = 11, .reference_down = 1};
    CHECK(go(&s6, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(s6.runs < 40);

    /* 6b. Блок адреса: тишина с любым именем, истории нет. Изнутри не
       отличить от мёртвого сервера — без опорной точки NO_REFERENCE. */
    d2km_sim s6b = {.blocked_suffix = "blocked.example", .box_hop = 5, .server_hop = 11, .reference_down = 1, .addr_block = 1};
    CHECK(go(&s6b, "blocked.example", NULL) == D2KM_NO_REFERENCE);
    CHECK(rep.state == D2KM_T_WAIT);
    /* С опорной точкой — блок подтверждён; вопросов, различающих гипотезы,
       для блока адреса пока нет — честный MODEL_INCOMPLETE, не перебор. */
    d2km_sim s6c = {.blocked_suffix = "blocked.example", .box_hop = 5, .server_hop = 11, .addr_block = 1};
    CHECK(go(&s6c, "blocked.example", NULL) == D2KM_MODEL_INCOMPLETE);
    /* Чистый обмен в истории — доказательство живости без внешнего сервиса. */
    history = "чистый обмен с тем же адресом 10 минут назад (событие датапата)";
    d2km_sim s6d = {.blocked_suffix = "blocked.example", .box_hop = 5, .server_hop = 11, .reference_down = 1, .addr_block = 1};
    CHECK(go(&s6d, "blocked.example", NULL) == D2KM_MODEL_INCOMPLETE);
    history = NULL;

    /* 7. Потери в сети — правило повтора, итог тот же. */
    d2km_sim s7 = {.blocked_suffix = "blocked.example", .reads_name = 1, .reassembles = 0, .box_hop = 5, .server_hop = 11, .server_down = 0, .reference_down = 0, .flaky_every = 5, .late_cut = 0};
    CHECK(go(&s7, "blocked.example", NULL) == D2KM_APPLIED);
    CHECK(rep.program.split_count == 1);

    /* 7b. Блок не по первому приветствию (как instagram в поле 08.11):
       коробка не реагирует на приветствие до сервера — фальшивки нет. */
    d2km_sim s7b = {.blocked_suffix = "blocked.example", .reads_name = 1, .reassembles = 1, .box_hop = 5, .server_hop = 11, .server_down = 0, .reference_down = 0, .flaky_every = 0, .late_cut = 1};
    CHECK(go(&s7b, "blocked.example", NULL) == D2KM_MODEL_INCOMPLETE);
    CHECK(rep.program.fake_count == 0);

    /* 8. Журнал «почему»: каждый шаг записан, итог — знание. */
    const char *tmpd = getenv("TMPDIR");
    char dir[512], path[600];
    snprintf(dir, sizeof dir, "%s/d2km-task-XXXXXX", tmpd && *tmpd ? tmpd : "/tmp");
    CHECK(mkdtemp(dir) != NULL);
    snprintf(path, sizeof path, "%s/why.jsonl", dir);
    d2km_journal j;
    CHECK(d2km_journal_open(&j, path, 1 << 20) == 0);
    d2km_sim s8 = {.blocked_suffix = "blocked.example", .reads_name = 1, .reassembles = 1, .box_hop = 5, .server_hop = 11, .server_down = 0, .reference_down = 0, .flaky_every = 0, .late_cut = 0};
    CHECK(go(&s8, "blocked.example", &j) == D2KM_APPLIED);
    CHECK(j.next_id > 6);
    d2km_journal_close(&j);
    FILE *f = fopen(path, "r");
    static char all[1 << 16];
    size_t got = f ? fread(all, 1, sizeof all - 1, f) : 0;
    if (f) fclose(f);
    all[got] = 0;
    CHECK(strstr(all, "\"step\":\"direct\"") && strstr(all, "\"outcome\":\"BLOCK_CONFIRMED\""));
    CHECK(strstr(all, "\"step\":\"question\"") && strstr(all, "\"step\":\"synth\""));
    CHECK(strstr(all, "\"step\":\"knowledge\"") && strstr(all, "\"outcome\":\"APPLIED\""));
    CHECK(strstr(all, "хоп коробки") && strstr(all, "хоп сервера"));
    /* Кандидат записан с происхождением: TTL и имя со ссылками на факты. */
    CHECK(strstr(all, "\"derivation\":[\"приветствие по форме клиента") != NULL);
    CHECK(strstr(all, "TTL 5: с этого хопа коробка реагирует") != NULL);
    unlink(path);
    rmdir(dir);
    extensions();
    own_knowledge();
    own_archive_chain();
    own_archive_contract();
    own_second_form();
    own_edges();
    DONE("test_task");
}
