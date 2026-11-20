#define _POSIX_C_SOURCE 200809L
#include "d2km_task.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* Состояние одного прохода ведущего. */
typedef struct {
    int exec_refused;                /* исполнитель отказался исполнить плечо */
    d2km_tls_task *t;
    d2km_task_report *rep;
    d2km_task_state state;
    d2km_arm_record base, control;   /* прямой обмен и контроль через опорную точку */
    d2km_result reference;           /* исход контроля */
    uint32_t name_fact, assembly_asked, name_asked;
    unsigned spoil_asked;          /* биты кодов 1..3 */
    int box_hop_unmeasurable;      /* реакция коробки — тишина: хоп по TTL не измерить */
    unsigned copies_asked;         /* биты методов R0..R3 */
    unsigned split_asked;          /* исчерпанные позиции 1,3,5,SNI+1 */
    unsigned combination_asked[4]; /* устойчивый ответ каждого R на позиции */
    d2km_arm_record split_answers[4]; /* standalone измеряется только один раз */
    int fact_error;
    long candidate_box;
    int published;
    char proof[D2KM_KNOWLEDGE_WHY_MAX];
    uint64_t proof_id;
    d2km_experiment current_question;
} run;

static uint64_t wall_ms(void);
static uint32_t allocate_id(run *r, uint32_t *next)
{
    uint32_t *shared=next==&r->t->next_fact?r->t->shared_fact:r->t->shared_experiment;
    if(shared) {if(*shared<*next)*shared=*next;next=shared;}
    if (*next == 0 || *next == UINT32_MAX) { r->fact_error = D2KM_NO_RESOURCES; return 0; }
    return (*next)++;
}

static void note(run *r, d2km_step step, d2km_outcome out, const uint32_t *facts,
                 size_t nf, const char *reason)
{
    if (r->t->journal == NULL)
        return;
    d2km_why w;
    memset(&w, 0, sizeof(w));
    w.time_ms = wall_ms();
    w.task = r->t->context;
    w.step = step;
    w.outcome = out;
    w.facts = facts;
    w.fact_count = nf;
    w.reason = reason;
    d2km_journal_append(r->t->journal, &w, NULL);
}

static int go(run *r, d2km_task_event_kind k, d2km_outcome o)
{
    d2km_task_event ev = {.kind = k, .outcome = o};
    d2km_task_state n = d2km_task_next(r->state, &ev);
    if (n == 0)
        return -1;
    r->state = n;
    return 0;
}

/* Плечо по правилу повтора §5.2. */
static d2km_arm_verdict stable_any(run *r, d2km_arm_spec *spec, uint32_t e, d2km_result *out,
                                   int *any_ok);
static d2km_arm_verdict stable(run *r, d2km_arm_spec *spec, uint32_t e, d2km_result *out)
{
    return stable_any(r, spec, e, out, NULL);
}

/* any_ok — был ли среди прогонов прикладной успех (для пути до сервера). */
static d2km_arm_verdict stable_any(run *r, d2km_arm_spec *spec, uint32_t e, d2km_result *out,
                                   int *any_ok)
{
    if (!e) return D2KM_ARM_LOCAL_FAIL;
    d2km_result runs[D2KM_ARM_RUNS_MAX];
    size_t n = 0;
    spec->experiment = e;
    if (spec->context == NULL) spec->context = r->t->context;
    r->rep->experiments++;
    unsigned local_fails = 0;
    for (;;) {
        d2km_observation obs;
        if (r->t->net->run(r->t->net->ctx, spec, &obs, &runs[n]) != 0) {
            r->exec_refused = 1;
            return D2KM_ARM_LOCAL_FAIL;
        }
        r->rep->runs++;
        /* §5.2: прогон с локальной ошибкой — не наблюдение коробки, в правило
           повтора не входит; три подряд — устойчивая поломка своей стороны. */
        if (runs[n].kind == D2KM_R_LOCAL_FAIL && ++local_fails < D2KM_LOCAL_FAILS_MAX) {
            note(r, D2KM_STEP_EXPERIMENT, 0, NULL, 0,
                 "прогон с локальной ошибкой — не ответ коробки, плечо прогоняется заново");
            continue;
        }
        if (runs[n].kind != D2KM_R_LOCAL_FAIL) local_fails = 0;
        if (any_ok && runs[n].kind == D2KM_R_APP_OK) *any_ok = 1;
        n++;
        d2km_arm_verdict v = d2km_arm_stability(runs, n, out);
        if (v != D2KM_ARM_NEED_MORE) {
            if (v == D2KM_ARM_STABLE && r->current_question.id == e) {
                unsigned confirmed, refuted;
                if (d2km_experiment_judge(&r->current_question, *out, &confirmed, &refuted) >= 0)
                    d2km_box_judge(r->t->box, &r->current_question, confirmed, refuted);
            }
            /* Наблюдения плеча — в запись «почему»: исходы всех прогонов. */
            if (r->t->journal != NULL) {
                char obs_text[200], reason[120];
                size_t k = 0;
                for (size_t i = 0; i < n && k < sizeof(obs_text) - 40; i++) {
                    int w = snprintf(obs_text + k, sizeof(obs_text) - k, "%s%s(%lld)", i ? " " : "",
                                     d2km_result_name(runs[i].kind) ? d2km_result_name(runs[i].kind) : "?",
                                     (long long)runs[i].value);
                    if (w > 0) k += (size_t)w;
                }
                snprintf(reason, sizeof(reason), "E%u: плечо %s, прогонов %zu",
                         (unsigned)e, v == D2KM_ARM_STABLE ? "устойчиво" : "без устойчивого исхода", n);
                d2km_why w;
                memset(&w, 0, sizeof(w));
                w.time_ms = wall_ms();
                w.task = r->t->context;
                w.step = D2KM_STEP_EXPERIMENT;
                w.observations = obs_text;
                w.reason = reason;
                d2km_journal_append(r->t->journal, &w, NULL);
            }
            return v;
        }
    }
}

static d2km_arm_record record(run *r, uint32_t e, int has, d2km_operator op,
                              uint32_t field, int64_t value, d2km_result res)
{
    d2km_arm_record a;
    memset(&a, 0, sizeof(a));
    a.experiment = e;
    a.context = *r->t->context;
    a.arm.has_action = has;
    a.arm.action.op = op;
    a.arm.action.field = field;
    a.arm.action.value = value;
    a.result = res;
    return a;
}

static d2km_signal signal_of(d2km_result res)
{
    switch (res.kind) {
    case D2KM_R_SYN_SILENT: return D2KM_S_SYN_SILENT;
    case D2KM_R_HELLO_SILENT: return D2KM_S_HELLO_SILENT;
    case D2KM_R_CUT: return D2KM_S_LATE_CUT;
    default: return D2KM_S_RST;
    }
}

static d2km_outcome publish_model(run *);

static d2km_outcome finish(run *r, d2km_outcome o, d2km_step step, const char *reason)
{
    if (r->fact_error == D2KM_NO_RESOURCES) { o = D2KM_NO_RESOURCES; reason = "NO_RESOURCES: идентификатор или модель исчерпаны"; }
    if (!r->rep->from_own && o != D2KM_DIRECT_OK && o != D2KM_SERVER_DOWN && o != D2KM_NO_REFERENCE &&
        (r->t->box->fact_count || r->t->box->counter_count)) {
        d2km_outcome stored = publish_model(r);
        if (stored) { o = stored; reason = "NO_RESOURCES: модель не помещается в каталог"; }
    }
    if (r->state != D2KM_T_CLOSED && r->state != D2KM_T_APPLIED &&
        r->state != D2KM_T_WAIT)
        go(r, D2KM_EV_OUTCOME, o);
    r->rep->outcome = o;
    r->rep->state = r->state;
    snprintf(r->rep->reason, sizeof(r->rep->reason), "%s", reason);
    note(r, step, o, NULL, 0, reason);
    return o;
}

static void add_fact(run *r, d2km_fact *f, const char *what)
{
    size_t conflict;
    d2km_box_code added = d2km_box_add_fact(r->t->box, f, &conflict);
    if (added != D2KM_BOX_OK && added != D2KM_BOX_DUPLICATE) {
        r->fact_error = added == D2KM_BOX_FULL ? D2KM_NO_RESOURCES : D2KM_MODEL_INCOMPLETE;
        return;
    }
    char buf[300];
    snprintf(buf, sizeof(buf), "%s: F%u (%s)", what, (unsigned)f->id,
             f->level == D2KM_LEVEL_ESTABLISHED ? "установленный" : "наблюдённый");
    note(r, D2KM_STEP_EXPERIMENT, 0, &f->id, 1, buf);
}

/* Вопрос «коробка читает имя?»: приветствие клиента с пропускаемым именем. */
static int ask_name(run *r)
{
    static __thread d2km_tls_hello h;
    static __thread uint8_t bytes[D2KM_TLS_MAX + 5];
    if (d2km_tls_parse(r->t->hello, r->t->hello_length, &h) != D2KM_TLS_OK ||
        d2km_tls_set_sni(&h, r->t->pass_name) != D2KM_TLS_OK)
        return -1;
    size_t n = d2km_tls_build(&h, bytes, sizeof(bytes));
    d2km_arm_spec spec = {.kind = D2KM_ARM_EXCHANGE, .hello = bytes, .hello_length = n};
    /* Вопрос записан до отправки: гипотезы, воздействие, прогнозы (§6.1). */
    d2km_experiment q;
    memset(&q, 0, sizeof(q));
    q.prediction_count = 4;
    q.predictions[0] = (d2km_prediction){.hypothesis = D2KM_H_HELLO_NAME, .predicted = {.kind = D2KM_R_APP_OK}};
    q.predictions[1] = (d2km_prediction){.hypothesis = D2KM_H_HELLO_FIELD, .predicted = r->base.result};
    q.predictions[2] = (d2km_prediction){.hypothesis = D2KM_H_HELLO_FORM, .predicted = r->base.result};
    q.predictions[3] = (d2km_prediction){.hypothesis = D2KM_H_ADDR_AFTER_HELLO, .predicted = r->base.result};
    if (r->state != D2KM_T_DIRECT) r->rep->questions++;
    note(r, r->state == D2KM_T_DIRECT ? D2KM_STEP_DIRECT : D2KM_STEP_QUESTION, 0, NULL, 0,
         "вопрос: читает ли коробка имя — то же приветствие с другим именем");
    d2km_result res;
    uint32_t e = allocate_id(r, &r->t->next_experiment);
    d2km_arm_verdict v = stable(r, &spec, e, &res);
    r->name_asked = 1;
    if (v != D2KM_ARM_STABLE)
        return (int)d2km_arm_verdict_outcome(v);
    /* Своё плечо с прикладным успехом само доказывает, что сервер жив: оно и
       есть контроль, если другого ещё нет (§4.3 п. 1). */
    /* Ответ сервера тоже доказывает живость: сервер прислал данные TLS, а
       обмен не сложился (сертификата на чужое имя у него нет). */
    if (r->control.experiment == 0 &&
        (res.kind == D2KM_R_APP_OK || res.kind == D2KM_R_REPLY)) {
        r->control = record(r, e, 1, D2KM_OP_SET_FIELD, D2KM_TLS_F_SNI, 1, res);
        r->reference = res;
    }
    unsigned c, f;
    if (d2km_experiment_judge(&q, res, &c, &f) >= 0)
        d2km_box_judge(r->t->box, &q, c, f);
    d2km_arm_record arm = record(r, e, 1, D2KM_OP_SET_FIELD, D2KM_TLS_F_SNI, 1, res);
    d2km_fact fact;
    uint32_t id = allocate_id(r, &r->t->next_fact);
    if (d2km_fact_establish(&fact, id, D2KM_F_PARSE, &r->base, &arm, &r->control,
                            r->reference, 0, r->t->box->version + 1) == D2KM_FR_OK) {
        r->name_fact = id;
        add_fact(r, &fact, "коробка читает имя: с другим именем прикладной успех");
    } else if (d2km_fact_establish_invariance(&fact, id, D2KM_F_PARSE, &r->base, &arm,
                   &r->control, r->reference, r->t->box->version + 1) == D2KM_FR_OK) {
        add_fact(r, &fact, "смена имени исход не меняет: имя коробка не читает");
    }
    return 0;
}

/* Уточнение второго уровня (§6.2): коробка, читающая имя, собирает ли
   приветствие из сегментов? Разрез сразу после начала имени. */
static int ask_assembly(run *r)
{
    static __thread d2km_program prog;
    memset(&prog, 0, sizeof(prog));
    prog.transport = D2KM_TCP;
    prog.protocol = D2KM_P_TLS13;
    prog.split_count = 1;
    prog.splits[0].anchor = D2KM_AT_SNI_START;
    prog.splits[0].offset = 1;
    snprintf(prog.splits[0].why, sizeof(prog.splits[0].why),
             "вопрос: собирает ли коробка сегменты (коробка читает имя, F%u)",
             (unsigned)r->name_fact);
    d2km_arm_spec spec = {.kind = D2KM_ARM_EXCHANGE, .hello = r->t->hello,
        .hello_length = r->t->hello_length, .program = &prog};
    r->rep->questions++;
    note(r, D2KM_STEP_QUESTION, 0, NULL, 0,
         "вопрос: собирает ли коробка приветствие из сегментов — разрез на имени");
    d2km_result res;
    uint32_t e = allocate_id(r, &r->t->next_experiment);
    d2km_arm_verdict v = stable(r, &spec, e, &res);
    r->assembly_asked = 1;
    if (v != D2KM_ARM_STABLE)
        return (int)d2km_arm_verdict_outcome(v);
    d2km_arm_record arm = record(r, e, 1, D2KM_OP_SPLIT, D2KM_TLS_F_SNI, 1, res);
    d2km_fact fact;
    uint32_t id = allocate_id(r, &r->t->next_fact);
    if (d2km_fact_establish(&fact, id, D2KM_F_ASSEMBLY, &r->base, &arm, &r->control,
                            r->reference, 0, r->t->box->version + 1) == D2KM_FR_OK) {
        /* Текст — по фактическим исходам: смена реакции не значит её снятия. */
        char what[200];
        if (res.kind == D2KM_R_APP_OK)
            snprintf(what, sizeof(what), "коробка не собирает сегменты: разрез на имени снимает реакцию");
        else
            snprintf(what, sizeof(what), "разрез на имени меняет реакцию коробки: %s → %s, но не снимает её",
                     d2km_result_name(r->base.result.kind), d2km_result_name(res.kind));
        add_fact(r, &fact, what);
    }
    else if (d2km_fact_establish_invariance(&fact, id, D2KM_F_ASSEMBLY, &r->base, &arm,
                 &r->control, r->reference, r->t->box->version + 1) == D2KM_FR_OK)
        add_fact(r, &fact, "коробка собирает сегменты: разрез исход не меняет");
    return 0;
}

/* Поиск хопа (§6.5) плечами PATH_*; числовой факт на границе. */
static int search_hop(run *r, d2km_arm_kind kind, uint32_t field, const char *what)
{
    d2km_search s;
    d2km_search_init(&s, 1, 255, 1);
    int64_t v;
    uint32_t ids[300];
    memset(ids, 0, sizeof(ids));
    while (d2km_search_next(&s, &v)) {
        d2km_arm_spec spec = {.kind = kind, .hello = r->t->hello,
            .hello_length = r->t->hello_length, .ttl = (uint8_t)v};
        d2km_result res;
        uint32_t e = allocate_id(r, &r->t->next_experiment);
        int any_ok = 0;
        d2km_arm_verdict verdict = stable_any(r, &spec, e, &res, &any_ok);
        /* Путь до сервера бывает переменной длины (несколько маршрутов): SYN
           с этим TTL то доходит, то нет. Для фальшивки важно «не дойдёт
           никогда», поэтому хоть раз дошедший SYN — это «доходит» (§7.5). */
        if (verdict == D2KM_ARM_CONFLICTING && kind == D2KM_ARM_PATH_SERVER && any_ok) {
            res.kind = D2KM_R_APP_OK;
            res.value = 0;
            verdict = D2KM_ARM_STABLE;
            note(r, D2KM_STEP_EXPERIMENT, 0, NULL, 0,
                 "путь до сервера переменной длины: SYN с этим TTL иногда доходит — считаю «доходит»");
        }
        if (verdict != D2KM_ARM_STABLE)
            return (int)d2km_arm_verdict_outcome(verdict);
        ids[v] = e;
        if (d2km_search_feed(&s, v, res) != 0)
            return (int)D2KM_LOCAL_FAIL;
    }
    if (s.phase != D2KM_SEARCH_BOUNDARY && kind == D2KM_ARM_PATH_BOX &&
        r->base.result.kind == D2KM_R_HELLO_SILENT && d2km_result_equal(s.base, r->base.result)) {
        /* Тишина на всех TTL — и ниже сервера, и дальше: реакция коробки и
           истечение TTL не различаются (поле 11.11, IPv6 к Cloudflare). */
        r->box_hop_unmeasurable = 1;
        note(r, D2KM_STEP_EXPERIMENT, 0, NULL, 0,
             "хоп коробки не измерить: тишина на всех TTL — способ TTL исключён");
        return 0;
    }
    if (s.phase != D2KM_SEARCH_BOUNDARY)
        return (int)D2KM_MODEL_INCOMPLETE;
    /* Хоп коробки — граница, на которой появляется РЕАКЦИЯ коробки. Если на
       границе ответил сервер, коробка на приветствие до сервера не реагирует:
       это другой класс блокировки, и хопа коробки такая граница не даёт. */
    if (kind == D2KM_ARM_PATH_BOX && !d2km_result_is_box_reaction(s.at_hi) &&
        r->base.result.kind == D2KM_R_HELLO_SILENT) {
        /* Коробка глушит приветствие: её реакция — тишина, а тишина ниже хопа
           сервера неотличима от истечения TTL. Хоп коробки так не измерить;
           фальшивке с порчей транспорта он не нужен (поле 11.11, IPv6 к
           Cloudflare: nnmclub, fost.club). */
        r->box_hop_unmeasurable = 1;
        note(r, D2KM_STEP_EXPERIMENT, 0, NULL, 0,
             "хоп коробки не измерить: её реакция — тишина, неотличимая от истечения TTL; способ TTL исключён");
        return 0;
    }
    if (kind == D2KM_ARM_PATH_BOX && !d2km_result_is_box_reaction(s.at_hi)) {
        note(r, D2KM_STEP_EXPERIMENT, 0, NULL, 0,
             "коробка не реагирует на приветствие, не дошедшее до сервера: блок не по первому приветствию");
        return (int)D2KM_MODEL_INCOMPLETE;
    }
    d2km_arm_record lo = record(r, ids[s.lo], 1, D2KM_OP_LIMIT_DELIVERY, field, s.lo, s.base);
    d2km_arm_record hi = record(r, ids[s.hi], 1, D2KM_OP_LIMIT_DELIVERY, field, s.hi, s.at_hi);
    d2km_fact fact;
    uint32_t id = allocate_id(r, &r->t->next_fact);
    if (d2km_fact_establish(&fact, id, D2KM_F_PATH, &lo, &hi, &r->control, r->reference,
                            1, r->t->box->version + 1) != D2KM_FR_OK)
        return (int)D2KM_MODEL_INCOMPLETE;
    char buf[200];
    snprintf(buf, sizeof(buf), "%s: граница между TTL %lld и %lld", what,
             (long long)s.lo, (long long)s.hi);
    add_fact(r, &fact, buf);
    return 0;
}

static int has_path(const d2km_box *b, uint32_t field)
{
    for (size_t i = 0; i < b->fact_count; i++) {
        const d2km_fact *f = &b->facts[i];
        if (d2km_fact_usable(f) && f->numeric && f->a.has_action &&
            f->a.action.op == D2KM_OP_LIMIT_DELIVERY && f->a.action.field == field)
            return 1;
    }
    return 0;
}


static d2km_synth_in synth_input(run *r)
{
    d2km_synth_in in = {.box = r->t->box, .target = &r->t->context->target,
        .client_hello = r->t->hello, .client_hello_length = r->t->hello_length,
        .pass_name = r->name_fact ? r->t->pass_name : NULL,
        .pass_name_fact = r->name_fact, .seed = r->t->seed, .max_payload = r->t->max_payload,
        .box_hop_unmeasurable = r->box_hop_unmeasurable};
    return in;
}

/* Полный вопрос §6.1 записывается до stable(), то есть до первого пакета.
 * Уточнения второго уровня открываются для текущего R/k/позиции.
 * Ответ предыдущего параметра не утверждает исход другого параметра. */
static int question(run *r, d2km_arm_spec *spec, d2km_action action,
                    d2km_result unchanged, const char *reason, uint32_t *e)
{
    r->rep->questions++;
    *e = allocate_id(r, &r->t->next_experiment);
    d2km_experiment q = {.id = *e, .kind = D2KM_E_QUESTION,
        .context = spec->context ? *spec->context : *r->t->context,
        .arm = {.has_action = 1, .action = action},
        .control = {.has_expected = 1, .expected = r->reference},
        .prediction_count = 2, .memory_bytes = sizeof(d2km_program)};
    d2km_hypothesis yes = D2KM_H_HEADER_SPLIT_RELIEF, no = D2KM_H_HEADER_SPLIT_BLOCKED;
    if (action.field == D2KM_FIELD_SPOIL) {
        yes = D2KM_H_SERVER_REJECTS_SPOIL; no = D2KM_H_SERVER_ACCEPTS_SPOIL;
    } else if (action.field == D2KM_FIELD_FAKE_COPIES) {
        yes = D2KM_H_COPIES_ENOUGH; no = D2KM_H_COPIES_INSUFFICIENT;
    } else if (action.field == D2KM_FIELD_FAKE_SPLIT) {
        yes = D2KM_H_COMBINATION_RELIEF; no = D2KM_H_COMBINATION_BLOCKED;
    }
    q.predictions[0] = (d2km_prediction){.hypothesis = yes,
        .predicted = {.kind = D2KM_R_APP_OK}};
    q.predictions[1] = (d2km_prediction){.hypothesis = no,
        .predicted = unchanged.kind == D2KM_R_APP_OK ? r->base.result : unchanged};
    r->t->box->hypotheses[yes] = D2KM_HYP_LIVE;
    r->t->box->hypotheses[no] = D2KM_HYP_LIVE;
    r->current_question = q;
    if (d2km_experiment_check(&q) != D2KM_EC_OK) return D2KM_LOCAL_FAIL;
    if (r->t->journal) {
        d2km_why w = {.task = &q.context, .step = D2KM_STEP_QUESTION,
            .experiment = &q, .reason = reason};
        if (d2km_journal_append(r->t->journal, &w, NULL) != D2KM_WHY_OK)
            return D2KM_LOCAL_FAIL;
    }
    return 0;
}

static unsigned hop(run *r)
{
    for (size_t i = 0; i < r->t->box->fact_count; i++) {
        const d2km_fact *f = &r->t->box->facts[i];
        if (d2km_fact_usable(f) && f->numeric && f->b.has_action &&
            f->b.action.field == D2KM_FIELD_PATH_BOX)
            return (unsigned)f->b.action.value;
    }
    return 0;
}

static int probe_fake(run *r, unsigned method, unsigned copies, d2km_program *p)
{
    d2km_synth_in in = synth_input(r);
    if (d2km_synth_message(&in, p, NULL, 0) != D2KM_SYN_CANDIDATE)
        return D2KM_EXEC_UNSUPPORTED;
    p->fake_count = 1;
    p->fakes[0].payload = 0;
    p->fakes[0].repeats = (uint8_t)copies;
    d2km_synth_poison(&p->fakes[0].poison, method, (uint8_t)hop(r));
    snprintf(p->fakes[0].why, sizeof(p->fakes[0].why),
             "вопрос: метод отвержения R%u, копий %u, имя по F%u", method, copies, r->name_fact);
    return 0;
}

static int available(run *r, unsigned method)
{
    if (!method) return hop(r) != 0;
    for (size_t i = 0; i < r->t->box->fact_count; i++) {
        const d2km_fact *f = &r->t->box->facts[i];
        if (d2km_fact_usable(f) && f->kind == D2KM_F_PATH && f->invariant &&
            f->b.has_action && f->b.action.field == D2KM_FIELD_SPOIL &&
            f->b.action.value == (int64_t)method && f->rb.kind == D2KM_R_APP_OK)
            return 1;
    }
    return 0;
}

static int ask_spoil(run *r, unsigned method)
{
    static __thread d2km_tls_hello h;
    static __thread uint8_t bytes[D2KM_TLS_MAX + 5];
    static __thread d2km_program p;
    if (d2km_tls_parse(r->t->hello, r->t->hello_length, &h) != D2KM_TLS_OK ||
        d2km_tls_set_sni(&h, r->t->pass_name) != D2KM_TLS_OK) return D2KM_LOCAL_FAIL;
    size_t n = d2km_tls_build(&h, bytes, sizeof(bytes));
    d2km_context context = *r->t->context;
    /* Контекст разрешённого приветствия, не исходного блокируемого:
     * APP_OK этой базы не должен опровергать факты исходного контекста. */
    if (d2km_target_name(&context.target, r->t->pass_name) != 0 ||
        d2km_form_set(&context.form, bytes, n, NULL, 0, r->t->context->form.tcp_options,
            r->t->context->form.tcp_options_length, r->t->context->form.ech,
            r->t->context->form.grease) != 0) return D2KM_LOCAL_FAIL;
    d2km_arm_spec spec = {.kind = D2KM_ARM_EXCHANGE, .context = &context,
        .hello = bytes, .hello_length = n};
    d2km_result control_result;
    uint32_t ec;
    d2km_action action = {.op = D2KM_OP_SPOIL_TRANSPORT,
        .field = D2KM_FIELD_SPOIL, .value = (int64_t)method};
    char why[300];
    snprintf(why, sizeof(why), "B: сервер отвергает порчу R%u? контроль: разрешённое hello без фальшивки; "
        "APP_OK — обмен не нарушен, иной исход — порча небезопасна; критерий: сравнить с контролем", method);
    int rc = question(r, &spec, action, r->reference, why, &ec);
    if (rc) return rc;
    d2km_arm_verdict v = stable(r, &spec, ec, &control_result);
    /* Безопасность порчи — только устойчивым ответом. Неустойчивый — факта
       нет, порча в синтезе не используется, путь цели идёт дальше (поле
       11.11: badsum у Cloudflare — rst/reply/app_ok вперемешку). */
    if (v == D2KM_ARM_CONFLICTING) {
        r->spoil_asked |= 1u << method;
        note(r, D2KM_STEP_EXPERIMENT, D2KM_CONFLICTING, NULL, 0,
             "B: контроль без фальшивки неустойчив — безопасность порчи не доказана, порча не используется");
        return 0;
    }
    if (v != D2KM_ARM_STABLE) return (int)d2km_arm_verdict_outcome(v);
    if (control_result.kind != D2KM_R_APP_OK) {
        /* Без прикладного успеха на разрешённом имени нечем отличить порчу,
           сорвавшую обмен, от обмена, который и так не складывается: вопрос
           B для этой цели не задаётся, порчи в синтезе не используются. */
        r->spoil_asked |= 0xEu;
        note(r, D2KM_STEP_EXPERIMENT, 0, NULL, 0,
             "B не задаётся: с разрешённым именем нет прикладного успеха — порча не проверяема");
        return 0;
    }
    d2km_arm_record control = record(r, ec, 0, 0, 0, 0, control_result);
    control.context = context;
    rc = probe_fake(r, method, 1, &p);
    if (rc) return rc;
    spec.program = &p;
    uint32_t e;
    rc = question(r, &spec, action, control_result, why, &e);
    if (rc) return rc;
    d2km_result res;
    v = stable(r, &spec, e, &res);
    if (v == D2KM_ARM_CONFLICTING) {
        r->spoil_asked |= 1u << method;
        note(r, D2KM_STEP_EXPERIMENT, D2KM_CONFLICTING, NULL, 0,
             "B: с порченой фальшивкой исход неустойчив — сервер её не отвергает надёжно, порча не используется");
        return 0;
    }
    if (v != D2KM_ARM_STABLE) return (int)d2km_arm_verdict_outcome(v);
    r->spoil_asked |= 1u << method;
    d2km_arm_record arm = record(r, e, 1, action.op, action.field, action.value, res);
    arm.context = context;
    d2km_fact fact;
    d2km_fact_reason fr = res.kind == D2KM_R_APP_OK
        ? d2km_fact_establish_invariance(&fact, allocate_id(r, &r->t->next_fact), D2KM_F_PATH,
            &control, &arm, &control, control_result, r->t->box->version + 1)
        : d2km_fact_establish(&fact, allocate_id(r, &r->t->next_fact), D2KM_F_PATH,
            &control, &arm, &control, control_result, 0, r->t->box->version + 1);
    if (fr != D2KM_FR_OK) return D2KM_MODEL_INCOMPLETE;
    add_fact(r, &fact, res.kind == D2KM_R_APP_OK
        ? "сервер отвергает фальшивку с порчей: обмен не нарушен"
        : "сервер принимает фальшивку с порчей: обмен нарушен");
    return 0;
}

static int next_copies(run *r)
{
    static __thread d2km_program p;
    for (unsigned method = 0; method <= 3; method++) {
        if ((r->copies_asked & (1u << method)) || !available(r, method)) continue;
        if (probe_fake(r, method, 1, &p)) continue;
        if (d2km_box_tried(r->t->box, d2km_program_hash(&p), &r->t->context->target))
            return (int)method;
    }
    return -1;
}

static int ask_copies(run *r, unsigned method)
{
    d2km_search search;
    /* Диапазон копий — пока исполнитель способен их послать (§7.1 п. 5):
       план длиннее он отвергнет целиком, и ответа о коробке не будет. */
    int64_t top = r->t->max_sends ? (int64_t)r->t->max_sends : 255;
    if (top > 255) top = 255;
    if (top < 2) {
        r->copies_asked |= 1u << method;
        note(r, D2KM_STEP_EXPERIMENT, 0, NULL, 0, "поиск копий невозможен: исполнитель не посылает больше одной фальшивки");
        return 0;
    }
    d2km_search_init(&search, 1, top, 1);
    uint32_t ids[256];
    d2km_result results[256];
    static __thread d2km_program p;
    int64_t k;
    while (d2km_search_next(&search, &k)) {
        int rc = probe_fake(r, method, (unsigned)k, &p);
        if (rc) return rc;
        d2km_arm_spec spec = {.kind = D2KM_ARM_EXCHANGE, .hello = r->t->hello,
            .hello_length = r->t->hello_length, .program = &p};
        d2km_action action = {.op = D2KM_OP_ADD_MESSAGE, .field = D2KM_FIELD_FAKE_COPIES,
            .value = D2KM_COPIES_VALUE(method, k)};
        char why[300];
        snprintf(why, sizeof(why), "C: сколько копий для R%u? k=%lld; контроль F%u: сервер отвечает с разрешённым именем; "
            "APP_OK — достаточно, любой иной сетевой исход — недостаточно; критерий: граница соседних k", method, (long long)k, r->name_fact);
        uint32_t e;
        rc = question(r, &spec, action, r->base.result, why, &e);
        if (rc) return rc;
        d2km_result res;
        d2km_arm_verdict v = stable(r, &spec, e, &res);
        if (v != D2KM_ARM_STABLE) return (int)d2km_arm_verdict_outcome(v);
        ids[k] = e;
        results[k] = res;
        /* Нужна смена именно на APP_OK. RST->тишина границу успеха не даёт. */
        d2km_result measured = res.kind == D2KM_R_APP_OK ? res : r->base.result;
        if (d2km_search_feed(&search, k, measured)) return D2KM_LOCAL_FAIL;
    }
    r->copies_asked |= 1u << method;
    if (search.phase == D2KM_SEARCH_BOUNDARY && search.at_hi.kind == D2KM_R_APP_OK) {
        d2km_fact f;
        d2km_arm_record lo = record(r, ids[search.lo], 1, D2KM_OP_ADD_MESSAGE,
            D2KM_FIELD_FAKE_COPIES, D2KM_COPIES_VALUE(method, search.lo), results[search.lo]);
        d2km_arm_record hi = record(r, ids[search.hi], 1, D2KM_OP_ADD_MESSAGE,
            D2KM_FIELD_FAKE_COPIES, D2KM_COPIES_VALUE(method, search.hi), results[search.hi]);
        if (d2km_fact_establish(&f, allocate_id(r, &r->t->next_fact), D2KM_F_ASSEMBLY,
            &lo, &hi, &r->control, r->reference,
            1, r->t->box->version + 1) != D2KM_FR_OK || !f.numeric)
            return D2KM_MODEL_INCOMPLETE;
        add_fact(r, &f, "измеренная граница числа копий для метода R");
    } else {
        char why[180];
        snprintf(why, sizeof(why), "копии не помогают для R%u: диапазон 1..%lld (предел исполнителя) исчерпан без APP_OK",
                 method, (long long)top);
        note(r, D2KM_STEP_EXPERIMENT, 0, NULL, 0, why);
    }
    return 0;
}

static unsigned copies_for(run *r, unsigned method)
{
    for (size_t i = 0; i < r->t->box->fact_count; i++) {
        const d2km_fact *f = &r->t->box->facts[i];
        if (d2km_fact_usable(f) && f->numeric && f->b.has_action &&
            f->b.action.field == D2KM_FIELD_FAKE_COPIES &&
            f->b.action.value / 256 == (int64_t)method && f->rb.kind == D2KM_R_APP_OK)
            return (unsigned)(f->b.action.value % 256);
    }
    return 1;
}

static int ask_combination(run *r, unsigned index)
{
    /* TLS record grammar: content_type(1), legacy_version(2), length(2).
     * Финальная позиция уже измерялась ask_assembly, повтор не нужен. */
    unsigned pos = index < 3 ? 1 + 2 * index : 257;
    static __thread d2km_program p;
    memset(&p, 0, sizeof(p));
    p.transport = D2KM_TCP; p.protocol = D2KM_P_TLS13;
    p.split_count = 1;
    p.splits[0].anchor = pos == 257 ? D2KM_AT_SNI_START : D2KM_AT_PAYLOAD_START;
    p.splits[0].offset = (int16_t)(pos == 257 ? 1 : pos);
    snprintf(p.splits[0].why, sizeof(p.splits[0].why), "вопрос D: граница поля TLS, позиция %u", pos);
    d2km_arm_record split = r->split_answers[index];
    d2km_result res = split.result;
    uint32_t e = split.experiment;
    if (split.experiment == 0) {
        if (pos == 257) {
            int found = 0;
            for (size_t i = 0; i < r->t->box->fact_count; i++) {
                const d2km_fact *f = &r->t->box->facts[i];
                if (d2km_fact_usable(f) && f->source_count >= 2 &&
                    d2km_context_diff(&f->context, r->t->context) == 0 &&
                    f->b.has_action && f->b.action.op == D2KM_OP_SPLIT &&
                    f->b.action.field == D2KM_TLS_F_SNI && f->b.action.value == 1) {
                    res = f->rb; e = f->sources[1]; found = 1; break;
                }
            }
            if (!found) {
                r->split_asked |= 1u << index;
                return 0;
            }
        } else {
            d2km_arm_spec spec = {.kind = D2KM_ARM_EXCHANGE, .hello = r->t->hello,
                .hello_length = r->t->hello_length, .program = &p};
            d2km_action action = {.op = D2KM_OP_SPLIT, .field = D2KM_FIELD_RECORD, .value = (int64_t)pos};
            int rc = question(r, &spec, action, r->base.result,
                "D: опознаёт ли коробка hello по первому сегменту? контроль: исходный обмен; "
                "APP_OK — разрез снимает блок, иной исход — проверить смену реакции; критерий: сравнить с базой", &e);
            if (rc) return rc;
            d2km_arm_verdict v = stable(r, &spec, e, &res);
            if (v != D2KM_ARM_STABLE) return (int)d2km_arm_verdict_outcome(v);
        }
        split = record(r, e, 1, D2KM_OP_SPLIT, pos == 257 ? D2KM_TLS_F_SNI : D2KM_FIELD_RECORD,
            (int64_t)(pos == 257 ? 1 : pos), res);
        r->split_answers[index] = split;
        if (pos != 257 && !d2km_result_equal(res, r->base.result)) {
            d2km_fact f;
            if (d2km_fact_establish(&f, allocate_id(r, &r->t->next_fact), D2KM_F_ASSEMBLY, &r->base,
                &split, &r->control, r->reference, 0, r->t->box->version + 1) != D2KM_FR_OK)
                return D2KM_MODEL_INCOMPLETE;
            add_fact(r, &f, "разрез границы заголовка меняет реакцию");
        }
    }
    if (d2km_result_equal(res, r->base.result) || res.kind == D2KM_R_APP_OK) {
        r->split_asked |= 1u << index;
        return 0;
    }
    /* Измерения C не различили методы по успеху: вопросы сочетания
     * сохраняют тот же порядок R; неудача TTL не исключает порчу. */
    for (unsigned method = 0; method <= 3; method++) {
        if (!available(r, method) || (r->combination_asked[index] & (1u << method))) continue;
        unsigned k = copies_for(r, method);
        /* Фальшивки и два куска разреза — одно исполнение (§7.1 п. 5). */
        if (r->t->max_sends && k + 2 > r->t->max_sends) {
            r->combination_asked[index] |= 1u << method;
            note(r, D2KM_STEP_EXPERIMENT, 0, NULL, 0,
                 "сочетание не задаётся: копии и куски разреза не помещаются в одно исполнение");
            continue;
        }
        int rc = probe_fake(r, method, k, &p);
        if (rc) return rc;
        d2km_arm_spec spec = {.kind = D2KM_ARM_EXCHANGE, .hello = r->t->hello,
            .hello_length = r->t->hello_length, .program = &p};
        d2km_action action = {.op = D2KM_OP_SPLIT, .field = D2KM_FIELD_FAKE_SPLIT,
            .value = D2KM_COMBO_VALUE(method, k, 0)};
        uint32_t ec;
        rc = question(r, &spec, action, r->base.result,
            "D контроль: фальшивка без разреза; гипотезы: сочетание снимает блок / не снимает; критерий: APP_OK только у сочетания", &ec);
        if (rc) return rc;
        d2km_result alone;
        d2km_arm_verdict v = stable(r, &spec, ec, &alone);
        if (v != D2KM_ARM_STABLE) return (int)d2km_arm_verdict_outcome(v);
        d2km_arm_record a = record(r, ec, 1, action.op, action.field, action.value, alone);
        p.split_count = 1;
        p.splits[0].anchor = pos == 257 ? D2KM_AT_SNI_START : D2KM_AT_PAYLOAD_START;
        p.splits[0].offset = (int16_t)(pos == 257 ? 1 : pos);
        snprintf(p.splits[0].why, sizeof(p.splits[0].why), "вопрос D: сочетание с разрезом %u", pos);
        action.value = D2KM_COMBO_VALUE(method, k, pos);
        rc = question(r, &spec, action, alone,
            "D: фальшивка вместе с разрезом; контроль: та же фальшивка без разреза; "
            "APP_OK — сочетание помогает, прежняя реакция — нет; критерий: разные исходы одного SPLIT", &e);
        if (rc) return rc;
        v = stable(r, &spec, e, &res);
        if (v != D2KM_ARM_STABLE) return (int)d2km_arm_verdict_outcome(v);
        r->combination_asked[index] |= 1u << method;
        if (res.kind == D2KM_R_APP_OK && alone.kind != D2KM_R_APP_OK) {
            d2km_arm_record b = record(r, e, 1, action.op, action.field, action.value, res);
            d2km_fact f;
            if (d2km_fact_establish(&f, allocate_id(r, &r->t->next_fact), D2KM_F_ASSEMBLY, &a, &b,
                &r->control, r->reference, 0, r->t->box->version + 1) != D2KM_FR_OK)
                return D2KM_MODEL_INCOMPLETE;
            add_fact(r, &f, "фальшивка вместе с разрезом снимает блок");
            /* Испытание ещё может провалиться: оставшиеся методы на этой
             * позиции остаются вопросами, standalone-ответ уже сохранён. */
            return 0;
        }
    }
    r->split_asked |= 1u << index;
    return 0;
}

/* Рабочая модель цели изолирована от подтверждённых коробок, пока новые
 * факты не проверены на противоречия. Успех OWN сам по себе цель в коробку
 * не включает (§5.3). */
static d2km_outcome publish_model(run *r)
{
    if (r->published || !r->t->boxes) return 0;
    d2km_box_set *set = r->t->boxes;
    d2km_box *work = r->t->box;
    d2km_box *stage = malloc(sizeof *stage);
    if (!stage) return D2KM_NO_RESOURCES;
    long chosen = r->candidate_box;
    if (chosen >= 0) {
        const d2km_box *old = &set->entries[chosen];
        for (size_t i = 0; i < work->fact_count; i++) {
            const d2km_fact *f = &work->facts[i];
            d2km_arm_record obs[2] = {
                {.experiment = f->sources[0], .context = f->context, .arm = f->a, .result = f->ra},
                {.experiment = f->sources[0], .context = f->context, .arm = f->b, .result = f->rb}};
            if (f->level == D2KM_LEVEL_ESTABLISHED && !d2km_box_candidate(old, obs, 2)) {
                chosen = -1;
                note(r, D2KM_STEP_EXPERIMENT, 0, &f->id, 1,
                     "новый факт противоречит коробке-кандидату: отдельная новая коробка, прежняя сохранена");
                break;
            }
        }
    }
    uint32_t id = 1;
    if (chosen < 0) {
        if (set->count >= D2KM_STORE_BOXES_MAX) { free(stage); return D2KM_NO_RESOURCES; }
        for (size_t i = 0; i < set->count; i++) {
            if (set->entries[i].id == UINT32_MAX) { free(stage); return D2KM_NO_RESOURCES; }
            if (set->entries[i].id >= id) id = set->entries[i].id + 1;
        }
        d2km_box_init(stage, id);
    } else *stage = set->entries[chosen];
    for (size_t i = 0; i < work->fact_count; i++) {
        d2km_box_code code = d2km_box_add_fact(stage, &work->facts[i], NULL);
        if (code != D2KM_BOX_OK && code != D2KM_BOX_DUPLICATE) {
            free(stage); return code == D2KM_BOX_FULL ? D2KM_NO_RESOURCES : D2KM_LOCAL_FAIL;
        }
    }
    for (size_t i = 0; i < work->counter_count; i++) {
        d2km_box_code code = d2km_box_add_counter(stage, &work->counters[i]);
        if (code != D2KM_BOX_OK && code != D2KM_BOX_DUPLICATE) { free(stage); return D2KM_NO_RESOURCES; }
    }
    memcpy(stage->hypotheses, work->hypotheses, sizeof stage->hypotheses);
    if (chosen < 0) { chosen = (long)set->count; set->count++; }
    set->entries[chosen] = *stage;
    *work = *stage;
    r->rep->box_id = stage->id;
    r->published = 1;
    free(stage);
    return 0;
}
static uint64_t wall_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static int same_binding(const d2km_knowledge *k, const d2km_context *c)
{
    return k->context.protocol == c->protocol && k->context.transport == c->transport &&
        k->context.family == c->family && d2km_target_equal(&k->context.target, &c->target) &&
        d2km_context_compatible(&k->context, c, 0) &&
        k->binding == (c->target.has_name ? D2KM_BIND_NAME : D2KM_BIND_ADDRESS);
}
static void history_add(d2km_knowledge *k, d2km_outcome o, uint32_t e, uint64_t now)
{
    if (k->history_count == D2KM_KNOWLEDGE_HISTORY_MAX) {
        memmove(k->history, k->history + 1, (D2KM_KNOWLEDGE_HISTORY_MAX - 1) * sizeof k->history[0]);
        k->history_count--;
    }
    k->history[k->history_count++] = (d2km_knowledge_history){.time_ms = now,
        .previous_hash = k->hash, .experiment = e, .outcome = o};
}

/* Read archive metadata as JSON tokens. Text in a reason, a nested task or
 * an escaped string cannot impersonate the top-level step of a record. */
static void archive_space(const char **p, const char *end)
{
    while (*p < end && (**p == ' ' || **p == '\t' || **p == '\r')) (*p)++;
}
static int archive_string(const char **p, const char *end, const char **start, size_t *length)
{
    if (*p == end || *(*p)++ != '"') return -1;
    const char *s = *p;
    while (*p < end) {
        unsigned char c = (unsigned char)*(*p)++;
        if (c == '"') {
            if (start) *start = s;
            if (length) *length = (size_t)(*p - s - 1);
            return 0;
        }
        if (c < 32) return -1;
        if (c == '\\') {
            if (*p == end) return -1;
            char escape = *(*p)++;
            if (escape == 'u') {
                for (unsigned i = 0; i < 4; i++) {
                    if (*p == end) return -1;
                    char h = *(*p)++;
                    if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
                          (h >= 'A' && h <= 'F'))) return -1;
                }
            } else if (!strchr("\"\\/bfnrt", escape)) return -1;
        }
    }
    return -1;
}
static int archive_value(const char **p, const char *end, unsigned depth)
{
    /* The serializer's maximum nesting is smaller; bound stack use even for
     * an invalid imported archive instead of trusting its contents. */
    if (depth > 32 || *p == end) return -1;
    if (**p == '"') return archive_string(p, end, NULL, NULL);
    if (**p == '{' || **p == '[') {
        int object = **p == '{'; char close = object ? '}' : ']';
        (*p)++; archive_space(p, end);
        if (*p < end && **p == close) { (*p)++; return 0; }
        for (;;) {
            if (object) {
                if (archive_string(p, end, NULL, NULL)) return -1;
                archive_space(p, end);
                if (*p == end || *(*p)++ != ':') return -1;
                archive_space(p, end);
            }
            if (archive_value(p, end, depth + 1)) return -1;
            archive_space(p, end);
            if (*p == end) return -1;
            char separator = *(*p)++;
            if (separator == close) return 0;
            if (separator != ',') return -1;
            archive_space(p, end);
        }
    }
    if (**p == 't' && end - *p >= 4 && !memcmp(*p, "true", 4)) { *p += 4; return 0; }
    if (**p == 'f' && end - *p >= 5 && !memcmp(*p, "false", 5)) { *p += 5; return 0; }
    if (**p == 'n' && end - *p >= 4 && !memcmp(*p, "null", 4)) { *p += 4; return 0; }
    if (**p == '-') (*p)++;
    if (*p == end || **p < '0' || **p > '9') return -1;
    if (**p == '0') (*p)++;
    else while (*p < end && **p >= '0' && **p <= '9') (*p)++;
    if (*p < end && **p == '.') {
        (*p)++;
        if (*p == end || **p < '0' || **p > '9') return -1;
        while (*p < end && **p >= '0' && **p <= '9') (*p)++;
    }
    if (*p < end && (**p == 'e' || **p == 'E')) {
        (*p)++;
        if (*p < end && (**p == '+' || **p == '-')) (*p)++;
        if (*p == end || **p < '0' || **p > '9') return -1;
        while (*p < end && **p >= '0' && **p <= '9') (*p)++;
    }
    return 0;
}
static int archive_metadata(const char *p, const char *end, int *knowledge, uint64_t *synth_id)
{
    int step_seen = 0, id_seen = 0, synth = 0;
    uint64_t id = 0;
    *knowledge = 0; *synth_id = 0;
    archive_space(&p, end);
    if (p == end || *p++ != '{') return -1;
    archive_space(&p, end);
    if (p < end && *p == '}') p++;
    else for (;;) {
        const char *key; size_t kn;
        if (archive_string(&p, end, &key, &kn)) return -1;
        archive_space(&p, end);
        if (p == end || *p++ != ':') return -1;
        archive_space(&p, end);
        const char *value = p;
        if (archive_value(&p, end, 1)) return -1;
        if (kn == 4 && !memcmp(key, "step", 4)) {
            const char *text; size_t n;
            if (step_seen++ || archive_string(&value, p, &text, &n)) return -1;
            *knowledge = n == 9 && !memcmp(text, "knowledge", 9);
            synth = n == 5 && !memcmp(text, "synth", 5);
        } else if (kn == 2 && !memcmp(key, "id", 2)) {
            const char *text; size_t n;
            if (id_seen++ || archive_string(&value, p, &text, &n) || n < 2 || text[0] != 'W') return -1;
            for (size_t i = 1; i < n; i++) {
                if (text[i] < '0' || text[i] > '9') return -1;
                unsigned d = (unsigned)(text[i] - '0');
                if (id > (UINT64_MAX - d) / 10) return -1;
                id = id * 10 + d;
            }
        }
        archive_space(&p, end);
        if (p == end) return -1;
        char separator = *p++;
        if (separator == '}') break;
        if (separator != ',') return -1;
        archive_space(&p, end);
    }
    archive_space(&p, end);
    if (p != end) return -1;
    if (synth) *synth_id = id;
    return 0;
}
static int archive_root(const char *source, char *out, size_t cap, size_t *length, uint64_t *proof_id)
{
    *length = 0; *proof_id = 0;
    for (const char *line = source; *line;) {
        const char *end = strchr(line, '\n');
        if (!end) return -1;
        int knowledge; uint64_t id;
        if (archive_metadata(line, end, &knowledge, &id)) return -1;
        size_t n = (size_t)(end + 1 - line);
        if (!knowledge) {
            if (n >= cap - *length) return -1;
            memcpy(out + *length, line, n); *length += n;
            if (id) *proof_id = id;
        }
        line = end + 1;
    }
    out[*length] = 0;
    return 0;
}
/* Запись содержит полный снимок обоснования, а не только ссылку в журнал
 * (который может быть сжат после перезапуска, §12.3). */
static d2km_outcome remember(run *r, const d2km_program *p, uint32_t e, d2km_knowledge *source)
{
    d2km_knowledge_set *set = r->t->knowledge;
    if (!set) return publish_model(r); /* программу получает вызывающий */
    d2km_knowledge *previous = NULL;
    uint32_t id = 1;
    for (size_t i = 0; i < set->count; i++) {
        d2km_knowledge *k = &set->entries[i];
        if (same_binding(k, r->t->context)) previous = k;
        if (k->id == UINT32_MAX) return D2KM_NO_RESOURCES;
        if (k->id >= id) id = k->id + 1;
    }
    if (!previous && set->count >= D2KM_STORE_KNOWLEDGE_MAX) return D2KM_NO_RESOURCES;
    d2km_knowledge *k = calloc(1, sizeof *k);
    if (!k) return D2KM_NO_RESOURCES;
    if (previous) *k = *previous;
    k->id = previous ? previous->id : id;
    uint64_t new_hash = d2km_program_hash(p);
    k->context = *r->t->context;
    k->binding = k->context.target.has_name ? D2KM_BIND_NAME : D2KM_BIND_ADDRESS;
    uint64_t now = wall_ms();
    if (!now) { free(k); return D2KM_LOCAL_FAIL; }
    if (previous && (previous->hash != new_hash || !d2km_knowledge_active(previous))) history_add(k, D2KM_APPLIED, e, now);
    k->program = *p; k->hash = new_hash;
    k->experiment = e; k->last_success_ms = now;
    if (source) {
        k->box = source->box; k->model_version = source->model_version;
    } else {
        d2km_outcome code = publish_model(r);
        if (code) { free(k); return code; }
        k->box = r->t->box->id; k->model_version = r->t->box->version;
    }
    const char *der[D2KM_PROG_PAYLOADS + D2KM_PROG_FAKES + D2KM_PROG_SPLITS + 1];
    size_t nd = 0;
    for (size_t i = 0; i < p->payload_count; i++) der[nd++] = p->payloads[i].why;
    for (size_t i = 0; i < p->fake_count; i++) der[nd++] = p->fakes[i].why;
    for (size_t i = 0; i < p->split_count; i++) der[nd++] = p->splits[i].why;
    if (p->reverse) der[nd++] = p->order_why;
    d2km_experiment trial = {.id = e, .kind = D2KM_E_TRIAL, .context = k->context,
        .candidate = k->hash, .memory_bytes = sizeof *p};
    char why[256];
    snprintf(why, sizeof why, "K%u: %s, прикладной успех испытания E%u; коробка B%u, версия %u",
        k->id, source ? "своё знание" : "вопросы", e, k->box, k->model_version);
    char observations[1800],application[1200];
    snprintf(application,sizeof application,"HTTP complete response");
    if(r->t->application_proof && !d2km_application_proof(application,sizeof application,&k->context,k->hash,r->t->application_proof)) {
        free(k);return D2KM_LOCAL_FAIL;
    }
    snprintf(observations,sizeof observations,"два устойчивых прикладных успеха на потоке с программой; исполнение с квитанцией; %s",application);
    d2km_why w = {.time_ms = now, .task = &k->context, .step = D2KM_STEP_KNOWLEDGE,
        .experiment = &trial, .observations = observations,
        .derivation = der, .derivation_count = nd, .outcome = D2KM_APPLIED, .reason = why,
        .links = r->proof_id ? &r->proof_id : NULL, .link_count = r->proof_id ? 1u : 0u};
    /* При повторном успехе той же записи не наращиваем архив одинаковыми
       проверками: её полное обоснование остаётся в записи, время обновится. */
    const char *proof = source ? source->why : r->proof;
    size_t base = strlen(proof);
    int keep_archive = source && previous && source->id == previous->id &&
        (!r->t->application_proof || strstr(source->why,application));
    uint64_t root_id = 0;
    if (source && !keep_archive) {
        /* Validation of the source target is not evidence for this target.
         * Keep root derivation records and append only this successful trial;
         * otherwise a chain of transfers exhausts the fixed resource limit. */
        if (archive_root(proof, k->why, sizeof k->why, &base, &root_id)) {
            free(k); return D2KM_LOCAL_FAIL;
        }
        w.links = root_id ? &root_id : NULL; w.link_count = root_id ? 1u : 0u;
    } else memcpy(k->why, proof, base + 1);
    size_t need = d2km_why_format(&w, 0, NULL, 0);
    if (keep_archive) need = 0;
    if (base + need >= sizeof k->why) { free(k); return D2KM_NO_RESOURCES; }
    uint64_t wid = 0;
    if (r->t->journal && d2km_journal_append(r->t->journal, &w, &wid) != D2KM_WHY_OK) {
        free(k); return D2KM_LOCAL_FAIL;
    }
    if (!keep_archive) need = d2km_why_format(&w, wid, NULL, 0);
    if (base + need >= sizeof k->why) { free(k); return D2KM_NO_RESOURCES; }
    if (!keep_archive) d2km_why_format(&w, wid, k->why + base, sizeof k->why - base);
    else k->why[base] = 0;
    /* The source target did not run: only the successful binding is updated. */
    if (!previous) previous = &set->entries[set->count++];
    *previous = *k;
    r->rep->knowledge_id = k->id; r->rep->box_id = k->box;
    free(k);
    return 0;
}
static int target_tried(run *r, uint64_t hash)
{
    if (d2km_box_tried_context(r->t->box, hash, r->t->context)) return 1;
    if (r->t->boxes)
        for (size_t i = 0; i < r->t->boxes->count; i++)
            if (d2km_box_tried_context(&r->t->boxes->entries[i], hash, r->t->context)) return 1;
    return 0;
}
/* OWN: точная привязка прежде знания коробок-кандидатов, внутри каждой
 * группы — последний прикладной успех. Программа не пересобирается. */
static d2km_outcome own(run *r)
{
    d2km_knowledge_set *set = r->t->knowledge;
    d2km_knowledge *best = NULL;
    int best_rank = 2;
    for (size_t i = 0; set && i < set->count; i++) {
        d2km_knowledge *k = &set->entries[i];
        const d2km_context *c = r->t->context;
        if ((!d2km_knowledge_active(k) && same_binding(k,c)) || k->context.protocol != c->protocol || k->context.transport != c->transport ||
            k->context.family != c->family || target_tried(r, k->hash)) continue;
        if (d2km_program_check(&k->program) != D2KM_PC_OK || k->hash != d2km_program_hash(&k->program) ||
            k->program.protocol != c->protocol || k->program.transport != c->transport) return D2KM_LOCAL_FAIL;
        int rank = same_binding(k, c) ? 0 : 2;
        /* A second form is a new context, not a new target. It may try the
           target's own program even before box compatibility is known.
           stable() below still requires this form's application/receipt proof;
           remember() keeps a separate binding and failure cannot retire k. */
        if (rank == 2 && d2km_knowledge_active(k) &&
            d2km_target_equal(&k->context.target, &c->target)) rank = 1;
        for (size_t j = 0; rank == 2 && r->t->boxes && j < r->t->boxes->count; j++)
            if (k->box == r->t->boxes->entries[j].id &&
                d2km_box_candidate(&r->t->boxes->entries[j], &r->base, 1)) rank = 1;
        if (rank == 2) continue;
        if (!best || rank < best_rank || (rank == best_rank && k->last_success_ms > best->last_success_ms)) {
            best = k; best_rank = rank;
        }
    }
    if (!best) {
        note(r, D2KM_STEP_OWN, 0, NULL, 0, "своё знание: подходящей записи нет; переход к вопросам");
        return 0;
    }
    char why[256];
    snprintf(why, sizeof why, "своё знание: запись K%u, коробка B%u; испытание той же программы на этой цели",
        best->id, best->box);
    uint32_t e = allocate_id(r, &r->t->next_experiment);
    d2km_experiment trial = {.id = e, .kind = D2KM_E_TRIAL, .context = *r->t->context,
        .candidate = best->hash, .memory_bytes = sizeof best->program};
    d2km_why w = {.time_ms = wall_ms(), .task = r->t->context, .step = D2KM_STEP_OWN,
        .experiment = &trial, .reason = why};
    if (r->t->journal && d2km_journal_append(r->t->journal, &w, NULL) != D2KM_WHY_OK) return D2KM_LOCAL_FAIL;
    d2km_knowledge source=*best;
    d2km_arm_spec spec = {.kind = D2KM_ARM_EXCHANGE, .hello = r->t->hello,
        .hello_length = r->t->hello_length, .program = &source.program};
    d2km_result result;
    d2km_arm_verdict v = stable(r, &spec, e, &result);
    r->rep->candidate = source.program; r->rep->has_candidate = 1;
    if (v != D2KM_ARM_STABLE) {
        d2km_outcome o = d2km_arm_verdict_outcome(v);
        /* §4.6 OWN не имеет непосредственного перехода по NOT_MEASURED /
         * CONFLICTING. Подтверждённого своего знания нет: OWN_NONE → ASK,
         * затем WAIT по коду измерения (§4.7), без вопросов и контрпримера. */
        if (o == D2KM_NOT_MEASURED || o == D2KM_CONFLICTING) go(r, D2KM_EV_OWN_NONE, 0);
        return o;
    }
    if (result.kind == D2KM_R_APP_OK) {
        d2km_outcome code = remember(r, &source.program, e, &source);
        if (code) return code;
        r->rep->program = source.program; r->rep->from_own = 1;
        go(r, D2KM_EV_OWN_OK, 0);
        return D2KM_APPLIED;
    }
    d2km_counterexample ce = {.candidate = source.hash, .experiment = e,
        .result = result, .target = r->t->context->target, .context = *r->t->context};
    if (d2km_box_add_counter(r->t->box, &ce) == D2KM_BOX_FULL) return D2KM_NO_RESOURCES;
    if (same_binding(best, r->t->context)) history_add(best, D2KM_DEGRADED, e, wall_ms());
    note(r, D2KM_STEP_OWN, D2KM_TRIAL_FAIL, NULL, 0,
         "своё знание: испытание не дало прикладного успеха; контрпример этой цели, переход к вопросам");
    return 0;
}

/* Восстановленные источники задают нижнюю границу номеров; счётчик
 * внешнего ведущего не может превратить новый опыт в прежний E/F. */
static int raise_next(uint32_t *next, uint32_t used)
{
    if (used == UINT32_MAX) return -1;
    if (*next <= used) *next = used + 1;
    return 0;
}
static int restored_ids(d2km_tls_task *t)
{
    size_t n = t->boxes ? t->boxes->count : 0;
    for (size_t i = 0; i <= n; i++) {
        const d2km_box *b = i == n ? t->box : &t->boxes->entries[i];
        if (b->fact_count > D2KM_BOX_FACTS_MAX || b->counter_count > D2KM_BOX_COUNTER_MAX ||
            b->target_count > D2KM_BOX_TARGETS_MAX) return -1;
        for (size_t j = 0; j < b->fact_count; j++) {
            const d2km_fact *f = &b->facts[j];
            if (f->source_count > D2KM_FACT_SOURCES_MAX || raise_next(&t->next_fact, f->id)) return -1;
            for (size_t k = 0; k < f->source_count; k++)
                if (raise_next(&t->next_experiment, f->sources[k])) return -1;
        }
        for (size_t j = 0; j < b->counter_count; j++)
            if (raise_next(&t->next_experiment, b->counters[j].experiment)) return -1;
    }
    if (t->knowledge)
        for (size_t i = 0; i < t->knowledge->count; i++) {
            const d2km_knowledge *k = &t->knowledge->entries[i];
            if (raise_next(&t->next_experiment, k->experiment) || k->history_count > D2KM_KNOWLEDGE_HISTORY_MAX) return -1;
            for (size_t j = 0; j < k->history_count; j++)
                if (raise_next(&t->next_experiment, k->history[j].experiment)) return -1;
        }
    return 0;
}

d2km_outcome d2km_tls_task_run(d2km_tls_task *t, d2km_task_report *rep)
{
    memset(rep, 0, sizeof(*rep));
    if (t == NULL || t->net == NULL || t->box == NULL || t->context == NULL ||
        t->hello == NULL || t->next_experiment == 0 || t->next_fact == 0) {
        rep->outcome = D2KM_LOCAL_FAIL;
        return D2KM_LOCAL_FAIL;
    }
    if ((t->knowledge && t->knowledge->count > D2KM_STORE_KNOWLEDGE_MAX) ||
        (t->boxes && t->boxes->count > D2KM_STORE_BOXES_MAX) || restored_ids(t)) {
        rep->outcome = D2KM_NO_RESOURCES; rep->state = D2KM_T_WAIT; return D2KM_NO_RESOURCES;
    }
    run r;
    memset(&r, 0, sizeof(r));
    r.t = t;
    r.rep = rep;
    r.state = D2KM_T_SUSPECT;
    r.candidate_box = -1;
    int degraded = 0;
    if (t->degradation_knowledge) {
        d2km_knowledge *bound = NULL;
        for (size_t i = 0; t->knowledge && i < t->knowledge->count; i++) {
            d2km_knowledge *k = &t->knowledge->entries[i];
            if (k->id == t->degradation_knowledge && k->hash == t->degradation_hash &&
                d2km_knowledge_active(k) && k->binding == D2KM_BIND_NAME &&
                k->context.protocol == t->context->protocol && k->context.transport == t->context->transport &&
                k->context.family == t->context->family && d2km_target_equal(&k->context.target, &t->context->target))bound = k;
        }
        r.state = D2KM_T_TRIAL;
        /* The signal identified this actual working installation. Recheck
           its K/hash with the current client's captured bytes: Random and
           key_share change on a fresh connection. This is no claim that
           those fields are unread. ECH remains a distinct context. */
        if (!bound || bound->context.form.ech!=t->context->form.ech ||
            bound->hash != d2km_program_hash(&bound->program) ||
            d2km_program_check(&bound->program) != D2KM_PC_OK)
            return finish(&r, D2KM_NOT_MEASURED, D2KM_STEP_WATCH,
                          "сигнал относится к другой или уже снятой привязке; знание не меняется");
        uint32_t e = allocate_id(&r, &t->next_experiment);
        d2km_experiment trial = {.id=e,.kind=D2KM_E_TRIAL,.context=*t->context,
            .candidate=bound->hash,.memory_bytes=sizeof bound->program};
        d2km_why w = {.time_ms=wall_ms(),.task=t->context,.step=D2KM_STEP_WATCH,
            .experiment=&trial,.reason="сигнал рабочего плана: испытание той же программы до прямого контроля"};
        if(t->journal && d2km_journal_append(t->journal,&w,NULL)!=D2KM_WHY_OK)
            return finish(&r,D2KM_LOCAL_FAIL,D2KM_STEP_WATCH,"не записан опыт деградации; знание сохранено");
        /* Network arms release the catalog mutex. A different form may
           replace this installation while we are on the wire: both repeats
           must still execute one immutable program, as in OWN. */
        d2km_knowledge source=*bound;
        d2km_arm_spec recheck = {.kind=D2KM_ARM_EXCHANGE,.hello=t->hello,.hello_length=t->hello_length,.program=&source.program};
        d2km_result result;d2km_arm_verdict verdict=stable(&r,&recheck,e,&result);
        rep->candidate=source.program;rep->has_candidate=1;
        rep->knowledge_id=source.id;rep->box_id=source.box;
        if(verdict!=D2KM_ARM_STABLE)
            return finish(&r,d2km_arm_verdict_outcome(verdict),D2KM_STEP_WATCH,"испытание не измерено или противоречиво; привязка сохранена");
        if(memcmp(bound,&source,sizeof source))
            return finish(&r,D2KM_NOT_MEASURED,D2KM_STEP_WATCH,
                          "знание изменилось во время испытания; результат старой установки не меняет новую");
        if(result.kind==D2KM_R_APP_OK) {
            bound->last_success_ms=wall_ms();rep->program=bound->program;rep->from_own=1;r.state=D2KM_T_APPLIED;
            return finish(&r,D2KM_APPLIED,D2KM_STEP_WATCH,"та же программа дала устойчивый прикладной успех; одиночный сигнал знание не меняет");
        }
        w.time_ms=wall_ms();w.outcome=D2KM_DEGRADED;
        w.reason="та же программа устойчиво не дала прикладного успеха; DEGRADED, переход к DIRECT";
        if(t->journal && d2km_journal_append(t->journal,&w,NULL)!=D2KM_WHY_OK)
            return finish(&r,D2KM_LOCAL_FAIL,D2KM_STEP_WATCH,"не записан итог деградации; знание сохранено");
        history_add(bound,D2KM_DEGRADED,e,w.time_ms);
        if(t->knowledge_changed && t->knowledge_changed(t->knowledge_changed_ctx))
            return finish(&r,D2KM_LOCAL_FAIL,D2KM_STEP_WATCH,"деградация не сохранена на диск; прямой контроль не запускается");
        d2km_counterexample ce={.candidate=bound->hash,.experiment=e,.result=result,
            .target=t->context->target,.context=*t->context};
        if(d2km_box_add_counter(t->box,&ce)==D2KM_BOX_FULL)
            return finish(&r,D2KM_NO_RESOURCES,D2KM_STEP_WATCH,"деградация сохранена; нет памяти для контрпримера");
        r.state=D2KM_T_APPLIED;go(&r,D2KM_EV_OUTCOME,D2KM_DEGRADED);degraded=1;
    } else go(&r, D2KM_EV_START, 0);

    /* Прямой контроль (§4.3): тот же обмен напрямую и через опорную точку. */
    d2km_arm_spec spec = {.kind = D2KM_ARM_EXCHANGE, .hello = t->hello, .hello_length = t->hello_length};
    d2km_result res;
    uint32_t eb = allocate_id(&r, &t->next_experiment);
    d2km_arm_verdict v = stable(&r, &spec, eb, &res);
    if (v != D2KM_ARM_STABLE)
        return finish(&r, d2km_arm_verdict_outcome(v), D2KM_STEP_DIRECT,
                      "прямой контроль: исход прогонов не устойчив или не измерен");
    if (res.kind == D2KM_R_APP_OK) {
        if(degraded)r.state=D2KM_T_APPLIED;
        return finish(&r, degraded?D2KM_BLOCK_GONE:D2KM_DIRECT_OK, D2KM_STEP_DIRECT,
                      "прямой контроль: цель работает напрямую — обходить нечего");
    }
    r.base = record(&r, eb, 0, 0, 0, 0, res);
    d2km_box_open(t->box, signal_of(res));
    if (t->boxes)
        for (size_t i = 0; i < t->boxes->count; i++)
            if (d2km_box_candidate(&t->boxes->entries[i], &r.base, 1)) { r.candidate_box = (long)i; break; }

    /* Контроль живости сервера (§4.3): сначала собственные доказательства,
       опорная точка — последней. */
    if (t->pass_name != NULL) {
        note(&r, D2KM_STEP_DIRECT, 0, NULL, 0,
             "контроль живости 1: то же приветствие клиента с другим именем");
        int rc = ask_name(&r);
        if (rc != 0)
            return finish(&r, (d2km_outcome)rc, D2KM_STEP_DIRECT,
                          "контроль живости: плечо с другим именем не дало устойчивого исхода");
    }
    if (r.control.experiment != 0 || t->alive_history != NULL) {
        go(&r, D2KM_EV_OUTCOME, D2KM_BLOCK_CONFIRMED);
        note(&r, D2KM_STEP_DIRECT, D2KM_BLOCK_CONFIRMED, NULL, 0,
             r.control.experiment ? "блок подтверждён без внешнего сервиса: с другим именем сервер отвечает полностью"
                                  : t->alive_history);
        goto own_knowledge;
    }
    spec.reference = 1;
    uint32_t er = allocate_id(&r, &t->next_experiment);
    d2km_result ref;
    v = stable(&r, &spec, er, &ref);
    if (v == D2KM_ARM_NOT_MEASURED)
        return finish(&r, D2KM_NO_REFERENCE, D2KM_STEP_DIRECT,
                      "прямой контроль: своих доказательств живости сервера нет, опорная точка недоступна");
    if (v != D2KM_ARM_STABLE)
        return finish(&r, d2km_arm_verdict_outcome(v), D2KM_STEP_DIRECT,
                      "прямой контроль: контроль через опорную точку не устойчив");
    if (!d2km_result_server_reached(ref))
        return finish(&r, D2KM_SERVER_DOWN, D2KM_STEP_DIRECT,
                      "сервер не отвечает ни напрямую, ни через опорную точку");
    r.reference = ref;
    /* Контроль — тот же обмен через опорную точку; в фактах он стоит в том
       же контексте цели. */
    r.control = record(&r, er, 0, 0, 0, 0, ref);
    go(&r, D2KM_EV_OUTCOME, D2KM_BLOCK_CONFIRMED);
    note(&r, D2KM_STEP_DIRECT, D2KM_BLOCK_CONFIRMED, NULL, 0,
         "блок подтверждён: напрямую реакция, через опорную точку сервер отвечает");
own_knowledge:;
    /* Контрпримеры цели живут дольше одного вызова ведущего. Передаём их
     * и синтезу, чтобы он не вернул под видом нового старый hash (§7.1). */
    if (t->boxes)
        for (size_t i = 0; i < t->boxes->count; i++)
            for (size_t j = 0; j < t->boxes->entries[i].counter_count; j++) {
                const d2km_counterexample *ce = &t->boxes->entries[i].counters[j];
                if (d2km_context_valid(&ce->context) == 0 &&
                    d2km_context_compatible(&ce->context, t->context, d2km_box_unread(&t->boxes->entries[i])) &&
                    d2km_box_add_counter(t->box, ce) == D2KM_BOX_FULL)
                    return finish(&r, D2KM_NO_RESOURCES, D2KM_STEP_OWN, "контрпримеры цели не помещаются в рабочую модель");
            }

    d2km_outcome owned = own(&r);
    if (owned == D2KM_APPLIED)
        return finish(&r, D2KM_APPLIED, D2KM_STEP_KNOWLEDGE, "своё знание: прикладной успех, привязка записана");
    if (owned)
        return finish(&r, owned, D2KM_STEP_OWN, "своё знание: испытание не измерено или запись невозможна");
    go(&r, D2KM_EV_OWN_NONE, 0);

    /* Конечное пространство вопросов: имя, сборка, 2 поиска хопов,
     * 3 B, 4 поиска C, 4 standalone-разреза, 4*4 сочетания (позиция,R).
     * Ответы D кэшируются отдельно: ранний APP_OK вопроса не исключает
     * оставшиеся пары после TRIAL_FAIL. Каждая пара отвечает один раз.
     * Испытаний не более 2 plain-кандидатов на R, 4*4 сочетаний и
     * 4 самостоятельных разрезов. Поиски конечны в грамматике 1..255. */
    enum { QUESTIONS = 1 + 1 + 2 + 3 + 4 + 4 + 4 * 4,
           TRIALS = 4 * 2 + 4 * 4 + 4 };
    for (int step = 0; step <= QUESTIONS + TRIALS; step++) {
        d2km_synth_in in = synth_input(&r);
        d2km_fact_kind need = 0;
        char why[300];
        static __thread d2km_program prog;
        d2km_synth_code sc = d2km_synth_tls(&in, &prog, &need, why, sizeof(why));
        if (sc == D2KM_SYN_CANDIDATE) {
            uint64_t hash = d2km_program_hash(&prog);
            d2km_target tg = t->context->target;
            /* Ведущий шёл к синтезу из ASK: модели хватило (§6.6). */
            if (r.state == D2KM_T_ASK)
                go(&r, D2KM_EV_MODEL_ENOUGH, 0);
            go(&r, D2KM_EV_CANDIDATE, 0);
            /* Запись кандидата — с происхождением каждого действия (§7.4). */
            {
                const char *der[D2KM_PROG_PAYLOADS + D2KM_PROG_FAKES + D2KM_PROG_SPLITS + 1];
                size_t nd = 0;
                for (size_t i = 0; i < prog.payload_count; i++) der[nd++] = prog.payloads[i].why;
                for (size_t i = 0; i < prog.fake_count; i++) der[nd++] = prog.fakes[i].why;
                for (size_t i = 0; i < prog.split_count; i++) der[nd++] = prog.splits[i].why;
                if (prog.reverse) der[nd++] = prog.order_why;
                d2km_why w;
                memset(&w, 0, sizeof(w));
                w.time_ms = wall_ms();
                w.task = t->context;
                w.step = D2KM_STEP_SYNTH;
                w.derivation = der;
                w.derivation_count = nd;
                w.reason = why;
                r.proof_id = 0;
                if (t->journal && d2km_journal_append(t->journal, &w, &r.proof_id) != D2KM_WHY_OK)
                    return finish(&r, D2KM_LOCAL_FAIL, D2KM_STEP_SYNTH, "не удалось записать обоснование кандидата");
                if (d2km_why_format(&w, r.proof_id, r.proof, sizeof r.proof) >= sizeof r.proof)
                    return finish(&r, D2KM_NO_RESOURCES, D2KM_STEP_SYNTH, "обоснование кандидата не помещается в запись знания");
            }
            d2km_arm_spec ts = {.kind = D2KM_ARM_EXCHANGE, .hello = t->hello,
                .hello_length = t->hello_length, .program = &prog};
            uint32_t et = allocate_id(&r, &t->next_experiment);
            d2km_result tr;
            v = stable(&r, &ts, et, &tr);
            rep->candidate = prog;
            rep->has_candidate = 1;
            if (v != D2KM_ARM_STABLE)
                return finish(&r, d2km_arm_verdict_outcome(v), D2KM_STEP_TRIAL,
                              r.exec_refused ? "кандидат построен, но не испытан: исполнитель плана недоступен"
                                             : "испытание: исход прогонов не устойчив");
            if (tr.kind == D2KM_R_APP_OK) {
                d2km_outcome stored = remember(&r, &prog, et, NULL);
                if (stored) return finish(&r, stored, D2KM_STEP_KNOWLEDGE, "испытание успешно, но знание записать не удалось");
                go(&r, D2KM_EV_TRIAL_OK, 0);
                rep->program = prog;
                rep->outcome = D2KM_APPLIED;
                rep->state = r.state;
                snprintf(rep->reason, sizeof(rep->reason),
                         "испытание дало прикладной успех: знание записано");
                note(&r, D2KM_STEP_KNOWLEDGE, D2KM_APPLIED, NULL, 0, rep->reason);
                return D2KM_APPLIED;
            }
            d2km_counterexample ce;
            memset(&ce, 0, sizeof(ce));
            ce.candidate = hash;
            ce.experiment = et;
            ce.result = tr;
            ce.target = tg;
            ce.context = *t->context;
            if (d2km_box_add_counter(t->box, &ce) == D2KM_BOX_FULL)
                return finish(&r, D2KM_NO_RESOURCES, D2KM_STEP_TRIAL, "модель не вмещает контрпример");
            go(&r, D2KM_EV_OUTCOME, D2KM_TRIAL_FAIL);
            note(&r, D2KM_STEP_TRIAL, D2KM_TRIAL_FAIL, NULL, 0,
                 "испытание без прикладного успеха — контрпример записан");
            continue;
        }
        if (sc == D2KM_SYN_REQ_CONFLICT || sc == D2KM_SYN_EXEC_UNSUPPORTED) {
            if (r.state == D2KM_T_ASK)
                go(&r, D2KM_EV_MODEL_ENOUGH, 0);
            return finish(&r, sc == D2KM_SYN_REQ_CONFLICT ? D2KM_REQ_CONFLICT
                                                          : D2KM_EXEC_UNSUPPORTED,
                          D2KM_STEP_SYNTH, why);
        }
        if (sc != D2KM_SYN_NEED_FACT)
            return finish(&r, D2KM_LOCAL_FAIL, D2KM_STEP_SYNTH, why);
        if (r.state == D2KM_T_SYNTH)
            go(&r, D2KM_EV_NEED_FACT, 0);

        /* Синтезу нужен факт: вопрос, который его даёт. */
        int rc;
        if (!r.name_asked && (need == D2KM_F_PARSE || need == D2KM_F_NAME)) {
            if (t->pass_name == NULL)
                return finish(&r, D2KM_MODEL_INCOMPLETE, D2KM_STEP_QUESTION,
                              "нет кандидата имени для вопроса о разборе имени");
            rc = ask_name(&r);
        } else if (r.name_fact && !r.assembly_asked) {
            rc = ask_assembly(&r);
        } else if (need == D2KM_F_PATH && !has_path(t->box, D2KM_FIELD_PATH_SERVER)) {
            rc = search_hop(&r, D2KM_ARM_PATH_SERVER, D2KM_FIELD_PATH_SERVER, "хоп сервера");
        } else if (need == D2KM_F_PATH && !has_path(t->box, D2KM_FIELD_PATH_BOX) &&
                   !r.box_hop_unmeasurable) {
            rc = search_hop(&r, D2KM_ARM_PATH_BOX, D2KM_FIELD_PATH_BOX, "хоп коробки");
        } else if (r.name_fact && r.spoil_asked != 14u) {
            unsigned method = 1;
            while (r.spoil_asked & (1u << method)) method++;
            rc = ask_spoil(&r, method);
        } else if (r.name_fact && next_copies(&r) >= 0) {
            rc = ask_copies(&r, (unsigned)next_copies(&r));
        } else if (r.name_fact && r.split_asked != 15u) {
            unsigned pos = 0;
            while (r.split_asked & (1u << pos)) pos++;
            rc = ask_combination(&r, pos);
        } else {
            return finish(&r, D2KM_MODEL_INCOMPLETE, D2KM_STEP_QUESTION, why);
        }
        if (r.fact_error) rc = r.fact_error;
        if (rc != 0)
            return finish(&r, (d2km_outcome)rc, D2KM_STEP_EXPERIMENT,
                          "вопрос не дал устойчивого ответа");
    }
    return finish(&r, D2KM_LOCAL_FAIL, D2KM_STEP_QUESTION,
                  "ведущий задачи не сошёлся: дефект ведущего, не ответ коробки");
}
