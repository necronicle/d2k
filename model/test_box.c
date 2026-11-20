#include "d2km_box.h"
#include "fixture.h"
#include "test.h"

static d2km_result R(d2km_result_kind k) { d2km_result r = {k, 0}; return r; }

static d2km_arm_record rec(const char *name, uint32_t e, int has, d2km_operator op,
                           uint32_t field, int64_t v, d2km_result r)
{
    d2km_arm_record a;
    memset(&a, 0, sizeof(a));
    a.experiment = e;
    fixture_context(&a.context);
    d2km_target_name(&a.context.target, name);
    a.arm.has_action = has;
    a.arm.action.op = op;
    a.arm.action.field = field;
    a.arm.action.value = v;
    a.result = r;
    return a;
}

static d2km_target T(const char *n) { d2km_target t; d2km_target_name(&t, n); return t; }

int main(void)
{
    d2km_box b;
    d2km_box_init(&b, 1);
    CHECK(b.version == 0 && b.fact_count == 0);

    /* Факт «реакция»: на a.com без воздействия RST, с другим именем — успех. */
    d2km_result ok = R(D2KM_R_APP_OK), rst = R(D2KM_R_RST);
    d2km_arm_record base = rec("a.com", 1, 0, 0, 0, 0, rst);
    d2km_arm_record name = rec("a.com", 2, 1, D2KM_OP_SET_FIELD, 1, 1, ok);
    d2km_arm_record ctl = rec("a.com", 3, 0, 0, 0, 0, ok);
    d2km_fact f1;
    CHECK(d2km_fact_establish(&f1, 10, D2KM_F_REACTION, &base, &name, &ctl, ok, 0, 0) == D2KM_FR_OK);
    CHECK(d2km_box_add_fact(&b, &f1, NULL) == D2KM_BOX_OK);
    CHECK(b.version == 1 && b.facts[0].model_version == 1);
    CHECK(d2km_box_add_fact(&b, &f1, NULL) == D2KM_BOX_DUPLICATE);
    CHECK(b.version == 1);

    /* Неизменность над ECH: и с ECH, и без — RST; поле нечитаемо. */
    d2km_arm_record e0 = rec("a.com", 4, 0, 0, 0, 0, rst);
    d2km_arm_record e1 = rec("a.com", 5, 1, D2KM_OP_SET_FIELD, D2KM_FIELD_FORM | D2KM_FORM_ECH, 1, rst);
    d2km_fact inv;
    CHECK(d2km_fact_establish_invariance(&inv, 11, D2KM_F_PARSE, &e1, &e0, &ctl, ok, 0) == D2KM_FR_OK);
    CHECK(inv.invariant && !inv.a.has_action && inv.b.has_action);
    CHECK(d2km_fact_unread_form(&inv) == D2KM_FORM_ECH);
    /* Одинаковый успех неизменности не доказывает. */
    d2km_arm_record s0 = rec("a.com", 4, 0, 0, 0, 0, ok), s1 = e1;
    s1.result = ok;
    CHECK(d2km_fact_establish_invariance(&inv, 11, D2KM_F_PARSE, &s0, &s1, &ctl, ok, 0) == D2KM_FR_NOT_BOX_REACTION);
    CHECK(d2km_fact_establish_invariance(&inv, 11, D2KM_F_PARSE, &e0, &name, &ctl, ok, 0) == D2KM_FR_SAME_RESULT);
    CHECK(d2km_fact_establish_invariance(&inv, 11, D2KM_F_PARSE, &e1, &e0, &ctl, ok, 0) == D2KM_FR_OK);
    CHECK(d2km_box_unread(&b) == 0);
    CHECK(d2km_box_add_fact(&b, &inv, NULL) == D2KM_BOX_OK);
    CHECK(d2km_box_unread(&b) == D2KM_FORM_ECH);

    /* Гипотезы: открытие по сигналу, критерий опыта. */
    d2km_box_open(&b, D2KM_S_RST);
    d2km_hypothesis live[8];
    CHECK(d2km_box_live(&b, live, 8) == 4);
    d2km_experiment q;
    memset(&q, 0, sizeof(q));
    q.prediction_count = 2;
    q.predictions[0].hypothesis = D2KM_H_HELLO_NAME;
    q.predictions[0].predicted = ok;
    q.predictions[1].hypothesis = D2KM_H_ADDR_AFTER_HELLO;
    q.predictions[1].predicted = rst;
    unsigned c, r;
    CHECK(d2km_experiment_judge(&q, ok, &c, &r) == 1);
    d2km_box_judge(&b, &q, c, r);
    CHECK(b.hypotheses[D2KM_H_HELLO_NAME] == D2KM_HYP_CONFIRMED);
    CHECK(b.hypotheses[D2KM_H_ADDR_AFTER_HELLO] == D2KM_HYP_REFUTED);
    CHECK(d2km_box_live(&b, live, 8) == 2);
    d2km_box_open(&b, D2KM_S_RST);   /* опровергнутую не воскрешает */
    CHECK(b.hypotheses[D2KM_H_ADDR_AFTER_HELLO] == D2KM_HYP_REFUTED);
    CHECK(b.hypotheses[D2KM_H_TIME_CUT] == D2KM_HYP_UNKNOWN);

    /* Кандидат и принадлежность цели b.com. */
    d2km_arm_record bb = rec("b.com", 20, 0, 0, 0, 0, rst);
    d2km_arm_record bn = rec("b.com", 21, 1, D2KM_OP_SET_FIELD, 1, 1, ok);
    d2km_arm_record pair[2] = {bb, bn};
    CHECK(d2km_box_candidate(&b, pair, 2));
    /* С ECH у b.com — всё равно совместимо: ECH нечитаем. */
    pair[0].context.form.ech = 1;
    CHECK(d2km_box_candidate(&b, pair, 2));
    CHECK(d2km_box_admit(&b, &(d2km_target){0}, pair, 0) == D2KM_BOX_BAD_INPUT);
    d2km_target tb = T("b.com");
    CHECK(d2km_box_admit(&b, &tb, pair, 2) == D2KM_BOX_OK);
    CHECK(d2km_box_has_target(&b, &tb));
    CHECK(d2km_box_admit(&b, &tb, pair, 2) == D2KM_BOX_DUPLICATE);
    /* c.com: только успех с другим именем, без повторённой реакции — не входит. */
    d2km_arm_record cn = rec("c.com", 30, 1, D2KM_OP_SET_FIELD, 1, 1, ok);
    d2km_target tc = T("c.com");
    CHECK(d2km_box_candidate(&b, &cn, 1));
    CHECK(d2km_box_admit(&b, &tc, &cn, 1) == D2KM_BOX_BAD_INPUT);
    /* d.com: без воздействия проходит — факт опровергнут, не кандидат. */
    d2km_arm_record dd = rec("d.com", 40, 0, 0, 0, 0, ok);
    CHECK(!d2km_box_candidate(&b, &dd, 1));
    /* Другой протокол — не совместимо, не опровергает. */
    dd.context.protocol = D2KM_P_TLS12;
    CHECK(d2km_box_candidate(&b, &dd, 1));

    /* Противоречие установленных фактов разных целей — деление, факт не добавлен. */
    d2km_arm_record xb = rec("x.com", 50, 0, 0, 0, 0, rst);
    d2km_arm_record xn = rec("x.com", 51, 1, D2KM_OP_SET_FIELD, 1, 1, rst);
    d2km_arm_record xd = rec("x.com", 52, 1, D2KM_OP_SET_FIELD, 1, 2, ok);
    d2km_arm_record xc = rec("x.com", 53, 0, 0, 0, 0, ok);
    d2km_fact fx;
    CHECK(d2km_fact_establish(&fx, 12, D2KM_F_REACTION, &xn, &xd, &xc, ok, 0, 0) == D2KM_FR_OK);
    size_t conflict = 99;
    uint32_t v = b.version;
    CHECK(d2km_box_add_fact(&b, &fx, &conflict) == D2KM_BOX_SPLIT_NEEDED);
    CHECK(conflict == 0 && b.version == v && b.fact_count == 2);
    (void)xb;

    /* Наблюдение той же цели против факта — понижение, новая версия. */
    d2km_arm_record again = rec("a.com", 60, 1, D2KM_OP_SET_FIELD, 1, 1, rst);
    CHECK(d2km_box_observe(&b, &again) == 1);
    CHECK(b.version == v + 1 && b.facts[0].level == D2KM_LEVEL_OBSERVED);
    CHECK(b.facts[0].model_version == v + 1);
    CHECK(d2km_box_observe(&b, &again) == 0);
    CHECK(b.version == v + 1);

    /* Контрпримеры: тот же кандидат на той же цели не повторяется. */
    d2km_counterexample ce;
    memset(&ce, 0, sizeof(ce));
    ce.candidate = 0xabc; ce.experiment = 70; ce.target = T("a.com"); ce.result = rst;
    CHECK(d2km_box_add_counter(&b, &ce) == D2KM_BOX_OK);
    CHECK(d2km_box_tried(&b, 0xabc, &ce.target));
    CHECK(!d2km_box_tried(&b, 0xabc, &tb));
    CHECK(d2km_box_add_counter(&b, &ce) == D2KM_BOX_DUPLICATE);

    /* Деление по цели a.com: её факты, контрпримеры уходят в новую коробку. */
    d2km_box nb;
    d2km_target ta = T("a.com");
    v = b.version;
    CHECK(d2km_box_split(&b, &ta, &nb, 1) == D2KM_BOX_BAD_INPUT);
    CHECK(d2km_box_split(&b, &ta, &nb, 2) == D2KM_BOX_OK);
    CHECK(nb.id == 2 && nb.fact_count == 2 && nb.counter_count == 1 && nb.version == 1);
    CHECK(b.fact_count == 0 && b.counter_count == 0 && b.version == v + 1);
    CHECK(b.target_count == 1 && d2km_box_has_target(&b, &tb));
    CHECK(nb.hypotheses[D2KM_H_HELLO_NAME] == D2KM_HYP_CONFIRMED);
    /* Теперь факт x.com добавляется в старую коробку без деления. */
    CHECK(d2km_box_add_fact(&b, &fx, &conflict) == D2KM_BOX_OK);

    /* Предел фактов — FULL, не молчаливая потеря. */
    d2km_box full;
    d2km_box_init(&full, 9);
    d2km_fact o;
    for (int i = 0; i < D2KM_BOX_FACTS_MAX; i++) {
        d2km_arm_record x = rec("f.com", (uint32_t)(100 + i), 1, D2KM_OP_DELAY, 0, i, rst);
        CHECK(d2km_fact_observe(&o, (uint32_t)(100 + i), D2KM_F_STATE, &x, 0) == D2KM_FR_OK);
        CHECK(d2km_box_add_fact(&full, &o, NULL) == D2KM_BOX_OK);
    }
    d2km_arm_record x = rec("f.com", 999, 1, D2KM_OP_DELAY, 0, 999, rst);
    d2km_fact_observe(&o, 999, D2KM_F_STATE, &x, 0);
    CHECK(d2km_box_add_fact(&full, &o, NULL) == D2KM_BOX_FULL);
    DONE("test_box");
}
