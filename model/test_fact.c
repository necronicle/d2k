#include "d2km_fact.h"
#include "fixture.h"
#include "test.h"

static d2km_result R(d2km_result_kind k, int64_t v) { d2km_result r = {.kind = k, .value = v}; return r; }

static d2km_arm_record rec(uint32_t e, int has, d2km_operator op, uint32_t field,
                           int64_t value, d2km_result r)
{
    d2km_arm_record a;
    memset(&a, 0, sizeof(a));
    a.experiment = e;
    fixture_context(&a.context);
    a.arm.has_action = has;
    a.arm.action.op = op;
    a.arm.action.field = field;
    a.arm.action.value = value;
    a.result = r;
    return a;
}

int main(void)
{
    d2km_fact f;
    d2km_result ok = R(D2KM_R_APP_OK, 0), rst = R(D2KM_R_RST, 0);
    d2km_arm_record ctl = rec(3, 0, 0, 0, 0, ok);

    /* Наблюдённый факт: устойчивый исход плеча, причины не утверждает. */
    d2km_arm_record base = rec(1, 0, 0, 0, 0, rst);
    CHECK(d2km_fact_observe(&f, 10, D2KM_F_REACTION, &base, 1) == D2KM_FR_OK);
    CHECK(f.level == D2KM_LEVEL_OBSERVED && !d2km_fact_usable(&f));
    CHECK(f.source_count == 1 && f.sources[0] == 1);
    base.result = R(D2KM_R_LOCAL_FAIL, 0);
    CHECK(d2km_fact_observe(&f, 10, D2KM_F_REACTION, &base, 1) == D2KM_FR_NOT_NETWORK);
    base.result = rst;

    /* Установленный: без воздействия RST, с изменённым именем — успех. */
    d2km_arm_record name = rec(2, 1, D2KM_OP_SET_FIELD, 1, 1, ok);
    CHECK(d2km_fact_establish(&f, 11, D2KM_F_PARSE, &base, &name, &ctl, ok, 0, 2) == D2KM_FR_OK);
    CHECK(f.level == D2KM_LEVEL_ESTABLISHED && d2km_fact_usable(&f) && !f.numeric);
    CHECK(f.source_count == 3 && f.model_version == 2);

    /* Отказы установления. */
    d2km_arm_record same = rec(2, 1, D2KM_OP_SET_FIELD, 1, 1, rst);
    CHECK(d2km_fact_establish(&f, 11, D2KM_F_PARSE, &base, &same, &ctl, ok, 0, 2) == D2KM_FR_SAME_RESULT);
    d2km_arm_record twin = rec(4, 0, 0, 0, 0, ok);
    CHECK(d2km_fact_establish(&f, 11, D2KM_F_PARSE, &base, &twin, &ctl, ok, 0, 2) == D2KM_FR_SAME_ACTION);
    d2km_arm_record o1 = rec(5, 1, D2KM_OP_SET_FIELD, 1, 1, rst);
    d2km_arm_record o2 = rec(6, 1, D2KM_OP_SPLIT, 0, 37, ok);
    CHECK(d2km_fact_establish(&f, 11, D2KM_F_PARSE, &o1, &o2, &ctl, ok, 0, 2) == D2KM_FR_NOT_ONE_PARAMETER);
    o2 = rec(6, 1, D2KM_OP_SET_FIELD, 2, 1, ok);
    CHECK(d2km_fact_establish(&f, 11, D2KM_F_PARSE, &o1, &o2, &ctl, ok, 0, 2) == D2KM_FR_NOT_ONE_PARAMETER);
    d2km_arm_record other = name;
    other.context.form.ech = 1;
    CHECK(d2km_fact_establish(&f, 11, D2KM_F_PARSE, &base, &other, &ctl, ok, 0, 2) == D2KM_FR_CONTEXT_DIFFERS);
    d2km_arm_record ctl_bad = rec(3, 0, 0, 0, 0, R(D2KM_R_SYN_SILENT, 0));
    CHECK(d2km_fact_establish(&f, 11, D2KM_F_PARSE, &base, &name, &ctl_bad, R(D2KM_R_SYN_SILENT, 0), 0, 2)
          == D2KM_FR_CONTROL_FAILED);   /* сервер не достигнут */
    CHECK(d2km_fact_establish(&f, 11, D2KM_F_PARSE, &base, &name, &ctl, R(D2KM_R_REPLY, 0), 0, 2)
          == D2KM_FR_CONTROL_FAILED);   /* не тот исход, что ожидали */
    d2km_arm_record ctl_far = ctl;
    ctl_far.context.path.mtu = 1280;
    CHECK(d2km_fact_establish(&f, 11, D2KM_F_PARSE, &base, &name, &ctl_far, ok, 0, 2) == D2KM_FR_CONTROL_CONTEXT);
    d2km_arm_record lf = rec(9, 1, D2KM_OP_SET_FIELD, 1, 1, R(D2KM_R_NOT_MEASURED, 0));
    CHECK(d2km_fact_establish(&f, 11, D2KM_F_PARSE, &base, &lf, &ctl, ok, 0, 2) == D2KM_FR_NOT_NETWORK);

    /* Числовой факт: соседние TTL 4 и 5, порядок плеч не важен. */
    d2km_arm_record t5 = rec(20, 1, D2KM_OP_LIMIT_DELIVERY, 0, 5, rst);
    d2km_arm_record t4 = rec(21, 1, D2KM_OP_LIMIT_DELIVERY, 0, 4, ok);
    CHECK(d2km_fact_establish(&f, 12, D2KM_F_PATH, &t5, &t4, &ctl, ok, 1, 3) == D2KM_FR_OK);
    CHECK(f.numeric && f.a.action.value == 4 && f.b.action.value == 5);
    CHECK(f.ra.kind == D2KM_R_APP_OK && f.rb.kind == D2KM_R_RST);
    /* Не соседние значения — установленный, но не числовой. */
    d2km_arm_record t8 = rec(22, 1, D2KM_OP_LIMIT_DELIVERY, 0, 8, rst);
    CHECK(d2km_fact_establish(&f, 13, D2KM_F_PATH, &t8, &t4, &ctl, ok, 1, 3) == D2KM_FR_OK);
    CHECK(!f.numeric && f.level == D2KM_LEVEL_ESTABLISHED);

    /* Контрпример понижает факт до наблюдённого. */
    CHECK(d2km_fact_establish(&f, 12, D2KM_F_PATH, &t5, &t4, &ctl, ok, 1, 3) == D2KM_FR_OK);
    d2km_arm_record counter = rec(30, 1, D2KM_OP_LIMIT_DELIVERY, 0, 5, ok);
    CHECK(d2km_fact_contradicted(&f, &counter));
    d2km_arm_record agree = rec(31, 1, D2KM_OP_LIMIT_DELIVERY, 0, 5, rst);
    CHECK(!d2km_fact_contradicted(&f, &agree));
    d2km_arm_record unrelated = rec(32, 1, D2KM_OP_LIMIT_DELIVERY, 0, 9, ok);
    CHECK(!d2km_fact_contradicted(&f, &unrelated));
    d2km_arm_record elsewhere = counter;
    elsewhere.context.form.grease = 1;
    CHECK(!d2km_fact_contradicted(&f, &elsewhere));
    CHECK(d2km_fact_demote(&f, 30, 4) == D2KM_FR_OK);
    CHECK(f.level == D2KM_LEVEL_OBSERVED && !d2km_fact_usable(&f) && f.model_version == 4);
    CHECK(f.sources[f.source_count - 1] == 30);
    CHECK(d2km_fact_demote(&f, 31, 5) == D2KM_FR_BAD_INPUT);   /* уже наблюдённый */
    CHECK(!d2km_fact_contradicted(&f, &counter));
    /* Отдельный серверный PATH-контракт не разрешает общий вывод о
       нечитаемости по APP_OK и не принимает другие действия/значения. */
    d2km_arm_record clean = rec(40, 0, 0, 0, 0, ok);
    d2km_arm_record spoil = rec(41, 1, D2KM_OP_SPOIL_TRANSPORT, D2KM_FIELD_SPOIL, 1, ok);
    CHECK(d2km_fact_establish_invariance(&f, 20, D2KM_F_PATH, &clean, &spoil, &clean, ok, 5) == D2KM_FR_OK);
    CHECK(f.invariant && f.source_count == 2 && d2km_fact_unread_form(&f) == 0);
    CHECK(d2km_fact_establish_invariance(&f, 20, D2KM_F_PARSE, &clean, &spoil, &clean, ok, 5) == D2KM_FR_NOT_BOX_REACTION);
    d2km_arm_record bad = spoil; bad.arm.action.field = D2KM_FIELD_FORM | D2KM_FORM_HELLO;
    CHECK(d2km_fact_establish_invariance(&f, 20, D2KM_F_PATH, &clean, &bad, &clean, ok, 5) == D2KM_FR_NOT_BOX_REACTION);
    bad = spoil; bad.arm.action.op = D2KM_OP_SET_FIELD;
    CHECK(d2km_fact_establish_invariance(&f, 20, D2KM_F_PATH, &clean, &bad, &clean, ok, 5) == D2KM_FR_NOT_BOX_REACTION);
    bad = spoil; bad.arm.action.value = 4;
    CHECK(d2km_fact_establish_invariance(&f, 20, D2KM_F_PATH, &clean, &bad, &clean, ok, 5) == D2KM_FR_NOT_BOX_REACTION);
    bad = clean; bad.context.path.mtu--;
    CHECK(d2km_fact_establish_invariance(&f, 20, D2KM_F_PATH, &clean, &spoil, &bad, ok, 5) == D2KM_FR_CONTROL_CONTEXT);
    bad = spoil; bad.result = R(D2KM_R_LOCAL_FAIL, 0);
    CHECK(d2km_fact_establish_invariance(&f, 20, D2KM_F_PATH, &clean, &bad, &clean, ok, 5) == D2KM_FR_NOT_NETWORK);
    CHECK(d2km_fact_establish_invariance(&f, 20, D2KM_F_PARSE, &clean, &name, &clean, ok, 5) == D2KM_FR_NOT_BOX_REACTION);
    DONE("test_fact");
}
