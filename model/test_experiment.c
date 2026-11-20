#include "d2km_experiment.h"
#include "fixture.h"
#include "test.h"

static d2km_result R(d2km_result_kind k, int64_t v) { d2km_result r = {k, v}; return r; }

static void question(d2km_experiment *e)
{
    memset(e, 0, sizeof(*e));
    e->id = 7;
    e->kind = D2KM_E_QUESTION;
    fixture_context(&e->context);
    e->memory_bytes = 4096;
    e->arm.has_action = 1;
    e->arm.action.op = D2KM_OP_SET_FIELD;
    e->arm.action.field = 1;   /* имя в приветствии */
    e->arm.action.value = 1;
    e->prediction_count = 2;
    e->predictions[0].hypothesis = D2KM_H_HELLO_NAME;
    e->predictions[0].predicted = R(D2KM_R_APP_OK, 0);
    e->predictions[1].hypothesis = D2KM_H_ADDR_AFTER_HELLO;
    e->predictions[1].predicted = R(D2KM_R_RST, 0);
}

int main(void)
{
    /* §6.2: перечень гипотез по сигналу. */
    d2km_hypothesis hs[D2KM_HYPOTHESES_MAX];
    CHECK(d2km_hypotheses_for(D2KM_S_HELLO_SILENT, hs, 8) == 3);
    CHECK(hs[1] == D2KM_H_RESPONSE_BLOCK);
    CHECK(d2km_hypotheses_for(D2KM_S_UDP_SILENT, hs, 2) == 6);   /* число — полное */
    CHECK(d2km_hypotheses_for(0, hs, 8) == 0);
    for (int s = D2KM_S_RST; s < D2KM_SIGNAL_END; s++) {
        size_t n = d2km_hypotheses_for((d2km_signal)s, hs, 8);
        CHECK(n >= 3);
        for (size_t i = 0; i < n; i++)
            CHECK(d2km_hypothesis_name(hs[i]) != NULL);
    }
    for (int o = D2KM_OP_SET_FIELD; o < D2KM_OPERATOR_END; o++)
        CHECK(d2km_operator_name((d2km_operator)o) != NULL);

    /* §6.1: вопрос со всем записанным проходит. */
    d2km_experiment e;
    question(&e);
    CHECK(d2km_experiment_check(&e) == D2KM_EC_OK);
    question(&e); e.id = 0;                 CHECK(d2km_experiment_check(&e) == D2KM_EC_NO_ID);
    question(&e); e.memory_bytes = 0;       CHECK(d2km_experiment_check(&e) == D2KM_EC_NO_MEMORY_DECLARED);
    question(&e); e.prediction_count = 1;   CHECK(d2km_experiment_check(&e) == D2KM_EC_FEW_HYPOTHESES);
    question(&e); e.predictions[1].hypothesis = D2KM_H_HELLO_NAME;
    CHECK(d2km_experiment_check(&e) == D2KM_EC_DUPLICATE_HYPOTHESIS);
    question(&e); e.predictions[1].hypothesis = 0;
    CHECK(d2km_experiment_check(&e) == D2KM_EC_BAD_HYPOTHESIS);
    question(&e); e.arm.has_action = 0;     CHECK(d2km_experiment_check(&e) == D2KM_EC_NO_ACTION);
    question(&e); e.arm.action.op = 0;      CHECK(d2km_experiment_check(&e) == D2KM_EC_BAD_OPERATOR);
    question(&e); e.predictions[1].predicted = R(D2KM_R_APP_OK, 0);
    CHECK(d2km_experiment_check(&e) == D2KM_EC_ZERO_WEIGHT);
    question(&e); e.predictions[1].predicted = R(D2KM_R_LOCAL_FAIL, 0);
    CHECK(d2km_experiment_check(&e) == D2KM_EC_BAD_PREDICTION);
    /* Контроль с воздействием — только с известным исходом. */
    question(&e); e.control.has_action = 1; e.control.action.op = D2KM_OP_DELAY;
    CHECK(d2km_experiment_check(&e) == D2KM_EC_NO_CONTROL);
    e.control.has_expected = 1; e.control.expected = R(D2KM_R_APP_OK, 0);
    CHECK(d2km_experiment_check(&e) == D2KM_EC_OK);
    question(&e); e.context.protocol = D2KM_P_QUIC1;
    CHECK(d2km_experiment_check(&e) == D2KM_EC_BAD_CONTEXT);

    /* Прямой контроль — без воздействия; испытание — с кандидатом. */
    question(&e); e.kind = D2KM_E_DIRECT;
    CHECK(d2km_experiment_check(&e) == D2KM_EC_DIRECT_HAS_ACTION);
    e.arm.has_action = 0;
    CHECK(d2km_experiment_check(&e) == D2KM_EC_OK);
    question(&e); e.kind = D2KM_E_TRIAL;
    CHECK(d2km_experiment_check(&e) == D2KM_EC_NO_CANDIDATE);
    e.candidate = 0x680fbe00u;
    CHECK(d2km_experiment_check(&e) == D2KM_EC_OK);

    /* Критерий по прогнозам. */
    question(&e);
    unsigned c, f;
    CHECK(d2km_experiment_judge(&e, R(D2KM_R_APP_OK, 0), &c, &f) == 1);
    CHECK(c == 1u && f == 2u);
    CHECK(d2km_experiment_judge(&e, R(D2KM_R_HELLO_SILENT, 0), &c, &f) == 0);
    CHECK(c == 0 && f == 3u);
    /* Локальный отказ ничего не говорит о коробке. */
    CHECK(d2km_experiment_judge(&e, R(D2KM_R_LOCAL_FAIL, 0), &c, &f) == -1);
    CHECK(c == 0 && f == 0);

    /* §5.2: правило повтора. */
    d2km_result st;
    d2km_result r1[] = {R(D2KM_R_RST, 0), R(D2KM_R_RST, 0)};
    CHECK(d2km_arm_stability(r1, 2, &st) == D2KM_ARM_STABLE && st.kind == D2KM_R_RST);
    d2km_result r2[] = {R(D2KM_R_RST, 0)};
    CHECK(d2km_arm_stability(r2, 1, &st) == D2KM_ARM_NEED_MORE);
    CHECK(d2km_arm_stability(NULL, 0, &st) == D2KM_ARM_NEED_MORE);
    d2km_result r3[] = {R(D2KM_R_RST, 0), R(D2KM_R_APP_OK, 0), R(D2KM_R_APP_OK, 0)};
    CHECK(d2km_arm_stability(r3, 3, &st) == D2KM_ARM_STABLE && st.kind == D2KM_R_APP_OK);
    d2km_result r4[] = {R(D2KM_R_RST, 0), R(D2KM_R_APP_OK, 0), R(D2KM_R_RST, 0), R(D2KM_R_APP_OK, 0)};
    CHECK(d2km_arm_stability(r4, 3, &st) == D2KM_ARM_NEED_MORE);
    CHECK(d2km_arm_stability(r4, 4, &st) == D2KM_ARM_CONFLICTING);
    CHECK(d2km_arm_verdict_outcome(D2KM_ARM_CONFLICTING) == D2KM_CONFLICTING);
    /* Объём обрыва — часть исхода: разный объём — не одинаковые исходы. */
    d2km_result r5[] = {R(D2KM_R_CUT, 16), R(D2KM_R_CUT, 17), R(D2KM_R_CUT, 17)};
    CHECK(d2km_arm_stability(r5, 2, &st) == D2KM_ARM_NEED_MORE);
    CHECK(d2km_arm_stability(r5, 3, &st) == D2KM_ARM_STABLE && st.value == 17);
    d2km_result r6[] = {R(D2KM_R_RST, 0), R(D2KM_R_LOCAL_FAIL, 5)};
    CHECK(d2km_arm_stability(r6, 2, &st) == D2KM_ARM_LOCAL_FAIL);
    CHECK(d2km_arm_verdict_outcome(D2KM_ARM_LOCAL_FAIL) == D2KM_LOCAL_FAIL);
    d2km_result r7[] = {R(D2KM_R_NOT_MEASURED, 0)};
    CHECK(d2km_arm_stability(r7, 1, &st) == D2KM_ARM_NOT_MEASURED);
    DONE("test_experiment");
}
