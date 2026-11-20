#include "d2km_codes.h"
#include "test.h"
#include <string.h>

static d2km_task_state step(d2km_task_state s, d2km_task_event_kind k, d2km_outcome o)
{
    d2km_task_event e = {k, o, 0};
    return d2km_task_next(s, &e);
}

int main(void)
{
    /* Имена: каждый код имеет имя, вне перечня — NULL. */
    for (int o = D2KM_DIRECT_OK; o < D2KM_OUTCOME_END; o++) {
        CHECK(d2km_outcome_name((d2km_outcome)o) != NULL);
        CHECK(d2km_outcome_next((d2km_outcome)o) != 0);
    }
    CHECK(d2km_outcome_name(0) == NULL);
    CHECK(d2km_outcome_name(D2KM_OUTCOME_END) == NULL);
    CHECK(strcmp(d2km_signal_name(D2KM_S_HELLO_SILENT), "S_HELLO_SILENT") == 0);
    CHECK(d2km_signal_name(D2KM_SIGNAL_END) == NULL);

    /* §4.7: только BLOCK_CONFIRMED доказывает блок, только APPLIED — обход. */
    for (int o = D2KM_DIRECT_OK; o < D2KM_OUTCOME_END; o++) {
        CHECK(d2km_outcome_proves_block((d2km_outcome)o) == (o == D2KM_BLOCK_CONFIRMED));
        CHECK(d2km_outcome_proves_bypass((d2km_outcome)o) == (o == D2KM_APPLIED));
    }
    CHECK(d2km_outcome_next(D2KM_TRIAL_FAIL) == D2KM_NEXT_ASK);
    CHECK(d2km_outcome_next(D2KM_DEGRADED) == D2KM_NEXT_DIRECT);
    CHECK(d2km_outcome_next(D2KM_BLOCK_GONE) == D2KM_NEXT_UNBIND_CLOSE);
    CHECK(d2km_outcome_next(D2KM_NO_RESOURCES) == D2KM_NEXT_WAIT);

    /* §4.6: полный путь до APPLIED. */
    d2km_task_state s = D2KM_T_SUSPECT;
    s = step(s, D2KM_EV_START, 0);                       CHECK(s == D2KM_T_DIRECT);
    s = step(s, D2KM_EV_OUTCOME, D2KM_BLOCK_CONFIRMED);  CHECK(s == D2KM_T_OWN);
    s = step(s, D2KM_EV_OWN_NONE, 0);                    CHECK(s == D2KM_T_ASK);
    s = step(s, D2KM_EV_MODEL_ENOUGH, 0);                CHECK(s == D2KM_T_SYNTH);
    s = step(s, D2KM_EV_NEED_FACT, 0);                   CHECK(s == D2KM_T_ASK);
    s = step(s, D2KM_EV_MODEL_ENOUGH, 0);                CHECK(s == D2KM_T_SYNTH);
    s = step(s, D2KM_EV_CANDIDATE, 0);                   CHECK(s == D2KM_T_TRIAL);
    s = step(s, D2KM_EV_OUTCOME, D2KM_TRIAL_FAIL);       CHECK(s == D2KM_T_ASK);
    s = step(s, D2KM_EV_MODEL_ENOUGH, 0);
    s = step(s, D2KM_EV_CANDIDATE, 0);
    s = step(s, D2KM_EV_TRIAL_OK, 0);                    CHECK(s == D2KM_T_APPLIED);
    s = step(s, D2KM_EV_OUTCOME, D2KM_DEGRADED);         CHECK(s == D2KM_T_DIRECT);
    CHECK(step(D2KM_T_APPLIED, D2KM_EV_OUTCOME, D2KM_BLOCK_GONE) == D2KM_T_CLOSED);

    /* DIRECT: закрывающие коды и отсрочка. */
    CHECK(step(D2KM_T_DIRECT, D2KM_EV_OUTCOME, D2KM_DIRECT_OK) == D2KM_T_CLOSED);
    CHECK(step(D2KM_T_DIRECT, D2KM_EV_OUTCOME, D2KM_SERVER_DOWN) == D2KM_T_CLOSED);
    CHECK(step(D2KM_T_DIRECT, D2KM_EV_OUTCOME, D2KM_NO_SERVICE) == D2KM_T_CLOSED);
    CHECK(step(D2KM_T_DIRECT, D2KM_EV_OUTCOME, D2KM_NO_REFERENCE) == D2KM_T_WAIT);
    CHECK(step(D2KM_T_DIRECT, D2KM_EV_OUTCOME, D2KM_FORM_NOT_REPRODUCED) == D2KM_T_WAIT);
    /* Обход не может «найтись» на прямом контроле. */
    CHECK(step(D2KM_T_DIRECT, D2KM_EV_OUTCOME, D2KM_APPLIED) == 0);

    /* ASK, SYNTH, OWN, TRIAL уходят в WAIT только по своим кодам. */
    CHECK(step(D2KM_T_ASK, D2KM_EV_OUTCOME, D2KM_MODEL_INCOMPLETE) == D2KM_T_WAIT);
    CHECK(step(D2KM_T_ASK, D2KM_EV_OUTCOME, D2KM_NO_RESOURCES) == D2KM_T_WAIT);
    CHECK(step(D2KM_T_ASK, D2KM_EV_OUTCOME, D2KM_TRIAL_FAIL) == 0);
    CHECK(step(D2KM_T_SYNTH, D2KM_EV_OUTCOME, D2KM_REQ_CONFLICT) == D2KM_T_WAIT);
    CHECK(step(D2KM_T_SYNTH, D2KM_EV_OUTCOME, D2KM_EXEC_UNSUPPORTED) == D2KM_T_WAIT);
    CHECK(step(D2KM_T_SYNTH, D2KM_EV_OUTCOME, D2KM_MODEL_INCOMPLETE) == 0);
    CHECK(step(D2KM_T_OWN, D2KM_EV_OWN_OK, 0) == D2KM_T_APPLIED);
    CHECK(step(D2KM_T_OWN, D2KM_EV_OUTCOME, D2KM_NO_RESOURCES) == D2KM_T_WAIT);
    CHECK(step(D2KM_T_TRIAL, D2KM_EV_OUTCOME, D2KM_LOCAL_FAIL) == D2KM_T_WAIT);

    /* WAIT: только условия пробуждения из закрытого перечня. */
    d2km_task_event wake = {D2KM_EV_WAKE, 0, D2KM_WAKE_MODEL_VERSION};
    CHECK(d2km_task_next(D2KM_T_WAIT, &wake) == D2KM_T_SUSPECT);
    wake.wake = 0;
    CHECK(d2km_task_next(D2KM_T_WAIT, &wake) == 0);
    wake.wake = D2KM_WAKE_END;
    CHECK(d2km_task_next(D2KM_T_WAIT, &wake) == 0);
    CHECK(step(D2KM_T_WAIT, D2KM_EV_START, 0) == 0);

    /* Закрытая задача никуда не переходит; мусор отвергается. */
    CHECK(step(D2KM_T_CLOSED, D2KM_EV_START, 0) == 0);
    CHECK(step(D2KM_T_DIRECT, D2KM_EV_OUTCOME, (d2km_outcome)99) == 0);
    CHECK(d2km_task_next(D2KM_T_SUSPECT, NULL) == 0);
    DONE("test_codes");
}
