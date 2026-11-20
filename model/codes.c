#include "d2km_codes.h"

static const char *const signal_names[D2KM_SIGNAL_END] = {
    [D2KM_S_RST] = "S_RST",
    [D2KM_S_SYN_SILENT] = "S_SYN_SILENT",
    [D2KM_S_HELLO_SILENT] = "S_HELLO_SILENT",
    [D2KM_S_LATE_CUT] = "S_LATE_CUT",
    [D2KM_S_RETRANS] = "S_RETRANS",
    [D2KM_S_UDP_SILENT] = "S_UDP_SILENT",
    [D2KM_S_UDP_STOP] = "S_UDP_STOP",
    [D2KM_S_DNS_FAIL] = "S_DNS_FAIL",
};

static const char *const outcome_names[D2KM_OUTCOME_END] = {
    [D2KM_DIRECT_OK] = "DIRECT_OK",
    [D2KM_BLOCK_CONFIRMED] = "BLOCK_CONFIRMED",
    [D2KM_BLOCK_GONE] = "BLOCK_GONE",
    [D2KM_SERVER_DOWN] = "SERVER_DOWN",
    [D2KM_NO_SERVICE] = "NO_SERVICE",
    [D2KM_NO_REFERENCE] = "NO_REFERENCE",
    [D2KM_NOT_MEASURED] = "NOT_MEASURED",
    [D2KM_FORM_NOT_REPRODUCED] = "FORM_NOT_REPRODUCED",
    [D2KM_LOCAL_FAIL] = "LOCAL_FAIL",
    [D2KM_EVENT_LOST] = "EVENT_LOST",
    [D2KM_NO_RESOURCES] = "NO_RESOURCES",
    [D2KM_CONFLICTING] = "CONFLICTING",
    [D2KM_MODEL_INCOMPLETE] = "MODEL_INCOMPLETE",
    [D2KM_REQ_CONFLICT] = "REQ_CONFLICT",
    [D2KM_EXEC_UNSUPPORTED] = "EXEC_UNSUPPORTED",
    [D2KM_TRIAL_FAIL] = "TRIAL_FAIL",
    [D2KM_APPLIED] = "APPLIED",
    [D2KM_DEGRADED] = "DEGRADED",
};

static const char *const state_names[D2KM_TASK_STATE_END] = {
    [D2KM_T_SUSPECT] = "SUSPECT",
    [D2KM_T_DIRECT] = "DIRECT",
    [D2KM_T_OWN] = "OWN",
    [D2KM_T_ASK] = "ASK",
    [D2KM_T_SYNTH] = "SYNTH",
    [D2KM_T_TRIAL] = "TRIAL",
    [D2KM_T_APPLIED] = "APPLIED",
    [D2KM_T_WAIT] = "WAIT",
    [D2KM_T_CLOSED] = "CLOSED",
};

static const char *const wake_names[D2KM_WAKE_END] = {
    [D2KM_WAKE_NEW_SIGNAL] = "new_signal",
    [D2KM_WAKE_MODEL_VERSION] = "model_version",
    [D2KM_WAKE_NEW_KNOWLEDGE] = "new_knowledge",
    [D2KM_WAKE_RESOURCE_FREED] = "resource_freed",
};

const char *d2km_signal_name(d2km_signal s)
{
    return (s > 0 && s < D2KM_SIGNAL_END) ? signal_names[s] : NULL;
}

const char *d2km_outcome_name(d2km_outcome o)
{
    return d2km_outcome_valid(o) ? outcome_names[o] : NULL;
}

const char *d2km_task_state_name(d2km_task_state s)
{
    return (s > 0 && s < D2KM_TASK_STATE_END) ? state_names[s] : NULL;
}

const char *d2km_wake_name(d2km_wake w)
{
    return (w > 0 && w < D2KM_WAKE_END) ? wake_names[w] : NULL;
}

int d2km_outcome_valid(d2km_outcome o)
{
    return o > 0 && o < D2KM_OUTCOME_END;
}

d2km_next_step d2km_outcome_next(d2km_outcome o)
{
    switch (o) {
    case D2KM_DIRECT_OK:
    case D2KM_SERVER_DOWN:
    case D2KM_NO_SERVICE:
        return D2KM_NEXT_CLOSE;
    case D2KM_BLOCK_CONFIRMED:
        return D2KM_NEXT_OWN;
    case D2KM_BLOCK_GONE:
        return D2KM_NEXT_UNBIND_CLOSE;
    case D2KM_NO_REFERENCE:
    case D2KM_NOT_MEASURED:
    case D2KM_FORM_NOT_REPRODUCED:
    case D2KM_LOCAL_FAIL:
    case D2KM_EVENT_LOST:
    case D2KM_NO_RESOURCES:
    case D2KM_CONFLICTING:
    case D2KM_MODEL_INCOMPLETE:
    case D2KM_REQ_CONFLICT:
    case D2KM_EXEC_UNSUPPORTED:
        return D2KM_NEXT_WAIT;
    case D2KM_TRIAL_FAIL:
        return D2KM_NEXT_ASK;
    case D2KM_APPLIED:
        return D2KM_NEXT_WATCH;
    case D2KM_DEGRADED:
        return D2KM_NEXT_DIRECT;
    default:
        return 0;
    }
}

int d2km_outcome_proves_block(d2km_outcome o)
{
    return o == D2KM_BLOCK_CONFIRMED;
}

int d2km_outcome_proves_bypass(d2km_outcome o)
{
    return o == D2KM_APPLIED;
}

/* Коды, с которыми ASK уходит в WAIT (§4.6). */
static int ask_waits(d2km_outcome o)
{
    return o == D2KM_MODEL_INCOMPLETE || o == D2KM_NOT_MEASURED ||
           o == D2KM_NO_REFERENCE || o == D2KM_CONFLICTING ||
           o == D2KM_LOCAL_FAIL;
}

/* Коды, которые прерывают любой шаг с опытами: ресурсы и потеря события
 * не являются ответом коробки и ведут в отсрочку (§4.7). */
static int resource_wait(d2km_outcome o)
{
    return o == D2KM_NO_RESOURCES || o == D2KM_EVENT_LOST ||
           o == D2KM_LOCAL_FAIL;
}

d2km_task_state d2km_task_next(d2km_task_state s, const d2km_task_event *ev)
{
    if (ev == NULL)
        return 0;
    if (ev->kind == D2KM_EV_OUTCOME && !d2km_outcome_valid(ev->outcome))
        return 0;
    switch (s) {
    case D2KM_T_SUSPECT:
        return ev->kind == D2KM_EV_START ? D2KM_T_DIRECT : 0;
    case D2KM_T_DIRECT:
        if (ev->kind != D2KM_EV_OUTCOME)
            return 0;
        switch (ev->outcome) {
        case D2KM_DIRECT_OK:
        case D2KM_SERVER_DOWN:
        case D2KM_NO_SERVICE:
            return D2KM_T_CLOSED;
        case D2KM_BLOCK_CONFIRMED:
            return D2KM_T_OWN;
        case D2KM_NO_REFERENCE:
        case D2KM_NOT_MEASURED:
        case D2KM_FORM_NOT_REPRODUCED:
        case D2KM_LOCAL_FAIL:
        case D2KM_EVENT_LOST:
        case D2KM_NO_RESOURCES:
        case D2KM_CONFLICTING:
            return D2KM_T_WAIT;
        default:
            return 0;
        }
    case D2KM_T_OWN:
        if (ev->kind == D2KM_EV_OWN_OK)
            return D2KM_T_APPLIED;
        if (ev->kind == D2KM_EV_OWN_NONE)
            return D2KM_T_ASK;
        if (ev->kind == D2KM_EV_OUTCOME && resource_wait(ev->outcome))
            return D2KM_T_WAIT;
        return 0;
    case D2KM_T_ASK:
        if (ev->kind == D2KM_EV_MODEL_ENOUGH)
            return D2KM_T_SYNTH;
        if (ev->kind == D2KM_EV_OUTCOME &&
            (ask_waits(ev->outcome) || resource_wait(ev->outcome)))
            return D2KM_T_WAIT;
        return 0;
    case D2KM_T_SYNTH:
        if (ev->kind == D2KM_EV_CANDIDATE)
            return D2KM_T_TRIAL;
        if (ev->kind == D2KM_EV_NEED_FACT)
            return D2KM_T_ASK;
        if (ev->kind == D2KM_EV_OUTCOME &&
            (ev->outcome == D2KM_REQ_CONFLICT ||
             ev->outcome == D2KM_EXEC_UNSUPPORTED))
            return D2KM_T_WAIT;
        return 0;
    case D2KM_T_TRIAL:
        if (ev->kind == D2KM_EV_TRIAL_OK)
            return D2KM_T_APPLIED;
        if (ev->kind == D2KM_EV_OUTCOME && ev->outcome == D2KM_TRIAL_FAIL)
            return D2KM_T_ASK;
        /* Противоречивые прогоны или прогон без наблюдений — не провал
           кандидата: контрпримера нет, задача ждёт. */
        if (ev->kind == D2KM_EV_OUTCOME &&
            (resource_wait(ev->outcome) || ev->outcome == D2KM_CONFLICTING ||
             ev->outcome == D2KM_NOT_MEASURED))
            return D2KM_T_WAIT;
        return 0;
    case D2KM_T_APPLIED:
        if (ev->kind != D2KM_EV_OUTCOME)
            return 0;
        if (ev->outcome == D2KM_DEGRADED)
            return D2KM_T_DIRECT;
        if (ev->outcome == D2KM_BLOCK_GONE)
            return D2KM_T_CLOSED;
        return 0;
    case D2KM_T_WAIT:
        if (ev->kind == D2KM_EV_WAKE && ev->wake > 0 && ev->wake < D2KM_WAKE_END)
            return D2KM_T_SUSPECT;
        return 0;
    default:
        return 0;
    }
}
