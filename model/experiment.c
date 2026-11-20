#include "d2km_experiment.h"

static const char *const hypothesis_names[D2KM_HYPOTHESIS_END] = {
    [D2KM_H_ADDR_BLOCK] = "addr_block",
    [D2KM_H_PORT_BLOCK] = "port_block",
    [D2KM_H_SERVER_DOWN] = "server_down",
    [D2KM_H_NET_LOSS] = "net_loss",
    [D2KM_H_HELLO_NAME] = "hello_name",
    [D2KM_H_HELLO_FIELD] = "hello_field",
    [D2KM_H_HELLO_FORM] = "hello_form",
    [D2KM_H_ADDR_AFTER_HELLO] = "addr_after_hello",
    [D2KM_H_NAME_ABSORBED] = "name_absorbed",
    [D2KM_H_RESPONSE_BLOCK] = "response_block",
    [D2KM_H_SERVER_NO_REPLY] = "server_no_reply",
    [D2KM_H_VOLUME_CUT] = "volume_cut",
    [D2KM_H_TIME_CUT] = "time_cut",
    [D2KM_H_CONTENT_CUT] = "content_cut",
    [D2KM_H_SERVER_CLOSED] = "server_closed",
    [D2KM_H_BOX_ABSORBS] = "box_absorbs",
    [D2KM_H_SERVER_OVERLOAD] = "server_overload",
    [D2KM_H_QUIC_HEADER] = "quic_header",
    [D2KM_H_QUIC_INITIAL] = "quic_initial",
    [D2KM_H_UDP_PORT] = "udp_port",
    [D2KM_H_STUN_BLOCK] = "stun_block",
    [D2KM_H_DNS_BLOCK] = "dns_block",
    [D2KM_H_UDP_VOLUME] = "udp_volume",
    [D2KM_H_UDP_TIME] = "udp_time",
    [D2KM_H_UDP_CONTENT] = "udp_content",
    [D2KM_H_DNS_ADDR] = "dns_addr",
    [D2KM_H_DNS_NAME] = "dns_name",
    [D2KM_H_DNS_LONG_SESSION] = "dns_long_session",
    [D2KM_H_SERVER_REJECTS_SPOIL] = "server_rejects_spoil",
    [D2KM_H_SERVER_ACCEPTS_SPOIL] = "server_accepts_spoil",
    [D2KM_H_COPIES_ENOUGH] = "copies_enough",
    [D2KM_H_COPIES_INSUFFICIENT] = "copies_insufficient",
    [D2KM_H_HEADER_SPLIT_RELIEF] = "header_split_relief",
    [D2KM_H_HEADER_SPLIT_BLOCKED] = "header_split_blocked",
    [D2KM_H_COMBINATION_RELIEF] = "combination_relief",
    [D2KM_H_COMBINATION_BLOCKED] = "combination_blocked",

};

const char *d2km_hypothesis_name(d2km_hypothesis h)
{
    return (h > 0 && h < D2KM_HYPOTHESIS_END) ? hypothesis_names[h] : NULL;
}

/* Таблица §6.2, строки по коду сигнала, 0 — конец строки. */
static const d2km_hypothesis catalogue[D2KM_SIGNAL_END][D2KM_HYPOTHESES_MAX] = {
    [D2KM_S_SYN_SILENT] = {D2KM_H_ADDR_BLOCK, D2KM_H_PORT_BLOCK,
                           D2KM_H_SERVER_DOWN, D2KM_H_NET_LOSS},
    [D2KM_S_RST] = {D2KM_H_HELLO_NAME, D2KM_H_HELLO_FIELD, D2KM_H_HELLO_FORM,
                    D2KM_H_ADDR_AFTER_HELLO},
    [D2KM_S_HELLO_SILENT] = {D2KM_H_NAME_ABSORBED, D2KM_H_RESPONSE_BLOCK,
                             D2KM_H_SERVER_NO_REPLY},
    [D2KM_S_LATE_CUT] = {D2KM_H_VOLUME_CUT, D2KM_H_TIME_CUT,
                         D2KM_H_CONTENT_CUT, D2KM_H_SERVER_CLOSED},
    [D2KM_S_RETRANS] = {D2KM_H_BOX_ABSORBS, D2KM_H_NET_LOSS,
                        D2KM_H_SERVER_OVERLOAD},
    [D2KM_S_UDP_SILENT] = {D2KM_H_QUIC_HEADER, D2KM_H_QUIC_INITIAL,
                           D2KM_H_UDP_PORT, D2KM_H_STUN_BLOCK,
                           D2KM_H_DNS_BLOCK, D2KM_H_SERVER_DOWN},
    [D2KM_S_UDP_STOP] = {D2KM_H_UDP_VOLUME, D2KM_H_UDP_TIME,
                         D2KM_H_UDP_CONTENT},
    [D2KM_S_DNS_FAIL] = {D2KM_H_DNS_ADDR, D2KM_H_DNS_NAME,
                         D2KM_H_DNS_LONG_SESSION, D2KM_H_SERVER_DOWN},
};

size_t d2km_hypotheses_for(d2km_signal s, d2km_hypothesis *out, size_t cap)
{
    if (s <= 0 || s >= D2KM_SIGNAL_END)
        return 0;
    size_t n = 0;
    while (n < D2KM_HYPOTHESES_MAX && catalogue[s][n] != 0) {
        if (out != NULL && n < cap)
            out[n] = catalogue[s][n];
        n++;
    }
    return n;
}

static const char *const operator_names[D2KM_OPERATOR_END] = {
    [D2KM_OP_SET_FIELD] = "set_field",
    [D2KM_OP_DROP_FIELD] = "drop_field",
    [D2KM_OP_ADD_FIELD] = "add_field",
    [D2KM_OP_REORDER] = "reorder",
    [D2KM_OP_SPLIT] = "split",
    [D2KM_OP_ADD_MESSAGE] = "add_message",
    [D2KM_OP_SPOIL_TRANSPORT] = "spoil_transport",
    [D2KM_OP_LIMIT_DELIVERY] = "limit_delivery",
    [D2KM_OP_DELAY] = "delay",
    [D2KM_OP_WINDOW] = "window",
    [D2KM_OP_RESET_REPEAT] = "reset_repeat",
};

const char *d2km_operator_name(d2km_operator o)
{
    return (o > 0 && o < D2KM_OPERATOR_END) ? operator_names[o] : NULL;
}

static const char *const result_names[D2KM_RESULT_END] = {
    [D2KM_R_APP_OK] = "app_ok",
    [D2KM_R_REPLY] = "reply",
    [D2KM_R_NO_SERVICE] = "no_service",
    [D2KM_R_RST] = "rst",
    [D2KM_R_SYN_SILENT] = "syn_silent",
    [D2KM_R_HELLO_SILENT] = "hello_silent",
    [D2KM_R_CUT] = "cut",
    [D2KM_R_UDP_SILENT] = "udp_silent",
    [D2KM_R_ICMP] = "icmp",
    [D2KM_R_SPOOFED] = "spoofed",
    [D2KM_R_NOT_MEASURED] = "not_measured",
    [D2KM_R_LOCAL_FAIL] = "local_fail",
};

const char *d2km_result_name(d2km_result_kind k)
{
    return (k > 0 && k < D2KM_RESULT_END) ? result_names[k] : NULL;
}

static int result_valid(d2km_result r)
{
    return r.kind > 0 && r.kind < D2KM_RESULT_END;
}

int d2km_result_equal(d2km_result a, d2km_result b)
{
    return a.kind == b.kind && a.value == b.value;
}

int d2km_result_is_network(d2km_result r)
{
    return result_valid(r) && r.kind != D2KM_R_NOT_MEASURED &&
           r.kind != D2KM_R_LOCAL_FAIL;
}

int d2km_result_server_reached(d2km_result r)
{
    return r.kind == D2KM_R_APP_OK || r.kind == D2KM_R_REPLY ||
           r.kind == D2KM_R_NO_SERVICE;
}

static int action_valid(const d2km_action *a)
{
    return a->op > 0 && a->op < D2KM_OPERATOR_END;
}

d2km_experiment_check_code d2km_experiment_check(const d2km_experiment *e)
{
    if (e == NULL || e->id == 0)
        return D2KM_EC_NO_ID;
    if (e->kind != D2KM_E_DIRECT && e->kind != D2KM_E_QUESTION &&
        e->kind != D2KM_E_TRIAL)
        return D2KM_EC_BAD_KIND;
    if (d2km_context_valid(&e->context) != 0)
        return D2KM_EC_BAD_CONTEXT;
    if (e->memory_bytes == 0)
        return D2KM_EC_NO_MEMORY_DECLARED;
    if (e->prediction_count > D2KM_HYPOTHESES_MAX)
        return D2KM_EC_BAD_PREDICTION;

    if (e->kind == D2KM_E_DIRECT) {
        /* Прямой контроль — без воздействия ни в одном плече. Контрольное
         * плечо — тот же обмен через опорную точку. */
        if (e->arm.has_action || e->control.has_action)
            return D2KM_EC_DIRECT_HAS_ACTION;
        return D2KM_EC_OK;
    }
    if (e->kind == D2KM_E_TRIAL)
        return e->candidate != 0 ? D2KM_EC_OK : D2KM_EC_NO_CANDIDATE;

    if (e->prediction_count < 2)
        return D2KM_EC_FEW_HYPOTHESES;
    for (size_t i = 0; i < e->prediction_count; i++) {
        const d2km_prediction *p = &e->predictions[i];
        if (d2km_hypothesis_name(p->hypothesis) == NULL)
            return D2KM_EC_BAD_HYPOTHESIS;
        if (!d2km_result_is_network(p->predicted))
            return D2KM_EC_BAD_PREDICTION;
        for (size_t j = 0; j < i; j++)
            if (e->predictions[j].hypothesis == p->hypothesis)
                return D2KM_EC_DUPLICATE_HYPOTHESIS;
    }
    if (!e->arm.has_action)
        return D2KM_EC_NO_ACTION;
    if (!action_valid(&e->arm.action))
        return D2KM_EC_BAD_OPERATOR;
    /* Контрольное плечо: без воздействия либо с заранее известным исходом. */
    if (e->control.has_action && !e->control.has_expected)
        return D2KM_EC_NO_CONTROL;
    if (e->control.has_action && !action_valid(&e->control.action))
        return D2KM_EC_BAD_OPERATOR;
    if (e->control.has_expected && !d2km_result_is_network(e->control.expected))
        return D2KM_EC_NO_CONTROL;
    /* Вес §6.3: хотя бы две гипотезы с разным прогнозом. */
    for (size_t i = 1; i < e->prediction_count; i++)
        if (!d2km_result_equal(e->predictions[i].predicted,
                               e->predictions[0].predicted))
            return D2KM_EC_OK;
    return D2KM_EC_ZERO_WEIGHT;
}

int d2km_experiment_judge(const d2km_experiment *e, d2km_result r,
                          unsigned *confirmed, unsigned *refuted)
{
    unsigned c = 0, f = 0;
    int n = 0;
    if (confirmed != NULL)
        *confirmed = 0;
    if (refuted != NULL)
        *refuted = 0;
    if (e == NULL || !d2km_result_is_network(r))
        return -1;
    for (size_t i = 0; i < e->prediction_count && i < D2KM_HYPOTHESES_MAX; i++) {
        if (d2km_result_equal(e->predictions[i].predicted, r)) {
            c |= 1u << i;
            n++;
        } else {
            f |= 1u << i;
        }
    }
    if (confirmed != NULL)
        *confirmed = c;
    if (refuted != NULL)
        *refuted = f;
    return n;
}

d2km_arm_verdict d2km_arm_stability(const d2km_result *runs, size_t n,
                                    d2km_result *stable)
{
    if (runs == NULL && n)
        return D2KM_ARM_NOT_MEASURED;
    if (n > D2KM_ARM_RUNS_MAX)
        n = D2KM_ARM_RUNS_MAX;
    for (size_t i = 0; i < n; i++) {
        if (runs[i].kind == D2KM_R_LOCAL_FAIL)
            return D2KM_ARM_LOCAL_FAIL;
        if (!d2km_result_is_network(runs[i]))
            return D2KM_ARM_NOT_MEASURED;
        if (i > 0 && d2km_result_equal(runs[i - 1], runs[i])) {
            if (stable != NULL)
                *stable = runs[i];
            return D2KM_ARM_STABLE;
        }
    }
    return n >= D2KM_ARM_RUNS_MAX ? D2KM_ARM_CONFLICTING : D2KM_ARM_NEED_MORE;
}

d2km_outcome d2km_arm_verdict_outcome(d2km_arm_verdict v)
{
    switch (v) {
    case D2KM_ARM_CONFLICTING:
        return D2KM_CONFLICTING;
    case D2KM_ARM_LOCAL_FAIL:
        return D2KM_LOCAL_FAIL;
    case D2KM_ARM_NOT_MEASURED:
        return D2KM_NOT_MEASURED;
    default:
        return 0;
    }
}
