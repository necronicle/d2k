#include "d2km_fact.h"

#include <string.h>

static const char *const kind_names[D2KM_FACT_KIND_END] = {
    [D2KM_F_PATH] = "path",
    [D2KM_F_PARSE] = "parse",
    [D2KM_F_ASSEMBLY] = "assembly",
    [D2KM_F_CHECKS] = "checks",
    [D2KM_F_REACTION] = "reaction",
    [D2KM_F_STATE] = "state",
    [D2KM_F_VOLUME] = "volume",
    [D2KM_F_RESPONSE] = "response",
    [D2KM_F_NAME] = "name",
};

const char *d2km_fact_kind_name(d2km_fact_kind k)
{
    return (k > 0 && k < D2KM_FACT_KIND_END) ? kind_names[k] : NULL;
}

const char *d2km_fact_reason_name(d2km_fact_reason r)
{
    switch (r) {
    case D2KM_FR_OK: return "ok";
    case D2KM_FR_BAD_INPUT: return "bad_input";
    case D2KM_FR_NOT_NETWORK: return "not_network";
    case D2KM_FR_CONTEXT_DIFFERS: return "context_differs";
    case D2KM_FR_NOT_ONE_PARAMETER: return "not_one_parameter";
    case D2KM_FR_SAME_ACTION: return "same_action";
    case D2KM_FR_SAME_RESULT: return "same_result";
    case D2KM_FR_CONTROL_FAILED: return "control_failed";
    case D2KM_FR_CONTROL_CONTEXT: return "control_context";
    case D2KM_FR_TOO_MANY_SOURCES: return "too_many_sources";
    case D2KM_FR_NOT_BOX_REACTION: return "not_box_reaction";
    }
    return NULL;
}

static int kind_valid(d2km_fact_kind k)
{
    return k > 0 && k < D2KM_FACT_KIND_END;
}

static int action_equal(const d2km_arm *x, const d2km_arm *y)
{
    if (x->has_action != y->has_action)
        return 0;
    if (!x->has_action)
        return 1;
    return x->action.op == y->action.op && x->action.field == y->action.field &&
           x->action.value == y->action.value;
}

static void arm_copy(d2km_arm *dst, const d2km_arm *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->has_action = src->has_action;
    if (src->has_action)
        dst->action = src->action;
}

d2km_fact_reason d2km_fact_observe(d2km_fact *f, uint32_t id, d2km_fact_kind kind,
                                   const d2km_arm_record *r, uint32_t version)
{
    if (f == NULL || r == NULL || id == 0 || r->experiment == 0 ||
        !kind_valid(kind))
        return D2KM_FR_BAD_INPUT;
    if (!d2km_result_is_network(r->result))
        return D2KM_FR_NOT_NETWORK;
    memset(f, 0, sizeof(*f));
    f->id = id;
    f->kind = kind;
    f->level = D2KM_LEVEL_OBSERVED;
    f->context = r->context;
    arm_copy(&f->a, &r->arm);
    f->ra = r->result;
    f->sources[0] = r->experiment;
    f->source_count = 1;
    f->model_version = version;
    return D2KM_FR_OK;
}

static void add_source(d2km_fact *f, uint32_t e)
{
    for (size_t i = 0; i < f->source_count; i++)
        if (f->sources[i] == e)
            return;
    f->sources[f->source_count++] = e;
}

d2km_fact_reason d2km_fact_establish(d2km_fact *f, uint32_t id, d2km_fact_kind kind,
                                     const d2km_arm_record *a,
                                     const d2km_arm_record *b,
                                     const d2km_arm_record *control,
                                     d2km_result control_expected,
                                     int64_t resolution, uint32_t version)
{
    if (f == NULL || a == NULL || b == NULL || control == NULL || id == 0 ||
        !kind_valid(kind) || resolution < 0 || a->experiment == 0 ||
        b->experiment == 0 || control->experiment == 0)
        return D2KM_FR_BAD_INPUT;
    if (!d2km_result_is_network(a->result) || !d2km_result_is_network(b->result) ||
        !d2km_result_is_network(control->result))
        return D2KM_FR_NOT_NETWORK;
    /* Цель, путь, семейство, протокол и вся форма совпадают. */
    if (d2km_context_diff(&a->context, &b->context) != 0)
        return D2KM_FR_CONTEXT_DIFFERS;
    if (d2km_context_diff(&a->context, &control->context) != 0)
        return D2KM_FR_CONTROL_CONTEXT;
    if (action_equal(&a->arm, &b->arm))
        return D2KM_FR_SAME_ACTION;
    /* Ровно один параметр одного оператора: либо одно плечо без
     * воздействия, либо одно поле одного оператора с разными значениями. */
    int numeric = 0;
    if (a->arm.has_action && b->arm.has_action) {
        if (a->arm.action.op != b->arm.action.op ||
            a->arm.action.field != b->arm.action.field)
            return D2KM_FR_NOT_ONE_PARAMETER;
        int64_t va = a->arm.action.value, vb = b->arm.action.value;
        int64_t d = va > vb ? va - vb : vb - va;
        numeric = resolution > 0 && d == resolution;
    }
    if (d2km_result_equal(a->result, b->result))
        return D2KM_FR_SAME_RESULT;
    if (!d2km_result_equal(control->result, control_expected) ||
        !d2km_result_server_reached(control->result))
        return D2KM_FR_CONTROL_FAILED;

    const d2km_arm_record *lo = a, *hi = b;
    if (numeric && a->arm.action.value > b->arm.action.value) {
        lo = b;
        hi = a;
    }
    memset(f, 0, sizeof(*f));
    f->id = id;
    f->kind = kind;
    f->level = D2KM_LEVEL_ESTABLISHED;
    f->context = a->context;
    arm_copy(&f->a, &lo->arm);
    arm_copy(&f->b, &hi->arm);
    f->ra = lo->result;
    f->rb = hi->result;
    f->numeric = numeric;
    add_source(f, a->experiment);
    add_source(f, b->experiment);
    add_source(f, control->experiment);
    f->model_version = version;
    return D2KM_FR_OK;
}

int d2km_result_is_box_reaction(d2km_result r)
{
    return r.kind == D2KM_R_RST || r.kind == D2KM_R_SYN_SILENT ||
           r.kind == D2KM_R_HELLO_SILENT || r.kind == D2KM_R_CUT ||
           r.kind == D2KM_R_UDP_SILENT || r.kind == D2KM_R_SPOOFED;
}

d2km_fact_reason d2km_fact_establish_invariance(d2km_fact *f, uint32_t id,
                                               d2km_fact_kind kind,
                                               const d2km_arm_record *a,
                                               const d2km_arm_record *b,
                                               const d2km_arm_record *control,
                                               d2km_result control_expected,
                                               uint32_t version)
{
    if (f == NULL || a == NULL || b == NULL || control == NULL || id == 0 ||
        !kind_valid(kind) || a->experiment == 0 || b->experiment == 0 ||
        control->experiment == 0)
        return D2KM_FR_BAD_INPUT;
    if (!d2km_result_is_network(a->result) || !d2km_result_is_network(b->result) ||
        !d2km_result_is_network(control->result))
        return D2KM_FR_NOT_NETWORK;
    if (d2km_context_diff(&a->context, &b->context) != 0)
        return D2KM_FR_CONTEXT_DIFFERS;
    if (d2km_context_diff(&a->context, &control->context) != 0)
        return D2KM_FR_CONTROL_CONTEXT;
    if (action_equal(&a->arm, &b->arm))
        return D2KM_FR_SAME_ACTION;
    if (a->arm.has_action && b->arm.has_action &&
        (a->arm.action.op != b->arm.action.op ||
         a->arm.action.field != b->arm.action.field))
        return D2KM_FR_NOT_ONE_PARAMETER;
    if (!d2km_result_equal(a->result, b->result))
        return D2KM_FR_SAME_RESULT;   /* исходы разные: это не неизменность */
    /* Это отдельное утверждение о безопасности для СЕРВЕРА, не о
     * нечитаемости поля коробкой (§5.2). Только канонический вопрос B:
     * контроль/база без воздействия, одна именованная порча 1..3. */
    int server_rejection = kind == D2KM_F_PATH &&
        !a->arm.has_action && b->arm.has_action && !control->arm.has_action &&
        b->arm.action.op == D2KM_OP_SPOIL_TRANSPORT &&
        b->arm.action.field == D2KM_FIELD_SPOIL &&
        b->arm.action.value >= 1 && b->arm.action.value <= 3 &&
        a->result.kind == D2KM_R_APP_OK && control_expected.kind == D2KM_R_APP_OK;
    if (!d2km_result_is_box_reaction(a->result) && !server_rejection)
        return D2KM_FR_NOT_BOX_REACTION;
    if (!d2km_result_equal(control->result, control_expected) ||
        !d2km_result_server_reached(control->result))
        return D2KM_FR_CONTROL_FAILED;
    /* Плечо без воздействия — первым. */
    const d2km_arm_record *x = a, *y = b;
    if (!b->arm.has_action && a->arm.has_action) {
        x = b;
        y = a;
    }
    memset(f, 0, sizeof(*f));
    f->id = id;
    f->kind = kind;
    f->level = D2KM_LEVEL_ESTABLISHED;
    f->context = a->context;
    arm_copy(&f->a, &x->arm);
    arm_copy(&f->b, &y->arm);
    f->ra = x->result;
    f->rb = y->result;
    f->invariant = 1;
    add_source(f, a->experiment);
    add_source(f, b->experiment);
    add_source(f, control->experiment);
    f->model_version = version;
    return D2KM_FR_OK;
}

unsigned d2km_fact_unread_form(const d2km_fact *f)
{
    if (f == NULL || f->level != D2KM_LEVEL_ESTABLISHED || !f->invariant)
        return 0;
    unsigned m = 0;
    const d2km_arm *arms[2] = {&f->a, &f->b};
    for (int i = 0; i < 2; i++)
        if (arms[i]->has_action && (arms[i]->action.field & D2KM_FIELD_FORM))
            m |= arms[i]->action.field & D2KM_FORM_ALL;
    return m;
}

d2km_fact_reason d2km_fact_demote(d2km_fact *f, uint32_t counter, uint32_t version)
{
    if (f == NULL || counter == 0 || f->level != D2KM_LEVEL_ESTABLISHED)
        return D2KM_FR_BAD_INPUT;
    int known = 0;
    for (size_t i = 0; i < f->source_count; i++)
        known |= f->sources[i] == counter;
    if (!known && f->source_count >= D2KM_FACT_SOURCES_MAX)
        return D2KM_FR_TOO_MANY_SOURCES;
    f->level = D2KM_LEVEL_OBSERVED;
    add_source(f, counter);
    f->model_version = version;
    return D2KM_FR_OK;
}

int d2km_fact_contradicted(const d2km_fact *f, const d2km_arm_record *r)
{
    if (f == NULL || r == NULL || f->level != D2KM_LEVEL_ESTABLISHED ||
        !d2km_result_is_network(r->result))
        return 0;
    if (d2km_context_diff(&f->context, &r->context) != 0)
        return 0;
    if (action_equal(&f->a, &r->arm))
        return !d2km_result_equal(f->ra, r->result);
    if (action_equal(&f->b, &r->arm))
        return !d2km_result_equal(f->rb, r->result);
    return 0;
}

int d2km_fact_usable(const d2km_fact *f)
{
    return f != NULL && f->level == D2KM_LEVEL_ESTABLISHED;
}
