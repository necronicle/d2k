#include "d2km_box.h"

#include <string.h>

int d2km_target_equal(const d2km_target *a, const d2km_target *b)
{
    if (a->has_name != b->has_name)
        return 0;
    if (a->has_name)
        return strcmp(a->name, b->name) == 0;
    size_t n = a->family == D2KM_IPV4 ? 4 : 16;
    return a->family == b->family && a->port == b->port &&
           memcmp(a->addr, b->addr, n) == 0;
}

static int arm_equal(const d2km_arm *x, const d2km_arm *y)
{
    if (x->has_action != y->has_action)
        return 0;
    if (!x->has_action)
        return 1;
    return x->action.op == y->action.op && x->action.field == y->action.field &&
           x->action.value == y->action.value;
}

/* Контексты совместимы без учёта цели (unread — нечитаемые поля формы). */
static int compatible_any_target(const d2km_context *f, const d2km_context *o,
                                 unsigned unread)
{
    d2km_context t = *o;
    t.target = f->target;
    return d2km_context_compatible(f, &t, unread);
}

/* Противоречит ли пара (воздействие, исход) установленному факту f в
 * совместимом контексте c без учёта цели. */
static int refutes(const d2km_fact *f, const d2km_context *c, const d2km_arm *arm,
                   d2km_result r, unsigned unread)
{
    if (f->level != D2KM_LEVEL_ESTABLISHED || !d2km_result_is_network(r))
        return 0;
    if (!compatible_any_target(&f->context, c, unread))
        return 0;
    if (arm_equal(&f->a, arm))
        return !d2km_result_equal(f->ra, r);
    if (arm_equal(&f->b, arm))
        return !d2km_result_equal(f->rb, r);
    return 0;
}

void d2km_box_init(d2km_box *b, uint32_t id)
{
    memset(b, 0, sizeof(*b));
    b->id = id;
}

static int fact_same(const d2km_fact *x, const d2km_fact *y)
{
    return x->kind == y->kind && x->level == y->level &&
           x->numeric == y->numeric && x->invariant == y->invariant &&
           d2km_context_diff(&x->context, &y->context) == 0 &&
           arm_equal(&x->a, &y->a) && arm_equal(&x->b, &y->b) &&
           d2km_result_equal(x->ra, y->ra) && d2km_result_equal(x->rb, y->rb);
}

d2km_box_code d2km_box_add_fact(d2km_box *b, const d2km_fact *f, size_t *conflict)
{
    if (b == NULL || f == NULL || f->id == 0 || f->source_count == 0)
        return D2KM_BOX_BAD_INPUT;
    for (size_t i = 0; i < b->fact_count; i++)
        if (fact_same(&b->facts[i], f))
            return D2KM_BOX_DUPLICATE;
    if (b->fact_count >= D2KM_BOX_FACTS_MAX)
        return D2KM_BOX_FULL;
    uint32_t next = b->version + 1;
    if (f->level == D2KM_LEVEL_ESTABLISHED) {
        /* Сначала ищем противоречие с другой целью: тогда ничего не меняем. */
        for (size_t i = 0; i < b->fact_count; i++) {
            const d2km_fact *g = &b->facts[i];
            if (d2km_target_equal(&g->context.target, &f->context.target))
                continue;
            if (refutes(g, &f->context, &f->a, f->ra, 0) ||
                refutes(g, &f->context, &f->b, f->rb, 0)) {
                if (conflict != NULL)
                    *conflict = i;
                return D2KM_BOX_SPLIT_NEEDED;
            }
        }
        /* Та же цель: новый установленный факт — контрпример старому. */
        for (size_t i = 0; i < b->fact_count; i++) {
            d2km_fact *g = &b->facts[i];
            if (!d2km_target_equal(&g->context.target, &f->context.target))
                continue;
            if (refutes(g, &f->context, &f->a, f->ra, 0) ||
                refutes(g, &f->context, &f->b, f->rb, 0))
                d2km_fact_demote(g, f->sources[0], next);
        }
    }
    b->facts[b->fact_count] = *f;
    b->facts[b->fact_count].model_version = next;
    b->fact_count++;
    b->version = next;
    return D2KM_BOX_OK;
}

size_t d2km_box_observe(d2km_box *b, const d2km_arm_record *r)
{
    if (b == NULL || r == NULL || r->experiment == 0)
        return 0;
    size_t n = 0;
    uint32_t next = b->version + 1;
    for (size_t i = 0; i < b->fact_count; i++) {
        d2km_fact *f = &b->facts[i];
        if (d2km_fact_contradicted(f, r) &&
            d2km_fact_demote(f, r->experiment, next) == D2KM_FR_OK)
            n++;
    }
    if (n)
        b->version = next;
    return n;
}

void d2km_box_open(d2km_box *b, d2km_signal s)
{
    d2km_hypothesis hs[D2KM_HYPOTHESES_MAX];
    size_t n = d2km_hypotheses_for(s, hs, D2KM_HYPOTHESES_MAX);
    for (size_t i = 0; i < n && i < D2KM_HYPOTHESES_MAX; i++)
        if (b->hypotheses[hs[i]] == D2KM_HYP_UNKNOWN)
            b->hypotheses[hs[i]] = D2KM_HYP_LIVE;
}

void d2km_box_judge(d2km_box *b, const d2km_experiment *e, unsigned confirmed,
                    unsigned refuted)
{
    if (b == NULL || e == NULL)
        return;
    size_t ones = 0;
    for (size_t i = 0; i < e->prediction_count && i < D2KM_HYPOTHESES_MAX; i++)
        ones += (confirmed >> i) & 1u;
    for (size_t i = 0; i < e->prediction_count && i < D2KM_HYPOTHESES_MAX; i++) {
        d2km_hypothesis h = e->predictions[i].hypothesis;
        if (h <= 0 || h >= D2KM_HYPOTHESIS_END)
            continue;
        if (refuted & (1u << i))
            b->hypotheses[h] = D2KM_HYP_REFUTED;
        else if ((confirmed & (1u << i)) && ones == 1)
            b->hypotheses[h] = D2KM_HYP_CONFIRMED;
    }
}

size_t d2km_box_live(const d2km_box *b, d2km_hypothesis *out, size_t cap)
{
    size_t n = 0;
    for (int h = 1; h < D2KM_HYPOTHESIS_END; h++)
        if (b->hypotheses[h] == D2KM_HYP_LIVE) {
            if (out != NULL && n < cap)
                out[n] = (d2km_hypothesis)h;
            n++;
        }
    return n;
}

d2km_box_code d2km_box_add_counter(d2km_box *b, const d2km_counterexample *c)
{
    if (b == NULL || c == NULL || c->candidate == 0 || c->experiment == 0)
        return D2KM_BOX_BAD_INPUT;
    if (d2km_context_valid(&c->context) == 0
        ? d2km_box_tried_context(b, c->candidate, &c->context)
        : d2km_box_tried(b, c->candidate, &c->target))
        return D2KM_BOX_DUPLICATE;
    if (b->counter_count >= D2KM_BOX_COUNTER_MAX)
        return D2KM_BOX_FULL;
    b->counters[b->counter_count++] = *c;
    b->version++;
    return D2KM_BOX_OK;
}

int d2km_box_tried(const d2km_box *b, uint64_t candidate, const d2km_target *t)
{
    for (size_t i = 0; i < b->counter_count; i++)
        if (b->counters[i].candidate == candidate &&
            d2km_target_equal(&b->counters[i].target, t))
            return 1;
    return 0;
}

int d2km_box_tried_context(const d2km_box *b, uint64_t hash, const d2km_context *context)
{
    if (!b || !context) return 0;
    unsigned unread = d2km_box_unread(b);
    for (size_t i = 0; i < b->counter_count; i++) {
        const d2km_counterexample *ce = &b->counters[i];
        if (ce->candidate == hash && d2km_context_valid(&ce->context) == 0 &&
            d2km_context_compatible(&ce->context, context, unread)) return 1;
    }
    return 0;
}

unsigned d2km_box_unread(const d2km_box *b)
{
    unsigned m = 0;
    for (size_t i = 0; i < b->fact_count; i++)
        m |= d2km_fact_unread_form(&b->facts[i]);
    return m;
}

int d2km_box_candidate(const d2km_box *b, const d2km_arm_record *obs, size_t n)
{
    if (b == NULL || (obs == NULL && n))
        return 0;
    unsigned unread = d2km_box_unread(b);
    for (size_t i = 0; i < b->fact_count; i++)
        for (size_t k = 0; k < n; k++)
            if (refutes(&b->facts[i], &obs[k].context, &obs[k].arm,
                        obs[k].result, unread))
                return 0;
    return 1;
}

int d2km_box_has_target(const d2km_box *b, const d2km_target *t)
{
    for (size_t i = 0; i < b->target_count; i++)
        if (d2km_target_equal(&b->targets[i], t))
            return 1;
    return 0;
}

d2km_box_code d2km_box_admit(d2km_box *b, const d2km_target *t,
                             const d2km_arm_record *obs, size_t n)
{
    if (b == NULL || t == NULL || !d2km_box_candidate(b, obs, n))
        return D2KM_BOX_BAD_INPUT;
    if (d2km_box_has_target(b, t))
        return D2KM_BOX_DUPLICATE;
    /* Повторён опыт целиком: на цели есть оба плеча установленного факта
     * «Реакция» с теми же исходами. Одно плечо (например, успех с другим
     * именем) реакцию коробки на этой цели не показывает. */
    unsigned unread = d2km_box_unread(b);
    int repeated = 0;
    for (size_t i = 0; i < b->fact_count && !repeated; i++) {
        const d2km_fact *f = &b->facts[i];
        if (f->level != D2KM_LEVEL_ESTABLISHED || f->kind != D2KM_F_REACTION)
            continue;
        int seen_a = 0, seen_b = 0;
        for (size_t k = 0; k < n; k++) {
            const d2km_arm_record *o = &obs[k];
            if (!d2km_target_equal(&o->context.target, t) ||
                !compatible_any_target(&f->context, &o->context, unread))
                continue;
            seen_a |= arm_equal(&f->a, &o->arm) && d2km_result_equal(f->ra, o->result);
            seen_b |= arm_equal(&f->b, &o->arm) && d2km_result_equal(f->rb, o->result);
        }
        repeated = seen_a && seen_b;
    }
    if (!repeated)
        return D2KM_BOX_BAD_INPUT;
    if (b->target_count >= D2KM_BOX_TARGETS_MAX)
        return D2KM_BOX_FULL;
    b->targets[b->target_count++] = *t;
    b->version++;
    return D2KM_BOX_OK;
}

d2km_box_code d2km_box_split(d2km_box *b, const d2km_target *t, d2km_box *out,
                             uint32_t out_id)
{
    if (b == NULL || t == NULL || out == NULL || out == b || out_id == 0 ||
        out_id == b->id)
        return D2KM_BOX_BAD_INPUT;
    d2km_box_init(out, out_id);
    memcpy(out->hypotheses, b->hypotheses, sizeof(out->hypotheses));
    size_t keep = 0;
    for (size_t i = 0; i < b->fact_count; i++) {
        if (d2km_target_equal(&b->facts[i].context.target, t))
            out->facts[out->fact_count++] = b->facts[i];
        else
            b->facts[keep++] = b->facts[i];
    }
    b->fact_count = keep;
    keep = 0;
    for (size_t i = 0; i < b->counter_count; i++) {
        if (d2km_target_equal(&b->counters[i].target, t))
            out->counters[out->counter_count++] = b->counters[i];
        else
            b->counters[keep++] = b->counters[i];
    }
    b->counter_count = keep;
    keep = 0;
    for (size_t i = 0; i < b->target_count; i++) {
        if (d2km_target_equal(&b->targets[i], t))
            out->targets[out->target_count++] = b->targets[i];
        else
            b->targets[keep++] = b->targets[i];
    }
    b->target_count = keep;
    b->version++;
    out->version = 1;
    return D2KM_BOX_OK;
}
