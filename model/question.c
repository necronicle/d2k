#include "d2km_question.h"

static int is_live(d2km_hypothesis h, const d2km_hypothesis *live, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (live[i] == h)
            return 1;
    return 0;
}

size_t d2km_question_weight(const d2km_question *q, const d2km_hypothesis *live,
                            size_t nlive, d2km_matters_fn matters, void *ctx)
{
    if (q == NULL || live == NULL)
        return 0;
    size_t n = q->prediction_count < D2KM_HYPOTHESES_MAX ? q->prediction_count
                                                         : D2KM_HYPOTHESES_MAX;
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        const d2km_prediction *a = &q->predictions[i];
        if (!is_live(a->hypothesis, live, nlive))
            continue;
        for (size_t j = i + 1; j < n; j++) {
            const d2km_prediction *b = &q->predictions[j];
            if (!is_live(b->hypothesis, live, nlive) ||
                a->hypothesis == b->hypothesis ||
                d2km_result_equal(a->predicted, b->predicted))
                continue;
            if (matters == NULL || matters(ctx, a->hypothesis, b->hypothesis))
                w++;
        }
    }
    return w;
}

static int action_same(const d2km_action *a, const d2km_action *b)
{
    return a->op == b->op && a->field == b->field && a->value == b->value;
}

long d2km_question_select(const d2km_question *qs, size_t n,
                          const d2km_hypothesis *live, size_t nlive,
                          const d2km_action *answered, size_t nanswered,
                          d2km_matters_fn matters, void *ctx)
{
    long best = -1;
    size_t best_w = 0;
    for (size_t i = 0; i < n; i++) {
        const d2km_question *q = &qs[i];
        if (q->action.op <= 0 || q->action.op >= D2KM_OPERATOR_END)
            continue;
        int done = 0;
        for (size_t k = 0; k < nanswered && !done; k++)
            done = action_same(&q->action, &answered[k]);
        if (done)
            continue;
        size_t w = d2km_question_weight(q, live, nlive, matters, ctx);
        if (w == 0)
            continue;
        if (best < 0 || w > best_w ||
            (w == best_w && (q->packets < qs[best].packets ||
                             (q->packets == qs[best].packets &&
                              q->action.op < qs[best].action.op)))) {
            best = (long)i;
            best_w = w;
        }
    }
    return best;
}

int d2km_search_init(d2km_search *s, int64_t min, int64_t max, int64_t resolution)
{
    if (s == NULL || min >= max || resolution <= 0)
        return -1;
    s->min = min;
    s->max = max;
    s->resolution = resolution;
    s->phase = D2KM_SEARCH_PROBE_MIN;
    s->base.kind = 0;
    s->base.value = 0;
    s->at_hi = s->base;
    s->lo = min;
    s->hi = min;
    s->pending = min;
    return 0;
}

/* Следующее значение удвоения от min: min + шаг, шаг удваивается. */
static int64_t doubled(const d2km_search *s, int64_t from)
{
    int64_t step = from - s->min;
    if (step < s->resolution)
        step = s->resolution;
    else if (step > (INT64_MAX - from) / 2)
        return s->max;
    else
        step *= 2;
    int64_t v = s->min + step;
    if (v > s->max || v <= from)
        v = s->max;
    return v;
}

static int64_t midpoint(const d2km_search *s)
{
    int64_t steps = (s->hi - s->lo) / s->resolution;
    return s->lo + (steps / 2) * s->resolution;
}

int d2km_search_next(d2km_search *s, int64_t *value)
{
    if (s == NULL || value == NULL)
        return 0;
    switch (s->phase) {
    case D2KM_SEARCH_PROBE_MIN:
    case D2KM_SEARCH_DOUBLING:
    case D2KM_SEARCH_BISECT:
        *value = s->pending;
        return 1;
    default:
        return 0;
    }
}

int d2km_search_feed(d2km_search *s, int64_t v, d2km_result r)
{
    if (s == NULL || v != s->pending || !d2km_result_is_network(r))
        return -1;
    switch (s->phase) {
    case D2KM_SEARCH_PROBE_MIN:
        s->base = r;
        s->lo = s->min;
        s->phase = D2KM_SEARCH_DOUBLING;
        s->pending = doubled(s, s->min);
        return 0;
    case D2KM_SEARCH_DOUBLING:
        if (d2km_result_equal(r, s->base)) {
            s->lo = v;
            if (v >= s->max) {
                s->phase = D2KM_SEARCH_EXHAUSTED;
                return 0;
            }
            s->pending = doubled(s, v);
            return 0;
        }
        s->hi = v;
        s->at_hi = r;
        break;
    case D2KM_SEARCH_BISECT:
        if (d2km_result_equal(r, s->base)) {
            s->lo = v;
        } else {
            s->hi = v;
            s->at_hi = r;
        }
        break;
    default:
        return -1;
    }
    if (s->hi - s->lo <= s->resolution) {
        s->phase = D2KM_SEARCH_BOUNDARY;
        return 0;
    }
    s->phase = D2KM_SEARCH_BISECT;
    s->pending = midpoint(s);
    return 0;
}

size_t d2km_split_positions(const uint32_t *bounds, size_t n, uint32_t length,
                            uint32_t *out, size_t cap)
{
    size_t m = 0;
    /* Вставка с упорядочением и без повторов; длина массива невелика. */
    uint32_t tmp[256];
    for (size_t i = 0; i < n; i++) {
        uint32_t p = bounds[i];
        if (p == 0 || p >= length)
            continue;
        size_t k = 0;
        while (k < m && tmp[k] < p)
            k++;
        if (k < m && tmp[k] == p)
            continue;
        if (m == sizeof(tmp) / sizeof(tmp[0]))
            break;
        for (size_t j = m; j > k; j--)
            tmp[j] = tmp[j - 1];
        tmp[k] = p;
        m++;
    }
    for (size_t i = 0; i < m && out != NULL && i < cap; i++)
        out[i] = tmp[i];
    return m;
}
