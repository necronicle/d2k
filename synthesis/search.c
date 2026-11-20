#include "search.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static d2k_syn_result path(const size_t *parent, const size_t *via,
                           size_t initial, size_t state, size_t extra,
                           d2k_syn_status status)
{
    d2k_syn_result r = {.status = D2K_SYN_ERROR};
    size_t n = extra != SIZE_MAX;
    for (size_t s = state; s != initial; s = parent[s]) ++n;
    if (n > SIZE_MAX / sizeof(size_t)) return r;
    r.operations = n ? malloc(n * sizeof(size_t)) : NULL;
    if (n && !r.operations) return r;
    r.length = n;
    r.unresolved_state = state;
    size_t at = n;
    if (extra != SIZE_MAX) r.operations[--at] = extra;
    for (size_t s = state; s != initial; s = parent[s])
        r.operations[--at] = via[s];
    r.status = status;
    return r;
}

d2k_syn_result d2k_syn_search(const d2k_syn_model *m)
{
    d2k_syn_result r = {.status = D2K_SYN_ERROR};
    if (!m || !m->step || !m->goal || !m->states ||
        m->initial >= m->states || m->states > SIZE_MAX / sizeof(size_t)) return r;
    int accepted = m->goal(m->ctx, m->initial);
    if (accepted != 0 && accepted != 1) return r;
    if (accepted == 1) {
        r.status = D2K_SYN_DIRECT;
        return r;
    }
    size_t *parent = malloc(m->states * sizeof(size_t));
    size_t *via = malloc(m->states * sizeof(size_t));
    size_t *queue = malloc(m->states * sizeof(size_t));
    if (!parent || !via || !queue) goto done;
    for (size_t i = 0; i < m->states; ++i) parent[i] = SIZE_MAX;
    parent[m->initial] = m->initial;
    size_t head = 0, tail = 0;
    size_t frontier = SIZE_MAX, question = SIZE_MAX;
    queue[tail++] = m->initial;
    while (head < tail) {
        size_t state = queue[head++];
        for (size_t op = 0; op < m->operations; ++op) {
            d2k_syn_edge edge = m->step(m->ctx, state, op);
            if (edge.kind == D2K_SYN_UNKNOWN) {
                if (frontier == SIZE_MAX) { frontier = state; question = op; }
                continue;
            }
            if (edge.kind == D2K_SYN_INVALID) continue;
            if (edge.kind != D2K_SYN_EDGE || edge.next >= m->states) goto done;
            if (parent[edge.next] != SIZE_MAX) continue;
            parent[edge.next] = state;
            via[edge.next] = op;
            accepted = m->goal(m->ctx, edge.next);
            if (accepted != 0 && accepted != 1) goto done;
            if (accepted == 1) {
                r = path(parent, via, m->initial, edge.next, SIZE_MAX,
                         D2K_SYN_CANDIDATE);
                goto done;
            }
            queue[tail++] = edge.next;
        }
    }
    if (frontier != SIZE_MAX)
        r = path(parent, via, m->initial, frontier, question, D2K_SYN_EXPERIMENT);
    else r.status = D2K_SYN_CLOSED;
done:
    free(parent); free(via); free(queue);
    return r;
}

void d2k_syn_result_free(d2k_syn_result *r)
{
    if (!r) return;
    free(r->operations);
    memset(r, 0, sizeof(*r));
}
