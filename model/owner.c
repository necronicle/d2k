#include "d2km_owner.h"

#include <string.h>

void d2km_ledger_init(d2km_ledger *l, d2km_resource *slots, size_t capacity)
{
    l->slots = slots;
    l->capacity = slots != NULL ? capacity : 0;
    if (l->capacity)
        memset(slots, 0, capacity * sizeof(*slots));
}

static int kind_valid(d2km_resource_kind k)
{
    return k > 0 && k < D2KM_RES_KIND_END;
}

static d2km_resource *find(const d2km_ledger *l, d2km_resource_kind k, uint64_t key)
{
    for (size_t i = 0; i < l->capacity; i++)
        if (l->slots[i].owner != 0 && l->slots[i].kind == k &&
            l->slots[i].key == key)
            return &l->slots[i];
    return NULL;
}

d2km_own_code d2km_ledger_acquire(d2km_ledger *l, uint32_t owner,
                                  d2km_resource_kind k, d2km_binding b,
                                  uint64_t key)
{
    if (l == NULL || owner == 0 || !kind_valid(k) ||
        (b != D2KM_BIND_NONE && b != D2KM_BIND_NAME && b != D2KM_BIND_ADDRESS))
        return D2KM_OWN_BAD_INPUT;
    /* Привязка есть только у планов и кандидатов. */
    int bound = k == D2KM_RES_TRIAL_PLAN || k == D2KM_RES_CANDIDATE;
    if (bound != (b != D2KM_BIND_NONE))
        return D2KM_OWN_BAD_INPUT;
    d2km_resource *r = find(l, k, key);
    if (r != NULL)
        return r->owner == owner ? D2KM_OWN_ALREADY : D2KM_OWN_FOREIGN;
    for (size_t i = 0; i < l->capacity; i++) {
        if (l->slots[i].owner == 0) {
            l->slots[i].owner = owner;
            l->slots[i].kind = k;
            l->slots[i].binding = b;
            l->slots[i].key = key;
            return D2KM_OWN_OK;
        }
    }
    return D2KM_OWN_FULL;
}

d2km_own_code d2km_ledger_release(d2km_ledger *l, uint32_t owner,
                                  d2km_resource_kind k, uint64_t key)
{
    if (l == NULL || owner == 0 || !kind_valid(k))
        return D2KM_OWN_BAD_INPUT;
    d2km_resource *r = find(l, k, key);
    if (r == NULL)
        return D2KM_OWN_ABSENT;
    if (r->owner != owner)
        return D2KM_OWN_FOREIGN;
    memset(r, 0, sizeof(*r));
    return D2KM_OWN_OK;
}

uint32_t d2km_ledger_owner(const d2km_ledger *l, d2km_resource_kind k, uint64_t key)
{
    if (l == NULL)
        return 0;
    const d2km_resource *r = find(l, k, key);
    return r != NULL ? r->owner : 0;
}

size_t d2km_ledger_finish(d2km_ledger *l, uint32_t owner)
{
    size_t n = 0;
    if (l == NULL || owner == 0)
        return 0;
    for (size_t i = 0; i < l->capacity; i++)
        if (l->slots[i].owner == owner) {
            memset(&l->slots[i], 0, sizeof(l->slots[i]));
            n++;
        }
    return n;
}

size_t d2km_ledger_cleanup(d2km_ledger *l, uint32_t owner, d2km_binding b)
{
    size_t n = 0;
    if (l == NULL || owner == 0 || b == D2KM_BIND_NONE)
        return 0;
    for (size_t i = 0; i < l->capacity; i++) {
        d2km_resource *r = &l->slots[i];
        if (r->owner == owner && r->binding == b &&
            (r->kind == D2KM_RES_TRIAL_PLAN || r->kind == D2KM_RES_CANDIDATE)) {
            memset(r, 0, sizeof(*r));
            n++;
        }
    }
    return n;
}

size_t d2km_ledger_count(const d2km_ledger *l, uint32_t owner)
{
    size_t n = 0;
    if (l == NULL)
        return 0;
    for (size_t i = 0; i < l->capacity; i++)
        n += owner == 0 ? l->slots[i].owner != 0 : l->slots[i].owner == owner;
    return n;
}

uint64_t d2km_memory_reserve(const uint64_t *samples, size_t n,
                             uint32_t period_s, uint64_t declared)
{
    if (samples == NULL || n < 2 || period_s == 0 || period_s > 60)
        return declared;
    /* Наблюдение короче часа — своего всплеска ещё не видно. */
    if ((uint64_t)(n - 1) * period_s < 3600)
        return declared;
    size_t day = 86400 / period_s + 1;
    size_t from = n > day ? n - day : 0;
    size_t window = 60 / period_s;   /* образцов в одной минуте */
    uint64_t worst = 0;
    for (size_t i = from; i < n; i++) {
        for (size_t j = i + 1; j < n && j <= i + window; j++) {
            if (samples[i] > samples[j] && samples[i] - samples[j] > worst)
                worst = samples[i] - samples[j];
        }
    }
    return worst;
}

int d2km_memory_admit(uint64_t free_now, uint64_t reserve, uint64_t declared)
{
    if (declared == 0)
        return 0;   /* опыт без объявленной памяти не допускается */
    if (free_now < reserve)
        return 0;
    return free_now - reserve >= declared;
}
