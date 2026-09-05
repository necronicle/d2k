/* plans.c — таблица планов по целям. */
#include <stdlib.h>
#include <string.h>

#include "d2k_plans.h"

enum { KEY_FREE = 0, KEY_NAME = 1, KEY_ADDR = 2 };

typedef struct {
    uint8_t  kind;
    uint8_t  name_len;
    uint8_t  name[D2K_TARGET_NAME_MAX];
    uint32_t addr_be;
    d2k_plan *plan;
} entry;

struct d2k_plantab {
    entry *v;
    size_t cap;
    size_t used;
};

d2k_plantab *d2k_plantab_new(size_t cap) {
    if (cap == 0) {
        return NULL;
    }
    d2k_plantab *t = calloc(1, sizeof *t);
    if (!t) {
        return NULL;
    }
    t->v = calloc(cap, sizeof *t->v);
    if (!t->v) {
        free(t);
        return NULL;
    }
    t->cap = cap;
    return t;
}

void d2k_plantab_free(d2k_plantab *t) {
    if (!t) {
        return;
    }
    for (size_t i = 0; i < t->cap; i++) {
        d2k_plan_free(t->v[i].plan);
    }
    free(t->v);
    free(t);
}

/* Имена сравниваются без учёта регистра: в SNI регистр незначим, а клиенты
   пишут по-разному. Своя функция, а не strncasecmp — тот зависит от локали, и
   в турецкой локали «I» ведёт себя не так, как ждёт остальной мир. */
static int name_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    if (alen != blen) {
        return 0;
    }
    for (size_t i = 0; i < alen; i++) {
        uint8_t x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') { x = (uint8_t)(x - 'A' + 'a'); }
        if (y >= 'A' && y <= 'Z') { y = (uint8_t)(y - 'A' + 'a'); }
        if (x != y) {
            return 0;
        }
    }
    return 1;
}

static entry *find_name(d2k_plantab *t, const uint8_t *name, size_t len) {
    for (size_t i = 0; i < t->cap; i++) {
        if (t->v[i].kind == KEY_NAME &&
            name_eq(t->v[i].name, t->v[i].name_len, name, len)) {
            return &t->v[i];
        }
    }
    return NULL;
}

static entry *find_addr(d2k_plantab *t, uint32_t addr_be) {
    for (size_t i = 0; i < t->cap; i++) {
        if (t->v[i].kind == KEY_ADDR && t->v[i].addr_be == addr_be) {
            return &t->v[i];
        }
    }
    return NULL;
}

static entry *take_free(d2k_plantab *t) {
    for (size_t i = 0; i < t->cap; i++) {
        if (t->v[i].kind == KEY_FREE) {
            return &t->v[i];
        }
    }
    return NULL;
}

int d2k_plantab_set_name(d2k_plantab *t, const uint8_t *name, size_t len,
                         d2k_plan *p) {
    if (!t || !name || len == 0 || len > D2K_TARGET_NAME_MAX) {
        d2k_plan_free(p);
        return -2;
    }
    entry *e = find_name(t, name, len);
    if (!e) {
        e = take_free(t);
        if (!e) {
            d2k_plan_free(p);
            return -1;
        }
        t->used++;
        e->kind = KEY_NAME;
        e->name_len = (uint8_t)len;
        memcpy(e->name, name, len);
    }
    /* Прежний план освобождается здесь, а не у вызывающего: иначе замена
       плана цели молча текла бы. */
    d2k_plan_free(e->plan);
    e->plan = p;
    return 0;
}

int d2k_plantab_set_addr(d2k_plantab *t, uint32_t addr_be, d2k_plan *p) {
    if (!t) {
        d2k_plan_free(p);
        return -2;
    }
    entry *e = find_addr(t, addr_be);
    if (!e) {
        e = take_free(t);
        if (!e) {
            d2k_plan_free(p);
            return -1;
        }
        t->used++;
        e->kind = KEY_ADDR;
        e->addr_be = addr_be;
    }
    d2k_plan_free(e->plan);
    e->plan = p;
    return 0;
}

static int drop(d2k_plantab *t, entry *e) {
    if (!e) {
        return 0;
    }
    d2k_plan_free(e->plan);
    memset(e, 0, sizeof *e);
    t->used--;
    return 1;
}

int d2k_plantab_del_name(d2k_plantab *t, const uint8_t *name, size_t len) {
    if (!t || !name || len == 0) {
        return 0;
    }
    return drop(t, find_name(t, name, len));
}

int d2k_plantab_del_addr(d2k_plantab *t, uint32_t addr_be) {
    return t ? drop(t, find_addr(t, addr_be)) : 0;
}

const d2k_plan *d2k_plantab_find(const d2k_plantab *t, const uint8_t *name,
                                 size_t len, uint32_t addr_be) {
    if (!t) {
        return NULL;
    }
    d2k_plantab *m = (d2k_plantab *)t;
    if (name && len) {
        entry *e = find_name(m, name, len);
        if (e) {
            return e->plan;
        }
    }
    /* Только теперь по адресу: обратный порядок дал бы плану соседа по CDN
       перебить план, подтверждённый для этого имени. */
    entry *e = find_addr(m, addr_be);
    return e ? e->plan : NULL;
}

size_t d2k_plantab_count(const d2k_plantab *t) {
    return t ? t->used : 0;
}

size_t d2k_plantab_capacity(const d2k_plantab *t) {
    return t ? t->cap : 0;
}
