#ifndef D2K_RUN_CACHE_H
#define D2K_RUN_CACHE_H
#include <stdlib.h>
#include <string.h>
/* Task-owned, exact-byte checkpoint. Never shared between tasks or persisted.
 * Allocation failure only disables reuse; it cannot produce an observation. */
typedef struct d2k_run_entry {
    struct d2k_run_entry *next;
    size_t key_len, extra_len;
    int pass, fail;
    unsigned char bytes[];
} d2k_run_entry;
typedef struct {
    void *context;
    size_t context_len;
    d2k_run_entry *entries;
} d2k_run_cache;
static inline void d2k_run_cache_clear(d2k_run_cache *c) {
    if (!c) return;
    while (c->entries) {
        d2k_run_entry *e = c->entries;
        c->entries = e->next;
        free(e);
    }
    free(c->context);
    memset(c, 0, sizeof *c);
}
static inline int d2k_run_cache_bind(d2k_run_cache *c, const void *key, size_t len) {
    if (!c) return 0;
    if (c->context && c->context_len == len && !memcmp(c->context, key, len)) return 1;
    d2k_run_cache_clear(c);
    c->context = malloc(len);
    if (!c->context) return 0;
    memcpy(c->context, key, len);
    c->context_len = len;
    return 1;
}
static inline d2k_run_entry *d2k_run_cache_get(d2k_run_cache *c,
        const void *key, size_t len, const void *extra, size_t extra_len) {
    if (!c || !c->context || (extra_len && !extra)) return NULL;
    for (d2k_run_entry *e = c->entries; e; e = e->next) {
        if (e->key_len == len && e->extra_len == extra_len &&
            !memcmp(e->bytes, key, len) &&
            (!extra_len || !memcmp(e->bytes + len, extra, extra_len))) return e;
    }
    return NULL;
}
static inline void d2k_run_cache_put(d2k_run_cache *c, const void *key, size_t len,
        const void *extra, size_t extra_len, int pass, int fail) {
    if (!c || !c->context || (extra_len && !extra)) return;
    d2k_run_entry *e = d2k_run_cache_get(c, key, len, extra, extra_len);
    if (!e) {
        if (len > (size_t)-1 - sizeof *e || extra_len > (size_t)-1 - sizeof *e - len) return;
        e = malloc(sizeof *e + len + extra_len);
        if (!e) return;
        e->key_len = len; e->extra_len = extra_len;
        memcpy(e->bytes, key, len);
        if (extra_len) memcpy(e->bytes + len, extra, extra_len);
        e->next = c->entries; c->entries = e;
    }
    e->pass = pass; e->fail = fail;
}
#endif
