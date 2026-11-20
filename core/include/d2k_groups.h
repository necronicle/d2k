#ifndef D2K_GROUPS_H
#define D2K_GROUPS_H
#include <stddef.h>
#include <stdint.h>
#define D2K_GROUP_MAX 64
#define D2K_GROUP_OBSERVATION_MAX 256
typedef struct {
    uint8_t transport, family, shape;
    char probe_path[256], ech_origin[256];
} d2k_group_key;
enum {
    D2K_GROUP_BLOCKED_CONFIRMED=1,
    D2K_GROUP_DIRECT_CLEAR=2,
    D2K_GROUP_PLAN_FAILED=4,
    D2K_GROUP_INCONCLUSIVE=8
};
/* Additional provenance bit: clean evidence found after area admission.
 * It blocks this exact member, not already learned unrelated siblings. */
#define D2K_GROUP_ADMITTED_EXCEPTION 16u
typedef struct {
    char name[256], plan_id[40];
    d2k_group_key key;
    unsigned evidence;
    int64_t at;
} d2k_group_observation;
typedef struct {
    char suffix[256], plan_id[40];
    d2k_group_key key;
    unsigned evidence_count;
    int64_t at;
} d2k_domain_group;
typedef struct {
    d2k_domain_group groups[D2K_GROUP_MAX];
    d2k_group_observation observations[D2K_GROUP_OBSERVATION_MAX];
    size_t n_groups, n_observations;
    int frozen, disabled;
    /* Derived hot-cache overflow; rebuilt from observations, never persisted. */
    int groups_overflow;
    /* Wall-clock seconds of the newest evidence when areas were disabled:
       plain votes at or before it are dropped on re-enable. */
    int64_t disabled_at;
    /* File-backed workspace; canonical persistence remains catalog.json. */
    d2k_group_observation *disk_observations;
    size_t disk_capacity;
    int disk_fd;
    char *index_path;
    void *derived_index;
    size_t derived_capacity;
    int derived_fd, derived_ready;
    /* Catalog-loaded demand results obey the same plan pruning as hot groups. */
    int (*plan_available)(const void *ctx, const d2k_domain_group *g);
    const void *plan_available_ctx;
    /* The flash-backed workspace could not be created: family learning is
       degraded (nothing learned, no areas). The saved history is never moved
       to heap memory: a read-only mapping of the ORIGINAL catalog inode (kept
       alive across an atomic replace) holds it, and a save writes the span
       [preserved_off, preserved_off+preserved_len) back unchanged. A span
       without a mapping refuses the save rather than lose history. */
    int store_failed;
    const char *preserved_map;
    size_t preserved_map_len, preserved_off, preserved_len;
    uint64_t preserved_dev, preserved_ino; /* inode the map belongs to */
} d2k_group_state;
static inline d2k_group_observation *d2k_group_rows(const d2k_group_state *s) {
    return s->disk_observations ? s->disk_observations :
        (d2k_group_observation *)s->observations;
}
static inline size_t d2k_group_capacity(const d2k_group_state *s) {
    return s->disk_observations ? s->disk_capacity : D2K_GROUP_OBSERVATION_MAX;
}
/* Moves rows into a growable unlinked workspace on the catalog filesystem.
   0: file-backed (idempotent). -1: no workspace (ENOSPC, read-only
   directory, no descriptor, no map); store_failed is set and sticky, and
   family learning stays degraded for this catalog instance. */
int d2k_group_store_open(d2k_group_state *s, const char *catalog_path);
int d2k_group_store_reserve(d2k_group_state *s, size_t count);
void d2k_group_store_close(d2k_group_state *s);
int d2k_group_key_same(const d2k_group_key *a, const d2k_group_key *b);
int d2k_group_key_make(d2k_group_key *key, uint8_t transport, uint8_t family,
    uint8_t shape, const char *path, const char *origin);
int d2k_group_learn(d2k_group_state *s, const d2k_group_observation *o);
/* Validate saved observations and derive active areas, never trust a saved
   suffix alone. Preserves failure exceptions and frozen admission state. */
int d2k_group_restore(d2k_group_state *s);
/* A member that neither the family plan nor its own search reached is
   unreachable, not evidence against the plan: drop its failure records for
   this transport and family. Returns how many were dropped. */
int d2k_group_forget(d2k_group_state *s, const char *name,
                     uint8_t transport, uint8_t family);
/* Failure records older than max_age seconds (wall clock) are dropped:
   a node nobody met again for that long says nothing about the plan.
   Confirmations do not age. Returns how many were dropped. */
int d2k_group_expire(d2k_group_state *s, int64_t now, int64_t max_age);
/* Returns *out on success, NULL on no match. The result is caller-owned and
   remains valid until the caller reuses its storage; matching never mutates s. */
const d2k_domain_group *d2k_group_match(const d2k_group_state *s,
    const char *name, const d2k_group_key *key, d2k_domain_group *out);
/* Sparse derived view. Slots without an elected group return zero. */
size_t d2k_group_slots(const d2k_group_state *s);
int d2k_group_at(const d2k_group_state *s,size_t index,d2k_domain_group *out);
#endif
