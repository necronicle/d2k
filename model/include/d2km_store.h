/* Каталог собственного знания (§5.4, §10, §12.3). Не содержит готовых ответов. */
#ifndef D2KM_STORE_H
#define D2KM_STORE_H
#include "d2km_box.h"
#include "d2km_program.h"
#include "d2km_owner.h"

/* §14: ограничиваем память каталога роутера, а не число опытов поиска.
 * 8 полных моделей и 64 программы занимают менее 3 МиБ; каждый факт имеет
 * существующий предел D2KM_BOX_FACTS_MAX (64: ограничение памяти модели).
 * При исчерпании — NO_RESOURCES, подтверждённые записи не вытесняются. */
#define D2KM_STORE_BOXES_MAX 8
#define D2KM_STORE_KNOWLEDGE_MAX 64
/* История хранит последние 8 замен/деградаций, не растёт с числом потоков.
 * Архив JSON why сохраняет обоснование независимо от ротации журнала.
 * Переполнение архива — NO_RESOURCES, не обрезание доказательства. */
#define D2KM_KNOWLEDGE_HISTORY_MAX 8
#define D2KM_KNOWLEDGE_WHY_MAX 8192
/* Scope application evidence inside a provenance archive: evidence inherited
 * from a donor is not verification of the new target/program. */
size_t d2km_application_proof(char *,size_t,const d2km_context *,uint64_t,const char *);

typedef struct {
    uint64_t time_ms;
    uint64_t previous_hash;
    uint32_t experiment;
    d2km_outcome outcome; /* APPLIED (замена) или DEGRADED */
} d2km_knowledge_history;

typedef struct {
    uint32_t id;
    d2km_program program;
    uint64_t hash;
    d2km_context context;
    d2km_binding binding; /* ключ — context.target + protocol/transport/family */
    uint32_t experiment, model_version, box;
    uint64_t last_success_ms;
    size_t history_count;
    d2km_knowledge_history history[D2KM_KNOWLEDGE_HISTORY_MAX];
    char why[D2KM_KNOWLEDGE_WHY_MAX]; /* полные JSON-записи, с id и links */
} d2km_knowledge;

typedef struct {
    size_t count;
    d2km_knowledge entries[D2KM_STORE_KNOWLEDGE_MAX];
} d2km_knowledge_set;
typedef struct {
    size_t count;
    d2km_box entries[D2KM_STORE_BOXES_MAX];
} d2km_box_set;
typedef struct {
    d2km_box_set boxes;
    d2km_knowledge_set knowledge;
    uint32_t next_experiment, next_fact;
} d2km_store;

typedef enum {
    D2KM_STORE_OK = 0,
    D2KM_STORE_IO,
    D2KM_STORE_INVALID,
    D2KM_STORE_VERSION,
    D2KM_STORE_NO_RESOURCES
} d2km_store_code;
typedef struct {
    size_t line; /* 0 — ошибка не в строке файла */
    char reason[256];
} d2km_store_error;

/* Last history event for the current content controls activation. A success
 * of this program on another target must never resurrect this binding. */
static inline int d2km_knowledge_active(const d2km_knowledge *k)
{
    if (!k || !k->last_success_ms) return 0;
    for (size_t i = k->history_count; i > 0; i--)
        if (k->history[i-1].previous_hash == k->hash)
            return k->history[i-1].outcome != D2KM_DEGRADED;
    return 1;
}
void d2km_store_init(d2km_store *);
/* При отказе загрузки *out не меняется. Ошибка содержит причину для §12. */
d2km_store_code d2km_store_load(const char *path, d2km_store *out, d2km_store_error *);
/* mkstemp в том же каталоге, 0600, fsync, rename. Любая ошибка удаляет tmp. */
d2km_store_code d2km_store_save(const char *path, const d2km_store *, d2km_store_error *);
#endif
