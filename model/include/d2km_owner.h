/* Владение ресурсами опыта и допуск по памяти (D2K_SPEC.md §2.3, §6.7,
 * §10.5, §14).
 *
 * Опыт владеет своими потоками, портами, пробными планами и кандидатами.
 * Чужой ресурс не освобождается. Знание в учёт не входит и очисткой опыта
 * не затрагивается. */
#ifndef D2KM_OWNER_H
#define D2KM_OWNER_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    D2KM_RES_FLOW = 1,
    D2KM_RES_PORT,
    D2KM_RES_TRIAL_PLAN,
    D2KM_RES_CANDIDATE,
    D2KM_RES_KIND_END
} d2km_resource_kind;

/* Вид привязки (§10.2). Для потоков и портов — D2KM_BIND_NONE. */
typedef enum {
    D2KM_BIND_NONE = 0,
    D2KM_BIND_NAME,
    D2KM_BIND_ADDRESS
} d2km_binding;

typedef struct {
    uint32_t owner;          /* опыт-владелец; 0 — слот свободен */
    d2km_resource_kind kind;
    d2km_binding binding;
    uint64_t key;            /* пятёрка, порт, хэш плана — в виде ключа */
} d2km_resource;

typedef struct {
    d2km_resource *slots;
    size_t capacity;
} d2km_ledger;

typedef enum {
    D2KM_OWN_OK = 0,
    D2KM_OWN_ALREADY,     /* ресурс уже принадлежит этому опыту */
    D2KM_OWN_FOREIGN,     /* ресурс принадлежит другому опыту */
    D2KM_OWN_FULL,        /* нет свободного слота: NO_RESOURCES, не «обхода нет» */
    D2KM_OWN_ABSENT,      /* ресурса нет */
    D2KM_OWN_BAD_INPUT
} d2km_own_code;

void d2km_ledger_init(d2km_ledger *, d2km_resource *slots, size_t capacity);
d2km_own_code d2km_ledger_acquire(d2km_ledger *, uint32_t owner,
                                  d2km_resource_kind, d2km_binding, uint64_t key);
/* Освобождает только свой ресурс. */
d2km_own_code d2km_ledger_release(d2km_ledger *, uint32_t owner,
                                  d2km_resource_kind, uint64_t key);
/* Владелец ресурса или 0. */
uint32_t d2km_ledger_owner(const d2km_ledger *, d2km_resource_kind, uint64_t key);
/* Завершение опыта (§6.7): освобождает все ресурсы этого опыта. Возвращает
 * число освобождённых. */
size_t d2km_ledger_finish(d2km_ledger *, uint32_t owner);
/* Очистка опыта (§10.5): только кандидаты и пробные планы этого опыта и
 * этого вида привязки. Возвращает число освобождённых. */
size_t d2km_ledger_cleanup(d2km_ledger *, uint32_t owner, d2km_binding);
size_t d2km_ledger_count(const d2km_ledger *, uint32_t owner);

/* §14. Резерв — наибольшее падение свободной памяти за одну минуту среди
 * образцов за последние сутки. samples — свободная память в байтах, по
 * времени, с шагом period_s секунд (1..60). Пока наблюдение короче часа,
 * резерв равен declared. */
uint64_t d2km_memory_reserve(const uint64_t *samples, size_t n,
                             uint32_t period_s, uint64_t declared);
/* Опыт допускается, если свободная память минус резерв не меньше
 * объявленной. 1 — допущен, 0 — нет (NO_RESOURCES). */
int d2km_memory_admit(uint64_t free_now, uint64_t reserve, uint64_t declared);

#endif
