/* Исполнение плеча опыта (D2K_SPEC.md §6.7, §8).
 *
 * Ведущий задачи не знает, чем исполняется плечо: сетью роутера (датапат,
 * собственный поток с меткой опыта) или моделью коробки в тестах (§15.1).
 * Он задаёт плечо — что послать и как — и получает наблюдение и исход
 * одного прогона. Повторы по правилу §5.2 делает ведущий. */
#ifndef D2KM_NET_H
#define D2KM_NET_H

#include "d2km_experiment.h"
#include "d2km_program.h"

typedef enum {
    D2KM_ARM_EXCHANGE = 1,   /* приветствие (+ программа) и прикладной обмен */
    D2KM_ARM_PATH_SERVER,    /* дойдёт ли до сервера пакет с TTL ttl (ответит ли он) */
    D2KM_ARM_PATH_BOX        /* отреагирует ли коробка на приветствие с TTL ttl, не дошедшее до сервера */
} d2km_arm_kind;

typedef struct {
    d2km_arm_kind kind;
    const d2km_context *context;
    const uint8_t *hello;        /* приветствие для этого плеча (форма клиента) */
    size_t hello_length;
    const d2km_program *program; /* NULL — без программы */
    uint8_t ttl;                 /* для PATH_*; 0 — обычный */
    int reference;               /* через опорную точку (вне пути коробки) */
    uint32_t experiment;         /* E<id>: метка опыта, владелец ресурсов */
} d2km_arm_spec;

typedef struct {
    void *ctx;
    /* Один прогон плеча. 0 — прогон состоялся (исход в *res, в том числе
     * NOT_MEASURED/LOCAL_FAIL), -1 — исполнить нельзя (EXEC_UNSUPPORTED). */
    int (*run)(void *ctx, const d2km_arm_spec *, d2km_observation *,
               d2km_result *res);
} d2km_net;

#endif
