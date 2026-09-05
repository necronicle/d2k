/* plan_internal.h — внутреннее устройство плана.
 *
 * Отдельно от d2k_plan.h намеренно: наружу торчит контракт из четырёх
 * функций, а раскладка структур — дело исполнителя и может меняться без
 * пересборки того, кто его зовёт.
 */
#ifndef D2K_PLAN_INTERNAL_H
#define D2K_PLAN_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_plan.h"

/* Коды записей. Обязаны совпадать с internal/plan/tlv.go — расхождение ловится
 * тестом моста, который гоняет planlab на плане, порождённом Go. */
enum {
    REC_ID      = 0x0001,
    REC_PROTO   = 0x0002,
    REC_PAYLOAD = 0x0010,
    REC_POISON  = 0x0011,
    REC_SPLIT   = 0x0100,
    REC_FAKE    = 0x0101,
    REC_SEQOVL  = 0x0102,
    REC_ORDER   = 0x0103,
    REC_GUARD   = 0x0104
};

/* Якоря семантических позиций. */
enum {
    ANCHOR_PAYLOAD_START = 0,
    ANCHOR_SNI_START     = 1,
    ANCHOR_SNI_END       = 2,
    ANCHOR_HELLO_MIDDLE  = 3,
    ANCHOR_RECORD_END    = 4
};

enum { PLACE_BEFORE = 0, PLACE_BETWEEN = 1 };
enum { ORDER_FORWARD = 0, ORDER_REVERSE = 1 };

struct d2k_payload {
    uint16_t id;
    uint8_t *bytes;
    size_t   len;
};

struct d2k_poison {
    uint16_t id;
    uint8_t  ttl;
    uint8_t  flags;
    int32_t  seq_shift;
};

struct d2k_split {
    uint16_t anchor;
    int16_t  offset;
};

struct d2k_fake {
    uint16_t payload_id;
    uint16_t poison_id;
    uint8_t  repeats;
    uint8_t  placement;
    uint32_t gap_us;
};

struct d2k_seqovl {
    uint16_t payload_id;
    uint16_t poison_id;
};

struct d2k_plan {
    uint16_t schema;
    uint16_t minexec;
    uint8_t  id[16];
    uint8_t  transport;
    uint8_t  proto;
    uint8_t  order;
    uint8_t  guards;

    struct d2k_payload *payloads; size_t n_payloads;
    struct d2k_poison  *poisons;  size_t n_poisons;
    struct d2k_split   *splits;   size_t n_splits;
    struct d2k_fake    *fakes;    size_t n_fakes;
    struct d2k_seqovl  *seqovls;  size_t n_seqovls;
};

const struct d2k_payload *d2k_find_payload(const d2k_plan *p, uint16_t id);
const struct d2k_poison  *d2k_find_poison(const d2k_plan *p, uint16_t id);

#endif /* D2K_PLAN_INTERNAL_H */
