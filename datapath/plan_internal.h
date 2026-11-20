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

/* Коды записей. Единственный их источник — этот файл: Go-сторона движка
 * удалена коммитом 1e95db1, и прежняя оговорка «обязаны совпадать с
 * internal/plan/tlv.go» больше ни к чему не относится. Совпадать обязаны
 * только две стороны СВОЕГО дерева — сборщик (core/compose.c, core/plantlv.c)
 * и разбор ниже, и это ловится planlab в test_compose.c.
 *
 * Незнакомый код разбор отвергает целиком (plan_parse.c), поэтому новая
 * запись безопасна для старого датапата: он откажет громко, а не исполнит
 * половину плана. */
enum {
    REC_ID      = 0x0001,
    REC_PROTO   = 0x0002,
    REC_PAYLOAD = 0x0010,
    REC_POISON  = 0x0011,
    REC_SPLIT   = 0x0100,
    REC_FAKE    = 0x0101,
    REC_SEQOVL  = 0x0102,
    REC_ORDER   = 0x0103,
    REC_GUARD   = 0x0104,
    REC_PACE    = 0x0105,
    REC_INPUT   = 0x0106,
    REC_SETTLE  = 0x0107,
    REC_SEGMENT = 0x0108,
    REC_WIRE    = 0x0109,
    REC_INPUT_TLS = 0x010a,
    REC_DELAY     = 0x010b,
    REC_IPFRAG    = 0x010c,
    REC_OOB       = 0x010d,
    REC_UDPLEN    = 0x010e,
    REC_QSPLIT    = 0x010f,
    REC_QDENY     = 0x0110,
    /* TTL фальшивки по измеренному пути (ip_autottl документации zapret2):
       id порчи, delta со знаком, min, max. Отдельная запись, а не расширение
       REC_POISON: старый исполнитель обязан отказаться громко, а не исполнить
       план без autottl — он поставил бы фальшивку с нашим константным TTL,
       то есть другое воздействие. Гейт — minexec 13. */
    REC_AUTOTTL   = 0x0111,
    REC_STREAM_OFFSET = 0x0112,
    REC_AFTER_SPLIT = 0x0113,
    REC_PREFLIGHT = 0x0114,
    REC_PREFLIGHT_RESYN = 0x0115,
    REC_HANDOVER_APPLY = 0x0116
};

/* Якоря семантических позиций. */
enum {
    ANCHOR_PAYLOAD_START = 0,
    ANCHOR_SNI_START     = 1,
    ANCHOR_SNI_END       = 2,
    ANCHOR_HELLO_MIDDLE  = 3,
    ANCHOR_RECORD_END    = 4,
    /* Середина ИМЕНИ хоста (sni_off + sni_len/2), а не середина пакета —
       см. anchor_offset в plan_apply.c и reorderPlan в
       internal/classify/properties.go. */
    ANCHOR_SNI_MIDDLE    = 5,
    ANCHOR_SLD_MIDDLE    = 6
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
    int32_t  ack_shift;
    /* autottl: 1 — TTL считается на исполнении по TTL ответной стороны
       потока, delta/min/max из записи REC_AUTOTTL. */
    /* tcp_ts_up: поднять опцию метки времени в начало (см. d2k_plan.h). */
    uint8_t  ts_up;
    uint8_t  autottl;
    int8_t   autottl_delta;
    uint8_t  autottl_min;
    uint8_t  autottl_max;
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
    uint8_t  tls_mod;
};

#define D2K_TLS_MOD_RND    (1u << 0)
#define D2K_TLS_MOD_DUPSID (1u << 1)

struct d2k_seqovl {
    uint16_t payload_id;
    uint16_t poison_id;
};

struct d2k_plan {
    /* Installation metadata only; not serialized, hashed or executed. The
       table owns this object uniquely and snapshots it before replacement. */
    const void *binding_owner;
    uint64_t binding_generation;
    uint8_t binding_trial_id[16];
    uint8_t binding_kind, binding_family, binding_shape, binding_temporary;
    uint8_t binding_exact_shape; /* installation scope, never program content/hash */
    uint16_t preflight_trial_sport; /* network order, zero for an unscoped trial */
    uint16_t schema;
    uint16_t minexec;
    uint8_t  id[D2K_PLAN_ID_LEN];
    uint8_t  transport;
    uint8_t  proto;
    uint8_t  order;
    uint8_t  guards;
    uint32_t input_len, input_sni_off, input_sni_len;
    uint32_t settle_us;
    uint32_t segment_size;
    uint8_t wire_profile;
    uint8_t input_tls;
    uint8_t has_stream_offset;
    uint32_t stream_offset;
    uint32_t after_offset,after_length,after_cut;
    uint8_t preflight, pf_wscale, pf_pieces, pf_hello_own;
    uint16_t pf_window, pf_data;
    uint8_t pf_handover_apply;
    const uint8_t *pf_hello; /* aliases the referenced immutable payload */
    size_t pf_hello_len;
    uint32_t pf_timeout_ms;
    uint32_t pf_resyn_timeout_ms;
    uint16_t pf_resyn_delay_ms;
    uint8_t pf_resyn_sends;
    char pf_name[254];
    uint8_t ipfrag;
    uint8_t oob_enabled;
    uint16_t oob_anchor;
    uint8_t oob_byte;
    /* УДЛИНЕНИЕ ДАТАГРАММЫ, байт; 0 — записи нет. zapret udplen
       increment=N: к UDP-нагрузке дописываются N нулевых байт, исходные
       байты не меняются (донор compose, questions.go:331-334). План с ним
       владеет нагрузкой: оригинал снимается, уходит удлинённая копия. */
    uint16_t udplen;
    /* РАЗРЕЗ CLIENTHELLO НА КАДРЫ CRYPTO внутри того же Initial (задача 40);
       0 — записи нет, 1 — два кадра, хвост первым. Нагрузка пересобирается
       функцией ядра d2k_quic_initial_split_crypto — той же, которой задан
       вопрос замера; план владеет нагрузкой, как при udplen. */
    uint8_t qsplit;
    /* QUIC ДЛЯ ИМЕНИ НЕ ПРОПУСКАЕТСЯ (задача 50, раунд 2); 0 — записи нет.
       Не воздействие и не обход: датаграммы клиента потока снимаются, чтобы
       браузер ушёл на TCP. Ставит контроллер, только когда обрыв QUIC
       воспроизведён своим запросом и обхода по QUIC нет. */
    uint8_t qdeny;

    struct d2k_payload *payloads; size_t n_payloads;
    struct d2k_poison  *poisons;  size_t n_poisons;
    struct d2k_split   *splits;   size_t n_splits;
    struct d2k_fake    *fakes;    size_t n_fakes;
    struct d2k_seqovl  *seqovls;  size_t n_seqovls;

    /* РАЗНОС ПОСЫЛОК ВО ВРЕМЕНИ, микросекунды. 0 — не задан.
     *
     * Задержка ставится перед каждой посылкой НАГРУЗКИ, кроме самой первой
     * посылки плана. Одно поле закрывает оба приёма донора:
     *
     *   три куска с паузой 12 мс между ними (disorder, raw_linux.go:686-694)
     *     — фальшивок нет, первый кусок уходит сразу, второй и третий с
     *       паузой;
     *   выдержка 15 мс между последней фальшивкой и правдой
     *     (probePoison, raw_linux.go:537) — первой посылкой идёт фальшивка,
     *     нагрузка получает задержку.
     *
     * Наличие записи означает, что план ВЛАДЕЕТ нагрузкой: оригинал снимается
     * (fate drop), а правда уходит собственной посылкой. Иначе выдержать
     * паузу не перед чем — оригинал отпускает ядро, и момент его отправки
     * планом не управляется. */
    uint32_t pace_us;

    /* ВЫДЕРЖКА ПЕРЕД ПЕРВОЙ СОБСТВЕННОЙ ПОСЫЛКОЙ НАГРУЗКИ, микросекунды.
     *
     * Отличается от обоих соседей, и различие несущее: pace задерживает
     * посылки ПОСЛЕ первой, settle — первую, но лишь когда перед ней уже
     * что-то ушло (фальшивка). Задержать ЕДИНСТВЕННУЮ посылку было нечем.
     *
     * Нужно это для датаграмм. Поле 19.09.2026: приветствие QUIC настоящего
     * клиента едет ДВУМЯ Initial-датаграммами в 40 мкс друг от друга, и
     * коробка складывает из них имя. Развести их во времени — и складывать
     * становится нечего; замерено, что поток после этого проходит. Разрезать
     * датаграмму нельзя (она атомарна), переставить куски внутри неё — тоже:
     * кусок один. Остаётся выдержка перед ним.
     *
     * Наличие записи означает владение нагрузкой (fate drop) по той же
     * причине, что у pace: оригинал, отпущенный ядром, уходит когда ему
     * угодно. */
    uint32_t delay_us;
};

const struct d2k_payload *d2k_find_payload(const d2k_plan *p, uint16_t id);
const struct d2k_poison  *d2k_find_poison(const d2k_plan *p, uint16_t id);

#endif /* D2K_PLAN_INTERNAL_H */
