/* Синтез программы TLS из модели коробки (D2K_SPEC.md §7.1–§7.5).
 *
 * Входы: установленные факты коробки, приветствие клиента (форма), имя,
 * которое коробка пропускает (с фактом-источником), зерно генератора.
 * Выход: кандидат с полной записью «почему», или «нужен факт» с видом
 * недостающего факта, или «требования несовместимы». Числа берутся только из
 * установленных фактов; чего нет — то не подставляется.
 *
 * Поля воздействия, по которым синтез узнаёт факты:
 *   - D2KM_OP_SET_FIELD / D2KM_TLS_F_SNI — замена имени в приветствии;
 *   - D2KM_OP_SPLIT / D2KM_TLS_F_SNI, value — смещение разреза от начала имени;
 *   - D2KM_OP_LIMIT_DELIVERY / D2KM_FIELD_PATH_BOX — TTL фальшивки, на
 *     которой коробка начинает реагировать (числовой факт: хоп коробки);
 *   - D2KM_OP_LIMIT_DELIVERY / D2KM_FIELD_PATH_SERVER — TTL, с которого пакет
 *     доходит до сервера (числовой факт: хоп сервера). */
#ifndef D2KM_SYNTH_H
#define D2KM_SYNTH_H

#include "d2km_box.h"
#include "d2km_program.h"
#include "d2km_tls.h"

#define D2KM_FIELD_PATH_BOX 0x20001u
#define D2KM_FIELD_PATH_SERVER 0x20002u
#define D2KM_FIELD_RECORD 0x20003u
#define D2KM_FIELD_FAKE_COPIES 0x20005u
#define D2KM_FIELD_FAKE_SPLIT 0x20006u

/* R=0: TTL хопа коробки; R=1/2/3: tcpts/md5/badsum.
 * copies.value = R*256+k (k=1..255): соседние значения одного R —
 * соседние значения параметра; переход между R не является границей.
 * combination.value = (R*256+k)*512+position; position=0 — без разреза,
 * 1/3/5 — PAYLOAD_START, 257 — SNI_START+1. Факт сравнивает только
 * position, фиксируя тело фальшивки, R и k в обоих плечах. */
#define D2KM_COPIES_VALUE(r, k) ((int64_t)(r) * 256 + (k))
#define D2KM_COMBO_VALUE(r, k, pos) (D2KM_COPIES_VALUE(r, k) * 512 + (pos))
#define D2KM_SPOIL_MASK(r) (1u << ((unsigned)(r) - 1u))


typedef struct {
    const d2km_box *box;
    const d2km_target *target; /* NULL: генерация без проверки контрпримеров */
    const uint8_t *client_hello;   /* запись TLS с ClientHello клиента */
    size_t client_hello_length;
    const char *pass_name;         /* имя, которое коробка пропускает; NULL — нет */
    uint32_t pass_name_fact;       /* установленный факт, доказавший пропуск имени */
    uint64_t seed;                 /* зерно генератора байтов фальшивки */
    /* §7.1 п. 5: сколько байт сообщения исполнитель унесёт одним пакетом;
       0 — не объявлено (тогда сообщение не ужимается). */
    size_t max_payload;
    /* Хоп коробки не измерить (реакция — тишина): способ TTL исключён,
       фальшивка — только с порчей транспорта, безопасной для сервера. */
    int box_hop_unmeasurable;
} d2km_synth_in;

typedef enum {
    D2KM_SYN_CANDIDATE = 1,
    D2KM_SYN_NEED_FACT,            /* *need — вид недостающего факта */
    D2KM_SYN_REQ_CONFLICT,         /* факты несовместимы с требованиями */
    D2KM_SYN_EXEC_UNSUPPORTED,     /* исполнитель не выразит нужное */
    D2KM_SYN_BAD_INPUT
} d2km_synth_code;

d2km_synth_code d2km_synth_tls(const d2km_synth_in *, d2km_program *out,
                               d2km_fact_kind *need, char *reason, size_t cap);

/* Общий генератор сообщения для синтеза и вопросов. Создаёт payload[0]
 * по форме клиента и ограничениям имени; безопасность воздействия
 * доказывается отдельно вопросом или установленным фактом. */
d2km_synth_code d2km_synth_message(const d2km_synth_in *, d2km_program *, char *, size_t);
void d2km_synth_poison(d2km_poison *, unsigned method, uint8_t box_hop);

#endif
