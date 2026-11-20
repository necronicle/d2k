/* Коды сигналов, состояния задачи и коды итога (D2K_SPEC.md §4.2, §4.6, §4.7).
 *
 * Перечни закрытые: новый код появляется только вместе с правкой ТЗ.
 * Префикс d2km_ — новая модель D2K; старые подсистемы с похожими именами
 * удаляются по ТЗ §18. */
#ifndef D2KM_CODES_H
#define D2KM_CODES_H

#include <stddef.h>

/* §4.2 */
typedef enum {
    D2KM_S_RST = 1,
    D2KM_S_SYN_SILENT,
    D2KM_S_HELLO_SILENT,
    D2KM_S_LATE_CUT,
    D2KM_S_RETRANS,
    D2KM_S_UDP_SILENT,
    D2KM_S_UDP_STOP,
    D2KM_S_DNS_FAIL,
    D2KM_SIGNAL_END
} d2km_signal;

/* §4.7 */
typedef enum {
    D2KM_DIRECT_OK = 1,
    D2KM_BLOCK_CONFIRMED,
    D2KM_BLOCK_GONE,
    D2KM_SERVER_DOWN,
    D2KM_NO_SERVICE,
    D2KM_NO_REFERENCE,
    D2KM_NOT_MEASURED,
    D2KM_FORM_NOT_REPRODUCED,
    D2KM_LOCAL_FAIL,
    D2KM_EVENT_LOST,
    D2KM_NO_RESOURCES,
    D2KM_CONFLICTING,
    D2KM_MODEL_INCOMPLETE,
    D2KM_REQ_CONFLICT,
    D2KM_EXEC_UNSUPPORTED,
    D2KM_TRIAL_FAIL,
    D2KM_APPLIED,
    D2KM_DEGRADED,
    D2KM_OUTCOME_END
} d2km_outcome;

/* §4.6. CLOSED — задача закрыта (не состояние таблицы, а её выход). */
typedef enum {
    D2KM_T_SUSPECT = 1,
    D2KM_T_DIRECT,
    D2KM_T_OWN,
    D2KM_T_ASK,
    D2KM_T_SYNTH,
    D2KM_T_TRIAL,
    D2KM_T_APPLIED,
    D2KM_T_WAIT,
    D2KM_T_CLOSED,
    D2KM_TASK_STATE_END
} d2km_task_state;

/* События задачи, которые не являются кодами итога (§4.6, столбец «Переходы»). */
typedef enum {
    D2KM_EV_OUTCOME = 1,     /* пришёл код итога, см. outcome */
    D2KM_EV_START,           /* SUSPECT → DIRECT: начат прямой контроль */
    D2KM_EV_OWN_OK,          /* OWN: своё знание прошло испытание */
    D2KM_EV_OWN_NONE,        /* OWN: знания нет или провал */
    D2KM_EV_MODEL_ENOUGH,    /* ASK: модели хватает (§6.6) */
    D2KM_EV_CANDIDATE,       /* SYNTH: кандидат готов */
    D2KM_EV_NEED_FACT,       /* SYNTH: синтезу нужен факт */
    D2KM_EV_TRIAL_OK,        /* TRIAL: прикладной успех */
    D2KM_EV_WAKE             /* WAIT: условие пробуждения выполнено */
} d2km_task_event_kind;

/* §4.6, закрытый перечень условий пробуждения. Таймера среди них нет. */
typedef enum {
    D2KM_WAKE_NEW_SIGNAL = 1,
    D2KM_WAKE_MODEL_VERSION,
    D2KM_WAKE_NEW_KNOWLEDGE,
    D2KM_WAKE_RESOURCE_FREED,
    D2KM_WAKE_END
} d2km_wake;

typedef struct {
    d2km_task_event_kind kind;
    d2km_outcome outcome;   /* для D2KM_EV_OUTCOME */
    d2km_wake wake;         /* для D2KM_EV_WAKE */
} d2km_task_event;

/* Следующий шаг пути (§4.1) для кода итога; столбец «Следующий шаг» §4.7. */
typedef enum {
    D2KM_NEXT_CLOSE = 1,      /* закрыть задачу */
    D2KM_NEXT_OWN,            /* шаг 3: своё знание */
    D2KM_NEXT_UNBIND_CLOSE,   /* снять привязку, закрыть */
    D2KM_NEXT_WAIT,           /* отсрочка */
    D2KM_NEXT_ASK,            /* контрпример, шаг 4 */
    D2KM_NEXT_WATCH,          /* шаг 10: наблюдение */
    D2KM_NEXT_DIRECT          /* шаг 2: прямой контроль */
} d2km_next_step;

const char *d2km_signal_name(d2km_signal);
const char *d2km_outcome_name(d2km_outcome);
const char *d2km_task_state_name(d2km_task_state);
const char *d2km_wake_name(d2km_wake);

/* 1 — код известен, 0 — нет. */
int d2km_outcome_valid(d2km_outcome);
d2km_next_step d2km_outcome_next(d2km_outcome);

/* Только BLOCK_CONFIRMED означает «блокировка доказана» (§4.7). */
int d2km_outcome_proves_block(d2km_outcome);
/* Только APPLIED означает «обход найден» (§4.7). */
int d2km_outcome_proves_bypass(d2km_outcome);

/* Переход по таблице §4.6. Возвращает новое состояние или 0, если переход
 * таблицей не разрешён (вызывающий обязан считать это ошибкой, а не
 * подбирать ближайшее состояние). */
d2km_task_state d2km_task_next(d2km_task_state, const d2km_task_event *);

#endif
