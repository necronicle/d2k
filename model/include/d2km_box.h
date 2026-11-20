/* Модель коробки (D2K_SPEC.md §5.1, §5.3).
 *
 * Факты, живые гипотезы, неизвестное, контрпримеры, версия, цели. В начале
 * модель пустая. Каждый новый факт, контрпример, понижение или деление —
 * новая версия. Факты коробки сравниваются с наблюдениями других целей
 * без учёта самой цели: коробка — поведение на пути, а не имя. */
#ifndef D2KM_BOX_H
#define D2KM_BOX_H

#include "d2km_fact.h"

#define D2KM_BOX_FACTS_MAX 64
#define D2KM_BOX_COUNTER_MAX 32
#define D2KM_BOX_TARGETS_MAX 64

typedef struct {
    uint64_t candidate;      /* хэш программы */
    uint32_t experiment;     /* опыт испытания */
    uint64_t receipt;        /* ссылка на квитанцию */
    d2km_result result;      /* что показала прикладная проверка */
    d2km_target target;
    d2km_context context;   /* контекст провала: отрицательное знание не глобально */
} d2km_counterexample;

/* Состояние гипотезы в модели. «Не спрашивали» и «спросили — нет» —
 * разные состояния (§5.1). */
typedef enum {
    D2KM_HYP_UNKNOWN = 0,   /* не спрашивали */
    D2KM_HYP_LIVE,          /* открыта сигналом, не опровергнута */
    D2KM_HYP_REFUTED,       /* опыт опроверг */
    D2KM_HYP_CONFIRMED      /* устойчиво подтверждена опытом */
} d2km_hyp_state;

typedef struct {
    uint32_t id;                                  /* B<id> */
    uint32_t version;
    size_t fact_count;
    d2km_fact facts[D2KM_BOX_FACTS_MAX];
    uint8_t hypotheses[D2KM_HYPOTHESIS_END];      /* d2km_hyp_state */
    size_t counter_count;
    d2km_counterexample counters[D2KM_BOX_COUNTER_MAX];
    size_t target_count;
    d2km_target targets[D2KM_BOX_TARGETS_MAX];
} d2km_box;

typedef enum {
    D2KM_BOX_OK = 0,
    D2KM_BOX_FULL,           /* предел ресурса: NO_RESOURCES */
    D2KM_BOX_BAD_INPUT,
    D2KM_BOX_SPLIT_NEEDED,   /* установленные факты разных целей противоречат */
    D2KM_BOX_DUPLICATE       /* такой факт уже есть */
} d2km_box_code;

void d2km_box_init(d2km_box *, uint32_t id);

/* Добавляет факт. Установленный факт, противоречащий установленному факту
 * ДРУГОЙ цели (тот же контекст без цели, то же воздействие, другой исход),
 * не добавляется: D2KM_BOX_SPLIT_NEEDED, *conflict — индекс факта. Факт той
 * же цели, противоречащий установленному, понижает тот (контрпример) и
 * добавляется. */
d2km_box_code d2km_box_add_fact(d2km_box *, const d2km_fact *, size_t *conflict);

/* Устойчивый исход плеча: понижает все установленные факты, которым он
 * противоречит в контексте той же цели. Возвращает число понижений;
 * при понижении версия растёт. */
size_t d2km_box_observe(d2km_box *, const d2km_arm_record *);

/* Открывает гипотезы сигнала (§6.2): UNKNOWN → LIVE. Опровергнутые и
 * подтверждённые не трогаются. */
void d2km_box_open(d2km_box *, d2km_signal);
/* Применяет критерий опыта (d2km_experiment_judge): гипотезы с битом в
 * refuted → REFUTED, в confirmed → CONFIRMED, если исход дал ровно одну. */
void d2km_box_judge(d2km_box *, const d2km_experiment *, unsigned confirmed,
                    unsigned refuted);
/* Живые гипотезы: пишет до cap, возвращает их число. */
size_t d2km_box_live(const d2km_box *, d2km_hypothesis *, size_t cap);

d2km_box_code d2km_box_add_counter(d2km_box *, const d2km_counterexample *);
/* Испытан ли уже этот кандидат на этой цели (контрпример есть). */
int d2km_box_tried(const d2km_box *, uint64_t candidate, const d2km_target *);

/* Нечитаемые поля формы по установленным фактам неизменности (§2.1). */
unsigned d2km_box_unread(const d2km_box *);

/* Контрпример только совместимого контекста; неизвестный контекст не
 * опровергает программу в новом. Для OWN и восстановления задачи. */
int d2km_box_tried_context(const d2km_box *, uint64_t candidate, const d2km_context *);

/* §5.3: коробка — кандидат для цели, если ни один установленный факт не
 * опровергнут наблюдениями цели (устойчивыми исходами плеч) в совместимом
 * контексте. obs — наблюдения цели. */
int d2km_box_candidate(const d2km_box *, const d2km_arm_record *obs, size_t n);

/* §5.3: цель относится к коробке, если на ней повторён опыт, установивший
 * факт вида «Реакция» этой коробки, — оба плеча с теми же исходами, — и коробка остаётся
 * кандидатом. Добавляет цель и возвращает D2KM_BOX_OK; иначе
 * D2KM_BOX_BAD_INPUT. */
d2km_box_code d2km_box_admit(d2km_box *, const d2km_target *,
                             const d2km_arm_record *obs, size_t n);
int d2km_box_has_target(const d2km_box *, const d2km_target *);

/* §5.3: деление. Факты и цели, относящиеся к target, переходит в out
 * (новая коробка out_id). Версии обеих моделей растут. */
d2km_box_code d2km_box_split(d2km_box *, const d2km_target *, d2km_box *out,
                             uint32_t out_id);

int d2km_target_equal(const d2km_target *, const d2km_target *);

#endif
