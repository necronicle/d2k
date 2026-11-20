/* Факты модели коробки (D2K_SPEC.md §5.2).
 *
 * Наблюдённый факт — устойчивый исход одного плеча; причину не утверждает.
 * Установленный факт — зависимость исхода от одного параметра: два плеча в
 * одном контексте различаются ровно одним параметром одного оператора, у
 * обоих устойчивые и разные исходы, контрольное плечо дало ожидаемый исход
 * и показало, что сервер достижим. Числовой факт — установленный факт для
 * соседних значений параметра. В синтезе — только установленные факты. */
#ifndef D2KM_FACT_H
#define D2KM_FACT_H

#include "d2km_experiment.h"

typedef enum {
    D2KM_F_PATH = 1,
    D2KM_F_PARSE,
    D2KM_F_ASSEMBLY,
    D2KM_F_CHECKS,
    D2KM_F_REACTION,
    D2KM_F_STATE,
    D2KM_F_VOLUME,
    D2KM_F_RESPONSE,
    D2KM_F_NAME,
    D2KM_FACT_KIND_END
} d2km_fact_kind;

typedef enum {
    D2KM_LEVEL_OBSERVED = 1,
    D2KM_LEVEL_ESTABLISHED
} d2km_fact_level;

#define D2KM_FACT_SOURCES_MAX 8

/* Устойчивый исход плеча вместе с его условиями. */
typedef struct {
    uint32_t experiment;
    d2km_context context;
    d2km_arm arm;           /* воздействие плеча; has_expected не учитывается */
    d2km_result result;     /* устойчивый исход по правилу повтора */
} d2km_arm_record;

typedef struct {
    uint32_t id;                    /* F<id> */
    d2km_fact_kind kind;
    d2km_fact_level level;
    d2km_context context;           /* условия */
    /* Утверждение. Наблюдённый: при воздействии a — исход ra.
     * Установленный: при a — ra, при b — rb, всё прочее равно.
     * Числовой: a и b — соседние значения одного поля одного оператора,
     * a.value < b.value. */
    d2km_arm a, b;
    d2km_result ra, rb;
    int numeric;
    /* Неизменность: при a и при b один и тот же исход-реакция коробки —
     * коробка не использует этот параметр для своего решения (вид «Разбор»:
     * поле не читается). ra == rb. */
    int invariant;
    uint32_t sources[D2KM_FACT_SOURCES_MAX];
    size_t source_count;
    uint32_t model_version;         /* версия модели, где факт появился или понижен */
} d2km_fact;

typedef enum {
    D2KM_FR_OK = 0,
    D2KM_FR_BAD_INPUT,
    D2KM_FR_NOT_NETWORK,      /* исход плеча — локальный или без наблюдений */
    D2KM_FR_CONTEXT_DIFFERS,  /* плечи в разных контекстах */
    D2KM_FR_NOT_ONE_PARAMETER,/* плечи различаются больше чем одним параметром */
    D2KM_FR_SAME_ACTION,      /* плечи не различаются */
    D2KM_FR_SAME_RESULT,      /* исходы равны: зависимости нет */
    D2KM_FR_CONTROL_FAILED,   /* контроль не дал ожидаемого или сервер не достигнут */
    D2KM_FR_CONTROL_CONTEXT,  /* контроль в другом контексте */
    D2KM_FR_TOO_MANY_SOURCES,
    D2KM_FR_NOT_BOX_REACTION  /* неизменность без реакции коробки не доказана */
} d2km_fact_reason;

const char *d2km_fact_kind_name(d2km_fact_kind);
const char *d2km_fact_reason_name(d2km_fact_reason);

/* Наблюдённый факт из устойчивого исхода плеча. */
d2km_fact_reason d2km_fact_observe(d2km_fact *, uint32_t id, d2km_fact_kind,
                                   const d2km_arm_record *, uint32_t model_version);

/* Установленный факт из двух плеч и контроля. resolution — шаг значения
 * параметра по грамматике (1 для TTL, байтов, окна); 0 — параметр не
 * числовой. Числовым факт становится, когда оба плеча задают одно поле
 * одного оператора и значения отличаются ровно на resolution. control_expected
 * — исход, который контроль обязан дать. */
d2km_fact_reason d2km_fact_establish(d2km_fact *, uint32_t id, d2km_fact_kind,
                                     const d2km_arm_record *a,
                                     const d2km_arm_record *b,
                                     const d2km_arm_record *control,
                                     d2km_result control_expected,
                                     int64_t resolution, uint32_t model_version);

/* Установленный факт неизменности: два плеча различаются ровно одним
 * параметром, у обоих устойчивый ОДИНАКОВЫЙ исход, и это реакция коробки
 * (RST, тишина, обрыв, подмена), а контроль в том же контексте достиг
 * сервера. Одинаковый успех неизменности не доказывает: коробка могла не
 * участвовать. Единственное отдельное утверждение о сервере: PATH,
 * база и контроль без воздействия, b=SPOIL_TRANSPORT/FIELD_SPOIL/1..3,
 * оба APP_OK. Такой факт означает безопасность порчи для сервера в
 * измеренном контексте разрешённого имени; не нечитаемость коробкой. */
d2km_fact_reason d2km_fact_establish_invariance(d2km_fact *, uint32_t id,
                                               d2km_fact_kind,
                                               const d2km_arm_record *a,
                                               const d2km_arm_record *b,
                                               const d2km_arm_record *control,
                                               d2km_result control_expected,
                                               uint32_t model_version);

/* Исход — реакция коробки, а не успех и не отказ сервера. */
int d2km_result_is_box_reaction(d2km_result);

/* Поля формы, которые факт признаёт нечитаемыми: маска D2KM_FORM_* для
 * установленного факта неизменности над полем формы, иначе 0. */
unsigned d2km_fact_unread_form(const d2km_fact *);

/* Контрпример противоречит установленному факту: понизить до наблюдённого
 * и записать опыт-источник. Понижение — новая версия модели. */
d2km_fact_reason d2km_fact_demote(d2km_fact *, uint32_t counter_experiment,
                                  uint32_t model_version);

/* Противоречит ли устойчивый исход плеча установленному факту: тот же
 * контекст, то же воздействие, что a или b, а исход другой. */
int d2km_fact_contradicted(const d2km_fact *, const d2km_arm_record *);

/* Годен ли факт для синтеза (§5.2): только установленный. */
int d2km_fact_usable(const d2km_fact *);

#endif
