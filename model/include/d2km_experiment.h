/* Опыт, плечо, наблюдение, исход прогона и правило повтора
 * (D2K_SPEC.md §2.3, §5.2, §6.1, §6.2, §6.4).
 *
 * Наблюдение — сырые числа без выводов. Исход прогона — классификация
 * наблюдения протокольным модулем; по исходам работает правило повтора.
 * Опыт записывает вопрос, воздействие, прогнозы, контрольное плечо и
 * критерий ДО отправки; d2km_experiment_check отвергает опыт без них. */
#ifndef D2KM_EXPERIMENT_H
#define D2KM_EXPERIMENT_H

#include "d2km_codes.h"
#include "d2km_context.h"

/* §6.2: закрытый перечень гипотез первого уровня. */
typedef enum {
    D2KM_H_ADDR_BLOCK = 1,
    D2KM_H_PORT_BLOCK,
    D2KM_H_SERVER_DOWN,
    D2KM_H_NET_LOSS,
    D2KM_H_HELLO_NAME,
    D2KM_H_HELLO_FIELD,
    D2KM_H_HELLO_FORM,
    D2KM_H_ADDR_AFTER_HELLO,
    D2KM_H_NAME_ABSORBED,
    D2KM_H_RESPONSE_BLOCK,
    D2KM_H_SERVER_NO_REPLY,
    D2KM_H_VOLUME_CUT,
    D2KM_H_TIME_CUT,
    D2KM_H_CONTENT_CUT,
    D2KM_H_SERVER_CLOSED,
    D2KM_H_BOX_ABSORBS,
    D2KM_H_SERVER_OVERLOAD,
    D2KM_H_QUIC_HEADER,
    D2KM_H_QUIC_INITIAL,
    D2KM_H_UDP_PORT,
    D2KM_H_STUN_BLOCK,
    D2KM_H_DNS_BLOCK,
    D2KM_H_UDP_VOLUME,
    D2KM_H_UDP_TIME,
    D2KM_H_UDP_CONTENT,
    D2KM_H_DNS_ADDR,
    D2KM_H_DNS_NAME,
    D2KM_H_DNS_LONG_SESSION,
    /* Уточнения второго уровня установленного класса по приветствию.
     * Параметр R/k/позиция принадлежит вопросу, не номеру гипотезы. */
    D2KM_H_SERVER_REJECTS_SPOIL,
    D2KM_H_SERVER_ACCEPTS_SPOIL,
    D2KM_H_COPIES_ENOUGH,
    D2KM_H_COPIES_INSUFFICIENT,
    D2KM_H_HEADER_SPLIT_RELIEF,
    D2KM_H_HEADER_SPLIT_BLOCKED,
    D2KM_H_COMBINATION_RELIEF,
    D2KM_H_COMBINATION_BLOCKED,
    D2KM_HYPOTHESIS_END
} d2km_hypothesis;

#define D2KM_HYPOTHESES_MAX 8

const char *d2km_hypothesis_name(d2km_hypothesis);
/* Гипотезы сигнала по таблице §6.2. Возвращает их число (0 — неизвестный
 * сигнал); пишет не больше cap. */
size_t d2km_hypotheses_for(d2km_signal, d2km_hypothesis *out, size_t cap);

/* §6.4. Номер оператора — его место в таблице: он же порядок при равном
 * весе вопросов (§6.3). */
typedef enum {
    D2KM_OP_SET_FIELD = 1,
    D2KM_OP_DROP_FIELD,
    D2KM_OP_ADD_FIELD,
    D2KM_OP_REORDER,
    D2KM_OP_SPLIT,
    D2KM_OP_ADD_MESSAGE,
    D2KM_OP_SPOIL_TRANSPORT,
    D2KM_OP_LIMIT_DELIVERY,
    D2KM_OP_DELAY,
    D2KM_OP_WINDOW,
    D2KM_OP_RESET_REPEAT,
    D2KM_OPERATOR_END
} d2km_operator;

const char *d2km_operator_name(d2km_operator);

/* Поля формы обмена как поля воздействия: D2KM_FIELD_FORM | D2KM_FORM_*.
 * Остальные номера полей задают протокольные модули. */
#define D2KM_FIELD_FORM 0x10000u
#define D2KM_FIELD_SPOIL 0x20004u

/* Воздействие: оператор, поле грамматики (номер поля задаёт протокольный
 * модуль; 0 — оператор без поля) и значение параметра. Чисел обхода
 * воздействие не содержит: значение приходит из поиска §6.5. */
typedef struct {
    d2km_operator op;
    uint32_t field;
    int64_t value;
} d2km_action;

/* Исход прогона. Сравнивается точно по виду и значению; гранулярность
 * значения (байты, пакеты, хопы) выбирает протокольный модуль. */
typedef enum {
    D2KM_R_APP_OK = 1,      /* прикладной успех по §9 */
    D2KM_R_REPLY,           /* сервер ответил, прикладной контракт не проверялся */
    D2KM_R_NO_SERVICE,      /* сервер ответил отказом протокола */
    D2KM_R_RST,
    D2KM_R_SYN_SILENT,
    D2KM_R_HELLO_SILENT,
    D2KM_R_CUT,             /* value — объём до обрыва */
    D2KM_R_UDP_SILENT,
    D2KM_R_ICMP,            /* value — тип и код ICMP */
    D2KM_R_SPOOFED,         /* подмена ответа (§9.2) */
    D2KM_R_NOT_MEASURED,    /* пакеты не ушли или нет ни одного наблюдения */
    D2KM_R_LOCAL_FAIL,      /* локальная ошибка: не ответ коробки */
    D2KM_RESULT_END
} d2km_result_kind;

typedef struct {
    d2km_result_kind kind;
    int64_t value;
} d2km_result;

const char *d2km_result_name(d2km_result_kind);
int d2km_result_equal(d2km_result, d2km_result);
/* Исход говорит о сети (коробке, сервере, пути), а не о D2K. */
int d2km_result_is_network(d2km_result);
/* Сервер достижим: исход исключает «сервер недоступен». */
int d2km_result_server_reached(d2km_result);

/* Наблюдение одного прогона: только сырые величины. */
typedef struct {
    uint32_t sent_packets, received_packets;
    uint64_t sent_bytes, received_bytes;
    uint64_t application_bytes;   /* полезные байты приложения от сервера */
    uint32_t acks, rsts, icmps, timeouts;
    uint32_t elapsed_ms;
    int local_error;              /* 0 — нет; иначе код ошибки D2K/ОС */
} d2km_observation;

/* Плечо: с воздействием или контрольное (без воздействия либо с заранее
 * известным исходом). */
typedef struct {
    int has_action;
    d2km_action action;
    int has_expected;
    d2km_result expected;
} d2km_arm;

typedef struct {
    d2km_hypothesis hypothesis;
    d2km_result predicted;
} d2km_prediction;

typedef enum {
    D2KM_E_DIRECT = 1,   /* прямой контроль: опыт без воздействия (§4.3) */
    D2KM_E_QUESTION,     /* вопрос (§6) */
    D2KM_E_TRIAL         /* испытание кандидата (§8.1) */
} d2km_experiment_kind;

typedef struct {
    uint32_t id;                    /* E<id>, не 0 */
    d2km_experiment_kind kind;
    d2km_context context;
    d2km_arm arm;                   /* плечо с воздействием (у вопроса) */
    d2km_arm control;               /* контрольное плечо */
    size_t prediction_count;
    d2km_prediction predictions[D2KM_HYPOTHESES_MAX];
    uint64_t candidate;             /* хэш программы кандидата (испытание) */
    uint64_t memory_bytes;          /* объявленная память (§14) */
} d2km_experiment;

typedef enum {
    D2KM_EC_OK = 0,
    D2KM_EC_NO_ID,
    D2KM_EC_BAD_KIND,
    D2KM_EC_BAD_CONTEXT,
    D2KM_EC_NO_MEMORY_DECLARED,
    D2KM_EC_DIRECT_HAS_ACTION,
    D2KM_EC_FEW_HYPOTHESES,
    D2KM_EC_DUPLICATE_HYPOTHESIS,
    D2KM_EC_BAD_HYPOTHESIS,
    D2KM_EC_NO_ACTION,
    D2KM_EC_BAD_OPERATOR,
    D2KM_EC_NO_CONTROL,
    D2KM_EC_ZERO_WEIGHT,
    D2KM_EC_BAD_PREDICTION,
    D2KM_EC_NO_CANDIDATE
} d2km_experiment_check_code;

/* Проверяет, что у опыта записано всё, что требует §6.1 (для вопроса),
 * §4.3 (прямой контроль) или §8.1 (испытание), и объявлена память. */
d2km_experiment_check_code d2km_experiment_check(const d2km_experiment *);

/* Критерий §6.1 по таблице прогнозов: гипотезы, чей прогноз совпал с
 * исходом, подтверждаются, остальные опровергаются. Биты масок — индексы
 * predictions[]. Возвращает число подтверждённых; 0 — исход не объяснён ни
 * одной гипотезой (повод для записи «почему», не для вывода). Исход не о
 * сети ничего не подтверждает и не опровергает: возвращает -1. */
int d2km_experiment_judge(const d2km_experiment *, d2km_result,
                          unsigned *confirmed, unsigned *refuted);

/* §5.2, правило повтора плеча. */
#define D2KM_ARM_RUNS_MAX 4
typedef enum {
    D2KM_ARM_STABLE = 1,       /* два одинаковых исхода подряд */
    D2KM_ARM_NEED_MORE,        /* нужен ещё прогон */
    D2KM_ARM_CONFLICTING,      /* за четыре прогона пары нет */
    D2KM_ARM_LOCAL_FAIL,       /* прогон с локальной ошибкой */
    D2KM_ARM_NOT_MEASURED      /* прогон без наблюдений */
} d2km_arm_verdict;

d2km_arm_verdict d2km_arm_stability(const d2km_result *runs, size_t n,
                                    d2km_result *stable);
/* Код итога опыта для вердикта плеча, который не дал устойчивого исхода. */
d2km_outcome d2km_arm_verdict_outcome(d2km_arm_verdict);

#endif
