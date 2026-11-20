/* Выбор следующего вопроса и поиск значения параметра
 * (D2K_SPEC.md §6.3, §6.5).
 *
 * Кандидат в вопросы — воздействие и прогнозы живых гипотез. Вес — число
 * пар живых гипотез с разным прогнозом, если от выбора между ними зависит
 * действие или число будущей программы. Задаётся кандидат с наибольшим
 * весом; при равенстве — с меньшим числом пакетов, затем с меньшим номером
 * оператора. Нулевой вес и уже отвеченный вопрос не задаются. */
#ifndef D2KM_QUESTION_H
#define D2KM_QUESTION_H

#include "d2km_experiment.h"

typedef struct {
    d2km_action action;
    size_t prediction_count;
    d2km_prediction predictions[D2KM_HYPOTHESES_MAX];
    uint32_t packets;   /* сколько пакетов пошлёт опыт */
} d2km_question;

/* Зависит ли действие или число программы от выбора между h1 и h2.
 * Решает синтез (§7.5); NULL — зависит всегда. */
typedef int (*d2km_matters_fn)(void *ctx, d2km_hypothesis h1, d2km_hypothesis h2);

/* Вес кандидата по живым гипотезам live[0..nlive). Гипотезы кандидата вне
 * живых не считаются. */
size_t d2km_question_weight(const d2km_question *, const d2km_hypothesis *live,
                            size_t nlive, d2km_matters_fn, void *ctx);

/* Индекс выбранного кандидата или -1, если задавать нечего (тогда
 * MODEL_INCOMPLETE, §6.6). answered[0..nanswered) — воздействия, на
 * которые в этом контексте уже есть устойчивый исход. */
long d2km_question_select(const d2km_question *, size_t n,
                          const d2km_hypothesis *live, size_t nlive,
                          const d2km_action *answered, size_t nanswered,
                          d2km_matters_fn, void *ctx);

/* §6.5, поиск монотонного параметра: удвоение от наименьшего значения до
 * первой смены исхода, затем деление пополам между последним значением без
 * смены и первым со сменой, до соседних значений. */
typedef enum {
    D2KM_SEARCH_PROBE_MIN = 1,   /* нужен исход при наименьшем значении */
    D2KM_SEARCH_DOUBLING,
    D2KM_SEARCH_BISECT,
    D2KM_SEARCH_BOUNDARY,        /* найдена граница: lo без смены, hi со сменой */
    D2KM_SEARCH_EXHAUSTED        /* диапазон грамматики пройден без смены */
} d2km_search_phase;

typedef struct {
    int64_t min, max, resolution;
    d2km_search_phase phase;
    d2km_result base;            /* исход при min */
    int64_t lo, hi;              /* lo — последний без смены, hi — первый со сменой */
    d2km_result at_hi;
    int64_t pending;             /* значение, которое сейчас проверяется */
} d2km_search;

/* min < max, resolution > 0. 0 — успех, -1 — ошибка. */
int d2km_search_init(d2km_search *, int64_t min, int64_t max, int64_t resolution);
/* Следующее значение для проверки; 0 — поиск окончен (см. phase). */
int d2km_search_next(d2km_search *, int64_t *value);
/* Устойчивый исход (по правилу повтора) для значения из next. 0 — принят,
 * -1 — не то значение или исход не о сети (поиск не меняется). */
int d2km_search_feed(d2km_search *, int64_t value, d2km_result);

/* §6.5, немонотонный параметр (позиция разреза): проверяются только
 * позиции, различающие гипотезы, — границы полей сообщения по грамматике.
 * Возвращает число различных позиций в (0, length), упорядоченных по
 * возрастанию; пишет не больше cap. */
size_t d2km_split_positions(const uint32_t *field_bounds, size_t n,
                            uint32_t length, uint32_t *out, size_t cap);

#endif
