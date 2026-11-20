/* Запись «почему» и её журнал (D2K_SPEC.md §12).
 *
 * Одна запись — одна строка JSON. Записи только добавляются. Журнал
 * ограничен по размеру: при переполнении вытесняются самые старые записи
 * (записи, на которые опирается знание, знание хранит у себя, §10.1).
 * Журнал переживает перезапуск: номер следующей записи восстанавливается
 * из файла. */
#ifndef D2KM_WHY_H
#define D2KM_WHY_H

#include "d2km_experiment.h"

/* §4.1, шаги пути. */
typedef enum {
    D2KM_STEP_SUSPECT = 1,
    D2KM_STEP_DIRECT,
    D2KM_STEP_OWN,
    D2KM_STEP_QUESTION,
    D2KM_STEP_EXPERIMENT,
    D2KM_STEP_SYNTH,
    D2KM_STEP_TRIAL,
    D2KM_STEP_CHECK,
    D2KM_STEP_KNOWLEDGE,
    D2KM_STEP_WATCH,
    D2KM_STEP_END
} d2km_step;

const char *d2km_step_name(d2km_step);

typedef struct {
    uint64_t time_ms;                    /* время записи, мс Unix */
    const d2km_context *task;            /* цель и контекст; обязателен */
    d2km_step step;
    const d2km_experiment *experiment;   /* опыт, если есть */
    const char *observations;            /* кратко + ссылка на квитанцию */
    const uint32_t *facts;               /* F<n>, появившиеся или понижённые */
    size_t fact_count;
    const char *const *derivation;       /* §7.4: по строке на действие/число */
    size_t derivation_count;
    d2km_outcome outcome;                /* 0 — кода итога нет */
    const char *reason;                  /* обязательна, простыми словами */
    const uint64_t *links;               /* W<n>, на которые опирается */
    size_t link_count;
} d2km_why;

typedef enum {
    D2KM_WHY_OK = 0,
    D2KM_WHY_NO_TASK,
    D2KM_WHY_BAD_STEP,
    D2KM_WHY_NO_REASON,
    D2KM_WHY_BAD_OUTCOME,
    D2KM_WHY_NO_DERIVATION   /* кандидат без происхождения действий (§7.4) */
} d2km_why_check_code;

d2km_why_check_code d2km_why_check(const d2km_why *);

/* Строка JSON с переводом строки в конце. Возвращает нужную длину без
 * завершающего нуля; пишет не больше cap байт и завершает нулём, если
 * хватает места. id — номер записи W<id>. */
size_t d2km_why_format(const d2km_why *, uint64_t id, char *out, size_t cap);

typedef struct {
    int fd;
    char path[256];
    uint64_t next_id;
    uint64_t size;
    uint64_t limit;   /* предел размера файла в байтах */
} d2km_journal;

/* Открывает или создаёт журнал. limit — предел размера (не меньше 4 КиБ).
 * 0 — успех, -1 — ошибка (errno сохраняется). */
int d2km_journal_open(d2km_journal *, const char *path, uint64_t limit);
/* Проверяет и добавляет запись, назначает ей номер. При переполнении
 * сначала вытесняет старые записи: остаются самые новые, суммарно не больше
 * половины предела. Возвращает D2KM_WHY_OK, код проверки или -1 при ошибке
 * файла. */
int d2km_journal_append(d2km_journal *, const d2km_why *, uint64_t *id);
void d2km_journal_close(d2km_journal *);

#endif
