/* Ведущий задачи TLS: путь цели §4.1 от прямого контроля до знания.
 *
 * Прямой контроль (§4.3) → своё знание (§10.3) → вопросы по весу (§6.3) → устойчивые исходы
 * плеч (§5.2) → факты в модели коробки (§5) → поиск хопов (§6.5) → синтез
 * (§7) → испытание (§8.1) → знание или контрпример. Каждый шаг пишет
 * запись «почему» (§12), если журнал задан. Сеть — через d2km_net: роутер
 * или модель коробки в тестах. */
#ifndef D2KM_TASK_H
#define D2KM_TASK_H

#include "d2km_net.h"
#include "d2km_question.h"
#include "d2km_synth.h"
#include "d2km_why.h"
#include "d2km_store.h"

/* §5.2: локальных ошибок подряд, после которых плечо — LOCAL_FAIL. */
#define D2KM_LOCAL_FAILS_MAX 3

typedef struct {
    const d2km_net *net;
    d2km_box *box;                 /* рабочая модель цели, отдельно от boxes.entries */
    d2km_knowledge_set *knowledge; /* NULL — своё знание не подключено */
    d2km_box_set *boxes;           /* NULL — только рабочая box */
    d2km_journal *journal;          /* NULL — без журнала */
    const d2km_context *context;
    const uint8_t *hello;           /* приветствие клиента */
    size_t hello_length;
    const char *pass_name;          /* кандидат имени (§3.3/§11.4); пропуск доказывает опыт */
    /* §4.3 п. 2: чистый обмен с тем же адресом за последний час (из событий
       датапата). NULL — нет. Строка — почему, для записи «почему». */
    const char *alive_history;
    const char *application_proof; /* optional application contract, archived after trial success */
    /* A client signal identifies one installed K/content. Recheck this exact
       program before DIRECT; zero preserves the ordinary target path. */
    int (*knowledge_changed)(void *); /* durable sole-writer checkpoint before DIRECT */
    void *knowledge_changed_ctx;
    uint32_t degradation_knowledge;
    uint64_t degradation_hash;
    uint64_t seed;
    size_t max_payload;             /* предел посылки исполнителя для фальшивки; 0 — не объявлен */
    /* §7.1 п. 5: сколько посылок исполнитель делает за одно исполнение
       плана (фальшивки и куски вместе). План сверх этого исполнитель
       отвергает целиком, и вопрос о нём ответа о коробке не даёт. 0 — не
       объявлено (тогда предел — язык плана, 255). */
    size_t max_sends;
    /* Optional shared namespaces, accessed only by the catalog owner lock.
       In-flight tasks must not reuse IDs absent from the persisted catalog. */
    uint32_t *shared_experiment,*shared_fact;
    uint32_t next_experiment;       /* следующий E<n> */
    uint32_t next_fact;             /* следующий F<n> */
} d2km_tls_task;

typedef struct {
    d2km_outcome outcome;
    d2km_task_state state;          /* конечное состояние по §4.6 */
    d2km_program program;           /* при APPLIED — применённая программа */
    d2km_program candidate;         /* последний синтезированный кандидат */
    int has_candidate;
    int from_own;                  /* OWN_OK: программа взята из своего знания */
    uint32_t knowledge_id, box_id;
    uint32_t questions;            /* вопросы после OWN; не контроль живости */
    uint32_t experiments;           /* сколько опытов (групп прогонов) */
    uint32_t runs;                  /* сколько прогонов плеч */
    char reason[300];
} d2km_task_report;

d2km_outcome d2km_tls_task_run(d2km_tls_task *, d2km_task_report *);

#endif
