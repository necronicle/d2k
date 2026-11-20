/* d2k_httpsearch.h — поиск обхода открытого HTTP (задача 51, шаг 4).
 *
 * ОСНОВАНИЕ — ЗАМЕР. Поле 03.10.2026 (ER-Telecom): на `GET /` с Host
 * заблокированного имени коробка через 0,7 мс (при RTT ~98 мс) вставляет
 * `302 Location: http://lawfilter.ertelecom.ru` + FIN, настоящий сервер не
 * отвечает. Датапат узнаёт эту вставку (http80.c). Если у имени HTTPS нет
 * (класс 3: портал проходит как есть, d2k_httpsprobe.h), вставка — подозрение
 * для поиска обхода самого HTTP-запроса. Прямой рабочий трафик поиска не
 * запускает: только узнанная вставка.
 *
 * ВОПРОСЫ К КОРОБКЕ — короткий ряд, каждый со своим смыслом:
 *   0. база: тот же запрос нашим зондом без плана. Вставки нет — блокировка
 *      с роутера не воспроизводится, искать нечего (подозрение не равно
 *      блокировке). Ответ не вставкой (тишина, сброс) — это другая коробка,
 *      к ней эти вопросы не относятся;
 *   1. «split»: Host разрезан посередине на два сегмента TCP. Коробка,
 *      читающая Host в одном сегменте, его не увидит;
 *   2. «disorder»: тот же разрез, хвост первым. Коробка, склеивающая
 *      сегменты только по порядку прихода, склеит не то;
 *   3. «fake-badsum»: перед разрезом — запрос-приманка (Host disk.rzd.ru,
 *      приманка TLS-поиска) с испорченной суммой TCP: сервер её отбросит,
 *      коробка, не проверяющая сумму, решит по ней;
 *   4. «fake-seqshift»: та же приманка с номером вне окна (−66000, как у
 *      TLS-поиска): сервер её отбросит как старую, коробка без учёта номеров
 *      — нет.
 *   Мутации заголовка (регистр «Host», пробелы) не задаются: они меняют
 *   байты, которые получит сервер, и нужны только коробке, для которой
 *   измерено чтение строки буквально, — такой замер пока не нужен ни одной
 *   встреченной коробке. Порчу TTL не задаём: расстояние до коробки не
 *   измерено.
 *   Сначала — свои уже подтверждённые планы других имён (той же линии):
 *   «для совместимой коробки сначала проверять уже найденное решение».
 *
 * ИСПЫТАНИЕ — своим HTTP-зондом через датапат: пробный план ставится на
 * местный порт зонда (SET_NAME_PROBE, форма HTTP, trial ID), зонд шлёт
 * `GET / HTTP/1.1` с Host. Успех — НАСТОЯЩИЙ ОТВЕТ СЕРВЕРА по тому же
 * правилу, что у датапата: строка статуса HTTP, не 30x на хост портала и не
 * раньше половины RTT соединения зонда. Плюс исполнение на проводе: событие
 * APPLIED каждого запроса с точными trial, plan, binding и потоком сокета.
 * Недостаток доказательства — кандидат не судим. Подтверждение — два опыта подряд, в каждом два полных ответа
 * на одной связи keep-alive, затем
 * постоянный план имени (SET_NAME, форма HTTP), если этот кандидат не имеет
 * связанного живого отказа в текущей жизни контроллера. Такой отказ не
 * стирается успешным зондом: поиск продолжает следующие вопросы. Пока
 * привязка охватывает имя целиком, другой IP не сужает область установки.
 *
 * Модуль переносим и не делает ввода-вывода сам: всё через d2k_hs_ops, а
 * сам зонд (d2k_hs_probe_run) — отдельной функцией для рабочего потока.
 */
#ifndef D2K_HTTPSEARCH_H
#define D2K_HTTPSEARCH_H
#define D2K_HS_KEEPALIVE_PROOF 1

#include <stddef.h>
#include <stdint.h>
#include "d2k_plans.h"
#include "d2k_link.h"

typedef enum {
    D2K_HS_NONE = 0,
    D2K_HS_REAL,          /* ответ сервера */
    D2K_HS_INJECTED,      /* 30x на хост портала — вставка */
    D2K_HS_EARLY,         /* ответ без портала, но раньше RTT/2 — не сервер */
    D2K_HS_GARBAGE,       /* пришли байты, но не ответ HTTP */
    D2K_HS_SILENT,        /* ответа нет до срока */
    D2K_HS_RESET,         /* сброс */
    D2K_HS_CLOSED,        /* закрытие без ответа */
    D2K_HS_CONNECT_FAIL,  /* соединение не установилось */
    D2K_HS_DECOY          /* ответ на приманку: имя приманки в ответе или
                             400/421 — сервер получил склейку приманки с
                             запросом, а не запрос цели */,
    D2K_HS_CUT            /* обрыв: заголовки ответа сервера пришли, тело
                             оборвалось раньше заявленной длины (поле 15.10.2026,
                             media5.cdnbase.com: 33120 из 106050 байт) */
} d2k_hs_answer;

const char *d2k_hs_answer_name(d2k_hs_answer a);

/* Суждение об ответе: head — первые байты ответа, rtt_us — установление
 * соединения зонда, reply_us — от отправки запроса до первого байта. */
d2k_hs_answer d2k_hs_judge(const char *host, const char *head, size_t n,
                           int64_t rtt_us, int64_t reply_us);

/* --- зонд ------------------------------------------------------------------ */
typedef struct {
    uint32_t seq;         /* номер запуска: ответ относится только к нему */
    int fd;               /* уже созданный и привязанный сокет (метка зондов) */
    uint8_t family;
    uint8_t addr[16];
    char host[256];
    char repeat_path[1024]; /* empty only for generic initial GET / experience */
    int cut;                /* поиск по обрыву ответа: первый запрос — тоже repeat_path */
} d2k_hs_job;

typedef struct {
    d2k_hs_answer answer;
    int64_t rtt_us, reply_us;
    char status[64];      /* строка статуса, если была */
    char why[160];
    uint32_t seq;         /* номер запуска (из d2k_hs_job) */
    unsigned complete_responses; /* fully framed replies on this connection */
    unsigned requests_sent;
    /* The server itself ended the connection after a complete response with
       explicit framing (Content-Length, chunked or bodiless status) and an
       announced close ("Connection: close", or HTTP/1.0 without keep-alive).
       A second request is impossible by protocol, not refused by the path.
       Close-delimited bodies never set it: a FIN cannot prove they are whole. */
    int server_closed;
    uint8_t local_ip[16]; /* actual connected socket, not a guessed interface */
    uint16_t local_port; /* host order */
    int fd;               /* его сокет: опоздавший ответ закрывает его */
} d2k_hs_result;

/* Порт и срок зонда; тесты подставляют свои. */
extern uint16_t d2k_hs_probe_port;
extern int d2k_hs_probe_ms;
/* Блокирующий зонд: connect, два GET / с Host на одной связи; полное HTTP framing.
 * REAL сохраняет смысл ответа; complete_responses отдельно доказывает повтор, а
 * server_closed — что второго запроса не было по объявлению самого сервера. Сокет
 * НЕ закрывает: им владеет поиск (close_port после ответа). */
void d2k_hs_probe_run(const d2k_hs_job *job, d2k_hs_result *r);

/* --- кандидаты -------------------------------------------------------------
 * Разрез ИМЕНИ ЗАГОЛОВКА («Ho» | «st:») не задаётся: разрез посреди значения
 * Host уже не даёт ни одному сегменту целого имени, а разрез имени заголовка
 * отличается от него только для коробки, которая, не найдя Host вовсе,
 * блокирует соединение целиком. Такой коробки не измерено ни одной — вопрос
 * был бы лишним зондом.
 * Порча приманки — ИЗМЕРЕННАЯ, если есть: d2k_httpsearch_measured_poison
 * (порча подтверждённых TLS-планов коробок этой линии из каталога). Нет
 * измеренной — заготовки «fake-badsum» и «fake-seqshift» (те же порчи, что
 * задаёт TLS-поиск), и это гипотезы, а не замер. Ключ измеренной —
 * «fake:<порча через +>», например «fake:ttl=5+badsum». */
size_t d2k_hs_candidate_count(void);
const char *d2k_hs_candidate_key(size_t i);
/* Текст плана кандидата (d2k_plantlv) с идентификатором id. 0 — собран. */
int d2k_hs_candidate_text(const char *key, const uint8_t id[16], char *buf, size_t cap);

/* --- поиск ----------------------------------------------------------------- */
typedef struct {
    /* Сокет зонда: метка зондов, привязан к местному порту. 0 — готов. */
    int  (*open_port)(void *ctx, uint8_t family, int *fd, uint16_t *sport_be);
    void (*close_port)(void *ctx, int fd);
    int  (*set_probe)(void *ctx, const char *host, uint8_t family, uint16_t sport_be,
                      const char *plan_text, const uint8_t trial_id[16]);
    int  (*del_probe)(void *ctx, const char *host, uint8_t family, uint16_t sport_be);
    int  (*set_plan)(void *ctx, const char *host, uint8_t family, const char *plan_text, const uint8_t install_id[16]);
    int  (*del_plan)(void *ctx, const char *host, uint8_t family, const d2k_binding_context *);
    /* Запустить зонд; ответ — d2k_httpsearch_result. 0 — запущен. */
    int  (*start_probe)(void *ctx, const d2k_hs_job *job);
    void (*say)(void *ctx, const char *line);
    /* Подтверждённые планы изменились — сохранить. */
    void (*changed)(void *ctx);
    void *ctx;
} d2k_hs_ops;

#include "d2k_diagnostics.h"
typedef struct d2k_httpsearch d2k_httpsearch;
void d2k_httpsearch_diagnostic_counts(d2k_httpsearch *,d2k_diag_counts *);
void d2k_httpsearch_diagnostics(d2k_httpsearch *,d2k_diag_observer,void *);

d2k_httpsearch *d2k_httpsearch_new(const d2k_hs_ops *ops);
void d2k_httpsearch_free(d2k_httpsearch *hs);
/* Порча приманки, измеренная на этой линии (строка признаков плана: «badsum»,
 * «ttl=N», «seqshift=N»; прочие — tcpts, ipidzero — HTTP-исполнитель без
 * шаблона потока не повторит, такая строка не принимается). ttl — только
 * вместе с badsum или seqshift: одна ttl подобрана под TLS-сервер и может
 * довести приманку до более близкого HTTP-сервера, а тот примет её как
 * запрос (повторное ревью I-A). 0 — принята. */
int d2k_httpsearch_measured_poison(d2k_httpsearch *hs, const char *spec);
/* Признаки порчи приманок из текста плана (строки «poison N …», на которые
 * ссылается «fake … poison=N»). Сколько записано в out. */
size_t d2k_hs_plan_poisons(const char *plan_text, char out[][64], size_t cap);

/* Вставка провайдера по host на адресе addr, HTTPS имени — класс 3. Ставит
 * поиск в очередь (или перепроверку, если план уже подтверждён — тогда
 * вставка значит, что он перестал работать). Повтор по имени — не чаще
 * D2K_HS_RETRY_MS после неудачи и D2K_HS_RECHECK_MS после перепроверки. */
#define D2K_HS_RETRY_MS   (60ll * 60 * 1000)
#define D2K_HS_RECHECK_MS (10ll * 60 * 1000)
/* Поиск, в котором ни один кандидат не судим (нет исполнения, отказ
 * датапата, нет подтверждения), — не измерен: план не снимается, «обход не
 * найден» не говорится, повтор — через этот срок (ревью I-2). */
/* ПОВТОРОВ БАЗЫ ПОСЛЕ МЕСТНОГО ОТКАЗА СОЕДИНЕНИЯ. Поле 23.10.2026: один
 * неустановившийся сокет нашего зонда закрывал цель с настоящим обрывом на
 * 10 минут. Один повтор — не бюджет, а отличение нашего сбоя от ответа
 * коробки: о коробке местный отказ не говорит ничего (§2.4). */
#define D2K_HS_BASE_RETRIES 1

#define D2K_HS_INCONCLUSIVE_MS (5ll * 60 * 1000)
/* Requires the current ACKed permanent binding and a completed request execution.
 * Unknown/stale identity is ignored; plan hash and timestamps alone are not proof. */
int d2k_httpsearch_bound_failure(d2k_httpsearch *hs, const char *host, uint8_t family,
                                const uint8_t *addr, const uint8_t plan_id[16], const d2k_binding_context *, uint64_t execution_id, int64_t request_ms, const char *path, int64_t now_ms);
/* Обрыв ответа без портала (код 4 HTTP_RESPONSE): поиск на пути ресурса. */
void d2k_httpsearch_cut(d2k_httpsearch *hs, const char *host, uint8_t family,
                        const uint8_t *addr, const char *path, uint64_t got, int64_t now);
void d2k_httpsearch_portal(d2k_httpsearch *hs, const char *host, uint8_t family,
                           const uint8_t *addr, int64_t now_ms);
int d2k_httpsearch_control(d2k_httpsearch *, const d2k_ev *, int64_t now_ms);
void d2k_httpsearch_install_ack(d2k_httpsearch *, const uint8_t install_id[16], int ok, const d2k_binding_context *);
/* Подтверждение SET_NAME_PROBE (trial ID и признак успеха). */
void d2k_httpsearch_ack(d2k_httpsearch *hs, const uint8_t trial_id[16], int ok, int64_t now_ms);
/* Exact trial/flow/binding execution, deduplicated by execution ID. */
int d2k_httpsearch_applied(d2k_httpsearch *hs, const d2k_ev *event);
/* Ответ зонда. */
void d2k_httpsearch_result(d2k_httpsearch *hs, const d2k_hs_result *r, int64_t now_ms);
/* Сроки: подтверждения, ответа, события APPLIED. */
void d2k_httpsearch_tick(d2k_httpsearch *hs, int64_t now_ms);
/* Идёт ли сейчас поиск (для тестов и журнала). */
int d2k_httpsearch_busy(const d2k_httpsearch *hs);
/* Подтверждённый кандидат имени или NULL. */
const char *d2k_httpsearch_plan_of(const d2k_httpsearch *hs, const char *host, uint8_t family);

/* Подтверждённые планы на диске: «d2k-http-plans 1», затем
 * «<имя> <семейство> <кандидат> <когда, unix>». Пишется атомарно. load
 * ставит каждый план датапату (set_plan); неизвестный кандидат и негодные
 * строки пропускаются; 0 — нет файла или прочитан, -1 — файл не наш. */
int d2k_httpsearch_save(d2k_httpsearch *hs, const char *path, int64_t wall_s,
                        char *err, size_t cap);
int d2k_httpsearch_load(d2k_httpsearch *hs, const char *path, size_t *n_loaded,
                        char *err, size_t cap);
/* Поставить все подтверждённые планы заново (переподключение датапата). */
void d2k_httpsearch_push_all(d2k_httpsearch *hs);

/* --- рабочий поток зонда (для d2kc) ----------------------------------------- */
typedef struct d2k_hs_runner d2k_hs_runner;
d2k_hs_runner *d2k_hs_runner_new(void);
void d2k_hs_runner_free(d2k_hs_runner *r);
int d2k_hs_runner_wake_fd(const d2k_hs_runner *r);
/* 0 — запущен; -1 — уже идёт другой. */
int d2k_hs_runner_start(d2k_hs_runner *r, const d2k_hs_job *job);
/* 1 — ответ готов и выдан. */
int d2k_hs_runner_done(d2k_hs_runner *r, d2k_hs_result *out);

#endif /* D2K_HTTPSEARCH_H */
