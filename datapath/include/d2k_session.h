/* d2k_session.h — склейка: пакет на входе, действия на выходе.
 *
 * Здесь и только здесь сходятся все модули датапата: учёт потоков, разбор
 * протокола, исполнитель плана и сборка на провод. Каждый из них по отдельности
 * не знает об остальных, и это намеренно — иначе протокольный модуль начал бы
 * принимать решения, а исполнитель разбирать заголовки.
 *
 * Модуль решает, КОГДА применять план, и это отдельный вопрос от того, ЧТО
 * план делает. План описывает обработку начала соединения, а не каждого
 * пакета: применить его дважды значит послать фальшивку в середину потока, где
 * она уже ничего не значит, а вреда наделает.
 */
#ifndef D2K_SESSION_H
#define D2K_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_journal.h"
#include "d2k_plan.h"
#include "d2k_plans.h"
#include "d2k_track.h"
#include "d2k_wire.h"
#include "d2k_ctq.h"
#include "d2k_preflight.h"
#include "d2k_preflight_lease.h"

/* Что делать с пакетом, который нам дали. */
typedef enum {
    /* Пропустить как есть. Самый частый исход и умолчание при любых
       сомнениях: не понял — не трогай. */
    D2K_VERDICT_ACCEPT = 0,
    /* Снять оригинал: его байты мы выпустили сами. */
    D2K_VERDICT_DROP = 1
} d2k_verdict;

/* Сколько посылок плана вмещает результат.
 *
 * Измеренный TCP-путь: вход до 2048, приманка 2*2048, сегменты по 1400,
 * до семи повторов. Фальшивки дают 7*ceil(4096/1400)=21 посылку.
 * Правда + перекрытие занимают до 4096 байт и до трёх логических частей:
 * ceil(4096/1400)+2=5 посылок — безопасная верхняя оценка. Итого 26.
 * Старые 17 не вмещали длинные фальшивки после восстановления сегментации.
 *
 * Потолок нужен и после этого: repeats приходит из TLV одним байтом без
 * ограничения (до 255), и план, пришедший не от нашего составителя, обязан
 * получить отказ, а не обрезанное исполнение.
 *
 * d2kd.c выделяет OUT_BUF = D2K_RESULT_MAX * MAX_PKT. */
#define D2K_RESULT_MAX D2K_WIRE_BATCH_MAX

typedef struct {
    d2k_verdict verdict;
    uint64_t execution_id;
    uint32_t replay_tls_bytes; /* complete cached input used for a TCP retry */
    d2k_binding_context binding;

    /* Готовые пакеты на отправку, по одному на посылку. Буфер принадлежит
       вызывающему и передаётся снаружи: датапат не выделяет память на
       пакетном пути. */
    size_t n_out;
    struct {
        uint32_t delay_us;
        size_t   off;   /* смещение в общем буфере */
        size_t   len;
    } out[D2K_RESULT_MAX];

    /* Почему план не применён. Пустая строка означает, что применён. Причина
       нужна журналу: «план не сработал» и «план не применялся» — разные
       факты, и путать их нельзя. */
    const char *skipped;

    /* КЛЮЧ ПОТОКА И ИДЕНТИФИКАТОР ПЛАНА, ДОВЕДЁННЫЕ ДО ТОЧКИ ОТПРАВКИ.
     *
     * Без них отправляющий (d2kd.c) знает только байты: чей это пакет и от
     * какого плана — неизвестно, и отказ sendto оставался голым счётчиком.
     * Отсюда и брался разрыв, ради которого эти поля заведены: на живой пробе
     * 12.09.2026 «sendto: Message too large» шло одновременно с ростом «план
     * применён», и отрицательный исход был неотличим от неотправленного
     * зонда (docs/decisions/0006-proof-boundaries.md).
     *
     * applied == 1 означает: план ПОДГОТОВЛЕН, и out[0..n_out) — ЕГО посылки,
     * судьбу которых обязан сообщить обратно тот, кто их отправляет
     * (d2k_session_sent/d2k_session_unsent ниже). При applied == 0 key и
     * plan_id нулевые и значения не несут. */
    int      applied;
    d2k_key  key;
    uint8_t  plan_id[D2K_PLAN_ID_LEN];
    uint8_t  trial_id[D2K_TRIAL_ID_LEN];
    /* Номер ПЕРВОЙ посылки нагрузки в out[], либо 0xFF — нагрузки в плане
     * нет (только фальшивки перед оригиналом).
     *
     * Нужен отправляющему, чтобы отличить два вида неудачи посреди плана.
     * Пока ушли одни фальшивки, оригинал цел и его можно отпустить: коробка
     * увидела лишнее, но поток клиента не разорван. Как только ушёл хоть один
     * кусок НАГРУЗКИ, чистого выхода нет — отпустить оригинал значит послать
     * те же байты дважды, не отпустить значит потерять остаток; поток
     * испорчен, и утверждать, что трафик остался нетронутым, нельзя
     * (§4.1, docs/decisions/0009 U3). */
    uint8_t  first_payload;
    uint8_t  udp_hold_wait;
    uint8_t  udp_hold_ready;
    /* Датаграмма снята quicdeny (задача 50, раунд 2): QUIC для имени не
       пропускается. Удержанная пачка снимается целиком, хвосты не
       переотправляются. */
    uint8_t  quic_deny;
    /* ДЛЯ ЖУРНАЛА РЕШЕНИЙ ПО КЛИЕНТСКОМУ ПОТОКУ: имя потока и признак «имя в
       таблице есть, но плана этой формы у него нет». Заведено для QUIC (поле
       15.10.2026), с 24.10.2026 заполняется и на TCP: по журналу нельзя было
       ответить, видел ли датапат поток браузера и почему не применил план
       (issue 25 и 28). */
    char     flow_name[64];
    uint8_t  shape_miss;
    /* Task 47: the first packet of a flow whose client carries a routing mark
       (d2k_session_set_route_mark) — the caller logs it once per flow. */
    uint8_t  routed_first;
    uint32_t routed_mark;
    /* Отложенная UDP-непрерывность (задача 63, сессионная часть). Свежий
       UDP-поток с планом фрагментации на ПЕРВОМ оригинале исполнить нельзя:
       внешний кортеж ещё не подтверждён. План НЕ ПРИМЕНЁН; датаграмма —
       КАНДИДАТ, который демон вправе взять во владение (postnat_own) и позже
       продолжить через d2k_session_udp_continue. Поэтому udp_defer_pending == 1
       значит «кандидат пригоден к владению», НЕ «уже во владении/применён».
       Привязка держится не по хешу плана: установочное поколение + эпоха
       таблицы + вид (d2k_binding_context) ПЛЮС эпоха/инкарнация потока ПЛЮС
       полный кортеж — те же байты, переустановленные заново, это ДРУГАЯ
       привязка. */
    uint8_t  udp_defer_pending;
    d2k_key  udp_defer_key;
    uint8_t  udp_defer_plan_id[D2K_PLAN_ID_LEN];
    uint8_t  udp_defer_trial_id[D2K_TRIAL_ID_LEN];
    d2k_binding_context udp_defer_binding;
    uint8_t  udp_defer_epoch[16];
    uint64_t udp_defer_incarnation;
} d2k_result;



typedef struct d2k_session d2k_session;

/* Startup configuration only. Disabled by default; no FSM calls while off.
 * DROP means the caller must NF_DROP the current ID BEFORE sending out,
 * using its own marked raw socket, never hold it in NFQUEUE. */
void d2k_session_preflight_output_sent(d2k_session *, const uint8_t *, size_t, unsigned clear);
void d2k_session_preflight_send_cap(d2k_session *, size_t);
void d2k_session_preflight_complete(d2k_session *, const uint8_t *, size_t, uint64_t, d2k_pf_out *);
void d2k_session_preflight_complete_on(d2k_session *, const uint8_t *, size_t, uint64_t, d2k_pf_out *, uint32_t path);
int d2k_session_set_preflight(d2k_session *, int enabled);
int d2k_session_provider_ips_load(d2k_session *, const char *, uint64_t now_seconds);
void d2k_session_preflight_ipv6(d2k_session *, int enabled);
/* Interface context supplied by the daemon for each current packet. */
void d2k_session_set_packet_path(d2k_session *, uint32_t path);
int d2k_session_preflight_packet(d2k_session *, const uint8_t *, size_t,
                                  uint64_t, d2k_pf_out *);
int d2k_session_preflight_packet_path(d2k_session *,const uint8_t *,size_t,
                                  uint64_t,d2k_pf_out *,uint32_t path);
uint64_t d2k_session_preflight_next_ns(const d2k_session *);
void d2k_session_preflight_tick(d2k_session *, uint64_t, d2k_pf_out *);
void d2k_session_preflight_original_sent(d2k_session *, const uint8_t *, size_t, uint64_t);
void d2k_session_preflight_flush(d2k_session *, uint64_t, d2k_pf_out *);
void d2k_session_preflight_abort(d2k_session *, const uint8_t *, size_t, uint64_t, d2k_pf_out *);
uint64_t d2k_session_preflight_calls(const d2k_session *);
int d2k_session_set_preflight_lease(d2k_session *,const d2k_pf_scope *,uint64_t,
    uint64_t,const uint8_t [16],d2k_plan *);
int d2k_session_del_preflight_lease(d2k_session *,const d2k_pf_scope *,const uint8_t [16]);
void d2k_session_invalidate_preflight_lease(d2k_session *,const d2k_pf_scope *);
const d2k_plan *d2k_session_find_preflight_lease(d2k_session *,const d2k_pf_scope *,uint64_t);
const d2k_binding_context *d2k_session_preflight_lease_binding(d2k_session *,const d2k_plan *);

uint64_t d2k_session_plan_revision(const d2k_session *s);
/* НОМЕР КРЮЧКА NETFILTER ДЛЯ СЛЕДУЮЩЕГО ПАКЕТА.
 *
 * ЗАЧЕМ. Направление пакета (клиент->сервер или обратно) датапат до сих пор
 * выводил ИЗ ПОРТА: «назначение 443, источник не 443 — клиентская сторона».
 * Приём верен ровно настолько, насколько весь периметр привязан к 443, и в
 * session.c это записано прямо, вместе с правильным ответом на будущее: когда
 * дойдёт до произвольных портов, порт перестаёт быть уликой, а улика —
 * НОМЕР КРЮЧКА из NFQA_PACKET_HDR. Очередь на OUTPUT или POSTROUTING значит
 * исходящее, на INPUT, PREROUTING или FORWARD — входящее.
 *
 * Провод его уже разбирает (d2k_nl_pkt.hook), и дело было только в том, чтобы
 * донести. Отдельным вызовом, а не параметром d2k_session_packet: у того
 * подпись прошла не одно ревью и зовут её из десятка тестов, а крючок нужен
 * ровно одному месту.
 *
 * D2K_HOOK_UNKNOWN (умолчание) — вернуться к прежнему выводу по порту. Это не
 * заглушка на будущее, а поведение для всех, кто крючка не знает: тесты,
 * лаборатория planlab, старые вызывающие. */
#define D2K_HOOK_UNKNOWN     0xff
#define D2K_HOOK_PREROUTING  0
#define D2K_HOOK_INPUT       1
#define D2K_HOOK_FORWARD     2
#define D2K_HOOK_OUTPUT      3
#define D2K_HOOK_POSTROUTING 4

/* СОСТАВНОЕ ПРИВЕТСТВИЕ ОТПУЩЕНО БЕЗ СБОРКИ.
 *
 * Пишет запись журнала по ключу ЭТОГО потока. Нужна затем, что общий счётчик
 * («составной вход: начато=N собрано=M») не говорит, ЧЕЙ поток пострадал, а
 * последствие тяжёлое: план к отпущенным пакетам не применяется, причины
 * пропуска не записывается, и в журнале от потока остаётся одно «приветствие».
 * Поле 17.09.2026 — именно так терялся зонд подтверждения, и отличить это от
 * «плана не нашлось» было нечем.
 *
 * Не чаще одного раза на поток: отпускается несколько пакетов, а событие про
 * них одно. */
void d2k_session_note_unassembled(d2k_session *s, const uint8_t *p, size_t n,
                                  uint64_t now_ns);

/* НАЧАЛО ПОТОКА, КОТОРОМУ ПРИНАДЛЕЖИТ ЭТОТ ПАКЕТ (номер сразу за SYN).
 *
 * 1 — известно и положено в *anchor, 0 — потока не видно или SYN не наблюдался.
 * Нужно удержанию и сборщику: с ним куски приветствия кладутся по смещению от
 * начала, и порядок прихода перестаёт значить что-либо. Догадка по первому
 * байту (0x16) для этого не годится — см. d2k_capture_feed. */
int d2k_session_stream_anchor(d2k_session *s, const uint8_t *p, size_t n,
                              uint32_t *anchor);

void d2k_session_set_hook(d2k_session *s, uint8_t hook);
/* КЛИЕНТ С МЕТКОЙ МАРШРУТИЗАЦИИ (задача 47). Ненулевое значение для ТЕКУЩЕГО
 * пакета: его nfmark выбирает маршрут по политике (Keenetic 0xffffaaa ->
 * таблица 4096, VPN), а сырые посылки d2k идут со своей меткой мимо этой
 * таблицы. Такой поток (и его ответы) идёт ядром: ни плана, ни удержания, ни
 * наблюдения — его поведение принадлежит чужому пути. Собственные метки d2k
 * (зонды контроллера) вызывающий сюда не передаёт. */
void d2k_session_set_route_mark(d2k_session *s, uint32_t mark);
uint32_t d2k_session_route_mark(const d2k_session *s);
uint64_t d2k_session_routed_flows(const d2k_session *s);
/* Явное подтверждение конфигурации: правило обратного направления UDP
   установлено. Нужен для распознавания полной тишины на заблокированном QUIC,
   где обратный пакет физически не может прийти. По умолчанию выключено. */
void d2k_session_set_udp_reverse_hook(d2k_session *s, int installed);
/* Счётчики пакетов потока у conntrack по прямому кортежу и состояние TCP:
   0 — out заполнен, иначе «не знаем». Обязана не ждать (d2k_ctq.h). d2kd
   ставит ctnetlink; NULL — детекторы «QUIC замолчал» и «TCP встал на
   бюджете» выключены. */
typedef int (*d2k_ct_query_fn)(void *ctx, const d2k_ct_tuple *t, d2k_ct_info *out);
void d2k_session_set_ct_query(d2k_session *s, d2k_ct_query_fn fn, void *ctx);
/* УЖЕ СУЩЕСТВУЮЩИЙ ПОТОК (этап 13): запись из таблицы conntrack на старте
 * службы — прямой кортеж (клиент → сервер) и счётчики на момент приёма.
 * Приветствия у такого потока не было: ни имени, ни формы, ни плана; поток
 * только наблюдается счётчиками (d2k_session_sweep): ответы сервера идут —
 * жив; сервер перестал отвечать, а клиент упорствует — подозрение SILENT
 * формы RAW, planned=NO. Поток, который сервер никогда не слышал, подозрения
 * не даёт (нет пути, который мог бы сломаться). 0 — принят, -1 — нет места/
 * негодный кортеж. */
int d2k_session_adopt(d2k_session *s, const d2k_ct_tuple *t, const d2k_ct_info *i, uint64_t now_ns);
/* Бюджеты потока коробок для детектора «TCP встал на бюджете» (задача 56):
   n значений, не больше D2K_STALL_BUDGETS_MAX; n == 0 возвращает полевой
   D2K_TCP_STALL_FIELD_BUDGET. Нули и лишнее отбрасываются: 0 — успех,
   -1 — список негоден (ничего не поменялось). */
int d2k_session_set_stall_budgets(d2k_session *s, const uint16_t *b, size_t n);
/* Действующие бюджеты: сколько их, первые cap — в out. */
size_t d2k_session_stall_budgets(const d2k_session *s, uint16_t *out, size_t cap);

/* Начать/завершить внешнее удержание split QUIC. Begin вызывается до обработки
 * первой кандидатной датаграммы; payload никогда не склеивается здесь. */
int d2k_session_udp_hold_begin(d2k_session *s, const uint8_t *p, size_t n,
                               uint64_t now_ns, d2k_key *key_out);
void d2k_session_udp_hold_end(d2k_session *s, const d2k_key *key);
/* End a successful hold and preserve first-packet semantics for the immediate
 * replay of its original client datagram. */
void d2k_session_udp_hold_replay(d2k_session *s, const d2k_key *key);
/* 1 when this already-processed UDP datagram was the first client-side
 * datagram the session counted on its flow (task 46: it opens the conntrack
 * clash window for the datagrams queued behind it).  Direction as in the UDP
 * branch: the NFQUEUE hook, the flow's known initiator, the 443 fallback. */
int d2k_session_udp_opening(d2k_session *s, const uint8_t *p, size_t n);

int d2k_session_hold_candidate(d2k_session *s, const uint8_t *p, size_t n);
/* Accounting/capture for originals released without intervention. Never
 * applies a plan or emits an APPLIED event. TCP-only hold rollback path. */
void d2k_session_observe_tcp(d2k_session *s, const uint8_t *p, size_t n, uint64_t now);

/* Объявляет поток ИСПОРЧЕННЫМ: часть плана ушла на провод, остаток не ушёл.
 *
 * Отдельно от d2k_session_unsent, потому что это разные факты: там «посылка не
 * покинула машину», здесь «клиентский поток больше не тот, каким был». Второй
 * запрещает применять к этому потоку что-либо ещё. Устаревшее поколение
 * игнорируется, как и в остальных уведомлениях. */
void d2k_session_damaged(d2k_session *s, const d2k_key *k, uint64_t execution);

/* ОБЩИЙ ИСХОД ОТКАЗА ИСПОЛНЕНИЯ — один на все ветки отправляющего:
 * немедленная посылка, очередь, вердикт, созревшая отложенная.
 *
 * payload_on_wire — хоть один кусок НАГРУЗКИ уже покинул машину.
 * orig_spent — оригиналом уже распорядились (вердикт ушёл ядру).
 *
 * Возвращает 1, если оригинал ещё наш и обязан уйти нетронутым; 0 — чистого
 * выхода нет и поток объявлен испорченным. Подробности и обоснование — у
 * определения (session.c). */
/* Биты защиты, действующие на потоке (D2K_GUARD_* из d2k_plan.h), либо 0.
 * Наружу нужен ровно для проверок: защита — часть плана, и снимается вместе
 * с ним, когда поток объявлен испорченным. */
uint8_t d2k_session_guards(const d2k_session *s, const d2k_key *k);

/* Планы, ДОИСПОЛНЕННЫЕ целиком (все посылки ушли и вердикт принят ядром), и
 * потоки, объявленные испорченными. Разрыв между «подготовлен» и
 * «доисполнен» — первое, на что надо смотреть, когда подтверждений нет:
 * контроллер видит применение ТОЛЬКО из доисполнения. */
uint64_t d2k_session_done(const d2k_session *s);
uint64_t d2k_session_damaged_count(const d2k_session *s);
uint64_t d2k_session_sent_lost(const d2k_session *s);

int d2k_session_exec_failed(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                            const uint8_t *plan_id, uint8_t code,
                            uint64_t execution, int payload_on_wire, int orig_spent);

/* capacity — предел числа отслеживаемых потоков,
 * journal — глубина диагностического журнала в записях (0 — без журнала). */
d2k_session *d2k_session_new(size_t capacity, size_t journal);
void         d2k_session_free(d2k_session *s);

/* Таблица планов по целям — то, чем пользуется продукт. Владение остаётся у
 * сессии; вызывающий ставит и убирает записи через d2k_plantab_*. */
d2k_plantab *d2k_session_plans(d2k_session *s);

/* Счётчики таблицы планов для сводки. Отдельные функции, чтобы читателю
 * не приходилось снимать const с сессии: снятый const прячет ошибки
 * ровно там, где их труднее всего искать. */
size_t d2k_session_plan_count(const d2k_session *s);
size_t d2k_session_plan_capacity(const d2k_session *s);

/* Ставит ЗАПАСНОЙ план, применяемый ко всем целям без своего плана. Прежний план остаётся
 * действовать на уже обслуживаемых: §2.5 запрещает менять действия посреди
 * соединения. Владение планом переходит сессии. */
void d2k_session_set_plan(d2k_session *s, d2k_plan *p);

/* Обрабатывает один пакет. pkt — сырой IPv4-пакет целиком.
 * buf/bufcap — куда складывать готовые пакеты.
 * Возвращает 0 всегда: «не наш пакет» и «нечего делать» не ошибки. */
int d2k_session_packet(d2k_session *s, const uint8_t *pkt, size_t len,
                       uint64_t now_ns, uint8_t *buf, size_t bufcap,
                       d2k_result *out);
/* Вариант для отправителя, который уже знает безопасную длину TCP payload
 * по MTU маршрута. Ограничивает настоящие TCP-сегменты обычных операций;
 * URG обрабатывается отдельно. Фальшивки, UDP и явная IP-фрагментация
 * этим ограничением не меняются. */
int d2k_session_packet_mtu(d2k_session *s, const uint8_t *pkt, size_t len,
                           uint64_t now_ns, size_t tcp_segment_cap,
                           uint8_t *buf, size_t bufcap, d2k_result *out);

/* Controller-owned active probe packet. It is still parsed and may receive
 * its exact trial plan, but it must not become fresh user-traffic evidence
 * (HELLO/SUSPECT/EXCHANGE) or replace an observed client's shape snapshot. */
int d2k_session_packet_probe(d2k_session *s, const uint8_t *pkt, size_t len,
                             uint64_t now_ns, uint8_t *buf, size_t bufcap,
                             d2k_result *out);
int d2k_session_packet_probe_mtu(d2k_session *s, const uint8_t *pkt, size_t len,
                                 uint64_t now_ns, size_t tcp_segment_cap,
                                 uint8_t *buf, size_t bufcap, d2k_result *out);

/* Отложенная UDP-непрерывность (задача 63, сессионная часть). Демон, взяв во
 * владение первую датаграмму свежего UDP-потока (postnat_own) и подтвердив её
 * внешний кортеж, продолжает РОВНО ЭТУ датаграмму через существующий UDP-
 * исполнитель. Внутренний повтор НЕ считается клиентским пакетом: без счётчиков
 * fwd_pkts, без HELLO/SUSPECT, без расширения области измеряемой пробы.
 *
 * datagram/len — ОРИГИНАЛ ДО NAT (не пост-NAT копия захвата): на отказе
 * вызывающий повторно вводит именно эти байты — пост-NAT реинъекция меняет порт
 * (лаба Linux). mapping — подтверждённый ответный кортеж ядра (не голые поля):
 * проверяется против оригинала. Привязка валидируется ЦЕЛИКОМ — установочное
 * поколение + эпоха таблицы + вид (binding), эпоха/инкарнация потока, план и
 * trial; истёкшая/заменённая/удалённая привязка или переиспользованный кортеж —
 * отказ. Контекст запроса STUN/QUIC потока сохраняется.
 *
 * Возврат: 1 — план применён, out[] заполнен (как у обычного исполнения);
 * 0 — отказ, вызывающий повторно вводит ОРИГИНАЛ. */
int d2k_session_udp_continue(d2k_session *s, uint64_t now_ns, const d2k_key *key,
        const uint8_t plan_id[D2K_PLAN_ID_LEN], const uint8_t trial_id[D2K_TRIAL_ID_LEN],
        const d2k_binding_context *binding, const uint8_t epoch[16], uint64_t incarnation,
        const d2k_ct_info *mapping, const uint8_t *datagram, size_t len,
        uint8_t *buf, size_t bufcap, d2k_result *out);

/* Освобождает потоки, молчавшие дольше idle_ns. Возвращает сколько освободил.
 * Зовётся вызывающим, а не сама: датапат не заводит таймеров и не решает, как
 * часто убирать — это дело того, кто владеет циклом. */
size_t d2k_session_expire(d2k_session *s, uint64_t now_ns, uint64_t idle_ns);

/* Заметить молчание, не дожидаясь забвения потока.
   Зовётся по часам. Отмечает подозрение по потокам, где приветствие ушло, а
   ответа с нагрузкой нет дольше срока, выведенного из ИЗМЕРЕННОГО RTT самого
   потока. Возвращает, сколько подозрений отмечено. */
size_t d2k_session_sweep(d2k_session *s, uint64_t now_ns);

/* Суммы по ОБЕИМ таблицам (TCP и UDP/QUIC, см. struct d2k_session в
 * session.c) — грубая оценка суммарной нагрузки, не диагностика. По ревью
 * задачи 4 (круг 2): для диагностики «какая таблица под давлением» сумма
 * ОПАСНА — TCP-таблица может быть уже на пределе (--flows считает потоки на
 * ТРАНСПОРТ, а не на датапат целиком, см. _tcp/_udp ниже), а сумма с пустой
 * UDP-таблицей покажет благополучный процент заполнения. Сводка d2kd.c
 * печатает _tcp/_udp раздельно ровно поэтому; эти три функции остаются для
 * тех редких случаев, где нужен именно общий порядок величины. */
size_t   d2k_session_flows(const d2k_session *s);
size_t   d2k_session_capacity(const d2k_session *s);
uint64_t d2k_session_refusals(const d2k_session *s);

/* Раздельно по таблицам — то, что обязана показывать диагностика оператору.
 * --flows задаёт ёмкость КАЖДОЙ из двух таблиц (TCP и UDP) отдельно, а не
 * общий бюджет датапата: у UDP нет соединения, окно наблюдения — первые
 * датаграммы потока (D2K_HELLO_WINDOW), и его профиль нагрузки на таблицу
 * никак не связан с TCP, так что общий бюджет на двоих означал бы, что
 * всплеск одного протокола отнимает ёмкость у другого без всякой причины. */
size_t   d2k_session_flows_tcp(const d2k_session *s);
size_t   d2k_session_flows_udp(const d2k_session *s);
size_t   d2k_session_capacity_tcp(const d2k_session *s);
size_t   d2k_session_capacity_udp(const d2k_session *s);
uint64_t d2k_session_refusals_tcp(const d2k_session *s);
uint64_t d2k_session_refusals_udp(const d2k_session *s);

uint64_t d2k_session_applied(const d2k_session *s);

/* СУДЬБА ПОСЫЛОК применённого плана, сообщаемая обратно тем, кто их
 * отправляет. Датапат не отправляет сам: он не знает ни сырого сокета, ни
 * очереди отложенных, и знать их не должен — иначе переносимая часть
 * перестала бы собираться там, где нет Linux.
 *
 * Счёт ведётся по ключу потока И execution_id: после FIN/истечения тот же
 * ключ может принадлежать новой попытке. Очередь обязана сохранить оба поля
 * и проверить send_pending перед отложенной отправкой.
 *
 * d2k_session_sent — одна сырая посылка либо вердикт оригинала принят ОС.
 * Только завершение ВСЕХ этих операций даёт D2K_JRN_PLAN_DONE. Это не
 * подтверждение доставки по сети и тем более не успех обхода.
 *
 * d2k_session_unsent — одна посылка НЕ ушла: в журнал идёт
 * D2K_JRN_PLAN_UNSENT с кодом причины (D2K_REFUSE_*), а остаток снимается со
 * счёта, чтобы поздняя удача остальных посылок не объявила недоисполненный
 * план доисполненным. При plan_id == NULL берётся ID текущей попытки.
 *
 * Поток забыт либо execution_id устарел — оба уведомления игнорируются:
 * старый результат не должен подтверждать или портить новую попытку. */
int d2k_session_send_pending(d2k_session *s, const d2k_key *k, uint64_t execution);
void d2k_session_sent(d2k_session *s, uint64_t at_ns, const d2k_key *k, uint64_t execution);
void d2k_session_unsent(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                        const uint8_t *plan_id, uint8_t code, uint64_t execution);

/* Узнано протоколом. Считается независимо от того, есть ли план: наблюдение
 * не должно зависеть от наличия воздействия. */
uint64_t d2k_session_hellos(const d2k_session *s);
uint64_t d2k_session_with_sni(const d2k_session *s);

/* Сколько потоков вызвали подозрение. Подозрение — наблюдение, а не
 * диагноз, и на диск оно не идёт: §2.3, §2.4. */
uint64_t d2k_session_suspects(const d2k_session *s);

/* Сколько входящих сбросов снято защитой D2K_GUARD_RST_ALIEN. Считать
 * обязательно: «защита стоит» и «защита сработала» — разные факты, и без
 * счётчика их не различить. */
uint64_t d2k_session_rst_dropped(const d2k_session *s);

/* Сколько потоков дали обмен: с обратной стороны пришла нагрузка после
 * приветствия. Это НАБЛЮДЕНИЕ уровня 2 по §4.2, а не «работает». */
uint64_t d2k_session_exchanges(const d2k_session *s);

/* Ответ, который очередь не увидела. Поток TCP показал приветствие, ни одного
 * пакета с обратной стороны после него в очередь не пришло, а клиент уже
 * подтвердил данные сервера (номер подтверждения вырос). Ответ был — его
 * увёл мимо netfilter аппаратный ускоритель (Keenetic PPE/fastnat) или иной
 * обход очереди. Каждый поток считается один раз. Это диагностика видимости,
 * не подозрение и не вердикт: повтор приветствия с прежним подтверждением —
 * молчание, и сюда не попадает.
 *
 * Знаменатель — потоки TCP с узнанным приветствием (d2k_session_hellos
 * считает и QUIC, где этого признака нет). */
uint64_t d2k_session_reply_hidden(const d2k_session *s);
uint64_t d2k_session_tcp_hello_flows(const d2k_session *s);

/* Почему нагрузка не стала узнанным приветствием.
 *
 * Все четыре случая раньше сваливались в один пропуск «плана для этой цели
 * нет», и сводка не давала отличить ответный пакет от прямого, не оказавшегося
 * приветствием. Диагностика 2026-09-05 на этом и встала. */
typedef struct {
    uint64_t reverse;      /* нагрузка пришла с обратной стороны */
    uint64_t after_hello;  /* поток уже показывал приветствие */
    uint64_t late;         /* прямая, но за окном поиска приветствия */
    uint64_t not_hello;    /* разобрали и это не приветствие */
    /* Первый байт последней неузнанной нагрузки: 0x16 — рукопожатие TLS и
     * разбор споткнулся внутри, 0x47 — обычный HTTP, прочее — не TLS. */
    uint8_t  last_first_byte;
    /* Приветствие узнано, но в первом сегменте имя ещё не видно. */
    uint64_t sni_next_seg;
    /* Bounded observational capture, separate from Plan application. */
    uint64_t capture_complete, capture_rejected, capture_expired, capture_full;
    /* ОТКРЫТЫЙ HTTP, KEEP-ALIVE (поле 04.10.2026). http_later — следующие
     * запросы соединения, узнанные на границе (с начала сегмента);
     * http_unaligned — граница запроса не на начале сегмента: конвейер в
     * одном сегменте, сегмент через границу, пропущенная граница, не запрос
     * на границе — дальше поток идёт как есть; http_open_end — конец запроса
     * не определить (chunked, заголовок не кончился в сегменте, Upgrade) —
     * дальше как есть. */
    uint64_t http_later, http_unaligned, http_open_end;
    /* ПОЯВЛЕНИЕ ПОТОКОВ БЕЗ ПРОТОКОЛА (этап 42): сообщено фактом D2K_JRN_FLOW
     * и подавлено ограничением объёма. Подавленный поток не наблюдается
     * контроллером — это предел, и он виден здесь, а не молча. */
    uint64_t flow_told, flow_suppressed;
} d2k_payload_stats;

/* Ограничение объёма фактов появления: запас и пополнение в секунду. Пачка
 * новых потоков (скан, торрент) не топит журнал и канал к контроллеру;
 * контроллер всё равно наблюдает не больше SCHED_FLOWWATCH_SLOTS потоков. */
#define D2K_FLOW_FACT_BURST 32u
#define D2K_FLOW_FACT_PER_S 8u

void d2k_session_payload_stats(const d2k_session *s, d2k_payload_stats *out);

/* Форма приветствия.
 *
 * Датапат ВСЕГДА держит последнее увиденное приветствие — один буфер на всю
 * сессию, и это объявленный предел (§5.2). Хранить приветствие каждого потока
 * нельзя: килобайт на поток.
 *
 * Запрос по имени отдаёт сохранённое НЕМЕДЛЕННО, если имя совпало. Иначе
 * взводит ловушку на следующее приветствие с этим именем. Разница важна:
 * подозрение возникает на том же соединении, чьё приветствие только что
 * прошло, и ждать следующего значило бы ждать повтора клиента — ровно того,
 * от чего мы уходим.
 *
 * Пустое имя означает любое приветствие: цель без имени — нормальное
 * состояние (§5.3), и зонд для неё тоже нужен.
 *
 * Возвращает 1, если сохранённое подошло и уже готово; 0 — ловушка взведена. */
/* transport — 6 или 17: снимок приветствия хранится ОТДЕЛЬНО НА ТРАНСПОРТ.
 * TLS-приветствие поверх TCP и Initial поверх UDP — разные байты разной формы,
 * и отдать одно вместо другого значит отправить контроллера мерить тем, чем
 * клиент не ходит. */
int d2k_session_want_shape(d2k_session *s, const uint8_t *name, size_t len,
                           uint8_t transport);
int d2k_session_want_shape_family(d2k_session *s, const uint8_t *name, size_t len,
                                  uint8_t transport, uint8_t family);
const uint8_t *d2k_session_shape_family(const d2k_session *s, uint8_t transport,
                                        uint8_t family, size_t *len);
/* Event delivery refuses an overwritten shared slot, including tuple reuse. */
const uint8_t *d2k_session_shape_event(const d2k_session *,const d2k_key *,uint64_t,size_t *);

/* Приветствие, готовое к выдаче. NULL — не готово. */
const uint8_t *d2k_session_shape(const d2k_session *s, uint8_t transport, size_t *len);
/* Набор опций TCP пакета, с которого снят TCP-снимок семейства family
 * (замысел 2026-10-23, п. 5.1). NULL — TCP-снимка нет; иначе указатель и
 * длина 0..40 (0 — клиент без опций в данных, набор известен и пуст). */
const uint8_t *d2k_session_shape_tcp_options_family(const d2k_session *s, uint8_t family,
                                                    size_t *len);

const d2k_journal *d2k_session_journal(const d2k_session *s);

/* Сколько потоков с планом вёл conntrack, сколько не вёл (посылки ушли бы
 * мимо NAT — план отвергнут) и сколько раз таблицы не было вовсе. Нужны
 * диагностике: без них «обход работает только для самого роутера»
 * выясняется только захватом трафика (так и выяснялось 13.09.2026). */
/* Счёт справок о трансляции. retried — сколько раз ответ «записи нет»
 * оказался НЕВЕРНЫМ: повторный запрос ту же запись нашёл. Число нужно в поле:
 * по нему видно, насколько часто чтение conntrack промахивается на живой
 * нагрузке, и не пора ли спрашивать ядро иначе, чем через procfs. */
void d2k_session_nat_stats(uint64_t *ok, uint64_t *miss, uint64_t *none,
                           uint64_t *retried);

uint8_t d2k_session_client_shape(const d2k_session *s, const d2k_key *k);
int d2k_session_retry_watch(d2k_session *, const uint8_t *, size_t);

/* ПОЗДНЯЯ ДОСТАВКА (этап 17). Кортеж conntrack (клиент → сервер) TCP-потока
 * по адресу сервера текстом (как имя в SET_NAME_PROBE: "1.2.3.4" / IPv6) и
 * порту клиента сетевого порядка; направление — только доказанное (SYN).
 * 0 — найден и записан в out; -1 — нет такого потока/адрес не разбирается. */
int d2k_session_tcp_tuple_by_port(d2k_session *s, const uint8_t *ip_text, size_t len,
                                  uint8_t family, uint16_t client_port_be, d2k_ct_tuple *out);
/* Флаг позднего наблюдения на потоке (TCP или UDP) по кортежу conntrack:
 * пока стоит, d2k_session_retry_watch отвечает «держать» (1). 0 — поток
 * найден; -1 — нет (флаг ставить не на что; это не ошибка опыта). */
#define D2K_SESSION_RAW_IDENTITY 1
#define D2K_SESSION_MEASURED_PROBE 1
/* Read-only identity of the current unrecognized direct client flow.
 * Returns -1 for absent, foreign-direction, recognized or unsuitable flows.
 * Output arguments are unchanged on failure. A reply is a transport fact. */
int d2k_session_raw_identity(d2k_session *, const d2k_ct_tuple *,
                             uint8_t epoch[16], uint64_t *generation, int *previous_reply);
int d2k_session_late_watch(d2k_session *s, const d2k_ct_tuple *t, int on);

/* Итог позднего наблюдения точного потока (этап 49) — в журнал записью
 * D2K_JRN_LATE_OBS: code D2K_LATEOBS_*, repeats — повторы данных клиента.
 * Кортеж orig (клиент → сервер); сторона клиента берётся из него. */
void d2k_session_note_lateobs(d2k_session *s, const d2k_ct_tuple *t, uint8_t code,
                              uint32_t repeats, const uint8_t token[D2K_TRIAL_ID_LEN], uint64_t now_ns);
/* Датаграмм клиента за окном поиска, принятых в опыт по точной пробе. */
uint64_t d2k_session_late_delivered(const d2k_session *s);

#endif /* D2K_SESSION_H */
