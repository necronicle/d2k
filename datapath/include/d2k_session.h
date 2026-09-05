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

/* Что делать с пакетом, который нам дали. */
typedef enum {
    /* Пропустить как есть. Самый частый исход и умолчание при любых
       сомнениях: не понял — не трогай. */
    D2K_VERDICT_ACCEPT = 0,
    /* Снять оригинал: его байты мы выпустили сами. */
    D2K_VERDICT_DROP = 1
} d2k_verdict;

typedef struct {
    d2k_verdict verdict;

    /* Готовые пакеты на отправку, по одному на посылку. Буфер принадлежит
       вызывающему и передаётся снаружи: датапат не выделяет память на
       пакетном пути. */
    size_t n_out;
    struct {
        uint32_t delay_us;
        size_t   off;   /* смещение в общем буфере */
        size_t   len;
    } out[16];

    /* Почему план не применён. Пустая строка означает, что применён. Причина
       нужна журналу: «план не сработал» и «план не применялся» — разные
       факты, и путать их нельзя. */
    const char *skipped;
} d2k_result;

typedef struct d2k_session d2k_session;

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

/* Освобождает потоки, молчавшие дольше idle_ns. Возвращает сколько освободил.
 * Зовётся вызывающим, а не сама: датапат не заводит таймеров и не решает, как
 * часто убирать — это дело того, кто владеет циклом. */
size_t d2k_session_expire(d2k_session *s, uint64_t now_ns, uint64_t idle_ns);

size_t   d2k_session_flows(const d2k_session *s);
size_t   d2k_session_capacity(const d2k_session *s);
uint64_t d2k_session_applied(const d2k_session *s);
uint64_t d2k_session_refusals(const d2k_session *s);

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

const d2k_journal *d2k_session_journal(const d2k_session *s);

#endif /* D2K_SESSION_H */
