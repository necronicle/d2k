/* d2k_plans.h — таблица планов по целям.
 *
 * §2.6 говорит: план закрепляется только за контекстом, на котором подтверждён.
 * Один план на весь трафик — это ровно то, чего продукт не делает: ошибка на
 * одной цели переключила бы все остальные без проверки.
 *
 * Ключей два, и они разные по надёжности:
 *
 *   имя  — то, что клиент попросил в приветствии. Самый точный ключ, но он
 *          есть не всегда: ECH, отсутствие SNI, не-TLS. §5.3 говорит, что
 *          «имени нет» — нормальное состояние модели, а не сбой.
 *   адрес — есть всегда, но за одним адресом CDN стоят сотни имён. Годится
 *          как запасной ключ и НЕ годится, чтобы приписать цели домен: §3.2
 *          прямо запрещает приписывать домен по совпавшему CDN-адресу.
 *
 * Поиск идёт сперва по имени, потом по адресу. Обратный порядок означал бы,
 * что план соседа по CDN перебивает план, подтверждённый для этого имени.
 *
 * Поиск ограничен ЗАНЯТОСТЬЮ (used), а не вместимостью (cap): занятые записи
 * уплотнены в v[0..used), свободные — в v[used..cap) (инвариант описан в
 * plans.c одним комментарием на find_name/find_addr/oldest/drop/
 * take_free_or_evict — по отдельности эти функции его не держат, только
 * вместе). Раньше здесь стояло другое обоснование — «таблица маленькая и
 * просматривается линейно, поиск случается раз на приветствие, а не на
 * пакет, и при сотне записей стоит меньше, чем разбор самого приветствия» —
 * и оно было написано под вместимость 256, где used и cap почти совпадали.
 * Рост вместимости до 2048 (см. историю ниже) их разъединил: used на живой
 * линии остался тем же (167–181), а cap вырос в 8 раз — старый код сканировал
 * именно cap, и цена ПРОМАХА (систематический случай — цели без плана нет в
 * таблице вовсе, ранний выход не срабатывает) выросла ровно во столько же
 * раз. Замер на этом коде, occupancy=180, Linux/aarch64 (кеш там меньше, чем
 * на маке, и разница между вместимостями видна кратно — на маке смазывается):
 *
 *   вместимость     промах ДО уплотнения   промах ПОСЛЕ уплотнения
 *      256                  179 нс                  129 нс
 *      512                1 752 нс                  120 нс
 *    1 024                5 028 нс                  120 нс
 *    2 048 (боевая)      11 417 нс                  122 нс
 *    4 096               25 847 нс                  122 нс
 *
 * Попадание уплотнение не тронуло вовсе (~450–490 нс что до, что после): оно
 * и раньше не заглядывало дальше своей цели, а не до конца cap, — регрессия
 * была ровно на промахе, симметрично тому, что промах и есть основной случай
 * на живом роутере (см. ниже). Предел объявлен и проверяется.
 *
 * Вместимость исчерпывается — это не баг, а свойство любого предела (§5.2).
 * Раньше при заполнении таблица ОТКАЗЫВАЛА новой цели навсегда: замер на
 * живом роутере d2kd (2026-09-06) поймал ровно это — вместимость 256 литералом
 * в session.c, каталог из 276 записей заливается при старте, и 20 целей (а
 * дальше КАЖДАЯ новая) получали отказ, из которого не было выхода. Youtube и
 * десятки других имён не пробивались не потому, что план плохой, а потому что
 * место кончилось насовсем.
 *
 * Поэтому вместо отказа — вытеснение самой давно не использованной записи
 * («least recently used»). Обращение к записи — успешный d2k_plantab_find
 * ИЛИ повторная установка того же ключа — обновляет её давность; кандидат на
 * вытеснение ищется линейным перебором при установке новой цели, когда
 * свободных записей не осталось (тем же уплотнением — до used, не до cap,
 * см. выше). Линейный поиск, а не куча/список по давности, — по той же
 * причине, что и линейный поиск ключа: таблица мала (замер рабочего набора
 * на живой линии, 2026-09-06: 167–181 адресов назначения одновременно,
 * накопительно 189 за пять минут, кривая почти плоская — набор устойчив,
 * оборачиваемость низкая), а вытеснение случается раз на установку плана, а
 * не на пакет.
 *
 * Вытеснение — ТОЛЬКО при установке плана (d2k_plantab_set_name/set_addr), то
 * есть на управляющем сокете. На пакетном пути (d2k_plantab_find) ничего не
 * отбирается и не выделяется — только читается и, как побочный эффект,
 * обновляется давность найденной записи.
 */
#ifndef D2K_PLANS_H
#define D2K_PLANS_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_plan.h"
#include "d2k_rawmeasure_wire.h"

/* Предел длины имени. Длиннее в SNI не бывает: RFC 6066 ограничивает имя
 * 255 байтами, а практика — куда меньше. */
#define D2K_TARGET_NAME_MAX 255

typedef struct d2k_plantab d2k_plantab;
/* Runtime installation identity, never part of the serialized packet program.
 * Snapshot while p is a live borrowed lookup result; the returned value survives
 * replacement/deletion. A plan hash and the table-wide revision are not a binding. */
#define D2K_BIND_NAME 1
#define D2K_BIND_ADDR 2
#define D2K_BIND_SUFFIX 3
#define D2K_BIND_FLOW 4
typedef struct {
    uint64_t generation;
    uint8_t kind, family, shape, temporary;
    uint8_t epoch[16]; /* random plan-table lifetime; zero means unknown */
} d2k_binding_context;
static inline int d2k_binding_known(const d2k_binding_context *b) {
    if (!b || !b->generation || !b->kind) return 0;
    for (unsigned i=0;i<16;i++) if (b->epoch[i]) return 1;
    return 0;
}
static inline int d2k_binding_equal(const d2k_binding_context *a, const d2k_binding_context *b) {
    if (!d2k_binding_known(a) || !d2k_binding_known(b) || a->generation!=b->generation ||
        a->kind!=b->kind || a->family!=b->family || a->shape!=b->shape || a->temporary!=b->temporary) return 0;
    for (unsigned i=0;i<16;i++) if (a->epoch[i]!=b->epoch[i]) return 0;
    return 1;
}
int d2k_plantab_binding(const d2k_plantab *, const d2k_plan *, d2k_binding_context *);
/* Разрешить точную ещё живую установку по её привязке (поколение уникально на
 * установку). Возвращает тот же план, что и обычный выбор, без дублирования
 * селекторов; переустановка тех же байт несёт новое поколение и не совпадёт;
 * пробы с истёкшим сроком (now_ns) пропускаются. NULL — привязки уже нет. */
const d2k_plan *d2k_plantab_find_by_binding(const d2k_plantab *,
                                            const d2k_binding_context *, uint64_t now_ns);
/* Name probe identity belongs to this installation, not to serialized plan bytes.
 * A legacy all-zero token is accepted and remains unknown proof. */
/* Production SET_NAME_BOUND uses exact declared shape. Installation metadata
 * does not alter program bytes/hash; legacy unbound lookup is unchanged. */
int d2k_plantab_set_name_bound(d2k_plantab *,const uint8_t *,size_t,
    uint64_t now_ns,d2k_plan *,uint8_t shape,uint8_t family);
int d2k_plantab_set_name_trial(d2k_plantab *, const uint8_t *name, size_t len,
    uint64_t now_ns, d2k_plan *, uint8_t shape, uint16_t sport_be, uint8_t family,
    const uint8_t trial_id[D2K_TRIAL_ID_LEN]);
void d2k_plantab_trial(const d2k_plantab *, const d2k_plan *, uint8_t out[D2K_TRIAL_ID_LEN]);
int d2k_plantab_set_endpoint_trial(d2k_plantab *, const uint8_t *, uint8_t,
    uint16_t, uint64_t, d2k_plan *, uint8_t, const uint8_t trial[16]);
int d2k_plantab_set_endpoint_trial_port(d2k_plantab *, const uint8_t *, uint8_t,
    uint16_t, uint16_t, uint64_t, d2k_plan *, uint8_t, const uint8_t trial[16]);
int d2k_plantab_commit_endpoint_trial(d2k_plantab *, const uint8_t *, uint8_t,
    uint16_t, uint8_t, const uint8_t trial[16]);
int d2k_plantab_del_endpoint_trial(d2k_plantab *, const uint8_t *, uint8_t,
    uint16_t, uint8_t, const uint8_t trial[16]);
int d2k_plantab_del_name_bound(d2k_plantab *, const uint8_t *, size_t,
    uint8_t transport, const d2k_binding_context *);

/* A bound non-ECH TLS13 proof requires a complete extension block to
 * distinguish plain TLS from an ECH offer arriving in a later segment. */
int d2k_plantab_needs_complete_tls_shape(const d2k_plantab *,const uint8_t *,size_t,
    uint8_t family);
int d2k_plantab_has_ech_target(const d2k_plantab *, const uint8_t *, size_t,
    const uint8_t *, uint8_t family, uint16_t sport_be);

/* Explicit family APIs. Legacy entry points are IPv4-only wrappers. */
int d2k_plantab_set_addr_family(d2k_plantab *, const uint8_t *, uint8_t family,
    uint64_t now_ns, d2k_plan *);
int d2k_plantab_del_addr_family(d2k_plantab *, const uint8_t *, uint8_t family);
/* Адресная привязка С ФОРМОЙ ПРОТОКОЛА (D2K_PLAN_SHAPE_*, не ANY): ключ —
 * (адрес, семейство, форма). QUIC, STUN/голос и TLS одного IP — разные
 * записи; план одной формы к пакетам другой не применяется (D2K_SPEC §5).
 * set — владение p переходит таблице на любом исходе; -2 при форме ANY.
 * del_shaped снимает ровно эту форму. Без формы (set/del_addr_family) —
 * внутренний вход: дедушкино право / снятие всех форм адреса. */
int d2k_plantab_set_addr_shaped(d2k_plantab *, const uint8_t *, uint8_t family,
    uint64_t now_ns, d2k_plan *, uint8_t shape);
int d2k_plantab_del_addr_shaped(d2k_plantab *, const uint8_t *, uint8_t family,
    uint8_t shape);
/* Permanent service binding: exact address, family, server port and shape.
 * Ports are in network order and must be nonzero. No wildcard shapes or
 * implicit TLS/ECH transfer. Ownership of p transfers on every outcome.
 * Legacy address lookup/deletion cannot see/remove these bindings. */
int d2k_plantab_set_endpoint(d2k_plantab *, const uint8_t *, uint8_t family,
    uint16_t dport_be, uint64_t now_ns, d2k_plan *, uint8_t shape);
int d2k_plantab_del_endpoint(d2k_plantab *, const uint8_t *, uint8_t family,
    uint16_t dport_be, uint8_t shape);
/* RAW requires explicit transport; ambiguous legacy deletion preserves both. */
int d2k_plantab_del_raw_endpoint(d2k_plantab *, const uint8_t *, uint8_t family,
    uint16_t dport_be, uint8_t transport);
int d2k_plantab_set_dns_endpoint(d2k_plantab *,const uint8_t *,uint8_t family,
    uint16_t dport_be,uint64_t now_ns,uint16_t wire_length,d2k_plan *);
int d2k_plantab_del_dns_endpoint(d2k_plantab *,const uint8_t *,uint8_t family,
    uint16_t dport_be,uint8_t transport);
void d2k_plantab_clear_dns_endpoints(d2k_plantab *);
const d2k_plan *d2k_plantab_find_dns_endpoint(d2k_plantab *,const uint8_t *,uint8_t family,
    uint16_t dport_be,uint8_t transport,const uint8_t *,size_t,uint64_t now_ns);
const d2k_plan *d2k_plantab_find_target_endpoint(d2k_plantab *, const uint8_t *name, size_t,
    const uint8_t *addr, uint8_t family, uint64_t now_ns, uint8_t shape,
    uint16_t sport_be, uint16_t dport_be);
/* Этап 39: то же с транспортом потока (6/17): у формы RAW адресная запись
 * своя для каждого транспорта плана. 0 — транспорт не задан (прежний поиск). */
const d2k_plan *d2k_plantab_find_target_endpoint_tr(d2k_plantab *, const uint8_t *name, size_t,
    const uint8_t *addr, uint8_t family, uint64_t now_ns, uint8_t seen_shape,
    uint16_t sport_be, uint16_t dport_be, uint8_t transport);
const d2k_plan *d2k_plantab_find_target(d2k_plantab *, const uint8_t *name, size_t,
    const uint8_t *addr, uint8_t family, uint64_t now_ns, uint8_t shape, uint16_t sport_be);
int d2k_plantab_set_name_family(d2k_plantab *, const uint8_t *, size_t,
    uint64_t, d2k_plan *, uint8_t shape, uint16_t sport_be, uint8_t family);
int d2k_plantab_del_name_family(d2k_plantab *, const uint8_t *, size_t, uint8_t family);
int d2k_plantab_del_name_probe_family(d2k_plantab *, const uint8_t *, size_t,
    uint8_t shape, uint16_t sport_be, uint8_t family);
/* Exact probe key AND experiment token; stale/recycled ports preserve the
 * currently installed owner's plan. A zero/absent token never deletes. */
int d2k_plantab_del_name_probe_trial(d2k_plantab *,const uint8_t *,size_t,
    uint8_t shape,uint16_t sport_be,uint8_t family,const uint8_t trial[D2K_TRIAL_ID_LEN]);
/* Постоянная запись ровно (имя, транспорт, форма, семейство); пробы не
 * трогает (задача 21). 1 — что-то снято. */
int d2k_plantab_del_name_shaped(d2k_plantab *, const uint8_t *, size_t,
    uint8_t transport, uint8_t shape, uint8_t family);
const d2k_plan *d2k_plantab_find_family(d2k_plantab *, const uint8_t *, size_t,
    uint32_t addr_be, uint64_t, uint8_t shape, uint16_t sport_be, uint8_t family);
/* Prefilter only: an unknown HTTP Host still requires exact lookup after assembly. */
int d2k_plantab_http_candidate(const d2k_plantab *,uint8_t,uint16_t);
int d2k_plantab_stream_candidate_family(const d2k_plantab *, const uint8_t *,
    size_t, uint32_t addr_be, uint16_t sport_be, uint8_t family);
int d2k_plantab_stream_candidate_target(const d2k_plantab *, const uint8_t *,
    size_t, const uint8_t *addr, uint16_t sport_be, uint8_t family);

/* Полный поток собственного адресного QUIC-зонда. Все порты в сетевом
 * порядке; адреса — четыре байта как в d2k_key. Не смешивать его с ключом
 * постоянной адресной привязки, у которой намеренно только destination IP. */
typedef struct {
    uint8_t  src_ip4[4];
    uint16_t src_port_be;
    uint8_t  dst_ip4[4];
    uint16_t dst_port_be;
    uint8_t  transport;
    uint8_t  family; /* 0 is the existing IPv4 caller default; otherwise 4/6. */
    uint8_t  src_ip6[16], dst_ip6[16];
} d2k_addr_probe_flow;

int d2k_plantab_set_dns_probe(d2k_plantab *,const d2k_addr_probe_flow *,
    const uint8_t [16],uint64_t,uint64_t,uint16_t,const uint8_t [32],d2k_plan *);
const d2k_plan *d2k_plantab_find_dns_probe(d2k_plantab *,const d2k_addr_probe_flow *,
    int,const uint8_t *,size_t,uint64_t,uint8_t [16],int *reserved);


d2k_plantab *d2k_plantab_new(size_t cap);
void         d2k_plantab_free(d2k_plantab *t);
/* Drop controller-owned experiments, retaining all confirmed bindings. */
void         d2k_plantab_clear_probes(d2k_plantab *t);

/* Ставит план для цели. Владение планом переходит таблице В ЛЮБОМ СЛУЧАЕ,
 * включая отказ: иначе каждая ошибка вызывающего оставляла бы течь.
 *
 * now_ns — давность обращения для будущего вытеснения: свежепоставленная или
 * переустановленная запись получает её как отметку последнего использования,
 * иначе немедленно оказалась бы вытесняемой как «давно не трогали».
 *
 *  0 — поставлено (прежний план для той же цели освобождён; таблица, полная
 *      доверху, вытесняет самую давно не использованную запись, а не
 *      отказывает — см. большой комментарий выше),
 * -1 — вытеснить нечего (защита от порчи состояния: недостижимо через
 *      d2k_plantab_new, тот не пускает таблицу нулевой ёмкости, а при
 *      cap >= 1 полная таблица всегда даёт хотя бы одну занятую запись),
 * -2 — аргументы негодны. */
/* ФОРМА ПРИВЕТСТВИЯ, на которой план подтверждён. Числа те же, что у
 * d2k_shape контроллера (core/hello.h): 0 — не объявлена, 1 — MODERN
 * (объявлен TLS 1.3), 2 — LEGACY. Ноль совместим с любым наблюдением: так
 * выглядит старый каталог, и молча перестать применять его планы нельзя. */
#define D2K_PLAN_SHAPE_ANY    0
#define D2K_PLAN_SHAPE_MODERN 1
#define D2K_PLAN_SHAPE_LEGACY 2
/* Приветствие QUIC. Своё значение, а не ANY: план, подтверждённый собственным
 * зондом на TLS поверх TCP, к Initial того же имени отношения не имеет —
 * другой транспорт, другое приветствие, другая коробка на пути. До 12.09.2026
 * путь QUIC звал поиск с ANY, и такой план ему выдавался (0009, U5). В
 * нумерации продолжает d2k_shape контроллера, у которого QUIC-формы нет: там
 * это значение не встречается и встречаться не может. */
#define D2K_PLAN_SHAPE_QUIC   3
/* ДЕДУШКИНО ПРАВО: форма не записывалась, применяем по совместимости.
 *
 * Отдельный токен, а не перегруженный ноль. Ноль значит «сказать нечего» и
 * доказательством совместимости больше не является ни с одной стороны;
 * исключение обязано быть названо явно, чтобы было видно, КТО его выдал и на
 * каком основании, а не спрятано в арифметике нулей.
 *
 * Ставит его синхронизация каталога для привязки ПО ИМЕНИ, когда в записи
 * формы нет (каталог заведён до появления поля). План по АДРЕСУ с управляющего
 * сокета так больше не ставится (v7, задача 16): адресная привязка несёт
 * форму протокола, иначе голосовой план одного IP доставался бы его QUIC
 * Initial (D2K_SPEC §5); d2k_plantab_set_addr/_family без формы — только
 * внутренний вход тестов датапата.
 *
 * Молча перестать применять такие планы нельзя: это работающий у человека
 * обход, и его миграция — задача каталога с повторной проверкой, а не
 * мгновенного отказа в датапате. */
#define D2K_PLAN_SHAPE_GRANDFATHER 4
/* ГОЛОС ДИСКОРДА: первый пакет потока — запрос IP Discovery, а не приветствие
 * TLS или QUIC. Своя форма по той же причине, что у QUIC: подтверждённое на
 * одном протоколе к другому отношения не имеет. */
#define D2K_PLAN_SHAPE_VOICE  5
#define D2K_PLAN_SHAPE_ECH_TCP 6
/* ОТКРЫТЫЙ HTTP (задача 51, шаг 4): вход — запрос GET/HEAD, имя — Host.
 * Запись этой формы держит ТОЛЬКО план протокола http (minexec 11) и только
 * по имени; TLS-поиск её не видит, а HTTP-поиск видит только её
 * (d2k_plantab_find_http): ни дедушкина запись, ни адрес, ни семейство
 * имён HTTP-запросу не достаются. */
#define D2K_PLAN_SHAPE_HTTP 7
/* Нагрузка без распознанного протокола — признак наблюдения потока (журнал,
 * SUSPECT), записей такой формы в таблице не бывает (этап 12, 28.10.2026). */
#define D2K_PLAN_SHAPE_RAW 8
#define D2K_PLAN_SHAPE_DNS 9

/* Learned areas never consume/evict exact bindings. Set owns p on all paths,
 * like set_name_family. Exceptions are exact and context-specific. */
#define D2K_PLAN_SUFFIX_MAX 64
#define D2K_PLAN_BYPASS_MAX 256
int d2k_plantab_set_suffix_family(d2k_plantab *, const uint8_t *, size_t,
    uint64_t, d2k_plan *, uint8_t shape, uint8_t family);
int d2k_plantab_del_suffix_family(d2k_plantab *, const uint8_t *, size_t,
    uint8_t transport, uint8_t shape, uint8_t family);
int d2k_plantab_set_bypass_family(d2k_plantab *, const uint8_t *, size_t,
    uint8_t transport, uint8_t shape, uint8_t family);
int d2k_plantab_del_bypass_family(d2k_plantab *, const uint8_t *, size_t,
    uint8_t transport, uint8_t shape, uint8_t family);

/* ИМЯ ГОЛОСА — КЛАСС, А НЕ ДОМЕН.
 *
 * У голоса имени нет: точка выдаётся на сессию, в DNS её нет, и выдумать ей
 * домен запрещено (D2K_SPEC: адресным целям домен не придумывать — это
 * померило бы другую цель). Но и по АДРЕСУ ключевать нельзя: боевой профиль
 * z2k держит состояние голоса общим для всех точек (hostkey=z2k_nohost_key),
 * иначе «голос холодно стартует на каждом новом DC-IP». Найденное на одной
 * точке годится для всех, потому что коробка узнаёт голос по первому пакету,
 * а не по адресу.
 *
 * Отсюда ярлык класса. «@» в DNS-имени невозможна, так что за имя сайта он
 * не сойдёт ни при каком разборе, а вся машинерия имён (таблица планов,
 * журнал, каталог) работает с ним без особых случаев. То же значение
 * объявлено у контроллера (D2K_LINK_VOICE_CLASS в d2k_link.h). */
#define D2K_VOICE_CLASS "@discord-voice"

/* Медиапорты Дискорда — те же, что DISCORD_MEDIA_PORT_RANGE эталона и
 * voice_ports в core/voice.c. STUN на них — голос Дискорда (класс выше);
 * STUN на прочие порты класса не получает и идёт адресным путём. */
#define D2K_DISCORD_MEDIA_PORT_LO 50000
#define D2K_DISCORD_MEDIA_PORT_HI 50099

int d2k_plantab_set_name(d2k_plantab *t, const uint8_t *name, size_t len,
                         uint64_t now_ns, d2k_plan *p);
/* То же, но с объявленной формой приветствия: план не применится к
 * приветствию ДРУГОЙ объявленной формы. Успех собственного зонда на TLS 1.3
 * ничего не говорит про браузер с TLS 1.2 (docs/decisions/0009 U5). */
int d2k_plantab_set_name_shaped(d2k_plantab *t, const uint8_t *name, size_t len,
                                uint64_t now_ns, d2k_plan *p, uint8_t shape);
int d2k_plantab_set_addr(d2k_plantab *t, uint32_t addr_be, uint64_t now_ns,
                         d2k_plan *p);

/* ПРОБНЫЙ ПЛАН — ТОЛЬКО ДЛЯ ОДНОГО ПОТОКА, а не для всех, кто пойдёт к этой
 * цели.
 *
 * Испытывает кандидата зонд, а платил за испытание пользователь: план встаёт
 * по ИМЕНИ, и его получают ВСЕ соединения к этой цели, пока идёт перебор. На
 * роутере владельца 13.09.2026 поиск по i.ytimg.com шёл двадцать одну минуту,
 * и всё это время цель у человека работала через раз — часть кандидатов её
 * пробивала, часть рвала.
 *
 * Есть и вторая, худшая беда: пока пробный план висит на имени, «цель молчит»
 * означает сразу две несовместимые вещи — «коробка режет» и «наш же кандидат
 * сломал». Отличить их нечем, и поиск меряет собственную тень.
 *
 * sport_be — местный порт зонда В СЕТЕВОМ ПОРЯДКЕ; зонд занимает его заранее
 * (bind до connect), потому и может назвать. Ноль означает «любой поток» —
 * так ставятся ПОДТВЕРЖДЁННЫЕ планы, им скрывать нечего. */
int d2k_plantab_set_name_probe(d2k_plantab *t, const uint8_t *name, size_t len,
                               uint64_t now_ns, d2k_plan *p, uint8_t shape,
                               uint16_t sport_be);

/* Убирает план цели. Возвращает 1, если что-то убрано. */
int d2k_plantab_del_name(d2k_plantab *t, const uint8_t *name, size_t len);
int d2k_plantab_del_name_probe(d2k_plantab *t, const uint8_t *name, size_t len,
                               uint8_t shape, uint16_t sport_be);
int d2k_plantab_del_addr(d2k_plantab *t, uint32_t addr_be);

/* Временный Plan для одного exact-flow опыта. plan ownership переходит
 * таблице при любом результате. expires_ns — монотонное время datapath.
 * 0 success; -1 capacity exhausted; -2 invalid args; -3 same flow already
 * owned by a different trial generation, or a renewal whose evidence or plan
 * differs from the installed one. */
#define D2K_MEASURED_PROBE 1
/* Owns p on every result. Guarded plans are invisible to ordinary lookups.
 * plan_digest: SHA-256 of the plan's wire bytes. The same flow and trial with
 * byte-identical report and plan only moves the expiry (lease renewal); the
 * installed plan and evidence stay as they were. */
int d2k_plantab_set_measured_probe(d2k_plantab *,const struct d2k_rawmeasure_report *,
                                  const uint8_t trial[16],const uint8_t plan_digest[32],
                                  uint64_t now,uint64_t expires,d2k_plan *p);
const d2k_plan *d2k_plantab_find_measured_probe(d2k_plantab *,const d2k_ct_tuple *,
    const uint8_t epoch[16],uint64_t generation,uint32_t seq,const uint8_t *payload,size_t len,
    uint64_t now,uint8_t trial_out[16]);
int d2k_plantab_set_addr_probe(d2k_plantab *t,
                               const d2k_addr_probe_flow *flow,
                               const uint8_t trial_id[D2K_TRIAL_ID_LEN],
                               uint64_t now_ns, uint64_t expires_ns,
                               d2k_plan *p);
/* Removes only exact (flow, generation); stale deletes return 0.
 * A DNS entry returns 2 because it has no conntrack lease to remove. */
int d2k_plantab_del_addr_probe(d2k_plantab *t,
                               const d2k_addr_probe_flow *flow,
                               const uint8_t trial_id[D2K_TRIAL_ID_LEN]);
/* Exact temporary match. Expired entries are removed lazily. trial_id_out may
 * be NULL when caller needs only the Plan. */
const d2k_plan *d2k_plantab_find_addr_probe(
    d2k_plantab *t, const d2k_addr_probe_flow *flow, uint64_t now_ns,
    uint8_t trial_id_out[D2K_TRIAL_ID_LEN]);
/* The same lookup for a voice request (IP Discovery / STUN) of a user flow.
 * Additionally matches a VOICE WILDCARD entry (flow.src_port_be == 0): the
 * same LAN client address, the same server address and UDP port, any client
 * port — the next call or rejoin from that client to that voice endpoint.
 * find_addr_probe never returns wildcard entries. */
const d2k_plan *d2k_plantab_find_voice_probe(
    d2k_plantab *t, const d2k_addr_probe_flow *flow, uint64_t now_ns,
    uint8_t trial_id_out[D2K_TRIAL_ID_LEN]);
size_t d2k_plantab_probe_count(const d2k_plantab *t);

/* Сперва по имени, потом по адресу. NULL — плана для этой цели нет, и это
 * обычный исход: пустая база при первом запуске (§2.2).
 *
 * now_ns обновляет давность НАЙДЕННОЙ записи (нет находки — нечего трогать):
 * обращение обязано продлевать жизнь записи, иначе рабочая цель, к которой
 * реально идёт трафик, вытеснялась бы наравне с той, про которую забыли.
 * Вызывается на пакетном пути (раз на приветствие) — ничего не выделяется и
 * не вытесняется, только читается запись и правится её отметка времени. */
/* seen_shape — форма НАБЛЮДАЕМОГО приветствия (D2K_PLAN_SHAPE_*). Ноль с
 * любой стороны означает «не объявлено» и совместим со всем: ограничение
 * действует, только когда обе стороны объявлены и не совпали. */
const d2k_plan *d2k_plantab_find(d2k_plantab *t, const uint8_t *name,
                                 size_t len, uint32_t addr_be, uint64_t now_ns,
                                 uint8_t seen_shape);

/* То же, но с МЕСТНЫМ ПОРТОМ потока (сетевой порядок). Запись, поставленная
 * под конкретный порт (d2k_plantab_set_name_probe), достаётся только потоку с
 * этим портом; запись без порта — любому. Вариант без порта выше зовёт этот с
 * нулём, то есть видит только записи без порта: так и надо всем, кто про
 * пробные планы не знает. */
const d2k_plan *d2k_plantab_find_sport(d2k_plantab *t, const uint8_t *name,
                                       size_t len, uint32_t addr_be, uint64_t now_ns,
                                       uint8_t seen_shape, uint16_t sport_be);

/* План для запроса HTTP: запись имени формы HTTP — пробная своего порта
 * (sport_be != 0), иначе постоянная. Больше ничего. */
const d2k_plan *d2k_plantab_find_http(d2k_plantab *t, const uint8_t *name, size_t len,
                                      uint8_t family, uint16_t sport_be, uint64_t now_ns);

/* Сколько раз запись нашлась по цели, но НЕ ПОДОШЛА по форме приветствия.
 * Отдельно от «плана нет»: тот счёт растёт и на каждом не-приветствии, и по
 * нему нельзя отличить «цель незнакома» от «знаем, но форма другая». */
size_t d2k_plantab_shape_misses(const d2k_plantab *t);

size_t d2k_plantab_count(const d2k_plantab *t);
size_t d2k_plantab_capacity(const d2k_plantab *t);

uint64_t d2k_plantab_revision(const d2k_plantab *t);
/* Conservative buffering prefilter, NOT permission to execute. Unknown SNI
 * may match a name entry; known SNI and probe port never widen their scope.
 * Full lookup including measured shape remains mandatory after assembly. */
int d2k_plantab_stream_candidate(const d2k_plantab *t, const uint8_t *name,
                                size_t len, uint32_t addr_be, uint16_t sport_be);

#endif /* D2K_PLANS_H */
