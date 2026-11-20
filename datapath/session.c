/* session.c — склейка модулей датапата.
 *
 * Правило, которому подчинено всё: НЕ ПОНЯЛ — НЕ ТРОГАЙ. Любая неясность —
 * незнакомый протокол, обрезанный заголовок, полная таблица, невычислимый
 * якорь — приводит к тому, что пакет проходит как есть. Пропустить чужой
 * пакет безвредно; тронуть непонятый — значит испортить соединение человеку и
 * не узнать об этом.
 *
 * Времена в наносекундах целыми. Плавающей арифметики на пакетном пути нет.
 */
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#include "d2k_preflight_plan.h"
#include "d2k_provider_ips.h"
#include "d2k_hello.h"
#include "d2k_plans.h"
#include "d2k_packet.h"
#include "d2k_quic.h"
#include "d2k_quicsnap.h" /* core/ — разбор QUIC линкуется исходниками, см. Makefile */
#include "d2k_nat.h"
#include "d2k_session.h"
#include "d2k_http80.h"
#include "d2k_time.h"
#include "d2k_tls.h"
#include "d2k_capture.h"
#include "d2k_hold.h"
#include "d2k_ipfrag.h"
#include "d2k_crypto.h"
#include "plan_internal.h"

/* Сколько первых пакетов потока имеет смысл разбирать в поисках приветствия.
 * ClientHello приходит первым или почти первым; после этого разбор — чистая
 * трата на каждом пакете загрузки. */
#define D2K_HELLO_WINDOW 8

/* Сколько последних клиентских Initial держит сессия. Полёт — не больше
   четырёх датаграмм, и тридцати двух записей хватает на полтора десятка
   одновременных целей: Chrome открывает вкладки пачкой, и полёт одной цели
   не должен вытеснять полёт другой раньше, чем соберётся имя. Около 48 КБ на
   сессию, один раз. */
#define D2K_SESSION_INIT_RING 32

typedef struct {
    uint64_t token;
    uint8_t bytes[D2K_CAPTURE_BYTES];
} tcp_retry_snapshot;

/* Separate from ordinary traffic accounting: probe packets must never become
 * client EXCHANGE/SUSPECT evidence. Bound identically to the configured FSM. */
typedef struct {
    int used, handover_reported;
    uint32_t path;
    uint8_t syn[D2K_HOLD_HEADER];
    size_t syn_len;
    d2k_key key;
    uint64_t started_ns;
    uint8_t pieces, client_side;
    d2k_pf_stage stage;
    uint8_t plan_id[D2K_PLAN_ID_LEN], trial_id[D2K_TRIAL_ID_LEN];
    d2k_binding_context binding;
} preflight_context;

struct d2k_session {
    int preflight_enabled, preflight_ipv6;
    d2k_provider_ips provider_ips;
    uint8_t provider_probe_hello[D2K_CAPTURE_BYTES];
    size_t provider_probe_len;
    size_t preflight_send_cap;
    d2k_pf_table preflight;
    d2k_pf_lease_table preflight_leases;
    preflight_context *preflight_contexts;
    uint64_t preflight_calls;
    uint32_t packet_path;

    /* Same concurrency bound as TLS assembly: 64 KiB, no heap per flow.
       Eviction invalidates the token, so another flow's bytes cannot replay. */
    tcp_retry_snapshot retries[D2K_HOLD_SLOTS];
    size_t retry_next;
    uint64_t retry_token;
    /* Event-loop owned; random initial value, nonzero counter per datagram.
       Never derive this from the client's frequently-zero DF packet ID. */
    uint32_t fragment_id;
    int fragment_seeded;
    /* Крючок netfilter для ТЕКУЩЕГО пакета — см. d2k_session_set_hook.
       D2K_HOOK_UNKNOWN значит «не сказали», и тогда направление выводится
       по порту, как и раньше. */
    uint8_t hook;
    /* Метка маршрутизации клиента у ТЕКУЩЕГО пакета (0 — нет), задача 47. */
    uint32_t route_mark;
    uint64_t routed_flows;
    d2k_capture capture;
    d2k_table   *flows;
    /* Учёт QUIC/UDP-потоков (задача 4 QUIC-вертикали) — ВТОРАЯ, независимая
     * таблица того же типа d2k_table/d2k_flow, не общая с flows.
     *
     * У ключа потока (d2k_key, d2k_track.h) теперь есть поле proto — по
     * ревью задачи 4: TCP-поток и UDP-поток с одинаковой парой адрес+порт
     * получают РАЗНЫЕ ключи и потому не схлопнулись бы в одну ячейку даже в
     * общей таблице (порты TCP и UDP — независимые пространства нумерации,
     * совпадение не запрещено ничем, а браузер именно так и делает —
     * гоняет QUIC и TCP к одному адресу наперегонки). Раздельные таблицы
     * здесь не ради снятия этой коллизии — её уже снял proto в ключе, — а
     * ради независимых бюджетов ёмкости: всплеск QUIC-трафика не должен
     * вытеснять из таблицы TCP-потоки, отняв у них ёмкость, которую
     * оператор выделил под TCP (--flows), и наоборот.
     *
     * Почему тот же d2k_flow, а не свой маленький тип: d2k_plan_apply()
     * принимает `const d2k_flow *` (d2k_plan.h) — эта сигнатура не в
     * периметре задачи 4, и подменить её другим типом означало бы менять
     * plan_apply.c. Поля d2k_flow, нужные UDP (key, first_ns/last_ns,
     * dir_known/init_low, fwd_pkts, saw_hello, plan_done, damaged), уже
     * названы и уже значат ровно то, что нужно; TCP-специфичные поля
     * (saw_syn, rst_dropped, типы TLS-записей) для UDP-записей просто
     * никогда не трогаются и остаются нулём — это честно: у ЭТОГО потока
     * действительно не было ни SYN, ни TCP-сброса. */
    d2k_table   *uflows;
    d2k_plantab *plans;
    /* Запасной план — на все цели сразу. В продукте его быть не должно: §2.6
     * закрепляет план за контекстом, на котором он подтверждён, а один план
     * на весь трафик означает, что ошибка на одной цели переключит все
     * остальные без проверки. Он существует для опытов, где сужение задано
     * снаружи правилом firewall на одну пару адресов. */
    d2k_plan    *plan;
    uint64_t plan_revision;
    d2k_journal *jrn;
    uint64_t     applied;
    /* Планы, ДОИСПОЛНЕННЫЕ целиком: все посылки ушли и вердикт оригинала
       принят ядром. Отдельно от applied, потому что это разные факты, и
       разрыв между ними — самое важное число диагностики: подготовили много,
       доисполнили мало значит, что до контроллера подтверждений не доходит. */
    uint64_t     done;
    /* Потоки, объявленные испорченными. Не число отказов по ним — именно
       потоки: отказов на одном потоке бывает много. */
    uint64_t     damaged_flows;
    /* Уведомления об отправке, которые НЕКОМУ приписать: поток забыт либо
       поколение чужое. Если это число велико, «доисполнен» не наступит
       никогда, и искать причину надо здесь, а не в поиске. */
    uint64_t     sent_lost;
    uint64_t     next_execution;
    uint64_t     hellos;
    uint64_t     with_sni;
    uint64_t     suspects;
    uint64_t     rst_dropped;
    uint64_t     exchanges;
    /* Потоки TCP с приветствием и те из них, чей ответ очередь не видела
       (d2k_session_reply_hidden). */
    uint64_t     tcp_hello_flows;
    uint64_t     reply_hidden;

    /* Разбор нагрузки: почему приветствие не узналось. */
    uint64_t     pay_reverse;      /* нагрузка с обратной стороны */
    uint64_t     pay_after_hello;  /* поток уже показал приветствие */
    uint64_t     pay_late;         /* прямая, но за окном поиска */
    /* ПОЗДНЯЯ ДОСТАВКА (этап 17): пакеты клиента на потоках под меткой записи
       (late_watch), дошедшие до очереди. Ненулевой счётчик — доказательство,
       что поздние пакеты потока вообще доходят (без правила connmark или при
       аппаратном ускорителе их здесь не бывает). */
    uint64_t     late_delivered;
    uint64_t     pay_not_hello;    /* разобрали и это не приветствие */
    uint8_t      last_nonhello_first;
    /* Открытый HTTP, keep-alive: см. d2k_payload_stats. */
    uint64_t     http_later, http_unaligned, http_open_end;
    uint64_t     sni_in_next_seg;
    uint64_t     captured_hellos;
    /* Факты появления потоков без протокола (этап 42): счёт и запас. */
    uint64_t     flow_told, flow_suppressed;
    uint32_t     flow_tokens;
    uint64_t     flow_tok_ns;

    /* Форма приветствия. Один буфер на всю сессию, и это объявленный предел:
     * хранить приветствие каждого потока значило бы килобайт на поток.
     *
     * last_* — последнее увиденное приветствие, копится всегда.
     * ready_* — то, что готово к выдаче по запросу. */
    /* Снимок приветствия храним ОТДЕЛЬНО НА ТРАНСПОРТ.
       Один слот на оба был дырой: приветствие TLS поверх TCP и Initial поверх
       UDP — разные байты, разной формы, и контроллеру они нужны РАЗНЫЕ.
       Общий слот отдавал QUIC-задаче то, что снято с TCP, и наоборот; задача
       QUIC шла мерить, держа в руках TLS-приветствие, и первый же разбор его
       отвергал. Индексы 0/1 — IPv4 TCP/UDP; 2/3 — IPv6 TCP/UDP.
       Семейства не делят снимок: опыт сохраняет контекст исходного потока. */
    uint8_t  last_hello[4][D2K_SHAPE_MAX];
    size_t   last_hello_len[4];
    /* Опции TCP пакета, с которого снят last_hello / shape (слоты TCP; у
       QUIC нули): набор клиента едет контроллеру рядом со снимком, чтобы
       зонд здоровался им, а не литералом (замысел 2026-10-23, п. 5.1). */
    uint8_t  last_opts[4][40];
    uint8_t  last_opts_len[4];
    uint8_t  shape_opts[4][40];
    uint8_t  shape_opts_len[4];
    uint8_t  last_name[4][256];
    size_t   last_name_len[4];

    /* ВИДНА ЛИ ВООБЩЕ ОБРАТНАЯ СТОРОНА — по транспорту (индексы те же, что у
     * last_hello: 0 TCP, 1 UDP, см. slot_of).
     *
     * Правило firewall на обратное направление ставится не всегда, и без него
     * в очередь не приходит ни один пакет сервера: КАЖДЫЙ поток выглядел бы
     * молчащим, а это ровно та подмена «не смотрели» на «нет ответа», которую
     * запрещает §2.4. Улика, что правило есть, — любой пакет оттуда, и она
     * СЕССИОННАЯ, а не поточная: видимость направления это свойство набора
     * правил, а не отдельного потока.
     *
     * Для TCP поточная улика сильнее и потому используется там, где она
     * доступна (SYN-ACK приходит раньше приветствия, см. sweep_one). Для UDP
     * поточной улики не существует в принципе: у QUIC первая же датаграмма —
     * это и есть приветствие, и на заблокированном потоке ответа не будет
     * никогда. Сессионная улика — единственная честная, какая тут вообще
     * бывает.
     *
     * Признак по транспорту, а не один на всё: правила на TCP и на UDP —
     * разные строки, и наличие одной ничего не говорит о другой. */
    int      rev_seen[4];
    int      udp_reverse_hook;
    /* Счётчики потока у ядра по кортежу (d2k_ctq.h); NULL — не спрашивать. */
    d2k_ct_query_fn ct_query;
    size_t   adopted;         /* потоков принято из conntrack на старте (этап 13) */
    void *ct_query_ctx;
    /* Бюджеты потока коробок (задача 56, D2K_CMD_SET_STALL_BUDGETS); по
       умолчанию — один полевой D2K_TCP_STALL_FIELD_BUDGET. */
    uint16_t stall_budget[D2K_STALL_BUDGETS_MAX];
    size_t   n_stall_budget;

    int      shape_armed[4];
    uint8_t  shape_name[4][256];
    size_t   shape_name_len[4];
    uint8_t  shape[4][D2K_SHAPE_MAX];
    size_t   shape_len[4];
    d2k_key  shape_key[4];
    uint64_t shape_at[4];

    /* КОЛЬЦО ПОСЛЕДНИХ INITIAL КЛИЕНТА (задача 66).
       Приветствие Chrome с постквантовым key_share едет ДВУМЯ Initial, и
       снимком обязан стать весь полёт: по одной датаграмме контроллер видит
       обрывок и уходит мерить встроенным профилем. Кольцо одно на сессию, а
       не буфер на поток: потоков 2048, и копия приветствия в каждом стоила бы
       мегабайты. Пишется, только пока ловушка снимка взведена, и живёт до
       сборки имени — то есть доли секунды. */
    struct {
        d2k_key  key;
        uint8_t  dcid[D2K_QW_CID_MAX];
        uint8_t  dcid_len;
        uint16_t len;
        uint8_t  dg[D2K_QW_MAX_DGRAM];
    } init_ring[D2K_SESSION_INIT_RING];
    size_t init_ring_n;      /* сколько записей заполнено (растёт до предела) */
    size_t init_ring_next;   /* куда писать следующую */
};

/* DCID датаграммы Initial: он лежит в открытом виде (RFC 9001 §5.2), и по
   нему датаграммы одного полёта отличаются от чужого соединения. 0 — успех. */
static int initial_dcid(const uint8_t *p, size_t n, uint8_t *out, uint8_t *out_len) {
    d2k_qw_hdr h;
    if (d2k_qw_hdr_parse(p, n, 0, &h) != 0 || !h.long_hdr ||
        h.type != D2K_QW_LT_INITIAL || h.dcid_len > D2K_QW_CID_MAX) {
        return -1;
    }
    memcpy(out, p + h.dcid_off, h.dcid_len);
    *out_len = (uint8_t)h.dcid_len;
    return 0;
}

/* Запоминает датаграмму полёта. Повтор по таймеру PTO (те же байты того же
   потока) не удваивает запись: полёт от повторов не удлиняется. */
static void init_ring_add(d2k_session *s, const d2k_key *key,
                          const uint8_t *dg, size_t len) {
    uint8_t dcid[D2K_QW_CID_MAX];
    uint8_t dcid_len = 0;
    if (len == 0 || len > D2K_QW_MAX_DGRAM || initial_dcid(dg, len, dcid, &dcid_len) != 0) {
        return;
    }
    for (size_t i = 0; i < s->init_ring_n; i++) {
        if (s->init_ring[i].len == len && d2k_key_equal(&s->init_ring[i].key, key) &&
            memcmp(s->init_ring[i].dg, dg, len) == 0) {
            return;
        }
    }
    size_t at = s->init_ring_next;
    s->init_ring[at].key = *key;
    memcpy(s->init_ring[at].dcid, dcid, dcid_len);
    s->init_ring[at].dcid_len = dcid_len;
    s->init_ring[at].len = (uint16_t)len;
    memcpy(s->init_ring[at].dg, dg, len);
    s->init_ring_next = (at + 1) % D2K_SESSION_INIT_RING;
    if (s->init_ring_n < D2K_SESSION_INIT_RING) { s->init_ring_n++; }
}

/* Забывает датаграммы потока: его полёт уже собран и снят. */
static void init_ring_drop(d2k_session *s, const d2k_key *key) {
    for (size_t i = 0; i < s->init_ring_n; i++) {
        if (d2k_key_equal(&s->init_ring[i].key, key)) {
            s->init_ring[i].len = 0;
            s->init_ring[i].dcid_len = 0;
            memset(&s->init_ring[i].key, 0, sizeof s->init_ring[i].key);
        }
    }
}

/* Пачка полёта: все датаграммы этого потока с тем же DCID, по порядку
   прихода. 0 — пачка не собралась (вытеснена, не поместилась) и вызывающий
   кладёт одну датаграмму, как раньше: контроллер отвергнет её как обрывок, и
   это честнее выдуманной склейки. */
static size_t init_ring_pack(const d2k_session *s, const d2k_key *key,
                             const uint8_t *last, size_t last_len,
                             uint8_t *out, size_t cap) {
    uint8_t dcid[D2K_QW_CID_MAX];
    uint8_t dcid_len = 0;
    if (initial_dcid(last, last_len, dcid, &dcid_len) != 0) {
        return 0;
    }
    const uint8_t *dg[D2K_QSNAP_MAX_DGRAMS];
    size_t len[D2K_QSNAP_MAX_DGRAMS];
    size_t n = 0;
    /* Кольцевой обход от самой старой записи: порядок в пачке — порядок на
       проводе, иначе номера пакетов пойдут вспять. */
    for (size_t k = 0; k < s->init_ring_n && n < D2K_QSNAP_MAX_DGRAMS; k++) {
        size_t i = (s->init_ring_next + D2K_SESSION_INIT_RING - s->init_ring_n + k)
                   % D2K_SESSION_INIT_RING;
        if (s->init_ring[i].len == 0 ||
            !d2k_key_equal(&s->init_ring[i].key, key) ||
            s->init_ring[i].dcid_len != dcid_len ||
            memcmp(s->init_ring[i].dcid, dcid, dcid_len) != 0) {
            continue;
        }
        dg[n] = s->init_ring[i].dg;
        len[n] = s->init_ring[i].len;
        n++;
    }
    if (n == 0) {
        return 0;
    }
    return d2k_qsnap_pack(dg, len, n, out, cap);
}

/* Номер слота снимка по транспорту. Всё, кроме UDP, живёт в слоте TCP: других
   транспортов у нас нет, а заводить третий слот под несуществующее значило бы
   завести неизмеренную сущность. */
static size_t slot_of(uint8_t transport) { return transport == 17 ? 1u : 0u; }
static size_t shape_slot(uint8_t transport, uint8_t family) {
    return slot_of(transport) + (family == 6 ? 2u : 0u);
}

static uint32_t next_fragment_id(d2k_session *s) {
    if (!s->fragment_seeded) {
        FILE *f=fopen("/dev/urandom","rb");
        if (!f) return 0;
        size_t n=fread(&s->fragment_id,1,sizeof s->fragment_id,f);
        fclose(f);
        if (n!=sizeof s->fragment_id) return 0;
        s->fragment_seeded=1;
    }
    if ((uint16_t)++s->fragment_id==0) ++s->fragment_id;
    return s->fragment_id;
}

d2k_session *d2k_session_new(size_t capacity, size_t journal) {
    d2k_session *s = calloc(1, sizeof *s);
    if (!s) {
        return NULL;
    }
    /* НЕ НОЛЬ. calloc обнулил бы поле, а ноль — это PREROUTING, то есть
       «серверная сторона»: молча и для ВСЕХ прежних вызывающих, которые про
       крючок ничего не знают. Умолчание обязано значить «не сказали». */
    s->hook = D2K_HOOK_UNKNOWN;
    s->stall_budget[0] = D2K_TCP_STALL_FIELD_BUDGET;
    s->n_stall_budget = 1;
    s->flows = d2k_track_new(capacity);
    /* Тот же capacity, что у TCP-таблицы: это не новое число, а
       унаследованное — оператор уже выбрал бюджет числа потоков одним
       параметром (--flows), заводить второй знак специально под UDP было бы
       придуманной величиной без замера. */
    s->uflows = d2k_track_new(capacity);
    s->jrn = d2k_journal_new(journal);
    /* Вместимость таблицы планов выводится из вместимости таблицы TCP-потоков
       (--flows), а не подбирается литералом: цели не может понадобиться план,
       если у неё нет потока, значит верхняя граница числа целей — число
       отслеживаемых потоков. d2k_track_capacity(s->flows), а не сырой
       capacity — округление до степени двойки внутри d2k_track_new делает
       фактическую вместимость таблицы потоков и таблицы планов равными на
       ту же величину, а не рассинхронизированными на округление. Если
       s->flows не создался (OOM), d2k_track_capacity(NULL) == 0, и
       d2k_plantab_new(0) вернёт NULL — это уже разбирает проверка ниже, как
       и отказ любой другой из таблиц. */
    s->plans = d2k_plantab_new(d2k_track_capacity(s->flows));
    if (!s->flows || !s->uflows || !s->plans || (journal > 0 && !s->jrn)) {
        d2k_plantab_free(s->plans);
        d2k_journal_free(s->jrn);
        d2k_track_free(s->uflows);
        d2k_track_free(s->flows);
        free(s);
        return NULL;
    }
    return s;
}

void d2k_session_free(d2k_session *s) {
    if (!s) {
        return;
    }
    d2k_pf_table_free(&s->preflight);
    d2k_pf_lease_free(&s->preflight_leases);
    free(s->preflight_contexts);
    d2k_plantab_free(s->plans);
    d2k_journal_free(s->jrn);
    d2k_track_free(s->uflows);
    d2k_track_free(s->flows);
    d2k_plan_free(s->plan);
    free(s);
}

/* The switch is set once by the daemon before reading packets. Allocation
 * failure leaves the path disabled, and cannot take ownership of a SYN. */
void d2k_session_preflight_ipv6(d2k_session *s, int enabled) {
    if (s) s->preflight_ipv6 = enabled;
}
void d2k_session_set_packet_path(d2k_session *s,uint32_t path) {
    if(s)s->packet_path=path;
}
int d2k_session_set_preflight(d2k_session *s, int enabled) {
    if (!s) return -1;
    if (!enabled) {
        if (s->preflight_enabled && d2k_pf_next_ns(&s->preflight)) return -1;
        s->preflight_enabled = 0;
        return 0;
    }
    if (!s->preflight.flows) {
        unsigned cap = (unsigned)d2k_track_capacity(s->flows);
        if (!d2k_pf_table_init(&s->preflight, cap)) return -1;
        s->preflight_contexts = calloc(cap, sizeof *s->preflight_contexts);
        if (!s->preflight_contexts) {
            d2k_pf_table_free(&s->preflight);
            return -1;
        }
        if (d2k_pf_lease_init(&s->preflight_leases,cap)) {
            free(s->preflight_contexts);s->preflight_contexts=NULL;
            d2k_pf_table_free(&s->preflight);return -1;
        }
    }
    if(d2k_hello_from_profile(D2K_SHAPE_LEGACY,"www.google.com",
        s->provider_probe_hello,sizeof s->provider_probe_hello,
        &s->provider_probe_len))return -1;
    s->preflight_enabled = 1;
    return 0;
}
int d2k_session_provider_ips_load(d2k_session *s,const char *path,uint64_t now_seconds) {
    return s?d2k_provider_ips_load(&s->provider_ips,path,now_seconds):-1;
}
int d2k_session_set_preflight_lease(d2k_session *s,const d2k_pf_scope *scope,uint64_t now,
    uint64_t expires,const uint8_t id[16],d2k_plan *plan) {
    if(!s||!s->preflight_enabled){d2k_plan_free(plan);return -2;}
    return d2k_pf_lease_set(&s->preflight_leases,scope,now,expires,id,plan);
}
int d2k_session_del_preflight_lease(d2k_session *s,const d2k_pf_scope *scope,const uint8_t id[16]) {
    return s?d2k_pf_lease_del(&s->preflight_leases,scope,id):0;
}
void d2k_session_invalidate_preflight_lease(d2k_session *s,const d2k_pf_scope *scope) {
    if(s)d2k_pf_lease_invalidate(&s->preflight_leases,scope);
}
const d2k_plan *d2k_session_find_preflight_lease(d2k_session *s,const d2k_pf_scope *scope,uint64_t now) {
    return s?d2k_pf_lease_find(&s->preflight_leases,scope,now):NULL;
}
const d2k_binding_context *d2k_session_preflight_lease_binding(d2k_session *s,const d2k_plan *plan) {
    return s?d2k_pf_lease_binding(&s->preflight_leases,plan):NULL;
}
static void preflight_event(d2k_session *s, preflight_context *c, uint64_t now, uint8_t kind) {
    d2k_journal_add_preflight(s->jrn, now, &c->key, kind, c->pieces,
        now >= c->started_ns ? now - c->started_ns : 0, c->client_side,
        c->plan_id, c->trial_id, &c->binding);
}
/* Scan only after a tick or the affected flow's packet; stored original is a
 * lookup witness, not another packet fed to the FSM. Terminal contexts release
 * their metadata slot; FSM terminal entries still suppress repeat same-ISN SYN. */
static void preflight_progress(d2k_session *s, const d2k_key *key, uint64_t now) {
    for (unsigned i = 0; i < s->preflight.cap; i++) {
        preflight_context *c = &s->preflight_contexts[i];
        if (!c->used || (key && !d2k_key_equal(&c->key, key))) continue;
        d2k_pkt p = {0}; p.wire = c->syn; p.wire_len = c->syn_len;
        d2k_pf_stage stage;
        if (!d2k_pf_get_stage(&s->preflight, &p, &stage)) { c->used = 0; continue; }
        if (stage != c->stage) {
            if (stage == PF_GAVE_UP) preflight_event(s, c, now, D2K_JRN_PREFLIGHT_GAVE_UP);
            c->stage = stage;
        }
        if (stage == PF_DONE || stage == PF_GAVE_UP) c->used = 0;
    }
}
void d2k_session_preflight_output_sent(d2k_session *s,const uint8_t *p,size_t n,unsigned clear) {
    if (!s || !s->preflight_enabled) return;
    d2k_pkt pkt={0}; pkt.wire=p; pkt.wire_len=n;
    d2k_pf_output_sent(&s->preflight,&pkt,clear);
}
void d2k_session_preflight_send_cap(d2k_session *s,size_t cap) {
    if (s) s->preflight_send_cap=cap;
}
static preflight_context *preflight_context_for(d2k_session *s, const d2k_key *key) {
    for (unsigned i = 0; i < s->preflight.cap; i++) {
        preflight_context *c = &s->preflight_contexts[i];
        if (c->used && d2k_key_equal(&c->key, key)) return c;
    }
    return NULL;
}
static int preflight_program_identity(d2k_session *s,const d2k_plan *p,
    d2k_binding_context *binding,uint8_t trial[16]) {
    const d2k_binding_context *lease=d2k_pf_lease_binding(&s->preflight_leases,p);
    if(lease) {
        *binding=*lease;memcpy(trial,p->binding_trial_id,16);return 1;
    }
    d2k_plantab_trial(s->plans,p,trial);
    return d2k_plantab_binding(s->plans,p,binding);
}
static int preflight_outgoing_admitted(d2k_session *s,const d2k_key *key,
    const d2k_flow *fl,const d2k_plan *p) {
    d2k_binding_context binding={0};uint8_t trial[16]={0};
    if(!p || !p->preflight || !p->pf_handover_apply ||
       !preflight_program_identity(s,p,&binding,trial))return 0;
    preflight_context *owner=preflight_context_for(s,key);
    if(owner && owner->stage==PF_HANDOVER && owner->path==s->packet_path &&
       !memcmp(owner->plan_id,d2k_plan_id(p),16) && !memcmp(owner->trial_id,trial,16) &&
       d2k_binding_equal(&owner->binding,&binding))return 1;
    /* A completed own outgoing execution may retry after its SYN context
     * was released. Flow reuse, plan/lease replacement and path changes
     * cannot borrow this admission. */
    return fl && fl->preflight_outgoing_owned && fl->preflight_outgoing_path==s->packet_path &&
        !memcmp(fl->execution_plan_id,d2k_plan_id(p),16) &&
        !memcmp(fl->execution_trial_id,trial,16) &&
        d2k_binding_equal(&fl->execution_binding,&binding);
}
void d2k_session_preflight_complete_on(d2k_session *s,const uint8_t *p,size_t n,
                                      uint64_t now,d2k_pf_out *out,uint32_t path) {
    out->count=0;
    if (!s || !s->preflight_enabled) return;
    d2k_hold_info v;
    if (!d2k_hold_parse(p,n,&v)) return;
    preflight_context *context = preflight_context_for(s, &v.key);
    if (!context || context->path != path) return;
    d2k_flow *fl=d2k_track_find(s->flows,&v.key);
    /* A preflight-only endpoint has no stream plan to enable holding.
     * Keep the CT watch through every fragment of its normal capture. */
    if (!fl || !fl->hello_capture_done) return;
    d2k_pkt pkt={0}; pkt.wire=p; pkt.wire_len=n;
    d2k_pf_complete(&s->preflight,&pkt,out);
    preflight_progress(s,NULL,now);
}
void d2k_session_preflight_complete(d2k_session *s,const uint8_t *p,size_t n,
                                    uint64_t now,d2k_pf_out *out) {
    d2k_session_preflight_complete_on(s,p,n,now,out,0);
}
void d2k_session_preflight_original_sent(d2k_session *s,const uint8_t *p,size_t n,uint64_t now) {
    if (!s || !s->preflight_enabled) return;
    for (unsigned i=0;i<s->preflight.cap;i++) {
        preflight_context *c=&s->preflight_contexts[i];
        if (!c->used || c->stage!=PF_RESYN || c->handover_reported ||
            c->syn_len!=n || memcmp(c->syn,p,n)) continue;
        c->handover_reported=1;
        preflight_event(s,c,now,D2K_JRN_PREFLIGHT_HANDOVER);
        break;
    }
}
void d2k_session_preflight_flush(d2k_session *s,uint64_t now,d2k_pf_out *out) {
    out->count=0;
    if (!s || !s->preflight_enabled) return;
    for (unsigned i=0;i<s->preflight.cap;i++) {
        preflight_context *c=&s->preflight_contexts[i];
        if (!c->used) continue;
        d2k_pkt p={0};p.wire=c->syn;p.wire_len=c->syn_len;
        s->preflight_calls++;
        d2k_pf_abort(&s->preflight,&p,out);
        preflight_progress(s,&c->key,now);
        return; /* caller drains until next_ns=0 */
    }
    /* Terminal flows may still own a locally failed cleanup token. */
    d2k_pf_tick(&s->preflight,UINT64_MAX,out);
}
void d2k_session_preflight_abort(d2k_session *s, const uint8_t *p, size_t n,
                                   uint64_t now, d2k_pf_out *out) {
    out->count = 0;
    if (!s || !s->preflight_enabled) return;
    d2k_hold_info v;
    if (!d2k_hold_parse(p, n, &v)) return;
    for (unsigned i=0;i<s->preflight.cap;i++) {
        preflight_context *c=&s->preflight_contexts[i];
        if (!c->used || !d2k_key_equal(&c->key,&v.key)) continue;
        d2k_pkt original={0};original.wire=c->syn;original.wire_len=c->syn_len;
        s->preflight_calls++;
        d2k_pf_abort(&s->preflight,&original,out);
        preflight_progress(s,&v.key,now);
        break;
    }
}
uint64_t d2k_session_preflight_calls(const d2k_session *s) { return s ? s->preflight_calls : 0; }
uint64_t d2k_session_preflight_next_ns(const d2k_session *s) {
    return s && s->preflight_enabled ? d2k_pf_next_ns(&s->preflight) : 0;
}
void d2k_session_preflight_tick(d2k_session *s, uint64_t now, d2k_pf_out *out) {
    out->count = 0;
    if (!s || !s->preflight_enabled) return;
    s->preflight_calls++;
    d2k_pf_tick(&s->preflight, now, out);
    preflight_progress(s, NULL, now);
}
int d2k_session_preflight_packet_path(d2k_session *s, const uint8_t *bytes, size_t n,
                                  uint64_t now, d2k_pf_out *out, uint32_t path) {
    out->count = 0;
    if (!s || !s->preflight_enabled || s->route_mark || !bytes || !n ||
        ((bytes[0] >> 4) == 6 && !s->preflight_ipv6))
        return 0;
    d2k_hold_info v;
    if (!d2k_hold_parse(bytes, n, &v)) return 0;
    d2k_pkt p = {0}; p.wire = bytes; p.wire_len = n;
    /* Known flows are dispatched by their actual initiating side, independent
     * of port heuristics and of later plan replacement/deletion. */
    preflight_context *context = preflight_context_for(s, &v.key);
    if (context) {
        if (context->path != path) return 0;
        int client = (v.src_low ? D2K_CLIENT_SIDE_LOW : D2K_CLIENT_SIDE_HIGH) == context->client_side;
        s->preflight_calls++;
        d2k_pf_verdict verdict = client ? d2k_pf_client_pkt(&s->preflight, &p, now, out)
                                        : d2k_pf_server_pkt(&s->preflight, &p, now, out);
        preflight_progress(s, &v.key, now);
        return verdict == PF_ACT_DROP;
    }
    /* Admission needs explicit outbound NFQUEUE context; a SYN on an incoming
     * hook is not authorization to create a probe. No name exists at SYN. */
    if ((v.flags & 0x17) != 2 ||
        (s->hook != D2K_HOOK_OUTPUT && s->hook != D2K_HOOK_POSTROUTING)) return 0;
    const uint8_t *tcp = bytes + v.ihl;
    uint16_t sport, dport; memcpy(&sport, tcp, 2); memcpy(&dport, tcp+2, 2);
    /* A bare SYN carries neither TLS shape nor name. It may use a lease only
     * when one live controller-authorized context matches the visible tuple. */
    const uint8_t shapes[] = {D2K_PLAN_SHAPE_MODERN, D2K_PLAN_SHAPE_LEGACY, D2K_PLAN_SHAPE_ECH_TCP, D2K_PLAN_SHAPE_RAW};
    const d2k_plan *use = NULL;
    const d2k_pf_lease *lease = NULL;
    for (size_t i = 0; i < sizeof shapes; i++) {
        const d2k_plan *candidate = d2k_plantab_find_target_endpoint_tr(s->plans, NULL, 0,
            v.dst.bytes, v.dst.family, now, shapes[i], sport, dport, 6);
        if (!candidate || !candidate->preflight || !candidate->binding_temporary ||
            !candidate->preflight_trial_sport || candidate->preflight_trial_sport != sport) continue;
        if (use && use != candidate) return 0;
        use = candidate;
    }
    if (!use) {
        d2k_packet_view ip;
        if (!d2k_packet_parse(bytes, n, &ip)) return 0;
        lease = d2k_pf_lease_match_syn(&s->preflight_leases, v.dst.family,
            ip.src.bytes, v.dst.bytes, dport, path, now);
        if (lease) use = lease->plan;
    }
    int provider_ip=!use && dport==htons(443) &&
        d2k_provider_ips_has(&s->provider_ips,v.dst.bytes,v.dst.family,(uint64_t)time(NULL));
    if (!provider_ip && (!use || !use->binding_temporary || !use->pf_hello || !use->pf_hello_len)) return 0;
    for (unsigned i = 0; i < s->preflight.cap; i++)
        if (!s->preflight_contexts[i].used) { context = &s->preflight_contexts[i]; break; }
    if (!context) return 0;
    d2k_pf_params params = provider_ip ? (d2k_pf_params){
        .window=1,.wscale=1,.pieces=1,.reference_hello=1,
        .timeout_ms=4000,.resyn_delay_ms=60,.resyn_sends=6,
        .resyn_timeout_ms=500,.hello=s->provider_probe_hello,
        .hello_len=s->provider_probe_len,.send_cap=s->preflight_send_cap
    } : (d2k_pf_params){ .window=use->pf_window, .wscale=use->pf_wscale,
        .pieces=use->pf_pieces, .hello_own=use->pf_hello_own, .timeout_ms=use->pf_timeout_ms,
        .reference_hello=!use->pf_hello_own && use->pf_wscale==D2K_PF_REFERENCE_WSCALE &&
                         use->pf_pieces==1,
        .resyn_delay_ms=use->pf_resyn_delay_ms, .resyn_sends=use->pf_resyn_sends,
        .resyn_timeout_ms=use->pf_resyn_timeout_ms,
        .hello=use->pf_hello, .hello_len=use->pf_hello_len, .send_cap=s->preflight_send_cap };
    s->preflight_calls++;
    if (d2k_pf_client_syn(&s->preflight, &p, &params, now, out) != PF_ACT_DROP) return 0;
    memset(context, 0, sizeof *context);
    context->used = 1; context->key = v.key; context->path = path;
    memcpy(context->syn, bytes, v.total); context->syn_len = v.total;
    context->started_ns = now; context->pieces = params.pieces;
    context->client_side = v.src_low ? D2K_CLIENT_SIDE_LOW : D2K_CLIENT_SIDE_HIGH;
    context->stage = PF_PROBE_SYN;
    if(use)memcpy(context->plan_id, d2k_plan_id(use), D2K_PLAN_ID_LEN);
    if (lease) {
        memcpy(context->trial_id, lease->id, sizeof context->trial_id);
        context->binding = lease->binding;
    } else if(use) {
        d2k_plantab_trial(s->plans, use, context->trial_id);
        (void)d2k_plantab_binding(s->plans, use, &context->binding);
    }
    preflight_event(s, context, now, D2K_JRN_PREFLIGHT_START);
    return 1;
}

int d2k_session_preflight_packet(d2k_session *s,const uint8_t *bytes,size_t n,
    uint64_t now,d2k_pf_out *out) {
    return d2k_session_preflight_packet_path(s,bytes,n,now,out,0);
}

void d2k_session_set_plan(d2k_session *s, d2k_plan *p) {
    if (!s) {
        return;
    }
    d2k_plan_free(s->plan);
    s->plan = p;
    s->plan_revision++;
}

/* Сравнение имени цели без учёта регистра. Своя функция, а не strncasecmp:
   тот зависит от локали. */
static int name_same(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    if (alen != blen) {
        return 0;
    }
    for (size_t i = 0; i < alen; i++) {
        uint8_t x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') { x = (uint8_t)(x - 'A' + 'a'); }
        if (y >= 'A' && y <= 'Z') { y = (uint8_t)(y - 'A' + 'a'); }
        if (x != y) {
            return 0;
        }
    }
    return 1;
}

static int tcp_retry_ready(const d2k_session *s, const d2k_flow *fl) {
    return fl->retry_tls_len && fl->plan_done && !fl->sends_left &&
        !fl->sends_failed && !fl->damaged && !fl->rev_payload_after_hello &&
        !fl->reply_hidden_told && !fl->saw_rev_rst &&
        fl->retry_slot < D2K_HOLD_SLOTS && fl->retry_token &&
        s->retries[fl->retry_slot].token == fl->retry_token &&
        fl->retry_plan_revision == d2k_session_plan_revision(s);
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

/* Отказ по плану в журнал. Отдельной функцией, чтобы каждая точка отказа
   писала одинаково: журнал, в котором половина отказов не отмечена, хуже
   отсутствующего — он выглядит полным. */
/* ОТКАЗ ПРИМЕНИТЬ ПЛАН. code — D2K_REFUSE_*: ноль значит «плана для цели
   нет» (обычное состояние транзитного потока), D2K_REFUSE_NOT_APPLIED —
   найденный план отвергнут исполнителем.
 *
 * О ЗОНДОВОМ ПОТОКЕ МОЛЧИМ ТОЛЬКО ПРИ НУЛЕ. Прежде молчали всегда, и
 * контроллер не мог узнать, что его зонд ушёл голым: он видел лишь
 * отсутствие применения и после одного повтора судил кандидата (поле
 * 13.10.2026, forum.ru-board.com — см. D2K_REFUSE_NOT_APPLIED). Для своего
 * зонда отказ исполнителя и есть результат опыта, а молчать о нулевом
 * по-прежнему нужно: план просто не успел доехать, и это ждёт сам
 * контроллер. */
static void refuse_coded(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                         const char *why, uint8_t code, const d2k_plan *use) {
    d2k_flow *fl = k ? d2k_track_find(k->proto == 17 ? s->uflows : s->flows, k)
                     : NULL;
    if (fl && fl->controller_probe && code == D2K_REFUSE_NONE) { return; }
    uint8_t trial[D2K_TRIAL_ID_LEN];
    memset(trial, 0, sizeof trial);
    if (use) { d2k_plantab_trial(s->plans, use, trial); }
    d2k_journal_add_refused(s->jrn, at_ns, k, code,
                            use ? d2k_plan_id(use) : NULL,
                            use ? trial : NULL, why);
}

static void refuse(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                   const char *why) {
    refuse_coded(s, at_ns, k, why, D2K_REFUSE_NONE, NULL);
}

/* Есть ли в опциях TCP пакета метка времени (вид 8, длина 10). Разбор тот же,
   что у сборщика (wire.c): побайтно, NOP и EOL отдельно, кривая длина — «нет». */
static int tcp_options_have_timestamp(const uint8_t *o, size_t n) {
    for (size_t off = 0; off < n;) {
        uint8_t kind = o[off];
        if (kind == 0) { break; }
        if (kind == 1) { off++; continue; }
        if (off + 2 > n || o[off + 1] < 2 || o[off + 1] > n - off) { return 0; }
        if (kind == 8 && o[off + 1] == 10) { return 1; }
        off += o[off + 1];
    }
    return 0;
}

/* План построен и передан на отправку. Ключ потока и идентификатор плана
   уезжают вызывающему, а на потоке взводится счёт непокинувших машину
   посылок: по нему отправляющий и скажет потом, доисполнен план или нет.

   Одна функция на обе ветки (TCP и UDP/QUIC) нарочно: разойдись они, одна из
   двух однажды забыла бы взвести счёт, и «план доисполнен» по этому
   транспорту перестало бы появляться молча. */
static const d2k_plan *measured_probe(d2k_session *s,const d2k_flow *fl,
    const d2k_packet_view *ip,const uint8_t *header,uint32_t seq,const uint8_t *payload,
    size_t len,uint64_t now,uint8_t *trial) {
    d2k_ct_tuple tuple;memset(&tuple,0,sizeof tuple);
    tuple.family=ip->family;tuple.proto=ip->protocol;
    memcpy(tuple.src,ip->src.bytes,16);memcpy(tuple.dst,ip->dst.bytes,16);
    memcpy(tuple.sport_be,header,2);memcpy(tuple.dport_be,header+2,2);
    return d2k_plantab_find_measured_probe(s->plans,&tuple,fl->flow_epoch,fl->incarnation,
                                         seq,payload,len,now,trial);
}

static const d2k_plan *owned_dns_probe(d2k_session *s,const d2k_packet_view *ip,
    const uint8_t *l4,int controller_probe,const uint8_t *payload,size_t length,
    uint64_t now,uint8_t trial[16],int *reserved) {
    d2k_addr_probe_flow flow={.family=ip->family,.transport=ip->protocol};
    size_t size=ip->family==6 ? 16 : 4;
    memcpy(ip->family==6 ? flow.src_ip6 : flow.src_ip4,ip->src.bytes,size);
    memcpy(ip->family==6 ? flow.dst_ip6 : flow.dst_ip4,ip->dst.bytes,size);
    memcpy(&flow.src_port_be,l4,2);
    memcpy(&flow.dst_port_be,l4+2,2);
    return d2k_plantab_find_dns_probe(s->plans,&flow,controller_probe,payload,length,now,trial,reserved);
}

static void plan_handed_off(d2k_session *s, d2k_result *out, d2k_flow *fl, const d2k_key *k,
                            const d2k_plan *use, const uint8_t *trial_id) {
    int continuation=(fl->stream_plan_stage==2 || fl->stream_plan_stage==4) &&
        d2k_plan_after_split(use,NULL,NULL,NULL) &&
        !memcmp(fl->execution_plan_id,d2k_plan_id(use),D2K_PLAN_ID_LEN);
    out->applied = 1;
    out->key = *k;
    const uint8_t *id = d2k_plan_id(use);
    if (id) {
        memcpy(out->plan_id, id, D2K_PLAN_ID_LEN);
    }
    if (trial_id) { memcpy(out->trial_id, trial_id, D2K_TRIAL_ID_LEN); }
    else if(use->preflight && use->pf_handover_apply) {
        (void)preflight_program_identity(s,use,&out->binding,out->trial_id);
    } else { d2k_plantab_trial(s->plans,use,out->trial_id); }
    /* n_out не может превысить вместимость out[] (16): выше стоит явная
       проверка, отвергающая план целиком. */
    /* One completion for each raw send AND one for the original's NF verdict. */
    /* Кто владеет оригиналом этой попытки. Вердикт уже посчитан обеими
       ветками выше; сохраняем его на потоке, потому что веткам отказа, где
       d2k_result недоступен, решать больше нечем. */
    fl->orig_taken = (out->verdict == D2K_VERDICT_DROP);
    fl->sends_left = (uint8_t)(out->n_out + 1);
    fl->sends_failed = 0;
    fl->sends_done = 0;
    fl->raw_execution_len = 0;
    fl->raw_proof_stage = 0;
    fl->raw_reply_len = 0;
    fl->udp_replan = 0;
    if(!continuation) {
        if (++s->next_execution == 0) { ++s->next_execution; }
        fl->execution_id=s->next_execution;
    }
    out->execution_id=fl->execution_id;
    if(use->preflight && use->pf_handover_apply) {
        uint8_t unused[16];(void)preflight_program_identity(s,use,&out->binding,unused);
    } else (void)d2k_plantab_binding(s->plans, use, &out->binding);
    fl->preflight_outgoing_owned=use->preflight && use->pf_handover_apply;
    fl->preflight_outgoing_path=s->packet_path;
    fl->execution_binding = out->binding;
    memcpy(fl->execution_plan_id, out->plan_id, D2K_PLAN_ID_LEN);
    memcpy(fl->execution_trial_id, out->trial_id, D2K_TRIAL_ID_LEN);
}

/* Unknown applications have no generic success parser. These observations
 * prove only full echo or ordered bidirectional progress on this execution.
 * A lone response, an empty datagram and repeated bytes are insufficient. */
static void raw_proof_begin(d2k_flow *fl, const uint8_t *data, size_t len,
                            uint32_t seq, uint32_t ack) {
    fl->raw_execution_seq = seq;
    fl->raw_execution_len = (uint16_t)len;
    fl->raw_proof_stage = 0;
    fl->raw_reply_len = 0;
    fl->raw_reply_seen = 0;
    fl->raw_echo_seq = ack;
    fl->raw_echo_len = fl->raw_echo_last_len = 0;
    fl->raw_echo_disabled = 0;
    d2k_sha256_init(&fl->raw_echo_hash);
    d2k_sha256(data, len, fl->raw_execution_digest);
    fl->exchange_told = 0;
}
static int raw_echo_packet(d2k_flow *fl, const uint8_t *data, size_t len,
                            uint32_t seq, uint32_t ack, const uint8_t digest[32]) {
    if (fl->raw_echo_disabled || fl->raw_proof_stage >= 2 || fl->raw_execution_len <= 1)
        return 0;
    int32_t off = (int32_t)(seq - fl->raw_echo_seq);
    if (off < 0 || (uint32_t)off > fl->raw_echo_len) return 0; /* gap: wait for retransmit */
    if ((uint32_t)off < fl->raw_echo_len) {
        if (seq != fl->raw_echo_last_seq || len != fl->raw_echo_last_len ||
            memcmp(digest, fl->raw_echo_last_digest, 32))
            fl->raw_echo_disabled = 1; /* ambiguous overlapping stream */
        return 0;
    }
    if (len > (size_t)(fl->raw_execution_len - fl->raw_echo_len)) {
        fl->raw_echo_disabled = 1;
        return 0;
    }
    d2k_sha256_update(&fl->raw_echo_hash, data, len);
    fl->raw_echo_len += (uint16_t)len;
    fl->raw_echo_last_seq = seq;fl->raw_echo_last_len = (uint16_t)len;
    memcpy(fl->raw_echo_last_digest, digest, 32);
    if (fl->raw_echo_len == fl->raw_execution_len) {
        uint8_t full[32];d2k_sha256_ctx hash = fl->raw_echo_hash;
        d2k_sha256_final(&hash, full);
        if (memcmp(full, fl->raw_execution_digest, 32)) {
            fl->raw_echo_disabled = 1;
            return 0;
        }
        return d2k_rm_ack_covers(ack, fl->raw_execution_seq, fl->raw_execution_len);
    }
    return 0;
}
static uint8_t raw_proof_packet(d2k_flow *fl, int client, const uint8_t *data,
                                size_t len, uint32_t seq, uint32_t ack, int terminal) {
    if (!fl->raw_execution_len || fl->exchange_told || !len || len > UINT16_MAX)
        return 0;
    int tcp = fl->key.proto == 6;
    uint8_t digest[32];
    d2k_sha256(data, len, digest);
    if (!client && tcp && raw_echo_packet(fl, data, len, seq, ack, digest))
        return D2K_RAW_PROOF_ECHO;
    if (len <= 1 || terminal) return 0;
    if (client) {
        if (fl->raw_proof_stage != 1 ||
            (len == fl->raw_execution_len && !memcmp(digest, fl->raw_execution_digest, 32)))
            return 0;
        if (tcp && (!d2k_rm_ack_covers(ack, fl->raw_reply_seq, fl->raw_reply_len) ||
            (int32_t)(seq - (fl->raw_execution_seq + fl->raw_execution_len)) < 0))
            return 0;
        fl->raw_proof_stage = 2;
        fl->raw_execution_seq = seq;
        fl->raw_execution_len = (uint16_t)len;
        memcpy(fl->raw_execution_digest, digest, 32);
        return 0;
    }
    if (tcp && !d2k_rm_ack_covers(ack, fl->raw_execution_seq, fl->raw_execution_len))
        return 0;
    if (!tcp && fl->raw_proof_stage < 2 && len == fl->raw_execution_len &&
        !memcmp(digest, fl->raw_execution_digest, 32))
        return D2K_RAW_PROOF_ECHO;
    uint64_t seen = (UINT64_C(1) << (digest[0] & 63)) |
                    (UINT64_C(1) << (digest[1] & 63));
    if (fl->raw_proof_stage < 2) fl->raw_reply_seen |= seen;
    if (!fl->raw_proof_stage) {
        fl->raw_proof_stage = 1;
        fl->raw_reply_len = (uint16_t)len;
        fl->raw_reply_seq = seq;
        memcpy(fl->raw_reply_digest, digest, 32);
    } else if (fl->raw_proof_stage == 2 &&
               (fl->raw_reply_seen & seen) != seen &&
               (len != fl->raw_reply_len || memcmp(digest, fl->raw_reply_digest, 32)) &&
               (!tcp || (int32_t)(seq - (fl->raw_reply_seq + fl->raw_reply_len)) >= 0)) {
        return D2K_RAW_PROOF_PROGRESS;
    }
    return 0;
}

/* Таблица, в которой живёт поток этого ключа. Транспорт лежит в самом ключе,
   и выбирать таблицу по чему-то ещё было бы вторым источником истины. */
static d2k_table *table_of(d2k_session *s, const d2k_key *k) {
    return (k->proto == 17) ? s->uflows : s->flows;
}

/* Подозрение. Отмечается ОДИН раз на поток: три улики об одном соединении
   выглядели бы как три соединения, а это разные факты.
   Слово «подозрение» выбрано вместо «блокировки» намеренно: §2.4 запрещает
   превращать наблюдение в диагноз, а §2.3 — сохранять отрицательный результат
   вообще. Отсюда ничего не пишется на диск. */
static void suspect_num(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                        d2k_flow *fl, uint8_t code, const d2k_jrn_detail *det,
                        uint32_t num) {
    if (fl->controller_probe || fl->suspected) {
        return;
    }
    fl->suspected = 1;
    s->suspects++;
    /* ПРИМЕНЯЛСЯ ЛИ ПЛАН К ЭТОМУ ПОТОКУ — говорим всегда (см. d_planned в
       d2k_journal.h). Знает это только датапат, и без его слова контроллер
       считает деградацией подтверждённой цели любое подозрение, в том числе
       о потоке, начатом до установки плана. */
    d2k_jrn_detail d;
    if (det) { d = *det; } else { memset(&d, 0, sizeof d); }
    d.planned = fl->plan_done ? D2K_PLANNED_YES : D2K_PLANNED_NO;
    d.client_shape = fl->client_shape;
    d.client_side = fl->dir_known ? (fl->init_low ? D2K_CLIENT_SIDE_LOW : D2K_CLIENT_SIDE_HIGH) : 0;
    d2k_journal_add_suspect_bound(s->jrn, at_ns, k, code, num, &d, fl);
}

static void suspect(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                    d2k_flow *fl, uint8_t code, const d2k_jrn_detail *det) {
    suspect_num(s, at_ns, k, fl, code, det, 0);
}

/* Зовётся при забвении потока по молчанию. Приветствие ушло, ответа с той
   стороны не было ни одного — и узнать это можно только здесь, в конце.

   У UDP такого обработчика НЕТ, и это решение, снятое с поля (задача 40,
   docs/field/2026-10-12g): калитка «поток QUIC истёк без прикладного
   доказательства» просуществовала три редакции и снята. Отличить молчащий
   поток от здорового наблюдаемыми датапата нечем — ни коротким заголовком
   1-RTT (5,3 % здоровых сеансов кладут его за окно очереди), ни упорством
   клиента (наших пакетов у кандидатов 11/12/6 против 6…12 у здоровых).
   Подробности и числа — в шапке test_quic_no_proof_ask. */
static void on_flow_expire(void *ctx, const d2k_flow *f) {
    d2k_session *s = ctx;
    d2k_capture_forget(&s->capture, &f->key);
    if (f->controller_probe || !f->saw_hello || f->rev_after_hello > 0 || f->suspected) {
        return;
    }
    /* Та же оговорка, что у sweep_one: без правила на обратное направление
       сервер невидим, и молчащим выглядит каждый поток. Улика тут сессионная
       (см. rev_seen): к моменту забвения поток мог не получить ни одного
       пакета оттуда именно потому, что его и не ждали. */
    if (!s->rev_seen[shape_slot(f->key.proto, f->key.family)] &&
        !(f->key.proto == 17 && s->udp_reverse_hook)) {
        return;
    }
    s->suspects++;
    d2k_jrn_detail d;
    memset(&d, 0, sizeof d);
    d.planned = f->plan_done ? D2K_PLANNED_YES : D2K_PLANNED_NO;
    d.client_shape = f->client_shape;
    d.client_side = f->dir_known ? (f->init_low ? D2K_CLIENT_SIDE_LOW : D2K_CLIENT_SIDE_HIGH) : 0;
    d2k_journal_add(s->jrn, f->last_ns, &f->key, D2K_JRN_SUSPECT, D2K_SUSPECT_SILENT, 0, &d, NULL, 0, NULL);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

/* ЗАПРОС IP DISCOVERY ГОЛОСА ДИСКОРДА — первый пакет голосового потока.
 *
 * Ровно 74 байта: тип 0x0001, длина 70, SSRC, 64 байта адреса и порт; в
 * ЗАПРОСЕ адрес ещё не заполнен, и 64 байта нулевые. Правило то же, что у
 * движка z2k (IsDiscordIpDiscoveryRequest, nfq2/protocol.c), — по нему боевой
 * профиль discord_udp голос и узнаёт. Порт не проверяется: сигнатура строгая
 * (74 байта и 64 нуля подряд), а порты ограничивает правило очереди. */
static int is_discord_ip_discovery(const uint8_t *d, size_t n) {
    if (n != 74 || d[0] != 0 || d[1] != 1 || d[2] != 0 || d[3] != 70) { return 0; }
    for (size_t i = 8; i < 72; i++) {
        if (d[i] != 0) { return 0; }
    }
    return 1;
}

static int is_discord_ip_discovery_response(const uint8_t *d, size_t n,
                                            const uint8_t ssrc[4]) {
    if (n != 74 || d[0] != 0 || d[1] != 2 || d[2] != 0 || d[3] != 70 ||
        memcmp(d + 4, ssrc, 4) != 0) { return 0; }
    int nonzero = 0;
    for (size_t i = 8; i < 72; i++) {
        unsigned char c = d[i];
        if (c == 0) { continue; }
        nonzero = 1;
        if (!((c >= '0' && c <= '9') || c == '.' || c == ':')) { return 0; }
    }
    return nonzero && (d[72] != 0 || d[73] != 0);
}

/* RFC 5389 Binding только: magic cookie и объявленная длина обязательны.
 * Один magic cookie без границ недостаточен — произвольный UDP с такими
 * байтами не должен становиться voice/STUN-доказательством. */
static int is_stun_binding(const uint8_t *d, size_t n, uint16_t type) {
    if (!d || n < 20 || (d[0] & 0xc0) != 0 ||
        ((size_t)d[2] << 8 | d[3]) % 4 != 0 ||
        20u + (((size_t)d[2] << 8) | d[3]) > n ||
        d[4] != 0x21 || d[5] != 0x12 || d[6] != 0xa4 || d[7] != 0x42 ||
        ((uint16_t)d[0] << 8 | d[1]) != type) {
        return 0;
    }
    size_t end = 20u + (((size_t)d[2] << 8) | d[3]);
    for (size_t off = 20; off < end;) {
        if (end - off < 4) { return 0; }
        size_t len = ((size_t)d[off + 2] << 8) | d[off + 3];
        size_t step = 4 + ((len + 3u) & ~(size_t)3u);
        if (step > end - off) { return 0; }
        off += step;
    }
    return 1;
}

/* ПОЯВЛЕНИЕ ПОТОКА БЕЗ ПРОТОКОЛА (этап 42). Один раз на поток: решение —
   сообщить или подавить — ставит флаг, повторы пакетов ничего не добавляют.
   Запас D2K_FLOW_FACT_BURST, пополнение D2K_FLOW_FACT_PER_S целыми фактами.
   Сторона клиента — только наблюдённая (крючок, SYN), иначе ноль. */
static void flow_fact(d2k_session *s, d2k_flow *fl, const d2k_key *key, uint64_t now_ns) {
    /* TCP без увиденного SYN подхвачен с середины (сессия его забыла, метка
       поздней доставки снова привела пакеты) — он не «появился» (этап 49). */
    if (fl->flow_told || fl->controller_probe || (key->proto == 6 && !fl->saw_syn)) return;
    fl->flow_told = 1;
    if (!s->flow_tok_ns) {
        s->flow_tokens = D2K_FLOW_FACT_BURST;
        s->flow_tok_ns = now_ns ? now_ns : 1;
    } else if (now_ns > s->flow_tok_ns) {
        const uint64_t step = 1000000000ull / D2K_FLOW_FACT_PER_S;
        uint64_t add = (now_ns - s->flow_tok_ns) / step;
        if (add >= D2K_FLOW_FACT_BURST) {
            s->flow_tokens = D2K_FLOW_FACT_BURST;
            s->flow_tok_ns = now_ns;
        } else if (add) {
            s->flow_tokens = s->flow_tokens + (uint32_t)add > D2K_FLOW_FACT_BURST
                ? D2K_FLOW_FACT_BURST : s->flow_tokens + (uint32_t)add;
            s->flow_tok_ns += add * step;
        }
    }
    if (!s->flow_tokens) { s->flow_suppressed++; return; }
    s->flow_tokens--;
    s->flow_told++;
    d2k_jrn_detail det;
    memset(&det, 0, sizeof det);
    det.client_side = fl->dir_known ? (fl->init_low ? D2K_CLIENT_SIDE_LOW : D2K_CLIENT_SIDE_HIGH) : 0;
    det.flow_incarnation=fl->incarnation;
    memcpy(det.flow_epoch,fl->flow_epoch,16);
    d2k_journal_add(s->jrn, now_ns, key, D2K_JRN_FLOW, 0, 0, &det, NULL, 0, NULL);
}

static int is_stun_request(const uint8_t *d, size_t n) {
    return is_stun_binding(d, n, 0x0001);
}

static int is_stun_response_for(const uint8_t *d, size_t n,
                                const uint8_t txid[12]) {
    if (!txid || !is_stun_binding(d, n, 0x0101) ||
        memcmp(d + 8, txid, 12) != 0) { return 0; }
    /* RFC 8489 6.3.3: Binding success requires XOR-MAPPED-ADDRESS.
       Framing and the transaction alone do not establish a valid response.
       is_stun_binding has already checked every attribute boundary, including
       those after the address. This is structural proof, not authentication. */
    size_t end = 20u + (((size_t)d[2] << 8) | d[3]);
    for (size_t off = 20; off < end;) {
        uint16_t type = (uint16_t)((uint16_t)d[off] << 8 | d[off + 1]);
        size_t len = ((size_t)d[off + 2] << 8) | d[off + 3];
        if (type == 0x0020) {
            return (len == 8 && d[off + 5] == 1) ||
                   (len == 20 && d[off + 5] == 2);
        }
        off += 4 + ((len + 3u) & ~(size_t)3u);
    }
    return 0;
}

/* A well-formed matching error is an observed response, never success. */
static int is_stun_error_for(const uint8_t *d,size_t n,const uint8_t txid[12]) {
    if(!is_stun_binding(d,n,0x0111) || memcmp(d+8,txid,12))return 0;
    size_t end=20u+((size_t)d[2]<<8)+d[3];
    for(size_t off=20;off<end;) {
        uint16_t type=(uint16_t)((uint16_t)d[off]<<8|d[off+1]);
        size_t len=((size_t)d[off+2]<<8)|d[off+3];
        if(type==0x0009) {
            if(len<4)return 0;
            unsigned cls=d[off+6]&7;
            return cls>=3 && cls<=6 && d[off+7]<=99;
        }
        off+=4+((len+3u)&~(size_t)3u);
    }
    return 0;
}

static d2k_stun_request_slot *stun_observe_request(d2k_flow *fl, const uint8_t *txid,
                                              uint64_t now_ns, int *fresh) {
    d2k_stun_request_slot *slot=NULL;
    *fresh=0;
    for (size_t i=0;i<D2K_STUN_REQUEST_SLOTS;i++) {
        d2k_stun_request_slot *r=&fl->stun_requests[i];
        if (r->valid && !memcmp(r->txid,txid,12)) {
            r->repeated=1;
            return r;
        }
        if (!slot || (!r->valid && slot->valid) ||
            (r->valid && slot->valid &&
             ((r->answered && !slot->answered) ||
              (r->answered==slot->answered && r->started_ns<slot->started_ns)))) slot=r;
    }
    memset(slot,0,sizeof *slot);
    slot->valid=1;slot->started_ns=now_ns;memcpy(slot->txid,txid,12);
    *fresh=1;
    return slot;
}

/* --- QUIC/UDP: та же склейка, что и для TCP выше, для другого транспорта --
 *
 * У UDP нет соединения — «поток» здесь пятёрка адрес+порт с истечением по
 * времени (s->uflows, вторая независимая таблица, см. её объявление в
 * struct d2k_session). Разбор QUIC (core/quic.c, задача 2 этой же
 * вертикали) не хранит НИЧЕГО между вызовами и не выделяет память: ключи на
 * каждый вызов выводятся заново из DCID именно ЭТОЙ датаграммы. Отсюда
 * прямое следствие для окна поиска: клиент повторяет Initial, а после Retry
 * шлёт НОВЫЙ Initial с ДРУГИМ DCID — вторая датаграмма расшифровывается
 * другими ключами, и попытка обязана повториться на ней, а не остановиться
 * после первой неудачи. Поэтому здесь, в отличие от TCP-ветки, «похоже на
 * Initial, но не расшифровалось» НЕ взводит saw_hello — взводит только
 * УСПЕШНОЕ d2k_quic_sni (см. по тексту ниже).
 *
 * Разрезы/перекрытие плана здесь неприменимы иначе, чем для TCP: датаграмма
 * атомарна, пересборки потока у UDP нет, и попытка плана нарезать payload на
 * несколько посылок для UDP означает не «разрезанный поток», а два огрызка
 * одного QUIC-пакета, которые ничей сборщик не соединит. Это ловится
 * отдельно, ниже, до обращения к сборщику на провод. */

/* ПОДСТАНОВКА ВНЕШНЕГО АДРЕСА. Всё обоснование — в d2k_nat.h; здесь только
   место, где оно применяется.

   Спрашиваем ОДИН раз на поток и запоминаем: таблица соединений читается
   целиком, и делать это на каждый пакет было бы дорого без всякой пользы —
   трансляция за время жизни потока не меняется.

   Отсутствие записи — НЕ повод собрать посылку с локальным адресом: она
   уйдёт в никуда, а план будет объявлен применённым. Возвращаем отказ, и
   вызывающий честно откажется целиком (§2.5: не подменять запрошенное
   похожим). Так бывает при включённом nf_conntrack_fastnat: ускоритель
   ведёт поток мимо conntrack, записи нет вовсе — поэтому files/S99d2k
   выключает его на время своей работы. */
/* ПОТОК ОБЯЗАН ВЕСТИСЬ CONNTRACK, иначе посылки уйдут мимо NAT.
 *
 * Датапат вклинивает свои пакеты сырым сокетом с адресами ИЗ ОЧЕРЕДИ. Для
 * транзитного потока это ещё локальный адрес клиента (очередь висит на mangle
 * POSTROUTING, SNAT делается позже), и правильно он превращается во внешний
 * ровно одним способом: пакет попадает в ТУ ЖЕ запись conntrack, что и поток
 * клиента, и получает её трансляцию. Тогда на проводе он неотличим от
 * клиентского — тот же адрес, тот же порт.
 *
 * Если записи нет, NAT считать нечего: пакет уходит с локальным адресом и
 * умирает у провайдера. Так бывает при включённом nf_conntrack_fastnat —
 * ускоритель ведёт поток мимо conntrack (поэтому files/S99d2k выключает его
 * на время работы). Замерено на роутере Марка 13.09.2026: обход работал
 * только для трафика самого роутера, а любое устройство за ним получало
 * ноль — при том, что собственный зонд на той же цели отвечал 200.
 *
 * ЧЕГО ЗДЕСЬ НАМЕРЕННО НЕТ. Подставлять внешний адрес САМИМ нельзя, хотя
 * conntrack его и знает. Проверено на том же роутере: пакет с уже внешним
 * адресом выглядит для NAT НОВЫМ соединением, чей порт занят потоком
 * клиента, и порт переписывается — собрали 88.87.93.11:61081, на провод
 * ушло 88.87.93.11:54212, сервер ответил сбросом. Правильный путь один:
 * отдать пакет как есть и дать роутеру перевести его вместе с потоком.
 *
 * Спрашиваем ОДИН раз на поток: таблица читается целиком, а ответ за время
 * жизни потока не меняется. */
static uint64_t g_nat_ok, g_nat_miss, g_nat_none, g_nat_retried;

void d2k_session_nat_stats(uint64_t *ok, uint64_t *miss, uint64_t *none,
                           uint64_t *retried) {
    if (ok) { *ok = g_nat_ok; }
    if (miss) { *miss = g_nat_miss; }
    if (none) { *none = g_nat_none; }
    if (retried) { *retried = g_nat_retried; }
}

/* ПЛАН ОБЪЯВЛЯЕТ СВОЙ ТРАНСПОРТ, И ЧУЖОМУ ПАКЕТУ ОН НЕ ДОСТАЁТСЯ.
 *
 * Таблица планов ключуется именем и ФОРМОЙ приветствия, а «дедушкино право»
 * (форма не объявлена) совместимо с любой формой — в том числе с QUIC. Отсюда
 * и брался перекос: план, подтверждённый на TLS поверх TCP, доставался
 * датаграмме того же имени, и исполнитель честно упирался в «посылка
 * невыполнима для UDP» — разреза и перекрытия у датаграммы нет. На роутере
 * владельца 13.09.2026 таких отказов набралось 221 за день: каждый из них —
 * сожжённый зонд и поиск, который не мог сойтись никогда.
 *
 * Транспорт у плана есть на проводе с самого начала (запись proto,
 * plan_parse.c), спрашивать о нём никого не надо. Ноль — «не объявлен», такой
 * план бывает у старого файла, и его пропускаем как раньше: §2.4, «не
 * измерено» ≠ «не тот». */
static int plan_fits_transport(const d2k_plan *p, uint8_t proto) {
    if (!p) { return 1; }
    uint8_t tr = d2k_plan_transport(p);
    return (tr == 0 || tr == proto) ? 1 : 0;
}

static int flow_tracked(d2k_flow *fl, const d2k_conn *c, uint8_t proto,
                        int first_packet) {
    /* ПЕРВОМУ ПАКЕТУ ТАБЛИЦУ НЕ ЧИТАЕМ (задача 46). Ответ для него известен
       заранее — «можно» (см. исключение ниже), а его собственная запись не
       подтверждена, пока он стоит в очереди, так что чтение заведомо
       промахивалось трижды. На роутере это три полных прохода
       /proc/net/nf_conntrack по ~14 мс: спланированный QUIC Initial уходил
       через 42 мс вместо ~1 мс, а хвосты его потока ждали в очереди со своей
       неподтверждённой записью (поле 03.10.2026). Состояние не запоминается:
       следующий пакет спросит таблицу, как и раньше после промаха. */
    if (fl->nat_state == 0 && first_packet) {
        return 0;
    }
    /* ОТВЕТ УЖЕ ПРОШЁЛ ЧЕРЕЗ ЯДРО — ЗАПИСЬ ДОКАЗАНА (задача 47). SYN-ACK
       возвращается к клиенту только по подтверждённой записи conntrack, с её
       трансляцией: прочитать таблицу значило бы заплатить ~14 мс (полный проход
       /proc/net/nf_conntrack на роутере, поле 03.10.2026) перед каждым
       спланированным ClientHello ради ответа, известного заранее. Без
       увиденного ответа (нет обратного правила, лаборатория) — чтение, как
       раньше. */
    if (fl->nat_state == 0 && proto == 6 && fl->saw_synack) {
        fl->nat_state = 1;
        g_nat_ok++;
        return 0;
    }
    if (fl->nat_state == 0) {
        uint32_t ext = 0;
        uint16_t eport = 0;
        /* ОДИН ОТВЕТ «НЕТ ЗАПИСИ» — ЕЩЁ НЕ ОТВЕТ.
         *
         * Чтение /proc/net/nf_conntrack не атомарно: таблица меняется под
         * руками, пока мы её читаем. Замер 17.09 на стенде транзита поймал
         * случай, когда запрос вернул «записи нет», а повторный запрос сразу
         * же, без единой паузы, ту же запись нашёл.
         *
         * Цена промаха несоразмерна его редкости. Клиент, чьё приветствие
         * попало на промах, остаётся без обхода — это один из тридцати. Но
         * если промах попадает на поток СОБСТВЕННОГО ЗОНДА, план к нему не
         * применяется, зонд не доходит до приложения, единственный найденный
         * кандидат объявляется негодным — и цель остаётся без обхода целиком.
         * Так прогон 17.09 дал «прошло 0 из 30» на рабочем плане.
         *
         * ТРИ ПОПЫТКИ, А НЕ ОДНА И НЕ ДЕСЯТЬ. Одна — это и есть прежнее
         * поведение. Десять стоили бы десяти чтений таблицы в сотни строк на
         * пакетном пути, причём КАЖДЫЙ раз, когда записи действительно нет
         * (ускоритель ведёт поток мимо conntrack — обычное дело на роутере).
         * Замеренный случай лечился первым же повтором; две про запас — на
         * случай, когда таблица меняется активнее, чем в стенде.
         *
         * Пауз между попытками нет намеренно: очередь NFQUEUE обрабатывается
         * одним потоком, и сон здесь тормозит ВЕСЬ трафик, а не только этот
         * пакет. */
        int rc = -1;
        for (int attempt = 0; attempt < 3; attempt++) {
            if (c->family == 6) {
                uint8_t ext6[16];
                rc = d2k_nat_family_hook(D2K_NAT_PROC, proto, c->src_ip6, c->src_port,
                    c->dst_ip6, c->dst_port, 6, ext6, &eport);
            } else {
                rc = d2k_nat_hook(D2K_NAT_PROC, proto, c->src_ip, c->src_port,
                              c->dst_ip, c->dst_port, &ext, &eport);
            }
            if (rc >= 0) {
                if (attempt > 0) { g_nat_retried++; }
                break;
            }
        }
        if (rc == 0) {
            fl->nat_state = 1;
            g_nat_ok++;
        } else if (rc > 0) {
            /* Таблицы соединений в системе нет вовсе — нет и NAT, переводить
               наши пакеты некому и незачем. */
            fl->nat_state = 3;
            g_nat_none++;
        } else {
            /* ОТРИЦАТЕЛЬНЫЙ ОТВЕТ НЕ ЗАПОМИНАЕТСЯ, и это не осторожность.
               Запись conntrack ПОДТВЕРЖДАЕТСЯ в конце прохода пакета, уже
               после mangle POSTROUTING, — значит на ПЕРВОМ пакете потока её в
               таблице ещё нет. У TCP приветствие третье по счёту и запись к
               тому времени на месте; у QUIC первая же датаграмма и есть
               приветствие, и ответ всегда «нет». Запомнив его, мы отвергали
               бы и повтор Initial по таймеру PTO, то есть весь поток. */
            g_nat_miss++;
            /* ПЕРВЫЙ ПАКЕТ ПОТОКА — исключение, и оно не поблажка. Запись
               подтверждается в конце прохода ЭТОГО САМОГО пакета, поэтому в
               таблице её ещё нет ни при каком исправном ядре. Наши посылки
               несут ТОТ ЖЕ кортеж, что и он; запись создаёт и подтверждает
               первая из них, и все последующие наши посылки получают её
               трансляцию. Сам удержанный оригинал в неё НЕ попадает — его
               неподтверждённая запись проигрывает вставку, и ядро его снимает
               (поле 02.10.2026), поэтому после фальшивок он уходит нашей же
               посылкой (own_after_fakes в handle_udp).
               Отказать здесь значило бы никогда не трогать первую датаграмму
               QUIC, а у QUIC первая датаграмма и есть приветствие. */
            return first_packet ? 0 : -1;
        }
    }
    return 0;
}

/* ИСПОЛНЕНИЕ ПЛАНА НА ДАТАГРАММЕ (вынесено из handle_udp, этап 16): общий
   хвост для QUIC/голоса/STUN и для потока без распознанного протокола (опыт
   на продолжении клиента). Сборка посылок, контекст NAT, вердикт, передача
   отправителю, APPLIED с trial ID. */
/* ПОЗДНЯЯ ДОСТАВКА (этап 17). Поток уже за окном поиска, но контроллер
   поставил точную пробу ЭТОГО 5-tuple (SET_ADDR_PROBE): датаграмма клиента без
   распознанного протокола идёт в опыт, а не в «за окном поиска». Узко: только
   точная запись этого потока (не постоянный адресный план — тот и так
   достаётся новым потокам), только пока план ещё не исполнен. */
/* An EXACT measured_probe match that is a FRESH trial on this flow: a distinct
   trial from the one already executed here, with the previous sends completed
   (sends_left==0) and none failed (sends_failed==0). This is the controller's
   new measured candidate placed after its own plan failed. It alone may reopen
   the search window and bypass plan_done. A permanent address plan, the
   address probe and the SAME trial never qualify, and pending/failed sends
   hold it off. Returns the plan (and its trial), or NULL. */
static const d2k_plan *raw_fresh_measured(d2k_session *s, const d2k_flow *fl,
        const d2k_packet_view *ip, const uint8_t *u, const uint8_t *payload,
        size_t payload_len, uint64_t now_ns, uint8_t trial_out[D2K_TRIAL_ID_LEN]) {
    uint8_t t[D2K_TRIAL_ID_LEN];
    const d2k_plan *p = measured_probe(s, fl, ip, u, 0, payload, payload_len, now_ns, t);
    if (!p || fl->sends_left || fl->sends_failed ||
        memcmp(t, fl->execution_trial_id, D2K_TRIAL_ID_LEN) == 0) { return NULL; }
    if (trial_out) { memcpy(trial_out, t, D2K_TRIAL_ID_LEN); }
    return p;
}

static int late_raw_probe(d2k_session *s, const d2k_flow *fl, const d2k_packet_view *ip,
                          const uint8_t *u, const uint8_t *payload, size_t payload_len,
                          uint64_t now_ns) {
    if (fl->saw_hello || fl->saw_initial || fl->controller_probe ||
        fl->stun_txid_valid || fl->voice_ssrc_valid) { return 0; }
    if (fl->plan_done) {
        /* Already executed: the window reopens ONLY for a fresh measured trial
           (the controller's next candidate), never the same trial, a permanent
           address plan or an address probe, and never over pending/failed
           sends — raw_fresh_measured enforces exactly that. */
        return raw_fresh_measured(s, fl, ip, u, payload, payload_len, now_ns, NULL) != NULL;
    }
    if(measured_probe(s,fl,ip,u,0,payload,payload_len,now_ns,NULL))return 1;
    d2k_addr_probe_flow rf;
    memset(&rf, 0, sizeof rf);
    rf.family = ip->family;
    memcpy(ip->family == 6 ? rf.src_ip6 : rf.src_ip4, ip->src.bytes, ip->family == 6 ? 16 : 4);
    memcpy(ip->family == 6 ? rf.dst_ip6 : rf.dst_ip4, ip->dst.bytes, ip->family == 6 ? 16 : 4);
    memcpy(&rf.src_port_be, u + 0, 2);
    memcpy(&rf.dst_port_be, u + 2, 2);
    rf.transport = 17;
    uint8_t tr[D2K_TRIAL_ID_LEN];
    return d2k_plantab_find_addr_probe(s->plans, &rf, now_ns, tr) != NULL;
}

static void udp_execute(d2k_session *s, d2k_flow *fl, const d2k_key *keyp, const d2k_plan *use,
                        const uint8_t trial_id[D2K_TRIAL_ID_LEN], const uint8_t *pkt,
                        size_t payload_off, size_t payload_len, const d2k_packet_view *ip,
                        const uint8_t *u, uint64_t now_ns, uint8_t *buf, size_t bufcap,
                        int held_first_replay, int first_voice_request,
                        d2k_stun_request_slot *stun_request, int new_stun_request,
                        const d2k_ct_info *forced_map, d2k_result *out) {
    const d2k_key key = *keyp;
    const size_t ihl = ip->l4;
    d2k_pkt in;
    memset(&in, 0, sizeof in);
    in.payload = pkt + payload_off;
    in.payload_len = payload_len;
    in.seq = 0;      /* у UDP нет номера последовательности */
    /* have_sni = 0 НАМЕРЕННО, хотя имя выше уже найдено. Имя d2k_quic_sni
       достаёт из ClientHello, пересобранного ВНУТРИ core/quic.c по смещениям
       CRYPTO-кадров расшифрованного потока — оно не лежит смещением в этом
       payload (тот всё ещё шифротекст). Якоря ANCHOR_SNI_START/END
       исполнителя (plan_apply.c) вычисляют смещение именно В payload; для
       QUIC такого смещения не существует ни при каком значении. Подставить
       сюда 0 «на всякий случай» значило бы дать исполнителю МОЛЧА вычислить
       заведомо неверный якорь вместо честного отказа — d2k_wire.h прямо
       запрещает подменять запрошенное на похожее. have_sni=0 — единственно
       честное значение: план, которому нужен якорь по SNI, получит отказ
       ниже (d2k_plan_apply вернёт -1 и пакет пройдёт как есть), а не тихую
       порчу. */
    in.have_sni = 0;
    in.sni_off = 0;
    in.sni_len = 0;
    /* ОРИГИНАЛ ПОСЛЕ ФАЛЬШИВОК — СВОЕЙ ПОСЫЛКОЙ (задача 42). Наши сырые
       фальшивки несут тот же кортеж, создают и ПОДТВЕРЖДАЮТ запись conntrack
       первыми (у транзита — с трансляцией по метке, S99d2k), а удержанный в
       NFQUEUE оригинал несёт свою неподтверждённую запись, и после ACCEPT ядро
       снимает его как дубль: insert_failed/drop росли на роутере ровно на
       число прогонов, настоящий Initial на ppp0 не появлялся, уходил только
       повтор клиента через ~300 мс без плана. Свой оригинал проходит через
       ту же подтверждённую запись — с той же трансляцией, что у фальшивок, —
       а копия в очереди снимается. */
    in.own_after_fakes = 1;

    d2k_actions acts;
    memset(&acts, 0, sizeof acts);
    if (d2k_plan_apply(use, fl, &in, &acts) != 0) {
        out->skipped = acts.refuse_why ? acts.refuse_why : "план неприменим к этому пакету";
        refuse_coded(s, now_ns, &key, out->skipped, D2K_REFUSE_NOT_APPLIED, use);
        d2k_actions_free(&acts);
        return;
    }

    /* Датаграмма атомарна: у UDP нет пересборки потока. План, который режет
       payload на несколько кусков (якоря ANCHOR_PAYLOAD_START/HELLO_MIDDLE
       это позволяют НЕЗАВИСИМО от have_sni — см. anchor_offset в
       plan_apply.c), для одной датаграммы неисполним честно: сервер получит
       два огрызка одного QUIC-пакета вместо целого, и это не то же самое,
       что разрез TCP-потока, который сервер пересобирает сам. wire_udp.c
       ловит только перекрытие (pre_len/seq_shift) — оно единственное метит
       себя этими полями; обычный разрез никакого признака не ставит и
       пройдёт сборщик как обычная нагрузка. Различить это может только тот,
       кто знает про транспорт, — то есть здесь, до обращения к сборщику. */
    size_t payload_emits = 0;
    for (size_t i = 0; i < acts.n; i++) {
        if (acts.v[i].kind == D2K_EMIT_PAYLOAD) {
            payload_emits++;
        }
    }
    if (payload_emits > 1) {
        out->skipped = "план режет датаграмму на части — для UDP это порча, не разрез";
        refuse(s, now_ns, &key, out->skipped);
        d2k_actions_free(&acts);
        return;
    }

    d2k_conn c;
    memset(&c, 0, sizeof c);
    c.family = ip->family;
    memcpy(ip->family == 6 ? c.src_ip6 : (uint8_t *)&c.src_ip,
           ip->src.bytes, ip->family == 6 ? 16 : 4);
    memcpy(ip->family == 6 ? c.dst_ip6 : (uint8_t *)&c.dst_ip,
           ip->dst.bytes, ip->family == 6 ? 16 : 4);
    c.traffic_class = ip->traffic_class; c.flow_label = ip->flow_label;
    memcpy(&c.src_port, u + 0, 2);
    memcpy(&c.dst_port, u + 2, 2);
    /* Транзитный поток обязан вестись conntrack — см. flow_tracked выше:
       иначе наши посылки уйдут с локальным адресом, мимо NAT. */
    if (flow_tracked(fl, &c, 17, held_first_replay || fl->fwd_pkts <= 1) != 0) {
        out->skipped = "поток не ведётся conntrack — посылки уйдут мимо NAT";
        refuse_coded(s,now_ns,&key,out->skipped,D2K_REFUSE_CONTEXT,use);
        d2k_actions_free(&acts);
        return;
    }
    c.ttl = ip->hop_limit;
    c.ip_id = ip->ip_id;
    d2k_conn fragment_conn=c;
    for (size_t i=0;i<acts.n;i++) if (acts.v[i].ipfrag) {
        /* NODEFRAG sends bypass reassembly/normal UDP conntrack. Translate
           ONLY fragments here, using the existing client's confirmed tuple.
           Whole fakes retain the original tuple and ordinary kernel NAT.
           No first-packet exemption: unknown mapping cannot be invented. */
        uint32_t ext=0;uint16_t port=0;
        uint8_t ext6[16] = {0};
        int found;
        if (forced_map) {
            /* Продолжение владения: внешний кортеж уже подтверждён демоном, и
               d2k_session_udp_continue сверил ответный кортеж с оригиналом.
               Берём внешний адрес/порт из ответного кортежа — без догадок, без
               hook и без повторного отложения (defer ниже недостижим). */
            const d2k_ct_tuple *rt = &forced_map->reply_tuple;
            /* Внешний адрес/порт храним в СЕТЕВОМ порядке — ровно так их кладёт
               d2k_nat_hook и так же хранятся c.src_ip/c.src_port (memcpy из
               байт пакета). Хостовая арифметика здесь была бы порчей порядка. */
            memcpy(&port, rt->dport_be, 2);
            if (c.family == 6) { memcpy(ext6, rt->dst, 16); }
            else { memcpy(&ext, rt->dst, 4); }
            found = 0;
        } else {
            found = c.family == 6
                ? d2k_nat_family_hook(D2K_NAT_PROC,17,c.src_ip6,c.src_port,
                                      c.dst_ip6,c.dst_port,6,ext6,&port)
                : d2k_nat_hook(D2K_NAT_PROC,17,c.src_ip,c.src_port,
                               c.dst_ip,c.dst_port,&ext,&port);
        }
        if(found!=0 || (c.family != 6 && !ext) || !port) {
            /* Первый QUIC Initial ещё не подтверждён conntrack, пока его
               NFQUEUE-ID удерживается на разбор/исполнение. NODEFRAG нельзя
               NAT-ить по догадке, поэтому этот пакет проходит нетронутым, но
               кандидат сохраняется для повтора Initial: ко второму пакету
               ядро уже подтвердило кортеж. Постоянный промах на последующих
               пакетах остаётся обычным отказом ниже. */
            if(found==-1 && (held_first_replay || fl->fwd_pkts<=1)) {
                out->skipped="ожидаю подтверждения conntrack для IP-фрагментов";
                /* План НЕ ПРИМЕНЁН: датаграмма проходит как есть. Но она —
                   КАНДИДАТ на владение (postnat_own): демон вправе взять её,
                   подтвердить внешний кортеж и продолжить через
                   d2k_session_udp_continue. Отдаём привязку ЦЕЛИКОМ, чтобы
                   продолжение отвергло переустановленный/replaced/удалённый
                   план: установочная привязка (поколение+эпоха таблицы+вид),
                   эпоха/инкарнация потока, план и trial, полный кортеж. */
                out->udp_defer_pending = 1;
                out->udp_defer_key = key;
                memcpy(out->udp_defer_plan_id, d2k_plan_id(use), D2K_PLAN_ID_LEN);
                memcpy(out->udp_defer_trial_id, trial_id, D2K_TRIAL_ID_LEN);
                memset(&out->udp_defer_binding, 0, sizeof out->udp_defer_binding);
                (void)d2k_plantab_binding(s->plans, use, &out->udp_defer_binding);
                memcpy(out->udp_defer_epoch, fl->flow_epoch, 16);
                out->udp_defer_incarnation = fl->incarnation;
                d2k_actions_free(&acts);
                return;
            }
            /* Missing procfs is NOT evidence of no NAT. Ordinary packets
               can leave translation to the kernel; NODEFRAG packets cannot. */
            out->skipped="нет подтверждённого NAT-контекста для IP-фрагментов";
            refuse_coded(s,now_ns,&key,out->skipped,D2K_REFUSE_CONTEXT,use);
            d2k_actions_free(&acts);return;
        }
        if(found==0){
            if(c.family==6)memcpy(fragment_conn.src_ip6,ext6,16);
            else fragment_conn.src_ip=ext;
            fragment_conn.src_port=port;
        }
        break;
    }
    /* c.ack и c.window остаются нулями: полей TCP у UDP нет, а
       d2k_wire_build_udp их не читает (см. d2k_wire.h). */

    size_t wire_count=acts.n;
    for (size_t i=0;i<acts.n;i++) {
        if (acts.v[i].ipfrag) wire_count+=acts.v[i].ipfrag<=2?1:2;
    }
    if (wire_count > sizeof out->out / sizeof out->out[0]) {
        /* План описывает больше посылок, чем вмещает d2k_result.out[]
           (ревью задачи 4, круг 2): repeats фальшивки приходит из TLV одним
           байтом без потолка (до 255), а out[] — фиксированные 16. Раньше n
           тихо обрезался до 16: план "применялся" целиком (plan_done,
           applied++, PLAN_APPLIED), а на провод уходило МЕНЬШЕ посылок, чем
           он описывал, — то же самое расхождение с планом, которое здесь же
           ловит ветка made==0 чуть ниже, только раньше нужного места и без
           единого слова об этом. Честный исход тот же, что там: отказ
           целиком, а не обрезанное исполнение, выданное за полное. */
        out->skipped = "план описывает больше посылок, чем вмещает буфер результата";
        refuse(s, now_ns, &key, out->skipped);
        d2k_actions_free(&acts);
        return;
    }
    size_t used = 0;
    size_t n = 0;
    for (size_t i = 0; i < acts.n; i++) {
        const d2k_emit *e=&acts.v[i];
        d2k_ipfrag_span spans[3];
        size_t count=0,made=0;
        if (e->ipfrag) {
            d2k_ipfrag_plan fp;
            /* Copying/fragmenting IPv4 options needs its own measured path.
               Reject unsupported context instead of silently losing options. */
            if (((c.family==6 && ihl==40) || (c.family!=6 && ihl==20)) &&
                e->kind==D2K_EMIT_PAYLOAD && !e->pre_len &&
                !e->seq_shift && !e->ack_shift && !e->poison && !e->wire_profile &&
                d2k_ipfrag_shape(e->ipfrag,&fp)==0) {
                uint32_t id=next_fragment_id(s);
                if (c.family==6) {
                    count=d2k_udpfrag6_build_ex(fragment_conn.src_ip6,fragment_conn.dst_ip6,
                        rd16((const uint8_t *)&fragment_conn.src_port),
                        rd16((const uint8_t *)&fragment_conn.dst_port),e->bytes,e->len,&fp,id,
                        c.ttl,c.traffic_class,c.flow_label,buf+used,bufcap-used,spans);
                } else count=d2k_udpfrag_build_ex((const uint8_t *)&fragment_conn.src_ip,
                    (const uint8_t *)&fragment_conn.dst_ip,rd16((const uint8_t *)&fragment_conn.src_port),
                    rd16((const uint8_t *)&fragment_conn.dst_port),e->bytes,e->len,&fp,(uint16_t)id,
                    c.ttl,pkt[1],buf+used,bufcap-used,spans);
                if(count)made=spans[count-1].off+spans[count-1].len;
            }
        } else {
            made=d2k_wire_build_udp(&c,e,buf+used,bufcap-used);
            if(made){count=1;spans[0]=(d2k_ipfrag_span){0,made};}
        }
        if (made == 0) {
            /* d2k_wire_build_udp возвращает 0 в двух случаях: посылка не
               поместилась в буфер и «эту порчу для UDP честно не исполнить»
               (pre_len/seq_shift/TCPTS_BACK/BADSUM, см. шапку d2k_wire.h).
               Оба — отказ, и его нельзя проглотить: отправить меньше, чем
               описал план, и промолчать значит приписать результат плану,
               который не исполнялся. Обработка — слово в слово как в
               TCP-ветке: спросить исполнитель, что делать с уже ушедшим.

               СОБРАНО — НЕ ОТПРАВЛЕНО. Сюда мы попадаем на СБОРКЕ, до
               единой отправки: сами посылки уйдут позже, из out->out[].
               Поэтому исполнителю сообщается ноль ушедших, а не i: с i он
               объявил бы поток испорченным и снял бы оригинал из-за байт,
               которых на проводе не было. Раз ничего не ушло — отказываемся
               ЦЕЛИКОМ, не меняя воздействия, и отпускаем оригинал нетронутым
               (0009, U3). */
            d2k_cancel cancel;
            d2k_actions_cancel(&acts, 0, &cancel);
            out->n_out = 0;
            out->verdict = (cancel.fate == D2K_ORIG_DROP) ? D2K_VERDICT_DROP
                                                          : D2K_VERDICT_ACCEPT;
            if (cancel.stream_damaged) {
                fl->damaged = 1;
            }
            out->skipped = "посылка невыполнима для UDP";
            refuse(s, now_ns, &key, out->skipped);
            d2k_actions_free(&acts);
            return;
        }
        if (acts.v[i].kind == D2K_EMIT_PAYLOAD && out->first_payload == 0xFF) {
            out->first_payload = (uint8_t)n;
        }
        for(size_t k=0;k<count;k++,n++) {
            out->out[n].delay_us=k?0:e->delay_us;
            out->out[n].off=used+spans[k].off;
            out->out[n].len=spans[k].len;
        }
        used += made;
    }
    if (acts.fate == D2K_ORIG_HOLD) {
        /* Как и в TCP-ветке: удержание оригинала датапат не умеет вовсе. */
        out->n_out = 0;
        out->verdict = D2K_VERDICT_ACCEPT;
        out->skipped = "удержание оригинала не поддержано";
        refuse(s, now_ns, &key, out->skipped);
        d2k_actions_free(&acts);
        return;
    }
    out->n_out = n;
    out->verdict = (acts.fate == D2K_ORIG_DROP) ? D2K_VERDICT_DROP
                                                : D2K_VERDICT_ACCEPT;
    fl->plan_done = 1;
    fl->guards = d2k_plan_guards(use);
    s->applied++;
    /* Ключ потока и идентификатор плана — ВЫЗЫВАЮЩЕМУ, до отправки. Без них
       отправляющий видит только байты, и отказ sendto оставался голым
       счётчиком (d2k_session.h, поля applied/key/plan_id). */
    plan_handed_off(s, out, fl, &key, use,
                    trial_id[0] || trial_id[1] || trial_id[2] || trial_id[3] ||
                    trial_id[4] || trial_id[5] || trial_id[6] || trial_id[7] ||
                    trial_id[8] || trial_id[9] || trial_id[10] || trial_id[11] ||
                    trial_id[12] || trial_id[13] || trial_id[14] || trial_id[15]
                    ? trial_id : NULL);
    if (!fl->saw_hello && !fl->saw_initial && payload_len)
        raw_proof_begin(fl, pkt + payload_off, payload_len, 0, 0);
    /* Bind only during the first observed request itself. A retransmission
       after installing another plan cannot re-label an older transaction. */
    if (first_voice_request) {
        d2k_udp_request_context *request=&fl->voice_request_context;
        request->execution_id=out->execution_id;
        request->binding=out->binding;
        memcpy(request->plan_id,out->plan_id,D2K_PLAN_ID_LEN);
        memcpy(request->trial_id,out->trial_id,D2K_TRIAL_ID_LEN);
    }
    /* A response to the same txid after another execution cannot tell which
       attempt produced it. Preserve observation, discard attribution. */
    if(stun_request && !new_stun_request)
        memset(&stun_request->context,0,sizeof stun_request->context);
    if(stun_request && new_stun_request) {
        stun_request->context.execution_id=out->execution_id;
        stun_request->context.binding=out->binding;
        memcpy(stun_request->context.plan_id,out->plan_id,D2K_PLAN_ID_LEN);
        memcpy(stun_request->context.trial_id,out->trial_id,D2K_TRIAL_ID_LEN);
    }
    /* Не просто «план применился», а КАКОЙ: без идентификатора контроллер не
       отличит применение своего кандидата от применения предыдущего, чьё
       событие пришло позже (d2k_ctl.h объявляет APPLIED «ключ + id плана»). */
    d2k_journal_add_applied(s->jrn, now_ns, &key, d2k_plan_id(use), out->trial_id);
    d2k_actions_free(&acts);
}

static void handle_udp(d2k_session *s, const uint8_t *pkt, size_t len,
                       const d2k_packet_view *ip, uint64_t now_ns,
                       uint8_t *buf, size_t bufcap, d2k_result *out,
                       int controller_probe) {
    size_t ihl = ip->l4;
    /* Минимум для UDP — 8 байт заголовка, а не унаследованные от TCP 20: у
       UDP нет ни номеров последовательности, ни опций, и датаграмма с пустой
       нагрузкой (total == ihl + 8) уже целиком помещается. Раньше эта
       проверка не была своей — общий пролог TCP-ветки отвергал короткую, но
       честную UDP-датаграмму С ЧУЖИМ ОБЪЯСНЕНИЕМ («заголовок не помещается»
       про TCP-заголовок, которого тут нет), см. ревью задачи 4. */
    if (len < ihl + 8) {
        out->skipped = "заголовок UDP не помещается";
        return;
    }
    /* Тот же фрагмент-контроль, что в общем прологе TCP-ветки чуть ниже — не
       вынесен в общий код, чтобы правка UDP-ветки не могла задеть уже
       проверенный путь TCP ни при каких условиях. */
    if ((ip->fragment & 0x1fff) != 0) {
        out->skipped = "фрагмент";
        return;
    }
    size_t total = ip->total;
    if (total > len || total < ihl + 8) {
        out->skipped = "поле длины не сходится";
        return;
    }

    const uint8_t *u = pkt + ihl;
    size_t payload_off = ihl + 8;
    size_t payload_len = total - payload_off;

    d2k_key key;
    int src_is_low = d2k_key_make_addr(&key, 17, &ip->src, &ip->dst, u, u + 2);

    d2k_flow *fl = d2k_track_get(s->uflows, &key, now_ns);
    if (!fl) {
        /* Таблица полна — тот же честный исход, что и у TCP: обработать
           пакет без учёта потока значит применить план второй раз к тому же
           потоку. */
        out->skipped = "таблица потоков полна";
        return;
    }
    if (controller_probe) { fl->controller_probe = 1; }

    /* Направление — из ПОРТА, а не из содержимого (ревью задачи 4, круг 3).
     *
     * Было (круг 2): направление ставилось по успеху d2k_quic_sni —
     * «раскрылось ключами client in, значит датаграмма от клиента». Это
     * неверно. Ключи QUIC Initial выводятся из ПУБЛИЧНОГО DCID (RFC 9001
     * §5.4.1/5.4.2, см. d2k_crypto.h), поэтому раскрытие доказывает только,
     * что БАЙТЫ ПОЛЕЗНОЙ НАГРУЗКИ — это содержимое клиентского Initial, и
     * ничего не говорит о том, куда едет ЭТА КОНКРЕТНАЯ датаграмма:
     * побайтовая копия тех же самых байт, пущенная в обратную сторону,
     * раскроется теми же ключами и даст то же самое «доказательство».
     * Ревьюер показал это стендом, не рассуждением: датаграмма
     * 1.2.3.4:443 -> LAN:50000 с байтами клиентского Initial при
     * поставленном плане давала приветствие, применение и поддельную
     * посылку В СТОРОНУ СОБСТВЕННОГО ПОЛЬЗОВАТЕЛЯ, а настоящий клиентский
     * Initial следом отбрасывался как «поток уже показывал приветствие» —
     * обход на этом потоке не срабатывал вовсе. Это НЕ регресс круга 2:
     * тот же стенд против dea3790 ведёт себя побайтно так же — дорожка была
     * открыта раньше, просто причина, написанная как факт, была написана
     * раньше, чем её проверили стендом.
     *
     * Улика — в самом пакете, а не в его содержимом. Основной firewall теперь
     * наблюдает весь TCP/UDP диапазон, поэтому для произвольного сервисного
     * порта направление берётся из hook NFQUEUE: OUTPUT/POSTROUTING — клиент,
     * INPUT/PREROUTING — сервер, а неоднозначный FORWARD уточняется по уже
     * известному направлению потока. Вызовы без hook сохраняют старый
     * безопасный fallback по портам 443. Серверную и неизвестную сторону
     * нельзя объявлять клиентским Initial только по успешной расшифровке:
     * публичный DCID не доказывает направление. */
    /* НАПРАВЛЕНИЕ: СНАЧАЛА КРЮЧОК, ПОТОМ ПОРТ.
       Крючок — прямая улика и работает на ЛЮБОМ порту. Порт остаётся запасным
       ответом ровно для тех вызывающих, кто крючка не знает. */
    int dst_is_443 = (rd16(u + 2) == 443);
    int src_is_443 = (rd16(u + 0) == 443);
    int from_client = -1;   /* -1 — не установлено */
    if (s->hook == D2K_HOOK_OUTPUT || s->hook == D2K_HOOK_POSTROUTING) {
        from_client = 1;
    } else if (s->hook == D2K_HOOK_INPUT || s->hook == D2K_HOOK_PREROUTING ||
               s->hook == D2K_HOOK_FORWARD) {
        /* FORWARD несёт транзит в ОБЕ стороны, и одной стороной его назвать
           нельзя. Пока сюда попадает только входящее (правило INPUT ставится
           на обратное направление), но выдавать транзит за серверную сторону
           нельзя — для него крючок уликой не является, и мы честно падаем
           обратно на порт. */
        from_client = (s->hook == D2K_HOOK_FORWARD) ? -1 : 0;
    }
    /* FORWARD НА ЛЮБОМ ПОРТУ: ПОТОК УЖЕ ЗНАЕТ, КТО ЕГО НАЧАЛ.
       Порт уликой работает только на 443; у голоса Дискорда его нет вовсе
       (клиент эфемерный, сервер 50004), и ответ сервера на FORWARD уходил в
       «направление неизвестно» — поток выглядел безответным при живом
       разговоре. Но начинатель потока уже назван: он показал приветствие
       (Initial или IP Discovery) на исходящем крючке. Та же улика, что у
       TCP-ветки (init_low), и только когда она есть. */
    if (from_client < 0 && fl->dir_known) {
        from_client = (src_is_low == fl->init_low) ? 1 : 0;
    }
    if (from_client == 0 || (from_client < 0 && src_is_443 && !dst_is_443)) {
        /* СЕРВЕРНАЯ СТОРОНА. Разбирать её как клиентский Initial нельзя (см.
           выше), а вот УЧЕСТЬ обязаны — и это не бухгалтерия ради полноты.
           Ровно два вывода стоят на этих двух счётчиках, и без них оба
           становятся ложью:
             rev_seen — что обратное направление вообще видно, то есть
               правило на него поставлено (иначе молчащими выглядят все);
             rev_after_hello — что на ЭТО приветствие ответили.
           Раньше учёта здесь не было вовсе: датаграмма сервера уходила
           отказом до всякого счёта, rev_pkts у QUIC-потока оставался нулём
           даже на исправной линии, и «сервер молчит» по UDP не мог родиться
           ни при каких обстоятельствах (лаборатория lab-quic.sh 13.09.2026:
           приветствий 4, подозрений 0). */
        fl->rev_pkts++;
        s->rev_seen[shape_slot(17, fl->key.family)] = 1;
        /* saw_initial — тот же поток, только имя не прочиталось (d2k_track.h).
           Ответ по нему тоже наблюдаем: иначе обратный трафик выглядел бы
           полным молчанием. Это не проверка протокола или успеха обхода. */
        if (fl->saw_hello || fl->saw_initial) {
            if (fl->rev_after_hello == 0 && now_ns >= fl->hello_ns) {
                fl->quic_rtt_ns = now_ns - fl->hello_ns;
            }
            fl->rev_after_hello++;
            fl->last_rev_after_hello_ns = now_ns;
            if (!fl->controller_probe && fl->voice_ssrc_valid &&
                is_discord_ip_discovery_response(pkt + payload_off, payload_len,
                                                 fl->voice_ssrc) &&
                !fl->voice_proof_told) {
                fl->voice_proof_told = 1;
                fl->exchange_told = 1;
                s->exchanges++;
                d2k_journal_add_udp_proof(s->jrn, now_ns, &key,
                                D2K_UDP_PROOF_VOICE_DISCOVERY, (uint32_t)payload_len,
                                &fl->voice_request_context);
            }
            if (!fl->controller_probe) {
                for(size_t i=0;i<D2K_STUN_REQUEST_SLOTS;i++) {
                    d2k_stun_request_slot *r=&fl->stun_requests[i];
                    if(!r->valid || r->answered)continue;
                    int success=is_stun_response_for(pkt+payload_off,payload_len,r->txid);
                    if(!success && !is_stun_error_for(pkt+payload_off,payload_len,r->txid))continue;
                    r->answered=1;
                    /* Сервер ответил на НАШ запрос — эпизод молчания окончен.
                       Флаги потока снимаются, чтобы следующее молчание того же
                       долгого потока было замечено снова (ТЗ §3.7); запросы
                       сообщённого эпизода помечены told и второй раз не
                       всплывут. */
                    if(fl->silence_told) {
                        fl->silence_told=0; fl->suspected=0;
                        /* Один эпизод — одно подозрение: всё, что осталось без
                           ответа к моменту восстановления, принадлежит ему. */
                        for(size_t k=0;k<D2K_STUN_REQUEST_SLOTS;k++) {
                            d2k_stun_request_slot *o=&fl->stun_requests[k];
                            if(o->valid && !o->answered) o->told=1;
                        }
                    }
                    if(!success)break;
                    fl->stun_proof_told=1;fl->exchange_told=1;
                    s->exchanges++;
                    d2k_journal_add_udp_proof(s->jrn,now_ns,&key,D2K_UDP_PROOF_STUN,
                                             (uint32_t)payload_len,&r->context);
                    break;
                }
            }
            /* UDP EXCHANGE — только первая обратная датаграмма, один раз на
               поток. UDP допускает пустую нагрузку. Здесь не проверяются
               ни транзакция STUN, ни QUIC Initial, ни IP Discovery: событие
               не вправе подтверждать протокол/обход/работу приложения. */
            if (!fl->controller_probe && !fl->exchange_told) {
                fl->exchange_told = 1;
                s->exchanges++;
                /* Применялся ли план к потоку и форма наблюдения — как у
                   подозрения (этап 16): для потока без протокола это и есть
                   «ответ на продолжение клиента под планом» — уровень пути. */
                d2k_jrn_detail xd;
                memset(&xd, 0, sizeof xd);
                xd.planned = fl->plan_done ? D2K_PLANNED_YES : D2K_PLANNED_NO;
                xd.client_shape = fl->client_shape;
                xd.client_side = fl->dir_known ? (fl->init_low ? D2K_CLIENT_SIDE_LOW : D2K_CLIENT_SIDE_HIGH) : 0;
                d2k_journal_add_exchange_bound(s->jrn, now_ns, &key, D2K_UDP_PROOF_NONE,
                                               (uint32_t)payload_len, &xd, fl);
            }
        }
        uint8_t raw_proof = 0;
        if (!fl->saw_hello && !fl->saw_initial && fl->plan_done && !fl->controller_probe)
            raw_proof = raw_proof_packet(fl, 0, pkt + payload_off, payload_len, 0, 0, 0);
        if (raw_proof) {
            fl->exchange_told = 1;
            s->exchanges++;
            d2k_jrn_detail rd;
            memset(&rd, 0, sizeof rd);
            rd.planned = D2K_PLANNED_YES;
            rd.client_shape = fl->client_shape;
            rd.client_side = fl->dir_known ? (fl->init_low ? D2K_CLIENT_SIDE_LOW : D2K_CLIENT_SIDE_HIGH) : 0;
            d2k_journal_add_exchange_bound(s->jrn, now_ns, &key, raw_proof,
                                           (uint32_t)payload_len, &rd, fl);
        }
        out->skipped = "датаграмма едет от сервера — не клиентский Initial";
        return;
    }
    if (from_client != 1 && (!dst_is_443 || src_is_443)) {
        /* Остаток: оба конца на 443 либо ни одного. Клиентской стороной это
           не объявишь — и «оба 443» тут не крючкотворство, а живой случай
           (сервер, отвечающий с 443 на 443). */
        out->skipped = "направление по порту неизвестно";
        return;
    }
    if (from_client==1 && controller_probe) {
        uint8_t trial[16]={0};
        int reserved;
        const d2k_plan *dns=owned_dns_probe(s,ip,u,controller_probe,
            fl->plan_done ? NULL : pkt+payload_off,payload_len,now_ns,trial,&reserved);
        if (!dns && !reserved && !fl->plan_done &&
            (s->hook==D2K_HOOK_OUTPUT || s->hook==D2K_HOOK_POSTROUTING)) {
            uint16_t port;
            memcpy(&port,u+2,2);
            dns=d2k_plantab_find_dns_endpoint(s->plans,ip->dst.bytes,ip->family,port,17,
                pkt+payload_off,payload_len,now_ns);
        }
        if (dns) {
            fl->client_shape=reserved ? D2K_PLAN_SHAPE_RAW : D2K_PLAN_SHAPE_DNS;
            fl->init_low=src_is_low;fl->dir_known=1;
            udp_execute(s,fl,&key,dns,trial,pkt,payload_off,payload_len,ip,u,now_ns,
                buf,bufcap,0,0,NULL,0,NULL,out);
            return;
        }
        if (reserved) {
            /* The direct control uses this same flow with a different ID. */
            fl->fwd_pkts++;
            return;
        }
    }
    if (!fl->controller_probe && !fl->saw_hello && !fl->saw_initial && fl->plan_done)
        (void)raw_proof_packet(fl, 1, pkt + payload_off, payload_len, 0, 0, 0);
    if (fl->late_watch) { s->late_delivered++; } /* этап 17: датаграмма клиента под меткой записи */

    /* Дальше — попытки разбора СОДЕРЖИМОГО. Направление уже доказано портом
       выше; счётчик попыток и окно поиска — про то, что Initial приходит в
       первых датаграммах клиентской стороны потока (сама датаграмма, её
       повтор, новый Initial после Retry), а дальше разбор ничего не найдёт
       и будет чистой тратой на каждом пакете загрузки. */
    int held_first_replay = fl->udp_hold_replay_first != 0;
    fl->udp_hold_replay_first = 0;
    fl->fwd_pkts++; /* счётчик попыток разбора клиентской стороны потока */
    if (fl->saw_hello || fl->saw_initial) {
        /* Клиент шлёт ЕЩЁ, уже показав приветствие, — повтор Initial по
           таймеру PTO. Половина критерия «шлём, а молчат» (см. d2k_track.h).
           Считается ДО раннего выхода ниже: там поток с разобранным
           приветствием уходит первой же строкой, и счёт, поставленный после,
           не двинулся бы никогда. */
        fl->fwd_after_hello++;
        fl->last_fwd_after_hello_ns = now_ns;
    }

    /* Observe each STUN transaction before the handshake/plan fast path.
       Later requests sent without execution must remain unbound. */
    int new_stun_request=0;
    d2k_stun_request_slot *stun_request=NULL;
    if(is_stun_request(pkt+payload_off,payload_len))
        stun_request=stun_observe_request(fl,pkt+payload_off+8,now_ns,&new_stun_request);

    /* ПОВРЕЖДЕНИЕ — ДО РАННЕГО ВЫХОДА по уже разобранному приветствию.
       Поток портится ПОСЛЕ применения плана, то есть saw_hello к этому
       моменту всегда взведён: проверка, стоящая после этого выхода,
       недостижима по построению (0009, U3-R2). */
    if (fl->damaged) {
        out->skipped = "поток испорчен предыдущей отменой";
        return;
    }
    if (fl->quic_deny) {
        out->verdict = D2K_VERDICT_DROP;
        out->quic_deny = 1;
        out->skipped = "QUIC для имени не пропускается: обхода по QUIC нет, клиент уйдёт на TCP";
        return;
    }
    /* Приветствие уже разбирали — второй раз незачем. КРОМЕ случая, когда
       план к нему так и не применился: у QUIC первая датаграмма и есть
       приветствие, и на ней запись conntrack ещё не подтверждена (см.
       flow_tracked) — применить план мы не смогли и честно отказались. Повтор
       Initial по таймеру PTO — второй и последний шанс это сделать, и
       отбрасывать его как «уже показывал» значило бы отказаться от обхода
       всего потока из-за порядка, в котором ядро подтверждает записи.
       Замерено на роутере Марка 13.09.2026: по QUIC клиент за роутером не
       проходил именно так.

       Окно поиска по-прежнему держит цену: попыток не больше
       D2K_HELLO_WINDOW на поток. */
    if (!stun_request && ((fl->saw_hello && fl->plan_done && !fl->udp_replan) ||
        fl->fwd_pkts > D2K_HELLO_WINDOW)) {
        /* Поздняя доставка (этап 17): точная проба этого потока открывает
           окно заново — ровно для него. */
        if (fl->saw_hello || !late_raw_probe(s, fl, ip, u, pkt+payload_off, payload_len, now_ns)) {
            out->skipped = fl->saw_hello ? "поток уже показывал приветствие"
                                          : "за окном поиска";
            return;
        }
    }

    if (payload_len == 0) {
        out->skipped = "нет полезной нагрузки";
        return;
    }

    /* ГОЛОС ИЛИ QUIC. Дальше путь общий — имя, журнал, план, исполнение, — и
       различаются только имя и форма: у QUIC имя из Initial, у голоса —
       ярлык класса (D2K_VOICE_CLASS в d2k_plans.h про то, почему не домен и
       не адрес). */
    int discord_voice = is_discord_ip_discovery(pkt + payload_off, payload_len);
    int stun_voice = is_stun_request(pkt + payload_off, payload_len);
    int voice = discord_voice || stun_voice;
    /* КЛАСС ГОЛОСА ДИСКОРДА — только то, что про Дискорд и доказано: IP
       Discovery (строгая сигнатура) или STUN на медиапорт Дискорда. Прочий
       STUN (3478 к любому адресу, TURN, WebRTC других приложений) — не голос
       Дискорда: ярлык класса отдал бы ему чужой постоянный план и завёл бы
       задачу @discord-voice. Его путь — адресный, по точке сервера с формой
       голоса/STUN (задача 16), без выдуманного имени (§4, §5). */
    uint16_t server_port = (uint16_t)((uint16_t)u[2] << 8 | u[3]);
    int discord_class = discord_voice ||
        (stun_voice && server_port >= D2K_DISCORD_MEDIA_PORT_LO &&
         server_port <= D2K_DISCORD_MEDIA_PORT_HI);
    int first_voice_request=discord_voice && !fl->voice_ssrc_valid;
    int first_stun_request=stun_voice && !fl->stun_txid_valid;
    if (first_voice_request) {
        memcpy(fl->voice_ssrc, pkt + payload_off + 4, sizeof fl->voice_ssrc);
        fl->voice_ssrc_valid = 1;
    }
    if (first_stun_request) {
        memcpy(fl->stun_txid, pkt + payload_off + 8, sizeof fl->stun_txid);
        fl->stun_txid_valid = 1;
    }
    if (!voice && !d2k_quic_is_initial(pkt + payload_off, payload_len)) {
        /* UDP БЕЗ РАСПОЗНАННОГО ПРОТОКОЛА (этап 16): опыт на ПРОДОЛЖЕНИИ
           самого клиента — точная запись опыта по 5-tuple этого потока
           (SET_ADDR_PROBE контроллера, trial ID, lease) или постоянный
           адресный план формы RAW (подтверждённое решение адреса). Ничего не
           выдумывается: исполняется план на ЭТОЙ датаграмме клиента, один раз
           на поток; ответ сервера после этого — EXCHANGE planned=YES. */
        if (!fl->saw_hello && !fl->saw_initial && !fl->controller_probe && payload_len > 0 &&
            !fl->stun_txid_valid && !fl->voice_ssrc_valid) {
            /* СТОРОНА — ТОЛЬКО ПО КРЮЧКУ. OUTPUT/POSTROUTING называют клиента
               прямо, и это знание потока: подозрение понесёт client_side, и
               контроллер сможет поставить точную пробу ЭТОГО 5-tuple. Догадку
               по порту 443 знанием не считаем — без крючка стороны нет. */
            if (from_client == 1 && !fl->dir_known) {
                fl->init_low = src_is_low;
                fl->dir_known = 1;
            }
            flow_fact(s, fl, &key, now_ns);
            d2k_addr_probe_flow rf;
            memset(&rf, 0, sizeof rf);
            rf.family = ip->family;
            memcpy(ip->family == 6 ? rf.src_ip6 : rf.src_ip4, ip->src.bytes, ip->family == 6 ? 16 : 4);
            memcpy(ip->family == 6 ? rf.dst_ip6 : rf.dst_ip4, ip->dst.bytes, ip->family == 6 ? 16 : 4);
            memcpy(&rf.src_port_be, u + 0, 2);
            memcpy(&rf.dst_port_be, u + 2, 2);
            rf.transport = 17;
            uint8_t raw_trial[D2K_TRIAL_ID_LEN] = {0};
            const d2k_plan *raw_use = measured_probe(s,fl,ip,u,0,pkt+payload_off,payload_len,now_ns,raw_trial);
            /* Свежий ИЗМЕРЕННЫЙ опыт на уже исполненном потоке (та же правка,
               что у TCP, раунд UDP): точное совпадение measured_probe по
               кортежу/поколению/байтам, ПРЕДЫДУЩИЕ посылки завершены
               (sends_left==0) и не падали (sends_failed==0), и это ДРУГОЙ trial.
               Только тогда plan_done не запрещает исполнение: контроллер после
               неудачи собственного плана ставит новый измеренный кандидат на
               том же продолжении клиента. Тот же trial, незавершённые/упавшие
               посылки — по-прежнему блокированы; адресная проба и постоянный
               план исключения не получают (их scope не first-segment). */
            int raw_measured_new = raw_use && !fl->sends_left && !fl->sends_failed &&
                memcmp(raw_trial, fl->execution_trial_id, D2K_TRIAL_ID_LEN) != 0;
            if(!raw_use)raw_use=d2k_plantab_find_addr_probe(s->plans, &rf, now_ns, raw_trial);
            if (!raw_use) {
                memset(raw_trial, 0, sizeof raw_trial);
                raw_use = d2k_plantab_find_target_endpoint_tr(s->plans, NULL, 0, ip->dst.bytes, ip->family,
                                                              now_ns, D2K_PLAN_SHAPE_RAW, 0, rf.dst_port_be, 17);
            }
            if (raw_use) {
                if (fl->plan_done && !raw_measured_new) { out->skipped = "план уже применён к этому потоку"; return; }
                if (!plan_fits_transport(raw_use, 17)) { out->skipped = "план объявлен для другого транспорта"; return; }
                if (!fl->client_shape) { fl->client_shape = D2K_PLAN_SHAPE_RAW; }
                udp_execute(s, fl, &key, raw_use, raw_trial, pkt, payload_off, payload_len, ip, u, now_ns,
                            buf, bufcap, held_first_replay, 0, NULL, 0, NULL, out);
                return;
            }
        }
        out->skipped = "не QUIC Initial и не голос Дискорда";
        return;
    }

    /* ДАТАГРАММА ПОЛЁТА — В КОЛЬЦО СРАЗУ (задача 66). Позже её взять
       неоткуда: к моменту, когда ClientHello сложился, первая датаграмма уже
       прошла, а ловушку снимка контроллер взводит ещё позже — по подозрению,
       то есть на следующем соединении. Поле 15.10.2026: с записью «только
       пока ловушка взведена» первый полёт целей не собирался вовсе, и снимок
       оставался обрывком (kinozal.me, 1038 байт). Цена — memcpy датаграммы
       на клиентский Initial, которых у соединения один-два.

       ТОЛЬКО ДО СНИМКА ПОЛЁТА. После рукопожатия клиент шлёт по тому же DCID
       ещё Initial — с подтверждениями, без добивки до 1200. Они часть
       соединения, но не часть ПРИВЕТСТВИЯ, и в пачке делали полёт из двух
       датаграмм полётом из четырёх (поле 15.10.2026: lostfilm.tv, 4488 байт
       вместо примерно 2400). */
    if (!voice && !fl->controller_probe && !fl->qsnap_done) {
        init_ring_add(s, &key, pkt + payload_off, payload_len);
    }

    /* Stateful assembly осознанно не различает «не расшифровалось этими
       ключами» и «расшифровалось, но server_name нет» — оба случая
       дают отсутствие готового имени (0 или -1). Различать их здесь тоже
       нельзя: объявить второе как
       факт значило бы дописать модулю определённость, которой у него нет, а
       расшифровка могла не сойтись из-за ловушки Retry выше. Направление
       здесь ни при чём — оно доказано портом до этого места, а не
       расшифровкой (см. большой комментарий выше). Поэтому -1 не взводит
       saw_hello и не пишет в журнал НИЧЕГО — ни узнанного имени, ни «имени
       нет»: со следующей датаграммой этого же потока попытка честно
       повторится, пока не кончится окно. */
    /* БЕЗ ИМЕНИ — НО НЕ БЕЗ ПЛАНА.
     *
     * Поле 19.09.2026: настоящий клиент (curl/ngtcp2) разбрасывает ClientHello
     * по множеству мелких кадров CRYPTO в разнобой, поперёк ДВУХ
     * Initial-датаграмм; d2k_quic_assembly теперь собирает их по DCID и
     * смещениям CRYPTO. Пока непрерывный ClientHello не готов, здесь всё ещё
     * должен быть честный выход — имя и план нельзя вывести из половины.
     *
     * Имя при этом не выдумывается и неполный пакет не объявляется
       приветствием:
     * счётчики, журнал и снимок остаются нетронутыми (§2.4 — «не измерено» не
     * превращается в факт). Но план, который про имя не спрашивает, обязан
     * достаться: у плана по адресу имени нет по построению, у общего — тем
     * более. */
    char name[256];
    int named = 1;
    if (discord_class) {
        snprintf(name, sizeof name, "%s", D2K_VOICE_CLASS);
    } else if (voice) {
        named = 0;          /* STUN без класса: только адресный путь */
        name[0] = '\0';
    } else {
        int assembled = d2k_quic_assembly_feed(&fl->quic_assembly,
                                                pkt + payload_off,
                                                payload_len, name, sizeof name);
        if (assembled != 1) {
            named = 0;
            name[0] = '\0';
        }
    }
    size_t name_len = strlen(name);
    uint8_t seen_shape = voice ? D2K_PLAN_SHAPE_VOICE : D2K_PLAN_SHAPE_QUIC;
    fl->client_shape = seen_shape;

    /* Внешний UDP hold уже сохранил эту датаграмму.  Пока ClientHello не
       собран, только накапливаем состояние; когда имя появилось, сообщаем
       владельцу hold, чтобы он взял ПЕРВУЮ исходную датаграмму и повторил её
       через обычный plan path. Нельзя применять воздействие к текущему
       хвосту: это поменяло бы порядок и оставило голову без стратегии. */
    if (fl->udp_hold_active) {
        if (!named) {
            out->udp_hold_wait = 1;
            out->skipped = "QUIC ClientHello ещё не собран — датаграмма удерживается";
        } else {
            out->udp_hold_ready = 1;
            out->skipped = "QUIC ClientHello собран — требуется replay исходных датаграмм";
        }
        return;
    }

    /* Направление уже доказано портом выше, ДО попытки разбора содержимого;
       успешный разбор здесь доказывает отдельный, независимый факт — что
       содержимое ДЕЙСТВИТЕЛЬНО клиентский Initial, а не мусор со случайно
       правильной стороны. Два независимых доказательства, а не одно на
       двоих. */
    fl->init_low = src_is_low;
    fl->dir_known = 1;

    /* ПРИВЕТСТВИЕ СЧИТАЕТСЯ ОДИН РАЗ НА ПОТОК. Сюда мы можем прийти второй
       раз — повтором Initial по таймеру PTO, когда план на первой датаграмме
       применить не удалось (см. большой комментарий у проверки выше). Это
       та же самая цель того же потока, и удваивать счётчики, событие журнала
       и снимок значило бы рассказывать контроллеру о двух обращениях там, где
       было одно. */
    int first_hello = named && !fl->saw_hello;
    if (named) {
        fl->saw_hello = 1;
        fl->had_sni = 1;
    } else if (!fl->saw_initial) {
        /* Имени нет — приветствием не объявляем (счётчики, журнал и снимок не
           трогаем), но молчание по этому потоку замечать обязаны: см.
           saw_initial в d2k_track.h. Срок молчания считается от ПЕРВОГО такого
           Initial, как и у приветствия с именем. */
        fl->saw_initial = 1;
        fl->hello_ns = now_ns;
    }
    if (first_hello) {
        fl->hello_ns = now_ns;
        /* Те же счётчики и то же событие журнала, что и для TLS
           (D2K_JRN_HELLO_SNI, s->hellos, s->with_sni) — по требованию задачи
           4: имя есть имя для контроллера независимо от транспорта. */
        s->hellos++;
        s->with_sni++;
        if (!fl->controller_probe) {
            d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_SNI, 0, 0, NULL,
                            (const uint8_t *)name, name_len, NULL);
        }
    }

    /* СНИМОК ПРИВЕТСТВИЯ QUIC — ровно то же, что делает ветка TCP, и по той
       же причине: контроллер мерит ТЕМ, чем ходит клиент, а не заготовкой.
       Без этого QUIC-задача уходила мерить с TLS-приветствием из профиля
       холодного старта — байтами, которые разбор Initial отвергает первым же
       шагом, и вертикаль обрывалась, не начавшись.

       Слот свой (см. slot_of): TLS-приветствие и Initial — разные байты
       разной формы, и отдавать одно вместо другого нельзя. */
    /* СНИМОК — КОГДА ПРИВЕТСТВИЕ ЦЕЛОЕ, а не когда нашлось имя (спецификация
       задачи 66, §1). Chrome переставляет расширения: имя бывает в первой
       датаграмме, а ClientHello кончается во второй. Снимок по имени уходил
       пачкой из одной датаграммы, и контроллер отвергал его как обрывок
       (поле 15.10.2026). Один раз на поток: повтор Initial с тем же именем,
       пришедший после снимка, снова снимком не становится — кольцо уже
       очищено, и уходила бы одиночная датаграмма-обрывок. */
    if (named && !voice && !fl->controller_probe && !fl->qsnap_done &&
        d2k_quic_assembly_complete(&fl->quic_assembly)) {
        fl->qsnap_done = 1;
        size_t k = shape_slot(17, key.family);
        /* ВЕСЬ ПОЛЁТ, А НЕ ПОСЛЕДНЯЯ ДАТАГРАММА (задача 66): приветствие с
           постквантовым key_share едет двумя Initial. Пачка не собралась —
           кладём одну датаграмму, как прежде: контроллер отвергнет её как
           обрывок, и это честнее склейки наугад. */
        uint8_t pack[D2K_SHAPE_MAX];
        size_t pack_len = init_ring_pack(s, &key, pkt + payload_off, payload_len,
                                         pack, sizeof pack);
        /* Полёт собран — записи этого потока кольцу больше не нужны. Без
           этого кольцо занимали уже ненужные полёты, и датаграмма цели, чьё
           имя ещё не собралось, вытеснялась: снимок оставался обрывком
           (поле 15.10.2026, enimerosi и mailsuite — пачка из одной
           датаграммы в 1044 байта). */
        init_ring_drop(s, &key);
        const uint8_t *snap = pack_len ? pack : pkt + payload_off;
        size_t snap_len = pack_len ? pack_len : payload_len;
        if (snap_len <= sizeof s->last_hello[k]) {
            memcpy(s->last_hello[k], snap, snap_len);
            s->last_hello_len[k] = snap_len;
            s->last_name_len[k] = 0;
            if (name_len > 0 && name_len <= sizeof s->last_name[k]) {
                memcpy(s->last_name[k], name, name_len);
                s->last_name_len[k] = name_len;
            }
        }
        /* ECH ВНЕ ОЧЕРЕДИ (поле 15.10.2026), как у TCP: внешнее приветствие
           с ECH заготовкой не воспроизвести, а коробка, глушащая полёт
           клиента, пропускает заготовку — и поиск кончался ложным
           «напрямую проходит». Такую пачку контроллер получает сразу, не
           дожидаясь заказа, пока следующее соединение её не перекрыло. */
        int ech = 0;
        if (pack_len) {
            d2k_qsnap pk;
            static uint8_t rec[5 + D2K_SHAPE_MAX];
            size_t chl = 0;
            if (d2k_qsnap_parse(pack, pack_len, &pk) == 0 &&
                d2k_qsnap_client_hello(&pk, rec + 5, sizeof rec - 5, &chl) == 0 &&
                chl > 0 && chl <= 0xffff) {
                rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x01;
                rec[3] = (uint8_t)(chl >> 8); rec[4] = (uint8_t)chl;
                d2k_tls_info ti;
                memset(&ti, 0, sizeof ti);
                (void)d2k_tls_parse(rec, chl + 5, &ti);
                ech = ti.is_client_hello && ti.ech_offer;
            }
        }
        int requested = s->shape_armed[k] &&
            (s->shape_name_len[k] == 0 ||
             name_same((const uint8_t *)name, name_len,
                       s->shape_name[k], s->shape_name_len[k]));
        if ((requested || ech) && snap_len <= sizeof s->shape[k]) {
            memcpy(s->shape[k], snap, snap_len);
            s->shape_len[k] = snap_len;
            s->shape_key[k]=key;s->shape_at[k]=now_ns;
            if (requested) s->shape_armed[k] = 0;
            d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_SHAPE, 0,
                            (uint32_t)snap_len, NULL, NULL, 0, NULL);
        }
    }

    /* Форма — СВОЯ, QUIC. Ноль здесь был дырой: он означает «не объявлено» и
       совместим с чем угодно, поэтому план, подтверждённый собственным зондом
       на TLS поверх TCP, выдавался Initial того же имени. Транспорт другой,
       приветствие другое, и коробка на пути может быть другая — переносить
       туда подтверждение нечем (0009, U5).

       Записи старого каталога (форма не объявлена) остаются совместимыми: их
       миграция — задача каталога, а не мгновенного отказа здесь. Совместимы
       они по ФОРМЕ; транспорт проверяется отдельно и ниже — он объявлен в
       самом плане, и догадываться о нём не нужно (plan_fits_transport). */
    /* МЕСТНЫЙ ПОРТ — чтобы пробная запись досталась только потоку зонда и
       никому больше (d2k_plans.h про d2k_plantab_set_name_probe). Берётся из
       заголовка как есть, в сетевом порядке: таблица сравнивает его с тем,
       что назвал контроллер, и переворачивать по дороге нечего. */
    uint16_t sport_be;
    memcpy(&sport_be, u + 0, 2);
    d2k_addr_probe_flow probe_flow;
    memset(&probe_flow, 0, sizeof probe_flow);
    probe_flow.family = ip->family;
    memcpy(ip->family == 6 ? probe_flow.src_ip6 : probe_flow.src_ip4,
           ip->src.bytes, ip->family == 6 ? 16 : 4);
    memcpy(&probe_flow.src_port_be, u + 0, 2);
    memcpy(ip->family == 6 ? probe_flow.dst_ip6 : probe_flow.dst_ip4,
           ip->dst.bytes, ip->family == 6 ? 16 : 4);
    memcpy(&probe_flow.dst_port_be, u + 2, 2);
    probe_flow.transport = 17;
    uint8_t trial_id[D2K_TRIAL_ID_LEN] = {0};
    /* ГОЛОСОВОЙ ОПЫТ (задача 15) — только запросу голоса пользовательского
       потока. Межсетевой экран отдаёт в очередь лишь первые пакеты потока
       (S99d2k, connbytes 0:8), поэтому опыт ждёт СЛЕДУЮЩИЙ разговор того же
       клиента LAN с той же точкой сервера (адрес и порт), с любым клиентским
       портом; его первый IP Discovery / STUN-запрос и получает план, APPLIED
       несёт trial ID. Зонд контроллера может брать только опыт своего
       точного 5-tuple: подстановочный клиентский порт ему недоступен,
       как и не-голосовому потоку (find_addr_probe). */
    const d2k_plan *use = NULL;
    if (!voice || fl->controller_probe) {
        use = d2k_plantab_find_addr_probe(s->plans, &probe_flow, now_ns, trial_id);
    } else {
        use = d2k_plantab_find_voice_probe(s->plans, &probe_flow, now_ns, trial_id);
    }
    if (!use) { memset(trial_id, 0, sizeof trial_id); }
    size_t misses_before = d2k_plantab_shape_misses(s->plans);
    if (!use) { use = d2k_plantab_find_target_endpoint(s->plans,
                                                 named ? (const uint8_t *)name : NULL,
                                                 name_len, ip->dst.bytes, ip->family, now_ns,
                                                 seen_shape, controller_probe ? sport_be : 0,
                                                 probe_flow.dst_port_be); }
    if (named && !voice) {
        snprintf(out->flow_name, sizeof out->flow_name, "%.*s", (int)name_len, name);
        out->shape_miss = d2k_plantab_shape_misses(s->plans) != misses_before;
    }
    if (!use) {
        use = s->plan;
    }
    if (!plan_fits_transport(use, 17)) {
        /* План не про этот транспорт — молчать нельзя: иначе контроллер
           считает, что цель без плана, и заводит поиск снова и снова. */
        out->skipped = "план объявлен для другого транспорта";
        if (first_hello) { refuse(s, now_ns, &key, out->skipped); }
        return;
    }
    if (!use) {
        out->skipped = "плана для этой цели нет";
        /* Событие обязано выйти на провод (ревью, пункт 3): раньше эта
           ветка не звала refuse() вовсе, и однажды вытесненная из таблицы
           (см. d2k_plans.h про LRU) подтверждённая цель терялась НАВСЕГДА
           без единого следа для контроллера, кроме счётчика в сводке d2kd.

           НЕ ЧАЩЕ ОДНОГО РАЗА НА ПОТОК — теперь это условие, а не следствие.
           Пока повтор Initial отсеивался раньше, сюда нельзя было попасть
           дважды; с тех пор как повтор допущен (план мог не примениться на
           первой датаграмме, см. flow_tracked), второй заход сюда означал бы
           два события об одном обращении. Прежний текст объяснял именно то
           следствие:
           дойдя до разбора Initial. */
        if (first_hello) { refuse(s, now_ns, &key, out->skipped); }
        return;
    }
    /* ПОВРЕЖДЕНИЕ ПРОВЕРЯЕТСЯ РАНЬШЕ «уже применён». Порядок не косметика:
       поток портится ровно тогда, когда план к нему уже применялся, и при
       обратном порядке ветка повреждения недостижима — флаг был бы
       write-only, а контроллер не получал бы о нём ни слова. */
    if (fl->plan_done && !fl->udp_replan) {
        d2k_binding_context selected={0};
        int changed=stun_request &&
            d2k_plantab_binding(s->plans,use,&selected) &&
            !d2k_binding_equal(&selected,&fl->execution_binding);
        if(!stun_request || (!new_stun_request && !changed)) {
            out->skipped = "план уже применён к этому потоку";
            return;
        }
    }
    if (d2k_plan_quic_deny(use)) {
        /* Задача 50, раунд 2: обхода по QUIC нет — поток не складывается,
           клиент уходит на TCP. Зонд контроллера не трогаем: им имя и
           перепроверяется. APPLIED нет — это не исполнение обхода. */
        if (fl->controller_probe) {
            out->skipped = "зонд контроллера: QUIC для имени снят только у клиентов";
            return;
        }
        fl->quic_deny = 1;
        out->verdict = D2K_VERDICT_DROP;
        out->quic_deny = 1;
        out->skipped = "QUIC для имени не пропускается: обхода по QUIC нет, клиент уйдёт на TCP";
        return;
    }

    udp_execute(s, fl, &key, use, trial_id, pkt, payload_off, payload_len, ip, u, now_ns,
                buf, bufcap, held_first_replay, first_voice_request, stun_request, new_stun_request,
                NULL, out);
}

/* Приветствие TCP узнано: запомнить подтверждение, с которым оно ушло, и
   учесть поток в знаменателе d2k_session_reply_hidden. */
static void note_tcp_hello(d2k_session *s, d2k_flow *fl, int ack,
                           const uint8_t *tcp) {
    /* Зонд контроллера — не пользовательский поток: исключён и здесь, и в
       числителе, иначе доля «невидимых» ответов занижалась бы. */
    if (!fl->controller_probe) { s->tcp_hello_flows++; }
    fl->hello_ack = rd32(tcp + 8);
    fl->hello_ack_valid = ack ? 1 : 0;
}

/* ПОТОК КЛИЕНТА С МЕТКОЙ МАРШРУТИЗАЦИИ (задача 47, поле 03.10.2026).
 *
 * Keenetic метит пакеты клиента с маршрутом по политике или доменам в mangle
 * PREROUTING (0xffffaaa -> ip rule 100 -> таблица 4096, например VPN) — до
 * нашей очереди в POSTROUTING. Все сырые посылки d2k (фальшивки, куски,
 * собственный Initial задачи 42) идут с меткой 0x2d по главной таблице, то
 * есть через провайдера мимо VPN: утечка ClientHello/Initial и разорванное
 * соединение. Такой поток не получает ни плана, ни удержания, ни наблюдения:
 * его ответы и молчание — свойство чужого пути, а не коробки провайдера, и
 * уликой для контроллера быть не могут. Помечается поток (обе стороны), а не
 * пакет: ответы сервера приходят без метки клиента. */
static int routed_flow(d2k_session *s, const uint8_t *pkt, size_t len,
                       const d2k_packet_view *ip, uint64_t now_ns, uint32_t route_mark,
                       d2k_result *out) {
    if ((ip->protocol != 6 && ip->protocol != 17) || len < ip->l4 + 4 ||
        (ip->fragment & 0x1fff)) {
        return 0;
    }
    const uint8_t *l4 = pkt + ip->l4;
    d2k_key key;
    (void)d2k_key_make_addr(&key, ip->protocol, &ip->src, &ip->dst, l4, l4 + 2);
    d2k_table *t = ip->protocol == 6 ? s->flows : s->uflows;
    d2k_flow *fl;
    if (route_mark) {
        fl = d2k_track_get(t, &key, now_ns);
        if (fl && !fl->routed) {
            fl->routed = 1;
            s->routed_flows++;
            out->routed_first = 1;
            out->routed_mark = route_mark;
        }
    } else {
        fl = d2k_track_find(t, &key);
        if (!fl || !fl->routed) { return 0; }
        /* Новый SYN без метки на том же кортеже — новое соединение (ревью M1):
           флаг прежнего не переживает его, дальше обычный путь SYN. */
        if (ip->protocol == 6 && len >= ip->l4 + 14 &&
            (l4[13] & 0x12) == 0x02) {
            fl->routed = 0;
            return 0;
        }
    }
    out->skipped = "клиент с меткой маршрутизации — поток идёт ядром";
    return 1;
}

static int session_packet(d2k_session *s, const uint8_t *pkt, size_t len,
                       uint64_t now_ns, uint8_t *buf, size_t bufcap,
                       d2k_result *out, int observe_only,
                       int controller_probe, size_t tcp_segment_cap) {
    if (!out) {
        return 0;
    }
    memset(out, 0, sizeof *out);
    /* 0xFF — «нагрузки в плане нет». Ноль был бы законным НОМЕРОМ посылки, и
       отличить «первая посылка — нагрузка» от «нагрузки нет» стало бы нечем. */
    out->first_payload = 0xFF;
    out->verdict = D2K_VERDICT_ACCEPT;
    if (!s || !pkt) {
        out->skipped = "нет сессии или пакета";
        return 0;
    }

    /* --- заголовки, с явными границами на каждом шаге ------------------- */
    d2k_packet_view ip;
    if (!d2k_packet_parse(pkt, len, &ip)) {
        out->skipped = "неподдержанный или неполный IP-пакет";
        return 0;
    }
    size_t ihl = ip.l4;
    if (ihl < 20) {
        /* Нарушение самого IPv4: IHL короче 20 байт не бывает ни при каком
           транспорте — эта проверка делится TCP и UDP честно, а не по
           TCP-инерции (ниже — наоборот, минимум под конкретный L4). */
        out->skipped = "заголовок не помещается";
        return 0;
    }
    /* Метка — только у пакета, ради которого её поставили: отпущенные
       удержанием сегменты (observe_only) идут с нулём, даже если вызов пришёл
       между пакетами (ревью I1). */
    if (routed_flow(s, pkt, len, &ip, now_ns, observe_only ? 0 : s->route_mark, out)) {
        return 0;
    }
    if (!observe_only && !controller_probe && buf &&
        bufcap >= D2K_PF_OUT_MAX * D2K_PF_PACKET_MAX) {
        d2k_pf_out pf;
        if (d2k_session_preflight_packet(s, pkt, len, now_ns, &pf)) {
            out->verdict = D2K_VERDICT_DROP;
            size_t off = 0;
            for (size_t i = 0; i < pf.count; i++) {
                memcpy(buf + off, pf.packet[i], pf.len[i]);
                out->out[i].off = off; out->out[i].len = pf.len[i];
                off += pf.len[i];
            }
            out->n_out = pf.count;
            return 0; /* lifecycle is distinct from ordinary plan APPLIED */
        }
    }
    if (ip.protocol == 17) {
        /* UDP — своя ветка, см. handle_udp выше. Дальше в этой функции всё
           написано под TCP-заголовок и трогать эти байты как UDP нельзя.
           Проверка «хватает ли len на минимальный заголовок» — внутри
           handle_udp, СВОИМ порогом (8 байт UDP, а не унаследованным TCP-20:
           см. ревью задачи 4 — короткая, но честная UDP-датаграмма получала
           TCP-объяснение «заголовок не помещается» ровно из-за этого). */
        if (!observe_only) {
            handle_udp(s, pkt, len, &ip, now_ns, buf, bufcap, out,
                       controller_probe);
        }
        return 0;
    }
    if (ip.protocol != 6) {
        out->skipped = "не TCP";
        return 0;
    }
    if (len < ihl + 20) {
        out->skipped = "заголовок не помещается";
        return 0;
    }
    /* Фрагмент без нулевого смещения не несёт заголовка TCP. Собирать
       фрагменты датапат не умеет и не должен: §5.2 говорит про ОГРАНИЧЕННУЮ
       пересборку, и её ещё нет. */
    if ((ip.fragment & 0x1fff) != 0) {
        out->skipped = "фрагмент";
        return 0;
    }
    size_t total = ip.total;
    if (total > len || total < ihl + 20) {
        out->skipped = "поле длины не сходится";
        return 0;
    }

    const uint8_t *t = pkt + ihl;
    size_t doff = (size_t)(t[12] >> 4) * 4;
    if (doff < 20 || ihl + doff > total) {
        out->skipped = "заголовок TCP не помещается";
        return 0;
    }

    d2k_key key;
    int src_is_low = d2k_key_make_addr(&key, 6, &ip.src, &ip.dst, t, t + 2);

    uint8_t flags = t[13];
    const int fin = (flags & 0x01) != 0;
    const int syn = (flags & 0x02) != 0;
    const int rst = (flags & 0x04) != 0;
    const int ack = (flags & 0x10) != 0;

    if (syn && !ack) { d2k_capture_forget(&s->capture, &key); }

    d2k_flow *fl = d2k_track_get(s->flows, &key, now_ns);
    if (!fl) {
        /* Таблица полна. Пропускаем — и это правильный исход: обработать
           пакет без учёта потока значит применить план второй раз к тому же
           соединению. */
        out->skipped = "таблица потоков полна";
        return 0;
    }

    if (syn && !ack) { fl->hello_capture_done = 0; }

    /* Направление. Сперва по флагам, и только потом по порядку прибытия.
       SYN без ACK шлёт тот, кто открывает соединение; SYN с ACK — тот, кто
       отвечает. Это свойство протокола, а не наблюдения, и потому надёжнее:
       два направления приходят из ДВУХ правил firewall, и порядок между ними
       не гарантирован ничем. Ранняя редакция определяла сторону по первому
       увиденному пакету, и поток, у которого SYN-ACK обогнал SYN, получал
       направления наоборот — приветствие клиента считалось ответом сервера и
       не разбиралось вовсе. */
    if (!fl->dir_known) {
        if (syn && !ack) {
            fl->init_low = src_is_low;
            fl->dir_known = 1;
        } else if (syn && ack) {
            fl->init_low = !src_is_low;
            fl->dir_known = 1;
        } else if (fl->fwd_pkts == 0 && fl->rev_pkts == 0) {
            /* Поток подхвачен посреди обмена: рукопожатия мы не видели.
               Берём порядок прибытия и НЕ считаем это знанием — придёт SYN,
               поправимся. */
            fl->init_low = src_is_low;
        }
    }
    const int fwd = (src_is_low == fl->init_low);
    if(!fwd && fl->stream_plan_stage==4 && fl->stream_plan_pending &&
       (t[13]&0x10) && !fl->sends_left && !fl->sends_failed) {
        uint32_t acked=rd32(t+8)-(fl->syn_seq+1u);
        if(acked<UINT32_C(0x80000000) && acked>=fl->stream_plan_offset+fl->stream_plan_length)
            fl->stream_plan_pending=0;
    }
    /* Поздняя доставка (этап 17): пакет клиента на потоке под меткой записи
       дошёл до очереди — свидетельство, что правило метки работает (без него
       d2kd честно говорит «пакетов не было»). */
    if (fwd && fl->late_watch) { s->late_delivered++; }
    if (total > ihl + doff) fl->tcp_payload_seen = 1;

    /* Снимок ДО учёта этого пакета. Сам сброс — тоже пакет с обратной
       стороны, и, посчитав его первым, проверка «ответов не было» не сработала
       бы никогда: счётчик к моменту проверки уже единица. */
    const uint32_t rev_before = fl->rev_after_hello;

    /* Пакеты с данными — для оценки бюджета потока (задача 56). */
    const int has_payload = total > ihl + doff;
    if (fwd) {
        fl->fwd_pkts++;
        fl->fwd_bytes += total;
        if (has_payload) { fl->fwd_data_pkts++; }
    } else {
        fl->rev_pkts_conn++;
        if (has_payload) { fl->rev_data_pkts++; }
        if (!fl->rev_profiled) {
            /* Первый пакет с той стороны задаёт ориентир. Обычно это SYN-ACK,
               то есть заведомо настоящий сервер: подделка приходит позже, в
               ответ на приветствие. */
            fl->rev_profiled = 1;
            fl->rev_ttl = ip.hop_limit;
            fl->rev_tos = pkt[1];
        }
        fl->rev_pkts++;
        fl->rev_bytes += total;
        s->rev_seen[shape_slot(6, fl->key.family)] = 1;
        if (fl->saw_hello) {
            fl->rev_after_hello++;
            size_t rpay_off = ihl + doff;
            if (total > rpay_off) {
                size_t rpay = total - rpay_off;
                uint8_t t0 = pkt[rpay_off];
                /* ОТВЕТ СЕРВЕРА — по разбору, а не по типу записи.
                   Спрашиваем один раз: как только ServerHello увиден, повод
                   разбирать обратное направление исчезает. Разбор здесь
                   дешёвый (несколько границ) и идёт только до первого
                   ответа. */
                if (!fl->rev_server_hello) {
                    d2k_tls_info ri;
                    if (d2k_tls_parse(pkt + rpay_off, rpay, &ri) == 0) {
                        if (ri.is_server_hello) fl->rev_server_hello = 1;
                        if (ri.is_server_hello || (ri.is_tls_record &&
                            ri.record_type == 23 && ri.have_record_end &&
                            ri.record_end > 5 && pkt[rpay_off + 2] <= 3))
                            fl->rev_tls_reply = 1;
                    }
                }
                if (fl->rev_first_type == 0) {
                    /* Тип первой TLS-записи запоминается как есть. Толковать
                       его здесь нельзя: 0x16 рукопожатие и 0x15 предупреждение
                       — разные вещи, а §4.2 требует, чтобы уровни
                       доказательства различал принимающий решение. */
                    fl->rev_first_type = t0;
                }
                /* Начало пакета — не начало записи, поэтому набор говорит
                   «такой тип встречался», а не «записей столько-то».
                   Прикладные данные здесь важнее прочего: по §4.2 одного
                   ServerHello для подтверждения НЕ хватает. */
                if (rpay >= 5 && t0 >= 20 && t0 <= 23 &&
                    pkt[rpay_off + 1] == 3 && pkt[rpay_off + 2] <= 3) {
                    fl->rev_types |= (uint8_t)(1u << (t0 - 20));
                }
                fl->rev_payload_after_hello += (uint32_t)rpay;
            }
        }
    }
    /* Ответ, которого очередь не видела (d2k_session_reply_hidden): клиент
       подтверждает данные сервера, а с обратной стороны после приветствия
       не пришло ни пакета. Стоит до разбора закрытия и до «нет нагрузки»:
       подтверждение чаще всего едет чистым ACK без нагрузки. Только
       наблюдение — вердикт пакета не меняется. */
    if (fwd && ack && !syn && fl->saw_hello && fl->hello_ack_valid &&
        !fl->reply_hidden_told && !fl->controller_probe &&
        fl->rev_after_hello == 0 &&
        (int32_t)(rd32(t + 8) - fl->hello_ack) > 0) {
        fl->reply_hidden_told = 1;
        s->reply_hidden++;
    }

    /* Признак «время не записано» — отдельный флаг, а не нулевое время. Ноль
       это законная отметка часов, и опираться на неё значит терять первый же
       поток, начавшийся в начале отсчёта. */
    if (syn && !ack) {
        /* SYN без ACK — граница соединений на этой пятёрке, а не «первый
           увиденный пакет». Прежде начало потока бралось только при первом
           SYN, и следующее соединение в той же ячейке жило с чужим ISN и
           чужими отметками (см. d2k_track_new_connection). */
        d2k_track_new_connection(fl);
        fl->syn_ns = now_ns;
        fl->syn_seq = rd32(t + 4);
        fl->saw_syn = 1;
    }
    if (syn && !ack) {
        fl->controller_probe = controller_probe ? 1 : 0;
    } else if (controller_probe) {
        fl->controller_probe = 1;
    }
    if (syn && ack) {
        /* RTT берём с самого потока: от SYN до SYN-ACK. Ориентир из измерения,
           а не из константы — на медленной линии константа объявила бы
           молчанием обычную задержку. */
        if (fl->saw_syn && !fl->saw_synack && now_ns >= fl->syn_ns) {
            fl->rtt_ns = now_ns - fl->syn_ns;
        }
        fl->saw_synack = 1;
    }

    /* Сообщаем дважды: когда обмен вообще пошёл и когда в нём появились
       ПРИКЛАДНЫЕ данные. Это разные уровни доказательства (§4.2), и второй
       наступает позже первого — сообщить только о первом значит навсегда
       оставить контроллер на уровне 2. */
    const uint8_t appdata_bit = (uint8_t)(1u << (23 - 20));
    uint8_t raw_proof = 0;
    if (!fl->controller_probe && !fl->saw_hello && fl->raw_seen && fl->plan_done &&
        has_payload && ack && !rst && !syn)
        raw_proof = raw_proof_packet(fl, fwd, pkt + ihl + doff, total - ihl - doff,
                                      rd32(t + 4), rd32(t + 8), fin);
    if (raw_proof) {
        fl->exchange_told = 1;
        s->exchanges++;
        d2k_jrn_detail det;
        memset(&det, 0, sizeof det);
        det.planned = D2K_PLANNED_YES;
        det.client_shape = fl->client_shape;
        det.client_side = fl->dir_known ? (fl->init_low ? D2K_CLIENT_SIDE_LOW : D2K_CLIENT_SIDE_HIGH) : 0;
        d2k_journal_add_exchange_bound(s->jrn, now_ns, &key, raw_proof, fl->rev_data_pkts, &det, fl);
    }
    if (!fl->controller_probe && fl->saw_hello && fl->rev_payload_after_hello > 0 &&
        (!fl->exchange_told ||
         (!fl->appdata_told && (fl->rev_types & appdata_bit)))) {
        if (fl->rev_types & appdata_bit) {
            fl->appdata_told = 1;
        }
        fl->exchange_told = 1;
        s->exchanges++;
        d2k_jrn_detail det;
        memset(&det, 0, sizeof det);
        det.tos = fl->rev_types;   /* набор увиденных типов записей */
        det.server_hello = fl->rev_server_hello;
        /* ПРИМЕНЯЛСЯ ЛИ ПЛАН — то же поле, что у подозрения (suspect_num).
           Обмен на потоке БЕЗ плана значит, что имя завершает рукопожатие
           само, и последующий RST/молчание по нему — не блок (поле
           15.10.2026, медиа VK: часть соединений «обмен пошёл» без плана,
           часть — «сброс в ответ на приветствие»). */
        det.planned = fl->plan_done ? D2K_PLANNED_YES : D2K_PLANNED_NO;
        d2k_journal_add_exchange_bound(s->jrn, now_ns, &key,
                                       fl->rev_first_type, fl->rev_payload_after_hello,
                                       &det, fl);
    }

    /* Закрытие — повод отпустить ячейку сразу, не дожидаясь молчания.
       Но сперва посмотреть, не улика ли это. */
    if (rst && !fwd && (fl->guards & D2K_GUARD_RST_ALIEN) && fl->rev_profiled &&
        ip.hop_limit != fl->rev_ttl) {
        /* Сброс пришёл с другим TTL, чем всё, что до сих пор отвечало по этому
           соединению, — значит послан не оттуда. Снимаем.

           Поток НЕ удаляется: настоящий сервер про это соединение ничего не
           знает и продолжит отвечать, а нам ещё смотреть, чем кончится.
           Подозрение при этом отмечается: то, что мы сняли подделку, не
           означает, что её не было. §2.3 — на диск отсюда не идёт ничего. */
        fl->rst_dropped++;
        s->rst_dropped++;
        if (fl->saw_hello && rev_before == 0) {
            d2k_jrn_detail det;
            det.ttl = ip.hop_limit;
            det.ref_ttl = fl->rev_ttl;
            det.tos = pkt[1];
            det.ipid = ip.ip_id;
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_RST_CUT, &det);
        } else if (fl->saw_hello && rev_before > 0 &&
                   (fl->rev_types & (uint8_t)(1u << (23 - 20)))) {
            /* Dropping an alien RST keeps the client alive, but must not
             * hide the residual failure from the narrow RX measurement. */
            d2k_jrn_detail det;
            memset(&det, 0, sizeof det);
            det.ttl = ip.hop_limit; det.ref_ttl = fl->rev_ttl;
            det.tos = pkt[1]; det.ipid = ip.ip_id;
            det.server_hello = fl->rev_server_hello;
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_RST_AFTER_APP, &det);
        }
        out->verdict = D2K_VERDICT_DROP;
        out->skipped = "чужой сброс снят защитой";
        return 0;
    }

    if (rst || fin) {
        /* ОТВЕТ ШЁЛ ДАЛЬШЕ РУКОПОЖАТИЯ — условие, при котором закрытие
           клиента вообще может говорить об обрыве ответа. Два свидетельства:
           пакет, начатый записью 0x17, или подтверждение клиента, ушедшее за
           байты ответа, которые видела очередь, при увиденном ServerHello.
           Второе нужно потому, что очередь видит только начало ответа
           (connbytes 0:8): у TLS 1.3 там ServerHello-полёт и чистые ACK, а
           первая запись 0x17 приходит позже (поле 03.10.2026, rua.gr — пакет
           №10). Без него глухой обрыв Cloudflare не виден ничем.
           Только подтверждение КЛИЕНТА: в пакете сервера оно считает байты
           клиента и об ответе ничего не говорит. */
        const int ack_beyond = fwd && ack && fl->hello_ack_valid && fl->rev_server_hello &&
            (int32_t)(rd32(t + 8) - fl->hello_ack) > 0 &&
            rd32(t + 8) - fl->hello_ack > fl->rev_payload_after_hello;
        const int response_went_on =
            (fl->rev_types & (uint8_t)(1u << (23 - 20))) || ack_beyond;
        /* FIN клиента после ответа: поток держим до FIN/RST сервера или до
           молчания и смотрим, не повторится ли FIN с тем же концом. Повтор
           значит, что подтверждения с той стороны не пришло — сервер не
           слышен вовсе. Обычное закрытие, длинная загрузка и long-poll
           получают ACK (и FIN сервера) и повтора не дают. Раньше это
           касалось только потоков под планом; поток без плана забывался на
           первом FIN, и глухой обрыв без RST не давал ни одной улики
           (задача 50). Подозрение — лишь повод для узкого RX-замера;
           повторяемость по независимым потокам требует контроллер. */
        if (fin && !rst && fwd && fl->saw_hello &&
            (fl->plan_done || !fl->controller_probe) && response_went_on) {
            uint32_t fin_seq = rd32(t + 4) + (uint32_t)(total - ihl - doff);
            if (fl->pending_fin && fl->pending_fin_seq == fin_seq) {
                d2k_jrn_detail det;
                memset(&det, 0, sizeof det);
                det.server_hello = fl->rev_server_hello;
                suspect(s, now_ns, &key, fl, D2K_SUSPECT_FIN_RETRY, &det);
            }
            if (!fl->pending_fin || fl->pending_fin_seq != fin_seq) {
                fl->pending_fin_ns = now_ns; /* окно повтора — от первого FIN */
            }
            fl->pending_fin = 1; fl->pending_fin_seq = fin_seq;
            d2k_capture_forget(&s->capture, &key);
            out->skipped = "клиент закрывает поток после ответа; ждём подтверждение или повтор FIN";
            return 0; /* retain bounded flow metadata, never hold/drop the FIN */
        }
        if (rst && !fwd && fl->saw_hello && rev_before == 0) {
            /* Сброс пришёл с той стороны, куда ушло приветствие, и никаких
               других ответов оттуда не было. Это НАБЛЮДЕНИЕ, а не диагноз:
               §2.4 запрещает выводить из него устройство механизма. Сервер
               мог и правда закрыть соединение. */
            fl->saw_rev_rst = 1;
            d2k_jrn_detail det;
            det.ttl = ip.hop_limit;
            det.ref_ttl = fl->rev_profiled ? fl->rev_ttl : 0;
            det.tos = pkt[1];
            det.ipid = ip.ip_id;
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_RST, &det);
        } else if (rst && fl->saw_hello && rev_before > 0 &&
                   (fl->rev_types & (uint8_t)(1u << (23 - 20)))) {
            /* Только пакет 0x17, БЕЗ свидетельства подтверждением (задача 50,
               раунд 2 — решение по полю 04.10). У RST нет второй половины
               сигнала FIN — повтора в тишину: он посылается один раз и не
               отвечается ни при обрыве, ни при обычном закрытии простаивающего
               соединения. В захвате 04.10 обычные RST клиентов к CloudFront
               легли на 21,5 и 24,8 КБ — внутри разброса самого обрыва
               (19,9–24,5 КБ). Safari на обрыве ушёл не в TCP, а в QUIC, curl
               закрывает FIN-ом; выигрыш не доказан, ложные — измерены. */
            /* Поздний RST после TLS app-data сам по себе НЕ диагноз: сбросить
               мог сервер или клиент (например, браузер, прекративший ждать
               оборванный ответ). Это лишь дешёвый сигнал, после которого
               контроллер обязан доказать парой identity/gzip, что режется
               именно входящий объём; без воспроизводимого среза дальнейший
               перебор запрещён. */
            d2k_jrn_detail det;
            det.ttl = pkt[8];
            det.ref_ttl = fl->rev_profiled ? fl->rev_ttl : 0;
            det.tos = pkt[1];
            det.ipid = rd16(pkt + 4);
            det.server_hello = fl->rev_server_hello;
            det.planned = fl->plan_done ? D2K_PLANNED_YES : D2K_PLANNED_NO;
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_RST_AFTER_APP, &det);
        } else if (rst && !fwd && !fl->saw_hello && fl->raw_seen && fl->rev_data_pkts == 0) {
            /* СБРОС ПОТОКА БЕЗ РАСПОЗНАННОГО ПРОТОКОЛА (этап 32): сервер (или
               кто-то на пути) сбросил соединение, не ответив данными на первый
               сегмент клиента. Прежде ветки выше требовали приветствия, и такой
               сброс не оставлял следа. Это ДИАГНОСТИЧЕСКИЙ факт, а не вывод о
               коробке: закрытый порт сбрасывает точно так же. Контроллеру —
               TTL сброса и TTL ответа сервера (SYN-ACK), если тот был виден
               ДО сброса; сам сброс ориентиром не служит. Зонд контроллера и
               повторное подозрение отсекает suspect(). */
            d2k_jrn_detail det;
            memset(&det, 0, sizeof det);
            det.ttl = ip.hop_limit;
            det.ref_ttl = fl->rev_profiled && fl->rev_pkts_conn > 1 ? fl->rev_ttl : 0;
            det.tos = pkt[1];
            det.ipid = ip.ip_id;
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_RST, &det);
        }
        d2k_capture_forget(&s->capture, &key);
        d2k_track_remove(s->flows, &key);
        out->skipped = rst ? "соединение сброшено" : "соединение закрывается";
        return 0;
    }

    size_t payload_off = ihl + doff;
    size_t payload_len = total - payload_off;
    if (payload_len == 0) {
        out->skipped = "нет полезной нагрузки";
        return 0;
    }
    uint32_t in_seq = rd32(t + 4);

    /* --- узнавание протокола -------------------------------------------
     * Стоит ДО всего, что связано с планом, и это не перестановка ради
     * красоты. Наблюдение обязано работать в режиме, где плана нет вовсе:
     * этап C документа — «видны реальные транзитные соединения», а не
     * «видны, если есть чем воздействовать». В первой версии проверка
     * «плана нет» стояла раньше разбора, и первый же полевой прогон дал
     * 145 пакетов с единственной причиной «плана нет» — о протоколе не
     * узналось ничего.
     *
     * Разбор ограничен началом соединения: дальше он всё равно ничего не
     * найдёт, а платить за него на каждом пакете загрузки незачем. Предел
     * здесь свой, а не унаследованный от правила firewall: датапат не
     * вправе считать, что снаружи стоит connbytes. */
    d2k_tls_info tls;
    memset(&tls, 0, sizeof tls);
    /* Повтор приветствия: тот же номер последовательности с той же стороны.
       Клиент повторяет, когда ответа нет, — самая дешёвая улика из доступных,
       и видна она в направлении, которое и так наблюдается. */
    if (fwd && fl->saw_hello && in_seq == fl->hello_seq &&
        !fl->rev_tls_reply) {
        fl->hello_repeats++;
        if (fl->hello_repeats >= 2) {
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_REPEAT, NULL);
        }
    }

    /* Почему разбор не состоялся — считается ОТДЕЛЬНО по каждой причине.
     *
     * Раньше все эти случаи сваливались в «плана для этой цели нет», и по
     * сводке нельзя было отличить ответный пакет от прямого, не оказавшегося
     * приветствием. Ровно на этом застряла диагностика 2026-09-05: ноль
     * узнанных приветствий при 59 пакетах с нагрузкой, и ни одной подсказки,
     * куда смотреть. Прибор, который не различает причины, не прибор. */
    if (!fwd) {
        s->pay_reverse++;
    } else if (fl->saw_hello) {
        s->pay_after_hello++;
    } else if (fl->fwd_pkts > D2K_HELLO_WINDOW) {
        s->pay_late++;
    }

    /* ЗАПРОС HTTP — ВХОД ПЛАНА ОБХОДА HTTP (задача 51, шаг 4). Первый —
       первая нагрузка клиента ровно с начала потока (SYN видели), один раз
       на поток. TLS-признаков (saw_hello) не взводит: подозрения, обмены и
       приветствия TLS к такому потоку отношения не имеют.

       СЛЕДУЮЩИЕ ЗАПРОСЫ СОЕДИНЕНИЯ (keep-alive, поле 04.10.2026: GET / под
       планом получил 200, GET /False/ на том же соединении — вставку 302).
       Граница — из потока клиента: конец заголовка + Content-Length
       предыдущего запроса. Запрос, начинающийся ровно на ней, с начала
       сегмента, — вход плана своего имени, как первый. Всё прочее —
       конвейер внутри сегмента, сегмент через границу, пропущенная граница
       не запрос на границе — идёт как есть, считается, и граница дальше
       не ищется. Конец заголовков может прийти последующими сегментами:
       их framing ведёт тот же parser, что и наблюдатель HTTP-ответа. */
    int http_hello = 0;
    const char *http_skip = NULL;
    size_t http_off = 0, http_len = 0;
    /* Порт 80 (ревью M-1): Host без порта означает 80, и запрос на другой
       порт — не наш вход. */
    if (!fl->saw_hello && fwd && t[2] == 0 && t[3] == 80) {
        d2k_http_req hr;
        int later = 0, http_tried = 0;
        if (!fl->http_checked && fl->saw_syn && in_seq == fl->syn_seq + 1u) {
            fl->http_checked = 1;
            http_tried = 1;
            http_hello = d2k_http_request(pkt + payload_off, payload_len, &hr);
            fl->http_flow = (uint8_t)http_hello;
        } else if (fl->http_headers) {
            d2k_http_request_stream_feed(&fl->http_request,in_seq,pkt+payload_off,payload_len);
            if(fl->http_request.invalid || fl->http_request.past_end) {
                fl->http_headers=0;s->http_unaligned++;
            } else if(fl->http_request.header_done) {
                fl->http_headers=0;fl->http_conn=1;fl->http_next=fl->http_request.end;
            }
        } else if (fl->http_conn) {
            const int32_t d = (int32_t)(in_seq - fl->http_next);
            if (d == 0) {
                http_tried = 1;
                http_hello = d2k_http_request(pkt + payload_off, payload_len, &hr);
                later = http_hello;
                if (!http_hello) {
                    fl->http_conn = 0;              /* на границе не запрос */
                    s->http_unaligned++;
                }
            } else if (d > 0 ||
                       (int32_t)(in_seq + (uint32_t)payload_len - fl->http_next) > 0) {
                /* Граница пропущена или лежит внутри сегмента. Сегмент
                   целиком до границы — тело или повтор: не наше. */
                fl->http_conn = 0;
                s->http_unaligned++;
            }
        }
        /* A failed request/stream parse is not a missing installed plan.
         * This changes only the diagnostic, never eligibility or ownership. */
        if (!http_hello) {
            const uint8_t *pay = pkt + payload_off;
            size_t method = 0;
            while (method < payload_len && method < 20 &&
                   pay[method] >= 'A' && pay[method] <= 'Z') method++;
            if (method && method + 1 < payload_len &&
                pay[method] == ' ' && pay[method + 1] == '/') {
                if (!fl->saw_syn)
                    http_skip = "HTTP: начало TCP не наблюдалось — граница запроса не доказана";
                else if (http_tried)
                    http_skip = "HTTP: Host или запрос не разобран в этом сегменте";
                else
                    http_skip = "HTTP: граница запроса не доказана или уже пройдена";
            }
        }
        if (http_hello) {
            http_off = hr.host_off;
            http_len = hr.host_len;
            if (later) { s->http_later++; }
            fl->http_conn = 0;
            d2k_http_request_stream_init(&fl->http_request,in_seq);
            d2k_http_request_stream_feed(&fl->http_request,in_seq,pkt+payload_off,payload_len);
            fl->http_headers=!fl->http_request.invalid && !fl->http_request.header_done;
            if (!hr.end_known) {
                s->http_open_end++;
            } else if (hr.end < payload_len) {
                /* Следующий запрос внутри этого же сегмента (конвейер):
                   разрезать его нечем, граница дальше неизвестна. */
                s->http_unaligned++;
            } else {
                fl->http_conn = 1;
                fl->http_next = in_seq + (uint32_t)hr.end;
            }
        }
    }

    int tls_retry = 0;
    /* Повтор первого сегмента потока без распознанного протокола (этап 12):
       вход опыта на продолжении клиента, см. выбор плана ниже. Определяется
       ДО учёта этого пакета в raw-признаках (raw_seen уже стоит с первого). */
    int raw_retry = 0, raw_first = 0, raw_measured_new = 0;
    uint8_t raw_measured_trial[D2K_TRIAL_ID_LEN] = {0};
    uint8_t retry_packet[D2K_CAPTURE_BYTES + D2K_HOLD_PACKET];
    if (!observe_only && fwd && !http_hello && tcp_retry_ready(s, fl)) {
        uint32_t offset = in_seq - fl->hello_seq;
        const uint8_t *saved = s->retries[fl->retry_slot].bytes;
        if (offset < fl->retry_tls_len && payload_len <= fl->retry_tls_len - offset &&
            payload_off <= sizeof retry_packet - fl->retry_tls_len &&
            memcmp(pkt + payload_off, saved + offset, payload_len) == 0) {
            /* A retransmitted tail need not wait for a new head: replay the
               known complete flight using the current TCP options/ACK. The
               original NFQUEUE packet is still the only original we own. */
            memcpy(retry_packet, pkt, payload_off);
            memcpy(retry_packet + payload_off, saved, fl->retry_tls_len);
            pkt = retry_packet;
            t = pkt + ihl;
            in_seq = fl->hello_seq;
            payload_len = fl->retry_tls_len;
            d2k_tls_parse(pkt + payload_off, payload_len, &tls);
            tls_retry = tls.is_client_hello && tls.have_record_end;
        }
    }
    if (!fl->saw_hello && fwd && fl->fwd_pkts <= D2K_HELLO_WINDOW && !http_hello) {
        d2k_tls_parse(pkt + payload_off, payload_len, &tls);
        if (!tls.is_client_hello) {
            s->pay_not_hello++;
            /* Первый байт нагрузки — самая дешёвая улика о том, ЧТО это
               было: 0x16 значит рукопожатие и разбор споткнулся внутри,
               0x47 — обычный HTTP, прочее — не TLS вовсе. */
            s->last_nonhello_first = pkt[payload_off];
            /* Поток без распознанного протокола (этап 12): запоминаем первый
               сегмент клиента и считаем его повторы — это и есть «клиент
               ждёт». Форма наблюдения RAW едет контроллеру в подозрении. */
            if (payload_len > 0 && !fl->controller_probe && !http_skip && !fl->http_conn) {
                /* Распознанный HTTP (пусть и без доказанной границы) — не
                   «нагрузка без протокола»: у него свои причины и свой путь. */
                if (!fl->raw_seen) {
                    fl->raw_seen = 1;
                    fl->raw_seq = in_seq;
                    fl->raw_ns = now_ns;
                    if (!fl->client_shape) { fl->client_shape = D2K_PLAN_SHAPE_RAW; }
                    flow_fact(s, fl, &key, now_ns);
                } else if (in_seq == fl->raw_seq) {
                    fl->raw_repeats++;
                }
            }
        }
        if (tls.is_client_hello) {
            fl->hello_ns = now_ns;
            fl->saw_hello = 1;
            fl->had_sni = tls.have_sni ? 1 : 0;
            if (!tls.have_sni && !tls.have_record_end) {
                /* В первом сегменте имени ещё нет. Сборщик ниже может
                   дополнить наблюдение; это не диагноз «без домена». */
                s->sni_in_next_seg++;
            }
            fl->hello_seq = in_seq;
            s->hellos++;
            note_tcp_hello(s, fl, ack, t);
            d2k_jrn_detail hello_detail={0};
            hello_detail.client_side=fl->dir_known?(fl->init_low?D2K_CLIENT_SIDE_LOW:D2K_CLIENT_SIDE_HIGH):0;
            if (tls.have_sni && !fl->controller_probe) {
                s->with_sni++;
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_SNI, 0, 0,
                                &hello_detail, pkt + payload_off + tls.sni_off,
                                tls.sni_len, NULL);
            } else if (tls.have_record_end && !fl->controller_probe) {
                /* Имени нет — и это нормальное состояние модели (§5.3), а не
                   ошибка разбора. */
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_NONAME, 0, 0,
                                &hello_detail, NULL, 0, NULL);
            }
        }
    }

    /* Сегмент потока без распознанного протокола (этап 12): первый — вход
       для ПОСТОЯННОГО адресного плана формы RAW (подтверждённое решение
       этого адреса), повтор — вход опыта по точной пробной записи порта
       клиента. Считается после учёта этого пакета в raw-признаках. */
    if (fwd && !observe_only && !fl->controller_probe && !fl->saw_hello && fl->raw_seen &&
        payload_len > 0 && in_seq == fl->raw_seq && !tls.is_client_hello && !http_hello && !http_skip) {
        if (fl->raw_repeats == 0) { raw_first = 1; } else { raw_retry = 1; }
        /* Поздняя доставка (этап 17): повтор клиента ЗА окном поиска дошёл до
           очереди (правило метки записи) — считаем как свидетельство пути. */
    }
    /* Снимок — только целый ClientHello. Это наблюдение, НЕ замена payload
       текущего пакета: tls ниже по-прежнему описывает именно этот пакет.
       Исполнение на составном входе требует отдельного удержания/выпуска. */
    if (fwd && !fl->hello_capture_done && fl->fwd_pkts <= D2K_CAPTURE_WINDOW &&
        (ip.fragment & 0x3fff) == 0) {
        const uint8_t *hello;
        size_t hello_len;
        uint32_t hello_seq;
        /* Снимок приветствия собирается от НАЧАЛА ПОТОКА, когда оно известно:
           куски приходят в любом порядке, и угадывать начало по первому байту
           нельзя (см. d2k_capture_feed). SYN не наблюдался — работаем
           по-прежнему, от куска, начинающего запись. */
        int captured = d2k_capture_feed(&s->capture, &key, fl->first_ns, now_ns,
                                        in_seq, fl->syn_seq + 1, fl->saw_syn,
                                        pkt + payload_off, payload_len,
                                        &hello, &hello_len, &hello_seq);
        if (captured == 1) {
            d2k_tls_info complete;
            d2k_tls_parse(hello, hello_len, &complete);
            if (complete.is_client_hello && complete.have_record_end &&
                complete.have_hello_middle && !complete.exts_truncated) {
                size_t k = shape_slot(6, key.family);
                s->captured_hellos++;
                /* Форма головы при оборванном блоке расширений — догадка
                   быстрого пути (MODERN). Целое приветствие с ECH — факт:
                   Chrome переставляет расширения, и ECH уезжает во второй
                   сегмент (поле 17.10.2026). Подозрение несёт форму потока. */
                if (fl->client_shape == D2K_PLAN_SHAPE_ANY)
                    fl->client_shape = complete.is_tls13 ?
                        (complete.ech_offer ? D2K_PLAN_SHAPE_ECH_TCP : D2K_PLAN_SHAPE_MODERN) :
                        D2K_PLAN_SHAPE_LEGACY;
                else if (complete.ech_offer && fl->client_shape == D2K_PLAN_SHAPE_MODERN)
                    fl->client_shape = D2K_PLAN_SHAPE_ECH_TCP;
                if (!fl->controller_probe) {
                    memcpy(s->last_hello[k], hello, hello_len);
                    s->last_hello_len[k] = hello_len;
                    /* Опции — с ЭТОГО пакета: они у потока одни на все сегменты. */
                    s->last_opts_len[k] = (uint8_t)(doff - 20);
                    memcpy(s->last_opts[k], t + 20, doff - 20);
                    s->last_name_len[k] = 0;
                    if (complete.have_sni && complete.sni_len <= sizeof s->last_name[k]) {
                        memcpy(s->last_name[k], hello + complete.sni_off, complete.sni_len);
                        s->last_name_len[k] = complete.sni_len;
                    }
                }
                if (!fl->saw_hello) {
                    fl->saw_hello = 1;
                    fl->hello_ns = now_ns;
                    fl->hello_seq = hello_seq;
                    s->hellos++;
                    note_tcp_hello(s, fl, ack, t);
                }
                d2k_jrn_detail hello_detail={0};
                hello_detail.client_side=fl->dir_known?(fl->init_low?D2K_CLIENT_SIDE_LOW:D2K_CLIENT_SIDE_HIGH):0;
                if (!fl->controller_probe && !fl->had_sni && complete.have_sni) {
                    fl->had_sni = 1;
                    s->with_sni++;
                    d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_SNI,
                                    0, 0, &hello_detail, hello + complete.sni_off,
                                    complete.sni_len, NULL);
                } else if (!fl->controller_probe && !complete.have_sni &&
                           !(tls.is_client_hello && tls.have_record_end)) {
                    d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_NONAME,
                                    0, 0, &hello_detail, NULL, 0, NULL);
                }
                int requested_shape = s->shape_armed[k] &&
                    (s->shape_name_len[k] == 0 ||
                     name_same(s->last_name[k], s->last_name_len[k],
                               s->shape_name[k], s->shape_name_len[k]));
                /* Every client form is input to DIRECT/OWN. Synthesis-only
                 * does not arm the legacy search's per-name snapshot trap. */
                if (!fl->controller_probe) {
                    memcpy(s->shape[k], hello, hello_len);
                    s->shape_len[k] = hello_len;
                    s->shape_key[k]=key;s->shape_at[k]=now_ns;
                    s->shape_opts_len[k] = (uint8_t)(doff - 20);
                    memcpy(s->shape_opts[k], t + 20, doff - 20);
                    if (requested_shape) s->shape_armed[k] = 0;
                    d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_SHAPE, 0,
                                    (uint32_t)hello_len, NULL, NULL, 0, NULL);
                }
            } else {
                s->capture.rejected++;
            }
        }
        if (captured == 1 || captured == -1) {
            fl->hello_capture_done = 1;
            d2k_capture_forget(&s->capture, &key);
        }
    }

    if (observe_only) {
        out->skipped = "оригинал отпущен без воздействия";
        return 0;
    }

    /* ПОВРЕЖДЁННЫЙ ПОТОК — РАНЬШЕ ВЫБОРА ПЛАНА И БЕЗ ОГЛЯДКИ НА ПРИВЕТСТВИЕ.
       Два условия, и оба выяснены дорогой ценой.

       Раньше проверка стояла после «плана нет» и «уже применён» и была
       недостижима: те возвращаются выше. Флаг повреждения оставался
       write-only, а контроллер о повреждении не узнавал вовсе.

       Привязывать проверку к разобранному приветствию тоже нельзя: разбор
       делается ТОЛЬКО для первого приветствия потока (`!fl->saw_hello`
       выше), а поток портится уже ПОСЛЕ него. То есть на всех последующих
       пакетах tls пуст по построению, и условие «это приветствие» не
       выполнилось бы никогда.

       Сообщаем ОДИН раз на поток: испорченный поток продолжает слать пакеты,
       и событие на каждом из них забило бы единственное управляющее
       соединение (события лосси, d2k_ctl.h). */
    if (fl->damaged) {
        /* Факт повреждения уже уехал контроллеру В МОМЕНТ установления
           (d2k_session_exec_failed): замолчавший поток второго пакета мог бы
           и не прислать. Здесь только отказываемся применять что-либо ещё —
           повторное событие на каждом пакете забило бы единственное
           управляющее соединение. */
        out->skipped = "поток испорчен предыдущей отменой";
        return 0;
    }

    /* Выбор плана по цели. Имя из приветствия точнее адреса и потому идёт
       первым; адрес — запасной ключ, за которым у CDN стоят сотни имён. */
    const d2k_plan *use = NULL;
    int scoped_packet=0,composed_retry=0;
    if (fwd && controller_probe && !observe_only) {
        int reserved;
        int first=!fl->plan_done && fl->saw_syn && !fl->adopted && in_seq==fl->syn_seq+1u;
        use=owned_dns_probe(s,&ip,t,controller_probe,first ? pkt+payload_off : NULL,
            payload_len,now_ns,raw_measured_trial,&reserved);
        if (reserved && !use)return 0;
        if (!reserved && first && (s->hook==D2K_HOOK_OUTPUT || s->hook==D2K_HOOK_POSTROUTING)) {
            uint16_t port;
            memcpy(&port,t+2,2);
            use=d2k_plantab_find_dns_endpoint(s->plans,ip.dst.bytes,ip.family,port,6,
                pkt+payload_off,payload_len,now_ns);
        }
        if (use)fl->client_shape=reserved ? D2K_PLAN_SHAPE_RAW : D2K_PLAN_SHAPE_DNS;
    }
    if (use) {
        raw_first=1;
    } else if (fwd && fl->stream_plan_pending) {
        use=d2k_plantab_find_by_binding(s->plans,&fl->stream_plan_binding,now_ns);
        if(!use) {
            if(fl->stream_plan_stage) {
                d2k_session_unsent(s,now_ns,&key,fl->execution_plan_id,
                    D2K_REFUSE_NOT_APPLIED,fl->execution_id);
            }
            fl->stream_plan_pending=0;
            fl->stream_plan_stage=0;
            out->skipped="late TCP plan binding expired or replaced";
            refuse(s,now_ns,&key,out->skipped);
            return 0;
        }
    } else if (tls.is_client_hello) {
        /* ФОРМА НАБЛЮДАЕМОГО ПРИВЕТСТВИЯ. План, подтверждённый на приветствии
           одной формы, не применяется к приветствию другой: успех
           собственного зонда на TLS 1.3 ничего не говорит про браузер с
           TLS 1.2 (0009, U5).

           ОБОРВАННЫЙ БЛОК РАСШИРЕНИЙ ФОРМЫ НЕ ДАЁТ. Первая редакция писала
           здесь LEGACY по отсутствию признака — то есть выдумывала замер:
           у браузера supported_versions приезжает вторым сегментом вслед за
           server_name из первого, пересборки у нас нет, и такое приветствие
           получало уверенную и неверную форму. Не разобрали — ANY. */
        uint8_t seen_shape = D2K_PLAN_SHAPE_ANY;
        /* Форма — свойство приветствия, не имени: приветствие БЕЗ server_name
           (адресная цель, этап 11) получает ту же форму по supported_versions.
           Прежде такой поток оставался ANY и ни одна адресная/пробная запись
           формы к нему не подходила — адресный план не применялся никогда. */
        if (tls.is_client_hello) {
            if (tls.is_tls13) {
                /* Признак найден — достоверен независимо от обрыва:
                   расширение прочитано целиком. */
                seen_shape = tls.ech_offer ? D2K_PLAN_SHAPE_ECH_TCP : D2K_PLAN_SHAPE_MODERN;
                /* ECH absence is unknown until the whole extension block
                 * arrives. Bound non-ECH proof also needs that distinction;
                 * legacy unbound fast paths and exact port probes retain
                 * their previous selection behavior. */
                uint16_t probe_port = 0;
                if (controller_probe) memcpy(&probe_port, t, 2);
                if (!tls.ech_offer && tls.exts_truncated &&
                    (d2k_plantab_has_ech_target(s->plans,
                        pkt + payload_off + tls.sni_off, tls.sni_len,
                        ip.dst.bytes, ip.family, probe_port) ||
                     d2k_plantab_needs_complete_tls_shape(s->plans,
                        pkt + payload_off + tls.sni_off,tls.sni_len,ip.family)))
                    seen_shape = D2K_PLAN_SHAPE_ANY;
            } else if (!tls.exts_truncated) {
                /* Признака нет, и блок расширений пришёл ВЕСЬ — значит его
                   действительно нет. */
                seen_shape = D2K_PLAN_SHAPE_LEGACY;
            }
            /* Признака нет, блок оборван — «ещё не всё пришло». Формы не
               объявляем: LEGACY здесь был бы выдуманным замером. */
        }
        fl->client_shape = seen_shape;
        /* Местный порт — см. ту же оговорку в ветке UDP выше. */
        uint16_t sport_be, dport_be;
        memcpy(&sport_be, t + 0, 2);
        size_t tcp_misses_before = d2k_plantab_shape_misses(s->plans);
        memcpy(&dport_be, t + 2, 2);
        if(!controller_probe && tls.have_sni && tls.sni_len<256 && seen_shape!=D2K_PLAN_SHAPE_ANY) {
            d2k_pf_scope scope={.family=ip.family,.shape=seen_shape,.server_port=dport_be,
                .path=s->packet_path};
            memcpy(scope.client,ip.src.bytes,ip.family==6?16:4);
            memcpy(scope.server,ip.dst.bytes,ip.family==6?16:4);
            memcpy(scope.name,pkt+payload_off+tls.sni_off,tls.sni_len);
            const d2k_plan *candidate=d2k_pf_lease_find(&s->preflight_leases,&scope,now_ns);
            if(preflight_outgoing_admitted(s,&key,fl,candidate))use=candidate;
        }
        if(!use)use = d2k_plantab_find_target_endpoint(s->plans,
                                     tls.have_sni ? pkt + payload_off + tls.sni_off : NULL,
                                     tls.have_sni ? tls.sni_len : 0,
                                     ip.dst.bytes, ip.family, now_ns, seen_shape,
                                     controller_probe ? sport_be : 0, dport_be);
        /* Имя и отказ по форме — в результат, для журнала решений (24.10.2026).
           Та же пара, что на UDP выше: по ней видно, видел ли датапат этот
           поток и почему не применил план. */
        if (tls.have_sni && tls.sni_len && tls.sni_len < sizeof out->flow_name) {
            snprintf(out->flow_name, sizeof out->flow_name, "%.*s",
                     (int)tls.sni_len, (const char *)pkt + payload_off + tls.sni_off);
            out->shape_miss = d2k_plantab_shape_misses(s->plans) != tcp_misses_before;
        }
        if (!use) {
            use = s->plan;
        }
    } else if (http_hello) {
        /* Только запись имени формы HTTP (пробная — своего порта). Ни
           дедушкина запись, ни адрес, ни общий план сюда не доходят. */
        uint16_t sport_be;
        memcpy(&sport_be, t + 0, 2);
        use = d2k_plantab_find_http(s->plans, pkt + payload_off + http_off, http_len,
                                    ip.family, controller_probe ? sport_be : 0, now_ns);
    } else if (raw_retry || raw_first ||
               (fwd && !observe_only && !fl->controller_probe && !fl->saw_hello &&
                fl->raw_seen && !fl->http_conn && !http_skip && payload_len)) {
        /* A measured late segment need not have the first segment's sequence.
           Only the exact measured guard admits it; permanent plans keep their
           first-segment scope. */
        /* Temporary RAW trials require the measured tuple, daemon epoch,
           incarnation, sequence and payload digest. A client port alone does
           not identify a LAN client. Permanent plans retain service scope. */
        uint16_t dport_be;
        memcpy(&dport_be,t+2,2);
        use=measured_probe(s,fl,&ip,t,in_seq,pkt+payload_off,payload_len,now_ns,raw_measured_trial);
        if(use) {
            raw_retry=1;
            raw_measured_new=!fl->sends_left && !fl->sends_failed &&
                memcmp(raw_measured_trial,fl->execution_trial_id,D2K_TRIAL_ID_LEN)!=0;
        }
        if(!use && (raw_retry || raw_first))use=d2k_plantab_find_target_endpoint_tr(s->plans,NULL,0,ip.dst.bytes,ip.family,
                                                      now_ns,D2K_PLAN_SHAPE_RAW,0,dport_be,6);
        if (!use) {
            out->skipped = http_skip ? http_skip :
                           raw_retry ? "опыта для этого потока без протокола нет"
                                     : "плана для адреса без протокола нет";
            return 0;
        }
    }

    if (use && use->preflight) {
        if(!preflight_outgoing_admitted(s,&key,fl,use)) {
            out->skipped = "preflight outgoing program requires its owned handover";
            return 0;
        }
    }
    if (!plan_fits_transport(use, 6)) {
        out->skipped = "план объявлен для другого транспорта";
        if (tls.is_client_hello) { refuse(s, now_ns, &key, out->skipped); }
        return 0;
    }
    if (!use) {
        out->skipped = http_skip ? http_skip : "плана для этой цели нет";
        /* refuse() — ТОЛЬКО когда это действительно приветствие, которому не
           нашлось плана (ревью, пункт 3), а не на каждом пакете, что сюда
           заходит. use остаётся NULL по ДВУМ разным причинам: либо это
           приветствие и d2k_plantab_find/s->plan оба ничего не дали (вот
           это и есть «плана для этой цели нет» по смыслу), либо пакет —
           вообще не приветствие (ACK, данные после рукопожатия, обратная
           сторона: tls.is_client_hello тогда ложно по построению, потому что
           d2k_plantab_find выше зовётся ТОЛЬКО внутри "if
           (tls.is_client_hello)") — и это НЕ то же самое наблюдение, хотя
           обе ветки доходят досюда с одинаковым use == NULL. Вторая причина
           встречается на КАЖДОМ пакете каждого потока, у которого план ещё
           не встал или не нужен вовсе — это подавляющее большинство трафика
           через этот датапат, а не 204 промаха в минуту (см. ревью пункта 1
           про эту частоту): звать refuse() без разбора причины значило бы
           затопить управляющий сокет на несколько порядков плотнее
           заявленной ловушки. Различие ниже и есть тот самый разбор.
           Ограничение "не чаще раза на поток" получается АВТОМАТИЧЕСКИ, не
           отдельным флагом: tls.is_client_hello истинно не более одного раза
           за жизнь потока (fl->saw_hello взводится в тот же момент, что и
           tls.is_client_hello, и дальше блокирует повторный разбор — см. по
           тексту выше), значит и это refuse() — тоже не больше одного раза. */
        if (tls.is_client_hello) {
            refuse(s, now_ns, &key, out->skipped);
        }
        return 0;
    }
    uint32_t stream_offset=0,scope=0;
    int have_stream_offset=fwd && fl->dir_known && fl->saw_syn && !fl->adopted;
    if(have_stream_offset) {
        stream_offset=in_seq-(fl->syn_seq+1u);
        have_stream_offset=stream_offset<UINT32_C(0x80000000);
    }
    uint32_t after_length=0;
    int composed=d2k_plan_after_split(use,&scope,&after_length,NULL);
    if(composed) {
        if(!have_stream_offset || !fwd) {
            if(fl->stream_plan_stage)d2k_session_unsent(s,now_ns,&key,fl->execution_plan_id,
                D2K_REFUSE_NOT_APPLIED,fl->execution_id);
            fl->stream_plan_pending=0;fl->stream_plan_stage=0;
            out->skipped="composed TCP plan requires observed stream origin";
            refuse_coded(s,now_ns,&key,out->skipped,D2K_REFUSE_NOT_APPLIED,use);return 0;
        }
        if(stream_offset==0) {
            if(fl->sends_left || fl->sends_failed || fl->stream_plan_stage>=3 ||
               !d2k_plantab_binding(s->plans,use,&fl->stream_plan_binding)) {
                out->skipped="composed first input cannot replace an active execution";
                refuse_coded(s,now_ns,&key,out->skipped,D2K_REFUSE_NOT_APPLIED,use);return 0;
            }
        } else if(fl->stream_plan_stage==4 && stream_offset>=scope+after_length) {
            fl->stream_plan_pending=0;
            out->skipped="past completed composed TCP input";return 0;
        } else if(fl->stream_plan_stage==4 && stream_offset>=scope &&
                  stream_offset-scope<after_length && payload_len<=after_length-(stream_offset-scope) &&
                  !fl->sends_left && !fl->sends_failed) {
            scoped_packet=1;composed_retry=1;
        } else if(stream_offset<scope && payload_len<=scope-stream_offset) {
            out->skipped="between composed TCP inputs";return 0;
        } else if(stream_offset==scope && payload_len==after_length &&
                  fl->stream_plan_stage==2 && !fl->sends_left && !fl->sends_failed) {
            scoped_packet=1;
        } else {
            if(fl->stream_plan_stage)d2k_session_unsent(s,now_ns,&key,fl->execution_plan_id,
                D2K_REFUSE_NOT_APPLIED,fl->execution_id);
            fl->stream_plan_pending=0;fl->stream_plan_stage=0;
            out->skipped="composed TCP request boundary differs or first input is not sent";
            refuse_coded(s,now_ns,&key,out->skipped,D2K_REFUSE_NOT_APPLIED,use);return 0;
        }
    } else if(d2k_plan_stream_offset(use,&scope)) {
        if(!have_stream_offset) {
            fl->stream_plan_pending=0;
            out->skipped="late TCP plan requires observed stream origin";
            refuse_coded(s,now_ns,&key,out->skipped,D2K_REFUSE_NOT_APPLIED,use);
            return 0;
        }
        if(stream_offset<scope && payload_len<=scope-stream_offset) {
            if(!fl->stream_plan_pending &&
               !d2k_plantab_binding(s->plans,use,&fl->stream_plan_binding)) {
                out->skipped="late TCP plan requires a live target binding";
                refuse_coded(s,now_ns,&key,out->skipped,D2K_REFUSE_NOT_APPLIED,use);
                return 0;
            }
            fl->stream_plan_pending=1;
            out->skipped="before measured TCP stream offset";
            return 0;
        }
        fl->stream_plan_pending=0;
        if(stream_offset!=scope) {
            out->skipped="measured TCP stream boundary crossed or missed";
            refuse_coded(s,now_ns,&key,out->skipped,D2K_REFUSE_NOT_APPLIED,use);
            return 0;
        }
        scoped_packet=1;
    }
    if (!tls.is_client_hello && !http_hello && !raw_retry && !raw_first && !scoped_packet) {
        /* Не приветствие — не наш случай. План первой версии описывает именно
           начало TLS-соединения. */
        out->skipped = "не ClientHello";
        return 0;
    }
    if (tls_retry && (!tcp_retry_ready(s, fl) ||
        memcmp(d2k_plan_id(use), fl->execution_plan_id, D2K_PLAN_ID_LEN) != 0)) {
        out->skipped = "TLS retry plan changed";
        return 0;
    }
    if (fl->plan_done && !http_hello && !tls_retry && !raw_measured_new && !(composed && scoped_packet)) {
        /* План описывает обработку начала соединения. Применить его дважды
           значит послать фальшивку в середину потока, где она уже ничего не
           значит, а вреда наделает. Исключение — следующий запрос HTTP на
           своей границе: у него своё «начало» (номер, Host), и коробка
           смотрит его так же, как первый (keep-alive, поле 04.10.2026). */
        out->skipped = "план уже применён к этому потоку";
        return 0;
    }
    if (http_hello && fl->sends_left) {
        /* Посылки прошлого запроса ещё не все отчитались (отложенные куски,
           разнос): новое исполнение затёрло бы учёт прежнего. Как есть. */
        out->skipped = "прошлое исполнение плана на потоке ещё не завершено";
        return 0;
    }

    /* ТРЕБОВАНИЯ ПЛАНА К ПОТОКУ — ДО СБОРКИ (замысел 2026-10-23, п. 5.3).
       Профиль tcp-template-v1 со сдвигом метки времени исполним только на
       потоке, который метку предлагает. Прежде это узнавал сборщик: нуль
       d2k_wire_build, тот же, что «не поместилось», с текстом «буфер отправки
       кончился» и без кода — и контроллер читал «план подтверждён, датапат его
       не применял» (поле issue #7, 22.10.2026: ПК без метки — 13 из 13).
       Свой код: для контроллера это «перемерить цель для этого клиента». */
    if (!http_hello && !(composed && scoped_packet) &&
        (d2k_plan_flow_needs(use) & D2K_FLOW_NEED_TCPTS) &&
        !tcp_options_have_timestamp(t + 20, doff - 20)) {
        out->skipped = "план требует метку времени TCP, а поток клиента её не предлагает";
        refuse_coded(s, now_ns, &key, out->skipped, D2K_REFUSE_FLOW_UNFIT, use);
        return 0;
    }

    d2k_pkt in;
    memset(&in, 0, sizeof in);
    in.payload = pkt + payload_off;
    in.payload_len = payload_len;
    in.seq = in_seq;
    in.have_stream_offset=have_stream_offset;
    in.stream_offset=stream_offset;
    in.after_split_retry=composed_retry;
    in.have_sni = tls.have_sni;
    in.is_tls13 = tls.is_tls13;
    in.sni_off = tls.sni_off;
    in.sni_len = tls.sni_len;
    in.segment_cap = tcp_segment_cap;
    if (http_hello) {
        in.is_http = 1;
        in.have_sni = 1;
        in.is_tls13 = 0;
        in.sni_off = http_off;
        in.sni_len = http_len;
    }

    d2k_actions acts;
    memset(&acts, 0, sizeof acts);
    if (d2k_plan_apply(use, fl, &in, &acts) != 0) {
        /* Неприменим — пропускаем как есть. Отказ исполнителя это результат, а
           не сбой: якорь может быть невычислим для конкретного пакета.
           ПРИЧИНА ИСПОЛНИТЕЛЯ — ДОСЛОВНО. Обобщённый текст уходил и в журнал,
           и контроллеру, и по нему нельзя было отличить «коробка срезала» от
           «мы сами не применили план» (поле 13.10.2026, forum.ru-board.com:
           10 таких отказов за 15 минут, зонд уходил голым, рабочий приём
           выброшен). Запасной текст остаётся на случай отказа без причины. */
        out->skipped = acts.refuse_why ? acts.refuse_why
                                       : "план неприменим к этому пакету";
        if (!http_hello) {
            refuse_coded(s, now_ns, &key, out->skipped,
                         D2K_REFUSE_NOT_APPLIED, use);
        }
        d2k_actions_free(&acts);
        return 0;
    }

    /* --- сборка на провод ----------------------------------------------- */
    d2k_conn c;
    memset(&c, 0, sizeof c);
    /* Из пакета, а не из ключа: ключ канонизирован, и «низкая» сторона может
       оказаться сервером. Собранный по нему пакет полетел бы задом наперёд. */
    c.family = ip.family;
    memcpy(ip.family == 6 ? c.src_ip6 : (uint8_t *)&c.src_ip,
           ip.src.bytes, ip.family == 6 ? 16 : 4);
    memcpy(ip.family == 6 ? c.dst_ip6 : (uint8_t *)&c.dst_ip,
           ip.dst.bytes, ip.family == 6 ? 16 : 4);
    c.traffic_class = ip.traffic_class; c.flow_label = ip.flow_label;
    memcpy(&c.src_port, t + 0, 2);
    memcpy(&c.dst_port, t + 2, 2);
    /* То же, что и на UDP-ветке: без записи conntrack наши посылки уйдут
       мимо NAT (см. flow_tracked). */
    if (flow_tracked(fl, &c, 6, 0) != 0) {
        out->skipped = "поток не ведётся conntrack — посылки уйдут мимо NAT";
        if (!http_hello) { refuse(s, now_ns, &key, out->skipped); }
        d2k_actions_free(&acts);
        return 0;
    }
    c.ack = rd32(t + 8);
    c.window = rd16(t + 14);
    c.ttl = ip.hop_limit;
    /* TTL ТОГО, ЧТО ОТВЕЧАЛО по этому соединению — вход эвристики autottl
       (d2k_wire.h). Ноль, пока ответа не было: сборщик тогда возьмёт заданный
       ttl, а без него TTL не тронет. */
    c.rev_ttl = fl->rev_ttl;
    c.ip_id = ip.ip_id;

    if (acts.n > sizeof out->out / sizeof out->out[0]) {
        /* Тот же класс отказа, что и made==0 чуть ниже (ревью задачи 4,
           круг 2): repeats фальшивки приходит из TLV байтом без потолка (до
           255), а out[] ограничен D2K_RESULT_MAX. Обрезать n молча значило бы
           "применить" план и отправить на провод меньше посылок, чем он
           описывает, — то есть план, который не исполнялся. Честный исход —
           отказ целиком. */
        out->skipped = "план описывает больше посылок, чем вмещает буфер результата";
        /* Отказ исполнителя по НАЙДЕННОМУ плану — с кодом и id плана, как у
           неприменимого плана выше. С кодом «плана нет» и без id опыт,
           поставивший такой план, квитанции не получал (поле 11.11). */
        if (!http_hello) {
            refuse_coded(s, now_ns, &key, out->skipped, D2K_REFUSE_NOT_APPLIED, use);
        }
        d2k_actions_free(&acts);
        return 0;
    }
    size_t used = 0;
    size_t n = acts.n;
    for (size_t i = 0; i < n; i++) {
        if (acts.v[i].wire_profile == D2K_WIRE_TCP_TEMPLATE) {
            size_t tcp_header = (size_t)(t[12] >> 4) * 4;
            c.tcp_options_len = (uint8_t)(tcp_header - 20);
            memcpy(c.tcp_options, t + 20, c.tcp_options_len);
            c.ip_id = (uint16_t)(ip.ip_id + i);
        } else if (acts.v[i].poison & D2K_POISON_MD5_TS) {
            /* Комбо MD5+метка на detect-tcp-v1 читает РЕАЛЬНУЮ метку клиента:
               копируем опции потока (их разберёт wire.c), не трогая IPID
               измеренного профиля и прочие профили. */
            size_t tcp_header = (size_t)(t[12] >> 4) * 4;
            c.tcp_options_len = (uint8_t)(tcp_header - 20);
            memcpy(c.tcp_options, t + 20, c.tcp_options_len);
        }
        size_t made = d2k_wire_build(&c, &acts.v[i], buf + used, bufcap - used);
        if (made == 0) {
            /* Не поместилось. Отменяем то, что ещё не ушло, и спрашиваем
               исполнитель, что делать с оригиналом: половина выпущенного плана
               — это отмена, а у неё есть определённые правила.

               СОБРАНО — НЕ ОТПРАВЛЕНО. Мы на СБОРКЕ, до единой отправки:
               посылки уйдут позже, из out->out[]. Исполнителю сообщается ноль
               ушедших, а не i, — иначе он объявил бы поток испорченным и снял
               бы оригинал из-за байт, которых на проводе не было. Ничего не
               ушло, значит отказываемся целиком, не меняя воздействия, и
               отпускаем оригинал нетронутым (0009, U3). */
            d2k_cancel cancel;
            d2k_actions_cancel(&acts, 0, &cancel);
            out->n_out = 0;
            out->verdict = (cancel.fate == D2K_ORIG_DROP) ? D2K_VERDICT_DROP
                                                          : D2K_VERDICT_ACCEPT;
            if (cancel.stream_damaged) {
                fl->damaged = 1;
            }
            out->skipped = "буфер отправки кончился";
            if (!http_hello) { refuse(s, now_ns, &key, out->skipped); }
            d2k_actions_free(&acts);
            return 0;
        }
        if (acts.v[i].kind == D2K_EMIT_PAYLOAD && out->first_payload == 0xFF) {
            out->first_payload = (uint8_t)i;
        }
        out->out[i].delay_us = acts.v[i].delay_us;
        out->out[i].off = used;
        out->out[i].len = made;
        used += made;
    }
    if (acts.fate == D2K_ORIG_HOLD) {
        /* Удержание оригинала датапат не умеет: пакет в очереди нельзя держать
           без вердикта, а выпустить его позже самим — отдельная работа с
           отдельной проверкой. Исполнитель такой судьбы сейчас не порождает,
           и проверка стоит здесь именно поэтому: если он начнёт, отказ
           случится сразу, а не превратится тихо в «пропустить». §2.5. */
        out->n_out = 0;
        out->verdict = D2K_VERDICT_ACCEPT;
        out->skipped = "удержание оригинала не поддержано";
        if (!http_hello) { refuse(s, now_ns, &key, out->skipped); }
        d2k_actions_free(&acts);
        return 0;
    }
    out->n_out = n;
    out->verdict = (acts.fate == D2K_ORIG_DROP) ? D2K_VERDICT_DROP
                                                : D2K_VERDICT_ACCEPT;
    if (!tls_retry && !http_hello && d2k_plan_stream_input(use) &&
        tls.have_record_end && payload_len >= 5 && payload_len <= D2K_CAPTURE_BYTES &&
        5u + rd16(pkt + payload_off + 3) == payload_len) {
        size_t slot = s->retry_next++ % D2K_HOLD_SLOTS;
        if (++s->retry_token == 0) ++s->retry_token;
        s->retries[slot].token = s->retry_token;
        memcpy(s->retries[slot].bytes, pkt + payload_off, payload_len);
        fl->retry_slot = (uint8_t)slot;
        fl->retry_token = s->retry_token;
        fl->retry_tls_len = (uint32_t)payload_len;
        fl->retry_plan_revision = d2k_session_plan_revision(s);
    }
    fl->plan_done = 1;
    fl->guards = d2k_plan_guards(use);
    s->applied++;
    /* Ключ потока и идентификатор плана — ВЫЗЫВАЮЩЕМУ, до отправки. Без них
       отправляющий видит только байты, и отказ sendto оставался голым
       счётчиком (d2k_session.h, поля applied/key/plan_id). */
    plan_handed_off(s, out, fl, &key, use, NULL);
    if(composed) {
        fl->stream_plan_stage=composed_retry?5:scoped_packet?3:1;
        fl->stream_plan_pending=1;
        fl->stream_plan_offset=scope;fl->stream_plan_length=after_length;
    }
    if(!fl->saw_hello && fl->raw_seen && payload_len) {
        /* An echo of only the first emitted segment is not delivery of the
           measured request. Bind the complete TCP byte range to this exact
           execution, including a retransmission whose prefix was ACKed. */
        raw_proof_begin(fl, pkt + payload_off, payload_len, rd32(t + 4), rd32(t + 8));
    }
    if (tls_retry) out->replay_tls_bytes = (uint32_t)payload_len;
    /* Не просто «план применился», а КАКОЙ: без идентификатора контроллер не
       отличит применение своего кандидата от применения предыдущего, чьё
       событие пришло позже (d2k_ctl.h объявляет APPLIED «ключ + id плана»). */
    d2k_journal_add_applied(s->jrn, now_ns, &key, d2k_plan_id(use), NULL);

    d2k_actions_free(&acts);
    return 0;
}

int d2k_session_udp_continue(d2k_session *s, uint64_t now_ns, const d2k_key *key,
        const uint8_t plan_id[D2K_PLAN_ID_LEN], const uint8_t trial_id[D2K_TRIAL_ID_LEN],
        const d2k_binding_context *binding, const uint8_t epoch[16], uint64_t incarnation,
        const d2k_ct_info *mapping, const uint8_t *datagram, size_t len,
        uint8_t *buf, size_t bufcap, d2k_result *out) {
    if (!out) { return 0; }
    memset(out, 0, sizeof *out);
    out->first_payload = 0xFF;
    out->verdict = D2K_VERDICT_ACCEPT;
    if (!s || !key || !plan_id || !trial_id || !binding || !epoch || !mapping || !datagram) {
        out->skipped = "продолжение UDP: не хватает контекста"; return 0;
    }
    /* Оригинал ДО NAT разбираем тем же парсером, что и обычный путь. */
    d2k_packet_view ip;
    if (!d2k_packet_parse(datagram, len, &ip) || ip.protocol != 17 || ip.l4 < 20) {
        out->skipped = "продолжение UDP: не UDP или неполный пакет"; return 0;
    }
    size_t payload_off = ip.l4 + 8;
    if (len < payload_off) {
        out->skipped = "продолжение UDP: UDP-заголовок не помещается"; return 0;
    }
    /* Полная датаграмма и длины: IP total сходится с буфером, это НЕ фрагмент
       (владеем целым первым Initial), а поле длины UDP сходится с полезной
       нагрузкой. Иначе исполнять нечего — отказ. */
    if ((ip.fragment & 0x3fff) != 0 || ip.total != len) {
        out->skipped = "продолжение UDP: пакет фрагментирован или длина IP не та"; return 0;
    }
    const uint8_t *u = datagram + ip.l4;
    size_t payload_len = len - payload_off;
    uint16_t udp_len = (uint16_t)((u[4] << 8) | u[5]);
    if (udp_len != 8 + payload_len) {
        out->skipped = "продолжение UDP: длина UDP не сходится с нагрузкой"; return 0;
    }

    /* КАНОНИЧЕСКИЙ ключ самой датаграммы обязан совпасть с переданным: демон
       не вправе продолжить одну датаграмму под ключом другого потока. */
    d2k_key parsed_key;
    int src_is_low = d2k_key_make_addr(&parsed_key, 17, &ip.src, &ip.dst, u, u + 2);
    if (memcmp(&parsed_key, key, sizeof parsed_key) != 0) {
        out->skipped = "продолжение UDP: ключ датаграммы не совпал с переданным"; return 0;
    }

    /* Поток обязан жить ТОЙ ЖЕ инкарнацией и эпохой: иначе он забыт/заменён
       (переиспользование кортежа — другой поток), и продолжать нечего. */
    d2k_flow *fl = d2k_track_find(s->uflows, key);
    if (!fl || fl->incarnation != incarnation ||
        memcmp(fl->flow_epoch, epoch, 16) != 0) {
        out->skipped = "продолжение UDP: поток забыт, заменён или другой инкарнации"; return 0;
    }
    if (!fl->dir_known || src_is_low != fl->init_low) {
        out->skipped = "продолжение UDP: неверное направление"; return 0;
    }
    /* Уже применён (например, повтор клиента подтвердил кортеж раньше):
       продолжения нет, вызывающий вводит ОРИГИНАЛ. */
    if (fl->plan_done) {
        out->skipped = "продолжение UDP: план уже применён к этому потоку"; return 0;
    }
    /* Подтверждённый ответный кортеж обязан сходиться с оригиналом: ядро
       транслирует ИСТОЧНИК, сервер (получатель) не меняется. Голые внешние
       поля не принимаем — только проверенный reply_tuple. */
    if (!mapping->reply_tuple_known) {
        out->skipped = "продолжение UDP: кортеж ответа не подтверждён"; return 0;
    }
    {
        const d2k_ct_tuple *rt = &mapping->reply_tuple;
        size_t al = ip.family == 6 ? 16u : 4u;
        /* Всё в СЕТЕВОМ порядке, сравниваем байты: сервер (источник ответного
           направления) = получатель оригинала, порт сервера = порт назначения
           оригинала (u+2). Внешний адрес/порт (reply dst) ядро выбрало — его в
           udp_execute и подставляем. */
        if (rt->family != ip.family || rt->proto != 17 ||
            memcmp(rt->sport_be, u + 2, 2) != 0 ||
            memcmp(rt->src, ip.dst.bytes, al) != 0) {
            out->skipped = "продолжение UDP: кортеж ответа не сошёлся с оригиналом"; return 0;
        }
    }
    /* РАЗРЕШЕНИЕ ПЛАНА — ПО ТОЧНОЙ ЖИВОЙ ПРИВЯЗКЕ, а не повторным выбором.
       Привязка (поколение + эпоха таблицы + вид/семейство/форма/временность)
       указывает ровно на ту установку, что была выбрана, каким бы селектором её
       ни нашли: цель/имя/адрес/суффикс/проба, измеренная raw-UDP, STUN/голос,
       многопакетный QUIC-SNI — все покрыты одинаково, без дублирования выбора и
       без зависимости от повторного извлечения имени. Истёкшая/заменённая/
       удалённая/переустановленная (новое поколение) привязка сюда не попадёт —
       NULL, отказ. Срок пробы учтён внутри (now_ns). */
    const d2k_plan *use = d2k_plantab_find_by_binding(s->plans, binding, now_ns);
    if (!use) {
        out->skipped = "продолжение UDP: привязка истекла, заменена, удалена или переустановлена";
        return 0;
    }
    /* Пояса и подтяжки: план и trial той же установки обязаны совпасть. */
    uint8_t now_trial[D2K_TRIAL_ID_LEN];
    d2k_plantab_trial(s->plans, use, now_trial);
    if (memcmp(d2k_plan_id(use), plan_id, D2K_PLAN_ID_LEN) != 0 ||
        memcmp(now_trial, trial_id, D2K_TRIAL_ID_LEN) != 0) {
        out->skipped = "продолжение UDP: план или trial привязки не совпали"; return 0;
    }
    /* СВЯЗКА ИСПОЛНЕНИЯ STUN/голоса. На defer handle_udp уже НАБЛЮДАЛ запрос
       (взвёл stun_txid_valid/voice_ssrc_valid), но план НЕ ПРИМЕНИЛСЯ, поэтому
       связка «запрос → исполнение» так и не записалась. Продолжение И ЕСТЬ это
       исполнение: получаем тот же слот запроса и ПРИНУДИТЕЛЬНО помечаем его
       как связываемое (new=1 / first=1), чтобы udp_execute записал execution_id
       — иначе ответ STUN/голоса нечем будет доказать. Прочий STUN контекст не
       трогаем. */
    int new_stun_request = 0;
    d2k_stun_request_slot *stun_request = NULL;
    if (is_stun_request(datagram + payload_off, payload_len)) {
        stun_request = stun_observe_request(fl, datagram + payload_off + 8,
                                            now_ns, &new_stun_request);
        new_stun_request = 1;   /* это исполнение связывает наблюдённый запрос */
    }
    int first_voice_request = is_discord_ip_discovery(datagram + payload_off, payload_len);

    /* Исполняем на ОРИГИНАЛЕ через общий UDP-исполнитель с подтверждённым
       отображением. handle_udp мы НЕ зовём, поэтому клиентский пакет не
       пересчитывается: fwd_pkts, HELLO/SUSPECT и область измеряемой пробы не
       трогаются. На отказе udp_execute вызывающий вводит ОРИГИНАЛ (эти же
       байты), НИКОГДА пост-NAT копию. */
    udp_execute(s, fl, key, use, trial_id, datagram, payload_off, payload_len, &ip, u,
                now_ns, buf, bufcap, /*held_first_replay=*/1, first_voice_request,
                stun_request, new_stun_request, mapping, out);
    return out->applied ? 1 : 0;
}

int d2k_session_packet(d2k_session *s, const uint8_t *pkt, size_t len,
                       uint64_t now_ns, uint8_t *buf, size_t bufcap, d2k_result *out) {
    return session_packet(s, pkt, len, now_ns, buf, bufcap, out, 0, 0, 0);
}

int d2k_session_packet_mtu(d2k_session *s, const uint8_t *pkt, size_t len,
                           uint64_t now_ns, size_t tcp_segment_cap,
                           uint8_t *buf, size_t bufcap, d2k_result *out) {
    return session_packet(s, pkt, len, now_ns, buf, bufcap, out, 0, 0,
                          tcp_segment_cap);
}

int d2k_session_packet_probe(d2k_session *s, const uint8_t *pkt, size_t len,
                             uint64_t now_ns, uint8_t *buf, size_t bufcap,
                             d2k_result *out) {
    return session_packet(s, pkt, len, now_ns, buf, bufcap, out, 0, 1, 0);
}

int d2k_session_packet_probe_mtu(d2k_session *s, const uint8_t *pkt, size_t len,
                                 uint64_t now_ns, size_t tcp_segment_cap,
                                 uint8_t *buf, size_t bufcap, d2k_result *out) {
    return session_packet(s, pkt, len, now_ns, buf, bufcap, out, 0, 1,
                          tcp_segment_cap);
}

void d2k_session_observe_tcp(d2k_session *s, const uint8_t *p, size_t n, uint64_t now) {
    d2k_result out;
    (void)session_packet(s, p, n, now, NULL, 0, &out, 1, 0, 0);
}

uint64_t d2k_session_plan_revision(const d2k_session *s) {
    return s ? s->plan_revision + d2k_plantab_revision(s->plans) : 0;
}

int d2k_session_stream_anchor(d2k_session *s, const uint8_t *p, size_t n,
                              uint32_t *anchor) {
    d2k_hold_info v;
    if (!s || !anchor || !d2k_hold_parse(p, n, &v)) { return 0; }
    d2k_flow *fl = d2k_track_find(s->flows, &v.key);
    if (!fl || !fl->saw_syn) { return 0; }
    if(fl->stream_plan_pending && fl->stream_plan_stage==2 && !fl->adopted) {
        *anchor=fl->syn_seq+1u+fl->stream_plan_offset;return 1;
    }
    *anchor = fl->http_flow && fl->http_conn ? fl->http_next : fl->syn_seq + 1;
    return 1;
}

void d2k_session_set_hook(d2k_session *s, uint8_t hook) {
    if (s) { s->hook = hook; }
}

void d2k_session_set_route_mark(d2k_session *s, uint32_t mark) {
    if (s) { s->route_mark = mark; }
}

uint32_t d2k_session_route_mark(const d2k_session *s) {
    return s ? s->route_mark : 0;
}

uint64_t d2k_session_routed_flows(const d2k_session *s) {
    return s ? s->routed_flows : 0;
}

void d2k_session_set_udp_reverse_hook(d2k_session *s, int installed) {
    if (s) { s->udp_reverse_hook = installed != 0; }
}

void d2k_session_set_ct_query(d2k_session *s, d2k_ct_query_fn fn, void *ctx) {
    if (s) { s->ct_query = fn; s->ct_query_ctx = ctx; }
}

int d2k_session_udp_hold_begin(d2k_session *s, const uint8_t *p, size_t n,
                               uint64_t now_ns, d2k_key *key_out) {
    d2k_packet_view ip;
    if (!s || s->route_mark || !d2k_packet_parse(p, n, &ip) || ip.protocol != 17 ||
        (ip.fragment & 0x3fff)) { return 0; }
    size_t ihl = ip.l4;
    const uint8_t *u = p + ihl;
    size_t total = ip.total;
    if (total < ihl + 8 || total > n) {
        return 0;
    }
    /* Only a client-side QUIC Initial needs split replay.  Voice/STUN and
       ordinary UDP remain observation-only here.  With a real OUTPUT or
       POSTROUTING hook the direction is already proven and the service may
       use any destination port; callers that do not provide a hook retain the
       old 443 fallback so tests/lab tools cannot silently reinterpret an
       unknown direction. */
    int hook_client = (s->hook == D2K_HOOK_OUTPUT ||
                       s->hook == D2K_HOOK_POSTROUTING);
    int hook_server = (s->hook == D2K_HOOK_INPUT ||
                       s->hook == D2K_HOOK_PREROUTING ||
                       s->hook == D2K_HOOK_FORWARD);
    if (hook_server || (!hook_client &&
                        (rd16(u + 2) != 443 || rd16(u) == 443)) ||
        !d2k_quic_is_initial(p + ihl + 8, total - ihl - 8)) {
        return 0;
    }
    d2k_key key;
    (void)d2k_key_make_addr(&key, 17, &ip.src, &ip.dst, u, u + 2);
    d2k_flow *fl = d2k_track_get(s->uflows, &key, now_ns);
    if (!fl) { return 0; }
    /* За окном поиска сессия выходит раньше блока удержания (ни wait, ни
       ready), и датаграмма осталась бы и в ячейке, и под обычным вердиктом:
       два вердикта на один ID и повторная посылка уже ушедшего (задача 46,
       ревью I1). fwd_pkts растёт уже после этого вызова. */
    if (fl->plan_done || fl->damaged || fl->saw_hello || fl->routed ||
        fl->fwd_pkts >= D2K_HELLO_WINDOW) { return 0; }
    fl->udp_hold_active = 1;
    if (key_out) { *key_out = key; }
    return 1;
}

int d2k_session_udp_opening(d2k_session *s, const uint8_t *p, size_t n) {
    d2k_packet_view ip;
    if (!s || !d2k_packet_parse(p, n, &ip) || ip.protocol != 17 || (ip.fragment & 0x3fff)) {
        return 0;
    }
    const uint8_t *u = p + ip.l4;
    d2k_key key;
    int src_is_low = d2k_key_make_addr(&key, 17, &ip.src, &ip.dst, u, u + 2);
    d2k_flow *fl = d2k_track_find(s->uflows, &key);
    if (!fl || fl->fwd_pkts != 1) { return 0; }
    int from_client = -1;
    if (s->hook == D2K_HOOK_OUTPUT || s->hook == D2K_HOOK_POSTROUTING) {
        from_client = 1;
    } else if (s->hook == D2K_HOOK_INPUT || s->hook == D2K_HOOK_PREROUTING) {
        from_client = 0;
    }
    if (from_client < 0 && fl->dir_known) {
        from_client = (src_is_low == fl->init_low) ? 1 : 0;
    }
    if (from_client < 0) {
        from_client = rd16(u + 2) == 443 && rd16(u) != 443;
    }
    return from_client == 1;
}

void d2k_session_udp_hold_end(d2k_session *s, const d2k_key *key) {
    if (!s || !key) { return; }
    d2k_flow *fl = d2k_track_find(s->uflows, key);
    if (fl) { fl->udp_hold_active = 0; }
}

void d2k_session_udp_hold_replay(d2k_session *s, const d2k_key *key) {
    if (!s || !key) { return; }
    d2k_flow *fl = d2k_track_find(s->uflows, key);
    if (fl) {
        fl->udp_hold_active = 0;
        fl->udp_hold_replay_first = 1;
    }
}

void d2k_session_note_unassembled(d2k_session *s, const uint8_t *p, size_t n,
                                  uint64_t now_ns) {
    d2k_hold_info v;
    if (!s || !d2k_hold_parse(p, n, &v)) { return; }
    d2k_flow *fl = d2k_track_find(s->flows, &v.key);
    /* НЕ ЧАЩЕ ОДНОГО РАЗА НА ПОТОК: отпускается несколько пакетов, а событие
       про них одно. Потока может и не быть в таблице — тогда сказать нечего,
       и выдумывать ключ незачем. */
    if (!fl) { return; }
    const uint8_t *tcp=p+v.ihl;
    if(fl->stream_plan_pending && fl->stream_plan_stage==2) {
        uint32_t delta=v.seq-(fl->syn_seq+1u+fl->stream_plan_offset);
        if(delta<fl->stream_plan_length) {
            d2k_session_unsent(s,now_ns,&v.key,fl->execution_plan_id,
                D2K_REFUSE_NOT_APPLIED,fl->execution_id);
            return;
        }
    }
    if(tcp[2]==0 && tcp[3]==80 && !fl->saw_hello &&
       (fl->http_flow || (v.seq==fl->syn_seq+1 && v.payload &&
                         p[v.header]>='A' && p[v.header]<='Z'))) {
        fl->http_checked=1;fl->http_conn=fl->http_headers=0;
        refuse(s,now_ns,&v.key,"HTTP: составной запрос отпущен — граница не доказана");
        return;
    }
    if (fl->noted_unassembled) { return; }
    fl->noted_unassembled = 1;
    /* ЧИСЛА — В ЛОГ, А НЕ В ЖУРНАЛ: журнал хранит УКАЗАТЕЛЬ на текст, не
       копию, и локальный буфер там повис бы. А числа нужны: они отличают
       «пришёл один кусок, остаток не дошёл» от «куски пришли, не собрались».
       Объявленная длина записи против пришедшей и есть этот ответ. */
    if (v.payload >= 5) {
        unsigned declared = 5u + (unsigned)rd16(p + v.header + 3);
        fprintf(stderr, "d2kd: составное приветствие отпущено без сборки: "
                        "объявлено %u байт записи, в этом куске %zu\n",
                declared, v.payload);
    }
    refuse(s, now_ns, &v.key,
           "составное приветствие не собралось — план не применён к его пакетам");
}

/* НАСКОЛЬКО ДАЛЕКО ОТ SYN ЕЩЁ МОЖЕТ ЛЕЖАТЬ КУСОК ПРИВЕТСТВИЯ.
 *
 * Приветствие TLS ограничено 16 КБ записи (RFC 8446 §5.1), а составное входит
 * в несколько сегментов подряд. Шестнадцати килобайт хватает с запасом, и это
 * не «на всякий случай»: окно нужно, чтобы не удерживать данные СЕРЕДИНЫ
 * соединения, приняв их за кусок приветствия. */
#define HOLD_EARLY_WINDOW 16384u

int d2k_session_retry_watch(d2k_session *s, const uint8_t *p, size_t n) {
    d2k_hold_info v;
    if (!s || !d2k_hold_parse(p, n, &v)) return -1;
    d2k_flow *fl = d2k_track_find(s->flows, &v.key);
    if (!fl || fl->routed || fl->damaged || fl->saw_rev_rst) return 0;
    if (fl->late_watch) return 1; /* этап 17: метку записи держит опыт, не SYN-правило */
    if (fl->stream_plan_pending) return 1;
    if (fl->saw_syn && !fl->tcp_payload_seen) return 1;
    /* Pending sends still own the flow; the watch is dropped after a reply,
       plan change or snapshot eviction, not merely because a send is paced. */
    return fl->retry_tls_len && !fl->rev_payload_after_hello &&
        !fl->reply_hidden_told && !fl->sends_failed &&
        fl->retry_slot < D2K_HOLD_SLOTS && fl->retry_token &&
        s->retries[fl->retry_slot].token == fl->retry_token &&
        fl->retry_plan_revision == d2k_session_plan_revision(s);
}

int d2k_session_hold_candidate(d2k_session *s, const uint8_t *p, size_t n) {
    d2k_hold_info v;
    if (!s || s->route_mark || !d2k_hold_parse(p, n, &v) || !v.payload ||
        (v.flags & ~0x18) || !(v.flags & 0x10)) { return 0; }
    d2k_flow *fl = d2k_track_find(s->flows, &v.key);
    /* Do not retain a tail of an already-passed stream or guess direction.
       Only a first payload anchored by the observed client SYN qualifies. */
    if (!fl || !fl->saw_syn || !fl->dir_known || fl->init_low != v.src_low ||
        fl->damaged || fl->routed) {
        return 0;
    }
    const uint8_t *tcp=p+v.ihl;
    if(fl->stream_plan_pending && fl->stream_plan_stage==2 && !fl->adopted &&
       fl->stream_plan_length && fl->stream_plan_length<=D2K_CAPTURE_BYTES) {
        uint32_t delta=v.seq-(fl->syn_seq+1u+fl->stream_plan_offset);
        if(delta>=fl->stream_plan_length || v.payload>fl->stream_plan_length-delta)return 0;
        if(!delta && v.payload==fl->stream_plan_length)return 0;
        return D2K_HOLD_EXACT(fl->stream_plan_length);
    }
    /* A port is not a protocol. Before HTTP is known, only a plausible
       method at the observed stream head may start HTTP collection. An
       unknown tail retains the existing TLS eligibility/readiness path. */
    if(tcp[2]==0 && tcp[3]==80 && !fl->saw_hello &&
       (fl->http_flow || (v.seq==fl->syn_seq+1 &&
                         p[v.header]>='A' && p[v.header]<='Z'))) {
        uint32_t start;
        if(!fl->http_checked)start=fl->syn_seq+1;
        else if(fl->http_flow && fl->http_conn)start=fl->http_next;
        else return 0;
        uint32_t delta=v.seq-start;
        if(delta>=D2K_CAPTURE_BYTES || v.payload>D2K_CAPTURE_BYTES-delta)return 0;
        d2k_http_req req;
        if(!delta && d2k_http_request(p+v.header,v.payload,&req))return 0;
        if(!delta && (p[v.header]<'A' || p[v.header]>'Z'))return 0;
        return d2k_plantab_http_candidate(s->plans,v.dst.family,
            fl->controller_probe?v.sport_be:0)?D2K_HOLD_HTTP:0;
    }
    /* Поток открытого HTTP: следующие запросы — не хвост приветствия TLS. */
    if (fl->http_flow) { return 0; }

    /* КУСОК ПРИВЕТСТВИЯ МОЖЕТ ПРИЙТИ НЕ ПЕРВЫМ, И ЕГО ТОЖЕ НАДО УДЕРЖАТЬ.
     *
     * Прежнее правило требовало, чтобы сегмент стоял сразу за SYN и НАЧИНАЛ
     * запись TLS. Поле 17.09.2026, зонд подтверждения d2k на живой линии:
     *   seq=3909908605 нагрузка=146   <- ХВОСТ пришёл первым
     *   seq=3909907217 нагрузка=1388  <- голова, после
     * Хвост кандидатом не становился и уходил на провод ГОЛЫМ — прямо в
     * коробку; голова заводила удержание и ждала того, чего уже нет. Таймаут,
     * план не применён, рабочий обход выброшен собственным подтверждением.
     *
     * Сборка по смещениям у датапата есть (capture.c собирает по seq) — не
     * хватало права НАЧАТЬ удержание не с первого куска. Окно и остальные
     * условия (SYN виден, приветствия ещё не было, поток не испорчен) держат
     * это правило узким: удерживается только раннее содержимое потока, для
     * цели которого план уже есть. */
    int at_head = (v.seq == fl->syn_seq + 1);
    uint32_t off = v.seq - (fl->syn_seq + 1);

    /* Пометки закрывают поток для НОВОГО удержания, и этого достаточно:
       кусок, пришедший к УЖЕ открытому слоту, берётся самим удержанием
       независимо от этого ответа (allow_start решает только «заводить ли
       слот», см. d2k_hold_feed). */
    /* Retransmissions use a validated snapshot in session_packet; do not
       wait for the rest of a record that the TCP sender may not repeat. */
    if (fl->saw_hello && fl->retry_tls_len) return 0;
    if (fl->saw_hello || fl->stream_attempted) { return 0; }
    if (!at_head && off >= HOLD_EARLY_WINDOW) { return 0; }
    if (at_head) {
        /* Голова обязана начинать запись TLS — иначе это не приветствие, а
           данные, и удерживать их незачем. */
        if (p[v.header] != 22) { return 0; }
        /* Запись целиком в этом куске — собирать нечего. */
        if (v.payload >= 5 && 5u + rd16(p + v.header + 3) <= v.payload) { return 0; }
    }

    d2k_tls_info tls;
    memset(&tls, 0, sizeof tls);
    /* Разбирать имеет смысл только голову: у хвоста заголовка записи нет, и
       имя из него не достать. Для него план ищется по адресу и порту — этого
       достаточно, чтобы не удерживать чужие потоки. */
    if (at_head) {
        d2k_tls_parse(p + v.header, v.payload, &tls);
        /* ECH proof and bound non-ECH proof both need the full form before
         * selecting a production plan. Reuse bounded, fail-open collection;
         * if ownership fails, packet classification still refuses to guess. */
        if (!fl->controller_probe && tls.have_sni && tls.exts_truncated &&
            !tls.ech_offer && (d2k_plantab_has_ech_target(s->plans,
                p + v.header + tls.sni_off, tls.sni_len,
                v.dst.bytes, v.dst.family, 0) ||
             d2k_plantab_needs_complete_tls_shape(s->plans,
                p + v.header + tls.sni_off,tls.sni_len,v.dst.family))) {
            fl->stream_attempted = 1;
            return 1;
        }
        /* A known name selects a plan, but does not complete the record.
         * Stream plans below may own the remaining bytes. d2kd immediately
         * drops owned originals from NFQUEUE so local TCP can emit the tail.
         * Plans that do not request stream input still use the packet path. */
    }
    int candidate = d2k_plan_stream_input(s->plan) ||
        d2k_plantab_stream_candidate_target(s->plans,
            tls.have_sni ? p + v.header + tls.sni_off : NULL,
            tls.have_sni ? tls.sni_len : 0, v.dst.bytes,
            fl->controller_probe ? v.sport_be : 0, v.dst.family);
    /* Also mark a failed capacity attempt: its head must not be held later
       after we have already released it unchanged. */
    /* stream_attempted — только у головы: пометка закрывает потоку удержание
       навсегда, и ставить её на хвост значило бы отнять у головы её же
       попытку. */
    if (candidate && at_head) { fl->stream_attempted = 1; }
    return candidate;
}

int d2k_session_want_shape(d2k_session *s, const uint8_t *name, size_t len,
                           uint8_t transport) {
    return d2k_session_want_shape_family(s, name, len, transport, 4);
}

int d2k_session_want_shape_family(d2k_session *s, const uint8_t *name, size_t len,
                                  uint8_t transport, uint8_t family) {
    if (!s || (family != 4 && family != 6) || (transport != 6 && transport != 17) ||
        (!name && len)) {
        return 0;
    }
    size_t k = shape_slot(transport, family);
    if (len > sizeof s->shape_name[k]) {
        len = sizeof s->shape_name[k];
    }
    /* Сохранённое подходит — отдаём немедленно. Ждать следующего приветствия
       значило бы ждать повтора клиента, а подозрение возникло на том же
       соединении, чьё приветствие только что прошло. */
    if (s->last_hello_len[k] > 0 &&
        (len == 0 || name_same(s->last_name[k], s->last_name_len[k], name, len))) {
        memcpy(s->shape[k], s->last_hello[k], s->last_hello_len[k]);
        s->shape_len[k] = s->last_hello_len[k];
        s->shape_at[k]=0; /* manual request is not an earlier event's snapshot */
        memcpy(s->shape_opts[k], s->last_opts[k], s->last_opts_len[k]);
        s->shape_opts_len[k] = s->last_opts_len[k];
        s->shape_armed[k] = 0;
        return 1;
    }
    s->shape_armed[k] = 1;
    s->shape_len[k] = 0;
    s->shape_name_len[k] = len;
    if (len) {
        memcpy(s->shape_name[k], name, len);
    }
    return 0;
}

const uint8_t *d2k_session_shape(const d2k_session *s, uint8_t transport, size_t *len) {
    return d2k_session_shape_family(s, transport, 4, len);
}

const uint8_t *d2k_session_shape_family(const d2k_session *s, uint8_t transport,
                                        uint8_t family, size_t *len) {
    if (len) { *len = 0; }
    if (!s || (family != 4 && family != 6) || (transport != 6 && transport != 17)) {
        return NULL;
    }
    size_t k = shape_slot(transport, family);
    if (s->shape_len[k] == 0) {
        return NULL;
    }
    if (len) {
        *len = s->shape_len[k];
    }
    return s->shape[k];
}

const uint8_t *d2k_session_shape_event(const d2k_session *s,const d2k_key *key,uint64_t at,size_t *len)
{
    if(len)*len=0;
    if(!s || !key || (key->proto!=6 && key->proto!=17))return NULL;
    size_t k=shape_slot(key->proto,key->family==6?6:4);
    if(s->shape_at[k]!=at || !d2k_key_equal(&s->shape_key[k],key))return NULL;
    return d2k_session_shape_family(s,key->proto,key->family==6?6:4,len);
}

const uint8_t *d2k_session_shape_tcp_options_family(const d2k_session *s, uint8_t family,
                                                    size_t *len) {
    if (len) { *len = 0; }
    if (!s || (family != 4 && family != 6)) { return NULL; }
    size_t k = shape_slot(6, family);
    if (s->shape_len[k] == 0) { return NULL; }
    if (len) { *len = s->shape_opts_len[k]; }
    return s->shape_opts[k];
}

d2k_plantab *d2k_session_plans(d2k_session *s) {
    return s ? s->plans : NULL;
}

size_t d2k_session_plan_count(const d2k_session *s) {
    return s ? d2k_plantab_count(s->plans) : 0;
}

size_t d2k_session_plan_capacity(const d2k_session *s) {
    return s ? d2k_plantab_capacity(s->plans) : 0;
}

/* Срок, после которого молчание перестаёт быть задержкой.
 *
 * Здоровый ответ на приветствие приходит за один RTT. Первая повторная посылка
 * TCP уходит примерно через секунду; значит к исходу секунды не пришло ни
 * ответа, ни толку от повтора. Отсюда пол в одну секунду — он про терпение
 * человека перед пустой страницей, а не про сеть.
 *
 * Множитель на измеренный RTT нужен линиям, где секунда — это меньше двух
 * оборотов: там пол сработал бы на здоровом соединении. Потолок в пять секунд
 * — снова про человека: дольше он уже не ждёт, и поиск, начатый позже, ему
 * не нужен.
 *
 * RTT не измерен (поток подхватили посреди обмена) — берём две секунды: одна
 * на здоровый ответ, одна на неизвестность. */
static uint64_t silence_deadline(const d2k_flow *f) {
    const uint64_t floor_ns = NS_PER_S;
    const uint64_t ceil_ns  = 5 * NS_PER_S;
    if (!f->rtt_ns) {
        return 2 * NS_PER_S;
    }
    uint64_t d = f->rtt_ns * 8;
    if (d < floor_ns) { d = floor_ns; }
    if (d > ceil_ns)  { d = ceil_ns; }
    return d;
}

/* ОКНО ПОВТОРА FIN — сколько держать запись после FIN клиента.
 *
 * Сигнал один: повтор того же FIN, то есть ретрансмиссия по таймеру. Таймер
 * задаёт RFC 6298: первый RTO по измеренному R — SRTT + 4·RTTVAR = R + 2R =
 * 3R (§2.2), не меньше секунды (§2.4); без измерения — секунда (§2.1). Окно
 * — первый повтор и ещё один после удвоения (§5.5): RTO + 2·RTO = 3·RTO, чтобы
 * один потерянный повтор не стоил сигнала. Linux и macOS шлют повтор раньше
 * (пол RTO 200 мс; в поле 03.10 macOS — через 0,44 с), значит окно с запасом.
 * Повтор, пришедший позже (RTO, раздутый очередью), теряется — это пропуск
 * сигнала, а не ложное срабатывание. После окна запись не говорит ничего и
 * только занимает место в таблице, которая выше трёх четвертей отказывает
 * новым потокам. */
static uint64_t fin_retry_window(const d2k_flow *f) {
    uint64_t rto = 3 * f->rtt_ns;
    if (rto < NS_PER_S) { rto = NS_PER_S; }
    return 3 * rto;
}

static int fin_window_over(void *ctx, const d2k_flow *f) {
    const uint64_t now_ns = *(const uint64_t *)ctx;
    return f->pending_fin && now_ns >= f->pending_fin_ns &&
           now_ns - f->pending_fin_ns >= fin_retry_window(f);
}

struct sweep_ctx {
    d2k_session *s;
    uint64_t     now_ns;
    size_t       told;
};

/* Молчание — это ОТСУТСТВИЕ нагрузки в ответ, а не отсутствие пакетов.
 * Сервер, подтвердивший приветствие пустым ACK и замолчавший, и есть картина
 * блокировки: TCP жив, ответа нет. */
static void sweep_one(void *ctx, d2k_flow *f) {
    struct sweep_ctx *c = ctx;
    if (!f->saw_hello && f->raw_seen) {
        /* МОЛЧАНИЕ ПОТОКА БЕЗ РАСПОЗНАННОГО ПРОТОКОЛА (этап 12). Те же три
           улики, что у приветствия: клиент ПОВТОРИЛ свой первый сегмент
           (ретрансмиссия — он ждёт), обратная сторона видна (SYN-ACK дошёл до
           очереди), а данных оттуда нет дольше срока. Ответ с данными или
           сброс сервера — не молчание; зонд контроллера — не клиент. */
        if (f->silence_told || f->suspected || f->controller_probe || f->raw_repeats == 0 ||
            f->rev_pkts == 0 || f->rev_data_pkts > 0 || f->saw_rev_rst ||
            c->now_ns < f->raw_ns || c->now_ns - f->raw_ns < silence_deadline(f)) {
            return;
        }
        f->silence_told = 1;
        c->told++;
        suspect(c->s, c->now_ns, &f->key, f, D2K_SUSPECT_SILENT, NULL);
        return;
    }
    if (!f->saw_hello || f->silence_told || f->suspected) {
        return;
    }
    if (f->rev_payload_after_hello > 0 || f->saw_rev_rst) {
        return;
    }
    /* Обратная сторона должна быть ВИДНА. Правило на обратное направление
       ставится не всегда, и без него в очередь не приходит ни один пакет
       сервера: каждый поток выглядел бы молчащим. Это была бы подмена «не
       смотрели» на «нет ответа» — ровно то, что §2.4 запрещает. Признаком
       видимости служит любой пакет оттуда, обычно SYN-ACK. */
    if (f->rev_pkts == 0) {
        return;
    }
    if (c->now_ns < f->hello_ns) {
        return;
    }
    if (c->now_ns - f->hello_ns < silence_deadline(f)) {
        return;
    }
    f->silence_told = 1;
    c->told++;
    suspect(c->s, c->now_ns, &f->key, f, D2K_SUSPECT_SILENT, NULL);
}

/* Молчание по UDP. Критерий СВОЙ, а не унаследованный от TCP, и разница не
 * в мелочах:
 *
 *   у TCP улика видимости обратной стороны поточная (SYN-ACK приходит до
 *   приветствия), у UDP её не существует — первая же датаграмма QUIC и есть
 *   приветствие, и на заблокированном потоке оттуда не придёт ничего
 *   никогда. Остаётся сессионная улика (rev_seen);
 *
 *   у TCP «нет ответа» это отсутствие НАГРУЗКИ при живом соединении: пустой
 *   ACK и молчание — уже картина блокировки. У UDP пустых пакетов нет,
 *   поэтому любой пакет оттуда считается ответом;
 *
 *   и главное: у TCP признаком того, что ответа всё ещё ждут, служат
 *   ретрансмиссии, которые считает сам транспорт. У UDP их считать некому,
 *   и спрашивать приходится клиента: повторил Initial по своему таймеру PTO
 *   — значит ждёт. Без этого условия «молчанием» стала бы всякая закрытая
 *   вкладка (см. fwd_after_hello в d2k_track.h).
 *
 * Сроку это ничего не добавляет: rtt_ns у UDP-потока не измерен никогда — ни
 * SYN, ни SYN-ACK у QUIC нет, — и silence_deadline честно отдаёт свои две
 * секунды «одна на здоровый ответ, одна на неизвестность». Первый повтор PTO
 * к этому времени уже ушёл (RFC 9002 §6.2.2: стартовый RTT 333 мс даёт около
 * секунды), то есть условие про повтор к сроку выполнимо, а не мертво. */
static void sweep_udp_one(void *ctx, d2k_flow *f) {
    struct sweep_ctx *c = ctx;
    /* saw_initial — тот же поток, только имя из Initial не прочиталось
       (см. d2k_track.h). Молчание по нему — наблюдение не хуже прочих. */
    if (!f->saw_hello && !f->saw_initial && !f->stun_txid_valid && !f->voice_ssrc_valid &&
        !f->silence_told && !f->suspected && !f->controller_probe && !f->quic_deny) {
        /* UDP БЕЗ РАСПОЗНАННОГО ПРОТОКОЛА (этап 12): не QUIC Initial, не STUN,
           не Discovery. Улики те же, что у QUIC-молчания, только без
           приветствия: клиент упорствует (не меньше трёх датаграмм), обратная
           сторона видна сессии, оттуда — ничего дольше срока. Любой пакет
           оттуда снимает подозрение: протокола мы не знаем и ответа не судим. */
        if (f->fwd_pkts < 3 || f->rev_pkts > 0 ||
            (!c->s->rev_seen[shape_slot(17, f->key.family)] && !c->s->udp_reverse_hook) ||
            c->now_ns < f->first_ns || c->now_ns - f->first_ns < silence_deadline(f)) {
            return;
        }
        if (!f->client_shape) { f->client_shape = D2K_PLAN_SHAPE_RAW; }
        f->silence_told = 1;
        c->told++;
        suspect(c->s, c->now_ns, &f->key, f, D2K_SUSPECT_SILENT, NULL);
        return;
    }
    if ((!f->saw_hello && !f->saw_initial) || f->silence_told || f->suspected ||
        f->quic_deny) {
        return;
    }
    if(f->stun_txid_valid) {
        if(f->controller_probe ||
           (!c->s->rev_seen[shape_slot(17,f->key.family)] && !c->s->udp_reverse_hook))return;
        for(size_t i=0;i<D2K_STUN_REQUEST_SLOTS;i++) {
            const d2k_stun_request_slot *r=&f->stun_requests[i];
            if(!r->valid || r->answered || r->told || !r->repeated || c->now_ns<r->started_ns ||
               c->now_ns-r->started_ns<silence_deadline(f))continue;
            d2k_jrn_detail detail={0};
            detail.planned=r->context.execution_id ? D2K_PLANNED_YES : D2K_PLANNED_NO;
            detail.client_shape=f->client_shape;
            detail.client_side=f->dir_known ?
                (f->init_low ? D2K_CLIENT_SIDE_LOW : D2K_CLIENT_SIDE_HIGH) : 0;
            f->silence_told=1;f->suspected=1;c->told++;c->s->suspects++;
            d2k_journal_add_suspect_request(c->s->jrn,c->now_ns,&f->key,
                                           D2K_SUSPECT_SILENT,&detail,&r->context);
            return;
        }
        return;
    }
    /* Один ответ не закрывает наблюдение навсегда: цензор может пропустить
       первый Initial, а затем съесть повтор PTO. Считаем поток отвечающим,
       только если после последней клиентской повторной посылки уже был ответ. */
    if (f->rev_after_hello > 0 &&
        f->last_rev_after_hello_ns >= f->last_fwd_after_hello_ns) {
        return;
    }
    if (!c->s->rev_seen[shape_slot(17, f->key.family)] && !c->s->udp_reverse_hook) {
        return;
    }
    if (f->fwd_after_hello == 0) {
        return;
    }
    if (c->now_ns < f->hello_ns) {
        return;
    }
    if (c->now_ns - f->hello_ns < silence_deadline(f)) {
        return;
    }
    f->silence_told = 1;
    c->told++;
    suspect(c->s, c->now_ns, &f->key, f, D2K_SUSPECT_SILENT, NULL);
}

/* QUIC ЗАМОЛЧАЛ ПОСЛЕ РУКОПОЖАТИЯ (задача 50, раунд 2; поле 04.10, rua.gr в
 * Safari и curl --http3-only).
 *
 * Рукопожатие прошло, сервер прислал ещё сколько-то пакетов — и замолчал
 * насовсем (на ppp0 пусто), а клиент шлёт повторы по PTO. Очередь видит у UDP
 * первые 8 пакетов каждой стороны, поэтому смотрим счётчики conntrack:
 *   - кандидат: поток с Initial (с именем или без), ответ в очереди был,
 *     подозрения ещё нет, не зонд контроллера;
 *   - обратный счётчик ушёл ЗА то, что видела очередь (rev_pkts): сервер
 *     прошёл дальше рукопожатия, иначе это молчание рукопожатия, у которого
 *     свой детектор (sweep_udp_one);
 *   - обратный счётчик стоит не меньше PTO (RFC 9002 §6.2: первый PTO = 3R,
 *     пол секунда как у окна повтора FIN — шаг обхода тоже секунда);
 *   - за это время клиент послал не меньше ТРЁХ пакетов. Без ответа законно
 *     остаются два: последний ACK на последние данные сервера (ACK без
 *     запроса подтверждения ответа не требует) и CONNECTION_CLOSE (RFC 9000
 *     §10.2: на него не отвечают). Третий — повтор в тишину: живой сервер на
 *     пакет, требующий подтверждения, ответил бы за RTT + max_ack_delay.
 * Это подозрение, не диагноз: контроллер обязан воспроизвести остановку
 * своим запросом HTTP/3, прежде чем что-то подбирать. */
static int quic_watch(const d2k_flow *f) {
    return f->key.proto == 17 && (f->saw_hello || f->saw_initial) &&
           f->rev_after_hello > 0 && !f->suspected && !f->controller_probe &&
           !f->quic_deny &&
           !f->voice_ssrc_valid && !f->stun_txid_valid;
}

/* Прямой кортеж потока, как его ведёт conntrack: клиент → сервер. Для
   транзита очередь стоит до SNAT, и адрес клиента в нём локальный — ровно
   такой же, как в прямом кортеже записи. */
static void flow_tuple(const d2k_flow *f, d2k_ct_tuple *t) {
    memset(t, 0, sizeof *t);
    int v6 = f->key.family == 6;
    t->family = v6 ? 6 : 4;
    t->proto = f->key.proto == 6 ? 6 : 17;
    const uint8_t *lo = v6 ? f->key.low_ip6 : (const uint8_t *)&f->key.low_ip;
    const uint8_t *hi = v6 ? f->key.high_ip6 : (const uint8_t *)&f->key.high_ip;
    size_t al = v6 ? 16 : 4;
    int cl = f->init_low;
    memcpy(t->src, cl ? lo : hi, al);
    memcpy(t->dst, cl ? hi : lo, al);
    memcpy(t->sport_be, cl ? (const void *)&f->key.low_port : (const void *)&f->key.high_port, 2);
    memcpy(t->dport_be, cl ? (const void *)&f->key.high_port : (const void *)&f->key.low_port, 2);
}

struct ct_ctx {
    d2k_session *s;
    uint64_t now_ns;
    size_t told;
};

/* ---- поздняя доставка (этап 17): кортеж по адресу/порту и флаг ---------- */
static int tuple_key(const d2k_ct_tuple *t, d2k_key *k, int *src_low) {
    d2k_addr src, dst;
    memset(&src, 0, sizeof src); memset(&dst, 0, sizeof dst);
    src.family = dst.family = t->family;
    memcpy(src.bytes, t->src, t->family == 6 ? 16 : 4);
    memcpy(dst.bytes, t->dst, t->family == 6 ? 16 : 4);
    int sl = d2k_key_make_addr(k, t->proto, &src, &dst, t->sport_be, t->dport_be);
    if (sl < 0) { return -1; }
    if (src_low) { *src_low = sl; }
    return 0;
}

struct tuple_find {
    uint8_t family;
    uint16_t port_be;
    uint8_t ip[16];
    d2k_ct_tuple *out;
    int found;
};

static void tuple_find_one(void *ctx, d2k_flow *f) {
    struct tuple_find *c = ctx;
    /* Ключ IPv4 несёт family 0 (d2k_key_make), IPv6 — 6: сравниваем как flow_tuple. */
    if (c->found || f->key.proto != 6 || !f->dir_known ||
        (f->key.family == 6 ? 6 : 4) != c->family) { return; }
    int v6 = c->family == 6;
    size_t al = v6 ? 16 : 4;
    const uint8_t *lo = v6 ? f->key.low_ip6 : (const uint8_t *)&f->key.low_ip;
    const uint8_t *hi = v6 ? f->key.high_ip6 : (const uint8_t *)&f->key.high_ip;
    /* Порт клиента — на стороне, начавшей поток; сервер — другая сторона. */
    uint16_t cport = f->init_low ? f->key.low_port : f->key.high_port;
    const uint8_t *sip = f->init_low ? hi : lo;
    if (cport != c->port_be || memcmp(sip, c->ip, al) != 0) { return; }
    flow_tuple(f, c->out);
    c->found = 1;
}

int d2k_session_tcp_tuple_by_port(d2k_session *s, const uint8_t *ip_text, size_t len,
                                  uint8_t family, uint16_t client_port_be, d2k_ct_tuple *out) {
    if (!s || !ip_text || !out || !client_port_be || len == 0 || len >= 64 ||
        (family != 4 && family != 6)) { return -1; }
    char txt[64];
    memcpy(txt, ip_text, len); txt[len] = '\0';
    struct tuple_find c;
    memset(&c, 0, sizeof c);
    c.family = family; c.port_be = client_port_be; c.out = out;
    if (inet_pton(family == 6 ? AF_INET6 : AF_INET, txt, c.ip) != 1) { return -1; }
    d2k_track_walk(s->flows, tuple_find_one, &c);
    return c.found ? 0 : -1;
}

int d2k_session_raw_identity(d2k_session *s,const d2k_ct_tuple *t,
                             uint8_t epoch[16],uint64_t *generation,int *previous_reply) {
    if (!s || !t || !epoch || !generation || !previous_reply ||
        (t->family!=4 && t->family!=6) || (t->proto!=6 && t->proto!=17)) return -1;
    if (t->family==4) {
        for (unsigned i=4;i<16;i++) if (t->src[i] || t->dst[i]) return -1;
    }
    d2k_key k;int src_low;
    if (tuple_key(t,&k,&src_low)) return -1;
    d2k_flow *fl=d2k_track_find(t->proto==6?s->flows:s->uflows,&k);
    if (!fl || !fl->dir_known || fl->init_low!=src_low || !fl->incarnation ||
        fl->controller_probe || fl->routed || fl->damaged || fl->pending_fin || fl->saw_rev_rst ||
        fl->saw_hello || fl->saw_initial || fl->http_conn || fl->stun_txid_valid || fl->voice_ssrc_valid ||
        (fl->client_shape && fl->client_shape!=D2K_PLAN_SHAPE_RAW) || (t->proto==6 && !fl->raw_seen)) return -1;
    uint8_t any=0;for (unsigned i=0;i<16;i++) any|=fl->flow_epoch[i];
    if (!any) return -1;
    memcpy(epoch,fl->flow_epoch,16);*generation=fl->incarnation;
    /* rev_pkts is lifetime accounting and survives a new TCP SYN. The
     * TCP data counter and conntrack observation reset at that boundary. */
    *previous_reply=((t->proto==6 ? fl->rev_data_pkts : fl->rev_pkts)!=0 ||
                     (fl->ct_known && fl->ct_reply!=0));
    return 0;
}

int d2k_session_late_watch(d2k_session *s, const d2k_ct_tuple *t, int on) {
    if (!s || !t || (t->proto != 6 && t->proto != 17)) { return -1; }
    d2k_key k;
    if (tuple_key(t, &k, NULL) != 0) { return -1; }
    d2k_flow *fl = d2k_track_find(t->proto == 6 ? s->flows : s->uflows, &k);
    if (!fl) { return -1; }
    fl->late_watch = on ? 1 : 0;
    return 0;
}

void d2k_session_note_lateobs(d2k_session *s, const d2k_ct_tuple *t, uint8_t code,
                              uint32_t repeats, const uint8_t token[D2K_TRIAL_ID_LEN], uint64_t now_ns) {
    d2k_key k;
    int src_low = 0;
    if (!s || !t || tuple_key(t, &k, &src_low) != 0) { return; }
    d2k_jrn_detail det;
    memset(&det, 0, sizeof det);
    det.client_side = src_low ? D2K_CLIENT_SIDE_LOW : D2K_CLIENT_SIDE_HIGH;
    d2k_journal_add_lateobs(s->jrn, now_ns, &k, code, repeats, &det, token);
}

uint64_t d2k_session_late_delivered(const d2k_session *s) {
    return s ? s->late_delivered : 0;
}

/* Один запрос ядру на наблюдаемый поток (раунд 3: не чтение всей таблицы).
   Нет ответа — не знаем, и подозрения нет. */
static void ct_flow(void *ctx, d2k_flow *f) {
    struct ct_ctx *c = ctx;
    if (!quic_watch(f)) { return; }
    d2k_ct_tuple t;
    flow_tuple(f, &t);
    d2k_ct_info ci;
    memset(&ci, 0, sizeof ci);
    if (c->s->ct_query(c->s->ct_query_ctx, &t, &ci) != 0) { return; }
    uint64_t orig = ci.orig_pkts, reply = ci.reply_pkts;
    if (!f->ct_known || reply != f->ct_reply) {
        f->ct_known = 1;
        f->ct_reply = reply;
        f->ct_reply_ns = c->now_ns;
        f->ct_orig_mark = orig;
        /* Сервер говорит — поток жив. Очередь видит первые датаграммы, и
           без этого запись истекала через idle после ПОСЛЕДНЕГО ПАКЕТА В
           ОЧЕРЕДИ: долгое вещание забывалось на третьей минуте, а его
           обрыв позже не замечал никто (очередь 28.10, задание 05). Улика
           та же, что у пакета в очереди, — ответ оттуда; молчащий сервер
           запись не продлевает, и забвение наступает штатно. */
        f->last_ns = c->now_ns;
        return;
    }
    if (reply <= f->rev_pkts || orig < f->ct_orig_mark || orig - f->ct_orig_mark < 3) {
        return;
    }
    uint64_t pto = 3 * f->quic_rtt_ns;
    if (pto < NS_PER_S) { pto = NS_PER_S; }
    if (c->now_ns < f->ct_reply_ns || c->now_ns - f->ct_reply_ns < pto) { return; }
    c->told++;
    suspect(c->s, c->now_ns, &f->key, f, D2K_SUSPECT_QUIC_STALL, NULL);
}

/* TCP ВСТАЛ НА БЮДЖЕТЕ КОРОБКИ (задача 56; поле 04.10, Safari: mailsuite.com
 * на AWS и www.romfea.gr на Cloudflare). Коробка режет поток после ~25
 * пакетов с данными обеих сторон (task-55-facts §1.2), сервер замолкает
 * насовсем — без RST и FIN. curl через 40 с закрывает FIN-ом, и это ловит
 * повтор FIN (задача 50); Safari держит соединение открытым, и до сих пор не
 * говорилось ничего. Очередь видит лишь первые пакеты каждой стороны, дальше —
 * счётчики conntrack по кортежу (ctnetlink, как у QUIC).
 *
 * Кандидат: поток с именем из приветствия, сервер прислал данные после
 * приветствия, клиент не закрывал (нет ждущего FIN), не зонд, подозрения не
 * было, запись жива (молодой поток: запись истекает через 120 с после
 * последнего пакета в очереди). Подозрение, когда ВСЁ сразу:
 *   - обратный счётчик ушёл за то, что видела очередь (сервер шёл дальше
 *     окна — иначе это молчание рукопожатия, у него SILENT);
 *   - обратный счётчик стоит не меньше RTO: 3 RTT рукопожатия (RFC 6298
 *     §2.2), не меньше 2 с. Сервер с данными в полёте за это время повторил
 *     бы их; медленный сервер, ответивший раньше, — не обрыв;
 *   - ядро говорит, что соединение ESTABLISHED (закрытие — дело детекторов
 *     закрытия); не сказало — не знаем, подозрения нет;
 *   - за это время клиент послал не меньше ТРЁХ пакетов, и ни один не получил
 *     ответа (как у QUIC: два без ответа законны, третий — в тишину). Пока
 *     клиент молчит, обрыв от простоя не отличить ничем — подозрение ждёт
 *     его следующего слова;
 *   - пакетов с данными обеих сторон к началу тишины — в полосе бюджета
 *     коробки (D2K_TCP_STALL_SLACK вокруг любого из бюджетов, по умолчанию
 *     полевые 25). ЭТО и отличает обрыв от keep-alive после полного ответа:
 *     простаивает соединение на любом числе пакетов, обрыв — на бюджете.
 * Оценка пакетов с данными: точные числа из окна очереди (обе стороны) плюс
 * пакеты сервера за окном по conntrack. Пакеты клиента за окном почти все —
 * чистые ACK и не считаются; чистые ACK сервера за окном считаются данными.
 * Ошибки противоположны и малы: mailsuite 24 против 26 на проводе, romfea 25
 * против 25. Поток выше полосы больше не спрашивается: число пакетов только
 * растёт. Это подозрение, не диагноз: контроллер требует второй поток имени и
 * RX-пару identity/gzip, прежде чем что-то подбирать. */
enum { TCP_WATCH_PAST_BUDGET = 1, TCP_WATCH_CLOSED = 2 };

static int tcp_watch(const d2k_flow *f) {
    return f->key.proto == 6 && f->saw_hello && f->had_sni &&
           f->rev_payload_after_hello > 0 && !f->suspected && !f->controller_probe &&
           !f->pending_fin && !f->tcp_watch_off && !f->routed;
}

static int tcp_in_band(const d2k_session *s, uint64_t est) {
    for (size_t i = 0; i < s->n_stall_budget; i++) {
        uint64_t b = s->stall_budget[i];
        if (est + D2K_TCP_STALL_SLACK >= b && est <= b + D2K_TCP_STALL_SLACK) { return 1; }
    }
    return 0;
}

static uint64_t tcp_band_top(const d2k_session *s) {
    uint64_t top = 0;
    for (size_t i = 0; i < s->n_stall_budget; i++) {
        if (s->stall_budget[i] > top) { top = s->stall_budget[i]; }
    }
    return top + D2K_TCP_STALL_SLACK;
}

static void ct_tcp_flow(void *ctx, d2k_flow *f) {
    struct ct_ctx *c = ctx;
    if (!tcp_watch(f)) { return; }
    d2k_ct_tuple t;
    flow_tuple(f, &t);
    d2k_ct_info ci;
    memset(&ci, 0, sizeof ci);
    if (c->s->ct_query(c->s->ct_query_ctx, &t, &ci) != 0) { return; }
    if (!ci.tcp_state_known) { return; }
    if (ci.tcp_state != D2K_CT_TCP_ESTABLISHED) {
        /* SYN_SENT/SYN_RECV (0..2) сюда не доходят: у потока уже есть данные
           сервера. Всё дальше ESTABLISHED — закрытие. */
        f->tcp_watch_off = TCP_WATCH_CLOSED;
        return;
    }
    const uint64_t reply = ci.reply_pkts;
    const uint64_t unseen = reply > f->rev_pkts_conn ? reply - f->rev_pkts_conn : 0;
    const uint64_t est = (uint64_t)f->fwd_data_pkts + f->rev_data_pkts + unseen;
    if (est > tcp_band_top(c->s)) {
        f->tcp_watch_off = TCP_WATCH_PAST_BUDGET;
        return;
    }
    if (!f->ct_known || reply != f->ct_reply) {
        f->ct_known = 1;
        f->ct_reply = reply;
        f->ct_reply_ns = c->now_ns;
        f->ct_orig_mark = ci.orig_pkts;
        return;
    }
    if (unseen == 0) { return; }
    /* Клиент говорит в тишину: с тех пор как обратный счётчик встал, от
       клиента ушло не меньше трёх пакетов, и ни на один не пришло ничего.
       Без ответа законно остаются два — ACK последних данных и обновление
       окна; живой сервер на данные клиента (новый запрос, PING HTTP/2)
       ответил бы хотя бы ACK. Замер 04.10 на роутере (отчёт задачи 56):
       без этого условия полоса дала 21 подозрение за 9 минут, из них у 15
       сервер потом говорил (keep-alive после полного ответа на 22–28
       пакетах); с ним — 4, и у всех четырёх сервер молчал до конца. */
    if (ci.orig_pkts < f->ct_orig_mark || ci.orig_pkts - f->ct_orig_mark < 3) { return; }
    uint64_t rto = 3 * f->rtt_ns;
    if (rto < 2 * NS_PER_S) { rto = 2 * NS_PER_S; }
    if (c->now_ns < f->ct_reply_ns || c->now_ns - f->ct_reply_ns < rto) { return; }
    if (!tcp_in_band(c->s, est)) { return; }
    c->told++;
    d2k_jrn_detail det;
    memset(&det, 0, sizeof det);
    det.server_hello = f->rev_server_hello;
    suspect_num(c->s, c->now_ns, &f->key, f, D2K_SUSPECT_TCP_STALL, &det,
                est > UINT16_MAX ? UINT16_MAX : (uint32_t)est);
}

static void tcp_rearm_budget(void *ctx, d2k_flow *f) {
    (void)ctx;
    if (f->tcp_watch_off == TCP_WATCH_PAST_BUDGET) {
        f->tcp_watch_off = 0;
        /* Counters accumulated while suspended are not a new observation. */
        f->ct_known = 0;
    }
}

int d2k_session_set_stall_budgets(d2k_session *s, const uint16_t *b, size_t n) {
    if (!s || n > D2K_STALL_BUDGETS_MAX || (n && !b)) { return -1; }
    for (size_t i = 0; i < n; i++) {
        if (b[i] == 0) { return -1; }
    }
    const uint16_t fallback = D2K_TCP_STALL_FIELD_BUDGET;
    if (n == 0) { b = &fallback; n = 1; }
    if (s->n_stall_budget == n && !memcmp(s->stall_budget, b, n * sizeof *b))
        return 0;
    memcpy(s->stall_budget, b, n * sizeof *b);
    s->n_stall_budget = n;
    d2k_track_walk(s->flows, tcp_rearm_budget, NULL);
    return 0;
}

size_t d2k_session_stall_budgets(const d2k_session *s, uint16_t *out, size_t cap) {
    if (!s) { return 0; }
    for (size_t i = 0; out && i < s->n_stall_budget && i < cap; i++) {
        out[i] = s->stall_budget[i];
    }
    return s->n_stall_budget;
}

int d2k_session_adopt(d2k_session *s, const d2k_ct_tuple *t, const d2k_ct_info *i, uint64_t now_ns) {
    if (!s || !t || (t->family != 4 && t->family != 6) || (t->proto != 6 && t->proto != 17)) return -1;
    d2k_addr src, dst;
    memset(&src, 0, sizeof src); memset(&dst, 0, sizeof dst);
    src.family = dst.family = t->family;
    memcpy(src.bytes, t->src, t->family == 6 ? 16 : 4);
    memcpy(dst.bytes, t->dst, t->family == 6 ? 16 : 4);
    d2k_key key;
    /* Возврат — «источник младшая сторона» (1/0) либо -1; раньше здесь стояло
       «!= 0», и клиент с младшим адресом не принимался вовсе (этап 17). */
    if (d2k_key_make_addr(&key, t->proto, &src, &dst, t->sport_be, t->dport_be) < 0) return -1;
    d2k_table *tab = t->proto == 6 ? s->flows : s->uflows;
    d2k_flow *fl = d2k_track_get(tab, &key, now_ns);
    if (!fl) return -1;
    if (fl->adopted || fl->saw_hello || fl->saw_initial || fl->fwd_pkts || fl->rev_pkts) return 0; /* уже наблюдается */
    fl->adopted = 1;
    fl->dir_known = 1;
    int src_is_low = key.family == 6 ? memcmp(key.low_ip6, t->src, 16) == 0
                                     : memcmp(&key.low_ip, t->src, 4) == 0;
    uint16_t sp; memcpy(&sp, t->sport_be, 2);
    fl->init_low = src_is_low && key.low_port == sp;
    fl->client_shape = D2K_PLAN_SHAPE_RAW;
    fl->ct_known = 1;
    fl->ct_reply = i ? i->reply_pkts : 0;
    fl->ct_orig_mark = i ? i->orig_pkts : 0;
    fl->ct_reply_ns = now_ns;
    if (t->proto == 6) { fl->saw_syn = 1; fl->saw_synack = fl->ct_reply > 0; }
    s->adopted++;
    return 0;
}

/* ПРИНЯТЫЙ ПОТОК — ТОЛЬКО СЧЁТЧИКИ (этап 13). Улики те же, что у QUIC_STALL:
   сервер уже отвечал (обратный счётчик > 0), обратный счётчик встал не меньше
   срока, а клиент за это время послал не меньше трёх пакетов. Пока клиент
   молчит — простой, не обрыв. TCP не в ESTABLISHED — закрытие, не молчание.
   Ответ сервера продлевает запись (как у наблюдаемого QUIC). */
static void ct_adopted_flow(void *ctx, d2k_flow *f) {
    struct ct_ctx *c = ctx;
    if (!f->adopted || f->suspected || f->silence_told || f->controller_probe) { return; }
    d2k_ct_tuple t;
    flow_tuple(f, &t);
    d2k_ct_info ci;
    memset(&ci, 0, sizeof ci);
    if (c->s->ct_query(c->s->ct_query_ctx, &t, &ci) != 0) { return; }
    if (f->key.proto == 6 && ci.tcp_state_known && ci.tcp_state != D2K_CT_TCP_ESTABLISHED) {
        f->silence_told = 1; /* закрывается — наблюдать нечего */
        return;
    }
    if (!f->ct_known || ci.reply_pkts != f->ct_reply) {
        f->ct_known = 1;
        f->ct_reply = ci.reply_pkts;
        f->ct_reply_ns = c->now_ns;
        f->ct_orig_mark = ci.orig_pkts;
        f->last_ns = c->now_ns;
        return;
    }
    if (f->ct_reply == 0) { return; } /* сервер никогда не отвечал — ломаться нечему, unknown */
    if (ci.orig_pkts < f->ct_orig_mark || ci.orig_pkts - f->ct_orig_mark < 3) { return; }
    if (c->now_ns < f->ct_reply_ns || c->now_ns - f->ct_reply_ns < silence_deadline(f)) { return; }
    f->silence_told = 1;
    c->told++;
    suspect(c->s, c->now_ns, &f->key, f, D2K_SUSPECT_SILENT, NULL);
}

size_t d2k_session_sweep(d2k_session *s, uint64_t now_ns) {
    if (!s) {
        return 0;
    }
    struct sweep_ctx c = { s, now_ns, 0 };
    d2k_track_walk(s->flows, sweep_one, &c);
    d2k_track_walk(s->uflows, sweep_udp_one, &c);
    /* Счётчики — только наблюдаемых потоков, по одному запросу ядру на
       поток (ctnetlink по кортежу, ~10 мкс на роутере). Нет наблюдаемых —
       ни одного запроса. */
    if (s->ct_query) {
        struct ct_ctx cc = { s, now_ns, 0 };
        d2k_track_walk(s->uflows, ct_flow, &cc);
        d2k_track_walk(s->flows, ct_tcp_flow, &cc);
        d2k_track_walk(s->uflows, ct_adopted_flow, &cc);
        d2k_track_walk(s->flows, ct_adopted_flow, &cc);
        c.told += cc.told;
    }
    return c.told;
}

size_t d2k_session_expire(d2k_session *s, uint64_t now_ns, uint64_t idle_ns) {
    if (!s) {
        return 0;
    }
    /* Ровно требование задачи 4: «таблице нужна чистка, иначе она растёт без
       границ» — тем же способом, что и у TCP, не своим: d2k_track_expire уже
       обходит ВСЕ живые записи своей таблицы и снимает молчавшие дольше
       idle_ns, и он не заботится о том, что лежит в d2k_flow — вызов для
       s->uflows отличается только отсутствием колбэка — и НЕ потому, что для
       UDP наблюдения «приветствие было, ответа не было» нет: оно есть, его
       делает sweep_udp_one, и делает по своему критерию (повтор Initial
       клиентом + видимая обратная сторона). Забвение же наступает через
       минуты, когда спрашивать давно поздно, а критерия у него своего нет:
       объявить молчанием всякий забытый UDP-поток с приветствием значило бы
       обойти условие про повтор через заднюю дверь. NULL как on_expire —
       штатный случай самого d2k_track_expire. */
    /* Записи после FIN клиента — по своему окну (fin_retry_window), не по
       молчанию: ответ у них был, и on_flow_expire им сказать нечего. */
    size_t freed = d2k_track_remove_if(s->flows, fin_window_over, &now_ns);
    freed += d2k_track_expire(s->flows, now_ns, idle_ns, on_flow_expire, s);
    freed += d2k_track_expire(s->uflows, now_ns, idle_ns, NULL, s);
    return freed;
}

size_t d2k_session_flows(const d2k_session *s) {
    return s ? d2k_track_count(s->flows) + d2k_track_count(s->uflows) : 0;
}

int d2k_session_send_pending(d2k_session *s, const d2k_key *k, uint64_t execution) {
    if (!s || !k || execution == 0) { return 0; }
    d2k_flow *fl = d2k_track_find(table_of(s, k), k);
    return fl && fl->execution_id == execution && fl->sends_left && !fl->sends_failed;
}

void d2k_session_sent(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                       uint64_t execution) {
    if (!s || !k) {
        return;
    }
    d2k_flow *fl = d2k_track_find(table_of(s, k), k);
    /* Потока нет (забыт по RST/FIN/молчанию) либо машине по нему ничего не
       должны — объявлять нечего. Молчание здесь честнее выдумки: «доисполнен»
       по потоку, которого уже нет, мы доказать не можем. */
    if (!fl || execution == 0 || fl->execution_id != execution || fl->sends_left == 0) {
        s->sent_lost++;
        return;
    }
    fl->sends_left--;
    if (fl->sends_done < 0xFF) { fl->sends_done++; }
    if (fl->sends_left == 0 && !fl->sends_failed) {
        if(fl->stream_plan_stage==1) {
            fl->stream_plan_stage=2;
            return;
        }
        if(fl->stream_plan_stage==3) {
            fl->stream_plan_stage=4;
        } else if(fl->stream_plan_stage==5) {
            fl->stream_plan_stage=4;
            return;
        }
        s->done++;
        d2k_journal_add_fate_bound(s->jrn, at_ns, k, D2K_JRN_PLAN_DONE,
                             D2K_REFUSE_NONE, fl->execution_plan_id,
                             fl->execution_trial_id, fl->execution_id, &fl->execution_binding);
    }
}

/* ОБЩИЙ ИСХОД ОТКАЗА ИСПОЛНЕНИЯ — один на все ветки: немедленная посылка,
   очередь, вердикт, созревшая отложенная.
   Раньше у каждой был свой кусок логики, и совпадали они только там, где
   кто-то не забыл: учёт повреждения стоял ровно в одной ветке из пяти, а
   обещание «оригинал пройдёт» не выполнялось нигде.

   payload_on_wire — хоть один кусок НАГРУЗКИ уже покинул машину.
   orig_spent — оригиналом уже распорядились (вердикт ушёл ядру), отпускать
   нечего.

   Возвращает 1, если оригинал ещё наш и обязан уйти нетронутым; 0 — чистого
   выхода нет. Чистый выход существует ровно в одном случае: ни один кусок
   нагрузки не ушёл И вердикт ещё не отправлен. Тогда воздействия для клиента
   не было, поток цел, и снимать оригинал значило бы оборвать человеку
   соединение из-за нашей внутренней причины (§4.1).

   Ушедшая нагрузка чистого выхода не оставляет: отпустить оригинал — послать
   те же байты дважды, не отпустить — потерять остаток. Восстановление здесь
   дело ретрансмиссии клиента; сами оригинал не переиздаём, байт у нас нет. */
int d2k_session_exec_failed(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                            const uint8_t *plan_id, uint8_t code,
                            uint64_t execution, int payload_on_wire, int orig_spent) {
    if (!s || !k) { return 1; }
    d2k_flow *fl = d2k_track_find(table_of(s, k), k);
    if (!fl || execution == 0 || fl->execution_id != execution) {
        /* Поток забыт или поколение чужое: старый отказ не относится к тому,
           что происходит сейчас, и портить им новую попытку нельзя. */
        return 1;
    }
    /* Запись об отказе — ОДНА на попытку. «Ошибка посылки, затем ошибка
       вердикта» это один несостоявшийся опыт, а не два. */
    if (!fl->sends_failed) {
        d2k_session_unsent(s, at_ns, k, plan_id, code, execution);
    }
    /* UDP: ОРИГИНАЛ ПОТЕРЯН — НЕ ПОТОК ИСПОРЧЕН (задача 42).
       Нагрузка не ушла, а оригинала больше нет: либо его копию сняли вердиктом
       DROP, а наша посылка с ним не ушла, либо его отпустят ядру ПОСЛЕ уже
       ушедших сырых фальшивок — и conntrack снимет его как дубль их записи.
       Байты не разорваны: датаграмма атомарна, клиент повторит Initial
       целиком, и этот повтор получает план. Отказ до единой посылки сюда не
       относится: тогда гонки не было, и оригинал уходит ядром как обычно. */
    if (k->proto == 17 && !payload_on_wire) {
        int lost = orig_spent ? fl->orig_taken : fl->sends_done > 0;
        if (lost) { fl->udp_replan = 1; }
        return (orig_spent && fl->orig_taken) ? 0 : 1;
    }
    if (payload_on_wire || (orig_spent && fl->orig_taken)) {
        if (!fl->damaged) { s->damaged_flows++; }
        fl->damaged = 1;
        /* ЗАЩИТЫ СНИМАЮТСЯ ВМЕСТЕ С ПЛАНОМ.
           Защита RST_ALIEN держит соединение живым, снимая подделанный сброс.
           На ЦЕЛОМ потоке это помощь: настоящий сервер продолжает отвечать.
           На испорченном — вред: поток уже не восстановится (байты либо ушли
           дважды, либо потерялись), и удерживать его живым значит заставлять
           человека ждать таймаута вместо быстрой переустановки соединения
           клиентом. Защита была частью плана; плана на этом потоке больше
           нет — нет и защиты. */
        fl->guards = 0;
        /* СООБЩАЕМ В МОМЕНТ УСТАНОВЛЕНИЯ, а не при следующем пакете:
           испорченный поток вполне может замолчать, и тогда факта не будет
           вовсе. Один раз на попытку — события лосси по контракту. */
        if (!fl->damaged_told) {
            fl->damaged_told = 1;
            d2k_journal_add_fate_bound(s->jrn, at_ns, k, D2K_JRN_PLAN_DAMAGED,
                                 D2K_REFUSE_DAMAGED,
                                 plan_id ? plan_id : fl->execution_plan_id,
                                 fl->execution_trial_id, fl->execution_id, &fl->execution_binding);
        }
        return 0;
    }
    return 1;
}

uint8_t d2k_session_guards(const d2k_session *s, const d2k_key *k) {
    if (!s || !k) { return 0; }
    d2k_flow *fl = d2k_track_find(table_of((d2k_session *)s, k), k);
    return fl ? fl->guards : 0;
}

uint8_t d2k_session_client_shape(const d2k_session *s, const d2k_key *k) {
    if (!s || !k) return 0;
    d2k_flow *fl = d2k_track_find(table_of((d2k_session *)s, k), k);
    return fl ? fl->client_shape : 0;
}

void d2k_session_damaged(d2k_session *s, const d2k_key *k, uint64_t execution) {
    if (!s || !k || execution == 0) {
        return;
    }
    d2k_flow *fl = d2k_track_find(table_of(s, k), k);
    if (fl && fl->execution_id == execution) {
        fl->damaged = 1;
    }
}

void d2k_session_unsent(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                        const uint8_t *plan_id, uint8_t code, uint64_t execution) {
    if (!s || !k) {
        return;
    }
    /* Устаревший отказ не относится к новой попытке с тем же ключом. */
    d2k_flow *fl = d2k_track_find(table_of(s, k), k);
    if (fl && execution != 0 && fl->execution_id == execution) {
        d2k_journal_add_fate_bound(s->jrn, at_ns, k, D2K_JRN_PLAN_UNSENT, code,
                             plan_id ? plan_id : fl->execution_plan_id,
                             fl->execution_trial_id, fl->execution_id, &fl->execution_binding);
        fl->sends_left = 0;
        fl->sends_failed = 1;
        fl->stream_plan_pending=0;fl->stream_plan_stage=0;
    }
}

uint64_t d2k_session_applied(const d2k_session *s) {
    return s ? s->applied : 0;
}

uint64_t d2k_session_done(const d2k_session *s) {
    return s ? s->done : 0;
}

uint64_t d2k_session_damaged_count(const d2k_session *s) {
    return s ? s->damaged_flows : 0;
}

uint64_t d2k_session_sent_lost(const d2k_session *s) {
    return s ? s->sent_lost : 0;
}

uint64_t d2k_session_refusals(const d2k_session *s) {
    return s ? d2k_track_refusals(s->flows) + d2k_track_refusals(s->uflows) : 0;
}

size_t d2k_session_capacity(const d2k_session *s) {
    return s ? d2k_track_capacity(s->flows) + d2k_track_capacity(s->uflows) : 0;
}

size_t d2k_session_flows_tcp(const d2k_session *s) {
    return s ? d2k_track_count(s->flows) : 0;
}

size_t d2k_session_flows_udp(const d2k_session *s) {
    return s ? d2k_track_count(s->uflows) : 0;
}

size_t d2k_session_capacity_tcp(const d2k_session *s) {
    return s ? d2k_track_capacity(s->flows) : 0;
}

size_t d2k_session_capacity_udp(const d2k_session *s) {
    return s ? d2k_track_capacity(s->uflows) : 0;
}

uint64_t d2k_session_refusals_tcp(const d2k_session *s) {
    return s ? d2k_track_refusals(s->flows) : 0;
}

uint64_t d2k_session_refusals_udp(const d2k_session *s) {
    return s ? d2k_track_refusals(s->uflows) : 0;
}

uint64_t d2k_session_hellos(const d2k_session *s) {
    return s ? s->hellos : 0;
}

uint64_t d2k_session_with_sni(const d2k_session *s) {
    return s ? s->with_sni : 0;
}

uint64_t d2k_session_suspects(const d2k_session *s) {
    return s ? s->suspects : 0;
}

uint64_t d2k_session_rst_dropped(const d2k_session *s) {
    return s ? s->rst_dropped : 0;
}

uint64_t d2k_session_exchanges(const d2k_session *s) {
    return s ? s->exchanges : 0;
}

uint64_t d2k_session_reply_hidden(const d2k_session *s) {
    return s ? s->reply_hidden : 0;
}

uint64_t d2k_session_tcp_hello_flows(const d2k_session *s) {
    return s ? s->tcp_hello_flows : 0;
}

void d2k_session_payload_stats(const d2k_session *s, d2k_payload_stats *out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof *out);
    if (!s) {
        return;
    }
    out->reverse = s->pay_reverse;
    out->after_hello = s->pay_after_hello;
    out->late = s->pay_late;
    out->not_hello = s->pay_not_hello;
    out->last_first_byte = s->last_nonhello_first;
    out->sni_next_seg = s->sni_in_next_seg;
    out->capture_complete = s->captured_hellos;
    out->capture_rejected = s->capture.rejected;
    out->capture_expired = s->capture.expired;
    out->capture_full = s->capture.full;
    out->http_later = s->http_later;
    out->http_unaligned = s->http_unaligned;
    out->http_open_end = s->http_open_end;
    out->flow_told = s->flow_told;
    out->flow_suppressed = s->flow_suppressed;
}

const d2k_journal *d2k_session_journal(const d2k_session *s) {
    return s ? s->jrn : NULL;
}
