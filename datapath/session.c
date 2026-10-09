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

#include "d2k_plans.h"
#include "d2k_packet.h"
#include "d2k_quic.h" /* core/ — разбор QUIC линкуется исходниками, см. Makefile */
#include "d2k_nat.h"
#include "d2k_session.h"
#include "d2k_http80.h"
#include "d2k_time.h"
#include "d2k_tls.h"
#include "d2k_capture.h"
#include "d2k_hold.h"
#include "d2k_ipfrag.h"

/* Сколько первых пакетов потока имеет смысл разбирать в поисках приветствия.
 * ClientHello приходит первым или почти первым; после этого разбор — чистая
 * трата на каждом пакете загрузки. */
#define D2K_HELLO_WINDOW 8

struct d2k_session {
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
    uint64_t     pay_not_hello;    /* разобрали и это не приветствие */
    uint8_t      last_nonhello_first;
    /* Открытый HTTP, keep-alive: см. d2k_payload_stats. */
    uint64_t     http_later, http_unaligned, http_open_end;
    uint64_t     sni_in_next_seg;
    uint64_t     captured_hellos;

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
    uint8_t  last_hello[4][2048];
    size_t   last_hello_len[4];
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
    void *ct_query_ctx;
    /* Бюджеты потока коробок (задача 56, D2K_CMD_SET_STALL_BUDGETS); по
       умолчанию — один полевой D2K_TCP_STALL_FIELD_BUDGET. */
    uint16_t stall_budget[D2K_STALL_BUDGETS_MAX];
    size_t   n_stall_budget;

    int      shape_armed[4];
    uint8_t  shape_name[4][256];
    size_t   shape_name_len[4];
    uint8_t  shape[4][2048];
    size_t   shape_len[4];
};

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
    d2k_plantab_free(s->plans);
    d2k_journal_free(s->jrn);
    d2k_track_free(s->uflows);
    d2k_track_free(s->flows);
    d2k_plan_free(s->plan);
    free(s);
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

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

/* Отказ по плану в журнал. Отдельной функцией, чтобы каждая точка отказа
   писала одинаково: журнал, в котором половина отказов не отмечена, хуже
   отсутствующего — он выглядит полным. */
static void refuse(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                   const char *why) {
    d2k_flow *fl = k ? d2k_track_find(k->proto == 17 ? s->uflows : s->flows, k)
                     : NULL;
    if (fl && fl->controller_probe) { return; }
    d2k_journal_add(s->jrn, at_ns, k, D2K_JRN_PLAN_REFUSED, 0, 0, NULL, NULL, 0, why);
}

/* План построен и передан на отправку. Ключ потока и идентификатор плана
   уезжают вызывающему, а на потоке взводится счёт непокинувших машину
   посылок: по нему отправляющий и скажет потом, доисполнен план или нет.

   Одна функция на обе ветки (TCP и UDP/QUIC) нарочно: разойдись они, одна из
   двух однажды забыла бы взвести счёт, и «план доисполнен» по этому
   транспорту перестало бы появляться молча. */
static void plan_handed_off(d2k_session *s, d2k_result *out, d2k_flow *fl, const d2k_key *k,
                            const d2k_plan *use, const uint8_t *trial_id) {
    out->applied = 1;
    out->key = *k;
    const uint8_t *id = d2k_plan_id(use);
    if (id) {
        memcpy(out->plan_id, id, D2K_PLAN_ID_LEN);
    }
    if (trial_id) { memcpy(out->trial_id, trial_id, D2K_TRIAL_ID_LEN); }
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
    fl->udp_replan = 0;
    if (++s->next_execution == 0) { ++s->next_execution; }
    out->execution_id = fl->execution_id = s->next_execution;
    memcpy(fl->execution_plan_id, out->plan_id, D2K_PLAN_ID_LEN);
    memcpy(fl->execution_trial_id, out->trial_id, D2K_TRIAL_ID_LEN);
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
    /* The controller may have restarted or evicted its name ring since the
     * startup packet. Replay only the class actually observed on this flow;
     * this is context delivery, not another counted client hello. */
    if(k->proto==17 && fl->had_sni && (fl->voice_ssrc_valid || fl->stun_txid_valid))
        d2k_journal_add(s->jrn,at_ns,k,D2K_JRN_HELLO_SNI,0,0,NULL,
                        (const uint8_t *)D2K_VOICE_CLASS,strlen(D2K_VOICE_CLASS),NULL);
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
    d2k_journal_add(s->jrn, at_ns, k, D2K_JRN_SUSPECT, code, num, &d, NULL, 0, NULL);
}

static void suspect(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                    d2k_flow *fl, uint8_t code, const d2k_jrn_detail *det) {
    suspect_num(s, at_ns, k, fl, code, det, 0);
}

/* Зовётся при забвении потока по молчанию. Приветствие ушло, ответа с той
   стороны не было ни одного — и узнать это можно только здесь, в конце. */
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
    return 1;
}

static int is_stun_request(const uint8_t *d, size_t n) {
    return is_stun_binding(d, n, 0x0001);
}

static int is_stun_response_for(const uint8_t *d, size_t n,
                                const uint8_t txid[12]) {
    return txid && is_stun_binding(d, n, 0x0101) &&
           memcmp(d + 8, txid, 12) == 0;
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

/* RTP header observation only; encrypted payload never proves audible audio.
 * Diagnostic STUN/Discovery datagrams do not have this framing. */
static void voice_media_sample(d2k_session *s, d2k_flow *f, const d2k_key *key,
                               const uint8_t *p, size_t n, int client, uint64_t now_ns) {
    if (f->controller_probe || (!f->voice_ssrc_valid && !f->stun_txid_valid) ||
        n < 12 || (p[0] & 0xc0) != 0x80 || 12u + 4u*(p[0]&15u) > n ||
        (p[1] >= 192 && p[1] <= 223)) return;
    f->voice_media_dirs |= client ? 1 : 2;
    if (f->voice_media_dirs == 3 && !f->voice_media_told) {
        f->voice_media_told = 1;
        d2k_journal_add(s->jrn, now_ns, key, D2K_JRN_EXCHANGE,
                        D2K_UDP_OBS_MEDIA_FLOW, 0, NULL, NULL, 0, NULL);
    }
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
    if (from_client >= 0)
        voice_media_sample(s, fl, &key, pkt + payload_off, payload_len, from_client, now_ns);
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
            if (fl->stun_txid_valid) {
            }
            if (!fl->controller_probe && fl->voice_ssrc_valid &&
                is_discord_ip_discovery_response(pkt + payload_off, payload_len,
                                                 fl->voice_ssrc) &&
                !fl->voice_proof_told) {
                fl->voice_proof_told = 1;
                fl->exchange_told = 1;
                s->exchanges++;
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_EXCHANGE,
                                D2K_UDP_PROOF_VOICE_DISCOVERY,
                                (uint32_t)payload_len, NULL, NULL, 0, NULL);
            }
            if (!fl->controller_probe && fl->stun_txid_valid &&
                is_stun_response_for(pkt + payload_off, payload_len,
                                     fl->stun_txid) && !fl->stun_proof_told) {
                fl->stun_proof_told = 1;
                fl->exchange_told = 1;
                s->exchanges++;
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_EXCHANGE,
                                D2K_UDP_PROOF_STUN,
                                (uint32_t)payload_len, NULL, NULL, 0, NULL);
            }
            /* UDP EXCHANGE — только первая обратная датаграмма, один раз на
               поток. UDP допускает пустую нагрузку. Здесь не проверяются
               ни транзакция STUN, ни QUIC Initial, ни IP Discovery: событие
               не вправе подтверждать протокол/обход/работу приложения. */
            if (!fl->controller_probe && !fl->exchange_told) {
                fl->exchange_told = 1;
                s->exchanges++;
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_EXCHANGE,
                                D2K_UDP_PROOF_NONE,
                                (uint32_t)payload_len, NULL, NULL, 0, NULL);
            }
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

    /* Дальше — попытки разбора СОДЕРЖИМОГО. Направление уже доказано портом
       выше; счётчик попыток и окно поиска — про то, что Initial приходит в
       первых датаграммах клиентской стороны потока (сама датаграмма, её
       повтор, новый Initial после Retry), а дальше разбор ничего не найдёт
       и будет чистой тратой на каждом пакете загрузки. */
    int held_first_replay = fl->udp_hold_replay_first != 0;
    fl->udp_hold_replay_first = 0;
    fl->fwd_pkts++; /* счётчик попыток разбора клиентской стороны потока */
    if ((is_discord_ip_discovery(pkt+payload_off,payload_len) ||
         is_stun_request(pkt+payload_off,payload_len)) && fl->voice_requests<255)
        fl->voice_requests++;

    if (fl->saw_hello || fl->saw_initial) {
        /* Клиент шлёт ЕЩЁ, уже показав приветствие, — повтор Initial по
           таймеру PTO. Половина критерия «шлём, а молчат» (см. d2k_track.h).
           Считается ДО раннего выхода ниже: там поток с разобранным
           приветствием уходит первой же строкой, и счёт, поставленный после,
           не двинулся бы никогда. */
        fl->fwd_after_hello++;
        fl->last_fwd_after_hello_ns = now_ns;
    }

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
    if ((fl->saw_hello && fl->plan_done && !fl->udp_replan) ||
        fl->fwd_pkts > D2K_HELLO_WINDOW) {
        out->skipped = fl->saw_hello ? "поток уже показывал приветствие"
                                      : "за окном поиска";
        return;
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
    if (discord_voice && !fl->voice_ssrc_valid) {
        memcpy(fl->voice_ssrc, pkt + payload_off + 4, sizeof fl->voice_ssrc);
        fl->voice_ssrc_valid = 1;
    }
    if (stun_voice && !fl->stun_txid_valid) {
        memcpy(fl->stun_txid, pkt + payload_off + 8, sizeof fl->stun_txid);
        fl->stun_txid_valid = 1;
    }
    if(discord_voice && !fl->controller_probe && fl->fwd_pkts>1) {
        /* Discovery comparison primes a NEW socket before its first byte.
         * Installing the trial after three failed client requests must not
         * inject the prefix into that already exposed tuple and then judge
         * the remedy by its failure. Keep the lease for the next fresh flow. */
        out->skipped="Discord prefix ждёт нового потока: первый Discovery уже ушёл";
        return;
    }
    if (!voice && !d2k_quic_is_initial(pkt + payload_off, payload_len)) {
        out->skipped = "не QUIC Initial и не голос Дискорда";
        return;
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
    if (named && !voice && !fl->controller_probe) {
        size_t k = shape_slot(17, key.family);
        if (payload_len <= sizeof s->last_hello[k]) {
            memcpy(s->last_hello[k], pkt + payload_off, payload_len);
            s->last_hello_len[k] = payload_len;
            s->last_name_len[k] = 0;
            if (name_len > 0 && name_len <= sizeof s->last_name[k]) {
                memcpy(s->last_name[k], name, name_len);
                s->last_name_len[k] = name_len;
            }
        }
        if (s->shape_armed[k] && payload_len <= sizeof s->shape[k] &&
            (s->shape_name_len[k] == 0 ||
             name_same((const uint8_t *)name, name_len,
                       s->shape_name[k], s->shape_name_len[k]))) {
            memcpy(s->shape[k], pkt + payload_off, payload_len);
            s->shape_len[k] = payload_len;
            s->shape_armed[k] = 0;
            d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_SHAPE, 0,
                            (uint32_t)payload_len, NULL, NULL, 0, NULL);
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
       несёт trial ID. Голосовые пакеты контроллера адресных опытов не берут;
       не-голос подстановочных записей не видит (find_addr_probe). */
    const d2k_plan *use = NULL;
    if (!voice) {
        use = d2k_plantab_find_addr_probe(s->plans, &probe_flow, now_ns, trial_id);
    } else if (!fl->controller_probe) {
        use = d2k_plantab_find_voice_probe(s->plans, &probe_flow, now_ns, trial_id);
    }
    if (!use) { memset(trial_id, 0, sizeof trial_id); }
    if (!use) { use = d2k_plantab_find_target(s->plans,
                                                 named ? (const uint8_t *)name : NULL,
                                                 name_len, ip->dst.bytes, ip->family, now_ns,
                                                 seen_shape, controller_probe ? sport_be : 0); }
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
        out->skipped = "план уже применён к этому потоку";
        return;
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
        refuse(s, now_ns, &key, out->skipped);
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
        refuse(s, now_ns, &key, out->skipped);
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
        int found = c.family == 6
            ? d2k_nat_family_hook(D2K_NAT_PROC,17,c.src_ip6,c.src_port,
                                  c.dst_ip6,c.dst_port,6,ext6,&port)
            : d2k_nat_hook(D2K_NAT_PROC,17,c.src_ip,c.src_port,
                           c.dst_ip,c.dst_port,&ext,&port);
        if(found!=0 || (c.family != 6 && !ext) || !port) {
            /* Первый QUIC Initial ещё не подтверждён conntrack, пока его
               NFQUEUE-ID удерживается на разбор/исполнение. NODEFRAG нельзя
               NAT-ить по догадке, поэтому этот пакет проходит нетронутым, но
               кандидат сохраняется для повтора Initial: ко второму пакету
               ядро уже подтвердило кортеж. Постоянный промах на последующих
               пакетах остаётся обычным отказом ниже. */
            if(found==-1 && (held_first_replay || fl->fwd_pkts<=1)) {
                out->skipped="ожидаю подтверждения conntrack для IP-фрагментов";
                d2k_actions_free(&acts);
                return;
            }
            /* Missing procfs is NOT evidence of no NAT. Ordinary packets
               can leave translation to the kernel; NODEFRAG packets cannot. */
            out->skipped="нет подтверждённого NAT-контекста для IP-фрагментов";
            refuse(s,now_ns,&key,out->skipped);d2k_actions_free(&acts);return;
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
                !e->seq_shift && !e->poison && !e->wire_profile &&
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
    /* Не просто «план применился», а КАКОЙ: без идентификатора контроллер не
       отличит применение своего кандидата от применения предыдущего, чьё
       событие пришло позже (d2k_ctl.h объявляет APPLIED «ключ + id плана»). */
    d2k_journal_add_applied(s->jrn, now_ns, &key, d2k_plan_id(use), out->trial_id);
    d2k_actions_free(&acts);
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
                if (t0 >= 20 && t0 <= 23) {
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
        d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_EXCHANGE,
                        fl->rev_first_type, fl->rev_payload_after_hello,
                        &det, NULL, 0, NULL);
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
    const uint32_t in_seq = rd32(t + 4);

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
       (очередь видит после окна только сегменты с PSH), не запрос на
       границе — идёт как есть, считается, и граница дальше не ищется. */
    int http_hello = 0;
    size_t http_off = 0, http_len = 0;
    /* Порт 80 (ревью M-1): Host без порта означает 80, и запрос на другой
       порт — не наш вход. */
    if (!fl->saw_hello && fwd && t[2] == 0 && t[3] == 80) {
        d2k_http_req hr;
        int later = 0;
        if (!fl->http_checked && fl->saw_syn && in_seq == fl->syn_seq + 1u) {
            fl->http_checked = 1;
            http_hello = d2k_http_request(pkt + payload_off, payload_len, &hr);
            fl->http_flow = (uint8_t)http_hello;
        } else if (fl->http_conn) {
            const int32_t d = (int32_t)(in_seq - fl->http_next);
            if (d == 0) {
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
        if (http_hello) {
            http_off = hr.host_off;
            http_len = hr.host_len;
            if (later) { s->http_later++; }
            fl->http_conn = 0;
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

    if (!fl->saw_hello && fwd && fl->fwd_pkts <= D2K_HELLO_WINDOW && !http_hello) {
        d2k_tls_parse(pkt + payload_off, payload_len, &tls);
        if (!tls.is_client_hello) {
            s->pay_not_hello++;
            /* Первый байт нагрузки — самая дешёвая улика о том, ЧТО это
               было: 0x16 значит рукопожатие и разбор споткнулся внутри,
               0x47 — обычный HTTP, прочее — не TLS вовсе. */
            s->last_nonhello_first = pkt[payload_off];
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
            if (tls.have_sni && !fl->controller_probe) {
                s->with_sni++;
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_SNI, 0, 0,
                                NULL, pkt + payload_off + tls.sni_off,
                                tls.sni_len, NULL);
            } else if (tls.have_record_end && !fl->controller_probe) {
                /* Имени нет — и это нормальное состояние модели (§5.3), а не
                   ошибка разбора. */
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_NONAME, 0, 0,
                                NULL, NULL, 0, NULL);
            }
        }
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
                if (!fl->controller_probe) {
                    memcpy(s->last_hello[k], hello, hello_len);
                    s->last_hello_len[k] = hello_len;
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
                if (!fl->controller_probe && !fl->had_sni && complete.have_sni) {
                    fl->had_sni = 1;
                    s->with_sni++;
                    d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_SNI,
                                    0, 0, NULL, hello + complete.sni_off,
                                    complete.sni_len, NULL);
                } else if (!fl->controller_probe && !complete.have_sni &&
                           !(tls.is_client_hello && tls.have_record_end)) {
                    d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_NONAME,
                                    0, 0, NULL, NULL, 0, NULL);
                }
                int requested_shape = s->shape_armed[k] &&
                    (s->shape_name_len[k] == 0 ||
                     name_same(s->last_name[k], s->last_name_len[k],
                               s->shape_name[k], s->shape_name_len[k]));
                /* ECH cannot be regenerated from the outer name. Deliver
                 * its observed input before another connection overwrites
                 * last_hello, rather than waiting for a late suspicion. */
                if (!fl->controller_probe && (requested_shape || complete.ech_offer)) {
                    memcpy(s->shape[k], hello, hello_len);
                    s->shape_len[k] = hello_len;
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
    if (tls.is_client_hello) {
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
        if (tls.is_client_hello && tls.have_sni) {
            if (tls.is_tls13) {
                /* Признак найден — достоверен независимо от обрыва:
                   расширение прочитано целиком. */
                seen_shape = tls.ech_offer ? D2K_PLAN_SHAPE_ECH_TCP : D2K_PLAN_SHAPE_MODERN;
                /* Absence on an incomplete extension block is unknown.
                 * Keep the old MODERN prefix fast path where no ECH binding
                 * exists; exact probes use their reserved-port identity. */
                uint16_t probe_port = 0;
                if (controller_probe) memcpy(&probe_port, t, 2);
                if (!tls.ech_offer && tls.exts_truncated &&
                    d2k_plantab_has_ech_target(s->plans,
                        pkt + payload_off + tls.sni_off, tls.sni_len,
                        ip.dst.bytes, ip.family, probe_port))
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
        uint16_t sport_be;
        memcpy(&sport_be, t + 0, 2);
        use = d2k_plantab_find_target(s->plans,
                                     tls.have_sni ? pkt + payload_off + tls.sni_off : NULL,
                                     tls.have_sni ? tls.sni_len : 0,
                                     ip.dst.bytes, ip.family, now_ns, seen_shape,
                                     controller_probe ? sport_be : 0);
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
    }

    if (!plan_fits_transport(use, 6)) {
        out->skipped = "план объявлен для другого транспорта";
        if (tls.is_client_hello) { refuse(s, now_ns, &key, out->skipped); }
        return 0;
    }
    if (!use) {
        out->skipped = "плана для этой цели нет";
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
    if (!tls.is_client_hello && !http_hello) {
        /* Не приветствие — не наш случай. План первой версии описывает именно
           начало TLS-соединения. */
        out->skipped = "не ClientHello";
        return 0;
    }
    if (fl->plan_done && !http_hello) {
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

    d2k_pkt in;
    memset(&in, 0, sizeof in);
    in.payload = pkt + payload_off;
    in.payload_len = payload_len;
    in.seq = in_seq;
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
           не сбой: якорь может быть невычислим для конкретного пакета. */
        out->skipped = "план неприменим к этому пакету";
        if (!http_hello) { refuse(s, now_ns, &key, out->skipped); }
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
    c.ip_id = ip.ip_id;

    if (acts.n > sizeof out->out / sizeof out->out[0]) {
        /* Тот же класс отказа, что и made==0 чуть ниже (ревью задачи 4,
           круг 2): repeats фальшивки приходит из TLV байтом без потолка (до
           255), а out[] ограничен D2K_RESULT_MAX. Обрезать n молча значило бы
           "применить" план и отправить на провод меньше посылок, чем он
           описывает, — то есть план, который не исполнялся. Честный исход —
           отказ целиком. */
        out->skipped = "план описывает больше посылок, чем вмещает буфер результата";
        if (!http_hello) { refuse(s, now_ns, &key, out->skipped); }
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
    fl->plan_done = 1;
    fl->guards = d2k_plan_guards(use);
    s->applied++;
    /* Ключ потока и идентификатор плана — ВЫЗЫВАЮЩЕМУ, до отправки. Без них
       отправляющий видит только байты, и отказ sendto оставался голым
       счётчиком (d2k_session.h, поля applied/key/plan_id). */
    plan_handed_off(s, out, fl, &key, use, NULL);
    /* Не просто «план применился», а КАКОЙ: без идентификатора контроллер не
       отличит применение своего кандидата от применения предыдущего, чьё
       событие пришло позже (d2k_ctl.h объявляет APPLIED «ключ + id плана»). */
    d2k_journal_add_applied(s->jrn, now_ns, &key, d2k_plan_id(use), NULL);

    d2k_actions_free(&acts);
    return 0;
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
    *anchor = fl->syn_seq + 1;
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
        /* Only a target with its own ECH binding needs to wait for an ECH
         * extension potentially hidden in the tail. Reuse the existing
         * bounded, fail-open collection, not a second stream buffer. */
        if (!fl->controller_probe && tls.have_sni && tls.exts_truncated &&
            !tls.ech_offer && d2k_plantab_has_ech_target(s->plans,
                p + v.header + tls.sni_off, tls.sni_len,
                v.dst.bytes, v.dst.family, 0)) {
            fl->stream_attempted = 1;
            return 1;
        }
        /* ИМЯ И ПРИГОДНАЯ ФОРМА УЖЕ ЗДЕСЬ — ДЕРЖАТЬ НЕЧЕГО.
         *
         * Если форма уже известна (либо её знает собственный exact-port
         * зонд), план выбирается прямо сейчас. Исключение — обычный клиент
         * с именем в голове и supported_versions в хвосте: для его shaped
         * привязки имя ещё недостаточно, и ниже разрешена ограниченная сборка.
         *
         * Замер 18.09.2026 на живой линии, три прогона подряд: пока голова
         * лежит в очереди без вердикта, ОСТАТОК ЯДРО НЕ ВЫПУСКАЕТ. Счётчики
         * удержания назвали это прямо — «добавлено к голове=0, несовместимых=0,
         * с другой стороны=0» при «начато=2, таймаутов=2 (пакетов в них=2)»:
         * второй сегмент до слота не доходил вовсе, его не отвергали. А без
         * удержания те же два сегмента уходят на провод через 130-220 мкс
         * друг за другом (дамп ppp0 того же прогона). Удержание головы само
         * отрезало себе то, чего ждало: сборка не завершалась никогда, план
         * не применялся, и каждое приветствие получало лишние 100 мс.
         *
         * Поле говорит и о цене этого правила: «имя уехало во второй сегмент»
         * за все прогоны — ноль раз. Составная сборка остаётся ровно для того
         * случая, ради которого написана. */
        if (tls.have_sni) {
            /* SNI precedes a large key_share in current Safari hellos, but
             * supported_versions can be in the next segment. Ordinary
             * shaped bindings cannot execute until that shape is known.
             * Probe-specific bindings already carry their own known shape;
             * keep their prefix fast path to avoid blocking kernel output. */
            if (tls.is_tls13 || !tls.exts_truncated || fl->controller_probe || s->plan)
                return 0;
            if (d2k_plantab_find_target(s->plans, p + v.header + tls.sni_off,
                tls.sni_len, v.dst.bytes, v.dst.family, fl->first_ns,
                D2K_PLAN_SHAPE_ANY, 0)) return 0;
            /* A grandfather/unshaped plan may already handle the prefix.
             * Otherwise only an existing named stream plan below can own
             * this bounded assembly; unknown targets remain pass-through. */
        }
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
    if ((!f->saw_hello && !f->saw_initial) || f->silence_told || f->suspected ||
        f->quic_deny) {
        return;
    }
    if(f->voice_ssrc_valid || f->stun_txid_valid) {
        /* The limited queue is not a clock for a continuing media session.
         * With counters, ct_voice_flow owns both startup and late silence.
         * Without counters, only three real unanswered protocol requests
         * inside the visible startup window provide a suspicion. */
        if(!c->s->ct_query && f->voice_requests>=3 && !f->rev_pkts &&
           (c->s->udp_reverse_hook || c->s->rev_seen[shape_slot(17,f->key.family)]) &&
           c->now_ns>=f->hello_ns && c->now_ns-f->hello_ns>=5*NS_PER_S) {
            f->silence_told=1;c->told++;
            suspect(c->s,c->now_ns,&f->key,f,D2K_SUSPECT_SILENT,NULL);
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

/* Voice uses the same bounded ctnetlink path as QUIC. A historical
 * Discovery/STUN answer cannot hide a later cut. This is suspicion only:
 * the controller must reproduce it with its protocol oracle. Missing
 * counters, reset counters and a quiet caller never prove a cut. */
static void ct_voice_flow(void *ctx, d2k_flow *f) {
    struct ct_ctx *c = ctx;
    if (f->key.proto != 17 || (!f->voice_ssrc_valid && !f->stun_txid_valid) ||
        f->suspected || f->controller_probe) return;
    d2k_ct_tuple t;
    flow_tuple(f, &t);
    d2k_ct_info ci = {0};
    if (c->s->ct_query(c->s->ct_query_ctx, &t, &ci) != 0) {
        f->ct_known = 0;
        f->voice_stable_since_ns = 0;
        return;
    }
    if (f->ct_known && (ci.orig_pkts > f->voice_ct_orig || ci.reply_pkts > f->ct_reply))
        f->last_ns = c->now_ns;
    int reset=f->ct_known && (ci.orig_pkts<f->voice_ct_orig || ci.reply_pkts<f->ct_reply);
    if(reset) {
        f->voice_requests=0;f->voice_media_dirs=0;f->voice_media_told=0;f->voice_stable_told=0;
    }
    if(!reset && !ci.reply_pkts && ci.orig_pkts>=3 && f->voice_requests>=3 &&
       c->now_ns>=f->hello_ns && c->now_ns-f->hello_ns>=5*NS_PER_S) {
        c->told++;
        suspect(c->s,c->now_ns,&f->key,f,D2K_SUSPECT_SILENT,NULL);
        return;
    }

    int advancing = f->ct_known && ci.orig_pkts > f->voice_ct_orig && ci.reply_pkts > f->ct_reply;
    if (reset || !f->ct_known || ci.reply_pkts < f->ct_reply || c->now_ns < f->ct_reply_ns ||
        (ci.reply_pkts == f->ct_reply && c->now_ns - f->ct_reply_ns >= 5*NS_PER_S))
        f->voice_stable_since_ns = 0;
    if (advancing && f->voice_media_dirs == 3) {
        if (!f->voice_stable_since_ns) f->voice_stable_since_ns = c->now_ns;
        if (!f->voice_stable_told && c->now_ns >= f->voice_stable_since_ns &&
            c->now_ns - f->voice_stable_since_ns >= 30*NS_PER_S) {
            f->voice_stable_told = 1;
            d2k_journal_add(c->s->jrn,c->now_ns,&f->key,D2K_JRN_EXCHANGE,
                            D2K_UDP_OBS_STABLE,0,NULL,NULL,0,NULL);
        }
    }

    f->voice_ct_orig = ci.orig_pkts;
    if (!f->ct_known || reset || ci.reply_pkts != f->ct_reply ||
        ci.orig_pkts < f->ct_orig_mark || c->now_ns < f->ct_reply_ns) {
        f->ct_known = 1;
        f->ct_reply = ci.reply_pkts;
        f->ct_reply_ns = c->now_ns;
        f->ct_orig_mark = ci.orig_pkts;
        return;
    }
    /* Five seconds plus five actual client packets tolerates startup,
     * isolated loss and normal channel teardown. No queued packet is needed. */
    if (ci.orig_pkts - f->ct_orig_mark < 5 ||
        c->now_ns - f->ct_reply_ns < 5 * NS_PER_S) return;
    c->told++;
    suspect(c->s, c->now_ns, &f->key, f, ci.reply_pkts ? D2K_SUSPECT_VOICE_STALL : D2K_SUSPECT_SILENT, NULL);
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
        f->tcp_watch_off = 1;
        return;
    }
    const uint64_t reply = ci.reply_pkts;
    const uint64_t unseen = reply > f->rev_pkts_conn ? reply - f->rev_pkts_conn : 0;
    const uint64_t est = (uint64_t)f->fwd_data_pkts + f->rev_data_pkts + unseen;
    if (est > tcp_band_top(c->s)) {
        f->tcp_watch_off = 1;
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

int d2k_session_set_stall_budgets(d2k_session *s, const uint16_t *b, size_t n) {
    if (!s || n > D2K_STALL_BUDGETS_MAX || (n && !b)) { return -1; }
    for (size_t i = 0; i < n; i++) {
        if (b[i] == 0) { return -1; }
    }
    if (n == 0) {
        s->stall_budget[0] = D2K_TCP_STALL_FIELD_BUDGET;
        s->n_stall_budget = 1;
        return 0;
    }
    memcpy(s->stall_budget, b, n * sizeof *b);
    s->n_stall_budget = n;
    return 0;
}

size_t d2k_session_stall_budgets(const d2k_session *s, uint16_t *out, size_t cap) {
    if (!s) { return 0; }
    for (size_t i = 0; out && i < s->n_stall_budget && i < cap; i++) {
        out[i] = s->stall_budget[i];
    }
    return s->n_stall_budget;
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
        d2k_track_walk(s->uflows, ct_voice_flow, &cc);
        d2k_track_walk(s->flows, ct_tcp_flow, &cc);
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
    freed += d2k_track_expire(s->uflows, now_ns, idle_ns, NULL, NULL);
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
        s->done++;
        d2k_journal_add_fate(s->jrn, at_ns, k, D2K_JRN_PLAN_DONE,
                             D2K_REFUSE_NONE, fl->execution_plan_id,
                             fl->execution_trial_id);
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
            d2k_journal_add_fate(s->jrn, at_ns, k, D2K_JRN_PLAN_DAMAGED,
                                 D2K_REFUSE_DAMAGED,
                                 plan_id ? plan_id : fl->execution_plan_id,
                                 fl->execution_trial_id);
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
        d2k_journal_add_fate(s->jrn, at_ns, k, D2K_JRN_PLAN_UNSENT, code,
                             plan_id ? plan_id : fl->execution_plan_id,
                             fl->execution_trial_id);
        fl->sends_left = 0;
        fl->sends_failed = 1;
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
}

const d2k_journal *d2k_session_journal(const d2k_session *s) {
    return s ? s->jrn : NULL;
}
