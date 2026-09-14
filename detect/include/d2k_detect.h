/* d2k_detect.h — ПЕРЕНОС инструмента «Поиск по домену» из z2k на C.
 *
 * Эталон: z2k/z2k-detect, коммит e9a3913, пакет internal/classify.
 * Здесь не «по мотивам» и не «упрощённо»: дерево зондов, порядок гипотез,
 * тексты вердиктов и имена наблюдений перенесены дословно, чтобы на одной
 * и той же цели с одним и тем же триггером оба инструмента давали
 * совпадающий вердикт, стратегию и трассу. Расхождение здесь — дефект
 * переноса, а не «другая реализация»: см. D2K_SPEC.md §2 и §8.
 *
 * ЧТО ИМЕННО СВЕРЯЕТСЯ. Триггер оба инструмента обязаны взять ОДИН И ТОТ ЖЕ
 * (флаг -raw у z2k-detect, --raw здесь): сборщик приветствия у них разный по
 * происхождению (там crypto/tls, здесь снятый с живого браузера профиль), и
 * сверять алгоритм на разных байтах нельзя. Поле duration из сверки исключено
 * — это время, а не вывод.
 */
#ifndef D2K_DETECT_H
#define D2K_DETECT_H

#include <stddef.h>
#include <stdint.h>

/* Метка, по которой правила NFQUEUE пропускают пакет мимо нашего десинка.
 * Зонд обязан ходить сырым путём: иначе он меряет не коробку провайдера, а
 * наш обход поверх неё. Значение — из эталона, менять нельзя: его знают
 * правила на роутере. */
#define D2K_BYPASS_MARK 0x40000000

/* Трёхзначное «да/нет/не измерено». nil в эталоне значит «не измерено», а не
 * «нет»; в C двух состояний булева не хватает, и молчать честнее, чем
 * догадываться (см. Properties в эталоне). */
typedef enum { D2K_TRI_UNSET = 0, D2K_TRI_FALSE = 1, D2K_TRI_TRUE = 2 } d2k_tri;

/* Класс блокировки, опознанный по форме отклика. Строковые значения — те же,
 * что в JSON эталона: вердикт читают снаружи. */
typedef enum {
    D2K_V_NONE = 0,
    D2K_V_CLEAR,        /* "clear"        триггер проходит как есть */
    D2K_V_PREFIX,       /* "prefix"       префиксный матчер без пересборки */
    D2K_V_WHOLE_PACKET, /* "whole_packet" матчер требует пакет целиком */
    D2K_V_OPAQUE,       /* "opaque"       решает по содержимому, разрез не помогает */
    D2K_V_INCONCLUSIVE, /* "inconclusive" контроль молчит, отравить не вышло */
    D2K_V_ADDRESS,      /* "address"      режут адрес */
    D2K_V_POISONABLE,   /* "poisonable"   буфер пересборки травится */
    D2K_V_FLAKY,        /* "flaky"        не воспроизводится */
    D2K_V_UNREACHABLE,  /* "unreachable"  нет даже TCP */
    D2K_V_RESPONSE      /* "response"     режут ОТВЕТ (TLS 1.2) */
} d2k_verdict_t;

const char *d2k_verdict_name(d2k_verdict_t v);

/* Чем считать ответ доказательством прохода. В эталоне это замыкание
 * Trigger.Accept; здесь — перечисление, потому что вариантов ровно три и
 * каждый из них в эталоне записан явным литералом. */
typedef enum {
    D2K_ACCEPT_ANY = 0,      /* любой непустой ответ (RawTrigger) */
    D2K_ACCEPT_SERVERHELLO,  /* только ServerHello (TLSTrigger) */
    D2K_ACCEPT_TLSRECORD     /* любая запись TLS, включая алерт (ControlTrigger) */
} d2k_accept_t;

#define D2K_TRIGGER_MAX 16384

/* Что шлём и как понимаем, что ответ пришёл. */
typedef struct {
    char          name[96];
    uint8_t       payload[D2K_TRIGGER_MAX];
    size_t        len;
    int           sni_off;   /* где в нагрузке лежит имя, 0 если неизвестно */
    int           sni_len;
    d2k_accept_t  accept;
} d2k_trigger;

int d2k_trigger_accepts(const d2k_trigger *t, const uint8_t *b, size_t n);

/* poison — чем отравляем буфер пересборки. Смысл каждого варианта один:
 * коробка обязана сегмент проглотить, сервер — выбросить. Различаются они
 * только тем, ЧЕМ именно сервер его забракует. Поля — дословно из эталона,
 * включая комментарии к каждому: они и есть обоснование, почему вариант
 * существует отдельно от соседнего. */
typedef struct {
    char    name[64];
    int     ttl;           /* >0 — пакет умрёт по дороге, не дойдя до сервера */
    int     badsum;        /* испортить контрольную сумму TCP */
    int32_t seq_shift;     /* сдвинуть номер последовательности за окно */
    int     md5;           /* добавить опцию TCP-MD5, которой сервер не ждёт */
    int     decoy_hello;   /* приманка — правдоподобное приветствие, а не набивка */
    const uint8_t *decoy;  /* готовые байты приманки */
    size_t  decoy_len;
    int     disorder;      /* слать сегменты НЕ ПО ПОРЯДКУ */
    int     tcp_ts;        /* метка времени со сдвигом назад */
    int     ip_id_zero;    /* обнулить идентификатор IP */
    int     gap_ms;        /* пауза между копиями фальшивки */
    int     syn_data;      /* приветствие ПРЯМО В SYN */
    int     oob;           /* байт ВНЕ ПОЛОСЫ (URG) */
    int     fake_between;  /* фальшивку класть МЕЖДУ кусками правды */
    int     repeats;       /* сколько копий фальшивки слать подряд */
    int     seqovl_exact;  /* длина перекрытия = длина приманки */
    int     seqovl;        /* перекрытие последовательностей */
} d2k_poison;

int d2k_poison_has_fake(const d2k_poison *p);

/* Что удалось узнать о самой коробке. UNSET означает «не измерено». */
typedef struct {
    d2k_tri reassembles;
    d2k_tri parses_l7;
    d2k_tri validates_checksum;
    d2k_tri tolerates_reorder;
    d2k_tri tolerates_left_overlap;
    d2k_tri counts_duplicates;
    d2k_tri inspects_syn;
    int     hop_ttl;
} d2k_props;

/* Один зонд: как писали и что получили. */
typedef struct {
    char probe[160];
    int  cuts[4];
    int  ncuts;
    int  delay_ms;
    int  pass;
    int  fail;
    char err[160];
} d2k_obs;

#define D2K_TRACE_MAX 512
#define D2K_NOTES_MAX 8

/* Итог зонда ответного направления (TLS 1.2, сертификат открытым текстом). */
typedef enum {
    D2K_RESP_NOT_APPLICABLE = 0, /* "not_applicable" — НЕ измерено */
    D2K_RESP_CLEAR,              /* "clear"          */
    D2K_RESP_BLOCKED,            /* "blocked"        */
    D2K_RESP_FLAKY               /* "flaky"          */
} d2k_resp_verdict;

typedef struct {
    d2k_resp_verdict verdict;
    char reason[320];
    int  target;
    int  control;
} d2k_resp_result;

const char *d2k_resp_name(d2k_resp_verdict v);

/* Что показал прогон. */
typedef struct {
    char          target[160];
    d2k_verdict_t verdict;
    char          reason[640];
    int           repeats;
    int           probes;
    long          duration_ms;

    int  trigger_len;
    int  boundary;    /* первая позиция разреза, которая УЖЕ не проходит */
    int  split_pos;   /* рекомендуемая позиция разреза */
    d2k_tri reassembles;
    char strategy[1024];

    char notes[D2K_NOTES_MAX][256];
    int  nnotes;

    d2k_tri covers_tls12;

    int             has_response;
    d2k_resp_result response;

    d2k_props props;
    /* Каким из трёх путей получен ответ: "свойство", "собрано", "перебор". */
    char path[32];
    int  composed;
    int  raw_usable;

    d2k_obs trace[D2K_TRACE_MAX];
    int     ntrace;
} d2k_result;

#define D2K_SKIP_MAX 32

/* Настройки прогона. Нули заменяются разумными умолчаниями. */
typedef struct {
    int  repeats;      /* повторов на КАЖДЫЙ зонд; вердикт только при единогласии */
    int  timeout_ms;   /* сколько ждём ответа */
    int  write_gap_ms; /* пауза между записями */
    int  long_gap_ms;  /* пауза для проверки на пересборку */
    int  allow_loopback;
    char only[64];                        /* прогнать ТОЛЬКО эту гипотезу */
    char skip[D2K_SKIP_MAX][64];          /* гипотезы, которые НЕ пробовать */
    int  nskip;
    int  joint_budget_ms;
    int  cross_check_tls12;
    int  no_raw;
    int  control_vouched;
    d2k_trigger control;
    /* accept — фильтр находок: вернул 0, перебор идёт дальше, как будто
     * гипотеза не сработала. Нужен поиску приёма, общего для двух приветствий. */
    int (*accept)(const d2k_poison *p, void *ctx);
    void *accept_ctx;
} d2k_opts;

void d2k_opts_defaults(d2k_opts *o);
int  d2k_opts_acceptable(const d2k_opts *o, const d2k_poison *p);
int  d2k_opts_skipped(const d2k_opts *o, const char *name);

/* ProbeResponse — не режут ли ОТВЕТ сервера (TLS 1.2, сертификат открытым
 * текстом). Зовётся только там, где запрос уже признан проходящим. */
void d2k_probe_response(const char *host, const char *port, const char *sni,
                        const d2k_opts *opt, d2k_resp_result *res);

/* triggerSNI достаёт имя из названия триггера: TLS-триггер кладёт туда
 * "tls:<имя>". Для сырого триггера имени нет, и зонд ответного направления
 * смысла не имеет. */
const char *d2k_trigger_sni(const d2k_trigger *t);

/* Run прогоняет дерево зондов по адресу addr ("host:port"). */
void d2k_classify_run(const char *addr, const d2k_trigger *tr,
                      d2k_opts *opt, d2k_result *res);

/* --- сырой слой (raw.c) ------------------------------------------------- */

int  d2k_raw_supported(void);
int  d2k_raw_rst_rule_failed(void);
/* probe_poison — ОДИН зонд, собранный из независимых приёмов.
 * Возврат: 1 — прошло, 0 — не прошло, -1 — ошибка зонда (err заполнен). */
int  d2k_raw_probe_poison(const uint8_t ip4[4], uint16_t port,
                          const d2k_trigger *tr, const d2k_poison *p,
                          int timeout_ms, char *err, size_t errcap);
int  d2k_raw_probe_handshake(const uint8_t ip4[4], uint16_t port,
                             int timeout_ms, char *err, size_t errcap);

/* --- гипотезы (poison.c) ------------------------------------------------ */

const d2k_poison *d2k_poisons(int *n);
void d2k_strategy_for_poison(const d2k_poison *p, char *out, size_t cap);
void d2k_strategy_for(int pos, char *out, size_t cap);
void d2k_note_props_hit(d2k_props *pr, const d2k_poison *p);
void d2k_note_props_miss(d2k_props *pr, const d2k_poison *p);

/* --- свойства (props.c) ------------------------------------------------- */

int d2k_run_properties(const uint8_t ip4[4], uint16_t port,
                       const d2k_trigger *tr, const d2k_opts *opt,
                       d2k_result *res, d2k_poison *hit);
int d2k_compose_from_props(const d2k_props *pr, const uint8_t *ctl, size_t ctl_len,
                           d2k_poison *out, int cap);

/* --- триггеры (trigger.c) ----------------------------------------------- */

int d2k_trigger_tls(const char *sni, int legacy, d2k_trigger *out, char *err, size_t errcap);
int d2k_trigger_raw_hex(const char *hex, d2k_trigger *out, char *err, size_t errcap);
int d2k_trigger_control(const char *tag, d2k_trigger *out, char *err, size_t errcap);

/* --- мелочи, общие для модулей ------------------------------------------ */

long d2k_now_ms(void);
void d2k_sleep_ms(int ms);
d2k_obs *d2k_trace_add(d2k_result *res, const char *probe);
void d2k_note(d2k_result *res, const char *fmt, ...);

#endif /* D2K_DETECT_H */
