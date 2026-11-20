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

#include "d2k_arm.h"
#include "d2k_boxprops.h" /* d2k_box_props — знание о коробке из каталога */
#include "d2k_preflight_candidate.h"
#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>

/* Метка, по которой правила NFQUEUE пропускают пакет мимо нашего десинка.
 * Зонд обязан ходить сырым путём: иначе он меряет не коробку провайдера, а
 * наш обход поверх неё.
 *
 * ЭТО ЗНАЧЕНИЕ — ЭТАЛОННОЕ, И ОНО НЕ ЕДИНСТВЕННОЕ. Правила z2k пропускают
 * мимо очереди метку 0x40000000, правила d2k — свою (её задаёт --mark при
 * запуске датапата, у владельца это 0x2d). Зашитая здесь константа годится
 * только когда измеритель работает сам по себе; внутри d2kc метку обязан
 * задавать вызывающий (d2k_opts.mark), иначе зонд пойдёт ЧЕРЕЗ наш же обход
 * и замерит его, а не коробку. */
#define D2K_BYPASS_MARK 0x40000000

/* ОТМЕНА. У оригинала её несёт context: `Run`, `measure`, `once`,
 * `sweepPoisons` и `runProperties` проверяют `ctx.Err()` в каждом цикле, а
 * `readPayload` — на каждом круге ожидания. В первую редакцию переноса
 * отмена не попала вовсе, и это стоило видимого дефекта: остановка d2kc
 * ждала окончания замера. Один зонд — до шести секунд, полный перебор —
 * десятки минут, и всё это время служба не выходила по сигналу, а стенд
 * висел на `wait`.
 *
 * Возврат ненулевого значения означает «бросай»: текущий зонд дорабатывает
 * до ближайшей границы, а результат помечается как БРОШЕННЫЙ (d2k_result.stopped).
 *
 * ФЛАГ ОБЯЗАН БЫТЬ ЛИПКИМ: взведён — значит взведён до конца прогона. На нём
 * держится пометка результата, а она важнее самого прерывания. Брошенный
 * замер, выданный за измеренный «чисто», снял бы рабочий план — это ровно та
 * ложь, от которой заведено различие «не измерено» и «нет». */
/* Имя с приставкой модуля не случайно: d2k_cancel уже занят датапатом
 * (datapath/include/d2k_plan.h) под совсем другое понятие, а переходник
 * включает оба заголовка сразу. */
typedef struct {
    int (*fn)(void *ctx);
    void *ctx;
} d2k_detect_stop;

int d2k_detect_stopped(const d2k_detect_stop *c);

/* Трёхзначное «да/нет/не измерено». nil в эталоне значит «не измерено», а не
 * «нет»; в C двух состояний булева не хватает, и молчать честнее, чем
 * догадываться (см. Properties в эталоне). */
typedef enum { D2K_TRI_UNSET = 0, D2K_TRI_FALSE = 1, D2K_TRI_TRUE = 2 } d2k_tri;

/* Класс блокировки, опознанный по форме отклика. Строковые значения — те же,
 * что в JSON эталона: вердикт читают снаружи.
 *
 * ПРЕФИКС DV, А НЕ V. У прежнего ядра d2k (core/d2k_verdict.h) свой набор
 * D2K_V_*, и половина имён совпадает при РАЗНОМ составе: там нет ни
 * poisonable, ни address, ни response, зато есть D2K_V_WHOLE вместо
 * whole_packet. Переходник между планировщиком и этим измерителем включает оба
 * заголовка сразу, и молчаливое совпадение имён дало бы там подмену вердикта
 * без единого предупреждения компилятора. То же и с d2k_dprops против
 * d2k_dprops из core/d2k_compose.h. */
typedef enum {
    D2K_DV_NONE = 0,
    D2K_DV_CLEAR,        /* "clear"        триггер проходит как есть */
    D2K_DV_PREFIX,       /* "prefix"       префиксный матчер без пересборки */
    D2K_DV_WHOLE_PACKET, /* "whole_packet" матчер требует пакет целиком */
    D2K_DV_OPAQUE,       /* "opaque"       решает по содержимому, разрез не помогает */
    D2K_DV_INCONCLUSIVE, /* "inconclusive" контроль молчит, отравить не вышло */
    D2K_DV_ADDRESS,      /* "address"      режут адрес */
    D2K_DV_POISONABLE,   /* "poisonable"   буфер пересборки травится */
    D2K_DV_FLAKY,        /* "flaky"        не воспроизводится */
    D2K_DV_UNREACHABLE,  /* "unreachable"  нет даже TCP */
    D2K_DV_RESPONSE,     /* "response"     режут ОТВЕТ (TLS 1.2) */
    D2K_DV_RESPONSE_GATE /* ACKed hello, small-window response, carry over RST */
} d2k_verdict_t;

const char *d2k_verdict_name(d2k_verdict_t v);

/* НАШ ИСТЁКШИЙ СРОК ИЛИ ОТВЕТ ЛИНИИ — РАЗНЫЕ ВЕЩИ (задача 19).
 *
 * 1 — текст ошибки транспорта означает, что кончилось НАШЕ время на
 * подключение; 0 — линия ответила (отказ порта, сброс, нет маршрута) либо
 * ошибка наша местная. Правило одно на все места, где этот исход решает: его
 * уже применял отбор базового ответа (classify.c: засеянный «dial tcp … i/o
 * timeout» не переиспользуется, его спрашивают заново), а теперь и вердикт.
 *
 * Поле 12.10.2026, flibusta.is: с роутера curl отдаёт 200 с адреса
 * 179.43.150.83, а установка соединения в трёх попытках подряд заняла 3,1 с
 * (отказ), 0 с (отказ) и 7,16 с (успех) — при сроке зонда 6000 мс. Замер не
 * состоялся ни разу: 218 поисков подряд писали «до цели нет транспорта» и
 * уходили на десять минут. Слова были неверные — транспорт есть, не хватило
 * нашего срока, — а вердикт попадал в корзину «кандидатов нет, и это не
 * бедность перебора», где планы не строятся вовсе. Это тот же запрет, что
 * «наш предел заголовков ≠ обрыв линии» (задача 44) и «не задан ≠ не
 * удался». */
int d2k_dial_deadline_err(const char *err);

/* Чем считать ответ доказательством прохода. В эталоне это замыкание
 * Trigger.Accept; здесь — перечисление, потому что вариантов ровно три и
 * каждый из них в эталоне записан явным литералом. */
typedef enum {
    D2K_ACCEPT_ANY = 0,      /* любой непустой ответ (RawTrigger) */
    D2K_ACCEPT_SERVERHELLO,  /* только ServerHello (TLSTrigger) */
    D2K_ACCEPT_TLSRECORD     /* любая запись TLS, включая алерт (ControlTrigger) */
} d2k_accept_t;

#define D2K_TRIGGER_MAX D2K_ARM_TRIGGER_MAX
#define D2K_TRIGGER_NAME_MAX 260 /* "tls:" + SNI до 253 + NUL, с запасом */

/* Что шлём и как понимаем, что ответ пришёл. */
typedef struct {
    char          name[D2K_TRIGGER_NAME_MAX]; /* "tls:" + SNI до 253 + NUL */
    uint8_t       payload[D2K_TRIGGER_MAX];
    size_t        len;
    int           sni_off;   /* где в нагрузке лежит имя, 0 если неизвестно */
    int           sni_len;
    d2k_accept_t  accept;
    /* НАБОР ОПЦИЙ TCP КЛИЕНТА, ЧЬЁ ПРИВЕТСТВИЕ ЭТО (замысел 2026-10-23,
     * п. 5.1). Снят датапатом с того же пакета, что и приветствие
     * (D2K_EV_CLIENT_TCP); зонд здоровается этим набором, а не своим
     * литералом: вопрос «коробка глотает устаревшую метку времени» задаётся
     * только клиенту, который метку предлагает. client_tcp_known == 0 — набор
     * не снят (холодный старт, старый датапат): зонд идёт прежним набором, с
     * меткой времени, как раньше. Пустой известный набор (known, len 0) —
     * клиент без опций в данных, и это честный профиль. Полноту входа привязки
     * (CLIENT/PROFILE) это поле не решает — см. core/include/d2k_meas.h. */
    int           client_tcp_known;
    uint8_t       client_tcp_options[40];
    size_t        client_tcp_options_len;
} d2k_trigger;

size_t d2k_trigger_prefix_size(const d2k_trigger *t);
int d2k_trigger_accepts(const d2k_trigger *t, const uint8_t *b, size_t n);

/* poison — чем отравляем буфер пересборки. Смысл каждого варианта один:
 * коробка обязана сегмент проглотить, сервер — выбросить. Различаются они
 * только тем, ЧЕМ именно сервер его забракует. Поля — дословно из эталона,
 * включая комментарии к каждому: они и есть обоснование, почему вариант
 * существует отдельно от соседнего. */
typedef struct {
    char    name[64];
    int     ttl;           /* >0 — пакет умрёт по дороге, не дойдя до сервера */
    /* TTL, вычисляемый по входящему TTL (ip_autottl документации zapret2):
     * приёму не нужно НИЧЕГО от клиентской ОС, в отличие от метки времени.
     * autottl == 0 — поля не значимы. */
    int     autottl;
    int     autottl_delta;
    int     autottl_min;
    int     autottl_max;
    int     badsum;        /* испортить контрольную сумму TCP */
    int32_t seq_shift;     /* сдвинуть номер последовательности за окно */
    int     md5;           /* добавить опцию TCP-MD5, которой сервер не ждёт */
    int     md5_ts;        /* MD5 первой + метка времени (раскладка nfqws1
                              tcp_md5_first); отдельная ось от md5-одиночки */
    int     decoy_hello;   /* приманка — правдоподобное приветствие, а не набивка */
    const uint8_t *decoy;  /* готовые байты приманки */
    size_t  decoy_len;
    int     disorder;      /* слать сегменты НЕ ПО ПОРЯДКУ */
    int     disorder_pos;  /* одиночный абсолютный разрез для reverse-disorder */
    int     tcp_ts;        /* метка времени со сдвигом назад */
    int     tcp_ts_up;     /* и поднять её в начало опций (tcp_ts_up) */
    int     ip_id_zero;    /* обнулить идентификатор IP */
    int     gap_ms;        /* пауза между копиями фальшивки */
    int     syn_data;      /* приветствие ПРЯМО В SYN */
    int     oob;           /* байт ВНЕ ПОЛОСЫ (URG) */
    int     fake_between;  /* фальшивку класть МЕЖДУ кусками правды */
    int     repeats;       /* сколько копий фальшивки слать подряд */
    int     seqovl_exact;  /* длина перекрытия = длина приманки */
    int     seqovl;        /* перекрытие последовательностей */
    int     split_pos;     /* разрез НАСТОЯЩЕЙ нагрузки в этой позиции,
                              порядок прямой (голова первой) — так режет
                              настоящее приветствие семейство C (split +2);
                              0 — не резать. Отличен от disorder_pos (там
                              хвост уходит ПЕРВЫМ, обратный порядок). */
} d2k_poison;

int d2k_poison_has_fake(const d2k_poison *p);
/* Предлагает ли клиент триггера метку времени TCP (вид 8). Неизвестный набор
 * — да: прежний зонд метку предлагал всегда. */
int d2k_trigger_offers_ts(const d2k_trigger *t);
/* Задаётся ли приём этому клиенту: порча «метка времени назад» требует
 * метки в потоке, и клиенту без неё вопрос не задаётся вовсе — ни в вопросах
 * о свойствах, ни в запасном переборе. */
/* ТЕСТОВАЯ ПОДМЕНА СПОСОБНОСТИ ЛОКАЛЬНОГО СТЕКА предлагать метку времени:
 * -1 — спрашивать систему (рабочее поведение), 0/1 — ответ для теста. Нужна
 * потому, что способность стека иначе не задать из теста, а именно она решает
 * судьбу плана, когда набор опций клиента не снят. */
void d2k_trigger_host_ts_override(int v);

int d2k_trigger_allows_poison(const d2k_trigger *t, const d2k_poison *p);
/* Одна и та же гипотеза по всем параметрам, кроме имени. */
int d2k_poison_same(const d2k_poison *a, const d2k_poison *b);


/* Pure conversion shared by raw execution and the scheduler bridge. */
int d2k_arm_from_poison(const d2k_poison *, d2k_arm *, char *, size_t);

typedef struct {
    int response_gate, pieces_pass;
    uint16_t window;
    uint8_t window_scale;
    unsigned pieces_needed;
    int carry_over_rst, hello_own;
    char white_name[256];
    uint32_t rtt_ms;
    uint16_t probes; /* Connections for questions 2–3, excludes ACK baselines. */
    uint8_t baseline_probes; /* Fresh normal-window controls actually opened. */
    uint32_t baseline_acked; /* Observed ACK bytes, not inferred delivery. */
    uint32_t small_response_bytes;
    d2k_preflight_candidate candidate;
    char reason[160]; /* Why the carry question stopped without a plan. */
} d2k_preflight_meas;

/* Что удалось узнать о самой коробке. UNSET означает «не измерено». */
typedef struct {
    d2k_tri reassembles;
    d2k_tri parses_l7;
    d2k_tri validates_checksum;
    d2k_tri tolerates_reorder;
    d2k_tri tolerates_left_overlap;
    d2k_tri counts_duplicates;
    d2k_tri inspects_syn;
    /* Сверяет ли коробка поле у подделки (§0.1 ТЗ, 07.10.2026: прежде это
     * узнавал только перебор). FALSE — подделку с таким полем глотает, а
     * сервер её отбрасывает; пишется ТОЛЬКО по проходу. */
    d2k_tri validates_md5;
    d2k_tri validates_seq_window;
    d2k_tri validates_timestamps;
    /* Перекрытие длиной до конца имени взято: коробка оставляет первую копию
     * всей сигнатуры. Только по проходу. */
    d2k_tri overlap_covers_sni;
    /* Учитывает ли коробка срочный байт TCP. Только по проходу: взяла зонд со
     * срочным байтом в середине имени — значит имя прочла с лишним байтом и
     * не узнала (гистограмма 23.10.2026: 111 из 124 попаданий перебора). */
    d2k_tri handles_urgent;
    int     hop_ttl;
} d2k_dprops;

/* Один зонд: как писали и что получили. */
typedef struct {
    char probe[160];
    int  cuts[4];
    int  ncuts;
    int  delay_ms;
    int  pass;
    int  fail;
    char err[160];
    /* ВОПРОС НЕ ЗАДАВАЛСЯ: ответ взят из знания о коробке (d2k_opts.known), и
     * зондов он не стоил. Признаком, а не пометкой в имени: имя вопроса едет
     * в трассу вердикта ярлыком (d2k_verdict.h, D2K_QLABEL_MAX), и приписка к
     * нему обрезалась бы ровно на самых длинных вопросах. pass/fail при этом
     * нули, и исход «вопрос не прошёл» читается как прежде. */
    int  from_known;
    /* Ответ взят из прежнего прогона того же входа (d2k_opts.known), зондов в
     * этом прогоне не было (этап 25). Счёт pass/fail — прежнего прогона. */
    int  seeded;
} d2k_obs;

/* ОТВЕТ ВОПРОСА О СВОЙСТВЕ, УЖЕ ПОЛУЧЕННЫЙ ТЕМ ЖЕ ВХОДОМ (этап 25): ярлык
 * вопроса (как в трассе, без «свойство:»), счёт повторов. Применяется только
 * при known_repeats == repeats прогона; локальные ошибки (UNKNOWN) сюда не
 * кладутся — такие вопросы задаются заново. */
#include "d2k_run_cache.h"
#define D2K_KNOWN_MAX 16
typedef struct {
    char label[64];
    int  pass;
    int  fail;
} d2k_known_prop;

#define D2K_TRACE_MAX 512
#define D2K_NOTES_MAX 8
#define D2K_ANSWERED_MAX 16

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

    /* Замер БРОШЕН по требованию вызывающего: то, что успели измерить, верно,
     * но дерево пройдено не до конца. Вердикт такого прогона не утверждает
     * ничего о цели — см. переходник, он не пускает его дальше. */
    int  stopped;
    /* Замер НЕ СОСТОЯЛСЯ из-за истечения нашего срока на подключение
     * (d2k_dial_deadline_err): это не отказ цели и не неубедительный замер. */
    int  dial_deadline;

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

    /* СТРУКТУРНАЯ находка, а не только её текст. Строка стратегии написана в
     * терминах nfqws2 — она для человека и для донора; датапат d2k принимает
     * план, и собирать его из разбора собственной же строки значило бы завести
     * две формы одного знания. Поэтому сработавшая гипотеза отдаётся как есть. */
    int        has_hit;
    d2k_poison hit;

    d2k_preflight_meas preflight;
    d2k_dprops props;
    /* Каким из трёх путей получен ответ: "свойство", "собрано", "перебор". */
    char path[32];
    int  composed;
    int  raw_usable;
    /* Самопроверка сырого слоя ПРОГНАНА и не прошла ни разу. Отлично от
     * raw_usable=0, которое остаётся и там, где до самопроверки не дошли. */
    int  raw_selftest_failed;
    /* Самопроверка взята из кэша процесса (см. classify.c): слой уже прошёл
     * её на этом процессе, и зонда в этом прогоне не было. */
    int  raw_selftest_cached;
    /* Исходы сырых зондов прогона: дошло ли наше рукопожатие (rc>=0) или
     * зонд упал локальной ошибкой (rc<0). Ими прогон с кэшированной
     * самопроверкой решает, не пора ли перепроверить сам слой. */
    int  raw_probes_ok;
    int  raw_probes_err;
    /* Счётчик отказов правила подавления RST на старте прогона: прогон
     * недостоверен, только если отказ случился в НЁМ (d2kc живёт сутками,
     * и один давний отказ не должен метить все последующие прогоны). */
    unsigned long rst_fail_base;
    /* Счётчик сырых соединений потока на старте: ходил ли прогон сырым слоем. */
    unsigned long raw_dial_base;

    /* Гипотезы, на которые вопросы о свойствах получили ответ сети (без
     * локальной ошибки зонда). Ответ засчитывается только при единогласии,
     * поэтому повтор дал бы тот же исход: перебор их второй раз не спрашивает. */
    d2k_poison answered[D2K_ANSWERED_MAX];
    int        nanswered;

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
    int  preflight_auto; /* the raw gate measures its own baseline */
    int  preflight_combined; /* permit explicit composed application trials */
    int  preflight_ipv6; /* IPv6 path with the matching firewall rules */
    const char *response_probe_name; /* name from a recent direct exchange */
    /* Метка SO_MARK для ВСЕХ сокетов прогона — и обычных, и сырых. Ноль
     * означает «взять D2K_BYPASS_MARK», а не «не метить»: непомеченный зонд
     * идёт сквозь наш обход, и «обходить нечего» в таком прогоне было бы
     * самоподтверждающимся. Чтобы честно не метить, задайте её явно. */
    uint32_t mark;
    /* Кто и когда просит бросить замер. Пустое поле — не бросать никогда. */
    d2k_detect_stop cancel;
    /* ХОД ПОИСКА НАРУЖУ, ПО ЗОНДУ ЗА РАЗ.
     *
     * Трасса печатается в конце, и это годится для инструмента, который
     * человек ждёт. Для службы — нет: поиск на трудной цели идёт десятки
     * минут, и всё это время «идёт» ничем не отличается от «висит». 17.09
     * это стоило двух прогонов стенда вслепую, прежде чем стало ясно, что
     * замер вообще жив.
     *
     * Зовётся СРАЗУ после того, как наблюдение закончено и записано в трассу,
     * из того же потока. Ничего не решает и ни на что не влияет: вызывающий
     * волен печатать, считать или игнорировать. */
    void (*on_obs)(void *ctx, const d2k_obs *o);
    void *on_obs_ctx;
    d2k_trigger control;
    /* ТЕЛО ПРИМАНКИ, ОТДЕЛЬНО ОТ КОНТРОЛЬНОГО ТРИГГЕРА (замысел 2026-10-23
     * «приманка: много фейков, а не один», п. 5.1).
     *
     * Приманка и контроль — два РАЗНЫХ измерения, и одни байты на оба им не
     * годятся. Контроль доказывает, что до цели доходит безобидное
     * приветствие с другим именем; приманка травит буфер пересборки коробки,
     * и коробка, разбирающая L7, смотрит В НЕЁ. Документация nfqws (bol-van,
     * docs/readme.md) задаёт фейк отдельной опцией `--dpi-desync-fake-tls`,
     * причём МНОГОКРАТНО и с любым фингерпринтом, — то есть источник тела
     * фальшивки у инструмента свой, не контрольный.
     *
     * Пусто (len 0) — приманка берётся из control, то есть прежнее поведение. */
    d2k_trigger decoy;
    /* БЕЛОЕ ИМЯ СЕТИ ПРИМАНКОЙ (поле 10.10.2026). Полный ClientHello-record с
     * подтверждённым белым именем сети, НЕ имя контроля: вопрос «приветствие
     * под меткой времени» шлёт именно его. Пусто (len 0) — белое имя не
     * известно, вопрос не задаётся. Заполняет планировщик через свой крючок,
     * измеритель его не выдумывает. */
    d2k_trigger white;
    /* accept — фильтр находок: вернул 0, перебор идёт дальше, как будто
     * гипотеза не сработала. Нужен поиску приёма, общего для двух приветствий. */
    int (*accept)(const d2k_poison *p, void *ctx);
    void *accept_ctx;
    /* ОТВЕТ БАЗЫ УЖЕ ИЗВЕСТЕН (задача 32 d2k). Тот же вопрос "whole" — тем же
     * триггером, с тем же числом повторов — только что задан отдельно; полный
     * прогон берёт его исход, а не задаёт вопрос второй раз. Применяется лишь
     * при seed_repeats == repeats (после умолчаний). err непуст — была ошибка
     * транспорта (has_err у донора). Зондов база в этом прогоне не тратит. */
    int  seed_whole;
    int  seed_repeats;
    int  seed_pass;
    int  seed_fail;
    char seed_err[160];
    /* ЗНАНИЕ О КОРОБКЕ, УЖЕ ИЗМЕРЕННОЕ РАНЬШЕ (23.10.2026). Вопрос, чей ответ
     * здесь означает «приём НЕ проходит», не задаётся: он заведомо потратил бы
     * повторы на уже известный промах. Вопрос, чей ответ означает «проходит»,
     * задаётся ВСЁ РАВНО — прошедший вопрос и есть доказательство приёма на
     * проводе (§0.1), а доказательство обязано быть свежим для этой сети.
     * Нули — знания нет, и тогда опрос идёт как раньше. */
    d2k_box_props known;
    /* ОТВЕТЫ ВОПРОСОВ О СВОЙСТВАХ ИЗ ПРЕЖНЕГО ПРОГОНА ТОГО ЖЕ ВХОДА (этап 25):
     * прогон, прерванный уступкой или отменой, успел измерить часть свойств;
     * перезапуск тем же триггером берёт их исходы вместо повторных зондов.
     * Контекст (цель, порт, байты триггера) сверяет вызывающий. */
    d2k_known_prop known_answers[D2K_KNOWN_MAX];
    int  nknown;
    int  known_repeats;
    d2k_run_cache *run_cache;
} d2k_opts;

void d2k_opts_defaults(d2k_opts *o);
int  d2k_opts_acceptable(const d2k_opts *o, const d2k_poison *p);
int  d2k_opts_skipped(const d2k_opts *o, const char *name);
/* Байты приманки прогона: opt->decoy, если задан, иначе opt->control. */
const d2k_trigger *d2k_opts_decoy(const d2k_opts *o);

/* РАССТОЯНИЕ ДО КОРОБКИ В ХОПАХ, двоичным поиском по отрезку прохода
 * фальшивки (detect/props.c). Возвращает найденное число и пишет его в
 * res->props.hop_ttl; 0 — НЕ ИЗМЕРЕНО: отрезка прохода нет, повторы
 * разошлись либо зонд не ушёл (§2.4). Расстояние — свойство коробки, не
 * цели: измеренное один раз, оно хранится в её записи каталога и следующей
 * цели зондов не стоит. */
int  d2k_hop_search(const uint8_t *ip4, uint8_t family, uint16_t port,
                    const d2k_trigger *tr, const d2k_opts *opt, d2k_result *res);

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

/* No SYN-ACK before the raw handshake deadline; no trigger was sent.
 * Distinct from local errors (-1) and a sent trigger that did not pass (0). */
#define D2K_RAW_CONNECT_TIMEOUT (-2)

int  d2k_raw_supported(void);
/* Счётчики ПОТОКА (прогон идёт в одном потоке целиком): отказы вставки
 * правила подавления RST и сырые соединения. Прогон сравнивает их со своим
 * стартом; чужой поток на них не влияет. */
unsigned long d2k_raw_rst_fail_count(void);
unsigned long d2k_raw_dial_count(void);
/* Повторить отложенные снятия правил (перед пачкой зондов; при выходе
 * процесса — само, через atexit). Сколько их сейчас — для теста и журнала. */
void d2k_raw_flush_pending(void);
size_t d2k_raw_pending_count(void);
/* Код возврата команды правила, убитой по сроку (не статус waitpid). */
#define D2K_RAW_RULE_KILLED (-2)
/* Запуск команды правила подавления RST (iptables -I/-D). По умолчанию
 * system(); тест подменяет, чтобы проверить зонд без root и iptables.
 * Есть только там, где есть сырой слой (Linux или тестовая сборка). */
typedef int (*d2k_raw_rule_fn)(const char *cmd);
extern d2k_raw_rule_fn d2k_raw_rule_hook;
/* probe_poison — ОДИН зонд, собранный из независимых приёмов.
 * Возврат: 1 — прошло, 0 — не прошло, -1 — ошибка зонда (err заполнен);
 * D2K_RAW_CONNECT_TIMEOUT — TCP не установился, триггер не отправлен. */
int  d2k_raw_probe_poison(const uint8_t ip4[4], uint16_t port,
                          const d2k_trigger *tr, const d2k_poison *p,
                          int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                          char *err, size_t errcap);
int  d2k_raw_probe_handshake(const uint8_t ip4[4], uint16_t port,
                             int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                             char *err, size_t errcap);

/* Принимает ли адрес ДАННЫЕ вообще (задача 54): своё обычное соединение,
 * один нейтральный байт (не запись TLS, не начало HTTP — матчить нечего) и
 * ожидание, пока TCP сервера его подтвердит. Подтверждение даёт ядро
 * сервера, а не его приложение, поэтому ответ не зависит от того, какие
 * имена сервер обслуживает (урок googlevideo 2026-08-28, где молчал контроль).
 * Возврат: 1 — байт подтверждён или сервер/путь как-то отреагировал
 * (данные, FIN, RST); 0 — тишина: за срок не подтверждён; -1 — локальная
 * ошибка или нет TCP (err заполнен); -2 — подтверждение на этой платформе
 * не наблюдается (err заполнен, соединения не было). */
int d2k_probe_data_ack(const char *host, const char *port, const d2k_opts *opt,
                       char *err, size_t errcap);

/* --- гипотезы (poison.c) ------------------------------------------------ */
int d2k_raw_probe_handshake_family(const uint8_t *ip, uint8_t family, uint16_t port,
    int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel, char *err, size_t errcap);
/* ТА ЖЕ САМОПРОВЕРКА НАБОРОМ ОПЦИЙ КЛИЕНТА (ревью ветки, находка 7). Прежняя
 * подпись всегда предлагала метку времени, а вопросы клиента без метки её не
 * предлагают: путь, который не отвечает на SYN без метки, давал промахи во
 * всех вопросах и живой слой в самопроверке — промахи зачлись бы ответами
 * коробки, а это запрет §2.4. Слой обязан ручаться за ТУ форму потока,
 * которой идут вопросы. offer_ts — из d2k_trigger_offers_ts. */
int d2k_raw_probe_handshake_as(const uint8_t *ip, uint8_t family, uint16_t port,
    int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel, int offer_ts,
    char *err, size_t errcap);
typedef enum {
    D2K_RAW_OBS_LOCAL = 0, D2K_RAW_OBS_CONNECT_TIMEOUT,
    D2K_RAW_OBS_CONNECT_RESET, D2K_RAW_OBS_CANCELLED,
    D2K_RAW_OBS_RESPONSE_TIMEOUT, D2K_RAW_OBS_RESPONSE_RESET,
    D2K_RAW_OBS_RESPONSE_BYTES, D2K_RAW_OBS_ACCEPTED,
    D2K_RAW_OBS_RESPONSE_ACK, D2K_RAW_OBS_RESPONSE_FIN, D2K_RAW_OBS_RESPONSE_PACKET
} d2k_raw_observation_kind;
typedef struct {
    uint64_t received_packets, received_payload_bytes, ack_packets, ack_advances;
    uint32_t sent_end, acked_end;
    uint16_t peer_window_raw;
    uint8_t available, ack_seen, window_seen;
} d2k_raw_transport;
typedef struct {
    d2k_raw_observation_kind kind;
    /* Cumulative post-handshake observations on this owned episode. Payload
       bytes include retransmissions; ACKs are observations, not origin proof.
       Offsets cover at most the unambiguous TCP half-space. Window is unscaled. */
    d2k_raw_transport transport;
    uint32_t rtt_ms; /* SYN to SYN-ACK; zero if retransmitted/unknown */
    int connected, sent;
    size_t response_bytes;
    /* Plan actions and successful socket submissions; not a delivery proof.
       A partial execution must not train a model of the complete program. */
    size_t program_packets, submitted_packets;
} d2k_raw_observation;
typedef struct d2k_raw_episode d2k_raw_episode;
typedef struct {
    uint8_t local[16],remote[16],family;
    uint16_t local_port,remote_port;
    uint32_t initial_seq;
} d2k_raw_tuple;
/* Actual connection coordinates, not a guessed flow or a plan identifier. */
int d2k_raw_episode_tuple(const d2k_raw_episode *,d2k_raw_tuple *);
/* One owned TCP connection, not a claim that a remote filter was reset.
   Offsets are relative to our first data sequence number. The experiment
   specifies send and next-ACK offsets explicitly, including retransmissions
   and overlaps; this transport does not infer endpoint stream equivalence. */
d2k_raw_episode *d2k_raw_episode_open(const uint8_t *, uint8_t, uint16_t,
    int, uint32_t, int, const d2k_detect_stop *, char *, size_t, d2k_raw_observation *);
/* Optional IPv4 probe shape. NULL preserves the legacy episode exactly.
   Zero windows select 65535; scale -1 selects the legacy scale 7. */
typedef struct {
    uint16_t sport, syn_window;
    int8_t syn_wscale;
    uint16_t data_window;
    uint8_t defer_response_ack; /* event(): ACK on next read, allowing RST instead. */
    uint8_t initial_seq_known;
    uint32_t initial_seq;
    uint16_t syn_retry_ms; /* Both zero: ordinary exponential TCP retries. */
    uint8_t syn_max_sends;
} d2k_raw_shape;
d2k_raw_episode *d2k_raw_episode_open_shaped(const uint8_t *, uint8_t, uint16_t,
    int, uint32_t, int, const d2k_raw_shape *, const d2k_detect_stop *, char *, size_t,
    d2k_raw_observation *);
int d2k_raw_episode_set_window(d2k_raw_episode *, uint16_t);
/* Sends current-sequence RST, then closes this episode (free still required).
   Only its own RST suppression is lifted, for the duration of the send. */
int d2k_raw_episode_reset(d2k_raw_episode *);
int d2k_raw_episode_send(d2k_raw_episode *, uint32_t, uint32_t, const d2k_trigger *,
    const char *, const d2k_detect_stop *, char *, size_t, d2k_raw_observation *);
/* 0: requested prefix read; -1: timeout/reset/cancel/FIN; -2: local error.
   have remains meaningful on a partial read. Timeout keeps the connection;
   local error, cancellation, reset and FIN invalidate it. FIN accompanying
   a complete prefix is reported with rc=0 and retained for the next read. */
int d2k_raw_episode_read(d2k_raw_episode *, int, const d2k_detect_stop *,
    uint8_t *, size_t, size_t *, size_t, d2k_raw_observation *);
typedef struct {
    uint8_t flags;
    uint32_t sequence_offset, ack_offset;
    int ack_in_sent_range;
    size_t payload_len;
} d2k_raw_packet_event;
/* One received packet, including pure ACKs. Sequence coordinates belong to
   this connection. In-range ACK is not proof of origin or application success.
   Payload is copied without truncation; caller owns stream reassembly. */
int d2k_raw_episode_event(d2k_raw_episode *, int, const d2k_detect_stop *,
    uint8_t *, size_t, d2k_raw_packet_event *, d2k_raw_observation *);
void d2k_raw_episode_free(d2k_raw_episode *);

/* Execute an exact synthesized Plan through the same runtime as the
 * datapath. A positive result is trigger acceptance, not application proof. */
int d2k_raw_probe_program(const uint8_t *, uint8_t, uint16_t,
    const d2k_trigger *, const char *, int, uint32_t,
    const d2k_detect_stop *, char *, size_t, d2k_raw_observation *);
int d2k_raw_probe_observed(const uint8_t *, uint8_t, uint16_t,
    const d2k_trigger *, const d2k_poison *, int, uint32_t,
    const d2k_detect_stop *, char *, size_t, d2k_raw_observation *);
int d2k_raw_probe_poison_family(const uint8_t *ip, uint8_t family, uint16_t port,
    const d2k_trigger *tr, const d2k_poison *p, int timeout_ms, uint32_t mark,
    const d2k_detect_stop *cancel, char *err, size_t errcap);
/* Потолок сегмента сырого отправителя замера. Ядро ставит d2k_arm_segment(предел
 * датапата), чтобы измеренное уходило теми же сегментами, что исполненное
 * (поле 22.10.2026, issue #5/#7). 0 — вернуть прежние 1400 (D2K_ARM_SEGMENT_MAX). */
void d2k_raw_set_segment_max(unsigned seg);
unsigned d2k_raw_segment_max(void);
/* Ответ вопроса о свойствах — большинством повторов (props.c): при N = 3 —
 * два прохода, при N = 1 — один. Общий для измерителя и моста (bridge.c). */
static inline int d2k_prop_majority(int pass, int repeats)
{
    return repeats > 0 && pass * 2 > repeats;
}

int d2k_run_properties_family(const uint8_t *ip, uint8_t family, uint16_t port,
    const d2k_trigger *tr, const d2k_opts *opt, d2k_result *res, d2k_poison *hit);
/* Каждый сырой зонд отравления отдаёт сюда свой код возврата: счёт прогона
 * и общий на процесс счёт подряд идущих локальных ошибок (rc<0). Серия таких
 * ошибок снимает кэш самопроверки — следующий прогон проверит слой заново. */
void d2k_raw_note_rc(d2k_result *res, uint8_t family, int rc);

const d2k_poison *d2k_poisons(int *n);
int d2k_poison_supports_family(const d2k_poison *p, uint8_t family);
void d2k_strategy_for_poison(const d2k_poison *p, char *out, size_t cap);
void d2k_strategy_for(int pos, char *out, size_t cap);
void d2k_note_props_hit(d2k_dprops *pr, const d2k_poison *p);
void d2k_note_props_miss(d2k_dprops *pr, const d2k_poison *p);

/* --- свойства (props.c) ------------------------------------------------- */

int d2k_run_properties(const uint8_t ip4[4], uint16_t port,
                       const d2k_trigger *tr, const d2k_opts *opt,
                       d2k_result *res, d2k_poison *hit);
int d2k_compose_from_props(const d2k_dprops *pr, const uint8_t *ctl, size_t ctl_len,
                           d2k_poison *out, int cap);

/* --- триггеры (trigger.c) ----------------------------------------------- */

int d2k_trigger_tls(const char *sni, int legacy, d2k_trigger *out, char *err, size_t errcap);
int d2k_trigger_raw_hex(const char *hex, d2k_trigger *out, char *err, size_t errcap);
int d2k_trigger_control(const char *tag, d2k_trigger *out, char *err, size_t errcap);

/* --- мелочи, общие для модулей ------------------------------------------ */

/* Монотонные миллисекунды, ВСЕГДА 64 бита: на mipsel/armv7 long — 32 бита, и
 * tv_sec*1000L переполнялся на 24,8 сутках аптайма (ревью detect M7), ломая
 * сроки зондов и команд правил. Хранить результат — только в int64_t. */
int64_t d2k_now_ms(void);
/* Сдвиг часов для теста (имитация долгого аптайма); в работе 0. */
extern int64_t d2k_clock_offset_ms;
void d2k_sleep_ms(int ms);
int d2k_sleep_us(uint32_t us);
d2k_obs *d2k_trace_add(d2k_result *res, const char *probe);
void d2k_note(d2k_result *res, const char *fmt, ...);
/* send без SIGPIPE: мёртвый пир даёт -1/EPIPE, а не гибель процесса. */
ssize_t d2k_send_nosig(int fd, const void *buf, size_t len);
/* Нейтральное имя контроля: свежая случайная метка из ОС-ГСЧ. */
void d2k_neutral_sni(char *out, size_t cap);

#endif /* D2K_DETECT_H */
