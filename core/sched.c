/* sched.c — планировщик поисков, один на оба транспорта. См. d2k_sched.h.
 *
 * УСТРОЙСТВО В ОДИН АБЗАЦ. Датапат шлёт события; цикл (d2kc.c) отдаёт их сюда
 * по одному. Приветствие (D2K_EV_HELLO) запоминает имя за ключом потока —
 * подозрение имени не несёт (на проводе это ключ и код причины, core/link.c),
 * и связать их иначе нечем. Подозрение (D2K_EV_SUSPECT) заводит задачу по паре
 * (имя, транспорт) и отправляет её сетевому оракулу в рабочий поток. Оракул
 * возвращается вердиктом; по вердикту собираются планы; план ставится
 * командой — и тут же ИСПЫТЫВАЕТСЯ СОБСТВЕННЫМ ЗОНДОМ.
 *
 * ПОЧЕМУ ИСПЫТЫВАЕМ САМИ. До 12.09 поставленный кандидат уходил ждать чужого
 * обмена: пока пользователь не откроет цель ещё раз, очередь не двигалась
 * вовсе. У телевизора живого потока нет — одно обращение, следующее через три
 * минуты (§4 спецификации, «почему не живой поток»), и рабочий вариант нужен
 * раньше; открывать цель несколько раз ради перебора спецификация прямо
 * отказывается. Теперь задача сама идёт к цели зондом (core/verify.c) и
 * получает ответ за секунды.
 *
 * ПОЧЕМУ ОДНОГО ЗОНДА МАЛО. Зонд доказывает, что ЛИНИЯ довела дело до
 * приложения, но не то, что она довела его С НАШИМ КАНДИДАТОМ: обход мог не
 * примениться к его пакетам вовсе, а цель — открыться сама (коробка сегодня
 * промахнулась). Вторая половина доказательства — событие применения
 * (D2K_EV_APPLIED) с идентификатором ЭТОГО плана по ключу ЭТОГО потока. Ни
 * одна половина в одиночку успехом не является.
 *
 * И ПОЧЕМУ НЕ ВНЕШНИЙ ТИП ЗАПИСИ 23. В TLS 1.3 им едет весь второй полёт
 * рукопожатия (RFC 8446 §5.2), то есть с провода «приложение ответило»
 * неотличимо от «коробка пропустила приветствие». Это наблюдение (§4.2,
 * уровень 2), и оно осталось наблюдением: поднять уровень уже подтверждённой
 * записи может, завести её — нет (d2k_ev_outer_appdata, d2k_link.h).
 *
 * ПАРА (ИМЯ, ТРАНСПОРТ), А НЕ ИМЯ. Go-сторона держит задачи по имени, и это её
 * известный дефект: комментарий в controller.go (обработка EvApplied) прямо
 * говорит, что «та же задача у TCP и QUIC к одному имени делят один *Task
 * (taskForKey резолвит по имени цели, не по ключу с протоколом)», и оттуда же
 * растёт оговорка про чужие применения. Здесь этого нет по построению: ключ
 * задачи — пара, и телевизор по QUIC не перезаписывает поиск браузера по TCP.
 *
 * ПОТОК ТОЛЬКО ПОД СЕТЕВОЙ ОРАКУЛ. d2k_classify и d2k_quic_classify —
 * блокирующие, секунды, со своими сокетами; управляющего сокета они не
 * касаются вовсе. Всё остальное делает цикл. Причина — в шапке d2k_sched.h
 * (единственное подключение к датапату) и в комментарии у Run на Go-стороне.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "d2k_compose.h"
#include "d2k_compose_internal.h"
#include "d2k_hello.h"
#include "d2k_plantlv.h"
#include "d2k_quicprobe.h"
#include "d2k_sched.h"
#include "d2k_verify.h"
#include "d2k_volume.h"

/* --------------------------------------------------------------------
 * Пределы. Перенесены с Go-стороны (internal/controller/controller.go, блок
 * «Пределы»), где они уже выведены; выдумывать здесь новые запрещено
 * проектным правилом «числа только из замера или наследования».
 * -------------------------------------------------------------------- */

/* Одновременных поисков. Больше — и рабочих потоков станет больше, чем у
   роутера есть смысла держать: каждый занят сетевым ожиданием, не счётом. */
#define SCHED_MAX_TASKS 64

/* Жизнь задачи. Дольше — и задача занимает место, давно перестав быть про
   актуальное состояние линии. */
#define SCHED_TASK_LIFE_MS (10 * 60 * 1000)

/* Отдых цели после неудачи: не долбить одну и ту же цель подряд. */
#define SCHED_REST_MS (2 * 60 * 1000)

/* Сколько выведенных планов держит задача. Это же потолок, который
   d2k_compose получает под свои плечи. */
#define SCHED_MAX_PLANS 8

/* Зондов на задачу. ЗАМЕРЕНО на живой линии 11.09 (accounts.youtube.com, та
   самая тяжёлая цель, из-за которой ревью 06.09 сказало «восьми мало»):

     19:28:26  вердикт «решает содержимое» — спрашиваю коробку о свойствах
     19:28:26  зонд вопроса 1 … 19:28:49 зонд вопроса 5   ← пять зондов
     19:28:57  поставил план 1 из 8
     19:29:40  план 1 … 19:30:12 план 2 … 19:30:42 план 3
     19:30:42  выведенные планы исчерпаны (зондов 8)      ← бюджет кончился

   Пять вопросов съели пять зондов, на планы осталось три из восьми — пять
   выведенных плечей не попробовали НИ РАЗУ, и «исчерпаны» означало «кончился
   бюджет», а не «кончились планы». Это и есть та подмена, из-за которой
   число пересматривалось.

   Новое значение не назначено с запасом, а ВЫВЕДЕНО из того, сколько зондов
   машина в принципе может потратить: пять вопросов (D2K_PROPS_QUESTIONS) плюс
   столько планов, сколько влезает в очередь (SCHED_MAX_PLANS). Больше она не
   израсходует по построению, меньше — обрежет саму себя. */
/* Reuse and new synthesis have independent bounded queues. Spending the
   reuse budget must not leave the subsequent research with no trials. */
#define SCHED_MAX_PROBES (D2K_PROPS_QUESTIONS + 2 * SCHED_MAX_PLANS)

/* Потолок ОДНОГО шага вопроса. Унаследован из D2K_PROPS_ASK_WAIT_MS (5000мс,
   compose.c) вместе с его оговоркой: это страховка от молчания, а не
   ожидаемая длительность, и для этого применения он НЕ измерен. */
#define SCHED_PROP_STEP_MS 5000

/* Потолок ОДНОГО шага испытания: столько же и по той же причине. Своего числа
   здесь взяться неоткуда — зонд идёт к той же цели по тому же транспорту, что
   и зонд вопроса, и его потолок это та же страховка от молчания. Выдумывать
   рядом второе число значило бы завести параметр, ничем не измеренный. */
#define SCHED_VERIFY_STEP_MS SCHED_PROP_STEP_MS

/* Сколько имён помним за ключами потоков. Приветствие приходит на КАЖДОЕ
   соединение, подозрение — на малую их часть; таблица нужна только чтобы
   пережить промежуток между ними. */
#define SCHED_SEEN 512

/* Имя приманки по умолчанию. Не выдумано: то же значение, что у Go-стороны в
   internal/config/config.go (DecoySNI = "disk.rzd.ru"), и по той же причине —
   имя, заведомо не связанное с целью, но реально обслуживаемое. Измеренное
   проходящее имя точнее заготовки (Go: decoyFor), но измерять его умеет пока
   только путь объёма, которого здесь ещё нет; когда появится — брать его. */
#define SCHED_DECOY "disk.rzd.ru"

/* Форма приветствия СОБСТВЕННОГО зонда — то, в чём проверка состоялась, и то,
 * что уезжает в привязку (d2k_catalog.h про shape/verified_by).
 *
 * Не назначено, а ВЫТЕКАЕТ из того, чем зонд доказывает: D2K_VER_APPLICATION
 * достижим только через ЗАВЕРШЁННОЕ рукопожатие TLS 1.3 (core/tls13.c ведёт
 * его своим ключом), а такое рукопожатие по RFC 8446 §4.2.1 невозможно без
 * расширения supported_versions с 0x0304 — ровно того признака, по которому
 * d2k_hello_shape и отличает MODERN от LEGACY. Константа, а не запрос у
 * зонда на каждом успехе: форма его приветствия не меняется от цели к цели.
 * Связь с проводом проверяется замером, а не на слово — test_sched.c,
 * probe_hello_shape: приветствие снимается с сокета и разбирается той же
 * d2k_hello_shape.
 *
 * Когда появится второй зонд (скажем, старой формы или для QUIC), форме
 * придётся приехать из d2k_ver_result, а не отсюда: одна константа на два
 * разных обращения снова превратила бы контекст проверки в догадку. */
#define SCHED_PROBE_SHAPE D2K_SHAPE_MODERN

/* --------------------------------------------------------------------
 * Подменяемые оракулы (см. d2k_sched.h).
 * -------------------------------------------------------------------- */

/* Умолчание зонда подтверждения. Прослойка, а не сам d2k_verify_probe, из-за
 * ОДНОГО: зонд ведёт TCP и своё рукопожатие TLS 1.3, а доказательство
 * принадлежит транспорту. Подтвердить им план QUIC значило бы записать успех
 * ДРУГОГО транспорта — той самой подменой, из-за которой эта вертикаль и
 * затеяна. Своего зонда для QUIC сегодня нет (quicprobe умеет спрашивать
 * Initial, а не доводить обмен приложения до конца), и честный ответ про
 * QUIC — «не измерено» (§2.4): кандидат ставится, но в каталог не попадает.
 * Когда такой зонд появится, он встанет сюда же. */
static d2k_ver_result verify_default(const char *ip, uint16_t port, uint8_t transport,
                                     const char *sni, int deadline_ms) {
    if (transport != 6) {
        d2k_ver_result r;
        memset(&r, 0, sizeof r);
        r.fd = -1;
        snprintf(r.reason, sizeof r.reason,
                 "зонда подтверждения для QUIC нет — не измерено");
        return r;
    }
    return d2k_verify_probe(ip, port, sni, deadline_ms);
}

d2k_sched_vol_fn  d2k_sched_vol_hook  = d2k_volume_probe;
d2k_sched_tcp_fn  d2k_sched_tcp_hook  = d2k_classify;
d2k_sched_quic_fn d2k_sched_quic_hook = d2k_quic_classify;
d2k_sched_ver_fn  d2k_sched_ver_hook  = verify_default;

/* --------------------------------------------------------------------
 * Состояние задачи.
 * -------------------------------------------------------------------- */

typedef enum {
    T_FREE = 0,
    T_ASKING,        /* сетевой оракул работает в потоке */
    T_PROPS_CONTACT, /* план-вопрос отправлен, обращение к цели работает в потоке */
    T_PROPS_WAIT,    /* обращение состоялось, ждём обмена по своему потоку */
    T_PLANNING,      /* вектор собран, ставим планы */
    T_VERIFY,        /* кандидат стоит, наш зонд идёт к цели в потоке */
    T_VERIFY_WAIT,   /* зонд вернулся успехом, ждём применения плана к ЕГО потоку */
    /* Подтверждено; смотрим на ЖИВОЙ трафик. Прежде это состояние означало
       «ждём, пока пользователь откроет цель» — того ожидания больше нет
       (см. шапку файла). Теперь оно означает другое: план подтверждён и
       стоит, а обмен по ПОСЛЕДУЮЩЕМУ живому соединению может поднять
       уровень записи в каталоге. Завести запись он не может. */
    T_WATCHING,
    T_RESTING        /* неудача, цель отдыхает */
} task_state;

/* Что делает рабочий поток задачи. Потоки заводятся только под сетевые
   оракулы; управляющего сокета они не касаются (см. шапку d2k_sched.h). */
typedef enum { JOB_NONE = 0, JOB_CLASSIFY, JOB_CONTACT, JOB_VERIFY } task_job;

typedef struct {
    task_state state;
    char       name[256];
    uint8_t    transport;
    char       ip[16];
    uint16_t   port;

    int64_t    started_ms;
    int64_t    rest_until_ms;
    int        probes;

    /* Приветствия. trigger — снятое датапатом, если уже поймано; иначе
       профиль холодного старта. control — приманка ДРУГИМ именем (§7). */
    uint8_t    trig[2048];
    size_t     trig_len;
    uint8_t    ctrl[2048];
    size_t     ctrl_len;
    int        shape_armed;
    /* Снимок в trig СНЯТ С ПРОВОДА, а не собран из профиля холодного старта.
       Различать обязательно: fill_hellos при пустом снимке подставляет
       профиль MODERN, и без этого признака «форма живого клиента» читалась бы
       по заготовке — то есть выдавалась бы за измерение то, что им не
       является (§2.4). Ноль означает «форма клиента не измерена». */
    int        trig_snapped;

    /* Кандидаты, собранные d2k_compose по вердикту. */
    char       plans[SCHED_MAX_PLANS][4096];
    char       plan_boxes[SCHED_MAX_PLANS][40]; /* candidate source, not established identity */
    size_t     n_plans;
    size_t     next_plan;

    /* Испытание текущего кандидата собственным зондом (§4.2, core/verify.c).

       ver_plan_id — идентификатор, С КОТОРЫМ кандидат ушёл на провод: по нему
       событие применения отличается от применения предыдущего кандидата,
       чьё событие опоздало (install_next ниже).

       ver_seen/ver_port — ПЕРВОЕ применение нашего кандидата к нашей цели,
       замеченное пока зонд ещё в сети: ключа его потока в тот момент нет,
       есть только чужой порт из события, и сверка отложена до возврата.

       ver_ok — применение сошлось с потоком зонда. Ноль здесь означает «не
       измерено», а не «плана не было» (§2.4): событие могло потеряться
       (d2k_ctl.h), и это проверяется отдельно по ver_dropped0. */
    d2k_ver_result ver;
    uint8_t    ver_plan_id[D2K_PLAN_ID_LEN];
    d2k_flowkey ver_flow;
    uint16_t   ver_port;
    int        ver_seen;
    int        ver_ok;
    int64_t    ver_until_ms;
    uint32_t   ver_dropped0;    /* сколько событий было потеряно, когда план встал */

    /* Отпечаток коробки, накопленный по приметам подозрений ЭТОЙ цели. По
       нему каталог узнаёт уже изученную коробку (d2k_catalog_match) — без
       этого каждая цель заводила бы новую «коробку», и каталог перестал бы
       быть каталогом коробок. */
    d2k_cat_fp fp;
    /* id узнанной коробки, пусто — не узнана. */
    char       box_id[40];
    /* Сколько первых кандидатов пришло из готовых планов узнанной коробки, а
       не из синтеза по вердикту: различать их нужно на записи успеха (план
       узнанной коробки не заводит новую) и в логе. */
    size_t     n_known;
    int        researched;     /* expensive measurement is a fallback, not recognition */
    int        trial_installed;

    /* Вопросы о свойствах коробки (§2.4, d2k_compose.h). Задаются ТОЛЬКО на
       вердикт «решает содержимое»: разрез такую коробку не берёт, берёт её
       отравление буфера пересборки, а чем именно — это и есть вопросы. */
    int        prop_q;          /* какой вопрос задаём, -1 — не спрашиваем */
    d2k_props  props;           /* накопленный вектор: не измерено / да / нет */
    int        props_asked;     /* хоть один вопрос задан — нужно снять план */
    d2k_flowkey prop_flow;      /* чей обмен ждём */
    int        prop_fd;         /* сокет обращения, держится до конца ожидания */
    int        prop_applied;    /* план вопроса применён к пакетам НАШЕГО зонда */
    int64_t    prop_until_ms;   /* потолок текущего шага */

    /* Рабочий поток оракула. */
    pthread_t  th;
    int        th_live;
    task_job   job;
    d2k_vres   res;
    d2k_vol_result vol;
    int        res_ready;   /* пишется потоком под мьютексом планировщика */
    /* Итог JOB_CONTACT. */
    uint8_t    c_ip[4];
    uint16_t   c_port;
    int        c_fd;
    int        c_ok;
} task;

typedef struct {
    uint8_t  low_ip[4], high_ip[4];
    uint16_t low_port, high_port;
    uint8_t  transport;
    char     name[256];
    int      used;
} seen_name;

struct d2k_sched {
    d2k_catalog *cat;
    int          link_fd;
    uint32_t     mark;

    /* Часы последнего тика. Подтверждения приходят СОБЫТИЕМ, а не по часам, и
       спрашивать время у ОС в каждом обработчике незачем: тик идёт трижды в
       секунду, а сроки здесь считаются секундами. */
    int64_t      now_ms;

    task         tasks[SCHED_MAX_TASKS];
    seen_name    seen[SCHED_SEEN];
    size_t       seen_next;   /* кольцо: старое вытесняется, а не отказывает */

    /* Проход по каталогу, разложенный на порции (см. d2k_sched_sync_step):
       где остановились и просили ли начать заново. */
    size_t       sync_box, sync_bind;
    int          sync_active, sync_pending, sync_sent, sync_skipped;

    /* Сколько событий датапат потерял к последнему отчёту. Нужно затем, что
       МОЛЧАНИЕ — не доказательство: пропавший обмен неотличим от «плана не
       сработало», и если связь в этот момент теряла события, считать молчание
       уликой нельзя (см. on_applied). */
    uint32_t     dropped_seen;

    /* Для вида панели: сколько подтверждено и сколько зондов потрачено за
       жизнь процесса, и отметка стенных часов, от которой считается «с
       какого времени идёт поиск» (внутри всё на монотонных). */
    int          confirms, probes_used;
    int64_t      wall_base_s;

    d2k_sched_say_fn say_fn;
    void            *say_ctx;

    int          wake[2];     /* самопайп: рабочий поток будит цикл */
    pthread_mutex_t mu;       /* охраняет res/res_ready/th_live задач */
};

/* --------------------------------------------------------------------
 * Мелочи.
 * -------------------------------------------------------------------- */

/* Говорит наружу, если есть кому. Сборка строки — здесь, чтобы вызывающий не
   тащил printf-обвязку в каждый вызов. */
static void say(d2k_sched *s, const char *fmt, ...) {
    if (!s->say_fn) { return; }
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    s->say_fn(s->say_ctx, line);
}

void d2k_sched_set_say(d2k_sched *s, d2k_sched_say_fn fn, void *ctx) {
    if (!s) { return; }
    s->say_fn = fn;
    s->say_ctx = ctx;
}

/* Вердикт словами. Своя таблица, а не в d2k_verdict.h: там перечисление —
   контракт измерения, а имена нужны ровно одному читателю, человеку у лога. */
static const char *verdict_name(d2k_verdict v) {
    switch (v) {
    case D2K_V_CLEAR:        return "проходит как есть";
    case D2K_V_PREFIX:       return "помогает разрез";
    case D2K_V_WHOLE:        return "нужен пакет целиком";
    case D2K_V_OPAQUE:       return "решает содержимое";
    case D2K_V_INCONCLUSIVE: return "вердикта нет";
    case D2K_V_FLAKY:        return "измерению верить нельзя";
    case D2K_V_UNREACHABLE:  return "до цели нет транспорта";
    }
    return "неизвестный вердикт";
}

/* Примета из подозрения. Порт signalOf (controller.go) — перенос, не
   пересказ, включая обе его оговорки:
   - сброс и снятый-защитой сброс дают ОДИН вид "rst": различие между ними —
     наша РЕАКЦИЯ, а отпечаток описывает поведение КОРОБКИ; разведи их, и одна
     коробка попала бы в каталог дважды;
   - TTL, ToS и идентификатор берутся ТОЛЬКО у сброса: у молчания и повтора
     подделанного пакета нет вовсе, и подставлять туда нули значило бы
     сравнивать приметы по полям, которых не измеряли. */
static d2k_cat_signal signal_of(const d2k_ev *ev) {
    d2k_cat_signal s;
    memset(&s, 0, sizeof s);
    s.seen = 1;
    switch (ev->code) {
    case 1: case 4: snprintf(s.kind, sizeof s.kind, "rst"); break;
    case 2:         snprintf(s.kind, sizeof s.kind, "repeat"); break;
    case 3:         snprintf(s.kind, sizeof s.kind, "silent"); break;
    default:        snprintf(s.kind, sizeof s.kind, "код-%u", (unsigned)ev->code); break;
    }
    if (strcmp(s.kind, "rst") == 0) {
        /* TTL самой подделки — примета коробки: она стоит на фиксированном
           расстоянии от нас. Разность с TTL сервера сохраняется как
           наблюдение, но приметой не является: серверы стоят на разном
           расстоянии (замер: на четырёх целях одной линии разности были
           3, 38, 40 и 74 при одном и том же TTL подделки 127). */
        s.ttl = ev->ttl;
        s.ttl_delta = (int)ev->ttl - (int)ev->ref_ttl;
        s.tos = ev->tos;
        s.ipid = ev->ipid;
    }
    return s;
}

/* Добавляет примету к отпечатку, схлопывая совпавшие. Допуск по TTL тот же,
   что в каталоге (D2K_TTL_SLACK): иначе задача накопит приметы, которые
   каталог потом сочтёт одной. Порт addSignal (controller.go). */
static void fp_add(d2k_cat_fp *fp, const d2k_cat_signal *sig) {
    for (size_t i = 0; i < fp->n_sig; i++) {
        d2k_cat_signal *x = &fp->sig[i];
        int d = (int)x->ttl - (int)sig->ttl;
        if (d < 0) { d = -d; }
        if (strcmp(x->kind, sig->kind) == 0 && d <= D2K_TTL_SLACK &&
            x->ipid == sig->ipid && x->tos == sig->tos) {
            x->seen += sig->seen;
            return;
        }
    }
    if (fp->n_sig >= sizeof fp->sig / sizeof fp->sig[0]) {
        return; /* приметы кончились — восьми хватает с запасом (d2k_catalog.h) */
    }
    fp->sig[fp->n_sig++] = *sig;
}

static void ip_text(const uint8_t ip[4], char *out, size_t cap) {
    snprintf(out, cap, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

/* Начало эфемерного диапазона Linux (ip_local_port_range, умолчание
   32768-60999). Не «порт сервера» и не список сервисов — граница, из которой
   клиентские порты берутся ядром. */
#define EPHEMERAL_FROM 32768

/* Кто из пары ключа — сервер.
 *
 * Ключ на проводе (13 байт: два адреса, два порта, протокол —
 * D2K_KEY_WIRE_LEN, d2k_ctlsrv.h) УПОРЯДОЧЕН канонизацией, а не по ролям:
 * который конец клиент, а который сервер, он не несёт вовсе. Роль приходится
 * выводить, и это ограничение СЕГОДНЯШНЕГО ключа, а не недосмотр здесь — ровно
 * как у SET_NAME сегодня нет места под транспорт (d2k_link.h).
 *
 * Правило: клиентский порт ядро берёт из эфемерного диапазона, серверный —
 * тот, который слушают. Если ровно один порт пары эфемерный, второй конец и
 * есть сервер. Если оба или ни одного (сервис на высоком порту и клиент,
 * попавший туда же; либо связь между двумя низкими портами) — берём меньший
 * порт: различать их больше нечем, и назвать правило честнее, чем взять
 * первый попавшийся молча.
 *
 * Go-сторона решает это же place'ом `if k.LowPort == 443` (controller.go,
 * serverOf) — то есть зашитым номером порта. Повторять это здесь нельзя:
 * охват d2k — весь IP-трафик, все порты всегда, а не 443. */
static void server_of(const d2k_ev *ev, char *ip, size_t ipcap, uint16_t *port) {
    int low_eph  = ev->low_port  >= EPHEMERAL_FROM;
    int high_eph = ev->high_port >= EPHEMERAL_FROM;
    int server_is_low;
    if (low_eph != high_eph) {
        server_is_low = high_eph; /* эфемерный — клиент, значит сервер другой */
    } else {
        server_is_low = ev->low_port <= ev->high_port;
    }
    if (server_is_low) {
        ip_text(ev->low_ip, ip, ipcap);
        *port = ev->low_port;
    } else {
        ip_text(ev->high_ip, ip, ipcap);
        *port = ev->high_port;
    }
}

static int same_flow(const seen_name *s, const d2k_ev *ev) {
    return s->used && s->transport == ev->transport &&
           s->low_port == ev->low_port && s->high_port == ev->high_port &&
           memcmp(s->low_ip, ev->low_ip, 4) == 0 &&
           memcmp(s->high_ip, ev->high_ip, 4) == 0;
}

static void remember(d2k_sched *s, const d2k_ev *ev) {
    if (ev->name[0] == '\0') { return; }
    for (size_t i = 0; i < SCHED_SEEN; i++) {
        if (same_flow(&s->seen[i], ev)) {
            snprintf(s->seen[i].name, sizeof s->seen[i].name, "%s", ev->name);
            return;
        }
    }
    seen_name *slot = &s->seen[s->seen_next];
    s->seen_next = (s->seen_next + 1) % SCHED_SEEN;
    memset(slot, 0, sizeof *slot);
    memcpy(slot->low_ip, ev->low_ip, 4);
    memcpy(slot->high_ip, ev->high_ip, 4);
    slot->low_port = ev->low_port;
    slot->high_port = ev->high_port;
    slot->transport = ev->transport;
    snprintf(slot->name, sizeof slot->name, "%s", ev->name);
    slot->used = 1;
}

static const char *recall(const d2k_sched *s, const d2k_ev *ev) {
    for (size_t i = 0; i < SCHED_SEEN; i++) {
        if (same_flow(&s->seen[i], ev)) { return s->seen[i].name; }
    }
    return NULL;
}

static task *task_of(d2k_sched *s, const char *name, uint8_t transport) {
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        if (s->tasks[i].state != T_FREE && s->tasks[i].transport == transport &&
            strcmp(s->tasks[i].name, name) == 0) {
            return &s->tasks[i];
        }
    }
    return NULL;
}

static task *task_free_slot(d2k_sched *s) {
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        if (s->tasks[i].state == T_FREE) { return &s->tasks[i]; }
    }
    return NULL;
}

/* Задача, которая своё уже отдала: подтверждена и только смотрит на живой
   трафик (T_WATCHING). Её место уступается новому поиску, когда свободных не
   осталось: знание такой задачи ЛЕЖИТ В КАТАЛОГЕ, и потерять от её закрытия
   можно только возможный подъём уровня записи — а отказ новому подозрению
   стоит целого поиска. До 12.09 этого выбора не было: подтверждённая задача
   освобождала место сразу. */
static task *task_watching_slot(d2k_sched *s) {
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        if (s->tasks[i].state == T_WATCHING) { return &s->tasks[i]; }
    }
    return NULL;
}

/* --------------------------------------------------------------------
 * Приветствия задачи: снятое, если есть; иначе профиль холодного старта.
 * -------------------------------------------------------------------- */

static int fill_hellos(task *t) {
    if (t->trig_len == 0) {
        /* Холодный старт: снимка ещё нет. Профиль — это заведомо НЕ те байты,
           что шлёт настоящий клиент (§4), и вердикт на нём слабее; но
           альтернатива — не измерять вовсе, пока цель не откроют второй раз.
           Снимок закажем параллельно (arm_shape ниже) и со следующего раза
           будем мерить уже им. MODERN, а не LEGACY: современный клиент —
           то, чем ходит браузер сегодня, и мерить им ближе к правде. */
        if (d2k_hello_from_profile(D2K_SHAPE_MODERN, t->name,
                                   t->trig, sizeof t->trig, &t->trig_len) != 0) {
            return -1;
        }
    }
    if (t->ctrl_len == 0 && strcmp(t->name, SCHED_DECOY) != 0) {
        d2k_shape sh = d2k_hello_shape(t->trig, t->trig_len);
        if (d2k_hello_from_profile(sh, SCHED_DECOY,
                                   t->ctrl, sizeof t->ctrl, &t->ctrl_len) != 0) {
            t->ctrl_len = 0; /* контроль — законно пустой: дерево отвечает за это само */
        }
    }
    return 0;
}

/* --------------------------------------------------------------------
 * Рабочий поток: сетевой оракул.
 * -------------------------------------------------------------------- */

typedef struct { d2k_sched *s; task *t; } worker_arg;

static void *worker_run(void *vp) {
    worker_arg *a = (worker_arg *)vp;
    d2k_sched *s = a->s;
    task *t = a->t;
    free(a);

    d2k_hello trig; trig.bytes = t->trig; trig.len = t->trig_len;
    d2k_hello ctl;  ctl.bytes  = t->ctrl_len ? t->ctrl : NULL; ctl.len = t->ctrl_len;

    if (t->job == JOB_VERIFY) {
        /* Испытание кандидата: своё рукопожатие TLS 1.3 своим ключом и
           настоящий запрос (d2k_verify.h). Блокирует НА СЕКУНДЫ — потому и
           живёт в рабочем потоке: цикл d2kc не блокируется никогда.
           Сокет остаётся ОТКРЫТЫМ: закроет его цикл, после решения (см.
           d2k_props_contact о том, что FIN удаляет ячейку потока раньше
           события применения). */
        d2k_ver_result vr = d2k_sched_ver_hook(t->ip, t->port, t->transport,
                                               t->name, SCHED_VERIFY_STEP_MS);
        pthread_mutex_lock(&s->mu);
        t->ver = vr;
        t->res_ready = 1;
        pthread_mutex_unlock(&s->mu);
        ssize_t ignv = write(s->wake[1], "w", 1);
        (void)ignv;
        return NULL;
    }

    if (t->job == JOB_CONTACT) {
        /* ОДНО обращение к цели — общее с d2kask (d2k_props_contact,
           compose.c): непомеченное (иначе только что поставленный план-вопрос
           прошёл бы мимо очереди нетронутым) и с ОТКРЫТЫМ сокетом наружу
           (иначе FIN удалит ячейку потока раньше ответа сервера, и обмену не
           с чем будет связаться). Закрывает сокет цикл, после ожидания. */
        uint8_t ip4[4];
        uint16_t lport = 0;
        int fd = -1;
        int rc = d2k_props_contact(t->ip, t->port, trig, ip4, &lport, &fd);
        pthread_mutex_lock(&s->mu);
        memcpy(t->c_ip, ip4, 4);
        t->c_port = lport;
        t->c_fd = fd;
        t->c_ok = (rc == 0);
        t->res_ready = 1;
        pthread_mutex_unlock(&s->mu);
        ssize_t ign = write(s->wake[1], "w", 1);
        (void)ign;
        return NULL;
    }

    /* Проба на объём идёт ПЕРВОЙ, и это не порядок ради порядка: пока её
       ответ неизвестен, вопрос «режут по имени или по адресу» ЛЖЁТ — при
       блоке по объёму рукопожатие проходит с любым именем, поток умирает и
       там и там, и ответ всегда получается «по адресу» (шапка d2k_volume.h).
       Только TCP: у QUIC нет установленного потока в этом смысле, и лестница
       HTTP-запросов туда неприменима. */
    if (t->transport == 6) {
        t->vol = d2k_sched_vol_hook(t->ip, t->port, t->name, t->port == 80, s->mark);
        if (t->vol.verdict == D2K_VOL_CUT) {
            /* Разрезом этот класс не лечится вовсе: режется не рукопожатие.
               Дальше мерить дерево вердиктов незачем — оно ответит про имя и
               адрес то, что диктует оборванный поток, а не коробка. */
            pthread_mutex_lock(&s->mu);
            memset(&t->res, 0, sizeof t->res);
            t->res.verdict = D2K_V_INCONCLUSIVE;
            snprintf(t->res.reason, sizeof t->res.reason,
                     "обрыв по объёму на %d КБ — разрезом не лечится", t->vol.at_kb);
            t->res_ready = 1;
            pthread_mutex_unlock(&s->mu);
            ssize_t ign2 = write(s->wake[1], "w", 1);
            (void)ign2;
            return NULL;
        }
    }

    d2k_vres r;
    if (t->transport == 17) {
        r = d2k_sched_quic_hook(t->ip, t->port, t->name, trig, ctl, s->mark);
    } else {
        /* repeats<=0 — то же умолчание (три), что у d2k_meas: второе число
           здесь развело бы два места по умолчанию (d2k_verdict.h). gap/wait
           нулями — та же передача умолчания вниз. */
        r = d2k_sched_tcp_hook(t->ip, t->port, trig, ctl, s->mark, 0, 0, 0);
    }

    pthread_mutex_lock(&s->mu);
    t->res = r;
    t->res_ready = 1;
    pthread_mutex_unlock(&s->mu);

    /* Разбудить цикл: без этого вердикт лежал бы до следующего события
       датапата или тика — секунды на ровном месте. Один байт, и отказ записи
       не беда: цикл всё равно проснётся по тику. */
    ssize_t ignored = write(s->wake[1], "w", 1);
    (void)ignored;
    return NULL;
}

static int start_worker(d2k_sched *s, task *t, task_job job) {
    worker_arg *a = malloc(sizeof *a);
    if (!a) { return -1; }
    a->s = s; a->t = t;
    t->job = job;
    t->res_ready = 0;
    if (pthread_create(&t->th, NULL, worker_run, a) != 0) {
        free(a);
        return -1;
    }
    t->th_live = 1;
    return 0;
}

static void join_worker(task *t) {
    if (t->th_live) {
        pthread_join(t->th, NULL);
        t->th_live = 0;
    }
}

/* --------------------------------------------------------------------
 * Каталог: записывается ТОЛЬКО по подтверждённому успеху.
 * -------------------------------------------------------------------- */

static d2k_cat_box *box_ensure(d2k_catalog *c, const char *id) {
    for (size_t i = 0; i < c->n_boxes; i++) {
        if (strcmp(c->boxes[i].id, id) == 0) { return &c->boxes[i]; }
    }
    d2k_cat_box *nb = realloc(c->boxes, (c->n_boxes + 1) * sizeof *nb);
    if (!nb) { return NULL; }
    c->boxes = nb;
    d2k_cat_box *b = &c->boxes[c->n_boxes];
    memset(b, 0, sizeof *b);
    snprintf(b->id, sizeof b->id, "%s", id);
    c->n_boxes++;
    return b;
}

/* Записывает подтверждённую привязку.
 *
 * КЛЮЧ — ТРОЙКА: цель, транспорт и форма приветствия (d2k_cat_shape_fits).
 * Форма в ключе затем, что успех добыт КОНКРЕТНЫМ приветствием, а коробка
 * вправе относиться к формам по-разному (§6): без неё успех собственного
 * зонда молча выдавался бы за успех любого клиента. Ноль в записи — «форма не
 * измерена» (старый файл): он совместим с любой формой, и такая привязка
 * ОБНОВЛЯЕТСЯ, а не дублируется — иначе каталог, копившийся неделями,
 * удвоился бы на первой же проверке.
 *
 * shape/verified_by кладутся только измеренными: ноль поверх записанного не
 * пишется никогда — «не измерено» не отменяет измеренного (§2.4). */
static int bind_confirmed(d2k_catalog *c, const char *box_id, const char *plan_id,
                          const char *plan_text, const char *proto,
                          const char *target, uint8_t transport,
                          uint8_t shape, uint8_t verified_by, int64_t now_ms,
                          const d2k_cat_fp *fp) {
    d2k_cat_box *b = box_ensure(c, box_id);
    if (!b) { return -1; }
    if (b->created == 0) { b->created = now_ms / 1000; }
    if (b->fp.n_sig == 0 && fp && fp->n_sig > 0) {
        /* Отпечаток записывается ОДИН раз, при заведении коробки: дальше он её
           удостоверение, и переписывать его приметами следующей цели значило
           бы менять то, по чему её узнают. */
        b->fp = *fp;
    }
    b->updated = now_ms / 1000;

    int have_plan = 0;
    for (size_t i = 0; i < b->n_plans; i++) {
        if (strcmp(b->plans[i].id, plan_id) == 0) { b->plans[i].successes++; have_plan = 1; break; }
    }
    if (!have_plan) {
        d2k_cat_plan *np = realloc(b->plans, (b->n_plans + 1) * sizeof *np);
        if (!np) { return -1; }
        b->plans = np;
        d2k_cat_plan *p = &b->plans[b->n_plans];
        memset(p, 0, sizeof *p);
        snprintf(p->id, sizeof p->id, "%s", plan_id);
        snprintf(p->proto, sizeof p->proto, "%s", proto);
        p->text = strdup(plan_text ? plan_text : "");
        if (!p->text) { return -1; }
        p->added = now_ms / 1000;
        p->successes = 1;
        p->enabled = 1;
        b->n_plans++;
    }

    for (size_t i = 0; i < b->n_binds; i++) {
        d2k_cat_binding *bd = &b->binds[i];
        if (bd->transport == transport && strcmp(bd->target, target) == 0 &&
            d2k_cat_shape_fits(bd->shape, shape)) {
            bd->successes++;
            bd->confirmed = now_ms / 1000;
            snprintf(bd->plan_id, sizeof bd->plan_id, "%s", plan_id);
            if (shape) { bd->shape = shape; }
            if (verified_by) { bd->verified_by = verified_by; }
            return 0;
        }
    }
    d2k_cat_binding *nb = realloc(b->binds, (b->n_binds + 1) * sizeof *nb);
    if (!nb) { return -1; }
    b->binds = nb;
    d2k_cat_binding *bd = &b->binds[b->n_binds];
    memset(bd, 0, sizeof *bd);
    snprintf(bd->kind, sizeof bd->kind, "name");
    snprintf(bd->target, sizeof bd->target, "%s", target);
    snprintf(bd->plan_id, sizeof bd->plan_id, "%s", plan_id);
    bd->level = 3;
    bd->confirmed = now_ms / 1000;
    bd->successes = 1;
    bd->enabled = 1;
    bd->transport = transport;
    bd->shape = shape;
    bd->verified_by = verified_by;
    b->n_binds++;
    return 0;
}

/* Поднимает уровень доказательства уже записанной привязки. 0 — поднят,
 * -1 — такой привязки нет (или уровень уже не ниже).
 *
 * Только вверх и только у существующей записи: наблюдение внешнего типа 23
 * записи не заводит (задача 4), а понижать уровень нечему — отрицательное не
 * хранится вовсе (§10, §13).
 *
 * Про числа. Подтверждение зондом — это «обмен прошёл», третий уровень
 * (level_name ниже, те же слова, что у status.LevelName на Go-стороне).
 * Живое ПОСЛЕДУЮЩЕЕ соединение — пятый, «подтверждён последующими
 * соединениями», буквально по имени. Четвёртый при этом пропускается, и это
 * не описка: он называется «прикладной обмен в проверенном объёме», а объёма
 * здесь никто не мерил (проба объёма живёт отдельно, d2k_volume.h). Назвать
 * им запись значило бы сказать о ней больше, чем измерено (§2.4). */
static int bind_raise_level(d2k_catalog *c, const char *box_id, const char *target,
                            uint8_t transport, uint8_t shape, uint8_t verified_by,
                            int level, int64_t now_ms) {
    for (size_t i = 0; i < c->n_boxes; i++) {
        d2k_cat_box *b = &c->boxes[i];
        if (box_id && box_id[0] && strcmp(b->id, box_id) != 0) { continue; }
        for (size_t j = 0; j < b->n_binds; j++) {
            d2k_cat_binding *bd = &b->binds[j];
            if (bd->transport != transport || strcmp(bd->target, target) != 0) { continue; }
            /* Форма — часть ключа и здесь: запись, добытая одним
               приветствием, не поднимается обменом ДРУГОГО. Ноль с любой
               стороны означает «не измерено» и не спорит ни с чем
               (d2k_cat_shape_fits). */
            if (!d2k_cat_shape_fits(bd->shape, shape)) { continue; }
            if (bd->level >= level) { return -1; }
            bd->level = level;
            if (shape) { bd->shape = shape; }
            if (verified_by) { bd->verified_by = verified_by; }
            b->updated = now_ms / 1000;
            return 0;
        }
    }
    return -1;
}

/* Идентификатор коробки и плана — из содержимого, а не счётчиком: тот же
   план, найденный дважды, обязан получить то же имя, иначе каталог распухнет
   копиями одного и того же. FNV-1a: нужна устойчивая функция на 64 бита, а
   не криптостойкость. */
static uint64_t fnv1a(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    for (; s && *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h;
}

/* Идентификатор кандидата в двух видах: строкой, под которой план ляжет в
 * каталог, и теми же байтами, с которыми он уйдёт на провод записью REC_ID.
 *
 * Вид на проводе — та же строка ASCII, добитая нулями до D2K_PLAN_ID_LEN, а
 * не отдельное число: два представления одного идентификатора разошлись бы
 * молча, а так журнал датапата и каталог показывают человеку буквально одно и
 * то же имя. Строка короче шестнадцати байт всегда: "plan-" плюс восемь
 * знаков. */
static void plan_ident(const char *text, char *id, size_t cap,
                       uint8_t wire[D2K_PLAN_ID_LEN]) {
    snprintf(id, cap, "plan-%08x", (unsigned)(fnv1a(text) & 0xFFFFFFFFu));
    memset(wire, 0, D2K_PLAN_ID_LEN);
    size_t n = strlen(id);
    if (n > D2K_PLAN_ID_LEN) { n = D2K_PLAN_ID_LEN; }
    memcpy(wire, id, n);
}

static int is_hex_digit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* Подставляет идентификатор в строку "id <32 hex>" текста плана НА МЕСТЕ.
 * 0 — подставлено, -1 — такой строки в тексте нет.
 *
 * Длина не меняется: тридцать два шестнадцатеричных знака были и остались,
 * поэтому переписывание идёт прямо в буфере, а остальной текст не двигается и
 * не перестраивается. Второго сборщика текста плана здесь не заводится (§2.5):
 * правится ровно одно поле уже собранного. */
static int stamp_plan_id(char *text, const uint8_t id[D2K_PLAN_ID_LEN]) {
    static const char digits[] = "0123456789abcdef";
    char *p = text;
    while (p) {
        if (strncmp(p, "id ", 3) == 0) {
            char *v = p + 3;
            while (*v == ' ') { v++; }
            size_t n = 0;
            while (n < 2 * D2K_PLAN_ID_LEN && is_hex_digit(v[n])) { n++; }
            if (n != 2 * D2K_PLAN_ID_LEN) { return -1; }
            for (size_t i = 0; i < D2K_PLAN_ID_LEN; i++) {
                v[2 * i]     = digits[id[i] >> 4];
                v[2 * i + 1] = digits[id[i] & 0x0Fu];
            }
            return 0;
        }
        p = strchr(p, '\n');
        if (p) { p++; }
    }
    return -1;
}

/* --------------------------------------------------------------------
 * Ход задачи.
 * -------------------------------------------------------------------- */

/* --------------------------------------------------------------------
 * Вопросы о свойствах коробки — конечный автомат, который двигает ЦИКЛ.
 *
 * Почему не d2k_props_ask: та блокирующая и читает управляющий сокет сама
 * (см. правку плана 11.09 и шапку d2k_sched.h). Смысл вопросов при этом
 * общий на обе стороны — d2k_props_question_plan/d2k_props_question_passed,
 * d2k_compose_internal.h: две копии этой развилки разошлись бы молча, и
 * вектор свойств стал бы зависеть от того, кто спрашивал.
 * -------------------------------------------------------------------- */

/* Обнулённая задача — это prop_fd == 0, а НЕ «нет сокета»: ноль это законный
   дескриптор (стандартный ввод), и закрывать его по такому признаку значит
   закрывать чужое. Первый прогон с вопросами так и падал: задача после
   memset закрывала дескриптор 0, дальше номер переиспользовался, и однажды на
   нём оказался читающий конец будилки планировщика — рабочий поток получал
   SIGPIPE и убивал весь процесс. Отсюда две вещи: task_reset ниже ставит -1
   явно, а эта функция не верит нулю. */
static void prop_close(task *t) {
    if (t->prop_fd > 0) {
        close(t->prop_fd);
    }
    t->prop_fd = -1;
}

/* Закрывает сокет зонда подтверждения. Не зовёт d2k_verify_close на нуле по
   той же причине, по которой prop_close не верит нулю выше: обнулённая задача
   это fd == 0, а ноль — законный дескриптор, и «закрыть пустое» означало бы
   закрыть чужое. */
static void ver_close(task *t) {
    if (t->ver.fd > 0) {
        d2k_verify_close(&t->ver);
    }
    t->ver.fd = -1;
}

/* Единственное место, где задача обнуляется. Не memset на месте: у неё есть
   поле, чей «пусто» не ноль (см. prop_close выше), и разложить это по всем
   точкам сброса значило бы завести столько же мест, где про него забудут. */
static void task_reset(task *t) {
    memset(t, 0, sizeof *t);
    t->prop_fd = -1;
    t->prop_q = -1;
    t->ver.fd = -1; /* та же ловушка нуля, что у prop_fd, — см. prop_close */
}

/* Отправляет план следующего задаваемого вопроса. 0 — отправлен (ждём ack),
   -1 — вопросов больше нет. */
static int prop_send_next(d2k_sched *s, task *t, int64_t now_ms) {
    static uint8_t planbuf[2200];
    static char hex[2 * sizeof planbuf + 1];
    d2k_hello ctl; ctl.bytes = t->ctrl_len ? t->ctrl : NULL; ctl.len = t->ctrl_len;

    while (++t->prop_q < D2K_PROPS_QUESTIONS) {
        size_t plan_len = 0;
        if (d2k_props_question_plan(t->prop_q, ctl, planbuf, sizeof planbuf, &plan_len) != 0) {
            continue; /* этот вопрос сегодня не собрать — не измерено, а не «нет» */
        }
        static const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < plan_len; i++) {
            hex[2 * i] = digits[planbuf[i] >> 4];
            hex[2 * i + 1] = digits[planbuf[i] & 0x0F];
        }
        hex[2 * plan_len] = '\0';
        char err[160];
        if (d2k_link_set_name(s->link_fd, t->name, t->transport, hex, err, sizeof err) != 0) {
            continue; /* план-вопрос не ушёл — не наше наблюдение о коробке */
        }
        t->props_asked = 1;
        t->trial_installed = 1;
        t->probes++;
        s->probes_used++;
        t->prop_applied = 0;
        /* Подтверждения команды НЕ ждём, и это не спешка.
         *
         * Привязать подтверждение к своей команде можно было бы только по
         * порядку: D2K_EV_ACK несёт тип команды и код, но не имя цели. А
         * порядок здесь неприменим, потому что события у датапата ЛОССИ по
         * контракту (d2k_ctl.h, дословно): «Событие — сообщение, а не
         * обязательство. Не поместилось в сокет — потеряно и посчитано».
         * Живой прогон это и показал: после прохода по каталогу (371 команда
         * разом) очередь ожидаемых подтверждений разъехалась навсегда, и ВСЕ
         * пять вопросов молча упирались в тайм-аут, ни разу не дойдя до цели.
         *
         * Вместо подтверждения берём то, что нельзя потерять незаметно:
         * D2K_EV_APPLIED по КЛЮЧУ НАШЕГО ПОТОКА. Он говорит не «план принят на
         * хранение», а «план применён к этим самым пакетам» — то есть ровно
         * то, что вопросу и нужно знать. Не пришёл — ответ не засчитывается
         * (не измерено, а не «нет»): иначе зонд мерил бы линию БЕЗ обхода,
         * считая, что мерит с обходом (docs/field/2026-09-05-active-probe.md). */
        t->state = T_PROPS_CONTACT;
        t->prop_until_ms = now_ms + SCHED_PROP_STEP_MS;
        if (start_worker(s, t, JOB_CONTACT) != 0) {
            continue; /* поток не завёлся — вопрос не задан, берём следующий */
        }
        return 0;
    }
    return -1;
}

/* Вопросы кончились: снять план последнего (он не сработал) и идти собирать
   кандидатов по накопленному вектору. */
static void prop_finish(d2k_sched *s, task *t) {
    prop_close(t);
    if (t->props_asked) {
        /* Иначе на боевом датапате остался бы стоять план, про который это же
           измерение только что сказало «не работает» (см. d2k_props_ask). */
        char err[160];
        (void)d2k_link_del_name(s->link_fd, t->name, err, sizeof err);
        t->trial_installed = 0;
    }
    t->prop_q = -1;
}

static void task_fail(d2k_sched *s, task *t, int64_t now_ms) {
    join_worker(t);
    prop_close(t);
    ver_close(t);
    if (t->trial_installed) {
        char err[160];
        if (d2k_link_del_name(s->link_fd, t->name, err, sizeof err) != 0) {
            say(s, "по %s не удалось снять пробный план: %s", t->name, err);
        }
        t->trial_installed = 0;
    }
    t->state = T_RESTING;
    t->rest_until_ms = now_ms + SCHED_REST_MS;
    t->n_plans = 0;
    t->next_plan = 0;
}

static void task_done(task *t) {
    join_worker(t);
    prop_close(t);
    ver_close(t);
    task_reset(t);
    t->state = T_FREE;
}

/* Ставит следующего кандидата. 0 — поставлен, -1 — кандидаты кончились. */
static int install_next(d2k_sched *s, task *t) {
    while (t->next_plan < t->n_plans) {
        if (t->probes >= SCHED_MAX_PROBES) { return -1; }
        const char *text = t->plans[t->next_plan++];
        snprintf(t->box_id, sizeof t->box_id, "%s", t->plan_boxes[t->next_plan - 1]);
        t->probes++;
        s->probes_used++;
        /* План в каталог НЕ пишется здесь: кандидат — ещё не знание (§10).
           Пишется только подтверждённый зондом, в verify_confirm ниже. */
        char err[160];

        /* Кандидат уходит на провод СО СВОИМ идентификатором — тем же, под
           которым он ляжет в каталог.

           Без этого шага сверять было бы нечего: d2k_compose печатает в шапке
           плана НУЛЕВОЙ REC_ID (emit_header, compose.c — перенос Go-стороны,
           где идентификатор каталога считается позже хэшем текста), и событие
           применения несло бы нули у КАЖДОГО кандидата. «Применился наш» стало
           бы неотличимо от «применился предыдущий, чьё событие опоздало», —
           ровно то, ради чего идентификатор в событие и завели (d2k_link.h).

           Подставляется в КОПИЮ текста, а не в сам план задачи: в каталог
           обязан лечь тот текст, который выдал d2k_compose, иначе его
           собственный хэш перестанет сходиться с идентификатором. */
        static char wire[sizeof t->plans[0]];
        char cat_id[40];
        plan_ident(text, cat_id, sizeof cat_id, t->ver_plan_id);
        snprintf(wire, sizeof wire, "%s", text);
        if (stamp_plan_id(wire, t->ver_plan_id) != 0) {
            /* Строки id в тексте нет — подставить некуда. Кандидата всё равно
               ставим: испытание тогда опирается на один ключ потока. Это
               слабее, но не ложь; нули здесь значат ровно то же, что нули в
               событии, — «плану нечем представиться» (d2k_link.h). */
            memset(t->ver_plan_id, 0, sizeof t->ver_plan_id);
        }

        /* d2k_compose выдаёт ТЕКСТ, датапат принимает hex от TLV — перевод
           обязателен, и без него сюда уезжал бы текст, который
           d2k_link_set_name законно отвергает как «не hex» (так и было
           обнаружено первым прогоном test_sched). */
        static char hex[2 * D2K_PLAN_TLV_MAX + 1];
        if (d2k_plan_text_to_hex(wire, hex, sizeof hex, err, sizeof err) != 0) {
            continue; /* кандидат не переводится — не наше наблюдение о коробке */
        }
        if (d2k_link_set_name(s->link_fd, t->name, t->transport, hex, err, sizeof err) == 0) {
            t->trial_installed = 1;
            return 0;
        }
    }
    return -1;
}

/* Готовые планы УЗНАННОЙ коробки — первыми, синтез по вердикту — следом.
 *
 * Порядок не произволен: план, который уже работал на коробке с такой же
 * приметой, проверен на ней же, а синтез — только выведен. Порт buildQueue
 * (controller.go), включая порядок по числу подтверждённых успехов (§3.4).
 * Возвращает, сколько кандидатов взято из каталога. */
static size_t known_plans(d2k_sched *s, task *t) {
    if (t->fp.n_sig == 0) { return 0; }
    /* Ambiguity yields candidates, not the identity of the first catalog
       entry. Order globally by positive evidence; retain each plan's owner. */
    size_t took = 0;
    size_t cap = sizeof t->plans / sizeof t->plans[0];
    /* proto у плана каталога — протокол УРОВНЯ ПРИЛОЖЕНИЯ ("tls"/"quic"), а
       не транспорт: живой каталог роутера Марка (11.09, 14 коробок, 353
       привязки) не содержит ни одного плана с proto "tcp" — у всех "tls".
       Сравнение с транспортом отбрасывало бы КАЖДЫЙ настоящий план узнанной
       коробки, и узнавание работало бы только в тесте, где план заводил сам
       планировщик. Имя поля общее с Go-стороной (Plan.Proto), и смысл берётся
       оттуда же, а не выдумывается здесь. */
    const char *want = (t->transport == 17) ? "quic" : "tls";
    while (took < cap) {
        const d2k_cat_plan *best = NULL;
        const d2k_cat_box *owner = NULL;
        for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
            const d2k_cat_box *b = &s->cat->boxes[bi];
            if (!d2k_fp_same(&b->fp, &t->fp)) { continue; }
            for (size_t i = 0; i < b->n_plans; i++) {
                const d2k_cat_plan *p = &b->plans[i];
                if (!p->enabled || !p->text || strcmp(p->proto, want) != 0 ||
                    strlen(p->text) >= sizeof t->plans[0]) { continue; }
                int used = 0;
                for (size_t k = 0; k < took; k++) {
                    if (strcmp(t->plans[k], p->text) == 0) { used = 1; break; }
                }
                if (!used && (!best || p->successes > best->successes)) {
                    best = p;
                    owner = b;
                }
            }
        }
        if (!best) { break; }
        memcpy(t->plans[took], best->text, strlen(best->text) + 1);
        snprintf(t->plan_boxes[took], sizeof t->plan_boxes[took], "%s", owner->id);
        took++;
    }
    return took;
}

/* Вектор свойств словами. Нужен наружу: иначе «кандидатов 3» ничего не
   говорит о том, ЧЕМ коробка себя выдала, а это и есть результат опроса.
   Тройственность сохраняется буквально — «не измерено» не превращается в
   «нет» (§2.4). */
static void props_text(const d2k_props *p, char *out, size_t cap) {
    static const char *v[] = { "не измерено", "да", "нет" };
    snprintf(out, cap,
             "перекрытие слева=%s, счёт дубликатов=%s, порядок сегментов=%s, "
             "контрольная сумма=%s, разбор протокола=%s",
             v[p->tolerates_left_overlap % 3], v[p->counts_duplicates % 3],
             v[p->tolerates_reorder % 3], v[p->validates_checksum % 3],
             v[p->parses_l7 % 3]);
}

static void verdict_to_plans(d2k_sched *s, task *t, d2k_verdict v) {
    (void)s;
    t->next_plan = 0;
    t->n_known = 0;
    t->n_plans = 0;
    memset(t->plan_boxes, 0, sizeof t->plan_boxes);
    /* Failed reuse does not prove this is the same box. A newly synthesized
       plan must not silently enlarge the first vaguely matching model. */
    t->box_id[0] = '\0';

    if (v == D2K_V_CLEAR || v == D2K_V_UNREACHABLE) {
        return;
    }
    /* Inconclusive/flaky classification limits our diagnosis, not the
       permitted search space. Candidates remain hypotheses until verified. */
    /* Вектор — накопленный вопросами, а не пустой: в этом весь смысл опроса.
       Пустой вектор d2k_compose честно превращает в ОДИН запасной план, и до
       появления вопросов планировщик только его и получал. */
    d2k_shape sh = d2k_hello_shape(t->trig, t->trig_len);
    size_t cap = sizeof t->plans / sizeof t->plans[0];
    if (t->n_plans < cap) {
        t->n_plans += d2k_compose(&t->props, sh, SCHED_DECOY,
                                  t->plans + t->n_plans, cap - t->n_plans);
    }
}

/* --------------------------------------------------------------------
 * Открытое наружу.
 * -------------------------------------------------------------------- */

d2k_sched *d2k_sched_new(d2k_catalog *cat, int link_fd, uint32_t mark) {
    if (!cat) { return NULL; }
    d2k_sched *s = calloc(1, sizeof *s);
    if (!s) { return NULL; }
    s->cat = cat;
    s->link_fd = link_fd;
    s->mark = mark;
    s->wake[0] = s->wake[1] = -1;
    s->wall_base_s = (int64_t)time(NULL);
    if (pipe(s->wake) != 0) {
        free(s);
        return NULL;
    }
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(s->wake[i], F_GETFL, 0);
        if (fl >= 0) { (void)fcntl(s->wake[i], F_SETFL, fl | O_NONBLOCK); }
    }
    if (pthread_mutex_init(&s->mu, NULL) != 0) {
        close(s->wake[0]); close(s->wake[1]);
        free(s);
        return NULL;
    }
    return s;
}

/* --------------------------------------------------------------------
 * Вид для панели. См. d2k_sched_write_live в d2k_sched.h.
 * -------------------------------------------------------------------- */

/* Экранирование строки в JSON. Тот же минимум, что и у писателя каталога:
   кавычка, обратная косая и управляющие. Имена целей приходят ИЗ СЕТИ, и
   пропустить их в файл как есть значило бы отдать панели то, что она разберёт
   не так, как мы записали. */
static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (*p == '"' || *p == '\\') { fprintf(f, "\\%c", *p); }
        else if (*p < 0x20) { fprintf(f, "\\u%04x", *p); }
        else { fputc(*p, f); }
    }
    fputc('"', f);
}

static void json_time(FILE *f, int64_t unix_s) {
    if (unix_s <= 0) {
        fputs("\"0001-01-01T00:00:00Z\"", f); /* нулевое время Go — панель знает его */
        return;
    }
    time_t t = (time_t)unix_s;
    struct tm tmv;
    gmtime_r(&t, &tmv);
    char buf[32];
    strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    json_str(f, buf);
}

/* Уровень доказательства словами — §4.2. Те же слова, что у status.LevelName
   на Go-стороне: подобраны так, чтобы уровень 2 нельзя было прочитать как
   уровень 4. Панель берёт готовую строку и не толкует число сама. */
static const char *level_name(int n) {
    switch (n) {
    case 1: return "транспорт установился";
    case 2: return "сервер ответил";
    case 3: return "обмен прошёл";
    case 4: return "прикладной обмен в проверенном объёме";
    case 5: return "подтверждён последующими соединениями";
    default: return "не измерено";
    }
}

/* Примета словами. Шаблон панели не должен знать, что 0x88 это ToS, а 54321 —
   идентификатор IP: собирается здесь, как и на Go-стороне. */
static void signal_human(const d2k_cat_signal *sig, char *out, size_t cap) {
    if (strcmp(sig->kind, "rst") == 0) {
        snprintf(out, cap, "подделанный сброс, TTL %u (на %d от сервера), ToS 0x%02x, ip id %u",
                 (unsigned)sig->ttl, sig->ttl_delta, (unsigned)sig->tos, (unsigned)sig->ipid);
    } else if (strcmp(sig->kind, "volume") == 0) {
        snprintf(out, cap, "обрыв по объёму около %d КБ", sig->volume);
    } else if (strcmp(sig->kind, "silent") == 0) {
        snprintf(out, cap, "ответа на приветствие не было");
    } else if (strcmp(sig->kind, "repeat") == 0) {
        snprintf(out, cap, "приветствие повторено");
    } else {
        snprintf(out, cap, "%s", sig->kind);
    }
}

/* Чем занята задача прямо сейчас — теми же словами, что показывала панель у
   Go-контроллера: §8 требует различать «распознаём», «проверяем готовое» и
   «ищем новое», и сливать их в одно нельзя. */
static const char *task_phase(const task *t) {
    switch (t->state) {
    case T_ASKING:        return "распознаём поведение";
    case T_PROPS_CONTACT:
    case T_PROPS_WAIT:    return "спрашиваем коробку о свойствах";
    case T_PLANNING:      return "выводим планы";
    case T_VERIFY:
    case T_VERIFY_WAIT:   return t->next_plan <= t->n_known
                                     ? "проверяем готовое узнанной коробки"
                                     : "проверяем выведенный план";
    case T_WATCHING:      return "подтверждено, смотрим живой трафик";
    case T_RESTING:       return "цель отдыхает после неудачи";
    default:              return "заводим поиск";
    }
}

int d2k_sched_write_live(d2k_sched *s, const char *path, const char *catalog_path) {
    if (!s || !path) { return -1; }
    char tmp[512];
    int n = snprintf(tmp, sizeof tmp, "%s.new", path);
    if (n < 0 || (size_t)n >= sizeof tmp) { return -1; }
    FILE *f = fopen(tmp, "wb");
    if (!f) { return -1; }

    size_t targets = 0;
    for (size_t i = 0; i < s->cat->n_boxes; i++) { targets += s->cat->boxes[i].n_binds; }

    fputs("{\n", f);
    fputs("  \"linked\": true,\n  \"link_note\": \"\",\n  \"catalog_at\": ", f);
    json_str(f, catalog_path ? catalog_path : "");
    fputs(",\n  \"boxes\": [", f);
    for (size_t i = 0; i < s->cat->n_boxes; i++) {
        const d2k_cat_box *b = &s->cat->boxes[i];
        fputs(i ? ",\n    {" : "\n    {", f);
        fputs("\"id\": ", f); json_str(f, b->id);
        fputs(", \"created\": ", f); json_time(f, b->created);
        fputs(", \"updated\": ", f); json_time(f, b->updated);

        fputs(", \"signals\": [", f);
        for (size_t j = 0; j < b->fp.n_sig; j++) {
            char human[200];
            signal_human(&b->fp.sig[j], human, sizeof human);
            fputs(j ? ", {" : "{", f);
            fputs("\"kind\": ", f); json_str(f, b->fp.sig[j].kind);
            fputs(", \"human\": ", f); json_str(f, human);
            fprintf(f, ", \"seen\": %d}", b->fp.sig[j].seen);
        }
        fputs("], \"plans\": [", f);
        for (size_t j = 0; j < b->n_plans; j++) {
            fputs(j ? ", {" : "{", f);
            fputs("\"id\": ", f); json_str(f, b->plans[j].id);
            fputs(", \"proto\": ", f); json_str(f, b->plans[j].proto);
            fprintf(f, ", \"successes\": %d, \"enabled\": %s",
                    b->plans[j].successes, b->plans[j].enabled ? "true" : "false");
            /* Human панель собирает сама из текста — здесь его и отдаём, а
               второго толкователя плана не заводим. */
            fputs(", \"human\": \"\", \"text\": ", f);
            json_str(f, b->plans[j].text ? b->plans[j].text : "");
            fputc('}', f);
        }
        fputs("], \"bindings\": [", f);
        for (size_t j = 0; j < b->n_binds; j++) {
            const d2k_cat_binding *bd = &b->binds[j];
            fputs(j ? ", {" : "{", f);
            fputs("\"target\": ", f); json_str(f, bd->target);
            fputs(", \"kind\": ", f); json_str(f, bd->kind);
            fprintf(f, ", \"level\": %d, ", bd->level);
            fputs("\"level_name\": ", f); json_str(f, level_name(bd->level));
            fprintf(f, ", \"successes\": %d, ", bd->successes);
            fputs("\"confirmed\": ", f); json_time(f, bd->confirmed);
            fprintf(f, ", \"enabled\": %s}", bd->enabled ? "true" : "false");
        }
        fputs("]}", f);
    }
    fputs(s->cat->n_boxes ? "\n  ],\n" : "],\n", f);

    fputs("  \"searches\": [", f);
    int first = 1;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        const task *t = &s->tasks[i];
        if (t->state == T_FREE) { continue; }
        fputs(first ? "\n    {" : ",\n    {", f);
        first = 0;
        fputs("\"target\": ", f); json_str(f, t->name);
        fputs(", \"phase\": ", f); json_str(f, task_phase(t));
        fputs(", \"since\": ", f); json_time(f, s->wall_base_s + t->started_ms / 1000);
        fprintf(f, ", \"attempts\": %zu, \"probes\": %d, ", t->next_plan, t->probes);
        fputs("\"candidate\": ", f);
        json_str(f, t->next_plan > 0 ? "план поставлен" : "");
        fputs(", \"source\": ", f);
        json_str(f, t->n_known > 0 && t->next_plan <= t->n_known
                        ? "готовый план узнанной коробки" : "выведен из замера");
        fputc('}', f);
    }
    fputs(first ? "],\n" : "\n  ],\n", f);
    fprintf(f, "  \"targets\": %zu,\n  \"confirms\": %d,\n  \"probes_used\": %d\n}\n",
            targets, s->confirms, s->probes_used);

    if (fclose(f) != 0) { (void)remove(tmp); return -1; }
    if (rename(tmp, path) != 0) { (void)remove(tmp); return -1; }
    return 0;
}

void d2k_sched_free(d2k_sched *s) {
    if (!s) { return; }
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        join_worker(&s->tasks[i]);
        /* Сокеты обращений закрываем сами: поток к этому моменту уже вернулся,
           а дескриптор принадлежит задаче, а не ему. */
        prop_close(&s->tasks[i]);
        ver_close(&s->tasks[i]);
    }
    pthread_mutex_destroy(&s->mu);
    if (s->wake[0] >= 0) { close(s->wake[0]); }
    if (s->wake[1] >= 0) { close(s->wake[1]); }
    free(s);
}

int d2k_sched_wake_fd(const d2k_sched *s) { return s ? s->wake[0] : -1; }

size_t d2k_sched_active(const d2k_sched *s) {
    if (!s) { return 0; }
    size_t n = 0;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task_state st = s->tasks[i].state;
        if (st == T_ASKING || st == T_PLANNING || st == T_VERIFY ||
            st == T_VERIFY_WAIT || st == T_WATCHING) { n++; }
    }
    return n;
}

/* Находит план коробки по идентификатору. NULL — нет такого или выключен. */
static const d2k_cat_plan *plan_by_id(const d2k_cat_box *b, const char *id) {
    for (size_t i = 0; i < b->n_plans; i++) {
        if (strcmp(b->plans[i].id, id) == 0) {
            return b->plans[i].enabled ? &b->plans[i] : NULL;
        }
    }
    return NULL;
}

/* Сколько команд за одну порцию. Восемь, а не одна: круг цикла стоит
   системного вызова, а датапат успевает отдать кадр за микросекунды — по
   одной команде за круг проход по большому каталогу растянулся бы на секунды
   без всякой пользы. И не сто: чем длиннее порция, тем длиннее окно, в котором
   датапату некуда сказать про живой трафик. */
#define SYNC_CHUNK 8

int d2k_sched_sync(d2k_sched *s) {
    if (!s || !s->cat) { return -1; }
    s->sync_box = 0;
    s->sync_bind = 0;
    s->sync_active = 1;
    s->sync_pending = 0;
    s->sync_sent = 0;
    s->sync_skipped = 0;
    return 0;
}

int d2k_sched_sync_pending(const d2k_sched *s) {
    return (s && (s->sync_active || s->sync_pending)) ? 1 : 0;
}

int d2k_sched_sync_step(d2k_sched *s) {
    if (!s || !s->cat || !s->sync_active) { return 0; }
    static char hex[2 * D2K_PLAN_TLV_MAX + 1];
    char err[200];
    int sent_now = 0;

    while (s->sync_box < s->cat->n_boxes && sent_now < SYNC_CHUNK) {
        const d2k_cat_box *b = &s->cat->boxes[s->sync_box];
        if (s->sync_bind >= b->n_binds) {
            s->sync_box++;
            s->sync_bind = 0;
            continue;
        }
        const d2k_cat_binding *bd = &b->binds[s->sync_bind++];
        if (!bd->enabled) { continue; }
        const d2k_cat_plan *p = plan_by_id(b, bd->plan_id);
        if (!p || !p->text) {
            s->sync_skipped++;
            continue;
        }
        if (d2k_plan_text_to_hex(p->text, hex, sizeof hex, err, sizeof err) != 0) {
            /* Битую запись нашли бы при загрузке; сюда она дойти не должна.
               Если дошла — молчать нельзя (та же оговорка, что у Sync на
               Go-стороне). */
            say(s, "каталог: план %s коробки %s не собирается: %s", p->id, b->id, err);
            s->sync_skipped++;
            continue;
        }
        int rc;
        if (strcmp(bd->kind, "addr") == 0) {
            uint8_t ip4[4];
            unsigned a, bb, c, d;
            if (sscanf(bd->target, "%u.%u.%u.%u", &a, &bb, &c, &d) != 4 ||
                a > 255 || bb > 255 || c > 255 || d > 255) {
                say(s, "каталог: привязка по адресу \"%s\" не разбирается", bd->target);
                s->sync_skipped++;
                continue;
            }
            ip4[0] = (uint8_t)a; ip4[1] = (uint8_t)bb;
            ip4[2] = (uint8_t)c; ip4[3] = (uint8_t)d;
            rc = d2k_link_set_addr(s->link_fd, ip4, hex, err, sizeof err);
        } else {
            /* transport привязки проверяется, но на провод не едет: у SET_NAME
               сегодня нет места под него (d2k_link.h). Ноль — старый файл,
               снятый до появления поля; принимаем как TCP, потому что до
               задачи 5 иных привязок не заводилось.

               Форма приветствия (shape) на провод не едет тем более: датапат
               выбирает план по имени и не разбирает, какой формой пришёл
               клиент. Значит две привязки одной цели, различающиеся только
               формой, поставят план ДВАЖДЫ, и победит последняя по файлу.
               Сегодня такой пары не бывает по построению — зонд один и форма
               у него одна (SCHED_PROBE_SHAPE), а наблюдение привязок не
               заводит; когда появится второй зонд, здесь понадобится правило
               выбора, и его придётся вывести из замера, а не назначить. */
            uint8_t tr = bd->transport ? bd->transport : 6;
            rc = d2k_link_set_name(s->link_fd, bd->target, tr, hex, err, sizeof err);
        }
        if (rc != 0) {
            say(s, "каталог: план для %s не отправился: %s", bd->target, err);
            s->sync_skipped++;
            continue;
        }
        s->sync_sent++;
        sent_now++;
    }

    if (s->sync_box >= s->cat->n_boxes) {
        s->sync_active = 0;
        if (s->sync_sent > 0 || s->sync_skipped > 0) {
            say(s, "каталог: поставлено планов по подтверждённым привязкам: %d%s",
                s->sync_sent, s->sync_skipped ? " (пропущено негодных: см. выше)" : "");
        }
        return 0;
    }
    return 1;
}

static int on_suspect(d2k_sched *s, const d2k_ev *ev) {
    /* Имя копируется СРАЗУ, а не держится указателем в кольцо имён: и потому
       что кольцо переживает вытеснение (следующее приветствие может занять
       ту же ячейку), и потому что источник с приёмником лежат внутри одного
       и того же d2k_sched — gcc справедливо ловит это как перекрытие
       restrict-аргументов snprintf. */
    const char *found = recall(s, ev);
    char name[256];
    name[0] = '\0';
    if (found) {
        size_t n = strlen(found);
        if (n >= sizeof name) { n = sizeof name - 1; }
        memcpy(name, found, n);
        name[n] = '\0';
    }
    if (name[0] == '\0') {
        /* Имени нет — искать не по чему. Это не отказ: датапат подозревает
           поток, а не имя, и поток без приветствия (или с приветствием, уже
           вытесненным из кольца) законно бывает. */
        return 0;
    }
    task *t = task_of(s, name, ev->transport);
    if (t) {
        /* Поиск уже идёт — но примета всё равно наша: отпечаток растёт по мере
           того, как коробка себя проявляет, и первое подозрение редко
           показывает её целиком. */
        d2k_cat_signal sig = signal_of(ev);
        fp_add(&t->fp, &sig);
        if (t->state != T_WATCHING) { return 0; }
        /* А эта задача уже подтверждена и только смотрела на живой трафик.
           Новое подозрение по той же цели означает, что коробка вмешалась
           СНОВА: смотреть больше не на что, и держать место десять минут
           незачем. Запись в каталоге при этом не трогаем — отрицательное не
           хранится и положительного не переписывает (§10, §13), а следующее
           подозрение (датапат не молчит) заведёт поиск заново. */
        say(s, "по %s подозрение при подтверждённом плане — наблюдение прекращаю",
            t->name);
        task_done(t);
        return 0;
    }
    t = task_free_slot(s);
    if (!t) {
        t = task_watching_slot(s);
        if (t) { task_done(t); }
    }
    if (!t) {
        return 0; /* мест нет — подозрение придёт снова, датапат не молчит */
    }
    task_reset(t);
    snprintf(t->name, sizeof t->name, "%s", name);
    t->transport = ev->transport;
    t->fp.method = D2K_FP_METHOD;
    {
        d2k_cat_signal sig = signal_of(ev);
        fp_add(&t->fp, &sig);
    }
    server_of(ev, t->ip, sizeof t->ip, &t->port);
    t->started_ms = 0;
    if (fill_hellos(t) != 0) {
        task_reset(t);
        return 0;
    }
    if (!t->shape_armed) {
        char err[128];
        if (d2k_link_arm_shape(s->link_fd, t->name, err, sizeof err) == 0) {
            t->shape_armed = 1;
        }
    }
    t->n_known = known_plans(s, t);
    t->n_plans = t->n_known;
    if (t->n_known > 0) {
        t->state = T_PLANNING;
        say(s, "по %s проверяю %zu готовых планов узнанной коробки / совместимых моделей ДО нового замера",
            t->name, t->n_known);
        return 1;
    }
    t->researched = 1;
    t->state = T_ASKING;
    if (start_worker(s, t, JOB_CLASSIFY) != 0) {
        task_reset(t);
        return 0;
    }
    say(s, "по %s (%s) начинаю поиск: %s:%u, приветствие %zu байт%s",
        t->name, t->transport == 17 ? "QUIC" : "TCP", t->ip, (unsigned)t->port,
        t->trig_len, t->shape_armed ? ", снимок заказан" : "");
    return 1;
}

static void on_shape(d2k_sched *s, const d2k_ev *ev) {
    if (ev->shape_len == 0 || ev->shape_len > sizeof s->tasks[0].trig) { return; }
    size_t off = 0, len = 0;
    if (d2k_hello_sni(ev->shape, ev->shape_len, &off, &len) != 0 || len == 0) { return; }
    char name[256];
    if (len >= sizeof name) { return; }
    memcpy(name, ev->shape + off, len);
    name[len] = '\0';
    /* Снимок кладём ВСЕМ задачам этого имени: транспортов два, а имя одно. */
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if (t->state != T_FREE && strcmp(t->name, name) == 0) {
            memcpy(t->trig, ev->shape, ev->shape_len);
            t->trig_len = ev->shape_len;
            t->trig_snapped = 1;
            say(s, "по %s поймана форма приветствия: %zu байт", t->name, ev->shape_len);
        }
    }
}

/* Испытание сошлось: наш зонд довёл прикладной обмен до конца, и датапат
   сказал, что ИМЕННО ЭТОТ план применился к пакетам ИМЕННО ЭТОГО потока.
   Только теперь — каталог. */
static void verify_confirm(d2k_sched *s, task *t, int64_t now_ms) {
    const char *text = t->plans[t->next_plan - 1];
    char plan_id[40], box_id[40];
    uint8_t wire_id[D2K_PLAN_ID_LEN];
    plan_ident(text, plan_id, sizeof plan_id, wire_id);
    if (t->box_id[0]) {
        /* Коробка узнана по отпечатку — успех идёт ей, а не новой записи:
           иначе каталог наполнялся бы клонами одной и той же коробки. */
        snprintf(box_id, sizeof box_id, "%s", t->box_id);
    } else if (t->fp.n_sig == 0) {
        /* Примет нет вовсе — узнавать нечем. Знание пишется под отдельную
           запись, и это честнее, чем выдать её за узнанную коробку. */
        snprintf(box_id, sizeof box_id, "box-без-приметы");
    } else {
        /* Новая коробка, и её имя выводится ИЗ ОТПЕЧАТКА, а не из счётчика и
           не из транспорта: та же коробка, встреченная завтра на другой цели,
           обязана получить то же имя. */
        uint64_t h = 1469598103934665603ULL;
        for (size_t i = 0; i < t->fp.n_sig; i++) {
            char b[64];
            snprintf(b, sizeof b, "%s/%u/%u/%u", t->fp.sig[i].kind,
                     (unsigned)t->fp.sig[i].ttl, (unsigned)t->fp.sig[i].tos,
                     (unsigned)t->fp.sig[i].ipid);
            h ^= fnv1a(b);
            h *= 1099511628211ULL;
        }
        /* Coarse passive evidence is not enough to merge a NEW solution
           into an old model whose ready plans failed. Keep it separate. */
        h ^= fnv1a(text);
        snprintf(box_id, sizeof box_id, "box-%08x", (unsigned)(h & 0xFFFFFFFFu));
    }
    /* Контекст: проверку вёл СОБСТВЕННЫЙ зонд и СВОЕЙ формой приветствия
       (SCHED_PROBE_SHAPE). Записывается вместе с успехом, а не выводится
       потом: через день по файлу будет не восстановить, чем именно он
       добыт. */
    (void)bind_confirmed(s->cat, box_id, plan_id, text,
                         t->transport == 17 ? "quic" : "tls",
                         t->name, t->transport,
                         (uint8_t)SCHED_PROBE_SHAPE, D2K_VERBY_PROBE,
                         now_ms, &t->fp);
    /* Коробку запоминаем: живое соединение потом поднимет уровень ИМЕННО этой
       записи, а не первой подходящей по имени цели. */
    snprintf(t->box_id, sizeof t->box_id, "%s", box_id);
    s->confirms++;
    say(s, "по %s (%s) ПОДТВЕРЖДЕНО собственным зондом: %s, приложение ответило %d "
           "(план применён к потоку зонда)",
        t->name, t->transport == 17 ? "QUIC" : "TCP", plan_id, t->ver.status);
    /* Решение принято — только теперь сокет зонда можно закрыть: до этого FIN
       удалил бы ячейку потока в датапате раньше события применения
       (см. d2k_props_contact). */
    ver_close(t);
    /* Пробным план быть перестал: он подтверждён и обязан остаться стоять.
       Снимать его при истечении задачи больше не за что (см. task_fail). */
    t->trial_installed = 0;
    t->state = T_WATCHING;
    /* Подтверждение — это новое знание, и датапат обязан узнать о нём сразу,
       а не после следующего запуска (та же причина, по которой Sync на
       Go-стороне зовётся «при запуске И после каждого подтверждения»). Но
       ЗАКАЗЫВАЕМ проход, а не делаем его здесь: залп команд из разбора
       события создал бы то самое окно слепоты, ради устранения которого
       проход и разложен на порции. */
    s->sync_pending = 1;
}

/* Тот ли это идентификатор, с которым кандидат ушёл на провод.
 *
 * Нули в событии означают «плану нечем представиться» (d2k_link.h): либо
 * датапат старый, либо в тексте плана не нашлось строки id. Сверяем с тем,
 * что записали в план САМИ (install_next), поэтому оба случая сходятся
 * естественно: нулю равен нуль, и проверка остаётся ровно настолько строгой,
 * насколько отличимы сами идентификаторы. */
static int plan_id_is_ours(const task *t, const d2k_ev *ev) {
    return memcmp(ev->plan_id, t->ver_plan_id, D2K_PLAN_ID_LEN) == 0;
}

/* Применение НАШЕГО кандидата к НАШЕЙ цели? Клиентский порт второго конца
   отдаётся наружу: с ним сверится местный порт зонда, когда тот вернётся. */
static int applied_of_candidate(const task *t, const d2k_ev *ev, uint16_t *cport) {
    if (ev->transport != t->transport || !plan_id_is_ours(t, ev)) { return 0; }
    char ip[16];
    ip_text(ev->low_ip, ip, sizeof ip);
    if (ev->low_port == t->port && strcmp(ip, t->ip) == 0) {
        *cport = ev->high_port;
        return 1;
    }
    ip_text(ev->high_ip, ip, sizeof ip);
    if (ev->high_port == t->port && strcmp(ip, t->ip) == 0) {
        *cport = ev->low_port;
        return 1;
    }
    return 0;
}

/* Кандидат доехал до какого-то соединения — ПОЛОВИНА доказательства: план
   тронул ЭТИ пакеты. Вторая половина у зонда (дошло ли по ним до приложения),
   и по отдельности ни одна успехом не является — см. шапку файла.

   Транспорт здесь больше НЕ фильтруется. Фильтр «только TCP» стоял, пока
   молчание считалось уликой против кандидата: событие обмена у QUIC-потока
   прийти не может структурно (datapath/session.c, handle_udp возвращается
   раньше хвоста со счётом обменов), и QUIC-кандидат выбрасывался бы по
   молчанию, которого не могло не быть. Счёт молчаливых применений снят —
   кандидата судит зонд, — а применение датапат журналирует для обоих
   транспортов (обе ветки session.c), и ключ потока с транспортом сверяет
   ev_matches_flow. */
static void on_applied(d2k_sched *s, const d2k_ev *ev) {
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if (t->state == T_PROPS_WAIT) {
            /* Зонд вопроса: «применён» по КЛЮЧУ НАШЕГО потока и есть то
               доказательство, которого вопрос ждёт вместо подтверждения
               команды (см. prop_send_next). */
            if (t->prop_applied || !ev_matches_flow(ev, &t->prop_flow)) { continue; }
            t->prop_applied = 1;
            return;
        }
        if (t->state == T_VERIFY) {
            /* Зонд ещё в сети, и его местный порт знает только он сам: ключа
               потока у нас пока нет. Поэтому запоминаем ПЕРВОЕ применение
               нашего кандидата к нашей цели, а сверка с портом зонда
               произойдёт, когда он вернётся.

               Первое, а не последнее: зонд идёт к цели сразу за установкой
               плана и потому почти всегда оказывается первым НОВЫМ
               соединением к ней (план применяется на приветствии, то есть к
               соединениям, начавшимся после установки). Если первым окажется
               чужое — браузер в ту же секунду переоткрыл цель, — порт не
               сойдётся и испытание не засчитается: «не измерено», а не ложный
               успех (§2.4). */
            uint16_t cport = 0;
            if (t->ver_seen || !applied_of_candidate(t, ev, &cport)) { continue; }
            t->ver_seen = 1;
            t->ver_port = cport;
            return;
        }
        if (t->state == T_VERIFY_WAIT) {
            /* Зонд вернулся, ключ его потока известен — сверяем точно. */
            if (!ev_matches_flow(ev, &t->ver_flow) || !plan_id_is_ours(t, ev)) { continue; }
            t->ver_ok = 1;
            return;
        }
    }
}

/* Обмен по живому трафику. Порога успеха здесь БОЛЬШЕ НЕТ: внешний тип
   записи 23 — наблюдение (§4.2, уровень 2), потому что в TLS 1.3 им едет и
   второй полёт рукопожатия (RFC 8446 §5.2, см. d2k_ev_outer_appdata). Два
   читателя у этого наблюдения: ответ на заданный вопрос о свойствах коробки
   и ПОСЛЕДУЮЩЕЕ живое соединение к уже подтверждённой цели.

   Часы берутся у последнего тика (s->now_ms), а не приходят аргументом:
   события приходят не по часам, и спрашивать время у ОС в обработчике
   незачем — ровно то, ради чего поле now_ms и заведено. Раньше сюда ехал
   литеральный ноль от d2k_sched_event, и всё, что от него считалось
   (потолок шага вопроса, время записи в каталоге), считалось от нуля. */
static void on_exchange(d2k_sched *s, const d2k_ev *ev) {
    int64_t now_ms = s->now_ms;
    /* Сперва — не ответ ли это на заданный вопрос. Своё это обращение или
       чужое, решает КЛЮЧ ПОТОКА: событие обмена не адресовано команде, и без
       фильтра чужой обмен засчитался бы за наш зонд (ревью 11.09, находка 1
       в compose.c — воспроизводилось 5/5 на стенде). */
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if (t->state != T_PROPS_WAIT) { continue; }
        if (!ev_matches_flow(ev, &t->prop_flow)) { continue; }
        if (!d2k_ev_outer_appdata(ev)) {
            /* Обмен пошёл, но внешнего типа 23 ещё нет: §4.2 — это первый
               уровень, и датапат сообщит ВТОРОЙ, когда он появится. Судить
               по первому значит навсегда остаться на первом (session.c).

               Вопросу этого наблюдения достаточно, и это не послабление: он
               спрашивает, ПРОПУСТИЛА ли коробка наш отравленный ClientHello
               до сервера, а второй полёт сервера и есть прямой ответ. Довести
               рукопожатие до конца вопрос и не собирается — повтором снятых
               байт это невозможно (d2k_verify.h). */
            return;
        }
        if (!t->prop_applied) {
            /* Обмен по нашему потоку есть, а доказательства, что план к нему
               применился, нет. Засчитать это за ответ значило бы записать
               свойство коробки по зонду, который, возможно, шёл голым — это
               не ошибка измерения, а измерение не того. Вопрос остаётся НЕ
               измеренным (§2.4), берём следующий. */
            say(s, "по %s вопрос %d: обмен есть, но план к зонду не применялся — не засчитан",
                t->name, t->prop_q + 1);
            prop_close(t);
            if (prop_send_next(s, t, now_ms) != 0) {
                prop_finish(s, t);
                verdict_to_plans(s, t, t->res.verdict);
                t->state = T_PLANNING;
            }
            return;
        }
        d2k_props_question_passed(t->prop_q, &t->props);
        {
            char pv[400];
            props_text(&t->props, pv, sizeof pv);
            say(s, "по %s вопрос %d прошёл, вектор: %s", t->name, t->prop_q + 1, pv);
        }
        /* Вопрос прошёл — это уже стратегия (двойное назначение плана, см.
           шапку compose.c), и второй вопрос той же цели не задаётся. */
        prop_close(t);
        t->prop_q = -1;
        verdict_to_plans(s, t, t->res.verdict);
        t->state = T_PLANNING;
        return;
    }

    if (!d2k_ev_outer_appdata(ev)) {
        return; /* даже наблюдения нет: внешнего типа 23 в обмене не было */
    }
    const char *name = recall(s, ev);
    if (!name) { return; }
    task *t = task_of(s, name, ev->transport);
    /* Только ПОДТВЕРЖДЁННАЯ задача. Завести привязку это наблюдение не может
       (задача 4): на нём кандидат, доведший дело лишь до ответа коробки,
       записывался бы в каталог рабочим — так и набрались 4796 «успехов» по
       instagram при мёртвом плане (§1 спецификации). */
    if (!t || t->state != T_WATCHING) { return; }
    if (ev_matches_flow(ev, &t->ver_flow)) {
        /* Это поток нашего же зонда: он уже был доказательством, и считать его
           вдобавок «последующим соединением» значит подтвердить себя собой. */
        return;
    }
    /* Форма ЖИВОГО клиента — только из снятого с провода приветствия. Не
       снято (trig держит профиль холодного старта) — «не измерено», и ноль
       честнее заготовки: заготовка всегда MODERN и сказала бы про клиента то,
       чего никто не мерил. */
    uint8_t live_shape = t->trig_snapped
                             ? (uint8_t)d2k_hello_shape(t->trig, t->trig_len)
                             : (uint8_t)D2K_SHAPE_UNKNOWN;
    if (bind_raise_level(s->cat, t->box_id, t->name, t->transport,
                         live_shape, D2K_VERBY_CLIENT, 5, now_ms) == 0) {
        say(s, "по %s (%s) последующее живое соединение дошло до обмена (%u байт) "
               "— уровень записи поднят до 5",
            t->name, t->transport == 17 ? "QUIC" : "TCP", (unsigned)ev->num);
    }
    /* Смотреть дальше не на что: выше пятого уровня ничего нет, а место под
       новый поиск нужнее. Подтверждённый план остаётся стоять. */
    task_done(t);
}

int d2k_sched_event(d2k_sched *s, const d2k_ev *ev) {
    if (!s || !ev) { return -1; }
    switch (ev->kind) {
    case D2K_EV_HELLO:
        remember(s, ev);
        return 0;
    case D2K_EV_SUSPECT:
        return on_suspect(s, ev);
    case D2K_EV_STATS:
        s->dropped_seen = ev->dropped;
        return 0;
    case D2K_EV_SHAPE:
        on_shape(s, ev);
        return 0;
    case D2K_EV_APPLIED:
        on_applied(s, ev);
        return 0;
    case D2K_EV_EXCHANGE:
        on_exchange(s, ev);
        return 0;
    default:
        return 0;
    }
}

int d2k_sched_tick(d2k_sched *s, int64_t now_ms) {
    if (!s) { return 0; }
    s->now_ms = now_ms;

    /* Осушить самопайп: он только будит, содержимое значения не имеет. */
    uint8_t drain[64];
    while (read(s->wake[0], drain, sizeof drain) > 0) { }

    if (s->sync_pending && !s->sync_active) {
        (void)d2k_sched_sync(s);
    }

    int moved = 0;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if (t->state == T_FREE) { continue; }

        if (t->state == T_RESTING) {
            if (now_ms >= t->rest_until_ms) { task_done(t); moved++; }
            continue;
        }
        if (t->started_ms == 0) { t->started_ms = now_ms; }
        if (now_ms - t->started_ms > SCHED_TASK_LIFE_MS) {
            if (t->state == T_WATCHING) {
                /* Наблюдение за живым трафиком кончилось ничем — и это НЕ
                   неудача: план уже подтверждён зондом и записан, снимать его
                   (task_fail) не за что. Просто освобождаем место. */
                task_done(t);
            } else {
                task_fail(s, t, now_ms);
            }
            moved++;
            continue;
        }

        if (t->state == T_ASKING) {
            int ready;
            d2k_vres r;
            pthread_mutex_lock(&s->mu);
            ready = t->res_ready;
            r = t->res;
            pthread_mutex_unlock(&s->mu);
            if (!ready) { continue; }
            join_worker(t);
            if (r.verdict == D2K_V_OPAQUE && t->transport == 6) {
                /* «Решает содержимое» — единственный вердикт, на который
                   вопросы о свойствах вообще осмысленны: разрез такую коробку
                   не берёт, берёт её отравление буфера пересборки, а чем
                   именно — это и есть вопросы (d2k_compose.h). На остальных
                   вердиктах спрашивать нечего: там ответ уже дан разрезом или
                   его отсутствием. Только TCP: все пять вопросов —
                   про TCP-сегменты, которых у QUIC нет. */
                say(s, "по %s вердикт: %s (%s) — спрашиваю коробку о свойствах",
                    t->name, verdict_name(r.verdict), r.reason);
                memset(&t->props, 0, sizeof t->props);
                t->prop_q = -1;
                t->props_asked = 0;
                t->res = r;
                if (prop_send_next(s, t, now_ms) == 0) {
                    moved++;
                    continue;
                }
                prop_finish(s, t);
            }
            verdict_to_plans(s, t, r.verdict);
            if (t->n_known > 0) {
                say(s, "по %s вердикт: %s (%s), кандидатов %zu — из них %zu готовых "
                       "планов узнанной коробки %s",
                    t->name, verdict_name(r.verdict), r.reason, t->n_plans,
                    t->n_known, t->box_id);
            } else {
                say(s, "по %s вердикт: %s (%s), кандидатов %zu",
                    t->name, verdict_name(r.verdict), r.reason, t->n_plans);
            }
            if (t->n_plans == 0) {
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            t->state = T_PLANNING;
            moved++;
        }

        if (t->state == T_PROPS_CONTACT) {
            int ready;
            pthread_mutex_lock(&s->mu);
            ready = t->res_ready;
            pthread_mutex_unlock(&s->mu);
            if (!ready) {
                if (now_ms < t->prop_until_ms) { continue; }
                /* Обращение не вернулось в срок — поток ещё в сети; бросать
                   его нельзя, ждём столько же ещё раз, а не режем задачу. */
                t->prop_until_ms = now_ms + SCHED_PROP_STEP_MS;
                continue;
            }
            join_worker(t);
            if (!t->c_ok) {
                /* Обращение не состоялось (транспорт) — вопрос не измерен. */
                if (prop_send_next(s, t, now_ms) != 0) {
                    prop_finish(s, t);
                    verdict_to_plans(s, t, t->res.verdict);
                    t->state = T_PLANNING;
                }
                moved++;
                if (t->state != T_PLANNING) { continue; }
            } else {
                t->prop_fd = t->c_fd;
                memcpy(t->prop_flow.a_ip, t->c_ip, 4);
                t->prop_flow.a_port = t->c_port;
                inet_pton(AF_INET, t->ip, t->prop_flow.b_ip);
                t->prop_flow.b_port = t->port;
                t->prop_flow.transport = 6;
                t->state = T_PROPS_WAIT;
                t->prop_until_ms = now_ms + SCHED_PROP_STEP_MS;
                say(s, "по %s зонд вопроса %d ушёл с местного порта %u — жду обмена",
                    t->name, t->prop_q + 1, (unsigned)t->c_port);
                moved++;
                continue;
            }
        }

        if (t->state == T_PROPS_WAIT) {
            if (now_ms < t->prop_until_ms) { continue; }
            /* Обмена с прикладными данными не дождались — промах вопроса. Он
               НЕ пишет ничего (§2.4, каждый Set в Go начинается с
               `if !passed { return }`). */
            prop_close(t);
            if (prop_send_next(s, t, now_ms) != 0) {
                prop_finish(s, t);
                verdict_to_plans(s, t, t->res.verdict);
                t->state = T_PLANNING;
            }
            moved++;
            if (t->state != T_PLANNING) { continue; }
        }

        if (t->state == T_VERIFY) {
            int ready;
            pthread_mutex_lock(&s->mu);
            ready = t->res_ready;
            pthread_mutex_unlock(&s->mu);
            if (!ready) { continue; } /* зонд в сети; срок задачи считается выше */
            join_worker(t);
            if (t->ver.level != D2K_VER_APPLICATION) {
                /* Транспорт, рукопожатие и даже «сервер что-то ответил» —
                   не доказательство (§4.2 и шапка d2k_verify.h). Кандидат не
                   виноват и не оправдан: он просто не показал прикладного
                   обмена, и в каталог не идёт ничего (§10). */
                say(s, "по %s план %zu: зонд не дошёл до приложения (%s) — беру следующего кандидата",
                    t->name, t->next_plan, t->ver.reason);
                ver_close(t);
                t->state = T_PLANNING;
            } else {
                /* Ключ потока зонда известен только теперь: местный порт
                   назначает ядро при обращении, и до возврата его не знает
                   никто, кроме самого зонда. */
                memcpy(t->ver_flow.a_ip, t->ver.local_ip4, 4);
                t->ver_flow.a_port = t->ver.local_port;
                inet_pton(AF_INET, t->ip, t->ver_flow.b_ip);
                t->ver_flow.b_port = t->port;
                t->ver_flow.transport = t->transport;
                if (t->ver_seen && t->ver_port == t->ver.local_port) { t->ver_ok = 1; }
                if (t->ver_ok) {
                    verify_confirm(s, t, now_ms);
                } else {
                    /* Применение могло ещё не доехать: событие — сообщение, а
                       не обязательство (d2k_ctl.h). Ждём его, держа сокет
                       зонда открытым. */
                    t->state = T_VERIFY_WAIT;
                    t->ver_until_ms = now_ms + SCHED_VERIFY_STEP_MS;
                    say(s, "по %s зонд дошёл до приложения (%d) с местного порта %u "
                           "— жду применения плана к его потоку",
                        t->name, t->ver.status, (unsigned)t->ver.local_port);
                }
            }
            moved++;
        }

        if (t->state == T_VERIFY_WAIT) {
            if (t->ver_ok) {
                verify_confirm(s, t, now_ms);
                moved++;
            } else if (now_ms >= t->ver_until_ms) {
                if (s->dropped_seen != t->ver_dropped0 && t->probes < SCHED_MAX_PROBES) {
                    /* Связь теряла события с тех пор, как план встал. Значит
                       «применения не было» может означать «было, но событие о
                       нём не доехало», — а это разные вещи, и вторая не улика
                       против кандидата. Испытываем ЕГО ЖЕ ещё раз, а не
                       выбрасываем: повтор стоит одного зонда и ограничен общим
                       бюджетом зондов, а выброшенный рабочий план стоит
                       поиска целиком (ровно эта ошибка ловилась счётом потерь
                       и раньше). */
                    say(s, "по %s связь потеряла события (%u) — молчание не в счёт, "
                           "испытываю кандидата ещё раз",
                        t->name, (unsigned)(s->dropped_seen - t->ver_dropped0));
                    t->ver_dropped0 = s->dropped_seen;
                    ver_close(t);
                    t->ver_seen = 0;
                    t->ver_ok = 0;
                    t->ver_port = 0;
                    t->probes++;
                    s->probes_used++;
                    t->state = T_VERIFY;
                    if (start_worker(s, t, JOB_VERIFY) != 0) { t->state = T_PLANNING; }
                } else {
                    /* Зонд прошёл, а доказательства, что план тронул ЕГО
                       пакеты, нет. Засчитать это значило бы записать план по
                       обращению, которое, возможно, шло голым, — цель просто
                       открылась сама. Не измерено (§2.4), берём следующего. */
                    say(s, "по %s зонд прошёл, а применения этого плана к его потоку не было "
                           "— не засчитано, беру следующего кандидата",
                        t->name);
                    ver_close(t);
                    t->state = T_PLANNING;
                }
                moved++;
            }
        }

        if (t->state == T_PLANNING) {
            if (install_next(s, t) != 0) {
                if (!t->researched) {
                    /* Exhausted known plans: remove the trial before any
                       baseline measurement. Research happens at most once. */
                    char err[160];
                    (void)d2k_link_del_name(s->link_fd, t->name, err, sizeof err);
                    t->trial_installed = 0;
                    t->researched = 1;
                    t->box_id[0] = '\0';
                    t->state = T_ASKING;
                    if (start_worker(s, t, JOB_CLASSIFY) == 0) {
                        say(s, "по %s готовые планы не помогли — начинаю новый замер", t->name);
                        moved++;
                        continue;
                    }
                }
                say(s, "по %s выведенные планы исчерпаны (зондов %d) — цель отдыхает. "
                       "Это не «перебор кончился»: планы выводятся из замера, и если "
                       "измерить было нечем, их и нет",
                    t->name, t->probes);
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            /* Кандидат стоит — испытываем его САМИ, не дожидаясь, пока цель
               откроет человек (см. шапку файла). */
            t->ver_seen = 0;
            t->ver_ok = 0;
            t->ver_port = 0;
            ver_close(t);
            memset(&t->ver, 0, sizeof t->ver);
            t->ver.fd = -1;
            t->ver_dropped0 = s->dropped_seen;
            t->state = T_VERIFY;
            if (start_worker(s, t, JOB_VERIFY) != 0) {
                /* Потока нет — испытать нечем. Это «не измерено»: следующий
                   круг тика возьмёт следующего кандидата. */
                say(s, "по %s поставил план %zu из %zu, но поток испытания не завёлся",
                    t->name, t->next_plan, t->n_plans);
                t->state = T_PLANNING;
                moved++;
                continue;
            }
            say(s, "по %s поставил план %zu из %zu — испытываю его собственным зондом",
                t->name, t->next_plan, t->n_plans);
            moved++;
        }
    }
    return moved;
}
