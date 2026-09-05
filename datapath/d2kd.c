/* d2kd — служба датапата. Только Linux.
 *
 * Берёт пакеты из NFQUEUE, ведёт учёт потоков, при необходимости применяет
 * план и отвечает вердиктом. Собственные пакеты уходят сырым сокетом; те, у
 * которых в плане назначена задержка, ждут своего срока в очереди отправки, а
 * не в цикле — спать в цикле значит остановить весь трафик роутера.
 *
 * УМОЛЧАНИЕ — НАБЛЮДЕНИЕ. В режиме observe ни один пакет не снимается и ни
 * один не выпускается: план прогоняется, его результат считается, трафик идёт
 * как шёл. Этап C документа прямо говорит «обход пока не применяется
 * автоматически», и режим по умолчанию обязан этому соответствовать. Активное
 * исполнение включается явным --mode apply.
 *
 * Времена — целые наносекунды от CLOCK_MONOTONIC. Плавающей арифметики на
 * пакетном пути нет: MIPS-коробки идут без сопроцессора.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <poll.h>

#include "d2k_ctl.h"
#include "d2k_ctlsrv.h"
#include "d2k_journal.h"
#include "d2k_nfq.h"
#include "d2k_nl.h"
#include "d2k_raw.h"
#include "d2k_sched.h"
#include "d2k_session.h"

/* Константы времени с явной шириной. Смешивать uint64_t с суффиксом ULL
   нельзя: на aarch64 это разные типы, и printf расходится с аргументом. */
#define NS_PER_S  UINT64_C(1000000000)
#define NS_PER_MS UINT64_C(1000000)
#define NS_PER_US UINT64_C(1000)

#define RECV_BUF   65536
#define OUT_BUF    32768
#define MAX_PKT     1600

static volatile sig_atomic_t stop_flag;
static void on_signal(int sig) { (void)sig; stop_flag = 1; }

/* Собственная цена. Читается у ядра, а не оценивается: §10 требует CPU и RSS
   как метрики, а «на глаз не тормозит» метрикой не является.
   /proc/self/stat: поля 14 и 15 — utime и stime в тиках.
   /proc/self/statm: поле 2 — резидентные страницы. */
static void self_cost(uint64_t *cpu_ms, uint64_t *rss_kb) {
    *cpu_ms = 0;
    *rss_kb = 0;

    FILE *f = fopen("/proc/self/stat", "r");
    if (f) {
        char buf[1024];
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        buf[n] = '\0';
        /* Имя процесса в скобках может содержать пробелы; поля считаем после
           последней закрывающей скобки. */
        char *p = strrchr(buf, ')');
        if (p) {
            int field = 2;
            unsigned long ut = 0, stime = 0;
            for (p++; *p; ) {
                while (*p == ' ') { p++; }
                if (!*p) { break; }
                field++;
                unsigned long v = strtoul(p, &p, 10);
                if (field == 14) { ut = v; }
                if (field == 15) { stime = v; break; }
            }
            long hz = sysconf(_SC_CLK_TCK);
            if (hz > 0) {
                *cpu_ms = (uint64_t)(ut + stime) * 1000u / (uint64_t)hz;
            }
        }
    }

    f = fopen("/proc/self/statm", "r");
    if (f) {
        unsigned long total = 0, resident = 0;
        if (fscanf(f, "%lu %lu", &total, &resident) == 2) {
            long pg = sysconf(_SC_PAGESIZE);
            if (pg > 0) {
                *rss_kb = (uint64_t)resident * (uint64_t)pg / 1024u;
            }
        }
        fclose(f);
    }
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NS_PER_S + (uint64_t)ts.tv_nsec;
}

/* --- учёт причин пропуска -------------------------------------------------
 * «План не сработал» и «план не применялся» — разные факты, и сводка обязана
 * их различать. Причины приходят строковыми литералами из session.c, поэтому
 * сравнение сперва по указателю (почти всегда попадает и стоит копейки) и
 * только потом по содержимому. */
#define MAX_REASONS 32
static struct {
    const char *text;
    uint64_t    n;
} reasons[MAX_REASONS];
static size_t n_reasons;

static void count_reason(const char *r) {
    if (!r) {
        return;
    }
    for (size_t i = 0; i < n_reasons; i++) {
        if (reasons[i].text == r) {
            reasons[i].n++;
            return;
        }
    }
    for (size_t i = 0; i < n_reasons; i++) {
        if (strcmp(reasons[i].text, r) == 0) {
            reasons[i].n++;
            return;
        }
    }
    if (n_reasons < MAX_REASONS) {
        reasons[n_reasons].text = r;
        reasons[n_reasons].n = 1;
        n_reasons++;
    }
}

/* --- счётчики -------------------------------------------------------------- */
static struct {
    uint64_t seen, bytes;
    uint64_t accepted, dropped;
    uint64_t emitted;          /* собственных пакетов выпущено */
    uint64_t deferred;         /* отложено до срока */
    uint64_t truncated;        /* ядро отдало кусок пакета */
    uint64_t no_payload;       /* атрибута с пакетом не было вовсе */
    uint64_t no_hdr;           /* некому отвечать вердиктом */
    uint64_t verdict_fail;
    uint64_t send_fail;
    uint64_t recv_err;
} st;

static const char *MODE_NAMES[] = {"observe", "apply"};
enum { MODE_OBSERVE = 0, MODE_APPLY = 1 };

static void usage(void) {
    fprintf(stderr,
        "d2kd — служба датапата d2k\n"
        "\n"
        "  --queue N          номер очереди NFQUEUE (обязательно)\n"
        "  --plan FILE        план в канонической форме TLV\n"
        "  --mode observe|apply   умолчание observe: ничего не менять\n"
        "  --mark M           SO_MARK на собственных пакетах (умолчание 0)\n"
        "  --flows N          предел числа отслеживаемых потоков (2048)\n"
        "  --queue-len N      глубина очереди ядра в пакетах (1024)\n"
        "  --copy-range N     сколько байт пакета брать у ядра (1600)\n"
        "  --sched-slots N    сколько отложенных пакетов держать (128)\n"
        "  --journal N        глубина диагностического журнала, 0 — без него (256)\n"
        "  --control PATH     управляющий сокет для контроллера\n"
        "  --idle SEC         молчащий поток забывается через (120)\n"
        "  --log FILE         писать вывод сюда вместо stdout\n"
        "  --stats SEC        период печати сводки, 0 — не печатать (10)\n"
        "  --duration SEC     остановиться через N секунд, 0 — бесконечно\n"
        "  --no-fail-open     НЕ пропускать при переполнении очереди\n"
        "\n"
        "Без --mode apply служба ничего не меняет в трафике.\n");
}

static int arg_u32(const char *v, uint32_t *out) {
    char *end = NULL;
    unsigned long n = strtoul(v, &end, 0);
    if (!end || *end != '\0' || n > 0xffffffffUL) {
        return -1;
    }
    *out = (uint32_t)n;
    return 0;
}

static void print_stats(const d2k_session *s, const d2k_sched *sched,
                        const d2k_nfq *q, const d2k_raw *r, uint64_t run_ns) {
    uint64_t cpu_ms = 0, rss_kb = 0;
    self_cost(&cpu_ms, &rss_kb);
    uint64_t secs = run_ns / NS_PER_S;
    /* Номер процесса в каждой сводке. Журнал дописывается через перезапуски,
       и «последний блок» без подписи принадлежит неизвестно кому: однажды я
       приписал показания одного экземпляра другому и сутки искал дефект,
       которого в той настройке не было. */
    printf("--- d2kd[%ld], %" PRIu64 " с; процессор %" PRIu64 " мс (%" PRIu64
           ",%" PRIu64 " %%), RSS %" PRIu64 " КиБ ---\n",
           (long)getpid(), secs, cpu_ms,
           secs ? cpu_ms / (secs * 10) : 0,
           secs ? (cpu_ms * 10 / secs) % 100 : 0,
           rss_kb);
    printf("пакетов %" PRIu64 ", байт %" PRIu64
           ", пропущено %" PRIu64 ", снято %" PRIu64 "\n",
           st.seen, st.bytes, st.accepted, st.dropped);
    /* Счёт применений берётся у сессии, а не свой. Своя переменная считала
       применения по числу выпущенных пакетов, и план из одной защиты — без
       единой посылки — показывался как «применён 0», хотя журнал той же
       минутой писал «план применён». Один факт не может иметь двух счётчиков. */
    printf("план применён %" PRIu64 ", выпущено %" PRIu64
           ", отложено %" PRIu64 "\n",
           d2k_session_applied(s), st.emitted, st.deferred);
    /* Второе число — предел таблицы, а не что попало. В первом полевом
       прогоне здесь стояла длина очереди отправки, и строка читалась как
       «23 потока из 0». */
    printf("потоков %zu из %zu, отказов таблицы %" PRIu64 "\n",
           d2k_session_flows(s), d2k_session_capacity(s),
           d2k_session_refusals(s));
    printf("узнано приветствий %" PRIu64 ", из них с именем %" PRIu64
           ", обменов %" PRIu64 ", подозрений %" PRIu64
           ", снято чужих сбросов %" PRIu64 "\n",
           d2k_session_hellos(s), d2k_session_with_sni(s),
           d2k_session_exchanges(s), d2k_session_suspects(s),
           d2k_session_rst_dropped(s));
    printf("в очереди отправки %zu, отказов расписания %" PRIu64 "\n",
           d2k_sched_count(sched), d2k_sched_refusals(sched));
    printf("обрезано %" PRIu64 ", без нагрузки %" PRIu64
           ", без заголовка %" PRIu64 "\n",
           st.truncated, st.no_payload, st.no_hdr);
    {
        d2k_payload_stats ps;
        d2k_session_payload_stats(s, &ps);
        printf("нагрузка мимо приветствия: обратная %" PRIu64
               ", после приветствия %" PRIu64 ", за окном %" PRIu64
               ", не приветствие %" PRIu64 " (первый байт %#02x)\n",
               ps.reverse, ps.after_hello, ps.late, ps.not_hello,
               ps.last_first_byte);
        printf("имя уехало во второй сегмент: %" PRIu64 "\n", ps.sni_next_seg);
    }
    printf("потеряно ядром %" PRIu64 ", ошибок вердикта %" PRIu64
           ", ошибок отправки %" PRIu64 ", ошибок чтения %" PRIu64 "\n",
           d2k_nfq_lost(q), st.verdict_fail, st.send_fail, st.recv_err);
    if (r) {
        printf("сырым сокетом отправлено %" PRIu64 ", ошибок %" PRIu64 "\n",
               d2k_raw_sent(r), d2k_raw_errors(r));
    }
    printf("планов по целям %zu из %zu\n",
           d2k_session_plan_count(s), d2k_session_plan_capacity(s));
    for (size_t i = 0; i < n_reasons; i++) {
        printf("  пропуск «%s»: %" PRIu64 "\n", reasons[i].text, reasons[i].n);
    }
    fflush(stdout);
}

/* Порт в ключе лежит в сетевом порядке — ровно как в заголовке. Читаем его
   как сетевой, а не переставляем байты «наугад»: перестановка вслепую уже
   стоила ошибки в контрольных суммах. */
static unsigned port_of(const void *p) {
    const uint8_t *b = p;
    return (unsigned)b[0] << 8 | b[1];
}

static const char *jrn_kind(uint8_t k) {
    switch (k) {
    case D2K_JRN_HELLO_SNI:     return "приветствие";
    case D2K_JRN_HELLO_NONAME:  return "приветствие без имени";
    case D2K_JRN_PLAN_APPLIED:  return "план применён";
    case D2K_JRN_PLAN_REFUSED:  return "план не применён";
    case D2K_JRN_SUSPECT:       return "подозрение:";
    case D2K_JRN_EXCHANGE:      return "обмен пошёл";
    default:                    return "?";
    }
}

/* Журнал печатается один раз, в конце: это диагностика, а не поток событий.
 * Печатать его на каждом тике значило бы утопить сводку. */
static void print_journal(const d2k_session *s, uint64_t start) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j);
    if (n == 0) {
        printf("журнал пуст\n");
        return;
    }
    printf("--- журнал: %zu записей, затёрто %" PRIu64 " ---\n",
           n, d2k_journal_dropped(j));
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (!e) {
            continue;
        }
        /* Ключ канонизирован: «низкая» и «высокая» стороны, а не источник и
           назначение. Печатается как пара, через тире, чтобы стрелка не врала
           о направлении. */
        const uint8_t *la = (const uint8_t *)&e->key.low_ip;
        const uint8_t *ha = (const uint8_t *)&e->key.high_ip;
        printf("  %6" PRIu64 " мс  %u.%u.%u.%u:%u - %u.%u.%u.%u:%u  %s%s%s%s\n",
               (e->at_ns - start) / NS_PER_MS,
               la[0], la[1], la[2], la[3], port_of(&e->key.low_port),
               ha[0], ha[1], ha[2], ha[3], port_of(&e->key.high_port),
               jrn_kind(e->kind),
               e->name_len ? " " : "", e->name_len ? e->name : "",
               e->note ? e->note : "");
    }
    fflush(stdout);
}

int main(int argc, char **argv) {
    uint32_t queue = 0;
    int have_queue = 0;
    const char *plan_path = NULL;
    const char *log_path = NULL;
    const char *ctl_path = NULL;
    int mode = MODE_OBSERVE;
    uint32_t mark = 0;
    uint32_t flows = 2048, qlen = 1024, copy_range = MAX_PKT;
    uint32_t slots = 128, idle_s = 120, stats_s = 10, duration_s = 0;
    uint32_t journal = 256;
    int fail_open = 1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
#define NEEDV() do { if (!v) { fprintf(stderr, "%s требует значения\n", a); return 2; } i++; } while (0)
        if (strcmp(a, "--queue") == 0)            { NEEDV(); if (arg_u32(v, &queue)) goto badval; have_queue = 1; }
        else if (strcmp(a, "--plan") == 0)        { NEEDV(); plan_path = v; }
        else if (strcmp(a, "--log") == 0)         { NEEDV(); log_path = v; }
        else if (strcmp(a, "--control") == 0)     { NEEDV(); ctl_path = v; }
        else if (strcmp(a, "--mark") == 0)        { NEEDV(); if (arg_u32(v, &mark)) goto badval; }
        else if (strcmp(a, "--flows") == 0)       { NEEDV(); if (arg_u32(v, &flows)) goto badval; }
        else if (strcmp(a, "--queue-len") == 0)   { NEEDV(); if (arg_u32(v, &qlen)) goto badval; }
        else if (strcmp(a, "--copy-range") == 0)  { NEEDV(); if (arg_u32(v, &copy_range)) goto badval; }
        else if (strcmp(a, "--sched-slots") == 0) { NEEDV(); if (arg_u32(v, &slots)) goto badval; }
        else if (strcmp(a, "--journal") == 0)     { NEEDV(); if (arg_u32(v, &journal)) goto badval; }
        else if (strcmp(a, "--idle") == 0)        { NEEDV(); if (arg_u32(v, &idle_s)) goto badval; }
        else if (strcmp(a, "--stats") == 0)       { NEEDV(); if (arg_u32(v, &stats_s)) goto badval; }
        else if (strcmp(a, "--duration") == 0)    { NEEDV(); if (arg_u32(v, &duration_s)) goto badval; }
        else if (strcmp(a, "--no-fail-open") == 0) { fail_open = 0; }
        else if (strcmp(a, "--mode") == 0) {
            NEEDV();
            if (strcmp(v, "observe") == 0)      { mode = MODE_OBSERVE; }
            else if (strcmp(v, "apply") == 0)   { mode = MODE_APPLY; }
            else { fprintf(stderr, "режим бывает observe или apply\n"); return 2; }
        }
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(); return 0; }
        else { fprintf(stderr, "неизвестный ключ: %s\n", a); usage(); return 2; }
#undef NEEDV
        continue;
    badval:
        fprintf(stderr, "плохое значение у %s\n", a);
        return 2;
    }

    if (!have_queue) {
        fprintf(stderr, "не задан --queue\n");
        usage();
        return 2;
    }
    if (queue > 0xffff) {
        fprintf(stderr, "номер очереди не помещается в 16 бит\n");
        return 2;
    }
    if (copy_range < 64 || copy_range > MAX_PKT) {
        fprintf(stderr, "--copy-range должен быть от 64 до %d\n", MAX_PKT);
        return 2;
    }
    if (mode == MODE_APPLY && !plan_path && !ctl_path) {
        /* Планы приходят либо файлом, либо от контроллера через сокет. Без
           обоих исполнять нечего, и запускаться в таком виде значит оставить
           человеку процесс, который выглядит работающим обходом. */
        fprintf(stderr, "режим apply без --plan и без --control ничего не сделал бы\n");
        return 2;
    }
    if (mode == MODE_APPLY && mark == 0) {
        /* §5.5: неудача пометки — явное снижение достоверности, если
           исключение обхода не гарантировано. Работать активно без метки
           значит рисковать тем, что собственные пакеты вернутся в свою же
           очередь и обучат систему на её собственном эхе. */
        fprintf(stderr, "режим apply без --mark запрещён: собственные пакеты "
                        "нечем исключить из своей же очереди\n");
        return 2;
    }

    if (log_path) {
        /* Служба уходит в фон через start-stop-daemon, который потоки не
           перенаправляет. Раз файл нужен нам, открываем его сами — до первой
           печати, иначе стартовая строка уйдёт в никуда. */
        if (!freopen(log_path, "a", stdout) || !freopen(log_path, "a", stderr)) {
            fprintf(stderr, "не открыть журнал %s: %s\n", log_path, strerror(errno));
            return 1;
        }
        setvbuf(stdout, NULL, _IOLBF, 0);
    }

    char err[256];
    err[0] = '\0';

    /* --- план ------------------------------------------------------------- */
    d2k_plan *plan = NULL;
    if (plan_path) {
        FILE *f = fopen(plan_path, "rb");
        if (!f) {
            fprintf(stderr, "план %s: %s\n", plan_path, strerror(errno));
            return 1;
        }
        static uint8_t pbuf[65536];
        size_t n = fread(pbuf, 1, sizeof pbuf, f);
        int short_read = !feof(f);
        fclose(f);
        if (short_read) {
            fprintf(stderr, "план %s длиннее %zu байт\n", plan_path, sizeof pbuf);
            return 1;
        }
        if (d2k_plan_load(pbuf, n, &plan, err, sizeof err) != 0) {
            fprintf(stderr, "план %s не принят: %s\n", plan_path, err);
            return 1;
        }
    }

    /* --- сырой сокет и сверка пределов ------------------------------------ */
    d2k_raw *raw = NULL;
    if (mode == MODE_APPLY) {
        raw = d2k_raw_open(mark, err, sizeof err);
        if (!raw) {
            fprintf(stderr, "сырой сокет: %s\n", err);
            d2k_plan_free(plan);
            return 1;
        }
        char why[200];
        if (plan && !d2k_plan_fits(plan, d2k_raw_limits(raw), why, sizeof why)) {
            fprintf(stderr, "план не активируется: %s.\n"
                            "Исполненное разошлось бы с измеренным (§2.5).\n", why);
            d2k_raw_close(raw);
            d2k_plan_free(plan);
            return 1;
        }
    }

    /* --- очередь ---------------------------------------------------------- */
    d2k_nfq_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.queue = (uint16_t)queue;
    cfg.copy_range = copy_range;
    cfg.maxlen = qlen;
    cfg.fail_open = fail_open;
    cfg.rcvbuf = 4 * 1024 * 1024;

    d2k_nfq *q = d2k_nfq_open(&cfg, err, sizeof err);
    if (!q) {
        fprintf(stderr, "очередь %u: %s\n", queue, err);
        d2k_raw_close(raw);
        d2k_plan_free(plan);
        return 1;
    }

    d2k_ctl *ctl = NULL;
    if (ctl_path) {
        ctl = d2k_ctl_open(ctl_path, err, sizeof err);
        if (!ctl) {
            fprintf(stderr, "управляющий сокет: %s\n", err);
            d2k_nfq_close(q);
            d2k_raw_close(raw);
            d2k_plan_free(plan);
            return 1;
        }
    }

    d2k_session *sess = d2k_session_new(flows, journal);
    d2k_sched   *sched = d2k_sched_new(slots, copy_range);
    if (!sess || !sched) {
        fprintf(stderr, "не хватило памяти на состояние\n");
        d2k_ctl_close(ctl);
        d2k_sched_free(sched);
        d2k_session_free(sess);
        d2k_nfq_close(q);
        d2k_raw_close(raw);
        d2k_plan_free(plan);
        return 1;
    }
    if (plan) {
        d2k_session_set_plan(sess, plan);   /* владение переходит сессии */
        plan = NULL;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    printf("=== d2kd[%ld] запущен ===\n", (long)getpid());
    printf("d2kd: очередь %u, режим %s, метка %u, потоков до %u, "
           "fail-open %s%s\n",
           queue, MODE_NAMES[mode], mark, flows, fail_open ? "да" : "НЕТ",
           plan_path ? ", план загружен" : ", плана нет");
    if (mode == MODE_OBSERVE) {
        printf("d2kd: наблюдение. Ни один пакет не будет изменён, снят или "
               "выпущен.\n");
    }
    fflush(stdout);

    d2k_ctlsrv cx;
    memset(&cx, 0, sizeof cx);
    cx.sess = sess;
    cx.ctl = ctl;
    cx.send_limits = raw ? d2k_raw_limits(raw) : 0;
    uint64_t events_seen = 0;

    static uint8_t rbuf[RECV_BUF];
    static uint8_t obuf[OUT_BUF];
    static uint8_t sbuf[MAX_PKT];

    const uint64_t start = now_ns();
    const uint64_t idle_ns = (uint64_t)idle_s * NS_PER_S;
    uint64_t next_stats = stats_s ? start + (uint64_t)stats_s * NS_PER_S : 0;
    uint64_t next_expire = start + NS_PER_S;

    while (!stop_flag) {
        uint64_t t = now_ns();
        if (duration_s && t - start >= (uint64_t)duration_s * NS_PER_S) {
            break;
        }

        /* Досыпаем ровно до ближайшего дела: созревшего пакета, срока сводки,
           уборки таблицы. Не до фиксированного тика — иначе задержки плана
           округлялись бы вверх на его величину. */
        uint64_t wake = t + 200 * NS_PER_MS;      /* потолок ожидания: 200 мс */
        uint64_t due = d2k_sched_next_ns(sched);
        if (due && due < wake) { wake = due; }
        if (next_stats && next_stats < wake) { wake = next_stats; }
        if (next_expire < wake) { wake = next_expire; }

        int timeout_ms = 0;
        if (wake > t) {
            uint64_t d = (wake - t + NS_PER_MS - 1) / NS_PER_MS;
            timeout_ms = (d > 200) ? 200 : (int)d;
        }

        struct pollfd pfd[3];
        nfds_t nfd = 0;
        pfd[nfd].fd = d2k_nfq_fd(q);
        pfd[nfd].events = POLLIN;
        pfd[nfd].revents = 0;
        const nfds_t iq = nfd++;

        nfds_t il = (nfds_t)-1, ip = (nfds_t)-1;
        if (ctl) {
            pfd[nfd].fd = d2k_ctl_listen_fd(ctl);
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            il = nfd++;
            int p = d2k_ctl_peer_fd(ctl);
            if (p >= 0) {
                pfd[nfd].fd = p;
                pfd[nfd].events = POLLIN;
                pfd[nfd].revents = 0;
                ip = nfd++;
            }
        }

        int pr = poll(pfd, nfd, timeout_ms);
        if (pr < 0 && errno != EINTR) {
            st.recv_err++;
        }

        if (ctl) {
            if (il != (nfds_t)-1 && (pfd[il].revents & POLLIN)) {
                d2k_ctl_accept(ctl);
            }
            if (ip != (nfds_t)-1 && (pfd[ip].revents & (POLLIN | POLLHUP))) {
                d2k_ctl_poll(ctl, d2k_ctlsrv_command, &cx);
            }
            d2k_ctl_flush(ctl);
        }

        if (pr > 0 && (pfd[iq].revents & POLLIN)) {
            ssize_t n = d2k_nfq_recv(q, rbuf, sizeof rbuf, err, sizeof err);
            if (n == -1) {
                st.recv_err++;
                fprintf(stderr, "d2kd: %s\n", err);
            } else if (n > 0) {
                t = now_ns();
                d2k_nl_iter it;
                d2k_nl_msg m;
                d2k_nl_iter_init(&it, rbuf, (size_t)n);
                while (d2k_nl_next(&it, &m)) {
                    int32_t kerr = 0;
                    if (d2k_nl_errno(&m, &kerr) == 0) {
                        if (kerr != 0) {
                            /* Молчаливо копить пакеты, получая EINVAL, уже
                               случалось на этапе 0. Больше не молча. */
                            fprintf(stderr, "d2kd: ядро отвергло сообщение: %s\n",
                                    strerror(-kerr));
                        }
                        continue;
                    }
                    if ((m.type & 0xff) != D2K_NFQNL_MSG_PACKET) {
                        continue;
                    }

                    d2k_nl_pkt np;
                    if (d2k_nl_packet(&m, &np) != 0 || !np.have_hdr) {
                        st.no_hdr++;
                        continue;   /* вердикт слать некому: нет номера пакета */
                    }

                    st.seen++;
                    st.bytes += np.payload_len;

                    uint32_t verdict = D2K_NF_ACCEPT;
                    d2k_result res;
                    memset(&res, 0, sizeof res);
                    res.verdict = D2K_VERDICT_ACCEPT;

                    if (!np.have_payload) {
                        st.no_payload++;
                        res.skipped = "ядро не отдало пакет";
                    } else if (np.truncated) {
                        /* Рассуждать о куске, считая его целым, нельзя. */
                        st.truncated++;
                        res.skipped = "пакет обрезан copy_range";
                    } else {
                        d2k_session_packet(sess, np.payload, np.payload_len, t,
                                           obuf, sizeof obuf, &res);
                    }

                    if (res.skipped) {
                        count_reason(res.skipped);
                    }

                    if (mode == MODE_APPLY) {
                        if (res.verdict == D2K_VERDICT_DROP) {
                            verdict = D2K_NF_DROP;
                        }
                    }


                    /* ПОРЯДОК ЗДЕСЬ — ЧАСТЬ ПЛАНА, А НЕ ДЕТАЛЬ.
                     *
                     * Посылки без задержки уходят ДО вердикта. Плечо
                     * place=before означает «фальшивка перед нагрузкой»; если
                     * сперва отпустить оригинал, фальшивка придёт коробке
                     * после него, и плечо превратится в другое. Первая
                     * редакция службы посылала вердикт первым делом, ради
                     * освобождения ячейки очереди, — и молча ломала бы
                     * каждое плечо с place=before.
                     *
                     * Ячейка при этом держится дольше ровно на одну
                     * sendto — десятки микросекунд.
                     *
                     * Задержки отсчитываются от предыдущей посылки. */
                    uint64_t at = t;
                    for (size_t k = 0; k < res.n_out && mode == MODE_APPLY; k++) {
                        at += (uint64_t)res.out[k].delay_us * NS_PER_US;
                        const uint8_t *p = obuf + res.out[k].off;
                        size_t plen = res.out[k].len;
                        if (at <= t) {
                            if (d2k_raw_send(raw, p, plen, err, sizeof err) != 0) {
                                st.send_fail++;
                                fprintf(stderr, "d2kd: %s\n", err);
                                break;
                            }
                            st.emitted++;
                        } else if (d2k_sched_push(sched, at, p, plen) != 0) {
                            st.send_fail++;
                            break;
                        } else {
                            st.deferred++;
                        }
                    }

                    if (d2k_nfq_verdict(q, np.id, verdict, err, sizeof err) != 0) {
                        st.verdict_fail++;
                    }
                    if (verdict == D2K_NF_DROP) {
                        st.dropped++;
                    } else {
                        st.accepted++;
                    }
                }
            }
        }

        /* --- созревшие отложенные ------------------------------------------ */
        t = now_ns();
        if (raw) {
            size_t slen = 0;
            while (d2k_sched_pop_due(sched, t, sbuf, sizeof sbuf, &slen)) {
                if (d2k_raw_send(raw, sbuf, slen, err, sizeof err) != 0) {
                    st.send_fail++;
                } else {
                    st.emitted++;
                }
            }
        }

        if (t >= next_expire) {
            d2k_session_expire(sess, t, idle_ns);
            next_expire = t + NS_PER_S;
        }
        if (ctl) {
            d2k_ctlsrv_pump(ctl, sess, &events_seen);
        }
        if (next_stats && t >= next_stats) {
            print_stats(sess, sched, q, raw, t - start);
            next_stats = t + (uint64_t)stats_s * NS_PER_S;
        }
    }

    printf("\n=== итог d2kd[%ld] ===\n", (long)getpid());
    print_stats(sess, sched, q, raw, now_ns() - start);
    print_journal(sess, start);

    d2k_ctl_close(ctl);
    d2k_sched_free(sched);
    d2k_session_free(sess);
    d2k_nfq_close(q);
    d2k_raw_close(raw);
    return 0;
}
