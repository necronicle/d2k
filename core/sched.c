/* sched.c — планировщик поисков, один на оба транспорта. См. d2k_sched.h.
 *
 * УСТРОЙСТВО В ОДИН АБЗАЦ. Датапат шлёт события; цикл (d2kc.c) отдаёт их сюда
 * по одному. Приветствие (D2K_EV_HELLO) запоминает имя за ключом потока —
 * подозрение имени не несёт (на проводе это ключ и код причины, core/link.c),
 * и связать их иначе нечем. Подозрение (D2K_EV_SUSPECT) заводит задачу по паре
 * (имя, транспорт) и отправляет её сетевому оракулу в рабочий поток. Оракул
 * возвращается вердиктом; по вердикту собираются планы; план ставится
 * командой; успех подтверждается событием обмена с прикладными данными.
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
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "d2k_compose.h"
#include "d2k_compose_internal.h"
#include "d2k_hello.h"
#include "d2k_plantlv.h"
#include "d2k_quicprobe.h"
#include "d2k_sched.h"

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

/* Зондов на задачу. ПЕРЕСМОТРЕТЬ ЗАМЕРОМ (задача 6 плана): ревью 06.09
   показало, что на тяжёлой цели восьми не хватает и поиск обрывается по
   бюджету при неисчерпанных кандидатах. До замера держим унаследованное
   значение — назначать новое «на глаз» было бы ровно тем, что правило про
   числа запрещает. */
#define SCHED_MAX_PROBES 8

/* Сколько раз кандидат может примениться БЕЗ обмена, прежде чем считаться
   плохим. Унаследовано с Go-стороны (controller.go, maxSilentTries) вместе с
   её обоснованием: одного раза мало (применение говорит, что кандидат доехал
   до соединения, а не что дело дошло до обмена), а без предела кандидат,
   который исправно применяется и не даёт обмена, залипал бы до истечения
   задачи — то есть на десять минут. Два, а не три: каждое применение без
   обмена — это ожидание у человека, и порог считается в его секундах.

   Живой прогон 11.09 показал ровно это залипание: по www.speedtest.net
   кандидат применился шесть раз, обмена не было, и поиск стоял. */
#define SCHED_MAX_SILENT 2

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

/* --------------------------------------------------------------------
 * Подменяемые оракулы (см. d2k_sched.h).
 * -------------------------------------------------------------------- */
d2k_sched_tcp_fn  d2k_sched_tcp_hook  = d2k_classify;
d2k_sched_quic_fn d2k_sched_quic_hook = d2k_quic_classify;

/* --------------------------------------------------------------------
 * Состояние задачи.
 * -------------------------------------------------------------------- */

typedef enum {
    T_FREE = 0,
    T_ASKING,    /* сетевой оракул работает в потоке */
    T_PLANNING,  /* вердикт есть, ставим планы */
    T_WATCHING,  /* план стоит, ждём обмена */
    T_RESTING    /* неудача, цель отдыхает */
} task_state;

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

    /* Кандидаты, собранные d2k_compose по вердикту. */
    char       plans[8][4096];
    size_t     n_plans;
    size_t     next_plan;
    int        silent_applied;  /* применений текущего кандидата без обмена */

    /* Рабочий поток оракула. */
    pthread_t  th;
    int        th_live;
    d2k_vres   res;
    int        res_ready;   /* пишется потоком под мьютексом планировщика */
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

    task         tasks[SCHED_MAX_TASKS];
    seen_name    seen[SCHED_SEEN];
    size_t       seen_next;   /* кольцо: старое вытесняется, а не отказывает */

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

static int start_worker(d2k_sched *s, task *t) {
    worker_arg *a = malloc(sizeof *a);
    if (!a) { return -1; }
    a->s = s; a->t = t;
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

static int bind_confirmed(d2k_catalog *c, const char *box_id, const char *plan_id,
                          const char *plan_text, const char *proto,
                          const char *target, uint8_t transport, int64_t now_ms) {
    d2k_cat_box *b = box_ensure(c, box_id);
    if (!b) { return -1; }
    if (b->created == 0) { b->created = now_ms / 1000; }
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
        if (bd->transport == transport && strcmp(bd->target, target) == 0) {
            bd->successes++;
            bd->confirmed = now_ms / 1000;
            snprintf(bd->plan_id, sizeof bd->plan_id, "%s", plan_id);
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
    b->n_binds++;
    return 0;
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

/* --------------------------------------------------------------------
 * Ход задачи.
 * -------------------------------------------------------------------- */

static void task_fail(task *t, int64_t now_ms) {
    join_worker(t);
    t->state = T_RESTING;
    t->rest_until_ms = now_ms + SCHED_REST_MS;
    t->n_plans = 0;
    t->next_plan = 0;
}

static void task_done(task *t) {
    join_worker(t);
    memset(t, 0, sizeof *t);
    t->state = T_FREE;
}

/* Ставит следующего кандидата. 0 — поставлен, -1 — кандидаты кончились. */
static int install_next(d2k_sched *s, task *t) {
    while (t->next_plan < t->n_plans) {
        if (t->probes >= SCHED_MAX_PROBES) { return -1; }
        const char *text = t->plans[t->next_plan++];
        t->probes++;
        /* План в каталог НЕ пишется здесь: кандидат — ещё не знание (§10).
           Пишется только подтверждённый обменом, в on_exchange ниже. */
        char err[160];
        /* d2k_compose выдаёт ТЕКСТ, датапат принимает hex от TLV — перевод
           обязателен, и без него сюда уезжал бы текст, который
           d2k_link_set_name законно отвергает как «не hex» (так и было
           обнаружено первым прогоном test_sched). */
        static char hex[2 * D2K_PLAN_TLV_MAX + 1];
        if (d2k_plan_text_to_hex(text, hex, sizeof hex, err, sizeof err) != 0) {
            continue; /* кандидат не переводится — не наше наблюдение о коробке */
        }
        if (d2k_link_set_name(s->link_fd, t->name, t->transport, hex, err, sizeof err) == 0) {
            return 0;
        }
    }
    return -1;
}

static void verdict_to_plans(task *t, d2k_verdict v) {
    t->n_plans = 0;
    t->next_plan = 0;
    if (v == D2K_V_CLEAR || v == D2K_V_UNREACHABLE ||
        v == D2K_V_INCONCLUSIVE || v == D2K_V_FLAKY) {
        /* Обходить нечего, либо мерить было нечем. Ни то, ни другое не
           знание о плане — в каталог не идёт ничего (§10, §13). */
        return;
    }
    d2k_props pr;
    memset(&pr, 0, sizeof pr);
    d2k_shape sh = d2k_hello_shape(t->trig, t->trig_len);
    t->n_plans = d2k_compose(&pr, sh, SCHED_DECOY, t->plans, 8);
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

void d2k_sched_free(d2k_sched *s) {
    if (!s) { return; }
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        join_worker(&s->tasks[i]);
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
        if (st == T_ASKING || st == T_PLANNING || st == T_WATCHING) { n++; }
    }
    return n;
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
        return 0; /* по этой паре (имя, транспорт) поиск уже идёт */
    }
    t = task_free_slot(s);
    if (!t) {
        return 0; /* мест нет — подозрение придёт снова, датапат не молчит */
    }
    memset(t, 0, sizeof *t);
    snprintf(t->name, sizeof t->name, "%s", name);
    t->transport = ev->transport;
    server_of(ev, t->ip, sizeof t->ip, &t->port);
    t->started_ms = 0;
    if (fill_hellos(t) != 0) {
        memset(t, 0, sizeof *t);
        return 0;
    }
    if (!t->shape_armed) {
        char err[128];
        if (d2k_link_arm_shape(s->link_fd, t->name, err, sizeof err) == 0) {
            t->shape_armed = 1;
        }
    }
    t->state = T_ASKING;
    if (start_worker(s, t) != 0) {
        memset(t, 0, sizeof *t);
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
            say(s, "по %s поймана форма приветствия: %zu байт", t->name, ev->shape_len);
        }
    }
}

/* Кандидат доехал до какого-то соединения. Это НЕ успех: §8 требует
   прикладного обмена. Считаем молчаливые применения, чтобы не залипнуть на
   кандидате, который исправно применяется и ничего не даёт.

   Только TCP: у QUIC-потока событие обмена прийти не может структурно —
   datapath/session.c считает обмены и обходит по молчанию ТОЛЬКО таблицу
   TCP-потоков, handle_udp возвращается раньше этого хвоста. Считать сюда
   QUIC-применения значило бы отбрасывать рабочего кандидата по молчанию
   потоков, для которых подтверждение вообще не реализовано, — ровно та
   оговорка, которую Go-сторона написала у себя в EvApplied. */
static void on_applied(d2k_sched *s, const d2k_ev *ev) {
    if (ev->transport != 6) { return; }
    const char *name = recall(s, ev);
    if (!name) { return; }
    task *t = task_of(s, name, ev->transport);
    if (!t || t->state != T_WATCHING) { return; }
    t->silent_applied++;
    if (t->silent_applied >= SCHED_MAX_SILENT) {
        say(s, "по %s кандидат %zu применился %d раза без обмена — беру следующего",
            t->name, t->next_plan, t->silent_applied);
        t->state = T_PLANNING; /* следующий круг тика поставит следующего */
    }
}

static void on_exchange(d2k_sched *s, const d2k_ev *ev, int64_t now_ms) {
    if (!d2k_ev_has_appdata(ev)) {
        return; /* §8: порог — прикладной обмен, а не любые вернувшиеся байты */
    }
    const char *name = recall(s, ev);
    if (!name) { return; }
    task *t = task_of(s, name, ev->transport);
    if (!t || t->state != T_WATCHING || t->next_plan == 0) { return; }

    const char *text = t->plans[t->next_plan - 1];
    char plan_id[40], box_id[40];
    snprintf(plan_id, sizeof plan_id, "plan-%08x", (unsigned)(fnv1a(text) & 0xFFFFFFFFu));
    /* Коробка пока опознаётся по примете подозрения; до тех пор, пока приметы
       не собраны, поведение группируется по транспорту — это честнее, чем
       завести одну коробку «всё подряд» и выдать её за узнанную. */
    snprintf(box_id, sizeof box_id, "box-транспорт-%u", (unsigned)t->transport);
    (void)bind_confirmed(s->cat, box_id, plan_id, text,
                         t->transport == 17 ? "quic" : "tcp",
                         t->name, t->transport, now_ms);
    say(s, "по %s (%s) ПОДТВЕРЖДЕНО прикладным обменом: %s, %u байт",
        t->name, t->transport == 17 ? "QUIC" : "TCP", plan_id, (unsigned)ev->num);
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
    case D2K_EV_SHAPE:
        on_shape(s, ev);
        return 0;
    case D2K_EV_APPLIED:
        on_applied(s, ev);
        return 0;
    case D2K_EV_EXCHANGE:
        on_exchange(s, ev, 0);
        return 0;
    default:
        return 0;
    }
}

int d2k_sched_tick(d2k_sched *s, int64_t now_ms) {
    if (!s) { return 0; }

    /* Осушить самопайп: он только будит, содержимое значения не имеет. */
    uint8_t drain[64];
    while (read(s->wake[0], drain, sizeof drain) > 0) { }

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
            task_fail(t, now_ms);
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
            verdict_to_plans(t, r.verdict);
            say(s, "по %s вердикт: %s (%s), кандидатов %zu",
                t->name, verdict_name(r.verdict), r.reason, t->n_plans);
            if (t->n_plans == 0) {
                task_fail(t, now_ms);
                moved++;
                continue;
            }
            t->state = T_PLANNING;
            moved++;
        }

        if (t->state == T_PLANNING) {
            if (install_next(s, t) != 0) {
                say(s, "по %s кандидаты кончились (зондов %d) — цель отдыхает",
                    t->name, t->probes);
                task_fail(t, now_ms);
                moved++;
                continue;
            }
            t->silent_applied = 0;
            say(s, "по %s поставил кандидата %zu из %zu, жду обмена",
                t->name, t->next_plan, t->n_plans);
            t->state = T_WATCHING;
            moved++;
        }
    }
    return moved;
}
