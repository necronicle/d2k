/* Exercise production terminal/reset paths without creating a network worker. */
#define pthread_create summary_thread_create
#define d2k_verify_probe_ech_origin_on summary_ech_probe
#define d2k_verify_doh_on summary_doh_probe
#include "sched.c"
#include "test_task_slots.h"
#undef d2k_verify_doh_on
#undef d2k_verify_probe_ech_origin_on
#undef pthread_create
#include "d2k_quic_arms.h"
#include "d2k_plantlv.h"

static int capture_spawn;
int summary_thread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg) {
    (void)thread; (void)attr; (void)start; (void)arg;
    /* Аргумент — слот задачи (task_slot.worker): не освобождается. */
    if (capture_spawn) { (void)arg; return 0; }
    return EAGAIN;
}

/* Без сети (стенд Astra, ревью rx6): ECH-зонд свидетеля и HTTPS RR подменены. */
static char probed_origin[256];
static int probe_calls;
d2k_ver_result summary_ech_probe(int use_fd, const char *ip, uint16_t port,
    const char *outer, const char *origin, int deadline, size_t wire,
    uint32_t mark, const char *path) {
    (void)use_fd; (void)ip; (void)port; (void)outer;
    (void)deadline; (void)wire; (void)mark; (void)path;
    probe_calls++;
    snprintf(probed_origin, sizeof probed_origin, "%s", origin ? origin : "");
    d2k_ver_result r = {0}; r.fd = -1; return r;
}
static int rr_queries;
static int summary_resolve(const char *name, uint32_t mark, d2k_ech_config *cfg) {
    (void)mark;
    rr_queries++;
    if (!strcmp(name, "bad1.example") || !strcmp(name, "bad2.example")) return -1;
    memset(cfg, 0, sizeof *cfg);
    strcpy(cfg->public_name, "cloudflare-ech.com"); return 0;
}

static int fails;
static char rows[8192];
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"summary:%d: %s\n",__LINE__,#x); fails++; } } while (0)
static void collect(void *ctx, const char *line) {
    (void)ctx;
    size_t used = strlen(rows);
    snprintf(rows + used, sizeof rows - used, "%s\n", line);
}
/* ЗАДАЧА 26: подменённая проба объёма. Мерить по «/» (или по устаревшему
   свидетелю привязки) нечем — завершённый 403 на 243 байта; обрыв даёт ТОЛЬКО
   путь, который уже наблюдался у этой цели (vol_cut_path). Проба в сеть не
   ходит: предмет проверки — какой путь спрашивает планировщик. */
static const char *vol_cut_path;
static char vol_asked[4][512];
static int vol_asks;
static d2k_vol_result vol_answer_for(const char *path) {
    d2k_vol_result r;
    memset(&r, 0, sizeof r);
    if (vol_asks < 4) snprintf(vol_asked[vol_asks], sizeof vol_asked[0], "%s", path ? path : "");
    vol_asks++;
    r.verdict = D2K_VOL_PASSED;
    r.at_kb = 40;
    if (path && vol_cut_path && !strcmp(path, vol_cut_path)) {
        r.rx_cut = 1; r.rx_compressed_complete = 1; r.rx_at_kb = 15;
        snprintf(r.measured_path, sizeof r.measured_path, "%s", path);
        snprintf(r.rx_reason, sizeof r.rx_reason, "обрыв 15985/15968, gzip завершился");
    } else {
        /* МЕРИТЬ БЫЛО НЕЧЕМ: ответ завершён и меньше полосы. Это НЕ парное
           отрицательное измерение (см. rx_short в d2k_volume.h). */
        r.rx_short = 1; r.rx_short_bytes = 243;
        snprintf(r.rx_reason, sizeof r.rx_reason, "HTTP 403, тело 243/243, complete=1");
    }
    return r;
}
static d2k_vol_result stub_vol_path(const char *ip, uint16_t port, const char *sni,
    int plain, int tls12, size_t wire, uint32_t mark, const char *path) {
    (void)ip; (void)port; (void)sni; (void)plain; (void)tls12; (void)wire; (void)mark;
    return vol_answer_for(path);
}
static d2k_vol_result stub_vol_root(const char *ip, uint16_t port, const char *sni,
    int plain, int tls12, size_t wire, uint32_t mark) {
    (void)ip; (void)port; (void)sni; (void)plain; (void)tls12; (void)wire; (void)mark;
    return vol_answer_for("");
}

static task *fixture(d2k_sched *s) {
    task *t = test_task_at(s, 0);
    memset(t, 0, sizeof *t);
    t->prop_fd = t->prop_q = t->probe_fd = t->ver.fd = t->c_fd = -1;
    strcpy(t->name, "summary.example");
    strcpy(t->ip, "127.0.0.1");
    t->port = 443; t->transport = 6; t->family = 4;
    t->shape_armed = 1;
    t->report_id = ++s->report_sequence;
    t->report_admitted_ms = 100;
    t->state = T_QUEUED;
    t->queued_ms = 800;
    t->report_queue_ms = 50; /* an earlier queue, then shape wait */
    s->now_ms = 900; s->clock_seen = 1;
    rows[0] = 0;
    return t;
}
/* Поле 17.10.2026, router-round RR3-fix2-1: свидетель ECH romfea.gr стоит за
   Cloudflare challenge. Под планом рукопожатие с принятым ECH прошло, сервер
   свидетеля ответил своей challenge-страницей — и cloudflare-ech.com получил
   60-минутную антибот-паузу: Chrome с ECH не открыл ни одного CF-сайта.
   Свидетель доказывает только проход ECH через коробку; полный HTTP-ответ его
   сервера через принятый ECH — это доказательство, а не антибот цели. */
static void ech_witness_challenge_is_transport_proof(d2k_sched *s) {
    task *t = fixture(s);
    strcpy(t->name, "cloudflare-ech.com"); strcpy(t->ech_origin, "romfea.gr");
    t->transport = 6; t->ech_offer = 1; t->ech_replay = 0;
    memset(&t->ver, 0, sizeof t->ver);
    t->ver.level = D2K_VER_CHALLENGE; t->ver.cloudflare_challenge = 1;
    t->ver.ech_accepted = 1; t->ver.name_ok = 1; t->ver.body_complete = 1; t->ver.status = 403;
    CHECK(ech_witness_transport_proof(t) == 1);
    t->ver.ech_accepted = 0;
    CHECK(ech_witness_transport_proof(t) == 0);  /* ECH не принят — прохода нет */
    t->ver.ech_accepted = 1; t->ver.body_complete = 0;
    CHECK(ech_witness_transport_proof(t) == 0);  /* ответ не полный */
    t->ver.body_complete = 1; t->ver.name_ok = 0;
    CHECK(ech_witness_transport_proof(t) == 0);  /* чужое имя сертификата */
    t->ver.name_ok = 1; strcpy(t->ech_origin, "cloudflare-ech.com");
    CHECK(ech_witness_transport_proof(t) == 0);  /* без свидетеля challenge — цели */
    strcpy(t->ech_origin, "romfea.gr"); t->ech_offer = 0;
    CHECK(ech_witness_transport_proof(t) == 0);  /* не ECH — обычный challenge */
    t->ech_offer = 1; t->ech_replay = 1;
    CHECK(ech_witness_transport_proof(t) == 0);  /* повтор байтов клиента — иной путь */
    t->ech_replay = 0; t->ver.level = D2K_VER_HANDSHAKE; t->ver.cloudflare_challenge = 0;
    CHECK(ech_witness_transport_proof(t) == 0);  /* рукопожатие без ответа — не проход */
    task_reset(s, t);
}

/* Поле 17.10.2026, RR3-ech1-1: под планами из перебора рукопожатие с принятым
   ECH проходит, свидетель kinozal.me отвечает 200, а тело обрывается около
   21 КБ — объёмный обрыв. Его надо считать измеренным RX-обрывом и включать
   лестницу белого имени, иначе кандидаты кончаются без плана. */
static void ech_witness_body_cut_is_rx_cut(d2k_sched *s) {
    task *t = fixture(s);
    strcpy(t->name, "cloudflare-ech.com"); strcpy(t->ech_origin, "kinozal.me");
    t->transport = 6; t->ech_offer = 1; t->ech_replay = 0;
    memset(&t->ver, 0, sizeof t->ver);
    t->ver.level = D2K_VER_TRANSPORT; t->ver.ech_accepted = 1; t->ver.name_ok = 1;
    t->ver.status = 200; t->ver.body_bytes = 21300; t->ver.body_expected = 0;
    t->ver.body_complete = 0; t->ver.body_framing_valid = 1;
    CHECK(ech_witness_rx_cut(t) == 1);
    t->ver.body_complete = 1;
    CHECK(ech_witness_rx_cut(t) == 0);   /* тело целиком — обрыва нет */
    t->ver.body_complete = 0; t->ver.body_bytes = 900;
    CHECK(ech_witness_rx_cut(t) == 0);   /* 900 байт — не объёмный обрыв */
    t->ver.body_bytes = 21300; t->ver.ech_accepted = 0;
    CHECK(ech_witness_rx_cut(t) == 0);   /* ECH не принят */
    t->ver.ech_accepted = 1; t->ver.status = 0;
    CHECK(ech_witness_rx_cut(t) == 0);   /* HTTP не разобран */
    t->ver.status = 200; strcpy(t->ech_origin, "cloudflare-ech.com");
    CHECK(ech_witness_rx_cut(t) == 0);   /* без свидетеля */
    task_reset(s, t);
}

/* Поле 17.10.2026, LR-rx4-1: свидетель romfea.gr отвечает через принятый ECH
   страницей проверки Cloudflare (403, 3,6 КБ). Проход ECH она доказывает, а
   обрыв на ~16 КБ на ней не случится: план перебора, снимающий только
   рукопожатие, подтверждался, и Chrome резался у шести сайтов.
   mode 0 — в списке есть другой свидетель (kinozal.me): тот же кандидат,
   следующего свидетеля выберет рабочий поток VERIFY; отчёт поиска открыт,
   список и курсор кандидатов те же (ревью Astra п.1, п.3);
   mode 1 — другого нет; mode 2 — другой тоже отвечал проверкой: ни
   подтверждения, ни паузы, кандидат не измерен (ревью Astra п.2). */
static void ech_challenge_witness(d2k_sched *s, int mode) {
    task *t = fixture(s);
    strcpy(t->name, "cloudflare-ech.com"); strcpy(t->ech_origin, "romfea.gr");
    t->transport = 6; t->ech_offer = 1; t->ech_replay = 0;
    strcpy(t->ech_witnesses[t->ech_witness_count++], "romfea.gr");
    ech_rr_store(s, "romfea.gr", 1, "cloudflare-ech.com");
    if (mode != 1) {
        strcpy(t->ech_witnesses[t->ech_witness_count++], "kinozal.me");
        ech_rr_store(s, "kinozal.me", 1, "cloudflare-ech.com");
    }
    if (mode == 2) ech_chal_add(s, "kinozal.me");
    snprintf(t->plans[0], sizeof t->plans[0], "%s", "tcp split pos=1");
    snprintf(t->plans[1], sizeof t->plans[1], "%s", "tcp split pos=2");
    t->n_plans = 2; t->next_plan = 1;
    memset(&t->ver, 0, sizeof t->ver);
    t->ver.fd = -1;
    t->ver.level = D2K_VER_CHALLENGE; t->ver.cloudflare_challenge = 1;
    t->ver.ech_accepted = 1; t->ver.name_ok = 1; t->ver.body_complete = 1; t->ver.status = 403;
    t->state = T_VERIFY; t->res_ready = 1;
    s->sync_pending = 0;
    capture_spawn = 1;
    (void)d2k_sched_tick(s, 900);
    capture_spawn = 0;
    t->th_live = 0; /* подменённое создание: потока нет, не присоединять */
    CHECK(strstr(rows, "ПОДТВЕРЖДЕНО") == NULL);
    CHECK(strstr(rows, "проход ECH через коробку доказан") == NULL);
    CHECK(strstr(rows, "антибот-ответ") == NULL);
    CHECK(ech_chal_has(s, "romfea.gr"));
    if (mode == 0) {
        CHECK(strstr(rows, "тот же кандидат проверяю через другого свидетеля") != NULL);
        CHECK(t->ech_reselect == 1);
        /* Тот же кандидат: курсор вернулся на него, установка — следующим тактом. */
        CHECK(t->n_plans == 2 && t->next_plan == 0 && t->state == T_PLANNING);
        CHECK(!strcmp(t->plans[0], "tcp split pos=1") && !strcmp(t->plans[1], "tcp split pos=2"));
        CHECK(!t->report_closed);
        rows[0] = 0;
        search_report(s, t, 901, "probe-confirmed", "property",
                      "кандидат подтверждён собственным зондом на проводе");
        CHECK(strstr(rows, "outcome=probe-confirmed") != NULL);
    } else {
        CHECK(strstr(rows, "через другого свидетеля") == NULL);
        /* Проверять объём нечем: кандидаты не оцениваются, поиск закрыт
           неубедительным (ревью Astra R2), без паузы антибота. */
        CHECK(strstr(rows, "объём ответа измерить нечем") != NULL);
        CHECK(strstr(rows, "outcome=inconclusive") != NULL);
        CHECK(!t->ech_reselect);
    }
    if (fails) fprintf(stderr, "%s\n", rows);
    memset(s->ech_chal, 0, sizeof s->ech_chal);
    memset(s->ech_rr, 0, sizeof s->ech_rr); s->ech_rr_next = 0;
    task_reset(s, t);
}

/* Ревью Astra rx6: следующего свидетеля выбирает рабочий поток VERIFY по
   необходимости; исключение — по результату (RR не та, страница проверки),
   не по счёту. mode 0 — подходящий третий после двух неподходящих; mode 1 —
   подходящих не осталось: зонда нет, кандидат не измерен. */
static void verify_reselects_witness(d2k_sched *s, int mode) {
    task *t = fixture(s);
    strcpy(t->name, "cloudflare-ech.com"); strcpy(t->ech_origin, "primary.example");
    t->transport = 6; t->ech_offer = 1; t->ech_reselect = 1; t->job = JOB_VERIFY;
    strcpy(t->ech_witnesses[t->ech_witness_count++], "primary.example");
    ech_rr_store(s, "primary.example", 1, t->name);
    ech_chal_add(s, "primary.example");
    strcpy(t->ech_witnesses[t->ech_witness_count++], "bad1.example");
    strcpy(t->ech_witnesses[t->ech_witness_count++], "bad2.example");
    if (mode == 0) strcpy(t->ech_witnesses[t->ech_witness_count++], "third.example");
    rr_queries = 0; probe_calls = 0; probed_origin[0] = 0;
    d2k_sched_ech_resolve_hook = summary_resolve;
    worker_arg *arg = calloc(1, sizeof *arg);
    arg->s = s; arg->t = t; arg->use_fd = -1;
    worker_run(arg);free(arg);
    CHECK(!t->ech_reselect);
    if (mode == 0) {
        CHECK(probe_calls == 1 && !strcmp(probed_origin, "third.example"));
        CHECK(!strcmp(t->ech_origin, "third.example"));
        CHECK(rr_queries == 3);
    } else {
        CHECK(probe_calls == 0);
        CHECK(!strcmp(t->ech_origin, "primary.example"));
        CHECK(t->ver.level == D2K_VER_HANDSHAKE && strstr(t->ver.reason, "не осталось"));
        /* The next candidate has the same task but no reselect flag. */
        worker_arg *next = calloc(1, sizeof *next);
        next->s = s; next->t = t; next->use_fd = -1;
        worker_run(next);free(next);
        CHECK(probe_calls == 0);
        fprintf(stderr, "after exhaustion: probe_calls=%d origin=%s\n", probe_calls, probed_origin);
    }
    if (fails) fprintf(stderr, "reselect mode=%d origin=%s probed=%s rr=%d\n%s\n",
        mode, t->ech_origin, probed_origin, rr_queries, rows);
    d2k_sched_ech_resolve_hook = d2k_ech_resolve;
    memset(s->ech_chal, 0, sizeof s->ech_chal);
    memset(s->ech_rr, 0, sizeof s->ech_rr); s->ech_rr_next = 0;
    task_reset(s, t);
}

/* Поле 17.10.2026, LR-rx5-2/rx6-1/rx6-2: у spzh.eu RX-проба получает 403
   (4540 Б), измерен только обрыв ИСХОДЯЩЕЙ лестницы ~19 КБ. Лестница белого
   имени открывалась только RX-обрывом: если spzh искался раньше, чем сеть
   подобрала 9gag.com на соседнем сайте, — перебор и «лучший частичный» план по
   403, Safari стоял; позже — свой план коробки, Safari открывался (rx5-1).
   Обрыв той же коробки в другую сторону — тот же вопрос имени. */
static void tx_cut_opens_white_ladder(d2k_sched *s, int known) {
    task *t = fixture(s);
    strcpy(t->name, "spzh.eu");
    CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "spzh.eu", t->trig, sizeof t->trig,
                                 &t->trig_len) == 0);
    t->vol.verdict = D2K_VOL_CUT; t->vol.at_kb = 19; t->vol.rx_cut = 0;
    snprintf(s->cat->net.name, sizeof s->cat->net.name, "%s", known ? "9gag.com" : "");
    s->cat->net.searched = known;
    d2k_vres r; memset(&r, 0, sizeof r); r.verdict = D2K_V_INCONCLUSIVE;
    verdict_to_plans(s, t, &r);
    char want[sizeof t->plans[0]];
    CHECK(d2k_rx_volume_plan_named(0, D2K_SHAPE_MODERN, s->send_cap,
                                   known ? "9gag.com" : d2k_net_whitelist_name(0),
                                   want, sizeof want) == 0);
    CHECK(t->n_plans > 0 && !strcmp(t->plans[0], want));
    if (!known) CHECK(t->net_probing);
    if (fails) fprintf(stderr, "%s\n", rows);
    s->cat->net.name[0] = 0; s->cat->net.searched = 0;
    task_reset(s, t);
}

static void challenge_exclusions_survive_cache_eviction(d2k_sched *s) {
    task *t = fixture(s);
    strcpy(t->name, "cloudflare-ech.com");
    int seen[10] = {0};
    for (int i = 0; i < 10; i++) {
        snprintf(t->ech_witnesses[i], sizeof t->ech_witnesses[i], "w%d.example", i);
        ech_rr_store(s, t->ech_witnesses[i], 1, t->name);
    }
    t->ech_witness_count = 10;
    for (int step = 0; step < 10; step++) {
        t->ech_origin[0] = 0;
        CHECK(ech_pick_witness(s, t, 1, 0));
        int chosen = -1;
        CHECK(sscanf(t->ech_origin, "w%d.example", &chosen) == 1);
        CHECK(chosen >= 0 && chosen < 10);
        if (chosen < 0 || chosen >= 10) break;
        fprintf(stderr, "challenge step=%d chosen=%s already_seen=%d\n", step, t->ech_origin, seen[chosen]);
        CHECK(!seen[chosen]);
        seen[chosen] = 1;
        ech_witness_reject(s, t); /* главный поток при ответе-проверке */
    }
    memset(s->ech_chal, 0, sizeof s->ech_chal); s->ech_chal_next = 0;
    memset(s->ech_rr, 0, sizeof s->ech_rr); s->ech_rr_next = 0;
    task_reset(s, t);
}

extern int pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static void *finished_worker(void *arg) { return arg; }

static void tx_ladder_requires_volume_proof(int passed) {
    d2k_catalog cat = {0};
    d2k_sched *s = d2k_sched_new(&cat, -1, 0x2d);
    d2k_sched_set_say(s, collect, NULL);
    task *t = fixture(s);
    strcpy(t->name, "spzh.eu");
    CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, t->name, t->trig,
        sizeof t->trig, &t->trig_len) == 0);
    t->trig_snapped = 1;
    t->vol.verdict = D2K_VOL_CUT; t->vol.at_kb = 19;
    d2k_vres r = {0}; r.verdict = D2K_V_INCONCLUSIVE;
    verdict_to_plans(s, t, &r);
    CHECK(t->n_plans > 0 && t->net_probing);
    t->next_plan = 1;
    t->state = T_VERIFY; t->res_ready = 1;
    memset(&t->ver, 0, sizeof t->ver); t->ver.fd = -1;
    t->ver.level = D2K_VER_APPLICATION; t->ver.name_ok = 1;
    t->ver.status = 403; t->ver.body_bytes = t->ver.body_expected = 4540;
    t->ver.body_complete = t->ver.body_framing_valid = 1;
    t->ver.budget = passed ? D2K_BUDGET_PASSED : D2K_BUDGET_NOT_APPLICABLE;
    t->ver.conn_close = !passed;
    t->ver.budget_packets = passed ? 51 : 6; t->ver.budget_need = 50;
    t->ver.local_port = 55001;
    inet_pton(AF_INET, "127.0.0.2", t->ver.local_ip4);
    /* Already validated APPLIED retained for this exact verifier flow. */
    t->ver_seen = 1;
    t->ver_early[0].family = 4; t->ver_early[0].transport = 6;
    memcpy(t->ver_early[0].a_ip, t->ver.local_ip4, 4);
    inet_pton(AF_INET, t->ip, t->ver_early[0].b_ip);
    t->ver_early[0].a_port = t->ver.local_port; t->ver_early[0].b_port = t->port;
    task *direct = test_task_at(s, 1);
    if (passed) {
        memset(direct, 0, sizeof *direct);
        direct->prop_fd = direct->prop_q = direct->probe_fd = direct->ver.fd = direct->c_fd = -1;
        strcpy(direct->name, "direct.example"); strcpy(direct->ip, "127.0.0.3");
        direct->transport=6; direct->family=4; direct->port=443;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, direct->name, direct->trig,
            sizeof direct->trig, &direct->trig_len)==0);
        direct->trig_snapped=1; direct->own_first=3; direct->state=T_ASKING;
        direct->res.verdict=D2K_V_CLEAR; direct->res_ready=1;
        direct->vol.verdict=D2K_VOL_PASSED; direct->vol.rx_direct_complete=1;
        /* Result published after an earlier yield request. A complete short
           RX answer is not a measured cut; TX ladder and handshake passed. */
        if (getenv("REVIEW_SHORT_RX")) {
            direct->vol.rx_short=1;
            direct->vol.rx_short_bytes=243;
            direct->vol.rx_direct_complete=0;
        }
        if (getenv("REVIEW_PENDING_YIELD")) {
            direct->yield_to_own_plan=1;
            direct->stop=1;
        }
        direct->report_id=++s->report_sequence; direct->report_admitted_ms=100;
        direct->started_ms=100;
        CHECK(pthread_create(&direct->th, NULL, finished_worker, NULL)==0);
        if (getenv("REVIEW_NO_YIELD")) pthread_join(direct->th, NULL);
        else direct->th_live=1;
    }
    s->sync_pending = 0;
    (void)d2k_sched_tick(s, 900);
    if(passed) {
        fprintf(stderr, "READY CLEAR after neighbour confirm: state=%d own_first=%d plans=%zu\n", direct->state,direct->own_first,direct->n_plans);
        CHECK(direct->state != T_PLANNING);
        CHECK(strstr(rows,"outcome=probe-direct") != NULL);
    }
    fprintf(stderr, "TX cut + short403: budget_passed=%d net=%s searched=%d\n%s\n", passed, cat.net.name, cat.net.searched, rows);
    CHECK((cat.net.name[0] != 0) == passed);
    /* ДОКАЗАТЕЛЬСТВО СВЯЗАНО С ТИПОМ ОБРЫВА (поле 23.10.2026, правка 8ba945d).
     * Здесь обрыв ИСХОДЯЩЕЙ лестницы, а не RX: имя запоминается — находка для
     * этой цели настоящая, — но подбор остаётся ОТКРЫТЫМ (`searched == 0`) и
     * имя помечено `tx_only`. Прежде оба доказательства закрывали подбор, и
     * цели с ВХОДЯЩИМ обрывом наследовали имя, против их обрыва не
     * проверенное: семь целей отдавали тела 13–17 КБ при ответе 200.
     * Поэтому утверждение здесь не «перевёрнуто», а усилено: проверяются и
     * открытость подбора, и сама пометка. */
    CHECK(cat.net.searched == 0);
    CHECK((cat.net.tx_only != 0) == passed);
    CHECK((strstr(rows, "outcome=probe-confirmed") != NULL) == passed);
    d2k_sched_free(s); d2k_catalog_free(&cat);
}

static int diag_calls;
static void diag_observe(void *ctx,const d2k_diag_event *e) {
    (void)ctx; CHECK(!strcmp(e->outcome,"failed")); CHECK(e->id==999);
    /* ПРИЧИНА ИТОГА — СВОЯ, А НЕ ПОСЛЕДНЯЯ ФРАЗА КЛАССИФИКАТОРА. В диагностике
       владельца 23.10 они противоречили друг другу в 18 событиях из 61:
       «probe-confirmed» с текстом «замер брошен», «failed» с текстом
       «дальнейшие вопросы не нужны». Здесь итог объясняет себя сам. */
    CHECK(e->outcome_reason && strstr(e->outcome_reason, "кандидаты кончились") != NULL);
    /* Идентичность решения едет рядом: пусто, когда решения нет. */
    CHECK(e->plan_id != NULL && e->box_id != NULL);
    diag_calls++;
}

#define REPORT_OBSERVE_MAX 4
static int report_calls;
static uint64_t report_ids[REPORT_OBSERVE_MAX];
static int64_t report_units[REPORT_OBSERVE_MAX], report_elapsed[REPORT_OBSERVE_MAX];
static char report_outcomes[REPORT_OBSERVE_MAX][32];
static void report_observe(void *ctx, const d2k_diag_event *e) {
    (void)ctx;
    if (report_calls < REPORT_OBSERVE_MAX) {
        int i = report_calls;
        report_ids[i] = e->id;
        report_units[i] = e->probe_units;
        report_elapsed[i] = e->elapsed_ms;
        snprintf(report_outcomes[i], sizeof report_outcomes[i], "%s", e->outcome);
    }
    report_calls++;
}

static void rx_short_reports_only_final_cumulative(d2k_sched *s) {
    task *t = fixture(s);
    t->state = T_ASKING; t->rx_volume_only = 1; t->res_ready = 1;
    t->trigger_code = D2K_SUSPECT_FIN_RETRY;
    t->res.verdict = D2K_V_INCONCLUSIVE;
    t->vol.verdict = D2K_VOL_PASSED; t->vol.rx_short = 1; t->vol.rx_short_bytes = 243;
    t->probes = 2; t->ask_probes = 3;
    uint64_t id = t->report_id;
    report_calls = 0;
    d2k_sched_diagnostics(s, report_observe, NULL);
    s->sync_pending = 0; s->measure_start_seen = 0;
    capture_spawn = 1;
    (void)d2k_sched_tick(s, 900);
    capture_spawn = 0;
    CHECK(t->state == T_RESTING && !t->th_live);
    CHECK(t->report_closed && t->report_id == id);
    CHECK(report_calls == 1);
    search_report(s, t, 1000, "unknown", "none", "fixture");
    CHECK(report_calls == 1);
    if (report_calls > 0) {
        CHECK(report_ids[0] == id);
        CHECK(!strcmp(report_outcomes[0], "inconclusive"));
        CHECK(report_units[0] == 5);
        CHECK(report_elapsed[0] == 800);
    }
    if (fails) fprintf(stderr, "RX-short reports=%d closed=%d id=%llu/%llu\n%s\n",
        report_calls, t->report_closed, (unsigned long long)id,
        (unsigned long long)t->report_id, rows);
    d2k_sched_diagnostics(s, NULL, NULL);
    task_reset(s, t);
}

static int doh_calls, doh_mode, doh_classify_calls;
static int doh_protocol_response;
static int doh_force_local;
static int doh_second_mode=-1;
static uint32_t doh_last_mark;
static d2k_vres doh_classify(const char *ip,uint16_t port,d2k_hello a,d2k_hello b,
    uint32_t mark,int repeats,uint32_t gap,uint32_t wait,const volatile sig_atomic_t *stop,const d2k_sched_tcp_extra *extra) {
    (void)extra;
    (void)ip;(void)port;(void)a;(void)b;(void)mark;(void)repeats;(void)gap;(void)wait;(void)stop;
    doh_classify_calls++; d2k_vres r={0};
    r.verdict=doh_protocol_response?D2K_V_INCONCLUSIVE:D2K_V_CLEAR;
    r.protocol_response=doh_protocol_response;return r;
}
d2k_ver_result summary_doh_probe(int fd,const char *ip,uint16_t port,const char *name,
    int wait,size_t wire,int tls12,uint32_t mark,const char *path) {
    (void)ip;(void)port;(void)name;(void)wait;(void)wire;(void)tls12;(void)mark;
    CHECK(!strcmp(path,"/dns-query")); doh_calls++;doh_last_mark=mark;
    d2k_ver_result r={0};r.fd=fd;
    int mode=doh_calls>1 && doh_second_mode>=0?doh_second_mode:doh_mode;
    r.level=mode==0 ? D2K_VER_APPLICATION : D2K_VER_HANDSHAKE;
    r.status=mode==0 ? 200 : mode==2 ? 503 : 0;
    r.body_complete=mode==0 || mode==2;
    r.peer_authenticated=1;
    if(mode==0){r.budget=D2K_BUDGET_PASSED;r.doh_replies=20;}
    if(mode>=3){r.level=D2K_VER_APPLICATION;r.status=200;r.budget=D2K_BUDGET_CUT;r.budget_packets=mode==4?40:24;}
    if(mode==6){r.status=0;r.budget_requests=5;r.doh_replies=4;}
    if(mode==7){r.status=0;r.budget_packets=32;r.budget_requests=6;r.doh_replies=5;}
    r.local_refusal=doh_force_local || mode==5;
    return r;
}
static void doh_service_gate(d2k_sched *s) {
    d2k_ver_result late={0};late.level=D2K_VER_APPLICATION;
    late.budget=D2K_BUDGET_CUT;late.budget_packets=24;late.budget_requests=5;late.doh_replies=4;
    CHECK(doh_measured_cut(&late));
    late.doh_replies=0;CHECK(!doh_measured_cut(&late));
    late.doh_replies=4;late.local_refusal=1;CHECK(!doh_measured_cut(&late));
    char name[]="/tmp/d2k-doh-targets-XXXXXX";
    int config_fd=mkstemp(name);CHECK(config_fd>=0);
    const char *config="dns.example 443 /dns-query 192.0.2.1\n";
    CHECK(write(config_fd,config,strlen(config))==(ssize_t)strlen(config));close(config_fd);
    CHECK(d2k_sched_doh_load(s,name)==1);
    CHECK(s->n_doh==1 && !strcmp(s->doh[0].path,"/dns-query"));
    unlink(name);s->n_doh=0;

    d2k_sched_tcp_fn old=d2k_sched_tcp_hook;
    d2k_sched_tcp_hook=doh_classify;
    for (doh_mode=0;doh_mode<4;doh_mode++) {
        task *t=fixture(s);t->state=T_ASKING;t->job=JOB_CLASSIFY;
        strcpy(t->doh_path,"/dns-query");t->skip_volume_once=1;
        doh_calls=doh_classify_calls=0;
        worker_arg *a=calloc(1,sizeof *a);a->s=s;a->t=t;a->use_fd=-1;
        worker_run(a);free(a);
        CHECK(doh_calls==(doh_mode==3?2:1) && t->res_ready);
        if (doh_mode==0) {
            CHECK(t->res.verdict==D2K_V_CLEAR && t->vol.rx_direct_complete);
            CHECK(!doh_classify_calls && !t->doh_trial);
        } else if (doh_mode==1) {
            CHECK(doh_classify_calls==1 && t->doh_trial);
            d2k_vres r={0};r.verdict=D2K_V_CLEAR;
            verdict_to_plans(s,t,&r);
            CHECK(t->n_plans>0);
        } else if(doh_mode==3) {
            CHECK(!doh_classify_calls && t->vol.rx_cut && t->vol.rx_cut_packets==24);
            CHECK(t->res.verdict==D2K_V_INCONCLUSIVE);
        } else CHECK(!doh_classify_calls && !t->doh_trial);
        task_reset(s,t);
    }
    for(int second=0;second<6;second++) {
        task *t=fixture(s);t->state=T_ASKING;t->job=JOB_CLASSIFY;
        strcpy(t->doh_path,"/dns-query");t->skip_volume_once=1;
        doh_mode=3;doh_second_mode=second;doh_calls=doh_classify_calls=0;
        worker_arg *a=calloc(1,sizeof *a);a->s=s;a->t=t;a->use_fd=-1;
        worker_run(a);free(a);
        CHECK(doh_calls==2 && t->res_ready);
        CHECK(t->vol.rx_cut==(second==3));
        if(second==5)CHECK(t->res.verdict==D2K_V_INCONCLUSIVE && !doh_classify_calls);
        task_reset(s,t);
    }
    doh_second_mode=-1;
    {
        task *late_task=fixture(s);late_task->state=T_ASKING;late_task->job=JOB_CLASSIFY;
        strcpy(late_task->doh_path,"/dns-query");late_task->skip_volume_once=1;
        doh_mode=6;doh_calls=doh_classify_calls=0;
        worker_arg *a=calloc(1,sizeof *a);a->s=s;a->t=late_task;a->use_fd=-1;
        worker_run(a);free(a);
        CHECK(doh_calls==2 && !doh_classify_calls && late_task->vol.rx_cut && late_task->res_ready);
        task_reset(s,late_task);
    }
    {
        task *late_task=fixture(s);late_task->state=T_ASKING;late_task->job=JOB_CLASSIFY;
        strcpy(late_task->doh_path,"/dns-query");late_task->skip_volume_once=1;
        doh_mode=6;doh_second_mode=7;doh_calls=doh_classify_calls=0;
        worker_arg *a=calloc(1,sizeof *a);a->s=s;a->t=late_task;a->use_fd=-1;
        worker_run(a);free(a);
        CHECK(doh_calls==2 && !doh_classify_calls && late_task->vol.rx_cut);
        CHECK(late_task->doh_failure_query==6);
        CHECK(!late_task->vol.rx_wire_basis && !late_task->vol.rx_cut_packets);
        CHECK(late_task->res.verdict==D2K_V_INCONCLUSIVE);
        task_reset(s,late_task);doh_second_mode=-1;
    }
    d2k_sched_tcp_hook=old;
    task *health=fixture(s);health->job=JOB_DOH_HEALTH;
    strcpy(health->doh_path,"/dns-query");
    uint32_t saved_mark=s->mark;s->mark=0x72f;
    doh_calls=0;doh_mode=0;
    worker_arg *health_arg=calloc(1,sizeof *health_arg);
    health_arg->s=s;health_arg->t=health;health_arg->use_fd=-1;
    worker_run(health_arg);free(health_arg);
    CHECK(doh_calls==1 && doh_last_mark==0 && health->res_ready);
    s->mark=saved_mark;task_reset(s,health);
    strcpy(s->doh[0].host,"summary.example");s->doh[0].port=443;s->n_doh=1;
    task *t=fixture(s);t->trigger_code=D2K_SUSPECT_LATE_SILENCE;
    cooldown_record(s,t,3);
    int64_t left=0;
    CHECK(!cooldown_blocks(s,t->name,6,4,t->trigger_code,&left));
    s->n_doh=0;
    CHECK(cooldown_blocks(s,t->name,6,4,t->trigger_code,&left));
    cooldown_clear(s,t->name,6,4);task_reset(s,t);    t=fixture(s);t->state=T_DOH_HEALTH;t->res_ready=1;
    strcpy(t->doh_path,"/dns-query");
    strcpy(s->doh[0].host,t->name);strcpy(s->doh[0].ip,t->ip);strcpy(s->doh[0].path,t->doh_path);
    s->doh[0].port=t->port;s->n_doh=1;
    t->ver.level=D2K_VER_APPLICATION;t->ver.budget=D2K_BUDGET_PASSED;
    t->ver.peer_authenticated=1;t->ver.body_complete=1;t->ver.doh_replies=20;
    CHECK(doh_health_complete(s,t)==1 && t->state==T_WATCHING);
    t->state=T_DOH_HEALTH;t->res_ready=1;t->ver.budget=D2K_BUDGET_CUT;
    capture_spawn=1;
    CHECK(doh_health_complete(s,t)==1 && t->state==T_ASKING && t->job==JOB_CLASSIFY);
    capture_spawn=0;t->th_live=0;t->worker_owner=NULL;s->n_doh=0;task_reset(s,t);
    strcpy(s->doh[0].host,"startup-dns.example");
    strcpy(s->doh[0].ip,"192.0.2.55");strcpy(s->doh[0].path,"/dns-query");
    s->doh[0].port=443;s->doh[0].next_ms=0;s->n_doh=1;
    int saved_sync_active=s->sync_active,saved_sync_pending=s->sync_pending;
    s->sync_active=0;s->sync_pending=1;capture_spawn=1;
    doh_health_tick(s);
    CHECK(!task_of(s,"startup-dns.example",6,4));
    s->sync_pending=0;
    doh_health_tick(s);
    task *startup=task_of(s,"startup-dns.example",6,4);
    CHECK(startup && startup->state==T_DOH_HEALTH && startup->job==JOB_DOH_HEALTH);
    CHECK(startup && !strcmp(startup->ip,"192.0.2.55") && !strcmp(startup->doh_path,"/dns-query"));
    capture_spawn=0;
    if(startup){startup->th_live=0;startup->worker_owner=NULL;task_reset(s,startup);}
    s->sync_active=saved_sync_active;s->sync_pending=saved_sync_pending;s->n_doh=0;
    t=fixture(s);strcpy(t->doh_path,"/dns-query");t->vol.rx_cut=1;
    t->n_plans=2;t->next_plan=1;t->ver.level=D2K_VER_APPLICATION;
    t->ver.budget=D2K_BUDGET_CUT;t->ver.budget_packets=24;t->ver.budget_need=50;
    snprintf(t->plans[0],sizeof t->plans[0],"proto tcp tls\nsplit payload_start +1\norder forward\n");
    budget_cut_reject(s,t,900);
    CHECK(t->state==T_PLANNING && !t->partial_valid && t->next_plan==1);
    CHECK(!partial_finish(s,t,900));task_reset(s,t);

}
static void protocol_response_reaches_application(d2k_sched *s) {
    d2k_sched_tcp_fn old=d2k_sched_tcp_hook;
    d2k_sched_tcp_hook=doh_classify;doh_protocol_response=1;
    for(int mode=0;mode<7;mode++) {
        task *t=fixture(s);t->state=T_ASKING;t->job=JOB_CLASSIFY;
        if(mode!=4)strcpy(t->doh_path,"/dns-query");
        t->doh_checked=1;t->doh_trial=mode!=4;t->skip_volume_once=1;t->stop=mode==6;
        doh_mode=mode==5?0:mode;doh_force_local=mode==5;
        doh_calls=doh_classify_calls=0;doh_last_mark=0;
        worker_arg *a=calloc(1,sizeof *a);a->s=s;a->t=t;a->use_fd=-1;
        worker_run(a);free(a);
        CHECK(t->res_ready && t->res.protocol_response==(mode!=3) && doh_classify_calls==1);
        CHECK(doh_calls==(mode==3?2:mode<4 || mode==5?1:0));
        CHECK(t->vol.rx_cut==(mode==3));
        if(mode==3)CHECK(t->vol.rx_wire_basis && t->vol.rx_cut_packets==24);
        if(doh_calls)CHECK(doh_last_mark==s->measure_mark);
        CHECK(t->res.verdict==(mode==0?D2K_V_CLEAR:D2K_V_INCONCLUSIVE));
        CHECK(t->vol.rx_direct_complete==(mode==0));
        CHECK(!t->res.program_len && !t->res.have_arm);
        task_reset(s,t);
    }
    for(int second=0;second<6;second++) {
        task *t=fixture(s);t->state=T_ASKING;t->job=JOB_CLASSIFY;
        strcpy(t->doh_path,"/dns-query");
        t->doh_checked=1;t->doh_trial=1;t->skip_volume_once=1;
        doh_mode=3;doh_second_mode=second;doh_force_local=0;
        doh_calls=doh_classify_calls=0;
        worker_arg *a=calloc(1,sizeof *a);a->s=s;a->t=t;a->use_fd=-1;
        worker_run(a);free(a);
        CHECK(doh_calls==2 && doh_classify_calls==1 && t->res_ready);
        CHECK(t->vol.rx_cut==(second==3));
        CHECK(t->res.verdict==(second==0?D2K_V_CLEAR:D2K_V_INCONCLUSIVE));
        CHECK(t->vol.rx_direct_complete==(second==0));
        CHECK(!t->res.program_len && !t->res.have_arm);
        task_reset(s,t);
    }
    doh_second_mode=-1;
    doh_protocol_response=doh_force_local=0;d2k_sched_tcp_hook=old;
}
static int direct_http_calls,direct_http_mode,direct_http_tls12;
static uint32_t direct_http_mark;
static d2k_ver_result direct_http_probe(int fd,const char *ip,uint16_t port,const char *name,
    int wait,size_t wire,int tls12,int encoding,uint32_t mark,const char *path) {
    (void)ip;(void)port;(void)name;(void)wait;(void)wire;
    CHECK(fd==-1 && !encoding && !strcmp(path,"/observed-resource"));
    direct_http_calls++;direct_http_tls12=tls12;direct_http_mark=mark;
    d2k_ver_result r={0};r.fd=-1;r.level=D2K_VER_APPLICATION;r.status=200;r.body_complete=1;
    if(direct_http_mode==1)r.body_complete=0;
    if(direct_http_mode==2)r.local_refusal=1;
    if(direct_http_mode==3)r.level=D2K_VER_CHALLENGE;
    if(direct_http_mode==4)r.budget=D2K_BUDGET_CUT;
    if(direct_http_mode==9)r.budget=D2K_BUDGET_PASSED;
    if(direct_http_mode==10)r.status=404;
    return r;
}
static void protocol_response_http_context(d2k_sched *s) {
    d2k_sched_path_ver_fn old=d2k_sched_path_ver_hook;d2k_sched_path_ver_hook=direct_http_probe;
    for(int legacy=0;legacy<2;legacy++)for(int mode=0;mode<12;mode++) {
        task *t=fixture(s);strcpy(t->measure_path,"/observed-resource");
        uint8_t hello[4096];size_t n=0;
        CHECK(d2k_hello_from_profile(legacy?D2K_SHAPE_LEGACY:D2K_SHAPE_MODERN,t->name,hello,sizeof hello,&n)==0);
        d2k_hello trigger={hello,n,NULL,0,0,0};
        if(mode==5)t->measure_path[0]=0;
        if(mode==6)t->by_addr=1;
        if(mode==7)t->ech_offer=1;
        if(mode==8 || mode==9)t->trigger_code=5;
        if(mode==11)trigger.len=0;
        direct_http_mode=mode;direct_http_calls=0;direct_http_mark=0;
        d2k_vres result={0};result.protocol_response=1;result.verdict=D2K_V_INCONCLUSIVE;
        worker_protocol_response(s,t,trigger,&result);
        int asked=mode!=5 && mode!=6 && mode!=7 && mode!=11;
        CHECK(direct_http_calls==asked);
        if(asked)CHECK(direct_http_tls12==legacy && direct_http_mark==s->measure_mark);
        int success=mode==0 || mode==9;
        CHECK(result.verdict==(success?D2K_V_CLEAR:D2K_V_INCONCLUSIVE));
        CHECK(t->vol.rx_direct_complete==success);
        CHECK(!result.program_len && !result.have_arm);task_reset(s,t);
    }
    d2k_sched_path_ver_hook=old;
}

static void exact_program_candidate(d2k_sched *s)
{
    task *t=fixture(s);
    d2k_vres *r=calloc(1,sizeof *r);CHECK(r!=NULL);if(!r)return;
    r->verdict=D2K_V_INCONCLUSIVE;r->owns_search=1;
    snprintf(r->program,sizeof r->program,
        "d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +13\nsplit payload_start +37\norder forward\n");
    r->program_len=strlen(r->program);
    verdict_to_plans(s,t,r);
    CHECK(t->n_plans==1 && !strcmp(t->plans[0],r->program));
    CHECK(t->next_plan==0 && t->n_known==0);
    strcpy(s->force_suffixes[0],"summary.example");s->n_force=1;
    tried_add(t,(uint32_t)fnv1a(r->program));
    verdict_to_plans(s,t,r);CHECK(t->n_plans==0);
    s->n_force=0;
    r->verdict=D2K_V_CLEAR;verdict_to_plans(s,t,r);CHECK(t->n_plans==0);
    r->verdict=D2K_V_OPAQUE;r->program_len--;
    verdict_to_plans(s,t,r);CHECK(t->n_plans==0);
    r->program_len++;
    uint8_t transport=t->transport;t->transport=17;
    verdict_to_plans(s,t,r);CHECK(t->n_plans==0);t->transport=transport;
    r->program[10]=0;
    verdict_to_plans(s,t,r);CHECK(t->n_plans==0);
    strcpy(r->program,"invalid program");r->program_len=strlen(r->program);
    verdict_to_plans(s,t,r);CHECK(t->n_plans==0);
    r->program_len=sizeof r->program;
    verdict_to_plans(s,t,r);CHECK(t->n_plans==0);
    free(r);task_reset(s,t);
}


static int synthesis_feedback_calls;
static void synthesis_feedback_observe(void *ctx,const d2k_synthesis_feedback *e) {
    int *applied=ctx;
    CHECK(e->generation==77 && e->search_id!=0);
    CHECK(!strcmp(e->target,"summary.example") && !strcmp(e->ip,"127.0.0.1"));
    CHECK(e->port==443 && e->transport==6 && e->family==4 && !e->by_addr);
    CHECK(!strcmp(e->program,"exact candidate"));
    if(e->trial_id[0]==10) {
        CHECK(!e->verification_available && !e->applied && !e->flow.transport);
        synthesis_feedback_calls++;return;
    }
    CHECK(e->trial_id[0]==9 && e->flow.transport==6);
    CHECK(e->verification_available && e->level==D2K_VER_APPLICATION);
    CHECK(e->status==200 && e->body_complete && e->applied==*applied);
    synthesis_feedback_calls++;
}
static void synthesis_retirement_feedback(d2k_sched *s) {
    int applied=0;
    d2k_sched_synthesis_observer(s,synthesis_feedback_observe,&applied);
    for(applied=0;applied<2;applied++) {
        task *t=fixture(s);
        d2k_vres r={.verdict=D2K_V_INCONCLUSIVE,.synthesis_generation=77};
        snprintf(r.program,sizeof r.program,"d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +1\norder forward\n");
        r.program_len=strlen(r.program);
        verdict_to_plans(s,t,&r);
        CHECK(t->synthesis_generation==77 && t->n_plans==1);
        t->next_plan=1;
        strcpy(t->plans[0],"exact candidate");
        t->trial_installed=1;t->trial_ack_id[0]=9;
        t->synthesis_ver_trial_id[0]=9;
        t->ver_flow.transport=6;t->ver.local_port=1234;
        t->ver.level=D2K_VER_APPLICATION;t->ver.status=200;t->ver.body_complete=1;
        t->ver_ok=applied;
        candidate_retire(s,t);candidate_retire(s,t);
        CHECK(synthesis_feedback_calls==applied+1);
        task_reset(s,t);
    }
    task *stale=fixture(s);
    stale->synthesis_generation=77;stale->next_plan=stale->n_plans=1;
    strcpy(stale->plans[0],"exact candidate");
    stale->trial_installed=1;stale->trial_ack_id[0]=10;
    stale->synthesis_ver_trial_id[0]=9;
    stale->ver.local_port=1234;stale->ver.level=D2K_VER_APPLICATION;
    stale->ver.status=200;stale->ver.body_complete=1;stale->ver_ok=1;
    stale->ver_flow.transport=6;
    candidate_retire(s,stale);
    CHECK(synthesis_feedback_calls==3);
    stale->synthesis_generation=0;stale->trial_installed=1;
    candidate_retire(s,stale);
    CHECK(synthesis_feedback_calls==3);
    task_reset(s,stale);
    d2k_sched_synthesis_observer(s,NULL,NULL);
}
static int retained_feedback_calls;
static int retained_feedback(void *ctx,const d2k_synthesis_feedback *e,d2k_verification_status outcome) {
    (void)ctx;CHECK(e->generation==7);CHECK(outcome==D2K_VF_UNKNOWN);retained_feedback_calls++;return 0;
}
static void retained_release(void *ctx) {(*(int *)ctx)++;}
static void synthesis_continuation_lifetime(d2k_sched *s)
{
    int released=0;
    CHECK(!d2k_sched_synthesis_retain(7,&released,retained_release,NULL));
    task *t=fixture(s);
    progress_sink saved=g_progress_sink;g_progress_sink=(progress_sink){s,t};
    CHECK(d2k_sched_synthesis_retain(7,&released,retained_release,retained_feedback)==1);
    CHECK(!d2k_sched_synthesis_retain(8,&released,retained_release,NULL));
    g_progress_sink=saved;
    CHECK(!released);
    uint64_t generation=0;
    g_progress_sink=(progress_sink){s,t};
    CHECK(d2k_sched_synthesis_take(NULL,&generation)==NULL);
    CHECK(d2k_sched_synthesis_take(retained_release,&generation)==&released && generation==7);
    CHECK(!released);
    CHECK(d2k_sched_synthesis_retain(7,&released,retained_release,retained_feedback)==1);
    g_progress_sink=saved;
    t->synthesis_generation=7;
t->n_plans=t->next_plan=1;
    strcpy(t->plans[0],"pending candidate");t->trial_installed=1;
    candidate_retire(s,t);candidate_retire(s,t);
    CHECK(retained_feedback_calls==1);
    t->synthesis_generation=8;t->trial_installed=1;candidate_retire(s,t);
    CHECK(retained_feedback_calls==1);
    task_reset(s,t);CHECK(released==1);
    task_reset(s,t);CHECK(released==1);
    d2k_catalog other_catalog={0};
    d2k_sched *other=d2k_sched_new(&other_catalog,-1,0x2d);CHECK(other!=NULL);
    if(other) {
        g_progress_sink=(progress_sink){other,test_task_at(other, 0)};
        CHECK(d2k_sched_synthesis_retain(9,&released,retained_release,NULL)==1);
        g_progress_sink=saved;
        d2k_sched_free(other);CHECK(released==2);
    }
}
static void synthesis_resume_launch(d2k_sched *s)
{
    int released=0;task *t=fixture(s);t->state=T_PLANNING;
    progress_sink saved=g_progress_sink;g_progress_sink=(progress_sink){s,t};
    strcpy(t->measure_path,"/resource");
    CHECK(d2k_sched_synthesis_retain(17,&released,retained_release,NULL)==1);
    g_progress_sink=saved;
    CHECK(!synthesis_resume(s,t));
    t->synthesis_resume_pending=1;t->n_plans=t->next_plan=1;
    capture_spawn=1;
    CHECK(synthesis_resume(s,t)==1);
    CHECK(t->state==T_ASKING && t->job==JOB_CLASSIFY && t->th_live);
    CHECK(t->skip_volume_once && !t->synthesis_resume_pending && !t->n_plans);
    CHECK(t->synthesis_context==&released && !released);
    t->th_live=0;capture_spawn=0;
    strcpy(t->measure_path,"/other");g_progress_sink=(progress_sink){s,t};
    uint64_t generation=0;
    CHECK(d2k_sched_synthesis_take(retained_release,&generation)==NULL);
    CHECK(released==1 && !t->synthesis_context);
    g_progress_sink=saved;task_reset(s,t);CHECK(released==1);
}
static int resume_feedback_calls;
static int request_resume_after_failure(void *ctx,const d2k_synthesis_feedback *e,d2k_verification_status result)
{
    (void)ctx;CHECK(e->generation==92 && e->status==403);
    CHECK(result==D2K_VF_APP_NOT_MET);resume_feedback_calls++;return 0;
}
static void synthesis_owned_results(d2k_sched *s) {
    for(int mode=0;mode<17;mode++) {
        task *t=fixture(s);
        strcpy(t->measure_path,"/measured-resource");
        if(mode>=7 && mode<15)strcpy(t->doh_path,"/dns-query");
        if(mode>=15)t->measure_path[0]=0;
        d2k_vres r={.verdict=D2K_V_INCONCLUSIVE,.synthesis_generation=92};
        snprintf(r.program,sizeof r.program,"d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +1\norder forward\n");
        r.program_len=strlen(r.program);
        verdict_to_plans(s,t,&r);
        CHECK(t->synthesis_owner!=NULL);
        int released=0;
        if(mode==5) {
            progress_sink saved=g_progress_sink;g_progress_sink=(progress_sink){s,t};
            CHECK(d2k_sched_synthesis_retain(92,&released,retained_release,request_resume_after_failure)==1);
            g_progress_sink=saved;
        }
        t->next_plan=1;t->trial_installed=1;t->trial_shape=probe_shape(t);
        t->trial_ack_id[0]=1;t->synthesis_ver_trial_id[0]=1;t->ver_plan_id[0]=2;
        t->ver.local_port=1234;t->ver_flow.a_port=1234;t->ver_flow.b_port=443;
        t->ver_flow.family=4;t->ver_flow.transport=6;
        inet_pton(AF_INET,"127.0.0.1",t->ver_flow.b_ip);
        t->ver.level=D2K_VER_APPLICATION;t->ver.status=200;t->ver.body_complete=1;
        t->ver_ok=1;
        if(mode>=8) {
            t->ver.budget=D2K_BUDGET_PASSED;t->ver.budget_need=50;
            t->ver.budget_packets=52;t->ver.budget_requests=11;
        }
        if(mode>=9 && mode<15) {
            t->ver.budget=D2K_BUDGET_CUT;t->ver.body_complete=0;t->ver.budget_packets=24;
            if(mode==9)t->ver.budget_need=0;
            if(mode==10)t->ver.budget_packets=0;
            if(mode==11)t->ver.budget_requests=0;
            if(mode==12)t->ver.status=0;
            if(mode==13)t->ver.status=503;
        }
        if(mode==1)t->synthesis_ver_trial_id[0]=2;
        if(mode==2)t->ver_ok=0;
        if(mode==3)t->ver.body_complete=0;
        if(mode==4)strcpy(t->measure_path,"/other-resource");
        if(mode==5)t->ver.status=403;
        if(mode==6)t->synthesis_generation=93;
        if(mode==16)t->ver.status=302;
        d2k_verification_status expected=mode==14?D2K_VF_NOT_MET:(mode==0 || mode==8 || mode==15)?D2K_VF_OBSERVED:
            (mode==4 || mode==6)?D2K_VF_FOREIGN:(mode==5 || mode==16)?D2K_VF_APP_NOT_MET:D2K_VF_UNKNOWN;
        if(mode==14){strcpy(s->force_suffixes[0],"summary.example");s->n_force=1;}
        CHECK(synthesis_report(s,t,0)==expected);
        if(mode==14){CHECK(t->n_tried==1 && t->tried[0]==(uint32_t)fnv1a(t->plans[0]));s->n_force=0;}
        if(mode==0)CHECK(synthesis_report(s,t,0)==D2K_VF_OBSERVED);
        candidate_retire(s,t);
        CHECK(t->synthesis_result==expected);
        if(mode==5)CHECK(t->synthesis_resume_pending==0 && resume_feedback_calls==1);
        /* A new verdict must discard evidence even for identical plan text. */
        r.synthesis_generation=94;
        verdict_to_plans(s,t,&r);
        CHECK(t->synthesis_result==D2K_VF_UNKNOWN);
        task_reset(s,t);
        CHECK(t->synthesis_owner==NULL);
        CHECK(released==(mode==5));
    }
}
static void synthesis_missing_owner_cannot_confirm(d2k_sched *s) {
    task *t=fixture(s);
    t->synthesis_generation=91;t->next_plan=t->n_plans=1;
    strcpy(t->plans[0],"d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsplit payload_start +1\norder forward\n");
    t->ver.level=D2K_VER_APPLICATION;t->ver.status=200;
    t->ver.body_complete=1;t->ver_ok=1;
    verify_confirm(s,t,1000);
    CHECK(t->state==T_PLANNING);
    CHECK(!t->bound_plan_id[0]);
    task_reset(s,t);
}
/* A known failed catalog plan must not return just because another plan
   appeared. Also cover a fresh plan beyond the first catalog batch. */
static void retry_remembers_failed_plans(int failed_count, int spawn_failure) {
    d2k_catalog cat;
    d2k_cat_box box;
    memset(&cat, 0, sizeof cat);
    memset(&box, 0, sizeof box);
    d2k_cat_plan plans[9];
    d2k_cat_binding binds[9];
    memset(plans, 0, sizeof plans);
    memset(binds, 0, sizeof binds);
    char texts[9][80];
    size_t n = (size_t)failed_count + 1;
    cat.boxes = &box; cat.n_boxes = 1;
    box.plans = plans; box.n_plans = n; box.binds = binds; box.n_binds = n;
    strcpy(box.id, "box-retry");
    for (size_t i = 0; i < n; i++) {
        snprintf(texts[i], sizeof texts[i], "d2k-plan 1 %zu\nproto tcp tls\n", i + 1);
        snprintf(plans[i].id, sizeof plans[i].id, "plan-%zu", i);
        strcpy(plans[i].proto, "tls"); plans[i].enabled = 1; plans[i].text = texts[i];
        strcpy(binds[i].plan_id, plans[i].id); strcpy(binds[i].kind, "name");
        snprintf(binds[i].target, sizeof binds[i].target, "donor%zu.example", i);
        binds[i].enabled = 1; binds[i].level = 3;
        binds[i].transport = 6; binds[i].family = 4; binds[i].shape = SCHED_PROBE_SHAPE;
        binds[i].confirmed = 100 - (int64_t)i;
    }
    d2k_sched *s = d2k_sched_new(&cat, -1, 0x2d);
    CHECK(s != NULL);
    if (!s) return;
    s->now_ms = 1000;
    target_cooldown *c = &s->cooldowns[0];
    c->used = c->exhausted = 1; c->transport = 6; c->family = 4;
    c->port = 443; c->until_ms = 600000;
    strcpy(c->name, "retry.example"); strcpy(c->ip, "192.0.2.1");
    for (int i = 0; i < failed_count; i++) c->failed_plans[c->n_failed_plans++] = fnv1a(texts[i]);
    d2k_sched_tcp_fn saved = d2k_sched_tcp_base_hook;
    d2k_sched_tcp_base_hook = d2k_sched_tcp_hook;
    capture_spawn = 1; /* capture launch only; no network or real worker */
    int started = plan_news_recheck(s, c, 1000);
    capture_spawn = 0;
    CHECK(started == 1);
    task *t = task_of(s, c->name, 6, 4);
    if (t) {
        t->th_live = 0; /* captured pthread_create did not create a thread */
        size_t offered = own_first_plans(s, t, 1);
        CHECK(offered == 1);
        CHECK(!strcmp(t->plans[0], texts[failed_count]));
        if (spawn_failure) {
            t->own_first = 2; t->n_plans = t->n_known = t->next_plan = 1;
            t->state = T_TRIAL_SETTLE; t->trial_acked = 1;
            /* summary_thread_create returns EAGAIN: no verifier exists. */
            d2k_sched_tick(s, 1010);
            CHECK(t->state == T_PLANNING);
            d2k_sched_tick(s, 1020);
            CHECK(c->n_failed_plans == 0);
            CHECK(c->until_ms == 600000);
            /* The unmeasured plan must still be eligible next time. */
            capture_spawn = 1;
            CHECK(plan_news_recheck(s, c, 1030) == 1);
            capture_spawn = 0;
            t = task_of(s, c->name, 6, 4);
            if (t) t->th_live = 0;
        }
    }
    d2k_sched_tcp_base_hook = saved;
    d2k_sched_free(s); /* catalog entries are stack-owned */
}

static int retry_offer(const char *name, size_t payload, uint8_t *out,
                                 size_t cap, size_t *len) {
    size_t n = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, name, out, cap, &n) != 0) return -1;
    size_t p = 9 + 2 + 32;
    p += 1 + out[p];
    p += 2 + ((size_t)out[p] << 8 | out[p + 1]);
    p += 1 + out[p];
    size_t ext_len_off = p;
    const size_t enc = 32, elen = 10 + enc + payload;
    if (n + 4 + elen > cap) return -1;
    uint8_t *e = out + n;
    e[0] = 0xfe; e[1] = 0x0d; e[2] = (uint8_t)(elen >> 8); e[3] = (uint8_t)elen;
    e[4] = 0; e[5] = 0; e[6] = 1; e[7] = 0; e[8] = 1; e[9] = 0x5a;
    e[10] = 0; e[11] = (uint8_t)enc;
    for (size_t i = 0; i < enc; i++) e[12 + i] = (uint8_t)(i * 7 + 3);
    e[12 + enc] = (uint8_t)(payload >> 8); e[13 + enc] = (uint8_t)payload;
    for (size_t i = 0; i < payload; i++) e[14 + enc + i] = (uint8_t)(i * 13 + 1);
    n += 4 + elen;
    size_t ext = ((size_t)out[ext_len_off] << 8 | out[ext_len_off + 1]) + 4 + elen;
    out[ext_len_off] = (uint8_t)(ext >> 8); out[ext_len_off + 1] = (uint8_t)ext;
    size_t hs = n - 9, rec = n - 5;
    out[6] = (uint8_t)(hs >> 16); out[7] = (uint8_t)(hs >> 8); out[8] = (uint8_t)hs;
    out[3] = (uint8_t)(rec >> 8); out[4] = (uint8_t)rec;
    *len = n;
    return 0;
}

/* Field 08.11: recheck must retain the form and resolved GREASE context. */
static void retry_keeps_client_context(int completed_retry) {
    for (int legacy=0;legacy<2;legacy++) {
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);
        task *t=fixture(s);t->trigger_shape=legacy?D2K_SHAPE_LEGACY:D2K_LINK_SHAPE_ECH_TCP;
        t->ech_grease=!legacy;t->trigger_code=D2K_SUSPECT_RST;
        if(!legacy) {
            CHECK(!retry_offer(t->name,144,t->trig,sizeof t->trig,&t->trig_len));
            t->trig_snapped=1;
            strcpy(s->ech_inputs[0].name,t->name);s->ech_inputs[0].family=4;
            s->ech_inputs[0].observed_ms=s->now_ms;
            memcpy(s->ech_inputs[0].bytes,t->trig,t->trig_len);
            s->ech_inputs[0].len=t->trig_len;
        }
        d2k_cat_box *b=box_ensure(&cat,"retry-box");
        const char *text="d2k-plan 1 5\nproto tcp tls\nsplit payload_start +1\norder forward\n";
        CHECK(bind_confirmed(&cat,b->id,"retry-plan",text,"tls","donor.example","name",6,4,
            legacy?D2K_SHAPE_LEGACY:D2K_SHAPE_MODERN,0,D2K_VERBY_PROBE,0,1,NULL,NULL,NULL)==0);
        cooldown_record(s,t,2);target_cooldown *c=cooldown_find(s,t->name,6,4);
        t->state=T_RESTING;
        d2k_sched_tcp_fn saved=d2k_sched_tcp_base_hook;
        d2k_sched_tcp_base_hook=d2k_sched_tcp_hook;
        capture_spawn=1;
        if(completed_retry) {
            task *watch=test_task_at(s, 1);task_reset(s,watch);
            watch->state=T_WATCHING;watch->plan_retry=1;
            strcpy(watch->name,"already-confirmed.example");
            s->plan_news=1;s->plan_gen=1;
            plan_news_tick(s,1000);
            CHECK(test_task_at(s, 0)->state==T_ASKING);
        } else CHECK(plan_news_recheck(s,c,1000)==1);
        capture_spawn=0;
        t=task_of(s,"summary.example",6,4);
        CHECK(t && t->trigger_shape==(legacy?D2K_SHAPE_LEGACY:D2K_LINK_SHAPE_ECH_TCP));
        CHECK(t && t->ech_grease==!legacy);
        CHECK(t && t->own_first==1 && !t->ech_offer);
        CHECK(t && d2k_hello_shape(t->trig,t->trig_len)==(legacy?D2K_SHAPE_LEGACY:D2K_SHAPE_MODERN));
        if(t)t->th_live=0;
        d2k_sched_tcp_base_hook=saved;d2k_sched_free(s);d2k_catalog_free(&cat);
    }
}

static int rx_worker_calls, generic_worker_calls;
static d2k_ver_result rx_worker_probe(int fd,const char *ip,uint16_t port,
    uint8_t transport,const char *name,int deadline,size_t wire,uint8_t shape) {
    (void)fd;(void)ip;(void)port;(void)transport;(void)name;(void)deadline;(void)wire;(void)shape;
    rx_worker_calls++;return (d2k_ver_result){.fd=-1};
}
static d2k_ver_result generic_worker_probe(int fd,const char *ip,uint16_t port,
    uint8_t transport,const char *name,int deadline,size_t wire,uint8_t shape) {
    (void)fd;(void)ip;(void)port;(void)transport;(void)name;(void)deadline;(void)wire;(void)shape;
    generic_worker_calls++;return (d2k_ver_result){.fd=-1};
}
static void synthesis_worker_measures_identity(void) {
    d2k_sched_ver_fn rx=d2k_sched_rx_ver_hook,generic=d2k_sched_ver_hook;
    d2k_sched_rx_ver_hook=rx_worker_probe;d2k_sched_ver_hook=generic_worker_probe;
    for(int mode=0;mode<3;mode++) {
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);
        task *t=fixture(s);t->trigger_shape=mode==2?D2K_SHAPE_LEGACY:D2K_SHAPE_MODERN;
        CHECK(!fill_hellos(s,t));t->res.verdict=D2K_V_INCONCLUSIVE;
        t->res.program_len=mode!=1;t->job=JOB_VERIFY;
        worker_arg *a=calloc(1,sizeof *a);a->s=s;a->t=t;a->use_fd=-1;
        memcpy(a->trig,t->trig,t->trig_len);a->trig_len=t->trig_len;
        rx_worker_calls=generic_worker_calls=0;worker_run(a);free(a);
        CHECK(t->res_ready && rx_worker_calls==(mode==0) && generic_worker_calls==(mode!=0));
        d2k_sched_free(s);d2k_catalog_free(&cat);
    }
    d2k_sched_rx_ver_hook=rx;d2k_sched_ver_hook=generic;
}

/* A ServerHello synthesis candidate exposes the same residual RX question
   as an opaque-handshake candidate. One cut is not yet an RX fingerprint. */
static void synthesis_candidate_opens_rx_ladder(void) {
    for(int negative=0;negative<5;negative++) {
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);
        cat.net.searched=1;strcpy(cat.net.name,"white.example");
        if(negative==4) {cat.net.searched=0;cat.net.name[0]=0;}
        task *t=fixture(s);t->trigger_shape=D2K_SHAPE_MODERN;
        CHECK(fill_hellos(s,t)==0);
        d2k_vres r={.verdict=D2K_V_INCONCLUSIVE,.synthesis_generation=98,.owns_search=1};
        strcpy(r.program,"d2k-plan 1 5\nproto tcp tls\nsplit payload_start +1\norder forward\n");
        r.program_len=strlen(r.program);t->res=r;
        verdict_to_plans(s,t,&r);t->next_plan=1;
        if(negative==3) {
            t->own_first=2;t->plan_retry=1;t->vol.rx_tls_unavailable=1;
            t->res.program_len=0;t->res.verdict=D2K_V_OPAQUE;
        }
        for(int phase=0;phase<3;phase++) {
            t->ver=(d2k_ver_result){.fd=-1,.level=D2K_VER_APPLICATION,.status=200,
                .body_framing_valid=1,.body_has_length=1,.body_expected=30000,
                .body_bytes=20000,.data_packets=24};
            if(phase==2) {
                t->ver.body_encoding=1;t->ver.body_bytes=4000;
                t->ver.body_complete=negative!=1;t->ver.data_packets=0;
            }
            t->ver_seen=negative==2?0:1;
            t->ver_flow.family=4;t->ver_flow.transport=6;
            t->ver_flow.a_port=1234;t->ver_flow.b_port=443;
            t->ver_early[0]=(d2k_flowkey){.family=4,.transport=6,.a_port=1234,.b_port=443};
            if(!layered_rx_result(s,t,1000+phase*1000)) {
                CHECK(negative==2);break;
            }
            if(phase<2) {CHECK(!t->vol.rx_cut);CHECK(t->rx_phase==(unsigned)phase+1);t->next_plan=1;}
        }
        if(!negative || negative==3 || negative==4) {
            CHECK(!t->plan_retry && t->own_first!=2);
            CHECK(t->vol.rx_cut && t->vol.rx_at_kb==19);
            CHECK(t->n_plans>0 && strcmp(t->plans[0],r.program));
            CHECK(!t->synthesis_generation && !t->synthesis_owner);
            if(negative==4) {
                CHECK(t->rx_volume_candidate_pending);
                size_t before=t->net_probe_next;
                t->n_plans=t->next_plan=0;
                CHECK(refill_from_fallback(s,t)>0 && t->net_probe_next>before);
                CHECK(!t->fb_next);
            } else CHECK(t->rx_volume_next_variant>0);
        } else CHECK(!t->vol.rx_cut);
        d2k_sched_free(s);d2k_catalog_free(&cat);
    }
}

/* A failed continuation must leave the target discoverable by plan news.
   Catalog compatibility is tested by a new baseline/trial, across boxes. */
static void failed_synthesis_waits_for_new_own_plan(void) {
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);
    task *t=fixture(s);t->trigger_shape=D2K_SHAPE_MODERN;
    t->trigger_code=D2K_SUSPECT_RST;t->state=T_PLANNING;
    strcpy(t->box_id,"box-old-measurement");
    int context=0;t->synthesis_context=&context;t->synthesis_resume_pending=-1;
    CHECK(synthesis_resume(s,t)==1);
    target_cooldown *c=cooldown_find(s,"summary.example",6,4);
    CHECK(c && c->exhausted);
    d2k_cat_box *b=box_ensure(&cat,"box-new-measurement");
    const char *text="d2k-plan 1 5\nproto tcp tls\nsplit payload_start +1\norder forward\n";
    CHECK(!bind_confirmed(&cat,b->id,"new-plan",text,"tls","donor.example","name",6,4,
        D2K_SHAPE_MODERN,0,D2K_VERBY_PROBE,0,1,NULL,NULL,NULL));
    d2k_sched_tcp_fn saved=d2k_sched_tcp_base_hook;
    d2k_sched_tcp_base_hook=d2k_sched_tcp_hook;
    capture_spawn=1;s->plan_news=1;s->plan_gen=1;plan_news_tick(s,1000);capture_spawn=0;
    t=task_of(s,"summary.example",6,4);
    CHECK(t && t->state==T_ASKING && t->own_first==1);
    if(t)t->th_live=0;
    d2k_sched_tcp_base_hook=saved;d2k_sched_free(s);d2k_catalog_free(&cat);
}

static void installed_family_skips_plan_news(void) {
    d2k_catalog cat={0};
    d2k_group_state *groups=calloc(1,sizeof *groups);
    d2k_cat_box box={0};d2k_cat_plan plan={0};d2k_cat_binding bind={0};
    CHECK(groups!=NULL);
    if(!groups)return;
    cat.groups=groups;cat.boxes=&box;cat.n_boxes=1;
    box.plans=&plan;box.n_plans=1;box.binds=&bind;box.n_binds=1;
    strcpy(box.id,"family-box");
    strcpy(plan.id,"plan-family");strcpy(plan.proto,"tls");plan.enabled=1;
    plan.text="d2k-plan 1 5\nproto tcp tls\nsplit payload_start +1\norder forward\n";
    strcpy(bind.kind,"name");strcpy(bind.target,"a.example.com");
    strcpy(bind.plan_id,plan.id);bind.enabled=1;bind.level=3;
    bind.transport=6;bind.family=4;bind.shape=D2K_SHAPE_MODERN;
    for(int i=0;i<3;i++) {
        d2k_group_observation o={0};
        snprintf(o.name,sizeof o.name,"%c.example.com",'a'+i);
        strcpy(o.plan_id,plan.id);
        CHECK(!d2k_group_key_make(&o.key,6,4,D2K_SHAPE_MODERN,"/",""));
        o.evidence=D2K_GROUP_BLOCKED_CONFIRMED;o.at=1000+i;
        CHECK(d2k_group_learn(groups,&o)>0);
    }
    d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);
    CHECK(s!=NULL);
    if(s) {
        d2k_group_key key={0};d2k_domain_group group;
        CHECK(!d2k_group_key_make(&key,6,4,D2K_SHAPE_MODERN,"/",""));
        CHECK(d2k_group_match(groups,"new.example.com",&key,&group)!=NULL);
        CHECK(!area_reserve(s,1));
        int installed=0;
        for(size_t i=0;i<d2k_group_slots(groups);i++)
            if(desired_area(s,i,&s->areas[0])){installed=1;break;}
        CHECK(installed);
        if(installed) {
            s->areas[0].confirmed=1;s->areas[0].confirmed_event=1;
            s->n_areas=1;s->now_ms=1000;
            target_cooldown *c=&s->cooldowns[0];
            c->used=c->exhausted=1;c->transport=6;c->family=4;
            c->port=443;c->trigger_shape=D2K_SHAPE_MODERN;c->until_ms=61000;
            strcpy(c->name,"new.example.com");strcpy(c->ip,"192.0.2.1");
            task probe={0};
            strcpy(probe.name,c->name);probe.transport=6;probe.family=4;
            probe.trigger_shape=D2K_SHAPE_MODERN;
            CHECK(installed_family_ready(s,&probe,0,0));
            d2k_sched_tcp_fn saved=d2k_sched_tcp_base_hook;
            d2k_sched_tcp_base_hook=d2k_sched_tcp_hook;capture_spawn=1;
            CHECK(!plan_news_recheck(s,c,1000));
            capture_spawn=0;d2k_sched_tcp_base_hook=saved;
            task *t=task_of(s,c->name,6,4);
            if(t)t->th_live=0;
            CHECK(!d2k_sched_active(s));
        }
        d2k_sched_free(s);
    }
    free(groups);
}

static void ipv6_late_silence_checks_verified_ipv4(void) {
    for(int complete=0;complete<2;complete++) {
        d2k_catalog cat={0};
        d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);
        CHECK(s!=NULL);
        if(!s)continue;
        d2k_sched_family_path(s,"/tmp/d2k-family-summary-test");
        task *t=fixture(s);
        strcpy(t->name,"ru.numista.com");
        strcpy(t->ip,"2a06:98c1:3122:8000::");
        t->family=6;t->state=T_ASKING;t->res_ready=1;
        t->trigger_code=D2K_SUSPECT_LATE_SILENCE;
        t->res.verdict=D2K_V_CLEAR;
        t->vol.rx_direct_complete=complete;
        capture_spawn=1;
        d2k_sched_tick(s,1000);
        capture_spawn=0;
        if(!complete) {
            CHECK(t->state==T_FAMILY_PROBE && t->job==JOB_FAMILY_PROBE);
            CHECK(cooldown_find(s,t->name,6,6)==NULL);
        } else CHECK(t->state!=T_FAMILY_PROBE);
        t->th_live=0;
        d2k_sched_free(s);
    }
}

static void measurement_timeout_does_not_cooldown(void) {
    for(int typed=0;typed<2;typed++) {
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0x2d);
        task *t=fixture(s);t->state=T_ASKING;t->res_ready=1;
        t->res.verdict=typed?D2K_V_FLAKY:D2K_V_INCONCLUSIVE;
        t->res.dial_deadline=typed;
        d2k_sched_tick(s,1000);
        CHECK((cooldown_find(s,"summary.example",6,4)!=NULL)==!typed);
        CHECK(!cat.n_boxes && !t->n_plans);
        d2k_sched_free(s);d2k_catalog_free(&cat);
    }
}

int main(void) {
    synthesis_worker_measures_identity();
    synthesis_candidate_opens_rx_ladder();
    failed_synthesis_waits_for_new_own_plan();
    installed_family_skips_plan_news();
    ipv6_late_silence_checks_verified_ipv4();
    retry_keeps_client_context(0);
    retry_keeps_client_context(1);
    measurement_timeout_does_not_cooldown();
    retry_remembers_failed_plans(1, 0);
    retry_remembers_failed_plans(8, 0);
    retry_remembers_failed_plans(0, 1);
    d2k_catalog cat = {0};
    d2k_sched *s = d2k_sched_new(&cat, -1, 0x2d);
    d2k_sched_diagnostics(s,diag_observe,NULL);
    task diag_task={0};diag_task.report_id=999;
    search_report(s,&diag_task,10,"failed","none","кандидаты кончились, ни один не подтверждён зондом");
    search_report(s,&diag_task,11,"failed","none","кандидаты кончились, ни один не подтверждён зондом");
    CHECK(diag_calls==1); /* observation independent of human log; exactly once */
    d2k_sched_diagnostics(s,NULL,NULL);

    CHECK(s != NULL);
    if (!s) return 1;
    synthesis_continuation_lifetime(s);
    synthesis_resume_launch(s);
    synthesis_owned_results(s);
    synthesis_missing_owner_cannot_confirm(s);
    synthesis_retirement_feedback(s);
    d2k_sched_set_say(s, collect, NULL);
    exact_program_candidate(s);
    doh_service_gate(s);
    protocol_response_reaches_application(s);
    protocol_response_http_context(s);
    rx_short_reports_only_final_cumulative(s);
    {
        task *q = fixture(s);
        q->report_id = 42; q->family = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, q->name, q->trig,
              sizeof q->trig, &q->trig_len) == 0);
        d2k_vres result = {.verdict = D2K_V_OPAQUE, .have_arm = 1};
        result.arm.badsum = 1;
        result.arm_input.trigger_len = q->trig_len;
        strcpy(result.arm_name, "badsum"); strcpy(result.arm_path, "свойство");
        verdict_to_plans(s, q, &result);
        CHECK(q->n_plans > 0);
        CHECK(strstr(rows, "НАЙДЕН замером (путь: свойство) search=42 protocol=tcp family=6") != NULL);
        task_reset(s, q);
    }
    challenge_exclusions_survive_cache_eviction(s);
    tx_ladder_requires_volume_proof(0);
    tx_ladder_requires_volume_proof(1);
    ech_witness_challenge_is_transport_proof(s);
    ech_witness_body_cut_is_rx_cut(s);
    for (int mode = 0; mode < 3; mode++) ech_challenge_witness(s, mode);
    for (int mode = 0; mode < 2; mode++) verify_reselects_witness(s, mode);
    tx_cut_opens_white_ladder(s, 1);
    tx_cut_opens_white_ladder(s, 0);
    for(int ladder=0;ladder<2;ladder++) {
        task *q=fixture(s);q->transport=17;q->arm.original=1;q->arm_ready=1;
        q->arm.kind=ladder?D2K_QA_COPIES:D2K_QA_UDPLEN;
        q->arm.strategy=ladder?D2K_QS_LADDER:D2K_QS_LENGTH;
        if(ladder){q->arm.bytes[0]=0x40;q->arm.len=1;q->arm.copies=1;}
        else q->arm.udplen=D2K_QUIC_LENGTH_INCREMENT;
        d2k_vres result={.verdict=D2K_V_OPAQUE};
        verdict_to_plans(s,q,&result);CHECK(q->n_plans==1);
        q->next_plan=1;
        CHECK(!strcmp(candidate_path(q),ladder?"перебор":"свойство"));
        search_report(s,q,900,"probe-confirmed",NULL,
                      "кандидат подтверждён собственным зондом на проводе");
        CHECK(strstr(rows,ladder?"path=fallback":"path=property"));
    }
    task *t = fixture(s);
    /* Real launch → pthread_create failure → reset used to lose the report. */
    CHECK(launch_task(s, t) == 0);
    CHECK(strstr(rows, "итог поиска:") != NULL);
    CHECK(strstr(rows, "elapsed_ms=800 queue_ms=150") != NULL);
    /* Строка журнала несёт причину итога и идентичность решения: без них
       «own-plan подтверждён» по одиннадцати именам не сверить с каталогом. */
    CHECK(strstr(rows, "why=") != NULL);
    CHECK(strstr(rows, "box=") != NULL && strstr(rows, "plan=") != NULL);

    t = fixture(s);
    task_done(s, t); /* cancellation while requeued, without launch */
    CHECK(strstr(rows, "elapsed_ms=800 queue_ms=150") != NULL);

    t = fixture(s);
    t->state = T_VOICE_MEASURE; t->transport = 17;
    t->voice_res.verdict = D2K_VOICE_CLEAR;
    voice_finish_measure(s, t, s->now_ms);
    CHECK(strstr(rows, "outcome=probe-direct path=direct") != NULL);
    CHECK(strstr(rows, "outcome=failed") == NULL);

    t = fixture(s);
    t->state = T_VOICE_MEASURE; t->transport = 17;
    t->voice_res.verdict = D2K_VOICE_CLEAR;
    t->voice_known_prefix_valid = 1;
    voice_finish_measure(s, t, s->now_ms);
    CHECK(strstr(rows, "outcome=probe-clear path=unknown") != NULL);
    CHECK(strstr(rows, "path=own-plan") == NULL);

    t = fixture(s);
    t->state = T_ASKING; t->rx_volume_only = 1; t->res_ready = 1;
    t->res.verdict = D2K_V_CLEAR; t->vol.rx_cut = 0;
    s->sync_pending = 0;
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=inconclusive path=none") != NULL);
    CHECK(strstr(rows, "outcome=failed") == NULL);

    /* Поле 17.10.2026, LR-rx8-1, rua.gr: позднее закрытие, исходящая лестница
       оборвалась (~19 КБ), RX-проба ничего не измерила (ответ встал на 4,5 КБ).
       Доказанный обрыв лестницы пустым RX не отменяется: поиск продолжается,
       а не уходит в «не подтвердилось» и покой на 10 минут. */
    t = fixture(s);
    t->state = T_ASKING; t->rx_volume_only = 1; t->res_ready = 1;
    t->res.verdict = D2K_V_INCONCLUSIVE;
    t->vol.verdict = D2K_VOL_CUT; t->vol.at_kb = 19; t->vol.rx_cut = 0;
    s->sync_pending = 0;
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "позднее закрытие не подтвердилось") == NULL);
    CHECK(strstr(rows, "исходящая лестница оборвалась около 19 КБ") != NULL);
    CHECK(strstr(rows, "пакетный бюджет потока: identity") == NULL);
    if (fails) fprintf(stderr, "%s\n", rows);
    task_reset(s, t);

    /* Поле 19.10.2026, mailsuite.com: подозрение позднего обрыва,
       базовый вопрос рукопожатия CLEAR, а RX-проба не измерена (rx_unmeasured).
       Неизмеренный объём не должен становиться probe-direct. */
    t = fixture(s);
    t->state = T_ASKING; t->transport = 6; t->trigger_code = D2K_SUSPECT_RST_AFTER_APP;
    t->res_ready = 1; t->res.verdict = D2K_V_CLEAR;
    t->vol.rx_unmeasured = 1; t->vol.rx_cut = 0; t->vol.verdict = D2K_VOL_UNREACHABLE;
    s->sync_pending = 0;
    rows[0] = '\0';
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=inconclusive path=none") != NULL);
    CHECK(strstr(rows, "outcome=probe-direct") == NULL);
    CHECK(strstr(rows, "объём ответа измерить не удалось; прямой замер не подтверждён") != NULL);
    task_reset(s, t);

    /* Доказанный TX-обрыв (D2K_VOL_CUT) имеет строгий приоритет над rx_unmeasured */
    t = fixture(s);
    t->state = T_ASKING; t->transport = 6; t->trigger_code = D2K_SUSPECT_RST_AFTER_APP;
    t->res_ready = 1; t->res.verdict = D2K_V_CLEAR;
    t->vol.rx_unmeasured = 1; t->vol.verdict = D2K_VOL_CUT; t->vol.at_kb = 16;
    s->sync_pending = 0;
    rows[0] = '\0';
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=inconclusive") == NULL);
    CHECK(strstr(rows, "объём ответа измерить не удалось") == NULL);
    task_reset(s, t);

    /* Полный не-2xx ответ выше полосы (напр. 403 на 20 КБ) при позднем обрыве:
       рукопожатие CLEAR, TX PASSED, rx_direct_complete = 0.
       Не должен давать probe-direct и не должен стирать привязку. */
    t = fixture(s);
    t->state = T_ASKING; t->transport = 6; t->trigger_code = D2K_SUSPECT_RST_AFTER_APP;
    t->res_ready = 1; t->res.verdict = D2K_V_CLEAR;
    t->vol.verdict = D2K_VOL_PASSED;
    t->vol.rx_cut = 0; t->vol.rx_short = 0; t->vol.rx_unmeasured = 0; t->vol.rx_direct_complete = 0;
    s->sync_pending = 0;
    rows[0] = '\0';
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=inconclusive path=none") != NULL);
    CHECK(strstr(rows, "outcome=probe-direct") == NULL);
    CHECK(strstr(rows, "прямой ответ не подтвердил прикладной успех; прямой замер не подтверждён") != NULL);
    task_reset(s, t);

    /* Полный 2xx ответ (rx_direct_complete = 1) при позднем обрыве:
       рукопожатие CLEAR, TX PASSED -> probe-direct. */
    t = fixture(s);
    t->state = T_ASKING; t->transport = 6; t->trigger_code = D2K_SUSPECT_RST_AFTER_APP;
    t->res_ready = 1; t->res.verdict = D2K_V_CLEAR;
    t->vol.verdict = D2K_VOL_PASSED;
    t->vol.rx_direct_complete = 1;
    s->sync_pending = 0;
    rows[0] = '\0';
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=probe-direct path=direct") != NULL);
    task_reset(s, t);

    /* Машинный флаг dial_deadline (истёк срок подключения, d2k_dial_deadline_err):
       FLAKY + dial_deadline=1 даёт исход outcome=unknown path=none ("замер не состоялся").
       FLAKY + dial_deadline=0 даёт исход outcome=inconclusive path=none даже с тем же текстом reason. */
    t = fixture(s);
    t->state = T_ASKING; t->transport = 6;
    t->res_ready = 1; t->res.verdict = D2K_V_FLAKY; t->res.dial_deadline = 1;
    snprintf(t->res.reason, sizeof t->res.reason, "наш срок на подключение 6000 мс истёк — замер не состоялся");
    s->sync_pending = 0;
    rows[0] = '\0';
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=unknown path=none") != NULL);
    CHECK(strstr(rows, "замер не состоялся: адрес не принимал соединений") != NULL);
    task_reset(s, t);

    /* Тот же текст без машинного флага не имитирует этот исход: машинный признак, а не строка. */
    t = fixture(s);
    t->state = T_ASKING; t->transport = 6;
    t->res_ready = 1; t->res.verdict = D2K_V_FLAKY; t->res.dial_deadline = 0;
    snprintf(t->res.reason, sizeof t->res.reason, "наш срок на подключение 6000 мс истёк — замер не состоялся");
    s->sync_pending = 0;
    rows[0] = '\0';
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=inconclusive path=none") != NULL);
    CHECK(strstr(rows, "outcome=unknown") == NULL);
    CHECK(strstr(rows, "замер не состоялся: адрес не принимал соединений") == NULL);
    task_reset(s, t);

    /* ЗАДАЧА 26, П.3: ДОКАЗАННЫЙ ПУТЬ ПЕРЕЖИВАЕТ ЭПИЗОД. Поле 12.10.2026,
       style.sndcdn.com: обрыв доказывает повтор зонда по /css/soehne-*.css, а
       следующий эпизод снова просил «/» и получал завершённый 403 на 243
       байта — измерения не было, цель уходила в покой. Сохранённый
       ДОКАЗАННЫЙ путь обязан идти первым и не вытесняться более поздней
       HTML-подсказкой того же имени: подсказка — только упоминание, а здесь
       обрыв ИЗМЕРЕН. */
    {
        const char *name = "style.cdn-vol.test";
        t = fixture(s);
        snprintf(t->ip, sizeof t->ip, "8.8.8.8");
        snprintf(t->name, sizeof t->name, "%s", name);
        t->port = 443; t->transport = 6; t->family = 4;
        t->state = T_ASKING; t->res_ready = 1; t->rx_volume_only = 1;
        t->res.verdict = D2K_V_CLEAR;
        t->vol.rx_cut = 1; t->vol.rx_at_kb = 15; t->vol.rx_compressed_complete = 1;
        snprintf(t->vol.measured_path, sizeof t->vol.measured_path, "/css/soehne-web.css");
        snprintf(t->measure_path, sizeof t->measure_path, "/css/soehne-web.css");
        s->sync_pending = 0;
        (void)d2k_sched_tick(s, 900); /* главный поток разбирает исход замера */
        /* Ни подсказок, ни подтверждённой привязки: единственное, что известно
           об этом имени, — доказанный обрыв на названном пути. Начинать заново
           с «/» значит выбросить измерение. */
        task *again = fixture(s);
        snprintf(again->ip, sizeof again->ip, "8.8.8.8");
        snprintf(again->name, sizeof again->name, "%s", name);
        again->port = 443; again->transport = 6; again->family = 4;
        select_resource_path(s, again);
        CHECK(!strcmp(again->measure_path, "/css/soehne-web.css"));
        if (strcmp(again->measure_path, "/css/soehne-web.css"))
            fprintf(stderr, "без подсказок эпизод спрашивает \"%s\" (пусто — «/») "
                            "вместо доказанного /css/soehne-web.css\n", again->measure_path);
        /* Позже HTML соседнего хоста назвал этот же хост другим ресурсом. */
        d2k_resource hint;
        memset(&hint, 0, sizeof hint);
        snprintf(hint.host, sizeof hint.host, "%s", name);
        snprintf(hint.path, sizeof hint.path, "/mentioned/only.css");
        remember_resources(s, &hint, 1);
        /* Следующий эпизод того же имени. */
        task *next = fixture(s);
        snprintf(next->ip, sizeof next->ip, "8.8.8.8");
        snprintf(next->name, sizeof next->name, "%s", name);
        next->port = 443; next->transport = 6; next->family = 4;
        select_resource_path(s, next);
        CHECK(!strcmp(next->measure_path, "/css/soehne-web.css"));
        if (strcmp(next->measure_path, "/css/soehne-web.css"))
            fprintf(stderr, "следующий эпизод спрашивает \"%s\" вместо "
                            "доказанного /css/soehne-web.css\n", next->measure_path);
    }

    /* ЗАДАЧА 26, П.4: ПОДСКАЗКА ИЗ ПАМЯТИ ПЛАНИРОВЩИКА. Хост, отдающий 403/401
       на любой путь, подсказку о своих ресурсах не даёт НИКОГДА: verify.c
       собирает их только из завершённого 2xx text/html. Значит путь берётся из
       уже наблюдавшихся по этой цели — здесь свидетель привязки (/witness.css)
       успел устареть и тоже ничего не измерил, а в памяти лежит ресурс
       /observed.css, увиденный в чужом HTML. Один повтор по названной причине
       «мерить было нечем», только наблюдавшийся путь, и тот же
       d2k_resource_path_ok. */
    {
        const char *name = "assets.cdn-vol.test";
        cat.boxes = calloc(1, sizeof *cat.boxes);
        CHECK(cat.boxes != NULL);
        if (cat.boxes) {
            cat.n_boxes = 1;
            snprintf(cat.boxes[0].id, sizeof cat.boxes[0].id, "box-vol-26");
            cat.boxes[0].binds = calloc(1, sizeof *cat.boxes[0].binds);
            CHECK(cat.boxes[0].binds != NULL);
            cat.boxes[0].n_binds = cat.boxes[0].binds ? 1 : 0;
        }
        if (cat.n_boxes && cat.boxes[0].n_binds) {
            d2k_cat_binding *bd = &cat.boxes[0].binds[0];
            snprintf(bd->kind, sizeof bd->kind, "name");
            snprintf(bd->target, sizeof bd->target, "%s", name);
            snprintf(bd->plan_id, sizeof bd->plan_id, "00000000000000000000000000000026");
            snprintf(bd->probe_path, sizeof bd->probe_path, "/witness.css");
            bd->level = 3; bd->enabled = 1; bd->confirmed = 100;
            bd->transport = 6; bd->family = 4; bd->shape = (uint8_t)D2K_SHAPE_MODERN;
        }
        d2k_resource seen;
        memset(&seen, 0, sizeof seen);
        snprintf(seen.host, sizeof seen.host, "%s", name);
        snprintf(seen.path, sizeof seen.path, "/observed.css");
        remember_resources(s, &seen, 1);
        t = fixture(s);
        snprintf(t->ip, sizeof t->ip, "8.8.8.8");
        snprintf(t->name, sizeof t->name, "%s", name);
        t->port = 443; t->transport = 6; t->family = 4;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, name, t->trig,
                                     sizeof t->trig, &t->trig_len) == 0);
        select_resource_path(s, t);
        CHECK(!strcmp(t->measure_path, "/witness.css"));
        d2k_sched_vol_path_hook = stub_vol_path;
        d2k_sched_vol_hook = stub_vol_root;
        vol_cut_path = "/observed.css";
        vol_asks = 0;
        d2k_hello trig = {0};
        trig.bytes = t->trig; trig.len = t->trig_len;
        worker_volume(s, t, trig);
        CHECK(vol_asks == 2 && !strcmp(vol_asked[0], "/witness.css") &&
              !strcmp(vol_asked[1], "/observed.css"));
        CHECK(t->vol.rx_cut && !strcmp(t->measure_path, "/observed.css"));
        if (vol_asks != 2 || !t->vol.rx_cut)
            fprintf(stderr, "замеров %d (первый \"%s\", второй \"%s\"), rx_cut=%d, "
                            "путь кандидата \"%s\"\n",
                    vol_asks, vol_asked[0], vol_asks > 1 ? vol_asked[1] : "-",
                    t->vol.rx_cut, t->measure_path);
        d2k_sched_vol_path_hook = d2k_volume_probe_path;
        d2k_sched_vol_hook = d2k_volume_probe;
        vol_cut_path = NULL;
    }
    /* ЗАЩИТА ОТ ВБРОШЕННОГО СБРОСА ПРОСИТСЯ ПО ИЗМЕРЕННОМУ ПОВОДУ.
     * Поле 13.10.2026, forum.ru-board.com: рукопожатие снято, план применён
     * ко всем 133 потокам, сервер ответил всем, и коробка вбросила сброс в
     * 132 — TTL 127 против 55–57 у сервера, каждый В ОКНО. Строку
     * `guard rst_alien` не выдавал ни один сборщик, и реализованная в
     * датапате защита не включалась никогда. */
    {
        char text[512];
        task probe;
        memset(&probe, 0, sizeof probe);
        probe.transport = 6;
        probe.trigger_code = D2K_SUSPECT_RST;
        CHECK(rst_guard_wanted(&probe));
        probe.trigger_code = D2K_SUSPECT_RST_AFTER_APP;
        CHECK(rst_guard_wanted(&probe));
        probe.trigger_code = D2K_SUSPECT_RST_CUT;
        CHECK(rst_guard_wanted(&probe));
        /* Тишина и объём поводом не являются. */
        probe.trigger_code = D2K_SUSPECT_SILENT;
        CHECK(!rst_guard_wanted(&probe));
        /* QUIC — другой транспорт: там нет TCP-сброса. */
        probe.trigger_code = D2K_SUSPECT_RST; probe.transport = 17;
        CHECK(!rst_guard_wanted(&probe));

        snprintf(text, sizeof text, "d2k-plan 1 5\nproto tcp tls\n");
        CHECK(plan_arm_rst_guard(text, sizeof text) == 1);
        CHECK(strstr(text, "guard rst_alien\n") != NULL);
        /* Второй раз не дописывается. */
        CHECK(plan_arm_rst_guard(text, sizeof text) == 0);
        /* Текст остаётся годным планом: защита уезжает в провод записью. */
        uint8_t tlv[D2K_PLAN_TLV_MAX]; size_t tlv_len = 0; char err[200];
        CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tlv_len, err, sizeof err) == 0);
        int found = 0;
        for (size_t at = 12; at + 4 <= tlv_len;) {
            unsigned rec = ((unsigned)tlv[at] << 8) | tlv[at + 1];
            size_t sz = ((size_t)tlv[at + 2] << 8) | tlv[at + 3];
            at += 4;
            if (sz > tlv_len - at) { break; }
            if (rec == 0x0104 && sz == 1 && tlv[at] == 1) { found = 1; }
            at += sz;
        }
        CHECK(found);
        /* ПОВОД ДЛЯ КЛИЕНТСКИХ ПРИВЯЗОК — ИЗМЕРЕННАЯ ПРИМЕТА КОРОБКИ.
         * Зонд судит по своему триггеру, а привязка в каталоге живёт дольше
         * задачи: её повод — примета «rst» в отпечатке коробки, записанная
         * тем же замером. */
        d2k_cat_box box;
        memset(&box, 0, sizeof box);
        CHECK(!box_injects_rst(&box));
        box.fp.n_sig = 2;
        snprintf(box.fp.sig[0].kind, sizeof box.fp.sig[0].kind, "%s", "volume");
        snprintf(box.fp.sig[1].kind, sizeof box.fp.sig[1].kind, "%s", "silent");
        CHECK(!box_injects_rst(&box));
        snprintf(box.fp.sig[1].kind, sizeof box.fp.sig[1].kind, "%s", "rst");
        CHECK(box_injects_rst(&box));
        CHECK(!box_injects_rst(NULL));

        /* Не поместилась — план идёт как был, а не теряется. */
        char tight[40];
        snprintf(tight, sizeof tight, "d2k-plan 1 5\nproto tcp tls\n");
        CHECK(plan_arm_rst_guard(tight, strlen(tight) + 4) == 0);
    }

    d2k_sched_free(s);
    d2k_catalog_free(&cat);
    if (fails) fprintf(stderr, "summary: %d failures\n", fails);
    return fails ? 1 : 0;
}
