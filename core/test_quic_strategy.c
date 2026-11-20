/* test_quic_strategy.c — стратегия QUIC из ответов замера (задача 40).
 *
 * Два вопроса раньше перебора приманок, на подменённых ответах:
 *   1. «остаточное разрешение» — безобидная датаграмма первой на той же
 *      четвёрке, затем наш Initial; да → план «одна безобидная датаграмма
 *      перед Initial», перебора нет;
 *   2. разрез ClientHello на кадры CRYPTO; да → план разреза.
 * Оба «нет» и фрагменты не прошли → перебор приманок askArms без уже
 * заданных вопросов (поле 04.10, rutracker.org: «нет» на оба вопроса не
 * значит, что приманки бесполезны). Перебор приманок (askArms) — и когда
 * ответ не получен (неизмеримо). Вопрос
 * повторяется один раз, пока исход не решающий (правило задачи 35).
 */
#include <stdio.h>
#include <string.h>
#include "d2k_udpruntime.h"
#include "d2k_compose.h"
#include "d2k_quic_arms.h"

static int fails, calls, data_calls;
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); fails++; } } while (0)

/* Ответы по классу вопроса: 'Y' 3/3 и данные прошли, 'C' 3/3 и поток
   оборван, 'N' 0/3, 'M' 1/3, 'E' не отправилось, 'R' 3/3 и этап данных не
   состоялся. Строка — по символу на повтор вопроса. */
static const char *ans_clear, *ans_split;
static int i_clear, i_split, ladder_calls, ladder_pass, marked_ok;
/* Круг 1: форма фрагментации, которая проходит (0 — фрагменты не доживают). */
static int frag_ok_shape;
/* Поле 02.10 rutracker.org: из приманок прошла только fake_default_quic ×11. */
static int fake_ok_blob = -1, fake_ok_copies;
static d2k_quic_arm_question seen[64];

static char next_answer(const d2k_quic_arm_question *q) {
    if(q->udplen)return 'N'; /* Existing fixtures reject the new independent question. */
    if (q->split) return ans_split[i_split] ? ans_split[i_split++] : 'N';
    if (q->blob_len == D2K_QUIC_BENIGN_LEN && q->copies == 1 && !q->ttl && !q->frag &&
        !q->control && q->benign) return ans_clear[i_clear] ? ans_clear[i_clear++] : 'N';
    return 0;
}

static char last;
static d2k_tally probe(const d2k_quic_arm_question *q, void *u, int *sent) {
    (void)u;
    if (calls < 64) seen[calls] = *q;
    calls++;
    d2k_tally t = {0};
    t.marked = marked_ok;
    char a = next_answer(q);
    last = a;
    if (!a) {
        ladder_calls++;
        *sent = 3;
        size_t fl = 0;
        const uint8_t *fb = fake_ok_blob >= 0 ?
            d2k_quic_original_blob((size_t)fake_ok_blob, &fl, NULL) : NULL;
        if ((ladder_pass && !q->control && !q->frag) ||
            (frag_ok_shape && (q->control || q->frag == frag_ok_shape)) ||
            (fb && q->blob == fb && q->copies == fake_ok_copies && !q->ttl && !q->frag)) t.pass = 3;
        else t.fail = 3;
        return t;
    }
    if (a == 'E') { *sent = 0; t.err = t.fail = 3; return t; }
    *sent = 3;
    if (a == 'Y' || a == 'C' || a == 'R') t.pass = 3;
    else if (a == 'M') { t.pass = 1; t.fail = 2; }
    else t.fail = 3;
    return t;
}

static d2k_quic_arm_data data(const d2k_quic_arm_question *q, void *u) {
    (void)q; (void)u;
    data_calls++;
    d2k_quic_arm_data d;
    memset(&d, 0, sizeof d);
    d.verdict = last == 'C' ? D2K_QAD_CUT : last == 'R' ? D2K_QAD_NOT_RUN : D2K_QAD_PASS;
    d.app_bytes = d.verdict == D2K_QAD_PASS ? D2K_QUIC_ARM_DATA_BYTES : 0;
    return d;
}

static char pool[3][D2K_QUIC_ADDR_LEN] = {"127.0.0.1", "127.0.0.2", "127.0.0.3"};

static d2k_quic_arm run(const char *c, const char *s, int residual, size_t n_pool) {
    ans_clear = c; ans_split = s; i_clear = i_split = 0;
    calls = data_calls = ladder_calls = 0;
    d2k_quic_arm_context ctx = {.pool = pool, .n_pool = n_pool, .next = 1, .residual = residual,
                                .probe = probe, .marked = 1, .data = data};
    return d2k_quic_strategy_arms(&ctx);
}

/* Field f: direct H3 stalls, quic5 x2 TTL3 plan carries six requests.
 * This is a question about that contrast, not a successful cheap filter. */
static int ttl_calls, ttl_data_calls, ttl_cut;
static d2k_tally ttl_probe(const d2k_quic_arm_question *q, void *u, int *sent) {
    (void)u; ttl_calls++; *sent=3;
    size_t n; const uint8_t *b=d2k_quic_original_blob(0,&n,NULL);
    int same=q->blob==b && q->blob_len==n && q->copies==2 && q->ttl==3 && !q->split && !q->frag;
    return (d2k_tally){.pass=same?3:0,.fail=same?0:3,.marked=1};
}
static d2k_quic_arm_data ttl_data(const d2k_quic_arm_question *q, void *u) {
    (void)u; ttl_data_calls++;
    CHECK(q->need_complete && q->budget_pk==25);
    return (d2k_quic_arm_data){.verdict=ttl_cut?D2K_QAD_CUT:D2K_QAD_PASS};
}
static void test_ttl_lifetime(void) {
    d2k_quic_arm_context c={.pool=pool,.n_pool=1,.marked=1,.probe=ttl_probe,
                          .data=ttl_data,.need_complete=1,.budget_pk=25};
    d2k_quic_arm r=d2k_quic_strategy_arms(&c);
    CHECK(r.kind==D2K_QA_TTL && r.copies==2 && r.ttl==3);
    CHECK(r.strategy!=D2K_QS_LADDER && ttl_calls==1 && ttl_data_calls==1);
    ttl_cut=1; ttl_calls=ttl_data_calls=0;
    r=d2k_quic_strategy_arms(&c);
    CHECK(r.kind==D2K_QA_NOT_FOUND); /* first complete response cannot win */
    CHECK(ttl_data_calls==1); /* fallback must not repeat the same question */
}

static int combo_calls, combo_cut, combo_partial;
static d2k_tally combo_probe(const d2k_quic_arm_question *q, void *u, int *sent) {
    (void)u; *sent=3;
    size_t n; const uint8_t *b=d2k_quic_original_blob(3,&n,NULL);
    int match=q->blob==b && q->copies==11 && !q->ttl && !q->frag;
    if(match && q->split) combo_calls++;
    int pass=match ? (combo_partial && !q->split ? 2:3):0;
    return (d2k_tally){.pass=pass,.fail=3-pass,.marked=1};
}
static d2k_quic_arm_data combo_data(const d2k_quic_arm_question *q, void *u) {
    (void)u;
    return (d2k_quic_arm_data){.verdict=q->split && !combo_cut?D2K_QAD_PASS:D2K_QAD_CUT};
}
static void test_fake_split(void) {
    d2k_quic_arm_context c={.pool=pool,.n_pool=1,.marked=1,.probe=combo_probe,.data=combo_data};
    d2k_quic_arm r=d2k_quic_strategy_arms(&c);
    CHECK(combo_calls==1 && r.kind==D2K_QA_SPLIT && r.copies==11 && r.len==620);
    CHECK(r.strategy!=D2K_QS_LADDER);
    combo_partial=1; combo_calls=0;
    r=d2k_quic_strategy_arms(&c);
    CHECK(combo_calls==1 && r.kind==D2K_QA_SPLIT);
    combo_cut=1; combo_calls=0;
    r=d2k_quic_strategy_arms(&c);
    CHECK(combo_calls==1 && r.kind==D2K_QA_NOT_FOUND);
    c.no_split=1; combo_calls=0;
    r=d2k_quic_strategy_arms(&c);
    CHECK(combo_calls==0 && r.kind==D2K_QA_NOT_FOUND);
}

static int length_mode,length_asks,length_data_calls,length_fallback;
static d2k_tally length_probe(const d2k_quic_arm_question *q,void *u,int *sent) {
    (void)u;char text[16384];*sent=3;
    CHECK(!d2k_quic_question_plan(q,text,sizeof text));
    int length=strstr(text,"\nudplen 100\n")!=NULL;
    if(q->blob_len && !q->benign && !q->ttl)length_fallback++;
    if(!length)return (d2k_tally){.fail=3,.marked=1};
    length_asks++;
    if(length_mode==2)return (d2k_tally){.pass=2,.fail=1,.marked=1};
    if(length_mode==3){*sent=0;return (d2k_tally){.err=3,.fail=3,.marked=1};}
    return (d2k_tally){.pass=3,.marked=1};
}
static d2k_quic_arm_data length_data(const d2k_quic_arm_question *q,void *u) {
    (void)u;length_data_calls++;
    CHECK(q->need_complete && q->budget_pk==25);
    return (d2k_quic_arm_data){.verdict=length_mode==1?D2K_QAD_CUT:
        length_mode==4?D2K_QAD_NOT_RUN:D2K_QAD_PASS};
}
static void test_length_before_fallback(void) {
    for(length_mode=0;length_mode<5;length_mode++) {
        length_asks=length_data_calls=length_fallback=0;
        d2k_quic_arm_context c={.pool=pool,.n_pool=1,.marked=1,
            .probe=length_probe,.data=length_data,.need_complete=1,.budget_pk=25};
        d2k_quic_arm r=d2k_quic_strategy_arms(&c);
        CHECK(length_asks==(length_mode>=2?2:1));
        CHECK(length_data_calls==(length_mode==2 || length_mode==3?0:length_mode==4?2:1));
        if(!length_mode) {
            char text[16384]={0};d2k_quic_props p={0};
            CHECK(r.kind!=D2K_QA_NOT_FOUND && r.strategy!=D2K_QS_LADDER);
            CHECK(!length_fallback);
            CHECK(!d2k_quic_compose_plan(&r,&p,text,sizeof text));
            CHECK(strstr(text,"\nudplen 100\n") && !strstr(text,"fake "));
            r.len=1;
            CHECK(d2k_quic_compose_plan(&r,&p,text,sizeof text)!=0);
            r.len=0;r.kind=D2K_QA_SPLIT;
            CHECK(d2k_quic_compose_plan(&r,&p,text,sizeof text)!=0);
        }else {
            CHECK(r.kind==D2K_QA_NOT_FOUND && length_fallback>0);
            CHECK(r.longer==(length_mode==1?D2K_PROP_NO:D2K_PROP_UNKNOWN));
            CHECK(r.incomplete==(length_mode>=2));
        }
    }
}

static unsigned yielded_budget;
static int yield_cancel,yield_probes;
static int test_yield(uint32_t *ms){*ms=50;return yield_cancel?-1:0;}
static void test_yield_spent(void *u,uint32_t ms){(void)u;yielded_budget+=ms;}
static int test_yield_can(void *u){(void)u;return yielded_budget>=50;}
static d2k_tally test_yield_probe(const d2k_quic_arm_question *q,void *u,int *sent){
    (void)q;(void)u;yield_probes++;*sent=3;return (d2k_tally){.pass=3,.marked=1};
}
static void test_yield_budget(void){
    d2k_quic_yield_fn saved=d2k_quic_yield_hook;
    d2k_quic_yield_hook=test_yield;
    for(yield_cancel=0;yield_cancel<2;yield_cancel++){
        yielded_budget=0;yield_probes=0;
        d2k_quic_arm_context c={.pool=pool,.n_pool=1,.marked=1,
            .probe=test_yield_probe,.can_ask=test_yield_can,.spent=test_yield_spent};
        d2k_quic_arm r=d2k_quic_strategy_arms(&c);
        if(!yield_cancel){CHECK(yield_probes==1 && yielded_budget==50);CHECK(r.kind==D2K_QA_BLOB && !r.incomplete);}
        else {CHECK(!yield_probes);CHECK(r.kind==D2K_QA_NOT_FOUND && r.incomplete);}
    }
    d2k_quic_yield_hook=saved;
}

int main(void) {
    test_yield_budget();
    test_length_before_fallback();
    static const uint8_t zero16[16];
    marked_ok = 1;

    /* 1. Остаточное разрешение есть: одна безобидная датаграмма, перебора нет. */
    d2k_quic_arm r = run("Y", "", 0, 1);
    CHECK(r.kind == D2K_QA_BLOB && r.strategy == D2K_QS_CLEARANCE && r.original);
    CHECK(r.len == D2K_QUIC_BENIGN_LEN && !memcmp(r.bytes, zero16, 16) && r.copies == 1 && !r.ttl);
    CHECK(r.clearance == D2K_PROP_YES && r.split_crypto == D2K_PROP_UNKNOWN);
    CHECK(calls == 1 && r.probes == 3 && data_calls == 1 && ladder_calls == 0 && !r.incomplete);
    CHECK(seen[0].benign && seen[0].blob_len == 16 && !strcmp(seen[0].addr, pool[0]));
    CHECK(r.n_trace == 1 && r.trace[0].data == D2K_QAD_PASS);

    /* 2. Разрешения нет, разрез CRYPTO проходит. */
    r = run("N", "Y", 0, 1);
    CHECK(r.kind == D2K_QA_SPLIT && r.strategy == D2K_QS_SPLIT && r.len == 0);
    CHECK(r.clearance == D2K_PROP_NO && r.split_crypto == D2K_PROP_YES);
    CHECK(calls == 2 && r.probes == 6 && data_calls == 1 && ladder_calls == 0);
    CHECK(seen[1].split == 1 && !seen[1].blob_len);

    /* 3. Оба «нет», фрагменты не доживают — это ПОЛЕ 04.10, rutracker.org
          (06:02:30: 0/3, 0/3, 0/3 — «плечо не нашлось за 9 опытов», браузер
          ушёл на TCP). Эти ответы не говорят о приманках ничего: на том же
          имени 02.10 21:39 fake_default_quic ×11 прошла 3/3, её план
          389a3920 — 4/4 полных ответа (task-55-facts §2). Дальше —
          перебор askArms, но уже заданные вопросы (0x00…0 ×1 и выживание
          фрагментов) он не повторяет. */
    fake_ok_blob = 3; fake_ok_copies = 11;
    r = run("N", "N", 0, 1);
    CHECK(r.strategy == D2K_QS_LADDER && r.kind == D2K_QA_COPIES && !r.incomplete);
    CHECK(r.copies == 11 && !r.ttl && !strcmp(r.blob_name, "fake_default_quic"));
    CHECK(r.clearance == D2K_PROP_NO && r.split_crypto == D2K_PROP_NO);
    CHECK(r.frag_survives == D2K_PROP_NO && !r.frag_kind);
    /* 3 вопроса стратегии; приманки ×1 без 0x00…0 (5, включая последнюю nofix), копии quic5 ×6/×11 и
       fake_default_quic ×6/×11 (4); после PASS TTL не задаётся. */
    CHECK(calls == 4 + 9 && ladder_calls == 1 + 9 && r.n_trace == 13);
    {
        int controls = 0, benign = 0;
        for (int i = 0; i < calls && i < 64; i++) {
            controls += seen[i].control;
            benign += seen[i].blob_len == 16 && seen[i].copies == 1 && !seen[i].ttl;
        }
        CHECK(controls == 1 && benign == 1);
    }
    /* cce1631 retains nofix as the last intrinsic question. It costs one
       question only after every earlier intrinsic fake failed; it must not
       replace or repeat another question, or move ahead of the donor fakes. */
    {
        size_t nofix_len = 0, default_len = 0;
        const uint8_t *nofix = d2k_quic_original_blob(5, &nofix_len, NULL);
        const uint8_t *def = d2k_quic_original_blob(3, &default_len, NULL);
        int nofix_count = 0;
        for (int i = 0; i < calls && i < 64; i++)
            if (seen[i].blob == nofix) nofix_count++;
        CHECK(nofix_count == 1 && nofix_len == 1200 && nofix[0] == 0x80);
        CHECK(seen[7].blob == def && seen[7].blob_len == default_len);
        CHECK(seen[8].blob == nofix && seen[8].blob_len == nofix_len &&
              seen[8].copies == 1 && !seen[8].ttl && !seen[8].frag);
        CHECK(seen[9].copies == D2K_QUIC_COPIES_A);
    }
    CHECK(strstr(r.reason, "fake_default_quic") != NULL);
    fake_ok_blob = -1; fake_ok_copies = 0;

    /* 3в. То же, и приманки не взяли ничего: обход по QUIC не найден, теперь
          — после перебора, а не вместо него. */
    r = run("N", "N", 0, 1);
    CHECK(r.kind == D2K_QA_NOT_FOUND && !r.incomplete && r.strategy == D2K_QS_LADDER);
    CHECK(calls == 4 + 13 && ladder_calls == 1 + 13 && data_calls == 0);
    CHECK(seen[3].control && r.frag_survives == D2K_PROP_NO);

    /* 3а. Финальное ревью core, I1: клиенту разрез CRYPTO неприменим
          (ClientHello шире датаграммы). Вопрос о разрезе не задаётся даже
          там, где коробка его пропустила бы; разрешения нет — дальше вопросы
          фрагментации, как при «нет». */
    {
        ans_clear = "N"; ans_split = "Y"; i_clear = i_split = 0;
        calls = data_calls = ladder_calls = 0;
        d2k_quic_arm_context ctx = {.pool = pool, .n_pool = 1, .next = 1, .residual = 0,
                                    .probe = probe, .marked = 1, .data = data, .no_split = 1};
        r = d2k_quic_strategy_arms(&ctx);
        CHECK(r.kind != D2K_QA_SPLIT && r.strategy != D2K_QS_SPLIT);
        CHECK(i_split == 0 && !r.split_asked && r.split_crypto == D2K_PROP_UNKNOWN);
        for (int i = 0; i < calls && i < 64; i++) CHECK(!seen[i].split);
        CHECK(r.kind == D2K_QA_NOT_FOUND && seen[2].control && strstr(r.reason, "неприменим"));
        CHECK(r.strategy == D2K_QS_LADDER && calls == 3 + 13);
    }

    /* 3б. Оба «нет», фрагменты доживают и форма 3 проходит — план из ответа. */
    frag_ok_shape = 3;
    r = run("N", "N", 0, 1);
    CHECK(r.kind == D2K_QA_FRAG && r.frag_kind == 3 && r.frag_survives == D2K_PROP_YES);
    CHECK(r.strategy == D2K_QS_FRAG && r.len == 0 && !r.incomplete);
    CHECK(calls == 3 + 1 + 3 && ladder_calls == 4 && data_calls == 1);
    frag_ok_shape = 0;

    /* 4. Фильтр прошёл, а поток оборван — это решающее «нет», не повтор. */
    r = run("C", "C", 0, 1);
    CHECK(r.kind == D2K_QA_NOT_FOUND && calls == 4 + 13 && data_calls == 2 && ladder_calls == 1 + 13);
    CHECK(r.clearance == D2K_PROP_NO && r.split_crypto == D2K_PROP_NO);

    /* 5. Неустойчивый ответ — один повтор; решающий второй ответ принимается. */
    r = run("MY", "", 0, 1);
    CHECK(r.kind == D2K_QA_BLOB && r.strategy == D2K_QS_CLEARANCE && calls == 2);
    CHECK(r.n_trace == 2 && r.trace[0].answered == 1);

    /* 6. Неизмеримо и после повтора (1/3, затем этап данных не состоялся):
          стратегия из ответов не собирается — запасной перебор askArms. */
    r = run("MR", "N", 0, 1);
    CHECK(r.clearance == D2K_PROP_UNKNOWN && r.split_crypto == D2K_PROP_NO);
    /* Круг 1: вопрос, заданный до предела повторов, перебор не задаёт снова
       (0x00…0 ×1 — тот же вопрос). */
    CHECK(r.clearance_asked && r.split_asked);
    CHECK(ladder_calls == 14 && calls == 4 + 14);
    CHECK(r.strategy == D2K_QS_LADDER && r.kind == D2K_QA_NOT_FOUND);
    CHECK(r.n_trace == 4 + 14 && r.n_trace <= D2K_QUIC_ARM_STEPS);
    CHECK(r.probes == 3 * (4 + 14));
    for (int i = 3; i < calls && i < 64; i++)
        CHECK(!(seen[i].blob_len == 16 && seen[i].copies == 1 && !seen[i].ttl));

    /* 7. Не отправилось оба раза — тоже неизмеримо; запасной перебор находит. */
    ladder_pass = 1;
    r = run("EE", "EE", 0, 1);
    /* quic5 ×1 completes; later axes are unnecessary. */
    CHECK(calls == 5 + 1 && r.strategy == D2K_QS_LADDER && r.kind == D2K_QA_COPIES);
    CHECK(r.clearance == D2K_PROP_UNKNOWN && r.split_crypto == D2K_PROP_UNKNOWN);
    ladder_pass = 0;

    /* 6б. Разрешения решающе нет, разрез неизмерим: запасной перебор не
           задаёт заново тот же вопрос (16 нулей ×1 перед Initial). */
    r = run("N", "EE", 0, 1);
    CHECK(r.clearance == D2K_PROP_NO && r.strategy == D2K_QS_LADDER);
    CHECK(ladder_calls == 14 && calls == 4 + 14);
    for (int i = 3; i < calls && i < 64; i++)
        CHECK(!(seen[i].blob_len == 16 && seen[i].copies == 1 && !seen[i].ttl));

    /* 8. Остаточная блокировка: каждый вопрос — свежий адрес; адреса кончились
          раньше ответа — неизмеримо, перебору тоже не на чем. */
    r = run("N", "Y", 1, 2);
    CHECK(calls == 1 && !strcmp(seen[0].addr, pool[1]));
    CHECK(r.clearance == D2K_PROP_NO && r.split_crypto == D2K_PROP_UNKNOWN);
    CHECK(r.incomplete && r.kind == D2K_QA_NOT_FOUND && ladder_calls == 0);
    CHECK(r.clearance_asked && !r.split_asked); /* адреса не было — вопрос не задан */

    /* 9. Метка не подтверждена — верить нельзя. */
    marked_ok = 0;
    r = run("Y", "", 0, 1);
    CHECK(r.kind == D2K_QA_FLAKY);
    marked_ok = 1;

    test_ttl_lifetime();
    test_fake_split();
    if (fails) return 1;
    puts("QUIC strategy from answers: passed");
    return 0;
}
