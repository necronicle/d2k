/* test_port.c — инварианты переноса, проверяемые БЕЗ сети.
 *
 * Перенос тестов эталона: strategy_export_test.go целиком и те проверки
 * classify_test.go, что не поднимают поддельную коробку (splitOffsets,
 * RawTrigger). Сетевая часть сверяется иначе и на роутере — tests/compare.sh.
 *
 * Смысл каждой проверки — тот же, что у её оригинала, и он в комментариях: это
 * не «тесты ради покрытия», а перечень мест, где инструмент уже врал.
 */
#include "d2k_detect.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int d2k_split_offsets(const int *cuts, int ncuts, int n, void *out, int cap);
int d2k_parse_stale_rst_rule(const char *line, int *port);
int d2k_parse_rst_rule(const char *line, int *port, long *pid);
int d2k_rst_rule_stale(const char *line, int *port, long *pid);
extern int (*d2k_raw_alive_hook)(long pid);

typedef struct { int from, to; } span;

static int fails;

static void fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("  ПРОВАЛ: ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    fails++;
}

/* ИНВАРИАНТ ЭКСПОРТА: строка обязана воспроизводить ту гипотезу, которая
 * сработала. Этого теста не было, и цена отсутствия оказалась высокой:
 * семнадцать гипотез семейства badsum-x{N}-g{G} печатались одной строкой,
 * неотличимой от одиночной badsum. Замер отвечал «поймали badsum-x7», человек
 * вставлял плечо с одной фальшивкой, и обход не вставал — при том, что
 * инструмент «нашёл». Проверяем не текст, а свойство: измеренное поле обязано
 * доехать до строки. */
static void test_repeats_reach_the_strategy(void)
{
    const d2k_poison *ps;
    int n, i, checked = 0;
    ps = d2k_poisons(&n);
    for (i = 0; i < n; i++) {
        char st[1024], want[32];
        if (ps[i].repeats <= 1 || !d2k_poison_has_fake(&ps[i])) {
            continue;
        }
        d2k_strategy_for_poison(&ps[i], st, sizeof(st));
        if (st[0] == '\0') {
            fail("%s: пустая строка при repeats=%d", ps[i].name, ps[i].repeats);
            continue;
        }
        snprintf(want, sizeof(want), "repeats=%d", ps[i].repeats);
        if (!strstr(st, want)) {
            fail("%s: в строке нет «%s»\n  %s", ps[i].name, want, st);
        }
        checked++;
    }
    if (checked == 0) {
        fail("ни одной гипотезы с копиями — тест перестал что-либо проверять");
    }
}

/* Метка времени и обнулённый идентификатор — такие же измеренные признаки
 * боевых плеч. Без них badsum+ts и badsum+ipid неотличимы от badsum. */
static void test_fooling_flags_reach_the_strategy(void)
{
    const d2k_poison *ps;
    int n, i;
    ps = d2k_poisons(&n);
    for (i = 0; i < n; i++) {
        char st[1024];
        d2k_strategy_for_poison(&ps[i], st, sizeof(st));
        if (st[0] == '\0') {
            continue;
        }
        if (ps[i].tcp_ts && !strstr(st, "tcp_ts")) {
            fail("%s: метка времени измерена, а в строке её нет\n  %s", ps[i].name, st);
        }
        if (ps[i].ip_id_zero && !strstr(st, "ip_id")) {
            fail("%s: обнулённый идентификатор измерен, а в строке его нет\n  %s",
                 ps[i].name, st);
        }
    }
}

/* ЗАДАЧА 49: НИ ОДНОЙ ГИПОТЕЗЫ ДВАЖДЫ. Донор спрашивал badsum-x2-g20 и
 * badsum-x2-g80 дважды (головной список и сетка «копии × пауза»), а
 * badsum-x7 и badsum-x7-g0 — одно и то же. При единогласии повтор уже
 * проваленной гипотезы исхода не меняет: три лишних зонда за прогон
 * (решение владельца 03.10: трассу донора здесь не повторяем). Сравнение —
 * по ВСЕМ параметрам, кроме имени; одна копия и «копий не задано» — одно. */
static void test_no_duplicate_hypotheses(void)
{
    const d2k_poison *ps;
    int n, i, j;
    ps = d2k_poisons(&n);
    for (i = 0; i < n; i++) {
        for (j = i + 1; j < n; j++) {
            d2k_poison a = ps[i], b = ps[j];
            memset(a.name, 0, sizeof a.name);
            memset(b.name, 0, sizeof b.name);
            if (a.repeats <= 1) a.repeats = 1;
            if (b.repeats <= 1) b.repeats = 1;
            if (memcmp(&a, &b, sizeof a) == 0) {
                fail("гипотеза спрашивается дважды: %s и %s", ps[i].name, ps[j].name);
            }
        }
    }
}

/* differsOnTheWire — отличаются ли две гипотезы чем-то, кроме паузы.
 *
 * Перечень полей здесь — это и есть список того, что обязано доезжать до
 * строки; появится новое поле — тест придётся дополнить осознанно. */
static int differs_on_the_wire(d2k_poison a, d2k_poison b)
{
    /* Перекрытие «по длине приманки» и перекрытие ровно в 681 байт с образцом
     * целого приветствия — на проводе одно и то же: 681 это и есть длина
     * шипованного приветствия. Разные способы задать одну величину не должны
     * считаться разными приёмами. */
    if (a.seqovl_exact != b.seqovl_exact && a.decoy_hello && b.decoy_hello) {
        a.seqovl_exact = b.seqovl_exact = 0;
        a.seqovl = b.seqovl = 0;
        return differs_on_the_wire(a, b);
    }
    return a.ttl != b.ttl || a.badsum != b.badsum || a.seq_shift != b.seq_shift ||
           a.md5 != b.md5 || a.md5_ts != b.md5_ts || a.decoy_hello != b.decoy_hello ||
           a.disorder != b.disorder || a.disorder_pos != b.disorder_pos ||
           a.tcp_ts != b.tcp_ts ||
           a.ip_id_zero != b.ip_id_zero || a.syn_data != b.syn_data ||
           a.oob != b.oob || a.fake_between != b.fake_between ||
           a.repeats != b.repeats || a.seqovl_exact != b.seqovl_exact ||
           a.seqovl != b.seqovl;
}

/* Гипотезы, различающиеся ПО ПРОВОДУ, обязаны давать различающиеся строки.
 * Пауза между копиями движком невыразима, поэтому семейства, отличающиеся
 * ТОЛЬКО паузой, схлопываться в одну строку имеют право — и только они. */
static void test_distinct_poisons_give_distinct_strategies(void)
{
    const d2k_poison *ps;
    int n, i, j;
    ps = d2k_poisons(&n);
    for (i = 0; i < n; i++) {
        char a[1024];
        d2k_strategy_for_poison(&ps[i], a, sizeof(a));
        if (a[0] == '\0') {
            continue;
        }
        for (j = i + 1; j < n; j++) {
            char b[1024];
            d2k_strategy_for_poison(&ps[j], b, sizeof(b));
            if (b[0] == '\0' || strcmp(a, b) != 0) {
                continue;
            }
            if (differs_on_the_wire(ps[i], ps[j])) {
                fail("разные по проводу гипотезы дают одну строку:\n  %s и %s\n  %s",
                     ps[i].name, ps[j].name, a);
            }
        }
    }
}

/* Именованные приёмы обязаны нести свои флаги: без них зонд шлёт обычную
 * фальшивку, а трасса называет её «syndata» — и отрицательный исход читается
 * как вывод о механизме, который ни разу не проверяли. */
static void test_named_primitives_carry_their_flags(void)
{
    const d2k_poison *ps;
    int n, i, seen_syn = 0, seen_oob = 0;
    ps = d2k_poisons(&n);
    for (i = 0; i < n; i++) {
        if (strcmp(ps[i].name, "syndata") == 0) {
            seen_syn = 1;
            if (!ps[i].syn_data) {
                fail("гипотеза «syndata» не несёт своего флага");
            }
        }
        if (strcmp(ps[i].name, "oob") == 0) {
            seen_oob = 1;
            if (!ps[i].oob) {
                fail("гипотеза «oob» не несёт своего флага");
            }
        }
    }
    if (!seen_syn) { fail("гипотеза «syndata» пропала из перебора"); }
    if (!seen_oob) { fail("гипотеза «oob» пропала из перебора"); }
}

/* A known working multidisorder variant cuts at byte 2 only. It is not the
 * donor's existing pos=1,midsld three-piece probe, so it must be independently
 * measurable and exported without silently changing its split position. */
static void test_disorder_pos2_candidate_is_measured_and_exported(void)
{
    const d2k_poison *ps;
    int n, found = 0;
    ps = d2k_poisons(&n);
    for (int i = 0; i < n; i++) {
        if (strcmp(ps[i].name, "disorder-pos2") != 0) { continue; }
        char st[1024];
        found = 1;
        if (!ps[i].disorder || ps[i].disorder_pos != 2) {
            fail("disorder-pos2 несёт неверные параметры: disorder=%d pos=%d",
                 ps[i].disorder, ps[i].disorder_pos);
        }
        d2k_strategy_for_poison(&ps[i], st, sizeof(st));
        if (!strstr(st, "--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=2") ||
            strstr(st, "midsld")) {
            fail("disorder-pos2 экспортирован как другой разрез: %s", st);
        }
        break;
    }
    if (!found) { fail("из измеряемого перебора отсутствует disorder-pos2"); }
}

/* Свойство «коробка проверяет контрольную сумму» нельзя выводить из молчания.
 * Промах фальшивки объясняется и разбором L7 — по тишине эти причины не
 * различить, а ложное «да» отключало битую сумму у собранных кандидатов. */
static void test_checksum_verdict_never_inferred_from_silence(void)
{
    const d2k_poison *ps;
    int n, i;
    d2k_poison badsum;
    d2k_dprops pr;

    ps = d2k_poisons(&n);
    for (i = 0; i < n; i++) {
        memset(&pr, 0, sizeof(pr));
        d2k_note_props_miss(&pr, &ps[i]);
        if (pr.validates_checksum != D2K_TRI_UNSET) {
            fail("%s: промах выставил «проверяет сумму» — вывод из тишины", ps[i].name);
        }
    }
    /* А проход badsum-зонда обязан давать «не проверяет»: коробка его съела. */
    memset(&pr, 0, sizeof(pr));
    memset(&badsum, 0, sizeof(badsum));
    snprintf(badsum.name, sizeof(badsum.name), "badsum");
    badsum.badsum = 1;
    d2k_note_props_hit(&pr, &badsum);
    if (pr.validates_checksum != D2K_TRI_FALSE) {
        fail("проход badsum-зонда не дал «сумму не проверяет»");
    }
}

/* Разбор правил подавления обязан узнавать СВОЮ форму и не трогать чужие.
 * Правило снимается уборщиком при закрытии соединения, но kill -9 уборщика не
 * даёт — панель именно так и добивает замер, не уложившийся в срок. */
static void test_stale_rule_recognition_is_exact(void)
{
    static const char *foreign[] = {
        "-A OUTPUT -p tcp -m tcp --sport 39997 --tcp-flags RST RST -j ACCEPT", /* чужое действие */
        "-A INPUT -p tcp -m tcp --sport 39997 --tcp-flags RST RST -j DROP",    /* другая цепочка */
        "-A OUTPUT -p udp -m udp --sport 39997 -j DROP",                       /* другой протокол */
        "-A OUTPUT -p tcp -m tcp --sport 22 --tcp-flags RST RST -j DROP",      /* порт не наш */
        "-A OUTPUT -p tcp -m tcp --sport 60000 --tcp-flags RST RST -j DROP",   /* выше диапазона */
        ""
    };
    int port = 0, i;
    if (!d2k_parse_stale_rst_rule(
            "-A OUTPUT -p tcp -m tcp --sport 39997 --tcp-flags RST RST -j DROP", &port) ||
        port != 39997) {
        fail("своё правило не опознано: port=%d", port);
    }
    for (i = 0; i < (int)(sizeof(foreign) / sizeof(foreign[0])); i++) {
        if (d2k_parse_stale_rst_rule(foreign[i], &port)) {
            fail("чужое правило принято за своё: «%s»", foreign[i]);
        }
    }
}

/* ЗАДАЧА 49: ПРАВИЛО НЕСЁТ ВЛАДЕЛЬЦА. Уборка при старте снимала ЛЮБОЕ правило
 * нашего диапазона — и правило живого зонда d2kc, если d2k-detect запускали
 * рядом (поле 03.10). Теперь правило помечено pid процесса-владельца;
 * снимается только правило мёртвого процесса или старое, без пометки. */
static int fake_alive_pid;
static int fake_alive(long pid) { return pid == fake_alive_pid; }

static void test_rst_rule_owner_and_staleness(void)
{
    int port = 0;
    long pid = -1;
    const char *mine =
        "-A OUTPUT -p tcp -m tcp --sport 40750 --tcp-flags RST RST "
        "-m comment --comment d2k-rst:4242 -j DROP";
    const char *quoted =
        "-A OUTPUT -p tcp -m tcp --sport 40751 --tcp-flags RST RST "
        "-m comment --comment \"d2k-rst:4243\" -j DROP";
    const char *legacy = "-A OUTPUT -p tcp -m tcp --sport 39842 --tcp-flags RST RST -j DROP";
    static const char *foreign[] = {
        "-A OUTPUT -p tcp -m tcp --sport 40750 --tcp-flags RST RST "
        "-m comment --comment other:4242 -j DROP",                           /* чужая пометка */
        "-A OUTPUT -p tcp -m tcp --sport 40750 --tcp-flags RST RST "
        "-m comment --comment d2k-rst:x -j DROP",                            /* не pid */
        "-A OUTPUT -p tcp -m tcp --sport 40750 --tcp-flags RST RST "
        "-m comment --comment d2k-rst:4242 -j ACCEPT",                       /* чужое действие */
        "-A OUTPUT -p tcp -m tcp --sport 22 --tcp-flags RST RST "
        "-m comment --comment d2k-rst:4242 -j DROP",                         /* порт не наш */
    };
    size_t i;
    if (!d2k_parse_rst_rule(mine, &port, &pid) || port != 40750 || pid != 4242)
        fail("помеченное правило не опознано: port=%d pid=%ld", port, pid);
    if (!d2k_parse_rst_rule(quoted, &port, &pid) || port != 40751 || pid != 4243)
        fail("помеченное правило в кавычках не опознано: port=%d pid=%ld", port, pid);
    if (!d2k_parse_rst_rule(legacy, &port, &pid) || port != 39842 || pid != 0)
        fail("правило без пометки не опознано: port=%d pid=%ld", port, pid);
    for (i = 0; i < sizeof foreign / sizeof foreign[0]; i++)
        if (d2k_parse_rst_rule(foreign[i], &port, &pid))
            fail("чужое правило принято за своё: «%s»", foreign[i]);

    d2k_raw_alive_hook = fake_alive;
    fake_alive_pid = 4242;
    if (d2k_rst_rule_stale(mine, &port, &pid))
        fail("правило ЖИВОГО процесса признано брошенным — уборка сняла бы его у живого зонда");
    fake_alive_pid = 1;
    if (!d2k_rst_rule_stale(mine, &port, &pid) || port != 40750 || pid != 4242)
        fail("правило мёртвого процесса не признано брошенным");
    if (!d2k_rst_rule_stale(legacy, &port, &pid) || pid != 0)
        fail("правило старого формата (без владельца) не признано брошенным");
    d2k_raw_alive_hook = NULL;
}

/* Разрез в нуле и в длине — это не разрез; такие точки обязаны отсеиваться,
 * иначе двоичный поиск на краю выродится в запись нулевой длины. */
static void test_split_offsets_ignores_out_of_range_cuts(void)
{
    int cuts[5] = {0, 3, 3, 10, 99};
    span got[8];
    int n = d2k_split_offsets(cuts, 5, 10, got, 8);
    if (n != 2) {
        fail("кусков = %d, ждали 2", n);
        return;
    }
    if (got[0].from != 0 || got[0].to != 3 || got[1].from != 3 || got[1].to != 10) {
        fail("куски = [%d,%d] [%d,%d], ждали [0,3] [3,10]",
             got[0].from, got[0].to, got[1].from, got[1].to);
    }
}

static void test_raw_trigger_parses_and_rejects_garbage(void)
{
    d2k_trigger tr;
    char err[160];
    static const uint8_t want[4] = {0x57, 0x41, 0x06, 0x03};

    if (d2k_trigger_raw_hex("57 41 06 03", &tr, err, sizeof(err)) != 0) {
        fail("hex с пробелами не разобран: %s", err);
    } else if (tr.len != 4 || memcmp(tr.payload, want, 4) != 0) {
        fail("нагрузка разобрана неверно, длина %d", (int)tr.len);
    }
    if (d2k_trigger_raw_hex("нехекс", &tr, err, sizeof(err)) == 0) {
        fail("мусор обязан отвергаться");
    }
    if (d2k_trigger_raw_hex("57", &tr, err, sizeof(err)) == 0) {
        fail("триггер в один байт обязан отвергаться");
    }
}

/* Собранный кандидат обязан отличаться от базового по тому свойству, из
 * которого он собран: иначе «собрано из вектора» — пустое слово. */
static void test_compose_follows_the_vector(void)
{
    d2k_dprops pr;
    d2k_poison out[8];
    int n;

    memset(&pr, 0, sizeof(pr));
    pr.tolerates_left_overlap = D2K_TRI_FALSE;
    n = d2k_compose_from_props(&pr, NULL, 0, out, 8);
    if (n < 1 || !out[0].seqovl_exact) {
        fail("«не держит перекрытие слева» не дало кандидата с перекрытием");
    }

    memset(&pr, 0, sizeof(pr));
    pr.tolerates_reorder = D2K_TRI_FALSE;
    n = d2k_compose_from_props(&pr, NULL, 0, out, 8);
    if (n < 1 || !out[0].disorder) {
        fail("«не держит порядок» не дало кандидата со сбитым порядком");
    }

    /* Пустой вектор — последний собранный кандидат перед падением в перебор. */
    memset(&pr, 0, sizeof(pr));
    n = d2k_compose_from_props(&pr, NULL, 0, out, 8);
    if (n != 1 || !out[0].badsum || !out[0].disorder || !out[0].seqovl_exact) {
        fail("пустой вектор не дал кандидата «всё сразу»");
    }

    /* Битую сумму пробуем и когда свойство НЕ ИЗМЕРЕНО: иначе выключается
     * единственный признак, работающий на коробках, не сверяющих сумму. */
    memset(&pr, 0, sizeof(pr));
    pr.counts_duplicates = D2K_TRI_TRUE;
    n = d2k_compose_from_props(&pr, NULL, 0, out, 8);
    if (n < 1 || !out[0].badsum) {
        fail("при неизмеренной сумме кандидат остался без битой суммы");
    }
}

static void test_md5ts_hypothesis_context(void)
{
    int n, found = 0, legacy = 0;
    const d2k_poison *ps = d2k_poisons(&n);
    d2k_trigger tr = {0};
    tr.client_tcp_known = 1;
    for (int i = 0; i < n; i++) {
        if (!strcmp(ps[i].name, "md5")) legacy += ps[i].md5 && !ps[i].md5_ts;
        if (!ps[i].md5_ts) continue;
        found++;
        if (ps[i].md5 || !d2k_poison_has_fake(&ps[i])) fail("MD5_TS must be a separate fake hypothesis");
        if (d2k_trigger_allows_poison(&tr, &ps[i])) fail("MD5_TS offered without client timestamp");
        memcpy(tr.client_tcp_options, (uint8_t[]){1,1,8,10,0,1,2,3,0,4,5,6}, 12);
        tr.client_tcp_options_len = 12;
        if (!d2k_trigger_allows_poison(&tr, &ps[i])) fail("MD5_TS absent with client timestamp");
        tr.client_tcp_options[3] = 9;
        if (d2k_trigger_allows_poison(&tr, &ps[i])) fail("MD5_TS accepted malformed timestamp");
        tr.client_tcp_options_len = 0;
    }
    if (found != 1 || legacy != 1) fail("expected one distinct MD5_TS and preserved legacy MD5 (%d/%d)", found, legacy);
}

int main(void)
{
    {
        /* §0.1 (поле 07.10.2026): вопрос «метка времени» шлёт подделку с одной
           только сдвинутой меткой; без признания её подделкой зонд слал
           обычное приветствие, и «проход» был ложным. */
        d2k_poison ts;
        memset(&ts, 0, sizeof ts);
        ts.tcp_ts = 1;
        if (!d2k_poison_has_fake(&ts)) { fail("подделка с одной меткой времени не признана подделкой"); }
    }

    {
        int n, applicable6 = 0, ipv4_only = 0;
        const d2k_poison *poisons = d2k_poisons(&n);
        for (int i = 0; i < n; i++) {
            if (!d2k_poison_supports_family(&poisons[i], 4))
                fail("IPv4 lost donor hypothesis %s", poisons[i].name);
            int supported6 = d2k_poison_supports_family(&poisons[i], 6);
            if (supported6 == !!poisons[i].ip_id_zero)
                fail("IPv6 applicability wrong for %s", poisons[i].name);
            applicable6 += supported6;
            ipv4_only += !!poisons[i].ip_id_zero;
        }
        if (!ipv4_only || applicable6 + ipv4_only != n)
            fail("family filtering did not exercise IPv4-only IPID");
    }
    printf("перенос: инварианты без сети\n");
    test_md5ts_hypothesis_context();
    test_no_duplicate_hypotheses();
    test_repeats_reach_the_strategy();
    test_fooling_flags_reach_the_strategy();
    test_distinct_poisons_give_distinct_strategies();
    test_named_primitives_carry_their_flags();
    test_disorder_pos2_candidate_is_measured_and_exported();
    test_checksum_verdict_never_inferred_from_silence();
    test_stale_rule_recognition_is_exact();
    test_rst_rule_owner_and_staleness();
    test_split_offsets_ignores_out_of_range_cuts();
    test_raw_trigger_parses_and_rejects_garbage();
    test_compose_follows_the_vector();
    if (fails) {
        printf("перенос: ПРОВАЛОВ %d\n", fails);
        return 1;
    }
    printf("перенос: все проверки прошли\n");
    return 0;
}
