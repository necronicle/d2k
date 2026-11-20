/* Этап 53: правила точного кортежа — argv, идемпотентность, откат пары, снятие, уборка. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "d2k_lwrules.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s\n", (m)); fails++; } } while (0)

/* Подменённый iptables: таблица правил по строке спецификации; сбои по сценарию. */
static char rules[64][512];
static int n_rules, calls;
/* Дубль правила стенда. Источник и приёмник — строки одного массива: gcc
   (-Wrestrict) не доказывает, что это разные строки, — копия через локальный
   буфер. */
static void dup_rule(int from) {
    char one[sizeof rules[0]];
    memcpy(one, rules[from], sizeof one);
    snprintf(rules[n_rules], sizeof rules[0], "%s", one); n_rules++;
}
static char log_[64][600];
static int fail_add_in, fail_delete, fail_check_code;
static void spec_of(char *const argv[], char *o, size_t cap, const char **op, const char **tool) {
    *tool = argv[0]; *op = "?"; o[0] = 0;
    for (int i = 1; argv[i]; i++) {
        if (!strcmp(argv[i], "-A") || !strcmp(argv[i], "-D") || !strcmp(argv[i], "-C") ||
            !strcmp(argv[i], "-N") || !strcmp(argv[i], "-F")) { *op = argv[i]; continue; }
        if (!strcmp(argv[i], "-w") || !strncmp(argv[i], "--wait=", 7)) continue;
        size_t n = strlen(o); snprintf(o + n, cap - n, "%s ", argv[i]);
    }
    size_t n = strlen(o); snprintf(o + n, cap - n, "[%s]", *tool);
}
static int old_iptables;   /* до 1.6: --wait=N не знает (код 2) */
static int saw_wait_eq, saw_plain_w, saw_split_w;
static int fake_run(void *ctx, char *const argv[]) {
    (void)ctx;
    for (int i = 1; argv[i]; i++) {
        if (!strncmp(argv[i], "--wait=", 7)) { saw_wait_eq++; if (old_iptables) return 2; }
        if (!strcmp(argv[i], "-w")) { if (argv[i + 1] && argv[i + 1][0] >= '0' && argv[i + 1][0] <= '9') saw_split_w++; else saw_plain_w++; }
    }
    char spec[512]; const char *op, *tool;
    spec_of(argv, spec, sizeof spec, &op, &tool);
    if (calls < 64) snprintf(log_[calls], sizeof log_[0], "%s %s", op, spec);
    calls++;
    int found = -1;
    for (int i = 0; i < n_rules; i++) if (!strcmp(rules[i], spec)) found = i;
    if (!strcmp(op, "-C")) return fail_check_code ? fail_check_code : found >= 0 ? 0 : 1;
    if (!strcmp(op, "-A")) {
        if (fail_add_in && strstr(spec, "REPLY")) return 4;
        snprintf(rules[n_rules++], sizeof rules[0], "%s", spec);
        return 0;
    }
    if (!strcmp(op, "-D")) {
        if (fail_delete) return 4;
        if (found < 0) return 1;
        memmove(rules[found], rules[found + 1], sizeof rules[0] * (size_t)(n_rules - found - 1));
        n_rules--;
        return 0;
    }
    if (!strcmp(op, "-F")) { n_rules = 0; return 0; }
    return 0;   /* -N */
}
static void reset(void) { n_rules = calls = fail_add_in = fail_delete = fail_check_code = 0; }
static int has(const char *needle) { for (int i = 0; i < n_rules; i++) if (strstr(rules[i], needle)) return 1; return 0; }
static int logged(const char *needle) { for (int i = 0; i < calls && i < 64; i++) if (strstr(log_[i], needle)) return 1; return 0; }

int main(void) {
    d2k_lwrules r = {"D2K_LATE_OUT", "D2K_LATE_IN", 2037, 5, 0, fake_run, NULL};
    d2k_ct_tuple t; memset(&t, 0, sizeof t);
    t.family = 4; t.proto = 6; t.src[0] = 192; t.src[1] = 168; t.src[2] = 1; t.src[3] = 67;
    t.dst[0] = 10; t.dst[1] = 207; t.dst[2] = 1; t.dst[3] = 2;
    t.sport_be[0] = 0xa4; t.sport_be[1] = 0x16; t.dport_be[0] = 0x01; t.dport_be[1] = 0xbb;   /* 42006 → 443 */

    /* 1. Пара правил по исходному кортежу conntrack, обе стороны, своя очередь. */
    reset();
    CHECK(d2k_lwrules_install(&r, &t) == 0 && n_rules == 2, "пара правил не поставлена");
    CHECK(has("D2K_LATE_OUT -t") || has("mangle D2K_LATE_OUT"), "правило не в своей цепочке OUT");
    CHECK(has("--ctdir ORIGINAL --ctproto tcp --ctorigsrc 192.168.1.67 --ctorigdst 10.207.1.2 --ctorigsrcport 42006 "
              "--ctorigdstport 443") && has("--ctdir REPLY"), "кортеж или направления правил неверны");
    CHECK(has("-j NFQUEUE --queue-num 2037 --queue-bypass [iptables]"), "очередь/обход/инструмент правил неверны");
    /* Идемпотентно: повтор установки не дублирует. */
    CHECK(d2k_lwrules_install(&r, &t) == 0 && n_rules == 2, "повторная установка задвоила правила");

    /* 2. IPv6 — ip6tables. */
    reset();
    d2k_ct_tuple t6 = t; t6.family = 6; memset(t6.src, 0, 16); memset(t6.dst, 0, 16);
    t6.src[0] = 0x20; t6.src[1] = 0x01; t6.src[15] = 0x67; t6.dst[0] = 0x20; t6.dst[1] = 0x01; t6.dst[15] = 2; t6.proto = 17;
    CHECK(d2k_lwrules_install(&r, &t6) == 0 && has("--ctproto udp --ctorigsrc 2001::67 --ctorigdst 2001::2") &&
          has("[ip6tables]"), "IPv6 UDP: инструмент или адреса неверны");

    /* 3. Частичная пара: вторая сторона не встала — откат первой, сбой. */
    reset();
    fail_add_in = 1;
    CHECK(d2k_lwrules_install(&r, &t) == -1 && n_rules == 0, "частичная пара оставлена или названа успехом");
    /* Откат тоже не удался — неясно (FAIL), правило осталось — снимет снятие. */
    reset();
    fail_add_in = 1; fail_delete = 1;
    CHECK(d2k_lwrules_install(&r, &t) == -1 && n_rules == 1, "неудачный откат: итог не FAIL");
    fail_add_in = 0; fail_delete = 0;
    CHECK(d2k_lwrules_clear(&r, &t) == 0 && n_rules == 0, "снятие после неудачного отката не убрало остаток");

    /* 4. Снятие: задвоенное правило снимается целиком; нечего — GONE; сбой — FAIL. */
    reset();
    d2k_lwrules_install(&r, &t);
    dup_rule(0);                                                                   /* дубль OUT */
    CHECK(d2k_lwrules_clear(&r, &t) == 0 && n_rules == 0, "дубль правила остался после снятия");
    CHECK(d2k_lwrules_clear(&r, &t) == 1, "снятие без правил не GONE");
    d2k_lwrules_install(&r, &t);
    fail_delete = 1;
    CHECK(d2k_lwrules_clear(&r, &t) == -1 && n_rules == 2, "сбой снятия не FAIL");
    fail_delete = 0;
    fail_check_code = 4;
    CHECK(d2k_lwrules_clear(&r, &t) == -1, "сбой проверки (блокировка) принят за «правила нет»");
    fail_check_code = 0;

    /* 4б. Девять копий каждой стороны (больше прохода): снятие — не успех,
           пока остаток есть; повтор дочищает (находка ревью). */
    reset();
    d2k_lwrules_install(&r, &t);
    for (int k = 0; k < 8; k++) {
        dup_rule(0);
        dup_rule(1);
    }
    CHECK(n_rules == 18, "стенд: 9 копий каждой стороны");
    CHECK(d2k_lwrules_clear(&r, &t) == -1 && n_rules > 0, "остаток правил после прохода назван успешным снятием");
    {
        int rc = -1, passes = 1;
        while (rc == -1 && passes < 6) { rc = d2k_lwrules_clear(&r, &t); passes++; if (rc == -1) CHECK(n_rules > 0, "сбой при пустой таблице"); }
        CHECK(rc == 0 && n_rules == 0 && passes <= 4, "повторы снятия не дочистили остаток за несколько проходов");
    }

    /* 4в. Настоящий запуск: несуществующая программа — сбой, не зависание. */
    {
        char *argv[] = {(char *)"/nonexistent/d2k-iptables", NULL};
        CHECK(d2k_lwrules_spawn(NULL, argv) == -1 || d2k_lwrules_spawn(NULL, argv) == 127,
              "запуск несуществующей программы не дал сбоя");
        unsigned dl = 1;
        char *sl[] = {(char *)"sleep", (char *)"10", NULL};
        struct timespec a0, a1; clock_gettime(CLOCK_MONOTONIC, &a0);
        int rc = d2k_lwrules_spawn(&dl, sl);
        clock_gettime(CLOCK_MONOTONIC, &a1);
        CHECK(rc == -1 && a1.tv_sec - a0.tv_sec < 4, "внешний срок потомка не сработал (ждал бы старый iptables без конца)");
        char *tr[] = {(char *)"true", NULL};
        char *fa[] = {(char *)"false", NULL};
        CHECK(d2k_lwrules_spawn(NULL, tr) == 0 && d2k_lwrules_spawn(NULL, fa) == 1, "код выхода потомка потерян");
    }

    /* 4г. Срок ожидания блокировки xtables — только слитной формой --wait=N:
           «-w 5» раздельно iptables не считает сроком (ждал бы без конца). Старый
           iptables (без --wait=N, код 2) — простое -w. */
    reset(); saw_wait_eq = saw_plain_w = saw_split_w = 0; old_iptables = 0;
    { d2k_lwrules r2 = r; d2k_lwrules_install(&r2, &t);
      CHECK(saw_wait_eq > 0 && saw_split_w == 0, "срок блокировки передан раздельным «-w N» (не учитывается)"); }
    reset(); saw_wait_eq = saw_plain_w = saw_split_w = 0; old_iptables = 1;
    { d2k_lwrules r3 = r; r3.wait_form = 0;
      CHECK(d2k_lwrules_install(&r3, &t) == 0 && saw_plain_w > 0 && n_rules == 2,
            "старый iptables без --wait=N: не перешли на простое -w"); }
    old_iptables = 0;

    /* 5. Уборка: свои цепочки обоих семейств очищаются, чужих не трогает. */
    reset();
    d2k_lwrules_install(&r, &t);
    CHECK(d2k_lwrules_sweep(&r) == 0 && n_rules == 0, "уборка не очистила свои цепочки");
    CHECK(logged("-F mangle D2K_LATE_OUT [iptables]") || logged("-F -t mangle D2K_LATE_OUT"), "уборка: OUT v4 не очищена");
    CHECK(logged("[ip6tables]"), "уборка: IPv6 не очищена");
    CHECK(!logged("D2K_OUT ") && !logged("D2K_IN "), "уборка тронула чужие цепочки");

    puts(fails ? "правила точного кортежа: ЕСТЬ ПРОВАЛЫ" : "правила точного кортежа: все проверки прошли");
    return fails ? 1 : 0;
}
