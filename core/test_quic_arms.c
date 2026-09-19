/* test_quic_arms.c — задача 6: подбор исполнимого плеча QUIC из измеренного.
 *
 * Проверяется в ТРИ РАЗНЫЕ СТОРОНЫ, той же дисциплиной, что и test_quicprobe.c
 * (см. его шапку):
 *
 * 1. ДИСЦИПЛИНА ЛЕСТНИЦЫ ЦЕНЫ (порядок блоб -> TTL -> фрагментация, единогласие
 *    на подтверждении, честный "не задано" при исчерпании бюджета/пула адресов,
 *    метка) — через подмену d2k_quic_ask_hook/d2k_quic_ask_ttl_hook/
 *    d2k_quic_ask_frag_hook/d2k_quic_resolve_hook. Без сети и без раздумий о
 *    том, помогает ли конкретный блоб конкретной коробке, — это вопрос
 *    измерения на линии, не этого теста (см. предупреждение в
 *    d2k_quicprobe.h у d2k_quic_pick_arm).
 * 2. СБОРКА ФРАГМЕНТОВ (d2k_quic_build_frag2) — чистая проверка байтов:
 *    контрольная сумма IP-заголовка каждого фрагмента и совпадение
 *    восстановленной пересборки с исходной датаграммой. Сумма считается
 *    СВОИМ кодом теста, а не переиспользованием проверяемой функции — иначе
 *    тест сверяет модуль с самим собой (тот же принцип, что для BADSUM в
 *    задаче 3, d2k_quicprobe.h).
 * 3. РЕАЛЬНЫЙ TTL НА ПРОВОДЕ (loopback, IP_RECVTTL) — то, что реально можно
 *    проверить без цензора на пути: приманка действительно уходит с
 *    запрошенным TTL, а сам триггер — обычным. Смерть приманки НЕ ДО сервера
 *    этот стенд доказать не может (на loopback нет промежуточных прыжков) —
 *    и не должен: см. предупреждение в комментарии у d2k_quic_pick_arm.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE /* IP_TTL/IP_RECVTTL/INADDR_LOOPBACK на macOS — тот же приём, что в props.c */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_crypto.h"
#include "d2k_meas.h"
#include "d2k_compose.h"
#include "d2k_plantlv.h"
#include "d2k_quicprobe.h"
/* d2k_quic_is_initial — им проверяется, что снятые приманки доехали в бинарник
   именно приветствиями, а не чем попало (см. test_blob_catalogue_is_captured). */
#include "d2k_quic.h"
/* Настоящий Initial из RFC 9001, приложение A.2 — тот же вектор, что у
   test_quichello/test_sched. Нужен затем, что приманка теперь ВЫВОДИТСЯ из
   снятого приветствия: выдуманные двадцать байт не пересобираются, и подбор
   честно отказал бы ещё до первого опыта. */
#include "test_quic_vector.h"

static int fails;
#define CHECK(cond, msg)                          \
    do {                                           \
        if (!(cond)) {                             \
            printf("ПРОВАЛ: %s\n", (msg));         \
            fails++;                               \
        }                                          \
    } while (0)

/* =========================================================================
 * Часть 1: дисциплина лестницы цены — моки трёх оракулов и резолвера.
 * ========================================================================= */

static d2k_quic_ask_fn real_ask_hook;
static d2k_quic_ask_ttl_fn real_ask_ttl_hook;
static d2k_quic_ask_copies_fn real_ask_copies_hook;
static d2k_quic_ask_frag_fn real_ask_frag_hook;
static d2k_quic_resolve_fn real_resolve_hook;

/* -- мок d2k_quic_ask_hook (одиночная фальшивка без TTL / подтверждение) -- */
static int g_ask_calls;
static char g_ask_last_addr[D2K_QUIC_ADDR_LEN];
static int g_ask_repeats_log[8];
/* Повторы ПОСЛЕДНЕГО обращения. Отдельно от лога на восемь ячеек: каталог
   приманок вырос, и подтверждение давно уезжает за его пределы — лог ловил
   бы чужую ячейку и молчал об этом. */
static int g_ask_last_repeats;
static uint32_t g_ask_mark_seen;
static int g_ask_pass_single;    /* 1 — одиночная приманка проходит */
static int g_ask_confirm_ok = 1; /* единогласие на подтверждении (repeats>1) */

/* Приманка у подбора одна и ВЫВЕДЕННАЯ. Мок не сверяет её с каталогом —
   каталога нет, — а проверяет, что ему дали именно выведенную: настоящий
   Initial, в котором стоит имя приманки, а не имя цели. */
#define TEST_DECOY_SNI "disk.rzd.ru"
static int decoy_is_derived(const uint8_t *prefix, size_t prefix_len) {
    char sni[256];
    if (!prefix || prefix_len == 0) { return 0; }
    if (!d2k_quic_is_initial(prefix, prefix_len)) { return 0; }
    if (d2k_quic_sni(prefix, prefix_len, sni, sizeof sni) != 0) { return 0; }
    return strcmp(sni, TEST_DECOY_SNI) == 0;
}

static d2k_tally mock_ask(const char *addr, uint16_t port, const uint8_t *prefix, size_t prefix_len,
                           d2k_hello msg, uint32_t wait_ms, uint32_t mark, int repeats,
                           uint32_t *rtt_ms_out, int *refused_out, int *sent_out,
                           uint8_t *ttl_in_out) {
    (void)port;
    (void)msg;
    (void)wait_ms;
    if (ttl_in_out) { *ttl_in_out = 0; } /* мок сокетов не трогает: TTL взять неоткуда */
    g_ask_mark_seen = mark;
    if (addr) {
        strncpy(g_ask_last_addr, addr, sizeof g_ask_last_addr - 1);
    }
    g_ask_last_repeats = repeats;
    if (g_ask_calls < 8) {
        g_ask_repeats_log[g_ask_calls] = repeats;
    }
    g_ask_calls++;
    if (rtt_ms_out) {
        *rtt_ms_out = 0;
    }
    if (refused_out) {
        *refused_out = 0;
    }
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    if (g_ask_pass_single && decoy_is_derived(prefix, prefix_len)) {
        if (repeats <= 1) {
            t.pass = 1;
        } else {
            t.pass = g_ask_confirm_ok ? repeats : repeats - 1;
            t.fail = repeats - t.pass;
        }
    } else {
        t.fail = repeats;
    }
    if (sent_out) {
        *sent_out = repeats;
    }
    return t;
}

/* -- мок d2k_quic_ask_copies_hook (несколько копий приманки) -- */
static int g_cop_calls;
static int g_cop_pass_at = -1;   /* число копий, при котором коробка поддаётся; -1 — никогда */
static int g_cop_log[8];

static d2k_tally mock_ask_copies(const char *addr, uint16_t port, const uint8_t *prefix,
                                  size_t prefix_len, int copies, d2k_hello msg,
                                  uint32_t wait_ms, uint32_t mark, int repeats, int *sent_out) {
    (void)addr; (void)port; (void)msg; (void)wait_ms; (void)mark;
    if (g_cop_calls < 8) { g_cop_log[g_cop_calls] = copies; }
    g_cop_calls++;
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    if (copies == g_cop_pass_at && decoy_is_derived(prefix, prefix_len)) {
        t.pass = repeats <= 1 ? 1 : repeats;
    } else {
        t.fail = repeats <= 1 ? 1 : repeats;
    }
    if (sent_out) { *sent_out = repeats <= 1 ? 1 : repeats; }
    return t;
}

/* -- мок d2k_quic_ask_ttl_hook (приманка с укороченным TTL) -- */
static int g_ttl_calls;
static int g_ttl_log[300];
static int g_ttl_pass_at = -1; /* -1 — ни один TTL не помогает */
static int g_ttl_confirm_ok = 1;

static d2k_tally mock_ask_ttl(const char *addr, uint16_t port, const uint8_t *prefix, size_t prefix_len,
                               int prefix_ttl, d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                               int repeats, int *sent_out) {
    (void)addr;
    (void)port;
    (void)prefix;
    (void)prefix_len;
    (void)msg;
    (void)wait_ms;
    (void)mark;
    if (g_ttl_calls < 300) {
        g_ttl_log[g_ttl_calls] = prefix_ttl;
    }
    g_ttl_calls++;
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    if (prefix_ttl == g_ttl_pass_at) {
        if (repeats <= 1) {
            t.pass = 1;
        } else {
            t.pass = g_ttl_confirm_ok ? repeats : repeats - 1;
            t.fail = repeats - t.pass;
        }
    } else {
        t.fail = repeats;
    }
    if (sent_out) {
        *sent_out = repeats;
    }
    return t;
}

/* -- мок d2k_quic_ask_frag_hook (фрагментация) -- */
static int g_frag_calls;
static int g_frag_works = 0;
static int g_frag_confirm_ok = 1;

/* ВЫЖИВАЮТ ЛИ ФРАГМЕНТЫ НА КАНАЛЕ ВООБЩЕ. Мок отличает этот зонд от боевого
   по имени внутри: проверка выживаемости идёт на ЗАВЕДОМО ОТВЕЧАЮЩЕМ имени
   (имени приманки), а плечо — на имени цели. Отличать по счётчику вызовов
   было бы хуже: тест перестал бы ловить перестановку зондов местами. */
static int g_frag_survive_calls;
static int g_frag_survives = 1;

static d2k_tally mock_ask_frag(const char *addr, uint16_t port, d2k_hello msg, uint32_t wait_ms,
                                uint32_t mark, int repeats, int *sent_out) {
    (void)addr;
    (void)port;
    (void)wait_ms;
    (void)mark;
    if (decoy_is_derived(msg.bytes, msg.len)) {
        g_frag_survive_calls++;
        d2k_tally st;
        memset(&st, 0, sizeof st);
        st.marked = 1;
        if (g_frag_survives) { st.pass = repeats; } else { st.fail = repeats; }
        if (sent_out) { *sent_out = repeats; }
        return st;
    }
    g_frag_calls++;
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    if (g_frag_works) {
        if (repeats <= 1) {
            t.pass = 1;
        } else {
            t.pass = g_frag_confirm_ok ? repeats : repeats - 1;
            t.fail = repeats - t.pass;
        }
    } else {
        t.fail = repeats;
    }
    if (sent_out) {
        *sent_out = repeats;
    }
    return t;
}

/* -- мок резолвера: детерминированный пул для проверки "свежий адрес" -- */
static size_t g_resolve_n = 3;
static size_t mock_resolve(const char *sni, char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    (void)sni;
    static const char *addrs[] = {"10.6.6.2", "10.6.6.3", "10.6.6.4"};
    size_t n = g_resolve_n;
    if (n > sizeof addrs / sizeof addrs[0]) {
        n = sizeof addrs / sizeof addrs[0];
    }
    if (n > cap) {
        n = cap;
    }
    for (size_t i = 0; i < n; i++) {
        strncpy(out[i], addrs[i], D2K_QUIC_ADDR_LEN - 1);
    }
    return n;
}

static void mocks_reset(void) {
    g_ask_calls = 0;
    g_ask_last_repeats = 0;
    memset(g_ask_last_addr, 0, sizeof g_ask_last_addr);
    memset(g_ask_repeats_log, 0, sizeof g_ask_repeats_log);
    g_ask_mark_seen = 0;
    g_ask_pass_single = 0;
    g_ask_confirm_ok = 1;
    g_cop_calls = 0;
    memset(g_cop_log, 0, sizeof g_cop_log);
    g_cop_pass_at = -1;
    g_ttl_calls = 0;
    memset(g_ttl_log, 0, sizeof g_ttl_log);
    g_ttl_pass_at = -1;
    g_ttl_confirm_ok = 1;
    g_frag_calls = 0;
    g_frag_survive_calls = 0;
    g_frag_survives = 1;
    g_frag_works = 0;
    g_frag_confirm_ok = 1;
    g_resolve_n = 3;
    d2k_quic_budget_s = 120;
}

/* Триггер — настоящий Initial: из него выводится приманка. */
#define g_trig_bytes d2k_test_v1_initial

static void test_ladder_blob_wins(void) {
    mocks_reset();
    g_ask_pass_single = 1;
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 7);

    CHECK(a.kind == D2K_QA_BLOB, "плечо приманки должно победить, когда одиночная приманка проходит");
    CHECK(g_ttl_calls == 0, "TTL дороже блоба — не должен спрашиваться, если блоб уже победил");
    CHECK(g_frag_calls == 0, "фрагментация дороже всех — не должна спрашиваться, если блоб победил");
    /* Приманка ОДНА: один разведочный опыт плюс одно подтверждение
       единогласием — два обращения, и никакого перебора. */
    CHECK(g_ask_calls == 2, "ожидались одна одиночная попытка и одно подтверждение");
    CHECK(g_ask_last_repeats == D2K_QUIC_REPEATS,
          "подтверждение обязано идти повторами, не одиночно");
    CHECK(strcmp(g_ask_last_addr, "1.2.3.4") != 0,
          "подтверждение обязано уйти на СВЕЖИЙ адрес, а не на тот, где велась разведка");
    CHECK(g_ask_mark_seen == 7, "метка обязана дойти до оракула без изменений");
}

static void test_ladder_ttl_wins_when_no_blob_helps(void) {
    mocks_reset();
    g_ask_pass_single = 0;
    g_ttl_pass_at = 5;
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 0);

    CHECK(a.kind == D2K_QA_TTL, "если ни один блоб без TTL не помог, а TTL=5 помогает — плечо TTL");
    CHECK(a.ttl == 5, "выбранный TTL обязан быть измеренным значением развёртки, не любым другим");
    CHECK(g_ask_calls == 1, "до развёртки TTL обязана быть ровно одна одиночная попытка приманкой");
    /* 5 разведочных шагов развёртки (1,2,3,4,5, останов на первом успехе) +
       1 подтверждение повторами на найденном TTL=5. */
    CHECK(g_ttl_calls == 6, "развёртка обязана идти С НАЧАЛА (1,2,3,4,5) и остановиться на первом успехе, плюс одно подтверждение");
    for (int i = 0; i < 5; i++) {
        char buf[128];
        snprintf(buf, sizeof buf, "шаг развёртки %d обязан пробовать TTL=%d, а не перепрыгивать", i, i + 1);
        CHECK(g_ttl_log[i] == i + 1, buf);
    }
    CHECK(g_ttl_log[5] == 5, "подтверждение обязано идти на ТОМ ЖЕ TTL, что и разведка, не на любом другом");
    CHECK(g_frag_calls == 0, "фрагментация не нужна, если развёртка TTL уже нашла рабочее значение");
}

/* ЧИСЛО КОПИЙ — отдельная ось, и она идёт ДО развёртки TTL: две точки против
   двухсот пятидесяти пяти. Донор ставит её так же (arms.go:117-150), и замер
   12.09 показал, зачем: instagram берётся ТОЛЬКО одиннадцатью копиями quic5,
   одиночные копии всех блобов дают 0/3. */
static void test_ladder_copies_before_ttl(void) {
    mocks_reset();
    g_ask_pass_single = 0;          /* одиночной копией не берётся ни один блоб */
    g_ttl_pass_at = 5;             /* TTL помог бы, но до него дойти не должно */
    g_cop_pass_at = D2K_QUIC_COPIES_A;
    
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 0);

    CHECK(a.kind == D2K_QA_COPIES,
          "плечо с числом копий не названо своим видом — воздействие выдано за одиночную приманку");
    CHECK(a.copies == D2K_QUIC_COPIES_A,
          "число копий в результате не то, которым коробка поддалась");

    CHECK(g_cop_log[0] == D2K_QUIC_COPIES_A,
          "лестница копий обязана начинаться с меньшей точки");
    CHECK(g_ttl_calls == 0,
          "развёртка TTL пошла раньше лестницы копий — дорогая ось обогнала дешёвую");
}

/* Вторая точка лестницы достигается, если первой не хватило. */
static void test_ladder_copies_second_point(void) {
    mocks_reset();
    g_ask_pass_single = 0;
    g_ttl_pass_at = -1;
    g_cop_pass_at = D2K_QUIC_COPIES_B;
    
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 0);

    CHECK(a.kind == D2K_QA_COPIES, "вторая точка лестницы не сработала");
    CHECK(a.copies == D2K_QUIC_COPIES_B, "число копий не совпало со второй точкой");

}

static void test_ladder_frag_is_last_resort(void) {
    mocks_reset();
    g_ask_pass_single = 0;
    g_ttl_pass_at = -1; /* ни один TTL до потолка протокола (255) не помогает */
    g_frag_works = 1;
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 0);

    CHECK(a.kind == D2K_QA_FRAG, "если ни блоб, ни TTL не помогли — последнее и самое дорогое средство: фрагментация");
    CHECK(g_ttl_calls == 255, "развёртка обязана дойти до предела поля TTL (RFC 791 §3.1, 8 бит), не остановиться раньше без причины");
    CHECK(g_frag_calls == 2, "один одиночный зонд фрагментацией + одно подтверждение повторами");
}

/* --- ФРАГМЕНТЫ НЕ ЖИВУТ НА КАНАЛЕ: СЕМЕЙСТВО НЕ ПРЕДЛАГАТЬ -------------
 *
 * Условие корректности, а не осторожность. Если фрагменты режет CGNAT или
 * сама коробка, «не помогло» будет значить «приём убивает трафик», а не
 * «коробка собирает». Выдать такое плечо человеку — тихо сломать ему сеть, и
 * он даже не свяжет одно с другим.
 *
 * Поэтому выживаемость меряется ПЕРВОЙ и на ЗАВЕДОМО ОТВЕЧАЮЩЕМ имени: если
 * фрагментированная датаграмма не доходит даже с ним, дело не в коробке. */
static void test_frag_not_offered_when_fragments_die(void) {
    mocks_reset();
    g_ask_pass_single = 0;
    g_ttl_pass_at = -1;
    g_frag_survives = 0;  /* фрагменты режет сам канал */
    g_frag_works = 1;     /* и «помогли» бы, если бы дошли */
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 0);

    CHECK(g_frag_survive_calls > 0, "выживаемость фрагментов не проверялась вовсе");
    CHECK(a.kind != D2K_QA_FRAG,
          "фрагментация предложена на канале, где фрагменты не доживают, — это не обход, а потеря трафика");
    CHECK(g_frag_calls == 0, "боевой зонд фрагментацией ушёл, хотя канал её не пропускает");
    CHECK(a.frag_survives == D2K_PROP_NO, "свойство «фрагменты доходят» не записано");
    CHECK(strstr(a.reason, "фрагмент") != NULL,
          "причина обязана назвать канал, а не выдать молчание за «приём не помог»");
}

/* Выживаемость ПРОВЕРЕНА и подтверждена — плечо предлагается как раньше, и
   свойство записано. Обратная половина той же проверки: без неё «не
   предлагать никогда» тоже прошло бы. */
static void test_frag_offered_when_fragments_live(void) {
    mocks_reset();
    g_ask_pass_single = 0;
    g_ttl_pass_at = -1;
    g_frag_survives = 1;
    g_frag_works = 1;
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 0);

    CHECK(a.kind == D2K_QA_FRAG, "фрагменты доходят и плечо помогает — оно обязано быть предложено");
    CHECK(a.frag_survives == D2K_PROP_YES, "свойство «фрагменты доходят» не записано");
}

static void test_nothing_works_is_honest_not_found(void) {
    mocks_reset();
    g_ask_pass_single = 0;
    g_ttl_pass_at = -1;
    g_frag_works = 0;
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 0);

    CHECK(a.kind == D2K_QA_NOT_FOUND, "если весь каталог исчерпан без единого прохода — честный отрицательный результат");
    CHECK(a.probes > 0, "отрицательный результат обязан отчитаться, сколько опытов он стоил");
}

static void test_confirm_disagreement_is_flaky_not_escalation(void) {
    mocks_reset();
    g_ask_pass_single = 1;
    g_ask_confirm_ok = 0; /* одиночная попытка прошла, повторы разошлись */
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 0);

    CHECK(a.kind == D2K_QA_FLAKY, "расхождение на подтверждении — FLAKY, а не округление в удобную сторону");
    CHECK(g_ttl_calls == 0, "разошедшееся подтверждение НЕ повод пробовать более дорогое плечо вместо честного FLAKY");
    CHECK(g_frag_calls == 0, "то же для фрагментации");
}

static void test_confirm_needs_fresh_address_honestly(void) {
    mocks_reset();
    g_ask_pass_single = 1;
    g_resolve_n = 0; /* пул исчерпан — кроме исходного ip, свежих адресов нет */
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 0);

    CHECK(a.kind == D2K_QA_NOT_FOUND,
          "разведка нашла блоб, но подтвердить не на чем (пул адресов пуст) — незадан, а не удача");
    /* Разведка останавливается на прошедшем блобе; ВАЖНО здесь другое: сколько
       бы попыток ни было, подтверждения СРЕДИ НИХ быть не должно (см. следующую
       проверку) — тратить опыт на заведомо провальное подтверждение (пул
       пуст) незачем. */
    CHECK(g_ask_calls == 1, "разведка обязана уложиться в одну попытку: приманка одна");
    CHECK(g_ask_repeats_log[0] == 1,
          "подтверждение НЕ ДОЛЖНО тайком уйти на разведанный (потенциально уже отравленный) адрес — "
          "единственный вызов обязан остаться одиночной разведкой (repeats=1), не превратиться в "
          "подтверждение");
}

static void test_budget_exhausted_is_honest(void) {
    mocks_reset();
    g_ask_pass_single = 0;
    d2k_quic_budget_s = 0; /* исчерпан ДО первого же опыта */
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, trig, 0);

    CHECK(a.kind == D2K_QA_NOT_FOUND, "бюджет 0 — честный отказ, не притворство, что что-то измерили");
    CHECK(g_ask_calls == 0, "при нулевом бюджете не должно уйти ни одного опыта");
    CHECK(strstr(a.reason, "бюджет") != NULL, "причина обязана называть бюджет по имени, а не молчать");
    d2k_quic_budget_s = 120;
}

static void test_structural_guard_rejects_bad_input(void) {
    mocks_reset();
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_hello empty = {NULL, 0};

    d2k_quic_arm a1 = d2k_quic_pick_arm("999.999.999.999", 443, "example.com", TEST_DECOY_SNI, trig, 0);
    CHECK(a1.kind == D2K_QA_FLAKY, "адрес, не разбирающийся как IPv4, — структурно непригодный вход");
    CHECK(g_ask_calls == 0, "структурно непригодный вход не тратит ни одного опыта");

    mocks_reset();
    d2k_quic_arm a2 = d2k_quic_pick_arm("1.2.3.4", 443, NULL, TEST_DECOY_SNI, trig, 0);
    CHECK(a2.kind == D2K_QA_FLAKY, "отсутствие имени — тоже структурно непригодный вход");

    mocks_reset();
    d2k_quic_arm a3 = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", TEST_DECOY_SNI, empty, 0);
    CHECK(a3.kind == D2K_QA_FLAKY, "отсутствие снимка триггера — измерять нечем");
    CHECK(g_ask_calls == 0, "без снимка триггера не отправляется ни один опыт");
}

/* =========================================================================
 * Часть 2: сборка фрагментов — чистая проверка байтов, без сокетов.
 * ========================================================================= */

/* Тот же алгоритм RFC 1071, но СВОЙ, тестовый — модуль не должен проверять
   себя своей же арифметикой (см. шапку файла и BADSUM в d2k_quicprobe.h). */
static uint16_t test_ip_checksum(const uint8_t *hdr, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint32_t)hdr[i] << 8) | hdr[i + 1];
    }
    if (len & 1) {
        sum += (uint32_t)hdr[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static void test_frag_builder_correctness(void) {
    uint8_t payload[64];
    for (size_t i = 0; i < sizeof payload; i++) {
        payload[i] = (uint8_t)(0x30 + i);
    }
    uint32_t src = htonl(0x0A060601u); /* 10.6.6.1 */
    uint32_t dst = htonl(0x0A060602u); /* 10.6.6.2 */
    uint8_t f1[D2K_QUIC_FRAG_MAX], f2[D2K_QUIC_FRAG_MAX];
    size_t f1len = 0, f2len = 0;

    size_t total = d2k_quic_build_frag2(payload, sizeof payload, src, dst, 55000, 443, 0xBEEF, 64, f1,
                                         &f1len, f2, &f2len);

    CHECK(total > 0, "сборка двух фрагментов из корректного входа обязана удаться");
    CHECK(f1len >= 20 && f2len >= 20, "у каждого фрагмента обязан быть хотя бы IP-заголовок");

    /* IHL занимает младшие 4 бита первого байта, в 32-битных словах. */
    size_t ihl1 = (size_t)(f1[0] & 0x0F) * 4;
    size_t ihl2 = (size_t)(f2[0] & 0x0F) * 4;
    CHECK(ihl1 == 20 && ihl2 == 20, "без опций IP-заголовок обязан быть ровно 20 байт");

    uint16_t totlen1 = (uint16_t)((f1[2] << 8) | f1[3]);
    uint16_t totlen2 = (uint16_t)((f2[2] << 8) | f2[3]);
    CHECK(totlen1 == f1len, "поле total length первого фрагмента обязано совпадать с реальной длиной посылки");
    CHECK(totlen2 == f2len, "то же для второго фрагмента");

    CHECK(f1[8] == 64 && f2[8] == 64, "TTL фрагментов обязан быть тем, что попросили строить (обычный, не укороченный — это другое плечо)");

    uint16_t id1 = (uint16_t)((f1[4] << 8) | f1[5]);
    uint16_t id2 = (uint16_t)((f2[4] << 8) | f2[5]);
    CHECK(id1 == 0xBEEF && id2 == 0xBEEF, "оба фрагмента одной датаграммы обязаны нести один Identification");

    uint16_t flagsoff1 = (uint16_t)((f1[6] << 8) | f1[7]);
    uint16_t flagsoff2 = (uint16_t)((f2[6] << 8) | f2[7]);
    CHECK((flagsoff1 & 0x2000) != 0, "первый фрагмент обязан нести MF=1 — данные ещё не кончились");
    CHECK((flagsoff1 & 0x1FFF) == 0, "первый фрагмент начинается с нулевого смещения");
    CHECK((flagsoff2 & 0x2000) == 0, "второй (последний) фрагмент обязан нести MF=0");
    size_t frag_offset_bytes = (size_t)(flagsoff2 & 0x1FFF) * 8;
    CHECK(frag_offset_bytes > 0 && (frag_offset_bytes % 8) == 0,
          "смещение второго фрагмента обязано быть кратно 8 байтам (RFC 791 §3.2)");

    uint16_t csum1 = (uint16_t)((f1[10] << 8) | f1[11]);
    uint16_t csum2 = (uint16_t)((f2[10] << 8) | f2[11]);
    uint8_t hdr1_zeroed[20], hdr2_zeroed[20];
    memcpy(hdr1_zeroed, f1, 20);
    memcpy(hdr2_zeroed, f2, 20);
    hdr1_zeroed[10] = hdr1_zeroed[11] = 0;
    hdr2_zeroed[10] = hdr2_zeroed[11] = 0;
    CHECK(csum1 == test_ip_checksum(hdr1_zeroed, 20), "контрольная сумма IP-заголовка первого фрагмента обязана быть верной");
    CHECK(csum2 == test_ip_checksum(hdr2_zeroed, 20), "то же для второго фрагмента");

    /* Пересборка: первый фрагмент несёт UDP-заголовок (8 байт) + начало
       данных; второй — хвост данных, БЕЗ собственного UDP-заголовка (он
       есть только в одной копии на всю датаграмму, RFC 791). */
    uint8_t reassembled[64 + 8];
    size_t r = 0;
    memcpy(reassembled + r, f1 + ihl1 + 8, f1len - ihl1 - 8);
    r += f1len - ihl1 - 8;
    memcpy(reassembled + r, f2 + ihl2, f2len - ihl2);
    r += f2len - ihl2;
    CHECK(r == sizeof payload, "пересобранная длина обязана совпасть с исходным UDP-payload");
    CHECK(r == sizeof payload && memcmp(reassembled, payload, sizeof payload) == 0,
          "пересобранные байты обязаны побайтно совпасть с тем, что просили отправить");

    /* Контрольная сумма UDP (RFC 768) — СВОИМ кодом теста, не переиспользуя
       udp_checksum из props.c (та же причина, что и для IP выше): псевдо-
       заголовок(12) + UDP-заголовок с обнулённой суммой(8) + данные. */
    uint8_t udp_hdr[8];
    memcpy(udp_hdr, f1 + ihl1, 8);
    uint16_t claimed_udp_csum = (uint16_t)((udp_hdr[6] << 8) | udp_hdr[7]);
    udp_hdr[6] = udp_hdr[7] = 0;
    uint8_t pseudo_and_hdr[12 + 8];
    memcpy(pseudo_and_hdr, &src, 4);
    memcpy(pseudo_and_hdr + 4, &dst, 4);
    pseudo_and_hdr[8] = 0;
    pseudo_and_hdr[9] = 17; /* IPPROTO_UDP */
    uint16_t udp_len = (uint16_t)(8 + sizeof payload);
    pseudo_and_hdr[10] = (uint8_t)(udp_len >> 8);
    pseudo_and_hdr[11] = (uint8_t)(udp_len & 0xFF);
    memcpy(pseudo_and_hdr + 12, udp_hdr, 8);
    uint32_t usum = 0;
    for (size_t i = 0; i + 1 < sizeof pseudo_and_hdr; i += 2) {
        usum += ((uint32_t)pseudo_and_hdr[i] << 8) | pseudo_and_hdr[i + 1];
    }
    for (size_t i = 0; i + 1 < sizeof payload; i += 2) {
        usum += ((uint32_t)reassembled[i] << 8) | reassembled[i + 1];
    }
    while (usum >> 16) {
        usum = (usum & 0xFFFFu) + (usum >> 16);
    }
    uint16_t computed_udp_csum = (uint16_t)~usum;
    if (computed_udp_csum == 0) {
        computed_udp_csum = 0xFFFFu;
    }
    CHECK(claimed_udp_csum == computed_udp_csum,
          "контрольная сумма UDP в собранном заголовке обязана быть настоящей (RFC 768), не нулём и не мусором");
    (void)total;
}

/* =========================================================================
 * Часть 3: реальный TTL на проводе (127.0.0.1, IP_RECVTTL) — без цензора на
 * пути это не доказывает, что приманка умирает ДО сервера (промежуточных
 * прыжков на loopback нет); проверяет ровно то, что проверяемо: приманка
 * реально уходит с запрошенным TTL, а триггер — обычным, и что после отправки
 * приманки TTL сокета корректно восстанавливается.
 * ========================================================================= */

static uint8_t recv_ttl_of(int fd) {
    uint8_t buf[512];
    uint8_t ctrl[256];
    struct iovec iov = {buf, sizeof buf};
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = ctrl;
    mh.msg_controllen = sizeof ctrl;
    ssize_t n = recvmsg(fd, &mh, 0);
    if (n < 0) {
        return 0xFF; /* часовой: "не пришло" — вызывающий тест сам сверится по числу байт снаружи */
    }
    /* Единственный запрошенный ancillary-тип — IP_RECVTTL, второго не будет,
       поэтому достаточно CMSG_FIRSTHDR без обхода CMSG_NXTHDR: её
       реализация в musl (см. cross-сборку через zig, aarch64-linux-musl)
       сравнивает знаковое с беззнаковым внутри самого макроса — предупреждение
       о чужом заголовке, не о коде этого файла, обходить через цикл незачем,
       когда в цикле и так только один элемент. */
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    if (c != NULL) {
        /* Проверено репродукцией на машине разработки (macOS): ancillary-
           данные о принятом TTL приходят с cmsg_type == IP_RECVTTL (24), а
           НЕ IP_TTL (4) — расхождение с Linux, где cmsg_type для этих же
           данных равен IP_TTL. Принимаем оба, а не гадаем один. */
        if (c->cmsg_level == IPPROTO_IP && (c->cmsg_type == IP_TTL || c->cmsg_type == IP_RECVTTL)) {
            return *(uint8_t *)CMSG_DATA(c);
        }
    }
    return 0xFF;
}

static void test_real_ttl_hook_on_wire(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0, "стенд обязан открыть UDP-сокет");
    if (fd < 0) {
        return;
    }
    int on = 1;
    CHECK(setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof on) == 0,
          "стенд обязан включить IP_RECVTTL, иначе TTL проверить нечем");
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    CHECK(bind(fd, (struct sockaddr *)&a, sizeof a) == 0, "стенд обязан забиндиться на 127.0.0.1");
    socklen_t alen = sizeof a;
    getsockname(fd, (struct sockaddr *)&a, &alen);
    uint16_t port = ntohs(a.sin_port);

    static const uint8_t prefix[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    d2k_hello msg = {g_trig_bytes, sizeof g_trig_bytes};
    int sent = 0;
    d2k_tally t =
        d2k_quic_ask_ttl_hook("127.0.0.1", port, prefix, sizeof prefix, 5, msg, 300, 0, 1, &sent);
    (void)t;
    CHECK(sent == 1, "реальный оракул TTL обязан реально отправить единственную запрошенную попытку");

    struct pollfd pfd = {fd, POLLIN, 0};
    CHECK(poll(&pfd, 1, 500) > 0, "приманка обязана дойти по loopback");
    uint8_t ttl_prefix = recv_ttl_of(fd);
    CHECK(ttl_prefix == 5, "приманка обязана реально уйти с запрошенным TTL=5, а не с обычным");

    CHECK(poll(&pfd, 1, 500) > 0, "триггер обязан дойти по loopback вторым пакетом");
    uint8_t ttl_trigger = recv_ttl_of(fd);
    CHECK(ttl_trigger != 5, "TTL сокета обязан быть ВОССТАНОВЛЕН перед отправкой триггера — иначе он тоже "
                            "уйдёт укороченным и рискует не дойти до настоящего сервера");
    close(fd);
}

/* ПОДОБРАННОЕ ПЛЕЧО ПЕРЕВОДИТСЯ В ПЛАН, И ПЛАН ЭТОТ ИСПОЛНИМ.
 *
 * До сих пор подбор плеча был вещью в себе: результат некуда было девать.
 * Проверяется три утверждения, и все три обязательны:
 *   - текст плана объявляет UDP и QUIC, а не унаследованные tcp/tls;
 *   - грамматика его принимает (d2k_plan_text_to_hex собирает TLV) — иначе
 *     «план» это строка, которую датапат отвергнет;
 *   - плечи, которые сегодня не выразимы, честно дают отказ, а не подменяются
 *     похожими (§2.5).
 */
static void test_arm_to_plan(void) {
    char plan[8192], err[200], hex[2 * D2K_PLAN_TLV_MAX + 1];
    d2k_quic_arm original = {0};
    original.original = 1; original.kind = D2K_QA_TTL;
    original.copies = 6; original.ttl = 3;
    original.len = 4; memcpy(original.bytes, "\x41\x42\x43\x44", 4);
    CHECK(d2k_quic_arm_plan(&original, original.bytes, original.len, plan, sizeof plan) == 0,
          "original fake must compose");
    CHECK(strstr(plan, "payload 1 41424344\n") != NULL, "exact original fake bytes");
    CHECK(strstr(plan, "repeats=6") != NULL, "TTL must not discard measured repeats");
    CHECK(strstr(plan, "pace ") == NULL, "original has no extra settle delay");
    CHECK(d2k_plan_text_to_hex(plan, hex, sizeof hex, err, sizeof err) == 0,
          "original plan grammar");
    original.frag_kind = 1;
    CHECK(d2k_quic_arm_plan(&original, original.bytes, original.len, plan, sizeof plan) != 0,
          "cannot silently omit found fragment combination");
    original.frag_kind = 0;
    CHECK(d2k_quic_arm_plan(&original, (const uint8_t *)"other", 5, plan, sizeof plan) != 0,
          "cannot replace original owned fake");
    /* Тело приманки — выведенное, как и в бою: то же, что подбор и увидит. */
    static uint8_t decoy[2048];
    size_t blen = 0;
    d2k_hello trg = {g_trig_bytes, sizeof g_trig_bytes};
    CHECK(d2k_quic_decoy_from_trigger(trg, TEST_DECOY_SNI, decoy, sizeof decoy, &blen) == 0,
          "приманка не вывелась из снятого приветствия");
    const uint8_t *blob = decoy;

    struct { d2k_quic_arm_kind kind; int copies; int ttl; int ok; const char *what; } c[] = {
        { D2K_QA_BLOB,      0,  0, 1, "одиночная приманка" },
        { D2K_QA_COPIES,   11,  0, 1, "одиннадцать копий" },
        { D2K_QA_TTL,       0,  3, 1, "приманка с укороченным TTL" },
        { D2K_QA_FRAG,      0,  0, 0, "фрагментация — не выразима" },
        { D2K_QA_NOT_FOUND, 0,  0, 0, "плечо не найдено — ставить нечего" },
        { D2K_QA_FLAKY,     0,  0, 0, "измерению верить нельзя" },
    };
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = c[i].kind;
        a.copies = c[i].copies;
        a.ttl = c[i].ttl;
        int rc = d2k_quic_arm_plan(&a, blob, blen, plan, sizeof plan);
        if (!c[i].ok) {
            CHECK(rc != 0, "невыразимое плечо всё-таки дало план");
            continue;
        }
        CHECK(rc == 0, "выразимое плечо не дало плана");
        CHECK(strstr(plan, "proto udp quic") != NULL,
              "план плеча QUIC объявил не тот транспорт или протокол");
        CHECK(strstr(plan, "place=before") != NULL,
              "приманка поставлена не перед правдой — между чем её ставить у датаграммы?");
        CHECK(d2k_plan_text_to_hex(plan, hex, sizeof hex, err, sizeof err) == 0,
              "грамматика не приняла план плеча QUIC");
        if (c[i].kind == D2K_QA_COPIES) {
            CHECK(strstr(plan, "repeats=11") != NULL, "число копий не доехало в план");
        }
        if (c[i].kind == D2K_QA_TTL) {
            CHECK(strstr(plan, "ttl=3") != NULL, "TTL приманки не доехал в план");
        }
    }
}


/* --- ПРИМАНКА ВЫВОДИТСЯ ИЗ ЗАМЕРА, А НЕ ВЫБИРАЕТСЯ ИЗ НАБОРА ---------------
 *
 * Здесь стоял каталог из девяти заготовок и снятых дампов, перебираемый по
 * очереди. Перебор набора — это блокчек, а не замер: длина набора влияла и на
 * цену подбора, и на бюджет, чего быть не должно.
 *
 * Приманка обязана выглядеть для коробки настоящим приветствием ЭТОГО
 * соединения. Ничего более похожего на него, чем оно само, не существует —
 * значит берётся оно, с подменённым именем. */
static void test_decoy_is_derived(void) {
    d2k_hello trg = {g_trig_bytes, sizeof g_trig_bytes};
    uint8_t out[2048];
    size_t olen = 0;
    char sni[256];

    CHECK(d2k_quic_decoy_from_trigger(trg, TEST_DECOY_SNI, out, sizeof out, &olen) == 0,
          "приманка не вывелась из снятого приветствия");
    CHECK(olen > 0 && d2k_quic_is_initial(out, olen),
          "выведенная приманка не Initial — коробка такому не поверит");
    CHECK(d2k_quic_sni(out, olen, sni, sizeof sni) == 0 && strcmp(sni, TEST_DECOY_SNI) == 0,
          "в выведенной приманке стоит не имя приманки");
    /* Имя ПОДМЕНЕНО, а не оставлено: приманка с именем цели ничего не
       отвлекает — коробка прочтёт ровно то, что и собиралась. */
    {
        char orig[256];
        if (d2k_quic_sni(g_trig_bytes, sizeof g_trig_bytes, orig, sizeof orig) == 0) {
            CHECK(strcmp(orig, sni) != 0, "приманка несёт имя цели — отвлекать нечем");
        }
    }
    /* Длина сохранена: длина — часть формы, по которой коробка отличает
       приветствие от чего угодно другого (см. d2k_quichello.h). */
    CHECK(olen == sizeof g_trig_bytes,
          "длина приманки разошлась с длиной снятого приветствия");

    /* Вывести не из чего — честный отказ, а не подстановка заготовки. */
    {
        d2k_hello empty = {NULL, 0};
        size_t n = 1;
        CHECK(d2k_quic_decoy_from_trigger(empty, TEST_DECOY_SNI, out, sizeof out, &n) != 0,
              "приманка «вывелась» из пустого снимка");
    }

    /* Цена лестницы не зависит ни от какой длины набора: набора нет. */
    CHECK(D2K_QUIC_ARM_LADDER_PROBES == 1u + 2u + D2K_QUIC_ARM_TTL_WINDOW_HI + 3u,
          "цена лестницы посчитана не по её ступеням");
}

/* --- ПЛАН ГОЛОСА: приманка перед IP Discovery --------------------------
 *
 * Та же фигура, что у плеча QUIC, — приманка отдельными датаграммами ПЕРЕД
 * первым пакетом потока, — только первый пакет другой: запрос IP Discovery
 * Дискорда. Протокол объявлен своим словом, и датапат отдаёт такой план
 * только голосу (форма D2K_PLAN_SHAPE_VOICE). Копий — десять: унаследовано у
 * боевого профиля discord_udp (strategy=1, «рабочий референс»). */
static void test_voice_plan(void) {
    uint8_t decoy[1200];
    for (size_t i = 0; i < sizeof decoy; i++) { decoy[i] = (uint8_t)(i * 7 + 1); }
    decoy[0] = 0xc3;
    char plan[8192], hex[16384], err[160];
    CHECK(d2k_voice_plan(decoy, sizeof decoy, plan, sizeof plan) == 0,
          "план голоса не собрался");
    CHECK(strstr(plan, "proto udp voice") != NULL, "план голоса объявил не свой протокол");
    CHECK(strstr(plan, "place=before") != NULL, "приманка голоса не перед правдой");
    CHECK(strstr(plan, "repeats=10") != NULL,
          "число копий не унаследовано у боевого профиля (10)");
    CHECK(strstr(plan, "c3080f") != NULL, "байты приманки не доехали в план");
    CHECK(d2k_plan_text_to_hex(plan, hex, sizeof hex, err, sizeof err) == 0,
          "грамматика не приняла план голоса");
    CHECK(d2k_voice_plan(NULL, 0, plan, sizeof plan) != 0,
          "план голоса собрался без приманки");
}

/* --- ПЛАН РАЗНОСА INITIAL-ДАТАГРАММ ------------------------------------ */
static void test_quic_delay_plan(void) {
    char plan[2048], hex[8192], err[160];
    CHECK(d2k_quic_delay_plan(plan, sizeof plan) == 0, "план разноса не собрался");
    CHECK(strstr(plan, "proto udp quic") != NULL, "план разноса объявил не тот протокол");
    CHECK(strstr(plan, "delay 15000") != NULL,
          "выдержка не унаследована у D2K_PACE_SETTLE_US");
    CHECK(strstr(plan, "payload") == NULL,
          "в плане разноса завелась приманка — резать и подменять датаграмму нечем");
    CHECK(d2k_plan_text_to_hex(plan, hex, sizeof hex, err, sizeof err) == 0,
          "грамматика не приняла план разноса");
    CHECK(d2k_quic_delay_plan(plan, 10) != 0, "план собрался в буфер на десять байт");
}

int main(void) {
    /* Сохраняем боевые крючки — они же используются другими тестами при
       линковке в один процесс (см. Makefile: test_quic_arms собирает
       quicprobe.o целиком) — подмена обязана быть временной. */
    real_ask_hook = d2k_quic_ask_hook;
    real_ask_ttl_hook = d2k_quic_ask_ttl_hook;
    real_ask_copies_hook = d2k_quic_ask_copies_hook;
    real_ask_frag_hook = d2k_quic_ask_frag_hook;
    real_resolve_hook = d2k_quic_resolve_hook;

    d2k_quic_resolve_hook = mock_resolve;

    d2k_quic_ask_hook = mock_ask;
    d2k_quic_ask_ttl_hook = mock_ask_ttl;
    d2k_quic_ask_copies_hook = mock_ask_copies;
    d2k_quic_ask_frag_hook = mock_ask_frag;

    test_ladder_blob_wins();
    test_ladder_ttl_wins_when_no_blob_helps();
    test_ladder_copies_before_ttl();
    test_decoy_is_derived();
    test_ladder_copies_second_point();
    test_ladder_frag_is_last_resort();
    test_frag_not_offered_when_fragments_die();
    test_frag_offered_when_fragments_live();
    test_nothing_works_is_honest_not_found();
    test_confirm_disagreement_is_flaky_not_escalation();
    test_confirm_needs_fresh_address_honestly();
    test_budget_exhausted_is_honest();
    test_structural_guard_rejects_bad_input();

    d2k_quic_ask_hook = real_ask_hook;
    d2k_quic_ask_ttl_hook = real_ask_ttl_hook;
    d2k_quic_ask_frag_hook = real_ask_frag_hook;
    d2k_quic_resolve_hook = real_resolve_hook;

    test_frag_builder_correctness();
    test_real_ttl_hook_on_wire();

    test_arm_to_plan();
    test_voice_plan();
    test_quic_delay_plan();

    if (fails == 0) {
        printf("плечи QUIC: все проверки прошли\n");
        return 0;
    }
    printf("плечи QUIC: %d провалов\n", fails);
    return 1;
}
