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
#include "d2k_quicprobe.h"

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
static d2k_quic_ask_frag_fn real_ask_frag_hook;
static d2k_quic_resolve_fn real_resolve_hook;

/* -- мок d2k_quic_ask_hook (одиночная фальшивка без TTL / подтверждение) -- */
static int g_ask_calls;
static char g_ask_last_addr[D2K_QUIC_ADDR_LEN];
static int g_ask_repeats_log[8];
static uint32_t g_ask_mark_seen;
static int g_ask_pass_blob = -1; /* -1 — ни один блоб не проходит одиночно */
static int g_ask_confirm_ok = 1; /* единогласие на подтверждении (repeats>1) */

static int blob_index_of(const uint8_t *prefix, size_t prefix_len) {
    for (size_t i = 0; i < D2K_QUIC_ARM_N_BLOBS; i++) {
        size_t blen;
        const uint8_t *b = d2k_quic_arm_blob(i, &blen);
        if (b && blen == prefix_len && (prefix_len == 0 || memcmp(b, prefix, prefix_len) == 0)) {
            return (int)i;
        }
    }
    return -1;
}

static d2k_tally mock_ask(const char *addr, uint16_t port, const uint8_t *prefix, size_t prefix_len,
                           d2k_hello msg, uint32_t wait_ms, uint32_t mark, int repeats,
                           uint32_t *rtt_ms_out, int *refused_out, int *sent_out) {
    (void)port;
    (void)msg;
    (void)wait_ms;
    g_ask_mark_seen = mark;
    if (addr) {
        strncpy(g_ask_last_addr, addr, sizeof g_ask_last_addr - 1);
    }
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
    int blob = blob_index_of(prefix, prefix_len);
    if (blob == g_ask_pass_blob) {
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

static d2k_tally mock_ask_frag(const char *addr, uint16_t port, d2k_hello msg, uint32_t wait_ms,
                                uint32_t mark, int repeats, int *sent_out) {
    (void)addr;
    (void)port;
    (void)msg;
    (void)wait_ms;
    (void)mark;
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
    memset(g_ask_last_addr, 0, sizeof g_ask_last_addr);
    memset(g_ask_repeats_log, 0, sizeof g_ask_repeats_log);
    g_ask_mark_seen = 0;
    g_ask_pass_blob = -1;
    g_ask_confirm_ok = 1;
    g_ttl_calls = 0;
    memset(g_ttl_log, 0, sizeof g_ttl_log);
    g_ttl_pass_at = -1;
    g_ttl_confirm_ok = 1;
    g_frag_calls = 0;
    g_frag_works = 0;
    g_frag_confirm_ok = 1;
    g_resolve_n = 3;
    d2k_quic_budget_s = 120;
}

static const uint8_t g_trig_bytes[20] = {0xC0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0xAA, 0xAA, 0xAA, 0xAA};

static void test_ladder_blob_wins(void) {
    mocks_reset();
    g_ask_pass_blob = (int)D2K_QUIC_ARM_BLOB_SHAPED;
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", trig, 7);

    CHECK(a.kind == D2K_QA_BLOB, "блоб-плечо должно победить, когда одиночная фальшивка проходит");
    CHECK(a.blob_id == D2K_QUIC_ARM_BLOB_SHAPED, "выбран именно прошедший блоб, не первый по счёту");
    CHECK(g_ttl_calls == 0, "TTL дороже блоба — не должен спрашиваться, если блоб уже победил");
    CHECK(g_frag_calls == 0, "фрагментация дороже всех — не должна спрашиваться, если блоб победил");
    /* Ровно два одиночных зонда (по одному на блоб, второй сразу проходит) плюс
       одно подтверждение единогласием — три обращения к d2k_quic_ask_hook. */
    CHECK(g_ask_calls == 3, "ожидались 2 одиночных попытки блобов + 1 подтверждение");
    CHECK(g_ask_repeats_log[2] == D2K_QUIC_REPEATS, "подтверждение обязано идти повторами, не одиночно");
    CHECK(strcmp(g_ask_last_addr, "1.2.3.4") != 0,
          "подтверждение обязано уйти на СВЕЖИЙ адрес, а не на тот, где велась разведка");
    CHECK(g_ask_mark_seen == 7, "метка обязана дойти до оракула без изменений");
}

static void test_ladder_ttl_wins_when_no_blob_helps(void) {
    mocks_reset();
    g_ask_pass_blob = -1;
    g_ttl_pass_at = 5;
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", trig, 0);

    CHECK(a.kind == D2K_QA_TTL, "если ни один блоб без TTL не помог, а TTL=5 помогает — плечо TTL");
    CHECK(a.ttl == 5, "выбранный TTL обязан быть измеренным значением развёртки, не любым другим");
    CHECK(g_ask_calls == (int)D2K_QUIC_ARM_N_BLOBS, "все блобы должны быть перепробованы дёшево, прежде чем перейти к TTL");
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

static void test_ladder_frag_is_last_resort(void) {
    mocks_reset();
    g_ask_pass_blob = -1;
    g_ttl_pass_at = -1; /* ни один TTL до потолка протокола (255) не помогает */
    g_frag_works = 1;
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", trig, 0);

    CHECK(a.kind == D2K_QA_FRAG, "если ни блоб, ни TTL не помогли — последнее и самое дорогое средство: фрагментация");
    CHECK(g_ttl_calls == 255, "развёртка обязана дойти до предела поля TTL (RFC 791 §3.1, 8 бит), не остановиться раньше без причины");
    CHECK(g_frag_calls == 2, "один одиночный зонд фрагментацией + одно подтверждение повторами");
}

static void test_nothing_works_is_honest_not_found(void) {
    mocks_reset();
    g_ask_pass_blob = -1;
    g_ttl_pass_at = -1;
    g_frag_works = 0;
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", trig, 0);

    CHECK(a.kind == D2K_QA_NOT_FOUND, "если весь каталог исчерпан без единого прохода — честный отрицательный результат");
    CHECK(a.probes > 0, "отрицательный результат обязан отчитаться, сколько опытов он стоил");
}

static void test_confirm_disagreement_is_flaky_not_escalation(void) {
    mocks_reset();
    g_ask_pass_blob = (int)D2K_QUIC_ARM_BLOB_GARBAGE;
    g_ask_confirm_ok = 0; /* одиночная попытка прошла, повторы разошлись */
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", trig, 0);

    CHECK(a.kind == D2K_QA_FLAKY, "расхождение на подтверждении — FLAKY, а не округление в удобную сторону");
    CHECK(g_ttl_calls == 0, "разошедшееся подтверждение НЕ повод пробовать более дорогое плечо вместо честного FLAKY");
    CHECK(g_frag_calls == 0, "то же для фрагментации");
}

static void test_confirm_needs_fresh_address_honestly(void) {
    mocks_reset();
    g_ask_pass_blob = (int)D2K_QUIC_ARM_BLOB_GARBAGE;
    g_resolve_n = 0; /* пул исчерпан — кроме исходного ip, свежих адресов нет */
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", trig, 0);

    CHECK(a.kind == D2K_QA_NOT_FOUND,
          "разведка нашла блоб, но подтвердить не на чем (пул адресов пуст) — незадан, а не удача");
    /* D2K_QUIC_ARM_BLOB_GARBAGE стоит первым в каталоге и сразу проходит —
       разведка останавливается на одной попытке; ВАЖНО здесь другое: сколько
       бы их ни было, подтверждения СРЕДИ НИХ быть не должно (см. следующую
       проверку) — тратить опыт на заведомо провальное подтверждение (пул
       пуст) незачем. */
    CHECK(g_ask_calls == 1, "разведка обязана остановиться на первом прошедшем блобе");
    CHECK(g_ask_repeats_log[0] == 1,
          "подтверждение НЕ ДОЛЖНО тайком уйти на разведанный (потенциально уже отравленный) адрес — "
          "единственный вызов обязан остаться одиночной разведкой (repeats=1), не превратиться в "
          "подтверждение");
}

static void test_budget_exhausted_is_honest(void) {
    mocks_reset();
    g_ask_pass_blob = -1;
    d2k_quic_budget_s = 0; /* исчерпан ДО первого же опыта */
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_quic_arm a = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", trig, 0);

    CHECK(a.kind == D2K_QA_NOT_FOUND, "бюджет 0 — честный отказ, не притворство, что что-то измерили");
    CHECK(g_ask_calls == 0, "при нулевом бюджете не должно уйти ни одного опыта");
    CHECK(strstr(a.reason, "бюджет") != NULL, "причина обязана называть бюджет по имени, а не молчать");
    d2k_quic_budget_s = 120;
}

static void test_structural_guard_rejects_bad_input(void) {
    mocks_reset();
    d2k_hello trig = {g_trig_bytes, sizeof g_trig_bytes};
    d2k_hello empty = {NULL, 0};

    d2k_quic_arm a1 = d2k_quic_pick_arm("999.999.999.999", 443, "example.com", trig, 0);
    CHECK(a1.kind == D2K_QA_FLAKY, "адрес, не разбирающийся как IPv4, — структурно непригодный вход");
    CHECK(g_ask_calls == 0, "структурно непригодный вход не тратит ни одного опыта");

    mocks_reset();
    d2k_quic_arm a2 = d2k_quic_pick_arm("1.2.3.4", 443, NULL, trig, 0);
    CHECK(a2.kind == D2K_QA_FLAKY, "отсутствие имени — тоже структурно непригодный вход");

    mocks_reset();
    d2k_quic_arm a3 = d2k_quic_pick_arm("1.2.3.4", 443, "example.com", empty, 0);
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

int main(void) {
    /* Сохраняем боевые крючки — они же используются другими тестами при
       линковке в один процесс (см. Makefile: test_quic_arms собирает
       quicprobe.o целиком) — подмена обязана быть временной. */
    real_ask_hook = d2k_quic_ask_hook;
    real_ask_ttl_hook = d2k_quic_ask_ttl_hook;
    real_ask_frag_hook = d2k_quic_ask_frag_hook;
    real_resolve_hook = d2k_quic_resolve_hook;

    d2k_quic_resolve_hook = mock_resolve;

    d2k_quic_ask_hook = mock_ask;
    d2k_quic_ask_ttl_hook = mock_ask_ttl;
    d2k_quic_ask_frag_hook = mock_ask_frag;

    test_ladder_blob_wins();
    test_ladder_ttl_wins_when_no_blob_helps();
    test_ladder_frag_is_last_resort();
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

    if (fails == 0) {
        printf("плечи QUIC: все проверки прошли\n");
        return 0;
    }
    printf("плечи QUIC: %d провалов\n", fails);
    return 1;
}
