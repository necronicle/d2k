/* test_quic_arm_data.c — честный замер плеча QUIC (задача 39).
 *
 * 1. Ответ плечу засчитывается ТОЛЬКО привязанный к нашему Initial: Retry
 *    (даже с верным тегом), Version Negotiation, Initial на ключах приманки
 *    и Initial не нашему SCID — не успех. Настоящие сокеты на 127.0.0.1.
 * 2. Прошедшее фильтр плечо засчитывается, только если после рукопожатия
 *    прошло не меньше D2K_QUIC_ARM_DATA_BYTES данных: обрыв на 6 КБ — не
 *    прошло, ответ, кончившийся до порога, — «не измерено», не успех.
 * 3. Каждая попытка (повтор фильтра, плечо, этап данных) — на своём местном
 *    порту; уже выданный порт за окно остаточной блокировки не повторяется.
 *
 * -DHEAD_API собирает только то, что компилируется против кода до задачи 39
 * (для доказательства RED): там фильтр засчитывал Retry/VN, а лестница —
 * плечо без данных. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "d2k_quic.h"
#include "d2k_quichello.h"
#include "d2k_quicprobe.h"
#include "d2k_quic_arms.h"
#include "d2k_quicwire.h"
#ifndef HEAD_API
#include "d2k_meas.h"
#endif

static int fails;
#define CHECK(x, what) do { if (!(x)) { printf("FAIL %s (line %d)\n", what, __LINE__); fails++; } \
                            else { printf("ok   %s\n", what); } } while (0)

#define TARGET "arm.example"

/* --- стенд: UDP-сервер с режимами ответа ------------------------------- */

enum { M_SILENT, M_BOUND, M_RETRY, M_RETRY_BADTAG, M_RETRY_FOREIGN, M_RETRY_NOTOKEN, M_RETRY_NOSCID,
       M_RETRY_SCID_IS_DCID, M_VN, M_FAKE_KEYS, M_WRONG_CID };

#define MAX_SEEN 256
static volatile int g_mode;
static int g_fd = -1;
static uint16_t g_seen_port[MAX_SEEN];
static size_t g_seen_token[MAX_SEEN]; /* длина токена Initial (после Retry) */
static size_t g_seen_len[MAX_SEEN];
static size_t g_seen_packet_len[MAX_SEEN];
static int g_seen_zero_tail[MAX_SEEN];
static int g_seen_ours[MAX_SEEN];
static int g_seen_split[MAX_SEEN]; /* первый кадр CRYPTO с ненулевым смещением */
static volatile int g_seen_n;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Initial сервера: ключи — из key_dcid (серверная сторона), заголовок
   адресован to_dcid. Тело — ACK и PADDING. */
static size_t server_initial(const uint8_t *key_dcid, size_t key_len,
                             const uint8_t *to_dcid, size_t to_len,
                             uint8_t *out, size_t cap) {
    uint8_t secret[32];
    d2k_qw_keys k;
    if (d2k_qw_initial_secret(D2K_QW_V1, key_dcid, key_len, D2K_QW_SERVER, secret) != 0 ||
        d2k_qw_keys_from_secret(D2K_QW_V1, secret, &k) != 0) return 0;
    uint8_t body[40] = {0x02, 0x00, 0x00, 0x00, 0x00}; /* ACK 0, далее PADDING */
    static const uint8_t scid[8] = {0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e};
    uint8_t hdr[64];
    size_t hl = d2k_qw_long_hdr(hdr, sizeof hdr, D2K_QW_V1, D2K_QW_LT_INITIAL,
                                to_dcid, to_len, scid, sizeof scid, 1, sizeof body);
    if (!hl) return 0;
    return d2k_qw_seal(&k, 1, hdr, hl, 0, 1, body, sizeof body, out, cap);
}

/* Смещение первого кадра CRYPTO в клиентском Initial (-1 — не Initial или
   не раскрылся). Хвост первым — признак разреза задачи 40. */
static long first_crypto_off(const uint8_t *p, size_t n) {
    d2k_qw_hdr h;
    if (d2k_qw_hdr_parse(p, n, 0, &h) != 0 || !h.long_hdr || h.type != D2K_QW_LT_INITIAL) return -1;
    uint8_t sec[32], plain[2048];
    d2k_qw_keys k;
    size_t pl = 0;
    uint64_t pn = 0;
    if (d2k_qw_initial_secret(h.version, p + h.dcid_off, h.dcid_len, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(h.version, sec, &k) != 0 ||
        h.packet_len > sizeof plain || d2k_qw_open(&k, &h, p, 0, plain, &pl, &pn) != 0) return -1;
    size_t i = 0;
    while (i < pl && (plain[i] == 0x00 || plain[i] == 0x01)) i++;
    if (i >= pl || plain[i] != 0x06) return -1;
    uint64_t off = 0;
    size_t w = 0;
    if (d2k_qw_varint_read(plain + i + 1, pl - i - 1, &off, &w) != 0) return -1;
    return (long)off;
}

static void *stand_run(void *arg) {
    (void)arg;
    for (;;) {
        uint8_t buf[2048];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(g_fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) return NULL;
        char sni[256] = {0};
        int ours = d2k_quic_sni(buf, (size_t)n, sni, sizeof sni) == 0 && strcmp(sni, TARGET) == 0;
        pthread_mutex_lock(&g_mu);
        if (g_seen_n < MAX_SEEN) {
            g_seen_port[g_seen_n] = ntohs(from.sin_port);
            g_seen_len[g_seen_n] = (size_t)n;
            g_seen_ours[g_seen_n] = ours;
            g_seen_token[g_seen_n] = 0;
            g_seen_split[g_seen_n] = first_crypto_off(buf, (size_t)n) > 0;
            {
                d2k_qw_hdr th;
                if (d2k_qw_hdr_parse(buf, (size_t)n, 0, &th) == 0 && th.long_hdr &&
                    th.type == D2K_QW_LT_INITIAL) {
                    g_seen_token[g_seen_n] = th.token_len;g_seen_packet_len[g_seen_n]=th.packet_len;
                    g_seen_zero_tail[g_seen_n]=1;
                    for(size_t k=th.packet_len;k<(size_t)n;k++)if(buf[k])g_seen_zero_tail[g_seen_n]=0;
                }
            }
            g_seen_n++;
        }
        pthread_mutex_unlock(&g_mu);
        d2k_qw_hdr h;
        if (d2k_qw_hdr_parse(buf, (size_t)n, 0, &h) != 0 || !h.long_hdr ||
            h.type != D2K_QW_LT_INITIAL) continue;
        const uint8_t *dcid = buf + h.dcid_off, *scid = buf + h.scid_off;
        uint8_t out[1500];
        size_t ol = 0;
        static const uint8_t other[8] = {9, 9, 9, 9, 9, 9, 9, 9};
        switch (g_mode) {
        case M_BOUND:
            if (ours) ol = server_initial(dcid, h.dcid_len, scid, h.scid_len, out, sizeof out);
            break;
        case M_RETRY_NOTOKEN:
        case M_RETRY_NOSCID:
        case M_RETRY_SCID_IS_DCID:
            /* Верный тег, наш SCID, но пустой токен / пустой SCID / SCID,
               равный DCID нашего Initial — RFC 9000 §17.2.5.2: отбросить. */
            if (ours && h.token_len == 0) {
                const uint8_t *rs = g_mode == M_RETRY_SCID_IS_DCID ? dcid : other;
                size_t rsl = g_mode == M_RETRY_NOSCID ? 0
                           : g_mode == M_RETRY_SCID_IS_DCID ? h.dcid_len : sizeof other;
                size_t tl = g_mode == M_RETRY_NOTOKEN ? 0 : 3;
                ol = d2k_qw_retry_build(out, sizeof out, D2K_QW_V1, dcid, h.dcid_len,
                                        scid, h.scid_len, rs, rsl, (const uint8_t *)"tok", tl);
            }
            break;
        case M_RETRY:
        case M_RETRY_BADTAG:
        case M_RETRY_FOREIGN:
            /* Retry нашему SCID с верным тегом от нашего DCID (M_RETRY);
               с испорченным тегом; адресованный чужому CID. Отвечаем только
               на Initial без токена: Initial после Retry стенд принимает
               молча (повторный Retry клиент обязан отвергнуть). */
            if (ours && h.token_len == 0) {
                int foreign = g_mode == M_RETRY_FOREIGN;
                ol = d2k_qw_retry_build(out, sizeof out, D2K_QW_V1, dcid, h.dcid_len,
                                        foreign ? other : scid, foreign ? sizeof other : h.scid_len,
                                        other, sizeof other, (const uint8_t *)"tok", 3);
                if (ol && g_mode == M_RETRY_BADTAG) out[ol - 1] ^= 0x01;
            }
            break;
        case M_VN:
            if (ours) {
                size_t o = 0;
                out[o++] = 0x80; out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 0;
                out[o++] = (uint8_t)h.scid_len; memcpy(out + o, scid, h.scid_len); o += h.scid_len;
                out[o++] = (uint8_t)h.dcid_len; memcpy(out + o, dcid, h.dcid_len); o += h.dcid_len;
                out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 1;
                ol = o;
            }
            break;
        case M_FAKE_KEYS:
            /* Сервер отвечает ПРИМАНКЕ (не нашему Initial): её ключи, её CID. */
            if (!ours) ol = server_initial(dcid, h.dcid_len, scid, h.scid_len, out, sizeof out);
            break;
        case M_WRONG_CID:
            /* Наши ключи, но адресован не нашему SCID. */
            if (ours) ol = server_initial(dcid, h.dcid_len, other, sizeof other, out, sizeof out);
            break;
        default:
            break;
        }
        if (ol) (void)sendto(g_fd, out, ol, 0, (struct sockaddr *)&from, fl);
    }
}

static uint16_t stand_start(void) {
    g_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    if (g_fd < 0 || bind(g_fd, (struct sockaddr *)&a, sizeof a) != 0) return 0;
    socklen_t al = sizeof a;
    if (getsockname(g_fd, (struct sockaddr *)&a, &al) != 0) return 0;
    pthread_t t;
    if (pthread_create(&t, NULL, stand_run, NULL) != 0) return 0;
    pthread_detach(t);
    return ntohs(a.sin_port);
}

static void seen_reset(void) {
    pthread_mutex_lock(&g_mu);
    g_seen_n = 0;
    pthread_mutex_unlock(&g_mu);
}

static d2k_quic_arm_question quic5_question(void) {
    d2k_quic_arm_question q;
    memset(&q, 0, sizeof q);
    q.label = "фальшивка quic5";
    q.addr = "127.0.0.1";
    q.blob = d2k_quic_original_blob(0, &q.blob_len, NULL);
    q.copies = 2;
    return q;
}

/* --- 1. только привязанный к нашему Initial ответ -------------------------- */

static void test_bound_replies_only(uint16_t port) {
    static const struct { int mode; int want; const char *what; } cases[] = {
        {M_BOUND, 3, "привязанный Initial: плечо проходит фильтр 3/3 (стенд исправен)"},
        {M_RETRY, 3, "Retry нашему SCID с верным тегом от нашего DCID проходит фильтр"},
        {M_RETRY_BADTAG, 0, "Retry с неверным тегом не проходит фильтр"},
        {M_RETRY_FOREIGN, 0, "Retry чужому CID не проходит фильтр"},
        {M_RETRY_NOTOKEN, 0, "Retry с пустым токеном не проходит фильтр (RFC 9000 §17.2.5.2)"},
        {M_RETRY_NOSCID, 0, "Retry с пустым SCID не проходит фильтр"},
        {M_RETRY_SCID_IS_DCID, 0, "Retry, чей SCID равен DCID нашего Initial, не проходит фильтр"},
        {M_VN, 0, "Version Negotiation не делает плечо успешным"},
        {M_FAKE_KEYS, 0, "ответ на приманку (её ключи и CID) не засчитывается"},
        {M_WRONG_CID, 0, "Initial на наших ключах, но не нашему SCID, не засчитывается"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        g_mode = cases[i].mode;
        d2k_quic_arm_question q = quic5_question();
        int sent = 0;
        d2k_tally t = d2k_quic_ask_arm_hook(&q, TARGET, port, 150, 0, &sent);
        if (t.pass != cases[i].want) printf("     pass=%d sent=%d\n", t.pass, sent);
        CHECK(sent == 3 && t.pass == cases[i].want, cases[i].what);
    }
}

/* --- 2. лестница: плечо, прошедшее фильтр, без данных — не плечо ---------- */

static void test_ladder_handshake_without_data(uint16_t port) {
    /* Стенд отвечает привязанным Initial и на фильтр, и на первый Initial
       этапа данных, но рукопожатия не ведёт: прежде это было плечо 3/3. */
    g_mode = M_BOUND;
    uint8_t trig[1500];
    size_t tl = 0;
    if (d2k_quic_probe_initial(TARGET, trig, sizeof trig, &tl) != 0) {
        CHECK(0, "триггер собран");
        return;
    }
    static const char pool[1][D2K_QUIC_ADDR_LEN] = {"127.0.0.1"};
    d2k_quic_arm_context c;
    memset(&c, 0, sizeof c);
    c.pool = pool; c.n_pool = 1; c.marked = 1;
    d2k_hello trigger = {trig, tl, NULL, 0, 0, 0}, control = {NULL, 0, NULL, 0, 0, 0};
    d2k_quic_arm r = d2k_quic_original_measure(&c, port, trigger, control, 100, 0);
    int filter_passes = 0;
    for (size_t i = 0; i < r.n_trace; i++) {
        if (r.trace[i].answered == D2K_QUIC_REPEATS) filter_passes++;
    }
    CHECK(filter_passes > 0, "фильтр плеч проходит (сервер отвечает на наш Initial)");
    CHECK(r.kind != D2K_QA_COPIES && r.kind != D2K_QA_TTL && r.kind != D2K_QA_BLOB,
          "ответ на Initial без рукопожатия и данных не делает плечо найденным");
#ifndef HEAD_API
    int no_hs = 0, other = 0;
    for (size_t i = 0; i < r.n_trace; i++) {
        if (r.trace[i].data == D2K_QAD_NO_HANDSHAKE) no_hs++;
        else if (r.trace[i].data != 0) other++;
    }
    CHECK(no_hs > 0 && other == 0,
          "прошедшее фильтр плечо доведено до этапа данных: рукопожатия нет");
#endif
}

#ifndef HEAD_API
/* --- 2б. судья и лестница с подменённым этапом данных -------------------- */

static void test_judge(void) {
    d2k_qw_ranges r;
    /* Полный короткий ответ: FIN, все байты 0..3000 — прошло. */
    d2k_qw_ranges_reset(&r);
    d2k_qw_ranges_add(&r, 1000, 2000, 1);
    d2k_qw_ranges_add(&r, 0, 1000, 0);
    CHECK(d2k_qw_ranges_complete(&r) && d2k_qw_ranges_bytes(&r) == 3000, "FIN и все байты до него — ответ целиком");
    CHECK(d2k_quic_arm_data_judge(1, 200, d2k_qw_ranges_bytes(&r), d2k_qw_ranges_complete(&r)) == D2K_QAD_PASS,
          "полный короткий ответ (3 КБ) — прошло");
    /* Дыра перед FIN — не целиком, ниже порога — обрыв. */
    d2k_qw_ranges_reset(&r);
    d2k_qw_ranges_add(&r, 0, 1000, 0);
    d2k_qw_ranges_add(&r, 2000, 1000, 1);
    CHECK(!d2k_qw_ranges_complete(&r) && d2k_qw_ranges_bytes(&r) == 2000, "дыра перед FIN — ответ не целиком");
    CHECK(d2k_quic_arm_data_judge(1, 200, d2k_qw_ranges_bytes(&r), d2k_qw_ranges_complete(&r)) == D2K_QAD_CUT,
          "дыра перед FIN — не прошло");
    /* Поток встал на 6 КБ без FIN — обрыв. */
    d2k_qw_ranges_reset(&r);
    for (uint64_t off = 0; off < 6144; off += 1024) d2k_qw_ranges_add(&r, off, 1024, 0);
    d2k_qw_ranges_add(&r, 0, 1024, 0); /* повтор не считается дважды */
    CHECK(d2k_qw_ranges_bytes(&r) == 6144 && r.n == 1, "повтор кадра не раздувает счёт");
    CHECK(d2k_quic_arm_data_judge(1, 200, d2k_qw_ranges_bytes(&r), d2k_qw_ranges_complete(&r)) == D2K_QAD_CUT,
          "рукопожатие есть, поток встал на 6 КБ без FIN — не прошло");
    CHECK(d2k_quic_arm_data_judge(1, 200, D2K_QUIC_ARM_DATA_BYTES, 0) == D2K_QAD_PASS,
          "не меньше порога без FIN — прошло");
    CHECK(d2k_quic_arm_data_judge(1, 200, D2K_QUIC_ARM_DATA_BYTES - 1, 0) == D2K_QAD_CUT,
          "на байт меньше порога без FIN — обрыв");
    CHECK(d2k_quic_arm_data_judge(0, 200, 100000, 1) == D2K_QAD_NO_HANDSHAKE,
          "без рукопожатия данных не бывает");
    /* Пустой поток с FIN — не ответ; без HEADERS нет ответа — правило
       плеча совпадает с проверкой плана (verify.c ждёт код ответа). */
    d2k_qw_ranges_reset(&r);
    d2k_qw_ranges_add(&r, 0, 0, 1);
    CHECK(!d2k_qw_ranges_complete(&r), "пустой поток с FIN — не ответ целиком");
    CHECK(d2k_quic_arm_data_judge(1, 0, 3000, 1) == D2K_QAD_CUT,
          "полный поток без заголовков HTTP/3 — не прошло (как у проверки плана)");
    CHECK(d2k_quic_arm_data_judge(1, 0, D2K_QUIC_ARM_DATA_BYTES, 0) == D2K_QAD_CUT,
          "порог данных без заголовков — не прошло");
    CHECK(d2k_quic_arm_data_judge(1, 451, 3000, 1) == D2K_QAD_CUT,
          "HTTP 451 — отказ, не успех плеча");
    /* Задача 44: заголовки длиннее нашего буфера — не измеренный обрыв. */
    CHECK(d2k_quic_arm_data_judge_limited(1, 0, 70000, 0, 1) == D2K_QAD_NOT_RUN,
          "заголовки не поместились в наш буфер — этап не проведён, не CUT");
    CHECK(d2k_quic_arm_data_judge_limited(1, 0, 3000, 0, 0) == D2K_QAD_CUT,
          "без признака предела пустые заголовки по-прежнему обрыв");
    CHECK(d2k_quic_arm_data_judge_limited(1, 200, 40000, 0, 1) == D2K_QAD_PASS,
          "разобранные заголовки признак предела не отменяет");
    CHECK(d2k_quic_arm_data_judge_limited(0, 0, 0, 0, 1) == D2K_QAD_NO_HANDSHAKE,
          "без рукопожатия предел заголовков ничего не меняет");
    CHECK(D2K_QUIC_ARM_DATA_BYTES >= 16384 && D2K_QUIC_ARM_DATA_BYTES <= 32768,
          "порог в пределах 16–32 КБ");
}

static int g_calls, g_data_calls;
static d2k_quic_arm_data_verdict g_data_verdict;
static uint32_t g_spent;

static d2k_tally all_pass(const d2k_quic_arm_question *q, void *u, int *sent) {
    (void)q; (void)u;
    g_calls++;
    d2k_tally t = {0};
    t.marked = 1; t.pass = 3; *sent = 3;
    return t;
}

static d2k_quic_arm_data fixed_data(const d2k_quic_arm_question *q, void *u) {
    (void)q; (void)u;
    g_data_calls++;
    d2k_quic_arm_data d;
    memset(&d, 0, sizeof d);
    d.verdict = g_data_verdict;
    d.app_bytes = g_data_verdict == D2K_QAD_PASS ? 3000 : 6144;
    return d;
}

static void spent(void *u, uint32_t ms) { (void)u; g_spent += ms + 1; }

static void test_ladder_with_data_stage(void) {
    static const char pool[1][D2K_QUIC_ADDR_LEN] = {"127.0.0.1"};
    d2k_quic_arm_context c;
    memset(&c, 0, sizeof c);
    c.pool = pool; c.n_pool = 1; c.marked = 1;
    c.probe = all_pass; c.data = fixed_data; c.spent = spent;

    g_data_verdict = D2K_QAD_CUT; g_calls = g_data_calls = 0; g_spent = 0;
    d2k_quic_arm r = d2k_quic_original_arms(&c);
    CHECK(r.kind == D2K_QA_NOT_FOUND || r.kind == D2K_QA_FRAG,
          "все плечи 3/3, но поток оборван после 6 КБ — фальшивка не выбрана");
    CHECK(r.len == 0, "фальшивка оборванного плеча в план не попала");
    CHECK(g_data_calls > 0 && g_data_calls == g_calls - 1,
          "этап данных — у каждого прошедшего фильтр плеча, кроме контроля фрагментов");
    CHECK(g_spent >= (uint32_t)g_data_calls, "время этапа данных продлевает бюджет Run");
    int cut_steps = 0;
    for (size_t i = 0; i < r.n_trace; i++) cut_steps += r.trace[i].data == D2K_QAD_CUT;
    CHECK(cut_steps == g_data_calls, "трасса несёт исход этапа данных");

    g_data_verdict = D2K_QAD_PASS; g_calls = g_data_calls = 0;
    r = d2k_quic_original_arms(&c);
    CHECK(r.kind == D2K_QA_COPIES && r.copies == 1 && !r.ttl &&
          r.len == 1200 && strcmp(r.blob_name, "quic5") == 0 &&
          g_calls == 1 && g_data_calls == 1,
          "первое плечо с прошедшим этапом данных завершает поиск");

    c.data = NULL;
    g_calls = g_data_calls = 0;
    r = d2k_quic_original_arms(&c);
    CHECK(r.kind == D2K_QA_COPIES && r.copies == 1 && r.len == 1200 &&
          !strcmp(r.blob_name, "quic5") && g_calls == 1 && !g_data_calls,
          "без этапа данных (только юнит-оракул) — остановка на первом ответе");
}

/* --- 3. свежая четвёрка -------------------------------------------------- */

static int all_distinct(const uint16_t *p, int n) {
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (p[i] == p[j]) return 0;
    return 1;
}

static void test_fresh_ports(uint16_t port) {
    g_mode = M_SILENT;
    seen_reset();
    d2k_quic_arm_question q = quic5_question();
    int sent = 0;
    (void)d2k_quic_ask_arm_hook(&q, TARGET, port, 60, 0, &sent);
    (void)d2k_quic_ask_arm_hook(&q, TARGET, port, 60, 0, &sent);
    d2k_quic_arm_data d = d2k_quic_arm_data_hook(&q, TARGET, NULL, port, 60, 0);
    {
        struct timespec nap = {0, 50000000L};
        (void)nanosleep(&nap, NULL);
    }
    CHECK(d.verdict == D2K_QAD_NO_HANDSHAKE, "этап данных без ответа: Initial ушёл, рукопожатия нет");
    uint16_t ports[16];
    int np = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_seen_n && np < 16; i++) {
        if (!g_seen_ours[i]) continue;
        /* Повторы Initial по таймеру в одном соединении — тот же порт. */
        int dup = 0;
        for (int j = 0; j < np; j++) dup |= ports[j] == g_seen_port[i];
        if (!dup) ports[np++] = g_seen_port[i];
    }
    int data_prefix = 0, data_initial_at = -1;
    for (int i = 0; i < g_seen_n; i++) {
        if (g_seen_port[i] != d.local_port) continue;
        if (g_seen_ours[i]) { if (data_initial_at < 0) data_initial_at = data_prefix; }
        else if (data_initial_at < 0) data_prefix++;
    }
    pthread_mutex_unlock(&g_mu);
    CHECK(np == 7, "семь попыток с нашим Initial: 2×3 повтора фильтра и этап данных");
    CHECK(all_distinct(ports, np), "каждый повтор, каждое плечо и этап данных — свой местный порт");
    if (data_prefix != 2 || data_initial_at != 2) printf("     port=%u prefix=%d initial_at=%d\n", d.local_port, data_prefix, data_initial_at);
    CHECK(d.local_port != 0 && data_prefix == 2 && data_initial_at == 2,
          "этап данных: 2 копии приманки перед первым Initial на той же четвёрке");

    /* Учёт выданных портов: свежий записывается, повторный отвергается. */
    d2k_udp_port_forget_all();
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(0x7f000001); a.sin_port = htons(port);
    int okc = s >= 0 && connect(s, (struct sockaddr *)&a, sizeof a) == 0;
    CHECK(okc && d2k_udp_port_claim(s) == 0, "свежий порт записан за зондом");
    CHECK(okc && d2k_udp_port_claim(s) == 1, "тот же порт за окно остаточной блокировки отвергнут");
    if (s >= 0) close(s);
    CHECK(D2K_UDP_RESIDUAL_MS >= 420000u, "окно не короче 420 с остаточной блокировки");
}
#endif

/* Retry, прошедший фильтр, ведёт этап данных: d2k_qc идёт за его токеном
   на той же свежей четвёрке. Стенд второй Retry не шлёт и рукопожатия не
   ведёт — исход «рукопожатия нет», но Initial с токеном обязан уйти. */
static void test_data_stage_follows_retry(uint16_t port) {
    g_mode = M_RETRY;
    seen_reset();
    d2k_quic_arm_question q = quic5_question();
    d2k_quic_arm_data d = d2k_quic_arm_data_hook(&q, TARGET, "/big.css", port, 100, 0);
    struct timespec nap = {0, 50000000L};
    (void)nanosleep(&nap, NULL);
    int plain = 0, with_token = 0, decoys_before = 0, decoys_after_retry = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_seen_n; i++) {
        if (g_seen_port[i] != d.local_port) continue;
        if (!g_seen_ours[i]) {
            if (with_token || plain) decoys_after_retry++; else decoys_before++;
            continue;
        }
        if (g_seen_token[i] == 3) with_token++; else if (g_seen_token[i] == 0) plain++;
    }
    pthread_mutex_unlock(&g_mu);
    /* Датапат (session.c) пропускает Initial потока с уже применённым
       планом как есть — и Initial после Retry тоже. Плечо обязано мерить то
       же: воздействие только перед первым Initial. */
    CHECK(decoys_before == 2 && decoys_after_retry == 0,
          "после Retry Initial с токеном уходит без воздействия, как в датапате");
    CHECK(strstr(d.note, "после Retry Initial без воздействия") != NULL,
          "трасса говорит, что Initial после Retry без воздействия");
    CHECK(d.local_port && plain >= 1 && with_token >= 1,
          "этап данных идёт за верным Retry: Initial с его токеном на той же четвёрке");
    CHECK(d.verdict == D2K_QAD_NO_HANDSHAKE, "Retry без рукопожатия плечо не засчитывает");
    CHECK(strstr(d.note, "d2k_qc") && strstr(d.note, "/big.css"),
          "трасса этапа: каким приветствием и по какому пути");
}

#ifndef HEAD_API
/* --- задача 40: вопросы стратегии на проводе ----------------------------- */

static void test_strategy_questions_on_wire(uint16_t port) {
    g_mode = M_BOUND;
    /* Разрез CRYPTO: три свежих Initial, у каждого хвост первым, сервер
       собирает имя и отвечает на НАШ Initial. */
    seen_reset();
    d2k_quic_arm_question q;
    memset(&q, 0, sizeof q);
    q.label = "разрез CRYPTO"; q.addr = "127.0.0.1"; q.split = 1;
    int sent = 0;
    d2k_tally t = d2k_quic_ask_arm_hook(&q, TARGET, port, 150, 0, &sent);
    struct timespec nap = {0, 50000000L};
    (void)nanosleep(&nap, NULL);
    int ours = 0, split = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_seen_n; i++) { ours += g_seen_ours[i]; split += g_seen_ours[i] && g_seen_split[i]; }
    pthread_mutex_unlock(&g_mu);
    CHECK(sent == 3 && t.pass == 3, "разрез CRYPTO: сервер собирает имя и отвечает 3/3");
    CHECK(ours == 3 && split == 3, "разрез CRYPTO: каждый Initial фильтра — хвостом первым");

    /* Этап данных разреза: первый Initial соединения разрезан, тем же
       кодом, что у датапата. */
    seen_reset();
    d2k_quic_arm_data d = d2k_quic_arm_data_hook(&q, TARGET, NULL, port, 100, 0);
    (void)nanosleep(&nap, NULL);
    int first_split = -1;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_seen_n; i++) {
        if (g_seen_port[i] == d.local_port && g_seen_ours[i]) { first_split = g_seen_split[i]; break; }
    }
    pthread_mutex_unlock(&g_mu);
    CHECK(d.local_port && first_split == 1, "этап данных: первый Initial соединения разрезан");
    CHECK(d.verdict == D2K_QAD_NO_HANDSHAKE, "этап данных разреза: стенд без рукопожатия — не прошло");

    /* Adaptive fake x split: same eleven prefixes before the reshaped
       Initial on all three filter ports and on the data-stage port. */
    q.blob=d2k_quic_original_blob(3,&q.blob_len,NULL); q.copies=11;
    seen_reset();
    t=d2k_quic_ask_arm_hook(&q,TARGET,port,150,0,&sent);
    (void)nanosleep(&nap,NULL);
    CHECK(sent==3 && t.pass==3, "fake x split filter must run 3/3");
    int good=0;
    pthread_mutex_lock(&g_mu);
    for(int i=0;i<g_seen_n;i++) if(g_seen_ours[i]) {
        int prefixes=0;
        for(int j=0;j<i;j++) if(g_seen_port[j]==g_seen_port[i] && g_seen_len[j]==620) prefixes++;
        good += prefixes==11 && g_seen_split[i];
    }
    pthread_mutex_unlock(&g_mu);
    CHECK(good==3,"fake x split: exact prefixes and CRYPTO order on filter wire");
    seen_reset();
    d=d2k_quic_arm_data_hook(&q,TARGET,NULL,port,100,0);
    (void)nanosleep(&nap,NULL);
    good=0;
    pthread_mutex_lock(&g_mu);
    for(int i=0;i<g_seen_n;i++) if(g_seen_port[i]==d.local_port && g_seen_ours[i]) {
        int prefixes=0;
        for(int j=0;j<i;j++) if(g_seen_port[j]==d.local_port && g_seen_len[j]==620) prefixes++;
        good=prefixes==11 && g_seen_split[i]; break;
    }
    pthread_mutex_unlock(&g_mu);
    CHECK(good,"fake x split: same question on data-stage wire");

    /* Остаточное разрешение: ровно одна безобидная датаграмма, затем Initial
       на той же четвёрке — и в фильтре, и на этапе данных. */
    memset(&q, 0, sizeof q);
    q.label = "разрешение"; q.addr = "127.0.0.1"; q.benign = 1;
    q.blob = d2k_quic_benign; q.blob_len = D2K_QUIC_BENIGN_LEN; q.copies = 1;
    seen_reset();
    t = d2k_quic_ask_arm_hook(&q, TARGET, port, 150, 0, &sent);
    CHECK(sent == 3 && t.pass == 3, "разрешение: фильтр 3/3 на привязанный ответ");
    /* Круг 1 (M3a): и в фильтре безобидная датаграмма и Initial — одна
       четвёрка: на каждом порту ровно одна 16-байтная датаграмма, затем наш
       Initial; порты попыток разные. */
    (void)nanosleep(&nap, NULL);
    {
        uint16_t fp[8];
        int nfp = 0, good = 0;
        pthread_mutex_lock(&g_mu);
        for (int i = 0; i < g_seen_n && nfp < 8; i++) {
            if (!g_seen_ours[i]) continue;
            int benign_before = 0;
            for (int j = 0; j < i; j++)
                if (g_seen_port[j] == g_seen_port[i] && !g_seen_ours[j] &&
                    g_seen_len[j] == D2K_QUIC_BENIGN_LEN) benign_before++;
            if (benign_before == 1) good++;
            fp[nfp++] = g_seen_port[i];
        }
        pthread_mutex_unlock(&g_mu);
        CHECK(nfp == 3 && good == 3 && all_distinct(fp, nfp),
              "разрешение, фильтр: на каждой свежей четвёрке одна безобидная датаграмма, затем Initial");
    }
    seen_reset();
    d = d2k_quic_arm_data_hook(&q, TARGET, NULL, port, 100, 0);
    (void)nanosleep(&nap, NULL);
    int before = 0, at = -1;
    size_t blen = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_seen_n; i++) {
        if (g_seen_port[i] != d.local_port) continue;
        if (g_seen_ours[i]) { at = before; break; }
        before++; blen = g_seen_len[i];
    }
    pthread_mutex_unlock(&g_mu);
    CHECK(d.local_port && at == 1 && before == 1 && blen == D2K_QUIC_BENIGN_LEN,
          "разрешение: одна безобидная датаграмма 16 байт, затем Initial той же четвёрки");
}
#endif

static void test_length_runtime(uint16_t port){
    uint8_t initial[4096];size_t n=0;
    CHECK(!d2k_quic_probe_initial(TARGET,initial,sizeof initial,&n),"length input builds");
    g_mode=M_BOUND;g_seen_n=0;int sent=0;
    d2k_tally t=d2k_quic_ask_longer_hook("127.0.0.1",port,NULL,0,(d2k_hello){initial, n, NULL, 0, 0, 0},
        400,0,3,NULL,NULL,&sent,NULL);
    CHECK(t.pass==3 && sent==3,"runtime length question receives bound replies 3/3");
    pthread_mutex_lock(&g_mu);
    CHECK(g_seen_n==3,"length sends one datagram per fresh flow");
    for(int i=0;i<g_seen_n;i++)CHECK(g_seen_len[i]==n+100 && g_seen_packet_len[i]==n && g_seen_zero_tail[i],
        "length question appends100 outside Initial, exactly as installed Plan");
    pthread_mutex_unlock(&g_mu);
}

int main(void) {
    int old_local = d2k_quic_allow_local;
    d2k_quic_allow_local = 1;
    uint16_t port = stand_start();
    if (!port) { puts("FAIL stand"); return 1; }
    test_length_runtime(port);
    test_bound_replies_only(port);
    test_ladder_handshake_without_data(port);
#ifndef HEAD_API
    test_judge();
    test_ladder_with_data_stage();
    test_fresh_ports(port);
    test_data_stage_follows_retry(port);
    test_strategy_questions_on_wire(port);
#endif
    d2k_quic_allow_local = old_local;
    if (fails) { printf("test_quic_arm_data: %d FAIL\n", fails); return 1; }
    puts("test_quic_arm_data: all passed");
    return 0;
}
