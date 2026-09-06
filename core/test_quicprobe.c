/* test_quicprobe.c — вопросник по QUIC проверяется в ДВЕ РАЗНЫЕ СТОРОНЫ,
 * умышленно разными средствами:
 *
 * 1. ДИСЦИПЛИНА ДЕРЕВА (порядок вопросов, УСЛОВНАЯ ротация адреса — только
 *    после обнаружения остаточной блокировки, бюджет, учёт метки и приём
 *    "N из K" на каждом шаге, "незаданный, а не проваленный") — через
 *    подмену d2k_quic_ask_hook. Причина не лень: чтобы честно проверить
 *    ротацию, нужно НЕСКОЛЬКО РАЗЛИЧИМЫХ адресов назначения, а bind() на
 *    127.0.0.x при x≠1 без явного алиаса интерфейса на macOS падает с "Can't
 *    assign requested address" (проверено эмпирически) — настоящий
 *    многоадресный стенд здесь непереносим. Мок ДОПОЛНИТЕЛЬНО умеет
 *    форсировать ЛЮБОЙ d2k_tally (частичный результат, ошибку транспорта,
 *    непровтверждённую метку) на конкретный вызов через очередь — без этого
 *    учёт метки и приём "2 из 3" на шагах 2-4 не доказаны ничем, кроме
 *    честного слова (см. находку 4 ревью 2026-09-06, круг 2: шесть мутаций
 *    ревьюера прошли зелёными именно потому, что обычная, детерминированная
 *    по содержимому модель стенда не умела ни того, ни другого).
 *
 * 2. САМ ОРАКУЛ (шифрование, аутентичность и ПРОГРЕСС рукопожатия в ответе,
 *    реальный ICMP при закрытом порте, согласование версии, реальные часы
 *    бюджета) — НАСТОЯЩИМИ сокетами на единственном настоящем адресе
 *    127.0.0.1. Стенд честно шифрует ответ (AES-128-GCM, "server in") —
 *    d2k_ghash_for_test здесь уместен ПО ПРЯМОМУ НАЗНАЧЕНИЮ (см. d2k_crypto.h:
 *    "не для общего пользования" — про продакшен-код, не про тестовый стенд).
 *
 * Так дисциплина дерева проверяется без сетевых допущений, а оракул — без
 * подмены сети.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
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

/* ---------------------------------------------------------------------
 * Снимки: минимально валидные заголовки Initial v1. Тело после заголовка
 * для НАШИХ отправляемых снимков не обязано разбираться как ClientHello:
 * quicprobe.c не расшифровывает то, что сам отправляет — только извлекает
 * DCID (см. шапку quicprobe.c). DCID у триггера и контроля РАЗНЫЙ, чтобы
 * стенд из части 2 мог вывести им разные ключи.
 * --------------------------------------------------------------------- */

static size_t build_plain_initial(uint8_t dcid_byte, uint8_t *out, size_t cap) {
    uint8_t dcid[8];
    memset(dcid, dcid_byte, sizeof dcid);
    if (cap < 5 + 1 + 8 + 1 + 1 + 1 + 1 + 36) {
        return 0;
    }
    size_t off = 0;
    out[off++] = 0xC0;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x01;
    out[off++] = 0x08;
    memcpy(out + off, dcid, 8);
    off += 8;
    out[off++] = 0x00; /* scid_len */
    out[off++] = 0x00; /* token varint 0 */
    out[off++] = 0x25; /* length varint (1 байт): pn(1)+тело(20)+тег(16)=37 */
    out[off] = 0x00;   /* pn */
    off += 1;
    for (int i = 0; i < 36; i++) {
        out[off + (size_t)i] = (uint8_t)(0xA0 + i);
    }
    off += 36;
    return off;
}

#define QP_DCID_OFF 6
#define QP_DCID_LEN 8

static uint8_t g_trig_buf[64], g_ctl_buf[64];
static size_t g_trig_len, g_ctl_len;
static const uint8_t *g_trig_bytes, *g_ctl_bytes;

/* ---------------------------------------------------------------------
 * Часть 1: подмена оракула — дисциплина дерева.
 * --------------------------------------------------------------------- */

struct mock_addr_state {
    char addr[D2K_QUIC_ADDR_LEN];
    int poisoned;
};
static struct mock_addr_state g_mock_states[16];
static size_t g_mock_n;
static int g_mock_mark_ok = 1;
static int g_mock_garbage_defeats;
/* 1 (умолчание) — триггер поражает адрес остаточной блокировкой, как и
 * положено сработавшей коробке. 0 — нужен отдельному сценарию: коробка
 * молчит на триггер, но остаточной блокировки НЕТ. */
static int g_mock_poison_on_trigger = 1;
/* Если не пустая строка — контроль молчит ИМЕННО на этом адресе (и только на
 * нём), остальные адреса отвечают как обычно. Раньше был глобальный
 * g_mock_ctl_dead (молчит контроль ВЕЗДЕ) — с появлением базовой живости
 * (шаг 0, тоже контроль на pool[0]) это стало ломать её без причины;
 * per-адресный флаг нацеливает "мёртвый сервер" ровно на нужный шаг. */
static char g_mock_dead_addr[D2K_QUIC_ADDR_LEN];

/* Очередь принудительных исходов — см. шапку файла и находку 4 ревью. */
#define MOCK_FORCE_MAX 8
static d2k_tally g_mock_force[MOCK_FORCE_MAX];
static size_t g_mock_force_n, g_mock_force_i;

static void mock_force_push(int pass, int fail, int err, int marked) {
    d2k_tally t;
    t.pass = pass;
    t.fail = fail;
    t.err = err;
    t.marked = marked;
    g_mock_force[g_mock_force_n++] = t;
}

static void mock_reset(void) {
    g_mock_n = 0;
    memset(g_mock_states, 0, sizeof g_mock_states);
    g_mock_mark_ok = 1;
    g_mock_garbage_defeats = 0;
    g_mock_poison_on_trigger = 1;
    g_mock_dead_addr[0] = '\0';
    g_mock_force_n = 0;
    g_mock_force_i = 0;
}

static struct mock_addr_state *mock_state_for(const char *addr) {
    for (size_t i = 0; i < g_mock_n; i++) {
        if (strcmp(g_mock_states[i].addr, addr) == 0) {
            return &g_mock_states[i];
        }
    }
    struct mock_addr_state *s = &g_mock_states[g_mock_n++];
    memset(s, 0, sizeof *s);
    strncpy(s->addr, addr, sizeof s->addr - 1);
    return s;
}

/* Модель: адрес, увидевший ТРИГГЕР (и не защищённый мусором-обманкой),
 * "поражается" и с этого момента молчит НА ЛЮБОЕ содержимое — ровно то
 * поведение остаточной блокировки, которое описывает донор (USENIX Sec'25 по
 * GFW). Контроль проходит на непоражённом адресе, кроме g_mock_dead_addr
 * (сервер, который сам недоступен). */
static d2k_tally mock_ask(const char *addr, uint16_t port,
                           const uint8_t *prefix, size_t prefix_len,
                           d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                           int repeats, uint32_t *rtt_ms_out) {
    (void)port;
    (void)wait_ms;
    d2k_tally t;
    if (g_mock_force_i < g_mock_force_n) {
        t = g_mock_force[g_mock_force_i++];
    } else {
        struct mock_addr_state *st = mock_state_for(addr);
        memset(&t, 0, sizeof t);
        t.marked = (mark == 0) || g_mock_mark_ok;
        int is_trig = (msg.bytes == g_trig_bytes && msg.len == g_trig_len);
        int is_ctl = (msg.bytes == g_ctl_bytes && msg.len == g_ctl_len);
        int is_dead = (g_mock_dead_addr[0] != '\0' && strcmp(addr, g_mock_dead_addr) == 0);
        for (int i = 0; i < repeats; i++) {
            int passed;
            if (st->poisoned) {
                passed = 0; /* остаточная блокировка: тишина НА ЛЮБОЕ содержимое */
            } else if (is_trig) {
                if (prefix && prefix_len > 0 && g_mock_garbage_defeats) {
                    passed = 1; /* мусор перед Initial "сбил" разбор коробки */
                } else {
                    if (g_mock_poison_on_trigger) {
                        st->poisoned = 1; /* коробка увидела триггер и сработала */
                    }
                    passed = 0;
                }
            } else if (is_ctl) {
                passed = is_dead ? 0 : 1;
            } else {
                passed = 0;
            }
            if (passed) {
                t.pass++;
            } else {
                t.fail++;
            }
        }
    }
    if (rtt_ms_out) {
        *rtt_ms_out = (t.pass > 0) ? 10u : 0u;
    }
    return t;
}

static char g_extra_pool[8][D2K_QUIC_ADDR_LEN];
static size_t g_extra_n;

/* trigger/control — параметры d2k_quic_classify (правка ревью 2026-09-06,
 * круг 1), не снимаются через крючок. no_hello() воспроизводит "снимка нет"
 * явно, тем же bytes==NULL, каким его увидел бы настоящий вызывающий. */
static d2k_hello trig_hello(void) {
    d2k_hello h;
    h.bytes = g_trig_bytes;
    h.len = g_trig_len;
    return h;
}
static d2k_hello ctl_hello(void) {
    d2k_hello h;
    h.bytes = g_ctl_bytes;
    h.len = g_ctl_len;
    return h;
}
static d2k_hello no_hello(void) {
    d2k_hello h;
    h.bytes = NULL;
    h.len = 0;
    return h;
}

static size_t test_resolve(const char *sni, char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    (void)sni;
    size_t n = g_extra_n < cap ? g_extra_n : cap;
    for (size_t i = 0; i < n; i++) {
        memcpy(out[i], g_extra_pool[i], D2K_QUIC_ADDR_LEN);
    }
    return n;
}

/* Хук, который ВРЁТ про число адресов — заполняет ровно cap строк (честно, в
 * пределах своего буфера out), но СООБЩАЕТ, что их вдесятеро больше. Нужен
 * ровно одному тесту (находка 9 ревью, круг 2): без явного зажима n_extra в
 * d2k_quic_classify цикл дедупликации читал бы extra[i] ЗА ГРАНИЦЕЙ локального
 * массива вызывающего — порча памяти, ловится санитайзером (`make -C core
 * san`), а не только этим тестом на голой логике.
 *
 * ВСЕ строки — ОДИН И ТОТ ЖЕ адрес (10.9.9.9): если бы они были различны,
 * дедупликация в d2k_quic_classify заполнила бы пул (n_pool) первыми же
 * cap записями и остановила цикл СВОИМ ЖЕ условием (n_pool < MAX_ADDRS)
 * раньше, чем i дошло бы до границы массива extra[] — маскируя ровно ту
 * порчу памяти, которую тест обязан проверить (обнаружено при разработке
 * этого теста: с уникальными адресами санитайзер молчал). Одинаковый адрес
 * держит n_pool на единице и даёт i честно добежать до extra[cap]. */
static size_t misbehaving_resolve(const char *sni, char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    (void)sni;
    for (size_t i = 0; i < cap; i++) {
        snprintf(out[i], D2K_QUIC_ADDR_LEN, "10.9.9.9");
    }
    return cap * 10; /* заведомая ложь сверх cap */
}

/* ---------------------------------------------------------------------
 * Часть 2: настоящий оракул на 127.0.0.1 — честный AEAD в обратную сторону,
 * реальный ICMP, реальное согласование версии, реальные часы.
 * --------------------------------------------------------------------- */

static const uint8_t v1_salt[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

static void qp_inc32(uint8_t b[16]) {
    for (int i = 15; i >= 12; i--) {
        b[i] = (uint8_t)(b[i] + 1);
        if (b[i] != 0) {
            break;
        }
    }
}

static void qp_ctr_xor(const uint8_t key[16], const uint8_t icb[16],
                        const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t cb[16];
    memcpy(cb, icb, 16);
    size_t i = 0;
    while (i < n) {
        uint8_t ks[16];
        d2k_aes128_ecb(key, cb, ks);
        size_t take = n - i;
        if (take > 16) {
            take = 16;
        }
        for (size_t j = 0; j < take; j++) {
            out[i + j] = (uint8_t)(in[i + j] ^ ks[j]);
        }
        i += take;
        qp_inc32(cb);
    }
}

/* Тело ответа: 0x06 (CRYPTO) + смещение varint(0) + длина varint(N) + N байт
 * "ServerHello" — минимальный кадр, дающий qp_progressed увидеть прогресс
 * рукопожатия (находка 5 ревью, круг 2: аутентичности одной мало). */
static size_t build_crypto_body(uint8_t *out, size_t cap) {
    if (cap < 1 + 1 + 1 + 8) {
        return 0;
    }
    size_t off = 0;
    out[off++] = 0x06; /* CRYPTO */
    out[off++] = 0x00; /* offset varint = 0 */
    out[off++] = 0x08; /* length varint = 8 */
    memcpy(out + off, "SERVHELO", 8);
    off += 8;
    return off;
}

/* Тело ответа "вежливый отказ" — CONNECTION_CLOSE(0x1c) без единого CRYPTO;
 * аутентичный, но НЕ прогресс (та же находка 5). */
static size_t build_close_body(uint8_t *out, size_t cap) {
    if (cap < 1 + 1 + 1 + 1) {
        return 0;
    }
    size_t off = 0;
    out[off++] = 0x1c; /* CONNECTION_CLOSE, транспортный */
    out[off++] = 0x00; /* error code varint */
    out[off++] = 0x00; /* frame type varint */
    out[off++] = 0x00; /* reason length varint = 0 */
    return off;
}

static size_t build_authentic_v1(const uint8_t *dcid, size_t dcid_len,
                                  const uint8_t *plaintext, size_t pt_len,
                                  uint8_t *out, size_t cap) {
    size_t need_length = 1 + pt_len + 16;
    if (need_length >= 64 || dcid_len > 20) {
        return 0;
    }
    size_t hdr_len = 5 + 1 + dcid_len + 1 + 1 + 1 + 1;
    if (hdr_len + pt_len + 16 > cap) {
        return 0;
    }
    size_t off = 0;
    out[off++] = 0xC0;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x01;
    out[off++] = (uint8_t)dcid_len;
    memcpy(out + off, dcid, dcid_len);
    off += dcid_len;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = (uint8_t)need_length;
    size_t pn_offset = off;
    out[off] = 0x00;
    off += 1;

    uint8_t initial_secret[32], secret[32], key[16], iv[12], hp[16];
    d2k_hkdf_extract(v1_salt, sizeof v1_salt, dcid, dcid_len, initial_secret);
    if (d2k_hkdf_expand_label(initial_secret, "server in", secret, sizeof secret) != 0) {
        return 0;
    }
    if (d2k_hkdf_expand_label(secret, "quic key", key, sizeof key) != 0) {
        return 0;
    }
    if (d2k_hkdf_expand_label(secret, "quic iv", iv, sizeof iv) != 0) {
        return 0;
    }
    if (d2k_hkdf_expand_label(secret, "quic hp", hp, sizeof hp) != 0) {
        return 0;
    }

    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    uint8_t ct[256];
    uint8_t icb[16];
    memcpy(icb, j0, 16);
    qp_inc32(icb);
    qp_ctr_xor(key, icb, plaintext, pt_len, ct);

    uint8_t zero[16];
    memset(zero, 0, 16);
    uint8_t h[16];
    d2k_aes128_ecb(key, zero, h);
    uint8_t s[16];
    d2k_ghash_for_test(h, out, pn_offset + 1, ct, pt_len, s);
    uint8_t j0ks[16];
    d2k_aes128_ecb(key, j0, j0ks);
    uint8_t tag[16];
    for (int i = 0; i < 16; i++) {
        tag[i] = (uint8_t)(s[i] ^ j0ks[i]);
    }

    memcpy(out + off, ct, pt_len);
    off += pt_len;
    memcpy(out + off, tag, 16);
    off += 16;
    size_t total = off;

    size_t sample_off = pn_offset + 4;
    uint8_t mask[16];
    d2k_aes128_ecb(hp, out + sample_off, mask);
    out[0] = (uint8_t)(out[0] ^ (mask[0] & 0x0f));
    out[pn_offset] = (uint8_t)(out[pn_offset] ^ mask[1]);

    return total;
}

/* respond: 0 молчать; 1 ответить аутентично+CRYPTO на триггер и контроль; 2
 * ответить мусором (не аутентично); 3 ответить аутентично+CRYPTO ТОЛЬКО на
 * контроль (триггер молчит — нужно тесту на реальные часы бюджета); 4
 * ответить аутентично, но БЕЗ CRYPTO (только CONNECTION_CLOSE — находка 5). */
static volatile int g_rs_respond;
static int g_rs_fd = -1;

static void *rs_run(void *arg) {
    (void)arg;
    for (;;) {
        uint8_t buf[2048];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(g_rs_fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n < 0) {
            return NULL;
        }
        if (g_rs_respond == 0) {
            continue;
        }
        if (g_rs_respond == 2) {
            uint8_t junk[80];
            memset(junk, 0x55, sizeof junk);
            (void)sendto(g_rs_fd, junk, sizeof junk, 0, (struct sockaddr *)&from, fl);
            continue;
        }
        int is_trig = ((size_t)n == g_trig_len && memcmp(buf, g_trig_bytes, (size_t)n) == 0);
        int is_ctl = ((size_t)n == g_ctl_len && memcmp(buf, g_ctl_bytes, (size_t)n) == 0);
        if (g_rs_respond == 3 && is_trig) {
            continue; /* триггер молчит нарочно */
        }
        const uint8_t *dcid = NULL;
        if (is_trig) {
            dcid = g_trig_bytes + QP_DCID_OFF;
        } else if (is_ctl) {
            dcid = g_ctl_bytes + QP_DCID_OFF;
        }
        if (dcid) {
            uint8_t body[32];
            size_t bl = (g_rs_respond == 4) ? build_close_body(body, sizeof body)
                                             : build_crypto_body(body, sizeof body);
            uint8_t resp[512];
            size_t rl = build_authentic_v1(dcid, QP_DCID_LEN, body, bl, resp, sizeof resp);
            if (rl > 0) {
                (void)sendto(g_rs_fd, resp, rl, 0, (struct sockaddr *)&from, fl);
            }
        }
    }
}

static uint16_t rs_start(void) {
    g_rs_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 — единственный переносимо-бинд-абельный адрес */
    a.sin_port = 0;
    bind(g_rs_fd, (struct sockaddr *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(g_rs_fd, (struct sockaddr *)&a, &al);
    uint16_t port = ntohs(a.sin_port);
    pthread_t t;
    pthread_create(&t, NULL, rs_run, NULL);
    pthread_detach(t);
    return port;
}

/* Стенд для "путь жив только через согласование версии": молчит на ЛЮБОЙ
 * настоящий Initial (control/trigger), но честно отвечает на зонд
 * согласования версии (длинный заголовок, версия 0x00000000 — RFC 9000 §6).
 * Отдельный стенд, не переиспользует rs_run: там нет ветки "узнать VN и
 * ответить на неё", а сюда для симметрии не нужна ветка "ответить на
 * Initial". */
static int g_vn_fd = -1;
static volatile int g_vn_should_answer = 1;
/* Сколько ПЕРВЫХ пришедших датаграмм стенд молча роняет (не отвечает), не
 * доходя до проверки "отвечать ли вообще", — нужен находке C ревью (круг 3):
 * симулирует ОБЫЧНУЮ потерю пакета в сети, а не решение стенда "не отвечать".
 * Единственный писатель — main() ДО vn_start(); единственный читатель —
 * vn_run(), обычный int без атомарности достаточен. */
static volatile int g_vn_drop_first_n;

static void *vn_run(void *arg) {
    (void)arg;
    for (;;) {
        uint8_t buf[2048];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(g_vn_fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n < 0) {
            return NULL;
        }
        if (n < 5 || (buf[0] & 0x80) == 0) {
            continue; /* не длинный заголовок — не наш клиент */
        }
        /* Реальный Initial (control/trigger, версия 1 или 2) — не зонд
           согласования версии; этот стенд НАРОЧНО молчит на такие пакеты
           (сценарий "control не отвечает вовсе"), и они не должны ни
           отвечаться, ни тратить g_vn_drop_first_n — иначе счётчик потерь
           списывался бы на базовую живость (шаг 0), которая шлёт свои три
           датаграммы РАНЬШЕ зонда согласования версии, и тест находки C
           проверял бы не то. */
        if (n >= 5) {
            uint32_t version =
                (uint32_t)buf[1] << 24 | (uint32_t)buf[2] << 16 | (uint32_t)buf[3] << 8 | (uint32_t)buf[4];
            if (version == 0x00000001u || version == 0x6b3343cfu) {
                continue;
            }
        }
        if (g_vn_drop_first_n > 0) {
            g_vn_drop_first_n--;
            continue; /* обычная потеря пакета, не решение "не отвечать" */
        }
        if (!g_vn_should_answer) {
            continue;
        }
        /* Отвечаем VN-пакетом: версия 0, эхо DCID/SCID клиента как SCID/DCID
           ответа не обязательно для нашей структурной проверки (см.
           qp_looks_like_vn в quicprobe.c — она смотрит только на длинный
           заголовок и нулевую версию), поэтому просто отражаем вход целиком
           с обнулённой версией. */
        uint8_t resp[2048];
        size_t rl = (size_t)n;
        if (rl > sizeof resp) {
            rl = sizeof resp;
        }
        memcpy(resp, buf, rl);
        resp[0] = 0x80;
        resp[1] = 0;
        resp[2] = 0;
        resp[3] = 0;
        resp[4] = 0;
        (void)sendto(g_vn_fd, resp, rl, 0, (struct sockaddr *)&from, fl);
    }
}

static uint16_t vn_start(void) {
    g_vn_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    a.sin_port = 0;
    bind(g_vn_fd, (struct sockaddr *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(g_vn_fd, (struct sockaddr *)&a, &al);
    uint16_t port = ntohs(a.sin_port);
    pthread_t t;
    pthread_create(&t, NULL, vn_run, NULL);
    pthread_detach(t);
    return port;
}

static int mark_never_ok(int fd, uint32_t mark) {
    (void)fd;
    (void)mark;
    return -1;
}

/* Успевает подтвердить метку на первых g_mark_fail_from-1 вызовах, дальше
 * всегда проваливает. Нужен ИМЕННО находке A: базовая живость (шаг 0) и
 * зонд согласования версии идут через ОДИН И ТОТ ЖЕ d2k_mark_hook, значит
 * mark_never_ok заваливает метку СРАЗУ на базе — all_marked падает там, и
 * тест не отличает "VN не учитывает свою метку" от "база не учла свою". Этот
 * хук пропускает базовые три вызова и валит только зонд согласования версии,
 * идущий следом, — единственный способ изолированно проверить находку A. */
static int g_mark_call_count;
static int g_mark_fail_from; /* 1-based; 0 — никогда не проваливать */
static int mark_fail_from_nth(int fd, uint32_t mark) {
    (void)fd;
    (void)mark;
    g_mark_call_count++;
    if (g_mark_fail_from > 0 && g_mark_call_count >= g_mark_fail_from) {
        return -1;
    }
    return 0;
}

int main(void) {
    uint32_t saved_wait_ms = d2k_quic_wait_ms; /* контракт: тест ужимает и ОБЯЗАН вернуть (находка 9, круг 2) */
    d2k_quic_resolve_hook = test_resolve;
    d2k_quic_wait_ms = 150; /* тест не обязан ждать боевые 3 с тишины на каждый опыт */

    g_trig_len = build_plain_initial(0x11, g_trig_buf, sizeof g_trig_buf);
    g_ctl_len = build_plain_initial(0x22, g_ctl_buf, sizeof g_ctl_buf);
    CHECK(g_trig_len > 0 && g_ctl_len > 0, "не собрались тестовые снимки триггера/контроля");
    g_trig_bytes = g_trig_buf;
    g_ctl_bytes = g_ctl_buf;

    /* ===================================================================
     * Часть 1: дисциплина дерева (подмена d2k_quic_ask_hook).
     * =================================================================== */

    d2k_quic_ask_fn real_ask = d2k_quic_ask_hook;
    d2k_quic_ask_hook = mock_ask;

    /* --- структурно непригодный вход: ни одного опыта (FLAKY, единый класс,
     * находка 9 ревью круг 2 — раньше !trigger.bytes давал INCONCLUSIVE) --- */
    {
        d2k_vres r = d2k_quic_classify(NULL, 443, "x.example", no_hello(), no_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "пустой ip не распознан как структурно непригодный вход");
        CHECK(r.probes == 0, "на структурно непригодном входе не должно быть ни одного опыта");
        CHECK(r.reason[0] != 0, "вердикт без причины нечитаем");
    }
    {
        d2k_vres r = d2k_quic_classify("10.0.0.1", 443, "x.example", no_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "нет снимка триггера — тот же класс FLAKY, что и !ip/!sni");
        CHECK(r.probes == 0, "без снимка не должно быть отправлено ни одного опыта");
    }
    {
        /* Длинный адрес молча обрезался бы strncpy — находка 9: вместо
           честного "вход непригоден" получился бы поход на ЧУЖОЙ адрес. */
        char toolong[64];
        memset(toolong, '1', sizeof toolong - 1);
        toolong[sizeof toolong - 1] = '\0';
        d2k_vres r = d2k_quic_classify(toolong, 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "адрес длиннее буфера пула обязан быть структурно непригодным");
        CHECK(r.probes == 0, "слишком длинный адрес не должен провоцировать ни одного опыта");
    }
    {
        /* НАХОДКА E РЕВЬЮ (круг 3): "999.999.999.999" короче буфера пула, но
           не разбирается как IPv4 — раньше проходил guard по длине и утекал
           в оракул, где давал UNREACHABLE (сетевое утверждение из
           непригодного ввода вместо честного "вход непригоден"). */
        d2k_vres r =
            d2k_quic_classify("999.999.999.999", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY,
              "нечитаемый как IPv4 адрес обязан быть структурно непригодным входом, не сетевым "
              "молчанием");
        CHECK(r.probes == 0, "непригодный адрес не должен провоцировать ни одного сетевого опыта");
    }

    /* --- ГЛАВНАЯ ПРОВЕРКА: остаточная блокировка -> ротация на свежий адрес
     * ТОЛЬКО ПОСЛЕ обнаружения (находка 1 ревью, круг 2) -------------------- */
    {
        mock_reset();
        g_extra_n = 2;
        strncpy(g_extra_pool[0], "10.0.0.2", D2K_QUIC_ADDR_LEN);
        strncpy(g_extra_pool[1], "10.0.0.3", D2K_QUIC_ADDR_LEN);

        d2k_vres r = d2k_quic_classify("10.0.0.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE,
              "коробка блокирует триггер, но пропускает контроль на чистом адресе — должен быть OPAQUE");
        CHECK(mock_state_for("10.0.0.1")->poisoned == 1, "адрес A обязан быть отмечен поражённым");
        CHECK(strstr(r.reason, "ост.блокировка") != NULL,
              "причина обязана явно упомянуть наблюдение остаточной блокировки (шаг 2)");
        CHECK(r.probes == 15,
              "3(база)+3(прямой)+3(шаг2)+3(шаг3-ротация)+3(шаг4) = 15 заданных опытов");
    }

    /* --- ОДИН адрес у цели: ротировать НЕЧЕМ, но контроль ТОЛЬКО ЧТО (шаг 2)
     * ответил на этом же адресе 3/3 — вердикт обязан быть OPAQUE БЕЗ
     * ротации, а не "адрес не задан" (это и есть провал безусловной ротации,
     * найденный ревьюером прогоном, находка 1) ----------------------------- */
    {
        mock_reset();
        g_mock_poison_on_trigger = 0; /* триггер молчит, но НЕ поражает адрес — коробка просто не отвечает */
        g_extra_n = 0;                /* адресов для ротации нет вовсе */

        d2k_vres r = d2k_quic_classify("10.0.1.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE,
              "один адрес: контроль до и после триггера прошёл на нём же — доказательство есть без "
              "ротации, находка 1 ревью");
        CHECK(strstr(r.reason, "блокировки по тройке нет") != NULL,
              "причина обязана сказать, что блокировки по тройке нет — контроль прошёл ДО и ПОСЛЕ");
        /* НАХОДКА B РЕВЬЮ (круг 3): правило "адрес закреплён, пока нет
           остаточной блокировки" — ОДНО на все вопросы, включая плечо. Раньше
           плечо ротировало БЕЗУСЛОВНО и на цели с одним адресом честно
           говорило "не задано (адреса)", хотя спросить было чем — pool[0]
           уже дважды подтверждён живым. Теперь плечо спрашивает pool[0] и
           реально измеряется (3 опыта, не "незадано"). */
        CHECK(strstr(r.reason, "плечо не задано") == NULL,
              "спросить было чем (адрес живой) — плечо не имеет права остаться незаданным");
        CHECK(strstr(r.reason, "плечо(мусор)=0/") != NULL,
              "плечо обязано реально измериться на закреплённом адресе, а не быть пропущено");
        CHECK(r.probes == 12, "3(база)+3(прямой)+3(шаг2)+3(плечо на pool[0], без ротации)");
    }

    /* --- остаточная блокировка ЕСТЬ, но лишних адресов НОЛЬ: шаг 3 (ротация)
     * обязан стать НЕЗАДАННЫМ, а не "сервер недоступен" ---------------------- */
    {
        mock_reset();
        g_extra_n = 0;

        d2k_vres r = d2k_quic_classify("10.0.2.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_INCONCLUSIVE,
              "без свежего адреса вопрос про устройство обязан остаться незаданным, а не "
              "превратиться в вывод про сервер");
        CHECK(strstr(r.reason, "НЕ ЗАДАН") != NULL, "причина обязана честно называть вопрос НЕЗАДАННЫМ");
        CHECK(strstr(r.reason, "недоступен") == NULL,
              "нельзя подменять «не смогли спросить» выводом «сервер недоступен»");
        CHECK(r.probes == 9, "3(база)+3(прямой)+3(шаг2) — дальше дерево не пошло, адресов не осталось");
    }

    /* --- блокировка есть, один лишний адрес хватает на устройство, но на
     * плечо уже не хватает: OPAQUE получен, плечо честно названо незаданным - */
    {
        mock_reset();
        g_extra_n = 1;
        strncpy(g_extra_pool[0], "10.0.3.2", D2K_QUIC_ADDR_LEN);

        d2k_vres r = d2k_quic_classify("10.0.3.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE, "устройство измерено — должен быть OPAQUE несмотря на "
                                          "нехватку адреса для плеча");
        CHECK(strstr(r.reason, "плечо не задано") != NULL,
              "нехватка адреса на плече обязана быть названа прямо, а не проглочена");
        CHECK(r.probes == 12, "3+3+3+3 — вопрос про плечо не задан, его опыты не считаются");
    }

    /* --- нет контрольного имени: даже базовая живость не проверяется ------- */
    {
        mock_reset();
        d2k_vres r = d2k_quic_classify("10.0.4.1", 443, "x.example", trig_hello(), no_hello(), 0);
        CHECK(r.verdict == D2K_V_INCONCLUSIVE, "без контроля даже базовая живость не проверяется");
        CHECK(strstr(r.reason, "контрольного имени") != NULL,
              "причина обязана прямо назвать нехватку контрольного имени");
        CHECK(r.probes == 0, "без контроля НИ ОДНОГО опыта: базовая живость на нём и стоит");
    }

    /* --- контроль молчит именно на СВЕЖЕМ адресе (сервер там сам
     * недоступен), а не на исходном — тоже INCONCLUSIVE, другая причина ---- */
    {
        mock_reset();
        strncpy(g_mock_dead_addr, "10.0.5.2", D2K_QUIC_ADDR_LEN);
        g_extra_n = 1;
        strncpy(g_extra_pool[0], "10.0.5.2", D2K_QUIC_ADDR_LEN);

        d2k_vres r = d2k_quic_classify("10.0.5.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_INCONCLUSIVE,
              "контроль молчит на чистом адресе — отличить содержимое от недоступности нечем");
        CHECK(strstr(r.reason, "недоступности") != NULL,
              "причина обязана назвать именно эту недостачу, а не содержимое");
    }

    /* --- плечо "мусор перед Initial" уже помогает --------------------------- */
    {
        mock_reset();
        g_mock_garbage_defeats = 1;
        g_extra_n = 2;
        strncpy(g_extra_pool[0], "10.0.6.2", D2K_QUIC_ADDR_LEN);
        strncpy(g_extra_pool[1], "10.0.6.3", D2K_QUIC_ADDR_LEN);

        d2k_vres r = d2k_quic_classify("10.0.6.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE, "плечо не отменяет вердикт по содержимому — остаётся OPAQUE");
        CHECK(strstr(r.reason, "плечо(мусор)=3/3") != NULL,
              "reason обязан назвать положительный сигнал по плечу прямо");
    }

    /* --- бюджет исчерпан ДО базовой живости (спецслучай budget_s==0,
     * детерминированный — см. budget_left в quicprobe.c) ------------------- */
    {
        mock_reset();
        uint32_t saved_budget = d2k_quic_budget_s;
        d2k_quic_budget_s = 0;
        d2k_vres r = d2k_quic_classify("10.0.7.1", 443, "x.example", trig_hello(), ctl_hello(), 0);
        d2k_quic_budget_s = saved_budget;

        CHECK(r.verdict == D2K_V_INCONCLUSIVE, "нулевой бюджет обязан остановить дерево честно");
        CHECK(strstr(r.reason, "бюджет") != NULL && strstr(r.reason, "НЕ ЗАДАН") != NULL,
              "причина обязана назвать именно бюджет");
        CHECK(r.probes == 0, "бюджет исчерпан ещё до базовой живости — ни одного опыта");
    }

    /* ===================================================================
     * НАХОДКА 4 РЕВЬЮ (круг 2): шесть мутаций, шесть отдельных тестов.
     * Обычная модель mock_ask детерминирована по содержимому и не умеет ни
     * частичного результата, ни ошибки транспорта — без принудительной
     * очереди (mock_force_push) шесть мутаций ревьюера (снятие учёта метки
     * на шагах 2/3/4, приём "2 из 3" на шагах 2/3, ослабление err>0)
     * проходили зелёными. Каждый тест ниже закрывает ровно одну.
     * =================================================================== */

    /* 1/6: учёт метки на шаге 2 (проверка остаточной блокировки). */
    {
        mock_reset();
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);              /* база: живость 3/3, помечено */
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);               /* прямой зонд: молчит 0/3, помечено */
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 0);               /* шаг 2: 3/3, НО не помечено */
        d2k_vres r = d2k_quic_classify("10.0.8.1", 443, "x.example", trig_hello(), ctl_hello(), 99);
        CHECK(r.verdict == D2K_V_OPAQUE, "1/6: неучёт метки на шаге 2 не должен менять вердикт");
        CHECK(r.marked == 0, "1/6: r.marked обязан упасть — шаг 2 не был помечен");
    }

    /* 2/6: учёт метки на шаге 3 (устройство, после обнаруженной блокировки). */
    {
        mock_reset();
        g_extra_n = 1;
        strncpy(g_extra_pool[0], "10.0.8.9", D2K_QUIC_ADDR_LEN);
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1); /* база: живость */
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);  /* прямой зонд: молчит */
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);  /* шаг 2: молчит — блокировка обнаружена */
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 0);  /* шаг 3: 3/3, НЕ помечено */
        d2k_vres r = d2k_quic_classify("10.0.8.2", 443, "x.example", trig_hello(), ctl_hello(), 99);
        CHECK(r.verdict == D2K_V_OPAQUE, "2/6: неучёт метки на шаге 3 не должен менять вердикт");
        CHECK(r.marked == 0, "2/6: r.marked обязан упасть — шаг 3 не был помечен");
    }

    /* 3/6: учёт метки на шаге 4 (плечо). */
    {
        mock_reset();
        g_extra_n = 1;
        strncpy(g_extra_pool[0], "10.0.8.9", D2K_QUIC_ADDR_LEN);
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1); /* база: живость */
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);  /* прямой зонд: молчит */
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);  /* шаг 2: 3/3 — блокировки НЕТ, сразу OPAQUE+плечо */
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 0);  /* плечо: 0/3, НЕ помечено */
        d2k_vres r = d2k_quic_classify("10.0.8.3", 443, "x.example", trig_hello(), ctl_hello(), 99);
        CHECK(r.verdict == D2K_V_OPAQUE, "3/6: неучёт метки на плече не должен менять вердикт");
        CHECK(r.marked == 0, "3/6: r.marked обязан упасть — плечо не было помечено");
    }

    /* 4/6: приём "2 из 3" на шаге 2 обязан быть FLAKY. */
    {
        mock_reset();
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);
        mock_force_push(2, 1, 0, 1); /* шаг 2: 2 из 3 — не единогласно */
        d2k_vres r = d2k_quic_classify("10.0.8.4", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "4/6: 2 из 3 на шаге 2 обязано быть FLAKY, не округлением");
    }

    /* 5/6: приём "2 из 3" на шаге 3 обязан быть FLAKY. */
    {
        mock_reset();
        g_extra_n = 1;
        strncpy(g_extra_pool[0], "10.0.8.9", D2K_QUIC_ADDR_LEN);
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1); /* шаг 2: молчит — блокировка обнаружена */
        mock_force_push(2, 1, 0, 1);                 /* шаг 3: 2 из 3 */
        d2k_vres r = d2k_quic_classify("10.0.8.5", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "5/6: 2 из 3 на шаге 3 обязано быть FLAKY, не округлением");
    }

    /* 6/6: ошибка транспорта на шаге 2 обязана быть FLAKY даже когда pass==0
     * (иначе неотличимо от "молчит — блокировка обнаружена"). pass=2 здесь
     * не годится: err>0 тогда ВСЕГДА совпадает с "0<pass<REPEATS", и ослабленная
     * до err==REPEATS проверка всё равно ловится ЧУЖИМ, соседним guard'ом
     * (сама эта путаница и есть находка: тест обязан бить ИМЕННО по err,
     * не разделяя правку с партиционным guard'ом). pass=0 исключает эту
     * путаницу: единственный guard, которому есть что проверять, — err>0. */
    {
        mock_reset();
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);
        mock_force_push(0, D2K_QUIC_REPEATS, 1, 1); /* шаг 2: 0 прошли, 1 из 3 — ошибка транспорта */
        d2k_vres r = d2k_quic_classify("10.0.8.6", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "6/6: ошибка транспорта на шаге 2 обязана быть FLAKY, не "
                                         "«блокировка обнаружена» по совпадению pass==0");
    }

    /* --- НАХОДКА 9 РЕВЬЮ (круг 2): резолвер, вернувший больше cap, не должен
     * читаться дальше своего же буфера — под `make -C core san` без зажима
     * n_extra это redzone-переполнение, здесь — хотя бы не падение и
     * содержательный, а не мусорный вердикт. -------------------------------- */
    {
        mock_reset();
        d2k_quic_resolve_fn saved_resolve = d2k_quic_resolve_hook;
        d2k_quic_resolve_hook = misbehaving_resolve;
        d2k_vres r = d2k_quic_classify("10.0.9.1", 443, "x.example", trig_hello(), ctl_hello(), 0);
        d2k_quic_resolve_hook = saved_resolve;
        CHECK(r.verdict == D2K_V_OPAQUE || r.verdict == D2K_V_INCONCLUSIVE,
              "лживый резолвер не должен портить память или ронять процесс — вердикт остаётся "
              "содержательным (OPAQUE с ротацией или INCONCLUSIVE, если пул честно исчерпался)");
    }

    d2k_quic_ask_hook = real_ask;

    /* ===================================================================
     * Часть 2: настоящий оракул — реальные сокеты на 127.0.0.1, реальный
     * AES-128-GCM с обеих сторон, реальный ICMP, реальное согласование
     * версии, реальные часы бюджета.
     * =================================================================== */
    g_extra_n = 0;

    /* --- прямой зонд проходит по-настоящему (аутентично + кадр CRYPTO): CLEAR */
    {
        g_rs_respond = 1;
        uint16_t port = rs_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_CLEAR, "настоящий аутентичный ответ с CRYPTO на триггер — должен быть CLEAR");
        close(g_rs_fd);
    }

    /* --- метка запрошена, но не подтвердилась: CLEAR не выдаём ------------ */
    {
        g_rs_respond = 1;
        uint16_t port = rs_start();
        d2k_mark_fn saved = d2k_mark_hook;
        d2k_mark_hook = mark_never_ok;
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 777);
        d2k_mark_hook = saved;
        CHECK(r.verdict == D2K_V_INCONCLUSIVE,
              "триггер прошёл, но метка ни разу не подтвердилась — CLEAR принимать нельзя");
        CHECK(r.marked == 0, "r.marked обязан честно сказать, что метка не подтверждена");
        close(g_rs_fd);
    }

    /* --- похожий на ответ, но НЕ аутентичный (тег не сходится): не должен
     * засчитаться успехом -------------------------------------------------- */
    {
        g_rs_respond = 2; /* мусор вместо настоящего AEAD */
        uint16_t port = rs_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict != D2K_V_CLEAR,
              "recv()>0 без аутентичности — это НЕ доказательство успеха, CLEAR здесь ошибка");
        close(g_rs_fd);
    }

    /* --- НАХОДКА 5 РЕВЬЮ: аутентичный ответ БЕЗ кадра CRYPTO (только
     * CONNECTION_CLOSE) — вежливый отказ, не прогресс, CLEAR запрещён ------ */
    {
        g_rs_respond = 4; /* аутентично, но только CONNECTION_CLOSE, без CRYPTO */
        uint16_t port = rs_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict != D2K_V_CLEAR,
              "аутентичный CONNECTION_CLOSE без CRYPTO — вежливый отказ, не рукопожатие; CLEAR — "
              "самая дорогая ошибка дерева (находка 5 ревью, круг 2)");
        close(g_rs_fd);
    }

    /* --- нет UDP-ответа вовсе: настоящий ICMP port-unreachable -> UNREACHABLE
     * СРАЗУ на базовой живости (контроль тоже получает ICMP) --------------- */
    {
        int probe = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(probe >= 0, "не удалось открыть щуп для свободного порта");
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(0x7f000001);
        a.sin_port = 0;
        bind(probe, (struct sockaddr *)&a, sizeof a);
        socklen_t al = sizeof a;
        getsockname(probe, (struct sockaddr *)&a, &al);
        uint16_t closed_port = ntohs(a.sin_port);
        close(probe); /* порт снова закрыт — гарантированный ICMP port-unreachable на UDP */

        d2k_vres r = d2k_quic_classify("127.0.0.1", closed_port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_UNREACHABLE,
              "закрытый порт обязан дать UNREACHABLE на базовой живости — честный сбой транспорта");
        CHECK(r.probes == D2K_QUIC_REPEATS,
              "UNREACHABLE выносится сразу по базовой живости, дальше дерево не идёт");
    }

    /* --- путь жив только через согласование версии; НАХОДКА D РЕВЬЮ (круг 3):
     * причина обязана честно сказать, что НАШЕ ИМЯ (триггер) не спрашивалось
     * — молчит только контрольное. Прежняя редакция писала "Initial молчит
     * на обоих именах", хотя триггер не отправлялся ни разу (r.probes был
     * бы 9, а не 6, если бы отправлялся: 3 база + 3 VN + 3 триггер). ------- */
    {
        g_vn_should_answer = 1;
        uint16_t port = vn_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_INCONCLUSIVE,
              "путь жив (VN ответило), но контроль молчит — мерить нечем, не UNREACHABLE");
        CHECK(r.probes == 2 * D2K_QUIC_REPEATS,
              "ровно база + VN (3+3=6) — триггер на этой ветке НЕ ОТПРАВЛЯЛСЯ, значит не должен "
              "войти ни в r.probes, ни (см. ниже) в текст причины как заданный");
        CHECK(strstr(r.reason, "не спрашивалось") != NULL,
              "причина обязана честно сказать, что НАШЕ имя не спрашивалось — незаданный вопрос "
              "не может быть подан как заданный и отказавший (находка D)");
        CHECK(strstr(r.reason, "молчит на обоих") == NULL,
              "старая формулировка донора неверна именно потому, что триггер не отправлялся ни разу");
        CHECK(strstr(r.reason, "адрес") == NULL,
              "§2.3: в тексте не должно быть утверждения про блокировку АДРЕСА");
        close(g_vn_fd);
    }

    /* --- молчит вообще всё, включая согласование версии -> UNREACHABLE ---- */
    {
        g_vn_should_answer = 0;
        uint16_t port = vn_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_UNREACHABLE,
              "молчит всё, включая согласование версии — UNREACHABLE, а не догадка о цензуре");
        close(g_vn_fd);
    }

    /* --- НАХОДКА A РЕВЬЮ (круг 3): зонд согласования версии обязан идти С
     * МЕТКОЙ, и её неудача обязана попасть в r.marked. База (шаг 0) идёт тем
     * же d2k_mark_hook, поэтому "просто mark_never_ok" не различил бы "VN не
     * учитывает свою метку" от "база не учла свою" — база сама завалила бы
     * all_marked первой. mark_fail_from_nth пропускает первые 3 (база) и
     * валит метку начиная с 4-го вызова (зонд согласования версии) —
     * изолированная проверка именно находки A. ------------------------------ */
    {
        g_vn_should_answer = 1;
        uint16_t port = vn_start();
        d2k_mark_fn saved = d2k_mark_hook;
        g_mark_call_count = 0;
        g_mark_fail_from = D2K_QUIC_REPEATS + 1; /* 4-й и далее вызовы — мимо метки */
        d2k_mark_hook = mark_fail_from_nth;
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 555);
        d2k_mark_hook = saved;
        g_mark_fail_from = 0;
        CHECK(r.verdict == D2K_V_INCONCLUSIVE, "вердикт не должен зависеть от того, встала ли метка");
        CHECK(r.marked == 0,
              "база помечена честно (первые 3 вызова), но зонд согласования версии — нет (вызовы "
              "4-6): r.marked обязан упасть на этом одном, а не остаться истинным (находка A)");
        close(g_vn_fd);
    }

    /* --- НАХОДКА C РЕВЬЮ (круг 3): одна обычная потеря пакета на зонде
     * согласования версии БОЛЬШЕ НЕ ПЕРЕВОРАЧИВАЕТ вердикт молча между
     * UNREACHABLE и INCONCLUSIVE — единственный зонд без повторов делал
     * именно это. Три параллельных попытки с той же дисциплиной единогласия,
     * что и у любого другого вопроса дерева (§7: "расхождение повторов —
     * FLAKY, а не округление в удобную сторону" — округлять 2-из-3 ДО
     * "путь жив" было бы ровно этим округлением) честно отвечают FLAKY:
     * третий, признающий неопределённость исход, а не молчаливый выбор
     * одного из двух неверных. ------------------------------------------- */
    {
        g_vn_should_answer = 1;
        g_vn_drop_first_n = 1; /* стенд теряет РОВНО одну из трёх датаграмм */
        uint16_t port = vn_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        g_vn_drop_first_n = 0;
        CHECK(r.verdict == D2K_V_FLAKY,
              "2 из 3 отвечают, 1 потерян — не единогласно, честный исход FLAKY, а НЕ молчаливое "
              "округление до UNREACHABLE или до INCONCLUSIVE (находка C)");
        close(g_vn_fd);
    }

    /* --- НАХОДКА "ПРО БЮДЖЕТ": исчерпание РЕАЛЬНЫМ временем, не спецслучаем
     * budget_s==0 — единственный шов, который не подменяется, часы, должен
     * быть прогнан хотя бы одним тестом (замечание ревьюера, круг 2). Контроль
     * отвечает (живость есть), триггер молчит нарочно (g_rs_respond=3) —
     * пол ожидания 1500 мс (D2K_QUIC_RTT_WAIT_FLOOR_MS) на шаге 1 сам по себе
     * съедает больше секундного бюджета. ------------------------------------ */
    {
        g_rs_respond = 3; /* отвечает только на контроль */
        uint16_t port = rs_start();
        uint32_t saved_budget = d2k_quic_budget_s;
        d2k_quic_budget_s = 1; /* 1 настоящая секунда, не 0 — проверяем часы, не спецслучай */
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        d2k_quic_budget_s = saved_budget;
        close(g_rs_fd);

        CHECK(r.verdict == D2K_V_INCONCLUSIVE,
              "реальный бюджет в 1 с обязан истечь до шага 2 (пол ожидания 1,5 с на шаге 1 один "
              "съедает больше) — проверка настоящих часов, не спецслучая budget_s==0");
        CHECK(strstr(r.reason, "бюджет") != NULL, "причина обязана назвать именно бюджет");
    }

    d2k_quic_wait_ms = saved_wait_ms; /* контракт: вернуть, как и положено (находка 9, круг 2) */

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("вопросник по QUIC: все проверки прошли\n");
    return 0;
}
