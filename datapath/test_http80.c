/* test_http80.c — вставка провайдера в открытый HTTP (задача 51).
 *
 * Пакеты собираются здесь байт в байт так, как их отдаёт очередь: исходящие
 * клиента — с локальным адресом (POSTROUTING, до SNAT), ответы — уже с
 * адресом клиента (FORWARD, после обратной трансляции). Времена — как в
 * захвате на ppp0 03.10.2026: RTT 98 мс, вставка через 0,7 мс после запроса.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_http80.h"
#include "d2k_wire.h"
#include "d2k_httpup.h"
#include "d2k_http_response.h"
#include "d2k_http_request_stream.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s (строка %d)\n", msg, __LINE__); \
            fails++;                                       \
        }                                                  \
    } while (0)

#define MS 1000000ull

#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_PSH 0x08
#define F_ACK 0x10

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void wr16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

typedef struct {
    int v6;
    uint8_t client[16], server[16];
    uint16_t cport, sport;
} flow;

/* Пакет одного направления. to_server — от клиента. */
static size_t pkt(const flow *f, int to_server, uint8_t flags, uint32_t seq, uint32_t ack,
                  const char *payload, uint8_t *o) {
    size_t pl = payload ? strlen(payload) : 0;
    size_t ip = f->v6 ? 40 : 20;
    size_t n = ip + 20 + pl;
    memset(o, 0, n);
    const uint8_t *src = to_server ? f->client : f->server;
    const uint8_t *dst = to_server ? f->server : f->client;
    if (f->v6) {
        o[0] = 0x60; wr16(o + 4, (unsigned)(20 + pl)); o[6] = 6; o[7] = 55;
        memcpy(o + 8, src, 16); memcpy(o + 24, dst, 16);
    } else {
        o[0] = 0x45; wr16(o + 2, (unsigned)n); wr16(o + 4, 0x1234); o[8] = 55; o[9] = 6;
        memcpy(o + 12, src, 4); memcpy(o + 16, dst, 4);
    }
    uint8_t *t = o + ip;
    wr16(t, to_server ? f->cport : f->sport);
    wr16(t + 2, to_server ? f->sport : f->cport);
    wr32(t + 4, seq); wr32(t + 8, ack);
    t[12] = 0x50; t[13] = flags; wr16(t + 14, 64240);
    if (pl) { memcpy(t + 20, payload, pl); }
    return n;
}

static const char GET[] =
    "GET /forum/index.php HTTP/1.1\r\nHost: RuTracker.org:80\r\n"
    "User-Agent: test\r\nAccept: */*\r\n\r\n";
static const char INJECT[] =
    "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://lawfilter.ertelecom.ru\r\n"
    "Connection: close\r\nContent-Length: 13\r\n\r\nlawfilter.ru\n";

#define CISN 1000u
#define SISN 5000000u

static uint8_t b[4096];
#define PKT(h, p, n, t, res) d2k_http80_packet((h), (p), (n), (t), 0, out, sizeof out, rst, sizeof rst, (res))
static d2k_http80_res r;
static uint8_t out[2048], rst[128];

/* Рукопожатие и запрос в моменты захвата: SYN 0, SYN/ACK 98 мс, запрос 99 мс. */
static void open_flow(d2k_http80 *h, const flow *f, uint64_t t0, const char *req) {
    size_t n = pkt(f, 1, F_SYN, CISN, 0, NULL, b);
    PKT(h, b, n, t0, &r);
    CHECK(r.action == D2K_HTTP80_PASS && !r.injection, "SYN не проходит как есть");
    n = pkt(f, 0, F_SYN | F_ACK, SISN, CISN + 1, NULL, b);
    PKT(h, b, n, t0 + 98 * MS, &r);
    CHECK(r.action == D2K_HTTP80_PASS, "SYN/ACK не проходит как есть");
    n = pkt(f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, req, b);
    PKT(h, b, n, t0 + 99 * MS, &r);
    CHECK(r.action == D2K_HTTP80_PASS && !r.injection, "запрос не проходит как есть");
}

static flow flow4(uint16_t cport) {
    flow f;
    memset(&f, 0, sizeof f);
    const uint8_t c[4] = {192, 168, 1, 117}, s[4] = {195, 82, 146, 214};
    memcpy(f.client, c, 4); memcpy(f.server, s, 4);
    f.cport = cport; f.sport = 80;
    return f;
}

static flow flow6(uint16_t cport) {
    flow f;
    memset(&f, 0, sizeof f);
    f.v6 = 1;
    f.client[0] = 0x20; f.client[1] = 0x01; f.client[2] = 0x0d; f.client[3] = 0xb8; f.client[15] = 0x17;
    f.server[0] = 0x2a; f.server[1] = 0x02; f.server[15] = 0x80;
    f.cport = cport; f.sport = 80;
    return f;
}

static void test_field_injection(int v6) {
    d2k_http80 *h = d2k_http80_new();
    flow f = v6 ? flow6(51000) : flow4(51000);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    open_flow(h, &f, 1000 * MS, GET);
    size_t n = pkt(&f, 0, F_ACK | F_PSH | F_FIN, SISN + 1, req_end, INJECT, b);
    PKT(h, b, n, 1000 * MS + 99 * MS + 700000ull, &r);
    CHECK(r.injection, v6 ? "IPv6: вставка 302→lawfilter через 0,7 мс не узнана"
                          : "вставка 302→lawfilter через 0,7 мс не узнана");
    CHECK(r.action == D2K_HTTP80_PASS, "без знания об HTTPS вставка обязана пройти как есть");
    CHECK(strcmp(r.host, "RuTracker.org") == 0, "Host запроса не передан");
    CHECK(strcmp(r.portal, "lawfilter.ertelecom.ru") == 0, "хост блокировки не передан");
    CHECK(r.rtt_ns == 98 * MS && r.reply_ns == 700000ull, "RTT и задержка ответа не те");
    CHECK(r.family == (v6 ? 6 : 4) && r.server_port == 80 && r.client_port == 51000 &&
          memcmp(r.server, f.server, v6 ? 16 : 4) == 0 &&
          memcmp(r.client, f.client, v6 ? 16 : 4) == 0, "адреса потока не те");
    /* Вторая копия — та же вставка, о ней второй раз не сообщаем. */
    PKT(h, b, n, 1000 * MS + 99 * MS + 900000ull, &r);
    CHECK(!r.injection && r.action == D2K_HTTP80_PASS, "вторая копия вставки сообщена повторно");
    d2k_http80_stats st = d2k_http80_get_stats(h);
    CHECK(st.injections == 1 && st.requests == 1, "счётчики вставок/запросов не те");
    d2k_http80_free(h);
}

static const char INJECT_MEGAFON[] =
    "HTTP/1.1 302 Found\r\nLocation: https://m.megafonpro.ru/rkn-auth?channel=2m\r\n"
    "Connection: close\r\nContent-Length: 0\r\n\r\n";

static void test_field_injection_megafon(void) {
    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(51500);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    open_flow(h, &f, 1000 * MS, GET);
    size_t n = pkt(&f, 0, F_ACK | F_PSH | F_FIN, SISN + 1, req_end, INJECT_MEGAFON, b);
    PKT(h, b, n, 1000 * MS + 99 * MS + 700000ull, &r);
    CHECK(r.injection, "вставка 302→m.megafonpro.ru/rkn-auth через 0,7 мс не узнана");
    CHECK(r.action == D2K_HTTP80_PASS, "без знания об HTTPS вставка обязана пройти как есть");
    CHECK(strcmp(r.host, "RuTracker.org") == 0, "Host запроса не передан");
    CHECK(strcmp(r.portal, "m.megafonpro.ru") == 0, "хост блокировки не передан");
    d2k_http80_free(h);
}

/* То, что вставкой не является, — молча проходит. */
static void test_not_injection(void) {
    static const char own_redirect[] =
        "HTTP/1.1 302 Found\r\nLocation: https://rutracker.org/forum/index.php\r\n"
        "Content-Length: 0\r\n\r\n";
    static const char foreign_redirect[] =
        "HTTP/1.1 302 Found\r\nLocation: https://login.example.net/\r\n"
        "Content-Length: 0\r\n\r\n";
    struct { const char *reply; uint64_t after; uint32_t seq_shift; const char *what; } cases[] = {
        {own_redirect, 700000ull, 0, "обычный 302 сервера на свой хост принят за вставку"},
        {foreign_redirect, 700000ull, 0, "302 на чужой хост без метки блокировки принят за вставку"},
        {INJECT, 120 * MS, 0, "медленный ответ (позже RTT) принят за вставку"},
        {INJECT, 50 * MS, 0, "ответ на 50 мс при RTT 98 мс (позже половины RTT) принят за вставку"},
        {INJECT, 700000ull, 7, "ответ не с начала потока сервера принят за вставку"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        d2k_http80 *h = d2k_http80_new();
        flow f = flow4((uint16_t)(52000 + i));
        open_flow(h, &f, 0, GET);
        size_t n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1 + cases[i].seq_shift,
                       CISN + 1 + (uint32_t)strlen(GET), cases[i].reply, b);
        PKT(h, b, n, 99 * MS + cases[i].after, &r);
        CHECK(!r.injection && r.action == D2K_HTTP80_PASS, cases[i].what);
        d2k_http80_free(h);
    }

    /* Поток, начатый до службы: SYN не видели, RTT не замерен — не решаем. */
    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(53000);
    size_t n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    PKT(h, b, n, 99 * MS, &r);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    PKT(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(!r.injection, "вставка без замеренного RTT признана вставкой");
    d2k_http80_free(h);

    /* Не порт 80 — не наше дело. */
    h = d2k_http80_new();
    f = flow4(54000);
    f.sport = 8080;
    open_flow(h, &f, 0, GET);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    PKT(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(!r.injection, "поток не на порт 80 разобран как HTTP");
    d2k_http80_free(h);

    /* POST — не навигация: не трогаем. */
    h = d2k_http80_new();
    f = flow4(55000);
    static const char post[] = "POST / HTTP/1.1\r\nHost: rutracker.org\r\nContent-Length: 0\r\n\r\n";
    open_flow(h, &f, 0, post);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(post), INJECT, b);
    PKT(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(!r.injection, "ответ на POST разобран как вставка в навигацию");
    d2k_http80_free(h);
}

/* Много потоков: таблица ограничена, старые вытесняются, разбор не ломается. */
static void test_table_bound(void) {
    d2k_http80 *h = d2k_http80_new();
    for (unsigned i = 0; i < D2K_HTTP80_FLOWS * 3; i++) {
        flow f = flow4((uint16_t)(10000 + i));
        open_flow(h, &f, (uint64_t)i * MS, GET);
    }
    flow f = flow4((uint16_t)(10000 + D2K_HTTP80_FLOWS * 3 - 1));
    size_t n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    PKT(h, b, n, (uint64_t)(D2K_HTTP80_FLOWS * 3 - 1) * MS + 99 * MS + 700000ull, &r);
    CHECK(r.injection, "свежий поток потерян при переполнении таблицы");
    CHECK(d2k_http80_get_stats(h).evicted > 0, "вытеснение не посчитано");
    d2k_http80_free(h);
}

/* Обрезки и мусор не роняют разбор. */
static void test_garbage(void) {
    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(56000);
    size_t n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    for (size_t cut = 0; cut < n; cut++) {
        PKT(h, b, cut, 0, &r);
        CHECK(r.action == D2K_HTTP80_PASS, "обрезанный пакет не прошёл как есть");
    }
    d2k_http80_free(h);
}

/* Вердикт и RST — подделки: замер того, что датапат сделал бы с очередью. */
typedef struct { int fail_verdict, payload_calls, accept_calls, rst_calls; size_t payload_len; } fake_io;
static int io_payload(void *c, const uint8_t *p, size_t n) {
    fake_io *f = c; (void)p; f->payload_calls++; f->payload_len = n;
    return f->fail_verdict ? -1 : 0;
}
static int io_accept(void *c) { ((fake_io *)c)->accept_calls++; return 0; }
static int io_rst(void *c, const uint8_t *p, size_t n) {
    (void)p; (void)n; ((fake_io *)c)->rst_calls++; return 0;
}
static int swap(d2k_http80 *h, d2k_http80_res *res, fake_io *f) {
    d2k_http80_io io = {io_payload, io_accept, io_rst, f};
    return d2k_http80_swap(h, res, out, rst, &io);
}

static int ip4_header_ok(const uint8_t *p) {
    uint32_t acc = 0;
    for (size_t i = 0; i < 20; i += 2) { acc += rd16(p + i); }
    while (acc >> 16) { acc = (acc & 0xffffu) + (acc >> 16); }
    return acc == 0xffffu;
}

/* HTTPS подтверждён: клиент получает 307 в том же потоке, сервер — RST,
   остальное от сервера снимается. */
static void test_answer(int v6) {
    d2k_http80 *h = d2k_http80_new();
    const uint64_t T = 5000 * MS;
    CHECK(d2k_http80_set_https(h, "rutracker.org.", 14, T + 3600 * 1000 * MS) == 0,
          "имя с HTTPS не принято");
    flow f = v6 ? flow6(51500) : flow4(51500);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    open_flow(h, &f, T, GET);
    size_t n = pkt(&f, 0, F_ACK | F_PSH | F_FIN, SISN + 1, req_end, INJECT, b);
    PKT(h, b, n, T + 99 * MS + 700000ull, &r);
    CHECK(r.injection && r.action == D2K_HTTP80_REPLACE,
          v6 ? "IPv6: вставка при подтверждённом HTTPS не заменена" :
               "вставка при подтверждённом HTTPS не заменена");
    {
        d2k_http80_res keep = r;
        fake_io io = {0, 0, 0, 0, 0};
        CHECK(swap(h, &keep, &io) == 1 && keep.answered && io.payload_calls == 1 &&
              io.payload_len == keep.len && io.rst_calls == 1 && io.accept_calls == 0,
              "удачная замена: не тот порядок вердикта и RST");
    }

    char want[1024];
    size_t wl = d2k_httpup_redirect_https("RuTracker.org", "/forum/index.php", want, sizeof want);
    CHECK(wl > 0 && strstr(want, "HTTP/1.1 307 Temporary Redirect\r\n") == want &&
          strstr(want, "Location: https://RuTracker.org/forum/index.php\r\n") &&
          strstr(want, "Content-Length: 0\r\n") && strstr(want, "Connection: close\r\n"),
          "307 собран не тем");
    size_t ip = v6 ? 40 : 20;
    CHECK(r.len == ip + 20 + wl, "длина пакета-замены не та");
    const uint8_t *o = out, *t = out + ip;
    if (v6) {
        CHECK(o[0] >> 4 == 6 && rd16(o + 4) == 20 + wl && o[6] == 6, "IPv6-заголовок замены не тот");
        CHECK(memcmp(o + 8, f.server, 16) == 0 && memcmp(o + 24, f.client, 16) == 0,
              "IPv6: адреса замены не те");
    } else {
        CHECK(o[0] == 0x45 && rd16(o + 2) == 20 + 20 + wl && o[9] == 6, "IPv4-заголовок замены не тот");
        CHECK(memcmp(o + 12, f.server, 4) == 0 && memcmp(o + 16, f.client, 4) == 0,
              "IPv4: адреса замены не те");
        CHECK(ip4_header_ok(o), "сумма IPv4-заголовка замены неверна");
    }
    CHECK(rd16(t) == 80 && rd16(t + 2) == 51500, "порты замены не те");
    CHECK(rd32(t + 4) == SISN + 1, "seq замены не начало потока сервера");
    CHECK(rd32(t + 8) == req_end, "ack замены не конец запроса");
    CHECK(t[13] == (F_FIN | F_PSH | F_ACK), "флаги замены не FIN|PSH|ACK");
    CHECK(memcmp(t + 20, want, wl) == 0, "нагрузка замены не 307");
    CHECK(d2k_wire_tcp_checksum_ok(out, r.len), "TCP-сумма замены неверна");

    /* RST к серверу: от клиента, с конца запроса. */
    CHECK(r.rst_len == ip + 20, "RST к серверу не собран");
    const uint8_t *q = rst + ip;
    if (v6) {
        CHECK(memcmp(rst + 8, f.client, 16) == 0 && memcmp(rst + 24, f.server, 16) == 0,
              "IPv6: адреса RST не те");
    } else {
        CHECK(memcmp(rst + 12, f.client, 4) == 0 && memcmp(rst + 16, f.server, 4) == 0,
              "IPv4: адреса RST не те");
        CHECK(ip4_header_ok(rst), "сумма IPv4-заголовка RST неверна");
    }
    CHECK(rd16(q) == 51500 && rd16(q + 2) == 80, "порты RST не те");
    CHECK(rd32(q + 4) == req_end && (q[13] & F_RST), "RST не с конца запроса");
    CHECK(d2k_wire_tcp_checksum_ok(rst, r.rst_len), "TCP-сумма RST неверна");

    /* Вторая копия, отдельный FIN вставки, поздний настоящий ответ — снимаются. */
    PKT(h, b, n, T + 99 * MS + 900000ull, &r);
    CHECK(r.action == D2K_HTTP80_DROP && !r.injection, "вторая копия вставки не снята");
    n = pkt(&f, 0, F_ACK | F_FIN, SISN + 1 + (uint32_t)strlen(INJECT), req_end, NULL, b);
    PKT(h, b, n, T + 99 * MS + 950000ull, &r);
    CHECK(r.action == D2K_HTTP80_DROP, "FIN вставки не снят");
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, req_end, "HTTP/1.1 200 OK\r\n\r\n", b);
    PKT(h, b, n, T + 200 * MS, &r);
    CHECK(r.action == D2K_HTTP80_DROP, "поздний пакет сервера не снят");
    /* Клиент закрывает своё — это не наше дело. */
    n = pkt(&f, 1, F_ACK | F_FIN, req_end, SISN + 2 + (uint32_t)wl, NULL, b);
    PKT(h, b, n, T + 200 * MS, &r);
    CHECK(r.action == D2K_HTTP80_PASS, "пакет клиента после замены снят");
    d2k_http80_stats st = d2k_http80_get_stats(h);
    CHECK(st.answered == 1 && st.dropped == 3, "счётчики замены не те");
    d2k_http80_free(h);
}

/* Ядро не приняло вердикт с заменой (ревью I3): вставка уходит как есть,
   поток не «отвечен», серверу RST не идёт, вторая копия не снимается. */
static void test_swap_failure(void) {
    d2k_http80 *h = d2k_http80_new();
    CHECK(d2k_http80_set_https(h, "rutracker.org", 13, 1000 * MS) == 0, "имя не принято");
    flow f = flow4(58000);
    open_flow(h, &f, 0, GET);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    size_t n = pkt(&f, 0, F_ACK | F_PSH | F_FIN, SISN + 1, req_end, INJECT, b);
    PKT(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(r.action == D2K_HTTP80_REPLACE, "замена не предложена");
    fake_io io = {1, 0, 0, 0, 0};
    CHECK(swap(h, &r, &io) == 0 && !r.answered, "неудачная замена сочтена удачной");
    CHECK(io.payload_calls == 1 && io.accept_calls == 1 && io.rst_calls == 0,
          "после неудачной замены не выпущен оригинал или ушёл RST");
    PKT(h, b, n, 99 * MS + 900000ull, &r);
    CHECK(r.action == D2K_HTTP80_PASS && !r.injection, "вторая копия снята после неудачной замены");
    d2k_http80_stats st = d2k_http80_get_stats(h);
    CHECK(st.answered == 0 && st.swap_failed == 1 && st.dropped == 0, "счётчики неудачи не те");
    d2k_http80_free(h);
}

/* Задержка самого d2kd (ревью M1): SYN/ACK пролежал в очереди 200 мс. По
   своим часам d2kd RTT 300 мс, и настоящий ответ через 60 мс выглядит
   вставкой. Метки ядра (приём пакета) дают настоящие 98 мс — не вставка. */
static void test_kernel_clock(void) {
    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(59000);
    const uint64_t K = 1700000000ull * 1000000000ull;
    size_t n = pkt(&f, 1, F_SYN, CISN, 0, NULL, b);
    d2k_http80_packet(h, b, n, 0, K, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 0, F_SYN | F_ACK, SISN, CISN + 1, NULL, b);
    d2k_http80_packet(h, b, n, 300 * MS, K + 98 * MS, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    d2k_http80_packet(h, b, n, 301 * MS, K + 99 * MS, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    d2k_http80_packet(h, b, n, 361 * MS, K + 159 * MS, out, sizeof out, rst, sizeof rst, &r);
    CHECK(!r.injection, "задержка d2kd превратила настоящий ответ во вставку");
    d2k_http80_free(h);

    /* Тот же поток, ответ через 0,7 мс по меткам ядра — вставка. */
    h = d2k_http80_new();
    n = pkt(&f, 1, F_SYN, CISN, 0, NULL, b);
    d2k_http80_packet(h, b, n, 0, K, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 0, F_SYN | F_ACK, SISN, CISN + 1, NULL, b);
    d2k_http80_packet(h, b, n, 300 * MS, K + 98 * MS, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    d2k_http80_packet(h, b, n, 301 * MS, K + 99 * MS, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    d2k_http80_packet(h, b, n, 302 * MS, K + 99 * MS + 700000ull, out, sizeof out, rst, sizeof rst, &r);
    CHECK(r.injection && r.rtt_ns == 98 * MS && r.reply_ns == 700000ull,
          "вставка по меткам ядра не узнана или замер не по ядру");
    d2k_http80_free(h);
}

static void test_https_table(void) {
    d2k_http80 *h = d2k_http80_new();
    CHECK(d2k_http80_set_https(h, "", 0, 10) != 0, "пустое имя принято");
    CHECK(d2k_http80_set_https(h, "bad name", 8, 10) != 0, "имя с пробелом принято");
    CHECK(d2k_http80_set_https(h, "Example.COM", 11, 100) == 0, "имя не принято");
    CHECK(d2k_http80_https(h, "example.com", 99), "имя не найдено без учёта регистра");
    CHECK(!d2k_http80_https(h, "example.com", 100), "имя живёт дольше срока");
    CHECK(!d2k_http80_https(h, "www.example.com", 1), "поддомен принят за имя");
    CHECK(d2k_http80_set_https(h, "example.com", 11, 0) == 0 && !d2k_http80_https(h, "example.com", 1),
          "имя не снимается нулевым сроком");
    char name[32];
    for (unsigned i = 0; i < D2K_HTTP80_NAMES + 20; i++) {
        int k = snprintf(name, sizeof name, "n%u.example", i);
        CHECK(d2k_http80_set_https(h, name, (size_t)k, 1000 + i) == 0, "полная таблица отказала");
    }
    int k = snprintf(name, sizeof name, "n%u.example", D2K_HTTP80_NAMES + 19);
    (void)k;
    CHECK(d2k_http80_https(h, name, 1), "свежее имя вытеснено");
    CHECK(!d2k_http80_https(h, "n0.example", 1), "вытеснено не самое раннее");

    /* Срок вышел — вставка снова проходит как есть. */
    CHECK(d2k_http80_set_https(h, "rutracker.org", 13, 10 * MS) == 0, "имя не принято");
    flow f = flow4(57000);
    open_flow(h, &f, 0, GET);
    size_t n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    PKT(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(r.injection && !r.answered && r.action == D2K_HTTP80_PASS,
          "истёкшее знание об HTTPS всё ещё переводит на https");
    d2k_http80_free(h);

    /* Замена не помещается в буфер — вставка проходит, а не теряется. */
    h = d2k_http80_new();
    CHECK(d2k_http80_set_https(h, "rutracker.org", 13, 1000 * MS) == 0, "имя не принято");
    f = flow4(57001);
    open_flow(h, &f, 0, GET);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    d2k_http80_packet(h, b, n, 99 * MS + 700000ull, 0, out, 64, rst, sizeof rst, &r);
    CHECK(r.injection && r.action == D2K_HTTP80_PASS, "замена без места не прошла как есть");
    d2k_http80_free(h);
}

/* Field h: a complete first response does not cover the next request.
 * Retransmission and a request-looking body must not create another request. */
/* A portal header may span TCP packets. The first fragment already went
 * to the client, so a late recognition must report, never inject a new 307. */
static void test_response_framing(void) {
    const char *bad[]={
      "HTTP/1.1 200 OK\r\nX: x\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
      "HTTP/1.1 200 O\rK\r\nContent-Length: 0\r\n\r\n",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\"unterminated\r\nx\r\n0\r\n\r\n",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n:\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\n"};
    for(size_t j=0;j<sizeof bad/sizeof *bad;j++) {
        d2k_http_response x={0};
        for(size_t k=0;k<strlen(bad[j]);k++)d2k_http_response_feed(&x,(const uint8_t *)bad[j]+k,1,0);
        d2k_http_response_feed(&x,NULL,0,1);
        CHECK(x.invalid && !x.complete,"malformed/partial framing never gives complete");
    }
    const char *good="HTTP/1.1 103 Early Hints\r\nLink: /x\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\"bar\"\r\nx\r\n0\r\nX-Trailer: yes\r\n\r\n";
    d2k_http_response x={0};
    for(size_t k=0;k<strlen(good);k++)d2k_http_response_feed(&x,(const uint8_t *)good+k,1,0);
    CHECK(x.complete && !x.invalid && x.status==200 && x.body_bytes==1,"interim and split chunk framing");
}

static void test_response_completion(void) {
    const char *heads[]={
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"};
    for(int v6=0;v6<2;v6++) for(int mode=0;mode<3;mode++) {
        d2k_http80 *h=d2k_http80_new();flow f=v6?flow6(52200):flow4(52200);
        uint64_t t=9000*MS;open_flow(h,&f,t,GET);
        uint8_t plan[16]={8},trial[16]={0};
        d2k_binding_context binding={.generation=9,.kind=D2K_BIND_NAME,
            .family=(uint8_t)(v6?6:4),.shape=D2K_PLAN_SHAPE_HTTP,.epoch={7}};
        d2k_http80_executed(h,b,(v6?60:40)+strlen(GET),t+99*MS,81,plan,trial,&binding);
        uint32_t seq=SISN+1,ack=CISN+1+(uint32_t)strlen(GET);
        size_t n=pkt(&f,0,F_ACK|F_PSH,seq,ack,heads[mode],b);
        PKT(h,b,n,t+197*MS,&r);seq+=(uint32_t)strlen(heads[mode]);
        CHECK(!r.response,"headers alone cannot complete a live body");
        const char *part=mode==1?"4\r\nab":"ab";
        n=pkt(&f,0,F_ACK|F_PSH,seq,ack,part,b);
        PKT(h,b,n,t+198*MS,&r);seq+=(uint32_t)strlen(part);
        CHECK(!r.response,"partial live body remains pending");
        PKT(h,b,n,t+199*MS,&r);
        CHECK(!r.response,"duplicate body does not complete or double count");
        part=mode==1?"cd\r\n0\r\nX-Trailer: yes\r\n\r\n":"cd";
        n=pkt(&f,0,F_ACK|F_PSH|(mode==2?F_FIN:0),seq,ack,part,b);
        PKT(h,b,n,t+200*MS,&r);
        CHECK(r.response==1 && r.status==200 && r.body_bytes==4,"complete framing of live response");
        CHECK(r.request_no==1 && r.execution_id==81 && d2k_binding_equal(&r.binding,&binding),
              "complete response retains its actual request execution");
        PKT(h,b,n,t+201*MS,&r);
        CHECK(!r.response,"completion emitted exactly once");
        d2k_http80_free(h);
    }
}

static void test_response_delivery(void) {
    for(int v6=0;v6<2;v6++) for(int early=0;early<2;early++) {
        d2k_http80 *h=d2k_http80_new();flow f=v6?flow6(52300):flow4(52300);
        uint64_t t=10000*MS;open_flow(h,&f,t,GET);
        const char *head="HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n";
        uint32_t ack=CISN+1+(uint32_t)strlen(GET);
        size_t n=pkt(&f,0,F_ACK|F_PSH,SISN+1,ack,head,b);
        PKT(h,b,n,t+197*MS,&r);d2k_http80_delivered(h,b,n,!early,&r);
        if(early)CHECK(r.response==2,"failed header delivery makes live result unknown");
        n=pkt(&f,0,F_ACK|F_PSH,SISN+1+(uint32_t)strlen(head),ack,"ok",b);
        PKT(h,b,n,t+198*MS,&r);d2k_http80_delivered(h,b,n,early,&r);
        CHECK(r.response!=1,"no complete witness after failed delivery anywhere in response");
        d2k_http80_free(h);
    }
}

static void test_retransmitted_fin(void) {
    d2k_http80 *h=d2k_http80_new();flow f=flow4(52440);uint64_t t=12000*MS;
    open_flow(h,&f,t,GET);
    const char *msg="HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok";
    uint32_t ack=CISN+1+(uint32_t)strlen(GET);
    size_t n=pkt(&f,0,F_ACK|F_PSH,SISN+1,ack,msg,b);PKT(h,b,n,t+197*MS,&r);
    CHECK(!r.response,"close framing waits for FIN");
    n=pkt(&f,0,F_ACK|F_PSH|F_FIN,SISN+1,ack,msg,b);PKT(h,b,n,t+198*MS,&r);
    CHECK(r.response==1 && r.body_bytes==2,"new FIN on repeated bytes completes once without counting bytes twice");
    d2k_http80_free(h);
}

static void test_response_gap(void) {
    for(int mode=0;mode<4;mode++) {
        d2k_http80 *h=d2k_http80_new();flow f=flow4(52450);uint64_t t=12000*MS;
        open_flow(h,&f,t,GET);
        const char *head="HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab";
        uint32_t ack=CISN+1+(uint32_t)strlen(GET),seq=SISN+1;
        size_t n=pkt(&f,0,F_ACK|F_PSH,seq,ack,head,b);PKT(h,b,n,t+197*MS,&r);
        seq+=(uint32_t)strlen(head);
        n=pkt(&f,0,F_ACK|(mode==2?F_RST:mode==3?F_FIN:F_PSH),
            mode==0?seq+1:mode==1?seq-1:seq,ack,mode>=2?NULL:"cd",b);
        PKT(h,b,n,t+198*MS,&r);
        CHECK(r.response==2,"gap overlap reset or premature FIN is unknown, not complete");
        n=pkt(&f,1,F_ACK|F_PSH,ack,seq+10,GET,b);PKT(h,b,n,t+199*MS,&r);
        n=pkt(&f,0,F_ACK|F_PSH,seq+10,ack+(uint32_t)strlen(GET),
              "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",b);
        PKT(h,b,n,t+200*MS,&r);
        CHECK(r.response!=1,"unknown response boundary cannot be reset by client ACK into a new proof");
        d2k_http80_free(h);
    }
}

static void test_late_portal_not_complete(void) {
    d2k_http80 *h=d2k_http80_new();flow f=flow4(52400);uint64_t t=12000*MS;
    open_flow(h,&f,t,GET);
    const char *portal="HTTP/1.1 302 Found\r\nLocation: http://lawfilter.ertelecom.ru/\r\nContent-Length: 0\r\n\r\n";
    size_t n=pkt(&f,0,F_ACK|F_PSH,SISN+1,CISN+1+(uint32_t)strlen(GET),portal,b);
    PKT(h,b,n,t+250*MS,&r);
    CHECK(!r.injection && r.response==3,"late portal violates class criterion without timing proof of injection");
    d2k_http80_free(h);
}

static void test_split_portal(void) {
    for(int v6=0;v6<2;v6++) {
        d2k_http80 *h=d2k_http80_new();flow f=v6?flow6(52100):flow4(52100);
        uint64_t t=8000*MS;open_flow(h,&f,t,GET);
        CHECK(!d2k_http80_set_https(h,"rutracker.org",12,t+10000*MS),"split portal HTTPS fixture");
        const size_t cut=40;char first[64];memcpy(first,INJECT,cut);first[cut]=0;
        size_t n=pkt(&f,0,F_ACK|F_PSH,SISN+1,CISN+1+(uint32_t)strlen(GET),first,b);
        PKT(h,b,n,t+99*MS+700000,&r);
        CHECK(!r.injection,"incomplete portal header is not yet evidence");
        n=pkt(&f,0,F_ACK|F_PSH,SISN+1+(uint32_t)cut,CISN+1+(uint32_t)strlen(GET),INJECT+cut,b);
        PKT(h,b,n,t+160*MS,&r);
        CHECK(r.injection,"split Location portal remains observable");
        CHECK(r.action==D2K_HTTP80_PASS,"already delivered prefix cannot be replaced by 307");
        PKT(h,b,n,t+161*MS,&r);
        CHECK(!r.injection,"split portal retransmission is not new evidence");
        d2k_http80_free(h);
    }
}

static void test_keepalive_later(void) {
    for (int v6 = 0; v6 < 2; v6++) {
    for (int bound = 0; bound < 2; bound++) {
    for (int large = 0; large < 2; large++) {
    d2k_http80 *h = d2k_http80_new();
    const uint64_t T = 7000 * MS;
    flow f = v6 ? flow6(52000) : flow4(52000);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    open_flow(h, &f, T, GET);
    uint8_t plan[16] = {0x42}, trial[16] = {0};
    d2k_binding_context binding={.generation=41,.kind=D2K_BIND_NAME,
        .family=(uint8_t)(v6?6:4),.shape=D2K_PLAN_SHAPE_HTTP,.epoch={0x81}};
    d2k_http80_executed(h, b, (v6 ? 60 : 40) + strlen(GET), T + 99 * MS, 71, plan, trial, &binding);
    static const char OK200[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const char *first=large?"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6000\r\n":OK200;
    size_t n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, req_end, first, b);
    PKT(h, b, n, T + 197 * MS, &r);
    CHECK(!r.injection && r.action == D2K_HTTP80_PASS, "real first response is neutral");
    uint32_t s2 = SISN + 1 + (uint32_t)strlen(first);
    if(large) {
        char body[1537];memset(body,'x',1536);body[1536]=0;
        CHECK(!r.response,"24 KiB chunk response cannot complete on headers");
        for(unsigned i=0;i<16;i++) {
            n=pkt(&f,0,F_ACK|(i%2?F_PSH:0),s2,req_end,body,b);
            PKT(h,b,n,T+(198+i)*MS,&r);s2+=1536;
            CHECK(!r.response,"24 KiB body waits for terminating chunk including non-PSH segments");
        }
        n=pkt(&f,0,F_ACK|F_PSH,s2,req_end,"\r\n0\r\n\r\n",b);
        PKT(h,b,n,T+220*MS,&r);s2+=7;
        CHECK(r.response==1 && r.body_bytes==24576 && r.execution_id==71,"field-shaped 24 KiB first response completes its own execution");
    }
    /* Old request retransmission must not disable observation of the next. */
    n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    PKT(h, b, n, T + 250 * MS, &r);
    n = pkt(&f, 1, F_ACK | F_PSH, req_end, s2, GET, b);
    PKT(h, b, n, T + 300 * MS, &r);
    CHECK(!r.injection && r.action == D2K_HTTP80_PASS, "second request passes unchanged");
    binding.generation=42;
    if (bound) d2k_http80_executed(h, b, n, T + 300 * MS, 72, plan, trial, &binding);
    binding.generation=43;binding.epoch[0]=0x82;
    n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    d2k_http80_executed(h, b, n, T + 300 * MS, 999, plan, trial, &binding);
    uint32_t req2_end = req_end + (uint32_t)strlen(GET);
    n = pkt(&f, 0, F_ACK | F_PSH | F_FIN, s2, req2_end, INJECT, b);
    PKT(h, b, n, T + 300 * MS + 500000ull, &r);
    CHECK(r.injection && r.action == D2K_HTTP80_PASS && r.len == 0,
          "live portal on second request must be reported, not silently ignored");
    CHECK(!strcmp(r.host, "RuTracker.org"), "second request evidence retains target");
    CHECK(!strcmp(r.request_path, "/forum/index.php"), "failed request path must survive live evidence");
    CHECK(r.execution_id == (bound ? 72u : 0u) &&
          (bound ? !memcmp(r.plan_id, plan, 16) : r.plan_id[0] == 0),
          "portal must identify the completed execution of this request");
    CHECK(bound ? (r.binding.generation==42 && r.binding.epoch[0]==0x81) : !d2k_binding_known(&r.binding),
          "portal keeps its request binding, not first request or newer mutable binding");
    PKT(h, b, n, T + 300 * MS + 600000ull, &r);
    CHECK(!r.injection && r.action == D2K_HTTP80_PASS, "portal retransmission is not new evidence");
    d2k_http80_stats st = d2k_http80_get_stats(h);
    CHECK(st.requests == 2 && st.injections == 1 && st.answered == 0 && st.dropped == 0,
          "both requests and exactly one portal must be counted");
    d2k_http80_free(h);
    }
    }
    }
}

/* ПОЛЕ 04.10.2026, 13:17:59: Safari показал портал провайдера, а у d2kd
   за всю минуту «запросов 13 → 13» и ни одной вставки — событие
   контроллеру не родилось вовсе. По одному счётчику запросов не отличить
   «запроса к :80 не было» (кэш браузера) от «был, но его здесь не разобрать»:
   соединение открыто до запуска d2kd (keep-alive), запрос не целиком в
   первом сегменте (большие Cookie), следующий запрос соединения. Каждый
   такой случай — свой счётчик в сводке. */
static void test_unseen_counted(void) {
    d2k_http80 *h = d2k_http80_new();
    const uint64_t T = 9000 * MS;
    /* 1. Соединение без SYN в таблице: запрос по keep-alive, открытому до
       запуска d2kd. */
    flow a = flow4(53000);
    size_t n = pkt(&a, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    PKT(h, b, n, T, &r);
    CHECK(r.action == D2K_HTTP80_PASS && !r.injection, "запрос чужого соединения не прошёл как есть");
    /* Чистый ACK клиента без нагрузки — не запрос, не считается. */
    n = pkt(&a, 1, F_ACK, CISN + 1, SISN + 1, NULL, b);
    PKT(h, b, n, T + MS, &r);
    /* 2. Запрос не целиком в первом сегменте. */
    flow c = flow4(53001);
    open_flow(h, &c, T, "GET / HTTP/1.1\r\nHost: www.fast-torrent.ru\r\nCookie: a=b\r\n");
    /* 3. Второй запрос того же соединения после настоящего ответа. */
    flow k = flow4(53002);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    open_flow(h, &k, T, GET);
    static const char OK200[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    n = pkt(&k, 0, F_ACK | F_PSH, SISN + 1, req_end, OK200, b);
    PKT(h, b, n, T + 200 * MS, &r);
    n = pkt(&k, 1, F_ACK | F_PSH, req_end, SISN + 1 + (uint32_t)strlen(OK200), GET, b);
    PKT(h, b, n, T + 300 * MS, &r);
    d2k_http80_stats st = d2k_http80_get_stats(h);
    CHECK(st.requests == 3, "полный Host с незавершённым Cookie тоже начинает наблюдение");
    CHECK(st.untracked == 1, "запрос соединения без SYN в таблице не сосчитан");
    CHECK(st.unparsed == 0, "незавершённый Cookie ошибочно отвергнут вместо ожидания хвоста");
    CHECK(st.later == 1, "следующий запрос соединения не сосчитан");
    d2k_http80_free(h);
}

static void test_segmented_headers(void) {
 for(int v6=0;v6<2;v6++) {
  d2k_http80 *h=d2k_http80_new();flow f=v6?flow6(56000):flow4(56000);
  const char *first="GET / HTTP/1.1\r\nHost: portal-target.example\r\nCookie: beginning";
  const char *tail="-end\r\n\r\n";
  const char *answer="HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
  open_flow(h,&f,MS,first);
  const uint8_t plan[16]={1},trial[16]={0};
  d2k_binding_context binding={.generation=7,.kind=D2K_BIND_NAME,
    .family=(uint8_t)(v6?6:4),.shape=D2K_PLAN_SHAPE_HTTP,.epoch={9}};
  d2k_http80_executed(h,b,(v6?60:40)+strlen(first),100*MS,81,plan,trial,&binding);
  uint32_t seq=CISN+1+(uint32_t)strlen(first);
  size_t n=pkt(&f,1,F_ACK|F_PSH,seq,SISN+1,tail,b);seq+=(uint32_t)strlen(tail);
  PKT(h,b,n,101*MS,&r);
  n=pkt(&f,0,F_ACK|F_PSH,SISN+1,seq,answer,b);PKT(h,b,n,200*MS,&r);
  CHECK(r.response==1 && r.status==200,"complete response after segmented request is observed");
  CHECK(r.execution_id==81 && r.request_no==1 && d2k_binding_equal(&r.binding,&binding),
        "early execution identity survives fragmented request headers");
  n=pkt(&f,1,F_ACK|F_PSH,seq,SISN+1+(uint32_t)strlen(answer),GET,b);seq+=(uint32_t)strlen(GET);
  PKT(h,b,n,210*MS,&r);
  d2k_http80_executed(h,b,n,210*MS,82,plan,trial,&binding);
  n=pkt(&f,0,F_ACK|F_PSH,SISN+1+(uint32_t)strlen(answer),seq,INJECT,b);PKT(h,b,n,210*MS+700000,&r);
  CHECK(r.injection,"portal on next request after segmented headers is observed");
  CHECK(r.execution_id==82 && r.request_no==2 && d2k_binding_equal(&r.binding,&binding),
        "portal belongs to the second request execution");
  d2k_http80_free(h);
 }

}

static void test_request_stream(void) {
    const char *cases[]={
        "GET / HTTP/1.1\r\nHost: a.example\r\nCookie: large-value\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 4\r\n\r\nbody",
        "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nbody",
        "GET / HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a.example\r\nUpgrade: websocket\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 1 2\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length : 0\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a.example\r\nCookie: x\r\n folded\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n"
    };
    for(size_t k=0;k<sizeof cases/sizeof cases[0];k++)for(size_t cut=1;cut<strlen(cases[k]);cut++) {
        const uint8_t *p=(const uint8_t *)cases[k];size_t n=strlen(cases[k]);
        d2k_http_request_stream st;d2k_http_request_stream_init(&st,0xfffffff0u);
        d2k_http_request_stream_feed(&st,st.start,p,cut);
        /* A full retransmission is not new framing input. */
        d2k_http_request_stream_feed(&st,st.start,p,cut);
        d2k_http_request_stream_feed(&st,st.start+(uint32_t)cut,p+cut,n-cut);
        CHECK((!st.invalid && st.header_done && !st.past_end && st.next==st.end)==(k<2),
              "every segmentation preserves valid framing and rejects ambiguity");
    }
    d2k_http_request_stream st;const uint8_t *p=(const uint8_t *)cases[0];
    d2k_http_request_stream_init(&st,100);d2k_http_request_stream_feed(&st,100,p,20);
    d2k_http_request_stream_feed(&st,121,p+21,strlen(cases[0])-21);
    CHECK(st.invalid,"missing byte cannot establish boundary");
    d2k_http_request_stream_init(&st,100);d2k_http_request_stream_feed(&st,100,p,20);
    d2k_http_request_stream_feed(&st,119,p+19,strlen(cases[0])-19);
    CHECK(st.invalid,"partial overlap cannot establish boundary");
}

/* ОБРЫВ ОТВЕТА БЕЗ ПОРТАЛА (поле 15.10.2026, fast-torrent.ru). Стили и
 * скрипты страницы идут с http://media5.cdnbase.com, и коробка обрывает
 * ответ на 23 пакетах (33120 из 106050 байт): ни портала, ни RST — сервер
 * просто замолкает. Наблюдатель это видел и молчал: исход был только у
 * запроса под планом, а таймера не было вовсе. Обрыв — ответ с заявленной
 * длиной встал раньше конца: ни байты сервера, ни ACK клиента не двигаются
 * дольше max(3·RTT, 2 с), либо клиент закрыл соединение, не дождавшись.
 * ACK клиента — второй свидетель: под PPE Keenetic тело ответа после ~30
 * пакетов идёт мимо очереди, а пакеты клиента к :80 видны всегда. */
static d2k_http80_res cut_seen;
static int cut_count;
static void cut_cb(void *ctx, const d2k_http80_res *res) { (void)ctx; cut_seen = *res; cut_count++; }

static void test_response_cut(void) {
    static const char CSS[] = "GET /media/theme/fast.5.css HTTP/1.1\r\nHost: media5.cdnbase.com\r\n"
                              "User-Agent: t\r\n\r\n";
    static char body[1441];
    memset(body, 'x', 1440); body[1440] = 0;
    const char *fixed = "HTTP/1.1 200 OK\r\nContent-Length: 106050\r\n\r\n";
    for (int mode = 0; mode < 5; mode++) {
        /* 0 сервер встал, 1 видны только ACK клиента, 2 клиент закрыл,
           3 полный ответ, 4 длина не заявлена */
        d2k_http80 *h = d2k_http80_new();
        flow f = flow4((uint16_t)(53000 + mode));
        uint64_t t = 20000 * MS;
        open_flow(h, &f, t, CSS);
        uint32_t ack = CISN + 1 + (uint32_t)strlen(CSS), seq = SISN + 1;
        const char *hd = mode == 3 ? "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" :
                         mode == 4 ? "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" : fixed;
        size_t n = pkt(&f, 0, F_ACK | F_PSH, seq, ack, hd, b);
        PKT(h, b, n, t + 197 * MS, &r);
        seq += (uint32_t)strlen(hd);
        uint64_t last = t + 197 * MS;
        if (mode != 3) {
            for (int i = 0; i < 22; i++) {
                n = pkt(&f, 0, F_ACK, seq, ack, body, b);
                PKT(h, b, n, t + (uint64_t)(198 + i) * MS, &r);
                CHECK(r.response == 0, "a body in progress has no outcome yet");
                seq += 1440; last = t + (uint64_t)(198 + i) * MS;
            }
        }
        cut_count = 0;
        d2k_http80_sweep(h, last + 1900 * MS, cut_cb, NULL);
        CHECK(cut_count == 0, "a stall shorter than max(3 RTT, 2 s) is not a cut");
        if (mode == 1) {
            uint32_t a = seq;
            for (int i = 1; i <= 10; i++) {
                a += 2 * 1440;
                n = pkt(&f, 1, F_ACK, ack, a, NULL, b);
                PKT(h, b, n, last + (uint64_t)i * 1000 * MS, &r);
            }
            d2k_http80_sweep(h, last + 11500 * MS, cut_cb, NULL);
            CHECK(cut_count == 0, "advancing client ACKs keep an unseen response alive");
            last += 10000 * MS; seq = a;
        }
        if (mode == 2) {
            n = pkt(&f, 1, F_ACK | F_FIN, ack, seq, NULL, b);
            PKT(h, b, n, last + 500 * MS, &r);
            CHECK(r.response == 4 && strcmp(r.host, "media5.cdnbase.com") == 0 &&
                  strcmp(r.request_path, "/media/theme/fast.5.css") == 0 && r.body_bytes == 22u * 1440u,
                  "client close mid-body is a cut with Host, path and received body");
            d2k_http80_sweep(h, last + 5000 * MS, cut_cb, NULL);
            CHECK(cut_count == 0, "a cut told on close is not told again by the sweep");
            d2k_http80_free(h);
            continue;
        }
        d2k_http80_sweep(h, last + 2100 * MS, cut_cb, NULL);
        if (mode == 3 || mode == 4) {
            CHECK(cut_count == 0, mode == 3 ? "a complete response is never a cut"
                                            : "without a length claim a stall is not a cut");
        } else {
            CHECK(cut_count == 1 && cut_seen.response == 4 &&
                  strcmp(cut_seen.host, "media5.cdnbase.com") == 0 &&
                  strcmp(cut_seen.request_path, "/media/theme/fast.5.css") == 0,
                  "a stalled fixed-length body is a cut");
            CHECK(cut_seen.body_bytes == (uint64_t)(seq - (SISN + 1) - (uint32_t)strlen(fixed)),
                  "the cut reports the received body (by client ACK when server bytes are unseen)");
            d2k_http80_sweep(h, last + 9000 * MS, cut_cb, NULL);
            CHECK(cut_count == 1, "a cut is told once");
        }
        d2k_http80_free(h);
    }
}

static void test_reset_before_http_response(void) {
    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(53100);
    uint64_t t = 30000 * MS;
    open_flow(h, &f, t, GET);
    uint32_t ack = CISN + 1 + (uint32_t)strlen(GET);
    size_t n = pkt(&f, 0, F_ACK | F_RST, SISN + 1, ack, NULL, b);
    PKT(h, b, n, t + 200 * MS, &r);
    CHECK(r.response == 5 && !strcmp(r.host, "RuTracker.org") &&
          !strcmp(r.request_path, "/forum/index.php") && r.body_bytes == 0,
          "a reset before any response is reported with the client's request context");
    d2k_http80_delivered(h, b, n, 0, &r);
    CHECK(r.response == 2, "a reset not delivered to the client is not network evidence");
    d2k_http80_free(h);
}

static void test_retry_before_http_response(void) {
    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(53101);
    uint64_t t = 31000 * MS;
    open_flow(h, &f, t, GET);
    size_t n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    PKT(h, b, n, t + 150 * MS, &r);
    CHECK(r.response == 0, "a duplicate inside the measured RTT is not a failure");
    n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, "GET /forum/", b);
    PKT(h, b, n, t + 400 * MS, &r);
    CHECK(r.response == 6 && !strcmp(r.host, "RuTracker.org") &&
          !strcmp(r.request_path, "/forum/index.php"),
          "a repeated full request without a response is reported with its path");
    n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    PKT(h, b, n, t + 700 * MS, &r);
    CHECK(r.response == 0, "a repeated request is reported only once per flow");
    d2k_http80_free(h);
}

int main(void) {
    test_reset_before_http_response();
    test_retry_before_http_response();
    test_field_injection(0);
    test_field_injection(1);
    test_field_injection_megafon();
    test_not_injection();
    test_table_bound();
    test_garbage();
    test_answer(0);
    test_answer(1);
    test_https_table();
    test_swap_failure();
    test_kernel_clock();
    test_keepalive_later();
    test_split_portal();
    test_response_completion();
    test_response_framing();
    test_response_delivery();
    test_late_portal_not_complete();
    test_response_gap();
    test_retransmitted_fin();
    test_unseen_counted();
    test_segmented_headers();
    test_request_stream();
    test_response_cut();
    if (fails) {
        printf("test_http80: провалов %d\n", fails);
        return 1;
    }
    printf("test_http80: все проверки прошли\n");
    return 0;
}
