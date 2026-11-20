/* Exercise production TX/RX sequencing. TCP is localhost-only; TLS and
 * baseline replies are deterministic, so no public service is probed. */
#include "volume.c"

static int failures, legacy_calls, modern_calls, baseline_calls;
static int expected_legacy;
static const char *expected_path;
static size_t expected_wire;
static int mark_calls;
static int repeat_missing, opaque_reply;
/* Поле 12.10.2026, www.tampermonkey.net: /style.css обрывается на линии восемь
   раз из восьми (15963 против 30182 с VPS), но ОДИН повтор зонда дошёл до
   конца. Шум линии не опровергает обрыв; третий прогон решает. */
static int noisy_second, third_also_full;
/* Поле 12.10.2026, CDN-хосты soundcloud: на единственный «/» style.sndcdn.com
   отдаёт завершённый 403 с телом 243 байта (то же и с VPS — так отвечает сам
   сервер), api-v2.soundcloud.com — 401 с пустым телом. До измеряемой полосы
   12 КБ таким ответам не хватает двух порядков, а НАСТОЯЩИЙ ресурс того же
   имени режется: /css/soehne-*.css — 301328 байт с VPS против 15985 с линии. */
static int short_then_hint, hint_status;
/* Что отдаёт подсказанный ресурс: 0 — обрыв, 1 — нет TLS, 2 — завершённый
   ответ ВЫШЕ полосы (настоящее отрицательное измерение). */
static int retry_outcome;
/* Поле 17.10.2026, rua.gr, вход без ECH: TLS 1.3 согласован, а на GET не
   пришло ни байта (HTTP 0, wire=0) — с роутера так 2 из 5 замеров подряд,
   при этом остальные identity режутся на ~23 КБ. Ответ не начался — мерить
   было нечем. Маска номеров вызовов, которые вернут пустой ответ. */
static unsigned unstarted;
/* Поле 17.10.2026, LR-rx8-1, rua.gr: «identity-1 HTTP 200, тело 4497/0,
   complete=0» — поток встал на ~6 КБ, ниже полосы: тоже нечем мерить. */
static unsigned early_cut;
static int full_non_2xx;
static int expected_gzip_call2 = -1;
static const char *hint_host, *hint_for_path, *cut_path, *last_path;
static int expected_gzip_call = 2;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "volume-context:%d: %s\n", __LINE__, #c); failures++; } } while (0)

static int mark_ok(int fd, uint32_t mark) {
    (void)fd; CHECK(mark == 0x2f); mark_calls++; return 0;
}
d2k_mark_fn d2k_mark_hook = mark_ok;

/* Scripted TLS TX (task 60): the TLS session is a stub, but the TCP socket is
   a real loopback connection, so the server's FIN/RST is a kernel fact that
   the ladder must classify itself. how: 0 healthy, 1 FIN instead of response
   tx_fail_step, 2 RST instead of it, 3 FIN right after response tx_fail_step-1. */
static int tx_script, tx_listen = -1, tx_server = -1, tx_client = -1;
static int tx_fail_step, tx_fail_how, tx_writes;
static uint64_t tx_written;
static unsigned tx_pad_sum[D2K_VOL_STEPS];
static size_t tx_resp_off;
static int tx_session;
static void tx_server_close(int rst) {
    if (tx_server < 0) return;
    /* Unread data turns close() into RST on Linux and BSD: drain it first so
       the FIN cases really send FIN. */
    for (;;) {
        struct pollfd q = { tx_server, POLLIN, 0 };
        char sink[4096];
        if (poll(&q, 1, 0) <= 0 || read(tx_server, sink, sizeof sink) <= 0) break;
    }
    if (rst) { struct linger lg = {1, 0}; (void)setsockopt(tx_server, SOL_SOCKET, SO_LINGER, &lg, sizeof lg); }
    close(tx_server); tx_server = -1;
    struct pollfd p = { tx_client, POLLIN, 0 };
    (void)poll(&p, 1, 1000); /* the kernel has seen it before we report */
}

int d2k_tls_connect(int fd, const char *sni, int ms, size_t wire,
                    d2k_tls **out, char *err, size_t cap) {
    (void)fd; (void)sni; (void)ms; *out = NULL;
    CHECK(!expected_legacy && wire == expected_wire); modern_calls++;
    if (tx_script) {
        tx_client = fd; tx_server = accept(tx_listen, NULL, NULL);
        CHECK(tx_server >= 0);
        *out = (d2k_tls *)&tx_session; return 0;
    }
    snprintf(err, cap, "TX reset"); return -1;
}
int d2k_tls12_connect(int fd, const char *sni, int ms, size_t wire,
                      d2k_tls12 **out, char *err, size_t cap) {
    (void)fd; (void)sni; (void)ms; *out = NULL;
    CHECK(expected_legacy && wire == expected_wire); legacy_calls++;
    snprintf(err, cap, "TX reset"); return -1;
}
int d2k_tls_write(d2k_tls *t, const uint8_t *b, size_t n, char *e, size_t c) {
    (void)e; (void)c;
    if (!tx_script) { (void)t; (void)b; (void)n; CHECK(0); return -1; }
    CHECK(t == (d2k_tls *)&tx_session && tx_writes < D2K_VOL_STEPS);
    const char *pad = NULL;
    for (size_t i = 0; i + 7 <= n && !pad; i++)
        if (!memcmp(b + i, "X-Pad: ", 7)) pad = (const char *)b + i;
    unsigned sum = 2166136261u;
    for (const char *q = pad ? pad + 7 : NULL; q && q < (const char *)b + n && *q != '\r'; q++)
        sum = (sum ^ (unsigned char)*q) * 16777619u;
    if (tx_writes < D2K_VOL_STEPS) tx_pad_sum[tx_writes] = pad ? sum : 0;
    tx_writes++; tx_written += n;
    /* The bytes really travel: after the server has closed, the peer kernel
       answers them with RST, as a real TLS write would provoke. */
    int fl = 0;
#ifdef MSG_NOSIGNAL
    fl = MSG_NOSIGNAL;
#endif
    if (tx_client >= 0 && send(tx_client, b, n, fl) == (ssize_t)n && tx_server >= 0) {
        /* The stub server consumes the request now: bytes still in flight at
           a later close() would make the kernel answer them with RST and turn
           a FIN case into an RST case. */
        size_t got = 0; char sink[4096];
        while (got < n) {
            struct pollfd q = { tx_server, POLLIN, 0 };
            if (poll(&q, 1, 1000) <= 0) break;
            ssize_t r = read(tx_server, sink, n - got < sizeof sink ? n - got : sizeof sink);
            if (r <= 0) break;
            got += (size_t)r;
        }
        CHECK(got == n);
    }
    return 0;
}
int d2k_tls12_write(d2k_tls12 *t, const uint8_t *b, size_t n, char *e, size_t c) {
    (void)t; (void)b; (void)n; (void)e; (void)c; CHECK(0); return -1;
}
long d2k_tls_read(d2k_tls *t, uint8_t *b, size_t n, int ms, char *e, size_t c) {
    (void)ms;
    if (!tx_script) { (void)t; (void)b; (void)n; (void)e; (void)c; CHECK(0); return -1; }
    static const char resp[] = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n";
    int k = tx_writes - 1;
    CHECK(t == (d2k_tls *)&tx_session && n >= 1);
    if ((tx_fail_how == 1 || tx_fail_how == 2) && k == tx_fail_step) {
        tx_server_close(tx_fail_how == 2);
        /* What the TLS layer reports for a FIN at a record boundary. */
        snprintf(e, c, "соединение закрыто на 0-м байте из 5");
        return -1;
    }
    if (tx_server < 0) {
        snprintf(e, c, "соединение закрыто на 0-м байте из 5");
        return -1;
    }
    *b = (uint8_t)resp[tx_resp_off++];
    if (tx_resp_off == sizeof resp - 1) {
        tx_resp_off = 0;
        if (tx_fail_how == 3 && k == tx_fail_step - 1) tx_server_close(0);
    }
    return 1;
}
long d2k_tls12_read(d2k_tls12 *t, uint8_t *b, size_t n, int ms, char *e, size_t c) {
    (void)t; (void)b; (void)n; (void)ms; (void)e; (void)c; CHECK(0); return -1;
}
void d2k_tls_free(d2k_tls *t) { CHECK(tx_script && t == (d2k_tls *)&tx_session); }
void d2k_tls12_free(d2k_tls12 *t) { (void)t; CHECK(0); }

d2k_ver_result d2k_verify_probe_baseline(const char *ip, uint16_t port,
    const char *sni, int ms, size_t wire, int legacy, int encoding, uint32_t mark) {
    (void)ip; (void)port; (void)ms;
    CHECK(strcmp(sni, "context.test") == 0 && legacy == expected_legacy &&
          wire == expected_wire && mark == 0x2f);
    CHECK(encoding == (baseline_calls == expected_gzip_call ||
                       baseline_calls == expected_gzip_call2));
    d2k_ver_result r = {0};
    if (full_non_2xx) {
        r.fd = -1; r.level = D2K_VER_APPLICATION; r.name_ok = 1;
        r.negotiated_tls = expected_legacy ? 0x0303 : 0x0304;
        r.status = 403; r.body_has_length = 1; r.body_framing_valid = 1;
        r.body_complete = 1;
        r.body_bytes = r.body_expected = 20000;
        r.rx_tls_wire_bytes = 20500;
        baseline_calls++;
        return r;
    }
    r.fd = -1; r.status = 200; r.body_has_length = 1;
    r.body_framing_valid = 1; r.body_expected = 96460;
    r.body_bytes = 23900 + baseline_calls * 10;
    if (encoding) {
        r.body_bytes = r.body_expected = 18000;
        r.body_complete = 1; r.body_encoding = 1;
    }
    if (noisy_second) {
        memset(&r, 0, sizeof r); r.fd = -1;
        r.status = 200; r.body_framing_valid = 1; r.body_chunked = 1;
        if (encoding) {
            r.body_bytes = r.body_expected = 6000;
            r.body_complete = 1; r.body_encoding = 1;
        } else if (baseline_calls == 1) {
            r.body_bytes = r.body_expected = 22094; r.body_complete = 1;
        } else {
            r.body_bytes = baseline_calls == 0 ? 15627 : 15963;
            if (third_also_full && baseline_calls == 2) {
                r.body_complete = 1; r.body_expected = r.body_bytes;
            }
        }
    }
    if (opaque_reply) {
        if (!encoding) {
            memset(&r, 0, sizeof r); r.fd = -1;
            r.level = D2K_VER_HANDSHAKE; r.name_ok = 1;
            r.negotiated_tls = expected_legacy ? 0x0303 : 0x0304;
            r.rx_tls_wire_bytes = 14005 + baseline_calls * 20;
            r.rx_tls_record_missing = 2384 - baseline_calls * 20;
        } else {
            r.level = D2K_VER_APPLICATION; r.name_ok = 1;
            r.negotiated_tls = expected_legacy ? 0x0303 : 0x0304;
            r.body_expected = r.body_bytes = 4000; r.rx_tls_wire_bytes = 4500;
        }
    }
    if (unstarted & (1u << baseline_calls)) {
        memset(&r, 0, sizeof r); r.fd = -1;
        r.level = D2K_VER_HANDSHAKE; r.name_ok = 1; r.negotiated_tls = 0x0304;
        snprintf(r.reason, sizeof r.reason,
                 "нет полных заголовков окончательного HTTP-ответа: не дождались 5 байт");
    }
    if (early_cut & (1u << baseline_calls)) {
        memset(&r, 0, sizeof r); r.fd = -1;
        r.level = D2K_VER_HANDSHAKE; r.name_ok = 1; r.negotiated_tls = 0x0304;
        r.status = 200; r.body_framing_valid = 1; r.body_chunked = 1;
        r.body_bytes = 4497; r.rx_tls_wire_bytes = 6063; r.rx_tls_record_missing = 1342;
    }
    if (repeat_missing && baseline_calls == 1) {
        memset(&r, 0, sizeof r); r.fd = -1;
        snprintf(r.reason, sizeof r.reason, "incomplete TLS record");
    }
    if (short_then_hint) {
        /* Обрыв отдаёт только подсказанный ресурс (cut_path); на любом другом
           пути — завершённый ответ на два порядка меньше полосы. */
        int cut = cut_path && last_path && !strcmp(last_path, cut_path);
        memset(&r, 0, sizeof r); r.fd = -1;
        r.level = D2K_VER_APPLICATION; r.name_ok = 1; r.body_framing_valid = 1;
        r.status = 200;
        if (!cut) {
            r.status = hint_status; r.body_has_length = 1; r.body_complete = 1;
            r.body_bytes = r.body_expected = 243;
            if (hint_host) {
                snprintf(r.resources[0].host, sizeof r.resources[0].host, "%s", hint_host);
                snprintf(r.resources[0].path, sizeof r.resources[0].path, "%s", hint_for_path);
                r.n_resources = 1;
            }
        } else if (retry_outcome == 1) {
            r.status = 0; r.level = D2K_VER_TRANSPORT; r.body_framing_valid = 0;
            snprintf(r.reason, sizeof r.reason, "нет TLS: сброс");
        } else if (retry_outcome == 2) {
            r.body_has_length = 1; r.body_complete = 1;
            r.body_bytes = r.body_expected = 30182;
        } else if (encoding) {
            r.body_chunked = 1; r.body_encoding = 1; r.body_complete = 1;
            r.body_bytes = r.body_expected = 6000;
        } else {
            r.body_chunked = 1;
            r.body_bytes = baseline_calls == 1 ? 15985 : 15968;
        }
    }
    baseline_calls++;
    return r;
}
void d2k_verify_close(d2k_ver_result *r) { CHECK(r->fd == -1); }

d2k_ver_result d2k_verify_probe_path_on(int fd, const char *ip, uint16_t port,
    const char *sni, int ms, size_t wire, int legacy, int encoding,
    uint32_t mark, const char *path) {
    /* В опыте с подсказкой путь меняется по ходу замера, и сверять его с
       одним ожидаемым нельзя: он сам и есть предмет проверки (last_path). */
    CHECK(fd == -1 && (short_then_hint ||
          (expected_path ? path && !strcmp(path, expected_path) : !path)));
    last_path = path;
    return d2k_verify_probe_baseline(ip, port, sni, ms, wire, legacy, encoding, mark);
}

#include <signal.h>
#include <sys/wait.h>

/* ---- task 60: TX ladder correctness ---------------------------------- */

static int head_rc(const char *s, size_t n) {
    volume_head h; memset(&h, 0, sizeof h); char why[160];
    for (size_t i = 0; i < n; i++) {
        int rc = volume_head_feed(&h, (unsigned char)s[i], why, sizeof why);
        if (rc) return rc;
    }
    return 0;
}
#define HEAD(lit) head_rc(lit, sizeof lit - 1)
/* 1 — final reusable head; -2 — the server itself ends or refuses the probe. */
static void head_parser_test(void) {
    CHECK(HEAD("HTTP/1.1 200 OK\r\nServer: x\r\nContent-Length: 5\r\n\r\n") == 1);
    CHECK(HEAD("HTTP/1.1 204\r\n\r\n") == 1);
    CHECK(HEAD("HTTP/1.1 301 Moved\r\nLocation: /a\r\n\r\n") == 1);
    CHECK(HEAD("HTTP/1.1 200 OK\n\n") == 1);
    /* Informational heads precede the final response of the same request. */
    CHECK(HEAD("HTTP/1.1 100 Continue\r\n\r\n") == 0);
    CHECK(HEAD("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n") == 1);
    CHECK(HEAD("HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 204\r\n\r\n") == 1);
    CHECK(HEAD("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 431 Too Large\r\n\r\n") == -2);
    /* Keep-alive: HTTP/1.0 only with an explicit token, HTTP/1.1 unless close. */
    CHECK(HEAD("HTTP/1.0 200 OK\r\n\r\n") == -2);
    CHECK(HEAD("HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\n\r\n") == 1);
    CHECK(HEAD("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n") == -2);
    CHECK(HEAD("HTTP/1.1 200 OK\r\nconnection: Keep-Alive, Close\r\n\r\n") == -2);
    CHECK(HEAD("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n") == -2);
    CHECK(HEAD("HTTP/1.1 200 OK\r\nConnection: closed\r\n\r\n") == 1);
    CHECK(HEAD("HTTP/1.1 200 OK\r\nX-Connection: close\r\n\r\n") == 1);
    /* Server refusal and protocol change are not path evidence. */
    CHECK(HEAD("HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n") == -2);
    CHECK(HEAD("HTTP/1.1 400 Bad Request\r\n\r\n") == -2);
    CHECK(HEAD("HTTP/1.1 503 Service Unavailable\r\n\r\n") == -2);
    CHECK(HEAD("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n") == -2);
    /* Malformed or unparseable heads end the probe without a verdict. */
    CHECK(HEAD("HTTP/2 200\r\n\r\n") == -2);
    CHECK(HEAD("HTTP/1.1 2000 OK\r\n\r\n") == -2);
    CHECK(HEAD("HTTP/1.1 600 X\r\n\r\n") == -2);
    CHECK(HEAD("<html>\r\n") == -2);
    CHECK(HEAD("HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n") == -2);
    static char longline[6000];
    int n = snprintf(longline, sizeof longline, "HTTP/1.1 200 OK\r\nX: ");
    memset(longline + n, 'a', 5000); memcpy(longline + n + 5000, "\r\n\r\n", 4);
    CHECK(head_rc(longline, (size_t)n + 5004) == -2);
}

/* Bounded plain write: a peer that never reads cannot hold the probe beyond
   its deadline, the partial count is reported, the descriptor flags restored. */
static void bounded_send_test(void) {
    int sv[2]; CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    int small = 4096;
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    (void)setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    static char big[1 << 20]; memset(big, 'x', sizeof big);
    size_t sent = 0; char why[160] = "";
    int64_t t0 = now_ms();
    int rc = volume_send_plain(sv[0], big, sizeof big, 300, &sent, why, sizeof why);
    int64_t took = now_ms() - t0;
    CHECK(rc == -1 && sent > 0 && sent < sizeof big);
    CHECK(took >= 250 && took < 3000 && strstr(why, "таймаут") != NULL);
    CHECK(!(fcntl(sv[0], F_GETFL, 0) & O_NONBLOCK));
    close(sv[1]);
    rc = volume_send_plain(sv[0], big, 100, 300, &sent, why, sizeof why);
    CHECK(rc == -1 && sent < 100);
    close(sv[0]);
}

/* Real plain ladder against a scripted loopback server. */
enum { PS_OK, PS_INFO, PS_HTTP10_KA, PS_HTTP10, PS_REFUSE, PS_CLOSE_HDR,
       PS_FIN, PS_FIN_BETWEEN, PS_RST, PS_SILENT };
static void plain_server(int ls, int how, int step, int report) {
    int c = accept(ls, NULL, NULL);
    uint64_t got = 0; char buf[16384]; size_t used = 0; int k = 0;
    while (c >= 0) {
        char *end = NULL;
        for (;;) {
            for (size_t i = 0; i + 4 <= used && !end; i++)
                if (!memcmp(buf + i, "\r\n\r\n", 4)) end = buf + i;
            if (end) break;
            ssize_t r = read(c, buf + used, sizeof buf - used);
            if (r <= 0) goto done;
            used += (size_t)r; got += (uint64_t)r;
        }
        size_t reqlen = (size_t)(end + 4 - buf);
        memmove(buf, buf + reqlen, used - reqlen); used -= reqlen;
        if (k == step && how >= PS_HTTP10) {
            static const char refuse[] = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n";
            static const char closing[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
            static const char old[] = "HTTP/1.0 200 OK\r\n\r\n";
            if (how == PS_REFUSE) { (void)!write(c, refuse, sizeof refuse - 1); goto wait_close; }
            if (how == PS_CLOSE_HDR) { (void)!write(c, closing, sizeof closing - 1); break; }
            if (how == PS_HTTP10) { (void)!write(c, old, sizeof old - 1); break; }
            if (how == PS_FIN) break;
            if (how == PS_RST) {
                struct linger lg = {1, 0};
                (void)setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
                break;
            }
            if (how == PS_SILENT) goto wait_close;
        }
        static const char ok[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        static const char ka10[] = "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
        static const char info[] = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n"
                                   "Link: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\n\r\n";
        const char *resp = how == PS_HTTP10_KA ? ka10 : how == PS_INFO ? info : ok;
        (void)!write(c, resp, strlen(resp));
        k++;
        if (how == PS_FIN_BETWEEN && k == step) break;
    }
    goto done;
wait_close:
    for (;;) { char sink[4096]; ssize_t r = read(c, sink, sizeof sink); if (r <= 0) break; got += (uint64_t)r; }
done:
    if (c >= 0) close(c);
    (void)!write(report, &got, sizeof got);
    (void)!write(report, &k, sizeof k);
    _exit(0);
}

static d2k_vol_result run_plain(int how, int step, uint64_t *got, int *served) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(0x7f000001u);
    socklen_t al = sizeof a;
    CHECK(ls >= 0 && bind(ls, (struct sockaddr *)&a, al) == 0 &&
          getsockname(ls, (struct sockaddr *)&a, &al) == 0 && listen(ls, 1) == 0);
    int pfd[2]; CHECK(!pipe(pfd));
    pid_t pid = fork();
    if (pid == 0) { close(pfd[0]); plain_server(ls, how, step, pfd[1]); }
    close(pfd[1]);
    d2k_vol_result r = d2k_volume_probe_path("127.0.0.1", ntohs(a.sin_port), NULL, 1, 0, 0, 0, NULL);
    *got = 0; *served = -1;
    CHECK(read(pfd[0], got, sizeof *got) == (ssize_t)sizeof *got);
    CHECK(read(pfd[0], served, sizeof *served) == (ssize_t)sizeof *served);
    (void)waitpid(pid, NULL, 0); close(pfd[0]); close(ls);
    return r;
}

static void plain_ladder_test(void) {
    uint64_t got; int served; d2k_vol_result r;
    static const struct { int how, step; d2k_vol_verdict verdict; int served; const char *what; } cases[] = {
        { PS_OK,          0, D2K_VOL_PASSED,      10, "healthy keep-alive" },
        { PS_INFO,        0, D2K_VOL_PASSED,      10, "100/103 before every final head" },
        { PS_HTTP10_KA,   0, D2K_VOL_PASSED,      10, "HTTP/1.0 with keep-alive" },
        { PS_HTTP10,      0, D2K_VOL_SHORT,        0, "HTTP/1.0 without keep-alive" },
        { PS_REFUSE,      5, D2K_VOL_SHORT,        5, "server refuses padded request (431)" },
        { PS_CLOSE_HDR,   5, D2K_VOL_SHORT,        5, "Connection: close" },
        { PS_FIN,         5, D2K_VOL_SHORT,        5, "server FIN instead of response" },
        { PS_FIN_BETWEEN, 5, D2K_VOL_SHORT,        5, "server FIN between responses" },
        { PS_RST,         5, D2K_VOL_CUT,          5, "RST after 12 KB" },
        { PS_SILENT,      5, D2K_VOL_CUT,          5, "silence after 12 KB" },
        { PS_RST,         2, D2K_VOL_SHORT,        2, "RST below 12 KB" },
        { PS_RST,         0, D2K_VOL_UNREACHABLE,  0, "RST on the first request" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        r = run_plain(cases[i].how, cases[i].step, &got, &served);
        int ok = r.verdict == cases[i].verdict && served == cases[i].served &&
                 r.at_kb == (int)(got / 1024);
        if (!ok) fprintf(stderr, "plain %s: verdict=%d at_kb=%d server got %llu bytes, served %d: %s\n",
                         cases[i].what, r.verdict, r.at_kb, (unsigned long long)got, served, r.reason);
        CHECK(ok);
        CHECK(!strcmp(r.tx_reason, r.reason)); /* plain HTTP: no RX ran */
        if (cases[i].verdict == D2K_VOL_SHORT && cases[i].step == 5)
            CHECK(got >= (uint64_t)D2K_VOL_MIN_KB * 1024); /* past the threshold, still no verdict */
    }
}

/* TLS path: FIN, RST and a close between responses on a real loopback TCP. */
static d2k_vol_result run_tls(int how, int step) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(0x7f000001u);
    socklen_t al = sizeof a;
    CHECK(ls >= 0 && bind(ls, (struct sockaddr *)&a, al) == 0 &&
          getsockname(ls, (struct sockaddr *)&a, &al) == 0 && listen(ls, 1) == 0);
    tx_listen = ls; tx_script = 1; tx_fail_how = how; tx_fail_step = step;
    tx_writes = 0; tx_written = 0; tx_resp_off = 0; tx_client = -1;
    memset(tx_pad_sum, 0, sizeof tx_pad_sum);
    expected_legacy = 0; expected_wire = 1489; expected_path = NULL;
    baseline_calls = 0; expected_gzip_call = 2; expected_gzip_call2 = -1;
    d2k_vol_result r = d2k_volume_probe("127.0.0.1", ntohs(a.sin_port), "context.test", 0, 0, 1489, 0x2f);
    if (tx_server >= 0) close(tx_server);
    tx_server = -1; tx_script = 0; tx_client = -1; close(ls);
    return r;
}

static void tls_ladder_test(void) {
    d2k_vol_result r = run_tls(0, 0);
    CHECK(r.verdict == D2K_VOL_PASSED && tx_writes == D2K_VOL_STEPS);
    CHECK(r.at_kb == (int)(tx_written / 1024) && tx_written > (uint64_t)(D2K_VOL_STEPS - 1) * D2K_VOL_CHUNK);
    for (int i = 1; i < D2K_VOL_STEPS; i++)
        for (int j = 1; j < i; j++) CHECK(tx_pad_sum[i] && tx_pad_sum[i] != tx_pad_sum[j]);
    /* RX is a separate measurement and still runs after the ladder. */
    CHECK(r.rx_cut && baseline_calls == 3);

    r = run_tls(1, 5);
    if (r.verdict != D2K_VOL_SHORT) fprintf(stderr, "tls FIN: verdict=%d: %s\n", r.verdict, r.reason);
    CHECK(r.verdict == D2K_VOL_SHORT && r.at_kb == (int)(tx_written / 1024));
    CHECK(tx_written >= (uint64_t)D2K_VOL_MIN_KB * 1024);
    CHECK(r.rx_cut && baseline_calls == 3);
    /* TX and RX evidence stay distinct: reason carries the RX finding the
       scheduler reports, tx_reason what ended the ladder. */
    CHECK(strstr(r.tx_reason, "FIN") != NULL && strstr(r.reason, "FIN") == NULL);
    /* With an RX cut, reason carries the RX evidence text (sched.c reports it
       for packet-budget/wire verdicts). Without one, the TX reason survives. */
    full_non_2xx = 1;
    r = run_tls(1, 5);
    full_non_2xx = 0;
    CHECK(r.verdict == D2K_VOL_SHORT && !r.rx_cut && baseline_calls == 1);
    CHECK(strstr(r.reason, "FIN") != NULL);

    r = run_tls(2, 5);
    if (r.verdict != D2K_VOL_CUT) fprintf(stderr, "tls RST: verdict=%d: %s\n", r.verdict, r.reason);
    CHECK(r.verdict == D2K_VOL_CUT && r.at_kb == (int)(tx_written / 1024));
    CHECK(r.rx_cut && baseline_calls == 3);

    /* Server closed after response 4: the next write would be answered by
       the server's own RST. Not a volume cut, and request 5 is never sent. */
    r = run_tls(3, 5);
    if (r.verdict != D2K_VOL_SHORT) fprintf(stderr, "tls FIN-between: verdict=%d: %s\n", r.verdict, r.reason);
    CHECK(r.verdict == D2K_VOL_SHORT && tx_writes == 5 && r.at_kb == (int)(tx_written / 1024));
}

int main(void) {
    for (int family = 4; family <= 6; family += 2) {
    for (int legacy = 0; legacy <= 1; legacy++) {
    for (int resource = 0; resource <= 1; resource++) {
        int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        struct sockaddr_storage addr = {0};
        socklen_t len;
        const char *ip;
        if (family == 6) {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr;
            a->sin6_family = AF_INET6; a->sin6_addr = in6addr_loopback;
            len = sizeof *a; ip = "::1";
        } else {
            struct sockaddr_in *a = (struct sockaddr_in *)&addr;
            a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(0x7f000001u);
            len = sizeof *a; ip = "127.0.0.1";
        }
        CHECK(fd >= 0 && bind(fd, (struct sockaddr *)&addr, len) == 0);
        CHECK(getsockname(fd, (struct sockaddr *)&addr, &len) == 0 && listen(fd, 2) == 0);
        uint16_t port = family == 6
            ? ntohs(((struct sockaddr_in6 *)&addr)->sin6_port)
            : ntohs(((struct sockaddr_in *)&addr)->sin_port);
        expected_legacy = legacy; expected_wire = legacy ? 512 : 1489;
        baseline_calls = 0;
        expected_path = resource ? "/public/main.css" : NULL;
        d2k_vol_result r = resource
            ? d2k_volume_probe_path(ip, port, "context.test", 0, legacy,
                                    expected_wire, 0x2f, expected_path)
            : d2k_volume_probe(ip, port, "context.test", 0, legacy, expected_wire, 0x2f);
        CHECK(r.verdict == D2K_VOL_UNREACHABLE && r.rx_cut &&
              baseline_calls == 3 && r.rx_at_kb == 23);
        CHECK(r.probes == 1 + baseline_calls);
        /* Задача 26: доказанный обрыв обязан назвать свой путь наверх. Мерили
           по названному ресурсу — он и в результате; мерили по «/» — поле
           пусто, выдумывать «/» нечем. */
        CHECK(resource ? !strcmp(r.measured_path, expected_path) : !r.measured_path[0]);
        if (resource && strcmp(r.measured_path, expected_path))
            fprintf(stderr, "measured_path=\"%s\", ожидался \"%s\"\n",
                    r.measured_path, expected_path);
        close(fd);
    }
    }
    }
    CHECK(modern_calls == 4 && legacy_calls == 4 && mark_calls == 8);
    baseline_calls = 0; repeat_missing = 1; expected_legacy = 0;
    expected_wire = 1536; expected_path = NULL;
    d2k_vol_result partial = {0};
    probe_response_volume(&partial, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(!partial.rx_cut && !partial.rx_direct_complete && baseline_calls == 2);
    CHECK(partial.rx_partial_bytes == 23900);
    CHECK(strstr(partial.rx_reason, "23900") && strstr(partial.rx_reason, "identity-2"));
    repeat_missing = 0; opaque_reply = 1;
    for (int legacy = 0; legacy < 2; legacy++) {
        expected_legacy = legacy; baseline_calls = 0;
        d2k_vol_result wire = {0};
        probe_response_volume(&wire, "127.0.0.1", 443, "context.test", legacy, 1536, 0x2f, NULL);
        CHECK(baseline_calls == 3 && wire.rx_cut && wire.rx_wire_basis);
        CHECK(!wire.rx_partial_bytes && wire.rx_partial_wire_bytes == 14005);
        CHECK(strstr(wire.rx_reason, "14005/14025/4500") != NULL);
    }
    /* ПОЛЕ 12.10.2026, www.tampermonkey.net. /style.css: 30182 байта с VPS
       против 15963 с линии, восемь прогонов байт в байт, без RST и FIN. Зонд
       видел «identity-1 partial=15627; identity-2 HTTP 200 body=22094
       complete=1» и возвращался ни с чем — три эпизода подряд ушли в покой на
       десять минут. Дошедшее измерение расходится с оборванным, а не
       опровергает его: третий identity-прогон подтверждает обрыв, и пара
       считается сошедшейся на двух обрывах, не на одном. */
    opaque_reply = 0; noisy_second = 1; expected_gzip_call = 3;
    expected_legacy = 0; expected_wire = 1536; expected_path = NULL;
    baseline_calls = 0;
    d2k_vol_result noisy = {0};
    probe_response_volume(&noisy, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 4);
    CHECK(noisy.rx_cut && !noisy.rx_wire_basis && noisy.rx_at_kb == 15);
    CHECK(noisy.rx_compressed_complete && noisy.rx_partial_bytes == 15627);
    CHECK(strstr(noisy.rx_reason, "15627/15963") != NULL);
    CHECK(strstr(noisy.rx_reason, "identity-3") != NULL);
    /* Третий прогон тоже дошёл до конца: обрыв не воспроизвёлся, вердикта
       НЕТ, и gzip-контроль не запрашивается — один обрыв ничего не доказывает. */
    third_also_full = 1; baseline_calls = 0;
    d2k_vol_result unconfirmed = {0};
    probe_response_volume(&unconfirmed, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 3 && !unconfirmed.rx_cut);
    CHECK(strstr(unconfirmed.rx_reason, "identity-3") != NULL);
    noisy_second = third_also_full = 0; expected_gzip_call = 2;
    /* ПОЛЕ 12.10.2026, style.sndcdn.com и api-v2.soundcloud.com. Зонд объёма
       просит единственный «/», а эти хосты отдают на него страницу отказа
       доступа: завершённый 403 с телом 243 байта и 401 с пустым телом (то же
       самое и с VPS — честное поведение сервера). До измеряемой полосы 12 КБ
       зонд не доходит на два порядка, и класс остаётся НЕизмеренным, хотя
       настоящие ресурсы тех же имён режутся: /css/soehne-*.css — 301328 байт
       с VPS против 15985 с линии (три прогона, зависание на таймаут).
       Публичный путь ресурса приходит вместе с тем же ответом — по нему и
       мерим, ОДИН раз и по названной причине «мерить было нечем». */
    short_then_hint = 1; expected_gzip_call = 3;
    hint_host = "context.test"; hint_for_path = "/css/soehne-web.css";
    cut_path = hint_for_path;
    for (int code = 0; code < 2; code++) {
        /* Страница отказа доступа и просто короткий документ — один случай:
           ответ завершён и меньше полосы, мерить по нему нечего. */
        hint_status = code ? 200 : 403;
        baseline_calls = 0; last_path = NULL;
        d2k_vol_result hinted = {0};
        probe_response_volume(&hinted, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
        CHECK(baseline_calls == 4);
        CHECK(hinted.rx_cut && !hinted.rx_wire_basis && hinted.rx_at_kb == 15);
        CHECK(hinted.rx_compressed_complete && hinted.rx_partial_bytes == 15985);
        CHECK(!hinted.rx_short && !hinted.rx_short_bytes);
        CHECK(strstr(hinted.rx_reason, "/css/soehne-web.css") != NULL);
        CHECK(strstr(hinted.rx_reason, "15985/15968") != NULL);
        CHECK(strstr(hinted.rx_reason, "243") != NULL);
        /* ЗАДАЧА 26: ПУТЬ ПОВТОРА — ЧАСТЬ ИЗМЕРЕНИЯ, А НЕ ТОЛЬКО ЖУРНАЛА.
           Причина читается человеком; наверх путь обязан идти полем, иначе
           кандидат проверяется по «/» (403, 243 байта) и доказанный обрыв не
           превращается в подтверждённое решение. */
        CHECK(!strcmp(hinted.measured_path, "/css/soehne-web.css"));
        if (strcmp(hinted.measured_path, "/css/soehne-web.css"))
            fprintf(stderr, "повтор доказал обрыв на /css/soehne-web.css, "
                            "а measured_path=\"%s\"\n", hinted.measured_path);
        /* Подсказка завершённого ответа по-прежнему уходит планировщику. */
        CHECK(hinted.n_resources == (size_t)code);
    }
    /* Повтор не дошёл до TLS — он не сказал ничего, и непроверенный бюджет
       первого ответа остаётся в силе: ложного «обрыв не воспроизвёлся» здесь
       быть не должно. */
    retry_outcome = 1; baseline_calls = 0; last_path = NULL; hint_status = 403;
    d2k_vol_result lost = {0};
    probe_response_volume(&lost, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 2 && !lost.rx_cut && lost.rx_tls_unavailable);
    CHECK(lost.rx_short && lost.rx_short_bytes == 243);
    CHECK(strstr(lost.rx_reason, "/css/soehne-web.css") != NULL);
    /* Повтор не измерил ничего — пути измерения нет: спрашивать кандидата по
       этому пути было бы выдумкой, а не замером. */
    CHECK(!lost.measured_path[0]);
    /* Подсказанный ресурс дошёл ЦЕЛИКОМ и сам прошёл полосу — это настоящее
       отрицательное измерение, и подменять его непроверенным бюджетом нельзя. */
    retry_outcome = 2; baseline_calls = 0; last_path = NULL;
    d2k_vol_result passed = {0};
    probe_response_volume(&passed, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 2 && !passed.rx_cut && !passed.rx_short);
    CHECK(strstr(passed.rx_reason, "30182") != NULL);
    /* Отрицательное измерение — тоже не обрыв: пути обрыва нет. */
    CHECK(!passed.measured_path[0]);
    retry_outcome = 0;
    /* Подсказки нет — честный непроверенный бюджет остаётся как есть, без
       выдумок, и лишнего зонда не заказываем. */
    hint_host = NULL; hint_status = 403; baseline_calls = 0; last_path = NULL;
    d2k_vol_result bare = {0};
    probe_response_volume(&bare, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 1 && !bare.rx_cut);
    CHECK(bare.rx_short && bare.rx_short_bytes == 243);
    CHECK(strstr(bare.rx_reason, "повтор") == NULL);
    /* Подсказка на ЧУЖОЕ имя — это другая цель: адрес и SNI у зонда свои, и
       спросили бы мы чужой путь не у того сервера. */
    hint_host = "other.cdn"; baseline_calls = 0; last_path = NULL;
    d2k_vol_result foreign = {0};
    probe_response_volume(&foreign, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 1 && !foreign.rx_cut && foreign.rx_short);
    /* Подсказка совпала с уже измеренным путём — повторять нечего. */
    hint_host = "context.test"; cut_path = NULL; baseline_calls = 0; last_path = NULL;
    d2k_vol_result same = {0};
    probe_response_volume(&same, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, hint_for_path);
    CHECK(baseline_calls == 1 && !same.rx_cut && same.rx_short);
    short_then_hint = 0; hint_host = NULL; expected_gzip_call = 2;
    /* ОТВЕТ НЕ НАЧАЛСЯ — ОДИН ПОВТОР (поле 17.10.2026, rua.gr). Пустой
       identity-1 не говорит об обрыве ничего; прежде поиск закрывался
       «позднее закрытие не подтвердилось» и отдыхом на 10 минут, хотя
       следующий же поток резался на 23 КБ. */
    unstarted = 0x1; expected_gzip_call = 3; baseline_calls = 0;
    d2k_vol_result late = {0};
    probe_response_volume(&late, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 4 && late.rx_cut && late.rx_at_kb == 23 && !late.rx_unmeasured);
    /* Повтор тоже пуст — измерения нет, третьего вопроса не задаём; это не
       отрицание и не непроверенный бюджет завершённого ответа. */
    unstarted = 0x3; expected_gzip_call = 2; baseline_calls = 0;
    d2k_vol_result mute = {0};
    probe_response_volume(&mute, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 2 && !mute.rx_cut && !mute.rx_short && mute.rx_unmeasured);
    CHECK(strstr(mute.rx_reason, "HTTP 0") != NULL);
    /* Поле 17.10.2026, LR-rx2-1, rua.gr: пара identity сошлась (22577/22292),
       а gzip-контроль вернул 0 байт — и замер пропал. Пустой контроль, как и
       пустой identity-2, — не ответ: один повтор того же вопроса. */
    unstarted = 0x4; expected_gzip_call = 2; expected_gzip_call2 = 3; baseline_calls = 0;
    d2k_vol_result gzmute = {0};
    probe_response_volume(&gzmute, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 4 && gzmute.rx_cut && gzmute.rx_at_kb == 23);
    unstarted = 0x2; expected_gzip_call = 3; expected_gzip_call2 = -1; baseline_calls = 0;
    d2k_vol_result idmute = {0};
    probe_response_volume(&idmute, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 4 && idmute.rx_cut && idmute.rx_at_kb == 23);
    unstarted = 0; expected_gzip_call = 2;
    early_cut = 0x1; expected_gzip_call = 3; baseline_calls = 0;
    d2k_vol_result early = {0};
    probe_response_volume(&early, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 4 && early.rx_cut && early.rx_at_kb == 23);
    early_cut = 0; expected_gzip_call = 2;
    /* Завершённый не-2xx ответ выше полосы (403 на 20 КБ) — не rx_unmeasured,
       не rx_short, и не rx_direct_complete. */
    full_non_2xx = 1; baseline_calls = 0;
    d2k_vol_result fn2 = {0};
    probe_response_volume(&fn2, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 1 && !fn2.rx_cut && !fn2.rx_short && !fn2.rx_unmeasured && !fn2.rx_direct_complete);
    full_non_2xx = 0;
    signal(SIGPIPE, SIG_IGN);
    head_parser_test();
    bounded_send_test();
    plain_ladder_test();
    tls_ladder_test();
    if (failures) return 1;
    puts("test_volume_context: OK"); return 0;
}
