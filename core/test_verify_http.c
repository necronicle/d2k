/* Exercise the production HTTP reader with fragmented byte streams, no sockets. */
#include "quicconn.c" /* настоящее соединение: удержание ответа в нём — часть проверки */
#include "verify.c"
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>

typedef struct { const char *reply; size_t pos, fragment; int eof_err; size_t len; } fixture;
static long fixture_read(void *ctx, uint8_t *buf, size_t cap, int wait,
                         char *err, size_t errcap) {
    fixture *f = ctx;
    (void)wait; (void)err; (void)errcap;
    size_t total = f->len ? f->len : strlen(f->reply);
    size_t n = total - f->pos;
    if (n == 0 && f->eof_err) return -1; /* обрыв без текста причины */
    if (n > cap) n = cap;
    if (n > f->fragment) n = f->fragment;
    memcpy(buf, f->reply + f->pos, n); f->pos += n;
    return (long)n;
}
static int fixture_write(void *ctx, const uint8_t *buf, size_t n,
                         char *err, size_t errcap) {
    (void)ctx; (void)buf; (void)n; (void)err; (void)errcap;
    return 0;
}

static char fetch_request[10000];
static int fetch_capture(void *ctx, const uint8_t *buf, size_t n, char *err, size_t cap) {
    (void)ctx; (void)err; (void)cap;
    assert(n < sizeof fetch_request);
    memcpy(fetch_request, buf, n); fetch_request[n] = 0;
    return 0;
}

/* Задача 44: поток HTTP/3 с кадром HEADERS заданной длины, кусками по step. */
typedef struct { uint8_t *data; size_t len, pos, step; } h3_fixture;
static long h3_fixture_recv(void *ctx, uint8_t *buf, size_t cap, char *err, size_t errcap) {
    h3_fixture *f = ctx; (void)err; (void)errcap;
    size_t n = f->len - f->pos;
    if (n == 0) return 0;
    if (n > cap) n = cap;
    if (n > f->step) n = f->step;
    memcpy(buf, f->data + f->pos, n); f->pos += n;
    return (long)n;
}
static size_t h3_headers_frame(uint8_t *out, size_t section_len) {
    /* секция: префикс 00 00, :status 200 индексом, затем x-pad с литеральным
       именем и значением по 400 байт (7-бит длина: 0x7f 0x91 0x02) */
    size_t o = 0;
    uint8_t *sec = malloc(section_len + 16);
    size_t k = 0;
    sec[k++] = 0; sec[k++] = 0; sec[k++] = 0xd9;
    while (k + 410 < section_len) {
        sec[k++] = 0x25; memcpy(sec + k, "x-pad", 5); k += 5;
        sec[k++] = 0x7f; sec[k++] = 0x91; sec[k++] = 0x02;
        memset(sec + k, 'q', 400); k += 400;
    }
    out[o++] = 0x01;
    out[o++] = 0x80 | (uint8_t)(k >> 24); out[o++] = (uint8_t)(k >> 16);
    out[o++] = (uint8_t)(k >> 8); out[o++] = (uint8_t)k;
    memcpy(out + o, sec, k); o += k;
    free(sec);
    return o;
}

/* Задача 44, раунд 1 (I1): ответ HTTP/3 идёт через НАСТОЯЩЕЕ соединение
   quicconn с ключами из постоянного секрета: проверяется то, сколько байт
   потока оно удерживает, а не поддельный приёмник. */
static d2k_qc *real_h3_conn(int *server, struct sockaddr_in *client_addr) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    assert(s >= 0);
    int rb = 1 << 20;
    (void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t len = sizeof a;
    assert(getsockname(s, (struct sockaddr *)&a, &len) == 0);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    assert(connect(fd, (struct sockaddr *)&a, sizeof a) == 0);
    len = sizeof *client_addr;
    assert(getsockname(fd, (struct sockaddr *)client_addr, &len) == 0);
    d2k_qc *c = calloc(1, sizeof *c);
    assert(c);
    c->fd = fd; c->peer_name = -1; c->version = D2K_QW_V1;
    c->dcid_len = 8; memset(c->dcid, 0x5a, 8);
    c->scid_len = 8; memset(c->scid, 0x3c, 8);
    uint8_t secret[32];
    memset(secret, 0x42, sizeof secret);
    assert(d2k_qw_keys_from_secret(c->version, secret, &c->lv[D2K_QW_LEVEL_APP].tx) == 0);
    assert(d2k_qw_keys_from_secret(c->version, secret, &c->lv[D2K_QW_LEVEL_APP].rx) == 0);
    *server = s;
    return c;
}
/* Сервер: кадр HEADERS длиной section_len на потоке 0, пакетами по ~1100 байт. */
static void real_h3_serve_end(int server, const struct sockaddr_in *to, const uint8_t *data, size_t n, int fin, int hole) {
    uint8_t secret[32];
    memset(secret, 0x42, sizeof secret);
    d2k_qw_keys sk;
    assert(d2k_qw_keys_from_secret(D2K_QW_V1, secret, &sk) == 0);
    uint64_t pn = 0;
    for (size_t off = 0; off < n; ) {
        size_t take = n - off > 1100 ? 1100 : n - off;
        uint8_t fr[1200], hdr[16], pkt[1500];
        size_t o = 0;
        fr[o++] = (uint8_t)(0x0e | (fin && off + take == n));
        o += d2k_qw_varint_write(fr + o, sizeof fr - o, 0);
        o += d2k_qw_varint_write(fr + o, sizeof fr - o, off);
        o += d2k_qw_varint_write(fr + o, sizeof fr - o, take);
        memcpy(fr + o, data + off, take); o += take;
        hdr[0] = 0x40; memset(hdr + 1, 0x3c, 8);
        size_t pl = d2k_qw_pn_len(pn, -1);
        size_t m = d2k_qw_seal(&sk, 0, hdr, 9, pn, pl, fr, o, pkt, sizeof pkt);
        assert(m > 0);
        if (!hole || off != 4400)
            assert(sendto(server, pkt, m, 0, (const struct sockaddr *)to, sizeof *to) == (ssize_t)m);
        pn++; off += take;
    }
}
static void real_h3_serve(int server, const struct sockaddr_in *to, const uint8_t *data, size_t n) {
    real_h3_serve_end(server, to, data, n, 0, 0);
}
/* ЗАДАЧА 55: сервер keep-alive за коробкой с бюджетом потока. Каждый запрос
   (один пакет клиента) получает тот же ответ сегментами по mss; коробка
   после cut_at пакетов с данными (обе стороны) глушит сервер — чтение
   молчит (тайм-аут), peer_spoke = 0. close_after — сервер закрывает поток
   после стольких ответов (конец потока, peer_spoke = 1). */
typedef struct {
    const char *resp;
    size_t mss;
    long pk, cut_at;
    int close_after, answered, eof;
    int alert_after, bad_after; /* после стольких ответов: тревога TLS / битый ответ */
    int alert, nocount;
    char buf[131072];
    size_t len, pos;
} ka_srv;
static int ka_write(void *ctx, const uint8_t *b, size_t n, char *err, size_t errcap) {
    ka_srv *k = ctx; (void)err; (void)errcap;
    if (n < 4 || memcmp(b, "GET ", 4)) return -1;
    if (k->cut_at && k->pk >= k->cut_at) { k->pk++; return 0; } /* клиент шлёт, сервер не слышен */
    k->pk++;
    if (k->close_after && k->answered >= k->close_after) { k->eof = 1; return 0; }
    if (k->alert_after && k->answered >= k->alert_after) { k->alert = 1; return 0; }
    const char *resp = k->bad_after && k->answered >= k->bad_after
        ? "XTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" : k->resp;
    size_t rl = strlen(resp), off = 0;
    while (off < rl) {
        if (k->cut_at && k->pk >= k->cut_at) break;  /* бюджет кончился посреди ответа */
        size_t seg = rl - off > k->mss ? k->mss : rl - off;
        memcpy(k->buf + k->len, resp + off, seg);
        k->len += seg; off += seg; k->pk++;
    }
    k->answered++;
    return 0;
}
static long ka_read(void *ctx, uint8_t *buf, size_t cap, int wait, char *err, size_t errcap) {
    ka_srv *k = ctx;
    if (k->pos < k->len) {
        size_t n = k->len - k->pos;
        if (n > cap) n = cap;
        memcpy(buf, k->buf + k->pos, n); k->pos += n;
        if (k->pos == k->len) k->pos = k->len = 0;
        return (long)n;
    }
    if (k->eof) return 0;
    if (k->alert) {
        snprintf(err, errcap, "тревога 20"); /* сразу, без молчания */
        return -1;
    }
    /* Молчание: срок чтения проходит целиком, как у настоящего сокета. */
    usleep((useconds_t)(wait > 0 ? wait : 1) * 1000);
    snprintf(err, errcap, "не дождались ответа (тайм-аут)");
    return -1;
}
static long ka_packets(void *ctx) { return ((ka_srv *)ctx)->nocount ? -1 : ((ka_srv *)ctx)->pk; }
static int ka_spoke(void *ctx) { return ((ka_srv *)ctx)->eof; }

/* QUIC-аналог: запрос — одна датаграмма клиента, ответ — dg датаграмм
   (первая несёт HEADERS 200, последняя — FIN). closed — CONNECTION_CLOSE. */
typedef struct {
    uint8_t frame[64]; size_t flen;
    unsigned dg; long pk, cut_at;
    int close_after, answered, closed;
    /* ЗАГЛУШЕНО ИСХОДЯЩЕЕ НАПРАВЛЕНИЕ (12.10.2026). После oneway_after
       отвеченных запросов сервер больше не получает от нас ничего и не
       отвечает, но продолжает повторять свой последний полёт по таймеру PTO:
       счётчик датаграмм связи РАСТЁТ, ответ не растёт ни на байт. Такова
       измеренная форма обоих известных цензоров QUIC (FOCI 2026(2) §3,
       USENIX Sec 25: дропанье только в исходящую сторону). */
    int oneway_after;
    unsigned left, sent; int fin; uint64_t bytes; uint64_t last_sid;
} q_srv;
static int q_request(void *ctx, uint64_t sid, char *err, size_t errcap) {
    q_srv *q = ctx; (void)err; (void)errcap;
    if (q->closed) return -1;
    q->pk++;
    q->last_sid = sid;
    q->fin = 0; q->bytes = 0; q->sent = 0;
    if (q->close_after && q->answered >= q->close_after) { q->closed = 1; q->left = 0; return 0; }
    q->left = q->dg;
    q->answered++;
    return 0;
}
static long q_recv(void *ctx, uint8_t *buf, size_t cap, char *err, size_t errcap) {
    q_srv *q = ctx; (void)errcap;
    if (q->closed) { snprintf(err, errcap, "сервер закрыл соединение кодом 0"); return -1; }
    /* Заглушение начинается ПОСРЕДИ ответа: заголовки уже прошли (sent >= 1),
       то есть код ответа известен и «сервер ответил» уже правда — а дальше
       поток встал, и растут только повторы. На границе запроса тот же блок
       распознаётся и так («сервер замолчал посреди повторов»), а здесь — нет. */
    if (q->oneway_after && q->answered >= q->oneway_after && q->sent >= 1) {
        q->pk++;      /* повтор полёта: датаграмма есть, новых байт ответа нет */
        return 0;
    }
    if (!q->left || (q->cut_at && q->pk >= q->cut_at)) return 0;
    q->pk++; q->left--;
    size_t n;
    if (q->sent++ == 0) { n = q->flen < cap ? q->flen : cap; memcpy(buf, q->frame, n); }
    else { n = cap < 900 ? cap : 900; memset(buf, 'b', n); }
    q->bytes += n;
    if (!q->left) q->fin = 1;
    return (long)n;
}
static void q_progress(void *ctx, uint64_t *bytes, int *complete) {
    q_srv *q = ctx; *bytes = q->bytes; *complete = q->fin;
}
static long q_packets(void *ctx) { return ((q_srv *)ctx)->pk; }

static int budget_checks(void) {
    int fails = 0;
    /* (1) Поле 04.10, cdn.discordapp.com под plan-8830b1a2 (только разрез):
       403 на 3,6 КБ проходит, сервер замолкает на 25-м пакете с данными.
       Под plan-680fbe00 (приманка первой) тот же ответ идёт без конца. */
    static char r403[4096];
    {
        int o = snprintf(r403, sizeof r403, "HTTP/1.1 403 Forbidden\r\nContent-Length: 3077\r\n"
                         "Content-Encoding: gzip\r\n\r\n");
        memset(r403 + o, 'z', 3077); r403[o + 3077] = 0;
    }
    for (int fake_first = 0; fake_first < 2; fake_first++) {
        static ka_srv k; memset(&k, 0, sizeof k);
        k.resp = r403; k.mss = 1400; k.pk = 6; /* рукопожатие: 6 пакетов с данными */
        k.cut_at = fake_first ? 0 : 25;
        budget_io io = { ka_packets, ka_spoke, &k };
        d2k_ver_result r = {0}; char err[200] = "";
        r.level = D2K_VER_HANDSHAKE;
        request_page_budget(ka_read, ka_write, &k, "cdn.discordapp.com", 2, NULL,
                            60, 0, &io, D2K_BUDGET_FIELD_PACKETS, &r, err, sizeof err, 0);
        int want = fake_first ? D2K_BUDGET_PASSED : D2K_BUDGET_CUT;
        if (r.level != D2K_VER_APPLICATION || r.status != 403 || r.budget != want ||
            r.budget_need != 50 || (fake_first && r.budget_packets < 50) ||
            (!fake_first && (r.budget_packets < 25 || r.budget_packets >= 50)) ||
            r.budget_requests < 2 || !r.budget_note[0]) {
            fprintf(stderr, "budget 403 fake_first=%d: level %d status %d budget %d pk %u/%u req %u [%s]\n",
                    fake_first, r.level, r.status, r.budget, r.budget_packets, r.budget_need,
                    r.budget_requests, r.budget_note); fails++;
        }
    }
    /* (2) gateway.discord.gg: 404 на 933 байта (один сегмент) — повторы по
       два пакета; коробка режет — CUT, без коробки — PASSED. */
    for (int cut = 0; cut < 2; cut++) {
        static char r404[1024];
        int o = snprintf(r404, sizeof r404, "HTTP/1.1 404 Not Found\r\nContent-Length: 800\r\n\r\n");
        memset(r404 + o, 'n', 800); r404[o + 800] = 0;
        static ka_srv k; memset(&k, 0, sizeof k);
        k.resp = r404; k.mss = 1400; k.pk = 6; k.cut_at = cut ? 25 : 0;
        budget_io io = { ka_packets, ka_spoke, &k };
        d2k_ver_result r = {0}; char err[200] = "";
        r.level = D2K_VER_HANDSHAKE;
        request_page_budget(ka_read, ka_write, &k, "gateway.discord.gg", 2, NULL,
                            60, 0, &io, D2K_BUDGET_FIELD_PACKETS, &r, err, sizeof err, 0);
        if (r.budget != (cut ? D2K_BUDGET_CUT : D2K_BUDGET_PASSED) ||
            r.budget_requests < (cut ? 9u : 20u)) {
            fprintf(stderr, "budget 404 cut=%d: budget %d pk %u req %u [%s]\n", cut, r.budget,
                    r.budget_packets, r.budget_requests, r.budget_note); fails++;
        }
        /* ПОРОГ ОБЯЗАН БЫТЬ В СООБЩЕНИИ ЦЕЛИКОМ. Поле 12.10.2026: текст
           кириллический, по два байта на символ, и при коротком буфере он
           обрезался посреди слова — 30 с лишним строк отказа по
           www.userscript.zone читались как «из нужных» без самого числа, и
           отказ кандидата нечем было проверить по журналу. */
        if (cut) {
            char need[32];
            snprintf(need, sizeof need, "из нужных %u", r.budget_need);
            if (!strstr(r.budget_note, need)) {
                fprintf(stderr, "budget note truncated, no \"%s\": [%s]\n",
                        need, r.budget_note); fails++;
            }
        }
    }
    /* (3) Keep-alive не дают: Connection: close в ответе, либо сервер закрыл
       поток после первого ответа — «не применимо», уровень прежний. */
    {
        static ka_srv k; memset(&k, 0, sizeof k);
        k.resp = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok";
        k.mss = 1400; k.pk = 6;
        budget_io io = { ka_packets, ka_spoke, &k };
        d2k_ver_result r = {0}; char err[200] = "";
        request_page_budget(ka_read, ka_write, &k, "example.com", 2, NULL,
                            60, 0, &io, D2K_BUDGET_FIELD_PACKETS, &r, err, sizeof err, 0);
        if (r.level != D2K_VER_APPLICATION || r.budget != D2K_BUDGET_NOT_APPLICABLE ||
            r.budget_requests != 1 || !strstr(r.budget_note, "keep-alive")) {
            fprintf(stderr, "budget conn-close: level %d budget %d req %u [%s]\n",
                    r.level, r.budget, r.budget_requests, r.budget_note); fails++;
        }
    }
    {
        static ka_srv k; memset(&k, 0, sizeof k);
        k.resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        k.mss = 1400; k.pk = 6; k.close_after = 3;
        budget_io io = { ka_packets, ka_spoke, &k };
        d2k_ver_result r = {0}; char err[200] = "";
        request_page_budget(ka_read, ka_write, &k, "example.com", 2, NULL,
                            60, 0, &io, D2K_BUDGET_FIELD_PACKETS, &r, err, sizeof err, 0);
        if (r.level != D2K_VER_APPLICATION || r.budget != D2K_BUDGET_NOT_APPLICABLE ||
            r.budget_requests != 4) {
            fprintf(stderr, "budget server close: level %d budget %d req %u [%s]\n",
                    r.level, r.budget, r.budget_requests, r.budget_note); fails++;
        }
    }
    /* (4) Без бюджета (0) повторов нет — прежнее поведение; пакеты не
       считаются (-1) — «не применимо», а не «пройдено». */
    {
        static ka_srv k; memset(&k, 0, sizeof k);
        k.resp = r403; k.mss = 1400; k.pk = 6;
        budget_io io = { ka_packets, ka_spoke, &k };
        d2k_ver_result r = {0}; char err[200] = "";
        request_page_budget(ka_read, ka_write, &k, "example.com", 2, NULL,
                            60, 0, &io, 0, &r, err, sizeof err, 0);
        if (r.budget != D2K_BUDGET_NOT_CHECKED || k.answered != 1) {
            fprintf(stderr, "budget off: budget %d answered %d\n", r.budget, k.answered); fails++;
        }
    }
    /* (5) Большой ответ сам переносит порог — повторов нет. */
    {
        static char big[80000];
        int o = snprintf(big, sizeof big, "HTTP/1.1 200 OK\r\nContent-Length: 70000\r\n\r\n");
        memset(big + o, 'x', 70000); big[o + 70000] = 0;
        static ka_srv k; memset(&k, 0, sizeof k);
        k.resp = big; k.mss = 1400; k.pk = 6;
        budget_io io = { ka_packets, ka_spoke, &k };
        d2k_ver_result r = {0}; char err[200] = "";
        request_page_budget(ka_read, ka_write, &k, "example.com", 0, NULL,
                            60, 0, &io, D2K_BUDGET_FIELD_PACKETS, &r, err, sizeof err, 0);
        if (r.budget != D2K_BUDGET_PASSED || r.budget_requests != 1 || k.answered != 1) {
            fprintf(stderr, "budget big: budget %d req %u\n", r.budget, r.budget_requests); fails++;
        }
    }
    /* (5b) Не молчание коробки — не обрыв (ревью M-2): тревога TLS сразу
       после запроса и битый ответ на повтор — «не применимо». */
    for (int kind = 0; kind < 2; kind++) {
        static ka_srv k; memset(&k, 0, sizeof k);
        k.resp = r403; k.mss = 1400; k.pk = 6;
        if (kind) k.bad_after = 2; else k.alert_after = 2;
        budget_io io = { ka_packets, ka_spoke, &k };
        d2k_ver_result r = {0}; char err[200] = "";
        request_page_budget(ka_read, ka_write, &k, "example.com", 2, NULL,
                            60, 0, &io, D2K_BUDGET_FIELD_PACKETS, &r, err, sizeof err, 0);
        if (r.level != D2K_VER_APPLICATION || r.budget != D2K_BUDGET_NOT_APPLICABLE) {
            fprintf(stderr, "budget non-silence kind=%d: budget %d [%s]\n", kind, r.budget,
                    r.budget_note); fails++;
        }
    }
    /* (5c) Пакеты не считаются — «не применимо» с признаком для разовой
       строки журнала (ревью M-5). */
    {
        static ka_srv k; memset(&k, 0, sizeof k);
        k.resp = r403; k.mss = 1400; k.pk = 6; k.nocount = 1;
        budget_io io = { ka_packets, ka_spoke, &k };
        d2k_ver_result r = {0}; char err[200] = "";
        request_page_budget(ka_read, ka_write, &k, "example.com", 2, NULL,
                            60, 0, &io, D2K_BUDGET_FIELD_PACKETS, &r, err, sizeof err, 0);
        if (r.budget != D2K_BUDGET_NOT_APPLICABLE || !r.budget_uncountable) {
            fprintf(stderr, "budget uncountable: budget %d flag %d\n", r.budget,
                    r.budget_uncountable); fails++;
        }
    }
    /* (6) QUIC: новые потоки той же связи. abc2b3eb (минимальная приманка):
       режется на 25 датаграммах; 389a3920 (приманки Initial) — проходит. */
    for (int pass = 0; pass < 2; pass++) {
        q_srv q; memset(&q, 0, sizeof q);
        q.flen = h3_headers_frame(q.frame, 3);
        q.dg = 3; q.pk = 5 + 1 + 3; q.fin = 1; q.bytes = 1800; q.answered = 1;
        q.cut_at = pass ? 0 : 25;
        quic_budget_io io = { q_request, q_recv, q_progress, q_packets, &q };
        d2k_ver_result r = {0};
        r.level = D2K_VER_APPLICATION; r.status = 200;
        budget_quic(&io, 50, D2K_BUDGET_FIELD_PACKETS, &r);
        if (r.budget != (pass ? D2K_BUDGET_PASSED : D2K_BUDGET_CUT) ||
            r.budget_requests < 4 || q.last_sid == 0 || (q.last_sid & 3) != 0) {
            fprintf(stderr, "budget quic pass=%d: budget %d pk %u req %u sid %llu [%s]\n", pass,
                    r.budget, r.budget_packets, r.budget_requests,
                    (unsigned long long)q.last_sid, r.budget_note); fails++;
        }
    }
    {
        q_srv q; memset(&q, 0, sizeof q);
        q.flen = h3_headers_frame(q.frame, 3);
        q.dg = 3; q.pk = 9; q.fin = 1; q.bytes = 1800; q.answered = 1; q.close_after = 2;
        quic_budget_io io = { q_request, q_recv, q_progress, q_packets, &q };
        d2k_ver_result r = {0};
        r.level = D2K_VER_APPLICATION; r.status = 200;
        budget_quic(&io, 50, D2K_BUDGET_FIELD_PACKETS, &r);
        if (r.budget != D2K_BUDGET_NOT_APPLICABLE) {
            fprintf(stderr, "budget quic close: budget %d [%s]\n", r.budget, r.budget_note); fails++;
        }
    }
    /* (7) ЗАГЛУШЕНО ИСХОДЯЩЕЕ НАПРАВЛЕНИЕ. Счётчик датаграмм связи растёт от
       повторов полёта сервера, ответ не растёт ни на байт. Бюджет пройденным
       НЕ СЧИТАЕТСЯ: иначе будет поставлен план, который ничего не делает —
       это дороже вранья в диагностике. */
    {
        q_srv q; memset(&q, 0, sizeof q);
        q.flen = h3_headers_frame(q.frame, 3);
        q.dg = 3; q.pk = 9; q.fin = 1; q.bytes = 1800; q.answered = 1; q.oneway_after = 2;
        quic_budget_io io = { q_request, q_recv, q_progress, q_packets, &q };
        d2k_ver_result r = {0};
        r.level = D2K_VER_APPLICATION; r.status = 200;
        budget_quic(&io, 50, D2K_BUDGET_FIELD_PACKETS, &r);
        /* Направление здесь не называется: у этого интерфейса нет
           подтверждений наших пакетов, он видит только остановку ответа. */
        if (r.budget != D2K_BUDGET_CUT) {
            fprintf(stderr, "budget quic oneway: budget %d pk %u/%u req %u [%s]\n", r.budget,
                    r.budget_packets, r.budget_need, r.budget_requests, r.budget_note); fails++;
        }
    }
    return fails;
}

/* Поле 24.10.2026 (h3-1024, класс B): www.cloudflare.com по QUIC прислал 139 КБ,
   прибор остановился на 32 КиБ и назвал это обрывом. Предел
   D2K_QUIC_ARM_DATA_BYTES — мера этапа данных плеча; прибор поля читает до FIN. */
static int read_body_checks(void) {
    int fails = 0;
    for (int mode = 0; mode < 4; mode++) {
        int all = mode & 1, full_response = (mode & 2) != 0;
        static q_srv q; memset(&q, 0, sizeof q);
        q.flen = h3_headers_frame(q.frame, 8);
        q.left = 60; /* 60 датаграмм ≈ 54 КБ, FIN в последней */
        d2k_verify_quic_read_all_set(all);
        uint64_t bytes = 0; int complete = 0; char err[200] = "";
        int closed = quic_read_body(q_recv, q_progress, &q, 0, verify_now_ms() + 5000, full_response,
                                    &bytes, &complete, err, sizeof err);
        int ok = (all || full_response) ? (complete && bytes > D2K_QUIC_ARM_DATA_BYTES && !closed)
                     : (!complete && bytes >= D2K_QUIC_ARM_DATA_BYTES && bytes < 40000);
        if (!ok) {
            fprintf(stderr, "quic_read_body mode=%d: bytes %llu complete %d closed %d\n",
                    mode, (unsigned long long)bytes, complete, closed); fails++;
        }
    }
    d2k_verify_quic_read_all_set(0);
    return fails;
}

int main(void) {
    struct { const char *reply; d2k_ver_level level; } cases[] = {
        {"HTTP/1.1 302 Found\r\nLocation: https://www.google.com/\r\nContent-Length: 0\r\n\r\n", D2K_VER_APPLICATION},
        {"HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru/\r\nContent-Length: 0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 302 Found\r\nLocation: //eais.rkn.gov.ru/\r\nContent-Length: 0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\n\r\naccess blocked by rkn", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n7\r\naccess \r\nE\r\nblocked by rkn\r\n0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Encoding: gzip\r\nContent-Length: 21\r\n\r\naccess blocked by rkn", D2K_VER_APPLICATION},
        {"HTTP/1.1 403 Forbidden\r\nLink: <https://eais.rkn.gov.ru/>\r\nContent-Length: 0\r\n\r\n", D2K_VER_APPLICATION},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nok", D2K_VER_APPLICATION},
        {"HTTP/1.1 451 Unavailable\r\nContent-Length: 0\r\n\r\n", D2K_VER_DENIED},
        {"HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\nContent-Length: 21\r\n\r\naccess blocked by rkn", D2K_VER_CHALLENGE},
        {"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 302 Found\r\nLocation: https://www.google.com/\r\nContent-Length: 20\r\n\r\nshort", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 14\r\n", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 15\r\n\r\neais.rkn.gov.ru", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 30\r\n\r\neais.rkn.gov.ru", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru/\r\nLocation: https://www.google.com/\r\nContent-Length: 0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 302 Found\r\nLocation: https://www.google.com/\r\nLocation: https://warning.rt.ru/\r\nContent-Length: 0\r\n\r\n", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 451 Unavailable\r\nContent-Length: nope\r\n\r\n", D2K_VER_DENIED},
        {"HTTP/1.1 451 Unavailable\r\nContent-Length: 0\r\nContent-Length: 4\r\n\r\n", D2K_VER_DENIED},
    };
    int fails = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        for (size_t fragment = 1; fragment <= 512; fragment *= 8) {
            fixture f = {cases[i].reply, 0, fragment, 0, 0};
            d2k_ver_result r = {0}; char err[200] = "";
            /* ИМЯ СОБЕСЕДНИКА ПОДТВЕРЖДЕНО: мишень здесь и есть запрошенный
               хост, и разбор ответа меряется сам по себе. С 24.10.2026 это не
               безразлично: 451 считается отказом сайта только от владельца
               имени (core/verify.c), и фикстура обязана сказать, кто ответил.
               Отдельный случай «имя не подтверждено» — ниже. */
            r.level = D2K_VER_HANDSHAKE; r.name_ok = 1;
            request_complete_page(fixture_read, fixture_write, &f, "googlevideo.com",
                0, NULL, 1000, 0, &r, err, sizeof err);
            if (r.level != cases[i].level || r.name_ok != 1) {
                fprintf(stderr, "case %zu fragment %zu: level %d expected %d (%s)\n",
                    i, fragment, r.level, cases[i].level, r.reason); fails++;
            }
            if (i == 0) {
                fixture css = {cases[i].reply, 0, fragment, 0, 0};
                memset(&r, 0, sizeof r); r.level = D2K_VER_HANDSHAKE;
                request_complete_page(fixture_read, fixture_write, &css, "googlevideo.com",
                    0, "/assets/app.css", 1000, 0, &r, err, sizeof err);
                if (r.level == D2K_VER_APPLICATION) {
                    fprintf(stderr, "cross-origin redirect accepted as stylesheet\n"); fails++;
                }
            }
        }
    }
    /* 451 БЕЗ ПОДТВЕРЖДЁННОГО ИМЕНИ — НЕ ОТКАЗ САЙТА (24.10.2026).
       Тот же ответ, та же мишень; разница только в том, что собеседник имени
       не подтвердил. Вставленный в линию 451 — штатный способ блокировки, и
       закрывать по нему поиск нельзя. */
    {
        static const char deny[] = "HTTP/1.1 451 Unavailable\r\nContent-Length: 0\r\n\r\n";
        for (int name_ok = -1; name_ok <= 1; name_ok++) {
            fixture f = {deny, 0, 64, 0, 0};
            d2k_ver_result r = {0}; char err[200] = "";
            r.level = D2K_VER_HANDSHAKE; r.name_ok = name_ok;
            request_complete_page(fixture_read, fixture_write, &f, "googlevideo.com",
                0, NULL, 1000, 0, &r, err, sizeof err);
            d2k_ver_level want = name_ok == 1 ? D2K_VER_DENIED : D2K_VER_HANDSHAKE;
            if (r.level != want) {
                fprintf(stderr, "451 при name_ok=%d: уровень %d, ждали %d (%s)\n",
                        name_ok, r.level, want, r.reason); fails++;
            }
            if (name_ok != 1 && !strstr(r.reason, "не подтвердил имя сертификатом")) {
                fprintf(stderr, "451 при name_ok=%d: причина не названа (%s)\n",
                        name_ok, r.reason); fails++;
            }
        }
    }

    struct { int code; d2k_ver_level before, after; } ech[] = {
        {451,D2K_VER_DENIED,D2K_VER_DENIED},
        {403,D2K_VER_BLOCKPAGE,D2K_VER_BLOCKPAGE},
        /* Поле 04.10: корень свидетеля cdn.discordapp.com всегда отвечает
           403 — это ответ приложения через ECH, а не антибот (challenge
           распознаётся по своим признакам, cf-mitigated). Пауза — только
           на явное ограничение частоты. */
        {403,D2K_VER_APPLICATION,D2K_VER_APPLICATION},
        {404,D2K_VER_APPLICATION,D2K_VER_APPLICATION},
        {429,D2K_VER_APPLICATION,D2K_VER_CHALLENGE},
        {200,D2K_VER_APPLICATION,D2K_VER_APPLICATION},
    };
    for (size_t i=0;i<sizeof ech/sizeof ech[0];i++) {
        d2k_ver_result r={0}; r.status=ech[i].code; r.level=ech[i].before;
        ech_http_denial(&r);
        if (r.level != ech[i].after) { fprintf(stderr,"ECH denial case %zu failed\n",i); fails++; }
    }
    /* Задача 42: этап «рукопожатие прошло, приложение молчит» назван прямо. */
    {
        d2k_ver_result r = {0};
        quic_app_silent(&r, 0, 4812, NULL);
        if (!strstr(r.reason, "рукопожатие прошло, приложение молчит, получено 0 байт") ||
            !strstr(r.reason, "4812")) {
            fprintf(stderr, "QUIC silent-application stage: %s\n", r.reason); fails++;
        }
        quic_app_silent(&r, 2337, 7170, "сервер закрыл соединение");
        if (!strstr(r.reason, "рукопожатие прошло, приложение молчит, получено 2337 байт") ||
            !strstr(r.reason, "закрыто")) {
            fprintf(stderr, "QUIC silent-application stage (closed): %s\n", r.reason); fails++;
        }
    }

    /* Задача 44: заголовки длиннее 8 КБ (поле 03.10.2026, web.whatsapp.com —
       край Meta отдаёт ~8,4 КБ заголовков) не отбраковывают рабочий обход. */
    {
        static char big[96 * 1024];
        size_t o = 0;
        o += (size_t)snprintf(big + o, sizeof big - o,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=\"utf-8\"\r\n"
            "Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n");
        const char *names[] = {"content-security-policy", "report-to",
            "set-cookie", "content-security-policy-report-only",
            "reporting-endpoints", "permissions-policy"};
        for (int k = 0; o < 8400; k++) {
            o += (size_t)snprintf(big + o, sizeof big - o, "%s: ", names[k % 6]);
            for (int j = 0; j < 400; j++) big[o++] = (char)('a' + (j * 7 + k) % 26);
            big[o++] = '\r'; big[o++] = '\n';
        }
        o += (size_t)snprintf(big + o, sizeof big - o, "\r\n");
        for (int chunk = 0; chunk < 8; chunk++) {
            o += (size_t)snprintf(big + o, sizeof big - o, "1000\r\n");
            for (int j = 0; j < 4096; j++) big[o++] = (char)('A' + j % 26);
            big[o++] = '\r'; big[o++] = '\n';
        }
        o += (size_t)snprintf(big + o, sizeof big - o, "0\r\n\r\n");
        big[o] = '\0';
        size_t frags[] = {1, 7, 1460, sizeof big};
        for (size_t k = 0; k < 4; k++) {
            fixture f = {big, 0, frags[k], 0, 0};
            d2k_ver_result r = {0}; char err[200] = "";
            r.level = D2K_VER_HANDSHAKE;
            request_complete_page(fixture_read, fixture_write, &f, "web.whatsapp.com",
                2, NULL, 1000, 0, &r, err, sizeof err);
            if (r.level != D2K_VER_APPLICATION || r.status != 200 || !r.body_complete ||
                r.local_limit) {
                fprintf(stderr, "long headers, fragment %zu: level %d status %d (%s)\n",
                    frags[k], r.level, r.status, r.reason); fails++;
            }
        }
        /* Предел: заголовки больше D2K_VERIFY_HEADER_LIMIT — отказ с названием
           предела, и это наш предел, а не улика с провода. */
        static char huge[D2K_VERIFY_HEADER_LIMIT + 4096];
        size_t h = (size_t)snprintf(huge, sizeof huge, "HTTP/1.1 200 OK\r\n");
        while (h < sizeof huge - 600) {
            h += (size_t)snprintf(huge + h, sizeof huge - h, "x-pad: ");
            memset(huge + h, 'q', 400); h += 400;
            huge[h++] = '\r'; huge[h++] = '\n';
        }
        huge[h] = '\0';
        fixture hf = {huge, 0, 1460, 0, 0};
        d2k_ver_result r = {0}; char err[200] = "";
        r.level = D2K_VER_HANDSHAKE;
        request_complete_page(fixture_read, fixture_write, &hf, "web.whatsapp.com",
            2, NULL, 1000, 0, &r, err, sizeof err);
        char want[64];
        snprintf(want, sizeof want, "длиннее %d байт", D2K_VERIFY_HEADER_LIMIT);
        if (r.level == D2K_VER_APPLICATION || !strstr(r.reason, "заголовки ответа") ||
            !strstr(r.reason, want) || !r.local_limit) {
            fprintf(stderr, "header limit: level %d local %d (%s)\n",
                r.level, r.local_limit, r.reason); fails++;
        }
    }
    /* Задача 44: у каждого неуспеха чтения ответа своя непустая причина. */
    {
        struct { const char *reply; int eof_err; const char *needle; } bad[] = {
            {"SMTP/1.1 200 OK\r\n\r\n", 0, "строка статуса"},
            {"HTTP/1.1 200 O\0K\r\n\r\n", 0, "нулев"},
            {"HTTP/1.1 101 Switching\r\n\r\n", 0, "101"},
            {"", 0, "закрыл"},
            {"HTTP/1.1 200 OK\r\nX: y\r\n", 0, "закрыл"},
            {"", 1, "ошибка чтения"},
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            fixture f = {bad[i].reply, 0, 64, bad[i].eof_err, i == 1 ? 20 : 0};
            d2k_ver_result r = {0}; char err[200] = "";
            r.level = D2K_VER_HANDSHAKE;
            request_complete_page(fixture_read, fixture_write, &f, "example.com",
                0, NULL, 1000, 0, &r, err, sizeof err);
            const char *colon = strstr(r.reason, "ответа: ");
            if (r.level == D2K_VER_APPLICATION || !colon || colon[strlen("ответа: ")] == '\0' ||
                !strstr(r.reason, bad[i].needle) || r.local_limit) {
                fprintf(stderr, "failure reason %zu: [%s]\n", i, r.reason); fails++;
            }
        }
    }
    /* Задача 44: заголовки HTTP/3 длиннее 8 КБ разбираются; сверх предела —
       названная причина и признак нашего предела. */
    {
        static uint8_t frame[D2K_VERIFY_HEADER_LIMIT + 8192], rx[D2K_VERIFY_HEADER_LIMIT];
        size_t frames[] = {8600, 20000};
        for (size_t k = 0; k < 2; k++) {
            size_t fl = h3_headers_frame(frame, frames[k]);
            h3_fixture f = {frame, fl, 0, k ? 1460 : 1};
            size_t got = 0; int st = 0, closed = 0; char err[100] = "";
            int too_long = h3_read_headers(h3_fixture_recv, &f, rx, sizeof rx,
                verify_now_ms() + 100000, &got, &st, &closed, err, sizeof err);
            if (too_long || st != 200) {
                fprintf(stderr, "H3 headers %zu: too_long %d status %d\n", frames[k], too_long, st); fails++;
            }
        }
        size_t fl = h3_headers_frame(frame, D2K_VERIFY_HEADER_LIMIT + 4000);
        h3_fixture f = {frame, fl, 0, 4096};
        size_t got = 0; int st = 0, closed = 0; char err[100] = "";
        int too_long = h3_read_headers(h3_fixture_recv, &f, rx, sizeof rx,
            verify_now_ms() + 100000, &got, &st, &closed, err, sizeof err);
        if (!too_long || st != 0) {
            fprintf(stderr, "H3 header limit: too_long %d status %d\n", too_long, st); fails++;
        }
    }
    /* Задача 44, раунд 1 (I1): через настоящее соединение заголовки HTTP/3
       ~20 КБ проходят, а больше предела — наш предел, не «приложение молчит». */
    {
        static uint8_t frame[D2K_VERIFY_HEADER_LIMIT + 8192], rx[D2K_VERIFY_HEADER_LIMIT];
        size_t sizes[] = {20000, D2K_VERIFY_HEADER_LIMIT + 4000};
        for (size_t k = 0; k < 2; k++) {
            int server = -1; struct sockaddr_in to;
            d2k_qc *c = real_h3_conn(&server, &to);
            char err[100] = "";
            static const uint8_t req[] = {1, 2, 3};
            assert(d2k_qc_stream_send(c, 0, req, sizeof req, 1, err, sizeof err) == 0);
            size_t fl = h3_headers_frame(frame, sizes[k]);
            real_h3_serve(server, &to, frame, fl);
            quic_recv_ctx rc = { c };
            size_t got = 0; int st = 0, closed = 0;
            int too_long = h3_read_headers(quic_recv_chunk, &rc, rx, sizeof rx,
                verify_now_ms() + 20000, &got, &st, &closed, err, sizeof err);
            if (k == 0 ? (too_long || st != 200) : (!too_long || st != 0)) {
                fprintf(stderr, "real quicconn H3 headers %zu: too_long %d status %d got %zu\n",
                    sizes[k], too_long, st, got); fails++;
            }
            d2k_qc_close(c); close(server);
        }
    }
    /* A full fetch must read beyond 32 KiB. FIN with a missing range and
       a large response without FIN must never become complete. */
    for (int mode = 0; mode < 4; mode++) {
        int server = -1; struct sockaddr_in to;
        d2k_qc *c = real_h3_conn(&server, &to);
        char err[100] = "";
        const uint8_t request[] = {1, 2, 3};
        assert(d2k_qc_stream_send(c, 0, request, sizeof request, 1, err, sizeof err) == 0);
        static uint8_t reply[70000];
        real_h3_serve_end(server, &to, reply, sizeof reply, mode != 2, mode == 3);
        int closed = 0, complete = 0; uint64_t bytes = 0;
        quic_read_response(c, verify_now_ms() + 250, mode != 0,
                           &closed, &bytes, &complete, err, sizeof err);
        int good = mode == 0 ? (!complete && bytes >= 32768 && bytes < 70000) :
                   mode == 1 ? (complete && bytes == 70000) :
                   (!complete && bytes == (mode == 2 ? 70000 : 68900));
        if (!good) {
            fprintf(stderr, "QUIC response mode %d: bytes=%llu complete=%d\n",
                    mode, (unsigned long long)bytes, complete); fails++;
        }
        d2k_qc_close(c); close(server);
    }
    /* Раунд 1: сбои чтения ТЕЛА тоже называют причину (после двоеточия не пусто). */
    {
        struct { const char *reply; int eof_err; const char *needle; } bad[] = {
            {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", 0, "не шестнадцатеричный"},
            {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXY0\r\n\r\n", 0, "нет CRLF"},
            {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\n", 0, "без CR"},
            {"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 0, "вместе с Transfer-Encoding"},
            {"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nabc", 0, "закрыл соединение посреди тела"},
            {"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nabc", 1, "ошибка чтения"},
            {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nx\r\n0\r\n\r\n", 0, "наш предел"},
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            fixture f = {bad[i].reply, 0, 64, bad[i].eof_err, 0};
            d2k_ver_result r = {0}; char err[200] = "";
            r.level = D2K_VER_HANDSHAKE;
            request_complete_page(fixture_read, fixture_write, &f, "example.com",
                0, NULL, 1000, 0, &r, err, sizeof err);
            const char *colon = strstr(r.reason, "байт): ");
            if (r.level == D2K_VER_APPLICATION || !colon || colon[strlen("байт): ")] == '\0' ||
                !strstr(r.reason, bad[i].needle) ||
                r.local_limit != (strstr(bad[i].needle, "предел") != NULL)) {
                fprintf(stderr, "body failure reason %zu: [%s] local %d\n", i, r.reason, r.local_limit); fails++;
            }
        }
    }
    /* Раунд 1: 1xx с длинными заголовками, затем длинный окончательный ответ. */
    {
        static char early[40 * 1024];
        size_t o = (size_t)snprintf(early, sizeof early, "HTTP/1.1 103 Early Hints\r\n");
        for (; o < 8500;) {
            o += (size_t)snprintf(early + o, sizeof early - o, "link: ");
            memset(early + o, 'l', 400); o += 400; early[o++] = '\r'; early[o++] = '\n';
        }
        o += (size_t)snprintf(early + o, sizeof early - o, "\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n");
        for (; o < 20000;) {
            o += (size_t)snprintf(early + o, sizeof early - o, "x-pad: ");
            memset(early + o, 'p', 400); o += 400; early[o++] = '\r'; early[o++] = '\n';
        }
        o += (size_t)snprintf(early + o, sizeof early - o, "\r\nbody");
        size_t frags[] = {1, 7, 1460, sizeof early};
        for (size_t k = 0; k < 4; k++) {
            fixture f = {early, 0, frags[k], 0, 0};
            d2k_ver_result r = {0}; char err[200] = "";
            r.level = D2K_VER_HANDSHAKE;
            request_complete_page(fixture_read, fixture_write, &f, "example.com",
                2, NULL, 1000, 0, &r, err, sizeof err);
            if (r.level != D2K_VER_APPLICATION || r.status != 200 || !r.body_complete) {
                fprintf(stderr, "1xx then long final, fragment %zu: level %d (%s)\n",
                    frags[k], r.level, r.reason); fails++;
            }
        }
    }
    {
        char target[1600], expected[1700];
        memset(target, 'x', 1400); target[1400] = 0;
        memcpy(target, "/videoplayback?token=", 20);
        snprintf(target + 1350, sizeof target - 1350, "%%2B&range=0-1048575");
        snprintf(expected, sizeof expected, "GET %s HTTP/1.1\r\n", target);
        fixture f = {"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody", 0, 64, 0, 0};
        d2k_ver_result r = {0}; char err[200] = "";
        request_complete_page(fixture_read, fetch_capture, &f, "example.com", 0, target,
                              1000, 0, &r, err, sizeof err);
        if (strncmp(fetch_request, expected, strlen(expected)) || !r.body_complete) {
            fprintf(stderr, "explicit fetch target was truncated or response incomplete\n"); fails++;
        }
    }
    fails += budget_checks();
    fails += read_body_checks();
    if (fails) return 1;
    puts("Production HTTP reader: 76 fragments + 4 stylesheet + 4 ECH + long-header (TCP 4+limit, H3 3) + 6 failure-reason + 15 flow-budget (TCP 11, QUIC 4) checks passed without sockets");
    return 0;
}
