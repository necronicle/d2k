/* quicconn.c — одно соединение QUIC. Контракт и границы — в d2k_quicconn.h.
 *
 * Байтовый уровень здесь не повторяется ни строкой: пакеты собирает и
 * разбирает core/quicwire.c, рукопожатие ведёт core/tls13core.c. Этот файл
 * отвечает ровно за то, чего нет ни там, ни там: за СОСТОЯНИЕ — три
 * пространства номеров, пересборку потока CRYPTO, подтверждения и повтор по
 * таймеру.
 */
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "d2k_crypto.h"
#include "d2k_meas.h"
#include "d2k_quicconn.h"
#include "d2k_quicwire.h"
#include "d2k_tls13core.h"

/* Типы кадров, которые этот модуль умеет назвать (RFC 9000 §19). Остальные
 * пропускаются по длине либо честно валят разбор — см. frames_in. */
#define FR_PADDING        0x00
#define FR_PING           0x01
#define FR_ACK            0x02
#define FR_ACK_ECN        0x03
#define FR_RESET_STREAM   0x04
#define FR_STOP_SENDING   0x05
#define FR_CRYPTO         0x06
#define FR_NEW_TOKEN      0x07
#define FR_STREAM_LO      0x08
#define FR_STREAM_HI      0x0f
#define FR_MAX_DATA       0x10
#define FR_MAX_STREAM_DATA 0x11
#define FR_MAX_STREAMS_BIDI 0x12
#define FR_MAX_STREAMS_UNI  0x13
#define FR_DATA_BLOCKED   0x14
#define FR_STREAM_DATA_BLOCKED 0x15
#define FR_STREAMS_BLOCKED_BIDI 0x16
#define FR_STREAMS_BLOCKED_UNI  0x17
#define FR_NEW_CONN_ID    0x18
#define FR_RETIRE_CONN_ID 0x19
#define FR_PATH_CHALLENGE 0x1a
#define FR_PATH_RESPONSE  0x1b
#define FR_CONN_CLOSE_Q   0x1c
#define FR_CONN_CLOSE_A   0x1d
#define FR_HANDSHAKE_DONE 0x1e

/* Сколько байт потока CRYPTO держим на уровень. Цепочка сертификатов бывает
 * в несколько килобайт и приезжает кусками из разных пакетов; меньше —
 * значит не собрать ServerHello..Finished, то есть не довести рукопожатие. */
#define CRYPTO_BUF 16384
/* Сколько байт прикладных данных держим на поток. Зонду нужен только
 * заголовочный кадр ответа; тело он не качает. */
#define STREAM_BUF 16384
/* Наибольшая датаграмма, которую отправляем и принимаем. 1452 — та же
 * оценка, что у max_udp_payload_size ниже: 1492 (PPPoE) минус заголовки
 * IPv4 и UDP. Принимаем с запасом: сервер вправе слать до 65527. */
#define DGRAM_OUT 1452
#define DGRAM_IN  2048

typedef struct {
    uint8_t buf[CRYPTO_BUF];
    uint8_t seen[CRYPTO_BUF];
    size_t  high;      /* докуда дотянулась сборка */
    size_t  taken;     /* сколько уже отдано разбору рукопожатия */
} crypto_rx;

typedef struct {
    d2k_qw_keys tx, rx;
    uint64_t    next_pn;    /* следующий свой номер */
    uint64_t    largest_rx; /* наибольший принятый (для восстановления номера) */
    int         have_rx;    /* принимали ли хоть один пакет этого уровня */
    int         ack_due;    /* пришло что-то, требующее подтверждения */
    crypto_rx   crypto;
} level;

struct d2k_qc {
    int      fd;
    uint32_t version;
    uint8_t  dcid[20], scid[20];
    size_t   dcid_len, scid_len;
    uint8_t  odcid[20];     /* DCID первого Initial — для проверки Retry и tp */
    size_t   odcid_len;

    level    lv[D2K_QW_LEVEL_COUNT];
    int      handshake_done;
    int      peer_cid_fixed;   /* SCID сервера принят как адрес ответа */
    int      peer_name;
    int      closed;

    uint8_t  transcript[CRYPTO_BUF];
    size_t   tr_len;
    uint8_t  hs_secret[32];
    /* Секрет КЛИЕНТСКОГО уровня рукопожатия держим отдельно: из него
       считается MAC нашего Finished, а к тому моменту он уже развёрнут в
       ключи и по ключам не восстанавливается. */
    uint8_t  c_hs_secret[32];

    /* Принятые прикладные данные ОДНОГО потока — того, на котором мы задали
       вопрос. Держать все подряд нельзя: сервер открывает свои
       однонаправленные потоки (управляющий, две таблицы QPACK), их байты
       приходят ПЕРВЫМИ, и ответ на запрос затерялся бы за ними. */
    uint64_t want_stream;
    int      have_want;
    uint64_t rx_stream;
    uint8_t  rx_data[STREAM_BUF];
    size_t   rx_len, rx_taken;
    int      rx_fin;

    /* Последняя прикладная посылка — для повтора по таймеру. Обнаружения
       потерь у нас нет и не нужно (см. шапку), но ОДИН повтор обязателен:
       наш запрос уходит сразу за нашим Finished, и сервер, ещё не успевший
       развернуть прикладные ключи, такой пакет просто отбрасывает. Без
       повтора запрос пропадает навсегда, а на замере это выглядит как
       «приложение не ответило» — тот самый ложный вывод, ради которого вся
       эта вертикаль и строится. */
    uint8_t  last_app[DGRAM_OUT];
    size_t   last_app_len;

    uint8_t  local_ip4[4];
    uint16_t local_port;
};

/* --- мелочи --------------------------------------------------------------- */

static void say(char *err, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void say(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) { return; }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

static int64_t now_ms(void) {
    struct timespec ts;
#ifdef CLOCK_MONOTONIC
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    }
#endif
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* --- пересборка потока CRYPTO --------------------------------------------- */

/* Кладёт кусок по его смещению В ПОТОКЕ. Перекрытия законны (повтор), дыры
 * законны (порядок датаграмм не гарантирован) — поэтому карта занятых байт, а
 * не «дописать в конец». */
static void crypto_put(crypto_rx *c, uint64_t off, const uint8_t *p, size_t n) {
    if (off >= CRYPTO_BUF) { return; }
    if (off + n > CRYPTO_BUF) { n = CRYPTO_BUF - (size_t)off; }
    for (size_t i = 0; i < n; i++) {
        c->buf[off + i] = p[i];
        c->seen[off + i] = 1;
    }
    if (off + n > c->high) { c->high = (size_t)off + n; }
}

/* Сколько байт подряд готово с начала потока. */
static size_t crypto_ready(const crypto_rx *c) {
    size_t i = 0;
    while (i < c->high && c->seen[i]) { i++; }
    return i;
}

/* --- отправка -------------------------------------------------------------- */

/* Кадр ACK по одному диапазону: наибольший принятый и сколько идёт подряд.
 * Диапазонами сложнее нам не нужно — за два пакета рукопожатия дыр не
 * набирается, а соврать в ACK нельзя: сервер поверит и не переотправит. */
static size_t build_ack(uint8_t *out, size_t cap, uint64_t largest) {
    if (cap < 8) { return 0; }
    size_t o = 0;
    out[o++] = FR_ACK;
    o += d2k_qw_varint_write(out + o, cap - o, largest);
    o += d2k_qw_varint_write(out + o, cap - o, 0);   /* задержка */
    o += d2k_qw_varint_write(out + o, cap - o, 0);   /* диапазонов сверх первого нет */
    o += d2k_qw_varint_write(out + o, cap - o, 0);   /* первый диапазон: один пакет */
    return o;
}

/* Отправляет один пакет уровня lvl с готовым телом. pad_to — добить всю
 * датаграмму до этой длины PADDING'ом (для Initial обязательно 1200). */
static int send_level(d2k_qc *c, d2k_qw_level lvl, const uint8_t *payload,
                      size_t payload_len, size_t pad_to, char *err, size_t errcap) {
    level *L = &c->lv[lvl];
    if (!L->tx.have) { say(err, errcap, "нет ключей уровня для отправки"); return -1; }

    uint8_t body[DGRAM_OUT];
    if (payload_len > sizeof body) { say(err, errcap, "тело пакета длиннее датаграммы"); return -1; }
    memcpy(body, payload, payload_len);
    size_t blen = payload_len;

    uint8_t pkt[DGRAM_OUT];
    size_t pn_len = d2k_qw_pn_len(L->next_pn, -1);
    size_t hlen;
    if (lvl == D2K_QW_LEVEL_APP) {
        size_t o = 0;
        pkt[o++] = 0x40;                       /* короткий заголовок, фикс. бит */
        memcpy(pkt + o, c->dcid, c->dcid_len); o += c->dcid_len;
        hlen = o;
    } else {
        uint8_t type = (lvl == D2K_QW_LEVEL_INITIAL) ? D2K_QW_LT_INITIAL
                                                     : D2K_QW_LT_HANDSHAKE;
        /* Добивка должна попасть ВНУТРЬ пакета, иначе поле Length соврёт. */
        if (pad_to) {
            /* Заголовок считаем предварительно, чтобы узнать, сколько
               PADDING'а нужно: его длина зависит от длины заголовка, а та —
               от поля Length, то есть от длины тела. Два прохода дешевле, чем
               гадание. */
            uint8_t probe[64];
            size_t h0 = d2k_qw_long_hdr(probe, sizeof probe, c->version, type,
                                        c->dcid, c->dcid_len,
                                        c->scid, c->scid_len, pn_len, blen);
            if (h0 == 0) { say(err, errcap, "заголовок не собрался"); return -1; }
            size_t total = h0 + pn_len + blen + 16;
            if (total < pad_to && blen + (pad_to - total) <= sizeof body) {
                size_t add = pad_to - total;
                memset(body + blen, 0, add);   /* PADDING это нули */
                blen += add;
            }
        }
        hlen = d2k_qw_long_hdr(pkt, sizeof pkt, c->version, type,
                               c->dcid, c->dcid_len,
                               c->scid, c->scid_len, pn_len, blen);
    }

    size_t n = d2k_qw_seal(&L->tx, lvl != D2K_QW_LEVEL_APP, pkt, hlen,
                           L->next_pn, pn_len, body, blen, pkt, sizeof pkt);
    if (n == 0) { say(err, errcap, "пакет не собрался"); return -1; }
    if (getenv("D2K_QC_TRACE")) {
        fprintf(stderr, "[шлём] уровень %d номер %llu байт %zu тело %zu\n",
                (int)lvl, (unsigned long long)L->next_pn, n, blen);
    }
    L->next_pn++;
    if (send(c->fd, pkt, n, 0) != (ssize_t)n) {
        say(err, errcap, "датаграмма не ушла: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* --- transport parameters -------------------------------------------------- */

static size_t tp_put_int(uint8_t *p, size_t cap, uint64_t id, uint64_t v) {
    size_t o = 0;
    size_t vlen = d2k_qw_varint_len(v);
    o += d2k_qw_varint_write(p + o, cap - o, id);
    o += d2k_qw_varint_write(p + o, cap - o, vlen);
    o += d2k_qw_varint_write(p + o, cap - o, v);
    return o;
}

/* Собирает расширение quic_transport_parameters целиком, готовым к вставке в
 * ClientHello. Набор — минимальный обязательный плюс пределы, при которых
 * сервер согласится что-то прислать: без initial_max_stream_data_* он вправе
 * не отдать ни байта, и «сервер молчит» стало бы нашей же настройкой. */
static size_t tp_build(const d2k_qc *c, uint8_t *out, size_t cap) {
    uint8_t v[256];
    size_t o = 0;
    o += tp_put_int(v + o, sizeof v - o, 0x01, 30000);     /* max_idle_timeout */
    o += tp_put_int(v + o, sizeof v - o, 0x03, 1452);      /* max_udp_payload_size */
    o += tp_put_int(v + o, sizeof v - o, 0x04, 1048576);   /* initial_max_data */
    o += tp_put_int(v + o, sizeof v - o, 0x05, 262144);    /* bidi_local */
    o += tp_put_int(v + o, sizeof v - o, 0x06, 262144);    /* bidi_remote */
    o += tp_put_int(v + o, sizeof v - o, 0x07, 262144);    /* uni */
    o += tp_put_int(v + o, sizeof v - o, 0x08, 16);        /* max_streams_bidi */
    o += tp_put_int(v + o, sizeof v - o, 0x09, 16);        /* max_streams_uni */
    o += tp_put_int(v + o, sizeof v - o, 0x0e, 2);         /* active_connection_id_limit */
    /* initial_source_connection_id ОБЯЗАТЕЛЕН (RFC 9000 §7.3): им сервер
       сверяет, что SCID наших пакетов не подменили по дороге. */
    o += d2k_qw_varint_write(v + o, sizeof v - o, 0x0f);
    o += d2k_qw_varint_write(v + o, sizeof v - o, c->scid_len);
    memcpy(v + o, c->scid, c->scid_len); o += c->scid_len;

    if (cap < o + 4) { return 0; }
    out[0] = 0x00; out[1] = 0x39;                 /* тип расширения */
    out[2] = (uint8_t)(o >> 8); out[3] = (uint8_t)o;
    memcpy(out + 4, v, o);
    return o + 4;
}

/* --- разбор кадров --------------------------------------------------------- */

/* Разбирает кадры расшифрованного пакета уровня lvl.
 * 0 — разобрано, -1 — встречен кадр, о котором мы не можем рассуждать. */
static int frames_in(d2k_qc *c, d2k_qw_level lvl, const uint8_t *p, size_t n,
                     char *err, size_t errcap) {
    size_t i = 0;
    while (i < n) {
        uint64_t t = 0; size_t w = 0;
        if (d2k_qw_varint_read(p + i, n - i, &t, &w) != 0) { return -1; }
        i += w;
        if (getenv("D2K_QC_TRACE")) {
            fprintf(stderr, "[кадр] уровень %d тип 0x%llx\n", (int)lvl,
                    (unsigned long long)t);
        }
        switch (t) {
        case FR_PADDING:
        case FR_PING:
            break;
        case FR_ACK:
        case FR_ACK_ECN: {
            uint64_t largest = 0, delay = 0, cnt = 0, first = 0;
            if (d2k_qw_varint_read(p + i, n - i, &largest, &w) != 0) { return -1; } i += w;
            if (d2k_qw_varint_read(p + i, n - i, &delay, &w) != 0) { return -1; } i += w;
            if (d2k_qw_varint_read(p + i, n - i, &cnt, &w) != 0) { return -1; } i += w;
            if (d2k_qw_varint_read(p + i, n - i, &first, &w) != 0) { return -1; } i += w;
            for (uint64_t r = 0; r < cnt; r++) {
                uint64_t gap = 0, len = 0;
                if (d2k_qw_varint_read(p + i, n - i, &gap, &w) != 0) { return -1; } i += w;
                if (d2k_qw_varint_read(p + i, n - i, &len, &w) != 0) { return -1; } i += w;
            }
            if (t == FR_ACK_ECN) {
                for (int e = 0; e < 3; e++) {
                    uint64_t x = 0;
                    if (d2k_qw_varint_read(p + i, n - i, &x, &w) != 0) { return -1; } i += w;
                }
            }
            break;
        }
        case FR_CRYPTO: {
            uint64_t off = 0, len = 0;
            if (d2k_qw_varint_read(p + i, n - i, &off, &w) != 0) { return -1; } i += w;
            if (d2k_qw_varint_read(p + i, n - i, &len, &w) != 0) { return -1; } i += w;
            if (len > n - i) { return -1; }
            crypto_put(&c->lv[lvl].crypto, off, p + i, (size_t)len);
            i += (size_t)len;
            break;
        }
        case FR_NEW_TOKEN: {
            uint64_t len = 0;
            if (d2k_qw_varint_read(p + i, n - i, &len, &w) != 0) { return -1; } i += w;
            if (len > n - i) { return -1; }
            i += (size_t)len;
            break;
        }
        case FR_HANDSHAKE_DONE:
            c->handshake_done = 1;
            break;
        case FR_NEW_CONN_ID: {
            /* Пропуск ТОЧНЫЙ: за длинами идут ещё шестнадцать байт токена
               сброса, и пропуск без них сдвигает разбор всего пакета — на
               замере это выглядит как «сервер прислал мусор». */
            uint64_t seq = 0, ret = 0;
            if (d2k_qw_varint_read(p + i, n - i, &seq, &w) != 0) { return -1; } i += w;
            if (d2k_qw_varint_read(p + i, n - i, &ret, &w) != 0) { return -1; } i += w;
            if (i >= n) { return -1; }
            size_t cl = p[i++];
            if (cl > n - i) { return -1; }
            /* ОТЗЫВ ИДЕНТИФИКАТОРА — не вежливость, а обязанность.
               retire_prior_to больше нуля означает, что идентификатор, которым
               мы адресуем пакеты, СНЯТ, и пакеты с ним сервер обязан
               отбрасывать (RFC 9000 §19.15, §5.1.2). Без этого перехода
               рукопожатие сходится, а прикладные пакеты уходят в никуда:
               измерено на живых серверах — одни продолжали узнавать старый
               идентификатор, другие молча не отвечали. */
            if (ret > 0 && cl > 0 && cl <= D2K_QW_CID_MAX) {
                memcpy(c->dcid, p + i, cl);
                c->dcid_len = cl;
                c->peer_cid_fixed = 1;
            }
            i += cl;
            if (16 > n - i) { return -1; }
            i += 16;
            break;
        }
        case FR_RETIRE_CONN_ID:
        case FR_MAX_DATA:
        case FR_MAX_STREAMS_BIDI:
        case FR_MAX_STREAMS_UNI:
        case FR_DATA_BLOCKED:
        case FR_STREAMS_BLOCKED_BIDI:
        case FR_STREAMS_BLOCKED_UNI: {
            uint64_t x = 0;
            if (d2k_qw_varint_read(p + i, n - i, &x, &w) != 0) { return -1; } i += w;
            break;
        }
        case FR_MAX_STREAM_DATA:
        case FR_STREAM_DATA_BLOCKED:
        case FR_STOP_SENDING: {
            uint64_t a = 0, b = 0;
            if (d2k_qw_varint_read(p + i, n - i, &a, &w) != 0) { return -1; } i += w;
            if (d2k_qw_varint_read(p + i, n - i, &b, &w) != 0) { return -1; } i += w;
            break;
        }
        case FR_RESET_STREAM: {
            uint64_t a = 0, b = 0, d = 0;
            if (d2k_qw_varint_read(p + i, n - i, &a, &w) != 0) { return -1; } i += w;
            if (d2k_qw_varint_read(p + i, n - i, &b, &w) != 0) { return -1; } i += w;
            if (d2k_qw_varint_read(p + i, n - i, &d, &w) != 0) { return -1; } i += w;
            break;
        }
        case FR_PATH_CHALLENGE:
        case FR_PATH_RESPONSE:
            if (8 > n - i) { return -1; }
            i += 8;
            break;
        case FR_CONN_CLOSE_Q:
        case FR_CONN_CLOSE_A: {
            uint64_t code = 0, ftype = 0, rlen = 0;
            if (d2k_qw_varint_read(p + i, n - i, &code, &w) != 0) { return -1; } i += w;
            if (t == FR_CONN_CLOSE_Q) {
                if (d2k_qw_varint_read(p + i, n - i, &ftype, &w) != 0) { return -1; } i += w;
            }
            if (d2k_qw_varint_read(p + i, n - i, &rlen, &w) != 0) { return -1; } i += w;
            if (rlen > n - i) { return -1; }
            i += (size_t)rlen;
            c->closed = 1;
            say(err, errcap, "сервер закрыл соединение кодом %llu",
                (unsigned long long)code);
            return -1;
        }
        default:
            if (t >= FR_STREAM_LO && t <= FR_STREAM_HI) {
                uint64_t sid = 0, off = 0, len = 0;
                if (d2k_qw_varint_read(p + i, n - i, &sid, &w) != 0) { return -1; } i += w;
                if (t & 0x04) {
                    if (d2k_qw_varint_read(p + i, n - i, &off, &w) != 0) { return -1; } i += w;
                }
                if (t & 0x02) {
                    if (d2k_qw_varint_read(p + i, n - i, &len, &w) != 0) { return -1; } i += w;
                } else {
                    len = n - i;   /* без поля длины кадр тянется до конца пакета */
                }
                if (len > n - i) { return -1; }
                if (getenv("D2K_QC_TRACE")) {
                    fprintf(stderr, "[поток] %llu смещение %llu байт %llu fin %d\n",
                            (unsigned long long)sid, (unsigned long long)off,
                            (unsigned long long)len, (int)(t & 1));
                }
                /* Держим данные ОДНОГО потока — того, чей ответ ждём. Прочие
                   (управляющий поток сервера, QPACK) пропускаем: разбирать их
                   зонду незачем, а притворяться, что разобрали, нельзя. */
                int mine = c->have_want ? (sid == c->want_stream)
                                        : (c->rx_len == 0 || c->rx_stream == sid);
                if (mine) {
                    c->rx_stream = sid;
                    if (off < STREAM_BUF) {
                        size_t take = (size_t)len;
                        if (off + take > STREAM_BUF) { take = STREAM_BUF - (size_t)off; }
                        memcpy(c->rx_data + off, p + i, take);
                        if (off + take > c->rx_len) { c->rx_len = (size_t)off + take; }
                    }
                    if (t & 0x01) { c->rx_fin = 1; }
                }
                i += (size_t)len;
                break;
            }
            say(err, errcap, "неизвестный кадр 0x%llx", (unsigned long long)t);
            return -1;
        }
    }
    return 0;
}

/* --- приём ---------------------------------------------------------------- */

/* Читает одну датаграмму (не дольше wait_ms) и разбирает ВСЕ пакеты в ней.
 * 1 — что-то разобрали, 0 — за это время ничего не пришло, -1 — отказ. */
static int recv_dgram(d2k_qc *c, int wait_ms, char *err, size_t errcap) {
    struct pollfd pfd;
    pfd.fd = c->fd; pfd.events = POLLIN; pfd.revents = 0;
    int pr = poll(&pfd, 1, wait_ms);
    if (pr == 0) { return 0; }
    if (pr < 0) {
        if (errno == EINTR) { return 0; }
        say(err, errcap, "ожидание не удалось: %s", strerror(errno));
        return -1;
    }
    uint8_t buf[DGRAM_IN];
    ssize_t n = recv(c->fd, buf, sizeof buf, 0);
    if (n <= 0) {
        say(err, errcap, "датаграмма не прочиталась: %s",
            n == 0 ? "пусто" : strerror(errno));
        return -1;
    }

    size_t off = 0;
    int any = 0;
    while (off < (size_t)n) {
        d2k_qw_hdr h;
        if (d2k_qw_hdr_parse(buf + off, (size_t)n - off, c->scid_len, &h) != 0) {
            break;   /* хвост датаграммы не разбирается — по контракту молча бросаем */
        }
        d2k_qw_level lvl;
        if (!h.long_hdr) {
            lvl = D2K_QW_LEVEL_APP;
        } else if (h.type == D2K_QW_LT_INITIAL) {
            lvl = D2K_QW_LEVEL_INITIAL;
        } else if (h.type == D2K_QW_LT_HANDSHAKE) {
            lvl = D2K_QW_LEVEL_HANDSHAKE;
        } else if (h.type == D2K_QW_LT_RETRY) {
            say(err, errcap, "сервер ответил Retry — повторное обращение не реализовано");
            return -1;
        } else {
            off += h.packet_len;
            continue;   /* 0-RTT нам не адресован */
        }
        level *L = &c->lv[lvl];
        if (!L->rx.have) {
            off += h.packet_len;
            continue;   /* ключей этого уровня ещё нет — пакет не наш черёд */
        }
        uint8_t plain[DGRAM_IN];
        size_t plen = 0;
        uint64_t pn = 0;
        if (d2k_qw_open(&L->rx, &h, buf + off, L->have_rx ? L->largest_rx : 0,
                        plain, &plen, &pn) != 0) {
            off += h.packet_len;
            continue;   /* не открылось — не наш пакет, а не повод падать */
        }
        /* АДРЕС ОТВЕТА — SCID СЕРВЕРА, а не тот случайный DCID, который мы
           выдумали для первого Initial. RFC 9000 §7.2: «the client MUST use
           the value from the Source Connection ID field of the first received
           packet». Ключи уровня Initial при этом остаются выведенными из
           ПЕРВОГО DCID (RFC 9001 §5.2) — меняется адресация, а не секреты.

           Пока этого не было, всё работало у серверов, которые продолжают
           узнавать старый идентификатор, и МОЛЧА не работало у тех, кто выдаёт
           свой: рукопожатие сходилось, а прикладные пакеты сервер не принимал
           и повторял свой флайт до истечения времени. */
        if (h.long_hdr && !c->peer_cid_fixed && h.scid_len > 0 &&
            h.scid_len <= D2K_QW_CID_MAX) {
            memcpy(c->dcid, buf + off + h.scid_off, h.scid_len);
            c->dcid_len = h.scid_len;
            c->peer_cid_fixed = 1;
        }
        if (!L->have_rx || pn > L->largest_rx) { L->largest_rx = pn; }
        L->have_rx = 1;
        L->ack_due = 1;
        any = 1;
        if (frames_in(c, lvl, plain, plen, err, errcap) != 0) { return -1; }
        off += h.packet_len;
    }
    return any;
}

/* --- рукопожатие ----------------------------------------------------------- */

/* Кладёт готовое сообщение рукопожатия в кадр CRYPTO. */
static size_t crypto_frame(uint8_t *out, size_t cap, uint64_t off,
                           const uint8_t *msg, size_t n) {
    size_t o = 0;
    out[o++] = FR_CRYPTO;
    o += d2k_qw_varint_write(out + o, cap - o, off);
    o += d2k_qw_varint_write(out + o, cap - o, n);
    if (o + n > cap) { return 0; }
    memcpy(out + o, msg, n); o += n;
    return o;
}

int d2k_qc_connect(const d2k_qc_opts *o, d2k_qc **out, char *err, size_t errcap) {
    if (err && errcap) { err[0] = '\0'; }
    if (!o || !o->ip || !out) { say(err, errcap, "нечем поднимать соединение"); return -1; }
    *out = NULL;

    d2k_qc *c = calloc(1, sizeof *c);
    if (!c) { say(err, errcap, "не хватило памяти"); return -1; }
    c->fd = -1;
    c->peer_name = -1;
    c->version = D2K_QW_V1;

    c->dcid_len = c->scid_len = 8;
    uint8_t priv[32], pub[32], rnd[32];
    if (d2k_t13_random(c->dcid, c->dcid_len) != 0 ||
        d2k_t13_random(c->scid, c->scid_len) != 0 ||
        d2k_t13_random(priv, 32) != 0 || d2k_t13_random(rnd, 32) != 0) {
        say(err, errcap, "нет случайности: /dev/urandom недоступен");
        free(c); return -1;
    }
    memcpy(c->odcid, c->dcid, c->dcid_len);
    c->odcid_len = c->dcid_len;
    if (d2k_x25519_base(pub, priv) != 0) {
        say(err, errcap, "открытый ключ не посчитался"); free(c); return -1;
    }

    c->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (c->fd < 0) { say(err, errcap, "сокет: %s", strerror(errno)); free(c); return -1; }
    if (o->mark) { (void)d2k_mark_hook(c->fd, o->mark); }

    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(o->port ? o->port : 443);
    if (inet_pton(AF_INET, o->ip, &to.sin_addr) != 1) {
        say(err, errcap, "адрес не разбирается"); d2k_qc_close(c); return -1;
    }
    /* connect на UDP не шлёт ни байта: он привязывает сокет к направлению,
       чтобы приходили ошибки ICMP и чтобы recv не принимал чужое. */
    if (connect(c->fd, (struct sockaddr *)&to, sizeof to) != 0) {
        say(err, errcap, "connect: %s", strerror(errno)); d2k_qc_close(c); return -1;
    }
    struct sockaddr_in me;
    socklen_t ml = sizeof me;
    if (getsockname(c->fd, (struct sockaddr *)&me, &ml) == 0) {
        memcpy(c->local_ip4, &me.sin_addr.s_addr, 4);
        c->local_port = ntohs(me.sin_port);
    }

    /* Ключи уровня Initial: обе стороны выводятся из DCID нашего первого
       пакета (RFC 9001 §5.2). */
    uint8_t sec[32];
    if (d2k_qw_initial_secret(c->version, c->dcid, c->dcid_len, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(c->version, sec, &c->lv[D2K_QW_LEVEL_INITIAL].tx) != 0 ||
        d2k_qw_initial_secret(c->version, c->dcid, c->dcid_len, D2K_QW_SERVER, sec) != 0 ||
        d2k_qw_keys_from_secret(c->version, sec, &c->lv[D2K_QW_LEVEL_INITIAL].rx) != 0) {
        say(err, errcap, "начальные ключи не вывелись"); d2k_qc_close(c); return -1;
    }

    /* ClientHello с транспортными параметрами и ALPN. */
    uint8_t tp[320];
    size_t tp_len = tp_build(c, tp, sizeof tp);
    if (tp_len == 0) { say(err, errcap, "транспортные параметры не собрались"); d2k_qc_close(c); return -1; }

    uint8_t ch[2560];
    d2k_t13_ch_opts cho;
    memset(&cho, 0, sizeof cho);
    cho.sni = o->sni;
    cho.pub = pub;
    cho.random = rnd;
    cho.session_id_len = 0;      /* RFC 9001 §8.4: у QUIC он обязан быть пуст */
    cho.alpn = o->alpn ? o->alpn : "h3";
    cho.extra = tp;
    cho.extra_len = tp_len;
    cho.pad_to = o->pad_to;
    size_t ch_len = d2k_t13_ch_build(&cho, ch, sizeof ch);
    if (ch_len == 0) { say(err, errcap, "приветствие не собралось"); d2k_qc_close(c); return -1; }
    memcpy(c->transcript, ch, ch_len);
    c->tr_len = ch_len;

    uint8_t frame[2600];
    size_t flen = crypto_frame(frame, sizeof frame, 0, ch, ch_len);
    if (flen == 0) { say(err, errcap, "кадр CRYPTO не собрался"); d2k_qc_close(c); return -1; }
    /* Первая датаграмма клиента обязана быть не короче 1200 байт
       (RFC 9000 §14.1): иначе сервер вправе её не обслуживать. */
    if (send_level(c, D2K_QW_LEVEL_INITIAL, frame, flen, 1200, err, errcap) != 0) {
        d2k_qc_close(c); return -1;
    }

    int64_t deadline = now_ms() + (o->deadline_ms > 0 ? o->deadline_ms : 5000);
    int64_t pto = now_ms() + 333;      /* RFC 9002 §6.2.2: стартовый RTT до замера */
    int tries = 0;
    int sh_done = 0, hs_keys = 0;

    while (now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        int wait = left > 50 ? 50 : left;
        int r = recv_dgram(c, wait, err, errcap);
        if (r < 0) { d2k_qc_close(c); return -1; }

        /* Разбираем то, что собралось на уровне Initial: ServerHello. */
        if (!sh_done) {
            crypto_rx *cr = &c->lv[D2K_QW_LEVEL_INITIAL].crypto;
            size_t ready = crypto_ready(cr);
            size_t off = cr->taken;
            uint8_t mt = 0; const uint8_t *body = NULL; size_t blen = 0;
            while (d2k_t13_flight_next(cr->buf, ready, &off, &mt, &body, &blen)) {
                size_t msg_len = blen + 4;
                if (c->tr_len + msg_len > sizeof c->transcript) { break; }
                memcpy(c->transcript + c->tr_len, body - 4, msg_len);
                c->tr_len += msg_len;
                cr->taken = off;
                if (mt == D2K_T13_SERVER_HELLO) {
                    const uint8_t *peer = NULL;
                    if (d2k_t13_sh_parse(body - 4, msg_len, &peer, err, errcap) != 0) {
                        d2k_qc_close(c); return -1;
                    }
                    uint8_t shared[32], c_hs[32], s_hs[32];
                    if (d2k_x25519(shared, priv, peer) != 0) {
                        say(err, errcap, "общий секрет не посчитался");
                        d2k_qc_close(c); return -1;
                    }
                    if (d2k_t13_schedule_hs(shared, c->transcript, c->tr_len,
                                            c_hs, s_hs, c->hs_secret) != 0 ||
                        d2k_qw_keys_from_secret(c->version, c_hs,
                                                &c->lv[D2K_QW_LEVEL_HANDSHAKE].tx) != 0 ||
                        d2k_qw_keys_from_secret(c->version, s_hs,
                                                &c->lv[D2K_QW_LEVEL_HANDSHAKE].rx) != 0) {
                        say(err, errcap, "ключи рукопожатия не собрались");
                        d2k_qc_close(c); return -1;
                    }
                    memcpy(c->c_hs_secret, c_hs, 32);
                    sh_done = 1; hs_keys = 1;
                }
            }
        }

        /* Флайт сервера на уровне Handshake: EE, Certificate, CV, Finished. */
        int fin_seen = 0;
        if (hs_keys) {
            crypto_rx *cr = &c->lv[D2K_QW_LEVEL_HANDSHAKE].crypto;
            size_t ready = crypto_ready(cr);
            size_t off = cr->taken;
            uint8_t mt = 0; const uint8_t *body = NULL; size_t blen = 0;
            while (d2k_t13_flight_next(cr->buf, ready, &off, &mt, &body, &blen)) {
                size_t msg_len = blen + 4;
                if (c->tr_len + msg_len > sizeof c->transcript) { break; }
                memcpy(c->transcript + c->tr_len, body - 4, msg_len);
                c->tr_len += msg_len;
                cr->taken = off;
                if (mt == D2K_T13_CERTIFICATE && o->sni && o->sni[0]) {
                    c->peer_name = d2k_t13_cert_name_ok(body, blen, o->sni);
                }
                if (mt == D2K_T13_FINISHED) { fin_seen = 1; }
            }
        }

        /* Подтверждения. Их нельзя откладывать: пока сервер не увидит ACK
           уровня Handshake, он упирается в предел троекратного усиления и
           замолкает — на замере это неотличимо от блокировки. */
        for (int l = 0; l < D2K_QW_LEVEL_COUNT; l++) {
            level *L = &c->lv[l];
            if (!L->ack_due || !L->tx.have) { continue; }
            uint8_t ab[32];
            size_t an = build_ack(ab, sizeof ab, L->largest_rx);
            if (an && send_level(c, (d2k_qw_level)l, ab, an, 0, err, errcap) == 0) {
                L->ack_due = 0;
            }
        }

        if (fin_seen) {
            /* Прикладные ключи считаются от транскрипта ДО нашего Finished. */
            uint8_t c_ap[32], s_ap[32];
            if (d2k_t13_schedule_ap(c->hs_secret, c->transcript, c->tr_len,
                                    c_ap, s_ap) != 0 ||
                d2k_qw_keys_from_secret(c->version, c_ap, &c->lv[D2K_QW_LEVEL_APP].tx) != 0 ||
                d2k_qw_keys_from_secret(c->version, s_ap, &c->lv[D2K_QW_LEVEL_APP].rx) != 0) {
                say(err, errcap, "прикладные ключи не собрались");
                d2k_qc_close(c); return -1;
            }
            uint8_t verify[32];
            if (d2k_t13_finished_mac(c->c_hs_secret, c->transcript, c->tr_len, verify) != 0) {
                say(err, errcap, "подтверждение не собралось");
                d2k_qc_close(c); return -1;
            }
            uint8_t fin[4 + 32];
            fin[0] = D2K_T13_FINISHED; fin[1] = 0; fin[2] = 0; fin[3] = 32;
            memcpy(fin + 4, verify, 32);
            uint8_t fr[64];
            size_t fn = crypto_frame(fr, sizeof fr, 0, fin, sizeof fin);
            if (fn == 0 || send_level(c, D2K_QW_LEVEL_HANDSHAKE, fr, fn, 0, err, errcap) != 0) {
                d2k_qc_close(c); return -1;
            }
            *out = c;
            return 0;
        }

        if (r == 0 && now_ms() >= pto) {
            /* Потери на рукопожатии лечим повтором того же: контроля
               перегрузки у нас нет и не нужно (см. шапку). */
            if (++tries > 3) { break; }
            pto = now_ms() + (333 << tries);
            if (!sh_done) {
                (void)send_level(c, D2K_QW_LEVEL_INITIAL, frame, flen, 1200, err, errcap);
            }
        }
    }

    say(err, errcap, "%s", c->closed ? err : "рукопожатие не завершилось за отведённое время");
    d2k_qc_close(c);
    return -1;
}

int d2k_qc_stream_send(d2k_qc *c, uint64_t stream_id, const uint8_t *data, size_t n,
                       int fin, char *err, size_t errcap) {
    if (!c || !c->lv[D2K_QW_LEVEL_APP].tx.have) {
        say(err, errcap, "прикладных ключей нет"); return -1;
    }
    /* Поток, открытый КЛИЕНТОМ и двунаправленный (номер кратен четырём), —
       это наш вопрос, и ответ придёт по нему же. Запоминаем его, чтобы не
       перепутать с однонаправленными потоками сервера. */
    if ((stream_id & 0x03) == 0) {
        c->want_stream = stream_id;
        c->have_want = 1;
        /* Всё, что успело накопиться до вопроса, — чужое: управляющий поток
           сервера и таблицы QPACK. Смешать их с ответом значит подать разбору
           байты двух разных потоков как один. */
        c->rx_len = c->rx_taken = 0;
        c->rx_fin = 0;
    }
    uint8_t fr[DGRAM_OUT];
    size_t o = 0;
    fr[o++] = (uint8_t)(FR_STREAM_LO | 0x02 | (fin ? 0x01 : 0x00)); /* с длиной */
    o += d2k_qw_varint_write(fr + o, sizeof fr - o, stream_id);
    o += d2k_qw_varint_write(fr + o, sizeof fr - o, n);
    if (o + n > sizeof fr) { say(err, errcap, "данные не помещаются в датаграмму"); return -1; }
    memcpy(fr + o, data, n); o += n;
    /* Повторяем ПОСЛЕДНЮЮ посылку — ту, ответа на которую ждём. Накопление
       всех подряд проверено и отвергнуто: повтор управляющего потока вместе с
       запросом сервер перестал обслуживать вовсе (измерено на cloudflare.com,
       13.09.2026). Кадры потока идемпотентны по смещению, но повторять их
       пачкой оказалось хуже, чем не повторять. */
    if (o <= sizeof c->last_app) {
        memcpy(c->last_app, fr, o);
        c->last_app_len = o;
    }
    return send_level(c, D2K_QW_LEVEL_APP, fr, o, 0, err, errcap);
}

long d2k_qc_stream_recv(d2k_qc *c, uint64_t *stream_out, uint8_t *buf, size_t cap,
                        int wait_ms, char *err, size_t errcap) {
    if (!c || !buf) { return -1; }
    int64_t until = now_ms() + (wait_ms > 0 ? wait_ms : 0);
    int64_t pto = now_ms() + 300;
    int tries = 0;
    for (;;) {
        if (c->rx_len > c->rx_taken) {
            size_t have = c->rx_len - c->rx_taken;
            if (have > cap) { have = cap; }
            memcpy(buf, c->rx_data + c->rx_taken, have);
            c->rx_taken += have;
            if (stream_out) { *stream_out = c->rx_stream; }
            return (long)have;
        }
        int left = (int)(until - now_ms());
        if (left <= 0) { return 0; }
        int r = recv_dgram(c, left > 50 ? 50 : left, err, errcap);
        if (r < 0) { return -1; }
        /* Повтор последней посылки по таймеру: см. last_app в структуре. */
        if (c->rx_len == 0 && c->last_app_len && now_ms() >= pto && tries < 3) {
            tries++;
            pto = now_ms() + (300 << tries);
            (void)send_level(c, D2K_QW_LEVEL_APP, c->last_app, c->last_app_len,
                             0, err, errcap);
        }
        /* Подтверждаем принятое: сервер не станет досылать, пока молчим. */
        level *L = &c->lv[D2K_QW_LEVEL_APP];
        if (L->ack_due && L->tx.have) {
            uint8_t ab[32];
            size_t an = build_ack(ab, sizeof ab, L->largest_rx);
            if (an && send_level(c, D2K_QW_LEVEL_APP, ab, an, 0, err, errcap) == 0) {
                L->ack_due = 0;
            }
        }
    }
}

int d2k_qc_peer_name(const d2k_qc *c) { return c ? c->peer_name : -1; }
int d2k_qc_handshake_done(const d2k_qc *c) { return c ? c->handshake_done : 0; }
int d2k_qc_fd(const d2k_qc *c) { return c ? c->fd : -1; }

void d2k_qc_local(const d2k_qc *c, uint8_t ip4[4], uint16_t *port) {
    if (!c) { return; }
    if (ip4) { memcpy(ip4, c->local_ip4, 4); }
    if (port) { *port = c->local_port; }
}

int d2k_qc_release(d2k_qc *c) {
    if (!c) { return -1; }
    int fd = c->fd;
    c->fd = -1;      /* чтобы close не тронул чужой теперь дескриптор */
    free(c);
    return fd;
}

void d2k_qc_close(d2k_qc *c) {
    if (!c) { return; }
    if (c->fd >= 0) { close(c->fd); }
    free(c);
}
