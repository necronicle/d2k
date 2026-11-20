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
#include "d2k_verify.h"
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
 * заголовочный кадр ответа; тело он не качает. Равно пределу заголовков
 * проверки (D2K_VERIFY_HEADER_LIMIT): прежние 16 КБ молча обрезали ответ, и
 * заголовки Meta длиннее них выглядели как «приложение молчит» (задача 44).
 * d2k_qc выделен на куче (calloc), так что буфер не лежит на стеке. */
#define STREAM_BUF D2K_VERIFY_HEADER_LIMIT
/* Наибольшая датаграмма, которую отправляем и принимаем. 1452 — та же
 * оценка, что у max_udp_payload_size ниже: 1492 (PPPoE) минус заголовки
 * IPv4 и UDP. Принимаем с запасом: сервер вправе слать до 65527. */
#define DGRAM_OUT 1452
/* Окна, объявленные в транспортных параметрах (tp_build). */
#define D2K_QC_STREAM_WIN 262144u
#define D2K_QC_CONN_WIN   1048576u
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
    /* НАИБОЛЬШИЙ НОМЕР НАШЕГО ПАКЕТА, ПОДТВЕРЖДЁННЫЙ СЕРВЕРОМ. Это
       единственное доказательство того, что наши пакеты до него ДОХОДЯТ:
       входящие датаграммы его не дают — сервер шлёт их и когда наше
       направление заглушено (повтор по PTO). have_acked, потому что нулевой
       номер пакета законен. */
    uint64_t    largest_acked;
    int         have_acked;
    uint64_t    rx_pkts;    /* принято пакетов этого уровня, с повторами */
    crypto_rx   crypto;
} level;

struct d2k_qc {
    int      fd;
    uint32_t version;
    uint8_t  dcid[20], scid[20];
    size_t   dcid_len, scid_len;
    uint8_t  odcid[20];     /* DCID первого Initial — для проверки Retry и tp */
    size_t   odcid_len;
    uint8_t  initial_scid[20]; /* SCID первого Initial для transport parameters */
    size_t   initial_scid_len;
    uint8_t  retry_token[D2K_QW_MAX_DGRAM];
    size_t   retry_token_len;
    unsigned retry_count;
    int      retry_pending;

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
    /* Какие байты ответа на НАШ запрос прошли через линию под ПРИКЛАДНЫМИ
       ключами — все, а не только то, что влезло в rx_data (задача 39).
       Коробка рвёт поток через несколько килобайт после рукопожатия, и
       «пришли заголовки» этого не видит; «ответ целиком» — это FIN и все
       байты до него без дыр, а не наибольшее смещение. */
    d2k_qw_ranges app_rx;

    /* Последняя прикладная посылка — для повтора по таймеру. Обнаружения
       потерь у нас нет и не нужно (см. шапку), но ОДИН повтор обязателен:
       наш запрос уходит сразу за нашим Finished, и сервер, ещё не успевший
       развернуть прикладные ключи, такой пакет просто отбрасывает. Без
       повтора запрос пропадает навсегда, а на замере это выглядит как
       «приложение не ответило» — тот самый ложный вывод, ради которого вся
       эта вертикаль и строится. */
    uint8_t  last_app[DGRAM_OUT];
    size_t   last_app_len;
    /* Срок и счёт повтора last_app — состояние СОЕДИНЕНИЯ, а не одного
       вызова d2k_qc_stream_recv. Проверка читает ответ кусками по 200 мс, и
       таймер в 300 мс, заводимый заново в каждом куске, не срабатывал
       никогда: запрос HTTP/3 ни разу не переотправлялся (задача 33, трасса).
       Заводится отправкой посылки. */
    int64_t  app_pto_ms;
    int      app_tries;
    /* Сколько байт датаграмм принято всего: по нему проверка отличает
       «сервер замолчал» от «сервер говорит, но не отвечает на запрос». */
    uint64_t rx_wire_bytes;
    /* Задача 50, раунд 3: RTT рукопожатия (первая датаграмма сервера после
       первого Initial) — основа RTO для «встал». */
    int64_t  sent0_ms;
    int64_t  rtt_ms;
    /* ЧЕСТНЫЙ ПРИЁМНИК (задача 50, раунд 4). Кредит, выданный серверу: окно
       потока ответа и соединения. Расширяется, когда принята половина окна
       (RFC 9000 §4.2); без этого сервер вставал на 256 КБ, и ответ больше
       окна не завершался никогда. Ноль — начальные значения из
       транспортных параметров (D2K_QC_STREAM_WIN / D2K_QC_CONN_WIN). */
    uint64_t fc_stream_limit, fc_conn_limit;
    uint64_t rx_want_high;   /* наибольший конец данных потока ответа */
    uint64_t rx_other;       /* байты прочих потоков (счёт сверху) */
    int      credit_due;     /* 1 — MAX_STREAM_DATA, 2 — MAX_DATA */
    /* Датаграммы связи в обе стороны (задачи 50, 55): коробка считает бюджет
       потока пакетами, и проверки «хватило на бюджет» считают так же. */
    uint64_t tx_dgrams, rx_dgrams;

    /* ПРЕДЕЛЫ, ОБЪЯВЛЕННЫЕ СЕРВЕРОМ (задача 29): его транспортные параметры
       из EncryptedExtensions и кадры MAX_STREAMS / MAX_DATA. Индекс 0 —
       двунаправленные потоки, 1 — однонаправленные.

       ЗАЧЕМ. Воспроизведение обрыва по бюджету коробки открывает поток на
       каждый запрос и в поле доходило до потока 68, ничего не зная о том,
       сколько их разрешил сервер. Сервер с низким initial_max_streams_bidi
       обязан закрыть связь кодом STREAM_LIMIT_ERROR (0x04) либо промолчать:
       ложным ОБРЫВОМ это не станет (оба исхода дают «не измерено»), но ЗАМЕР
       НЕ СОСТОИТСЯ и будет выглядеть нехваткой времени.

       Признак *_set отдельно от значения, потому что ноль — законный предел:
       «сервер не сказал» и «сервер разрешил нисколько» — разные вещи, и
       выдумывать за него число нельзя. */
    uint64_t peer_streams[2];
    int      peer_streams_set[2];
    uint64_t peer_sdata[2];      /* initial_max_stream_data для НАШИХ потоков */
    int      peer_sdata_set[2];
    uint64_t peer_max_data;
    int      peer_max_data_set;

    uint8_t  local_addr[16];
    uint8_t  family;
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
/* Запечатывает пакет уровня lvl в pkt (не короче DGRAM_OUT) и сдвигает номер.
   Отдельно от отправки: первый Initial нужен и БАЙТАМИ — приманкой голоса
   (d2k_qc_first_initial), без всякого соединения. */
static size_t seal_level(d2k_qc *c, d2k_qw_level lvl, const uint8_t *payload,
                         size_t payload_len, size_t pad_to, uint8_t *pkt, size_t pkt_cap,
                         char *err, size_t errcap) {
    level *L = &c->lv[lvl];
    if (!L->tx.have) { say(err, errcap, "нет ключей уровня для отправки"); return 0; }

    uint8_t body[DGRAM_OUT];
    if (payload_len > sizeof body) { say(err, errcap, "тело пакета длиннее датаграммы"); return 0; }
    memcpy(body, payload, payload_len);
    size_t blen = payload_len;

    size_t pn_len = d2k_qw_pn_len(L->next_pn, -1);
    size_t hlen;
    if (lvl == D2K_QW_LEVEL_APP) {
        /* RFC 9001 §5.4.2: образец защиты заголовка берётся через 4 байта
           после начала номера — номер и тело вместе не короче 4 байт. Пакет
           из одного PING (тело 1 байт, номер 1 байт) иначе не запечатывался
           и молча не уходил: «PING без ответа» было просто тишиной (поле
           04.10). Добивка — PADDING (нули) внутри пакета. */
        if (pn_len + blen < 4) {
            size_t add = 4 - (pn_len + blen);
            memset(body + blen, 0, add);
            blen += add;
        }
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
            size_t h0 = d2k_qw_long_hdr_token(probe, sizeof probe, c->version, type,
                                              c->dcid, c->dcid_len,
                                              c->scid, c->scid_len,
                                              lvl == D2K_QW_LEVEL_INITIAL ? c->retry_token : NULL,
                                              lvl == D2K_QW_LEVEL_INITIAL ? c->retry_token_len : 0,
                                              pn_len, blen);
            if (h0 == 0) { say(err, errcap, "заголовок не собрался"); return 0; }
            size_t total = h0 + pn_len + blen + 16;
            if (total < pad_to && blen + (pad_to - total) <= sizeof body) {
                size_t add = pad_to - total;
                memset(body + blen, 0, add);   /* PADDING это нули */
                blen += add;
            }
        }
        hlen = d2k_qw_long_hdr_token(pkt, pkt_cap, c->version, type,
                                     c->dcid, c->dcid_len,
                                     c->scid, c->scid_len,
                                     lvl == D2K_QW_LEVEL_INITIAL ? c->retry_token : NULL,
                                     lvl == D2K_QW_LEVEL_INITIAL ? c->retry_token_len : 0,
                                     pn_len, blen);
    }

    size_t n = d2k_qw_seal(&L->tx, lvl != D2K_QW_LEVEL_APP, pkt, hlen,
                           L->next_pn, pn_len, body, blen, pkt, pkt_cap);
    if (n == 0) { say(err, errcap, "пакет не собрался"); return 0; }
    if (getenv("D2K_QC_TRACE")) {
        fprintf(stderr, "[шлём] уровень %d номер %llu байт %zu тело %zu\n",
                (int)lvl, (unsigned long long)L->next_pn, n, blen);
    }
    L->next_pn++;
    return n;
}

static int send_level(d2k_qc *c, d2k_qw_level lvl, const uint8_t *payload,
                      size_t payload_len, size_t pad_to, char *err, size_t errcap) {
    uint8_t pkt[DGRAM_OUT];
    size_t n = seal_level(c, lvl, payload, payload_len, pad_to, pkt, sizeof pkt, err, errcap);
    if (n == 0) { return -2; }
    if (send(c->fd, pkt, n, 0) != (ssize_t)n) {
        say(err, errcap, "датаграмма не ушла: %s", strerror(errno));
        return -1;
    }
    c->tx_dgrams++;
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
    o += tp_put_int(v + o, sizeof v - o, 0x04, D2K_QC_CONN_WIN);   /* initial_max_data */
    o += tp_put_int(v + o, sizeof v - o, 0x05, D2K_QC_STREAM_WIN); /* bidi_local */
    o += tp_put_int(v + o, sizeof v - o, 0x06, D2K_QC_STREAM_WIN); /* bidi_remote */
    o += tp_put_int(v + o, sizeof v - o, 0x07, D2K_QC_STREAM_WIN); /* uni */
    o += tp_put_int(v + o, sizeof v - o, 0x08, 16);        /* max_streams_bidi */
    o += tp_put_int(v + o, sizeof v - o, 0x09, 16);        /* max_streams_uni */
    o += tp_put_int(v + o, sizeof v - o, 0x0e, 2);         /* active_connection_id_limit */
    /* initial_source_connection_id ОБЯЗАТЕЛЕН (RFC 9000 §7.3): им сервер
       сверяет, что SCID наших пакетов не подменили по дороге. */
    o += d2k_qw_varint_write(v + o, sizeof v - o, 0x0f);
    o += d2k_qw_varint_write(v + o, sizeof v - o, c->initial_scid_len);
    memcpy(v + o, c->initial_scid, c->initial_scid_len); o += c->initial_scid_len;

    if (cap < o + 4) { return 0; }
    out[0] = 0x00; out[1] = 0x39;                 /* тип расширения */
    out[2] = (uint8_t)(o >> 8); out[3] = (uint8_t)o;
    memcpy(out + 4, v, o);
    return o + 4;
}

/* ПАРАМЕТРЫ СЕРВЕРА — то, чего здесь не было вовсе: свои мы объявляли, а его
 * не читали ни разу. Содержимое расширения — подряд идущие тройки varint
 * «идентификатор, длина, значение» (RFC 9000 §18).
 *
 * Берём ровно те пределы, которые ограничивают НАС: сколько потоков мы вправе
 * открыть (0x08, 0x09) и сколько байт в них послать (0x04, 0x06, 0x07).
 * Остальное пропускается ПО ДЛИНЕ, а не по догадке о смысле: неизвестные
 * параметры сервер вправе присылать и делает это (RFC 9000 §18.1 отводит под
 * это целый ряд идентификаторов 31N+27 — ровно чтобы их пропускали), а
 * пропуск не по длине сдвинул бы разбор и съел бы те самые пределы.
 *
 * Параметр, которого НЕТ, нулём здесь не становится: предел остаётся
 * неизвестным, ограничивать нечем, и число за сервер не выдумывается. */
static void tp_server_parse(d2k_qc *c, const uint8_t *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint64_t id = 0, len = 0;
        size_t w = 0;
        if (d2k_qw_varint_read(p + i, n - i, &id, &w) != 0) { return; }
        i += w;
        if (d2k_qw_varint_read(p + i, n - i, &len, &w) != 0) { return; }
        i += w;
        if (len > n - i) { return; }
        /* Целочисленный параметр — ровно varint длиной в своё поле. Значение
           иной длины (идентификаторы связи, адрес, токен сброса) числом не
           считаем. */
        uint64_t v = 0;
        size_t vw = 0;
        int num = d2k_qw_varint_read(p + i, (size_t)len, &v, &vw) == 0 &&
                  vw == (size_t)len;
        switch (id) {
        case 0x04: if (num) { c->peer_max_data = v; c->peer_max_data_set = 1; } break;
        case 0x06: if (num) { c->peer_sdata[0] = v; c->peer_sdata_set[0] = 1; } break;
        case 0x07: if (num) { c->peer_sdata[1] = v; c->peer_sdata_set[1] = 1; } break;
        case 0x08: if (num) { c->peer_streams[0] = v; c->peer_streams_set[0] = 1; } break;
        case 0x09: if (num) { c->peer_streams[1] = v; c->peer_streams_set[1] = 1; } break;
        default: break;
        }
        i += (size_t)len;
    }
    if (getenv("D2K_QC_TRACE")) {
        fprintf(stderr, "[параметры сервера] потоки дву %llu/%d одно %llu/%d "
                        "данные связи %llu/%d потока %llu/%d\n",
                (unsigned long long)c->peer_streams[0], c->peer_streams_set[0],
                (unsigned long long)c->peer_streams[1], c->peer_streams_set[1],
                (unsigned long long)c->peer_max_data, c->peer_max_data_set,
                (unsigned long long)c->peer_sdata[0], c->peer_sdata_set[0]);
    }
}

/* Расширения EncryptedExtensions сервера: ищет среди них
 * quic_transport_parameters (0x0039). Второго разбора TLS тут нет — само
 * сообщение выделено из флайта общим ядром (d2k_t13_flight_next), и остаётся
 * только список расширений: два байта общей длины, затем тип и длина по два
 * байта у каждого. */
static void tp_server_ee(d2k_qc *c, const uint8_t *body, size_t blen) {
    if (blen < 2) { return; }
    size_t total = (size_t)body[0] << 8 | body[1];
    if (total > blen - 2) { return; }
    size_t p = 2, end = 2 + total;
    while (end - p >= 4) {
        unsigned et = (unsigned)body[p] << 8 | body[p + 1];
        size_t el = (size_t)body[p + 2] << 8 | body[p + 3];
        p += 4;
        if (el > end - p) { return; }
        if (et == 0x0039) { tp_server_parse(c, body + p, el); }
        p += el;
    }
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
            {
                level *La = &c->lv[lvl];
                if (!La->have_acked || largest > La->largest_acked) {
                    La->largest_acked = largest;
                    La->have_acked = 1;
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
        case FR_MAX_DATA:
        case FR_MAX_STREAMS_BIDI:
        case FR_MAX_STREAMS_UNI: {
            uint64_t x = 0;
            if (d2k_qw_varint_read(p + i, n - i, &x, &w) != 0) { return -1; } i += w;
            /* ПРЕДЕЛ, КОТОРЫЙ СЕРВЕР РАСШИРЯЕТ ПО ХОДУ СВЯЗИ: потоки он
               разрешает по мере закрытия прежних. Прежде эти кадры просто
               пропускались по длине — объявленное число не доходило до нас
               вовсе, и открывать следующий поток мы шли наугад. Сужать предел
               кадры не вправе (RFC 9000 §19.9, §19.11): меньшее значение —
               повтор или перестановка датаграмм, а не отзыв разрешения. */
            if (t == FR_MAX_DATA) {
                if (!c->peer_max_data_set || x > c->peer_max_data) { c->peer_max_data = x; }
                c->peer_max_data_set = 1;
            } else {
                int uni = (t == FR_MAX_STREAMS_UNI);
                if (!c->peer_streams_set[uni] || x > c->peer_streams[uni]) {
                    c->peer_streams[uni] = x;
                }
                c->peer_streams_set[uni] = 1;
            }
            break;
        }
        case FR_RETIRE_CONN_ID:
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
                if (lvl == D2K_QW_LEVEL_APP) {
                    /* Кредит: половина окна принята — расширить. */
                    if (mine && c->have_want) {
                        if (off + len > c->rx_want_high) c->rx_want_high = off + len;
                        uint64_t lim = c->fc_stream_limit ? c->fc_stream_limit : D2K_QC_STREAM_WIN;
                        if (c->rx_want_high + D2K_QC_STREAM_WIN / 2 > lim) {
                            c->fc_stream_limit = c->rx_want_high + D2K_QC_STREAM_WIN;
                            c->credit_due |= 1;
                        }
                    } else {
                        c->rx_other += len;
                    }
                    uint64_t used = c->rx_want_high + c->rx_other;
                    uint64_t clim = c->fc_conn_limit ? c->fc_conn_limit : D2K_QC_CONN_WIN;
                    if (used + D2K_QC_CONN_WIN / 2 > clim) {
                        c->fc_conn_limit = used + D2K_QC_CONN_WIN;
                        c->credit_due |= 2;
                    }
                }
                if (mine) {
                    c->rx_stream = sid;
                    if (off < STREAM_BUF) {
                        size_t take = (size_t)len;
                        if (off + take > STREAM_BUF) { take = STREAM_BUF - (size_t)off; }
                        memcpy(c->rx_data + off, p + i, take);
                        if (off + take > c->rx_len) { c->rx_len = (size_t)off + take; }
                    }
                    if (t & 0x01) { c->rx_fin = 1; }
                    if (lvl == D2K_QW_LEVEL_APP && c->have_want) {
                        d2k_qw_ranges_add(&c->app_rx, off, len, (int)(t & 0x01));
                    }
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
    c->rx_wire_bytes += (uint64_t)n;
    c->rx_dgrams++;
    if (!c->rtt_ms && c->sent0_ms) {
        int64_t d = now_ms() - c->sent0_ms;
        c->rtt_ms = d > 0 ? d : 1;
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
            /* RFC 9000 §17.2.5.2: второй Retry, Retry после любого пакета
               сервера и Retry с неверным тегом клиент ОТБРАСЫВАЕТ, а не рвёт
               соединение (финальное ревью core, M7): наш DCID виден на пути,
               и поздний поддельный Retry иначе обрывал проверку раньше срока.
               Retry занимает датаграмму до конца — дальше разбирать нечего. */
            if (c->retry_count != 0 || c->peer_cid_fixed || h.version != c->version ||
                h.dcid_len != c->scid_len ||
                memcmp(buf + off + h.dcid_off, c->scid, c->scid_len) != 0 ||
                h.scid_len == 0 || h.scid_len > sizeof c->dcid ||
                /* RFC 9000 §17.2.5.2: пустой токен и SCID, равный нашему
                   исходному DCID, — отбросить. */
                h.token_len == 0 ||
                (h.scid_len == c->odcid_len &&
                 memcmp(buf + off + h.scid_off, c->odcid, c->odcid_len) == 0) ||
                h.token_len > sizeof c->retry_token ||
                d2k_qw_retry_verify(c->version, c->odcid, c->odcid_len,
                                    buf + off, h.packet_len) != 0) {
                break;
            }
            memcpy(c->dcid, buf + off + h.scid_off, h.scid_len);
            c->dcid_len = h.scid_len;
            memcpy(c->retry_token, buf + off + h.token_off, h.token_len);
            c->retry_token_len = h.token_len;
            c->retry_pending = 1;
            return 2;
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
        /* ПАКЕТЫ ЭТОГО УРОВНЯ, ВКЛЮЧАЯ ПОВТОРЫ. Нужны одному вызывающему и по
           одной причине: когда рукопожатие не сложилось, по ним видно ФОРМУ
           отказа. Сервер, получивший наш ACK уровня Initial, идёт дальше и
           присылает полёт Handshake; сервер, нашего ACK не получивший, упирается
           в предел троекратного усиления и повторяет свой Initial. Значит
           «Initial пришёл несколько раз, Handshake не пришёл ни разу» — это
           измеренное «наши пакеты до сервера не доходят», а не «не успели». */
        L->rx_pkts++;
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

/* ПЕРВЫЙ ПОЛЁТ КЛИЕНТА — без сокета: идентификаторы соединения, ключи уровня
   Initial и ClientHello с транспортными параметрами в кадре CRYPTO. priv —
   закрытый ключ обмена, он нужен соединению дальше. Вынесено из
   d2k_qc_connect, чтобы тот же первый Initial можно было получить БАЙТАМИ
   (d2k_qc_first_initial) — не второй сборкой рядом, а этой же. */
static int first_flight(d2k_qc *c, const char *sni, const char *alpn, size_t pad_to,
                        uint8_t priv[32], uint8_t *frame, size_t cap, size_t *flen,
                        char *err, size_t errcap) {
    c->dcid_len = c->scid_len = 8;
    uint8_t pub[32], rnd[32];
    if (d2k_t13_random(c->dcid, c->dcid_len) != 0 ||
        d2k_t13_random(c->scid, c->scid_len) != 0 ||
        d2k_t13_random(priv, 32) != 0 || d2k_t13_random(rnd, 32) != 0) {
        say(err, errcap, "нет случайности: /dev/urandom недоступен");
        return -1;
    }
    memcpy(c->initial_scid, c->scid, c->scid_len);
    c->initial_scid_len = c->scid_len;
    memcpy(c->odcid, c->dcid, c->dcid_len);
    c->odcid_len = c->dcid_len;
    if (d2k_x25519_base(pub, priv) != 0) {
        say(err, errcap, "открытый ключ не посчитался"); return -1;
    }


    /* Ключи уровня Initial: обе стороны выводятся из DCID нашего первого
       пакета (RFC 9001 §5.2). */
    uint8_t sec[32];
    if (d2k_qw_initial_secret(c->version, c->dcid, c->dcid_len, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(c->version, sec, &c->lv[D2K_QW_LEVEL_INITIAL].tx) != 0 ||
        d2k_qw_initial_secret(c->version, c->dcid, c->dcid_len, D2K_QW_SERVER, sec) != 0 ||
        d2k_qw_keys_from_secret(c->version, sec, &c->lv[D2K_QW_LEVEL_INITIAL].rx) != 0) {
        say(err, errcap, "начальные ключи не вывелись"); return -1;
    }

    /* ClientHello с транспортными параметрами и ALPN. */
    uint8_t tp[320];
    size_t tp_len = tp_build(c, tp, sizeof tp);
    if (tp_len == 0) { say(err, errcap, "транспортные параметры не собрались"); return -1; }

    uint8_t ch[2560];
    d2k_t13_ch_opts cho;
    memset(&cho, 0, sizeof cho);
    uint8_t ip_target[16];
    cho.sni = (sni && (inet_pton(AF_INET, sni, ip_target) == 1 ||
                       inet_pton(AF_INET6, sni, ip_target) == 1)) ? NULL : sni;
    cho.pub = pub;
    cho.random = rnd;
    cho.session_id_len = 0;      /* RFC 9001 §8.4: у QUIC он обязан быть пуст */
    cho.alpn = alpn ? alpn : "h3";
    cho.extra = tp;
    cho.extra_len = tp_len;
    cho.pad_to = pad_to;
    size_t ch_len = d2k_t13_ch_build(&cho, ch, sizeof ch);
    if (ch_len == 0 || ch_len < pad_to) { say(err, errcap, "приветствие заданной длины не собралось"); return -1; }
    memcpy(c->transcript, ch, ch_len);
    c->tr_len = ch_len;

    *flen = crypto_frame(frame, cap, 0, ch, ch_len);
    if (*flen == 0) { say(err, errcap, "кадр CRYPTO не собрался"); return -1; }
    return 0;
}

/* Retry не является новым TLS-сеансом: клиент пересылает тот же ClientHello,
 * но с новым Destination CID сервера, новым своим SCID и token. Начальные
 * ключи выводятся заново из CID Retry, тогда как initial_source_connection_id
 * в уже собранном ClientHello остаётся SCID самого первого Initial. */
static int prepare_retry(d2k_qc *c, char *err, size_t errcap) {
    if (!c || !c->retry_pending || c->retry_count != 0 ||
        c->dcid_len == 0 || c->dcid_len > D2K_QW_CID_MAX) {
        say(err, errcap, "Retry нельзя применить к этому состоянию");
        return -1;
    }
    c->scid_len = 8;
    if (d2k_t13_random(c->scid, c->scid_len) != 0) {
        say(err, errcap, "новый SCID Retry не собрался");
        return -1;
    }
    memset(c->lv, 0, sizeof c->lv);
    uint8_t sec[32];
    if (d2k_qw_initial_secret(c->version, c->dcid, c->dcid_len,
                              D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(c->version, sec,
                                &c->lv[D2K_QW_LEVEL_INITIAL].tx) != 0 ||
        d2k_qw_initial_secret(c->version, c->dcid, c->dcid_len,
                              D2K_QW_SERVER, sec) != 0 ||
        d2k_qw_keys_from_secret(c->version, sec,
                                &c->lv[D2K_QW_LEVEL_INITIAL].rx) != 0) {
        say(err, errcap, "начальные ключи Retry не вывелись");
        return -1;
    }
    c->peer_cid_fixed = 0;
    c->retry_count = 1;
    c->retry_pending = 0;
    return 0;
}

int d2k_qc_first_initial(const char *sni, uint8_t *out, size_t cap, size_t *out_len) {
    if (!sni || !out || !out_len) { return -1; }
    *out_len = 0;
    d2k_qc *c = calloc(1, sizeof *c);
    if (!c) { return -1; }
    c->fd = -1;
    c->version = D2K_QW_V1;
    uint8_t priv[32];
    uint8_t frame[2600];
    size_t flen = 0;
    char err[128];
    int rc = -1;
    if (first_flight(c, sni, NULL, 0, priv, frame, sizeof frame, &flen, err, sizeof err) == 0) {
        uint8_t pkt[DGRAM_OUT];
        size_t n = seal_level(c, D2K_QW_LEVEL_INITIAL, frame, flen, 1200,
                              pkt, sizeof pkt, err, sizeof err);
        if (n > 0 && n <= cap) {
            memcpy(out, pkt, n);
            *out_len = n;
            rc = 0;
        }
    }
    memset(priv, 0, sizeof priv);
    free(c);
    return rc;
}

/* Connected UDP sends may raise SIGPIPE on macOS after an ICMP refusal.
   Keep that refusal as a socket error, including caller-supplied sockets. */
static int qc_no_sigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int enabled = 1;
    return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof enabled);
#else
    (void)fd;
    return 0;
#endif
}

int d2k_qc_connect(const d2k_qc_opts *o, d2k_qc **out, char *err, size_t errcap) {
    if (err && errcap) { err[0] = '\0'; }
    if (!o || !o->ip || !out) { say(err, errcap, "нечем поднимать соединение"); return -1; }
    *out = NULL;

    d2k_qc *c = calloc(1, sizeof *c);
    if (!c) { say(err, errcap, "не хватило памяти"); return -1; }
    c->fd = (o->use_fd > 0) ? o->use_fd : -1;
    c->peer_name = -1;
    c->version = D2K_QW_V1;

    uint8_t priv[32];
    uint8_t frame[2600];
    size_t flen = 0;
    /* Длина приветствия — из формы клиента, когда она известна. */
    size_t want_ch = (o->form && o->form->ch_len) ? (size_t)o->form->ch_len : o->pad_to;
    if (first_flight(c, o->sni, o->alpn, want_ch, priv, frame, sizeof frame, &flen,
                     err, errcap) != 0) {
        d2k_qc_close(c); return -2;
    }

    int af = strchr(o->ip, ':') ? AF_INET6 : AF_INET;
    c->family = af == AF_INET6 ? 6 : 4;

    struct sockaddr_storage to;
    memset(&to, 0, sizeof to);
    socklen_t tolen;
    void *dst;
    if (af == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&to;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(o->port ? o->port : 443);
        dst = &v6->sin6_addr; tolen = sizeof *v6;
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&to;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(o->port ? o->port : 443);
        dst = &v4->sin_addr; tolen = sizeof *v4;
    }
    if (strchr(o->ip, '%') || inet_pton(af, o->ip, dst) != 1) {
        say(err, errcap, "адрес не разбирается");
        if (c->fd < 0) { free(c); return -1; }
        d2k_qc_close(c); return -1;
    }
    if (c->fd >= 0) {
        if (qc_no_sigpipe(c->fd) != 0) {
            say(err, errcap, "SO_NOSIGPIPE: %s", strerror(errno));
            d2k_qc_close(c); return -2;
        }
        if (o->mark && d2k_mark_hook(c->fd, o->mark) != 0) {
            say(err, errcap, "метка измерительного сокета не поставилась");
            d2k_qc_close(c);
            return -2;
        }
        /* connect на UDP не шлёт ни байта: он привязывает сокет к направлению,
           чтобы приходили ошибки ICMP и чтобы recv не принимал чужое. */
        if (connect(c->fd, (struct sockaddr *)&to, tolen) != 0) {
            say(err, errcap, "connect: %s", strerror(errno)); d2k_qc_close(c); return -1;
        }
    } else {
        /* СВОЙ СОКЕТ — СО СВЕЖЕЙ ЧЕТВЁРКОЙ (задача 39): местный порт, бывший
           у нашего зонда за окно остаточной блокировки, отвергается; сокет с
           ним открыт, пока ищется следующий, и закрывается при выходе из
           поиска. Занятый вызывающим
           сокет (use_fd) проверен там, где его заняли. */
        int held[D2K_UDP_FRESH_TRIES];
        int n_held = 0;
        int local_failed = 0;
        for (;;) {
            int fd = socket(af, SOCK_DGRAM, 0);
            if (fd < 0) { say(err, errcap, "сокет: %s", strerror(errno)); break; }
            if (qc_no_sigpipe(fd) != 0) {
                say(err, errcap, "SO_NOSIGPIPE: %s", strerror(errno));
                local_failed = 1;
                close(fd); break;
            }
            if (o->mark && d2k_mark_hook(fd, o->mark) != 0) {
                say(err, errcap, "метка измерительного сокета не поставилась");
                close(fd);
                local_failed = 1;
                break;
            }
            if (connect(fd, (struct sockaddr *)&to, tolen) != 0) {
                say(err, errcap, "connect: %s", strerror(errno)); close(fd); break;
            }
            if (d2k_udp_port_claim(fd) <= 0) { c->fd = fd; break; }
            if (n_held == D2K_UDP_FRESH_TRIES) {
                say(err, errcap, "свежего местного порта нет"); close(fd); break;
            }
            held[n_held++] = fd;
        }
        for (int i = 0; i < n_held; i++) { close(held[i]); }
        if (local_failed) { free(c); return -2; }
        if (c->fd < 0) { free(c); return -1; }
    }
    struct sockaddr_storage me;
    socklen_t ml = sizeof me;
    if (getsockname(c->fd, (struct sockaddr *)&me, &ml) == 0) {
        if (me.ss_family == AF_INET6) {
            struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&me;
            memcpy(c->local_addr, &v6->sin6_addr, 16);
            c->local_port = ntohs(v6->sin6_port);
        } else {
            struct sockaddr_in *v4 = (struct sockaddr_in *)&me;
            memcpy(c->local_addr, &v4->sin_addr, 4);
            c->local_port = ntohs(v4->sin_port);
        }
    }
    /* Первая датаграмма клиента обязана быть не короче 1200 байт
       (RFC 9000 §14.1): иначе сервер вправе её не обслуживать. */
    if (o->form && o->form->n > 1 && !o->first_send) {
        /* ПОЛЁТ ИЗ НЕСКОЛЬКИХ ДАТАГРАММ (задача 66). ClientHello режется на
           form->n кадров CRYPTO по смещениям, каждый уходит своим Initial с
           номерами 0..n-1 под общим DCID — ровно так его шлёт клиент, чьё
           приветствие в одну датаграмму не влезло. Размер каждой датаграммы —
           из формы: он тоже свойство клиента, по которому коробка решает. */
        size_t parts = o->form->n > D2K_QSNAP_MAX_DGRAMS
                       ? D2K_QSNAP_MAX_DGRAMS : o->form->n;
        size_t chunk = (c->tr_len + parts - 1) / parts;
        size_t pad = o->form->dgram_len ? o->form->dgram_len : 1200;
        for (size_t i = 0; i < parts; i++) {
            size_t off = i * chunk;
            if (off >= c->tr_len) { break; }
            size_t take = c->tr_len - off < chunk ? c->tr_len - off : chunk;
            uint8_t part[2600];
            size_t plen = crypto_frame(part, sizeof part, off, c->transcript + off, take);
            int send_rc = plen ? send_level(c, D2K_QW_LEVEL_INITIAL, part, plen,
                                             pad, err, errcap) : -2;
            if (send_rc != 0) { d2k_qc_close(c); return send_rc; }
        }
    } else if (!o->first_send) {
        int send_rc = send_level(c, D2K_QW_LEVEL_INITIAL, frame, flen, 1200, err, errcap);
        if (send_rc != 0) { d2k_qc_close(c); return send_rc; }
    } else {
        /* Замер плеча (задача 39): воздействие плеча идёт ПЕРЕД первым
           Initial на той же четвёрке, ровно как в вопросе-фильтре. Повторы
           по таймеру уходят как есть — так же их пропускает датапат. */
        uint8_t pkt[DGRAM_OUT];
        size_t n = seal_level(c, D2K_QW_LEVEL_INITIAL, frame, flen, 1200,
                              pkt, sizeof pkt, err, errcap);
        if (n == 0) { d2k_qc_close(c); return -2; }
        int sent = o->first_send(c->fd, pkt, n, o->first_send_user);
        if (sent < 0) {
            say(err, errcap, "воздействие перед первым Initial не ушло");
            d2k_qc_close(c); return -1;
        }
        if (sent == 0 && send(c->fd, pkt, n, 0) != (ssize_t)n) {
            say(err, errcap, "датаграмма не ушла: %s", strerror(errno));
            d2k_qc_close(c); return -1;
        }
        c->tx_dgrams++;
    }

    c->sent0_ms = now_ms();
    int64_t deadline = now_ms() + (o->deadline_ms > 0 ? o->deadline_ms : 5000);
    int64_t pto = now_ms() + 333;      /* RFC 9002 §6.2.2: стартовый RTT до замера */
    int tries = 0;
    int sh_done = 0, hs_keys = 0;

    while (now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        int wait = left > 50 ? 50 : left;
        int r = recv_dgram(c, wait, err, errcap);
        if (r < 0) { d2k_qc_close(c); return -1; }
        if (r == 2) {
            if (prepare_retry(c, err, errcap) != 0 ||
                send_level(c, D2K_QW_LEVEL_INITIAL, frame, flen, 1200,
                           err, errcap) != 0) {
                d2k_qc_close(c); return -1;
            }
            pto = now_ms() + 333;
            tries = 0;
            continue;
        }

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
                /* Пределы сервера приезжают ЗДЕСЬ, в его EncryptedExtensions,
                   и больше нигде: дальше о них говорят только кадры
                   MAX_STREAMS / MAX_DATA (задача 29). */
                if (mt == D2K_T13_ENCRYPTED_EXT) { tp_server_ee(c, body, blen); }
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

    /* ФОРМА ОТКАЗА НАЗЫВАЕТСЯ ИЗМЕРЕНИЕМ, А НЕ НЕХВАТКОЙ ВРЕМЕНИ (задача 34).
     * Поле 12.10c: nnmclub.to не завершает рукопожатие 4 раза из 4, а контроль
     * katzauction.com на адресе из той же /24 того же CDN проходит 2 из 2 —
     * значит дело не во времени и не в маршруте. Прежний единственный текст
     * «не завершилось за отведённое время» эту разницу скрывал.
     *
     * Различаются три формы по тому, что ПРИШЛО, а не по догадке:
     *   Handshake не пришёл ни разу, Initial приходил НЕСКОЛЬКО раз — сервер
     *     упирается в предел троекратного усиления, то есть нашего ACK он не
     *     получил: наши пакеты до него не доходят;
     *   Handshake не пришёл, Initial пришёл один раз — сервер замолчал после
     *     первого ответа, направление не названо;
     *   Handshake пришёл — полёт есть, но Finished из него не собрался, и это
     *     уже вопрос к разбору, а не к линии.
     * Текст короткий и цифры в конце: вызывающий печатает его через «%.120s»,
     * кириллица идёт по два байта. */
    if (!c->closed) {
        uint64_t ini = c->lv[D2K_QW_LEVEL_INITIAL].rx_pkts;
        uint64_t hs = c->lv[D2K_QW_LEVEL_HANDSHAKE].rx_pkts;
        size_t hs_crypto = c->lv[D2K_QW_LEVEL_HANDSHAKE].crypto.high;
        if (hs == 0 && ini >= 2) {
            say(err, errcap, "наши пакеты до сервера не доходят: он повторяет Initial ×%llu, "
                             "Handshake не пришёл", (unsigned long long)ini);
        } else if (hs == 0) {
            say(err, errcap, "сервер замолчал после Initial ×%llu, Handshake не пришёл",
                (unsigned long long)ini);
        } else {
            say(err, errcap, "полёт Handshake пришёл (%llu пак., CRYPTO %zu Б), "
                             "Finished не собрался", (unsigned long long)hs, hs_crypto);
        }
    }
    d2k_qc_close(c);
    return -1;
}

int d2k_qc_stream_send(d2k_qc *c, uint64_t stream_id, const uint8_t *data, size_t n,
                       int fin, char *err, size_t errcap) {
    if (!c || !c->lv[D2K_QW_LEVEL_APP].tx.have) {
        say(err, errcap, "прикладных ключей нет"); return -1;
    }
    /* ПРЕДЕЛ, ОБЪЯВЛЕННЫЙ СЕРВЕРОМ (задача 29). Поток с номером выше
       разрешённого — не неудача на проводе: сервер обязан закрыть связь кодом
       STREAM_LIMIT_ERROR (0x04) либо промолчать, и замер на нём не состоится.
       Поэтому причина называет ПРЕДЕЛ ПОТОКОВ СЕРВЕРА, а не сеть: выше этот
       текст попадает в журнал как причина «не измерено», и назвать её сетью
       значило бы потерять настоящую. Проверка стоит ПЕРЕД учётом потока
       ответа: отказ не вправе сбрасывать состояние уже идущего опыта. */
    if ((stream_id & 0x01) == 0) {        /* поток открываем мы */
        int uni = (stream_id & 0x02) != 0;
        /* RFC 9000 §2.1, §4.6: предел задан ЧИСЛОМ потоков, а номер потока —
           это 4 × (счёт − 1) + тип. */
        uint64_t count = (stream_id >> 2) + 1;
        /* ТЕКСТ КОРОТКИЙ, ВАЖНЫМ ВПЕРЁД И С ЦИФРАМИ В КОНЦЕ. Вызывающие
           печатают его через «%.60s» и «%.80s», кириллица идёт по два байта, и
           длинная причина теряет при усечении ровно то, ради чего написана.
           Цифры стоят в конце: при обычных числах текст влезает в 60 байт
           целиком, а при огромных обрежется хвост цифр, а не половина буквы и
           не само слово «предел». Двунаправленный поток от
           однонаправленного различать здесь незачем: это уже сказано
           приставкой вызывающего — «управляющий поток не ушёл» против
           «запрос HTTP/3 не ушёл». */
        if (c->peer_streams_set[uni] && count > c->peer_streams[uni]) {
            say(err, errcap, "предел потоков сервера: %llu, наш %llu",
                (unsigned long long)c->peer_streams[uni],
                (unsigned long long)count);
            return -1;
        }
        if (c->peer_sdata_set[uni] && n > c->peer_sdata[uni]) {
            say(err, errcap, "предел данных потока сервера: %llu, наш %zu",
                (unsigned long long)c->peer_sdata[uni], n);
            return -1;
        }
    }
    /* Счёт посланного за всю связь мы не ведём: смысл проверки — назвать
       предел, когда в него не влезает ОДНА посылка. Соврать про сумму было бы
       хуже, чем не проверять её вовсе. */
    if (c->peer_max_data_set && n > c->peer_max_data) {
        say(err, errcap, "предел данных связи сервера: %llu, наш %zu",
            (unsigned long long)c->peer_max_data, n);
        return -1;
    }
    /* Поток, открытый КЛИЕНТОМ и двунаправленный (номер кратен четырём), —
       это наш вопрос, и ответ придёт по нему же. Запоминаем его, чтобы не
       перепутать с однонаправленными потоками сервера. */
    if ((stream_id & 0x03) == 0) {
        if (!c->have_want || c->want_stream != stream_id) {
            /* Credit belongs to a stream. Carry the finished response into
               connection usage, then start the new stream at its initial
               window; the previous stream's MAX_STREAM_DATA does not apply. */
            c->rx_other += c->rx_want_high;
            c->rx_want_high = 0;
            c->fc_stream_limit = 0;
            c->credit_due &= ~1;
        }
        c->want_stream = stream_id;
        c->have_want = 1;
        /* Всё, что успело накопиться до вопроса, — чужое: управляющий поток
           сервера и таблицы QPACK. Смешать их с ответом значит подать разбору
           байты двух разных потоков как один. */
        c->rx_len = c->rx_taken = 0;
        c->rx_fin = 0;
        d2k_qw_ranges_reset(&c->app_rx);
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
        c->app_pto_ms = now_ms() + 300;
        c->app_tries = 0;
    }
    return send_level(c, D2K_QW_LEVEL_APP, fr, o, 0, err, errcap);
}

long d2k_qc_stream_recv(d2k_qc *c, uint64_t *stream_out, uint8_t *buf, size_t cap,
                        int wait_ms, char *err, size_t errcap) {
    if (!c || !buf) { return -1; }
    int64_t until = now_ms() + (wait_ms > 0 ? wait_ms : 0);
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
        if (c->rx_len == 0 && c->last_app_len && now_ms() >= c->app_pto_ms &&
            c->app_tries < 3) {
            c->app_tries++;
            c->app_pto_ms = now_ms() + (300 << c->app_tries);
            (void)send_level(c, D2K_QW_LEVEL_APP, c->last_app, c->last_app_len,
                             0, err, errcap);
        }
        /* Подтверждаем принятое: сервер не станет досылать, пока молчим.
           Вместе с ACK — расширение кредита, если половина окна принята. */
        level *L = &c->lv[D2K_QW_LEVEL_APP];
        if ((L->ack_due || c->credit_due) && L->tx.have) {
            uint8_t ab[64];
            size_t an = L->ack_due ? build_ack(ab, sizeof ab, L->largest_rx) : 0;
            if (c->credit_due & 2) {
                ab[an++] = FR_MAX_DATA;
                an += d2k_qw_varint_write(ab + an, sizeof ab - an, c->fc_conn_limit);
            }
            if ((c->credit_due & 1) && c->have_want) {
                ab[an++] = FR_MAX_STREAM_DATA;
                an += d2k_qw_varint_write(ab + an, sizeof ab - an, c->want_stream);
                an += d2k_qw_varint_write(ab + an, sizeof ab - an, c->fc_stream_limit);
            }
            if (an && send_level(c, D2K_QW_LEVEL_APP, ab, an, 0, err, errcap) == 0) {
                L->ack_due = 0;
                c->credit_due = 0;
            }
        }
    }
}

void d2k_qc_app_progress(const d2k_qc *c, uint64_t *bytes, int *complete) {
    if (bytes) { *bytes = c ? d2k_qw_ranges_bytes(&c->app_rx) : 0; }
    if (complete) { *complete = c ? d2k_qw_ranges_complete(&c->app_rx) : 0; }
}

int d2k_qc_peer_name(const d2k_qc *c) { return c ? c->peer_name : -1; }
uint64_t d2k_qc_rx_wire_bytes(const d2k_qc *c) { return c ? c->rx_wire_bytes : 0; }
void d2k_qc_datagrams(const d2k_qc *c, uint64_t *tx, uint64_t *rx) {
    if (tx) { *tx = c ? c->tx_dgrams : 0; }
    if (rx) { *rx = c ? c->rx_dgrams : 0; }
}
int d2k_qc_handshake_done(const d2k_qc *c) { return c ? c->handshake_done : 0; }
int64_t d2k_qc_rtt_ms(const d2k_qc *c) { return c ? c->rtt_ms : 0; }
void d2k_qc_dgrams(const d2k_qc *c, uint64_t *tx, uint64_t *rx) {
    if (tx) *tx = c ? c->tx_dgrams : 0;
    if (rx) *rx = c ? c->rx_dgrams : 0;
}

int d2k_qc_outbound(const d2k_qc *c, uint64_t *sent_pn, uint64_t *acked_pn) {
    if (!c) { return 0; }
    const level *L = &c->lv[D2K_QW_LEVEL_APP];
    /* next_pn — СЛЕДУЮЩИЙ свой номер, поэтому последний отправленный на один
       меньше; до первой отправки его нет вовсе. */
    if (sent_pn) { *sent_pn = L->next_pn ? L->next_pn - 1 : 0; }
    if (!L->have_acked) { return 0; }
    if (acked_pn) { *acked_pn = L->largest_acked; }
    return 1;
}

int d2k_qc_ping(d2k_qc *c, char *err, size_t errcap) {
    if (!c) return -1;
    uint8_t fr[1] = { FR_PING };
    return send_level(c, D2K_QW_LEVEL_APP, fr, sizeof fr, 0, err, errcap);
}
int d2k_qc_fd(const d2k_qc *c) { return c ? c->fd : -1; }

void d2k_qc_local(const d2k_qc *c, uint8_t ip4[4], uint16_t *port) {
    if (!c) { return; }
    if (ip4) {
        memset(ip4, 0, 4);
        if (c->family == 4) memcpy(ip4, c->local_addr, 4);
    }
    if (port) { *port = c->local_port; }
}

void d2k_qc_local_addr(const d2k_qc *c, uint8_t addr[16], uint8_t *family,
                      uint16_t *port) {
    if (!c) return;
    if (addr) memcpy(addr, c->local_addr, 16);
    if (family) *family = c->family;
    if (port) *port = c->local_port;
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
