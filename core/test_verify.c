/* test_verify.c — уровни доказательства работоспособности (d2k_verify.h).
 *
 * ЧТО ИМЕННО ЗДЕСЬ ДОКАЗЫВАЕТСЯ. Не «зонд что-то вернул», а что четыре
 * уровня РАЗЛИЧАЮТСЯ и не сливаются: обращение не состоялось / встал
 * транспорт / завершено рукопожатие / ответило приложение. Пока успехом
 * считался внешний тип записи TLS 23, «сервер что-то ответил» читалось как
 * «приложение работает» — в TLS 1.3 в записи типа 23 едет весь второй полёт
 * рукопожатия (RFC 8446 §5.2), и настоящий тип лежит внутри шифротекста.
 * Проверка ровно на это: мишень режима ROLE_PLAIN отвечает настоящим
 * «HTTP/1.1 200 OK» — и обязана остаться на уровне транспорта, потому что
 * НАШЕГО рукопожатия не было.
 *
 * ЗАЧЕМ СВОЙ СТЕНД, А НЕ ОБЩИЙ test_stand.h. Общая петля-мишень отвечает
 * семью байтами, похожими на TLS-запись, и считает подключения — этого
 * хватало, пока «ответ» и был вердиктом. Различить уровни можно только
 * напротив собеседника, который умеет довести рукопожатие TLS 1.3 до конца —
 * и умеет НЕ довести. Такого режима у общего стенда нет и быть не может: про
 * TLS он не знает ничего, а дописывать в него половину протокола ради одного
 * теста значило бы утащить туда же и ключевое расписание.
 *
 * СТЕНД НЕ ДОКАЗЫВАЕТ ПРАВИЛЬНОСТЬ core/tls13.c и написан не для этого.
 * Правильность клиента доказана живыми серверами (Google, Cloudflare,
 * Microsoft, instagram, youtube, rutracker — см. шапку d2k_tls13.h); здесь он
 * просто вторая сторона того же протокола, площадка, на которой уровни
 * различимы БЕЗ ИНТЕРНЕТА. Тест, зависящий от чужого сервера, был бы тестом
 * сегодняшней погоды в сети, а не нашего кода: вердикт менялся бы от того,
 * что отвечает удалённая сторона в этот час.
 *
 * В СЕТЬ НЕ ХОДИТ: всё на 127.0.0.1, порт назначает ядро (bind на 0).
 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "d2k_crypto.h" /* то же расписание ключей, что у клиента, с другой стороны */
#include "d2k_meas.h"   /* d2k_mark_hook — им проверяется «обращение непомеченное» */
#include "d2k_verify.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* --- стенд-мишень -------------------------------------------------------- */

/* Отвечает открытым текстом, настоящим «HTTP/1.1 200 OK», и TLS не умеет
   вовсе. Самый опасный из трёх: сервер ОТВЕТИЛ, и ответил успехом — если
   уровни сольются, зонд засчитает это за работу приложения. */
#define ROLE_PLAIN  0
/* Доводит рукопожатие TLS 1.3 до конца и после него молчит. */
#define ROLE_SILENT 1
/* Доводит рукопожатие и отвечает внутри сессии настоящим ответом HTTP. */
#define ROLE_APP    2

static const struct {
    const char *text;
    int status;
    size_t split;
} replies[] = {
    {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 200, 0},
    {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 200, 10},
    {"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", 200, 0},
    {"HTTP/1.1 103 Early Hints\r\n\r\n", 0, 0},
    {"HTTP/1.1 200", 0, 0},
    {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n", 0, 0},
    {"HTTP/1.1 2000 OK\r\n\r\n", 0, 0},
    {"HTTP/1.1 200x OK\r\n\r\n", 0, 0},
    {"HTTP/1.12 200 OK\r\n\r\n", 0, 0},
    {"HTTP/1.1 999 Invalid\r\n\r\n", 0, 0},
    {"HTTP/1.0 403 Forbidden\r\n\r\n", 403, 0},
    {"HTTP/1.1 101 Switching Protocols\r\n\r\n", 0, 0},
};

struct stand {
    int       fd;        /* слушающий сокет */
    uint16_t  port;
    int       role;
    uint16_t  peer_port; /* местный порт зонда, каким его ВИДИТ мишень */
    pthread_t th;
};

/* Потолок ожидания на стороне стенда. Больше любого потолка, который тест
   даёт зонду (см. вызовы d2k_verify_probe ниже), чтобы стенд никогда не
   становился причиной отказа: он мишень, а не участник измерения. */
#define STAND_IO_MS 5000

#define REC_CCS       20
#define REC_ALERT     21
#define REC_HANDSHAKE 22
#define REC_APPDATA   23
#define REC_MAX       18432

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }

static int rd_exact(int fd, uint8_t *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, b + got, n - got, 0);
        if (r <= 0) { return -1; }
        got += (size_t)r;
    }
    return 0;
}

static int wr_all(int fd, const uint8_t *b, size_t n) {
    size_t sent = 0;
    while (sent < n) {
#ifdef MSG_NOSIGNAL
        ssize_t w = send(fd, b + sent, n - sent, MSG_NOSIGNAL);
#else
        ssize_t w = send(fd, b + sent, n - sent, 0);
#endif
        if (w <= 0) { return -1; }
        sent += (size_t)w;
    }
    return 0;
}

/* Одно направление шифрования: ключ, вектор и счётчик записей. Сторон две, и
   у каждой свой счётчик — путать их нельзя, тег не сойдётся. */
struct dir { uint8_t key[16], iv[12]; uint64_t seq; };

static void nonce_of(const uint8_t iv[12], uint64_t seq, uint8_t out[12]) {
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++) {
        out[11 - i] ^= (uint8_t)(seq >> (8 * i));
    }
}

/* Читает одну запись. enc — снимать ли защиту ключами d. Наружу отдаётся
   ВНУТРЕННИЙ тип (RFC 8446 §5.2: настоящий тип — последний ненулевой байт
   открытого текста), у смены шифра — её собственный тип с пустым телом. */
static int rec_read(int fd, struct dir *d, int enc, uint8_t *type,
                    uint8_t *buf, size_t cap, size_t *len) {
    uint8_t hdr[5];
    if (rd_exact(fd, hdr, 5) != 0) { return -1; }
    size_t rlen = get16(hdr + 3);
    if (rlen == 0 || rlen > REC_MAX) { return -1; }
    uint8_t raw[REC_MAX];
    if (rd_exact(fd, raw, rlen) != 0) { return -1; }

    if (hdr[0] == REC_CCS) {
        *type = REC_CCS;
        *len = 0;
        return 0;
    }
    if (!enc || hdr[0] != REC_APPDATA) {
        if (rlen > cap) { return -1; }
        memcpy(buf, raw, rlen);
        *type = hdr[0];
        *len = rlen;
        return 0;
    }
    if (rlen < 17 || rlen - 16 > cap) { return -1; }
    uint8_t nonce[12];
    nonce_of(d->iv, d->seq, nonce);
    if (d2k_aes128_gcm_decrypt(d->key, nonce, hdr, 5, raw, rlen, buf) != 0) { return -1; }
    d->seq++;
    size_t n = rlen - 16;
    while (n > 0 && buf[n - 1] == 0) { n--; }
    if (n == 0) { return -1; }
    *type = buf[n - 1];
    *len = n - 1;
    return 0;
}

static int rec_write(int fd, struct dir *d, uint8_t type,
                     const uint8_t *data, size_t n) {
    if (n + 1 + 16 > REC_MAX) { return -1; }
    uint8_t out[REC_MAX + 5];
    uint8_t inner[REC_MAX];
    memcpy(inner, data, n);
    inner[n] = type;

    out[0] = REC_APPDATA;
    put16(out + 1, 0x0303);
    put16(out + 3, (uint16_t)(n + 1 + 16));
    uint8_t nonce[12], tag[16];
    nonce_of(d->iv, d->seq, nonce);
    if (d2k_aes128_gcm_encrypt(d->key, nonce, out, 5, inner, n + 1, out + 5, tag) != 0) {
        return -1;
    }
    memcpy(out + 5 + n + 1, tag, 16);
    d->seq++;
    return wr_all(fd, out, 5 + n + 1 + 16);
}

static int derive_secret(const uint8_t secret[32], const char *label,
                         const uint8_t *msgs, size_t msgs_len, uint8_t out[32]) {
    uint8_t th[32];
    d2k_sha256(msgs, msgs_len, th);
    return d2k_hkdf_expand_label_ctx(secret, label, th, sizeof th, out, 32);
}

static int traffic_keys(const uint8_t secret[32], struct dir *d) {
    if (d2k_hkdf_expand_label(secret, "key", d->key, 16) != 0) { return -1; }
    if (d2k_hkdf_expand_label(secret, "iv", d->iv, 12) != 0) { return -1; }
    d->seq = 0;
    return 0;
}

/* Закрытый ключ и случайное стенда — ПОСТОЯННЫЕ, и это осознанно: секретность
   здесь не измеряется (петля на локалхосте, сессия живёт полсекунды), а
   постоянные байты делают разбор упавшего прогона повторяемым. Клиенту они
   ничем не помогают: свой ключ он генерирует сам, из /dev/urandom. */
static const uint8_t stand_priv[32] = {
    0x4a, 0x2f, 0x11, 0x08, 0x77, 0x3c, 0x9d, 0x51, 0x20, 0xe4, 0x6b, 0x33,
    0x0c, 0x91, 0xa7, 0x5e, 0x12, 0xbd, 0x40, 0x88, 0x6f, 0x2a, 0xd3, 0x17,
    0x59, 0xc0, 0x7e, 0x84, 0x35, 0xab, 0x62, 0x09
};
static const uint8_t stand_random[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

/* Достаёт из ClientHello ровно две вещи: идентификатор сессии (его обязан
   вернуть эхом ServerHello) и открытый ключ X25519. Полного разбора здесь
   нет и не нужно — стенд не притворяется сервером общего назначения. */
static int parse_client_hello(const uint8_t *ch, size_t len,
                              const uint8_t **sid, size_t *sid_len,
                              const uint8_t **peer_pub) {
    size_t q = 4;                       /* тип и длина сообщения */
    if (q + 2 + 32 + 1 > len) { return -1; }
    q += 2 + 32;                        /* legacy_version, random */
    *sid_len = ch[q++];
    if (q + *sid_len + 2 > len) { return -1; }
    *sid = ch + q;
    q += *sid_len;
    size_t cs = get16(ch + q); q += 2;  /* cipher_suites */
    if (q + cs + 1 > len) { return -1; }
    q += cs;
    size_t comp = ch[q++];              /* compression_methods */
    if (q + comp + 2 > len) { return -1; }
    q += comp;
    size_t ext_end = q + 2 + get16(ch + q);
    q += 2;
    if (ext_end > len) { return -1; }

    *peer_pub = NULL;
    while (q + 4 <= ext_end) {
        uint16_t et = get16(ch + q), el = get16(ch + q + 2);
        q += 4;
        if (q + el > ext_end) { break; }
        if (et == 0x0033 && el >= 38 && get16(ch + q) == 36 &&
            get16(ch + q + 2) == 0x001d && get16(ch + q + 4) == 32) {
            *peer_pub = ch + q + 6;
        }
        q += el;
    }
    return *peer_pub ? 0 : -1;
}

/* Рукопожатие TLS 1.3 со стороны сервера: ServerHello открытым текстом,
   EncryptedExtensions и Finished под ключами рукопожатия, потом смена на
   прикладные ключи в обе стороны. Сертификата стенд не шлёт вовсе — клиент
   его не проверяет и не будет (шапка d2k_tls13.h называет это прямо), а
   лишний сертификат означал бы держать в тесте ещё и X.509. */
static int stand_handshake(int c, struct dir *rd, struct dir *wr) {
    uint8_t tr[REC_MAX * 2];
    size_t tr_len = 0;

    uint8_t ch[REC_MAX];
    size_t ch_len = 0;
    uint8_t type = 0;
    struct dir none;
    memset(&none, 0, sizeof none);
    if (rec_read(c, &none, 0, &type, ch, sizeof ch, &ch_len) != 0) { return -1; }
    if (type != REC_HANDSHAKE || ch_len < 4 || ch[0] != 1) { return -1; }

    const uint8_t *sid = NULL, *peer_pub = NULL;
    size_t sid_len = 0;
    if (parse_client_hello(ch, ch_len, &sid, &sid_len, &peer_pub) != 0) { return -1; }
    memcpy(tr, ch, ch_len);
    tr_len = ch_len;

    uint8_t pub[32];
    if (d2k_x25519_base(pub, stand_priv) != 0) { return -1; }

    uint8_t sh[256];
    size_t p = 0;
    sh[p++] = 2;                                  /* ServerHello */
    size_t len_at = p; p += 3;
    put16(sh + p, 0x0303); p += 2;                /* legacy_version */
    memcpy(sh + p, stand_random, 32); p += 32;
    sh[p++] = (uint8_t)sid_len;
    memcpy(sh + p, sid, sid_len); p += sid_len;   /* эхо идентификатора сессии */
    put16(sh + p, 0x1301); p += 2;                /* TLS_AES_128_GCM_SHA256 */
    sh[p++] = 0;                                  /* compression */
    size_t ext_at = p; p += 2;
    put16(sh + p, 0x002b); p += 2;                /* supported_versions */
    put16(sh + p, 2); p += 2; put16(sh + p, 0x0304); p += 2;
    put16(sh + p, 0x0033); p += 2;                /* key_share */
    put16(sh + p, 36); p += 2; put16(sh + p, 0x001d); p += 2;
    put16(sh + p, 32); p += 2; memcpy(sh + p, pub, 32); p += 32;
    put16(sh + ext_at, (uint16_t)(p - ext_at - 2));
    size_t body = p - len_at - 3;
    sh[len_at] = (uint8_t)(body >> 16);
    sh[len_at + 1] = (uint8_t)(body >> 8);
    sh[len_at + 2] = (uint8_t)body;

    uint8_t rec[5 + sizeof sh];
    rec[0] = REC_HANDSHAKE;
    put16(rec + 1, 0x0303);
    put16(rec + 3, (uint16_t)p);
    memcpy(rec + 5, sh, p);
    if (wr_all(c, rec, 5 + p) != 0) { return -1; }
    memcpy(tr + tr_len, sh, p);
    tr_len += p;

    uint8_t shared[32];
    if (d2k_x25519(shared, stand_priv, peer_pub) != 0) { return -1; }

    uint8_t zero[32], early[32], derived[32], hs[32], c_hs[32], s_hs[32];
    memset(zero, 0, sizeof zero);
    d2k_hkdf_extract(zero, 32, zero, 32, early);
    if (derive_secret(early, "derived", NULL, 0, derived) != 0) { return -1; }
    d2k_hkdf_extract(derived, 32, shared, 32, hs);
    if (derive_secret(hs, "c hs traffic", tr, tr_len, c_hs) != 0 ||
        derive_secret(hs, "s hs traffic", tr, tr_len, s_hs) != 0 ||
        traffic_keys(c_hs, rd) != 0 || traffic_keys(s_hs, wr) != 0) {
        return -1;
    }

    /* Пустая смена шифра — то же, что шлёт браузер (RFC 8446 §D.4); заодно
       проверяется, что клиент её пропускает, а не считает записью полёта. */
    const uint8_t ccs[6] = { REC_CCS, 0x03, 0x03, 0x00, 0x01, 0x01 };
    if (wr_all(c, ccs, sizeof ccs) != 0) { return -1; }

    /* EncryptedExtensions и Finished — ОДНОЙ записью: клиент обязан искать
       Finished среди нескольких сообщений записи, а не по первому байту. */
    uint8_t flight[4 + 2 + 4 + 32];
    size_t f = 0;
    flight[f++] = 8; flight[f++] = 0; flight[f++] = 0; flight[f++] = 2;
    put16(flight + f, 0); f += 2;                 /* расширений нет */
    memcpy(tr + tr_len, flight, f);
    tr_len += f;

    uint8_t fin_key[32], th[32], verify[32];
    if (d2k_hkdf_expand_label(s_hs, "finished", fin_key, 32) != 0) { return -1; }
    d2k_sha256(tr, tr_len, th);
    d2k_hmac_sha256(fin_key, 32, th, 32, verify);
    flight[f++] = 20; flight[f++] = 0; flight[f++] = 0; flight[f++] = 32;
    memcpy(flight + f, verify, 32); f += 32;
    memcpy(tr + tr_len, flight + 6, 4 + 32);
    tr_len += 4 + 32;
    if (rec_write(c, wr, REC_HANDSHAKE, flight, f) != 0) { return -1; }

    /* Прикладные ключи — от транскрипта ДО клиентского Finished (§7.1). */
    uint8_t derived2[32], master[32], c_ap[32], s_ap[32];
    if (derive_secret(hs, "derived", NULL, 0, derived2) != 0) { return -1; }
    d2k_hkdf_extract(derived2, 32, zero, 32, master);
    if (derive_secret(master, "c ap traffic", tr, tr_len, c_ap) != 0 ||
        derive_secret(master, "s ap traffic", tr, tr_len, s_ap) != 0) {
        return -1;
    }

    /* Клиентский Finished — ещё под ключами рукопожатия. Содержимое не
       проверяем по той же причине, по какой клиент не проверяет серверный:
       подлинность сторон в этом стенде не измеряется. */
    for (;;) {
        uint8_t msg[REC_MAX];
        size_t mlen = 0;
        if (rec_read(c, rd, 1, &type, msg, sizeof msg, &mlen) != 0) { return -1; }
        if (type == REC_CCS) { continue; }
        if (type != REC_HANDSHAKE) { return -1; }
        break;
    }
    if (traffic_keys(c_ap, rd) != 0 || traffic_keys(s_ap, wr) != 0) { return -1; }
    return 0;
}

static void *stand_run(void *arg) {
    struct stand *s = arg;
    int c = accept(s->fd, NULL, NULL);
    if (c < 0) { return NULL; }

    /* Местный порт зонда, снятый С ЭТОЙ стороны провода: ровно то, что увидел
       бы датапат и по чему привязывал бы событие к потоку. Своё представление
       зонда о нём сверять было бы не с чем. */
    struct sockaddr_in peer;
    socklen_t plen = sizeof peer;
    if (getpeername(c, (struct sockaddr *)&peer, &plen) == 0) {
        s->peer_port = ntohs(peer.sin_port);
    }
    struct timeval tv = { STAND_IO_MS / 1000, (STAND_IO_MS % 1000) * 1000 };
    (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    if (s->role == ROLE_PLAIN) {
        /* Дожидаемся приветствия и отвечаем настоящим успехом HTTP открытым
           текстом. Клиент отвергает это сразу, на заголовке записи: байты
           'P' и '/' на месте длины дают 20527 — больше предела записи TLS
           (RFC 8446 §5.1), то есть отказ приходит мгновенно, а не по
           тайм-ауту, и тест не платит за него секундами. */
        uint8_t junk[4096];
        (void)recv(c, junk, sizeof junk, 0);
        static const char ok[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        (void)wr_all(c, (const uint8_t *)ok, sizeof ok - 1);
        /* Держим открытым, пока зонд не уйдёт сам: закрытие сразу после
           ответа дало бы зонду RST вместо тишины, и «транспорт встал» стало
           бы неотличимо от «транспорта не было». */
        (void)recv(c, junk, sizeof junk, 0);
        close(c);
        return NULL;
    }

    struct dir rd, wr;
    memset(&rd, 0, sizeof rd);
    memset(&wr, 0, sizeof wr);
    if (stand_handshake(c, &rd, &wr) != 0) {
        close(c);
        return NULL;
    }

    uint8_t req[REC_MAX];
    size_t rlen = 0;
    uint8_t type = 0;
    if (rec_read(c, &rd, 1, &type, req, sizeof req, &rlen) != 0 || type != REC_APPDATA) {
        close(c);
        return NULL;
    }

    if (s->role >= ROLE_APP) {
        size_t i = (size_t)(s->role - ROLE_APP);
        const uint8_t *p = (const uint8_t *)replies[i].text;
        size_t n = strlen(replies[i].text), split = replies[i].split;
        if (split) { (void)rec_write(c, &wr, REC_APPDATA, p, split); }
        (void)rec_write(c, &wr, REC_APPDATA, p + split, n - split);
    }
    /* ROLE_SILENT: запрос прочитан, ответа нет. Сокет держим открытым до
       ухода зонда — молчание обязано наблюдаться как молчание, а не как
       обрыв: обрыв зонд вправе счесть отдельной бедой. */
    uint8_t drain[256];
    (void)recv(c, drain, sizeof drain, 0);
    close(c);
    return NULL;
}

static uint16_t stand_start(struct stand *s, int role) {
    memset(s, 0, sizeof *s);
    s->fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    a.sin_port = 0;
    if (bind(s->fd, (struct sockaddr *)&a, sizeof a) != 0) { return 0; }
    socklen_t l = sizeof a;
    if (getsockname(s->fd, (struct sockaddr *)&a, &l) != 0) { return 0; }
    if (listen(s->fd, 4) != 0) { return 0; }
    s->role = role;
    s->port = ntohs(a.sin_port);
    if (pthread_create(&s->th, NULL, stand_run, s) != 0) { return 0; }
    return s->port;
}

static void stand_stop(struct stand *s) {
    pthread_join(s->th, NULL);
    close(s->fd);
}

struct probe_job { uint16_t port; d2k_ver_result result; };
static void *parallel_probe(void *arg) {
    struct probe_job *j = arg;
    j->result = d2k_verify_probe("127.0.0.1", j->port, "parallel.example", 3000);
    d2k_verify_close(&j->result);
    return NULL;
}

/* --- проверка «обращение непомеченное» ----------------------------------- */

/* Метку ставит d2k_mark_hook и только он (см. d2k_meas.h). Зонд обязан идти
   НЕПОМЕЧЕННЫМ: помеченный пакет уходит мимо NFQUEUE первым правилом цепочки
   (files/S99d2k), поставленный план к нему не применится, и зонд мерил бы
   линию БЕЗ обхода, считая, что мерит с обходом. Счётчик ловит ровно это. */
static int mark_calls;
static int counting_mark(int fd, uint32_t mark) {
    (void)fd; (void)mark;
    mark_calls++;
    return 0;
}

/* Свободный порт, на котором заведомо никто не слушает: занимаем и сразу
   отпускаем. Чужой процесс теоретически может успеть его занять между
   вызовами — но тогда упало бы утверждение, а не прошло молча. */
static uint16_t closed_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return 0; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return 0; }
    socklen_t l = sizeof a;
    if (getsockname(fd, (struct sockaddr *)&a, &l) != 0) { close(fd); return 0; }
    close(fd);
    return ntohs(a.sin_port);
}

int main(void) {
    d2k_mark_hook = counting_mark;

    /* --- обращение не состоялось: про линию не сказано ничего ------------- */
    {
        uint16_t port = closed_port();
        CHECK(port != 0, "свободный порт не нашёлся");
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "стенд.пример", 2000);
        CHECK(r.level == D2K_VER_NOT_MEASURED,
              "отказ транспорта засчитан выше уровня «не измерено»");
        CHECK(r.status == 0, "кода состояния взяться неоткуда, а он не ноль");
        CHECK(r.fd < 0, "обращение не состоялось, а сокет остался");
        CHECK(r.reason[0] != '\0', "отказ без причины — диагностировать нечем");
        d2k_verify_close(&r);
    }

    /* --- сервер ответил успехом, но не по-нашему: только транспорт -------- */
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_PLAIN);
        CHECK(port != 0, "стенд ROLE_PLAIN не поднялся");

        mark_calls = 0;
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "стенд.пример", 2000);
        CHECK(r.level == D2K_VER_TRANSPORT,
              "не-TLS ответ засчитан выше уровня транспорта");
        CHECK(r.status == 0, "кода состояния взяться неоткуда, а он не ноль");
        CHECK(mark_calls == 0, "зонд пометил обращение — план к нему не применится");
        CHECK(r.fd >= 0, "сокет закрыт до явного d2k_verify_close");

        /* Сокет обязан быть ЖИВЫМ: датапат по FIN удаляет ячейку потока, и
           ответ сервера станет не с чем связать (docs/field/2026-09-11). */
        CHECK(fcntl(r.fd, F_GETFD) >= 0, "сокет отдан числом, но уже закрыт");

        int saved = r.fd;
        d2k_verify_close(&r);
        CHECK(r.fd < 0, "после закрытия дескриптор остался в результате");
        CHECK(fcntl(saved, F_GETFD) < 0 && errno == EBADF,
              "d2k_verify_close не закрыл сокет");

        /* Местный порт — ключ потока, по которому событие датапата
           привязывается к ЭТОМУ обращению. Сверяем с тем, что увидела
           мишень: своё представление о нём сверять не с чем. Join только
           ПОСЛЕ закрытия: мишень держит соединение до ухода зонда (см.
           stand_run), и join до этого стоил бы теста на потолке ожидания. */
        stand_stop(&s);
        CHECK(r.local_port != 0 && r.local_port == s.peer_port,
              "местный порт обращения не тот, что увидела мишень");
    }

    /* --- рукопожатие завершено, приложение молчит ------------------------- */
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_SILENT);
        CHECK(port != 0, "стенд ROLE_SILENT не поднялся");

        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "стенд.пример", 1200);
        CHECK(r.level == D2K_VER_HANDSHAKE,
              "молчание после рукопожатия засчитано за ответ приложения");
        CHECK(r.status == 0, "приложение молчало, а код состояния появился");
        d2k_verify_close(&r);
        stand_stop(&s);
    }

    /* --- ответило приложение: ЭТО и есть доказательство ------------------- */
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_APP);
        CHECK(port != 0, "стенд ROLE_APP не поднялся");

        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "стенд.пример", 3000);
        CHECK(r.level == D2K_VER_APPLICATION,
              "разобранный ответ приложения не поднял уровень до прикладного");
        CHECK(r.status == 200, "код состояния разобран неверно");
        CHECK(r.fd >= 0, "сокет закрыт до явного d2k_verify_close");
        d2k_verify_close(&r);
        stand_stop(&s);
    }

    /* Ни обрыв строки, ни промежуточный 1xx не заменяют окончательный ответ.
       Валидный ответ, разделённый между TLS-записями, не теряется. */
    for (size_t i = 1; i < sizeof replies / sizeof replies[0]; i++) {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_APP + (int)i);
        CHECK(port != 0, "HTTP-стенд не поднялся");
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "http.example", 600);
        CHECK(r.status == replies[i].status, "неверный статус HTTP на граничном ответе");
        CHECK((r.level == D2K_VER_APPLICATION) == (replies[i].status != 0),
              "фрагмент или промежуточный ответ засчитан как окончательный HTTP");
        d2k_verify_close(&r);
        stand_stop(&s);
    }
    {
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", 1, "a\r\nInjected: yes", 100);
        CHECK(r.level == D2K_VER_NOT_MEASURED && r.fd < 0,
              "управляющие символы имени дошли до сети");
    }
    /* Общие static-буферы TLS портили транскрипт/записи соседнего зонда. */
    for (int round = 0; round < 3; round++) {
        struct stand stands[4];
        struct probe_job jobs[4];
        pthread_t threads[4];
        int started[4];
        for (int i = 0; i < 4; i++) {
            jobs[i].port = stand_start(&stands[i], ROLE_APP);
            CHECK(jobs[i].port != 0, "параллельный стенд не поднялся");
            started[i] = pthread_create(&threads[i], NULL, parallel_probe, &jobs[i]) == 0;
            CHECK(started[i], "поток зонда не создан");
        }
        for (int i = 0; i < 4; i++) {
            if (!started[i]) { continue; }
            pthread_join(threads[i], NULL);
            CHECK(jobs[i].result.status == 200, "параллельные TLS-сессии мешают друг другу");
            stand_stop(&stands[i]);
        }
    }

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("уровни доказательства: все проверки прошли\n");
    return 0;
}
