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
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

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
#include "d2k_tls13core.h"
#include "d2k_verify.h"
#include "d2k_hello.h"

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
/* Редирект и конечный ответ идут в одном TLS-соединении. */
#define ROLE_REDIRECT_COMPLETE 64
#define ROLE_REDIRECT_TRUNCATED 65
#define ROLE_PUBLIC_HTML 66
#define ROLE_PARTIAL_TLS 67
#define ROLE_BAD_TAG_TLS 68

static const struct {
    const char *text;
    int status;
    size_t split;
    int cloudflare_challenge;
    int body_complete;
} replies[] = {
    {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 200, 0, 0, 1},
    {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 200, 10, 0, 1},
    {"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 200, 0, 0, 1},
    {"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort", 200, 0, 0, 0},
    {"HTTP/1.1 200", 0, 0, 0, 0},
    {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n", 0, 0, 0, 0},
    {"HTTP/1.1 2000 OK\r\n\r\n", 0, 0, 0, 0},
    {"HTTP/1.1 200x OK\r\n\r\n", 0, 0, 0, 0},
    {"HTTP/1.12 200 OK\r\n\r\n", 0, 0, 0, 0},
    {"HTTP/1.1 999 Invalid\r\n\r\n", 0, 0, 0, 0},
    {"HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 403, 0, 0, 1},
    {"HTTP/1.1 101 Switching Protocols\r\n\r\n", 0, 0, 0, 0},
    {"HTTP/1.1 204 No Content\r\n\r\n", 204, 10, 0, 1},
    {"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n", 204, 0, 0, 1},
    {"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nCf-Mitigated: challenge\r\nContent-Length: 15\r\n\r\n<!doctype html>", 403, 0, 1, 1},
    {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n2\r\ntw\r\n0\r\nX-End: yes\r\n\r\n", 200, 0, 0, 1},
    {"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nok", 200, 0, 0, 1},
    {"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Encoding: identity\r\nContent-Length: 2\r\n\r\nok", 200, 0, 0, 1},
    {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4000\r\nshort", 200, 0, 0, 0},
    {"HTTP/1.1 302 Found\r\nLocation: https://other.example/\r\nContent-Length: 0\r\n\r\n", 302, 0, 0, 1},
    {"HTTP/1.1 302 Found\r\nLocation: https://other.example/\r\nContent-Length: 20\r\n\r\nshort", 302, 0, 0, 0},
    {"HTTP/1.1 302 Found\r\nLocation: http://other.example/\r\nContent-Length: 0\r\n\r\n", 302, 0, 0, 1},
    {"HTTP/1.1 302 Found\r\nLocation: https:///\r\nContent-Length: 0\r\n\r\n", 302, 0, 0, 1},
    {"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n", 302, 0, 0, 1},
    {"HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru/\r\nContent-Length: 0\r\n\r\n", 302, 0, 0, 1},
    {"HTTP/1.1 302 Found\r\nLocation: //eais.rkn.gov.ru/blocked\r\nContent-Length: 0\r\n\r\n", 302, 0, 0, 1},
    {"HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru.evil.example/\r\nContent-Length: 0\r\n\r\n", 302, 0, 0, 1},
    {"HTTP/1.1 451 Unavailable For Legal Reasons\r\nContent-Length: 0\r\n\r\n", 451, 0, 0, 1},
    {"HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\n\r\naccess blocked by rkn", 403, 0, 0, 1},
    {"HTTP/1.1 403 Forbidden\r\nContent-Length: 46\r\n\r\n<a href=\"https://eais.rkn.gov.ru/\">blocked</a>", 403, 0, 0, 1},
    {"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n7\r\naccess \r\nE\r\nblocked by rkn\r\n0\r\n\r\n", 403, 0, 0, 1},
    {"HTTP/1.1 403 Forbidden\r\nContent-Encoding: gzip\r\nContent-Length: 21\r\n\r\naccess blocked by rkn", 403, 0, 0, 1},
    {"HTTP/1.1 403 Forbidden\r\nLink: <https://eais.rkn.gov.ru/>\r\nContent-Length: 0\r\n\r\n", 403, 0, 0, 1},
    {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\n\r\n", 200, 0, 0, 0},
};

struct stand {
    int       fd;        /* слушающий сокет */
    uint16_t  port;
    int       role;
    uint16_t  peer_port; /* местный порт зонда, каким его ВИДИТ мишень */
    int       accepted_compression;
    int       accepted_identity;
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

static int contains_bytes(const uint8_t *buf, size_t len, const char *needle) {
    size_t n = strlen(needle);
    if (n > len) { return 0; }
    for (size_t i = 0; i <= len - n; i++) {
        if (memcmp(buf + i, needle, n) == 0) { return 1; }
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

static int rec_write_mode(int fd, struct dir *d, uint8_t type,
                     const uint8_t *data, size_t n, int mode) {
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
    if(mode==2)out[5+n]^=1;
    return wr_all(fd, out, mode==1 ? 14005 : 5 + n + 1 + 16);
}

static int rec_write(int fd, struct dir *d, uint8_t type, const uint8_t *data, size_t n) {
    return rec_write_mode(fd,d,type,data,n,0);
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
/* Длина последнего приветствия, ДОШЕДШЕГО до мишени. Пишется из потока
   стенда, читается тестом после join — гонки нет. */
static size_t stand_ch_wire;

/* Имя, которым мишень представляется в сертификате. NULL — сертификата нет
   вовсе (так стенд вёл себя всегда: подлинность здесь не измеряется).
   Ставится тестом ДО запуска потока стенда.

   Сертификат ненастоящий и настоящим быть не обязан: зонд ищет в нём ровно
   расширение subjectAltName и ровно его dNSName, а цепочку не строит и
   строить не будет (см. d2k_tls_peer_name). Стенд кладёт эти байты и ничего
   больше — так проверяется РАЗБОР, а не чужая библиотека X.509. */
static const char *stand_cert_name;
static char stand_request[REC_MAX + 1];
static int stand_same_origin_redirect;
static int stand_redirect_followed;

/* ALPN, которого требует мишень (задача 37, F3), и то, что предложил зонд.
   Требование задано, а в списке зонда его нет — мишень отвечает тревогой
   120 (no_application_protocol, RFC 7301 §3.2), как сервер MQTT поверх TLS
   на поле 02.10.2026. stand_alpn_seen: "-" — расширения не было вовсе,
   иначе имена через запятую. */
static const char *stand_alpn_need;
static char stand_alpn_seen[300];

static void stand_read_alpn(const uint8_t *ch, size_t len) {
    snprintf(stand_alpn_seen, sizeof stand_alpn_seen, "-");
    size_t q = 4 + 2 + 32;
    if (q + 1 > len) return;
    q += 1 + ch[q];
    if (q + 2 > len) return;
    q += 2 + get16(ch + q);
    if (q + 1 > len) return;
    q += 1 + ch[q];
    if (q + 2 > len) return;
    size_t end = q + 2 + get16(ch + q);
    q += 2;
    if (end > len) return;
    while (q + 4 <= end) {
        uint16_t et = get16(ch + q), el = get16(ch + q + 2);
        q += 4;
        if (q + el > end) return;
        if (et == 0x0010 && el >= 2) {
            size_t w = 0;
            stand_alpn_seen[0] = '\0';
            for (size_t i = 2; i < el && i + 1 + ch[q + i] <= el; i += 1 + ch[q + i]) {
                int n = snprintf(stand_alpn_seen + w, sizeof stand_alpn_seen - w, "%s%.*s",
                                 w ? "," : "", (int)ch[q + i], (const char *)ch + q + i + 1);
                if (n < 0 || (size_t)n >= sizeof stand_alpn_seen - w) break;
                w += (size_t)n;
            }
            return;
        }
        q += el;
    }
}

static int stand_alpn_offered(const char *name) {
    size_t n = strlen(name);
    for (const char *p = stand_alpn_seen; (p = strstr(p, name)) != NULL; p += n)
        if ((p == stand_alpn_seen || p[-1] == ',') && (p[n] == ',' || p[n] == '\0')) return 1;
    return 0;
}

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
    stand_read_alpn(ch, ch_len);
    if (stand_alpn_need && !stand_alpn_offered(stand_alpn_need)) {
        static const uint8_t alert120[7] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 120 };
        (void)wr_all(c, alert120, sizeof alert120);
        return -1;
    }
    /* Проводная длина приветствия, какой её увидела МИШЕНЬ: пять байт
       заголовка записи плюс тело. Своё представление о ней сверять не с чем —
       ровно та же причина, по которой местный порт берётся у мишени. */
    stand_ch_wire = ch_len + 5;
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
    uint8_t flight[1024];
    size_t f = 0;
    flight[f++] = 8; flight[f++] = 0; flight[f++] = 0; flight[f++] = 2;
    put16(flight + f, 0); f += 2;                 /* расширений нет */
    if (stand_cert_name) {
        size_t nlen = strlen(stand_cert_name);
        if (nlen > 100) { return -1; }            /* всё длины однобайтные */
        uint8_t der[128];
        size_t d = 0;
        der[d++] = 0x06; der[d++] = 0x03;         /* OID 2.5.29.17 */
        der[d++] = 0x55; der[d++] = 0x1D; der[d++] = 0x11;
        der[d++] = 0x04; der[d++] = (uint8_t)(2 + 2 + nlen);   /* OCTET STRING */
        der[d++] = 0x30; der[d++] = (uint8_t)(2 + nlen);       /* GeneralNames */
        der[d++] = 0x82; der[d++] = (uint8_t)nlen;             /* dNSName */
        memcpy(der + d, stand_cert_name, nlen); d += nlen;

        size_t body = 1 + 3 + 3 + d + 2;
        flight[f++] = 11;                                       /* Certificate */
        flight[f++] = (uint8_t)(body >> 16);
        flight[f++] = (uint8_t)(body >> 8);
        flight[f++] = (uint8_t)body;
        flight[f++] = 0;                                        /* контекст пуст */
        size_t list = 3 + d + 2;
        flight[f++] = (uint8_t)(list >> 16);
        flight[f++] = (uint8_t)(list >> 8);
        flight[f++] = (uint8_t)list;
        flight[f++] = (uint8_t)(d >> 16);
        flight[f++] = (uint8_t)(d >> 8);
        flight[f++] = (uint8_t)d;
        memcpy(flight + f, der, d); f += d;
        flight[f++] = 0; flight[f++] = 0;                       /* расширений нет */
    }
    memcpy(tr + tr_len, flight, f);
    tr_len += f;

    uint8_t fin_key[32], th[32], verify[32];
    if (d2k_hkdf_expand_label(s_hs, "finished", fin_key, 32) != 0) { return -1; }
    d2k_sha256(tr, tr_len, th);
    d2k_hmac_sha256(fin_key, 32, th, 32, verify);
    size_t fin_at = f;
    flight[f++] = 20; flight[f++] = 0; flight[f++] = 0; flight[f++] = 32;
    memcpy(flight + f, verify, 32); f += 32;
    memcpy(tr + tr_len, flight + fin_at, 4 + 32);
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
    struct sockaddr_storage peer;
    socklen_t plen = sizeof peer;
    if (getpeername(c, (struct sockaddr *)&peer, &plen) == 0) {
        s->peer_port = peer.ss_family == AF_INET6
            ? ntohs(((struct sockaddr_in6 *)&peer)->sin6_port)
            : ntohs(((struct sockaddr_in *)&peer)->sin_port);
    }
    struct timeval tv = { STAND_IO_MS / 1000, (STAND_IO_MS % 1000) * 1000 };
    (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    if (s->role == ROLE_PLAIN) {
        /* Точный вид полевого ответа Cloudflare, пойманного на Rutracker
           при плане 8: открытый HTTP 400 на TCP/443, затем FIN. Первые пять
           байт "HTTP/" не являются TLS-заголовком; P/ в позициях длины
           дают 20527. Это не запись TLS и не повод поднимать REC_MAX. */
        uint8_t junk[4096];
        (void)recv(c, junk, sizeof junk, 0);
        static const char cloudflare_400[] =
            "HTTP/1.1 400 Bad Request\r\n"
            "Server: cloudflare\r\n"
            "Date: Tue, 29 Sep 2026 11:32:03 GMT\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 155\r\n"
            "Connection: close\r\n"
            "CF-RAY: -\r\n\r\n"
            "<html>\r\n"
            "<head><title>400 Bad Request</title></head>\r\n"
            "<body>\r\n"
            "<center><h1>400 Bad Request</h1></center>\r\n"
            "<hr><center>cloudflare</center>\r\n"
            "</body>\r\n"
            "</html>\r\n";
        CHECK(sizeof cloudflare_400 - 1 == 316,
              "захваченный Cloudflare 400 должен содержать 316 байт TCP payload");
        static const char cf_prefix[] =
            "HTTP/1.1 400 Bad Request\r\nServer: cloudflare\r\n";
        CHECK(memcmp(cloudflare_400, cf_prefix, sizeof cf_prefix - 1) == 0,
              "fixture соответствует наблюдаемому ответу Cloudflare");
        (void)wr_all(c, (const uint8_t *)cloudflare_400, sizeof cloudflare_400 - 1);
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
    size_t copy = rlen < sizeof stand_request - 1 ? rlen : sizeof stand_request - 1;
    memcpy(stand_request, req, copy);
    stand_request[copy] = '\0';

    if(s->role==ROLE_PARTIAL_TLS||s->role==ROLE_BAD_TAG_TLS) {
        uint8_t payload[16367];memset(payload,'x',sizeof payload);
        memcpy(payload,"HTTP/1.1 200 OK\r\nContent-Length: 16300\r\n\r\n",42);
        (void)rec_write_mode(c,&wr,REC_APPDATA,payload,sizeof payload,s->role==ROLE_PARTIAL_TLS?1:2);
        close(c);return NULL;
    }
    if (stand_same_origin_redirect) {
        static const char moved[] =
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Location: /forum/index.php\r\nContent-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n";
        static const char page[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            "Connection: keep-alive\r\n\r\nok";
        if (rec_write(c, &wr, REC_APPDATA, (const uint8_t *)moved, sizeof moved - 1) == 0 &&
            rec_read(c, &rd, 1, &type, req, sizeof req, &rlen) == 0 &&
            type == REC_APPDATA) {
            copy = rlen < sizeof stand_request - 1 ? rlen : sizeof stand_request - 1;
            memcpy(stand_request, req, copy);
            stand_request[copy] = '\0';
            stand_redirect_followed = 1;
            (void)rec_write(c, &wr, REC_APPDATA, (const uint8_t *)page, sizeof page - 1);
        }
        uint8_t drain_redirect[256];
        (void)recv(c, drain_redirect, sizeof drain_redirect, 0);
        close(c);
        return NULL;
    }

    if (s->role == ROLE_REDIRECT_COMPLETE || s->role == ROLE_REDIRECT_TRUNCATED) {
        s->accepted_compression = contains_bytes(req, rlen, "Accept-Encoding: gzip, deflate");
        s->accepted_identity = contains_bytes(req, rlen, "Accept-Encoding: identity");
        static const char redirect[] =
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Location: /forum/index.php\r\n"
            "Content-Length: 0\r\n\r\n";
        struct timeval short_wait = { 0, 500000 };
        (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &short_wait, sizeof short_wait);
        if (rec_write(c, &wr, REC_APPDATA, (const uint8_t *)redirect,
                      sizeof redirect - 1) != 0 ||
            rec_read(c, &rd, 1, &type, req, sizeof req, &rlen) != 0 ||
            type != REC_APPDATA ||
            rlen < 29 || memcmp(req, "GET /forum/index.php HTTP/1.1", 29) != 0) {
            close(c);
            return NULL;
        }
        static const char headers[] =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        static const char complete[] = "4\r\npage\r\n0\r\n\r\n";
        static const char truncated[] = "4\r\npa";
        const char *body = s->role == ROLE_REDIRECT_COMPLETE ? complete : truncated;
        size_t body_len = s->role == ROLE_REDIRECT_COMPLETE
            ? sizeof complete - 1 : sizeof truncated - 1;
        uint8_t close_notify[2] = { 1, 0 };
        (void)rec_write(c, &wr, REC_APPDATA, (const uint8_t *)headers,
                        sizeof headers - 1);
        (void)rec_write(c, &wr, REC_APPDATA, (const uint8_t *)body, body_len);
        if (s->role == ROLE_REDIRECT_TRUNCATED) {
            (void)rec_write(c, &wr, REC_ALERT, close_notify, sizeof close_notify);
        }
        close(c);
        return NULL;
    }

    if (s->role == ROLE_PUBLIC_HTML) {
        const char *body = "<head><link rel='stylesheet' href='//assets.example/main.css'></head><body>ok";
        char header[180];
        int n = snprintf(header, sizeof header,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\n\r\n", strlen(body));
        (void)rec_write(c, &wr, REC_APPDATA, (const uint8_t *)header, (size_t)n);
        (void)rec_write(c, &wr, REC_APPDATA, (const uint8_t *)body, 43);
        (void)rec_write(c, &wr, REC_APPDATA, (const uint8_t *)body + 43, strlen(body) - 43);
    } else if (s->role >= ROLE_APP) {
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

static uint16_t stand_start_family(struct stand *s, int role, int family) {
    memset(s, 0, sizeof *s);
    stand_request[0] = '\0';
    s->fd = socket(family, SOCK_STREAM, 0);
    struct sockaddr_storage a;
    memset(&a, 0, sizeof a);
    socklen_t alen;
    if (family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&a;
        v6->sin6_family = AF_INET6; v6->sin6_addr = in6addr_loopback;
        alen = sizeof *v6;
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&a;
        v4->sin_family = AF_INET; v4->sin_addr.s_addr = htonl(0x7f000001);
        alen = sizeof *v4;
    }
    if (bind(s->fd, (struct sockaddr *)&a, alen) != 0) { return 0; }
    socklen_t l = sizeof a;
    if (getsockname(s->fd, (struct sockaddr *)&a, &l) != 0) { return 0; }
    if (listen(s->fd, 4) != 0) { return 0; }
    s->role = role;
    s->port = family == AF_INET6 ? ntohs(((struct sockaddr_in6 *)&a)->sin6_port)
                               : ntohs(((struct sockaddr_in *)&a)->sin_port);
    if (pthread_create(&s->th, NULL, stand_run, s) != 0) { return 0; }
    return s->port;
}

static uint16_t stand_start(struct stand *s, int role) {
    return stand_start_family(s, role, AF_INET);
}

static void stand_stop(struct stand *s) {
    pthread_join(s->th, NULL);
    close(s->fd);
}

struct probe_job { uint16_t port; d2k_ver_result result; };
static void *parallel_probe(void *arg) {
    struct probe_job *j = arg;
    j->result = d2k_verify_probe("127.0.0.1", j->port, "parallel.example", 3000, 0);
    d2k_verify_close(&j->result);
    return NULL;
}

/* --- проверка «обращение непомеченное» ----------------------------------- */

/* Метку ставит d2k_mark_hook и только он (см. d2k_meas.h). Зонд обязан идти
   НЕПОМЕЧЕННЫМ: помеченный пакет уходит мимо NFQUEUE первым правилом цепочки
   (files/S99d2k), поставленный план к нему не применится, и зонд мерил бы
   линию БЕЗ обхода, считая, что мерит с обходом. Счётчик ловит ровно это. */
static int mark_calls;
static uint32_t last_mark;
static int counting_mark(int fd, uint32_t mark) {
    (void)fd;
    last_mark = mark;
    mark_calls++;
    return 0;
}
static int protected_udp_mark(int fd, uint32_t mark) {
#ifdef SO_NOSIGPIPE
    int enabled = 0;
    socklen_t len = sizeof enabled;
    CHECK(getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, &len) == 0 && enabled,
          "QUIC socket must suppress SIGPIPE before its first send");
#endif
    (void)fd; (void)mark;
    return -1; /* Stop before network I/O, for both owned and supplied sockets. */
}
static int failing_mark(int fd, uint32_t mark) {
    (void)fd;
    last_mark = mark;
    mark_calls++;
    return -1;
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

static void test_rx_wire_progress(void) {
    for(int bad=0;bad<2;bad++) {
        struct stand s;uint16_t port=stand_start(&s,bad?ROLE_BAD_TAG_TLS:ROLE_PARTIAL_TLS);
        d2k_ver_result r=d2k_verify_probe_identity_on(-1,"127.0.0.1",port,"wire.example",800,0,0);
        CHECK(r.negotiated_tls==0x0304,"wire progress retains negotiated TLS version");
        CHECK(r.level==D2K_VER_HANDSHAKE&&!r.status&&!r.body_bytes&&!r.body_complete,
              "partial/bad-tag ciphertext must never become HTTP plaintext");
        CHECK(r.rx_tls_wire_bytes==(bad?16389u:14005u),"actual consumed TLS wire bytes missing or handshake counted");
        CHECK(r.rx_tls_record_missing==(bad?0u:2384u),"full bad-tag record is not a truncated record");
        d2k_verify_close(&r);stand_stop(&s);
    }
}
int main(int argc,char **argv) {
    test_rx_wire_progress();
    if(argc==2&&!strcmp(argv[1],"--wire-progress-only"))return fails?1:0;
    const char *html = "<head><!-- <link rel='stylesheet' href='//bad.test/a.css'> -->"
        "<script>var x=\"<link rel='stylesheet' href='//bad.test/b.css'>\";</script>"
        "<LINK HREF='https://Assets.Example/a.min.css' REL='stylesheet'>"
        "<link href='//second.example/b.css?token=secret' rel='stylesheet'>"
        "<link href='//third.example/c.css' rel='stylesheet'></head><body>"
        "<link href='//bad.test/d.css' rel='stylesheet'>";
    for (size_t chunk = 1; chunk < 40; chunk++) {
        d2k_resource_scan scan = {0};
        for (size_t i = 0; i < strlen(html); i += chunk) {
            size_t take = strlen(html) - i;
            if (take > chunk) take = chunk;
            d2k_resource_feed(&scan, (const uint8_t *)html + i, take);
        }
        CHECK(scan.count == 2 && !strcmp(scan.refs[0].host, "assets.example") &&
              !strcmp(scan.refs[0].path, "/a.min.css") &&
              !strcmp(scan.refs[1].host, "third.example"),
              "streamed public CSS hints depend on chunk boundaries or include unsafe context");
    }
    /* ПОДСКАЗКА ИЗ ТЕЛА CSS, А НЕ ИЗ ТЕГА (поле 12.10.2026). Крупный файл
       цели бывает указан только внутри таблицы стилей другого хоста: у
       style.sndcdn.com нужный путь лежал в CSS с a-v2.sndcdn.com, поэтому
       зонд объёма просил «/» и получал 403 на 243 байта, не входя в полосу.
       Ссылка собирается по байтам и проходит ту же строгую проверку. */
    {
        static const char css[] =
            "@charset \"utf-8\";\n"
            "@import url(\"https://Fonts.Example/soehne-6ee1b930.css\");\n"
            ".a{background:url('https://img.example/p.png');color:red}\n"
            ".b{src:url(https://second.example/late.css)}\n"
            ".c{src:url(\"https://third.example/q.css?token=secret\")}\n";
        for (size_t chunk = 1; chunk < 40; chunk++) {
            d2k_resource_scan scan = {0};
            for (size_t i = 0; i < strlen(css); i += chunk) {
                size_t take = strlen(css) - i;
                if (take > chunk) take = chunk;
                d2k_resource_feed(&scan, (const uint8_t *)css + i, take);
            }
            CHECK(scan.count == 2 &&
                  !strcmp(scan.refs[0].host, "fonts.example") &&
                  !strcmp(scan.refs[0].path, "/soehne-6ee1b930.css") &&
                  !strcmp(scan.refs[1].host, "second.example") &&
                  !strcmp(scan.refs[1].path, "/late.css"),
                  "CSS body hints are missed, chunk-dependent or include unsafe context");
        }
    }
    CHECK(!d2k_resource_path_ok("//evil/a.css") &&
          !d2k_resource_path_ok("/a.css?token=secret") &&
          !d2k_resource_path_ok("/a/../b.css") &&
          !d2k_resource_path_ok("/a.css\r\nX: yes"), "unsafe witness path accepted");
    d2k_mark_hook = counting_mark;
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_PUBLIC_HTML);
        d2k_ver_result r = d2k_verify_probe_identity_on(-1, "127.0.0.1", port,
            "public.example", 3000, 0, 0);
        CHECK(r.body_complete && r.n_resources == 1 &&
              !strcmp(r.resources[0].host, "assets.example") &&
              !strcmp(r.resources[0].path, "/main.css"),
              "native HTTP-body reader lost CSS hint across TLS records");
        d2k_verify_close(&r); stand_stop(&s);
    }
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_APP);
        d2k_ver_result r = d2k_verify_probe_path_on(-1, "127.0.0.1", port,
            "public.example", 3000, 0, 0, 0, 0, "/assets/app.min.css");
        CHECK(r.body_complete && r.status == 200, "stylesheet verifier lost existing HTTP proof");
        CHECK(strstr(stand_request, "GET /assets/app.min.css HTTP/1.1\r\n") != NULL &&
              strstr(stand_request, "Accept-Encoding: identity") != NULL,
              "stylesheet witness silently replaced with root or compressed request");
        d2k_verify_close(&r); stand_stop(&s);
        r = d2k_verify_probe_path_on(-1, "127.0.0.1", 1, "public.example",
            100, 0, 0, 0, 0, "/app.css?private=yes");
        CHECK(r.fd == -1 && r.level == D2K_VER_NOT_MEASURED,
              "invalid witness opened a socket");
    }
    {
        /* Проверка изоляции метки QUIC: зонд d2k_verify_probe_quic_path_on идёт
           НЕПОМЕЧЕННЫМ (mark_calls == 0), а d2k_verify_probe_quic_path_mark_on с
           mark > 0 зовёт mark hook до отправки Initial. */
        mark_calls = 0;
        last_mark = 0;
        d2k_ver_result r = d2k_verify_probe_quic_path_on(-1, "127.0.0.1", 1,
                                                         "stand.example", 1, 0, "/");
        CHECK(mark_calls == 0, "QUIC probe without mark must not call mark hook");
        d2k_verify_close(&r);

        mark_calls = 0;
        last_mark = 0;
        r = d2k_verify_probe_quic_path_mark_on(-1, "127.0.0.1", 1,
                                               "stand.example", 1, 0, 0x1234, "/");
        CHECK(mark_calls > 0, "QUIC probe with mark must call mark hook");
        CHECK(last_mark == 0x1234, "QUIC probe mark hook received wrong mark");
        CHECK(r.negotiated_tls == 0, "unsuccessful QUIC probe must not report negotiated TLS");
        d2k_verify_close(&r);

        /* Регрессия: ошибка установки метки (SO_MARK) обязана прекратить контроль
           с локальной ошибкой, без отправки пакетов, без сетевого вердикта и без
           скрытого отката на непомеченный сокет. */
        d2k_mark_hook = failing_mark;
        mark_calls = 0;
        last_mark = 0;
        r = d2k_verify_probe_quic_path_mark_on(-1, "127.0.0.1", 1,
                                               "stand.example", 1, 0, 0x1234, "/");
        CHECK(mark_calls > 0, "failing mark hook was invoked");
        CHECK(last_mark == 0x1234, "failing mark hook got requested mark");
        CHECK(r.level == D2K_VER_NOT_MEASURED, "mark failure must not advance level");
        CHECK(r.fd == -1, "mark failure must close socket");
        CHECK(r.local_refusal == 1, "mark failure must set local_refusal flag");
        CHECK(r.negotiated_tls == 0, "mark failure must leave negotiated_tls 0");
        CHECK(strstr(r.reason, "метка измерительного сокета не поставилась") != NULL,
              "mark failure reason mismatch");
        d2k_verify_close(&r);

        d2k_mark_hook = protected_udp_mark;
        r = d2k_verify_probe_quic_path_mark_on(-1, "127.0.0.1", 1,
                                               "stand.example", 1, 0, 0x1234, "/");
        d2k_verify_close(&r);
        int supplied = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(supplied >= 0, "supplied UDP socket");
        r = d2k_verify_probe_quic_path_mark_on(supplied, "127.0.0.1", 1,
                                               "stand.example", 1, 0, 0x1234, "/");
        d2k_verify_close(&r);
        close(supplied);
        d2k_mark_hook = failing_mark;

        /* Проверяем, что и на TCP отказ SO_MARK даёт машинный флаг local_refusal */
        mark_calls = 0;
        last_mark = 0;
        r = d2k_verify_probe_path_on(-1, "127.0.0.1", 1, "stand.example",
                                     100, 0, 0, 0, 0x1234, NULL);
        CHECK(mark_calls > 0, "failing TCP mark hook was invoked");
        CHECK(r.level == D2K_VER_NOT_MEASURED, "TCP mark failure must not advance level");
        CHECK(r.fd == -1, "TCP mark failure must close socket");
        CHECK(r.local_refusal == 1, "TCP mark failure must set local_refusal flag");
        d2k_verify_close(&r);
        d2k_mark_hook = counting_mark;
    }
    {
        struct stand s;
        uint16_t port = stand_start_family(&s, ROLE_APP, AF_INET6);
        CHECK(port != 0, "IPv6 TLS fixture starts");
        d2k_ver_result r = d2k_verify_probe("::1", port, "ipv6.example", 3000, 0);
        CHECK(r.level == D2K_VER_APPLICATION && r.status == 200,
              "IPv6 TLS verifier completes handshake and receives HTTP");
        if (r.fd < 0) return 1;
        CHECK(r.family == 6 && memcmp(r.local_addr, &in6addr_loopback, 16) == 0,
              "IPv6 verifier retains full native source address");
        d2k_verify_close(&r);
        stand_stop(&s);
        CHECK(r.local_port == s.peer_port && r.local_port != 0,
              "IPv6 verifier reports actual trial port");
    }

    /* --- обращение не состоялось: про линию не сказано ничего ------------- */
    {
        uint16_t port = closed_port();
        CHECK(port != 0, "свободный порт не нашёлся");
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "стенд.пример", 2000, 0);
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
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "стенд.пример", 2000, 0);
        CHECK(r.level == D2K_VER_TRANSPORT,
              "не-TLS ответ засчитан выше уровня транспорта");
        CHECK(r.status == 0, "кода состояния взяться неоткуда, а он не ноль");
        CHECK(strstr(r.reason, "48 54 54 50 2f") != NULL &&
              strstr(r.reason, "открытый HTTP") != NULL &&
              strstr(r.reason, "20527") == NULL,
              "verifier принял открытый HTTP-ответ Cloudflare за поле длины TLS");
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

    /* Тот же неверный формат серверного ответа должен быть виден при
       подтверждении старой TLS-формой, а не только у TLS 1.3 verifier. */
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_PLAIN);
        CHECK(port != 0, "стенд ROLE_PLAIN для TLS 1.2 не поднялся");
        d2k_ver_result r = d2k_verify_probe12_on(-1, "127.0.0.1", port,
                                                  "стенд.пример", 2000, 0);
        CHECK(r.level == D2K_VER_TRANSPORT,
              "TLS 1.2 verifier принял открытый HTTP за TLS");
        CHECK(strstr(r.reason, "48 54 54 50 2f") != NULL &&
              strstr(r.reason, "открытый HTTP") != NULL &&
              strstr(r.reason, "20527") == NULL,
              "TLS 1.2 verifier принял открытый HTTP-ответ за поле длины TLS");
        d2k_verify_close(&r);
        stand_stop(&s);
    }

    /* --- рукопожатие завершено, приложение молчит ------------------------- */
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_SILENT);
        CHECK(port != 0, "стенд ROLE_SILENT не поднялся");

        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "стенд.пример", 1200, 0);
        CHECK(r.level == D2K_VER_HANDSHAKE,
              "молчание после рукопожатия засчитано за ответ приложения");
        CHECK(r.status == 0, "приложение молчало, а код состояния появился");
        d2k_verify_close(&r);
        stand_stop(&s);
    }

    /* --- ЗАДАЧА 37, F3: ALPN КЛИЕНТА ------------------------------------
       Мишень — сервер MQTT поверх TLS: без «mqtt» в ALPN отвечает тревогой
       120. Прежний HTTP-зонд (http/1.1) её и получает; зонд с ALPN клиента
       доводит рукопожатие до конца и засчитывает его уровнем рукопожатия,
       не приложения. */
    {
        uint8_t ch[2048]; size_t chl = 0, ll = 0; uint8_t list[256];
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "alpn.example", ch, sizeof ch, &chl) == 0 &&
              d2k_hello_alpn(ch, chl, list, sizeof list, &ll) == 1 && d2k_alpn_is_http(list, ll),
              "ALPN профиля браузера не прочитан как HTTP");
        CHECK(d2k_hello_alpn(ch, chl - 1, list, sizeof list, &ll) == -1,
              "обрезанное приветствие выдало ALPN вместо «не измерено»");
        static const uint8_t mqtt[] = { 4, 'm', 'q', 't', 't' };
        CHECK(!d2k_alpn_is_http(mqtt, sizeof mqtt), "mqtt принят за HTTP");

        struct stand s;
        stand_alpn_need = "mqtt";
        uint16_t port = stand_start(&s, ROLE_SILENT);
        d2k_ver_result r = d2k_verify_probe_on(-1, "127.0.0.1", port, "mqtt.example", 1500, 0);
        CHECK(r.level == D2K_VER_TRANSPORT && strstr(r.reason, "120") != NULL &&
              stand_alpn_offered("http/1.1"),
              "стенд не воспроизводит поле: HTTP-зонд должен получить тревогу 120");
        d2k_verify_close(&r);
        stand_stop(&s);

        port = stand_start(&s, ROLE_SILENT);
        r = d2k_verify_probe_alpn_on(-1, "127.0.0.1", port, "mqtt.example", 1500, 0,
                                     mqtt, sizeof mqtt);
        CHECK(stand_alpn_offered("mqtt") && !stand_alpn_offered("http/1.1"),
              "зонд с ALPN клиента предложил не mqtt");
        CHECK(r.level == D2K_VER_HANDSHAKE && r.handshake_proof && r.status == 0 &&
              strstr(r.reason, "120") == NULL,
              "рукопожатие с ALPN клиента не завершено или выдано за приложение");
        d2k_verify_close(&r);
        stand_stop(&s);

        /* Клиент без ALPN — и зонд без ALPN. */
        stand_alpn_need = NULL;
        port = stand_start(&s, ROLE_SILENT);
        r = d2k_verify_probe_alpn_on(-1, "127.0.0.1", port, "noalpn.example", 1500, 0, NULL, 0);
        CHECK(!strcmp(stand_alpn_seen, "-") && r.level == D2K_VER_HANDSHAKE && r.handshake_proof,
              "клиент без ALPN, а зонд его предложил");
        d2k_verify_close(&r);
        stand_stop(&s);
    }

    /* The RX candidate must request identity even across its same-origin
       redirect. A compressed control cannot prove repair of the RX cut. */
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_REDIRECT_COMPLETE);
        CHECK(port != 0, "identity-стенд не поднялся");
        d2k_ver_result r = d2k_verify_probe_identity_on(-1, "127.0.0.1", port,
                                                       "http.example", 1800, 0, 0);
        CHECK(r.level == D2K_VER_APPLICATION && r.status == 200 && r.body_complete,
              "identity verifier не получил полное конечное тело");
        d2k_verify_close(&r);
        stand_stop(&s);
        CHECK(s.accepted_identity && !s.accepted_compression,
              "RX-кандидат проверяется сжатием вместо identity");
    }

    /* --- ответило приложение: ЭТО и есть доказательство ------------------- */
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_APP);
        CHECK(port != 0, "стенд ROLE_APP не поднялся");

        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "стенд.пример", 3000, 0);
        CHECK(r.level == D2K_VER_APPLICATION,
              "разобранный ответ приложения не поднял уровень до прикладного");
        CHECK(r.status == 200, "код состояния разобран неверно");
        CHECK(r.fd >= 0, "сокет закрыт до явного d2k_verify_close");
        d2k_verify_close(&r);
        stand_stop(&s);
    }

    /* Успех проверяется по конечному ответу на той же TLS-сессии, а не по
       промежуточному 301. Chunked-ответ должен дойти до нулевого чанка. */
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_REDIRECT_COMPLETE);
        CHECK(port != 0, "стенд редиректа с полным ответом не поднялся");
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "http.example", 1800, 0);
        CHECK(r.level == D2K_VER_APPLICATION && r.status == 200,
              "проверка остановилась на 301 вместо конечного ответа по тому же TLS-соединению");
        d2k_verify_close(&r);
        stand_stop(&s);
        CHECK(s.accepted_compression,
              "HTTP verifier не запросил обычное сжатие, из-за чего меняется поведение источника");
    }
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_REDIRECT_TRUNCATED);
        CHECK(port != 0, "стенд оборванного ответа не поднялся");
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "http.example", 1800, 0);
        CHECK(r.level != D2K_VER_APPLICATION,
              "оборванное тело конечного ответа засчитано как рабочий обход");
        d2k_verify_close(&r);
        stand_stop(&s);
    }

    /* --- ИМЯ, КОТОРЫМ ПРЕДСТАВИЛСЯ СЕРВЕР -------------------------------
       Коробка, ТЕРМИНИРУЮЩАЯ TLS и отдающая страницу блокировки, даёт зонду
       ровно ту же картину, что рабочий обход: рукопожатие сошлось, HTTP
       ответил 200. Отличить её можно только по имени в сертификате — и это
       не проверка подлинности (цепочка не строится), а защита от записи
       «подтверждено» на разговоре с ЧУЖИМ сервером.

       Ответ трёхзначный: 1 совпало, 0 НЕ совпало, -1 сказать нечего. */
    {
        struct { const char *cert; const char *ask; int want; const char *what; } cn[] = {
            { "стенд.пример",  "стенд.пример", 1,  "точное совпадение" },
            { "чужой.пример",  "стенд.пример", 0,  "чужое имя" },
            { "*.пример",      "стенд.пример", 1,  "подстановочная первая метка" },
            { "*.пример",      "пример",       0,  "подстановка не покрывает голый домен" },
            { NULL,            "стенд.пример", -1, "сертификата нет вовсе" },
        };
        for (size_t i = 0; i < sizeof cn / sizeof cn[0]; i++) {
            struct stand s;
            stand_cert_name = cn[i].cert;
            uint16_t port = stand_start(&s, ROLE_APP);
            CHECK(port != 0, "стенд для сверки имени не поднялся");
            d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, cn[i].ask, 3000, 0);
            CHECK(r.level == D2K_VER_APPLICATION,
                  "сверка имени сломала рукопожатие — мишень отвечает, а зонд не дошёл");
            CHECK(r.name_ok == cn[i].want,
                  "сверка имени сервера дала не тот ответ");
            d2k_verify_close(&r);
            stand_stop(&s);
        }
        stand_cert_name = NULL;
    }

    /* 451 ОТ ВЛАДЕЛЬЦА ИМЕНИ — ВСЁ ТАКИ ОТКАЗ САЙТА. Та же мишень, тот же
       ответ, разница только в сертификате: имя совпало — отвечал владелец
       имени, и решение прежнее (D2K_VER_DENIED, поиск закрывается). Без этой
       пары правка 24.10.2026 читалась бы как «451 больше ничего не значит». */
    {
        struct { const char *cert; int denied; const char *what; } who[] = {
            { "отказ.пример", 1, "имя совпало — отказ сайта" },
            { "чужой.пример", 0, "имя чужое — не отказ сайта" },
            { NULL,           0, "сертификата нет — не отказ сайта" },
        };
        for (size_t i = 0; i < sizeof who / sizeof who[0]; i++) {
            struct stand s;
            stand_cert_name = who[i].cert;
            /* 27 — индекс фикстуры 451 в replies[]; стенд выбирает ответ по
               роли (ROLE_APP + индекс), см. stand_serve. */
            uint16_t port = stand_start(&s, ROLE_APP + 27);
            CHECK(port != 0, "стенд 451 не поднялся");
            d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "отказ.пример", 3000, 0);
            CHECK(r.status == 451, "стенд 451 ответил не 451");
            CHECK((r.level == D2K_VER_DENIED) == who[i].denied,
                  "451: решение об отказе сайта не зависит от подтверждения имени");
            d2k_verify_close(&r);
            stand_stop(&s);
        }
        stand_cert_name = NULL;
    }

    /* RFC 5280 iPAddress SAN is an OCTET STRING inside GeneralNames, not a
       dNSName containing the textual IP. QUIC address targets have no SNI,
       so verification must bind the certificate to the literal IP. */
    {
        static const uint8_t ip_cert[] = {
            0x00, 0x00, 0x00, 0x14, /* context, certificate_list length */
            0x00, 0x00, 0x0f,       /* certificate length */
            0x06, 0x03, 0x55, 0x1d, 0x11, /* subjectAltName OID */
            0x04, 0x08, 0x30, 0x06, 0x87, 0x04, 127, 0, 0, 1,
            0x00, 0x00              /* certificate extensions */
        };
        CHECK(d2k_t13_cert_name_ok(ip_cert, sizeof ip_cert, "127.0.0.1") == 1,
              "QUIC/IP verification must accept a matching iPAddress SAN");
        CHECK(d2k_t13_cert_name_ok(ip_cert, sizeof ip_cert, "127.0.0.2") == 0,
              "QUIC/IP verification must reject a different iPAddress SAN");
    }

    /* --- ДОБИВКА ДО ДЛИНЫ ПРИВЕТСТВИЯ КЛИЕНТА ---------------------------
       Зонд ходит своим приветствием, вчетверо короче браузерного (замерено в
       лаборатории 13.09.2026: curl шлёт 1581 байт, наше — около четырёхсот).
       На этой разнице ломается переносимость: план, чьи куски помещаются в
       посылку на коротком приветствии, на длинном не помещается вовсе, и
       подтверждение достаётся зонду, а не человеку.

       Проверяется ДВА утверждения, и оба обязательны:
         - на проводе оказалось РОВНО столько байт, сколько просили (иначе
           добивка есть, а контекст всё равно чужой);
         - рукопожатие при этом дошло до приложения (иначе мы научились
           добивать, но сломали зонд). */
    for (size_t i = 0; i < 2; i++) {
        size_t want = i == 0 ? (size_t)900 : (size_t)1581;
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_APP);
        CHECK(port != 0, "стенд ROLE_APP для добивки не поднялся");
        stand_ch_wire = 0;

        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "стенд.пример", 3000, want);
        CHECK(r.level == D2K_VER_APPLICATION,
              "добитое приветствие не довело зонд до приложения");
        d2k_verify_close(&r);
        stand_stop(&s);
        CHECK(stand_ch_wire == want,
              "до мишени дошло приветствие НЕ той длины — измерение идёт в чужом контексте");
    }

    /* Просьба короче собственного приветствия не укорачивает его и ничего не
       ломает: добивать назад нечем, и притворяться, что получилось, нельзя. */
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_APP);
        CHECK(port != 0, "стенд ROLE_APP для короткой просьбы не поднялся");
        stand_ch_wire = 0;
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "стенд.пример", 3000, 50);
        CHECK(r.level == D2K_VER_APPLICATION,
              "невыполнимая просьба о длине сломала зонд");
        d2k_verify_close(&r);
        stand_stop(&s);
        CHECK(stand_ch_wire > 50,
              "приветствие внезапно укоротилось до невозможного");
    }

    /* RX-измерительный зонд умеет запросить gzip отдельно от identity и
       подтверждает полное framing тела. Тест смотрит на запрос, реально
       дошедший до TLS-стенда, а не на переданный вызывающим режим. */
    {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_APP);
        CHECK(port != 0, "стенд для baseline gzip-зонда не поднялся");
        d2k_ver_result r = d2k_verify_probe_baseline("127.0.0.1", port,
            "baseline.example", 3000, 0, 0, 1, 0);
        CHECK(r.level == D2K_VER_APPLICATION && r.body_complete && r.body_bytes == 2,
              "baseline-зонд не прочитал тело ответа полностью");
        d2k_verify_close(&r);
        stand_stop(&s);
        CHECK(strstr(stand_request, "Accept-Encoding: gzip\r\n") != NULL,
              "gzip-контроль фактически ушёл как другой запрос");
    }

    /* Root redirect RuTracker is same-origin; the verifier must ask for the
       redirected page on the same TLS flow and credit only its full response. */
    {
        struct stand s;
        stand_same_origin_redirect = 1;
        stand_redirect_followed = 0;
        uint16_t port = stand_start(&s, ROLE_APP);
        CHECK(port != 0, "стенд same-origin redirect не поднялся");
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port,
                                             "redirect.example", 3000, 0);
        CHECK(r.level == D2K_VER_APPLICATION && r.status == 200 &&
              r.body_complete && r.body_bytes == 2,
              "same-origin redirect не довёл проверку до тела страницы");
        d2k_verify_close(&r);
        stand_stop(&s);
        stand_same_origin_redirect = 0;
        CHECK(stand_redirect_followed &&
              strstr(stand_request, "GET /forum/index.php HTTP/1.1\r\n") != NULL,
              "same-origin redirect не запросил целевой путь на том же TLS-потоке");
    }

    /* Ни обрыв строки, ни промежуточный 1xx не заменяют окончательный ответ.
       Валидный ответ, разделённый между TLS-записями, не теряется. */
    for (size_t i = 1; i < sizeof replies / sizeof replies[0]; i++) {
        struct stand s;
        uint16_t port = stand_start(&s, ROLE_APP + (int)i);
        CHECK(port != 0, "HTTP-стенд не поднялся");
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", port, "http.example", 600, 0);
        if (r.status != replies[i].status) {
            fprintf(stderr, "HTTP case %zu: expected %d, got %d (level %d): %s\n",
                    i, replies[i].status, r.status, (int)r.level, r.reason);
        }
        CHECK(r.status == replies[i].status, "неверный статус HTTP на граничном ответе");
        int expected_application = replies[i].body_complete &&
            (!(replies[i].status >= 300 && replies[i].status < 400) ||
             strstr(replies[i].text, "Location: https://other.example/\r\n") != NULL ||
             strstr(replies[i].text, "Location: https://warning.rt.ru.evil.example/\r\n") != NULL) &&
            !replies[i].cloudflare_challenge;
        /* 451 БЕЗ ПОДТВЕРЖДЁННОГО ИМЕНИ — НЕ ОТКАЗ САЙТА (24.10.2026). Стенд
           этих случаев сертификата не присылает (stand_cert_name == NULL), то
           есть собеседник имени не подтвердил; отказом сайта такой 451 не
           считается, и поиск обязан продолжиться. Случай с подтверждённым
           именем — отдельным блоком ниже. */
        int block_fixture =
            strstr(replies[i].text, "Location: https://warning.rt.ru/\r\n") != NULL ||
            strstr(replies[i].text, "Location: //eais.rkn.gov.ru/blocked\r\n") != NULL ||
            (replies[i].status == 403 &&
             strstr(replies[i].text, "Content-Encoding: gzip") == NULL &&
             (strstr(replies[i].text, "\r\n\r\naccess blocked by rkn") != NULL ||
              strstr(replies[i].text, "<a href=") != NULL ||
              strstr(replies[i].text, "blocked by rkn\r\n0") != NULL));
        if (block_fixture) expected_application = 0;
        CHECK(!block_fixture || strstr(r.reason, "HTTP отказ:") != NULL,
              "явная заглушка не получила отдельную причину отказа");
        if (replies[i].status == 451) {
            expected_application = 0;
            CHECK(r.level != D2K_VER_DENIED,
                  "451 без подтверждённого имени записан отказом сайта");
            CHECK(strstr(r.reason, "не подтвердил имя сертификатом") != NULL,
                  "451 без имени не объяснил, почему это не отказ сайта");
            CHECK(r.http_outcome == D2K_HTTP_NEUTRAL,
                  "451 без имени оставил исход «юридический отказ»");
        }
        CHECK((r.level == D2K_VER_APPLICATION) == expected_application,
              "полный HTTPS redirect потерян либо неполный/невалидный ответ засчитан");
        CHECK(r.body_complete == replies[i].body_complete,
              "ошибочный вывод о полноте HTTP-тела");
        CHECK(r.cloudflare_challenge == replies[i].cloudflare_challenge,
              "challenge Cloudflare не отличён от обычного ответа приложения");
        CHECK((r.level == D2K_VER_CHALLENGE) == replies[i].cloudflare_challenge,
              "антибот challenge потерял отдельный неуспешный уровень");
        if (strstr(replies[i].text, "Transfer-Encoding: chunked\r\n") != NULL &&
            strstr(replies[i].text, "4000\r\nshort") == NULL &&
            strstr(replies[i].text, "Transfer-Encoding: chunked\r\nTransfer-Encoding") == NULL) {
            CHECK(r.body_chunked && r.body_framing_valid,
                  "валидный chunked-ответ потерял framing metadata");
        }
        if (strstr(replies[i].text, "Transfer-Encoding: chunked\r\nTransfer-Encoding") != NULL) {
            CHECK(!r.body_framing_valid && !r.body_complete,
                  "дублированный Transfer-Encoding принят как однозначный framing");
        }
        if (strstr(replies[i].text, "Content-Encoding: gzip\r\nContent-Encoding:") != NULL) {
            CHECK(r.body_encoding == 2 && r.body_framing_valid,
                  "несколько Content-Encoding не помечены как неизвестная coding-stack");
        } else if (strstr(replies[i].text, "Content-Encoding: gzip\r\n") != NULL) {
            CHECK(r.body_encoding == 1 && r.body_framing_valid,
                  "gzip-ответ не распознан как сжатый и однозначно оформленный");
        }
        if (r.status != 0 && strstr(replies[i].text, "Content-Length:") != NULL) {
            CHECK(r.body_has_length && r.body_framing_valid,
                  "Content-Length-ответ потерял достоверную framing metadata");
        }
        if (strstr(replies[i].text, "4000\r\nshort") != NULL) {
            CHECK(r.body_chunked && !r.body_complete && r.body_bytes == 5,
                  "обрыв chunked-тела не сохранил реально полученный объём");
        }
        d2k_verify_close(&r);
        stand_stop(&s);
        if (replies[i].status == 302 && expected_application) {
            port = stand_start(&s, ROLE_APP + (int)i);
            CHECK(port != 0, "stylesheet redirect стенд не поднялся");
            r = d2k_verify_probe_path_on(-1, "127.0.0.1", port,
                "http.example", 600, 0, 0, 0, 0, "/assets/app.min.css");
            CHECK(r.status == 302 && r.body_complete &&
                  r.level != D2K_VER_APPLICATION,
                  "redirect другого origin заменил подтверждение CSS");
            d2k_verify_close(&r);
            stand_stop(&s);
        }
    }
    {
        d2k_ver_result r = d2k_verify_probe("127.0.0.1", 1, "a\r\nInjected: yes", 100, 0);
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
