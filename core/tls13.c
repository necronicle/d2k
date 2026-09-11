/* tls13.c — минимальный клиент TLS 1.3. См. d2k_tls13.h: зачем он есть и чего
 * он намеренно не делает.
 *
 * КЛЮЧЕВОЕ РАСПИСАНИЕ (RFC 8446 §7.1) целиком:
 *
 *   early   = HKDF-Extract(salt=0,      IKM=0)
 *   derived = Derive-Secret(early,      "derived", "")
 *   hs      = HKDF-Extract(salt=derived, IKM=ECDHE)
 *   c_hs    = Derive-Secret(hs, "c hs traffic", CH..SH)
 *   s_hs    = Derive-Secret(hs, "s hs traffic", CH..SH)
 *   derived2= Derive-Secret(hs,         "derived", "")
 *   master  = HKDF-Extract(salt=derived2, IKM=0)
 *   c_ap    = Derive-Secret(master, "c ap traffic", CH..server Finished)
 *   s_ap    = Derive-Secret(master, "s ap traffic", CH..server Finished)
 *
 * Транскрипт — SHA-256 по СООБЩЕНИЯМ рукопожатия (без заголовков записей и без
 * шифрования), и порядок в нём тот, в каком они пришли на провод.
 *
 * ЧТО МЫ НЕ ПРОВЕРЯЕМ И ПОЧЕМУ ЭТО НАЗВАНО ЗДЕСЬ, А НЕ СКРЫТО: подпись
 * сертификата, цепочку доверия, имя в сертификате и Finished сервера. Сессия
 * служит ОДНОЙ цели — протолкнуть по линии десятки килобайт и посмотреть, на
 * каком объёме её оборвут. Подмена сервера этому измерению не мешает: коробка
 * на линии и есть предмет измерения. Проверять Finished было бы дёшево, но
 * бессмысленно без проверки подписи, а та требует X.509 и цепочки доверия —
 * это отдельный модуль, которого у проекта нет и который эта задача не
 * оправдывает.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_crypto.h"
#include "d2k_tls13.h"

#define REC_CCS       20
#define REC_ALERT     21
#define REC_HANDSHAKE 22
#define REC_APPDATA   23

#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2
#define HS_FINISHED     20

/* Предел одной записи TLS (RFC 8446 §5.1: 2^14 открытого текста плюс накладные). */
#define REC_MAX 18432

struct d2k_tls {
    int      fd;
    uint8_t  c_key[16], c_iv[12];
    uint8_t  s_key[16], s_iv[12];
    uint64_t c_seq, s_seq;

    /* Остаток прочитанного, ещё не отданный вызывающему. */
    uint8_t  plain[REC_MAX];
    size_t   plain_len, plain_off;
};

static void say(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) { return; }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Читает ровно n байт с потолком по времени. 0 — прочитано, -1 — отказ. */
static int read_exact(int fd, uint8_t *buf, size_t n, int64_t deadline,
                      char *err, size_t errcap) {
    size_t got = 0;
    while (got < n) {
        int64_t left = deadline - now_ms();
        if (left <= 0) {
            say(err, errcap, "не дождались %zu байт за отведённое время", n - got);
            return -1;
        }
        struct pollfd p;
        p.fd = fd; p.events = POLLIN; p.revents = 0;
        int pr = poll(&p, 1, (int)(left > 1000 ? 1000 : left));
        if (pr < 0) {
            if (errno == EINTR) { continue; }
            say(err, errcap, "poll: %s", strerror(errno));
            return -1;
        }
        if (pr == 0) { continue; }
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r == 0) {
            say(err, errcap, "соединение закрыто на %zu-м байте из %zu", got, n);
            return -1;
        }
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) { continue; }
            say(err, errcap, "чтение: %s", strerror(errno));
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t n, char *err, size_t errcap) {
    size_t sent = 0;
    while (sent < n) {
#ifdef MSG_NOSIGNAL
        ssize_t w = send(fd, buf + sent, n - sent, MSG_NOSIGNAL);
#else
        ssize_t w = send(fd, buf + sent, n - sent, 0);
#endif
        if (w <= 0) {
            if (w < 0 && (errno == EINTR || errno == EAGAIN)) { continue; }
            say(err, errcap, "запись: %s", strerror(errno));
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/* Случайные байты из ядра. Своего генератора не заводим: 32 байта на сессию —
   не та частота, ради которой стоит держать собственный поток случайности, а
   предсказуемый client_random сделал бы сессию воспроизводимой для того, кто
   слушает линию. */
static int fill_random(uint8_t *b, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { return -1; }
    size_t got = fread(b, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }

/* --- сборка ClientHello -------------------------------------------------- */

/* Собирает ClientHello с НАШИМ ключом. Приветствия из core/hello.c сюда не
   годятся: там реальные захваты чужих сессий, и закрытого ключа к их key_share
   у нас нет по определению. Форма здесь минимальная и своя — её задача
   договориться, а не обмануть коробку (обманывает план в датапате, и этот
   зонд ходит НЕПОМЕЧЕННЫМ именно затем, чтобы план к нему применился). */
static size_t build_client_hello(uint8_t *out, size_t cap, const char *sni,
                                 const uint8_t pub[32], const uint8_t rnd[32]) {
    if (cap < 512) { return 0; }
    size_t sni_len = sni ? strlen(sni) : 0;
    size_t p = 0;

    out[p++] = HS_CLIENT_HELLO;
    size_t len_at = p; p += 3;                    /* длина тела — впишем в конце */
    put16(out + p, 0x0303); p += 2;               /* legacy_version = TLS 1.2 */
    memcpy(out + p, rnd, 32); p += 32;            /* random */
    out[p++] = 32;                                /* legacy_session_id */
    memcpy(out + p, rnd, 32); p += 32;            /* тот же случайный — годится */
    put16(out + p, 2); p += 2;                    /* cipher_suites */
    put16(out + p, 0x1301); p += 2;               /* TLS_AES_128_GCM_SHA256 */
    out[p++] = 1; out[p++] = 0;                   /* compression: null */

    size_t ext_at = p; p += 2;                    /* длина расширений */

    if (sni_len > 0 && sni_len < 256) {           /* server_name */
        put16(out + p, 0x0000); p += 2;
        put16(out + p, (uint16_t)(sni_len + 5)); p += 2;
        put16(out + p, (uint16_t)(sni_len + 3)); p += 2;
        out[p++] = 0;
        put16(out + p, (uint16_t)sni_len); p += 2;
        memcpy(out + p, sni, sni_len); p += sni_len;
    }
    put16(out + p, 0x000b); p += 2;               /* ec_point_formats */
    put16(out + p, 2); p += 2; out[p++] = 1; out[p++] = 0;

    put16(out + p, 0x000a); p += 2;               /* supported_groups */
    put16(out + p, 4); p += 2; put16(out + p, 2); p += 2;
    put16(out + p, 0x001d); p += 2;               /* x25519 */

    /* signature_algorithms — набор браузера, а не минимальный из трёх.
       Минимальный работал на Google, Cloudflare и Microsoft и получал
       handshake_failure от Akamai (проверено на example.com): сервер вправе
       отказать, если ни один предложенный алгоритм ему не подходит, и узкий
       список превращает измерение в лотерею по тому, чья это сеть. */
    put16(out + p, 0x000d); p += 2;
    put16(out + p, 20); p += 2; put16(out + p, 18); p += 2;
    put16(out + p, 0x0403); p += 2;               /* ecdsa_secp256r1_sha256 */
    put16(out + p, 0x0503); p += 2;               /* ecdsa_secp384r1_sha384 */
    put16(out + p, 0x0603); p += 2;               /* ecdsa_secp521r1_sha512 */
    put16(out + p, 0x0804); p += 2;               /* rsa_pss_rsae_sha256 */
    put16(out + p, 0x0805); p += 2;               /* rsa_pss_rsae_sha384 */
    put16(out + p, 0x0806); p += 2;               /* rsa_pss_rsae_sha512 */
    put16(out + p, 0x0401); p += 2;               /* rsa_pkcs1_sha256 */
    put16(out + p, 0x0501); p += 2;               /* rsa_pkcs1_sha384 */
    put16(out + p, 0x0601); p += 2;               /* rsa_pkcs1_sha512 */

    put16(out + p, 0x002b); p += 2;               /* supported_versions */
    put16(out + p, 3); p += 2; out[p++] = 2;
    put16(out + p, 0x0304); p += 2;               /* TLS 1.3 */

    /* ALPN и psk_key_exchange_modes — то, что шлёт браузер. Формально для
       обмена ключами не нужны; практически часть сетей отвечает
       handshake_failure на приветствие, непохожее на браузерное, и тогда
       проба меряла бы нашу непохожесть вместо блока по объёму. */
    put16(out + p, 0x0010); p += 2;               /* application_layer_protocol_negotiation */
    put16(out + p, 11); p += 2; put16(out + p, 9); p += 2;
    out[p++] = 8; memcpy(out + p, "http/1.1", 8); p += 8;

    put16(out + p, 0x002d); p += 2;               /* psk_key_exchange_modes */
    put16(out + p, 2); p += 2; out[p++] = 1; out[p++] = 1; /* psk_dhe_ke */

    put16(out + p, 0x0033); p += 2;               /* key_share */
    put16(out + p, 38); p += 2; put16(out + p, 36); p += 2;
    put16(out + p, 0x001d); p += 2; put16(out + p, 32); p += 2;
    memcpy(out + p, pub, 32); p += 32;

    put16(out + ext_at, (uint16_t)(p - ext_at - 2));
    size_t body = p - len_at - 3;
    out[len_at] = (uint8_t)(body >> 16);
    out[len_at + 1] = (uint8_t)(body >> 8);
    out[len_at + 2] = (uint8_t)body;
    return p;
}

/* --- работа с записями --------------------------------------------------- */

static void nonce_of(const uint8_t iv[12], uint64_t seq, uint8_t out[12]) {
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++) {
        out[11 - i] ^= (uint8_t)(seq >> (8 * i));
    }
}

/* Читает ОДНУ запись. type/payload/len — наружу. Для зашифрованных записей
   снимает защиту и отдаёт ВНУТРЕННИЙ тип (RFC 8446 §5.2: настоящий тип —
   последний ненулевой байт открытого текста). */
static int read_record(d2k_tls *t, int encrypted, uint8_t *type,
                       uint8_t *payload, size_t cap, size_t *len,
                       int64_t deadline, char *err, size_t errcap) {
    uint8_t hdr[5];
    if (read_exact(t->fd, hdr, 5, deadline, err, errcap) != 0) { return -1; }
    size_t rlen = get16(hdr + 3);
    if (rlen == 0 || rlen > REC_MAX) {
        say(err, errcap, "запись длиной %zu вне предела", rlen);
        return -1;
    }
    static uint8_t raw[REC_MAX];
    if (read_exact(t->fd, raw, rlen, deadline, err, errcap) != 0) { return -1; }

    if (hdr[0] == REC_CCS) {
        /* Смена шифра в TLS 1.3 — пустая формальность совместимости
           (RFC 8446 §5), содержимого не несёт и в транскрипт не идёт. */
        *type = REC_CCS;
        *len = 0;
        return 0;
    }
    if (!encrypted || hdr[0] != REC_APPDATA) {
        if (rlen > cap) { say(err, errcap, "запись не помещается"); return -1; }
        memcpy(payload, raw, rlen);
        *type = hdr[0];
        *len = rlen;
        return 0;
    }

    uint8_t nonce[12];
    nonce_of(t->s_iv, t->s_seq, nonce);
    if (rlen < 17 || rlen - 16 > cap) {
        say(err, errcap, "зашифрованная запись длиной %zu не разбирается", rlen);
        return -1;
    }
    if (d2k_aes128_gcm_decrypt(t->s_key, nonce, hdr, 5, raw, rlen, payload) != 0) {
        say(err, errcap, "тег записи не сошёлся (номер %llu)", (unsigned long long)t->s_seq);
        return -1;
    }
    t->s_seq++;
    size_t n = rlen - 16;
    while (n > 0 && payload[n - 1] == 0) { n--; }   /* набивка нулями, §5.2 */
    if (n == 0) {
        say(err, errcap, "запись без внутреннего типа");
        return -1;
    }
    *type = payload[n - 1];
    *len = n - 1;
    return 0;
}

static int write_record(d2k_tls *t, uint8_t type, const uint8_t *data, size_t n,
                        char *err, size_t errcap) {
    if (n + 1 + 16 > REC_MAX) { say(err, errcap, "запись длиннее предела"); return -1; }
    static uint8_t buf[REC_MAX + 5];
    uint8_t inner[REC_MAX];
    memcpy(inner, data, n);
    inner[n] = type;                               /* настоящий тип внутри, §5.2 */

    buf[0] = REC_APPDATA;                          /* снаружи всегда 23, §5.2 */
    put16(buf + 1, 0x0303);
    put16(buf + 3, (uint16_t)(n + 1 + 16));

    uint8_t nonce[12];
    nonce_of(t->c_iv, t->c_seq, nonce);
    uint8_t tag[16];
    if (d2k_aes128_gcm_encrypt(t->c_key, nonce, buf, 5, inner, n + 1, buf + 5, tag) != 0) {
        say(err, errcap, "не зашифровалось");
        return -1;
    }
    memcpy(buf + 5 + n + 1, tag, 16);
    t->c_seq++;
    return write_all(t->fd, buf, 5 + n + 1 + 16, err, errcap);
}

/* --- ключевое расписание ------------------------------------------------- */

static int derive_secret(const uint8_t secret[32], const char *label,
                         const uint8_t *msgs, size_t msgs_len, uint8_t out[32]) {
    uint8_t th[32];
    d2k_sha256(msgs, msgs_len, th);
    return d2k_hkdf_expand_label_ctx(secret, label, th, sizeof th, out, 32);
}

static int traffic_keys(const uint8_t secret[32], uint8_t key[16], uint8_t iv[12]) {
    if (d2k_hkdf_expand_label(secret, "key", key, 16) != 0) { return -1; }
    return d2k_hkdf_expand_label(secret, "iv", iv, 12);
}

int d2k_tls_connect(int fd, const char *sni, int deadline_ms,
                    d2k_tls **out, char *err, size_t errcap) {
    if (err && errcap) { err[0] = '\0'; }
    if (fd < 0 || !out) { say(err, errcap, "нечем поднимать сессию"); return -1; }
    *out = NULL;
    int64_t deadline = now_ms() + (deadline_ms > 0 ? deadline_ms : 8000);

    uint8_t priv[32], pub[32], rnd[32];
    if (fill_random(priv, 32) != 0 || fill_random(rnd, 32) != 0) {
        say(err, errcap, "нет случайности: /dev/urandom недоступен");
        return -1;
    }
    if (d2k_x25519_base(pub, priv) != 0) {
        say(err, errcap, "открытый ключ не посчитался");
        return -1;
    }

    /* Транскрипт: сообщения рукопожатия подряд, без заголовков записей. */
    static uint8_t tr[REC_MAX * 4];
    size_t tr_len = 0;

    uint8_t ch[1024];
    size_t ch_len = build_client_hello(ch, sizeof ch, sni, pub, rnd);
    if (ch_len == 0) { say(err, errcap, "приветствие не собралось"); return -1; }

    uint8_t rec[5 + 1024];
    rec[0] = REC_HANDSHAKE;
    put16(rec + 1, 0x0301);                        /* legacy_record_version */
    put16(rec + 3, (uint16_t)ch_len);
    memcpy(rec + 5, ch, ch_len);
    if (write_all(fd, rec, 5 + ch_len, err, errcap) != 0) { return -1; }
    memcpy(tr, ch, ch_len);
    tr_len = ch_len;

    d2k_tls *t = calloc(1, sizeof *t);
    if (!t) { say(err, errcap, "не хватило памяти"); return -1; }
    t->fd = fd;

    /* ServerHello — открытым текстом. */
    uint8_t sh[REC_MAX];
    size_t sh_len = 0;
    uint8_t type = 0;
    for (;;) {
        if (read_record(t, 0, &type, sh, sizeof sh, &sh_len, deadline, err, errcap) != 0) {
            free(t);
            return -1;
        }
        if (type == REC_CCS) { continue; }
        if (type == REC_ALERT) {
            say(err, errcap, "сервер прервал рукопожатие тревогой %u",
                sh_len >= 2 ? (unsigned)sh[1] : 0u);
            free(t);
            return -1;
        }
        if (type != REC_HANDSHAKE || sh_len < 4 || sh[0] != HS_SERVER_HELLO) {
            say(err, errcap, "вместо ServerHello пришло другое (тип %u)", (unsigned)type);
            free(t);
            return -1;
        }
        break;
    }
    memcpy(tr + tr_len, sh, sh_len);
    tr_len += sh_len;

    /* Из ServerHello нужен ровно один байт смысла — общий ключ. Разбираем
       ровно до него, не притворяясь полным разбором. */
    size_t q = 4 + 2 + 32;                         /* тип+длина, версия, random */
    if (q + 1 > sh_len) { say(err, errcap, "ServerHello обрезан"); free(t); return -1; }
    q += 1 + sh[q];                                /* legacy_session_id_echo */
    if (q + 3 > sh_len) { say(err, errcap, "ServerHello обрезан"); free(t); return -1; }
    uint16_t suite = get16(sh + q); q += 2;
    q += 1;                                        /* compression */
    if (suite != 0x1301) {
        say(err, errcap, "сервер выбрал шифр 0x%04x, а поддержан только 0x1301",
            (unsigned)suite);
        free(t);
        return -1;
    }
    if (q + 2 > sh_len) { say(err, errcap, "ServerHello без расширений"); free(t); return -1; }
    size_t ext_end = q + 2 + get16(sh + q);
    q += 2;
    if (ext_end > sh_len) { ext_end = sh_len; }

    const uint8_t *peer = NULL;
    while (q + 4 <= ext_end) {
        uint16_t et = get16(sh + q), el = get16(sh + q + 2);
        q += 4;
        if (q + el > ext_end) { break; }
        if (et == 0x0033 && el >= 4 && get16(sh + q) == 0x001d && get16(sh + q + 2) == 32 &&
            el >= 36) {
            peer = sh + q + 4;
        }
        q += el;
    }
    if (!peer) {
        say(err, errcap, "сервер не прислал ключ X25519 — TLS 1.3 не согласован");
        free(t);
        return -1;
    }

    uint8_t shared[32];
    if (d2k_x25519(shared, priv, peer) != 0) {
        say(err, errcap, "общий секрет не посчитался (точка малого порядка)");
        free(t);
        return -1;
    }

    uint8_t zero[32], early[32], derived[32], hs[32], c_hs[32], s_hs[32];
    memset(zero, 0, sizeof zero);
    d2k_hkdf_extract(zero, 32, zero, 32, early);
    if (derive_secret(early, "derived", NULL, 0, derived) != 0) {
        say(err, errcap, "расписание ключей не собралось"); free(t); return -1;
    }
    d2k_hkdf_extract(derived, 32, shared, 32, hs);
    if (derive_secret(hs, "c hs traffic", tr, tr_len, c_hs) != 0 ||
        derive_secret(hs, "s hs traffic", tr, tr_len, s_hs) != 0 ||
        traffic_keys(c_hs, t->c_key, t->c_iv) != 0 ||
        traffic_keys(s_hs, t->s_key, t->s_iv) != 0) {
        say(err, errcap, "ключи рукопожатия не собрались"); free(t); return -1;
    }
    t->c_seq = t->s_seq = 0;

    /* Флайт сервера: всё под ключами рукопожатия, до его Finished включительно.
       Содержимое не проверяем (см. шапку файла), но в транскрипт кладём — от
       него зависят прикладные ключи. */
    for (;;) {
        uint8_t msg[REC_MAX];
        size_t mlen = 0;
        if (read_record(t, 1, &type, msg, sizeof msg, &mlen, deadline, err, errcap) != 0) {
            free(t);
            return -1;
        }
        if (type == REC_CCS) { continue; }
        if (type == REC_ALERT) {
            say(err, errcap, "сервер прервал рукопожатие тревогой %u",
                mlen >= 2 ? (unsigned)msg[1] : 0u);
            free(t);
            return -1;
        }
        if (type != REC_HANDSHAKE) {
            say(err, errcap, "в рукопожатии запись типа %u", (unsigned)type);
            free(t);
            return -1;
        }
        if (tr_len + mlen > sizeof tr) {
            say(err, errcap, "транскрипт рукопожатия длиннее предела");
            free(t);
            return -1;
        }
        memcpy(tr + tr_len, msg, mlen);
        tr_len += mlen;

        /* Одна запись может нести несколько сообщений — ищем Finished среди
           них по заголовкам, а не по первому байту записи. */
        int done = 0;
        size_t o = 0;
        while (o + 4 <= mlen) {
            size_t blen = (size_t)msg[o + 1] << 16 | (size_t)msg[o + 2] << 8 | msg[o + 3];
            if (msg[o] == HS_FINISHED) { done = 1; }
            o += 4 + blen;
        }
        if (done) { break; }
    }

    /* Прикладные ключи считаются от транскрипта ДО нашего Finished. */
    uint8_t derived2[32], master[32], c_ap[32], s_ap[32];
    if (derive_secret(hs, "derived", NULL, 0, derived2) != 0) {
        say(err, errcap, "расписание ключей не собралось"); free(t); return -1;
    }
    d2k_hkdf_extract(derived2, 32, zero, 32, master);
    if (derive_secret(master, "c ap traffic", tr, tr_len, c_ap) != 0 ||
        derive_secret(master, "s ap traffic", tr, tr_len, s_ap) != 0) {
        say(err, errcap, "прикладные ключи не собрались"); free(t); return -1;
    }

    /* Наш Finished — под ключами РУКОПОЖАТИЯ, поэтому шлём до смены ключей. */
    uint8_t fin_key[32], th[32], verify[32];
    if (d2k_hkdf_expand_label(c_hs, "finished", fin_key, 32) != 0) {
        say(err, errcap, "ключ подтверждения не собрался"); free(t); return -1;
    }
    d2k_sha256(tr, tr_len, th);
    d2k_hmac_sha256(fin_key, 32, th, 32, verify);
    uint8_t fin[4 + 32];
    fin[0] = HS_FINISHED; fin[1] = 0; fin[2] = 0; fin[3] = 32;
    memcpy(fin + 4, verify, 32);

    /* Пустая смена шифра перед Finished — совместимость со «средними ящиками»
       (RFC 8446 §D.4). Ровно то, что шлёт браузер; без неё часть сетевого
       оборудования рвёт сессию, и мы измеряли бы это вместо блока по объёму. */
    uint8_t ccs[6] = { REC_CCS, 0x03, 0x03, 0x00, 0x01, 0x01 };
    if (write_all(fd, ccs, sizeof ccs, err, errcap) != 0) { free(t); return -1; }
    if (write_record(t, REC_HANDSHAKE, fin, sizeof fin, err, errcap) != 0) {
        free(t);
        return -1;
    }

    /* Смена на прикладные ключи — в обе стороны, счётчики с нуля (§5.3). */
    if (traffic_keys(c_ap, t->c_key, t->c_iv) != 0 ||
        traffic_keys(s_ap, t->s_key, t->s_iv) != 0) {
        say(err, errcap, "прикладные ключи не развернулись"); free(t); return -1;
    }
    t->c_seq = t->s_seq = 0;

    *out = t;
    return 0;
}

int d2k_tls_write(d2k_tls *t, const uint8_t *buf, size_t n, char *err, size_t errcap) {
    if (!t) { say(err, errcap, "сессии нет"); return -1; }
    while (n > 0) {
        size_t take = n > 16384 ? 16384 : n;
        if (write_record(t, REC_APPDATA, buf, take, err, errcap) != 0) { return -1; }
        buf += take;
        n -= take;
    }
    return 0;
}

long d2k_tls_read(d2k_tls *t, uint8_t *buf, size_t cap, int wait_ms,
                  char *err, size_t errcap) {
    if (!t) { say(err, errcap, "сессии нет"); return -1; }
    if (t->plain_off < t->plain_len) {
        size_t take = t->plain_len - t->plain_off;
        if (take > cap) { take = cap; }
        memcpy(buf, t->plain + t->plain_off, take);
        t->plain_off += take;
        return (long)take;
    }
    int64_t deadline = now_ms() + (wait_ms > 0 ? wait_ms : 8000);
    for (;;) {
        uint8_t type = 0;
        size_t len = 0;
        if (read_record(t, 1, &type, t->plain, sizeof t->plain, &len,
                        deadline, err, errcap) != 0) {
            return -1;
        }
        if (type == REC_CCS) { continue; }
        if (type == REC_ALERT) {
            /* close_notify (уровень 1, описание 0) — законный конец потока, а
               не отказ: сервер сказал «я всё». Остальные тревоги — отказ. */
            if (len >= 2 && t->plain[1] == 0) { return 0; }
            say(err, errcap, "тревога %u", len >= 2 ? (unsigned)t->plain[1] : 0u);
            return -1;
        }
        if (type == REC_HANDSHAKE) {
            continue; /* билеты возобновления — нам не нужны, пропускаем */
        }
        if (type != REC_APPDATA) { continue; }
        t->plain_len = len;
        t->plain_off = 0;
        if (len == 0) { continue; }
        size_t take = len > cap ? cap : len;
        memcpy(buf, t->plain, take);
        t->plain_off = take;
        return (long)take;
    }
}

void d2k_tls_free(d2k_tls *t) { free(t); }
