/* tls12.c — минимальный клиент TLS 1.2. См. d2k_tls12.h: зачем он есть и чего
 * он намеренно не делает.
 *
 * РАСПИСАНИЕ КЛЮЧЕЙ (RFC 5246 §6.3, §8.1; RFC 5288 для AEAD) целиком:
 *
 *   pre_master  = ECDHE(наш секрет, открытый ключ сервера из SKE)
 *   master      = PRF(pre_master, "master secret", cr + sr, 48)
 *   key_block   = PRF(master, "key expansion", sr + cr, 2*key_len + 2*iv_len)
 *                 = c_key | s_key | c_iv | s_iv
 *   verify_data = PRF(master, "client finished", Hash(транскрипт), 12)
 *
 * AES128-GCM: P_SHA256, ключи 16, IV 4; AES256-GCM: P_SHA384, ключи 32,
 * IV 4; ChaCha20-Poly1305 (RFC 7905): P_SHA256, ключи 32, IV 12.
 * Порядок cr+sr для master и sr+cr для key_block различается по RFC.
 * Если форма предложила EMS и сервер принял, master выводится с меткой
 * "extended master secret" по хэшу транскрипта до CKE включительно (RFC 7627).
 *
 * ЗАПИСЬ AEAD: GCM передаёт явный nonce (8 байт), затем шифротекст и тег;
 * nonce = IV[4] || явная часть (RFC 5288). ChaCha не передаёт явную часть:
 * nonce = IV[12] XOR (00000000 || seq[8]). AAD у обоих — seq, тип, версия,
 * длина ОТКРЫТОГО текста (RFC 5246 §6.2.3.3).
 *
 * ТРАНСКРИПТ — сообщения рукопожатия без заголовков записей и без CCS, в том
 * порядке, в каком они были на проводе. ClientHello кладётся в него ПОСЛЕ
 * подмены client_random: иначе наш Finished считался бы по байтам, которых
 * сервер не видел.
 */
/* Файл включают и как текст в составные тесты — после системных заголовков,
   где glibc (с 2026) уже задал _POSIX_C_SOURCE сам: голый #define там —
   переопределение под -Werror (CI 22.10.2026). Отдельной единицей трансляции
   значение задаётся как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_crypto.h"
#include "d2k_p256.h"
#include "d2k_suite.h"
#include "d2k_tls12.h"
#include "d2k_tls13core.h"

#define REC_CCS       20
#define REC_ALERT     21
#define REC_HANDSHAKE 22
#define REC_APPDATA   23

#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2
#define HS_NEW_TICKET   4
#define HS_CERTIFICATE 11
#define HS_SKE         12
#define HS_CERT_REQ    13
#define HS_DONE        14
#define HS_CKE         16
#define HS_FINISHED    20

/* ПСЕВДОТИП «пришла смена шифра».
 *
 * Тип ЗАПИСИ у ChangeCipherSpec — 20, и тип СООБЩЕНИЯ у Finished — тоже 20.
 * Это разные пространства имён, и пока их возвращали одним полем, проверка
 * «это CCS?» съедала Finished: рукопожатие висело до таймаута, а выглядело
 * как молчание сервера. Поэтому CCS выдаётся значением, которого среди типов
 * сообщений рукопожатия нет и быть не может. */
#define HS_PSEUDO_CCS 0xfe

#define REC_MAX 18432
/* Транскрипт держит рукопожатие целиком. Цепочка сертификатов — самая
   длинная его часть; четыре записи предела хватает с запасом, и это тот же
   размер и та же причина, что у клиента 1.3. */
#define TR_MAX (REC_MAX * 4)

/* Нормативные коды TLS 1.2, не параметры воздействия на коробку. */
#define CS_ECDHE_RSA_AES128_GCM_SHA256   0xc02f
#define CS_ECDHE_ECDSA_AES128_GCM_SHA256 0xc02b
#define GROUP_X25519 0x001d

struct d2k_tls12 {
    int      fd;
    d2k_tls_io io;
    int have_io;
    uint64_t rx_wire_bytes;
    uint32_t rx_record_missing;
    d2k_suite suite;       /* hash/HMAC/AEAD family from suite.c */
    size_t   iv_len;       /* GCM: 4; ChaCha20-Poly1305: 12 */
    int      extended_master_secret;
    uint8_t  c_key[D2K_AEAD_KEY_MAX], s_key[D2K_AEAD_KEY_MAX];
    uint8_t  c_salt[12], s_salt[12];
    uint64_t c_seq, s_seq;
    uint8_t  master[48];
    uint8_t  c_random[32], s_random[32];
    uint8_t  transcript[TR_MAX];
    size_t   tr_len;
    int      peer_name;
    char     alpn[32];     /* протокол, выбранный сервером в ServerHello (RFC 7301) */
    uint8_t  raw[REC_MAX], wire[REC_MAX + 5];
    uint8_t  plain[REC_MAX];
    size_t   plain_len, plain_off;
};

/* TLS 1.2 IDs select the same primitives as TLS 1.3, but NOT its
 * record framing or key schedule (RFC 5289 / RFC 7905). */
static int suite12_of(uint16_t id, d2k_tls12 *t) {
    uint16_t primitive;
    switch (id) {
    case 0xc02b: case 0xc02f: primitive = 0x1301; break;
    case 0xc02c: case 0xc030: primitive = 0x1302; break;
    case 0xcca9: case 0xcca8: primitive = 0x1303; break;
    default: return -1;
    }
    if (d2k_suite_of(primitive, &t->suite) != 0) return -1;
    t->iv_len = primitive == 0x1303 ? 12 : 4;
    return 0;
}

static size_t explicit_nonce_len(const d2k_tls12 *t) {
    return t->suite.id == 0x1303 ? 0 : 8;
}

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

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }

static int read_exact(d2k_tls12 *t, uint8_t *buf, size_t n, int body, int64_t deadline,
                      char *err, size_t errcap) {
    size_t got = 0;
    t->rx_record_missing = body ? (uint32_t)n : 0;
    while (got < n) {
        int64_t left = deadline - now_ms();
        if (left <= 0) {
            say(err, errcap, "не дождались %zu байт за отведённое время", n - got);
            return -1;
        }
        if(t->have_io) {
            long r=t->io.read(t->io.context,buf+got,n-got,
                (int)(left>INT_MAX?INT_MAX:left),err,errcap);
            if(r<=0 || (size_t)r>n-got) {
                if(!r)say(err,errcap,"measurement stream closed during TLS 1.2 record");
                else if(r>0)say(err,errcap,"measurement stream exceeded read capacity");
                return -1;
            }
            got+=(size_t)r;t->rx_wire_bytes+=(uint64_t)r;
            if(body)t->rx_record_missing=(uint32_t)(n-got);
            continue;
        }
        struct pollfd p;
        p.fd = t->fd; p.events = POLLIN; p.revents = 0;
        int pr = poll(&p, 1, (int)(left > 1000 ? 1000 : left));
        if (pr < 0) {
            if (errno == EINTR) { continue; }
            say(err, errcap, "poll: %s", strerror(errno));
            return -1;
        }
        if (pr == 0) { continue; }
        ssize_t r = recv(t->fd, buf + got, n - got, 0);
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
        t->rx_wire_bytes += (uint64_t)r;
        if(body)t->rx_record_missing=(uint32_t)(n-got);
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
static int write_transport(d2k_tls12 *t,const uint8_t *buf,size_t n,char *err,size_t errcap) {
    return t->have_io?t->io.write(t->io.context,buf,n,err,errcap):write_all(t->fd,buf,n,err,errcap);
}

/* P_SHA256 / P_SHA384 (RFC 5246 §5). Разворачивается до нужной длины: байты
   последнего блока отбрасываются, как того и требует определение. */
/* Предел «метка плюс затравка». Самая длинная пара у нас — "key expansion"
   (13 байт) с двумя случайными числами по 32; сорок байт запаса хватает с
   избытком, а МОЛЧА обрезать здесь нельзя: получились бы верные с виду ключи,
   не совпадающие с серверными, и проявилось бы это «меткой, которая не
   сошлась». Первая редакция держала буфер в 96 байт при 77 нужных и падала на
   первом же рукопожатии (поймано ASan, а не сервером). */
#define PRF_LS_MAX 128

static void prf(const d2k_suite *s, const uint8_t *secret, size_t slen, const char *label,
                const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len) {
    uint8_t a[D2K_HASH_MAX];
    uint8_t buf[D2K_HASH_MAX + PRF_LS_MAX];
    size_t hlen = s->hash_len;
    size_t llen = strlen(label);
    size_t done = 0;
    /* A(1) = HMAC(secret, label + seed) */
    uint8_t ls[PRF_LS_MAX];
    size_t ls_len = llen + seed_len;
    if (ls_len > sizeof ls) {
        /* Недостижимо при нынешних вызовах, и именно поэтому проверка здесь:
           молча испортить ключи дороже, чем выдать нули и упасть на сверке. */
        memset(out, 0, out_len);
        return;
    }
    memcpy(ls, label, llen);
    memcpy(ls + llen, seed, seed_len);
    d2k_suite_hmac(s, secret, slen, ls, ls_len, a);
    while (done < out_len) {
        uint8_t block[D2K_HASH_MAX];
        size_t n = out_len - done;
        memcpy(buf, a, hlen);
        memcpy(buf + hlen, ls, ls_len);
        d2k_suite_hmac(s, secret, slen, buf, hlen + ls_len, block);
        if (n > hlen) { n = hlen; }
        memcpy(out + done, block, n);
        done += n;
        d2k_suite_hmac(s, secret, slen, a, hlen, a);
    }
}

void d2k_tls12_prf_for_test(const uint8_t *secret, size_t slen, const char *label,
                            const uint8_t *seed, size_t seed_len,
                            uint8_t *out, size_t out_len) {
    d2k_suite s;
    d2k_suite_of(0x1301, &s);
    prf(&s, secret, slen, label, seed, seed_len, out, out_len);
}

/* RFC 5246 / RFC 7627. For EMS the transcript must include CKE. */
static void derive_keys(d2k_tls12 *t, const uint8_t shared[32]) {
    uint8_t seed[64];
    if (t->extended_master_secret) {
        d2k_suite_hash(&t->suite, t->transcript, t->tr_len, seed);
        prf(&t->suite, shared, 32, "extended master secret", seed,
            t->suite.hash_len, t->master, 48);
    } else {
        memcpy(seed, t->c_random, 32);
        memcpy(seed + 32, t->s_random, 32);
        prf(&t->suite, shared, 32, "master secret", seed, 64, t->master, 48);
    }
    /* Server random FIRST for key expansion (RFC 5246 section 6.3). */
    memcpy(seed, t->s_random, 32);
    memcpy(seed + 32, t->c_random, 32);
    uint8_t kb[2 * D2K_AEAD_KEY_MAX + 2 * 12];
    size_t k = t->suite.key_len, iv = t->iv_len;
    prf(&t->suite, t->master, 48, "key expansion", seed, 64, kb, 2 * k + 2 * iv);
    memcpy(t->c_key, kb, k);
    memcpy(t->s_key, kb + k, k);
    memcpy(t->c_salt, kb + 2 * k, iv);
    memcpy(t->s_salt, kb + 2 * k + iv, iv);
}

static void client_finished(const d2k_tls12 *t, uint8_t fin[16]) {
    uint8_t hash[D2K_HASH_MAX];
    d2k_suite_hash(&t->suite, t->transcript, t->tr_len, hash);
    fin[0] = HS_FINISHED; fin[1] = 0; fin[2] = 0; fin[3] = 12;
    prf(&t->suite, t->master, 48, "client finished", hash, t->suite.hash_len, fin + 4, 12);
}

static void tr_add(d2k_tls12 *t, const uint8_t *msg, size_t n) {
    if (t->tr_len + n <= sizeof t->transcript) {
        memcpy(t->transcript + t->tr_len, msg, n);
        t->tr_len += n;
    }
}

/* Полный одноразовый номер: соль из key_block плюс явная часть записи. */
static void nonce_of(const uint8_t salt[4], uint64_t seq, uint8_t out[12]) {
    memcpy(out, salt, 4);
    for (int i = 0; i < 8; i++) {
        out[11 - i] = (uint8_t)(seq >> (8 * i));
    }
}

/* RFC 7905: IV XOR (four zero bytes || big-endian record sequence).
 * GCM instead concatenates a four-byte salt with an explicit nonce. */
static void record_nonce(const d2k_tls12 *t, const uint8_t *iv, uint64_t seq,
                         uint8_t out[12]) {
    if (explicit_nonce_len(t)) { nonce_of(iv, seq, out); return; }
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++) out[11 - i] ^= (uint8_t)(seq >> (8 * i));
}

static void aad_of(uint64_t seq, uint8_t type, size_t plen, uint8_t out[13]) {
    for (int i = 0; i < 8; i++) {
        out[7 - i] = (uint8_t)(seq >> (8 * i));
    }
    out[8] = type;
    out[9] = 3; out[10] = 3;
    put16(out + 11, (uint16_t)plen);
}

/* --- запись наружу -------------------------------------------------------- */

static int send_plain(d2k_tls12 *t, uint8_t type, const uint8_t *body, size_t n,
                      char *err, size_t errcap) {
    if (n + 5 > sizeof t->wire) {
        say(err, errcap, "запись длиной %zu не помещается", n);
        return -1;
    }
    t->wire[0] = type; t->wire[1] = 3; t->wire[2] = 3;
    put16(t->wire + 3, (uint16_t)n);
    memcpy(t->wire + 5, body, n);
    return write_transport(t, t->wire, n + 5, err, errcap);
}

static int send_sealed(d2k_tls12 *t, uint8_t type, const uint8_t *body, size_t n,
                       char *err, size_t errcap) {
    uint8_t nonce[12], aad[13];
    size_t explicit_len = explicit_nonce_len(t);
    if (n > sizeof t->wire - 5 - explicit_len - 16) {
        say(err, errcap, "запись длиной %zu не помещается", n);
        return -1;
    }
    record_nonce(t, t->c_salt, t->c_seq, nonce);
    aad_of(t->c_seq, type, n, aad);
    if (explicit_len) memcpy(t->wire + 5, nonce + 4, explicit_len);
    if (d2k_suite_seal(&t->suite, t->c_key, nonce, aad, sizeof aad, body, n,
                        t->wire + 5 + explicit_len) != 0) {
        say(err, errcap, "не зашифровалась запись");
        return -1;
    }
    t->wire[0] = type; t->wire[1] = 3; t->wire[2] = 3;
    put16(t->wire + 3, (uint16_t)(explicit_len + n + 16));
    t->c_seq++;
    return write_transport(t, t->wire, 5 + explicit_len + n + 16, err, errcap);
}

/* --- чтение --------------------------------------------------------------- */

/* Читает ОДНУ запись. encrypted — снимать ли защиту. */
static int read_record(d2k_tls12 *t, int encrypted, uint8_t *type,
                       uint8_t *payload, size_t cap, size_t *len,
                       int64_t deadline, char *err, size_t errcap) {
    uint8_t hdr[5];
    if (read_exact(t, hdr, 5, 0, deadline, err, errcap) != 0) { return -1; }
    /* На TLS/443 сетевой узел иногда отвечает открытым HTTP (на Rutracker
       Cloudflare прислал HTTP/1.1 400). P/ из HTTP/ — не TLS length=20527. */
    if (memcmp(hdr, "HTTP/", 5) == 0) {
        say(err, errcap,
            "не TLS: открытый HTTP-ответ вместо TLS (заголовок %02x %02x %02x %02x %02x)",
            hdr[0], hdr[1], hdr[2], hdr[3], hdr[4]);
        return -1;
    }
    size_t rlen = get16(hdr + 3);
    if (rlen == 0 || rlen > REC_MAX) {
        say(err, errcap,
            "не TLS-заголовок %02x %02x %02x %02x %02x: длина %zu вне предела",
            hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], rlen);
        return -1;
    }
    if (read_exact(t, t->raw, rlen, 1, deadline, err, errcap) != 0) { return -1; }
    *type = hdr[0];

    /* CCS не шифруется никогда и содержимого не несёт. */
    if (hdr[0] == REC_CCS) { *len = 0; return 0; }

    if (!encrypted) {
        if (rlen > cap) {
            say(err, errcap, "запись длиной %zu не помещается в буфер", rlen);
            return -1;
        }
        memcpy(payload, t->raw, rlen);
        *len = rlen;
        return 0;
    }
    size_t explicit_len = explicit_nonce_len(t);
    if (rlen < explicit_len + 16) {
        say(err, errcap, "зашифрованная запись короче служебных полей");
        return -1;
    }
    {
        uint8_t nonce[12], aad[13];
        size_t body = rlen - explicit_len;
        if (body < 16 || body - 16 > cap) {
            say(err, errcap, "запись длиной %zu не помещается в буфер", body);
            return -1;
        }
        if (explicit_len) {
            memcpy(nonce, t->s_salt, 4);
            memcpy(nonce + 4, t->raw, explicit_len);
        } else record_nonce(t, t->s_salt, t->s_seq, nonce);
        aad_of(t->s_seq, hdr[0], body - 16, aad);
        if (d2k_suite_open(&t->suite, t->s_key, nonce, aad, sizeof aad,
                            t->raw + explicit_len, body, payload) != 0) {
            say(err, errcap, "запись не расшифровалась (метка не сошлась)");
            return -1;
        }
        t->s_seq++;
        *len = body - 16;
    }
    return 0;
}

/* Следующее сообщение рукопожатия из потока записей. Записи могут нести
   несколько сообщений и одно сообщение может быть разрезано между записями —
   поэтому склейка, а не «одна запись = одно сообщение». */
typedef struct {
    uint8_t  buf[TR_MAX];
    size_t   len, off;
} hs_stream;

static int hs_next(d2k_tls12 *t, hs_stream *hs, int encrypted, uint8_t *type,
                   const uint8_t **msg, size_t *msg_len,
                   int64_t deadline, char *err, size_t errcap) {
    for (;;) {
        if (hs->len - hs->off >= 4) {
            const uint8_t *p = hs->buf + hs->off;
            size_t body = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
            if (hs->len - hs->off >= 4 + body) {
                *type = p[0];
                *msg = p;
                *msg_len = 4 + body;
                hs->off += 4 + body;
                return 0;
            }
        }
        {
            uint8_t rtype;
            size_t rlen = 0;
            uint8_t rec[REC_MAX];
            if (read_record(t, encrypted, &rtype, rec, sizeof rec, &rlen,
                            deadline, err, errcap) != 0) {
                return -1;
            }
            if (rtype == REC_ALERT) {
                say(err, errcap, "сервер прислал тревогу %u уровня %u",
                    rlen >= 2 ? rec[1] : 0, rlen >= 1 ? rec[0] : 0);
                return -1;
            }
            if (rtype == REC_CCS) {
                *type = HS_PSEUDO_CCS;
                *msg = NULL;
                *msg_len = 0;
                return 0;
            }
            if (rtype != REC_HANDSHAKE) {
                say(err, errcap, "запись типа %u посреди рукопожатия", rtype);
                return -1;
            }
            /* Уплотняем: разобранное больше не нужно. */
            if (hs->off > 0) {
                memmove(hs->buf, hs->buf + hs->off, hs->len - hs->off);
                hs->len -= hs->off;
                hs->off = 0;
            }
            if (hs->len + rlen > sizeof hs->buf) {
                say(err, errcap, "рукопожатие длиннее предела");
                return -1;
            }
            memcpy(hs->buf + hs->len, rec, rlen);
            hs->len += rlen;
        }
    }
}

/* Собирает ClientHello старой формы: без supported_versions (по нему
   d2k_hello_shape и отличает старое приветствие от современного), с теми
   шестью AEAD-шифрнаборами и группами X25519/P-256. Добивается до want_wire
   расширением padding (RFC 7685) — та же надобность, что у клиента 1.3:
   план, чьи куски помещаются в посылку на коротком приветствии, на длинном
   не помещается вовсе. */
static size_t ch12_build(const char *sni, const uint8_t random[32],
                         size_t want_wire, uint8_t *out, size_t cap) {
    size_t sni_len = sni && sni[0] ? strlen(sni) : 0;
    if (cap < 512 + sni_len) { return 0; }
    uint8_t *p = out + 5 + 4;          /* заголовок записи и рукопожатия — позже */
    uint8_t *body = p;
    *p++ = 3; *p++ = 3;                /* client_version = TLS 1.2 */
    memcpy(p, random, 32); p += 32;
    *p++ = 0;                          /* session_id пуст */
    put16(p, 12); p += 2;
    put16(p, CS_ECDHE_ECDSA_AES128_GCM_SHA256); p += 2;
    put16(p, CS_ECDHE_RSA_AES128_GCM_SHA256); p += 2;
    put16(p, 0xc02c); p += 2;
    put16(p, 0xc030); p += 2;
    put16(p, 0xcca9); p += 2;
    put16(p, 0xcca8); p += 2;
    *p++ = 1; *p++ = 0;                /* compression: null */

    uint8_t *ext_len_at = p; p += 2;
    uint8_t *ext = p;
    if (sni_len > 0 && sni_len < 256) {
        put16(p, 0); p += 2;                       /* server_name */
        put16(p, (uint16_t)(sni_len + 5)); p += 2;
        put16(p, (uint16_t)(sni_len + 3)); p += 2;
        *p++ = 0;
        put16(p, (uint16_t)sni_len); p += 2;
        memcpy(p, sni, sni_len); p += sni_len;
    }
    /* ГРУППЫ: X25519 и secp256r1 — обмен на обеих реализован.
       В TLS 1.2 список групп ограничивает ещё и
       КРИВУЮ СЕРТИФИКАТА (RFC 4492 §5.1): сервер с сертификатом на P-256,
       не увидев её в списке, отвечает handshake_failure — проверено на
       openssl s_server, тревога 40 на приветствии с одним лишь X25519.
       Обмен на secp256r1 зонд тоже умеет (d2k_p256.h, поле 07.10.2026). */
    put16(p, 10); p += 2;                          /* supported_groups */
    put16(p, 8); p += 2;
    put16(p, 6); p += 2;
    put16(p, GROUP_X25519); p += 2;
    put16(p, 0x0017); p += 2;   /* secp256r1 — обмен и сертификаты */
    put16(p, 0x0018); p += 2;   /* secp384r1 — та же причина */
    put16(p, 11); p += 2;                          /* ec_point_formats */
    put16(p, 2); p += 2;
    *p++ = 1; *p++ = 0;                            /* uncompressed */
    put16(p, 13); p += 2;                          /* signature_algorithms */
    put16(p, 10); p += 2;
    put16(p, 8); p += 2;
    put16(p, 0x0403); p += 2;   /* ecdsa_secp256r1_sha256 */
    put16(p, 0x0804); p += 2;   /* rsa_pss_rsae_sha256 */
    put16(p, 0x0401); p += 2;   /* rsa_pkcs1_sha256 */
    put16(p, 0x0203); p += 2;   /* ecdsa_sha1 — старые серверы без него молчат */

    /* Набивка до нужной проводной длины. Считаем ПОЛНУЮ длину записи. */
    if (want_wire > 0) {
        size_t now = 5 + 4 + (size_t)(p - body) + 2;
        if (want_wire > now + 4 && want_wire - now - 4 < 65535) {
            size_t pad = want_wire - now - 4;
            if ((size_t)(p - out) + 4 + pad + 16 <= cap) {
                put16(p, 21); p += 2;
                put16(p, (uint16_t)pad); p += 2;
                memset(p, 0, pad); p += pad;
            }
        }
    }
    put16(ext_len_at, (uint16_t)(p - ext));

    size_t body_len = (size_t)(p - body);
    out[0] = REC_HANDSHAKE; out[1] = 3; out[2] = 3;
    put16(out + 3, (uint16_t)(4 + body_len));
    out[5] = HS_CLIENT_HELLO;
    out[6] = (uint8_t)(body_len >> 16);
    out[7] = (uint8_t)(body_len >> 8);
    out[8] = (uint8_t)body_len;
    return 5 + 4 + body_len;
}

void (*d2k_tls12_test_barrier)(void);

static int tls12_finish(d2k_tls12 *t, const char *sni, int64_t deadline,
                        hs_stream *hs_in, d2k_tls12 **out, char *err, size_t errcap);

size_t d2k_tls12_probe_hello(const uint8_t random[32],const char *sni,size_t want_wire,
    uint8_t *out,size_t cap) {
    if(!random || !sni || !out)return 0;
    return ch12_build(sni,random,want_wire,out,cap);
}
static int connect_transport(int fd,const d2k_tls_io *io,const uint8_t random[32],
    const char *sni,int deadline_ms,size_t want_wire,d2k_tls12 **out,char *err,size_t errcap) {
    if (!out) { say(err, errcap, "некуда положить сессию"); return -1; }
    *out=NULL;
    if(!sni || (io && (!io->read || !io->write || !random))) {
        say(err,errcap,"invalid TLS 1.2 measurement transport");return -1;
    }
    d2k_tls12 *t = calloc(1, sizeof *t);
    if (!t) { say(err, errcap, "нет памяти"); return -1; }
    t->fd = fd;
    if(io){t->io=*io;t->have_io=1;}
    t->peer_name = -1;
    int64_t deadline = now_ms() + (deadline_ms > 0 ? deadline_ms : 5000);

    /* Буфер приветствия — в структуре соединения, не static: connect идёт
       из нескольких рабочих потоков, общий буфер смешал бы чужие SNI. */
    uint8_t *ch = t->wire;
    if(random)memcpy(t->c_random,random,32);
    else if (d2k_t13_random(t->c_random, 32) != 0) {
        say(err, errcap, "нет случайных байт");
        free(t);
        return -1;
    }
    size_t hello_len = ch12_build(sni, t->c_random, want_wire, ch, sizeof t->wire);
    if (hello_len == 0) {
        say(err, errcap, "приветствие не собралось");
        free(t);
        return -1;
    }
    if (d2k_tls12_test_barrier) { d2k_tls12_test_barrier(); }
    if (write_transport(t, ch, hello_len, err, errcap) != 0) { free(t); return -1; }
    tr_add(t, ch + 5, hello_len - 5);
    hs_stream hs;
    memset(&hs, 0, sizeof hs);
    return tls12_finish(t, sni, deadline, &hs, out, err, errcap);
}
int d2k_tls12_connect(int fd,const char *sni,int timeout,size_t wire,d2k_tls12 **out,char *err,size_t cap) {
    return connect_transport(fd,NULL,NULL,sni,timeout,wire,out,err,cap);
}
int d2k_tls12_connect_probe(const d2k_tls_io *io,const uint8_t random[32],const char *sni,
    int timeout,size_t wire,d2k_tls12 **out,char *err,size_t cap) {
    if(!io){if(out)*out=NULL;say(err,cap,"missing TLS 1.2 measurement transport");return -1;}
    return connect_transport(-1,io,random,sni,timeout,wire,out,err,cap);
}

/* ПРОДОЛЖЕНИЕ ПОСЛЕ ПРИВЕТСТВИЯ 1.3, НА КОТОРОЕ СЕРВЕР ОТВЕТИЛ 1.2.
 * Поле 07.10.2026 (KN-1811): report.appmetrica.yandex.net, clck.yandex.net,
 * rustore, login.live.com — только TLS 1.2; зонд, предлагавший один 1.3,
 * получал тревогу 70 (protocol_version) 500+ раз за сутки, а настоящий
 * клиент договаривался на 1.2. Приветствие 1.3 зонда предлагает теперь и
 * 1.2 (как браузер); выбрал сервер 1.2 — рукопожатие доводит этот клиент.
 * srv — открытые байты рукопожатия сервера, уже прочитанные клиентом 1.3,
 * начиная с ServerHello (запись может нести и следующие сообщения). */
static int resume_on(int fd, const d2k_tls_io *io, const char *sni, int deadline_ms,
                     const uint8_t c_random[32], const uint8_t *ch_msg, size_t ch_len,
                     const uint8_t *srv, size_t srv_len,
                     d2k_tls12 **out, char *err, size_t errcap) {
    if (!out || !c_random || !ch_msg || !srv) { say(err, errcap, "нечем продолжать"); return -1; }
    if (io && (!io->read || !io->write)) { say(err, errcap, "invalid TLS 1.2 transport"); return -1; }
    d2k_tls12 *t = calloc(1, sizeof *t);
    if (!t) { say(err, errcap, "нет памяти"); return -1; }
    t->fd = fd;
    if (io) { t->io = *io; t->have_io = 1; }
    t->peer_name = -1;
    memcpy(t->c_random, c_random, 32);
    if (ch_len > TR_MAX || srv_len > TR_MAX) { say(err, errcap, "рукопожатие длиннее предела"); free(t); return -1; }
    tr_add(t, ch_msg, ch_len);
    int64_t deadline = now_ms() + (deadline_ms > 0 ? deadline_ms : 5000);
    hs_stream hs;
    memset(&hs, 0, sizeof hs);
    memcpy(hs.buf, srv, srv_len);
    hs.len = srv_len;
    return tls12_finish(t, sni, deadline, &hs, out, err, errcap);
}

int d2k_tls12_resume(int fd, const char *sni, int deadline_ms,
                     const uint8_t c_random[32], const uint8_t *ch_msg, size_t ch_len,
                     const uint8_t *srv, size_t srv_len,
                     d2k_tls12 **out, char *err, size_t errcap) {
    return resume_on(fd, NULL, sni, deadline_ms, c_random, ch_msg, ch_len, srv, srv_len,
                     out, err, errcap);
}

/* То же через транспорт исполнителя плеча (свой разрез потока): форма клиента,
   на которую сервер ответил TLS 1.2 (поле 11.11, flibusta.is). */
int d2k_tls12_resume_io(const d2k_tls_io *io, const char *sni, int deadline_ms,
                        const uint8_t c_random[32], const uint8_t *ch_msg, size_t ch_len,
                        const uint8_t *srv, size_t srv_len,
                        d2k_tls12 **out, char *err, size_t errcap) {
    if (!io) { say(err, errcap, "нет транспорта"); return -1; }
    return resume_on(-1, io, sni, deadline_ms, c_random, ch_msg, ch_len, srv, srv_len,
                     out, err, errcap);
}

/* Флайт сервера и всё до Finished. hs — поток сообщений (может быть уже
 * наполнен прочитанным); t — с транскриптом до ServerHello включительно не
 * считая, его добавит разбор. Владеет t: при отказе освобождает. */
static int tls12_finish(d2k_tls12 *t, const char *sni, int64_t deadline,
                        hs_stream *hs_in, d2k_tls12 **out, char *err, size_t errcap) {
    uint8_t peer_pub[65];
    uint16_t group = 0;
    int have_peer = 0, have_done = 0;
    uint16_t suite = 0;
    for (;;) {
        uint8_t type;
        const uint8_t *msg;
        size_t mlen;
        if (hs_next(t, hs_in, 0, &type, &msg, &mlen, deadline, err, errcap) != 0) {
            free(t);
            return -1;
        }
        if (type == HS_PSEUDO_CCS) {
            say(err, errcap, "смена шифра раньше ServerHelloDone");
            free(t);
            return -1;
        }
        tr_add(t, msg, mlen);
        const uint8_t *b = msg + 4;
        size_t n = mlen - 4;
        if (type == HS_SERVER_HELLO) {
            if (n < 2 + 32 + 1) { say(err, errcap, "ServerHello обрезан"); free(t); return -1; }
            memcpy(t->s_random, b + 2, 32);
            size_t i = 2 + 32;
            i += 1 + b[i];
            if (i + 2 > n) { say(err, errcap, "ServerHello обрезан на шифре"); free(t); return -1; }
            suite = get16(b + i);
            if (suite12_of(suite, t) != 0) {
                say(err, errcap, "сервер выбрал шифрнабор 0x%04x — зонд умеет "
                    "ECDHE+AES128-GCM-SHA256, AES256-GCM-SHA384 и CHACHA20-POLY1305-SHA256",
                    (unsigned)suite);
                free(t);
                return -1;
            }
            i += 3;
            if (i < n) {
                if (n - i < 2 || get16(b + i) != n - i - 2) {
                    say(err, errcap, "ServerHello обрезан на расширениях"); free(t); return -1;
                }
                i += 2;
                while (i < n) {
                    if (n - i < 4 || get16(b + i + 2) > n - i - 4) {
                        say(err, errcap, "ServerHello: расширение обрезано"); free(t); return -1;
                    }
                    size_t el = get16(b + i + 2);
                    if (get16(b + i) == 23) {
                        if (el != 0) {
                            say(err, errcap, "ServerHello: extended_master_secret не пуст"); free(t); return -1;
                        }
                        t->extended_master_secret = 1;
                    }
                    /* ALPN (RFC 7301 §3.1): сервер выбирает ровно один
                       протокол. Без него прикладной уровень не знает, h2 это
                       или HTTP/1.1 (поле 11.11, flibusta.is: h2 по TLS 1.2). */
                    if (get16(b + i) == 16) {
                        const uint8_t *e = b + i + 4;
                        if (el < 3 || get16(e) != el - 2 || e[2] != el - 3 || e[2] == 0) {
                            say(err, errcap, "ServerHello: ALPN не по грамматике"); free(t); return -1;
                        }
                        size_t pl = e[2] < sizeof t->alpn ? e[2] : sizeof t->alpn - 1;
                        memcpy(t->alpn, e + 3, pl);
                        t->alpn[pl] = 0;
                    }
                    i += 4 + el;
                }
            }
        } else if (type == HS_CERTIFICATE) {
            if (sni && sni[0]) {
                t->peer_name = d2k_t13_cert_name_ok12(b, n, sni);
            }
        } else if (type == HS_SKE) {
            if (n < 4) { say(err, errcap, "ServerKeyExchange обрезан"); free(t); return -1; }
            if (b[0] != 3) {
                say(err, errcap, "сервер предложил не именованную кривую (%u)", b[0]);
                free(t);
                return -1;
            }
            /* X25519 и secp256r1. Поле 07.10.2026 (KN-1811): graph.facebook.com
               и api.facebook.com в TLS 1.2 выбирают secp256r1, и зонд умевший
               лишь X25519 отказывал 253 раза за сутки — ни один план этих
               целей не подтверждался (d2k_p256.h). */
            group = get16(b + 1);
            size_t want = group == GROUP_X25519 ? 32 : group == 0x0017 ? 65 : 0;
            if (want == 0) {
                say(err, errcap, "сервер выбрал группу 0x%04x — зонд умеет X25519 и secp256r1",
                    (unsigned)group);
                free(t);
                return -1;
            }
            if (b[3] != want || n < 4 + want) {
                say(err, errcap, "открытый ключ сервера длиной %u вместо %zu", b[3], want);
                free(t);
                return -1;
            }
            memcpy(peer_pub, b + 4, want);
            have_peer = 1;
        } else if (type == HS_CERT_REQ) {
            /* Клиентский сертификат зонду взять негде, а слать пустой значит
               менять форму обмена. Честный отказ. */
            say(err, errcap, "сервер требует клиентский сертификат — зонду его негде взять");
            free(t);
            return -1;
        } else if (type == HS_DONE) {
            have_done = 1;
            break;
        }
    }
    if (!have_peer || !have_done || suite == 0) {
        say(err, errcap, "флайт сервера неполон");
        free(t);
        return -1;
    }

    /* --- наш ключ, секреты --- */
    uint8_t priv[32], pub[65], shared[32];
    size_t pub_len = group == GROUP_X25519 ? 32 : 65;
    if (group == GROUP_X25519) {
        if (d2k_t13_random(priv, 32) != 0) {
            say(err, errcap, "нет случайных байт");
            free(t);
            return -1;
        }
        if (d2k_x25519_base(pub, priv) != 0 || d2k_x25519(shared, priv, peer_pub) != 0) {
            say(err, errcap, "X25519 не сошёлся");
            free(t);
            return -1;
        }
    } else if (d2k_p256_keypair(priv, pub) != 0 || d2k_p256_ecdh(priv, peer_pub, shared) != 0) {
        /* Точка сервера не на кривой — тоже сюда: это утверждение о сервере,
           не о коробке, и в каталог по нему не идёт ничего. */
        say(err, errcap, "secp256r1 не сошёлся");
        free(t);
        return -1;
    }


    /* --- ClientKeyExchange, CCS, Finished --- */
    {
        uint8_t cke[4 + 1 + 65];
        size_t cke_len = 4 + 1 + pub_len;
        cke[0] = HS_CKE;
        cke[1] = 0; cke[2] = 0; cke[3] = (uint8_t)(1 + pub_len);
        cke[4] = (uint8_t)pub_len;
        memcpy(cke + 5, pub, pub_len);
        if (send_plain(t, REC_HANDSHAKE, cke, cke_len, err, errcap) != 0) {
            free(t);
            return -1;
        }
        tr_add(t, cke, cke_len);
    }
    derive_keys(t, shared);
    {
        uint8_t ccs = 1;
        if (send_plain(t, REC_CCS, &ccs, 1, err, errcap) != 0) { free(t); return -1; }
    }
    {
        uint8_t fin[4 + 12];
        client_finished(t, fin);
        if (send_sealed(t, REC_HANDSHAKE, fin, sizeof fin, err, errcap) != 0) {
            free(t);
            return -1;
        }
        tr_add(t, fin, sizeof fin);
    }

    /* --- флайт сервера: билет (необязателен), CCS, Finished --- */
    {
        hs_stream shs;
        memset(&shs, 0, sizeof shs);
        int seen_ccs = 0;
        for (;;) {
            uint8_t type;
            const uint8_t *msg;
            size_t mlen;
            if (hs_next(t, &shs, seen_ccs, &type, &msg, &mlen, deadline, err, errcap) != 0) {
                free(t);
                return -1;
            }
            if (type == HS_PSEUDO_CCS) {
                seen_ccs = 1;
                /* Записи после CCS идут под новыми ключами, и остаток
                   открытого потока к ним не относится. */
                memset(&shs, 0, sizeof shs);
                continue;
            }
            if (type == HS_NEW_TICKET) { continue; }
            if (type == HS_FINISHED) {
                /* РАСШИФРОВАЛОСЬ — И ЭТО И ЕСТЬ ДОКАЗАТЕЛЬСТВО.
                   Метка AEAD сошлась на ключах, выведенных из общего секрета,
                   значит рукопожатие завершено обеими сторонами. Сверять
                   verify_data сверх этого нечем: подпись сервера мы не
                   проверяем по построению (см. шапку). */
                if (mlen != 4 + 12) {
                    say(err, errcap, "Finished сервера длиной %zu вместо 16", mlen);
                    free(t);
                    return -1;
                }
                break;
            }
        }
    }

    *out = t;
    return 0;
}

int d2k_tls12_write(d2k_tls12 *t, const uint8_t *buf, size_t n,
                    char *err, size_t errcap) {
    if (!t) { say(err, errcap, "сессии нет"); return -1; }
    return send_sealed(t, REC_APPDATA, buf, n, err, errcap);
}

long d2k_tls12_read(d2k_tls12 *t, uint8_t *buf, size_t cap, int wait_ms,
                    char *err, size_t errcap) {
    if (!t) { say(err, errcap, "сессии нет"); return -1; }
    if (t->plain_off < t->plain_len) {
        size_t n = t->plain_len - t->plain_off;
        if (n > cap) { n = cap; }
        memcpy(buf, t->plain + t->plain_off, n);
        t->plain_off += n;
        return (long)n;
    }
    int64_t deadline = now_ms() + (wait_ms > 0 ? wait_ms : 1000);
    for (;;) {
        uint8_t type;
        size_t len = 0;
        if (read_record(t, 1, &type, t->plain, sizeof t->plain, &len,
                        deadline, err, errcap) != 0) {
            return -1;
        }
        if (type == REC_ALERT) {
            /* Закрытие — это конец потока, а не отказ: сервер вправе закрыть
               сессию после ответа. */
            if (len >= 2 && t->plain[1] == 0) { return 0; }
            say(err, errcap, "тревога %u уровня %u",
                len >= 2 ? t->plain[1] : 0, len >= 1 ? t->plain[0] : 0);
            return -1;
        }
        if (type != REC_APPDATA) { continue; }
        t->plain_len = len;
        t->plain_off = 0;
        {
            size_t n = len;
            if (n > cap) { n = cap; }
            memcpy(buf, t->plain, n);
            t->plain_off = n;
            return (long)n;
        }
    }
}

int d2k_tls12_peer_name(const d2k_tls12 *t) { return t ? t->peer_name : -1; }

const char *d2k_tls12_alpn(const d2k_tls12 *t) { return t ? t->alpn : ""; }

void d2k_tls12_free(d2k_tls12 *t) { free(t); }

uint64_t d2k_tls12_rx_wire_bytes(const d2k_tls12 *t) { return t ? t->rx_wire_bytes : 0; }
uint32_t d2k_tls12_rx_record_missing(const d2k_tls12 *t) { return t ? (t->rx_record_missing) : 0; }
