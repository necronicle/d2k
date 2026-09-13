/* tls13core.c — ядро TLS 1.3 без транспорта. Контракт — в d2k_tls13core.h.
 *
 * Здесь нет ни одного системного вызова, кроме чтения случайности: всё
 * остальное — арифметика над байтами. Это и делает ядро пригодным обоим
 * транспортам сразу.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "d2k_crypto.h"
#include "d2k_tls13core.h"

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }

/* --- случайность --------------------------------------------------------- */

int d2k_t13_random(uint8_t *b, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { return -1; }
    size_t got = fread(b, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

/* --- ИМЯ В СЕРТИФИКАТЕ СЕРВЕРА ------------------------------------------
 *
 * ЧТО ЭТО И ЧЕГО ЭТО НЕ ДЕЛАЕТ. Здесь сверяется имя, которым сервер
 * ПРЕДСТАВИЛСЯ, с именем, которое мы спросили. Это НЕ проверка подлинности:
 * цепочка не строится, доверенных корней у нас нет, и самоподписанный
 * сертификат с правильным именем проверку пройдёт. Уровень доказательства от
 * этого не растёт и расти не может (§4.2: зонд как был на третьем, так и
 * остался) — задача ровно одна, зато важная в поле: не записать в
 * «подтверждено» разговор с ЧУЖИМ сервером.
 *
 * Зачем это нужно именно на цензурируемой линии. Коробка, которая
 * ТЕРМИНИРУЕТ TLS и отдаёт страницу блокировки, даёт зонду ровно ту же
 * картину, что рабочий обход: рукопожатие сошлось, HTTP ответил 200. Без
 * сверки имени такой ответ записывается успехом плана, и каталог наполняется
 * «обходами», которые ведут в страницу блокировки. Различить это дёшево:
 * у своего сертификата коробки в SAN будет не то имя.
 *
 * Ответ трёхзначный, как и всё в этом проекте: 1 — имя совпало, 0 — имя
 * НЕ совпало, -1 — сказать нечего (сертификата не было, SAN не нашлось,
 * разбор не сошёлся). «Не измерено» не превращается в «нет» (§2.4). */

/* Длина DER по месту. 0 — разобрать не вышло; *hdr — сколько байт занял сам
   заголовок длины. Неопределённая длина (0x80) в DER запрещена, и здесь она
   считается ошибкой, а не «до конца». */
static size_t der_len(const uint8_t *p, size_t avail, size_t *hdr) {
    if (avail < 1) { return 0; }
    if (p[0] < 0x80) { *hdr = 1; return p[0]; }
    size_t n = (size_t)(p[0] & 0x7F);
    if (n == 0 || n > 4 || avail < 1 + n) { return 0; }
    size_t v = 0;
    for (size_t i = 0; i < n; i++) { v = (v << 8) | p[1 + i]; }
    *hdr = 1 + n;
    return v;
}

static int ascii_lower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

/* Совпадает ли имя из сертификата с тем, что мы спросили.
 *
 * Подстановочный знак — ТОЛЬКО в первой метке и только целой меткой
 * (RFC 6125 §6.4.3): "*.example.com" покрывает "a.example.com" и не покрывает
 * ни "example.com", ни "a.b.example.com". Частичные вида "w*.example.com" не
 * поддерживаются намеренно: они выведены из обращения и их поддержка
 * расширяла бы совпадение там, где сегодня оно сузилось бы честно. */
static int name_matches(const char *pat, size_t plen, const char *host) {
    size_t hlen = strlen(host);
    if (plen == 0 || hlen == 0) { return 0; }
    if (plen > 2 && pat[0] == '*' && pat[1] == '.') {
        const char *dot = strchr(host, '.');
        if (!dot || dot == host) { return 0; }
        const char *rest = dot + 1;
        size_t rlen = strlen(rest);
        if (rlen != plen - 2) { return 0; }
        for (size_t i = 0; i < rlen; i++) {
            if (ascii_lower((unsigned char)rest[i]) != ascii_lower((unsigned char)pat[2 + i])) {
                return 0;
            }
        }
        return 1;
    }
    if (plen != hlen) { return 0; }
    for (size_t i = 0; i < hlen; i++) {
        if (ascii_lower((unsigned char)host[i]) != ascii_lower((unsigned char)pat[i])) {
            return 0;
        }
    }
    return 1;
}

/* Ищет расширение subjectAltName в DER сертификата и сверяет его dNSName с
   host. OID 2.5.29.17 на проводе — 06 03 55 1D 11.

   Поиск идёт ПО БАЙТАМ, а не полным обходом X.509: полный обход означал бы
   разбор всей структуры сертификата ради одного поля, а совпадение этих пяти
   байт вне расширения возможно только в данных, которые мы всё равно не
   примем за SAN — следом обязаны идти OCTET STRING и SEQUENCE нужной формы,
   иначе разбор честно отвечает «сказать нечего». */
static int cert_name_ok(const uint8_t *der, size_t len, const char *host) {
    static const uint8_t oid[] = { 0x06, 0x03, 0x55, 0x1D, 0x11 };
    for (size_t i = 0; i + sizeof oid <= len; i++) {
        if (memcmp(der + i, oid, sizeof oid) != 0) { continue; }
        size_t q = i + sizeof oid;
        /* Необязательный признак critical. */
        if (q + 3 <= len && der[q] == 0x01 && der[q + 1] == 0x01) { q += 3; }
        if (q >= len || der[q] != 0x04) { continue; }     /* OCTET STRING */
        size_t hdr = 0;
        size_t olen = der_len(der + q + 1, len - q - 1, &hdr);
        if (olen == 0 || q + 1 + hdr + olen > len) { continue; }
        const uint8_t *gn = der + q + 1 + hdr;
        size_t gnlen = olen;
        if (gnlen < 2 || gn[0] != 0x30) { continue; }     /* GeneralNames */
        size_t shdr = 0;
        size_t slen = der_len(gn + 1, gnlen - 1, &shdr);
        if (slen == 0 || 1 + shdr + slen > gnlen) { continue; }
        const uint8_t *e = gn + 1 + shdr;
        size_t left = slen;
        int saw_dns = 0;
        while (left >= 2) {
            uint8_t tag = e[0];
            size_t ehdr = 0;
            size_t elen = der_len(e + 1, left - 1, &ehdr);
            if (1 + ehdr + elen > left) { break; }
            if (tag == 0x82) {                            /* dNSName */
                saw_dns = 1;
                if (name_matches((const char *)(e + 1 + ehdr), elen, host)) { return 1; }
            }
            e += 1 + ehdr + elen;
            left -= 1 + ehdr + elen;
        }
        return saw_dns ? 0 : -1;
    }
    return -1;
}

/* Достаёт ЛИСТОВОЙ сертификат из сообщения Certificate (TLS 1.3, RFC 8446
   §4.4.2) и сверяет его имя. Тело: длина контекста (байт), затем список,
   каждая запись — трёхбайтная длина, DER, двухбайтные расширения. Нужен
   только первый: подписывает ответ сервера именно он. */
int d2k_t13_cert_name_ok(const uint8_t *body, size_t len, const char *host) {
    if (len < 1) { return -1; }
    size_t ctx = body[0];
    size_t o = 1 + ctx;
    if (o + 3 > len) { return -1; }
    size_t list = (size_t)body[o] << 16 | (size_t)body[o + 1] << 8 | body[o + 2];
    o += 3;
    if (list < 3 || o + list > len) { return -1; }
    size_t clen = (size_t)body[o] << 16 | (size_t)body[o + 1] << 8 | body[o + 2];
    o += 3;
    if (clen == 0 || o + clen > len) { return -1; }
    return cert_name_ok(body + o, clen, host);
}
/* --- сборка ClientHello -------------------------------------------------- */

/* Собирает ClientHello с НАШИМ ключом. Приветствия из core/hello.c сюда не
   годятся: там реальные захваты чужих сессий, и закрытого ключа к их key_share
   у нас нет по определению. Форма здесь минимальная и своя — её задача
   договориться, а не обмануть коробку (обманывает план в датапате, и этот
   зонд ходит НЕПОМЕЧЕННЫМ именно затем, чтобы план к нему применился). */
size_t d2k_t13_ch_build(const d2k_t13_ch_opts *o, uint8_t *out, size_t cap) {
    if (!o || !out || !o->pub || !o->random || cap < 512) { return 0; }
    const char *sni = o->sni;
    const uint8_t *pub = o->pub;
    const uint8_t *rnd = o->random;
    size_t want_wire = o->pad_to;
    size_t sni_len = sni ? strlen(sni) : 0;
    size_t p = 0;

    out[p++] = D2K_T13_CLIENT_HELLO;
    size_t len_at = p; p += 3;                    /* длина тела — впишем в конце */
    put16(out + p, 0x0303); p += 2;               /* legacy_version = TLS 1.2 */
    memcpy(out + p, rnd, 32); p += 32;            /* random */
    /* legacy_session_id. У TLS поверх TCP это 32 байта «совместимости», у
       QUIC он ОБЯЗАН быть пустым (RFC 9001 §8.4: «MUST be set to a
       zero-length value»), и сервер вправе оборвать соединение, увидев
       непустой. Поэтому длина приходит опцией, а не зашита. */
    if (o->session_id_len > 32) { return 0; }
    out[p++] = (uint8_t)o->session_id_len;
    if (o->session_id_len) {
        memcpy(out + p, rnd, o->session_id_len); p += o->session_id_len;
    }
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
    if (o->alpn && o->alpn[0]) {
        size_t al = strlen(o->alpn);
        if (al > 255) { return 0; }
        put16(out + p, 0x0010); p += 2;           /* application_layer_protocol_negotiation */
        put16(out + p, (uint16_t)(al + 3)); p += 2;
        put16(out + p, (uint16_t)(al + 1)); p += 2;
        out[p++] = (uint8_t)al; memcpy(out + p, o->alpn, al); p += al;
    }

    put16(out + p, 0x002d); p += 2;               /* psk_key_exchange_modes */
    put16(out + p, 2); p += 2; out[p++] = 1; out[p++] = 1; /* psk_dhe_ke */

    /* Готовые байты дополнительных расширений. Через них едет
       quic_transport_parameters (0x0039): собирать их здесь значило бы
       затащить транспорт QUIC в общее ядро TLS. */
    if (o->extra && o->extra_len) {
        if (p + o->extra_len > cap) { return 0; }
        memcpy(out + p, o->extra, o->extra_len); p += o->extra_len;
    }

    put16(out + p, 0x0033); p += 2;               /* key_share */
    put16(out + p, 38); p += 2; put16(out + p, 36); p += 2;
    put16(out + p, 0x001d); p += 2; put16(out + p, 32); p += 2;
    memcpy(out + p, pub, 32); p += 32;

    /* ДОБИВКА ДО ДЛИНЫ ПРИВЕТСТВИЯ КЛИЕНТА (RFC 7685).
       Зонд подтверждения ходит СВОИМ приветствием — чужое сюда не годится,
       закрытого ключа к чужому key_share у нас нет. Но своё приветствие
       вчетверо короче браузерного, и на этом ломается переносимость: план,
       чьи куски помещаются в посылку на коротком приветствии зонда, на
       длинном приветствии браузера не помещается вовсе. В каталоге
       «подтверждено», у человека обхода нет (лаборатория 13.09.2026, седьмая
       находка).

       Поэтому длина выравнивается по приветствию, которое датапат СНЯЛ С
       КЛИЕНТА. Расширение padding выбрано не за отсутствием идей: это
       единственный штатный способ добрать длину, ничего не сообщив о себе
       (RFC 7685), и браузеры пользуются им ровно за этим же. Нули внутри
       значения не несут.

       Добивается длина САМОГО СООБЩЕНИЯ: заголовка записи у QUIC нет вовсе,
       и считать его в общем ядре значило бы зашить сюда чужой транспорт.
       Вызывающий, у которого записи есть, вычитает их сам.
       Четыре байта — заголовок самого расширения; если до цели меньше,
       добивать нечем и незачем, разница в четыре байта ни на какой предел
       отправки не влияет. */
    if (want_wire > 0) {
        size_t have = p;
        if (want_wire > have + 4 && want_wire - have - 4 <= 0xFFFF &&
            p + 4 + (want_wire - have - 4) <= cap) {
            size_t pad = want_wire - have - 4;
            put16(out + p, 0x0015); p += 2;
            put16(out + p, (uint16_t)pad); p += 2;
            memset(out + p, 0, pad); p += pad;
        }
    }

    put16(out + ext_at, (uint16_t)(p - ext_at - 2));
    size_t body = p - len_at - 3;
    out[len_at] = (uint8_t)(body >> 16);
    out[len_at + 1] = (uint8_t)(body >> 8);
    out[len_at + 2] = (uint8_t)body;
    return p;
}

/* --- ключевое расписание -------------------------------------------------- */

int d2k_t13_derive_secret(const uint8_t secret[32], const char *label,
                          const uint8_t *msgs, size_t n, uint8_t out[32]) {
    uint8_t th[32];
    d2k_sha256(msgs, n, th);
    return d2k_hkdf_expand_label_ctx(secret, label, th, 32, out, 32);
}

int d2k_t13_schedule_hs(const uint8_t shared[32], const uint8_t *tr, size_t tr_len,
                        uint8_t c_hs[32], uint8_t s_hs[32], uint8_t hs_out[32]) {
    uint8_t zero[32], early[32], derived[32], hs[32];
    memset(zero, 0, sizeof zero);
    d2k_hkdf_extract(zero, 32, zero, 32, early);
    if (d2k_t13_derive_secret(early, "derived", NULL, 0, derived) != 0) { return -1; }
    d2k_hkdf_extract(derived, 32, shared, 32, hs);
    if (d2k_t13_derive_secret(hs, "c hs traffic", tr, tr_len, c_hs) != 0 ||
        d2k_t13_derive_secret(hs, "s hs traffic", tr, tr_len, s_hs) != 0) {
        return -1;
    }
    if (hs_out) { memcpy(hs_out, hs, 32); }
    return 0;
}

int d2k_t13_schedule_ap(const uint8_t hs[32], const uint8_t *tr, size_t tr_len,
                        uint8_t c_ap[32], uint8_t s_ap[32]) {
    uint8_t zero[32], derived[32], master[32];
    memset(zero, 0, sizeof zero);
    if (d2k_t13_derive_secret(hs, "derived", NULL, 0, derived) != 0) { return -1; }
    d2k_hkdf_extract(derived, 32, zero, 32, master);
    if (d2k_t13_derive_secret(master, "c ap traffic", tr, tr_len, c_ap) != 0 ||
        d2k_t13_derive_secret(master, "s ap traffic", tr, tr_len, s_ap) != 0) {
        return -1;
    }
    return 0;
}

int d2k_t13_finished_mac(const uint8_t secret[32], const uint8_t *tr, size_t tr_len,
                         uint8_t out[32]) {
    uint8_t fin_key[32], th[32];
    if (d2k_hkdf_expand_label(secret, "finished", fin_key, 32) != 0) { return -1; }
    d2k_sha256(tr, tr_len, th);
    d2k_hmac_sha256(fin_key, 32, th, 32, out);
    return 0;
}

/* --- разбор ServerHello ---------------------------------------------------- */

int d2k_t13_sh_parse(const uint8_t *sh, size_t sh_len, const uint8_t **peer_key,
                     char *err, size_t errcap) {
    if (!sh || !peer_key) { return -1; }
    *peer_key = NULL;
    /* Из ServerHello нужен ровно один байт смысла — общий ключ. Разбираем
       ровно до него, не притворяясь полным разбором. */
    size_t q = 4 + 2 + 32;                         /* тип+длина, версия, random */
    if (q + 1 > sh_len) { goto trunc; }
    q += 1 + sh[q];                                /* legacy_session_id_echo */
    if (q + 3 > sh_len) { goto trunc; }
    uint16_t suite = get16(sh + q); q += 2;
    q += 1;                                        /* compression */
    if (suite != 0x1301) {
        if (err && errcap) {
            snprintf(err, errcap,
                     "сервер выбрал шифр 0x%04x, а поддержан только 0x1301",
                     (unsigned)suite);
        }
        return -1;
    }
    if (q + 2 > sh_len) {
        if (err && errcap) { snprintf(err, errcap, "ServerHello без расширений"); }
        return -1;
    }
    size_t ext_end = q + 2 + get16(sh + q);
    q += 2;
    if (ext_end > sh_len) { ext_end = sh_len; }

    while (q + 4 <= ext_end) {
        uint16_t et = get16(sh + q), el = get16(sh + q + 2);
        q += 4;
        if (q + el > ext_end) { break; }
        if (et == 0x0033 && el >= 36 && get16(sh + q) == 0x001d && get16(sh + q + 2) == 32) {
            *peer_key = sh + q + 4;
        }
        q += el;
    }
    if (!*peer_key) {
        if (err && errcap) {
            snprintf(err, errcap, "сервер не прислал ключ X25519 — TLS 1.3 не согласован");
        }
        return -1;
    }
    return 0;
trunc:
    if (err && errcap) { snprintf(err, errcap, "ServerHello обрезан"); }
    return -1;
}

/* --- ход по флайту --------------------------------------------------------- */

int d2k_t13_flight_next(const uint8_t *buf, size_t len, size_t *off,
                        uint8_t *type, const uint8_t **body, size_t *blen) {
    if (!buf || !off || *off + 4 > len) { return 0; }
    size_t o = *off;
    size_t n = (size_t)buf[o + 1] << 16 | (size_t)buf[o + 2] << 8 | buf[o + 3];
    if (o + 4 + n > len) { return 0; }   /* хвост обрезан — следующего нет */
    if (type) { *type = buf[o]; }
    if (body) { *body = buf + o + 4; }
    if (blen) { *blen = n; }
    *off = o + 4 + n;
    return 1;
}
