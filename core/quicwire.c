/* quicwire.c — байтовый уровень QUIC. Контракт и границы — в d2k_quicwire.h.
 *
 * Ни одна функция здесь не выделяет память и не ходит в сеть: всё считается
 * на месте, в буферах вызывающего. Это не стиль, а условие проверяемости —
 * весь файл проверяется векторами приложения A RFC 9001 без единой строки
 * сетевого кода (см. core/test_quicwire.c).
 */
#include <string.h>

#include "d2k_crypto.h"
#include "d2k_quicwire.h"

/* RFC 9001 §5.2, приложение A.1. */
static const uint8_t salt_v1[D2K_QW_SALT_LEN] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};
/* RFC 9369 §3.3.1: первые 20 байт sha256("QUICv2 salt"). */
static const uint8_t salt_v2[D2K_QW_SALT_LEN] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

/* Ключ и вектор метки целостности Retry (RFC 9001 §5.8 для v1,
 * RFC 9369 §3.3.3 для v2). Числа даны прямо в тексте RFC. */
static const uint8_t retry_key_v1[16] = {
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
static const uint8_t retry_nonce_v1[12] = {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};
static const uint8_t retry_key_v2[16] = {
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
    0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
};
static const uint8_t retry_nonce_v2[12] = {
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
};

static const uint8_t *salt_for(uint32_t version) {
    return version == D2K_QW_V2 ? salt_v2 : salt_v1;
}
static const char *label_key(uint32_t version) {
    return version == D2K_QW_V2 ? "quicv2 key" : "quic key";
}
static const char *label_iv(uint32_t version) {
    return version == D2K_QW_V2 ? "quicv2 iv" : "quic iv";
}
static const char *label_hp(uint32_t version) {
    return version == D2K_QW_V2 ? "quicv2 hp" : "quic hp";
}

/* --- числа переменной длины --------------------------------------------- */

int d2k_qw_varint_read(const uint8_t *p, size_t avail, uint64_t *val, size_t *width) {
    if (!p || avail < 1) { return -1; }
    /* Два старших бита ПЕРВОГО байта задают ширину, поэтому её нельзя
       проверить на помещаемость раньше, чем прочитан этот байт. */
    size_t w = (size_t)1 << (p[0] >> 6);
    if (avail < w) { return -1; }
    uint64_t v = (uint64_t)(p[0] & 0x3f);
    for (size_t i = 1; i < w; i++) { v = (v << 8) | p[i]; }
    if (val) { *val = v; }
    if (width) { *width = w; }
    return 0;
}

size_t d2k_qw_varint_len(uint64_t v) {
    if (v <= 63ull) { return 1; }
    if (v <= 16383ull) { return 2; }
    if (v <= 1073741823ull) { return 4; }
    if (v <= 4611686018427387903ull) { return 8; }
    return 0;   /* больше 2^62-1 переменной длиной не представимо */
}

size_t d2k_qw_varint_write(uint8_t *p, size_t cap, uint64_t v) {
    size_t w = d2k_qw_varint_len(v);
    if (!p || w == 0 || cap < w) { return 0; }
    switch (w) {
    case 1: p[0] = (uint8_t)v; break;
    case 2: p[0] = (uint8_t)(0x40 | (v >> 8)); p[1] = (uint8_t)v; break;
    case 4:
        p[0] = (uint8_t)(0x80 | (v >> 24));
        p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
        break;
    default:
        p[0] = (uint8_t)(0xc0 | (v >> 56));
        for (size_t i = 1; i < 8; i++) { p[i] = (uint8_t)(v >> (8 * (7 - i))); }
        break;
    }
    return w;
}

/* --- заголовки ---------------------------------------------------------- */

/* Тип длинного заголовка, приведённый к нумерации v1.
 *
 * RFC 9369 §3.2 перенумеровал типы: Initial стал 1, 0-RTT 2, Handshake 3,
 * Retry 0. Приводим здесь, а не у вызывающего: иначе каждый читатель
 * заголовка обязан был бы знать про версии, и однажды один из них не узнал
 * бы. */
static uint8_t long_type_v1(uint32_t version, uint8_t raw) {
    if (version != D2K_QW_V2) { return raw; }
    switch (raw) {
    case 1: return D2K_QW_LT_INITIAL;
    case 2: return D2K_QW_LT_0RTT;
    case 3: return D2K_QW_LT_HANDSHAKE;
    default: return D2K_QW_LT_RETRY;
    }
}

int d2k_qw_hdr_parse(const uint8_t *p, size_t n, size_t dcid_len_short,
                     d2k_qw_hdr *out) {
    if (!p || !out || n < 1) { return -1; }
    memset(out, 0, sizeof *out);

    if ((p[0] & 0x80) == 0) {
        /* КОРОТКИЙ ЗАГОЛОВОК. Длина DCID на проводе не объявлена: её знает
           только тот, кто этот идентификатор выдал. Без неё разбирать нечего,
           и гадать нельзя — ошибка на байт сдвигает весь пакет. */
        if (dcid_len_short == 0 || dcid_len_short > D2K_QW_CID_MAX) { return -1; }
        if (n < 1 + dcid_len_short + 1) { return -1; }
        out->long_hdr = 0;
        out->dcid_off = 1;
        out->dcid_len = dcid_len_short;
        out->pn_offset = 1 + dcid_len_short;
        /* У короткого заголовка поля Length нет вовсе: пакет занимает весь
           остаток датаграммы (RFC 9000 §17.3), и коалесцировать после него
           нечего. */
        out->packet_len = n;
        return 0;
    }

    if (n < 7) { return -1; }   /* первый байт, версия, две длины */
    out->long_hdr = 1;
    out->version = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 |
                   (uint32_t)p[3] << 8 | p[4];
    if (out->version == 0) { return -1; }  /* согласование версии — не пакет */
    out->type = long_type_v1(out->version, (uint8_t)((p[0] >> 4) & 0x03));

    size_t o = 5;
    size_t dl = p[o++];
    if (dl > D2K_QW_CID_MAX || o + dl >= n) { return -1; }
    out->dcid_off = o; out->dcid_len = dl; o += dl;
    size_t sl = p[o++];
    if (sl > D2K_QW_CID_MAX || o + sl > n) { return -1; }
    out->scid_off = o; out->scid_len = sl; o += sl;

    if (out->type == D2K_QW_LT_RETRY) {
        /* У Retry нет ни Length, ни номера пакета: остаток датаграммы это
           токен и шестнадцать байт метки целостности (RFC 9000 §17.2.5). */
        out->packet_len = n;
        return 0;
    }

    if (out->type == D2K_QW_LT_INITIAL) {
        uint64_t tlen = 0; size_t tw = 0;
        if (d2k_qw_varint_read(p + o, n - o, &tlen, &tw) != 0) { return -1; }
        o += tw;
        if (tlen > n - o) { return -1; }
        out->token_off = o; out->token_len = (size_t)tlen;
        o += (size_t)tlen;
    }

    uint64_t plen = 0; size_t pw = 0;
    if (d2k_qw_varint_read(p + o, n - o, &plen, &pw) != 0) { return -1; }
    o += pw;
    if (plen < 1 + 16 || plen > n - o) { return -1; }  /* номер + тег — минимум */
    out->length_claimed = (size_t)plen;
    out->pn_offset = o;
    out->packet_len = o + (size_t)plen;
    /* Сэмпл защиты заголовка берётся с четвёртого байта после начала номера
       (RFC 9001 §5.4.2) и обязан помещаться целиком — иначе снимать защиту
       нечем, и пакет не наш. */
    if (out->pn_offset + 4 + 16 > n) { return -1; }
    return 0;
}

/* --- номера пакетов ------------------------------------------------------ */

size_t d2k_qw_pn_len(uint64_t pn, int64_t largest_acked) {
    /* Дословно алгоритм RFC 9000 A.2, а не «на глаз».
       num_unacked НЕ удваивается: требование «покрыть вдвое больший диапазон»
       выполняется добавлением ОДНОГО бита к длине числа, и именно так оно
       записано в псевдокоде приложения. Удвоение вместо добавления бита даёт
       на границе лишний байт — поймано вектором A.2 (0xac5c02 при
       подтверждённом 0xabe8b3 обязан кодироваться двумя байтами). */
    uint64_t unacked = (largest_acked < 0) ? (pn + 1)
                                           : (pn - (uint64_t)largest_acked);
    if (unacked == 0) { unacked = 1; }
    size_t bits = 0;
    while (unacked) { bits++; unacked >>= 1; }
    size_t bytes = (bits + 1 + 7) / 8;
    if (bytes < 1) { bytes = 1; }
    if (bytes > 4) { bytes = 4; }
    return bytes;
}

uint64_t d2k_qw_pn_decode(uint64_t largest_pn, uint64_t truncated, size_t pn_len) {
    /* Дословно алгоритм RFC 9000 A.3. Своими словами его пересказывать
       нельзя: «дополнить нулями» верно только в самом начале соединения, а
       дальше даёт номер из прошлого и провал расшифровки. */
    if (pn_len == 0 || pn_len > 4) { return truncated; }
    uint64_t pn_nbits = pn_len * 8;
    uint64_t pn_win = 1ull << pn_nbits;
    uint64_t pn_hwin = pn_win / 2;
    uint64_t pn_mask = pn_win - 1;
    uint64_t expected = largest_pn + 1;
    uint64_t candidate = (expected & ~pn_mask) | truncated;
    if (candidate + pn_hwin <= expected && candidate + pn_win < (1ull << 62)) {
        return candidate + pn_win;
    }
    if (candidate > expected + pn_hwin && candidate >= pn_win) {
        return candidate - pn_win;
    }
    return candidate;
}

/* --- ключи --------------------------------------------------------------- */

int d2k_qw_initial_secret(uint32_t version, const uint8_t *dcid, size_t dcid_len,
                          d2k_qw_side side, uint8_t out[32]) {
    if (!dcid || !out || dcid_len > D2K_QW_CID_MAX) { return -1; }
    uint8_t initial[32];
    d2k_hkdf_extract(salt_for(version), D2K_QW_SALT_LEN, dcid, dcid_len, initial);
    /* Метки уровня общие для обеих версий: RFC 9369 меняет только защиту. */
    return d2k_hkdf_expand_label(initial, side == D2K_QW_SERVER ? "server in" : "client in",
                                 out, 32);
}

int d2k_qw_keys_from_secret(uint32_t version, const uint8_t secret[32],
                            d2k_qw_keys *out) {
    if (!secret || !out) { return -1; }
    memset(out, 0, sizeof *out);
    if (d2k_hkdf_expand_label(secret, label_key(version), out->key, sizeof out->key) != 0 ||
        d2k_hkdf_expand_label(secret, label_iv(version), out->iv, sizeof out->iv) != 0 ||
        d2k_hkdf_expand_label(secret, label_hp(version), out->hp, sizeof out->hp) != 0) {
        return -1;
    }
    out->have = 1;
    return 0;
}

/* --- защита пакета -------------------------------------------------------- */

/* Вектор для AEAD: IV уровня, в котором младшие байты сложены по модулю два
 * с номером пакета (RFC 9001 §5.3). */
static void nonce_of(const uint8_t iv[12], uint64_t pn, uint8_t out[12]) {
    memcpy(out, iv, 12);
    for (size_t i = 0; i < 8; i++) {
        out[11 - i] ^= (uint8_t)(pn >> (8 * i));
    }
}

size_t d2k_qw_seal(const d2k_qw_keys *k, int long_hdr,
                   const uint8_t *hdr, size_t hdr_len,
                   uint64_t pn, size_t pn_len,
                   const uint8_t *payload, size_t payload_len,
                   uint8_t *out, size_t out_cap) {
    if (!k || !k->have || !hdr || !out || pn_len < 1 || pn_len > 4) { return 0; }
    if (payload_len > 0 && !payload) { return 0; }
    size_t total = hdr_len + pn_len + payload_len + 16;
    if (total > out_cap) { return 0; }
    /* Сэмпл берётся с четвёртого байта после НАЧАЛА номера, то есть требует,
       чтобы за номером было не меньше 16 байт полезного (RFC 9001 §5.4.2).
       На коротких payload это не выполняется, и такой пакет собирать нельзя —
       защиту заголовка будет нечем навести. */
    if (pn_len + payload_len + 16 < 4 + 16) { return 0; }

    memcpy(out, hdr, hdr_len);
    /* Младшие два бита первого байта — длина номера минус один (§17.2/§17.3). */
    out[0] = (uint8_t)((out[0] & 0xfc) | (uint8_t)(pn_len - 1));
    for (size_t i = 0; i < pn_len; i++) {
        out[hdr_len + i] = (uint8_t)(pn >> (8 * (pn_len - 1 - i)));
    }

    uint8_t nonce[12];
    nonce_of(k->iv, pn, nonce);
    /* AAD — весь заголовок вместе с НЕЗАЩИЩЁННЫМ номером пакета. */
    size_t aad_len = hdr_len + pn_len;
    /* Тег кладётся СРАЗУ за шифртекстом — так он лежит и на проводе
       (RFC 9001 §5.3: «AEAD output» это ct||tag). */
    if (d2k_aes128_gcm_encrypt(k->key, nonce, out, aad_len,
                               payload, payload_len,
                               out + aad_len, out + aad_len + payload_len) != 0) {
        return 0;
    }

    /* Защита заголовка наводится ПОСЛЕ шифрования: сэмпл берётся из уже
       зашифрованного (RFC 9001 §5.4.2). */
    uint8_t mask[16];
    d2k_aes128_ecb(k->hp, out + hdr_len + 4, mask);
    out[0] = (uint8_t)(out[0] ^ (mask[0] & (long_hdr ? 0x0f : 0x1f)));
    for (size_t i = 0; i < pn_len; i++) {
        out[hdr_len + i] = (uint8_t)(out[hdr_len + i] ^ mask[1 + i]);
    }
    return total;
}

int d2k_qw_open(const d2k_qw_keys *k, const d2k_qw_hdr *h,
                const uint8_t *p, uint64_t largest_pn,
                uint8_t *plain, size_t *plain_len, uint64_t *pn_out) {
    if (!k || !k->have || !h || !p || !plain || !plain_len) { return -1; }
    if (h->long_hdr && h->type == D2K_QW_LT_RETRY) { return -1; }

    size_t sample_off = h->pn_offset + 4;
    uint8_t mask[16];
    d2k_aes128_ecb(k->hp, p + sample_off, mask);

    uint8_t byte0 = (uint8_t)(p[0] ^ (mask[0] & (h->long_hdr ? 0x0f : 0x1f)));
    size_t pn_len = (size_t)(byte0 & 0x03) + 1;
    uint8_t pn_bytes[4];
    for (size_t i = 0; i < pn_len; i++) {
        pn_bytes[i] = (uint8_t)(p[h->pn_offset + i] ^ mask[1 + i]);
    }

    size_t ct_len;
    if (h->long_hdr) {
        if (h->length_claimed < pn_len) { return -1; }
        ct_len = h->length_claimed - pn_len;
    } else {
        if (h->packet_len < h->pn_offset + pn_len) { return -1; }
        ct_len = h->packet_len - h->pn_offset - pn_len;
    }
    if (ct_len < 16) { return -1; }

    uint64_t truncated = 0;
    for (size_t i = 0; i < pn_len; i++) { truncated = (truncated << 8) | pn_bytes[i]; }
    uint64_t pn = d2k_qw_pn_decode(largest_pn, truncated, pn_len);

    size_t aad_len = h->pn_offset + pn_len;
    uint8_t aad[D2K_QW_MAX_DGRAM];
    if (aad_len > sizeof aad) { return -1; }
    memcpy(aad, p, aad_len);
    aad[0] = byte0;
    memcpy(aad + h->pn_offset, pn_bytes, pn_len);

    uint8_t nonce[12];
    nonce_of(k->iv, pn, nonce);
    if (d2k_aes128_gcm_decrypt(k->key, nonce, aad, aad_len,
                               p + h->pn_offset + pn_len, ct_len, plain) != 0) {
        return -1;
    }

    /* Резервные биты проверяются ТОЛЬКО после снятия обеих защит: до этого
       byte0 не аутентифицирован ничем, а «Discarding such a packet after only
       removing header protection can expose the endpoint to attacks»
       (RFC 9000 §17.2). Маска у заголовков разная. */
    if ((byte0 & (h->long_hdr ? 0x0c : 0x18)) != 0) { return -1; }

    *plain_len = ct_len - 16;
    if (pn_out) { *pn_out = pn; }
    return 0;
}

/* --- Retry ---------------------------------------------------------------- */

int d2k_qw_retry_verify(uint32_t version, const uint8_t *odcid, size_t odcid_len,
                        const uint8_t *retry, size_t retry_len) {
    if (!odcid || !retry || odcid_len > D2K_QW_CID_MAX) { return -1; }
    if (retry_len < 17 || retry_len + 1 + odcid_len > D2K_QW_MAX_DGRAM) { return -1; }

    /* Псевдопакет: длина исходного DCID, он сам, затем весь Retry без
       последних шестнадцати байт метки (RFC 9001 §5.8). */
    uint8_t pseudo[D2K_QW_MAX_DGRAM];
    size_t o = 0;
    pseudo[o++] = (uint8_t)odcid_len;
    memcpy(pseudo + o, odcid, odcid_len); o += odcid_len;
    size_t body = retry_len - 16;
    memcpy(pseudo + o, retry, body); o += body;

    uint8_t tag[16];
    const uint8_t *key = version == D2K_QW_V2 ? retry_key_v2 : retry_key_v1;
    const uint8_t *nonce = version == D2K_QW_V2 ? retry_nonce_v2 : retry_nonce_v1;
    if (d2k_aes128_gcm_encrypt(key, nonce, pseudo, o, NULL, 0, NULL, tag) != 0) {
        return -1;
    }
    /* Сравнение за постоянное время: метка — аутентификатор, и утечка через
       время сравнения здесь так же не нужна, как в любом другом MAC. */
    uint8_t diff = 0;
    for (size_t i = 0; i < 16; i++) { diff |= (uint8_t)(tag[i] ^ retry[body + i]); }
    return diff == 0 ? 0 : -1;
}
