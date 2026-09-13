/* quichello.c — контракт и все обоснования в d2k_quichello.h.
 *
 * Своего разбора здесь нет ни одной строки: приветствие достаёт core/quic.c
 * (он же разбирает Initial для датапата), имя подставляет core/hello.c (он же
 * собирает приветствие холодного старта), байты пакета кладёт
 * core/quicwire.c (он же — единственный проводной слой QUIC). Этот файл
 * только связывает три готовых шага, и это намеренно: любой четвёртый разбор
 * QUIC в проекте был бы вторым экземпляром уже существующего (§2.5).
 */
#include <string.h>

#include "d2k_hello.h"
#include "d2k_quic.h"
#include "d2k_quichello.h"
#include "d2k_quicwire.h"
#include "d2k_tls13core.h"

#define FR_CRYPTO 0x06
/* Наименьшая датаграмма с Initial (RFC 9000 §14.1): сервер обязан отбросить
   всё, что короче, и такой отказ выглядел бы как молчание коробки. */
#define INITIAL_MIN 1200

int d2k_quic_hello_rename(const uint8_t *in, size_t n, const char *sni,
                          uint8_t *out, size_t cap, size_t *out_len) {
    if (!in || !sni || !out || !out_len) { return -1; }

    d2k_qw_hdr h;
    if (d2k_qw_hdr_parse(in, n, 0, &h) != 0 || !h.long_hdr ||
        h.type != D2K_QW_LT_INITIAL) {
        return -1;
    }

    uint8_t ch[D2K_QW_MAX_DGRAM];
    size_t ch_len = 0;
    if (d2k_quic_client_hello(in, n, ch, sizeof ch, &ch_len) != 0) {
        return -1;
    }

    uint8_t ch2[D2K_QW_MAX_DGRAM];
    size_t ch2_len = 0;
    if (d2k_hello_rename(ch, ch_len, sni, ch2, sizeof ch2, &ch2_len) != 0) {
        return -1;
    }

    /* DCID — СВЕЖИЙ: из него выводятся ключи, и повторить чужой значит
       послать второй Initial ЧУЖОГО соединения. Короче восьми байт у первого
       Initial клиента он не бывает (RFC 9000 §7.2); принёс снимок такой —
       берём восемь, идентификатор всё равно наш.

       SCID — НАОБОРОТ, ДОСЛОВНО ИЗ СНИМКА, и это не экономия на случайных
       байтах. Клиент обязан объявить свой SCID внутри приветствия,
       параметром initial_source_connection_id (RFC 9000 §7.3), и сервер
       СЛИЧАЕТ его с полем заголовка; расхождение — ошибка соединения
       TRANSPORT_PARAMETER_ERROR. Свежий SCID в заголовке при старом в
       приветствии означал бы, что на контрольный вопрос сервер отвечает
       закрытием — то есть «контрольное имя молчит» вместо «путь жив».
       Переписать параметр внутри приветствия было бы можно, но это меняло бы
       байты, ради сохранности которых весь этот файл и существует. */
    uint8_t dcid[D2K_QW_CID_MAX], scid[D2K_QW_CID_MAX];
    size_t dcid_len = (h.dcid_len >= 8 && h.dcid_len <= sizeof dcid) ? h.dcid_len : 8;
    size_t scid_len = (h.scid_len <= sizeof scid) ? h.scid_len : 0;
    if (d2k_t13_random(dcid, dcid_len) != 0) { return -1; }
    if (scid_len) { memcpy(scid, in + h.scid_off, scid_len); }

    d2k_qw_keys k;
    uint8_t sec[32];
    if (d2k_qw_initial_secret(h.version, dcid, dcid_len, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(h.version, sec, &k) != 0) {
        return -1;
    }

    /* Тело: один кадр CRYPTO со смещением 0. */
    uint8_t body[D2K_QW_MAX_DGRAM];
    size_t b = 0;
    body[b++] = FR_CRYPTO;
    b += d2k_qw_varint_write(body + b, sizeof body - b, 0);
    size_t lw = d2k_qw_varint_write(body + b, sizeof body - b, ch2_len);
    if (lw == 0) { return -1; }
    b += lw;
    if (b + ch2_len > sizeof body) { return -1; }
    memcpy(body + b, ch2, ch2_len);
    b += ch2_len;

    size_t want = (n > INITIAL_MIN) ? n : INITIAL_MIN;
    if (want > D2K_QW_MAX_DGRAM || want > cap) { return -1; }

    /* Добивка считается итерацией, а не формулой: длина заголовка зависит от
       поля Length, а оно — от длины тела вместе с добивкой. Ширина varint'а
       может подрасти на единицу, и тогда нужен ещё один проход. Четырёх
       хватает с запасом (ширина растёт максимум трижды: 1->2->4->8). */
    size_t pn_len = d2k_qw_pn_len(0, -1);
    uint8_t probe[64];
    size_t hlen = 0;
    for (int i = 0; i < 4; i++) {
        hlen = d2k_qw_long_hdr(probe, sizeof probe, h.version, D2K_QW_LT_INITIAL,
                               dcid, dcid_len, scid, scid_len, pn_len, b);
        if (hlen == 0) { return -1; }
        size_t total = hlen + pn_len + b + 16;
        if (total >= want) { break; }
        size_t add = want - total;
        if (b + add > sizeof body) { return -1; }
        memset(body + b, 0, add);   /* PADDING — нули (RFC 9000 §19.1) */
        b += add;
    }

    uint8_t pkt[D2K_QW_MAX_DGRAM];
    hlen = d2k_qw_long_hdr(pkt, sizeof pkt, h.version, D2K_QW_LT_INITIAL,
                           dcid, dcid_len, scid, scid_len, pn_len, b);
    if (hlen == 0) { return -1; }
    size_t made = d2k_qw_seal(&k, 1, pkt, hlen, 0, pn_len, body, b, pkt, sizeof pkt);
    if (made == 0 || made > cap) { return -1; }
    memcpy(out, pkt, made);
    *out_len = made;
    return 0;
}

int d2k_quic_hello_recid(const uint8_t *in, size_t n,
                         uint8_t *out, size_t cap, size_t *out_len) {
    if (!in || !out || !out_len) { return -1; }

    d2k_qw_hdr h;
    if (d2k_qw_hdr_parse(in, n, 0, &h) != 0 || !h.long_hdr ||
        h.type != D2K_QW_LT_INITIAL) {
        return -1;
    }
    /* Соль у каждой версии своя (RFC 9001 §5.2, RFC 9369 §3.3.1), и версию,
       которой мы не знаем, расшифровать нечем. Отказ здесь честен и нужен:
       зонд согласования версий шлёт Initial с ЗАВЕДОМО чужой версией, и
       трогать его этой функцией нельзя. */
    if (h.version != D2K_QW_V1 && h.version != D2K_QW_V2) { return -1; }
    /* Склеенная датаграмма (Initial плюс что-то ещё, RFC 9000 §12.2) сюда не
       годится: пересобрав только первый пакет, мы отдали бы датаграмму
       КОРОЧЕ снимка — то есть изменили бы ровно ту форму, ради сохранности
       которой эта функция и написана. */
    if (h.packet_len != n) { return -1; }

    d2k_qw_keys k;
    uint8_t sec[32];
    if (d2k_qw_initial_secret(h.version, in + h.dcid_off, h.dcid_len,
                              D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(h.version, sec, &k) != 0) {
        return -1;
    }
    uint8_t plain[D2K_QW_MAX_DGRAM];
    size_t plain_len = 0;
    uint64_t pn = 0;
    if (h.packet_len > sizeof plain ||
        d2k_qw_open(&k, &h, in, 0, plain, &plain_len, &pn) != 0) {
        return -1;
    }

    /* Новый DCID той же длины: длина — тоже форма (по ней коробка отличает
       клиента от клиента), а вот содержимое обязано быть новым. */
    uint8_t dcid[D2K_QW_CID_MAX];
    size_t dcid_len = (h.dcid_len >= 8 && h.dcid_len <= sizeof dcid) ? h.dcid_len : 8;
    if (d2k_t13_random(dcid, dcid_len) != 0) { return -1; }
    if (d2k_qw_initial_secret(h.version, dcid, dcid_len, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(h.version, sec, &k) != 0) {
        return -1;
    }

    /* SCID — из снимка дословно, по той же причине, что и в переименовании
       выше: клиент объявил его внутри приветствия, и сервер сличает. */
    const uint8_t *scid = in + h.scid_off;
    /* Длина номера пакета берётся ИЗ СНИМКА, а не считается заново: клиент
       выбирает её сам (RFC 9000 §17.1), и вектор A.2 шлёт четырёхбайтный
       номер там, где хватило бы одного. Пересчёт укоротил бы датаграмму на
       три байта — то есть изменил бы форму. Считается вычитанием: поле
       Length покрывает номер, тело и тег AEAD. */
    if (h.length_claimed < plain_len + 16) { return -1; }
    size_t pn_len = h.length_claimed - plain_len - 16;
    if (pn_len < 1 || pn_len > 4) { return -1; }
    uint8_t pkt[D2K_QW_MAX_DGRAM];
    size_t hlen = d2k_qw_long_hdr(pkt, sizeof pkt, h.version, D2K_QW_LT_INITIAL,
                                  dcid, dcid_len, scid, h.scid_len, pn_len, plain_len);
    if (hlen == 0) { return -1; }
    size_t made = d2k_qw_seal(&k, 1, pkt, hlen, pn, pn_len, plain, plain_len,
                              pkt, sizeof pkt);
    if (made == 0 || made > cap) { return -1; }
    /* Длина обязана совпасть со снимком: добивка уже внутри расшифрованного
       содержимого, и если бы пересборка дала другую длину, значит ушло что-то
       ещё, кроме идентификатора. */
    if (made != h.pn_offset + h.length_claimed) { return -1; }
    memcpy(out, pkt, made);
    *out_len = made;
    return 0;
}
