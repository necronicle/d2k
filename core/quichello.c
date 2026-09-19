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
#include "d2k_crypto.h"
#include "profiles/quic_probe.h"

typedef char probe_profile_fields_fit[
    D2K_QUIC_PROFILE_RANDOM_OFF + 32 <= sizeof d2k_quic_probe_profile &&
    D2K_QUIC_PROFILE_KEY_SHARE_OFF + 32 <= sizeof d2k_quic_probe_profile &&
    D2K_QUIC_PROFILE_SCID_OFF + 8 <= sizeof d2k_quic_probe_profile ? 1 : -1];

#define FR_CRYPTO 0x06
/* Наименьшая датаграмма с Initial (RFC 9000 §14.1): сервер обязан отбросить
   всё, что короче, и такой отказ выглядел бы как молчание коробки. */
#define INITIAL_MIN 1200

/* ГДЕ РЕЗАТЬ ПРИВЕТСТВИЕ — ВНУТРИ ИМЕНИ, А НЕ ПОСЕРЕДИНЕ БУФЕРА.
 *
 * Разрез ломает коробку только там, где он рвёт то, что коробка ищет. Разрыв
 * в случайном месте буфера оставляет имя лежать целиком, и коробка находит
 * его обычным поиском подстроки — вопрос тогда задан не был, а молчание в
 * ответ прочиталось бы как «приём не помогает».
 *
 * Имени в приветствии может и не оказаться (снимок не от того клиента, имя
 * подставлено не туда) — тогда режем пополам. Это честнее отказа: вопрос
 * получится слабее, но он всё равно спрашивает про пересборку кадров. */
static size_t split_point(const uint8_t *hello, size_t n, const char *sni) {
    size_t m = strlen(sni);
    if (m && n >= m) {
        for (size_t i = 1; i + m <= n; i++) {
            if (memcmp(hello + i, sni, m) == 0) { return i + m / 2; }
        }
    }
    return n / 2;
}

/* Один кадр CRYPTO (RFC 9000 §19.6): тип, смещение в потоке, длина, данные. */
static int put_crypto(uint8_t *body, size_t cap, size_t *pb, uint64_t off,
                      const uint8_t *data, size_t len) {
    size_t b = *pb;
    if (b >= cap) { return -1; }
    body[b++] = FR_CRYPTO;
    size_t w = d2k_qw_varint_write(body + b, cap - b, off);
    if (w == 0) { return -1; }
    b += w;
    w = d2k_qw_varint_write(body + b, cap - b, len);
    if (w == 0) { return -1; }
    b += w;
    if (b + len > cap) { return -1; }
    memcpy(body + b, data, len);
    *pb = b + len;
    return 0;
}

/* Общая голова обоих сборщиков: разобрать снимок, достать приветствие,
 * подставить имя, выбрать идентификаторы и вывести ключи.
 *
 * want_v2 — спрошена ли вторая версия. ВЕРСИЯ ОДНА НА ВЕСЬ ПАКЕТ, и её нельзя
 * сменить только в заголовке: у второй версии (RFC 9369) другая соль вывода
 * начального секрета, другие метки ключей и перенумерованы типы пакетов — всё
 * это провод уже знает (d2k_qw_initial_secret, d2k_qw_long_hdr), но только
 * если ему сказать версию. Поставить в заголовок другое число, а запечатать
 * ключами первой версии, значит послать битый пакет и получить молчание,
 * которое читалось бы как свойство коробки.
 *
 * DCID — СВЕЖИЙ: из него выводятся ключи, и повторить чужой значит послать
 * второй Initial ЧУЖОГО соединения. Короче восьми байт у первого Initial
 * клиента он не бывает (RFC 9000 §7.2); принёс снимок такой — берём восемь,
 * идентификатор всё равно наш.
 *
 * SCID — НАОБОРОТ, ДОСЛОВНО ИЗ СНИМКА, и это не экономия на случайных байтах.
 * Клиент обязан объявить свой SCID внутри приветствия, параметром
 * initial_source_connection_id (RFC 9000 §7.3), и сервер СЛИЧАЕТ его с полем
 * заголовка; расхождение — ошибка соединения TRANSPORT_PARAMETER_ERROR.
 * Свежий SCID в заголовке при старом в приветствии означал бы, что на
 * контрольный вопрос сервер отвечает закрытием — то есть «контрольное имя
 * молчит» вместо «путь жив». Переписать параметр внутри приветствия было бы
 * можно, но это меняло бы байты, ради сохранности которых весь этот файл и
 * существует.
 *
 * ch2/dcid/scid обязаны вмещать D2K_QW_MAX_DGRAM и D2K_QW_CID_MAX. */
static int prepare(const uint8_t *in, size_t n, const char *sni, int want_v2,
                   uint8_t *ch2, size_t *ch2_len,
                   uint8_t *dcid, size_t *dcid_len,
                   uint8_t *scid, size_t *scid_len,
                   uint32_t *ver, d2k_qw_keys *k) {
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
    if (d2k_hello_rename(ch, ch_len, sni, ch2, D2K_QW_MAX_DGRAM, ch2_len) != 0) {
        return -1;
    }

    *dcid_len = (h.dcid_len >= 8 && h.dcid_len <= D2K_QW_CID_MAX) ? h.dcid_len : 8;
    *scid_len = (h.scid_len <= D2K_QW_CID_MAX) ? h.scid_len : 0;
    if (d2k_t13_random(dcid, *dcid_len) != 0) { return -1; }
    if (*scid_len) { memcpy(scid, in + h.scid_off, *scid_len); }

    *ver = want_v2 ? D2K_QW_V2 : h.version;
    uint8_t sec[32];
    if (d2k_qw_initial_secret(*ver, dcid, *dcid_len, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(*ver, sec, k) != 0) {
        return -1;
    }
    return 0;
}

/* Общий хвост сборки: добивка PADDING до want и запечатывание.
 *
 * Вынесен, потому что им пользуются ВСЕ вопросы и пара датаграмм, а расчёт
 * добивки — единственное место во всём файле, где легко разойтись незаметно:
 * длина заголовка зависит от поля Length, а оно — от длины тела ВМЕСТЕ с
 * добивкой. */
static int seal_one(const d2k_qw_keys *k, uint32_t ver,
                    const uint8_t *dcid, size_t dcid_len,
                    const uint8_t *scid, size_t scid_len,
                    uint8_t *body, size_t b, uint64_t pn, size_t pn_len, size_t want,
                    int clear_fixed, uint8_t *out, size_t cap, size_t *out_len) {
    if (want > D2K_QW_MAX_DGRAM || want > cap) { return -1; }

    /* Добивка считается итерацией, а не формулой: ширина varint'а поля Length
       может подрасти на единицу, и тогда нужен ещё один проход. Четырёх
       хватает с запасом (ширина растёт максимум трижды: 1->2->4->8). */
    if (pn_len == 0) { pn_len = d2k_qw_pn_len(pn, -1); }
    uint8_t probe[64];
    size_t hlen = 0;
    for (int i = 0; i < 4; i++) {
        hlen = d2k_qw_long_hdr(probe, sizeof probe, ver, D2K_QW_LT_INITIAL,
                               dcid, dcid_len, scid, scid_len, pn_len, b);
        if (hlen == 0) { return -1; }
        size_t total = hlen + pn_len + b + 16;
        if (total >= want) { break; }
        size_t add = want - total;
        if (b + add > D2K_QW_MAX_DGRAM) { return -1; }
        memset(body + b, 0, add);   /* PADDING — нули (RFC 9000 §19.1) */
        b += add;
    }

    uint8_t pkt[D2K_QW_MAX_DGRAM];
    hlen = d2k_qw_long_hdr(pkt, sizeof pkt, ver, D2K_QW_LT_INITIAL,
                           dcid, dcid_len, scid, scid_len, pn_len, b);
    if (hlen == 0) { return -1; }
    if (clear_fixed) {
        /* ГАСИМ ДО ЗАПЕЧАТЫВАНИЯ, и порядок здесь не вкусовой.
           Первый байт входит в связанные данные AEAD (RFC 9001 §5.3), и
           получатель строит их из ВОССТАНОВЛЕННОГО заголовка — то есть из
           того байта, который увидит после снятия защиты. Погасить бит
           снаружи, уже над запечатанным пакетом, значит разойтись с
           отправителем в связанных данных: тег не сойдётся ни у сервера, ни
           у нас. Первая редакция так и сделала, и тест поймал это сразу —
           «пакет перестал разбираться». */
        pkt[0] &= (uint8_t)~0x40u;
    }
    size_t made = d2k_qw_seal(k, 1, pkt, hlen, pn, pn_len, body, b, pkt, sizeof pkt);
    if (made == 0 || made > cap) { return -1; }
    memcpy(out, pkt, made);
    *out_len = made;
    return 0;
}

/* Измерительный вход оригинала, отдельно от полноценного клиента
 * подтверждения. Профиль получен вызовом donor ClientHello, а не собран
 * похожим. Случайные поля обновляем ДО переименования: длина SNI сдвигает
 * последующие расширения. Закрытый X25519-ключ не нужен после построения
 * вопроса — этот опыт не продолжает TLS-рукопожатие. */
int d2k_quic_probe_initial(const char *sni, uint8_t *out, size_t cap,
                           size_t *out_len) {
    if (!sni || !sni[0] || strlen(sni) > 253 || !out || !out_len) { return -1; }
    *out_len = 0;
    if (cap < INITIAL_MIN) { return -1; }
    uint8_t profile[sizeof d2k_quic_probe_profile], ch[D2K_QW_MAX_DGRAM];
    uint8_t dcid[8], scid[8], priv[32], sec[32];
    memcpy(profile, d2k_quic_probe_profile, sizeof profile);
    if (d2k_t13_random(dcid, sizeof dcid) != 0 ||
        d2k_t13_random(scid, sizeof scid) != 0 ||
        d2k_t13_random(profile + D2K_QUIC_PROFILE_RANDOM_OFF, 32) != 0 ||
        d2k_t13_random(priv, sizeof priv) != 0) { return -1; }
    int rc = d2k_x25519_base(profile + D2K_QUIC_PROFILE_KEY_SHARE_OFF, priv);
    memset(priv, 0, sizeof priv);
    if (rc != 0) { return -1; }
    memcpy(profile + D2K_QUIC_PROFILE_SCID_OFF, scid, sizeof scid);
    size_t ch_len = 0;
    if (d2k_hello_rename(profile, sizeof profile, sni, ch, sizeof ch, &ch_len) != 0) {
        return -1;
    }
    d2k_qw_keys k;
    if (d2k_qw_initial_secret(D2K_QW_V1, dcid, sizeof dcid, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(D2K_QW_V1, sec, &k) != 0) { return -1; }
    uint8_t body[D2K_QW_MAX_DGRAM];
    size_t b = 0;
    if (put_crypto(body, sizeof body, &b, 0, ch, ch_len) != 0) { return -1; }
    /* buildInitial оригинала: PN=0, PNLen=4, один CRYPTO, 1200 байт. */
    return seal_one(&k, D2K_QW_V1, dcid, sizeof dcid, scid, sizeof scid,
                    body, b, 0, 4, INITIAL_MIN, 0, out, cap, out_len);
}

int d2k_quic_hello_rename(const uint8_t *in, size_t n, const char *sni,
                          uint8_t *out, size_t cap, size_t *out_len) {
    return d2k_quic_hello_ask(in, n, D2K_QASK_PLAIN, sni, out, cap, out_len);
}

/* ОДИН СБОРЩИК НА ВСЕ ВОПРОСЫ, А НЕ ПО ФУНКЦИИ НА КАЖДЫЙ.
 *
 * Собрать Initial — это восемь шагов, из которых вопрос меняет один-два:
 * разобрать снимок, достать приветствие, подставить имя, взять свежий DCID и
 * старый SCID, вывести ключи, сложить кадры, добить до длины, запечатать.
 * Второй экземпляр этой последовательности разошёлся бы с первым на первой же
 * правке, и разошёлся бы молча: оба собирают «похожий» пакет. */
int d2k_quic_hello_ask(const uint8_t *in, size_t n, d2k_quic_ask ask,
                       const char *sni, uint8_t *out, size_t cap, size_t *out_len) {
    if (!in || !sni || !out || !out_len) { return -1; }

    uint8_t ch2[D2K_QW_MAX_DGRAM];
    size_t ch2_len = 0;
    uint8_t dcid[D2K_QW_CID_MAX], scid[D2K_QW_CID_MAX];
    size_t dcid_len = 0, scid_len = 0;
    uint32_t ver = 0;
    d2k_qw_keys k;
    if (prepare(in, n, sni, ask == D2K_QASK_VERSION2, ch2, &ch2_len,
                dcid, &dcid_len, scid, &scid_len, &ver, &k) != 0) {
        return -1;
    }

    /* Тело: один кадр CRYPTO со смещением 0 — или два, если спрошено про
       разрез. Кадры внутри ОДНОГО пакета не обязаны идти по возрастанию
       смещения (RFC 9000 §19.6), и хвост уезжает первым по той же причине,
       по которой в TCP второй сегмент шлётся раньше первого: коробка,
       читающая приветствие подряд из первого кадра, получает обрывок, а
       сервер собирает поток по смещениям и не замечает разницы. */
    uint8_t body[D2K_QW_MAX_DGRAM];
    size_t b = 0;
    if (ask == D2K_QASK_SPLIT_CRYPTO) {
        size_t cut = split_point(ch2, ch2_len, sni);
        if (cut == 0 || cut >= ch2_len) { return -1; }
        if (put_crypto(body, sizeof body, &b, cut, ch2 + cut, ch2_len - cut) != 0 ||
            put_crypto(body, sizeof body, &b, 0, ch2, cut) != 0) {
            return -1;
        }
    } else if (put_crypto(body, sizeof body, &b, 0, ch2, ch2_len) != 0) {
        return -1;
    }

    size_t want = (n > INITIAL_MIN) ? n : INITIAL_MIN;
    if (ask == D2K_QASK_LONGER) {
        /* СТО БАЙТ — ЧИСЛО ОРИГИНАЛА (questions.go: 1300 против 1200), и
           берётся оно как наследство, а не как замер: своего замера под эту
           величину у нас нет, а выдумывать другую значило бы задать другой
           вопрос и назвать его тем же именем. */
        want += 100;
    }
    return seal_one(&k, ver, dcid, dcid_len, scid, scid_len, body, b, 0, 0, want,
                    ask == D2K_QASK_CLEAR_FIXED_BIT, out, cap, out_len);
}

/* ПРИВЕТСТВИЕ ДВУМЯ ДАТАГРАММАМИ, ХВОСТ ПЕРВЫМ (вопрос 4 оригинала).
 *
 * Отдельная функция, а не ещё один d2k_quic_ask: у вопроса ДВА выхода, и
 * втиснуть их в один буфер значило бы отдать склеенную датаграмму — то есть
 * задать совсем другой вопрос (RFC 9000 §12.2 про коалесценцию).
 *
 * ОБА ПАКЕТА — ОДНО СОЕДИНЕНИЕ, и это здесь несущее: DCID у них обязан быть
 * ОДИН, иначе сервер увидит два разных начатых соединения, каждое с половиной
 * приветствия, и не ответит ни на одно. Поэтому пара собирается вместе, а не
 * двумя вызовами сборщика — два вызова взяли бы два разных свежих DCID.
 *
 * Свежесть при этом сохраняется: DCID новый на КАЖДЫЙ вызов, значит три
 * параллельные попытки вопроса — три разных соединения, как того требует
 * RFC 9000 §7.2 (и как показал замер 13.09: одинаковые Initial сервер
 * считает одним).
 *
 * Так, между прочим, шлёт и настоящий клиент: Chrome с постквантовым
 * key_share и Firefox 137 по умолчанию не помещают приветствие в одну
 * датаграмму. */
int d2k_quic_hello_split(const uint8_t *in, size_t n, const char *sni,
                         uint8_t *head, size_t head_cap, size_t *head_len,
                         uint8_t *tail, size_t tail_cap, size_t *tail_len) {
    if (!in || !sni || !head || !head_len || !tail || !tail_len) { return -1; }

    uint8_t ch2[D2K_QW_MAX_DGRAM];
    size_t ch2_len = 0;
    uint8_t dcid[D2K_QW_CID_MAX], scid[D2K_QW_CID_MAX];
    size_t dcid_len = 0, scid_len = 0;
    uint32_t ver = 0;
    d2k_qw_keys k;
    if (prepare(in, n, sni, 0, ch2, &ch2_len, dcid, &dcid_len, scid, &scid_len,
                &ver, &k) != 0) {
        return -1;
    }

    size_t cut = split_point(ch2, ch2_len, sni);
    if (cut == 0 || cut >= ch2_len) { return -1; }

    /* Длина КАЖДОЙ датаграммы — не меньше 1200 (RFC 9000 §14.1): сервер
       обязан отбросить недомерок, и такой отказ выглядел бы как молчание
       коробки. Форму снимка здесь не сохранить в принципе — снимок был одной
       датаграммой, а тут их две; это и есть цена вопроса. */
    uint8_t body[D2K_QW_MAX_DGRAM];
    size_t b = 0;
    if (put_crypto(body, sizeof body, &b, cut, ch2 + cut, ch2_len - cut) != 0 ||
        seal_one(&k, ver, dcid, dcid_len, scid, scid_len, body, b, 1, 0, INITIAL_MIN,
                 0, tail, tail_cap, tail_len) != 0) {
        return -1;
    }
    b = 0;
    if (put_crypto(body, sizeof body, &b, 0, ch2, cut) != 0 ||
        seal_one(&k, ver, dcid, dcid_len, scid, scid_len, body, b, 0, 0, INITIAL_MIN,
                 0, head, head_cap, head_len) != 0) {
        return -1;
    }
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
    /* ФИКСИРОВАННЫЙ БИТ — ИЗ СНИМКА, а не от сборщика заголовка.
       d2k_qw_long_hdr ставит его всегда (RFC 9000 §17.2 требует единицу), а
       эта функция обещает «тот же снимок во всём, кроме идентификатора
       назначения» — значит и этот бит обязан приехать из снимка. Защита
       заголовка его не маскирует (RFC 9001 §5.4.1 у длинного заголовка
       закрывает только младшие четыре бита), поэтому в in[0] он настоящий.

       Цена ошибки несимметрична и потому не абстрактна: вопрос про
       погашенный бит (D2K_QASK_CLEAR_FIXED_BIT) уезжает тремя попытками
       через эту функцию, и все три вернулись бы с битом на месте. Свойство
       требует единогласия 3/3 — оно не подтвердилось бы НИКОГДА, а молчание
       записали бы коробке. То же верно и для снимка настоящего клиента,
       который бит гризовал по RFC 9287. */
    pkt[0] = (uint8_t)((pkt[0] & (uint8_t)~0x40u) | (in[0] & 0x40u));
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
