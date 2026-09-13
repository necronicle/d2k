/* test_quicwire.c — байтовый уровень QUIC против векторов RFC.
 *
 * ПОЧЕМУ ВЕКТОРЫ, А НЕ СВОИ ПРИМЕРЫ. Весь этот уровень — арифметика над
 * байтами, у которой нет наблюдаемого поведения: ошибка в метке, в маске или
 * в порядке байт не роняет ничего, она молча даёт «тег не сошёлся», и на
 * живой линии это неотличимо от «сервер не ответил». Единственный способ
 * поймать такую ошибку — сверить с числами, посчитанными не нами: приложение
 * A RFC 9001 и §16/A.2-A.3 RFC 9000.
 *
 * Что здесь НЕ проверяется: сеть, состояние соединения, кадры. Их здесь нет
 * (см. шапку d2k_quicwire.h), и притворяться, что тест их покрывает, нельзя.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_crypto.h"
#include "d2k_quicwire.h"

static int fails;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            printf("ПРОВАЛ: %s\n", (msg));                                    \
            fails++;                                                          \
        }                                                                     \
    } while (0)

/* Шестнадцатеричная строка в байты. Возвращает длину. */
static size_t unhex(const char *h, uint8_t *out, size_t cap) {
    size_t n = 0;
    for (const char *p = h; *p; p++) {
        if (*p == ' ' || *p == '\n') { continue; }
        int hi = -1, lo = -1;
        char c = *p;
        if (c >= '0' && c <= '9') { hi = c - '0'; }
        else if (c >= 'a' && c <= 'f') { hi = c - 'a' + 10; }
        else { return 0; }
        p++;
        c = *p;
        if (c >= '0' && c <= '9') { lo = c - '0'; }
        else if (c >= 'a' && c <= 'f') { lo = c - 'a' + 10; }
        else { return 0; }
        if (n >= cap) { return 0; }
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static int same(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

/* --- RFC 9000 §16: числа переменной длины -------------------------------- */

static void test_varint(void) {
    struct { const char *hex; uint64_t val; size_t width; } v[] = {
        { "c2197c5eff14e88c", 151288809941952652ull, 8 },
        { "9d7f3e7d",         494878333ull,          4 },
        { "7bbd",             15293ull,              2 },
        { "25",               37ull,                 1 },
        { "4025",             37ull,                 2 },   /* та же величина шире — законно на чтении */
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint8_t b[8];
        size_t n = unhex(v[i].hex, b, sizeof b);
        uint64_t got = 0; size_t w = 0;
        CHECK(d2k_qw_varint_read(b, n, &got, &w) == 0, "переменная длина не прочиталась");
        CHECK(got == v[i].val, "переменная длина прочиталась не тем числом");
        CHECK(w == v[i].width, "ширина переменной длины не та");
    }
    /* Запись берёт МИНИМАЛЬНУЮ ширину — иначе одно и то же число уезжало бы
       на провод по-разному от вызова к вызову. */
    uint8_t out[8];
    CHECK(d2k_qw_varint_write(out, sizeof out, 37) == 1 && out[0] == 0x25,
          "малое число записано не одним байтом");
    CHECK(d2k_qw_varint_write(out, sizeof out, 15293) == 2 && out[0] == 0x7b && out[1] == 0xbd,
          "число в два байта записано неверно");
    CHECK(d2k_qw_varint_write(out, 1, 15293) == 0, "запись не заметила нехватки места");
    CHECK(d2k_qw_varint_len(4611686018427387904ull) == 0,
          "непредставимое число объявлено представимым");
}

/* --- RFC 9000 A.3: восстановление номера пакета --------------------------- */

static void test_pn(void) {
    /* Пример из приложения: принято до 0xa82f30ea, пришло 0x9b32 двумя
       байтами — полный номер 0xa82f9b32. */
    CHECK(d2k_qw_pn_decode(0xa82f30eaull, 0x9b32ull, 2) == 0xa82f9b32ull,
          "номер пакета восстановлен не по алгоритму A.3");
    /* Начало соединения: дополнение нулями и алгоритм совпадают. */
    CHECK(d2k_qw_pn_decode(0, 1, 1) == 1, "номер в начале соединения восстановлен неверно");
    /* Ширина кодирования: A.2. */
    CHECK(d2k_qw_pn_len(0xac5c02, 0xabe8b3) == 2, "ширина номера пакета не та");
    CHECK(d2k_qw_pn_len(0xace8fe, 0xabe8b3) == 3, "ширина номера пакета не та (три байта)");
    CHECK(d2k_qw_pn_len(0, -1) == 1, "первый номер закодирован шире одного байта");
}

/* --- RFC 9001 A.1: начальные секреты и ключи ------------------------------ */

static void test_initial_keys(void) {
    uint8_t dcid[8];
    CHECK(unhex("8394c8f03e515708", dcid, sizeof dcid) == 8, "DCID вектора не разобрался");

    struct { d2k_qw_side side; const char *secret, *key, *iv, *hp; } c[] = {
        { D2K_QW_CLIENT,
          "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
          "1f369613dd76d5467730efcbe3b1a22d",
          "fa044b2f42a3fd3b46fb255c",
          "9f50449e04a0e810283a1e9933adedd2" },
        { D2K_QW_SERVER,
          "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
          "cf3a5331653c364c88f0f379b6067e37",
          "0ac1493ca1905853b0bba03e",
          "c206b8d9b9f0f37644430b490eeaa314" },
    };
    for (size_t i = 0; i < 2; i++) {
        uint8_t want[32], got[32];
        CHECK(d2k_qw_initial_secret(D2K_QW_V1, dcid, sizeof dcid, c[i].side, got) == 0,
              "начальный секрет не вывелся");
        CHECK(unhex(c[i].secret, want, sizeof want) == 32, "вектор секрета не разобрался");
        CHECK(same(got, want, 32), "начальный секрет уровня разошёлся с вектором RFC 9001 A.1");

        d2k_qw_keys k;
        CHECK(d2k_qw_keys_from_secret(D2K_QW_V1, got, &k) == 0, "ключи уровня не вывелись");
        uint8_t w[16];
        CHECK(unhex(c[i].key, w, sizeof w) == 16 && same(k.key, w, 16),
              "ключ пакетной защиты разошёлся с вектором");
        CHECK(unhex(c[i].iv, w, sizeof w) == 12 && same(k.iv, w, 12),
              "вектор пакетной защиты разошёлся с вектором RFC");
        CHECK(unhex(c[i].hp, w, sizeof w) == 16 && same(k.hp, w, 16),
              "ключ защиты заголовка разошёлся с вектором");
    }
}

/* --- RFC 9001 A.3: серверный Initial открывается и собирается обратно ------ */

static const char SERVER_INITIAL_HEX[] =
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
    "2158407dd074ee";

static const char SERVER_PLAIN_HEX[] =
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
    "020304";

static void test_server_initial(void) {
    uint8_t pkt[256], want_plain[256], dcid[8];
    size_t pkt_len = unhex(SERVER_INITIAL_HEX, pkt, sizeof pkt);
    size_t want_len = unhex(SERVER_PLAIN_HEX, want_plain, sizeof want_plain);
    CHECK(pkt_len > 0 && want_len > 0, "векторы A.3 не разобрались");
    CHECK(unhex("8394c8f03e515708", dcid, sizeof dcid) == 8, "DCID вектора не разобрался");

    uint8_t secret[32];
    d2k_qw_keys k;
    CHECK(d2k_qw_initial_secret(D2K_QW_V1, dcid, sizeof dcid, D2K_QW_SERVER, secret) == 0,
          "серверный секрет не вывелся");
    CHECK(d2k_qw_keys_from_secret(D2K_QW_V1, secret, &k) == 0, "серверные ключи не вывелись");

    d2k_qw_hdr h;
    CHECK(d2k_qw_hdr_parse(pkt, pkt_len, 0, &h) == 0, "заголовок серверного Initial не разобрался");
    CHECK(h.long_hdr == 1 && h.type == D2K_QW_LT_INITIAL, "тип пакета определён неверно");
    CHECK(h.packet_len == pkt_len, "длина пакета посчитана не по полю Length");

    uint8_t plain[256];
    size_t plain_len = 0;
    uint64_t pn = 0;
    CHECK(d2k_qw_open(&k, &h, pkt, 0, plain, &plain_len, &pn) == 0,
          "серверный Initial не открылся ключами из вектора");
    CHECK(plain_len == want_len && same(plain, want_plain, want_len),
          "расшифрованное содержимое разошлось с вектором A.3");
    CHECK(pn == 1, "номер серверного пакета восстановлен неверно");

    /* И обратно: тот же заголовок и то же содержимое обязаны дать ТОТ ЖЕ
       пакет побайтно. Это ловит ошибки, которых чтение не ловит: маску
       защиты заголовка, порядок байт номера, границу AAD. */
    uint8_t built[256], hdr_plain[64];
    size_t hdr_len = h.pn_offset;
    memcpy(hdr_plain, pkt, hdr_len);
    /* Первый байт на проводе ЗАЩИЩЁН; отправитель собирает пакет из
       НЕзащищённого. Для Initial версии 1 с номером в два байта это 0xc1
       (RFC 9001 A.3): длинный заголовок, фиксированный бит, тип 0, длина
       номера минус один. */
    hdr_plain[0] = 0xc1;
    size_t got = d2k_qw_seal(&k, 1, hdr_plain, hdr_len, 1, 2, want_plain, want_len,
                             built, sizeof built);
    CHECK(got == pkt_len, "собранный пакет другой длины");
    CHECK(got == pkt_len && same(built, pkt, pkt_len),
          "собранный пакет разошёлся с вектором A.3 побайтно");
}

/* --- RFC 9001 A.4: метка целостности Retry -------------------------------- */

static void test_retry(void) {
    uint8_t retry[64], odcid[8];
    size_t n = unhex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d82"
                     "9058fb3f0f2496ba", retry, sizeof retry);
    CHECK(n == 36, "вектор Retry не разобрался");
    CHECK(unhex("8394c8f03e515708", odcid, sizeof odcid) == 8, "DCID вектора не разобрался");
    CHECK(d2k_qw_retry_verify(D2K_QW_V1, odcid, 8, retry, n) == 0,
          "метка целостности Retry не сошлась с вектором A.4");

    /* Испорченная метка обязана отвергаться: иначе проверка бесполезна. */
    retry[n - 1] ^= 0x01;
    CHECK(d2k_qw_retry_verify(D2K_QW_V1, odcid, 8, retry, n) != 0,
          "испорченная метка Retry принята");
}

/* --- свои свойства, которых в векторах нет -------------------------------- */

static void test_roundtrip_levels(void) {
    /* Кругооборот на ПРОИЗВОЛЬНОМ секрете: векторы есть только для Initial, а
       ошибиться в вектору AEAD или маске можно на любом уровне. Проверяется
       не значение, а согласованность сборки и разбора. */
    uint8_t secret[32];
    for (size_t i = 0; i < sizeof secret; i++) { secret[i] = (uint8_t)(i * 7 + 1); }
    d2k_qw_keys k;
    CHECK(d2k_qw_keys_from_secret(D2K_QW_V1, secret, &k) == 0, "ключи не вывелись");

    uint8_t payload[64];
    for (size_t i = 0; i < sizeof payload; i++) { payload[i] = (uint8_t)(i ^ 0x5a); }

    /* Короткий заголовок: первый байт с битом фиксированного значения, DCID 4. */
    uint8_t hdr[5] = { 0x40, 0xde, 0xad, 0xbe, 0xef };
    uint8_t pkt[256], plain[256];
    uint64_t pns[] = { 0, 1, 255, 256, 0xa82f9b32ull };
    for (size_t i = 0; i < sizeof pns / sizeof pns[0]; i++) {
        size_t pn_len = d2k_qw_pn_len(pns[i], -1);
        size_t n = d2k_qw_seal(&k, 0, hdr, sizeof hdr, pns[i], pn_len,
                               payload, sizeof payload, pkt, sizeof pkt);
        CHECK(n > 0, "короткий пакет не собрался");
        d2k_qw_hdr h;
        CHECK(d2k_qw_hdr_parse(pkt, n, 4, &h) == 0, "короткий заголовок не разобрался");
        size_t plen = 0;
        uint64_t got_pn = 0;
        CHECK(d2k_qw_open(&k, &h, pkt, pns[i] ? pns[i] - 1 : 0, plain, &plen, &got_pn) == 0,
              "короткий пакет не открылся");
        CHECK(plen == sizeof payload && same(plain, payload, plen),
              "содержимое короткого пакета не сошлось");
        CHECK(got_pn == pns[i], "номер короткого пакета восстановлен неверно");
    }

    /* Испорченный байт обязан ломать тег, а не проходить молча. */
    size_t n = d2k_qw_seal(&k, 0, hdr, sizeof hdr, 7, 1, payload, sizeof payload,
                           pkt, sizeof pkt);
    CHECK(n > 0, "пакет для порчи не собрался");
    pkt[n - 1] ^= 0x80;
    d2k_qw_hdr h;
    size_t plen = 0;
    CHECK(d2k_qw_hdr_parse(pkt, n, 4, &h) == 0, "заголовок испорченного пакета не разобрался");
    CHECK(d2k_qw_open(&k, &h, pkt, 6, plain, &plen, NULL) != 0,
          "испорченный пакет открылся — тег не проверяется");
}

static void test_hdr_guards(void) {
    uint8_t buf[64];
    d2k_qw_hdr h;
    memset(buf, 0, sizeof buf);
    /* Короткий заголовок без объявленной длины DCID разбирать нечем. */
    buf[0] = 0x40;
    CHECK(d2k_qw_hdr_parse(buf, sizeof buf, 0, &h) != 0,
          "короткий заголовок разобран без длины DCID — длина угадана");
    /* Согласование версии (version == 0) — не пакет. */
    buf[0] = 0xc0;
    CHECK(d2k_qw_hdr_parse(buf, sizeof buf, 0, &h) != 0,
          "пакет согласования версии разобран как обычный");
    /* Слишком длинный CID обязан отвергаться требованием стандарта. */
    uint8_t big[64];
    memset(big, 0, sizeof big);
    big[0] = 0xc0; big[4] = 0x01; big[5] = 21;
    CHECK(d2k_qw_hdr_parse(big, sizeof big, 0, &h) != 0,
          "идентификатор длиннее двадцати байт принят");
}

int main(void) {
    test_varint();
    test_pn();
    test_initial_keys();
    test_server_initial();
    test_retry();
    test_roundtrip_levels();
    test_hdr_guards();

    if (fails == 0) {
        printf("байтовый уровень QUIC: все проверки прошли\n");
        return 0;
    }
    printf("байтовый уровень QUIC: %d провалов\n", fails);
    return 1;
}
