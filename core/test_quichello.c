/* test_quichello.c — приветствие QUIC с другим именем, собранное из снятого.
 *
 * Что здесь проверяется и почему именно так. Собрать пакет мало: он обязан
 * быть ПРИНЯТ тем же разбором, которым его будет читать и коробка, и мы сами.
 * Поэтому проверка идёт не по байтам сборки, а кругом: собрали -> прочитали
 * своим же разбором (core/quic.c) -> вернули имя назад -> сравнили с
 * оригиналом ПОБАЙТНО. Круг ловит то, чего не видно глазом: пропущенную
 * длину в цепочке server_name, съеденный байт кадра CRYPTO, сбитую добивку.
 *
 * Вектор — RFC 9001 приложение A.2, из общего test_quic_vector.h: этот файл
 * проверяет НЕ разбор QUIC (он проверен в test_quic.c против текста RFC), а
 * сборку поверх него.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_hello.h"
#include "d2k_quic.h"
#include "d2k_quichello.h"
#include "d2k_quicconn.h"
#include "d2k_quicwire.h"
#include "test_quic_vector.h"

/* Расшифровывает собранный Initial. Нужна ровно одному вопросу — про два
 * кадра CRYPTO: там проверяется не то, что пакет ЧИТАЕТСЯ (это делает
 * d2k_quic_sni, и он кадры как раз пересобирает, то есть разрез от него
 * скрыт), а то, КАК пакет сложен внутри. */
static size_t open_initial(const uint8_t *p, size_t n, uint8_t *plain, size_t cap) {
    d2k_qw_hdr h;
    if (d2k_qw_hdr_parse(p, n, 0, &h) != 0 || cap < h.packet_len) { return 0; }
    d2k_qw_keys k;
    uint8_t sec[32];
    if (d2k_qw_initial_secret(h.version, p + h.dcid_off, h.dcid_len,
                              D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(h.version, sec, &k) != 0) { return 0; }
    size_t plen = 0;
    uint64_t pn = 0;
    if (d2k_qw_open(&k, &h, p, 0, plain, &plen, &pn) != 0) { return 0; }
    return plen;
}

/* Лежит ли игла в стоге ЦЕЛИКОМ. Своя, потому что memmem — расширение и под
 * -std=c99 его нет. */
static int contains(const uint8_t *hay, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0 || n < m) { return 0; }
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0) { return 1; }
    }
    return 0;
}

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

int main(int argc, char **argv) {
    /* Опциональный независимый Go-оракул читает только измерительный вход.
       Никаких соединений, даже для этого режима теста. */
    if (argc == 3 && (strcmp(argv[1], "--dump-probe-hello") == 0 ||
                      strcmp(argv[1], "--dump-probe") == 0)) {
        uint8_t packet[1500], hello[1500];
        size_t packet_len = 0, hello_len = 0;
        if (d2k_quic_probe_initial(argv[2], packet, sizeof packet, &packet_len) != 0 ||
            d2k_quic_client_hello(packet, packet_len, hello, sizeof hello, &hello_len) != 0) {
            return 2;
        }
        const uint8_t *bytes = strcmp(argv[1], "--dump-probe") == 0 ? packet : hello;
        size_t len = strcmp(argv[1], "--dump-probe") == 0 ? packet_len : hello_len;
        for (size_t i = 0; i < len; i++) { printf("%02x", bytes[i]); }
        puts("");
        return 0;
    }
    if (argc != 1) { return 2; }
    uint8_t out[2048];
    size_t out_len = 0;
    char name[256];

    /* --- ВОПРОС: ПРИВЕТСТВИЕ ДВУМЯ КАДРАМИ CRYPTO -----------------------
     *
     * Единственный из вопросов, который ломает РАЗБОР, а не сигнатуру. Кадр
     * CRYPTO несёт смещение в потоке (RFC 9000 §19.6), и кадры не обязаны
     * идти по возрастанию смещения: коробка, читающая приветствие подряд из
     * первого кадра, увидит обрывок. Точный аналог разреза TCP-потока.
     *
     * РЕЖЕМ ВНУТРИ ИМЕНИ, а не посередине буфера, и это не мелочь: коробку
     * ломает разрыв именно того, что она ищет, а разрыв в случайном месте —
     * нет. Проверяется это прямо: имени в открытом теле не должно остаться
     * ЦЕЛИКОМ. Круг через d2k_quic_sni такую ошибку не поймал бы вовсе — наш
     * разбор кадры пересобирает и вернёт имя при любом месте разреза.
     *
     * ХВОСТ ИДЁТ ПЕРВЫМ — по той же причине, по которой в TCP посылается
     * второй сегмент раньше первого. */
    {
        CHECK(d2k_quic_hello_ask(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                 D2K_QASK_SPLIT_CRYPTO, "www.microsoft.com",
                                 out, sizeof out, &out_len) == 0,
              "приветствие двумя кадрами CRYPTO не собралось");
        CHECK(d2k_quic_sni(out, out_len, name, sizeof name) == 0 &&
              strcmp(name, "www.microsoft.com") == 0,
              "разложенное приветствие не пересобирается — это мусор, а не вопрос");

        uint8_t plain[2048];
        size_t plen = open_initial(out, out_len, plain, sizeof plain);
        CHECK(plen > 0, "собранный пакет не расшифровался");
        CHECK(!contains(plain, plen, "www.microsoft.com"),
              "имя лежит в теле целиком — разрез пришёлся мимо имени");

        /* Ходим по кадрам руками: тест обязан смотреть на байты, а не
           спрашивать у того же кода, который их и сложил. */
        size_t off = 0, frames = 0;
        uint64_t first_off = 0, total = 0;
        while (off < plen && plain[off] == 0x06 && frames < 8) {
            uint64_t o = 0, l = 0;
            size_t w = 0;
            off++;
            if (d2k_qw_varint_read(plain + off, plen - off, &o, &w) != 0) { break; }
            off += w;
            if (d2k_qw_varint_read(plain + off, plen - off, &l, &w) != 0) { break; }
            off += w;
            if (frames == 0) { first_off = o; }
            frames++;
            total += l;
            off += (size_t)l;
        }
        CHECK(frames == 2, "приветствие уехало не двумя кадрами CRYPTO");
        CHECK(first_off > 0, "первым идёт начало приветствия — порядок кадров не обратный");

        uint8_t ch[2048];
        size_t ch_len = 0;
        CHECK(d2k_quic_client_hello(out, out_len, ch, sizeof ch, &ch_len) == 0 &&
              total == ch_len,
              "куски в сумме не дают целое приветствие");
    }

    /* --- ВОПРОС: ПРИВЕТСТВИЕ ДВУМЯ ДАТАГРАММАМИ ------------------------
     *
     * То же, что разрез на кадры, но половины уезжают РАЗНЫМИ датаграммами и
     * хвост первым. Разница принципиальная: кадры коробка хотя бы видит в
     * одном пакете и могла бы сложить, а две датаграммы надо ещё и связать
     * между собой — по DCID и по состоянию соединения. Так, между прочим,
     * шлёт и настоящий клиент: Chrome с постквантовым key_share и Firefox 137
     * по умолчанию.
     *
     * ГЛАВНОЕ ЗДЕСЬ — ОБЩИЙ DCID. Ключи Initial выводятся из него, и два
     * разных DCID означали бы два начатых соединения с половиной приветствия
     * в каждом: сервер не ответит ни на одно, а молчание запишут коробке.
     * Проверяется прямо побайтно, а не через «оба разобрались». */
    {
        uint8_t head[2048], tail[2048];
        size_t head_len = 0, tail_len = 0;
        CHECK(d2k_quic_hello_split(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                   "www.microsoft.com",
                                   head, sizeof head, &head_len,
                                   tail, sizeof tail, &tail_len) == 0,
              "приветствие двумя датаграммами не собралось");

        d2k_qw_hdr hh, ht;
        CHECK(d2k_qw_hdr_parse(head, head_len, 0, &hh) == 0 &&
              d2k_qw_hdr_parse(tail, tail_len, 0, &ht) == 0,
              "половины не разбираются как пакеты");
        CHECK(hh.dcid_len == ht.dcid_len && hh.dcid_len >= 8 &&
              memcmp(head + hh.dcid_off, tail + ht.dcid_off, hh.dcid_len) == 0,
              "у половин разный DCID — это два соединения по половине приветствия");
        CHECK(head_len >= 1200 && tail_len >= 1200,
              "половина короче 1200 байт — сервер обязан её отбросить (RFC 9000 §14.1)");

        /* Ни одна половина сама по себе имени не даёт — иначе разрез
           фиктивный. И в открытом теле каждой имени нет целиком: режем
           внутри него. */
        CHECK(d2k_quic_sni(head, head_len, name, sizeof name) != 0,
              "голова одна даёт имя целиком — разрез фиктивный");
        uint8_t plain[2048];
        size_t plen = open_initial(head, head_len, plain, sizeof plain);
        CHECK(plen > 0 && !contains(plain, plen, "www.microsoft.com"),
              "имя лежит целиком в голове");
        plen = open_initial(tail, tail_len, plain, sizeof plain);
        CHECK(plen > 0 && !contains(plain, plen, "www.microsoft.com"),
              "имя лежит целиком в хвосте");

        /* Две пары подряд — разные соединения: DCID свежий на каждый вызов,
           иначе три параллельные попытки снова станут одной (замер 13.09). */
        uint8_t head2[2048], tail2[2048];
        size_t h2 = 0, t2 = 0;
        CHECK(d2k_quic_hello_split(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                   "www.microsoft.com",
                                   head2, sizeof head2, &h2,
                                   tail2, sizeof tail2, &t2) == 0,
              "вторая пара не собралась");
        CHECK(memcmp(head, head2, head_len < h2 ? head_len : h2) != 0,
              "две пары вышли одинаковыми — DCID не свежий");
    }

    /* --- ВОПРОС: ПОГАШЕННЫЙ ФИКСИРОВАННЫЙ БИТ --------------------------
     *
     * По RFC 9000 §17.2 второй по старшинству бит первого байта обязан быть
     * единицей, и коробка обычно по нему отличает QUIC от прочего UDP.
     * RFC 9287 разрешает его гасить — а значит и спросить коробку, смотрит
     * ли она на него.
     *
     * Бит проверяется ПРЯМО В СОБРАННОМ ПАКЕТЕ: защита заголовка (RFC 9001
     * §5.4.1) маскирует у длинного заголовка только младшие четыре бита,
     * фиксированного не касается.
     *
     * И пакет обязан остаться РАЗБИРАЕМЫМ: вопрос меняет один бит, а не
     * ломает приветствие. Иначе молчание коробки означало бы «мы послали
     * мусор», а не «она смотрит на бит». */
    {
        CHECK(d2k_quic_hello_ask(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                 D2K_QASK_CLEAR_FIXED_BIT, "www.microsoft.com",
                                 out, sizeof out, &out_len) == 0,
              "приветствие с погашенным фиксированным битом не собралось");
        CHECK((out[0] & 0x40) == 0, "фиксированный бит не погашен — вопрос не задан");
        CHECK(d2k_quic_sni(out, out_len, name, sizeof name) == 0 &&
              strcmp(name, "www.microsoft.com") == 0,
              "пакет перестал разбираться: молчание означало бы мусор, а не свойство коробки");

        /* И ПЕРЕСБОРКА ПОД НОВОЕ СОЕДИНЕНИЕ ОБЯЗАНА БИТ СОХРАНИТЬ.
           Каждая параллельная попытка вопроса уходит через
           d2k_quic_hello_recid — свой DCID на соединение, иначе сервер
           считает три одинаковые датаграммы одной (замер 13.09, 1/3). А
           заголовок он собирает ЗАНОВО, то есть поставил бы бит обратно.
           Вопрос требует единогласия 3/3, значит свойство «коробка смотрит
           на бит» не подтвердилось бы никогда, и молчание списали бы на
           коробку — вывод из собственной ошибки, а не из сети. */
        uint8_t again[2048];
        size_t again_len = 0;
        CHECK(d2k_quic_hello_recid(out, out_len, again, sizeof again, &again_len) == 0,
              "пакет с погашенным битом не пересобрался под новое соединение");
        CHECK((again[0] & 0x40) == 0,
              "пересборка вернула фиксированный бит — вопрос уехал бы незаданным");
        CHECK(d2k_quic_sni(again, again_len, name, sizeof name) == 0 &&
              strcmp(name, "www.microsoft.com") == 0,
              "пересобранный пакет с погашенным битом не разбирается");
    }

    /* --- ВОПРОС: ВТОРАЯ ВЕРСИЯ QUIC ------------------------------------
     *
     * У второй версии (RFC 9369) другая соль вывода начального секрета,
     * другие метки ключей и перенумерованы типы пакетов. Коробка, зашитая на
     * первую версию, такой Initial не расшифрует вовсе — а сервер, знающий
     * обе, разберёт.
     *
     * Проверяем и поле версии, и то, что пакет собран ключами ВТОРОЙ версии:
     * поставить в заголовок другое число, а запечатать по-старому — это не
     * вопрос про версию, это битый пакет. Разбор идёт тем же d2k_quic_sni,
     * который выводит ключи из версии в заголовке: сойдётся он только если
     * версия и ключи согласованы. */
    {
        CHECK(d2k_quic_hello_ask(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                 D2K_QASK_VERSION2, "www.microsoft.com",
                                 out, sizeof out, &out_len) == 0,
              "приветствие второй версии не собралось");
        CHECK(out[1] == 0x6b && out[2] == 0x33 && out[3] == 0x43 && out[4] == 0xcf,
              "в заголовке не версия 2 (RFC 9369 §3.1)");
        CHECK(d2k_quic_sni(out, out_len, name, sizeof name) == 0 &&
              strcmp(name, "www.microsoft.com") == 0,
              "пакет не разбирается ключами второй версии — версия сменена только на бумаге");
    }

    /* --- ВОПРОС: ДАТАГРАММА ДЛИННЕЕ ОБЫЧНОЙ ----------------------------
     *
     * Единственный из приёмов, который правит САМ ПАКЕТ, а не добавляет
     * соседей. По RFC 9000 §12.2 приёмник разбирает первый пакет по его полю
     * длины, а неразобранный хвост датаграммы отбрасывает — значит добивку
     * сервер съест молча, а коробка, отбирающая трафик по размеру, может
     * такую датаграмму и не тронуть.
     *
     * Сто байт — число оригинала (questions.go: 1300 против 1200). Проверяем
     * не его, а СВОЙСТВО: датаграмма стала длиннее снимка ровно на столько и
     * осталась разбираемой. */
    {
        CHECK(d2k_quic_hello_ask(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                 D2K_QASK_LONGER, "www.microsoft.com",
                                 out, sizeof out, &out_len) == 0,
              "удлинённое приветствие не собралось");
        CHECK(out_len == sizeof d2k_test_v1_initial + 100,
              "датаграмма не стала длиннее ровно на сто байт");
        CHECK(d2k_quic_sni(out, out_len, name, sizeof name) == 0 &&
              strcmp(name, "www.microsoft.com") == 0,
              "удлинённый пакет не разбирается");
    }

    /* --- круг: собрали, прочитали, вернули имя, сравнили побайтно ------- */
    {
        CHECK(d2k_quic_hello_rename(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                    "www.microsoft.com", out, sizeof out, &out_len) == 0,
              "приветствие с другим именем не собралось");
        CHECK(out_len == sizeof d2k_test_v1_initial,
              "длина датаграммы не сохранена — по ней коробка отличает приветствие");
        CHECK(d2k_quic_is_initial(out, out_len) == 1,
              "собранное не узнаётся как Initial собственным же разбором");
        CHECK(d2k_quic_sni(out, out_len, name, sizeof name) == 0 &&
              strcmp(name, "www.microsoft.com") == 0,
              "из собранного не достаётся подставленное имя");

        /* DCID обязан быть СВЕЖИМ: повтор чужого — это второй Initial ЧУЖОГО
           соединения, а не наш вопрос. Лежит он сразу за первым байтом,
           версией и длиной (1+4+1). */
        CHECK(memcmp(out + 6, d2k_test_v1_initial + 6, 8) != 0,
              "DCID повторён из снимка — вопрос уехал бы в чужое соединение");
        /* SCID — НАОБОРОТ, дословно из снимка: клиент объявляет его внутри
           приветствия (initial_source_connection_id, RFC 9000 §7.3), и
           сервер сличает. Свежий SCID в заголовке при старом в приветствии
           получил бы в ответ закрытие соединения, а не ответ на вопрос.
           В векторе A.2 SCID пустой, поэтому проверяем ДЛИНУ: она обязана
           совпасть с длиной из снимка. */
        {
            d2k_qw_hdr h0, h1;
            CHECK(d2k_qw_hdr_parse(d2k_test_v1_initial, sizeof d2k_test_v1_initial, 0, &h0) == 0 &&
                  d2k_qw_hdr_parse(out, out_len, 0, &h1) == 0,
                  "заголовки снимка и собранного не разобрались");
            CHECK(h1.scid_len == h0.scid_len &&
                  (h0.scid_len == 0 ||
                   memcmp(out + h1.scid_off, d2k_test_v1_initial + h0.scid_off, h0.scid_len) == 0),
                  "SCID не перенесён из снимка — сервер ответит закрытием, а не ответом");
        }

        /* И обратно: вернув исходное имя, обязаны получить ТОТ ЖЕ
           ClientHello побайтно. Это и есть доказательство, что кроме имени
           не поехало ничего. */
        uint8_t back[2048];
        size_t back_len = 0;
        CHECK(d2k_quic_hello_rename(out, out_len, "example.com",
                                    back, sizeof back, &back_len) == 0,
              "обратная подстановка имени не собралась");
        uint8_t ch0[2048], ch1[2048];
        size_t n0 = 0, n1 = 0;
        CHECK(d2k_quic_client_hello(d2k_test_v1_initial, sizeof d2k_test_v1_initial, ch0, sizeof ch0, &n0) == 0,
              "открытый ClientHello не достался из вектора");
        CHECK(d2k_quic_client_hello(back, back_len, ch1, sizeof ch1, &n1) == 0,
              "открытый ClientHello не достался из собранного");
        CHECK(n0 == n1 && memcmp(ch0, ch1, n0) == 0,
              "круг не сошёлся побайтно: поехало что-то кроме имени");
    }

    /* --- имя ДЛИННЕЕ и КОРОЧЕ исходного: длины пересчитываются ----------
     * Цепочка длин у server_name четырёхзвенная, и пропуск любого звена
     * оставляет приветствие похожим на валидное. Разбор поймает. */
    {
        CHECK(d2k_quic_hello_rename(d2k_test_v1_initial, sizeof d2k_test_v1_initial, "a.io",
                                    out, sizeof out, &out_len) == 0 &&
              d2k_quic_sni(out, out_len, name, sizeof name) == 0 &&
              strcmp(name, "a.io") == 0,
              "короткое имя не подставилось");
        CHECK(d2k_quic_hello_rename(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                    "very.long.name.example.museum.invalid",
                                    out, sizeof out, &out_len) == 0 &&
              d2k_quic_sni(out, out_len, name, sizeof name) == 0 &&
              strcmp(name, "very.long.name.example.museum.invalid") == 0,
              "длинное имя не подставилось");
        CHECK(out_len == sizeof d2k_test_v1_initial,
              "длинное имя сдвинуло длину датаграммы");
    }

    /* --- ТОТ ЖЕ СНИМОК, ДРУГОЕ СОЕДИНЕНИЕ -------------------------------
     *
     * Три параллельные попытки одного вопроса были побайтно одинаковыми, и
     * сервер засчитывал первую, роняя остальные как повтор (замер 13.09.2026,
     * www.google.com: 1/3). Здесь проверяется, что новая датаграмма — ТОТ ЖЕ
     * снимок во всём, кроме идентификатора назначения. */
    {
        uint8_t a[2048], b[2048];
        size_t alen = 0, blen = 0;
        CHECK(d2k_quic_hello_recid(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                   a, sizeof a, &alen) == 0,
              "снимок с новым идентификатором не собрался");
        CHECK(alen == sizeof d2k_test_v1_initial, "длина датаграммы изменилась");
        CHECK(memcmp(a, d2k_test_v1_initial, alen) != 0,
              "байты не изменились вовсе — идентификатор тот же, сервер сочтёт повтором");
        CHECK(d2k_quic_sni(a, alen, name, sizeof name) == 0 &&
              strcmp(name, "example.com") == 0,
              "имя не пережило смену идентификатора");

        /* Содержимое обязано совпасть ПОБАЙТНО — не только имя: порядок
           кадров, добивка, всё. Сверяем открытый ClientHello целиком. */
        uint8_t ch0[2048], ch1[2048];
        size_t n0 = 0, n1 = 0;
        CHECK(d2k_quic_client_hello(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                    ch0, sizeof ch0, &n0) == 0 &&
              d2k_quic_client_hello(a, alen, ch1, sizeof ch1, &n1) == 0 &&
              n0 == n1 && memcmp(ch0, ch1, n0) == 0,
              "приветствие внутри изменилось при смене идентификатора");

        /* Две подряд обязаны отличаться друг от друга: идентификатор берётся
           заново каждый раз, иначе три попытки снова станут одной. */
        CHECK(d2k_quic_hello_recid(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                   b, sizeof b, &blen) == 0, "вторая копия не собралась");
        CHECK(alen == blen && memcmp(a, b, alen) != 0,
              "две копии вышли одинаковыми — идентификатор не свежий");

        /* SCID остаётся своим — его клиент объявил внутри приветствия. */
        {
            d2k_qw_hdr h0, h1;
            CHECK(d2k_qw_hdr_parse(d2k_test_v1_initial, sizeof d2k_test_v1_initial, 0, &h0) == 0 &&
                  d2k_qw_hdr_parse(a, alen, 0, &h1) == 0 &&
                  h1.scid_len == h0.scid_len,
                  "длина SCID не сохранена");
        }

        /* Не Initial и чужая версия — честный отказ: зонд согласования версий
           шлёт Initial заведомо чужой версии, и трогать его нельзя. */
        uint8_t alien[1200];
        memcpy(alien, d2k_test_v1_initial, sizeof alien);
        alien[1] = 0x0a; alien[2] = 0x0a; alien[3] = 0x0a; alien[4] = 0x0a;
        CHECK(d2k_quic_hello_recid(alien, sizeof alien, a, sizeof a, &alen) != 0,
              "Initial чужой версии пересобран — соль для неё неизвестна");
    }

    /* --- непригодный вход: отказ, а не догадка -------------------------- */
    {
        uint8_t junk[1200];
        memset(junk, 0x5a, sizeof junk);
        CHECK(d2k_quic_hello_rename(junk, sizeof junk, "a.io", out, sizeof out, &out_len) != 0,
              "мусор сошёл за приветствие");
        CHECK(d2k_quic_hello_rename(d2k_test_v1_initial, 200, "a.io", out, sizeof out, &out_len) != 0,
              "обрезанная датаграмма сошла за приветствие");
        CHECK(d2k_quic_hello_rename(d2k_test_v1_initial, sizeof d2k_test_v1_initial, "", out, sizeof out, &out_len) != 0,
              "пустое имя принято за имя");
        CHECK(d2k_quic_hello_rename(d2k_test_v1_initial, sizeof d2k_test_v1_initial, "a.io", out, 100, &out_len) != 0,
              "результат втиснут в буфер, куда он не помещается");
    }

    /* --- длинный заголовок: собранное читается разбором ------------------
     * d2k_qw_long_hdr вынесен в проводной слой из quicconn (там он был
     * static и второй сборщик Initial завёл бы его копию). Проверка —
     * кругом же: собрать заголовок и разобрать его обратно. */
    {
        uint8_t dcid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        uint8_t scid[4] = { 9, 10, 11, 12 };
        uint8_t hdr[64];
        size_t hlen = d2k_qw_long_hdr(hdr, sizeof hdr, D2K_QW_V1, D2K_QW_LT_INITIAL,
                                      dcid, sizeof dcid, scid, sizeof scid, 1, 100);
        CHECK(hlen > 0, "длинный заголовок не собрался");
        /* Дописываем столько байт, сколько обещает поле Length, — разбор
           проверяет, что пакет помещается целиком. */
        uint8_t pkt[256];
        memcpy(pkt, hdr, hlen);
        memset(pkt + hlen, 0, sizeof pkt - hlen);
        d2k_qw_hdr h;
        CHECK(d2k_qw_hdr_parse(pkt, hlen + 1 + 100 + 16, 0, &h) == 0,
              "собранный заголовок не разобрался");
        CHECK(h.long_hdr && h.type == D2K_QW_LT_INITIAL && h.version == D2K_QW_V1,
              "разбор вернул другой тип или версию");
        CHECK(h.dcid_len == sizeof dcid && memcmp(pkt + h.dcid_off, dcid, sizeof dcid) == 0,
              "DCID не совпал после круга");
        CHECK(h.scid_len == sizeof scid && memcmp(pkt + h.scid_off, scid, sizeof scid) == 0,
              "SCID не совпал после круга");
        CHECK(h.packet_len == hlen + 1 + 100 + 16, "длина пакета не сошлась");

        /* Версия 2 нумерует типы иначе (RFC 9369 §3.2). Сборка обязана
           написать номер ЭТОЙ версии, а разбор — вернуть его к номеру v1;
           иначе Initial версии 2 собрался бы как 0-RTT молча. */
        hlen = d2k_qw_long_hdr(hdr, sizeof hdr, D2K_QW_V2, D2K_QW_LT_INITIAL,
                               dcid, sizeof dcid, scid, sizeof scid, 1, 100);
        CHECK(hlen > 0, "длинный заголовок версии 2 не собрался");
        memcpy(pkt, hdr, hlen);
        CHECK(d2k_qw_hdr_parse(pkt, hlen + 1 + 100 + 16, 0, &h) == 0 &&
              h.type == D2K_QW_LT_INITIAL && h.version == D2K_QW_V2,
              "тип Initial версии 2 не пережил круг сборка-разбор");
    }

    /* Измерительный вход отделён от клиента подтверждения. Независимая
       сверка ВСЕХ байтов с донором — scripts/check-quic-input-parity.sh. */
    {
        uint8_t first[1500], second[1500], hello[1500];
        size_t fl = 0, sl = 0, hl = 0;
        CHECK(d2k_quic_probe_initial("measure.example", first, sizeof first, &fl) == 0 && fl == 1200,
              "измерительный Initial оригинала не собрался в 1200 байт");
        CHECK(d2k_quic_sni(first, fl, name, sizeof name) == 0 && strcmp(name, "measure.example") == 0,
              "Initial оригинала не раскрывается или потерял имя");
        CHECK(d2k_quic_client_hello(first, fl, hello, sizeof hello, &hl) == 0 && hl > 0,
              "Initial оригинала не содержит полного ClientHello");
        CHECK(d2k_quic_probe_initial("measure.example", second, sizeof second, &sl) == 0 &&
              sl == fl && memcmp(first, second, fl) != 0,
              "измерительный Initial повторяет случайность другого опыта");
        CHECK(d2k_quic_probe_initial("measure.example", first, 1199, &fl) != 0 && fl == 0,
              "измерительный Initial обрезан до слишком малого буфера");
        CHECK(d2k_quic_probe_initial("", first, sizeof first, &fl) != 0,
              "безымянной цели выдуман именованный измерительный вход");
    }

    /* ПЕРВЫЙ INITIAL СВОИМ СТЕКОМ — БАЙТЫ, А НЕ СОЕДИНЕНИЕ.
       Нужен приманкой голоса: коробка узнаёт голос по первому пакету потока,
       а боевой профиль z2k ставит перед ним Initial QUIC чужим блобом
       (quic_dbankcloud). Чужих блобов d2k не берёт; настоящий Initial у него
       свой — тот же, что уходит от зонда подтверждения QUIC. Проверяется он
       собственным же разбором: раскрывается ключами из своего DCID и отдаёт
       заданное имя. */
    {
        uint8_t ini[1500];
        size_t il = 0;
        CHECK(d2k_qc_first_initial("decoy.example", ini, sizeof ini, &il) == 0,
              "первый Initial не собрался");
        CHECK(il >= 1200, "первый Initial короче 1200 байт — сервер вправе его не обслуживать");
        CHECK(d2k_quic_is_initial(ini, il), "собранное не похоже на Initial");
        char name[256];
        CHECK(d2k_quic_sni(ini, il, name, sizeof name) == 0 &&
              strcmp(name, "decoy.example") == 0,
              "собственный разбор не раскрыл собранный Initial или имя не то");
        uint8_t again[1500];
        size_t al = 0;
        CHECK(d2k_qc_first_initial("decoy.example", again, sizeof again, &al) == 0 &&
              (al != il || memcmp(again, ini, il) != 0),
              "два Initial совпали байт в байт — случайности в них нет");
        CHECK(d2k_qc_first_initial("decoy.example", ini, 100, &il) != 0,
              "Initial «собрался» в буфер на 100 байт");
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("приветствие QUIC с другим именем: все проверки прошли\n");
    return 0;
}
