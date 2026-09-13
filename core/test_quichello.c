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
#include "d2k_quicwire.h"
#include "test_quic_vector.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

int main(void) {
    uint8_t out[2048];
    size_t out_len = 0;
    char name[256];

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

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("приветствие QUIC с другим именем: все проверки прошли\n");
    return 0;
}
