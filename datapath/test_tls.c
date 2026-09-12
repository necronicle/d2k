/* test_tls.c — распознавание TLS и вычисление якорей.
 *
 * Модуль отвечает на один вопрос: где в этих байтах лежит то, на что
 * ссылается план. Всё, чего он не может ответить уверенно, он объявляет
 * неизвестным — и исполнитель тогда отказывает, а не берёт нулевое смещение.
 *
 * Поэтому проверок на «не распознал» здесь больше, чем на «распознал»: вход
 * приходит из сети, и уверенный неправильный ответ хуже честного «не знаю».
 */
#include <stdio.h>
#include <string.h>
#include "d2k_tls.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Собирает настоящий ClientHello с указанным именем. Пишет длину в *len. */
static size_t build_hello(uint8_t *out, const char *sni, int with_sni_ext) {
    uint8_t body[512];
    size_t b = 0;

    body[b++] = 0x03; body[b++] = 0x03;              /* client_version */
    for (int i = 0; i < 32; i++) body[b++] = (uint8_t)i;   /* random */
    body[b++] = 32;
    for (int i = 0; i < 32; i++) body[b++] = (uint8_t)i;   /* session id */

    static const uint8_t suites[] = {0x13,0x01,0x13,0x02,0x13,0x03};
    body[b++] = 0x00; body[b++] = sizeof suites;
    memcpy(body + b, suites, sizeof suites); b += sizeof suites;

    body[b++] = 0x01; body[b++] = 0x00;              /* compression */

    uint8_t exts[256];
    size_t e = 0;
    if (with_sni_ext) {
        size_t nl = strlen(sni);
        size_t entry = 1 + 2 + nl;
        size_t list = 2 + entry;
        exts[e++] = 0x00; exts[e++] = 0x00;                       /* server_name */
        exts[e++] = (uint8_t)(list >> 8); exts[e++] = (uint8_t)list;
        exts[e++] = (uint8_t)(entry >> 8); exts[e++] = (uint8_t)entry;
        exts[e++] = 0x00;                                          /* host_name */
        exts[e++] = (uint8_t)(nl >> 8); exts[e++] = (uint8_t)nl;
        memcpy(exts + e, sni, nl); e += nl;
    }
    /* supported_versions — чтобы расширение было не одно. */
    exts[e++] = 0x00; exts[e++] = 0x2b;
    exts[e++] = 0x00; exts[e++] = 0x03;
    exts[e++] = 0x02; exts[e++] = 0x03; exts[e++] = 0x04;

    body[b++] = (uint8_t)(e >> 8); body[b++] = (uint8_t)e;
    memcpy(body + b, exts, e); b += e;

    size_t o = 0;
    out[o++] = 0x16; out[o++] = 0x03; out[o++] = 0x01;
    out[o++] = (uint8_t)((b + 4) >> 8); out[o++] = (uint8_t)(b + 4);
    out[o++] = 0x01;
    out[o++] = 0x00; out[o++] = (uint8_t)(b >> 8); out[o++] = (uint8_t)b;
    memcpy(out + o, body, b); o += b;
    return o;
}


/* Настоящее приветствие, порождённое openssl (ya.ru, TLS 1.3, 301 байт).
 *
 * Взято из независимого источника намеренно: остальные проверки строят
 * приветствия ЭТИМ ЖЕ файлом, и если бы строитель и разборщик разделяли одно
 * неверное допущение, тест бы этого не увидел. Позиция имени сверена третьей
 * стороной — поиском подстроки по сырым байтам: 244, длина 5.
 *
 * Внутри GREASE, десяток расширений и порядок полей настоящего клиента, а не
 * учебный минимум.
 */
static const uint8_t real_hello[] = {
    0x16, 0x03, 0x01, 0x01, 0x28, 0x01, 0x00, 0x01, 0x24, 0x03, 0x03, 0xaa,
    0x3a, 0xf7, 0x6c, 0x66, 0x8b, 0xf7, 0xda, 0x65, 0x69, 0x34, 0x2a, 0xdb,
    0x32, 0xb7, 0xd3, 0xc9, 0x83, 0x4e, 0x53, 0x18, 0xfd, 0x06, 0xf8, 0x63,
    0x97, 0xd1, 0x85, 0x11, 0x89, 0x2a, 0x8e, 0x20, 0xcf, 0x29, 0x77, 0x95,
    0x8a, 0x6d, 0x8b, 0xe1, 0xc0, 0xde, 0x50, 0x0e, 0x15, 0xc0, 0x88, 0x67,
    0xab, 0x21, 0x78, 0xe1, 0x06, 0x66, 0xad, 0x6d, 0x98, 0x80, 0x44, 0xee,
    0x8b, 0xed, 0x5e, 0xe0, 0x00, 0x62, 0x13, 0x03, 0x13, 0x02, 0x13, 0x01,
    0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x30, 0xc0, 0x2c, 0xc0, 0x28,
    0xc0, 0x24, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9f, 0x00, 0x6b, 0x00, 0x39,
    0xff, 0x85, 0x00, 0xc4, 0x00, 0x88, 0x00, 0x81, 0x00, 0x9d, 0x00, 0x3d,
    0x00, 0x35, 0x00, 0xc0, 0x00, 0x84, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x27,
    0xc0, 0x23, 0xc0, 0x13, 0xc0, 0x09, 0x00, 0x9e, 0x00, 0x67, 0x00, 0x33,
    0x00, 0xbe, 0x00, 0x45, 0x00, 0x9c, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0xba,
    0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05, 0x00, 0x04, 0xc0, 0x12,
    0xc0, 0x08, 0x00, 0x16, 0x00, 0x0a, 0x00, 0xff, 0x01, 0x00, 0x00, 0x79,
    0x00, 0x2b, 0x00, 0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03,
    0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xad,
    0xaa, 0x8e, 0x43, 0x8f, 0x0f, 0xff, 0x60, 0xa4, 0x27, 0x9a, 0x5b, 0x23,
    0x88, 0x42, 0x72, 0x1e, 0xb5, 0xee, 0xd2, 0x63, 0x4f, 0xc3, 0xe5, 0x96,
    0x03, 0x73, 0xb9, 0xa2, 0x44, 0x22, 0x6b, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x08, 0x00, 0x00, 0x05, 0x79, 0x61, 0x2e, 0x72, 0x75, 0x00, 0x0b, 0x00,
    0x02, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00,
    0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x18, 0x00, 0x16, 0x08, 0x06, 0x06, 0x01, 0x06, 0x03, 0x08, 0x05, 0x05,
    0x01, 0x05, 0x03, 0x08, 0x04, 0x04, 0x01, 0x04, 0x03, 0x02, 0x01, 0x02,
    0x03,
};

static void check_real_hello(void) {
    d2k_tls_info info;
    memset(&info, 0, sizeof info);
    CHECK(d2k_tls_parse(real_hello, sizeof real_hello, &info) == 0,
          "настоящее приветствие openssl не разобралось");
    CHECK(info.is_client_hello == 1, "настоящее приветствие не признано ClientHello");
    CHECK(info.have_sni == 1, "имя в настоящем приветствии не найдено");
    CHECK(info.sni_off == 244, "смещение имени разошлось с независимым поиском");
    CHECK(info.sni_len == 5, "длина имени разошлась с независимым поиском");
    CHECK(memcmp(real_hello + info.sni_off, "ya.ru", 5) == 0, "по смещению лежит не имя");
    CHECK(info.have_record_end == 1 && info.record_end == sizeof real_hello,
          "конец записи настоящего приветствия неверен");
}


/* Приветствие с набивкой: так выглядит браузерное, где расширение padding
   доводит запись до полутора килобайт и больше. */
static size_t build_hello_padded(uint8_t *out, const char *sni, size_t pad) {
    uint8_t body[4096];
    size_t b = 0;
    body[b++] = 0x03; body[b++] = 0x03;
    for (int i = 0; i < 32; i++) { body[b++] = (uint8_t)i; }
    body[b++] = 0;
    body[b++] = 0x00; body[b++] = 0x02; body[b++] = 0x13; body[b++] = 0x01;
    body[b++] = 0x01; body[b++] = 0x00;

    uint8_t ext[4096];
    size_t e = 0;
    size_t nl = strlen(sni);
    /* server_name первым: у браузера оно тоже в начале блока расширений. */
    ext[e++] = 0x00; ext[e++] = 0x00;
    ext[e++] = 0x00; ext[e++] = (uint8_t)(5 + nl);
    ext[e++] = 0x00; ext[e++] = (uint8_t)(3 + nl);
    ext[e++] = 0x00;
    ext[e++] = 0x00; ext[e++] = (uint8_t)nl;
    memcpy(ext + e, sni, nl); e += nl;
    /* padding (21) в конце — то, что и раздувает браузерное приветствие. */
    ext[e++] = 0x00; ext[e++] = 0x15;
    ext[e++] = (uint8_t)(pad >> 8); ext[e++] = (uint8_t)pad;
    memset(ext + e, 0, pad); e += pad;

    body[b++] = (uint8_t)(e >> 8); body[b++] = (uint8_t)e;
    memcpy(body + b, ext, e); b += e;

    size_t o = 0;
    out[o++] = 0x16; out[o++] = 0x03; out[o++] = 0x01;
    out[o++] = (uint8_t)((b + 4) >> 8); out[o++] = (uint8_t)(b + 4);
    out[o++] = 0x01;
    out[o++] = (uint8_t)(b >> 16); out[o++] = (uint8_t)(b >> 8); out[o++] = (uint8_t)b;
    memcpy(out + o, body, b); o += b;
    return o;
}

int main(void) {
    uint8_t buf[1024];
    d2k_tls_info info;

    /* --- нормальный ClientHello --------------------------------------- */
    size_t n = build_hello(buf, "hetzner.com", 1);
    memset(&info, 0, sizeof info);
    CHECK(d2k_tls_parse(buf, n, &info) == 0, "настоящий ClientHello не распознан");
    CHECK(info.is_client_hello == 1, "не помечен как ClientHello");
    CHECK(info.have_sni == 1, "имя не найдено");
    CHECK(info.sni_len == 11, "длина имени неверна");
    CHECK(memcmp(buf + info.sni_off, "hetzner.com", 11) == 0, "смещение имени указывает не туда");
    CHECK(info.have_record_end == 1, "конец записи не вычислен");
    CHECK(info.record_end == n, "конец записи не совпал с длиной");

    /* --- ClientHello без расширения имени ------------------------------ */
    n = build_hello(buf, "", 0);
    memset(&info, 0, sizeof info);
    CHECK(d2k_tls_parse(buf, n, &info) == 0, "hello без SNI обязан разбираться");
    CHECK(info.is_client_hello == 1, "не помечен как ClientHello");
    CHECK(info.have_sni == 0, "имени нет, но модуль его нашёл");
    /* Отсутствие имени — не ошибка: так выглядит ECH и часть клиентов.
       Исполнитель откажет сам, если план просит якорь по имени. */

    /* --- обрезанная запись --------------------------------------------- */
    n = build_hello(buf, "hetzner.com", 1);
    memset(&info, 0, sizeof info);
    CHECK(d2k_tls_parse(buf, n - 20, &info) == 0, "обрезанный вход не должен ронять разбор");
    CHECK(info.have_sni == 0, "имя выдано из обрезанной записи");
    CHECK(info.have_record_end == 0, "конец записи выдан для обрезанной записи");

    /* --- не TLS вовсе --------------------------------------------------- */
    memset(&info, 0, sizeof info);
    CHECK(d2k_tls_parse((const uint8_t *)"GET / HTTP/1.1\r\n", 16, &info) == 0,
          "не-TLS не должен быть ошибкой разбора");
    CHECK(info.is_client_hello == 0, "HTTP принят за ClientHello");

    /* --- запись TLS, но не рукопожатие ---------------------------------- */
    {
        uint8_t app[] = {0x17, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB};
        memset(&info, 0, sizeof info);
        CHECK(d2k_tls_parse(app, sizeof app, &info) == 0, "запись данных не должна быть ошибкой");
        CHECK(info.is_client_hello == 0, "запись данных принята за ClientHello");
        CHECK(info.have_record_end == 1, "конец записи данных обязан вычисляться");
        CHECK(info.record_end == sizeof app, "конец записи данных неверен");
    }

    /* --- рукопожатие, но не ClientHello --------------------------------- */
    {
        uint8_t sh[] = {0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00};
        memset(&info, 0, sizeof info);
        CHECK(d2k_tls_parse(sh, sizeof sh, &info) == 0, "ServerHello не должен быть ошибкой");
        CHECK(info.is_client_hello == 0, "ServerHello принят за ClientHello");
    }

    /* --- враньё в длине расширений -------------------------------------- */
    n = build_hello(buf, "hetzner.com", 1);
    memset(&info, 0, sizeof info);
    /* Длина блока расширений — два байта прямо перед первым расширением.
       Задираем её выше остатка: разбор обязан остановиться, а не читать за
       буфером. Позиция вычисляется так же, как её вычисляет разбор. */
    {
        size_t hs = 5;                      /* заголовок записи */
        size_t body = hs + 4;               /* заголовок рукопожатия */
        size_t off = body + 2 + 32;         /* версия и random */
        off += 1 + buf[off];                /* session id */
        off += 2 + ((size_t)buf[off] << 8 | buf[off + 1]); /* наборы шифров */
        off += 1 + buf[off];                /* сжатие */
        buf[off] = 0x7f; buf[off + 1] = 0xff;
    }
    CHECK(d2k_tls_parse(buf, n, &info) == 0, "враньё в длине не должно ронять разбор");
    CHECK(info.have_sni == 0, "имя выдано из записи с враньём в длине");

    check_real_hello();

    /* --- приветствие браузера: запись не влезает в один сегмент ------------
     * Приветствие curl — 322 байта и влезает. Приветствие браузера — 1700 с
     * лишним из-за GREASE и набивки, на PPPoE не влезает в MSS и приходит
     * ДВУМЯ сегментами. Разборщик, который требует запись целиком, у браузера
     * не узнаёт ничего — а браузер это и есть пользователь.
     *
     * Имя при этом лежит в первом сегменте: расширения идут после наборов
     * шифров, а набивка — в конце. Значит узнать цель можно, не собирая
     * запись целиком, и §5.2 говорит про ОГРАНИЧЕННУЮ пересборку именно
     * потому, что полная тут не нужна.                                      */
    {
        uint8_t big[4096];
        size_t n = build_hello_padded(big, "instagram.com", 1600);
        /* Обрезаем как MSS: даём разборщику только первый сегмент. */
        size_t seg = 1400;
        CHECK(n > seg, "приветствие в проверке влезло в сегмент — проверять нечего");
        d2k_tls_info info;
        d2k_tls_parse(big, seg, &info);
        CHECK(info.is_tls_record, "обрезанная запись не признана записью TLS");
        CHECK(info.is_client_hello,
              "приветствие браузера не узнано: запись не влезла в сегмент");
        CHECK(info.have_sni, "имя не найдено, хотя лежит в первом сегменте");
        if (info.have_sni) {
            CHECK(info.sni_len == 13 &&
                  memcmp(big + info.sni_off, "instagram.com", 13) == 0,
                  "имя из обрезанного приветствия прочиталось неверно");
        }
        /* А конец записи честно неизвестен: он за пределами сегмента. */
        CHECK(!info.have_record_end,
              "конец записи объявлен известным, хотя он за пределами сегмента");

        /* И ФОРМА тоже неизвестна. Блок расширений оборван, значит
           supported_versions мог уехать во второй сегмент — «признака не
           нашли» тут не значит «клиент не умеет TLS 1.3». Первая редакция
           выдавала уверенный LEGACY, и он уезжал в каталог и в ограничение
           применения плана. */
        CHECK(info.exts_truncated,
              "оборванный блок расширений не объявлен оборванным");
        CHECK(!info.is_tls13,
              "форма объявлена по оборванному блоку — выдуманный замер");
    }

    /* --- ОТВЕТ СЕРВЕРА: приёмка вопроса --------------------------------
     *
     * Донор считает доказательством прохода ТОЛЬКО ServerHello
     * (acceptServerHello, z2k-detect/internal/classify/trigger.go:67-70:
     * len>=6 && b[0]==0x16 && b[1]==0x03 && b[5]==0x02). Алерт сюда не
     * годится, хотя это тоже ответ: его инжектируют и сами коробки, и
     * засчитав его за успех мы объявили бы блокировку обходом.
     *
     * Проверяем все четыре случая из списка приёмки U1: годный ответ, алерт,
     * мусор и оборванная запись. */
    {
        d2k_tls_info si;

        /* Годный: запись рукопожатия, тело 42 байта, рукопожатие 0x02 длиной
           38 — минимально возможное тело ServerHello (RFC 8446 §4.1.3) и
           укладывается в обещание записи. */
        uint8_t ok[47];
        memset(ok, 0, sizeof ok);
        ok[0] = 0x16; ok[1] = 0x03; ok[2] = 0x03; ok[3] = 0x00; ok[4] = 0x2A;
        ok[5] = 0x02; ok[6] = 0x00; ok[7] = 0x00; ok[8] = 0x26;
        CHECK(d2k_tls_parse(ok, sizeof ok, &si) == 0 && si.is_server_hello,
              "годный ServerHello не признан ответом сервера");
        CHECK(!si.is_client_hello, "ServerHello принят за ClientHello");

        /* Фатальный алерт: тип записи 21. Ответ есть, приёмки нет. */
        uint8_t alert[7] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };
        CHECK(d2k_tls_parse(alert, sizeof alert, &si) == 0 && !si.is_server_hello,
              "фатальный алерт засчитан за ответ сервера — блокировка стала бы обходом");

        /* Мусор в теле записи рукопожатия: тип сообщения не 0x02. */
        uint8_t junk[45];
        memcpy(junk, ok, sizeof junk);
        junk[5] = 0x0b;   /* certificate, а не server_hello */
        CHECK(d2k_tls_parse(junk, sizeof junk, &si) == 0 && !si.is_server_hello,
              "чужое сообщение рукопожатия засчитано за ServerHello");

        /* Запись, спорящая сама с собой: рукопожатие длиннее собственной
           записи. Такую разметку принимать нельзя — на ней коробка и клиент
           разойдутся в том, где кончается запись. */
        uint8_t bad[45];
        memcpy(bad, ok, sizeof bad);
        bad[6] = 0x00; bad[7] = 0x01; bad[8] = 0x00;  /* 256 > 42 - 4 */
        CHECK(d2k_tls_parse(bad, sizeof bad, &si) == 0 && !si.is_server_hello,
              "ServerHello длиннее своей записи признан годным");

        /* Обрывок: пришли только первые пять байт. */
        CHECK(d2k_tls_parse(ok, 5, &si) == 0 && !si.is_server_hello,
              "оборванная запись признана ответом сервера");

        /* Рукопожатие НУЛЕВОЙ длины: тип тот, разметка непротиворечива, а
           ServerHello'ом это быть не может — по RFC 8446 §4.1.3 его тело не
           короче 38 байт. Раньше такой вход приёмку проходил. */
        uint8_t empty[9] = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00 };
        CHECK(d2k_tls_parse(empty, sizeof empty, &si) == 0 && !si.is_server_hello,
              "рукопожатие нулевой длины признано ответом сервера");

        /* Тело есть, но короче минимального: 20 байт вместо 38. */
        uint8_t shortbody[29];
        memset(shortbody, 0, sizeof shortbody);
        shortbody[0] = 0x16; shortbody[1] = 0x03; shortbody[2] = 0x03;
        shortbody[3] = 0x00; shortbody[4] = 0x18;   /* запись 24 байта */
        shortbody[5] = 0x02; shortbody[6] = 0x00; shortbody[7] = 0x00; shortbody[8] = 0x14;
        CHECK(d2k_tls_parse(shortbody, sizeof shortbody, &si) == 0 && !si.is_server_hello,
              "ServerHello короче минимально возможного признан годным");
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("TLS: все проверки прошли\n");
    return 0;
}
