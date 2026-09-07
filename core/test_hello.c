/* test_hello.c — вид приветствия, координаты имени, сборка холодного старта.
 *
 * Три источника фикстур, и это не разнообразия ради:
 *
 *   1. Синтетические (modern/legacy/legacy_versions_no_13) — построены
 *      ОТДЕЛЬНЫМ скриптом (не этим разборщиком и не hello.c), и позиция
 *      имени в каждой сверена поиском подстроки по сырым байтам, как в
 *      datapath/test_tls.c: если бы строитель и разборщик делили одно
 *      неверное допущение о формате, тест бы этого не заметил.
 *   2. build_ch() ниже — гибкий строитель ПРЯМО в этом файле, для случаев,
 *      которые неудобно замораживать в литерал (нет имени вовсе, обрубленный
 *      вход, испорченная длина).
 *   3. real_legacy_youtube — настоящий байтовый снимок TLS 1.2 (см.
 *      происхождение в core/profiles/legacy.hex: openssl s_client -tls1_2 к
 *      youtube.com через роутер владельца, 07.09.2026), ДО замены имени на
 *      __SNI__. Разбор синтетики и разбор настоящего трафика — не одно и то
 *      же утверждение: коробка (и здесь — наш же разборщик) сличает то, что
 *      реально шлёт клиент, а не то, что укладывается в написанный вручную
 *      минимум.
 *
 * Профили в core/profiles/ (настоящий современный захват и настоящий
 * библиотечный TLS 1.2 — оба живые, см. их шапки) проверяются здесь ЖЕ,
 * через d2k_hello_from_profile: это единственный путь, которым их вообще
 * можно исполнить, и одновременно сквозная проверка core/hello_profiles.inc
 * (генерируется Makefile'ом из тех же .hex, см. его правило).
 */
#include <stdio.h>
#include <string.h>

#include "d2k_hello.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* --- синтетические фикстуры --------------------------------------------
 * Построены scripts/... нет, отдельным Python-скриптом при разработке (не
 * входит в дерево — только его результат), НЕ hello.c: тот же довод, что у
 * real_hello в datapath/test_tls.c. Независимая проверка (поиск подстроки
 * по сырым байтам): имя лежит со смещения 67 во всех трёх — до имени байты
 * одинаковы (session_id, наборы шифров, compression, заголовок расширения
 * server_name совпадают буквально), поэтому и смещение совпадает. */
static const uint8_t modern[] = {
    0x16, 0x03, 0x01, 0x00, 0x5b, 0x01, 0x00, 0x00, 0x57, 0x03, 0x03, 0x01,
    0x08, 0x0f, 0x16, 0x1d, 0x24, 0x2b, 0x32, 0x39, 0x40, 0x47, 0x4e, 0x55,
    0x5c, 0x63, 0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2, 0xa9,
    0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0x00, 0x00, 0x08, 0x13, 0x01,
    0x13, 0x02, 0x13, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0x26, 0x00, 0x00,
    0x00, 0x19, 0x00, 0x17, 0x00, 0x00, 0x14, 0xd0, 0xbf, 0xd1, 0x80, 0xd0,
    0xb8, 0xd0, 0xbc, 0xd0, 0xb5, 0xd1, 0x80, 0x2e, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03,
}; /* "пример.example", supported_versions {0x0304, 0x0303} */

static const uint8_t legacy[] = {
    0x16, 0x03, 0x01, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x48, 0x03, 0x03, 0x01,
    0x08, 0x0f, 0x16, 0x1d, 0x24, 0x2b, 0x32, 0x39, 0x40, 0x47, 0x4e, 0x55,
    0x5c, 0x63, 0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2, 0xa9,
    0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0x00, 0x00, 0x08, 0x13, 0x01,
    0x13, 0x02, 0x13, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00,
    0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x6c, 0x65, 0x67, 0x61, 0x63,
    0x79, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
}; /* "legacy.example", БЕЗ расширения supported_versions вовсе */

/* Расширение supported_versions ЕСТЬ, но в списке только 0x0303 — граничный
 * случай, которым d2k_hello_shape обязан остаться LEGACY: признак — не
 * присутствие расширения само по себе, а 0x0304 СРЕДИ перечисленных версий
 * (см. doc-комментарий d2k_hello_shape). */
static const uint8_t legacy_versions_no_13[] = {
    0x16, 0x03, 0x01, 0x00, 0x53, 0x01, 0x00, 0x00, 0x4f, 0x03, 0x03, 0x01,
    0x08, 0x0f, 0x16, 0x1d, 0x24, 0x2b, 0x32, 0x39, 0x40, 0x47, 0x4e, 0x55,
    0x5c, 0x63, 0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2, 0xa9,
    0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0x00, 0x00, 0x08, 0x13, 0x01,
    0x13, 0x02, 0x13, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0x1e, 0x00, 0x00,
    0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x6c, 0x65, 0x67, 0x61, 0x63,
    0x79, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00, 0x2b, 0x00,
    0x03, 0x02, 0x03, 0x03,
};

/* Настоящий снимок TLS 1.2 (openssl s_client -tls1_2 к youtube.com, живой
 * захват 07.09.2026 — то же самое происхождение, что у core/profiles/
 * legacy.hex, но ДО замены имени на __SNI__). supported_versions
 * отсутствует — вот почему это LEGACY. Имя youtube.com на смещении 151,
 * длина 11 — независимо сверено поиском подстроки при подготовке профиля
 * (см. core/profiles/legacy.hex). */
static const uint8_t real_legacy_youtube[] = {
    0x16, 0x03, 0x03, 0x00, 0xd1, 0x01, 0x00, 0x00, 0xcd, 0x03, 0x03, 0xcb,
    0x96, 0x8e, 0x14, 0x47, 0x60, 0xbf, 0x6d, 0x3c, 0xe9, 0x1a, 0x3b, 0x4d,
    0x42, 0xd7, 0x6d, 0x41, 0xa2, 0xa2, 0x92, 0xcd, 0xd1, 0x05, 0x09, 0x65,
    0x1d, 0xd4, 0xee, 0x94, 0xce, 0xd5, 0x43, 0x00, 0x00, 0x5c, 0xcc, 0xa9,
    0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x30, 0xc0, 0x2c, 0xc0, 0x28, 0xc0, 0x24,
    0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9f, 0x00, 0x6b, 0x00, 0x39, 0xff, 0x85,
    0x00, 0xc4, 0x00, 0x88, 0x00, 0x81, 0x00, 0x9d, 0x00, 0x3d, 0x00, 0x35,
    0x00, 0xc0, 0x00, 0x84, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x27, 0xc0, 0x23,
    0xc0, 0x13, 0xc0, 0x09, 0x00, 0x9e, 0x00, 0x67, 0x00, 0x33, 0x00, 0xbe,
    0x00, 0x45, 0x00, 0x9c, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0xba, 0x00, 0x41,
    0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05, 0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08,
    0x00, 0x16, 0x00, 0x0a, 0x00, 0xff, 0x01, 0x00, 0x00, 0x48, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x79, 0x6f, 0x75, 0x74, 0x75,
    0x62, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
    0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
    0x00, 0x19, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x18, 0x00, 0x16,
    0x08, 0x06, 0x06, 0x01, 0x06, 0x03, 0x08, 0x05, 0x05, 0x01, 0x05, 0x03,
    0x08, 0x04, 0x04, 0x01, 0x04, 0x03, 0x02, 0x01, 0x02, 0x03,
};

/* --- гибкий строитель для случаев, неудобных как литерал ---------------- */

/* sni==NULL — без расширения server_name вовсе. with_tls13 — класть ли
 * supported_versions со значением 0x0304. Возвращает длину. */
static size_t build_ch(uint8_t *out, const char *sni, int with_tls13) {
    uint8_t body[512];
    size_t b = 0;
    body[b++] = 0x03; body[b++] = 0x03;
    for (int i = 0; i < 32; i++) {
        body[b++] = (uint8_t)i;
    }
    body[b++] = 0x00; /* session_id пуст */
    static const uint8_t suites[] = {0x13, 0x01, 0x13, 0x02, 0x13, 0x03};
    body[b++] = 0x00; body[b++] = (uint8_t)sizeof suites;
    memcpy(body + b, suites, sizeof suites); b += sizeof suites;
    body[b++] = 0x01; body[b++] = 0x00; /* compression: null */

    uint8_t exts[256];
    size_t e = 0;
    if (sni) {
        size_t nl = strlen(sni);
        size_t entry = 1 + 2 + nl;
        size_t list = 2 + entry;
        exts[e++] = 0x00; exts[e++] = 0x00;
        exts[e++] = (uint8_t)(list >> 8); exts[e++] = (uint8_t)list;
        exts[e++] = (uint8_t)(entry >> 8); exts[e++] = (uint8_t)entry;
        exts[e++] = 0x00;
        exts[e++] = (uint8_t)(nl >> 8); exts[e++] = (uint8_t)nl;
        memcpy(exts + e, sni, nl); e += nl;
    }
    if (with_tls13) {
        exts[e++] = 0x00; exts[e++] = 0x2b;
        exts[e++] = 0x00; exts[e++] = 0x03;
        exts[e++] = 0x02; exts[e++] = 0x03; exts[e++] = 0x04;
    }

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

int main(void) {
    /* --- вид приветствия читается по supported_versions -------------------- */
    CHECK(d2k_hello_shape(modern, sizeof modern) == D2K_SHAPE_MODERN,
          "современное приветствие не опознано");
    CHECK(d2k_hello_shape(legacy, sizeof legacy) == D2K_SHAPE_LEGACY,
          "старое приветствие не опознано");
    /* --- имя находится по координатам, а не поиском подстроки ------------- */
    {
        size_t off = 0, len = 0;
        CHECK(d2k_hello_sni(modern, sizeof modern, &off, &len) == 0,
              "имя не найдено в приветствии");
        CHECK(len == strlen("пример.example"), "длина имени неверна");
        CHECK(off == 67 && memcmp(modern + off, "пример.example", len) == 0,
              "смещение или содержимое имени разошлись с независимой проверкой");
    }
    /* --- профиль подставляет имя и не портит остального -------------------
     *
     * Бриф задачи иллюстрировал этот вызов буфером в 1024 байта — цифра из
     * времени, когда профиля ещё не было. Настоящий современный профиль
     * (core/profiles/modern.hex) — 1530 байт ДО подстановки: постквантовый
     * key_share (X25519MLKEM768) даёт 1216 байт в ОДНОМ расширении, и это
     * не с потолка, а из настоящего захвата браузера (см. шапку файла и
     * ниже — MODERN_BASE_LEN). 1024 байт не хватило бы НИКОГДА, при любом
     * имени: приветствие настоящего браузера просто больше. Буфер здесь —
     * 2048, с тем же запасом, что и в остальных проверках профиля ниже. */
    {
        uint8_t out[2048]; size_t n = 0;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "цель.example", out, sizeof out, &n) == 0,
              "профиль не собрался");
        size_t off = 0, len = 0;
        CHECK(d2k_hello_sni(out, n, &off, &len) == 0, "в собранном приветствии нет имени");
        CHECK(memcmp(out + off, "цель.example", len) == 0, "подставлено не то имя");
        CHECK(d2k_hello_shape(out, n) == D2K_SHAPE_MODERN, "профиль сменил вид приветствия");
    }

    /* --- граничный случай вида: расширение есть, а 0x0304 в нём нет -------- */
    CHECK(d2k_hello_shape(legacy_versions_no_13, sizeof legacy_versions_no_13) == D2K_SHAPE_LEGACY,
          "supported_versions без 0x0304 распознан как современный");

    /* --- настоящий снимок, не синтетика ------------------------------------ */
    {
        CHECK(d2k_hello_shape(real_legacy_youtube, sizeof real_legacy_youtube) == D2K_SHAPE_LEGACY,
              "настоящее приветствие TLS 1.2 (youtube.com) не опознано как LEGACY");
        size_t off = 0, len = 0;
        CHECK(d2k_hello_sni(real_legacy_youtube, sizeof real_legacy_youtube, &off, &len) == 0,
              "имя не найдено в настоящем снимке TLS 1.2");
        CHECK(off == 151 && len == 11 &&
              memcmp(real_legacy_youtube + off, "youtube.com", 11) == 0,
              "координаты имени в настоящем снимке разошлись с provenance-заметкой");
    }

    /* --- честные "не знаю": UNKNOWN, а не угаданный MODERN/LEGACY ---------- */
    {
        CHECK(d2k_hello_shape(NULL, 0) == D2K_SHAPE_UNKNOWN, "NULL должен давать UNKNOWN");
        static const uint8_t tiny[] = {0x16, 0x03};
        CHECK(d2k_hello_shape(tiny, sizeof tiny) == D2K_SHAPE_UNKNOWN,
              "обрывок из двух байт не может быть ни MODERN, ни LEGACY");
        static const uint8_t not_tls[] = {0x47, 0x45, 0x54, 0x20, 0x2f}; /* "GET /" */
        CHECK(d2k_hello_shape(not_tls, sizeof not_tls) == D2K_SHAPE_UNKNOWN,
              "не-TLS вход распознан как приветствие");
        /* Запись TLS, но тип рукопожатия — ServerHello (0x02), не ClientHello. */
        uint8_t not_ch[64];
        memcpy(not_ch, modern, sizeof not_ch);
        not_ch[5] = 0x02;
        CHECK(d2k_hello_shape(not_ch, sizeof not_ch) == D2K_SHAPE_UNKNOWN,
              "ServerHello распознан как ClientHello");
        CHECK(d2k_hello_shape(modern, 4) == D2K_SHAPE_UNKNOWN,
              "четырёх байт недостаточно даже для заголовка записи, а не UNKNOWN");
    }

    /* --- отсутствие имени — честный отказ, а не угаданное смещение --------- */
    {
        uint8_t buf[256];
        size_t n = build_ch(buf, NULL, 1);
        CHECK(d2k_hello_shape(buf, n) == D2K_SHAPE_MODERN,
              "вид не должен зависеть от присутствия имени");
        size_t off = 0, len = 0;
        CHECK(d2k_hello_sni(buf, n, &off, &len) != 0,
              "имя найдено там, где расширения server_name вообще нет");
    }
    /* --- негодные аргументы --------------------------------------------- */
    {
        size_t off = 0, len = 0;
        CHECK(d2k_hello_sni(modern, sizeof modern, NULL, &len) != 0, "NULL off должен отвергаться");
        CHECK(d2k_hello_sni(modern, sizeof modern, &off, NULL) != 0, "NULL len должен отвергаться");
    }

    /* --- обрывок против противоречия: разные причины отказа, не одна ------ */
    {
        /* Обрывок: буфер обрублен ДО имени — как MSS режет сегмент браузера
           (см. datapath/tls.c). Дальше расширений нет вовсе, но и
           противоречия нет: пришедшего просто не хватило. */
        uint8_t buf[256];
        size_t n = build_ch(buf, "example.com", 1);
        size_t off = 0, len = 0;
        CHECK(d2k_hello_sni(buf, 60, &off, &len) != 0,
              "обрубленный ДО имени вход не должен давать имя");
        /* А если обрубить ПОСЛЕ имени, но до конца расширений — имя всё
           равно должно найтись, ровно как в tls.c для браузерной записи,
           разъехавшейся по сегментам. */
        CHECK(d2k_hello_sni(buf, n - 4, &off, &len) == 0,
              "имя потеряно при обрубке ПОСЛЕ него самого");

        /* Противоречие: длина блока расширений объявлена больше, чем
           влезает в запись TLS (claimed). Это не "не хватило данных" — это
           "разметка врёт", и разбор обязан остановиться, не имени в руках. */
        uint8_t bad[256];
        memcpy(bad, buf, n);
        /* Смещение длины блока расширений: REC_HDR(5)+HS_HDR(4)+2+32(random)
           +1(session_id=0)+2+6(cipher_suites)+1+1(compression) = 54. */
        size_t exts_len_off = 54;
        bad[exts_len_off] = 0x7f; bad[exts_len_off + 1] = 0xff; /* заведомо огромно */
        CHECK(d2k_hello_sni(bad, n, &off, &len) != 0,
              "противоречивая длина блока расширений не должна давать имя");
    }

    /* --- d2k_hello_from_profile: отказы -------------------------------- */
    {
        uint8_t out[2048]; size_t n = 0;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_UNKNOWN, "x.example", out, sizeof out, &n) != 0,
              "профиля для UNKNOWN не бывает");
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "", out, sizeof out, &n) != 0,
              "пустое имя должно отвергаться");
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, NULL, out, sizeof out, &n) != 0,
              "NULL имя должно отвергаться");
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "x.example", NULL, sizeof out, &n) != 0,
              "NULL буфер должен отвергаться");
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "x.example", out, sizeof out, NULL) != 0,
              "NULL out_len должен отвергаться");
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "x.example", out, 5, &n) != 0,
              "буфер размером 5 не должен вмещать современный профиль");
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "x.example", out, 5, &n) != 0,
              "буфер размером 5 не должен вмещать старый профиль");
    }

    /* --- профиль MODERN: имя короче и длиннее метки, оба раза целиком ------
     *
     * Ровно то место, о котором предупреждает бриф задачи: подстановка имени
     * ДРУГОЙ длины (не 7 байт __SNI__) обязана пересчитать ВСЕ объемлющие
     * длины. Смещение имени (137) — известное значение из провенанса
     * core/profiles/modern.hex (там же имя найдено ДО замены, независимым
     * поиском подстроки) и НЕ должно меняться: смещение имени внутри
     * приветствия не зависит от того, что именно в нём лежит, меняется
     * только всё, что идёт ПОСЛЕ. Если это утверждение когда-нибудь
     * перестанет быть верным — значит где-то забыли пересчитать длину, и
     * именно этот CHECK обязан покраснеть первым. */
    {
        static const size_t MODERN_BASE_LEN = 1530; /* см. шапку modern.hex */
        static const size_t MODERN_SNI_OFF = 137;

        uint8_t out[2048]; size_t n = 0;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "a.co", out, sizeof out, &n) == 0,
              "короткая подстановка в современный профиль не собралась");
        CHECK(n == MODERN_BASE_LEN - 7 + 4, "итоговая длина не сошлась для короткого имени");
        size_t off = 0, len = 0;
        CHECK(d2k_hello_sni(out, n, &off, &len) == 0 && off == MODERN_SNI_OFF && len == 4 &&
              memcmp(out + off, "a.co", 4) == 0,
              "короткое имя в современном профиле разъехалось");
        CHECK(d2k_hello_shape(out, n) == D2K_SHAPE_MODERN, "короткое имя сменило вид приветствия");

        const char *longname = "очень-длинное-поддоменное-имя.example.com";
        size_t longlen = strlen(longname);
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, longname, out, sizeof out, &n) == 0,
              "длинная подстановка в современный профиль не собралась");
        CHECK(n == MODERN_BASE_LEN - 7 + longlen, "итоговая длина не сошлась для длинного имени");
        off = 0; len = 0;
        CHECK(d2k_hello_sni(out, n, &off, &len) == 0 && off == MODERN_SNI_OFF && len == longlen &&
              memcmp(out + off, longname, longlen) == 0,
              "длинное имя в современном профиле разъехалось");
        CHECK(d2k_hello_shape(out, n) == D2K_SHAPE_MODERN, "длинное имя сменило вид приветствия");
    }

    /* --- профиль LEGACY: то же самое, другое смещение (151, из youtube.com) */
    {
        static const size_t LEGACY_BASE_LEN = 210; /* см. шапку legacy.hex */
        static const size_t LEGACY_SNI_OFF = 151;

        uint8_t out[2048]; size_t n = 0;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "a.co", out, sizeof out, &n) == 0,
              "короткая подстановка в старый профиль не собралась");
        CHECK(n == LEGACY_BASE_LEN - 7 + 4, "итоговая длина не сошлась для короткого имени (LEGACY)");
        size_t off = 0, len = 0;
        CHECK(d2k_hello_sni(out, n, &off, &len) == 0 && off == LEGACY_SNI_OFF && len == 4 &&
              memcmp(out + off, "a.co", 4) == 0,
              "короткое имя в старом профиле разъехалось");
        CHECK(d2k_hello_shape(out, n) == D2K_SHAPE_LEGACY, "короткое имя сменило вид приветствия (LEGACY)");

        const char *longname = "очень-длинное-поддоменное-имя.example.com";
        size_t longlen = strlen(longname);
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, longname, out, sizeof out, &n) == 0,
              "длинная подстановка в старый профиль не собралась");
        CHECK(n == LEGACY_BASE_LEN - 7 + longlen, "итоговая длина не сошлась для длинного имени (LEGACY)");
        off = 0; len = 0;
        CHECK(d2k_hello_sni(out, n, &off, &len) == 0 && off == LEGACY_SNI_OFF && len == longlen &&
              memcmp(out + off, longname, longlen) == 0,
              "длинное имя в старом профиле разъехалось");
        CHECK(d2k_hello_shape(out, n) == D2K_SHAPE_LEGACY, "длинное имя сменило вид приветствия (LEGACY)");
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("приветствие: все проверки прошли\n");
    return 0;
}
