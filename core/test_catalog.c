/* test_catalog.c — каталог на C поверх ТОГО ЖЕ файла, что читает панель.
 *
 * Два слоя проверок:
 *
 *   1. Примитивы формата, которые круговой обход настоящего файла не бьёт
 *      напрямую: RFC 3339 в обе стороны (против ground truth ИЗВНЕ, не
 *      против собственной же арифметики — см. check_time_roundtrip),
 *      отказ на дробном числе, отказ на строке длиннее буфера, отказ на
 *      девятой примете отпечатка (буфер fp.sig фиксирован на 8),
 *      пропуск незнакомых полей, \u-экранирование, null как пустой
 *      массив, безопасность повторного d2k_catalog_free.
 *
 *   2. Настоящий каталог с роутера (testdata/catalog-real.json) — четыре
 *      проверки из брифа задачи, ниже ДОСЛОВНО (см. задание): полный
 *      разбор, круговой обход без потерь, транспорт переживает круговой
 *      обход, обрубок JSON отвергается с причиной.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_catalog.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Пишет content в path целиком. Используется только синтетическими
 * проверками ниже (блоки из брифа пишут свой обрубок сами, inline, как в
 * задании, — этот helper их не трогает). */
static void write_tmp(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("ПРОВАЛ: не удалось создать %s для теста\n", path);
        fails++;
        return;
    }
    fputs(content, f);
    fclose(f);
}

/* ---------------------------------------------------------------------
 * Время: RFC 3339 <-> секунды эпохи.
 *
 * Опорные значения — вывод `date -u -j -f "%Y-%m-%dT%H:%M:%S" ... +%s` на
 * macOS, независимый от этого кода источник истины. Проверять кодирование
 * и раскодирование друг против друга было бы кругом: обе стороны могли бы
 * разделять одну и ту же компенсирующую ошибку и сходиться на неверном
 * числе. Диапазон случаев: эпоха 0, обычная дата 2026 года, граница
 * високосного дня 2000-02-29/03-01 (год кратен 400 — високосный по
 * григорианскому правилу), отрицательная эпоха (до 1970), граница int32
 * (2038-01-19) — используется int64_t, переполнения нет, но число всё
 * равно узнаваемое. Последний случай — дробная доля секунды из настоящего
 * файла: она отбрасывается, а не портит целую часть.
 * --------------------------------------------------------------------- */
static void check_time_roundtrip(void) {
    static const struct { const char *rfc3339; int64_t epoch; } cases[] = {
        { "1970-01-01T00:00:00Z",          0 },
        { "2026-09-06T04:08:02Z",          1788667682 },
        { "2026-09-07T07:13:56Z",          1788765236 },
        { "2000-03-01T00:00:00Z",          951868800 },
        { "2000-02-29T12:00:00Z",          951825600 },
        { "1969-12-31T23:59:59Z",          -1 },
        { "2038-01-19T03:14:07Z",          2147483647 },
        { "2026-09-06T04:09:29.08957744Z", 1788667769 }, /* дробная доля отбрасывается */
    };
    size_t n = sizeof cases / sizeof cases[0];
    for (size_t k = 0; k < n; k++) {
        char json[512], msg1[160], msg2[160];
        snprintf(json, sizeof json,
            "{\"boxes\":[{\"id\":\"box-t\",\"created\":\"%s\","
            "\"updated\":\"2026-01-01T00:00:00Z\","
            "\"fingerprint\":{\"method\":1,\"signals\":[]},\"plans\":[],\"bindings\":[]}]}",
            cases[k].rfc3339);
        write_tmp("/tmp/d2k-cat-time.json", json);
        snprintf(msg1, sizeof msg1, "время %s не прочиталось", cases[k].rfc3339);
        snprintf(msg2, sizeof msg2, "время %s дало не ту эпоху", cases[k].rfc3339);

        d2k_catalog c; char err[200] = {0};
        CHECK(d2k_catalog_load("/tmp/d2k-cat-time.json", &c, err, sizeof err) == 0, msg1);
        if (c.n_boxes == 1) {
            CHECK(c.boxes[0].created == cases[k].epoch, msg2);
        }
        d2k_catalog_free(&c);
    }

    /* Запись: то же время обязано выйти строкой БЕЗ дробной доли, тем же
       видом Y-M-DTH:M:SZ. Сверяем СЫРЫЕ байты записанного файла, а не
       собственный же разбор — иначе тест доказывал бы только то, что
       кодирование и раскодирование согласны друг с другом, а не что они
       верны (тот же довод, что выше). */
    write_tmp("/tmp/d2k-cat-time2.json",
        "{\"boxes\":[{\"id\":\"box-t\",\"created\":\"2026-09-06T04:08:02.5Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\","
        "\"fingerprint\":{\"method\":1,\"signals\":[]},\"plans\":[],\"bindings\":[]}]}");
    {
        d2k_catalog c; char err[200] = {0};
        CHECK(d2k_catalog_load("/tmp/d2k-cat-time2.json", &c, err, sizeof err) == 0,
              "загрузка перед проверкой записи времени");
        CHECK(d2k_catalog_save(&c, "/tmp/d2k-cat-time2-out.json", err, sizeof err) == 0,
              "запись времени");
        d2k_catalog_free(&c);

        FILE *rf = fopen("/tmp/d2k-cat-time2-out.json", "r");
        CHECK(rf != NULL, "записанный файл не открылся для сверки байт");
        if (rf) {
            char buf[8192];
            size_t got = fread(buf, 1, sizeof buf - 1, rf);
            buf[got] = 0;
            fclose(rf);
            CHECK(strstr(buf, "\"created\": \"2026-09-06T04:08:02Z\"") != NULL,
                  "время на записи не вышло строкой RFC 3339 без дробной доли");
        }
    }
}

/* Снимок с роутера снят ДО появления поля transport (см. шапку
 * d2k_catalog.h) — в core/testdata/catalog-real.json ключа "transport" нет
 * вовсе (проверено grep'ом при подготовке теста). Разбор обязан такой файл
 * читать, а привязки — получать 0 ("не записано"), а не мусор со стека. */
static void check_transport_default_zero_on_old_file(void) {
    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("testdata/catalog-real.json", &c, err, sizeof err) == 0,
          "старый файл (без transport) не прочитался");
    if (c.n_boxes > 0 && c.boxes[0].n_binds > 0) {
        CHECK(c.boxes[0].binds[0].transport == 0,
              "поле transport не 0 в файле, где его вообще нет");
    }
    d2k_catalog_free(&c);
}

/* "Плавающей арифметики нет" (Global Constraints) — дробное число ЛЮБОГО
 * целочисленного поля обязано быть отказом с причиной, а не atof и не
 * молчаливым обрезанием до целой части. */
static void check_rejects_float_number(void) {
    write_tmp("/tmp/d2k-cat-float.json",
        "{\"boxes\":[{\"id\":\"box-f\",\"created\":\"2026-01-01T00:00:00Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\","
        "\"fingerprint\":{\"method\":1,\"signals\":[]},"
        "\"plans\":[{\"id\":\"plan-f\",\"proto\":\"tls\",\"text\":\"x\","
        "\"added\":\"2026-01-01T00:00:00Z\",\"successes\":3.14,\"enabled\":true}],"
        "\"bindings\":[]}]}");
    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("/tmp/d2k-cat-float.json", &c, err, sizeof err) != 0,
          "дробное число в поле successes принято за целое");
    CHECK(err[0] != 0, "отказ на дробном числе без причины");
}

/* box.id — char[40]: строка длиннее буфера обязана быть отказом, а не
 * тихим обрезанием. Обрезанный id — это ДРУГОЙ, ложный идентификатор
 * коробки, и в файле не остаётся следа, что он был обрезан. */
static void check_rejects_oversized_string(void) {
    char longid[60];
    memset(longid, 'x', 50);
    longid[50] = 0;

    char json[512];
    snprintf(json, sizeof json,
        "{\"boxes\":[{\"id\":\"%s\",\"created\":\"2026-01-01T00:00:00Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\","
        "\"fingerprint\":{\"method\":1,\"signals\":[]},\"plans\":[],\"bindings\":[]}]}",
        longid);
    write_tmp("/tmp/d2k-cat-longid.json", json);

    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("/tmp/d2k-cat-longid.json", &c, err, sizeof err) != 0,
          "id длиннее 40 байт принят без отказа");
    CHECK(err[0] != 0, "отказ на длинном id без причины");
}

/* d2k_cat_fp.sig — фиксированный массив на 8 (см. d2k_catalog.h); девятая
 * примета обязана быть отказом, а не потерей одной из девяти без следа. */
static void check_rejects_too_many_signals(void) {
    char sigs[700] = {0};
    for (int i = 0; i < 9; i++) {
        char one[64];
        snprintf(one, sizeof one, "%s{\"kind\":\"x\",\"seen\":1}", i ? "," : "");
        strncat(sigs, one, sizeof sigs - strlen(sigs) - 1);
    }
    char json[1024];
    snprintf(json, sizeof json,
        "{\"boxes\":[{\"id\":\"box-9\",\"created\":\"2026-01-01T00:00:00Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\","
        "\"fingerprint\":{\"method\":1,\"signals\":[%s]},\"plans\":[],\"bindings\":[]}]}",
        sigs);
    write_tmp("/tmp/d2k-cat-9sig.json", json);

    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("/tmp/d2k-cat-9sig.json", &c, err, sizeof err) != 0,
          "девятая примета отпечатка принята при ёмкости буфера 8");
    CHECK(err[0] != 0, "отказ на переполнении примет без причины");
}

/* Неизвестное поле пропускается на любом уровне вложенности — иначе
 * завтрашнее расширение формата ломало бы вчерашний разбор (ровно то же
 * одностороннее устройство совместимости, что у transport: Go незнакомые
 * поля тоже молча пропускает). Незнакомые поля стоят РЯДОМ с настоящими на
 * каждом уровне (верхний, коробка, отпечаток/сигнал, план, привязка) —
 * проверяется, что известные поля не задеты соседями. */
static void check_skips_unknown_fields(void) {
    write_tmp("/tmp/d2k-cat-unknown.json",
        "{\"schema\":1,\"updated\":\"2026-01-01T00:00:00Z\","
        "\"future_top\":{\"a\":[1,2,{\"b\":true}]},"
        "\"boxes\":[{\"id\":\"box-u\",\"created\":\"2026-01-01T00:00:00Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\",\"future_box\":null,"
        "\"fingerprint\":{\"method\":1,\"signals\":[{\"kind\":\"x\",\"seen\":1,\"future_sig\":\"z\"}]},"
        "\"plans\":[{\"id\":\"plan-u\",\"proto\":\"tls\",\"text\":\"t\","
        "\"added\":\"2026-01-01T00:00:00Z\",\"successes\":1,\"enabled\":true,"
        "\"future_plan\":[1,2,3]}],"
        "\"bindings\":[{\"kind\":\"name\",\"target\":\"example.com\",\"plan_id\":\"plan-u\","
        "\"level\":3,\"confirmed\":\"2026-01-01T00:00:00Z\",\"successes\":1,\"enabled\":true,"
        "\"future_binding\":\"ignored\"}]}]}");

    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("/tmp/d2k-cat-unknown.json", &c, err, sizeof err) == 0,
          "незнакомые поля не должны валить разбор");
    if (c.n_boxes == 1) {
        CHECK(strcmp(c.boxes[0].id, "box-u") == 0,
              "id коробки испорчен соседним незнакомым полем");
        CHECK(c.boxes[0].n_plans == 1 && strcmp(c.boxes[0].plans[0].text, "t") == 0,
              "план испорчен незнакомым полем рядом");
        CHECK(c.boxes[0].n_binds == 1 && strcmp(c.boxes[0].binds[0].target, "example.com") == 0,
              "привязка испорчена незнакомым полем рядом");
        CHECK(c.boxes[0].fp.n_sig == 1, "сигнал испорчен незнакомым полем рядом");
    }
    d2k_catalog_free(&c);
}

/* \u0041 — тривиальный ASCII-диапазон; \u00e9 — двухбайтовый UTF-8
 * (0xC3 0xA9, "é") — единственный путь, которым это ядро вообще порождает
 * многобайтовый UTF-8 на выходе разбора, и без прямой проверки этот путь
 * остался бы непроверенным кодом. Обычные экранирования (\n \" \\) уже
 * гоняются круговым обходом настоящего файла — plan.text там их содержит
 * взаправду, — здесь проверяется именно \u. */
static void check_string_escapes(void) {
    write_tmp("/tmp/d2k-cat-esc.json",
        "{\"boxes\":[{\"id\":\"box-e\",\"created\":\"2026-01-01T00:00:00Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\","
        "\"fingerprint\":{\"method\":1,\"signals\":[]},\"plans\":[],"
        "\"bindings\":[{\"kind\":\"name\",\"target\":\"caf\\u00e9-\\u0041.example.com\","
        "\"plan_id\":\"plan-e\",\"level\":3,\"confirmed\":\"2026-01-01T00:00:00Z\","
        "\"successes\":1,\"enabled\":true}]}]}");

    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("/tmp/d2k-cat-esc.json", &c, err, sizeof err) == 0,
          "строка с \\u-экранированием не разобралась");
    if (c.n_boxes == 1 && c.boxes[0].n_binds == 1) {
        CHECK(strcmp(c.boxes[0].binds[0].target, "caf\xc3\xa9-A.example.com") == 0,
              "\\u00e9/\\u0041 не превратились в верные байты UTF-8");
    }
    d2k_catalog_free(&c);
}

/* Суррогатная половина и \u0000 сознательно отвергаются, а не принимаются
 * с потерей смысла: суррогат вне пары ничего не кодирует в UTF-8 сам по
 * себе (кодировать полную пару этому ядру негде и незачем — единственный
 * потребитель строк здесь простой char*), а \u0000 внутри NUL-terminated
 * C-строки обрезал бы значение молча на этом байте. */
static void check_surrogate_and_nul_rejected(void) {
    d2k_catalog c; char err[200] = {0};

    write_tmp("/tmp/d2k-cat-surrogate.json",
        "{\"boxes\":[{\"id\":\"box-s\",\"created\":\"2026-01-01T00:00:00Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\","
        "\"fingerprint\":{\"method\":1,\"signals\":[{\"kind\":\"\\ud800\",\"seen\":1}]},"
        "\"plans\":[],\"bindings\":[]}]}");
    CHECK(d2k_catalog_load("/tmp/d2k-cat-surrogate.json", &c, err, sizeof err) != 0,
          "суррогатная половина \\ud800 принята как валидный символ");
    CHECK(err[0] != 0, "отказ на суррогате без причины");

    write_tmp("/tmp/d2k-cat-nul.json",
        "{\"boxes\":[{\"id\":\"box-n\",\"created\":\"2026-01-01T00:00:00Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\","
        "\"fingerprint\":{\"method\":1,\"signals\":[{\"kind\":\"a\\u0000b\",\"seen\":1}]},"
        "\"plans\":[],\"bindings\":[]}]}");
    CHECK(d2k_catalog_load("/tmp/d2k-cat-nul.json", &c, err, sizeof err) != 0,
          "\\u0000 внутри строки принят — C-строка так не может");
    CHECK(err[0] != 0, "отказ на \\u0000 без причины");
}

/* Ревью 2026-09-10: jskip_value рекурсировал без предела на незнакомом
 * поле — санитайзер поймал stack-overflow на ~200 000 уровнях (между
 * 80 000 и 100 000 падает при стеке 8 МБ; файл ~180-200 КБ, не экзотика).
 * Проверяем отказ на глубине, заведомо превышающей предел (см.
 * D2K_JSON_MAX_DEPTH в catalog.c), но далёкой от порога краха: защита
 * действует ПОСТЕПЕННО по мере разбора и отказывает на одном и том же
 * уровне что при глубине 200, что при 200 000 — глубже эта версия просто
 * никогда не заходит, и 200 000 одинаковых символов здесь ничего не
 * доказали бы сверх этого, только замедлили бы обычный прогон. */
static void check_depth_limit_rejects_not_crashes(void) {
    size_t depth = 200;
    size_t cap = 64 + depth * 2;
    char *json = malloc(cap);
    CHECK(json != NULL, "не удалось выделить буфер для теста глубины");
    if (!json) return;

    size_t pos = 0;
    memcpy(json + pos, "{\"future\":", 10); pos += 10;
    for (size_t i = 0; i < depth; i++) json[pos++] = '[';
    for (size_t i = 0; i < depth; i++) json[pos++] = ']';
    memcpy(json + pos, ",\"boxes\":[]}", 12); pos += 12;
    json[pos] = '\0';

    write_tmp("/tmp/d2k-cat-deep.json", json);
    free(json);

    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("/tmp/d2k-cat-deep.json", &c, err, sizeof err) != 0,
          "вложенность в 200 уровней внутри незнакомого поля принята без отказа");
    CHECK(err[0] != 0, "отказ на превышении глубины разбора без причины");
}

/* Ревью 2026-09-10: после успешного разбора верхнего объекта курсор не
 * проверялся против конца буфера — "{}x" (см. ниже) грузился как валидный
 * пустой каталог, хвост терялся молча. Go в этой же точке отказывает
 * ("invalid character 'x' after top-level value") — разбор был регрессией
 * относительно эталона на этом входе. Тот же класс — склейка двух валидных
 * каталогов подряд в одном файле: файл, расширенный лишними байтами, —
 * реальный класс порчи, не гипотетический. */
static void check_rejects_trailing_garbage(void) {
    write_tmp("/tmp/d2k-cat-trail1.json", "{\"boxes\":[]}x");
    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("/tmp/d2k-cat-trail1.json", &c, err, sizeof err) != 0,
          "байт 'x' после конца каталога принят молча");
    CHECK(err[0] != 0, "отказ на мусоре после каталога без причины");

    write_tmp("/tmp/d2k-cat-trail2.json", "{\"boxes\":[]}{\"boxes\":[]}");
    CHECK(d2k_catalog_load("/tmp/d2k-cat-trail2.json", &c, err, sizeof err) != 0,
          "склейка двух каталогов подряд принята за один");
    CHECK(err[0] != 0, "отказ на склейке каталогов без причины");

    /* Законный хвост — то, чем сам Go завершает файл (store.go:
       b = append(b, '\n')) — обязан ПРОХОДИТЬ: отказ на любом байте после
       '}' легко перепутать с отказом на настоящих файлах. */
    write_tmp("/tmp/d2k-cat-trail-ok.json", "{\"boxes\":[]}\n");
    CHECK(d2k_catalog_load("/tmp/d2k-cat-trail-ok.json", &c, err, sizeof err) == 0,
          "законный завершающий перевод строки принят за мусор");
    d2k_catalog_free(&c);
}

/* Go маршалит nil-срез как null (encoding/json) — свежий каталог
 * Catalog{Schema:1} без единой Confirm() даёт "boxes":null, а не
 * "boxes":[]. Обе формы — валидный пустой каталог, и пустой каталог
 * обязан и сохраняться, и потом читаться снова тем же пустым. */
static void check_null_boxes_is_empty_catalog(void) {
    write_tmp("/tmp/d2k-cat-nullboxes.json",
        "{\"schema\":1,\"updated\":\"2026-01-01T00:00:00Z\",\"boxes\":null}");

    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("/tmp/d2k-cat-nullboxes.json", &c, err, sizeof err) == 0,
          "\"boxes\":null не разобран как пустой каталог");
    CHECK(c.n_boxes == 0, "null дал не ноль коробок");
    CHECK(d2k_catalog_save(&c, "/tmp/d2k-cat-nullboxes-out.json", err, sizeof err) == 0,
          "пустой каталог не записался");
    d2k_catalog_free(&c);

    CHECK(d2k_catalog_load("/tmp/d2k-cat-nullboxes-out.json", &c, err, sizeof err) == 0,
          "записанный пустой каталог не перечитался");
    CHECK(c.n_boxes == 0, "пустой каталог перестал быть пустым после записи");
    d2k_catalog_free(&c);
}

/* d2kc (спека §3) — долгоживущий процесс; d2k_catalog_free обязан быть
 * no-op на пустом/уже освобождённом каталоге и на NULL. Здесь нет CHECK на
 * булево условие — свойство под проверкой в том, что процесс ДОХОДИТ до
 * конца функции: двойной free или free(NULL), которые портят память, роняют
 * его сами (тем более под ASan, см. цель san в Makefile), а не выставляют
 * неверный флаг. */
static void check_free_is_safe(void) {
    d2k_catalog c;
    memset(&c, 0, sizeof c);
    d2k_catalog_free(&c);
    d2k_catalog_free(&c);
    d2k_catalog_free(NULL);

    char err[200] = {0};
    if (d2k_catalog_load("testdata/catalog-real.json", &c, err, sizeof err) == 0) {
        d2k_catalog_free(&c);
        d2k_catalog_free(&c);
    }
}

int main(void) {
    check_time_roundtrip();
    check_transport_default_zero_on_old_file();
    check_rejects_float_number();
    check_rejects_oversized_string();
    check_rejects_too_many_signals();
    check_skips_unknown_fields();
    check_string_escapes();
    check_surrogate_and_nul_rejected();
    check_null_boxes_is_empty_catalog();
    check_free_is_safe();
    check_depth_limit_rejects_not_crashes();
    check_rejects_trailing_garbage();

    /* ===================================================================
     * Дальше — ДОСЛОВНО из брифа задачи (шаг 2): круговой обход настоящего
     * каталога с роутера. Эта проверка НЕСЁТ смысл задания и не
     * переформулирована — переформулировка потеряла бы то, что она
     * специально ловит (порядок полей, потерю массива, порчу чисел).
     * =================================================================== */

    /* --- настоящий каталог читается целиком ------------------------------- */
    {
        d2k_catalog c; char err[200] = {0};
        CHECK(d2k_catalog_load("testdata/catalog-real.json", &c, err, sizeof err) == 0,
              "настоящий каталог не прочитался");
        CHECK(c.n_boxes >= 1, "коробок ноль — разбор потерял содержимое");
        size_t binds = 0;
        for (size_t i = 0; i < c.n_boxes; i++) binds += c.boxes[i].n_binds;
        CHECK(binds >= 100, "привязок подозрительно мало — разбор потерял массив");
        d2k_catalog_free(&c);
    }
    /* --- круговой обход не теряет и не портит ------------------------------ */
    {
        d2k_catalog a, b; char err[200] = {0};
        CHECK(d2k_catalog_load("testdata/catalog-real.json", &a, err, sizeof err) == 0, "первая загрузка");
        CHECK(d2k_catalog_save(&a, "/tmp/d2k-cat-rt.json", err, sizeof err) == 0, "запись");
        CHECK(d2k_catalog_load("/tmp/d2k-cat-rt.json", &b, err, sizeof err) == 0, "вторая загрузка");
        CHECK(a.n_boxes == b.n_boxes, "число коробок изменилось");
        for (size_t i = 0; i < a.n_boxes; i++) {
            CHECK(strcmp(a.boxes[i].id, b.boxes[i].id) == 0, "id коробки изменился");
            CHECK(a.boxes[i].n_plans == b.boxes[i].n_plans, "число планов изменилось");
            CHECK(a.boxes[i].n_binds == b.boxes[i].n_binds, "число привязок изменилось");
            for (size_t j = 0; j < a.boxes[i].n_plans; j++) {
                CHECK(strcmp(a.boxes[i].plans[j].text, b.boxes[i].plans[j].text) == 0,
                      "текст плана изменился при круговом обходе");
                CHECK(a.boxes[i].plans[j].successes == b.boxes[i].plans[j].successes,
                      "счётчик успехов изменился");
            }
        }
        d2k_catalog_free(&a); d2k_catalog_free(&b);
    }
    /* --- транспорт переживает круговой обход ------------------------------- */
    {
        d2k_catalog c; char err[200] = {0};
        CHECK(d2k_catalog_load("testdata/catalog-real.json", &c, err, sizeof err) == 0, "загрузка");
        CHECK(c.n_boxes > 0 && c.boxes[0].n_binds > 0, "нечего помечать");
        c.boxes[0].binds[0].transport = 17;
        CHECK(d2k_catalog_save(&c, "/tmp/d2k-cat-tr.json", err, sizeof err) == 0, "запись");
        d2k_catalog_free(&c);
        CHECK(d2k_catalog_load("/tmp/d2k-cat-tr.json", &c, err, sizeof err) == 0, "перечитывание");
        CHECK(c.boxes[0].binds[0].transport == 17, "транспорт потерялся при круговом обходе");
        d2k_catalog_free(&c);
    }
    /* --- битый ввод отвергается, а не разбирается наполовину --------------- */
    {
        d2k_catalog c; char err[200] = {0};
        FILE *f = fopen("/tmp/d2k-cat-bad.json", "w");
        fputs("{\"boxes\":[{\"id\":\"box-1\",\"plans\":[", f); /* обрыв */
        fclose(f);
        CHECK(d2k_catalog_load("/tmp/d2k-cat-bad.json", &c, err, sizeof err) != 0,
              "обрубок принят за каталог");
        CHECK(err[0] != 0, "отказ без причины — человеку нечитаемо");
    }

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("каталог: все проверки прошли\n");
    return 0;
}
