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

/* Тот же снимок — и то же требование к ПОЛЯМ КОНТЕКСТА ПРОВЕРКИ (shape,
 * verified_by, задача 5). Проверяется ОТДЕЛЬНО и по ВСЕМ привязкам файла, а
 * не по первой: на роутере автора лежит каталог, накопленный неделями, и
 * ноль в новом поле обязан означать "не записано" у каждой записи. Ключ
 * привязки стал тройкой (цель, транспорт, форма), и если бы ноль не был
 * совместим с любой формой, всё накопленное знание обнулилось бы разом —
 * первая же проверка завела бы рядом со старой записью вторую.
 *
 * Отсюда две половины: сами поля читаются нулями (ниже) и ноль совместим с
 * любой формой (check_shape_fits_rule). */
static void check_shape_default_zero_on_old_file(void) {
    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("testdata/catalog-real.json", &c, err, sizeof err) == 0,
          "старый файл (без shape/verified_by) не прочитался");
    size_t seen = 0, dirty = 0;
    for (size_t i = 0; i < c.n_boxes; i++) {
        for (size_t j = 0; j < c.boxes[i].n_binds; j++) {
            seen++;
            if (c.boxes[i].binds[j].shape != 0 ||
                c.boxes[i].binds[j].verified_by != 0) { dirty++; }
        }
    }
    CHECK(seen >= 100, "привязок подозрительно мало — проверять контекст не на чем");
    CHECK(dirty == 0,
          "поля контекста проверки не 0 в файле, где их вообще нет");
    d2k_catalog_free(&c);
}

/* Правило совместимости форм — ТРЕТЬЯ составляющая ключа привязки, и оно
 * несимметрично по смыслу, но симметрично по устройству: ноль с ЛЮБОЙ
 * стороны означает "не измерено" (§2.4), а "не измерено" не противоречит
 * ничему. Противоречат только две РАЗНЫЕ измеренные формы.
 *
 * Правило проверяется здесь, а не только через планировщика: от него зависит,
 * удвоится ли накопленный каталог при первом же обновлении. */
static void check_shape_fits_rule(void) {
    CHECK(d2k_cat_shape_fits(0, D2K_SHAPE_MODERN) == 1,
          "записанное \"не измерено\" не приняло современную форму");
    CHECK(d2k_cat_shape_fits(0, D2K_SHAPE_LEGACY) == 1,
          "записанное \"не измерено\" не приняло старую форму");
    CHECK(d2k_cat_shape_fits(D2K_SHAPE_MODERN, 0) == 1,
          "неизмеренная форма проверки не подошла к записанной");
    CHECK(d2k_cat_shape_fits(0, 0) == 1, "два \"не измерено\" разошлись между собой");
    CHECK(d2k_cat_shape_fits(D2K_SHAPE_MODERN, D2K_SHAPE_MODERN) == 1,
          "одинаковые формы не сошлись");
    CHECK(d2k_cat_shape_fits(D2K_SHAPE_LEGACY, D2K_SHAPE_LEGACY) == 1,
          "одинаковые формы не сошлись");
    CHECK(d2k_cat_shape_fits(D2K_SHAPE_MODERN, D2K_SHAPE_LEGACY) == 0,
          "успех современной формы перенесён на старую");
    CHECK(d2k_cat_shape_fits(D2K_SHAPE_LEGACY, D2K_SHAPE_MODERN) == 0,
          "успех старой формы перенесён на современную");
}

/* Форма приветствия — часть ключа привязки, значит файл обязан нести ДВЕ
 * привязки одной цели, различающиеся только формой, и круговой обход обязан
 * вернуть обе СО СВОИМИ формами, а не схлопнуть их в одну.
 *
 * Берётся настоящий снимок, а не синтетика: так проверяется и то, что новые
 * поля не портят соседей в реальной раскладке файла. */
static void check_two_shapes_of_one_target_survive(void) {
    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("testdata/catalog-real.json", &c, err, sizeof err) == 0,
          "загрузка перед проверкой двух форм");
    if (c.n_boxes == 0 || c.boxes[0].n_binds == 0) {
        CHECK(0, "в снимке нет привязок — проверять нечего");
        d2k_catalog_free(&c);
        return;
    }
    d2k_cat_box *b = &c.boxes[0];
    d2k_cat_binding *grown = realloc(b->binds, (b->n_binds + 1) * sizeof *grown);
    CHECK(grown != NULL, "не хватило памяти на вторую привязку");
    if (!grown) { d2k_catalog_free(&c); return; }
    b->binds = grown;
    b->binds[b->n_binds] = b->binds[0];   /* та же цель, тот же транспорт */
    b->binds[0].shape = (uint8_t)D2K_SHAPE_MODERN;
    b->binds[0].verified_by = D2K_VERBY_PROBE;
    b->binds[b->n_binds].shape = (uint8_t)D2K_SHAPE_LEGACY;
    b->binds[b->n_binds].verified_by = D2K_VERBY_CLIENT;
    b->n_binds++;

    char target[256];
    snprintf(target, sizeof target, "%s", b->binds[0].target);
    CHECK(d2k_catalog_save(&c, "/tmp/d2k-cat-shape.json", err, sizeof err) == 0,
          "запись двух форм одной цели");
    d2k_catalog_free(&c);

    CHECK(d2k_catalog_load("/tmp/d2k-cat-shape.json", &c, err, sizeof err) == 0,
          "перечитывание двух форм одной цели");
    int modern = 0, legacy = 0;
    if (c.n_boxes > 0) {
        for (size_t j = 0; j < c.boxes[0].n_binds; j++) {
            const d2k_cat_binding *bd = &c.boxes[0].binds[j];
            if (strcmp(bd->target, target) != 0) { continue; }
            if (bd->shape == (uint8_t)D2K_SHAPE_MODERN &&
                bd->verified_by == D2K_VERBY_PROBE) { modern++; }
            if (bd->shape == (uint8_t)D2K_SHAPE_LEGACY &&
                bd->verified_by == D2K_VERBY_CLIENT) { legacy++; }
        }
    }
    CHECK(modern == 1, "привязка современной формы не пережила круговой обход");
    CHECK(legacy == 1, "привязка старой формы не пережила круговой обход");
    d2k_catalog_free(&c);
}

/* ЧЕМ МЕРИЛИ — ЧАСТЬ ЗАПИСИ, А НЕ ПОДРАЗУМЕВАЕМОЕ.
 *
 * План выводится из замера, а замер идёт КАКИМИ-ТО байтами: либо снятыми у
 * настоящего клиента, либо заготовкой холодного старта, когда снимка ещё
 * нет. Это разные по силе доказательства, и привязка обязана помнить, какое
 * у неё. Без поля обе выглядели одинаково, и слабая молча выдавалась за
 * сильную. */
static void check_input_completeness_survives(void) {
    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("testdata/catalog-real.json", &c, err, sizeof err) == 0,
          "загрузка перед проверкой полноты входа");
    if (c.n_boxes == 0 || c.boxes[0].n_binds == 0) {
        CHECK(0, "в снимке нет привязок — проверять нечего");
        d2k_catalog_free(&c);
        return;
    }
    /* Старый файл поля не знает — это «не записано», а не «профиль». */
    CHECK(c.boxes[0].binds[0].input == 0,
          "у старой записи полнота входа взялась из ниоткуда");
    char target[256];
    snprintf(target, sizeof target, "%s", c.boxes[0].binds[0].target);
    c.boxes[0].binds[0].input = D2K_INPUT_CLIENT;
    CHECK(d2k_catalog_save(&c, "/tmp/d2k-cat-input.json", err, sizeof err) == 0,
          "запись полноты входа");
    d2k_catalog_free(&c);
    CHECK(d2k_catalog_load("/tmp/d2k-cat-input.json", &c, err, sizeof err) == 0,
          "перечитывание полноты входа");
    int seen = 0;
    if (c.n_boxes > 0) {
        for (size_t j = 0; j < c.boxes[0].n_binds; j++) {
            if (strcmp(c.boxes[0].binds[j].target, target) == 0 &&
                c.boxes[0].binds[j].input == D2K_INPUT_CLIENT) { seen++; }
        }
    }
    CHECK(seen == 1, "полнота входа не пережила круговой обход");
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

static void check_dns_context_persistence(void) {
    const char *path = "/tmp/d2k-cat-dns-context.json";
    const char *out = "/tmp/d2k-cat-dns-context-out.json";
    char err[200], buf[8192];
    d2k_catalog c;
    write_tmp(path, "{\"boxes\":[{\"bindings\":["
        "{\"kind\":\"name\",\"target\":\"resolver.test\",\"family\":4,"
        "\"dns_name\":\"resolver.test\",\"dns_port\":8443,\"dns_address\":\"192.0.2.53\",\"probe_path\":\"/dns-query\"},"
        "{\"kind\":\"name\",\"target\":\"resolver.test\",\"family\":6,"
        "\"dns_address\":\"2001:db8::53\",\"dns_port\":65535,\"probe_path\":\"/dns-query\"}]}]}");
    CHECK(d2k_catalog_load(path, &c, err, sizeof err) == 0, "load DNS context");
    CHECK(d2k_catalog_save(&c, out, err, sizeof err) == 0, "save DNS context");
    d2k_catalog_free(&c);
    FILE *f = fopen(out, "r");
    CHECK(f != NULL, "open saved DNS context");
    if (f) {
        size_t n = fread(buf, 1, sizeof buf - 1, f); buf[n] = 0; fclose(f);
        CHECK(strstr(buf, "\"dns_port\": 8443") != NULL, "DNS port lost on save");
        CHECK(strstr(buf, "\"dns_address\": \"192.0.2.53\"") != NULL,
              "IPv4 DNS address lost on save");
        CHECK(strstr(buf, "\"dns_address\": \"2001:db8::53\"") != NULL,
              "IPv6 DNS address lost on save");
        CHECK(strstr(buf, "\"server_port\"") == NULL, "DNS proof changed legacy binding kind");
    }
    CHECK(d2k_catalog_load(out, &c, err, sizeof err) == 0, "reload DNS context");
    CHECK(c.n_boxes == 1 && c.boxes[0].n_binds == 2, "DNS contexts survive reload");
    if (c.n_boxes == 1 && c.boxes[0].n_binds == 2) {
        const d2k_cat_binding *v4 = &c.boxes[0].binds[0], *v6 = &c.boxes[0].binds[1];
        CHECK(v4->dns_port == 8443 && !strcmp(v4->dns_name, "resolver.test") && !strcmp(v4->dns_address, "192.0.2.53") &&
              !strcmp(v4->probe_path, "/dns-query"), "IPv4 DNS context roundtrip");
        CHECK(v6->dns_port == 65535 && !strcmp(v6->dns_address, "2001:db8::53") &&
              !strcmp(v6->probe_path, "/dns-query"), "IPv6 DNS context roundtrip");
        CHECK(v4->server_port == 0 && v6->server_port == 0, "DNS port changed legacy service port");
    }
    d2k_catalog_free(&c);

    /* An HTTP resource alone is not a DNS-contract witness. */
    write_tmp(path, "{\"boxes\":[{\"bindings\":[{\"kind\":\"name\","
        "\"target\":\"resolver.test\",\"probe_path\":\"/main.css\"}]}]}");
    CHECK(d2k_catalog_load(path, &c, err, sizeof err) == 0, "load legacy HTTP context");
    if (c.n_boxes == 1 && c.boxes[0].n_binds == 1)
        CHECK(c.boxes[0].binds[0].dns_port == 0 && !c.boxes[0].binds[0].dns_address[0] &&
              !c.boxes[0].binds[0].dns_name[0],
              "legacy HTTP context invented DNS witness");
    CHECK(d2k_catalog_save(&c, out, err, sizeof err) == 0, "save legacy HTTP context");
    d2k_catalog_free(&c);
    f = fopen(out, "r");
    CHECK(f != NULL, "open saved legacy HTTP context");
    if (f) {
        size_t n = fread(buf, 1, sizeof buf - 1, f); buf[n] = 0; fclose(f);
        CHECK(strstr(buf, "\"dns_port\"") == NULL && strstr(buf, "\"dns_address\"") == NULL,
              "HTTP resource invented DNS proof");
    }
    const char *bad[] = {
        "\"dns_port\":0", "\"dns_port\":-1", "\"dns_port\":65536",
        "\"dns_port\":443.0", "\"dns_port\":\"443\"", "\"dns_port\":null",
        "\"dns_address\":\"resolver.test\"", "\"dns_address\":\"192.0.2.999\"",
        "\"dns_address\":\"\"", "\"dns_address\":\"fe80::1%en0\"",
        "\"dns_address\":\"2001:db8::53\",\"family\":4",
        "\"family\":6,\"dns_address\":\"192.0.2.53\""
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        snprintf(buf, sizeof buf, "{\"boxes\":[{\"bindings\":[{%s}]}]}", bad[i]);
        write_tmp(path, buf);
        int rc = d2k_catalog_load(path, &c, err, sizeof err);
        CHECK(rc != 0, "invalid DNS context accepted");
        CHECK(rc == 0 || err[0] != 0, "invalid DNS context has no diagnostic");
        d2k_catalog_free(&c);
    }
}

static void check_binding_family_persistence(void) {
    const char *path = "/tmp/d2k-cat-family.json";
    const char *out = "/tmp/d2k-cat-family-out.json";
    char err[200];
    /* Old bindings must become explicitly IPv4; a new IPv6 binding for
       the same name must retain its own identity through save/reload. */
    write_tmp(path, "{\"boxes\":[{\"bindings\":["
        "{\"target\":\"example.com\",\"transport\":6},"
        "{\"target\":\"example.com\",\"transport\":6,\"family\":6}]}]}");
    d2k_catalog c;
    CHECK(d2k_catalog_load(path, &c, err, sizeof err) == 0, "load family fixture");
    CHECK(c.n_boxes == 1 && c.boxes[0].n_binds == 2 &&
          c.boxes[0].binds[0].probe_path[0] == 0,
          "legacy binding invented resource witness");
    if (c.n_boxes == 1 && c.boxes[0].n_binds == 2) {
        strcpy(c.boxes[0].binds[1].probe_path, "/public/main.css");
        strcpy(c.boxes[0].binds[1].ech_origin, "witness.example");
    }
    CHECK(d2k_catalog_save(&c, out, err, sizeof err) == 0, "save family fixture");
    d2k_catalog_free(&c);
    FILE *f = fopen(out, "r");
    CHECK(f != NULL, "open saved family fixture");
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof buf - 1, f);
        buf[n] = 0; fclose(f);
        CHECK(strstr(buf, "\"family\": 4") != NULL, "legacy binding saved as IPv4");
        CHECK(strstr(buf, "\"family\": 6") != NULL, "IPv6 binding preserved");
    }
    CHECK(d2k_catalog_load(out, &c, err, sizeof err) == 0, "reload family fixture");
    CHECK(c.n_boxes == 1 && c.boxes[0].n_binds == 2, "both bindings survive");
    if (c.n_boxes == 1 && c.boxes[0].n_binds == 2)
        CHECK(!strcmp(c.boxes[0].binds[1].probe_path, "/public/main.css"),
              "resource witness not preserved across save/reload");
    if (c.n_boxes == 1 && c.boxes[0].n_binds == 2) {
        CHECK(!strcmp(c.boxes[0].binds[1].ech_origin, "witness.example"),
              "ECH witness not preserved across save/reload");
        CHECK(c.boxes[0].binds[0].family == 4, "legacy binding reloads as IPv4");
        CHECK(c.boxes[0].binds[1].family == 6, "IPv6 binding reloads as IPv6");
    }
    d2k_catalog_free(&c);
    write_tmp(path, "{\"boxes\":[{\"bindings\":[{\"family\":5}]}]}");
    CHECK(d2k_catalog_load(path, &c, err, sizeof err) != 0, "reject invalid binding family");
    d2k_catalog_free(&c);
}

/* Задача 21: пометка «требует повторной проверки» переживает перезапуск, а
   старый файл без ключа читается как «не помечена». Монотонная отметка
   процесса в файл не попадает. */
static void check_recheck_mark_persistence(void) {
    const char *path = "/tmp/d2k-cat-recheck.json";
    const char *out = "/tmp/d2k-cat-recheck-out.json";
    char err[200];
    write_tmp(path, "{\"boxes\":[{\"bindings\":["
        "{\"target\":\"old.example\",\"transport\":6,\"shape\":1},"
        "{\"target\":\"marked.example\",\"transport\":6,\"shape\":1}]}]}");
    d2k_catalog c;
    CHECK(d2k_catalog_load(path, &c, err, sizeof err) == 0, "load recheck fixture");
    CHECK(c.n_boxes == 1 && c.boxes[0].n_binds == 2 &&
          c.boxes[0].binds[0].recheck_since == 0 && c.boxes[0].binds[1].recheck_since == 0,
          "old file without recheck_since invented a recheck mark");
    if (c.n_boxes == 1 && c.boxes[0].n_binds == 2) {
        c.boxes[0].binds[1].recheck_since = 1790000000;
        c.boxes[0].binds[1].recheck_mono_ms = 12345;
    }
    CHECK(d2k_catalog_save(&c, out, err, sizeof err) == 0, "save recheck fixture");
    d2k_catalog_free(&c);
    FILE *f = fopen(out, "r");
    CHECK(f != NULL, "open saved recheck fixture");
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof buf - 1, f);
        buf[n] = 0; fclose(f);
        const char *first = strstr(buf, "\"recheck_since\"");
        CHECK(first != NULL && strstr(first + 1, "\"recheck_since\"") == NULL,
              "recheck_since must be written for the marked binding only");
        CHECK(strstr(buf, "recheck_mono") == NULL, "process-local recheck time leaked to file");
    }
    CHECK(d2k_catalog_load(out, &c, err, sizeof err) == 0, "reload recheck fixture");
    CHECK(c.n_boxes == 1 && c.boxes[0].n_binds == 2 &&
          c.boxes[0].binds[0].recheck_since == 0 &&
          c.boxes[0].binds[1].recheck_since == 1790000000 &&
          c.boxes[0].binds[1].recheck_mono_ms == 0,
          "recheck mark not preserved across restart (or monotonic stamp survived)");
    d2k_catalog_free(&c);
}

/* Задача 55: отметка «бюджет пройден/не проверен» привязки и бюджет коробки
   (пакеты на обрыве rx-volume) переживают перезапуск; старый файл без ключей
   читается как «не проверено» и «не измерено», ничего не выдумывая. */
static void check_budget_persistence(void) {
    const char *path = "/tmp/d2k-cat-budget.json";
    const char *out = "/tmp/d2k-cat-budget-out.json";
    char err[200];
    write_tmp(path, "{\"boxes\":[{\"id\":\"box-b\",\"fingerprint\":{\"method\":2,\"signals\":["
        "{\"kind\":\"rx-volume\",\"volume\":20,\"seen\":1}]},\"bindings\":["
        "{\"target\":\"old.example\",\"transport\":6,\"shape\":1},"
        "{\"target\":\"passed.example\",\"transport\":6,\"shape\":1},"
        "{\"target\":\"unchecked.example\",\"transport\":6,\"shape\":1}]}]}");
    d2k_catalog c;
    CHECK(d2k_catalog_load(path, &c, err, sizeof err) == 0, "load budget fixture");
    CHECK(c.n_boxes == 1 && c.boxes[0].n_binds == 3 && c.boxes[0].binds[0].budget == 0 &&
          c.boxes[0].fp.n_sig == 1 && c.boxes[0].fp.sig[0].packets == 0,
          "old file invented a budget mark or a box budget");
    if (c.n_boxes == 1 && c.boxes[0].n_binds == 3) {
        c.boxes[0].binds[1].budget = D2K_CAT_BUDGET_PASSED;
        c.boxes[0].binds[2].budget = D2K_CAT_BUDGET_UNCHECKED;
        c.boxes[0].fp.sig[0].packets = 25;
    }
    CHECK(d2k_catalog_save(&c, out, err, sizeof err) == 0, "save budget fixture");
    d2k_catalog_free(&c);
    FILE *f = fopen(out, "r");
    if (f) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof buf - 1, f);
        buf[n] = 0; fclose(f);
        int keys = 0;
        for (const char *q = buf; (q = strstr(q, "\"budget\"")) != NULL; q++) keys++;
        CHECK(keys == 2, "budget key must be written only for checked bindings");
    }
    CHECK(d2k_catalog_load(out, &c, err, sizeof err) == 0, "reload budget fixture");
    CHECK(c.n_boxes == 1 && c.boxes[0].n_binds == 3 && c.boxes[0].binds[0].budget == 0 &&
          c.boxes[0].binds[1].budget == D2K_CAT_BUDGET_PASSED &&
          c.boxes[0].binds[2].budget == D2K_CAT_BUDGET_UNCHECKED &&
          c.boxes[0].fp.sig[0].packets == 25,
          "budget mark or box budget not preserved across restart");
    d2k_catalog_free(&c);
}

/* Объёмные коробки (задача 23): направление (род приметы) и порог (volume)
 * переживают круговой обход — по ним коробку узнают и называют. Старая
 * запись объёмной приметы без поля volume грузится и остаётся с порогом 0
 * («корзина не измерена»), а не валит разбор и не получает выдуманный порог. */
static void check_volume_box_fingerprint_persistence(void) {
    write_tmp("/tmp/d2k-cat-vol.json",
        "{\"schema\":1,\"updated\":\"2026-01-01T00:00:00Z\",\"boxes\":["
        "{\"id\":\"box-tx16\",\"created\":\"2026-01-01T00:00:00Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\","
        "\"fingerprint\":{\"method\":2,\"signals\":[{\"kind\":\"volume\",\"volume\":16,\"seen\":1}]},"
        "\"plans\":[],\"bindings\":[]},"
        "{\"id\":\"box-rx128\",\"created\":\"2026-01-01T00:00:00Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\","
        "\"fingerprint\":{\"method\":2,\"signals\":[{\"kind\":\"rx-volume\",\"volume\":128,\"seen\":1}]},"
        "\"plans\":[],\"bindings\":[]},"
        "{\"id\":\"box-old\",\"created\":\"2026-01-01T00:00:00Z\","
        "\"updated\":\"2026-01-01T00:00:00Z\","
        "\"fingerprint\":{\"method\":2,\"signals\":[{\"kind\":\"volume\",\"seen\":3}]},"
        "\"plans\":[],\"bindings\":[]}]}");
    d2k_catalog c; char err[200] = {0};
    CHECK(d2k_catalog_load("/tmp/d2k-cat-vol.json", &c, err, sizeof err) == 0,
          "объёмные коробки (в т.ч. старая без порога) не загрузились");
    CHECK(c.n_boxes == 3 && c.boxes[2].fp.n_sig == 1 &&
          strcmp(c.boxes[2].fp.sig[0].kind, "volume") == 0 &&
          c.boxes[2].fp.sig[0].volume == 0 && c.boxes[2].fp.sig[0].seen == 3,
          "старая объёмная примета без порога загрузилась не как «порог не измерен»");
    CHECK(d2k_catalog_save(&c, "/tmp/d2k-cat-vol-rt.json", err, sizeof err) == 0,
          "запись объёмных коробок");
    d2k_catalog_free(&c);
    CHECK(d2k_catalog_load("/tmp/d2k-cat-vol-rt.json", &c, err, sizeof err) == 0,
          "перечитывание объёмных коробок");
    CHECK(c.n_boxes == 3 &&
          strcmp(c.boxes[0].fp.sig[0].kind, "volume") == 0 && c.boxes[0].fp.sig[0].volume == 16 &&
          strcmp(c.boxes[1].fp.sig[0].kind, "rx-volume") == 0 && c.boxes[1].fp.sig[0].volume == 128 &&
          c.boxes[2].fp.sig[0].volume == 0,
          "направление или порог объёмной коробки потерялись при круговом обходе");
    d2k_catalog_free(&c);
}

/* БЕЛОЕ ИМЯ СЕТИ — ВЕРХНЕУРОВНЕВОЕ ПОЛЕ (поле 10.10.2026). SNI-whitelist
 * коробки различается по оператору и в поле одно имя (hcaptcha.com) сняло
 * RX-обрыв сразу у нескольких целей за Cloudflare: это свойство сети, не
 * цели. Хранится рядом с boxes, переживает перезапуск (подбор стоит до 266
 * зондов). Исход «не найдено» тоже хранится с меткой времени, чтобы не
 * перебирать список на каждой цели, пока сеть не сменится. */
static void check_network_whitelist_roundtrip(void) {
    /* Найдено: имя + метка + searched. */
    write_tmp("/tmp/d2k-cat-net.json",
        "{\"boxes\":[],\"network_whitelist\":{\"name\":\"hcaptcha.com\","
        "\"searched\":true,\"confirmed_utc\":\"2026-10-10T00:48:41Z\"}}");
    {
        d2k_catalog c; char err[200] = {0};
        CHECK(d2k_catalog_load("/tmp/d2k-cat-net.json", &c, err, sizeof err) == 0,
              "каталог с network_whitelist не прочитался");
        CHECK(!strcmp(c.net.name, "hcaptcha.com"), "белое имя сети не прочиталось");
        CHECK(c.net.searched == 1, "метка «подбор доведён» не прочиталась");
        CHECK(c.net.confirmed_at == 1791593321, "время подтверждения белого имени не то");
        CHECK(d2k_catalog_save(&c, "/tmp/d2k-cat-net-out.json", err, sizeof err) == 0,
              "каталог с белым именем не записался");
        d2k_catalog_free(&c);
        FILE *rf = fopen("/tmp/d2k-cat-net-out.json", "r");
        CHECK(rf != NULL, "записанный каталог с белым именем не открылся");
        if (rf) {
            char buf[8192]; size_t got = fread(buf, 1, sizeof buf - 1, rf); buf[got] = 0; fclose(rf);
            CHECK(strstr(buf, "\"network_whitelist\": {") != NULL, "поле network_whitelist не записано");
            CHECK(strstr(buf, "\"name\": \"hcaptcha.com\"") != NULL, "имя в записи потеряно");
            CHECK(strstr(buf, "\"searched\": true") != NULL, "метка searched в записи потеряна");
            CHECK(strstr(buf, "\"confirmed_utc\": \"2026-10-10T00:48:41Z\"") != NULL,
                  "время в записи не RFC 3339");
        }
    }
    /* Честное «не найдено»: searched=true, имя пустое — сохраняется с меткой,
       чтобы не перебирать заново. */
    write_tmp("/tmp/d2k-cat-net-none.json",
        "{\"boxes\":[],\"network_whitelist\":{\"name\":\"\",\"searched\":true,"
        "\"confirmed_utc\":\"2026-10-10T00:48:41Z\"}}");
    {
        d2k_catalog c; char err[200] = {0};
        CHECK(d2k_catalog_load("/tmp/d2k-cat-net-none.json", &c, err, sizeof err) == 0,
              "каталог с «не найдено» не прочитался");
        CHECK(c.net.name[0] == '\0' && c.net.searched == 1,
              "«не найдено» с меткой не сохранилось как отдельный исход");
        CHECK(d2k_catalog_save(&c, "/tmp/d2k-cat-net-none-out.json", err, sizeof err) == 0,
              "каталог «не найдено» не записался");
        d2k_catalog_free(&c);
        FILE *rf = fopen("/tmp/d2k-cat-net-none-out.json", "r");
        if (rf) {
            char buf[8192]; size_t got = fread(buf, 1, sizeof buf - 1, rf); buf[got] = 0; fclose(rf);
            CHECK(strstr(buf, "\"searched\": true") != NULL,
                  "исход «не найдено» не пережил круговой обход");
        }
    }
    /* Старый файл без поля: не найдено, не искали. */
    write_tmp("/tmp/d2k-cat-net-old.json", "{\"boxes\":[]}");
    {
        d2k_catalog c; char err[200] = {0};
        CHECK(d2k_catalog_load("/tmp/d2k-cat-net-old.json", &c, err, sizeof err) == 0,
              "старый каталог без network_whitelist не прочитался");
        CHECK(c.net.name[0] == '\0' && c.net.searched == 0 && c.net.confirmed_at == 0,
              "старый файл дал не-пустое белое имя сети");
        d2k_catalog_save(&c, "/tmp/d2k-cat-net-old-out.json", err, sizeof err);
        d2k_catalog_free(&c);
        FILE *rf = fopen("/tmp/d2k-cat-net-old-out.json", "r");
        if (rf) {
            char buf[8192]; size_t got = fread(buf, 1, sizeof buf - 1, rf); buf[got] = 0; fclose(rf);
            CHECK(strstr(buf, "network_whitelist") == NULL,
                  "пустое белое имя записано лишним полем");
        }
    }
}

static void check_raw_service_persistence(void) {
    const char *path = "/tmp/d2k-cat-raw-service.json";
    const char *out = "/tmp/d2k-cat-raw-service-out.json";
    for (unsigned family = 4; family <= 6; family += 2) {
        const char *ip = family == 4 ? "192.0.2.8" : "2001:db8::8";
        char json[1024], err[200];
        snprintf(json, sizeof json, "{\"boxes\":[{\"endpoints\":["
            "{\"kind\":\"service\",\"target\":\"%s\",\"family\":%u,\"server_port\":443,\"transport\":6,\"shape\":8},"
            "{\"kind\":\"service\",\"target\":\"%s\",\"family\":%u,\"server_port\":443,\"transport\":17,\"shape\":8}]}]}",
            ip, family, ip, family);
        write_tmp(path, json);
        d2k_catalog c;
        int loaded = d2k_catalog_load(path, &c, err, sizeof err);
        CHECK(!loaded, "RAW service: accept explicit TCP and UDP endpoints");
        if (loaded) continue;
        CHECK(!d2k_catalog_save(&c, out, err, sizeof err), "RAW service: persist endpoints");
        d2k_catalog_free(&c);
        loaded = d2k_catalog_load(out, &c, err, sizeof err);
        CHECK(!loaded, "RAW service: reload endpoints");
        if (loaded) continue;
        CHECK(c.n_boxes == 1 && c.boxes[0].n_binds == 2, "RAW service: both transports retained");
        if (c.n_boxes == 1 && c.boxes[0].n_binds == 2) {
            for (unsigned j = 0; j < 2; j++) {
                d2k_cat_binding *b = &c.boxes[0].binds[j];
                CHECK(!strcmp(b->kind, "service") && b->server_port == 443 &&
                      b->family == family && b->shape == 8 &&
                      b->transport == (j ? 17 : 6) && !strcmp(b->target, ip),
                      "RAW service: address, port, shape and transport survive restart");
            }
            c.boxes[0].binds[0].transport = 0;
            CHECK(d2k_catalog_save(&c, out, err, sizeof err) != 0,
                  "RAW service: unspecified transport refused");
        }
        d2k_catalog_free(&c);
    }
}

static void check_service_persistence(void) {
    const char *path="/tmp/d2k-cat-service.json", *out="/tmp/d2k-cat-service-out.json";
    char err[200];
    write_tmp(path,"{\"boxes\":[{\"endpoints\":["
        "{\"kind\":\"service\",\"target\":\"192.0.2.1\",\"server_port\":3478,\"family\":4,\"transport\":17,\"shape\":5,\"enabled\":true},"
        "{\"kind\":\"service\",\"target\":\"2001:db8::1\",\"server_port\":65535,\"family\":6,\"transport\":17,\"shape\":5,\"enabled\":true}],"
        "\"bindings\":[{\"kind\":\"addr\",\"target\":\"192.0.2.1\",\"enabled\":true}]}]}");
    d2k_catalog c;
    CHECK(d2k_catalog_load(path,&c,err,sizeof err)==0,"load exact services with legacy binding");
    CHECK(c.n_boxes==1 && c.boxes[0].n_binds==3,"append both arrays independent of order");
    if (c.n_boxes==1 && c.boxes[0].n_binds==3) {
        CHECK(c.boxes[0].binds[0].server_port==3478 && c.boxes[0].binds[1].server_port==65535,
              "service ports survive input");
        CHECK(c.boxes[0].binds[2].server_port==0,"legacy binding does not invent port");
    }
    CHECK(d2k_catalog_save(&c,out,err,sizeof err)==0,"save exact services");
    d2k_catalog_free(&c);
    CHECK(d2k_catalog_load(out,&c,err,sizeof err)==0,"reload service catalog");
    CHECK(c.n_boxes==1 && c.boxes[0].n_binds==3,"reload keeps service and legacy entries");
    if (c.n_boxes==1 && c.boxes[0].n_binds==3) {
        CHECK(!strcmp(c.boxes[0].binds[0].kind,"addr") && c.boxes[0].binds[0].server_port==0,
              "legacy array stays portless");
        CHECK(!strcmp(c.boxes[0].binds[1].kind,"service") && c.boxes[0].binds[1].server_port==3478 &&
              c.boxes[0].binds[2].server_port==65535 && c.boxes[0].binds[2].family==6,
              "exact service identity survives roundtrip");
        c.boxes[0].binds[1].server_port=0;
        CHECK(d2k_catalog_save(&c,"/tmp/d2k-cat-service-invalid.json",err,sizeof err)!=0,
              "save refuses wildcard service authority");
    }
    d2k_catalog_free(&c);
    const char *bad[]={
        "{\"kind\":\"service\",\"server_port\":0}",
        "{\"kind\":\"service\",\"server_port\":65536}",
        "{\"kind\":\"service\",\"server_port\":-1}",
        "{\"kind\":\"name\",\"server_port\":443}",
        "{\"kind\":\"service\",\"server_port\":443,\"target\":\"example.com\",\"transport\":6,\"shape\":1}",
        "{\"kind\":\"service\",\"server_port\":443,\"target\":\"192.0.2.1\",\"transport\":17,\"shape\":1}"
    };
    for(size_t i=0;i<sizeof bad/sizeof bad[0];i++) {
        char buf[600];snprintf(buf,sizeof buf,"{\"boxes\":[{\"endpoints\":[%s]}]}",bad[i]);
        write_tmp(path,buf);
        CHECK(d2k_catalog_load(path,&c,err,sizeof err)!=0,"invalid service key rejected");
        d2k_catalog_free(&c);
    }
    write_tmp(path,"{\"boxes\":[{\"bindings\":[{\"kind\":\"addr\",\"server_port\":443}]}]}");
    CHECK(d2k_catalog_load(path,&c,err,sizeof err)!=0,"legacy array cannot hide new port semantics");
    d2k_catalog_free(&c);
}


static void test_gate_props_roundtrip(void) {
    d2k_catalog c; char err[200] = {0};
    const char *path = "/tmp/d2k-cat-gate.json";
    write_tmp(path, "{\"boxes\":[{\"id\":\"gate\",\"properties\":[{\"handles_urgent\":\"no\",\"hops\":12}]}]}");
    CHECK(d2k_catalog_load(path, &c, err, sizeof err) == 0, "gate: load old properties");
    if (!c.n_boxes || !c.boxes[0].n_props) { d2k_catalog_free(&c); return; }
    d2k_box_props *p = &c.boxes[0].props[0].p;
    CHECK(p->response_gate == D2K_PROP_UNKNOWN && p->gate_carry == D2K_PROP_UNKNOWN &&
          p->gate_hello_own == D2K_PROP_UNKNOWN && !p->gate_window &&
          !p->gate_pieces && !p->gate_rtt_ms, "gate: old fields must be unknown");
    p->response_gate = D2K_PROP_YES; p->gate_window = 17; p->gate_pieces = 1234;
    p->gate_carry = D2K_PROP_YES; p->gate_hello_own = D2K_PROP_NO; p->gate_rtt_ms = 42;
    CHECK(d2k_catalog_save(&c, path, err, sizeof err) == 0, "gate: save");
    d2k_catalog_free(&c);
    CHECK(d2k_catalog_load(path, &c, err, sizeof err) == 0, "gate: reload");
    if (c.n_boxes && c.boxes[0].n_props) {
        p = &c.boxes[0].props[0].p;
        CHECK(p->response_gate == D2K_PROP_YES && p->gate_window == 17 &&
              p->gate_pieces == 1234 && p->gate_carry == D2K_PROP_YES &&
              p->gate_hello_own == D2K_PROP_NO && p->gate_rtt_ms == 42,
              "test_gate_props_roundtrip: measured fields lost");
        CHECK(p->handles_urgent == D2K_PROP_NO && p->hops == 12, "gate: old fields lost");
    } else CHECK(0, "gate: properties lost");
    d2k_catalog_free(&c);
}
static void test_gate_negative_is_known(void) {
    d2k_catalog c; char err[200] = {0};
    const char *path = "/tmp/d2k-cat-gate-negative.json";
    write_tmp(path, "{\"boxes\":[{\"id\":\"gate\",\"properties\":[{\"response_gate\":\"yes\",\"gate_carry\":\"no\"}]}]}");
    CHECK(d2k_catalog_load(path, &c, err, sizeof err) == 0, "negative: load");
    CHECK(c.n_boxes && c.boxes[0].n_props &&
          c.boxes[0].props[0].p.gate_carry == D2K_PROP_NO,
          "test_gate_negative_is_known: no read as unknown");
    CHECK(d2k_catalog_save(&c, path, err, sizeof err) == 0, "negative: save");
    d2k_catalog_free(&c);
    CHECK(d2k_catalog_load(path, &c, err, sizeof err) == 0, "negative: reload");
    CHECK(c.n_boxes && c.boxes[0].n_props &&
          c.boxes[0].props[0].p.gate_carry == D2K_PROP_NO,
          "test_gate_negative_is_known: no lost on roundtrip");
    d2k_catalog_free(&c);
}


static void test_preflight_catalog_endpoint_only(void) {
    const char *path="/tmp/d2k-cat-preflight.json";
    char err[200];d2k_catalog c={0};d2k_cat_box box={0};
    d2k_cat_plan plan={0};d2k_cat_binding bind={0};
    c.boxes=&box;c.n_boxes=1;box.plans=&plan;box.n_plans=1;box.binds=&bind;box.n_binds=1;
    strcpy(box.id,"gate");strcpy(plan.id,"pf");strcpy(plan.proto,"tls");plan.enabled=1;
    plan.text="d2k-plan 1 18\nproto tcp tls\npreflight window=7 wscale=0 pieces=9 hello=own timeout=2400 data=1\npayload 1 160301\n";
    strcpy(bind.plan_id,"pf");strcpy(bind.kind,"name");strcpy(bind.target,"x.example");
    bind.enabled=1;bind.transport=6;bind.family=4;bind.shape=1;
    CHECK(d2k_catalog_save(&c,path,err,sizeof err)!=0,"preflight catalog accepted name binding");
    strcpy(bind.kind,"service");strcpy(bind.target,"192.0.2.1");bind.server_port=443;
    CHECK(d2k_catalog_save(&c,path,err,sizeof err)==0,"preflight catalog rejected IPv4 endpoint");
    d2k_catalog loaded={0};
    CHECK(d2k_catalog_load(path,&loaded,err,sizeof err)==0,"preflight catalog roundtrip failed");
    d2k_catalog_free(&loaded);
    bind.family=6;strcpy(bind.target,"2001:db8::1");
    strcpy(bind.preflight_name,"video.example");
    CHECK(d2k_catalog_save(&c,path,err,sizeof err)==0,"preflight catalog rejected IPv6 endpoint");
    CHECK(d2k_catalog_load(path,&loaded,err,sizeof err)==0,"preflight IPv6 catalog roundtrip failed");
    CHECK(loaded.n_boxes==1 && loaded.boxes[0].n_binds==1 &&
          loaded.boxes[0].binds[0].family==6 &&
          !strcmp(loaded.boxes[0].binds[0].target,"2001:db8::1") &&
          !strcmp(loaded.boxes[0].binds[0].preflight_name,"video.example"),
          "preflight IPv6 endpoint lost on reload");
    d2k_catalog_free(&loaded);
    write_tmp(path,"{\"boxes\":[{\"id\":\"gate\",\"plans\":[{\"id\":\"pf\",\"text\":\"d2k-plan 1 18\\nproto tcp tls\\npreflight window=7 wscale=0 pieces=9 hello=own timeout=2400 data=1\\npayload 1 160301\\n\"}],\"bindings\":[{\"kind\":\"name\",\"target\":\"x.example\",\"plan_id\":\"pf\"}]}]}");
    CHECK(d2k_catalog_load(path,&loaded,err,sizeof err)!=0,"preflight catalog loaded legacy name binding");
    d2k_catalog_free(&loaded);remove(path);
}
int main(void) {
    test_preflight_catalog_endpoint_only();
    test_gate_props_roundtrip();
    test_gate_negative_is_known();
    check_service_persistence();
    check_raw_service_persistence();
    check_network_whitelist_roundtrip();
    check_volume_box_fingerprint_persistence();
    check_binding_family_persistence();
    check_dns_context_persistence();
    check_recheck_mark_persistence();
    check_budget_persistence();
    check_time_roundtrip();
    check_transport_default_zero_on_old_file();
    check_shape_default_zero_on_old_file();
    check_shape_fits_rule();
    check_two_shapes_of_one_target_survive();
    check_input_completeness_survives();
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
        snprintf(c.boxes[0].binds[0].kind, sizeof c.boxes[0].binds[0].kind, "addr");
        snprintf(c.boxes[0].binds[0].target, sizeof c.boxes[0].binds[0].target,
                 "203.0.113.7");
        CHECK(d2k_catalog_save(&c, "/tmp/d2k-cat-tr.json", err, sizeof err) == 0, "запись");
        d2k_catalog_free(&c);
        CHECK(d2k_catalog_load("/tmp/d2k-cat-tr.json", &c, err, sizeof err) == 0, "перечитывание");
        CHECK(c.boxes[0].binds[0].transport == 17, "транспорт потерялся при круговом обходе");
        CHECK(strcmp(c.boxes[0].binds[0].kind, "addr") == 0 &&
              strcmp(c.boxes[0].binds[0].target, "203.0.113.7") == 0,
              "kind=addr/IPv4 target потерялись при круговом обходе");
        d2k_catalog_free(&c);
    }
    /* --- ВЕКТОР СВОЙСТВ КОРОБКИ (23.10.2026) ------------------------------
     *
     * Отпечаток до правки отвечал только на вопрос «та же коробка?»
     * (приметы узнавания), а знание «чем её брать» нигде не хранилось: оно
     * измерялось заново на каждой цели. Вектор лежит рядом с приметами, в
     * сравнение d2k_fp_same не входит и хранится С ФОРМОЙ КЛИЕНТА, которой
     * измерен (issue #7: клиент без метки времени не исполняет план со
     * сдвигом метки назад).
     *
     * ОТСУТСТВИЕ ПОЛЯ — «НЕ ИЗМЕРЕНО», А НЕ «НЕТ» (§2.4): поэтому в файл
     * пишутся только измеренные поля, а старый файл без ключа читается как
     * пустое знание, а не как отрицание всех свойств. */
    {
        d2k_catalog c; char err[200] = {0};
        write_tmp("/tmp/d2k-cat-props.json",
                  "{\"boxes\":[{\"id\":\"box-1\",\"properties\":[{"
                  "\"client_shape\":3,\"validates_checksum\":\"no\","
                  "\"counts_duplicates\":\"yes\",\"hops\":58,"
                  "\"reasm_boundary\":517,\"measured_utc\":\"2026-10-23T18:10:18Z\"}]}]}");
        CHECK(d2k_catalog_load("/tmp/d2k-cat-props.json", &c, err, sizeof err) == 0,
              "каталог с вектором свойств не разобрался");
        CHECK(c.n_boxes == 1 && c.boxes[0].n_props == 1, "вектор свойств не прочитан");
        if (c.n_boxes == 1 && c.boxes[0].n_props == 1) {
            const d2k_cat_props *r = &c.boxes[0].props[0];
            CHECK(r->p.client_shape == 3, "форма клиента потерялась");
            CHECK(r->p.validates_checksum == D2K_PROP_NO, "\"no\" прочитано не как НЕТ");
            CHECK(r->p.counts_duplicates == D2K_PROP_YES, "\"yes\" прочитано не как ДА");
            CHECK(r->p.hops == 58 && r->p.reasm_boundary == 517, "величины потерялись");
            CHECK(r->p.parses_l7 == D2K_PROP_UNKNOWN,
                  "отсутствующее поле прочитано не как «не измерено»");
            CHECK(r->measured_at == 1792779018, "время замера вектора потерялось");
        }
        /* Круговой обход: пишем и перечитываем — измеренное обязано дойти,
         * неизмеренное обязано остаться неизмеренным. */
        CHECK(d2k_catalog_save(&c, "/tmp/d2k-cat-props-out.json", err, sizeof err) == 0,
              "запись вектора свойств");
        d2k_catalog_free(&c);
        CHECK(d2k_catalog_load("/tmp/d2k-cat-props-out.json", &c, err, sizeof err) == 0,
              "перечитывание вектора свойств");
        if (c.n_boxes == 1 && c.boxes[0].n_props == 1) {
            const d2k_cat_props *r = &c.boxes[0].props[0];
            CHECK(r->p.validates_checksum == D2K_PROP_NO &&
                  r->p.counts_duplicates == D2K_PROP_YES &&
                  r->p.hops == 58 && r->p.reasm_boundary == 517 &&
                  r->p.client_shape == 3 && r->measured_at == 1792779018,
                  "вектор свойств потерялся при круговом обходе");
            CHECK(r->p.parses_l7 == D2K_PROP_UNKNOWN,
                  "неизмеренное свойство записалось отрицанием");
        } else {
            CHECK(0, "вектор свойств не дошёл до перечитывания");
        }
        d2k_catalog_free(&c);
    }
    {
        /* Файл БЕЗ ключа — пустое знание, а не отрицание. */
        d2k_catalog c; char err[200] = {0};
        CHECK(d2k_catalog_load("testdata/catalog-real.json", &c, err, sizeof err) == 0,
              "настоящий каталог не разобрался");
        CHECK(c.boxes[0].n_props == 0, "файл без ключа дал вектор из ниоткуда");
        d2k_catalog_free(&c);
    }
    {
        /* Девятая запись вектора — ОТКАЗ С ПРИЧИНОЙ, как девятая примета:
         * буфер фиксирован, и молчаливая потеря одной из девяти хуже отказа. */
        d2k_catalog c; char err[200] = {0};
        write_tmp("/tmp/d2k-cat-props-many.json",
                  "{\"boxes\":[{\"id\":\"box-1\",\"properties\":["
                  "{\"client_shape\":1},{\"client_shape\":2},{\"client_shape\":3},"
                  "{\"client_shape\":4},{\"client_shape\":5},{\"client_shape\":6},"
                  "{\"client_shape\":7},{\"client_shape\":8},{\"client_shape\":9}]}]}");
        CHECK(d2k_catalog_load("/tmp/d2k-cat-props-many.json", &c, err, sizeof err) != 0,
              "девятая запись вектора принята — буфер фиксирован на восьми");
        CHECK(err[0] != 0, "отказ без причины — человеку нечитаемо");
    }
    {
        /* Неизвестное значение признака — отказ, а не тихое «не измерено»:
         * иначе опечатка в файле читалась бы как отсутствие знания. */
        d2k_catalog c; char err[200] = {0};
        write_tmp("/tmp/d2k-cat-props-bad.json",
                  "{\"boxes\":[{\"id\":\"box-1\",\"properties\":["
                  "{\"client_shape\":3,\"parses_l7\":\"maybe\"}]}]}");
        CHECK(d2k_catalog_load("/tmp/d2k-cat-props-bad.json", &c, err, sizeof err) != 0,
              "значение \"maybe\" принято за тройственную логику");
        CHECK(err[0] != 0, "отказ без причины");
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
