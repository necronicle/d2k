/* test_journal.c — кольцо наблюдений.
 *
 * Проверяется прежде всего поведение на переполнении: журнал, который молча
 * теряет записи и не признаётся в этом, хуже отсутствующего — он выглядит
 * полным. И обрезка имени, которое приходит из сети и потому может быть
 * любым.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_journal.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static d2k_key mk(uint16_t port) {
    d2k_key k;
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    uint8_t sp[2], dp[2] = {0x01, 0xbb};
    memcpy(sp, &port, 2);
    d2k_key_make(&k, s, d, sp, dp);
    return k;
}

int main(void) {
    /* --- порядок от старой к новой ---------------------------------------- */
    {
        d2k_journal *j = d2k_journal_new(8);
        CHECK(j != NULL, "журнал не создался");
        CHECK(d2k_journal_count(j) == 0, "новый журнал не пуст");
        CHECK(d2k_journal_at(j, 0) == NULL, "из пустого журнала что-то взялось");

        for (uint16_t i = 0; i < 5; i++) {
            d2k_key k = mk(i);
            d2k_journal_add(j, 1000 + i, &k, D2K_JRN_HELLO_NONAME, 0, 0, NULL, NULL, 0, NULL);
        }
        CHECK(d2k_journal_count(j) == 5, "счётчик записей неверен");
        for (uint64_t i = 0; i < 5; i++) {
            const d2k_jrn_entry *e = d2k_journal_at(j, (size_t)i);
            CHECK(e && e->at_ns == 1000 + i, "порядок записей нарушен");
        }
        CHECK(d2k_journal_dropped(j) == 0, "потери там, где ничего не терялось");
        d2k_journal_free(j);
    }

    /* --- переполнение: старое затирается, потери считаются ------------------ */
    {
        d2k_journal *j = d2k_journal_new(4);
        for (uint16_t i = 0; i < 10; i++) {
            d2k_key k = mk(i);
            d2k_journal_add(j, 2000 + i, &k, D2K_JRN_HELLO_NONAME, 0, 0, NULL, NULL, 0, NULL);
        }
        CHECK(d2k_journal_count(j) == 4, "кольцо выросло за предел");
        CHECK(d2k_journal_dropped(j) == 6, "потерянные записи не посчитаны");
        /* Остаться должны последние четыре: 2006..2009. */
        for (size_t i = 0; i < 4; i++) {
            const d2k_jrn_entry *e = d2k_journal_at(j, i);
            if (!e || e->at_ns != 2006 + i) {
                printf("ПРОВАЛ: на позиции %zu ожидалось %llu, пришло %llu\n",
                       i, (unsigned long long)(2006 + i),
                       e ? (unsigned long long)e->at_ns : 0ull);
                fails++;
            }
        }
        CHECK(d2k_journal_at(j, 4) == NULL, "за пределом кольца что-то нашлось");
        d2k_journal_free(j);
    }

    /* --- обрезка имени ------------------------------------------------------ */
    {
        d2k_journal *j = d2k_journal_new(4);
        d2k_key k = mk(1);
        char longname[300];
        memset(longname, 'a', sizeof longname);
        d2k_journal_add(j, 1, &k, D2K_JRN_HELLO_SNI, 0, 0, NULL,
                        (const uint8_t *)longname, sizeof longname, NULL);
        const d2k_jrn_entry *e = d2k_journal_at(j, 0);
        CHECK(e && e->name_len == D2K_JRN_NAME_MAX, "имя обрезано не по пределу");
        CHECK(e && strlen(e->name) == D2K_JRN_NAME_MAX, "имя не завершено нулём");
        d2k_journal_free(j);
    }

    /* --- имя из сети может быть любым --------------------------------------
     * Журнал печатается в терминал и уходит в панель. Управляющие байты и
     * перевод строки оттуда доезжать не должны: одна запись не имеет права
     * выглядеть как несколько. Экранирование для HTML — дело панели, здесь
     * снимается только то, что ломает печать как таковую.                    */
    {
        d2k_journal *j = d2k_journal_new(4);
        d2k_key k = mk(1);
        const uint8_t nasty[] = {'a', '\n', 'b', 0x1b, '[', '2', 'J', 0x00, 'c', 0xff};
        d2k_journal_add(j, 1, &k, D2K_JRN_HELLO_SNI, 0, 0, NULL, nasty, sizeof nasty, NULL);
        const d2k_jrn_entry *e = d2k_journal_at(j, 0);
        CHECK(e != NULL, "запись с грязным именем не появилась");
        if (e) {
            CHECK(e->name_len == sizeof nasty, "длина грязного имени изменилась");
            CHECK(strchr(e->name, '\n') == NULL, "перевод строки доехал до вывода");
            CHECK(strchr(e->name, 0x1b) == NULL, "управляющий байт доехал до вывода");
            CHECK(strlen(e->name) == sizeof nasty,
                  "нулевой байт внутри имени обрезал строку");
            CHECK(strcmp(e->name, "a.b.[2J.c.") == 0, "замена байтов не та");
        }
        d2k_journal_free(j);
    }

    /* --- подробности наблюдения ---------------------------------------------
     * Отпечаток коробки складывается из них. Запись без подробностей и запись
     * с нулевыми подробностями — разные вещи только на бумаге, поэтому здесь
     * проверяется, что переданное доезжает целиком.                          */
    {
        d2k_journal *j = d2k_journal_new(4);
        d2k_key k = mk(1);
        d2k_jrn_detail det = {.ttl = 127, .ref_ttl = 124, .tos = 0x88, .ipid = 54321};
        d2k_journal_add(j, 1, &k, D2K_JRN_SUSPECT, D2K_SUSPECT_RST, 0, &det,
                        NULL, 0, NULL);
        const d2k_jrn_entry *e = d2k_journal_at(j, 0);
        CHECK(e && e->d_ttl == 127, "TTL подозрительного пакета потерян");
        CHECK(e && e->d_ref_ttl == 124, "ориентир TTL потерян");
        CHECK(e && e->d_tos == 0x88, "ToS потерян");
        CHECK(e && e->d_ipid == 54321, "идентификатор IP потерян");
        CHECK(e && e->code == D2K_SUSPECT_RST, "код причины потерян");

        /* Без подробностей поля обязаны остаться нулевыми, а не мусорными. */
        d2k_journal_add(j, 2, &k, D2K_JRN_SUSPECT, D2K_SUSPECT_SILENT, 0, NULL,
                        NULL, 0, NULL);
        e = d2k_journal_at(j, 1);
        CHECK(e && e->d_ttl == 0 && e->d_ipid == 0,
              "запись без подробностей унаследовала чужие");
        d2k_journal_free(j);
    }

    /* --- журнал нулевой глубины: законный режим ----------------------------- */
    {
        d2k_journal *j = d2k_journal_new(0);
        CHECK(j != NULL, "журнал нулевой глубины не создался");
        d2k_key k = mk(1);
        d2k_journal_add(j, 1, &k, D2K_JRN_HELLO_SNI, 0, 0, NULL, (const uint8_t *)"x", 1, NULL);
        CHECK(d2k_journal_count(j) == 0, "в выключенный журнал что-то записалось");
        CHECK(d2k_journal_dropped(j) == 0, "выключенный журнал считает потери");
        d2k_journal_free(j);
    }

    /* --- нулевые аргументы --------------------------------------------------- */
    {
        d2k_journal_free(NULL);
        d2k_journal_add(NULL, 1, NULL, 0, 0, 0, NULL, NULL, 0, NULL);
        CHECK(d2k_journal_count(NULL) == 0, "счётчик нулевого журнала не ноль");
        CHECK(d2k_journal_at(NULL, 0) == NULL, "из нулевого журнала что-то взялось");
        CHECK(d2k_journal_dropped(NULL) == 0, "потери нулевого журнала не ноль");
        d2k_journal *j = d2k_journal_new(4);
        d2k_journal_add(j, 1, NULL, D2K_JRN_HELLO_NONAME, 0, 0, NULL, NULL, 0, NULL);
        CHECK(d2k_journal_count(j) == 1, "запись без ключа потеряна");
        d2k_journal_free(j);
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("журнал: все проверки прошли\n");
    return 0;
}
