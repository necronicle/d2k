/* test_plan_parse.c — проверки разбора плана.
 *
 * Отказы проверяются раньше и подробнее успехов: вход исполнителя приходит из
 * сети, и всё, чего он не понимает целиком, обязано отвергаться. Пропустить
 * незнакомое молча значило бы исполнить не тот план, который измеряли.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_plan.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Минимальный правильный план: заголовок и одна запись ORDER. */
static const uint8_t good[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 1,
    0x01, 0x03, 0x00, 0x01, 0x00
};

static int loads(const uint8_t *b, size_t n) {
    d2k_plan *p = NULL;
    char err[160];
    int rc = d2k_plan_load(b, n, &p, err, sizeof err);
    if (rc == 0) {
        d2k_plan_free(p);
    }
    return rc == 0;
}

int main(void) {
    uint8_t t[sizeof good];

    CHECK(loads(good, sizeof good), "правильный план не загрузился");

    memcpy(t, good, sizeof good); t[0] = 'X';
    CHECK(!loads(t, sizeof good), "чужая магия принята");

    memcpy(t, good, sizeof good); t[5] = 99;
    CHECK(!loads(t, sizeof good), "схема из будущего принята");

    memcpy(t, good, sizeof good); t[7] = 99;
    CHECK(!loads(t, sizeof good), "план для более нового исполнителя принят");

    memcpy(t, good, sizeof good); t[9] = 1;
    CHECK(!loads(t, sizeof good), "ненулевые флаги приняты");

    memcpy(t, good, sizeof good); t[12] = 0x77;
    CHECK(!loads(t, sizeof good), "неизвестная запись пропущена молча");

    CHECK(!loads(good, sizeof good - 1), "обрезанный план принят");
    CHECK(!loads(good, 4), "огрызок заголовка принят");
    CHECK(!loads(NULL, 0), "пустой вход принят");

    /* Заявлено записей больше, чем есть: расхождение обязано ловиться, иначе
       план можно молча урезать по дороге. */
    memcpy(t, good, sizeof good); t[11] = 9;
    CHECK(!loads(t, sizeof good), "несовпадение числа записей пропущено");

    /* Длина записи выходит за буфер. */
    memcpy(t, good, sizeof good); t[15] = 0xff;
    CHECK(!loads(t, sizeof good), "запись длиннее буфера принята");

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("разбор: все проверки прошли\n");
    return 0;
}
