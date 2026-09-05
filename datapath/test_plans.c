/* test_plans.c — таблица планов по целям.
 *
 * Главное здесь: порядок поиска и владение памятью. Порядок «имя, потом
 * адрес» — не вкус: обратный дал бы плану соседа по CDN перебить план,
 * подтверждённый для конкретного имени. Владение проверяется тем, что
 * санитайзер гоняет этот же набор.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_plans.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Минимальный годный план: только порядок. */
static const uint8_t tiny[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 1,
    0x01, 0x03, 0x00, 0x01, 0x00
};

static d2k_plan *mkplan(void) {
    d2k_plan *p = NULL;
    char err[128];
    if (d2k_plan_load(tiny, sizeof tiny, &p, err, sizeof err) != 0) {
        printf("ПРОВАЛ: тестовый план не грузится: %s\n", err);
        fails++;
        return NULL;
    }
    return p;
}

static uint32_t addr(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    uint8_t v[4] = {a, b, c, d};
    uint32_t r;
    memcpy(&r, v, 4);
    return r;
}

int main(void) {
    /* --- поиск по имени и по адресу ---------------------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(8);
        CHECK(t != NULL, "таблица не создалась");
        CHECK(d2k_plantab_count(t) == 0, "новая таблица не пуста");

        const uint8_t nm[] = "linkedin.com";
        d2k_plan *a = mkplan(), *b = mkplan();
        CHECK(d2k_plantab_set_name(t, nm, sizeof nm - 1, a) == 0, "план по имени не встал");
        CHECK(d2k_plantab_set_addr(t, addr(1, 2, 3, 4), b) == 0, "план по адресу не встал");
        CHECK(d2k_plantab_count(t) == 2, "счётчик записей неверен");

        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, addr(9, 9, 9, 9)) == a,
              "план по имени не нашёлся");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(1, 2, 3, 4)) == b,
              "план по адресу не нашёлся");
        CHECK(d2k_plantab_find(t, (const uint8_t *)"nope.example", 12,
                               addr(9, 9, 9, 9)) == NULL,
              "нашёлся план для незнакомой цели");
        d2k_plantab_free(t);
    }

    /* --- имя важнее адреса --------------------------------------------------
     * За одним адресом CDN стоят сотни имён. Если адрес будет перебивать имя,
     * подтверждённый план цели заменится планом соседа.                       */
    {
        d2k_plantab *t = d2k_plantab_new(8);
        const uint8_t nm[] = "discord.com";
        d2k_plan *by_name = mkplan(), *by_addr = mkplan();
        d2k_plantab_set_name(t, nm, sizeof nm - 1, by_name);
        d2k_plantab_set_addr(t, addr(162, 159, 135, 232), by_addr);
        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, addr(162, 159, 135, 232)) == by_name,
              "адрес перебил имя");
        /* Другое имя на том же адресе падает на адресный план — это законный
           запасной путь, а не приписывание домена. */
        CHECK(d2k_plantab_find(t, (const uint8_t *)"other.example", 13,
                               addr(162, 159, 135, 232)) == by_addr,
              "запасной поиск по адресу не сработал");
        d2k_plantab_free(t);
    }

    /* --- регистр имени незначим ---------------------------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        d2k_plan *p = mkplan();
        d2k_plantab_set_name(t, (const uint8_t *)"Example.COM", 11, p);
        CHECK(d2k_plantab_find(t, (const uint8_t *)"example.com", 11, 0) == p,
              "регистр имени оказался значимым");
        CHECK(d2k_plantab_find(t, (const uint8_t *)"example.co", 10, 0) == NULL,
              "префикс имени принят за имя");
        d2k_plantab_free(t);
    }

    /* --- замена плана цели: прежний освобождается ---------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        const uint8_t nm[] = "a.example";
        d2k_plan *first = mkplan(), *second = mkplan();
        d2k_plantab_set_name(t, nm, sizeof nm - 1, first);
        d2k_plantab_set_name(t, nm, sizeof nm - 1, second);
        CHECK(d2k_plantab_count(t) == 1, "замена завела вторую запись");
        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, 0) == second,
              "после замены нашёлся прежний план");
        d2k_plantab_free(t);
    }

    /* --- удаление ------------------------------------------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        const uint8_t nm[] = "b.example";
        d2k_plantab_set_name(t, nm, sizeof nm - 1, mkplan());
        d2k_plantab_set_addr(t, addr(5, 6, 7, 8), mkplan());
        CHECK(d2k_plantab_del_name(t, nm, sizeof nm - 1) == 1, "удаление по имени не сработало");
        CHECK(d2k_plantab_del_name(t, nm, sizeof nm - 1) == 0, "повторное удаление что-то нашло");
        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, 0) == NULL, "удалённый план находится");
        CHECK(d2k_plantab_del_addr(t, addr(5, 6, 7, 8)) == 1, "удаление по адресу не сработало");
        CHECK(d2k_plantab_count(t) == 0, "счётчик после удаления неверен");
        /* Освобождённое место снова годится. */
        CHECK(d2k_plantab_set_name(t, nm, sizeof nm - 1, mkplan()) == 0,
              "после удаления место не переиспользуется");
        d2k_plantab_free(t);
    }

    /* --- переполнение: отказ, и план всё равно не течёт ------------------------
     * Владение переходит таблице ДАЖЕ ПРИ ОТКАЗЕ. Иначе каждая ошибка
     * вызывающего оставляла бы течь, а вызывающий — это тот, кто разбирает
     * команды из сокета.                                                       */
    {
        d2k_plantab *t = d2k_plantab_new(2);
        d2k_plantab_set_addr(t, addr(1, 1, 1, 1), mkplan());
        d2k_plantab_set_addr(t, addr(2, 2, 2, 2), mkplan());
        CHECK(d2k_plantab_set_addr(t, addr(3, 3, 3, 3), mkplan()) == -1,
              "переполнение не отказало");
        CHECK(d2k_plantab_count(t) == 2, "переполнение изменило содержимое");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(1, 1, 1, 1)) != NULL,
              "переполнение вытеснило прежнюю запись");
        d2k_plantab_free(t);
    }

    /* --- негодные аргументы: план всё равно не течёт ---------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        CHECK(d2k_plantab_set_name(t, NULL, 0, mkplan()) == -2, "пустое имя принято");
        uint8_t huge[D2K_TARGET_NAME_MAX + 1];
        memset(huge, 'x', sizeof huge);
        CHECK(d2k_plantab_set_name(t, huge, sizeof huge, mkplan()) == -2,
              "слишком длинное имя принято");
        CHECK(d2k_plantab_count(t) == 0, "негодные аргументы что-то записали");
        d2k_plantab_free(t);

        CHECK(d2k_plantab_new(0) == NULL, "таблица на ноль записей создалась");
        d2k_plantab_free(NULL);
        CHECK(d2k_plantab_find(NULL, NULL, 0, 0) == NULL, "поиск в нулевой таблице");
        CHECK(d2k_plantab_count(NULL) == 0, "счётчик нулевой таблицы");
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("планы целей: все проверки прошли\n");
    return 0;
}
