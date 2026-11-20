#include "d2km_owner.h"
#include "test.h"

int main(void)
{
    d2km_resource slots[6];
    d2km_ledger l;
    d2km_ledger_init(&l, slots, 6);

    CHECK(d2km_ledger_acquire(&l, 1, D2KM_RES_FLOW, D2KM_BIND_NONE, 100) == D2KM_OWN_OK);
    CHECK(d2km_ledger_acquire(&l, 1, D2KM_RES_FLOW, D2KM_BIND_NONE, 100) == D2KM_OWN_ALREADY);
    CHECK(d2km_ledger_acquire(&l, 2, D2KM_RES_FLOW, D2KM_BIND_NONE, 100) == D2KM_OWN_FOREIGN);
    CHECK(d2km_ledger_owner(&l, D2KM_RES_FLOW, 100) == 1);
    /* Тот же ключ другого вида — другой ресурс. */
    CHECK(d2km_ledger_acquire(&l, 2, D2KM_RES_PORT, D2KM_BIND_NONE, 100) == D2KM_OWN_OK);
    /* Привязка — только у планов и кандидатов, и у них обязательна. */
    CHECK(d2km_ledger_acquire(&l, 1, D2KM_RES_FLOW, D2KM_BIND_NAME, 101) == D2KM_OWN_BAD_INPUT);
    CHECK(d2km_ledger_acquire(&l, 1, D2KM_RES_CANDIDATE, D2KM_BIND_NONE, 7) == D2KM_OWN_BAD_INPUT);
    CHECK(d2km_ledger_acquire(&l, 0, D2KM_RES_FLOW, D2KM_BIND_NONE, 1) == D2KM_OWN_BAD_INPUT);

    CHECK(d2km_ledger_acquire(&l, 1, D2KM_RES_CANDIDATE, D2KM_BIND_NAME, 7) == D2KM_OWN_OK);
    CHECK(d2km_ledger_acquire(&l, 1, D2KM_RES_TRIAL_PLAN, D2KM_BIND_ADDRESS, 8) == D2KM_OWN_OK);
    CHECK(d2km_ledger_acquire(&l, 2, D2KM_RES_TRIAL_PLAN, D2KM_BIND_NAME, 9) == D2KM_OWN_OK);
    CHECK(d2km_ledger_acquire(&l, 3, D2KM_RES_FLOW, D2KM_BIND_NONE, 200) == D2KM_OWN_OK);
    CHECK(d2km_ledger_acquire(&l, 3, D2KM_RES_FLOW, D2KM_BIND_NONE, 201) == D2KM_OWN_FULL);

    /* Чужое не освобождается. */
    CHECK(d2km_ledger_release(&l, 2, D2KM_RES_FLOW, 100) == D2KM_OWN_FOREIGN);
    CHECK(d2km_ledger_release(&l, 2, D2KM_RES_FLOW, 555) == D2KM_OWN_ABSENT);

    /* §10.5: очистка опыта 1 по привязке по имени — только его кандидат
     * по имени; план по адресу и поток остаются; чужой план по имени цел. */
    CHECK(d2km_ledger_cleanup(&l, 1, D2KM_BIND_NAME) == 1);
    CHECK(d2km_ledger_owner(&l, D2KM_RES_CANDIDATE, 7) == 0);
    CHECK(d2km_ledger_owner(&l, D2KM_RES_TRIAL_PLAN, 8) == 1);
    CHECK(d2km_ledger_owner(&l, D2KM_RES_FLOW, 100) == 1);
    CHECK(d2km_ledger_owner(&l, D2KM_RES_TRIAL_PLAN, 9) == 2);
    CHECK(d2km_ledger_cleanup(&l, 1, D2KM_BIND_NONE) == 0);

    /* §6.7: завершение опыта освобождает все его ресурсы, и только их. */
    CHECK(d2km_ledger_count(&l, 1) == 2);
    CHECK(d2km_ledger_finish(&l, 1) == 2);
    CHECK(d2km_ledger_count(&l, 1) == 0);
    CHECK(d2km_ledger_count(&l, 2) == 2);
    CHECK(d2km_ledger_count(&l, 0) == 3);
    CHECK(d2km_ledger_acquire(&l, 3, D2KM_RES_FLOW, D2KM_BIND_NONE, 201) == D2KM_OWN_OK);

    /* §14: резерв памяти. Меньше часа наблюдения — резерв = объявленной. */
    uint64_t s[200];
    for (int i = 0; i < 200; i++)
        s[i] = 100000000u;
    CHECK(d2km_memory_reserve(s, 60, 60, 5000) == 5000);   /* 59 минут */
    CHECK(d2km_memory_reserve(s, 61, 60, 5000) == 0);      /* час, падений нет */
    s[30] = 90000000u;                                       /* падение 10 МБ за минуту */
    CHECK(d2km_memory_reserve(s, 61, 60, 5000) == 10000000u);
    /* Медленное падение за две минуты в минутное окно не входит. */
    for (int i = 0; i < 200; i++)
        s[i] = 100000000u;
    s[40] = 97000000u;
    s[41] = 94000000u;
    CHECK(d2km_memory_reserve(s, 100, 60, 5000) == 3000000u);
    /* Шаг 10 с: окно — шесть образцов. */
    for (int i = 0; i < 200; i++)
        s[i] = 100000000u;
    s[5] = 99000000u; s[11] = 92000000u;
    uint64_t big[400];
    for (int i = 0; i < 400; i++)
        big[i] = i < 200 ? s[i] : 100000000u;
    CHECK(d2km_memory_reserve(big, 400, 10, 1) == 8000000u);
    /* Падение старше суток не учитывается. */
    static uint64_t day[1500];
    for (int i = 0; i < 1500; i++)
        day[i] = 100000000u;
    day[1] = 50000000u;
    CHECK(d2km_memory_reserve(day, 1500, 60, 1) == 0);
    day[1490] = 99000000u;
    CHECK(d2km_memory_reserve(day, 1500, 60, 1) == 1000000u);
    CHECK(d2km_memory_reserve(NULL, 0, 60, 77) == 77);
    CHECK(d2km_memory_reserve(day, 1500, 0, 77) == 77);

    CHECK(d2km_memory_admit(100, 30, 70) == 1);
    CHECK(d2km_memory_admit(100, 31, 70) == 0);
    CHECK(d2km_memory_admit(10, 30, 1) == 0);
    CHECK(d2km_memory_admit(100, 0, 0) == 0);   /* без объявленной памяти — нет */
    DONE("test_owner");
}
