/* test_plans.c — таблица планов по целям.
 *
 * Главное здесь: порядок поиска, владение памятью и вытеснение по давности.
 * Порядок «имя, потом адрес» — не вкус: обратный дал бы плану соседа по CDN
 * перебить план, подтверждённый для конкретного имени. Владение проверяется
 * тем, что санитайзер гоняет этот же набор. Вытеснение проверяется
 * ПОВЕДЕНИЕМ таблицы (что находится, а не что отказало) — по требованию
 * задачи: внутреннее поле давности наружу не выставлено и не должно быть.
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
        CHECK(d2k_plantab_set_name(t, nm, sizeof nm - 1, 1, a) == 0, "план по имени не встал");
        CHECK(d2k_plantab_set_addr(t, addr(1, 2, 3, 4), 1, b) == 0, "план по адресу не встал");
        CHECK(d2k_plantab_count(t) == 2, "счётчик записей неверен");

        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, addr(9, 9, 9, 9), 2, D2K_PLAN_SHAPE_ANY) == a,
              "план по имени не нашёлся");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(1, 2, 3, 4), 2, D2K_PLAN_SHAPE_ANY) == b,
              "план по адресу не нашёлся");
        CHECK(d2k_plantab_find(t, (const uint8_t *)"nope.example", 12,
                               addr(9, 9, 9, 9), 2, D2K_PLAN_SHAPE_ANY) == NULL,
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
        d2k_plantab_set_name(t, nm, sizeof nm - 1, 1, by_name);
        d2k_plantab_set_addr(t, addr(162, 159, 135, 232), 1, by_addr);
        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, addr(162, 159, 135, 232), 2, D2K_PLAN_SHAPE_ANY) == by_name,
              "адрес перебил имя");
        /* Другое имя на том же адресе падает на адресный план — это законный
           запасной путь, а не приписывание домена. */
        CHECK(d2k_plantab_find(t, (const uint8_t *)"other.example", 13,
                               addr(162, 159, 135, 232), 2, D2K_PLAN_SHAPE_ANY) == by_addr,
              "запасной поиск по адресу не сработал");
        d2k_plantab_free(t);
    }

    /* --- регистр имени незначим ---------------------------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        d2k_plan *p = mkplan();
        d2k_plantab_set_name(t, (const uint8_t *)"Example.COM", 11, 1, p);
        CHECK(d2k_plantab_find(t, (const uint8_t *)"example.com", 11, 0, 2, D2K_PLAN_SHAPE_ANY) == p,
              "регистр имени оказался значимым");
        CHECK(d2k_plantab_find(t, (const uint8_t *)"example.co", 10, 0, 2, D2K_PLAN_SHAPE_ANY) == NULL,
              "префикс имени принят за имя");
        d2k_plantab_free(t);
    }

    /* --- замена плана цели: прежний освобождается ---------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        const uint8_t nm[] = "a.example";
        d2k_plan *first = mkplan(), *second = mkplan();
        d2k_plantab_set_name(t, nm, sizeof nm - 1, 1, first);
        d2k_plantab_set_name(t, nm, sizeof nm - 1, 2, second);
        CHECK(d2k_plantab_count(t) == 1, "замена завела вторую запись");
        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, 0, 3, D2K_PLAN_SHAPE_ANY) == second,
              "после замены нашёлся прежний план");
        d2k_plantab_free(t);
    }

    /* --- удаление ------------------------------------------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        const uint8_t nm[] = "b.example";
        d2k_plantab_set_name(t, nm, sizeof nm - 1, 1, mkplan());
        d2k_plantab_set_addr(t, addr(5, 6, 7, 8), 1, mkplan());
        CHECK(d2k_plantab_del_name(t, nm, sizeof nm - 1) == 1, "удаление по имени не сработало");
        CHECK(d2k_plantab_del_name(t, nm, sizeof nm - 1) == 0, "повторное удаление что-то нашло");
        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, 0, 2, D2K_PLAN_SHAPE_ANY) == NULL, "удалённый план находится");
        CHECK(d2k_plantab_del_addr(t, addr(5, 6, 7, 8)) == 1, "удаление по адресу не сработало");
        CHECK(d2k_plantab_count(t) == 0, "счётчик после удаления неверен");
        /* Освобождённое место снова годится. */
        CHECK(d2k_plantab_set_name(t, nm, sizeof nm - 1, 2, mkplan()) == 0,
              "после удаления место не переиспользуется");
        d2k_plantab_free(t);
    }

    /* --- переполнение: вытеснение самой давно не использованной записи, а не
     * отказ навсегда ------------------------------------------------------------
     * Замер на живом роутере (см. d2k_plans.h, 2026-09-06): без вытеснения
     * таблица набивается доверху ещё до живого трафика (каталог 276 записей
     * против вместимости 256), и КАЖДАЯ следующая цель получает отказ, из
     * которого нет выхода. Владение планом переходит таблице и здесь —
     * возврат 0 не бесплатен, план вытесненной записи освобождён внутри.
     *
     * Давности расставлены НЕ по индексу вставки (2,2,2,2 вставлен ПЕРВЫМ, но
     * его давность БОЛЬШЕ): реализация, вытесняющая по индексу или по порядку
     * вставки вместо настоящей давности, эту проверку не пройдёт. */
    {
        d2k_plantab *t = d2k_plantab_new(2);
        d2k_plantab_set_addr(t, addr(2, 2, 2, 2), 10, mkplan()); /* новее */
        d2k_plantab_set_addr(t, addr(1, 1, 1, 1), 5, mkplan());  /* старше */
        CHECK(d2k_plantab_set_addr(t, addr(3, 3, 3, 3), 20, mkplan()) == 0,
              "переполнение отказало вместо вытеснения");
        CHECK(d2k_plantab_count(t) == 2, "вытеснение изменило число записей");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(3, 3, 3, 3), 21, D2K_PLAN_SHAPE_ANY) != NULL,
              "новая запись после вытеснения не находится");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(1, 1, 1, 1), 21, D2K_PLAN_SHAPE_ANY) == NULL,
              "самая давняя запись пережила вытеснение");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(2, 2, 2, 2), 21, D2K_PLAN_SHAPE_ANY) != NULL,
              "вытеснена не самая давняя запись, а более свежая");
        d2k_plantab_free(t);
    }

    /* --- обращение обновляет давность: тронутая запись переживает
     * вытеснение, нетронутая соседка — нет ---------------------------------
     * Проверяем ПОВЕДЕНИЕМ (что нашлось после вытеснения), а не внутренним
     * полем — оно не выставлено наружу нарочно (см. d2k_plans.h). */
    {
        d2k_plantab *t = d2k_plantab_new(2);
        d2k_plantab_set_addr(t, addr(1, 1, 1, 1), 1, mkplan()); /* старше при вставке */
        d2k_plantab_set_addr(t, addr(2, 2, 2, 2), 2, mkplan()); /* новее при вставке */
        /* Без обращения (1,1,1,1) — самая давняя и вытеснилась бы первой.
           Трогаем именно её отметкой новее соседки — порядок вытеснения
           обязан развернуться. */
        CHECK(d2k_plantab_find(t, NULL, 0, addr(1, 1, 1, 1), 100, D2K_PLAN_SHAPE_ANY) != NULL,
              "обращение к записи её не находит");
        CHECK(d2k_plantab_set_addr(t, addr(3, 3, 3, 3), 101, mkplan()) == 0,
              "вытеснение после обращения отказало");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(1, 1, 1, 1), 200, D2K_PLAN_SHAPE_ANY) != NULL,
              "тронутая запись не пережила вытеснение");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(2, 2, 2, 2), 200, D2K_PLAN_SHAPE_ANY) == NULL,
              "нетронутая соседка пережила вытеснение вместо тронутой");
        d2k_plantab_free(t);
    }

    /* --- негодные аргументы: план всё равно не течёт ---------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        CHECK(d2k_plantab_set_name(t, NULL, 0, 1, mkplan()) == -2, "пустое имя принято");
        uint8_t huge[D2K_TARGET_NAME_MAX + 1];
        memset(huge, 'x', sizeof huge);
        CHECK(d2k_plantab_set_name(t, huge, sizeof huge, 1, mkplan()) == -2,
              "слишком длинное имя принято");
        CHECK(d2k_plantab_count(t) == 0, "негодные аргументы что-то записали");
        d2k_plantab_free(t);

        CHECK(d2k_plantab_new(0) == NULL, "таблица на ноль записей создалась");
        d2k_plantab_free(NULL);
        CHECK(d2k_plantab_find(NULL, NULL, 0, 0, 1, D2K_PLAN_SHAPE_ANY) == NULL, "поиск в нулевой таблице");
        CHECK(d2k_plantab_count(NULL) == 0, "счётчик нулевой таблицы");
    }

    /* --- ФОРМА ПРИВЕТСТВИЯ ОГРАНИЧИВАЕТ ПРИМЕНЕНИЕ (0009, U5) -----------
     *
     * Успех собственного зонда на TLS 1.3 ничего не говорит про браузер с
     * TLS 1.2: это разные приветствия, и коробка разбирает их по-разному.
     * До этой правки shape жил только в каталоге контроллера и применение
     * плана не ограничивал вовсе — датапат отдавал план любому обращению к
     * имени.
     *
     * Ноль с любой стороны означает «не объявлено» и совместим со всем: у
     * записи это старый каталог, у наблюдения — приветствие, форму которого
     * разобрать не удалось. Молча перестать применять планы старого каталога
     * нельзя, и выдумывать форму неразобранному приветствию — тоже. */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        CHECK(t != NULL, "таблица для проверки формы не создалась");
        static const uint8_t nm[] = "shape.example";
        size_t nl = sizeof nm - 1;

        CHECK(d2k_plantab_set_name_shaped(t, nm, nl, 1, mkplan(),
                                          D2K_PLAN_SHAPE_MODERN) == 0,
              "план с объявленной формой не поставился");
        CHECK(d2k_plantab_find(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_MODERN) != NULL,
              "план не отдан приветствию СВОЕЙ формы");
        CHECK(d2k_plantab_find(t, nm, nl, 0, 3, D2K_PLAN_SHAPE_LEGACY) == NULL,
              "план, подтверждённый на TLS 1.3, отдан приветствию TLS 1.2");
        /* НЕИЗМЕРЕННОЕ наблюдение подтверждённый план НЕ получает. Раньше
           ноль наблюдения проходил к любой записи, то есть «не измерено»
           выдавалось за доказанную совместимость (0009, U5-R3). Утверждение
           теста перевёрнуто вместе с политикой намеренно: прежнее закрепляло
           ровно ту поблажку, которую требовалось снять. */
        CHECK(d2k_plantab_find(t, nm, nl, 0, 4, D2K_PLAN_SHAPE_ANY) == NULL,
              "план, подтверждённый на конкретной форме, отдан обращению, "
              "про форму которого ничего не известно");

        /* QUIC — ОТДЕЛЬНАЯ форма, и план, подтверждённый на TLS, ему не
           достаётся: другой транспорт, другое приветствие, и переносить туда
           подтверждение нечем (0009, U5). До правки путь QUIC звал поиск с
           ANY и такой план получал. */
        CHECK(d2k_plantab_find(t, nm, nl, 0, 8, D2K_PLAN_SHAPE_QUIC) == NULL,
              "план, подтверждённый на TLS, выдан приветствию QUIC");

        /* ДВА ТРАНСПОРТА ОДНОГО ИМЕНИ ЖИВУТ ОДНОВРЕМЕННО.
         *
         * Замер на роутере Марка 13.09.2026: у www.facebook.com подтверждены
         * и TCP-план, и QUIC-план. Пока запись была одна на имя, вторая
         * привязка затирала первую, и какой из двух обходов работает,
         * решал порядок синхронизации каталога — а клиент за роутером не
         * проходил ни по одному транспорту.
         *
         * Проверяется именно ОДНОВРЕМЕННОСТЬ: поставили QUIC — TLS-план
         * остался на месте и наоборот. */
        {
            const uint8_t two[] = "оба.транспорта";
            size_t tl = sizeof two - 1;
            CHECK(d2k_plantab_set_name_shaped(t, two, tl, 10, mkplan(),
                                              D2K_PLAN_SHAPE_MODERN) == 0,
                  "план TLS не поставился");
            CHECK(d2k_plantab_set_name_shaped(t, two, tl, 11, mkplan(),
                                              D2K_PLAN_SHAPE_QUIC) == 0,
                  "план QUIC не поставился");
            CHECK(d2k_plantab_find(t, two, tl, 0, 12, D2K_PLAN_SHAPE_MODERN) != NULL,
                  "план TLS затёрт привязкой QUIC того же имени");
            CHECK(d2k_plantab_find(t, two, tl, 0, 12, D2K_PLAN_SHAPE_QUIC) != NULL,
                  "план QUIC не нашёлся");
            /* И ни один из них не достаётся форме, на которой его не
               подтверждали. */
            CHECK(d2k_plantab_find(t, two, tl, 0, 12, D2K_PLAN_SHAPE_LEGACY) == NULL,
                  "план выдан приветствию формы, на которой не подтверждался");
        }

        /* ФОРМА НЕ ПОНИЖАЕТСЯ. Синхронизация каталога может прийти ПОСЛЕ
           испытания, и порядок команд не должен решать, к каким приветствиям
           применяется план. */
        CHECK(d2k_plantab_set_name_shaped(t, nm, nl, 5, mkplan(),
                                          D2K_PLAN_SHAPE_GRANDFATHER) == 0,
              "перезапись плана не прошла");
        CHECK(d2k_plantab_find(t, nm, nl, 0, 6, D2K_PLAN_SHAPE_LEGACY) == NULL,
              "измеренная форма понижена до дедушкиного права порядком команд");

        d2k_plantab_free(t);
        t = d2k_plantab_new(4);
        CHECK(t != NULL, "таблица для дедушкиного права не создалась");

        /* СТАРАЯ ЗАПИСЬ (формы не записывали) применяется ко всем формам.
           Это весь каталог, заведённый до появления поля: в снятом с роутера
           состоянии формы нет ни у одной записи, и отказать значило бы молча
           выключить работающий у человека обход. */
        CHECK(d2k_plantab_set_name(t, nm, nl, 5, mkplan()) == 0,
              "план без объявленной формы не поставился");
        CHECK(d2k_plantab_find(t, nm, nl, 0, 6, D2K_PLAN_SHAPE_MODERN) != NULL &&
              d2k_plantab_find(t, nm, nl, 0, 7, D2K_PLAN_SHAPE_LEGACY) != NULL &&
              d2k_plantab_find(t, nm, nl, 0, 8, D2K_PLAN_SHAPE_QUIC) != NULL &&
              d2k_plantab_find(t, nm, nl, 0, 9, D2K_PLAN_SHAPE_ANY) != NULL,
              "старый каталог перестал применяться — «не записано» принято за «не подходит»");
        d2k_plantab_free(t);
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("планы целей: все проверки прошли\n");
    return 0;
}
