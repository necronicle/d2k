/* test_sched.c — очередь отложенной отправки.
 *
 * Главное здесь — устойчивость порядка. Две копии фейка с одинаковой задержкой
 * обязаны уйти в том порядке, в котором их поставил план: §2.5 требует, чтобы
 * исполненное совпадало с измеренным, а обычная двоичная куча порядок равных
 * элементов не сохраняет. Поэтому вперемешку с проверками сроков идёт
 * случайный стресс со сверкой против независимо посчитанного эталона.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "d2k_sched.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Опознавательный знак пакета — его номер в первых четырёх байтах. */
static void mark(uint8_t *b, size_t len, uint32_t id) {
    memset(b, 0xCC, len);
    b[0] = (uint8_t)(id >> 24); b[1] = (uint8_t)(id >> 16);
    b[2] = (uint8_t)(id >> 8);  b[3] = (uint8_t)id;
}
static uint32_t idof(const uint8_t *b) {
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 |
           (uint32_t)b[2] << 8 | b[3];
}

int main(void) {
    uint8_t pkt[64], got[64];
    size_t len = 0;

    /* --- пустая очередь ---------------------------------------------------- */
    {
        d2k_sched *s = d2k_sched_new(4, 64);
        CHECK(s != NULL, "очередь не создалась");
        CHECK(d2k_sched_count(s) == 0, "новая очередь не пуста");
        CHECK(d2k_sched_next_ns(s) == 0, "у пустой очереди есть срок");
        CHECK(d2k_sched_pop_due(s, 1000, got, sizeof got, &len) == 0,
              "из пустой очереди что-то забралось");
        d2k_sched_free(s);
    }

    /* --- срок соблюдается -------------------------------------------------- */
    {
        d2k_sched *s = d2k_sched_new(4, 64);
        mark(pkt, 10, 1);
        CHECK(d2k_sched_push(s, 5000, pkt, 10) == 0, "пакет не принят");
        CHECK(d2k_sched_next_ns(s) == 5000, "ближайший срок не тот");
        CHECK(d2k_sched_pop_due(s, 4999, got, sizeof got, &len) == 0,
              "пакет выдан раньше срока");
        CHECK(d2k_sched_pop_due(s, 5000, got, sizeof got, &len) == 1,
              "пакет не выдан в свой срок");
        CHECK(len == 10 && idof(got) == 1, "выдался не тот пакет");
        CHECK(d2k_sched_count(s) == 0, "счётчик после выдачи не обнулился");
        d2k_sched_free(s);
    }

    /* --- порядок по сроку, а не по постановке ------------------------------ */
    {
        d2k_sched *s = d2k_sched_new(8, 64);
        uint64_t due[5] = {900, 100, 500, 50, 700};
        for (uint32_t i = 0; i < 5; i++) {
            mark(pkt, 8, i);
            d2k_sched_push(s, due[i], pkt, 8);
        }
        uint32_t want[5] = {3, 1, 2, 4, 0};
        for (int i = 0; i < 5; i++) {
            CHECK(d2k_sched_pop_due(s, 100000, got, sizeof got, &len) == 1,
                  "пакет не выдался");
            if (idof(got) != want[i]) {
                printf("ПРОВАЛ: на позиции %d ожидался пакет %u, пришёл %u\n",
                       i, want[i], idof(got));
                fails++;
            }
        }
        d2k_sched_free(s);
    }

    /* --- равные сроки: порядок постановки ---------------------------------- */
    {
        d2k_sched *s = d2k_sched_new(16, 64);
        for (uint32_t i = 0; i < 10; i++) {
            mark(pkt, 8, i);
            CHECK(d2k_sched_push(s, 1000, pkt, 8) == 0, "равные сроки: не принят");
        }
        for (uint32_t i = 0; i < 10; i++) {
            CHECK(d2k_sched_pop_due(s, 1000, got, sizeof got, &len) == 1,
                  "равные сроки: не выдался");
            if (idof(got) != i) {
                printf("ПРОВАЛ: равные сроки переставлены: ждали %u, пришёл %u\n",
                       i, idof(got));
                fails++;
            }
        }
        d2k_sched_free(s);
    }

    /* --- переполнение: отказ, а не вытеснение ------------------------------- */
    {
        d2k_sched *s = d2k_sched_new(3, 64);
        for (uint32_t i = 0; i < 3; i++) {
            mark(pkt, 8, i);
            CHECK(d2k_sched_push(s, 1000 + i, pkt, 8) == 0, "не принят до предела");
        }
        mark(pkt, 8, 99);
        CHECK(d2k_sched_push(s, 1, pkt, 8) == -1, "переполнение не отказало");
        CHECK(d2k_sched_refusals(s) == 1, "отказ не посчитан");
        CHECK(d2k_sched_count(s) == 3, "отказ изменил содержимое очереди");
        /* Ранее принятые обязаны остаться нетронутыми. */
        for (uint32_t i = 0; i < 3; i++) {
            d2k_sched_pop_due(s, 100000, got, sizeof got, &len);
            CHECK(idof(got) == i, "отказ вытеснил уже принятый пакет");
        }
        d2k_sched_free(s);
    }

    /* --- слоты переиспользуются -------------------------------------------- */
    {
        d2k_sched *s = d2k_sched_new(2, 64);
        for (uint32_t round = 0; round < 100; round++) {
            mark(pkt, 16, round);
            CHECK(d2k_sched_push(s, round, pkt, 16) == 0, "слот не освободился");
            CHECK(d2k_sched_pop_due(s, round, got, sizeof got, &len) == 1,
                  "пакет не выдался в цикле переиспользования");
            CHECK(idof(got) == round && len == 16, "содержимое слота испортилось");
        }
        CHECK(d2k_sched_refusals(s) == 0, "в цикле переиспользования были отказы");
        d2k_sched_free(s);
    }

    /* --- пакет длиннее слота ------------------------------------------------ */
    {
        d2k_sched *s = d2k_sched_new(4, 16);
        uint8_t big[64];
        mark(big, sizeof big, 7);
        CHECK(d2k_sched_push(s, 1, big, sizeof big) == -2, "великан принят в слот");
        CHECK(d2k_sched_refusals(s) == 1, "отказ по размеру не посчитан");
        CHECK(d2k_sched_count(s) == 0, "великан всё-таки лёг в очередь");
        d2k_sched_free(s);
    }

    /* --- тесный буфер вызывающего: пакет остаётся --------------------------- */
    {
        d2k_sched *s = d2k_sched_new(4, 64);
        mark(pkt, 40, 5);
        d2k_sched_push(s, 100, pkt, 40);
        uint8_t small[8];
        CHECK(d2k_sched_pop_due(s, 100, small, sizeof small, &len) == 0,
              "пакет выдался в тесный буфер");
        CHECK(d2k_sched_count(s) == 1, "пакет пропал из-за тесного буфера");
        CHECK(d2k_sched_pop_due(s, 100, got, sizeof got, &len) == 1,
              "пакет не выдался в нормальный буфер после тесного");
        CHECK(idof(got) == 5 && len == 40, "после тесного буфера пакет испорчен");
        d2k_sched_free(s);
    }

    /* --- случайный стресс со сверкой против эталона -------------------------
     * Куча ломается не на аккуратных случаях, а на кластерах равных ключей.
     * Ставим случайные сроки, забираем всё и сверяем с независимо посчитанным
     * порядком: сортировка вставками по паре (срок, номер постановки).
     * Генератор детерминированный — провал обязан воспроизводиться.          */
    {
        enum { N = 500 };
        static uint64_t due[N];
        static uint32_t order[N];
        d2k_sched *s = d2k_sched_new(N, 32);
        uint32_t rnd = 20260905u;

        for (uint32_t i = 0; i < N; i++) {
            rnd = rnd * 1103515245u + 12345u;
            /* Диапазон сроков намеренно узкий: нужны совпадения. */
            due[i] = (rnd >> 20) % 25;
            mark(pkt, 32, i);
            CHECK(d2k_sched_push(s, due[i], pkt, 32) == 0, "стресс: пакет не принят");
            order[i] = i;
        }

        /* Эталон: устойчивая сортировка вставками по (срок, номер). */
        for (uint32_t i = 1; i < N; i++) {
            uint32_t v = order[i];
            uint32_t j = i;
            while (j > 0 && due[order[j - 1]] > due[v]) {
                order[j] = order[j - 1];
                j--;
            }
            order[j] = v;
        }

        for (uint32_t i = 0; i < N; i++) {
            if (d2k_sched_pop_due(s, (uint64_t)-1, got, sizeof got, &len) != 1) {
                printf("ПРОВАЛ: стресс: очередь опустела на %u из %u\n", i, (uint32_t)N);
                fails++;
                break;
            }
            if (idof(got) != order[i]) {
                printf("ПРОВАЛ: стресс: на позиции %u ждали %u, пришёл %u "
                       "(сроки %llu и %llu)\n",
                       i, order[i], idof(got),
                       (unsigned long long)due[order[i]],
                       (unsigned long long)due[idof(got)]);
                fails++;
                break;
            }
        }
        CHECK(d2k_sched_count(s) == 0, "стресс: очередь не опустела");
        d2k_sched_free(s);
    }

    /* --- вырожденные аргументы ---------------------------------------------- */
    {
        CHECK(d2k_sched_new(0, 64) == NULL, "очередь на ноль слотов создалась");
        CHECK(d2k_sched_new(4, 0) == NULL, "очередь с нулевым слотом создалась");
        d2k_sched_free(NULL);
        CHECK(d2k_sched_count(NULL) == 0, "счётчик нулевой очереди не ноль");
        CHECK(d2k_sched_next_ns(NULL) == 0, "срок нулевой очереди не ноль");
        d2k_sched *s = d2k_sched_new(2, 64);
        CHECK(d2k_sched_push(s, 1, NULL, 10) == -2, "принят нулевой указатель");
        CHECK(d2k_sched_push(s, 1, pkt, 0) == -2, "принят пакет нулевой длины");
        d2k_sched_free(s);
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("расписание: все проверки прошли\n");
    return 0;
}
