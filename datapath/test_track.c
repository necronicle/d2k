/* test_track.c — учёт потоков.
 *
 * Главное здесь не «находит поток», а поведение на границах: что таблица
 * делает, когда кончилось место, и не теряет ли она соседей после удаления.
 * Именно там живут ошибки, которые на роутере выглядят как «поток перестал
 * отслеживаться сам собой».
 */
#include <stdio.h>
#include <string.h>
#include "d2k_track.h"

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

static int expired_with_hello;
static void count_expired(void *ctx, const d2k_flow *f) {
    int *n = ctx;
    (*n)++;
    if (f->saw_hello) {
        expired_with_hello++;
    }
}

int main(void) {
    d2k_table *t = d2k_track_new(16);
    CHECK(t != NULL, "таблица не создалась");
    if (!t) {
        return 1;
    }

    /* --- заведение и повторный поиск ----------------------------------- */
    d2k_key a = mk(1000);
    d2k_flow *f1 = d2k_track_get(t, &a, 1000);
    CHECK(f1 != NULL, "поток не заведён");
    CHECK(d2k_track_count(t) == 1, "счётчик потоков неверен");

    d2k_flow *f2 = d2k_track_get(t, &a, 2000);
    CHECK(f1 == f2, "повторный запрос вернул другой поток");
    CHECK(d2k_track_count(t) == 1, "повторный запрос завёл дубликат");
    CHECK(f2->first_ns == 1000 && f2->last_ns == 2000,
          "времена первого и последнего касания не обновляются как надо");

    /* --- канон: обе стороны соединения дают ОДИН ключ ---------------------
     * Без этого ответное направление завело бы второй поток, и план мог бы
     * примениться к одному соединению дважды.                               */
    {
        uint8_t c1[4] = {192, 168, 1, 67}, c2[4] = {1, 2, 3, 4};
        uint8_t p1[2] = {0xc0, 0x00}, p2[2] = {0x01, 0xbb};
        d2k_key out_key, in_key;
        int out_low = d2k_key_make(&out_key, c1, c2, p1, p2);
        int in_low  = d2k_key_make(&in_key,  c2, c1, p2, p1);
        CHECK(memcmp(&out_key, &in_key, sizeof out_key) == 0,
              "прямое и обратное направления дали разные ключи");
        CHECK(out_low != in_low,
              "признак «источник — низкая сторона» одинаков для обеих сторон");

        d2k_table *s = d2k_track_new(16);
        d2k_flow *a1 = d2k_track_get(s, &out_key, 100);
        d2k_flow *a2 = d2k_track_get(s, &in_key, 200);
        CHECK(a1 == a2, "стороны одного соединения попали в разные потоки");
        CHECK(d2k_track_count(s) == 1, "одно соединение заняло две ячейки");
        d2k_track_free(s);
    }

    /* --- обратный вызов при истечении --------------------------------------
     * «Приветствие было, ответа не пришло» становится известно только в
     * момент забвения потока. Если вызов не случится, подозрение по молчанию
     * не заметит никто.                                                      */
    {
        d2k_table *s = d2k_track_new(16);
        d2k_key k1 = mk(4001), k2 = mk(4002);
        d2k_flow *f = d2k_track_get(s, &k1, 1000);
        f->saw_hello = 1;
        d2k_track_get(s, &k2, 1000);

        int seen_total = 0;
        /* Сперва без обратного вызова: NULL не должен ронять уборку. */
        d2k_track_expire(s, 1000 + 99999, 60000, NULL, NULL);
        CHECK(d2k_track_count(s) == 0, "истечение без вызова не освободило потоки");

        /* Теперь с вызовом. */
        d2k_flow *g = d2k_track_get(s, &k1, 5000);
        g->saw_hello = 1;
        d2k_track_get(s, &k2, 5000);
        d2k_track_expire(s, 5000 + 99999, 60000, count_expired, &seen_total);
        CHECK(seen_total == 2, "обратный вызов случился не для каждого потока");
        CHECK(expired_with_hello == 1,
              "признаки потока в обратном вызове потеряны");
        d2k_track_free(s);
    }

    /* --- поиск без заведения --------------------------------------------- */
    d2k_key nope = mk(9999);
    CHECK(d2k_track_find(t, &nope) == NULL, "найден несуществующий поток");
    CHECK(d2k_track_count(t) == 1, "поиск завёл поток, хотя не должен");

    /* --- переполнение: отказ, а не рост и не вытеснение ------------------- */
    size_t cap = d2k_track_capacity(t);
    size_t made = 1;
    for (uint16_t p = 1001; p < 1001 + 1000; p++) {
        d2k_key k = mk(p);
        if (d2k_track_get(t, &k, 3000) == NULL) {
            break;
        }
        made++;
    }
    CHECK(made < cap, "таблица заполнилась до предела: порог заполнения не работает");
    CHECK(d2k_track_refusals(t) > 0, "отказ не посчитан — панель не отличит «не видим» от «не взяли»");

    /* Уже заведённый поток обязан находиться и после отказов: отказ не смеет
       вытеснять соседа. */
    CHECK(d2k_track_find(t, &a) != NULL, "существующий поток потерян после переполнения");

    /* --- истечение и повторное использование ячеек ------------------------ */
    size_t before = d2k_track_count(t);
    size_t freed = d2k_track_expire(t, 3000 + 60000, 60000, NULL, NULL);
    CHECK(freed > 0, "ничего не освободилось, хотя все потоки молчат дольше срока");
    CHECK(d2k_track_count(t) == before - freed, "счётчик после истечения неверен");

    /* Время, ушедшее назад, не должно сносить таблицу: вычитание беззнаковое. */
    {
        size_t was = d2k_track_count(t);
        d2k_track_expire(t, 1, 1, NULL, NULL);
        CHECK(d2k_track_count(t) == was,
              "истечение со временем назад снесло потоки — беззнаковое вычитание");
    }

    /* После освобождения таблица обязана снова принимать потоки. */
    d2k_key fresh = mk(30000);
    CHECK(d2k_track_get(t, &fresh, 100000) != NULL,
          "после истечения таблица не принимает новые потоки");

    /* --- удаление не рвёт цепочку ------------------------------------------ */
    {
        d2k_table *s = d2k_track_new(16);
        d2k_key k1 = mk(1), k2 = mk(2), k3 = mk(3);
        /* Свежие времена у соседей и старое у среднего: истечь обязан ровно
           один. В первой версии теста время было одинаковым у всех, и
           истечение сносило все три — тест проверял не то, что заявлял. */
        d2k_track_get(s, &k1, 1000);
        d2k_track_get(s, &k2, 1000);
        d2k_track_get(s, &k3, 1000);
        CHECK(d2k_track_find(s, &k2) != NULL, "средний поток не найден до удаления");
        d2k_track_remove(s, &k2);
        CHECK(d2k_track_find(s, &k2) == NULL, "удалённый поток всё ещё находится");
        CHECK(d2k_track_find(s, &k1) != NULL, "сосед потерян после удаления");
        CHECK(d2k_track_find(s, &k3) != NULL, "сосед за удалённым потерян: цепочка разорвана");
        d2k_track_free(s);
    }

    d2k_track_free(t);

    /* --- случайный стресс -------------------------------------------------
     * Фиксированные случаи ошибок сдвига назад не ловят: там надо попасть в
     * кластер нужной формы. Гоняем случайные вставки и удаления и после
     * каждого шага требуем, чтобы ВСЕ живые ключи находились. Генератор
     * детерминированный: провал обязан воспроизводиться. */
    {
        d2k_table *s = d2k_track_new(256);
        enum { N = 400 };
        static int alive[N];
        uint32_t rnd = 12345;
        size_t live = 0;

        for (int step = 0; step < 20000; step++) {
            rnd = rnd * 1103515245u + 12345u;
            int idx = (int)((rnd >> 16) % N);
            d2k_key k = mk((uint16_t)(20000 + idx));

            if (alive[idx]) {
                d2k_flow *fl = d2k_track_find(s, &k);
                if (!fl) {
                    printf("ПРОВАЛ: живой ключ %d потерян на шаге %d\n", idx, step);
                    fails++;
                    break;
                }
                d2k_track_remove(s, &k);
                alive[idx] = 0;
                live--;
            } else {
                if (d2k_track_get(s, &k, 100) != NULL) {
                    alive[idx] = 1;
                    live++;
                }
            }

            if (d2k_track_count(s) != live) {
                printf("ПРОВАЛ: счётчик %zu против ожидаемых %zu на шаге %d\n",
                       d2k_track_count(s), live, step);
                fails++;
                break;
            }
        }

        /* Итоговая сверка: каждый живой ключ обязан находиться. */
        for (int i = 0; i < N && !fails; i++) {
            d2k_key k = mk((uint16_t)(20000 + i));
            d2k_flow *fl = d2k_track_find(s, &k);
            if (alive[i] && !fl) {
                printf("ПРОВАЛ: живой ключ %d не найден в итоге\n", i);
                fails++;
            }
            if (!alive[i] && fl) {
                printf("ПРОВАЛ: удалённый ключ %d находится\n", i);
                fails++;
            }
        }
        d2k_track_free(s);
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("потоки: все проверки прошли\n");
    return 0;
}
