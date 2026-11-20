#include "d2km_question.h"
#include "test.h"
#include <string.h>

static d2km_result R(d2km_result_kind k) { d2km_result r = {k, 0}; return r; }

static d2km_question Q(d2km_operator op, int64_t v, uint32_t packets, size_t n,
                       const d2km_hypothesis *h, const d2km_result_kind *p)
{
    d2km_question q;
    memset(&q, 0, sizeof(q));
    q.action.op = op;
    q.action.value = v;
    q.packets = packets;
    q.prediction_count = n;
    for (size_t i = 0; i < n; i++) {
        q.predictions[i].hypothesis = h[i];
        q.predictions[i].predicted = R(p[i]);
    }
    return q;
}

static int no_server(void *ctx, d2km_hypothesis a, d2km_hypothesis b)
{
    (void)ctx;
    /* Пример: выбор между «сервер недоступен» и «потеря» программу не меняет. */
    return !((a == D2KM_H_SERVER_DOWN && b == D2KM_H_NET_LOSS) ||
             (b == D2KM_H_SERVER_DOWN && a == D2KM_H_NET_LOSS));
}

/* Модель границы: при значении >= edge исход RST, иначе успех. */
static d2km_result box(int64_t v, int64_t edge)
{
    return v >= edge ? R(D2KM_R_RST) : R(D2KM_R_APP_OK);
}

int main(void)
{
    d2km_hypothesis live[] = {D2KM_H_ADDR_BLOCK, D2KM_H_PORT_BLOCK,
                              D2KM_H_SERVER_DOWN, D2KM_H_NET_LOSS};
    d2km_hypothesis h4[] = {D2KM_H_ADDR_BLOCK, D2KM_H_PORT_BLOCK,
                            D2KM_H_SERVER_DOWN, D2KM_H_NET_LOSS};
    d2km_result_kind all_diff[] = {D2KM_R_SYN_SILENT, D2KM_R_APP_OK, D2KM_R_RST, D2KM_R_ICMP};
    d2km_result_kind two_groups[] = {D2KM_R_SYN_SILENT, D2KM_R_SYN_SILENT, D2KM_R_APP_OK, D2KM_R_APP_OK};
    d2km_result_kind same[] = {D2KM_R_APP_OK, D2KM_R_APP_OK, D2KM_R_APP_OK, D2KM_R_APP_OK};

    d2km_question a = Q(D2KM_OP_SET_FIELD, 1, 3, 4, h4, all_diff);
    d2km_question b = Q(D2KM_OP_SET_FIELD, 2, 3, 4, h4, two_groups);
    d2km_question c = Q(D2KM_OP_SET_FIELD, 3, 3, 4, h4, same);
    CHECK(d2km_question_weight(&a, live, 4, NULL, NULL) == 6);
    CHECK(d2km_question_weight(&b, live, 4, NULL, NULL) == 4);
    CHECK(d2km_question_weight(&c, live, 4, NULL, NULL) == 0);
    /* Пара, от которой программа не зависит, веса не даёт. */
    CHECK(d2km_question_weight(&a, live, 4, no_server, NULL) == 5);
    /* Неживая гипотеза не считается. */
    CHECK(d2km_question_weight(&a, live, 2, NULL, NULL) == 1);

    d2km_question qs[3] = {b, c, a};
    CHECK(d2km_question_select(qs, 3, live, 4, NULL, 0, NULL, NULL) == 2);
    /* Уже отвеченный не задаётся повторно. */
    CHECK(d2km_question_select(qs, 3, live, 4, &a.action, 1, NULL, NULL) == 0);
    /* Нулевой вес не задаётся: задавать нечего. */
    CHECK(d2km_question_select(&c, 1, live, 4, NULL, 0, NULL, NULL) == -1);
    CHECK(d2km_question_select(qs, 0, live, 4, NULL, 0, NULL, NULL) == -1);
    /* Равный вес: меньше пакетов, затем меньший номер оператора. */
    d2km_question t1 = Q(D2KM_OP_WINDOW, 1, 2, 4, h4, all_diff);
    d2km_question t2 = Q(D2KM_OP_SPLIT, 1, 5, 4, h4, all_diff);
    d2km_question t3 = Q(D2KM_OP_DROP_FIELD, 1, 2, 4, h4, all_diff);
    d2km_question tie[3] = {t2, t1, t3};
    CHECK(d2km_question_select(tie, 3, live, 4, NULL, 0, NULL, NULL) == 2);
    tie[2].packets = 9;
    CHECK(d2km_question_select(tie, 3, live, 4, NULL, 0, NULL, NULL) == 1);
    d2km_question bad = a;
    bad.action.op = 0;
    CHECK(d2km_question_select(&bad, 1, live, 4, NULL, 0, NULL, NULL) == -1);

    /* §6.5: поиск границы TTL в 1..255 для каждой границы. */
    for (int64_t edge = 2; edge <= 255; edge++) {
        d2km_search s;
        CHECK(d2km_search_init(&s, 1, 255, 1) == 0);
        int64_t v;
        int steps = 0;
        while (d2km_search_next(&s, &v)) {
            CHECK(v >= 1 && v <= 255);
            CHECK(d2km_search_feed(&s, v, box(v, edge)) == 0);
            if (++steps > 40) break;
        }
        CHECK(s.phase == D2KM_SEARCH_BOUNDARY);
        CHECK(s.lo == edge - 1 && s.hi == edge);
        CHECK(s.at_hi.kind == D2KM_R_RST && s.base.kind == D2KM_R_APP_OK);
        CHECK(steps <= 18);   /* удвоение + деление: логарифм, не перебор */
    }
    /* Смены нет во всём диапазоне — исчерпан. */
    d2km_search s;
    d2km_search_init(&s, 1, 255, 1);
    int64_t v;
    while (d2km_search_next(&s, &v))
        d2km_search_feed(&s, v, R(D2KM_R_APP_OK));
    CHECK(s.phase == D2KM_SEARCH_EXHAUSTED && s.lo == 255);
    /* Смена уже на втором значении. */
    d2km_search_init(&s, 1, 255, 1);
    while (d2km_search_next(&s, &v))
        d2km_search_feed(&s, v, box(v, 2));
    CHECK(s.phase == D2KM_SEARCH_BOUNDARY && s.lo == 1 && s.hi == 2);
    /* Чужое значение и локальный исход не принимаются. */
    d2km_search_init(&s, 1, 65535, 1);
    CHECK(d2km_search_feed(&s, 7, R(D2KM_R_APP_OK)) == -1);
    CHECK(d2km_search_feed(&s, 1, R(D2KM_R_LOCAL_FAIL)) == -1);
    CHECK(s.phase == D2KM_SEARCH_PROBE_MIN);
    /* Шаг грамматики больше единицы. */
    d2km_search_init(&s, 0, 1000, 8);
    while (d2km_search_next(&s, &v)) {
        CHECK(v % 8 == 0 || v == 1000);
        d2km_search_feed(&s, v, box(v, 333));
    }
    CHECK(s.phase == D2KM_SEARCH_BOUNDARY && s.hi - s.lo <= 8 && s.lo < 333 && s.hi >= 333);
    CHECK(d2km_search_init(&s, 5, 5, 1) == -1);
    CHECK(d2km_search_init(&s, 1, 5, 0) == -1);

    /* Позиции разреза — только границы полей внутри сообщения. */
    uint32_t bounds[] = {5, 0, 43, 9, 43, 517, 600, 9};
    uint32_t out[8];
    CHECK(d2km_split_positions(bounds, 8, 517, out, 8) == 3);
    CHECK(out[0] == 5 && out[1] == 9 && out[2] == 43);
    DONE("test_question");
}
