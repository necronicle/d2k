/* match.c — узнавание коробки по примете (задача 2, см. задание в
 * .superpowers/sdd/2026-09-07-engine-c-both-transports/task-2-brief.md).
 * Контракт, числа допусков и их обоснование — в шапке d2k_catalog.h над
 * D2K_TTL_SLACK/D2K_VOLUME_SLACK/d2k_fp_same/d2k_catalog_match; здесь —
 * только реализация.
 *
 * Ни malloc, ни разбор байт провода здесь не происходит — сравниваются уже
 * типизированные поля d2k_cat_fp, выделенного и заполненного catalog.c
 * (задача 1) или собранного вручную (как в тестах). Наложения структуры на
 * буфер нет и здесь по построению быть не может, поэтому оговорка про
 * выравнивание MIPS/ARM (см. шапку d2k_catalog.h) этого файла не касается.
 *
 * ПОРЯДОК ФУНКЦИЙ — СНИЗУ ВВЕРХ ПО ЗАВИСИМОСТЯМ, как в catalog.c: sig_same
 * определена раньше d2k_fp_same (зовёт её), та — раньше d2k_catalog_match
 * (зовёт её). Ни одной forward declaration не требуется.
 */
#include <string.h>

#include "d2k_catalog.h"

/* Сравнение ОДНОЙ пары сигналов. Смысл и числа — см. d2k_fp_same в
 * d2k_catalog.h; здесь — только код правила.
 *
 * kind сравнивается первым и точно: разные роды сигнала не сравниваются по
 * числовым полям вовсе, независимо от того, насколько близки числа — это и
 * есть ловушка "разный механизм не должен слиться числовым допуском". */
static int sig_same(const d2k_cat_signal *a, const d2k_cat_signal *b) {
    int d;

    if (strcmp(a->kind, b->kind) != 0) {
        return 0;
    }

    if (strcmp(a->kind, "volume") == 0) {
        /* У обрыва по объёму нет ни TTL, ни идентификатора: коробка ничего
         * не присылает, она просто перестаёт пропускать. Сравнивать
         * нечего, кроме объёма. */
        d = a->volume - b->volume; /* volume — int (знаковый), обычное вычитание */
        if (d < 0) {
            d = -d;
        }
        return d <= D2K_VOLUME_SLACK;
    }

    /* ttl — uint8_t. Явные (int)-приведения ниже не полагаются молча на
     * то, что целочисленное продвижение C99 само переведёт оба операнда в
     * int перед вычитанием (а оно переводит: диапазон 0..255 целиком
     * умещается в int) — они документируют это рассуждение и не сломаются
     * тихо, если ttl когда-нибудь станет шире uint8_t. Без него при a < b
     * беззнаковая разность дала бы огромное положительное число вместо
     * отрицательного, и |d| <= D2K_TTL_SLACK никогда бы не сработало для
     * "соседа снизу". */
    d = (int)a->ttl - (int)b->ttl;
    if (d < 0) {
        d = -d;
    }
    if (d > D2K_TTL_SLACK) {
        return 0;
    }

    /* tos и ipid — точно: их дрожание от маршрута не измерено (в отличие
     * от ttl и volume выше), а вводить допуск без замера этот проект
     * запрещает. */
    return a->tos == b->tos && a->ipid == b->ipid;
}

int d2k_fp_same(const d2k_cat_fp *a, const d2k_cat_fp *b) {
    size_t i;

    if (a->method != b->method) {
        return 0;
    }
    if (a->n_sig != b->n_sig) {
        return 0;
    }
    for (i = 0; i < a->n_sig; i++) {
        if (!sig_same(&a->sig[i], &b->sig[i])) {
            return 0;
        }
    }
    return 1;
}

int d2k_catalog_match(const d2k_catalog *c, const d2k_cat_fp *fp) {
    size_t i;

    for (i = 0; i < c->n_boxes; i++) {
        if (d2k_fp_same(&c->boxes[i].fp, fp)) {
            return (int)i;
        }
    }
    return -1;
}
