/* test_plan_apply.c — проверки применения плана.
 *
 * Список посылок содержит ТОЛЬКО то, что порождаем мы. Судьба оригинала —
 * отдельное поле, а не ещё одна строка в списке: иначе «пропустить оригинал» и
 * «выпустить его копию» стали бы неразличимы, и пакет ушёл бы дважды.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_plan.h"
/* Полное определение потока живёт здесь: d2k_plan.h объявляет тип
   опережающе, и одного его для переменной по значению не хватает. */
#include "d2k_track.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Фальшивка перед всеми кусками, две копии с паузой 78 мс — ровно то, чем
   обходится боевое плечо донора. Байты собраны здесь, а не подсунуты внешним
   символом: тест не должен зависеть от порядка сборки. */
static const uint8_t plan_fake_before[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 4,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Разрез по началу SNI и ничего больше. */
static const uint8_t plan_split_sni[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Фальшивка МЕЖДУ кусками, но разрезов в плане нет: класть её некуда. */
static const uint8_t plan_between_no_split[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 3,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0xAA,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01,
                            0, 0, 0, 0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

static uint8_t hello[64];

static void init_pkt(d2k_pkt *in, int have_sni) {
    memset(hello, 0xCC, sizeof hello);
    in->payload = hello;
    in->payload_len = sizeof hello;
    in->seq = 1000;
    in->have_sni = have_sni;
    in->sni_off = 10;
    in->sni_len = 8;
}

int main(void) {
    d2k_plan *p = NULL;
    char err[160];
    d2k_flow f;
    memset(&f, 0, sizeof f);
    d2k_actions a;
    d2k_pkt in;

    /* --- фальшивка перед кусками ------------------------------------- */
    CHECK(d2k_plan_load(plan_fake_before, sizeof plan_fake_before, &p, err, sizeof err) == 0,
          "план с фальшивкой не загрузился");
    if (p) {
        init_pkt(&in, 1);
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) == 0, "применение не удалось");
        CHECK(a.n == 2, "ожидались ровно две копии фальшивки");
        if (a.n == 2) {
            CHECK(a.v[0].delay_us == 0, "первая копия не должна ждать");
            CHECK(a.v[1].delay_us == 78000, "пауза между копиями потеряна");
            CHECK(a.v[0].seq == in.seq, "фальшивка обязана занимать место начала потока");
            CHECK(a.v[0].ttl == 3, "ttl порчи не доехал");
            CHECK(a.v[0].poison == D2K_POISON_BADSUM, "флаг порчи не доехал");
            CHECK(a.v[0].len == 3, "длина приманки не совпала");
        }
        /* Оригинал мы не трогали — его обязан выпустить вызывающий. */
        CHECK(a.fate == D2K_ORIG_PASS, "судьба оригинала должна быть «пропустить»");
        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- разрез по SNI ------------------------------------------------ */
    CHECK(d2k_plan_load(plan_split_sni, sizeof plan_split_sni, &p, err, sizeof err) == 0,
          "план с разрезом не загрузился");
    if (p) {
        init_pkt(&in, 1);
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) == 0, "применение разреза не удалось");
        CHECK(a.n == 2, "разрез обязан дать два куска");
        if (a.n == 2) {
            CHECK(a.v[0].seq == 1000 && a.v[0].len == 10, "первый кусок не по якорю");
            CHECK(a.v[1].seq == 1010 && a.v[1].len == 54, "второй кусок не по якорю");
        }
        /* Нагрузку выпустили мы сами — оригинал обязан быть снят, иначе
           байты уйдут дважды. */
        CHECK(a.fate == D2K_ORIG_DROP, "при своём выпуске нагрузки оригинал обязан сниматься");
        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- невычислимый якорь ------------------------------------------- */
    CHECK(d2k_plan_load(plan_split_sni, sizeof plan_split_sni, &p, err, sizeof err) == 0,
          "план не загрузился повторно");
    if (p) {
        init_pkt(&in, 0); /* SNI в пакете нет */
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) != 0,
              "невычислимый якорь обязан давать отказ, а не нулевое смещение");
        CHECK(a.n == 0, "при отказе действий быть не должно");
        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- фальшивка между кусками без разрезов -------------------------- */
    CHECK(d2k_plan_load(plan_between_no_split, sizeof plan_between_no_split, &p, err, sizeof err) != 0,
          "фальшивка «между кусками» без разрезов принята: класть её некуда");
    if (p) {
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- отмена исполнения на середине -------------------------------- */
    CHECK(d2k_plan_load(plan_fake_before, sizeof plan_fake_before, &p, err, sizeof err) == 0,
          "план с фальшивкой не загрузился для проверки отмены");
    if (p) {
        init_pkt(&in, 1);
        memset(&a, 0, sizeof a);
        d2k_plan_apply(p, &f, &in, &a);
        d2k_cancel c;

        /* Ничего не ушло: отмена совершенно чистая. */
        memset(&c, 0, sizeof c);
        d2k_actions_cancel(&a, 0, &c);
        CHECK(c.fate == D2K_ORIG_PASS, "до первой посылки оригинал обязан пройти");
        /* partial означает «полного исполнения не было», а не «оборвалось на
           середине». Потребитель решает по нему единственный вопрос — можно ли
           записывать измерение, — и ответ «нельзя» одинаков и для оборванного
           плана, и для не начинавшегося. Ноль здесь прочитался бы как
           разрешение записать измерение по плану, который не исполнялся.
           Различить «не начинался» и «оборвался» контроллер может по emitted,
           которое он и так передаёт. */
        CHECK(c.partial == 1, "неисполненный план не должен выглядеть исполненным");
        CHECK(c.stream_damaged == 0, "поток не мог испортиться до первой посылки");

        /* Ушла одна копия фальшивки из двух: нагрузку не трогали. */
        memset(&c, 0, sizeof c);
        d2k_actions_cancel(&a, 1, &c);
        CHECK(c.fate == D2K_ORIG_PASS, "после фальшивки оригинал обязан пройти");
        CHECK(c.partial == 1, "исполнение неполное — измерение по нему недействительно");
        CHECK(c.stream_damaged == 0, "фальшивка нагрузку не портит");

        /* Ушло всё: это не отмена. */
        memset(&c, 0, sizeof c);
        d2k_actions_cancel(&a, a.n, &c);
        CHECK(c.partial == 0, "полностью исполненный план не является частичным");

        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* Отмена посреди НАГРУЗКИ: чистого выхода нет. */
    CHECK(d2k_plan_load(plan_split_sni, sizeof plan_split_sni, &p, err, sizeof err) == 0,
          "план с разрезом не загрузился для проверки отмены");
    if (p) {
        init_pkt(&in, 1);
        memset(&a, 0, sizeof a);
        d2k_plan_apply(p, &f, &in, &a);
        d2k_cancel c;

        /* Первый кусок уже на проводе. Отпустить оригинал — послать те же
           байты дважды; не отпустить — потерять остаток. */
        memset(&c, 0, sizeof c);
        d2k_actions_cancel(&a, 1, &c);
        CHECK(c.stream_damaged == 1, "отмена посреди нагрузки обязана помечать поток испорченным");
        CHECK(c.fate == D2K_ORIG_DROP, "оригинал нельзя отпускать: его байты уже частично ушли");
        CHECK(c.partial == 1, "исполнение неполное");

        /* До первого куска — ещё чисто. */
        memset(&c, 0, sizeof c);
        d2k_actions_cancel(&a, 0, &c);
        CHECK(c.stream_damaged == 0, "до первого куска поток цел");
        CHECK(c.fate == D2K_ORIG_PASS, "нагрузку не трогали — оригинал обязан пройти");

        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("применение: все проверки прошли\n");
    return 0;
}
