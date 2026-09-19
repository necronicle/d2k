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

    {
        uint8_t b[] = {'D','2','K','P',0,1,0,7,0,0,0,2,
                       0,2,0,2,17,2, 1,12,0,1,1};
        for (unsigned shape=1;shape<=4;shape++) {
            b[22]=(uint8_t)shape;
            CHECK(loads(b,sizeof b), "original IP fragment shape rejected");
        }
        b[22]=0; CHECK(!loads(b,sizeof b), "zero fragment shape accepted");
        b[22]=5; CHECK(!loads(b,sizeof b), "unknown fragment shape accepted");
        b[22]=1;b[7]=6;
        CHECK(!loads(b,sizeof b), "fragment requires executor 7");
        b[7]=7;b[16]=6;
        CHECK(!loads(b,sizeof b), "UDP fragment accepted for TCP");
        b[16]=0;
        CHECK(!loads(b,sizeof b), "fragment without transport accepted");
        b[16]=17;b[21]=0;
        CHECK(!loads(b,sizeof b-1), "empty fragment record accepted");
    }

    {
        uint8_t b[] = {'D','2','K','P',0,1,0,4,0,0,0,2,
                       0,2,0,2,6,1, 1,9,0,1,D2K_WIRE_DETECT_TCP};
        CHECK(loads(b, sizeof b), "detect wire profile rejected");
        b[7] = 3;
        CHECK(!loads(b, sizeof b), "detect wire profile accepted with minexec=3");
        b[7] = 4; b[22] = 2;
        CHECK(!loads(b, sizeof b), "unknown wire profile accepted");
        b[22] = 1; b[16] = 17;
        CHECK(!loads(b, sizeof b), "TCP wire profile accepted for UDP");
        b[16] = 6; b[21] = 0;
        CHECK(!loads(b, sizeof b - 1), "empty wire profile accepted");
    }

    {
        uint8_t b[] = {'D','2','K','P',0,1,0,5,0,0,0,2,
                       0,2,0,2,6,1, 1,10,0,0,0};
        CHECK(loads(b, sizeof b - 1), "complete TLS input guard rejected");
        b[7] = 4;
        CHECK(!loads(b, sizeof b - 1), "TLS input guard accepted with minexec=4");
        b[7] = 5; b[16] = 17;
        CHECK(!loads(b, sizeof b - 1), "TLS input guard accepted for UDP");
        b[16] = 0;
        CHECK(!loads(b, sizeof b - 1), "TLS input guard accepted without transport");
        b[16] = 6; b[21] = 1;
        CHECK(!loads(b, sizeof b), "TLS input guard accepted unexpected body");
    }

    /* New measured-context records: validate length, value and minexec. */
    for (unsigned code = 6; code <= 8; code++) {
        uint8_t b[34] = {'D','2','K','P',0,1,0,3,0,0,0,2,0,2,0,2,6,1,1,0,0,0};
        size_t len = code == 6 ? 12 : 4;
        b[19] = (uint8_t)code; b[21] = (uint8_t)len; b[25] = 100;
        CHECK(loads(b, 22 + len), "valid measured record rejected");
        b[16] = 17;
        CHECK(!loads(b, 22 + len), "TCP operation accepted for UDP");
        b[16] = 0;
        CHECK(!loads(b, 22 + len), "TCP operation accepted for unspecified transport");
        b[16] = 6;
        b[7] = 2;
        CHECK(!loads(b, 22 + len), "measured record accepted with minexec=2");
        b[7] = 3; b[25] = 0;
        CHECK(!loads(b, 22 + len), "zero measured value accepted");
        b[25] = 100; b[21]--;
        CHECK(!loads(b, 21 + len), "short measured record accepted");
        b[21] = (uint8_t)len;
        if (code == 6) {
            b[29] = 99; b[33] = 2;
            CHECK(!loads(b, sizeof b), "SNI past end accepted");
        } else if (code == 8) {
            b[23] = 1;
            CHECK(!loads(b, 26), "segment over 65535 accepted");
        }
    }

    /* РАЗНОС ВО ВРЕМЕНИ (REC_PACE 0x0105): ровно 4 байта.
     *
     * Запись новая, и проверка длины у неё отдельная от прочих не случайно:
     * запись, принятая с чужой длиной, сдвинула бы разбор всех последующих, и
     * план исполнился бы не тем, чем его измеряли. Заодно здесь видно, что
     * новый код записи вообще ПРИНИМАЕТСЯ — иначе правка языка молча осталась
     * бы только в сборщике. */
    {
        static const uint8_t pace_ok[] = {
            'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 1,
            0x01, 0x05, 0x00, 0x04, 0x00, 0x00, 0x2E, 0xE0   /* 12000 мкс */
        };
        static const uint8_t pace_short[] = {
            'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 1,
            0x01, 0x05, 0x00, 0x02, 0x2E, 0xE0
        };
        CHECK(loads(pace_ok, sizeof pace_ok), "правильный разнос во времени не принят");
        CHECK(!loads(pace_short, sizeof pace_short), "разнос во времени принят с длиной 2 байта");
    }

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
