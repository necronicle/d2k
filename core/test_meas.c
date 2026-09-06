/* test_meas.c — проверки оракула.
 *
 * Стенд ведёт себя как коробка: молчит, если ПЕРВЫЙ сегмент начинается с
 * сигнатуры. Меряем правила, а не чужую линию. Сам стенд вынесен в
 * test_stand.h и общий с test_verdict.c (см. его шапку про источник этого
 * решения — не бриф, а сопроводительное письмо к задаче 2); у задачи 2 те
 * же режимы 0 и 1, что и здесь.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "d2k_meas.h"
#include "test_stand.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Подставные реализации d2k_mark_hook для проверки И-семантики метки без
 * зависимости от CAP_NET_ADMIN на машине проверки (см. блок теста в main). */
static int mark_always_ok(int fd, uint32_t mark) {
    (void)fd;
    (void)mark;
    return 0;
}

static int mark_fail_calls;
static int mark_fail_on_second(int fd, uint32_t mark) {
    (void)fd;
    (void)mark;
    mark_fail_calls++;
    return mark_fail_calls == 2 ? -1 : 0;
}

int main(void) {
    uint8_t hello[64];
    memset(hello, 0xAA, sizeof hello);
    memcpy(hello, d2k_test_sig, sizeof d2k_test_sig);
    d2k_hello h = { hello, sizeof hello };

    /* --- чистая мишень: все три повтора проходят -------------------------- */
    {
        struct stand s;
        uint16_t p = stand_start(&s, 0);
        d2k_tally t = d2k_meas("127.0.0.1", p, h, NULL, 0, 0, 700, 0, 3);
        CHECK(t.pass == 3, "на чистой мишени прошли не все три повтора");
        CHECK(t.fail == 0, "на чистой мишени есть промахи");
    }

    /* --- блокирующая мишень: не проходит ни один -------------------------- */
    {
        struct stand s;
        uint16_t p = stand_start(&s, 1);
        d2k_tally t = d2k_meas("127.0.0.1", p, h, NULL, 0, 0, 700, 0, 3);
        CHECK(t.pass == 0, "на блокирующей мишени что-то прошло");
    }

    /* --- разрез ломает префиксный матчер ---------------------------------- */
    {
        struct stand s;
        uint16_t p = stand_start(&s, 1);
        size_t cuts[1] = { 1 };
        /* Пауза обязательна: на петле два send подряд попадают в один recv, и
           опыт про разрез перестаёт быть опытом про разрез. */
        d2k_tally t = d2k_meas("127.0.0.1", p, h, cuts, 1, 5000, 700, 0, 3);
        CHECK(t.pass == 3, "разрез не прошёл на префиксном матчере");
    }

    /* --- нулевая метка означает «не метили», а не «метка не встала» ------- */
    {
        struct stand s;
        uint16_t p = stand_start(&s, 0);
        d2k_tally t = d2k_meas("127.0.0.1", p, h, NULL, 0, 0, 700, 0, 1);
        CHECK(t.marked == 1, "без запроса метки серия объявлена непомеченной");
    }

    /* --- И-семантика метки не зависит от привилегии запускающего -----------
     * Настоящий SO_MARK требует CAP_NET_ADMIN: без него setsockopt всегда
     * проваливается, и проверка «marked==1 при mark!=0» зеленела бы только
     * под root, а под обычным пользователем краснела бы, ничего не доказывая
     * про саму И-логику. Подменяем механизм постановки метки целиком
     * (d2k_mark_hook), проверяя ПОЛИТИКУ отдельно от привилегии на машине
     * проверки — тот же приём, что markFunc в internal/classify/measure.go,
     * и по той же причине. */
    {
        struct stand s;
        uint16_t p = stand_start(&s, 0);
        d2k_mark_fn real_mark = d2k_mark_hook; /* вернуть после подмены */

        d2k_mark_hook = mark_always_ok;
        d2k_tally t_ok = d2k_meas("127.0.0.1", p, h, NULL, 0, 0, 700, 0x2d, 3);
        CHECK(t_ok.marked == 1,
              "успешная метка на всех трёх дозвонах не признана серией помеченной");

        mark_fail_calls = 0;
        d2k_mark_hook = mark_fail_on_second;
        d2k_tally t_bad = d2k_meas("127.0.0.1", p, h, NULL, 0, 0, 700, 0x2d, 3);
        CHECK(t_bad.marked == 0,
              "один непомеченный дозвон из трёх не погасил метку всей серии");

        d2k_mark_hook = real_mark;
    }

    /* --- невалидные точки разреза: отказ, а не тихая подмена ---------------
     * На живом пробнике показано: [12,4,8] теряет границы 4 и 8, а [1000,8]
     * гасит вообще все точки и шлёт целиком одним куском. Тихая подмена
     * запрошенного разреза на похожий — тот же грех, что пересборка
     * приветствия: контракт («строго возрастают, лежат внутри длины») либо
     * соблюдён целиком, либо опыт не проводится вовсе. */
    {
        struct stand s;
        uint16_t p = stand_start(&s, 0);
        int marked;

        size_t unordered[3] = { 12, 4, 8 };
        int r1 = d2k_meas_once("127.0.0.1", p, h, unordered, 3, 0, 700, 0, &marked);
        CHECK(r1 == -1, "немонотонные точки разреза приняты вместо отказа");

        size_t out_of_range[2] = { 1000, 8 };
        int r2 = d2k_meas_once("127.0.0.1", p, h, out_of_range, 2, 0, 700, 0, &marked);
        CHECK(r2 == -1, "точка разреза за пределами длины принята вместо отказа");

        size_t valid[1] = { 1 };
        int r3 = d2k_meas_once("127.0.0.1", p, h, valid, 1, 0, 700, 0, &marked);
        CHECK(r3 == 1, "валидный разрез отклонён заодно с невалидными");
    }

    /* --- connect ограничен по времени, а не висит на умолчании ядра --------
     * Настоящую чёрную дыру на SYN без root и файрвола переносимо и
     * детерминированно не собрать — здесь проверяется другое: неблокирующий
     * connect() обязан отличать ОШИБКУ соединения от готовности к записи
     * через SO_ERROR, а не считать любой POLLOUT успехом. Закрытый порт на
     * петле даёт мгновенный RST одинаково на любой ОС — сам потолок в 8 с
     * (см. meas.c) проверке подлежит инспекцией кода: poll() структурно не
     * может ждать дольше срока, который ему передали. */
    {
        int probe = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(0x7f000001);
        a.sin_port = 0;
        bind(probe, (struct sockaddr *)&a, sizeof a);
        socklen_t l = sizeof a;
        getsockname(probe, (struct sockaddr *)&a, &l);
        uint16_t closed_port = ntohs(a.sin_port);
        close(probe);

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int marked;
        int r = d2k_meas_once("127.0.0.1", closed_port, h, NULL, 0, 0, 700, 0, &marked);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double secs = (double)(t1.tv_sec - t0.tv_sec) +
                      (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

        CHECK(r == -1, "отказ на connect не распознан как несостоявшийся опыт");
        CHECK(secs < 3.0, "отказ на connect ждал слишком долго — потолок не сработал");
    }

    /* --- короткая запись не теряет часть куска ------------------------------
     * Кусок крупнее буфера отправки почти наверняка получит короткий send()
     * уже на первом вызове: ядро копирует в буфер ровно столько, сколько
     * влезает прямо сейчас, и это законный, документированный POSIX-исход на
     * блокирующем сокете, а не ошибка. Старый код проверял только `< 0` и
     * продвигал границу куска на весь его размер независимо от того, сколько
     * байт ушло на самом деле: часть приветствия молча оставалась в процессе
     * и никогда не попадала на провод.
     *
     * Проверяем не факт короткой записи (это внутренности ядра), а
     * наблюдаемое следствие: если её не долечивать, до мишени дойдёт МЕНЬШЕ
     * байт, чем послано, ack не придёт никогда, и опыт покажет 0 там, где
     * мишень ничего не блокировала. */
    {
        static uint8_t big[16 * 1024 * 1024];
        memset(big, 0xBB, sizeof big);
        memcpy(big, d2k_test_sig, sizeof d2k_test_sig);
        d2k_hello bh = { big, sizeof big };

        struct stand s;
        memset(&s, 0, sizeof s);
        s.want = sizeof big;
        /* Режим 4 — «копит ровно want байт» (см. test_stand.h). Раньше был
           под номером 2; сдвинут, чтобы 2 в общем стенде досталось
           пересборке, которую использует test_verdict.c. */
        uint16_t p = stand_start(&s, 4);

        /* Сокращаем потолок записи на время этого блока: короткая запись —
           наблюдаемое следствие истечения SO_SNDTIMEO при недренирующем
           приёмнике (см. комментарий у mode==2 в stand_run), а ждать
           боевые 8 секунд ради одной проверки в каждом прогоне make check
           незачем. Обязаны вернуть значение обратно — оно глобальное. */
        d2k_send_timeout_s = 1;
        int marked;
        int r = d2k_meas_once("127.0.0.1", p, bh, NULL, 0, 0, 3000, 0, &marked);
        d2k_send_timeout_s = 8;
        CHECK(r == 1, "короткая запись потеряла часть большого приветствия");
    }

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("оракул: все проверки прошли\n");
    return 0;
}
