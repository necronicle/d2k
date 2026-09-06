/* test_meas.c — проверки оракула.
 *
 * Стенд ведёт себя как коробка: молчит, если ПЕРВЫЙ сегмент начинается с
 * сигнатуры. Меряем правила, а не чужую линию.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "d2k_meas.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static const uint8_t sig[4] = { 0x16, 0x03, 0x01, 0x00 };

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

struct stand { int fd; uint16_t port; int mode; size_t want; };
/* mode: 0 отвечает всегда; 1 молчит на сигнатуру в первом сегменте;
   2 копит байты до want и только тогда шлёт ack — если отправитель замолчал
   раньше срока (потерял хвост куска на короткой записи), ack не придёт
   никогда, и это наблюдаемое отличие «долечили короткую запись» от «нет». */

static void *stand_run(void *arg) {
    struct stand *s = arg;
    for (;;) {
        int c = accept(s->fd, NULL, NULL);
        if (c < 0) { return NULL; }
        if (s->mode == 2) {
            /* Пауза дольше d2k_send_timeout_s обязательна и вот почему:
               замером на этой же машине показано, что короткая запись
               НАБЛЮДАЕТСЯ только когда SO_SNDTIMEO успевает истечь при
               недренирующем приёмнике (send() 16 МиБ пассивному получателю
               вернул 1 135 204 из 16 777 216 за это время) — если приёмник
               начинает читать РАНЬШЕ истечения таймаута, ядро само
               дотягивает всю запись за один вызов, и короткой записи
               снаружи не видно вовсе. Тест уменьшает d2k_send_timeout_s до
               1 с; здесь пауза 1.5 с — заведомо за его пределами. */
            struct timespec pause_ts = { 1, 500000000L }; /* 1.5 с */
            nanosleep(&pause_ts, NULL);
            uint8_t buf[65536];
            size_t got = 0;
            while (got < s->want) {
                ssize_t n = recv(c, buf, sizeof buf, 0);
                if (n <= 0) { break; }
                got += (size_t)n;
            }
            if (got == s->want) {
                const uint8_t ans[7] = { 0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00 };
                (void)send(c, ans, sizeof ans, 0);
            }
            close(c);
            continue;
        }
        uint8_t buf[8192];
        ssize_t n = recv(c, buf, sizeof buf, 0);
        int blocked = 0;
        if (s->mode == 1 && n >= (ssize_t)sizeof sig &&
            memcmp(buf, sig, sizeof sig) == 0) {
            blocked = 1;
        }
        if (!blocked) {
            const uint8_t ans[7] = { 0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00 };
            (void)send(c, ans, sizeof ans, 0);
        }
        close(c);
    }
}

static uint16_t stand_start(struct stand *s, int mode) {
    s->fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    a.sin_port = 0;
    bind(s->fd, (struct sockaddr *)&a, sizeof a);
    socklen_t l = sizeof a;
    getsockname(s->fd, (struct sockaddr *)&a, &l);
    listen(s->fd, 8);
    s->mode = mode;
    s->port = ntohs(a.sin_port);
    pthread_t t;
    pthread_create(&t, NULL, stand_run, s);
    pthread_detach(t);
    return s->port;
}

int main(void) {
    uint8_t hello[64];
    memset(hello, 0xAA, sizeof hello);
    memcpy(hello, sig, sizeof sig);
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
        memcpy(big, sig, sizeof sig);
        d2k_hello bh = { big, sizeof big };

        struct stand s;
        memset(&s, 0, sizeof s);
        s.want = sizeof big;
        uint16_t p = stand_start(&s, 2);

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
