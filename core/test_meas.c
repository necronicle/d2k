/* test_meas.c — проверки оракула.
 *
 * Стенд ведёт себя как коробка: молчит, если ПЕРВЫЙ сегмент начинается с
 * сигнатуры. Меряем правила, а не чужую линию.
 */
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
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

struct stand { int fd; uint16_t port; int mode; };
/* mode: 0 отвечает всегда; 1 молчит на сигнатуру в первом сегменте */

static void *stand_run(void *arg) {
    struct stand *s = arg;
    for (;;) {
        int c = accept(s->fd, NULL, NULL);
        if (c < 0) { return NULL; }
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

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("оракул: все проверки прошли\n");
    return 0;
}
