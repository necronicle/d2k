/* test_ctl.c — управляющий сокет, на настоящем сокете.
 *
 * AF_UNIX работает и на маке, поэтому здесь ничего не подделывается: тот же
 * код, что пойдёт на роутер, разговаривает с настоящим клиентом.
 *
 * Проверяется прежде всего то, что ломает поток: кадр, пришедший по кускам;
 * два кадра в одной записи; врущая длина; исчезнувший собеседник. Разбор
 * потока — место, где ошибка не видна до тех пор, пока не станет поздно.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "d2k_ctl.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static const char *SOCK = "/tmp/d2k-test-ctl.sock";

static int dial(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, SOCK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Собранные обратным вызовом команды. */
static struct { uint16_t type; size_t len; uint8_t body[64]; } got[8];
static size_t n_got;

static void on_cmd(void *ctx, uint16_t type, const uint8_t *body, size_t len) {
    (void)ctx;
    if (n_got >= 8) {
        return;
    }
    got[n_got].type = type;
    got[n_got].len = len;
    if (len <= sizeof got[0].body) {
        memcpy(got[n_got].body, body, len);
    }
    n_got++;
}

static void frame(uint8_t *o, uint16_t type, const uint8_t *body, size_t len) {
    uint32_t plen = (uint32_t)(2 + len);
    o[0] = (uint8_t)(plen >> 24); o[1] = (uint8_t)(plen >> 16);
    o[2] = (uint8_t)(plen >> 8);  o[3] = (uint8_t)plen;
    o[4] = (uint8_t)(type >> 8);  o[5] = (uint8_t)type;
    if (len) {
        memcpy(o + 6, body, len);
    }
}

int main(void) {
    char err[160];
    d2k_ctl *c = d2k_ctl_open(SOCK, err, sizeof err);
    CHECK(c != NULL, "сокет не создался");
    if (!c) {
        printf("  причина: %s\n", err);
        return 1;
    }

    /* --- событие без подключённого контроллера теряется -------------------- */
    {
        uint8_t body[4] = {1, 2, 3, 4};
        d2k_ctl_event(c, D2K_EV_HELLO, body, sizeof body);
        CHECK(d2k_ctl_dropped(c) == 1, "событие без собеседника не посчитано потерянным");
        CHECK(d2k_ctl_sent(c) == 0, "событие без собеседника сочтено отправленным");
    }

    int cli = dial();
    CHECK(cli >= 0, "клиент не подключился");
    d2k_ctl_accept(c);
    CHECK(d2k_ctl_peer_fd(c) >= 0, "подключение не принято");

    /* --- второй контроллер отвергается -------------------------------------
     * Двое поставили бы противоречащие планы, не зная друг о друге.          */
    {
        int cli2 = dial();
        d2k_ctl_accept(c);
        CHECK(d2k_ctl_peer_fd(c) >= 0, "первое подключение потеряно из-за второго");
        /* Второму закрыли — чтение вернёт ноль (конец файла). */
        if (cli2 >= 0) {
            uint8_t junk[4];
            ssize_t n = read(cli2, junk, sizeof junk);
            CHECK(n == 0, "второй контроллер не был отвергнут");
            close(cli2);
        }
    }

    /* --- событие доезжает байт в байт --------------------------------------- */
    {
        uint8_t body[5] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
        d2k_ctl_event(c, D2K_EV_SUSPECT, body, sizeof body);
        CHECK(d2k_ctl_sent(c) == 1, "событие не отправлено");

        uint8_t buf[64];
        ssize_t n = read(cli, buf, sizeof buf);
        CHECK(n == 11, "длина кадра события не та");
        uint8_t want[11];
        frame(want, D2K_EV_SUSPECT, body, sizeof body);
        CHECK(n == 11 && memcmp(buf, want, 11) == 0, "байты кадра события разошлись");
    }

    /* --- команда целиком ------------------------------------------------------ */
    {
        n_got = 0;
        uint8_t body[3] = {7, 8, 9};
        uint8_t f[16];
        frame(f, D2K_CMD_DEL_ADDR, body, sizeof body);
        CHECK(write(cli, f, 9) == 9, "команда не записалась");
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == 1, "команда не разобрана");
        CHECK(n_got == 1 && got[0].type == D2K_CMD_DEL_ADDR, "тип команды не тот");
        CHECK(n_got == 1 && got[0].len == 3 && got[0].body[2] == 9,
              "тело команды не то");
    }

    /* --- команда по кускам ------------------------------------------------------
     * Поток не обязан приходить кадрами. Разбор, который на это надеется,
     * ломается ровно тогда, когда команда большая — то есть когда в ней план. */
    {
        n_got = 0;
        uint8_t body[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t f[16];
        frame(f, D2K_CMD_SET_ADDR, body, sizeof body);
        CHECK(write(cli, f, 3) == 3, "первый кусок не записался");
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == 0, "полкадра разобрано как кадр");
        CHECK(n_got == 0, "обратный вызов случился на половине кадра");
        CHECK(write(cli, f + 3, 11) == 11, "второй кусок не записался");
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == 1, "кадр не собрался из кусков");
        CHECK(n_got == 1 && got[0].len == 8, "собранный кадр повреждён");
    }

    /* --- два кадра в одной записи ------------------------------------------- */
    {
        n_got = 0;
        uint8_t a[2] = {0x11, 0x22}, b[1] = {0x33};
        uint8_t f[16];
        frame(f, D2K_CMD_DEL_ADDR, a, sizeof a);
        frame(f + 8, D2K_CMD_CLEAR, b, sizeof b);
        CHECK(write(cli, f, 8 + 7) == 15, "пара кадров не записалась");
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == 2, "из двух кадров разобран не два");
        CHECK(n_got == 2 && got[1].type == D2K_CMD_CLEAR, "второй кадр не тот");
    }

    /* --- врущая длина рвёт соединение ---------------------------------------
     * Идти дальше по потоку нельзя: следующий заголовок пришлось бы искать по
     * выдуманному смещению.                                                   */
    {
        uint8_t f[8];
        f[0] = 0xFF; f[1] = 0xFF; f[2] = 0xFF; f[3] = 0xFF;
        f[4] = 0; f[5] = 1;
        CHECK(write(cli, f, 6) == 6, "кадр с врущей длиной не записался");
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == -1, "врущая длина не порвала соединение");
        CHECK(d2k_ctl_peer_fd(c) == -1, "собеседник остался после врущей длины");
        close(cli);
    }

    /* --- исчезнувший собеседник ---------------------------------------------- */
    {
        cli = dial();
        d2k_ctl_accept(c);
        CHECK(d2k_ctl_peer_fd(c) >= 0, "переподключение не принято");
        close(cli);
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == -1, "уход собеседника не замечен");
        CHECK(d2k_ctl_peer_fd(c) == -1, "собеседник числится живым после ухода");
    }

    /* --- слишком большое событие теряется, а не переполняет буфер ------------ */
    {
        cli = dial();
        d2k_ctl_accept(c);
        static uint8_t huge[D2K_CTL_FRAME_MAX];
        memset(huge, 0x5A, sizeof huge);
        uint64_t before = d2k_ctl_dropped(c);
        d2k_ctl_event(c, D2K_EV_STATS, huge, sizeof huge);
        CHECK(d2k_ctl_dropped(c) == before + 1, "великан не посчитан потерянным");
        close(cli);
    }

    /* --- текст причины выводится из кода, а не наоборот ---------------------- */
    {
        CHECK(strcmp(d2k_suspect_text(D2K_SUSPECT_RST),
                     "сброс в ответ на приветствие") == 0, "текст причины RST не тот");
        CHECK(d2k_suspect_text(200) != NULL, "неизвестный код без текста");
    }

    d2k_ctl_close(c);

    /* Файл сокета обязан исчезнуть: иначе следующий запуск наткнётся на него. */
    CHECK(access(SOCK, F_OK) != 0, "файл сокета остался после закрытия");

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("управление: все проверки прошли\n");
    return 0;
}
