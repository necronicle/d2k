/* d2kc и версия провода: смешанная пара останавливается на приветствии.
 *
 * Проверка ТОЧНОГО совпадения: v7 (до задачи 19 SET_NAME_PROBE не нёс trial
 * ID) и будущая v+1 отвергаются с ненулевым кодом, своя версия — принимается
 * (процесс продолжает работать, пока его не остановят). Запускает "./d2kc"
 * подпроцессом, как test_d2kask запускает "./d2kask". */
#define _XOPEN_SOURCE 700
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "d2k_ctl.h"
#include "d2k_ctlsrv.h"

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { printf("ПРОВАЛ: %s\n", (msg)); fails++; } } while (0)

/* Возвращает: код выхода d2kc (>=0), или -1 если через wait_ms он ещё жив
   (тогда процесс убит). out — stderr d2kc. */
static int run_with_greeting(unsigned version, long wait_ms, const uint8_t *extra, size_t extra_len,
                             char *out, size_t outcap) {
    /* Имя каталога уникально на запуск: живой d2kc оставляет рядом с каталогом
       свои файлы, и повтор той же версии упирался бы в EEXIST. */
    static int seq;
    char dir[80];
    snprintf(dir, sizeof dir, "/tmp/d2kc-proto-%ld-%u-%d", (long)getpid(), version, ++seq);
    if (mkdir(dir, 0700) != 0) { return -2; }
    char sock_path[108], cat_path[128];
    snprintf(sock_path, sizeof sock_path, "%s/s", dir);
    snprintf(cat_path, sizeof cat_path, "%s/catalog.json", dir);

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", sock_path);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(lfd, 1) != 0) {
        if (lfd >= 0) close(lfd);
        rmdir(dir);
        return -2;
    }
    int errp[2];
    if (pipe(errp) != 0) { close(lfd); unlink(sock_path); rmdir(dir); return -2; }
    pid_t pid = fork();
    if (pid == 0) {
        dup2(errp[1], 2);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) dup2(devnull, 1);
        close(errp[0]);
        execl("./d2kc", "d2kc", "--control", sock_path, "--catalog", cat_path, (char *)NULL);
        _exit(127);
    }
    close(errp[1]);

    int rc = -2;
    struct pollfd p = { lfd, POLLIN, 0 };
    if (pid > 0 && poll(&p, 1, 15000) == 1) {
        int c = accept(lfd, NULL, NULL);
        if (c >= 0) {
            /* Приветствие несёт и release ID датапата: d2kc принимает только
               свой выпуск (задача 5). Без него и «своя» версия — чужая. */
            const size_t idlen = strlen(D2K_RELEASE_ID);
            uint8_t f[6 + D2K_KEY_WIRE_LEN + 7 + 64];
            memset(f, 0, sizeof f);
            uint32_t plen = (uint32_t)(2 + D2K_KEY_WIRE_LEN + 7 + idlen);
            f[0] = (uint8_t)(plen >> 24); f[1] = (uint8_t)(plen >> 16);
            f[2] = (uint8_t)(plen >> 8);  f[3] = (uint8_t)plen;
            f[4] = (uint8_t)(D2K_EV_PROTO >> 8); f[5] = (uint8_t)D2K_EV_PROTO;
            f[6] = 4;
            f[6 + D2K_KEY_WIRE_LEN] = (uint8_t)(version >> 8);
            f[6 + D2K_KEY_WIRE_LEN + 1] = (uint8_t)version;
            f[6 + D2K_KEY_WIRE_LEN + 4] = 0x05; f[6 + D2K_KEY_WIRE_LEN + 5] = 0xdc; /* 1500 */
            f[6 + D2K_KEY_WIRE_LEN + 6] = (uint8_t)idlen;
            memcpy(f + 6 + D2K_KEY_WIRE_LEN + 7, D2K_RELEASE_ID, idlen);
            (void)!write(c, f, 4 + plen);
            /* Следом — произвольный кадр «датапата» (например, ACK старого
               формата): d2kc обязан его не принять и сказать об этом вслух. */
            if (extra_len) { (void)!write(c, extra, extra_len); }
            int status = 0;
            long waited = 0;
            pid_t w = 0;
            while (waited < wait_ms && (w = waitpid(pid, &status, WNOHANG)) == 0) {
                /* Командам d2kc нужен читатель: иначе он встанет в write. */
                uint8_t sink[4096];
                struct pollfd cp = { c, POLLIN, 0 };
                /* Закрытый d2kc сокет даёт POLLIN мгновенно (EOF): без паузы
                   счётчик «10 мс» пробегал весь срок за микросекунды, раньше,
                   чем вышедший d2kc становился виден waitpid (Linux, CI). */
                if (poll(&cp, 1, 10) == 1 && read(c, sink, sizeof sink) <= 0) {
                    struct timespec pause = { 0, 10000000 };
                    nanosleep(&pause, NULL);
                }
                waited += 10;
            }
            if (w == pid) {
                rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
            } else {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                rc = -1;
            }
            close(c);
        }
    }
    if (rc == -2 && pid > 0) { kill(pid, SIGKILL); waitpid(pid, NULL, 0); }
    size_t got = 0;
    ssize_t n;
    while (got + 1 < outcap && (n = read(errp[0], out + got, outcap - 1 - got)) > 0) {
        got += (size_t)n;
    }
    out[got] = '\0';
    close(errp[0]);
    close(lfd);
    unlink(sock_path);
    unlink(cat_path);
    {   /* живой d2kc пишет сердцебиение рядом с каталогом */
        char live[160]; snprintf(live, sizeof live, "%s/live.json", dir); unlink(live);
    }
    rmdir(dir);
    return rc;
}

int main(void) {
    /* Offline release gate must agree with the actual control handshake. */
    pid_t self = fork();
    if (self == 0) {
        execl("./d2kc", "d2kc", "--self-check", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    CHECK(self > 0 && waitpid(self, &status, 0) == self &&
          WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "offline self-check disagrees with control protocol");
    signal(SIGPIPE, SIG_IGN);
    char err[4096];
    int rc = run_with_greeting(7, 10000, NULL, 0, err, sizeof err);
    CHECK(rc == 1, "d2kc принял приветствие v7 (SET_NAME_PROBE без trial ID)");
    CHECK(strstr(err, "несовместимое приветствие") != NULL,
          "отказ d2kc на v7 не назван несовместимым приветствием");
    rc = run_with_greeting(D2K_CTL_PROTO_VERSION + 1, 10000, NULL, 0, err, sizeof err);
    CHECK(rc == 1, "d2kc принял приветствие будущей версии — сверка не точная");
    rc = run_with_greeting(D2K_CTL_PROTO_VERSION, 500, NULL, 0, err, sizeof err);
    CHECK(rc == -1, "d2kc не работает со своей версией провода");
    {   /* Своя версия, но следом ACK снятия адресного опыта СТАРОГО формата
           (успех без trial ID, v22). По контракту (d2k_stuntrial.h) такой ACK
           ничего не освобождает; d2kc его отвергает — и обязан не молчать:
           иначе «зависший» cleanup невозможно отличить от потерянного ACK. */
        uint8_t ack[6 + D2K_KEY_WIRE_LEN + 4];
        memset(ack, 0, sizeof ack);
        uint32_t plen = (uint32_t)(2 + D2K_KEY_WIRE_LEN + 4);
        ack[0] = (uint8_t)(plen >> 24); ack[1] = (uint8_t)(plen >> 16);
        ack[2] = (uint8_t)(plen >> 8);  ack[3] = (uint8_t)plen;
        ack[4] = (uint8_t)(D2K_EV_ACK >> 8); ack[5] = (uint8_t)D2K_EV_ACK;
        ack[6] = 4;
        ack[6 + D2K_KEY_WIRE_LEN] = (uint8_t)(D2K_CMD_DEL_ADDR_PROBE >> 8);
        ack[6 + D2K_KEY_WIRE_LEN + 1] = (uint8_t)D2K_CMD_DEL_ADDR_PROBE;
        ack[6 + D2K_KEY_WIRE_LEN + 2] = 1; /* ok */
        rc = run_with_greeting(D2K_CTL_PROTO_VERSION, 500, ack, sizeof ack, err, sizeof err);
        CHECK(rc == -1, "короткий ACK старого формата уронил d2kc вместо того, чтобы быть отвергнутым");
        CHECK(strstr(err, "без его идентификатора") != NULL,
              "d2kc молча проглотил неразобранный ACK — причина отказа не названа");
    }
    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("d2kc: сверка версии провода — все проверки прошли\n");
    return 0;
}
