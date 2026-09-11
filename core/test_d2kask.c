/* test_d2kask.c — проверки командной утилиты d2kask (задача 5в).
 *
 * ЧЁРНЫЙ ЯЩИК, И ЭТО НАМЕРЕННО. d2kask.c — CLI с main(), тем же приёмом, что
 * ctlprobe.c/planlab.c/d2kd.c в этом дереве: файл с main() собирается в СВОЙ
 * бинарник и не превращается во второй объектник для линковки с чужим
 * main() в отдельном тестовом бинарнике. Смысл её разбора аргументов и
 * печати проверяется тем же способом, что смысл протокола в test_link.c —
 * настоящим запуском настоящего бинарника, а не чтением её кода на глаз.
 *
 * ЧАСТЬ A — разбор аргументов, БЕЗ ctlprobe и БЕЗ сети: все проверки этого
 * блока отказывают ДО d2k_link_open, поэтому им сокет не нужен вовсе.
 * Каждая проверяет ОДНУ причину отказа по отдельной, отличимой подстроке —
 * не "упало", а "упало вот почему".
 *
 * ЧАСТЬ B — отказ среды (сокет не открылся) — тоже без ctlprobe, путь к
 * сокету заведомо не существует.
 *
 * ЧАСТЬ C — сквозные проверки печати против НАСТОЯЩЕГО ctlprobe и петли-
 * мишени test_stand.h, тем же приёмом, что test_compose.c (probe/driver_run/
 * stand): d2k_props_ask там уже проверена по существу (все YES/NO/UNKNOWN
 * пути) — здесь проверяется НАДСТРОЙКА, которую добавляет именно d2kask:
 * различение "вопрос не задан" от "задан, но без однозначного ответа" в
 * ПЕЧАТИ, а не в векторе. Сценарии C1/C2/C3 — те же b3/b1/b4 из
 * test_compose.c, но наблюдаемые через stdout бинарника, а не через
 * возвращённую структуру.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "d2k_hello.h"
#include "d2k_link.h"
#include "test_stand.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* --------------------------------------------------------------------
 * Запуск d2kask как чёрного ящика: argv, захват stdout/stderr/кода выхода.
 * -------------------------------------------------------------------- */

typedef struct {
    char out[16384];
    char errbuf[4096];
    int  exit_code;
} run_result;

/* argv — NULL-терминированный массив, argv[0] игнорируется execv (там всё
 * равно путь к бинарнику), но по соглашению это имя программы. Читает оба
 * потока через poll ПАРАЛЛЕЛЬНО — раздельным чтением "сначала out, потом
 * err" рисковали бы дедлоком: ребёнок мог заполнить один канал и заблокироваться
 * на записи в него, ожидая, что кто-то читает, пока родитель читает другой. */
static int run_d2kask(char *const argv[], run_result *r) {
    memset(r, 0, sizeof *r);
    int outpipe[2], errpipe[2];
    if (pipe(outpipe) != 0) { return -1; }
    if (pipe(errpipe) != 0) { close(outpipe[0]); close(outpipe[1]); return -1; }

    pid_t pid = fork();
    if (pid < 0) {
        close(outpipe[0]); close(outpipe[1]); close(errpipe[0]); close(errpipe[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(outpipe[1], STDOUT_FILENO);
        dup2(errpipe[1], STDERR_FILENO);
        close(outpipe[0]); close(outpipe[1]);
        close(errpipe[0]); close(errpipe[1]);
        /* D2KASK_BIN — переопределение пути к бинарнику, которое использует
           только цель `san` в Makefile: обычный прогон проверяет "./d2kask"
           (собранный вместе с этим тестом обычной целью), санитайзерный —
           отдельно собранную под тем же santflags копию, иначе san ловил бы
           переполнения буфера ТЕСТА, но не самого d2kask. */
        const char *bin = getenv("D2KASK_BIN");
        execv(bin ? bin : "./d2kask", argv);
        _exit(127); /* execv не вернулся бы при успехе */
    }
    close(outpipe[1]);
    close(errpipe[1]);

    size_t outn = 0, errn = 0;
    int outdone = 0, errdone = 0;
    while (!outdone || !errdone) {
        struct pollfd pfd[2];
        nfds_t n = 0;
        int oi = -1, ei = -1;
        if (!outdone) { pfd[n].fd = outpipe[0]; pfd[n].events = POLLIN; pfd[n].revents = 0; oi = (int)n; n++; }
        if (!errdone) { pfd[n].fd = errpipe[0]; pfd[n].events = POLLIN; pfd[n].revents = 0; ei = (int)n; n++; }
        int pr = poll(pfd, n, -1);
        if (pr < 0) {
            if (errno == EINTR) { continue; }
            break;
        }
        if (oi >= 0 && (pfd[oi].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t got = (outn < sizeof r->out - 1)
                              ? read(outpipe[0], r->out + outn, sizeof r->out - 1 - outn)
                              : 0;
            if (got > 0) { outn += (size_t)got; } else { outdone = 1; }
        }
        if (ei >= 0 && (pfd[ei].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t got = (errn < sizeof r->errbuf - 1)
                              ? read(errpipe[0], r->errbuf + errn, sizeof r->errbuf - 1 - errn)
                              : 0;
            if (got > 0) { errn += (size_t)got; } else { errdone = 1; }
        }
    }
    r->out[outn] = '\0';
    r->errbuf[errn] = '\0';
    close(outpipe[0]);
    close(errpipe[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    r->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return 0;
}

static int contains(const char *hay, const char *needle) {
    return hay && strstr(hay, needle) != NULL;
}

static void drain_all_events(const char *sock_path);

/* --------------------------------------------------------------------
 * ЧАСТЬ A — разбор аргументов, без сети.
 * -------------------------------------------------------------------- */

static void part_a(void) {
    run_result r;

    /* A1: без аргументов вовсе — использование, а не молчаливое умолчание. */
    {
        char *argv[] = { "d2kask", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A1: запуск не удался");
        CHECK(r.exit_code == 2, "A1: без аргументов обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "использование: d2kask"), "A1: нет строки использования");
    }

    /* A2: нет --control. */
    {
        char *argv[] = { "d2kask", "--ip", "127.0.0.1", "--sni", "x.example",
                         "--hello-hex", "/tmp/does-not-matter", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A2: запуск не удался");
        CHECK(r.exit_code == 2, "A2: без --control обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "обязателен --control"), "A2: причина не названа");
    }

    /* A3: нет --ip. */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--sni", "x.example",
                         "--hello-hex", "/tmp/does-not-matter", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A3: запуск не удался");
        CHECK(r.exit_code == 2, "A3: без --ip обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "обязателен --ip"), "A3: причина не названа");
    }

    /* A4: нет --sni. */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--hello-hex", "/tmp/does-not-matter", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A4: запуск не удался");
        CHECK(r.exit_code == 2, "A4: без --sni обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "обязателен --sni"), "A4: причина не названа");
    }

    /* A5: ни --hello-hex, ни --arm-wait-ms — оба способа молчат по-разному,
     * отсутствие обоих обязано быть названо явно, а не выбрать умолчание. */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A5: запуск не удался");
        CHECK(r.exit_code == 2, "A5: без обоих способов обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "нужен один способ снять приветствие"), "A5: причина не названа");
    }

    /* A6: --hello-hex и --arm-wait-ms одновременно — взаимоисключающие
     * аргументы не молчат (это то же правило, что и в вопроснике QUIC). */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", "/tmp/does-not-matter",
                         "--arm-wait-ms", "1000", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A6: запуск не удался");
        CHECK(r.exit_code == 2, "A6: оба способа сразу обязаны отказать кодом 2");
        CHECK(contains(r.errbuf, "взаимоисключающие"), "A6: причина не названа");
    }

    /* A7: нечётная длина шестнадцатеричной строки в файле. */
    {
        const char *path = "/tmp/d2kask-test-odd.hex";
        FILE *f = fopen(path, "w");
        CHECK(f != NULL, "A7: файл не создался");
        if (f) { fputs("abc", f); fclose(f); }
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", (char *)path, NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A7: запуск не удался");
        CHECK(r.exit_code == 2, "A7: нечётная длина обязана отказать кодом 2");
        CHECK(contains(r.errbuf, "нечётное число шестнадцатеричных цифр"), "A7: причина не названа");
        unlink(path);
    }

    /* A8: недопустимый символ в hex-файле — не отбрасывается молча. */
    {
        const char *path = "/tmp/d2kask-test-badchar.hex";
        FILE *f = fopen(path, "w");
        CHECK(f != NULL, "A8: файл не создался");
        if (f) { fputs("abgh", f); fclose(f); }
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", (char *)path, NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A8: запуск не удался");
        CHECK(r.exit_code == 2, "A8: недопустимый символ обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "недопустимый символ"), "A8: причина не названа");
        unlink(path);
    }

    /* A9: --control-hex и --control-sni одновременно. */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", "/tmp/does-not-matter",
                         "--control-hex", "/tmp/does-not-matter2", "--control-sni", "y.example", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A9: запуск не удался");
        CHECK(r.exit_code == 2, "A9: оба control-способа сразу обязаны отказать кодом 2");
        CHECK(contains(r.errbuf, "--control-hex и --control-sni взаимоисключающие"), "A9: причина не названа");
    }

    /* A10: --control-sni без --arm-wait-ms (т.е. в режиме --hello-hex) —
     * армировать ловушку нечем без потолка ожидания. */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", "/tmp/does-not-matter",
                         "--control-sni", "y.example", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A10: запуск не удался");
        CHECK(r.exit_code == 2, "A10: control-sni без arm-wait-ms обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "требует --arm-wait-ms"), "A10: причина не названа");
    }

    /* A11: неизвестный флаг. */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", "/tmp/does-not-matter",
                         "--frobnicate", "1", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A11: запуск не удался");
        CHECK(r.exit_code == 2, "A11: неизвестный флаг обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "неизвестный аргумент: --frobnicate"), "A11: причина не названа");
    }

    /* A12: --port не число 1..65535. */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", "/tmp/does-not-matter",
                         "--port", "0", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A12: запуск не удался");
        CHECK(r.exit_code == 2, "A12: --port=0 обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "--port не число"), "A12: причина не названа");
    }
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", "/tmp/does-not-matter",
                         "--port", "abc", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A12b: запуск не удался");
        CHECK(r.exit_code == 2, "A12b: --port=abc обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "--port не число"), "A12b: причина не названа");
    }

    /* A13: --mark не число. */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", "/tmp/does-not-matter",
                         "--mark", "abc", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A13: запуск не удался");
        CHECK(r.exit_code == 2, "A13: --mark=abc обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "--mark не число"), "A13: причина не названа");
    }

    /* A14: файл --hello-hex не существует — отказ отличим от "внутри плохой hex". */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", "/tmp/d2kask-does-not-exist.hex", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A14: запуск не удался");
        CHECK(r.exit_code == 2, "A14: несуществующий файл обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "открыть не удалось"), "A14: причина не названа");
    }

    /* A15: --arm-wait-ms не положительное целое. */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--arm-wait-ms", "0", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A15: запуск не удался");
        CHECK(r.exit_code == 2, "A15: --arm-wait-ms=0 обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "--arm-wait-ms не положительное целое"), "A15: причина не названа");
    }
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--arm-wait-ms", "-5", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A15b: запуск не удался");
        CHECK(r.exit_code == 2, "A15b: --arm-wait-ms=-5 обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "--arm-wait-ms не положительное целое"), "A15b: причина не названа");
    }

    /* A16: флаг без значения — не читает argv за границей, отказывает явно. */
    {
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A16: запуск не удался");
        CHECK(r.exit_code == 2, "A16: флаг без значения обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "--sni требует значения"), "A16: причина не названа");
    }

    /* A17: hex-файл пуст (0 шестнадцатеричных цифр). */
    {
        const char *path = "/tmp/d2kask-test-empty.hex";
        FILE *f = fopen(path, "w");
        CHECK(f != NULL, "A17: файл не создался");
        if (f) { fputs("# только комментарий\n", f); fclose(f); }
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", (char *)path, NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A17: запуск не удался");
        CHECK(r.exit_code == 2, "A17: пустой снимок обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "файл пуст"), "A17: причина не названа");
        unlink(path);
    }

    /* A18: hex-файл длиннее потолка формы приветствия (2048 байт = 4096 цифр). */
    {
        const char *path = "/tmp/d2kask-test-toolong.hex";
        FILE *f = fopen(path, "w");
        CHECK(f != NULL, "A18: файл не создался");
        if (f) {
            for (int i = 0; i < 2100; i++) { fputs("41", f); }
            fclose(f);
        }
        char *argv[] = { "d2kask", "--control", "/tmp/x.sock", "--ip", "127.0.0.1",
                         "--sni", "x.example", "--hello-hex", (char *)path, NULL };
        CHECK(run_d2kask(argv, &r) == 0, "A18: запуск не удался");
        CHECK(r.exit_code == 2, "A18: слишком длинный снимок обязан отказать кодом 2");
        CHECK(contains(r.errbuf, "больше потолка формы приветствия"), "A18: причина не названа");
        unlink(path);
    }
}

/* --------------------------------------------------------------------
 * ЧАСТЬ B — отказ среды: сокет не открылся. Аргументы синтаксически
 * годные, --hello-hex указывает на настоящий (валидный) снимок, чтобы
 * отказ случился именно на d2k_link_open, а не раньше.
 * -------------------------------------------------------------------- */

static void part_b(void) {
    run_result r;
    char *argv[] = { "d2kask", "--control", "/tmp/d2kask-definitely-absent.sock",
                     "--ip", "127.0.0.1", "--sni", "x.example",
                     "--arm-wait-ms", "100", NULL };
    CHECK(run_d2kask(argv, &r) == 0, "B: запуск не удался");
    CHECK(r.exit_code == 1, "B: отказ связи обязан быть кодом 1, а не 2 и не 0");
    CHECK(contains(r.errbuf, "не удалось открыть управляющий сокет"), "B: причина не названа");
}

/* --------------------------------------------------------------------
 * ЧАСТЬ C — сквозные проверки печати, против настоящего ctlprobe.
 * -------------------------------------------------------------------- */

static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[b[i] >> 4];
        out[2 * i + 1] = digits[b[i] & 0xFu];
    }
    out[2 * n] = '\0';
}

/* Собирает НАСТОЯЩЕЕ приветствие (профиль LEGACY, hello.c) с заданным SNI и
 * пишет его hex-строкой в файл path — тем же путём, каким d2k_props_ask сам
 * находит имя (d2k_hello_sni), а не самодельными байтами (см. шапку
 * d2k_meas.h про то, чего стоил самодельный hello 06.09.2026). */
static int write_hello_hex_file(const char *path, const char *sni) {
    uint8_t buf[2048];
    size_t len = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_LEGACY, sni, buf, sizeof buf, &len) != 0) {
        return -1;
    }
    char hex[2 * sizeof buf + 1];
    to_hex(buf, len, hex);
    FILE *f = fopen(path, "w");
    if (!f) { return -1; }
    fputs(hex, f);
    fclose(f);
    return 0;
}

/* --- стенд ctlprobe: те же probe_start/probe_say/probe_stop/dial_retry, что
 * test_link.c/test_compose.c (см. их шапки про то, почему это две трубы
 * плюс отдельный настоящий AF_UNIX-сокет). d2kask держит сокет САМ — этому
 * тесту он не нужен, только трубы, которыми стенд управляется построчно. */
typedef struct {
    pid_t pid;
    int   in_fd;
    FILE *out;
} probe;

static void probe_write_line(probe *p, const char *line) {
    char buf[700];
    int n = snprintf(buf, sizeof buf, "%s\n", line);
    if (n > 0) { (void)write(p->in_fd, buf, (size_t)n); }
}

static const char *probe_say(probe *p, const char *line) {
    static char resp[512];
    probe_write_line(p, line);
    if (!fgets(resp, sizeof resp, p->out)) {
        resp[0] = '\0';
        return resp;
    }
    resp[strcspn(resp, "\r\n")] = '\0';
    return resp;
}

static int probe_start(probe *p, const char *sock_path) {
    if (access("../datapath/ctlprobe", X_OK) != 0) {
        fprintf(stderr, "стенд не собран (%s); нужен `make -C datapath ctlprobe`\n", strerror(errno));
        return -1;
    }
    int inpipe[2], outpipe[2];
    if (pipe(inpipe) != 0 || pipe(outpipe) != 0) {
        fprintf(stderr, "pipe: %s\n", strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        dup2(inpipe[0], STDIN_FILENO);
        dup2(outpipe[1], STDOUT_FILENO);
        close(inpipe[0]); close(inpipe[1]);
        close(outpipe[0]); close(outpipe[1]);
        execl("../datapath/ctlprobe", "ctlprobe", sock_path, (char *)NULL);
        _exit(127);
    }
    close(inpipe[0]);
    close(outpipe[1]);
    p->pid = pid;
    p->in_fd = inpipe[1];
    p->out = fdopen(outpipe[0], "r");
    if (!p->out) {
        fprintf(stderr, "fdopen: %s\n", strerror(errno));
        return -1;
    }
    char line[512];
    if (!fgets(line, sizeof line, p->out)) {
        fprintf(stderr, "стенд молчит на старте\n");
        return -1;
    }
    line[strcspn(line, "\r\n")] = '\0';
    if (strcmp(line, "готов") != 0) {
        fprintf(stderr, "стенд не поздоровался: \"%s\"\n", line);
        return -1;
    }
    return 0;
}

static void probe_stop(probe *p, const char *sock_path) {
    if (p->in_fd >= 0) {
        probe_write_line(p, "quit");
        close(p->in_fd);
    }
    if (p->out) { fclose(p->out); }
    if (p->pid > 0) { (void)waitpid(p->pid, NULL, 0); }
    unlink(sock_path);
}

/* Ведущий поток: пока d2kask (дочерний процесс) синхронно блокируется
 * внутри d2k_props_ask (SET_NAME -> ack -> одно обращение -> ждать обмен),
 * кто-то обязан ПАРАЛЛЕЛЬНО дать ctlprobe команды "hello"/"reply",
 * изображающие датапат, который увидел ту же цель и её ответ — без этого
 * событие обмена взяться неоткуда (см. driver_run в test_compose.c, тот же
 * приём и та же причина). pre_delay_ms — тот же запас, что там (300мс на
 * АФ_UNIX-обмен и TCP-петлю на локалхосте, обе — миллисекунды). */
typedef struct {
    probe *p;
    const char *name;
    const int *replies;
    size_t n;
    unsigned pre_delay_ms;
} driver_args;

static void nap_ms(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void *driver_run(void *arg) {
    driver_args *d = (driver_args *)arg;
    for (size_t i = 0; i < d->n; i++) {
        nap_ms((int)d->pre_delay_ms);
        char cmd[200];
        snprintf(cmd, sizeof cmd, "hello %s", d->name);
        (void)probe_say(d->p, cmd);
        if (d->replies[i] >= 0) {
            snprintf(cmd, sizeof cmd, "reply %d", d->replies[i]);
            (void)probe_say(d->p, cmd);
        }
    }
    return NULL;
}

/* Запускает d2kask в фоне (тем же fork, но БЕЗ ожидания завершения здесь —
 * читать stdout начинаем ПОСЛЕ старта ведущего потока, иначе он попытался
 * бы поговорить с ctlprobe раньше, чем d2kask вообще поставил план). Вызов
 * run_d2kask() уже блокирует до завершения ребёнка изнутри (читает трубы до
 * EOF) — здесь она просто вызывается из ОТДЕЛЬНОГО потока теста, пока
 * driver_run работает в СВОЁМ, тоже отдельном потоке; join обоих потоков
 * ниже дожидается настоящего завершения. */
typedef struct {
    char *const *argv;
    run_result *out;
} runner_args;

static void *runner_thread(void *arg) {
    runner_args *ra = arg;
    run_d2kask(ra->argv, ra->out);
    return NULL;
}

static void part_c(void) {
    char sock_path[64];
    snprintf(sock_path, sizeof sock_path, "/tmp/d2k-core-d2kask-%d.sock", (int)getpid());
    probe p;
    memset(&p, 0, sizeof p);
    p.in_fd = -1;
    if (probe_start(&p, sock_path) != 0) {
        printf("ПРОВАЛ: стенд ctlprobe не поднялся — часть C пропущена\n");
        fails++;
        return;
    }

    struct stand st;
    memset(&st, 0, sizeof st);
    uint16_t stand_port = stand_start(&st, 0); /* mode 0 — отвечает всегда, см. test_stand.h */

    /* --- C1 (мирроит b3 test_compose.c): нет control — вопросы [2]/[5]
     * пропускаются целиком, оставшиеся три промахиваются (реплики 22,22,22),
     * итоговый вектор весь "не измерено", но КАЖДЫЙ из пяти напечатан
     * РАЗЛИЧИМО: [2]/[5] как "спрошен: нет" (причина control), [1]/[3]/[4]
     * как "спрошен: да" / "ответ: не измерено". ------------------------- */
    {
        const char *hexpath = "/tmp/d2kask-test-c1.hex";
        CHECK(write_hello_hex_file(hexpath, "c1.example") == 0, "C1: снимок не собрался");

        char port_s[16]; snprintf(port_s, sizeof port_s, "%u", (unsigned)stand_port);
        char *argv[] = { "d2kask", "--control", sock_path, "--ip", "127.0.0.1",
                         "--port", port_s, "--sni", "c1.example",
                         "--hello-hex", (char *)hexpath, NULL };

        int replies[] = { 22, 22, 22 };
        driver_args da = { &p, "c1.example", replies, 3, 300 };
        pthread_t dth;
        CHECK(pthread_create(&dth, NULL, driver_run, &da) == 0, "C1: ведущий поток не запустился");

        run_result r;
        runner_args ra = { argv, &r };
        pthread_t rth;
        CHECK(pthread_create(&rth, NULL, runner_thread, &ra) == 0, "C1: d2kask не запустился");
        pthread_join(rth, NULL);
        pthread_join(dth, NULL);

        CHECK(r.exit_code == 0, "C1: прогон обязан завершиться кодом 0 (честный пустой результат — не отказ)");
        CHECK(contains(r.out, "[2/5]") && contains(r.out, "[5/5]"), "C1: не нашлись заголовки вопросов 2/5");

        /* [2/5] и [5/5] — НЕ заданы, причина про control. */
        {
            const char *p2 = strstr(r.out, "[2/5]");
            const char *p3 = strstr(r.out, "[3/5]");
            CHECK(p2 && p3 && p2 < p3, "C1: вопрос 2 не нашёлся перед вопросом 3");
            CHECK(p2 && strstr(p2, "спрошен: нет") && strstr(p2, "спрошен: нет") < p3,
                  "C1: вопрос 2 обязан быть НЕ ЗАДАН");
            CHECK(p2 && strstr(p2, "нет control-приветствия") && strstr(p2, "нет control-приветствия") < p3,
                  "C1: причина непоказана верно для вопроса 2");
        }
        {
            const char *p5 = strstr(r.out, "[5/5]");
            CHECK(p5 && strstr(p5, "спрошен: нет"), "C1: вопрос 5 обязан быть НЕ ЗАДАН");
            CHECK(p5 && strstr(p5, "нет control-приветствия"), "C1: причина непоказана верно для вопроса 5");
        }
        /* [1/5], [3/5], [4/5] — заданы, но без однозначного ответа. */
        {
            const char *p1 = strstr(r.out, "[1/5]");
            const char *p2 = strstr(r.out, "[2/5]");
            CHECK(p1 && p2 && strstr(p1, "спрошен: да") && strstr(p1, "спрошен: да") < p2,
                  "C1: вопрос 1 обязан быть ЗАДАН");
            CHECK(p1 && strstr(p1, "ответ: не измерено") && strstr(p1, "ответ: не измерено") < p2,
                  "C1: вопрос 1 обязан остаться не измеренным (промах, не отказ)");
        }
        /* Печать различает "не задан" от "задан, но без ответа" — они
           обязаны быть разными подстроками, а не общим "не измерено". */
        CHECK(contains(r.out, "спрошен: да") && contains(r.out, "спрошен: нет"),
              "C1: обе ветки печати обязаны встретиться в одном прогоне");
        /* Полный промах — предупреждение про оставшийся план обязано быть. */
        CHECK(contains(r.out, "ни один зонд не прошёл"), "C1: не напечатан долг про оставшийся план");

        unlink(hexpath);
        drain_all_events(sock_path); /* см. выше: очищаем перед следующим блоком */
    }

    /* --- C2 (мирроит b1): первый вопрос проходит немедленно — печатается
     * ЗАДАН+ответ, остальные четыре — НЕ ЗАДАН с причиной "опрос
     * остановился раньше". ------------------------------------------------ */
    {
        const char *hexpath = "/tmp/d2kask-test-c2.hex";
        const char *ctrlpath = "/tmp/d2kask-test-c2-control.hex";
        CHECK(write_hello_hex_file(hexpath, "c2.example") == 0, "C2: снимок не собрался");
        CHECK(write_hello_hex_file(ctrlpath, "c2-control.example") == 0, "C2: control-снимок не собрался");

        char port_s[16]; snprintf(port_s, sizeof port_s, "%u", (unsigned)stand_port);
        char *argv[] = { "d2kask", "--control", sock_path, "--ip", "127.0.0.1",
                         "--port", port_s, "--sni", "c2.example",
                         "--hello-hex", (char *)hexpath,
                         "--control-hex", (char *)ctrlpath, NULL };

        int replies[] = { 23 }; /* прикладные данные — проходит с первого раза */
        driver_args da = { &p, "c2.example", replies, 1, 300 };
        pthread_t dth;
        CHECK(pthread_create(&dth, NULL, driver_run, &da) == 0, "C2: ведущий поток не запустился");

        run_result r;
        runner_args ra = { argv, &r };
        pthread_t rth;
        CHECK(pthread_create(&rth, NULL, runner_thread, &ra) == 0, "C2: d2kask не запустился");
        pthread_join(rth, NULL);
        pthread_join(dth, NULL);

        CHECK(r.exit_code == 0, "C2: прогон обязан завершиться кодом 0");
        const char *p1 = strstr(r.out, "[1/5]");
        const char *p2 = strstr(r.out, "[2/5]");
        CHECK(p1 && p2, "C2: вопросы 1/2 не нашлись");
        if (p1 && p2) {
            CHECK(strstr(p1, "спрошен: да") && strstr(p1, "спрошен: да") < p2,
                  "C2: вопрос 1 обязан быть ЗАДАН");
            CHECK(strstr(p1, "ответ: нет") && strstr(p1, "ответ: нет") < p2,
                  "C2: вопрос 1 обязан получить ответ НЕТ");
        }
        for (const char *tag = "[2/5]"; ;) {
            const char *seg = strstr(r.out, tag);
            CHECK(seg != NULL, "C2: вопрос 2 не нашёлся");
            if (seg) {
                CHECK(strstr(seg, "спрошен: нет") != NULL, "C2: вопрос 2 обязан быть НЕ ЗАДАН");
                CHECK(strstr(seg, "опрос остановился раньше") != NULL,
                      "C2: причина обязана называть более ранний вопрос");
            }
            break;
        }
        CHECK(contains(r.out, "[3/5]") && contains(r.out, "[4/5]") && contains(r.out, "[5/5]"),
              "C2: вопросы 3-5 не нашлись");
        CHECK(!contains(r.out, "ни один зонд не прошёл"),
              "C2: долг про оставшийся план НЕ должен печататься, если что-то прошло");
        /* Ровно один выведенный план (перекрытие), и в нём есть seqovl. */
        CHECK(contains(r.out, "выведенные планы") && contains(r.out, "seqovl"),
              "C2: план перекрытия не выведен");

        unlink(hexpath);
        unlink(ctrlpath);
        drain_all_events(sock_path);
    }

    /* --- C3 (мирроит b4): четыре промаха, пятый (разбор протокола) проходит
     * последним — вопрос [4/5] обязан остаться "не измерено" (а не
     * приписать себе НЕТ, которое на самом деле пришло от [5/5]), а [5/5] —
     * ЗАДАН/ДА с примечанием про побочный эффект. ------------------------- */
    {
        const char *hexpath = "/tmp/d2kask-test-c3.hex";
        const char *ctrlpath = "/tmp/d2kask-test-c3-control.hex";
        CHECK(write_hello_hex_file(hexpath, "c3.example") == 0, "C3: снимок не собрался");
        CHECK(write_hello_hex_file(ctrlpath, "c3-control.example") == 0, "C3: control-снимок не собрался");

        char port_s[16]; snprintf(port_s, sizeof port_s, "%u", (unsigned)stand_port);
        char *argv[] = { "d2kask", "--control", sock_path, "--ip", "127.0.0.1",
                         "--port", port_s, "--sni", "c3.example",
                         "--hello-hex", (char *)hexpath,
                         "--control-hex", (char *)ctrlpath, NULL };

        int replies[] = { 22, 22, 22, 22, 23 };
        driver_args da = { &p, "c3.example", replies, 5, 300 };
        pthread_t dth;
        CHECK(pthread_create(&dth, NULL, driver_run, &da) == 0, "C3: ведущий поток не запустился");

        run_result r;
        runner_args ra = { argv, &r };
        pthread_t rth;
        CHECK(pthread_create(&rth, NULL, runner_thread, &ra) == 0, "C3: d2kask не запустился");
        pthread_join(rth, NULL);
        pthread_join(dth, NULL);

        CHECK(r.exit_code == 0, "C3: прогон обязан завершиться кодом 0");
        const char *p4 = strstr(r.out, "[4/5]");
        const char *p5 = strstr(r.out, "[5/5]");
        CHECK(p4 && p5 && p4 < p5, "C3: вопросы 4/5 не нашлись в порядке");
        if (p4 && p5) {
            CHECK(strstr(p4, "спрошен: да") && strstr(p4, "спрошен: да") < p5,
                  "C3: вопрос 4 обязан быть ЗАДАН (не пропущен по контролю)");
            CHECK(strstr(p4, "ответ: не измерено") && strstr(p4, "ответ: не измерено") < p5,
                  "C3: вопрос 4 обязан остаться не измеренным — ответ принадлежит вопросу 5, не ему");
            CHECK(strstr(p5, "спрошен: да") != NULL, "C3: вопрос 5 обязан быть ЗАДАН");
            CHECK(strstr(p5, "ответ: да") != NULL, "C3: вопрос 5 обязан получить ответ ДА");
            CHECK(strstr(p5, "снят вопрос [4/5]") != NULL,
                  "C3: побочный эффект на вопрос 4 обязан быть назван явно");
        }
        CHECK(!contains(r.out, "ни один зонд не прошёл"),
              "C3: долг про оставшийся план НЕ должен печататься, если что-то прошло");

        unlink(hexpath);
        unlink(ctrlpath);
        drain_all_events(sock_path);
    }

 /* тест не держит fd связи сам — см. шапку; вызов no-op, оставлен для симметрии сборки заголовков */
    probe_stop(&p, sock_path);
}

/* Осушает всё, что уже лежит (или придёт в течение недолгого времени) на
 * настоящем управляющем сокете, ОТКРЫВ его на короткое время сама тестовая
 * программа — иначе события одного блока (APPLIED/REFUSED от плана,
 * оставленного предыдущим сценарием, см. долг 1) просочились бы в разбор
 * следующего запуска d2kask как ЕГО СОБСТВЕННЫЕ события. d2kask каждый раз
 * открывает НОВОЕ подключение (accept на ctlprobe одно и то же), поэтому
 * очередь предыдущего клиента ему не видна — эта функция существует
 * ИСКЛЮЧИТЕЛЬНО чтобы не путать читателя теста, а не потому что она нужна
 * для правильности следующего сценария. */
static void drain_all_events(const char *sock_path) {
    char err[128];
    int fd = d2k_link_open(sock_path, err, sizeof err);
    if (fd < 0) { return; }
    d2k_ev ev;
    while (d2k_link_next(fd, &ev, 150, err, sizeof err) == 0) { }
    d2k_link_close(fd);
}

int main(void) {
    part_a();
    part_b();
    part_c();

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("d2kask: все проверки прошли\n");
    return 0;
}
