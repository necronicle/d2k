/* test_link.c — связь с датапатом (d2k_link.h), на настоящем ctlprobe.
 *
 * ctlprobe — тот же разбор команд (d2k_ctlsrv_command) и та же сессия
 * (d2k_session), что в боевом d2kd, но пакеты собираются на месте, а не из
 * NFQUEUE (см. шапку datapath/ctlprobe.c). Проверять d2k_link_* против
 * представления о протоколе бесполезно — расходятся они молча; здесь
 * расхождение падает набором, как и в internal/control/bridge_test.go на
 * Go-стороне (этот файл — её зеркало на C, тот же сценарий hello+quic).
 *
 * Управление стендом — по двум трубам (stdin/stdout ctlprobe, команды
 * "hello"/"quic"/"reply"/... построчно) и ОТДЕЛЬНО настоящий AF_UNIX-сокет
 * управления, который ctlprobe сам слушает по переданному пути — их два, и
 * путать нельзя: трубы это как в тесте дёргать стенд, сокет это то, что
 * проверяется.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "d2k_link.h"
/* Только ради D2K_KEY_WIRE_LEN — строим синтетические кадры руками (см.
 * send_synthetic ниже), тем же приёмом, что datapath/test_ctl.c: ширина
 * ключа нужна настоящая, а не переизобретённая здесь копией. */
#include "d2k_ctlsrv.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static void nap_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    (void)nanosleep(&ts, NULL);
}

static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[b[i] >> 4];
        out[2 * i + 1] = digits[b[i] & 0xFu];
    }
    out[2 * n] = '\0';
}

/* Собирает и пишет в fd кадр вида [длина][тип][ключ (13 произвольных байт,
 * не важных для этих проверок)][rest]. Нужен ровно для того, ЧЕГО настоящий
 * ctlprobe никогда не пришлёт: он воспитанный сервер и обрезанных/
 * переполненных событий не шлёт — а разбор обязан отказывать на них не
 * только на бумаге. rest может быть NULL при rest_len == 0. */
static void send_synthetic(int fd, uint16_t kind, const uint8_t *rest, size_t rest_len) {
    static uint8_t frame[6 + D2K_KEY_WIRE_LEN + 4096];
    size_t body_len = D2K_KEY_WIRE_LEN + rest_len;
    uint32_t plen = (uint32_t)(2 + body_len);
    frame[0] = (uint8_t)(plen >> 24);
    frame[1] = (uint8_t)(plen >> 16);
    frame[2] = (uint8_t)(plen >> 8);
    frame[3] = (uint8_t)plen;
    frame[4] = (uint8_t)(kind >> 8);
    frame[5] = (uint8_t)kind;
    memset(frame + 6, 0xAB, D2K_KEY_WIRE_LEN);
    if (rest_len) {
        memcpy(frame + 6 + D2K_KEY_WIRE_LEN, rest, rest_len);
    }
    (void)write(fd, frame, 6 + body_len);
}

/* --- запуск и остановка стенда ------------------------------------------ */

typedef struct {
    pid_t pid;
    int   in_fd;  /* пишем сюда команды построчно */
    FILE *out;    /* читаем отсюда ответные строки */
} probe;

static void probe_write_line(probe *p, const char *line) {
    char buf[700];
    int n = snprintf(buf, sizeof buf, "%s\n", line);
    if (n > 0) {
        (void)write(p->in_fd, buf, (size_t)n);
    }
}

/* Отправляет команду стенду и возвращает его ответную строку (без \n).
 * Синхронизирует: ctlprobe печатает строку-ответ ПОСЛЕ того, как обработал
 * команду и прогнал d2k_ctlsrv_pump — значит, к этому моменту событие(я) уже
 * лежат в сокете управления и можно смело читать их через d2k_link_next. */
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

/* 0 — запущен и поздоровался; -1 — отказ (причина в stderr самого дочернего
 * процесса и в сообщении здесь). */
static int probe_start(probe *p, const char *sock_path) {
    if (access("../datapath/ctlprobe", X_OK) != 0) {
        fprintf(stderr,
                "стенд не собран (%s); нужен `make -C datapath ctlprobe`\n",
                strerror(errno));
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
        (void)dup2(inpipe[0], STDIN_FILENO);
        (void)dup2(outpipe[1], STDOUT_FILENO);
        close(inpipe[0]);
        close(inpipe[1]);
        close(outpipe[0]);
        close(outpipe[1]);
        execl("../datapath/ctlprobe", "ctlprobe", sock_path, (char *)NULL);
        _exit(127); /* execl не вернулся бы при успехе */
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
    if (p->out) {
        fclose(p->out);
    }
    if (p->pid > 0) {
        (void)waitpid(p->pid, NULL, 0);
    }
    unlink(sock_path);
}

static int dial_retry(const char *sock_path, char *err, size_t errcap) {
    int fd = -1;
    for (int i = 0; i < 50; i++) {
        fd = d2k_link_open(sock_path, err, errcap);
        if (fd >= 0) {
            return fd;
        }
        nap_ms(20);
    }
    return fd;
}

/* Читает события, пропуская мимо всё, что не нужного вида, — до tries
 * штук. Нужно потому, что за приветствием без плана честно идёт REFUSED
 * (session.c ищет план и не находит), и это не сбой, а протокол (тот же
 * приём, что nextHello в internal/control/bridge_test.go). Возвращает 0,
 * если нашли (и *out заполнено), -1 иначе (тайм-аут/ошибка/не нашли за
 * tries попыток — вызывающему достаточно этой границы, причина не важна: он
 * всё равно CHECK'ает факт "нашли или нет"). */
static int next_of_kind(int fd, uint16_t want, int tries, d2k_ev *out,
                        char *err, size_t errcap) {
    for (int i = 0; i < tries; i++) {
        int rc = d2k_link_next(fd, out, 2000, err, errcap);
        if (rc != 0) {
            return -1;
        }
        if (out->kind == want) {
            return 0;
        }
    }
    return -1;
}

int main(void) {
    /* --- §8: успех это ПРИКЛАДНЫЕ данные, а не любые байты ---------------- */
    CHECK(d2k_success(23) == 1, "прикладные данные не засчитаны за успех");
    CHECK(d2k_success(21) == 0, "предупреждение TLS засчитано за успех — это ОТКАЗ сервера");
    CHECK(d2k_success(22) == 0, "рукопожатие засчитано за успех: §8 требует прикладного обмена");
    CHECK(d2k_success(20) == 0, "смена шифра засчитана за успех");
    CHECK(d2k_success(0)  == 0, "нулевой тип засчитан за успех");
    /* Границы — мутация "==23" в ">=23" или в "!=23" здесь и поймается. */
    CHECK(d2k_success(24) == 0, "тип 24 (за пределами алфавита TLS-записей) засчитан за успех");
    CHECK(d2k_success(19) == 0, "тип 19 засчитан за успех");
    CHECK(d2k_success(255) == 0, "тип 255 засчитан за успех");
    CHECK(d2k_success(65535) == 0, "верхняя граница uint16_t засчитана за успех");

    /* --- открытие несуществующего сокета отказывает, а не зависает -------- */
    {
        char err[200] = {0};
        int fd = d2k_link_open("/tmp/d2k-core-link-test-nobody-home.sock", err, sizeof err);
        CHECK(fd < 0, "открытие несуществующего сокета должно отказать");
        CHECK(err[0] != '\0', "отказ открытия без причины в err");
    }
    {
        /* NULL и пустая строка — отдельная ветка ДО strlen/connect: без неё
           strlen(NULL) — неопределённое поведение, а не просто "тоже
           откажет" (в отличие от предыдущей проверки, где отказ пришёл бы и
           без явной проверки, через ENOENT от connect() на несуществующем
           пути — здесь такой смежной страховки нет). */
        char err[200] = {0};
        CHECK(d2k_link_open(NULL, err, sizeof err) < 0, "открытие с NULL-путём должно отказать, не падать");
        CHECK(d2k_link_open("", err, sizeof err) < 0, "открытие с пустым путём должно отказать");
    }

    /* --- защита входа d2k_link_next/d2k_link_close ------------------------ */
    {
        char err[200] = {0};
        d2k_ev ev;
        CHECK(d2k_link_next(-1, &ev, 100, err, sizeof err) == -1, "закрытый fd должен отказывать, не тайм-аутить");
        CHECK(d2k_link_next(-1, NULL, 100, err, sizeof err) == -1, "нет места для события должно отказывать");
        d2k_link_close(-1); /* не должно падать */
    }

    /* --- разбор кадра против ПОДДЕЛЬНОГО собеседника: границы длины ------- */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (длина < 2) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            uint8_t bad[6] = { 0, 0, 0, 0, 0, 0 }; /* plen = 0: короче минимума под тип */
            CHECK(write(sv[1], bad, sizeof bad) == (ssize_t)sizeof bad, "тестовый кадр (длина 0) не записался");
            d2k_ev ev;
            char err[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, err, sizeof err) == -1,
                  "кадр с длиной payload < 2 должен быть отказом, а не тихо принят");
            close(sv[0]);
            close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (короче ключа) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            /* plen=2 — только тип, тела вовсе нет: короче D2K_KEY_WIRE_LEN. */
            uint8_t bad[6];
            bad[0] = 0; bad[1] = 0; bad[2] = 0; bad[3] = 2;
            bad[4] = (uint8_t)(D2K_EV_HELLO >> 8);
            bad[5] = (uint8_t)D2K_EV_HELLO;
            CHECK(write(sv[1], bad, sizeof bad) == (ssize_t)sizeof bad, "тестовый кадр (короче ключа) не записался");
            d2k_ev ev;
            char err[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, err, sizeof err) == -1,
                  "кадр короче ключа потока должен быть отказом");
            close(sv[0]);
            close(sv[1]);
        }
    }
    {
        /* Тот же отказ, но РОВНО на 1 байт короче ключа (12 из 13) — граница,
           отличающая верную проверку "body_len < D2K_KEY_WIRE_LEN" от
           однобайтно ослабленной "< D2K_KEY_WIRE_LEN - 1"; предыдущая
           проверка (тело нулевой длины) обе версии отклоняют одинаково и
           мутацию здесь не поймала бы (поймано мутацией на первом прогоне). */
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (ключ короче на 1 байт) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            uint8_t frame[6 + 12];
            uint32_t plen = (uint32_t)(2 + 12);
            frame[0] = (uint8_t)(plen >> 24); frame[1] = (uint8_t)(plen >> 16);
            frame[2] = (uint8_t)(plen >> 8);  frame[3] = (uint8_t)plen;
            frame[4] = (uint8_t)(D2K_EV_APPLIED >> 8); frame[5] = (uint8_t)D2K_EV_APPLIED;
            memset(frame + 6, 0xAB, 12);
            CHECK(write(sv[1], frame, sizeof frame) == (ssize_t)sizeof frame,
                  "тестовый кадр (ключ короче на 1 байт) не записался");
            d2k_ev ev;
            char err[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, err, sizeof err) == -1,
                  "кадр короче ключа РОВНО на 1 байт (12 из 13) должен отклоняться");
            close(sv[0]);
            close(sv[1]);
        }
    }
    {
        /* Кадр за пределом D2K_CTL_FRAME_MAX. Тело — ровно на 1 байт больше
           разрешённого (D2K_CTL_FRAME_MAX - 2 + 1): без верхней границы
           разбор попытался бы дочитать все эти байты в g_scratch (тот на 6
           байт больше предела, так что здесь бы не переполнился, но принял
           бы кадр как валидный — 0 вместо -1). Писать 65535 байт в один
           конец пары синхронно и ПОТОМ читать нельзя — сокет-пара такой
           объём не бufferизует, write() блокируется, а читающего пока нет:
           классический дедлок. Пишущий — отдельный процесс, читает
           родитель, как и с настоящим ctlprobe. */
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (кадр за пределом) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            pid_t wpid = fork();
            CHECK(wpid >= 0, "fork писателя (кадр за пределом) не удался");
            if (wpid == 0) {
                close(sv[0]);
                uint32_t body_len = (uint32_t)D2K_CTL_FRAME_MAX - 1;
                uint32_t plen = body_len + 2;
                uint8_t hdr[6];
                hdr[0] = (uint8_t)(plen >> 24); hdr[1] = (uint8_t)(plen >> 16);
                hdr[2] = (uint8_t)(plen >> 8);  hdr[3] = (uint8_t)plen;
                hdr[4] = (uint8_t)(D2K_EV_STATS >> 8); hdr[5] = (uint8_t)D2K_EV_STATS;
                (void)write(sv[1], hdr, sizeof hdr);
                static uint8_t filler[D2K_CTL_FRAME_MAX];
                memset(filler, 0x22, body_len);
                size_t sent = 0;
                while (sent < body_len) {
                    ssize_t n = write(sv[1], filler + sent, body_len - sent);
                    if (n <= 0) { break; }
                    sent += (size_t)n;
                }
                close(sv[1]);
                _exit(0);
            }
            close(sv[1]);
            d2k_ev ev;
            char err[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 2000, err, sizeof err) == -1,
                  "кадр длиннее D2K_CTL_FRAME_MAX должен отклоняться");
            close(sv[0]);
            if (wpid > 0) { (void)waitpid(wpid, NULL, 0); }
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (уход без байта) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            close(sv[1]); /* собеседник ушёл, не написав ни байта заголовка */
            d2k_ev ev;
            char err[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, err, sizeof err) == -1,
                  "уход без единого байта — это отказ, а не тайм-аут (1)");
            close(sv[0]);
        }
    }

    /* --- границы разбора по каждому виду события — настоящий ctlprobe их
     * никогда не пришлёт (он воспитанный сервер), значит без синтетического
     * собеседника эти ветки НИКОГДА не исполнятся ни одним другим тестом
     * этого файла. -------------------------------------------------------- */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (HELLO без длины имени) не создался");
        if (sv[0] >= 0) {
            send_synthetic(sv[1], D2K_EV_HELLO, NULL, 0);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "HELLO без байта длины имени должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (HELLO обрезанное имя) не создался");
        if (sv[0] >= 0) {
            /* Ровно на 1 байт короче нужного (rlen == nl, а нужно nl+1: сам
               байт длины плюс nl байт имени) — граница, отличающая верную
               проверку "rlen < 1+nl" от однобайтно ослабленной "rlen < nl";
               с запасом в несколько байт (как было раньше) обе проверки
               совпадали, и мутация в этом самом месте прошла бы незамеченной
               (поймано мутацией на первом прогоне этого файла). */
            uint8_t rest[5] = { 5, 'a', 'b', 'c', 'd' }; /* заявлено 5, дано 4 */
            send_synthetic(sv[1], D2K_EV_HELLO, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "HELLO короче объявленной длины имени РОВНО на 1 байт должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (HELLO 255 байт) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[256];
            rest[0] = 255;
            for (int i = 0; i < 255; i++) { rest[1 + i] = (uint8_t)('a' + (i % 26)); }
            send_synthetic(sv[1], D2K_EV_HELLO, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0,
                  "HELLO с именем ровно 255 байт (граница буфера name[256]) должен приниматься");
            CHECK(strlen(ev.name) == 255, "имя длиной 255 байт не поместилось целиком в out->name");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (SUSPECT без кода) не создался");
        if (sv[0] >= 0) {
            send_synthetic(sv[1], D2K_EV_SUSPECT, NULL, 0);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "SUSPECT без кода причины должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (EXCHANGE короче 6) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[5] = { 22, 0, 0, 0, 0 }; /* на 1 короче минимума в 6 байт */
            send_synthetic(sv[1], D2K_EV_EXCHANGE, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "EXCHANGE короче 6 байт (тип записи + маска + длина) должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (ACK короче 4) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[3] = { 0, 0x81, 1 }; /* на 1 короче минимума в 4 байта */
            send_synthetic(sv[1], D2K_EV_ACK, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "ACK короче 4 байт (тип команды + признак + причина) должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (SHAPE переполнение) не создался");
        if (sv[0] >= 0) {
            static uint8_t rest[2049]; /* на 1 больше буфера out->shape */
            memset(rest, 0x16, sizeof rest);
            send_synthetic(sv[1], D2K_EV_SHAPE, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "форма приветствия длиннее буфера (2049 байт) должна отклоняться, а не переполнять его");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (SHAPE ровно 2048) не создался");
        if (sv[0] >= 0) {
            static uint8_t rest[2048]; /* ровно во весь буфер out->shape */
            memset(rest, 0x16, sizeof rest);
            send_synthetic(sv[1], D2K_EV_SHAPE, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0,
                  "форма приветствия ровно 2048 байт (граница буфера) должна приниматься");
            CHECK(ev.shape_len == 2048, "shape_len не 2048 на границе буфера");
            close(sv[0]); close(sv[1]);
        }
    }

    /* --- проверка hex/имени у d2k_link_set_name — без сети целиком --------
     * Один заведомо валидный fd (сокет-пара, второй конец никто не читает)
     * достаточен: все эти отказы случаются ДО первой попытки записи. */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (валидация set_name) не создался");
        if (sv[0] >= 0) {
            char err[200] = {0};
            CHECK(d2k_link_set_name(sv[0], "x.example", 6, "abc", err, sizeof err) == -1,
                  "нечётная длина hex должна отклоняться");
            CHECK(d2k_link_set_name(sv[0], "x.example", 6, "zz", err, sizeof err) == -1,
                  "недопустимый hex-символ должен отклоняться");
            CHECK(d2k_link_set_name(sv[0], "", 6, "", err, sizeof err) == -1,
                  "пустое имя должно отклоняться");
            CHECK(d2k_link_set_name(sv[0], "x.example", 99, "", err, sizeof err) == -1,
                  "транспорт вне {6,17} должен отклоняться до похода к серверу");
            char longname[300];
            memset(longname, 'a', sizeof longname - 1);
            longname[sizeof longname - 1] = '\0';
            CHECK(d2k_link_set_name(sv[0], longname, 6, "", err, sizeof err) == -1,
                  "имя длиннее 255 байт должно отклоняться");
            close(sv[0]);
            close(sv[1]);
        }
    }

    /* --- дальше всё против НАСТОЯЩЕГО ctlprobe ----------------------------- */
    char sock_path[64];
    snprintf(sock_path, sizeof sock_path, "/tmp/d2k-core-link-%d.sock", (int)getpid());
    probe p;
    memset(&p, 0, sizeof p);
    p.in_fd = -1;
    if (probe_start(&p, sock_path) != 0) {
        printf("ПРОВАЛ: стенд ctlprobe не поднялся — далее проверки против настоящего сервера пропущены\n");
        fails++;
        if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
        return 0;
    }

    char err[200] = {0};
    int fd = dial_retry(sock_path, err, sizeof err);
    CHECK(fd >= 0, "клиент не подключился к настоящему ctlprobe");
    if (fd < 0) {
        probe_stop(&p, sock_path);
        printf("ПРОВАЛ: без подключения к ctlprobe остальные проверки не имеют смысла\n");
        fails++;
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }

    /* --- транспорт доезжает и различает TCP- и QUIC-поток к ОДНОМУ и тому
     * же адресу и порту (зеркало TestTCPИQUICСОдинаковымАдресомИПортомДают
     * РазныеКлючи из internal/control/bridge_test.go). "quic" в ctlprobe
     * нарочно переиспользует порт последнего "hello". ------------------- */
    {
        (void)probe_say(&p, "hello example.com");
        d2k_ev a;
        char e1[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_HELLO, 5, &a, e1, sizeof e1) == 0, "первое (TCP) приветствие не пришло");

        (void)probe_say(&p, "quic");
        d2k_ev b;
        char e2[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_HELLO, 5, &b, e2, sizeof e2) == 0, "второе (QUIC) приветствие не пришло");

        CHECK(strcmp(a.name, "example.com") == 0, "имя TCP-приветствия не example.com");
        CHECK(strcmp(b.name, "example.com") == 0, "имя QUIC-приветствия не example.com");
        CHECK(memcmp(a.low_ip, b.low_ip, 4) == 0 && memcmp(a.high_ip, b.high_ip, 4) == 0 &&
              a.low_port == b.low_port && a.high_port == b.high_port,
              "адрес+порт TCP и QUIC разошлись — проверка не про то, что должна быть про то же");
        CHECK(a.transport == 6, "транспорт TCP-ключа не 6");
        CHECK(b.transport == 17, "транспорт QUIC-ключа не 17");
        CHECK(a.transport != b.transport,
              "TCP и QUIC к одному адресу и порту неразличимы — планы двух транспортов перетрут друг друга");

        /* Абсолютные значения, не только взаимное совпадение a и b: сверка
           "a==b" одна не поймает побайтную перестановку внутри разбора
           ключа (например, перепутанные low_port/high_port) — она даёт ОДНУ
           и ТУ ЖЕ неверную пару на обеих сторонах и остаётся незамеченной.
           Ключ канонизирован по шести байтам "адрес+порт": WAN 93.184.216.34
           численно меньше LAN 192.168.1.67 уже по первому байту адреса,
           независимо от порта, поэтому WAN — низкий конец ВСЕГДА (см. тот
           же вывод в bridge_test.go). Порт клиента — детерминированное
           40001: ctlprobe стартует со 40000 и делает port++ ОДИН раз перед
           первым же "hello" в процессе (см. ctlprobe.c) — а это первый
           hello/raw/quic во всём прогоне этого файла. */
        CHECK(memcmp(a.low_ip, (uint8_t[4]){93, 184, 216, 34}, 4) == 0,
              "низкий конец ключа не 93.184.216.34 — порядок байт адреса разобрался неверно");
        CHECK(a.low_port == 443, "порт низкого конца не 443 — порядок байт порта разобрался неверно");
        CHECK(memcmp(a.high_ip, (uint8_t[4]){192, 168, 1, 67}, 4) == 0,
              "высокий конец ключа не 192.168.1.67");
        CHECK(a.high_port == 40001, "порт высокого конца не 40001 (первый hello в процессе)");

        /* Дренируем то, что осталось (REFUSED от "quic": плана для имени
           нет), прежде чем проверять тайм-аут ниже — иначе d2k_link_next
           честно вернёт 0 на уже лежащем в очереди событии, а не тайм-аут. */
        d2k_ev tmp;
        char e3[200] = {0};
        while (d2k_link_next(fd, &tmp, 200, e3, sizeof e3) == 0) { }
    }

    /* --- тайм-аут без события — это 1, а не 0 и не -1 ---------------------- */
    {
        d2k_ev ev;
        char e[200] = {0};
        int rc = d2k_link_next(fd, &ev, 50, e, sizeof e);
        CHECK(rc == 1, "тайм-аут без события должен возвращать 1");
    }

    /* --- SET_NAME долетает, ack различим по причине (годный план) --------- */
    {
        /* "tiny" — тот же минимальный годный план (только порядок), что и в
           datapath/test_ctl.c: 'D''2''K''P' схема=1 минисполн=1 флаги=0
           записей=1, запись ORDER (тип 0x0103, длина 1, значение 0). */
        static const uint8_t tiny[] = {
            'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 1,
            0x01, 0x03, 0x00, 0x01, 0x00
        };
        char tiny_hex[2 * sizeof tiny + 1];
        to_hex(tiny, sizeof tiny, tiny_hex);

        char e1[200] = {0};
        CHECK(d2k_link_set_name(fd, "ok.example", 6, tiny_hex, e1, sizeof e1) == 0,
              "SET_NAME с годным планом не отправилась");

        d2k_ev ack;
        char e2[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_ACK, 5, &ack, e2, sizeof e2) == 0, "ack на годную команду не пришёл");
        CHECK(ack.code == D2K_CMD_SET_NAME, "ack не на команду SET_NAME");
        CHECK(((ack.num >> 8) & 0xFFu) == 1, "годная команда подтверждена как отвергнутая");
        CHECK((ack.num & 0xFFu) == D2K_ACK_OK, "у успеха причина не D2K_ACK_OK");
    }

    /* --- SET_NAME с негодным планом — ack ok=0, причина D2K_ACK_BAD_PLAN --- */
    {
        char e1[200] = {0};
        CHECK(d2k_link_set_name(fd, "bad.example", 6, "0000000000000000", e1, sizeof e1) == 0,
              "SET_NAME с негодным планом должна ДОЕХАТЬ — отказ приходит по ack, не по rc отправки");

        d2k_ev ack;
        char e2[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_ACK, 5, &ack, e2, sizeof e2) == 0, "ack на негодный план не пришёл");
        CHECK(((ack.num >> 8) & 0xFFu) == 0, "негодный план подтверждён как принятый");
        CHECK((ack.num & 0xFFu) == D2K_ACK_BAD_PLAN, "негодный план не помечен D2K_ACK_BAD_PLAN");
    }

    /* --- ARM_SHAPE: форма приходит РАНЬШЕ ack на саму команду, если она уже
     * поймана (ctlsrv.c) — проверяем порядок на настоящем сервере, а не по
     * тому, что нам кажется по чтению кода. ------------------------------- */
    {
        (void)probe_say(&p, "hello shape.example");

        char e1[200] = {0};
        CHECK(d2k_link_arm_shape(fd, "shape.example", e1, sizeof e1) == 0, "ARM_SHAPE не отправилась");

        d2k_ev ev;
        int found_shape = 0;
        for (int i = 0; i < 6 && !found_shape; i++) {
            char e2[200] = {0};
            int rc = d2k_link_next(fd, &ev, 2000, e2, sizeof e2);
            CHECK(rc == 0, "событие в очереди после ARM_SHAPE не пришло");
            if (rc != 0) { break; }
            if (ev.kind == D2K_EV_SHAPE) { found_shape = 1; }
        }
        CHECK(found_shape, "форма приветствия не пришла после ARM_SHAPE");
        CHECK(ev.shape_len >= 3 && ev.shape[0] == 0x16 && ev.shape[1] == 0x03 && ev.shape[2] == 0x01,
              "форма приветствия не похожа на снятый ClientHello (build_hello, ctlprobe.c)");

        d2k_ev ack;
        char e3[200] = {0};
        CHECK(d2k_link_next(fd, &ack, 2000, e3, sizeof e3) == 0, "ack на ARM_SHAPE не пришёл следом за формой");
        CHECK(ack.kind == D2K_EV_ACK, "событие сразу после формы — не ack (нарушен документированный порядок)");
        CHECK(ack.code == D2K_CMD_ARM_SHAPE, "ack не на команду ARM_SHAPE");
        CHECK(((ack.num >> 8) & 0xFFu) == 1, "ARM_SHAPE не подтверждена как принятая");
    }

    /* --- EXCHANGE: code липкий (первый тип), поэтому появление прикладных
     * данных ПОСЛЕ другого типа видно только по seen_types, а не по code —
     * ровно та причина, по которой seen_types добавлено сверх контракта
     * брифа (см. d2k_link.h). Проверяем на настоящем обмене: рукопожатие
     * (22), потом прикладные данные (23) на ОДНОМ потоке. --------------- */
    {
        (void)probe_say(&p, "hello exchange.example");
        (void)probe_say(&p, "reply 22");

        d2k_ev ev1;
        char e1[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_EXCHANGE, 6, &ev1, e1, sizeof e1) == 0, "первый обмен (код 22) не пришёл");
        CHECK(ev1.code == 22, "первый обмен: тип записи не 22");
        /* rec[64] в ctlprobe.c ("reply <тип>") — 64 байта нагрузки ровно
           одним пакетом; num = fl->rev_payload_after_hello (session.c) —
           НАКОПЛЕННЫЙ счёт с момента приветствия, не размер текущего
           пакета, поэтому после ВТОРОГО reply это 128, а не снова 64. */
        CHECK(ev1.num == 64, "первый обмен: число байт не 64 — порядок байт длины разобрался неверно");
        CHECK(d2k_success(ev1.code) == 0, "рукопожатие в настоящем обмене засчитано успехом");

        (void)probe_say(&p, "reply 23");
        d2k_ev ev2;
        char e2[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_EXCHANGE, 6, &ev2, e2, sizeof e2) == 0,
              "второй обмен (появились прикладные данные) не пришёл");
        CHECK(ev2.code == 22,
              "второй обмен: code изменился — липкое поле ведёт себя иначе, чем задокументировано в d2k_link.h");
        CHECK(ev2.num == 128, "второй обмен: накопленное число байт не 128 (64+64)");
        CHECK(d2k_success(ev2.code) == 0,
              "второй обмен по code читается как успех — это и есть дефект, который seen_types обязано закрыть");
        CHECK((ev2.seen_types & (uint8_t)(1u << (D2K_TLS_APPLICATION_DATA - 20))) != 0,
              "seen_types не отражает пришедшие прикладные данные — по code одному успех не увидеть");
    }

    /* --- отрицательный wait_ms — «ждать неограниченно» (семантика poll(2)),
     * проверяется безопасно: событие гарантированно уже лежит в буфере к
     * моменту вызова (иначе тест мог бы зависнуть навечно при поломке). --- */
    {
        char e1[200] = {0};
        CHECK(d2k_link_set_name(fd, "forever.example", 17, "", e1, sizeof e1) == 0,
              "SET_NAME для проверки wait_ms<0 не отправилась");
        nap_ms(100); /* ack успевает дойти и лечь в буфер сокета */

        d2k_ev ack;
        char e2[200] = {0};
        int rc = d2k_link_next(fd, &ack, -1, e2, sizeof e2);
        CHECK(rc == 0, "wait_ms<0 не увидел уже лежащее в буфере событие");
        CHECK(ack.kind == D2K_EV_ACK, "wait_ms<0 прочитал не то событие");
    }

    d2k_link_close(fd);
    probe_stop(&p, sock_path);

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("связь с датапатом и порог успеха: все проверки прошли\n");
    return 0;
}
