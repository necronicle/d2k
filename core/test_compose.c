/* test_compose.c — проверки свойств коробки и вывода плана для TCP.
 *
 * d2k_compose — без сети: чистая сборка текста плана из вектора свойств и
 * вида приветствия цели (задача 5, шаг 0б добавила второй параметр — см.
 * блок проверок "вид приманки").
 *
 * d2k_props_ask (задача 5, шаг 0) — С СЕТЬЮ, тем же приёмом, что test_link.c:
 * настоящий ctlprobe (datapath/ctlprobe.c) как датапат, и петля-мишень
 * test_stand.h (mode 0, "отвечает всегда") как цель для d2k_meas_once внутри
 * d2k_props_ask — стенд и ctlprobe не заменяют друг друга: петля-мишень нужна,
 * чтобы "одно обращение к цели" не упёрлось в ECONNREFUSED, а ctlprobe — чтобы
 * дать событие обмена, по которому судит сам d2k_props_ask. Проверять этот
 * протокол по представлению о нём бесполезно — расхождение падает молча
 * (см. шапку test_link.c).
 *
 * РАСХОЖДЕНИЯ С БРИФОМ ЗАДАЧИ, НАЙДЕННЫЕ ПРИ ЧТЕНИИ properties.go.
 *
 * Бриф задачи (task-3-brief.md, шаг 1) ожидал 0 планов от вектора, в котором
 * ни одно свойство не встало в NO/YES ("да и только да, если требуется") —
 * ТРИ его примера построены ровно на этом: полностью нулевой вектор,
 * ToleratesLeftOverlap=YES при остальном неизмеренном, и
 * ValidatesChecksum=UNKNOWN на нулевом векторе. Но Go Compose
 * (properties.go:214-221) в точности для этого случая — «ни один вопрос
 * ничего не подтвердил» — добавляет everythingPlan: `if len(out) == 0 { add
 * (everythingPlan(decoy)) }`. Комментарий рядом называет его «единственным
 * честным кандидатом», а не отсутствием кандидата. Все три сценария ниже
 * проверяют ИСПРАВЛЕННОЕ ожидание — ровно 1 план (everythingPlan), а не 0 — и
 * это подтверждено и в отчёте задачи.
 *
 * ЗАДАЧА 5 (11.09.2026): d2k_props_ask.Set в Go — ОДИН исход на один вопрос
 * (`Set: func(*Properties, bool)`), а не сама точка входа опроса: реально
 * `.Set` в бою вызывается ТОЛЬКО в properties_test.go — controller.go
 * (verdictCandidates) читает у PropProbe только Plan, кладёт кандидатов в
 * ОБЩУЮ очередь и решает опросом ЛЕСТНИЦЫ advance()/onProbe(), а не отдельным
 * проходом вопросов с записью Set(). Свойства (t.Traits.Props) в проде
 * поэтому НИКОГДА не заполняются самим Go — controller.go прямо это
 * признаёт (комментарий у verdictCandidates: "до сбора нескольких
 * подтверждённых свойств... дело физически не доходит"). d2k_props_ask на
 * C-стороне — САМОСТОЯТЕЛЬНЫЙ синхронный опрос по всем пяти вопросам подряд
 * (так решает бриф задачи 5, шаг 0, явно), а не копия недостроенного пути
 * Go — это и есть то расхождение с Go-стороной, которое велено искать и
 * называть, а не молчать о нём.
 */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "d2k_compose.h"
#include "d2k_compose_internal.h"
#include "d2k_link.h"
/* Только ради D2K_KEY_WIRE_LEN — поддельный конец связи (fakeend_run ниже)
 * строит кадры событий руками, тем же приёмом, что test_link.c и datapath/
 * test_ctl.c: ширина ключа нужна настоящая, а не переизобретённая здесь
 * копией. */
#include "d2k_ctlsrv.h"
#include "test_stand.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Подстрока, которая может встретиться ТОЛЬКО в checksum_plan_text: 64 байта
 * набивки 0x41 гарантируют длинный повтор "41", которого в decoy-приветствии
 * (LEGACY-профиль настоящего захвата) нет ни разу (проверено по исходнику
 * profiles/legacy.hex) — так отличаем "это план про сумму" от "это план про
 * разбор протокола/дубликаты", у которых тот же скелет (poison+fake), но
 * другая приманка. */
static const char CHECKSUM_FILLER_MARK[] = "4141414141414141";

/* Число подряд идущих hex-цифр сразу после needle — используется, чтобы
 * измерить длину приманки в собранном плане без знания её байт: LEGACY и
 * MODERN дают заметно разные длины (см. шапку build_decoy_hello, compose.c),
 * и это единственный способ различить их снаружи, не подглядывая в profiles/
 * *.hex рукам. */
static size_t hexrun_after(const char *hay, const char *needle) {
    const char *p = strstr(hay, needle);
    if (!p) { return 0; }
    p += strlen(needle);
    size_t n = 0;
    while (isxdigit((unsigned char)p[n])) { n++; }
    return n;
}

/* Считает непересекающиеся вхождения needle в hay — нужно посчитать строки
 * "emit " в выводе planlab без ещё одного разбора построчно. */
static int count_substr(const char *hay, const char *needle) {
    int n = 0;
    size_t nl = strlen(needle);
    const char *p = hay;
    while ((p = strstr(p, needle)) != NULL) { n++; p += nl; }
    return n;
}

static int write_file_bytes(const char *path, const uint8_t *b, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) { return -1; }
    size_t wr = n ? fwrite(b, 1, n, f) : 0;
    fclose(f);
    return (wr == n) ? 0 : -1;
}

static int write_file_text(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) { return -1; }
    size_t n = strlen(text);
    size_t wr = fwrite(text, 1, n, f);
    fclose(f);
    return (wr == n) ? 0 : -1;
}

/* Запускает planlab (лаборатория плана, datapath/planlab.c — тот же
 * исполнитель, d2k_plan_load+d2k_plan_apply, что и прод) на паре файлов и
 * возвращает его STDOUT целиком в out (обрезан до cap-1, для пяти зондов
 * этого с большим запасом достаточно). Возвращает 0, если сам процесс
 * запустился (даже если planlab написал "reject"/"refuse" — это результат
 * исполнителя, а не сбой запуска, см. шапку planlab.c), -1 иначе. cwd теста
 * — core/ (см. Makefile), отсюда относительный путь "../datapath/planlab". */
static int run_planlab(const char *plan_path, const char *scenario_path,
                       char *out, size_t cap) {
    char cmd[600];
    int n = snprintf(cmd, sizeof cmd, "../datapath/planlab %s %s 2>/dev/null",
                     plan_path, scenario_path);
    if (n < 0 || (size_t)n >= sizeof cmd) { return -1; }
    FILE *pf = popen(cmd, "r");
    if (!pf) { return -1; }
    size_t got = 0;
    while (got + 1 < cap) {
        size_t r = fread(out + got, 1, cap - 1 - got, pf);
        if (r == 0) { break; }
        got += r;
    }
    out[got] = '\0';
    pclose(pf);
    return 0;
}

static void nap_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    (void)nanosleep(&ts, NULL);
}

/* --------------------------------------------------------------------
 * Стенд ctlprobe — тот же приём, что test_link.c (см. её шапку): две трубы
 * (stdin/stdout ctlprobe, команды построчно) и ОТДЕЛЬНО настоящий AF_UNIX-
 * сокет управления. Копия, не общий код: test_link.c и этот файл — разные
 * цели сборки Makefile, и второй экземпляр той же логики здесь не хуже
 * оправдан, чем в hello.c/tls.c (см. шапку core/hello.c).
 * -------------------------------------------------------------------- */
typedef struct {
    pid_t pid;
    int   in_fd;
    FILE *out;
} probe;

static void probe_write_line(probe *p, const char *line) {
    char buf[700];
    int n = snprintf(buf, sizeof buf, "%s\n", line);
    if (n > 0) {
        (void)write(p->in_fd, buf, (size_t)n);
    }
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

/* Ищет событие вида want (среди want2, если >0) не дольше tries чтений по
 * 500мс — тот же приём и та же причина, что next_of_kind в test_link.c:
 * REFUSED/HELLO чужих проверок могут смешаться с нужным. */
static int next_of_kind2(int fd, uint16_t want, uint16_t want2, int tries,
                         d2k_ev *out, char *err, size_t errcap) {
    for (int i = 0; i < tries; i++) {
        int rc = d2k_link_next(fd, out, 500, err, errcap);
        if (rc != 0) { return -1; }
        if (out->kind == want || (want2 && out->kind == want2)) { return 0; }
    }
    return -1;
}

/* Осушает всё, что уже лежит (или придёт в течение недолгого времени) в
 * очереди событий, без разбора вида — чтобы события ОДНОГО блока проверок не
 * просочились в следующий и не были прочитаны за "своё" в другом контексте. */
static void drain_all(int fd) {
    d2k_ev ev;
    char err[200];
    while (d2k_link_next(fd, &ev, 150, err, sizeof err) == 0) { }
}

/* "plans" отдаёт СЕРВЕРНЫЙ, некопящийся у клиента счётчик принятых команд
 * (cx.ok_cmds, ctlprobe.c) — в отличие от событий ACK, который d2k_props_ask
 * сам вычитывает из очереди по пути (иначе после её возврата в очереди уже
 * нечего было бы посчитать). Разница before/after — надёжный способ узнать,
 * сколько РЕАЛЬНО раз d2k_props_ask поставил план за один вызов, не читая
 * события параллельно с ним. */
static unsigned long long query_ok_cmds(probe *p) {
    const char *resp = probe_say(p, "plans");
    unsigned long long total = 0, ok = 0, bad = 0;
    (void)sscanf(resp, "planов %llu, команд принято %llu, отвергнуто %llu", &total, &ok, &bad);
    return ok;
}

/* Собирает НАСТОЯЩЕЕ приветствие (LEGACY-профиль, hello.c) с заданным SNI —
 * тем же путём, каким его строил бы вызывающий d2k_props_ask на первом
 * контакте с целью (d2k_hello_from_profile, задача 1). Нужно, чтобы
 * d2k_hello_sni внутри d2k_props_ask нашёл настоящее имя, а не подстроку по
 * случайности: самодельные байты здесь были бы тем самым грехом, против
 * которого возражает вся остальная приманка этого файла. */
static d2k_hello build_trigger(uint8_t *buf, size_t cap, const char *sni) {
    d2k_hello h; h.bytes = NULL; h.len = 0;
    size_t len = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_LEGACY, sni, buf, cap, &len) == 0) {
        h.bytes = buf;
        h.len = len;
    }
    return h;
}

/* --------------------------------------------------------------------
 * Ведущий поток стенда: пока d2k_props_ask синхронно блокируется внутри
 * своего цикла (SET_NAME → ack → одно обращение → ждать обмен), кто-то
 * должен ПАРАЛЛЕЛЬНО дать ctlprobe команды "hello"/"reply", изображающие
 * датапат, который увидел ту же цель и её ответ. Без этого события для
 * d2k_props_ask взяться неоткуда — ctlprobe их не производит сам.
 *
 * pre_delay_ms ПЕРЕД каждой парой — не гонка "на глаз": SET_NAME/ack — это
 * АФ_UNIX-обмен на этой же машине (см. wait_for_event, compose.c, комментарий
 * про миллисекунды), а connect+send в d2k_meas_once — TCP-петля на
 * локалхосте, тоже миллисекунды; 300мс — на порядок больше того и другого
 * вместе, тем же приёмом запаса, что D2K_TEST_IDLE_MS в test_stand.h.
 * Без этой паузы пара "hello+reply" рисковала бы прийти РАНЬШЕ, чем
 * d2k_props_ask поставит план и начнёт ждать обмен — и её событие
 * потерялось бы, будучи прочитанным (и отброшенным как "не тот вид") ещё
 * во время ожидания ack. -------------------------------------------------- */
typedef struct {
    probe *p;
    const char *name;
    const int *replies; /* -1 — не отвечать вовсе (для проверки честного тайм-аута) */
    size_t n;
    unsigned pre_delay_ms;
} driver_args;

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

/* ========================================================================
 * ПОДДЕЛЬНЫЙ КОНЕЦ СВЯЗИ — нужен РОВНО для находки 1 ревью 11.09 (круг
 * правок 2): D2K_EV_EXCHANGE не адресован нашей команде, его несёт ключ
 * потока (свой адрес:порт против адреса:порта цели), а настоящий ctlprobe
 * строит синтетические пакеты с ЖЁСТКО ЗАШИТЫМ адресом клиента (LAN
 * 192.168.1.67, datapath/ctlprobe.c: build_pkt) — тем же для ЛЮБОГО теста,
 * что даёт test_link.c проверять КОНСТАНТУ (её же тесты на key.low_ip и
 * т.п.). d2k_props_ask, наоборот, соединяется с целью НАСТОЯЩИМ сокетом
 * (props_ask_contact, compose.c) — местный порт назначает ядро при
 * connect(), заранее его не знает НИКТО, включая ctlprobe, и подделать
 * событие с ключом, который действительно совпадёт, через её "hello"/
 * "reply" нечем: порт там свой, внутренний, auto-increment, без ручки
 * снаружи. Проверять фильтр по ключу можно только на конце связи, которым
 * управляет сам тест, — отсюда socketpair() вместо ctlprobe для B1/B2/B4 и
 * новых проверок находки 1 (C1/C2) ниже; B3 остаётся на настоящем ctlprobe
 * (там фильтр никакого "прохода" не даёт увидеть — все ответы намеренно
 * без прикладных данных, а имя проверяется её собственным, отдельным
 * приёмом APPLIED/REFUSED).
 * ==================================================================== */

/* Слушает на локалхосте и отдаёт РЕАЛЬНЫЙ адрес клиента, принявшего РОВНО
 * одно подключение, — getpeername() с принявшей стороны это тот же самый
 * местный адрес, что выбрал props_ask_contact и что легло бы в ключ
 * настоящего события на живом датапате. Сам props_ask_contact его наружу
 * не отдаёт (не часть её контракта, compose.c) — единственный способ узнать
 * порт вовремя это спросить у того, кто его увидел. */
typedef struct { int listen_fd; uint16_t port; } peerstand;

static uint16_t peerstand_start(peerstand *s) {
    s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    a.sin_port = 0;
    bind(s->listen_fd, (struct sockaddr *)&a, sizeof a);
    socklen_t l = sizeof a;
    getsockname(s->listen_fd, (struct sockaddr *)&a, &l);
    listen(s->listen_fd, 4);
    s->port = ntohs(a.sin_port);
    return s->port;
}

static int peerstand_accept_one(peerstand *s, uint8_t *peer_ip, uint16_t *peer_port) {
    struct sockaddr_in pa;
    socklen_t pl = sizeof pa;
    int c = accept(s->listen_fd, (struct sockaddr *)&pa, &pl);
    if (c < 0) { return -1; }
    memcpy(peer_ip, &pa.sin_addr, 4);
    *peer_port = ntohs(pa.sin_port);
    uint8_t buf[4096];
    (void)recv(c, buf, sizeof buf, 0); /* осушить присланное — содержимое здесь не проверяем */
    close(c);
    return 0;
}

/* Читает и отбрасывает РОВНО один кадр команды (заголовок [длина
 * payload BE32][тип BE16], затем длина-2 байт тела) — та же раскладка,
 * что и у события (d2k_ctl.h: "Кадр: [длина payload u32 BE][тип u16
 * BE][payload]", общая для обоих направлений), поэтому разбирать ВНУТРЕННЕЕ
 * устройство SET_NAME здесь незачем: границы кадра снаружи одни на всех. */
static int drain_one_command(int fd) {
    uint8_t hdr[6];
    size_t got = 0;
    while (got < sizeof hdr) {
        ssize_t n = read(fd, hdr + got, sizeof hdr - got);
        if (n <= 0) { return -1; }
        got += (size_t)n;
    }
    uint32_t plen = (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 |
                    (uint32_t)hdr[2] << 8 | hdr[3];
    if (plen < 2) { return -1; }
    size_t remaining = (size_t)plen - 2;
    uint8_t buf[4096];
    while (remaining > 0) {
        size_t chunk = remaining < sizeof buf ? remaining : sizeof buf;
        ssize_t n = read(fd, buf, chunk);
        if (n <= 0) { return -1; }
        remaining -= (size_t)n;
    }
    return 0;
}

/* Пишет один кадр события руками — та же раскладка, что send_synthetic в
 * test_link.c: [длина payload BE32][тип BE16][ключ 13 байт][rest]. ip
 * может быть NULL (ключ нулевой, как у настоящего ACK — ctlsrv.c: ack()
 * зовёт memset ровно по этой причине, событие не про поток). */
static void send_event_frame(int fd, uint16_t kind,
                             const uint8_t *low_ip, uint16_t low_port,
                             const uint8_t *high_ip, uint16_t high_port,
                             uint8_t transport,
                             const uint8_t *rest, size_t rest_len) {
    uint8_t frame[6 + D2K_KEY_WIRE_LEN + 32];
    size_t body_len = D2K_KEY_WIRE_LEN + rest_len;
    uint32_t plen = (uint32_t)(2 + body_len);
    frame[0] = (uint8_t)(plen >> 24); frame[1] = (uint8_t)(plen >> 16);
    frame[2] = (uint8_t)(plen >> 8);  frame[3] = (uint8_t)plen;
    frame[4] = (uint8_t)(kind >> 8);  frame[5] = (uint8_t)kind;
    uint8_t *k = frame + 6;
    if (low_ip) { memcpy(k, low_ip, 4); } else { memset(k, 0, 4); }
    if (high_ip) { memcpy(k + 4, high_ip, 4); } else { memset(k + 4, 0, 4); }
    k[8] = (uint8_t)(low_port >> 8); k[9] = (uint8_t)low_port;
    k[10] = (uint8_t)(high_port >> 8); k[11] = (uint8_t)high_port;
    k[12] = transport;
    if (rest_len) { memcpy(frame + 6 + D2K_KEY_WIRE_LEN, rest, rest_len); }
    (void)write(fd, frame, 6 + body_len);
}

static void send_ack_ok(int fd, uint16_t cmd) {
    uint8_t rest[4];
    rest[0] = (uint8_t)(cmd >> 8); rest[1] = (uint8_t)cmd;
    rest[2] = 1; /* признак успеха */
    rest[3] = 0; /* D2K_ACK_OK */
    send_event_frame(fd, D2K_EV_ACK, NULL, 0, NULL, 0, 0, rest, sizeof rest);
}

/* seen_types: бит appdata — (1<<(23-20))=0x08; бит "только рукопожатие" —
 * (1<<(22-20))=0x04 (см. d2k_ev_has_appdata, d2k_link.h). code/num — тут не
 * важны для порога (см. её же большой комментарий про липкое поле code),
 * заполнены правдоподобно, не нулём, чтобы не полагаться на memset. */
static void send_exchange(int fd, const uint8_t *ip_a, uint16_t port_a,
                          const uint8_t *ip_b, uint16_t port_b,
                          uint8_t transport, uint8_t seen_types) {
    uint8_t rest[6];
    rest[0] = 22;
    rest[1] = seen_types;
    rest[2] = 0; rest[3] = 0; rest[4] = 0; rest[5] = 64;
    send_event_frame(fd, D2K_EV_EXCHANGE, ip_a, port_a, ip_b, port_b, transport, rest, sizeof rest);
}

static const uint8_t LOOPBACK4[4] = { 127, 0, 0, 1 };

/* Обслуживает N раундов SET_NAME→ack→(подключение цели)→обмен, каждый ПОД
 * СВОЙ, настоящий местный порт (peerstand_accept_one) — синхронно, без
 * сна "на авось" (круг правок 1 гонял hello/reply с фиксированной паузой
 * 300мс; здесь пауз нет вовсе, каждый шаг блокируется РОВНО до своего
 * события на уровне ОС).
 *
 * outcomes[i]: -1 — тайм-аут (обмена не шлём совсем, props_ask_contact всё
 * равно подключится к настоящей peerstand — сама цель "жива", просто ответа
 * от датапата не будет НИКОГДА, честная проверка тайм-аута); 0 — обмен без
 * прикладных данных (промах); 1 — обмен с прикладными данными (проход).
 * foreign_before_round: если раунд с этим индексом дошёл до обмена, ПЕРЕД
 * настоящим событием шлётся ОДНО чужое — с appdata, но с чужим ключом
 * (адрес 10.0.0.9:9999, к делу не относится) — находка 1: opros обязан его
 * пропустить, не засчитав за свой. -1 выключает это для всех раундов.
 *
 * extra_round_seen: выставляется в 1, если ПОСЛЕ всех настроенных раундов
 * пришла ЕЩЁ одна команда — опрос не остановился по первому проходу или по
 * исчерпании раундов, хотя обязан был (короткий poll, не полный тайм-аут:
 * если что-то есть, оно уже в буфере ядра). */
typedef struct {
    int fd;
    peerstand *ps;
    uint16_t target_port;
    const int *outcomes;
    size_t n;
    int foreign_before_round;
    int extra_round_seen;
} fakeend_args;

static void *fakeend_run(void *arg) {
    fakeend_args *a = (fakeend_args *)arg;
    for (size_t i = 0; i < a->n; i++) {
        if (drain_one_command(a->fd) != 0) { return NULL; }
        send_ack_ok(a->fd, D2K_CMD_SET_NAME);

        uint8_t peer_ip[4]; uint16_t peer_port = 0;
        if (peerstand_accept_one(a->ps, peer_ip, &peer_port) != 0) { return NULL; }

        if ((int)i == a->foreign_before_round) {
            /* Чужое — ДАЖЕ с appdata — шлётся независимо от исхода этого
               раунда: находка 1 именно про то, что такое событие не должно
               подтвердить наш зонд НИ ПРИ КАКИХ обстоятельствах, включая
               "своего обмена не будет никогда" (outcomes[i]==-1, C1). */
            static const uint8_t foreign_ip[4] = { 10, 0, 0, 9 };
            send_exchange(a->fd, foreign_ip, 9999, LOOPBACK4, a->target_port, 6, 0x08);
        }
        if (a->outcomes[i] == -1) {
            continue; /* настоящего обмена не шлём вовсе — честный тайм-аут у wait_for_event */
        }
        uint8_t seen = (a->outcomes[i] == 1) ? 0x08 : 0x04;
        send_exchange(a->fd, LOOPBACK4, a->target_port, peer_ip, peer_port, 6, seen);
    }

    struct pollfd pfd;
    pfd.fd = a->fd; pfd.events = POLLIN; pfd.revents = 0;
    if (poll(&pfd, 1, 300) > 0) {
        a->extra_round_seen = 1;
    }
    return NULL;
}

int main(void) {
    const char *decoy = "disk.rzd.ru";
    char out[8][4096];

    /* --- пустой вектор: НЕ "плечей нет", а единственный честный кандидат --
     *
     * См. большой комментарий в шапке файла про расхождение с брифом. */
    {
        d2k_props pr = {0};
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8);
        CHECK(n == 1, "полностью неизмеренный вектор обязан дать ровно один "
                       "запасной план (everythingPlan), а не ноль и не больше");
        CHECK(strstr(out[0], "seqovl") != NULL, "запасной план без перекрытия");
        CHECK(strstr(out[0], "split payload_start +1") != NULL,
              "запасной план без разреза payload_start+1");
        CHECK(strstr(out[0], "split sni_middle +0") != NULL,
              "запасной план без разреза по имени");
        CHECK(strstr(out[0], "order reverse") != NULL, "запасной план без обратного порядка");
        CHECK(strstr(out[0], "poison 1 badsum") != NULL, "запасной план без порчи суммы");
        CHECK(strstr(out[0], "fake payload=1 poison=1 repeats=2 gap_us=20000") != NULL,
              "запасной план без пары дублей с разрывом 20000мкс");
        CHECK(strstr(out[0], "payload 2 41") != NULL, "запасной план без приставки перекрытия");
    }

    /* --- перекрытие выводится только из своего свойства -------------------- */
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8);
        CHECK(n == 1, "ожидалось ровно одно плечо");
        CHECK(strstr(out[0], "seqovl") != NULL, "плечо перекрытия не собрано");
        CHECK(strstr(out[0], "payload 1 41") != NULL, "приставка перекрытия не та");

        pr.tolerates_left_overlap = D2K_P_YES;
        n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8);
        CHECK(n == 1, "коробка держит перекрытие: свой план не должен выводиться, "
                       "но вектор пуст и обязан дать everythingPlan, а не 0 и не 2");
        CHECK(strstr(out[0], "seqovl") != NULL && strstr(out[0], "order reverse") != NULL,
              "при YES-перекрытии на пустом остальном векторе вышел не запасной план");
    }

    /* --- порядок режет ПО ИМЕНИ, а не по середине приветствия -------------- */
    {
        d2k_props pr = {0};
        pr.tolerates_reorder = D2K_P_NO;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8);
        CHECK(n == 1, "ожидалось ровно одно плечо");
        CHECK(strstr(out[0], "sni_middle") != NULL,
              "рез не по имени: замер донора 07.09 показал, что середина приветствия не работает");
        CHECK(strstr(out[0], "hello_middle") == NULL,
              "вернулся рез по середине приветствия — забракованная замером форма");
        CHECK(strstr(out[0], "order reverse") != NULL, "куски не переставлены");
    }

    /* --- «не измерено» не равно «нет»: неизмеренная сумма ------------------ */
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        pr.validates_checksum = D2K_P_UNKNOWN;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8);
        CHECK(n == 1, "неизмеренная сумма всё равно породила своё плечо");
        CHECK(strstr(out[0], CHECKSUM_FILLER_MARK) == NULL,
              "неизмеренное свойство породило checksum-плечо");
    }

    /* --- счёт дубликатов: YES выводит пару с разрывом 20000мкс ------------- */
    {
        d2k_props pr = {0};
        pr.counts_duplicates = D2K_P_YES;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8);
        CHECK(n == 1, "ожидалось ровно одно плечо");
        CHECK(strstr(out[0], "fake payload=1 poison=1 repeats=2 gap_us=20000 place=before") != NULL,
              "план дубликатов: не та форма fake");
        CHECK(strstr(out[0], "poison 1 badsum") != NULL, "план дубликатов без порчи суммы");
        CHECK(strstr(out[0], CHECKSUM_FILLER_MARK) == NULL,
              "план дубликатов использует набивку вопроса о сумме, а не decoy-приветствие");
    }

    /* --- разбор протокола: YES выводит целое приветствие с decoy-именем ---- */
    {
        d2k_props pr = {0};
        pr.parses_l7 = D2K_P_YES;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8);
        CHECK(n == 1, "ожидалось ровно одно плечо");
        CHECK(strstr(out[0], "fake payload=1 poison=1 repeats=1 gap_us=0 place=before") != NULL,
              "план разбора протокола: не та форма fake (repeats/gap перепутаны с дубликатами)");
        CHECK(strstr(out[0], CHECKSUM_FILLER_MARK) == NULL,
              "план разбора протокола использует набивку вопроса о сумме, а не decoy-приветствие");
        CHECK(strlen(out[0]) < 1200,
              "при shape=LEGACY план разбора протокола заметно длиннее ожидаемого");
    }

    /* --- вид приманки — по виду СНЯТОГО приветствия ЦЕЛИ, не назначен
     * (задача 5, шаг 0б) ------------------------------------------------------
     *
     * MODERN (1530 «живых» байт) даёт заметно длиннее hex, чем LEGACY (210
     * байт) — разница больше чем в 2 раза с большим запасом, поэтому порог
     * *2 не хрупкий. D2K_SHAPE_UNKNOWN обязан падать на тот же LEGACY, что
     * и раньше — безопасный запасной вид, а не угаданный MODERN. */
    {
        d2k_props pr = {0};
        pr.parses_l7 = D2K_P_YES;
        CHECK(d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8) == 1, "LEGACY: не одно плечо");
        size_t legacy_hex = hexrun_after(out[0], "payload 1 ");
        CHECK(legacy_hex > 100 && legacy_hex < 1000,
              "длина hex LEGACY-приманки вне ожидаемых границ (~420 симв. для LEGACY)");

        CHECK(d2k_compose(&pr, D2K_SHAPE_MODERN, decoy, out, 8) == 1, "MODERN: не одно плечо");
        size_t modern_hex = hexrun_after(out[0], "payload 1 ");
        CHECK(modern_hex > legacy_hex * 2,
              "вид цели MODERN не выбрал MODERN-приманку — hex не заметно длиннее LEGACY");
        CHECK(strlen(out[0]) < 4096, "MODERN-план не поместился бы в старый буфер out[][2048]" );

        CHECK(d2k_compose(&pr, D2K_SHAPE_UNKNOWN, decoy, out, 8) == 1, "UNKNOWN: не одно плечо");
        size_t unknown_hex = hexrun_after(out[0], "payload 1 ");
        CHECK(unknown_hex == legacy_hex,
              "вид цели UNKNOWN не упал на безопасный запасной LEGACY, дал другую длину");
    }

    /* --- сумма выводится только из своего свойства -------------------------- */
    {
        d2k_props pr = {0};
        pr.validates_checksum = D2K_P_NO;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8);
        CHECK(n == 1, "ожидалось ровно одно плечо");
        CHECK(strstr(out[0], CHECKSUM_FILLER_MARK) != NULL,
              "план суммы не содержит набивку 0x41 — приманка не та");
        CHECK(strstr(out[0], "repeats=1 gap_us=0") != NULL,
              "план суммы: не та форма fake");
        CHECK(strstr(out[0], "split") == NULL, "план суммы не должен резать поток");
        CHECK(strstr(out[0], "seqovl") == NULL, "план суммы не должен перекрывать поток");
    }

    /* --- ловушка донора наоборот: сумма=NO вместе с разбором=YES не даёт
     * ДВУХ планов ---------------------------------------------------------- */
    {
        d2k_props pr = {0};
        pr.validates_checksum = D2K_P_NO;
        pr.parses_l7 = D2K_P_YES;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8);
        CHECK(n == 1, "сумма=NO вместе с разбором=YES дала не одно плечо — "
                       "ловушка донора наоборот не подавлена");
        CHECK(strstr(out[0], CHECKSUM_FILLER_MARK) == NULL,
              "вышел план про сумму, а не про разбор протокола — правило подавления не сработало");
    }

    /* --- несколько свойств сразу: порядок и отсутствие взаимного стирания -- */
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        pr.counts_duplicates = D2K_P_YES;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out, 8);
        CHECK(n == 2, "два независимых свойства обязаны дать два плеча");
        CHECK(strstr(out[0], "seqovl") != NULL,
              "порядок плеч расходится с Go Compose: перекрытие обязано идти первым");
        CHECK(strstr(out[1], "fake payload=1 poison=1 repeats=2 gap_us=20000") != NULL,
              "порядок плеч расходится с Go Compose: дубликаты обязаны идти вторыми");
    }

    /* --- cap ограничивает запись и не переполняет буфер вызывающего -------- */
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        pr.counts_duplicates = D2K_P_YES;
        char out1[1][4096];
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out1, 1);
        CHECK(n == 1, "cap=1 не ограничил число записанных плеч");
        CHECK(strstr(out1[0], "seqovl") != NULL,
              "при cap=1 записано не первое по порядку плечо");
    }
    {
        d2k_props pr = {0};
        char out0[1][4096];
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, out0, 0);
        CHECK(n == 0, "cap=0 обязан дать 0 независимо от вектора");
    }

    /* --- decoy не нужен свойствам, которые его не используют --------------- */
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, NULL, out, 8);
        CHECK(n == 1, "план перекрытия обязан собираться и без decoy");
    }
    {
        d2k_props pr = {0};
        pr.tolerates_reorder = D2K_P_NO;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, NULL, out, 8);
        CHECK(n == 1, "план порядка обязан собираться и без decoy — якорь вычисляется датапатом");
    }

    /* --- decoy нужен свойствам, которые его используют ---------------------- */
    {
        d2k_props pr = {0};
        pr.counts_duplicates = D2K_P_YES;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, NULL, out, 8);
        CHECK(n == 0, "без decoy план дубликатов обязан быть пропущен, а не выдуман; "
                       "запасной план тоже нуждается в decoy и падает по той же причине");
    }
    {
        d2k_props pr = {0};
        pr.counts_duplicates = D2K_P_YES;
        size_t n = d2k_compose(&pr, D2K_SHAPE_LEGACY, "", out, 8);
        CHECK(n == 0, "пустая строка decoy обязана трактоваться как «имени нет», а не как имя");
    }

    /* --- decoy длиннее буфера декой-приветствия: план пропускается ---------- */
    {
        char long_decoy[2000];
        memset(long_decoy, 'a', sizeof long_decoy - 1);
        long_decoy[sizeof long_decoy - 1] = '\0';
        d2k_props pr = {0};
        pr.parses_l7 = D2K_P_YES;
        size_t n = d2k_compose(&pr, D2K_SHAPE_MODERN, long_decoy, out, 8);
        CHECK(n == 0, "слишком длинный decoy обязан дать пропуск плеча, а не переполнение/усечение");
    }

    /* --- нулевые/негодные аргументы d2k_compose не падают и не пишут ------- */
    {
        CHECK(d2k_compose(NULL, D2K_SHAPE_LEGACY, decoy, out, 8) == 0, "pr==NULL обязан дать 0, а не падение");
    }
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        CHECK(d2k_compose(&pr, D2K_SHAPE_LEGACY, decoy, NULL, 8) == 0, "out==NULL обязан дать 0, а не падение");
    }

    /* ======================================================================
     * planlab: содержимое пяти TLV-планов зонда d2k_props_ask (ревью 11.09,
     * круг правок 1) — байты и порядок посылок, а не структурная валидность.
     *
     * Обмен на настоящем ctlprobe (блок ниже) НЕ зависит от содержимого
     * установленного плана — ctlprobe отвечает "reply", которую задаёт САМ
     * ТЕСТ, а не применение плана к синтетическому пакету. Значит порченный
     * бит порчи или переставленный порядок посылок там пройдёт молча (это
     * и произошло с мутациями 3 и 6 в первом отчёте задачи). planlab гоняет
     * ТОТ ЖЕ исполнитель, что и датапат (d2k_plan_load+d2k_plan_apply, см.
     * её шапку) — единственный способ проверить содержимое без второй его
     * реализации в тесте (§2.5 запрещает вторую реализацию преобразований).
     * ==================================================================== */
    {
        char tlvpath[128], scnpath[128], out[4096];

        /* --- перекрытие: один кусок, приставка 41 перед ВСЕЙ нагрузкой,
         * seq на 1 меньше начала — тот же байт, что видел бы сервер, минус
         * длина приставки. order лежит в TLV (байт-в-байт с Go: MarshalTLV
         * пишет recOrder БЕЗУСЛОВНО, см. большой комментарий у
         * overlap_plan_tlv в compose.c), но НАБЛЮДАЕМО НЕЙТРАЛЕН — проверено
         * ниже отдельно, до и после переворота бита руками. --------------- */
        {
            uint8_t plan[256]; size_t plen;
            CHECK(overlap_plan_tlv(plan, sizeof plan, &plen) == 0, "overlap_plan_tlv не собрался");
            snprintf(tlvpath, sizeof tlvpath, "/tmp/d2k-core-planlab-%d-overlap.tlv", (int)getpid());
            snprintf(scnpath, sizeof scnpath, "/tmp/d2k-core-planlab-%d-overlap.scn", (int)getpid());
            CHECK(write_file_bytes(tlvpath, plan, plen) == 0, "план перекрытия не записался");
            CHECK(write_file_text(scnpath, "pkt 5000 none 0 00010203040506070809\n") == 0,
                  "сценарий перекрытия не записался");
            CHECK(run_planlab(tlvpath, scnpath, out, sizeof out) == 0, "planlab (перекрытие) не запустился");
            CHECK(strstr(out, "emit payload 0 4999 ttl=0 poison=00 4100010203040506070809") != NULL,
                  "перекрытие: смещение/приставка/нагрузка не те, что должен выпустить исполнитель");
            CHECK(strstr(out, "fate drop") != NULL, "перекрытие: план обязан снять оригинал (fate drop)");
            CHECK(count_substr(out, "emit ") == 1, "перекрытие: ожидалась ровно одна посылка");
            unlink(tlvpath); unlink(scnpath);

            /* Мутация 3 (первый отчёт) — order forward→reverse на этом
               плане — здесь физически не может поймать себя: order у
               одиночного куска нагрузки нечего переставлять (datapath/
               plan_apply.c — цикл переворота меняет местами куски, а он
               ровно один). Утверждаем это, а не считаем на глаз. */
            uint8_t flipped[256]; size_t flen;
            memcpy(flipped, plan, plen); flen = plen;
            flipped[flen - 1] = (uint8_t)(flipped[flen - 1] ? 0 : 1); /* последний байт — значение REC_ORDER */
            char tlvpath2[128];
            snprintf(tlvpath2, sizeof tlvpath2, "/tmp/d2k-core-planlab-%d-overlap-flip.tlv", (int)getpid());
            CHECK(write_file_bytes(tlvpath2, flipped, flen) == 0, "перевёрнутый план перекрытия не записался");
            snprintf(scnpath, sizeof scnpath, "/tmp/d2k-core-planlab-%d-overlap.scn", (int)getpid());
            CHECK(write_file_text(scnpath, "pkt 5000 none 0 00010203040506070809\n") == 0,
                  "сценарий перекрытия (повтор) не записался");
            char out2[4096];
            CHECK(run_planlab(tlvpath2, scnpath, out2, sizeof out2) == 0,
                  "planlab (перекрытие, order перевёрнут) не запустился");
            CHECK(strcmp(out, out2) == 0,
                  "перекрытие: order оказался НЕ нейтральным — вывод изменился после переворота бита, "
                  "а комментарий у overlap_plan_tlv утверждает нейтральность");
            unlink(tlvpath2); unlink(scnpath);
        }

        /* --- порядок сегментов: три куска (payload_start+1, sni_middle),
         * ОБРАТНЫЙ порядок посылки — хвост, середина, голова. Здесь order
         * не нейтрален (кусков больше одного) — мутация "reverse→forward"
         * обязана быть видна как смена порядка эмиссии. --------------------- */
        {
            uint8_t plan[256]; size_t plen;
            CHECK(reorder_plan_tlv(plan, sizeof plan, &plen) == 0, "reorder_plan_tlv не собрался");
            snprintf(tlvpath, sizeof tlvpath, "/tmp/d2k-core-planlab-%d-reorder.tlv", (int)getpid());
            snprintf(scnpath, sizeof scnpath, "/tmp/d2k-core-planlab-%d-reorder.scn", (int)getpid());
            CHECK(write_file_bytes(tlvpath, plan, plen) == 0, "план порядка не записался");
            /* 20 байт 00..13, sni_off=10 sni_len=6 → sni_middle=10+3=13:
               разрезы {1,13} дают куски [0,1) [1,13) [13,20). */
            CHECK(write_file_text(scnpath,
                    "pkt 5000 10 6 000102030405060708090a0b0c0d0e0f10111213\n") == 0,
                  "сценарий порядка не записался");
            CHECK(run_planlab(tlvpath, scnpath, out, sizeof out) == 0, "planlab (порядок) не запустился");
            CHECK(count_substr(out, "emit ") == 3, "порядок: ожидались ровно три куска");
            CHECK(strstr(out, "fate drop") != NULL, "порядок: план обязан снять оригинал (fate drop)");
            /* Порядок эмиссии — хвост [13,20), середина [1,13), голова [0,1) —
               проверяется через ОТНОСИТЕЛЬНЫЕ позиции подстрок, а не только
               их наличие: три strstr по отдельности не отличили бы "хвост,
               середина, голова" от любой другой перестановки тех же трёх строк. */
            const char *tail = strstr(out, "emit payload 0 5013 ttl=0 poison=00 0d0e0f10111213");
            const char *mid  = strstr(out, "emit payload 0 5001 ttl=0 poison=00 0102030405060708090a0b0c");
            const char *head = strstr(out, "emit payload 0 5000 ttl=0 poison=00 00\n");
            CHECK(tail && mid && head, "порядок: не нашлись все три ожидаемых куска");
            if (tail && mid && head) {
                CHECK(tail < mid && mid < head,
                      "порядок: куски не в порядке хвост→середина→голова — мутация order "
                      "(или разрезов) обязана быть видна ровно здесь");
            }
            unlink(tlvpath); unlink(scnpath);
        }

        /* --- контрольная сумма/дубликаты/разбор протокола: общая форма
         * badsum_fake_plan_tlv. Мутация 6 (первый отчёт) — снятый бит
         * D2K_POISON_BADSUM — здесь виден напрямую в поле poison=, которое
         * planlab печатает из ТОГО ЖЕ d2k_emit.poison, что уйдёт на провод. */
        {
            snprintf(scnpath, sizeof scnpath, "/tmp/d2k-core-planlab-%d-fakes.scn", (int)getpid());
            CHECK(write_file_text(scnpath, "pkt 7000 none 0 aabbccdd\n") == 0,
                  "сценарий фальшивок не записался");

            /* контрольная сумма: набивка 64×0x41, один повтор, без разреза
               нагрузки — оригинал ПРОХОДИТ (fate pass), фальшивка идёт
               перед ним отдельной посылкой. */
            uint8_t plan[256]; size_t plen;
            CHECK(checksum_plan_tlv(plan, sizeof plan, &plen) == 0, "checksum_plan_tlv не собрался");
            snprintf(tlvpath, sizeof tlvpath, "/tmp/d2k-core-planlab-%d-checksum.tlv", (int)getpid());
            CHECK(write_file_bytes(tlvpath, plan, plen) == 0, "план суммы не записался");
            CHECK(run_planlab(tlvpath, scnpath, out, sizeof out) == 0, "planlab (сумма) не запустился");
            CHECK(count_substr(out, "emit ") == 1, "сумма: ожидалась ровно одна фальшивка");
            CHECK(strstr(out, "emit fake 0 7000 ttl=0 poison=01 ") != NULL,
                  "сумма: фальшивка не помечена битом порчи (poison=01) — мутация 6 обязана быть видна здесь");
            CHECK(count_substr(out, "41") >= 64, "сумма: набивка не похожа на 64 байта 0x41");
            CHECK(strstr(out, "fate pass") != NULL,
                  "сумма: план не разрезает нагрузку — оригинал обязан пройти (fate pass)");
            unlink(tlvpath);

            /* счёт дубликатов: та же control-приманка, ДВЕ копии, разрыв
               20000мкс — вторая посылка обязана нести именно эту задержку
               (первая посылка delay=0 по построению emit_fake). */
            static const uint8_t ctrl[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
            CHECK(badsum_fake_plan_tlv(ctrl, sizeof ctrl, 2, 20000, plan, sizeof plan, &plen) == 0,
                  "badsum_fake_plan_tlv (дубликаты) не собрался");
            snprintf(tlvpath, sizeof tlvpath, "/tmp/d2k-core-planlab-%d-dup.tlv", (int)getpid());
            CHECK(write_file_bytes(tlvpath, plan, plen) == 0, "план дубликатов не записался");
            CHECK(run_planlab(tlvpath, scnpath, out, sizeof out) == 0, "planlab (дубликаты) не запустился");
            CHECK(count_substr(out, "emit ") == 2, "дубликаты: ожидались ровно две фальшивки");
            CHECK(strstr(out, "emit fake 0 7000 ttl=0 poison=01 aabbccddeeff1122") != NULL,
                  "дубликаты: первая копия не та (задержка/содержимое/порча)");
            CHECK(strstr(out, "emit fake 20000 7000 ttl=0 poison=01 aabbccddeeff1122") != NULL,
                  "дубликаты: вторая копия без разрыва 20000мкс — repeats/gap_us перепутаны");
            CHECK(strstr(out, "fate pass") != NULL, "дубликаты: оригинал обязан пройти (fate pass)");
            unlink(tlvpath);

            /* разбор протокола: та же control-приманка, ОДНА копия, без
               разрыва — отличается от checksumPlan содержимым (control, не
               набивка), а не формой; здесь это и проверяется. */
            CHECK(badsum_fake_plan_tlv(ctrl, sizeof ctrl, 1, 0, plan, sizeof plan, &plen) == 0,
                  "badsum_fake_plan_tlv (разбор протокола) не собрался");
            snprintf(tlvpath, sizeof tlvpath, "/tmp/d2k-core-planlab-%d-parse.tlv", (int)getpid());
            CHECK(write_file_bytes(tlvpath, plan, plen) == 0, "план разбора протокола не записался");
            CHECK(run_planlab(tlvpath, scnpath, out, sizeof out) == 0, "planlab (разбор протокола) не запустился");
            CHECK(count_substr(out, "emit ") == 1, "разбор протокола: ожидалась ровно одна фальшивка");
            CHECK(strstr(out, "emit fake 0 7000 ttl=0 poison=01 aabbccddeeff1122") != NULL,
                  "разбор протокола: приманка не та (обязана быть control, не набивка суммы)");
            CHECK(strstr(out, "fate pass") != NULL, "разбор протокола: оригинал обязан пройти (fate pass)");
            unlink(tlvpath);
            unlink(scnpath);
        }
    }

    /* ======================================================================
     * d2k_props_ask — задача 5, шаг 0: настоящий оракул.
     * ==================================================================== */

    /* --- нечем спросить: защита входа БЕЗ сети (эти пути возвращают до
     * первой попытки I/O, поэтому валидный fd им не нужен вовсе, кроме
     * там, где нужно ИЗОЛИРОВАТЬ, что виновата не связь) --------------------- */
    {
        uint8_t tb[2048];
        d2k_hello trig = build_trigger(tb, sizeof tb, "guard.example");
        uint8_t cb[2048];
        d2k_hello ctl = build_trigger(cb, sizeof cb, "guard-control.example");
        CHECK(trig.bytes != NULL && ctl.bytes != NULL, "стенд build_trigger не собрался — проверки guard бессмысленны");

        d2k_props pr = d2k_props_ask(-1, "192.0.2.1", 443, trig, ctl, 0x2d);
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN &&
              pr.tolerates_reorder == D2K_P_UNKNOWN &&
              pr.validates_checksum == D2K_P_UNKNOWN &&
              pr.parses_l7 == D2K_P_UNKNOWN &&
              pr.counts_duplicates == D2K_P_UNKNOWN,
              "link_fd < 0 обязан дать вектор из одних D2K_P_UNKNOWN");

        d2k_hello empty = { NULL, 0 };
        pr = d2k_props_ask(-1, NULL, 0, empty, empty, 0);
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN &&
              pr.tolerates_reorder == D2K_P_UNKNOWN &&
              pr.validates_checksum == D2K_P_UNKNOWN &&
              pr.parses_l7 == D2K_P_UNKNOWN &&
              pr.counts_duplicates == D2K_P_UNKNOWN,
              "полностью вырожденный вход изменил вектор");
    }

    /* --- дальше всё против НАСТОЯЩЕГО ctlprobe и настоящей петли-мишени ---- */
    char sock_path[64];
    snprintf(sock_path, sizeof sock_path, "/tmp/d2k-core-compose-%d.sock", (int)getpid());
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

    struct stand st;
    memset(&st, 0, sizeof st);
    uint16_t stand_port = stand_start(&st, 0); /* mode 0 — отвечает всегда, см. test_stand.h */

    /* --- защита входа, ИЗОЛИРУЮЩАЯ причину: связь есть и годна, но не
     * годен один из остальных аргументов — тоже вектор из одних UNKNOWN,
     * а не наблюдение, будто коробка держит вообще всё --------------------- */
    {
        uint8_t tb[2048];
        d2k_hello trig = build_trigger(tb, sizeof tb, "guard2.example");
        d2k_hello empty = { NULL, 0 };

        d2k_props pr = d2k_props_ask(fd, NULL, 443, trig, empty, 0x2d);
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN && pr.parses_l7 == D2K_P_UNKNOWN,
              "ip == NULL при валидном fd всё равно обязан дать вектор из одних UNKNOWN");

        d2k_hello notrig = { NULL, 0 };
        pr = d2k_props_ask(fd, stand_port ? "127.0.0.1" : "127.0.0.1", stand_port, notrig, empty, 0x2d);
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN,
              "trigger без байт при валидных fd/ip обязан дать вектор из одних UNKNOWN");

        /* Триггер без извлекаемого SNI (не ClientHello вовсе) — d2k_hello_sni
           честно откажет, а не подставит первые байты за имя. */
        uint8_t garbage[32];
        memset(garbage, 0x99, sizeof garbage);
        d2k_hello notls = { garbage, sizeof garbage };
        pr = d2k_props_ask(fd, "127.0.0.1", stand_port, notls, empty, 0x2d);
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN,
              "триггер без извлекаемого SNI обязан дать вектор из одних UNKNOWN, а не имя из мусора");
        drain_all(fd); /* эти вызовы не должны были ничего послать, но убеждаемся, что очередь чиста для дальше */
    }

    /* --- ev_matches_flow напрямую: неупорядоченная пара, транспорт обязан
     * совпасть — прежде чем гонять сквозь весь d2k_props_ask, проверяем саму
     * сверку ключа на руками собранных значениях (находка 1 ревью 11.09). -- */
    {
        d2k_ev ev; memset(&ev, 0, sizeof ev);
        memcpy(ev.low_ip, (uint8_t[4]){1,2,3,4}, 4);
        memcpy(ev.high_ip, (uint8_t[4]){5,6,7,8}, 4);
        ev.low_port = 100; ev.high_port = 200; ev.transport = 6;

        d2k_flowkey k; memset(&k, 0, sizeof k);
        memcpy(k.a_ip, (uint8_t[4]){1,2,3,4}, 4); k.a_port = 100;
        memcpy(k.b_ip, (uint8_t[4]){5,6,7,8}, 4); k.b_port = 200;
        k.transport = 6;
        CHECK(ev_matches_flow(&ev, &k) == 1, "прямой порядок (a=low, b=high) не совпал");

        d2k_flowkey k2 = k;
        memcpy(k2.a_ip, (uint8_t[4]){5,6,7,8}, 4); k2.a_port = 200;
        memcpy(k2.b_ip, (uint8_t[4]){1,2,3,4}, 4); k2.b_port = 100;
        CHECK(ev_matches_flow(&ev, &k2) == 1, "обратный порядок (a=high, b=low) не совпал — ключ неупорядоченный");

        d2k_flowkey bad_ip = k; memcpy(bad_ip.a_ip, (uint8_t[4]){1,2,3,9}, 4);
        CHECK(ev_matches_flow(&ev, &bad_ip) == 0, "отличающийся ОДНИМ байтом адрес засчитан как совпадение");

        d2k_flowkey bad_port = k; bad_port.a_port = 101;
        CHECK(ev_matches_flow(&ev, &bad_port) == 0, "отличающийся порт засчитан как совпадение");

        d2k_flowkey bad_transport = k; bad_transport.transport = 17;
        CHECK(ev_matches_flow(&ev, &bad_transport) == 0,
              "разный транспорт (TCP-событие против UDP-ключа) засчитан как совпадение");
    }

    /* --- B1: первый вопрос (перекрытие) проходит немедленно — опрос
     * останавливается, второй вопрос не задаётся. Через поддельный конец
     * связи (socketpair), не через ctlprobe: см. большой комментарий перед
     * fakeend_run про то, почему настоящий ctlprobe не может дать событие с
     * ключом, который действительно совпадёт с настоящим соединением. ----- */
    {
        uint8_t tb[2048], cb[2048];
        d2k_hello trig = build_trigger(tb, sizeof tb, "b1.example");
        d2k_hello ctl = build_trigger(cb, sizeof cb, "b1-control.example");
        CHECK(trig.bytes && ctl.bytes, "build_trigger(b1) не собрался");

        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "b1: socketpair не создался");
        peerstand ps;
        uint16_t target_port = peerstand_start(&ps);

        int outcomes[] = { 1 }; /* первый вопрос проходит сразу */
        fakeend_args fa; memset(&fa, 0, sizeof fa);
        fa.fd = sv[1]; fa.ps = &ps; fa.target_port = target_port;
        fa.outcomes = outcomes; fa.n = 1; fa.foreign_before_round = -1;
        pthread_t th;
        CHECK(pthread_create(&th, NULL, fakeend_run, &fa) == 0, "b1: поддельный конец связи не запустился");

        d2k_props pr = d2k_props_ask(sv[0], "127.0.0.1", target_port, trig, ctl, 0);
        pthread_join(th, NULL);
        close(sv[0]); close(sv[1]); close(ps.listen_fd);

        CHECK(!fa.extra_round_seen, "b1: опрос продолжился после первого прохода — лишняя команда");
        CHECK(pr.tolerates_left_overlap == D2K_P_NO, "b1: перекрытие не записано по проходу");
        CHECK(pr.tolerates_reorder == D2K_P_UNKNOWN && pr.validates_checksum == D2K_P_UNKNOWN &&
              pr.parses_l7 == D2K_P_UNKNOWN && pr.counts_duplicates == D2K_P_UNKNOWN,
              "b1: опрос не остановился на первом проходе — задал вопрос, до которого не должен дойти");
    }

    /* --- B2: первый вопрос молчит содержательно (обмен есть, но без
     * прикладных данных), второй (счёт дубликатов, нужен control) проходит -- */
    {
        uint8_t tb[2048], cb[2048];
        d2k_hello trig = build_trigger(tb, sizeof tb, "b2.example");
        d2k_hello ctl = build_trigger(cb, sizeof cb, "b2-control.example");
        CHECK(trig.bytes && ctl.bytes, "build_trigger(b2) не собрался");

        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "b2: socketpair не создался");
        peerstand ps;
        uint16_t target_port = peerstand_start(&ps);

        int outcomes[] = { 0, 1 }; /* 1-й вопрос — рукопожатие без appdata (промах), 2-й проходит */
        fakeend_args fa; memset(&fa, 0, sizeof fa);
        fa.fd = sv[1]; fa.ps = &ps; fa.target_port = target_port;
        fa.outcomes = outcomes; fa.n = 2; fa.foreign_before_round = -1;
        pthread_t th;
        CHECK(pthread_create(&th, NULL, fakeend_run, &fa) == 0, "b2: поддельный конец связи не запустился");

        d2k_props pr = d2k_props_ask(sv[0], "127.0.0.1", target_port, trig, ctl, 0);
        pthread_join(th, NULL);
        close(sv[0]); close(sv[1]); close(ps.listen_fd);

        CHECK(!fa.extra_round_seen, "b2: опрос продолжился после второго прохода — лишняя команда");
        CHECK(pr.counts_duplicates == D2K_P_YES, "b2: счёт дубликатов не записан по проходу");
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN,
              "b2: промах первого вопроса записал что-то — промах обязан не писать НИЧЕГО (§2.4)");
        CHECK(pr.tolerates_reorder == D2K_P_UNKNOWN && pr.validates_checksum == D2K_P_UNKNOWN &&
              pr.parses_l7 == D2K_P_UNKNOWN,
              "b2: опрос не остановился на втором проходе");
    }

    /* --- C1 (находка 1 ревью 11.09): чужое событие обмена — ДАЖЕ с
     * прикладными данными — не подтверждает наш зонд, если своего обмена не
     * будет никогда. Без фильтра по ключу это ровно воспроизведение находки
     * ревьюера: "цель на недостижимом адресе, которая ни разу не ответила,
     * даёт tolerates_left_overlap = NO". Здесь цель ДОСТИЖИМА (соединение
     * состоится — props_ask_contact дойдёт до конца), но ответа от датапата
     * не будет никогда: разница не в достижимости, а в том, что событие с
     * чужим ключом лежит в очереди РЯДОМ с ожиданием. ------------------------ */
    {
        uint8_t tb[2048], cb[2048];
        d2k_hello trig = build_trigger(tb, sizeof tb, "c1.example");
        d2k_hello ctl = build_trigger(cb, sizeof cb, "c1-control.example");
        CHECK(trig.bytes && ctl.bytes, "build_trigger(c1) не собрался");

        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "c1: socketpair не создался");
        peerstand ps;
        uint16_t target_port = peerstand_start(&ps);

        int outcomes[] = { -1 }; /* своего обмена не будет никогда */
        fakeend_args fa; memset(&fa, 0, sizeof fa);
        fa.fd = sv[1]; fa.ps = &ps; fa.target_port = target_port;
        fa.outcomes = outcomes; fa.n = 1; fa.foreign_before_round = 0; /* чужое (с appdata) шлём */
        pthread_t th;
        CHECK(pthread_create(&th, NULL, fakeend_run, &fa) == 0, "c1: поддельный конец связи не запустился");

        d2k_props pr = d2k_props_ask(sv[0], "127.0.0.1", target_port, trig, ctl, 0);
        pthread_join(th, NULL);
        close(sv[0]); close(sv[1]); close(ps.listen_fd);

        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN,
              "c1: чужое событие обмена (appdata, чужой ключ) засчитано за свой зонд — находка 1 не закрыта");
    }

    /* --- C2 (находка 1 ревью 11.09, продолжение): чужое событие ПЕРЕД
     * своим не должно "съесть" опрос целиком — фильтр обязан пропустить
     * мимо чужое и всё равно дождаться СВОЕГО, а не просто отбрасывать все
     * подряд события без разбора. ------------------------------------------- */
    {
        uint8_t tb[2048], cb[2048];
        d2k_hello trig = build_trigger(tb, sizeof tb, "c2.example");
        d2k_hello ctl = build_trigger(cb, sizeof cb, "c2-control.example");
        CHECK(trig.bytes && ctl.bytes, "build_trigger(c2) не собрался");

        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "c2: socketpair не создался");
        peerstand ps;
        uint16_t target_port = peerstand_start(&ps);

        int outcomes[] = { 1 };
        fakeend_args fa; memset(&fa, 0, sizeof fa);
        fa.fd = sv[1]; fa.ps = &ps; fa.target_port = target_port;
        fa.outcomes = outcomes; fa.n = 1; fa.foreign_before_round = 0; /* чужое, затем своё */
        pthread_t th;
        CHECK(pthread_create(&th, NULL, fakeend_run, &fa) == 0, "c2: поддельный конец связи не запустился");

        d2k_props pr = d2k_props_ask(sv[0], "127.0.0.1", target_port, trig, ctl, 0);
        pthread_join(th, NULL);
        close(sv[0]); close(sv[1]); close(ps.listen_fd);

        CHECK(pr.tolerates_left_overlap == D2K_P_NO,
              "c2: своё событие обмена, пришедшее ПОСЛЕ чужого, не признано — фильтр отбрасывает лишнее");
    }

    /* --- B3: control недоступен — вопросы 2 и 5 пропускаются целиком (SET_NAME
     * для них не отправляется вовсе), оставшиеся три промахиваются, вектор
     * весь остаётся UNKNOWN; ПОСЛЕ вызова план последнего заданного вопроса
     * (контрольная сумма) всё ещё стоит РОВНО под этим именем — проверяем
     * САМОСТОЯТЕЛЬНО, что d2k_hello_sni извлёк то же имя, что использовал
     * build_trigger, а не подстроку по случайности. -------------------------- */
    {
        uint8_t tb[2048];
        d2k_hello trig = build_trigger(tb, sizeof tb, "b3.example");
        d2k_hello nodecoy = { NULL, 0 };
        CHECK(trig.bytes, "build_trigger(b3) не собрался");

        int replies[] = { 22, 22, 22 }; /* перекрытие, порядок, сумма — все промах */
        driver_args da = { &p, "b3.example", replies, 3, 300 };
        pthread_t th;
        CHECK(pthread_create(&th, NULL, driver_run, &da) == 0, "b3: ведущий поток не запустился");

        unsigned long long before = query_ok_cmds(&p);
        d2k_props pr = d2k_props_ask(fd, "127.0.0.1", stand_port, trig, nodecoy, 0);
        pthread_join(th, NULL);
        unsigned long long after = query_ok_cmds(&p);

        CHECK(after - before == 3, "b3: без control должны были встать ровно три плана "
                                    "(счёт дубликатов и разбор протокола — пропущены целиком)");
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN && pr.tolerates_reorder == D2K_P_UNKNOWN &&
              pr.validates_checksum == D2K_P_UNKNOWN && pr.parses_l7 == D2K_P_UNKNOWN &&
              pr.counts_duplicates == D2K_P_UNKNOWN,
              "b3: полный промах записал хоть что-то — отрицательный результат не должен сохраняться");
        drain_all(fd);

        /* Последний заданный вопрос — контрольная сумма — не снят: план
           остался стоять под именем "b3.example". Если бы d2k_props_ask
           перепутал имя (например, взял НЕ то, что дал d2k_hello_sni), это
           "hello" получило бы REFUSED, а не APPLIED. */
        (void)probe_say(&p, "hello b3.example");
        d2k_ev ev;
        CHECK(next_of_kind2(fd, D2K_EV_APPLIED, D2K_EV_REFUSED, 6, &ev, err, sizeof err) == 0,
              "b3: ни APPLIED, ни REFUSED не пришли после повторного hello");
        CHECK(ev.kind == D2K_EV_APPLIED,
              "b3: план стоит НЕ под тем именем, что дал d2k_hello_sni из триггера — REFUSED вместо APPLIED");
        drain_all(fd);
    }

    /* --- B4: пятый вопрос (разбор протокола) проходит последним — пишет ОБА
     * поля из ОДНОГО факта (parses_l7=YES И validates_checksum=NO), а не
     * только своё -------------------------------------------------------------- */
    {
        uint8_t tb[2048], cb[2048];
        d2k_hello trig = build_trigger(tb, sizeof tb, "b4.example");
        d2k_hello ctl = build_trigger(cb, sizeof cb, "b4-control.example");
        CHECK(trig.bytes && ctl.bytes, "build_trigger(b4) не собрался");

        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "b4: socketpair не создался");
        peerstand ps;
        uint16_t target_port = peerstand_start(&ps);

        int outcomes[] = { 0, 0, 0, 0, 1 };
        fakeend_args fa; memset(&fa, 0, sizeof fa);
        fa.fd = sv[1]; fa.ps = &ps; fa.target_port = target_port;
        fa.outcomes = outcomes; fa.n = 5; fa.foreign_before_round = -1;
        pthread_t th;
        CHECK(pthread_create(&th, NULL, fakeend_run, &fa) == 0, "b4: поддельный конец связи не запустился");

        d2k_props pr = d2k_props_ask(sv[0], "127.0.0.1", target_port, trig, ctl, 0);
        pthread_join(th, NULL);
        close(sv[0]); close(sv[1]); close(ps.listen_fd);

        CHECK(!fa.extra_round_seen, "b4: опрос продолжился после пятого раунда — лишняя команда");
        CHECK(pr.parses_l7 == D2K_P_YES, "b4: разбор протокола не записан по проходу");
        CHECK(pr.validates_checksum == D2K_P_NO,
              "b4: разбор протокола обязан писать ОБА поля из одного факта (properties.go), "
              "а validates_checksum не встал");
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN && pr.tolerates_reorder == D2K_P_UNKNOWN &&
              pr.counts_duplicates == D2K_P_UNKNOWN,
              "b4: промахи первых четырёх вопросов записали что-то лишнее");
    }

    d2k_link_close(fd);
    probe_stop(&p, sock_path);

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("compose: все проверки прошли\n");
    return 0;
}
