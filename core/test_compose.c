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
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "d2k_compose.h"
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

    /* --- B1: первый вопрос (перекрытие) проходит немедленно — опрос
     * останавливается, второй вопрос не задаётся ---------------------------- */
    {
        uint8_t tb[2048], cb[2048];
        d2k_hello trig = build_trigger(tb, sizeof tb, "b1.example");
        d2k_hello ctl = build_trigger(cb, sizeof cb, "b1-control.example");
        CHECK(trig.bytes && ctl.bytes, "build_trigger(b1) не собрался");

        int replies[] = { 23 }; /* прикладные данные — проходит с первого раза */
        driver_args da = { &p, "b1.example", replies, 1, 300 };
        pthread_t th;
        CHECK(pthread_create(&th, NULL, driver_run, &da) == 0, "b1: ведущий поток не запустился");

        unsigned long long before = query_ok_cmds(&p);
        d2k_props pr = d2k_props_ask(fd, "127.0.0.1", stand_port, trig, ctl, 0);
        pthread_join(th, NULL);
        unsigned long long after = query_ok_cmds(&p);

        CHECK(after - before == 1, "b1: должен был встать ровно один план (первый вопрос), "
                                    "а не продолжить опрос дальше");
        CHECK(pr.tolerates_left_overlap == D2K_P_NO, "b1: перекрытие не записано по проходу");
        CHECK(pr.tolerates_reorder == D2K_P_UNKNOWN && pr.validates_checksum == D2K_P_UNKNOWN &&
              pr.parses_l7 == D2K_P_UNKNOWN && pr.counts_duplicates == D2K_P_UNKNOWN,
              "b1: опрос не остановился на первом проходе — задал вопрос, до которого не должен дойти");
        drain_all(fd);
    }

    /* --- B2: первый вопрос молчит содержательно (обмен есть, но без
     * прикладных данных), второй (счёт дубликатов, нужен control) проходит -- */
    {
        uint8_t tb[2048], cb[2048];
        d2k_hello trig = build_trigger(tb, sizeof tb, "b2.example");
        d2k_hello ctl = build_trigger(cb, sizeof cb, "b2-control.example");
        CHECK(trig.bytes && ctl.bytes, "build_trigger(b2) не собрался");

        int replies[] = { 22, 23 }; /* 1-й вопрос: рукопожатие без appdata — промах; 2-й: проходит */
        driver_args da = { &p, "b2.example", replies, 2, 300 };
        pthread_t th;
        CHECK(pthread_create(&th, NULL, driver_run, &da) == 0, "b2: ведущий поток не запустился");

        unsigned long long before = query_ok_cmds(&p);
        d2k_props pr = d2k_props_ask(fd, "127.0.0.1", stand_port, trig, ctl, 0);
        pthread_join(th, NULL);
        unsigned long long after = query_ok_cmds(&p);

        CHECK(after - before == 2, "b2: должны были встать ровно два плана (перекрытие промахнулось, "
                                    "дубликаты прошли)");
        CHECK(pr.counts_duplicates == D2K_P_YES, "b2: счёт дубликатов не записан по проходу");
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN,
              "b2: промах первого вопроса записал что-то — промах обязан не писать НИЧЕГО (§2.4)");
        CHECK(pr.tolerates_reorder == D2K_P_UNKNOWN && pr.validates_checksum == D2K_P_UNKNOWN &&
              pr.parses_l7 == D2K_P_UNKNOWN,
              "b2: опрос не остановился на втором проходе");
        drain_all(fd);
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

        int replies[] = { 22, 22, 22, 22, 23 };
        driver_args da = { &p, "b4.example", replies, 5, 300 };
        pthread_t th;
        CHECK(pthread_create(&th, NULL, driver_run, &da) == 0, "b4: ведущий поток не запустился");

        unsigned long long before = query_ok_cmds(&p);
        d2k_props pr = d2k_props_ask(fd, "127.0.0.1", stand_port, trig, ctl, 0);
        pthread_join(th, NULL);
        unsigned long long after = query_ok_cmds(&p);

        CHECK(after - before == 5, "b4: должны были встать все пять планов подряд");
        CHECK(pr.parses_l7 == D2K_P_YES, "b4: разбор протокола не записан по проходу");
        CHECK(pr.validates_checksum == D2K_P_NO,
              "b4: разбор протокола обязан писать ОБА поля из одного факта (properties.go), "
              "а validates_checksum не встал");
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN && pr.tolerates_reorder == D2K_P_UNKNOWN &&
              pr.counts_duplicates == D2K_P_UNKNOWN,
              "b4: промахи первых четырёх вопросов записали что-то лишнее");
        drain_all(fd);
    }

    d2k_link_close(fd);
    probe_stop(&p, sock_path);

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("compose: все проверки прошли\n");
    return 0;
}
