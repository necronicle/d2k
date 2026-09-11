/* d2kc.c — контроллер d2k на C: цикл событий поверх планировщика.
 *
 * Заменяет Go-процесс `d2k serve` (cmd/d2k, internal/controller). Делает ровно
 * три вещи и ничего сверх: держит связь с датапатом, отдаёт его события
 * планировщику (core/sched.c) и время от времени сохраняет каталог на диск.
 * Подбор, развилка по транспорту и запись знания — там, не здесь.
 *
 * ЦИКЛ НЕ БЛОКИРУЕТСЯ. poll() на двух дескрипторах: связь с датапатом и
 * будилка планировщика (рабочий поток, закончив сетевой оракул, пишет в неё
 * байт). Потолок ожидания — период тика: задачам нужно время, а не только
 * события (истёкшие сроки, отдых после неудачи), ровно та же причина, по
 * которой Go-сторона завела тикер рядом с событиями.
 *
 * КАТАЛОГ ПИШЕТСЯ АТОМАРНО. d2k_catalog_save пишет прямо в файл (см. её
 * doc-комментарий: атомарность в её контракт не входит и принадлежит тому,
 * кто решает КОГДА писать) — значит здесь: пишем во временный файл рядом,
 * fsync, rename. Оборванная запись каталога стоила бы всего накопленного
 * знания разом, а падение питания на роутере — обычное дело.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "d2k_sched.h"

/* Период тика. Унаследован с Go-стороны (controller.go: time.NewTicker(3 *
   time.Second)) и там же обоснован: счётчики ядра опрашиваются по часам, а не
   по событиям. Выдумывать здесь другое число запрещено правилом «числа только
   из замера или наследования». */
#define TICK_MS 3000

/* Как часто сохранять каталог. Реже тика: запись на флеш роутера — дорогая
   операция, а знание между сохранениями не теряется (оно в памяти), теряется
   только при падении. Минута — тот же порядок, что у Go-стороны. */
#define SAVE_EVERY_MS 60000

/* Как часто говорить, что видно. Чаще сохранения: это наблюдаемость, а не
   запись на флеш, и стоит она одной строки. */
#define REPORT_EVERY_MS 15000

/* Как часто обновлять вид для панели. Две секунды: человек, открывший панель,
   ждёт, что идущий поиск на ней виден, а не появится через минуту. Файл
   маленький и лежит на tmpfs-подобном разделе состояния. */
#define LIVE_EVERY_MS 2000

static volatile sig_atomic_t stop_asked;
static void on_signal(int sig) { (void)sig; stop_asked = 1; }

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Атомарное сохранение: временный файл рядом, затем rename. Рядом, а не в
   /tmp — rename между файловыми системами не работает, а /opt и /tmp на
   роутере разные (tmpfs). */
/* Потолок пути каталога. Не «сколько влезет»: err у вызывающего 512 байт, и
   путь обязан помещаться в сообщение об ошибке целиком — иначе причина отказа
   приезжает обрезанной ровно тогда, когда она нужна (gcc ловит это как
   format-truncation, цель cross). */
#define CATPATH_MAX 256

static int save_atomic(const d2k_catalog *cat, const char *path,
                       char *err, size_t errcap) {
    char tmp[CATPATH_MAX + 8];
    if (strlen(path) >= CATPATH_MAX) {
        snprintf(err, errcap, "путь каталога длиннее %d байт", CATPATH_MAX - 1);
        return -1;
    }
    int n = snprintf(tmp, sizeof tmp, "%s.new", path);
    if (n < 0 || (size_t)n >= sizeof tmp) {
        snprintf(err, errcap, "путь каталога не собрался");
        return -1;
    }
    if (d2k_catalog_save(cat, tmp, err, errcap) != 0) { return -1; }
    if (rename(tmp, path) != 0) {
        snprintf(err, errcap, "переименование %s: %s", tmp, strerror(errno));
        (void)remove(tmp);
        return -1;
    }
    return 0;
}

/* Печать планировщика. Со временем по стенным часам, а не монотонным: строку
   читает человек, и ему нужно сопоставить её с тем, что он делал. */
static void sched_say(void *ctx, const char *line) {
    (void)ctx;
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    printf("%02d:%02d:%02d %s\n", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, line);
    fflush(stdout);
}

static void usage(void) {
    fprintf(stderr,
        "использование: d2kc --control <сокет> [--catalog <файл>] [--mark 0x2d]\n"
        "  --control  управляющий сокет датапата (обязателен)\n"
        "  --catalog  где держать знание (умолчание /opt/d2k/catalog.json)\n"
        "  --live     куда писать вид для панели (умолчание — рядом с каталогом)\n"
        "  --mark     метка SO_MARK для зондов поиска (умолчание 0x2d)\n");
}

int main(int argc, char **argv) {
    const char *sock = NULL;
    const char *catpath = "/opt/d2k/catalog.json";
    const char *livepath = NULL;
    uint32_t mark = 0x2d;

    for (int i = 1; i < argc; i++) {
        const char *f = argv[i];
        if (strcmp(f, "--control") == 0 && i + 1 < argc) { sock = argv[++i]; }
        else if (strcmp(f, "--catalog") == 0 && i + 1 < argc) { catpath = argv[++i]; }
        else if (strcmp(f, "--live") == 0 && i + 1 < argc) { livepath = argv[++i]; }
        else if (strcmp(f, "--mark") == 0 && i + 1 < argc) {
            mark = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else {
            usage();
            return 2;
        }
    }
    if (!sock) { usage(); return 2; }

    /* Тот же приём, что в d2kd.c и ctlprobe.c: процесс не имеет права умирать
       оттого, что собеседник отвалился между записями. */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    d2k_catalog cat;
    memset(&cat, 0, sizeof cat);
    char err[512];
    if (d2k_catalog_load(catpath, &cat, err, sizeof err) != 0) {
        /* Каталога может не быть вовсе — это первый запуск, а не отказ.
           Отличить «нет файла» от «файл битый» обязательно: во втором случае
           молча начать с чистого листа значило бы потерять всё знание и не
           сказать об этом. */
        if (access(catpath, F_OK) == 0) {
            fprintf(stderr, "d2kc: каталог %s не разобрался: %s\n", catpath, err);
            return 1;
        }
        memset(&cat, 0, sizeof cat);
        printf("d2kc: каталога %s нет — начинаю с пустого\n", catpath);
    }

    int fd = d2k_link_open(sock, err, sizeof err);
    if (fd < 0) {
        fprintf(stderr, "d2kc: связь с датапатом %s: %s\n", sock, err);
        d2k_catalog_free(&cat);
        return 1;
    }

    d2k_sched *s = d2k_sched_new(&cat, fd, mark);
    if (!s) {
        fprintf(stderr, "d2kc: планировщик не завёлся\n");
        d2k_link_close(fd);
        d2k_catalog_free(&cat);
        return 1;
    }

    d2k_sched_set_say(s, sched_say, NULL);

    /* Знание из каталога — датапату СРАЗУ: он состояния между запусками не
       хранит, и без этого прохода каждая уже изученная цель начинала бы поиск
       заново. Сам проход идёт порциями в цикле ниже — залпом он создавал бы
       окно, в котором датапату некуда сказать про живой трафик. */
    (void)d2k_sched_sync(s);

    printf("d2kc: запущен, сокет %s, каталог %s (%zu коробок), метка 0x%x\n",
           sock, catpath, cat.n_boxes, (unsigned)mark);
    fflush(stdout);

    /* Счётчики событий. Заведены измеренной нуждой: первый живой прогон
       молчал, и отличить «датапат не подозревает» от «связь есть, а событий не
       идёт» было нечем — а это разные беды, одна про линию, другая про нас. */
    unsigned long seen_events = 0, seen_hello = 0, seen_suspect = 0;
    unsigned long seen_exchange = 0, seen_applied = 0, seen_refused = 0;
    int64_t last_report = now_ms();

    /* Путь вида для панели: рядом с каталогом, если не задан явно. Панель
       читает его и больше ничего о движке не знает (см. d2k_sched_write_live). */
    char livebuf[CATPATH_MAX + 16];
    if (!livepath) {
        const char *slash = strrchr(catpath, '/');
        size_t dirlen = slash ? (size_t)(slash - catpath + 1) : 0;
        if (dirlen < sizeof livebuf - 10) {
            memcpy(livebuf, catpath, dirlen);
            snprintf(livebuf + dirlen, sizeof livebuf - dirlen, "live.json");
            livepath = livebuf;
        }
    }
    int64_t last_live = 0;

    int64_t last_tick = now_ms(), last_save = last_tick;
    size_t dirty = 0;   /* сколько привязок было при последнем сохранении */
    size_t known = 0;
    for (size_t i = 0; i < cat.n_boxes; i++) { known += cat.boxes[i].n_binds; }
    dirty = known;

    while (!stop_asked) {
        struct pollfd pfd[2];
        pfd[0].fd = fd;                       pfd[0].events = POLLIN; pfd[0].revents = 0;
        pfd[1].fd = d2k_sched_wake_fd(s);     pfd[1].events = POLLIN; pfd[1].revents = 0;

        int64_t t = now_ms();
        int wait = (int)(TICK_MS - (t - last_tick));
        if (wait < 0) { wait = 0; }
        if (d2k_sched_sync_pending(s)) {
            /* Пока проход по каталогу не закончен, круг цикла не ждёт: каждая
               порция обязана идти сразу за чтением событий. */
            wait = 0;
        }
        int pr = poll(pfd, 2, wait);
        if (pr < 0 && errno != EINTR) {
            fprintf(stderr, "d2kc: poll: %s\n", strerror(errno));
            break;
        }

        if (pr > 0 && (pfd[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            /* Читаем всё, что уже пришло, а не по одному событию за круг:
               датапат за секунду присылает сотни наблюдений, и круг poll на
               каждое был бы чистой тратой. Нулевой потолок — «только то, что
               уже в буфере». */
            for (int i = 0; i < 256; i++) {
                d2k_ev ev;
                if (d2k_link_next(fd, &ev, 0, err, sizeof err) != 0) { break; }
                seen_events++;
                switch (ev.kind) {
                case D2K_EV_HELLO:    seen_hello++; break;
                case D2K_EV_SUSPECT:  seen_suspect++; break;
                case D2K_EV_EXCHANGE: seen_exchange++; break;
                case D2K_EV_APPLIED:  seen_applied++; break;
                case D2K_EV_REFUSED:  seen_refused++; break;
                default: break;
                }
                d2k_sched_event(s, &ev);
            }
        }

        /* Порция прохода по каталогу — ПОСЛЕ чтения событий и до следующего
           круга poll: так между командами всегда есть чтение, и датапату
           всегда есть куда сказать. */
        int more = d2k_sched_sync_step(s);

        t = now_ms();
        if (more || t - last_tick >= TICK_MS || (pr > 0 && (pfd[1].revents & POLLIN))) {
            d2k_sched_tick(s, t);
            last_tick = t;
        }

        if (t - last_report >= REPORT_EVERY_MS) {
            char line[300];
            snprintf(line, sizeof line,
                     "событий %lu (приветствий %lu, подозрений %lu, обменов %lu, "
                     "применений %lu, отказов %lu), поисков идёт %zu",
                     seen_events, seen_hello, seen_suspect, seen_exchange,
                     seen_applied, seen_refused, d2k_sched_active(s));
            sched_say(NULL, line);
            last_report = t;
        }

        if (livepath && t - last_live >= LIVE_EVERY_MS) {
            (void)d2k_sched_write_live(s, livepath, catpath);
            last_live = t;
        }

        if (t - last_save >= SAVE_EVERY_MS) {
            size_t n = 0;
            for (size_t i = 0; i < cat.n_boxes; i++) { n += cat.boxes[i].n_binds; }
            if (n != dirty) {
                if (save_atomic(&cat, catpath, err, sizeof err) != 0) {
                    fprintf(stderr, "d2kc: каталог не сохранён: %s\n", err);
                } else {
                    dirty = n;
                    printf("d2kc: каталог сохранён (%zu привязок)\n", n);
                    fflush(stdout);
                }
            }
            last_save = t;
        }
    }

    printf("d2kc: останавливаюсь\n");
    d2k_sched_free(s);
    size_t n = 0;
    for (size_t i = 0; i < cat.n_boxes; i++) { n += cat.boxes[i].n_binds; }
    if (n != dirty) {
        if (save_atomic(&cat, catpath, err, sizeof err) != 0) {
            fprintf(stderr, "d2kc: каталог не сохранён на выходе: %s\n", err);
        }
    }
    d2k_link_close(fd);
    d2k_catalog_free(&cat);
    return 0;
}
