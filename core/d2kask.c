/* d2kask.c — командная утилита: спросить настоящую коробку DPI с командной
 * строки, на живой линии, без планировщика (задача 5в).
 *
 * ЗАЧЕМ. Всё, что написано на C в этой вертикали, до сих пор проверялось
 * только против planlab (исполнитель плана), ctlprobe (протокол) и петли
 * 127.0.0.1 (механика, test_stand.h) — они доказывают, что механизм СОБРАН
 * верно, и ничего не говорят о том, что он МЕРИТ верно на настоящей линии.
 * Эта утилита — первый инструмент, которым замысел (§3 спеки: "libd2k — то
 * же ядро библиотекой, линкуется и в d2kc, И В КОМАНДНУЮ СТРОКУ") можно
 * проверить на живой коробке, не дожидаясь планировщика.
 *
 * ТОНКАЯ ОБЁРТКА, И ЭТО НАМЕРЕННО. Разбор аргументов, d2k_link_open,
 * получение снимка приветствия (arm+wait ИЛИ hex-файл), d2k_props_ask,
 * d2k_compose, печать — и больше НИЧЕГО своего про то, чем коробка отвечает
 * на TCP-манипуляции: вторая реализация той же логики замера рядом с
 * d2k_props_ask рано или поздно разойдётся с первой (см. её же doc-комментарий
 * в d2k_compose.h). Единственная логика, которая здесь ЕСТЬ своя, —
 * разбор argv, чтение hex-файла и то, как честно ПОКАЗАТЬ человеку то, что
 * вернула библиотека: это печать, а не замер.
 *
 * ПОЧЕМУ ПЕЧАТЬ ЗАДАННОГО/НЕЗАДАННОГО ВОПРОСА — СВОЯ ЛОГИКА, А НЕ ПОДГЛЯДЫВАНИЕ
 * ВНУТРЬ d2k_props_ask. Сам вызов отдаёт только итоговый вектор (d2k_props) —
 * пять значений тройственной логики, без трассировки того, какой из пяти
 * зондов на самом деле дошёл до провода. Различить "вопрос не задан" от
 * "задан, но не получил однозначного ответа" эта утилита обязана (главное
 * требование к выводу, task-5v-brief.md) — и делает это ТОЛЬКО из фактов,
 * задокументированных в ПУБЛИЧНОМ контракте d2k_props_ask (d2k_compose.h),
 * а не из догадок о её внутренностях:
 *   1. "Счёт дубликатов" и "разбор протокола" нуждаются в control-приветствии
 *      и пропускаются целиком без него (см. doc-комментарий d2k_props_ask,
 *      абзац про вопрос 2/5).
 *   2. "Первый ПРОШЕДШИЙ вопрос обрывает опрос" (там же) — значит, если
 *      более ранний по порядку опроса вопрос получил да/нет, все более
 *      поздние заведомо не заданы.
 *   3. "Свойство пишется ТОЛЬКО по проходу вопроса" (там же) — значит, что
 *      НЕ-неизмеренное значение поля гарантированно означает "план встал,
 *      обмен был, с прикладными данными": это не подсмотрено, а прямое
 *      следствие контракта.
 *   4. Вопрос "разбор протокола" пишет ОБА поля (parses_l7 и
 *      validates_checksum) из ОДНОГО факта — если разбор протокола решён
 *      (YES), то "контрольная сумма" не была задана САМА ПО СЕБЕ, даже если
 *      её поле тоже стало НЕТ: это побочный эффект, а не отдельный проход
 *      (см. compose.c про "разбор протокола пишет ОБА поля из ОДНОГО факта").
 * Из (1)-(4) позиция вопроса в фиксированном порядке опроса
 * [overlap, duplicates, reorder, checksum, parse_l7] и текущий вектор ЦЕЛИКОМ
 * определяют "задан/не задан" без единого обращения к сети сверх того ОДНОГО
 * вызова d2k_props_ask, который уже сделан.
 *
 * "МЕТКА" НИКОГДА НЕ СТАВИТСЯ, И ЭТО НЕ ДЫРА, А РЕШЕНИЕ (doc-комментарий
 * d2k_props_ask, компонент mark; props_ask_contact, compose.c). Опрос
 * свойств сам только что поставил план-кандидат, которому предстоит
 * применить датапат, — если бы обращение к цели шло с той же меткой, что
 * боевой зонд дерева вердиктов, files/S99d2k увело бы помеченный пакет мимо
 * NFQUEUE (первое правило исходящей цепочки), план-кандидат остался бы
 * неприложенным, а ответ на ГОЛОЕ приветствие засчитался бы за ответ на
 * приём. Значит --mark принимается интерфейсом ради единообразия с
 * d2k_classify, но этим зондом заведомо не применяется НИКОГДА — утилита
 * печатает "метка: не ставится" как известный факт, а не как "не измерено":
 * тройственная логика здесь неприменима, потому что здесь нет неизвестности.
 *
 * ДВА ДОЛГА ИЗ ШАПКИ d2k_props_ask (d2k_compose.h), КОТОРЫЕ ЭТА УТИЛИТА
 * ОБЯЗАНА ПОКАЗЫВАТЬ, А НЕ СКРЫВАТЬ:
 *   (а) потолок ожидания D2K_PROPS_ASK_WAIT_MS (compose.c, 5000мс) — одно
 *       унаследованное число и на локальный ACK (AF_UNIX), и на сетевой
 *       обмен, не измеренное для этого применения;
 *   (б) если ни один из пяти вопросов не прошёл, d2k_props_ask снимает план
 *       последнего заданного зонда (D2K_CMD_DEL_NAME) — то есть после такого
 *       прогона на датапате НЕ остаётся плана, про который это же измерение
 *       только что сказало «не работает». Печатается, потому что это
 *       изменение состояния БОЕВОГО датапата, а не внутреннее дело утилиты.
 * (б) печатается ТОЛЬКО когда применимо (полностью неизмеренный итоговый
 * вектор при заданном хотя бы одном вопросе) — печатать её всегда было бы
 * тем же самым грехом наоборот: неприменимое предупреждение так же вводит в
 * заблуждение, как скрытое применимое.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "d2k_compose.h"
#include "d2k_hello.h"
#include "d2k_link.h"
#include "d2k_meas.h"

/* --------------------------------------------------------------------
 * Разбор аргументов.
 * -------------------------------------------------------------------- */

#define D2KASK_DEFAULT_PORT 443

typedef struct {
    const char *control_path;
    const char *ip;
    const char *sni;
    const char *control_sni;
    const char *hello_hex_path;
    const char *control_hex_path;
    const char *save_trigger_path;
    const char *save_control_path;
    const char *port_raw;
    const char *mark_raw;
    const char *arm_wait_raw;
    uint16_t    port;
    uint32_t    mark;
    long        arm_wait_ms;
} cli_args;

static const char D2KASK_USAGE[] =
    "использование: d2kask --control <сокет> --ip <адрес> --sni <имя> "
    "(--hello-hex <файл> | --arm-wait-ms <мс>) [--port 443] "
    "[--control-sni <имя>] [--control-hex <файл>] [--mark 0x2d] "
    "[--save-trigger <файл>] [--save-control <файл>]";

/* Проверяет, что у флага f (argv[i]) есть следующий токен-значение.
 * Отсутствие значения — отказ с причиной, а не чтение argv за границей. */
static int need_value(int argc, char **argv, int i, const char *f,
                      char *err, size_t errcap) {
    (void)argv;
    if (i + 1 >= argc) {
        snprintf(err, errcap, "%s требует значения", f);
        return -1;
    }
    return 0;
}

/* Разбирает беззнаковое число флага в [1, max], базой 10 (--port). Пустая
 * строка, минус, хвост из недопустимых символов и переполнение — отказ:
 * молчаливое округление до похожего числа было бы той же тихой подменой,
 * которую весь этот проект отвергает на уровне протокола. */
static int parse_flag_u16(const char *s, const char *flag, unsigned long max,
                          uint16_t *out, char *err, size_t errcap) {
    if (!s || s[0] == '\0' || s[0] == '-') {
        snprintf(err, errcap, "%s не число 1..%lu: %s", flag, max, s ? s : "");
        return -1;
    }
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (*end != '\0' || errno == ERANGE || v == 0 || v > max) {
        snprintf(err, errcap, "%s не число 1..%lu: %s", flag, max, s);
        return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

/* --mark: та же запись, что везде на проводе этого дерева для меток —
 * strtoul с базой 0 (0x... — hex, как в примере интерфейса; 0 в начале без
 * 'x' — восьмеричное, обычная семантика strtoul, не "на глаз"; иначе
 * десятичное). Отрицательные значения запрещены явно — strtoul бы принял
 * "-1" как гигантское беззнаковое, что для метки бессмысленно и опаснее
 * тихой ошибки, чем явный отказ. */
static int parse_flag_u32(const char *s, const char *flag, uint32_t *out,
                          char *err, size_t errcap) {
    if (!s || s[0] == '\0' || s[0] == '-') {
        snprintf(err, errcap, "%s не число: %s", flag, s ? s : "");
        return -1;
    }
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 0);
    if (*end != '\0' || errno == ERANGE) {
        snprintf(err, errcap, "%s не число: %s", flag, s);
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

/* --arm-wait-ms: положительное целое миллисекунд (d2k_link_next трактует
 * отрицательное как "ждать бесконечно", а 0 как "не ждать вовсе" — этой
 * утилите не годится ни то, ни другое: висящий без обратной связи CLI и
 * гарантированный "не получено" одинаково не те повадки, что нужны на
 * живой линии). */
static int parse_flag_ms(const char *s, const char *flag, long *out,
                         char *err, size_t errcap) {
    if (!s || s[0] == '\0' || s[0] == '-') {
        snprintf(err, errcap, "%s не положительное целое (мс): %s", flag, s ? s : "");
        return -1;
    }
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || errno == ERANGE || v <= 0) {
        snprintf(err, errcap, "%s не положительное целое (мс): %s", flag, s);
        return -1;
    }
    *out = v;
    return 0;
}

/* Разбирает argv целиком в cli_args. Возвращает 0/-1 (причина в err).
 * Порядок проверок: сначала синтаксис (неизвестный флаг, флаг без
 * значения), потом обязательные аргументы, потом взаимоисключающие пары —
 * КАЖДАЯ проверка отказывает независимо от остальных (не "первая находка
 * скрывает остальные бессистемно", а фиксированный порядок, который тесты
 * проверяют по имени причины). */
static int parse_args(int argc, char **argv, cli_args *a, char *err, size_t errcap) {
    memset(a, 0, sizeof *a);

    if (argc <= 1) {
        snprintf(err, errcap, "%s", D2KASK_USAGE);
        return -1;
    }

    for (int i = 1; i < argc; i++) {
        const char *f = argv[i];
        if (strcmp(f, "--control") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->control_path = argv[++i];
        } else if (strcmp(f, "--ip") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->ip = argv[++i];
        } else if (strcmp(f, "--port") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->port_raw = argv[++i];
        } else if (strcmp(f, "--sni") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->sni = argv[++i];
        } else if (strcmp(f, "--control-sni") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->control_sni = argv[++i];
        } else if (strcmp(f, "--mark") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->mark_raw = argv[++i];
        } else if (strcmp(f, "--hello-hex") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->hello_hex_path = argv[++i];
        } else if (strcmp(f, "--save-trigger") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->save_trigger_path = argv[++i];
        } else if (strcmp(f, "--save-control") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->save_control_path = argv[++i];
        } else if (strcmp(f, "--control-hex") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->control_hex_path = argv[++i];
        } else if (strcmp(f, "--arm-wait-ms") == 0) {
            if (need_value(argc, argv, i, f, err, errcap) != 0) { return -1; }
            a->arm_wait_raw = argv[++i];
        } else {
            snprintf(err, errcap, "неизвестный аргумент: %s", f);
            return -1;
        }
    }

    if (!a->control_path || !a->control_path[0]) {
        snprintf(err, errcap, "обязателен --control <путь к управляющему сокету датапата>");
        return -1;
    }
    if (!a->ip || !a->ip[0]) {
        snprintf(err, errcap, "обязателен --ip <адрес цели>");
        return -1;
    }
    if (!a->sni || !a->sni[0]) {
        snprintf(err, errcap, "обязателен --sni <имя цели>");
        return -1;
    }
    if (a->hello_hex_path && a->arm_wait_raw) {
        snprintf(err, errcap,
                "--hello-hex и --arm-wait-ms взаимоисключающие: снимок приветствия "
                "берётся ОДНИМ способом");
        return -1;
    }
    if (!a->hello_hex_path && !a->arm_wait_raw) {
        snprintf(err, errcap,
                "нужен один способ снять приветствие: --hello-hex <файл> или "
                "--arm-wait-ms <мс>");
        return -1;
    }
    if (a->control_hex_path && a->control_sni) {
        snprintf(err, errcap,
                "--control-hex и --control-sni взаимоисключающие: control-приветствие "
                "берётся ОДНИМ способом");
        return -1;
    }
    if (a->control_sni && !a->arm_wait_raw) {
        snprintf(err, errcap,
                "--control-sni требует --arm-wait-ms: армирование ловушки нуждается "
                "в потолке ожидания, а в режиме --hello-hex он не задан");
        return -1;
    }

    a->port = D2KASK_DEFAULT_PORT;
    if (a->port_raw && parse_flag_u16(a->port_raw, "--port", 65535, &a->port, err, errcap) != 0) {
        return -1;
    }
    a->mark = 0;
    if (a->mark_raw && parse_flag_u32(a->mark_raw, "--mark", &a->mark, err, errcap) != 0) {
        return -1;
    }
    if (a->arm_wait_raw && parse_flag_ms(a->arm_wait_raw, "--arm-wait-ms", &a->arm_wait_ms, err, errcap) != 0) {
        return -1;
    }

    return 0;
}

/* --------------------------------------------------------------------
 * Снимок приветствия: из hex-файла или из живой ловушки датапата.
 * -------------------------------------------------------------------- */

/* Потолок формы приветствия — тот же, что D2K_EV_SHAPE.shape (d2k_link.h,
 * uint8_t shape[2048]): общего именованного символа на этот предел нет
 * (в d2k_link.h он зашит инлайн в поле структуры), поэтому здесь он назван
 * тем же приёмом, что и planbuf в compose.c ("control до 2048 байт (потолок
 * D2K_EV_SHAPE.shape, d2k_link.h)") — документированным числом, а не общим
 * заголовком, которого у этого предела нет ни у кого. */
#define D2KASK_HELLO_CAP 2048

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/* Сохраняет снятый снимок в тот же формат, который читает read_hex_file выше
 * (комментарий на '#', затем шестнадцатеричные цифры) — чтобы следующий
 * прогон брал его через --hello-hex/--control-hex и не ждал заново живого
 * трафика. Причина прямая: армирование стоит окна ожидания и РУЧНОГО захода
 * на цель, и платить эту цену на каждый повтор одного и того же измерения
 * незачем. Отказ записи не прерывает измерение — снимок уже в памяти, и
 * потерять из-за него живой прогон было бы хуже, чем не сохранить файл. */
static void save_hex(const char *path, const char *what, const char *sni,
                     const uint8_t *b, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "d2kask: снимок %s не сохранён в %s: %s\n", what, path, strerror(errno));
        return;
    }
    fprintf(f, "# снимок %s, имя %s, %zu байт — снят d2kask с живого датапата\n",
            what, sni && sni[0] ? sni : "(без имени)", n);
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%02x", b[i]);
        if ((i + 1) % 32 == 0) { fputc('\n', f); }
    }
    if (n % 32 != 0) { fputc('\n', f); }
    if (fclose(f) != 0) {
        fprintf(stderr, "d2kask: снимок %s записан не полностью в %s: %s\n",
                what, path, strerror(errno));
        return;
    }
    printf("снимок %s сохранён: %s (%zu байт)\n", what, path, n);
}

/* Читает шестнадцатеричный снимок из файла той же условности, что
 * core/profiles/ (файлы .hex, см. core/Makefile, правило hello_profiles.inc):
 * строки, начинающиеся с '#' после пробелов, — комментарий и пропускаются
 * целиком; в остальных строках допустимы только шестнадцатеричные цифры и
 * пробельные символы. Никакой символ не отбрасывается молча за пределами
 * этих двух правил: тихая подмена содержимого — тот же грех, что пересборка
 * приветствия, против которой возражает всё это дерево (см. шапку
 * d2k_meas.h). Возвращает 0 и заполняет *out_len при успехе, -1 иначе
 * (причина в err): файл не открылся, недопустимый символ, нечётное число
 * цифр, пустой снимок, снимок длиннее cap. */
static int read_hex_file(const char *path, uint8_t *out, size_t cap,
                         size_t *out_len, char *err, size_t errcap) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(err, errcap, "открыть не удалось: %s", strerror(errno));
        return -1;
    }
    char line[8200]; /* cap(2048)*2 hex-цифр с большим запасом на \r\n */
    int hi = -1;
    size_t hexdigits = 0;
    size_t nbytes = 0;
    int rc = 0;
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') { p++; }
        if (*p == '#') { continue; }
        for (; *p; p++) {
            char c = *p;
            if (c == '\n' || c == '\r' || c == ' ' || c == '\t') { continue; }
            int v = hex_nibble((unsigned char)c);
            if (v < 0) {
                snprintf(err, errcap, "недопустимый символ '%c' (не шестнадцатеричная цифра)", c);
                rc = -1;
                goto out;
            }
            hexdigits++;
            if (hi < 0) {
                hi = v;
            } else {
                if (nbytes >= cap) {
                    snprintf(err, errcap, "снимок больше потолка формы приветствия (%zu байт)", cap);
                    rc = -1;
                    goto out;
                }
                out[nbytes++] = (uint8_t)((hi << 4) | v);
                hi = -1;
            }
        }
    }
    if (hexdigits % 2 != 0) {
        snprintf(err, errcap, "нечётное число шестнадцатеричных цифр (%zu)", hexdigits);
        rc = -1;
        goto out;
    }
    if (nbytes == 0) {
        snprintf(err, errcap, "файл пуст (0 байт)");
        rc = -1;
        goto out;
    }
    *out_len = nbytes;
out:
    fclose(f);
    return rc;
}

/* Ждёт D2K_EV_SHAPE не дольше wait_ms суммарно, пропуская мимо остальные
 * события, — тот же приём и та же причина, что wait_for_event в compose.c:
 * датапат волен прислать что угодно ещё (HELLO/SUSPECT/EXCHANGE от чужого
 * трафика на живом роутере), пока мы ждём именно форму, и число попыток
 * ничего не говорит о реальной длительности, в отличие от бюджета по
 * времени. Возвращает 0 (форма получена, out/out_len заполнены), 1
 * (тайм-аут всего бюджета — НЕ получено, и это не ошибка: устройство в сети
 * могло просто не обратиться к имени), -1 (ошибка связи, причина в err). */
static int wait_shape(int fd, long wait_ms, uint8_t *out, size_t cap,
                      size_t *out_len, char *err, size_t errcap) {
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - t0.tv_sec) * 1000L +
                          (now.tv_nsec - t0.tv_nsec) / 1000000L;
        if (elapsed_ms < 0) { elapsed_ms = 0; }
        if (elapsed_ms >= wait_ms) { return 1; }
        d2k_ev ev;
        int rc = d2k_link_next(fd, &ev, (int)(wait_ms - elapsed_ms), err, errcap);
        if (rc < 0) { return -1; }
        if (rc == 1) { continue; } /* тайм-аут этого чтения — бюджет проверит цикл */
        if (ev.kind == D2K_EV_SHAPE) {
            if (ev.shape_len > cap) {
                /* Недостижимо на сегодняшнем проводе (d2k_ev.shape тоже
                   2048 байт, d2k_link.h, и d2k_link_next сам отказывает на
                   более длинном кадре) — отказ вслух, а не молчаливое
                   усечение, если этот инвариант когда-нибудь разойдётся. */
                snprintf(err, errcap, "форма приветствия (%zu байт) больше буфера (%zu)",
                         ev.shape_len, cap);
                return -1;
            }
            memcpy(out, ev.shape, ev.shape_len);
            *out_len = ev.shape_len;
            return 0;
        }
        /* не тот вид события — пропускаем мимо, ждём остаток бюджета */
    }
}

/* --------------------------------------------------------------------
 * Печать. Всё, что ниже, ТОЛЬКО показывает то, что уже вычислено выше и в
 * библиотеке — ни сокетов, ни таймеров, ни решений о коробке здесь нет.
 * -------------------------------------------------------------------- */

static const char *pval_str(d2k_pval v) {
    switch (v) {
    case D2K_P_YES: return "да";
    case D2K_P_NO: return "нет";
    default: return "не измерено";
    }
}

static void print_header(const cli_args *a) {
    printf("d2kask: спрашиваем настоящую коробку DPI\n\n");
    printf("цель: %s:%u\n", a->ip, (unsigned)a->port);
    printf("имя (--sni): %s\n", a->sni);
    printf("управляющий сокет: %s\n", a->control_path);
    printf("метка (--mark): 0x%x\n", (unsigned)a->mark);
}

/* Печатает отчёт об ОДНОМ снимке (триггера или control): как получен,
 * сколько байт, и — если применимо — извлечённое имя и вид приветствия.
 * label — "триггера" или "control", склоняется вызывающим в самих строках
 * шаблона ниже, поэтому передаётся именно в этой форме. */
static void print_snapshot(const char *label, int have_bytes, int timed_out,
                           const char *how, const char *detail,
                           const uint8_t *buf, size_t len) {
    if (have_bytes) {
        printf("снимок %s: %s (%s), %zu байт\n", label, how, detail, len);
        size_t off = 0, sl = 0;
        if (d2k_hello_sni(buf, len, &off, &sl) == 0 && sl > 0 && sl < 256) {
            printf("  SNI в снимке: %.*s\n", (int)sl, buf + off);
        } else {
            printf("  SNI в снимке: НЕ НАЙДЕНО\n");
        }
        d2k_shape sh = d2k_hello_shape(buf, len);
        printf("  вид приветствия: %s\n",
              sh == D2K_SHAPE_MODERN ? "MODERN" : sh == D2K_SHAPE_LEGACY ? "LEGACY" : "UNKNOWN");
    } else if (timed_out) {
        printf("снимок %s: %s (%s) — НЕ ПОЛУЧЕН (D2K_EV_SHAPE не пришло за отведённое время)\n",
              label, how, detail);
    } else {
        printf("снимок %s: %s (%s) — НЕ ПОЛУЧЕН\n", label, how, detail);
    }
}

/* Позиция в фиксированном порядке опроса d2k_props_ask: 0 перекрытие слева,
 * 1 счёт дубликатов, 2 порядок сегментов, 3 контрольная сумма, 4 разбор
 * протокола (см. её doc-комментарий в d2k_compose.h и цикл в compose.c). */
enum { POS_OVERLAP = 0, POS_DUP = 1, POS_REORDER = 2, POS_CHECKSUM = 3, POS_PARSE = 4 };

/* Решено ли положение pos САМО ПО СЕБЕ (т.е. итоговое поле, за которое оно
 * отвечает, не D2K_P_UNKNOWN) — за вычетом случая, когда НЕТ (checksum),
 * записанного как ПОБОЧНЫЙ эффект прохода "разбора протокола" (см. большой
 * комментарий в шапке файла, пункт 4): если parses_l7 сам решён, то любое
 * значение validates_checksum принадлежит ЕМУ, а не отдельному проходу
 * вопроса про сумму — иначе один и тот же факт посчитался бы дважды. */
static int pos_decided(const d2k_props *pr, int pos) {
    switch (pos) {
    case POS_OVERLAP: return pr->tolerates_left_overlap != D2K_P_UNKNOWN;
    case POS_DUP: return pr->counts_duplicates != D2K_P_UNKNOWN;
    case POS_REORDER: return pr->tolerates_reorder != D2K_P_UNKNOWN;
    case POS_CHECKSUM: return pr->validates_checksum != D2K_P_UNKNOWN && pr->parses_l7 != D2K_P_YES;
    case POS_PARSE: return pr->parses_l7 != D2K_P_UNKNOWN;
    default: return 0;
    }
}

static d2k_pval pos_value(const d2k_props *pr, int pos) {
    switch (pos) {
    case POS_OVERLAP: return pr->tolerates_left_overlap;
    case POS_DUP: return pr->counts_duplicates;
    case POS_REORDER: return pr->tolerates_reorder;
    case POS_CHECKSUM: return pr->validates_checksum;
    case POS_PARSE: return pr->parses_l7;
    default: return D2K_P_UNKNOWN;
    }
}

/* Расшифровка шага трассы: КАКИМ местом вопрос не состоялся. Печатается
 * вместо прежнего "неизвестно снаружи" — первый живой прогон (11.09,
 * www.instagram.com) вернул "не измерено" по всем трём заданным вопросам, и
 * различить "коробка заблокировала манипуляцию" от "план вообще не встал"
 * было нечем. Это диагностика нашего зонда, а не четвёртое состояние
 * вектора: тройственная логика §2.4 остаётся ровно такой же. */
static const char *step_rc_str(d2k_step_rc rc) {
    switch (rc) {
    case D2K_STEP_NOT_ASKED:    return "вопрос не собран";
    case D2K_STEP_SEND_FAIL:    return "SET_NAME не ушёл в сокет";
    case D2K_STEP_NO_ACK:       return "подтверждение SET_NAME не пришло в срок";
    case D2K_STEP_REFUSED:      return "датапат отверг план";
    case D2K_STEP_CONTACT_FAIL: return "обращение к цели не состоялось";
    case D2K_STEP_NO_EXCHANGE:  return "своего обмена не было в срок";
    case D2K_STEP_NO_APPDATA:   return "обмен был, но без прикладных данных (§8)";
    case D2K_STEP_PASSED:       return "прошёл";
    }
    return "неизвестно";
}

/* Код отказа датапата словами (d2k_ctl.h). Печатается только при ack_ok==0 —
 * на проводе reason значим ровно там же. */
static const char *ack_code_str(uint8_t code) {
    switch (code) {
    case D2K_ACK_OK:        return "принято";
    case D2K_ACK_BAD_PLAN:  return "план не разобрался";
    case D2K_ACK_BAD_ARGS:  return "аргументы команды не разобрались";
    case D2K_ACK_NO_ROOM:   return "нет места в таблице планов";
    }
    return "неизвестная причина";
}

/* Типы TLS-записей, встреченных в обмене, — из маски в текст. §8: порог —
 * запись типа 23; остальные типы печатаются, потому что именно они
 * отличают "коробка молчит" от "сервер ответил, но до прикладных данных
 * дело не дошло". */
static void print_seen_types(uint8_t mask) {
    static const struct { uint8_t t; const char *n; } names[] = {
        { 20, "20 смена шифра" }, { 21, "21 тревога" },
        { 22, "22 рукопожатие" }, { 23, "23 прикладные данные" },
    };
    int first = 1;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (mask & (uint8_t)(1u << (names[i].t - 20))) {
            printf("%s%s", first ? "" : ", ", names[i].n);
            first = 0;
        }
    }
    if (first) {
        printf("ни одной");
    }
}

/* Печатает строки "план"/"обмен" одного вопроса по его трассе. */
static void print_step(const d2k_props_step *st) {
    if (st->plan_len == 0) {
        printf("  план: не собрался\n");
    } else if (st->ack_ok == 1) {
        printf("  план: %zu байт, датапат принял\n", st->plan_len);
    } else if (st->rc == D2K_STEP_REFUSED) {
        printf("  план: %zu байт, датапат ОТВЕРГ — %s\n", st->plan_len, ack_code_str(st->ack_code));
    } else {
        printf("  план: %zu байт, подтверждения нет\n", st->plan_len);
    }

    if (st->local_port == 0) {
        printf("  обмен: до обращения к цели дело не дошло\n");
    } else if (st->rc == D2K_STEP_NO_EXCHANGE) {
        printf("  обмен: обращение с местного порта %u, события обмена не пришло\n",
              (unsigned)st->local_port);
    } else {
        printf("  обмен: с местного порта %u, %u байт, первая запись типа %u, встречены типы: ",
              (unsigned)st->local_port, (unsigned)st->bytes, (unsigned)st->first_type);
        print_seen_types(st->seen_types);
        printf("\n");
    }
    if (st->err[0]) {
        printf("  причина остановки: %s (%s)\n", step_rc_str(st->rc), st->err);
    } else {
        printf("  причина остановки: %s\n", step_rc_str(st->rc));
    }
}

/* Печатает один из пяти вопросов: заголовок с полем, потом ровно одно из
 * трёх: "спрошен: нет" с причиной, "спрошен: да" с планом/обменом/меткой и
 * решённым ответом, либо "спрошен: да" с тем же скелетом, но НЕ ИЗМЕРЕНО в
 * ответе — незаданный и заданный-безрезультатный вопрос печатаются РАЗНЫМИ
 * ветками этой функции, а не общим "неизвестно" (главное требование к
 * выводу, task-5v-brief.md). */
static void print_question(int idx1, int pos, const char *field, const char *doc_phrase,
                           const d2k_props *pr, int have_control,
                           const d2k_props_step *st) {
    printf("\n[%d/5] %s (%s):\n", idx1, field, doc_phrase);

    for (int q = 0; q < pos; q++) {
        if (pos_decided(pr, q)) {
            printf("  спрошен: нет\n  причина: опрос остановился раньше (вопрос %d уже дал ответ — "
                  "первый прошедший вопрос обрывает опрос)\n", q + 1);
            return;
        }
    }
    if ((pos == POS_DUP || pos == POS_PARSE) && !have_control) {
        printf("  спрошен: нет\n  причина: нет control-приветствия (второе реальное имя на ту же "
              "цель не снято)\n");
        return;
    }

    printf("  спрошен: да\n");
    print_step(st);
    printf("  метка: не ставится (см. предупреждение выше)\n");
    if (!pos_decided(pr, pos)) {
        printf("  ответ: не измерено — зонд не прошёл (строки выше говорят, каким именно "
              "местом; «обмен без прикладных данных» и «обмена не было» — это про коробку, "
              "остальное — про нас)\n");
        return;
    }

    d2k_pval v = pos_value(pr, pos);
    printf("  ответ: %s\n", pval_str(v));
    if (pos == POS_CHECKSUM && pr->parses_l7 == D2K_P_YES) {
        /* Не должно быть достижимо (pos_decided(POS_CHECKSUM) уже исключает
           этот случай выше), но названо явно: если когда-нибудь достигнется,
           лучше видимая нестыковка, чем тихая. */
        printf("  примечание: значение приписано ЭТОМУ вопросу, хотя разбор протокола тоже решён "
              "— проверьте pos_decided\n");
    }
    if (pos == POS_PARSE && v == D2K_P_YES) {
        printf("  примечание: тем же фактом снят вопрос [4/5] (контрольная сумма = %s) — "
              "\"разбор протокола пишет ОБА поля из одного факта\" (compose.c)\n",
              pval_str(pr->validates_checksum));
    }
}

static int all_unknown(const d2k_props *pr) {
    return pr->tolerates_left_overlap == D2K_P_UNKNOWN &&
           pr->tolerates_reorder == D2K_P_UNKNOWN &&
           pr->validates_checksum == D2K_P_UNKNOWN &&
           pr->parses_l7 == D2K_P_UNKNOWN &&
           pr->counts_duplicates == D2K_P_UNKNOWN;
}

static void print_not_asked_at_all(const char *reason) {
    printf("\nни один из 5 вопросов не задан: %s\n", reason);
    static const char *fields[5] = {
        "перекрытие слева (tolerates_left_overlap)",
        "счёт дубликатов (counts_duplicates)",
        "порядок сегментов (tolerates_reorder)",
        "контрольная сумма (validates_checksum)",
        "разбор протокола (parses_l7)"
    };
    for (int i = 0; i < 5; i++) {
        printf("\n[%d/5] %s:\n  спрошен: нет\n  причина: %s\n", i + 1, fields[i], reason);
    }
}

static void print_vector(const d2k_props *pr) {
    printf("\nитоговый вектор (не измерено / да / нет):\n");
    printf("  tolerates_left_overlap = %s\n", pval_str(pr->tolerates_left_overlap));
    printf("  counts_duplicates      = %s\n", pval_str(pr->counts_duplicates));
    printf("  tolerates_reorder      = %s\n", pval_str(pr->tolerates_reorder));
    printf("  validates_checksum     = %s\n", pval_str(pr->validates_checksum));
    printf("  parses_l7              = %s\n", pval_str(pr->parses_l7));
}

static void print_plans(char plans[][4096], size_t n, const char *decoy, const char *no_decoy_reason) {
    if (n == 0) {
        printf("\nвыведенные планы: НЕТ (d2k_compose не собрал ни одного плана — приманка "
              "(decoy) недоступна: %s)\n", no_decoy_reason);
        return;
    }
    printf("\nвыведенные планы (d2k_compose, приманка=%s):\n", decoy ? decoy : "нет");
    for (size_t i = 0; i < n; i++) {
        printf("\n  план %zu/%zu:\n", i + 1, n);
        const char *line = plans[i];
        while (*line) {
            const char *nl = strchr(line, '\n');
            size_t len = nl ? (size_t)(nl - line) : strlen(line);
            printf("    %.*s\n", (int)len, line);
            if (!nl) { break; }
            line = nl + 1;
        }
    }
}

/* --------------------------------------------------------------------
 * main — только последовательность вызовов: разбор аргументов,
 * d2k_link_open, получение снимка (arm+wait или hex), d2k_props_ask,
 * d2k_compose, печать. Коды возврата: 2 — отказ на входе (аргументы,
 * hex-файл), 1 — отказ среды (сокет не открылся, ошибка связи), 0 —
 * прогон состоялся (даже если ни один вопрос не получил ответа: пустой,
 * но честный результат — не отказ инструмента).
 * -------------------------------------------------------------------- */

int main(int argc, char **argv) {
    cli_args a;
    /* Вмещает D2KASK_USAGE целиком: parse_args отдаёт использование через тот
       же err, и буфер, который его обрезает, gcc ловит как format-truncation
       (цель cross), а пользователь — как оборванную строку помощи. */
    char err[sizeof D2KASK_USAGE + 64];

    if (parse_args(argc, argv, &a, err, sizeof err) != 0) {
        fprintf(stderr, "d2kask: %s\n", err);
        return 2;
    }

    static uint8_t trig_buf[D2KASK_HELLO_CAP];
    static uint8_t ctrl_buf[D2KASK_HELLO_CAP];
    size_t trig_len = 0, ctrl_len = 0;
    int have_trig = 0, have_ctrl = 0;
    int trig_timed_out = 0, ctrl_timed_out = 0;

    if (a.hello_hex_path) {
        if (read_hex_file(a.hello_hex_path, trig_buf, sizeof trig_buf, &trig_len, err, sizeof err) != 0) {
            fprintf(stderr, "d2kask: --hello-hex %s: %s\n", a.hello_hex_path, err);
            return 2;
        }
        have_trig = 1;
    }
    if (a.control_hex_path) {
        if (read_hex_file(a.control_hex_path, ctrl_buf, sizeof ctrl_buf, &ctrl_len, err, sizeof err) != 0) {
            fprintf(stderr, "d2kask: --control-hex %s: %s\n", a.control_hex_path, err);
            return 2;
        }
        have_ctrl = 1;
    }

    int fd = d2k_link_open(a.control_path, err, sizeof err);
    if (fd < 0) {
        fprintf(stderr, "d2kask: не удалось открыть управляющий сокет %s: %s\n", a.control_path, err);
        return 1;
    }

    char trig_detail[512];
    const char *trig_how;
    if (a.hello_hex_path) {
        trig_how = "--hello-hex";
        snprintf(trig_detail, sizeof trig_detail, "файл %s", a.hello_hex_path);
    } else {
        trig_how = "--arm-wait-ms";
        snprintf(trig_detail, sizeof trig_detail, "имя=%s, потолок=%ld мс", a.sni, a.arm_wait_ms);
        if (d2k_link_arm_shape(fd, a.sni, err, sizeof err) != 0) {
            fprintf(stderr, "d2kask: ARM_SHAPE(%s) не отправился: %s\n", a.sni, err);
            d2k_link_close(fd);
            return 1;
        }
        int rc = wait_shape(fd, a.arm_wait_ms, trig_buf, sizeof trig_buf, &trig_len, err, sizeof err);
        if (rc < 0) {
            fprintf(stderr, "d2kask: ожидание формы триггера: %s\n", err);
            d2k_link_close(fd);
            return 1;
        }
        have_trig = (rc == 0);
        trig_timed_out = (rc != 0);
    }

    int have_control_at_all = a.control_hex_path || a.control_sni;
    char ctrl_detail[512];
    const char *ctrl_how = "";
    if (a.control_hex_path) {
        ctrl_how = "--control-hex";
        snprintf(ctrl_detail, sizeof ctrl_detail, "файл %s", a.control_hex_path);
    } else if (a.control_sni) {
        ctrl_how = "--arm-wait-ms";
        snprintf(ctrl_detail, sizeof ctrl_detail, "имя=%s, потолок=%ld мс", a.control_sni, a.arm_wait_ms);
        if (d2k_link_arm_shape(fd, a.control_sni, err, sizeof err) != 0) {
            fprintf(stderr, "d2kask: ARM_SHAPE(%s) не отправился: %s\n", a.control_sni, err);
            d2k_link_close(fd);
            return 1;
        }
        int rc = wait_shape(fd, a.arm_wait_ms, ctrl_buf, sizeof ctrl_buf, &ctrl_len, err, sizeof err);
        if (rc < 0) {
            fprintf(stderr, "d2kask: ожидание формы control: %s\n", err);
            d2k_link_close(fd);
            return 1;
        }
        have_ctrl = (rc == 0);
        ctrl_timed_out = (rc != 0);
    }

    print_header(&a);
    printf("\n");
    print_snapshot("триггера", have_trig, trig_timed_out, trig_how, trig_detail, trig_buf, trig_len);
    if (a.save_trigger_path && have_trig) {
        save_hex(a.save_trigger_path, "триггера", a.sni, trig_buf, trig_len);
    }
    if (have_control_at_all) {
        print_snapshot("control", have_ctrl, ctrl_timed_out, ctrl_how, ctrl_detail, ctrl_buf, ctrl_len);
        if (a.save_control_path && have_ctrl) {
            save_hex(a.save_control_path, "control", a.control_sni, ctrl_buf, ctrl_len);
        }
    } else {
        printf("снимок control: не запрошен (--control-sni/--control-hex не заданы) — вопросы "
              "\"счёт дубликатов\" и \"разбор протокола\" не будут заданы (см. секцию "
              "\"вопросы\" ниже)\n");
    }

    size_t sni_off = 0, sni_len = 0;
    int trig_sni_ok = have_trig &&
                      d2k_hello_sni(trig_buf, trig_len, &sni_off, &sni_len) == 0 &&
                      sni_len > 0 && sni_len < 256;

    if (!have_trig) {
        print_not_asked_at_all("снимок приветствия триггера не получен");
        d2k_link_close(fd);
        return 0;
    }
    if (!trig_sni_ok) {
        /* Кириллица в UTF-8 — по два байта на символ; буфер обязан вмещать
           саму строку формата целиком, а не только цифры %zu (санитайзерная
           сборка ловит это как -Wformat-truncation, обычная -O2 — не всегда). */
        char reason[160];
        snprintf(reason, sizeof reason, "в снимке триггера (%zu байт) не нашлось SNI (d2k_hello_sni)", trig_len);
        print_not_asked_at_all(reason);
        d2k_link_close(fd);
        return 0;
    }

    printf("\nпредупреждения (относятся к этому прогону, см. doc-комментарий d2k_props_ask):\n"
          "  - потолок ожидания 5000 мс общий и для подтверждения плана (AF_UNIX), и для "
          "сетевого обмена — унаследован (WAIT_CEIL_MS), не измерен для этого применения\n"
          "  - метка (--mark=0x%x) принята d2k_props_ask по контракту, но НЕ применяется этим "
          "зондом: обращение к цели всегда идёт непомеченным (props_ask_contact, compose.c) — "
          "иначе только что поставленный план-кандидат прошёл бы мимо NFQUEUE нетронутым "
          "(files/S99d2k, правило mangle) — ниже везде \"метка: не ставится\"\n", (unsigned)a.mark);

    d2k_hello trigger; trigger.bytes = trig_buf; trigger.len = trig_len;
    d2k_hello control; control.bytes = have_ctrl ? ctrl_buf : NULL; control.len = have_ctrl ? ctrl_len : 0;

    d2k_props_step steps[D2K_PROPS_QUESTIONS];
    d2k_props pr = d2k_props_ask_traced(fd, a.ip, a.port, trigger, control, a.mark, steps);

    if (all_unknown(&pr)) {
        printf("  - ни один зонд не прошёл: план последнего заданного вопроса СНЯТ с датапата "
              "(DEL_NAME по имени \"%s\") — иначе на боевом датапате остался бы стоять план, "
              "про который это же измерение сказало \"не работает\"\n", a.sni);
    }

    printf("\nвопросы (порядок = порядок опроса d2k_props_ask):\n");
    print_question(1, POS_OVERLAP, "перекрытие слева", "держит ли сегмент, начинающийся левее данных", &pr, have_ctrl, &steps[0]);
    print_question(2, POS_DUP, "счёт дубликатов", "считает ли разнесённые копии за одно", &pr, have_ctrl, &steps[1]);
    print_question(3, POS_REORDER, "порядок сегментов", "держит ли сегменты не по порядку прихода", &pr, have_ctrl, &steps[2]);
    print_question(4, POS_CHECKSUM, "контрольная сумма", "сверяет ли контрольную сумму TCP", &pr, have_ctrl, &steps[3]);
    print_question(5, POS_PARSE, "разбор протокола", "разбирает ли TLS, а не просто смотрит байты", &pr, have_ctrl, &steps[4]);

    print_vector(&pr);

    d2k_shape target_shape = d2k_hello_shape(trig_buf, trig_len);
    char decoy_buf[256];
    const char *decoy = NULL;
    const char *no_decoy_reason = "control-приветствие не задано";
    if (have_ctrl) {
        size_t coff = 0, clen = 0;
        if (d2k_hello_sni(ctrl_buf, ctrl_len, &coff, &clen) == 0 && clen > 0 && clen < sizeof decoy_buf) {
            memcpy(decoy_buf, ctrl_buf + coff, clen);
            decoy_buf[clen] = '\0';
            decoy = decoy_buf;
        } else {
            no_decoy_reason = "в control-приветствии не нашлось имени (d2k_hello_sni)";
        }
    }

    static char plans[8][4096];
    size_t n = d2k_compose(&pr, target_shape, decoy, plans, 8);
    print_plans(plans, n, decoy, no_decoy_reason);

    d2k_link_close(fd);
    return 0;
}
