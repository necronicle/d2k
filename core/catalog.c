/* Файл включают и как текст в составные тесты — после системных заголовков,
   где glibc (с 2026) уже задал _POSIX_C_SOURCE сам: голый #define там —
   переопределение под -Werror (CI 22.10.2026). Отдельной единицей трансляции
   значение задаётся как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* catalog.c — каталог: чтение и запись файла, который остаётся общим с
 * Go-панелью. Контракт и обоснования — в шапке d2k_catalog.h; здесь —
 * реализация и её собственные инварианты.
 *
 * УСТРОЙСТВО РАЗБОРА. Рекурсивный спуск по шести формам JSON (объект,
 * массив, строка, число, true/false, null). Скелет общий для всех шести
 * объектных форм каталога (signal/fingerprint/plan/binding/box/каталог
 * целиком) — parse_object берёт на себя скобки и запятые, каждый
 * "handle_*_key" решает только СВОЁ: что делать со значением известного
 * ключа, а незнакомый — jskip_value (то самое "неизвестное поле
 * пропускается" из задания). Массивы переменной длины (планы, привязки,
 * коробки) идут через тот же приём — parse_array. Единственное
 * исключение — fingerprint.signals: он не растёт, а пишется в фиксированный
 * d2k_cat_fp.sig[8] (так задан контракт), и девятая примета — отказ, а не
 * рост за пределы буфера.
 *
 * ИНВАРИАНТ ОЧИСТКИ ПРИ ОТКАЗЕ. И parse_array, и бespoke-цикл signals
 * резервируют слот (n++) ДО разбора элемента, а не после. Если элемент
 * упадёт на середине — скажем, d2k_cat_plan.text уже выделен, а
 * "successes" ещё нет, — счётчик n_plans уже считает этот слот
 * существующим, и d2k_catalog_free (вызванный ОДИН раз, из
 * d2k_catalog_load, на любом отказе на любой глубине) найдёт и освободит
 * всё, что успело выделиться, а не только то, что успело доразобраться до
 * конца. Каждый parse_* обязан начинать с memset(out, 0, sizeof *out) —
 * это то, что делает частично заполненную структуру безопасной для free
 * ещё ДО того, как в неё вообще что-то записали.
 *
 * ПОРЯДОК ФУНКЦИЙ В ЭТОМ ФАЙЛЕ — СНИЗУ ВВЕРХ ПО ЗАВИСИМОСТЯМ: каждая
 * вызывающая определена ПОСЛЕ того, кого зовёт (кроме d2k_catalog_free,
 * которую d2k_catalog_load зовёт из своей ветки отказа, но её объявление
 * приходит из d2k_catalog.h — обратных ссылок внутри файла нет нигде).
 * Ни одной forward declaration в файле поэтому не требуется.
 */
#include <errno.h>
#include "d2k_plantlv.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "d2k_catalog.h"

/* Пишет причину отказа в err, если есть куда. err[0]!=0 после этого
 * вызова гарантированно — "не разобралось" без объяснения нечитаемо (см.
 * d2k_verdict.h про тот же принцип у вердиктов дерева). */
static void set_err(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

/* --------------------------------------------------------------------
 * Курсор разбора и низкоуровневые примитивы.
 * -------------------------------------------------------------------- */

typedef struct {
    const char *s;
    size_t      len;
    size_t      i;
    const char *store_path;
} jctx;

/* Смотрит на следующий незанятый пробелом байт, НЕ потребляя его, и
 * заодно продвигает курсор за пробелы перед ним. Это ЕДИНСТВЕННОЕ место
 * пропуска пробелов на весь файл: раздельный jskip_ws() перед каждым из
 * десятков мест разбора легко забыть ровно в одном — слитый в peek,
 * забыть негде, потому что без него не работает ни один разбор символа.
 * -1 на конце буфера. */
static int jpeek(jctx *j) {
    while (j->i < j->len) {
        char c = j->s[j->i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
        j->i++;
    }
    if (j->i >= j->len) return -1;
    return (unsigned char)j->s[j->i];
}

/* Требует ровно байт want на текущей позиции (после пропуска пробелов) и
 * потребляет его; иначе отказ с причиной, называющей и ожидание, и то,
 * что встречено. */
static int jeat(jctx *j, char want, char *err, size_t errcap) {
    int c = jpeek(j);
    if (c != (unsigned char)want) {
        if (c < 0) {
            set_err(err, errcap, "ожидался '%c', встречен конец файла (позиция %zu)", want, j->i);
        } else {
            set_err(err, errcap, "ожидался '%c', встречен '%c' (позиция %zu)", want, (char)c, j->i);
        }
        return -1;
    }
    j->i++;
    return 0;
}

/* true (и курсор сдвинут за "null"), если на текущей позиции буквально
 * null. Нужно любому массивному полю: Go маршалит nil-срез как null
 * (encoding/json), а не как [] — пустой каталог без единого Confirm()
 * даёт именно "boxes":null. */
static int jeat_null_if_present(jctx *j) {
    jpeek(j); /* сдвигает курсор за пробелы, символ не потребляет */
    if (j->i + 4 <= j->len && memcmp(j->s + j->i, "null", 4) == 0) {
        j->i += 4;
        return 1;
    }
    return 0;
}

/* --------------------------------------------------------------------
 * Время: RFC 3339 <-> секунды эпохи Unix, целыми числами, без обращения
 * к таймзонам libc.
 *
 * ПОЧЕМУ НЕ timegm/mktime. timegm — расширение GNU/BSD, не часть C99
 * (сборка идёт строгим -std=c99, три компилятора, mipsel и aarch64
 * кросс-сборкой — см. Makefile). mktime зависит от TZ окружения, которого
 * на роутере нет, а на кросс-собранном mipsel/aarch64-musl оно может вести
 * себя иначе, чем при разработке на маке. Все времена в файле — UTC ("Z",
 * см. шапку d2k_catalog.h), и календарная арифметика ниже это не обходит
 * стороной через окружение, а считает сама, целыми числами.
 *
 * АЛГОРИТМ — days_from_civil/civil_from_days Ховарда Хиннанта
 * (http://howardhinnant.github.io/date_algorithms.html, общественное
 * достояние). Проверен НЕЗАВИСИМО от этого кода по семи опорным точкам
 * (test_catalog.c, check_time_roundtrip) — вывод
 * `date -u -j -f "%Y-%m-%dT%H:%M:%S" ... +%s` на macOS, включая границы
 * (эпоха 0, отрицательная эпоха до 1970, високосный день 2000 года —
 * кратен 400, поэтому високосный по григорианскому правилу, — и границу
 * int32 2038-01-19), а не только самосогласованность кодирования с
 * раскодированием.
 * -------------------------------------------------------------------- */

/* Деление с округлением ВНИЗ, а не к нулю. Обычное C-деление отрицательных
 * чисел (epoch % 86400 при epoch < 0) даёт отрицательный остаток, а нужен
 * остаток в [0, 86400) — секунда внутри суток не бывает отрицательной. В
 * данных 2026 года отрицательной эпохи нет, но check_time_roundtrip
 * намеренно проверяет 1969-12-31 — эта граница часть контракта, а не
 * гипотеза. */
static int64_t floor_div(int64_t a, int64_t b) {
    int64_t q = a / b;
    int64_t r = a % b;
    if (r != 0 && ((r < 0) != (b < 0))) q--;
    return q;
}

/* Дней от 1970-01-01 (само 1970-01-01 => 0). */
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);                                  /* [0, 399] */
    unsigned doy = (153 * (m + (m > 2 ? (unsigned)-3 : 9)) + 2) / 5 + d - 1;    /* [0, 365] */
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;                      /* [0, 146096] */
    return era * 146097 + (int64_t)doe - 719468;
}

/* Обратное преобразование: дни от эпохи -> календарная дата (UTC). */
static void civil_from_days(int64_t z, int64_t *y, unsigned *m, unsigned *d) {
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);                              /* [0, 146096] */
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;      /* [0, 399] */
    int64_t yy = (int64_t)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);                    /* [0, 365] */
    unsigned mp = (5 * doy + 2) / 153;                                        /* [0, 11] */
    unsigned dd = doy - (153 * mp + 2) / 5 + 1;                               /* [1, 31] */
    unsigned mm = mp + (mp < 10 ? 3 : (unsigned)-9);
    yy += (mm <= 2);
    *y = yy; *m = mm; *d = dd;
}

/* Секунды эпохи -> строка RFC 3339 с суффиксом Z, БЕЗ дробной доли (см.
 * d2k_catalog.h: точнее целой секунды каталогу не нужно, и это осознанная
 * потеря точности при чтении, а не ошибка округления при записи). out
 * должен вмещать минимум 21 байт при 4-значном годе — outcap проверяется
 * snprintf'ом, не молча. */
static void format_rfc3339(int64_t epoch, char *out, size_t outcap) {
    int64_t days = floor_div(epoch, 86400);
    int64_t sod  = epoch - days * 86400; /* [0, 86399] — гарантирует floor_div */
    int64_t y; unsigned mo, d;
    civil_from_days(days, &y, &mo, &d);
    unsigned h  = (unsigned)(sod / 3600);
    unsigned mi = (unsigned)((sod % 3600) / 60);
    unsigned se = (unsigned)(sod % 60);
    snprintf(out, outcap, "%04lld-%02u-%02uT%02u:%02u:%02uZ",
             (long long)y, mo, d, h, mi, se);
}

/* --------------------------------------------------------------------
 * Числа и bool.
 * -------------------------------------------------------------------- */

/* Разбирает целое число JSON. Дробная часть и экспонента — ОТКАЗ, не
 * atof и не молчаливое обрезание до целой части: на роутере нет
 * сопроцессора, и плавающей арифметики в этом коде нет нигде (Global
 * Constraints). Проверка одна на весь файл — jskip_value зовёт эту же
 * функцию для пропускаемых полей, так что дробное число ловится и там,
 * где эта версия разбора поле вообще не знает. */
static int jparse_raw_int(jctx *j, int64_t *out, char *err, size_t errcap) {
    int c = jpeek(j);
    size_t start = j->i;
    int neg = 0;
    if (c == '-') {
        neg = 1;
        j->i++;
        c = (j->i < j->len) ? (unsigned char)j->s[j->i] : -1;
    }
    if (c < '0' || c > '9') {
        set_err(err, errcap, "ожидалось число (позиция %zu)", start);
        return -1;
    }
    int64_t v = 0;
    int ndigits = 0;
    while (j->i < j->len && j->s[j->i] >= '0' && j->s[j->i] <= '9') {
        if (ndigits >= 18) { /* int64_t держит ~18-19 десятичных цифр без переполнения */
            set_err(err, errcap, "число слишком длинное (позиция %zu)", start);
            return -1;
        }
        v = v * 10 + (j->s[j->i] - '0');
        j->i++;
        ndigits++;
    }
    if (j->i < j->len && (j->s[j->i] == '.' || j->s[j->i] == 'e' || j->s[j->i] == 'E')) {
        set_err(err, errcap,
                "дробное или экспоненциальное число (позиция %zu) — плавающей арифметики нет",
                start);
        return -1;
    }
    *out = neg ? -v : v;
    return 0;
}

static int jparse_i32(jctx *j, int *out, const char *field, char *err, size_t errcap) {
    int64_t v;
    if (jparse_raw_int(j, &v, err, errcap) != 0) return -1;
    if (v < INT_MIN || v > INT_MAX) {
        set_err(err, errcap, "%s: %lld вне диапазона int", field, (long long)v);
        return -1;
    }
    *out = (int)v;
    return 0;
}

static int jparse_u8(jctx *j, uint8_t *out, const char *field, char *err, size_t errcap) {
    int64_t v;
    if (jparse_raw_int(j, &v, err, errcap) != 0) return -1;
    if (v < 0 || v > 255) {
        set_err(err, errcap, "%s: %lld вне диапазона 0..255", field, (long long)v);
        return -1;
    }
    *out = (uint8_t)v;
    return 0;
}

static int jparse_u16(jctx *j, uint16_t *out, const char *field, char *err, size_t errcap) {
    int64_t v;
    if (jparse_raw_int(j, &v, err, errcap) != 0) return -1;
    if (v < 0 || v > 65535) {
        set_err(err, errcap, "%s: %lld вне диапазона 0..65535", field, (long long)v);
        return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

static int jparse_u32(jctx *j, uint32_t *out, const char *field, char *err, size_t errcap) {
    int64_t v;
    if (jparse_raw_int(j, &v, err, errcap) != 0) return -1;
    if (v < 0 || (uint64_t)v > UINT32_MAX) {
        set_err(err, errcap, "%s: вне диапазона uint32", field);
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

static int jparse_bool_i(jctx *j, int *out, const char *field, char *err, size_t errcap) {
    jpeek(j);
    if (j->i + 4 <= j->len && memcmp(j->s + j->i, "true", 4) == 0) {
        j->i += 4; *out = 1; return 0;
    }
    if (j->i + 5 <= j->len && memcmp(j->s + j->i, "false", 5) == 0) {
        j->i += 5; *out = 0; return 0;
    }
    set_err(err, errcap, "%s: ожидалось true/false (позиция %zu)", field, j->i);
    return -1;
}

/* --------------------------------------------------------------------
 * Строки.
 * -------------------------------------------------------------------- */

/* Разбирает JSON-строку начиная с открывающей кавычки (курсор до пробелов
 * перед ней — jeat сам их пропустит). Возвращает через *out свежий
 * malloc'd NUL-terminated буфер, владение переходит вызывающему (см.
 * jparse_string_fixed и plan.text).
 *
 * Экранирования: стандартные (\" \\ \/ \b \f \n \r \t) и \uXXXX для
 * базовой многоязычной плоскости — КРОМЕ суррогатов и кодовой точки ноль
 * (U+0000). Суррогат без пары ничего не кодирует в UTF-8 сам по себе, а
 * собирать полную пару здесь незачем: единственный потребитель этих строк
 * — простой char*, а форма ни разу не встретилась в реальном каталоге
 * (testdata). Кодовая точка ноль оборвала бы значение молча на этом
 * байте — весь остальной контракт этого модуля построен на
 * NUL-terminated char* и char[N], и это не частный случай, который стоит
 * обходить. Оба — явный отказ с причиной (см. test_catalog.c,
 * check_surrogate_and_nul_rejected). */
static int jparse_string_dyn(jctx *j, char **out, char *err, size_t errcap) {
    if (jeat(j, '"', err, errcap) != 0) return -1;

    size_t cap = 32, len = 0;
    char *buf = malloc(cap);
    if (!buf) { set_err(err, errcap, "память: строка не выделилась"); return -1; }

    for (;;) {
        if (j->i >= j->len) {
            set_err(err, errcap, "строка не закрыта до конца файла");
            free(buf);
            return -1;
        }
        unsigned char c = (unsigned char)j->s[j->i++];
        if (c == '"') break;

        /* Запас 4 — самый длинный однократный APPEND ниже (3-байтовый
           UTF-8 из \uXXXX) плюс байт головой. Растим ДО записи, а не
           после — после могло быть поздно. */
        if (len + 4 > cap) {
            size_t newcap = cap * 2;
            char *p = realloc(buf, newcap);
            if (!p) { set_err(err, errcap, "память: строка не выросла"); free(buf); return -1; }
            buf = p; cap = newcap;
        }

        if (c == '\\') {
            if (j->i >= j->len) {
                set_err(err, errcap, "строка обрывается на экранировании");
                free(buf); return -1;
            }
            unsigned char e = (unsigned char)j->s[j->i++];
            switch (e) {
            case '"':  buf[len++] = '"';  break;
            case '\\': buf[len++] = '\\'; break;
            case '/':  buf[len++] = '/';  break;
            case 'b':  buf[len++] = '\b'; break;
            case 'f':  buf[len++] = '\f'; break;
            case 'n':  buf[len++] = '\n'; break;
            case 'r':  buf[len++] = '\r'; break;
            case 't':  buf[len++] = '\t'; break;
            case 'u': {
                if (j->i + 4 > j->len) {
                    set_err(err, errcap, "\\u без четырёх шестнадцатеричных цифр");
                    free(buf); return -1;
                }
                unsigned cp = 0;
                for (int k = 0; k < 4; k++) {
                    char hc = j->s[j->i + (size_t)k];
                    unsigned v;
                    if (hc >= '0' && hc <= '9') v = (unsigned)(hc - '0');
                    else if (hc >= 'a' && hc <= 'f') v = (unsigned)(hc - 'a' + 10);
                    else if (hc >= 'A' && hc <= 'F') v = (unsigned)(hc - 'A' + 10);
                    else {
                        set_err(err, errcap, "\\u: не шестнадцатеричная цифра");
                        free(buf); return -1;
                    }
                    cp = (cp << 4) | v;
                }
                j->i += 4;
                if (cp == 0) {
                    set_err(err, errcap, "\\u0000 внутри строки не поддержан (оборвал бы C-строку)");
                    free(buf); return -1;
                }
                if (cp >= 0xD800 && cp <= 0xDFFF) {
                    set_err(err, errcap, "суррогатная половина \\u%04x без пары не поддержана", cp);
                    free(buf); return -1;
                }
                if (cp < 0x80) {
                    buf[len++] = (char)cp;
                } else if (cp < 0x800) {
                    buf[len++] = (char)(0xC0 | (cp >> 6));
                    buf[len++] = (char)(0x80 | (cp & 0x3F));
                } else {
                    buf[len++] = (char)(0xE0 | (cp >> 12));
                    buf[len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    buf[len++] = (char)(0x80 | (cp & 0x3F));
                }
                break;
            }
            default:
                set_err(err, errcap, "неизвестное экранирование \\%c", (char)e);
                free(buf); return -1;
            }
            continue;
        }

        if (c < 0x20) {
            set_err(err, errcap, "управляющий байт 0x%02x в строке без экранирования", c);
            free(buf); return -1;
        }
        buf[len++] = (char)c;
    }

    buf[len] = '\0';
    *out = buf;
    return 0;
}

/* Тот же разбор строки, но в буфер фиксированного размера (id/kind/
 * target/proto/plan_id). Отказ, если результат не влезает — тихое
 * обрезание сделало бы из длинного id ДРУГОЙ, ложный идентификатор без
 * единого следа подмены в файле (см. d2k_catalog.h). */
static int jparse_string_fixed(jctx *j, char *out, size_t outcap,
                                const char *field, char *err, size_t errcap) {
    char *dyn = NULL;
    if (jparse_string_dyn(j, &dyn, err, errcap) != 0) return -1;
    size_t n = strlen(dyn);
    if (n + 1 > outcap) {
        set_err(err, errcap, "%s: строка длиной %zu не влезает в буфер %zu байт",
                field, n, outcap);
        free(dyn);
        return -1;
    }
    memcpy(out, dyn, n + 1);
    free(dyn);
    return 0;
}

/* Ровно n десятичных цифр на текущей позиции — БЕЗ пропуска пробелов: в
 * фиксированных позициях RFC 3339 пробелам взяться неоткуда, и если они
 * есть, это уже не тот формат (отказ, а не попытка съесть пробел и
 * продолжить). */
static int read_fixed_digits(jctx *j, int n, long *out, char *err, size_t errcap) {
    if (j->i + (size_t)n > j->len) {
        set_err(err, errcap, "время обрывается раньше ожидаемого (позиция %zu)", j->i);
        return -1;
    }
    long v = 0;
    for (int k = 0; k < n; k++) {
        char c = j->s[j->i + (size_t)k];
        if (c < '0' || c > '9') {
            set_err(err, errcap, "не цифра в поле времени (позиция %zu)", j->i + (size_t)k);
            return -1;
        }
        v = v * 10 + (c - '0');
    }
    j->i += (size_t)n;
    *out = v;
    return 0;
}

static int eat_lit(jctx *j, char want, char *err, size_t errcap) {
    if (j->i >= j->len || j->s[j->i] != want) {
        set_err(err, errcap, "время: ожидался '%c' (позиция %zu)", want, j->i);
        return -1;
    }
    j->i++;
    return 0;
}

/* Разбирает JSON-строку, обязанную быть RFC 3339 в форме
 * "YYYY-MM-DDTHH:MM:SS[.дробь]Z" — единственной, которую этот проект
 * производит (time.Time.MarshalJSON, всегда UTC — см. шапку файла и
 * d2k_catalog.h). Пояса со смещением (+03:00 и т.п.) не разбираются: их
 * не бывает в данных, а полу-поддержка хуже явного отказа. Дробная доля
 * секунды пропускается и не хранится (секунды эпохи в int64_t). */
static int jparse_rfc3339(jctx *j, int64_t *out, const char *field, char *err, size_t errcap) {
    if (jeat(j, '"', err, errcap) != 0) return -1;

    long y, mo, d, h, mi, se;
    if (read_fixed_digits(j, 4, &y, err, errcap) != 0) return -1;
    if (eat_lit(j, '-', err, errcap) != 0) return -1;
    if (read_fixed_digits(j, 2, &mo, err, errcap) != 0) return -1;
    if (eat_lit(j, '-', err, errcap) != 0) return -1;
    if (read_fixed_digits(j, 2, &d, err, errcap) != 0) return -1;
    if (eat_lit(j, 'T', err, errcap) != 0) return -1;
    if (read_fixed_digits(j, 2, &h, err, errcap) != 0) return -1;
    if (eat_lit(j, ':', err, errcap) != 0) return -1;
    if (read_fixed_digits(j, 2, &mi, err, errcap) != 0) return -1;
    if (eat_lit(j, ':', err, errcap) != 0) return -1;
    if (read_fixed_digits(j, 2, &se, err, errcap) != 0) return -1;

    if (j->i < j->len && j->s[j->i] == '.') {
        j->i++;
        if (j->i >= j->len || j->s[j->i] < '0' || j->s[j->i] > '9') {
            set_err(err, errcap, "%s: дробная часть времени пуста", field);
            return -1;
        }
        while (j->i < j->len && j->s[j->i] >= '0' && j->s[j->i] <= '9') j->i++;
    }
    if (eat_lit(j, 'Z', err, errcap) != 0) return -1;
    if (jeat(j, '"', err, errcap) != 0) return -1;

    /* Базовая защита от мусора, не полная календарная валидация — 13-й
       месяц или 99-й день ловится здесь явно, а не расползается по
       days_from_civil молча в дату из другой эпохи. */
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) {
        set_err(err, errcap, "%s: значение вне диапазона в %04ld-%02ld-%02ldT%02ld:%02ld:%02ldZ",
                field, y, mo, d, h, mi, se);
        return -1;
    }
    int64_t days = days_from_civil(y, (unsigned)mo, (unsigned)d);
    *out = days * 86400 + h * 3600 + mi * 60 + se;
    return 0;
}

/* ТРОЙСТВЕННЫЙ ПРИЗНАК В ФАЙЛЕ — "yes" ИЛИ "no", И НИЧЕГО БОЛЬШЕ.
 *
 * «Не измерено» в файле выглядит ОТСУТСТВИЕМ ключа, а не третьим словом:
 * так старый каталог без вектора читается как пустое знание сам собой, без
 * особого случая. Поэтому и значения всего два, а любое другое слово —
 * отказ с причиной: опечатка в файле иначе прочиталась бы как отсутствие
 * знания, то есть тихо изменила бы смысл записи (§2.4). */
static int jparse_tri(jctx *j, int8_t *out, const char *field, char *err, size_t errcap) {
    char word[8];
    if (jparse_string_fixed(j, word, sizeof word, field, err, errcap) != 0) { return -1; }
    if (strcmp(word, "yes") == 0) { *out = D2K_PROP_YES; return 0; }
    if (strcmp(word, "no") == 0)  { *out = D2K_PROP_NO;  return 0; }
    set_err(err, errcap, "%s: ожидалось \"yes\" или \"no\", прочитано \"%s\"", field, word);
    return -1;
}


/* --------------------------------------------------------------------
 * Пропуск незнакомого значения и предел вложенности.
 *
 * Ревью 2026-09-10 (круг 1): jskip_value рекурсировал без предела — на
 * незнакомом поле с вложенностью ~200 000 ("future": [[[[...]]]]) это
 * стек-оверфлоу, пойманный санитайзером (падение между 80 000 и 100 000
 * уровней при стеке 8 МБ; сам файл — около 180-200 КБ, не экзотика). Схема
 * этого файла собственной глубины не задаёт — она известна только для
 * ЗНАКОМЫХ ключей (см. дальше по файлу), а jskip_value обязан пройти
 * ЛЮБУЮ форму под незнакомым ключом, в том числе бесконечно вложенную.
 *
 * D2K_JSON_MAX_DEPTH — общий предел для всех трёх мест рекурсивного
 * спуска (jskip_value, parse_object, parse_array): один счётчик, а не три
 * раздельных, потому что известная и незнакомая вложенность считаются с
 * одной и той же точки отсчёта (незнакомое поле внутри coробки уже сидит
 * на глубине этой коробки, а не с нуля).
 *
 * Число: Go (encoding/json), с которым этот код обязан читать одни и те
 * же файлы, отказывает на глубине около 10000 ("exceeded max depth",
 * проверено эмпирически ревьюером) — то есть по этому входу наш разбор до
 * фикса был регрессией относительно эталона, а не просто небезопасным
 * сам по себе. Настоящая вложенность каталога, если считать КАЖДЫЙ { и [
 * отдельным уровнем (см. ниже, как считает эта версия): catalog{1 ->
 * boxes[2 -> box{3 -> fingerprint{4 -> signals[5 -> signal{6 — глубже 6
 * схема не уходит нигде (plans/bindings мельче — 5). 64 — что оставляет
 * десятикратный запас над настоящей вложенностью и при этом на четыре
 * порядка меньше глубины, на которой падает стек, а не "на всякий
 * случай": оба факта проверены (test_catalog.c,
 * check_depth_limit_rejects_not_crashes), а не приняты на слово. */
#define D2K_JSON_MAX_DEPTH 64

/* Пропускает одно JSON-значение произвольной формы — единственный
 * честный способ "не знать" незнакомое поле: прочитать и отбросить по
 * грамматике, а не угадать его длину. Числа проверяются ТЕМ ЖЕ
 * jparse_raw_int, что и известные поля: дробное число в пропускаемом поле
 * — такой же отказ, как в известном (см. jparse_raw_int — "плавающей
 * арифметики нет" про файл целиком, а не только про то, что эта версия
 * понимает).
 *
 * depth — глубина ЭТОГО значения (сколько { и [ его уже окружает,
 * считая его собственную пару, если это объект/массив). Вызывающий
 * обязан посчитать её: при спуске в значение одного ключа объекта или
 * элемента массива — depth+1 относительно СВОЕЙ. */
static int jskip_value(jctx *j, int depth, char *err, size_t errcap) {
    if (depth > D2K_JSON_MAX_DEPTH) {
        set_err(err, errcap,
                "JSON вложен глубже %d уровней — отказ вместо риска переполнения стека "
                "(настоящая вложенность каталога не превышает 6)",
                D2K_JSON_MAX_DEPTH);
        return -1;
    }
    int c = jpeek(j);
    if (c < 0) { set_err(err, errcap, "неожиданный конец файла"); return -1; }

    if (c == '"') {
        char *tmp = NULL;
        if (jparse_string_dyn(j, &tmp, err, errcap) != 0) return -1;
        free(tmp);
        return 0;
    }
    if (c == '{') {
        j->i++;
        if (jpeek(j) == '}') { j->i++; return 0; }
        for (;;) {
            if (jpeek(j) != '"') {
                set_err(err, errcap, "ожидался ключ-строка при пропуске объекта (позиция %zu)", j->i);
                return -1;
            }
            char *key = NULL;
            if (jparse_string_dyn(j, &key, err, errcap) != 0) return -1;
            free(key); /* ключ нужен был только сдвинуть курсор — не храним */
            if (jeat(j, ':', err, errcap) != 0) return -1;
            if (jskip_value(j, depth + 1, err, errcap) != 0) return -1;
            int cc = jpeek(j);
            if (cc == ',') { j->i++; continue; }
            if (cc == '}') { j->i++; break; }
            set_err(err, errcap, "ожидался ',' или '}' при пропуске объекта (позиция %zu)", j->i);
            return -1;
        }
        return 0;
    }
    if (c == '[') {
        j->i++;
        if (jpeek(j) == ']') { j->i++; return 0; }
        for (;;) {
            if (jskip_value(j, depth + 1, err, errcap) != 0) return -1;
            int cc = jpeek(j);
            if (cc == ',') { j->i++; continue; }
            if (cc == ']') { j->i++; break; }
            set_err(err, errcap, "ожидался ',' или ']' при пропуске массива (позиция %zu)", j->i);
            return -1;
        }
        return 0;
    }
    if (c == 't' || c == 'f') {
        int b;
        return jparse_bool_i(j, &b, "<пропускаемое поле>", err, errcap);
    }
    if (c == 'n') {
        if (j->i + 4 <= j->len && memcmp(j->s + j->i, "null", 4) == 0) { j->i += 4; return 0; }
        set_err(err, errcap, "ожидалось null (позиция %zu)", j->i);
        return -1;
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        int64_t v;
        return jparse_raw_int(j, &v, err, errcap);
    }
    set_err(err, errcap, "непонятное значение начиная с '%c' (позиция %zu)", (char)c, j->i);
    return -1;
}

/* --------------------------------------------------------------------
 * Общий скелет объектов и массивов.
 * -------------------------------------------------------------------- */

typedef int (*key_handler)(jctx *j, const char *key, void *ctx, int depth, char *err, size_t errcap);

/* Общий разбор JSON-объекта: скобки, запятые и чтение ключа — в одном
 * месте, а не в шести похожих функциях по отдельности (signal/
 * fingerprint/plan/binding/box/каталог). Обработчик решает только СВОЁ —
 * что делать со значением ДАННОГО ключа; неизвестный ключ — его забота
 * позвать jskip_value, не забота parse_object.
 *
 * depth — глубина ЭТОГО объекта (см. D2K_JSON_MAX_DEPTH и шапку
 * jskip_value про общий счётчик на все три места спуска). Проверяется
 * ДО потребления '{': пустой вызов на уже недопустимой глубине не должен
 * даже начинать читать байты, которых, может, и нет. */
static int parse_object(jctx *j, key_handler handle, void *ctx, int depth, char *err, size_t errcap) {
    if (depth > D2K_JSON_MAX_DEPTH) {
        set_err(err, errcap, "JSON вложен глубже %d уровней — отказ вместо риска переполнения стека",
                D2K_JSON_MAX_DEPTH);
        return -1;
    }
    if (jeat(j, '{', err, errcap) != 0) return -1;
    if (jpeek(j) == '}') { j->i++; return 0; }
    for (;;) {
        if (jpeek(j) != '"') {
            set_err(err, errcap, "ожидался ключ-строка (позиция %zu)", j->i);
            return -1;
        }
        char *key = NULL;
        if (jparse_string_dyn(j, &key, err, errcap) != 0) return -1;
        if (jeat(j, ':', err, errcap) != 0) { free(key); return -1; }
        int rc = handle(j, key, ctx, depth, err, errcap);
        free(key);
        if (rc != 0) return -1;
        int c = jpeek(j);
        if (c == ',') { j->i++; continue; }
        if (c == '}') { j->i++; break; }
        set_err(err, errcap, "ожидался ',' или '}' в объекте (позиция %zu)", j->i);
        return -1;
    }
    return 0;
}

/* Растит массив вдвое, когда некуда больше писать. Стартовая ёмкость 4 —
 * коробок и планов в реальном каталоге единицы (см. testdata),
 * экономить нечего, а частые realloc на пустом месте дороже одного
 * лишнего удвоения. Рабочий cap передаётся снаружи; вызывающий
 * (handle_box_key/handle_catalog_key) по-прежнему инициализирует его
 * ТЕКУЩИМ числом элементов на каждый вызов — благодаря этому дубль ключа
 * "plans" в одном объекте (не встречается в реальных файлах, но не должен
 * переполнить буфер, если встретится) тоже получит верный размер, а не
 * решит, что ёмкость 0 при уже ненулевом числе элементов.
 * Диагностические cap_* в каталоге только запоминают размер успешного
 * realloc и не участвуют в выборе размера следующего выделения. */
static void *grow(void *arr, size_t *cap, size_t count, size_t elemsize,
                   char *err, size_t errcap) {
    if (count < *cap) return arr;
    size_t newcap = (*cap == 0) ? 4 : (*cap * 2);
    void *p = realloc(arr, newcap * elemsize);
    if (!p) {
        set_err(err, errcap, "память: массив не вырос (было %zu элементов)", *cap);
        return NULL;
    }
    *cap = newcap;
    return p;
}

typedef int (*elem_parser)(jctx *j, void *out_elem, int depth, char *err, size_t errcap);

/* Общий разбор JSON-массива в растущий буфер элементов фиксированного
 * размера. null — валидный пустой массив (см. jeat_null_if_present).
 * Слот резервируется (*n += 1) ДО разбора элемента — см. шапку файла про
 * инвариант очистки при отказе: это единственный способ гарантировать,
 * что d2k_catalog_free найдёт и освободит частично разобранный элемент,
 * а не только полностью разобранные.
 *
 * depth — глубина ЭТОГО массива (см. parse_object про тот же параметр и
 * D2K_JSON_MAX_DEPTH про общий предел). Элементы массива на один уровень
 * глубже самого массива — parse_elem зовётся с depth+1. */
static int parse_array(jctx *j, void **arr, size_t *n, size_t *cap, size_t *allocated_cap,
                        size_t elemsize, elem_parser parse_elem,
                        const char *what, int depth, char *err, size_t errcap) {
    if (depth > D2K_JSON_MAX_DEPTH) {
        set_err(err, errcap, "JSON вложен глубже %d уровней — отказ вместо риска переполнения стека",
                D2K_JSON_MAX_DEPTH);
        return -1;
    }
    if (jeat_null_if_present(j)) return 0;
    if (jeat(j, '[', err, errcap) != 0) return -1;
    if (jpeek(j) == ']') { j->i++; return 0; }
    for (;;) {
        int growing = *n >= *cap;
        void *p = grow(*arr, cap, *n, elemsize, err, errcap);
        if (!p) return -1;
        *arr = p;
        if (growing) *allocated_cap = *cap;
        memset((char *)*arr + (*n) * elemsize, 0, elemsize);
        (*n)++;
        if (parse_elem(j, (char *)*arr + (*n - 1) * elemsize, depth + 1, err, errcap) != 0) return -1;
        int c = jpeek(j);
        if (c == ',') { j->i++; continue; }
        if (c == ']') { j->i++; break; }
        set_err(err, errcap, "ожидался ',' или ']' в массиве %s (позиция %zu)", what, j->i);
        return -1;
    }
    return 0;
}

/* --------------------------------------------------------------------
 * Приметы и отпечаток.
 * -------------------------------------------------------------------- */

static int handle_signal_key(jctx *j, const char *key, void *ctx, int depth, char *err, size_t errcap) {
    d2k_cat_signal *out = (d2k_cat_signal *)ctx;
    if (strcmp(key, "kind") == 0)
        return jparse_string_fixed(j, out->kind, sizeof out->kind, "signal.kind", err, errcap);
    if (strcmp(key, "ttl") == 0)
        return jparse_u8(j, &out->ttl, "signal.ttl", err, errcap);
    if (strcmp(key, "ttl_delta") == 0)
        return jparse_i32(j, &out->ttl_delta, "signal.ttl_delta", err, errcap);
    if (strcmp(key, "tos") == 0)
        return jparse_u8(j, &out->tos, "signal.tos", err, errcap);
    if (strcmp(key, "ipid") == 0)
        return jparse_u16(j, &out->ipid, "signal.ipid", err, errcap);
    if (strcmp(key, "volume") == 0)
        return jparse_i32(j, &out->volume, "signal.volume", err, errcap);
    if (strcmp(key, "seen") == 0)
        return jparse_i32(j, &out->seen, "signal.seen", err, errcap);
    if (strcmp(key, "packets") == 0)
        return jparse_i32(j, &out->packets, "signal.packets", err, errcap);
    return jskip_value(j, depth + 1, err, errcap);
}
static int parse_signal(jctx *j, d2k_cat_signal *out, int depth, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    return parse_object(j, handle_signal_key, out, depth, err, errcap);
}

/* fingerprint.signals — единственный массив каталога, который НЕ растёт:
 * ёмкость d2k_cat_fp.sig фиксирована на 8 самим контрактом (см.
 * "Produces" задания и d2k_catalog.h), и девятая примета — отказ, а не
 * рост за пределы буфера или молчаливая потеря одной из девяти. Поэтому
 * этот цикл — не parse_array (которому есть куда расти), а bespoke, но
 * тот же приём "слот резервируется до разбора элемента" — и тот же приём
 * "depth+1 на каждый спуск", что и в parse_array, хоть массив и не растёт:
 * предел вложенности общий на весь файл, а не только на растущие массивы. */
static int handle_fp_key(jctx *j, const char *key, void *ctx, int depth, char *err, size_t errcap) {
    d2k_cat_fp *out = (d2k_cat_fp *)ctx;
    if (strcmp(key, "method") == 0)
        return jparse_i32(j, &out->method, "fingerprint.method", err, errcap);
    if (strcmp(key, "signals") == 0) {
        if (depth + 1 > D2K_JSON_MAX_DEPTH) {
            set_err(err, errcap, "JSON вложен глубже %d уровней — отказ вместо риска переполнения стека",
                    D2K_JSON_MAX_DEPTH);
            return -1;
        }
        if (jeat_null_if_present(j)) return 0;
        if (jeat(j, '[', err, errcap) != 0) return -1;
        if (jpeek(j) == ']') { j->i++; return 0; }
        for (;;) {
            if (out->n_sig >= 8) {
                set_err(err, errcap,
                        "fingerprint.signals: сигналов больше 8, буфер фиксирован (примета #%zu)",
                        out->n_sig + 1);
                return -1;
            }
            memset(&out->sig[out->n_sig], 0, sizeof out->sig[0]);
            out->n_sig++;
            if (parse_signal(j, &out->sig[out->n_sig - 1], depth + 2, err, errcap) != 0) return -1;
            int c = jpeek(j);
            if (c == ',') { j->i++; continue; }
            if (c == ']') { j->i++; break; }
            set_err(err, errcap, "ожидался ',' или ']' в массиве signals (позиция %zu)", j->i);
            return -1;
        }
        return 0;
    }
    return jskip_value(j, depth + 1, err, errcap);
}
static int parse_fp(jctx *j, d2k_cat_fp *out, int depth, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    return parse_object(j, handle_fp_key, out, depth, err, errcap);
}

/* --------------------------------------------------------------------
 * Планы и привязки.
 * -------------------------------------------------------------------- */

static int handle_plan_key(jctx *j, const char *key, void *ctx, int depth, char *err, size_t errcap) {
    d2k_cat_plan *out = (d2k_cat_plan *)ctx;
    if (strcmp(key, "id") == 0)
        return jparse_string_fixed(j, out->id, sizeof out->id, "plan.id", err, errcap);
    if (strcmp(key, "proto") == 0)
        return jparse_string_fixed(j, out->proto, sizeof out->proto, "plan.proto", err, errcap);
    if (strcmp(key, "text") == 0) {
        free(out->text); /* дубль ключа "text" в одном объекте — не течь на первой копии */
        out->text = NULL;
        return jparse_string_dyn(j, &out->text, err, errcap);
    }
    if (strcmp(key, "added") == 0)
        return jparse_rfc3339(j, &out->added, "plan.added", err, errcap);
    if (strcmp(key, "successes") == 0)
        return jparse_i32(j, &out->successes, "plan.successes", err, errcap);
    if (strcmp(key, "enabled") == 0)
        return jparse_bool_i(j, &out->enabled, "plan.enabled", err, errcap);
    return jskip_value(j, depth + 1, err, errcap);
}
static int parse_plan(jctx *j, d2k_cat_plan *out, int depth, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    return parse_object(j, handle_plan_key, out, depth, err, errcap);
}
static int elem_plan(jctx *j, void *o, int depth, char *err, size_t errcap) {
    return parse_plan(j, (d2k_cat_plan *)o, depth, err, errcap);
}

/* transport — поле, которого нет в Go-структуре Binding (см. d2k_catalog.h
 * про то, зачем оно и почему совместимость односторонняя). Для файла,
 * снятого до его появления, ключ "transport" в объекте попросту
 * отсутствует — handle_binding_key на него не попадёт, а memset в
 * parse_binding уже оставил 0 ("не записано"), см. testdata и
 * check_transport_default_zero_on_old_file. Ровно то же и по той же
 * механике верно для shape/verified_by, заведённых позже (см. d2k_catalog.h
 * про контекст проверки): ключей нет — поля остаются нулями, и такая
 * привязка совместима с любой формой. */
static int handle_binding_key(jctx *j, const char *key, void *ctx, int depth, char *err, size_t errcap) {
    d2k_cat_binding *out = (d2k_cat_binding *)ctx;
    if (strcmp(key, "kind") == 0)
        return jparse_string_fixed(j, out->kind, sizeof out->kind, "binding.kind", err, errcap);
    if (strcmp(key, "target") == 0)
        return jparse_string_fixed(j, out->target, sizeof out->target, "binding.target", err, errcap);
    if (strcmp(key, "plan_id") == 0)
        return jparse_string_fixed(j, out->plan_id, sizeof out->plan_id, "binding.plan_id", err, errcap);
    if (strcmp(key, "level") == 0)
        return jparse_i32(j, &out->level, "binding.level", err, errcap);
    if (strcmp(key, "confirmed") == 0)
        return jparse_rfc3339(j, &out->confirmed, "binding.confirmed", err, errcap);
    if (strcmp(key, "successes") == 0)
        return jparse_i32(j, &out->successes, "binding.successes", err, errcap);
    if (strcmp(key, "enabled") == 0)
        return jparse_bool_i(j, &out->enabled, "binding.enabled", err, errcap);
    if (strcmp(key, "transport") == 0)
        return jparse_u8(j, &out->transport, "binding.transport", err, errcap);
    if (strcmp(key, "dns_authenticated") == 0)
        return jparse_bool_i(j, &out->dns_authenticated, "binding.dns_authenticated", err, errcap);
    if (strcmp(key, "dns_dot") == 0)
        return jparse_bool_i(j, &out->dns_dot, "binding.dns_dot", err, errcap);
    if (strcmp(key, "dns_query_bytes") == 0)
        return jparse_u16(j,&out->dns_query_bytes,"binding.dns_query_bytes",err,errcap);
    if (strcmp(key, "dns_http_version") == 0) {
        if (jparse_u8(j,&out->dns_http_version,"binding.dns_http_version",err,errcap))return -1;
        if (out->dns_http_version!=1 && out->dns_http_version!=2) {
            set_err(err,errcap,"binding.dns_http_version must be 1 or 2");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "dns_port") == 0) {
        if (jparse_u16(j, &out->dns_port, "binding.dns_port", err, errcap) != 0) return -1;
        if (!out->dns_port) {
            set_err(err, errcap, "binding.dns_port must be 1..65535");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "dns_name") == 0)
        return jparse_string_fixed(j, out->dns_name, sizeof out->dns_name,
                                   "binding.dns_name", err, errcap);
    if (strcmp(key, "dns_address") == 0) {
        if (jparse_string_fixed(j, out->dns_address, sizeof out->dns_address,
                                "binding.dns_address", err, errcap) != 0) return -1;
        if (!out->dns_address[0]) {
            set_err(err, errcap, "binding.dns_address must be a numeric address");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "server_port") == 0)
        return jparse_u16(j, &out->server_port, "binding.server_port", err, errcap);
    if (strcmp(key, "family") == 0) {
        if (jparse_u8(j, &out->family, "binding.family", err, errcap) != 0) return -1;
        if (out->family != 4 && out->family != 6) {
            if (err && errcap) snprintf(err, errcap, "binding.family must be 4 or 6");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "shape") == 0)
        return jparse_u8(j, &out->shape, "binding.shape", err, errcap);
    if (strcmp(key, "verified_by") == 0)
        return jparse_u8(j, &out->verified_by, "binding.verified_by", err, errcap);
    if (strcmp(key, "input") == 0)
        return jparse_u8(j, &out->input, "binding.input", err, errcap);
    if (strcmp(key, "probe_path") == 0)
        return jparse_string_fixed(j, out->probe_path, sizeof out->probe_path,
                                   "binding.probe_path", err, errcap);
    if (strcmp(key, "preflight_name") == 0)
        return jparse_string_fixed(j, out->preflight_name, sizeof out->preflight_name,
                                   "binding.preflight_name", err, errcap);
    if (strcmp(key, "ech_origin") == 0)
        return jparse_string_fixed(j, out->ech_origin, sizeof out->ech_origin,
                                   "binding.ech_origin", err, errcap);
    if (strcmp(key, "recheck_since") == 0)
        return jparse_rfc3339(j, &out->recheck_since, "binding.recheck_since", err, errcap);
    if (strcmp(key, "budget") == 0)
        return jparse_u8(j, &out->budget, "binding.budget", err, errcap);
    return jskip_value(j, depth + 1, err, errcap);
}
static int dns_binding_address_valid(const d2k_cat_binding *b) {
    uint8_t address[16];
    if (!b->dns_address[0]) return 1; /* No recorded DNS address. */
    return memchr(b->dns_address, 0, sizeof b->dns_address) != NULL &&
           (b->family == 0 || b->family == 4 || b->family == 6) &&
           inet_pton(b->family == 6 ? AF_INET6 : AF_INET, b->dns_address, address) == 1;
}

static int plain_dns_binding_valid(const d2k_cat_binding *b) {
    if (b->shape!=D2K_CAT_SHAPE_DNS)return !b->dns_query_bytes;
    unsigned prefix=b->transport==6 ? 2 : 0;
    return (b->transport==6 || b->transport==17) &&
        b->dns_query_bytes>=17+prefix && b->dns_query_bytes<=272+prefix &&
        !b->dns_authenticated && !b->dns_dot && !b->dns_http_version && !b->probe_path[0] &&
        b->dns_name[0] && b->dns_address[0] && !strcmp(b->dns_address,b->target) &&
        b->dns_port==b->server_port && b->server_port && !strcmp(b->kind,"service") &&
        b->level>=3 && b->verified_by==D2K_VERBY_PROBE && b->budget==D2K_CAT_BUDGET_PASSED;
}

static int parse_binding(jctx *j, d2k_cat_binding *out, int depth, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    out->family = 4;
    if (parse_object(j, handle_binding_key, out, depth, err, errcap)) return -1;
    if (!dns_binding_address_valid(out)) {
        set_err(err, errcap, "binding.dns_address must be numeric and match binding.family");
        return -1;
    }
    if (!plain_dns_binding_valid(out)) {
        set_err(err,errcap,"invalid plain DNS proof or endpoint");
        return -1;
    }
    return 0;
}
static int service_binding_valid(const d2k_cat_binding *b) {
    uint8_t address[16];
    /* Shapes share the control protocol numbering: TLS 1/2/6, QUIC 3,
       STUN/voice 5, RAW 8 with explicit TCP/UDP transport. No wildcard context. */
    int shape_ok = (b->transport == 6 && (b->shape == 1 || b->shape == 2 || b->shape == 6 || b->shape == 8)) ||
                   (b->transport == 17 && (b->shape == 3 || b->shape == 5 || b->shape == 8)) ||
                   b->shape==D2K_CAT_SHAPE_DNS;
    return !strcmp(b->kind, "service") && b->server_port && shape_ok &&
           (b->family == 4 || b->family == 6) &&
           inet_pton(b->family == 6 ? AF_INET6 : AF_INET, b->target, address) == 1;
}

static int elem_binding(jctx *j, void *o, int depth, char *err, size_t errcap) {
    d2k_cat_binding *b = o;
    if (parse_binding(j, b, depth, err, errcap)) return -1;
    if (b->server_port || !strcmp(b->kind, "service")) {
        set_err(err, errcap, "service binding must be in endpoints, not legacy bindings");
        return -1;
    }
    return 0;
}

static int elem_endpoint(jctx *j, void *o, int depth, char *err, size_t errcap) {
    d2k_cat_binding *b = o;
    if (parse_binding(j, b, depth, err, errcap)) return -1;
    if (!service_binding_valid(b)) {
        set_err(err, errcap, "invalid service address, port or protocol context");
        return -1;
    }
    return 0;
}

/* Числа поля d2k_cat_binding.shape — ЭТО ЗНАЧЕНИЯ d2k_shape, а не своя
 * нумерация (см. d2k_catalog.h). Связь закреплена на сборке, потому что
 * проверить её иначе нечем: перестановка перечисления в d2k_hello.h ничего
 * здесь не сломает — она молча переименует то, что уже записано в файл на
 * роутере, и накопленные привязки начнут утверждать про форму приветствия
 * обратное тому, что измерялось. Отрицательный размер массива — способ
 * сказать это компилятору на C99, где _Static_assert ещё нет. */
typedef char d2k_cat_shape_numbering_check[
    (D2K_SHAPE_MODERN == 1 && D2K_SHAPE_LEGACY == 2) ? 1 : -1];

int d2k_cat_shape_fits(uint8_t stored, uint8_t got) {
    /* Ноль с любой стороны — «не измерено» (§2.4), и оно не противоречит
       ничему: старый файл без поля совместим с любой формой, а проверка без
       измеренной формы не спорит с записанной. Противоречат только две
       РАЗНЫЕ измеренные формы. */
    if (stored == 0 || got == 0) { return 1; }
    return stored == got ? 1 : 0;
}

/* --------------------------------------------------------------------
 * Коробка и каталог целиком.
 * -------------------------------------------------------------------- */

/* ВЕКТОР СВОЙСТВ КОРОБКИ (23.10.2026). Ключи — имена полей d2k_box_props;
 * отсутствующий ключ оставляет поле неизмеренным. hops и reasm_boundary —
 * числа, и ноль в них значит «не измерено» (расстояния в нуль хопов и порога
 * в нулевой позиции не бывает), поэтому отдельного признака им не нужно. */
static int handle_props_key(jctx *j, const char *key, void *ctx, int depth, char *err, size_t errcap) {
    d2k_cat_props *out = (d2k_cat_props *)ctx;
    if (strcmp(key, "reassembles") == 0)
        return jparse_tri(j, &out->p.reassembles, "properties.reassembles", err, errcap);
    if (strcmp(key, "parses_l7") == 0)
        return jparse_tri(j, &out->p.parses_l7, "properties.parses_l7", err, errcap);
    if (strcmp(key, "validates_checksum") == 0)
        return jparse_tri(j, &out->p.validates_checksum, "properties.validates_checksum", err, errcap);
    if (strcmp(key, "tolerates_reorder") == 0)
        return jparse_tri(j, &out->p.tolerates_reorder, "properties.tolerates_reorder", err, errcap);
    if (strcmp(key, "tolerates_left_overlap") == 0)
        return jparse_tri(j, &out->p.tolerates_left_overlap, "properties.tolerates_left_overlap", err, errcap);
    if (strcmp(key, "counts_duplicates") == 0)
        return jparse_tri(j, &out->p.counts_duplicates, "properties.counts_duplicates", err, errcap);
    if (strcmp(key, "inspects_syn") == 0)
        return jparse_tri(j, &out->p.inspects_syn, "properties.inspects_syn", err, errcap);
    if (strcmp(key, "validates_md5") == 0)
        return jparse_tri(j, &out->p.validates_md5, "properties.validates_md5", err, errcap);
    if (strcmp(key, "validates_seq_window") == 0)
        return jparse_tri(j, &out->p.validates_seq_window, "properties.validates_seq_window", err, errcap);
    if (strcmp(key, "validates_timestamps") == 0)
        return jparse_tri(j, &out->p.validates_timestamps, "properties.validates_timestamps", err, errcap);
    if (strcmp(key, "overlap_covers_sni") == 0)
        return jparse_tri(j, &out->p.overlap_covers_sni, "properties.overlap_covers_sni", err, errcap);
    if (strcmp(key, "handles_urgent") == 0)
        return jparse_tri(j, &out->p.handles_urgent, "properties.handles_urgent", err, errcap);
    if (strcmp(key, "response_gate") == 0)
        return jparse_tri(j, &out->p.response_gate, "properties.response_gate", err, errcap);
    if (strcmp(key, "gate_carry") == 0)
        return jparse_tri(j, &out->p.gate_carry, "properties.gate_carry", err, errcap);
    if (strcmp(key, "gate_own") == 0)
        return jparse_tri(j, &out->p.gate_hello_own, "properties.gate_own", err, errcap);
    if (strcmp(key, "gate_window") == 0)
        return jparse_u16(j, &out->p.gate_window, "properties.gate_window", err, errcap);
    if (strcmp(key, "gate_pieces") == 0)
        return jparse_u32(j, &out->p.gate_pieces, "properties.gate_pieces", err, errcap);
    if (strcmp(key, "gate_rtt") == 0)
        return jparse_u32(j, &out->p.gate_rtt_ms, "properties.gate_rtt", err, errcap);
    if (strcmp(key, "hops") == 0)
        return jparse_i32(j, &out->p.hops, "properties.hops", err, errcap);
    if (strcmp(key, "reasm_boundary") == 0)
        return jparse_i32(j, &out->p.reasm_boundary, "properties.reasm_boundary", err, errcap);
    if (strcmp(key, "client_shape") == 0)
        return jparse_u8(j, &out->p.client_shape, "properties.client_shape", err, errcap);
    if (strcmp(key, "measured_utc") == 0)
        return jparse_rfc3339(j, &out->measured_at, "properties.measured_utc", err, errcap);
    return jskip_value(j, depth + 1, err, errcap);
}

/* Массив фиксированный, как fingerprint.signals, и по той же причине: буфер
 * в структуре конечен, а молчаливая потеря одной из записей хуже отказа. */
static int parse_props(jctx *j, d2k_cat_box *out, int depth, char *err, size_t errcap) {
    if (depth + 1 > D2K_JSON_MAX_DEPTH) {
        set_err(err, errcap, "JSON вложен глубже %d уровней — отказ вместо риска переполнения стека",
                D2K_JSON_MAX_DEPTH);
        return -1;
    }
    if (jeat_null_if_present(j)) { return 0; }
    if (jeat(j, '[', err, errcap) != 0) { return -1; }
    if (jpeek(j) == ']') { j->i++; return 0; }
    for (;;) {
        if (out->n_props >= D2K_CAT_PROPS_MAX) {
            set_err(err, errcap,
                    "properties: записей больше %d, буфер фиксирован (запись #%zu)",
                    D2K_CAT_PROPS_MAX, out->n_props + 1);
            return -1;
        }
        memset(&out->props[out->n_props], 0, sizeof out->props[0]);
        out->n_props++;
        if (parse_object(j, handle_props_key, &out->props[out->n_props - 1],
                         depth + 2, err, errcap) != 0) { return -1; }
        int c = jpeek(j);
        if (c == ',') { j->i++; continue; }
        if (c == ']') { j->i++; break; }
        set_err(err, errcap, "ожидался ',' или ']' в массиве properties (позиция %zu)", j->i);
        return -1;
    }
    return 0;
}

static int handle_box_key(jctx *j, const char *key, void *ctx, int depth, char *err, size_t errcap) {
    d2k_cat_box *out = (d2k_cat_box *)ctx;
    if (strcmp(key, "id") == 0)
        return jparse_string_fixed(j, out->id, sizeof out->id, "box.id", err, errcap);
    if (strcmp(key, "created") == 0)
        return jparse_rfc3339(j, &out->created, "box.created", err, errcap);
    if (strcmp(key, "updated") == 0)
        return jparse_rfc3339(j, &out->updated, "box.updated", err, errcap);
    if (strcmp(key, "fingerprint") == 0)
        return parse_fp(j, &out->fp, depth + 1, err, errcap);
    if (strcmp(key, "properties") == 0)
        return parse_props(j, out, depth + 1, err, errcap);
    if (strcmp(key, "plans") == 0) {
        size_t cap = out->n_plans; /* см. grow() про то, почему не 0 */
        return parse_array(j, (void **)&out->plans, &out->n_plans, &cap, &out->cap_plans,
                            sizeof(d2k_cat_plan), elem_plan, "plans", depth + 1, err, errcap);
    }
    if (strcmp(key, "bindings") == 0 || strcmp(key, "endpoints") == 0) {
        size_t cap = out->n_binds;
        return parse_array(j, (void **)&out->binds, &out->n_binds, &cap, &out->cap_binds,
                            sizeof(d2k_cat_binding), !strcmp(key, "endpoints") ? elem_endpoint : elem_binding,
                            key, depth + 1, err, errcap);
    }
    return jskip_value(j, depth + 1, err, errcap);
}
static int parse_box(jctx *j, d2k_cat_box *out, int depth, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    return parse_object(j, handle_box_key, out, depth, err, errcap);
}
static int elem_box(jctx *j, void *o, int depth, char *err, size_t errcap) {
    return parse_box(j, (d2k_cat_box *)o, depth, err, errcap);
}

/* "schema" и верхнеуровневый "updated" пропускаются jskip_value: в
 * d2k_catalog им нет соответствующего поля (см. d2k_catalog.h — подробно
 * о том, почему это не потеря: schema всегда константа 1, updated Go
 * перезаписывает текущим временем на каждой записи независимо от
 * прочитанного). */
static int handle_domain_observation(jctx *j,const char *key,void *ctx,
                                    int depth,char *err,size_t errcap) {
    d2k_group_observation *o=ctx;
    if(!strcmp(key,"name")) return jparse_string_fixed(j,o->name,sizeof o->name,"domain.name",err,errcap);
    if(!strcmp(key,"plan_id")) return jparse_string_fixed(j,o->plan_id,sizeof o->plan_id,"domain.plan_id",err,errcap);
    if(!strcmp(key,"transport")) return jparse_u8(j,&o->key.transport,"domain.transport",err,errcap);
    if(!strcmp(key,"family")) return jparse_u8(j,&o->key.family,"domain.family",err,errcap);
    if(!strcmp(key,"shape")) return jparse_u8(j,&o->key.shape,"domain.shape",err,errcap);
    if(!strcmp(key,"probe_path")) return jparse_string_fixed(j,o->key.probe_path,sizeof o->key.probe_path,"domain.path",err,errcap);
    if(!strcmp(key,"ech_origin")) return jparse_string_fixed(j,o->key.ech_origin,sizeof o->key.ech_origin,"domain.origin",err,errcap);
    if(!strcmp(key,"at")) return jparse_rfc3339(j,&o->at,"domain.at",err,errcap);
    if(!strcmp(key,"evidence")) {
        uint8_t value=0;
        if(jparse_u8(j,&value,"domain.evidence",err,errcap)) return -1;
        o->evidence=value; return 0;
    }
    return jskip_value(j,depth+1,err,errcap);
}

static int parse_domain_observations(jctx *j,d2k_group_state *s,int depth,
                                     char *err,size_t errcap) {
    if(depth>D2K_JSON_MAX_DEPTH) { set_err(err,errcap,"domain observations too deep"); return -1; }
    if(d2k_group_store_open(s,j->store_path)) {
        /* No flash-backed workspace: exact plans still load in full, family
           learning is degraded. Only the span of the saved history is noted
           here; d2k_catalog_load maps the original inode read-only for it.
           It is never parsed into rows or copied to the heap. */
        if(jpeek(j)!='[' || s->preserved_len) {
            set_err(err,errcap,"invalid domain observations array"); return -1;
        }
        size_t start=j->i;
        if(jskip_value(j,depth,err,errcap)) return -1;
        s->preserved_off=start; s->preserved_len=j->i-start;
        return 0;
    }
    if(jeat(j,'[',err,errcap)) return -1;
    if(jpeek(j)==']') { j->i++; return 0; }
    for(;;) {
        if(d2k_group_store_reserve(s,s->n_observations+1)) {
            set_err(err,errcap,"cannot grow domain observation store"); return -1;
        }
        d2k_group_observation *o=&d2k_group_rows(s)[s->n_observations++];
        memset(o,0,sizeof *o);
        if(parse_object(j,handle_domain_observation,o,depth+1,err,errcap)) return -1;
        int c=jpeek(j);
        if(c==']') { j->i++; return 0; }
        if(c!=',') { set_err(err,errcap,"invalid domain observations array"); return -1; }
        j->i++;
    }
}

static int handle_net_whitelist_key(jctx *j, const char *key, void *ctx, int depth,
                                    char *err, size_t errcap) {
    d2k_net_whitelist *n = (d2k_net_whitelist *)ctx;
    if (!strcmp(key, "name")) return jparse_string_fixed(j, n->name, sizeof n->name, "network_whitelist.name", err, errcap);
    if (!strcmp(key, "searched")) return jparse_bool_i(j, &n->searched, "network_whitelist.searched", err, errcap);
    if (!strcmp(key, "tx_only")) return jparse_bool_i(j, &n->tx_only, "network_whitelist.tx_only", err, errcap);
    if (!strcmp(key, "confirmed_utc")) return jparse_rfc3339(j, &n->confirmed_at, "network_whitelist.confirmed_utc", err, errcap);
    return jskip_value(j, depth + 1, err, errcap);
}

static int handle_catalog_key(jctx *j, const char *key, void *ctx, int depth, char *err, size_t errcap) {
    d2k_catalog *out = (d2k_catalog *)ctx;
    if (strcmp(key, "boxes") == 0) {
        size_t cap = out->n_boxes;
        return parse_array(j, (void **)&out->boxes, &out->n_boxes, &cap, &out->cap_boxes,
                            sizeof(d2k_cat_box), elem_box, "boxes", depth + 1, err, errcap);
    }
    if(!strcmp(key,"domain_observations") || !strcmp(key,"domain_groups_frozen") ||
       !strcmp(key,"domain_groups_disabled") || !strcmp(key,"domain_groups_disabled_at")) {
        if(!out->groups) out->groups=calloc(1,sizeof *out->groups);
        if(!out->groups) { set_err(err,errcap,"memory: domain groups"); return -1; }
        if(!strcmp(key,"domain_groups_frozen"))
            return jparse_bool_i(j,&out->groups->frozen,"domain_groups_frozen",err,errcap);
        if(!strcmp(key,"domain_groups_disabled"))
            return jparse_bool_i(j,&out->groups->disabled,"domain_groups_disabled",err,errcap);
        /* Optional: catalogs written before it load as 0. */
        if(!strcmp(key,"domain_groups_disabled_at"))
            return jparse_rfc3339(j,&out->groups->disabled_at,"domain_groups_disabled_at",err,errcap);
        return parse_domain_observations(j,out->groups,depth+1,err,errcap);
    }
    if (!strcmp(key, "network_whitelist")) {
        return parse_object(j, handle_net_whitelist_key, &out->net, depth + 1, err, errcap);
    }
    /* domain_groups is a human-readable derived snapshot, never authority
       to activate a rule without its retained learning observations. */
    return jskip_value(j, depth + 1, err, errcap);
}
static int parse_catalog_obj(jctx *j, d2k_catalog *out, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    /* Вершина спуска: глубина 1 (мы вот-вот войдём в самую внешнюю '{').
       Дальше глубина считается ОТСЮДА на каждый вложенный уровень — см.
       D2K_JSON_MAX_DEPTH про весь путь catalog{1->boxes[2->box{3->... */
    return parse_object(j, handle_catalog_key, out, 1, err, errcap);
}

static int preflight_bindings_valid(const d2k_catalog *c, char *err, size_t cap) {
    for(size_t i=0;i<c->n_boxes;i++) {
        const d2k_cat_box *box=&c->boxes[i];
        for(size_t j=0;j<box->n_plans;j++) {
            const d2k_cat_plan *p=&box->plans[j];
            char why[160];
            if(!p->text || d2k_plan_text_requires_endpoint(p->text,why,sizeof why)!=1)continue;
            for(size_t k=0;k<box->n_binds;k++) {
                const d2k_cat_binding *b=&box->binds[k];
                if(!strcmp(b->plan_id,p->id) &&
                   (!service_binding_valid(b) || b->transport!=6)) {
                    set_err(err,cap,"preflight requires a TCP service endpoint binding");return 0;
                }
            }
        }
    }
    return 1;
}

static int domain_group_available(const void *ctx,const d2k_domain_group *g) {
    const d2k_catalog *cat=ctx;
    const char *proto=g->key.transport==17?"quic":"tls";
    for(size_t bi=0;bi<cat->n_boxes;bi++) {
        const d2k_cat_box *b=&cat->boxes[bi];
        for(size_t pi=0;pi<b->n_plans;pi++) {
            const d2k_cat_plan *p=&b->plans[pi];
            if(p->enabled && p->text && !strcmp(p->id,g->plan_id) &&
               !strcmp(p->proto,proto)) return 1;
        }
    }
    return 0;
}
static void prune_unavailable_domain_groups(d2k_catalog *cat) {
    d2k_group_state *s=cat->groups;
    if(!s) return;
    for(size_t i=0;i<s->n_groups;) {
        const d2k_domain_group *g=&s->groups[i];
        if(!domain_group_available(cat,g)) s->groups[i]=s->groups[--s->n_groups]; else i++;
    }
}

/* --------------------------------------------------------------------
 * Освобождение. Определено ДО d2k_catalog_load, потому что тот зовёт
 * d2k_catalog_free на пути отказа (объявление берётся из d2k_catalog.h в
 * любом случае, но порядок определений в файле — снизу вверх без
 * исключений, см. шапку).
 * -------------------------------------------------------------------- */

static void free_box(d2k_cat_box *b) {
    for (size_t i = 0; i < b->n_plans; i++) {
        free(b->plans[i].text);
    }
    free(b->plans);
    free(b->binds);
    b->plans = NULL; b->n_plans = b->cap_plans = 0;
    b->binds = NULL; b->n_binds = b->cap_binds = 0;
}

void d2k_catalog_free(d2k_catalog *c) {
    if (!c) return;
    for (size_t i = 0; i < c->n_boxes; i++) {
        free_box(&c->boxes[i]);
    }
    free(c->boxes);
    d2k_group_store_close(c->groups);
    free(c->groups);
    c->groups = NULL;
    c->boxes = NULL;
    c->n_boxes = c->cap_boxes = 0;
}

/* --------------------------------------------------------------------
 * Чтение файла и публичная точка входа.
 * -------------------------------------------------------------------- */

/* The catalog is parsed from a read-only mapping of the opened inode with
   explicit bounds (the parser never relies on a terminator), not a heap copy
   of the whole file. An empty file maps nothing and parses as empty input. */
static int map_whole_file(const char *path, const char **map_out, size_t *len_out,
                          uint64_t *dev_out, uint64_t *ino_out, char *err, size_t errcap) {
    *map_out = NULL; *len_out = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        set_err(err, errcap, "%s: %s", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uintmax_t)st.st_size > (uintmax_t)SIZE_MAX) {
        set_err(err, errcap, "%s: не обычный файл или размер не читается", path);
        close(fd);
        return -1;
    }
    size_t len = (size_t)st.st_size;
    *dev_out = (uint64_t)st.st_dev; *ino_out = (uint64_t)st.st_ino;
    if (len) {
        void *m = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
        if (m == MAP_FAILED) {
            set_err(err, errcap, "%s: отображение не удалось: %s", path, strerror(errno));
            close(fd);
            return -1;
        }
        *map_out = m;
    }
    close(fd);
    *len_out = len;
    return 0;
}

int d2k_catalog_load(const char *path, d2k_catalog *out, char *err, size_t errcap) {
    if (err && errcap) err[0] = '\0';
    memset(out, 0, sizeof *out);

    const char *map = NULL;
    size_t len = 0;
    uint64_t dev = 0, ino = 0;
    if (map_whole_file(path, &map, &len, &dev, &ino, err, errcap) != 0) return -1;

    jctx j; j.s = map ? map : ""; j.len = len; j.i = 0;j.store_path=path;
    int rc = parse_catalog_obj(&j, out, err, errcap);
    if(rc==0 && !preflight_bindings_valid(out,err,errcap))rc=-1;
    int groups_were_frozen=out->groups && out->groups->frozen;
    if(rc==0 && out->groups) {
        out->groups->plan_available=domain_group_available;
        out->groups->plan_available_ctx=out;
    }
    if(rc==0 && out->groups && d2k_group_restore(out->groups)) {
        set_err(err,errcap,"invalid domain learning observations"); rc=-1;
    }
    if(rc==0 && groups_were_frozen && !out->groups->frozen) out->revision++;
    if(rc==0) prune_unavailable_domain_groups(out);

    /* Ревью 2026-09-10 (круг 1): курсор после успешного разбора не
       проверялся против конца буфера — "{}x" грузился как валидный пустой
       каталог, хвост терялся молча, и так же прошла бы склейка двух
       каталогов подряд (файл, расширенный лишними байтами, — реальный
       класс порчи). Go в этой же точке отказывает ("invalid character 'x'
       after top-level value") — без этой проверки наш разбор был мягче
       эталона на входах, где мягкость ничего хорошего не значит. jpeek
       пропускает пробелы САМ (см. его шапку) — законный завершающий
       перевод строки (store.go: b = append(b, '\n')) поэтому проходит, а
       любой РЕАЛЬНЫЙ байт после '}' — нет. */
    if (rc == 0) {
        int trailing = jpeek(&j);
        if (trailing >= 0) {
            set_err(err, errcap, "мусор после конца каталога: '%c' (позиция %zu)",
                    (char)trailing, j.i);
            rc = -1;
        }
    }
    /* Degraded family learning: the mapping of the original inode becomes
       the preserved history (page cache backed by flash, never a heap copy);
       it outlives an atomic replace of the path. Otherwise it is unmapped. */
    if (rc == 0 && map && out->groups && out->groups->store_failed && out->groups->preserved_len &&
        out->groups->preserved_off <= len && out->groups->preserved_len <= len - out->groups->preserved_off) {
        out->groups->preserved_map = map; out->groups->preserved_map_len = len;
        out->groups->preserved_dev = dev; out->groups->preserved_ino = ino;
        map = NULL;
    }
    if (map) munmap((void *)map, len);

    if (rc != 0) {
        /* Незакрытая структура/дробное число/переполнение/мусор в хвосте —
           отказ разбора ЦЕЛИКОМ, а не результат с потерянной частью (см.
           шапку файла и d2k_catalog.h). Всё, что успело выделиться до
           отказа, найдено и освобождено здесь же, вызывающему звать free
           не на чем и не нужно (см. d2k_catalog.h и test_catalog.c, блок
           про обрубок). */
        d2k_catalog_free(out);
        return -1;
    }
    return 0;
}

/* --------------------------------------------------------------------
 * Запись — тот же вид, что производит Go (2-пробельный отступ, порядок
 * ключей как у Box/Plan/Binding/Signal, время строкой RFC 3339 с Z).
 * -------------------------------------------------------------------- */

static void write_json_string(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        case '\b': fputs("\\b", f); break;
        case '\f': fputs("\\f", f); break;
        default:
            if (*p < 0x20) {
                fprintf(f, "\\u%04x", *p);
            } else {
                fputc(*p, f); /* UTF-8 многобайтовые последовательности проходят как есть — валидный JSON */
            }
        }
    }
    fputc('"', f);
}

static void wr_indent(FILE *f, int depth) {
    for (int i = 0; i < depth; i++) fputs("  ", f);
}

typedef void (*elem_writer)(FILE *f, const void *elem, int depth);

/* Симметрично parse_array на чтение: та же развилка (пусто -> "[]", иначе
 * многострочный список с запятыми между элементами и без запятой после
 * последнего) в одном месте вместо четырёх копий (signals/plans/
 * bindings/boxes). */
static void write_json_array(FILE *f, const void *arr, size_t n, size_t elemsize,
                              elem_writer wr, int depth) {
    if (n == 0) { fputs("[]", f); return; }
    fputs("[\n", f);
    for (size_t i = 0; i < n; i++) {
        wr(f, (const char *)arr + i * elemsize, depth + 1);
        fputs(i + 1 < n ? ",\n" : "\n", f);
    }
    wr_indent(f, depth);
    fputc(']', f);
}

static void write_signal_elem(FILE *f, const void *e, int depth) {
    const d2k_cat_signal *s = (const d2k_cat_signal *)e;
    wr_indent(f, depth); fputs("{\n", f);
    wr_indent(f, depth + 1); fputs("\"kind\": ", f); write_json_string(f, s->kind); fputs(",\n", f);
    wr_indent(f, depth + 1); fprintf(f, "\"ttl\": %u,\n", (unsigned)s->ttl);
    wr_indent(f, depth + 1); fprintf(f, "\"ttl_delta\": %d,\n", s->ttl_delta);
    wr_indent(f, depth + 1); fprintf(f, "\"tos\": %u,\n", (unsigned)s->tos);
    wr_indent(f, depth + 1); fprintf(f, "\"ipid\": %u,\n", (unsigned)s->ipid);
    wr_indent(f, depth + 1); fprintf(f, "\"volume\": %d,\n", s->volume);
    wr_indent(f, depth + 1); fprintf(f, "\"seen\": %d", s->seen);
    if (s->packets) { /* только посчитанный бюджет (задача 55) */
        fputs(",\n", f); wr_indent(f, depth + 1); fprintf(f, "\"packets\": %d", s->packets);
    }
    fputc('\n', f);
    wr_indent(f, depth); fputc('}', f);
}

static void write_fp(FILE *f, const d2k_cat_fp *fp, int depth) {
    fputs("{\n", f);
    wr_indent(f, depth + 1); fprintf(f, "\"method\": %d,\n", fp->method);
    wr_indent(f, depth + 1); fputs("\"signals\": ", f);
    write_json_array(f, fp->sig, fp->n_sig, sizeof(d2k_cat_signal), write_signal_elem, depth + 1);
    fputc('\n', f);
    wr_indent(f, depth); fputc('}', f);
}

static void write_plan_elem(FILE *f, const void *e, int depth) {
    const d2k_cat_plan *p = (const d2k_cat_plan *)e;
    char added_s[32];
    format_rfc3339(p->added, added_s, sizeof added_s);
    wr_indent(f, depth); fputs("{\n", f);
    wr_indent(f, depth + 1); fputs("\"id\": ", f); write_json_string(f, p->id); fputs(",\n", f);
    wr_indent(f, depth + 1); fputs("\"proto\": ", f); write_json_string(f, p->proto); fputs(",\n", f);
    wr_indent(f, depth + 1); fputs("\"text\": ", f); write_json_string(f, p->text ? p->text : ""); fputs(",\n", f);
    wr_indent(f, depth + 1); fprintf(f, "\"added\": \"%s\",\n", added_s);
    wr_indent(f, depth + 1); fprintf(f, "\"successes\": %d,\n", p->successes);
    wr_indent(f, depth + 1); fprintf(f, "\"enabled\": %s\n", p->enabled ? "true" : "false");
    wr_indent(f, depth); fputc('}', f);
}

static void write_binding_elem(FILE *f, const void *e, int depth) {
    const d2k_cat_binding *bd = (const d2k_cat_binding *)e;
    char confirmed_s[32];
    format_rfc3339(bd->confirmed, confirmed_s, sizeof confirmed_s);
    wr_indent(f, depth); fputs("{\n", f);
    wr_indent(f, depth + 1); fputs("\"kind\": ", f); write_json_string(f, bd->kind); fputs(",\n", f);
    wr_indent(f, depth + 1); fputs("\"target\": ", f); write_json_string(f, bd->target); fputs(",\n", f);
    wr_indent(f, depth + 1); fputs("\"plan_id\": ", f); write_json_string(f, bd->plan_id); fputs(",\n", f);
    wr_indent(f, depth + 1); fprintf(f, "\"level\": %d,\n", bd->level);
    wr_indent(f, depth + 1); fprintf(f, "\"confirmed\": \"%s\",\n", confirmed_s);
    wr_indent(f, depth + 1); fprintf(f, "\"successes\": %d,\n", bd->successes);
    wr_indent(f, depth + 1); fprintf(f, "\"enabled\": %s,\n", bd->enabled ? "true" : "false");
    /* transport — новое поле, последним, как в d2k_cat_binding (задание,
       "Produces"). Выводится всегда, даже 0 ("не записано") — Go
       незнакомое поле молча пропустит (см. d2k_catalog.h), а сохранить
       для НЕЁ omitempty-поведение Go смысла не имеет: этого поля в её
       структуре нет вообще, ей нечего сравнивать с нулём. */
    wr_indent(f, depth + 1); fprintf(f, "\"transport\": %u,\n", (unsigned)bd->transport);
    wr_indent(f, depth + 1); fprintf(f, "\"family\": %u,\n", (unsigned)(bd->family ? bd->family : 4));
    if (bd->server_port) {
        wr_indent(f, depth + 1); fprintf(f, "\"server_port\": %u,\n", (unsigned)bd->server_port);
    }
    /* shape/verified_by — контекст, в котором проверка состоялась; тем же
       порядком и по тем же правилам, что transport (Go их тоже не знает и
       молча пропустит). Ноль выводится наравне с остальным: «не измерено» —
       такое же состояние записи, как измеренное, и молчать о нём значило бы
       делать вид, что поля нет вовсе. */
    wr_indent(f, depth + 1); fprintf(f, "\"shape\": %u,\n", (unsigned)bd->shape);
    wr_indent(f, depth + 1); fprintf(f, "\"verified_by\": %u,\n", (unsigned)bd->verified_by);
    wr_indent(f, depth + 1); fprintf(f, "\"input\": %u", (unsigned)bd->input);
    if (bd->probe_path[0]) {
        fputs(",\n", f); wr_indent(f, depth + 1); fputs("\"probe_path\": ", f);
        write_json_string(f, bd->probe_path);
    }
    if (bd->preflight_name[0]) {
        fputs(",\n", f); wr_indent(f, depth + 1); fputs("\"preflight_name\": ", f);
        write_json_string(f, bd->preflight_name);
    }
    if (bd->dns_authenticated) {
        fputs(",\n", f); wr_indent(f, depth + 1); fputs("\"dns_authenticated\": true", f);
    }
    if (bd->dns_dot) {
        fputs(",\n", f); wr_indent(f, depth + 1); fputs("\"dns_dot\": true", f);
    }
    if (bd->dns_query_bytes) {
        fputs(",\n",f);wr_indent(f,depth+1);
        fprintf(f,"\"dns_query_bytes\": %u",(unsigned)bd->dns_query_bytes);
    }
    if (bd->dns_http_version) {
        fputs(",\n", f); wr_indent(f, depth + 1);
        fprintf(f,"\"dns_http_version\": %u",(unsigned)bd->dns_http_version);
    }
    if (bd->dns_port) {
        fputs(",\n", f); wr_indent(f, depth + 1);
        fprintf(f, "\"dns_port\": %u", (unsigned)bd->dns_port);
    }
    if (bd->dns_name[0]) {
        fputs(",\n", f); wr_indent(f, depth + 1); fputs("\"dns_name\": ", f);
        write_json_string(f, bd->dns_name);
    }
    if (bd->dns_address[0]) {
        fputs(",\n", f); wr_indent(f, depth + 1); fputs("\"dns_address\": ", f);
        write_json_string(f, bd->dns_address);
    }
    if (bd->ech_origin[0]) {
        fputs(",\n", f); wr_indent(f, depth + 1); fputs("\"ech_origin\": ", f);
        write_json_string(f, bd->ech_origin);
    }
    if (bd->recheck_since) {
        /* Только помеченная: отсутствие ключа и есть «не помечена» (задача 21). */
        char recheck_s[32];
        format_rfc3339(bd->recheck_since, recheck_s, sizeof recheck_s);
        fputs(",\n", f); wr_indent(f, depth + 1);
        fprintf(f, "\"recheck_since\": \"%s\"", recheck_s);
    }
    if (bd->budget) {
        /* Только проверенная: отсутствие ключа — «не проверено» (задача 55). */
        fputs(",\n", f); wr_indent(f, depth + 1);
        fprintf(f, "\"budget\": %u", (unsigned)bd->budget);
    }
    fputc('\n', f);
    wr_indent(f, depth); fputc('}', f);
}

/* ПИШЕТСЯ ТОЛЬКО ИЗМЕРЕННОЕ. Неизмеренный признак ключа не получает вовсе —
 * так «не измерено» и «нет» не сливаются в одно слово при перечитывании
 * (§2.4), и файл не растёт на знание, которого нет. */
static void write_tri(FILE *f, int depth, const char *key, int8_t v) {
    if (v != D2K_PROP_YES && v != D2K_PROP_NO) { return; }
    wr_indent(f, depth); fprintf(f, "\"%s\": \"%s\",\n", key, v == D2K_PROP_YES ? "yes" : "no");
}

static void write_props_elem(FILE *f, const void *e, int depth) {
    const d2k_cat_props *r = (const d2k_cat_props *)e;
    char at[32];
    format_rfc3339(r->measured_at, at, sizeof at);
    wr_indent(f, depth); fputs("{\n", f);
    write_tri(f, depth + 1, "reassembles", r->p.reassembles);
    write_tri(f, depth + 1, "parses_l7", r->p.parses_l7);
    write_tri(f, depth + 1, "validates_checksum", r->p.validates_checksum);
    write_tri(f, depth + 1, "tolerates_reorder", r->p.tolerates_reorder);
    write_tri(f, depth + 1, "tolerates_left_overlap", r->p.tolerates_left_overlap);
    write_tri(f, depth + 1, "counts_duplicates", r->p.counts_duplicates);
    write_tri(f, depth + 1, "inspects_syn", r->p.inspects_syn);
    write_tri(f, depth + 1, "validates_md5", r->p.validates_md5);
    write_tri(f, depth + 1, "validates_seq_window", r->p.validates_seq_window);
    write_tri(f, depth + 1, "validates_timestamps", r->p.validates_timestamps);
    write_tri(f, depth + 1, "overlap_covers_sni", r->p.overlap_covers_sni);
    write_tri(f, depth + 1, "handles_urgent", r->p.handles_urgent);
    if (r->p.hops > 0) { wr_indent(f, depth + 1); fprintf(f, "\"hops\": %d,\n", r->p.hops); }
    if (r->p.reasm_boundary > 0) {
        wr_indent(f, depth + 1); fprintf(f, "\"reasm_boundary\": %d,\n", r->p.reasm_boundary);
    }
    write_tri(f, depth + 1, "response_gate", r->p.response_gate);
    write_tri(f, depth + 1, "gate_carry", r->p.gate_carry);
    write_tri(f, depth + 1, "gate_own", r->p.gate_hello_own);
    if (r->p.gate_window) {
        wr_indent(f, depth + 1); fprintf(f, "\"gate_window\": %u,\n", (unsigned)r->p.gate_window);
    }
    if (r->p.gate_pieces) {
        wr_indent(f, depth + 1); fprintf(f, "\"gate_pieces\": %u,\n", (unsigned)r->p.gate_pieces);
    }
    if (r->p.gate_rtt_ms) {
        wr_indent(f, depth + 1); fprintf(f, "\"gate_rtt\": %u,\n", (unsigned)r->p.gate_rtt_ms);
    }
    /* Форма клиента и время — ключ и срок записи: пишутся всегда и последними,
       поэтому запятая стоит у всех полей выше, а не у последнего измеренного. */
    wr_indent(f, depth + 1); fprintf(f, "\"client_shape\": %u,\n", (unsigned)r->p.client_shape);
    wr_indent(f, depth + 1); fprintf(f, "\"measured_utc\": \"%s\"\n", at);
    wr_indent(f, depth); fputc('}', f);
}

/* Old releases ignore the endpoints array. Never serialize service authority
   in bindings: their parsers ignore unknown fields, including server_port. */
static void write_binding_array(FILE *f, const d2k_cat_box *b, int services, int depth) {
    size_t count = 0;
    for (size_t i = 0; i < b->n_binds; i++) {
        const d2k_cat_binding *bd = &b->binds[i];
        if ((!strcmp(bd->kind, "service")) != services) continue;
        fputs(count++ ? ",\n" : "[\n", f);
        write_binding_elem(f, bd, depth + 1);
    }
    if (count) { fputc('\n', f); wr_indent(f, depth); fputc(']', f); }
    else fputs("[]", f);
}

static void write_box_elem(FILE *f, const void *e, int depth) {
    const d2k_cat_box *b = (const d2k_cat_box *)e;
    char created_s[32], updated_s[32];
    format_rfc3339(b->created, created_s, sizeof created_s);
    format_rfc3339(b->updated, updated_s, sizeof updated_s);
    wr_indent(f, depth); fputs("{\n", f);
    wr_indent(f, depth + 1); fputs("\"id\": ", f); write_json_string(f, b->id); fputs(",\n", f);
    wr_indent(f, depth + 1); fprintf(f, "\"created\": \"%s\",\n", created_s);
    wr_indent(f, depth + 1); fprintf(f, "\"updated\": \"%s\",\n", updated_s);
    wr_indent(f, depth + 1); fputs("\"fingerprint\": ", f); write_fp(f, &b->fp, depth + 1); fputs(",\n", f);
    wr_indent(f, depth + 1); fputs("\"plans\": ", f);
    write_json_array(f, b->plans, b->n_plans, sizeof(d2k_cat_plan), write_plan_elem, depth + 1);
    fputs(",\n", f);
    wr_indent(f, depth + 1); fputs("\"bindings\": ", f);
    write_binding_array(f, b, 0, depth + 1);
    int services = 0;
    for (size_t i = 0; i < b->n_binds; i++)
        if (!strcmp(b->binds[i].kind, "service")) { services = 1; break; }
    if (services) {
        fputs(",\n", f);
        wr_indent(f, depth + 1); fputs("\"endpoints\": ", f);
        write_binding_array(f, b, 1, depth + 1);
    }
    if (b->n_props > 0) {
        /* Пустое знание ключа не получает: файл без вектора — обычное
           состояние коробки, которую ещё не измеряли. */
        fputs(",\n", f);
        wr_indent(f, depth + 1); fputs("\"properties\": ", f);
        write_json_array(f, b->props, b->n_props, sizeof(d2k_cat_props), write_props_elem, depth + 1);
    }
    fputc('\n', f);
    wr_indent(f, depth); fputc('}', f);
}

static void write_domain_key(FILE *f,const d2k_group_key *key) {
    fprintf(f,",\"transport\":%u,\"family\":%u,\"shape\":%u,\"probe_path\":",
            key->transport,key->family,key->shape);
    write_json_string(f,key->probe_path);
    fputs(",\"ech_origin\":",f); write_json_string(f,key->ech_origin);
}
static void write_domain_observation(FILE *f,const void *value,int depth) {
    const d2k_group_observation *o=value; char at[32];
    format_rfc3339(o->at,at,sizeof at);
    wr_indent(f,depth); fputs("{\"name\":",f); write_json_string(f,o->name);
    fputs(",\"plan_id\":",f); write_json_string(f,o->plan_id);
    write_domain_key(f,&o->key);
    fprintf(f,",\"evidence\":%u,\"at\":\"%s\"}",o->evidence,at);
}
static void write_domain_group(FILE *f,const void *value,int depth) {
    const d2k_domain_group *g=value;
    wr_indent(f,depth); fputs("{\"suffix\":",f); write_json_string(f,g->suffix);
    fputs(",\"plan_id\":",f); write_json_string(f,g->plan_id);
    write_domain_key(f,&g->key); fprintf(f,",\"evidence_count\":%u}",g->evidence_count);
}

int d2k_catalog_save(const d2k_catalog *c, const char *path, char *err, size_t errcap) {
    if (err && errcap) err[0] = '\0';
    if(!preflight_bindings_valid(c,err,errcap))return -1;
    /* Degraded family learning: the history lives only in the read-only
       mapping of the original catalog. Without it, refuse to save rather
       than write a catalog that has lost that history. */
    if (c->groups && c->groups->store_failed && c->groups->preserved_len &&
        (!c->groups->preserved_map ||
         c->groups->preserved_off > c->groups->preserved_map_len ||
         c->groups->preserved_len > c->groups->preserved_map_len - c->groups->preserved_off)) {
        set_err(err, errcap, "family history is not mapped; catalog not saved");
        return -1;
    }
    /* Writing in place would truncate the very inode the preserved history
       is read from; the atomic save writes a new inode and renames. */
    if (c->groups && c->groups->preserved_map) {
        struct stat st;
        if (stat(path, &st) == 0 && (uint64_t)st.st_dev == c->groups->preserved_dev &&
            (uint64_t)st.st_ino == c->groups->preserved_ino) {
            set_err(err, errcap, "%s holds the preserved family history; save atomically", path);
            return -1;
        }
    }
    /* Validate before opening/truncating the destination. */
    for (size_t i = 0; i < c->n_boxes; i++) {
        for (size_t k = 0; k < c->boxes[i].n_binds; k++) {
            const d2k_cat_binding *bd = &c->boxes[i].binds[k];
            if (!dns_binding_address_valid(bd)) {
                set_err(err, errcap, "refusing invalid DNS binding address or family");
                return -1;
            }
            if (!plain_dns_binding_valid(bd)) {
                set_err(err,errcap,"refusing invalid plain DNS proof or endpoint");
                return -1;
            }
            if ((bd->server_port || !strcmp(bd->kind, "service")) && !service_binding_valid(bd)) {
                set_err(err, errcap, "refusing invalid service binding");
                return -1;
            }
        }
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        set_err(err, errcap, "%s: %s", path, strerror(errno));
        return -1;
    }

    char now_s[32];
    format_rfc3339((int64_t)time(NULL), now_s, sizeof now_s);

    fputs("{\n", f);
    /* "schema" константой 1, не полем структуры — единственное значение,
       с которым Go вообще соглашается прочитать файл (Validate,
       internal/catalog/catalog.go — см. d2k_catalog.h). "updated" —
       текущее время: Go делает ТО ЖЕ САМОЕ на каждой записи, независимо
       от того, что было прочитано (internal/catalog/store.go,
       writeLocked: "s.cat.Updated = now"). */
    fputs("  \"schema\": 1,\n", f);
    fprintf(f, "  \"updated\": \"%s\",\n", now_s);
    fputs("  \"boxes\": ", f);
    write_json_array(f, c->boxes, c->n_boxes, sizeof(d2k_cat_box), write_box_elem, 1);
    if(c->groups) {
        fputs(",\n  \"domain_groups\": ",f);
        write_json_array(f,c->groups->groups,c->groups->n_groups,sizeof(d2k_domain_group),write_domain_group,1);
        fputs(",\n  \"domain_observations\": ",f);
        if(c->groups->store_failed && c->groups->preserved_len)
            fwrite(c->groups->preserved_map+c->groups->preserved_off,1,c->groups->preserved_len,f);
        else
            write_json_array(f,d2k_group_rows(c->groups),c->groups->n_observations,sizeof(d2k_group_observation),write_domain_observation,1);
        fprintf(f,",\n  \"domain_groups_frozen\": %s",c->groups->frozen?"true":"false");
        fprintf(f,",\n  \"domain_groups_disabled\": %s",c->groups->disabled?"true":"false");
        if(c->groups->disabled_at) {
            char at[32]; format_rfc3339(c->groups->disabled_at,at,sizeof at);
            fprintf(f,",\n  \"domain_groups_disabled_at\": \"%s\"",at);
        }
    }
    /* Белое имя сети пишется, только если подбор был (найдено или честно
       «не найдено»): пустое неискомое поле — то же, что его отсутствие,
       и старый файл не должен обрастать лишним ключом. */
    if(c->net.searched || c->net.name[0]) {
        fputs(",\n  \"network_whitelist\": {\"name\": ", f);
        write_json_string(f, c->net.name);
        fprintf(f,", \"searched\": %s", c->net.searched?"true":"false");
        /* Пишется только когда взведён: старый каталог не обрастает ключом, а
           его отсутствие читается как «доказано входящим обрывом». */
        if(c->net.tx_only) { fputs(", \"tx_only\": true", f); }
        if(c->net.confirmed_at) {
            char at[32]; format_rfc3339(c->net.confirmed_at,at,sizeof at);
            fprintf(f,", \"confirmed_utc\": \"%s\"",at);
        }
        fputs("}", f);
    }
    fputs("\n}\n", f);

    /* Проверяется КАЖДАЯ ошибка вплоть до закрытия: неотловленный сбой
       где-то посреди буферизованной записи выглядел бы как "файл записан"
       ровно так же, как настоящий успех (тот же довод, что для Sync/Close
       в Go-версии — internal/catalog/store.go). */
    int had_err = ferror(f);
    if (!had_err && (fflush(f) != 0 || fsync(fileno(f)) != 0)) had_err = 1;
    if (fclose(f) != 0) {
        set_err(err, errcap, "%s: закрытие файла не удалось", path);
        return -1;
    }
    if (had_err) {
        set_err(err, errcap, "%s: запись не удалась", path);
        return -1;
    }
    return 0;
}

/* rename в том же каталоге делает замену атомарной, fsync закрепляет её на диске. */
int d2k_catalog_save_atomic(const d2k_catalog *cat, const char *path,
                            char *err, size_t errcap) {
    char tmp[D2K_CATALOG_PATH_MAX + sizeof(".new")], dir[D2K_CATALOG_PATH_MAX];
    if (!path || strlen(path) >= sizeof dir) {
        set_err(err, errcap, "слишком длинный путь каталога (максимум %u байт)",
                (unsigned)(D2K_CATALOG_PATH_MAX - 1)); return -1;
    }
    snprintf(tmp, sizeof tmp, "%s.new", path);
    if (d2k_catalog_save(cat, tmp, err, errcap) != 0) {
        (void)remove(tmp); return -1;
    }
    if (rename(tmp, path) != 0) {
        set_err(err, errcap, "переименование %s: %s", tmp, strerror(errno));
        (void)remove(tmp); return -1;
    }
    const char *slash = strrchr(path, '/');
    if (slash) {
        size_t len = slash == path ? 1 : (size_t)(slash - path);
        memcpy(dir, path, len); dir[len] = '\0';
    } else strcpy(dir, ".");
    int fd = open(dir, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        set_err(err, errcap, "открытие каталога %s: %s", dir, strerror(errno));
        return -1;
    }
    int failed = fsync(fd), saved_errno = errno;
    if (close(fd) != 0 && failed == 0) { failed = -1; saved_errno = errno; }
    if (failed != 0) {
        set_err(err, errcap, "синхронизация каталога %s: %s", dir, strerror(saved_errno));
        return -1;
    }
    return 0;
}
