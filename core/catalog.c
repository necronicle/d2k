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

/* --------------------------------------------------------------------
 * Пропуск незнакомого значения.
 * -------------------------------------------------------------------- */

/* Пропускает одно JSON-значение произвольной формы — единственный
 * честный способ "не знать" незнакомое поле: прочитать и отбросить по
 * грамматике, а не угадать его длину. Числа проверяются ТЕМ ЖЕ
 * jparse_raw_int, что и известные поля: дробное число в пропускаемом поле
 * — такой же отказ, как в известном (см. jparse_raw_int — "плавающей
 * арифметики нет" про файл целиком, а не только про то, что эта версия
 * понимает). */
static int jskip_value(jctx *j, char *err, size_t errcap) {
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
            free(key);
            if (jeat(j, ':', err, errcap) != 0) return -1;
            if (jskip_value(j, err, errcap) != 0) return -1;
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
            if (jskip_value(j, err, errcap) != 0) return -1;
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

typedef int (*key_handler)(jctx *j, const char *key, void *ctx, char *err, size_t errcap);

/* Общий разбор JSON-объекта: скобки, запятые и чтение ключа — в одном
 * месте, а не в шести похожих функциях по отдельности (signal/
 * fingerprint/plan/binding/box/каталог). Обработчик решает только СВОЁ —
 * что делать со значением ДАННОГО ключа; неизвестный ключ — его забота
 * позвать jskip_value, не забота parse_object. */
static int parse_object(jctx *j, key_handler handle, void *ctx, char *err, size_t errcap) {
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
        int rc = handle(j, key, ctx, err, errcap);
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
 * лишнего удвоения. cap передаётся снаружи, а не хранится в d2k_cat_box/
 * d2k_catalog: в этих структурах его нет (см. "Produces" задания), и
 * вызывающий (handle_box_key/handle_catalog_key) инициализирует его
 * ТЕКУЩИМ числом элементов на каждый вызов — благодаря этому дубль ключа
 * "plans" в одном объекте (не встречается в реальных файлах, но не должен
 * переполнить буфер, если встретится) тоже получит верный размер, а не
 * решит, что ёмкость 0 при уже ненулевом числе элементов. */
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

typedef int (*elem_parser)(jctx *j, void *out_elem, char *err, size_t errcap);

/* Общий разбор JSON-массива в растущий буфер элементов фиксированного
 * размера. null — валидный пустой массив (см. jeat_null_if_present).
 * Слот резервируется (*n += 1) ДО разбора элемента — см. шапку файла про
 * инвариант очистки при отказе: это единственный способ гарантировать,
 * что d2k_catalog_free найдёт и освободит частично разобранный элемент,
 * а не только полностью разобранные. */
static int parse_array(jctx *j, void **arr, size_t *n, size_t *cap,
                        size_t elemsize, elem_parser parse_elem,
                        const char *what, char *err, size_t errcap) {
    if (jeat_null_if_present(j)) return 0;
    if (jeat(j, '[', err, errcap) != 0) return -1;
    if (jpeek(j) == ']') { j->i++; return 0; }
    for (;;) {
        void *p = grow(*arr, cap, *n, elemsize, err, errcap);
        if (!p) return -1;
        *arr = p;
        memset((char *)*arr + (*n) * elemsize, 0, elemsize);
        (*n)++;
        if (parse_elem(j, (char *)*arr + (*n - 1) * elemsize, err, errcap) != 0) return -1;
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

static int handle_signal_key(jctx *j, const char *key, void *ctx, char *err, size_t errcap) {
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
    return jskip_value(j, err, errcap);
}
static int parse_signal(jctx *j, d2k_cat_signal *out, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    return parse_object(j, handle_signal_key, out, err, errcap);
}

/* fingerprint.signals — единственный массив каталога, который НЕ растёт:
 * ёмкость d2k_cat_fp.sig фиксирована на 8 самим контрактом (см.
 * "Produces" задания и d2k_catalog.h), и девятая примета — отказ, а не
 * рост за пределы буфера или молчаливая потеря одной из девяти. Поэтому
 * этот цикл — не parse_array (которому есть куда расти), а bespoke, но
 * тот же приём "слот резервируется до разбора элемента". */
static int handle_fp_key(jctx *j, const char *key, void *ctx, char *err, size_t errcap) {
    d2k_cat_fp *out = (d2k_cat_fp *)ctx;
    if (strcmp(key, "method") == 0)
        return jparse_i32(j, &out->method, "fingerprint.method", err, errcap);
    if (strcmp(key, "signals") == 0) {
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
            if (parse_signal(j, &out->sig[out->n_sig - 1], err, errcap) != 0) return -1;
            int c = jpeek(j);
            if (c == ',') { j->i++; continue; }
            if (c == ']') { j->i++; break; }
            set_err(err, errcap, "ожидался ',' или ']' в массиве signals (позиция %zu)", j->i);
            return -1;
        }
        return 0;
    }
    return jskip_value(j, err, errcap);
}
static int parse_fp(jctx *j, d2k_cat_fp *out, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    return parse_object(j, handle_fp_key, out, err, errcap);
}

/* --------------------------------------------------------------------
 * Планы и привязки.
 * -------------------------------------------------------------------- */

static int handle_plan_key(jctx *j, const char *key, void *ctx, char *err, size_t errcap) {
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
    return jskip_value(j, err, errcap);
}
static int parse_plan(jctx *j, d2k_cat_plan *out, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    return parse_object(j, handle_plan_key, out, err, errcap);
}
static int elem_plan(jctx *j, void *o, char *err, size_t errcap) {
    return parse_plan(j, (d2k_cat_plan *)o, err, errcap);
}

/* transport — поле, которого нет в Go-структуре Binding (см. d2k_catalog.h
 * про то, зачем оно и почему совместимость односторонняя). Для файла,
 * снятого до его появления, ключ "transport" в объекте попросту
 * отсутствует — handle_binding_key на него не попадёт, а memset в
 * parse_binding уже оставил 0 ("не записано"), см. testdata и
 * check_transport_default_zero_on_old_file. */
static int handle_binding_key(jctx *j, const char *key, void *ctx, char *err, size_t errcap) {
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
    return jskip_value(j, err, errcap);
}
static int parse_binding(jctx *j, d2k_cat_binding *out, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    return parse_object(j, handle_binding_key, out, err, errcap);
}
static int elem_binding(jctx *j, void *o, char *err, size_t errcap) {
    return parse_binding(j, (d2k_cat_binding *)o, err, errcap);
}

/* --------------------------------------------------------------------
 * Коробка и каталог целиком.
 * -------------------------------------------------------------------- */

static int handle_box_key(jctx *j, const char *key, void *ctx, char *err, size_t errcap) {
    d2k_cat_box *out = (d2k_cat_box *)ctx;
    if (strcmp(key, "id") == 0)
        return jparse_string_fixed(j, out->id, sizeof out->id, "box.id", err, errcap);
    if (strcmp(key, "created") == 0)
        return jparse_rfc3339(j, &out->created, "box.created", err, errcap);
    if (strcmp(key, "updated") == 0)
        return jparse_rfc3339(j, &out->updated, "box.updated", err, errcap);
    if (strcmp(key, "fingerprint") == 0)
        return parse_fp(j, &out->fp, err, errcap);
    if (strcmp(key, "plans") == 0) {
        size_t cap = out->n_plans; /* см. grow() про то, почему не 0 */
        return parse_array(j, (void **)&out->plans, &out->n_plans, &cap,
                            sizeof(d2k_cat_plan), elem_plan, "plans", err, errcap);
    }
    if (strcmp(key, "bindings") == 0) {
        size_t cap = out->n_binds;
        return parse_array(j, (void **)&out->binds, &out->n_binds, &cap,
                            sizeof(d2k_cat_binding), elem_binding, "bindings", err, errcap);
    }
    return jskip_value(j, err, errcap);
}
static int parse_box(jctx *j, d2k_cat_box *out, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    return parse_object(j, handle_box_key, out, err, errcap);
}
static int elem_box(jctx *j, void *o, char *err, size_t errcap) {
    return parse_box(j, (d2k_cat_box *)o, err, errcap);
}

/* "schema" и верхнеуровневый "updated" пропускаются жskip_value: в
 * d2k_catalog им нет соответствующего поля (см. d2k_catalog.h — подробно
 * о том, почему это не потеря: schema всегда константа 1, updated Go
 * перезаписывает текущим временем на каждой записи независимо от
 * прочитанного). */
static int handle_catalog_key(jctx *j, const char *key, void *ctx, char *err, size_t errcap) {
    d2k_catalog *out = (d2k_catalog *)ctx;
    if (strcmp(key, "boxes") == 0) {
        size_t cap = out->n_boxes;
        return parse_array(j, (void **)&out->boxes, &out->n_boxes, &cap,
                            sizeof(d2k_cat_box), elem_box, "boxes", err, errcap);
    }
    return jskip_value(j, err, errcap);
}
static int parse_catalog_obj(jctx *j, d2k_catalog *out, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    return parse_object(j, handle_catalog_key, out, err, errcap);
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
    b->plans = NULL; b->n_plans = 0;
    b->binds = NULL; b->n_binds = 0;
}

void d2k_catalog_free(d2k_catalog *c) {
    if (!c) return;
    for (size_t i = 0; i < c->n_boxes; i++) {
        free_box(&c->boxes[i]);
    }
    free(c->boxes);
    c->boxes = NULL;
    c->n_boxes = 0;
}

/* --------------------------------------------------------------------
 * Чтение файла и публичная точка входа.
 * -------------------------------------------------------------------- */

static int read_whole_file(const char *path, char **buf_out, size_t *len_out,
                            char *err, size_t errcap) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        set_err(err, errcap, "%s: %s", path, strerror(errno));
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        set_err(err, errcap, "%s: fseek(END) не удался", path);
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if (sz < 0) {
        set_err(err, errcap, "%s: ftell не удался", path);
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        set_err(err, errcap, "%s: fseek(0) не удался", path);
        fclose(f);
        return -1;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        set_err(err, errcap, "%s: память не выделилась (%ld байт)", path, sz);
        fclose(f);
        return -1;
    }
    size_t got = (sz > 0) ? fread(buf, 1, (size_t)sz, f) : 0;
    fclose(f);
    if (got != (size_t)sz) {
        set_err(err, errcap, "%s: прочиталось %zu из %ld байт", path, got, sz);
        free(buf);
        return -1;
    }
    buf[sz] = '\0';
    *buf_out = buf;
    *len_out = (size_t)sz;
    return 0;
}

int d2k_catalog_load(const char *path, d2k_catalog *out, char *err, size_t errcap) {
    if (err && errcap) err[0] = '\0';
    memset(out, 0, sizeof *out);

    char *buf = NULL;
    size_t len = 0;
    if (read_whole_file(path, &buf, &len, err, errcap) != 0) return -1;

    jctx j; j.s = buf; j.len = len; j.i = 0;
    int rc = parse_catalog_obj(&j, out, err, errcap);
    free(buf);

    if (rc != 0) {
        /* Незакрытая структура/дробное число/переполнение — отказ разбора
           ЦЕЛИКОМ, а не результат с потерянной частью (см. шапку файла и
           d2k_catalog.h). Всё, что успело выделиться до отказа, найдено
           и освобождено здесь же, вызывающему звать free не на чем и не
           нужно (см. d2k_catalog.h и test_catalog.c, блок про обрубок). */
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
    wr_indent(f, depth + 1); fprintf(f, "\"seen\": %d\n", s->seen);
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
    wr_indent(f, depth + 1); fprintf(f, "\"transport\": %u\n", (unsigned)bd->transport);
    wr_indent(f, depth); fputc('}', f);
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
    write_json_array(f, b->binds, b->n_binds, sizeof(d2k_cat_binding), write_binding_elem, depth + 1);
    fputc('\n', f);
    wr_indent(f, depth); fputc('}', f);
}

int d2k_catalog_save(const d2k_catalog *c, const char *path, char *err, size_t errcap) {
    if (err && errcap) err[0] = '\0';

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
    fputs("\n}\n", f);

    /* Проверяется КАЖДАЯ ошибка вплоть до закрытия: неотловленный сбой
       где-то посреди буферизованной записи выглядел бы как "файл записан"
       ровно так же, как настоящий успех (тот же довод, что для Sync/Close
       в Go-версии — internal/catalog/store.go). */
    int had_err = ferror(f);
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
