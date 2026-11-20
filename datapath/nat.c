/* nat.c — контракт и все обоснования в d2k_nat.h.
 *
 * Разбор текстовый и намеренно грубый: строка conntrack — это набор полей
 * `ключ=значение` через пробел, и ПОРЯДОК полей в ней зависит от версии ядра
 * и включённых расширений. Опираться на позицию нельзя; опираемся на имена и
 * на одно свойство, которое держится во всех виденных ядрах: сперва идёт
 * ПРЯМОЙ кортеж, потом ОБРАТНЫЙ, и каждое имя (src/dst/sport/dport)
 * встречается в строке дважды — первый раз прямое, второй обратное.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "d2k_nat.h"
d2k_nat_family_fn d2k_nat_family_hook = d2k_nat_outside_family;

/* "192.168.1.117" -> адрес в сетевом порядке. 0 — не разобралось. */
static int parse_ip4(const char *s, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        if (*s < '0' || *s > '9') { return -1; }
        unsigned b = 0;
        while (*s >= '0' && *s <= '9') {
            b = b * 10 + (unsigned)(*s - '0');
            if (b > 255) { return -1; }
            s++;
        }
        v = (v << 8) | b;
        if (i < 3) {
            if (*s != '.') { return -1; }
            s++;
        }
    }
    if (*s != '\0') { return -1; }
    /* Строка собиралась старшим байтом вперёд — это и есть сетевой порядок. */
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    memcpy(out, b, 4);
    return 0;
}

/* Значение поля `name=` из строки, начиная с позиции from. Возвращает
   указатель на значение внутри копии строки (строка режется на месте) либо
   NULL. *next — откуда продолжать поиск следующего вхождения того же имени. */
static char *field_after(char *s, const char *name, char **next) {
    size_t nl = strlen(name);
    char *p = s;
    while ((p = strstr(p, name)) != NULL) {
        /* Имя обязано начинаться на границе слова: иначе `dport=` нашлось бы
           внутри `sport=` и наоборот. */
        if (p != s && p[-1] != ' ') { p += nl; continue; }
        if (p[nl] != '=') { p += nl; continue; }
        char *v = p + nl + 1;
        char *e = v;
        while (*e && *e != ' ' && *e != '\n') { e++; }
        char saved = *e;
        *e = '\0';
        *next = (saved == '\0') ? e : e + 1;
        return v;
    }
    return NULL;
}

d2k_nat_fn d2k_nat_hook = d2k_nat_outside;

int d2k_nat_outside(const char *path, uint8_t proto,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dst_ip, uint16_t dst_port,
                    uint32_t *out_src, uint16_t *out_sport) {
    return d2k_nat_outside_family(path, proto, (const uint8_t *)&src_ip, src_port,
        (const uint8_t *)&dst_ip, dst_port, 4, (uint8_t *)out_src, out_sport);
}

static int parse_address(const char *text, uint8_t family, uint8_t out[16]) {
    memset(out, 0, 16);
    if (family == 6) { return inet_pton(AF_INET6, text, out) == 1 ? 0 : -1; }
    uint32_t v;
    if (parse_ip4(text, &v) != 0) { return -1; }
    memcpy(out, &v, 4);
    return 0;
}

int d2k_nat_outside_family(const char *path, uint8_t proto,
    const uint8_t *src_ip, uint16_t src_port, const uint8_t *dst_ip, uint16_t dst_port,
    uint8_t family, uint8_t *out_src, uint16_t *out_sport) {
    if (!path || !src_ip || !dst_ip || !out_src || !out_sport ||
        (family != 4 && family != 6)) { return -1; }
    size_t alen = family == 6 ? 16 : 4;
    FILE *f = fopen(path, "r");
    if (!f) {
        /* Таблицы соединений в системе НЕТ — значит нет и conntrack, а без
           него не бывает и NAT: переписывать адрес некому. Это не то же
           самое, что «таблица есть, а записи нет» (ниже -1): там поток
           ведётся мимо conntrack ускорителем, и трансляция существует, просто
           она нам не видна. Разные факты — разные ответы. */
        return 1;
    }

    /* Строка conntrack с расширениями на Keenetic доходит до ~400 байт;
       берём с запасом и ДЛИННЫЕ строки пропускаем целиком, а не режем:
       обрезок разобрался бы как другой поток. */
    char line[1024];
    int found = -1;
    /* ЛУЧШАЯ ЗАПИСЬ, А НЕ ПЕРВАЯ. Клиент переиспользует местные порты, а
       conntrack держит закрытые записи ещё десятки секунд — и у старой
       записи того же кортежа внешний порт ДРУГОЙ. Первая попавшаяся давала
       посылку с чужим портом: замерено на роутере Марка 13.09.2026 (клиент
       ушёл с 60639, наша посылка — с 37741, сервер ответил сбросом).
       Выбираем запись с наибольшим ОСТАТКОМ ЖИЗНИ: у живого соединения он
       близок к полному, у закрывающегося — секунды. */
    long best_ttl = -1;
    const char *pname = (proto == 6) ? "tcp" : (proto == 17) ? "udp" : NULL;
    if (!pname) { fclose(f); return -1; }

    while (fgets(line, sizeof line, f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n' && !feof(f)) {
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n') { }
            continue;
        }
        if (!strstr(line, pname)) { continue; }

        char *next = NULL;
        char work[1024];
        memcpy(work, line, len + 1);

        /* Прямой кортеж — первые вхождения имён. */
        char *v_src = field_after(work, "src", &next);
        if (!v_src) { continue; }
        char *after_src = next;
        char *v_dst = field_after(after_src, "dst", &next);
        if (!v_dst) { continue; }
        char *after_dst = next;
        char *v_sport = field_after(after_dst, "sport", &next);
        if (!v_sport) { continue; }
        char *after_sport = next;
        char *v_dport = field_after(after_sport, "dport", &next);
        if (!v_dport) { continue; }
        char *after_dport = next;

        uint8_t o_src[16], o_dst[16];
        if (parse_address(v_src, family, o_src) != 0 ||
            parse_address(v_dst, family, o_dst) != 0) { continue; }
        uint16_t o_sport = (uint16_t)atoi(v_sport);
        uint16_t o_dport = (uint16_t)atoi(v_dport);
        uint16_t n_sport = htons(o_sport);
        uint16_t n_dport = htons(o_dport);

        if (memcmp(o_src, src_ip, alen) || memcmp(o_dst, dst_ip, alen) ||
            n_sport != src_port || n_dport != dst_port) {
            continue;
        }

        /* Обратный кортеж — следующие вхождения тех же имён. Нас интересуют
           его dst и dport: это и есть «каким нас видит сервер». */
        char *r_dst = field_after(after_dport, "dst", &next);
        if (!r_dst) { break; }
        char *after_rdst = next;
        char *r_dport = field_after(after_rdst, "dport", &next);
        if (!r_dport) { break; }

        uint8_t ext[16];
        if (parse_address(r_dst, family, ext) != 0) { continue; }
        uint16_t ext_port = (uint16_t)atoi(r_dport);

        /* Остаток жизни — третье число строки: «ipv4 2 tcp 6 1194 ...».
           Разбираем по позиции ЧИСЕЛ, а не по имени: имени у этого поля в
           строке нет вовсе. */
        long ttl = -1;
        {
            const char *q = line;
            int nums = 0;
            while (*q) {
                while (*q == ' ') { q++; }
                if (*q >= '0' && *q <= '9') {
                    long v = strtol(q, (char **)&q, 10);
                    nums++;
                    if (nums == 3) { ttl = v; break; }
                } else {
                    while (*q && *q != ' ') { q++; }
                }
            }
        }
        if (ttl <= best_ttl && found == 0) { continue; }
        best_ttl = ttl;
        memcpy(out_src, ext, alen);
        *out_sport = htons(ext_port);
        found = 0;
    }
    fclose(f);
    return found;
}
