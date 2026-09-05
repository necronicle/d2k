/* planlab — лаборатория плана.
 *
 * Принимает план в канонической форме и сценарий фиксированных пакетов,
 * печатает точные байты, которые выпустил бы исполнитель, и относительные
 * времена.
 *
 * Главное свойство — не удобство, а то, что здесь работает ТОТ ЖЕ исполнитель,
 * что пойдёт в прод: те же d2k_plan_load и d2k_plan_apply. Второй реализации
 * преобразований не появляется, а §2.5 документа запрещает её именно потому,
 * что две реализации разойдутся, и измеренное перестанет соответствовать
 * исполняемому.
 *
 * Вывод детерминирован: только относительные задержки из плана, никаких
 * настенных часов. Иначе эталонные файлы разъезжались бы от прогона к прогону.
 *
 * Формат сценария, по строке на пакет:
 *   pkt <seq> <sni_off|none> <sni_len> <нагрузка в hex>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_plan.h"

#define MAX_PAYLOAD 65536

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static long unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (s[0] && s[1]) {
        int hi = hex_nibble((unsigned char)s[0]);
        int lo = hex_nibble((unsigned char)s[1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        if (n >= cap) {
            return -1;
        }
        out[n++] = (uint8_t)(hi << 4 | lo);
        s += 2;
    }
    return s[0] ? -1 : (long)n;
}

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *fh = fopen(path, "rb");
    if (!fh) {
        return NULL;
    }
    if (fseek(fh, 0, SEEK_END) != 0) {
        fclose(fh);
        return NULL;
    }
    long sz = ftell(fh);
    if (sz < 0) {
        fclose(fh);
        return NULL;
    }
    rewind(fh);
    uint8_t *buf = malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) {
        fclose(fh);
        return NULL;
    }
    if (sz > 0 && fread(buf, 1, (size_t)sz, fh) != (size_t)sz) {
        free(buf);
        fclose(fh);
        return NULL;
    }
    fclose(fh);
    *len = (size_t)sz;
    return buf;
}

static const char *fate_name(d2k_orig_fate f) {
    switch (f) {
    case D2K_ORIG_PASS: return "pass";
    case D2K_ORIG_DROP: return "drop";
    case D2K_ORIG_HOLD: return "hold";
    default:            return "неизвестно";
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "использование: planlab <план.tlv> <сценарий>\n");
        return 2;
    }

    size_t plan_len = 0;
    uint8_t *plan_raw = read_file(argv[1], &plan_len);
    if (!plan_raw) {
        fprintf(stderr, "не прочитать план %s\n", argv[1]);
        return 2;
    }

    d2k_plan *p = NULL;
    char err[200];
    if (d2k_plan_load(plan_raw, plan_len, &p, err, sizeof err) != 0) {
        /* Отказ — это результат, а не сбой инструмента: план, который
           исполнитель не принял, обязан быть видимым в эталоне. */
        printf("reject %s\n", err);
        free(plan_raw);
        return 0;
    }

    FILE *sc = fopen(argv[2], "r");
    if (!sc) {
        fprintf(stderr, "не прочитать сценарий %s\n", argv[2]);
        d2k_plan_free(p);
        free(plan_raw);
        return 2;
    }

    uint8_t *payload = malloc(MAX_PAYLOAD);
    char *line = malloc(MAX_PAYLOAD * 2 + 256);
    if (!payload || !line) {
        fprintf(stderr, "нет памяти\n");
        free(payload);
        free(line);
        fclose(sc);
        d2k_plan_free(p);
        free(plan_raw);
        return 2;
    }

    int rc = 0;
    size_t lineno = 0;
    while (fgets(line, MAX_PAYLOAD * 2 + 256, sc)) {
        lineno++;
        char kind[16], sni_off_s[32], hex[MAX_PAYLOAD * 2 + 1];
        unsigned long seq = 0, sni_len = 0;
        if (sscanf(line, "%15s %lu %31s %lu %131072s",
                   kind, &seq, sni_off_s, &sni_len, hex) != 5) {
            continue; /* пустые строки и комментарии */
        }
        if (strcmp(kind, "pkt") != 0) {
            fprintf(stderr, "строка %zu: неизвестная директива %s\n", lineno, kind);
            rc = 2;
            break;
        }

        long n = unhex(hex, payload, MAX_PAYLOAD);
        if (n < 0) {
            fprintf(stderr, "строка %zu: нагрузка не hex\n", lineno);
            rc = 2;
            break;
        }

        d2k_pkt in;
        memset(&in, 0, sizeof in);
        in.payload = payload;
        in.payload_len = (size_t)n;
        in.seq = (uint32_t)seq;
        if (strcmp(sni_off_s, "none") == 0) {
            in.have_sni = 0;
        } else {
            in.have_sni = 1;
            in.sni_off = strtoul(sni_off_s, NULL, 10);
            in.sni_len = sni_len;
        }

        d2k_flow f;
        memset(&f, 0, sizeof f);
        d2k_actions a;
        memset(&a, 0, sizeof a);

        if (d2k_plan_apply(p, &f, &in, &a) != 0) {
            /* Неприменимость — тоже результат: эталон обязан её показывать,
               иначе отказ будет неотличим от «действий не потребовалось». */
            printf("refuse\n");
            d2k_actions_free(&a);
            continue;
        }

        for (size_t i = 0; i < a.n; i++) {
            /* Вид посылки печатается намеренно: без него эталон не заметил бы,
               если фальшивка и кусок нагрузки однажды поменяются местами, — а
               от этого различия зависит поведение при отмене. */
            printf("emit %s %u %u ttl=%u poison=%02x ",
                   a.v[i].kind == D2K_EMIT_PAYLOAD ? "payload" : "fake",
                   a.v[i].delay_us, a.v[i].seq, a.v[i].ttl, a.v[i].poison);
            print_hex(a.v[i].bytes, a.v[i].len);
            printf("\n");
        }
        printf("fate %s\n", fate_name(a.fate));
        d2k_actions_free(&a);
    }

    free(line);
    free(payload);
    fclose(sc);
    d2k_plan_free(p);
    free(plan_raw);
    return rc;
}
