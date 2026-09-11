/* test_plantlv.c — перевод текста плана в байты провода.
 *
 * ГЛАВНАЯ ПРОВЕРКА: для КАЖДОЙ формы, которую умеет собирать compose.c, текст,
 * пропущенный через d2k_plan_text_to_tlv, обязан дать РОВНО те же байты, что
 * собирает прямой TLV-сборщик рядом. Это не сверка перевода с представлением
 * теста о нём: обе формы одной фигуры уже существуют в дереве и уже проверены
 * planlab'ом (test_compose), поэтому равенство между ними — настоящий эталон.
 *
 * Вторая проверка: план, собранный d2k_compose (тот, что реально едет от
 * планировщика), после перевода принимается НАСТОЯЩИМ исполнителем датапата —
 * planlab гоняет d2k_plan_load + d2k_plan_apply, те же, что в проде. Без неё
 * равенство с сборщиком доказывало бы лишь внутреннюю согласованность. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_compose.h"
#include "d2k_compose_internal.h"
#include "d2k_plantlv.h"

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { printf("ПРОВАЛ: %s\n", (msg)); fails++; } } while (0)

static void show_diff(const char *what, const uint8_t *a, size_t an,
                      const uint8_t *b, size_t bn) {
    printf("  %s: прямой сборщик %zu байт, перевод %zu байт\n", what, an, bn);
    size_t n = an < bn ? an : bn;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            printf("  первое расхождение в байте %zu: %02x против %02x\n", i, a[i], b[i]);
            return;
        }
    }
}

static void same(const char *what, const char *text,
                 const uint8_t *want, size_t want_len) {
    uint8_t got[D2K_PLAN_TLV_MAX];
    size_t got_len = 0;
    char err[200];
    if (d2k_plan_text_to_tlv(text, got, sizeof got, &got_len, err, sizeof err) != 0) {
        printf("ПРОВАЛ: %s: перевод отказал: %s\n", what, err);
        fails++;
        return;
    }
    if (got_len != want_len || memcmp(got, want, want_len) != 0) {
        printf("ПРОВАЛ: %s: перевод текста дал НЕ те байты, что прямой сборщик\n", what);
        show_diff(what, want, want_len, got, got_len);
        fails++;
    }
}

static int write_file_bytes(const char *path, const uint8_t *b, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) { return -1; }
    size_t wr = n ? fwrite(b, 1, n, f) : 0;
    int ok = (wr == n) && (fclose(f) == 0);
    return ok ? 0 : -1;
}

static int write_file_text(const char *path, const char *s) {
    FILE *f = fopen(path, "wb");
    if (!f) { return -1; }
    int ok = fputs(s, f) >= 0;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}

int main(void) {
    /* --- перекрытие слева ------------------------------------------------ */
    {
        char text[4096];
        uint8_t tlv[4096];
        size_t tlv_len = 0;
        CHECK(overlap_plan_text(text, sizeof text) == 0, "overlap_plan_text не собрался");
        CHECK(overlap_plan_tlv(tlv, sizeof tlv, &tlv_len) == 0, "overlap_plan_tlv не собрался");
        same("перекрытие слева", text, tlv, tlv_len);
    }

    /* --- порядок сегментов ----------------------------------------------- */
    {
        char text[4096];
        uint8_t tlv[4096];
        size_t tlv_len = 0;
        CHECK(reorder_plan_text(text, sizeof text) == 0, "reorder_plan_text не собрался");
        CHECK(reorder_plan_tlv(tlv, sizeof tlv, &tlv_len) == 0, "reorder_plan_tlv не собрался");
        same("порядок сегментов", text, tlv, tlv_len);
    }

    /* --- контрольная сумма (набивка 64×0x41) ----------------------------- */
    {
        char text[4096];
        uint8_t tlv[4096];
        size_t tlv_len = 0;
        CHECK(checksum_plan_text(text, sizeof text) == 0, "checksum_plan_text не собрался");
        CHECK(checksum_plan_tlv(tlv, sizeof tlv, &tlv_len) == 0, "checksum_plan_tlv не собрался");
        same("контрольная сумма", text, tlv, tlv_len);
    }

    /* --- фальшивка с повторами и паузой (счёт дубликатов) ---------------- */
    {
        uint8_t payload[300];
        for (size_t i = 0; i < sizeof payload; i++) { payload[i] = (uint8_t)(i * 7 + 3); }
        char text[4096];
        uint8_t tlv[4096];
        size_t tlv_len = 0;
        CHECK(badsum_fake_plan_text(payload, sizeof payload, 2, 20000, text, sizeof text) == 0,
              "badsum_fake_plan_text не собрался");
        CHECK(badsum_fake_plan_tlv(payload, sizeof payload, 2, 20000, tlv, sizeof tlv, &tlv_len) == 0,
              "badsum_fake_plan_tlv не собрался");
        same("счёт дубликатов", text, tlv, tlv_len);
    }

    /* --- неизвестная директива = ОТКАЗ, а не пропуск (§2.5) -------------- */
    {
        uint8_t out[1024];
        size_t n = 0;
        char err[200];
        const char *bad =
            "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\n"
            "жарить payload=1\norder forward\n";
        CHECK(d2k_plan_text_to_tlv(bad, out, sizeof out, &n, err, sizeof err) != 0,
              "неизвестная директива прошла молча — план на проводе отличался бы от записанного");
        CHECK(strstr(err, "неизвестная директива") != NULL,
              "отказ по неизвестной директиве без внятной причины");
    }

    /* --- текст без заголовка = отказ ------------------------------------- */
    {
        uint8_t out[1024];
        size_t n = 0;
        char err[200];
        CHECK(d2k_plan_text_to_tlv("order forward\n", out, sizeof out, &n, err, sizeof err) != 0,
              "план без заголовка d2k-plan принят");
    }

    /* --- план от d2k_compose принимается НАСТОЯЩИМ исполнителем датапата -- */
    {
        d2k_props pr;
        memset(&pr, 0, sizeof pr);
        char plans[8][4096];
        size_t n = d2k_compose(&pr, D2K_SHAPE_MODERN, "disk.rzd.ru", plans, 8);
        CHECK(n == 1, "пустой вектор обязан дать ровно один запасной план");
        if (n >= 1) {
            uint8_t tlv[D2K_PLAN_TLV_MAX];
            size_t tlv_len = 0;
            char err[200];
            CHECK(d2k_plan_text_to_tlv(plans[0], tlv, sizeof tlv, &tlv_len, err, sizeof err) == 0,
                  "запасной план d2k_compose не переводится в байты провода");
            if (tlv_len > 0) {
                const char *pp = "/tmp/d2k-test-plantlv.bin";
                const char *sp = "/tmp/d2k-test-plantlv.scn";
                /* Сценарий planlab: один пакет, имя на известном смещении —
                   разрезы по якорям sni_middle обязаны во что-то упереться. */
                CHECK(write_file_bytes(pp, tlv, tlv_len) == 0, "план не записался");
                CHECK(write_file_text(sp,
                        "pkt 1000 11 17 "
                        "16030100200100001c0303000000000000000000000000000000000000"
                        "0000000000000000000000000000\n") == 0,
                      "сценарий не записался");
                char cmd[400];
                snprintf(cmd, sizeof cmd, "../datapath/planlab %s %s 2>&1", pp, sp);
                FILE *f = popen(cmd, "r");
                CHECK(f != NULL, "planlab не запустился");
                char out[8192];
                size_t got = 0;
                if (f) {
                    while (got + 1 < sizeof out) {
                        size_t r = fread(out + got, 1, sizeof out - 1 - got, f);
                        if (r == 0) { break; }
                        got += r;
                    }
                    pclose(f);
                }
                out[got] = '\0';
                CHECK(strstr(out, "reject") == NULL && strstr(out, "не принят") == NULL &&
                      strstr(out, "не разобрался") == NULL,
                      "настоящий исполнитель датапата отверг переведённый план");
                CHECK(strstr(out, "emit") != NULL,
                      "исполнитель не выдал ни одной посылки по переведённому плану");
                remove(pp);
                remove(sp);
            }
        }
    }

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("перевод плана: все проверки прошли\n");
    return 0;
}
