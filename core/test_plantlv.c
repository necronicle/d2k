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

    /* --- контрольная сумма (набивка 64×0x0f) ----------------------------- */
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

    /* --- delay: выдержка перед единственной посылкой ---------------------
     *
     * Ни pace, ни settle её не выражают (см. d2k_plan_internal.h про
     * delay_us). Требует minexec=6: старый датапат выдержки не знает, и
     * молча выпустить посылку без паузы значит исполнить не тот план. */
    {
        uint8_t out[1024];
        size_t n = 0;
        char err[200];
        static const char *h6 =
            "d2k-plan 1 6\nid 00000000000000000000000000000000\nproto udp quic\n";
        static const char *h1 =
            "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto udp quic\n";
        char text[1024];

        snprintf(text, sizeof text, "%sdelay 15000\n", h6);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) == 0,
              "выдержка не собралась");
        {
            static const uint8_t want[4] = { 0x01, 0x0b, 0x00, 0x04 };
            int seen = 0;
            for (size_t i = 0; n >= 4 && i + 4 <= n; i++) {
                if (memcmp(out + i, want, 4) == 0) { seen = 1; break; }
            }
            CHECK(seen, "записи выдержки нет в TLV");
        }

        /* ГЛАВНАЯ ПРОВЕРКА — ЧТО ПЛАН ПРИМЕТ РАЗБОР ДАТАПАТА, а не что байты
           записи где-то лежат. Поле 19.09.2026: запись выдержки собиралась,
           но не попала в СЧЁТЧИК записей заголовка, и служба отвергла план
           целиком — «число записей не совпадает с заявленным». Тест, который
           смотрел только на наличие байтов, этого не поймал. */
        {
            const char *pp = "/tmp/d2k-test-delay.bin";
            const char *sp = "/tmp/d2k-test-delay.scn";
            CHECK(write_file_bytes(pp, out, n) == 0, "план выдержки не записался");
            CHECK(write_file_text(sp, "pkt 1000 11 17 "
                    "16030100200100001c0303000000000000000000000000000000000000"
                    "0000000000000000000000000000\n") == 0, "сценарий не записался");
            char cmd[400];
            snprintf(cmd, sizeof cmd, "../datapath/planlab %s %s 2>&1", pp, sp);
            FILE *pf = popen(cmd, "r");
            CHECK(pf != NULL, "planlab не запустился");
            char o[4096];
            size_t got = 0;
            if (pf) {
                while (got + 1 < sizeof o) {
                    size_t r = fread(o + got, 1, sizeof o - 1 - got, pf);
                    if (r == 0) { break; }
                    got += r;
                }
                pclose(pf);
            }
            o[got] = '\0';
            CHECK(strstr(o, "reject") == NULL,
                  "разбор датапата отверг план с выдержкой");
            remove(pp);
            remove(sp);
        }

        snprintf(text, sizeof text, "%sdelay 15000\n", h1);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "выдержка принята при minexec=1 — старый датапат исполнит не тот план");

        snprintf(text, sizeof text, "%sdelay 0\n", h6);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "delay 0 принят — он неотличим от отсутствия строки");

        snprintf(text, sizeof text, "%sdelay 15ms\n", h6);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "delay принял не-число");

        snprintf(text, sizeof text, "%sdelay 15000 20000\n", h6);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "delay принял два значения");
    }

    {
        uint8_t out[256];size_t n=0;char err[200],text[256];
        const char *bad[]={"ipfrag 0\n","ipfrag 5\n","ipfrag 1 2\n",
            "ipfrag 1\nipfrag 1\n","ipfrag -1\n","ipfrag 1ms\n",
            "ipfrag 1\nsplit payload_start +1\n","ipfrag 1\norder reverse\n"};
        for(size_t i=0;i<sizeof bad/sizeof bad[0];i++) {
            snprintf(text,sizeof text,"d2k-plan 1 7\nproto udp quic\n%s",bad[i]);
            CHECK(d2k_plan_text_to_tlv(text,out,sizeof out,&n,err,sizeof err)!=0,
                  "invalid/conflicting fragment text accepted");
        }
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 6\nproto udp quic\nipfrag 1\n",
              out,sizeof out,&n,err,sizeof err)!=0,"fragment with old executor");
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 7\nproto tcp tls\nipfrag 1\n",
              out,sizeof out,&n,err,sizeof err)!=0,"fragment with TCP text");
    }

    /* --- pace: ноль и мусор отвергаются ---------------------------------
     *
     * «pace 0» запрещён нарочно: он и отсутствие строки означали бы одно и то
     * же, а директива, ничего не меняющая, — способ написать план, который
     * читается не так, как исполняется. Здесь же ловится и второе: значение у
     * pace идёт БЕЗ ключа, и разбор не должен принимать "pace pace=12000". */
    {
        uint8_t out[1024];
        size_t n = 0;
        char err[200];
        static const char *head =
            "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\n"
            "split payload_start +1\norder forward\n";
        char text[1024];

        snprintf(text, sizeof text, "%space 0\n", head);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "pace 0 принят — а он неотличим от отсутствия строки");

        snprintf(text, sizeof text, "%space pace=12000\n", head);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "pace принял значение с ключом — у него значение голое");

        snprintf(text, sizeof text, "%space 12ms\n", head);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "pace принял не-число");

        snprintf(text, sizeof text, "%space 12000 15000\n", head);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "pace принял два значения");

        snprintf(text, sizeof text, "%space 12000\n", head);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) == 0,
              "правильный pace отвергнут заодно с неправильными");
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
        size_t n = d2k_compose(&pr, D2K_SHAPE_MODERN, "disk.rzd.ru", 0, plans, 8);
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
