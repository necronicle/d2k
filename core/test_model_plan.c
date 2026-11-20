/* Программа новой модели (model/) → текст плана → TLV → план датапата.
 * Фальшивка — приветствие, собранное генератором TLS по грамматике со своим
 * зерном. Проверяет, что язык программы целиком исполним нынешним датапатом
 * и что исполнителю не оставлено выбора. */
#include <stdio.h>
#include <string.h>
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include "../model/include/d2km_program.h"
#include "../model/include/d2km_tls.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static size_t w16(uint8_t *p, size_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2; }

/* Приветствие клиента в тесте собрано по грамматике; в продукте оно берётся
 * у клиента. */
static size_t client_hello(uint8_t *out)
{
    uint8_t e[256]; size_t el = 0;
    const char *sni = "blocked.example"; size_t n = strlen(sni);
    w16(e, 0); w16(e + 2, n + 5); w16(e + 4, n + 3); e[6] = 0; w16(e + 7, n);
    memcpy(e + 9, sni, n); el = 9 + n;
    uint8_t body[512]; size_t b = 0;
    b += w16(body + b, 0x0303);
    memset(body + b, 0x11, 32); b += 32;
    body[b++] = 0;
    b += w16(body + b, 2); b += w16(body + b, 0x1301);
    body[b++] = 1; body[b++] = 0;
    b += w16(body + b, el); memcpy(body + b, e, el); b += el;
    out[0] = 0x16; w16(out + 1, 0x0301); w16(out + 3, b + 4);
    out[5] = 1; out[6] = 0; w16(out + 7, b);
    memcpy(out + 9, body, b);
    return 9 + b;
}

int main(void)
{
    static d2km_tls_hello h;
    uint8_t in[1024];
    size_t n = client_hello(in);
    CHECK(d2km_tls_parse(in, n, &h) == D2KM_TLS_OK);
    d2km_rng r;
    d2km_rng_seed(&r, 42);
    CHECK(d2km_tls_refresh(&h, &r) == D2KM_TLS_OK);
    CHECK(d2km_tls_set_sni(&h, "passes.example") == D2KM_TLS_OK);
    CHECK(d2km_tls_pad_to(&h, 517) == D2KM_TLS_OK);

    static d2km_program p;
    memset(&p, 0, sizeof p);
    p.transport = D2KM_TCP; p.protocol = D2KM_P_TLS13; p.seed = 42;
    p.payload_count = 1;
    p.payloads[0].length = (uint16_t)d2km_tls_build(&h, p.payloads[0].bytes, sizeof p.payloads[0].bytes);
    CHECK(p.payloads[0].length == 517);
    strcpy(p.payloads[0].why, "приветствие по форме клиента; имя, которое коробка пропускает (F20)");
    p.fake_count = 1;
    p.fakes[0].repeats = 2; p.fakes[0].gap_us = 1000;
    p.fakes[0].poison.ttl = 5; p.fakes[0].poison.badsum = 1;
    strcpy(p.fakes[0].why, "TTL 5 < хоп сервера 11 (F12, F13); копий 2 (F14)");
    p.split_count = 1; p.splits[0].anchor = D2KM_AT_SNI_START; p.splits[0].offset = 1;
    strcpy(p.splits[0].why, "коробка не собирает сегменты (F21)");
    p.fakes[0].between = 1;

    static char text[16384];
    size_t tl = d2km_program_text(&p, text, sizeof text);
    CHECK(tl > 0);
    static uint8_t tlv[D2K_PLAN_TLV_MAX];
    size_t tn = 0;
    char err[240] = "";
    CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tn, err, sizeof err) == 0);
    if (err[0]) fprintf(stderr, "plantlv: %s\n", err);
    d2k_plan *pl = NULL;
    err[0] = 0;
    CHECK(d2k_plan_load(tlv, tn, &pl, err, sizeof err) == 0 && pl);
    if (err[0]) fprintf(stderr, "plan_load: %s\n", err);
    d2k_plan_free(pl);

    /* Протоколы, которые программа выражает, принимает разборщик плана. */
    p.transport = D2KM_UDP; p.protocol = D2KM_P_QUIC1;
    p.split_count = 0; p.fakes[0].between = 0;
    p.fakes[0].poison.badsum = 0;
    tl = d2km_program_text(&p, text, sizeof text);
    CHECK(tl > 0);
    CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tn, err, sizeof err) == 0);
    if (fails) { fprintf(stderr, "%s\n", text); return 1; }
    puts("model program -> plan text -> TLV -> datapath plan PASS");
    return 0;
}
