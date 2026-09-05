/* test_session.c — склейка модулей на настоящих пакетах.
 *
 * Правило, которое здесь проверяется главным образом: НЕ ПОНЯЛ — НЕ ТРОГАЙ.
 * Проверок на «пропустили и объяснили почему» больше, чем на «применили»:
 * пропустить чужой пакет безвредно, тронуть непонятый — значит испортить
 * человеку соединение и не узнать об этом.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_session.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* План: одна фальшивка перед куском, две копии с паузой 78 мс. */
static const uint8_t plan_bytes[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 4,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* Собирает IPv4/TCP пакет с заданной нагрузкой. */
static size_t build_pkt(uint8_t *o, uint16_t sport, uint8_t flags,
                        const uint8_t *pay, size_t paylen) {
    size_t total = 20 + 20 + paylen;
    memset(o, 0, 40);
    o[0] = 0x45;
    wr16(o + 2, (uint16_t)total);
    wr16(o + 4, 0x1000);
    o[8] = 64;
    o[9] = 6;
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    memcpy(o + 12, s, 4);
    memcpy(o + 16, d, 4);
    wr16(o + 20, sport);
    wr16(o + 22, 443);
    wr32(o + 24, 1000);
    wr32(o + 28, 0x11223344);
    o[32] = 0x50;
    o[33] = flags;
    wr16(o + 34, 64240);
    if (paylen) {
        memcpy(o + 40, pay, paylen);
    }
    return total;
}

/* Настоящее приветствие с именем hetzner.com. */
static size_t build_hello(uint8_t *out) {
    uint8_t body[256];
    size_t b = 0;
    body[b++] = 0x03; body[b++] = 0x03;
    for (int i = 0; i < 32; i++) body[b++] = (uint8_t)i;
    body[b++] = 0;
    body[b++] = 0x00; body[b++] = 0x02; body[b++] = 0x13; body[b++] = 0x01;
    body[b++] = 0x01; body[b++] = 0x00;
    const char *sni = "hetzner.com";
    size_t nl = strlen(sni);
    uint8_t ext[64]; size_t e = 0;
    ext[e++] = 0x00; ext[e++] = 0x00;
    ext[e++] = 0x00; ext[e++] = (uint8_t)(5 + nl);
    ext[e++] = 0x00; ext[e++] = (uint8_t)(3 + nl);
    ext[e++] = 0x00;
    ext[e++] = 0x00; ext[e++] = (uint8_t)nl;
    memcpy(ext + e, sni, nl); e += nl;
    body[b++] = 0x00; body[b++] = (uint8_t)e;
    memcpy(body + b, ext, e); b += e;

    size_t o = 0;
    out[o++] = 0x16; out[o++] = 0x03; out[o++] = 0x01;
    out[o++] = (uint8_t)((b + 4) >> 8); out[o++] = (uint8_t)(b + 4);
    out[o++] = 0x01; out[o++] = 0x00;
    out[o++] = (uint8_t)(b >> 8); out[o++] = (uint8_t)b;
    memcpy(out + o, body, b); o += b;
    return o;
}

int main(void) {
    d2k_session *s = d2k_session_new(64, 32);
    CHECK(s != NULL, "сессия не создалась");
    if (!s) {
        return 1;
    }

    d2k_plan *p = NULL;
    char err[160];
    CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0,
          "план не загрузился");
    d2k_session_set_plan(s, p);

    uint8_t hello[512];
    size_t hlen = build_hello(hello);
    uint8_t pkt[1024], buf[4096];
    d2k_result r;

    /* --- ClientHello: план применяется ---------------------------------- */
    size_t n = build_pkt(pkt, 40000, 0x18, hello, hlen);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.n_out == 2, "ожидались две копии фальшивки");
    CHECK(r.skipped == NULL, "план не применён, хотя должен был");
    CHECK(r.verdict == D2K_VERDICT_ACCEPT, "оригинал обязан пройти: нагрузку не трогали");
    if (r.n_out == 2) {
        CHECK(r.out[0].delay_us == 0, "первая копия не должна ждать");
        CHECK(r.out[1].delay_us == 78000, "пауза между копиями потеряна");
        CHECK(r.out[0].len == 20 + 20 + 3, "длина собранного пакета неверна");
    }
    CHECK(d2k_session_applied(s) == 1, "счётчик применений не сдвинулся");

    /* --- тот же поток второй раз: план НЕ применяется -------------------- */
    d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(r.n_out == 0, "план применён к потоку повторно");
    CHECK(r.skipped != NULL, "повторное применение не объяснено");
    CHECK(d2k_session_applied(s) == 1, "счётчик применений вырос повторно");

    /* --- не ClientHello: пропускаем -------------------------------------- */
    {
        uint8_t junk[] = {'G', 'E', 'T', ' ', '/', '\r', '\n'};
        n = build_pkt(pkt, 40001, 0x18, junk, sizeof junk);
        d2k_session_packet(s, pkt, n, 3000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "план применён к не-TLS");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "не-TLS обязан пройти как есть");
    }

    /* --- пустая нагрузка --------------------------------------------------- */
    n = build_pkt(pkt, 40002, 0x10, NULL, 0);
    d2k_session_packet(s, pkt, n, 4000, buf, sizeof buf, &r);
    CHECK(r.n_out == 0, "план применён к пакету без нагрузки");

    /* --- сброс убирает поток ---------------------------------------------- */
    {
        size_t before = d2k_session_flows(s);
        n = build_pkt(pkt, 40001, 0x14, NULL, 0);  /* RST|ACK */
        d2k_session_packet(s, pkt, n, 5000, buf, sizeof buf, &r);
        CHECK(d2k_session_flows(s) < before, "сброс не освободил поток");
    }

    /* --- мусор вместо пакета: пропускаем и объясняем ------------------------ */
    {
        uint8_t garbage[8];
        memset(garbage, 0xFF, sizeof garbage);
        d2k_session_packet(s, garbage, sizeof garbage, 6000, buf, sizeof buf, &r);
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "мусор обязан проходить как есть");
        CHECK(r.skipped != NULL, "пропуск мусора не объяснён");
    }

    /* --- врущее поле длины --------------------------------------------------- */
    {
        n = build_pkt(pkt, 40010, 0x18, hello, hlen);
        wr16(pkt + 2, (uint16_t)(n + 500));   /* объявляем больше, чем есть */
        d2k_session_packet(s, pkt, n, 7000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "пакет с врущей длиной обработан");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "пакет с врущей длиной обязан пройти");
    }

    /* --- крошечный буфер отправки ------------------------------------------- */
    {
        n = build_pkt(pkt, 40011, 0x18, hello, hlen);
        d2k_session_packet(s, pkt, n, 8000, buf, 10, &r);
        CHECK(r.n_out == 0, "в крошечный буфер что-то поместилось");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT,
              "ничего не выпустив, оригинал обязаны пропустить");
        CHECK(r.skipped != NULL, "нехватка буфера не объяснена");
    }

    d2k_session_free(s);

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("сессия: все проверки прошли\n");
    return 0;
}
