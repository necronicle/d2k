/* Этап 49: наблюдатель позднего потока — только наблюдаемое на проводе. */
#include <stdio.h>
#include <string.h>
#include "d2k_lateobs.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s\n", (m)); fails++; } } while (0)

static const uint8_t CLI4[4] = {192, 168, 1, 67}, SRV4[4] = {1, 2, 3, 4};
static const uint8_t CLI6[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 0x67}, SRV6[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 4};

static void wr16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

/* TCP с опциями opt (кратно 4) и полезной нагрузкой pay; from_client — направление. */
static size_t tcp(uint8_t *o, int fam, int from_client, uint32_t seq, uint8_t flags, size_t opt, size_t pay) {
    size_t ip = fam == 6 ? 40 : 20, th = 20 + opt, total = ip + th + pay;
    memset(o, 0, total);
    const uint8_t *s = fam == 6 ? (from_client ? CLI6 : SRV6) : (from_client ? CLI4 : SRV4);
    const uint8_t *d = fam == 6 ? (from_client ? SRV6 : CLI6) : (from_client ? SRV4 : CLI4);
    if (fam == 6) {
        o[0] = 0x60; wr16(o + 4, (unsigned)(th + pay)); o[6] = 6; o[7] = 64;
        memcpy(o + 8, s, 16); memcpy(o + 24, d, 16);
    } else {
        o[0] = 0x45; wr16(o + 2, (unsigned)total); o[8] = 64; o[9] = 6;
        memcpy(o + 12, s, 4); memcpy(o + 16, d, 4);
    }
    uint8_t *t = o + ip;
    wr16(t, from_client ? 45000 : 443); wr16(t + 2, from_client ? 443 : 45000);
    wr32(t + 4, seq); wr32(t + 8, 7777);
    t[12] = (uint8_t)((th / 4) << 4); t[13] = flags; wr16(t + 14, 64000);
    for (size_t i = 0; i < opt; i++) t[20 + i] = 1;   /* NOP */
    memset(t + th, 'q', pay);
    return total;
}

static d2k_ct_tuple tuple(int fam) {
    d2k_ct_tuple t; memset(&t, 0, sizeof t);
    t.family = (uint8_t)fam; t.proto = 6;
    memcpy(t.src, fam == 6 ? CLI6 : CLI4, fam == 6 ? 16 : 4);
    memcpy(t.dst, fam == 6 ? SRV6 : SRV4, fam == 6 ? 16 : 4);
    wr16(t.sport_be, 45000); wr16(t.dport_be, 443);
    return t;
}

int main(void) {
    uint8_t p[2048];
    for (int fam = 4; fam <= 6; fam += 2) {
        d2k_ct_tuple t = tuple(fam);
        d2k_lateobs o;

        /* Чистые ACK, обновления окна, ACK с опциями (SACK/TS) — данных нет. */
        d2k_lateobs_init(&o, &t);
        for (int i = 0; i < 6; i++) CHECK(d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 1000, 0x10, i % 2 ? 12 : 0, 0)), "свой пакет не учтён");
        CHECK(d2k_lateobs_result(&o, 0) == D2K_LATEOBS_PENDING, "без данных клиента итог раньше срока");
        CHECK(d2k_lateobs_result(&o, 1) == D2K_LATEOBS_NO_CLIENT_DATA,
              "чистые ACK/окно/опции клиента названы данными или повтором");

        /* Тот же сегмент с данными дважды, сервер молчит — повтор в тишине. */
        d2k_lateobs_init(&o, &t);
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 5000, 0x18, 12, 1));
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 5001, 0x10, 12, 0));   /* ACK между ними */
        CHECK(d2k_lateobs_result(&o, 0) == D2K_LATEOBS_PENDING, "одна копия данных — уже повтор");
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 5000, 0x18, 12, 1));
        CHECK(d2k_lateobs_result(&o, 0) == D2K_LATEOBS_REPEAT_SILENT,
              "повтор сегмента с данными в тишине сервера не доказан");

        /* Повтор со слиянием (Linux tcp_retrans_try_collapse): тот же seq, длина
           больше; и частичное перекрытие — повтор уже посланных байт. */
        d2k_lateobs_init(&o, &t);
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 7000, 0x18, 12, 1));
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 7000, 0x18, 12, 3));
        CHECK(d2k_lateobs_result(&o, 0) == D2K_LATEOBS_REPEAT_SILENT, "повтор со слиянием сегментов не узнан");
        d2k_lateobs_init(&o, &t);
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 0xfffffff0u, 0x18, 0, 32));   /* через перенос seq */
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 0x00000008u, 0x18, 0, 8));
        CHECK(d2k_lateobs_result(&o, 0) == D2K_LATEOBS_REPEAT_SILENT, "перекрытие через перенос seq не узнано");
        d2k_lateobs_init(&o, &t);
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 7000, 0x18, 0, 10));
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 7010, 0x18, 0, 10));          /* стык, не перекрытие */
        CHECK(d2k_lateobs_result(&o, 1) == D2K_LATEOBS_CLIENT_NEW_DATA, "стык сегментов назван повтором");

        /* Повтор, но сервер ответил хоть чем-то (голым ACK) — жив на уровне TCP. */
        d2k_lateobs_init(&o, &t);
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 5000, 0x18, 0, 100));
        d2k_lateobs_feed(&o, p, tcp(p, fam, 0, 9000, 0x10, 0, 0));
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 5000, 0x18, 0, 100));
        CHECK(d2k_lateobs_result(&o, 0) == D2K_LATEOBS_SERVER_ANSWERED, "пакет сервера не отменил тишину");

        /* Новые данные без повтора — не повтор. */
        d2k_lateobs_init(&o, &t);
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 5000, 0x18, 0, 100));
        d2k_lateobs_feed(&o, p, tcp(p, fam, 1, 5100, 0x18, 0, 100));
        CHECK(d2k_lateobs_result(&o, 1) == D2K_LATEOBS_CLIENT_NEW_DATA, "новые данные клиента названы повтором");

        /* Ничего не пришло — метка не сработала или поток умер; не тишина сервера. */
        d2k_lateobs_init(&o, &t);
        CHECK(d2k_lateobs_result(&o, 1) == D2K_LATEOBS_NOTHING, "отсутствие пакетов не названо «ничего не пришло»");

        /* Чужие потоки и не TCP не учитываются. */
        d2k_lateobs_init(&o, &t);
        size_t n = tcp(p, fam, 1, 5000, 0x18, 0, 10);
        p[(fam == 6 ? 40 : 20) + 1] ^= 1;                   /* другой порт клиента */
        CHECK(!d2k_lateobs_feed(&o, p, n), "чужой поток учтён");
        n = tcp(p, fam, 1, 5000, 0x18, 0, 10);
        if (fam == 6) p[6] = 17; else p[9] = 17;
        CHECK(!d2k_lateobs_feed(&o, p, n), "не-TCP учтён");
        CHECK(!d2k_lateobs_feed(&o, p, 10), "обрезанный пакет учтён");
        CHECK(o.client_pkts == 0 && o.server_pkts == 0, "чужое попало в счёт");
    }
    puts(fails ? "наблюдатель позднего потока: ЕСТЬ ПРОВАЛЫ" : "наблюдатель позднего потока: все проверки прошли");
    return fails ? 1 : 0;
}
