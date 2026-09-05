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

/* Тот же план плюс защита от чужого сброса. minexec=2: защита появилась во
   второй версии исполнителя, и план обязан это объявлять. */
static const uint8_t plan_guard[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 2, 0, 0, 0, 5,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00,
    0x01, 0x04, 0x00, 0x01, 0x01
};

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

/* Тот же поток, но со стороны сервера: концы поменяны местами. */
static size_t build_rev_pkt_ttl(uint8_t *o, uint16_t client_port, uint8_t flags,
                                const uint8_t *pay, size_t paylen, uint8_t ttl);

static size_t build_rev_pkt(uint8_t *o, uint16_t client_port, uint8_t flags,
                            const uint8_t *pay, size_t paylen) {
    return build_rev_pkt_ttl(o, client_port, flags, pay, paylen, 64);
}

static size_t build_rev_pkt_ttl(uint8_t *o, uint16_t client_port, uint8_t flags,
                                const uint8_t *pay, size_t paylen, uint8_t ttl) {
    size_t total = 20 + 20 + paylen;
    memset(o, 0, 40);
    o[0] = 0x45;
    wr16(o + 2, (uint16_t)total);
    wr16(o + 4, 0x2000);
    o[8] = ttl;
    o[9] = 6;
    uint8_t s[4] = {1, 2, 3, 4}, d[4] = {192, 168, 1, 67};
    memcpy(o + 12, s, 4);
    memcpy(o + 16, d, 4);
    wr16(o + 20, 443);
    wr16(o + 22, client_port);
    wr32(o + 24, 5000);
    wr32(o + 28, 1001);
    o[32] = 0x50;
    o[33] = flags;
    wr16(o + 34, 64240);
    if (paylen) {
        memcpy(o + 40, pay, paylen);
    }
    return total;
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

    /* --- подозрения ---------------------------------------------------------
     * Три улики, доступные в направлении, которое и так наблюдается, плюс
     * одна, доступная только в момент забвения потока. Все три — НАБЛЮДЕНИЯ:
     * §2.4 запрещает выводить из них устройство механизма, и ни одна на диск
     * не идёт (§2.3).                                                       */
    {
        d2k_session *z = d2k_session_new(64, 64);

        /* 1. Сброс в ответ на приветствие. */
        n = build_pkt(pkt, 41000, 0x18, hello, hlen);
        d2k_session_packet(z, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 0, "приветствие само по себе — подозрение");
        n = build_rev_pkt(pkt, 41000, 0x14, NULL, 0);   /* RST|ACK от сервера */
        d2k_session_packet(z, pkt, n, 2000, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 1, "сброс после приветствия не замечен");

        /* Сброс БЕЗ предшествующего приветствия подозрением не является:
           соединение могло закрыться по любой причине. */
        n = build_pkt(pkt, 41001, 0x02, NULL, 0);       /* SYN */
        d2k_session_packet(z, pkt, n, 3000, buf, sizeof buf, &r);
        n = build_rev_pkt(pkt, 41001, 0x14, NULL, 0);
        d2k_session_packet(z, pkt, n, 3100, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 1, "сброс без приветствия сочтён подозрением");

        /* 2. Повтор приветствия. Один повтор — ещё не улика: пакет мог
           потеряться на линии. */
        n = build_pkt(pkt, 41002, 0x18, hello, hlen);
        d2k_session_packet(z, pkt, n, 4000, buf, sizeof buf, &r);
        d2k_session_packet(z, pkt, n, 4500, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 1, "один повтор уже объявлен подозрением");
        d2k_session_packet(z, pkt, n, 5000, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 2, "два повтора не замечены");

        /* Тот же поток дальше не должен множить подозрения. */
        d2k_session_packet(z, pkt, n, 5500, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 2, "подозрение отмечено по одному потоку дважды");

        /* 3. Ответа не было вовсе — видно только при забвении потока. */
        n = build_pkt(pkt, 41003, 0x18, hello, hlen);
        d2k_session_packet(z, pkt, n, 6000, buf, sizeof buf, &r);
        uint64_t before = d2k_session_suspects(z);
        d2k_session_expire(z, 6000 + 100000, 50000);
        CHECK(d2k_session_suspects(z) > before,
              "молчание в ответ на приветствие не замечено при уборке");

        /* Поток, на приветствие которого ответили, подозрения не вызывает. */
        d2k_session *w = d2k_session_new(64, 64);
        n = build_pkt(pkt, 41004, 0x18, hello, hlen);
        d2k_session_packet(w, pkt, n, 1000, buf, sizeof buf, &r);
        {
            uint8_t data[8] = {0x16, 0x03, 0x03, 0, 3, 2, 0, 0};
            n = build_rev_pkt(pkt, 41004, 0x18, data, sizeof data);
            d2k_session_packet(w, pkt, n, 1100, buf, sizeof buf, &r);
        }
        d2k_session_expire(w, 1100 + 100000, 50000);
        CHECK(d2k_session_suspects(w) == 0,
              "поток с ответом на приветствие сочтён подозрительным");
        d2k_session_free(w);
        d2k_session_free(z);
    }

    /* --- защита от чужого сброса ------------------------------------------
     * Ориентир берётся из САМОГО потока: TTL первого пакета, пришедшего с той
     * стороны. Сброс с другим TTL послан не тем, кто до этого отвечал.       */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_guard, sizeof plan_guard, &gp, err, sizeof err) == 0,
              "план с защитой не загрузился");
        d2k_session_set_plan(g, gp);

        /* Рукопожатие: SYN клиента, затем SYN-ACK сервера с TTL 124 —
           он и задаёт ориентир для защиты. */
        n = build_pkt(pkt, 42000, 0x02, NULL, 0);
        d2k_session_packet(g, pkt, n, 900, buf, sizeof buf, &r);
        n = build_rev_pkt_ttl(pkt, 42000, 0x12, NULL, 0, 124);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);

        /* Приветствие: план применяется, защита назначается потоку. */
        n = build_pkt(pkt, 42000, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1100, buf, sizeof buf, &r);
        CHECK(d2k_session_applied(g) == 1, "план с защитой не применился");

        /* Сброс с ЧУЖИМ TTL — снимается. */
        n = build_rev_pkt_ttl(pkt, 42000, 0x14, NULL, 0, 127);
        d2k_session_packet(g, pkt, n, 1200, buf, sizeof buf, &r);
        CHECK(r.verdict == D2K_VERDICT_DROP, "чужой сброс не снят");
        CHECK(d2k_session_rst_dropped(g) == 1, "снятый сброс не посчитан");
        CHECK(d2k_session_flows(g) > 0,
              "поток удалён вместе со снятым сбросом: сервер ещё отвечает");

        /* Сброс с ТЕМ ЖЕ TTL — настоящий, проходит и закрывает поток.
           Это и есть цена ошибки в обратную сторону, и она обязана быть
           маленькой: настоящий сброс мы не трогаем. */
        size_t before_flows = d2k_session_flows(g);
        n = build_rev_pkt_ttl(pkt, 42000, 0x14, NULL, 0, 124);
        d2k_session_packet(g, pkt, n, 1300, buf, sizeof buf, &r);
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "настоящий сброс снят защитой");
        CHECK(d2k_session_rst_dropped(g) == 1, "настоящий сброс посчитан снятым");
        CHECK(d2k_session_flows(g) < before_flows, "настоящий сброс не закрыл поток");

        d2k_session_free(g);
    }

    /* --- план выбирается по цели, а не один на всех ------------------------
     * §2.6: план закрепляется за контекстом, на котором подтверждён. Имя
     * точнее адреса, поэтому ищется первым.                                  */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *by_name = NULL, *by_addr = NULL;
        d2k_plan_load(plan_bytes, sizeof plan_bytes, &by_name, err, sizeof err);
        d2k_plan_load(plan_guard, sizeof plan_guard, &by_addr, err, sizeof err);

        /* Приветствие в наших пакетах несёт имя hetzner.com, а адрес цели —
           1.2.3.4. Ставим планы на оба ключа и проверяем, что берётся тот,
           что по имени. */
        uint8_t dst[4] = {1, 2, 3, 4};
        uint32_t dst_be;
        memcpy(&dst_be, dst, 4);
        d2k_plantab_set_addr(d2k_session_plans(g), dst_be, by_addr);
        d2k_plantab_set_name(d2k_session_plans(g),
                             (const uint8_t *)"hetzner.com", 11, by_name);

        n = build_pkt(pkt, 43000, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.n_out == 2, "план по имени не применился");
        CHECK(d2k_session_applied(g) == 1, "применение не посчитано");

        /* Цель без своего плана и без запасного — пропуск с объяснением. */
        d2k_session *w = d2k_session_new(64, 64);
        n = build_pkt(pkt, 43001, 0x18, hello, hlen);
        d2k_session_packet(w, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "план взялся ниоткуда");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "цель без плана не пропущена");
        CHECK(d2k_session_hellos(w) == 1,
              "приветствие не узнано из-за отсутствия плана");
        d2k_session_free(w);
        d2k_session_free(g);
    }

    /* --- SYN-ACK обогнал SYN: направление всё равно верное -----------------
     * Два направления приходят из ДВУХ правил firewall, и порядок между ними
     * не гарантирован. Раньше такой поток получал направления наоборот, и
     * приветствие клиента не разбиралось вовсе.                             */
    {
        d2k_session *g = d2k_session_new(64, 64);
        n = build_rev_pkt_ttl(pkt, 42002, 0x12, NULL, 0, 124);   /* SYN-ACK первым */
        d2k_session_packet(g, pkt, n, 900, buf, sizeof buf, &r);
        n = build_pkt(pkt, 42002, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(g) == 1,
              "приветствие потеряно, когда SYN-ACK пришёл раньше SYN");
        d2k_session_free(g);
    }

    /* --- без защиты чужой сброс проходит ------------------------------------
     * Проверка, что защита не включается сама собой: план без guard обязан
     * оставлять поведение прежним.                                          */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err);
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 42001, 0x02, NULL, 0);
        d2k_session_packet(g, pkt, n, 900, buf, sizeof buf, &r);
        n = build_rev_pkt_ttl(pkt, 42001, 0x12, NULL, 0, 124);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        n = build_pkt(pkt, 42001, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1100, buf, sizeof buf, &r);
        n = build_rev_pkt_ttl(pkt, 42001, 0x14, NULL, 0, 127);
        d2k_session_packet(g, pkt, n, 1200, buf, sizeof buf, &r);
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "защита сработала без плана с защитой");
        CHECK(d2k_session_rst_dropped(g) == 0, "снятие посчитано там, где защиты нет");
        d2k_session_free(g);
    }

    d2k_session_free(s);

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("сессия: все проверки прошли\n");
    return 0;
}
