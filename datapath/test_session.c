/* test_session.c — склейка модулей на настоящих пакетах.
 *
 * Правило, которое здесь проверяется главным образом: НЕ ПОНЯЛ — НЕ ТРОГАЙ.
 * Проверок на «пропустили и объяснили почему» больше, чем на «применили»:
 * пропустить чужой пакет безвредно, тронуть непонятый — значит испортить
 * человеку соединение и не узнать об этом.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_nat.h"
#include "d2k_session.h"
#include "d2k_hold.h"
#include "d2k_tls.h"

static int fails;
static size_t hold_released;
static void hold_release(void *ctx, uint32_t id, const uint8_t *p, size_t n) {
    (void)id;
    hold_released++;
    d2k_session_observe_tcp(ctx, p, n, 20);
}
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Сколько раз в журнале встретился отказ плана (D2K_JRN_PLAN_REFUSED) — по
   count, не по note: разные причины отказа делят один и тот же вид записи
   (см. d2k_journal.h), а здесь для каждого сценария в таблице ровно одна
   цель, так что кода причины достаточно. */
static size_t count_plan_refused(const d2k_session *s) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j);
    size_t c = 0;
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == D2K_JRN_PLAN_REFUSED) {
            c++;
        }
    }
    return c;
}

/* Сколько записей заданного вида в журнале. Отдельно от count_plan_refused:
   «план не доисполнен» и «план не применялся» — разные виды записи, и считать
   их одной функцией значило бы снова смешать два разных факта. */
static size_t count_kind(const d2k_session *s, uint8_t kind) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j);
    size_t c = 0;
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == kind) {
            c++;
        }
    }
    return c;
}

/* Последняя запись заданного вида. NULL — такой не было. */
static const d2k_jrn_entry *last_of_kind(const d2k_session *s, uint8_t kind) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j);
    const d2k_jrn_entry *found = NULL;
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == kind) {
            found = e;
        }
    }
    return found;
}

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

/* Тот же план, что plan_bytes, плюс запись REC_ID (тип 0x0001, длина 16) —
 * записей в заголовке поэтому пять. Идентификатор НЕпечатный (0xС0..0xCF)
 * нарочно: он двоичный, и путь от разбора плана до ТОЧКИ ОТПРАВКИ не имеет
 * права его чистить под печать — дорога через поле имени журнала заменила бы
 * каждый такой байт точкой (journal.c), и проверка печатным идентификатором
 * прошла бы мимо этого. */
static const uint8_t want_send_id[16] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF
};
static const uint8_t plan_with_send_id[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 5,
    0x00, 0x01, 0x00, 0x10,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Тот же план, но ВЛАДЕЮЩИЙ НАГРУЗКОЙ: добавлена запись REC_PACE (0x0105,
 * 4 байта, 12000 мкс). Наличие разноса во времени означает, что правду
 * выпускает план, а не ядро, — оригинал снимается (fate DROP). Нужен веткам
 * отказа: только у такого плана «оригинал уже не наш» вообще возможно.
 * Записей шесть: ID, PAYLOAD, POISON, FAKE, ORDER, PACE. */
static const uint8_t plan_owns_payload[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 6,
    0x00, 0x01, 0x00, 0x10,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00,
    0x01, 0x05, 0x00, 0x04, 0x00, 0x00, 0x2E, 0xE0
};

/* План с числом повторов D2K_RESULT_MAX+1: больше вместимости результата.
 * Он должен отвергаться целиком, а не тихо обрезаться. Заголовок schema=1
 * + minexec=1 + flags=0 + число записей=2: REC_PAYLOAD (id=1, байт 0xAA) и
 * REC_FAKE (payload_id=1, poison_id=0, placement=PLACE_BEFORE,
 * gap_us=0). */
static const uint8_t plan_too_many_repeats[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0xAA,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, D2K_RESULT_MAX + 1, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Порты в ключе потока лежат в СЕТЕВОМ порядке (d2k_key_make, d2k_track.h):
   сравнивать их с числом напрямую значит сравнить по-разному на разных арках.
   Своя функция, а не htons: <arpa/inet.h> тянуть в переносимый тест незачем. */
static uint16_t htons16(uint16_t v) {
    uint8_t b[2];
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
    uint16_t o;
    memcpy(&o, b, 2);
    return o;
}

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

/* То же приветствие, добитое расширением padding (RFC 7685) до want байт на
   проводе. Нужно затем, что «перекрытие на полном сегменте» — отдельный
   случай приёмки U3: статическая проверка длины считает только объявленные
   планом части, а кусок нагрузки приходит ИЗ ПАКЕТА, и на коротком
   приветствии расхождение не видно. */
static size_t build_hello_pad(uint8_t *out, size_t want) {
    size_t base = build_hello(out);
    if (want <= base + 4) { return base; }
    size_t pad = want - base - 4;
    if (pad > 0xFF00) { return base; }

    /* Три длины растут на одну величину: блок расширений, тело рукопожатия и
       запись. Позиция длины блока расширений считается ПРОХОДОМ по телу —
       зашитое смещение поменялось бы от любой правки build_hello. */
    size_t q = 5 + 4 + 2 + 32;                      /* запись, заголовок, версия, random */
    q += 1 + out[q];                                /* session_id */
    q += 2 + ((size_t)out[q] << 8 | out[q + 1]);    /* cipher_suites */
    q += 1 + out[q];                                /* compression */
    wr16(out + q, (uint16_t)(((size_t)out[q] << 8 | out[q + 1]) + 4 + pad));

    size_t end = base;
    out[end++] = 0x00; out[end++] = 0x15;           /* padding */
    wr16(out + end, (uint16_t)pad); end += 2;
    memset(out + end, 0, pad); end += pad;

    wr16(out + 7, (uint16_t)(((size_t)out[7] << 8 | out[8]) + 4 + pad));
    wr16(out + 3, (uint16_t)(((size_t)out[3] << 8 | out[4]) + 4 + pad));
    return end;
}

/* Пакет с ОПЦИЯМИ TCP: смещение данных растёт, и всё, что собирается из
   пакета, растёт вместе с ним. Опции — NOP'ы: их содержимое здесь не предмет,
   предмет — длина. */
static size_t build_pkt_opt(uint8_t *o, uint16_t sport, uint8_t flags,
                            const uint8_t *pay, size_t paylen, size_t optlen) {
    size_t total = 20 + 20 + optlen + paylen;
    memset(o, 0, 40 + optlen);
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
    o[32] = (uint8_t)(((20 + optlen) / 4) << 4);
    o[33] = flags;
    wr16(o + 34, 64240);
    memset(o + 40, 0x01, optlen);          /* NOP */
    if (paylen) {
        memcpy(o + 40 + optlen, pay, paylen);
    }
    return total;
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

/* --- ПРОМАХ CONNTRACK: ОДИН ОТВЕТ ЕЩЁ НЕ ОТВЕТ ----------------------------
 *
 * Справка о трансляции читается из /proc/net/nf_conntrack, и это чтение НЕ
 * атомарно: замер 17.09 на стенде транзита поймал случай, когда запрос вернул
 * «записи нет», а повторный запрос сразу же, без паузы, ту же запись нашёл
 * (диагностика печатала «ПОВТОР СРАЗУ ЖЕ: rc=0»).
 *
 * Цена одного промаха оказалась несоразмерной. Мелкое следствие: клиент, чьё
 * приветствие пришлось на промах, остаётся без обхода — один из тридцати.
 * Тяжёлое: если промах попадает на поток СОБСТВЕННОГО ЗОНДА, план к нему не
 * применяется, зонд не доходит до приложения, единственный найденный
 * кандидат объявляется негодным и цель остаётся без обхода ЦЕЛИКОМ. Именно
 * это дало «прошло 0 из 30» в прогоне 17.09.
 *
 * Поэтому промах перепроверяется. Здесь проверяется ровно это, и с двух
 * сторон: гонка обязана лечиться, а настоящее отсутствие записи обязано
 * по-прежнему отвергать план — иначе посылки уйдут мимо NAT с локальным
 * адресом (13.09, docs/field/2026-09-13-transit-vs-local.md). */
static int nat_calls;
static int nat_miss_first_n;   /* сколько первых вызовов отвечают «нет записи» */

static int nat_stub(const char *path, uint8_t proto,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dst_ip, uint16_t dst_port,
                    uint32_t *out_src, uint16_t *out_sport) {
    (void)path; (void)proto; (void)dst_ip; (void)dst_port;
    nat_calls++;
    if (nat_calls <= nat_miss_first_n) { return -1; }
    *out_src = src_ip;
    *out_sport = src_port;
    return 0;
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

    /* --- СБОРКА НЕ ВЛЕЗЛА: отказ целиком, оригинал нетронут -------------
     *
     * 0009, U3. Буфер результата даётся заведомо маленький — первая же
     * посылка в него не поместится. Это происходит на СБОРКЕ, до единой
     * отправки, и значит чистый выход есть: воздействия не было, поток не
     * испорчен, оригинал обязан пройти.
     *
     * Раньше исполнителю сообщалось число уже СОБРАННЫХ посылок как число
     * ушедших: с ним он объявлял поток испорченным и снимал оригинал из-за
     * байт, которых на проводе не было. Проверяется именно это: ноль посылок
     * и проход оригинала. */
    {
        uint8_t tiny[8];
        size_t nn = build_pkt(pkt, 40001, 0x18, hello, hlen);
        d2k_result rt;
        d2k_session_packet(s, pkt, nn, 900, tiny, sizeof tiny, &rt);
        CHECK(rt.n_out == 0, "несобранный план выдан как частично исполненный");
        CHECK(rt.verdict == D2K_VERDICT_ACCEPT,
              "оригинал снят, хотя на провод не ушло ни байта");
        CHECK(rt.skipped != NULL, "отказ сборки не назван причиной");
    }

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
        d2k_plantab_set_addr(d2k_session_plans(g), dst_be, 1, by_addr);
        d2k_plantab_set_name(d2k_session_plans(g),
                             (const uint8_t *)"hetzner.com", 11, 1, by_name);

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

    /* Segmented measured fake: 7 * ceil(4096/1400) + truth = 22 packets.
     * Check the real session output and an all-or-nothing small-buffer refusal. */
    {
        uint8_t tlv[4200] = {'D','2','K','P',0,1,0,3,0,0,0,5,0,2,0,2,6,1};
        size_t z = 18;
        wr16(tlv + z, 0x0010); wr16(tlv + z + 2, 4098); wr16(tlv + z + 4, 1);
        memset(tlv + z + 6, 0x0f, 4096); z += 4102;
        const uint8_t tail[] = {
            0x01,0x01,0,10, 0,1,0,0,7,0,0,0,0,0,
            0x01,0x07,0,4, 0,0,0x3a,0x98,
            0x01,0x08,0,4, 0,0,0x05,0x78
        };
        memcpy(tlv + z, tail, sizeof tail); z += sizeof tail;
        uint8_t bigbuf[D2K_RESULT_MAX * 1600];
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(tlv, z, &gp, err, sizeof err) == 0, "segmented plan rejected");
        CHECK(d2k_plan_max_emit(gp) == 1440, "MTU check ignores segmentation");
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 43098, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0 && !r.applied && r.verdict == D2K_VERDICT_ACCEPT,
              "small buffer produced partial measured execution");
        n = build_pkt(pkt, 43099, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 2000, bigbuf, sizeof bigbuf, &r);
        CHECK(r.n_out == 22 && r.applied && r.verdict == D2K_VERDICT_DROP,
              "long measured fake does not fit real session");
        if (r.n_out == 22) {
            for (size_t k = 0; k < 21; k++) {
                CHECK(r.out[k].len == (k % 3 == 2 ? 1336u : 1440u), "segment length changed");
                CHECK(r.out[k].delay_us == 0, "segment gained delay");
            }
            CHECK(r.out[21].delay_us == 15000, "settle delay lost");
            CHECK(r.out[21].len == hlen + 40, "truth length changed");
            CHECK(memcmp(bigbuf + r.out[21].off + 40, hello, hlen) == 0, "truth bytes changed");
        }
        d2k_session_free(g);
    }

    /* --- план с repeats больше вместимости out[] отвергается целиком -------
       Ревью задачи 4, круг 2: repeats берётся из TLV байтом без потолка (до
       255), d2k_result.out[] ограничен D2K_RESULT_MAX. Раньше n тихо
       обрезался до 16, на провод уходило меньше посылок, чем описывал план,
       а plan_done/applied++/PLAN_APPLIED ставились как за полное исполнение.
       Честный исход — отказ целиком: ни одной посылки, план не применён. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_too_many_repeats, sizeof plan_too_many_repeats, &gp, err, sizeof err) == 0,
              "план с лишним повтором не загрузился");
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 43100, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "план с лишним повтором отправил посылку вместо отказа");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "ничего не отправив, оригинал обязаны пропустить");
        CHECK(r.skipped != NULL, "отказ по переполнению out[] не объяснён вызывающему");
        CHECK(d2k_session_applied(g) == 0, "план с лишним повтором засчитан применённым");
        d2k_session_free(g);
    }

    /* --- молчание замечается по измеренному RTT, а не через две минуты ---
     *
     * Полевой прогон 06.09.2026: цель молчала в ответ на приветствие, и поиск
     * не начинался вовсе — подозрение рождалось только при забвении потока, а
     * это 120 секунд. Человек перед пустой страницей столько не ждёт. */
    {
        d2k_session *q = d2k_session_new(16, 32);
        CHECK(q != NULL, "сессия для молчания не создалась");
        const uint64_t ms = 1000000ull;
        uint8_t qp[1024], qb[4096];
        d2k_result qr;

        /* SYN и SYN-ACK с интервалом 20 мс — вот и измеренный RTT. */
        size_t qn = build_pkt(qp, 41000, 0x02, NULL, 0);
        d2k_session_packet(q, qp, qn, 0, qb, sizeof qb, &qr);
        qn = build_rev_pkt(qp, 41000, 0x12, NULL, 0);
        d2k_session_packet(q, qp, qn, 20 * ms, qb, sizeof qb, &qr);

        uint8_t qh[512];
        size_t qhl = build_hello(qh);
        qn = build_pkt(qp, 41000, 0x18, qh, qhl);
        d2k_session_packet(q, qp, qn, 30 * ms, qb, sizeof qb, &qr);
        CHECK(d2k_session_suspects(q) == 0, "подозрение сразу после приветствия");

        CHECK(d2k_session_sweep(q, 530 * ms) == 0,
              "полсекунды молчания объявлены блокировкой");
        CHECK(d2k_session_sweep(q, 1530 * ms) == 1,
              "молчание не замечено на второй секунде");
        CHECK(d2k_session_suspects(q) == 1, "подозрение о молчании не отмечено");
        CHECK(d2k_session_sweep(q, 9000 * ms) == 0, "подозрение продублировано");
        d2k_session_free(q);
    }

    /* --- без видимости обратной стороны молчания не бывает ---------------
     *
     * Правило на обратное направление ставится не всегда. Без него сервер
     * невидим, и каждый поток выглядел бы молчащим: это подмена «не смотрели»
     * на «нет ответа». */
    {
        d2k_session *q = d2k_session_new(16, 32);
        const uint64_t ms = 1000000ull;
        uint8_t qp[1024], qb[4096];
        d2k_result qr;

        /* Только исходящее: SYN и приветствие. Ответов не видим вовсе. */
        size_t qn = build_pkt(qp, 43000, 0x02, NULL, 0);
        d2k_session_packet(q, qp, qn, 0, qb, sizeof qb, &qr);
        uint8_t qh[512];
        size_t qhl = build_hello(qh);
        qn = build_pkt(qp, 43000, 0x18, qh, qhl);
        d2k_session_packet(q, qp, qn, 30 * ms, qb, sizeof qb, &qr);

        CHECK(d2k_session_sweep(q, 9000 * ms) == 0,
              "невидимая обратная сторона объявлена молчащей");
        d2k_session_free(q);
    }

    /* --- ответивший сервер не молчит, сколько ни выжидай ----------------- */
    {
        d2k_session *q = d2k_session_new(16, 32);
        const uint64_t ms = 1000000ull;
        uint8_t qp[1024], qb[4096];
        d2k_result qr;

        size_t qn = build_pkt(qp, 42000, 0x02, NULL, 0);
        d2k_session_packet(q, qp, qn, 0, qb, sizeof qb, &qr);
        qn = build_rev_pkt(qp, 42000, 0x12, NULL, 0);
        d2k_session_packet(q, qp, qn, 20 * ms, qb, sizeof qb, &qr);

        uint8_t qh[512];
        size_t qhl = build_hello(qh);
        qn = build_pkt(qp, 42000, 0x18, qh, qhl);
        d2k_session_packet(q, qp, qn, 30 * ms, qb, sizeof qb, &qr);

        uint8_t sh[8] = { 0x16, 0x03, 0x03, 0x00, 0x03, 0x02, 0x00, 0x00 };
        qn = build_rev_pkt(qp, 42000, 0x18, sh, sizeof sh);
        d2k_session_packet(q, qp, qn, 50 * ms, qb, sizeof qb, &qr);

        CHECK(d2k_session_sweep(q, 9000 * ms) == 0, "ответивший сервер объявлен молчащим");
        d2k_session_free(q);
    }

    /* --- отказ «плана для этой цели нет» доходит до журнала и не чаще
     * одного раза на поток (ревью, пункт 3) ---------------------------------
     *
     * Раньше session.c просто выставлял out->skipped и возвращался: refuse()
     * не звался, в журнал ничего не попадало, на провод ничего не уходило —
     * единственным следом оставался счётчик в сводке d2kd. Управляющий сокет
     * — единственное, что видит контроллер, а вытеснение из таблицы планов
     * теперь штатный путь (см. d2k_plans.h): однажды выпавшая подтверждённая
     * цель терялась бы НАВСЕГДА без единого сигнала об этом.
     *
     * Ловушка, которую эта проверка обязана ловить: наивная правка звала бы
     * refuse() там же, где стоит "плана для этой цели нет", — а это условие
     * ложно совпадает с «пакет вообще не приветствие» (use остаётся NULL,
     * потому что tls.is_client_hello ложно, а не потому, что план искали и не
     * нашли). На потоке без всякого плана КАЖДЫЙ пакет после SYN подпадал бы
     * под то же условие — событие на каждый пакет вместо события на промах. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        /* Ни глобального плана (d2k_session_set_plan не звался), ни записи в
           таблице планов — это и есть «плана для этой цели нет» по-настоящему. */
        uint8_t pkt[1024], buf[4096];
        d2k_result r;

        /* Мусор вместо приветствия на СВОЁМ потоке, план для которого тоже
           не встал: use == NULL здесь по причине "не приветствие", а не
           "искали план и не нашли". Событие отказа плана не обязано
           появиться ложно. */
        uint8_t junk[] = {'G', 'E', 'T', ' ', '/', '\r', '\n'};
        size_t n = build_pkt(pkt, 45000, 0x18, junk, sizeof junk);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(count_plan_refused(g) == 0,
              "не-приветствие без всякого плана ложно засчитано отказом плана");

        /* Настоящее приветствие на ДРУГОМ потоке: d2k_plantab_find и s->plan
           оба ничего не дают — вот теперь это по-настоящему «плана для этой
           цели нет», и событие обязано дойти до журнала. */
        uint8_t hello[512];
        size_t hlen = build_hello(hello);
        n = build_pkt(pkt, 45001, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 2000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "план взялся ниоткуда для цели без плана");
        size_t after_hello = count_plan_refused(g);
        CHECK(after_hello == 1,
              "отказ «плана для этой цели нет» не ушёл в журнал");

        /* Тот же поток дальше: пакет с нагрузкой, но не приветствием. После
           рукопожатия tls.is_client_hello уже не взводится вовсе — saw_hello
           взведён первым же пакетом приветствия (session.c) и держит эту
           дверь закрытой до конца потока. Событие не обязано прибавиться —
           сравниваем с after_hello, а не с литералом 1, чтобы эта проверка
           отвечала за СВОЙ факт (пакет ничего не добавил), а не дублировала
           провал предыдущей, если та уже упала. */
        uint8_t appdata[] = {0x17, 0x03, 0x03, 0x00, 0x01, 0xAA};
        n = build_pkt(pkt, 45001, 0x18, appdata, sizeof appdata);
        d2k_session_packet(g, pkt, n, 3000, buf, sizeof buf, &r);
        CHECK(count_plan_refused(g) == after_hello,
              "пакет после рукопожатия на том же потоке размножил отказ плана");

        d2k_session_free(g);
    }

    /* --- результат исполнения доезжает до контроллера ---------------------
     *
     * Разрыв, ради которого заведён этот блок (docs/decisions/0006, «Что
     * по-прежнему НЕ доказано»): APPLIED писался при ПОСТРОЕНИИ результата, до
     * отправки, и ошибка отправки его не отзывала. На живой пробе 12.09.2026
     * «sendto: Message too large» шло ОДНОВРЕМЕННО с ростом «план применён».
     * Отрицательный исход становился неотличим от неотправленного зонда.
     *
     * Проверяется тройка: (1) ключ потока и идентификатор плана доезжают до
     * точки отправки в самом результате; (2) когда все посылки ушли, журнал
     * получает «план доисполнен»; (3) когда хоть одна не ушла — «план не
     * доисполнен» с кодом причины, и поздняя удача остатка НЕ превращает это
     * обратно в «доисполнен». */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_with_send_id, sizeof plan_with_send_id, &gp,
                            err, sizeof err) == 0,
              "план с идентификатором не загрузился");
        d2k_session_set_plan(g, gp);

        n = build_pkt(pkt, 46000, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.n_out == 2, "план с идентификатором не дал двух посылок");
        CHECK(r.applied == 1, "результат не объявил план применённым");
        /* Ключ канонический: низкий конец пары — не обязательно клиент.
           Сверяем то, что не зависит от порядка: транспорт и оба порта. */
        CHECK(r.key.proto == 6, "в результате нет транспорта ключа потока");
        CHECK((r.key.low_port == htons16(46000) || r.key.high_port == htons16(46000)),
              "ключ потока в результате не про этот поток");
        CHECK(memcmp(r.plan_id, want_send_id, 16) == 0,
              "идентификатор плана не доехал до точки отправки");

        /* Все посылки ушли — «план доисполнен». */
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 0,
              "«доисполнен» записан до единой отправки");
        d2k_session_sent(g, 1100, &r.key, r.execution_id);
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 0,
              "«доисполнен» записан на половине посылок");
        d2k_session_sent(g, 1200, &r.key, r.execution_id);
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 0,
              "отправки завершены, но судьба оригинала ещё не подтверждена");
        d2k_session_sent(g, 1250, &r.key, r.execution_id);
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 1,
              "все посылки ушли, а «доисполнен» не записан");
        CHECK(count_kind(g, D2K_JRN_PLAN_UNSENT) == 0,
              "успешная отправка записана недоисполнением");

        d2k_session_free(g);
    }

    /* --- ДЛИНА ПОСЫЛКИ И ОБЪЯВЛЕННАЯ В НЕЙ ДЛИНА — ОДНО ЧИСЛО -----------
     *
     * Приёмка U3 просит опыт на разных опциях TCP и на перекрытии ПОЛНОГО
     * сегмента. Проверяемое утверждение здесь одно, зато оно держит всю
     * проверку предела отправки: число, по которому d2kd сверяет посылку с
     * пределом (out[].len), обязано совпадать с числом, по которому её
     * нарежет ядро (поле длины в заголовке IPv4). Разойдись они — проверка
     * предела сверяла бы не то, и EMSGSIZE приходил бы посреди исполнения,
     * где чистого выхода нет.
     *
     * Опции — NOP'ы: их содержимое не предмет опыта, предмет — смещение
     * данных, от которого зависит всё, что собирается из пакета. Нагрузка —
     * приветствие, добитое до полутора килобайт: на коротком приветствии
     * расхождение статической и настоящей длины не видно. */
    for (size_t oi = 0; oi < 3; oi++) {
        static const size_t opts[] = { 0, 12, 20 };
        static const size_t sizes[] = { 0, 700, 1400 };
        /* Свои буферы: общие на функцию рассчитаны на короткое приветствие, а
           здесь нагрузка нарочно полноразмерная, и посылок из неё выходит
           больше её самой. */
        uint8_t big[2048], bpkt[2048], bbuf[16384];
        size_t blen = build_hello_pad(big, sizes[oi]);
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_owns_payload, sizeof plan_owns_payload, &gp,
                            err, sizeof err) == 0, "план для опыта с опциями");
        d2k_session_set_plan(g, gp);
        n = build_pkt_opt(bpkt, (uint16_t)(46200 + oi), 0x18, big, blen, opts[oi]);
        d2k_session_packet(g, bpkt, n, 1000, bbuf, sizeof bbuf, &r);
        CHECK(r.applied == 1, "план не применился при опциях TCP");
        CHECK(r.n_out > 0, "посылок не собралось — сверять нечего");
        for (size_t k = 0; k < r.n_out; k++) {
            const uint8_t *e = bbuf + r.out[k].off;
            CHECK(r.out[k].len >= 20, "посылка короче заголовка IPv4");
            size_t decl = (size_t)e[2] << 8 | e[3];
            CHECK(decl == r.out[k].len,
                  "объявленная длина посылки расходится с её размером — "
                  "предел отправки сверяется не по тому числу");
        }
        d2k_session_free(g);
    }

    /* --- ОБЩИЙ ИСХОД ОТКАЗА ИСПОЛНЕНИЯ (0009, U3) ----------------------
     *
     * Пять веток отказа у отправляющего вели себя по-разному: учёт повреждения
     * стоял ровно в одной, а обещание «оригинал пройдёт» не выполнялось
     * нигде — вердикт оставался DROP, и ClientHello клиента не уходил на
     * провод вовсе из-за НАШЕЙ внутренней ошибки.
     *
     * Чистый выход существует ровно в одном случае: ни один кусок нагрузки не
     * ушёл И вердикт ещё не отправлен. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_owns_payload, sizeof plan_owns_payload, &gp,
                            err, sizeof err) == 0, "план для проверки отказа");
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 46010, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied == 1, "план не применился");
        d2k_key key0 = r.key;
        uint64_t exec0 = r.execution_id;

        /* Нагрузка не ушла, вердикт не отправлен — оригинал ещё наш. */
        CHECK(d2k_session_exec_failed(g, 1100, &r.key, r.plan_id, D2K_REFUSE_QUEUE,
                                      r.execution_id, 0, 0) == 1,
              "оригинал не отпущен, хотя на провод не ушло ни байта нагрузки");
        CHECK(count_kind(g, D2K_JRN_PLAN_UNSENT) == 1, "отказ не записан");

        /* Вторая неудача той же попытки не удваивает запись: «ошибка посылки,
           затем ошибка вердикта» — один несостоявшийся опыт, а не два. */
        CHECK(d2k_session_exec_failed(g, 1150, &r.key, r.plan_id, D2K_REFUSE_SEND,
                                      r.execution_id, 0, 1) == 0,
              "вердикт уже ушёл, а оригинал объявлен отпускаемым");
        CHECK(count_kind(g, D2K_JRN_PLAN_UNSENT) == 1,
              "двойной отказ одной попытки записан дважды");

        /* Защиты сняты вместе с планом: держать испорченный поток живым,
           снимая подделанный сброс, значит заставлять человека ждать таймаута
           вместо быстрой переустановки соединения клиентом. */
        CHECK(d2k_session_guards(g, &key0) == 0,
              "защиты остались на испорченном потоке");

        /* Факт повреждения записан В МОМЕНТ установления, а не при следующем
           пакете: замолчавший поток второго пакета мог бы и не прислать. */
        CHECK(count_kind(g, D2K_JRN_PLAN_DAMAGED) == 1,
              "повреждение не записано в момент установления");
        CHECK(d2k_session_exec_failed(g, 1160, &key0, r.plan_id, D2K_REFUSE_SEND,
                                      exec0, 1, 0) == 0,
              "повторный отказ той же попытки вернул «оригинал ещё наш»");
        CHECK(count_kind(g, D2K_JRN_PLAN_DAMAGED) == 1,
              "повреждение записано дважды за одну попытку");

        /* Повреждение стало НАБЛЮДАЕМЫМ: следующее приветствие того же потока
           получает именно его, а не «план уже применён». */
        /* Другой ПОРТ — тот же поток? Нет: ключ другой. Берём тот же порт,
           но проверяем через send_pending, что поток жив и это он. */
        CHECK(!d2k_session_send_pending(g, &key0, exec0),
              "после отказа поток всё ещё принимает посылки этой попытки");
        n = build_pkt(pkt, 46010, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1200, buf, sizeof buf, &r);
        CHECK(r.skipped != NULL && strstr(r.skipped, "испорчен") != NULL,
              "повреждение потока не наблюдаемо — флаг остался write-only");
        d2k_session_free(g);
    }

    {
        /* План ИЗ ОДНИХ ФАЛЬШИВОК оригинал не забирает. Отказ отложенной
           посылки по такому плану поток НЕ портит: байты клиента целы, и
           единственный факт — воздействие неполно. Слишком широкая политика
           «отложенный отказ = всегда порча» этот случай завалит. */
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0,
              "план из одних фальшивок не загрузился");
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 46011, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied == 1 && r.verdict == D2K_VERDICT_ACCEPT,
              "план из одних фальшивок забрал оригинал");
        CHECK(r.first_payload == 0xFF, "у плана без нагрузки объявлен номер её посылки");

        CHECK(d2k_session_exec_failed(g, 1100, &r.key, r.plan_id, D2K_REFUSE_SEND,
                                      r.execution_id, 0, 1) == 1,
              "поток объявлен испорченным, хотя оригинал не наш и байты клиента целы");
        n = build_pkt(pkt, 46011, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1200, buf, sizeof buf, &r);
        CHECK(r.skipped != NULL && strstr(r.skipped, "испорчен") == NULL,
              "целый поток объявлен испорченным");
        d2k_session_free(g);
    }

    /* One 5-tuple may be reused while old delayed packets still exist. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_with_send_id, sizeof plan_with_send_id, &gp,
                            err, sizeof err) == 0, "план для повторного ключа");
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 46002, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        uint64_t old = r.execution_id;
        d2k_key key = r.key;
        n = build_pkt(pkt, 46002, 0x11, NULL, 0);
        d2k_session_packet(g, pkt, n, 1100, buf, sizeof buf, &r);
        n = build_pkt(pkt, 46002, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1200, buf, sizeof buf, &r);
        CHECK(r.applied && r.execution_id != old, "повторный поток наследовал номер исполнения");
        CHECK(!d2k_session_send_pending(g, &key, old), "старый пакет разрешён к отправке");
        d2k_session_sent(g, 1300, &key, old);
        d2k_session_unsent(g, 1301, &key, NULL, D2K_REFUSE_SEND, old);
        CHECK(d2k_session_send_pending(g, &r.key, r.execution_id), "старый отказ отменил новое исполнение");
        for (size_t i = 0; i < r.n_out; i++) {
            d2k_session_sent(g, 1400 + i, &r.key, r.execution_id);
        }
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 0, "чужая отправка зачтена новому потоку");
        d2k_session_sent(g, 1500, &r.key, r.execution_id);
        const d2k_jrn_entry *e = last_of_kind(g, D2K_JRN_PLAN_DONE);
        CHECK(e && memcmp(e->plan_id, want_send_id, 16) == 0, "DONE потерял ID плана");
        d2k_session_free(g);
    }

    /* Отказ отправки: «план не доисполнен» с кодом, и поздняя удача остатка
       не отменяет отказ. Отдельная сессия — иначе счётчики предыдущей
       смешались бы с этими. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_with_send_id, sizeof plan_with_send_id, &gp,
                            err, sizeof err) == 0,
              "план с идентификатором не загрузился (вторая сессия)");
        d2k_session_set_plan(g, gp);

        n = build_pkt(pkt, 46001, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied == 1, "план не применился во второй сессии");

        d2k_session_unsent(g, 1100, &r.key, r.plan_id, D2K_REFUSE_TOO_LONG, r.execution_id);
        CHECK(count_kind(g, D2K_JRN_PLAN_UNSENT) == 1,
              "отказ отправки не записан в журнал");
        {
            const d2k_jrn_entry *e = last_of_kind(g, D2K_JRN_PLAN_UNSENT);
            CHECK(e != NULL && e->code == D2K_REFUSE_TOO_LONG,
                  "у недоисполнения нет кода причины");
            CHECK(e != NULL && memcmp(e->plan_id, want_send_id, 16) == 0,
                  "недоисполнение не названо идентификатором плана");
            CHECK(e != NULL && e->key.proto == 6,
                  "недоисполнение не названо ключом потока");
        }

        /* Остаток плана уходит успешно — «доисполнен» всё равно не пишется:
           план исполнен НЕ полностью, и поздняя удача этого не меняет. */
        d2k_session_sent(g, 1200, &r.key, r.execution_id);
        d2k_session_sent(g, 1300, &r.key, r.execution_id);
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 0,
              "поздняя удача остатка объявила недоисполненный план доисполненным");

        d2k_session_free(g);
    }

    d2k_session_free(s);

    /* Snapshot assembly is observation, never a packet verdict/byte change.
       SNI can cross a boundary or be in the first segment. Neither case may
       publish a truncated SHAPE or duplicate the target event. */
    {
        uint8_t whole[2048], part[2100], saved[2100];
        size_t whole_len = build_hello_pad(whole, 1544);
        const size_t cuts[] = {1, 4, 8, 60, 64, 70, 1448, 1544};
        const uint8_t name[] = "hetzner.com";
        for (size_t j = 0; j < sizeof cuts / sizeof cuts[0]; j++) {
            d2k_session *g = d2k_session_new(64, 64);
            CHECK(g != NULL, "capture session allocation");
            if (!g) { continue; }
            CHECK(d2k_session_want_shape(g, name, sizeof name - 1, 6) == 0,
                  "empty capture was ready");
            size_t cut = cuts[j];
            size_t pn = build_pkt(part, 47000, 0x18, whole, cut);
            memcpy(saved, part, pn);
            d2k_session_packet(g, part, pn, 1, buf, sizeof buf, &r);
            CHECK(r.verdict == D2K_VERDICT_ACCEPT && !r.applied && !r.n_out,
                  "capture changed first packet verdict");
            CHECK(!memcmp(saved, part, pn), "capture changed first packet bytes");
            size_t got_len = 0;
            if (cut < whole_len) {
                CHECK(d2k_session_shape(g, 6, &got_len) == NULL,
                      "partial hello published as SHAPE");
                CHECK(count_kind(g, D2K_JRN_SHAPE) == 0, "partial SHAPE event");
                CHECK(count_kind(g, D2K_JRN_HELLO_NONAME) == 0,
                      "incomplete SNI was called nameless");
                pn = build_pkt(part, 47000, 0x18, whole + cut, whole_len - cut);
                wr32(part + 24, 1000 + (uint32_t)cut);
                memcpy(saved, part, pn);
                d2k_session_packet(g, part, pn, 2, buf, sizeof buf, &r);
                CHECK(r.verdict == D2K_VERDICT_ACCEPT && !r.applied && !r.n_out,
                      "capture changed tail verdict");
                CHECK(!memcmp(saved, part, pn), "capture changed tail bytes");
            }
            const uint8_t *got = d2k_session_shape(g, 6, &got_len);
            CHECK(got && got_len == whole_len && !memcmp(got, whole, whole_len),
                  "assembled snapshot differs from original hello");
            CHECK(count_kind(g, D2K_JRN_SHAPE) == 1, "expected one SHAPE event");
            CHECK(count_kind(g, D2K_JRN_HELLO_SNI) == 1, "expected one SNI event");
            CHECK(d2k_session_want_shape(g, name, sizeof name - 1, 6) == 1,
                  "full hello not available to later search");
            CHECK(d2k_session_shape(g, 17, &got_len) == NULL, "TCP polluted QUIC snapshot");
            pn = build_pkt(part, 47000, 0x18, whole, whole_len);
            d2k_session_packet(g, part, pn, 3, buf, sizeof buf, &r);
            d2k_payload_stats ps;
            d2k_session_payload_stats(g, &ps);
            CHECK(ps.capture_complete == 1, "retransmit duplicated completed capture");
            d2k_session_free(g);
        }
        /* Fast successful flows must release slots, not fill all 64 slots
           for five seconds and starve the next incomplete ClientHello. */
        {
            d2k_session *g = d2k_session_new(256, 64);
            CHECK(g != NULL, "capture pressure allocation");
            if (g) {
                for (uint16_t port = 48000; port < 48080; port++) {
                    size_t pn = build_pkt(part, port, 0x18, whole, whole_len);
                    d2k_session_packet(g, part, pn, 1, buf, sizeof buf, &r);
                }
                d2k_payload_stats ps;
                d2k_session_payload_stats(g, &ps);
                CHECK(ps.capture_complete == 80 && ps.capture_full == 0,
                      "completed captures starved new flows");
                d2k_session_free(g);
            }
        }
        {
            /* Even with an installed input-tls plan, completion on a tail
               is NOT permission to send a reconstructed hello after its
               original head has already passed. Whole-packet path still works. */
            static const uint8_t strict_plan[] = {
                'D','2','K','P', 0,1, 0,5, 0,0, 0,8,
                0,2, 0,2, 6,1,                 /* TCP/TLS */
                1,10, 0,0,                     /* input tls-sni */
                1,0, 0,4, 0,0, 0,1,           /* split payload_start+1 */
                1,0, 0,4, 0,5, 0,0,           /* split sni_middle */
                1,8, 0,4, 0,0,5,120,           /* segment 1400 */
                1,3, 0,1, 1,                   /* reverse */
                1,5, 0,4, 0,0,46,224,          /* pace 12000 */
                1,9, 0,1, 1                    /* detect-tcp-v1 */
            };
            d2k_session *g = d2k_session_new(64, 64);
            d2k_plan *gp = NULL;
            CHECK(g != NULL, "strict capture allocation");
            CHECK(d2k_plan_load(strict_plan, sizeof strict_plan, &gp,
                                err, sizeof err) == 0, "strict capture plan parse");
            if (g && gp) {
                d2k_session_set_plan(g, gp);
                gp = NULL;
                size_t pn = build_pkt(part, 47500, 0x18, whole, 1448);
                d2k_session_packet(g, part, pn, 1, buf, sizeof buf, &r);
                CHECK(!r.applied && !r.n_out && r.verdict == D2K_VERDICT_ACCEPT,
                      "strict plan consumed incomplete head");
                pn = build_pkt(part, 47500, 0x18, whole + 1448, whole_len - 1448);
                wr32(part + 24, 2448);
                d2k_session_packet(g, part, pn, 2, buf, sizeof buf, &r);
                CHECK(!r.applied && !r.n_out && r.verdict == D2K_VERDICT_ACCEPT,
                      "observation executed full plan on passed-through tail");
                pn = build_pkt(part, 47501, 0x18, whole, whole_len);
                d2k_session_packet(g, part, pn, 3, buf, sizeof buf, &r);
                CHECK(r.applied && r.n_out > 0 && r.verdict == D2K_VERDICT_DROP,
                      "capture prevented whole-packet plan execution");

                /* The explicit owning path is allowed to execute the WHOLE
                   held hello, once, using its first seq/ACK and normal NAT. */
                d2k_hold *h = d2k_hold_new();
                d2k_hold_batch batch;
                CHECK(h != NULL, "owning hold allocation");
                if (h) {
                    pn = build_pkt(part, 47502, 0x02, NULL, 0);
                    d2k_session_packet(g, part, pn, 4, buf, sizeof buf, &r);
                    pn = build_pkt(part, 47502, 0x18, whole, 1448);
                    wr32(part + 24, 1001);
                    int allow = d2k_session_hold_candidate(g, part, pn);
                    CHECK(allow, "installed measured plan did not enable hold");
                    CHECK(d2k_hold_feed(h, 80, part, pn, 5, d2k_session_plan_revision(g),
                        allow, hold_release, g, &batch) == 1, "first piece not owned");
                    pn = build_pkt(part, 47502, 0x18, whole + 1448, whole_len - 1448);
                    wr32(part + 24, 2449);
                    CHECK(d2k_hold_feed(h, 81, part, pn, 6, d2k_session_plan_revision(g),
                        0, hold_release, g, &batch) == 2, "held hello not completed");
                    CHECK(batch.count == 2 && batch.ids[0] == 80 && batch.ids[1] == 81,
                          "original ownership lost");
                    d2k_session_packet(g, batch.packet, batch.len, 7, buf, sizeof buf, &r);
                    CHECK(r.applied && r.verdict == D2K_VERDICT_DROP && r.n_out == 4,
                          "whole held disorder was not applied");
                    d2k_tls_info ti;
                    d2k_tls_parse(whole, whole_len, &ti);
                    size_t middle = ti.sni_off + ti.sni_len / 2;
                    size_t offsets[] = {middle, middle + 1400, 1, 0};
                    size_t lengths[] = {1400, whole_len - middle - 1400, middle - 1, 1};
                    for (size_t k = 0; k < r.n_out && k < 4; k++) {
                        const uint8_t *wire = buf + r.out[k].off;
                        size_t ihl = (wire[0] & 15u) * 4;
                        const uint8_t *tcp = wire + ihl;
                        size_t hdr = ihl + (tcp[12] >> 4) * 4;
                        uint8_t want_seq[4]; wr32(want_seq, 1001 + (uint32_t)offsets[k]);
                        CHECK(!memcmp(tcp + 4, want_seq, 4), "held disorder sequence differs");
                        CHECK(r.out[k].len == hdr + lengths[k] &&
                              !memcmp(wire + hdr, whole + offsets[k], lengths[k]),
                              "held disorder payload differs");
                        CHECK(r.out[k].delay_us == (k < 2 ? 0u : 12000u),
                              "held disorder timing differs");
                        d2k_session_sent(g, 8 + k, &r.key, r.execution_id);
                    }
                    size_t done = count_kind(g, D2K_JRN_PLAN_DONE);
                    CHECK(done == 0, "DONE before all originals acknowledged");
                    /* One logical acknowledgement, only AFTER both IDs. */
                    d2k_session_sent(g, 12, &r.key, r.execution_id);
                    CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == done + 1,
                          "group acknowledgement failed to finish Plan");

                    /* Change/delete the installed plan while waiting: release
                       unmodified originals, no synthetic application. */
                    pn = build_pkt(part, 47503, 0x02, NULL, 0);
                    d2k_session_packet(g, part, pn, 13, buf, sizeof buf, &r);
                    pn = build_pkt(part, 47503, 0x18, whole, 1448);
                    wr32(part + 24, 1001);
                    allow = d2k_session_hold_candidate(g, part, pn);
                    CHECK(allow, "second hold not enabled");
                    CHECK(d2k_hold_feed(h, 82, part, pn, 14, d2k_session_plan_revision(g),
                        allow, hold_release, g, &batch) == 1, "revision test not held");
                    d2k_session_set_plan(g, NULL);
                    d2k_hold_flush(h, 15, d2k_session_plan_revision(g), 0, hold_release, g);
                    CHECK(hold_released == 1 && d2k_hold_next(h) == 0,
                          "plan revision did not release originals");
                    CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == done + 1,
                          "rollback observation acknowledged a plan");
                    CHECK(!d2k_session_hold_candidate(g, part, pn),
                          "released head was eligible to hold again");
                    d2k_hold_free(h);
                }
                /* A probe plan never causes a different source port to be
                   held, even when SNI is still in a later segment. */
                CHECK(d2k_plan_load(strict_plan, sizeof strict_plan, &gp,
                                    err, sizeof err) == 0, "probe hold plan parse");
                CHECK(d2k_plantab_set_name_probe(d2k_session_plans(g), name,
                        sizeof name - 1, 30, gp, D2K_PLAN_SHAPE_LEGACY,
                        htons16(47504)) == 0, "probe hold plan install");
                gp = NULL;
                for (uint16_t port = 47504; port <= 47505; port++) {
                    pn = build_pkt(part, port, 0x02, NULL, 0);
                    d2k_session_packet(g, part, pn, 31, buf, sizeof buf, &r);
                    pn = build_pkt(part, port, 0x18, whole, 1);
                    wr32(part + 24, 1001);
                    CHECK(d2k_session_hold_candidate(g, part, pn) == (port == 47504),
                          "probe hold source-port isolation failed");
                }
            }
            d2k_plan_free(gp);
            d2k_session_free(g);
        }

        /* Reset between pieces: neither FIN nor SYN can join two incarnations. */
        const uint8_t reset_flags[] = {0x11, 0x14, 0x02};
        for (size_t j = 0; j < sizeof reset_flags; j++) {
            d2k_session *g = d2k_session_new(64, 64);
            CHECK(g != NULL, "reset capture session allocation");
            if (!g) { continue; }
            d2k_session_want_shape(g, name, sizeof name - 1, 6);
            size_t pn = build_pkt(part, 47000, 0x18, whole, 1448);
            d2k_session_packet(g, part, pn, 1, buf, sizeof buf, &r);
            pn = build_pkt(part, 47000, reset_flags[j], NULL, 0);
            d2k_session_packet(g, part, pn, 2, buf, sizeof buf, &r);
            pn = build_pkt(part, 47000, 0x18, whole + 1448, whole_len - 1448);
            wr32(part + 24, 2448);
            d2k_session_packet(g, part, pn, 3, buf, sizeof buf, &r);
            size_t got_len = 0;
            CHECK(d2k_session_shape(g, 6, &got_len) == NULL, "reset mixed captures");
            d2k_session_free(g);
        }
    }

    /* --- ПРОМАХ CONNTRACK (см. пояснение у nat_stub) --------------------- */
    {
        d2k_nat_fn saved = d2k_nat_hook;
        d2k_nat_hook = nat_stub;

        /* ГОНКА: первый ответ «нет», сразу следом «есть». План обязан
           примениться — запись существует, её просто не увидели с первого
           раза. Без перепроверки здесь теряется и клиент, и зонд. */
        {
            d2k_session *g = d2k_session_new(8, 4);
            d2k_plan *gp = NULL;
            CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0,
                  "план гонки не загрузился");
            d2k_session_set_plan(g, gp);
            nat_calls = 0;
            nat_miss_first_n = 1;
            size_t nn = build_pkt(pkt, 41100, 0x18, hello, hlen);
            d2k_result rr;
            d2k_session_packet(g, pkt, nn, 1000, buf, sizeof buf, &rr);
            CHECK(rr.skipped == NULL,
                  "промах conntrack принят с первого ответа — клиент и зонд остаются без обхода");
            CHECK(rr.n_out > 0, "план не исполнен, хотя запись conntrack существует");
            CHECK(nat_calls >= 2, "перепроверки не было вовсе");
            d2k_session_free(g);
        }

        /* ЗАПИСИ ДЕЙСТВИТЕЛЬНО НЕТ: сколько ни спрашивай, ответ один. План
           обязан быть отвергнут — иначе посылки уйдут с локальным адресом
           мимо NAT, и это ровно тот дефект, ради которого проверка заведена. */
        {
            d2k_session *g = d2k_session_new(8, 4);
            d2k_plan *gp = NULL;
            CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0,
                  "план отсутствия не загрузился");
            d2k_session_set_plan(g, gp);
            nat_calls = 0;
            nat_miss_first_n = 1000;
            size_t nn = build_pkt(pkt, 41200, 0x18, hello, hlen);
            d2k_result rr;
            d2k_session_packet(g, pkt, nn, 1000, buf, sizeof buf, &rr);
            CHECK(rr.skipped != NULL,
                  "план применён без записи conntrack — посылки уйдут мимо NAT");
            CHECK(rr.n_out == 0, "посылки собраны, хотя уйдут с локальным адресом");
            /* Перепроверка не должна превращаться в бесконечный опрос: цена
               каждой — чтение таблицы в сотни строк, и платит за неё пакетный
               путь. */
            CHECK(nat_calls <= 8, "перепроверок слишком много — цена каждой чтение всей таблицы");
            d2k_session_free(g);
        }

        d2k_nat_hook = saved;
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("сессия: все проверки прошли\n");
    return 0;
}
