/* test_wire.c — сборка пакета на провод.
 *
 * Порча проверяется не тем, что «флаг выставлен», а тем, что получившийся
 * пакет ДЕЙСТВИТЕЛЬНО таков: сумма неверна, TTL мал, идентификатор нулевой.
 * Проверять флаг значило бы проверять собственное намерение, а не результат.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_wire.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}


/* Эталонный чистый пакет, собранный этим кодом и СВЕРЕННЫЙ СТОРОННЕЙ
 * реализацией контрольных сумм. Лежит здесь именно потому, что собственный
 * проверяльщик однажды уже согласился с собственным сборщиком, когда оба
 * ошибались одинаково: адреса клались в псевдозаголовок как числа, а лежат они
 * в сетевом порядке, и на little-endian это переворачивало адрес. Сумма была
 * неверна у всех пакетов, включая чистые, и на проводе это означало бы, что
 * фальшивку выбрасывают и коробка, и сервер.
 *
 * Эталон ловит возврат этой ошибки без всякого внешнего инструмента.
 */
static const uint8_t golden_clean[] = {
    0x45, 0x00, 0x00, 0x2d, 0x10, 0x01, 0x40, 0x00, 0x40, 0x06, 0x64, 0xd9,
    0xc0, 0xa8, 0x01, 0x43, 0x01, 0x02, 0x03, 0x04, 0x9c, 0x40, 0x01, 0xbb,
    0x00, 0x00, 0x03, 0xe8, 0x11, 0x22, 0x33, 0x44, 0x50, 0x18, 0xfa, 0xf0,
    0x59, 0xfe, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x11,
};

static void check_golden(void) {
    d2k_conn c;
    memset(&c, 0, sizeof c);
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    memcpy(&c.src_ip, s, 4);
    memcpy(&c.dst_ip, d, 4);
    uint8_t sp[2] = {0x9c, 0x40}, dp[2] = {0x01, 0xbb};
    memcpy(&c.src_port, sp, 2);
    memcpy(&c.dst_port, dp, 2);
    c.ack = 0x11223344;
    c.window = 64240;
    c.ttl = 64;
    c.ip_id = 0x1000;

    static const uint8_t body[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x11};
    d2k_emit e;
    memset(&e, 0, sizeof e);
    e.seq = 1000;
    e.bytes = body;
    e.len = sizeof body;

    uint8_t pkt[256];
    size_t n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(n == sizeof golden_clean, "длина разошлась с эталоном");
    if (n == sizeof golden_clean) {
        CHECK(memcmp(pkt, golden_clean, n) == 0, "пакет разошёлся с эталоном побайтово");
    }
}

int main(void) {
    d2k_conn c;
    memset(&c, 0, sizeof c);
    /* 192.168.1.67 -> 1.2.3.4, порты 40000 -> 443 */
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    memcpy(&c.src_ip, s, 4);
    memcpy(&c.dst_ip, d, 4);
    uint8_t sp[2] = {0x9c, 0x40}, dp[2] = {0x01, 0xbb};
    memcpy(&c.src_port, sp, 2);
    memcpy(&c.dst_port, dp, 2);
    c.ack = 0x11223344;
    c.window = 64240;
    c.ttl = 64;
    c.ip_id = 0x1000;

    static const uint8_t body[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x11};
    uint8_t pkt[256];

    /* --- чистая посылка ------------------------------------------------- */
    d2k_emit e;
    memset(&e, 0, sizeof e);
    e.seq = 1000;
    e.bytes = body;
    e.len = sizeof body;

    size_t n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(n == 20 + 20 + sizeof body, "длина чистого пакета неверна");
    CHECK((pkt[0] >> 4) == 4, "не IPv4");
    CHECK(rd16(pkt + 2) == n, "поле длины не совпало с фактической");
    CHECK(pkt[8] == 64, "TTL не унаследован от соединения");
    CHECK(pkt[9] == 6, "протокол не TCP");
    CHECK(rd32(pkt + 20 + 4) == 1000, "номер последовательности не тот");
    CHECK(memcmp(pkt + 40, body, sizeof body) == 0, "полезная нагрузка не на месте");
    CHECK(d2k_wire_tcp_checksum_ok(pkt, n), "контрольная сумма чистого пакета неверна");

    /* Сумма IP тоже обязана сходиться: свёртка заголовка даёт ноль. */
    {
        uint32_t acc = 0;
        for (size_t i = 0; i < 20; i += 2) {
            acc += rd16(pkt + i);
        }
        while (acc >> 16) {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        CHECK((uint16_t)~acc == 0, "контрольная сумма IP неверна");
    }

    /* --- испорченная сумма ---------------------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000;
    e.bytes = body;
    e.len = sizeof body;
    e.poison = D2K_POISON_BADSUM;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(n > 0, "пакет с испорченной суммой не собрался");
    CHECK(!d2k_wire_tcp_checksum_ok(pkt, n),
          "сумма обязана быть неверной: сервер должен выбросить фальшивку");

    /* Испорченная сумма обязана быть ПРЕДСКАЗУЕМОЙ: эталоны иначе не сойдутся
       от прогона к прогону. */
    {
        uint8_t again[256];
        size_t m = d2k_wire_build(&c, &e, again, sizeof again);
        CHECK(m == n && memcmp(pkt, again, n) == 0,
              "порча суммы не воспроизводима — эталон не сойдётся");
    }

    /* --- малый TTL ------------------------------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body; e.ttl = 3;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(pkt[8] == 3, "TTL порчи не доехал до заголовка");
    CHECK(d2k_wire_tcp_checksum_ok(pkt, n), "TTL не должен ломать сумму TCP");

    /* --- нулевой идентификатор ------------------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body;
    e.poison = D2K_POISON_IPID_ZERO;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(rd16(pkt + 4) == 0, "идентификатор IP не обнулён");

    /* Без порчи идентификатор обязан ОТЛИЧАТЬСЯ от исходного: совпадение —
       известная ловушка, сборщик фрагментов на той стороне может счесть
       пакеты частями одной дейтаграммы. */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(rd16(pkt + 4) != c.ip_id, "идентификатор совпал с исходным");

    /* --- сдвиг номера последовательности --------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body; e.seq_shift = -10000;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(rd32(pkt + 20 + 4) == (uint32_t)(1000 - 10000), "сдвиг seq не применён");
    CHECK(d2k_wire_tcp_checksum_ok(pkt, n), "сдвиг seq не должен ломать сумму");

    /* --- метка времени со сдвигом ---------------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body;
    e.poison = D2K_POISON_TCPTS_BACK;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK((pkt[20 + 12] >> 4) == 8, "длина заголовка TCP не выросла под опцию");
    CHECK(pkt[20 + 20 + 2] == 8 && pkt[20 + 20 + 3] == 10, "опция метки времени не та");
    CHECK(d2k_wire_tcp_checksum_ok(pkt, n), "опции не должны ломать сумму");
    CHECK(memcmp(pkt + 20 + 20 + 12, body, sizeof body) == 0,
          "нагрузка сместилась не туда при наличии опций");

    /* --- буфер не резиновый ----------------------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body;
    CHECK(d2k_wire_build(&c, &e, pkt, 10) == 0, "сборка в маленький буфер должна отказать");

    check_golden();

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("провод: все проверки прошли\n");
    return 0;
}
