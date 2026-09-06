/* test_wire_udp.c — сборка UDP-дейтаграммы на провод.
 *
 * Тот же принцип, что в test_wire.c: порча и сумма проверяются по
 * РЕЗУЛЬТАТУ (реальные биты собранного пакета), а не по факту «флаг
 * выставлен». Отдельно от этого — две ловушки, специфичные для UDP, которых
 * у TCP нет вовсе:
 *
 *   1. Проверяльщик здесь СОЗНАТЕЛЬНО не переиспользует внутренние функции
 *      wire_udp.c (там всё static). Он написан заново, по тексту RFC 1071 и
 *      RFC 768, и собирает псевдозаголовок в один буфер одним проходом, а не
 *      двумя вызовами, как сборщик. Если бы оба места считали одинаково
 *      неправильно — например, положили адрес в псевдозаголовок как число,
 *      а не как сырые байты, — тест бы с этим согласился. Ровно так уже
 *      ловили баг в TCP-сборщике 05-09 (см. wire.c) — сверкой со сторонней
 *      реализацией, а не проверкой самим собой.
 *   2. Эталоны golden_* даны байт в байт и получены НЕЗАВИСИМО, скриптом на
 *      Python, писавшимся по тексту стандартов, а не портированием этого C.
 *      Один из двух эталонов подобран так, что честный подсчёт суммы даёт
 *      ровно ноль, — именно тот случай, который на случайных данных
 *      проявляется примерно раз на 65536 дейтаграмм и потому сам себя в
 *      обычном прогоне не покажет.
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

/* Свёртка RFC 1071 «с нуля»: сумма 16-битных слов с переносом, дополнение до
 * единицы. Возвращает 1, если ПОСЛЕДНЕЕ слово (переданная сумма) верно —
 * то есть если досчитать весь блок целиком, включая уже записанную сумму,
 * результат обязан свернуться в все единицы. Написана независимо от
 * wire_udp.c: там подсчёт разбит на псевдозаголовок отдельно и остальное
 * отдельно, здесь — один проход по одному буферу. */
static int ones_complement_ok(const uint8_t *b, size_t n) {
    uint32_t acc = 0;
    size_t i = 0;
    for (; i + 1 < n; i += 2) {
        acc += (uint32_t)b[i] << 8 | b[i + 1];
    }
    if (i < n) {
        acc += (uint32_t)b[i] << 8;
    }
    while (acc >> 16) {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    return (uint16_t)~acc == 0;
}

/* Проверка суммы IP-заголовка: те же 20 байт, что и в TCP-варианте. */
static int verify_ip(const uint8_t *pkt) {
    return ones_complement_ok(pkt, 20);
}

/* Проверка суммы UDP: складывает псевдозаголовок (адреса из ЭТОГО ЖЕ
 * пакета, не из соединения) и весь UDP-сегмент как переданный. Собирается в
 * один буфер и проверяется одним вызовом — если бы сборщик забыл включить
 * псевдозаголовок в свой подсчёт, эта функция всё равно его вставит и
 * сумма разойдётся. */
static int verify_udp(const uint8_t *pkt, size_t total) {
    if (total < 20 + 8) {
        return 0;
    }
    size_t udp_len = total - 20;
    uint8_t scratch[12 + 65535];
    memcpy(scratch + 0, pkt + 12, 4);   /* src ip — из пакета */
    memcpy(scratch + 4, pkt + 16, 4);   /* dst ip — из пакета */
    scratch[8] = 0;
    scratch[9] = 17;                    /* UDP */
    scratch[10] = (uint8_t)(udp_len >> 8);
    scratch[11] = (uint8_t)udp_len;
    memcpy(scratch + 12, pkt + 20, udp_len);
    return ones_complement_ok(scratch, 12 + udp_len);
}

static void conn_init(d2k_conn *c) {
    memset(c, 0, sizeof *c);
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    memcpy(&c->src_ip, s, 4);
    memcpy(&c->dst_ip, d, 4);
    uint8_t sp[2] = {0x9c, 0x40}, dp[2] = {0x01, 0xbb}; /* 40000 -> 443 */
    memcpy(&c->src_port, sp, 2);
    memcpy(&c->dst_port, dp, 2);
    c->ttl = 64;
    c->ip_id = 0x1000;
}

/* Эталон: собран этим кодом и сверен с независимой Python-реализацией
 * RFC 1071/768 (сумма и псевдозаголовок написаны заново по тексту стандарта,
 * не портированием C). Обычный случай: сумма выходит ненулевой сама по
 * себе, подмена «ноль -> все единицы» здесь не участвует. */
static const uint8_t golden_clean[] = {
    0x45, 0x00, 0x00, 0x21, 0x10, 0x01, 0x40, 0x00, 0x40, 0x11, 0x64, 0xda,
    0xc0, 0xa8, 0x01, 0x43, 0x01, 0x02, 0x03, 0x04, 0x9c, 0x40, 0x01, 0xbb,
    0x00, 0x0d, 0xed, 0x49, 0xde, 0xad, 0xbe, 0xef, 0x11,
};

/* Эталон: та же независимая сверка, но нагрузка ПОДОБРАНА перебором так,
 * чтобы честная сумма (до подмены) оказалась ровно нулём. Поле суммы здесь
 * обязано быть 0xffff, а не 0x0000 — и то и другое одинаково «сходится» при
 * проверке (у нуля в дополнении до единицы два представления), поэтому
 * одной лишь verify_udp() эту ошибку не поймать: byte-in-byte сравнение с
 * эталоном — единственный способ отличить правильную подмену от забытой. */
static const uint8_t golden_zero_checksum[] = {
    0x45, 0x00, 0x00, 0x1e, 0x10, 0x01, 0x40, 0x00, 0x40, 0x11, 0x64, 0xdd,
    0xc0, 0xa8, 0x01, 0x43, 0x01, 0x02, 0x03, 0x04, 0x9c, 0x40, 0x01, 0xbb,
    0x00, 0x0a, 0xff, 0xff, 0x9b, 0xed,
};

static void check_golden_clean(void) {
    d2k_conn c;
    conn_init(&c);

    static const uint8_t body[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x11};
    d2k_emit e;
    memset(&e, 0, sizeof e);
    e.bytes = body;
    e.len = sizeof body;

    uint8_t pkt[256];
    size_t n = d2k_wire_build_udp(&c, &e, pkt, sizeof pkt);
    CHECK(n == sizeof golden_clean, "длина разошлась с эталоном (чистый случай)");
    if (n == sizeof golden_clean) {
        CHECK(memcmp(pkt, golden_clean, n) == 0,
              "дейтаграмма разошлась с эталоном побайтово (чистый случай)");
    }
}

static void check_golden_zero_checksum(void) {
    d2k_conn c;
    conn_init(&c);

    /* Подобрано перебором (см. шапку файла): при этих байтах честный подсчёт
       суммы даёт ровно 0x0000 ДО подмены. */
    static const uint8_t body[] = {0x9b, 0xed};
    d2k_emit e;
    memset(&e, 0, sizeof e);
    e.bytes = body;
    e.len = sizeof body;

    uint8_t pkt[256];
    size_t n = d2k_wire_build_udp(&c, &e, pkt, sizeof pkt);
    CHECK(n == sizeof golden_zero_checksum, "длина разошлась с эталоном (нулевая сумма)");
    if (n == sizeof golden_zero_checksum) {
        CHECK(memcmp(pkt, golden_zero_checksum, n) == 0,
              "дейтаграмма разошлась с эталоном побайтово (нулевая сумма)");
        CHECK(rd16(pkt + 20 + 6) == 0xffff,
              "ноль как результат подсчёта обязан кодироваться как все единицы");
    }
}

int main(void) {
    d2k_conn c;
    conn_init(&c);

    static const uint8_t body[] = {0xC0, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB};
    uint8_t pkt[256];

    /* --- чистая посылка: длина, поля, суммы ------------------------------ */
    d2k_emit e;
    memset(&e, 0, sizeof e);
    e.bytes = body;
    e.len = sizeof body;

    size_t n = d2k_wire_build_udp(&c, &e, pkt, sizeof pkt);
    CHECK(n == 20 + 8 + sizeof body, "длина дейтаграммы не равна заголовкам плюс нагрузка");
    CHECK((pkt[0] >> 4) == 4, "не IPv4");
    CHECK(rd16(pkt + 2) == n, "поле длины IP не совпало с фактической длиной");
    CHECK(pkt[8] == 64, "TTL не унаследован от соединения");
    CHECK(pkt[9] == 17, "протокол не UDP");
    CHECK(rd16(pkt + 20 + 0) == 0x9c40, "порт источника не тот");
    CHECK(rd16(pkt + 20 + 2) == 0x01bb, "порт получателя не тот");
    CHECK(rd16(pkt + 20 + 4) == 8 + sizeof body, "поле длины UDP не равно заголовку плюс нагрузке");
    CHECK(memcmp(pkt + 20 + 8, body, sizeof body) == 0, "полезная нагрузка не на месте");
    CHECK(verify_ip(pkt), "контрольная сумма IP неверна");
    CHECK(verify_udp(pkt, n), "контрольная сумма UDP неверна");

    /* --- сумма действительно покрывает псевдозаголовок -------------------- */
    {
        uint8_t tampered[256];
        memcpy(tampered, pkt, n);
        tampered[16] ^= 0xff; /* один байт IP получателя в копии пакета */
        CHECK(!verify_udp(tampered, n),
              "сумма не зависит от адреса получателя: псевдозаголовок не учтён");
    }

    /* --- малый TTL --------------------------------------------------------- */
    memset(&e, 0, sizeof e);
    e.bytes = body; e.len = sizeof body; e.ttl = 3;
    n = d2k_wire_build_udp(&c, &e, pkt, sizeof pkt);
    CHECK(pkt[8] == 3, "TTL порчи не доехал до заголовка IP");
    CHECK(verify_udp(pkt, n), "малый TTL не должен ломать сумму UDP");

    /* --- нулевой идентификатор IP ------------------------------------------ */
    memset(&e, 0, sizeof e);
    e.bytes = body; e.len = sizeof body;
    e.poison = D2K_POISON_IPID_ZERO;
    n = d2k_wire_build_udp(&c, &e, pkt, sizeof pkt);
    CHECK(rd16(pkt + 4) == 0, "идентификатор IP не обнулён");

    /* Без порчи идентификатор обязан отличаться от исходного — та же
       ловушка, что и у TCP: совпадение может склеить независимые
       дейтаграммы в один фрагментированный пакет на стороне получателя. */
    memset(&e, 0, sizeof e);
    e.bytes = body; e.len = sizeof body;
    n = d2k_wire_build_udp(&c, &e, pkt, sizeof pkt);
    CHECK(rd16(pkt + 4) != c.ip_id, "идентификатор совпал с исходным");

    /* --- приставка перекрытия для UDP смысла не имеет: отказ, не тишина --- */
    {
        d2k_emit e2;
        memset(&e2, 0, sizeof e2);
        const uint8_t pre[] = {0xAA, 0xBB};
        e2.pre = pre;
        e2.pre_len = sizeof pre;
        e2.bytes = body;
        e2.len = sizeof body;
        CHECK(d2k_wire_build_udp(&c, &e2, pkt, sizeof pkt) == 0,
              "приставка перекрытия обязана отвергаться, а не тихо игнорироваться");
    }

    /* --- сдвиг номера последовательности — тот же класс, что и приставка -- */
    {
        d2k_emit e2;
        memset(&e2, 0, sizeof e2);
        e2.bytes = body;
        e2.len = sizeof body;
        e2.seq_shift = -10000;
        CHECK(d2k_wire_build_udp(&c, &e2, pkt, sizeof pkt) == 0,
              "сдвиг seq обязан отвергаться для UDP, а не собираться как обычная дейтаграмма");
    }

    /* --- метка времени со сдвигом — опция TCP, у UDP опций нет: отказ ----- */
    {
        d2k_emit e2;
        memset(&e2, 0, sizeof e2);
        e2.bytes = body;
        e2.len = sizeof body;
        e2.poison = D2K_POISON_TCPTS_BACK;
        CHECK(d2k_wire_build_udp(&c, &e2, pkt, sizeof pkt) == 0,
              "метка времени TCP обязана отвергаться для UDP, а не тихо игнорироваться");
    }

    /* --- порченая сумма по требованию — эта сборка её не умеет: отказ ----- */
    {
        d2k_emit e2;
        memset(&e2, 0, sizeof e2);
        e2.bytes = body;
        e2.len = sizeof body;
        e2.poison = D2K_POISON_BADSUM;
        CHECK(d2k_wire_build_udp(&c, &e2, pkt, sizeof pkt) == 0,
              "порча суммы обязана отвергаться для UDP, а не собираться с честной суммой молча");
    }

    /* --- буфер не резиновый: проверка размера ДО записи ------------------- */
    memset(&e, 0, sizeof e);
    e.bytes = body; e.len = sizeof body;
    {
        size_t exact = 20 + 8 + sizeof body;
        CHECK(d2k_wire_build_udp(&c, &e, pkt, exact - 1) == 0,
              "сборка обязана отказать, если буфер меньше нужного ровно на байт");
        CHECK(d2k_wire_build_udp(&c, &e, pkt, exact) == exact,
              "сборка обязана пройти, если буфер ровно нужного размера");
    }
    CHECK(d2k_wire_build_udp(&c, &e, pkt, 10) == 0, "сборка в маленький буфер должна отказать");

    /* --- нагрузка нулевой длины: заголовок без данных тоже датаграмма ----- */
    {
        d2k_emit e2;
        memset(&e2, 0, sizeof e2);
        n = d2k_wire_build_udp(&c, &e2, pkt, sizeof pkt);
        CHECK(n == 20 + 8, "пустая нагрузка должна дать чистые заголовки без данных");
        CHECK(rd16(pkt + 20 + 4) == 8, "поле длины UDP для пустой нагрузки должно быть 8");
        CHECK(verify_udp(pkt, n), "сумма пустой дейтаграммы должна сходиться");
    }

    check_golden_clean();
    check_golden_zero_checksum();

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("провод UDP: все проверки прошли\n");
    return 0;
}
