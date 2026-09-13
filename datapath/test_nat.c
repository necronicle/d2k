/* test_nat.c — «каким адресом нас видит сервер», по настоящим строкам
 * conntrack, снятым с роутера Марка 13.09.2026.
 *
 * Строки взяты дословно из /proc/net/nf_conntrack живого Keenetic, а не
 * сочинены: набор расширений там свой (RTCACHE, nmark, slan, attrs), и разбор
 * обязан переживать именно его. Сочинённая строка проверяла бы сочинителя.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_nat.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    uint8_t v[4] = { a, b, c, d };
    uint32_t r;
    memcpy(&r, v, 4);
    return r;
}
static uint16_t port_be(uint16_t p) { return (uint16_t)((p >> 8) | (p << 8)); }

static const char *g_lines =
"ipv4     2 tcp      6 1194 ESTABLISHED src=192.168.1.117 dst=157.240.205.21 sport=50759 dport=443 packets=905 bytes=76261 src=157.240.205.21 dst=88.87.93.11 sport=443 dport=50759 packets=895 bytes=55144 [ASSURED] [RTCACHE o33/r37] mark=0 nmark=256 sc=0 ifw=37 ifl=33 mac=d6:62:df:88:c1:14 slan attrs= use=2\n"
"ipv4     2 udp      17 143 src=88.87.93.11 dst=157.240.205.35 sport=55732 dport=443 packets=23 bytes=2566 src=157.240.205.35 dst=88.87.93.11 sport=443 dport=55732 packets=9 bytes=5901 [ASSURED] [FASTNAT] mark=0 nmark=256 sc=0 nomac swan no_if attrs= use=2\n"
"ipv4     2 udp      17 29 src=192.168.1.90 dst=142.251.1.188 sport=49633 dport=443 packets=4 bytes=4800 src=142.251.1.188 dst=88.87.93.11 sport=443 dport=61001 packets=0 bytes=0 mark=0 nmark=256 sc=0 attrs= use=2\n"
"ipv4     2 icmp     1 29 type=8 code=0 id=1 src=10.1.30.5 dst=8.8.8.8 packets=1 bytes=84 src=8.8.8.8 dst=88.87.93.11 type=0 code=0 id=1 packets=1 bytes=84 mark=0 use=2\n";

int main(void) {
    char path[] = "/tmp/d2k-test-nat.XXXXXX";
    FILE *f = fopen("/tmp/d2k-test-nat.txt", "w");
    if (!f) { printf("ПРОВАЛ: не создать файл стенда\n"); return 1; }
    fputs(g_lines, f);
    fclose(f);
    snprintf(path, sizeof path, "%s", "/tmp/d2k-test-nat.txt");

    uint32_t src = 0;
    uint16_t sport = 0;

    /* 1. ТРАНЗИТНЫЙ поток: клиент за роутером, NAT переписал адрес и сохранил
       порт. Именно этот случай ломал обход у всех, кроме самого роутера. */
    CHECK(d2k_nat_outside(path, 6, ip4(192,168,1,117), port_be(50759),
                          ip4(157,240,205,21), port_be(443), &src, &sport) == 0,
          "транзитный TCP-поток не нашёлся");
    CHECK(src == ip4(88,87,93,11), "внешний адрес взят неверно");
    CHECK(sport == port_be(50759), "внешний порт взят неверно");

    /* 2. Поток САМОГО роутера: трансляции нет, наружу видно то же самое.
       Ответ обязан быть тем же, что на входе, — иначе подмена там, где её
       не просили. */
    CHECK(d2k_nat_outside(path, 17, ip4(88,87,93,11), port_be(55732),
                          ip4(157,240,205,35), port_be(443), &src, &sport) == 0,
          "локальный UDP-поток не нашёлся");
    CHECK(src == ip4(88,87,93,11) && sport == port_be(55732),
          "локальному потоку приписана трансляция");

    /* 3. NAT ПЕРЕПИСАЛ И ПОРТ. Так бывает при столкновении портов, и
       «взять адрес интерфейса, порт оставить» здесь дало бы чужой поток. */
    CHECK(d2k_nat_outside(path, 17, ip4(192,168,1,90), port_be(49633),
                          ip4(142,251,1,188), port_be(443), &src, &sport) == 0,
          "поток с переписанным портом не нашёлся");
    CHECK(src == ip4(88,87,93,11) && sport == port_be(61001),
          "переписанный порт не прочитан");

    /* 4. Потока нет в таблице — честный отказ, а не догадка. */
    CHECK(d2k_nat_outside(path, 6, ip4(192,168,1,200), port_be(1234),
                          ip4(1,2,3,4), port_be(443), &src, &sport) != 0,
          "несуществующий поток «нашёлся»");

    /* 5. Совпадение по адресам, но НЕ по порту — не наш поток. */
    CHECK(d2k_nat_outside(path, 6, ip4(192,168,1,117), port_be(50760),
                          ip4(157,240,205,21), port_be(443), &src, &sport) != 0,
          "чужой порт сошёл за наш поток");

    /* 6. Тот же кортеж, но другой транспорт: записи tcp и udp не должны
       путаться между собой. */
    CHECK(d2k_nat_outside(path, 17, ip4(192,168,1,117), port_be(50759),
                          ip4(157,240,205,21), port_be(443), &src, &sport) != 0,
          "TCP-запись отдана по запросу UDP");

    /* 7. ДВЕ ЗАПИСИ ОДНОГО КОРТЕЖА: клиент переиспользовал местный порт, а
     * старая запись ещё жива. Брать первую попавшуюся нельзя — у неё другой
     * внешний порт, и посылка уйдёт чужим потоком. Замер на роутере Марка
     * 13.09.2026: клиент ушёл с 60639, наша посылка — с 37741, сервер
     * ответил сбросом. Берём с наибольшим остатком жизни. */
    {
        FILE *g = fopen("/tmp/d2k-test-nat2.txt", "w");
        if (!g) { printf("ПРОВАЛ: не создать второй файл стенда\n"); return 1; }
        fputs("ipv4     2 tcp      6 11 CLOSE src=192.168.1.117 dst=157.240.205.35 sport=60639 dport=443 packets=4 bytes=872 src=157.240.205.35 dst=88.87.93.11 sport=443 dport=37741 packets=2 bytes=100 [ASSURED] mark=0 use=2\n", g);
        fputs("ipv4     2 tcp      6 1198 ESTABLISHED src=192.168.1.117 dst=157.240.205.35 sport=60639 dport=443 packets=3 bytes=500 src=157.240.205.35 dst=88.87.93.11 sport=443 dport=60639 packets=2 bytes=120 [ASSURED] mark=0 use=2\n", g);
        fclose(g);
        CHECK(d2k_nat_outside("/tmp/d2k-test-nat2.txt", 6, ip4(192,168,1,117),
                              port_be(60639), ip4(157,240,205,35), port_be(443),
                              &src, &sport) == 0,
              "живая запись не нашлась среди двух");
        CHECK(sport == port_be(60639),
              "взята закрывающаяся запись — посылка ушла бы чужим портом");
    }

    /* 8. Файла нет вовсе — отказ, а не падение. */
    CHECK(d2k_nat_outside("/tmp/нет-такого-файла-d2k", 6, ip4(1,1,1,1), port_be(1),
                          ip4(2,2,2,2), port_be(2), &src, &sport) != 0,
          "отсутствующий файл не обработан отказом");

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("трансляция NAT: все проверки прошли\n");
    return 0;
}
