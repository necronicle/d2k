/* wire.c — единственное место в датапате, где считаются контрольные суммы.
 *
 * Всё здесь пишется байт за байтом, без наложения структур на буфер: на MIPS
 * выравнивание не гарантировано, а приведение указателя к структуре заголовка
 * — классический способ получить неверное чтение там, где на x86 всё работало.
 *
 * Плавающей арифметики нет и быть не может: коробки идут без сопроцессора.
 */
#include <string.h>

#include "d2k_wire.h"

#define IP_HDR  20
#define TCP_HDR 20

/* Метка времени TCP: тип 8, длина 10, значение и эхо. Плюс два NOP для
 * выравнивания опций до четырёх байт. */
#define TS_OPT_LEN 12

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

/* Сумма по RFC 1071. Складывает 16-битные слова с переносом. */
static uint32_t sum16(const uint8_t *b, size_t n, uint32_t acc) {
    size_t i = 0;
    for (; i + 1 < n; i += 2) {
        acc += (uint32_t)b[i] << 8 | b[i + 1];
    }
    if (i < n) {
        acc += (uint32_t)b[i] << 8;
    }
    return acc;
}

static uint16_t fold(uint32_t acc) {
    while (acc >> 16) {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    return (uint16_t)~acc;
}

/* Псевдозаголовок TCP: адреса, протокол и длина сегмента.
 *
 * Адреса принимаются СЫРЫМИ БАЙТАМИ, а не числами, и это не придирка к стилю.
 * В структуре соединения они лежат в сетевом порядке; сложить их в число и
 * записать через wr32 значит перевернуть адрес на little-endian. Ошибка не
 * видна ничем, кроме независимой проверки: собственный проверяльщик сделал бы
 * ровно ту же подстановку и согласился бы сам с собой. Поймано 05-09 сверкой
 * со сторонней реализацией — до того, как хоть один пакет ушёл в сеть. */
static uint32_t pseudo_sum(const uint8_t *src4, const uint8_t *dst4, size_t tcp_len) {
    uint8_t ph[12];
    memcpy(ph + 0, src4, 4);
    memcpy(ph + 4, dst4, 4);
    ph[8] = 0;
    ph[9] = 6; /* TCP */
    wr16(ph + 10, (uint16_t)tcp_len);
    return sum16(ph, sizeof ph, 0);
}

size_t d2k_wire_build(const d2k_conn *c, const d2k_emit *e,
                      uint8_t *out, size_t cap) {
    if (!c || !e || !out) {
        return 0;
    }
    size_t opt_len = (e->poison & D2K_POISON_TCPTS_BACK) ? TS_OPT_LEN : 0;
    size_t total = IP_HDR + TCP_HDR + opt_len + e->len;
    if (total > cap || total > 0xffff) {
        return 0;
    }
    memset(out, 0, IP_HDR + TCP_HDR + opt_len);

    /* --- IPv4 --- */
    out[0] = 0x45;                       /* версия 4, длина заголовка 5 слов */
    out[1] = 0;                          /* DSCP/ECN */
    wr16(out + 2, (uint16_t)total);
    /* Идентификатор: либо ноль по требованию порчи, либо чужой плюс единица.
       Совпадение идентификатора с оригиналом — известная ловушка: сборщик
       фрагментов на той стороне может счесть пакеты частями одной дейтаграммы. */
    wr16(out + 4, (e->poison & D2K_POISON_IPID_ZERO) ? 0
                                                     : (uint16_t)(c->ip_id + 1));
    wr16(out + 6, 0x4000);               /* не фрагментировать */
    /* TTL: если порча его задаёт, ставим её значение — пакет умрёт по дороге,
       не дойдя до сервера, но коробку пройдёт. */
    out[8] = e->ttl ? e->ttl : (c->ttl ? c->ttl : 64);
    out[9] = 6;                          /* TCP */
    wr16(out + 10, 0);                   /* сумма считается ниже */
    memcpy(out + 12, &c->src_ip, 4);
    memcpy(out + 16, &c->dst_ip, 4);
    wr16(out + 10, fold(sum16(out, IP_HDR, 0)));

    /* --- TCP --- */
    uint8_t *t = out + IP_HDR;
    memcpy(t + 0, &c->src_port, 2);
    memcpy(t + 2, &c->dst_port, 2);
    /* Сдвиг номера последовательности — отдельный приём: сегмент уезжает за
       окно сервера и отбрасывается им, а коробка, окна не считающая, его
       берёт. */
    wr32(t + 4, e->seq + (uint32_t)e->seq_shift);
    wr32(t + 8, c->ack);
    t[12] = (uint8_t)(((TCP_HDR + opt_len) / 4) << 4);
    t[13] = 0x18;                        /* PSH | ACK */
    wr16(t + 14, c->window);
    wr16(t + 16, 0);                     /* сумма */
    wr16(t + 18, 0);                     /* указатель срочных данных */

    if (opt_len) {
        uint8_t *o = t + TCP_HDR;
        o[0] = 1; o[1] = 1;              /* NOP, NOP */
        o[2] = 8; o[3] = 10;             /* метка времени, длина 10 */
        /* Значение со сдвигом назад: сервер забракует такую метку как
           устаревшую, а коробка, метки не сверяющая, сегмент возьмёт. */
        wr32(o + 4, 0);
        wr32(o + 8, 0);
    }

    if (e->len) {
        memcpy(out + IP_HDR + TCP_HDR + opt_len, e->bytes, e->len);
    }

    size_t tcp_len = TCP_HDR + opt_len + e->len;
    uint32_t acc = pseudo_sum(out + 12, out + 16, tcp_len);
    acc = sum16(out + IP_HDR, tcp_len, acc);
    uint16_t ck = fold(acc);
    if (e->poison & D2K_POISON_BADSUM) {
        /* Портим предсказуемо, а не случайно: эталонные файлы обязаны
           сходиться от прогона к прогону. Инверсия гарантированно даёт
           неверную сумму и никогда не совпадёт с правильной. */
        ck = (uint16_t)~ck;
        if (ck == 0) {
            ck = 0xffff;
        }
    }
    wr16(t + 16, ck);

    return total;
}

int d2k_wire_tcp_checksum_ok(const uint8_t *pkt, size_t len) {
    if (!pkt || len < IP_HDR + TCP_HDR) {
        return 0;
    }
    size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
    if (ihl < IP_HDR || len < ihl + TCP_HDR) {
        return 0;
    }
    size_t total = rd16(pkt + 2);
    if (total > len || total < ihl) {
        return 0;
    }
    size_t tcp_len = total - ihl;

    uint32_t acc = pseudo_sum(pkt + 12, pkt + 16, tcp_len);
    acc = sum16(pkt + ihl, tcp_len, acc);
    /* Сумма верна, если свёртка всего сегмента вместе с уже записанной суммой
       даёт ноль. */
    return fold(acc) == 0;
}
