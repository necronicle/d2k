/* wire.c — единственное место в датапате, где считаются контрольные суммы.
 *
 * Всё здесь пишется байт за байтом, без наложения структур на буфер: на MIPS
 * выравнивание не гарантировано, а приведение указателя к структуре заголовка
 * — классический способ получить неверное чтение там, где на x86 всё работало.
 *
 * Плавающей арифметики нет и быть не может: коробки идут без сопроцессора.
 */
#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include <string.h>
#include <stdlib.h>

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

/* TTL ФАЛЬШИВКИ ПО ИЗМЕРЕННОМУ ПУТИ (ip_autottl документации zapret2).
 *
 * Жёсткий TTL сам становится приметой: у донора ip_ttl=8 палился с роутера,
 * стоящего в 50 хопах от назначения. Здесь длина пути берётся из TTL ТОГО,
 * ЧТО ОТВЕЧАЛО по этому соединению: исходный TTL сервера угадывается по
 * ближайшему сверху обычному значению (64, 128, 255 — так ставят ОС), разность
 * даёт длину пути в хопах, к ней прибавляется delta и результат зажимается в
 * [min, max].
 *
 * Ноль возвращается, когда определить нельзя: ответа ещё не было (rev_ttl 0)
 * или значение бессмысленно. Вызывающий тогда берёт заданный ttl, а если и его
 * нет — не меняет TTL вовсе. Это дословно поведение документации.
 *
 * Арифметика целочисленная и со знаком только в пределах int: на коробках без
 * сопроцессора плавающей точки нет (см. шапку файла). */
static uint8_t auto_ttl(const d2k_emit *e, uint8_t rev_ttl) {
    static const int guesses[] = {64, 128, 255};
    if (!rev_ttl) { return 0; }
    int origin = 0;
    for (size_t i = 0; i < sizeof guesses / sizeof guesses[0]; i++) {
        if (rev_ttl <= guesses[i]) { origin = guesses[i]; break; }
    }
    if (!origin) { return 0; }
    int hops = origin - (int)rev_ttl;
    int ttl = hops + (int)e->autottl_delta;
    int lo = e->autottl_min, hi = e->autottl_max;
    if (hi && ttl > hi) { ttl = hi; }
    if (ttl < lo) { ttl = lo; }
    if (ttl < 1) { ttl = 1; }
    if (ttl > 255) { ttl = 255; }
    return (uint8_t)ttl;
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
    if (c->family != 0 && c->family != 4 && c->family != 6) { return 0; }
    if ((e->urgent && (!e->urgent_ptr || e->urgent_ptr > e->len)) ||
        (!e->urgent && e->urgent_ptr)) { return 0; }
    int ipv6 = c->family == 6;
    size_t ip_hdr = ipv6 ? 40u : IP_HDR;
    if (ipv6 && (e->poison & D2K_POISON_IPID_ZERO)) { return 0; }
    if (e->ipfrag || (e->wire_profile != 0 && e->wire_profile != D2K_WIRE_DETECT_TCP &&
                      e->wire_profile != D2K_WIRE_TCP_TEMPLATE)) { return 0; }
    int measured = e->wire_profile == D2K_WIRE_DETECT_TCP;
    /* MD5 и комбо MD5+метка синтезируют опции сами — только измеренный профиль
       detect-tcp-v1. На потоковом профиле tcp-template-v1 опции берутся из
       самого клиента, подделать их сборкой нельзя: отказ, а не тихая подмена
       (контекст клиента отсутствует). */
    if ((e->poison & (D2K_POISON_MD5 | D2K_POISON_MD5_TS)) && !measured) { return 0; }
    int native = e->wire_profile == D2K_WIRE_TCP_TEMPLATE;
    uint8_t native_options[40];
    size_t opt_len = (e->poison & D2K_POISON_MD5_TS) ? 28
        : (e->poison & D2K_POISON_MD5) ? 20
        : (e->poison & D2K_POISON_TCPTS_BACK) ? TS_OPT_LEN : 0;
    if (native) {
        opt_len = c->tcp_options_len;
        if (opt_len > sizeof native_options || opt_len % 4) return 0;
        memcpy(native_options, c->tcp_options, opt_len);
        int found_timestamp = 0;
        for (size_t off = 0; off < opt_len;) {
            uint8_t kind = native_options[off];
            if (kind == 0) break;
            if (kind == 1) { off++; continue; }
            if (off + 2 > opt_len || native_options[off + 1] < 2 ||
                native_options[off + 1] > opt_len - off) return 0;
            if (kind == 8) {
                if (native_options[off + 1] != 10 || found_timestamp) return 0;
                found_timestamp = 1;
                if (e->poison & D2K_POISON_TCPTS_BACK) {
                    const uint8_t *v = native_options + off + 2;
                    uint32_t ts = (uint32_t)v[0] << 24 | (uint32_t)v[1] << 16 |
                                  (uint32_t)v[2] << 8 | v[3];
                    wr32(native_options + off + 2, ts - 1000u);
                }
            }
            off += native_options[off + 1];
        }
        if ((e->poison & D2K_POISON_TCPTS_BACK) && !found_timestamp) return 0;
        /* МЕТКУ — ПЕРВОЙ (tcp_ts_up документации zapret2): linux отбрасывает
           пакет с валидным seq и невалидным ack только когда опция метки идёт
           первой, и nfqws1 случайно соблюдал это всегда. Переносим опцию
           целиком в начало, остальные сдвигаем вправо: длина опций не меняется,
           значит и заголовок остаётся того же размера, а сдвиг значения назад
           уже применён выше. Ищем заново, потому что смещение после правки
           значения то же, но код выше его не сохранял. */
        if (e->ts_up && found_timestamp) {
            uint8_t reordered[40];
            size_t at = opt_len;
            for (size_t off = 0; off + 1 < opt_len;) {
                uint8_t kind = native_options[off];
                if (kind == 0) { break; }
                if (kind == 1) { off++; continue; }
                if (kind == 8 && native_options[off + 1] == 10) { at = off; break; }
                off += native_options[off + 1];
            }
            if (at + 10 <= opt_len) {
                memcpy(reordered, native_options + at, 10);
                memcpy(reordered + 10, native_options, at);
                memcpy(reordered + 10 + at, native_options + at + 10,
                       opt_len - at - 10);
                memcpy(native_options, reordered, opt_len);
            }
        }
    }
    /* Комбо MD5+метка несёт РЕАЛЬНУЮ согласованную метку потока, а не
       синтетическую: ищем опцию 8/10 в опциях соединения (измеритель кладёт её
       из SYN-ACK — detect/raw.c; датапат — из опций клиента, session.c). Нет
       опции или она кривая — контекст отсутствует, явный отказ, а не подделка
       метки. MD5-одиночка (D2K_POISON_MD5) опций потока не читает и не
       меняется. */
    const uint8_t *md5ts_ts = NULL;
    if (e->poison & D2K_POISON_MD5_TS) {
        size_t off = 0;
        while (off + 1 < (size_t)c->tcp_options_len) {
            uint8_t kind = c->tcp_options[off];
            if (kind == 0) { break; }
            if (kind == 1) { off++; continue; }
            if (off + 2 > (size_t)c->tcp_options_len) { break; }
            uint8_t ol = c->tcp_options[off + 1];
            if (ol < 2 || off + ol > (size_t)c->tcp_options_len) { break; }
            if (kind == 8 && ol == 10) { md5ts_ts = c->tcp_options + off; break; }
            off += ol;
        }
        if (!md5ts_ts) { return 0; }
    }
    /* TTL по пути считается ОДИН раз на посылку: оба заголовка берут его. */
    uint8_t auto_hl = e->autottl ? auto_ttl(e, c->rev_ttl) : 0;
    if (e->pre_len > 65535u || e->len > 65535u - e->pre_len) { return 0; }
    const size_t body = e->pre_len + e->len;
    size_t total = ip_hdr + TCP_HDR + opt_len + body;
    if (total > cap || total > 0xffff) {
        return 0;
    }
    memset(out, 0, ip_hdr + TCP_HDR + opt_len);

    if (ipv6) {
        wr32(out, 0x60000000u | ((uint32_t)c->traffic_class << 20) | (c->flow_label & 0xfffffu));
        wr16(out + 4, (uint16_t)(total - 40));
        out[6] = 6;
        out[7] = auto_hl ? auto_hl
               : e->ttl ? e->ttl : (measured ? 64 : (c->ttl ? c->ttl : 64));
        memcpy(out + 8, c->src_ip6, 16);
        memcpy(out + 24, c->dst_ip6, 16);
    } else {
    /* --- IPv4 --- */
    out[0] = 0x45;                       /* версия 4, длина заголовка 5 слов */
    out[1] = 0;                          /* DSCP/ECN */
    wr16(out + 2, (uint16_t)total);
    /* Идентификатор: либо ноль по требованию порчи, либо чужой плюс единица.
       Совпадение идентификатора с оригиналом — известная ловушка: сборщик
       фрагментов на той стороне может счесть пакеты частями одной дейтаграммы. */
    wr16(out + 4, (e->poison & D2K_POISON_IPID_ZERO) ? 0
                      : measured ? (uint16_t)(random() % 65535)
                      : native ? c->ip_id : (uint16_t)(c->ip_id + 1));
    wr16(out + 6, measured ? 0 : 0x4000);
    /* TTL: если порча его задаёт, ставим её значение — пакет умрёт по дороге,
       не дойдя до сервера, но коробку пройдёт. */
    out[8] = auto_hl ? auto_hl
           : e->ttl ? e->ttl : (measured ? 64 : (c->ttl ? c->ttl : 64));
    out[9] = 6;                          /* TCP */
    wr16(out + 10, 0);                   /* сумма считается ниже */
    memcpy(out + 12, &c->src_ip, 4);
    memcpy(out + 16, &c->dst_ip, 4);
    wr16(out + 10, fold(sum16(out, IP_HDR, 0)));
    }

    /* --- TCP --- */
    uint8_t *t = out + ip_hdr;
    memcpy(t + 0, &c->src_port, 2);
    memcpy(t + 2, &c->dst_port, 2);
    /* Сдвиг номера последовательности — отдельный приём: сегмент уезжает за
       окно сервера и отбрасывается им, а коробка, окна не считающая, его
       берёт. */
    wr32(t + 4, e->seq + (uint32_t)e->seq_shift);
    wr32(t + 8, c->ack + (uint32_t)e->ack_shift);
    t[12] = (uint8_t)(((TCP_HDR + opt_len) / 4) << 4);
    t[13] = (uint8_t)(0x18 | (e->urgent ? 0x20 : 0)); /* PSH | ACK | URG? */
    wr16(t + 14, measured ? 65535 : c->window);
    wr16(t + 16, 0);                     /* сумма */
    wr16(t + 18, e->urgent ? e->urgent_ptr : 0);

    if (native && opt_len) {
        memcpy(t + TCP_HDR, native_options, opt_len);
    } else if (e->poison & D2K_POISON_MD5_TS) {
        /* nfqws1 tcp_md5_first + метка: MD5 (kind 19, len 18) ПЕРВОЙ, за ней
         * РЕАЛЬНАЯ метка потока (kind 8, len 10), скопированная дословно из
         * опций соединения (md5ts_ts найдена выше). 18+10 = 28, кратно
         * четырём, добивки NOP не нужно. 16 байт подписи MD5 намеренно нули,
         * как у MD5-одиночки: подделку бракует сервер по подписи, метка —
         * настоящая, как и просит донорская раскладка. */
        uint8_t *o = t + TCP_HDR;
        o[0] = 19; o[1] = 18;            /* MD5, далее 16 нулей */
        memcpy(o + 18, md5ts_ts, 10);    /* 08 0a + TSval + TSecr потока */
    } else if (e->poison & D2K_POISON_MD5) {
        /* raw.c: MD5 replaces timestamp/options, not an appended option.
         * Header was zeroed: the 16-byte signature is deliberately zero. */
        uint8_t *o = t + TCP_HDR;
        o[0] = 19; o[1] = 18; o[18] = 1; o[19] = 1;
    } else if (opt_len) {
        uint8_t *o = t + TCP_HDR;
        o[0] = 1; o[1] = 1;              /* NOP, NOP */
        o[2] = 8; o[3] = 10;             /* метка времени, длина 10 */
        /* Значение со сдвигом назад: сервер забракует такую метку как
           устаревшую, а коробка, метки не сверяющая, сегмент возьмёт. */
        wr32(o + 4, measured ? 1 : 0);
        wr32(o + 8, 0);
    }

    if (e->pre_len) {
        memcpy(out + ip_hdr + TCP_HDR + opt_len, e->pre, e->pre_len);
    }
    if (e->len) {
        memcpy(out + ip_hdr + TCP_HDR + opt_len + e->pre_len, e->bytes, e->len);
    }

    size_t tcp_len = TCP_HDR + opt_len + body;
    uint32_t acc = ipv6 ? sum16(out + 8, 32, (uint32_t)tcp_len + 6)
                        : pseudo_sum(out + 12, out + 16, tcp_len);
    acc = sum16(out + ip_hdr, tcp_len, acc);
    uint16_t ck = fold(acc);
    if (e->poison & D2K_POISON_BADSUM) {
        /* Measured mode reproduces detect/raw.c, including its zero case;
           legacy plans retain their historical inversion semantics. */
        if (measured) {
            ck ^= 0xbeef;
            if (ck == 0) { ck = 0x1234; }
        } else {
            ck = (uint16_t)~ck;
            if (ck == 0) { ck = 0xffff; }
        }
    }
    wr16(t + 16, ck);

    return total;
}

int d2k_wire_tcp_checksum_ok(const uint8_t *pkt, size_t len) {
    if (!pkt || len < IP_HDR + TCP_HDR) {
        return 0;
    }
    if ((pkt[0] >> 4) == 6) {
        if (len < 60 || pkt[6] != 6) { return 0; }
        size_t tcp_len = rd16(pkt + 4);
        if (tcp_len < TCP_HDR || tcp_len > len - 40) { return 0; }
        return fold(sum16(pkt + 40, tcp_len,
                    sum16(pkt + 8, 32, (uint32_t)tcp_len + 6))) == 0;
    }
    if ((pkt[0] >> 4) != 4 || pkt[9] != 6) { return 0; }
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
