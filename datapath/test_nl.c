/* test_nl.c — разбор и сборка netlink.
 *
 * Проверок на кривой вход здесь больше, чем на правильный, и это соотношение
 * намеренное: правильные сообщения приходят от ядра и потому почти всегда
 * правильные, а стоимость ошибки на кривом — чтение за буфером в процессе,
 * который видит весь трафик роутера.
 *
 * Отдельно закреплён случай, на котором C-версия замерщика упала на первом же
 * пакете: последний атрибут без выравнивающего хвоста.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_nl.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static int little_endian(void) {
    uint16_t v = 1;
    uint8_t b[2];
    memcpy(b, &v, 2);
    return b[0] == 1;
}

static void dump(const char *tag, const uint8_t *p, size_t n) {
    printf("  %s:", tag);
    for (size_t i = 0; i < n; i++) {
        printf(" %02x", p[i]);
    }
    printf("\n");
}

/* --- вспомогательная сборка сообщения ЯДРА (то, что мы только читаем) ----- */

static void wh16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void wh32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void wn16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wn32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* Кладёт атрибут БЕЗ выравнивающего хвоста, если pad == 0. Именно так и
   выглядит хвост настоящего сообщения. */
static size_t put(uint8_t *o, size_t pos, uint16_t type,
                  const uint8_t *val, size_t vlen, int pad) {
    size_t alen = 4 + vlen;
    wh16(o + pos, (uint16_t)alen);
    wh16(o + pos + 2, type);
    if (vlen) {
        memcpy(o + pos + 4, val, vlen);
    }
    size_t step = pad ? ((alen + 3) & ~(size_t)3) : alen;
    for (size_t i = alen; i < step; i++) {
        o[pos + i] = 0;
    }
    return pos + step;
}

int main(void) {
    /* ================= сборка ============================================ */

    /* --- вердикт: длина, раскладка и сетевые поля ------------------------ */
    {
        uint8_t o[64];
        size_t n = d2k_nl_verdict(o, sizeof o, 1, 7, 0x11223344u, D2K_NF_ACCEPT);
        CHECK(n == 32, "длина вердикта не 32 байта");

        /* Эталон для little-endian. Обе целевые арки v1 (aarch64 и mipsel)
           little-endian; на big-endian сравнение пропускается, потому что поля
           ЗАГОЛОВКОВ netlink идут в порядке хозяина — это не ошибка формата. */
        static const uint8_t want[32] = {
            0x20, 0x00, 0x00, 0x00,   /* nlmsg_len = 32 */
            0x01, 0x03,               /* type = (SUBSYS_QUEUE<<8)|VERDICT */
            0x01, 0x00,               /* flags = NLM_F_REQUEST */
            0x07, 0x00, 0x00, 0x00,   /* seq */
            0x00, 0x00, 0x00, 0x00,   /* pid */
            0x00, 0x00,               /* family=AF_UNSPEC, version=0 */
            0x00, 0x01,               /* res_id = очередь 1, сетевой порядок */
            0x0c, 0x00,               /* nla_len = 12 */
            0x02, 0x00,               /* nla_type = NFQA_VERDICT_HDR */
            0x00, 0x00, 0x00, 0x01,   /* verdict = NF_ACCEPT, сетевой */
            0x11, 0x22, 0x33, 0x44    /* id, сетевой */
        };
        if (little_endian()) {
            if (n != 32 || memcmp(o, want, 32) != 0) {
                printf("ПРОВАЛ: байты вердикта разошлись с эталоном\n");
                dump("получено", o, n < 32 ? n : 32);
                dump("ожидалось", want, 32);
                fails++;
            }
        } else {
            printf("  (big-endian: побайтовый эталон вердикта пропущен)\n");
        }

        /* Сетевые поля обязаны совпадать на любой арке. */
        CHECK(o[18] == 0x00 && o[19] == 0x01, "res_id не в сетевом порядке");
        CHECK(o[24] == 0 && o[27] == 1, "вердикт не в сетевом порядке");
        CHECK(o[28] == 0x11 && o[31] == 0x44, "id пакета не в сетевом порядке");

        CHECK(d2k_nl_verdict(o, 31, 1, 7, 1, D2K_NF_ACCEPT) == 0,
              "вердикт слепился в буфер, куда не влезает");
    }

    /* --- команда настройки ------------------------------------------------ */
    {
        uint8_t o[64];
        size_t n = d2k_nl_cfg_cmd(o, sizeof o, 1, 3, D2K_NFQNL_CFG_CMD_BIND, 2);
        CHECK(n == 28, "длина команды настройки не 28 байт");
        static const uint8_t want[28] = {
            0x1c, 0x00, 0x00, 0x00,
            0x02, 0x03,               /* type = CONFIG */
            0x05, 0x00,               /* flags = REQUEST|ACK */
            0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
            0x08, 0x00, 0x01, 0x00,   /* nla_len=8, type=NFQA_CFG_CMD */
            0x01, 0x00, 0x00, 0x02    /* cmd=BIND, pad, pf=AF_INET сетевой */
        };
        if (little_endian() && (n != 28 || memcmp(o, want, 28) != 0)) {
            printf("ПРОВАЛ: байты команды настройки разошлись с эталоном\n");
            dump("получено", o, n < 28 ? n : 28);
            dump("ожидалось", want, 28);
            fails++;
        }
        CHECK((o[6] & D2K_NLM_F_ACK) != 0,
              "настройка идёт без NLM_F_ACK — отказ ядра будет неотличим от успеха");
    }

    /* --- параметры очереди: атрибут из 9 байт выравнивается до 12 --------- */
    {
        uint8_t o[128];
        size_t n = d2k_nl_cfg_params(o, sizeof o, 1, 4, 0xFFFF,
                                     D2K_NFQNL_COPY_PACKET, 1024,
                                     D2K_NFQA_CFG_F_FAIL_OPEN,
                                     D2K_NFQA_CFG_F_FAIL_OPEN | D2K_NFQA_CFG_F_GSO);
        CHECK(n == 16 + 4 + 12 + 8 + 8 + 8, "длина параметров очереди неверна");
        /* PARAMS начинается на 20-м байте: len=9, тип=2, copy_range, copy_mode */
        CHECK(o[20] == 9 && o[21] == 0, "nla_len параметров не 9");
        CHECK(o[24] == 0 && o[25] == 0 && o[26] == 0xFF && o[27] == 0xFF,
              "copy_range не в сетевом порядке");
        CHECK(o[28] == D2K_NFQNL_COPY_PACKET, "copy_mode не на своём месте");
        CHECK(o[29] == 0 && o[30] == 0 && o[31] == 0,
              "хвост выравнивания не обнулён: наружу уходит чужая память");

        CHECK(d2k_nl_cfg_params(o, 40, 1, 4, 0xFFFF, D2K_NFQNL_COPY_PACKET,
                                1024, 1, 1) == 0,
              "параметры слепились в тесный буфер");
    }

    /* ================= разбор ============================================ */

    /* --- обычный пакет из очереди ---------------------------------------- */
    {
        uint8_t buf[256];
        memset(buf, 0, sizeof buf);
        size_t pos = 16;
        buf[16] = 2;                      /* AF_INET */
        buf[17] = 0;
        wn16(buf + 18, 1);
        pos = 20;

        uint8_t ph[7];
        wn32(ph, 0xDEADBEEFu);
        wn16(ph + 4, 0x0800);
        ph[6] = 3;                        /* NF_INET_FORWARD */
        pos = put(buf, pos, D2K_NFQA_PACKET_HDR, ph, sizeof ph, 1);

        uint8_t mark[4];
        wn32(mark, 0x1234);
        pos = put(buf, pos, D2K_NFQA_MARK, mark, sizeof mark, 1);

        uint8_t pay[40];
        for (size_t i = 0; i < sizeof pay; i++) {
            pay[i] = (uint8_t)i;
        }
        pos = put(buf, pos, D2K_NFQA_PAYLOAD, pay, sizeof pay, 1);

        wh32(buf, (uint32_t)pos);
        wh16(buf + 4, D2K_NFQ_TYPE(D2K_NFQNL_MSG_PACKET));

        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_iter_init(&it, buf, pos);
        CHECK(d2k_nl_next(&it, &m) == 1, "сообщение не разобралось");
        CHECK(m.type == D2K_NFQ_TYPE(D2K_NFQNL_MSG_PACKET), "тип сообщения не тот");

        d2k_nl_pkt p;
        CHECK(d2k_nl_packet(&m, &p) == 0, "пакет не разобрался");
        CHECK(p.have_hdr && p.id == 0xDEADBEEFu, "id пакета потерян");
        CHECK(p.hw_protocol == 0x0800, "hw_protocol потерян");
        CHECK(p.hook == 3, "hook потерян");
        CHECK(p.have_mark && p.mark == 0x1234, "метка потеряна");
        CHECK(p.have_payload && p.payload_len == 40, "нагрузка потеряна");
        CHECK(p.payload && p.payload[0] == 0 && p.payload[39] == 39,
              "содержимое нагрузки не то");
        CHECK(!p.truncated, "целый пакет объявлен обрезанным");
        CHECK(d2k_nl_next(&it, &m) == 0, "итератор нашёл лишнее сообщение");
    }

    /* --- последний атрибут без выравнивающего хвоста ----------------------
     * Ровно этот случай уронил C-версию замерщика 2026-09-05: NLA_ALIGN(95)=96
     * при 95 оставшихся байтах, беззнаковое вычитание уходит в минус.        */
    {
        uint8_t buf[256];
        memset(buf, 0, sizeof buf);
        buf[16] = 2;
        wn16(buf + 18, 1);
        size_t pos = 20;

        uint8_t ph[7];
        wn32(ph, 42);
        wn16(ph + 4, 0x0800);
        ph[6] = 3;
        pos = put(buf, pos, D2K_NFQA_PACKET_HDR, ph, sizeof ph, 1);

        uint8_t pay[91];
        memset(pay, 0xA5, sizeof pay);
        pos = put(buf, pos, D2K_NFQA_PAYLOAD, pay, sizeof pay, 0);  /* без хвоста */

        wh32(buf, (uint32_t)pos);
        wh16(buf + 4, D2K_NFQ_TYPE(D2K_NFQNL_MSG_PACKET));

        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_pkt p;
        d2k_nl_iter_init(&it, buf, pos);   /* буфер РОВНО по длине сообщения */
        CHECK(d2k_nl_next(&it, &m) == 1, "невыровненный хвост: сообщение не взято");
        CHECK(d2k_nl_packet(&m, &p) == 0, "невыровненный хвост: разбор провалился");
        CHECK(p.have_payload && p.payload_len == 91,
              "невыровненный хвост: нагрузка потеряна");
        CHECK(p.payload && p.payload[90] == 0xA5, "невыровненный хвост: данные не те");
        CHECK(d2k_nl_next(&it, &m) == 0, "невыровненный хвост: итератор пошёл дальше");
    }

    /* --- обрезанный пакет: cap_len больше нагрузки ------------------------ */
    {
        uint8_t buf[256];
        memset(buf, 0, sizeof buf);
        buf[16] = 2;
        wn16(buf + 18, 1);
        size_t pos = 20;
        uint8_t ph[7];
        wn32(ph, 1);
        wn16(ph + 4, 0x0800);
        ph[6] = 3;
        pos = put(buf, pos, D2K_NFQA_PACKET_HDR, ph, sizeof ph, 1);
        uint8_t pay[64];
        memset(pay, 0, sizeof pay);
        pos = put(buf, pos, D2K_NFQA_PAYLOAD, pay, sizeof pay, 1);
        uint8_t cl[4];
        wn32(cl, 1400);
        pos = put(buf, pos, D2K_NFQA_CAP_LEN, cl, sizeof cl, 1);
        wh32(buf, (uint32_t)pos);
        wh16(buf + 4, D2K_NFQ_TYPE(D2K_NFQNL_MSG_PACKET));

        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_pkt p;
        d2k_nl_iter_init(&it, buf, pos);
        CHECK(d2k_nl_next(&it, &m) == 1, "обрезанный: сообщение не взято");
        CHECK(d2k_nl_packet(&m, &p) == 0, "обрезанный: разбор провалился");
        CHECK(p.cap_len == 1400 && p.payload_len == 64, "обрезанный: длины не те");
        CHECK(p.truncated, "обрезанный пакет не помечен обрезанным");
    }

    /* --- врущая длина сообщения ------------------------------------------- */
    {
        uint8_t buf[64];
        memset(buf, 0, sizeof buf);
        wh32(buf, 1000);                  /* объявляем больше, чем есть */
        wh16(buf + 4, D2K_NFQ_TYPE(D2K_NFQNL_MSG_PACKET));
        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_iter_init(&it, buf, sizeof buf);
        CHECK(d2k_nl_next(&it, &m) == 0, "сообщение с врущей длиной принято");
    }

    /* --- длина сообщения меньше заголовка --------------------------------- */
    {
        uint8_t buf[64];
        memset(buf, 0, sizeof buf);
        wh32(buf, 8);
        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_iter_init(&it, buf, sizeof buf);
        CHECK(d2k_nl_next(&it, &m) == 0, "сообщение короче заголовка принято");
    }

    /* --- врущая длина атрибута -------------------------------------------- */
    {
        uint8_t buf[64];
        memset(buf, 0, sizeof buf);
        buf[16] = 2;
        wn16(buf + 18, 1);
        wh16(buf + 20, 500);              /* nla_len больше тела */
        wh16(buf + 22, D2K_NFQA_PAYLOAD);
        wh32(buf, 40);
        wh16(buf + 4, D2K_NFQ_TYPE(D2K_NFQNL_MSG_PACKET));

        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_pkt p;
        d2k_nl_iter_init(&it, buf, 40);
        CHECK(d2k_nl_next(&it, &m) == 1, "сообщение с кривым атрибутом не взято");
        CHECK(d2k_nl_packet(&m, &p) == 0, "разбор упал на кривом атрибуте");
        CHECK(!p.have_payload, "нагрузка взята из атрибута с врущей длиной");
        CHECK(!p.have_hdr, "заголовок взялся из ниоткуда");
    }

    /* --- нулевая длина атрибута: цикл обязан кончиться --------------------- */
    {
        uint8_t buf[64];
        memset(buf, 0, sizeof buf);
        buf[16] = 2;
        wn16(buf + 18, 1);
        wh16(buf + 20, 0);                /* nla_len = 0 — бесконечный цикл? */
        wh16(buf + 22, D2K_NFQA_PAYLOAD);
        wh32(buf, 40);
        wh16(buf + 4, D2K_NFQ_TYPE(D2K_NFQNL_MSG_PACKET));
        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_pkt p;
        d2k_nl_iter_init(&it, buf, 40);
        CHECK(d2k_nl_next(&it, &m) == 1, "сообщение с нулевым атрибутом не взято");
        CHECK(d2k_nl_packet(&m, &p) == 0, "разбор нулевого атрибута провалился");
        CHECK(!p.have_payload, "из нулевого атрибута что-то извлеклось");
    }

    /* --- тело короче nfgenmsg --------------------------------------------- */
    {
        uint8_t buf[32];
        memset(buf, 0, sizeof buf);
        wh32(buf, 18);                    /* 16 заголовка + 2 тела */
        wh16(buf + 4, D2K_NFQ_TYPE(D2K_NFQNL_MSG_PACKET));
        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_pkt p;
        d2k_nl_iter_init(&it, buf, 18);
        CHECK(d2k_nl_next(&it, &m) == 1, "короткое тело: сообщение не взято");
        CHECK(d2k_nl_packet(&m, &p) == -1, "тело короче nfgenmsg принято за пакет");
    }

    /* --- ошибка от ядра --------------------------------------------------- */
    {
        uint8_t buf[64];
        memset(buf, 0, sizeof buf);
        wh32(buf, 36);
        wh16(buf + 4, D2K_NLMSG_ERROR);
        int32_t e = -22;                  /* -EINVAL */
        memcpy(buf + 16, &e, 4);

        d2k_nl_iter it;
        d2k_nl_msg m;
        int32_t got = 0;
        d2k_nl_iter_init(&it, buf, 36);
        CHECK(d2k_nl_next(&it, &m) == 1, "ошибка ядра не разобралась как сообщение");
        CHECK(d2k_nl_errno(&m, &got) == 0, "NLMSG_ERROR не распознан");
        CHECK(got == -22, "код ошибки ядра потерян");

        /* Подтверждение на NLM_F_ACK приходит тем же типом с нулём. */
        memset(buf + 16, 0, 4);
        d2k_nl_iter_init(&it, buf, 36);
        d2k_nl_next(&it, &m);
        CHECK(d2k_nl_errno(&m, &got) == 0 && got == 0,
              "подтверждение ACK не распознано");
    }

    /* --- несколько сообщений в одном буфере -------------------------------- */
    {
        uint8_t buf[128];
        memset(buf, 0, sizeof buf);
        wh32(buf, 20);
        wh16(buf + 4, D2K_NFQ_TYPE(D2K_NFQNL_MSG_PACKET));
        wh32(buf + 20, 24);
        wh16(buf + 24, D2K_NLMSG_ERROR);
        int32_t e = -1;
        memcpy(buf + 36, &e, 4);

        d2k_nl_iter it;
        d2k_nl_msg m;
        int n = 0;
        d2k_nl_iter_init(&it, buf, 44);
        while (d2k_nl_next(&it, &m)) {
            n++;
        }
        CHECK(n == 2, "из буфера с двумя сообщениями взялось не два");
    }

    /* --- пустой и нулевой вход --------------------------------------------- */
    {
        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_iter_init(&it, NULL, 100);
        CHECK(d2k_nl_next(&it, &m) == 0, "из нулевого буфера что-то взялось");
        uint8_t one = 0;
        d2k_nl_iter_init(&it, &one, 0);
        CHECK(d2k_nl_next(&it, &m) == 0, "из пустого буфера что-то взялось");
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("netlink: все проверки прошли\n");
    return 0;
}
