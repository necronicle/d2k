/* test_quic_session.c — датапат видит QUIC поверх UDP (задача 4 QUIC-вертикали).
 *
 * Тот же принцип, что и test_session.c: проверок на «пропустили и объяснили
 * почему» больше, чем на «применили» — пропустить чужую или непонятую
 * датаграмму безвредно, тронуть непонятую значит испортить живое QUIC-
 * соединение и не узнать об этом. Ошибка здесь роняет не тест, а весь QUIC
 * у всех устройств за роутером (см. бриф задачи 4).
 *
 * Вектор Initial — RFC 9001, приложение A.2, побайтно тот же массив, что в
 * core/test_quic.c (задача 2 уже сверила его с текстом RFC и независимым
 * пересчётом; копия здесь нужна, потому что этот файл проверяет НЕ разбор
 * QUIC как таковой — он уже проверен, — а то, что session.c правильно
 * зовёт его на UDP-ветке пакетного пути и правильно распоряжается
 * результатом). ClientHello внутри несёт имя example.com.
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

/* Почти тот же план, что в test_session.c: одна фальшивка перед куском, две
 * копии с паузой 78 мс. Скопирован, а не разделён с тем файлом, по той же
 * причине, по которой в датапате уже не делят между модулями три строки
 * арифметики (см. шапку wire_udp.c) — тесты пакетного пути самодостаточны.
 * Байт flags порчи здесь 0x00, а не 0x01, — ЕДИНСТВЕННОЕ отличие от плана
 * test_session.c, и оно намеренное: 0x01 там — D2K_POISON_BADSUM
 * (d2k_plan.h), а d2k_wire_build_udp отвергает его безусловно (см. шапку
 * d2k_wire.h) — с этим байтом d2k_wire_build_udp честно вернул бы 0 на
 * КАЖДОЙ фальшивке, и план ни разу не «применился» бы, хотя это ничего не
 * говорит про то, что проверяет этот тест. Для UDP план не содержит
 * разрезов/перекрытия: единственное, что применимо к атомарной датаграмме,
 * — фальшивка целиком до или вместо неё, и это именно та фигура, которую
 * этот план описывает. */
static const uint8_t plan_bytes[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 4,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x00, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* План с ОДНИМ разрезом (ANCHOR_PAYLOAD_START, смещение 600 — середина
 * 1200-байтного Initial) и без единой фальшивки/перекрытия. Заголовок:
 * "D2KP" + schema=1 + minexec=1 + flags=0 + число записей=1; единственная
 * запись — REC_SPLIT (тип 0x0100, длина 4): anchor=0 (ANCHOR_PAYLOAD_START,
 * plan_internal.h), offset=600 (0x0258). Разрезы не ссылаются на приманку/
 * порчу (d2k_split — только anchor+offset), поэтому check_refs пропускает
 * план без единой REC_PAYLOAD/REC_POISON. Нужен ровно для одной проверки:
 * такой план для UDP-потока обязан быть отвергнут целиком (см. "план режет
 * датаграмму" ниже), а не тихо нарезать датаграмму на два непонятных
 * половинных огрызка. */
static const uint8_t plan_split[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 1,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x02, 0x58,
};

/* Тот же план, что plan_bytes, но с flags порчи 0x01 — D2K_POISON_BADSUM
 * (d2k_plan.h). Нужен ровно для одной проверки: d2k_wire_build_udp обязан
 * отвергнуть портящую фальшивку (см. шапку d2k_wire.h — BADSUM для UDP не
 * реализован НАМЕРЕННО), а session.c обязан честно СООБЩИТЬ об этом отказе
 * наверх, а не тихо отправить меньше, чем описал план, или сделать вид, что
 * применил план целиком. Это дословно требование брифа задачи 4 про
 * контракт отказа d2k_wire_build_udp. */
static const uint8_t plan_badsum[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 4,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* План с ОДНОЙ фальшивкой и repeats=20: заголовок "D2KP" + schema=1 +
 * minexec=1 + flags=0 + число записей=2; REC_PAYLOAD (id=1, байт 0xAA) и
 * REC_FAKE (payload_id=1, poison_id=0, repeats=20, placement=PLACE_BEFORE,
 * gap_us=0). repeats — байт TLV без потолка (d2k_plan.h/plan_parse.c), а
 * d2k_result.out[] вмещает 16 посылок (d2k_session.h) — 20 > 16. Нужен ровно
 * для одной проверки (ревью задачи 4, круг 2): план, который просит больше
 * посылок, чем помещается в результат, обязан быть отвергнут ЦЕЛИКОМ, а не
 * тихо обрезан до 16 с "применённым" видом. */
static const uint8_t plan_too_many_repeats[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0xAA,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

/* Собирает IPv4/UDP-датаграмму. Контрольная сумма UDP не считается —
 * session.c её не проверяет ни для UDP, ни для TCP (см. build_pkt в
 * test_session.c: там TCP-сумма тоже не настоящая), это забота отправителя
 * на проводе, а не разбора на входе. */
static size_t build_udp_pkt(uint8_t *o, uint16_t sport, uint16_t dport,
                            const uint8_t *pay, size_t paylen) {
    size_t total = 20 + 8 + paylen;
    memset(o, 0, 28);
    o[0] = 0x45;
    wr16(o + 2, (uint16_t)total);
    wr16(o + 4, 0x1000);
    o[8] = 64;
    o[9] = 17; /* UDP */
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    memcpy(o + 12, s, 4);
    memcpy(o + 16, d, 4);
    wr16(o + 20, sport);
    wr16(o + 22, dport);
    wr16(o + 24, (uint16_t)(8 + paylen));
    wr16(o + 26, 0); /* сумма — см. комментарий выше */
    if (paylen) {
        memcpy(o + 28, pay, paylen);
    }
    return total;
}

/* Тот же поток, но со стороны сервера: концы поменяны местами. */
static size_t build_udp_rev_pkt(uint8_t *o, uint16_t client_port,
                                const uint8_t *pay, size_t paylen) {
    size_t total = 20 + 8 + paylen;
    memset(o, 0, 28);
    o[0] = 0x45;
    wr16(o + 2, (uint16_t)total);
    wr16(o + 4, 0x2000);
    o[8] = 64;
    o[9] = 17;
    uint8_t s[4] = {1, 2, 3, 4}, d[4] = {192, 168, 1, 67};
    memcpy(o + 12, s, 4);
    memcpy(o + 16, d, 4);
    wr16(o + 20, 443);
    wr16(o + 22, client_port);
    wr16(o + 24, (uint16_t)(8 + paylen));
    wr16(o + 26, 0);
    if (paylen) {
        memcpy(o + 28, pay, paylen);
    }
    return total;
}
static const uint8_t v1_initial[1200] = {
    0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51,
    0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34, 0xd1, 0xb1,
    0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23,
    0xdc, 0x9b, 0xd8, 0xba, 0xb9, 0x36, 0xb4, 0x7d, 0x92, 0xec, 0x35, 0x6c,
    0x0b, 0xab, 0x7d, 0xf5, 0x97, 0x6d, 0x27, 0xcd, 0x44, 0x9f, 0x63, 0x30,
    0x00, 0x99, 0xf3, 0x99, 0x1c, 0x26, 0x0e, 0xc4, 0xc6, 0x0d, 0x17, 0xb3,
    0x1f, 0x84, 0x29, 0x15, 0x7b, 0xb3, 0x5a, 0x12, 0x82, 0xa6, 0x43, 0xa8,
    0xd2, 0x26, 0x2c, 0xad, 0x67, 0x50, 0x0c, 0xad, 0xb8, 0xe7, 0x37, 0x8c,
    0x8e, 0xb7, 0x53, 0x9e, 0xc4, 0xd4, 0x90, 0x5f, 0xed, 0x1b, 0xee, 0x1f,
    0xc8, 0xaa, 0xfb, 0xa1, 0x7c, 0x75, 0x0e, 0x2c, 0x7a, 0xce, 0x01, 0xe6,
    0x00, 0x5f, 0x80, 0xfc, 0xb7, 0xdf, 0x62, 0x12, 0x30, 0xc8, 0x37, 0x11,
    0xb3, 0x93, 0x43, 0xfa, 0x02, 0x8c, 0xea, 0x7f, 0x7f, 0xb5, 0xff, 0x89,
    0xea, 0xc2, 0x30, 0x82, 0x49, 0xa0, 0x22, 0x52, 0x15, 0x5e, 0x23, 0x47,
    0xb6, 0x3d, 0x58, 0xc5, 0x45, 0x7a, 0xfd, 0x84, 0xd0, 0x5d, 0xff, 0xfd,
    0xb2, 0x03, 0x92, 0x84, 0x4a, 0xe8, 0x12, 0x15, 0x46, 0x82, 0xe9, 0xcf,
    0x01, 0x2f, 0x90, 0x21, 0xa6, 0xf0, 0xbe, 0x17, 0xdd, 0xd0, 0xc2, 0x08,
    0x4d, 0xce, 0x25, 0xff, 0x9b, 0x06, 0xcd, 0xe5, 0x35, 0xd0, 0xf9, 0x20,
    0xa2, 0xdb, 0x1b, 0xf3, 0x62, 0xc2, 0x3e, 0x59, 0x6d, 0x11, 0xa4, 0xf5,
    0xa6, 0xcf, 0x39, 0x48, 0x83, 0x8a, 0x3a, 0xec, 0x4e, 0x15, 0xda, 0xf8,
    0x50, 0x0a, 0x6e, 0xf6, 0x9e, 0xc4, 0xe3, 0xfe, 0xb6, 0xb1, 0xd9, 0x8e,
    0x61, 0x0a, 0xc8, 0xb7, 0xec, 0x3f, 0xaf, 0x6a, 0xd7, 0x60, 0xb7, 0xba,
    0xd1, 0xdb, 0x4b, 0xa3, 0x48, 0x5e, 0x8a, 0x94, 0xdc, 0x25, 0x0a, 0xe3,
    0xfd, 0xb4, 0x1e, 0xd1, 0x5f, 0xb6, 0xa8, 0xe5, 0xeb, 0xa0, 0xfc, 0x3d,
    0xd6, 0x0b, 0xc8, 0xe3, 0x0c, 0x5c, 0x42, 0x87, 0xe5, 0x38, 0x05, 0xdb,
    0x05, 0x9a, 0xe0, 0x64, 0x8d, 0xb2, 0xf6, 0x42, 0x64, 0xed, 0x5e, 0x39,
    0xbe, 0x2e, 0x20, 0xd8, 0x2d, 0xf5, 0x66, 0xda, 0x8d, 0xd5, 0x99, 0x8c,
    0xca, 0xbd, 0xae, 0x05, 0x30, 0x60, 0xae, 0x6c, 0x7b, 0x43, 0x78, 0xe8,
    0x46, 0xd2, 0x9f, 0x37, 0xed, 0x7b, 0x4e, 0xa9, 0xec, 0x5d, 0x82, 0xe7,
    0x96, 0x1b, 0x7f, 0x25, 0xa9, 0x32, 0x38, 0x51, 0xf6, 0x81, 0xd5, 0x82,
    0x36, 0x3a, 0xa5, 0xf8, 0x99, 0x37, 0xf5, 0xa6, 0x72, 0x58, 0xbf, 0x63,
    0xad, 0x6f, 0x1a, 0x0b, 0x1d, 0x96, 0xdb, 0xd4, 0xfa, 0xdd, 0xfc, 0xef,
    0xc5, 0x26, 0x6b, 0xa6, 0x61, 0x17, 0x22, 0x39, 0x5c, 0x90, 0x65, 0x56,
    0xbe, 0x52, 0xaf, 0xe3, 0xf5, 0x65, 0x63, 0x6a, 0xd1, 0xb1, 0x7d, 0x50,
    0x8b, 0x73, 0xd8, 0x74, 0x3e, 0xeb, 0x52, 0x4b, 0xe2, 0x2b, 0x3d, 0xcb,
    0xc2, 0xc7, 0x46, 0x8d, 0x54, 0x11, 0x9c, 0x74, 0x68, 0x44, 0x9a, 0x13,
    0xd8, 0xe3, 0xb9, 0x58, 0x11, 0xa1, 0x98, 0xf3, 0x49, 0x1d, 0xe3, 0xe7,
    0xfe, 0x94, 0x2b, 0x33, 0x04, 0x07, 0xab, 0xf8, 0x2a, 0x4e, 0xd7, 0xc1,
    0xb3, 0x11, 0x66, 0x3a, 0xc6, 0x98, 0x90, 0xf4, 0x15, 0x70, 0x15, 0x85,
    0x3d, 0x91, 0xe9, 0x23, 0x03, 0x7c, 0x22, 0x7a, 0x33, 0xcd, 0xd5, 0xec,
    0x28, 0x1c, 0xa3, 0xf7, 0x9c, 0x44, 0x54, 0x6b, 0x9d, 0x90, 0xca, 0x00,
    0xf0, 0x64, 0xc9, 0x9e, 0x3d, 0xd9, 0x79, 0x11, 0xd3, 0x9f, 0xe9, 0xc5,
    0xd0, 0xb2, 0x3a, 0x22, 0x9a, 0x23, 0x4c, 0xb3, 0x61, 0x86, 0xc4, 0x81,
    0x9e, 0x8b, 0x9c, 0x59, 0x27, 0x72, 0x66, 0x32, 0x29, 0x1d, 0x6a, 0x41,
    0x82, 0x11, 0xcc, 0x29, 0x62, 0xe2, 0x0f, 0xe4, 0x7f, 0xeb, 0x3e, 0xdf,
    0x33, 0x0f, 0x2c, 0x60, 0x3a, 0x9d, 0x48, 0xc0, 0xfc, 0xb5, 0x69, 0x9d,
    0xbf, 0xe5, 0x89, 0x64, 0x25, 0xc5, 0xba, 0xc4, 0xae, 0xe8, 0x2e, 0x57,
    0xa8, 0x5a, 0xaf, 0x4e, 0x25, 0x13, 0xe4, 0xf0, 0x57, 0x96, 0xb0, 0x7b,
    0xa2, 0xee, 0x47, 0xd8, 0x05, 0x06, 0xf8, 0xd2, 0xc2, 0x5e, 0x50, 0xfd,
    0x14, 0xde, 0x71, 0xe6, 0xc4, 0x18, 0x55, 0x93, 0x02, 0xf9, 0x39, 0xb0,
    0xe1, 0xab, 0xd5, 0x76, 0xf2, 0x79, 0xc4, 0xb2, 0xe0, 0xfe, 0xb8, 0x5c,
    0x1f, 0x28, 0xff, 0x18, 0xf5, 0x88, 0x91, 0xff, 0xef, 0x13, 0x2e, 0xef,
    0x2f, 0xa0, 0x93, 0x46, 0xae, 0xe3, 0x3c, 0x28, 0xeb, 0x13, 0x0f, 0xf2,
    0x8f, 0x5b, 0x76, 0x69, 0x53, 0x33, 0x41, 0x13, 0x21, 0x19, 0x96, 0xd2,
    0x00, 0x11, 0xa1, 0x98, 0xe3, 0xfc, 0x43, 0x3f, 0x9f, 0x25, 0x41, 0x01,
    0x0a, 0xe1, 0x7c, 0x1b, 0xf2, 0x02, 0x58, 0x0f, 0x60, 0x47, 0x47, 0x2f,
    0xb3, 0x68, 0x57, 0xfe, 0x84, 0x3b, 0x19, 0xf5, 0x98, 0x40, 0x09, 0xdd,
    0xc3, 0x24, 0x04, 0x4e, 0x84, 0x7a, 0x4f, 0x4a, 0x0a, 0xb3, 0x4f, 0x71,
    0x95, 0x95, 0xde, 0x37, 0x25, 0x2d, 0x62, 0x35, 0x36, 0x5e, 0x9b, 0x84,
    0x39, 0x2b, 0x06, 0x10, 0x85, 0x34, 0x9d, 0x73, 0x20, 0x3a, 0x4a, 0x13,
    0xe9, 0x6f, 0x54, 0x32, 0xec, 0x0f, 0xd4, 0xa1, 0xee, 0x65, 0xac, 0xcd,
    0xd5, 0xe3, 0x90, 0x4d, 0xf5, 0x4c, 0x1d, 0xa5, 0x10, 0xb0, 0xff, 0x20,
    0xdc, 0xc0, 0xc7, 0x7f, 0xcb, 0x2c, 0x0e, 0x0e, 0xb6, 0x05, 0xcb, 0x05,
    0x04, 0xdb, 0x87, 0x63, 0x2c, 0xf3, 0xd8, 0xb4, 0xda, 0xe6, 0xe7, 0x05,
    0x76, 0x9d, 0x1d, 0xe3, 0x54, 0x27, 0x01, 0x23, 0xcb, 0x11, 0x45, 0x0e,
    0xfc, 0x60, 0xac, 0x47, 0x68, 0x3d, 0x7b, 0x8d, 0x0f, 0x81, 0x13, 0x65,
    0x56, 0x5f, 0xd9, 0x8c, 0x4c, 0x8e, 0xb9, 0x36, 0xbc, 0xab, 0x8d, 0x06,
    0x9f, 0xc3, 0x3b, 0xd8, 0x01, 0xb0, 0x3a, 0xde, 0xa2, 0xe1, 0xfb, 0xc5,
    0xaa, 0x46, 0x3d, 0x08, 0xca, 0x19, 0x89, 0x6d, 0x2b, 0xf5, 0x9a, 0x07,
    0x1b, 0x85, 0x1e, 0x6c, 0x23, 0x90, 0x52, 0x17, 0x2f, 0x29, 0x6b, 0xfb,
    0x5e, 0x72, 0x40, 0x47, 0x90, 0xa2, 0x18, 0x10, 0x14, 0xf3, 0xb9, 0x4a,
    0x4e, 0x97, 0xd1, 0x17, 0xb4, 0x38, 0x13, 0x03, 0x68, 0xcc, 0x39, 0xdb,
    0xb2, 0xd1, 0x98, 0x06, 0x5a, 0xe3, 0x98, 0x65, 0x47, 0x92, 0x6c, 0xd2,
    0x16, 0x2f, 0x40, 0xa2, 0x9f, 0x0c, 0x3c, 0x87, 0x45, 0xc0, 0xf5, 0x0f,
    0xba, 0x38, 0x52, 0xe5, 0x66, 0xd4, 0x45, 0x75, 0xc2, 0x9d, 0x39, 0xa0,
    0x3f, 0x0c, 0xda, 0x72, 0x19, 0x84, 0xb6, 0xf4, 0x40, 0x59, 0x1f, 0x35,
    0x5e, 0x12, 0xd4, 0x39, 0xff, 0x15, 0x0a, 0xab, 0x76, 0x13, 0x49, 0x9d,
    0xbd, 0x49, 0xad, 0xab, 0xc8, 0x67, 0x6e, 0xef, 0x02, 0x3b, 0x15, 0xb6,
    0x5b, 0xfc, 0x5c, 0xa0, 0x69, 0x48, 0x10, 0x9f, 0x23, 0xf3, 0x50, 0xdb,
    0x82, 0x12, 0x35, 0x35, 0xeb, 0x8a, 0x74, 0x33, 0xbd, 0xab, 0xcb, 0x90,
    0x92, 0x71, 0xa6, 0xec, 0xbc, 0xb5, 0x8b, 0x93, 0x6a, 0x88, 0xcd, 0x4e,
    0x8f, 0x2e, 0x6f, 0xf5, 0x80, 0x01, 0x75, 0xf1, 0x13, 0x25, 0x3d, 0x8f,
    0xa9, 0xca, 0x88, 0x85, 0xc2, 0xf5, 0x52, 0xe6, 0x57, 0xdc, 0x60, 0x3f,
    0x25, 0x2e, 0x1a, 0x8e, 0x30, 0x8f, 0x76, 0xf0, 0xbe, 0x79, 0xe2, 0xfb,
    0x8f, 0x5d, 0x5f, 0xbb, 0xe2, 0xe3, 0x0e, 0xca, 0xdd, 0x22, 0x07, 0x23,
    0xc8, 0xc0, 0xae, 0xa8, 0x07, 0x8c, 0xdf, 0xcb, 0x38, 0x68, 0x26, 0x3f,
    0xf8, 0xf0, 0x94, 0x00, 0x54, 0xda, 0x48, 0x78, 0x18, 0x93, 0xa7, 0xe4,
    0x9a, 0xd5, 0xaf, 0xf4, 0xaf, 0x30, 0x0c, 0xd8, 0x04, 0xa6, 0xb6, 0x27,
    0x9a, 0xb3, 0xff, 0x3a, 0xfb, 0x64, 0x49, 0x1c, 0x85, 0x19, 0x4a, 0xab,
    0x76, 0x0d, 0x58, 0xa6, 0x06, 0x65, 0x4f, 0x9f, 0x44, 0x00, 0xe8, 0xb3,
    0x85, 0x91, 0x35, 0x6f, 0xbf, 0x64, 0x25, 0xac, 0xa2, 0x6d, 0xc8, 0x52,
    0x44, 0x25, 0x9f, 0xf2, 0xb1, 0x9c, 0x41, 0xb9, 0xf9, 0x6f, 0x3c, 0xa9,
    0xec, 0x1d, 0xde, 0x43, 0x4d, 0xa7, 0xd2, 0xd3, 0x92, 0xb9, 0x05, 0xdd,
    0xf3, 0xd1, 0xf9, 0xaf, 0x93, 0xd1, 0xaf, 0x59, 0x50, 0xbd, 0x49, 0x3f,
    0x5a, 0xa7, 0x31, 0xb4, 0x05, 0x6d, 0xf3, 0x1b, 0xd2, 0x67, 0xb6, 0xb9,
    0x0a, 0x07, 0x98, 0x31, 0xaa, 0xf5, 0x79, 0xbe, 0x0a, 0x39, 0x01, 0x31,
    0x37, 0xaa, 0xc6, 0xd4, 0x04, 0xf5, 0x18, 0xcf, 0xd4, 0x68, 0x40, 0x64,
    0x7e, 0x78, 0xbf, 0xe7, 0x06, 0xca, 0x4c, 0xf5, 0xe9, 0xc5, 0x45, 0x3e,
    0x9f, 0x7c, 0xfd, 0x2b, 0x8b, 0x4c, 0x8d, 0x16, 0x9a, 0x44, 0xe5, 0x5c,
    0x88, 0xd4, 0xa9, 0xa7, 0xf9, 0x47, 0x42, 0x41, 0xe2, 0x21, 0xaf, 0x44,
    0x86, 0x00, 0x18, 0xab, 0x08, 0x56, 0x97, 0x2e, 0x19, 0x4c, 0xd9, 0x34,
};

static size_t build_tcp_syn(uint8_t *o, uint16_t sport, uint16_t dport) {
    size_t total = 20 + 20;
    memset(o, 0, 40);
    o[0] = 0x45;
    wr16(o + 2, (uint16_t)total);
    wr16(o + 4, 0x3000);
    o[8] = 64;
    o[9] = 6; /* TCP */
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    memcpy(o + 12, s, 4);
    memcpy(o + 16, d, 4);
    wr16(o + 20, sport);
    wr16(o + 22, dport);
    o[32] = 0x50; /* data offset 5 слов, опций нет */
    o[33] = 0x02; /* SYN */
    wr16(o + 34, 64240);
    return total;
}

int main(void) {
    /* --- Initial узнаётся, имя уходит контроллеру ТЕМ ЖЕ событием, что и
       для TLS (Step 1, пункт 1 брифа) ------------------------------------ */
    {
        d2k_session *s = d2k_session_new(64, 32);
        CHECK(s != NULL, "сессия не создалась");

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 50000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(d2k_session_hellos(s) == 1, "QUIC Initial не узнан как приветствие");
        CHECK(d2k_session_with_sni(s) == 1, "имя QUIC не засчитано как SNI");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "датаграмма без плана обязана пройти как есть");
        CHECK(r.n_out == 0, "план взялся ниоткуда для цели без плана");

        const d2k_journal *j = d2k_session_journal(s);
        int found = 0;
        for (size_t i = 0; i < d2k_journal_count(j); i++) {
            const d2k_jrn_entry *e = d2k_journal_at(j, i);
            if (e->kind == D2K_JRN_HELLO_SNI && e->name_len == 11 &&
                memcmp(e->name, "example.com", 11) == 0) {
                found = 1;
            }
        }
        CHECK(found, "имя example.com не ушло в журнал тем же событием, что у TLS");

        d2k_session_free(s);
    }

    /* --- план по имени применяется к UDP-потоку (Step 1, пункт 2) --------- */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0,
              "план не загрузился");
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, p);

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 51000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(r.skipped == NULL, "план по имени не применился к UDP-потоку");
        CHECK(r.n_out == 2, "ожидались две копии фальшивки");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT,
              "оригинальная датаграмма обязана пройти: план только добавляет фальшивку");
        if (r.n_out == 2) {
            CHECK(r.out[0].delay_us == 0, "первая копия не должна ждать");
            CHECK(r.out[1].delay_us == 78000, "пауза между копиями потеряна");
            CHECK(r.out[0].len == 20 + 8 + 3, "длина собранной датаграммы неверна");
        }
        CHECK(d2k_session_applied(s) == 1, "счётчик применений не сдвинулся");

        /* тот же поток второй раз: план не применяется повторно */
        d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "план применён к UDP-потоку повторно");
        CHECK(r.skipped != NULL, "повторное применение не объяснено");
        CHECK(d2k_session_applied(s) == 1, "счётчик применений вырос повторно");

        d2k_session_free(s);
    }

    /* --- не-QUIC UDP не трогается вовсе (Step 1, пункт 3) ------------------ */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t junk[40];
        memset(junk, 0x41, sizeof junk); /* короткий заголовок — не похоже на Initial */
        uint8_t pkt[100], buf[256];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 52000, 443, junk, sizeof junk);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "не-QUIC UDP обязан пройти как есть");
        CHECK(r.n_out == 0, "не-QUIC UDP породил посылки");
        CHECK(r.skipped != NULL, "пропуск не-QUIC UDP не объяснён");
        CHECK(d2k_session_hellos(s) == 0, "не-QUIC UDP засчитан приветствием");

        d2k_session_free(s);
    }

    /* --- несколько QUIC-пакетов в одной датаграмме: разбираем первый
       (ловушка 5 брифа) ---------------------------------------------------
       Initial сам объявляет свою длину полем Length, и core/quic.c
       ограничивается ЕЮ, а не длиной датаграммы — здесь проверяется, что
       session.c честно передаёт ВЕСЬ payload не обрезая его, и хвостовой
       мусор (заготовка «следующего пакета») не мешает найти имя. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t coalesced[1200 + 40];
        memcpy(coalesced, v1_initial, sizeof v1_initial);
        memset(coalesced + sizeof v1_initial, 0x99, 40);

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 53000, 443, coalesced, sizeof coalesced);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(d2k_session_hellos(s) == 1, "Initial не узнан в датаграмме со следующим пакетом");
        CHECK(d2k_session_with_sni(s) == 1, "имя не найдено в датаграмме со следующим пакетом");

        d2k_session_free(s);
    }

    /* --- окно поиска переживает неудачную расшифровку (ловушка 4 брифа) ----
       Первая датаграмма структурно похожа на Initial, но DCID испорчен —
       ключи из НЕГО не совпадут ни с чем, и d2k_quic_sni честно вернёт -1.
       Вторая датаграмма на ТОМ ЖЕ потоке — настоящий Initial: попытка
       обязана повториться, а не остановиться после первой неудачи, — ровно
       то, что происходит у клиента после Retry с новым DCID. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t garbled[1200];
        memcpy(garbled, v1_initial, sizeof v1_initial);
        garbled[6] ^= 0xFF; /* байт 6 — начало DCID (после первого байта и версии) */

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 54000, 443, garbled, sizeof garbled);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 0, "неудачная расшифровка ошибочно засчитана приветствием");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "нерасшифрованная датаграмма обязана пройти как есть");

        n = build_udp_pkt(pkt, 54000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 1,
              "окно поиска не пережило неудачную расшифровку первой датаграммы");
        CHECK(d2k_session_with_sni(s) == 1, "имя не найдено на второй датаграмме окна");

        d2k_session_free(s);
    }

    /* --- направление НЕ берётся из порядка прибытия (ловушка ревью задачи
       4, круг 2) --------------------------------------------------------
     * Живой сценарий: правило `-m mark ... -j RETURN` в files/S99d2k стоит
     * только в исходящей цепочке, поэтому собственный исходящий зонд службы
     * (задача 5) в очередь не попадает вовсе, а ОТВЕТ на него — попадает.
     * Первая датаграмма такого потока, какую вообще увидит датапат, —
     * серверная. Здесь это смоделировано буквально: первый пакет потока —
     * мусор с ОБРАТНОЙ стороны (build_udp_rev_pkt — та же сторона, что занял
     * бы ответ сервера). ВТОРАЯ датаграмма — настоящий клиентский Initial, и
     * приходит с ПРЯМОЙ стороны (build_udp_pkt — сторона клиента), то есть с
     * ДРУГОЙ стороны, чем первая. Если направление берётся из порядка
     * прибытия (старое поведение — «кто пришёл первым, тот и прямой»),
     * первый пакет закрепит за «прямой» стороной сервера, и второй,
     * настоящий клиентский, будет сочтён «нагрузкой с обратной стороны» и
     * никогда не разберётся — ровно тот баг, который чинит эта правка.
     *
     * ПРАВКА КРУГА 3: круг 2 определял направление успехом d2k_quic_sni —
     * этого сейчас в session.c уже нет (см. большой комментарий в
     * handle_udp: успешная расшифровка доказывает содержимое, а не то, куда
     * едет датаграмма, — направление теперь берётся из порта назначения).
     * Junk здесь остаётся мусором при любом критерии направления, и тест
     * по-прежнему проверяет то же наблюдаемое поведение (первый пакет с
     * обратной стороны не должен помешать разбору второго, настоящего) —
     * отдельная, более прямая проверка самого признака направления по порту
     * — следующий блок ниже. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;

        uint8_t junk[12];
        memset(junk, 0x41, sizeof junk); /* короткий заголовок — не Initial */
        size_t n = build_udp_rev_pkt(pkt, 55000, junk, sizeof junk);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 0, "мусор ошибочно сочтён приветствием");

        n = build_udp_pkt(pkt, 55000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);

        CHECK(d2k_session_hellos(s) == 1,
              "настоящий клиентский Initial не разобран из-за догадки о направлении по порядку прибытия");
        CHECK(d2k_session_with_sni(s) == 1, "имя не найдено");

        d2k_session_free(s);
    }

    /* --- отражённая копия клиентского Initial не проходит как приветствие
       (ревью задачи 4, круг 3) ------------------------------------------
     * Круг 2 доказывал направление успехом d2k_quic_sni: "раскрылось ключами
     * client in — значит датаграмма от клиента". Неверно — ключи выводятся
     * из ПУБЛИЧНОГО DCID (RFC 9001 §5.4.1/5.4.2), раскрытие доказывает
     * только содержимое, а не куда датаграмма едет. Побайтовая копия
     * v1_initial, пущенная в обратную сторону (build_udp_rev_pkt: порт
     * источника 443, как у настоящего сервера, порт назначения — высокий
     * порт клиента), раскрывается ТЕМИ ЖЕ ключами и несёт то же самое
     * "доказательство". Ревьюер показал стендом: 1.2.3.4:443 -> LAN:50000 с
     * байтами клиентского Initial при поставленном плане давало приветствие,
     * применение и поддельную посылку В СТОРОНУ СОБСТВЕННОГО ПОЛЬЗОВАТЕЛЯ, а
     * настоящий клиентский Initial следом отбрасывался как "поток уже
     * показывал приветствие". Здесь — тот же стенд: отражённая копия обязана
     * не завести приветствие, не дать применения и не породить ни одной
     * посылки, а контрольная половина (настоящая клиентская датаграмма,
     * порт назначения 443) обязана по-прежнему обрабатываться — иначе тест
     * прошёл бы просто оттого, что путь перестал работать вовсе. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0,
              "план не загрузился");
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, p);

        uint8_t pkt[1300], buf[4096];
        d2k_result r;

        /* Отражённая копия — стенд ревьюера буквально: те же байты
           клиентского Initial, но едущие ОТ сервера (порт источника 443) К
           клиенту на высокий порт. */
        size_t n = build_udp_rev_pkt(pkt, 59000, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 0,
              "отражённая копия клиентского Initial ошибочно сочтена приветствием");
        CHECK(d2k_session_with_sni(s) == 0, "имя добыто из отражённой копии");
        CHECK(d2k_session_applied(s) == 0,
              "план применён к отражённой копии — обход бьёт по собственному пользователю");
        CHECK(r.n_out == 0, "отражённая копия породила посылку");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "отражённая копия обязана пройти как есть");

        /* Контрольная половина: настоящая клиентская датаграмма (порт
           назначения 443) с тем же именем ОБЯЗАНА по-прежнему обрабатываться. */
        n = build_udp_pkt(pkt, 59000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 1,
              "настоящий клиентский Initial не разобран после фикса направления по порту");
        CHECK(d2k_session_with_sni(s) == 1, "имя настоящего клиентского Initial не найдено");
        CHECK(d2k_session_applied(s) == 1, "план не применился к настоящему клиентскому Initial");
        CHECK(r.n_out == 2, "план не дал ожидаемых двух посылок на настоящем клиентском Initial");

        d2k_session_free(s);
    }

    /* --- ни один порт не 443: направление неизвестно, план не применяется -
       Третья ветка того же признака (ревью задачи 4, круг 3): порт источника
       и порт назначения оба НЕ 443. По правилам files/S99d2k такая
       датаграмма в очередь вообще не попала бы (обе цепочки заточены под
       443), но handle_udp вызывается и напрямую (эта программа), и обязан
       вести себя безопасно на входе, которого честная эксплуатация не
       производит: "не понял — не тронь" распространяется и на направление,
       не только на содержимое. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0,
              "план не загрузился");
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, p);

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 51500, 8443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(d2k_session_hellos(s) == 0,
              "датаграмма без порта 443 ни с одной стороны ошибочно сочтена приветствием");
        CHECK(d2k_session_applied(s) == 0, "план применился при неизвестном направлении");
        CHECK(r.n_out == 0, "неизвестное направление породило посылку");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "датаграмма с неизвестным направлением обязана пройти как есть");

        d2k_session_free(s);
    }

    /* --- план, режущий датаграмму на части, отвергается для UDP ------------
       Разрез — рабочий приём для TCP-потока (сервер пересобирает поток из
       сегментов), но для одной атомарной UDP-датаграммы он означает не
       «разрезанный поток», а два огрызка одного QUIC-пакета, которые никто
       не соединит. session.c обязан отказать целиком, а не отправить оба
       огрызка как есть (см. большой комментарий в handle_udp, session.c). */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_split, sizeof plan_split, &p, err, sizeof err) == 0,
              "план с разрезом не загрузился");
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, p);

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 56000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(r.n_out == 0, "план разрезал UDP-датаграмму на части");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT,
              "отвергнутый разрез обязан оставить оригинал нетронутым");
        CHECK(d2k_session_applied(s) == 0, "разрез датаграммы засчитан применением плана");

        d2k_session_free(s);
    }

    /* --- отказ d2k_wire_build_udp сообщается наверх, а не проглатывается ---
       Требование брифа задачи 4 дословно: контракт отказа d2k_wire_build_udp
       нельзя проглатывать. BADSUM для UDP не реализован НАМЕРЕННО (см.
       d2k_wire.h) — сборщик честно вернёт 0 на каждой фальшивке, и
       session.c обязан это заметить: не отправить ничего, оставить
       оригинал нетронутым и объяснить причину, а не сделать вид, что план
       применился. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_badsum, sizeof plan_badsum, &p, err, sizeof err) == 0,
              "план с BADSUM не загрузился");
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, p);

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 56500, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(r.n_out == 0, "отказ сборщика не помешал отправке");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT,
              "ничего не отправив, оригинал обязаны пропустить");
        CHECK(r.skipped != NULL, "отказ сборщика не объяснён вызывающему");
        CHECK(d2k_session_applied(s) == 0, "невыполненный план засчитан применённым");

        const d2k_journal *j = d2k_session_journal(s);
        int refused = 0;
        for (size_t i = 0; i < d2k_journal_count(j); i++) {
            const d2k_jrn_entry *e = d2k_journal_at(j, i);
            if (e->kind == D2K_JRN_PLAN_REFUSED) {
                refused = 1;
            }
        }
        CHECK(refused, "отказ сборщика не ушёл в журнал");

        d2k_session_free(s);
    }

    /* --- план с repeats больше вместимости out[] отвергается целиком -------
       Ревью задачи 4, круг 2: repeats берётся из TLV байтом без потолка (до
       255), d2k_result.out[] вмещает 16 (d2k_session.h). План с repeats=20
       раньше "применялся" — n тихо обрезался до 16, на провод уходило 16
       посылок вместо 20, а plan_done/applied++/PLAN_APPLIED ставились
       безусловно, как будто ушли все 20. Честный исход — отказ целиком: ни
       одной посылки, план не считается применённым. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_too_many_repeats, sizeof plan_too_many_repeats, &p, err, sizeof err) == 0,
              "план с repeats=20 не загрузился");
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, p);

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 56600, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(r.n_out == 0, "план с repeats=20 отправил хоть одну посылку вместо честного отказа");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "ничего не отправив, оригинал обязаны пропустить");
        CHECK(r.skipped != NULL, "отказ по переполнению out[] не объяснён вызывающему");
        CHECK(d2k_session_applied(s) == 0, "план с repeats=20 засчитан применённым (обрезанным)");

        d2k_session_free(s);
    }

    /* --- окно поиска закрывается коротким замыканием по найденному имени ---
       По ревью задачи 4, круг 2: мутация №2 из первой версии этого файла
       проверяла, что окно НЕ закрывается СЛИШКОМ РАНО (переживает неудачную
       расшифровку) — а что оно вообще закрывается, не проверял никто.
       Ревьюер снял стража целиком (`if (0 && (...))`), и весь набор остался
       зелёным. Здесь — половина «короткое замыкание»: второй валидный
       Initial на потоке, где имя УЖЕ найдено, не должен пересчитываться. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;

        size_t n = build_udp_pkt(pkt, 64000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 1, "первый Initial не разобран");

        /* Тот же поток, снова валидный Initial. Без короткого замыкания по
           fl->saw_hello разбор попробовал бы его заново и пересчитал имя. */
        n = build_udp_pkt(pkt, 64000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 1,
              "приветствие пересчитано на потоке, где имя уже найдено — короткое замыкание снято");
        CHECK(d2k_session_with_sni(s) == 1,
              "SNI пересчитан на потоке, где имя уже найдено — короткое замыкание снято");

        d2k_session_free(s);
    }

    /* --- окно поиска закрывается верхней границей числа попыток -----------
       Вторая половина того же стража: D2K_HELLO_WINDOW неудачных попыток
       обязаны исчерпать окно, и датаграмма ЗА окном не должна пробоваться
       на разбор, даже если она настоящая и валидная. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;

        uint8_t garbled[1200];
        memcpy(garbled, v1_initial, sizeof garbled);
        garbled[6] ^= 0xFF; /* байт 6 — начало DCID, портит расшифровку */

        /* D2K_HELLO_WINDOW (8) неудачных попыток на одном потоке. */
        for (int i = 0; i < 8; i++) {
            size_t n = build_udp_pkt(pkt, 65000, 443, garbled, sizeof garbled);
            d2k_session_packet(s, pkt, n, (uint64_t)(1000 + i), buf, sizeof buf, &r);
        }
        CHECK(d2k_session_hellos(s) == 0, "неудачные попытки ошибочно сочтены приветствием");

        /* Девятая датаграмма на том же потоке — настоящий, валидный Initial.
           Верхняя граница окна обязана остановить попытки ДО неё: без неё
           разбор попробовал бы и эту датаграмму, и она бы удалась. */
        size_t n = build_udp_pkt(pkt, 65000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 0,
              "окно поиска не закрылось верхней границей — валидный Initial за окном всё равно разобран");

        d2k_session_free(s);
    }

    /* --- таблица UDP-потоков чистится по молчанию, как и таблица TCP ------- */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 57000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        size_t before = d2k_session_flows(s);
        CHECK(before > 0, "UDP-поток не завёлся в таблице");

        const uint64_t s_ns = 1000000000ull;
        size_t freed = d2k_session_expire(s, 1000 + 100 * s_ns, 50 * s_ns);
        CHECK(freed > 0, "истечение не освободило ни одного UDP-потока");
        CHECK(d2k_session_flows(s) < before, "уборка не уменьшила число потоков");

        d2k_session_free(s);
    }

    /* --- счётчики суммируют TCP- и UDP-таблицы ТОЧНЫМ числом, а отказ по
       переполнению приходит от ТОЙ таблицы, которая переполнилась ----------
       По ревью задачи 4: d2k_session_flows/capacity/refusals стали суммой
       двух таблиц вместо одной — поведение публичного API изменилось, и
       незакреплённое тестом на точное число оно назавтра поменяется молча.
       Ёмкость 16 округляется вверх до себя же (round_pow2 в track.c), порог
       отказа — 3/4 от неё, то есть 12 живых записей; 13-я в ТУ ЖЕ таблицу
       получает честный отказ. Обе таблицы получают ту же ёмкость 16
       (наследуется от одного capacity, см. d2k_session_new) — но это ДВЕ
       независимые ёмкости по 12, а не одна на двоих: TCP-потоки заводятся
       не менее чем 12 раз, а сумма после этого не 12, а 24. */
    {
        d2k_session *s = d2k_session_new(16, 32);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;

        /* Не меньше 12 байт нагрузки: общий пролог требует total >= ihl+20
           (см. handle_udp) — короче отвергнут раньше учёта потока, и
           переполнение вообще не при чём. */
        uint8_t tiny[12];
        memset(tiny, 0, sizeof tiny);

        for (uint16_t i = 0; i < 12; i++) {
            size_t n = build_tcp_syn(pkt, (uint16_t)(61000 + i), 443);
            d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        }
        CHECK(d2k_session_flows(s) == 12, "12 TCP-потоков не завелись точным числом");

        for (uint16_t i = 0; i < 12; i++) {
            size_t n = build_udp_pkt(pkt, (uint16_t)(62000 + i), 443, tiny, sizeof tiny);
            d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        }
        CHECK(d2k_session_flows(s) == 24,
              "12 TCP + 12 UDP не дали точную сумму 24 — таблицы делят один бюджет?");
        CHECK(d2k_session_capacity(s) == 32,
              "ёмкость 16+16 не сложилась в точную сумму 32");

        d2k_session_free(s);
    }

    /* --- отдельная сессия: отказ по переполнению приходит от ТОЙ таблицы,
       которая переполнилась, а не от общего на двоих бюджета -------------
       Не тот же блок, что выше, нарочно: там TCP-таблица к концу УЖЕ на
       своём пределе (12 из 12) её же собственным заполнением, и «завести
       ещё один TCP-поток» там ничего не доказало бы — отказ пришёл бы от
       предела TCP-таблицы, не от переполнения UDP. Здесь TCP-таблица пуста
       весь тест: единственная нагрузка — на UDP-таблицу. */
    {
        d2k_session *s = d2k_session_new(16, 32);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        uint8_t tiny[12];
        memset(tiny, 0, sizeof tiny);

        for (uint16_t i = 0; i < 12; i++) {
            size_t n = build_udp_pkt(pkt, (uint16_t)(63000 + i), 443, tiny, sizeof tiny);
            d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        }
        CHECK(d2k_session_flows(s) == 12, "12 UDP-потоков не завелись точным числом");

        uint64_t refusals_before = d2k_session_refusals(s);

        /* 13-й UDP-поток — таблица UDP уже полна (12 из 12), честный отказ. */
        size_t n = build_udp_pkt(pkt, 63100, 443, tiny, sizeof tiny);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.skipped != NULL && strcmp(r.skipped, "таблица потоков полна") == 0,
              "13-й UDP-поток не отвергнут переполнением своей таблицы");
        CHECK(d2k_session_refusals(s) == refusals_before + 1,
              "отказ по переполнению UDP-таблицы не посчитан ровно один раз");
        CHECK(d2k_session_flows(s) == 12, "отвергнутый UDP-поток всё равно занял ячейку");
        /* Раздельные счётчики (ревью задачи 4, круг 2) обязаны показать, что
           отказала ИМЕННО UDP-таблица, а не «сумма отказов выросла где-то». */
        CHECK(d2k_session_refusals_udp(s) == 1, "отказ UDP-таблицы не отражён в d2k_session_refusals_udp");
        CHECK(d2k_session_refusals_tcp(s) == 0, "отказ UDP-таблицы ошибочно приписан TCP-таблице");
        CHECK(d2k_session_flows_udp(s) == 12, "d2k_session_flows_udp разошёлся с точным числом UDP-потоков");
        CHECK(d2k_session_flows_tcp(s) == 0, "d2k_session_flows_tcp не ноль при пустой TCP-таблице");

        /* TCP-таблица пуста и НЕЗАВИСИМА от переполненной UDP-таблицы: самый
           первый TCP-поток в этой сессии обязан завестись без отказа. */
        n = build_tcp_syn(pkt, 61000, 443);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.skipped == NULL || strcmp(r.skipped, "таблица потоков полна") != 0,
              "переполнение UDP-таблицы отказало независимому TCP-потоку");
        CHECK(d2k_session_flows(s) == 13,
              "первый TCP-поток не завёлся при переполненной, но чужой UDP-таблице");
        CHECK(d2k_session_refusals(s) == refusals_before + 1,
              "независимый TCP-поток ошибочно посчитан отказом по переполнению");
        CHECK(d2k_session_flows_tcp(s) == 1, "d2k_session_flows_tcp не увидел новый TCP-поток");
        CHECK(d2k_session_refusals_tcp(s) == 0, "независимый TCP-поток испортил d2k_session_refusals_tcp");
        CHECK(d2k_session_capacity_tcp(s) == 16 && d2k_session_capacity_udp(s) == 16,
              "d2k_session_capacity_tcp/udp разошлись с ёмкостью 16 каждой таблицы");

        d2k_session_free(s);
    }

    /* --- TCP- и UDP-поток с одинаковыми портами не путаются ----------------
       Ключ потока теперь несёт транспорт (d2k_key.proto, по ревью задачи 4 —
       см. большой комментарий у d2k_key в d2k_track.h): TCP-поток и
       QUIC/UDP-поток к одному адресу с одинаковым исходным портом получают
       РАЗНЫЕ ключи и потому не путают состояние, даже если бы жили в одной
       таблице. Раздельные таблицы (s->flows/s->uflows) поверх этого — про
       независимые бюджеты ёмкости, а не про снятие коллизии ключей (та уже
       снята полем proto); эта проверка — что QUIC всё равно РАЗБИРАЕТСЯ, а
       не только не путается счётчиком (числа — отдельным тестом ниже). */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;

        size_t n = build_tcp_syn(pkt, 58000, 443);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_flows(s) == 1, "TCP SYN не завёл поток");

        n = build_udp_pkt(pkt, 58000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
        CHECK(d2k_session_flows(s) == 2,
              "TCP- и UDP-поток с одинаковым портом схлопнулись в один");
        CHECK(d2k_session_hellos(s) == 1,
              "QUIC Initial не разобран из-за коллизии с TCP-потоком того же порта");

        d2k_session_free(s);
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("QUIC/UDP: все проверки прошли\n");
    return 0;
}
