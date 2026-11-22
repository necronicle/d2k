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
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "test_nat_stub.h"
#include "d2k_session.h"
#include "d2k_journal.h"
#include "d2k_quic.h"
#include "d2k_quichello.h"
#include "d2k_nat.h"
#include "../core/test_quic_pq.h"
#include "d2k_quicsnap.h"
#include "d2k_crypto.h"

/* The packet path must work with no heap allocation after flow admission. */
#define malloc(size) ((void)(size), (void *)0)
#include "quic_flow.h"
#undef malloc

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static int quic_nat_not_ready(const char *path, uint8_t proto,
                             uint32_t src, uint16_t sport,
                             uint32_t dst, uint16_t dport,
                             uint32_t *outside_src, uint16_t *outside_sport) {
    (void)path; (void)proto; (void)src; (void)sport;
    (void)dst; (void)dport; (void)outside_src; (void)outside_sport;
    return -1;
}

/* Сколько раз в журнале встретился отказ плана (D2K_JRN_PLAN_REFUSED). */
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

static size_t count_journal_kind(const d2k_session *s, int kind) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j), c = 0;
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == kind) { c++; }
    }
    return c;
}

/* Встречалась ли запись такого вида С ТАКИМ КОДОМ. Вид без кода у обмена
   ничего не говорит: весь смысл D2K_JRN_EXCHANGE для UDP лежит в коде
   (D2K_UDP_PROOF_*), и «обмен был» без него читается как успех, которым он
   не является. */
static int journal_code_seen(const d2k_session *s, int kind, uint8_t code) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j);
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == kind && e->code == code) { return 1; }
    }
    return 0;
}

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

/* ТОТ ЖЕ план, что plan_bytes, но с объявленным транспортом TCP
 * (REC_PROTO = 0x0002, длина 2: транспорт 6, прикладной протокол 1 «tls»).
 *
 * Нужен ровно для одной проверки: таблица планов ключуется именем и ФОРМОЙ,
 * а «дедушкино право» совместимо с любой формой, включая QUIC, — и план,
 * подтверждённый на TLS поверх TCP, доставался датаграмме того же имени.
 * Исполнитель потом честно упирался в «посылка невыполнима для UDP»
 * (разреза и перекрытия у датаграммы нет), и каждый такой случай сжигал зонд
 * на поиске, который не мог сойтись. На роутере владельца 13.09.2026 таких
 * отказов набралось 221 за день. */
static const uint8_t plan_tcp_declared[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 5,
    0x00, 0x02, 0x00, 0x02, 0x06, 0x01,
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

/* Одна фальшивка, D2K_RESULT_MAX+1 повторов: отказ целиком,
 * а не тихое обрезание до вместимости результата. */
static const uint8_t plan_too_many_repeats[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0xAA,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, D2K_RESULT_MAX + 1, 0x00, 0x00, 0x00, 0x00, 0x00,
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

/* --- НАПРАВЛЕНИЕ ПО КРЮЧКУ, А НЕ ПО ПОРТУ ----------------------------------
 *
 * Пока весь периметр стоял на 443, направление выводилось из порта. Для любого
 * другого порта это неверно, и session.c это прямо называл: улика — номер
 * крючка netfilter, а не порт.
 *
 * Проверяется на голосовом порту Дискорда (50004, боевой профиль discord_udp),
 * потому что там порт уликой не работает вовсе: у клиента эфемерный порт, у
 * сервера 50004, и по одним портам сторону не назвать. */
static void test_direction_by_hook(void) {
    /* Клиент -> сервер: очередь на OUTPUT. Пакет обязан быть РАЗОБРАН как
       исходящий, то есть дойти до поиска плана, а не быть отброшенным на
       «направление по порту неизвестно». */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[256], buf[4096];
        d2k_result r;
        uint8_t voice[48];
        memset(voice, 0x90, sizeof voice);
        size_t n = build_udp_pkt(pkt, 64035, 50004, voice, sizeof voice);

        d2k_session_set_hook(s, D2K_HOOK_OUTPUT);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.skipped == NULL || strstr(r.skipped, "направление") == NULL,
              "исходящий пакет на голосовой порт отвергнут как «направление неизвестно», "
              "хотя крючок OUTPUT сторону называет прямо");
        d2k_session_free(s);
    }

    /* Активные зонды контроллера идут через NFQUEUE, чтобы проверить точный
       trial Plan. Но они не являются пользовательским трафиком: их SNI и
       молчание нельзя возвращать scheduler как новые цели/блокировки, а их
       ClientHello не должен перебить snapshot настоящего клиента. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        CHECK(s != NULL, "сессия для controller probe не создалась");
        d2k_plan *candidate = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &candidate,
                            err, sizeof err) == 0,
              "QUIC candidate для controller probe не загрузился");
        CHECK(d2k_plantab_set_name_probe(d2k_session_plans(s),
                  (const uint8_t *)"example.com", 11, 1, candidate,
                  D2K_PLAN_SHAPE_QUIC, htons(50001)) == 0,
              "exact-flow QUIC candidate не установился");
        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 50001, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet_probe(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied && r.n_out > 0,
              "controller probe не получил exact-flow trial Plan");
        for (size_t i = 0; i <= r.n_out; i++) {
            d2k_session_sent(s, 1100 + i, &r.key, r.execution_id);
        }
        CHECK(count_journal_kind(s, D2K_JRN_PLAN_DONE) == 1,
              "точное исполнение trial Plan на controller probe не дошло до DONE/APPLIED");
        CHECK(count_journal_kind(s, D2K_JRN_HELLO_SNI) == 0,
              "SNI собственного QUIC-зонда ушёл как пользовательский HELLO");
        CHECK(count_journal_kind(s, D2K_JRN_SUSPECT) == 0,
              "собственный QUIC-зонд породил пользовательское SUSPECT");
        CHECK(count_journal_kind(s, D2K_JRN_EXCHANGE) == 0,
              "ответ на собственный QUIC-зонд ушёл как пользовательский EXCHANGE");
        CHECK(count_plan_refused(s) == 0,
              "отсутствие пользовательских событий не должно журналировать отказ плана");
        CHECK(d2k_session_hellos(s) == 1,
              "controller probe обязан разбираться для точного применения trial Plan");
        CHECK(d2k_session_want_shape(s, (const uint8_t *)"example.com", 11, 17) == 0,
              "controller probe ошибочно выдан за клиентский QUIC snapshot");
        n = build_udp_pkt(pkt, 50002, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
        CHECK(d2k_session_want_shape(s, (const uint8_t *)"example.com", 11, 17) == 1,
              "реальный клиентский QUIC snapshot не удовлетворил ARM_SHAPE после probe");
        size_t shape_len = 0;
        const uint8_t *shape = d2k_session_shape(s, 17, &shape_len);
        /* Снимок QUIC — пачка полёта (задача 66): у одиночного Initial в ней
           одна датаграмма, и это ровно байты клиента. */
        d2k_qsnap probe_pack;
        CHECK(shape && d2k_qsnap_is(shape, shape_len) &&
              d2k_qsnap_parse(shape, shape_len, &probe_pack) == 0 &&
              probe_pack.n == 1 && probe_pack.len[0] == sizeof v1_initial &&
              memcmp(probe_pack.dg[0], v1_initial, sizeof v1_initial) == 0,
              "после controller probe вернута не исходная форма клиента");
        d2k_session_free(s);
    }

    /* Сервер -> клиент: очередь на INPUT. Разбирать как клиентский пакет
       нельзя ни при каком содержимом. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[256], buf[4096];
        d2k_result r;
        uint8_t voice[48];
        memset(voice, 0x90, sizeof voice);
        size_t n = build_udp_pkt(pkt, 50004, 64035, voice, sizeof voice);

        d2k_session_set_hook(s, D2K_HOOK_INPUT);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.skipped != NULL && strstr(r.skipped, "от сервера") != NULL,
              "входящий пакет не опознан как серверная сторона по крючку INPUT");
        d2k_session_free(s);
    }

    /* Крючок НЕ ЗАДАН — прежний вывод по порту, слово в слово. Иначе правка
       молча поменяла бы поведение всем, кто крючка не знает. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 50000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 1,
              "без крючка вывод по порту 443 перестал работать");
        d2k_session_free(s);
    }
}

/* QUIC is identified by its Initial form, not by a hard-coded destination
 * port.  A real netfilter hook is the direction proof for a non-443 service,
 * so split hold must accept an outgoing Initial to (for example) 8443 and
 * reject the corresponding incoming packet. */
static void test_quic_non443_client_hold(void) {
    d2k_session *s = d2k_session_new(64, 32);
    uint8_t pkt[1300];
    d2k_key key;
    size_t n = build_udp_pkt(pkt, 58101, 8443, v1_initial, sizeof v1_initial);
    CHECK(s != NULL, "non-443 hold session allocation");
    if (!s) return;
    d2k_session_set_hook(s, D2K_HOOK_OUTPUT);
    CHECK(d2k_session_udp_hold_begin(s, pkt, n, 1000, &key) == 1,
          "outgoing QUIC Initial on non-443 was rejected by port gate");
    d2k_session_udp_hold_end(s, &key);
    d2k_session_set_hook(s, D2K_HOOK_INPUT);
    CHECK(d2k_session_udp_hold_begin(s, pkt, n, 1100, NULL) == 0,
          "incoming non-443 QUIC was treated as client hold");
    d2k_session_free(s);

    /* The same hook evidence must survive the normal packet path, not only
       the pre-classification hold gate: an all-port firewall must be able to
       apply a compatible QUIC plan on 8443. */
    s = d2k_session_new(64, 32);
    d2k_plan *plan = NULL;
    char err[160];
    CHECK(s != NULL, "non-443 packet session allocation");
    if (!s) return;
    CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &plan, err, sizeof err) == 0,
          "non-443 QUIC plan load");
    d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11,
                         1, plan);
    uint8_t buf[4096];
    d2k_result res;
    d2k_session_set_hook(s, D2K_HOOK_OUTPUT);
    d2k_session_packet(s, pkt, n, 1200, buf, sizeof buf, &res);
    CHECK(res.applied == 1, "non-443 hook did not reach normal QUIC plan path");
    CHECK(d2k_session_hellos(s) == 1, "non-443 QUIC name was not classified");
    d2k_session_free(s);
}

/* Реальный ClientHello может быть разнесён по двум Initial и прийти хвостом
 * раньше головы. Датапат обязан держать состояние на 5-tuple, иначе такой
 * поток навсегда остаётся без имени и не доходит до общего поиска. */
static void test_quic_cross_datagram_assembly(void) {
    d2k_session *s = d2k_session_new(64, 32);
    d2k_plan *p = NULL;
    char plan_err[160];
    uint8_t head[2048], tail[2048], pkt[2200], buf[4096];
    d2k_result r;
    size_t head_len = 0, tail_len = 0;
    CHECK(s != NULL &&
          d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, plan_err, sizeof plan_err) == 0 &&
          d2k_plantab_set_name(d2k_session_plans(s),
                               (const uint8_t *)"www.microsoft.com",
                               sizeof "www.microsoft.com" - 1, 1, p) == 0 &&
          d2k_quic_hello_split(v1_initial, sizeof v1_initial,
                                "www.microsoft.com",
                                head, sizeof head, &head_len,
                                tail, sizeof tail, &tail_len) == 0,
          "не собрался fixture QUIC с двумя датаграммами");
    if (!s || head_len == 0 || tail_len == 0) {
        d2k_session_free(s);
        return;
    }
    size_t n = build_udp_pkt(pkt, 58100, 443, tail, tail_len);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(d2k_session_hellos(s) == 0,
          "один хвост QUIC ошибочно дал имя до головы");
    CHECK(!r.applied && r.n_out == 0,
          "неполный QUIC Initial получил общий план до сборки имени");
    n = build_udp_pkt(pkt, 58100, 443, head, head_len);
    d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
    CHECK(d2k_session_hellos(s) == 1,
          "ClientHello между датаграммами не дошёл до session");
    CHECK(r.applied && r.n_out > 0,
          "после сборки имени план не применился к распознанной QUIC-цели");
    d2k_session_free(s);
}

static void test_quic_flow_storage(void) {
    d2k_flow_protocol_storage storage;
    d2k_flow f = {.storage = &storage};
    int complete;
    char name[256];
    uint8_t first[1500], second[1500], bad[1500];
    size_t first_len, second_len;
    if (d2k_test_pq_initials("example.com", first, &first_len, second, &second_len)) {
        CHECK(0, "QUIC memory fixture");
        return;
    }
    CHECK(flow_quic_feed(&f, first, first_len, name, &complete) == 0 && !complete,
          "split ClientHello keeps its first fragment after flow admission");
    CHECK(flow_quic_feed(&f, second, second_len, name, &complete) == 1 &&
          complete && !strcmp(name, "example.com"),
          "split ClientHello must survive allocation pressure after flow admission");
    d2k_track_new_connection(&f);
    memcpy(bad, first, first_len);
    bad[first_len - 1] ^= 1;
    CHECK(flow_quic_feed(&f, bad, first_len, name, &complete) < 0 && !f.quic_assembly->active,
          "bad authentication does not leave an assembly behind");
    CHECK(flow_quic_feed(&f, first, first_len, name, &complete) == 0 &&
          !complete && f.quic_assembly, "incomplete authenticated Initial keeps its CRYPTO bytes");
    CHECK(flow_quic_feed(&f, second, second_len, name, &complete) == 1 &&
          complete && !strcmp(name, "example.com"), "completion uses the reserved buffer");
    CHECK(flow_quic_feed(&f, first, first_len, name, &complete) == 1 &&
          complete && !strcmp(name, "example.com"),
          "partial retransmit recovers the name");
    CHECK(flow_quic_feed(&f, bad, first_len, name, &complete) < 0 && !complete,
          "same DCID cannot reuse the completed name without authentication");
    memcpy(bad, v1_initial, sizeof v1_initial);
    bad[sizeof v1_initial - 1] ^= 1;
    CHECK(flow_quic_feed(&f, bad, sizeof v1_initial, name, &complete) < 0 &&
          !complete, "invalid new DCID does not displace a completed flight");
    CHECK(flow_quic_feed(&f, first, first_len, name, &complete) == 1 && complete &&
          !strcmp(name, "example.com"), "completed flight survives an invalid new DCID");
    d2k_track_new_connection(&f);
    CHECK(!f.quic_assembly, "new incarnation discarded the previous flight");
    CHECK(flow_quic_feed(&f, first, first_len, name, &complete) == 0 && !complete,
          "an old head fragment alone cannot identify the next connection");
}

/* СНИМОК QUIC — ВЕСЬ ПОЛЁТ КЛИЕНТА, А НЕ ПОСЛЕДНЯЯ ДАТАГРАММА (задача 66).
 *
 * Поле 15.10.2026: Chrome с постквантовым key_share шлёт ClientHello двумя
 * Initial. Снимком раньше становилась одна датаграмма — та, на которой
 * собралось имя, — и контроллер честно отвергал её как обрывок: цель уходила
 * мериться встроенным профилем, а планы, подтверждённые профилем, Chrome не
 * открывали. Снимок обязан нести обе датаграммы, по порядку и с их
 * размерами. */
static void test_quic_snapshot_is_every_initial(void) {
    d2k_session *s = d2k_session_new(64, 32);
    uint8_t d1[1500], d2[1500], pkt[2200], buf[4096];
    d2k_result r;
    size_t l1 = 0, l2 = 0;
    CHECK(s != NULL && d2k_test_pq_initials("rutracker.org", d1, &l1, d2, &l2) == 0,
          "не собрался стенд двух Initial");
    if (!s || !l1 || !l2) { d2k_session_free(s); return; }
    CHECK(d2k_session_want_shape_family(s, (const uint8_t *)"rutracker.org", 13, 17, 4) == 0,
          "ловушка снимка QUIC не взвелась");

    size_t n = build_udp_pkt(pkt, 50010, 443, d1, l1);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    size_t sl = 0;
    CHECK(d2k_session_shape_family(s, 17, 4, &sl) == NULL,
          "обрывок приветствия стал снимком до сборки имени");

    n = build_udp_pkt(pkt, 50010, 443, d2, l2);
    d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
    /* Повтор по таймеру PTO: та же датаграмма не удлиняет полёт. */
    d2k_session_packet(s, pkt, n, 1200, buf, sizeof buf, &r);

    /* ПОСЛЕ РУКОПОЖАТИЯ клиент шлёт по тому же DCID ещё Initial — с
       подтверждениями и без добивки до 1200. Они часть соединения, но не
       часть ПРИВЕТСТВИЯ: в пачке они делали полёт из двух датаграмм полётом
       из четырёх (поле 15.10.2026, lostfilm.tv). */
    {
        uint8_t later[1500], payload[16];
        memset(payload, 0x01, sizeof payload);   /* PING, не CRYPTO */
        size_t ll = d2k_test_pq_dgram(d1 + 6, 2, 0, payload, sizeof payload,
                                      later, sizeof later);
        if (ll) {
            n = build_udp_pkt(pkt, 50010, 443, later, ll);
            d2k_session_packet(s, pkt, n, 1300, buf, sizeof buf, &r);
        }
    }

    const uint8_t *sh = d2k_session_shape_family(s, 17, 4, &sl);
    CHECK(sh != NULL && d2k_qsnap_is(sh, sl), "снимок QUIC — не пачка");
    d2k_qsnap p;
    if (sh && d2k_qsnap_is(sh, sl) && d2k_qsnap_parse(sh, sl, &p) == 0) {
        CHECK(p.n == 2, "в снимке не обе датаграммы");
        CHECK(p.len[0] == l1 && p.len[1] == l2, "длины датаграмм снимка не те");
        CHECK(!memcmp(p.dg[0], d1, l1) && !memcmp(p.dg[1], d2, l2),
              "датаграммы снимка не те или не по порядку");
    } else {
        CHECK(0, "снимок не разбирается как пачка");
    }
    d2k_session_free(s);
}

/* ИМЯ В ПЕРВОЙ ДАТАГРАММЕ — ЕЩЁ НЕ ПРИВЕТСТВИЕ (поле 15.10.2026). Chrome
 * переставляет расширения, и имя бывает в первой датаграмме, а ClientHello
 * кончается во второй. Снимок по имени уходил пачкой из одной датаграммы,
 * и контроллер отвергал её: «не складывается в целое приветствие». Снимок
 * обязан ждать конца приветствия. */
static void test_quic_snapshot_waits_for_whole_hello(void) {
    d2k_session *s = d2k_session_new(64, 32);
    uint8_t d1[1500], d2[1500], pkt[2200], buf[4096];
    d2k_result r;
    size_t l1 = 0, l2 = 0;
    CHECK(s != NULL && d2k_test_pq_initials_sni_first("rutracker.org", d1, &l1, d2, &l2) == 0,
          "не собрался стенд: имя в первой датаграмме");
    if (!s || !l1 || !l2) { d2k_session_free(s); return; }
    CHECK(d2k_session_want_shape_family(s, (const uint8_t *)"rutracker.org", 13, 17, 4) == 0,
          "ловушка снимка QUIC не взвелась");
    size_t n = build_udp_pkt(pkt, 50020, 443, d1, l1);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    size_t sl = 0;
    CHECK(d2k_session_shape_family(s, 17, 4, &sl) == NULL,
          "снимок снят по имени, до конца приветствия");
    n = build_udp_pkt(pkt, 50020, 443, d2, l2);
    d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
    const uint8_t *sh = d2k_session_shape_family(s, 17, 4, &sl);
    d2k_qsnap p;
    CHECK(sh && d2k_qsnap_is(sh, sl) && d2k_qsnap_parse(sh, sl, &p) == 0 && p.n == 2 &&
          p.len[0] == l1 && p.len[1] == l2,
          "снимок целого приветствия — не обе датаграммы");
    d2k_session_free(s);
}

/* Чужое соединение, пришедшее между датаграммами полёта, в пачку не попадает:
 * склейка двух полётов дала бы приветствие, которого никто не слал. */
static void test_quic_snapshot_skips_other_flow(void) {
    d2k_session *s = d2k_session_new(64, 32);
    uint8_t a1[1500], a2[1500], b1[1500], b2[1500], pkt[2200], buf[4096];
    d2k_result r;
    size_t al1 = 0, al2 = 0, bl1 = 0, bl2 = 0;
    CHECK(s != NULL && d2k_test_pq_initials("rutracker.org", a1, &al1, a2, &al2) == 0 &&
          d2k_test_pq_initials("example.org", b1, &bl1, b2, &bl2) == 0, "стенды");
    if (!s || !al2 || !bl1) { d2k_session_free(s); return; }
    CHECK(d2k_session_want_shape_family(s, (const uint8_t *)"rutracker.org", 13, 17, 4) == 0,
          "ловушка");
    size_t n = build_udp_pkt(pkt, 50020, 443, a1, al1);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    n = build_udp_pkt(pkt, 50021, 443, b1, bl1);      /* другой поток */
    d2k_session_packet(s, pkt, n, 1050, buf, sizeof buf, &r);
    n = build_udp_pkt(pkt, 50020, 443, a2, al2);
    d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);

    size_t sl = 0;
    const uint8_t *sh = d2k_session_shape_family(s, 17, 4, &sl);
    d2k_qsnap p;
    CHECK(sh && d2k_qsnap_is(sh, sl) && d2k_qsnap_parse(sh, sl, &p) == 0 && p.n == 2 &&
          !memcmp(p.dg[0], a1, al1) && !memcmp(p.dg[1], a2, al2),
          "в пачке датаграммы чужого потока");
    d2k_session_free(s);
}

/* Ownership handoff for a split QUIC input: both original datagrams are held
 * while the name is incomplete, and the caller must replay the first original
 * after assembly.  Session must not apply the plan to the second (tail) piece. */
static void test_quic_split_hold_handshake(void) {
    d2k_session *s = d2k_session_new(64, 32);
    d2k_plan *p = NULL;
    char e[160];
    uint8_t head[2048], tail[2048], pkt[2200], buf[4096];
    d2k_result r;
    size_t hn = 0, tn = 0;
    CHECK(s && d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, e, sizeof e) == 0 &&
          d2k_plantab_set_name(d2k_session_plans(s),
                               (const uint8_t *)"www.microsoft.com", 17, 1, p) == 0 &&
          d2k_quic_hello_split(v1_initial, sizeof v1_initial, "www.microsoft.com",
                               head, sizeof head, &hn, tail, sizeof tail, &tn) == 0,
          "split hold fixture не собрался");
    if (!s || !hn || !tn) { d2k_session_free(s); return; }

    d2k_key key;
    size_t n = build_udp_pkt(pkt, 58200, 443, tail, tn);
    CHECK(d2k_session_udp_hold_begin(s, pkt, n, 1000, &key) == 1,
          "split QUIC hold не начал транзакцию");
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.udp_hold_wait && !r.applied && d2k_session_hellos(s) == 0,
          "хвост split QUIC применил план до сборки имени");

    n = build_udp_pkt(pkt, 58200, 443, head, hn);
    d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
    CHECK(r.udp_hold_ready && !r.applied && d2k_session_hellos(s) == 0,
          "голова split QUIC не запросила replay исходных датаграмм");

    d2k_session_udp_hold_end(s, &key);
    n = build_udp_pkt(pkt, 58200, 443, tail, tn);
    d2k_session_packet(s, pkt, n, 1200, buf, sizeof buf, &r);
    CHECK(r.applied && d2k_session_hellos(s) == 1,
          "replay первого оригинала не прошёл обычный plan path");
    CHECK(d2k_session_udp_hold_begin(s, pkt, n, 1300, NULL) == 0,
          "после Plan done поток снова ошибочно вошёл в UDP hold");
    d2k_session_free(s);
}

/* A held first Initial is replayed by d2kd after its ClientHello has been
 * assembled. That replay is still the first packet seen by conntrack; counting
 * the same datagram twice must not revoke the first-packet NAT exception. */
static void test_quic_held_initial_replay_is_first_packet(void) {
    d2k_nat_fn saved_nat = d2k_nat_hook;
    d2k_nat_hook = quic_nat_not_ready;
    d2k_session *s = d2k_session_new(64, 32);
    d2k_plan *p = NULL;
    char err[160];
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    CHECK(s && d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_name_shaped(d2k_session_plans(s),
                  (const uint8_t *)"example.com", 11, 1, p,
                  D2K_PLAN_SHAPE_QUIC) == 0,
          "QUIC held-replay plan fixture не собрался");
    if (!s) { d2k_nat_hook = saved_nat; return; }

    size_t n = build_udp_pkt(pkt, 50601, 443, v1_initial, sizeof v1_initial);
    d2k_key key;
    CHECK(d2k_session_udp_hold_begin(s, pkt, n, 1000, &key) == 1,
          "первый QUIC Initial не вошёл в hold");
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.udp_hold_ready && !r.applied,
          "собранный Initial не запросил replay исходной датаграммы");

    d2k_session_udp_hold_replay(s, &key);
    d2k_session_packet(s, pkt, n, 1001, buf, sizeof buf, &r);
    CHECK(r.applied && r.n_out > 0,
          "replay первого Initial ошибочно отвергнут как второй пакет без conntrack");
    d2k_session_free(s);
    d2k_nat_hook = saved_nat;
}

/* ЗАДАЧА 47, п. 0: QUIC/голос клиента с меткой маршрутизации — без плана,
 * без удержания (удерживать незачем: плана не будет, а 100 мс — чистая
 * задержка), без наблюдения. */
static void test_routed_client_gets_no_plan_udp(void) {
    d2k_session *s = d2k_session_new(64, 32);
    d2k_plan *p = NULL;
    char err[160];
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    CHECK(s && d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_name_shaped(d2k_session_plans(s), (const uint8_t *)"example.com", 11,
                                      1, p, D2K_PLAN_SHAPE_QUIC) == 0, "routed udp fixture");
    if (!s) { return; }
    size_t n = build_udp_pkt(pkt, 50711, 443, v1_initial, sizeof v1_initial);
    d2k_session_set_route_mark(s, 0xffffaaa);
    d2k_key key;
    CHECK(d2k_session_udp_hold_begin(s, pkt, n, 1000, &key) == 0, "a routed Initial is not held");
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(!r.applied && r.n_out == 0 && r.verdict == D2K_VERDICT_ACCEPT && r.routed_first,
          "routed Initial: no plan, kernel path, reported");
    CHECK(d2k_session_hellos(s) == 0, "no hello from a foreign path");
    CHECK(d2k_session_udp_opening(s, pkt, n) == 0, "a routed flow never opens a follow window");
    d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(!r.routed_first && !r.applied, "once per flow");
    d2k_session_set_route_mark(s, 0);
    n = build_udp_pkt(pkt, 50712, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 3000, buf, sizeof buf, &r);
    CHECK(r.applied, "unmarked client still planned");
    CHECK(d2k_session_routed_flows(s) == 1, "one routed flow counted");
    d2k_session_free(s);
}

/* ЗАДАЧА 46: ПЕРВАЯ ДАТАГРАММА НЕ ЧИТАЕТ ТАБЛИЦУ CONNTRACK.
 *
 * Поле 03.10.2026: спланированный QUIC Initial уходил через 42 мс (против
 * ~1 мс без плана), и все 42 мс — три полных чтения /proc/net/nf_conntrack
 * по ~14 мс на роутере, каждое заведомо пустое: запись первой датаграммы не
 * подтверждена, пока она сама стоит в очереди, а ответ для первого пакета
 * всё равно «можно». Хвосты потока всё это время ждали в очереди со своей
 * неподтверждённой записью. Чтение остаётся для непервых пакетов. */
static unsigned nat_lookups;
static int quic_nat_counting(const char *path, uint8_t proto,
                             uint32_t src, uint16_t sport,
                             uint32_t dst, uint16_t dport,
                             uint32_t *outside_src, uint16_t *outside_sport) {
    (void)path; (void)proto; (void)src; (void)sport;
    (void)dst; (void)dport; (void)outside_src; (void)outside_sport;
    nat_lookups++;
    return -1;
}

static void test_quic_first_packet_skips_conntrack_scan(void) {
    d2k_nat_fn saved_nat = d2k_nat_hook;
    d2k_nat_hook = quic_nat_counting;
    d2k_session *s = d2k_session_new(64, 32);
    d2k_plan *p = NULL;
    char err[160];
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    CHECK(s && d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_name_shaped(d2k_session_plans(s),
                  (const uint8_t *)"example.com", 11, 1, p,
                  D2K_PLAN_SHAPE_QUIC) == 0,
          "first-packet scan fixture");
    if (!s) { d2k_nat_hook = saved_nat; return; }

    /* Held and replayed first Initial (the d2kd path). */
    size_t n = build_udp_pkt(pkt, 50611, 443, v1_initial, sizeof v1_initial);
    d2k_key key;
    nat_lookups = 0;
    CHECK(d2k_session_udp_hold_begin(s, pkt, n, 1000, &key) == 1, "hold begins");
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.udp_hold_ready, "assembled Initial asks for replay");
    d2k_session_udp_hold_replay(s, &key);
    d2k_session_packet(s, pkt, n, 1001, buf, sizeof buf, &r);
    CHECK(r.applied && r.n_out > 0, "the held first Initial still gets its plan");
    CHECK(nat_lookups == 0,
          "the first datagram must not scan conntrack: its entry is unconfirmed by construction");

    /* Unheld first Initial (direct path). */
    n = build_udp_pkt(pkt, 50612, 443, v1_initial, sizeof v1_initial);
    nat_lookups = 0;
    d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(r.applied && nat_lookups == 0, "direct first Initial: plan, no scan");

    /* A later packet that gets a plan (retransmit after a lost original)
       still proves its conntrack entry. */
    d2k_session_sent(s, 2001, &r.key, r.execution_id);
    (void)d2k_session_exec_failed(s, 2002, &r.key, r.plan_id, D2K_REFUSE_SEND,
                                  r.execution_id, 0, 0);
    nat_lookups = 0;
    d2k_session_packet(s, pkt, n, 300002000ull, buf, sizeof buf, &r);
    CHECK(nat_lookups > 0 && !r.applied,
          "a non-first packet without a conntrack entry is still refused");
    d2k_session_free(s);
    d2k_nat_hook = saved_nat;
}

/* ЗАДАЧА 42: ОРИГИНАЛ ПОСЛЕ ФАЛЬШИВОК УХОДИТ НАШЕЙ ПОСЫЛКОЙ.
 *
 * Поле 02.10.2026 (задача 33): сырые фальшивки создают и подтверждают запись
 * conntrack первой датаграммы, пока оригинал ещё в NFQUEUE со своей
 * неподтверждённой записью; после ACCEPT ядро снимает его как дубль
 * (insert_failed/drop), и настоящий Initial не уходит вовсе. Значит оригинал
 * — последняя посылка самого плана, а копия в очереди снимается. */
static void test_quic_original_after_fakes(void) {
    d2k_session *s = d2k_session_new(64, 32);
    d2k_plan *p = NULL;
    char err[160];
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    CHECK(s && d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, 1, p) == 0,
          "original-after-fakes fixture");
    if (!s) { return; }

    /* 1. Порядок на проводе: фальшивки, затем оригинал целиком; копия снята. */
    size_t n = build_udp_pkt(pkt, 51700, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.applied && r.n_out == 3 && r.verdict == D2K_VERDICT_DROP,
          "fakes then our own original; the queued copy is dropped");
    CHECK(r.first_payload == 2, "the original is the last emit, after every fake");
    if (r.n_out == 3) {
        const uint8_t *o = buf + r.out[2].off;
        CHECK(r.out[2].len == n && r.out[2].delay_us == 0,
              "original whole, right after the last fake");
        CHECK(!memcmp(o + 12, pkt + 12, 8) && !memcmp(o + 20, pkt + 20, 4),
              "original keeps the client tuple (kernel NAT follows the fakes' entry)");
        CHECK(o[8] == pkt[8], "original keeps the client TTL");
        CHECK(!memcmp(o + 28, v1_initial, sizeof v1_initial), "original bytes unchanged");
        CHECK(r.out[0].len == 31 && r.out[1].len == 31, "fakes unchanged");
    }
    /* Всё ушло — исполнение доведено, повтор Initial плана не получает. */
    for (size_t i = 0; i <= r.n_out; i++) d2k_session_sent(s, 1001 + i, &r.key, r.execution_id);
    CHECK(d2k_session_done(s) == 1, "fakes + original + verdict complete the execution");
    d2k_session_packet(s, pkt, n, 1300000000ull, buf, sizeof buf, &r);
    CHECK(!r.applied && r.n_out == 0 && r.verdict == D2K_VERDICT_ACCEPT,
          "a retransmit after a completed execution passes untouched");

    /* 2. Фальшивка ушла, дальше отказ — оригинал отдан ядру после неё и
          снят conntrack. Повтор Initial того же потока обязан получить план. */
    n = build_udp_pkt(pkt, 51701, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(r.applied && r.n_out == 3, "second flow applied");
    d2k_session_sent(s, 2001, &r.key, r.execution_id);
    CHECK(d2k_session_exec_failed(s, 2002, &r.key, r.plan_id, D2K_REFUSE_SEND,
                                  r.execution_id, 0, 0) == 1,
          "nothing of the payload left: the original is still released");
    uint64_t first_exec = r.execution_id;
    d2k_session_packet(s, pkt, n, 300002000ull, buf, sizeof buf, &r);
    CHECK(r.applied && r.n_out == 3 && r.verdict == D2K_VERDICT_DROP,
          "the client's Initial retransmit gets the plan when the original was lost");
    CHECK(r.execution_id != first_exec, "the retransmit is a new execution");
    CHECK(d2k_session_applied(s) == 3, "applied counts each real execution");
    d2k_session_packet(s, pkt, n, 600002000ull, buf, sizeof buf, &r);
    CHECK(!r.applied, "the plan is not reapplied once the retransmit got it");

    /* 3. Отложенная посылка не ушла после вердикта DROP: оригинала нет ни в
          очереди, ни на проводе. Датаграмма атомарна — поток не испорчен,
          повтор Initial получает план. */
    n = build_udp_pkt(pkt, 51702, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 3000, buf, sizeof buf, &r);
    CHECK(r.applied && r.verdict == D2K_VERDICT_DROP, "third flow applied");
    d2k_session_sent(s, 3001, &r.key, r.execution_id); /* first fake */
    d2k_session_sent(s, 3002, &r.key, r.execution_id); /* verdict */
    size_t damaged_before = d2k_session_damaged_count(s);
    (void)d2k_session_exec_failed(s, 3003, &r.key, NULL, D2K_REFUSE_SEND,
                                  r.execution_id, 0, 1);
    CHECK(d2k_session_damaged_count(s) == damaged_before,
          "a lost QUIC original is not a damaged stream: the client retransmits it whole");
    d2k_session_packet(s, pkt, n, 300003000ull, buf, sizeof buf, &r);
    CHECK(r.applied && r.n_out == 3,
          "the retransmit gets the plan after a deferred send failed");

    /* 4. Отказ до единой посылки: оригинал ушёл ядром как обычно, гонки не
          было — повтор плана не получает. */
    n = build_udp_pkt(pkt, 51703, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 4000, buf, sizeof buf, &r);
    CHECK(r.applied, "fourth flow applied");
    CHECK(d2k_session_exec_failed(s, 4001, &r.key, r.plan_id, D2K_REFUSE_TOO_LONG,
                                  r.execution_id, 0, 0) == 1, "clean refusal");
    d2k_session_packet(s, pkt, n, 300004000ull, buf, sizeof buf, &r);
    CHECK(!r.applied, "nothing raced the original: no second execution");
    d2k_session_free(s);
}

/* Задача 40: план «разрез ClientHello на кадры CRYPTO». Исполнение — одна
 * посылка: наш собственный Initial той же длины с переложенными кадрами, копия
 * в очереди снимается (порядок задачи 42: оригинал уходит нашей посылкой).
 * Повтор Initial после завершённого исполнения идёт нетронутым, как у любого
 * плана QUIC. */
static const uint8_t plan_qsplit[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 10, 0, 0, 0, 3,
    0x00, 0x02, 0x00, 0x02, 17, 2,
    0x01, 0x03, 0x00, 0x01, 0x00,
    0x01, 0x0f, 0x00, 0x01, 0x01
};

/* Задача 40, круг 1 (I1): ClientHello размера Chrome с ML-KEM, имя во
 * второй датаграмме. Hold собирает имя и просит replay первой датаграммы;
 * разрез на ней невыполним честно — явный отказ в журнале, план не
 * «применён», датаграммы уходят как есть. */
static void test_quic_crypto_split_name_in_second(void) {
    d2k_session *s = d2k_session_new(64, 32);
    d2k_plan *p = NULL;
    char err[160];
    uint8_t d1[1500], d2[1500], pkt[1600], buf[4096];
    size_t l1 = 0, l2 = 0;
    d2k_result r;
    CHECK(s && d2k_plan_load(plan_qsplit, sizeof plan_qsplit, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, 1, p) == 0 &&
          d2k_test_pq_initials("example.com", d1, &l1, d2, &l2) == 0,
          "split/PQ fixture");
    if (!s || !l1) { d2k_session_free(s); return; }
    size_t refused0 = count_plan_refused(s);
    d2k_key key;
    size_t n = build_udp_pkt(pkt, 51900, 443, d1, l1);
    CHECK(d2k_session_udp_hold_begin(s, pkt, n, 1000, &key) == 1, "PQ: hold began");
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.udp_hold_wait && !r.applied, "PQ: datagram 1 held, no name yet");
    n = build_udp_pkt(pkt, 51900, 443, d2, l2);
    d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
    CHECK(r.udp_hold_ready && !r.applied, "PQ: name assembled, replay requested");
    d2k_session_udp_hold_replay(s, &key);
    n = build_udp_pkt(pkt, 51900, 443, d1, l1);
    d2k_session_packet(s, pkt, n, 1200, buf, sizeof buf, &r);
    CHECK(!r.applied && r.n_out == 0 && r.verdict == D2K_VERDICT_ACCEPT,
          "PQ: split not applied to datagram 1, it passes as is");
    CHECK(count_plan_refused(s) == refused0 + 1, "PQ: refusal counted in the journal");
    CHECK(r.skipped && strstr(r.skipped, "имени нет"), "PQ: refusal reason is explicit");
    d2k_session_free(s);
}

static void test_quic_crypto_split_plan(void) {
    d2k_session *s = d2k_session_new(64, 32);
    d2k_plan *p = NULL;
    char err[160];
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    CHECK(s && d2k_plan_load(plan_qsplit, sizeof plan_qsplit, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, 1, p) == 0,
          "crypto-split plan fixture");
    if (!s) { return; }
    size_t n = build_udp_pkt(pkt, 51800, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.applied && r.n_out == 1 && r.verdict == D2K_VERDICT_DROP && r.first_payload == 0,
          "crypto split: one own Initial, the queued copy is dropped");
    if (r.n_out == 1) {
        const uint8_t *o = buf + r.out[0].off;
        uint8_t want[1500];
        size_t want_len = 0;
        char name[64];
        CHECK(r.out[0].len == n && r.out[0].delay_us == 0, "same datagram length, no delay");
        CHECK(!memcmp(o + 12, pkt + 12, 8) && !memcmp(o + 20, pkt + 20, 4) && o[8] == pkt[8],
              "client tuple and TTL kept");
        CHECK(d2k_quic_initial_split_crypto(v1_initial, sizeof v1_initial, want, sizeof want,
                                            &want_len) == 0 &&
              !memcmp(o + 28, want, want_len), "wire bytes are the core split (what was measured)");
        CHECK(memcmp(o + 28, v1_initial, sizeof v1_initial) != 0, "the Initial did change");
        CHECK(d2k_quic_sni(o + 28, r.out[0].len - 28, name, sizeof name) == 0 &&
              !strcmp(name, "example.com"), "server assembles the same name");
    }
    for (size_t i = 0; i <= r.n_out; i++) d2k_session_sent(s, 1001 + i, &r.key, r.execution_id);
    CHECK(d2k_session_done(s) == 1, "split Initial + verdict complete the execution");
    d2k_session_packet(s, pkt, n, 1300000000ull, buf, sizeof buf, &r);
    CHECK(!r.applied && r.n_out == 0 && r.verdict == D2K_VERDICT_ACCEPT,
          "a retransmit after a completed split execution passes untouched");
    d2k_session_free(s);
}

/* После QUIC Retry клиент начинает новый Initial с новым DCID. Старый
 * stateful-контекст не должен отбрасывать такой пакет как «чужой» и оставлять
 * поток без имени навсегда. */
static void test_quic_retry_resets_assembly(void) {
    d2k_session *s = d2k_session_new(64, 32);
    uint8_t head[2048], tail[2048], retry[2048], pkt[2200], buf[4096];
    d2k_result r;
    size_t head_len = 0, tail_len = 0, retry_len = 0;
    CHECK(s != NULL &&
          d2k_quic_hello_split(v1_initial, sizeof v1_initial,
                                "www.microsoft.com",
                                head, sizeof head, &head_len,
                                tail, sizeof tail, &tail_len) == 0 &&
          d2k_quic_probe_initial("www.microsoft.com", retry, sizeof retry,
                                 &retry_len) == 0,
          "не собрался Retry fixture с новым DCID");
    if (!s || !tail_len || !retry_len) {
        d2k_session_free(s);
        return;
    }
    size_t n = build_udp_pkt(pkt, 58110, 443, tail, tail_len);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(d2k_session_hellos(s) == 0,
          "хвост до Retry ошибочно дал имя");
    n = build_udp_pkt(pkt, 58110, 443, retry, retry_len);
    d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
    CHECK(d2k_session_hellos(s) == 1 && d2k_session_with_sni(s) == 1,
          "новый Initial после Retry не сбросил старый QUIC assembly context");
    d2k_session_free(s);
}

/* --- ГОЛОС ДИСКОРДА: первый пакет потока — IP Discovery -------------------
 *
 * Ровно 74 байта: тип 0x0001, длина 70, SSRC, 64 нулевых байта адреса, порт
 * (IsDiscordIpDiscoveryRequest в nfq2/protocol.c движка z2k). По нему боевой
 * профиль discord_udp и узнаёт голос (--filter-l7=discord,
 * --payload=discord_ip_discovery), и фальшивку ставит ПЕРЕД ним. */
static size_t build_ip_discovery(uint8_t *p, uint32_t ssrc) {
    memset(p, 0, 74);
    p[1] = 1;
    p[3] = 70;
    p[4] = (uint8_t)(ssrc >> 24); p[5] = (uint8_t)(ssrc >> 16);
    p[6] = (uint8_t)(ssrc >> 8);  p[7] = (uint8_t)ssrc;
    return 74;
}

/* Настоящий ответ IP Discovery: та же сигнатура, но адрес и порт уже
 * заполнены. Нулевой адрес — это только запрос и не может быть доказательством
 * работы голосового потока. */
static size_t build_ip_discovery_response(uint8_t *p, uint32_t ssrc) {
    size_t n = build_ip_discovery(p, ssrc);
    p[1] = 2; /* ответ — тип 0x0002; 0x0001 — запрос */
    memcpy(p + 8, "203.0.113.7", 11);
    p[72] = 0xC3; p[73] = 0x50; /* 50000 */
    return n;
}

static size_t build_stun_binding(uint8_t *p, uint16_t type, const uint8_t txid[12]) {
    memset(p, 0, 20);
    p[0] = (uint8_t)(type >> 8); p[1] = (uint8_t)type;
    p[4] = 0x21; p[5] = 0x12; p[6] = 0xa4; p[7] = 0x42;
    memcpy(p + 8, txid, 12);
    if (type == 0x0101) {
        /* A success fixture includes the mandatory mapped address. */
        memset(p + 20, 0, 12); wr16(p + 2, 12);
        wr16(p + 20, 0x0020); wr16(p + 22, 8);
        p[25] = 1; wr16(p + 26, (uint16_t)(50000 ^ 0x2112));
        return 32;
    }
    return 20;
}

/* Тот же поток со стороны сервера: концы и порты меняются местами. */
static void swap_udp_ends(uint8_t *pkt) {
    uint8_t t[4];
    memcpy(t, pkt + 12, 4); memcpy(pkt + 12, pkt + 16, 4); memcpy(pkt + 16, t, 4);
    memcpy(t, pkt + 20, 2); memcpy(pkt + 20, pkt + 22, 2); memcpy(pkt + 22, t, 2);
}

static size_t count_kind_name(const d2k_session *s, uint8_t kind, const char *name) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j), c = 0;
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (!e || e->kind != kind) { continue; }
        if (name && (e->name_len != strlen(name) || memcmp(e->name, name, e->name_len) != 0)) {
            continue;
        }
        c++;
    }
    return c;
}

/* Тот же план, что plan_bytes, но с объявленным протоколом голоса: REC_PROTO,
 * транспорт 17, прикладной протокол 3 («voice» в тексте плана). Ровно такой
 * план собирает контроллер (d2k_voice_plan). */
static const uint8_t plan_voice_declared[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 5,
    0x00, 0x02, 0x00, 0x02, 0x11, 0x03,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x00, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* --- БЕЗЫМЯННЫЙ INITIAL: план по адресу и общий план ----------------------
 *
 * Поле 19.09.2026: настоящий клиент (curl/ngtcp2) разбрасывает ClientHello по
 * множеству мелких кадров CRYPTO, идущих в разнобой, поперёк ДВУХ
 * Initial-датаграмм. Разбор собирает CRYPTO только внутри одной датаграммы и
 * держит восемь кусков, поэтому имя не извлекается ни из одной. Датапат при
 * этом выходил РАНЬШЕ поиска плана — «имя не извлечено из Initial», — и к
 * такому потоку не применялся НИКАКОЙ план, даже поставленный по адресу или
 * общий. За прогон это дало «узнано приветствий 0» при 91 ушедшей датаграмме.
 *
 * Имя мы по-прежнему не выдумываем: приветствием такой пакет не считается,
 * снимок с него не снимается, в журнал имя не идёт. Но план, который про имя
 * не спрашивает, применить обязаны. */
static void test_nameless_initial(void) {
    /* Initial с испорченной нагрузкой: заголовок разбирается (клиентский
       Initial), а расшифровка не сходится — ровно то же, что даёт разбросанный
       по датаграммам ClientHello. */
    static uint8_t blind[sizeof v1_initial];
    memcpy(blind, v1_initial, sizeof blind);
    blind[sizeof blind - 1] ^= 0xff;   /* тег AEAD не сойдётся */
    CHECK(d2k_quic_is_initial(blind, sizeof blind),
          "испорченная нагрузка сломала и заголовок — набор негоден");
    {
        char nm[256];
        CHECK(d2k_quic_sni(blind, sizeof blind, nm, sizeof nm) != 0,
              "имя всё-таки извлеклось — проверять нечего");
    }

    /* ОБЩИЙ план (--plan у службы) обязан достаться такому потоку. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0,
              "общий план не загрузился");
        d2k_session_set_plan(s, p);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 51600, 443, blind, sizeof blind);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied, "общий план не применён к безымянному Initial");
        /* Приветствием он не объявлен: имени нет, и выдумывать его нельзя. */
        CHECK(d2k_session_hellos(s) == 0,
              "безымянный Initial засчитан приветствием — имени у него нет");
        d2k_session_free(s);
    }

    /* План ПО АДРЕСУ — тоже. Имя для него не нужно по построению. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0,
              "план по адресу не загрузился");
        uint32_t dst;
        uint8_t d[4] = {1, 2, 3, 4};
        memcpy(&dst, d, 4);
        d2k_plantab_set_addr(d2k_session_plans(s), dst, 1, p);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 51601, 443, blind, sizeof blind);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied, "план по адресу не применён к безымянному Initial");
        d2k_session_free(s);
    }
}

/* --- МОЛЧАНИЕ ПО БЕЗЫМЯННОМУ INITIAL ТОЖЕ ПОДОЗРИТЕЛЬНО ------------------
 *
 * Поле 19.09.2026: настоящий клиент разбрасывает ClientHello так, что имя из
 * него не читается. Разбор такого пакета приветствием не считает — и правильно,
 * имени нет, — но и молчание по нему никем не замечалось: развёртка требовала
 * saw_hello. Выходило «узнано приветствий 0, подозрений 0» при 91 ушедшей
 * датаграмме: контроллер о беде не узнавал вовсе и цель по адресу не искал. */
static void test_nameless_silence(void) {
    const uint64_t s_ns = 1000000000ull;
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    const uint8_t any[4] = { 0xAA, 0xBB, 0xCC, 0xDD };

    static uint8_t blind[sizeof v1_initial];
    memcpy(blind, v1_initial, sizeof blind);
    blind[sizeof blind - 1] ^= 0xff;   /* имя не извлечётся */

    d2k_session *s = d2k_session_new(64, 64);
    /* Крючок НЕ задаём: направление называет порт 443, как в соседних
       проверках. С крючком POSTROUTING ответ сервера тоже стал бы
       «исходящим», и обратная сторона осталась бы невидимой. */
    /* Обратная сторона видна — иначе молчащим выглядит каждый поток. */
    size_t n = build_udp_rev_pkt(pkt, 50200, any, sizeof any);
    d2k_session_packet(s, pkt, n, 1 * s_ns, buf, sizeof buf, &r);

    n = build_udp_pkt(pkt, 50201, 443, blind, sizeof blind);
    d2k_session_packet(s, pkt, n, 2 * s_ns, buf, sizeof buf, &r);
    CHECK(d2k_session_hellos(s) == 0,
          "безымянный Initial засчитан приветствием — имени у него нет");
    /* Повтор по таймеру PTO: клиент всё ещё ждёт ответа. */
    d2k_session_packet(s, pkt, n, 3 * s_ns, buf, sizeof buf, &r);

    CHECK(d2k_session_sweep(s, 3 * s_ns + 900000000ull) == 0,
          "неполные две секунды молчания объявлены блокировкой");
    CHECK(d2k_session_sweep(s, 4 * s_ns + 100000000ull) == 1,
          "молчание по безымянному Initial не замечено — контроллер о беде не узнает");
    CHECK(d2k_session_suspects(s) == 1, "подозрение не отмечено");
    d2k_session_free(s);
}

/* --- ОТВЕТ ПО БЕЗЫМЯННОМУ ПОТОКУ — ТОЖЕ ОБМЕН ---------------------------
 *
 * Поле 19.09.2026, вторая половина: учёт обратной стороны и событие обмена
 * стояли на saw_hello, которого у безымянного потока нет. Выходило сразу два
 * вранья: успешные потоки выглядели молчащими («подозрений 8 при восьми
 * ответах»), а подтверждать адресную цель было нечем — «обменов 0». */
static void test_nameless_exchange(void) {
    const uint64_t s_ns = 1000000000ull;
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    static uint8_t blind[sizeof v1_initial];
    memcpy(blind, v1_initial, sizeof blind);
    blind[sizeof blind - 1] ^= 0xff;

    d2k_session *s = d2k_session_new(64, 64);
    size_t n = build_udp_pkt(pkt, 50301, 443, blind, sizeof blind);
    d2k_session_packet(s, pkt, n, 1 * s_ns, buf, sizeof buf, &r);
    /* Сервер ответил по ЭТОМУ же потоку. */
    const uint8_t any[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    n = build_udp_rev_pkt(pkt, 50301, any, sizeof any);
    d2k_session_packet(s, pkt, n, 1 * s_ns + 50000000ull, buf, sizeof buf, &r);

    CHECK(count_kind_name(s, D2K_JRN_EXCHANGE, NULL) == 1,
          "ответ по безымянному потоку не дал события обмена — подтверждать нечем");
    /* И молчащим такой поток больше не выглядит. */
    d2k_session_packet(s, pkt, n, 2 * s_ns, buf, sizeof buf, &r);
    CHECK(d2k_session_sweep(s, 10 * s_ns) == 0,
          "поток, по которому пришёл ответ, объявлен молчащим");
    CHECK(d2k_session_suspects(s) == 0, "подозрение по отвечающему потоку");
    d2k_session_free(s);
}

static void test_discord_voice(void) {
    /* STUN Binding — тот же voice-контекст, но отдельная строгая сигнатура и
       отдельное подтверждение ответа по transaction ID. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        uint8_t stun[32], txid[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
        uint8_t pkt[256], buf[4096];
        d2k_result r;
        CHECK(d2k_plan_load(plan_voice_declared, sizeof plan_voice_declared, &p,
                            err, sizeof err) == 0 &&
              d2k_plantab_set_name_shaped(d2k_session_plans(s),
                                          (const uint8_t *)D2K_VOICE_CLASS,
                                          strlen(D2K_VOICE_CLASS), 1, p,
                                          D2K_PLAN_SHAPE_VOICE) == 0,
              "STUN voice plan не загрузился");
        size_t sn = build_stun_binding(stun, 0x0001, txid);
        /* Медиапорт Дискорда: STUN на него — голосовой класс (задача 17;
           STUN на прочие порты класса не получает, см. test_stun_session). */
        size_t n = build_udp_pkt(pkt, 64041, 50004, stun, sn);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied && d2k_session_hellos(s) == 1,
              "STUN Binding Request не пошёл в voice Plan");
        CHECK(count_kind_name(s, D2K_JRN_HELLO_SNI, D2K_VOICE_CLASS) == 1,
              "STUN не назван классом voice");
        d2k_session_free(s);
    }
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t req[32], resp[32], txid[12] = {11,10,9,8,7,6,5,4,3,2,1,0};
        uint8_t pkt[256], buf[4096];
        d2k_result r;
        size_t rn = build_stun_binding(req, 0x0001, txid);
        size_t n = build_udp_pkt(pkt, 64042, 3478, req, rn);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        size_t sn = build_stun_binding(resp, 0x0101, txid);
        uint8_t wrong[12];
        memcpy(wrong, txid, sizeof wrong);
        wrong[0] ^= 0xff;
        uint8_t wrong_resp[32];
        size_t wn = build_stun_binding(wrong_resp, 0x0101, wrong);
        n = build_udp_rev_pkt(pkt, 64042, wrong_resp, wn);
        wr16(pkt + 20, 3478);
        d2k_session_set_hook(s, D2K_HOOK_FORWARD);
        d2k_session_packet(s, pkt, n, 1100, buf, sizeof buf, &r);
        int wrong_stun_code = 0;
        const d2k_journal *wj = d2k_session_journal(s);
        for (size_t i = 0; i < d2k_journal_count(wj); i++) {
            const d2k_jrn_entry *e = d2k_journal_at(wj, i);
            if (e && e->kind == D2K_JRN_EXCHANGE && e->code == D2K_UDP_PROOF_STUN) {
                wrong_stun_code = 1;
            }
        }
        CHECK(!wrong_stun_code,
              "STUN response с чужим transaction ID ошибочно дал protocol proof");
        n = build_udp_rev_pkt(pkt, 64042, resp, sn);
        wr16(pkt + 20, 3478);
        d2k_session_packet(s, pkt, n, 1200, buf, sizeof buf, &r);
        const d2k_journal *j = d2k_session_journal(s);
        size_t exchanges = count_kind_name(s, D2K_JRN_EXCHANGE, NULL);
        int stun_code = 0;
        for (size_t i = 0; i < d2k_journal_count(j); i++) {
            const d2k_jrn_entry *e = d2k_journal_at(j, i);
            if (e && e->kind == D2K_JRN_EXCHANGE && e->code == D2K_UDP_PROOF_STUN) {
                stun_code = 1;
            }
        }
        CHECK(exchanges == 2 && stun_code, "STUN response не дал transaction-bound proof");
        d2k_session_free(s);
    }
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t bad[20] = {0}, pkt[256], buf[4096];
        d2k_result r;
        bad[4] = 0x21; bad[5] = 0x12; bad[6] = 0xa4; bad[7] = 0x42;
        size_t n = build_udp_pkt(pkt, 64043, 3478, bad, sizeof bad);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 0, "неполный STUN ошибочно признан voice");
        d2k_session_free(s);
    }
    /* План, объявленный голосом, датапат принимает и голосу отдаёт. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_voice_declared, sizeof plan_voice_declared, &p,
                            err, sizeof err) == 0,
              "план с объявленным протоколом голоса не загрузился");
        d2k_plantab_set_name_shaped(d2k_session_plans(s), (const uint8_t *)D2K_VOICE_CLASS,
                                    strlen(D2K_VOICE_CLASS), 1, p, D2K_PLAN_SHAPE_VOICE);
        uint8_t pkt[256], buf[4096], disc[74];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 64040, 50004, disc, build_ip_discovery(disc, 0x55));
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied, "план, объявленный голосом, голосу не применён");
        d2k_session_free(s);
    }
    /* Узнан — и назван КЛАССОМ, а не доменом. Имени у голоса нет (D2K_SPEC:
       адресным целям домен не придумывать); «@» в DNS-имени невозможна, так
       что за имя сайта этот ярлык не сойдёт ни при каком разборе. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[256], buf[4096], disc[74];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 64035, 50004, disc, build_ip_discovery(disc, 0x1234));
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 1, "IP Discovery Дискорда не узнан как начало голоса");
        CHECK(count_kind_name(s, D2K_JRN_HELLO_SNI, D2K_VOICE_CLASS) == 1,
              "голос не назван своим классом в журнале");
        d2k_session_free(s);
    }
    /* Похожее, но не то: адрес в запросе не нулевой. Это уже не запрос
       IP Discovery, и голосом его объявлять нельзя. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[256], buf[4096], disc[74];
        d2k_result r;
        build_ip_discovery(disc, 0x1234);
        disc[20] = 0x31;
        size_t n = build_udp_pkt(pkt, 64036, 50004, disc, sizeof disc);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(s) == 0, "пакет с ненулевым адресом принят за IP Discovery");
        d2k_session_free(s);
    }
    /* План голоса — под СВОЕЙ формой. План той же метки под формой QUIC
       голосу не достаётся: подтверждён он был не на нём. */
    for (int own = 1; own >= 0; own--) {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0,
              "план голоса не загрузился");
        d2k_plantab_set_name_shaped(d2k_session_plans(s), (const uint8_t *)D2K_VOICE_CLASS,
                                    strlen(D2K_VOICE_CLASS), 1, p,
                                    own ? D2K_PLAN_SHAPE_VOICE : D2K_PLAN_SHAPE_QUIC);
        uint8_t pkt[256], buf[4096], disc[74];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 64037, 50004, disc, build_ip_discovery(disc, 0x77));
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        if (own) {
            CHECK(r.applied && r.n_out >= 2, "план голоса не применён к IP Discovery");
        } else {
            CHECK(!r.applied, "план формы QUIC достался голосу");
        }
        d2k_result request=r;
        d2k_plan *replacement=NULL;
        CHECK(!d2k_plan_load(plan_bytes,sizeof plan_bytes,&replacement,err,sizeof err),
              "Discovery replacement plan loads");
        CHECK(!d2k_plantab_set_name_shaped(d2k_session_plans(s),
              (const uint8_t *)D2K_VOICE_CLASS,strlen(D2K_VOICE_CLASS),1001,
              replacement,D2K_PLAN_SHAPE_VOICE),"Discovery replacement installs");
        n=build_udp_rev_pkt(pkt,64037,disc,build_ip_discovery_response(disc,0x77));
        wr16(pkt+20,50004);
        d2k_session_set_hook(s,D2K_HOOK_FORWARD);
        d2k_session_packet(s,pkt,n,2000,buf,sizeof buf,&r);
        const d2k_journal *j=d2k_session_journal(s);int found=0;
        for(size_t i=0;i<d2k_journal_count(j);i++) {
            const d2k_jrn_entry *e=d2k_journal_at(j,i);
            if(e->kind!=D2K_JRN_EXCHANGE || e->code!=D2K_UDP_PROOF_VOICE_DISCOVERY)continue;
            found=1;
            CHECK(e->execution_id==request.execution_id &&
                  (!own || d2k_binding_equal(&e->binding,&request.binding)),
                  "Discovery response rebound to later plan");
            CHECK(e->num==74,"Discovery context loses response size");
        }
        CHECK(found,"Discovery response context emitted");
        d2k_session_free(s);
    }
    /* ОТВЕТ СЕРВЕРА — СОБЫТИЕ ОБМЕНА, и приходит он на FORWARD.
       Подтвердить приём голоса своим зондом нечем (точка молчит посторонним),
       значит подтверждает только ответ по потоку самого клиента. На FORWARD
       сторону не назвать ни крючком, ни портом (голос не на 443) — зато поток
       уже знает, кто его начал: клиент показал IP Discovery. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[256], buf[4096], disc[74];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 64038, 50004, disc, build_ip_discovery(disc, 0x99));
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        uint8_t reply[74];
        memcpy(reply, disc, sizeof reply);
        reply[1] = 2;                   /* ответ IP Discovery */
        n = build_udp_pkt(pkt, 64038, 50004, reply, sizeof reply);
        swap_udp_ends(pkt);
        d2k_session_set_hook(s, D2K_HOOK_FORWARD);
        d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
        CHECK(count_kind_name(s, D2K_JRN_EXCHANGE, NULL) == 1,
              "ответ сервера по голосовому потоку не дал события обмена");
        d2k_session_packet(s, pkt, n, 3000, buf, sizeof buf, &r);
        CHECK(count_kind_name(s, D2K_JRN_EXCHANGE, NULL) == 1,
              "обмен по одному потоку объявлен дважды");
        d2k_session_free(s);
    }
    /* Только корректный ответ IP Discovery, с тем же SSRC, является
       протокольным доказательством. Пустой/чужой ответ остаётся обычным
       наблюдением и не получает этот код. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[256], buf[4096], disc[74], reply[74];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 64039, 50004, disc, build_ip_discovery(disc, 0xAABBCCDD));
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        build_ip_discovery_response(reply, 0xAABBCCDD);
        n = build_udp_pkt(pkt, 64039, 50004, reply, sizeof reply);
        swap_udp_ends(pkt);
        d2k_session_set_hook(s, D2K_HOOK_FORWARD);
        d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
        const d2k_journal *j = d2k_session_journal(s);
        int proof = 0;
        for (size_t i = 0; i < d2k_journal_count(j); i++) {
            const d2k_jrn_entry *e = d2k_journal_at(j, i);
            if (e && e->kind == D2K_JRN_EXCHANGE &&
                e->code == D2K_UDP_PROOF_VOICE_DISCOVERY) { proof = 1; }
        }
        CHECK(proof, "валидный IP Discovery response не дал протокольного доказательства");
        d2k_session_free(s);
    }
    /* Эхо запроса с типом 0x0001 (даже с заполненным адресом) — не ответ. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[256], buf[4096], disc[74], reply[74];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 64039, 50004, disc, build_ip_discovery(disc, 0xAABBCCDD));
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
        build_ip_discovery_response(reply, 0xAABBCCDD);
        reply[1] = 1;
        n = build_udp_pkt(pkt, 64039, 50004, reply, sizeof reply);
        swap_udp_ends(pkt);
        d2k_session_set_hook(s, D2K_HOOK_FORWARD);
        d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
        const d2k_journal *j = d2k_session_journal(s);
        int proof = 0;
        for (size_t i = 0; i < d2k_journal_count(j); i++) {
            const d2k_jrn_entry *e = d2k_journal_at(j, i);
            if (e && e->kind == D2K_JRN_EXCHANGE &&
                e->code == D2K_UDP_PROOF_VOICE_DISCOVERY) { proof = 1; }
        }
        CHECK(!proof, "эхо запроса типа 0x0001 принято за IP Discovery response");
        d2k_session_free(s);
    }
}

/* ВРЕМЕННЫЙ ГОЛОСОВОЙ ПЛАН ДОХОДИТ ДО РАЗГОВОРА (задача 15).
 *
 * Межсетевой экран роутера (files/S99d2k, CONNBYTES=0:8) отдаёт в очередь
 * только первые 8 пакетов потока в каждую сторону: поздние пакеты разговора,
 * идущего во время замера, до датапата не доходят вовсе. Поэтому опыт —
 * клиент LAN + адрес и UDP-порт сервера + ЛЮБОЙ клиентский порт + trial ID +
 * lease: его получает первый запрос голоса СЛЕДУЮЩЕГО потока того же клиента
 * к той же точке (повторный вход / новый звонок). Другой клиент, другая точка,
 * не-голос и истёкший lease — нет. fw_feed моделирует окно экрана. */
static unsigned fw_seen[65536];

static void fw_feed(d2k_session *s, const uint8_t *pkt, size_t n, uint64_t now,
                    uint8_t *buf, size_t cap, d2k_result *r) {
    uint16_t sport = (uint16_t)(pkt[20] << 8 | pkt[21]);
    memset(r, 0, sizeof *r);
    if (++fw_seen[sport] > 8) { return; }   /* connbytes 0:8, original */
    d2k_session_packet(s, pkt, n, now, buf, cap, r);
}

static void test_voice_trial_live_flow(void) {
    const uint8_t trial[D2K_TRIAL_ID_LEN] = {
        0x15, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x15
    };
    const uint64_t ms = 1000000ull;
    memset(fw_seen, 0, sizeof fw_seen);
    d2k_session *s = d2k_session_new(64, 32);
    CHECK(s != NULL, "сессия голосового опыта не завелась");
    if (!s) { return; }
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    uint8_t pkt[256], buf[4096], disc[74], rtp[48];
    d2k_result r;
    memset(rtp, 0x90, sizeof rtp);
    /* Разговор во время замера: IP Discovery без плана, дальше голос. */
    size_t n = build_udp_pkt(pkt, 64060, 50004, disc, build_ip_discovery(disc, 0x4242));
    fw_feed(s, pkt, n, 1 * ms, buf, sizeof buf, &r);
    CHECK(!r.applied, "голос без плана получил план");
    for (int i = 0; i < 20; i++) {
        n = build_udp_pkt(pkt, 64060, 50004, rtp, sizeof rtp);
        fw_feed(s, pkt, n, 2 * ms, buf, sizeof buf, &r);
    }
    /* Опыт контроллера: клиент LAN, точка сервера, любой клиентский порт. */
    d2k_plan *p = NULL;
    char err[160];
    d2k_addr_probe_flow f;
    memset(&f, 0, sizeof f);
    f.family = 4;
    memcpy(f.src_ip4, "\xc0\xa8\x01\x43", 4);
    memcpy(f.dst_ip4, "\x01\x02\x03\x04", 4);
    f.src_port_be = 0;
    f.dst_port_be = htons(50004);
    f.transport = 17;
    const uint64_t expires = 100 * ms + 120000 * ms;
    CHECK(d2k_plan_load(plan_voice_declared, sizeof plan_voice_declared, &p,
                        err, sizeof err) == 0 &&
          d2k_plantab_set_addr_probe(d2k_session_plans(s), &f, trial, 100 * ms,
                                     expires, p) == 0,
          "голосовой опыт не поставился на клиента и точку сервера");
    /* Портовая запись имени — проба контроллера — пользователю невидима. */
    p = NULL;
    CHECK(d2k_plan_load(plan_voice_declared, sizeof plan_voice_declared, &p,
                        err, sizeof err) == 0 &&
          d2k_plantab_set_name_probe(d2k_session_plans(s), (const uint8_t *)D2K_VOICE_CLASS,
                                     strlen(D2K_VOICE_CLASS), 100 * ms, p,
                                     D2K_PLAN_SHAPE_VOICE, htons(64062)) == 0,
          "портовая запись голоса не поставилась");
    n = build_udp_pkt(pkt, 64062, 50004, disc, build_ip_discovery(disc, 0x4343));
    pkt[15] = 69;   /* другой клиент: опыт клиента .67 его не касается */
    fw_feed(s, pkt, n, 150 * ms, buf, sizeof buf, &r);
    CHECK(!r.applied, "портовая проба контроллера досталась пользовательскому голосу");
    n = build_udp_pkt(pkt, 64066, 50004, rtp, sizeof rtp);
    fw_feed(s, pkt, n, 160 * ms, buf, sizeof buf, &r);
    CHECK(!r.applied, "голосовой опыт достался пакету, который не запрос голоса");
    /* Повтор запроса разговора, шедшего во время замера, экран не отдаёт. */
    n = build_udp_pkt(pkt, 64060, 50004, disc, build_ip_discovery(disc, 0x4242));
    fw_seen[64060] = 21;
    fw_feed(s, pkt, n, 200 * ms, buf, sizeof buf, &r);
    CHECK(!r.applied, "пакет за окном экрана дошёл до датапата");
    /* Другой клиент LAN — не тот опыт. */
    n = build_udp_pkt(pkt, 64064, 50004, disc, build_ip_discovery(disc, 0x4444));
    pkt[15] = 68;
    fw_feed(s, pkt, n, 300 * ms, buf, sizeof buf, &r);
    CHECK(!r.applied, "опыт достался другому клиенту LAN");
    /* Другая точка сервера (порт) — не тот опыт. */
    n = build_udp_pkt(pkt, 64065, 50005, disc, build_ip_discovery(disc, 0x4545));
    fw_feed(s, pkt, n, 400 * ms, buf, sizeof buf, &r);
    CHECK(!r.applied, "опыт достался другой точке сервера");
    /* Не-голос подстановочной записи не видит. */
    d2k_addr_probe_flow q = f;
    q.src_port_be = htons(64061);
    CHECK(d2k_plantab_find_addr_probe(d2k_session_plans(s), &q, 450 * ms, NULL) == NULL,
          "подстановочный голосовой опыт виден поиску не-голоса");
    /* СЛЕДУЮЩИЙ разговор того же клиента к той же точке — первый пакет. */
    n = build_udp_pkt(pkt, 64061, 50004, disc, build_ip_discovery(disc, 0x4646));
    fw_feed(s, pkt, n, 500 * ms, buf, sizeof buf, &r);
    CHECK(r.applied && memcmp(r.trial_id, trial, sizeof trial) == 0,
          "следующий разговор того же клиента не получил опыт с trial ID");
    /* Ответ type 2 по нему — протокольное доказательство на этом потоке. */
    uint8_t reply[74];
    build_ip_discovery_response(reply, 0x4646);
    n = build_udp_pkt(pkt, 64061, 50004, reply, sizeof reply);
    swap_udp_ends(pkt);
    d2k_session_set_hook(s, D2K_HOOK_FORWARD);
    d2k_session_packet(s, pkt, n, 600 * ms, buf, sizeof buf, &r);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    int proof = 0;
    const d2k_journal *j = d2k_session_journal(s);
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == D2K_JRN_EXCHANGE &&
            e->code == D2K_UDP_PROOF_VOICE_DISCOVERY) { proof = 1; }
    }
    CHECK(proof, "ответ IP Discovery по потоку с опытом не дал доказательства");
    /* После lease не совпадает ничто. */
    n = build_udp_pkt(pkt, 64063, 50004, disc, build_ip_discovery(disc, 0x4747));
    fw_feed(s, pkt, n, expires + 1, buf, sizeof buf, &r);
    CHECK(!r.applied, "истёкший голосовой опыт применён");
    CHECK(d2k_plantab_probe_count(d2k_session_plans(s)) == 0,
          "истёкший голосовой опыт остался в таблице");
    d2k_session_free(s);
}

static int frag_nat_missing;
static int frag_nat(const char *path,uint8_t proto,uint32_t src,uint16_t sp,
                    uint32_t dst,uint16_t dp,uint32_t *os,uint16_t *op) {
    (void)path;(void)src;(void)sp;(void)dst;(void)dp;
    CHECK(proto==17,"fragment NAT transport");
    if(frag_nat_missing)return frag_nat_missing==2?1:-1;
    const uint8_t ip[]={203,0,113,7},port[]={0xc3,0x50};
    memcpy(os,ip,4);memcpy(op,port,2);return 0;
}
static unsigned frag_sum(const uint8_t *p,size_t n,unsigned sum) {
    for(size_t i=0;i<n;i+=2)sum+=(unsigned)p[i]*256+(i+1<n?p[i+1]:0);
    while(sum>>16)sum=(sum&65535)+(sum>>16);
    return sum;
}
static unsigned frag_u16(const uint8_t *p) {return (unsigned)p[0]*256+p[1];}
static void test_fragments(void) {
    d2k_nat_fn saved=d2k_nat_hook;d2k_nat_hook=frag_nat;
    for(int fake=0;fake<2;fake++)for(int shape=1;shape<=4;shape++) {
        uint8_t tlv[128]={'D','2','K','P',0,1,0,7,0,0,0,2,
                          0,2,0,2,17,2,1,12,0,1,0};
        tlv[22]=(uint8_t)shape;size_t tn=23;
        if(fake) {memcpy(tlv+tn,plan_bytes+12,sizeof plan_bytes-12);
            tn+=sizeof plan_bytes-12;tlv[11]=6;}
        d2k_plan *p=NULL;char err[160];
        CHECK(d2k_plan_load(tlv,tn,&p,err,sizeof err)==0,"fragment session plan load");
        if(!p)continue;
        d2k_session *s=d2k_session_new(64,64);
        d2k_plantab_set_name(d2k_session_plans(s),(const uint8_t *)"example.com",11,1,p);
        uint8_t pkt[1300],buf[4096];d2k_result r;
        unsigned lastid=0;
        for(unsigned attempt=0;attempt<2;attempt++) {
            size_t n=build_udp_pkt(pkt,(uint16_t)(51000+attempt),443,v1_initial,sizeof v1_initial);
            pkt[8]=47;pkt[1]=0x2e;pkt[4]=pkt[5]=0; /* DF-style client ID must not be reused. */
            d2k_session_packet(s,pkt,n,1000+attempt,buf,sizeof buf,&r);
            size_t start=fake?2:0,frags=shape<=2?2:3;
            CHECK(r.applied && r.n_out==start+frags && r.verdict==D2K_VERDICT_DROP,
                  "fragment plan must emit all frames and drop whole original");
            CHECK(r.first_payload==start,"first payload indexes actual wire fragment");
            if(r.n_out!=start+frags)continue;
            uint8_t reassembled[1208]={0},seen[1208]={0};
            unsigned id=frag_u16(buf+r.out[start].off+4);
            CHECK(id && id!=lastid,"fragment group requires distinct nonzero ID");lastid=id;
            for(size_t i=0;i<r.n_out;i++) {
                const uint8_t *f=buf+r.out[i].off;
                CHECK(frag_sum(f,20,0)==65535,"fragment IPv4 checksum");
                if(i<start) {
                    CHECK(!memcmp(f+12,"\xc0\xa8\x01\x43",4),"whole fake retains kernel NAT path");
                    CHECK(f[8]==3 && frag_u16(f+20)==51000+attempt &&
                          !memcmp(f+28,"\xde\xad\xbe",3),"fake unchanged before fragments");
                    continue;
                }
                CHECK(!memcmp(f+12,"\xcb\x00\x71\x07",4),"fragment NAT source");
                unsigned off=(frag_u16(f+6)&8191)*8;
                size_t ln=r.out[i].len-20;
                CHECK(f[8]==47 && f[1]==0x2e,"fragment preserves client TTL/TOS");
                CHECK(frag_u16(f+4)==id,"one IP ID per group");
                CHECK(frag_u16(f+6)&0x3fff,"no whole unfragmented UDP emitted");
                CHECK(off+ln<=sizeof reassembled,"fragment bounds");
                if(off+ln>sizeof reassembled)continue;
                memcpy(reassembled+off,f+20,ln);memset(seen+off,1,ln);
                CHECK(r.out[i].delay_us==0,"original fragments have no invented delay");
                if(i==start)CHECK((shape==1)==(off==0),"original fragment wire order");
            }
            for(size_t i=0;i<sizeof seen;i++)CHECK(seen[i],"complete UDP reassembly");
            CHECK(frag_u16(reassembled)==50000 && frag_u16(reassembled+2)==443 &&
                  frag_u16(reassembled+4)==1208,"translated UDP header");
            CHECK(!memcmp(reassembled+8,v1_initial,1200),"full original QUIC bytes");
            const uint8_t ph[]={203,0,113,7,1,2,3,4,0,17,4,184};
            CHECK(frag_sum(reassembled,sizeof reassembled,frag_sum(ph,sizeof ph,0))==65535,
                  "UDP checksum over translated full datagram, not individual cuts");
            CHECK(d2k_session_done(s)==0,"prepared fragments are not DONE");
            if(attempt==0) {
                for(size_t i=0;i<=start;i++)d2k_session_sent(s,1200+i,&r.key,r.execution_id);
                CHECK(d2k_session_exec_failed(s,1300,&r.key,r.plan_id,D2K_REFUSE_SEND,
                      r.execution_id,1,0)==0,"partial fragment must not release whole original");
                CHECK(d2k_session_done(s)==0 && d2k_session_damaged_count(s)==1,
                      "partial fragment group is damaged, never DONE");
            } else {
                for(size_t i=0;i<r.n_out;i++)d2k_session_sent(s,1400+i,&r.key,r.execution_id);
                CHECK(d2k_session_done(s)==0,"missing original verdict is not DONE");
                d2k_session_sent(s,1500,&r.key,r.execution_id);
                CHECK(d2k_session_done(s)==1,"all fragments and verdict complete one execution");
            }
        }
        /* Failure while constructing: no raw sends, no false application. */
        size_t n=build_udp_pkt(pkt,52000,443,v1_initial,sizeof v1_initial);
        d2k_session_packet(s,pkt,n,2000,buf,100,&r);
        CHECK(!r.applied && !r.n_out && r.verdict==D2K_VERDICT_ACCEPT && r.skipped,
              "short output buffer must pass untouched original without APPLIED");
        frag_nat_missing=1;
        n=build_udp_pkt(pkt,52001,443,v1_initial,sizeof v1_initial);
        size_t refusals_before = count_plan_refused(s);
        d2k_session_packet(s,pkt,n,2100,buf,sizeof buf,&r);
        CHECK(!r.applied && !r.n_out && r.verdict==D2K_VERDICT_ACCEPT && r.skipped,
              "first packet cannot guess unconfirmed fragment NAT mapping");
        CHECK(count_plan_refused(s)==refusals_before,
              "unconfirmed first-packet mapping is deferred, not reported as a rejected plan");
        frag_nat_missing=0;
        d2k_session_packet(s,pkt,n,2101,buf,sizeof buf,&r);
        CHECK(r.applied && r.n_out>0 && r.verdict==D2K_VERDICT_DROP,
              "same QUIC flow retries its fragment plan after conntrack confirms");
        frag_nat_missing=2;
        n=build_udp_pkt(pkt,52002,443,v1_initial,sizeof v1_initial);
        d2k_session_packet(s,pkt,n,2200,buf,sizeof buf,&r);
        CHECK(!r.applied && !r.n_out && r.verdict==D2K_VERDICT_ACCEPT,
              "missing conntrack procfs is not evidence of untranslated fragment context");
        frag_nat_missing=0;
        if(fake && shape==4) {
            /* 24 fake datagrams + 3 IP fragments exceeds the 26-frame result,
               despite only 25 logical actions. Refuse before sending any. */
            tlv[23+9+12+8]=24;
            d2k_plan *large=NULL;
            CHECK(d2k_plan_load(tlv,tn,&large,err,sizeof err)==0,"large fragment plan load");
            if(large)d2k_plantab_set_name(d2k_session_plans(s),(const uint8_t *)"example.com",11,2,large);
            n=build_udp_pkt(pkt,52003,443,v1_initial,sizeof v1_initial);
            d2k_session_packet(s,pkt,n,2300,buf,sizeof buf,&r);
            CHECK(!r.applied && !r.n_out && r.verdict==D2K_VERDICT_ACCEPT,
                  "expanded wire fragment count must be capacity checked");
        }
        d2k_session_free(s);
    }
    d2k_nat_hook=saved;
}

static int frag_nat6(const char *path, uint8_t proto, const uint8_t *src,
    uint16_t sport, const uint8_t *dst, uint16_t dport, uint8_t family,
    uint8_t *outside, uint16_t *out_port) {
    (void)path; (void)dst; (void)dport;
    CHECK(proto == 17 && family == 6, "fragment native NAT context");
    memcpy(outside, src, 16); outside[15] = 7; *out_port = sport;
    return 0;
}

/* --- QUIC ЗАМОЛЧАЛ ПОСЛЕ РУКОПОЖАТИЯ (задача 50, раунд 2) ---------------
 *
 * Поле 04.10: Safari и curl --http3-only на rua.gr. Рукопожатие проходит,
 * сервер присылает ещё несколько пакетов данных и замолкает НАСОВСЕМ (на ppp0
 * пусто), клиент повторяет короткие пакеты по PTO (1, 2, 3, 4, 6, 10… с).
 * Очередь видит лишь первые 8 пакетов каждой стороны; остальное видно только
 * по счётчикам conntrack: прямой растёт, обратный стоит. Раунд 3: счётчики
 * спрашиваются у ядра по кортежу (ctnetlink, d2k_ctq.h), только для
 * наблюдаемых потоков; здесь запрос подменён. */
static struct { uint16_t cport; uint64_t orig, reply; int acct; } fake_ct;
static unsigned ct_queries;
static void ct_write(uint16_t cport, uint64_t orig, uint64_t reply, int acct) {
    fake_ct.cport = cport; fake_ct.orig = orig; fake_ct.reply = reply; fake_ct.acct = acct;
}
static int fake_ct_query(void *ctx, const d2k_ct_tuple *t, d2k_ct_info *out) {
    (void)ctx;
    ct_queries++;
    static const uint8_t cli[4] = {192, 168, 1, 67}, srv[4] = {1, 2, 3, 4};
    uint16_t sp = (uint16_t)(t->sport_be[0] << 8 | t->sport_be[1]);
    uint16_t dp = (uint16_t)(t->dport_be[0] << 8 | t->dport_be[1]);
    /* Прямой кортеж — клиент → сервер, как его ведёт conntrack. */
    if (t->family != 4 || t->proto != 17 || memcmp(t->src, cli, 4) || memcmp(t->dst, srv, 4) ||
        dp != 443 || sp != fake_ct.cport || !fake_ct.acct) return -1;
    out->orig_pkts = fake_ct.orig; out->reply_pkts = fake_ct.reply;
    return 0;
}

static uint8_t last_suspect_code(const d2k_session *s) {
    const d2k_journal *j = d2k_session_journal(s);
    uint8_t code = 0;
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == D2K_JRN_SUSPECT) code = e->code;
    }
    return code;
}

/* Поток с именем: Initial клиента, rev ответных пакетов в окне очереди. */
/* Поток QUIC, где первый байт КАЖДОГО ответа сервера задан. Нужен ровно для
   различения двух случаев, которые иначе неотличимы: 0xc3 — длинный заголовок
   (рукопожатие идёт и не кончилось), 0x40 — короткий заголовок 1-RTT
   (рукопожатие состоялось, RFC 9000 §17.3). */
static d2k_session *quic_flow_first_byte(uint16_t cport, int rev, uint8_t first) {
    const uint64_t S = 1000000000ull;
    d2k_session *s = d2k_session_new(64, 64);
    if (!s) return NULL;
    d2k_session_set_ct_query(s, fake_ct_query, NULL);
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    size_t n = build_udp_pkt(pkt, cport, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 1 * S, buf, sizeof buf, &r);
    uint8_t rev_pay[40];
    memset(rev_pay, 0, sizeof rev_pay);
    rev_pay[0] = first;
    for (int i = 0; i < rev; i++) {
        n = build_udp_rev_pkt(pkt, cport, rev_pay, sizeof rev_pay);
        d2k_session_packet(s, pkt, n, 1 * S + 50000000ull + (uint64_t)i, buf, sizeof buf, &r);
    }
    return s;
}

/* Одна обратная датаграмма со СКЛЕЙКОЙ: сперва пакет с длинным заголовком
   (Handshake), следом — короткий. Так и шлёт настоящий сервер: замер
   12.10.2026 (netlog Chrome, scripts/quic-proof-margin.py) показал
   «HAND#9 + S#10» в одной датаграмме у r2---sn-...gvt1.com,
   «HAND#6 + S#7» у ad.doubleclick.net и googleads.g.doubleclick.net.
   Склейка разрешена RFC 9000 §12.2, а короткий заголовок не несёт поля
   длины, поэтому он обязан быть ПОСЛЕДНИМ — значит пройти датаграмму
   насквозь можно по полям Length длинных пакетов, не расшифровывая. */
static size_t build_coalesced_hand_then_short(uint8_t *o, size_t cap) {
    const size_t body = 24;             /* номер пакета + нагрузка + тег AEAD */
    if (cap < 8 + body + 21) { return 0; }
    size_t i = 0;
    o[i++] = 0xE0;                      /* длинный, фикс. бит, тип Handshake */
    o[i++] = 0x00; o[i++] = 0x00; o[i++] = 0x00; o[i++] = 0x01;  /* версия 1 */
    o[i++] = 0x00;                      /* длина DCID */
    o[i++] = 0x00;                      /* длина SCID */
    o[i++] = (uint8_t)body;             /* Length одним байтом varint (<64) */
    memset(o + i, 0xAA, body);
    i += body;
    o[i++] = 0x40;                      /* короткий заголовок: 0x80 снят, 0x40 стоит */
    memset(o + i, 0xBB, 20);
    i += 20;
    return i;
}

/* Поток с одной обратной датаграммой, собранной вызывающим. */
static d2k_session *quic_flow_rev_payload(uint16_t cport, const uint8_t *pay,
                                          size_t paylen) {
    const uint64_t S = 1000000000ull;
    d2k_session *s = d2k_session_new(64, 64);
    if (!s) return NULL;
    d2k_session_set_ct_query(s, fake_ct_query, NULL);
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    size_t n = build_udp_pkt(pkt, cport, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 1 * S, buf, sizeof buf, &r);
    n = build_udp_rev_pkt(pkt, cport, pay, paylen);
    d2k_session_packet(s, pkt, n, 1 * S + 50000000ull, buf, sizeof buf, &r);
    return s;
}

static d2k_session *stall_flow(uint16_t cport, int rev) {
    const uint64_t S = 1000000000ull;
    d2k_session *s = d2k_session_new(64, 64);
    if (!s) return NULL;
    d2k_session_set_ct_query(s, fake_ct_query, NULL);
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    size_t n = build_udp_pkt(pkt, cport, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 1 * S, buf, sizeof buf, &r);
    const uint8_t any[40] = {0x40};
    for (int i = 0; i < rev; i++) {
        n = build_udp_rev_pkt(pkt, cport, any, sizeof any);
        d2k_session_packet(s, pkt, n, 1 * S + 50000000ull + (uint64_t)i, buf, sizeof buf, &r);
    }
    return s;
}

/* ДОЛГИЙ ПОТОК (очередь 28.10, задание 05). Очередь видит первые 8 датаграмм,
   дальше запись потока живёт только 120 с после последнего пакета В ОЧЕРЕДИ —
   пятиминутный здоровый поток забывался на третьей минуте, и его обрыв на
   шестой не замечал никто. Активность сервера по conntrack — такая же улика
   жизни потока, как пакет в очереди: пока обратный счётчик растёт, запись
   жива; кончился поток (записи conntrack нет) — забывается штатно. Критерии
   самого подозрения не меняются: здоровый или просто молчащий поток
   подозрения не даёт. */
/* UDP БЕЗ РАСПОЗНАННОГО ПРОТОКОЛА (этап 12, 28.10.2026): не QUIC Initial,
   не STUN, не Discovery. Молчание — только при трёх уликах: клиент упорствует
   (≥3 датаграмм), обратная сторона видна сессии, оттуда ничего дольше срока.
   Любой ответ оттуда снимает подозрение; две датаграммы — не упорство.
   Подозрение несёт форму RAW и planned=NO. */
static void test_udp_raw_silence(void) {
    const uint64_t S = 1000000000ull;
    static const uint8_t game[] = "\x01\x00GAME-PING\x00\x00";
    for (int variant = 0; variant < 3; variant++) {
        d2k_session *s = d2k_session_new(64, 64);
        d2k_session_set_udp_reverse_hook(s, 1);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        uint16_t cport = (uint16_t)(46000 + variant);
        int sends = variant == 2 ? 2 : 3;
        for (int i = 0; i < sends; i++) {
            size_t n = build_udp_pkt(pkt, cport, 443, game, sizeof game - 1);
            d2k_session_packet(s, pkt, n, (uint64_t)(i + 1) * S, buf, sizeof buf, &r);
        }
        if (variant == 1) {
            size_t n = build_udp_rev_pkt(pkt, cport, game, sizeof game - 1);
            d2k_session_packet(s, pkt, n, 3 * S + S / 2, buf, sizeof buf, &r);
        }
        CHECK(d2k_session_hellos(s) == 0, "udp raw: нагрузка принята за приветствие");
        CHECK(d2k_session_sweep(s, 2 * S) == 0, "udp raw: подозрение раньше срока/упорства");
        size_t told = d2k_session_sweep(s, 8 * S);
        if (variant == 0) {
            CHECK(told == 1, "udp raw: молчание при упорстве клиента и видимой обратной стороне не заподозрено");
            CHECK(last_suspect_code(s) == D2K_SUSPECT_SILENT, "udp raw: код подозрения не SILENT");
            const d2k_journal *j = d2k_session_journal(s);
            for (size_t i = 0; i < d2k_journal_count(j); i++) {
                const d2k_jrn_entry *e = d2k_journal_at(j, i);
                if (e->kind != D2K_JRN_SUSPECT) continue;
                CHECK(e->d_client_shape == D2K_PLAN_SHAPE_RAW && e->d_planned == D2K_PLANNED_NO,
                      "udp raw: подозрение без формы RAW/планности");
            }
            CHECK(d2k_session_sweep(s, 20 * S) == 0, "udp raw: подозрение продублировано");
        } else {
            CHECK(told == 0, variant == 1 ? "udp raw: ответ сервера назван молчанием"
                                          : "udp raw: две датаграммы названы упорством");
        }
        d2k_session_free(s);
    }
    /* Обратная сторона сессии не видна — не молчание. */
    d2k_session *s = d2k_session_new(64, 64);
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    for (int i = 0; i < 3; i++) {
        size_t n = build_udp_pkt(pkt, 46010, 443, game, sizeof game - 1);
        d2k_session_packet(s, pkt, n, (uint64_t)(i + 1) * S, buf, sizeof buf, &r);
    }
    CHECK(d2k_session_sweep(s, 8 * S) == 0, "udp raw: без видимой обратной стороны названо молчанием");
    d2k_session_free(s);
}

/* ПОЯВЛЕНИЕ ПОТОКА БЕЗ ПРОТОКОЛА (этап 42): здоровый безымянный поток без
   нашего плана событий не давал вовсе, и контроллер его не видел. Теперь —
   один факт D2K_JRN_FLOW на поток (не на пакет), с наблюдённой стороной
   клиента; не для QUIC/STUN/зонда; объём ограничен, подавленное считается. */
static size_t count_flow_facts(const d2k_session *s) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t c = 0;
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == D2K_JRN_FLOW) c++;
    }
    return c;
}
static void test_flow_fact_udp(void) {
    const uint64_t S = 1000000000ull;
    static const uint8_t game[] = "\x01\x00GAME-PING\x00\x00";
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    d2k_session *s = d2k_session_new(512, 1024);
    d2k_session_set_hook(s, D2K_HOOK_OUTPUT);
    for (int i = 0; i < 4; i++) {
        size_t n = build_udp_pkt(pkt, 47000, 27015, game, sizeof game - 1);
        d2k_session_packet(s, pkt, n, (uint64_t)(i + 1) * S, buf, sizeof buf, &r);
    }
    CHECK(count_flow_facts(s) == 1, "поток UDP без протокола: не один факт появления на поток");
    const d2k_journal *j = d2k_session_journal(s);
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e->kind != D2K_JRN_FLOW) continue;
        /* 192.168.1.67 — высокий конец пары относительно 1.2.3.4. */
        CHECK(e->key.proto == 17 && e->d_client_side == D2K_CLIENT_SIDE_HIGH && e->name_len == 0,
              "поток UDP: факт без транспорта/стороны клиента или с выдуманным именем");
        CHECK(e->execution_id == 0, "поток UDP: факт появления несёт исполнение");
    }
    /* QUIC Initial, STUN и поток зонда — свои пути, факта появления нет. */
    size_t n = build_udp_pkt(pkt, 47001, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 6 * S, buf, sizeof buf, &r);
    uint8_t stun[20] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1,2,3,4,5,6,7,8,9,10,11,12};
    n = build_udp_pkt(pkt, 47002, 3478, stun, sizeof stun);
    d2k_session_packet(s, pkt, n, 6 * S, buf, sizeof buf, &r);
    n = build_udp_pkt(pkt, 47003, 27015, game, sizeof game - 1);
    d2k_session_packet_probe(s, pkt, n, 6 * S, buf, sizeof buf, &r);
    CHECK(count_flow_facts(s) == 1, "поток UDP: факт появления у QUIC/STUN/зонда");
    d2k_session_free(s);

    /* Без крючка на не-443 направление не известно: датаграмма уходит как
       есть до разбора, клиент не угадывается и факта нет. */
    s = d2k_session_new(64, 64);
    n = build_udp_pkt(pkt, 47010, 27015, game, sizeof game - 1);
    d2k_session_packet(s, pkt, n, S, buf, sizeof buf, &r);
    CHECK(count_flow_facts(s) == 0, "поток UDP без крючка: клиент угадан по порту");
    d2k_session_free(s);

    /* ОБЪЁМ: пачка новых потоков разом — сообщается не больше запаса,
       остальное считается подавленным; со временем запас восполняется. */
    s = d2k_session_new(512, 1024);
    d2k_session_set_hook(s, D2K_HOOK_OUTPUT);
    for (int i = 0; i < 300; i++) {
        n = build_udp_pkt(pkt, (uint16_t)(48000 + i), 27015, game, sizeof game - 1);
        d2k_session_packet(s, pkt, n, S, buf, sizeof buf, &r);
    }
    d2k_payload_stats ps;
    d2k_session_payload_stats(s, &ps);
    CHECK(ps.flow_told == count_flow_facts(s) && ps.flow_told == D2K_FLOW_FACT_BURST &&
          ps.flow_suppressed == 300 - D2K_FLOW_FACT_BURST,
          "поток UDP: пачка потоков не ограничена запасом или подавленное не сосчитано");
    n = build_udp_pkt(pkt, 48000, 27015, game, sizeof game - 1);   /* повтор подавленного — не новый */
    d2k_session_packet(s, pkt, n, 30 * S, buf, sizeof buf, &r);
    n = build_udp_pkt(pkt, 48299, 27015, game, sizeof game - 1);
    d2k_session_packet(s, pkt, n, 30 * S, buf, sizeof buf, &r);
    d2k_session_payload_stats(s, &ps);
    CHECK(ps.flow_told == D2K_FLOW_FACT_BURST && ps.flow_suppressed == 300 - D2K_FLOW_FACT_BURST,
          "поток UDP: повтор потока сочтён новым появлением");
    n = build_udp_pkt(pkt, 49000, 27015, game, sizeof game - 1);
    d2k_session_packet(s, pkt, n, 30 * S, buf, sizeof buf, &r);
    d2k_session_payload_stats(s, &ps);
    CHECK(ps.flow_told == D2K_FLOW_FACT_BURST + 1, "поток UDP: запас не восполнился со временем");
    d2k_session_free(s);
}

/* УЖЕ СУЩЕСТВУЮЩИЕ ПОТОКИ НА СТАРТЕ (этап 13): принятый из conntrack поток
   без приветствия наблюдается только счётчиками. Ответы идут — жив и запись
   продлевается; сервер встал, клиент упорствует (≥3) дольше срока —
   подозрение SILENT формы RAW, planned=NO, один раз; сервер никогда не
   отвечал — подозрения нет; запись conntrack исчезла — забвение штатное. */
static struct { uint16_t cport; uint64_t orig, reply; int acct; uint8_t proto; int tcp_known; uint8_t tcp_state; } fake_any;
static int fake_ct_any(void *ctx, const d2k_ct_tuple *t, d2k_ct_info *out) {
    (void)ctx;
    uint16_t sp = (uint16_t)(t->sport_be[0] << 8 | t->sport_be[1]);
    if (!fake_any.acct || t->proto != fake_any.proto || sp != fake_any.cport) return -1;
    out->orig_pkts = fake_any.orig; out->reply_pkts = fake_any.reply;
    out->tcp_state_known = fake_any.tcp_known; out->tcp_state = fake_any.tcp_state;
    return 0;
}
static void test_adopted_flows(void) {
    const uint64_t S = 1000000000ull, IDLE = 120 * S;
    for (int proto = 17; proto >= 6; proto -= 11) {
        for (int variant = 0; variant < 3; variant++) {
            d2k_session *s = d2k_session_new(64, 64);
            d2k_session_set_ct_query(s, fake_ct_any, NULL);
            d2k_ct_tuple t; memset(&t, 0, sizeof t);
            t.family = 4; t.proto = (uint8_t)proto;
            uint8_t cli[4] = {192, 168, 1, 67}, srv[4] = {1, 2, 3, 4};
            memcpy(t.src, cli, 4); memcpy(t.dst, srv, 4);
            uint16_t cport = (uint16_t)(47000 + variant + (proto == 6 ? 10 : 0));
            t.sport_be[0] = (uint8_t)(cport >> 8); t.sport_be[1] = (uint8_t)cport;
            t.dport_be[0] = 0x01; t.dport_be[1] = 0xbb;
            d2k_ct_info i; memset(&i, 0, sizeof i);
            i.orig_pkts = 10; i.reply_pkts = variant == 2 ? 0 : 8;
            CHECK(d2k_session_adopt(s, &t, &i, 1 * S) == 0, "adopt: поток не принят");
            CHECK(d2k_session_adopt(s, &t, &i, 1 * S) == 0 && d2k_session_flows(s) == 1, "adopt: повторный приём размножил запись");
            memset(&fake_any, 0, sizeof fake_any);
            fake_any.cport = cport; fake_any.proto = (uint8_t)proto; fake_any.acct = 1;
            fake_any.tcp_known = proto == 6; fake_any.tcp_state = D2K_CT_TCP_ESTABLISHED;
            uint64_t orig = 10, reply = i.reply_pkts, now;
            for (now = 2; now <= 200; now++) {            /* три минуты живого обмена */
                orig += 2; if (variant != 2) reply += 2;
                fake_any.orig = orig; fake_any.reply = reply;
                d2k_session_sweep(s, now * S);
                d2k_session_expire(s, now * S, IDLE);
            }
            if (variant == 2) {
                CHECK(d2k_session_suspects(s) == 0, "adopt: поток, которому сервер никогда не отвечал, заподозрен");
                d2k_session_free(s);
                continue;
            }
            CHECK(d2k_session_flows(s) == 1 && d2k_session_suspects(s) == 0,
                  "adopt: живой принятый поток забыт или заподозрен");
            if (variant == 0) {                            /* сервер встал, клиент упорствует */
                for (; now <= 212; now++) { orig += 1; fake_any.orig = orig; d2k_session_sweep(s, now * S); }
                CHECK(d2k_session_suspects(s) == 1 && last_suspect_code(s) == D2K_SUSPECT_SILENT,
                      "adopt: обрыв принятого потока не заподозрен");
                const d2k_journal *j = d2k_session_journal(s);
                for (size_t k = 0; k < d2k_journal_count(j); k++) {
                    const d2k_jrn_entry *e = d2k_journal_at(j, k);
                    if (e->kind != D2K_JRN_SUSPECT) continue;
                    CHECK(e->d_client_shape == D2K_PLAN_SHAPE_RAW && e->d_planned == D2K_PLANNED_NO,
                          "adopt: подозрение без формы RAW / planned=NO");
                }
                for (; now <= 240; now++) { orig += 1; fake_any.orig = orig; d2k_session_sweep(s, now * S); }
                CHECK(d2k_session_suspects(s) == 1, "adopt: подозрение продублировано");
            } else {                                       /* клиент замолчал сам: простой, не обрыв */
                for (; now <= 230; now++) { d2k_session_sweep(s, now * S); }
                CHECK(d2k_session_suspects(s) == 0, "adopt: простой клиента назван обрывом");
                fake_any.acct = 0;                         /* запись conntrack исчезла */
                for (; now <= 400; now++) { d2k_session_sweep(s, now * S); d2k_session_expire(s, now * S, IDLE); }
                CHECK(d2k_session_flows(s) == 0, "adopt: исчезнувший поток не забыт");
            }
            d2k_session_free(s);
        }
    }
}

/* ОПЫТ НА ПРОДОЛЖЕНИИ КЛИЕНТА ПО UDP (этап 16, 28.10.2026). Поток без
   протокола молчит; контроллер ставит точную запись опыта по 5-tuple
   (SET_ADDR_PROBE, trial, lease). Следующая датаграмма ТОГО ЖЕ клиента
   исполняет план (один раз на поток), APPLIED несёт trial ID; ответ сервера
   после этого — EXCHANGE planned=YES формы RAW (уровень пути). Чужой порт
   клиента опыта не получает; после истечения lease — тоже; постоянный
   адресный план формы RAW применяется к первой датаграмме нового потока. */
static const uint8_t raw_plan_voice[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 5,
    0x00, 0x02, 0x00, 0x02, 0x11, 0x03,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x00, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};
static size_t jcount(const d2k_session *s, uint8_t kind, uint8_t code, int *planned_yes, int *shape_raw) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = 0;
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e->kind != kind || e->code != code) continue;
        n++;
        if (planned_yes) *planned_yes = e->d_planned == D2K_PLANNED_YES;
        if (shape_raw) *shape_raw = e->d_client_shape == D2K_PLAN_SHAPE_RAW;
    }
    return n;
}
static void test_udp_raw_experiment(void) {
    const uint64_t S = 1000000000ull;
    static const uint8_t game[] = "\x01\x00GAME-PING\x00\x00";
    char err[160];
    d2k_session *s = d2k_session_new(64, 64);
    d2k_session_set_udp_reverse_hook(s, 1);
    D2K_TEST_NAT_NO_TABLE();
    uint8_t pkt[1300], buf[8192];
    d2k_result r;
    uint16_t cport = 48000;
    for (int i = 0; i < 3; i++) {
        size_t n = build_udp_pkt(pkt, cport, 443, game, sizeof game - 1);
        d2k_session_packet(s, pkt, n, (uint64_t)(i + 1) * S, buf, sizeof buf, &r);
        CHECK(r.n_out == 0 && !r.applied, "udp-опыт: без записи опыта план взялся ниоткуда");
    }
    CHECK(d2k_session_sweep(s, 8 * S) == 1, "udp-опыт: молчание не заподозрено");
    /* Без крючка направление — догадка по порту 443: сторона клиента в
       подозрении НЕ называется (контроллер точную пробу не выдумает). */
    {
        const d2k_journal *j = d2k_session_journal(s); int side = -1;
        for (size_t i = 0; i < d2k_journal_count(j); i++) {
            const d2k_jrn_entry *e = d2k_journal_at(j, i);
            if (e->kind == D2K_JRN_SUSPECT) side = e->d_client_side;
        }
        CHECK(side == 0, "udp-опыт: без крючка сторона клиента выдумана по порту");
    }
    /* Контроллер ставит точный опыт по 5-tuple этого потока. */
    d2k_addr_probe_flow f = {0};
    f.family = 4; f.transport = 17;
    memcpy(f.src_ip4, "\xc0\xa8\x01\x43", 4); memcpy(f.dst_ip4, "\x01\x02\x03\x04", 4);
    f.src_port_be = (uint16_t)((cport >> 8) | ((cport & 0xff) << 8)); f.dst_port_be = (uint16_t)(0x01bb >> 8 | (0xbb << 8));
    uint8_t trial[16] = {0x16, 0x01};
    d2k_plan *p = NULL;
    CHECK(!d2k_plan_load(raw_plan_voice, sizeof raw_plan_voice, &p, err, sizeof err) &&
          !d2k_plantab_set_addr_probe(d2k_session_plans(s), &f, trial, 9 * S, 60 * S, p),
          "udp-опыт: запись опыта не поставилась");
    size_t n = build_udp_pkt(pkt, cport, 443, game, sizeof game - 1);     /* продолжение клиента */
    d2k_session_packet(s, pkt, n, 10 * S, buf, sizeof buf, &r);
    CHECK(r.applied && r.n_out >= 2 && !memcmp(r.trial_id, trial, 16),
          "udp-опыт: план не исполнен на продолжении клиента или без trial ID");
    d2k_session_packet(s, pkt, n, 11 * S, buf, sizeof buf, &r);
    CHECK(!r.applied && r.n_out == 0, "udp-опыт: план исполнен дважды на одном потоке");
    n = build_udp_rev_pkt(pkt, cport, game, sizeof game - 1);             /* сервер ответил */
    d2k_session_packet(s, pkt, n, 11 * S + S / 2, buf, sizeof buf, &r);
    int yes = 0, raw = 0;
    CHECK(jcount(s, D2K_JRN_PLAN_APPLIED, 0, NULL, NULL) >= 1, "udp-опыт: нет APPLIED");
    CHECK(jcount(s, D2K_JRN_EXCHANGE, D2K_RAW_PROOF_ECHO, &yes, &raw) == 1 && yes && raw,
          "udp-опыт: ответ сервера без planned=YES/формы RAW");
    CHECK(d2k_session_sweep(s, 30 * S) == 0, "udp-опыт: ответивший поток назван молчащим");
    /* Чужой порт клиента — опыта нет. */
    n = build_udp_pkt(pkt, 48001, 443, game, sizeof game - 1);
    d2k_session_packet(s, pkt, n, 12 * S, buf, sizeof buf, &r);
    CHECK(!r.applied, "udp-опыт: запись опыта досталась чужому порту");
    d2k_session_free(s);
    /* Even an exact echo of a one-byte original is not meaningful evidence. */
    s=d2k_session_new(16,32);D2K_TEST_NAT_NO_TABLE();
    p=NULL;
    CHECK(!d2k_plan_load(raw_plan_voice,sizeof raw_plan_voice,&p,err,sizeof err)&&
          !d2k_plantab_set_addr_probe(d2k_session_plans(s),&f,trial,S,5*S,p),
          "one-byte UDP proof fixture");
    n=build_udp_pkt(pkt,cport,443,game,1);
    d2k_session_packet(s,pkt,n,2*S,buf,sizeof buf,&r);
    CHECK(r.applied,"one-byte UDP fixture not executed");
    n=build_udp_rev_pkt(pkt,cport,game,1);
    d2k_session_packet(s,pkt,n,3*S,buf,sizeof buf,&r);
    CHECK(count_journal_kind(s,D2K_JRN_EXCHANGE)==0,"one-byte original echo confirmed RAW proof");
    d2k_session_free(s);
    /* Lease истёк — продолжение без опыта. */
    s = d2k_session_new(64, 64); D2K_TEST_NAT_NO_TABLE();
    d2k_plan *q = NULL;
    CHECK(!d2k_plan_load(raw_plan_voice, sizeof raw_plan_voice, &q, err, sizeof err) &&
          !d2k_plantab_set_addr_probe(d2k_session_plans(s), &f, trial, 1 * S, 5 * S, q), "udp-опыт: запись с коротким lease");
    n = build_udp_pkt(pkt, cport, 443, game, sizeof game - 1);
    d2k_session_packet(s, pkt, n, 2 * S, buf, sizeof buf, &r);
    CHECK(r.applied, "udp-опыт: в пределах lease не исполнен");
    d2k_session_free(s);
    s = d2k_session_new(64, 64); D2K_TEST_NAT_NO_TABLE();
    q = NULL;
    CHECK(!d2k_plan_load(raw_plan_voice, sizeof raw_plan_voice, &q, err, sizeof err) &&
          !d2k_plantab_set_addr_probe(d2k_session_plans(s), &f, trial, 1 * S, 5 * S, q), "udp-опыт: запись для истечения");
    d2k_session_packet(s, pkt, n, 9 * S, buf, sizeof buf, &r);
    CHECK(!r.applied, "udp-опыт: истёкший lease всё ещё исполняет план");
    d2k_session_free(s);
    /* КРЮЧОК OUTPUT ДОКАЗЫВАЕТ СТОРОНУ (Linux, этап 16): подозрение по потоку
       без протокола на произвольном порту несёт client_side — иначе контроллеру
       не на что ставить точную пробу 5-tuple. */
    s = d2k_session_new(64, 64); D2K_TEST_NAT_NO_TABLE();
    d2k_session_set_udp_reverse_hook(s, 1);
    d2k_session_set_hook(s, D2K_HOOK_OUTPUT);
    for (int i = 0; i < 3; i++) {
        n = build_udp_pkt(pkt, 44749, 4455, game, sizeof game - 1);
        d2k_session_packet(s, pkt, n, (uint64_t)(i + 1) * S, buf, sizeof buf, &r);
    }
    CHECK(d2k_session_sweep(s, 8 * S) == 1, "udp-опыт/крючок: молчание на порту 4455 не заподозрено");
    {
        const d2k_journal *j = d2k_session_journal(s); int side = -1, shape = -1;
        for (size_t i = 0; i < d2k_journal_count(j); i++) {
            const d2k_jrn_entry *e = d2k_journal_at(j, i);
            if (e->kind == D2K_JRN_SUSPECT) { side = e->d_client_side; shape = e->d_client_shape; }
        }
        /* клиент 192.168.1.67:44749 → 1.2.3.4:4455: клиент — старшая сторона ключа */
        CHECK(side == D2K_CLIENT_SIDE_HIGH, "udp-опыт/крючок: сторона клиента, доказанная крючком OUTPUT, не названа");
        CHECK(shape == D2K_PLAN_SHAPE_RAW, "udp-опыт/крючок: форма подозрения не RAW");
    }
    d2k_session_free(s);
    /* ПОЗДНЯЯ ДОСТАВКА (этап 17): поток уже прошёл окно поиска (8 датаграмм
       клиента без ответа), только потом контроллер поставил точную пробу
       5-tuple — следующая датаграмма ТОГО ЖЕ потока обязана получить план,
       а не «за окном поиска». Чужой поток за окном по-прежнему мимо. */
    s = d2k_session_new(64, 64); D2K_TEST_NAT_NO_TABLE();
    d2k_session_set_udp_reverse_hook(s, 1);
    d2k_session_set_hook(s, D2K_HOOK_OUTPUT);
    for (int i = 0; i < 10; i++) {
        n = build_udp_pkt(pkt, cport, 443, game, sizeof game - 1);
        d2k_session_packet(s, pkt, n, (uint64_t)(i + 1) * S, buf, sizeof buf, &r);
        CHECK(!r.applied, "поздняя доставка: план взялся без записи");
    }
    CHECK(r.skipped && strstr(r.skipped, "за окном поиска"), "поздняя доставка: десятая датаграмма без записи не «за окном поиска»");
    {
        d2k_plan *lp = NULL; uint8_t ltrial[16] = {0x17, 0x01};
        CHECK(!d2k_plan_load(raw_plan_voice, sizeof raw_plan_voice, &lp, err, sizeof err) &&
              !d2k_plantab_set_addr_probe(d2k_session_plans(s), &f, ltrial, 11 * S, 70 * S, lp),
              "поздняя доставка: запись опыта не поставилась");
        n = build_udp_pkt(pkt, cport, 443, game, sizeof game - 1);
        d2k_session_packet(s, pkt, n, 12 * S, buf, sizeof buf, &r);
        CHECK(r.applied && r.n_out >= 2 && !memcmp(r.trial_id, ltrial, 16),
              "поздняя доставка: датаграмма за окном под точной пробой не получила план");
        n = build_udp_pkt(pkt, 48002, 443, game, sizeof game - 1);
        for (int i = 0; i < 10; i++) { d2k_session_packet(s, pkt, n, (uint64_t)(13 + i) * S, buf, sizeof buf, &r); }
        CHECK(!r.applied && r.skipped && strstr(r.skipped, "за окном поиска"),
              "поздняя доставка: чужой поток за окном прошёл в опыт");
    }
    d2k_session_free(s);
    /* ПРИНЯТИЕ ПОТОКА С МЛАДШИМ АДРЕСОМ КЛИЕНТА (этап 17, дефект 13):
       d2k_key_make_addr отвечает 1, когда источник — младшая сторона ключа, и
       adopt принимал это за ошибку: клиент 10.0.0.2 → сервер 172.16.0.1 не
       принимался. Флаг позднего наблюдения ставится по тому же кортежу. */
    {
        d2k_session *a = d2k_session_new(64, 64);
        d2k_ct_tuple lt; memset(&lt, 0, sizeof lt);
        lt.family = 4; lt.proto = 17;
        inet_pton(AF_INET, "10.0.0.2", lt.src); inet_pton(AF_INET, "172.16.0.1", lt.dst);
        lt.sport_be[0] = 0xc3; lt.sport_be[1] = 0x50; lt.dport_be[0] = 0x01; lt.dport_be[1] = 0xbb;
        d2k_ct_info ci; memset(&ci, 0, sizeof ci); ci.orig_pkts = 5; ci.reply_pkts = 3;
        CHECK(d2k_session_adopt(a, &lt, &ci, 1 * S) == 0,
              "adopt: клиент с младшим адресом не принят (возврат low=1 принят за ошибку)");
        CHECK(d2k_session_late_watch(a, &lt, 1) == 0, "late_watch: принятый поток не найден по кортежу");
        d2k_ct_tuple other = lt; other.dport_be[1] = 0xbc;
        CHECK(d2k_session_late_watch(a, &other, 1) == -1, "late_watch: чужой кортеж «найден»");
        d2k_session_free(a);
    }
    /* Постоянный адресный план формы RAW — первой датаграмме нового потока. */
    s = d2k_session_new(64, 64); D2K_TEST_NAT_NO_TABLE();
    q = NULL;
    uint8_t dst[4] = {1, 2, 3, 4};
    CHECK(!d2k_plan_load(raw_plan_voice, sizeof raw_plan_voice, &q, err, sizeof err) &&
          !d2k_plantab_set_addr_shaped(d2k_session_plans(s), dst, 4, 1, q, D2K_PLAN_SHAPE_RAW), "udp-опыт: постоянная RAW-запись");
    n = build_udp_pkt(pkt, 48002, 443, game, sizeof game - 1);
    d2k_session_packet(s, pkt, n, 2 * S, buf, sizeof buf, &r);
    CHECK(r.applied && r.n_out >= 2, "udp-опыт: постоянный RAW-план не применён к первой датаграмме");
    n = build_udp_pkt(pkt, 48003, 443, v1_initial, sizeof v1_initial);   /* QUIC того же адреса — не его форма */
    d2k_session_packet(s, pkt, n, 3 * S, buf, sizeof buf, &r);
    CHECK(!r.applied, "udp-опыт: RAW-план достался QUIC Initial");
    d2k_session_free(s);

    /* A measured RAW service owns only its UDP destination port. */
    s = d2k_session_new(64, 64); D2K_TEST_NAT_NO_TABLE();
    q = NULL;
    const uint8_t port443_bytes[2] = {1, 0xbb};
    uint16_t port443_be;
    memcpy(&port443_be, port443_bytes, sizeof port443_be);
    CHECK(!d2k_plan_load(raw_plan_voice, sizeof raw_plan_voice, &q, err, sizeof err) &&
          !d2k_plantab_set_endpoint(d2k_session_plans(s), dst, 4, port443_be, 1,
                                   q, D2K_PLAN_SHAPE_RAW), "udp RAW service: install");
    n = build_udp_pkt(pkt, 48012, 443, game, sizeof game - 1);
    d2k_session_packet(s, pkt, n, 2 * S, buf, sizeof buf, &r);
    CHECK(r.applied && r.n_out >= 2, "udp RAW service: measured port not transformed");
    n = build_udp_pkt(pkt, 48013, 8443, game, sizeof game - 1);
    d2k_session_packet(s, pkt, n, 3 * S, buf, sizeof buf, &r);
    CHECK(!r.applied && !r.n_out, "udp RAW service: unrelated port transformed");
    n = build_udp_pkt(pkt, 48014, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 4 * S, buf, sizeof buf, &r);
    CHECK(!r.applied, "udp RAW service: QUIC Initial inherited RAW plan");
    d2k_session_free(s);
}

static void test_quic_long_stream(void) {
    const uint64_t S = 1000000000ull, IDLE = 120 * S;
    d2k_session *s = stall_flow(50420, 8);
    CHECK(s != NULL, "долгий поток: сессия");
    if (!s) return;
    uint64_t orig = 12, reply = 14, t;
    for (t = 2; t <= 300; t++) {            /* пять минут здорового вещания */
        orig += 2; reply += 3;
        ct_write(50420, orig, reply, 1);
        d2k_session_sweep(s, t * S);
        d2k_session_expire(s, t * S, IDLE);
    }
    CHECK(d2k_session_flows(s) == 1, "здоровый долгий поток забыт, пока conntrack показывает ответы сервера");
    CHECK(d2k_session_suspects(s) == 0, "здоровый долгий поток заподозрен");
    for (; t <= 310; t++) {                 /* сервер встал, клиент повторяет */
        orig += 1;
        ct_write(50420, orig, reply, 1);
        d2k_session_sweep(s, t * S);
        d2k_session_expire(s, t * S, IDLE);
    }
    CHECK(d2k_session_suspects(s) == 1 && last_suspect_code(s) == D2K_SUSPECT_QUIC_STALL,
          "обрыв после пяти минут вещания не замечен");
    /* Пауза клиента — не обрыв: при молчащем клиенте второго подозрения нет. */
    for (; t <= 330; t++) { d2k_session_sweep(s, t * S); d2k_session_expire(s, t * S, IDLE); }
    CHECK(d2k_session_suspects(s) == 1, "пауза породила второе подозрение");
    ct_write(50420, orig, reply, 0);        /* записи conntrack больше нет */
    for (; t <= 460; t++) { d2k_session_sweep(s, t * S); d2k_session_expire(s, t * S, IDLE); }
    CHECK(d2k_session_flows(s) == 0, "завершённый поток не забыт");
    d2k_session_free(s);
}

static void test_quic_post_handshake_stall(void) {
    const uint64_t S = 1000000000ull;
    /* Нечего смотреть — ядро не спрашивается вовсе. */
    {
        d2k_session *s0 = d2k_session_new(64, 64);
        d2k_session_set_ct_query(s0, fake_ct_query, NULL);
        ct_queries = 0;
        d2k_session_sweep(s0, 5 * S);
        uint8_t p0[1300], b0[4096];
        d2k_result r0;
        /* Initial без ответа сервера — тоже не кандидат (молчание
           рукопожатия — забота SILENT). */
        size_t n0 = build_udp_pkt(p0, 50399, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s0, p0, n0, 6 * S, b0, sizeof b0, &r0);
        d2k_session_sweep(s0, 7 * S);
        CHECK(ct_queries == 0, "conntrack спрошен, хотя наблюдать нечего");
        d2k_session_free(s0);
    }

    /* Обрыв: сервер дал 14 пакетов (очередь видела 8), дальше молчит; клиент
       шлёт повторы. */
    d2k_session *s = stall_flow(50400, 8);
    ct_write(50400, 12, 14, 1);
    d2k_session_sweep(s, 2 * S);
    ct_write(50400, 13, 14, 1);
    d2k_session_sweep(s, 3 * S);
    CHECK(d2k_session_suspects(s) == 0, "два пакета клиента в тишину уже объявлены обрывом");
    ct_write(50400, 15, 14, 1);
    d2k_session_sweep(s, 4 * S);
    CHECK(last_suspect_code(s) == D2K_SUSPECT_QUIC_STALL,
          "QUIC замолчал после рукопожатия, клиент повторяет — подозрения нет");
    ct_write(50400, 25, 14, 1);
    d2k_session_sweep(s, 9 * S);
    CHECK(d2k_session_suspects(s) == 1, "один поток дал больше одного подозрения");
    d2k_session_free(s);

    /* Рабочий QUIC: обратный счётчик растёт — ни при каком числе пакетов клиента. */
    s = stall_flow(50401, 8);
    for (int i = 0; i < 10; i++) {
        ct_write(50401, 20 + 50 * (uint64_t)i, 30 + 900 * (uint64_t)i, 1);
        d2k_session_sweep(s, (uint64_t)(2 + i) * S);
    }
    CHECK(d2k_session_suspects(s) == 0, "рабочая загрузка по QUIC объявлена обрывом");
    d2k_session_free(s);

    /* Обычное окончание: последний ACK клиента и его CONNECTION_CLOSE остаются
       без ответа законно — два пакета в тишину не обрыв. */
    s = stall_flow(50402, 8);
    ct_write(50402, 20, 40, 1);
    d2k_session_sweep(s, 2 * S);
    ct_write(50402, 22, 40, 1);
    d2k_session_sweep(s, 30 * S);
    CHECK(d2k_session_suspects(s) == 0, "ACK и CONNECTION_CLOSE клиента объявлены обрывом");
    d2k_session_free(s);

    /* Обратный счётчик не ушёл за окно очереди: это молчание рукопожатия,
       у него свой детектор (SILENT), не этот. */
    s = stall_flow(50403, 1);
    ct_write(50403, 3, 1, 1);
    d2k_session_sweep(s, 1 * S + 100000000ull);
    ct_write(50403, 9, 1, 1);
    d2k_session_sweep(s, 1 * S + 900000000ull);
    CHECK(last_suspect_code(s) != D2K_SUSPECT_QUIC_STALL,
          "молчание до конца рукопожатия выдано за обрыв после него");
    d2k_session_free(s);

    /* Счётчиков в таблице нет (accounting выключен) — сказать нечего. */
    s = stall_flow(50404, 8);
    ct_write(50404, 0, 0, 0);
    d2k_session_sweep(s, 2 * S);
    d2k_session_sweep(s, 6 * S);
    CHECK(d2k_session_suspects(s) == 0, "строка без счётчиков дала подозрение");
    d2k_session_free(s);

    /* Тишина короче PTO: клиент шлёт три пакета за полсекунды — сервер ещё
       мог не успеть ответить. */
    s = stall_flow(50405, 8);
    ct_write(50405, 12, 14, 1);
    d2k_session_sweep(s, 2 * S);
    ct_write(50405, 15, 14, 1);
    d2k_session_sweep(s, 2 * S + 500000000ull);
    CHECK(d2k_session_suspects(s) == 0, "тишина короче PTO объявлена обрывом");
    d2k_session_free(s);

    /* Один наблюдаемый поток — один запрос на обход, не чтение таблицы. */
    s = stall_flow(50406, 8);
    ct_write(50406, 12, 14, 1);
    ct_queries = 0;
    d2k_session_sweep(s, 2 * S);
    CHECK(ct_queries == 1, "на обход ушло не по одному запросу на наблюдаемый поток");
    d2k_session_free(s);
}

/* --- ОДНОСТОРОННЕЕ ЗАГЛУШЕНИЕ ИСХОДЯЩЕГО: ДЕТЕКТОР МОЛЧИТ (задача 31) -----
 * (12.10.2026)
 *
 * Оба измеренных цензора QUIC роняют пакеты только В ИСХОДЯЩЕМ направлении
 * (Россия, ТСПУ: FOCI 2026(2) §3, остаточная блокировка 420 с по четвёрке,
 * любой пакет сбрасывает таймер; Китай, GFW: USENIX Security 25, 180 с, причём
 * блок включается с задержкой — уже ПОСЛЕ прошедшего рукопожатия). Пока
 * исходящее заглушено, сервер повторяет свой последний полёт по таймеру PTO
 * (RFC 9002 §6.2), поэтому обратный счётчик conntrack РАСТЁТ, и ct_flow на
 * каждом его сдвиге обнуляет свой таймер и свою отметку прямого счётчика.
 *
 * ЧТО СЕГОДНЯШНЕМУ ct_flow НУЖНО ДЛЯ ПОДОЗРЕНИЯ: чтобы в ОДНОМ промежутке
 * между полётами сервера уместились сразу две вещи — целый PTO
 * (max(3·RTT, 1 с)) и не меньше ТРЁХ пакетов клиента. Промер по сетке
 * «период повторов сервера × постоянная скорость клиента» (стенд этого файла,
 * шаг обхода 1 с):
 *
 *     сервер \ клиент   1 пак/с   2 пак/с   3 пак/с   4 пак/с
 *     каждые 1 с        никогда   никогда   никогда   никогда
 *     каждые 2 с        никогда   никогда     3 с       3 с
 *     каждые 3 с        никогда     5 с       4 с       4 с
 *     каждые 4 с          7 с       6 с       3 с       3 с
 *
 * Эта сетка СОБЛАЗНЯЕТ сказать, что RFC-совместимый сервер ловится сам: у него
 * промежуток удваивается (RFC 9002 §6.2.1) и быстро уходит за 4 с. Но клиент
 * при заглушённом исходящем НЕ шлёт с постоянной скоростью: подтверждений он
 * не получает, поэтому его собственный pto_count тоже растёт, и в один
 * промежуток сервера он кладёт примерно ДВА пакета — ACK на полёт сервера
 * (RFC 9000 §13.2.1) и свой зонд PTO. Трёх не выходит ни разу.
 *
 * Поэтому проверка 1 ниже — реальный класс, и она закрепляет ДЕФЕКТ:
 * подозрения нет НИКОГДА за всю жизнь записи (120 с после последнего пакета в
 * окне очереди, --idle), ни при какой базе PTO. Цель исчезает без следа в
 * журнале, поиск не начинается.
 *
 * ПОЧЕМУ ДЕФЕКТ ЗДЕСЬ НЕ ЗАКРЫТ. Признак «лестница PTO в промежутках
 * обратного счётчика» измерим и у него есть опора в RFC 9002 §6.2.1
 * (подтверждение сбрасывает pto_count, значит удвоений подряд у слышащего
 * сервера быть не может). Но при секундном опросе счётчиков он не отделяется
 * от СЛУЧАЙНОГО каданса сервера: три роста промежутка подряд даёт 10,3 %
 * потоков с памятью-нулём (экспоненциальные интервалы, среднее 1–15 с,
 * 3000 прогонов на точку), а это подбор на рабочем трафике и прямой запрет
 * §0 ТЗ. Пять ростов подряд дают 0,03 % промахов, но срабатывают на 106–257-й
 * секунде, то есть позже, чем живёт запись. Учащение опроса не помогает:
 * стоимость самой лестницы 2^N·база от шага опроса не зависит, а промахов при
 * 10 Гц становится больше (47 % на трёх ростах). Отношение прямого счётчика к
 * обратному тоже не делит классы: клиент не знает, что его не слышат, и по
 * RFC 9000 §13.2.1/§13.2.2 подтверждает повторы, поэтому orig ≈ reply/2 и при
 * заглушении, и у здоровой загрузки. Размеры датаграмм и каданс внутри полёта
 * из счётчиков не видны вовсе: после `connbytes 0:8` очередь этих пакетов не
 * получает. Признака, который был бы и измеренным, и безопасным для §0, в
 * нынешних наблюдаемых датапата нет — это записано как результат, а не как
 * недоделка.
 *
 * ЧТО СДЕЛАНО ВМЕСТО КАДАНСА (задача 36, 12.10.2026). Единственное, что
 * датапат об этом классе сказать может, — не каданс, а ОТСУТСТВИЕ УЛИК на
 * истечении записи: см. test_quic_no_proof_ask ниже. Кадансовые проверки
 * этого теста поэтому остаются зелёными и остаются в силе: подозрения по
 * счётчикам по-прежнему нет ни в одном из 16 случаев, и когда кто-нибудь всё
 * же найдёт безопасный кадансовый признак, упадёт именно проверка 1. */
static void test_quic_oneway_block(void) {
    const uint64_t S = 1000000000ull;

    /* 1. РЕАЛЬНЫЙ КЛАСС: ОБЕ стороны на своих лестницах PTO. Сервер — полёты
       с удвоением промежутка от базы b; клиент — ACK на полёт сервера
       (RFC 9000 §13.2.1) плюс свой зонд PTO, тоже с удвоением, потому что
       подтверждений он не получает. RFC 9002 §6.2.4 разрешает один ИЛИ два
       пакета за срабатывание — перебираются оба числа для обеих сторон и
       четыре базы, 16 случаев. Подозрения нет НИ В ОДНОМ за 120 с (отдельным
       прогоном проверено и удвоенное число ACK клиента по RFC 9000 §13.2.2 —
       тоже ни одного).
       Причина ровно одна: ct_orig_mark обнуляется на КАЖДОМ полёте сервера, а
       пакеты клиента в одностороннем блоке идут В ФАЗЕ с этими полётами (ACK
       на полёт и зонд по тому же таймеру), поэтому внутри промежутка их почти
       не бывает, и трёх не набирается никогда.
       ЭТО ДЕФЕКТ: когда он будет закрыт, упадёт именно здесь, и проверку надо
       переписать на новое измеренное поведение. */
    static const uint64_t base_ms[] = {200, 500, 1000, 2000};
    for (int srv_pk = 1; srv_pk <= 2; srv_pk++) {
    for (int cli_pk = 1; cli_pk <= 2; cli_pk++) {
    for (size_t bi = 0; bi < sizeof base_ms / sizeof *base_ms; bi++) {
        d2k_session *s = stall_flow(50410, 8);
        uint64_t orig = 12, reply = 14;
        /* Времена в миллисекундах: у лестницы целые промежутки, и округления
           с плавающей точкой в регрессию не попадают. Заглушение с 2000 мс. */
        uint64_t ts = 2000, is = base_ms[bi], tc = 2000, ic = base_ms[bi];
        for (uint64_t t = 3; t <= 120; t++) {
            while (ts + is <= t * 1000) {
                ts += is; is *= 2;
                reply += (uint64_t)srv_pk;
                orig += 1;                   /* ACK клиента на полёт */
            }
            while (tc + ic <= t * 1000) {
                tc += ic; ic *= 2;
                orig += (uint64_t)cli_pk;    /* свой зонд PTO */
            }
            ct_write(50410, orig, reply, 1);
            d2k_session_sweep(s, t * S);
        }
        CHECK(d2k_session_suspects(s) == 0,
              "лестницы PTO обеих сторон дали подозрение — дефект закрыт, перепишите проверку");
        d2k_session_free(s);
    }}}

    /* 2. ГРАНИЦА СЕГОДНЯШНЕГО ПРАВИЛА с рабочей стороны: сервер повторяет раз
       в 4 с, клиент шлёт пакет в секунду — в один промежуток укладываются и
       целый PTO, и три пакета клиента. Это закрепляет, что форма «счётчик
       стоит» работает и при РАСТУЩЕМ счётчике, если промежуток достаточно
       велик; именно поэтому дефект узкий, а не всеобъемлющий. */
    d2k_session *s = stall_flow(50411, 8);
    uint64_t orig = 12, reply = 14, fired = 0;
    for (uint64_t t = 2; t <= 60; t++) {
        if (t % 4 == 0) { reply += 2; }
        orig += 1;
        ct_write(50411, orig, reply, 1);
        d2k_session_sweep(s, t * S);
        if (!fired && d2k_session_suspects(s)) { fired = t; }
    }
    CHECK(last_suspect_code(s) == D2K_SUSPECT_QUIC_STALL,
          "промежуток в 4 с с тремя пакетами клиента не дал подозрения");
    CHECK(fired == 7, "такой промежуток замечен не на 7-й секунде");
    d2k_session_free(s);

    /* 3. ГРАНИЦА С ДРУГОЙ СТОРОНЫ: шторм повторов (сдвиг счётчика на каждом
       отсчёте обхода) — так вёл себя стенд петли core/test_quic_repro_budget.c
       в режиме M_ONEWAY, 32 547 датаграмм. Промежуток не доходит до PTO
       никогда, подозрения нет при любой скорости клиента. */
    s = stall_flow(50412, 8);
    orig = 12; reply = 14;
    for (uint64_t t = 2; t <= 120; t++) {
        reply += 40;
        orig += 4;
        ct_write(50412, orig, reply, 1);
        d2k_session_sweep(s, t * S);
    }
    CHECK(d2k_session_suspects(s) == 0,
          "шторм повторов стал подозрением — граница сдвинулась, перепишите проверку");
    d2k_session_free(s);
}

/* --- QUIC ДЛЯ ИМЕНИ НЕ ПРОПУСКАЕТСЯ (задача 50, раунд 2, требование 5c) ----
 *
 * Обрыв QUIC после рукопожатия воспроизведён своим запросом, обхода по QUIC
 * нет: контроллер ставит на имя план «quicdeny». Каждая датаграмма клиента
 * этого потока, которую видит очередь, снимается — рукопожатие не
 * складывается, и браузер уходит на TCP (там свой поиск). Это НЕ обход QUIC
 * (§4 спецификации): ни посылок, ни события APPLIED. Зонд контроллера не
 * снимается — иначе перепроверить имя было бы нечем. Молчание потока, которое
 * мы устроили сами, подозрением не становится. */
static const uint8_t plan_deny[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 11, 0, 0, 0, 2,
    0x00, 0x02, 0x00, 0x02, 17, 2,
    0x01, 0x10, 0x00, 0x01, 0x01,
};
static const uint8_t plan_deny_tcp[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 11, 0, 0, 0, 2,
    0x00, 0x02, 0x00, 0x02, 6, 1,
    0x01, 0x10, 0x00, 0x01, 0x01,
};
static const uint8_t plan_deny_old[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 10, 0, 0, 0, 2,
    0x00, 0x02, 0x00, 0x02, 17, 2,
    0x01, 0x10, 0x00, 0x01, 0x01,
};

static void test_quic_deny(void) {
    const uint64_t S = 1000000000ull;
    char err[160];
    d2k_plan *p = NULL;
    CHECK(d2k_plan_load(plan_deny, sizeof plan_deny, &p, err, sizeof err) == 0,
          "план quicdeny не разобрался");
    CHECK(p && d2k_plan_quic_deny(p), "план quicdeny не опознан");
    d2k_plan *bad = NULL;
    CHECK(d2k_plan_load(plan_deny_tcp, sizeof plan_deny_tcp, &bad, err, sizeof err) != 0,
          "quicdeny принят для TCP");
    CHECK(d2k_plan_load(plan_deny_old, sizeof plan_deny_old, &bad, err, sizeof err) != 0,
          "quicdeny принят без minexec=11");
    if (!p) return;

    d2k_session *s = d2k_session_new(64, 64);
    CHECK(d2k_plantab_set_name_family(d2k_session_plans(s), (const uint8_t *)"example.com", 11,
                                      1, p, D2K_PLAN_SHAPE_QUIC, 0, 4) == 0,
          "quicdeny не встал на имя");
    uint8_t pkt[1300], buf[4096];
    d2k_result r;
    /* Обратная сторона видна — молчание иначе не рассматривалось бы вовсе. */
    const uint8_t any[4] = {1, 2, 3, 4};
    size_t n = build_udp_rev_pkt(pkt, 50500, any, sizeof any);
    d2k_session_packet(s, pkt, n, 1 * S, buf, sizeof buf, &r);

    n = build_udp_pkt(pkt, 50501, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet(s, pkt, n, 2 * S, buf, sizeof buf, &r);
    CHECK(r.verdict == D2K_VERDICT_DROP && r.n_out == 0,
          "Initial имени без обхода по QUIC не снят (или ушли посылки)");
    CHECK(r.quic_deny == 1, "снятие quicdeny не помечено для удержанной пачки");
    CHECK(count_journal_kind(s, D2K_JRN_PLAN_APPLIED) == 0,
          "снятие QUIC выдано контроллеру за применение плана");
    /* Повтор Initial по PTO — тоже снимается: иначе рукопожатие сложится
       со второй попытки. */
    d2k_session_packet(s, pkt, n, 3 * S, buf, sizeof buf, &r);
    CHECK(r.verdict == D2K_VERDICT_DROP, "повтор Initial прошёл мимо quicdeny");
    d2k_session_sweep(s, 10 * S);
    CHECK(d2k_session_suspects(s) == 0, "молчание, устроенное quicdeny, стало подозрением");

    /* Зонд контроллера того же имени не снимается. */
    n = build_udp_pkt(pkt, 50502, 443, v1_initial, sizeof v1_initial);
    d2k_session_packet_probe(s, pkt, n, 11 * S, buf, sizeof buf, &r);
    CHECK(r.verdict != D2K_VERDICT_DROP, "quicdeny снял зонд контроллера");
    d2k_session_free(s);
}

/* --- QUIC: УЛИК УСПЕХА НЕТ — И СПРАШИВАТЬ ПО ЭТОМУ НЕЛЬЗЯ (задача 40) ---
 *
 * Кадансового признака одностороннего блока в счётчиках conntrack нет и быть
 * не может (см. шапку test_quic_oneway_block выше: три кандидата отвергнуты
 * числами). Датапат не видит, доходят ли НАШИ пакеты, а именно это отличает
 * повтор полёта сервера от ответа.
 *
 * Назвать ОТСУТСТВИЕ УЛИК датапат может: поток QUIC показал приветствие с
 * именем, обратная сторона ответила, а код обмена остался
 * D2K_UDP_PROOF_NONE, и запись дожила до конца срока. Но СПРАШИВАТЬ по этому
 * нельзя, и это решение, снятое с поля, а не осторожность.
 *
 * ИСТОРИЯ ТРЁХ РЕДАКЦИЙ И ЧЕМ ОНА КОНЧИЛАСЬ.
 *   330d789 — калитка заведена на доказательстве «короткий заголовок 1-RTT от
 *     сервера» (RFC 9000 §17.3: до прикладных ключей он прийти не может).
 *     Основание — пять рукопожатий Google и Apple: первый такой пакет седьмым
 *     обратным при окне очереди 0:8, «запас один пакет».
 *   96bafd2 — замер 114 сеансов настоящего Chrome (scripts/quic-proof-margin.py)
 *     показал, что запас ОТРИЦАТЕЛЬНЫЙ: 5,3 % здоровых сеансов кладут
 *     доказательство в датаграмму 9–17. Калитка сужена: доказательство ищется
 *     проходом по склейке, и события нет при исчерпанном окне обратных
 *     датаграмм. В лабораторной выборке ложных поводов стало 0.
 *   ПОЛЕ 12.10.2026v (docs/field/2026-10-12g) сузило не до нуля, а до 4:
 *     калитка сработала по www.gstatic.com, двум адресам Cloudflare и
 *     imagedelivery.net за 14 минут браузинга. По www.gstatic.com замер,
 *     запущенный ЭТОЙ ЖЕ калиткой, ответил probe-direct — цель не блокирована
 *     вовсе. Цена четырёх поводов: 97 единиц зондов, планов построено 0.
 *
 * ПОЧЕМУ НЕ СУЗИТЬ ЕЩЁ РАЗ. Оставшийся класс — «клиент перестал спрашивать»
 * (гонка соединений, закрытая вкладка, пул). Единственный различитель,
 * доступный датапату, — упорство клиента, и он ИЗМЕРЕН в том же прогоне по
 * netlog: у трёх кандидатов калитки наших пакетов было 11, 12 и 6, а у
 * здоровых сеансов с доказательством — 6…12. Тот же диапазон. Различить эти
 * классы наблюдаемыми датапата нечем, поэтому калитка снята целиком, вместе с
 * признаком quic_app_proof и проходом по склейке: вопрос «молчит ли QUIC у
 * пользователя» остаётся за живым критерием (scripts/live-protocol.mjs,
 * alt-svc как опровергатель) и за своим запросом HTTP/3, у которого есть
 * настоящий повод.
 *
 * Проверки ниже закрепляют именно это: ни одна форма молчащего потока QUIC
 * события не даёт. */
static void test_quic_no_proof_ask(void) {
    const uint64_t S = 1000000000ull;
    const uint64_t IDLE = 120 * S;   /* ровно то, что ставит d2kd (--idle 120) */

    /* 1. ВСЕ ЧЕТЫРЕ ФОРМЫ МОЛЧАЩЕГО ПОТОКА QUIC — СОБЫТИЯ НЕТ НИ У ОДНОЙ.
       Прежде первая из них давала повод спросить; поле 12.10.2026v показало,
       что отличить её от остальных нечем (см. шапку: наших пакетов 11/12/6
       против 6…12 у здоровых). Проверка оставлена не для симметрии — она
       падает, если калитку заведут снова на тех же наблюдаемых. */
    {
        /* Заглушённый на вид: от сервера только длинные заголовки, коротких
           полётов шесть, рукопожатие не кончилось. */
        d2k_session *s = quic_flow_first_byte(50420, 6, 0xc3);
        CHECK(count_journal_kind(s, D2K_JRN_HELLO_SNI) == 1,
              "стенд не записал приветствие с именем");
        CHECK(count_journal_kind(s, D2K_JRN_EXCHANGE) == 1,
              "стенд не записал обмен");
        CHECK(d2k_session_expire(s, 200 * S, IDLE) == 1,
              "запись QUIC не истекла через 120 с молчания");
        CHECK(d2k_session_suspects(s) == 0,
              "поток QUIC без доказательства снова даёт повод спросить: поле "
              "12.10 назвало такой повод ложным (www.gstatic.com → probe-direct)");
        d2k_session_free(s);
    }
    {
        /* Здоровый h3: сервер прислал короткий заголовок. */
        d2k_session *s = quic_flow_first_byte(50421, 6, 0x40);
        CHECK(d2k_session_expire(s, 200 * S, IDLE) == 1,
              "здоровая запись не истекла");
        CHECK(d2k_session_suspects(s) == 0,
              "здоровый поток h3 дал повод спросить: это подбор на рабочем "
              "трафике (§0)");
        d2k_session_free(s);
    }
    {
        /* Склейка «Handshake + 1-RTT» в одной датаграмме — форма, встреченная
           замером 12.10 («HAND#9 + S#10»). Сама по себе она больше ни на что
           не влияет, но поток такого вида события давать не вправе. */
        uint8_t pay[128];
        size_t len = build_coalesced_hand_then_short(pay, sizeof pay);
        CHECK(len > 0, "стенд не собрал склеенную датаграмму");
        d2k_session *s = quic_flow_rev_payload(50423, pay, len);
        CHECK(d2k_session_expire(s, 200 * S, IDLE) == 1, "запись не истекла");
        CHECK(d2k_session_suspects(s) == 0,
              "поток со склейкой дал повод спросить");
        d2k_session_free(s);
    }
    {
        /* Окно обратных датаграмм исчерпано (D2K_HELLO_WINDOW штук): дальше
           датапат не смотрел вовсе, и 5,3 % здоровых сеансов кладут
           доказательство именно за этой границей. */
        d2k_session *s = quic_flow_first_byte(50424, 8, 0xc3);
        CHECK(d2k_session_expire(s, 200 * S, IDLE) == 1, "запись не истекла");
        CHECK(d2k_session_suspects(s) == 0,
              "исчерпанное окно дало повод спросить — это догадка, не замер");
        d2k_session_free(s);
    }

    /* 2. §0 ТЗ: УЛИКА ЕСТЬ — СОБЫТИЯ НЕТ НИКОГДА. Прикладное доказательство
       любого вида, кроме D2K_UDP_PROOF_NONE: ответ IP Discovery с тем же SSRC
       и ответ STUN с тем же transaction ID. Оба — потоки с именем класса
       голоса, оба отвечены, оба истекают по тому же сроку. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[256], buf[4096], disc[74], reply[74];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 64420, 50004, disc, build_ip_discovery(disc, 0x4242));
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1 * S, buf, sizeof buf, &r);
        build_ip_discovery_response(reply, 0x4242);
        n = build_udp_pkt(pkt, 64420, 50004, reply, sizeof reply);
        swap_udp_ends(pkt);
        d2k_session_set_hook(s, D2K_HOOK_FORWARD);
        d2k_session_packet(s, pkt, n, 2 * S, buf, sizeof buf, &r);
        CHECK(journal_code_seen(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_VOICE_DISCOVERY),
              "стенд не получил прикладного доказательства голоса");
        CHECK(d2k_session_expire(s, 200 * S, IDLE) == 1, "голосовая запись не истекла");
        CHECK(d2k_session_suspects(s) == 0,
              "поток с прикладным доказательством дал событие об отсутствии улик");
        d2k_session_free(s);
    }
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t req[32], resp[32], pkt[256], buf[4096];
        uint8_t txid[12] = {3,1,4,1,5,9,2,6,5,3,5,8};
        d2k_result r;
        size_t rn = build_stun_binding(req, 0x0001, txid);
        size_t n = build_udp_pkt(pkt, 64421, 50004, req, rn);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1 * S, buf, sizeof buf, &r);
        size_t sn = build_stun_binding(resp, 0x0101, txid);
        n = build_udp_rev_pkt(pkt, 64421, resp, sn);
        wr16(pkt + 20, 50004);
        d2k_session_set_hook(s, D2K_HOOK_FORWARD);
        d2k_session_packet(s, pkt, n, 2 * S, buf, sizeof buf, &r);
        CHECK(journal_code_seen(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_STUN),
              "стенд не получил прикладного доказательства STUN");
        CHECK(d2k_session_expire(s, 200 * S, IDLE) == 1, "запись STUN не истекла");
        CHECK(d2k_session_suspects(s) == 0,
              "поток с доказательством STUN дал событие об отсутствии улик");
        d2k_session_free(s);
    }

    /* 3. ГОЛОС И STUN БЕЗ ОТВЕТА — ТОЖЕ НЕ ЭТОТ КЛАСС. Событие названо про
       QUIC, и голосовой поток в него не попадает даже тогда, когда улики у
       него нет: у разговора свой путь подтверждения (§4 ТЗ), и выдать его
       тишину за вопрос по QUIC значило бы подменить протокол. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        uint8_t pkt[256], buf[4096], disc[74];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 64422, 50004, disc, build_ip_discovery(disc, 0x77));
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 1 * S, buf, sizeof buf, &r);
        uint8_t any[8] = {0};
        n = build_udp_pkt(pkt, 64422, 50004, any, sizeof any);
        swap_udp_ends(pkt);
        d2k_session_set_hook(s, D2K_HOOK_FORWARD);
        d2k_session_packet(s, pkt, n, 2 * S, buf, sizeof buf, &r);
        CHECK(journal_code_seen(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_NONE),
              "стенд не получил обмена без доказательства");
        d2k_session_expire(s, 200 * S, IDLE);
        CHECK(d2k_session_suspects(s) == 0,
              "голосовой поток без улики выдан за вопрос по QUIC");
        d2k_session_free(s);
    }

    /* 4. ОТВЕТА НЕ БЫЛО ВОВСЕ — это не этот класс, а молчание рукопожатия, и
       у него свой детектор (sweep_udp_one). Истечение не вправе объявлять
       молчанием всякий забытый UDP-поток: это обошло бы условие про повтор
       клиента через заднюю дверь (см. d2k_session_expire). */
    {
        d2k_session *s = stall_flow(50421, 0);
        CHECK(count_journal_kind(s, D2K_JRN_EXCHANGE) == 0, "стенд получил обмен");
        CHECK(d2k_session_expire(s, 200 * S, IDLE) == 1, "запись не истекла");
        CHECK(d2k_session_suspects(s) == 0,
              "забытый UDP-поток без ответа объявлен вопросом по QUIC");
        d2k_session_free(s);
    }

    /* 5. ПОДОЗРЕНИЕ УЖЕ БЫЛО — второго события по тому же потоку нет: три
       улики об одном соединении выглядели бы как три соединения. Поток
       доводится до D2K_SUSPECT_QUIC_STALL счётчиками, а потом истекает. */
    {
        d2k_session *s = stall_flow(50411, 8);
        uint64_t orig = 12, reply = 14;
        for (uint64_t t = 2; t <= 10; t++) {
            if (t % 4 == 0) { reply += 2; }
            orig += 1;
            ct_write(50411, orig, reply, 1);
            d2k_session_sweep(s, t * S);
        }
        CHECK(last_suspect_code(s) == D2K_SUSPECT_QUIC_STALL,
              "стенд не довёл поток до подозрения об обрыве");
        CHECK(d2k_session_expire(s, 200 * S, IDLE) == 1, "запись не истекла");
        CHECK(d2k_session_suspects(s) == 1,
              "истечение добавило второе событие к уже подозреваемому потоку");
        CHECK(last_suspect_code(s) == D2K_SUSPECT_QUIC_STALL,
              "истечение перебило уже сказанное подозрение");
        d2k_session_free(s);
    }

    /* 6. ЗОНД КОНТРОЛЛЕРА — не улика о живом трафике ни в какую сторону. */
    {
        const uint8_t any[40] = {0x40};
        d2k_session *s = d2k_session_new(64, 64);
        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 50422, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet_probe(s, pkt, n, 1 * S, buf, sizeof buf, &r);
        n = build_udp_rev_pkt(pkt, 50422, any, sizeof any);
        d2k_session_packet(s, pkt, n, 1 * S + 50000000ull, buf, sizeof buf, &r);
        CHECK(d2k_session_expire(s, 200 * S, IDLE) == 1, "запись зонда не истекла");
        CHECK(d2k_session_suspects(s) == 0, "зонд контроллера дал событие о себе");
        d2k_session_free(s);
    }

    /* 7. МОЛЧАНИЕ, УСТРОЕННОЕ НАМИ (quicdeny), вопросом не становится: своей
       же работы датапат коробке не приписывает. */
    {
        char err[160];
        d2k_plan *p = NULL;
        CHECK(d2k_plan_load(plan_deny, sizeof plan_deny, &p, err, sizeof err) == 0 && p,
              "план quicdeny не разобрался");
        d2k_session *s = d2k_session_new(64, 64);
        CHECK(d2k_plantab_set_name_family(d2k_session_plans(s),
                                          (const uint8_t *)"example.com", 11,
                                          1, p, D2K_PLAN_SHAPE_QUIC, 0, 4) == 0,
              "quicdeny не встал на имя");
        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        const uint8_t any[40] = {0x40};
        size_t n = build_udp_rev_pkt(pkt, 50423, any, sizeof any);
        d2k_session_packet(s, pkt, n, 1 * S, buf, sizeof buf, &r);
        n = build_udp_pkt(pkt, 50423, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 2 * S, buf, sizeof buf, &r);
        d2k_session_expire(s, 200 * S, IDLE);
        CHECK(d2k_session_suspects(s) == 0,
              "молчание, устроенное quicdeny, стало вопросом по QUIC");
        d2k_session_free(s);
    }
}

static size_t measured_udp_packet(uint8_t *out,int family,int reverse,uint16_t port,
                                  const uint8_t *data,size_t len) {
    uint8_t v4[1500];
    size_t n=reverse?build_udp_rev_pkt(v4,49001,data,len):build_udp_pkt(v4,49001,port,data,len);
    if(family==4){memcpy(out,v4,n);return n;}
    memset(out,0,40);out[0]=0x60;wr16(out+4,(uint16_t)(n-20));out[6]=17;out[7]=64;
    out[8]=out[24]=0x20;out[9]=out[25]=1;out[10]=out[26]=0x0d;out[11]=out[27]=0xb8;
    out[23]=v4[15];out[39]=v4[19];memcpy(out+40,v4+20,n-20);return n+20;
}
static int measured_nat6(const char *path,uint8_t proto,const uint8_t *src,uint16_t sp,
                         const uint8_t *dst,uint16_t dp,uint8_t family,uint8_t *ext,uint16_t *ep) {
    if(frag_nat_missing)return frag_nat_missing==2?1:-1;
    return frag_nat6(path,proto,src,sp,dst,dp,family,ext,ep);
}
static void test_measured_udp_packet_scope(int family, int progress) {
    d2k_session *s=d2k_session_new(32,64);CHECK(s!=NULL,"measured UDP session");if(!s)return;
    d2k_nat_family_fn saved_nat6=d2k_nat_family_hook;d2k_nat_family_hook=measured_nat6;
    d2k_nat_fn saved_nat=d2k_nat_hook;frag_nat_missing=0;d2k_nat_hook=frag_nat;
    d2k_session_set_udp_reverse_hook(s,1);
    uint8_t packet[1500],scratch[8192],data[20];memset(data,'q',sizeof data);d2k_result out;
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    size_t n=measured_udp_packet(packet,family,0,443,data,sizeof data);
    d2k_session_packet(s,packet,n,1,scratch,sizeof scratch,&out);
    struct d2k_rawmeasure_report report={0};report.request.tuple.family=(uint8_t)family;report.request.tuple.proto=17;
    memcpy(report.request.tuple.src,packet+(family==6?8:12),family==6?16:4);
    memcpy(report.request.tuple.dst,packet+(family==6?24:16),family==6?16:4);
    unsigned l4=family==6?40:20;
    memcpy(report.request.tuple.sport_be,packet+l4,2);memcpy(report.request.tuple.dport_be,packet+l4+2,2);
    int prior=0;
    CHECK(!d2k_session_raw_identity(s,&report.request.tuple,report.request.epoch,&report.request.generation,&prior)&&!prior,
          "new UDP flow inherited prior reply");
    d2k_session_set_hook(s,D2K_HOOK_FORWARD);n=measured_udp_packet(packet,family,1,443,data,sizeof data);
    d2k_session_packet(s,packet,n,2,scratch,sizeof scratch,&out);
    CHECK(!d2k_session_raw_identity(s,&report.request.tuple,report.request.epoch,&report.request.generation,&prior)&&prior,
          "same-flow UDP reply not available to measurement");
    /* Measured trials must survive the ordinary initial parse window. */
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    n=measured_udp_packet(packet,family,0,443,data,sizeof data);
    for(unsigned i=0;i<12;i++)d2k_session_packet(s,packet,n,2,scratch,sizeof scratch,&out);
    CHECK(!d2k_session_late_watch(s,&report.request.tuple,1),"UDP late delivery fixture");
    report.request.token[0]=1;report.request.seconds=10;report.code=D2K_RM_REPEAT_SILENT;
    report.flags=D2K_RM_PRIOR_REPLY;report.sample_len=report.smallest_data=report.largest_data=sizeof data;
    report.client_data=2;report.exact_repeats=1;d2k_sha256(data,sizeof data,report.sample_digest);
    const uint8_t tlv[]={'D','2','K','P',0,1,0,7,0,0,0,2,0,2,0,2,17,2,1,12,0,1,1};
    uint8_t trial[16]={9};d2k_plan *plan=NULL;char err[160];
    CHECK(!d2k_plan_load(tlv,sizeof tlv,&plan,err,sizeof err),"measured UDP fragment plan load");
    CHECK(!d2k_plantab_set_measured_probe(d2k_session_plans(s),&report,trial,(const uint8_t[32]){1},3,1000,plan),"measured UDP plan install");
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    n=measured_udp_packet(packet,family,0,443,data,sizeof data);packet[family==6?23:15]=68;
    d2k_session_packet(s,packet,n,4,scratch,sizeof scratch,&out);CHECK(!out.applied,"UDP candidate leaked to other client");
    n=measured_udp_packet(packet,family,0,8443,data,sizeof data);
    d2k_session_packet(s,packet,n,5,scratch,sizeof scratch,&out);CHECK(!out.applied,"UDP candidate leaked to other service");
    n=measured_udp_packet(packet,family,0,443,data,sizeof data);packet[l4+8]='r';
    d2k_session_packet(s,packet,n,6,scratch,sizeof scratch,&out);CHECK(!out.applied,"UDP candidate accepted changed payload");
    packet[l4+8]='q';frag_nat_missing=1;
    d2k_session_packet(s,packet,n,7,scratch,sizeof scratch,&out);
    CHECK(!out.applied,"UDP fragmented without confirmed NAT context");
    frag_nat_missing=2;d2k_session_packet(s,packet,n,8,scratch,sizeof scratch,&out);
    CHECK(!out.applied,"absent conntrack table treated as no-NAT proof");
    int local_refusal=0;const d2k_journal *before=d2k_session_journal(s);
    for(size_t i=0;i<d2k_journal_count(before);i++) {
        const d2k_jrn_entry *e=d2k_journal_at(before,i);
        if(e->kind==D2K_JRN_PLAN_REFUSED&&e->code==D2K_REFUSE_CONTEXT&&!memcmp(e->trial_id,trial,16))local_refusal++;
    }
    if(local_refusal!=2)for(size_t i=0;i<d2k_journal_count(before);i++) {
        const d2k_jrn_entry *e=d2k_journal_at(before,i);
        if(e->kind==D2K_JRN_PLAN_REFUSED)fprintf(stderr,"UDP local refusal code=%u trial=%u\n",e->code,e->trial_id[0]);
    }
    CHECK(local_refusal==2,"missing NAT context not reported with exact trial identity");
    frag_nat_missing=0;d2k_session_packet(s,packet,n,9,scratch,sizeof scratch,&out);
    CHECK(out.applied&&out.n_out==2&&out.verdict==D2K_VERDICT_DROP&&!memcmp(out.trial_id,trial,16),
          "measured UDP repetition not fragmented with exact trial identity");
    if(!out.applied)fprintf(stderr,"measured UDP skip: %s\n",out.skipped?out.skipped:"none");
    uint64_t execution=out.execution_id;
    CHECK(execution&&!d2k_session_done(s),"prepared measured UDP trial treated as completed sends");
    d2k_session_set_hook(s,D2K_HOOK_FORWARD);
    n=measured_udp_packet(packet,family,1,443,data,0);
    d2k_session_packet(s,packet,n,10,scratch,sizeof scratch,&out);
    n=measured_udp_packet(packet,family,1,443,data,1);
    d2k_session_packet(s,packet,n,11,scratch,sizeof scratch,&out);
    n=measured_udp_packet(packet,family,1,443,(const uint8_t *)"arbitrary",9);
    d2k_session_packet(s,packet,n,12,scratch,sizeof scratch,&out);
    CHECK(jcount(s,D2K_JRN_EXCHANGE,0,NULL,NULL)==0,
          "RAW UDP arbitrary/empty/one-byte reply attributed as trial proof");
    if (progress) {
        n=measured_udp_packet(packet,family,1,443,(const uint8_t *)"server-timer",12);
        d2k_session_packet(s,packet,n,13,scratch,sizeof scratch,&out);
        CHECK(count_journal_kind(s,D2K_JRN_EXCHANGE)==0,"RAW server burst promoted without client progress");
        d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        n=measured_udp_packet(packet,family,0,443,data,sizeof data);
        d2k_session_packet(s,packet,n,14,scratch,sizeof scratch,&out);
        d2k_session_set_hook(s,D2K_HOOK_FORWARD);
        n=measured_udp_packet(packet,family,1,443,(const uint8_t *)"server-timer",12);
        d2k_session_packet(s,packet,n,15,scratch,sizeof scratch,&out);
        CHECK(count_journal_kind(s,D2K_JRN_EXCHANGE)==0,"RAW retransmitted request promoted server burst");
        d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        n=measured_udp_packet(packet,family,0,443,(const uint8_t *)"next-request",12);
        d2k_session_packet(s,packet,n,16,scratch,sizeof scratch,&out);
        d2k_session_set_hook(s,D2K_HOOK_FORWARD);
        n=measured_udp_packet(packet,family,1,443,(const uint8_t *)"arbitrary",9);
        d2k_session_packet(s,packet,n,17,scratch,sizeof scratch,&out);
        CHECK(count_journal_kind(s,D2K_JRN_EXCHANGE)==0,"RAW repeated server bytes promoted progress");
        n=measured_udp_packet(packet,family,1,443,(const uint8_t *)"server-timer",12);
        d2k_session_packet(s,packet,n,17,scratch,sizeof scratch,&out);
        CHECK(count_journal_kind(s,D2K_JRN_EXCHANGE)==0,"RAW known periodic server data promoted progress");
        n=measured_udp_packet(packet,family,1,443,(const uint8_t *)"next-response",13);
        d2k_session_packet(s,packet,n,18,scratch,sizeof scratch,&out);
    } else {
        n=measured_udp_packet(packet,family,1,443,data,sizeof data);
        d2k_session_packet(s,packet,n,13,scratch,sizeof scratch,&out);
    }
    const d2k_journal *j=d2k_session_journal(s);int own=0;
    for(size_t i=0;i<d2k_journal_count(j);i++) {
        const d2k_jrn_entry *e=d2k_journal_at(j,i);
        if(e->kind==D2K_JRN_EXCHANGE&&e->execution_id==execution&&!memcmp(e->trial_id,trial,16)) {
            own++;CHECK(e->code==(progress ? D2K_RAW_PROOF_PROGRESS : D2K_RAW_PROOF_ECHO),"unknown UDP evidence missing path-only proof");
        }
    }
    CHECK(own==1,"measured UDP reply missing exact execution/trial context");
    CHECK(d2k_session_expire(s,100,10)>0,"UDP replacement fixture did not expire flow");
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);n=measured_udp_packet(packet,family,0,443,data,sizeof data);
    d2k_session_packet(s,packet,n,101,scratch,sizeof scratch,&out);
    CHECK(!out.applied,"new UDP incarnation inherited measured plan");
    d2k_session_free(s);d2k_nat_hook=saved_nat;d2k_nat_family_hook=saved_nat6;
}
/* Install a measured UDP fragment probe for `payload` under `trial`, keyed to
   the live flow identity of `packet`. */
static int install_udp_measured(d2k_session *s,const uint8_t *packet,int family,
        const uint8_t *payload,size_t plen,const uint8_t trial[16],uint64_t now) {
    struct d2k_rawmeasure_report r={0};
    r.request.tuple.family=(uint8_t)family;r.request.tuple.proto=17;
    unsigned l4=family==6?40:20;
    memcpy(r.request.tuple.src,packet+(family==6?8:12),family==6?16:4);
    memcpy(r.request.tuple.dst,packet+(family==6?24:16),family==6?16:4);
    memcpy(r.request.tuple.sport_be,packet+l4,2);memcpy(r.request.tuple.dport_be,packet+l4+2,2);
    int prior=0;
    if(d2k_session_raw_identity(s,&r.request.tuple,r.request.epoch,&r.request.generation,&prior))return -1;
    r.request.token[0]=1;r.request.seconds=10;r.code=D2K_RM_REPEAT_SILENT;r.flags=D2K_RM_PRIOR_REPLY;
    r.sample_len=r.smallest_data=r.largest_data=(uint16_t)plen;r.client_data=2;r.exact_repeats=1;
    d2k_sha256(payload,plen,r.sample_digest);
    static const uint8_t tlv[]={'D','2','K','P',0,1,0,7,0,0,0,2,0,2,0,2,17,2,1,12,0,1,1};
    d2k_plan *plan=NULL;char err[160];
    if(d2k_plan_load(tlv,sizeof tlv,&plan,err,sizeof err))return -1;
    return d2k_plantab_set_measured_probe(d2k_session_plans(s),&r,trial,(const uint8_t[32]){1},now,now+1000000000ull,plan);
}
static void complete_sends(d2k_session *s,const d2k_result *r,uint64_t *now) {
    for(size_t i=0;i<=r->n_out;i++)d2k_session_sent(s,(*now)++,&r->key,r->execution_id);
}
/* UDP63: the controller's FRESH measured candidate (after its own plan failed)
   must execute on the same client continuation even though a plan already ran
   on the flow — both inside the hello window and, as the real LAN does, after
   it. The same trial, pending/failed sends, and permanent/address plans stay
   rejected. Mirrors the TCP raw_measured_new refinement. */
static void test_measured_udp_refinement(int family,int past_window) {
    d2k_session *s=d2k_session_new(32,64);CHECK(s!=NULL,"udp refine session");if(!s)return;
    d2k_nat_family_fn sn6=d2k_nat_family_hook;d2k_nat_family_hook=measured_nat6;
    d2k_nat_fn sn=d2k_nat_hook;frag_nat_missing=0;d2k_nat_hook=frag_nat;
    d2k_session_set_udp_reverse_hook(s,1);
    uint8_t packet[1500],scratch[8192],qa[20],rb[20];memset(qa,'q',20);memset(rb,'r',20);
    uint8_t trialA[16]={9},trialB[16]={0x20};d2k_result out,first;uint64_t now=1;size_t n;
    /* Establish the flow and a same-flow reply so a measured probe is valid. */
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    n=measured_udp_packet(packet,family,0,443,qa,20);d2k_session_packet(s,packet,n,now++,scratch,sizeof scratch,&out);
    d2k_session_set_hook(s,D2K_HOOK_FORWARD);
    n=measured_udp_packet(packet,family,1,443,qa,20);d2k_session_packet(s,packet,n,now++,scratch,sizeof scratch,&out);
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    n=measured_udp_packet(packet,family,0,443,qa,20);
    CHECK(!install_udp_measured(s,packet,family,qa,20,trialA,now),"first measured probe install");
    d2k_session_packet(s,packet,n,now++,scratch,sizeof scratch,&first);
    CHECK(first.applied&&first.n_out==2&&first.verdict==D2K_VERDICT_DROP&&!memcmp(first.trial_id,trialA,16),
          "in-window first measured execution missing");
    if(!first.applied){fprintf(stderr,"udp refine first skip: %s\n",first.skipped?first.skipped:"none");}
    if(past_window) {
        /* Push the flow beyond the hello window (session.c D2K_HELLO_WINDOW==8,
           not exported); the already-applied plan makes each filler a plain
           "already applied" miss. */
        for(int i=0;i<12;i++){n=measured_udp_packet(packet,family,0,443,qa,20);
            d2k_session_packet(s,packet,n,now++,scratch,sizeof scratch,&out);CHECK(!out.applied,"filler executed");}
    }
    /* The controller's fresh candidate arrives after the first probe's lease
       (the real repeat was ~123 s later); advance past it so the measured slot
       is free for the new trial. fwd_pkts (the window) is unchanged by time. */
    now=2000000000ull;
    /* Fresh candidate installed; while the first sends are still pending it must
       NOT execute (pending-sends protection), window or not. */
    CHECK(!install_udp_measured(s,packet,family,rb,20,trialB,now),"fresh measured probe install");
    n=measured_udp_packet(packet,family,0,443,rb,20);
    d2k_session_packet(s,packet,n,now++,scratch,sizeof scratch,&out);
    CHECK(!out.applied,"fresh measured trial executed over pending sends");
    /* Complete the first execution's sends, then the fresh trial executes with
       a distinct execution and its own trial, despite plan_done. */
    complete_sends(s,&first,&now);
    n=measured_udp_packet(packet,family,0,443,rb,20);
    d2k_session_packet(s,packet,n,now++,scratch,sizeof scratch,&out);
    CHECK(out.applied&&out.n_out==2&&out.execution_id!=first.execution_id&&!memcmp(out.trial_id,trialB,16),
          past_window?"fresh measured trial rejected after window":"fresh measured trial rejected in window");
    if(!out.applied)fprintf(stderr,"udp refine fresh skip (past=%d): %s\n",past_window,out.skipped?out.skipped:"none");
    d2k_result second=out;
    /* The SAME trial, after its sends complete, does not execute again. */
    complete_sends(s,&second,&now);
    n=measured_udp_packet(packet,family,0,443,rb,20);
    d2k_session_packet(s,packet,n,now++,scratch,sizeof scratch,&out);
    CHECK(!out.applied,"same measured trial executed twice");
    d2k_session_free(s);d2k_nat_hook=sn;d2k_nat_family_hook=sn6;
}
/* UDP63 сессионная непрерывность: демон, взяв во владение первую датаграмму
 * свежего QUIC-потока с планом фрагментации (NAT ещё не подтверждён → defer),
 * продолжает её через d2k_session_udp_continue, когда внешний кортеж
 * подтверждён. Проверяем: один выстрел применяется; устаревшая инкарнация,
 * переиспользованный кортеж, удалённая и переустановленная (то же байты, новое
 * поколение) привязки — отказ; счётчик применений на отказах не растёт. */
static const uint8_t cont_frag_tlv[] =
    {'D','2','K','P',0,1,0,7,0,0,0,2,0,2,0,2,17,2,1,12,0,1,1};

static d2k_session *udp_cont_defer(uint8_t *pkt, size_t *np, d2k_result *r) {
    char err[160];
    d2k_session *s = d2k_session_new(32, 64);
    if (!s) { return NULL; }
    d2k_plan *p = NULL;
    if (d2k_plan_load(cont_frag_tlv, sizeof cont_frag_tlv, &p, err, sizeof err) != 0 ||
        d2k_plantab_set_name_shaped(d2k_session_plans(s), (const uint8_t *)"example.com", 11,
                                    1, p, D2K_PLAN_SHAPE_QUIC) != 0) {
        d2k_session_free(s); return NULL;
    }
    uint8_t buf[8192];
    size_t n = build_udp_pkt(pkt, 50801, 443, v1_initial, sizeof v1_initial);
    *np = n;
    /* Первый QUIC Initial демон держит и повторяет после сборки ClientHello;
       на повторе NAT всё ещё не подтверждён → план фрагментации откладывается,
       а датаграмма помечается кандидатом на владение. */
    d2k_key key;
    d2k_session_udp_hold_begin(s, pkt, n, 1000, &key);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, r);
    d2k_session_udp_hold_replay(s, &key);
    d2k_session_packet(s, pkt, n, 1001, buf, sizeof buf, r);
    return s;
}

static void fill_reply(d2k_ct_info *m, int good_server) {
    memset(m, 0, sizeof *m);
    m->reply_tuple_known = 1;
    m->reply_tuple.family = 4; m->reply_tuple.proto = 17;
    uint8_t good[4] = {1, 2, 3, 4}, bad[4] = {9, 9, 9, 9};
    memcpy(m->reply_tuple.src, good_server ? good : bad, 4);          /* сервер */
    uint8_t ext[4] = {203, 0, 113, 9}; memcpy(m->reply_tuple.dst, ext, 4); /* внешний */
    m->reply_tuple.sport_be[0] = (uint8_t)(443 >> 8); m->reply_tuple.sport_be[1] = (uint8_t)443;
    m->reply_tuple.dport_be[0] = (uint8_t)(40001 >> 8); m->reply_tuple.dport_be[1] = (uint8_t)40001;
}

static void test_udp_continue(void) {
    d2k_nat_fn saved = d2k_nat_hook;
    d2k_nat_hook = quic_nat_not_ready;
    uint8_t pkt[1300], scratch[8192];
    d2k_result r;
    d2k_ct_info map; fill_reply(&map, 1);

    /* --- один выстрел: defer, затем применение на подтверждённом кортеже --- */
    size_t n = 0;
    d2k_session *s = udp_cont_defer(pkt, &n, &r);
    CHECK(s != NULL, "udp-continue fixture");
    if (!s) { d2k_nat_hook = saved; return; }
    CHECK(r.udp_defer_pending && !r.applied,
          "udp-continue: первый Initial не помечен кандидатом на владение");
    d2k_key key = r.udp_defer_key;
    uint8_t pid[16], tid[16];
    memcpy(pid, r.udp_defer_plan_id, 16); memcpy(tid, r.udp_defer_trial_id, 16);
    d2k_binding_context bind = r.udp_defer_binding;
    uint8_t ep[16]; memcpy(ep, r.udp_defer_epoch, 16);
    uint64_t inc = r.udp_defer_incarnation;

    d2k_key foreign = key; foreign.proto = 6;
    CHECK(!d2k_session_udp_continue(s, 1900, &foreign, pid, tid, &bind, ep, inc,
          &map, pkt, n, scratch, sizeof scratch, &r), "foreign supplied key refused");
    uint8_t wrong_epoch[16]; memcpy(wrong_epoch, ep, 16); wrong_epoch[0] ^= 1;
    CHECK(!d2k_session_udp_continue(s, 1900, &key, pid, tid, &bind, wrong_epoch, inc,
          &map, pkt, n, scratch, sizeof scratch, &r), "foreign flow epoch refused");
    CHECK(!d2k_session_udp_continue(s, 1900, &key, pid, tid, &bind, ep, inc,
          &map, pkt, n-1, scratch, sizeof scratch, &r), "incomplete IP packet refused");
    pkt[25] ^= 1;
    CHECK(!d2k_session_udp_continue(s, 1900, &key, pid, tid, &bind, ep, inc,
          &map, pkt, n, scratch, sizeof scratch, &r), "invalid UDP length refused");
    pkt[25] ^= 1;
    /* A reversed datagram has the same canonical key, but is not this send. */
    uint8_t reverse[1300]; memcpy(reverse, pkt, n);
    memcpy(reverse + 12, pkt + 16, 4); memcpy(reverse + 16, pkt + 12, 4);
    memcpy(reverse + 20, pkt + 22, 2); memcpy(reverse + 22, pkt + 20, 2);
    d2k_ct_info reverse_map = map;
    memcpy(reverse_map.reply_tuple.src, reverse + 16, 4);
    memcpy(reverse_map.reply_tuple.sport_be, reverse + 22, 2);
    CHECK(!d2k_session_udp_continue(s, 1999, &key, pid, tid, &bind, ep, inc,
          &reverse_map, reverse, n, scratch, sizeof scratch, &r),
          "udp-continue must reject reverse direction with same canonical key");
    pkt[6] |= 0x40; /* DF is not fragmentation. */
    uint64_t app0 = d2k_session_applied(s);
    int rc = d2k_session_udp_continue(s, 2000, &key, pid, tid, &bind, ep, inc, &map,
                                      pkt, n, scratch, sizeof scratch, &r);
    CHECK(rc == 1 && r.applied && r.n_out > 0,
          "udp-continue: один выстрел не применён на подтверждённом кортеже");
    CHECK(d2k_session_applied(s) == app0 + 1, "udp-continue: счётчик применений не +1");
    /* Повторное продолжение после применения — отказ (plan_done). */
    rc = d2k_session_udp_continue(s, 2001, &key, pid, tid, &bind, ep, inc, &map,
                                  pkt, n, scratch, sizeof scratch, &r);
    CHECK(rc == 0, "udp-continue: второе продолжение после применения не отвергнуто");
    d2k_session_free(s);

    /* --- устаревшая инкарнация потока: отказ, счётчик не растёт ------------ */
    s = udp_cont_defer(pkt, &n, &r); CHECK(s != NULL, "fixture stale");
    if (s) {
        key = r.udp_defer_key; memcpy(pid, r.udp_defer_plan_id, 16); memcpy(tid, r.udp_defer_trial_id, 16);
        bind = r.udp_defer_binding; memcpy(ep, r.udp_defer_epoch, 16); inc = r.udp_defer_incarnation;
        app0 = d2k_session_applied(s);
        rc = d2k_session_udp_continue(s, 2000, &key, pid, tid, &bind, ep, inc + 1, &map,
                                      pkt, n, scratch, sizeof scratch, &r);
        CHECK(rc == 0 && d2k_session_applied(s) == app0,
              "udp-continue: устаревшая инкарнация не отвергнута или счётчик сдвинулся");
        d2k_session_free(s);
    }

    /* --- переиспользованный/чужой кортеж ответа: отказ --------------------- */
    s = udp_cont_defer(pkt, &n, &r); CHECK(s != NULL, "fixture tuple");
    if (s) {
        key = r.udp_defer_key; memcpy(pid, r.udp_defer_plan_id, 16); memcpy(tid, r.udp_defer_trial_id, 16);
        bind = r.udp_defer_binding; memcpy(ep, r.udp_defer_epoch, 16); inc = r.udp_defer_incarnation;
        d2k_ct_info badmap; fill_reply(&badmap, 0);
        app0 = d2k_session_applied(s);
        rc = d2k_session_udp_continue(s, 2000, &key, pid, tid, &bind, ep, inc, &badmap,
                                      pkt, n, scratch, sizeof scratch, &r);
        CHECK(rc == 0 && d2k_session_applied(s) == app0,
              "udp-continue: чужой кортеж ответа не отвергнут");
        d2k_session_free(s);
    }

    /* --- удалённая привязка (поток тот же): отказ -------------------------- */
    s = udp_cont_defer(pkt, &n, &r); CHECK(s != NULL, "fixture del");
    if (s) {
        key = r.udp_defer_key; memcpy(pid, r.udp_defer_plan_id, 16); memcpy(tid, r.udp_defer_trial_id, 16);
        bind = r.udp_defer_binding; memcpy(ep, r.udp_defer_epoch, 16); inc = r.udp_defer_incarnation;
        d2k_plantab_del_name_shaped(d2k_session_plans(s), (const uint8_t *)"example.com", 11,
                                    17, D2K_PLAN_SHAPE_QUIC, 4);
        app0 = d2k_session_applied(s);
        rc = d2k_session_udp_continue(s, 2000, &key, pid, tid, &bind, ep, inc, &map,
                                      pkt, n, scratch, sizeof scratch, &r);
        CHECK(rc == 0 && d2k_session_applied(s) == app0,
              "udp-continue: удалённая привязка не отвергнута");
        d2k_session_free(s);
    }

    /* --- переустановка ТЕХ ЖЕ байт (новое поколение привязки): отказ ------- */
    s = udp_cont_defer(pkt, &n, &r); CHECK(s != NULL, "fixture reinstall");
    if (s) {
        char err[160];
        key = r.udp_defer_key; memcpy(pid, r.udp_defer_plan_id, 16); memcpy(tid, r.udp_defer_trial_id, 16);
        bind = r.udp_defer_binding; memcpy(ep, r.udp_defer_epoch, 16); inc = r.udp_defer_incarnation;
        d2k_plan *again = NULL;
        CHECK(d2k_plan_load(cont_frag_tlv, sizeof cont_frag_tlv, &again, err, sizeof err) == 0 &&
              d2k_plantab_set_name_shaped(d2k_session_plans(s), (const uint8_t *)"example.com", 11,
                                          1, again, D2K_PLAN_SHAPE_QUIC) == 0,
              "udp-continue: переустановка плана");
        app0 = d2k_session_applied(s);
        rc = d2k_session_udp_continue(s, 2000, &key, pid, tid, &bind, ep, inc, &map,
                                      pkt, n, scratch, sizeof scratch, &r);
        CHECK(rc == 0 && d2k_session_applied(s) == app0,
              "udp-continue: переустановленная привязка (новое поколение) не отвергнута");
        d2k_session_free(s);
    }
    d2k_nat_hook = saved;
}

/* Непрерывность на ПОТОКЕ STUN/голоса: defer плана фрагментации, продолжение
 * на подтверждённом кортеже, затем STUN-ответ по тому же transaction ID обязан
 * дать transaction-bound proof — связка запрос→исполнение сохранена (не теряется
 * из-за stun_request=NULL, как было бы без её восстановления в продолжении). */
static void test_udp_continue_stun(void) {
    d2k_nat_fn saved = d2k_nat_hook;
    d2k_nat_hook = quic_nat_not_ready;
    char err[160];
    d2k_session *s = d2k_session_new(64, 32);
    CHECK(s != NULL, "stun-continue session");
    if (!s) { d2k_nat_hook = saved; return; }
    d2k_plan *p = NULL;
    CHECK(d2k_plan_load(cont_frag_tlv, sizeof cont_frag_tlv, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_name_shaped(d2k_session_plans(s), (const uint8_t *)D2K_VOICE_CLASS,
                                      strlen(D2K_VOICE_CLASS), 1, p, D2K_PLAN_SHAPE_VOICE) == 0,
          "stun-continue: ipfrag voice plan fixture");
    uint8_t stun[32], txid[12] = {7,7,1,2,3,4,5,6,7,8,9,10};
    uint8_t pkt[256], buf[4096], scratch[4096];
    d2k_result r;
    size_t sn = build_stun_binding(stun, 0x0001, txid);
    size_t n = build_udp_pkt(pkt, 64051, 50004, stun, sn);   /* Discord media port */
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.udp_defer_pending && !r.applied,
          "stun-continue: STUN-запрос с планом фрагментации не отложен");
    d2k_key key = r.udp_defer_key;
    uint8_t pid[16], tid[16];
    memcpy(pid, r.udp_defer_plan_id, 16); memcpy(tid, r.udp_defer_trial_id, 16);
    d2k_binding_context bind = r.udp_defer_binding;
    uint8_t ep[16]; memcpy(ep, r.udp_defer_epoch, 16);
    uint64_t inc = r.udp_defer_incarnation;

    d2k_ct_info map; memset(&map, 0, sizeof map);
    map.reply_tuple_known = 1;
    map.reply_tuple.family = 4; map.reply_tuple.proto = 17;
    uint8_t srv[4] = {1,2,3,4}; memcpy(map.reply_tuple.src, srv, 4);
    uint8_t ext[4] = {203,0,113,9}; memcpy(map.reply_tuple.dst, ext, 4);
    map.reply_tuple.sport_be[0] = (uint8_t)(50004 >> 8); map.reply_tuple.sport_be[1] = (uint8_t)50004;
    map.reply_tuple.dport_be[0] = (uint8_t)(40001 >> 8); map.reply_tuple.dport_be[1] = (uint8_t)40001;

    int rc = d2k_session_udp_continue(s, 2000, &key, pid, tid, &bind, ep, inc, &map,
                                      pkt, n, scratch, sizeof scratch, &r);
    CHECK(rc == 1 && r.applied, "stun-continue: не применено на подтверждённом кортеже");
    uint64_t exec = r.execution_id;   /* исполнение, с которым обязан связаться ответ */
    CHECK(exec != 0, "stun-continue: продолжение не дало execution_id");

    /* STUN-ответ тем же transaction ID. Proof обязан быть ПРИВЯЗАН к исполнению
       продолжения (execution_id), а не просто существовать: без восстановления
       связки запрос→исполнение (stun_request + new=1) запись обмена несла бы
       execution_id==0, и этот CHECK падает — что и подтверждает ред-проверка. */
    uint8_t resp[32]; size_t rn = build_stun_binding(resp, 0x0101, txid);
    n = build_udp_rev_pkt(pkt, 64051, resp, rn);
    wr16(pkt + 20, 50004);
    d2k_session_set_hook(s, D2K_HOOK_FORWARD);
    d2k_session_packet(s, pkt, n, 1200, buf, sizeof buf, &r);
    const d2k_journal *j = d2k_session_journal(s);
    int stun_bound = 0;
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == D2K_JRN_EXCHANGE && e->code == D2K_UDP_PROOF_STUN &&
            e->execution_id == exec) { stun_bound = 1; }
    }
    CHECK(stun_bound,
          "stun-continue: STUN proof не привязан к исполнению продолжения (связка потеряна)");
    d2k_session_free(s);
    d2k_nat_hook = saved;
}

int main(void) {
    D2K_TEST_NAT_NO_TABLE();
    test_udp_continue();
    test_udp_continue_stun();
    test_measured_udp_refinement(4,0);
    test_measured_udp_refinement(4,1);
    test_measured_udp_refinement(6,0);
    test_measured_udp_refinement(6,1);
    test_quic_deny();
    test_quic_post_handshake_stall();
    test_quic_long_stream();
    test_udp_raw_silence();
    test_flow_fact_udp();
    test_adopted_flows();
    test_udp_raw_experiment();
    for (int f=4; f<=6; f+=2) for (int p=0; p<2; p++) test_measured_udp_packet_scope(f,p);
    test_quic_oneway_block();
    test_quic_no_proof_ask();
    {
        d2k_session *s = d2k_session_new(32, 32);
        uint8_t pkt[1400], out[8192]; char err[128]; d2k_plan *p = NULL;
        CHECK(!d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err), "QUIC area plan parse");
        CHECK(!d2k_plantab_set_suffix_family(d2k_session_plans(s),
            (const uint8_t *)"example.com", 11, 1, p, D2K_PLAN_SHAPE_QUIC, 4), "QUIC suffix install");
        size_t n = build_udp_pkt(pkt, 50011, 443, v1_initial, sizeof v1_initial);
        d2k_result r;
        d2k_session_packet(s, pkt, n, 2, out, sizeof out, &r);
        CHECK(r.applied && r.n_out, "QUIC first Initial inherits area");
        CHECK(!d2k_plantab_count(d2k_session_plans(s)), "QUIC area does not create exact binding");
        d2k_session_free(s);
    }
    {
        /* An IPv4 server reply cannot prove the IPv6 reply hook exists. */
        d2k_session *s = d2k_session_new(32, 32);
        uint8_t old[1400], pkt[1420] = {0}, out[8192], reply[] = {1, 2, 3};
        d2k_result r;
        size_t n = build_udp_rev_pkt(old, 50010, reply, sizeof reply);
        d2k_session_packet(s, old, n, 1000000000ull, out, sizeof out, &r);
        n = build_udp_pkt(old, 50011, 443, v1_initial, sizeof v1_initial);
        pkt[0] = 0x60; pkt[4] = (uint8_t)((n - 20) >> 8); pkt[5] = (uint8_t)(n - 20);
        pkt[6] = 17; pkt[7] = 64;
        pkt[8] = pkt[24] = 0x20; pkt[9] = pkt[25] = 1;
        pkt[23] = 1; pkt[39] = 2;
        memcpy(pkt + 40, old + 20, n - 20);
        d2k_session_packet(s, pkt, n + 20, 2000000000ull, out, sizeof out, &r);
        d2k_session_packet(s, pkt, n + 20, 3000000000ull, out, sizeof out, &r);
        CHECK(d2k_session_sweep(s, 30000000000ull) == 0,
              "IPv4 reply visibility must not manufacture IPv6 silence evidence");
        d2k_session_expire(s, 300000000000ull, 50000000000ull);
        CHECK(d2k_session_suspects(s) == 0,
              "expiry must not mix reply visibility across families");
        d2k_session_free(s);
    }
    {
        d2k_session *s6 = d2k_session_new(32, 32);
        uint8_t old[1400], pkt[1420] = {0}, output[8192];
        size_t n4 = build_udp_pkt(old, 50011, 443, v1_initial, sizeof v1_initial);
        pkt[0] = 0x60; pkt[4] = (uint8_t)((n4 - 20) >> 8); pkt[5] = (uint8_t)(n4 - 20);
        pkt[6] = 17; pkt[7] = 64;
        pkt[8] = pkt[24] = 0x20; pkt[9] = pkt[25] = 1;
        pkt[23] = 1; pkt[39] = 2;
        memcpy(pkt + 40, old + 20, n4 - 20);
        d2k_plan *p6 = NULL; char err6[128];
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p6, err6, sizeof err6) == 0,
              "IPv6 QUIC fixture plan");
        CHECK(d2k_plantab_set_name_family(d2k_session_plans(s6),
                  (const uint8_t *)"example.com", 11, 1, p6, D2K_PLAN_SHAPE_QUIC, 0, 6) == 0,
              "IPv6 QUIC name binding");
        d2k_result r6;
        d2k_session_packet(s6, pkt, n4 + 20, 2, output, sizeof output, &r6);
        CHECK(r6.applied && r6.n_out > 0 && (output[0] >> 4) == 6,
              "IPv6 QUIC plan did not emit native IPv6");
        CHECK(r6.key.family == 6 && count_journal_kind(s6, D2K_JRN_HELLO_SNI) == 1,
              "IPv6 QUIC hello/key lost");
        CHECK(d2k_session_want_shape_family(s6, (const uint8_t *)"example.com", 11, 17, 6) == 1,
              "IPv6 QUIC original snapshot missing");
        CHECK(d2k_session_want_shape(s6, (const uint8_t *)"example.com", 11, 17) == 0,
              "IPv6 QUIC snapshot leaked to IPv4");
        d2k_session_free(s6);
        s6 = d2k_session_new(32, 32); p6 = NULL;
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p6, err6, sizeof err6) == 0,
              "IPv6 private trial fixture");
        CHECK(d2k_plantab_set_name_family(d2k_session_plans(s6),
                  (const uint8_t *)"example.com", 11, 1, p6, D2K_PLAN_SHAPE_QUIC,
                  htons(50011), 6) == 0, "IPv6 private trial install");
        d2k_session_packet(s6, pkt, n4 + 20, 2, output, sizeof output, &r6);
        CHECK(!r6.applied && r6.n_out == 0 && r6.verdict == D2K_VERDICT_ACCEPT,
              "ordinary IPv6 client sharing a probe port must not receive a trial");
        pkt[23] = 3;
        d2k_session_packet_probe(s6, pkt, n4 + 20, 3, output, sizeof output, &r6);
        CHECK(r6.applied && r6.n_out > 0,
              "marked IPv6 controller probe must still execute its trial");
        pkt[39] = 4;
        d2k_session_packet(s6, pkt, n4 + 20, 4, output, sizeof output, &r6);
        CHECK(!r6.applied && r6.n_out == 0 && r6.verdict == D2K_VERDICT_ACCEPT,
              "another destination on the same probe port must stay direct");
        pkt[23] = 1; pkt[39] = 2;
        d2k_session_free(s6);
        d2k_nat_family_fn saved6 = d2k_nat_family_hook;
        d2k_nat_family_hook = frag_nat6;
        for (int shape = 1; shape <= 4; shape++) {
            uint8_t tlv[] = {'D','2','K','P',0,1,0,7,0,0,0,2,
                            0,2,0,2,17,2,1,12,0,1,0};
            tlv[22] = (uint8_t)shape;
            s6 = d2k_session_new(32, 32); p6 = NULL;
            CHECK(d2k_plan_load(tlv, sizeof tlv, &p6, err6, sizeof err6) == 0,
                  "native fragment plan load");
            d2k_session_set_plan(s6, p6);
            d2k_session_packet(s6, pkt, n4 + 20, 2, output, sizeof output, &r6);
            CHECK(r6.applied && r6.n_out == (shape <= 2 ? 2u : 3u),
                  "native fragment plan must emit every fragment");
            CHECK(output[0] == 0x60 && output[6] == 44 && output[40] == 17,
                  "native fragment plan emitted wrong headers");
            CHECK(output[23] == 7, "native fragments need confirmed full NAT address");
            d2k_session_free(s6);
        }
        d2k_nat_family_hook = saved6;
    }
    test_fragments();
    test_direction_by_hook();
    test_quic_non443_client_hold();
    test_quic_cross_datagram_assembly();
    test_quic_flow_storage();
    test_quic_snapshot_is_every_initial();
    test_quic_snapshot_waits_for_whole_hello();
    test_quic_snapshot_skips_other_flow();
    test_quic_split_hold_handshake();
    test_quic_held_initial_replay_is_first_packet();
    test_quic_first_packet_skips_conntrack_scan();
    test_routed_client_gets_no_plan_udp();
    test_quic_retry_resets_assembly();
    test_quic_original_after_fakes();
    test_quic_crypto_split_plan();
    test_quic_crypto_split_name_in_second();
    test_discord_voice();
    test_voice_trial_live_flow();
    test_nameless_initial();
    test_nameless_silence();
    test_nameless_exchange();

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

        /* «плана для этой цели нет» (ревью, пункт 3) обязано дойти до
           журнала — раньше эта ветка session.c просто возвращалась, не
           звала refuse(), и единственным следом оставался счётчик сводки.
           Здесь это ВСЕГДА честный случай (в отличие от TCP-ветки): досюда
           доходит только после того, как d2k_quic_sni уже успешно достал
           имя, — не-Initial и нерасшифровавшееся отсеиваются раньше и
           событие не порождают вовсе (см. handle_udp, session.c). */
        size_t after_first = count_plan_refused(s);
        CHECK(after_first == 1,
              "отказ «плана для этой цели нет» не ушёл в журнал на QUIC-ветке");

        /* Повтор того же Initial на том же потоке (тот же 5-tuple) — не
           обязан прибавить событие: saw_hello уже взведён первой датаграммой,
           и следующая отсеивается раньше разбора, на «поток уже показывал
           приветствие» (см. handle_udp). Не чаще одного раза на поток — по
           той же причине, что и на TCP-ветке. Сравниваем с after_first, а не
           с литералом 1, чтобы эта проверка отвечала за СВОЙ факт (повтор
           ничего не добавил), а не дублировала провал предыдущей. */
        n = build_udp_pkt(pkt, 50000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
        CHECK(count_plan_refused(s) == after_first,
              "повтор Initial на том же потоке размножил отказ плана");

        d2k_session_free(s);
    }

    /* --- план ЧУЖОГО транспорта к датаграмме не применяется -------------- */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_tcp_declared, sizeof plan_tcp_declared, &p,
                            err, sizeof err) == 0,
              "план с объявленным транспортом не загрузился");
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, 1, p);

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 51500, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(r.skipped != NULL &&
              strcmp(r.skipped, "план объявлен для другого транспорта") == 0,
              "план, объявленный для TCP, достался датаграмме QUIC");
        CHECK(r.n_out == 0, "чужой план успел что-то собрать");
        CHECK(d2k_session_applied(s) == 0, "чужой план засчитан как применённый");
        d2k_session_free(s);
    }

    /* --- план по имени применяется к UDP-потоку (Step 1, пункт 2) --------- */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0,
              "план не загрузился");
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, 1, p);

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 51000, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(r.skipped == NULL, "план по имени не применился к UDP-потоку");
        /* Две копии фальшивки и оригинал СВОЕЙ посылкой следом (задача 42):
           отданный ядру после сырой фальшивки, он снимается conntrack. */
        CHECK(r.n_out == 3, "ожидались две копии фальшивки и оригинал");
        CHECK(r.verdict == D2K_VERDICT_DROP,
              "удержанная копия снимается: оригинал уходит посылкой плана");
        if (r.n_out == 3) {
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
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, 1, p);

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
        CHECK(r.n_out == 3, "план не дал ожидаемых двух фальшивок и оригинала на настоящем клиентском Initial");

        d2k_session_free(s);
    }

    /* --- неизвестный hook и нестандартный порт: направление неизвестно,
       план не применяется. Это сохраняет безопасный fallback для старых
       вызывающих, которые не передают NFQUEUE hook; боевой all-port firewall
       передаёт hook и проходит отдельную проверку выше. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0,
              "план не загрузился");
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, 1, p);

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
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, 1, p);

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
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, 1, p);

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
       255), d2k_result.out[] ограничен D2K_RESULT_MAX. Раньше лишние
       посылки тихо обрезались, но plan_done/applied++/PLAN_APPLIED ставились
       безусловно, как будто ушли все. Честный исход — отказ целиком: ни
       одной посылки, план не считается применённым. */
    {
        d2k_session *s = d2k_session_new(64, 32);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_too_many_repeats, sizeof plan_too_many_repeats, &p, err, sizeof err) == 0,
              "план с лишним повтором не загрузился");
        d2k_plantab_set_name(d2k_session_plans(s), (const uint8_t *)"example.com", 11, 1, p);

        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        size_t n = build_udp_pkt(pkt, 56600, 443, v1_initial, sizeof v1_initial);
        d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

        CHECK(r.n_out == 0, "план с лишним повтором отправил посылку вместо отказа");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "ничего не отправив, оригинал обязаны пропустить");
        CHECK(r.skipped != NULL, "отказ по переполнению out[] не объяснён вызывающему");
        CHECK(d2k_session_applied(s) == 0, "план с лишним повтором засчитан применённым");

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

    /* --- «ШЛЁМ, А МОЛЧАТ»: молчание сервера по QUIC ----------------------
     *
     * Лаборатория lab-quic.sh 13.09.2026: цензор снимал датаграммы по имени,
     * датапат узнавал приветствия (4 из 4 с именем) — и не подозревал НИЧЕГО,
     * поиск не начинался вовсе. Причина была в учёте: датаграмма сервера
     * уходила отказом «не клиентский Initial» до всякого счёта, обратная
     * сторона у QUIC-потока навсегда оставалась нулём, и наблюдение «ответа
     * не было» по UDP не могло родиться ни при каких обстоятельствах.
     *
     * Критерий здесь СВОЙ, не унаследованный от TCP, и каждая его часть
     * закрепляется отдельной проверкой — иначе завтра любая из них уйдёт
     * молча, а подозрение останется. */
    {
        const uint64_t s_ns = 1000000000ull;
        uint8_t pkt[1300], buf[4096];
        d2k_result r;
        const uint8_t any[4] = { 0xAA, 0xBB, 0xCC, 0xDD };

        /* 1. Все части на месте: обратная сторона видна, приветствие было,
           клиент повторил, срок вышел. */
        {
            d2k_session *s1 = d2k_session_new(64, 64);
            /* Ответ сервера на ЧУЖОМ потоке — единственная улика того, что
               правило на обратное направление вообще поставлено. */
            size_t n = build_udp_rev_pkt(pkt, 50100, any, sizeof any);
            d2k_session_packet(s1, pkt, n, 1 * s_ns, buf, sizeof buf, &r);

            n = build_udp_pkt(pkt, 50101, 443, v1_initial, sizeof v1_initial);
            d2k_session_packet(s1, pkt, n, 2 * s_ns, buf, sizeof buf, &r);
            CHECK(d2k_session_hellos(s1) == 1, "QUIC-приветствие не узнано");
            CHECK(d2k_session_suspects(s1) == 0, "подозрение сразу после приветствия");

            /* Повтор Initial по таймеру PTO — тот же поток, те же байты. */
            d2k_session_packet(s1, pkt, n, 3 * s_ns, buf, sizeof buf, &r);

            CHECK(d2k_session_sweep(s1, 3 * s_ns + 900000000ull) == 0,
                  "неполные две секунды молчания по QUIC объявлены блокировкой");
            CHECK(d2k_session_sweep(s1, 4 * s_ns + 100000000ull) == 1,
                  "молчание по QUIC не замечено после срока");
            CHECK(d2k_session_suspects(s1) == 1, "подозрение о молчании по QUIC не отмечено");
            CHECK(d2k_session_sweep(s1, 20 * s_ns) == 0, "подозрение по QUIC продублировано");
            d2k_session_free(s1);
        }

        /* 2. Клиент не повторял — это не «сервер молчит», а «больше не
           спрашивали». У QUIC ждущий клиент ВСЕГДА повторяет Initial (RFC
           9002 §6.2), и закрытая вкладка отличается от блокировки ровно
           этим. */
        {
            d2k_session *s2 = d2k_session_new(64, 64);
            size_t n = build_udp_rev_pkt(pkt, 50200, any, sizeof any);
            d2k_session_packet(s2, pkt, n, 1 * s_ns, buf, sizeof buf, &r);
            n = build_udp_pkt(pkt, 50201, 443, v1_initial, sizeof v1_initial);
            d2k_session_packet(s2, pkt, n, 2 * s_ns, buf, sizeof buf, &r);
            CHECK(d2k_session_sweep(s2, 30 * s_ns) == 0,
                  "приветствие без единого повтора объявлено молчанием сервера");
            d2k_session_free(s2);
        }

        /* 3. Обратная сторона не видна вовсе: правило на неё не поставлено,
           оттуда не приходит ничего и никогда. Объявить это молчанием значит
           подменить «не смотрели» на «нет ответа» (§2.4). */
        {
            d2k_session *s3 = d2k_session_new(64, 64);
            size_t n = build_udp_pkt(pkt, 50301, 443, v1_initial, sizeof v1_initial);
            d2k_session_packet(s3, pkt, n, 2 * s_ns, buf, sizeof buf, &r);
            d2k_session_packet(s3, pkt, n, 3 * s_ns, buf, sizeof buf, &r);
            CHECK(d2k_session_sweep(s3, 30 * s_ns) == 0,
                  "невидимая обратная сторона QUIC объявлена молчащей");
            /* И забвение потока не должно обойти ту же оговорку с чёрного
               хода. */
            d2k_session_expire(s3, 300 * s_ns, 50 * s_ns);
            CHECK(d2k_session_suspects(s3) == 0,
                  "забвение UDP-потока объявило молчанием невидимую обратную сторону");
            d2k_session_free(s3);
        }

        /* 3b. Служба знает из собственной конфигурации, что обратное
           направление QUIC поставлено в NFQUEUE. Для заблокированного
           сервера ответного пакета не будет никогда, поэтому требовать
           «доказательства видимости» именно ответом — тупик. Без такого
           объявления остаётся проверка 3 выше: обычная сессия не угадывает,
           был ли обратный крючок установлен. */
        {
            d2k_session *s3b = d2k_session_new(64, 64);
            d2k_session_set_udp_reverse_hook(s3b, 1);
            size_t n = build_udp_pkt(pkt, 50311, 443, v1_initial,
                                     sizeof v1_initial);
            d2k_session_packet(s3b, pkt, n, 2 * s_ns, buf, sizeof buf, &r);
            d2k_session_packet(s3b, pkt, n, 3 * s_ns, buf, sizeof buf, &r);
            CHECK(d2k_session_sweep(s3b, 4 * s_ns + 100000000ull) == 1,
                  "установленный обратный QUIC-крючок не позволил обнаружить блокировку без ответа");
            d2k_session_free(s3b);
        }

        /* 4. По ЭТОМУ потоку есть обратный трафик — это не полное молчание.
           Наблюдаем любую датаграмму (UDP допускает и пустую), но это
           НЕ доказательство успешного QUIC или работающего обхода. */
        {
            d2k_session *s4 = d2k_session_new(64, 64);
            size_t n = build_udp_pkt(pkt, 50401, 443, v1_initial, sizeof v1_initial);
            d2k_session_packet(s4, pkt, n, 2 * s_ns, buf, sizeof buf, &r);
            d2k_session_packet(s4, pkt, n, 3 * s_ns, buf, sizeof buf, &r);
            n = build_udp_rev_pkt(pkt, 50401, any, sizeof any);
            d2k_session_packet(s4, pkt, n, 3 * s_ns + 100000000ull, buf, sizeof buf, &r);
            CHECK(d2k_session_sweep(s4, 30 * s_ns) == 0,
                  "ответивший по QUIC сервер объявлен молчащим");
            d2k_session_free(s4);
        }

        /* 4b. Один ответ на первый Initial не отменяет подозрение, если
           следующий PTO клиента снова остаётся без ответа: это модель
           «первый пакет пропустили, повторы режутся», которую использует
           transit QUIC fixture. Ответ после повтора, напротив, снимает
           подозрение через last_{rev,fwd}_after_hello_ns. */
        {
            d2k_session *s4b = d2k_session_new(64, 64);
            size_t n = build_udp_pkt(pkt, 50411, 443, v1_initial, sizeof v1_initial);
            d2k_session_packet(s4b, pkt, n, 2 * s_ns, buf, sizeof buf, &r);
            n = build_udp_rev_pkt(pkt, 50411, any, sizeof any);
            d2k_session_packet(s4b, pkt, n, 2 * s_ns + 100000000ull,
                               buf, sizeof buf, &r);
            n = build_udp_pkt(pkt, 50411, 443, v1_initial, sizeof v1_initial);
            d2k_session_packet(s4b, pkt, n, 3 * s_ns, buf, sizeof buf, &r);
            CHECK(d2k_session_sweep(s4b, 4 * s_ns + 100000000ull) == 1,
                  "ответ на первый Initial навсегда скрыл молчание после PTO");
            CHECK(d2k_session_suspects(s4b) == 1,
                  "потерянный ответ после повторного QUIC Initial не дал SUSPECT");
            d2k_session_free(s4b);
        }

        /* 5. Обе стороны на порту 443 — направление неизвестно, и ни
           видимости обратной стороны, ни приветствия из такой датаграммы не
           следует. */
        {
            d2k_session *s5 = d2k_session_new(64, 64);
            size_t n = build_udp_pkt(pkt, 443, 443, v1_initial, sizeof v1_initial);
            d2k_session_packet(s5, pkt, n, 1 * s_ns, buf, sizeof buf, &r);
            CHECK(r.skipped != NULL && strstr(r.skipped, "неизвестно") != NULL,
                  "датаграмма 443->443 не объяснена как неизвестное направление");
            n = build_udp_pkt(pkt, 50501, 443, v1_initial, sizeof v1_initial);
            d2k_session_packet(s5, pkt, n, 2 * s_ns, buf, sizeof buf, &r);
            d2k_session_packet(s5, pkt, n, 3 * s_ns, buf, sizeof buf, &r);
            CHECK(d2k_session_sweep(s5, 30 * s_ns) == 0,
                  "443->443 сошла за видимость обратной стороны");
            d2k_session_free(s5);
        }
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
