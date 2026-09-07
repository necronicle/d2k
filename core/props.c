/* props.c — задача 6: подбор исполнимого плеча QUIC из измеренного.
 *
 * ЭТОТ ФАЙЛ НЕ РЕШАЕТ, РЕЖЕТ ЛИ КОРОБКА. Это уже решено к моменту вызова
 * d2k_quic_pick_arm — вызывающий обязан дойти сюда только после того, как
 * d2k_quic_classify (quicprobe.c) вернула D2K_V_OPAQUE: коробка решает по
 * содержимому. Здесь — не "решает ли", а "чем конкретно её обойти": каким
 * блобом-приманкой, с каким TTL, нужна ли фрагментация. См. полный контракт
 * и обоснование лестницы цены в doc-комментарии d2k_quic_pick_arm
 * (d2k_quicprobe.h) — здесь только то, что относится к РЕАЛИЗАЦИИ.
 *
 * ПОЧЕМУ КАЖДОЕ ПОДТВЕРЖДЕНИЕ — НА СВЕЖЕМ АДРЕСЕ, А НЕ ЖИВАЯ ПРОВЕРКА
 * ОСТАТОЧНОЙ БЛОКИРОВКИ МЕЖДУ КАЖДЫМ ШАГОМ РАЗВЕДКИ. У дерева вопросов
 * (quicprobe.c) есть отдельный вопрос "проверка остаточной блокировки" ровно
 * потому, что там всего ОДНО событие, способное завести блокировку (прямой
 * зонд), и цена лишнего опыта на его проверку разумна. Здесь разведка — это
 * ДО 257 отдельных попыток (2 блоба + до 255 значений TTL), и каждая несёт
 * тот же trigger, который уже ИЗВЕСТНО решает коробку: живая проверка после
 * КАЖДОЙ удваивала бы стоимость всей лестницы. Асимметрия цены ошибок здесь
 * безопасная: поджог тройки во время разведки может только ЗАНИЗИТЬ шанс
 * найти рабочее плечо (ложноотрицательный, дешёвый исход по всей доктрине
 * проекта — см. D2K_QUIC_CLEAR_CONFIRM_REPEATS в quicprobe.c), но не может
 * подделать ложный ПРОХОД: единогласное подтверждение всё равно проводится
 * ОТДЕЛЬНО, на адресе, которого разведка не касалась.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE /* IP_TTL/IP_HDRINCL на macOS — см. тот же приём в quicprobe.c */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"
#include "d2k_quicprobe.h"

/* =========================================================================
 * Каталог блобов — см. контракт в d2k_quicprobe.h.
 * ========================================================================= */

static const uint8_t g_blob_garbage[16]; /* 16 нулей — та же приманка, что qp_arm_step в quicprobe.c */

/* D2K_QUIC_ARM_BLOB_SHAPED строится ОДИН РАЗ (лениво, при первом обращении) —
 * не на стеке КАЖДОГО вызова d2k_quic_pick_arm: 1200 байт незачем копировать
 * заново на каждую попытку разведки (их до 257 за один подбор), а сама
 * заготовка от вызова к вызову не меняется. Не на пакетном горячем пути
 * (см. общие ограничения проекта про "на пакетном пути память не
 * выделяется") — это измерительный код, не путь пакета датапата. */
static uint8_t g_blob_shaped[1200];
static int g_blob_shaped_ready;

static void build_shaped_blob(void) {
    /* Валидный ПО ФОРМЕ длинный заголовок QUIC v1 Initial (RFC 9000 §17.2),
       дополненный до 1200 байт (RFC 9000 §14.1 — см. её же обоснование у
       qp_build_vn_trigger в quicprobe.c, тот же порог и та же причина).
       Токен и SCID пустые, DCID — 8 произвольных байт (эта приманка не
       пытается расшифроваться, см. doc-комментарий в заголовке). */
    size_t off = 0;
    g_blob_shaped[off++] = 0xC0; /* long header, fixed bit, type=Initial(v1) */
    g_blob_shaped[off++] = 0x00;
    g_blob_shaped[off++] = 0x00;
    g_blob_shaped[off++] = 0x00;
    g_blob_shaped[off++] = 0x01; /* version = 1 */
    g_blob_shaped[off++] = 0x08; /* dcid_len */
    for (int i = 0; i < 8; i++) {
        g_blob_shaped[off++] = (uint8_t)(0xE0 + i);
    }
    g_blob_shaped[off++] = 0x00; /* scid_len = 0 */
    g_blob_shaped[off++] = 0x00; /* token varint (1 байт, значение 0) */
    /* length varint (2 байта, RFC 9000 §16): верхние 2 бита формы = 01,
       значение — сколько байт (packet number + тело) идёт после этого поля,
       чтобы итог был ровно 1200: 1200 - off(16) - 2(это поле) = 1182. */
    size_t remaining = 1200 - off - 2;
    g_blob_shaped[off++] = (uint8_t)(0x40 | ((remaining >> 8) & 0x3F));
    g_blob_shaped[off++] = (uint8_t)(remaining & 0xFF);
    for (size_t i = 0; i < remaining; i++) {
        g_blob_shaped[off + i] = (uint8_t)(0xA0 + (i & 0x3F));
    }
    off += remaining;
    /* off обязан быть ровно 1200 — если арифметика выше когда-нибудь разъедется
       (например, remaining пересчитают неверно), тест test_quic_arms.c поймает
       это через d2k_quic_is_initial и/или прямую проверку длины. */
    g_blob_shaped_ready = 1;
}

const uint8_t *d2k_quic_arm_blob(size_t idx, size_t *len_out) {
    if (idx == D2K_QUIC_ARM_BLOB_GARBAGE) {
        if (len_out) {
            *len_out = sizeof g_blob_garbage;
        }
        return g_blob_garbage;
    }
    if (idx == D2K_QUIC_ARM_BLOB_SHAPED) {
        if (!g_blob_shaped_ready) {
            build_shaped_blob();
        }
        if (len_out) {
            *len_out = sizeof g_blob_shaped;
        }
        return g_blob_shaped;
    }
    if (len_out) {
        *len_out = 0;
    }
    return NULL;
}

/* =========================================================================
 * Сборка IP-фрагментов — чистые вычисления, без сокетов (см. контракт в
 * d2k_quicprobe.h). Тестируется напрямую в test_quic_arms.c.
 * ========================================================================= */

/* RFC 1071. Сумма 16-битных слов big-endian, с переносом; len нечётной длины
   — последний байт дополняется нулём справа (стандартный приём). */
static uint16_t ip_checksum16(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < len; i += 2) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
    }
    if (len & 1u) {
        sum += (uint32_t)data[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint16_t udp_checksum(uint32_t src_be, uint32_t dst_be, uint16_t sport, uint16_t dport,
                              uint16_t udp_len, const uint8_t *payload, size_t payload_len) {
    /* Псевдозаголовок UDP (RFC 768): src(4) dst(4) zero(1) proto(1) len(2). */
    uint8_t buf[12 + 8];
    memcpy(buf, &src_be, 4);
    memcpy(buf + 4, &dst_be, 4);
    buf[8] = 0;
    buf[9] = 17; /* IPPROTO_UDP */
    buf[10] = (uint8_t)(udp_len >> 8);
    buf[11] = (uint8_t)(udp_len & 0xFF);
    buf[12] = (uint8_t)(sport >> 8);
    buf[13] = (uint8_t)(sport & 0xFF);
    buf[14] = (uint8_t)(dport >> 8);
    buf[15] = (uint8_t)(dport & 0xFF);
    buf[16] = (uint8_t)(udp_len >> 8);
    buf[17] = (uint8_t)(udp_len & 0xFF);
    buf[18] = 0; /* контрольная сумма при подсчёте — ноль */
    buf[19] = 0;

    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < sizeof buf; i += 2) {
        sum += ((uint32_t)buf[i] << 8) | buf[i + 1];
    }
    for (i = 0; i + 1 < payload_len; i += 2) {
        sum += ((uint32_t)payload[i] << 8) | payload[i + 1];
    }
    if (payload_len & 1u) {
        sum += (uint32_t)payload[payload_len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    uint16_t csum = (uint16_t)~sum;
    /* RFC 768: "If the computed checksum is zero, it is transmitted as all
       ones" — ноль в поле суммы у UDP означает "сумма не считалась". */
    return (csum == 0) ? 0xFFFFu : csum;
}

size_t d2k_quic_build_frag2(const uint8_t *udp_payload, size_t udp_payload_len, uint32_t src_ip_be,
                             uint32_t dst_ip_be, uint16_t src_port, uint16_t dst_port, uint16_t ip_id,
                             uint8_t ttl, uint8_t frag1[D2K_QUIC_FRAG_MAX], size_t *frag1_len,
                             uint8_t frag2[D2K_QUIC_FRAG_MAX], size_t *frag2_len) {
    *frag1_len = 0;
    *frag2_len = 0;
    if (!udp_payload || udp_payload_len < 16) {
        return 0; /* короче попросту нечего делить на два непустых фрагмента */
    }

    size_t udp_total = 8u + udp_payload_len; /* UDP-заголовок + данные — это и есть то, что фрагментируется */
    /* Смещение фрагмента — в 8-байтных единицах (RFC 791 §3.2): середина,
       округлённая ВНИЗ до кратного 8, и не меньше 8, чтобы весь UDP-заголовок
       (ровно 8 байт) целиком уместился в первый фрагмент — если бы он тоже
       делился между фрагментами, второй фрагмент было бы нечем связать с
       UDP-портами при разборе (реальные стеки не пересобирают L4-заголовок
       из кусков поперёк IP-фрагментов). */
    size_t split = (udp_total / 2) & ~(size_t)7;
    if (split < 8) {
        split = 8;
    }
    if (split >= udp_total) {
        return 0; /* вырожденный случай — не должен случаться при payload>=16, но проверка не лишняя */
    }
    size_t frag1_ip_payload = split;
    size_t frag2_ip_payload = udp_total - split;
    if (20 + frag1_ip_payload > D2K_QUIC_FRAG_MAX || 20 + frag2_ip_payload > D2K_QUIC_FRAG_MAX) {
        return 0; /* буфер вызывающего мал для такого payload */
    }

    uint16_t udp_len_field = (uint16_t)udp_total;
    uint16_t csum = udp_checksum(src_ip_be, dst_ip_be, src_port, dst_port, udp_len_field, udp_payload,
                                  udp_payload_len);
    uint8_t udp_hdr[8];
    udp_hdr[0] = (uint8_t)(src_port >> 8);
    udp_hdr[1] = (uint8_t)(src_port & 0xFF);
    udp_hdr[2] = (uint8_t)(dst_port >> 8);
    udp_hdr[3] = (uint8_t)(dst_port & 0xFF);
    udp_hdr[4] = (uint8_t)(udp_len_field >> 8);
    udp_hdr[5] = (uint8_t)(udp_len_field & 0xFF);
    udp_hdr[6] = (uint8_t)(csum >> 8);
    udp_hdr[7] = (uint8_t)(csum & 0xFF);

    /* ---- фрагмент 1: IP(20) + UDP-заголовок(8) + начало данных ---- */
    memset(frag1, 0, 20);
    frag1[0] = 0x45; /* version=4, IHL=5 (20 байт, без опций) */
    uint16_t totlen1 = (uint16_t)(20 + frag1_ip_payload);
    frag1[2] = (uint8_t)(totlen1 >> 8);
    frag1[3] = (uint8_t)(totlen1 & 0xFF);
    frag1[4] = (uint8_t)(ip_id >> 8);
    frag1[5] = (uint8_t)(ip_id & 0xFF);
    frag1[6] = 0x20; /* MF=1, смещение=0 (флаги — верхние 3 бита этого поля) */
    frag1[7] = 0x00;
    frag1[8] = ttl;
    frag1[9] = 17; /* IPPROTO_UDP */
    memcpy(frag1 + 12, &src_ip_be, 4);
    memcpy(frag1 + 16, &dst_ip_be, 4);
    uint16_t hcsum1 = ip_checksum16(frag1, 20);
    frag1[10] = (uint8_t)(hcsum1 >> 8);
    frag1[11] = (uint8_t)(hcsum1 & 0xFF);
    memcpy(frag1 + 20, udp_hdr, 8);
    memcpy(frag1 + 28, udp_payload, split - 8);
    *frag1_len = 20 + frag1_ip_payload;

    /* ---- фрагмент 2: IP(20) + хвост данных, БЕЗ своего UDP-заголовка ---- */
    memset(frag2, 0, 20);
    frag2[0] = 0x45;
    uint16_t totlen2 = (uint16_t)(20 + frag2_ip_payload);
    frag2[2] = (uint8_t)(totlen2 >> 8);
    frag2[3] = (uint8_t)(totlen2 & 0xFF);
    frag2[4] = (uint8_t)(ip_id >> 8);
    frag2[5] = (uint8_t)(ip_id & 0xFF);
    uint16_t frag_off_units = (uint16_t)(split / 8); /* MF=0 — старшие 3 бита нулевые */
    frag2[6] = (uint8_t)(frag_off_units >> 8);
    frag2[7] = (uint8_t)(frag_off_units & 0xFF);
    frag2[8] = ttl;
    frag2[9] = 17;
    memcpy(frag2 + 12, &src_ip_be, 4);
    memcpy(frag2 + 16, &dst_ip_be, 4);
    uint16_t hcsum2 = ip_checksum16(frag2, 20);
    frag2[10] = (uint8_t)(hcsum2 >> 8);
    frag2[11] = (uint8_t)(hcsum2 & 0xFF);
    memcpy(frag2 + 20, udp_payload + (split - 8), frag2_ip_payload);
    *frag2_len = 20 + frag2_ip_payload;

    return *frag1_len + *frag2_len;
}

/* =========================================================================
 * Реальный отправитель фрагментации (сырой сокет, IP_HDRINCL) — умолчание
 * d2k_quic_ask_frag_hook. НЕ протестирован на проводе в этом дереве: сырой
 * сокет требует CAP_NET_RAW, а `make check` обязан быть зелёным и без него
 * (тот же приём, что d2k_mark_hook в d2k_meas.h) — тест подставляет свой хук
 * и проверяет ДИСЦИПЛИНУ ЛЕСТНИЦЫ, не эту функцию; построение самих байт
 * (d2k_quic_build_frag2 выше) проверено отдельно и без сокетов.
 * ========================================================================= */

static d2k_tally frag_fail(int repeats, uint32_t mark, int *sent_out) {
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.err = repeats;
    t.fail = repeats;
    t.marked = (mark == 0);
    if (sent_out) {
        *sent_out = 0;
    }
    return t;
}

static d2k_tally frag_real(const char *addr, uint16_t port, d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                            int repeats, int *sent_out) {
    if (repeats <= 0) {
        repeats = D2K_QUIC_REPEATS;
    }
    if (repeats > D2K_QUIC_MAX_ADDRS) {
        /* Тот же приём, что и quic_ask_ex в quicprobe.c: нарушение контракта
           отклоняет опыт целиком, а не молча ужимает repeats. */
        return frag_fail(repeats, mark, sent_out);
    }
    if (!addr || !msg.bytes || msg.len == 0) {
        return frag_fail(repeats, mark, sent_out);
    }

    /* Шаг 1: узнать локальный адрес/порт и ИЗМЕРЕННЫЙ (не изобретённый) TTL
       маршрута — тем же способом, каким это выбрала бы обычная отправка:
       обычный подключенный UDP-сокет, ничего по нему не посылаем. */
    int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe_fd < 0) {
        return frag_fail(repeats, mark, sent_out);
    }
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &dst.sin_addr) != 1 || connect(probe_fd, (struct sockaddr *)&dst, sizeof dst) != 0) {
        close(probe_fd);
        return frag_fail(repeats, mark, sent_out);
    }
    struct sockaddr_in local;
    socklen_t local_len = sizeof local;
    if (getsockname(probe_fd, (struct sockaddr *)&local, &local_len) != 0) {
        close(probe_fd);
        return frag_fail(repeats, mark, sent_out);
    }
    int ttl_int = 64; /* умолчание на случай, если getsockopt откажет — тот же порядок, что qp_send_one */
    socklen_t ttl_len = sizeof ttl_int;
    (void)getsockopt(probe_fd, IPPROTO_IP, IP_TTL, &ttl_int, &ttl_len);
    close(probe_fd);

    /* Шаг 2: реальный ответ слушаем ОБЫЧНЫМ UDP-сокетом, забинденным на тот
       же локальный адрес/порт, что "занял" зонд выше, — сырой сокет отдаёт
       IP-пакеты как есть и не даёт ядру собрать UDP-ответ для recv(). Порт
       зонда уже освобождён (probe_fd закрыт) к моменту bind — но ЭТО и есть
       порт, который мы впишем как исходный в самодельный UDP-заголовок ниже,
       так что ответ сервера придёт именно на него. */
    int rx_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rx_fd < 0) {
        return frag_fail(repeats, mark, sent_out);
    }
    int reuse = 1;
    (void)setsockopt(rx_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
    if (bind(rx_fd, (struct sockaddr *)&local, sizeof local) != 0) {
        close(rx_fd);
        return frag_fail(repeats, mark, sent_out);
    }
    if (mark != 0 && d2k_mark_hook(rx_fd, mark) != 0) {
        /* Отказ пометить не отменяет опыт — та же дисциплина, что qp_send_one
           (marked отражает факт подтверждения, а не блокирует отправку). */
    }

    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_fd < 0) {
        /* НЕТ CAP_NET_RAW — опыт не состоялся, наша сторона, тот же класс,
           что и сбой socket() в qp_send_one. */
        close(rx_fd);
        return frag_fail(repeats, mark, sent_out);
    }
    int hdrincl = 1;
    (void)setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof hdrincl);

    uint8_t frag1[D2K_QUIC_FRAG_MAX], frag2[D2K_QUIC_FRAG_MAX];
    size_t f1len = 0, f2len = 0;
    uint16_t ip_id = (uint16_t)(local.sin_port); /* повторяемо в пределах одного вызова, не для секретности */
    size_t built = d2k_quic_build_frag2(msg.bytes, msg.len, local.sin_addr.s_addr, dst.sin_addr.s_addr,
                                         ntohs(local.sin_port), port, ip_id, (uint8_t)ttl_int, frag1, &f1len,
                                         frag2, &f2len);
    if (built == 0) {
        close(raw_fd);
        close(rx_fd);
        return frag_fail(repeats, mark, sent_out);
    }

#ifdef __APPLE__
    /* Известная особенность BSD/Darwin raw-сокетов с IP_HDRINCL: ip_len и
       ip_off ядро ожидает в ХОСТОВОМ порядке байт (оно само переводит их в
       сетевой перед отправкой) — на Linux те же поля обязаны быть уже в
       сетевом порядке, как их и строит d2k_quic_build_frag2. Это
       задокументированное расхождение, не догадка (см. исторические man-
       страницы ip(4) BSD-семейства); НЕ проверено эмпирически в этой песочнице
       — сырой сокет здесь недоступен без привилегии, см. шапку файла. */
    uint8_t *apple_fixup[2];
    apple_fixup[0] = frag1;
    apple_fixup[1] = frag2;
    for (int fi = 0; fi < 2; fi++) {
        uint8_t *f = apple_fixup[fi];
        uint16_t totlen = (uint16_t)((f[2] << 8) | f[3]);
        uint16_t offflags = (uint16_t)((f[6] << 8) | f[7]);
        f[2] = (uint8_t)(totlen & 0xFF);
        f[3] = (uint8_t)(totlen >> 8);
        f[6] = (uint8_t)(offflags & 0xFF);
        f[7] = (uint8_t)(offflags >> 8);
    }
#endif

    struct sockaddr_in raw_dst;
    memset(&raw_dst, 0, sizeof raw_dst);
    raw_dst.sin_family = AF_INET;
    raw_dst.sin_port = htons(port);
    raw_dst.sin_addr.s_addr = dst.sin_addr.s_addr;

    int sent = 0;
    struct timespec sent_at[8];
    int fds_marker[8]; /* фиктивный — recv идёт с ОДНОГО rx_fd, но время отправки нужно на каждую попытку */
    (void)fds_marker;
    for (int i = 0; i < repeats; i++) {
        ssize_t r1 = sendto(raw_fd, frag1, f1len, 0, (struct sockaddr *)&raw_dst, sizeof raw_dst);
        ssize_t r2 = sendto(raw_fd, frag2, f2len, 0, (struct sockaddr *)&raw_dst, sizeof raw_dst);
        if (r1 >= 0 && r2 >= 0) {
            clock_gettime(CLOCK_MONOTONIC, &sent_at[sent < 8 ? sent : 7]);
            sent++;
        }
    }
    close(raw_fd);

    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    int not_sent = repeats - sent;
    t.err += not_sent;
    t.fail += not_sent;

    if (sent > 0) {
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        uint32_t w = (wait_ms == 0) ? D2K_QUIC_RTT_WAIT_FLOOR_MS : wait_ms;
        deadline.tv_sec += (time_t)(w / 1000u);
        deadline.tv_nsec += (long)(w % 1000u) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        int got = 0;
        while (got < sent) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long remain_ms =
                (long)(deadline.tv_sec - now.tv_sec) * 1000L + (deadline.tv_nsec - now.tv_nsec) / 1000000L;
            if (remain_ms <= 0) {
                break;
            }
            struct pollfd pfd = {rx_fd, POLLIN, 0};
            int pr = poll(&pfd, 1, (int)remain_ms);
            if (pr <= 0) {
                break;
            }
            uint8_t buf[2048];
            ssize_t n = recv(rx_fd, buf, sizeof buf, 0);
            got++;
            if (n > 0 && d2k_quic_verify_response(buf, (size_t)n, msg) == 0) {
                t.pass++;
            } else {
                t.fail++;
            }
        }
        t.fail += (sent - got); /* тайм-аут без ответа на оставшиеся отправленные попытки */
    }
    close(rx_fd);

    if (sent_out) {
        *sent_out = sent;
    }
    return t;
}

d2k_quic_ask_frag_fn d2k_quic_ask_frag_hook = frag_real;

/* =========================================================================
 * Бюджет — своя копия budget_left из quicprobe.c (см. её большой комментарий
 * про гонку на бюджете 0: явный случай снимает гонку совсем). Не экспорт: в
 * отличие от d2k_quic_build_pool/d2k_quic_verify_response выше, здесь нечему
 * разойтись — четыре строки сравнения времени против одной и той же
 * переменной d2k_quic_budget_s, заводить публичный экспорт ради них было бы
 * обобщением на пустом месте.
 * ========================================================================= */

static int qa_budget_left(const struct timespec *start) {
    if (d2k_quic_budget_s == 0) {
        return 0;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    time_t deadline = start->tv_sec + (time_t)d2k_quic_budget_s;
    if (now.tv_sec > deadline) {
        return 0;
    }
    if (now.tv_sec == deadline && now.tv_nsec > start->tv_nsec) {
        return 0;
    }
    return 1;
}

/* =========================================================================
 * Подтверждение — единогласием, на СВЕЖЕМ адресе (см. большой комментарий в
 * шапке файла). Общий хвост для веток "блоб/TTL" и отдельно для
 * "фрагментация" — у последней другая сигнатура хука (нет prefix), объединять
 * их через приведение типов функций в C99 значило бы жертвовать проверкой
 * типов ради пяти общих строк — не стоит.
 * ========================================================================= */

static d2k_quic_arm qa_confirm(const char pool[][D2K_QUIC_ADDR_LEN], size_t n_pool, size_t *next_fresh,
                                uint16_t port, d2k_hello trigger, uint32_t mark, int *probes,
                                d2k_quic_arm_kind kind, size_t blob_id, int ttl) {
    d2k_quic_arm a;
    memset(&a, 0, sizeof a);
    if (*next_fresh >= n_pool) {
        a.kind = D2K_QA_NOT_FOUND;
        snprintf(a.reason, sizeof a.reason,
                 "плечо не подтверждено (адреса): пул из %zu исчерпан, подтверждать на разведанном нельзя",
                 n_pool);
        a.probes = *probes;
        return a;
    }
    const char *fresh = pool[(*next_fresh)++];
    size_t blen;
    const uint8_t *bytes = d2k_quic_arm_blob(blob_id, &blen);
    int sent = 0;
    d2k_tally t;
    if (ttl > 0) {
        t = d2k_quic_ask_ttl_hook(fresh, port, bytes, blen, ttl, trigger, d2k_quic_wait_ms, mark,
                                   D2K_QUIC_REPEATS, &sent);
    } else {
        t = d2k_quic_ask_hook(fresh, port, bytes, blen, trigger, d2k_quic_wait_ms, mark, D2K_QUIC_REPEATS,
                               NULL, NULL, &sent);
    }
    *probes += sent;
    if (t.err > 0) {
        a.kind = D2K_QA_FLAKY;
        snprintf(a.reason, sizeof a.reason, "подтверждение на %s: %d/%d не состоялись — транспорт", fresh,
                 t.err, D2K_QUIC_REPEATS);
    } else if (t.pass == D2K_QUIC_REPEATS) {
        a.kind = kind;
        a.blob_id = blob_id;
        a.ttl = ttl;
        snprintf(a.reason, sizeof a.reason, "подтверждено на свежем адресе %s: %d/%d", fresh, t.pass,
                 D2K_QUIC_REPEATS);
    } else if (t.pass > 0) {
        a.kind = D2K_QA_FLAKY;
        snprintf(a.reason, sizeof a.reason, "подтверждение не воспроизводится: %d/%d — flaky дешевле "
                                             "ложного плеча",
                 t.pass, D2K_QUIC_REPEATS);
    } else {
        a.kind = D2K_QA_NOT_FOUND;
        snprintf(a.reason, sizeof a.reason,
                 "разведочный проход не воспроизвёлся на свежем адресе (0/%d) — не подтверждено",
                 D2K_QUIC_REPEATS);
    }
    a.probes = *probes;
    return a;
}

static d2k_quic_arm qa_confirm_frag(const char pool[][D2K_QUIC_ADDR_LEN], size_t n_pool, size_t *next_fresh,
                                     uint16_t port, d2k_hello trigger, uint32_t mark, int *probes) {
    d2k_quic_arm a;
    memset(&a, 0, sizeof a);
    if (*next_fresh >= n_pool) {
        a.kind = D2K_QA_NOT_FOUND;
        snprintf(a.reason, sizeof a.reason,
                 "фрагментация сработала разведочно, но подтвердить не на чем — пул из %zu адресов "
                 "исчерпан",
                 n_pool);
        a.probes = *probes;
        return a;
    }
    const char *fresh = pool[(*next_fresh)++];
    int sent = 0;
    d2k_tally t =
        d2k_quic_ask_frag_hook(fresh, port, trigger, d2k_quic_wait_ms, mark, D2K_QUIC_REPEATS, &sent);
    *probes += sent;
    if (t.err > 0) {
        a.kind = D2K_QA_FLAKY;
        snprintf(a.reason, sizeof a.reason,
                 "подтверждение фрагментации на %s: %d/%d не состоялись — транспорт", fresh, t.err,
                 D2K_QUIC_REPEATS);
    } else if (t.pass == D2K_QUIC_REPEATS) {
        a.kind = D2K_QA_FRAG;
        snprintf(a.reason, sizeof a.reason, "фрагментация подтверждена на свежем адресе %s: %d/%d", fresh,
                 t.pass, D2K_QUIC_REPEATS);
    } else if (t.pass > 0) {
        a.kind = D2K_QA_FLAKY;
        snprintf(a.reason, sizeof a.reason, "подтверждение фрагментации не воспроизводится: %d/%d",
                 t.pass, D2K_QUIC_REPEATS);
    } else {
        a.kind = D2K_QA_NOT_FOUND;
        snprintf(a.reason, sizeof a.reason, "фрагментация не воспроизвелась на свежем адресе (0/%d)",
                 D2K_QUIC_REPEATS);
    }
    a.probes = *probes;
    return a;
}

/* =========================================================================
 * Дерево плеч — см. полный контракт в d2k_quicprobe.h.
 * ========================================================================= */

d2k_quic_arm d2k_quic_pick_arm(const char *ip, uint16_t port, const char *sni, d2k_hello trigger,
                                uint32_t mark) {
    d2k_quic_arm a;
    memset(&a, 0, sizeof a);

    /* Тот же guard, что d2k_quic_classify (quicprobe.c) — тот же класс входа,
       та же причина: структурно непригодный вход не измеряется, а отвергается
       ДО первого опыта. */
    int ip_ok = 0;
    if (ip && strlen(ip) < D2K_QUIC_ADDR_LEN) {
        struct in_addr probe;
        ip_ok = (inet_pton(AF_INET, ip, &probe) == 1);
    }
    if (!ip_ok || !sni || !trigger.bytes || trigger.len == 0) {
        a.kind = D2K_QA_FLAKY;
        snprintf(a.reason, sizeof a.reason,
                 "вход структурно непригоден: адрес не разбирается как IPv4, имя или снимок триггера "
                 "отсутствуют — подбирать плечо не на чем");
        return a;
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    char pool[D2K_QUIC_MAX_ADDRS][D2K_QUIC_ADDR_LEN];
    size_t n_pool = d2k_quic_build_pool(ip, sni, pool, D2K_QUIC_MAX_ADDRS);
    size_t next_fresh = 1; /* pool[0] занят разведкой — см. шапку файла */
    int probes = 0;

    if (!qa_budget_left(&start)) {
        a.kind = D2K_QA_NOT_FOUND;
        snprintf(a.reason, sizeof a.reason, "бюджет исчерпан до первой попытки — подбор не начат");
        return a;
    }

    /* ===== Ступень 1 (самая дешёвая): одиночная фальшивка, перебор блобов ===== */
    int chosen_blob = -1;
    for (size_t i = 0; i < D2K_QUIC_ARM_N_BLOBS && chosen_blob < 0; i++) {
        if (!qa_budget_left(&start)) {
            a.kind = D2K_QA_NOT_FOUND;
            snprintf(a.reason, sizeof a.reason, "бюджет исчерпан на переборе блобов (успели %zu из %u)", i,
                      D2K_QUIC_ARM_N_BLOBS);
            a.probes = probes;
            return a;
        }
        size_t blen;
        const uint8_t *bytes = d2k_quic_arm_blob(i, &blen);
        int sent = 0;
        d2k_tally t = d2k_quic_ask_hook(pool[0], port, bytes, blen, trigger, d2k_quic_wait_ms, mark, 1,
                                          NULL, NULL, &sent);
        probes += sent;
        if (t.pass == 1) {
            chosen_blob = (int)i;
        }
    }
    if (chosen_blob >= 0) {
        return qa_confirm(pool, n_pool, &next_fresh, port, trigger, mark, &probes, D2K_QA_BLOB,
                           (size_t)chosen_blob, 0);
    }

    /* ===== Ступень 2: приманка с укороченным TTL, взятым РАЗВЁРТКОЙ =====
       Развёртка, а не вычисление из входящего пакета: путь туда и обратно не
       обязан быть симметричным, и TTL ответа не говорит, сколько прыжков было
       ДО цензора на исходящем пути — выдавать невычислимое число за
       измеренное опаснее, чем не иметь числа вовсе (см. doc-комментарий
       d2k_quic_pick_arm). Снизу вверх (TTL=1) и до предела самого поля (RFC
       791 §3.1 — 8 бит, 255), останов на первом успехе: сама лестница держит
       стоимость минимальной, изобретённый потолок ниже 255 не нужен —
       бюджет §7 обрежет её раньше, если потребуется. */
    size_t shaped_len;
    const uint8_t *shaped = d2k_quic_arm_blob(D2K_QUIC_ARM_BLOB_SHAPED, &shaped_len);
    int chosen_ttl = -1;
    for (int ttl = 1; ttl <= 255 && chosen_ttl < 0; ttl++) {
        if (!qa_budget_left(&start)) {
            a.kind = D2K_QA_NOT_FOUND;
            snprintf(a.reason, sizeof a.reason, "бюджет исчерпан на развёртке TTL (успели до %d)", ttl - 1);
            a.probes = probes;
            return a;
        }
        int sent = 0;
        d2k_tally t = d2k_quic_ask_ttl_hook(pool[0], port, shaped, shaped_len, ttl, trigger,
                                              d2k_quic_wait_ms, mark, 1, &sent);
        probes += sent;
        if (t.pass == 1) {
            chosen_ttl = ttl;
        }
    }
    if (chosen_ttl >= 0) {
        return qa_confirm(pool, n_pool, &next_fresh, port, trigger, mark, &probes, D2K_QA_TTL,
                           D2K_QUIC_ARM_BLOB_SHAPED, chosen_ttl);
    }

    /* ===== Ступень 3 (самая дорогая): IP-фрагментация ===== */
    if (!qa_budget_left(&start)) {
        a.kind = D2K_QA_NOT_FOUND;
        snprintf(a.reason, sizeof a.reason, "бюджет исчерпан до фрагментации");
        a.probes = probes;
        return a;
    }
    int frag_sent = 0;
    d2k_tally tf = d2k_quic_ask_frag_hook(pool[0], port, trigger, d2k_quic_wait_ms, mark, 1, &frag_sent);
    probes += frag_sent;
    if (tf.pass == 1) {
        return qa_confirm_frag(pool, n_pool, &next_fresh, port, trigger, mark, &probes);
    }

    a.kind = D2K_QA_NOT_FOUND;
    snprintf(a.reason, sizeof a.reason,
             "ни один блоб, ни развёртка TTL до предела поля (255), ни фрагментация не дали прохода в "
             "пределах бюджета — каталог исчерпан");
    a.probes = probes;
    return a;
}
