#define _POSIX_C_SOURCE 200809L
/* SO_MARK — НЕ POSIX, и под строгим _POSIX_C_SOURCE библиотека его ПРЯЧЕТ.
 * Молча: #ifdef не срабатывает, компилятор не ругается, метка просто не
 * ставится ни на одном зонде — и замер меряет наш же обход поверх коробки.
 * Та же причина и то же лекарство, что в core/meas.c и datapath/raw.c.
 * Ловится это только счётчиком iptables, то есть уже на роутере. */
#define _DEFAULT_SOURCE 1

/* raw.c — сырой слой зондов: то, что нельзя сделать обычным сокетом.
 *
 * Перенос internal/classify/raw_linux.go эталона (коммит e9a3913) на C.
 *
 * ЗАЧЕМ ЦЕЛИКОМ СВОЙ TCP, А НЕ ЯДЕРНЫЙ СОКЕТ ПЛЮС ИНЪЕКЦИЯ. Чтобы отравить
 * буфер пересборки, фальшивый сегмент обязан лечь в ТУ ЖЕ область
 * последовательности, что и настоящие данные. Значит нужно знать snd_nxt
 * соединения — а ядро его наружу не отдаёт: в struct tcp_info такого поля нет.
 * Подсмотреть можно только сниффером, но к тому моменту настоящий сегмент уже
 * ушёл, и травить поздно.
 *
 * Поэтому рукопожатие делается здесь: SYN, SYN-ACK, ACK. Нам не нужен полный
 * стек — ни ретрансмиты, ни окно, ни контроль перегрузки. Нужно несколько
 * пакетов с полным контролем над каждым полем, а живёт соединение секунды.
 *
 * ЯДРО ПРИДЁТСЯ ПРИДЕРЖАТЬ. О нашем соединении оно не знает и на SYN-ACK
 * ответит своим RST, оборвав зонд раньше, чем тот что-то измерит. На время
 * работы ставим правило, роняющее исходящие RST с нашего порта, и снимаем его
 * при закрытии. Порт из счётчика, правило узкое.
 */
#include "d2k_detect.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SO_MARK
#define SO_MARK 36
#endif

int d2k_raw_supported(void) { return 1; }

enum {
    TCP_FIN = 0x01,
    TCP_SYN = 0x02,
    TCP_RST = 0x04,
    TCP_PSH = 0x08,
    TCP_ACK = 0x10,
    TCP_URG = 0x20
};

typedef struct {
    int      send_fd;
    int      recv_fd;
    uint8_t  src[4];
    uint8_t  dst[4];
    uint16_t sport;
    uint16_t dport;
    uint32_t seq; /* наш следующий номер */
    uint32_t ack; /* что подтверждаем */
    int      rule_up;
} raw_conn;

/* rstRuleFailed — хоть раз не удалось закрыть ядру рот. Взводится навсегда:
 * один отказ уже делает отрицательные результаты сырых зондов недостоверными. */
static int g_rst_rule_failed;
static int g_swept;
static uint32_t g_sport_counter;
static int g_seeded;

int d2k_raw_rst_rule_failed(void) { return g_rst_rule_failed; }

static void seed_once(void)
{
    if (!g_seeded) {
        g_seeded = 1;
        srandom((unsigned)(d2k_now_ms() ^ (long)getpid()));
        g_sport_counter = (uint32_t)(random() % 25000);
    }
}

/* nextSourcePort выдаёт исходный порт для сырого зонда.
 *
 * ПОЧЕМУ СЧЁТЧИК, А НЕ СЛУЧАЙНОЕ ЧИСЛО. Зонд вешает правило iptables по
 * СВОЕМУ порту. Два зонда с одинаковым портом делят одно правило, и уборщик
 * первого закрывает рот ядру у второго — тот получает RST от собственного
 * ядра и читает это как блокировку. Замер, врущий раз в сотню прогонов, —
 * худший вид замера: ошибку в нём не воспроизвести. */
static uint16_t next_source_port(void)
{
    seed_once();
    g_sport_counter++;
    return (uint16_t)(30000 + g_sport_counter % 25000);
}

/* parseStaleRSTRule — наше ли это правило и на каком порту.
 *
 * Форма нормализована самим iptables (проверено на роутере, v1.4.21).
 * Сверяем её ЦЕЛИКОМ, началом и концом: частичный разбор уже прострелил —
 * правило с чужим действием (-j ACCEPT) принималось за своё. */
static const char STALE_PREFIX[] = "-A OUTPUT -p tcp -m tcp --sport ";
static const char STALE_SUFFIX[] = " --tcp-flags RST RST -j DROP";

int d2k_parse_stale_rst_rule(const char *line, int *port)
{
    size_t n, pl, sl;
    const char *mid;
    char buf[32];
    char *end;
    long v;

    while (*line == ' ' || *line == '\t') {
        line++;
    }
    n = strlen(line);
    while (n > 0 && (line[n - 1] == ' ' || line[n - 1] == '\t' ||
                     line[n - 1] == '\r' || line[n - 1] == '\n')) {
        n--;
    }
    pl = sizeof(STALE_PREFIX) - 1;
    sl = sizeof(STALE_SUFFIX) - 1;
    if (n <= pl + sl) {
        return 0;
    }
    if (strncmp(line, STALE_PREFIX, pl) != 0) {
        return 0;
    }
    if (strncmp(line + n - sl, STALE_SUFFIX, sl) != 0) {
        return 0;
    }
    mid = line + pl;
    if (n - pl - sl >= sizeof(buf)) {
        return 0;
    }
    memcpy(buf, mid, n - pl - sl);
    buf[n - pl - sl] = '\0';
    errno = 0;
    v = strtol(buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0') {
        return 0;
    }
    /* Только наш диапазон: чужие правила с флагом RST снимать мы не вправе. */
    if (v < 30000 || v > 54999) {
        return 0;
    }
    *port = (int)v;
    return 1;
}

/* sweepStaleRSTRules снимает правила подавления, оставшиеся от прошлых
 * прогонов: уборщик не выполнится, если процесс убили сигналом KILL — а
 * панель именно так и добивает замер, не уложившийся в отведённое время. */
static void sweep_stale_rst_rules(void)
{
    FILE *f;
    char line[512];

    if (g_swept) {
        return;
    }
    g_swept = 1;
    f = popen("iptables -S OUTPUT 2>/dev/null", "r");
    if (!f) {
        return;
    }
    while (fgets(line, sizeof(line), f)) {
        int port;
        if (d2k_parse_stale_rst_rule(line, &port)) {
            char cmd[192];
            snprintf(cmd, sizeof(cmd),
                     "iptables -D OUTPUT -p tcp --sport %d --tcp-flags RST RST -j DROP"
                     " >/dev/null 2>&1", port);
            (void)system(cmd);
        }
    }
    pclose(f);
}

/* suppressKernelRST закрывает ядру рот на время зонда.
 *
 * БЕЗ -w, И ЭТО ПРОВЕРЕНО. На роутере владельца iptables v1.4.21: он понимает
 * голый -w, но не понимает «-w 5» — числовой аргумент появился только в
 * 1.4.22. С «-w 5» вставка падает, правило не встаёт, каждый зонд получает RST
 * от собственного ядра и читается как блокировка (замер 04.09: классификатор
 * вырождался в opaque с полным перебором на любом домене). Отказ здесь
 * молчаливый по замыслу, поэтому факт отказа обязан доехать до вердикта. */
static int suppress_kernel_rst(uint16_t sport)
{
    char cmd[192];
    snprintf(cmd, sizeof(cmd),
             "iptables -I OUTPUT -p tcp --sport %u --tcp-flags RST RST -j DROP"
             " >/dev/null 2>&1", (unsigned)sport);
    if (system(cmd) != 0) {
        g_rst_rule_failed = 1;
        return 0;
    }
    return 1;
}

static void release_kernel_rst(uint16_t sport)
{
    char cmd[192];
    snprintf(cmd, sizeof(cmd),
             "iptables -D OUTPUT -p tcp --sport %u --tcp-flags RST RST -j DROP"
             " >/dev/null 2>&1", (unsigned)sport);
    (void)system(cmd);
}

/* localAddrFor узнаёт, с какого адреса ядро пошло бы к этой цели. */
static int local_addr_for(const uint8_t dst[4], uint16_t port, uint8_t out[4])
{
    int fd;
    struct sockaddr_in sa;
    struct sockaddr_in local;
    socklen_t sl = sizeof(local);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, dst, 4);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return 0;
    }
    if (getsockname(fd, (struct sockaddr *)&local, &sl) != 0) {
        close(fd);
        return 0;
    }
    close(fd);
    memcpy(out, &local.sin_addr, 4);
    return 1;
}

static uint16_t rd16(const uint8_t *b) { return (uint16_t)((b[0] << 8) | b[1]); }

static uint32_t rd32(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static void wr16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)v; }

static void wr32(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);  b[3] = (uint8_t)v;
}

static uint16_t checksum(const uint8_t *b, size_t n)
{
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < n; i += 2) {
        sum += (uint32_t)rd16(b + i);
    }
    if (n % 2 == 1) {
        sum += (uint32_t)b[n - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(const uint8_t src[4], const uint8_t dst[4],
                             const uint8_t *t, size_t tlen)
{
    static uint8_t ph[12 + 65535];
    if (tlen > 65535) {
        return 0;
    }
    memset(ph, 0, 12);
    memcpy(ph, src, 4);
    memcpy(ph + 4, dst, 4);
    ph[9] = 6; /* IPPROTO_TCP */
    wr16(ph + 10, (uint16_t)tlen);
    memcpy(ph + 12, t, tlen);
    ph[12 + 16] = 0;
    ph[12 + 17] = 0;
    return checksum(ph, 12 + tlen);
}

/* buildIPv4TCP собирает пакет целиком. Контрольные суммы считаем сами: ядро
 * их для IP_HDRINCL не трогает, а нам порча суммы нужна как инструмент. */
static size_t build_ipv4_tcp(uint8_t *pkt, size_t cap,
                             const uint8_t src[4], const uint8_t dst[4],
                             uint16_t sport, uint16_t dport,
                             uint32_t seq, uint32_t ack, uint8_t flags,
                             const uint8_t *payload, size_t plen,
                             const d2k_poison *p,
                             const uint8_t *extra, size_t extralen)
{
    uint8_t opts[64];
    size_t olen = 0;
    size_t data_off, tcp_len, ip_len;
    uint8_t *t;
    uint16_t sum;

    if (extra && extralen > 0 && extralen <= sizeof(opts)) {
        memcpy(opts, extra, extralen);
        olen = extralen;
    }
    if (p->tcp_ts && olen + 12 <= sizeof(opts)) {
        /* Метка времени со сдвигом назад: сервер бракует устаревшую, коробка
         * её не сверяет. Значение произвольное, важен сам факт «в прошлом». */
        opts[olen + 0] = 1; opts[olen + 1] = 1; /* NOP, NOP — выравнивание */
        opts[olen + 2] = 8; opts[olen + 3] = 10;
        wr32(opts + olen + 4, 1);
        wr32(opts + olen + 8, 0);
        olen += 12;
    }
    if (p->md5) {
        /* TCP-MD5 (kind 19, len 18) плюс NOP-ы до кратности четырём.
         * В эталоне эта ветка ЗАМЕЩАЕТ опции, а не дополняет. */
        memset(opts, 0, 20);
        opts[0] = 19;
        opts[1] = 18;
        opts[18] = 1;
        opts[19] = 1;
        olen = 20;
    }
    while (olen % 4 != 0 && olen < sizeof(opts)) {
        opts[olen++] = 0;
    }
    data_off = 5 + olen / 4;
    tcp_len = data_off * 4 + plen;
    ip_len = 20 + tcp_len;
    if (ip_len > cap) {
        return 0;
    }

    memset(pkt, 0, ip_len);
    pkt[0] = 0x45;
    wr16(pkt + 2, (uint16_t)ip_len);
    if (!p->ip_id_zero) {
        seed_once();
        wr16(pkt + 4, (uint16_t)(random() % 65535));
    }
    pkt[8] = p->ttl > 0 ? (uint8_t)p->ttl : (uint8_t)64;
    pkt[9] = 6; /* IPPROTO_TCP */
    memcpy(pkt + 12, src, 4);
    memcpy(pkt + 16, dst, 4);
    wr16(pkt + 10, checksum(pkt, 20));

    t = pkt + 20;
    wr16(t + 0, sport);
    wr16(t + 2, dport);
    wr32(t + 4, seq);
    wr32(t + 8, ack);
    t[12] = (uint8_t)(data_off << 4);
    t[13] = flags;
    wr16(t + 14, 65535);
    if (olen > 0) {
        memcpy(t + 20, opts, olen);
    }
    if (plen > 0) {
        memcpy(t + data_off * 4, payload, plen);
    }

    sum = tcp_checksum(src, dst, t, tcp_len);
    if (p->badsum) {
        sum ^= 0xbeef;
        if (sum == 0) {
            sum = 0x1234;
        }
    }
    wr16(t + 16, sum);
    return ip_len;
}

static int raw_sendto(raw_conn *c, const uint8_t *pkt, size_t n)
{
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(c->dport);
    memcpy(&to.sin_addr, c->dst, 4);
    if (sendto(c->send_fd, pkt, n, 0, (struct sockaddr *)&to, sizeof(to)) < 0) {
        return -1;
    }
    return 0;
}

/* Потолок полезной нагрузки в ОДНОМ сегменте.
 *
 * ЗАЧЕМ ОН ЗДЕСЬ ЕСТЬ. Сырой сокет не режет по MTU — он отвечает EMSGSIZE и
 * не шлёт ничего. Эталон этого не учитывает: шаг 1 отравления строит фальшивку
 * длиной 2×len(триггер), и на приветствии настоящего браузера (1534 байта)
 * это 3068 байт одним куском. Замер 14.09 на роутере владельца: ВСЯ половина
 * перебора, опирающаяся на отдельную фальшивку, молча проваливалась с
 * «message too long» — 294 зонда, четыре минуты, вердикт opaque на цели,
 * которую та же коробка отдаёт за 18 зондов. На приветствии crypto/tls
 * (287 байт) фальшивка занимает 574 байта и проходит — поэтому дефект и не
 * замечали: он просыпается ровно тогда, когда мерят теми байтами, которыми
 * ходит настоящий браузер. То есть в продукте — всегда.
 *
 * 1400 — с запасом под PPPoE (1492) и под опции TCP в нашем же заголовке. */
#define D2K_SEG_MAX 1400

/* send кладёт нагрузку на провод. Номер последовательности НЕ двигается при
 * отравленной посылке: фальшивка обязана занять ту же область, что займут
 * настоящие данные, иначе травить нечего.
 *
 * ДЛИННАЯ НАГРУЗКА УХОДИТ НЕСКОЛЬКИМИ СЕГМЕНТАМИ ПОДРЯД, а не одним. Область
 * последовательности при этом та же — сегменты идут встык, — то есть для
 * коробки и для сервера это ровно те же байты в тех же номерах. Для нагрузок
 * короче потолка поведение побайтно прежнее, и сверка с эталоном на его
 * собственном приветствии от этого не двигается.
 *
 * Мерить это не мешает: в эту ветку мы попадаем только тогда, когда разрез
 * pos=1 уже не помог, то есть коробка поток ПЕРЕСОБИРАЕТ. Для пересобирающей
 * коробки «одним сегментом или двумя» — не разница; для не пересобирающей
 * ответ уже получен выше по дереву. */
static int raw_send(raw_conn *c, const uint8_t *payload, size_t plen,
                    uint8_t flags, const d2k_poison *p)
{
    static uint8_t pkt[2048];
    uint32_t seq = c->seq;
    size_t off = 0;

    if (p->seq_shift != 0) {
        seq = (uint32_t)((int64_t)seq + (int64_t)p->seq_shift);
    }
    do {
        size_t take = plen - off;
        size_t n;
        if (take > D2K_SEG_MAX) {
            take = D2K_SEG_MAX;
        }
        n = build_ipv4_tcp(pkt, sizeof(pkt), c->src, c->dst, c->sport, c->dport,
                           seq + (uint32_t)off, c->ack, flags,
                           plen ? payload + off : NULL, take, p, NULL, 0);
        if (n == 0) {
            return -1;
        }
        if (raw_sendto(c, pkt, n) != 0) {
            return -1;
        }
        off += take;
    } while (off < plen);
    return 0;
}

/* sendSYN шлёт SYN с обычным набором опций: MSS, SACK-permitted, метки
 * времени, масштаб окна — ровно то, что кладёт ядро. Голое приветствие без
 * них само по себе аномалия: так не здоровается ни один настоящий клиент, и
 * коробка вправе относиться к такому потоку иначе. */
static int raw_send_syn(raw_conn *c)
{
    static const uint8_t opts[] = {
        2, 4, 0x05, 0xac,               /* MSS 1452 */
        4, 2,                           /* SACK permitted */
        8, 10, 0, 0, 0, 1, 0, 0, 0, 0,  /* timestamps */
        1,                              /* NOP */
        3, 3, 7                         /* window scale 7 */
    };
    static uint8_t pkt[256];
    d2k_poison none;
    size_t n;

    memset(&none, 0, sizeof(none));
    n = build_ipv4_tcp(pkt, sizeof(pkt), c->src, c->dst, c->sport, c->dport,
                       c->seq, 0, TCP_SYN, NULL, 0, &none, opts, sizeof(opts));
    if (n == 0) {
        return -1;
    }
    return raw_sendto(c, pkt, n);
}

/* recv возвращает следующий сегмент ОТ НАШЕГО пира. */
static int raw_recv(raw_conn *c, uint8_t *flags, uint32_t *seq, uint32_t *ack,
                    const uint8_t **payload, size_t *plen)
{
    static uint8_t buf[65535];
    for (;;) {
        ssize_t n = recvfrom(c->recv_fd, buf, sizeof(buf), 0, NULL, NULL);
        size_t ihl, off;
        const uint8_t *t;
        size_t tlen;
        if (n < 0) {
            return -1;
        }
        if (n < 40) {
            continue;
        }
        ihl = (size_t)(buf[0] & 0x0f) * 4;
        if ((size_t)n < ihl + 20) {
            continue;
        }
        if (memcmp(buf + 12, c->dst, 4) != 0) {
            continue;
        }
        t = buf + ihl;
        tlen = (size_t)n - ihl;
        if (rd16(t + 0) != c->dport || rd16(t + 2) != c->sport) {
            continue;
        }
        off = (size_t)(t[12] >> 4) * 4;
        if (off > tlen) {
            continue;
        }
        *flags = t[13];
        *seq = rd32(t + 4);
        *ack = rd32(t + 8);
        *payload = t + off;
        *plen = tlen - off;
        return 0;
    }
}

/* readPayload ждёт от сервера сегмент с данными. */
static int raw_read_payload(raw_conn *c, int timeout_ms,
                            uint8_t *out, size_t cap, size_t *outlen)
{
    long deadline = d2k_now_ms() + timeout_ms;
    while (d2k_now_ms() < deadline) {
        uint8_t flags;
        uint32_t seq, ack;
        const uint8_t *pay;
        size_t plen;
        if (raw_recv(c, &flags, &seq, &ack, &pay, &plen) != 0) {
            continue;
        }
        if (flags & TCP_RST) {
            return -1; /* RST */
        }
        if (plen > 0) {
            size_t k = plen < cap ? plen : cap;
            memcpy(out, pay, k);
            *outlen = k;
            return 0;
        }
    }
    return -1; /* тишина */
}

static void raw_close(raw_conn *c)
{
    if (c->rule_up) {
        release_kernel_rst(c->sport);
        c->rule_up = 0;
    }
    if (c->send_fd > 0) {
        close(c->send_fd);
        c->send_fd = -1;
    }
    if (c->recv_fd > 0) {
        close(c->recv_fd);
        c->recv_fd = -1;
    }
}

static int raw_handshake(raw_conn *c, int timeout_ms, char *err, size_t errcap)
{
    long deadline;
    d2k_poison none;

    memset(&none, 0, sizeof(none));
    if (raw_send_syn(c) != 0) {
        snprintf(err, errcap, "%s", strerror(errno));
        return -1;
    }
    deadline = d2k_now_ms() + timeout_ms;
    while (d2k_now_ms() < deadline) {
        uint8_t flags;
        uint32_t seq, ack;
        const uint8_t *pay;
        size_t plen;
        if (raw_recv(c, &flags, &seq, &ack, &pay, &plen) != 0) {
            continue;
        }
        if (flags & TCP_RST) {
            snprintf(err, errcap, "classify: сервер ответил RST на SYN");
            return -1;
        }
        if ((flags & TCP_SYN) && (flags & TCP_ACK)) {
            if (ack != c->seq + 1) {
                continue;
            }
            c->seq++;
            c->ack = seq + 1;
            if (raw_send(c, NULL, 0, TCP_ACK, &none) != 0) {
                snprintf(err, errcap, "%s", strerror(errno));
                return -1;
            }
            return 0;
        }
    }
    snprintf(err, errcap, "classify: SYN-ACK не пришёл");
    return -1;
}

/* dialRaw поднимает соединение своими руками и возвращает его установленным. */
static int raw_dial(raw_conn *c, const uint8_t dst[4], uint16_t dport,
                    int timeout_ms, uint32_t mark_val, char *err, size_t errcap)
{
    int one = 1;
    int mark = (int)mark_val;
    struct timeval tv;

    memset(c, 0, sizeof(*c));
    c->send_fd = -1;
    c->recv_fd = -1;
    memcpy(c->dst, dst, 4);
    c->dport = dport;

    if (!local_addr_for(dst, dport, c->src)) {
        snprintf(err, errcap, "classify: не удалось определить свой адрес");
        return -1;
    }
    c->send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (c->send_fd < 0) {
        snprintf(err, errcap, "classify: сырой сокет на отправку (нужен root): %s",
                 strerror(errno));
        return -1;
    }
    /* МЕТКА, ОТКЛЮЧАЮЩАЯ НАШ ЖЕ ОБХОД. Замер обязан идти по СЫРОМУ пути,
     * иначе меряется не коробка провайдера, а наш десинк поверх неё. В
     * правилах NFQUEUE уже есть дверь: `-m mark ! --mark 0x40000000`. */
    (void)setsockopt(c->send_fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (setsockopt(c->send_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
        snprintf(err, errcap, "classify: IP_HDRINCL: %s", strerror(errno));
        raw_close(c);
        return -1;
    }
    c->recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (c->recv_fd < 0) {
        snprintf(err, errcap, "classify: сырой сокет на приём: %s", strerror(errno));
        raw_close(c);
        return -1;
    }
    tv.tv_sec = 0;
    tv.tv_usec = 300000;
    (void)setsockopt(c->recv_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Подметаем один раз за прогон, а не перед каждым зондом: зондов сотни, а
     * разбор таблицы стоит вызова iptables. */
    sweep_stale_rst_rules();
    c->sport = next_source_port();
    seed_once();
    c->seq = (uint32_t)random();
    c->rule_up = suppress_kernel_rst(c->sport);

    if (raw_handshake(c, timeout_ms, err, errcap) != 0) {
        raw_close(c);
        return -1;
    }
    return 0;
}

/* sendURG шлёт один байт как срочные данные: флаг URG плюс указатель за ним.
 * Сервер по RFC 793 изымает такой байт из потока, коробка — обычно нет. */
static int raw_send_urg(raw_conn *c, const uint8_t *payload, size_t plen)
{
    static uint8_t pkt[256];
    d2k_poison none;
    size_t n;
    uint8_t *t;
    uint16_t sum;

    memset(&none, 0, sizeof(none));
    n = build_ipv4_tcp(pkt, sizeof(pkt), c->src, c->dst, c->sport, c->dport,
                       c->seq, c->ack, (uint8_t)(TCP_PSH | TCP_ACK | TCP_URG),
                       payload, plen, &none, NULL, 0);
    if (n == 0) {
        return -1;
    }
    t = pkt + 20;
    /* Указатель срочности — сразу за нашим байтом. */
    t[18] = 0x00;
    t[19] = (uint8_t)plen;
    sum = tcp_checksum(c->src, c->dst, t, n - 20);
    wr16(t + 16, sum);
    return raw_sendto(c, pkt, n);
}

/* probeRawHandshake — самопроверка сырого слоя: доходит ли наше собственное
 * рукопожатие. Проверять его отправкой полезной нагрузки нельзя — поле
 * 2026-08-28, googlevideo: тот фронтенд обслуживает только заблокированные
 * имена, безобидной нагрузки для него не существует, и самопроверка падала не
 * потому, что слой сломан, а потому, что отвечать было не на что. */
int d2k_raw_probe_handshake(const uint8_t ip4[4], uint16_t port,
                            int timeout_ms, uint32_t mark, char *err, size_t errcap)
{
    raw_conn c;
    if (raw_dial(&c, ip4, port, timeout_ms, mark, err, errcap) != 0) {
        return -1;
    }
    raw_close(&c);
    return 1;
}

/* Текст ошибки зонда попадает в ТРАССУ и сверяется с эталоном построчно.
 * Поэтому здесь голый текст errno, без своей приписки: приписка расходилась бы
 * с эталоном на ровном месте и прятала бы настоящие расхождения. Остаточная
 * разница — сами строки libc (musl «Message too large» против glibc «message
 * too long» на одном и том же EMSGSIZE); она снимается таблицей в
 * tests/compare.sh, а не подгонкой кода. */

/* probePoison — ОДИН зонд, собранный из независимых приёмов.
 *
 * Боевое плечо для googlevideo это фальшивка С БИТОЙ СУММОЙ И НИЗКИМ TTL плюс
 * настоящие сегменты, пущенные НЕ ПО ПОРЯДКУ, — всё сразу, в одной стратегии.
 * Зонды, проверяющие приёмы по одному, такую коробку не поймают никогда
 * (замер 2026-08-28: 48 гипотез поодиночке мимо, то же плечо в связке — 10 из
 * 10 на том же адресе). Поэтому здесь два независимых шага: отравить буфер
 * фальшивкой и отдать правду — как есть, задом наперёд или внахлёст слева. */
int d2k_raw_probe_poison(const uint8_t ip4[4], uint16_t port,
                         const d2k_trigger *tr, const d2k_poison *p,
                         int timeout_ms, uint32_t mark, char *err, size_t errcap)
{
    static uint8_t fake[2 * D2K_TRIGGER_MAX];
    static uint8_t seg[D2K_TRIGGER_MAX + 4096];
    static uint8_t resp[8192];
    raw_conn c;
    d2k_poison none;
    uint32_t base;
    size_t resp_len = 0;
    int rc = 0;
    size_t n = tr->len;

    memset(&none, 0, sizeof(none));
    if (raw_dial(&c, ip4, port, timeout_ms, mark, err, errcap) != 0) {
        return -1;
    }

    /* ШАГ 1: фальшивка в ту же область последовательности, что займёт правда.
     *
     * ФАЛЬШИВКА — ОТДЕЛЬНАЯ ПОСЫЛКА, А НЕ НАЧИНКА ПЕРЕКРЫТИЯ. Дамп боевого
     * плеча 2026-08-29 показал, что это разные вещи и идут они подряд:
     *     ttl 63  seq 1:678     len 677   × 7   ← фальшивка, семь копий
     *     ttl 64  seq -680:2    len 682         ← перекрытие слева
     *     ttl 64  seq 2:1210    len 1208        ← остальное приветствие */
    if (strcmp(p->name, "none") != 0 && d2k_poison_has_fake(p)) {
        /* ФАЛЬШИВКА ДЛИННЕЕ ПРАВДЫ, и это тоже из дампа: боевое плечо шлёт 677
         * байт на приветствие в 343, то есть накрывает его целиком И заходит
         * за край. Коробка, дочитывающая запись до конца, на укороченной
         * фальшивке осталась бы ждать продолжения и приняла бы настоящие байты
         * как это продолжение — отравление тогда не срабатывает. */
        size_t flen = n * 2;
        int reps = p->repeats < 1 ? 1 : p->repeats;
        int i;
        if (flen > sizeof(fake)) {
            flen = sizeof(fake);
        }
        memset(fake, 0x0f, flen);
        if (p->decoy && p->decoy_len > 0) {
            /* Коробке, разбирающей протокол, набивка не годится: она её
             * пропустит мимо и продолжит ждать настоящее приветствие. */
            size_t k = p->decoy_len < flen ? p->decoy_len : flen;
            memcpy(fake, p->decoy, k);
        }
        for (i = 0; i < reps; i++) {
            if (raw_send(&c, fake, flen, (uint8_t)(TCP_PSH | TCP_ACK), p) != 0) {
                snprintf(err, errcap, "%s", strerror(errno));
                raw_close(&c);
                return -1;
            }
            if (p->gap_ms > 0 && i + 1 < reps) {
                d2k_sleep_ms(p->gap_ms);
            }
        }
        d2k_sleep_ms(15);
    }

    /* ШАГ 2: настоящие данные. */
    base = c.seq;
    if (p->syn_data) {
        /* ДАННЫЕ В САМОМ SYN. Рукопожатие уже прошло обычным путём, поэтому
         * здесь мы шлём приветствие сегментом с флагом SYN поверх готового
         * соединения: коробка увидит SYN и, если она payload в нём не
         * разбирает, сигнатуру пропустит. */
        if (raw_send(&c, tr->payload, n, (uint8_t)(TCP_SYN | TCP_PSH | TCP_ACK), &none) != 0) {
            snprintf(err, errcap, "%s", strerror(errno));
            raw_close(&c);
            return -1;
        }
    } else if (p->oob) {
        /* БАЙТ ВНЕ ПОЛОСЫ. Вставляем посторонний символ в середину имени и
         * помечаем его срочным: сервер по правилам изымет его из потока,
         * коробка, читающая всё подряд, оставит — и соберёт не ту строку. */
        static const uint8_t urgb[1] = {0x0f};
        size_t mid = n / 2;
        if (tr->sni_len > 1 && tr->sni_off > 0) {
            mid = (size_t)tr->sni_off + (size_t)tr->sni_len / 2;
        }
        if (mid < 1 || mid >= n) {
            mid = n / 2;
        }
        if (raw_send(&c, tr->payload, mid, (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) {
            goto senderr;
        }
        c.seq = base + (uint32_t)mid;
        if (raw_send_urg(&c, urgb, 1) != 0) {
            goto senderr;
        }
        c.seq = base + (uint32_t)mid + 1;
        if (raw_send(&c, tr->payload + mid, n - mid, (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) {
            goto senderr;
        }
        c.seq = base + (uint32_t)n + 1;
        if (raw_read_payload(&c, timeout_ms, resp, sizeof(resp), &resp_len) != 0) {
            raw_close(&c);
            return 0;
        }
        rc = d2k_trigger_accepts(tr, resp, resp_len);
        raw_close(&c);
        return rc;
    } else if (p->fake_between) {
        /* ФАЛЬШИВКА МЕЖДУ КУСКАМИ. Отличие от общего пути — размещение:
         * сперва настоящий первый кусок, следом фальшивка на его же
         * продолжение, и только потом настоящий остаток. */
        size_t mid = 1;
        size_t flen;
        d2k_poison fp;
        int reps = p->repeats < 1 ? 1 : p->repeats;
        int i;
        if (tr->sni_len > 1 && tr->sni_off > 0) {
            mid = (size_t)tr->sni_off;
        }
        if (mid >= n) {
            mid = 1;
        }
        if (raw_send(&c, tr->payload, mid, (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) {
            goto senderr;
        }
        flen = n - mid;
        if (flen > sizeof(fake)) {
            flen = sizeof(fake);
        }
        memset(fake, 0x0f, flen);
        memset(&fp, 0, sizeof(fp));
        fp.badsum = p->badsum;
        fp.ttl = p->ttl;
        for (i = 0; i < reps; i++) {
            c.seq = base + (uint32_t)mid;
            if (raw_send(&c, fake, flen, (uint8_t)(TCP_PSH | TCP_ACK), &fp) != 0) {
                goto senderr;
            }
        }
        d2k_sleep_ms(12);
        c.seq = base + (uint32_t)mid;
        if (raw_send(&c, tr->payload + mid, n - mid, (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) {
            goto senderr;
        }
    } else if (p->seqovl > 0 && p->disorder) {
        /* ПЕРЕКРЫТИЕ ВМЕСТЕ С ПОРЯДКОМ. Боевое плечо 1 пула rkn_tcp именно
         * такое: multisplit с seqovl И multidisorder на одном соединении.
         * Замер 2026-08-29: три хоста, которые арсенал берёт, а семьдесят
         * гипотез нет, стояли ровно на нём. */
        size_t mid = n / 2;
        size_t ov = (size_t)p->seqovl;
        if (tr->sni_len > 1 && tr->sni_off > 0) {
            mid = (size_t)tr->sni_off + (size_t)tr->sni_len / 2;
        }
        if (mid < 2) {
            mid = 2;
        }
        if (mid >= n) {
            mid = n - 1;
        }
        /* Хвост уходит первым, голова — последней и внахлёст слева. */
        c.seq = base + (uint32_t)mid;
        if (raw_send(&c, tr->payload + mid, n - mid, (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) {
            goto senderr;
        }
        d2k_sleep_ms(12);
        c.seq = base + 1;
        if (raw_send(&c, tr->payload + 1, mid - 1, (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) {
            goto senderr;
        }
        d2k_sleep_ms(12);
        if (ov + 1 > sizeof(seg)) {
            ov = sizeof(seg) - 1;
        }
        memset(seg, 0x0f, ov);
        if (p->decoy && p->decoy_len > 0) {
            size_t k = p->decoy_len < ov ? p->decoy_len : ov;
            memcpy(seg, p->decoy, k);
        }
        seg[ov] = tr->payload[0];
        c.seq = base - (uint32_t)ov;
        if (raw_send(&c, seg, ov + 1, (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) {
            goto senderr;
        }
    } else if (p->seqovl > 0) {
        /* Внахлёст слева: один сегмент с номером base-N, где первые N байт —
         * приманка. Сервер подрежет левый край окна и возьмёт правду. */
        size_t ov = (size_t)p->seqovl;
        if (ov + n > sizeof(seg)) {
            ov = sizeof(seg) - n;
        }
        memset(seg, 0x0f, ov);
        if (p->decoy && p->decoy_len > 0) {
            size_t k = p->decoy_len < ov ? p->decoy_len : ov;
            memcpy(seg, p->decoy, k);
        }
        memcpy(seg + ov, tr->payload, n);
        c.seq = base - (uint32_t)ov;
        if (raw_send(&c, seg, ov + n, (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) {
            goto senderr;
        }
    } else if (p->disorder) {
        /* ТРИ КУСКА, ПЕРВЫЙ БАЙТ — ПОСЛЕДНИМ. Дамп боевого плеча:
         *   seq 268:344 (76 б), seq 2:268 (266 б), seq 1:2 (1 б)
         * То есть `multidisorder:pos=1,midsld` режет по единице и по середине
         * домена, а на провод кладёт задом наперёд. Деление пополам на два
         * куска это не воспроизводит: коробке достаётся осмысленное начало
         * записи, и она спокойно дожидается остального.
         *
         * РЕЖЕМ ПО ИМЕНИ, А НЕ ПО СЕРЕДИНЕ ПАКЕТА: разорвано имя между
         * сегментами или лежит в одном куске — это и есть разница между
         * «сработало» и «нет». */
        size_t mid = n / 2;
        size_t from[3], to[3];
        int i;
        if (tr->sni_len > 1 && tr->sni_off > 0) {
            mid = (size_t)tr->sni_off + (size_t)tr->sni_len / 2;
        }
        if (mid < 2) {
            mid = 2;
        }
        if (mid >= n) {
            mid = n - 1;
        }
        from[0] = mid; to[0] = n;
        from[1] = 1;   to[1] = mid;
        from[2] = 0;   to[2] = 1;
        for (i = 0; i < 3; i++) {
            c.seq = base + (uint32_t)from[i];
            if (raw_send(&c, tr->payload + from[i], to[i] - from[i],
                         (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) {
                goto senderr;
            }
            d2k_sleep_ms(12);
        }
    } else {
        if (raw_send(&c, tr->payload, n, (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) {
            goto senderr;
        }
    }
    c.seq = base + (uint32_t)n;

    if (raw_read_payload(&c, timeout_ms, resp, sizeof(resp), &resp_len) != 0) {
        raw_close(&c);
        return 0;
    }
    rc = d2k_trigger_accepts(tr, resp, resp_len);
    raw_close(&c);
    return rc;

senderr:
    snprintf(err, errcap, "%s", strerror(errno));
    raw_close(&c);
    return -1;
}

#else /* !__linux__ */

/* Сырого слоя вне Linux нет. Это не заглушка «на будущее»: отрицательный
 * результат отравления без сырых сокетов не означает ничего, и вердикт обязан
 * это сказать (см. res.RawUsable в эталоне), а не промолчать. */
int d2k_raw_supported(void) { return 0; }
int d2k_raw_rst_rule_failed(void) { return 0; }

int d2k_parse_stale_rst_rule(const char *line, int *port);

int d2k_raw_probe_poison(const uint8_t ip4[4], uint16_t port,
                         const d2k_trigger *tr, const d2k_poison *p,
                         int timeout_ms, uint32_t mark, char *err, size_t errcap)
{
    (void)ip4; (void)port; (void)tr; (void)p; (void)timeout_ms; (void)mark;
    snprintf(err, errcap, "classify: сырой слой доступен только на Linux");
    return -1;
}

int d2k_raw_probe_handshake(const uint8_t ip4[4], uint16_t port,
                            int timeout_ms, uint32_t mark, char *err, size_t errcap)
{
    (void)ip4; (void)port; (void)timeout_ms; (void)mark;
    snprintf(err, errcap, "classify: сырой слой доступен только на Linux");
    return -1;
}

/* Разбор правила — чистая работа со строкой, и он обязан проверяться на любой
 * машине, а не только там, где есть iptables (так же вынесен в эталоне:
 * raw_rules.go отдельно от raw_linux.go). */
static const char STALE_PREFIX[] = "-A OUTPUT -p tcp -m tcp --sport ";
static const char STALE_SUFFIX[] = " --tcp-flags RST RST -j DROP";

int d2k_parse_stale_rst_rule(const char *line, int *port)
{
    size_t n, pl, sl;
    char buf[32];
    char *end;
    long v;

    while (*line == ' ' || *line == '\t') {
        line++;
    }
    n = strlen(line);
    while (n > 0 && (line[n - 1] == ' ' || line[n - 1] == '\t' ||
                     line[n - 1] == '\r' || line[n - 1] == '\n')) {
        n--;
    }
    pl = sizeof(STALE_PREFIX) - 1;
    sl = sizeof(STALE_SUFFIX) - 1;
    if (n <= pl + sl) {
        return 0;
    }
    if (strncmp(line, STALE_PREFIX, pl) != 0) {
        return 0;
    }
    if (strncmp(line + n - sl, STALE_SUFFIX, sl) != 0) {
        return 0;
    }
    if (n - pl - sl >= sizeof(buf)) {
        return 0;
    }
    memcpy(buf, line + pl, n - pl - sl);
    buf[n - pl - sl] = '\0';
    errno = 0;
    v = strtol(buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0') {
        return 0;
    }
    if (v < 30000 || v > 54999) {
        return 0;
    }
    *port = (int)v;
    return 1;
}

#endif /* __linux__ */
