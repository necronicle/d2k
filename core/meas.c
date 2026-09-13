#define _POSIX_C_SOURCE 200809L
/* SO_MARK — НЕ POSIX, и под строгим _POSIX_C_SOURCE glibc его ПРЯЧЕТ. Без
 * этой строки ветка #ifdef SO_MARK ниже не компилировалась НА LINUX ТОЖЕ, и
 * метка молча не ставилась ни на одном зонде: d2k_mark_real всегда возвращал
 * -1, r.marked оставался нулём, а правило «свои пакеты мимо очереди»
 * (-m mark --mark $MARK -j RETURN, files/S99d2k) не срабатывало ни разу.
 * Замерено счётчиками iptables в лаборатории 13.09.2026: на правиле метки 0
 * пакетов при шести ушедших зондах, и те же зонды — в журнале датапата, то
 * есть система видела собственное эхо (§5.5).
 *
 * Тот же приём и та же причина, что у _DEFAULT_SOURCE в datapath/raw.c
 * (там он стоял с самого начала — потому метка датапата работала) и у
 * _DARWIN_C_SOURCE в core/quicprobe.c ради IP_TTL. Ставится ДО первого
 * include: после него определение уже не подействует. */
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"

/* Ждать ответа дольше этого незачем: человек уже ушёл со страницы. */
#define WAIT_CEIL_MS 5000

/* Потолок ожидания САМОГО connect(). SO_RCVTIMEO/SO_SNDTIMEO на фазу
 * установления соединения не действуют — это таймер стека, а не опция
 * сокета, — а чёрная дыра на SYN (пакет просто не подтверждается) обычный
 * приём цензуры. Без явного срока три повтора на одном адресе способны
 * съесть весь бюджет цели (docs/spec/2026-09-06-c-engine-design.md, §7:
 * «Бюджет: до двух минут на цель») на одном зависшем дозвоне — умолчание
 * ядра для connect() на SYN-чёрной-дыре измеряется минутами.
 *
 * Число то же и того же происхождения, что и d2k_send_timeout_s ниже: оба
 * унаследованы от connectTimeout/transportCeiling в
 * internal/classify/measure.go, а туда — из internal/volume/probe.go и из
 * пробы донора z2k-detect/internal/tcp16. */
#define CONNECT_TIMEOUT_MS 8000

/* Потолок ОДНОЙ блокирующей записи. Объявлена и документирована в
 * d2k_meas.h: тесту на короткую запись нужно дождаться настоящего истечения
 * этого таймаута, а не восьми секунд в проде. */
uint32_t d2k_send_timeout_s = 8;

static void nap_us(uint32_t us) {
    struct timespec ts = { (time_t)(us / 1000000u), (long)(us % 1000000u) * 1000L };
    (void)nanosleep(&ts, NULL);
}

/* Настоящая попытка поставить метку — то, на что d2k_mark_hook указывает по
 * умолчанию. SO_MARK есть только на Linux (см. шапку core/Makefile и
 * scripts/check.sh: цели gcc-warn/cross существуют именно потому, что на
 * машине разработки — маке — эта ветка не компилируется вовсе). */
static int d2k_mark_real(int fd, uint32_t mark) {
#ifdef SO_MARK
    int m = (int)mark;
    return setsockopt(fd, SOL_SOCKET, SO_MARK, &m, sizeof m);
#else
    (void)fd;
    (void)mark;
    return -1;
#endif
}

d2k_mark_fn d2k_mark_hook = d2k_mark_real;

/* Типы записей TLS (RFC 8446 §5.1) и тип сообщения рукопожатия (§4). Те же
 * числа названы в d2k_link.h (D2K_TLS_ALERT, D2K_TLS_HANDSHAKE) — там их
 * видит датапат на проводе, здесь мы читаем ответ сами. Общего заголовка на
 * двоих не заводится нарочно: meas.o линкуется в тесты и утилиты, где link.o
 * нет вовсе (см. core/Makefile), а ради двух констант тащить туда связь с
 * датапатом незачем. Запись по версии не фильтруется: в поле версии
 * ServerHello ставят и 0x0301, и 0x0303 независимо от того, о чём
 * договорились (RFC 8446 §4.1.3), — проверяется старший байт 0x03, общий у
 * всех живых версий. */
#define TLS_REC_ALERT      0x15
#define TLS_REC_HANDSHAKE  0x16
#define TLS_HS_SERVER_HELLO 0x02

int d2k_accept_serverhello(const uint8_t *buf, size_t len) {
    /* 5 байт заголовка записи (тип, версия, длина) и первый байт тела —
       тип сообщения рукопожатия. Шесть байт минимум, иначе смотреть не на
       что; дочитывать ради полного разбора незачем — рукопожатие всё равно
       не доводится до конца. */
    return len >= 6 && buf[0] == TLS_REC_HANDSHAKE && buf[1] == 0x03 &&
           buf[5] == TLS_HS_SERVER_HELLO;
}

int d2k_accept_tls_record(const uint8_t *buf, size_t len) {
    return len >= 3 && (buf[0] == TLS_REC_HANDSHAKE || buf[0] == TLS_REC_ALERT) &&
           buf[1] == 0x03;
}

int d2k_accept_any(const uint8_t *buf, size_t len) {
    (void)buf;
    return len > 0;
}

/* Точки разреза обязаны строго возрастать и лежать внутри длины приветствия
 * — контракт описан в d2k_meas.h. Нарушение отклоняется целиком, а не
 * ужимается до похожего валидного подмножества. */
static int cuts_valid(const size_t *cuts, size_t n_cuts, size_t len) {
    size_t prev = 0;
    for (size_t i = 0; i < n_cuts; i++) {
        if (cuts[i] <= prev || cuts[i] >= len) { return 0; }
        prev = cuts[i];
    }
    return 1;
}

/* Дописывает КУСОК целиком. POSIX прямо разрешает send() на блокирующем
 * сокете вернуть меньше запрошенного без единой ошибки — задокументированный
 * исход (типично — как побочный эффект истечения SO_SNDTIMEO при
 * недренирующем приёмнике), а не редкий сбой. Молча продолжать как ни в чём
 * не бывало значило бы отправить не те байты, что просили: часть куска
 * осталась бы в процессе, а провод увидел бы урезанное приветствие. */
static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
#ifdef MSG_NOSIGNAL
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
#else
        ssize_t n = send(fd, buf + sent, len - sent, 0);
#endif
        if (n <= 0) { return -1; }
        sent += (size_t)n;
    }
    return 0;
}

/* Неблокирующий connect с явным потолком (см. CONNECT_TIMEOUT_MS выше).
 * poll() на POLLOUT сигнализирует и успех, и отказ соединения одинаково —
 * различать их обязан getsockopt(SO_ERROR), иначе RST, пришедший вместо
 * SYN-ACK, будет принят за готовность сокета к записи. */
static int connect_bounded(int fd, const struct sockaddr *addr, socklen_t len,
                            uint32_t timeout_ms) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) { return -1; }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { return -1; }

    if (connect(fd, addr, len) == 0) {
        /* Успело сразу — обычный случай на петле. Возвращаем блокирующий
           режим: дальше send/recv рассчитаны на обычную блокирующую
           семантику с таймаутами SO_SNDTIMEO/SO_RCVTIMEO. */
        (void)fcntl(fd, F_SETFL, flags);
        return 0;
    }
    if (errno != EINPROGRESS) { return -1; }

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr <= 0) {
        /* Таймаут или сбой самого poll — соединение не состоялось. */
        return -1;
    }
    int soerr = 0;
    socklen_t soerr_len = sizeof soerr;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &soerr_len) < 0 || soerr != 0) {
        return -1;
    }
    (void)fcntl(fd, F_SETFL, flags);
    return 0;
}

int d2k_meas_once(const char *ip, uint16_t port, d2k_hello h,
                  const size_t *cuts, size_t n_cuts,
                  uint32_t gap_us, uint32_t wait_ms,
                  uint32_t mark, d2k_accept_fn accept, int *marked_out) {
    if (!ip || !h.bytes || h.len == 0) { return D2K_MEAS_ERR; }
    if (n_cuts > 0 && !cuts_valid(cuts, n_cuts, h.len)) { return D2K_MEAS_ERR; }
    if (marked_out) { *marked_out = (mark == 0); }
    if (wait_ms == 0 || wait_ms > WAIT_CEIL_MS) { wait_ms = WAIT_CEIL_MS; }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return D2K_MEAS_ERR; }

    if (mark != 0) {
        if (d2k_mark_hook(fd, mark) == 0) {
            if (marked_out) { *marked_out = 1; }
        }
    }
    int one = 1;
    /* Без этого куски склеятся в один сегмент, и опыт про место разреза
       перестанет быть опытом про место разреза. */
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    /* Та же защита, что у зонда свойств (compose.c): библиотека не имеет
       права убивать вызывающего. Сброс от цели посреди посылки для замера —
       не исключение, а ожидаемый исход: ради него замер и делается. Прогон
       test-meas ловил это SIGPIPE'ом (выход 141) до правки. На Linux того
       же добивается MSG_NOSIGNAL в send_all. */
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif

    struct timeval tv = { (time_t)(wait_ms / 1000u), (suseconds_t)(wait_ms % 1000u) * 1000 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct timeval ctv = { (time_t)d2k_send_timeout_s, 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &ctv, sizeof ctv);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { close(fd); return D2K_MEAS_ERR; }
    if (connect_bounded(fd, (struct sockaddr *)&a, sizeof a, CONNECT_TIMEOUT_MS) != 0) {
        close(fd);
        return D2K_MEAS_ERR;
    }

    size_t prev = 0;
    for (size_t i = 0; i <= n_cuts; i++) {
        size_t end = (i < n_cuts) ? cuts[i] : h.len;
        if (end > h.len) { end = h.len; }
        if (end <= prev) { continue; }
        if (send_all(fd, h.bytes + prev, end - prev) != 0) {
            /* НЕУДАВШАЯСЯ ОТПРАВКА — СБОЙ ОПЫТА, А НЕ РЕШЕНИЕ КОРОБКИ.
               Раньше здесь стоял D2K_MEAS_SILENT, и это выдавало нашу
               собственную неудачу за молчание мишени: воздействие на провод
               целиком не попало, значит опыта не было и сказать про коробку
               нечего (§2.4 — «не измерено» ≠ «нет»).

               Граница проходит ровно здесь: сбой ОТПРАВКИ — опыт не
               состоялся; сброс или тишина ПОСЛЕ того, как приветствие ушло
               целиком, — законное наблюдение «убито» и остаётся
               D2K_MEAS_SILENT ниже. У донора та же разводка: ошибка записи
               возвращается вызывающему ошибкой и никогда не становится
               отрицательным свойством коробки (probePoison →
               classify.go:838-842). */
            close(fd);
            return D2K_MEAS_ERR;
        }
        prev = end;
        if (prev < h.len && gap_us > 0) { nap_us(gap_us); }
    }

    uint8_t buf[512];
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    close(fd);
    if (n <= 0) { return D2K_MEAS_SILENT; }
    /* Приёмки нет — годится любой непустой ответ (см. d2k_meas.h про NULL).
       Есть — решает она, и её отказ НЕ выдаётся за молчание: ответ был. */
    if (accept && !accept(buf, (size_t)n)) { return D2K_MEAS_UNPROVEN; }
    return D2K_MEAS_PASS;
}

d2k_tally d2k_meas(const char *ip, uint16_t port, d2k_hello h,
                   const size_t *cuts, size_t n_cuts,
                   uint32_t gap_us, uint32_t wait_ms,
                   uint32_t mark, d2k_accept_fn accept, int repeats) {
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    if (repeats <= 0) { repeats = 3; }
    for (int i = 0; i < repeats; i++) {
        int marked = 0;
        int r = d2k_meas_once(ip, port, h, cuts, n_cuts, gap_us, wait_ms, mark,
                              accept, &marked);
        /* Метка серии — И по всем дозвонам: один непомеченный делает серию
           непомеченной. */
        if (!marked) { t.marked = 0; }
        if (r == D2K_MEAS_ERR) { t.err++; t.fail++; continue; }
        if (r == D2K_MEAS_PASS) { t.pass++; continue; }
        /* Не прошло. ЧЕМ именно не прошло — вопрос отдельный: непризнанный
           ответ и тишина ложатся в один fail, но unproven помнит, что ответ
           был (см. d2k_meas.h). */
        if (r == D2K_MEAS_UNPROVEN) { t.unproven++; }
        t.fail++;
    }
    return t;
}
