/* voice.c — контракт и все обоснования в d2k_voice.h. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"
#include "d2k_net4.h"
#include "d2k_stun.h"
#include "d2k_voice.h"

/* --- цель из живого разговора ------------------------------------------- */

/* ПОРТЫ ГОЛОСА — ТЕ ЖЕ, ЧТО В БОЕВОМ ПРОФИЛЕ (lib/config_official.sh,
   discord_udp). Разъедутся — зонд начнёт мерить не тот трафик, который
   обходит движок, и вердикт будет про чужой поток.

   Верхняя граница медиапортов — 50099, как у профиля и у эталонного
   50-discord-media bol-van (DISCORD_MEDIA_PORT_RANGE). Здесь стояло 50100, а
   карта переноса уверяла, что диапазоны совпадают. */
static const struct { uint16_t lo, hi; } voice_ports[] = {
    { 50000, 50099 },
    { 1400, 1400 },
    { 3478, 3481 },
    { 5349, 5349 },
    { 19294, 19344 }
};

static int is_voice_port(unsigned p) {
    for (size_t i = 0; i < sizeof voice_ports / sizeof voice_ports[0]; i++) {
        if (p >= voice_ports[i].lo && p <= voice_ports[i].hi) { return 1; }
    }
    return 0;
}

/* ВТОРОЙ ЧИТАТЕЛЬ CONNTRACK В ПРОЕКТЕ, И ЭТО ОСОЗНАННО.
 *
 * Первый — datapath/nat.c, он спрашивает про ОДИН известный поток («каким
 * адресом нас видит сервер»). Здесь запрос обратный: перебрать все и выбрать
 * подходящие. Общего у них не функция, а ДИСЦИПЛИНА разбора, и она повторена
 * дословно: порядок полей в строке зависит от версии ядра и включённых
 * расширений, опираться на позицию нельзя — только на имена; и имя обязано
 * начинаться на границе слова, иначе `dport=` найдётся внутри `sport=`.
 * Одной функцией их не сделать, не связав датапат с ядром: датапат обязан
 * собираться сам по себе (см. его Makefile).
 *
 * ГОНКА ЧТЕНИЯ ЗДЕСЬ НЕ СМЕРТЕЛЬНА, в отличие от nat.c. Там пропущенная
 * строка означала отказ применить готовый план (разобрано 17.09,
 * docs/field/2026-09-17-conntrack-race.md); здесь — что один из разговоров не
 * попал в список. Если разговор идёт, он попадёт со следующего замера, а
 * выдумывать вместо него нечего. */
static const char *field_val(char *line, const char *name, char **next, char *endbuf) {
    size_t nl = strlen(name);
    char *p = line;
    while ((p = strstr(p, name)) != NULL) {
        if (p != line && p[-1] != ' ') { p += nl; continue; }
        if (p[nl] != '=') { p += nl; continue; }
        char *v = p + nl + 1;
        char *e = v;
        while (*e && *e != ' ' && *e != '\n' && *e != '\t') { e++; }
        size_t len = (size_t)(e - v);
        if (len >= 64) { return NULL; }
        memcpy(endbuf, v, len);
        endbuf[len] = '\0';
        *next = (*e == '\0') ? e : e + 1;
        return endbuf;
    }
    return NULL;
}

size_t d2k_voice_targets(const char *path, d2k_voice_target *out, size_t cap) {
    if (!out || cap == 0) { return 0; }
    FILE *f = fopen(path ? path : "/proc/net/nf_conntrack", "r");
    if (!f) { return 0; }

    size_t n = 0;
    char line[2048];
    while (fgets(line, sizeof line, f)) {
        if (!strstr(line, "udp")) { continue; }

        /* БЕРЁМ ПЕРВЫЕ dst/dport: они относятся к ПРЯМОМУ кортежу, то есть к
           тому, куда шлёт клиент. Вторые — обратный кортеж, это мы сами. */
        char buf[64];
        char *next = NULL;
        const char *v = field_val(line, "dst", &next, buf);
        uint32_t ip = 0;
        if (!v || d2k_ip4_parse(v, &ip) != 0) { continue; }
        /* Голос идёт НАРУЖУ: приватный адрес назначения — это чужой NAT или
           наш же редирект по хостлисту, и коробка провайдера там ни при чём. */
        if (d2k_ip4_private(ip)) { continue; }

        char pbuf[64];
        v = field_val(line, "dport", &next, pbuf);
        if (!v) { continue; }
        unsigned long dport = strtoul(v, NULL, 10);
        if (dport == 0 || dport > 65535 || !is_voice_port((unsigned)dport)) { continue; }

        char kbuf[64];
        v = field_val(line, "packets", &next, kbuf);
        long packets = v ? strtol(v, NULL, 10) : 0;
        /* Пометку ставит ядро, пока ОБРАТНОГО трафика по потоку не было
           (RFC-ничего, это состояние conntrack). Её отсутствие и значит
           «точка кому-то отвечает» — см. d2k_voice_target.replied про то,
           почему признак надёжнее счётчика на этом роутере. */
        int replied = (strstr(line, "[UNREPLIED]") == NULL);

        /* ПОТОК — ПЯТЁРКА, А НЕ АДРЕС СЕРВЕРА. Записи разных клиентов к одной
           точке раньше складывались, и признак «отвечает» брался ИЛИ по всем:
           ответ одному клиенту объявлял живым поток другого. Теперь каждый
           поток отдельной строкой; складываются только записи ОДНОГО потока
           (conntrack держит их раздельно по направлению). */
        char sbuf[64], spbuf[64];
        char *next2 = NULL;
        const char *sv = field_val(line, "src", &next2, sbuf);
        uint32_t src_ip = 0;
        if (!sv || d2k_ip4_parse(sv, &src_ip) != 0) { continue; }
        next2 = NULL;
        sv = field_val(line, "sport", &next2, spbuf);
        unsigned long sport = sv ? strtoul(sv, NULL, 10) : 0;

        size_t i = 0;
        for (; i < n; i++) {
            if (out[i].ip == ip && out[i].port == (uint16_t)dport &&
                out[i].src_ip == src_ip && out[i].sport == (uint16_t)sport) {
                out[i].packets += (int)packets;
                out[i].replied |= replied;
                break;
            }
        }
        if (i == n && n < cap) {
            out[n].ip = ip;
            out[n].port = (uint16_t)dport;
            out[n].src_ip = src_ip;
            out[n].sport = (uint16_t)sport;
            out[n].packets = (int)packets;
            out[n].replied = replied;
            n++;
        }
    }
    fclose(f);

    /* По убыванию пакетов: первым обязан идти тот разговор, который человек
       прямо сейчас и ведёт. Вставками — список не длиннее восьми. */
    for (size_t i = 1; i < n; i++) {
        d2k_voice_target t = out[i];
        size_t j = i;
        while (j > 0 && out[j - 1].packets < t.packets) {
            out[j] = out[j - 1];
            j--;
        }
        out[j] = t;
    }
    return n;
}

/* --- настоящий оракул ---------------------------------------------------- */

#define VOICE_WAIT_DEFAULT_MS 3000

static int send_one(uint32_t ip, uint16_t port, const uint8_t *pre, size_t pre_len,
                    int copies, uint32_t mark, uint8_t txid[D2K_STUN_TXID_LEN],
                    int *marked) {
    *marked = (mark == 0);
    uint8_t req[D2K_STUN_HDR_LEN];
    if (d2k_stun_request(req, sizeof req, txid) == 0) { return -1; }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { return -1; }
    if (mark != 0 && d2k_mark_hook(fd, mark) == 0) { *marked = 1; }

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    memcpy(&a.sin_addr.s_addr, &ip, 4);
    /* «Подключенный» UDP — не ради семантики соединения (её у UDP нет), а
       чтобы ICMP-отказ дошёл до нас ошибкой, а не неотличимой тишиной. */
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    /* КОПИЙ СТОЛЬКО, СКОЛЬКО ПРОСИЛИ, И КАЖДАЯ — СВОЯ ДАТАГРАММА: коробка
       считает датаграммы, и одна длинная из склеенных копий измеряла бы не то. */
    if (pre && pre_len > 0) {
        for (int c = 0; c < (copies > 0 ? copies : 1); c++) {
            if (send(fd, pre, pre_len, 0) < 0) {
                close(fd);
                return -1;
            }
        }
    }
    if (send(fd, req, sizeof req, 0) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static long ms_since(const struct timespec *t0) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - t0->tv_sec) * 1000 + (now.tv_nsec - t0->tv_nsec) / 1000000;
}

/* Серия из repeats ПАРАЛЛЕЛЬНЫХ зондов: сперва все уходят, потом ждём разом.
   Каждый — свой сокет и свой идентификатор транзакции: чужой ответ не должен
   сойти за наш (см. d2k_stun.h). */
static d2k_tally voice_ask(uint32_t ip, uint16_t port, const uint8_t *pre, size_t pre_len,
                           int copies, uint32_t wait_ms, uint32_t mark, int repeats,
                           uint32_t *rtt_ms_out) {
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    if (repeats <= 0 || repeats > D2K_VOICE_MAX_REPEATS) { repeats = D2K_VOICE_REPEATS; }
    if (wait_ms == 0) { wait_ms = VOICE_WAIT_DEFAULT_MS; }
    if (rtt_ms_out) { *rtt_ms_out = 0; }

    int fds[D2K_VOICE_MAX_REPEATS];
    uint8_t txid[D2K_VOICE_MAX_REPEATS][D2K_STUN_TXID_LEN];
    int done[D2K_VOICE_MAX_REPEATS];
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int pending = 0;
    for (int i = 0; i < repeats; i++) {
        int marked = 1;
        fds[i] = send_one(ip, port, pre, pre_len, copies, mark, txid[i], &marked);
        if (!marked) { t.marked = 0; }
        done[i] = (fds[i] < 0);
        if (done[i]) {
            t.err++;
            t.fail++;
        } else {
            pending++;
        }
    }

    while (pending > 0) {
        long left = (long)wait_ms - ms_since(&t0);
        if (left <= 0) { break; }
        struct pollfd pfd[D2K_VOICE_MAX_REPEATS];
        int idx[D2K_VOICE_MAX_REPEATS];
        int np = 0;
        for (int i = 0; i < repeats; i++) {
            if (done[i]) { continue; }
            pfd[np].fd = fds[i];
            pfd[np].events = POLLIN;
            pfd[np].revents = 0;
            idx[np] = i;
            np++;
        }
        if (np == 0) { break; }
        int rc = poll(pfd, (nfds_t)np, (int)left);
        if (rc <= 0) { break; }
        for (int k = 0; k < np; k++) {
            int i = idx[k];
            if (!(pfd[k].revents & (POLLIN | POLLERR | POLLHUP))) { continue; }
            uint8_t buf[1500];
            ssize_t n = recv(fds[i], buf, sizeof buf, 0);
            if (n <= 0) {
                /* Явный сетевой отказ (ICMP «порт недоступен») — это ответ
                   сети, а не наша ошибка: fail, не err. */
                done[i] = 1;
                pending--;
                t.fail++;
                continue;
            }
            uint8_t seen_ip[16];
            int family = 0;
            uint16_t seen_port = 0;
            if (d2k_stun_parse_response(buf, (size_t)n, txid[i], seen_ip, &family, &seen_port) == 0) {
                done[i] = 1;
                pending--;
                t.pass++;
                if (rtt_ms_out) {
                    long ms = ms_since(&t0);
                    if (*rtt_ms_out == 0 || (uint32_t)ms < *rtt_ms_out) {
                        *rtt_ms_out = (uint32_t)(ms > 0 ? ms : 1);
                    }
                }
            }
            /* Не наш ответ — не закрываем зонд: на порт мог прилететь чужой
               пакет, а настоящий ответ ещё в пути. */
        }
    }
    for (int i = 0; i < repeats; i++) {
        if (!done[i]) { t.fail++; }
        if (fds[i] >= 0) { close(fds[i]); }
    }
    return t;
}

static int voice_resolve(const char *hostport, uint32_t *ip, uint16_t *port) {
    if (!hostport || !ip || !port) { return -1; }
    const char *colon = strrchr(hostport, ':');
    if (!colon || colon == hostport) { return -1; }
    char host[256];
    size_t hl = (size_t)(colon - hostport);
    if (hl >= sizeof host) { return -1; }
    memcpy(host, hostport, hl);
    host[hl] = '\0';
    unsigned long p = strtoul(colon + 1, NULL, 10);
    if (p == 0 || p > 65535) { return -1; }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) { return -1; }
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    memcpy(ip, &sa->sin_addr.s_addr, 4);
    freeaddrinfo(res);
    *port = (uint16_t)p;
    return 0;
}

/* ОТВЕЧАЕТ ЛИ ТОЧКА ЭТОМУ ПОТОКУ — по пометке [UNREPLIED] из той же таблицы,
   откуда берётся цель (контракт и ответы — в d2k_voice.h).

   Признак, а не счётчик: голосовой поток уходит в железо ([FASTNAT]), и
   conntrack перестаёт считать (замер 17.09: 5593, 5593, 5593, 5594 за три
   секунды разговора). Счётчик ИСХОДЯЩИХ при этом годится для порога
   «молчат»: первые пакеты ядро считает до того, как поток уйдёт в железо. */
static int voice_alive(const char *ct_path, uint32_t ip, uint16_t port,
                       uint32_t src_ip, uint16_t sport) {
    d2k_voice_target t[D2K_VOICE_MAX_TARGETS];
    size_t n = d2k_voice_targets(ct_path, t, D2K_VOICE_MAX_TARGETS);
    for (size_t i = 0; i < n; i++) {
        if (t[i].ip != ip || t[i].port != port) { continue; }
        if (src_ip != 0 && (t[i].src_ip != src_ip || t[i].sport != sport)) { continue; }
        if (t[i].replied) { return D2K_VOICE_ANSWERS; }
        return t[i].packets >= D2K_VOICE_SILENT_AFTER ? D2K_VOICE_SILENT : D2K_VOICE_YOUNG;
    }
    return D2K_VOICE_UNSEEN;
}

d2k_voice_ask_fn d2k_voice_ask_hook = voice_ask;
d2k_voice_alive_fn d2k_voice_alive_hook = voice_alive;

d2k_voice_ask_fn voice_ask_real(void) { return voice_ask; }
d2k_voice_resolve_fn d2k_voice_resolve_hook = voice_resolve;

/* --- прогон -------------------------------------------------------------- */

static void say_reason(d2k_voice_res *r, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(r->reason, sizeof r->reason, fmt, ap);
    va_end(ap);
}

static void add_reason(d2k_voice_res *r, const char *fmt, ...) {
    size_t used = strlen(r->reason);
    if (used + 1 >= sizeof r->reason) { return; }
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(r->reason + used, sizeof r->reason - used, fmt, ap);
    va_end(ap);
}

/* ПОЧЕМУ ЗДЕСЬ НЕТ ПОДБОРА ПРИЁМА.
 *
 * Он был: лестница фальшивок боевого профиля, испытываемая зондом STUN. Поле
 * 17.09.2026 показало, что этот зонд оракулом быть не может — голосовая точка
 * Дискорда молчит на STUN, на нули и на мусор одинаково при ЖИВОМ разговоре.
 * Значит молчание зонда С приманкой доказывает ровно столько же, сколько без
 * неё, то есть ничего, а вывод «ни одна фальшивка не пробивает» был выводом
 * из непригодного измерения.
 *
 * Подтверждать приём надо НА САМОМ РАЗГОВОРЕ: применить воздействие к его
 * потоку через датапат и посмотреть, пошли ли по нему ответы (пометка
 * [UNREPLIED] снимается). Это работа датапата, а не зонда, и её ещё нет.
 * Держать вместо неё лестницу, которая ничего не меряет, хуже, чем не держать
 * ничего: она выглядела бы измерением. */

d2k_voice_res d2k_voice_run(const d2k_voice_opt *opt) {
    d2k_voice_opt o;
    memset(&o, 0, sizeof o);
    if (opt) { o = *opt; }

    d2k_voice_res r;
    memset(&r, 0, sizeof r);
    r.marked = 1;

    uint32_t wait_ms = o.wait_ms ? o.wait_ms : VOICE_WAIT_DEFAULT_MS;

    /* КОНТРОЛЬ — ЗАРАНЕЕ, И НЕ ТОЛЬКО РАДИ КОНТРОЛЯ. Его адрес нужен ещё и
       поиску цели: зонд контроля ходит на 3478, а 3478 входит в голосовые
       порты профиля. Его поток ложится в таблицу соединений рядом с
       разговором и живёт там до трёх минут, и взять его целью значило бы
       мерить самих себя. */
    const char *ctl = o.control ? o.control : D2K_VOICE_CONTROL_DEFAULT;
    uint32_t cip = 0;
    uint16_t cport = 0;
    int ctl_resolved = (d2k_voice_resolve_hook(ctl, &cip, &cport) == 0);

    /* ЦЕЛЬ — ПОТОК, А НЕ ТОЧКА. Адрес задан — ищем самый нагруженный поток к
       нему; нет — самый нагруженный разговор вообще. Выдумать голосовой цели
       домен и померить его нельзя (D2K_SPEC): это померило бы другую цель и
       назвало чужой результат её именем. */
    d2k_voice_target t[D2K_VOICE_MAX_TARGETS];
    size_t n = d2k_voice_targets(o.ct_path, t, D2K_VOICE_MAX_TARGETS);
    const d2k_voice_target *flow = NULL;
    for (size_t i = 0; i < n && !flow; i++) {
        if (ctl_resolved && t[i].ip == cip) { continue; }   /* свой же контроль */
        if (o.ip && o.port && (t[i].ip != o.ip || t[i].port != o.port)) { continue; }
        flow = &t[i];
    }
    r.ip = o.ip;
    r.port = o.port;
    if (r.ip == 0 || r.port == 0) {
        if (!flow) {
            r.verdict = D2K_VOICE_NO_CALL;
            say_reason(&r, "живого разговора не видно. Начните звонок и повторите замер: "
                           "у голоса нет имени, которое можно вписать, и адрес берётся из "
                           "идущего разговора");
            return r;
        }
        r.ip = flow->ip;
        r.port = flow->port;
    }

    char addr[24];
    d2k_ip4_text(r.ip, addr, sizeof addr);

    /* ===== СЛОЙ 0: ОТВЕЧАЕТ ЛИ ТОЧКА НАСТОЯЩЕМУ КЛИЕНТУ =====
     *
     * ГЛАВНЫЙ ОРАКУЛ, И ОН НАБЛЮДАТЕЛЬНЫЙ, А НЕ ЗОНДОВЫЙ. Поле 17.09.2026
     * доказало прямым замером, что зонд оракулом быть НЕ МОЖЕТ: голосовая
     * точка Дискорда молчит на STUN, на нули и на мусор одинаково — при живом
     * разговоре через тот же адрес. Она обслуживает только установленную
     * сессию, по SSRC от гейтвея.
     *
     * Зато ядро видит, идёт ли ОБРАТНЫЙ трафик по потоку настоящего клиента
     * (пометка [UNREPLIED]). Это ответ про ТОТ САМЫЙ поток, который надо
     * пробить, а не про наш зонд, и получается он бесплатно — данные уже
     * прочитаны при поиске цели.
     *
     * 1 — отвечает: резать нечего, и ни одного зонда слать не надо.
     * 0 — поток идёт, ответов нет: вот это и есть блокировка потока.
     * -1 — наблюдать нечего (задан явный адрес, таблицы нет): тогда и только
     *      тогда работает старый зондовый путь, со своей оговоркой. */
    int obs = d2k_voice_alive_hook(o.ct_path, r.ip, r.port,
                                   flow ? flow->src_ip : 0, flow ? flow->sport : 0);
    if (obs == D2K_VOICE_YOUNG) {
        /* РАНО СУДИТЬ. Ответа нет, но и ушло меньше, чем боевой профиль
           требует для признания провала (udp_out=4): ответ мог просто не
           успеть. Это «мало данных», а не блокировка. */
        r.verdict = D2K_VOICE_UNMEASURED;
        say_reason(&r, "поток к %s:%u без ответа, но ушло %d из %d пакетов, после которых "
                       "молчание что-то значит — рано судить, повторите замер через "
                       "несколько секунд разговора",
                   addr, r.port, flow ? flow->packets : 0, D2K_VOICE_SILENT_AFTER);
        return r;
    }
    if (obs == D2K_VOICE_ANSWERS) {
        r.verdict = D2K_VOICE_CLEAR;
        say_reason(&r, "разговор с %s:%u идёт, и сервер по нему отвечает", addr, r.port);
        return r;
    }
    if (obs == D2K_VOICE_SILENT) {
        /* Поток без единого ответа. Контроль нужен ровно затем, чтобы
           отделить «режут этот поток» от «UDP не ходит вовсе». */
        const char *ctl0 = ctl;
        int ctl_ok = 0, asked0 = 0;
        if (ctl_resolved) {
            d2k_tally c0 = d2k_voice_ask_hook(cip, cport, NULL, 0, 0, wait_ms, o.mark,
                                              D2K_VOICE_REPEATS, NULL);
            r.probes += D2K_VOICE_REPEATS - c0.err;
            if (!c0.marked) { r.marked = 0; }
            asked0 = 1;
            ctl_ok = (c0.pass > 0);
        }
        if (!asked0) {
            /* КОНТРОЛЬ НЕ СПРОШЕН — ВЫБОРА МЕЖДУ ДВУМЯ ОБЪЯСНЕНИЯМИ НЕТ.
               «Режут этот поток» и «UDP не ходит вовсе» различает только он.
               Объявлять первое вердиктом, потому что второе не проверено, —
               вывод из недостачи данных (ревью, P1-3). Приёмы тем более не
               подбираем: подбирать не к чему. */
            r.verdict = D2K_VOICE_UNMEASURED;
            say_reason(&r, "поток к %s:%u идёт без единого ответа, но контроль НЕ СПРОШЕН "
                           "(имя %s не разрешилось): отделить «режут этот поток» от «UDP не "
                           "ходит вовсе» нечем — измерение не закончено", addr, r.port, ctl0);
        } else if (!ctl_ok) {
            r.verdict = D2K_VOICE_NO_UDP;
            say_reason(&r, "поток к %s:%u идёт без единого ответа, и публичный STUN %s тоже "
                           "молчит: на этом канале не ходит UDP или его режут целиком — "
                           "обходить голос отдельно бессмысленно", addr, r.port, ctl0);
        } else {
            r.verdict = D2K_VOICE_BLOCKED;
            say_reason(&r, "поток к %s:%u идёт, а ответов нет НИ ОДНОГО, при живом "
                           "публичном STUN: режут именно этот поток", addr, r.port);
            /* ПРИЁМЫ ЗДЕСЬ НЕ ИСПЫТЫВАЮТСЯ, И ЭТО НЕ ПРОБЕЛ, А ЧЕСТНОСТЬ.
               Базовый оракул заменён наблюдением разговора именно потому, что
               голосовая точка не отвечает посторонним (поле 17.09: молчит на
               STUN, на нули и на мусор одинаково при живом разговоре).
               Испытывать приманки тем же отвергнутым зондом и делать вывод
               «не пробивает» значило бы повторить ту же ошибку на шаг позже:
               молчание зонда с приманкой доказывает ровно столько же, сколько
               без неё, то есть ничего.
               Подтверждать приём надо НА САМОМ РАЗГОВОРЕ — применив
               воздействие к его потоку и посмотрев, пошли ли ответы. Этого
               сегодня нет, и вместо вывода стоит причина, по которой его
               нет. */
            add_reason(&r, "; приём не подтвердить: голосовая точка не отвечает "
                           "посторонним, а воздействие на сам разговор не применяется");
        }
        if (!r.marked) {
            add_reason(&r, "; СОКЕТ НЕ ПОМЕЧЕН — зонд шёл через наш же обход");
        }
        return r;
    }

    /* ===== НАБЛЮДАТЬ НЕЧЕГО: ОСТАЁТСЯ ЗОНД, И ОН ПОЧТИ НИЧЕГО НЕ ДОКАЗЫВАЕТ =====
     *
     * Сюда попадают только два случая: адрес задан вручную на машине без
     * таблицы соединений, либо потока к этой точке ядро не видит вовсе.
     *
     * ПОЛОЖИТЕЛЬНЫЙ исход зонда по-прежнему информативен: ответил — значит
     * точка достижима и отвечает посторонним (так ведут себя настоящие
     * серверы STUN). ОТРИЦАТЕЛЬНЫЙ не значит ничего: голосовая точка Дискорда
     * молчит и на исправной линии (поле 17.09). Выдавать это молчание за
     * блокировку — ровно та ложь, которую поле и вскрыло. */
    uint32_t rtt = 0;
    d2k_tally direct = d2k_voice_ask_hook(r.ip, r.port, NULL, 0, 0, wait_ms, o.mark,
                                          D2K_VOICE_REPEATS, &rtt);
    r.probes += D2K_VOICE_REPEATS - direct.err;
    if (!direct.marked) { r.marked = 0; }

    if (direct.pass == D2K_VOICE_REPEATS) {
        r.verdict = D2K_VOICE_CLEAR;
        say_reason(&r, "точка %s:%u отвечает на зонд (%d/%d за %u мс) — резать нечего",
                   addr, r.port, direct.pass, D2K_VOICE_REPEATS, rtt);
    } else if (direct.pass > 0) {
        r.verdict = D2K_VOICE_FLAKY;
        say_reason(&r, "ответов %d из %d — не воспроизводится, вердикт выносить нельзя",
                   direct.pass, D2K_VOICE_REPEATS);
    } else {
        r.verdict = D2K_VOICE_NO_ORACLE;
        say_reason(&r, "зонд к %s:%u молчит (0/%d), а разговора к этой точке ядро не видит — "
                       "опровергнуть молчание нечем. Голосовая точка не отвечает посторонним "
                       "и на исправной линии, поэтому её молчание блокировкой НЕ является: "
                       "мерить этим способом нечем",
                   addr, r.port, D2K_VOICE_REPEATS);
    }

    if (!r.marked) {
        add_reason(&r, "; СОКЕТ НЕ ПОМЕЧЕН — зонд шёл через наш же обход, замер не про "
                       "коробку провайдера");
    }
    return r;
}
