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
   обходит движок, и вердикт будет про чужой поток. */
static const struct { uint16_t lo, hi; } voice_ports[] = {
    { 50000, 50100 },
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

        size_t i = 0;
        for (; i < n; i++) {
            if (out[i].ip == ip && out[i].port == (uint16_t)dport) {
                out[i].packets += (int)packets;
                out[i].replied |= replied;
                break;
            }
        }
        if (i == n && n < cap) {
            out[n].ip = ip;
            out[n].port = (uint16_t)dport;
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

/* ЖИВ ЛИ ПОТОК К ЭТОЙ ТОЧКЕ — два снимка счётчика пакетов из той же таблицы,
   откуда берётся цель. Второго источника не заводим: расхождение двух
   источников про один поток было бы хуже отсутствия второго.

   Пауза короткая: голос идёт непрерывно (замер 17.09 — пакет каждые 20 мс),
   и четверти секунды хватает, чтобы счётчик сдвинулся. -1 — потока не видно
   или таблицы нет: опровергать молчание нечем, и выдумывать нечего. */
static int voice_alive(const char *ct_path, uint32_t ip, uint16_t port) {
    d2k_voice_target t[D2K_VOICE_MAX_TARGETS];
    size_t n = d2k_voice_targets(ct_path, t, D2K_VOICE_MAX_TARGETS);
    for (size_t i = 0; i < n; i++) {
        if (t[i].ip == ip && t[i].port == port) { return t[i].replied ? 1 : 0; }
    }
    return -1; /* потоков к этой точке не видно — опровергать молчание нечем */
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

/* ФАЛЬШИВКИ БОЕВОГО ПРОФИЛЯ discord_udp, В ПОРЯДКЕ ПРОВЕРКИ. Имена — те же,
   что в строке стратегии: мерить одним файлом, а рекомендовать другой значило
   бы выдать человеку приём, который он не сможет применить. */
static const struct { const char *name, *file; } voice_blobs[] = {
    { "active_discord_udp", "active_discord_udp.bin" },
    { "stun", "stun.bin" },
    { "quic_dbankcloud", "quic_initial_dbankcloud_ru.bin" }
};

/* ЛЕСТНИЦА КОПИЙ — ДВЕ ТОЧКИ ОРИГИНАЛА: одна копия могла потеряться, а могла
   и не хватить коробке. Это точечные числа из замера, а не диапазон перебора
   (§"мерить, а не перебирать"). */
static const int voice_copies[] = { 1, 6 };

static size_t load_blob(const char *dir, const char *file, uint8_t *out, size_t cap) {
    char path[512];
    if (snprintf(path, sizeof path, "%s/%s", dir, file) < 0) { return 0; }
    FILE *f = fopen(path, "rb");
    if (!f) { return 0; }
    size_t n = fread(out, 1, cap, f);
    fclose(f);
    /* Короче шестнадцати байт — это не фальшивка, а обрывок: слать его
       значило бы мерить мусор и назвать исход свойством коробки. */
    return (n >= 16) ? n : 0;
}

static void ask_voice_arms(d2k_voice_res *r, const d2k_voice_opt *o, uint32_t wait_ms) {
    const char *dir = o->blob_dir ? o->blob_dir : "/opt/zapret2/files/fake";
    uint8_t blob[4096];
    int had_file = 0;

    for (size_t b = 0; b < sizeof voice_blobs / sizeof voice_blobs[0]; b++) {
        size_t blen = load_blob(dir, voice_blobs[b].file, blob, sizeof blob);
        if (blen == 0) { continue; }
        had_file = 1;
        for (size_t c = 0; c < sizeof voice_copies / sizeof voice_copies[0]; c++) {
            d2k_tally t = d2k_voice_ask_hook(r->ip, r->port, blob, blen, voice_copies[c],
                                             wait_ms, o->mark, D2K_VOICE_REPEATS, NULL);
            r->probes += D2K_VOICE_REPEATS - t.err; /* ушедшее на провод, не запрошенное */
            if (!t.marked) { r->marked = 0; }
            if (t.pass != D2K_VOICE_REPEATS) { continue; }
            /* ЧИСЛО КОПИЙ — ТО, КОТОРЫМ ПРИЁМ ВЗЯЛ, но не меньше двух:
               одиночная датаграмма на живом канале теряется, и приём,
               подтверждённый одной копией, на проводе надо ставить с запасом
               (то же решение у оригинала, questions.go: max(n, 2)). */
            int n = voice_copies[c] > 2 ? voice_copies[c] : 2;
            snprintf(r->arm, sizeof r->arm, "%s:repeats=%d", voice_blobs[b].name, n);
            snprintf(r->strategy, sizeof r->strategy,
                     "--lua-desync=fake:payload=all:blob=%s:repeats=%d",
                     voice_blobs[b].name, n);
            add_reason(r, "; приём: %s", r->arm);
            return;
        }
    }
    if (!had_file) {
        /* НЕ ИЗМЕРЕНО — НЕ «НЕ ПОМОГЛО». Отсутствие файлов это про запуск (не
           на роутере), а не про коробку, и склеить их значило бы выдать
           собственную нехватку за факт. */
        add_reason(r, "; приёмы НЕ ИЗМЕРЕНЫ: нет ни одного файла блоба в %s", dir);
        return;
    }
    add_reason(r, "; ни одна фальшивка не пробивает");
}

d2k_voice_res d2k_voice_run(const d2k_voice_opt *opt) {
    d2k_voice_opt o;
    memset(&o, 0, sizeof o);
    if (opt) { o = *opt; }

    d2k_voice_res r;
    memset(&r, 0, sizeof r);
    r.marked = 1;

    uint32_t wait_ms = o.wait_ms ? o.wait_ms : VOICE_WAIT_DEFAULT_MS;

    /* ЦЕЛЬ. Адрес задан — берём его; нет — ищем живой разговор. Выдумать
       голосовой цели домен и померить его нельзя (D2K_SPEC): это померило бы
       другую цель и назвало чужой результат её именем. */
    r.ip = o.ip;
    r.port = o.port;
    if (r.ip == 0 || r.port == 0) {
        d2k_voice_target t[D2K_VOICE_MAX_TARGETS];
        size_t n = d2k_voice_targets(o.ct_path, t, D2K_VOICE_MAX_TARGETS);
        if (n == 0) {
            r.verdict = D2K_VOICE_NO_CALL;
            say_reason(&r, "живого разговора не видно. Начните звонок и повторите замер: "
                           "у голоса нет имени, которое можно вписать, и адрес берётся из "
                           "идущего разговора");
            return r;
        }
        r.ip = t[0].ip;
        r.port = t[0].port;
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
    int obs = d2k_voice_alive_hook(o.ct_path, r.ip, r.port);
    if (obs == 1) {
        r.verdict = D2K_VOICE_CLEAR;
        say_reason(&r, "разговор с %s:%u идёт, и сервер по нему отвечает", addr, r.port);
        return r;
    }
    if (obs == 0) {
        /* Поток без единого ответа. Контроль нужен ровно затем, чтобы
           отделить «режут этот поток» от «UDP не ходит вовсе». */
        uint32_t cip0 = 0;
        uint16_t cport0 = 0;
        const char *ctl0 = o.control ? o.control : D2K_VOICE_CONTROL_DEFAULT;
        int ctl_ok = 0, asked0 = 0;
        if (d2k_voice_resolve_hook(ctl0, &cip0, &cport0) == 0) {
            d2k_tally c0 = d2k_voice_ask_hook(cip0, cport0, NULL, 0, 0, wait_ms, o.mark,
                                              D2K_VOICE_REPEATS, NULL);
            r.probes += D2K_VOICE_REPEATS - c0.err;
            if (!c0.marked) { r.marked = 0; }
            asked0 = 1;
            ctl_ok = (c0.pass > 0);
        }
        if (asked0 && !ctl_ok) {
            r.verdict = D2K_VOICE_NO_UDP;
            say_reason(&r, "поток к %s:%u идёт без единого ответа, и публичный STUN %s тоже "
                           "молчит: на этом канале не ходит UDP или его режут целиком — "
                           "обходить голос отдельно бессмысленно", addr, r.port, ctl0);
        } else {
            r.verdict = D2K_VOICE_BLOCKED;
            if (asked0) {
                say_reason(&r, "поток к %s:%u идёт, а ответов нет НИ ОДНОГО, при живом "
                               "публичном STUN: режут именно этот поток", addr, r.port);
            } else {
                say_reason(&r, "поток к %s:%u идёт без единого ответа; контроль НЕ СПРОШЕН "
                               "(имя %s не разрешилось) — «UDP не ходит» не исключено",
                           addr, r.port, ctl0);
            }
            ask_voice_arms(&r, &o, wait_ms);
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
