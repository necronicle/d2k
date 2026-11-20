/* Файл включают и как текст в составные тесты — после системных заголовков,
   где glibc (с 2026) уже задал _POSIX_C_SOURCE сам: голый #define там —
   переопределение под -Werror (CI 22.10.2026). Отдельной единицей трансляции
   значение задаётся как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
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
#include "d2k_arm.h"
#include "d2k_compose.h"
#include "d2k_plantlv.h"
#include "d2k_wire.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* ПРАВИЛО ПОДАВЛЕНИЯ RST: РАЗБОР И ВЛАДЕЛЕЦ.
 *
 * Разбор — чистая работа со строкой, и он обязан проверяться на любой машине,
 * а не только там, где есть iptables (так же вынесен в эталоне: raw_rules.go
 * отдельно от raw_linux.go). Форма нормализована самим iptables (проверено на
 * роутере, v1.4.21). Сверяем её ЦЕЛИКОМ, началом и концом: частичный разбор
 * уже прострелил — правило с чужим действием (-j ACCEPT) принималось за своё.
 *
 * ЗАДАЧА 49: ПРАВИЛО НЕСЁТ PID ВЛАДЕЛЬЦА (-m comment --comment d2k-rst:PID).
 * Без него уборка при старте любого процесса-измерителя снимала и правило
 * живого зонда d2kc (поле 03.10: запуск d2k-detect рядом с d2kc снял три
 * правила d2kc). Старое правило без пометки — от прежней версии, владельца
 * у него нет, и оно по-прежнему считается брошенным. */
static const char RST_PREFIX[] = "-A OUTPUT -p tcp -m tcp --sport ";
static const char RST_LEGACY_SUFFIX[] = " --tcp-flags RST RST -j DROP";
static const char RST_OWNED_MID[] = " --tcp-flags RST RST -m comment --comment ";
static const char RST_OWNED_TAG[] = "d2k-rst:";
static const char RST_OWNED_SUFFIX[] = " -j DROP";

static int parse_long_exact(const char *from, size_t len, long *out)
{
    char buf[32];
    char *end;
    long v;
    if (len == 0 || len >= sizeof buf) return 0;
    memcpy(buf, from, len);
    buf[len] = '\0';
    if (buf[0] < '0' || buf[0] > '9') return 0;
    errno = 0;
    v = strtol(buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0') return 0;
    *out = v;
    return 1;
}

int d2k_parse_rst_rule(const char *line, int *port, long *pid)
{
    size_t n, pl = sizeof(RST_PREFIX) - 1;
    const char *num, *rest;
    long v, owner = 0;

    while (*line == ' ' || *line == '\t') line++;
    n = strlen(line);
    while (n > 0 && (line[n - 1] == ' ' || line[n - 1] == '\t' ||
                     line[n - 1] == '\r' || line[n - 1] == '\n')) n--;
    if (n <= pl || strncmp(line, RST_PREFIX, pl) != 0) return 0;
    num = line + pl;
    rest = num;
    while (rest < line + n && *rest >= '0' && *rest <= '9') rest++;
    if (!parse_long_exact(num, (size_t)(rest - num), &v)) return 0;
    /* Только наш диапазон: чужие правила с флагом RST снимать мы не вправе. */
    if (v < 30000 || v > 54999) return 0;
    size_t left = (size_t)(line + n - rest);
    size_t ls = sizeof(RST_LEGACY_SUFFIX) - 1;
    size_t om = sizeof(RST_OWNED_MID) - 1, ot = sizeof(RST_OWNED_TAG) - 1;
    size_t os = sizeof(RST_OWNED_SUFFIX) - 1;
    if (left == ls && strncmp(rest, RST_LEGACY_SUFFIX, ls) == 0) {
        owner = 0;
    } else if (left > om + ot + os && strncmp(rest, RST_OWNED_MID, om) == 0 &&
               strncmp(line + n - os, RST_OWNED_SUFFIX, os) == 0) {
        const char *c = rest + om, *ce = line + n - os;
        int quoted = c < ce && *c == '"';
        if (quoted) {
            if (ce - c < 2 || ce[-1] != '"') return 0;
            c++; ce--;
        }
        if ((size_t)(ce - c) <= ot || strncmp(c, RST_OWNED_TAG, ot) != 0) return 0;
        if (!parse_long_exact(c + ot, (size_t)(ce - c - (long)ot), &owner) || owner <= 0) return 0;
    } else {
        return 0;
    }
    *port = (int)v;
    if (pid) *pid = owner;
    return 1;
}

/* Прежний вход: наше ли правило (любого формата) и на каком порту. */
int d2k_parse_stale_rst_rule(const char *line, int *port)
{
    return d2k_parse_rst_rule(line, port, NULL);
}

/* Жив ли процесс-владелец. Крючок — для теста; EPERM тоже «жив». */
int (*d2k_raw_alive_hook)(long pid);
static int pid_alive(long pid)
{
    if (d2k_raw_alive_hook) return d2k_raw_alive_hook(pid);
    return kill((pid_t)pid, 0) == 0 || errno == EPERM;
}

/* Брошенное ли наше правило: без владельца (прежняя версия) или владелец
 * мёртв. Правило живого процесса — никогда, в том числе своего: его снимет
 * тот, кто ставил (raw_close / отложенный повтор). */
int d2k_rst_rule_stale(const char *line, int *port, long *pid)
{
    long owner = 0;
    if (!d2k_parse_rst_rule(line, port, &owner)) return 0;
    if (pid) *pid = owner;
    return owner == 0 || !pid_alive(owner);
}

#if defined(__linux__) || defined(D2K_RAW_UNIT_TEST)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_MARK
#define SO_MARK 36
#endif
#if defined(D2K_RAW_UNIT_TEST) && !defined(IPV6_HDRINCL)
/* Only packet helpers run in the non-Linux unit harness. */
#define IPV6_HDRINCL (-1)
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
    uint8_t recv[65535];
    uint8_t resp[8192];
    uint8_t pending[65536];
    uint8_t present[8192];
} raw_buffers;

typedef struct {
    d2k_raw_observation observed;
    d2k_raw_transport transport;
    uint32_t transport_base;
    int      send_fd;
    int      recv_fd;
    uint8_t  src[16];
    uint8_t  dst[16];
    uint8_t  family; /* 0/4 IPv4, 6 IPv6 */
    uint16_t sport;
    uint16_t dport;
    uint16_t syn_window, data_window;
    uint8_t syn_wscale, port_reserved;
    uint16_t syn_retry_ms;
    uint8_t syn_max_sends;
    uint32_t seq; /* наш следующий номер */
    uint32_t ack; /* что подтверждаем */
    int      rule_up;
    int      rx_fin;
    int      rx_initialized, rx_fin_pending;
    uint32_t rx_fin_seq;
    uint8_t tcp_options[12];
    uint8_t tcp_options_len;
    /* Предлагать ли метку времени в SYN — по набору опций клиента, чьё
     * приветствие повторяет зонд (d2k_trigger_offers_ts; замысел 2026-10-23,
     * п. 5.1). Прежде метка стояла литералом, и зонд здоровался не как клиент. */
    uint8_t offer_ts;
    /* raw_recv returns a slice which must survive until the next receive
     * on THIS connection, without being overwritten by another worker. */
    raw_buffers *buffers; /* heap-owned: do not grow the router worker stack */
} raw_conn;

/* Сколько раз не удалось закрыть ядру рот — СЧЁТЧИК ПОТОКА, а не процесса
 * (финальное ревью detect, I1). Прогон сравнивает его со своим стартом
 * (res->rst_fail_base); прогон идёт целиком в одном рабочем потоке, а
 * задача 38 гоняет несколько классификаторов сразу. Общий на процесс
 * счётчик метил чужой прогон отказом вставки соседа — и измеренный split
 * PREFIX/WHOLE соседа выбрасывался вместе с owns_search. Рядом — счётчик
 * сырых соединений потока: пометка «RST не подавлен» уместна, только если
 * этот прогон сам ходил сырым слоем. */
static __thread unsigned long t_rst_rule_failures;
static __thread unsigned long t_raw_dials;

/* Запуск команды правила iptables. Крючок — для теста без root и iptables;
 * в работе это system(). */
/* КОМАНДА ПРАВИЛА — СО СВОИМ СРОКОМ (ревью 49, решение 3). Голый -w (на
 * 1.4.21 «-w N» отвергается, rc=2) ждёт замок xtables без срока, а ждём мы
 * под g_raw_state — с ним стоят все рабочие потоки. Поэтому не system(), а
 * fork/exec своей группой процессов и ожидание с дедлайном: зависшая команда
 * убивается целиком (sh и iptables), вызов отвечает отказом. Код возврата —
 * как у system(): статус waitpid. */
#define RST_RULE_DEADLINE_MS 5000
static int g_rule_deadline_ms = RST_RULE_DEADLINE_MS;

static int raw_rule_system(const char *cmd)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* Только async-signal-safe вызовы: процесс многопоточный. Дескрипторы
         * d2kc (NFQUEUE, сокеты зондов, журналы) команде правила не нужны и не
         * должны пережить её в iptables — закрываем всё, кроме 0–2. */
        setpgid(0, 0);
        long maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
        for (int fd = 3; fd < maxfd; fd++) close(fd);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    int64_t deadline = d2k_now_ms() + g_rule_deadline_ms;
    for (;;) {
        int st = 0;
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid) return st;
        if (w < 0 && errno != EINTR) return -1;
        if (d2k_now_ms() >= deadline) {
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
            return D2K_RAW_RULE_KILLED;
        }
        struct timespec ts = {0, 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
}
d2k_raw_rule_fn d2k_raw_rule_hook = raw_rule_system;
static uint32_t g_sport_counter;
static pthread_once_t g_seed_once = PTHREAD_ONCE_INIT;
static pthread_once_t g_sweep_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_raw_state = PTHREAD_MUTEX_INITIALIZER;

unsigned long d2k_raw_rst_fail_count(void) { return t_rst_rule_failures; }
unsigned long d2k_raw_dial_count(void) { return t_raw_dials; }

static void seed_init(void)
{
    srandom((unsigned)((uint64_t)d2k_now_ms() ^ (uint64_t)getpid()));
    g_sport_counter = (uint32_t)(random() % 25000);
}

static void seed_once(void)
{
    pthread_once(&g_seed_once, seed_init);
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
    uint16_t port;
    seed_once();
    pthread_mutex_lock(&g_raw_state);
    g_sport_counter++;
    port = (uint16_t)(30000 + g_sport_counter % 25000);
    pthread_mutex_unlock(&g_raw_state);
    return port;
}

/* sweepStaleRSTRules снимает правила подавления, оставшиеся от прошлых
 * прогонов: уборщик не выполнится, если процесс убили сигналом KILL — а
 * панель именно так и добивает замер, не уложившийся в отведённое время. */
/* OpenWrt без iptables (25.12, 07.10.2026): S99d2k ставит правила в nftables
 * и экспортирует D2K_FW=nft. Тогда правило подавления — элемент множества
 * inet d2k_rst (rst4/rst6) с таймаутом: после kill -9 он истекает сам, и ни
 * уборки по владельцу, ни комментария не нужно. Таймаут с запасом больше
 * жизни зонда (шаги по timeout_ms, секунды). */
#define RST_NFT_TIMEOUT "300s"
/* Ключ правила подавления. iptables берёт только порт (у каждого процесса —
 * своё правило с меткой владельца). Элемент nft один на ключ, поэтому ключ —
 * весь кортеж зонда: тот же порт другого процесса к другой цели — другой
 * элемент, а один кортеж у двух зондов сразу невозможен (ревью 07.10). */
typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint8_t  family; /* 0/4 IPv4, 6 IPv6 */
    uint8_t  dst[16];
} rst_key;
static int rst_nft(void)
{
    const char *fw = getenv("D2K_FW");
    return fw && strcmp(fw, "nft") == 0;
}

static void sweep_stale_rst_rules(void)
{
    FILE *f;
    char line[512];

    if (rst_nft()) return;

    const char *tables[] = {"iptables", "ip6tables"};
    for (size_t family = 0; family < 2; family++) {
    char list[96];
    snprintf(list, sizeof list, "%s -w -S OUTPUT 2>/dev/null", tables[family]);
    f = popen(list, "r");
    if (!f) {
        continue;
    }
    while (fgets(line, sizeof(line), f)) {
        int port;
        long owner = 0;
        if (d2k_rst_rule_stale(line, &port, &owner)) {
            char cmd[256], tag[64] = ""; /* " -m comment --comment d2k-rst:" + 20 цифр long */
            if (owner > 0) snprintf(tag, sizeof tag, " -m comment --comment %s%ld", RST_OWNED_TAG, owner);
            snprintf(cmd, sizeof(cmd),
                     "%s -w -D OUTPUT -p tcp --sport %d --tcp-flags RST RST%s -j DROP"
                     " >/dev/null 2>&1", tables[family], port, tag);
            (void)raw_rule_system(cmd);
        }
    }
    pclose(f);
    }
}

/* suppressKernelRST закрывает ядру рот на время зонда.
 *
 * ТОЛЬКО ГОЛЫЙ -w, И ЭТО ПРОВЕРЕНО. На роутере владельца iptables v1.4.21: он
 * понимает голый -w (проверено 03.10: iptables -w -S, ip6tables -w -S), но не «-w 5» — числовой аргумент появился только в
 * 1.4.22. С «-w 5» вставка падает, правило не встаёт, каждый зонд получает RST
 * от собственного ядра и читается как блокировка (замер 04.09: классификатор
 * вырождался в opaque с полным перебором на любом домене). Отказ здесь
 * молчаливый по замыслу, поэтому факт отказа обязан доехать до вердикта. */
/* ЗАДАЧА 49: СНЯТИЕ НЕ ТЕРЯЕТСЯ. Голый -w (его v1.4.21 понимает) ждёт замок
 * xtables вместо мгновенного отказа: NDM и сторож правил держат его регулярно,
 * и без -w отказывали и вставка (94 «RST не подавлен» в журнале 03.10), и
 * удаление — правило оставалось висеть (--sport 39842/39408/39354, 40750
 * без единого поиска). Неудавшееся удаление повторяется сразу, затем
 * запоминается и повторяется перед каждой следующей правкой правил. */
#define RST_PENDING_MAX 64
/* Сколько попыток снять одно правило (сразу и отложенно перед правками
 * правил и прогонами), прежде чем перестать повторять его на ходу. Запись при
 * этом НЕ теряется: при выходе процесса снимается ещё раз (atexit), а что
 * останется — снимет уборка следующего запуска (владелец уже мёртв). Пока
 * процесс жив, чужая уборка правило не тронет: владелец жив. */
#define RST_RELEASE_ATTEMPTS 5
static struct { rst_key key; int attempts; } g_rst_pending[RST_PENDING_MAX];
static size_t g_rst_pending_n;
static uint8_t g_raw_ports[65536];
/* g_raw_state held: an unresolved delete must never affect a new owner. */
static int raw_port_busy(uint16_t port)
{
    if (g_raw_ports[port]) return 1;
    for (size_t i=0;i<g_rst_pending_n;i++)
        if (g_rst_pending[i].key.sport==port) return 1;
    return 0;
}
static uint16_t reserve_source_port(uint16_t requested)
{
    unsigned count=requested ? 1 : 25000;
    for (unsigned i=0;i<count;i++) {
        uint16_t port=requested ? requested : next_source_port();
        pthread_mutex_lock(&g_raw_state);
        int busy=raw_port_busy(port);
        if (!busy) g_raw_ports[port]=1;
        pthread_mutex_unlock(&g_raw_state);
        if (!busy) return port;
    }
    return 0;
}
static int g_rst_abandon_said;
static pthread_once_t g_atexit_once = PTHREAD_ONCE_INIT;

/* xt_comment есть не во всех прошивках (поле 03.10.2026, Keenetic mipsel
 * 3.4_kn: в lsmod нет xt_comment). Если правило с комментарием-владельцем
 * отвергнуто, а старая форма встала — дальше процесс ставит и снимает старую:
 * уборка старта узнаёт её по форме (владельца нет — снимается как чужая). */
static int g_rst_comment = 1;

static int rst_rule_cmd_form(const char *op, const rst_key *k, int comment)
{
    char cmd[256], tag[64] = "";
    if (rst_nft()) {
        /* -I/-D/-C той же семантики: get отвечает 1, если элемента нет. */
        const char *verb = strcmp(op, "-I") == 0 ? "add" : strcmp(op, "-D") == 0 ? "delete" : "get";
        char addr[INET6_ADDRSTRLEN];
        if (!inet_ntop(k->family == 6 ? AF_INET6 : AF_INET, k->dst, addr, sizeof addr)) return -1;
        snprintf(cmd, sizeof(cmd), "nft %s element inet d2k_rst rst%c { %u . %s . %u%s } >/dev/null 2>&1",
                 verb, k->family == 6 ? '6' : '4', (unsigned)k->sport, addr, (unsigned)k->dport,
                 strcmp(verb, "add") == 0 ? " timeout " RST_NFT_TIMEOUT : "");
        return d2k_raw_rule_hook(cmd);
    }
    if (comment) snprintf(tag, sizeof tag, " -m comment --comment %s%ld", RST_OWNED_TAG, (long)getpid());
    snprintf(cmd, sizeof(cmd),
             "%s -w %s OUTPUT -p tcp --sport %u --tcp-flags RST RST%s -j DROP >/dev/null 2>&1",
             k->family == 6 ? "ip6tables" : "iptables", op, (unsigned)k->sport, tag);
    return d2k_raw_rule_hook(cmd);
}

static int rst_rule_cmd(const char *op, const rst_key *k)
{
    return rst_rule_cmd_form(op, k, g_rst_comment);
}

static int rc_exit1(int rc)
{
    return rc > 0 && WIFEXITED(rc) && WEXITSTATUS(rc) == 1;
}

/* Одна попытка снять правило; 1 — правила больше нет. Exit 1 у -D в 1.4.21 —
 * и «правила нет» (NDM перестроил netfilter), и общий OTHER_PROBLEM (ENOMEM,
 * сбой фиксации), поэтому на слово -D не верим: отсутствие подтверждает -C
 * (exit 1 — правила нет; 0 — правило ещё стоит; прочее — не знаем). */
static int rst_delete_once(const rst_key *k)
{
    int rc = rst_rule_cmd("-D", k);
    if (rc == 0) return 1;
    if (!rc_exit1(rc)) return 0;
    return rc_exit1(rst_rule_cmd("-C", k));
}

static void rst_abandon(const rst_key *k)
{
    uint16_t sport = k->sport;
    uint8_t family = k->family;
    if (g_rst_abandon_said) return;
    g_rst_abandon_said = 1;
    fprintf(stderr, "d2k: правило подавления RST (%s, порт %u) не снято за %d попыток — "
                    "больше не повторяю до выхода процесса; при выходе попробую ещё раз, "
                    "оставшееся снимет уборка следующего запуска d2k\n",
            family == 6 ? "ip6tables" : "iptables", (unsigned)sport, RST_RELEASE_ATTEMPTS);
}

static void raw_atexit(void);
static void register_atexit(void) { (void)atexit(raw_atexit); }

/* Под g_raw_state. Запомнить правило, которое снять не удалось. */
static void rst_remember(const rst_key *k, int attempts)
{
    pthread_once(&g_atexit_once, register_atexit);
    if (g_rst_pending_n < RST_PENDING_MAX) {
        g_rst_pending[g_rst_pending_n].key = *k;
        g_rst_pending[g_rst_pending_n].attempts = attempts;
        g_rst_pending_n++;
    } else {
        rst_abandon(k);
    }
}

/* Под g_raw_state. final — выход процесса: каждая запись ещё раз, в том числе
 * исчерпавшие попытки. */
static void retry_pending_releases(int final)
{
    size_t k = 0;
    while (k < g_rst_pending_n) {
        if (!final && g_rst_pending[k].attempts >= RST_RELEASE_ATTEMPTS) { k++; continue; }
        if (rst_delete_once(&g_rst_pending[k].key)) {
            g_rst_pending[k] = g_rst_pending[--g_rst_pending_n];
            continue;
        }
        if (++g_rst_pending[k].attempts >= RST_RELEASE_ATTEMPTS && !final) {
            rst_abandon(&g_rst_pending[k].key);
        }
        k++;
    }
}

/* Под g_raw_state. Снять правило: сразу дважды, иначе запомнить. */
static void rst_release_locked(const rst_key *k)
{
    if (!rst_delete_once(k) && !rst_delete_once(k)) {
        rst_remember(k, 2);
    }
}

/* Отложенные снятия — и тогда, когда новых правок правил нет (d2kc простаивает
 * или прогон обходится без сырого слоя): перед каждой пачкой зондов (старт
 * прогона классификатора) и при выходе процесса. */
void d2k_raw_flush_pending(void)
{
    pthread_mutex_lock(&g_raw_state);
    if (g_rst_pending_n) retry_pending_releases(0);
    pthread_mutex_unlock(&g_raw_state);
}

size_t d2k_raw_pending_count(void)
{
    size_t n;
    pthread_mutex_lock(&g_raw_state);
    n = g_rst_pending_n;
    pthread_mutex_unlock(&g_raw_state);
    return n;
}

static void raw_atexit(void)
{
    /* На выходе рабочие потоки уже собраны (d2k_sched_free); если замок всё же
     * занят — не ждать его, выход важнее. */
    if (pthread_mutex_trylock(&g_raw_state) != 0) return;
    if (g_rst_pending_n) retry_pending_releases(1);
    pthread_mutex_unlock(&g_raw_state);
}

static rst_key rst_key_of(const raw_conn *c)
{
    rst_key k;
    memset(&k, 0, sizeof k);
    k.sport = c->sport;
    k.dport = c->dport;
    k.family = c->family;
    memcpy(k.dst, c->dst, c->family == 6 ? 16 : 4);
    return k;
}

static int suppress_kernel_rst(const raw_conn *c)
{
    int rc;
    rst_key key = rst_key_of(c);
    const rst_key *k = &key;
    /* Old router iptables cannot be relied on to serialize our commands.
     * Protect only rule edits, not the network lifetime of the probe. */
    pthread_mutex_lock(&g_raw_state);
    retry_pending_releases(0);
    rc = rst_rule_cmd("-I", k);
    if (rc > 0 && g_rst_comment && !rst_nft() && WIFEXITED(rc) && WEXITSTATUS(rc) <= 2 &&
        rst_rule_cmd_form("-I", k, 0) == 0) {
        g_rst_comment = 0;
        fprintf(stderr, "d2k: в прошивке нет xt_comment — правила подавления RST "
                        "ставлю без метки владельца\n");
        rc = 0;
    }
    if (rc != 0) {
        t_rst_rule_failures++;
        /* Вставку убили по сроку: с -w iptables мог дождаться замка и
         * зафиксировать правило за миг до SIGKILL. Правило, о котором мы не
         * знаем, не снимет никто, пока процесс жив, — снимаем его сами (ревью
         * detect, I2). Ненулевой код самого iptables означает, что фиксации
         * не было: снимать нечего. */
        if (rc == D2K_RAW_RULE_KILLED) rst_release_locked(k);
    }
    pthread_mutex_unlock(&g_raw_state);
    return rc == 0;
}

static void release_kernel_rst(const raw_conn *c)
{
    rst_key k = rst_key_of(c);
    pthread_mutex_lock(&g_raw_state);
    rst_release_locked(&k);
    pthread_mutex_unlock(&g_raw_state);
}

/* localAddrFor узнаёт, с какого адреса ядро пошло бы к этой цели. */
static int local_addr_for(const uint8_t *dst, uint16_t port, uint8_t *out, uint8_t family)
{
    if (family == 6) {
        struct sockaddr_in6 to, local;
        memset(&to, 0, sizeof to);
        to.sin6_family = AF_INET6; to.sin6_port = htons(port);
        memcpy(&to.sin6_addr, dst, 16);
        int sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sock < 0) return 0;
        socklen_t len = sizeof local;
        int ok = connect(sock, (struct sockaddr *)&to, sizeof to) == 0 &&
                 getsockname(sock, (struct sockaddr *)&local, &len) == 0;
        if (ok) memcpy(out, &local.sin6_addr, 16);
        close(sock);
        return ok;
    }
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
    uint32_t sum;
    size_t i;
    if (tlen < 20 || tlen > 65535) {
        return 0;
    }
    /* Same pseudo-header checksum, without a shared 64 KiB scratch array
     * or an equally large stack allocation. Skip TCP's checksum word. */
    sum = (uint32_t)rd16(src) + rd16(src + 2) + rd16(dst) + rd16(dst + 2)
          + 6u + (uint32_t)tlen;
    for (i = 0; i + 1 < tlen; i += 2) {
        if (i != 16) { sum += rd16(t + i); }
    }
    if (tlen & 1u) { sum += (uint32_t)t[tlen - 1] << 8; }
    while (sum >> 16) { sum = (sum & 0xffffu) + (sum >> 16); }
    return (uint16_t)~sum;
}

/* buildIPv4TCP собирает пакет целиком. Контрольные суммы считаем сами: ядро
 * их для IP_HDRINCL не трогает, а нам порча суммы нужна как инструмент. */
static size_t build_ipv4_tcp_window(uint8_t *pkt, size_t cap,
                             const uint8_t src[4], const uint8_t dst[4],
                             uint16_t sport, uint16_t dport,
                             uint32_t seq, uint32_t ack, uint8_t flags,
                             const uint8_t *payload, size_t plen,
                             const d2k_poison *p,
                             const uint8_t *extra, size_t extralen, uint16_t window)
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
    wr16(t + 14, window);
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


static uint16_t tcp_checksum_family(uint8_t family, const uint8_t *src,
                                     const uint8_t *dst, const uint8_t *tcp, size_t n)
{
    uint16_t base = tcp_checksum(src, dst, tcp, n);
    if (family != 6) return base;
    uint32_t sum = (uint16_t)~base;
    for (size_t i = 4; i < 16; i += 2) sum += rd16(src + i) + rd16(dst + i);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Share TCP/options/poison construction with the original IPv4 builder. */
static size_t build_ip_tcp_window(uint8_t *pkt, size_t cap, uint8_t family,
                            const uint8_t *src, const uint8_t *dst,
                            uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                            uint8_t flags, const uint8_t *payload, size_t plen,
                            const d2k_poison *p, const uint8_t *extra, size_t extralen, uint16_t window)
{
    if (family != 6)
        return build_ipv4_tcp_window(pkt, cap, src, dst, sport, dport, seq, ack, flags,
                               payload, plen, p, extra, extralen, window);
    if (cap < 60 || p->ip_id_zero) return 0;
    size_t n = build_ipv4_tcp_window(pkt + 20, cap - 20, src, dst, sport, dport,
                              seq, ack, flags, payload, plen, p, extra, extralen, window);
    if (n < 40 || n - 20 > 65535) return 0;
    memset(pkt, 0, 40);
    pkt[0] = 0x60; wr16(pkt + 4, (uint16_t)(n - 20));
    pkt[6] = 6; pkt[7] = p->ttl > 0 ? (uint8_t)p->ttl : 64;
    memcpy(pkt + 8, src, 16); memcpy(pkt + 24, dst, 16);
    uint16_t sum = tcp_checksum_family(6, src, dst, pkt + 40, n - 20);
    if (p->badsum) { sum ^= 0xbeef; if (!sum) sum = 0x1234; }
    wr16(pkt + 56, sum);
    return n + 20;
}


static int raw_sendto(raw_conn *c, const uint8_t *pkt, size_t n)
{
    if (c->family == 6) {
        struct sockaddr_in6 to;
        memset(&to, 0, sizeof to);
        to.sin6_family = AF_INET6;
        memcpy(&to.sin6_addr, c->dst, 16);
        return sendto(c->send_fd, pkt, n, 0, (struct sockaddr *)&to, sizeof to) == (ssize_t)n ? 0 : -1;
    }
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
 * 1400 — с запасом под PPPoE (1492) и под опции TCP в нашем же заголовке.
 *
 * Потолок — переменная, а не константа (поле 22.10.2026, issue #5/#7): ядро
 * ставит его по пределу датапата (d2k_arm_segment), и замер уходит теми же
 * сегментами, какими потом пойдёт план. Иначе на узком канале (туннель, LTE)
 * замер шёл сегментами 1400, а план с таким сегментом датапат отвергал — и
 * измеренное расходилось с исполнимым. По умолчанию — прежние 1400. */
static unsigned seg_max = D2K_ARM_SEGMENT_MAX;
void d2k_raw_set_segment_max(unsigned seg) { seg_max = seg ? seg : D2K_ARM_SEGMENT_MAX; }
unsigned d2k_raw_segment_max(void) { return seg_max; }

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
    uint8_t pkt[2048];
    uint32_t seq = c->seq;
    size_t off = 0;

    if (p->seq_shift != 0) {
        seq = (uint32_t)((int64_t)seq + (int64_t)p->seq_shift);
    }
    do {
        size_t take = plen - off;
        size_t n;
        if (take > seg_max) {
            take = seg_max;
        }
        n = build_ip_tcp_window(pkt, sizeof(pkt), c->family, c->src, c->dst, c->sport, c->dport,
                           seq + (uint32_t)off, c->ack, flags,
                           plen ? payload + off : NULL, take, p,
                           c->tcp_options,c->tcp_options_len,c->data_window ? c->data_window : 65535);
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
    /* Набор с меткой времени — прежний литерал; без метки — как здоровается
     * клиент, метку не предлагающий (MSS, окно, SACK): так ответ сервера не
     * принесёт эха метки, и данные пойдут без неё, как у этого клиента. */
    static const uint8_t opts_ts[] = {
        2, 4, 0x05, 0xac,               /* MSS 1452 */
        4, 2,                           /* SACK permitted */
        8, 10, 0, 0, 0, 1, 0, 0, 0, 0,  /* timestamps */
        1,                              /* NOP */
        3, 3, 7                         /* window scale 7 */
    };
    static const uint8_t opts_plain[] = {
        2, 4, 0x05, 0xac,               /* MSS 1452 */
        1,                              /* NOP */
        3, 3, 7,                        /* window scale 7 */
        1, 1,                           /* NOP, NOP */
        4, 2                            /* SACK permitted */
    };
    uint8_t opts[sizeof opts_ts];
    memcpy(opts,c->offer_ts ? opts_ts : opts_plain,c->offer_ts ? sizeof opts_ts : sizeof opts_plain);
    opts[c->offer_ts ? 19 : 7]=c->syn_wscale;
    size_t optlen = c->offer_ts ? sizeof(opts_ts) : sizeof(opts_plain);
    uint8_t pkt[256];
    d2k_poison none;
    size_t n;

    memset(&none, 0, sizeof(none));
    n = build_ip_tcp_window(pkt, sizeof(pkt), c->family, c->src, c->dst, c->sport, c->dport,
                       c->seq, 0, TCP_SYN, NULL, 0, &none, opts, optlen,c->syn_window ? c->syn_window : 65535);
    if (n == 0) {
        return -1;
    }
    return raw_sendto(c, pkt, n);
}

static uint64_t raw_count_add(uint64_t value,uint64_t add)
{
    return UINT64_MAX-value<add?UINT64_MAX:value+add;
}
static void raw_transport_receive(raw_conn *c,const uint8_t *tcp,size_t payload)
{
    d2k_raw_transport *t=&c->transport;
    if(!t->available)return;
    t->received_packets=raw_count_add(t->received_packets,1);
    t->received_payload_bytes=raw_count_add(t->received_payload_bytes,payload);
    if((tcp[13]&TCP_ACK) && !(tcp[13]&(TCP_SYN|TCP_RST))) {
        uint32_t offset=rd32(tcp+8)-c->transport_base;
        t->ack_packets=raw_count_add(t->ack_packets,1);
        if(offset<UINT32_C(0x80000000) && offset<=t->sent_end) {
            t->ack_seen=1;
            if(offset>t->acked_end) {
                t->acked_end=offset;
                t->ack_advances=raw_count_add(t->ack_advances,1);
            }
            t->peer_window_raw=rd16(tcp+14);t->window_seen=1;
        }
    }
    c->observed.transport=*t;
}

/* recv returns our peer's segment, a wait/deadline, or a local error. */
enum { RAW_RECV_WAIT = -1, RAW_RECV_ERROR = -2 };
static int raw_recv(raw_conn *c, uint8_t *flags, uint32_t *seq, uint32_t *ack,
                    const uint8_t **payload, size_t *plen,
                    int64_t deadline, const d2k_detect_stop *cancel)
{
    uint8_t *buf = c->buffers->recv;
    for (;;) {
        /* SO_RCVTIMEO bounds one recvfrom, not this filtering loop. On a
         * busy router unrelated packets otherwise keep a silent probe alive
         * forever, also preventing cancellation and occupying its worker. */
        if (d2k_now_ms() >= deadline || d2k_detect_stopped(cancel)) return -1;
        struct sockaddr_storage peer={0};
        socklen_t peerlen = sizeof peer;
        ssize_t n = recvfrom(c->recv_fd, buf, sizeof(c->buffers->recv), 0,
                              (struct sockaddr *)&peer, &peerlen);
        size_t ihl, off;
        const uint8_t *t;
        size_t tlen;
        if (n < 0) {
            return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
                ? RAW_RECV_WAIT : RAW_RECV_ERROR;
        }
        if (c->family == 6) {
            /* Linux IPv6 raw TCP receives the transport segment, without IP header. */
            if (n < 20 || peer.ss_family != AF_INET6 ||
                memcmp(&((struct sockaddr_in6 *)&peer)->sin6_addr, c->dst, 16) != 0)
                continue;
            ihl = 0;
        } else {
            if (n < 40) continue;
            ihl = (size_t)(buf[0] & 0x0f) * 4;
            if (ihl < 20 || (size_t)n < ihl + 20 || memcmp(buf + 12, c->dst, 4) != 0)
                continue;
        }
        t = buf + ihl;
        tlen = (size_t)n - ihl;
        if (rd16(t + 0) != c->dport || rd16(t + 2) != c->sport) {
            continue;
        }
        off = (size_t)(t[12] >> 4) * 4;
        if (off < 20 || off > tlen) {
            continue;
        }
        *flags = t[13];
        *seq = rd32(t + 4);
        *ack = rd32(t + 8);
        *payload = t + off;
        *plen = tlen - off;
        raw_transport_receive(c,t,*plen);
        return 0;
    }
}

/* Collect the contiguous reply prefix required by the trigger predicate. */
static int raw_read_payload(raw_conn *c, int timeout_ms, const d2k_detect_stop *cancel,
                            uint8_t *out, size_t cap, size_t *outlen, size_t minimum)
{
    int64_t deadline = d2k_now_ms() + timeout_ms;
    *outlen = 0;
    if (!minimum || minimum > cap) { errno = EINVAL; return RAW_RECV_ERROR; }
    if(c->rx_fin) {c->observed.kind=D2K_RAW_OBS_RESPONSE_FIN;return -1;}
    if(!c->rx_initialized) {
        memset(c->buffers->present,0,sizeof c->buffers->present);
        c->rx_initialized=1;
    }
    while (d2k_now_ms() < deadline) {
        uint8_t flags;
        if (d2k_detect_stopped(cancel)) {
            c->observed.kind = D2K_RAW_OBS_CANCELLED;
            return -1;
        }
        size_t before=*outlen;
        while(*outlen<cap && !(c->rx_fin_pending && c->ack==c->rx_fin_seq)) {
            size_t at=c->ack&65535u;uint8_t bit=(uint8_t)(1u<<(at&7));
            if(!(c->buffers->present[at>>3]&bit))break;
            out[(*outlen)++]=c->buffers->pending[at];
            c->buffers->present[at>>3]&=(uint8_t)~bit;c->ack++;
        }
        if(c->rx_fin_pending && c->ack==c->rx_fin_seq) {
            c->rx_fin=1;c->ack++;
        }
        c->observed.response_bytes=*outlen;
        if(c->rx_fin || *outlen>=minimum) {
            if(c->rx_fin) {
                d2k_poison none={0};
                if(raw_send(c,NULL,0,TCP_ACK,&none)) {
                    c->observed.kind=D2K_RAW_OBS_LOCAL;return RAW_RECV_ERROR;
                }
            }
            c->observed.kind=c->rx_fin?D2K_RAW_OBS_RESPONSE_FIN:D2K_RAW_OBS_RESPONSE_BYTES;
            return *outlen?0:-1;
        }
        if(*outlen>before) {
            d2k_poison none={0};
            if(raw_send(c,NULL,0,TCP_ACK,&none)) {
                c->observed.kind=D2K_RAW_OBS_LOCAL;return RAW_RECV_ERROR;
            }
        }
        uint32_t seq, ack;
        const uint8_t *pay;
        size_t plen;
        int received = raw_recv(c, &flags, &seq, &ack, &pay, &plen, deadline, cancel);
        if (received == RAW_RECV_ERROR) {
            c->observed.kind = D2K_RAW_OBS_LOCAL;
            return RAW_RECV_ERROR;
        }
        if (received != 0) continue;
        if (flags & TCP_RST) {
            if ((uint32_t)(seq - c->ack) >= UINT32_C(0x80000000)) continue;
            c->observed.kind = D2K_RAW_OBS_RESPONSE_RESET;
            return -1; /* RST */
        }
        uint32_t fin_at=seq+(uint32_t)plen;
        if((flags&TCP_FIN) && fin_at-c->ack<65536u && !c->rx_fin_pending) {
            c->rx_fin_pending=1;c->rx_fin_seq=fin_at;
        }
        if (plen > 0) {
            /* A bounded sequence-indexed window retains reordered segments and
               the unread tail of a small application read. First arrival wins;
               bytes outside the window are neither retained nor acknowledged. */
            for(size_t i=0;i<plen;i++) {
                uint32_t pos=seq+(uint32_t)i;
                if(pos-c->ack>=65536u)continue;
                size_t at=pos&65535u;uint8_t bit=(uint8_t)(1u<<(at&7));
                if(!(c->buffers->present[at>>3]&bit)) {
                    c->buffers->pending[at]=pay[i];c->buffers->present[at>>3]|=bit;
                }
            }
            if ((int32_t)(seq - c->ack) > 0 || c->ack-seq>=plen) {
                d2k_poison none={0};
                if(raw_send(c,NULL,0,TCP_ACK,&none)) {
                    c->observed.kind=D2K_RAW_OBS_LOCAL;return RAW_RECV_ERROR;
                }
            }
        }
    }
    c->observed.kind = D2K_RAW_OBS_RESPONSE_TIMEOUT;
    return -1; /* тишина */
}

static void raw_close(raw_conn *c)
{
    if (c->rule_up) {
        release_kernel_rst(c);
        c->rule_up = 0;
    }
    if (c->send_fd >= 0) {
        close(c->send_fd);
        c->send_fd = -1;
    }
    if (c->recv_fd >= 0) {
        close(c->recv_fd);
        c->recv_fd = -1;
    }
    free(c->buffers);
    c->buffers = NULL;
    if (c->port_reserved) {
        pthread_mutex_lock(&g_raw_state);
        g_raw_ports[c->sport]=0;
        pthread_mutex_unlock(&g_raw_state);
        c->port_reserved=0;
    }
}

static int raw_handshake(raw_conn *c, int timeout_ms, const d2k_detect_stop *cancel,
                         char *err, size_t errcap)
{
    int64_t deadline;
    d2k_poison none;

    memset(&none, 0, sizeof(none));
    int64_t syn_at = d2k_now_ms();
    if (raw_send_syn(c) != 0) {
        snprintf(err, errcap, "%s", strerror(errno));
        return -1;
    }
    int retransmitted = 0;
    deadline = syn_at + timeout_ms;
    /* ПОТЕРЯННЫЙ SYN ПОВТОРЯЕТСЯ, КАК У TCP ЯДРА (RFC 6298: RTO с секунды,
     * затем вдвое), тем же номером. Поле 15.10.2026, flibusta.is: путь
     * эпизодами теряет SYN (17-19 %, в эпизоде до половины), а единственный
     * SYN на весь срок делал каждую потерю «SYN-ACK не пришёл» — замер
     * бросался, не дойдя до вопросов, которыми цель берётся. Настоящий
     * клиент повторяет SYN; зонд, который этого не делает, мерит не коробку,
     * а потери пути. */
    unsigned syn_sends=1;
    int rto_ms = c->syn_retry_ms ? c->syn_retry_ms : 1000;
    int64_t next_syn = d2k_now_ms() + rto_ms;
    while (d2k_now_ms() < deadline) {
        uint8_t flags;
        uint32_t seq, ack;
        const uint8_t *pay;
        size_t plen;
        if (d2k_detect_stopped(cancel)) {
            c->observed.kind = D2K_RAW_OBS_CANCELLED;
            snprintf(err, errcap, "context canceled");
            return -1;
        }
        if (d2k_now_ms() >= next_syn) {
            if(c->syn_max_sends && syn_sends>=c->syn_max_sends) {
                next_syn=deadline;
                continue;
            }
            if (raw_send_syn(c) != 0) {
                snprintf(err, errcap, "%s", strerror(errno));
                return -1;
            }
            retransmitted = 1;
            syn_sends++;
            if(!c->syn_retry_ms)rto_ms *= 2;
            next_syn = d2k_now_ms() + rto_ms;
        }
        int received = raw_recv(c, &flags, &seq, &ack, &pay, &plen,
                                next_syn < deadline ? next_syn : deadline, cancel);
        if (received == RAW_RECV_ERROR) {
            snprintf(err, errcap, "classify: recvfrom: %s", strerror(errno));
            return -1;
        }
        if (received != 0) continue;
        if (flags & TCP_RST) {
            c->observed.kind = D2K_RAW_OBS_CONNECT_RESET;
            snprintf(err, errcap, "classify: сервер ответил RST на SYN");
            return -1;
        }
        if ((flags & TCP_SYN) && (flags & TCP_ACK)) {
            if (ack != c->seq + 1) {
                continue;
            }
            int64_t elapsed = d2k_now_ms() - syn_at;
            if (!retransmitted) c->observed.rtt_ms = elapsed > 0 ? (uint32_t)elapsed : 1;
            /* Keep negotiated timestamps for tcp-template-v1. The SYN
               offered TSval=1; echo the peer's actual SYN-ACK timestamp. */
            const uint8_t *tcp = c->buffers->recv + (c->family == 6 ? 0 :
                (size_t)(c->buffers->recv[0] & 15) * 4);
            size_t hlen = (size_t)(tcp[12] >> 4) * 4;
            for (size_t off = 20; off < hlen;) {
                uint8_t kind = tcp[off];
                if (!kind) break;
                if (kind == 1) { off++; continue; }
                if (off + 2 > hlen || tcp[off + 1] < 2 || tcp[off + 1] > hlen - off) break;
                if (kind == 8 && tcp[off + 1] == 10) {
                    memcpy(c->tcp_options, (uint8_t[]){1,1,8,10,0,0,0,1,0,0,0,0}, 12);
                    memcpy(c->tcp_options + 8, tcp + off + 2, 4);
                    c->tcp_options_len = 12;
                }
                off += tcp[off + 1];
            }
            c->seq++;
            c->ack = seq + 1;
            if (raw_send(c, NULL, 0, TCP_ACK, &none) != 0) {
                snprintf(err, errcap, "%s", strerror(errno));
                return -1;
            }
            c->observed.connected = 1;
            return 0;
        }
    }
    snprintf(err, errcap, "classify: SYN-ACK не пришёл");
    c->observed.kind = D2K_RAW_OBS_CONNECT_TIMEOUT;
    return D2K_RAW_CONNECT_TIMEOUT;
}

/* dialRaw поднимает соединение своими руками и возвращает его установленным. */
static int raw_dial_shaped(raw_conn *c, const uint8_t *dst, uint8_t family, uint16_t dport,
                    int timeout_ms, uint32_t mark_val, const d2k_detect_stop *cancel,
                    int offer_ts, const d2k_raw_shape *shape, char *err, size_t errcap)
{
    int one = 1;
    int mark = (int)mark_val;
    struct timeval tv;

    memset(c, 0, sizeof(*c));
    c->offer_ts = offer_ts ? 1 : 0;
    c->syn_window=shape ? shape->syn_window : 0;
    c->data_window=shape ? shape->data_window : 0;
    c->syn_wscale=shape && shape->syn_wscale>=0 ? (uint8_t)shape->syn_wscale : 7;
    c->syn_retry_ms=shape ? shape->syn_retry_ms : 0;
    c->syn_max_sends=shape ? shape->syn_max_sends : 0;
    c->send_fd = -1;
    c->recv_fd = -1;
    if (family != 4 && family != 6) return -1;
    c->family = family;
    memcpy(c->dst, dst, family == 6 ? 16 : 4);
    c->dport = dport;

    if (!local_addr_for(dst, dport, c->src, family)) {
        snprintf(err, errcap, "classify: не удалось определить свой адрес");
        return -1;
    }
    c->buffers = malloc(sizeof(*c->buffers));
    if (!c->buffers) {
        snprintf(err, errcap, "classify: нет памяти для буферов сырого зонда");
        return -1;
    }
    int af = family == 6 ? AF_INET6 : AF_INET;
    c->send_fd = socket(af, SOCK_RAW, IPPROTO_RAW);
    if (c->send_fd < 0) {
        snprintf(err, errcap, "classify: сырой сокет на отправку (нужен root): %s",
                 strerror(errno));
        raw_close(c);
        return -1;
    }
    /* МЕТКА, ОТКЛЮЧАЮЩАЯ НАШ ЖЕ ОБХОД. Замер обязан идти по СЫРОМУ пути,
     * иначе меряется не коробка провайдера, а наш десинк поверх неё. В
     * правилах NFQUEUE уже есть дверь: `-m mark ! --mark 0x40000000`. */
    if ((mark && setsockopt(c->send_fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) ||
        setsockopt(c->send_fd, family == 6 ? IPPROTO_IPV6 : IPPROTO_IP,
                    family == 6 ? IPV6_HDRINCL : IP_HDRINCL, &one, sizeof(one)) != 0) {
        snprintf(err, errcap, "classify: IP_HDRINCL: %s", strerror(errno));
        raw_close(c);
        return -1;
    }
    c->recv_fd = socket(af, SOCK_RAW, IPPROTO_TCP);
    if (c->recv_fd < 0) {
        snprintf(err, errcap, "classify: сырой сокет на приём: %s", strerror(errno));
        raw_close(c);
        return -1;
    }
    tv.tv_sec = 0;
    if (family == 6) {
        struct sockaddr_in6 local;
        memset(&local, 0, sizeof local);
        local.sin6_family = AF_INET6;
        memcpy(&local.sin6_addr, c->src, 16);
        if (bind(c->recv_fd, (struct sockaddr *)&local, sizeof local) != 0) {
            snprintf(err, errcap, "classify: IPv6 receive bind: %s", strerror(errno));
            raw_close(c); return -1;
        }
    }
    /* A receive must yield before the next shaped SYN retry. A fixed
     * 300-ms read otherwise swallows the executor's 60-ms retry schedule. */
    unsigned receive_ms=c->syn_retry_ms && c->syn_retry_ms<300 ? c->syn_retry_ms : 300;
    tv.tv_usec = (int)receive_ms*1000;
    if(setsockopt(c->recv_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) && c->syn_retry_ms) {
        snprintf(err,errcap,"shaped receive timeout: %s",strerror(errno));
        raw_close(c);return -1;
    }

    /* Подметаем один раз за прогон, а не перед каждым зондом: зондов сотни, а
     * разбор таблицы стоит вызова iptables. */
    /* Other workers must wait for cleanup to finish before creating rules;
     * otherwise first-use cleanup can delete a new worker's live rule. */
    pthread_once(&g_sweep_once, sweep_stale_rst_rules);
    c->sport = reserve_source_port(shape ? shape->sport : 0);
    if (!c->sport) {
        snprintf(err,errcap,"raw source port is already owned or unavailable");
        raw_close(c);return -1;
    }
    c->port_reserved=1;
    seed_once();
    c->seq = shape && shape->initial_seq_known ? shape->initial_seq : (uint32_t)random();
    /* Как у донора (suppressKernelRST): без правила мерить ПРОДОЛЖАЕМ —
     * ядерный RST прилетает после SYN-ACK, а зонд к тому времени часто уже
     * пишет данные. Отказ iptables (нет бинарника, роутер только на nft) —
     * своя поломка, а не свойство сети: вернув ошибку, мы роняли
     * самопроверку, и цель уходила в «обойти нечем». Факт отказа не молчит:
     * он считается в t_rst_rule_failures потока (трасса вердикта и адаптер
     * планировщика сравнивают d2k_raw_rst_fail_count со стартом прогона). */
    t_raw_dials++;
    c->rule_up = suppress_kernel_rst(c);

    int rc = raw_handshake(c, timeout_ms, cancel, err, errcap);
    if (rc != 0) {
        raw_close(c);
        return rc;
    }
    return 0;
}

static int raw_dial(raw_conn *c,const uint8_t *dst,uint8_t family,uint16_t dport,
    int timeout,uint32_t mark,const d2k_detect_stop *stop,int ts,char *err,size_t cap)
{
    return raw_dial_shaped(c,dst,family,dport,timeout,mark,stop,ts,NULL,err,cap);
}

/* probeRawHandshake — самопроверка сырого слоя: доходит ли наше собственное
 * рукопожатие. Проверять его отправкой полезной нагрузки нельзя — поле
 * 2026-08-28, googlevideo: тот фронтенд обслуживает только заблокированные
 * имена, безобидной нагрузки для него не существует, и самопроверка падала не
 * потому, что слой сломан, а потому, что отвечать было не на что. */
int d2k_raw_probe_handshake_as(const uint8_t *ip4, uint8_t family, uint16_t port,
                            int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                            int offer_ts, char *err, size_t errcap)
{
    raw_conn c;
    int dial_rc = raw_dial(&c, ip4, family, port, timeout_ms, mark, cancel,
                           offer_ts ? 1 : 0, err, errcap);
    if (dial_rc != 0) return dial_rc;
    raw_close(&c);
    return 1;
}

/* Текст ошибки зонда попадает в ТРАССУ и сверяется с эталоном построчно.
 * Поэтому здесь голый текст errno, без своей приписки: приписка расходилась бы
 * с эталоном на ровном месте и прятала бы настоящие расхождения. Остаточная
 * разница — сами строки libc (musl «Message too large» против glibc «message
 * too long» на одном и том же EMSGSIZE); она снимается таблицей в
 * tests/compare.sh, а не подгонкой кода. */

/* The measured Plan is the program, not a second description reconstructed
 * after the experiment. Same compiler, parser, TLS modifiers, segmentation,
 * ordering and IP/TCP builder as the datapath. Only the sink differs. */
static int raw_send_program(raw_conn *c, const d2k_trigger *tr, const d2k_poison *p, const char *program,
                         const d2k_detect_stop *cancel, char *err, size_t errcap)
{
    d2k_arm arm;
    d2k_arm_input input = {0};
    d2k_plan *plan = NULL;
    d2k_actions out = {0};
    d2k_pkt pkt = {0};
    d2k_conn conn = {0};
    struct plan_buffers { char text[8192]; uint8_t tlv[D2K_PLAN_TLV_MAX]; uint8_t packet[8192]; };
    struct plan_buffers *b = NULL;
    size_t tn = 0;
    int rc = -1;
    if (errcap) err[0] = '\0';
    b = malloc(sizeof *b);
    if (!b) { snprintf(err, errcap, "нет памяти для измерительного плана"); return -1; }
    if (!program) {
        if (!p || d2k_arm_from_poison(p, &arm, err, errcap)) goto done;
        if (p->decoy_len > sizeof input.decoy || (p->decoy_len && !p->decoy)) {
            snprintf(err, errcap, "приманку измерительного плана нельзя сохранить целиком");
            goto done;
        }
        input.trigger_len = tr->len;
        input.sni_off = tr->sni_off; input.sni_len = tr->sni_len;
        input.decoy_len = p->decoy_len;
        if (p->decoy_len) memcpy(input.decoy, p->decoy, p->decoy_len);
        if (d2k_arm_plan_measured(&arm, &input, b->text, sizeof b->text)) goto done;
        program = b->text;
    }
    if (d2k_plan_text_to_tlv(program, b->tlv, sizeof b->tlv, &tn, err, errcap) ||
        d2k_plan_load(b->tlv, tn, &plan, err, errcap)) goto done;
    pkt.seq = c->seq; pkt.payload = tr->payload; pkt.payload_len = tr->len;
    pkt.segment_cap = seg_max;
    pkt.emit_original = 1;
    pkt.have_sni = tr->sni_off > 0 && tr->sni_len > 0;
    uint32_t stream_offset=c->seq-c->transport_base;
    if(c->transport.available && stream_offset<UINT32_C(0x80000000)) {
        pkt.have_stream_offset=1;pkt.stream_offset=stream_offset;
    }
    pkt.sni_off = tr->sni_off; pkt.sni_len = tr->sni_len;
    if (d2k_plan_apply(plan, NULL, &pkt, &out) || out.fate != D2K_ORIG_DROP) {
        snprintf(err,errcap,"measurement plan apply: %s",
            out.refuse_why ? out.refuse_why : "original not owned");
        goto done;
    }
    conn.family = c->family; conn.ack = c->ack; conn.window = c->data_window ? c->data_window : 65535; conn.ttl = 64;
    memcpy(&conn.src_ip, c->src, 4); memcpy(&conn.dst_ip, c->dst, 4);
    memcpy(conn.src_ip6, c->src, 16); memcpy(conn.dst_ip6, c->dst, 16);
    conn.src_port = htons(c->sport); conn.dst_port = htons(c->dport);
    memcpy(conn.tcp_options, c->tcp_options, c->tcp_options_len);
    conn.tcp_options_len = c->tcp_options_len;
    c->observed.program_packets = out.n;
    c->observed.submitted_packets = 0;
    for (size_t i = 0; i < out.n; i++) {
        uint32_t remaining=out.v[i].delay_us;
        while(remaining) {
            if(d2k_detect_stopped(cancel)) {
                c->observed.kind=D2K_RAW_OBS_CANCELLED;
                snprintf(err,errcap,"context canceled");goto done;
            }
            uint32_t chunk=remaining>50000u?50000u:remaining;
            if(d2k_sleep_us(chunk)) {snprintf(err,errcap,"packet delay failed");goto done;}
            remaining-=chunk;
        }
        if (d2k_detect_stopped(cancel)) {
            c->observed.kind=D2K_RAW_OBS_CANCELLED;
            snprintf(err, errcap, "context canceled"); goto done;
        }
        size_t n = d2k_wire_build(&conn, &out.v[i], b->packet, sizeof b->packet);
        if (!n) {
            snprintf(err,errcap,"measurement plan build packet %zu/%zu",i+1,out.n);
            goto done;
        }
        /* detect-tcp-v1 deliberately fixes the legacy window in wire.c.
         * A shaped episode overrides only that connection-local field. */
        if (c->data_window && c->data_window!=65535) {
            size_t ihl=c->family==6 ? 40 : (b->packet[0]&15u)*4u;
            uint8_t *tcp=b->packet+ihl;
            wr16(tcp+14,c->data_window);wr16(tcp+16,0);
            uint16_t sum=tcp_checksum_family(c->family,c->src,c->dst,tcp,n-ihl);
            if (out.v[i].poison & D2K_POISON_BADSUM) {
                if (out.v[i].wire_profile==D2K_WIRE_DETECT_TCP) {
                    sum^=0xbeef;if (!sum) sum=0x1234;
                } else {
                    sum=(uint16_t)~sum;if (!sum) sum=0xffff;
                }
            }
            wr16(tcp+16,sum);
        }
        if (raw_sendto(c, b->packet, n)) {
            int saved_errno=errno;
            snprintf(err,errcap,"measurement plan send packet %zu/%zu (%zu bytes): %s",
                i+1,out.n,n,strerror(saved_errno));
            goto done;
        }
        c->observed.submitted_packets++;
    }
    /* Historical receive-side grace period; not an emission instruction. */
    if (p && p->disorder && !p->disorder_pos && !p->seqovl && !p->seqovl_exact && !p->fake_between)
        d2k_sleep_ms(12);
    c->seq += (uint32_t)tr->len + (p && p->oob ? 1u : 0u);
    rc = 0;
done:
    if (rc && errcap && !err[0]) snprintf(err, errcap, "не удалось исполнить измерительный план");
    d2k_actions_free(&out); d2k_plan_free(plan); free(b);
    return rc;
}

static int raw_send_plan(raw_conn *c, const d2k_trigger *tr, const d2k_poison *p,
                         const d2k_detect_stop *cancel, char *err, size_t errcap)
{
    return raw_send_program(c, tr, p, NULL, cancel, err, errcap);
}

/* probePoison — ОДИН зонд, собранный из независимых приёмов.
 *
 * Боевое плечо для googlevideo это фальшивка С БИТОЙ СУММОЙ И НИЗКИМ TTL плюс
 * настоящие сегменты, пущенные НЕ ПО ПОРЯДКУ, — всё сразу, в одной стратегии.
 * Зонды, проверяющие приёмы по одному, такую коробку не поймают никогда
 * (замер 2026-08-28: 48 гипотез поодиночке мимо, то же плечо в связке — 10 из
 * 10 на том же адресе). Поэтому здесь два независимых шага: отравить буфер
 * фальшивкой и отдать правду — как есть, задом наперёд или внахлёст слева. */
static int raw_probe_program(const uint8_t *ip4, uint8_t family, uint16_t port,
                         const d2k_trigger *tr, const d2k_poison *p,
                         int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                         char *err, size_t errcap, d2k_raw_observation *observed, const char *program)
{
    uint8_t *resp;
    raw_conn c;
    size_t resp_len = 0;
    int rc = 0;

    int dial_rc = raw_dial(&c, ip4, family, port, timeout_ms, mark, cancel,
                          d2k_trigger_offers_ts(tr), err, errcap);
    if (dial_rc != 0) { if (observed) *observed = c.observed; return dial_rc; }
    resp = c.buffers->resp;

    /* Direct control and SYN-data have no bypass Plan. All expressible
       hypotheses execute the Plan; a compile/apply failure never falls back
       to the old sender and cannot become a positive measurement. */
    if (program || (strcmp(p->name, "none") && !p->syn_data)) {
        if (program ? raw_send_program(&c, tr, NULL, program, cancel, err, errcap) :
                      raw_send_plan(&c, tr, p, cancel, err, errcap)) {
            if (observed) *observed = c.observed;
            raw_close(&c); return -1;
        }
        goto receive;
    }

    /* Non-bypass diagnostics only: direct control / unsupported SYN-data.
       Neither can be promoted to a measured bypass plan by the bridge. */
    d2k_poison none = {0};
    if (raw_send(&c, tr->payload, tr->len,
                 (uint8_t)(TCP_PSH | TCP_ACK | (p->syn_data ? TCP_SYN : 0)), &none)) {
        goto senderr;
    }
    c.seq += (uint32_t)tr->len;

receive:
    c.observed.sent = 1;
    rc = raw_read_payload(&c, timeout_ms, cancel, resp, sizeof(c.buffers->resp), &resp_len, d2k_trigger_prefix_size(tr));
    if (rc == RAW_RECV_ERROR) {
        snprintf(err, errcap, "classify: recvfrom: %s", strerror(errno));
        if (observed) *observed = c.observed;
        raw_close(&c); return -1;
    }
    if (rc != 0) { if (observed) *observed = c.observed; raw_close(&c); return 0; }
    rc = d2k_trigger_accepts(tr, resp, resp_len);
    if (rc > 0) c.observed.kind = D2K_RAW_OBS_ACCEPTED;
    if (observed) *observed = c.observed;
    raw_close(&c);
    return rc;

senderr:
    if (observed) *observed = c.observed;
    snprintf(err, errcap, "%s", strerror(errno));
    raw_close(&c);
    return -1;
}

int d2k_raw_probe_observed(const uint8_t *ip, uint8_t family, uint16_t port,
    const d2k_trigger *tr, const d2k_poison *p, int timeout_ms, uint32_t mark,
    const d2k_detect_stop *cancel, char *err, size_t errcap, d2k_raw_observation *obs)
{
    return raw_probe_program(ip, family, port, tr, p, timeout_ms, mark,
                             cancel, err, errcap, obs, NULL);
}
int d2k_raw_probe_program(const uint8_t *ip, uint8_t family, uint16_t port,
    const d2k_trigger *tr, const char *program, int timeout_ms, uint32_t mark,
    const d2k_detect_stop *cancel, char *err, size_t errcap, d2k_raw_observation *obs)
{
    if (!program || !program[0]) {
        if (obs) memset(obs, 0, sizeof(*obs));
        snprintf(err, errcap, "empty measurement program");
        return -1;
    }
    return raw_probe_program(ip, family, port, tr, NULL, timeout_ms, mark,
                             cancel, err, errcap, obs, program);
}

#else /* !__linux__ */

/* Сырого слоя вне Linux нет. Это не заглушка «на будущее»: отрицательный
 * результат отравления без сырых сокетов не означает ничего, и вердикт обязан
 * это сказать (см. res.RawUsable в эталоне), а не промолчать. */
int d2k_raw_supported(void) { return 0; }
void d2k_raw_set_segment_max(unsigned seg) { (void)seg; }
unsigned d2k_raw_segment_max(void) { return D2K_ARM_SEGMENT_MAX; }
unsigned long d2k_raw_rst_fail_count(void) { return 0; }
unsigned long d2k_raw_dial_count(void) { return 0; }
void d2k_raw_flush_pending(void) {}
size_t d2k_raw_pending_count(void) { return 0; }

int d2k_raw_probe_observed(const uint8_t *ip4, uint8_t family, uint16_t port,
                         const d2k_trigger *tr, const d2k_poison *p,
                         int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                         char *err, size_t errcap, d2k_raw_observation *observed)
{
    if (observed) memset(observed, 0, sizeof(*observed));
    (void)family; (void)ip4; (void)port; (void)tr; (void)p; (void)timeout_ms; (void)mark; (void)cancel;
    snprintf(err, errcap, "classify: сырой слой доступен только на Linux");
    return -1;
}

int d2k_raw_probe_program(const uint8_t *ip, uint8_t family, uint16_t port,
    const d2k_trigger *tr, const char *program, int timeout_ms, uint32_t mark,
    const d2k_detect_stop *cancel, char *err, size_t errcap, d2k_raw_observation *obs)
{
    (void)program;
    return d2k_raw_probe_observed(ip, family, port, tr, NULL, timeout_ms, mark,
                                  cancel, err, errcap, obs);
}

int d2k_raw_probe_handshake_as(const uint8_t *ip4, uint8_t family, uint16_t port,
                            int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                            int offer_ts, char *err, size_t errcap)
{
    (void)family; (void)ip4; (void)port; (void)timeout_ms; (void)mark; (void)cancel;
    (void)offer_ts;
    snprintf(err, errcap, "classify: сырой слой доступен только на Linux");
    return -1;
}

#endif /* __linux__ */

int d2k_raw_probe_handshake(const uint8_t ip4[4], uint16_t port,
    int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel, char *err, size_t errcap)
{
    return d2k_raw_probe_handshake_family(ip4, 4, port, timeout_ms, mark, cancel, err, errcap);
}

/* Прежняя подпись — прежний набор с меткой времени. */
int d2k_raw_probe_handshake_family(const uint8_t *ip4, uint8_t family, uint16_t port,
                            int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                            char *err, size_t errcap)
{
    return d2k_raw_probe_handshake_as(ip4, family, port, timeout_ms, mark, cancel, 1,
                                      err, errcap);
}

int d2k_raw_probe_poison(const uint8_t ip4[4], uint16_t port,
    const d2k_trigger *tr, const d2k_poison *p, int timeout_ms, uint32_t mark,
    const d2k_detect_stop *cancel, char *err, size_t errcap)
{
    return d2k_raw_probe_poison_family(ip4, 4, port, tr, p, timeout_ms, mark, cancel, err, errcap);
}

int d2k_raw_probe_poison_family(const uint8_t *ip, uint8_t family, uint16_t port,
    const d2k_trigger *tr, const d2k_poison *p, int timeout_ms, uint32_t mark,
    const d2k_detect_stop *cancel, char *err, size_t errcap)
{
    return d2k_raw_probe_observed(ip, family, port, tr, p, timeout_ms, mark,
                                  cancel, err, errcap, NULL);
}

#if defined(__linux__) || defined(D2K_RAW_UNIT_TEST)
struct d2k_raw_episode { raw_conn conn; uint32_t base, peer_base, sent_end; int active, defer_ack, pending_ack; };
int d2k_raw_episode_tuple(const d2k_raw_episode *ep,d2k_raw_tuple *out) {
    if(out)memset(out,0,sizeof *out);
    if(!ep || !out)return 0;
    const raw_conn *c=&ep->conn;
    if((c->family!=4 && c->family!=6) || !c->sport || !c->dport)return 0;
    size_t n=c->family==6?16:4;
    memcpy(out->local,c->src,n);memcpy(out->remote,c->dst,n);
    out->family=c->family;out->local_port=c->sport;out->remote_port=c->dport;
    out->initial_seq=ep->base-1;return 1;
}
static void episode_abort(d2k_raw_episode *ep)
{
    if(ep && ep->active) { raw_close(&ep->conn); ep->active=0; }
}
d2k_raw_episode *d2k_raw_episode_open_shaped(const uint8_t *ip,uint8_t family,uint16_t port,
    int timeout,uint32_t mark,int ts,const d2k_raw_shape *shape,const d2k_detect_stop *stop,char *err,size_t cap,
    d2k_raw_observation *obs)
{
    if(obs) memset(obs,0,sizeof *obs);
    if(!ip || (family!=4 && family!=6) || !port || timeout<=0 ||
        (shape && (shape->syn_wscale < -1 || shape->syn_wscale > 14 ||
                   (!shape->syn_retry_ms != !shape->syn_max_sends)))) {
        snprintf(err,cap,"invalid episode endpoint or timeout"); return NULL;
    }
    d2k_raw_episode *ep=calloc(1,sizeof *ep);
    if(!ep) {snprintf(err,cap,"episode allocation failed");return NULL;}
    int rc=raw_dial_shaped(&ep->conn,ip,family,port,timeout,mark,stop,ts,shape,err,cap);
    if(obs) *obs=ep->conn.observed;
    if(rc) {free(ep);return NULL;}
    ep->active=1;ep->base=ep->conn.seq;ep->peer_base=ep->conn.ack;
    ep->defer_ack=shape && shape->defer_response_ack;
    ep->conn.transport.available=1;ep->conn.transport_base=ep->base;
    ep->conn.observed.transport=ep->conn.transport;
    if(obs)*obs=ep->conn.observed;
    return ep;
}
int d2k_raw_episode_set_window(d2k_raw_episode *ep,uint16_t window)
{
    if (!ep || !ep->active) return -1;
    ep->conn.data_window=window;return 0;
}
int d2k_raw_episode_reset(d2k_raw_episode *ep)
{
    if (!ep || !ep->active) return -1;
    raw_conn *c=&ep->conn;
    if (!c->rule_up) {episode_abort(ep);return -1;}
    rst_key key=rst_key_of(c);
    pthread_mutex_lock(&g_raw_state);
    int removed=rst_delete_once(&key);
    pthread_mutex_unlock(&g_raw_state);
    if (!removed) return -1; /* Never send a reset while suppression remains. */
    c->rule_up=0;
    d2k_poison none={0};
    int rc=raw_send(c,NULL,0,TCP_RST,&none);
    c->rule_up=suppress_kernel_rst(c);
    if (!c->rule_up) rc=-1;
    episode_abort(ep);
    return rc;
}
int d2k_raw_episode_send(d2k_raw_episode *ep,uint32_t offset,uint32_t next_offset,const d2k_trigger *tr,
    const char *plan,const d2k_detect_stop *stop,char *err,size_t cap,d2k_raw_observation *obs)
{
    if(obs) memset(obs,0,sizeof *obs);
    if(!ep || !ep->active) {snprintf(err,cap,"episode is closed");return -1;}
    raw_conn *c=&ep->conn;
    memset(&c->observed,0,sizeof c->observed);c->observed.connected=1;
    c->observed.transport=c->transport;
    if(!tr || !tr->len || tr->len>sizeof tr->payload || !plan || !*plan) {
        snprintf(err,cap,"invalid episode program or payload");
        if(obs) *obs=c->observed;
        episode_abort(ep);return -1;
    }
    c->seq=ep->base+offset;
    int rc=raw_send_program(c,tr,NULL,plan,stop,err,cap);
    if(rc) {
        if(d2k_detect_stopped(stop)) c->observed.kind=D2K_RAW_OBS_CANCELLED;
    } else { c->observed.sent=1;c->seq=ep->base+next_offset;
        if(next_offset>ep->sent_end) ep->sent_end=next_offset;
        if(next_offset<UINT32_C(0x80000000) && next_offset>c->transport.sent_end)
            c->transport.sent_end=next_offset;
        else if(next_offset>=UINT32_C(0x80000000))c->transport.available=0;
        c->observed.transport=c->transport; }
    if(obs) *obs=c->observed;
    if(rc) episode_abort(ep);
    return rc;
}
int d2k_raw_episode_read(d2k_raw_episode *ep,int timeout,const d2k_detect_stop *stop,
    uint8_t *buf,size_t cap,size_t *have,size_t minimum,d2k_raw_observation *obs)
{
    if(obs) memset(obs,0,sizeof *obs);
    if(have) *have=0;
    if(!ep || !ep->active) return RAW_RECV_ERROR;
    raw_conn *c=&ep->conn;
    c->observed.kind=D2K_RAW_OBS_LOCAL;c->observed.response_bytes=0;
    if(!buf || !have || !minimum || minimum>cap || timeout<=0) {
        if(obs) *obs=c->observed;
        episode_abort(ep);return RAW_RECV_ERROR;
    }
    int rc=raw_read_payload(c,timeout,stop,buf,cap,have,minimum);
    if(!rc) {
        d2k_poison none={0};
        if(raw_send(c,NULL,0,TCP_ACK,&none)) {
            c->observed.kind=D2K_RAW_OBS_LOCAL;rc=RAW_RECV_ERROR;
        }
    }

    if(obs) *obs=c->observed;
    if(rc && c->observed.kind!=D2K_RAW_OBS_RESPONSE_TIMEOUT) episode_abort(ep);
    return rc;
}
void d2k_raw_episode_free(d2k_raw_episode *ep)
{
    episode_abort(ep);free(ep);
}
#else

d2k_raw_episode *d2k_raw_episode_open_shaped(const uint8_t *ip,uint8_t family,uint16_t port,
    int timeout,uint32_t mark,int ts,const d2k_raw_shape *shape,const d2k_detect_stop *stop,char *err,size_t cap,
    d2k_raw_observation *obs)
{
    (void)shape;(void)ip;(void)family;(void)port;(void)timeout;(void)mark;(void)ts;
    (void)stop;if(obs) memset(obs,0,sizeof *obs);snprintf(err,cap,"raw episodes require Linux");return NULL;
}
int d2k_raw_episode_set_window(d2k_raw_episode *ep,uint16_t window)
{ (void)ep;(void)window;return -1; }
int d2k_raw_episode_reset(d2k_raw_episode *ep)
{ (void)ep;return -1; }
int d2k_raw_episode_send(d2k_raw_episode *ep,uint32_t offset,uint32_t next_offset,const d2k_trigger *tr,
    const char *plan,const d2k_detect_stop *stop,char *err,size_t cap,d2k_raw_observation *obs)
{
    (void)ep;(void)offset;(void)next_offset;(void)tr;(void)plan;(void)stop;if(obs) memset(obs,0,sizeof *obs);snprintf(err,cap,"raw episodes require Linux");return -1;
}
int d2k_raw_episode_read(d2k_raw_episode *ep,int timeout,const d2k_detect_stop *stop,
    uint8_t *buf,size_t cap,size_t *have,size_t minimum,d2k_raw_observation *obs)
{
    (void)ep;(void)timeout;(void)stop;(void)buf;(void)cap;(void)minimum;if(have) *have=0;if(obs) memset(obs,0,sizeof *obs);return -2;
}
void d2k_raw_episode_free(d2k_raw_episode *ep) { (void)ep; }
int d2k_raw_episode_tuple(const d2k_raw_episode *ep,d2k_raw_tuple *out) {
    (void)ep;if(out)memset(out,0,sizeof *out);return 0;
}

#endif
d2k_raw_episode *d2k_raw_episode_open(const uint8_t *ip,uint8_t family,uint16_t port,
    int timeout,uint32_t mark,int ts,const d2k_detect_stop *stop,char *err,size_t cap,
    d2k_raw_observation *obs)
{
    return d2k_raw_episode_open_shaped(ip,family,port,timeout,mark,ts,NULL,stop,err,cap,obs);
}
int d2k_raw_episode_event(d2k_raw_episode *ep,int timeout,const d2k_detect_stop *stop,
    uint8_t *buf,size_t cap,d2k_raw_packet_event *event,d2k_raw_observation *obs)
{
    if(event) memset(event,0,sizeof *event);
    if(obs) memset(obs,0,sizeof *obs);
#if defined(__linux__) || defined(D2K_RAW_UNIT_TEST)
    if(!ep || !ep->active) return RAW_RECV_ERROR;
    raw_conn *c=&ep->conn;
    c->observed.kind=D2K_RAW_OBS_LOCAL;c->observed.response_bytes=0;
    if(!event || (!buf && cap) || timeout<=0) {
        if(obs) *obs=c->observed;
        episode_abort(ep);return RAW_RECV_ERROR;
    }
    if(ep->pending_ack) {
        d2k_poison none={0};
        if(d2k_detect_stopped(stop) || raw_send(c,NULL,0,TCP_ACK,&none)) {
            if(obs)*obs=c->observed;
            episode_abort(ep);return RAW_RECV_ERROR;
        }
        ep->pending_ack=0;
    }
    int64_t deadline=d2k_now_ms()+timeout;
    while(d2k_now_ms()<deadline) {
        if(d2k_detect_stopped(stop)) {
            c->observed.kind=D2K_RAW_OBS_CANCELLED;
            if(obs) *obs=c->observed;
            episode_abort(ep);return -1;
        }
        uint8_t flags;uint32_t seq,ack;const uint8_t *payload;size_t n;
        int rc=raw_recv(c,&flags,&seq,&ack,&payload,&n,deadline,stop);
        if(rc==RAW_RECV_ERROR) {
            if(obs) *obs=c->observed;
            episode_abort(ep);return rc;
        }
        if(rc) continue;
        if(n>cap) {
            if(obs) *obs=c->observed;
            episode_abort(ep);return RAW_RECV_ERROR;
        }
        event->flags=flags;event->sequence_offset=seq-ep->peer_base;
        event->ack_offset=ack-ep->base;event->payload_len=n;
        event->ack_in_sent_range=(flags&TCP_ACK) && event->ack_offset<=ep->sent_end;
        if(n) memcpy(buf,payload,n);
        c->observed.response_bytes=n;
        c->observed.kind=(flags&TCP_RST)?D2K_RAW_OBS_RESPONSE_RESET:
            (flags&TCP_FIN)?D2K_RAW_OBS_RESPONSE_FIN:
            n?D2K_RAW_OBS_RESPONSE_BYTES:
            (flags&TCP_ACK)?D2K_RAW_OBS_RESPONSE_ACK:D2K_RAW_OBS_RESPONSE_PACKET;
        int finished=0;
        if(flags&TCP_RST) finished=seq==c->ack;
        else if(event->ack_in_sent_range && !(flags&TCP_SYN)) {
            if((int32_t)(seq-c->ack)<=0) {
                uint32_t skip=c->ack-seq;
                if(skip<n) c->ack+=(uint32_t)(n-skip);
            }
            if((flags&TCP_FIN) && seq+(uint32_t)n==c->ack) {c->ack++;finished=1;}
            if(n || (flags&TCP_FIN)) {
                d2k_poison none={0};
                if(ep->defer_ack && !finished) ep->pending_ack=1;
                else if(raw_send(c,NULL,0,TCP_ACK,&none)) {
                    c->observed.kind=D2K_RAW_OBS_LOCAL;
                    if(obs) *obs=c->observed;
                    episode_abort(ep);return RAW_RECV_ERROR;
                }
            }
        }
        if(obs) *obs=c->observed;
        if(finished) episode_abort(ep);
        return 0;
    }
    c->observed.kind=D2K_RAW_OBS_RESPONSE_TIMEOUT;
    if(obs) *obs=c->observed;
    return -1;
#else
    (void)ep;(void)timeout;(void)stop;(void)buf;(void)cap;return -2;
#endif
}
