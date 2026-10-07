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
#include "d2k_arm.h"

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
    uint8_t fake[2 * D2K_TRIGGER_MAX];
    uint8_t seg[D2K_TRIGGER_MAX + 4096];
    uint8_t resp[8192];
} raw_buffers;

typedef struct {
    int      send_fd;
    int      recv_fd;
    uint8_t  src[16];
    uint8_t  dst[16];
    uint8_t  family; /* 0/4 IPv4, 6 IPv6 */
    uint16_t sport;
    uint16_t dport;
    uint32_t seq; /* наш следующий номер */
    uint32_t ack; /* что подтверждаем */
    int      rule_up;
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
static size_t build_ip_tcp(uint8_t *pkt, size_t cap, uint8_t family,
                            const uint8_t *src, const uint8_t *dst,
                            uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                            uint8_t flags, const uint8_t *payload, size_t plen,
                            const d2k_poison *p, const uint8_t *extra, size_t extralen)
{
    if (family != 6)
        return build_ipv4_tcp(pkt, cap, src, dst, sport, dport, seq, ack, flags,
                               payload, plen, p, extra, extralen);
    if (cap < 60 || p->ip_id_zero) return 0;
    size_t n = build_ipv4_tcp(pkt + 20, cap - 20, src, dst, sport, dport,
                              seq, ack, flags, payload, plen, p, extra, extralen);
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
 * 1400 — с запасом под PPPoE (1492) и под опции TCP в нашем же заголовке. */
#define D2K_SEG_MAX D2K_ARM_SEGMENT_MAX

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
        if (take > D2K_SEG_MAX) {
            take = D2K_SEG_MAX;
        }
        n = build_ip_tcp(pkt, sizeof(pkt), c->family, c->src, c->dst, c->sport, c->dport,
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

/* The measured pos=2 multidisorder candidate is exactly two segments, sent
 * tail first and then the original two-byte prefix. Keep this separate from
 * SNI-middle disorder: it has neither the third one-byte segment nor a pace. */
static int raw_send_disorder_pos(raw_conn *c, const d2k_trigger *tr,
                                 uint32_t base, size_t split)
{
    d2k_poison none;
    memset(&none, 0, sizeof none);
    if (!c || !tr || split == 0 || split >= tr->len) { return -1; }
    c->seq = base + (uint32_t)split;
    if (raw_send(c, tr->payload + split, tr->len - split,
                 (uint8_t)(TCP_PSH | TCP_ACK), &none) != 0) { return -1; }
    c->seq = base;
    return raw_send(c, tr->payload, split, (uint8_t)(TCP_PSH | TCP_ACK), &none);
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
    uint8_t pkt[256];
    d2k_poison none;
    size_t n;

    memset(&none, 0, sizeof(none));
    n = build_ip_tcp(pkt, sizeof(pkt), c->family, c->src, c->dst, c->sport, c->dport,
                       c->seq, 0, TCP_SYN, NULL, 0, &none, opts, sizeof(opts));
    if (n == 0) {
        return -1;
    }
    return raw_sendto(c, pkt, n);
}

/* recv возвращает следующий сегмент ОТ НАШЕГО пира. */
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
        struct sockaddr_storage peer;
        socklen_t peerlen = sizeof peer;
        ssize_t n = recvfrom(c->recv_fd, buf, sizeof(c->buffers->recv), 0,
                              (struct sockaddr *)&peer, &peerlen);
        size_t ihl, off;
        const uint8_t *t;
        size_t tlen;
        if (n < 0) {
            return -1;
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
        return 0;
    }
}

/* readPayload ждёт от сервера сегмент с данными. */
static int raw_read_payload(raw_conn *c, int timeout_ms, const d2k_detect_stop *cancel,
                            uint8_t *out, size_t cap, size_t *outlen)
{
    int64_t deadline = d2k_now_ms() + timeout_ms;
    while (d2k_now_ms() < deadline) {
        uint8_t flags;
        if (d2k_detect_stopped(cancel)) {
            return -1;
        }
        uint32_t seq, ack;
        const uint8_t *pay;
        size_t plen;
        if (raw_recv(c, &flags, &seq, &ack, &pay, &plen, deadline, cancel) != 0) {
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
}

static int raw_handshake(raw_conn *c, int timeout_ms, const d2k_detect_stop *cancel,
                         char *err, size_t errcap)
{
    int64_t deadline;
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
        if (d2k_detect_stopped(cancel)) {
            snprintf(err, errcap, "context canceled");
            return -1;
        }
        if (raw_recv(c, &flags, &seq, &ack, &pay, &plen, deadline, cancel) != 0) {
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
static int raw_dial(raw_conn *c, const uint8_t *dst, uint8_t family, uint16_t dport,
                    int timeout_ms, uint32_t mark_val, const d2k_detect_stop *cancel,
                    char *err, size_t errcap)
{
    int one = 1;
    int mark = (int)mark_val;
    struct timeval tv;

    memset(c, 0, sizeof(*c));
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
    tv.tv_usec = 300000;
    (void)setsockopt(c->recv_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Подметаем один раз за прогон, а не перед каждым зондом: зондов сотни, а
     * разбор таблицы стоит вызова iptables. */
    /* Other workers must wait for cleanup to finish before creating rules;
     * otherwise first-use cleanup can delete a new worker's live rule. */
    pthread_once(&g_sweep_once, sweep_stale_rst_rules);
    c->sport = next_source_port();
    seed_once();
    c->seq = (uint32_t)random();
    /* Как у донора (suppressKernelRST): без правила мерить ПРОДОЛЖАЕМ —
     * ядерный RST прилетает после SYN-ACK, а зонд к тому времени часто уже
     * пишет данные. Отказ iptables (нет бинарника, роутер только на nft) —
     * своя поломка, а не свойство сети: вернув ошибку, мы роняли
     * самопроверку, и цель уходила в «обойти нечем». Факт отказа не молчит:
     * он считается в t_rst_rule_failures потока (трасса вердикта и адаптер
     * планировщика сравнивают d2k_raw_rst_fail_count со стартом прогона). */
    t_raw_dials++;
    c->rule_up = suppress_kernel_rst(c);

    if (raw_handshake(c, timeout_ms, cancel, err, errcap) != 0) {
        raw_close(c);
        return -1;
    }
    return 0;
}

/* sendURG шлёт один байт как срочные данные: флаг URG плюс указатель за ним.
 * Сервер по RFC 793 изымает такой байт из потока, коробка — обычно нет. */
static int raw_send_urg(raw_conn *c, const uint8_t *payload, size_t plen)
{
    uint8_t pkt[256];
    d2k_poison none;
    size_t n;
    uint8_t *t;
    uint16_t sum;

    memset(&none, 0, sizeof(none));
    n = build_ip_tcp(pkt, sizeof(pkt), c->family, c->src, c->dst, c->sport, c->dport,
                       c->seq, c->ack, (uint8_t)(TCP_PSH | TCP_ACK | TCP_URG),
                       payload, plen, &none, NULL, 0);
    if (n == 0) {
        return -1;
    }
    size_t ihl = c->family == 6 ? 40 : 20;
    t = pkt + ihl;
    /* Указатель срочности — сразу за нашим байтом. */
    t[18] = 0x00;
    t[19] = (uint8_t)plen;
    sum = tcp_checksum_family(c->family, c->src, c->dst, t, n - ihl);
    wr16(t + 16, sum);
    return raw_sendto(c, pkt, n);
}

/* probeRawHandshake — самопроверка сырого слоя: доходит ли наше собственное
 * рукопожатие. Проверять его отправкой полезной нагрузки нельзя — поле
 * 2026-08-28, googlevideo: тот фронтенд обслуживает только заблокированные
 * имена, безобидной нагрузки для него не существует, и самопроверка падала не
 * потому, что слой сломан, а потому, что отвечать было не на что. */
int d2k_raw_probe_handshake_family(const uint8_t *ip4, uint8_t family, uint16_t port,
                            int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                            char *err, size_t errcap)
{
    raw_conn c;
    if (raw_dial(&c, ip4, family, port, timeout_ms, mark, cancel, err, errcap) != 0) {
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
int d2k_raw_probe_poison_family(const uint8_t *ip4, uint8_t family, uint16_t port,
                         const d2k_trigger *tr, const d2k_poison *p,
                         int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                         char *err, size_t errcap)
{
    uint8_t *fake, *seg, *resp;
    raw_conn c;
    d2k_poison none;
    uint32_t base;
    size_t resp_len = 0;
    int rc = 0;
    size_t n = tr->len;

    memset(&none, 0, sizeof(none));
    if (raw_dial(&c, ip4, family, port, timeout_ms, mark, cancel, err, errcap) != 0) {
        return -1;
    }
    fake = c.buffers->fake;
    seg = c.buffers->seg;
    resp = c.buffers->resp;

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
        if (flen > sizeof(c.buffers->fake)) {
            flen = sizeof(c.buffers->fake);
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
                if (d2k_detect_stopped(cancel)) {
                    raw_close(&c);
                    snprintf(err, errcap, "context canceled");
                    return -1;
                }
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
        if (raw_read_payload(&c, timeout_ms, cancel, resp, sizeof(c.buffers->resp),
                             &resp_len) != 0) {
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
        if (flen > sizeof(c.buffers->fake)) {
            flen = sizeof(c.buffers->fake);
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
    } else if (p->disorder_pos > 0) {
        if (raw_send_disorder_pos(&c, tr, base, (size_t)p->disorder_pos) != 0) {
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
        if (ov + 1 > sizeof(c.buffers->seg)) {
            ov = sizeof(c.buffers->seg) - 1;
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
        if (ov + n > sizeof(c.buffers->seg)) {
            ov = sizeof(c.buffers->seg) - n;
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

    if (raw_read_payload(&c, timeout_ms, cancel, resp, sizeof(c.buffers->resp),
                         &resp_len) != 0) {
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
unsigned long d2k_raw_rst_fail_count(void) { return 0; }
unsigned long d2k_raw_dial_count(void) { return 0; }
void d2k_raw_flush_pending(void) {}
size_t d2k_raw_pending_count(void) { return 0; }

int d2k_raw_probe_poison_family(const uint8_t *ip4, uint8_t family, uint16_t port,
                         const d2k_trigger *tr, const d2k_poison *p,
                         int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                         char *err, size_t errcap)
{
    (void)family; (void)ip4; (void)port; (void)tr; (void)p; (void)timeout_ms; (void)mark; (void)cancel;
    snprintf(err, errcap, "classify: сырой слой доступен только на Linux");
    return -1;
}

int d2k_raw_probe_handshake_family(const uint8_t *ip4, uint8_t family, uint16_t port,
                            int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                            char *err, size_t errcap)
{
    (void)family; (void)ip4; (void)port; (void)timeout_ms; (void)mark; (void)cancel;
    snprintf(err, errcap, "classify: сырой слой доступен только на Linux");
    return -1;
}

#endif /* __linux__ */

int d2k_raw_probe_handshake(const uint8_t ip4[4], uint16_t port,
    int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel, char *err, size_t errcap)
{
    return d2k_raw_probe_handshake_family(ip4, 4, port, timeout_ms, mark, cancel, err, errcap);
}

int d2k_raw_probe_poison(const uint8_t ip4[4], uint16_t port,
    const d2k_trigger *tr, const d2k_poison *p, int timeout_ms, uint32_t mark,
    const d2k_detect_stop *cancel, char *err, size_t errcap)
{
    return d2k_raw_probe_poison_family(ip4, 4, port, tr, p, timeout_ms, mark, cancel, err, errcap);
}
