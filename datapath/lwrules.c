#define _POSIX_C_SOURCE 200809L
/* Правила точного кортежа conntrack — запасной способ поздней доставки
   (этап 53), см. include/d2k_lwrules.h. Только поток исполнителя. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include "d2k_lwrules.h"

extern char **environ;

enum { SIDE_OUT = 0, SIDE_IN = 1 };

/* argv одного правила: op — "-C"/"-A"/"-D". Буферы — в b. */
typedef struct {
    char *argv[40];
    char wait[24], src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN], sp[8], dp[8], q[12];
} rule_argv;

/* Запуск с определением формы срока ожидания: --wait=N, а если iptables его не
   знает (код 2) — простое -w; форма запоминается. wait_at — индекс токена срока. */
static int run_wait(d2k_lwrules *r, char **argv, size_t wait_at, char *wait_buf, size_t cap) {
    unsigned s = r->lock_wait_s ? r->lock_wait_s : 5;
    if (r->wait_form != 2) {
        snprintf(wait_buf, cap, "--wait=%u", s);
        argv[wait_at] = wait_buf;
        int rc = r->run(r->ctx, argv);
        if (rc != 2 || r->wait_form == 1) { if (rc != 2) r->wait_form = 1; return rc; }
        r->wait_form = 2;          /* старый iptables: --wait=N не знает */
    }
    argv[wait_at] = (char *)"-w";
    return r->run(r->ctx, argv);
}

static const char *tool_of(const d2k_ct_tuple *t) { return t->family == 6 ? "ip6tables" : "iptables"; }

static void build(d2k_lwrules *r, const d2k_ct_tuple *t, int side, const char *op, rule_argv *b) {
    int af = t->family == 6 ? AF_INET6 : AF_INET;
    if (!inet_ntop(af, t->src, b->src, sizeof b->src)) b->src[0] = 0;
    if (!inet_ntop(af, t->dst, b->dst, sizeof b->dst)) b->dst[0] = 0;
    snprintf(b->sp, sizeof b->sp, "%u", (unsigned)(t->sport_be[0] << 8 | t->sport_be[1]));
    snprintf(b->dp, sizeof b->dp, "%u", (unsigned)(t->dport_be[0] << 8 | t->dport_be[1]));
    snprintf(b->q, sizeof b->q, "%u", r->queue);
    const char *proto = t->proto == 17 ? "udp" : "tcp";
    size_t i = 0;
    b->argv[i++] = (char *)tool_of(t);
    b->argv[i++] = (char *)"-w";                 /* форма срока — run_wait */
    b->argv[i++] = (char *)"-t"; b->argv[i++] = (char *)"mangle";
    b->argv[i++] = (char *)op;
    b->argv[i++] = (char *)(side == SIDE_OUT ? r->chain_out : r->chain_in);
    b->argv[i++] = (char *)"-p"; b->argv[i++] = (char *)proto;
    b->argv[i++] = (char *)"-m"; b->argv[i++] = (char *)"conntrack";
    b->argv[i++] = (char *)"--ctdir"; b->argv[i++] = (char *)(side == SIDE_OUT ? "ORIGINAL" : "REPLY");
    b->argv[i++] = (char *)"--ctproto"; b->argv[i++] = (char *)proto;
    b->argv[i++] = (char *)"--ctorigsrc"; b->argv[i++] = b->src;
    b->argv[i++] = (char *)"--ctorigdst"; b->argv[i++] = b->dst;
    b->argv[i++] = (char *)"--ctorigsrcport"; b->argv[i++] = b->sp;
    b->argv[i++] = (char *)"--ctorigdstport"; b->argv[i++] = b->dp;
    b->argv[i++] = (char *)"-j"; b->argv[i++] = (char *)"NFQUEUE";
    b->argv[i++] = (char *)"--queue-num"; b->argv[i++] = b->q;
    b->argv[i++] = (char *)"--queue-bypass";
    b->argv[i] = NULL;
}

static int rule(d2k_lwrules *r, const d2k_ct_tuple *t, int side, const char *op) {
    rule_argv b;
    build(r, t, side, op, &b);
    return run_wait(r, b.argv, 1, b.wait, sizeof b.wait);
}

/* -C: 0 — есть, 1 — нет; прочее (блокировка, параметры) — не знаем. */
int d2k_lwrules_install(d2k_lwrules *r, const d2k_ct_tuple *t) {
    int added[2] = {0, 0};
    for (int side = SIDE_OUT; side <= SIDE_IN; side++) {
        int c = rule(r, t, side, "-C");
        if (c == 0) continue;
        if (c == 1 && rule(r, t, side, "-A") == 0) { added[side] = 1; continue; }
        /* Сторона не встала: откат того, что поставила эта операция. */
        for (int s = SIDE_OUT; s < side; s++)
            if (added[s] && rule(r, t, s, "-D") != 0) return -1;   /* откат не удался — неясно */
        return -1;
    }
    return 0;
}

/* OK/GONE — только когда -C подтвердил отсутствие ОБЕИХ сторон; остаток после
   прохода (дубли сверх предела) — FAIL, снятие повторится (находка ревью). */
int d2k_lwrules_clear(d2k_lwrules *r, const d2k_ct_tuple *t) {
    int removed = 0;
    for (int side = SIDE_OUT; side <= SIDE_IN; side++) {
        int absent = 0;
        for (int k = 0; k < 8 && !absent; k++) {
            int c = rule(r, t, side, "-C");
            if (c == 1) { absent = 1; break; }
            if (c != 0) return -1;
            if (rule(r, t, side, "-D") != 0) return -1;
            removed = 1;
        }
        if (!absent && rule(r, t, side, "-C") != 1) return -1;
    }
    return removed ? 0 : 1;
}

int d2k_lwrules_sweep(d2k_lwrules *r) {
    static const char *tools[2] = {"iptables", "ip6tables"};
    char wait[24];
    for (int f = 0; f < 2; f++) {
        for (int c = 0; c < 2; c++) {
            const char *chain = c ? r->chain_in : r->chain_out;
            char *nargv[] = {(char *)tools[f], (char *)"-w", (char *)"-t", (char *)"mangle", (char *)"-N",
                             (char *)chain, NULL};
            (void)run_wait(r, nargv, 1, wait, sizeof wait);   /* уже есть — ладно */
            char *fargv[] = {(char *)tools[f], (char *)"-w", (char *)"-t", (char *)"mangle", (char *)"-F",
                             (char *)chain, NULL};
            if (run_wait(r, fargv, 1, wait, sizeof wait) != 0) return -1;
        }
    }
    return 0;
}

/* Путь программы — в родителе (поиск по PATH до fork: в потомке только
   async-signal-safe вызовы). */
static int resolve(const char *name, char *out, size_t cap) {
    if (strchr(name, '/')) { snprintf(out, cap, "%s", name); return access(out, X_OK) == 0 ? 0 : -1; }
    const char *path = getenv("PATH");
    if (!path || !*path) path = "/usr/sbin:/usr/bin:/sbin:/bin";
    for (const char *p = path; *p;) {
        const char *e = strchr(p, ':');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n && n + 1 + strlen(name) < cap) {
            memcpy(out, p, n); out[n] = '/'; strcpy(out + n + 1, name);
            if (access(out, X_OK) == 0) return 0;
        }
        p += n + (e ? 1 : 0);
        if (!e) break;
    }
    return -1;
}

/* ПОТОМОК НЕ ПЕРЕЖИВАЕТ D2KD И НЕ НАСЛЕДУЕТ ЗАБЛОКИРОВАННЫЕ СИГНАЛЫ (находки
   ревью, этап 53). Поток исполнителя блокирует все сигналы — потомок с той же
   маской не получает SIGALRM срока --wait=N и ждёт блокировку без конца; маска
   потомка — пустая. После SIGKILL d2kd «медленный» iptables вернул бы правило,
   уже убранное уборкой нового d2kd: на Linux потомок получает
   PR_SET_PDEATHSIG=SIGKILL и сам выходит, если родитель умер до prctl. Вывод —
   в /dev/null. Ожидание — только EINTR повторяется. */
int d2k_lwrules_spawn(void *ctx, char *const argv[]) {
    unsigned deadline_s = ctx ? *(const unsigned *)ctx : 0;
    char path[512];
    if (!argv || !argv[0] || resolve(argv[0], path, sizeof path) != 0) return -1;
    pid_t pid;
#ifdef __linux__
    pid_t parent = getpid();
    pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) _exit(127);
        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); if (fd > 2) close(fd); }
        execv(path, argv);
        _exit(127);
    }
#else
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    posix_spawnattr_init(&at);
    sigset_t empty;
    sigemptyset(&empty);
    posix_spawnattr_setsigmask(&at, &empty);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGMASK);
    int e = posix_spawn(&pid, path, &fa, &at, argv, environ);
    posix_spawnattr_destroy(&at);
    posix_spawn_file_actions_destroy(&fa);
    if (e != 0) return -1;
#endif
    int st = 0;
    struct timespec t0, now, nap = {0, 20000000L};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        pid_t w = waitpid(pid, &st, deadline_s ? WNOHANG : 0);
        if (w == pid) break;
        if (w < 0 && errno != EINTR) return -1;  /* потомка не дождаться — итога нет */
        if (w == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            if ((unsigned long)(now.tv_sec - t0.tv_sec) >= deadline_s) {
                /* Внешний срок: старый iptables ждёт блокировку без конца. */
                kill(pid, SIGKILL);
                while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
                return -1;
            }
            nanosleep(&nap, NULL);
        }
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}
