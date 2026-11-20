#define _POSIX_C_SOURCE 200809L
#include "../runtime/d2k_runtime.h"
#include "server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef D2K_PANEL_VERSION
#define D2K_PANEL_VERSION "dev"
#endif
#ifndef D2K_PANEL_COMMIT
#define D2K_PANEL_COMMIT ""
#endif
#ifndef D2K_PANEL_BUILT
#define D2K_PANEL_BUILT ""
#endif
#ifndef D2K_PANEL_DIRTY
#define D2K_PANEL_DIRTY 0
#endif
#define D2K_PANEL_FEATURES "telegram-control update-control"

#define UNKNOWN_MAX 64
#define UNKNOWN_KEY_MAX 128
#define CONFIG_LINE_MAX 2048

static const char *health_path = "/tmp/d2k/d2kpanel.health";
static volatile sig_atomic_t stop_requested;

static void on_signal(int sig) {
    (void)sig;
    stop_requested = 1;
}

static void say(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void usage(FILE *f) {
    fputs("d2kpanel --version | serve [--config FILE] [--live FILE] [--assets DIR] "
          "[--listen HOST:PORT] [--state-dir DIR] [--mode MODE] [--queue N] "
          "[--service FILE] [--engine-pid FILE] [--controller-pid FILE] [--log FILE]\n",
          f);
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') { s++; }
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
                     s[n - 1] == '\r' || s[n - 1] == '\n')) { s[--n] = '\0'; }
    return s;
}

static int known_key(const char *key) {
    static const char *const keys[] = {
        "SCHEMA", "MODE", "PANEL_LISTEN", "STATE_DIR", "QUEUE_NUM",
        "CONTROL_SOCKET", "DECOY_SNI", "MARK", "PROBE_MARK", "FLOWS",
        "STATS_SEC", "HEAL_EVERY", "LOGMAX", "LOGKEEP", "LOG_EVERY", "D2K_RUNTIME_DIR", "PORTS",
        "CONNBYTES", "VOICE_PORTS", "VOICE_CONNBYTES", "TG_ENABLED",
        "TG_RELAY_URL", "TG_RELAY_SECRET", "TG_IDENTITY", "TG_CA_BUNDLE",
        "TG_STATUS", "TG_PORT", "TG_ENROLL_PORT",
        /* Читает files/S99d2k (разгрузка PPE на Keenetic); панели значение
           не нужно, но ключ законный и пишется установщиком. */
        "D2K_PPE_DEOFFLOAD", "KEENETIC_POLICY",
        "SHADOW", "EXP_CONTROL", "NEWCHAIN", "SYNTHESIS_ONLY"
    };
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        if (strcmp(key, keys[i]) == 0) { return 1; }
    }
    return 0;
}

static int valid_mode(const char *mode) {
    return strcmp(mode, "off") == 0 || strcmp(mode, "observe") == 0 ||
           strcmp(mode, "apply") == 0;
}

static void remember_unknown(char keys[UNKNOWN_MAX][UNKNOWN_KEY_MAX], size_t *n,
                             const char *key) {
    if (!key[0] || strlen(key) >= UNKNOWN_KEY_MAX || *n >= UNKNOWN_MAX) { return; }
    for (size_t i = 0; i < *n; i++) {
        if (strcmp(keys[i], key) == 0) { return; }
    }
    snprintf(keys[*n], UNKNOWN_KEY_MAX, "%s", key);
    (*n)++;
}

static int copy_value(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (n >= cap) { return -1; }
    memcpy(dst, src, n + 1);
    return 0;
}

/* Literal shell-style quoting and trailing comments; never execute config. */
static int normalize_shell_value(char *value) {
    if (!value[0]) return 0;
    if (value[0] == '\'' || value[0] == '"') {
        char *end = strchr(value + 1, value[0]);
        if (!end) return -1;
        if (end[1] && end[1] != ' ' && end[1] != '\t') return -1;
        char *tail = trim(end + 1);
        if (*tail && *tail != '#') return -1;
        *end = '\0';
        memmove(value, value + 1, (size_t)(end - value));
    } else {
        for (char *p = value; *p; p++) {
            if (*p == '#' && (p == value || p[-1] == ' ' || p[-1] == '\t')) {
                *p = '\0';
                break;
            }
        }
        trim(value);
        size_t n = strlen(value);
        if (n && (value[n - 1] == '\'' || value[n - 1] == '"')) return -1;
    }
    return 0;
}

static int config_unsigned(const char *value, long maximum, long *out) {
    if (!value[0]) return -1;
    for (const char *p = value; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
    }
    errno = 0;
    char *end;
    long number = strtol(value, &end, 10);
    if (errno || *end || number > maximum) return -1;
    *out = number;
    return 0;
}

static int read_config(const char *path, char *mode, size_t mode_cap,
                       char *listen, size_t listen_cap,
                       char *state_dir, size_t state_cap, int *queue,
                       int cli_mode, int cli_listen, int cli_state, int cli_queue,
                       char unknown[UNKNOWN_MAX][UNKNOWN_KEY_MAX], size_t *n_unknown,
                       int *exists) {
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) { *exists = 0; return 0; }
        return -1;
    }
    *exists = 1;
    char line[CONFIG_LINE_MAX];
    for (;;) {
        if (!fgets(line, sizeof line, f)) { break; }
        size_t line_len = strlen(line);
        if (line_len == sizeof line - 1 && line[line_len - 1] != '\n') {
            /* Reject an overlong line instead of silently parsing its tail. */
            fclose(f);
            return -1;
        }
        char *p = trim(line);
        if (!p[0] || p[0] == '#') { continue; }
        char *eq = strchr(p, '=');
        if (!eq) { continue; }
        *eq++ = '\0';
        char *key = trim(p), *value = trim(eq);
        if (!known_key(key)) { remember_unknown(unknown, n_unknown, key); continue; }
        if (strcmp(key, "SCHEMA") && strcmp(key, "MODE") &&
            strcmp(key, "PANEL_LISTEN") && strcmp(key, "STATE_DIR") &&
            strcmp(key, "QUEUE_NUM")) continue;
        if (normalize_shell_value(value) != 0) { fclose(f); return -1; }
        if (strcmp(key, "SCHEMA") == 0) {
            long schema;
            if (config_unsigned(value, 1, &schema) != 0) {
                say("конфигурация %s: SCHEMA — нужны цифры без знака, значение 0 или 1", path);
                fclose(f); return -1;
            }
        } else if (strcmp(key, "MODE") == 0) {
            if (!valid_mode(value)) { fclose(f); return -1; }
            if (!cli_mode && copy_value(mode, mode_cap, value) != 0) { fclose(f); return -1; }
        } else if (!cli_listen && strcmp(key, "PANEL_LISTEN") == 0) {
            if (copy_value(listen, listen_cap, value) != 0) { fclose(f); return -1; }
        } else if (strcmp(key, "STATE_DIR") == 0) {
            if (value[0] && value[0] != '/') { fclose(f); return -1; }
            if (!cli_state && copy_value(state_dir, state_cap, value) != 0) { fclose(f); return -1; }
        } else if (strcmp(key, "QUEUE_NUM") == 0) {
            long v;
            if (config_unsigned(value, 65535, &v) != 0) {
                say("конфигурация %s: QUEUE_NUM — нужны цифры без знака, значение от 0 до 65535", path);
                fclose(f); return -1;
            }
            if (!cli_queue) { *queue = (int)v; }
        }
    }
    int err = ferror(f) ? -1 : 0;
    fclose(f);
    return err;
}

static int split_listen(const char *listen, char *host, size_t host_cap,
                        char *port, size_t port_cap) {
    const char *start = listen, *colon = NULL;
    size_t host_len;
    if (listen[0] == '[') {
        const char *end = strchr(listen, ']');
        if (!end || end[1] != ':') { return -1; }
        start = listen + 1;
        host_len = (size_t)(end - start);
        colon = end + 1;
    } else {
        colon = strrchr(listen, ':');
        if (!colon) { return -1; }
        host_len = (size_t)(colon - start);
    }
    if (host_len == 0 || host_len >= host_cap || strlen(colon + 1) >= port_cap) { return -1; }
    memcpy(host, start, host_len);
    host[host_len] = '\0';
    if (copy_value(port, port_cap, colon + 1) != 0) { return -1; }
    char *end = NULL;
    long p = strtol(port, &end, 10);
    return end && *end == '\0' && p > 0 && p <= 65535 ? 0 : -1;
}

static int listen_socket(const char *addr) {
    char host[256], port[16];
    if (split_listen(addr, host, sizeof host, port, sizeof port) != 0) {
        say("неверный адрес панели: %s", addr);
        return -1;
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    struct addrinfo *res = NULL;
    int e = getaddrinfo(host, port, &hints, &res);
    if (e != 0) { say("адрес панели %s: %s", addr, gai_strerror(e)); return -1; }
    int listener = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        listener = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (listener < 0) { continue; }
        if (fcntl(listener, F_SETFD, FD_CLOEXEC) != 0) {
            close(listener);
            listener = -1;
            continue;
        }
        int yes = 1;
        (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
        if (bind(listener, ai->ai_addr, ai->ai_addrlen) == 0 && listen(listener, 16) == 0) { break; }
        close(listener);
        listener = -1;
    }
    freeaddrinfo(res);
    if (listener < 0) { say("не удалось открыть панель на %s: %s", addr, strerror(errno)); }
    return listener;
}

static int is_loopback_addr(const char *addr) {
    char host[256], port[16];
    if (split_listen(addr, host, sizeof host, port, sizeof port) != 0) { return 0; }
    return strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0 ||
           strcmp(host, "::1") == 0;
}

static void set_state_note(const char *dir, char *out, size_t cap) {
    struct stat st;
    if (stat(dir, &st) != 0) {
        snprintf(out, cap, "%s", errno == ENOENT ? "не создан" : "недоступен");
    } else if (!S_ISDIR(st.st_mode)) {
        snprintf(out, cap, "существует, но это не каталог");
    } else {
        snprintf(out, cap, "есть");
    }
}

static int serve(const char *listen_addr, const char *live_path, const char *asset_dir,
                 const char *config_path, const char *mode, const char *state_dir,
                 int queue, const char *service_path, const char *engine_pid_path,
                 const char *controller_pid_path, const char *telegram_pid_path,
                 const char *telegram_status_path, const char *log_path) {
    if (log_path && log_path[0]) {
        int logfd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (logfd < 0) { say("не открыть журнал %s: %s", log_path, strerror(errno)); return 1; }
        (void)dup2(logfd, STDOUT_FILENO);
        (void)dup2(logfd, STDERR_FILENO);
        close(logfd);
    }
    char unknown[UNKNOWN_MAX][UNKNOWN_KEY_MAX];
    const char *unknown_ptrs[UNKNOWN_MAX];
    size_t n_unknown = 0;
    int config_exists = 0;
    char config_mode[32];
    char config_listen[256];
    char config_state[512];
    snprintf(config_mode, sizeof config_mode, "%s", mode);
    snprintf(config_listen, sizeof config_listen, "%s", listen_addr);
    snprintf(config_state, sizeof config_state, "%s", state_dir);
    if (read_config(config_path, config_mode, sizeof config_mode,
                    config_listen, sizeof config_listen,
                    config_state, sizeof config_state, &queue,
                    1, 1, 1, 1, unknown, &n_unknown, &config_exists) != 0) {
        say("не прочитать конфигурацию %s", config_path);
        return 1;
    }
    if (!listen_addr || !listen_addr[0]) {
        say("PANEL_LISTEN пуст — панель выключена");
        return 0;
    }
    int listener = listen_socket(listen_addr);
    if (listener < 0) { return 1; }
    if (!is_loopback_addr(listen_addr)) {
        say("внимание: панель слушает не на петле (%s) и не имеет аутентификации", listen_addr);
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);

    char state_note[128];
    set_state_note(config_state, state_note, sizeof state_note);
    for (size_t i = 0; i < n_unknown; i++) { unknown_ptrs[i] = unknown[i]; }
    d2k_panel_config cfg = {
        .live_path = live_path,
        .asset_dir = asset_dir,
        .version = D2K_PANEL_VERSION,
        .commit = D2K_PANEL_COMMIT,
        .built = D2K_PANEL_BUILT,
        .mode = config_mode,
        .panel_listen = config_listen,
        .config_path = config_path,
        .state_dir = config_state,
        .state_dir_note = state_note,
        .service_path = service_path,
        .engine_pid_path = engine_pid_path,
        .controller_pid_path = controller_pid_path,
        .telegram_pid_path = telegram_pid_path,
        .telegram_status_path = telegram_status_path,
        .unknown_keys = unknown_ptrs,
        .unknown_key_count = n_unknown,
        .started_epoch = (long long)time(NULL),
        .queue_num = queue,
        .config_exists = config_exists,
        .dirty = D2K_PANEL_DIRTY,
        /* The operator explicitly selected this panel bind address. Allow
         * same-origin controls there; server.c rejects cross-origin actions. */
        .control_enabled = 1,
        .update_state_path = "/opt/d2k/state/update.json",
        .updater_path = "/opt/d2k/d2k-update.sh",
        .listener_fd = listener,
    };
    printf("d2kpanel %s\nhttp://%s/\n", D2K_PANEL_VERSION, listen_addr);
    fflush(stdout);

    while (!stop_requested) {
        (void)d2k_runtime_heartbeat(health_path, NULL, 0, 1, 1);
        d2k_panel_control_tick();
        struct pollfd ready = { .fd = listener, .events = POLLIN };
        int pr = poll(&ready, 1, 1000);
        if (pr == 0 || (pr < 0 && errno == EINTR)) continue;
        if (pr < 0) { say("poll: %s", strerror(errno)); break; }
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) { continue; }
            if (stop_requested) { break; }
            say("accept: %s", strerror(errno));
            struct timespec pause = { .tv_nsec = 100000000 };
            (void)nanosleep(&pause, NULL);
            continue;
        }
        struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
        (void)fcntl(client, F_SETFD, FD_CLOEXEC);
        (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        (void)setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
        (void)d2k_panel_handle_fd(client, &cfg);
        close(client);
    }
    close(listener);
    return 0;
}

static int offline_self_check(void) {
    char host[128], port[16];
    if (split_listen("127.0.0.1:8090", host, sizeof host, port, sizeof port) != 0 ||
        strcmp(host, "127.0.0.1") || strcmp(port, "8090")) return -1;
    if (split_listen("[::1]:8090", host, sizeof host, port, sizeof port) != 0 || strcmp(host, "::1")) return -1;
    return split_listen("127.0.0.1:65536", host, sizeof host, port, sizeof port) == -1 ? 0 : -1;
}

int main(int argc, char **argv) {
    int offline = d2k_runtime_offline(argc, argv, "d2kpanel", offline_self_check);
    if (offline >= 0) return offline;
    if (d2k_panel_ignore_sigpipe() != 0) {
        say("не удалось настроить обработку разрыва HTTP-клиента: %s", strerror(errno));
        return 1;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("d2kpanel %s commit %s features=%s release=%s\n", D2K_PANEL_VERSION,
               D2K_PANEL_COMMIT, D2K_PANEL_FEATURES, D2K_RELEASE_ID);
        return 0;
    }
    if (argc < 2 || strcmp(argv[1], "serve") != 0) {
        usage(stderr);
        return 2;
    }
    const char *config_path = "/opt/d2k/config";
    char live_path[768] = "";
    char asset_dir[768] = "/opt/d2k/panel";
    char listen_addr[256] = "127.0.0.1:8090";
    char mode[32] = "observe";
    char state_dir[512] = "/opt/d2k/state";
    int queue = 2000;
    const char *log_path = NULL;
    const char *service_path = "/opt/etc/init.d/S99d2k";
    const char *engine_pid_path = "/opt/d2k/run/d2kd.pid";
    const char *controller_pid_path = "/opt/d2k/run/d2k.pid";
    const char *telegram_pid_path = "/opt/d2k/run/d2ktg.pid";
    const char *telegram_status_path = "/opt/d2k/state/telegram.status";
    int cli_listen = 0, cli_mode = 0, cli_state = 0, cli_queue = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) { config_path = argv[++i]; }
        else if (strcmp(argv[i], "--live") == 0 && i + 1 < argc) {
            if (copy_value(live_path, sizeof live_path, argv[++i]) != 0) { return 2; }
        } else if (strcmp(argv[i], "--assets") == 0 && i + 1 < argc) {
            if (copy_value(asset_dir, sizeof asset_dir, argv[++i]) != 0) { return 2; }
        } else if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            if (copy_value(listen_addr, sizeof listen_addr, argv[++i]) != 0) { return 2; }
            cli_listen = 1;
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            if (copy_value(mode, sizeof mode, argv[++i]) != 0) { return 2; }
            cli_mode = 1;
        } else if (strcmp(argv[i], "--state-dir") == 0 && i + 1 < argc) {
            if (copy_value(state_dir, sizeof state_dir, argv[++i]) != 0) { return 2; }
            cli_state = 1;
        } else if (strcmp(argv[i], "--queue") == 0 && i + 1 < argc) {
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (!end || *end || v < 0 || v > 65535) { return 2; }
            queue = (int)v;
            cli_queue = 1;
        } else if (strcmp(argv[i], "--service") == 0 && i + 1 < argc) { service_path = argv[++i]; }
        else if (strcmp(argv[i], "--engine-pid") == 0 && i + 1 < argc) { engine_pid_path = argv[++i]; }
        else if (strcmp(argv[i], "--controller-pid") == 0 && i + 1 < argc) { controller_pid_path = argv[++i]; }
        else if (strcmp(argv[i], "--telegram-pid") == 0 && i + 1 < argc) { telegram_pid_path = argv[++i]; }
        else if (strcmp(argv[i], "--health-file") == 0 && i + 1 < argc) { health_path = argv[++i]; }
        else if (strcmp(argv[i], "--telegram-status") == 0 && i + 1 < argc) { telegram_status_path = argv[++i]; }
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) { log_path = argv[++i]; }
        else { usage(stderr); return 2; }
    }
    if (!valid_mode(mode)) { say("недопустимый MODE: %s", mode); return 2; }
    if (!cli_listen || !cli_mode || !cli_state || !cli_queue) {
        char unknown[UNKNOWN_MAX][UNKNOWN_KEY_MAX];
        size_t n_unknown = 0;
        int exists = 0;
        if (read_config(config_path, mode, sizeof mode, listen_addr, sizeof listen_addr,
                        state_dir, sizeof state_dir, &queue,
                        cli_mode, cli_listen, cli_state, cli_queue,
                        unknown, &n_unknown, &exists) != 0) {
            say("не разобрать конфигурацию %s", config_path);
            return 1;
        }
    }
    if (!live_path[0]) {
        int n = snprintf(live_path, sizeof live_path, "%s/live.json", state_dir);
        if (n < 0 || (size_t)n >= sizeof live_path) { return 2; }
    }
    return serve(listen_addr, live_path, asset_dir, config_path, mode,
                 state_dir, queue, service_path, engine_pid_path,
                 controller_pid_path, telegram_pid_path, telegram_status_path, log_path);
}
