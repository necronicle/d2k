#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "server.h"
#include "../runtime/d2k_diagnostics_files.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUEST_MAX (32u * 1024u)
#define BODY_MAX (1024u * 1024u)
#define STATUS_OVERHEAD 16384u
#ifndef D2K_PANEL_HEADER_TIMEOUT_MS
#define D2K_PANEL_HEADER_TIMEOUT_MS 5000
#endif
#ifndef D2K_PANEL_RESPONSE_TIMEOUT_MS
#define D2K_PANEL_RESPONSE_TIMEOUT_MS 5000
#endif
#ifndef D2K_PANEL_ACTION_TIMEOUT_MS
#define D2K_PANEL_ACTION_TIMEOUT_MS 60000
#endif

static pid_t action_pid;
static int policy_action;
static const char *action_state = "idle";

static long long monotonic_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

void d2k_panel_control_tick(void) {
    if (!action_pid) return;
    int status;
    pid_t r = waitpid(action_pid, &status, WNOHANG);
    if (r == 0 || (r < 0 && errno == EINTR)) return;
    action_pid = 0;
    action_state = r < 0 || !WIFEXITED(status) ? "failed" :
        WEXITSTATUS(status) == 124 ? "timeout" :
        WEXITSTATUS(status) == 0 ? "done" : "failed";
}

int d2k_panel_ignore_sigpipe(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_IGN;
    if (sigemptyset(&action.sa_mask) != 0) { return -1; }
    return sigaction(SIGPIPE, &action, NULL);
}

typedef struct { const char *p, *end; unsigned depth; } json_reader;

static void json_ws(json_reader *r) {
    while (r->p < r->end && (*r->p == ' ' || *r->p == '\t' ||
                              *r->p == '\r' || *r->p == '\n')) { r->p++; }
}

static int json_string(json_reader *r) {
    if (r->p >= r->end || *r->p++ != '"') { return -1; }
    while (r->p < r->end) {
        unsigned char c = (unsigned char)*r->p++;
        if (c == '"') { return 0; }
        if (c < 0x20) { return -1; }
        if (c != '\\') { continue; }
        if (r->p >= r->end) { return -1; }
        c = (unsigned char)*r->p++;
        if (c == '"' || c == '\\' || c == '/' || c == 'b' || c == 'f' ||
            c == 'n' || c == 'r' || c == 't') { continue; }
        if (c != 'u' || r->end - r->p < 4) { return -1; }
        for (int i = 0; i < 4; i++) {
            unsigned char h = (unsigned char)*r->p++;
            if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
                  (h >= 'A' && h <= 'F'))) { return -1; }
        }
    }
    return -1;
}

static int json_value(json_reader *r);

static int json_compound(json_reader *r, char open, char close, int object) {
    if (++r->depth > 64 || r->p >= r->end || *r->p++ != open) {
        r->depth--;
        return -1;
    }
    json_ws(r);
    if (r->p < r->end && *r->p == close) { r->p++; r->depth--; return 0; }
    for (;;) {
        if (object) {
            if (json_string(r) != 0) { r->depth--; return -1; }
            json_ws(r);
            if (r->p >= r->end || *r->p++ != ':') { r->depth--; return -1; }
            json_ws(r);
        }
        if (json_value(r) != 0) { r->depth--; return -1; }
        json_ws(r);
        if (r->p >= r->end) { r->depth--; return -1; }
        char c = *r->p++;
        if (c == close) { r->depth--; return 0; }
        if (c != ',') { r->depth--; return -1; }
        json_ws(r);
    }
}

static int json_number(json_reader *r) {
    const char *p = r->p;
    if (p < r->end && *p == '-') { p++; }
    if (p >= r->end) { return -1; }
    if (*p == '0') { p++; }
    else {
        if (*p < '1' || *p > '9') { return -1; }
        do { p++; } while (p < r->end && *p >= '0' && *p <= '9');
    }
    if (p < r->end && *p == '.') {
        p++;
        if (p >= r->end || *p < '0' || *p > '9') { return -1; }
        do { p++; } while (p < r->end && *p >= '0' && *p <= '9');
    }
    if (p < r->end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < r->end && (*p == '+' || *p == '-')) { p++; }
        if (p >= r->end || *p < '0' || *p > '9') { return -1; }
        do { p++; } while (p < r->end && *p >= '0' && *p <= '9');
    }
    r->p = p;
    return 0;
}

static int json_value(json_reader *r) {
    json_ws(r);
    if (r->p >= r->end) { return -1; }
    switch (*r->p) {
    case '"': return json_string(r);
    case '{': return json_compound(r, '{', '}', 1);
    case '[': return json_compound(r, '[', ']', 0);
    case 't': if (r->end - r->p >= 4 && memcmp(r->p, "true", 4) == 0) { r->p += 4; return 0; } return -1;
    case 'f': if (r->end - r->p >= 5 && memcmp(r->p, "false", 5) == 0) { r->p += 5; return 0; } return -1;
    case 'n': if (r->end - r->p >= 4 && memcmp(r->p, "null", 4) == 0) { r->p += 4; return 0; } return -1;
    default: return json_number(r);
    }
}

static int json_valid_object(const char *p, const char *end) {
    json_reader r = { .p = p, .end = end, .depth = 0 };
    json_ws(&r);
    if (r.p >= r.end || *r.p != '{' || json_value(&r) != 0) { return 0; }
    json_ws(&r);
    return r.p == r.end;
}

static int json_top_value(const char *json, const char *wanted,
                          const char **value, size_t *value_len) {
    json_reader r = { .p = json, .end = json + strlen(json), .depth = 0 };
    json_ws(&r);
    if (r.p >= r.end || *r.p++ != '{') { return 0; }
    json_ws(&r);
    while (r.p < r.end && *r.p != '}') {
        const char *key_start = r.p;
        if (json_string(&r) != 0) { return 0; }
        size_t key_len = (size_t)(r.p - key_start);
        json_ws(&r);
        if (r.p >= r.end || *r.p++ != ':') { return 0; }
        json_ws(&r);
        const char *value_start = r.p;
        int match = strlen(wanted) + 2 == key_len && key_start[0] == '"' &&
                    key_start[key_len - 1] == '"' &&
                    memcmp(key_start + 1, wanted, strlen(wanted)) == 0;
        if (json_value(&r) != 0) { return 0; }
        if (match) {
            *value = value_start;
            *value_len = (size_t)(r.p - value_start);
            return 1;
        }
        json_ws(&r);
        if (r.p >= r.end || *r.p == '}') { break; }
        if (*r.p++ != ',') { return 0; }
        json_ws(&r);
    }
    return 0;
}

static int json_top_true(const char *json, const char *key) {
    const char *value;
    size_t len;
    return json_top_value(json, key, &value, &len) && len == 4 &&
           memcmp(value, "true", 4) == 0;
}

static int json_top_nonempty_string(const char *json, const char *key) {
    const char *value;
    size_t len;
    return json_top_value(json, key, &value, &len) && len > 2 &&
           value[0] == '"' && value[len - 1] == '"';
}

static int pid_path_running(const char *path, time_t *started_at) {
    if (started_at) { *started_at = 0; }
    if (!path || !path[0]) { return 1; }
    FILE *f = fopen(path, "r");
    if (!f) { return 0; }
    struct stat st;
    int have_stat = fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode);
    char line[32];
    int ok = fgets(line, sizeof line, f) != NULL;
    fclose(f);
    if (!ok || !have_stat) { return 0; }
    char *end = NULL;
    errno = 0;
    long value = strtol(line, &end, 10);
    if (errno || value <= 1 || value > 4194304L || !end) { return 0; }
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') { end++; }
    if (*end) { return 0; }
    int running = kill((pid_t)value, 0) == 0 || errno == EPERM;
    if (running && started_at) { *started_at = st.st_mtime; }
    return running;
}

static int engine_pid_running(const d2k_panel_config *cfg, time_t *started_at) {
    return pid_path_running(cfg ? cfg->engine_pid_path : NULL, started_at);
}

static int controller_pid_running(const d2k_panel_config *cfg) {
    return pid_path_running(cfg ? cfg->controller_pid_path : NULL, NULL);
}

static int write_all(int fd, const void *buf, size_t len, long long deadline) {
    const char *p = buf;
    while (len > 0) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) { errno = ETIMEDOUT; return -1; }
        struct pollfd ready = { .fd = fd, .events = POLLOUT };
        int rc = poll(&ready, 1, (int)remaining);
        if (rc < 0 && errno == EINTR) { continue; }
        if (rc == 0) { errno = ETIMEDOUT; return -1; }
        if (rc < 0) { return -1; }
        ssize_t n = write(fd, p, len);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) { continue; }
        if (n <= 0) { return -1; }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

typedef struct {
    const char *data;
    size_t len;
} response_part;

static int write_file_body(int fd, int in, size_t len, long long deadline) {
    char chunk[4096];
    while (len) {
        size_t want = len < sizeof chunk ? len : sizeof chunk;
        ssize_t n = read(in, chunk, want);
        if (n < 0 && errno == EINTR) { continue; }
        if (n == 0) { errno = EIO; return -1; }
        if (n < 0 || write_all(fd, chunk, (size_t)n, deadline) != 0) { return -1; }
        len -= (size_t)n;
    }
    return 0;
}

/* A response has either memory parts or a regular file opened by static_file.
   The length of a file comes from fstat on that same descriptor. */
static int send_response(int fd, int code, const char *reason, const char *type,
                         const char *extra, const response_part *parts, size_t count,
                         int in, size_t file_len) {
    size_t len = file_len;
    for (size_t i = 0; i < count; i++) { len += parts[i].len; }
    char hdr[1024];
    int n = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "%s"
        "Connection: close\r\n"
        "Content-Security-Policy: default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\n\r\n",
        code, reason, type, len, extra ? extra : "");
    if (n < 0 || (size_t)n >= sizeof hdr) { return -1; }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) { return -1; }
    /* One deadline covers headers and body, including repeated partial writes. */
    const long long deadline = monotonic_ms() + D2K_PANEL_RESPONSE_TIMEOUT_MS;
    int rc = write_all(fd, hdr, (size_t)n, deadline);
    for (size_t i = 0; rc == 0 && i < count; i++) {
        rc = write_all(fd, parts[i].data, parts[i].len, deadline);
    }
    if (rc == 0 && in >= 0) { rc = write_file_body(fd, in, file_len, deadline); }
    int saved_errno = errno;
    int restored = fcntl(fd, F_SETFL, flags);
    if (rc != 0) { errno = saved_errno; return rc; }
    return restored == 0 ? 0 : -1;
}

static int response_ex(int fd, int code, const char *reason, const char *type,
                       const char *extra, const char *body, size_t len) {
    const response_part part = { body, len };
    return send_response(fd, code, reason, type, extra, &part, 1, -1, 0);
}

static int response(int fd, int code, const char *reason, const char *type,
                    const char *body, size_t len) {
    return response_ex(fd, code, reason, type, NULL, body, len);
}

static int header_value(const char *req, const char *wanted,
                        const char **value, size_t *value_len) {
    const char *line = strstr(req, "\r\n");
    if (!line) { return 0; }
    line += 2;
    while (*line && !(line[0] == '\r' && line[1] == '\n')) {
        const char *end = strstr(line, "\r\n");
        if (!end) { return 0; }
        const char *colon = memchr(line, ':', (size_t)(end - line));
        if (colon && (size_t)(colon - line) == strlen(wanted) &&
            strncasecmp(line, wanted, strlen(wanted)) == 0) {
            const char *start = colon + 1;
            while (start < end && (*start == ' ' || *start == '\t')) { start++; }
            const char *finish = end;
            while (finish > start && (finish[-1] == ' ' || finish[-1] == '\t')) { finish--; }
            *value = start;
            *value_len = (size_t)(finish - start);
            return 1;
        }
        line = end + 2;
    }
    return 0;
}

int d2k_panel_same_origin(const char *req) {
  const char *host = NULL, *origin = NULL;
  size_t host_len = 0, origin_len = 0;
  if (!header_value(req, "Host", &host, &host_len) ||
      !header_value(req, "Origin", &origin, &origin_len) || origin_len < 7 ||
      memcmp(origin, "http://", 7) != 0) {
    return 0;
  }
  const char *authority = origin + 7;
  size_t authority_len = origin_len - 7;
  return host_len == authority_len && memcmp(host, authority, host_len) == 0;
}

static int run_service_action(const d2k_panel_config *cfg, const char *action, int client) {
    if (!cfg || !cfg->service_path || !cfg->service_path[0]) { return -1; }
    d2k_panel_control_tick();
    if (action_pid) return 1;
    pid_t pid = fork();
    if (pid < 0) { return -1; }
    if (pid == 0) {
        close(client);
        if (cfg->listener_fd > 2) close(cfg->listener_fd);
        signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL);
        pid_t worker = fork();
        if (worker < 0) _exit(125);
        if (worker == 0) {
            if (setpgid(0, 0) != 0) _exit(125);
            execl(cfg->service_path, cfg->service_path, action, (char *)NULL);
            _exit(127);
        }
        (void)setpgid(worker, worker);
        long long deadline = monotonic_ms() + D2K_PANEL_ACTION_TIMEOUT_MS;
        int status = 0, timed_out = 0;
        for (;;) {
            pid_t r = waitpid(worker, &status, WNOHANG);
            if (r == worker) {
                if (timed_out) { (void)kill(-worker, SIGKILL); _exit(124); }
                _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 125);
            }
            if (r < 0 && errno != EINTR) _exit(125);
            if (monotonic_ms() >= deadline) {
                if (!timed_out) {
                    timed_out = 1;
                    (void)kill(-worker, SIGTERM);
                    deadline = monotonic_ms() + 1000;
                } else {
                    (void)kill(-worker, SIGKILL);
                    while (waitpid(worker, &status, 0) < 0 && errno == EINTR) {}
                    _exit(124);
                }
            }
            struct timespec pause = { .tv_nsec = 20000000 };
            (void)nanosleep(&pause, NULL);
        }
    }
    policy_action = 0;
    action_pid = pid;
    action_state = "running";
    return 0;
}

static void telegram_config_flags(const d2k_panel_config *cfg,int *enabled,int *configured) {
    *enabled=0;*configured=0;
    if(!cfg||!cfg->config_path)return;
    FILE *f=fopen(cfg->config_path,"r");if(!f)return;
    char line[2048];int have_url=0,have_secret=0,have_enroll=0;
    while(fgets(line,sizeof(line),f)) {
        char *p=line;while(*p==' '||*p=='\t')p++;
        if(*p=='#'||!*p)continue;
        char *eq=strchr(p,'=');if(!eq)continue;*eq++='\0';
        char *end=p+strlen(p);while(end>p&&(end[-1]==' '||end[-1]=='\t'||end[-1]=='\r'||end[-1]=='\n'))*--end='\0';
        while(*eq==' '||*eq=='\t')eq++;
        end=eq+strlen(eq);while(end>eq&&(end[-1]==' '||end[-1]=='\t'||end[-1]=='\r'||end[-1]=='\n'))*--end='\0';
        if(*eq=='\''||*eq=='"') {
            char quote=*eq;
            if(end-eq<2||end[-1]!=quote){*configured=0;fclose(f);return;}
            *--end='\0';eq++;
            if(strchr(eq,quote)){*configured=0;fclose(f);return;}
        }
        if(strcmp(p,"TG_ENABLED")==0)*enabled=strcmp(eq,"1")==0||strcmp(eq,"yes")==0;
        else if(strcmp(p,"TG_RELAY_URL")==0)have_url=*eq!='\0';
        else if(strcmp(p,"TG_RELAY_SECRET")==0)have_secret=*eq!='\0';
        else if(strcmp(p,"TG_ENROLL_PORT")==0) {
            char *tail;unsigned long port=strtoul(eq,&tail,10);
            have_enroll=tail!=eq&&!*tail&&port>0&&port<=65535;
        }
    }
    fclose(f);*configured=have_url&&(have_secret||have_enroll);
}

static void telegram_status_value(const d2k_panel_config *cfg,int enabled,int configured,int *running,char out[24]) {
    *running=cfg&&cfg->telegram_pid_path?pid_path_running(cfg->telegram_pid_path,NULL):0;
    const char *fallback=!configured?"not_configured":(!enabled||!*running?"stopped":"connecting");
    if(!configured||!enabled||!*running){snprintf(out,24,"%s",fallback);return;}
    int fd=cfg&&cfg->telegram_status_path?
        open(cfg->telegram_status_path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW):-1;
    if(fd<0){snprintf(out,24,"%s",fallback);return;}
    char buf[64];ssize_t n=read(fd,buf,sizeof(buf)-1);close(fd);
    if(n<=0){snprintf(out,24,"%s",fallback);return;}buf[n]='\0';
    char *end=buf+strlen(buf);while(end>buf&&(end[-1]=='\r'||end[-1]=='\n'||end[-1]==' '||end[-1]=='\t'))*--end='\0';
    if(strcmp(buf,"connected")==0||strcmp(buf,"connecting")==0||strcmp(buf,"stopped")==0||strcmp(buf,"not_configured")==0)
        snprintf(out,24,"%.23s",buf);
    else snprintf(out,24,"%s",fallback);
}

static int api_control(int fd, const d2k_panel_config *cfg, const char *req,
                       const char *path) {
    static const struct { const char *path; const char *command; const char *label; } actions[] = {
        { "/api/control/start", "engine-start", "Запуск движка" },
        { "/api/control/stop", "engine-stop", "Остановка движка" },
        { "/api/control/restart", "engine-restart", "Перезапуск движка" },
        { "/api/control/reapply", "reapply", "Восстановление правил" },
        /* Необратимая операция. Подтверждение спрашивает панель диалогом
           (internal/web/assets/panel.js, CONFIRM): здесь его проверять нечем —
           POST приходит один и тот же, подтверждён он или нет. Защита та же,
           что у остальных команд: control_enabled и единый источник. */
        { "/api/control/clear-found", "clear-found", "Очистка подобранного" },
        { "/api/control/telegram-enable", "telegram-enable", "Включение Telegram-туннеля" },
        { "/api/control/telegram-disable", "telegram-disable", "Отключение Telegram-туннеля" },
        { "/api/control/update-check", "update-check", "Проверка обновлений" },
        { "/api/control/update-install", "update-install", "Установка обновления" },
        { "/api/control/update-auto-on", "update-auto-on", "Включение автообновления" },
        { "/api/control/update-auto-off", "update-auto-off", "Выключение автообновления" },
    };
    const char *command = NULL, *label = NULL;
    for (size_t i = 0; i < sizeof actions / sizeof actions[0]; i++) {
        if (strcmp(path, actions[i].path) == 0) {
            command = actions[i].command;
            label = actions[i].label;
            break;
        }
    }
    if (!command) {
        static const char body[] = "{\"ok\":false,\"message\":\"Неизвестная операция\"}";
        return response(fd, 404, "Not Found", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    if (!cfg || !cfg->control_enabled || !d2k_panel_same_origin(req)) {
      static const char body[] = "{\"ok\":false,\"message\":\"Управление "
                                 "разрешено только с этой панели\"}";
      return response(fd, 403, "Forbidden", "application/json; charset=utf-8",
                      body, sizeof body - 1);
    }
    if ((strcmp(command, "engine-start") == 0 ||
         strcmp(command, "engine-restart") == 0) &&
        cfg->mode && strcmp(cfg->mode, "off") == 0) {
        static const char body[] = "{\"ok\":false,\"message\":\"В config задан MODE=off; сначала измените режим движка\"}";
        return response(fd, 409, "Conflict", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    if(strcmp(command,"telegram-enable")==0) {
        int enabled=0,configured=0;telegram_config_flags(cfg,&enabled,&configured);(void)enabled;
        if(!configured) {
            static const char body[]="{\"ok\":false,\"message\":\"Сначала задайте TG_RELAY_URL и TG_RELAY_SECRET в конфигурации\"}";
            return response(fd,409,"Conflict","application/json; charset=utf-8",body,sizeof body-1);
        }
    }
    const char *transfer = NULL;
    size_t transfer_len = 0;
    if (header_value(req, "Transfer-Encoding", &transfer, &transfer_len)) {
        static const char body[] = "{\"ok\":false,\"message\":\"Тело запроса запрещено\"}";
        return response(fd, 400, "Bad Request", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    const char *length = NULL;
    size_t length_len = 0;
    if (header_value(req, "Content-Length", &length, &length_len) &&
        !(length_len == 1 && length[0] == '0')) {
        static const char body[] = "{\"ok\":false,\"message\":\"Тело запроса запрещено\"}";
        return response(fd, 400, "Bad Request", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    int started = run_service_action(cfg, command, fd);
    if (started > 0) {
        static const char body[] = "{\"ok\":false,\"message\":\"Предыдущая команда ещё выполняется\"}";
        return response(fd, 409, "Conflict", "application/json; charset=utf-8", body, sizeof body - 1);
    }
    if (started < 0) {
        static const char body[] = "{\"ok\":false,\"message\":\"Команда службы завершилась ошибкой\"}";
        return response(fd, 500, "Service Error", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    char body[256];
    int n = snprintf(body, sizeof body, "{\"ok\":true,\"action\":\"%s\",\"message\":\"Команда запущена\"}", label);
    if (n < 0 || (size_t)n >= sizeof body) { return -1; }
    return response(fd, 202, "Accepted", "application/json; charset=utf-8", body, (size_t)n);
}

/* Состояние автообновления — файл d2k-update.sh, отдаётся как есть: его
   пишет только эта утилита, атомарно и целиком. */
static int api_update(int fd, const d2k_panel_config *cfg) {
    static const char json[] = "application/json; charset=utf-8";
    if (!cfg || !cfg->updater_path || access(cfg->updater_path, X_OK) != 0) {
        static const char body[] = "{\"absent\":true}";
        return response(fd, 200, "OK", json, body, sizeof body - 1);
    }
    char body[16384];
    size_t n = 0;
    int in = cfg->update_state_path ?
        open(cfg->update_state_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
    if (in >= 0) {
        for (;;) {
            ssize_t k = read(in, body + n, sizeof body - n);
            if (k < 0 && errno == EINTR) continue;
            if (k <= 0) break;
            n += (size_t)k;
            if (n == sizeof body) { n = 0; break; }
        }
        close(in);
    }
    while (n && (body[n - 1] == '\n' || body[n - 1] == '\r')) n--;
    if (n < 2 || body[0] != '{' || body[n - 1] != '}') {
        static const char never[] = "{\"never\":true}";
        return response(fd, 200, "OK", json, never, sizeof never - 1);
    }
    return response(fd, 200, "OK", json, body, n);
}

static int read_request(int fd, char *buf, size_t cap, size_t *used, long long deadline) {
    while (*used + 1 < cap) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) { return -2; }
        struct pollfd ready = { .fd = fd, .events = POLLIN };
        int rc = poll(&ready, 1, (int)remaining);
        if (rc < 0 && errno == EINTR) { continue; }
        if (rc == 0) { return -2; }
        if (rc < 0) { return -1; }
        ssize_t n = read(fd, buf + *used, cap - *used - 1);
        if (n < 0 && errno == EINTR) { continue; }
        if (n < 0) { return -1; }
        if (n == 0) { break; }
        *used += (size_t)n;
        buf[*used] = '\0';
        if (strstr(buf, "\r\n\r\n")) { return 0; }
    }
    return *used + 1 >= cap ? 1 : -1;
}

static int read_status_object(const char *path, char **out, size_t *out_len, time_t *modified) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 1 ||
        (uint64_t)st.st_size > BODY_MAX) {
        close(fd);
        return -1;
    }
    size_t cap = (size_t)st.st_size;
    char *buf = malloc(cap + STATUS_OVERHEAD);
    if (!buf) { close(fd); return -1; }
    size_t nread = 0;
    while (nread < cap) {
        ssize_t n = read(fd, buf + nread, cap - nread);
        if (n < 0 && errno == EINTR) { continue; }
        if (n <= 0) { free(buf); close(fd); return -1; }
        nread += (size_t)n;
    }
    close(fd);
    buf[nread] = '\0';
    char *p = buf;
    char *end = buf + nread;
    if (!json_valid_object(p, end)) { free(buf); return -1; }
    *out = buf;
    *out_len = nread;
    *modified = st.st_mtime;
    return 0;
}

typedef struct {
    char *p;
    size_t len, cap;
    int failed;
} panel_buf;

static void buf_add(panel_buf *b, const char *s, size_t n) {
    if (b->failed || n > b->cap - b->len - 1) { b->failed = 1; return; }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void buf_puts(panel_buf *b, const char *s) { buf_add(b, s, strlen(s)); }

static void buf_printf(panel_buf *b, const char *fmt, ...) {
    if (b->failed) { return; }
    va_list ap, cp;
    va_start(ap, fmt);
    va_copy(cp, ap);
    int n = vsnprintf(NULL, 0, fmt, cp);
    va_end(cp);
    if (n < 0 || (size_t)n > b->cap - b->len - 1) {
        b->failed = 1;
        va_end(ap);
        return;
    }
    (void)vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    b->len += (size_t)n;
    va_end(ap);
}

static void buf_json_string(panel_buf *b, const char *s) {
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    buf_puts(b, "\"");
    for (; *p && !b->failed; p++) {
        char esc[7];
        if (*p == '"' || *p == '\\') {
            esc[0] = '\\'; esc[1] = (char)*p;
            buf_add(b, esc, 2);
        } else if (*p < 0x20) {
            (void)snprintf(esc, sizeof esc, "\\u%04x", (unsigned)*p);
            buf_add(b, esc, 6);
        } else {
            buf_add(b, (const char *)p, 1);
        }
    }
    buf_puts(b, "\"");
}

/* Cache validator for catalog content, not a security/authentication token. */
static int catalog_revision(const char *json, char out[17]) {
    const char *keys[] = { "boxes", "groups" };
    uint64_t hash = UINT64_C(14695981039346656037);
    int found = 0;
    for (size_t k = 0; k < 2; ++k) {
        const char *value = NULL; size_t len = 0;
        int present = json_top_value(json, keys[k], &value, &len);
        hash ^= k + 1; hash *= UINT64_C(1099511628211);
        hash ^= (uint64_t)len; hash *= UINT64_C(1099511628211);
        if (!present) continue;
        found = 1;
        for (size_t i = 0; i < len; ++i) {
            hash ^= (unsigned char)value[i]; hash *= UINT64_C(1099511628211);
        }
    }
    snprintf(out, 17, "%016llx", (unsigned long long)hash);
    return found;
}

/* The read buffer includes STATUS_OVERHEAD spare bytes. At most three
   replacements can grow, each by at most four bytes. Apply from the right so
   the offsets recorded against the validated JSON remain valid. */
static size_t update_live_knowledge(char *json, size_t len, int effective_linked, int slim) {
    struct replacement { size_t offset, len; const char *text; } parts[3];
    const char *keys[] = { "linked", "boxes", "groups" };
    size_t count = 0;
    for (size_t k = 0; k < 3; ++k) {
        if (k && !slim) continue;
        const char *value = NULL; size_t value_len = 0;
        if (!json_top_value(json, keys[k], &value, &value_len) ||
            value < json || (size_t)(value - json) > len ||
            value_len > len - (size_t)(value - json)) continue;
        struct replacement part = { (size_t)(value - json), value_len,
                                     k ? "null" : (effective_linked ? "true" : "false") };
        size_t i = count++;
        while (i && parts[i - 1].offset > part.offset) { parts[i] = parts[i - 1]; --i; }
        parts[i] = part;
    }
    while (count) {
        struct replacement part = parts[--count];
        size_t text_len = strlen(part.text);
        char *value = json + part.offset;
        if (text_len != part.len) {
            memmove(value + text_len, value + part.len, len - part.offset - part.len);
            len = len - part.len + text_len;
        }
        memcpy(value, part.text, text_len);
    }
    return len;
}

static void append_stage(panel_buf *b, const char *key, const char *title,
                         int built, const char *detail, int comma) {
    if (comma) { buf_puts(b, ","); }
    buf_puts(b, "{\"key\":"); buf_json_string(b, key);
    buf_puts(b, ",\"title\":"); buf_json_string(b, title);
    buf_printf(b, ",\"built\":%s,\"detail\":", built < 0 ? "null" : built ? "true" : "false");
    buf_json_string(b, detail);
    buf_puts(b, "}");
}

static void append_snapshot(panel_buf *b, const d2k_panel_config *cfg,
                            int linked, int have_catalog, int live_fresh,
                            int engine_running, int controller_running) {
    time_t now = time(NULL);
    struct tm tmv;
    char now_iso[32], started_iso[32];
    if (gmtime_r(&now, &tmv)) { strftime(now_iso, sizeof now_iso, "%Y-%m-%dT%H:%M:%SZ", &tmv); }
    else { snprintf(now_iso, sizeof now_iso, "1970-01-01T00:00:00Z"); }
    long long started = cfg ? cfg->started_epoch : 0;
    time_t started_t = (time_t)started;
    if (started > 0 && gmtime_r(&started_t, &tmv)) {
        strftime(started_iso, sizeof started_iso, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    } else { snprintf(started_iso, sizeof started_iso, "0001-01-01T00:00:00Z"); }
    long long uptime = started > 0 && (long long)now > started ? (long long)now - started : 0;
    const char *cfg_path = cfg && cfg->config_path ? cfg->config_path : "/opt/d2k/config";
    const char *state_dir = cfg && cfg->state_dir ? cfg->state_dir : "/opt/d2k/state";
    const char *state_note = cfg && cfg->state_dir_note ? cfg->state_dir_note : "неизвестно";
    const char *mode = cfg && cfg->mode ? cfg->mode : "observe";
    const char *panel_listen = cfg && cfg->panel_listen ? cfg->panel_listen : "127.0.0.1:8090";
    int queue = cfg ? cfg->queue_num : 2000;
    int telegram_enabled=0,telegram_configured=0,telegram_running=0;char telegram_status[24];
    telegram_config_flags(cfg,&telegram_enabled,&telegram_configured);
    telegram_status_value(cfg,telegram_enabled,telegram_configured,&telegram_running,telegram_status);
    buf_puts(b, "{\"taken\":"); buf_json_string(b, now_iso);
    buf_puts(b, ",\"version\":"); buf_json_string(b, cfg ? cfg->version : "dev");
    buf_puts(b, ",\"commit\":"); buf_json_string(b, cfg ? cfg->commit : "");
    buf_puts(b, ",\"built\":"); buf_json_string(b, cfg ? cfg->built : "");
    buf_printf(b, ",\"dirty\":%s,\"config_path\":", cfg && cfg->dirty ? "true" : "false");
    buf_json_string(b, cfg_path);
    buf_printf(b, ",\"config_exists\":%s,\"mode\":", cfg && cfg->config_exists ? "true" : "false");
    buf_json_string(b, mode);
    buf_puts(b, ",\"panel_listen\":"); buf_json_string(b, panel_listen);
    buf_printf(b, ",\"controls_enabled\":%s", cfg && cfg->control_enabled ? "true" : "false");
    d2k_panel_control_tick();
    buf_puts(b, ",\"control_state\":"); buf_json_string(b, action_state);
    buf_printf(b, ",\"catalog_available\":%s", have_catalog ? "true" : "false");
    buf_printf(b, ",\"live_fresh\":%s", live_fresh ? "true" : "false");
    buf_printf(b, ",\"engine_running\":%s", engine_running ? "true" : "false");
    buf_printf(b, ",\"controller_running\":%s", controller_running ? "true" : "false");
    buf_printf(b, ",\"telegram_enabled\":%s,\"telegram_configured\":%s,\"telegram_running\":%s,\"telegram_status\":",
               telegram_enabled?"true":"false",telegram_configured?"true":"false",telegram_running?"true":"false");
    buf_json_string(b,telegram_status);
    buf_puts(b, ",\"state_dir\":"); buf_json_string(b, state_dir);
    buf_puts(b, ",\"state_dir_note\":"); buf_json_string(b, state_note);
    buf_printf(b, ",\"queue_num\":%d,\"unknown_keys\":[", queue);
    for (size_t i = 0; cfg && i < cfg->unknown_key_count; i++) {
        if (i) { buf_puts(b, ","); }
        buf_json_string(b, cfg->unknown_keys ? cfg->unknown_keys[i] : "");
    }
    buf_puts(b, "],\"started_at\":");
    buf_json_string(b, started_iso);
    buf_printf(b, ",\"uptime_seconds\":%lld,\"stages\":[", uptime);
    append_stage(b, "config", "Конфигурация", 1,
                 cfg && cfg->config_exists ? "Прочитана из конфигурационного файла." :
                 "Файла конфигурации нет, действуют умолчания.", 0);
    int unknown = engine_running && controller_running && !live_fresh;
    int stage = unknown ? -1 : linked;
    const char *missing = "Нет свежего снимка контроллера.";
    append_stage(b, "capture", "Чтение пакетов", stage,
                 unknown ? missing : linked ? "Очередь ядра открыта, пакеты читаются: контроллер получает события датапата." :
                          "Контроллер не подключён к датапату — сказать, читаются ли пакеты, нечем.", 1);
    append_stage(b, "flow", "Состояние потоков", stage,
                 unknown ? missing : linked ? "Датапат ведёт учёт соединений и сообщает о подозрениях." :
                          "Контроллер не подключён к датапату.", 1);
    append_stage(b, "plan", "Исполнение планов", stage,
                 unknown ? missing : linked ? "Планы ставятся датапату и исполняются на живых соединениях." :
                          "Контроллер не подключён к датапату: применяется ли обход, отсюда не видно.", 1);
    char boxes_detail[512];
    if (have_catalog) {
        snprintf(boxes_detail, sizeof boxes_detail, "Каталог открыт: изученные коробки и цели доступны.");
    } else { snprintf(boxes_detail, sizeof boxes_detail, "Каталог не открыт."); }
    append_stage(b, "boxes", "Каталог коробок", have_catalog, boxes_detail, 1);
    append_stage(b, "panel", "Панель", 1, "Показывает этот снимок.", 1);
    buf_puts(b, "],\"absent\":[");
    append_stage(b, "outages", "Здоровье наблюдения", 0,
                 "Нечем: сколько пакетов не дошло до очереди, снаружи не измеряется.", 0);
    if (!linked) {
        append_stage(b, "traffic", "Наблюдаемый трафик", 0,
                     unknown ? missing : "Нечем: контроллер не подключён к датапату. Это не «ноль соединений», а отсутствие измерения.", 1);
    }
    buf_puts(b, "]}");
}

static int api_status(int fd, const d2k_panel_config *cfg, const char *query) {
    char *live = NULL;
    size_t live_len = 0;
    time_t modified;
    if (cfg && cfg->live_path && read_status_object(cfg->live_path, &live, &live_len, &modified) == 0) {
        time_t now = time(NULL);
        time_t engine_started_at = 0;
        int engine_running = engine_pid_running(cfg, &engine_started_at);
        int controller_running = controller_pid_running(cfg);
        int live_fresh = (!engine_started_at || modified >= engine_started_at) &&
            (modified > now ? modified - now <= 5 : now - modified <= 15);
        int linked = json_top_true(live, "linked") && live_fresh &&
                     engine_running && controller_running;
        int have_catalog = json_top_nonempty_string(live, "catalog_at");
        char revision[17];
        int have_revision = catalog_revision(live, revision);
        int unchanged = have_revision && query &&
            strncmp(query, "catalog_revision=", 17) == 0 &&
            strcmp(query + 17, revision) == 0;
        size_t knowledge_len = update_live_knowledge(live, live_len, linked, unchanged);
        panel_buf b = { .p = live + knowledge_len,
                        .cap = live_len + STATUS_OVERHEAD - knowledge_len };
        buf_puts(&b, "{\"snapshot\":");
        append_snapshot(&b, cfg, linked, have_catalog, live_fresh,
                        engine_running, controller_running);
        buf_puts(&b, ",\"knowledge\":");
        size_t prefix_len = b.len;
        if (have_revision) {
            buf_printf(&b, ",\"catalog_revision\":\"%s\",\"catalog_unchanged\":%s",
                       revision, unchanged ? "true" : "false");
        }
        buf_puts(&b, "}");
        const response_part parts[] = {
            { b.p, prefix_len }, { live, knowledge_len }, { b.p + prefix_len, b.len - prefix_len }
        };
        int rc = b.failed ? -1 : send_response(fd, 200, "OK", "application/json; charset=utf-8",
                                                NULL, parts, 3, -1, 0);
        free(live);
        return rc;
    }
    static const char unavailable_knowledge[] =
        "{\"linked\":false,\"link_note\":\"движок не отдаёт состояние\","
        "\"catalog_at\":\"\",\"boxes\":[],\"searches\":[],\"targets\":0,"
        "\"confirms\":0,\"probes_used\":0,\"client_unfit\":0}";
    size_t cap = STATUS_OVERHEAD;
    char *body = malloc(cap);
    if (!body) { return -1; }
    panel_buf b = { .p = body, .len = 0, .cap = cap, .failed = 0 };
    buf_puts(&b, "{\"snapshot\":");
    append_snapshot(&b, cfg, 0, 0, 0, engine_pid_running(cfg, NULL),
                    controller_pid_running(cfg));
    buf_puts(&b, ",\"knowledge\":");
    buf_puts(&b, unavailable_knowledge);
    buf_puts(&b, "}");
    int rc = b.failed ? -1 : response(fd, 200, "OK", "application/json; charset=utf-8", body, b.len);
    free(body);
    return rc;
}

/* Статика отдаётся с ETag из размера и времени изменения и всегда
   перепроверяется (no-cache): после обновления панели браузер не держит
   старый файл, а неизменённый получает ответ 304 без тела. */
static int static_file(int fd, const d2k_panel_config *cfg, const char *req,
                       const char *name, const char *type) {
    if (!cfg || !cfg->asset_dir) {
        return response(fd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
    }
    int dirfd = open(cfg->asset_dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) {
        return response(fd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
    }
    int in = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(dirfd);
    if (in < 0) {
        return response(fd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
    }
    struct stat st;
    if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > BODY_MAX) {
        close(in);
        return response(fd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
    }
    char etag[64], extra[128];
    snprintf(etag, sizeof etag, "\"%llx-%llx\"",
             (unsigned long long)st.st_size, (unsigned long long)st.st_mtime);
    snprintf(extra, sizeof extra, "Cache-Control: no-cache\r\nETag: %s\r\n", etag);
    const char *inm = NULL;
    size_t inm_len = 0;
    if (req && header_value(req, "If-None-Match", &inm, &inm_len) &&
        inm_len == strlen(etag) && memcmp(inm, etag, inm_len) == 0) {
        close(in);
        return response_ex(fd, 304, "Not Modified", type, extra, NULL, 0);
    }
    int rc = send_response(fd, 200, "OK", type, extra, NULL, 0, in, (size_t)st.st_size);
    int saved_errno = errno;
    close(in);
    errno = saved_errno;
    return rc;
}

static int diagnostic_response(int fd,int code,const char *reason,const char *type,const char *body,size_t len) {
    return response_ex(fd,code,reason,type,"Cache-Control: no-store\r\n",body,len);
}
#include "policies.h"

/* Keep the controller history intact and add a snapshot taken at download time. */
static void diagnostic_queue(panel_buf *b, FILE *f, int queue) {
    char line[256];
    unsigned id, peer, queued, dropped, user_dropped, sequence;
    while (f && fgets(line,sizeof line,f)) {
        if (sscanf(line,"%u %u %u %*u %*u %u %u %u",&id,&peer,&queued,
                   &dropped,&user_dropped,&sequence)==6 && id==(unsigned)queue) {
            buf_printf(b,"{\"bound\":true,\"peer\":%u,\"queued\":%u,\"kernel_drops\":%u,"
                       "\"userspace_drops\":%u,\"packet_sequence\":%u}",peer,queued,dropped,user_dropped,sequence);
            return;
        }
    }
    buf_puts(b,f && !ferror(f) ? "{\"bound\":false}" : "null");
}

/* Export known events only. Arbitrary relay messages and log lines can contain
 * network addresses or credentials. Scan at most the last 16 KiB. */
struct diagnostic_pattern { const char *prefix; const char *label; };

static void diagnostic_log_events(panel_buf *b, FILE *f,
                                  const struct diagnostic_pattern *patterns, size_t n_patterns) {
    struct stat st;
    if(!f || fstat(fileno(f),&st) || !S_ISREG(st.st_mode)){buf_puts(b,"null");return;}
    char line[512];
    if(st.st_size>16384){
        if(fseek(f,st.st_size-16384,SEEK_SET)){buf_puts(b,"null");return;}
        if(!fgets(line,sizeof line,f)){buf_puts(b,"null");return;}
    }
    char records[24][128]; unsigned count=0;
    off_t left=st.st_size<16384?st.st_size:16384;
    while(left>0 && fgets(line,sizeof line,f)){
        size_t n=strlen(line);left-=(off_t)n;
        if(!n)break;
        if(n<21 || line[19]!=' ' || strspn(line,"0123456789- :")!=20)continue;
        for(size_t i=0;i<n_patterns;i++){
            const char *prefix = patterns[i].prefix;
            if(strncmp(line+20,prefix,strlen(prefix)))continue;
            char *record=records[count++%24];
            snprintf(record,128,"%.19s %s",line,patterns[i].label ? patterns[i].label : prefix);
            int rc;
            if(!patterns[i].label && sscanf(line+20+strlen(prefix),": curl_rc=%d",&rc)==1){
                size_t used=strlen(record);snprintf(record+used,128-used," curl_rc=%d",rc);
            }
            break;
        }
    }
    buf_puts(b,"[");
    unsigned start=count>24?count-24:0;
    for(unsigned i=start;i<count;i++){if(i!=start)buf_puts(b,",");buf_json_string(b,records[i%24]);}
    buf_puts(b,"]");
}

static void diagnostic_tunnel_events(panel_buf *b, FILE *f) {
    static const struct diagnostic_pattern events[]={
        { "d2k-tg-watchdog: probe failed", NULL }, { "d2k-tg-watchdog: probe recovered", NULL },
        { "d2k-tg-watchdog: restart requested", NULL }, { "d2k-tg-watchdog: restart command completed", NULL },
        { "d2k-tg-watchdog: restart command failed", NULL }, { "d2ktg: relay session authenticated", NULL },
        { "d2ktg: relay session ended", NULL }, { "d2ktg: relay authentication failed", NULL },
        { "d2ktg: verified relay WSS connection failed", NULL }, { "d2ktg: cannot bind", NULL },
        { "d2ktg: relay identity registration failed", NULL }, { "d2k-tg-watchdog: probe unavailable", NULL }
    };
    diagnostic_log_events(b, f, events, sizeof events / sizeof events[0]);
}

static void diagnostic_service_events(panel_buf *b, FILE *f) {
    static const struct diagnostic_pattern events[] = {
        { "датапат не работает (контроллер работает: нет)", "both_down" },
        { "датапат не работает (контроллер работает: да)", "datapath_down" },
        { "контроллер не работает при живом датапате", "controller_down" },
        { "движок неполон (датапат: нет, контроллер: нет,", "both_down" },
        { "движок неполон (датапат: нет, контроллер: да,", "datapath_down" },
        { "движок неполон (датапат: да, контроллер: нет,", "controller_down" },
        { "датапат не поднялся (код ", "datapath_restart_failed" },
        { "контроллер не поднялся (код ", "controller_restart_failed" },
        { "движок восстановлен:", "recovered" },
        { "перезапуск движка для восстановления правил", "firewall_restart" },
        { "получена команда engine-restart", "restart_requested" },
        { "правила восстановлены сторожем", "firewall_recovered" }
    };
    diagnostic_log_events(b, f, events, sizeof events / sizeof events[0]);
}

#define DIAG_DOWNLOAD_EXTRA 8192

static int download_diagnostics(int fd,const d2k_panel_config *cfg,char *body,size_t len) {
    if (!cfg || !json_valid_object(body,body+len))
        return diagnostic_response(fd,500,"Internal Server Error","text/plain","",0);
    while (len && body[len-1]!='}') len--;
    size_t end=len-1;
    while (end && strchr(" \r\n\t",body[end-1])) end--;
    panel_buf b={.p=body,.len=len-1,.cap=len+DIAG_DOWNLOAD_EXTRA};
    buf_puts(&b,body[end-1]=='{' ? "" : ",");
    buf_printf(&b,"\"router_at_download\":{\"epoch\":%lld,\"engine_running\":%s,\"controller_running\":%s,"
               "\"queue_id\":%d,\"nfqueue\":",(long long)time(NULL),
               engine_pid_running(cfg,NULL)?"true":"false",controller_pid_running(cfg)?"true":"false",cfg->queue_num);
    FILE *q=fopen("/proc/net/netfilter/nfnetlink_queue","r");
    diagnostic_queue(&b,q,cfg->queue_num);
    if(q)fclose(q);
    char policy[256],state[24];int enabled=0,configured=0,running=0;
    buf_puts(&b,",\"configured_policy\":");
    if(cfg->config_path && !policy_config_read(cfg->config_path,policy,sizeof policy))buf_json_string(&b,policy);
    else buf_puts(&b,"null");
    buf_puts(&b,",\"mode\":");buf_json_string(&b,cfg->mode);
    telegram_config_flags(cfg,&enabled,&configured);
    telegram_status_value(cfg,enabled,configured,&running,state);
    buf_printf(&b,",\"telegram_running\":%s,\"telegram_state\":",running?"true":"false");
    buf_json_string(&b,state);
    buf_puts(&b,",\"telegram_recent_events\":");
    FILE *log=fopen("/opt/d2k/log/telegram.log","r");
    diagnostic_tunnel_events(&b,log);
    if(log)fclose(log);
    buf_puts(&b,",\"engine_recovery_events\":");
    log=fopen("/opt/d2k/log/service.log","r");
    diagnostic_service_events(&b,log);
    if(log)fclose(log);
    struct stat live;
    buf_puts(&b,",\"live_snapshot\":");
    if(cfg->live_path && !stat(cfg->live_path,&live) && S_ISREG(live.st_mode))
        buf_printf(&b,"{\"mtime\":%lld,\"bytes\":%lld}",(long long)live.st_mtime,(long long)live.st_size);
    else buf_puts(&b,"null");
    buf_puts(&b,"}}");
    if(b.failed)return diagnostic_response(fd,500,"Internal Server Error","text/plain","",0);
    return response_ex(fd,200,"OK","application/json; charset=utf-8",
        "Cache-Control: no-store\r\nContent-Disposition: attachment; filename=\"d2k-diagnostics.json\"\r\n",body,b.len);
}

static int api_diagnostics(int fd,const d2k_panel_config *cfg,const char *req,
                           const char *method,const char *action) {
    const char *dir=cfg&&cfg->diagnostics_dir?cfg->diagnostics_dir:D2K_DIAG_DIR;
    if(!strcmp(method,"POST")) {
        if(!cfg||!cfg->control_enabled||!d2k_panel_same_origin(req))
            return diagnostic_response(fd,403,"Forbidden","application/json","{\"error\":\"same-origin control required\"}",sizeof "{\"error\":\"same-origin control required\"}"-1);
        if(strcmp(action,"enable")&&strcmp(action,"disable"))
            return diagnostic_response(fd,400,"Bad Request","application/json","{}",2);
        if(d2k_diag_toggle(dir,!strcmp(action,"enable")))
            return diagnostic_response(fd,500,"Internal Server Error","application/json","{\"error\":\"diagnostic toggle failed\"}",sizeof "{\"error\":\"diagnostic toggle failed\"}"-1);
        const char *body=d2k_diag_enabled(dir)?"{\"enabled\":true}":"{\"enabled\":false}";
        return diagnostic_response(fd,200,"OK","application/json",body,strlen(body));
    }
    if(strcmp(method,"GET"))return diagnostic_response(fd,405,"Method Not Allowed","text/plain","",0);
    if(!d2k_diag_enabled(dir))return diagnostic_response(fd,200,"OK","application/json","{\"enabled\":false}",17);
    if(!strcmp(action,"status"))return diagnostic_response(fd,200,"OK","application/json","{\"enabled\":true}",16);
    char path[512];struct stat st;
    if(d2k_diag_path(path,sizeof path,dir,"report.json"))return diagnostic_response(fd,500,"Internal Server Error","text/plain","",0);
    int in=open(path,O_RDONLY|O_NOFOLLOW);
    if(in<0){
        if(errno==ENOENT && !strcmp(action,"download")){
            char empty[DIAG_DOWNLOAD_EXTRA+128]="{\"enabled\":true,\"pending\":true,\"events\":[],\"samples\":[]}";
            return download_diagnostics(fd,cfg,empty,strlen(empty));
        }
        return diagnostic_response(fd,503,"Service Unavailable","application/json","{\"enabled\":true,\"pending\":true}",31);
    }
    if(fstat(in,&st)||!S_ISREG(st.st_mode)||st.st_size<0||(uint64_t)st.st_size>D2K_DIAG_REPORT_MAX) {
        close(in);return diagnostic_response(fd,500,"Internal Server Error","text/plain","",0);
    }
    size_t len=(size_t)st.st_size,off=0;char *body=malloc(len+DIAG_DOWNLOAD_EXTRA);
    if(!body){close(in);return diagnostic_response(fd,503,"Service Unavailable","text/plain","",0);}
    while(off<len){ssize_t n=read(in,body+off,len-off);if(n<0&&errno==EINTR)continue;if(n<=0)break;off+=(size_t)n;}
    close(in);
    int rc;
    if(off!=len)rc=diagnostic_response(fd,503,"Service Unavailable","text/plain","",0);
    else if(!strcmp(action,"download"))rc=download_diagnostics(fd,cfg,body,len);
    else rc=diagnostic_response(fd,200,"OK","application/json; charset=utf-8",body,len);
    free(body);return rc;
}

static int dispatch_request(int fd, const d2k_panel_config *cfg, const char *req) {
    char method[8], path[256], version[16];
    if (sscanf(req, "%7s %255s %15s", method, path, version) != 3 ||
        (strcmp(version, "HTTP/1.1") != 0 && strcmp(version, "HTTP/1.0") != 0)) {
        return response(fd, 400, "Bad Request", "text/plain; charset=utf-8", "bad request\n", 12);
    }
    char *query = strchr(path, '?');
    if (query) { *query++ = '\0'; }
    if (!strcmp(path,"/api/policies")) return api_policies(fd,cfg,req,method);
    if (!strcmp(path,"/api/diagnostics"))
        return api_diagnostics(fd,cfg,req,method,query?query:"status");
    if (strcmp(path, "/api/update") == 0) {
        if (strcmp(method, "GET") != 0) {
            return response(fd, 405, "Method Not Allowed", "text/plain; charset=utf-8",
                            "method not allowed\n", 19);
        }
        return api_update(fd, cfg);
    }
    if (strncmp(path, "/api/control/", sizeof "/api/control/" - 1) == 0) {
        if (strcmp(method, "POST") != 0) {
            return response(fd, 405, "Method Not Allowed", "text/plain; charset=utf-8",
                            "method not allowed\n", 19);
        }
        return api_control(fd, cfg, req, path);
    }
    if (strcmp(method, "GET") != 0) {
        return response(fd, 405, "Method Not Allowed", "text/plain; charset=utf-8", "method not allowed\n", 19);
    }
    if (strcmp(path, "/api/status") == 0) { return api_status(fd, cfg, query); }
    if (strcmp(path, "/") == 0) {
        return static_file(fd, cfg, req, "index.html", "text/html; charset=utf-8");
    }
    if (strcmp(path, "/assets/favicon.svg") == 0) {
        return static_file(fd, cfg, req, "favicon.svg", "image/svg+xml");
    }
    if (strcmp(path, "/assets/panel.css") == 0) {
        return static_file(fd, cfg, req, "panel.css", "text/css; charset=utf-8");
    }
    if (!strcmp(path,"/assets/diagnostics.js"))
        return static_file(fd,cfg,req,"diagnostics.js","application/javascript; charset=utf-8");
    if (strcmp(path, "/assets/panel.js") == 0) {
        return static_file(fd, cfg, req, "panel.js", "application/javascript; charset=utf-8");
    }
    if (strcmp(path, "/assets/gsap.js") == 0) {
        return static_file(fd, cfg, req, "gsap.js", "application/javascript; charset=utf-8");
    }
    if (strcmp(path, "/assets/onest.woff2") == 0) {
        return static_file(fd, cfg, req, "fonts/onest.woff2", "font/woff2");
    }
    if (strcmp(path, "/assets/jbmono.woff2") == 0) {
        return static_file(fd, cfg, req, "fonts/jbmono.woff2", "font/woff2");
    }
    return response(fd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
}

int d2k_panel_handle_fd(int fd, const d2k_panel_config *cfg) {
    char small[2048];
    char *req = small;
    size_t used = 0;
    const long long deadline = monotonic_ms() + D2K_PANEL_HEADER_TIMEOUT_MS;
    int rr = read_request(fd, req, sizeof small, &used, deadline);
    if (rr == 1) {
        req = malloc(REQUEST_MAX + 1);
        if (!req) { return -1; }
        memcpy(req, small, used + 1);
        rr = read_request(fd, req, REQUEST_MAX + 1, &used, deadline);
    }
    if (rr == 0) {
        int rc = dispatch_request(fd, cfg, req);
        if (req != small) { free(req); }
        return rc;
    }
    if (req != small) { free(req); }
    if (rr == -2) {
        static const char timed_out[] = "request timeout\n";
        return response(fd, 408, "Request Timeout", "text/plain; charset=utf-8",
                        timed_out, sizeof timed_out - 1);
    }
    static const char too_large[] = "request too large\n";
    static const char bad_request[] = "bad request\n";
    return response(fd, rr > 0 ? 431 : 400,
                    rr > 0 ? "Request Header Fields Too Large" : "Bad Request",
                    "text/plain; charset=utf-8",
                    rr > 0 ? too_large : bad_request,
                    rr > 0 ? sizeof too_large - 1 : sizeof bad_request - 1);
}
