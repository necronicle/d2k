#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include "server.c"
/* Ответ читается с другого конца настоящей пары сокетов: после общего срока
   на ответ (#12) отправка идёт через fcntl и poll, подмена write не годится. */
static char captured[65536]; static size_t captured_len;
static void save_live(const char *path, int wins, int counter, const char *suffix) {
    FILE *f = fopen(path, "w"); assert(f);
    fprintf(f, "{\"linked\":true,\"catalog_at\":\"fixture\",\"boxes\":[{\"wins\":%d,\"name\":\"", wins);
    for (int i = 0; i < 3000; ++i) fputc('a', f);
    fprintf(f, "\"}],\"groups\":[{\"suffix\":\"%s\"}],\"searches\":[],\"probes_used\":%d}", suffix, counter);
    assert(fclose(f) == 0);
}
static char *get_status(const d2k_panel_config *cfg, const char *query) {
    captured_len = 0;
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    int big = 1 << 20;
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    (void)setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    assert(api_status(sv[0], cfg, query) == 0);
    close(sv[0]);
    for (;;) {
        assert(captured_len + 1 < sizeof captured);
        ssize_t n = read(sv[1], captured + captured_len, sizeof captured - 1 - captured_len);
        assert(n >= 0);
        if (n == 0) break;
        captured_len += (size_t)n;
    }
    close(sv[1]);
    captured[captured_len] = 0;
    char *body = strstr(captured, "\r\n\r\n"); assert(body); body += 4;
    assert(json_valid_object(body, body + strlen(body))); return body;
}
int main(void) {
    char dir[] = "/tmp/d2k-cache-XXXXXX", live[256], pid[256], revision[17], query[64];
    assert(mkdtemp(dir)); snprintf(live, sizeof live, "%s/live", dir); snprintf(pid, sizeof pid, "%s/pid", dir);
    FILE *f = fopen(pid, "w"); assert(f); fprintf(f, "%ld\n", (long)getpid()); fclose(f);
    d2k_panel_config cfg = { .mode = "apply", .live_path = live, .engine_pid_path = pid, .controller_pid_path = pid,
                            .telegram_pid_path = pid, .config_path = live, .state_dir = dir };
    save_live(live, 1, 10, "example.test");
    char *body = get_status(&cfg, NULL); const char *value; size_t len;
    assert(json_top_value(body, "catalog_revision", &value, &len) && len == 18);
    memcpy(revision, value + 1, 16); revision[16] = 0;
    size_t full_len = captured_len;
    snprintf(query, sizeof query, "catalog_revision=%s", revision);
    save_live(live, 1, 11, "example.test"); body = get_status(&cfg, query);
    assert(json_top_true(body, "catalog_unchanged"));
    assert(strstr(body, "\"boxes\":null") && strstr(body, "\"groups\":null"));
    assert(strstr(body, "\"probes_used\":11") && full_len > captured_len + 2500);
    save_live(live, 2, 12, "example.test"); body = get_status(&cfg, query);
    assert(!json_top_true(body, "catalog_unchanged") && strstr(body, "\"wins\":2"));
    save_live(live, 1, 13, "changed.test"); body = get_status(&cfg, query);
    assert(!json_top_true(body, "catalog_unchanged") && strstr(body, "changed.test"));
    f = fopen(live, "w"); assert(f);
    assert(fputs("{\"groups\":[1],\"probes_used\":42,\"boxes\":[2],\"linked\":true}", f) >= 0);
    assert(fclose(f) == 0);
    cfg.engine_pid_path = "/absent";
    body = get_status(&cfg, NULL);
    assert(json_top_value(body, "catalog_revision", &value, &len) && len == 18);
    snprintf(query, sizeof query, "catalog_revision=%.*s", 16, value + 1);
    body = get_status(&cfg, query);
    assert(strstr(body, "\"groups\":null,\"probes_used\":42,\"boxes\":null,\"linked\":false"));
    body = get_status(&cfg, "catalog_revision=invalid");
    assert(!json_top_true(body, "catalog_unchanged") && strstr(body, "\"boxes\":["));
    body = get_status(&cfg, NULL);
    assert(strstr(body, "\"groups\":["));
    unlink(live); unlink(pid); rmdir(dir);
    puts("status: cache validator, fresh counters, catalog changes and full fallback PASS"); return 0;
}
