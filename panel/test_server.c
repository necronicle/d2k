#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <utime.h>
#include <unistd.h>

typedef struct {
    int fd;
    const d2k_panel_config *cfg;
} server_call;

static void *serve_thread(void *arg) {
    server_call *call = arg;
    (void)d2k_panel_handle_fd(call->fd, call->cfg);
    close(call->fd);
    return NULL;
}

static void write_all(int fd, const char *s) {
    size_t n = strlen(s), off = 0;
    while (off < n) {
        ssize_t wr = write(fd, s + off, n - off);
        assert(wr > 0);
        off += (size_t)wr;
    }
}

static void send_request(int fd, const char *s) {
    size_t n = strlen(s), off = 0;
    while (off < n) {
        ssize_t wr = write(fd, s + off, n - off);
        if (wr <= 0) { return; } /* handler may correctly reject and close early */
        off += (size_t)wr;
    }
}

static size_t request(const d2k_panel_config *cfg, const char *req,
                      char *response, size_t cap) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    server_call call = { .fd = sv[1], .cfg = cfg };
    pthread_t thread;
    assert(pthread_create(&thread, NULL, serve_thread, &call) == 0);
    send_request(sv[0], req);
    (void)shutdown(sv[0], SHUT_WR);
    size_t used = 0;
    char drain[4096];
    for (;;) {
        char *dst = used + 1 < cap ? response + used : drain;
        size_t room = used + 1 < cap ? cap - used - 1 : sizeof drain;
        ssize_t n = read(sv[0], dst, room);
        if (n <= 0) { break; }
        if (used + 1 < cap) { used += (size_t)n; }
    }
    response[used] = '\0';
    assert(pthread_join(thread, NULL) == 0);
    close(sv[0]);
    return used;
}

static void write_temp_file(char path[], const char *contents) {
    int fd = mkstemp(path);
    assert(fd >= 0);
    write_all(fd, contents);
    close(fd);
}

static void rewrite_file(const char *path,const char *contents) {
    FILE *f=fopen(path,"w");assert(f);assert(fwrite(contents,1,strlen(contents),f)==strlen(contents));assert(fclose(f)==0);
}

static void test_api_exposes_live_knowledge(void) {
    char live[] = "/tmp/d2k-panel-live.XXXXXX";
    write_temp_file(live, "{\"linked\":true,\"link_note\":\"\",\"boxes\":[],\"searches\":[],\"targets\":0,\"confirms\":0,\"probes_used\":0,\"client_unfit\":0}");

    static const char *unknown[] = { "FUTURE_OPTION" };
    d2k_panel_config cfg = {
        .live_path = live,
        .asset_dir = "panel/assets",
        .version = "test-version",
        .commit = "0123456789abcdef",
        .built = "2026-09-27T00:00:00Z",
        .mode = "observe",
        .panel_listen = "127.0.0.1:8090",
        .config_path = "/tmp/d2k/config",
        .state_dir = "/tmp/d2k/state",
        .state_dir_note = "есть",
        .unknown_keys = unknown,
        .unknown_key_count = 1,
        .queue_num = 2000,
        .started_epoch = 1,
        .config_exists = 1,
    };
    char response[32768];
    (void)request(&cfg, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "Content-Type: application/json; charset=utf-8") != NULL);
    assert(strstr(response, "\"snapshot\":{\"taken\":") != NULL);
    assert(strstr(response, "\"version\":\"test-version\"") != NULL);
    assert(strstr(response, "\"unknown_keys\":[\"FUTURE_OPTION\"]") != NULL);
    assert(strstr(response, "\"linked\":true") != NULL);
    assert(strstr(response, "\"live_fresh\":true") != NULL);
    rewrite_file(live, "{\"linked\":true,\"boxes\":[],\"groups\":[{\"suffix\":\"googlevideo.com\",\"shape\":1,\"active\":true,\"exceptions\":[{\"name\":\"clean.googlevideo.com\"}]}]}");
    (void)request(&cfg, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n", response, sizeof response);
    assert(strstr(response, "\"groups\":[") != NULL);
    assert(strstr(response, "clean.googlevideo.com") != NULL);
    assert(strstr(response, "Content-Security-Policy:") != NULL);
    cfg.engine_pid_path = "/tmp/d2k-panel-no-such-engine.pid";
    cfg.controller_pid_path = "/tmp/d2k-panel-no-such-controller.pid";
    (void)request(&cfg, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "\"engine_running\":false") != NULL);
    assert(strstr(response, "\"controller_running\":false") != NULL);
    assert(strstr(response, "\"linked\":false") != NULL);
    assert(strstr(response, "\"linked\":true") == NULL);
    cfg.engine_pid_path = NULL;
    struct utimbuf old = { .actime = time(NULL) - 60, .modtime = time(NULL) - 60 };
    assert(utime(live, &old) == 0);
    (void)request(&cfg, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "\"live_fresh\":false") != NULL);
    assert(strstr(response, "\"linked\":false") != NULL);
    assert(strstr(response, "\"linked\":true") == NULL);
    unlink(live);
}

static void test_invalid_live_json_is_not_reported_as_empty_knowledge(void) {
    char live[] = "/tmp/d2k-panel-invalid.XXXXXX";
    write_temp_file(live, "{broken json}");
    d2k_panel_config cfg = {
        .live_path = live,
        .asset_dir = "panel/assets",
        .version = "test-version",
        .commit = "0123456789abcdef",
        .built = "2026-09-27T00:00:00Z",
        .mode = "observe",
        .panel_listen = "127.0.0.1:8090",
        .config_path = "/tmp/d2k/config",
        .state_dir = "/tmp/d2k/state",
        .state_dir_note = "есть",
        .queue_num = 2000,
        .started_epoch = 1,
        .config_exists = 1,
    };
    char response[4096];
    (void)request(&cfg, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "\"linked\":false") != NULL);
    assert(strstr(response, "движок не отдаёт состояние") != NULL);
    assert(strstr(response, "broken json") == NULL);
    unlink(live);
}

static void test_telegram_status_is_dynamic_and_never_exposes_secret(void) {
    char live[]="/tmp/d2k-panel-tg-live.XXXXXX",config[]="/tmp/d2k-panel-tg-config.XXXXXX";
    char status[]="/tmp/d2k-panel-tg-status.XXXXXX",pid[]="/tmp/d2k-panel-tg-pid.XXXXXX";
    write_temp_file(live,"{\"linked\":false,\"boxes\":[],\"searches\":[],\"targets\":0,\"confirms\":0,\"probes_used\":0,\"client_unfit\":0}");
    write_temp_file(config,"TG_ENABLED=0\nTG_RELAY_URL=wss://relay.example/ws\nTG_RELAY_SECRET=secret-must-not-leak\n");
    write_temp_file(status,"connected\n");write_temp_file(pid,"1\n");
    d2k_panel_config cfg={.live_path=live,.asset_dir="panel/assets",.config_path=config,
        .telegram_status_path=status,.telegram_pid_path=pid,.mode="observe",.state_dir="/tmp/state",.started_epoch=1};
    char response[32768];
    (void)request(&cfg,"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",response,sizeof response);
    assert(strstr(response,"\"telegram_configured\":true")!=NULL);
    assert(strstr(response,"\"telegram_enabled\":false")!=NULL);
    assert(strstr(response,"\"telegram_running\":false")!=NULL);
    assert(strstr(response,"\"telegram_status\":\"stopped\"")!=NULL);
    assert(strstr(response,"secret-must-not-leak")==NULL);

    rewrite_file(config,"TG_ENABLED=1\nTG_RELAY_URL=wss://relay.example/ws\nTG_RELAY_SECRET=secret-must-not-leak\n");
    FILE *f=fopen(pid,"w");assert(f);assert(fprintf(f,"%ld\n",(long)getpid())>0);fclose(f);
    (void)request(&cfg,"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",response,sizeof response);
    assert(strstr(response,"\"telegram_enabled\":true")!=NULL);
    assert(strstr(response,"\"telegram_running\":true")!=NULL);
    assert(strstr(response,"\"telegram_status\":\"connected\"")!=NULL);
    assert(strstr(response,"secret-must-not-leak")==NULL);

    rewrite_file(config,"TG_ENABLED=1\nTG_RELAY_URL=wss://relay.example/ws\n");
    (void)request(&cfg,"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",response,sizeof response);
    assert(strstr(response,"\"telegram_configured\":false")!=NULL);
    assert(strstr(response,"\"telegram_status\":\"not_configured\"")!=NULL);
    rewrite_file(config,"TG_ENABLED=1\nTG_RELAY_URL=wss://relay.example/ws\nTG_ENROLL_PORT=9443\n");
    (void)request(&cfg,"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",response,sizeof response);
    assert(strstr(response,"\"telegram_configured\":true")!=NULL);
    assert(strstr(response,"\"telegram_status\":\"connected\"")!=NULL);
    rewrite_file(config,"TG_ENABLED=\"1\"\nTG_RELAY_URL='wss://relay.example/ws'\nTG_ENROLL_PORT=\"9443\"\n");
    (void)request(&cfg,"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",response,sizeof response);
    assert(strstr(response,"\"telegram_configured\":true")!=NULL);
    assert(strstr(response,"\"telegram_status\":\"connected\"")!=NULL);
    unlink(live);unlink(config);unlink(status);unlink(pid);
}

/* Состояние автообновления пишет d2k-update.sh; панель отдаёт файл как есть.
   Нет утилиты — «не подключено», есть, но не проверялось — пустое состояние. */
static void test_update_state_is_served_from_file(void) {
    char state[] = "/tmp/d2k-panel-update-state.XXXXXX";
    write_temp_file(state, "{\"busy\":\"\",\"current\":\"r2\"}\n");
    d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = "panel/assets",
                             .update_state_path = state, .updater_path = "/bin/sh" };
    char response[4096];
    (void)request(&cfg, "GET /api/update HTTP/1.1\r\nHost: localhost\r\n\r\n", response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "{\"busy\":\"\",\"current\":\"r2\"}") != NULL);
    unlink(state);
    (void)request(&cfg, "GET /api/update HTTP/1.1\r\nHost: localhost\r\n\r\n", response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL && strstr(response, "{\"never\":true}") != NULL);
    cfg.updater_path = "/absent/d2k-update.sh";
    (void)request(&cfg, "GET /api/update HTTP/1.1\r\nHost: localhost\r\n\r\n", response, sizeof response);
    assert(strstr(response, "{\"absent\":true}") != NULL);
    (void)request(&cfg, "POST /api/update HTTP/1.1\r\nHost: localhost\r\n\r\n", response, sizeof response);
    assert(strstr(response, "HTTP/1.1 405") != NULL);
}

static void test_unsupported_method_is_rejected(void) {
    d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = "panel/assets" };
    char response[4096];
    (void)request(&cfg, "POST /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 405 Method Not Allowed") != NULL);
}

static void wait_action_done(const d2k_panel_config *cfg) {
    char result[8192];
    for (int i=0; i<300; i++) {
        request(cfg, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n", result, sizeof result);
        if (!strstr(result, "\"control_state\":\"running\"")) break;
        struct timespec pause = { .tv_nsec=10000000 }; nanosleep(&pause, NULL);
    }
    assert(strstr(result, "\"control_state\":\"done\""));
}

static void test_panel_accepts_a_control_action_request(void) {
    char service[] = "/tmp/d2k-panel-service.XXXXXX";
    char marker[] = "/tmp/d2k-panel-action.XXXXXX";
    int marker_fd = mkstemp(marker);
    assert(marker_fd >= 0);
    close(marker_fd);
    int service_fd = mkstemp(service);
    assert(service_fd >= 0);
    char script[PATH_MAX];
    int n = snprintf(script, sizeof script,
        "#!/bin/sh\nprintf '%%s' \"$1\" > '%s'\nexit 0\n", marker);
    assert(n > 0 && (size_t)n < sizeof script);
    write_all(service_fd, script);
    close(service_fd);
    assert(chmod(service, 0700) == 0);
    d2k_panel_config cfg = {
        .live_path = "/absent", .asset_dir = "panel/assets",
        .service_path = service, .control_enabled = 1,
    };
    char response[4096];
    (void)request(&cfg,
        "POST /api/control/stop HTTP/1.1\r\n"
        "Host: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\n"
        "Content-Length: 0\r\n\r\n",
        response, sizeof response);
    assert(strstr(response, "HTTP/1.1 202 Accepted") != NULL);
    wait_action_done(&cfg);
    char action[64] = "";
    FILE *f = fopen(marker, "r");
    assert(f != NULL);
    assert(fgets(action, sizeof action, f) != NULL);
    fclose(f);
    assert(strcmp(action, "engine-stop") == 0);
    static const struct { const char *path; const char *command; } routes[] = {
        { "start", "engine-start" }, { "restart", "engine-restart" },
        { "reapply", "reapply" }, { "telegram-disable", "telegram-disable" },
        { "update-check", "update-check" }, { "update-install", "update-install" },
        { "update-auto-on", "update-auto-on" }, { "update-auto-off", "update-auto-off" },
    };
    for (size_t i = 0; i < sizeof routes / sizeof routes[0]; i++) {
        char req[512];
        n = snprintf(req, sizeof req,
            "POST /api/control/%s HTTP/1.1\r\nHost: localhost:8090\r\n"
            "Origin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n",
            routes[i].path);
        assert(n > 0 && (size_t)n < sizeof req);
        (void)request(&cfg, req, response, sizeof response);
        assert(strstr(response, "HTTP/1.1 202 Accepted") != NULL);
        wait_action_done(&cfg);
        f = fopen(marker, "r");
        assert(f != NULL);
        strcpy(action, "");
        assert(fgets(action, sizeof action, f) != NULL);
        fclose(f);
        assert(strcmp(action, routes[i].command) == 0);
    }
    (void)request(&cfg,
        "POST /api/control/telegram-enable HTTP/1.1\r\nHost: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n",
        response, sizeof response);
    assert(strstr(response,"HTTP/1.1 409 Conflict")!=NULL);
    char tg_config[]="/tmp/d2k-panel-tg-control-config.XXXXXX";
    write_temp_file(tg_config,"TG_ENABLED=0\nTG_RELAY_URL=wss://relay.example/ws\nTG_ENROLL_PORT=9443\n");
    cfg.config_path=tg_config;
    (void)request(&cfg,
        "POST /api/control/telegram-enable HTTP/1.1\r\nHost: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n",
        response, sizeof response);
    assert(strstr(response,"HTTP/1.1 202 Accepted")!=NULL);
    wait_action_done(&cfg);
    f=fopen(marker,"r");assert(f);strcpy(action,"");assert(fgets(action,sizeof action,f));fclose(f);
    assert(strcmp(action,"telegram-enable")==0);
    assert(strstr(response,"private")==NULL);unlink(tg_config);
    (void)request(&cfg,
        "POST /api/control/stop HTTP/1.1\r\n"
        "Host: 192.168.1.1:8090\r\n"
        "Origin: http://192.168.1.1:8090\r\n"
        "Content-Length: 0\r\n\r\n",
        response, sizeof response);
    assert(strstr(response, "HTTP/1.1 202 Accepted") != NULL);
    wait_action_done(&cfg);
    f = fopen(marker, "r");
    assert(f != NULL);
    strcpy(action, "");
    assert(fgets(action, sizeof action, f) != NULL);
    fclose(f);
    assert(strcmp(action, "engine-stop") == 0);
    (void)request(&cfg,
        "POST /api/control/start HTTP/1.1\r\n"
        "Host: localhost:8090\r\n"
        "Origin: http://attacker.example\r\n"
        "Content-Length: 0\r\n\r\n",
        response, sizeof response);
    assert(strstr(response, "HTTP/1.1 403 Forbidden") != NULL);
    f = fopen(marker, "r");
    assert(f != NULL);
    strcpy(action, "");
    assert(fgets(action, sizeof action, f) != NULL);
    fclose(f);
    assert(strcmp(action, "engine-stop") == 0);
    cfg.mode = "off";
    (void)request(&cfg,
        "POST /api/control/start HTTP/1.1\r\nHost: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n",
        response, sizeof response);
    assert(strstr(response, "HTTP/1.1 409 Conflict") != NULL);
    (void)request(&cfg,
        "POST /api/control/restart HTTP/1.1\r\nHost: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n",
        response, sizeof response);
    assert(strstr(response, "HTTP/1.1 409 Conflict") != NULL);
    f = fopen(marker, "r");
    assert(f != NULL);
    strcpy(action, "");
    assert(fgets(action, sizeof action, f) != NULL);
    fclose(f);
    assert(strcmp(action, "engine-stop") == 0);
    cfg.mode = NULL;
    cfg.control_enabled = 0;
    (void)request(&cfg,
        "POST /api/control/start HTTP/1.1\r\nHost: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n",
        response, sizeof response);
    assert(strstr(response, "HTTP/1.1 403 Forbidden") != NULL);
    (void)request(&cfg,
        "POST /api/control/anything HTTP/1.1\r\n"
        "Host: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\n"
        "Content-Length: 0\r\n\r\n",
        response, sizeof response);
    assert(strstr(response, "HTTP/1.1 404 Not Found") != NULL);
    unlink(marker);
    unlink(service);
}

static void test_slow_control_does_not_block_status(void) {
    char service[] = "/tmp/d2k-panel-slow.XXXXXX";
    write_temp_file(service, "#!/bin/sh\nsleep 2\n");
    assert(chmod(service, 0700) == 0);
    d2k_panel_config cfg = { .service_path = service, .control_enabled = 1 };
    char result[8192];
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    request(&cfg, "POST /api/control/stop HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n", result, sizeof result);
    clock_gettime(CLOCK_MONOTONIC, &b);
    assert((b.tv_sec-a.tv_sec)*1000+(b.tv_nsec-a.tv_nsec)/1000000 < 500);
    assert(strstr(result, "202 Accepted"));
    request(&cfg, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n", result, sizeof result);
    assert(strstr(result, "\"control_state\":\"running\""));
    request(&cfg, "POST /api/control/stop HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n", result, sizeof result);
    assert(strstr(result, "409 Conflict"));
    for (int i=0; i<300; i++) {
        struct timespec pause = { .tv_nsec=10000000 }; nanosleep(&pause, NULL);
        request(&cfg, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n", result, sizeof result);
        if (!strstr(result, "\"control_state\":\"running\"")) break;
    }
    assert(strstr(result, "\"control_state\":\"timeout\""));
    unlink(service);
}

static void test_unknown_and_traversal_paths_are_not_served(void) {
    d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = "panel/assets" };
    char response[4096];
    (void)request(&cfg, "GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 404 Not Found") != NULL);
    assert(strstr(response, "root:") == NULL);
}

static void test_oversized_request_header_gets_431(void) {
    size_t n = 40u * 1024u;
    char *req = malloc(n + 128);
    assert(req != NULL);
    size_t used = (size_t)snprintf(req, n + 128,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: ");
    memset(req + used, 'a', n);
    used += n;
    memcpy(req + used, "\r\n\r\n", 5);
    d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = "panel/assets" };
    char response[4096];
    (void)request(&cfg, req, response, sizeof response);
    assert(strstr(response, "HTTP/1.1 431 Request Header Fields Too Large") != NULL);
    free(req);
}

static void test_asset_symlink_cannot_escape_asset_directory(void) {
    char dir[PATH_MAX];
    int dn = snprintf(dir, sizeof dir, "/tmp/d2k-panel-assets.%ld", (long)getpid());
    assert(dn > 0 && (size_t)dn < sizeof dir);
    assert(mkdir(dir, 0700) == 0);
    char linkpath[PATH_MAX];
    int n = snprintf(linkpath, sizeof linkpath, "%s/panel.css", dir);
    assert(n > 0 && (size_t)n < sizeof linkpath);
    assert(symlink("/etc/passwd", linkpath) == 0);
    d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = dir };
    char response[4096];
    (void)request(&cfg, "GET /assets/panel.css HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 404 Not Found") != NULL);
    assert(strstr(response, "root:") == NULL);
    unlink(linkpath);
    rmdir(dir);
}

static void test_root_serves_static_offline_panel_shell(void) {
    d2k_panel_config cfg = {
        .live_path = "/absent",
        .asset_dir = "../internal/web/assets",
    };
    char response[8192];
    (void)request(&cfg, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "Content-Type: text/html; charset=utf-8") != NULL);
    assert(strstr(response, "id=\"app\"") != NULL);
    assert(strstr(response, "src=\"/assets/panel.js\"") != NULL);
}

static void test_panel_javascript_is_served_same_origin(void) {
    d2k_panel_config cfg = {
        .live_path = "/absent",
        .asset_dir = "../internal/web/assets",
    };
    char response[8192];
    (void)request(&cfg, "GET /assets/panel.js HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "Content-Type: application/javascript; charset=utf-8") != NULL);
}

static void test_retired_slidoscope_assets_are_not_served(void) {
    d2k_panel_config cfg = {
        .live_path = "/absent",
        .asset_dir = "../internal/web/assets",
    };
    static const char *retired[] = {
        "/assets/logo-d2k.png", "/assets/mascot-d2k.png", "/assets/mascot.svg",
        "/assets/oswald.ttf", "/assets/ground.webp", "/assets/rack.webp",
        "/assets/family-rack.webp", "/assets/slide-left.webp", "/assets/slide-center.webp",
        "/assets/slide-right.webp", "/assets/slide-holder.webp",
    };
    char req[256], response[8192];
    for (size_t i = 0; i < sizeof retired / sizeof retired[0]; i++) {
        snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", retired[i]);
        (void)request(&cfg, req, response, sizeof response);
        assert(strstr(response, "HTTP/1.1 404 Not Found") != NULL);
    }
}

static void test_offline_text_fonts_are_served_as_woff2(void) {
    d2k_panel_config cfg = {
        .live_path = "/absent",
        .asset_dir = "../internal/web/assets",
    };
    char response[8192];
    (void)request(&cfg, "GET /assets/onest.woff2 HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "Content-Type: font/woff2") != NULL);
    (void)request(&cfg, "GET /assets/jbmono.woff2 HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "Content-Type: font/woff2") != NULL);
}

static void test_vendored_animation_library_is_served_same_origin(void) {
    d2k_panel_config cfg = {
        .live_path = "/absent",
        .asset_dir = "../internal/web/assets",
    };
    char response[8192];
    (void)request(&cfg, "GET /assets/gsap.js HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "Content-Type: application/javascript; charset=utf-8") != NULL);
}

static void test_static_assets_revalidate_with_etag(void) {
    d2k_panel_config cfg = {
        .live_path = "/absent",
        .asset_dir = "../internal/web/assets",
    };
    char response[8192];
    (void)request(&cfg, "GET /assets/panel.css HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "Cache-Control: no-cache") != NULL);
    const char *etag = strstr(response, "ETag: \"");
    assert(etag != NULL);
    char tag[64];
    const char *start = etag + 6, *end = strstr(start, "\r\n");
    assert(end && (size_t)(end - start) < sizeof tag);
    memcpy(tag, start, (size_t)(end - start));
    tag[end - start] = '\0';
    char req[256];
    snprintf(req, sizeof req, "GET /assets/panel.css HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: %s\r\n\r\n", tag);
    size_t n = request(&cfg, req, response, sizeof response);
    assert(strstr(response, "HTTP/1.1 304 Not Modified") != NULL);
    assert(strstr(response, "Content-Length: 0") != NULL);
    assert(n < 1024);
    (void)request(&cfg, "GET /assets/panel.css HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: \"0-0\"\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
}

static void test_disconnected_client_cannot_sigpipe_server(void) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        (void)signal(SIGPIPE, SIG_DFL);
        d2k_panel_ignore_sigpipe();
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { _exit(10); }
        const char req[] = "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        if (write(sv[0], req, sizeof req - 1) != (ssize_t)(sizeof req - 1)) { _exit(11); }
        shutdown(sv[0], SHUT_RDWR);
        close(sv[0]);
        d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = "panel/assets" };
        (void)d2k_panel_handle_fd(sv[1], &cfg);
        close(sv[1]);
        _exit(0);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_diagnostic_history_controls_and_download(void) {
    char dir[128],path[256],reply[8192];
    snprintf(dir,sizeof dir,"/tmp/d2k-panel-diag-api-%ld",(long)getpid());assert(mkdir(dir,0700)==0);
    d2k_panel_config cfg={.control_enabled=1,.diagnostics_dir=dir};
    request(&cfg,"GET /api/diagnostics HTTP/1.1\r\nHost: localhost\r\n\r\n",reply,sizeof reply);
    assert(strstr(reply,"\"enabled\":false"));assert(strstr(reply,"Cache-Control: no-store"));
    const char *enable="POST /api/diagnostics?enable HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n";
    request(&cfg,enable,reply,sizeof reply);assert(strstr(reply,"200 OK"));assert(strstr(reply,"\"enabled\":true"));
    request(&cfg,"GET /api/diagnostics?download HTTP/1.1\r\nHost: localhost\r\n\r\n",reply,sizeof reply);
    assert(strstr(reply,"200 OK"));assert(strstr(reply,"\"pending\":true"));assert(strstr(reply,"\"router_at_download\":"));
    snprintf(path,sizeof path,"%s/report.json",dir);FILE *f=fopen(path,"w");assert(f);fputs("{\"schema\":1,\"enabled\":true,\"samples\":[]}",f);fclose(f);
    request(&cfg,"GET /api/diagnostics?download HTTP/1.1\r\nHost: localhost\r\n\r\n",reply,sizeof reply);
    assert(strstr(reply,"200 OK"));assert(strstr(reply,"Content-Disposition: attachment"));assert(strstr(reply,"\"samples\":[]"));
    assert(truncate(path,256*1024+1)==0);
    request(&cfg,"GET /api/diagnostics?download HTTP/1.1\r\nHost: localhost\r\n\r\n",reply,sizeof reply);assert(strstr(reply,"500 Internal Server Error"));
    request(&cfg,"POST /api/diagnostics?disable HTTP/1.1\r\nHost: localhost\r\nOrigin: http://evil.invalid\r\nContent-Length: 0\r\n\r\n",reply,sizeof reply);assert(strstr(reply,"403 Forbidden"));
    snprintf(path,sizeof path,"%s/report.new",dir);f=fopen(path,"w");assert(f);fputs("partial",f);fclose(f);
    request(&cfg,"POST /api/diagnostics?disable HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n",reply,sizeof reply);assert(strstr(reply,"\"enabled\":false"));assert(access(path,F_OK)!=0);
    assert(rmdir(dir)==0);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    test_diagnostic_history_controls_and_download();
    test_api_exposes_live_knowledge();
    test_invalid_live_json_is_not_reported_as_empty_knowledge();
    test_telegram_status_is_dynamic_and_never_exposes_secret();
    test_update_state_is_served_from_file();
    test_unsupported_method_is_rejected();
    test_slow_control_does_not_block_status();
    test_panel_accepts_a_control_action_request();
    test_unknown_and_traversal_paths_are_not_served();
    test_oversized_request_header_gets_431();
    test_asset_symlink_cannot_escape_asset_directory();
    test_root_serves_static_offline_panel_shell();
    test_panel_javascript_is_served_same_origin();
    test_retired_slidoscope_assets_are_not_served();
    test_offline_text_fonts_are_served_as_woff2();
    test_vendored_animation_library_is_served_same_origin();
    test_static_assets_revalidate_with_etag();
    test_disconnected_client_cannot_sigpipe_server();
    puts("C panel HTTP contract: all checks passed");
    return 0;
}
