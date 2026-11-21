#define _POSIX_C_SOURCE 200809L
#include "server.c"
#include <assert.h>

/* ЧТО ИМЕННО ОБЯЗАН ВЕРНУТЬ response() НА МЕСТО.
 *
 * Он снимает и возвращает O_NONBLOCK — и только его. Сравнивать ВСЁ слово
 * флагов нельзя: на macOS сама запись в дескриптор поднимает бит 0x10000, без
 * всякого fcntl. Замер 12.10.2026 (/tmp/bit.c, пять случаев):
 *
 *   просто запись                       до=0x00001 после=0x10001  ИЗМЕНИЛОСЬ
 *   O_NONBLOCK туда-обратно, без записи  до=0x00001 после=0x00001  —
 *   O_NONBLOCK, запись, возврат          до=0x00001 после=0x10001  ИЗМЕНИЛОСЬ
 *   только poll                          до=0x00001 после=0x00001  —
 *   poll + запись                        до=0x00001 после=0x10001  ИЗМЕНИЛОСЬ
 *
 * То же у socketpair (0x00002 → 0x10002), то есть дело не в канале. Тот же
 * двоичный код на Linux (роутер, aarch64 musl) не меняет слово НИ В ОДНОМ из
 * пяти случаев. В публичных заголовках macOS этот бит как флаг открытия не
 * назван — он не наш, мы его не ставили и возвращать не обязаны.
 *
 * Требование от этого не ослабло, а стало точным: F_SETFL по POSIX меняет
 * только O_APPEND, O_NONBLOCK и O_ASYNC, и ровно эти биты обязаны вернуться
 * такими, какими были. Оставленный O_NONBLOCK или затёртый O_APPEND проверка
 * ловит по-прежнему. */
#define SETTABLE_FLAGS (O_APPEND | O_NONBLOCK | O_ASYNC)

static void slow_reader(const d2k_panel_config *assets) {
    int fds[2];
    assert(pipe(fds) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(fds[1]);
        char chunk[4096];
        struct timespec pause = { .tv_nsec = 20000000 };
        for (int i = 0; i < 25; i++) {
            nanosleep(&pause, NULL);
            if (read(fds[0], chunk, sizeof chunk) <= 0) break;
        }
        close(fds[0]); _exit(0);
    }
    close(fds[0]);
    static char body[BODY_MAX];
    int flags = fcntl(fds[1], F_GETFL);
    long long start = monotonic_ms();
    int rc = assets ? static_file(fds[1], assets, NULL, "asset", "text/plain")
                    : response(fds[1], 200, "OK", "text/plain", body, sizeof body);
    int saved_errno = errno;
    long long elapsed = monotonic_ms() - start;
    assert(rc == -1 && saved_errno == ETIMEDOUT);
    assert(elapsed >= D2K_PANEL_RESPONSE_TIMEOUT_MS && elapsed < 400);
    /* И на отказе тоже: прерванная по сроку посылка обязана вернуть
       дескриптор в прежний режим, иначе следующий ответ уйдёт неблокирующим
       и оборвётся на первом же EAGAIN. */
    assert((fcntl(fds[1], F_GETFL) & SETTABLE_FLAGS) == (flags & SETTABLE_FLAGS));
    close(fds[1]);
    assert(kill(child, SIGTERM) == 0); assert(waitpid(child, NULL, 0) == child);
}

int main(void) {
    assert(d2k_panel_ignore_sigpipe() == 0);
    int fds[2]; assert(pipe(fds) == 0);
    int flags = fcntl(fds[1], F_GETFL); assert(flags >= 0);
    assert(response(fds[1], 200, "OK", "text/plain", "complete\n", 9) == 0);
    assert((fcntl(fds[1], F_GETFL) & SETTABLE_FLAGS) == (flags & SETTABLE_FLAGS));
    close(fds[1]);
    char small[2048]; ssize_t n = read(fds[0], small, sizeof small - 1);
    assert(n > 0); small[n] = '\0';
    assert(strstr(small, "HTTP/1.1 200 OK\r\n"));
    assert(strstr(small, "\r\n\r\ncomplete\n")); close(fds[0]);

    slow_reader(NULL);
    char dir[] = "/tmp/d2k-response-deadline-XXXXXX", path[256];
    assert(mkdtemp(dir));
    snprintf(path, sizeof path, "%s/asset", dir);
    int asset = open(path, O_CREAT | O_RDWR, 0600);
    assert(asset >= 0 && ftruncate(asset, BODY_MAX) == 0 && close(asset) == 0);
    d2k_panel_config cfg = { .asset_dir = dir };
    slow_reader(&cfg);
    assert(unlink(path) == 0 && rmdir(dir) == 0);
    puts("HTTP responses: complete response accepted; slow reader total deadline enforced PASS");
    return 0;
}
