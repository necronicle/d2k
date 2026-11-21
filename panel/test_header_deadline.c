#define _POSIX_C_SOURCE 200809L
#include "server.c"
#include <assert.h>
#include <sys/socket.h>
#include <sys/wait.h>

int main(void) {
    const char *header = "GET / HTTP/1.0\r\n\r\n";
    char buf[REQUEST_MAX + 1]; size_t used = 0;
    int fds[2]; assert(pipe(fds) == 0);
    assert(write(fds[1], header, strlen(header)) == (ssize_t)strlen(header));
    assert(read_request(fds[0], buf, sizeof buf, &used, monotonic_ms() + D2K_PANEL_HEADER_TIMEOUT_MS) == 0);
    close(fds[0]); close(fds[1]);
    assert(pipe(fds) == 0);
    pid_t pid = fork(); assert(pid >= 0);
    if (!pid) {
        close(fds[0]); signal(SIGPIPE, SIG_IGN);
        struct timespec pause = { .tv_nsec = 20000000 };
        for (size_t i = 0; header[i]; ++i) {
            nanosleep(&pause, NULL);
            if (write(fds[1], header + i, 1) != 1) break;
        }
        close(fds[1]); _exit(0);
    }
    close(fds[1]);
    used = 0;
    long long start = monotonic_ms();
    assert(read_request(fds[0], buf, sizeof buf, &used, monotonic_ms() + D2K_PANEL_HEADER_TIMEOUT_MS) == -2);
    assert(monotonic_ms() - start < 1000);
    close(fds[0]); assert(waitpid(pid, NULL, 0) == pid);
    int sv[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    pid = fork(); assert(pid >= 0);
    if (!pid) {
        close(sv[0]);
        int rc = d2k_panel_handle_fd(sv[1], NULL);
        close(sv[1]); _exit(rc == 0 ? 0 : 1);
    }
    close(sv[1]);
    assert(write(sv[0], "GET /", 5) == 5);
    used = 0;
    ssize_t n;
    while ((n = read(sv[0], buf + used, sizeof buf - used - 1)) > 0) used += (size_t)n;
    assert(n == 0); buf[used] = '\0';
    assert(strstr(buf, "HTTP/1.1 408 Request Timeout\r\n"));
    assert(strstr(buf, "request too large") == NULL);
    close(sv[0]);
    int status; assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("HTTP headers: complete request accepted; slow drip deadline enforced PASS");
    return 0;
}
