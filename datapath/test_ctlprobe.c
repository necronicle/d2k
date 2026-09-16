/* Regression for batched commands and EOF in the poll-driven test server.
 * Bounded even against the old implementation that hangs on stdio read-ahead. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int run(int with_quit) {
    int input[2], output[2];
    if (pipe(input) || pipe(output)) { return 1; }
    char path[100];
    snprintf(path, sizeof path, "/tmp/d2k-ctlprobe-batch-%ld-%d.sock", (long)getpid(), with_quit);
    pid_t child = fork();
    if (child < 0) { return 1; }
    if (!child) {
        dup2(input[0], STDIN_FILENO); dup2(output[1], STDOUT_FILENO);
        close(input[0]); close(input[1]); close(output[0]); close(output[1]);
        execl("./ctlprobe", "ctlprobe", path, (char *)NULL);
        _exit(127);
    }
    close(input[0]); close(output[1]);
    const char *commands = with_quit ? "plans\nplans\nquit\n" : "plans\nplans\n";
    ssize_t sent = write(input[1], commands, strlen(commands));
    /* Keep the writer open for quit: EOF must not accidentally wake poll
       and hide read-ahead of commands already buffered by fgets. */
    if (!with_quit) { close(input[1]); }
    int64_t end = now_ms() + 3000;
    char buf[4096] = {0}; size_t used = 0;
    int status = 0, done = 0;
    while (now_ms() < end) {
        struct pollfd p = { output[0], POLLIN, 0 };
        int rc = poll(&p, 1, 25);
        if (rc > 0 && (p.revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(output[0], buf + used, sizeof buf - 1 - used);
            if (n > 0) { used += (size_t)n; buf[used] = 0; }
        }
        if (waitpid(child, &status, WNOHANG) == child) { done = 1; break; }
    }
    if (!done) { kill(child, SIGKILL); waitpid(child, &status, 0); }
    if (with_quit) { close(input[1]); }
    while (used < sizeof buf - 1) {
        ssize_t n = read(output[0], buf + used, sizeof buf - 1 - used);
        if (n <= 0) { break; }
        used += (size_t)n; buf[used] = 0;
    }
    close(output[0]); unlink(path);
    const char *first = strstr(buf, "planов 0");
    int good = sent == (ssize_t)strlen(commands) && done && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0 && first && strstr(first + 1, "planов 0");
    if (!good) { fprintf(stderr, "ctlprobe batch/EOF failed (quit=%d, exited=%d): %s\n", with_quit, done, buf); }
    return !good;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    int failures = run(1) + run(0);
    if (failures) { return 1; }
    puts("ctlprobe: batched commands and EOF passed");
    return 0;
}
