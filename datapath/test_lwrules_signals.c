#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include "d2k_lwrules.h"
int main(int argc, char **argv) {
    sigset_t mask;
    if (argc == 2 && !strcmp(argv[1], "child")) {
        if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0) return 18;
        return sigismember(&mask, SIGALRM) == 0 ? 0 : 17;
    }
    sigset_t saved;
    sigfillset(&mask);
    if (sigprocmask(SIG_SETMASK, &mask, &saved) != 0) return 2;
    char *child[] = {argv[0], "child", NULL};
    int rc = d2k_lwrules_spawn(NULL, child);
    if (sigprocmask(SIG_SETMASK, &saved, NULL) != 0) return 2;
    printf("child exit=%d (0 means lock timeout signal unblocked)\n", rc);
    return rc != 0;
}
