/* d2k_stun_trial_open must report WHY it returned NULL on every failure path:
 * the caller (sched.c, stun_candidate_start) prints err with %s without
 * initialising it. Allocation failure is the one path a normal test cannot
 * reach, so stuntrial.c is compiled here with -Dcalloc=d2k_test_calloc
 * (the same trick san-mips-pipe uses for pipe()). */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_stuntrial.h"

void *d2k_test_calloc(size_t n, size_t size) {
    (void)n; (void)size;
    errno = ENOMEM;
    return NULL;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); return 1; }
    d2k_stun_probe_opt opt = {"127.0.0.1", 3478, 3000, 0x2e};
    uint8_t id[D2K_TRIAL_ID_LEN];
    memset(id, 0x5a, sizeof id);
    char err[160];
    err[0] = 0;
    d2k_stun_trial *t = d2k_stun_trial_open(sv[0], &opt, "00", id, 1000, err, sizeof err);
    int fails = 0;
    if (t) { fprintf(stderr, "FAIL: trial opened although calloc failed\n"); fails++; }
    if (!err[0]) { fprintf(stderr, "FAIL: allocation failure left err empty\n"); fails++; }
    close(sv[0]); close(sv[1]);
    if (!fails) puts("stun trial: allocation failure is reported");
    return fails ? 1 : 0;
}
