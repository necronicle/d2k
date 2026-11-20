/* Этап 53 (находка ревью root-review-orphan53): внешний потомок iptables не
   переживает d2kd. Процесс P запускает из потока «медленный iptables» (sh:
   sleep 2; touch файл) и получает SIGKILL через 0.5 с — потомок обязан умереть
   вместе с ним, иначе он позже вернул бы правило, уже убранное уборкой нового
   d2kd. Только Linux (PR_SET_PDEATHSIG). */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "d2k_lwrules.h"

#define MARKER "/tmp/d2k-orphan-added"
#define READY "/tmp/d2k-orphan-ready"

static void *slow_iptables(void *arg) {
    (void)arg;
    sigset_t all; sigfillset(&all); pthread_sigmask(SIG_BLOCK, &all, NULL);   /* как поток исполнителя */
    char *argv[] = {(char *)"/bin/sh", (char *)"-c", (char *)"touch " READY "; sleep 2; touch " MARKER, NULL};
    (void)d2k_lwrules_spawn(NULL, argv);
    return NULL;
}

int main(void) {
    unlink(MARKER); unlink(READY);
    pid_t p = fork();
    if (p < 0) { puts("ПРОВАЛ: fork"); return 2; }
    if (p == 0) {
        pthread_t th;
        if (pthread_create(&th, NULL, slow_iptables, NULL) != 0) _exit(3);
        for (;;) pause();
    }
    /* Готовность — «медленный iptables» уже запущен (сам пишет READY), не наугад. */
    struct stat st;
    struct timespec tick = {0, 20000000L};
    int waited = 0;
    while (stat(READY, &st) != 0 && waited < 250) { nanosleep(&tick, NULL); waited++; }
    if (waited >= 250) { puts("ПРОВАЛ: потомок не запустился — проверка не состоялась"); kill(p, SIGKILL); return 2; }
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
    sleep(3);
    int orphan_ran = stat(MARKER, &st) == 0;
    puts(orphan_ran ? "ПРОВАЛ: потомок iptables пережил d2kd и исполнился после SIGKILL"
                    : "потомок iptables умер вместе с d2kd: все проверки прошли");
    unlink(MARKER); unlink(READY);
    return orphan_ran;
}
