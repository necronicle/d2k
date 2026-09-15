/* Exercise first use concurrently, before ANY call initializes the list. */
#include "d2k_detect.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define WORKERS 24
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int ready, go;
static struct { int count; d2k_poison entries[128]; } results[WORKERS];

static void *read_list(void *arg)
{
    int i = *(int *)arg;
    const d2k_poison *ps;
    pthread_mutex_lock(&mu);
    ready++;
    pthread_cond_broadcast(&cv);
    while (!go) { pthread_cond_wait(&cv, &mu); }
    pthread_mutex_unlock(&mu);
    ps = d2k_poisons(&results[i].count);
    if (results[i].count > 0 && results[i].count <= 128) {
        memcpy(results[i].entries, ps, (size_t)results[i].count * sizeof(*ps));
    }
    return NULL;
}

int main(void)
{
    pthread_t threads[WORKERS];
    int ids[WORKERS], n;
    const d2k_poison *ps;
    for (int i = 0; i < WORKERS; i++) {
        ids[i] = i;
        if (pthread_create(&threads[i], NULL, read_list, &ids[i])) { return 2; }
    }
    pthread_mutex_lock(&mu);
    while (ready < WORKERS) { pthread_cond_wait(&cv, &mu); }
    go = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
    for (int i = 0; i < WORKERS; i++) { pthread_join(threads[i], NULL); }
    ps = d2k_poisons(&n);
    for (int i = 0; i < WORKERS; i++) {
        if (n <= 0 || n > 128 || results[i].count != n ||
            memcmp(results[i].entries, ps, (size_t)n * sizeof(*ps))) {
            fprintf(stderr, "thread %d saw incomplete/mutating hypotheses (%d, final %d)\n",
                    i, results[i].count, n);
            return 1;
        }
    }
    printf("threads: %d readers saw the same %d complete hypotheses\n", WORKERS, n);
    return 0;
}
