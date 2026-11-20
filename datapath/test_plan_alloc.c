#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t live;
static void *count_malloc(size_t n) {
    void *p = malloc(n);
    if (p) live++;
    return p;
}
static void *count_calloc(size_t n, size_t size) {
    void *p = calloc(n, size);
    if (p) live++;
    return p;
}
static void count_free(void *p) {
    if (p) live--;
    free(p);
}
#define malloc count_malloc
#define calloc count_calloc
#define free count_free
#include "plan_parse.c"
#undef malloc
#undef calloc
#undef free

int main(void) {
    uint8_t input[] = {
        'D','2','K','P',0,1,0,13,0,0,0,3,
        0,16,0,3,0,1,0x16,
        0,17,0,8,0,1,0,0,0,0,0,0,
        1,17,0,5,0,2,0,1,64
    };
    d2k_plan *plan = NULL;
    char error[160] = {0};
    int rc = d2k_plan_load(input, sizeof input, &plan, error, sizeof error);
    if (rc != -1 || plan || !strstr(error, "autottl") || live) {
        fprintf(stderr, "unknown poison: rc=%d outstanding=%zu error=%s\n",
                rc, live, error);
        d2k_plan_free(plan);
        return 1;
    }
    puts("plan rejection releases owned allocations");
    return 0;
}
