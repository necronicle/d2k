#define d2k_verify_doh_on observe_doh_query
#include "sched.c"
#include "test_task_slots.h"
#undef d2k_verify_doh_on

static unsigned calls;
static const char *resolver = "resolver.example.test";
static const char *path = "/private/dns-query?profile=test";

d2k_ver_result observe_doh_query(int fd, const char *ip, uint16_t port,
    const char *name, int timeout_ms, size_t wire_len, int tls12,
    uint32_t mark, const char *request_path) {
    (void)wire_len;
    calls++;
    if (mark || tls12 != -1 || fd != -1 || timeout_ms <= 0 ||
        strcmp(ip, "192.0.2.53") || port != 8443 || strcmp(name, resolver) ||
        strcmp(request_path, path)) {
        fprintf(stderr, "unexpected DoH health request (mark=%u, tls=%d)\n",
            (unsigned)mark, tls12);
        return (d2k_ver_result){.fd = -1};
    }
    return (d2k_ver_result){.fd = -1, .status = 200};
}

int main(void) {
    d2k_catalog catalog = {0};
    d2k_sched *scheduler = d2k_sched_new(&catalog, -1, 0x2d);
    if (!scheduler) return 1;
    task *target = test_task_at(scheduler, 0);
    strcpy(target->name, resolver);
    strcpy(target->ip, "192.0.2.53");
    strcpy(target->doh_path, path);
    target->port = 8443;
    target->job = JOB_DOH_HEALTH;
    worker_arg job = {.s = scheduler, .t = target, .use_fd = -1};
    scheduler->memory.worker_args_allocated++;
    worker_run(&job);
    int ok = calls == 1 && target->res_ready && target->ver.status == 200;
    d2k_sched_free(scheduler);
    d2k_catalog_free(&catalog);
    return ok ? 0 : 1;
}
