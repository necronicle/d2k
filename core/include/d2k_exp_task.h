/* Shared single-target TLS assembly for d2kexp and d2kshadow. The only
 * datapath operations here install/remove experimental name probes. */
#ifndef D2K_EXP_TASK_H
#define D2K_EXP_TASK_H
#include <signal.h>
#include "d2km_task.h"
typedef struct {
    const char *host, *ip, *form, *pass_name, *exp_control;
    /* Optional observed bytes. NULL keeps the manual --form path. */
    const uint8_t *client_hello, *tcp_options;
    size_t client_hello_len, tcp_options_len;
    const char *alive_history, *shadow_queue, *doh_path;
    int (*knowledge_changed)(void *);
    void *knowledge_changed_ctx;
    /* Caller serializes model/catalog work. Only network I/O runs unlocked. */
    void (*network_begin)(void *),(*network_end)(void *);
    void *network_ctx;
    uint32_t *shared_experiment,*shared_fact;
    uint32_t degradation_knowledge;
    uint64_t degradation_hash;
    uint8_t expected_protocol;
    uint16_t port;
    int family;
    uint32_t mark;
    volatile sig_atomic_t *cancel;
} d2k_exp_options;
typedef struct d2k_exp_task d2k_exp_task;
/* injected_net is for offline simulators. NULL uses marked netarm sockets.
 * catalog/journal are owned by caller and remain alive until close. */
d2k_exp_task *d2k_exp_task_open(const d2k_exp_options *, d2km_store *,
                              d2km_journal *, const d2km_net *injected_net,
                              char *err, size_t cap);
d2km_outcome d2k_exp_task_run(d2k_exp_task *, d2km_task_report *);
const d2km_box *d2k_exp_task_box(const d2k_exp_task *);
const d2km_context *d2k_exp_task_context(const d2k_exp_task *);
size_t d2k_exp_task_memory(void);
void d2k_exp_task_close(d2k_exp_task *);
#endif
