#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "d2k_stuntrial.h"
#include "d2k_ctl.h"

struct d2k_stun_trial {
    d2k_stun_socket *socket;
    d2k_stun_flow flow;
    uint8_t id[D2K_TRIAL_ID_LEN];
    d2k_stun_trial_state state;
    uint64_t send_deadline_ms;
    struct d2k_stun_trial *next_pending;
};

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

d2k_stun_trial *d2k_stun_trial_open(int fd, const d2k_stun_probe_opt *opt,
    const char *hex, const uint8_t id[D2K_TRIAL_ID_LEN], uint32_t lease_ms,
    char *err, size_t cap) {
    uint8_t any = 0;
    if (id) for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) any |= id[i];
    if (fd < 0 || !any || !hex || !opt || !opt->mark) {
        if (err && cap) snprintf(err, cap, "STUN trial requires socket, mark, plan and identity");
        return NULL;
    }
    d2k_stun_trial *t = calloc(1, sizeof *t);
    if (!t) {
        if (err && cap) snprintf(err, cap, "STUN trial: %s", strerror(errno));
        return NULL;
    }
    d2k_stun_probe_res r;
    t->socket = d2k_stun_probe_open(opt, &t->flow, &r);
    if (!t->socket) {
        if (err && cap) snprintf(err, cap, "STUN socket: %s", strerror(r.error));
        free(t); return NULL;
    }
    memcpy(t->id, id, sizeof t->id);
    uint64_t now = monotonic_ms();
    if (!now || now > UINT64_MAX - lease_ms) {
        if (err && cap) snprintf(err, cap, "STUN trial clock unavailable");
        d2k_stun_probe_close(t->socket); free(t); return NULL;
    }
    /* Conservative send deadline: the datapath starts its lease only after
       receiving SET. Expiry never authorizes port release; only DEL ACK does. */
    t->send_deadline_ms = now + lease_ms;
    if (d2k_link_set_addr_probe_family(fd, t->flow.source, t->flow.source_port_be,
        t->flow.destination, t->flow.destination_port_be, 17, t->flow.family,
        t->id, lease_ms, hex, err, cap)) {
        d2k_stun_probe_close(t->socket); free(t); return NULL;
    }
    t->state = D2K_STUN_TRIAL_WAIT_INSTALL;
    return t;
}

d2k_stun_trial_state d2k_stun_trial_get_state(const d2k_stun_trial *t) {
    return t ? t->state : D2K_STUN_TRIAL_REMOVED;
}
const d2k_stun_flow *d2k_stun_trial_flow(const d2k_stun_trial *t) {
    return t ? &t->flow : NULL;
}
int d2k_stun_trial_event(d2k_stun_trial *t, const d2k_ev *e) {
    if (!t || !e || e->kind != D2K_EV_ACK || memcmp(e->trial_id, t->id, sizeof t->id)) return 0;
    int ok = ((e->num >> 8) & 0xff) == 1;
    if (e->code == D2K_CMD_SET_ADDR_PROBE && t->state == D2K_STUN_TRIAL_WAIT_INSTALL) {
        t->state = ok ? D2K_STUN_TRIAL_READY : D2K_STUN_TRIAL_INSTALL_REFUSED;
        return ok ? 1 : -1;
    }
    if (e->code == D2K_CMD_DEL_ADDR_PROBE && t->state == D2K_STUN_TRIAL_WAIT_REMOVE) {
        if (ok) t->state = D2K_STUN_TRIAL_REMOVED;
        return ok ? 1 : -1;
    }
    return 0;
}
d2k_stun_socket *d2k_stun_trial_start(d2k_stun_trial *t) {
    if (!t || t->state != D2K_STUN_TRIAL_READY) return NULL;
    uint64_t now = monotonic_ms();
    if (!now || now >= t->send_deadline_ms) return NULL;
    t->state = D2K_STUN_TRIAL_RUNNING;
    return t->socket;
}
int d2k_stun_trial_finished(d2k_stun_trial *t) {
    if (!t || t->state != D2K_STUN_TRIAL_RUNNING) return -1;
    t->state = D2K_STUN_TRIAL_FINISHED;
    return 0;
}
int d2k_stun_trial_retire(d2k_stun_trial *t, int fd, char *err, size_t cap) {
    if (!t) return 0;
    if (t->state == D2K_STUN_TRIAL_RUNNING) {
        if (err && cap) snprintf(err, cap, "STUN worker still owns the socket");
        return -1;
    }
    if (t->state == D2K_STUN_TRIAL_INSTALL_REFUSED) t->state = D2K_STUN_TRIAL_REMOVED;
    if (t->state == D2K_STUN_TRIAL_REMOVED) return 0;
    t->state = D2K_STUN_TRIAL_WAIT_REMOVE;
    return d2k_link_del_addr_probe_family(fd, t->flow.source, t->flow.source_port_be,
        t->flow.destination, t->flow.destination_port_be, 17, t->flow.family,
        t->id, err, cap);
}
int d2k_stun_trial_free(d2k_stun_trial *t) {
    if (!t) return 0;
    if (t->state != D2K_STUN_TRIAL_REMOVED && t->state != D2K_STUN_TRIAL_INSTALL_REFUSED) return -1;
    d2k_stun_probe_close(t->socket); free(t); return 0;
}

/* The control loop owns this list, not any scheduler task. Losing a task or
 * control connection does not prove that the remote exact-flow rule vanished.
 * Keep the reserved port until the matching removal acknowledgement arrives. */
static d2k_stun_trial *pending;

int d2k_stun_trial_defer(d2k_stun_trial **owner) {
    if (!owner || !*owner) return 0;
    d2k_stun_trial *t = *owner;
    if (t->state == D2K_STUN_TRIAL_RUNNING) return -1;
    if (t->state == D2K_STUN_TRIAL_REMOVED || t->state == D2K_STUN_TRIAL_INSTALL_REFUSED) {
        (void)d2k_stun_trial_free(t);
    } else {
        t->state = D2K_STUN_TRIAL_WAIT_REMOVE;
        t->next_pending = pending;
        pending = t;
    }
    *owner = NULL;
    return 0;
}
size_t d2k_stun_trial_pending(void) {
    size_t n = 0;
    for (d2k_stun_trial *t = pending; t; t = t->next_pending) n++;
    return n;
}
int d2k_stun_trial_retry_pending(int fd) {
    int failed = 0;
    for (d2k_stun_trial *t = pending; t; t = t->next_pending)
        if (d2k_stun_trial_retire(t, fd, NULL, 0)) failed = 1;
    return failed ? -1 : 0;
}
size_t d2k_stun_trial_reap(const d2k_ev *ev) {
    size_t n = 0;
    d2k_stun_trial **p = &pending;
    while (*p) {
        d2k_stun_trial *t = *p;
        (void)d2k_stun_trial_event(t, ev);
        if (t->state == D2K_STUN_TRIAL_REMOVED) {
            *p = t->next_pending;
            (void)d2k_stun_trial_free(t);
            n++;
        } else p = &t->next_pending;
    }
    return n;
}
