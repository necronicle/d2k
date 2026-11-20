#ifndef D2K_STUNTRIAL_H
#define D2K_STUNTRIAL_H
#include <stddef.h>
#include "d2k_stunprobe.h"
#include "d2k_link.h"

typedef struct d2k_stun_trial d2k_stun_trial;
typedef enum {
    D2K_STUN_TRIAL_WAIT_INSTALL, D2K_STUN_TRIAL_READY,
    D2K_STUN_TRIAL_RUNNING, D2K_STUN_TRIAL_FINISHED,
    D2K_STUN_TRIAL_WAIT_REMOVE, D2K_STUN_TRIAL_REMOVED,
    D2K_STUN_TRIAL_INSTALL_REFUSED
} d2k_stun_trial_state;

/* Caller supplies a fresh nonzero trial ID. Successful open reserves a
 * socket and sends SET_ADDR_PROBE, but emits no STUN request. No application
 * or packet-execution success is inferred by this lifecycle helper. */
d2k_stun_trial *d2k_stun_trial_open(int link_fd, const d2k_stun_probe_opt *opt,
    const char *plan_hex, const uint8_t id[D2K_TRIAL_ID_LEN], uint32_t lease_ms,
    char *err, size_t errcap);
d2k_stun_trial_state d2k_stun_trial_get_state(const d2k_stun_trial *trial);
const d2k_stun_flow *d2k_stun_trial_flow(const d2k_stun_trial *trial);
/* Main-loop operations are serialized. Event: 1 accepted success, -1 own
 * refusal, 0 unrelated/late event. A late install ACK never cancels removal. */
int d2k_stun_trial_event(d2k_stun_trial *trial, const d2k_ev *ev);
/* Borrowed socket for one worker; only available after its install ACK.
 * Never close it directly. Call finished after joining that worker. */
d2k_stun_socket *d2k_stun_trial_start(d2k_stun_trial *trial);
int d2k_stun_trial_finished(d2k_stun_trial *trial);
/* Retire may be retried on the current control connection. No timer or
 * write failure releases the port. It stays reserved until its removal ACK
 * (or an explicit refusal to install). RUNNING cannot be retired/freed. */
int d2k_stun_trial_retire(d2k_stun_trial *trial, int link_fd, char *err, size_t errcap);
int d2k_stun_trial_free(d2k_stun_trial *trial);
/* Process-owned cleanup after task cancellation. Main-loop only. Transfer
 * clears *trial on success and refuses a worker-owned socket. No expiry
 * releases it: retry on the current link and reap only its positive DEL ACK.
 * Pending sockets survive scheduler destruction (the OS owns process exit).
 * They must not count as running measurements. */
int d2k_stun_trial_defer(d2k_stun_trial **trial);
size_t d2k_stun_trial_pending(void);
int d2k_stun_trial_retry_pending(int link_fd);
size_t d2k_stun_trial_reap(const d2k_ev *ev);
#endif
