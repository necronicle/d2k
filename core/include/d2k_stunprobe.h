#ifndef D2K_STUNPROBE_H
#define D2K_STUNPROBE_H
#include <stdint.h>

typedef enum {
    D2K_STUN_LOCAL_ERROR = 0,
    D2K_STUN_TIMEOUT,
    D2K_STUN_NETWORK_ERROR,
    D2K_STUN_BINDING_OK,
    D2K_STUN_PROTOCOL_ERROR
} d2k_stun_probe_status;

typedef struct {
    const char *ip; /* Numeric endpoint; never invent a hostname for an IP flow. */
    uint16_t port;
    uint32_t wait_ms;
    uint32_t mark; /* If requested, failure to mark prevents transmission. */
} d2k_stun_probe_opt;

typedef struct {
    d2k_stun_probe_status status;
    int sent, marked, error;
    unsigned rejected;
    unsigned protocol_error;
    uint32_t elapsed_ms;
    uint8_t mapped_ip[16];
    int mapped_family;
    uint16_t mapped_port;
    uint8_t request_length;
    uint8_t request[20];
} d2k_stun_probe_res;

typedef struct d2k_stun_socket d2k_stun_socket;
typedef struct {
    uint8_t family; /* 4 or 6; addresses padded to 16 bytes. */
    uint8_t source[16], destination[16];
    uint16_t source_port_be, destination_port_be;
} d2k_stun_flow;

/* Reserve a connected, marked UDP socket without sending a request. The
 * returned exact flow is stable until close. Install/ACK a trial for that
 * flow before calling run. NULL means local/network failure in error_out.
 * run borrows the socket and creates a fresh transaction on each call;
 * only close releases it. The caller must retire any installed trial before
 * releasing its port. No descriptor or mutable endpoint is exposed. */
d2k_stun_socket *d2k_stun_probe_open(const d2k_stun_probe_opt *opt,
    d2k_stun_flow *flow, d2k_stun_probe_res *error_out);
d2k_stun_probe_res d2k_stun_probe_run(d2k_stun_socket *socket);
void d2k_stun_probe_close(d2k_stun_socket *socket);

/* A fresh unauthenticated Binding transaction, not an ICE/voice/game proof.
 * Silence is inconclusive: endpoints requiring credentials may ignore it.
 * A response must come from the connected endpoint, match the transaction,
 * and contain a valid XOR-MAPPED-ADDRESS. */
d2k_stun_probe_res d2k_stun_probe(const d2k_stun_probe_opt *opt);
#endif
