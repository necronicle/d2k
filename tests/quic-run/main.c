/* Test-only entry point: real C classifier against the local donor oracle. */
#include <stdio.h>
#include <stdlib.h>
#include "d2k_quichello.h"
#include "d2k_quicprobe.h"

static const char *verdict(d2k_verdict v) {
    switch (v) {
    case D2K_V_CLEAR: return "clear";
    case D2K_V_ADDRESS: return "address";
    case D2K_V_NO_QUIC: return "no_quic";
    case D2K_V_FLAKY: return "flaky";
    case D2K_V_INCONCLUSIVE: return "inconclusive";
    case D2K_V_LOCAL_ADDRESS: return "local_address";
    case D2K_V_OPAQUE: return "content";
    default: return "other";
    }
}

static size_t no_extra_addresses(const char *sni, char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    (void)sni; (void)out; (void)cap;
    return 0; /* Explicit loopback endpoint only: do not query external DNS. */
}

int main(int argc, char **argv) {
    if (argc != 2) { return 2; }
    char *end;
    long port = strtol(argv[1], &end, 10);
    if (*end || port < 1 || port > 65535) { return 2; }
    uint8_t trigger[1500], control[1500];
    size_t tn = 0, cn = 0;
    if (d2k_quic_probe_initial("blocked.example", trigger, sizeof trigger, &tn) != 0 ||
        d2k_quic_probe_initial("z0011223344.example.com", control, sizeof control, &cn) != 0) { return 2; }
    d2k_quic_allow_local = 1;
    d2k_quic_resolve_hook = no_extra_addresses;
    d2k_quic_wait_ms = 40;
    d2k_vres r = d2k_quic_classify("127.0.0.1", (uint16_t)port, "blocked.example",
                                  (d2k_hello){trigger, tn}, (d2k_hello){control, cn}, 0);
    printf("%s %d\n", verdict(r.verdict), r.probes);
    return 0;
}
