/* Test-only entry point: real C classifier against the local donor oracle. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "d2k_quichello.h"
#include "d2k_quicprobe.h"
#include "d2k_quic_arms.h"

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
    if (argc == 2 && !strcmp(argv[1], "--blobs")) {
        for (size_t i=0;i<5;i++) {
            size_t len; const char *name;
            const uint8_t *b=d2k_quic_original_blob(i,&len,&name);
            printf("%s ",name);
            for(size_t j=0;j<len;j++) printf("%02x",b[j]);
            putchar('\n');
        }
        return 0;
    }
    if (argc != 2 && argc != 3) { return 2; }
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
    if (argc==3 && !strcmp(argv[2],"arms")) {
        char pool[1][D2K_QUIC_ADDR_LEN]={"127.0.0.1"};
        d2k_quic_arm_context c={.pool=pool,.n_pool=1,.next=1,.marked=1};
        d2k_quic_arm a=d2k_quic_original_measure(&c,(uint16_t)port,
            (d2k_hello){trigger,tn},(d2k_hello){control,cn},40,0);
        printf("%s %d %d %d\n",a.blob_name,a.copies,a.ttl,a.probes);
        for(size_t i=0;i<a.n_trace;i++) {
            d2k_quic_arm_step *s=&a.trace[i];
            printf("%s|%d|%d|%d\n",s->label,s->sent,s->answered,s->not_measured);
        }
        return 0;
    }
    d2k_quic_arm arm;
    d2k_vres r = d2k_quic_run("127.0.0.1", (uint16_t)port, "blocked.example",
                                  (d2k_hello){trigger, tn}, (d2k_hello){control, cn}, 0, &arm);
    if(argc==3 && !strcmp(argv[2],"content")) {
        printf("%s %d %s %d %d\n",verdict(r.verdict),r.qprops.residual_blocking,
               arm.blob_name,arm.copies,arm.ttl);
        return 0;
    }
    printf("%s %d\n", verdict(r.verdict), r.probes);
    return 0;
}
