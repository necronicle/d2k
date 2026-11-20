#ifndef D2K_SYNTHESIS_PROVIDER_H
#define D2K_SYNTHESIS_PROVIDER_H
#include "path_work.h"
typedef d2k_syn_status (*d2k_synthesis_provider)(const d2k_tls_stream *,
    const d2k_experiment *,uint64_t,d2k_vres *);
/* Controller startup only, before workers. NULL retains legacy integration.
   Provider owns primary search; only CLOSED permits last-resort legacy search.
   ERROR, cancellation and direct-response uncertainty must not invoke it. */
void d2k_detect_synthesis_set(d2k_synthesis_provider);
#endif
