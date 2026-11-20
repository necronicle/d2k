#ifndef D2K_RAW_TAPE_H
#define D2K_RAW_TAPE_H
#include "raw_tls.h"
typedef struct d2k_raw_tape d2k_raw_tape;
/* One connection's actual events, copied until a late-created consumer binds.
   Binding replays originals once, then forwards future events synchronously.
   Rejection is terminal. Consumer must outlive channel and tape. */
d2k_raw_tape *d2k_raw_tape_new(uint64_t);
void d2k_raw_tape_free(d2k_raw_tape *);
d2k_raw_tls_sink d2k_raw_tape_sink(d2k_raw_tape *);
const d2k_raw_tls_event *d2k_raw_tape_event(const d2k_raw_tape *,size_t);
int d2k_raw_tape_bind(d2k_raw_tape *,const d2k_raw_tls_sink *);
#endif
