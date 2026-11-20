#ifndef D2K_SHADOW_WORKERS_H
#define D2K_SHADOW_WORKERS_H
#include <stddef.h>
#include <stdint.h>
/* Resource ceiling for simultaneous sockets/worker stacks, not a search budget. */
#define D2K_SHADOW_WORKERS_MAX 4u
/* Until a day's memory history is available (§14), reserve a full additional
 * declared task; unknown available memory permits no additional worker. */
static inline unsigned d2k_shadow_worker_capacity(uint64_t available,size_t declared,unsigned cpus) {
    /* H: two admitted tasks spent hundreds of seconds in network waits;
       CPU count is not a limit on simultaneous sockets. Keep the existing
       socket/stack ceiling and charge memory plus the §14 reserve. */
    (void)cpus;
    if(!declared || available<declared)return 0;
    uint64_t n=(available-declared)/declared;
    if(n>D2K_SHADOW_WORKERS_MAX)n=D2K_SHADOW_WORKERS_MAX;
    return (unsigned)n;
}
static inline int d2k_shadow_worker_admit(uint64_t available,size_t declared,unsigned cpus,unsigned active) {
    /* Charge every admitted task, including threads which have not allocated
       yet. Counting committed memory again is conservative. */
    return active<d2k_shadow_worker_capacity(available,declared,cpus);
}
#endif
