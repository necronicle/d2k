#ifndef D2K_FLOW_IO_H
#define D2K_FLOW_IO_H
#include <stdint.h>

enum d2k_flow_open_status {D2K_FLOW_OPEN_OK,D2K_FLOW_OPEN_LOCAL,
    D2K_FLOW_OPEN_TIMEOUT,D2K_FLOW_OPEN_NETWORK,D2K_FLOW_OPEN_CANCELLED};
struct d2k_flow_open_options {
    const char *address;uint16_t port;int transport;
    uint32_t mark,timeout_ms,guard_interval_ms;
    int (*allowed)(void *);void *guard_context;
};
struct d2k_flow_open_result {
    enum d2k_flow_open_status status;int fd,error;
    uint8_t family,transport,source[16],destination[16];
    uint16_t source_port,destination_port; /* Host order. */
};
/* Numeric peer and exact transport. Mark zero uses normal router routing.
 * A nonzero mark is applied before connect. The caller owns the resulting fd. */
enum d2k_flow_open_status d2k_flow_open_numeric(const struct d2k_flow_open_options *,
    struct d2k_flow_open_result *);
#endif
