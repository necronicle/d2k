#ifndef D2K_POSTNAT_LINK_H
#define D2K_POSTNAT_LINK_H
#include <stddef.h>
#include <stdint.h>
typedef struct d2k_postnat_link d2k_postnat_link;
/* Install one exclusive egress filter; never replace an existing filter.
 * The supplied capture interface must already be up. No packet is marked
 * by this module. The caller must mark only packets it explicitly owns. */
d2k_postnat_link *d2k_postnat_link_open(unsigned output_ifindex,
    unsigned capture_ifindex, uint32_t mark_bit, uint16_t priority,
    char *err, size_t cap);
/* Remove only our exact filter. An empty clsact is retained: another program
 * may have attached its own filters since our creation. Returns 0 on success. */
int d2k_postnat_link_close(d2k_postnat_link *, char *err, size_t cap);
#endif
