#ifndef D2K_OBSERVATION_H
#define D2K_OBSERVATION_H
#include "../detect/include/d2k_detect.h"
typedef struct d2k_observations d2k_observations;
typedef struct {
    d2k_raw_observation_kind kind;
    d2k_raw_packet_event packet;
    const uint8_t *bytes;
    size_t length;
} d2k_observed_packet;
d2k_observations *d2k_observations_new(void);
void d2k_observations_free(d2k_observations *);
/* experiment.decode_packet callback. IDs are scoped to this dictionary.
 * Equality means identical observation, not endpoint or application success.
 * Local failures and connection setup failures are not learning outputs. */
int d2k_observations_decode(void *,size_t,const d2k_raw_observation *,
    const d2k_raw_packet_event *,const uint8_t *,size_t,uint64_t *);
const d2k_observed_packet *d2k_observations_get(const d2k_observations *,uint64_t);
#endif
