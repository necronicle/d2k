#ifndef D2K_APPLICATION_LATE_H
#define D2K_APPLICATION_LATE_H
#include "application_model.h"
/* One packetization question for the failed request of an owned direct DoH/HTTPS
 * experience. No IO. Caller owns *plan. 1 generated, 0 ineligible, -1 error.
 * The length guard rejects a different write layout in the next experience.
 * A partial ACK supplies an interior boundary between acknowledged and
 * outstanding bytes; otherwise use a balanced partition. ACKs do not prove
 * the peer's identity or that this boundary differs from original wire packets.
 * This is a question, not a blocking diagnosis or a successful candidate. */
int d2k_application_late_question(const d2k_application_model *,char **plan);
/* Same measured interval while preserving the failed trial's first-input plan. */
int d2k_application_late_composed_question(const d2k_application_model *,char **plan);
#define D2K_LATE_SEEN_BYTES 8192u
/* Refine a failed owned late split using a new partial-ACK boundary. The
 * caller retains a zero-initialized seen set for this baseline/geometry.
 * Reject changed contexts, foreign program shapes, and repeated boundaries. */
int d2k_application_late_refine(const d2k_application_model *,const d2k_application_model *,
    unsigned char *,size_t,char **);
int d2k_application_late_composed_refine(const d2k_application_model *,const d2k_application_model *,
    unsigned char *,size_t,char **);
#endif
