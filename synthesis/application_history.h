#ifndef D2K_APPLICATION_HISTORY_H
#define D2K_APPLICATION_HISTORY_H
#include "cancel.h"
#include <stdio.h>
#include <stdint.h>
typedef struct {uint64_t opened,rejected;} d2k_history_scan_stats;
/* Stream sibling files produced by mkstemp(catalog+".application-XXXXXX").
 * Visit only regular files owned by this uid, never symlinks/FIFOs. The loader
 * returns 1 for a compatible supported proposal, 0 for none, -1 for invalid.
 * Each accepted visit replaces the previous proposal and is at least as new
 * by file mtime. Rejected/in-progress files do not erase an older proposal.
 * No FILE escapes this call. No network IO. 1 selected,0 none,-1 IO/cancelled.
 * This discovers input for revalidation, not current application evidence. */
int d2k_application_history_scan(const char *,int (*)(void *,FILE *),void *,
    const d2k_inference_control *,d2k_history_scan_stats *);
#endif
