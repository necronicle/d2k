#ifndef D2K_PREFLIGHT_PROBE_H
#define D2K_PREFLIGHT_PROBE_H
#include "d2k_detect.h"
/* 1: gate and minimal successful carry repeated consistently; 0: not demonstrated;
 * 2: direct response observed (stop classification, inconsistent silent base);
 * 3: explicit combined candidate, direct carry remains unconfirmed;
 * -1: local/cancelled/incomplete experiment. Partial measurements retained.
 * Two identical consecutive outcomes, at most four completed runs;
 * three consecutive local failures abort. Handover delay is an explicit finite
 * fallback parameter shared with the executor, never a measured state lifetime.
 * Numeric IPv4/IPv6 endpoints; IPv6 requires the matching capability gate.
 * No DNS or synthesized name for an IP target. */
int d2k_probe_preflight(const char *addr, const d2k_trigger *tr,
                      const d2k_opts *opt, d2k_preflight_meas *out);
/* Returns 1 if the compatible box already answered the carry question.
 * verdict is the probe's 0/1 result; out contains no new probes or white name. */
int d2k_preflight_known(const d2k_box_props *known, d2k_preflight_meas *out, int *verdict);
#endif
