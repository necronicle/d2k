#ifndef D2K_TOKEN_CONTENT_H
#define D2K_TOKEN_CONTENT_H
#include "../detect/include/d2k_detect.h"
/* Derive a same-length token-content question from a measured ClientHello.
 * Only the additional prefix is changed; caller preserves the original.
 * 1 changed, 0 ineligible/identical, -1 invalid output. No network claims. */
int d2k_token_content_question(const d2k_trigger *,uint8_t *,size_t);
#endif
