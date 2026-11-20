/* Shared validation for the preflight program's network-owned white name. */
#ifndef D2K_PREFLIGHT_PLAN_H
#define D2K_PREFLIGHT_PLAN_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#define D2K_PF_REFERENCE_WSCALE 1u
#define D2K_PF_REFERENCE_TIMEOUT_MS 4000u
/* Only modify the fixed-size fields of the complete probe ClientHello. */
static inline int d2k_pf_randomize_hello(uint8_t *hello, size_t len) {
    if (len < 44 || hello[0] != 22 || hello[5] != 1 ||
        hello[43] > 32 || hello[43] > len - 44) return 0;
    uint8_t bytes[64];
    size_t sid = hello[43], need = 32 + sid;
    FILE *entropy = fopen("/dev/urandom", "rb");
    if (!entropy) return 0;
    size_t got = fread(bytes, 1, need, entropy);
    fclose(entropy);
    if (got != need) return 0;
    for (size_t i = 0; i < 32; i++) hello[11+i] = bytes[i];
    for (size_t i = 0; i < sid; i++) hello[44+i] = bytes[32+i];
    return 1;
}
/* Finite empirical handover schedule, used only after a context-specific
 * response/carry experiment. These are fallback parameters, not facts about
 * state lifetime or a lower bound of any network mechanism. */
#define D2K_PF_FALLBACK_RESYN_DELAY_MS 60u
#define D2K_PF_FALLBACK_RESYN_SENDS 6u
/* Product resource limit on owning an initiating SYN, not a network fact. */
#define D2K_PF_EXEC_MAX_TIMEOUT_MS 30000u
static inline int d2k_pf_name_valid(const uint8_t *name, size_t len) {
    if(!name || !len || len>253)return 0;
    size_t label=0;
    for(size_t i=0;i<len;i++) {
        uint8_t c=name[i];
        if(c=='.') {
            if(!label || name[i-1]=='-')return 0;
            label=0;continue;
        }
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-') ||
           (!label && c=='-') || ++label>63)return 0;
    }
    return label && name[len-1]!='-';
}
#endif
