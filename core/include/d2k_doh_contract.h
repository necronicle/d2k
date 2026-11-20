#ifndef D2K_DOH_CONTRACT_H
#define D2K_DOH_CONTRACT_H
#include "d2k_verify.h"
#include "d2km_experiment.h"
/* qname from router DNS observations; server name if none (§9.5). */
int d2k_doh_query_name(const char *);
void d2k_doh_contract(d2k_tls *,const char *,const char *,const char *,int,d2k_ver_result *);
d2km_result d2k_doh_result(const d2k_ver_result *);
#endif
