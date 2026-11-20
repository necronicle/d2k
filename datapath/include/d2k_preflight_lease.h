#ifndef D2K_PREFLIGHT_LEASE_H
#define D2K_PREFLIGHT_LEASE_H
#include <stddef.h>
#include <stdint.h>
#include "d2k_plans.h"
#include "d2k_plan.h"

typedef struct {
    uint8_t family,client[16],server[16],shape;
    uint16_t server_port;
    uint32_t path;
    char name[256];
} d2k_pf_scope;
typedef struct {uint64_t generation;uint8_t epoch[16];} d2k_pf_lease_identity;
typedef struct {
    d2k_pf_scope scope;
    uint64_t expires_ns,generation;
    uint8_t id[16];
    d2k_binding_context binding;
    d2k_plan *plan;
} d2k_pf_lease;
typedef struct {
    d2k_pf_lease *entries;
    size_t cap,used;
    uint64_t next_binding;
    d2k_pf_lease_identity identity;
} d2k_pf_lease_table;
int d2k_pf_lease_init(d2k_pf_lease_table *,size_t);
void d2k_pf_lease_free(d2k_pf_lease_table *);
int d2k_pf_lease_set(d2k_pf_lease_table *,const d2k_pf_scope *,uint64_t now_ns,
    uint64_t expires_ns,const uint8_t id[16],d2k_plan *);
int d2k_pf_lease_del(d2k_pf_lease_table *,const d2k_pf_scope *,const uint8_t id[16]);
void d2k_pf_lease_invalidate(d2k_pf_lease_table *,const d2k_pf_scope *);
const d2k_plan *d2k_pf_lease_find(d2k_pf_lease_table *,const d2k_pf_scope *,uint64_t now_ns);
const d2k_pf_lease *d2k_pf_lease_match(d2k_pf_lease_table *,const d2k_pf_scope *,uint64_t now_ns);
const d2k_pf_lease *d2k_pf_lease_match_syn(d2k_pf_lease_table *,uint8_t family,
    const uint8_t client[16],const uint8_t server[16],uint16_t server_port,
    uint32_t path,uint64_t now_ns);
const d2k_binding_context *d2k_pf_lease_binding(const d2k_pf_lease_table *,const d2k_plan *);
#endif
