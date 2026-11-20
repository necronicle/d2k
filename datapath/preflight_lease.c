#include "d2k_preflight_lease.h"
#include "d2k_preflight_plan.h"
#include "plan_internal.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int same(const d2k_pf_scope *a, const d2k_pf_scope *b) {
    return a->family == b->family && a->server_port == b->server_port &&
        a->shape == b->shape && a->path == b->path &&
        !memcmp(a->client, b->client, sizeof a->client) &&
        !memcmp(a->server, b->server, sizeof a->server) &&
        !strncmp(a->name, b->name, sizeof a->name);
}
static int nonzero(const uint8_t *p,size_t n) {uint8_t any=0;for(size_t i=0;i<n;i++)any|=p[i];return any!=0;}
static int valid(const d2k_pf_scope *s) {
    return s&&(s->family==4||s->family==6)&&
        (s->shape==D2K_PLAN_SHAPE_MODERN||s->shape==D2K_PLAN_SHAPE_LEGACY)&&
        s->server_port&&s->path&&nonzero(s->client,16)&&nonzero(s->server,16)&&
        memchr(s->name, 0, sizeof s->name) &&
        d2k_pf_name_valid((const uint8_t *)s->name,strlen(s->name));
}
int d2k_pf_lease_init(d2k_pf_lease_table *t,size_t cap) {
    if(!t)return -1;
    memset(t,0,sizeof *t);
    if(!cap)return -1;
    t->entries=calloc(cap,sizeof *t->entries);if(!t->entries)return -1;t->cap=cap;
    FILE *entropy=fopen("/dev/urandom","rb");
    if(entropy) {if(fread(t->identity.epoch,1,16,entropy)!=16)memset(t->identity.epoch,0,16);fclose(entropy);}
    return 0;
}
static void remove_at(d2k_pf_lease_table *t,size_t i) {
    d2k_plan_free(t->entries[i].plan);t->entries[i]=t->entries[--t->used];
    memset(&t->entries[t->used],0,sizeof t->entries[t->used]);
}
static void expire(d2k_pf_lease_table *t, uint64_t now_ns) {
    for (size_t i = 0; i < t->used;) {
        if (t->entries[i].expires_ns <= now_ns) remove_at(t, i);
        else i++;
    }
}
void d2k_pf_lease_free(d2k_pf_lease_table *t) {
    if(!t)return;
    while(t->used)remove_at(t,t->used-1);
    free(t->entries);
    memset(t,0,sizeof *t);
}
static void metadata(d2k_pf_lease_table *t,d2k_pf_lease *e) {
    d2k_plan *p=e->plan;
    p->binding_owner=NULL;p->binding_generation=t->next_binding==UINT64_MAX?0:++t->next_binding;
    p->binding_kind=D2K_BIND_ADDR;p->binding_family=e->scope.family;p->binding_shape=e->scope.shape;
    p->binding_temporary=1;p->binding_exact_shape=1;
    memcpy(p->binding_trial_id,e->id,16);
    e->binding=(d2k_binding_context){.generation=p->binding_generation,.kind=D2K_BIND_ADDR,
        .family=e->scope.family,.shape=e->scope.shape,.temporary=1};
    memcpy(e->binding.epoch,t->identity.epoch,16);
}
int d2k_pf_lease_set(d2k_pf_lease_table *t,const d2k_pf_scope *s,uint64_t now_ns,
    uint64_t expires_ns,const uint8_t id[16],d2k_plan *plan) {
    if(!t||!valid(s)||!plan||!plan->preflight||expires_ns<=now_ns||!nonzero(id,16)) {
        d2k_plan_free(plan);return -2;
    }
    expire(t, now_ns);
    d2k_pf_lease *e=NULL;
    for(size_t i=0;i<t->used;i++)if(same(&t->entries[i].scope,s)){e=&t->entries[i];break;}
    if(!e) {if(t->used==t->cap){d2k_plan_free(plan);return -1;}e=&t->entries[t->used++];memset(e,0,sizeof *e);e->scope=*s;}
    d2k_plan_free(e->plan);e->plan=plan;e->expires_ns=expires_ns;memcpy(e->id,id,16);metadata(t,e);
    return 0;
}
int d2k_pf_lease_del(d2k_pf_lease_table *t,const d2k_pf_scope *s,const uint8_t id[16]) {
    if(!t||!s||!nonzero(id,16))return 0;
    for(size_t i=0;i<t->used;i++)if(same(&t->entries[i].scope,s)&&!memcmp(t->entries[i].id,id,16)) {
        remove_at(t,i);return 1;
    }
    return 0;
}
void d2k_pf_lease_invalidate(d2k_pf_lease_table *t,const d2k_pf_scope *s) {
    if(!t||!s)return;
    for(size_t i=0;i<t->used;) {
        d2k_pf_lease *e=&t->entries[i];
        if(e->scope.family==s->family&&e->scope.server_port==s->server_port&&
            !memcmp(e->scope.client,s->client,16)&&!memcmp(e->scope.server,s->server,16))remove_at(t,i);
        else i++;
    }
}
const d2k_plan *d2k_pf_lease_find(d2k_pf_lease_table *t,const d2k_pf_scope *s,uint64_t now_ns) {
    const d2k_pf_lease *lease = d2k_pf_lease_match(t, s, now_ns);
    return lease ? lease->plan : NULL;
}
const d2k_binding_context *d2k_pf_lease_binding(const d2k_pf_lease_table *t,const d2k_plan *plan) {
    if(!t||!plan)return NULL;
    for(size_t i=0;i<t->used;i++)if(t->entries[i].plan==plan)return &t->entries[i].binding;
    return NULL;
}

const d2k_pf_lease *d2k_pf_lease_match(d2k_pf_lease_table *t,const d2k_pf_scope *s,uint64_t now_ns) {
    if (!t || !s) return NULL;
    expire(t, now_ns);
    for (size_t i = 0; i < t->used; i++) {
        if (same(&t->entries[i].scope, s)) return &t->entries[i];
    }
    return NULL;
}

const d2k_pf_lease *d2k_pf_lease_match_syn(d2k_pf_lease_table *t,uint8_t family,
    const uint8_t client[16],const uint8_t server[16],uint16_t server_port,
    uint32_t path,uint64_t now_ns) {
    if(!t||!client||!server)return NULL;
    expire(t,now_ns);
    const d2k_pf_lease *match=NULL;
    for(size_t i=0;i<t->used;i++) {
        const d2k_pf_lease *e=&t->entries[i];
        if(e->scope.family!=family||e->scope.server_port!=server_port||
            e->scope.path!=path||memcmp(e->scope.client,client,16)||
            memcmp(e->scope.server,server,16))continue;
        if(match)return NULL;
        match=e;
    }
    return match;
}
