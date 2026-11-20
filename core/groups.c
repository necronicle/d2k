#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "include/d2k_domain.h"
#include "include/d2k_groups.h"

typedef struct { uint64_t valid; d2k_domain_group group; } derived_entry;

int d2k_group_store_reserve(d2k_group_state *s,size_t count) {
    if(!s) return -1;
    if(count<=d2k_group_capacity(s)) return 0;
    if(!s->disk_observations || count>SIZE_MAX/sizeof(d2k_group_observation)) return -1;
    size_t capacity=s->disk_capacity;
    while(capacity<count) {
        if(capacity>SIZE_MAX/2/sizeof(d2k_group_observation)) {capacity=count;break;}
        capacity*=2;
    }
    size_t old_bytes=s->disk_capacity*sizeof(d2k_group_observation);
    size_t bytes=capacity*sizeof(d2k_group_observation);
    if((off_t)bytes<0 || (uintmax_t)(off_t)bytes!=(uintmax_t)bytes) return -1;
    /* Allocate backing blocks before mapping: ENOSPC must be an error here,
       not SIGBUS later on the packet controller's first store. */
    const unsigned char zeros[4096]={0};
    for(size_t off=old_bytes;off<bytes;) {
        size_t n=bytes-off<sizeof zeros?bytes-off:sizeof zeros;
        ssize_t written=pwrite(s->disk_fd,zeros,n,(off_t)off);
        if(written<0&&errno==EINTR) continue;
        if(written<=0) return -1;
        off+=(size_t)written;
    }
    void *p=mmap(NULL,bytes,PROT_READ|PROT_WRITE,MAP_SHARED,s->disk_fd,0);
    if(p==MAP_FAILED) return -1;
    munmap(s->disk_observations,old_bytes);
    s->disk_observations=p;s->disk_capacity=capacity;
    return 0;
}

/* The file-backed workspace on the catalog filesystem, or -1. */
static int store_file(const d2k_group_state *s,const char *catalog_path,void **map) {
    size_t n=strlen(catalog_path);
    if(n>SIZE_MAX-24) return -1;
    char *path=malloc(n+24);
    if(!path) return -1;
    snprintf(path,n+24,"%s.groups-XXXXXX",catalog_path);
    int fd=mkstemp(path);
    if(fd<0) {free(path);return -1;}
    if(fcntl(fd,F_SETFD,FD_CLOEXEC)) {unlink(path);close(fd);free(path);return -1;}
    /* The fd keeps blocks on the catalog filesystem, but a crash cannot
       leave an orphan workspace or make it override the atomic catalog. */
    if(unlink(path)) {close(fd);free(path);return -1;}
    free(path);
    size_t bytes=sizeof s->observations;
    for(size_t off=0;off<bytes;) {
        ssize_t written=pwrite(fd,(const unsigned char *)s->observations+off,bytes-off,(off_t)off);
        if(written<0&&errno==EINTR) continue;
        if(written<=0) {close(fd);return -1;}
        off+=(size_t)written;
    }
    void *p=mmap(NULL,bytes,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(p==MAP_FAILED) {close(fd);return -1;}
    *map=p;
    return fd;
}

int d2k_group_store_open(d2k_group_state *s,const char *catalog_path) {
    if(!s||!catalog_path||!catalog_path[0]) return -1;
    if(s->disk_observations) return 0;
    /* Sticky for this catalog instance: once its history could not be
       mapped, a later open must not start an empty history that the next
       save would write over the preserved one. */
    if(s->store_failed) return -1;
    void *p=NULL;
    int fd=store_file(s,catalog_path,&p);
    if(fd<0) {
        /* No flash-backed workspace (ENOSPC, read-only directory, no
           descriptor, no map). History is never moved to RAM: family
           learning is degraded, exact catalog plans are untouched. */
        s->store_failed=1; s->n_groups=0;
        return -1;
    }
    s->disk_fd=fd;s->disk_observations=p;s->disk_capacity=D2K_GROUP_OBSERVATION_MAX;
    s->index_path=strdup(catalog_path);
    memset(s->observations,0,sizeof s->observations);
    if(!s->disabled) s->frozen=0;
    return 0;
}

void d2k_group_store_close(d2k_group_state *s) {
    if(!s) return;
    if(s->preserved_map) munmap((void *)s->preserved_map,s->preserved_map_len);
    s->preserved_map=NULL; s->preserved_map_len=s->preserved_off=s->preserved_len=0;
    if(s->derived_index) {
        munmap(s->derived_index,s->derived_capacity*sizeof(derived_entry));
        close(s->derived_fd);s->derived_index=NULL;s->derived_capacity=0;
    }
    free(s->index_path);s->index_path=NULL;s->derived_ready=0;
    if(!s->disk_observations) return;

    munmap(s->disk_observations,s->disk_capacity*sizeof(d2k_group_observation));
    close(s->disk_fd);s->disk_observations=NULL;s->disk_capacity=0;s->disk_fd=-1;
}

/* Seconds (observation `at` is wall-clock seconds, sched.c wall_s). */
#define D2K_GROUP_VOTE_TTL_S (30*86400)

int d2k_group_key_make(d2k_group_key *key,uint8_t transport,uint8_t family,
    uint8_t shape,const char *path,const char *origin) {
    if(!key || !path || !origin || strlen(path)>=sizeof key->probe_path ||
       strlen(origin)>=sizeof key->ech_origin) return -1;
    memset(key,0,sizeof *key);
    key->transport=transport; key->family=family; key->shape=shape;
    strcpy(key->probe_path,path); strcpy(key->ech_origin,origin);
    return 0;
}

int d2k_group_key_same(const d2k_group_key *a,const d2k_group_key *b) {
    return a && b && a->transport==b->transport && a->family==b->family &&
        a->shape==b->shape && !strcmp(a->probe_path,b->probe_path) &&
        !strcmp(a->ech_origin,b->ech_origin);
}
static int valid(const d2k_group_observation *o) {
    if(!o || !memchr(o->name,0,sizeof o->name) ||
       !memchr(o->plan_id,0,sizeof o->plan_id) ||
       !memchr(o->key.probe_path,0,sizeof o->key.probe_path) ||
       !memchr(o->key.ech_origin,0,sizeof o->key.ech_origin)) return 0;
    if((o->key.family!=4 && o->key.family!=6) ||
       !((o->key.transport==6 && (o->key.shape==1 || o->key.shape==2 || o->key.shape==6)) ||
         (o->key.transport==17 && o->key.shape==3))) return 0;
    if(o->evidence!=1 && o->evidence!=2 && o->evidence!=4 && o->evidence!=8) return 0;
    return (o->evidence!=D2K_GROUP_BLOCKED_CONFIRMED &&
            o->evidence!=D2K_GROUP_PLAN_FAILED) || o->plan_id[0];
}
/* Normalized names, checked against PSL before entering this model. */
static int member(const char *name,const char *suffix) {
    size_t n=strlen(name),z=strlen(suffix);
    return n>=z && !strcmp(name+n-z,suffix) && (n==z || name[n-z-1]=='.');
}
/* Live votes for the seed plan. A vote that later failed this plan or
   proved directly clear is stale: §3.7 returns a degraded family to the
   direct path instead of inheriting an unverified plan. */
static unsigned votes(const d2k_group_state *s,const char *suffix,
                       const d2k_group_observation *seed,int64_t *latest) {
    unsigned live=0,stale=0; *latest=0;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2k_group_observation *o=&d2k_group_rows(s)[i];
        if(!d2k_group_key_same(&o->key,&seed->key) || !member(o->name,suffix)) continue;
        if((o->evidence&D2K_GROUP_DIRECT_CLEAR) &&
           !(o->evidence&D2K_GROUP_ADMITTED_EXCEPTION)) return 0;
        if((o->evidence&D2K_GROUP_BLOCKED_CONFIRMED) && strcmp(o->name,suffix) &&
           !strcmp(o->plan_id,seed->plan_id)) {
            if(o->evidence&(D2K_GROUP_PLAN_FAILED|D2K_GROUP_DIRECT_CLEAR)) { stale++; continue; }
            live++; if(o->at>*latest) *latest=o->at;
        }
    }
    return live>=2 && live>stale && live+stale>=3 ? live : 0;
}
static unsigned failures(const d2k_group_state *s,const char *suffix,
                         const d2k_group_key *key,const char *plan) {
    unsigned n=0;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2k_group_observation *o=&d2k_group_rows(s)[i];
        if((o->evidence&D2K_GROUP_PLAN_FAILED) &&
           d2k_group_key_same(&o->key,key) && member(o->name,suffix) &&
           !strcmp(o->plan_id,plan)) n++;
    }
    return n;
}
static int election_wins(const d2k_group_state *s,const char *suffix,
    const d2k_group_key *key,const char *plan,unsigned count,int64_t at,
    const d2k_domain_group *elected) {
    unsigned candidate_fail=failures(s,suffix,key,plan);
    unsigned elected_fail=failures(s,suffix,&elected->key,elected->plan_id);
    return candidate_fail<elected_fail || (candidate_fail==elected_fail &&
        (count>elected->evidence_count || (count==elected->evidence_count &&
        (at>elected->at || (at==elected->at && strcmp(plan,elected->plan_id)<0)))));
}
static int derive_group(const d2k_group_state *s,const d2k_group_observation *o,
                        d2k_domain_group *out) {
    if(!(o->evidence&D2K_GROUP_BLOCKED_CONFIRMED)) return 0;
    char base[256],best[256]={0};
    if(d2k_domain_base(o->name,base)) return 0;
    const char *suffix=strchr(o->name,'.');
    unsigned best_count=0; int64_t best_at=0;
    while(suffix && strlen(++suffix)>=strlen(base)) {
        int64_t at=0; unsigned count=votes(s,suffix,o,&at);
        if(count) { strcpy(best,suffix); best_count=count; best_at=at; }
        suffix=strchr(suffix,'.');
    }
    if(!best[0]) return 0;
    memset(out,0,sizeof *out);
    strcpy(out->suffix,best); strcpy(out->plan_id,o->plan_id);
    out->key=o->key; out->evidence_count=best_count; out->at=best_at;
    return 1;
}
static void add_group(d2k_group_state *s,const char *suffix,
                      const d2k_group_observation *seed,unsigned count,int64_t at) {
    for(size_t i=0;i<s->n_groups;i++) {
        d2k_domain_group *g=&s->groups[i];
        if(!d2k_group_key_same(&g->key,&seed->key)) continue;
        if(!strcmp(g->suffix,suffix)) {
            /* Deterministic election, not catalog traversal order. */
            if(election_wins(s,suffix,&seed->key,seed->plan_id,count,at,g)) {
                strcpy(g->plan_id,seed->plan_id); g->evidence_count=count; g->at=at;
            }
            return;
        }
        if(!strcmp(g->plan_id,seed->plan_id) && member(suffix,g->suffix)) return;
    }
    for(size_t i=0;i<s->n_groups;) {
        d2k_domain_group *g=&s->groups[i];
        if(d2k_group_key_same(&g->key,&seed->key) &&
           !strcmp(g->plan_id,seed->plan_id) && member(g->suffix,suffix))
            s->groups[i]=s->groups[--s->n_groups];
        else i++;
    }
    if(s->n_groups==D2K_GROUP_MAX) { s->groups_overflow=1; return; }
    d2k_domain_group *g=&s->groups[s->n_groups++];
    memset(g,0,sizeof *g);
    strcpy(g->suffix,suffix); strcpy(g->plan_id,seed->plan_id);
    g->key=seed->key; g->evidence_count=count; g->at=at;
}
static int group_at_uncached(const d2k_group_state *,size_t,d2k_domain_group *);
static void build_index(d2k_group_state *s) {
    if(!s->groups_overflow || !s->disk_observations || !s->index_path) return;
    size_t count=s->n_observations;
    if(count>SIZE_MAX/sizeof(derived_entry)) return;
    if(count>s->derived_capacity) {
        size_t capacity=s->derived_capacity?s->derived_capacity:64;
        while(capacity<count) {
            if(capacity>SIZE_MAX/2/sizeof(derived_entry)){capacity=count;break;}
            capacity*=2;
        }
        size_t len=strlen(s->index_path)+24,bytes=capacity*sizeof(derived_entry);
        if((off_t)bytes<0 || (uintmax_t)(off_t)bytes!=(uintmax_t)bytes)return;

        char *path=malloc(len);if(!path)return;
        snprintf(path,len,"%s.index-XXXXXX",s->index_path);
        int fd=mkstemp(path);
        if(fd<0){free(path);return;}
        int failed=fcntl(fd,F_SETFD,FD_CLOEXEC)<0;
        if(unlink(path)) failed=1;
        free(path);
        const unsigned char zeros[4096]={0};
        for(size_t off=0;!failed && off<bytes;) {
            size_t n=bytes-off<sizeof zeros?bytes-off:sizeof zeros;
            ssize_t wrote=pwrite(fd,zeros,n,(off_t)off);
            if(wrote<0 && errno==EINTR)continue;
            if(wrote<=0){failed=1;break;}off+=(size_t)wrote;
        }
        void *map=failed?MAP_FAILED:mmap(NULL,bytes,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
        if(map==MAP_FAILED){close(fd);return;}
        if(s->derived_index){munmap(s->derived_index,s->derived_capacity*sizeof(derived_entry));close(s->derived_fd);}
        s->derived_index=map;s->derived_capacity=capacity;s->derived_fd=fd;
    }
    derived_entry *entries=s->derived_index;
    for(size_t i=0;i<count;i++) entries[i].valid=group_at_uncached(s,i,&entries[i].group);
    s->derived_ready=1;
}
static void rebuild(d2k_group_state *s) {
    s->n_groups=0; s->groups_overflow=0; s->derived_ready=0;
    if(s->disabled) return;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2k_group_observation *o=&d2k_group_rows(s)[i];
        d2k_domain_group g;
        if(derive_group(s,o,&g)) add_group(s,g.suffix,o,g.evidence_count,g.at);
    }
    build_index(s);
}
static int member_excluded(const d2k_group_state *s,const char *norm,
                           const d2k_group_key *key,const char *plan) {
    for(size_t i=0;i<s->n_observations;i++) {
        const d2k_group_observation *o=&d2k_group_rows(s)[i];
        if(strcmp(o->name,norm) || !d2k_group_key_same(&o->key,key)) continue;
        if((o->evidence&D2K_GROUP_DIRECT_CLEAR) ||
           ((o->evidence&D2K_GROUP_PLAN_FAILED) && !strcmp(o->plan_id,plan))) return 1;
    }
    return 0;
}
static int hot_group(const d2k_group_state *s,const char *norm,
    const d2k_group_key *key,d2k_domain_group *out,int exclusions) {
    const d2k_domain_group *best=NULL;
    for(size_t i=0;i<s->n_groups;i++) {
        const d2k_domain_group *g=&s->groups[i];
        if(!d2k_group_key_same(&g->key,key) || !member(norm,g->suffix) ||
           (exclusions && member_excluded(s,norm,key,g->plan_id))) continue;
        if(!best || strlen(g->suffix)>strlen(best->suffix)) best=g;
    }
    if(!best) return 0;
    *out=*best;
    return 1;
}
static int elect_suffix(const d2k_group_state *s,const char *suffix,
                        const d2k_group_key *key,d2k_domain_group *out) {
    int found=0;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2k_group_observation *o=&d2k_group_rows(s)[i];
        d2k_domain_group candidate;
        if(!d2k_group_key_same(&o->key,key) || !member(o->name,suffix) ||
           !strcmp(o->name,suffix)) continue;
        if(!derive_group(s,o,&candidate) || strcmp(candidate.suffix,suffix)) continue;
        if(!found || election_wins(s,suffix,&candidate.key,candidate.plan_id,
                                  candidate.evidence_count,candidate.at,out)) {
            *out=candidate; found=1;
        }
    }
    return found;
}
size_t d2k_group_slots(const d2k_group_state *s) {
    return !s || s->disabled ? 0 : s->groups_overflow ? s->n_observations : s->n_groups;
}
static int group_at_uncached(const d2k_group_state *s,size_t index,d2k_domain_group *out) {
    if(!out || index>=d2k_group_slots(s)) return 0;
    if(!s->groups_overflow) { *out=s->groups[index]; return 1; }
    d2k_domain_group seed;
    if(!derive_group(s,&d2k_group_rows(s)[index],&seed)) return 0;
    for(size_t i=0;i<index;i++) {
        const d2k_group_observation *o=&d2k_group_rows(s)[i];
        d2k_domain_group prev;
        if(d2k_group_key_same(&o->key,&seed.key) && member(o->name,seed.suffix) &&
           derive_group(s,o,&prev) && !strcmp(prev.suffix,seed.suffix)) return 0;
    }
    if(!elect_suffix(s,seed.suffix,&seed.key,out)) return 0;
    for(const char *p=strchr(out->suffix,'.');p;p=strchr(p+1,'.')) {
        d2k_domain_group broader;
        if(elect_suffix(s,p+1,&out->key,&broader) &&
           !strcmp(broader.plan_id,out->plan_id)) return 0;
    }
    return !s->plan_available || s->plan_available(s->plan_available_ctx,out);
}
int d2k_group_at(const d2k_group_state *s,size_t index,d2k_domain_group *out) {
    if(!out || index>=d2k_group_slots(s)) return 0;
    if(s->groups_overflow && s->derived_ready) {
        const derived_entry *entry=&((const derived_entry *)s->derived_index)[index];
        if(!entry->valid)return 0;
        *out=entry->group;
        return !s->plan_available || s->plan_available(s->plan_available_ctx,out);
    }
    return group_at_uncached(s,index,out);
}
static int demand_group(const d2k_group_state *s,const char *norm,
    const d2k_group_key *key,d2k_domain_group *out,int exclusions) {
    char base[256];
    if(d2k_domain_base(norm,base)) return 0;
    const char *suffix=norm;
    while(suffix && strlen(suffix)>=strlen(base)) {
        d2k_domain_group candidate;
        if(elect_suffix(s,suffix,key,&candidate) &&
           (!s->plan_available || s->plan_available(s->plan_available_ctx,&candidate)) &&
           (!exclusions || !member_excluded(s,norm,key,candidate.plan_id))) {
            *out=candidate;
            return 1;
        }
        suffix=strchr(suffix,'.');
        if(suffix) suffix++;
    }
    return 0;
}
static int resolve_group(const d2k_group_state *s,const char *norm,
    const d2k_group_key *key,d2k_domain_group *out,int exclusions) {
    if(s->disabled || s->n_groups>D2K_GROUP_MAX) return 0;
    if(s->groups_overflow && s->derived_ready) {
        int found=0;
        for(size_t i=0;i<d2k_group_slots(s);i++) {
            d2k_domain_group candidate;
            if(!d2k_group_at(s,i,&candidate) || !d2k_group_key_same(key,&candidate.key) ||
               !member(norm,candidate.suffix) ||
               (exclusions && member_excluded(s,norm,key,candidate.plan_id)))continue;
            if(!found || strlen(candidate.suffix)>strlen(out->suffix)){*out=candidate;found=1;}
        }
        return found;
    }
    return s->groups_overflow ? demand_group(s,norm,key,out,exclusions) :

        hot_group(s,norm,key,out,exclusions);
}
/* Group covering a normalized name, ignoring per-member exclusions. */
static int cover(const d2k_group_state *s,const char *norm,const d2k_group_key *key) {
    d2k_domain_group out;
    return resolve_group(s,norm,key,&out,0);
}
int d2k_group_learn(d2k_group_state *s,const d2k_group_observation *o) {
    char name[256],base[256];
    if(s && s->store_failed) return 0; /* degraded: nothing is learned in RAM */
    if(!s || !valid(o) || d2k_domain_normalize(o->name,name) ||
       d2k_domain_base(name,base) || s->n_groups>D2K_GROUP_MAX ||
       s->n_observations>d2k_group_capacity(s)) return -1;
    d2k_group_observation incoming=*o;
    o=&incoming; /* reserve can move file mappings, including caller's row */
    int admitted_clear=o->evidence==D2K_GROUP_DIRECT_CLEAR &&
        cover(s,name,&o->key);
    size_t slot=s->n_observations;
    size_t replace=s->n_observations,any=s->n_observations;
    for(size_t i=0;i<s->n_observations;i++)
        if(!strcmp(d2k_group_rows(s)[i].name,name) &&
           d2k_group_key_same(&d2k_group_rows(s)[i].key,&o->key)) {
            const d2k_group_observation *old=&d2k_group_rows(s)[i];
            if(!strcmp(old->plan_id,o->plan_id)) { slot=i; break; }
            /* Prefer the same-plan entry: never leave two entries of one plan. */
            if((o->evidence==D2K_GROUP_DIRECT_CLEAR || o->evidence==D2K_GROUP_INCONCLUSIVE) &&
               any==s->n_observations) any=i;
            if(o->evidence==D2K_GROUP_BLOCKED_CONFIRMED &&
               !(old->evidence&D2K_GROUP_PLAN_FAILED) && replace==s->n_observations) replace=i;
        }
    if(slot==s->n_observations && any<s->n_observations) slot=any;
    if(slot==s->n_observations && replace<s->n_observations) slot=replace;
    int negative=o->evidence==D2K_GROUP_DIRECT_CLEAR || o->evidence==D2K_GROUP_PLAN_FAILED;
    if(slot==s->n_observations) {
        /* Growth is storage, independent of area enablement: a lost
           exclusion (disabled) must not also stop retaining evidence. */
        if(s->disk_observations) {
            if(d2k_group_store_reserve(s,slot+1)) {
                /* Flash full (ENOSPC/EFBIG/no map): retained history is kept
                   whole. The new vote is not stored (frozen, reported); an
                   exclusion that cannot be stored fails areas closed. */
                s->frozen=1;
                if(negative) {
                    s->disabled=1;s->n_groups=0;
                    if(o->at>s->disabled_at)s->disabled_at=o->at;
                }
                return 1;
            }
            s->frozen=0;
        }
        if(s->frozen || slot==d2k_group_capacity(s)) {
            int changed=!s->frozen; s->frozen=1;
            if(o->evidence!=D2K_GROUP_DIRECT_CLEAR && o->evidence!=D2K_GROUP_PLAN_FAILED)
                return changed;
            /* A bounded budget must never discard a new exclusion while
             * retaining a broad rule. Exact confirmed catalog bindings are
             * independent and untouched; negative evidence is never evicted.
             * Re-enabling: families re-learn only from confirmations newer
               than the moment the journal lost an exclusion. */
            if(s->disabled)
                for(size_t i=0;i<s->n_observations;) {
                    const d2k_group_observation *v=&d2k_group_rows(s)[i];
                    if(v->evidence==D2K_GROUP_BLOCKED_CONFIRMED && v->at<=s->disabled_at)
                        d2k_group_rows(s)[i]=d2k_group_rows(s)[--s->n_observations];
                    else i++;
                }
            size_t reclaim=s->n_observations;
            /* Reclaim exactly one slot: the oldest expired unknown evidence,
               else the oldest expired positive vote (expired: strictly more
               than D2K_GROUP_VOTE_TTL_S older than this event), else the
               first unknown evidence, else the first positive vote. */
            for(unsigned pass=D2K_GROUP_INCONCLUSIVE;
                reclaim==d2k_group_capacity(s) && pass;
                pass=pass==D2K_GROUP_INCONCLUSIVE?D2K_GROUP_BLOCKED_CONFIRMED:0)
                for(size_t i=0;i<s->n_observations;i++) {
                    const d2k_group_observation *v=&d2k_group_rows(s)[i];
                    if(v->evidence==pass && o->at-v->at>D2K_GROUP_VOTE_TTL_S &&
                       (reclaim==d2k_group_capacity(s) ||
                        v->at<d2k_group_rows(s)[reclaim].at)) reclaim=i;
                }
            if(reclaim==d2k_group_capacity(s))
                for(size_t i=0;i<s->n_observations;i++) {
                    if(d2k_group_rows(s)[i].evidence==D2K_GROUP_INCONCLUSIVE) { reclaim=i; break; }
                    if(reclaim==d2k_group_capacity(s) &&
                       d2k_group_rows(s)[i].evidence==D2K_GROUP_BLOCKED_CONFIRMED) reclaim=i;
                }
            if(reclaim==d2k_group_capacity(s)) {
                /* Historic votes may also carry negative evidence. Without
                   room for this exclusion, fail closed for areas, never
                   forget an exclusion or disturb exact catalog plans. */
                changed |= !s->disabled; s->disabled=1; s->n_groups=0;
                if(o->at>s->disabled_at) { s->disabled_at=o->at; changed=1; }
                for(size_t i=0;i<s->n_observations;i++)
                    if(d2k_group_rows(s)[i].at>s->disabled_at) {
                        s->disabled_at=d2k_group_rows(s)[i].at; changed=1;
                    }
                return changed;
            }
            slot=reclaim;
            if(slot==s->n_observations) s->n_observations++;
            d2k_group_rows(s)[slot]=*o; strcpy(d2k_group_rows(s)[slot].name,name);
            s->disabled=0; s->disabled_at=0; /* the new exclusion is retained */
            if(s->n_observations<d2k_group_capacity(s)) s->frozen=0; /* room again */
        } else {
            if(s->disabled && negative) {
                /* Same re-enable rule as the bounded path below the store
                   limit: the new exclusion is retained, and families re-learn
                   only from confirmations newer than the lost exclusion. */
                for(size_t i=0;i<s->n_observations;) {
                    const d2k_group_observation *v=&d2k_group_rows(s)[i];
                    if(v->evidence==D2K_GROUP_BLOCKED_CONFIRMED && v->at<=s->disabled_at)
                        d2k_group_rows(s)[i]=d2k_group_rows(s)[--s->n_observations];
                    else i++;
                }
                slot=s->n_observations;
                s->disabled=0; s->disabled_at=0;
            }
            d2k_group_rows(s)[slot]=*o; strcpy(d2k_group_rows(s)[slot].name,name);
            s->n_observations++;
        }
    } else {
        d2k_group_observation *old=&d2k_group_rows(s)[slot];
        if(o->at<old->at || o->evidence==D2K_GROUP_INCONCLUSIVE) return 0;
        if(o->evidence==D2K_GROUP_DIRECT_CLEAR &&
           (old->evidence&D2K_GROUP_ADMITTED_EXCEPTION)) admitted_clear=1;
        /* Execution failure becomes an exception, not erasure of a historic
           successful vote: other group members keep their bypass. */
        if(o->evidence==D2K_GROUP_PLAN_FAILED) {
            if(strcmp(o->plan_id,old->plan_id)) return 0;
            old->evidence|=D2K_GROUP_PLAN_FAILED; old->at=o->at;
        } else if(admitted_clear && (old->evidence&D2K_GROUP_BLOCKED_CONFIRMED)) {
            old->evidence=D2K_GROUP_BLOCKED_CONFIRMED|D2K_GROUP_DIRECT_CLEAR|
                D2K_GROUP_ADMITTED_EXCEPTION;
            old->at=o->at; /* keep its historical own-plan vote for siblings */
        } else { *old=*o; strcpy(old->name,name); }
    }
    if(admitted_clear) d2k_group_rows(s)[slot].evidence |= D2K_GROUP_ADMITTED_EXCEPTION;
    /* Keep one latest positive/clean observation per member, but preserve
       independent failed Plan IDs: trying B must not erase the failure of A. */
    if(o->evidence==D2K_GROUP_BLOCKED_CONFIRMED || o->evidence==D2K_GROUP_DIRECT_CLEAR)
        for(size_t i=0;i<s->n_observations;) {
            const d2k_group_observation *other=&d2k_group_rows(s)[i];
            if(i!=slot && !strcmp(other->name,name) &&
               d2k_group_key_same(&other->key,&o->key) &&
               !(other->evidence&D2K_GROUP_PLAN_FAILED)) {
                size_t last=--s->n_observations;
                d2k_group_rows(s)[i]=d2k_group_rows(s)[last];
                if(slot==last) slot=i;
            } else i++;
        }
    if(o->evidence!=D2K_GROUP_INCONCLUSIVE) rebuild(s);
    else s->derived_ready=0;
    return 1;
}
int d2k_group_restore(d2k_group_state *s) {
    if(!s || s->n_observations>d2k_group_capacity(s) || s->disabled_at<0) return -1;
    for(size_t i=0;i<s->n_observations;i++) {
        d2k_group_observation *o=&d2k_group_rows(s)[i], test=*o;
        /* learn() writes masks; reduce them to the raw events they came from. */
        /* A failure may be ORed onto a stored INCONCLUSIVE; the failure stays. */
        if(test.evidence!=D2K_GROUP_INCONCLUSIVE) test.evidence&=~D2K_GROUP_INCONCLUSIVE;
        if(test.evidence&D2K_GROUP_ADMITTED_EXCEPTION) {
            if(!(test.evidence&D2K_GROUP_DIRECT_CLEAR)) return -1;
            test.evidence&=~D2K_GROUP_ADMITTED_EXCEPTION;
        }
        if(test.evidence&D2K_GROUP_BLOCKED_CONFIRMED)
            test.evidence&=~(D2K_GROUP_DIRECT_CLEAR|D2K_GROUP_PLAN_FAILED);
        else if((test.evidence&D2K_GROUP_DIRECT_CLEAR) &&
                (test.evidence&D2K_GROUP_PLAN_FAILED))
            test.evidence=D2K_GROUP_PLAN_FAILED;
        char norm[256],base[256];
        if(!valid(&test) || o->at<0 || d2k_domain_normalize(o->name,norm) ||
           d2k_domain_base(norm,base)) return -1;
        strcpy(o->name,norm);
        for(size_t j=0;j<i;j++)
            if(!strcmp(d2k_group_rows(s)[j].name,o->name) &&
               d2k_group_key_same(&d2k_group_rows(s)[j].key,&o->key) &&
               (!strcmp(d2k_group_rows(s)[j].plan_id,o->plan_id) ||
                !((d2k_group_rows(s)[j].evidence|o->evidence)&D2K_GROUP_PLAN_FAILED))) return -1;
    }
    if(s->disk_observations && !s->disabled) s->frozen=0;
    rebuild(s); return 0;
}
const d2k_domain_group *d2k_group_match(const d2k_group_state *s,
    const char *name,const d2k_group_key *key,d2k_domain_group *out) {
    char norm[256];
    if(!s || s->disabled || !key || !out || d2k_domain_normalize(name,norm) ||
       s->n_groups>D2K_GROUP_MAX || s->n_observations>d2k_group_capacity(s)) return NULL;
    return resolve_group(s,norm,key,out,1) ? out : NULL;
}
int d2k_group_forget(d2k_group_state *s,const char *name,uint8_t transport,uint8_t family) {
    char norm[256];
    if(!s || !name || d2k_domain_normalize(name,norm) ||
       s->n_observations>d2k_group_capacity(s)) return 0;
    int dropped=0;
    for(size_t i=0;i<s->n_observations;) {
        const d2k_group_observation *o=&d2k_group_rows(s)[i];
        if(!strcmp(o->name,norm) && o->key.transport==transport && o->key.family==family &&
           (o->evidence&D2K_GROUP_PLAN_FAILED)) {
            d2k_group_rows(s)[i]=d2k_group_rows(s)[--s->n_observations];
            memset(&d2k_group_rows(s)[s->n_observations],0,sizeof d2k_group_rows(s)[0]);
            dropped++;
        } else i++;
    }
    if(dropped) rebuild(s);
    return dropped;
}
int d2k_group_expire(d2k_group_state *s,int64_t now,int64_t max_age) {
    if(!s || max_age<=0 || now<max_age || s->n_observations>d2k_group_capacity(s)) return 0;
    int dropped=0;
    for(size_t i=0;i<s->n_observations;) {
        const d2k_group_observation *o=&d2k_group_rows(s)[i];
        if((o->evidence&D2K_GROUP_PLAN_FAILED) && o->at<now-max_age) {
            d2k_group_rows(s)[i]=d2k_group_rows(s)[--s->n_observations];
            memset(&d2k_group_rows(s)[s->n_observations],0,sizeof d2k_group_rows(s)[0]);
            dropped++;
        } else i++;
    }
    if(dropped) rebuild(s);
    return dropped;
}
