#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include "include/d2k_catalog.h"
#include "include/d2k_groups.h"
static int failed;
static d2k_domain_group match;
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"group-catalog:%d: %s\n",__LINE__,#c); failed++; } } while(0)

/* ---- growable store: retention, fallback, faults (task 61) ---------- */
static d2k_group_observation vote(const char *fmt,int i,unsigned evidence,int64_t at,
                                  const d2k_group_key *key) {
    d2k_group_observation o; memset(&o,0,sizeof o);
    snprintf(o.name,sizeof o.name,fmt,i);
    if(evidence&(D2K_GROUP_BLOCKED_CONFIRMED|D2K_GROUP_PLAN_FAILED)) strcpy(o.plan_id,"plan-test");
    o.key=*key; o.evidence=evidence; o.at=at;
    return o;
}
static size_t count_rows(const d2k_group_state *s,unsigned evidence) {
    size_t n=0;
    for(size_t i=0;i<s->n_observations;i++) if(d2k_group_rows(s)[i].evidence==evidence) n++;
    return n;
}
static const d2k_group_observation *row_named(const d2k_group_state *s,const char *name) {
    for(size_t i=0;i<s->n_observations;i++)
        if(!strcmp(d2k_group_rows(s)[i].name,name)) return &d2k_group_rows(s)[i];
    return NULL;
}
static int with_plan(d2k_catalog *c) {
    c->boxes=calloc(1,sizeof *c->boxes); if(!c->boxes) return -1;
    c->n_boxes=1; strcpy(c->boxes[0].id,"box-growth");
    c->boxes[0].plans=calloc(1,sizeof *c->boxes[0].plans); if(!c->boxes[0].plans) return -1;
    c->boxes[0].n_plans=1; strcpy(c->boxes[0].plans[0].id,"plan-test");
    strcpy(c->boxes[0].plans[0].proto,"tls"); c->boxes[0].plans[0].enabled=1;
    c->boxes[0].plans[0].text=strdup("opaque-test-plan");
    return c->boxes[0].plans[0].text ? 0 : -1;
}
/* The catalog is parsed from a read-only mapping with explicit bounds. Files
   sized exactly to a page and cut mid-token put the byte after the end on an
   unmapped page: any read past the bound would fault instead of erroring. */
static void bounded_parse_tests(const char *path) {
    char err[256]; d2k_catalog c={0};
    static const char *const small[]={"", "   \n", "{", "{\"boxes\":[", "{\"boxes\":[{\"id\":\"ab"};
    for(size_t i=0;i<sizeof small/sizeof small[0];i++) {
        FILE *f=fopen(path,"w"); CHECK(f!=NULL); if(!f) return;
        fputs(small[i],f); fclose(f);
        CHECK(d2k_catalog_load(path,&c,err,sizeof err)!=0 && !c.groups && !c.boxes);
        d2k_catalog_free(&c);
    }
    long page=sysconf(_SC_PAGESIZE);
    CHECK(page>=4096 && page<=65536);
    static const char *const heads[]={
        "{\"boxes\":[{\"id\":\"",                 /* inside a string */
        "{\"boxes\":[],\"x\":\"\\u00",            /* inside an escape */
        "{\"boxes\":[],\"domain_groups_frozen\":tr", /* inside a literal */
        "{\"boxes\":[],\"domain_observations\":[{\"at\":\"2026-10-3", /* inside a time */
        "{\"boxes\":[],\"x\":12345"};               /* inside a number */
    for(size_t h=0;page>0 && h<sizeof heads/sizeof heads[0];h++) {
        FILE *f=fopen(path,"w"); CHECK(f!=NULL); if(!f) return;
        size_t n=strlen(heads[h]);
        fputs(heads[h],f);
        char fill=h==4?'9':'a';
        for(long k=(long)n;k<page;k++) fputc(fill,f);
        fclose(f);
        CHECK(d2k_catalog_load(path,&c,err,sizeof err)!=0);
        d2k_catalog_free(&c);
    }
}
static void growth_tests(const char *path,const d2k_group_key *key) {
    char err[256];
    bounded_parse_tests(path);
    enum { VOTES=300 };
    /* 1. More than the old 256 positive votes, real backing plan, file store:
       every vote retained (none evicted) through save/load/restore. */
    d2k_catalog c={0},d={0};
    c.groups=calloc(1,sizeof *c.groups);
    CHECK(c.groups && with_plan(&c)==0);
    if(!c.groups || !c.boxes || !c.boxes[0].plans) { d2k_catalog_free(&c); return; }
    CHECK(d2k_group_store_open(c.groups,path)==0 && c.groups->disk_fd>=0);
    for(int i=0;i<VOTES;i++) {
        d2k_group_observation o=vote("v%d.googlevideo.com",i,D2K_GROUP_BLOCKED_CONFIRMED,1000+i,key);
        CHECK(d2k_group_learn(c.groups,&o)==1);
    }
    CHECK(c.groups->n_observations==VOTES && c.groups->disk_capacity>=VOTES);
    CHECK(!c.groups->frozen && !c.groups->disabled);
    CHECK(d2k_group_match(c.groups,"new.googlevideo.com",key,&match)!=NULL);
    CHECK(d2k_catalog_save(&c,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&d,err,sizeof err)==0);
    CHECK(d.groups && d.groups->n_observations==VOTES && d.groups->disk_fd>=0);
    if(d.groups) {
        CHECK(count_rows(d.groups,D2K_GROUP_BLOCKED_CONFIRMED)==VOTES);
        CHECK(row_named(d.groups,"v0.googlevideo.com") && row_named(d.groups,"v299.googlevideo.com"));
        CHECK(!d.groups->frozen && !d.groups->disabled);
        CHECK(d2k_group_match(d.groups,"new.googlevideo.com",key,&match)!=NULL);
        /* Exclusions after reload are retained and evict no vote. */
        d2k_group_observation clear=vote("v7.googlevideo.com",0,D2K_GROUP_DIRECT_CLEAR,5000,key);
        CHECK(d2k_group_learn(d.groups,&clear)==1);
        clear=vote("c%d.googlevideo.com",1,D2K_GROUP_DIRECT_CLEAR,5001,key);
        CHECK(d2k_group_learn(d.groups,&clear)==1);
        CHECK(d.groups->n_observations==VOTES+1);
        CHECK(!d2k_group_match(d.groups,"v7.googlevideo.com",key,&match) &&
              !d2k_group_match(d.groups,"c1.googlevideo.com",key,&match) &&
              d2k_group_match(d.groups,"new.googlevideo.com",key,&match)!=NULL);
        CHECK(d2k_catalog_save(&d,path,err,sizeof err)==0);
    }
    d2k_catalog_free(&d);
    CHECK(d2k_catalog_load(path,&d,err,sizeof err)==0);
    CHECK(d.groups && d.groups->n_observations==VOTES+1 &&
          d2k_group_match(d.groups,"new.googlevideo.com",key,&match)!=NULL &&
          !d2k_group_match(d.groups,"v7.googlevideo.com",key,&match));
    d2k_catalog_free(&d); d2k_catalog_free(&c);

    /* 2. No flash-backed workspace: family learning is degraded, nothing is
       learned into RAM, and the open failure is sticky. */
    d2k_group_state *h=calloc(1,sizeof *h);
    CHECK(h!=NULL);
    if(h) {
        CHECK(d2k_group_store_open(h,"/nonexistent-d2k-groups-dir/catalog.json")==-1 && h->store_failed);
        d2k_group_observation o=vote("v%d.googlevideo.com",1,D2K_GROUP_BLOCKED_CONFIRMED,1000,key);
        CHECK(d2k_group_learn(h,&o)==0 && h->n_observations==0 && !h->disk_observations);
        CHECK(d2k_group_store_open(h,path)==-1); /* sticky, even where a store could exist */
        d2k_group_store_close(h); free(h);
    }
    /* A catalog with an exact plan and >256 observations, loaded when no
       workspace can be created (RLIMIT_FSIZE applies to root too): the plan
       loads, family learning is degraded, the history is written back
       unchanged by a save and is whole again once storage works. */
    struct rlimit old,lim;
    CHECK(getrlimit(RLIMIT_FSIZE,&old)==0);
    signal(SIGXFSZ,SIG_IGN);
    {
        FILE *f=fopen(path,"w"); CHECK(f!=NULL);
        if(f) {
            fputs("{\"boxes\":[{\"id\":\"box-exact\",\"plans\":[{\"id\":\"plan-test\",\"proto\":\"tls\","
                  "\"text\":\"opaque-test-plan\",\"enabled\":true}],\"bindings\":[]}],"
                  "\"domain_observations\":[",f);
            for(int i=0;i<=D2K_GROUP_OBSERVATION_MAX;i++)
                fprintf(f,"%s{\"name\":\"h%d.example.com\",\"transport\":6,\"family\":4,\"shape\":1,\"evidence\":2}",i?",":"",i);
            fputs("]}",f); fclose(f);
        }
        lim=old; lim.rlim_cur=0;
        CHECK(setrlimit(RLIMIT_FSIZE,&lim)==0);
        int rc=d2k_catalog_load(path,&d,err,sizeof err);
        CHECK(setrlimit(RLIMIT_FSIZE,&old)==0);
        CHECK(rc==0 && d.n_boxes==1 && d.boxes[0].n_plans==1 && !strcmp(d.boxes[0].plans[0].id,"plan-test"));
        CHECK(d.groups && d.groups->store_failed && d.groups->n_observations==0 &&
              !d.groups->disk_observations && d.groups->preserved_len>0);
        /* History stays in a read-only mapping of the original inode. */
        CHECK(d.groups && d.groups->preserved_map &&
              d.groups->preserved_map[d.groups->preserved_off]=='[');
        if(d.groups) {
            CHECK(d2k_group_store_open(d.groups,path)==-1);
            d2k_group_observation o=vote("v%d.googlevideo.com",1,D2K_GROUP_BLOCKED_CONFIRMED,1000,key);
            CHECK(d2k_group_learn(d.groups,&o)==0 && d.groups->n_observations==0);
            CHECK(!d2k_group_match(d.groups,"h1.example.com",key,&match));
        }
        /* In place onto the mapped inode would truncate the history source:
           refused. The atomic save (new inode + rename) is the production path. */
        CHECK(d2k_catalog_save(&d,path,err,sizeof err)==-1 && strstr(err,"atomically"));
        CHECK(d2k_catalog_save_atomic(&d,path,err,sizeof err)==0);
        {
            d2k_catalog e={0};
            CHECK(d2k_catalog_load(path,&e,err,sizeof err)==0 && e.groups &&
                  e.groups->n_observations==D2K_GROUP_OBSERVATION_MAX+1 && e.n_boxes==1);
            d2k_catalog_free(&e);
        }
        /* The path is atomically replaced by another catalog: the mapping
           still holds the original inode, and the save writes its history. */
        {
            char other[600]; snprintf(other,sizeof other,"%s.other",path);
            FILE *g=fopen(other,"w"); CHECK(g!=NULL);
            if(g) { fputs("{\"boxes\":[]}",g); fclose(g); }
            CHECK(rename(other,path)==0);
        }
        CHECK(d2k_catalog_save(&d,path,err,sizeof err)==0);
        d2k_catalog_free(&d);
        CHECK(d2k_catalog_load(path,&d,err,sizeof err)==0);
        CHECK(d.groups && !d.groups->store_failed && d.groups->disk_fd>=0 &&
              d.groups->n_observations==D2K_GROUP_OBSERVATION_MAX+1);
        CHECK(d.groups && row_named(d.groups,"h0.example.com") && row_named(d.groups,"h256.example.com"));
        CHECK(d.n_boxes==1 && d.boxes[0].n_plans==1);
        d2k_catalog_free(&d);
        /* Degraded with no mapping: the save is refused and the flash copy is
           left exactly as it was — history is never written away. */
        lim=old; lim.rlim_cur=0;
        CHECK(setrlimit(RLIMIT_FSIZE,&lim)==0);
        int rc2=d2k_catalog_load(path,&d,err,sizeof err);
        CHECK(setrlimit(RLIMIT_FSIZE,&old)==0);
        CHECK(rc2==0 && d.groups && d.groups->store_failed && d.groups->preserved_map);
        if(rc2==0 && d.groups && d.groups->preserved_map) {
            munmap((void *)d.groups->preserved_map,d.groups->preserved_map_len);
            d.groups->preserved_map=NULL;
            FILE *g=fopen(path,"rb"); long before_size=-1;
            if(g) { fseek(g,0,SEEK_END); before_size=ftell(g); fclose(g); }
            CHECK(d2k_catalog_save(&d,path,err,sizeof err)==-1 && strstr(err,"not saved"));
            g=fopen(path,"rb"); long after_size=-2;
            if(g) { fseek(g,0,SEEK_END); after_size=ftell(g); fclose(g); }
            CHECK(before_size>0 && before_size==after_size);
        }
        d2k_catalog_free(&d);
        CHECK(d2k_catalog_load(path,&d,err,sizeof err)==0 && d.groups &&
              d.groups->n_observations==D2K_GROUP_OBSERVATION_MAX+1);
        d2k_catalog_free(&d);
    }

    /* 3. The workspace cannot grow (EFBIG here, ENOSPC in the field): history
       stays whole. A vote is not stored (frozen); an exclusion that cannot be
       stored fails areas closed; no vote is evicted. Growth resumes later. */
    d2k_group_state *s=calloc(1,sizeof *s);
    CHECK(s!=NULL);
    if(!s) return;
    CHECK(d2k_group_store_open(s,path)==0 && s->disk_fd>=0);
    for(int i=0;i<D2K_GROUP_OBSERVATION_MAX;i++) {
        d2k_group_observation o=vote("v%d.googlevideo.com",i,D2K_GROUP_BLOCKED_CONFIRMED,1000+i,key);
        CHECK(d2k_group_learn(s,&o)==1);
    }
    CHECK(s->n_observations==D2K_GROUP_OBSERVATION_MAX && s->disk_capacity==D2K_GROUP_OBSERVATION_MAX);
    lim=old; lim.rlim_cur=(rlim_t)(D2K_GROUP_OBSERVATION_MAX*sizeof(d2k_group_observation));
    CHECK(setrlimit(RLIMIT_FSIZE,&lim)==0);
    d2k_group_observation lost=vote("w%d.googlevideo.com",1,D2K_GROUP_BLOCKED_CONFIRMED,3000,key);
    CHECK(d2k_group_learn(s,&lost)==1);
    CHECK(s->frozen && !s->disabled && s->disk_capacity==D2K_GROUP_OBSERVATION_MAX);
    CHECK(!row_named(s,"w1.googlevideo.com"));
    d2k_group_observation clear=vote("x%d.googlevideo.com",1,D2K_GROUP_DIRECT_CLEAR,4000,key);
    CHECK(d2k_group_learn(s,&clear)==1);
    CHECK(s->disabled && s->disabled_at==4000 && !d2k_group_match(s,"new.googlevideo.com",key,&match));
    CHECK(s->n_observations==D2K_GROUP_OBSERVATION_MAX &&
          count_rows(s,D2K_GROUP_BLOCKED_CONFIRMED)==D2K_GROUP_OBSERVATION_MAX);
    CHECK(setrlimit(RLIMIT_FSIZE,&old)==0);
    CHECK(d2k_group_learn(s,&lost)==1);
    CHECK(!s->frozen && s->disabled && row_named(s,"w1.googlevideo.com") &&
          s->disk_capacity>D2K_GROUP_OBSERVATION_MAX);

    /* 4. Disabled does not stop growth, and a newly retained exclusion
       re-enables areas by the documented rule: plain votes at or before
       disabled_at are dropped. */
    for(int i=0;s->n_observations<s->disk_capacity;i++) {
        d2k_group_observation o=vote("z%d.googlevideo.com",i,D2K_GROUP_BLOCKED_CONFIRMED,5000+i,key);
        CHECK(d2k_group_learn(s,&o)==1);
    }
    size_t before=s->n_observations;
    for(int i=0;i<20;i++) {
        d2k_group_observation o=vote("y%d.googlevideo.com",i,D2K_GROUP_BLOCKED_CONFIRMED,6000+i,key);
        CHECK(d2k_group_learn(s,&o)==1);
    }
    CHECK(s->n_observations==before+20 && s->disabled &&
          !d2k_group_match(s,"new.googlevideo.com",key,&match));
    /* A plan failure excludes only its member; the family re-forms from the
       retained newer votes. (A direct-clear member learned while nothing
       covered it would rightly keep the suffix degraded, §3.7.) */
    clear=vote("x%d.googlevideo.com",2,D2K_GROUP_PLAN_FAILED,7000,key);
    CHECK(d2k_group_learn(s,&clear)==1);
    CHECK(!s->disabled && !s->disabled_at && row_named(s,"x2.googlevideo.com"));
    CHECK(!row_named(s,"v100.googlevideo.com") && !row_named(s,"w1.googlevideo.com") &&
          row_named(s,"z0.googlevideo.com") && row_named(s,"y19.googlevideo.com"));
    CHECK(d2k_group_match(s,"new.googlevideo.com",key,&match)!=NULL &&
          !d2k_group_match(s,"x2.googlevideo.com",key,&match));
    d2k_group_store_close(s); free(s);
}

static void availability_tests(const char *path,const d2k_group_key *key) {
    char other[600],err[256];
    snprintf(other,sizeof other,"%s.other",path);
    d2k_catalog saturated={0},plain={0};
    saturated.groups=calloc(1,sizeof *saturated.groups);
    plain.groups=calloc(1,sizeof *plain.groups);
    CHECK(saturated.groups && plain.groups && with_plan(&saturated)==0 && with_plan(&plain)==0);
    if(!saturated.groups || !plain.groups || !saturated.boxes || !plain.boxes) {
        d2k_catalog_free(&saturated); d2k_catalog_free(&plain); return;
    }
    CHECK(d2k_group_store_open(saturated.groups,path)==0);
    for(int family=0;family<=D2K_GROUP_MAX;family++)
        for(int member=0;member<3;member++) {
            char name[256]; snprintf(name,sizeof name,"v%d.f%02d.com",member,family);
            d2k_group_observation o=vote(name,0,D2K_GROUP_BLOCKED_CONFIRMED,
                                         1000+family*3+member,key);
            CHECK(d2k_group_learn(saturated.groups,&o)==1);
            if(family==D2K_GROUP_MAX) CHECK(d2k_group_learn(plain.groups,&o)==1);
        }
    for(int variant=0;variant<3;variant++) {
        d2k_cat_plan *sp=&saturated.boxes[0].plans[0],*pp=&plain.boxes[0].plans[0];
        sp->enabled=pp->enabled=variant!=0;
        saturated.boxes[0].n_plans=plain.boxes[0].n_plans=variant==1?0:1;
        strcpy(sp->proto,variant==2?"quic":"tls"); strcpy(pp->proto,variant==2?"quic":"tls");
        CHECK(d2k_catalog_save(&saturated,path,err,sizeof err)==0);
        CHECK(d2k_catalog_save(&plain,other,err,sizeof err)==0);
        d2k_catalog a={0},b={0};
        CHECK(d2k_catalog_load(path,&a,err,sizeof err)==0);
        CHECK(d2k_catalog_load(other,&b,err,sizeof err)==0);
        CHECK(a.groups && a.groups->groups_overflow &&
              a.groups->n_observations==(D2K_GROUP_MAX+1)*3);
        CHECK(b.groups && !b.groups->groups_overflow && b.groups->n_observations==3);
        CHECK(a.groups && !d2k_group_match(a.groups,"new.f64.com",key,&match));
        CHECK(b.groups && !d2k_group_match(b.groups,"new.f64.com",key,&match));
        d2k_catalog_free(&a); d2k_catalog_free(&b);
        sp->enabled=pp->enabled=1;
        saturated.boxes[0].n_plans=plain.boxes[0].n_plans=1;
        strcpy(sp->proto,"tls"); strcpy(pp->proto,"tls");
    }
    d2k_catalog_free(&saturated); d2k_catalog_free(&plain);
    unlink(other);
}

int main(void) {
    char path[]="/tmp/d2k-groups-catalog-XXXXXX",err[256];
    int fd=mkstemp(path); CHECK(fd>=0); if(fd<0) return 1; close(fd);
    d2k_catalog a={0},b={0};
    a.groups=calloc(1,sizeof *a.groups);
    CHECK(a.groups!=NULL); if(!a.groups) { unlink(path); return 1; }
    a.boxes=calloc(1,sizeof *a.boxes); a.n_boxes=1;
    CHECK(a.boxes!=NULL); if(!a.boxes) { d2k_catalog_free(&a); unlink(path); return 1; }
    strcpy(a.boxes[0].id,"box-test");
    a.boxes[0].plans=calloc(1,sizeof *a.boxes[0].plans); a.boxes[0].n_plans=1;
    CHECK(a.boxes[0].plans!=NULL); if(!a.boxes[0].plans) { a.boxes[0].n_plans=0; d2k_catalog_free(&a); unlink(path); return 1; }
    strcpy(a.boxes[0].plans[0].id,"plan-test");
    strcpy(a.boxes[0].plans[0].proto,"tls");
    a.boxes[0].plans[0].text=strdup("opaque-test-plan");
    a.boxes[0].plans[0].enabled=1;
    d2k_group_key key={6,4,1,"",""};
    /* §3.7: five voters, so the two exceptions below (rr0 failed, rr1
       clear) stay a minority and the family legitimately survives. */
    for(int i=0;i<5;i++) {
        d2k_group_observation o={0};
        snprintf(o.name,sizeof o.name,"rr%d.googlevideo.com",i);
        strcpy(o.plan_id,"plan-test"); o.key=key; o.evidence=1; o.at=123;
        CHECK(d2k_group_learn(a.groups,&o)==1);
    }
    d2k_group_observation o=a.groups->observations[0]; o.evidence=4; o.at=124;
    CHECK(d2k_group_learn(a.groups,&o)==1);
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->n_observations==5 && b.groups->n_groups==1);
    CHECK(b.groups && d2k_group_match(b.groups,"new.googlevideo.com",&key,&match));
    CHECK(b.groups && !d2k_group_match(b.groups,"rr0.googlevideo.com",&key,&match));
    CHECK(b.n_boxes==1 && b.boxes[0].n_plans==1);
    d2k_catalog_free(&b);
    memset(&o,0,sizeof o); strcpy(o.name,"clean.googlevideo.com");
    o.key=key; o.evidence=2; o.at=125;
    CHECK(d2k_group_learn(a.groups,&o)==1);
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && d2k_group_match(b.groups,"new.googlevideo.com",&key,&match));
    CHECK(b.groups && !d2k_group_match(b.groups,"clean.googlevideo.com",&key,&match));
    d2k_catalog_free(&b);
    o=a.groups->observations[1]; o.evidence=2; o.at=126;
    CHECK(d2k_group_learn(a.groups,&o)==1);
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && d2k_group_match(b.groups,"new.googlevideo.com",&key,&match));
    CHECK(b.groups && !d2k_group_match(b.groups,"rr1.googlevideo.com",&key,&match));
    d2k_catalog_free(&b);
    a.groups->frozen=1;
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0 && b.groups && !b.groups->frozen);
    CHECK(b.groups && d2k_group_match(b.groups,"never-seen.googlevideo.com",&key,&match));
    d2k_catalog_free(&b);
    /* §3.7: a third degraded voter makes them the majority → retired,
       also after save/load. */
    memset(&o,0,sizeof o); strcpy(o.name,"rr2.googlevideo.com");
    o.key=key; o.evidence=2; o.at=127;
    CHECK(d2k_group_learn(a.groups,&o)==1);
    CHECK(!d2k_group_match(a.groups,"new.googlevideo.com",&key,&match));
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->n_groups==0 &&
          !d2k_group_match(b.groups,"new.googlevideo.com",&key,&match));
    d2k_catalog_free(&b);
    /* Disabled without a stored moment (older catalogs) loads as 0. */
    a.groups->disabled=1;
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->disabled && b.groups->disabled_at==0);
    d2k_catalog_free(&b);
    a.groups->disabled_at=1700000000;
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->disabled_at==1700000000);
    CHECK(b.groups && b.groups->disabled && b.groups->n_groups==0);
    CHECK(b.n_boxes==1 && b.boxes[0].n_plans==1 && b.boxes[0].plans[0].enabled);
    d2k_catalog_free(&b);
    a.groups->disabled=0;
    a.boxes[0].plans[0].enabled=0;
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && !d2k_group_match(b.groups,"new.googlevideo.com",&key,&match));
    d2k_catalog_free(&a); d2k_catalog_free(&b);
    FILE *f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) { fputs("{\"boxes\":[],\"domain_observations\":[{\"name\":\"a.example.com\",\"evidence\":255}]}",f); fclose(f); }
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)!=0);
    d2k_catalog_free(&b);
    f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) {
        fputs("{\"boxes\":[],\"domain_observations\":[",f);
        for(int i=0;i<=D2K_GROUP_OBSERVATION_MAX;i++) {
            if(i) fputc(',',f);
            fprintf(f,"{\"name\":\"h%d.example.com\",\"transport\":6,\"family\":4,\"shape\":1,\"evidence\":2}",i);
        }
        fputs("]}",f); fclose(f);
    }
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->n_observations==D2K_GROUP_OBSERVATION_MAX+1);
    CHECK(b.groups && b.groups->disk_observations && !b.groups->frozen);
    if(b.groups) {
        b.boxes=calloc(1,sizeof *b.boxes);CHECK(b.boxes!=NULL);
        if(!b.boxes)return 1;
        b.n_boxes=1;strcpy(b.boxes[0].id,"retained-plan");
        b.boxes[0].plans=calloc(1,sizeof *b.boxes[0].plans);
        CHECK(b.boxes[0].plans!=NULL);if(!b.boxes[0].plans)return 1;
        b.boxes[0].n_plans=1;
        strcpy(b.boxes[0].plans[0].id,"plan-test");
        strcpy(b.boxes[0].plans[0].proto,"tls");
        b.boxes[0].plans[0].enabled=1;
        b.boxes[0].plans[0].text=strdup("opaque-test-plan");
        d2k_group_observation fresh={0};
        fresh.key=key;fresh.evidence=D2K_GROUP_BLOCKED_CONFIRMED;fresh.at=200;
        strcpy(fresh.plan_id,"plan-test");
        for(int i=0;i<3;i++) {
            snprintf(fresh.name,sizeof fresh.name,"fresh%d.googlevideo.com",i);
            CHECK(d2k_group_learn(b.groups,&fresh)>0);
        }
        CHECK(d2k_group_match(b.groups,"another.googlevideo.com",&key,&match)!=NULL);
        CHECK(d2k_catalog_save(&b,path,err,sizeof err)==0);
        d2k_catalog again={0};
        CHECK(d2k_catalog_load(path,&again,err,sizeof err)==0);
        CHECK(again.groups && again.groups->n_observations==D2K_GROUP_OBSERVATION_MAX+4);
        CHECK(again.groups && !again.groups->frozen);
        CHECK(again.groups && d2k_group_match(again.groups,"another.googlevideo.com",&key,&match)!=NULL);
        d2k_catalog_free(&again);
    }
    d2k_catalog_free(&b);
    f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) { fputs("{\"boxes\":[],\"domain_groups\":[{\"suffix\":\"google.com\",\"plan_id\":\"forged\"}]}",f); fclose(f); }
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0 && !b.groups);
    d2k_catalog_free(&b); /* derived snapshot cannot create an executable rule */
    f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) { fputs("{\"boxes\":[]}",f); fclose(f); }
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0 && !b.groups);
    d2k_catalog_free(&b);
    growth_tests(path,&key);
    availability_tests(path,&key);
    /* More confirmed families than the derived hot cache: the file-backed
       observations, including the family absent from the cache, survive
       repeated close/reopen without being truncated to the cached groups. */
    {
        enum { FAMILIES=D2K_GROUP_MAX+1, VOTES_PER_FAMILY=3 };
        d2k_catalog c={0},d={0},e={0};
        c.groups=calloc(1,sizeof *c.groups);
        CHECK(c.groups && with_plan(&c)==0);
        if(c.groups && c.boxes && c.boxes[0].plans) {
            CHECK(d2k_group_store_open(c.groups,path)==0);
            for(int family=0;family<FAMILIES;family++)
                for(int member=0;member<VOTES_PER_FAMILY;member++) {
                    char name[256];
                    snprintf(name,sizeof name,"v%d.f%02d.com",member,family);
                    d2k_group_observation o=vote(name,0,D2K_GROUP_BLOCKED_CONFIRMED,
                                                 1000+family*VOTES_PER_FAMILY+member,&key);
                    CHECK(d2k_group_learn(c.groups,&o)==1);
                }
            CHECK(c.groups->n_groups==D2K_GROUP_MAX && c.groups->groups_overflow &&
                  !c.groups->frozen);
            CHECK(c.groups->n_observations==FAMILIES*VOTES_PER_FAMILY);
            CHECK(d2k_group_match(c.groups,"v2.f64.com",&key,&match)!=NULL);
            CHECK(d2k_catalog_save(&c,path,err,sizeof err)==0);
        }
        d2k_catalog_free(&c);
        CHECK(d2k_catalog_load(path,&d,err,sizeof err)==0);
        CHECK(d.groups && d.groups->n_groups==D2K_GROUP_MAX &&
              d.groups->n_observations==FAMILIES*VOTES_PER_FAMILY);
        CHECK(d.groups && row_named(d.groups,"v2.f64.com"));
        CHECK(d.groups && d2k_group_match(d.groups,"v2.f64.com",&key,&match)!=NULL);
        CHECK(d2k_catalog_save(&d,path,err,sizeof err)==0);
        d2k_catalog_free(&d);
        CHECK(d2k_catalog_load(path,&e,err,sizeof err)==0);
        CHECK(e.groups && e.groups->n_observations==FAMILIES*VOTES_PER_FAMILY &&
              row_named(e.groups,"v2.f64.com"));
        CHECK(e.groups && d2k_group_match(e.groups,"v2.f64.com",&key,&match)!=NULL);
        if(e.groups) {
            const d2k_domain_group *cold=d2k_group_match(e.groups,"new.f64.com",&key,&match);
            CHECK(cold && !strcmp(cold->suffix,"f64.com") &&
                  !strcmp(cold->plan_id,"plan-test") && cold->evidence_count==3);
            d2k_group_key wrong=key;
            wrong.family=6;
            CHECK(!d2k_group_match(e.groups,"new.f64.com",&wrong,&match));
            wrong=key; wrong.shape=2;
            CHECK(!d2k_group_match(e.groups,"new.f64.com",&wrong,&match));
            wrong=key; wrong.transport=17; wrong.shape=3;
            CHECK(!d2k_group_match(e.groups,"new.f64.com",&wrong,&match));
            wrong=key; strcpy(wrong.probe_path,"/other.css");
            CHECK(!d2k_group_match(e.groups,"new.f64.com",&wrong,&match));
            wrong=key; wrong.shape=6; strcpy(wrong.ech_origin,"origin.example.com");
            CHECK(!d2k_group_match(e.groups,"new.f64.com",&wrong,&match));
            /* cover() must see the cold family while learning a direct-clear
               exception: siblings retain their plan, this member does not. */
            d2k_group_observation o=vote("clean.f64.com",0,D2K_GROUP_DIRECT_CLEAR,5000,&key);
            CHECK(d2k_group_learn(e.groups,&o)==1);
            const d2k_group_observation *clean=row_named(e.groups,"clean.f64.com");
            CHECK(clean && (clean->evidence&D2K_GROUP_ADMITTED_EXCEPTION));
            CHECK(!d2k_group_match(e.groups,"clean.f64.com",&key,&match) &&
                  d2k_group_match(e.groups,"v2.f64.com",&key,&match));
            o=vote("bad.f64.com",0,D2K_GROUP_PLAN_FAILED,5001,&key);
            CHECK(d2k_group_learn(e.groups,&o)==1);
            CHECK(!d2k_group_match(e.groups,"bad.f64.com",&key,&match) &&
                  d2k_group_match(e.groups,"v2.f64.com",&key,&match));
            for(int member=0;member<VOTES_PER_FAMILY;member++) {
                char name[256]; snprintf(name,sizeof name,"v%d.f65.com",member);
                o=vote(name,0,D2K_GROUP_BLOCKED_CONFIRMED,6000+member,&key);
                CHECK(d2k_group_learn(e.groups,&o)==1);
            }
            CHECK(e.groups->n_observations==FAMILIES*VOTES_PER_FAMILY+5 &&
                  d2k_group_match(e.groups,"new.f65.com",&key,&match));
            CHECK(d2k_catalog_save(&e,path,err,sizeof err)==0);
        }
        d2k_catalog_free(&e);
        CHECK(d2k_catalog_load(path,&d,err,sizeof err)==0);
        CHECK(d.groups && d.groups->n_observations==FAMILIES*VOTES_PER_FAMILY+5 &&
              !d2k_group_match(d.groups,"clean.f64.com",&key,&match) &&
              !d2k_group_match(d.groups,"bad.f64.com",&key,&match) &&
              d2k_group_match(d.groups,"v2.f64.com",&key,&match) &&
              d2k_group_match(d.groups,"new.f65.com",&key,&match));
        d2k_catalog_free(&d);
    }
    unlink(path);
    if(!failed) puts("group catalog: passed");
    return failed?1:0;
}
