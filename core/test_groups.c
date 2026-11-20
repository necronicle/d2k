#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/d2k_groups.h"
static int failed;
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"groups:%d: %s\n",__LINE__,#c); failed++; } } while(0)
static d2k_group_key modern={6,4,1,"",""};
static void observe(d2k_group_state *s, const char *name, const char *plan,
                    unsigned evidence, d2k_group_key key) {
    d2k_group_observation o={0};
    snprintf(o.name,sizeof o.name,"%s",name);
    snprintf(o.plan_id,sizeof o.plan_id,"%s",plan);
    o.evidence=evidence; o.key=key; o.at=100;
    CHECK(d2k_group_learn(s,&o)>=0);
}
/* Full, frozen, enabled journal: every entry a plain vote of plan Q at `at`
   (names p<i>.fill<i>.example.net, one family each, never 3 votes). */
static void full_plain(d2k_group_state *s,int64_t at) {
    memset(s,0,sizeof *s);
    for(size_t i=0;i<D2K_GROUP_OBSERVATION_MAX;i++) {
        d2k_group_observation *o=&s->observations[i];
        snprintf(o->name,sizeof o->name,"p%zu.fill%zu.example.net",i,i);
        strcpy(o->plan_id,"Q"); o->key=modern; o->at=at;
        o->evidence=D2K_GROUP_BLOCKED_CONFIRMED;
    }
    s->n_observations=D2K_GROUP_OBSERVATION_MAX; s->frozen=1;
}
static int present(const d2k_group_state *s,const char *name) {
    for(size_t i=0;i<s->n_observations;i++)
        if(!strcmp(s->observations[i].name,name)) return 1;
    return 0;
}
static int clean_at(d2k_group_state *s,const char *name,int64_t at) {
    d2k_group_observation o={0};
    snprintf(o.name,sizeof o.name,"%s",name);
    o.key=modern; o.evidence=D2K_GROUP_DIRECT_CLEAR; o.at=at;
    return d2k_group_learn(s,&o);
}
int main(void) {
    d2k_domain_group match;
    d2k_group_key long_key;
    char path_a[512],path_b[512];
    memset(path_a,'a',sizeof path_a); path_a[0]='/'; path_a[300]=0;
    memcpy(path_b,path_a,sizeof path_b); path_b[299]='b';
    CHECK(d2k_group_key_make(&long_key,6,4,1,path_a,"")==-1);
    CHECK(d2k_group_key_make(&long_key,6,4,1,path_b,"")==-1);
    CHECK(d2k_group_key_make(&long_key,6,4,1,"/public/site.css","")==0 &&
          !strcmp(long_key.probe_path,"/public/site.css"));
    d2k_group_state *s=calloc(1,sizeof *s);
    CHECK(s!=NULL); if(!s) return 1;
    /* Counting requests rather than independent host evidence must fail. */
    for(int i=0;i<5;i++) observe(s,"meet.google.com","plan-a",1,modern);
    CHECK(s->n_groups==0 && s->n_observations==1);
    observe(s,"rr1.googlevideo.com","plan-a",1,modern);
    observe(s,"rr2.googlevideo.com","plan-a",1,modern);
    CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    observe(s,"rr3.googlevideo.com","plan-a",1,modern);
    const d2k_domain_group *g=d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match);
    CHECK(g && !strcmp(g->suffix,"googlevideo.com") && !strcmp(g->plan_id,"plan-a"));
    CHECK(!d2k_group_match(s,"evilgooglevideo.com",&modern,&match));
    CHECK(!d2k_group_match(s,"google.com",&modern,&match));
    {
        /* Поле 06.10: узел семейства, на котором не помог ни общий план, ни
           собственный поиск, — недоступен. Его отказы выкидываются целиком:
           домен снова под общим планом, голосов против плана нет. */
        d2k_group_state *d=calloc(1,sizeof *d);
        CHECK(d!=NULL);
        if(d) {
            observe(d,"rr1.googlevideo.com","plan-a",1,modern);
            observe(d,"rr2.googlevideo.com","plan-a",1,modern);
            observe(d,"rr3.googlevideo.com","plan-a",1,modern);
            observe(d,"rr4.googlevideo.com","plan-a",D2K_GROUP_PLAN_FAILED,modern);
            observe(d,"rr4.googlevideo.com","plan-b",D2K_GROUP_PLAN_FAILED,modern);
            CHECK(!d2k_group_match(d,"rr4.googlevideo.com",&modern,&match));
            d2k_group_key quic={17,4,3,"",""};
            observe(d,"rr4.googlevideo.com","plan-q",D2K_GROUP_PLAN_FAILED,quic);
            CHECK(d2k_group_forget(d,"rr4.googlevideo.com",6,4)==2);
            CHECK(!present(d,"rr4.googlevideo.com") || d->n_observations==4);
            const d2k_domain_group *dg=d2k_group_match(d,"rr4.googlevideo.com",&modern,&match);
            CHECK(dg && !strcmp(dg->plan_id,"plan-a"));
            CHECK(present(d,"rr1.googlevideo.com"));
            CHECK(d2k_group_forget(d,"rr4.googlevideo.com",6,4)==0);
            CHECK(d2k_group_forget(d,"rr1.googlevideo.com",6,4)==0);
            /* Отказ узла, который неделю больше не встречался, уходит сам:
               узлы googlevideo меняются, и на старый может больше не прийти
               никто. Подтверждения не стареют. */
            observe(d,"rr7.googlevideo.com","plan-a",D2K_GROUP_PLAN_FAILED,modern);
            observe(d,"rr8.googlevideo.com","plan-a",D2K_GROUP_PLAN_FAILED,modern);
            for(size_t i=0;i<d->n_observations;i++)
                if(!strcmp(d->observations[i].name,"rr8.googlevideo.com")) d->observations[i].at=100+6*86400;
            CHECK(!d2k_group_match(d,"rr7.googlevideo.com",&modern,&match));
            CHECK(d2k_group_expire(d,100+7*86400,7*86400)==0);
            /* rr7 и оставшийся QUIC-отказ rr4 того же возраста; rr8 моложе. */
            CHECK(d2k_group_expire(d,101+7*86400,7*86400)==2);
            CHECK(!present(d,"rr7.googlevideo.com") && present(d,"rr8.googlevideo.com"));
            CHECK(present(d,"rr1.googlevideo.com"));
            CHECK(d2k_group_match(d,"rr7.googlevideo.com",&modern,&match));
            free(d);
        }
    }
    size_t before=s->n_observations;
    for(int i=0;i<100;i++) CHECK(d2k_group_match(s,"a.b.new.googlevideo.com",&modern,&match));
    CHECK(s->n_observations==before); /* Lookup does not enrol every CDN name. */
    d2k_group_key other=modern;
    other.family=6; CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&other,&match));
    other=modern; other.shape=2; CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&other,&match));
    other=modern; other.transport=17; other.shape=3;
    CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&other,&match));
    other=modern; strcpy(other.probe_path,"/large.css");
    CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&other,&match));
    other=modern; strcpy(other.ech_origin,"origin.example.com"); other.shape=6;
    CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&other,&match));
    observe(s,"rr1.googlevideo.com","plan-a",8,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    observe(s,"rr1.googlevideo.com","plan-a",4,modern);
    CHECK(!d2k_group_match(s,"rr1.googlevideo.com",&modern,&match));
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    /* A clean sibling prevents broadening, but allows the nested CDN branch. */
    observe(s,"www.example.com","",2,modern);
    observe(s,"a.cdn.example.com","plan-b",1,modern);
    observe(s,"b.cdn.example.com","plan-b",1,modern);
    observe(s,"c.cdn.example.com","plan-b",1,modern);
    g=d2k_group_match(s,"new.cdn.example.com",&modern,&match);
    CHECK(g && !strcmp(g->suffix,"cdn.example.com"));
    CHECK(!d2k_group_match(s,"api.example.com",&modern,&match));
    CHECK(!d2k_group_match(s,"www.example.com",&modern,&match));
    /* Independent hosting tenants must never collapse at github.io. */
    observe(s,"a.github.io","plan-c",1,modern);
    observe(s,"b.github.io","plan-c",1,modern);
    observe(s,"c.github.io","plan-c",1,modern);
    CHECK(!d2k_group_match(s,"new.github.io",&modern,&match));
    /* A different successful plan is not a vote for the elected candidate. */
    observe(s,"a.mixed.net","plan-a",1,modern);
    observe(s,"b.mixed.net","plan-b",1,modern);
    observe(s,"c.mixed.net","plan-c",1,modern);
    CHECK(!d2k_group_match(s,"new.mixed.net",&modern,&match));
    /* A measured failure must outweigh a one-vote popularity advantage. */
    observe(s,"a.recovery.net","plan-a",1,modern);
    observe(s,"b.recovery.net","plan-a",1,modern);
    observe(s,"c.recovery.net","plan-a",1,modern);
    observe(s,"d.recovery.net","plan-a",1,modern);
    observe(s,"e.recovery.net","plan-b",1,modern);
    observe(s,"f.recovery.net","plan-b",1,modern);
    observe(s,"g.recovery.net","plan-b",1,modern);
    g=d2k_group_match(s,"new.recovery.net",&modern,&match);
    CHECK(g && !strcmp(g->plan_id,"plan-a"));
    observe(s,"failed.recovery.net","plan-a",4,modern);
    g=d2k_group_match(s,"new.recovery.net",&modern,&match);
    CHECK(g && !strcmp(g->plan_id,"plan-b"));
    CHECK(d2k_group_restore(s)==0);
    g=d2k_group_match(s,"new.recovery.net",&modern,&match);
    CHECK(g && !strcmp(g->plan_id,"plan-b"));
    observe(s,"failed.recovery.net","plan-b",4,modern);
    unsigned failed_plans=0;
    for(size_t i=0;i<s->n_observations;i++)
        if(!strcmp(s->observations[i].name,"failed.recovery.net") &&
           (s->observations[i].evidence&D2K_GROUP_PLAN_FAILED)) failed_plans++;
    CHECK(failed_plans==2);
    CHECK(d2k_group_restore(s)==0);
    observe(s,"failed.recovery.net","plan-b",1,modern);
    CHECK(d2k_group_restore(s)==0);
    observe(s,"failed.recovery.net","plan-a",1,modern);
    CHECK(d2k_group_restore(s)==0);
    /* A proven clean member becomes an exception, not a family-wide outage. */
    observe(s,"clean.googlevideo.com","",2,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    CHECK(!d2k_group_match(s,"clean.googlevideo.com",&modern,&match));
    observe(s,"clean.googlevideo.com","",2,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    observe(s,"clean.googlevideo.com","plan-a",1,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    d2k_group_observation invalid={0};
    strcpy(invalid.name,"a.example.com"); invalid.key=modern;
    invalid.evidence=1;
    CHECK(d2k_group_learn(s,&invalid)==-1); /* no authenticated plan */
    strcpy(invalid.plan_id,"plan-a");
    invalid.key.shape=255;
    CHECK(d2k_group_learn(s,&invalid)==-1);
    invalid.key=modern; invalid.key.transport=17;
    CHECK(d2k_group_learn(s,&invalid)==-1);
    invalid.key=modern;
    memset(invalid.name,'x',sizeof invalid.name);
    CHECK(d2k_group_learn(s,&invalid)==-1); /* no NUL */
    /* §3.7: an exception keeps the family only while live voters outnumber
       degraded ones; rr1 already failed, rr2/rr3 turn clear below. */
    observe(s,"rr4.googlevideo.com","plan-a",1,modern);
    observe(s,"rr5.googlevideo.com","plan-a",1,modern);
    observe(s,"rr6.googlevideo.com","plan-a",1,modern);
    for(int i=0;s->n_observations<D2K_GROUP_OBSERVATION_MAX;i++) {
        char name[256]; snprintf(name,sizeof name,"h%d.fill.example.net",i);
        observe(s,name,"plan-z",8,modern);
    }
    observe(s,"overflow.example.net","plan-z",1,modern);
    CHECK(s->frozen && s->n_observations==D2K_GROUP_OBSERVATION_MAX);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    CHECK(!d2k_group_match(s,"unknown.fill.example.net",&modern,&match));
    observe(s,"overflow-clean.googlevideo.com","",2,modern);
    CHECK(!d2k_group_match(s,"overflow-clean.googlevideo.com",&modern,&match));
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    CHECK(s->n_observations==D2K_GROUP_OBSERVATION_MAX);
    observe(s,"rr2.googlevideo.com","",2,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    CHECK(!d2k_group_match(s,"rr2.googlevideo.com",&modern,&match));
    observe(s,"rr3.googlevideo.com","",2,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    /* §3.7: once degraded voters are the majority, return to the direct path. */
    observe(s,"rr4.googlevideo.com","",2,modern);
    CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&modern,&match));
    /* A full budget of exceptions can still contain historic positive votes.
       Never keep an area active when a new exclusion cannot be retained. */
    memset(s,0,sizeof *s);
    for(int i=0;i<3;i++) {
        char name[256]; snprintf(name,sizeof name,"h%d.googlevideo.com",i);
        observe(s,name,"plan-a",1,modern);
    }
    for(int i=0;i<3;i++) {
        char name[256]; snprintf(name,sizeof name,"h%d.googlevideo.com",i);
        observe(s,name,"plan-a",4,modern);
    }
    for(int i=3;i<D2K_GROUP_OBSERVATION_MAX;i++) {
        char name[256]; snprintf(name,sizeof name,"clean%d.example.net",i);
        observe(s,name,"",2,modern);
    }
    /* §3.7: деградация всех голосующих → не наследуем непроверенный план. */
    CHECK(!d2k_group_match(s,"new.googlevideo.com",&modern,&match));
    observe(s,"unrecordable.googlevideo.com","",2,modern);
    CHECK(s->n_groups==0);
    CHECK(!d2k_group_match(s,"new.googlevideo.com",&modern,&match));
    CHECK(d2k_group_restore(s)==0 && s->n_groups==0);
    /* (a) member excluded by plan failure, then directly clear, does not
       disable the family for its siblings. */
    memset(s,0,sizeof *s);
    observe(s,"a.example.com","P",1,modern);
    observe(s,"b.example.com","P",1,modern);
    observe(s,"c.example.com","P",1,modern);
    observe(s,"x.example.com","P",4,modern);
    CHECK(!d2k_group_match(s,"x.example.com",&modern,&match));
    observe(s,"x.example.com","",2,modern);
    CHECK(d2k_group_match(s,"new.example.com",&modern,&match));
    CHECK(!d2k_group_match(s,"x.example.com",&modern,&match));
    /* (b) everything learn writes can be restored. */
    memset(s,0,sizeof *s);
    observe(s,"a.example.com","P",1,modern);
    observe(s,"b.example.com","P",1,modern);
    observe(s,"c.example.com","P",1,modern);
    observe(s,"a.example.com","",2,modern);
    observe(s,"a.example.com","P",4,modern);
    CHECK(d2k_group_restore(s)==0);
    /* все голосующие провалили план → семейства нет */
    memset(s,0,sizeof *s);
    for(int i=0;i<3;i++){char n[64];snprintf(n,sizeof n,"v%d.example.com",i);observe(s,n,"P",1,modern);}
    for(int i=0;i<3;i++){char n[64];snprintf(n,sizeof n,"v%d.example.com",i);observe(s,n,"P",4,modern);}
    CHECK(!d2k_group_match(s,"new.example.com",&modern,&match));
    /* один из трёх провалил → семейство живо (исключение, не отключение) */
    memset(s,0,sizeof *s);
    for(int i=0;i<3;i++){char n[64];snprintf(n,sizeof n,"v%d.example.com",i);observe(s,n,"P",1,modern);}
    observe(s,"v0.example.com","P",4,modern);
    CHECK(d2k_group_match(s,"new.example.com",&modern,&match));
    /* §3.7: два из трёх деградировали (провал + чистый) → семейства нет */
    memset(s,0,sizeof *s);
    for(int i=0;i<3;i++){char n[64];snprintf(n,sizeof n,"v%d.example.com",i);observe(s,n,"P",1,modern);}
    observe(s,"v0.example.com","P",4,modern);
    CHECK(d2k_group_match(s,"new.example.com",&modern,&match));
    observe(s,"v1.example.com","",2,modern);
    CHECK(!d2k_group_match(s,"new.example.com",&modern,&match));
    CHECK(d2k_group_restore(s)==0 && !d2k_group_match(s,"new.example.com",&modern,&match));
    /* все голосующие стали напрямую чистыми → прямой путь */
    memset(s,0,sizeof *s);
    for(int i=0;i<3;i++){char n[64];snprintf(n,sizeof n,"v%d.example.com",i);observe(s,n,"P",1,modern);}
    for(int i=0;i<3;i++){char n[64];snprintf(n,sizeof n,"v%d.example.com",i);observe(s,n,"",2,modern);}
    CHECK(!d2k_group_match(s,"new.example.com",&modern,&match));
    /* старение: журнал из старых голосов (at=0) не должен навсегда
       отключать семейства; новое исключение спустя 31 сутки сохраняется. */
    memset(s,0,sizeof *s);
    for(size_t i=0;i<D2K_GROUP_OBSERVATION_MAX;i++) {
        d2k_group_observation *o=&s->observations[i];
        snprintf(o->name,sizeof o->name,"o%zu.old.example.net",i);
        strcpy(o->plan_id,"Q"); o->key=modern; o->at=0;
        o->evidence=D2K_GROUP_BLOCKED_CONFIRMED|D2K_GROUP_PLAN_FAILED;
    }
    s->n_observations=D2K_GROUP_OBSERVATION_MAX;
    CHECK(d2k_group_restore(s)==0);
    {
        d2k_group_observation o={0};
        o.key=modern; o.at=0;
        strcpy(o.name,"lost.example.com"); o.evidence=2;
        CHECK(d2k_group_learn(s,&o)>0);
        CHECK(s->frozen && s->disabled); /* no room: fail closed */
        CHECK(s->disabled_at==0);
        /* indexes 1 and 2 become old pure votes, index 0 a fresh one */
        strcpy(o.name,"o1.old.example.net"); strcpy(o.plan_id,"Q"); o.evidence=1; o.at=0;
        CHECK(d2k_group_learn(s,&o)>=0);
        strcpy(o.name,"o2.old.example.net");
        CHECK(d2k_group_learn(s,&o)>=0);
        strcpy(o.name,"o0.old.example.net"); o.at=31*86400;
        CHECK(d2k_group_learn(s,&o)>=0);
        strcpy(o.name,"fresh-clean.example.com"); o.plan_id[0]=0; o.evidence=2; o.at=31*86400;
        CHECK(d2k_group_learn(s,&o)>0);
        CHECK(s->disabled==0);
        int kept=0,fresh=0,aged=0;
        for(size_t i=0;i<s->n_observations;i++) {
            const d2k_group_observation *v=&s->observations[i];
            if(!strcmp(v->name,"fresh-clean.example.com") &&
               (v->evidence&D2K_GROUP_DIRECT_CLEAR)) kept=1;
            if(!strcmp(v->name,"o0.old.example.net")) fresh=1;
            if(!strcmp(v->name,"o1.old.example.net")) aged=1;
        }
        CHECK(kept && fresh && !aged);
        /* aging left room: the journal learns positive votes again */
        CHECK(s->n_observations==D2K_GROUP_OBSERVATION_MAX-1 && !s->frozen);
        strcpy(o.name,"after-room.example.org"); strcpy(o.plan_id,"Q"); o.evidence=1;
        CHECK(d2k_group_learn(s,&o)>0 && s->n_observations==D2K_GROUP_OBSERVATION_MAX);
        CHECK(d2k_group_restore(s)==0);
    }
    /* Re-enable after disabling: plain votes from before the lost exclusion
       are dropped; an old family reappears only after 3 fresh votes. */
    memset(s,0,sizeof *s);
    for(size_t i=0;i<D2K_GROUP_OBSERVATION_MAX-1;i++) { /* frozen, one spare */
        d2k_group_observation *o=&s->observations[i];
        if(i<3) {
            snprintf(o->name,sizeof o->name,"v%zu.fam.example.com",i);
            strcpy(o->plan_id,"P"); o->evidence=D2K_GROUP_BLOCKED_CONFIRMED; o->at=50;
        } else {
            snprintf(o->name,sizeof o->name,"x%zu.fill.example.net",i);
            strcpy(o->plan_id,"Q"); o->evidence=D2K_GROUP_BLOCKED_CONFIRMED|D2K_GROUP_PLAN_FAILED;
        }
        o->key=modern;
    }
    s->n_observations=D2K_GROUP_OBSERVATION_MAX-1;
    s->frozen=1; s->disabled=1; s->disabled_at=100;
    CHECK(d2k_group_restore(s)==0 && s->n_groups==0);
    {
        d2k_group_observation o={0};
        o.key=modern; o.at=200; strcpy(o.name,"clean.example.org"); o.evidence=2;
        CHECK(d2k_group_learn(s,&o)>0);
        CHECK(!s->disabled && s->disabled_at==0 && !s->frozen);
        CHECK(!d2k_group_match(s,"new.fam.example.com",&modern,&match));
        strcpy(o.plan_id,"P"); o.evidence=1; o.at=300;
        for(int i=0;i<3;i++) {
            snprintf(o.name,sizeof o.name,"v%d.fam.example.com",i);
            CHECK(d2k_group_learn(s,&o)>0);
            CHECK(!d2k_group_match(s,"new.fam.example.com",&modern,&match)==(i<2));
        }
        CHECK(d2k_group_restore(s)==0 && d2k_group_match(s,"new.fam.example.com",&modern,&match));
    }
    /* Aging on a frozen, NOT disabled journal reclaims exactly one slot,
       the oldest expired plain vote; the journal stays full and frozen. */
    {
        const int64_t T=100*86400;
        full_plain(s,T-40*86400);
        s->observations[7].at=T-50*86400; /* oldest */
        s->observations[0].at=T;          /* fresh, first by index */
        CHECK(d2k_group_restore(s)==0);
        CHECK(clean_at(s,"neg.example.org",T)>0);
        CHECK(!s->disabled && s->frozen && s->n_observations==D2K_GROUP_OBSERVATION_MAX);
        CHECK(present(s,"neg.example.org") && !present(s,"p7.fill7.example.net"));
        CHECK(present(s,"p0.fill0.example.net") && present(s,"p1.fill1.example.net"));
        unsigned plain=0;
        for(size_t i=0;i<s->n_observations;i++)
            if(s->observations[i].evidence==D2K_GROUP_BLOCKED_CONFIRMED) plain++;
        CHECK(plain==D2K_GROUP_OBSERVATION_MAX-1);
        CHECK(!d2k_group_match(s,"neg.example.org",&modern,&match) && d2k_group_restore(s)==0);
    }
    /* INCONCLUSIVE ages before plain votes, oldest first, even when a plain
       vote is older and a fresh unknown entry comes first by index. */
    {
        const int64_t T=100*86400;
        full_plain(s,T-60*86400);
        s->observations[0].evidence=D2K_GROUP_INCONCLUSIVE; s->observations[0].at=T;
        s->observations[0].plan_id[0]=0;
        s->observations[5].evidence=D2K_GROUP_INCONCLUSIVE; s->observations[5].at=T-35*86400;
        s->observations[5].plan_id[0]=0;
        s->observations[9].evidence=D2K_GROUP_INCONCLUSIVE; s->observations[9].at=T-45*86400;
        s->observations[9].plan_id[0]=0;
        CHECK(d2k_group_restore(s)==0);
        CHECK(clean_at(s,"neg.example.org",T)>0);
        CHECK(present(s,"neg.example.org") && !present(s,"p9.fill9.example.net"));
        CHECK(present(s,"p0.fill0.example.net") && present(s,"p5.fill5.example.net"));
        CHECK(s->n_observations==D2K_GROUP_OBSERVATION_MAX && !s->disabled);
    }
    /* Exact boundary: expired means strictly more than 30*86400 s older.
       Entry 0 is a fresh INCONCLUSIVE (the non-aging fallback's choice),
       entry 1 a plain vote at the probed age. */
    {
        const int64_t T=100*86400, ages[]={30*86400-1,30*86400,30*86400+1};
        for(int k=0;k<3;k++) {
            full_plain(s,T);
            s->observations[0].evidence=D2K_GROUP_INCONCLUSIVE; s->observations[0].plan_id[0]=0;
            s->observations[1].at=T-ages[k];
            CHECK(d2k_group_restore(s)==0);
            CHECK(clean_at(s,"neg.example.org",T)>0);
            int aged=!present(s,"p1.fill1.example.net");
            CHECK(aged==(k==2));
            CHECK(present(s,"p0.fill0.example.net")==(k==2));
        }
    }
    /* A stable family with voters older than 30 days survives one reclaim
       when older expired candidates exist; only one entry is reclaimed. */
    {
        const int64_t T=100*86400;
        full_plain(s,T-60*86400);
        for(int i=0;i<3;i++) {
            d2k_group_observation *o=&s->observations[i];
            snprintf(o->name,sizeof o->name,"v%d.fam.example.com",i);
            strcpy(o->plan_id,"P"); o->at=T-40*86400;
        }
        CHECK(d2k_group_restore(s)==0 && d2k_group_match(s,"new.fam.example.com",&modern,&match));
        CHECK(clean_at(s,"neg.example.org",T)>0);
        CHECK(d2k_group_match(s,"new.fam.example.com",&modern,&match));
        CHECK(present(s,"v0.fam.example.com") && present(s,"v1.fam.example.com") &&
              present(s,"v2.fam.example.com"));
        CHECK(s->n_observations==D2K_GROUP_OBSERVATION_MAX);
    }
    /* Cache residency must not change longest-suffix election. The saturated
       journal has 64 unrelated hot families; both nested families are cold. */
    {
        d2k_group_state *plain=calloc(1,sizeof *plain);
        CHECK(plain!=NULL);
        if(!plain) return 1;
        static const char *const broad[]={"a.example.com","b.example.com","c.example.com"};
        static const char *const nested[]={"a.cdn.example.com","b.cdn.example.com","c.cdn.example.com"};
        static const char *const degraded[]={"x.example.com","y.example.com","z.example.com"};
        for(int i=0;i<3;i++) {
            observe(plain,broad[i],"plan-broad",1,modern);
            observe(plain,nested[i],"plan-nested",1,modern);
            observe(plain,degraded[i],"plan-nested",1,modern);
            observe(plain,degraded[i],"plan-nested",D2K_GROUP_PLAN_FAILED,modern);
        }
        d2k_domain_group expected_nested,expected_broad;
        CHECK(d2k_group_match(plain,"new.cdn.example.com",&modern,&expected_nested) &&
              !strcmp(expected_nested.suffix,"cdn.example.com") &&
              d2k_group_match(plain,"new.example.com",&modern,&expected_broad) &&
              !strcmp(expected_broad.suffix,"example.com"));
        memset(s,0,sizeof *s);
        for(int family=0;family<D2K_GROUP_MAX;family++)
            for(int member=0;member<3;member++) {
                char name[256];
                snprintf(name,sizeof name,"v%d.f%02d.com",member,family);
                observe(s,name,"plan-fill",1,modern);
            }
        for(int i=0;i<3;i++) {
            observe(s,broad[i],"plan-broad",1,modern);
            observe(s,nested[i],"plan-nested",1,modern);
            observe(s,degraded[i],"plan-nested",1,modern);
            observe(s,degraded[i],"plan-nested",D2K_GROUP_PLAN_FAILED,modern);
        }
        CHECK(s->n_groups==D2K_GROUP_MAX && s->groups_overflow);
        d2k_domain_group actual_nested,actual_broad;
        const d2k_domain_group *cold_nested=d2k_group_match(s,"new.cdn.example.com",&modern,&actual_nested);
        CHECK(cold_nested && !strcmp(cold_nested->suffix,expected_nested.suffix) &&
              !strcmp(cold_nested->plan_id,"plan-nested") &&
              cold_nested->evidence_count==expected_nested.evidence_count);
        const d2k_domain_group *cold_broad=d2k_group_match(s,"new.example.com",&modern,&actual_broad);
        CHECK(cold_broad && !strcmp(cold_broad->suffix,expected_broad.suffix) &&
              !strcmp(cold_broad->plan_id,"plan-broad") &&
              cold_broad->evidence_count==expected_broad.evidence_count);
        free(plain);
    }
    /* (c) property: random learn chains always pass restore. */
    srand(7);
    for(int round=0;round<2000;round++) {
        memset(s,0,sizeof *s);
        const char *names[]={"a.example.com","b.example.com","c.example.com","d.example.com"};
        const char *plans[]={"P","Q",""};
        static const unsigned ev[]={1,2,4,8};
        for(int k=0;k<12;k++) {
            unsigned e=ev[rand()%4]; const char *p=plans[rand()%3];
            if((e==1||e==4)&&!p[0]) p="P";
            observe(s,names[rand()%4],p,e,modern);
        }
        if(d2k_group_restore(s)!=0) { CHECK(0); break; }
    }
    free(s);
    if(!failed) puts("groups: passed");
    return failed?1:0;
}
