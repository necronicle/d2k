#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2k_newchain.h"
#include "d2k_plantlv.h"
#include "d2k_ctl.h"
#include "d2k_hello.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>
static void note(d2k_newchain_log log,void *ctx,const char *action,const d2k_newchain_value *v,const char *why) {
    char text[768];snprintf(text,sizeof text,"NEWCHAIN: %s %s TLS%s IPv%u K%u B%u: %s",action,
        v?v->name:"store",v&&v->shape==D2K_SHAPE_LEGACY?"1.2":"1.3",v?v->family:0,
        v?v->knowledge:0,v?v->box:0,why);if(log)log(ctx,text);
}
int d2k_newchain_set(d2k_newchain *n,const char *path) {
    if(!n || (path && strlen(path)>=sizeof n->path))return -1;
    free(n->pending_hex);free(n->cached);memset(n,0,sizeof *n);snprintf(n->path,sizeof n->path,"%s",path?path:"");return 0;
}
static int key(const d2k_newchain_value *a,const d2k_newchain_value *b) {
    return a->family==b->family && a->shape==b->shape && !strcasecmp(a->name,b->name);
}
int d2k_newchain_protects(const d2k_newchain *n,const char *name,uint8_t tr,uint8_t family,uint8_t shape) {
    if(!n || tr!=6 || !name)return 0;
    for(size_t i=0;i<n->count;i++) {
        const d2k_newchain_entry *e=&n->entries[i];
        const d2k_newchain_value *v=e->active.name[0]?&e->active:&e->desired;
        if((e->active.name[0] || e->pending) && !strcasecmp(v->name,name) && v->family==family &&
           (!shape || shape==D2K_LINK_SHAPE_GRANDFATHER || v->shape==shape))return 1;
    }
    return 0;
}
size_t d2k_newchain_count(const d2k_newchain *n) {
    size_t count=0;for(size_t i=0;i<n->count;i++)count+=n->entries[i].active.name[0]!=0;return count;
}
static int token(uint8_t out[16]) {
    int fd=open("/dev/urandom",O_RDONLY);if(fd<0)return -1;
    ssize_t count=read(fd,out,16);close(fd);return count==16?0:-1;
}
static void value(d2k_newchain_value *v,const d2km_knowledge *k) {
    memset(v,0,sizeof *v);strcpy(v->name,k->context.target.name);
    v->knowledge=k->id;v->box=k->box;v->hash=k->hash;v->last_success=k->last_success_ms;v->authority=k->last_success_ms;
    for(size_t i=0;i<k->history_count;i++)
        if(k->history[i].previous_hash==k->hash && k->history[i].time_ms>v->authority)v->authority=k->history[i].time_ms;
    v->family=(uint8_t)k->context.family;v->shape=k->context.protocol==D2KM_P_TLS12?D2K_SHAPE_LEGACY:k->context.form.ech?D2K_LINK_SHAPE_ECH_TCP:D2K_SHAPE_MODERN;
    /* Source is the persisted provenance, never inferred from K/B or hash.
       remember() appends a knowledge reason; revalidation retains that archive. */
    strcpy(v->source,"unknown");
    for(const char *p=k->why;(p=strstr(p,"\"reason\""));p++) {
        const char *end=strchr(p,'\n');size_t len=end?(size_t)(end-p):strlen(p);
        const char *own=strstr(p,"своё знание"),*questions=strstr(p,"вопросы");
        if(own && (size_t)(own-p)<len)strcpy(v->source,"own");
        if(questions && (size_t)(questions-p)<len)strcpy(v->source,"questions");
    }
    for(unsigned i=0;i<8;i++) {v->plan_id[i]=(uint8_t)(k->hash>>(56-8*i));v->plan_id[8+i]=(uint8_t)((~k->hash)>>(56-8*i));}
}
int d2k_newchain_poll(d2k_newchain *n,int fd,int64_t now,d2k_newchain_log log,void *ctx) {
    if(!n || !n->path[0])return 0;
    /* Five seconds bounds stat/load CPU and control writes on small routers.
       This is store observation pacing, never a search/measurement budget. */
    int due=!n->polled || now<n->last_poll || now-n->last_poll>=5000;
    if(!due && !n->reconcile)return 0;
    n->reconcile=0;
    if(due) {n->polled=1;n->last_poll=now;}
    /* Exactly one unacknowledged SET; retries keep its bytes even when
       the source disappears. ACK progression never bypasses IO pacing. */
    for(size_t i=0;i<n->count;i++)if(n->entries[i].pending) {
        if(!due)return 0;
        d2k_newchain_entry *e=&n->entries[i];char err[256];uint8_t id[16];
        if(e->pending==D2K_CMD_DEL_NAME_BOUND)
            return d2k_link_fence(fd,e->token,err,sizeof err)?-1:1;
        if(!n->pending_hex || token(id) || d2k_link_set_name_bound(fd,e->desired.name,6,n->pending_hex,
            e->desired.shape,e->desired.family,id,err,sizeof err))return -1;
        memcpy(e->token,id,16);return 1;
    }
    d2km_store *store=n->cached;int fresh=0;struct stat st={0};long ns=0;
    if(due) {
        if(stat(n->path,&st)) {note(log,ctx,"load",NULL,"store unavailable; previous bindings retained");return -1;}
#ifdef __APPLE__
        ns=st.st_mtimespec.tv_nsec;
#else
        ns=st.st_mtim.tv_nsec;
#endif
        if(!n->loaded || n->mtime!=st.st_mtime || n->mtime_ns!=ns || n->size!=st.st_size) {
            store=calloc(1,sizeof *store);if(!store)return -1;
            d2km_store_error error={0};
            if(d2km_store_load(n->path,store,&error)!=D2KM_STORE_OK) {
                note(log,ctx,"load",NULL,error.reason);free(store);return -1;
            }
            fresh=1;
        }
    }
    if(!store)return 0;
    d2k_newchain_value wanted[D2KM_STORE_KNOWLEDGE_MAX];const d2km_knowledge *program[D2KM_STORE_KNOWLEDGE_MAX];size_t count=0;
    for(size_t i=0;i<store->knowledge.count;i++) {
        const d2km_knowledge *k=&store->knowledge.entries[i];
        if(n->allow_knowledge && !n->allow_knowledge(n->allow_ctx,k))continue;
        if(k->binding!=D2KM_BIND_NAME || !k->context.target.has_name || k->context.transport!=D2KM_TCP ||
           (k->context.protocol!=D2KM_P_TLS12 && k->context.protocol!=D2KM_P_TLS13))continue;
        d2km_target normalized;
        if(d2km_target_name(&normalized,k->context.target.name) || strcmp(normalized.name,k->context.target.name)) {
            note(log,ctx,"load",NULL,"invalid or noncanonical knowledge name; previous bindings retained");
            if(fresh)free(store);
            return -1;
        }
        d2k_newchain_value v;value(&v,k);size_t j=0;for(;j<count;j++)if(key(&wanted[j],&v))break;
        if(j<count) {
            /* Retirement is an authoritative result for the wire key too.
               Never remove it before ranking and resurrect older knowledge. */
            if(wanted[j].authority>v.authority)continue;
            if(wanted[j].authority==v.authority) {
                int was_active=d2km_knowledge_active(program[j]),is_active=d2km_knowledge_active(k);
                if((!was_active && is_active) || (was_active==is_active && wanted[j].knowledge>v.knowledge))continue;
            }
        }
        if(j==count)count++;
        wanted[j]=v;program[j]=k;
    }
    size_t active=0;
    for(size_t i=0;i<count;i++)if(d2km_knowledge_active(program[i])) {
        wanted[active]=wanted[i];program[active++]=program[i];
    }
    count=active;
    if(fresh) {free(n->cached);n->cached=store;n->loaded=1;n->mtime=st.st_mtime;n->mtime_ns=ns;n->size=st.st_size;}
    int sent=0,failed=0;
    for(size_t j=0;j<count;j++) {
        size_t i=0;for(;i<n->count;i++) {
            d2k_newchain_entry *e=&n->entries[i];
            if(key(e->active.name[0]?&e->active:&e->desired,&wanted[j]))break;
        }
        if(i==n->count) {
            for(i=0;i<n->count;i++)if(!n->entries[i].active.name[0] && !n->entries[i].pending)break;
            if(i==n->count) {if(n->count==D2KM_STORE_KNOWLEDGE_MAX){failed=1;continue;}n->count++;}
        }
        d2k_newchain_entry *e=&n->entries[i];
        if(e->active.name[0] && e->active.hash==wanted[j].hash && !e->pending) {e->active=wanted[j];continue;}
        /* Pending ownership blocks old writers, but is never reported active.
           On loss, repeat correlated SET; old binding remains until atomic SET. */
        if(sent)continue;
        char text[32768],hex[2*D2K_PLAN_TLV_MAX+1],err[256];uint8_t id[16];
        if(!d2km_program_text(&program[j]->program,text,sizeof text) ||
           d2k_plan_text_to_hex(text,hex,sizeof hex,err,sizeof err) || token(id)) {
            note(log,ctx,"install failed",&wanted[j],"program conversion failed");failed=1;continue;
        }
        n->pending_hex=strdup(hex);if(!n->pending_hex){failed=1;continue;}
        if(d2k_link_set_name_bound(fd,wanted[j].name,6,hex,wanted[j].shape,wanted[j].family,id,err,sizeof err)) {
            note(log,ctx,"install failed",&wanted[j],"command rejected locally; no ownership acquired");free(n->pending_hex);n->pending_hex=NULL;failed=1;continue;
        }
        e->desired=wanted[j];memcpy(e->token,id,16);e->pending=D2K_CMD_SET_NAME_BOUND;sent++;
    }
    if(sent)return failed?-1:sent; /* do not interleave install ACK with a delete fence */
    int deleting=0;for(size_t i=0;i<n->count;i++)deleting|=n->entries[i].pending==D2K_CMD_DEL_NAME_BOUND;
    for(size_t i=0;i<n->count;i++) {
        d2k_newchain_entry *e=&n->entries[i];size_t j=0;
        const d2k_newchain_value *v=e->active.name[0]?&e->active:&e->desired;
        for(;j<count;j++)if(key(v,&wanted[j]))break;
        if(e->pending==D2K_CMD_DEL_NAME_BOUND) {
            char err[256];(void)d2k_link_fence(fd,e->token,err,sizeof err);continue;
        }
        if(j<count || !e->active.name[0] || deleting || e->pending)continue;
        char err[256];if(token(e->token) || d2k_link_del_name_bound(fd,e->active.name,6,&e->binding,err,sizeof err)) {failed=1;continue;}
        e->pending=D2K_CMD_DEL_NAME_BOUND;deleting=1;sent++;
        /* The query ACK is a correlated fence on this ordered socket. DEL
           itself has no correlation, and HTTP owns its own deletes. */
        (void)d2k_link_fence(fd,e->token,err,sizeof err);
    }
    return failed?-1:sent;
}
int d2k_newchain_event(d2k_newchain *n,const d2k_ev *ev,d2k_newchain_log log,void *ctx) {
    if(!n || ev->kind!=D2K_EV_ACK)return 0;
    for(size_t i=0;i<n->count;i++) {
        d2k_newchain_entry *e=&n->entries[i];
        if(!e->pending)continue;
        if(e->pending==D2K_CMD_DEL_NAME_BOUND) {
            if(ev->code!=D2K_CMD_ARM_SHAPE || memcmp(ev->trial_id,e->token,16))continue;
        } else if(ev->code!=e->pending)continue;
        if(ev->code==D2K_CMD_SET_NAME_BOUND) {
            if(memcmp(ev->trial_id,e->token,16))continue;
            free(n->pending_hex);n->pending_hex=NULL;
            const d2k_binding_context *b=&ev->execution_binding;
            if(((ev->num>>8)&255u)==1 && d2k_binding_known(b) && b->kind==D2K_BIND_NAME && !b->temporary &&
               b->family==e->desired.family && b->shape==e->desired.shape) {
                e->active=e->desired;e->binding=*b;note(log,ctx,"installed",&e->active,"datapath ACK; atomic replacement");
            } else {note(log,ctx,"refused",&e->desired,"datapath rejected SET; previous binding retained");n->reconcile=0;}
        } else {
            /* Correlated ARM_SHAPE ACK proves the preceding conditional
               delete was processed; unrelated command ACKs cannot release it. */
            if(((ev->num>>8)&255u)!=0 || (ev->num&255u)!=D2K_ACK_BAD_ARGS) {note(log,ctx,"remove refused",&e->active,"conditional delete not acknowledged");n->reconcile=0;}
            else {note(log,ctx,"removed",&e->active,"knowledge removed or DEGRADED; conditional generation delete processed (correlated fence)");memset(&e->active,0,sizeof e->active);}
        }
        e->pending=0;n->reconcile=((ev->num>>8)&255u)==1 || ev->code==D2K_CMD_ARM_SHAPE;return 1;
    }
    return 0;
}
int d2k_newchain_signal(const d2k_newchain *n,const char *name,const d2k_ev *ev,d2k_shadow_record *r) {
    if(!n || !name || ev->planned!=D2K_LINK_PLANNED_YES)return 0;
    for(size_t i=0;i<n->count;i++) {
        const d2k_newchain_entry *e=&n->entries[i];const d2k_newchain_value *v=&e->active;
        if(!v->name[0] || strcmp(v->name,name) || ev->transport!=6 || ev->family!=v->family ||
           !d2k_binding_equal(&e->binding,&ev->execution_binding) || memcmp(v->plan_id,ev->plan_id,16))continue;
        r->degradation=1;r->knowledge=v->knowledge;r->program_hash=v->hash;r->protocol=v->shape==D2K_SHAPE_LEGACY?1:2;
        r->binding=e->binding;return 1;
    }
    return 0;
}
void d2k_newchain_json(const d2k_newchain *n,FILE *f) {
    fprintf(f,"\"newchain_count\": %zu, \"newchain_bindings\": [",d2k_newchain_count(n));size_t count=0;
    for(size_t i=0;i<n->count;i++) {
        const d2k_newchain_value *v=&n->entries[i].active;if(!v->name[0])continue;
        fprintf(f,"%s{\"name\":\"%s\",\"source\":\"%s\",\"knowledge\":%u,\"box\":%u,\"family\":%u,\"protocol\":\"TLS%s\",\"last_success_ms\":%" PRIu64 "}",
            count++?",":"",v->name,v->source,v->knowledge,v->box,v->family,v->shape==D2K_SHAPE_LEGACY?"1.2":"1.3",v->last_success);
    }
    fputs("]",f);
}
