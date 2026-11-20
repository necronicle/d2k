/* Common task assembly and experimental control socket, extracted from d2kexp.
 * No production plan API is used. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "d2k_exp_task.h"
#include "d2k_netarm.h"
#include "d2k_hello.h"
#include "d2k_link.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include "d2k_tls13core.h"
#include "d2km_tls.h"

static size_t load_hex(const char *path, uint8_t *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[8192];
    size_t n = 0;
    while (fgets(line, sizeof line, f)) {
        char *h = strchr(line, '#');
        if (h) *h = 0;
        for (char *c = line; *c; c++) {
            int v = -1;
            if (*c >= '0' && *c <= '9') v = *c - '0';
            else if (*c >= 'a' && *c <= 'f') v = *c - 'a' + 10;
            else if (*c >= 'A' && *c <= 'F') v = *c - 'A' + 10;
            if (v < 0) continue;
            if (n / 2 >= cap) { fclose(f); return 0; }
            if (n % 2 == 0) out[n / 2] = (uint8_t)(v << 4);
            else out[n / 2] |= (uint8_t)v;
            n++;
        }
    }
    fclose(f);
    return n / 2;
}

static long long mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Ждём нужное событие по сроку, а не по числу событий: в сокет опытов идут
   и другие события, и при многих посылках плана их больше, чем любой
   «счётчик на глаз» (поле 11.11: 33 копии — квитанция потерялась). */
static int wait_left(long long deadline)
{
    long long left = deadline - mono_ms();
    return left > 0 ? (int)left : 0;
}

/* Пробный план через сокет опытов датапата (--exp-control). */
typedef struct {
    int fd;
    const char *host;
    uint8_t shape;
    uint8_t family;
    uint8_t trial[16];
} expctl;

static int plan_install_wire(void *c, const char *name, uint16_t lport, const d2km_program *p, uint32_t e,
                        char *err, size_t cap)
{
    expctl *x = c;
    static __thread char text[40000], hex[2 * D2K_PLAN_TLV_MAX + 1];
    if (!d2km_program_text(p, text, sizeof text)) { snprintf(err, cap, "программа не переводится в план"); return -1; }
    if (d2k_plan_text_to_hex(text, hex, sizeof hex, err, cap) != 0) {
        fprintf(stderr, "план не переводится в TLV: %s\n", err);
        return -1;
    }
    if (d2k_t13_random(x->trial, 16) != 0) { snprintf(err, cap, "нет случайности"); return -1; }
    x->trial[0] = (uint8_t)(e | 1);
    if (d2k_link_set_name_probe_trial(x->fd, name, 6, hex, x->shape, htons(lport), x->family,
                                      x->trial, err, cap) != 0) {
        fprintf(stderr, "пробный план не отправлен: %s\n", err);
        return -1;
    }
    for (long long dl = mono_ms() + 10000; wait_left(dl) > 0;) {
        d2k_ev ev;
        if (d2k_link_next(x->fd, &ev, wait_left(dl), err, cap) < 0) return -1;
        if (ev.kind == D2K_EV_ACK && ev.code == D2K_CMD_SET_NAME_PROBE &&
            !memcmp(ev.trial_id,x->trial,sizeof x->trial)) {
            if ((ev.num >> 8) & 1) return 0;
            snprintf(err, cap, "датапат отверг план: причина %u", (unsigned)(ev.num & 255));
            fprintf(stderr, "%s\n", err);
            return -1;
        }
    }
    snprintf(err, cap, "нет подтверждения от датапата");
    return -1;
}

static int plan_install(void *c,const char *name,uint16_t port,const d2km_program *p,uint32_t e,char *err,size_t cap)
{
    long long begin=mono_ms();int rc=plan_install_wire(c,name,port,p,e,err,cap);
    int saved=errno;
    expctl *x=c;
    fprintf(stderr,"experiment E%u host=%s phase=install shape=%u program=%016llx elapsed_ms=%lld rc=%d\n",
        e,name,(unsigned)x->shape,(unsigned long long)d2km_program_hash(p),mono_ms()-begin,rc);
    errno=saved;
    return rc;
}
static int plan_receipt_wire(void *c, uint16_t lport, uint32_t e, char *note, size_t cap)
{
    expctl *x = c;
    (void)lport; (void)e;
    for (long long dl = mono_ms() + 3000; wait_left(dl) > 0;) {
        d2k_ev ev;
        char err[160];
        if (d2k_link_next(x->fd, &ev, wait_left(dl), err, sizeof err) < 0) break;
        if ((ev.kind == D2K_EV_APPLIED || ev.kind == D2K_EV_REFUSED) &&
            !memcmp(ev.trial_id, x->trial, 16)) {
            snprintf(note, cap, "%s", ev.kind == D2K_EV_APPLIED ? "исполнен" : "отвергнут исполнителем");
            fprintf(stderr, "квитанция: план %s (код %u)\n", note, (unsigned)ev.code);
            return ev.kind == D2K_EV_APPLIED;
        }
    }
    snprintf(note, cap, "квитанции нет");
    fprintf(stderr, "квитанции нет: исполнение не засчитано\n");
    return 0;
}
static int plan_receipt(void *c,uint16_t port,uint32_t e,char *note,size_t cap)
{
    expctl *x=c;long long begin=mono_ms();int rc=plan_receipt_wire(c,port,e,note,cap);
    int saved=errno;
    fprintf(stderr,"experiment E%u host=%s phase=receipt elapsed_ms=%lld rc=%d\n",e,x->host?x->host:"?",mono_ms()-begin,rc);
    errno=saved;
    return rc;
}

static void plan_remove(void *c, const char *name, uint16_t lport, uint32_t e)
{
    expctl *x = c;
    char err[160];
    (void)e;
    if(d2k_link_del_name_probe_trial(x->fd,name,6,x->shape,htons(lport),x->family,x->trial,err,sizeof err))
        fprintf(stderr,"probe cleanup E%u port=%u: %s\n",e,(unsigned)lport,err);
}


struct d2k_exp_task {
    d2km_context context;
    d2km_box box;
    uint8_t hello[D2KM_TLS_MAX];
    expctl control;
    d2k_netarm arm;
    d2km_net underlying, net;
    d2km_tls_task task;
    char application_proof[600];
    char last_local_reason[200];
    d2km_store *catalog;
    volatile sig_atomic_t *cancel;
    void (*network_begin)(void *),(*network_end)(void *);
    void *network_ctx;
};

static int run_arm(void *ctx, const d2km_arm_spec *spec,
                   d2km_observation *obs, d2km_result *res)
{
    d2k_exp_task *x=ctx;
    if(x->cancel && *x->cancel) {
        memset(obs,0,sizeof *obs);memset(res,0,sizeof *res);
        res->kind=D2KM_R_LOCAL_FAIL;
        return 0;
    }
    if(x->network_begin)x->network_begin(x->network_ctx);
    long long begin=mono_ms();
    int rc=x->underlying.run(x->underlying.ctx,spec,obs,res);
    long long elapsed=mono_ms()-begin;
    if(x->network_end)x->network_end(x->network_ctx);
    fprintf(stderr,"experiment E%u host=%s phase=network kind=%u elapsed_ms=%lld result=%s rc=%d\n",
        spec->experiment,x->control.host?x->control.host:"?",(unsigned)spec->kind,elapsed,d2km_result_name(res->kind),rc);
    if(res->kind==D2KM_R_LOCAL_FAIL && x->arm.last_reason[0])
        snprintf(x->last_local_reason,sizeof x->last_local_reason,"%s",x->arm.last_reason);
    if(x->arm.last_reason[0] && x->task.journal) {
        d2km_why why={.task=spec->context,.step=D2KM_STEP_EXPERIMENT,
            .observations=x->arm.last_reason,.reason=x->arm.doh_path?
                "DoH: результат прикладного контракта на потоке плеча":
                "TLS: наблюдение собственного плеча, включая локальные отказы"};
        if(d2km_journal_append(x->task.journal,&why,NULL)!=D2KM_WHY_OK) {
            res->kind=D2KM_R_LOCAL_FAIL;res->value=0;
        }
        x->arm.last_reason[0]=0;
    }
    return rc;
}

d2k_exp_task *d2k_exp_task_open(const d2k_exp_options *o, d2km_store *store,
                              d2km_journal *journal, const d2km_net *injected,
                              char *err, size_t cap)
{
    if(!o || !o->host || !o->ip || (!o->form && !o->client_hello) || !o->port ||
       (o->family!=4 && o->family!=6) || (injected && !injected->run)) {
        snprintf(err,cap,"негодные параметры задачи");return NULL;
    }
    uint8_t addr[16];
    if(inet_pton(o->family==6?AF_INET6:AF_INET,o->ip,addr)!=1) {
        snprintf(err,cap,"адрес не соответствует семейству");return NULL;
    }
    d2k_exp_task *x=calloc(1,sizeof *x);
    if(!x) { snprintf(err,cap,"нет памяти для задачи");return NULL; }
    x->control.fd=-1;
    uint8_t raw[D2KM_TLS_MAX];d2km_tls_hello parsed;
    size_t rn=o->client_hello?o->client_hello_len:load_hex(o->form,raw,sizeof raw);
    const uint8_t *input=o->client_hello?o->client_hello:raw;
    if(!rn || rn>sizeof x->hello || d2km_tls_parse(input,rn,&parsed)!=D2KM_TLS_OK ||
       (!o->client_hello && d2km_tls_set_sni(&parsed,o->host)!=D2KM_TLS_OK)) {
        snprintf(err,cap,"форма не разобралась или имя не встало");goto failed;
    }
    size_t hn;
    if(o->client_hello) {memcpy(x->hello,input,rn);hn=rn;}
    else hn=d2km_tls_build(&parsed,x->hello,sizeof x->hello);
    if(!hn || d2km_target_name(&x->context.target,o->host)) {
        snprintf(err,cap,"имя цели или форма негодны");goto failed;
    }
    x->context.transport=D2KM_TCP;
    x->context.protocol=D2KM_P_TLS12;
    int ech=0,grease=0;
    for(size_t i=0;i<parsed.ext_count;i++) {
        const d2km_tls_ext *e=&parsed.ext[i];const uint8_t *v=parsed.arena+e->offset;
        if(e->type==43 && e->length>0 && v[0]+1u==e->length)
            for(size_t k=1;k+1<e->length;k+=2)if(v[k]==3 && v[k+1]==4)x->context.protocol=D2KM_P_TLS13;
        if(e->type==0xfe0d)ech=1;
        if((e->type&0x0f0f)==0x0a0a && (e->type>>8)==(e->type&255))grease=1;
    }
    if(o->expected_protocol && x->context.protocol!=(d2km_protocol)o->expected_protocol) {
        snprintf(err,cap,"сигнал и наблюдённая форма имеют разные версии TLS");goto failed;
    }
    x->context.family=o->family==6?D2KM_IPV6:D2KM_IPV4;
    if(d2km_form_set(&x->context.form,x->hello,hn,NULL,0,o->tcp_options,o->tcp_options_len,ech,grease)) {
        snprintf(err,cap,"форма не воспроизведена");goto failed;
    }
    d2km_box_init(&x->box,1);
    x->control.host=o->host;
    x->control.shape=(uint8_t)d2k_hello_shape(x->hello,hn);
    /* The full observed outer offer selects the datapath's ECH slot.
       A MODERN probe cannot match a complete ECH ClientHello. */
    if(x->control.shape==D2K_SHAPE_MODERN && d2k_hello_ech_offer(x->hello,hn,NULL)==1)
        x->control.shape=D2K_PLAN_SHAPE_ECH_TCP;
    x->control.family=(uint8_t)o->family;
    size_t max_payload=0;
    if(!injected && o->exp_control) {
        /* Private control socket setup can wait for PROTO. It owns no shared
           model/catalog data and must not hold the catalog owner's mutex. */
        if(o->network_begin)o->network_begin(o->network_ctx);
        long long begin=mono_ms();
        char note[200];
        x->control.fd=d2k_link_open(o->exp_control,note,sizeof note);
        if(x->control.fd<0)
            fprintf(stderr,"сокет опытов датапата: %s — испытание будет невозможно\n",note);
        else {
            for(int i=0;i<10;i++) {
                d2k_ev ev;
                if(d2k_link_next(x->control.fd,&ev,300,note,sizeof note)<0)break;
                if(ev.kind==D2K_EV_PROTO) {
                    size_t hdr=(o->family==6?40u:20u)+60u;
                    if(ev.send_maxlen>hdr)max_payload=ev.send_maxlen-hdr;
                    break;
                }
            }
            fprintf(stderr,"предел посылки исполнителя под сообщение: %zu байт\n",max_payload);
        }
        long long elapsed=mono_ms()-begin;
        if(o->network_end)o->network_end(o->network_ctx);
        fprintf(stderr,"experiment host=%s phase=control-setup elapsed_ms=%lld\n",o->host,elapsed);
    }
    x->arm=(d2k_netarm){.mark=o->mark,.probe_mark=0x2e,.family=o->family,
        .ip=o->ip,.port=o->port,.host=o->host,.path="/",.doh_path=o->doh_path,.connect_ms=3000,.exchange_ms=8000,
        .install=x->control.fd>=0?plan_install:NULL,.remove=plan_remove,
        .receipt=plan_receipt,.plan_ctx=&x->control};
    x->underlying=injected?*injected:d2k_netarm_net(&x->arm);
    x->network_begin=o->network_begin;x->network_end=o->network_end;x->network_ctx=o->network_ctx;
    x->net=(d2km_net){.ctx=x,.run=run_arm};x->cancel=o->cancel;x->catalog=store;
    if(o->doh_path)snprintf(x->application_proof,sizeof x->application_proof,"doh-contract-v1 path=%s replies>=20 span>=30000ms",o->doh_path);
    x->task=(d2km_tls_task){.application_proof=x->application_proof[0]?x->application_proof:NULL,.net=&x->net,.box=&x->box,
        .knowledge=store?&store->knowledge:NULL,.boxes=store?&store->boxes:NULL,
        .journal=journal,.context=&x->context,.hello=x->hello,.hello_length=hn,
        .shared_experiment=o->shared_experiment,.shared_fact=o->shared_fact,
        .pass_name=o->pass_name,.alive_history=o->alive_history,.seed=42,.max_payload=max_payload,
        .max_sends=D2K_WIRE_BATCH_MAX,
        .knowledge_changed=o->knowledge_changed,.knowledge_changed_ctx=o->knowledge_changed_ctx,
        .degradation_knowledge=o->degradation_knowledge,.degradation_hash=o->degradation_hash,
        .next_experiment=store?store->next_experiment:1,.next_fact=store?store->next_fact:1};
    return x;
failed:
    d2k_exp_task_close(x);return NULL;
}

d2km_outcome d2k_exp_task_run(d2k_exp_task *x,d2km_task_report *report)
{
    x->last_local_reason[0]=0;
    d2km_outcome outcome=d2km_tls_task_run(&x->task,report);
    if(outcome==D2KM_LOCAL_FAIL && x->last_local_reason[0]) {
        snprintf(report->reason,sizeof report->reason,"%s",x->last_local_reason);
    }
    if(x->catalog) {
        if(!x->task.shared_experiment && x->catalog->next_experiment<x->task.next_experiment)x->catalog->next_experiment=x->task.next_experiment;
        if(!x->task.shared_fact && x->catalog->next_fact<x->task.next_fact)x->catalog->next_fact=x->task.next_fact;
    }
    return outcome;
}
const d2km_box *d2k_exp_task_box(const d2k_exp_task *x) { return &x->box; }
const d2km_context *d2k_exp_task_context(const d2k_exp_task *x) { return &x->context; }
void d2k_exp_task_close(d2k_exp_task *x)
{
    if(!x)return;
    if(x->control.fd>=0)d2k_link_close(x->control.fd);
    free(x);
}

/* Includes worker stack (1 MiB), HTTP receive buffer (1 MiB), TLS/parser
 * scratch (1 MiB) and model staging. Declaration protects router memory,
 * never limits the number of questions or trials. */
size_t d2k_exp_task_memory(void) {
    return 3u*1024u*1024u+sizeof(d2k_exp_task)+sizeof(d2km_task_report)+
        2*sizeof(d2km_box)+6*sizeof(d2km_program)+2*sizeof(d2km_tls_hello);
}
