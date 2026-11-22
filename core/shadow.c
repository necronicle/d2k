#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2k_shadow.h"
#include "d2k_domain.h"
#include "d2km_tls.h"
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int d2k_shadow_same_context(const d2k_shadow_record *a,const d2k_shadow_record *b)
{
    /* Preserve the task owner's scope for a named target. Endpoint changes
       do not admit another writer for the same observed form. */
    return a->family==b->family && a->form_key==b->form_key &&
        (a->protocol?a->protocol:2)==(b->protocol?b->protocol:2) && !strcmp(a->host,b->host);
}
static int same(const d2k_shadow_record *a,const d2k_shadow_record *b)
{
    return d2k_shadow_same_context(a,b) && a->port==b->port && !strcmp(a->ip,b->ip) &&
        a->degradation==b->degradation &&
        (!a->degradation || (a->knowledge==b->knowledge && a->program_hash==b->program_hash &&
          d2k_binding_equal(&a->binding,&b->binding)));
}
static uint64_t after(uint64_t now,uint64_t delta)
{
    return now>UINT64_MAX-delta?UINT64_MAX:now+delta;
}
int d2k_shadow_obsolete(const d2k_shadow_dedup *d,const d2k_shadow_record *r,uint64_t now)
{
    for(size_t i=0;i<D2K_SHADOW_DEDUP_MAX;i++)if(d->entries[i].used && same(&d->entries[i].target,r)) {
        int owner_wake=r->priority==2 && r->time>d->entries[i].target.time;
        int error=d->entries[i].target.snapshot_errno;
        int resource_wake=(error==ENOSPC || error==ENOMEM) && r->snapshot && !r->snapshot_errno;
        return !owner_wake && !resource_wake && (now<d->entries[i].until || r->time<d->entries[i].until);
    }
    return 0;
}
int d2k_shadow_admit(d2k_shadow_dedup *d,const d2k_shadow_record *r,uint64_t now)
{
    if(d2k_shadow_obsolete(d,r,now))return 0;
    size_t free_slot=D2K_SHADOW_DEDUP_MAX;
    for(size_t i=0;i<D2K_SHADOW_DEDUP_MAX;i++) {
        if(d->entries[i].used && same(&d->entries[i].target,r)) {
            /* Old queued signals cannot become timer-only retries when they
               are finally consumed after the cooldown. */
            free_slot=i;break;
        }
        if(free_slot==D2K_SHADOW_DEDUP_MAX &&
           (!d->entries[i].used || now>=d->entries[i].until))free_slot=i;
    }
    if(free_slot==D2K_SHADOW_DEDUP_MAX) { d->dropped++;return 0; }
    d->entries[free_slot].used=1;d->entries[free_slot].target=*r;
    /* Concurrent ownership is held by the consumer, never a durable infinite
       cooldown. Fresh owner traffic can wake an interrupted task. */
    d->entries[free_slot].until=after(now,3600);return 1;
}
void d2k_shadow_complete(d2k_shadow_dedup *d,const d2k_shadow_record *r,uint64_t now,
                         const d2km_task_report *report)
{
    uint64_t cooldown=report->state==D2KM_T_WAIT &&
        (report->outcome==D2KM_LOCAL_FAIL || report->outcome==D2KM_NOT_MEASURED)?600:3600;
    for(size_t i=0;i<D2K_SHADOW_DEDUP_MAX;i++)
        if(d->entries[i].used && same(&d->entries[i].target,r)) {
            d->entries[i].until=after(now,cooldown);
            if(r->priority==2)d->entries[i].target.time=now;
            return;
        }
}

/* Cooldowns survive watchdog restarts. Admission is saved before starting
 * any arm. Corrupt/unknown state is a startup error, never a retry waiver. */
int d2k_shadow_dedup_load(const char *path,d2k_shadow_dedup *d,uint64_t now)
{
    int fd=open(path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW);
    if(fd<0)return errno==ENOENT?0:-1;
    struct stat st;
    if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<0 ||
       (uint64_t)st.st_size>D2K_SHADOW_DEDUP_MAX*D2K_SHADOW_RECORD_MAX+32u) {
        close(fd);return -1;
    }
    FILE *f=fdopen(fd,"r");if(!f) { close(fd);return -1; }
    char line[D2K_SHADOW_RECORD_MAX];int bad=0;
    if(!fgets(line,sizeof line,f) || strcmp(line,"D2KSHADOW1\n"))bad=1;
    d2k_shadow_dedup *loaded=calloc(1,sizeof *loaded);
    if(!loaded) { fclose(f);return -1; }
    size_t slot=0;
    while(!bad && fgets(line,sizeof line,f)) {
        unsigned long long until,signal_time;
        unsigned port,family,signal;int used=0;
        d2k_shadow_record r={0};
        int fields=sscanf(line,"%llu %llu %253s %45s %u %u %u%n",
            &until,&signal_time,r.host,r.ip,&port,&family,&signal,&used);
        if(fields!=7 || port>65535 || family>255 || signal>65535) { bad=1;break; }
        if(strcmp(line+used,"\n")) {
            unsigned degradation,protocol,knowledge,shape;unsigned long long hash,generation;char epoch[33];int end=0;
            if(sscanf(line+used," %u %u %u %llu %llu %32s %u%n",&degradation,&protocol,&knowledge,&hash,&generation,epoch,&shape,&end)!=7 ||
               degradation>1 || protocol>2 || shape>255 || strlen(epoch)!=32) {bad=1;break;}
            if(strcmp(line+used+end,"\n")) {
                unsigned long long form;int tail=0;
                if(sscanf(line+used+end," %llu%n",&form,&tail)!=1) {bad=1;break;}
                r.form_key=(uint64_t)form;
                if(strcmp(line+used+end+tail,"\n")) {
                    unsigned code;int rest=0;
                    if(sscanf(line+used+end+tail," %u%n",&code,&rest)!=1 || code>INT_MAX ||
                       strcmp(line+used+end+tail+rest,"\n")) {bad=1;break;}
                    r.snapshot_errno=(int)code;
                }
            }
            r.degradation=(uint8_t)degradation;r.protocol=(uint8_t)protocol;r.knowledge=knowledge;r.program_hash=(uint64_t)hash;
            r.binding=(d2k_binding_context){.kind=degradation?D2K_BIND_NAME:0,.generation=(uint64_t)generation,
                .family=(uint8_t)family,.shape=(uint8_t)shape};
            for(unsigned j=0;j<16;j++) {
                char byte[3]={epoch[j*2],epoch[j*2+1],0},*tail;unsigned long b=strtoul(byte,&tail,16);
                if(*tail || b>255)bad=1;
                r.binding.epoch[j]=(uint8_t)b;
            }
            if(bad)break;
        }
        r.time=(uint64_t)signal_time;r.port=(uint16_t)port;r.family=(uint8_t)family;r.signal=(uint16_t)signal;
        if(d2k_shadow_record_normalize(&r)) { bad=1;break; }
        if(slot==D2K_SHADOW_DEDUP_MAX) { bad=1;break; }
        for(size_t i=0;i<slot;i++)if(same(&loaded->entries[i].target,&r))bad=1;
        loaded->entries[slot].target=r;loaded->entries[slot].until=(uint64_t)until;
        if((uint64_t)until==UINT64_MAX) {
            loaded->entries[slot].until=after(now,600);
            loaded->entries[slot].target.time=now;
        }
        loaded->entries[slot++].used=1;
    }
    if(ferror(f))bad=1;
    fclose(f);
    if(!bad)*d=*loaded;
    free(loaded);return bad?-1:0;
}
int d2k_shadow_dedup_save(const char *path,const d2k_shadow_dedup *d,uint64_t now)
{
    (void)now;
    char temporary[1024];
    int n=snprintf(temporary,sizeof temporary,"%s.new",path);
    if(n<0 || (size_t)n>=sizeof temporary)return -1;
    int fd=open(temporary,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,0600);
    if(fd<0)return -1;
    struct stat st;
    if(fstat(fd,&st) || !S_ISREG(st.st_mode)) { close(fd);return -1; }
    FILE *f=fdopen(fd,"w");if(!f) { close(fd);return -1; }
    int bad=fputs("D2KSHADOW1\n",f)==EOF;
    for(size_t i=0;i<D2K_SHADOW_DEDUP_MAX && !bad;i++) {
        if(!d->entries[i].used)continue;
        const d2k_shadow_record *r=&d->entries[i].target;
        char epoch[33];for(unsigned j=0;j<16;j++)snprintf(epoch+j*2,3,"%02x",r->binding.epoch[j]);
        if(fprintf(f,"%" PRIu64 " %" PRIu64 " %s %s %u %u %u %u %u %u %" PRIu64 " %" PRIu64 " %s %u %" PRIu64 " %d\n",d->entries[i].until,
            r->time,r->host,r->ip,(unsigned)r->port,(unsigned)r->family,(unsigned)r->signal,
            (unsigned)r->degradation,(unsigned)r->protocol,r->knowledge,r->program_hash,r->binding.generation,epoch,(unsigned)r->binding.shape,r->form_key,r->snapshot_errno)<0)bad=1;
    }
    if(fflush(f) || fsync(fd))bad=1;
    if(fclose(f))bad=1;
    if(!bad && rename(temporary,path))bad=1;
    if(bad)unlink(temporary);
    return bad?-1:0;
}

static int log_form(const char *path,const d2k_shadow_record *r,uint64_t now,
                    const d2km_task_report *report,const char *form)
{
    char program[1536];size_t pos=0;
    const d2km_program *p=report->outcome==D2KM_APPLIED?&report->program:
                           report->has_candidate?&report->candidate:NULL;
    int n=snprintf(program,sizeof program,"fakes=%zu",p?p->fake_count:0);
    if(n<0 || (size_t)n>=sizeof program)return -1;
    pos=(size_t)n;
    if(p) {
        for(size_t i=0;i<p->fake_count;i++) {
            const d2km_fake *f=&p->fakes[i];
            n=snprintf(program+pos,sizeof program-pos,
                " fake%zu:spoil=badsum:%u,md5:%u,tcpts:%u,seq:%" PRId32 ",ttl=%u,copies=%u",
                i,(unsigned)f->poison.badsum,(unsigned)f->poison.md5,(unsigned)f->poison.tcpts,
                f->poison.seqshift,(unsigned)f->poison.ttl,(unsigned)f->repeats);
            if(n<0 || (size_t)n>=sizeof program-pos)return -1;
            pos+=(size_t)n;
        }
    }
    if(!p || !p->fake_count) {
        n=snprintf(program+pos,sizeof program-pos," spoil=none ttl=0 copies=0");
        if(n<0 || (size_t)n>=sizeof program-pos)return -1;
        pos+=(size_t)n;
    }
    n=snprintf(program+pos,sizeof program-pos," split=");
    if(n<0 || (size_t)n>=sizeof program-pos)return -1;
    pos+=(size_t)n;
    if(p && p->split_count) {
        for(size_t i=0;i<p->split_count;i++) {
            const char *anchor=d2km_anchor_name(p->splits[i].anchor);
            n=snprintf(program+pos,sizeof program-pos,"%s%s%+d",i?",":"",anchor?anchor:"?",p->splits[i].offset);
            if(n<0 || (size_t)n>=sizeof program-pos)return -1;
            pos+=(size_t)n;
        }
    } else {
        n=snprintf(program+pos,sizeof program-pos,"none");
        if(n<0 || (size_t)n>=sizeof program-pos)return -1;
    }
    char reason[sizeof report->reason*6+3];size_t rp=0;
    reason[rp++]='"';
    for(const unsigned char *s=(const unsigned char *)report->reason;
        s<(const unsigned char *)report->reason+sizeof report->reason && *s;s++) {
        if(*s=='"' || *s=='\\') {reason[rp++]='\\';reason[rp++]=(char)*s;}
        else if(*s<32 || *s==127) {int k=snprintf(reason+rp,sizeof reason-rp,"\\u%04x",*s);rp+=(size_t)k;}
        else reason[rp++]=(char)*s;
    }
    reason[rp++]='"';reason[rp]=0;
    char line[4096];
    const char *outcome=d2km_outcome_name(report->outcome),*state=d2km_task_state_name(report->state);
    n=snprintf(line,sizeof line,
        "time=%" PRIu64 " signal_time=%" PRIu64 " host=%s ip=%s port=%u family=%u signal=%u"
        " outcome=%s state=%s experiments=%u runs=%u source=%s K%u B%u form=%s form_key=%016" PRIx64
        " snapshot=%016" PRIx64 " snapshot_errno=%d %s reason=%s\n",
        now,r->time,r->host,r->ip,(unsigned)r->port,(unsigned)r->family,(unsigned)r->signal,
        outcome?outcome:"LOCAL_FAIL",state?state:"WAIT",report->experiments,report->runs,
        report->from_own?"own":"questions",report->knowledge_id,report->box_id,form,r->form_key,
        r->snapshot,r->snapshot_errno,program,reason);
    if(n<0 || (size_t)n>=sizeof line)return -1;
    int fd=open(path,O_WRONLY|O_CREAT|O_APPEND,0600);
    if(fd<0)return -1;
    int result=write(fd,line,(size_t)n)==n?0:-1;
    if(close(fd))result=-1;
    return result;
}

int d2k_shadow_log(const char *path,const d2k_shadow_record *r,uint64_t now,const d2km_task_report *report)
{ return log_form(path,r,now,report,"not-client"); }

static const char *site(const char *name,char out[256])
{
    if(!d2k_domain_base(name,out))return out;
    /* Reserved/unknown TLDs have no PSL registrable domain. Conservatively
       exclude their final two labels rather than assume unrelated sites. */
    const char *last=strrchr(name,'.');if(!last)return name;
    const char *p=last;while(p>name && p[-1]!='.')p--;
    return p;
}
static const d2k_shadow_record *best_name(const d2k_shadow_recent *list,
    const d2k_shadow_record *target,uint64_t now,const d2k_shadow_record *best)
{
    if(!list || list->count>D2K_SHADOW_RECENT_MAX)return best;
    char target_site[256],candidate_site[256];const char *ts=site(target->host,target_site);
    for(size_t i=0;i<list->count;i++) {
        const d2k_shadow_record *e=&list->entries[i];
        if(!e->time || e->time>now || now-e->time>D2K_SHADOW_HOUR ||
           !strcmp(site(e->host,candidate_site),ts))continue;
        int same_ip=!strcmp(e->ip,target->ip),old_same=best && !strcmp(best->ip,target->ip);
        if(!best || (same_ip && !old_same) || (same_ip==old_same &&
           (e->time>best->time || (e->time==best->time && e->signal>best->signal))))best=e;
    }
    return best;
}

static int describe_name(const d2k_shadow_record *best,const d2k_shadow_record *target,
                         char *reason,size_t cap)
{
    if(!best) {if(cap)reason[0]=0;return 0;}
    time_t seconds=(time_t)best->time;struct tm tm;
    char clock[16]="?";if(localtime_r(&seconds,&tm))strftime(clock,sizeof clock,"%H:%M",&tm);
    if(best->signal)snprintf(reason,cap,"прямой успех цели %s в %s (DIRECT_OK, %s:%u)",
        best->host,clock,best->ip,(unsigned)best->port);
    else snprintf(reason,cap,"имя %s ходило на %s в %s (чистый обмен, %s:%u)",
        best->host,!strcmp(best->ip,target->ip)?"этот адрес":"другой адрес",clock,best->ip,(unsigned)best->port);
    return 1;
}

int d2k_shadow_pick_names(const d2k_shadow_recent *recent,const d2k_shadow_recent *direct,
                           const d2k_shadow_record *target,uint64_t now,
                          d2k_shadow_record *chosen,char *reason,size_t cap)
{
    const d2k_shadow_record *best=best_name(recent,target,now,NULL);
    best=best_name(direct,target,now,best);
    if(best)*chosen=*best;
    return describe_name(best,target,reason,cap);
}

int d2k_shadow_pick_name(const d2k_shadow_recent *recent,const d2k_shadow_record *target,uint64_t now,
                         d2k_shadow_record *chosen,char *reason,size_t cap)
{ return d2k_shadow_pick_names(recent,NULL,target,now,chosen,reason,cap); }

static int load_history(const char *queue,const d2k_shadow_record *r,uint64_t now,
                        d2k_shadow_record *chosen,char *name_reason,size_t name_cap,
                        char *history,size_t history_cap)
{
    d2k_shadow_recent scratch;
    int recent_rc=d2k_shadow_recent_load(queue,"recent",&scratch,now);
    size_t recent_count=scratch.count;
    const d2k_shadow_record *best=best_name(&scratch,r,now,NULL);
    if(best) {
        *chosen=*best;
        best=chosen;
    }
    int direct_rc=d2k_shadow_recent_load(queue,"direct",&scratch,now);
    fprintf(stderr,"d2kshadow: inputs host=%s recent=%zu(%d) direct=%zu(%d) queued_seconds=%llu\n",
        r->host,recent_count,recent_rc,scratch.count,direct_rc,(unsigned long long)(now>=r->time?now-r->time:0));
    best=best_name(&scratch,r,now,best);
    int found=describe_name(best,r,name_reason,name_cap);
    if(found && best!=chosen)*chosen=*best;
    /* §4.3 п. 2 — обмен с тем же адресом и портом, ДОШЕДШИЙ ДО ДАННЫХ
       ПРИЛОЖЕНИЯ. Пассивный «чистый обмен» датапата этого не доказывает:
       в TLS 1.3 зашифрованное рукопожатие тоже идёт записями типа 23
       (ревью задачи 23, R4). Поэтому доказательство живости — только
       прямой успех самой тени (прикладная проверка §9) на этом адресе и
       порту за час; пассивные наблюдения остаются лишь кандидатами имени,
       пропуск которых доказывает контрольное плечо. */
    for(size_t i=0;i<scratch.count;i++) {
        const d2k_shadow_record *d=&scratch.entries[i];
        if(d->port!=r->port || strcmp(d->ip,r->ip) || !d->time || d->time>now ||
           now-d->time>D2K_SHADOW_HOUR) continue;
        time_t stamp=(time_t)d->time;struct tm tm;char clock[16]="?";
        if(localtime_r(&stamp,&tm))strftime(clock,sizeof clock,"%H:%M",&tm);
        snprintf(history,history_cap,"прикладной успех на том же адресе: %s на %s:%u в %s (DIRECT_OK тени)",
            d->host,r->ip,(unsigned)r->port,clock);
        break;
    }
    return found;
}

static int note_direct_success(const char *queue,const d2k_shadow_record *r,uint64_t now)
{
    d2k_shadow_recent direct;
    (void)d2k_shadow_recent_load(queue,"direct",&direct,now);
    d2k_shadow_record success=*r;success.time=now;success.signal=1;
    d2k_shadow_recent_note(&direct,&success,now);
    return d2k_shadow_recent_save(queue,"direct",&direct,now);
}

int d2k_shadow_run(const d2k_shadow_record *r,const d2k_exp_options *options,d2km_store *store,
                    d2km_journal *journal,const d2km_net *injected,const char *log,
                    d2km_task_report *report)
{
    uint64_t now=(uint64_t)time(NULL);char err[300],history[700]="",name_reason[700]="";
    d2k_exp_options assembled=*options;const char *form="not-client";
    d2k_shadow_snapshot snapshot;d2k_shadow_record chosen;
    int snapshot_error=r->snapshot_errno;
    const char *form_error=NULL;
    if(options->shadow_queue) {
        assembled.pass_name=NULL;assembled.alive_history=NULL;
        assembled.client_hello=NULL;assembled.client_hello_len=0;
        assembled.tcp_options=NULL;assembled.tcp_options_len=0;
        if(!d2k_shadow_snapshot_read(options->shadow_queue,r,&snapshot)) {
            d2km_tls_hello parsed;char sni[254];d2km_target observed,target;
            if(d2km_tls_parse(snapshot.hello,snapshot.hello_len,&parsed)==D2KM_TLS_OK &&
               d2km_tls_sni(&parsed,sni,sizeof sni)==D2KM_TLS_OK &&
               !d2km_target_name(&observed,sni) && !d2km_target_name(&target,r->host) &&
               !strcmp(observed.name,target.name)) {
                /* We do not own the client's resumption secret/binder.
                   Removing PSK would replace its form, not reproduce it. */
                for(size_t i=0;i<parsed.ext_count;i++)if(parsed.ext[i].type==41)
                    form_error="форма клиента с pre_shared_key не воспроизводится: нет секрета возобновления";
                if(!form_error) {
                    assembled.client_hello=snapshot.hello;assembled.client_hello_len=snapshot.hello_len;
                    assembled.tcp_options=snapshot.options;assembled.tcp_options_len=snapshot.options_len;form="client";
                }
            }
        }
        /* The task uses this stack copy, so no durable slot is needed
           during network waits. The exact file is released only once. */
        d2k_shadow_snapshot_remove(options->shadow_queue,r);
        int picked=load_history(options->shadow_queue,r,now,&chosen,name_reason,sizeof name_reason,
                                history,sizeof history);
        if(picked>0)assembled.pass_name=chosen.host;
        if(history[0])assembled.alive_history=history;
    }
    assembled.doh_path=r->doh_path[0]?r->doh_path:NULL;
    assembled.expected_protocol=r->protocol;
    assembled.degradation_knowledge=r->degradation?r->knowledge:0;
    assembled.degradation_hash=r->degradation?r->program_hash:0;
    d2km_context ctx={0};d2km_target_name(&ctx.target,r->host);
    ctx.transport=D2KM_TCP;ctx.protocol=r->protocol==1?D2KM_P_TLS12:D2KM_P_TLS13;ctx.family=(d2km_family)r->family;
    char provenance[1600];snprintf(provenance,sizeof provenance,"form=%s; %s; %s",form,
        name_reason[0]?name_reason:"нет измеренного имени для контроля живости 1",history);
    d2km_why inputs={.task=&ctx,.step=D2KM_STEP_DIRECT,.reason=provenance};
    if(journal && d2km_journal_append(journal,&inputs,NULL)!=D2KM_WHY_OK)
        fprintf(stderr,"d2kshadow: отказ записи происхождения входов\n");
    d2k_exp_task *task=NULL;
    if(options->shadow_queue && !assembled.client_hello) {
        if(form_error)snprintf(err,sizeof err,"%s",form_error);
        else if(snapshot_error)snprintf(err,sizeof err,"snapshot-write: errno=%d; форма клиента не сохранена",snapshot_error);
        else snprintf(err,sizeof err,"форма клиента для проверки той же привязки или новой задачи не воспроизведена (snapshot=%016" PRIx64 ")",r->snapshot);
    }
    else task=d2k_exp_task_open(&assembled,store,journal,injected,err,sizeof err);
    if(task) {
        d2k_exp_task_run(task,report);d2k_exp_task_close(task);
    } else {
        memset(report,0,sizeof *report);report->outcome=options->shadow_queue && !assembled.client_hello?
            (snapshot_error?(snapshot_error==ENOSPC || snapshot_error==ENOMEM?D2KM_NO_RESOURCES:D2KM_LOCAL_FAIL):D2KM_FORM_NOT_REPRODUCED):
            D2KM_LOCAL_FAIL;report->state=D2KM_T_WAIT;
        snprintf(report->reason,sizeof report->reason,"%s",err);
        char reason[400];snprintf(reason,sizeof reason,"form=%s; %s",form,err);
        d2km_why why={.task=&ctx,.step=D2KM_STEP_DIRECT,.outcome=report->outcome,.reason=reason};
        if(journal && d2km_journal_append(journal,&why,NULL)!=D2KM_WHY_OK)
            fprintf(stderr,"d2kshadow: отказ записи причины ошибки сборки задачи\n");
    }
    if(options->shadow_queue) {
        if(report->outcome==D2KM_DIRECT_OK || report->outcome==D2KM_BLOCK_GONE) {
            if(note_direct_success(options->shadow_queue,r,(uint64_t)time(NULL)))
                fprintf(stderr,"d2kshadow: отказ сохранения DIRECT_OK\n");
        }
    }
    int result=log_form(log,r,(uint64_t)time(NULL),report,form);
    if(result)fprintf(stderr,"d2kshadow: отказ записи итога %s\n",r->host);
    return result;
}
