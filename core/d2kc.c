/* d2kc.c — контроллер d2k на C: цикл событий поверх планировщика.
 *
 * Заменяет Go-процесс `d2k serve` (cmd/d2k, internal/controller). Делает ровно
 * три вещи и ничего сверх: держит связь с датапатом, отдаёт его события
 * планировщику (core/sched.c) и время от времени сохраняет каталог на диск.
 * Подбор, развилка по транспорту и запись знания — там, не здесь.
 *
 * ЦИКЛ НЕ БЛОКИРУЕТСЯ. poll() на двух дескрипторах: связь с датапатом и
 * будилка планировщика (рабочий поток, закончив сетевой оракул, пишет в неё
 * байт). Потолок ожидания — период тика: задачам нужно время, а не только
 * события (истёкшие сроки, отдых после неудачи), ровно та же причина, по
 * которой Go-сторона завела тикер рядом с событиями.
 *
 * КАТАЛОГ ПИШЕТСЯ АТОМАРНО. d2k_catalog_save пишет прямо в файл (см. её
 * doc-комментарий: атомарность в её контракт не входит и принадлежит тому,
 * кто решает КОГДА писать) — значит здесь: пишем во временный файл рядом,
 * fsync, rename. Оборванная запись каталога стоила бы всего накопленного
 * знания разом, а падение питания на роутере — обычное дело.
 */
/* Файл включают и как текст в составные тесты — после системных заголовков,
   где glibc (с 2026) уже задал _POSIX_C_SOURCE сам: голый #define там —
   переопределение под -Werror (CI 22.10.2026). Отдельной единицей трансляции
   значение задаётся как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "../runtime/d2k_runtime.h"
#include "d2k_crypto.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#include "d2k_sched.h"
#include "dns_journal.inc"
#ifdef D2K_TRUSTED_DOH
#include "d2k_dns_capture.h"
#include "d2k_provider_ips.h"
static d2k_provider_ips provider_ips;
static char provider_ips_path[D2K_CATALOG_PATH_MAX + 32];
#endif
#include "../synthesis/provider.h"
#include "../synthesis/application_search.h"
#include "../synthesis/application_history.h"
#include "d2k_arm.h"
#include "d2k_diagnostics.h"
#include "../runtime/d2k_diagnostics_files.h"
#include "d2k_httpsprobe.h"
#include "d2k_httpsearch.h"
#include "d2k_plantlv.h"
#include "d2k_groups.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include "d2k_link.h"
#include <arpa/inet.h>

/* Переходник к перенесённому измерителю (detect/bridge.c). Объявлен здесь, а
 * не в заголовке ядра: ядро о detect/ не знает и знать не должно — связь
 * односторонняя, её ставит тот, кто собирает бинарник. */
/* Просит перенесённый измеритель бросить всё, что он сейчас меряет. Нужен на
 * остановке: без него выход ждал окончания замера — до десятков минут. */
void d2k_detect_stop_all(void);
static int synthesis_session_feedback(void *ctx,const d2k_synthesis_feedback *event,
    d2k_verification_status outcome)
{
    return d2k_tls_path_session_disposition(ctx,event->generation,event->program,outcome);
}
static void synthesis_session_release(void *ctx) {d2k_tls_path_session_free(ctx);}
static const char *synthesis_catalog_path;
typedef struct {d2k_application_search *search;FILE *archive;int reported_probes;} application_search_owner;
static int application_search_feedback(void *ctx,const d2k_synthesis_feedback *event,
    d2k_verification_status outcome) {
    application_search_owner *owner=ctx;
    return owner?d2k_application_search_feedback(owner->search,event,outcome):-1;
}
static void application_search_release(void *ctx) {
    application_search_owner *owner=ctx;if(!owner)return;
    d2k_application_search_free(owner->search);
    if(owner->archive)fclose(owner->archive);
    free(owner);
}
static int application_history_offer(void *ctx,FILE *file) {
    return d2k_application_search_history(ctx,file);
}
static d2k_syn_status application_search_provider(const d2k_application_request *request,
    const d2k_tls_stream *stream,const d2k_experiment *experiment,uint64_t generation,d2k_vres *out) {
    uint64_t old_generation=0;
    application_search_owner *old=d2k_sched_synthesis_take(application_search_release,&old_generation);
    memset(out,0,sizeof *out);out->verdict=D2K_V_INCONCLUSIVE;out->owns_search=1;
    application_search_owner *owner=NULL;
    char *path=NULL;
    if(old) {
        if(!old_generation || !d2k_application_search_matches(old->search,request,
            experiment,old_generation,stream->read_timeout_ms,stream->trigger->len)) {
            application_search_release(old);
        } else {
            generation=old_generation;owner=old;goto resume;
        }
    }
    owner=calloc(1,sizeof *owner);
    if(!owner || !synthesis_catalog_path)goto fail;
    size_t length=strlen(synthesis_catalog_path);
    static const char suffix[]=".application-XXXXXX";
    if(length>SIZE_MAX-sizeof suffix)goto fail;
    path=malloc(length+sizeof suffix);if(!path)goto fail;
    memcpy(path,synthesis_catalog_path,length);memcpy(path+length,suffix,sizeof suffix);
    int fd=mkstemp(path);free(path);path=NULL;
    if(fd<0)goto fail;
    owner->archive=fdopen(fd,"w+b");
    if(!owner->archive){close(fd);goto fail;}
    owner->search=d2k_application_search_new(request,experiment,generation,
        stream->read_timeout_ms,stream->trigger->len,owner->archive);
    if(!owner->search)goto fail;
    d2k_inference_control history_control={0};
    if(experiment->cancel) {
        history_control.cancelled=experiment->cancel->fn;
        history_control.context=experiment->cancel->ctx;
    }
    if(d2k_application_history_scan(synthesis_catalog_path,application_history_offer,
        owner->search,&history_control,NULL)<0)goto fail;
resume:;
    d2k_syn_status status=d2k_application_search_next(owner->search,out);
    int total=out->probes;
    out->probes=total>=owner->reported_probes?total-owner->reported_probes:0;
    if(total>owner->reported_probes)owner->reported_probes=total;
    if(status!=D2K_SYN_CANDIDATE ||
       !d2k_sched_synthesis_retain(generation,owner,application_search_release,application_search_feedback))
        application_search_release(owner);
    return status;
fail:
    free(path);application_search_release(owner);
    snprintf(out->reason,sizeof out->reason,"cannot create owned DoH application search/archive");
    return D2K_SYN_ERROR;
}
static int application_stop(void *ctx) {
    return ctx && *(const volatile sig_atomic_t *)ctx;
}
static int application_synthesis_dispatch(const d2k_application_request *request,size_t wire,
    int timeout,uint32_t mark,const volatile sig_atomic_t *stop,d2k_vres *out) {
    uint64_t generation=0;
    d2k_trigger *trigger=calloc(1,sizeof *trigger);
    d2k_detect_stop cancel={application_stop,(void *)stop};
    d2k_experiment network={.family=request->family,.port=request->port,
        .mark=mark,.connect_ms=timeout,.offer_ts=1,.cancel=&cancel};
    if(!trigger || d2k_t13_random((uint8_t *)&generation,sizeof generation) || !generation ||
       inet_pton(request->family==6?AF_INET6:AF_INET,request->ip,network.ip)!=1) {
        free(trigger);memset(out,0,sizeof *out);out->verdict=D2K_V_INCONCLUSIVE;out->owns_search=1;
        snprintf(out->reason,sizeof out->reason,"cannot create owned application synthesis context");return 1;
    }
    trigger->len=wire;size_t whole=wire;
    d2k_tls_stream stream={trigger,&whole,1,timeout,1};
    d2k_syn_status status=application_search_provider(request,&stream,&network,generation,out);
    free(trigger);
    return status!=D2K_SYN_CLOSED;
}
static int synthesis_response_control(d2k_tls_path_session *session,
    const d2k_application_request *request,const d2k_experiment *experiment)
{
    const d2k_application_control *c=&request->control;unsigned epoch=0;
    for(size_t i=0;i<sizeof c->epoch;i++)epoch|=c->epoch[i];
    if(!session || !experiment->offer_ts || !epoch || !c->incarnation || !c->bytes ||
       !c->low_port || !c->high_port || c->transport!=6 ||
       (c->family!=4 && c->family!=6) || c->family!=request->family ||
       c->family!=experiment->family || !memchr(c->name,0,sizeof c->name) ||
       !c->name[0] || !strcmp(c->name,request->target))return 0;
    for(const unsigned char *p=(const unsigned char *)c->name;*p;p++)
        if(!((*p>='a' && *p<='z') || (*p>='A' && *p<='Z') ||
             (*p>='0' && *p<='9') || *p=='.' || *p=='-'))return 0;
    uint8_t *bytes=malloc(D2K_TRIGGER_MAX);if(!bytes)return -1;
    size_t length=0;
    if(d2k_hello_from_profile((d2k_shape)request->shape,c->name,bytes,D2K_TRIGGER_MAX,&length)) {
        free(bytes);return -1;
    }
    size_t segment=d2k_raw_segment_max();if(segment>length)segment=length;
    int added=d2k_tls_path_session_add_prefix(session,bytes,length,segment,0);
    free(bytes);return added;
}
static d2k_syn_status synthesis_session_provider(const d2k_tls_stream *stream,
    const d2k_experiment *experiment,uint64_t generation,d2k_vres *out)
{
    d2k_application_request request;
    int requested=d2k_sched_application_request(&request)==1;
    if(requested && !request.ech &&
       !request.by_addr && request.transport==6 &&
       (request.shape==D2K_SHAPE_MODERN || (request.shape==D2K_SHAPE_LEGACY && !request.doh)) &&
       request.resource[0]=='/' && memchr(request.resource,0,sizeof request.resource))
        return application_search_provider(&request,stream,experiment,generation,out);
    int response_mode=requested && !request.ech && !request.by_addr && request.transport==6 &&
        (request.shape==D2K_SHAPE_MODERN || request.shape==D2K_SHAPE_LEGACY) && !request.resource[0];
    size_t whole=stream->trigger->len;
    d2k_tls_stream response_stream=*stream;
    d2k_experiment response_experiment=*experiment;
    if(response_mode) {
        response_stream.chunk_bytes=&whole;response_stream.chunks=1;
        response_experiment.tls_input=stream->trigger->payload;
        response_experiment.tls_input_length=whole;
        stream=&response_stream;experiment=&response_experiment;
    }
    uint64_t previous_generation=0;
    int previous_probes=0;
    d2k_tls_path_session *session=d2k_sched_synthesis_take(synthesis_session_release,&previous_generation);
    if(session && (!d2k_tls_path_session_resumable(session) ||
                   !d2k_tls_path_session_matches(session,stream,experiment))) {
        d2k_tls_path_session_free(session);session=NULL;
    }
    if(session) {generation=previous_generation;previous_probes=d2k_tls_path_session_probes(session);}
    else session=response_mode?d2k_tls_path_session_new_response(stream,experiment,generation):
        d2k_tls_path_session_new(stream,experiment,generation);

    d2k_syn_status status=d2k_tls_path_session_next(session,out);
    if(!session)return status;
    if(response_mode && status==D2K_SYN_CLOSED) {
        int added=synthesis_response_control(session,&request,experiment);
        if(added>0)status=d2k_tls_path_session_next(session,out);
        else if(added<0) {
            status=D2K_SYN_ERROR;
            if(out) {
                out->program[0]=0;out->program_len=0;
                snprintf(out->reason,sizeof out->reason,"не удалось построить вопрос из наблюдения прямого TLS-потока");
            }
        }
    }
    if(out)out->probes=out->probes>=previous_probes?out->probes-previous_probes:0;
    if((status!=D2K_SYN_CANDIDATE && status!=D2K_SYN_DIRECT_RESPONSE) ||
       !d2k_sched_synthesis_retain(generation,session,synthesis_session_release,synthesis_session_feedback))
        d2k_tls_path_session_free(session);
    return status;
}
/* Opt-in for the working controller: only an owned, named HTTPS application
 * request enters the experimental path. Other protocols keep their current
 * controller and DNS recovery without spending synthesis probes. */
static d2k_syn_status synthesis_https_provider(const d2k_tls_stream *stream,
    const d2k_experiment *experiment,uint64_t generation,d2k_vres *out)
{
    d2k_application_request request;
    if(d2k_sched_application_request(&request)!=1 || request.doh || request.ech ||
       request.by_addr || request.transport!=6 ||
       (request.shape!=D2K_SHAPE_MODERN && request.shape!=D2K_SHAPE_LEGACY) ||
       request.resource[0]!='/' || !memchr(request.resource,0,sizeof request.resource)) {
        memset(out,0,sizeof *out);out->verdict=D2K_V_INCONCLUSIVE;out->owns_search=1;
        snprintf(out->reason,sizeof out->reason,"экспериментальный синтез HTTPS не применим к контексту");
        return D2K_SYN_CLOSED;
    }
    d2k_syn_status status=synthesis_session_provider(stream,experiment,generation,out);
    if(status==D2K_SYN_ERROR) {
        out->program_len=0;out->program[0]=0;out->synthesis_generation=0;
        return D2K_SYN_CLOSED;
    }
    return status;
}

/* Потолок сегмента отправителя замера (detect/raw.c): ставится по пределу
 * датапата вместе с d2k_sched_set_send_cap, чтобы замер и план шли одними
 * сегментами (поле 22.10.2026, issue #5/#7). */
void d2k_raw_set_segment_max(unsigned seg);

d2k_vres d2k_detect_sched_tcp(const char *ip, uint16_t port,
                              d2k_hello trigger, d2k_hello control,
                              uint32_t mark, int repeats,
                              uint32_t gap_us, uint32_t wait_ms,
                              const volatile sig_atomic_t *stop,
                              const d2k_sched_tcp_extra *extra);
/* Только базовый вопрос того же измерителя (задача 32): им планировщик
 * подтверждает блокировку на рукопожатии, прежде чем пробовать свои планы. */
d2k_vres d2k_detect_sched_tcp_base(const char *ip, uint16_t port,
                                   d2k_hello trigger, d2k_hello control,
                                   uint32_t mark, int repeats,
                                   uint32_t gap_us, uint32_t wait_ms,
                                   const volatile sig_atomic_t *stop,
                                   const d2k_sched_tcp_extra *extra);
/* Нейтральный байт перепроверки мёртвого адреса (задача 54). */
int d2k_detect_sched_tcp_ack(const char *ip, uint16_t port, uint32_t mark,
                             const volatile sig_atomic_t *stop, int *probes);

/* Период тика. Унаследован с Go-стороны (controller.go: time.NewTicker(3 *
   time.Second)) и там же обоснован: счётчики ядра опрашиваются по часам, а не
   по событиям. Выдумывать здесь другое число запрещено правилом «числа только
   из замера или наследования». */
#define TICK_MS 3000

/* Как часто сохранять каталог. Реже тика: запись на флеш роутера — дорогая
   операция, а знание между сохранениями не теряется (оно в памяти), теряется
   только при падении. Минута — тот же порядок, что у Go-стороны. */
#define SAVE_EVERY_MS 60000

/* Как часто говорить, что видно. Строка идёт в журнал на флеше: раз в 15 с
   это ~6000 строк в сутки (поле 06.10), а счётчики накопительные — пятнадцати
   минут хватает понять, видит ли служба трафик. Живой вид — в панели. */
#define REPORT_EVERY_MS (15 * 60 * 1000)

/* Как часто обновлять вид для панели. Две секунды: человек, открывший панель,
   ждёт, что идущий поиск на ней виден, а не появится через минуту. Файл
   маленький и лежит на tmpfs-подобном разделе состояния. */
#define LIVE_EVERY_MS 2000

static volatile sig_atomic_t stop_asked;
static volatile sig_atomic_t stop_sender;
static void on_signal(int sig, siginfo_t *info, void *context) {
    (void)context;
    stop_sender = info && info->si_code <= 0 ? info->si_pid : 0;
    stop_asked = sig;
}
typedef struct {
    int output,openwrt;
    volatile sig_atomic_t halt;
    dns_journal_cursor cursor;
} dns_journal_reader;
/* Local Keenetic RCI handles show/log without opening an ndmc CLI session.
 * Ask for a small tail normally, the firmware ring on a burst. */
static int journal_snapshot(unsigned lines,dns_journal_cursor *cursor,dns_journal_hits *hits) {
    char command[256];
    snprintf(command,sizeof command,
        "curl -q -fs --noproxy '*' --max-time %u -H 'Content-Type: application/json' "
        "-d '{\"once\":true,\"max-lines\":%u}' http://127.0.0.1:79/rci/show/log",lines>32 ? 12U : 3U,lines);
    FILE *f=popen(command,"r");
    if(!f)return -1;
    char *data=NULL;
    size_t used=0,cap=0;
    int complete=0;
    while(!feof(f) && !ferror(f)) {
        if(used==cap) {
            if(cap>=8*1024*1024)break;
            size_t larger=cap ? cap*2 : 4096;
            char *grown=realloc(data,larger);
            if(!grown)break;
            data=grown;cap=larger;
        }
        used+=fread(data+used,1,cap-used,f);
    }
    complete=feof(f) && !ferror(f);
    int status=pclose(f);
    int rc=complete && !status && used ? dns_journal_parse(data,used,cursor,hits) : -1;
    free(data);
    return rc;
}

static int journal_api_poll(dns_journal_cursor *next,dns_journal_hits *hits) {
    dns_journal_cursor previous=*next;
    int failed=journal_snapshot(next->ready ? 32 : 1,next,hits);
    if(!failed && !previous.text_mode && previous.ready && next->first!=UINT64_MAX &&
       next->first>previous.last && next->first-previous.last>1) {
        uint64_t gap=next->last-previous.last;
        unsigned lines=gap>=3000-32 ? 3000 : (unsigned)gap+32;
        *next=previous;
        failed=journal_snapshot(lines,next,hits);
        /* If even the expanded tail moved past the cursor, read the ring. */
        if(!failed && lines<3000 && next->first!=UINT64_MAX &&
           next->first>previous.last && next->first-previous.last>1) {
            *next=previous;
            failed=journal_snapshot(3000,next,hits);
        }
    }
    if(failed==1 && previous.text_mode) {
        *next=previous;
        failed=journal_snapshot(3000,next,hits);
        if(failed==1) {
            /* The CLI anchor has rolled out of the ring. Baseline as at startup. */
            *next=(dns_journal_cursor){0};
            failed=journal_snapshot(1,next,hits);
        }
    }
    return failed;
}

/* Neither platform guarantees a timeout utility. Bound this child even if the
 * logging service accepts its connection and then stops responding. */
static int journal_text_snapshot(int openwrt,int tail,dns_journal_cursor *next,dns_journal_hits *hits) {
    int output[2];
    if(pipe(output))return -1;
    pid_t child=fork();
    if(child==0) {
        close(output[0]);
        if(dup2(output[1],STDOUT_FILENO)<0)_exit(127);
        if(output[1]!=STDOUT_FILENO)close(output[1]);
        int quiet=open("/dev/null",O_WRONLY);
        if(quiet<0 || dup2(quiet,STDERR_FILENO)<0)_exit(127);
        if(quiet!=STDERR_FILENO)close(quiet);
        alarm(20);
        if(!openwrt)execl("/bin/ndmc","ndmc","-c","show log",(char *)NULL);
        else if(tail)execl("/sbin/logread","logread","-l","32",(char *)NULL);
        else execl("/sbin/logread","logread",(char *)NULL);
        _exit(127);
    }
    close(output[1]);
    if(child<0){close(output[0]);return -1;}
    FILE *f=fdopen(output[0],"r");
    int rc=-1,status;
    if(f){rc=journal_scan_text(f,openwrt,next,hits);fclose(f);}
    else close(output[0]);
    pid_t waited;
    do {waited=waitpid(child,&status,0);} while(waited<0 && errno==EINTR);
    return waited==child && WIFEXITED(status) && !WEXITSTATUS(status) ? rc : -1;
}

static int journal_cli_poll(int openwrt,dns_journal_cursor *next,dns_journal_hits *hits) {
    if(openwrt) {
        dns_journal_cursor previous=*next;
        int rc=journal_text_snapshot(1,1,next,hits);
        if(rc<=0)return rc;
        /* Busy ring: the last read record may precede this tail. */
        *next=previous;
    }
    return journal_text_snapshot(openwrt,0,next,hits)<0 ? -1 : 0;
}

static void *dns_journal_run(void *context) {
    dns_journal_reader *reader=context;
    int previous_mode=-1;
    while(!reader->halt) {
        dns_journal_cursor next=reader->cursor;
        dns_journal_hits hits={0};
        int failed=reader->openwrt || journal_api_poll(&next,&hits);
        int mode=0;
        if(failed) {
            next=reader->cursor;
            failed=journal_cli_poll(reader->openwrt,&next,&hits);
            mode=failed ? 2 : 1;
        }
        if(mode!=previous_mode) {
            if(mode==2)fprintf(stderr,"d2kc: DNS journal temporarily unavailable\n");
            else if(!reader->openwrt && mode==1)fprintf(stderr,"d2kc: DNS journal using ndmc fallback\n");
            else if(previous_mode>=0)fprintf(stderr,"d2kc: DNS journal using %s\n",reader->openwrt?"logread":"RCI");
            previous_mode=mode;
        }
        if(!failed) {
            reader->cursor=next;
            for(size_t i=0;i<hits.count;i++)
                if(write(reader->output,hits.names[i],sizeof hits.names[i])!=
                   (ssize_t)sizeof hits.names[i])break;
        }
        for(int i=0;i<50 && !reader->halt;i++) {
            struct timespec pause={0,100000000L};
            while(nanosleep(&pause,&pause)<0 && errno==EINTR && !reader->halt){}
        }
    }
    return NULL;
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
#ifdef D2K_TRUSTED_DOH
static void observe_dns_answer(void *context,const d2k_dns_answer *answer) {
    d2k_sched_dns_observe_answer(context,answer,now_ms());
    (void)d2k_provider_ips_observe(&provider_ips,answer,(uint64_t)time(NULL));
}
static void observe_dns_question(void *context,const char *name,uint16_t type) {
    d2k_sched_dns_observe_question(context,name,type,now_ms());
}
#endif

/* Атомарное сохранение: временный файл рядом, затем rename. Рядом, а не в
   /tmp — rename между файловыми системами не работает, а /opt и /tmp на
   роутере разные (tmpfs). */
static int save_atomic(const d2k_catalog *cat, const char *path,
                       char *err, size_t errcap) {
    return d2k_catalog_save_atomic(cat, path, err, errcap);
}

/* Печать планировщика. Со временем по стенным часам, а не монотонным: строку
   читает человек, и ему нужно сопоставить её с тем, что он делал. */
/* ПАМЯТЬ КОНТРОЛЛЕРА — В ТОЙ ЖЕ СВОДКЕ (задача 60). Поле 14.10.2026, Netis N6
   (mipsel, OpenWrt 25.12.5): d2kc 10,6 МБ сразу после перезапуска и 29,1 МБ
   через 1 д 9 ч, а датапат и туннель стояли на месте. Свою память d2kc не
   называл, и отличить заполнение ограниченных кэшей от утечки было не по
   чему. Теперь сводка несёт RSS, его пик, объём данных и число потоков, а
   рядом — размер каталога: рост памяти вместе с каталогом и без него —
   разные истории. Вне Linux /proc нет — память не печатается. */
static void self_mem(long *rss, long *hwm, long *data, long *thr) {
    *rss = *hwm = *data = *thr = -1;
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) { return; }
    char l[128];
    while (fgets(l, sizeof l, f)) {
        if (!strncmp(l, "VmRSS:", 6)) { *rss = strtol(l + 6, NULL, 10); }
        else if (!strncmp(l, "VmHWM:", 6)) { *hwm = strtol(l + 6, NULL, 10); }
        else if (!strncmp(l, "VmData:", 7)) { *data = strtol(l + 7, NULL, 10); }
        else if (!strncmp(l, "Threads:", 8)) { *thr = strtol(l + 8, NULL, 10); }
    }
    fclose(f);
}

static void sched_say(void *ctx, const char *line) {
    (void)ctx;
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    printf("%02d:%02d:%02d %s\n", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, line);
    fflush(stdout);
}

/* --- открытый HTTP: вставка провайдера → HTTPS имени (задача 51) -------- */

/* Поиск обхода самого HTTP (шаг 4): имена, у которых HTTPS нет. */
static d2k_httpsearch *g_hs;
static d2k_hs_runner *g_hr;
static int g_link_fd = -1;
static uint32_t g_probe_mark;
static const char *g_http_plans;

static void http_search_portal(const char *host, uint8_t family, const uint8_t *addr,
                               d2k_https_state st, int64_t now) {
    /* Только класс 3 — портал проходит как есть, HTTPS у имени нет. */
    if (!g_hs || !family || st == D2K_HTTPS_UNKNOWN || st == D2K_HTTPS_PROBING ||
        d2k_https_upgrade(st)) { return; }
    d2k_httpsearch_portal(g_hs, host, family, addr, now);
}

static int hs_open_port(void *ctx, uint8_t family, int *fd_out, uint16_t *sport_be) {
    (void)ctx;
    int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }
#ifdef SO_MARK
    /* Метка зондов: через очередь, к потоку достаётся только пробный план
       его порта, нового обнаружения он не рождает. */
    if (g_probe_mark &&
        setsockopt(fd, SOL_SOCKET, SO_MARK, &g_probe_mark, sizeof g_probe_mark) != 0) {
        close(fd);
        return -1;
    }
#endif
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t sl;
    if (family == 6) {
        ((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
        sl = sizeof(struct sockaddr_in6);
    } else {
        ((struct sockaddr_in *)&ss)->sin_family = AF_INET;
        sl = sizeof(struct sockaddr_in);
    }
    if (bind(fd, (struct sockaddr *)&ss, sl) != 0 ||
        getsockname(fd, (struct sockaddr *)&ss, &sl) != 0) {
        close(fd);
        return -1;
    }
    *sport_be = family == 6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                            : ((struct sockaddr_in *)&ss)->sin_port;
    *fd_out = fd;
    return 0;
}

static void hs_close_port(void *ctx, int fd) { (void)ctx; close(fd); }

static int hs_hex(const char *text, char *hex, size_t cap) {
    char err[200];
    if (d2k_plan_text_to_hex(text, hex, cap, err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: план HTTP не собрался: %s\n", err);
        return -1;
    }
    return 0;
}

static int hs_set_probe(void *ctx, const char *host, uint8_t family, uint16_t sport_be,
                        const char *text, const uint8_t trial[16]) {
    (void)ctx;
    static char hex[8192];
    char err[200];
    if (hs_hex(text, hex, sizeof hex) != 0) { return -1; }
    if (d2k_link_set_name_probe_trial(g_link_fd, host, 6, hex, D2K_LINK_SHAPE_HTTP, sport_be,
                                      family, trial, err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
        return -1;
    }
    return 0;
}

static int hs_del_probe(void *ctx, const char *host, uint8_t family, uint16_t sport_be) {
    (void)ctx;
    char err[200];
    if (d2k_link_del_name_probe_family(g_link_fd, host, 6, D2K_LINK_SHAPE_HTTP, sport_be,
                                       family, err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
        return -1;
    }
    return 0;
}

static int hs_set_plan(void *ctx, const char *host, uint8_t family, const char *text, const uint8_t token[16]) {
    (void)ctx;
    static char hex[8192];
    char err[200];
    if (hs_hex(text, hex, sizeof hex) != 0) { return -1; }
    if (d2k_link_set_name_bound(g_link_fd, host, 6, hex, D2K_LINK_SHAPE_HTTP, family, token,
                                 err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
        return -1;
    }
    return 0;
}

static int hs_del_plan(void *ctx, const char *host, uint8_t family, const d2k_binding_context *binding) {
    (void)ctx;
    if(!binding || binding->family!=family || !d2k_binding_known(binding))return -1;
    char err[200];
    if (d2k_link_del_name_bound(g_link_fd, host, 6, binding,
                                 err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
        return -1;
    }
    return 0;
}

static int hs_start(void *ctx, const d2k_hs_job *job) {
    (void)ctx;
    return d2k_hs_runner_start(g_hr, job);
}

static void hs_say(void *ctx, const char *line);
static void hs_changed(void *ctx) {
    (void)ctx;
    char err[300];
    if (g_hs && g_http_plans &&
        d2k_httpsearch_save(g_hs, g_http_plans, (int64_t)time(NULL), err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: планы HTTP не сохранены: %s\n", err);
    }
}

/* Датапат узнал вставку провайдера. Проверить HTTPS имени на том же адресе;
   подтверждённое, но забытое датапатом — повторить. */
static void http_portal(d2k_httpsprobe *hp, int fd, const d2k_ev *ev, int64_t now) {
    char line[512];
    uint32_t ttl = 0;
    int rc = d2k_httpsprobe_portal(hp, ev->name, ev->family, ev->high_ip, ev->code == 1,
                                   now, &ttl);
    if (rc == 0) {
        http_search_portal(ev->name, ev->family, ev->high_ip,
                           d2k_httpsprobe_state(hp, ev->name, now), now);
    }
    if (rc == 1) {
        snprintf(line, sizeof line, "HTTP %.255s: %s — проверяю HTTPS имени", ev->name,
                 ev->kind == D2K_EV_HTTP_RESPONSE ? "ответ перенаправляет на известный портал блокировки"
                                                : "провайдер подменяет ответ порталом блокировки");
        sched_say(NULL, line);
    } else if (rc == 2) {
        char err[200];
        if (d2k_link_set_https(fd, ev->name, ttl, err, sizeof err) != 0) {
            fprintf(stderr, "d2kc: %s\n", err);
        }
    }
}

static void http_push(int fd, const char *host, uint32_t ttl) {
    char err[200];
    if (d2k_link_set_https(fd, host, ttl, err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
    }
}

static void http_save(d2k_httpsprobe *hp, const char *path, int64_t now) {
    char err[300];
    if (path && d2k_httpsprobe_save(hp, path, now, (int64_t)time(NULL), err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: кэш HTTPS не сохранён: %s\n", err);
    }
}

static void http_probe_done(d2k_httpsprobe *hp, int fd, int64_t now, const char *cache_path) {
    d2k_httpsprobe_result r[8];
    size_t n, total = 0;
    while ((n = d2k_httpsprobe_done(hp, now, r, sizeof r / sizeof r[0])) > 0) {
        total += n;
        for (size_t i = 0; i < n; i++) {
            char line[1200];
            int up = d2k_https_upgrade(r[i].state);
            snprintf(line, sizeof line, "HTTP %.255s: %s (%.255s) — %s", r[i].host,
                     r[i].state == D2K_HTTPS_SERVED ? "TLS к 443 прошёл, имя в листе сертификата" :
                     r[i].state == D2K_HTTPS_TLS_BLOCKED ? "443 принимает, TLS срезан на линии" :
                     r[i].state == D2K_HTTPS_CLOSED ? "HTTPS у источника нет (443 закрыт)" :
                     r[i].state == D2K_HTTPS_OTHER_NAME ? "на 443 сертификат другого имени" :
                                                          "HTTPS не решён",
                     r[i].why,
                     up ? "вставку провайдера датапат заменит на 307 → https"
                        : "вставка провайдера идёт клиенту как есть: перевод на https "
                          "был бы тупиком");
            sched_say(NULL, line);
            if (up) { http_push(fd, r[i].host, r[i].ttl_s); }
            else { http_search_portal(r[i].host, r[i].family, r[i].addr, r[i].state, now); }
        }
    }
    if (total) { http_save(hp, cache_path, now); }
    static uint64_t lost_told;
    uint64_t lost = d2k_httpsprobe_lost(hp);
    if (lost != lost_told) {
        fprintf(stderr, "d2kc: ответов зонда HTTPS потеряно %llu (имена перепроверятся)\n",
                (unsigned long long)lost);
        lost_told = lost;
    }
}

static void hs_say(void *ctx, const char *line) { (void)ctx; sched_say(NULL, line); }

/* ПОРЧА ПРИМАНКИ, ИЗМЕРЕННАЯ НА ЭТОЙ ЛИНИИ: признаки порчи, на которой
   держатся подтверждённые TLS-планы коробок каталога (успехи > 0), —
   самые успешные первыми. Каждая — вопрос к HTTP-коробке той же линии
   вместо заготовки; tcpts/ipidzero HTTP-исполнитель не повторит, они
   отбрасываются (d2k_httpsearch_measured_poison). */
typedef struct { int succ; char spec[64]; } poison_seen;
static int poison_cmp(const void *a, const void *b) {
    return ((const poison_seen *)b)->succ - ((const poison_seen *)a)->succ;
}
static void hs_measured_poisons(d2k_httpsearch *hs, const d2k_catalog *cat) {
    poison_seen v[64];
    size_t n = 0;
    for (size_t b = 0; b < cat->n_boxes; b++) {
        const d2k_cat_box *box = &cat->boxes[b];
        for (size_t k = 0; k < box->n_plans && n < 64; k++) {
            const d2k_cat_plan *pl = &box->plans[k];
            if (!pl->text || pl->successes <= 0 || !pl->enabled ||
                !strstr(pl->text, "\nproto tcp tls\n")) { continue; }
            char specs[8][64];
            size_t m = d2k_hs_plan_poisons(pl->text, specs, 8);
            for (size_t i = 0; i < m && n < 64; i++) {
                snprintf(v[n].spec, sizeof v[n].spec, "%.63s", specs[i]);
                v[n].succ = pl->successes;
                n++;
            }
        }
    }
    qsort(v, n, sizeof v[0], poison_cmp);
    size_t taken = 0;
    for (size_t i = 0; i < n; i++) {
        if (d2k_httpsearch_measured_poison(hs, v[i].spec) == 0) { taken++; }
    }
    if (taken) { printf("d2kc: HTTP: измеренной порчи приманки с этой линии — %zu\n", taken); }
}

static void usage(void) {
    fprintf(stderr,
        "использование: d2kc --control <сокет> [--catalog <файл>] [--mark 0x2e] [--measure-mark 0x2f]\n"
        "  --control  управляющий сокет датапата (обязателен)\n"
        "  --catalog  где держать знание (умолчание /opt/d2k/catalog.json)\n"
        "  --live     куда писать вид для панели (умолчание — рядом с каталогом)\n"
        "  --log      куда писать журнал (умолчание — стандартный вывод)\n"
        "  --https-cache  кэш HTTPS имён для вставки провайдера (умолчание — рядом с каталогом)\n"
        "  --mark     метка verifier-зондов; они идут через NFQUEUE (умолчание 0x2d)\n"
        "  --synthesis-only: disable all legacy searches and catalog plans (requires SHADOW+NEWCHAIN)\n"
        "  --synthesis-https: opt in to bounded HTTPS synthesis in the working controller\n"
        "  --newchain-store PATH: opt-in working bindings from SHADOW (default disabled)\n"
        "  --shadow-queue ограниченная очередь TLS-подозрений для тени (умолчание — выключено)\n"
        "  --dns-upstreams снимок текущих DNS-апстримов; изменения подхватываются автоматически\n"
        "  --dns-addresses собственные наблюдения адресов апстримов, без смены TLS-имени\n"
        "  --dns-routes частный снимок разрешений для восстановления настроенных DNS\n"
        "  --measure-mark метка измерений; обычно обходит собственную NFQUEUE (по умолчанию --mark)\n");
}

static int offline_self_check(void) {
    static const uint8_t want[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    uint8_t got[32]; d2k_sha256((const uint8_t *)"abc", 3, got);
    return D2K_CTL_PROTO_VERSION == D2K_RUNTIME_WIRE && memcmp(got, want, 32) == 0 ? 0 : -1;
}

/* Bounded optional observer. Its state never participates in search decisions. */
/* НАБЛЮДЕНИЕ ПОТОКОВ ПО CONNTRACK (этап 37): счётчики записи по кортежу.
   Только чтение (GET); поток не меняется. Нет ctnetlink — наблюдения нет. */
static int g_ct_fd = -1;
static uint32_t g_ct_seq;
static int ct_query_live(const d2k_ct_tuple *t, d2k_ct_info *out) {
    if (g_ct_fd < 0) return -1;
    if (++g_ct_seq == 0) g_ct_seq = 1;
    int rc = d2k_ct_query_info_fd(g_ct_fd, g_ct_seq, t, out);
    /* 2 — запись есть, счётчиков нет (учёт conntrack выключен): это «данных
       нет» для наблюдения (counters_known = 0), а не «недоступно». */
    if (rc == 2) { out->counters_known = 0; return 0; }
    return rc == 0 ? 0 : rc == 1 ? 1 : -1;
}

/* Соседи по адресу (этап 38): одно перечисление conntrack семейства — только
   чтение. Сосед — запись того же транспорта к тому же адресу и порту
   сервера, кроме самого потока. Счётчики — за ВСЮ жизнь записи (этап 45):
   ответ виден когда-то за её жизнь, не «сейчас». Ответ засчитывается только
   доказанный: у UDP — хоть одна датаграмма оттуда; у TCP — байты сверх
   наибольших возможных заголовков (IPv4: 60 IP + 60 TCP); у IPv6 заголовки
   расширения не ограничены — данные байтами не доказываются. Иначе — «не
   доказан» (ACK с опциями и короткий ответ неразличимы), а не «ответа нет». */
typedef struct { const d2k_ct_tuple *self; unsigned flows, judged, answered; } peers_ctx;
static int peers_cb(void *ctx, const d2k_ct_tuple *t, const d2k_ct_info *i) {
    peers_ctx *c = ctx;
    const d2k_ct_tuple *me = c->self;
    size_t al = me->family == 6 ? 16 : 4;
    if (t->family != me->family || t->proto != me->proto || memcmp(t->dst, me->dst, al) ||
        memcmp(t->dport_be, me->dport_be, 2)) return 0;
    if (!memcmp(t->src, me->src, al) && !memcmp(t->sport_be, me->sport_be, 2)) return 0;
    c->flows++;
    if (!i->counters_known) return 0;   /* учёт выключен — ответ не судим */
    c->judged++;
    if (me->proto == 6 ? me->family != 6 && i->reply_bytes > i->reply_pkts * 120u : i->reply_pkts > 0)
        c->answered++;
    return 0;
}
static int ct_peers_live(const d2k_ct_tuple *self, unsigned *flows, unsigned *judged, unsigned *answered) {
    if (g_ct_fd < 0) return -1;
    peers_ctx c = { self, 0, 0, 0 };
    if (++g_ct_seq == 0) g_ct_seq = 1;
    if (d2k_ct_dump_fd(g_ct_fd, g_ct_seq, self->family, peers_cb, &c, 200) < 0) return -1;
    *flows = c.flows; *judged = c.judged; *answered = c.answered;
    return 0;
}

static d2k_diag *diagnostics;
static void diagnostic_event(void *ctx,const d2k_diag_event *e) {
    (void)ctx;d2k_diag_record(diagnostics,e);
}
static void diagnostic_tick(d2k_sched *s,int64_t now) {
    static int64_t checked=-1000,written=-60000;
    if(now>=checked && now-checked<1000)return;
    checked=now;
    if(!d2k_diag_enabled(D2K_DIAG_DIR)) {
        /* Finish cleanup if an export raced the panel's disable operation. */
        if(diagnostics) (void)d2k_diag_toggle(D2K_DIAG_DIR,0);
        d2k_diag_free(diagnostics);diagnostics=NULL;
        d2k_sched_diagnostics(s,NULL,NULL);
        d2k_httpsearch_diagnostics(g_hs,NULL,NULL);
        return;
    }
    if(!diagnostics) {
        diagnostics=d2k_diag_new();if(!diagnostics)return;
        d2k_sched_diagnostics(s,diagnostic_event,NULL);
        d2k_httpsearch_diagnostics(g_hs,diagnostic_event,NULL);
        written=now-60000;
    }
    if(now>=written && now-written<60000)return;
    written=now;
    d2k_diag_counts counts;d2k_sched_diagnostic_counts(s,&counts);
    d2k_httpsearch_diagnostic_counts(g_hs,&counts);
    d2k_diag_sample(diagnostics,now,&counts,"/proc","/opt/d2k/run");
    char path[512],tmp[512];
    if(d2k_diag_path(path,sizeof path,D2K_DIAG_DIR,"report.json") ||
       d2k_diag_path(tmp,sizeof tmp,D2K_DIAG_DIR,"report.new"))return;
    /* Directory is private; interrupted writes are never served by the panel. */
    unlink(tmp);
    int fd=open(tmp,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return;
    FILE *f=fdopen(fd,"w");if(!f){close(fd);unlink(tmp);return;}
    int bad=d2k_diag_write(diagnostics,f);long size=ftell(f);
    if(size<0||(unsigned long)size>D2K_DIAG_REPORT_MAX)bad=1;
    if(fclose(f))bad=1;
    if(bad||!d2k_diag_enabled(D2K_DIAG_DIR)||rename(tmp,path))unlink(tmp);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) { printf("d2kc release=%s wire=%u\n", D2K_RELEASE_ID, D2K_RUNTIME_WIRE); return 0; }
    int offline = d2k_runtime_offline(argc, argv, "d2kc", offline_self_check);
    if (offline >= 0) return offline;
    const char *health_path = "/tmp/d2k/d2kc.health";
    const char *sock = NULL;
    const char *catpath = "/opt/d2k/catalog.json";
    const char *livepath = NULL;
    const char *logpath = NULL;
    const char *https_path = NULL;
    uint32_t mark = 0x2d;
    uint32_t measure_mark = 0;
    int have_measure_mark = 0;
    const char *doh_path = NULL;
    const char *dns_configuration = NULL,*dns_addresses=NULL,*dns_routes=NULL;
    const char *force_path = NULL;
    const char *shadow_queue = NULL,*newchain_store=NULL;
    const char *synthesis_https_env=getenv("D2K_SYNTHESIS_HTTPS");
    int synthesis_only=0,synthesis_https=synthesis_https_env && !strcmp(synthesis_https_env,"1");

    for (int i = 1; i < argc; i++) {
        const char *f = argv[i];
        if(!strcmp(f,"--synthesis-only")) {synthesis_only=1;}
        else if(!strcmp(f,"--synthesis-https")) {synthesis_https=1;}
        else if (strcmp(f, "--health-file") == 0 && i + 1 < argc) { health_path = argv[++i]; }
        else if (strcmp(f, "--control") == 0 && i + 1 < argc) { sock = argv[++i]; }
        else if (strcmp(f, "--newchain-store") == 0 && i + 1 < argc) { newchain_store = argv[++i]; }
        else if (strcmp(f, "--shadow-queue") == 0 && i + 1 < argc) { shadow_queue = argv[++i]; }
        else if (strcmp(f, "--force-targets") == 0 && i + 1 < argc) { force_path = argv[++i]; }
        else if (strcmp(f, "--doh-targets") == 0 && i + 1 < argc) { doh_path = argv[++i]; }
        else if (strcmp(f,"--dns-upstreams")==0 && i+1<argc) {dns_configuration=argv[++i];}
        else if (strcmp(f,"--dns-addresses")==0 && i+1<argc) {dns_addresses=argv[++i];}
        else if (strcmp(f,"--dns-routes")==0 && i+1<argc) {dns_routes=argv[++i];}
        else if (strcmp(f, "--catalog") == 0 && i + 1 < argc) { catpath = argv[++i]; }
        else if (strcmp(f, "--live") == 0 && i + 1 < argc) { livepath = argv[++i]; }
        else if (strcmp(f, "--log") == 0 && i + 1 < argc) { logpath = argv[++i]; }
        else if (strcmp(f, "--https-cache") == 0 && i + 1 < argc) { https_path = argv[++i]; }
        else if (strcmp(f, "--mark") == 0 && i + 1 < argc) {
            mark = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(f, "--measure-mark") == 0 && i + 1 < argc) {
            measure_mark = (uint32_t)strtoul(argv[++i], NULL, 0);
            have_measure_mark = 1;
        } else {
            usage();
            return 2;
        }
    }
    if (!sock) { usage(); return 2; }
    if(synthesis_only && (!shadow_queue || !newchain_store)) {
        fprintf(stderr,"d2kc: SYNTHESIS_ONLY requires SHADOW and NEWCHAIN\n");return 2;
    }
    if(newchain_store && !shadow_queue) {fprintf(stderr,"d2kc: NEWCHAIN requires SHADOW (--shadow-queue)\n");return 2;}

    /* Тот же приём, что в d2kd.c и ctlprobe.c: процесс не имеет права умирать
       оттого, что собеседник отвалился между записями. */
    /* Журнал открываем САМИ, а не перенаправлением снаружи: start-stop-daemon
       с -b потоки потомка не наследует — проверено на роутере, файл оставался
       нулевой длины при исправно работающем движке. Ровно то же было у
       Go-стороны, и там это тоже кончилось ключом. */
    if (logpath) {
        FILE *lf = freopen(logpath, "a", stdout);
        if (!lf) {
            fprintf(stderr, "d2kc: не открыть журнал %s: %s\n", logpath, strerror(errno));
            return 1;
        }
        (void)dup2(fileno(stdout), fileno(stderr));
        setvbuf(stdout, NULL, _IOLBF, 0);
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = {0};
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = on_signal;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
#ifdef D2K_TRUSTED_DOH
    d2k_verify_doh_set_tls(d2k_doh_trusted_tls_open);
    d2k_verify_page_set_tls(d2k_http1_trusted_tls_open);
    d2k_verify_dot_set_probe(d2k_dot_trusted_probe);
    d2k_verify_plain_dns_set_probe(d2k_plain_dns_probe);
#endif

    d2k_catalog cat;
    memset(&cat, 0, sizeof cat);
    char err[512];
    if (d2k_catalog_load(catpath, &cat, err, sizeof err) != 0) {
        /* Каталога может не быть вовсе — это первый запуск, а не отказ.
           Отличить «нет файла» от «файл битый» обязательно: во втором случае
           молча начать с чистого листа значило бы потерять всё знание и не
           сказать об этом. */
        if (access(catpath, F_OK) == 0) {
            fprintf(stderr, "d2kc: каталог %s не разобрался: %s\n", catpath, err);
            return 1;
        }
        memset(&cat, 0, sizeof cat);
        printf("d2kc: каталога %s нет — начинаю с пустого\n", catpath);
    }

    if(!cat.groups) cat.groups=calloc(1,sizeof *cat.groups);
    if(!cat.groups) {
        fprintf(stderr,"d2kc: нет памяти под наблюдения семейств\n");
        d2k_catalog_free(&cat);return 1;
    }
    /* Без рабочего файла на флеше (диск полон, каталог только для чтения,
       нет дескриптора или отображения) обучение семейств ОТКЛЮЧЕНО, а не
       перенесено в память: история остаётся в каталоге как есть, точные
       подтверждённые планы работают. Отказ запуска стоил бы их всех. */
    if(d2k_group_store_open(cat.groups,catpath))
        fprintf(stderr,"d2kc: ДЕГРАДАЦИЯ: файловое хранилище наблюдений семейств рядом с %s "
                       "не создалось — обучение семейств и их области отключены, история "
                       "семейств в каталоге сохраняется без изменений; точные планы работают\n",
                catpath);
    if(cat.groups->store_failed && cat.groups->preserved_len && !cat.groups->preserved_map)
        fprintf(stderr,"d2kc: ДЕГРАДАЦИЯ: историю семейств в %s не удалось отобразить для "
                       "обратной записи — сохранение каталога отключено, файл на флеше не "
                       "меняется; точные планы работают\n", catpath);
    int fd = d2k_link_open(sock, err, sizeof err);
    if (fd < 0) {
        fprintf(stderr, "d2kc: связь с датапатом %s: %s\n", sock, err);
        d2k_catalog_free(&cat);
        return 1;
    }

    /* Do not send catalog commands or start measurements before the peer
       proves it uses this key layout. Old greetings have shorter keys and
       cannot be safely interpreted as version-4 traffic. */
    d2k_ev greeting;
    if (d2k_link_greeting(fd, 2000, &greeting, err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
        d2k_link_close(fd);
        d2k_catalog_free(&cat);
        return 1;
    }

    d2k_sched *s = d2k_sched_new(&cat, fd, mark);
    if (!s) {
        fprintf(stderr, "d2kc: планировщик не завёлся: %s\n",
                strerror(errno ? errno : EIO));
        d2k_link_close(fd);
        d2k_catalog_free(&cat);
        return 1;
    }
    char family_path[512];
    const char *family_slash=strrchr(catpath,'/');
    size_t family_dir=family_slash?(size_t)(family_slash-catpath+1):0;
    if(family_dir+sizeof "ipv4-fallback"<=sizeof family_path) {
        memcpy(family_path,catpath,family_dir);
        memcpy(family_path+family_dir,"ipv4-fallback",sizeof "ipv4-fallback");
        d2k_sched_family_path(s,family_path);
    }
#ifdef D2K_TRUSTED_DOH
    d2k_sched_set_plain_trial(s,d2k_plain_dns_prepare,d2k_plain_dns_run_trial);
#endif
    if(d2k_sched_set_shadow(s,shadow_queue)) {
        fprintf(stderr,"d2kc: путь очереди тени слишком длинный\n");
        d2k_sched_free(s);d2k_link_close(fd);d2k_catalog_free(&cat);return 2;
    }
    d2k_sched_set_measure_mark(s, have_measure_mark ? measure_mark : mark);
    if (doh_path && d2k_sched_doh_load(s,doh_path)<0) {
        fprintf(stderr,"d2kc: invalid DoH targets file\n"); return 2;
    }
    if (force_path && d2k_sched_force_load(s,force_path)<0) {
        fprintf(stderr,"d2kc: invalid force targets file\n"); return 2;
    }
    int dns_reload_error=0;
    if(dns_configuration && d2k_sched_doh_discover(s,dns_configuration,dns_addresses)<0) {
        dns_reload_error=1;
        fprintf(stderr,"d2kc: DNS configuration snapshot rejected; previous registry retained\n");
    }
    g_ct_fd = d2k_ct_open();
    if (g_ct_fd >= 0 && d2k_ct_probe_fd(g_ct_fd, ++g_ct_seq, 200) == 1) {
        d2k_sched_set_ct_query(s, ct_query_live);
        d2k_sched_set_ct_peers(s, ct_peers_live);
        printf("d2kc: наблюдение потоков по conntrack включено (только чтение счётчиков)\n");
    } else {
        printf("d2kc: conntrack по netlink недоступен — наблюдения скорости и застоя потоков нет\n");
        if (g_ct_fd >= 0) { close(g_ct_fd); g_ct_fd = -1; }
    }
    d2k_sched_set_send_cap(s, greeting.send_maxlen);
    d2k_raw_set_segment_max(d2k_arm_segment(greeting.send_maxlen));

    d2k_sched_set_say(s, sched_say, NULL);

    /* Зонд HTTPS — с меткой зондов контроллера: через очередь, с уже
       подтверждённым планом имени, без нового обнаружения. */
    d2k_httpsprobe *hp = synthesis_only?NULL:d2k_httpsprobe_new(mark, NULL);
    if (!hp && !synthesis_only) {
        fprintf(stderr, "d2kc: зонд HTTPS не завёлся — вставка провайдера в HTTP "
                        "будет идти клиенту как есть\n");
    }
#ifdef D2K_TRUSTED_DOH
    {
        const char *slash=strrchr(catpath,'/');
        size_t dirlen=slash?(size_t)(slash-catpath+1):0;
        if(dirlen<sizeof provider_ips_path-20) {
            memcpy(provider_ips_path,catpath,dirlen);
            strcpy(provider_ips_path+dirlen,"provider-ips");
            (void)d2k_provider_ips_load(&provider_ips,provider_ips_path,(uint64_t)time(NULL));
        }
    }
#endif
    /* Кэш HTTPS переживает перезапуск (ревью I2): иначе первый заход после
       каждого перезапуска снова видел бы портал. Рядом с каталогом. */
    char https_buf[D2K_CATALOG_PATH_MAX + 32];
    if (!https_path) {
        const char *slash = strrchr(catpath, '/');
        size_t dirlen = slash ? (size_t)(slash - catpath + 1) : 0;
        if (dirlen < sizeof https_buf - 20) {
            memcpy(https_buf, catpath, dirlen);
            snprintf(https_buf + dirlen, sizeof https_buf - dirlen, "https-cache.txt");
            https_path = https_buf;
        }
    }
    /* Поиск обхода HTTP и его подтверждённые планы — рядом с каталогом. */
    g_link_fd = fd;
    g_probe_mark = mark;
    static char plans_buf[D2K_CATALOG_PATH_MAX + 32];
    {
        const char *slash = strrchr(catpath, '/');
        size_t dirlen = slash ? (size_t)(slash - catpath + 1) : 0;
        if (dirlen < sizeof plans_buf - 20) {
            memcpy(plans_buf, catpath, dirlen);
            snprintf(plans_buf + dirlen, sizeof plans_buf - dirlen, "http-plans.txt");
            g_http_plans = plans_buf;
        }
    }
    g_hr = synthesis_only?NULL:d2k_hs_runner_new();
    if (g_hr) {
        d2k_hs_ops ops = {hs_open_port, hs_close_port, hs_set_probe, hs_del_probe, hs_set_plan,
                          hs_del_plan, hs_start, hs_say, hs_changed, NULL};
        g_hs = d2k_httpsearch_new(&ops);
        if (g_hs) { hs_measured_poisons(g_hs, &cat); }
    }
    if (!g_hs && !synthesis_only) {
        fprintf(stderr, "d2kc: поиск обхода HTTP не завёлся — вставка в HTTP без HTTPS "
                        "останется как есть\n");
    } else if (g_hs && g_http_plans) {
        size_t nl = 0;
        char herr[300];
        if (d2k_httpsearch_load(g_hs, g_http_plans, &nl, herr, sizeof herr) != 0) {
            fprintf(stderr, "d2kc: планы HTTP не прочитаны: %s\n", herr);
        } else if (nl) {
            printf("d2kc: планы HTTP %s: имён %zu поставлено датапату\n", g_http_plans, nl);
        }
    }
    if (hp && https_path) {
        static d2k_httpsprobe_result push[D2K_HTTPSPROBE_NAMES];
        size_t np = 0, nl = 0;
        char herr[300];
        if (d2k_httpsprobe_load(hp, https_path, now_ms(), (int64_t)time(NULL), push,
                                D2K_HTTPSPROBE_NAMES, &np, &nl, herr, sizeof herr) != 0) {
            fprintf(stderr, "d2kc: кэш HTTPS не прочитан, начинаю с пустого: %s\n", herr);
        } else {
            for (size_t i = 0; i < np; i++) { http_push(fd, push[i].host, push[i].ttl_s); }
            if (nl) {
                printf("d2kc: кэш HTTPS %s: имён %zu, к датапату с 307 — %zu\n",
                       https_path, nl, np);
            }
        }
    }

    /* ИЗМЕРИТЕЛЬ TCP — ПЕРЕНЕСЁННЫЙ «ПОИСК ПО ДОМЕНУ», а не прежнее дерево.
     *
     * Прежнее (core/verdict.c) отвечало только на вопрос «какого класса
     * блокировка» и на этом кончалось: чем брать коробку, выяснял уже
     * планировщик отдельными вопросами через датапат. Перенесённый отвечает на
     * оба вопроса сразу и своими сокетами — фаза свойств и перебор отравлений
     * живут внутри того же вызова, — и возвращает НАЙДЕННОЕ ПЛЕЧО. Сверка с
     * оригиналом на живой линии: docs/field/2026-09-14-port-correspondence.md.
     *
     * Крючок, а не правка планировщика: тесты подменяют эту же точку, чтобы
     * утверждать развилку по транспорту, не выходя в сеть. */
    synthesis_catalog_path=catpath;
    /* Keep research searches out of the restored working controller. An
       experimental result must not delay or short-circuit its measurements. */
    d2k_detect_synthesis_set(synthesis_only ? synthesis_session_provider :
                             synthesis_https ? synthesis_https_provider : NULL);
    d2k_sched_application_synthesis_hook=synthesis_only ? application_synthesis_dispatch : NULL;
    d2k_sched_tcp_hook = d2k_detect_sched_tcp;
    /* Свои подтверждённые планы — до полного замера (задача 32, ТЗ §3.4):
     * базовый вопрос донора отдельно, тем же измерителем. */
    d2k_sched_tcp_base_hook = d2k_detect_sched_tcp_base;
    /* Дополнения полного прогона — ответ уже снятой базы, белое имя сети
     * приманкой и знание о коробке из каталога — едут в d2k_sched_tcp_extra
     * через тот же крючок. Прежде у каждого был свой: четыре сигнатуры и
     * каскад выбора в планировщике (23.10.2026). QUIC свой путь сохраняет
     * (core/quicprobe.c). */
    /* Перепроверка адреса с вердиктом address — сначала один нейтральный
     * байт, до любого триггера (задача 54). */
    d2k_sched_tcp_ack_hook = d2k_detect_sched_tcp_ack;
    d2k_sched_quic_base_hook = d2k_quic_base;
    d2k_sched_quic_seeded_hook = d2k_quic_run_seeded;

    /* Знание из каталога — датапату СРАЗУ: он состояния между запусками не
       хранит, и без этого прохода каждая уже изученная цель начинала бы поиск
       заново. Сам проход идёт порциями в цикле ниже — залпом он создавал бы
       окно, в котором датапату некуда сказать про живой трафик. */
    if(d2k_sched_set_newchain(s,newchain_store)) {
        fprintf(stderr,"d2kc: NEWCHAIN store path rejected\n");d2k_sched_free(s);d2k_link_close(fd);d2k_catalog_free(&cat);return 2;
    }
    if(d2k_sched_set_synthesis_only(s,synthesis_only)) {
        fprintf(stderr,"d2kc: SYNTHESIS_ONLY dependencies rejected\n");return 2;
    }
    if(synthesis_only)printf("d2kc: SYNTHESIS_ONLY=1: старый поиск и восстановление каталога отключены; цели владельца — в DIRECT тени\n");
    else if(synthesis_https)printf("d2kc: SYNTHESIS_HTTPS=1: HTTPS-опыты включены в рабочем контроллере\n");
    /* Restore acknowledged bindings before admitting client events or old
       catalog work. Five seconds bounds startup on a broken control peer;
       unresolved writes stay protected and retry through normal polling. */
    int64_t restore_until=now_ms()+5000;
    while(d2k_sched_newchain_pending(s) && now_ms()<restore_until) {
        d2k_ev e;int rc=d2k_link_next(fd,&e,200,err,sizeof err);
        if(rc<0)break;
        if(rc==0 && (e.kind==D2K_EV_ACK || e.kind==D2K_EV_PROTO))d2k_sched_event(s,&e);
    }
    if(d2k_sched_newchain_pending(s))sched_say(NULL,"NEWCHAIN: restoration awaiting datapath ACK; pending ownership retained");
    (void)d2k_sched_sync(s);

    printf("d2kc: запущен, сокет %s, каталог %s (%zu коробок), метка 0x%x\n",
           sock, catpath, cat.n_boxes, (unsigned)mark);
    fflush(stdout);

    /* Счётчики событий. Заведены измеренной нуждой: первый живой прогон
       молчал, и отличить «датапат не подозревает» от «связь есть, а событий не
       идёт» было нечем — а это разные беды, одна про линию, другая про нас. */
    unsigned long seen_events = 0, seen_hello = 0, seen_suspect = 0;
    unsigned long seen_exchange = 0, seen_applied = 0, seen_refused = 0;
    /* Версия провода: объявлена ли вообще и совпала ли. Оба «нет» означают
       «мы не знаем, с кем говорили», и оба обязаны быть слышны. */
    int proto_seen = 1, proto_bad = 0;
    int64_t last_report = now_ms();

    /* Путь вида для панели: рядом с каталогом, если не задан явно. Панель
       читает его и больше ничего о движке не знает (см. d2k_sched_write_live). */
    char livebuf[D2K_CATALOG_PATH_MAX + 16];
    if (!livepath) {
        const char *slash = strrchr(catpath, '/');
        size_t dirlen = slash ? (size_t)(slash - catpath + 1) : 0;
        if (dirlen < sizeof livebuf - 10) {
            memcpy(livebuf, catpath, dirlen);
            snprintf(livebuf + dirlen, sizeof livebuf - dirlen, "live.json");
            livepath = livebuf;
        }
    }
    int64_t last_live = 0;

    int64_t last_tick = now_ms(), last_save = last_tick;
#ifdef D2K_TRUSTED_DOH
    int64_t last_ip_save=last_tick;
#endif
    int64_t last_dns_save=0;
    uint64_t saved_catalog_revision = 0; /* load migrations and startup changes still need saving */
    int link_lost = 0;

    int64_t dns_reload_at=0;
    int journal_pipe[2]={-1,-1};pthread_t journal_thread;int journal_started=0;
    dns_journal_reader journal_reader={.output=-1};
    journal_reader.openwrt=access("/etc/openwrt_release",F_OK)==0 && access("/bin/ndmc",X_OK)!=0;
    if(dns_configuration && (journal_reader.openwrt || access("/bin/ndmc",X_OK)==0) && pipe(journal_pipe)>=0) {
        journal_reader.output=journal_pipe[1];
        int flags=fcntl(journal_pipe[0],F_GETFL,0);
        int output_flags=fcntl(journal_pipe[1],F_GETFL,0);
        if(flags>=0 && output_flags>=0 &&
           !fcntl(journal_pipe[0],F_SETFL,flags|O_NONBLOCK) &&
           !fcntl(journal_pipe[1],F_SETFL,output_flags|O_NONBLOCK) &&
           !pthread_create(&journal_thread,NULL,dns_journal_run,&journal_reader))journal_started=1;
        if(!journal_started){close(journal_pipe[0]);close(journal_pipe[1]);journal_pipe[0]=journal_pipe[1]=-1;}
    }
#ifdef D2K_TRUSTED_DOH
    struct d2k_dns_capture *dns_capture=dns_configuration ? d2k_dns_capture_open() : NULL;
#endif
    while (!stop_asked) {
        int64_t dns_now=now_ms();
#ifdef D2K_TRUSTED_DOH
        d2k_dns_capture_drain_full(dns_capture,dns_now,observe_dns_question,observe_dns_answer,s);
        if(provider_ips.dirty && provider_ips_path[0] && dns_now-last_ip_save>=100) {
            if(d2k_provider_ips_save(&provider_ips,provider_ips_path,(uint64_t)time(NULL)))
                fprintf(stderr,"d2kc: provider IP registry save failed\n");
            last_ip_save=dns_now;
        }
#endif
        if(dns_configuration && dns_now>=dns_reload_at) {
            int failed=d2k_sched_doh_discover(s,dns_configuration,dns_addresses)<0;
            if(failed && !dns_reload_error)
                fprintf(stderr,"d2kc: DNS configuration snapshot rejected; previous registry retained\n");
            dns_reload_error=failed;dns_reload_at=dns_now+1000;
            if(dns_routes && d2k_sched_dns_routes(s,dns_routes)<0)
                fprintf(stderr,"d2kc: DNS routing snapshot could not be published\n");
            if(dns_routes) {
                char applied[4096+sizeof ".applied"];
                int n=snprintf(applied,sizeof applied,"%s.applied",dns_routes);
                if(n>0 && (size_t)n<sizeof applied)d2k_sched_dns_routed(s,applied);
            }
        }
        (void)d2k_runtime_heartbeat(health_path, greeting.release_id, 1, 1, 1);
        struct pollfd pfd[5];
        pfd[0].fd = fd;                       pfd[0].events = POLLIN; pfd[0].revents = 0;
        pfd[1].fd = d2k_sched_wake_fd(s);     pfd[1].events = POLLIN; pfd[1].revents = 0;
        pfd[2].fd = d2k_httpsprobe_wake_fd(hp); pfd[2].events = POLLIN; pfd[2].revents = 0;
        pfd[3].fd = d2k_hs_runner_wake_fd(g_hr); pfd[3].events = POLLIN; pfd[3].revents = 0;
        pfd[4].fd = journal_pipe[0];           pfd[4].events = POLLIN; pfd[4].revents = 0;

        int64_t t = now_ms();
        int wait = (int)(TICK_MS - (t - last_tick));
        if (wait < 0) { wait = 0; }
        if (d2k_sched_sync_pending(s)) {
            /* Пока проход по каталогу не закончен, круг цикла не ждёт: каждая
               порция обязана идти сразу за чтением событий. */
            wait = 0;
        }
        int pr = poll(pfd, 5, wait);
        if (pr < 0 && errno != EINTR) {
            fprintf(stderr, "d2kc: poll: %s\n", strerror(errno));
            break;
        }
        if(pr>0 && (pfd[4].revents&POLLIN)) {
            char domain[256];
            while(read(journal_pipe[0],domain,sizeof domain)==sizeof domain) {
                domain[sizeof domain-1]=0;
                (void)d2k_sched_dns_journal_error(s,domain);
            }
        }

        if (pr > 0 && (pfd[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            /* Читаем всё, что уже пришло, а не по одному событию за круг:
               датапат за секунду присылает сотни наблюдений, и круг poll на
               каждое был бы чистой тратой. Нулевой потолок — «только то, что
               уже в буфере». */
            for (;;) {
                int drained = 0;
                for (; drained < 256; drained++) {
                    d2k_ev ev;
                    err[0] = '\0';
                    int lrc = d2k_link_next(fd, &ev, 0, err, sizeof err);
                    if (lrc != 0) {
                        /* Кадр прочитан, но не принят (чужой формат, нет
                           обязательных полей) — он пропущен, канал цел. Молчать
                           нельзя: иначе невозможно отличить потерянный ACK от
                           отвергнутого (зависший cleanup, задание 02 28.10). Обрыв
                           связи сюда не попадает — о нём скажет peer_closed ниже. */
                        if (lrc < 0 && err[0] && d2k_link_peer_closed(fd) != 1) {
                            fprintf(stderr, "d2kc: событие датапата отвергнуто и пропущено: %s\n", err);
                        }
                        break;
                    }
                    seen_events++;
                    switch (ev.kind) {
                    case D2K_EV_HELLO:    seen_hello++; break;
                    case D2K_EV_SUSPECT:  seen_suspect++; break;
                    case D2K_EV_EXCHANGE: seen_exchange++; break;
                    case D2K_EV_APPLIED:  seen_applied++; break;
                    case D2K_EV_REFUSED:  seen_refused++; break;
                    case D2K_EV_HTTP_RESPONSE: {
                        static const uint8_t no_trial[16] = {0};
                        (void)d2k_httpsearch_control(g_hs,&ev,now_ms());
                        /* Late portals lack timing proof for replacement, but
                           must still trigger direct verification on a clean
                           catalog. A probe's result belongs to its own job. */
                        if (hp && ev.code == 3 && ev.transport == 6 && ev.high_port == 80 &&
                            !memcmp(ev.trial_id, no_trial, sizeof no_trial))
                            http_portal(hp, fd, &ev, now_ms());
                        break;
                    }
                    case D2K_EV_HTTP_PORTAL:
                        (void)d2k_httpsearch_control(g_hs,&ev,now_ms());
                        if (hp) { http_portal(hp, fd, &ev, now_ms()); }
                        break;
                    default: break;
                    }
                    /* Поиск HTTP: подтверждение своей пробы и исполнение
                       своего плана (сверка по trial ID и Plan ID). */
                    if(ev.kind==D2K_EV_ACK)(void)d2k_httpsearch_control(g_hs,&ev,now_ms());
                    if (g_hs && ev.kind == D2K_EV_ACK && ev.code == D2K_CMD_SET_NAME_PROBE) {
                        d2k_httpsearch_ack(g_hs, ev.trial_id, ((ev.num >> 8) & 0xffu) == 1u, now_ms());
                    } else if (g_hs && ev.kind == D2K_EV_APPLIED) {
                        (void)d2k_httpsearch_control(g_hs,&ev,now_ms());
                    }
                    switch (ev.kind) {
                    case D2K_EV_PROTO:
                        /* ВЕРСИЯ ПРОВОДА. Чужая — работать нельзя: смешанная пара
                           не падает и не ругается, она молча не даёт
                           подтверждений, и всё измерение уходит в никуда. Лучше
                           громкий отказ сейчас, чем полдня пустых замеров. */
                        proto_seen = 1;
                        /* Предел отправки едет тем же событием и нужен сборке
                           планов: тело фальшивки обязано помещаться в канал. */
                        d2k_sched_set_send_cap(s, ev.send_maxlen);
                        d2k_raw_set_segment_max(d2k_arm_segment(ev.send_maxlen));
                        if (ev.num != (uint32_t)D2K_CTL_PROTO_VERSION) {
                            fprintf(stderr,
                                "d2kc: датапат говорит на версии протокола %u, наша %u — "
                                "работать с такой парой нельзя: подтверждений она не даст, "
                                "а измерения будут пустыми. Обновите d2kd, d2kc и d2kask "
                                "вместе, из одного дерева.\n",
                                (unsigned)ev.num, (unsigned)D2K_CTL_PROTO_VERSION);
                            proto_bad = 1;
                        }
                        break;
                    default: break;
                    }
                    d2k_sched_event(s, &ev);
                }
                /* В обычном потоке ограничиваем круг 256 событиями, чтобы
                   таймеры и планировщик не голодали. После закрытия peer
                   очередь конечна: дочитываем её до EOF, иначе последняя
                   пачка наблюдений теряется перед сохранением каталога. */
                if (drained < 256 || d2k_link_peer_closed(fd) != 1) { break; }
            }
        }
        if (hp && pr > 0 && (pfd[2].revents & POLLIN)) {
            http_probe_done(hp, fd, now_ms(), https_path);
        }
        if (g_hs && pr > 0 && (pfd[3].revents & POLLIN)) {
            d2k_hs_result hr;
            if (d2k_hs_runner_done(g_hr, &hr)) { d2k_httpsearch_result(g_hs, &hr, now_ms()); }
        }
        if (g_hs) { d2k_httpsearch_tick(g_hs, now_ms()); }
        /* Таблица датапата вытесняет давно не нужные записи (LRU): свои
           HTTP-планы ставятся заново раз в 30 мин (ревью M-5). */
        static int64_t last_http_push;
        if (g_hs && now_ms() - last_http_push >= 30ll * 60 * 1000) {
            if (last_http_push) { d2k_httpsearch_push_all(g_hs); }
            last_http_push = now_ms();
        }
        /* PID живого контроллера ещё не означает, что он связан с датапатом:
           закрытый AF_UNIX peer даёт POLLHUP один раз. Не выходя здесь,
           контроллер продолжал бы публиковать live.json с linked=true. */
        int peer_closed = d2k_link_peer_closed(fd);
        if (peer_closed != 0) {
            if (peer_closed < 0) {
                fprintf(stderr, "d2kc: проверка связи с датапатом: %s\n",
                        strerror(errno));
            } else {
                fprintf(stderr, "d2kc: связь с датапатом оборвалась\n");
            }
            link_lost = 1;
            break;
        }
        if (proto_bad) { break; }

        /* Порция прохода по каталогу — ПОСЛЕ чтения событий и до следующего
           круга poll: так между командами всегда есть чтение, и датапату
           всегда есть куда сказать. */
        int more = d2k_sched_sync_step(s);

        t = now_ms();
        if (more || t - last_tick >= TICK_MS || (pr > 0 && (pfd[1].revents & POLLIN))) {
            diagnostic_tick(s,t);
            d2k_sched_tick(s, t);
            last_tick = t;
        }

        if (t - last_report >= REPORT_EVERY_MS) {
            size_t n_binds = 0, n_plans = 0;
            for (size_t b = 0; b < cat.n_boxes; b++) {
                n_binds += cat.boxes[b].n_binds;
                n_plans += cat.boxes[b].n_plans;
            }
            long rss, hwm, data, thr;
            self_mem(&rss, &hwm, &data, &thr);
            char mem[160] = "";
            if (rss >= 0) {
                snprintf(mem, sizeof mem, "; память: RSS %ld КиБ (пик %ld), данные %ld КиБ, потоков %ld",
                         rss, hwm, data, thr);
            }
            char line[600];
            snprintf(line, sizeof line,
                     "событий %lu (приветствий %lu, подозрений %lu, обменов %lu, "
                     "применений %lu, отказов %lu), поисков идёт %zu; каталог: коробок %zu, "
                     "привязок %zu, планов %zu%s",
                     seen_events, seen_hello, seen_suspect, seen_exchange,
                     seen_applied, seen_refused, d2k_sched_active(s),
                     cat.n_boxes, n_binds, n_plans, mem);
            sched_say(NULL, line);
            last_report = t;
        }

        if (livepath && t - last_live >= LIVE_EVERY_MS) {
            (void)d2k_sched_write_live(s, livepath, catpath);
            last_live = t;
        }

        int save_dns=d2k_sched_dns_save_pending(s, saved_catalog_revision) && t - last_dns_save >= 1000;
        if (save_dns || t - last_save >= SAVE_EVERY_MS) {
            if (save_dns)last_dns_save=t;
            if (cat.revision != saved_catalog_revision) {
                if (save_atomic(&cat, catpath, err, sizeof err) != 0) {
                    fprintf(stderr, "d2kc: каталог не сохранён: %s\n", err);
                } else {
                    saved_catalog_revision = cat.revision;
                    d2k_sched_plain_dns_saved(s,d2k_sched_plain_dns_revision(s));
                    printf("d2kc: каталог сохранён (изменение %llu)\n",
                           (unsigned long long)saved_catalog_revision);
                    fflush(stdout);
                }
            }
            last_save = t;
        }
    }

    fprintf(stderr, "d2kc: engine-exit time=%ld pid=%ld signal=%d sender_pid=%d link_lost=%d protocol_mismatch=%d\n",
            (long)time(NULL), (long)getpid(), (int)stop_asked, (int)stop_sender, link_lost, proto_bad);
    if (proto_bad) {
        printf("d2kc: остановлен из-за несовпадения версии протокола\n");
    }
    if (!proto_seen) {
        /* Версии не было вовсе — либо датапат старый (до появления
           объявления), либо событие потерялось. Оба случая одинаково значат
           «мы не знаем, с кем говорили», и молчать об этом нельзя. */
        fprintf(stderr, "d2kc: датапат версию протокола не объявил — "
                        "работоспособность пары НЕ подтверждена\n");
    }
    printf("d2kc: останавливаюсь\n");
    if(journal_started) {
        journal_reader.halt=1;
        pthread_join(journal_thread,NULL);
        close(journal_pipe[0]);close(journal_pipe[1]);
    }
    /* Сперва сказать измерителю бросить, потом уже дожидаться потоков: иначе
       d2k_sched_free досиживает замер до конца, и служба не выходит по
       сигналу (стенд транзита 17.09 повис на этом). Журнал при этом уезжает
       в файл через буфер, поэтому строка выше явно выталкивается — иначе
       «останавливаюсь» не видно ровно тогда, когда его и ищут. */
    fflush(stdout);
    d2k_detect_stop_all();
    d2k_httpsprobe_free(hp);
    /* Сперва дождаться зонда (он держит сокет), потом снять свою пробу. */
    d2k_hs_runner_free(g_hr);
    d2k_httpsearch_free(g_hs);
#ifdef D2K_TRUSTED_DOH
    d2k_dns_capture_free(dns_capture);
    if(provider_ips.dirty && provider_ips_path[0] &&
       d2k_provider_ips_save(&provider_ips,provider_ips_path,(uint64_t)time(NULL)))
        fprintf(stderr,"d2kc: provider IP registry save failed on shutdown\n");
#endif
    d2k_sched_free(s);
    d2k_diag_free(diagnostics);diagnostics=NULL;
    if (cat.revision != saved_catalog_revision) {
        if (save_atomic(&cat, catpath, err, sizeof err) != 0) {
            fprintf(stderr, "d2kc: каталог не сохранён на выходе: %s\n", err);
        }
    }
    d2k_link_close(fd);
    d2k_catalog_free(&cat);
    return link_lost ? 1 : 0;
}
