#define _POSIX_C_SOURCE 200809L
/* One explicit direct raw/TLS/DoH experiment. Does not install a plan,
 * change DNS configuration, or run the controller. */
#include "../synthesis/application_policy.h"
#include "../synthesis/application_archive.h"
#include "../synthesis/application_search.h"
#include "../synthesis/application_history.h"
#include "../synthesis/path_work.h"
#include "d2k_hello.h"
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
static volatile sig_atomic_t interrupted;
static void interrupt(int sig) {(void)sig;interrupted=1;}
static int cancelled(void *ctx) {(void)ctx;return interrupted!=0;}
static int first_query(void *ctx,d2k_application_model *model,d2k_application_update update) {
    if(update==D2K_APP_ERROR || update==D2K_APP_REJECTED)return -1;
    size_t count=0;const d2k_application_observation *history=d2k_application_model_history(model,&count);
    if(!history || !count)return -1;
    const d2k_doh_observation *q=&history[count-1].query;
    if(!q->dns_valid || !d2k_application_query_complete(&q->response))return 0;
    return q->ordinal<*(const unsigned *)ctx;
}
typedef struct {
    const d2k_application_model *reference;
    unsigned required,completed;
    d2k_application_question comparison;
} application_confirmation;
static int confirm_query(void *ctx,d2k_application_model *model,d2k_application_update update) {
    application_confirmation *c=ctx;
    if(update==D2K_APP_ERROR || update==D2K_APP_REJECTED)return -1;
    c->comparison=d2k_application_model_question(c->reference,model);
    if(c->comparison.status==D2K_APP_QUESTION_CONTEXT || c->comparison.status==D2K_APP_NO_WITNESS)return -1;
    size_t count=0;
    const d2k_application_observation *history=d2k_application_model_history(model,&count);
    if(!history || !count)return -1;
    const d2k_doh_observation *query=&history[count-1].query;
    if(!query->dns_valid || !d2k_application_query_complete(&query->response))return 0;
    if(c->completed==UINT_MAX || query->ordinal!=c->completed+1)return -1;
    c->completed=query->ordinal;
    return c->completed<c->required;
}
static int run_application(char **argv,int measure,FILE *archive,unsigned through_query) {
    d2k_experiment network={0};network.family=strchr(argv[1],':')?6:4;
    if(inet_pton(network.family==6?AF_INET6:AF_INET,argv[1],network.ip)!=1)return 2;
    network.port=443;network.connect_ms=5000;network.mark=0x2f;network.offer_ts=1;
    d2k_detect_stop stop={cancelled,NULL};network.cancel=&stop;
    signal(SIGINT,interrupt);signal(SIGTERM,interrupt);
    static const char direct[]="d2k-plan 1 5\nid 00000000000000000000000000000001\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
    d2k_synthesis_feedback id={0};
    uint64_t numbers[3];
    if(d2k_t13_random((uint8_t *)numbers,sizeof numbers) ||
       d2k_t13_random(id.trial_id,sizeof id.trial_id))return 2;
    id.generation=numbers[0]?numbers[0]:1;id.search_id=numbers[1]?numbers[1]:1;
    uint64_t experience=numbers[2]?numbers[2]:1;
    id.plan_id[sizeof id.plan_id-1]=1;
    id.target=argv[2];id.ip=argv[1];id.resource=argv[3];id.program=direct;
    id.doh=1;id.port=443;id.family=network.family;id.transport=6;id.shape=D2K_SHAPE_MODERN;
    d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();if(!seed)return 2;
    d2k_ver_result result;
    d2k_application_model *reference=NULL;
    d2k_verification_status status=d2k_application_doh_learn(&id,experience,&network,seed,5000,1200,
        first_query,&through_query,&reference,&result);
    const d2k_application_end *baseline=d2k_application_model_end(reference);
    if(d2k_application_save(archive,reference,&result))status=D2K_VF_UNKNOWN;
    int learning_probes=0;
    /* Explicit diagnostic measurement, never automatic censorship admission.
       A complete direct application response does not start synthesis. */
    if(measure && !interrupted && baseline && baseline->network_evidence && baseline->input_length &&
       status!=D2K_VF_QUERY_OBSERVED &&
       result.level>=D2K_VER_TRANSPORT && !result.body_complete &&
       !result.local_refusal && !result.local_limit && !result.unsupported) {
        d2k_trigger *trigger=calloc(1,sizeof *trigger);
        d2k_vres *candidate=calloc(1,sizeof *candidate);
        if(!trigger || !candidate){free(trigger);free(candidate);d2k_application_model_free(reference);d2k_tls_probe_seed_free(seed);return 2;}
        const uint8_t alpn[]={2,'h','2'};
        trigger->len=d2k_tls_probe_hello(seed,id.target,1200,alpn,sizeof alpn,
            trigger->payload,sizeof trigger->payload);
        trigger->accept=D2K_ACCEPT_SERVERHELLO;
        size_t off=0,len=0;
        if(!trigger->len || d2k_hello_sni(trigger->payload,trigger->len,&off,&len)) {
            free(trigger);free(candidate);d2k_application_model_free(reference);d2k_tls_probe_seed_free(seed);return 2;
        }
        trigger->sni_off=(int)off;trigger->sni_len=(int)len;
        snprintf(trigger->name,sizeof trigger->name,"tls:%s",id.target);
        size_t whole=trigger->len;
        d2k_tls_stream stream={trigger,&whole,1,5000,1};network.reply_capacity=4096;
        network.tls_input=trigger->payload;network.tls_input_length=trigger->len;
        d2k_application_policy measured={0};
        if(d2k_application_policy_init(&measured,&id,reference,seed,trigger->payload,trigger->len,
            experience,5000,1200,archive)) {
            free(trigger);free(candidate);d2k_application_model_free(reference);d2k_tls_probe_seed_free(seed);return 2;
        }
        if(measured.required_queries<through_query)measured.required_queries=through_query;
        network.make_sink=d2k_application_policy_sink;network.sink_context=&measured;
        d2k_tls_application application=d2k_application_policy_callbacks(&measured);
        d2k_tls_path_session *session=d2k_tls_path_session_new_application(&stream,&network,id.generation,&application);
        d2k_syn_status proposed=d2k_tls_path_session_next(session,candidate);
        learning_probes=candidate->probes;
        printf("learning_status=%d learning_probes=%d reason=%s\n",proposed,learning_probes,candidate->reason);
        d2k_tls_path_session_free(session);
        result=measured.result;
        int continued=measured.qualified && !interrupted &&
            (proposed==D2K_SYN_CANDIDATE || proposed==D2K_SYN_DIRECT_RESPONSE);
        status=continued?D2K_VF_QUERY_OBSERVED:D2K_VF_UNKNOWN;
        if(!continued && d2k_application_query_complete(&result)) {
            result.local_refusal=1;
            snprintf(result.reason,sizeof result.reason,"query did not establish the requested application witness");
        }
        printf("same_connection_query=%d http=%d replies=%u owned_comparison=%d ordinal=%u\n",
            continued,result.status,result.doh_replies,measured.comparison.status,measured.comparison.ordinal);
        experience=measured.experience;
        network.make_sink=NULL;network.sink_context=NULL;
        network.tls_input=NULL;network.tls_input_length=0;
        /* Replaying a successful candidate is a separate reproducibility
           experiment, with its own identity, not continuation of the first. */
        if(proposed==D2K_SYN_CANDIDATE && continued && !interrupted) {
            char *label=strstr(candidate->program,"\nid ");
            if(!label || strlen(label+4)<32 ||
               d2k_t13_random(id.plan_id,sizeof id.plan_id) ||
               d2k_t13_random(id.trial_id,sizeof id.trial_id) ||
               d2k_t13_random((uint8_t *)&experience,sizeof experience) || !experience) {
                d2k_application_policy_destroy(&measured);free(trigger);free(candidate);
                d2k_application_model_free(reference);d2k_tls_probe_seed_free(seed);return 2;
            }
            static const char hex[]="0123456789abcdef";
            for(size_t i=0;i<sizeof id.plan_id;i++) {
                label[4+2*i]=hex[id.plan_id[i]>>4];label[5+2*i]=hex[id.plan_id[i]&15];
            }
            id.program=candidate->program;
            d2k_application_model *trial=NULL;
            application_confirmation confirmation={.reference=measured.reference,.required=measured.required_queries};
            status=d2k_application_doh_learn(&id,experience,&network,seed,5000,1200,
                confirm_query,&confirmation,&trial,&result);
            confirmation.comparison=d2k_application_model_question(measured.reference,trial);
            const d2k_application_end *confirmed=d2k_application_model_end(trial);
            if(d2k_application_query_complete(&result) && (!confirmed || !confirmed->network_evidence ||
                confirmation.completed<confirmation.required ||
                confirmation.comparison.status==D2K_APP_QUESTION_CONTEXT ||
                confirmation.comparison.status==D2K_APP_NO_WITNESS)) {
                result.local_refusal=1;status=D2K_VF_UNKNOWN;
                snprintf(result.reason,sizeof result.reason,"fresh trial lacks owned success through the witnessed query ordinal");
            }
            printf("application_comparison=%d ordinal=%u confirmed_queries=%u\n",
                confirmation.comparison.status,confirmation.comparison.ordinal,confirmation.completed);
            if(d2k_application_save(archive,trial,&result))status=D2K_VF_UNKNOWN;
            d2k_application_model_free(trial);
        }
        d2k_application_policy_destroy(&measured);free(trigger);free(candidate);
    }
    d2k_application_model_free(reference);d2k_tls_probe_seed_free(seed);
    d2k_raw_flush_pending();
    printf("verdict=%d learning_probes=%d level=%d http=%d complete=%d queries=%u tls_bytes=%llu missing=%u local=%d reason=%s\n",
        status,learning_probes,result.level,result.status,result.body_complete,result.budget_requests,
        (unsigned long long)result.rx_tls_wire_bytes,result.rx_tls_record_missing,
        result.local_refusal,result.reason);
    return d2k_application_query_complete(&result)?0:1;
}
static int offer_history(void *ctx,FILE *file) {
    return d2k_application_search_history(ctx,file);
}
static int run_search(char **argv,FILE *archive,unsigned through_query,FILE *history,const char *catalog) {
    d2k_application_request request={.port=443,.transport=6,.shape=D2K_SHAPE_MODERN,
        .doh=1,.doh_failure_query=through_query};
    request.family=strchr(argv[1],':')?6:4;
    if(strlen(argv[1])>=sizeof request.ip || strlen(argv[2])>=sizeof request.target ||
       strlen(argv[3])>=sizeof request.resource)return 2;
    strcpy(request.ip,argv[1]);strcpy(request.target,argv[2]);strcpy(request.resource,argv[3]);
    uint64_t generation;
    if(d2k_t13_random((uint8_t *)&generation,sizeof generation) ||
       d2k_t13_random((uint8_t *)&request.search_id,sizeof request.search_id))return 2;
    if(!generation)generation=1;
    if(!request.search_id)request.search_id=1;
    d2k_detect_stop stop={cancelled,NULL};
    d2k_experiment net={.family=request.family,.port=443,.connect_ms=5000,.mark=0x2f,
        .offer_ts=1,.cancel=&stop};
    if(inet_pton(request.family==6?AF_INET6:AF_INET,request.ip,net.ip)!=1)return 2;
    signal(SIGINT,interrupt);signal(SIGTERM,interrupt);
    d2k_application_search *search=d2k_application_search_new(&request,&net,generation,5000,1200,archive);
    if(!search)return 2;
    if(history && d2k_application_search_history(search,history)<0) {
        d2k_application_search_free(search);return 2;
    }
    d2k_inference_control history_control={cancelled,NULL};
    if(catalog && d2k_application_history_scan(catalog,offer_history,search,&history_control,NULL)<0) {
        d2k_application_search_free(search);return 2;
    }
    d2k_vres result;
    d2k_syn_status status=d2k_application_search_next(search,&result);
    printf("search_status=%d probes=%d program_bytes=%zu reason=%s\n",status,result.probes,result.program_len,result.reason);
    if(status==D2K_SYN_CANDIDATE)printf("unconfirmed_candidate:\n%s\n",result.program);
    d2k_application_search_free(search);
    return status==D2K_SYN_ERROR?2:status==D2K_SYN_CLOSED?1:0;
}
int main(int argc,char **argv) {
    int measure=0,search=0,have_depth=0;const char *path=NULL,*history_path=NULL,*history_catalog=NULL;unsigned through_query=1;
    if(argc<4)goto usage;
    for(int i=4;i<argc;i++) {
        if(!strcmp(argv[i],"--measure") && !measure && !search)measure=1;
        else if(!strcmp(argv[i],"--search") && !measure && !search)search=1;
        else if(!strcmp(argv[i],"--archive") && !path && i+1<argc)path=argv[++i];
        else if(!strcmp(argv[i],"--history") && !history_path && i+1<argc)history_path=argv[++i];
        else if(!strcmp(argv[i],"--history-catalog") && !history_catalog && i+1<argc)history_catalog=argv[++i];
        else if(!strcmp(argv[i],"--through-query") && !have_depth && i+1<argc) {
            const unsigned char *p=(const unsigned char *)argv[++i];unsigned value=0;
            if(!*p)goto usage;
            for(;*p;p++) {
                if(*p<'0' || *p>'9' || value>(0x3fffffffU-(unsigned)(*p-'0'))/10)goto usage;
                value=value*10+(unsigned)(*p-'0');
            }
            if(!value)goto usage;
            through_query=value;have_depth=1;
        }
        else goto usage;
    }
    if(((history_path || history_catalog) && !search) || (history_path && history_catalog))goto usage;
    FILE *archive=NULL,*history=NULL;
    if(path) {
        int fd=open(path,O_RDWR|O_CREAT|O_EXCL,0600);
        if(fd<0){perror("create evidence archive");return 2;}
        archive=fdopen(fd,"w+b");
        if(!archive){close(fd);perror("open evidence archive");return 2;}
    }
    if(history_path) {
        history=fopen(history_path,"rb");
        if(!history){if(archive)fclose(archive);perror("open own measurement history");return 2;}
    }
    int rc=search?run_search(argv,archive,through_query,history,history_catalog):run_application(argv,measure,archive,through_query);
    if(history)fclose(history);
    if(archive && fclose(archive)){perror("close evidence archive");return 2;}
    return rc;
usage:
    fprintf(stderr,"usage: %s IP DOH_HOST /path [--measure|--search] [--archive NEW_FILE] [--through-query N] [--history OWN_ARCHIVE | --history-catalog CATALOG (search only)]\n",argv[0]);
    return 2;
}
