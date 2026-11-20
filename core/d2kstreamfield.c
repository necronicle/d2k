/* One explicitly requested identity-stream diagnostic; no synthesis/install. */
#include "../synthesis/experiment.h"
#include "../synthesis/tls_decode.h"
#include "../synthesis/application_model.h"
#include "../synthesis/raw_tape.h"
#include "../synthesis/path_run.h"
#include "d2k_verify.h"
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static volatile sig_atomic_t interrupted;
static void stop_signal(int sig){(void)sig;interrupted=1;}
static int stopped(void *ctx){(void)ctx;return interrupted!=0;}
typedef struct {
    d2k_application_owner *owner;
    d2k_application_model *model;
    uint64_t generation,experience;
    unsigned accepted;
} field_observer;
static int observed(void *ctx,const d2k_doh_observation *q)
{
    field_observer *f=ctx;d2k_application_observation observation;
    if(d2k_application_owner_observe(f->owner,f->generation,f->experience,q,&observation)!=1)return -1;
    d2k_application_update update=d2k_application_model_add(f->model,&observation);
    if(update==D2K_APP_ERROR || update==D2K_APP_REJECTED)return -1;
    f->accepted++;
    printf("query=%u dns_valid=%d status=%d complete=%d\n",q->ordinal,q->dns_valid,
        q->response.status,q->response.body_complete);
    return 0;
}
typedef struct {
    field_observer *observer;
    const d2k_synthesis_feedback *id;
    d2k_raw_tape *tape;
    const d2k_tls_probe_seed *seed;
    const d2k_trigger *trigger;
    d2k_ver_result result;
    int successful;
} field_macro;
static int run_application(void *ctx,const d2k_tls_io *io)
{
    field_macro *m=ctx;
    m->observer->owner=d2k_application_owner_recorded(m->id,1,m->tape,
        m->trigger->payload,m->trigger->len);
    printf("late_binding=%d\n",m->observer->owner!=NULL);
    if(!m->observer->owner){m->result.local_refusal=1;return -1;}
    m->result=d2k_verify_doh_observe_io(io,m->seed,m->id->target,m->id->resource,
        5000,1200,observed,m->observer);
    return 0;
}
static int finish_application(void *ctx,uint64_t *symbol)
{
    field_macro *m=ctx;d2k_application_end end;
    if(d2k_application_owner_end(m->observer->owner,&m->result,&end))return 0;
    end.timeout_ms=5000;end.hello_wire=1200;
    if(d2k_application_model_finish(m->observer->model,&end))return -1;
    const d2k_ver_result *r=&m->result;
    m->successful=end.network_evidence && m->observer->accepted==1 &&
        r->level==D2K_VER_APPLICATION && r->status==200 && r->body_complete && r->doh_replies==1;
    *symbol=((uint64_t)(uint32_t)r->level<<32)|((uint64_t)(uint32_t)r->status<<8)|!!r->body_complete;
    printf("macro_application http=%d replies=%u owned_queries=%u owned_end=%d\n",
        r->status,r->doh_replies,m->observer->accepted,end.network_evidence);
    return end.network_evidence;
}
int main(int argc,char **argv)
{
    int macro=argc==5 && !strcmp(argv[4],"macro");
    int partition=macro || (argc==5 && !strcmp(argv[4],"partition"));
    if(argc!=4 && !partition)return 2;
    signal(SIGINT,stop_signal);signal(SIGTERM,stop_signal);
    d2k_experiment e={.family=4,.port=443,.connect_ms=5000,.mark=0x2f,.offer_ts=1};
    if(inet_pton(AF_INET,argv[1],e.ip)!=1)return 2;
    d2k_detect_stop cancel={stopped,NULL};e.cancel=&cancel;
    d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();
    d2k_trigger *tr=calloc(1,sizeof *tr);
    if(!seed || !tr){d2k_tls_probe_seed_free(seed);free(tr);return 2;}
    const uint8_t alpn[]={2,'h','2'};
    tr->len=d2k_tls_probe_hello(seed,argv[2],1200,alpn,sizeof alpn,tr->payload,sizeof tr->payload);
    static const char identity[]="d2k-plan 1 5\nid 00000000000000000000000000000001\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
    d2k_synthesis_feedback id={.generation=1,.search_id=1,.target=argv[2],.ip=argv[1],
        .resource=argv[3],.program=identity,.doh=1,.port=443,.family=4,.transport=6,.shape=D2K_SHAPE_MODERN};
    id.plan_id[sizeof id.plan_id-1]=1;
    d2k_payload_piece pieces[]={{0,tr->len/2,0},{tr->len/2,tr->len-tr->len/2,0}};
    char *partition_plan=NULL;
    if(partition) {
        char error[160];
        if(d2k_lower_partition(tr->len,pieces,2,"tls",&partition_plan,error,sizeof error)!=D2K_LOWER_OK) {
            d2k_tls_probe_seed_free(seed);free(tr);return 2;
        }
        char *label=strstr(partition_plan,"\nid ");label[35]='1';id.program=partition_plan;
    }
    uint64_t experience;
    if(d2k_t13_random(id.trial_id,sizeof id.trial_id) ||
       d2k_t13_random((uint8_t *)&experience,sizeof experience) || !experience) {
        d2k_tls_probe_seed_free(seed);free(partition_plan);free(tr);return 2;
    }
    field_observer context={.generation=id.generation,.experience=experience};
    d2k_raw_tape *tape=d2k_raw_tape_new(experience);
    context.model=d2k_application_model_new(&id,experience);
    if(!tape || !context.model) {
        d2k_raw_tape_free(tape);d2k_application_model_free(context.model);
        d2k_tls_probe_seed_free(seed);free(partition_plan);free(tr);return 2;
    }
    d2k_raw_tls_sink sink=d2k_raw_tape_sink(tape);e.sink=&sink;
    d2k_experiment_operation ops[3]={
        {.kind=D2K_EXPERIMENT_SEND,.trigger=tr,.program=identity,.next_offset=(uint32_t)tr->len},
        {.kind=D2K_EXPERIMENT_READ,.timeout_ms=5000,.minimum=1}};
    if(partition) {
        static const char slice_identity[]="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
        ops[2]=ops[1];
        for(size_t i=0;i<2;i++)ops[i]=(d2k_experiment_operation){
            .kind=D2K_EXPERIMENT_SEND_SLICE,.trigger=tr,.program=slice_identity,
            .offset=(uint32_t)pieces[i].offset,.next_offset=(uint32_t)(pieces[i].offset+pieces[i].length),
            .payload_offset=pieces[i].offset,.payload_length=pieces[i].length};
    }
    uint8_t scratch[16];d2k_tls_decoder decoder={0};
    e.operations=ops;e.operation_count=partition?3:2;e.reply=scratch;e.reply_capacity=sizeof scratch;
    e.decoder_context=&decoder;e.begin_decode=d2k_tls_decoder_begin;e.decode=d2k_tls_decoder_read;
    e.read_to_terminal=1;e.tls_input=tr->payload;e.tls_input_length=tr->len;
    char err[200]={0};d2k_raw_observation raw={0};
    int rc=1;
    if(macro) {
        field_macro trial={.observer=&context,.id=&id,.tape=tape,.seed=seed,.trigger=tr};
        d2k_path_application app={&trial,run_application,finish_application,NULL};
        d2k_path_run *path=d2k_path_run_new_application(&e,&app);
        if(path) {
            const size_t word[]={3,0,1,2,5};int complete=1;
            for(size_t i=0;i<sizeof word/sizeof *word;i++)if(d2k_path_run_step(path,word[i],err,sizeof err)!=1) {
                complete=0;fprintf(stderr,"macro action %zu: %s\n",word[i],err);break;
            }
            size_t count;const d2k_path_event *events=d2k_path_run_history(path,&count);
            printf("macro_history=%zu final_action=%zu\n",count,count?events[count-1].sample.operation:0);
            rc=!(complete && trial.successful && count==5);
            d2k_hypothesis *hypothesis=NULL;d2k_transducer current;
            int modeled=d2k_path_run_model(path,&hypothesis,&current);
            printf("macro_model=%d operations=%zu\n",modeled,modeled==1?current.operations:0);
            if(modeled!=1 || current.operations!=6)rc=1;
            d2k_hypothesis_free(hypothesis);
            d2k_path_run_free(path);
        }
        d2k_tls_decoder_free(&decoder);goto cleanup;
    }
    d2k_experiment_channel *channel=d2k_experiment_open(&e,&raw,err,sizeof err);
    d2k_ver_result r={.fd=-1};
    if(channel) {
        size_t word[]={0,1,2},done=0;d2k_sample samples[3];
        int status=d2k_experiment_continue(channel,word,e.operation_count,samples,&done,&raw,err,sizeof err);
        printf("measurement=%d completed=%zu raw=%d bytes=%zu reason=%s\n",
            status,done,raw.kind,(size_t)raw.response_bytes,err);
        context.owner=partition?d2k_application_owner_recorded(&id,1,tape,tr->payload,tr->len):
            d2k_application_owner_new(&id,experience,1);
        d2k_raw_tls_sink consumer=d2k_application_owner_sink(context.owner);
        int bound=context.owner && (partition || !d2k_raw_tape_bind(tape,&consumer));
        printf("late_binding=%d\n",bound);
        d2k_tls_io io=d2k_experiment_tls_io(channel);
        if(bound && io.context && !interrupted) {
            r=d2k_verify_doh_observe_io(&io,seed,argv[2],argv[3],5000,1200,observed,&context);
            printf("same_connection level=%d http=%d complete=%d replies=%u local=%d reason=%s\n",
                r.level,r.status,r.body_complete,r.doh_replies,r.local_refusal,r.reason);
            rc=!(r.level==D2K_VER_APPLICATION && r.status==200 && r.body_complete &&
                 r.doh_replies==1 && !r.local_refusal && !r.local_limit && !r.unsupported);
        }
    } else fprintf(stderr,"open failed: %s\n",err);
    d2k_experiment_close(channel);d2k_tls_decoder_free(&decoder);
    d2k_application_end end;
    int owned=d2k_application_owner_end(context.owner,&r,&end)==0;
    if(owned) {
        end.timeout_ms=5000;end.hello_wire=1200;
        owned=!d2k_application_model_finish(context.model,&end) && end.network_evidence;
    }
    printf("owned_queries=%u owned_end=%d\n",context.accepted,owned);
    if(!owned || context.accepted!=1)rc=1;
cleanup:
    d2k_raw_tape_free(tape);
    d2k_application_model_free(context.model);d2k_application_owner_free(context.owner);
    d2k_tls_probe_seed_free(seed);free(partition_plan);free(tr);d2k_raw_flush_pending();return rc;
}
