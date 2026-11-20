#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2k_shadow.h"
#include "d2km_sim.h"
#include "d2km_tls.h"
#include "d2k_doh_contract.h"
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static d2k_shadow_dedup dedup;
static d2km_task_report report;
static d2k_shadow_dedup restored;
static d2km_store store;
static uint8_t client_hello[D2KM_TLS_MAX];static size_t client_len;
static const char *captured_queue;static d2k_shadow_record captured_record;
static d2km_net simulator;static int capture_calls, references;
static int capture(void *ctx,const d2km_arm_spec *a,d2km_observation *o,d2km_result *r)
{
    (void)ctx;references+=a->reference;
    if(!capture_calls++) {
        d2k_shadow_snapshot freed;
        assert(d2k_shadow_snapshot_read(captured_queue,&captured_record,&freed)<0);
        assert(a->hello_length==client_len && !memcmp(a->hello,client_hello,client_len));
        assert(a->context->form.tcp_options_length==2 && a->context->form.tcp_options[0]==1);
        d2km_tls_hello parsed;char name[254];assert(d2km_tls_parse(a->hello,a->hello_length,&parsed)==D2KM_TLS_OK);
        assert(d2km_tls_sni(&parsed,name,sizeof name)==D2KM_TLS_OK && !strcmp(name,"blocked.example"));
    }
    return simulator.run(simulator.ctx,a,o,r);
}
static int count_reference(void *ctx,const d2km_arm_spec *a,d2km_observation *o,d2km_result *r)
{ (void)ctx;references+=a->reference;return simulator.run(simulator.ctx,a,o,r); }
static int incomplete_doh(void *ctx,const d2km_arm_spec *a,d2km_observation *o,d2km_result *r) {
    (void)a;memset(o,0,sizeof *o);o->sent_packets=o->received_packets=1;
    *r=d2k_doh_result(ctx);return 0;
}
static void measured_names(void)
{
    d2k_shadow_recent recent={0};d2k_shadow_record target={.time=5000,.port=443,.family=4};
    strcpy(target.host,"blocked.example.co.uk");strcpy(target.ip,"192.0.2.1");
    d2k_shadow_record e=target,chosen;
    strcpy(e.host,"sibling.example.co.uk");d2k_shadow_recent_note(&recent,&e,5000);
    char reason[500];assert(!d2k_shadow_pick_name(&recent,&target,5000,&chosen,reason,sizeof reason));
    strcpy(e.host,"other.example.com");strcpy(e.ip,"192.0.2.2");d2k_shadow_recent_note(&recent,&e,5000);
    strcpy(e.host,"same.example.net");strcpy(e.ip,target.ip);d2k_shadow_recent_note(&recent,&e,5000);
    assert(d2k_shadow_pick_name(&recent,&target,5000,&chosen,reason,sizeof reason));
    assert(!strcmp(chosen.host,e.host) && strstr(reason,"этот адрес"));
    e.signal=1;d2k_shadow_recent_note(&recent,&e,5000);
    assert(d2k_shadow_pick_name(&recent,&target,5000,&chosen,reason,sizeof reason) && strstr(reason,"DIRECT_OK"));
    assert(d2k_shadow_pick_name(&recent,&target,8600,&chosen,reason,sizeof reason));
    assert(!d2k_shadow_pick_name(&recent,&target,8601,&chosen,reason,sizeof reason));
    /* R3: select over both bounded sources, retaining the only same-address
       candidate even when the combined source count exceeds either cap. */
    d2k_shadow_recent controller={0},direct={0};
    for(unsigned i=0;i<D2K_SHADOW_RECENT_MAX;i++) {
        e=target;e.time=4990;e.signal=0;
        snprintf(e.host,sizeof e.host,"measured%u.example.net",i);
        if(i)strcpy(e.ip,"192.0.2.2");
        d2k_shadow_recent_note(&controller,&e,5000);
        e.time=1500;e.signal=1;snprintf(e.host,sizeof e.host,"direct%u.example.com",i);
        strcpy(e.ip,"192.0.2.3");d2k_shadow_recent_note(&direct,&e,5000);
    }
    assert(d2k_shadow_pick_names(&controller,&direct,&target,5000,&chosen,reason,sizeof reason));
    assert(!strcmp(chosen.host,"measured0.example.net") && chosen.time==4990);
    assert(d2k_shadow_pick_names(&direct,&controller,&target,5000,&chosen,reason,sizeof reason));
    assert(!strcmp(chosen.host,"measured0.example.net") && chosen.time==4990);
    direct.entries[0]=controller.entries[0];direct.entries[0].time=1500;direct.entries[0].signal=1;
    assert(d2k_shadow_pick_names(&controller,&direct,&target,5000,&chosen,reason,sizeof reason));
    assert(chosen.time==4990 && !chosen.signal);

}
static void degradation_keys(const char *seen) {
    static d2k_shadow_dedup d,reloaded;
    d2k_shadow_record normal={.time=100,.port=443,.family=4,.protocol=2,.signal=2};
    strcpy(normal.host,"blocked.example");strcpy(normal.ip,"192.0.2.1");
    assert(d2k_shadow_admit(&d,&normal,100));
    d2k_shadow_record failed=normal;failed.degradation=1;failed.knowledge=1;failed.program_hash=123;
    failed.binding=(d2k_binding_context){.kind=D2K_BIND_NAME,.family=4,.shape=1,.generation=7};failed.binding.epoch[0]=1;
    assert(d2k_shadow_admit(&d,&failed,100)); /* APPLIED cooldown cannot suppress first degradation */
    assert(!d2k_shadow_admit(&d,&failed,100));
    failed.binding.generation++;assert(d2k_shadow_admit(&d,&failed,100));
    failed.protocol=1;failed.binding.shape=2;assert(d2k_shadow_admit(&d,&failed,100));
    failed.family=6;failed.binding.family=6;strcpy(failed.ip,"2001:db8::1");assert(d2k_shadow_admit(&d,&failed,100));
    assert(!d2k_shadow_dedup_save(seen,&d,100));assert(!d2k_shadow_dedup_load(seen,&reloaded,100));
    assert(!d2k_shadow_admit(&reloaded,&failed,100));unlink(seen);
}
static void owner_restart(const char *seen) {
    static d2k_shadow_dedup d,reloaded;
    d2k_shadow_record r={.time=100,.port=443,.family=4,.protocol=2,.priority=2};
    strcpy(r.host,"owner.example");strcpy(r.ip,"192.0.2.1");
    assert(d2k_shadow_admit(&d,&r,100));
    assert(!d2k_shadow_dedup_save(seen,&d,100));
    assert(!d2k_shadow_dedup_load(seen,&reloaded,101));
    assert(!d2k_shadow_admit(&reloaded,&r,101)); /* interrupted old signal */
    r.time=102;assert(d2k_shadow_admit(&reloaded,&r,102)); /* fresh owner traffic */
    /* Also recover files written by the initial sentinel implementation. */
    reloaded.entries[0].until=UINT64_MAX;
    assert(!d2k_shadow_dedup_save(seen,&reloaded,102));
    assert(!d2k_shadow_dedup_load(seen,&d,103));
    r.time=104;assert(d2k_shadow_admit(&d,&r,104));unlink(seen);
}
static void form_admission(const char *seen) {
    static d2k_shadow_dedup d,loaded;
    d2k_shadow_record a={.time=100,.port=443,.family=4,.protocol=2,.form_key=11};
    strcpy(a.host,"forms.example");strcpy(a.ip,"192.0.2.1");
    assert(d2k_shadow_admit(&d,&a,100));
    d2k_shadow_record b=a;b.form_key=22;
    assert(d2k_shadow_admit(&d,&b,100)); /* another form has its own DIRECT/OWN task */
    assert(!d2k_shadow_admit(&d,&a,100));
    assert(!d2k_shadow_dedup_save(seen,&d,100));
    assert(!d2k_shadow_dedup_load(seen,&loaded,101));
    assert(!d2k_shadow_admit(&loaded,&a,101) && !d2k_shadow_admit(&loaded,&b,101));
    b.form_key=33;assert(d2k_shadow_admit(&loaded,&b,101));unlink(seen);
    FILE *legacy=fopen(seen,"w");assert(legacy);
    fputs("D2KSHADOW1\n3700 100 forms.example 192.0.2.1 443 4 2\n",legacy);fclose(legacy);
    memset(&loaded,0,sizeof loaded);assert(!d2k_shadow_dedup_load(seen,&loaded,101));
    a.form_key=0;assert(!d2k_shadow_admit(&loaded,&a,101));
    a.form_key=11;assert(d2k_shadow_admit(&loaded,&a,101));unlink(seen);
}
static void resource_wakeup(const char *path)
{
    d2k_shadow_dedup d={0},loaded={0};
    d2k_shadow_record r={.time=100,.port=443,.family=4,.protocol=2,.form_key=123,.snapshot_errno=ENOSPC};
    strcpy(r.host,"resource.example");strcpy(r.ip,"192.0.2.1");
    assert(d2k_shadow_admit(&d,&r,100));
    d2km_task_report waiting={.outcome=D2KM_NO_RESOURCES,.state=D2KM_T_WAIT};
    d2k_shadow_complete(&d,&r,101,&waiting);
    assert(!d2k_shadow_dedup_save(path,&d,101));
    assert(!d2k_shadow_dedup_load(path,&loaded,102));
    r.time=102;assert(!d2k_shadow_admit(&loaded,&r,102)); /* resource still missing */
    r.snapshot_errno=0;r.snapshot=77;
    assert(d2k_shadow_admit(&loaded,&r,102)); /* successful publication proves release */
    unlink(path);
}
static void snapshot_resource_refusal(void)
{
    char dir[]="/tmp/shadow-resource-XXXXXX",queue[512],log[512];assert(mkdtemp(dir));
    snprintf(queue,sizeof queue,"%s/q",dir);snprintf(log,sizeof log,"%s/log",dir);
    uint8_t hello[]={22,3,3,0,1,1};
    d2k_shadow_record r={.time=(uint64_t)time(NULL),.family=4,.port=443};
    strcpy(r.host,"blocked.example");strcpy(r.ip,"192.0.2.1");
    /* Unreadable/oversized owned files are charged conservatively. */
    char guard[600];snprintf(guard,sizeof guard,"%s.snap-0000000000000001",queue);
    int fd=open(guard,O_WRONLY|O_CREAT,0600);assert(fd>=0);
    assert(!ftruncate(fd,(off_t)D2K_SHADOW_QUEUE_MAX*D2K_SHADOW_HELLO_MAX));close(fd);
    assert(d2k_shadow_snapshot_write(queue,&r,hello,sizeof hello,NULL,0,r.time)<0 && errno==ENOSPC);
    d2k_shadow_writer writer={0};d2k_shadow_reader reader={0};d2k_shadow_record delivered;
    assert(!d2k_shadow_writer_set(&writer,queue));
    assert(d2k_shadow_queue_append(&writer,&r)==1);
    assert(d2k_shadow_queue_next(queue,&delivered,&reader)==1);r=delivered;
    d2k_exp_options o={.host=r.host,.ip=r.ip,.port=443,.family=4,.shadow_queue=queue};
    assert(!d2k_shadow_run(&r,&o,&store,NULL,NULL,log,&report));
    assert(report.outcome==D2KM_NO_RESOURCES && !report.runs && strstr(report.reason,"errno="));
    assert(!unlink(guard));
    unlink(log);unlink(queue);
    /* A missing directory is an I/O failure, not a full resource pool. */
    snprintf(queue,sizeof queue,"%s/missing/q",dir);
    assert(d2k_shadow_snapshot_write(queue,&r,hello,sizeof hello,NULL,0,r.time)<0);
    assert(r.snapshot_errno==ENOENT);
    o.shadow_queue=queue;
    assert(!d2k_shadow_run(&r,&o,&store,NULL,NULL,log,&report));
    assert(report.outcome==D2KM_LOCAL_FAIL && !report.runs && strstr(report.reason,"snapshot-write"));
    unlink(log);assert(!rmdir(dir));
}
static int unexpected_arm(void *ctx,const d2km_arm_spec *a,d2km_observation *o,d2km_result *r)
{ (void)a;(*(unsigned *)ctx)++;memset(o,0,sizeof *o);*r=(d2km_result){D2KM_R_APP_OK,0};return 0; }
static void unreproducible_resumption(void)
{
    char dir[]="/tmp/shadow-resumption-XXXXXX",queue[512],log[512];assert(mkdtemp(dir));
    snprintf(queue,sizeof queue,"%s/q",dir);snprintf(log,sizeof log,"%s/log",dir);
    d2km_tls_hello h={.record_version=0x0301,.version=0x0303,.ciphers_length=2,
        .compression_length=1,.compression_offset=2,.arena_length=3};h.arena[1]=0x2f;
    assert(d2km_tls_put_ext(&h,0,NULL,0)==D2KM_TLS_OK);
    assert(d2km_tls_set_sni(&h,"blocked.example")==D2KM_TLS_OK);
    assert(d2km_tls_put_ext(&h,41,NULL,0)==D2KM_TLS_OK);
    uint8_t hello[512];size_t hn=d2km_tls_build(&h,hello,sizeof hello);assert(hn);
    d2k_shadow_record r={.time=(uint64_t)time(NULL),.port=443,.family=4};
    strcpy(r.host,"blocked.example");strcpy(r.ip,"192.0.2.1");
    assert(!d2k_shadow_snapshot_write(queue,&r,hello,hn,NULL,0,r.time));
    d2k_exp_options o={.host=r.host,.ip=r.ip,.port=443,.family=4,.shadow_queue=queue};
    unsigned calls=0;d2km_net net={&calls,unexpected_arm};
    assert(!d2k_shadow_run(&r,&o,&store,NULL,&net,log,&report));
    assert(report.outcome==D2KM_FORM_NOT_REPRODUCED && !calls && !report.experiments);
    assert(strstr(report.reason,"pre_shared_key"));
    d2k_shadow_snapshot snapshot;assert(d2k_shadow_snapshot_read(queue,&r,&snapshot)<0);
    unlink(log);assert(!rmdir(dir));
}
static int deferred_record(void *ctx,const d2k_shadow_record *r)
{ return d2k_shadow_obsolete(ctx,r,102); }
static void reclaim_deferred_context(void)
{
    char dir[]="/tmp/shadow-deferred-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/q",dir);d2k_shadow_writer w={0};assert(!d2k_shadow_writer_set(&w,path));
    d2k_shadow_dedup d={0};d2k_shadow_record a={.time=100,.family=4,.port=443,.protocol=2};
    strcpy(a.host,"blocked.example");strcpy(a.ip,"192.0.2.1");uint8_t hello[]={22,3,3,0,1,1};
    assert(!d2k_shadow_snapshot_write(path,&a,hello,sizeof hello,NULL,0,100));
    assert(d2k_shadow_admit(&d,&a,100));
    d2km_task_report applied={.outcome=D2KM_APPLIED,.state=D2KM_T_APPLIED};
    d2k_shadow_complete(&d,&a,100,&applied);assert(d2k_shadow_queue_append(&w,&a)==1);
    d2k_shadow_record form=a;form.time=101;hello[5]=2;
    assert(!d2k_shadow_snapshot_write(path,&form,hello,sizeof hello,NULL,0,101));
    assert(d2k_shadow_queue_append(&w,&form)==1);
    d2k_shadow_record owner=a;owner.priority=2;owner.time=102;hello[5]=1;
    assert(!d2k_shadow_snapshot_write(path,&owner,hello,sizeof hello,NULL,0,102));
    assert(d2k_shadow_queue_append(&w,&owner)==1);
    d2k_shadow_reader rd={.discard=deferred_record,.discard_ctx=&d};
    assert(d2k_shadow_queue_prune(path,&rd)==1);
    d2k_shadow_snapshot snap;assert(d2k_shadow_snapshot_read(path,&a,&snap)<0);
    assert(!d2k_shadow_snapshot_read(path,&form,&snap) && snap.hello[5]==2);
    assert(!d2k_shadow_snapshot_read(path,&owner,&snap) && snap.hello[5]==1);
    d2k_shadow_record out;assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.priority==2);
    d2k_shadow_snapshot_remove(path,&out);
    assert(d2k_shadow_queue_next(path,&out,&rd)==1 && out.form_key==form.form_key);
    d2k_shadow_snapshot_remove(path,&out);unlink(path);assert(!rmdir(dir));
}
int main(void)
{
    reclaim_deferred_context();
    unreproducible_resumption();
    snapshot_resource_refusal();
    measured_names();
    d2k_shadow_record r={.time=100,.port=443,.family=4,.signal=2};
    strcpy(r.host,"blocked.example");strcpy(r.ip,"192.0.2.1");
    assert(d2k_shadow_admit(&dedup,&r,100)==1);
    report.state=D2KM_T_APPLIED;report.outcome=D2KM_APPLIED;
    d2k_shadow_complete(&dedup,&r,100,&report);
    assert(!d2k_shadow_admit(&dedup,&r,3699));
    assert(!d2k_shadow_admit(&dedup,&r,3700)); /* stale queue record */
    r.time=3700;assert(d2k_shadow_admit(&dedup,&r,3700));
    report.state=D2KM_T_WAIT;report.outcome=D2KM_LOCAL_FAIL;
    d2k_shadow_complete(&dedup,&r,3700,&report);
    assert(!d2k_shadow_admit(&dedup,&r,4299));
    r.time=4300;assert(d2k_shadow_admit(&dedup,&r,4300));
    report.outcome=D2KM_NOT_MEASURED;d2k_shadow_complete(&dedup,&r,4300,&report);
    assert(!d2k_shadow_admit(&dedup,&r,4899));
    r.time=4900;assert(d2k_shadow_admit(&dedup,&r,4900));
    report.outcome=D2KM_NO_REFERENCE;d2k_shadow_complete(&dedup,&r,4900,&report);
    assert(!d2k_shadow_admit(&dedup,&r,5500));
    /* Exact endpoint key; a full table cannot evict a cooling target. */
    d2k_shadow_record other=r;other.port=8443;
    assert(d2k_shadow_admit(&dedup,&other,5000));
    for(unsigned i=2;i<D2K_SHADOW_DEDUP_MAX;i++) {
        snprintf(other.host,sizeof other.host,"h%u.example",i);
        assert(d2k_shadow_admit(&dedup,&other,5000));
    }
    strcpy(other.host,"overflow.example");assert(!d2k_shadow_admit(&dedup,&other,5000));
    assert(dedup.dropped==1 && !d2k_shadow_admit(&dedup,&r,5000));

    char dir[]="/tmp/d2k-shadow-task-XXXXXX", log[512], why[512], seen[512];assert(mkdtemp(dir));
    snprintf(seen,sizeof seen,"%s/seen",dir);degradation_keys(seen);owner_restart(seen);
    form_admission(seen);
    resource_wakeup(seen);
    assert(!d2k_shadow_dedup_save(seen,&dedup,5000));
    assert(!d2k_shadow_dedup_load(seen,&restored,5000));
    assert(!d2k_shadow_admit(&restored,&r,5000));
    other.time=10000;assert(d2k_shadow_admit(&restored,&other,10000));
    FILE *broken=fopen(seen,"w");assert(broken);fputs("invalid\n",broken);fclose(broken);
    assert(d2k_shadow_dedup_load(seen,&restored,5000)==-1);
    unlink(seen);
    snprintf(log,sizeof log,"%s/shadow.log",dir);snprintf(why,sizeof why,"%s/why",dir);
    d2km_store_init(&store);d2km_journal j;assert(!d2km_journal_open(&j,why,1u<<20));
    d2km_sim sim={.blocked_suffix="example",.reads_name=1,.reassembles=0,.box_hop=5,.server_hop=12};
    d2km_net net=d2km_sim_net(&sim);
    d2k_exp_options options={.host=r.host,.ip=r.ip,.port=r.port,.family=r.family,
        .form="profiles/modern.hex",.pass_name="passes.test",.mark=0x2f};
    /* Production and simulator use exactly the same task assembly. */
    assert(d2k_shadow_run(&r,&options,&store,&j,&net,log,&report)==0);
    assert(report.outcome==D2KM_APPLIED && report.state==D2KM_T_APPLIED);
    assert(report.experiments && report.runs && report.knowledge_id && report.box_id);
    FILE *f=fopen(log,"r");assert(f);char line[4096];assert(fgets(line,sizeof line,f));
    assert(strstr(line,"outcome=APPLIED") && strstr(line,"source=questions"));
    assert(strstr(line,"form=not-client"));
    assert(strstr(line,"host=blocked.example") && strstr(line,"copies=") && strstr(line,"split="));
    assert(!fgets(line,sizeof line,f));fclose(f);
    strcpy(r.host,"next.example");options.host=r.host;
    assert(d2k_shadow_run(&r,&options,&store,&j,&net,log,&report)==0);
    assert(report.outcome==D2KM_APPLIED && report.from_own);
    /* GOAWAY must not become a fabricated RST even with both liveness
       controls and reusable knowledge. No inference/counterexample. */
    d2k_ver_result partial={.doh_replies=1,.budget=D2K_BUDGET_NOT_APPLICABLE};
    d2km_net neutral={&partial,incomplete_doh};size_t knowledge_before=store.knowledge.count,boxes_before=store.boxes.count;
    options.alive_history="same server application success";
    assert(!d2k_shadow_run(&r,&options,&store,&j,&neutral,log,&report));
    assert(report.outcome==D2KM_NOT_MEASURED && report.state==D2KM_T_WAIT && !report.has_candidate);
    assert(store.knowledge.count==knowledge_before && store.boxes.count==boxes_before);
    options.alive_history=NULL;
    /* Read a fixture only to create distinct client bytes/SNI; the snapshot
       handed to the task must retain these bytes and its transport options. */
    FILE *hex=fopen("profiles/modern.hex","r");assert(hex);int c,hi=-1;
    while((c=fgetc(hex))!=EOF) {
        if(c=='#') {while((c=fgetc(hex))!=EOF && c!='\n') {} continue;}
        int v=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;
        if(v<0)continue;
        if(hi<0)hi=v;else {client_hello[client_len++]=(uint8_t)(hi*16+v);hi=-1;}
    }
    fclose(hex);d2km_tls_hello parsed;assert(d2km_tls_parse(client_hello,client_len,&parsed)==D2KM_TLS_OK);
    assert(d2km_tls_set_sni(&parsed,"blocked.example")==D2KM_TLS_OK);
    client_len=d2km_tls_build(&parsed,client_hello,sizeof client_hello);assert(client_len);
    {
        uint8_t renewed[D2KM_TLS_MAX],tcp[]={1,1};
        uint64_t key=d2k_shadow_form_key(client_hello,client_len,tcp,sizeof tcp);
        d2km_rng rng;d2km_rng_seed(&rng,123);
        assert(d2km_tls_refresh(&parsed,&rng)==D2KM_TLS_OK);
        size_t n=d2km_tls_build(&parsed,renewed,sizeof renewed);
        assert(n==client_len && memcmp(renewed,client_hello,n));
        assert(key==d2k_shadow_form_key(renewed,n,tcp,sizeof tcp));
        tcp[0]=2;assert(key!=d2k_shadow_form_key(renewed,n,tcp,sizeof tcp));
    }
    strcpy(r.host,"blocked.example");r.time=(uint64_t)time(NULL);r.history_time=r.time;
    strcpy(r.history_name,"earlier.example.net");
    char queue[512];snprintf(queue,sizeof queue,"%s/queue",dir);uint8_t opts[]={1,1};
    assert(!d2k_shadow_snapshot_write(queue,&r,client_hello,client_len,opts,2,r.time));
    options.host=r.host;options.shadow_queue=queue;options.pass_name=NULL;
    /* §4.3 п. 2: живость доказывает прикладной успех тени на том же адресе
       и порту (DIRECT_OK), а не пассивный обмен (R4). */
    {   d2k_shadow_recent seen={0};d2k_shadow_record ok=r;ok.time=r.time;ok.signal=1;
        strcpy(ok.host,"earlier.example.net");d2k_shadow_recent_note(&seen,&ok,r.time);
        assert(!d2k_shadow_recent_save(queue,"direct",&seen,r.time)); }
    captured_queue=queue;captured_record=r;
    simulator=net;d2km_net inspect={.run=capture};d2km_store_init(&store);
    assert(!d2k_shadow_run(&r,&options,&store,&j,&inspect,log,&report));
    assert(capture_calls && !references && report.outcome!=D2KM_NO_REFERENCE);
    assert(d2k_shadow_snapshot_read(queue,&r,(d2k_shadow_snapshot[1]){{0}})<0);
    /* No candidates means no name-control; history still proves liveness. */
    f=fopen(log,"r");assert(f);int marked=0;while(fgets(line,sizeof line,f))if(strstr(line,"form=client"))marked++;
    fclose(f);assert(marked==1);
    /* A different client form on the same target must earn its own trial.
       This validates admission/OWN, not the coarser production wire selector. */
    assert(report.outcome==D2KM_APPLIED);
    assert(d2km_tls_parse(client_hello,client_len,&parsed)==D2KM_TLS_OK);
    uint8_t extension[]={0};
    assert(d2km_tls_put_ext(&parsed,0xfe0d,extension,sizeof extension)==D2KM_TLS_OK);
    uint8_t second_form[D2KM_TLS_MAX];size_t second_len=d2km_tls_build(&parsed,second_form,sizeof second_form);
    d2k_shadow_record second_record=r;
    assert(!d2k_shadow_snapshot_write(queue,&second_record,second_form,second_len,opts,2,r.time));
    assert(second_record.form_key!=r.form_key);
    assert(!d2k_shadow_run(&second_record,&options,&store,&j,&net,log,&report));
    assert(report.outcome==D2KM_APPLIED && report.from_own && report.experiments==3 && report.runs==6);
    /* Restore the first context for exact-binding degradation below. */
    assert(!d2k_shadow_snapshot_write(queue,&r,client_hello,client_len,opts,2,r.time));
    assert(!d2k_shadow_run(&r,&options,&store,&j,&net,log,&report));
    assert(report.outcome==D2KM_APPLIED);
    /* The live marker routes exact K/hash before DIRECT, with this client's
       bytes/options. A lost snapshot cannot silently fall back to a form. */
    assert(report.outcome==D2KM_APPLIED && store.knowledge.count);
    r.degradation=1;r.knowledge=report.knowledge_id;r.program_hash=d2km_program_hash(&report.program);r.protocol=2;
    r.binding=(d2k_binding_context){.kind=D2K_BIND_NAME,.family=4,.shape=1,.generation=7};r.binding.epoch[0]=1;
    assert(!d2k_shadow_snapshot_write(queue,&r,client_hello,client_len,opts,2,r.time));
    assert(!d2k_shadow_run(&r,&options,&store,&j,&net,log,&report));
    assert(report.outcome==D2KM_APPLIED && report.experiments==1 && report.runs==2);
    assert(!d2k_shadow_run(&r,&options,&store,&j,&net,log,&report));
    assert(report.outcome==D2KM_FORM_NOT_REPRODUCED && !report.runs);
    f=fopen(why,"r");assert(f);char last_reason[4096]="";
    while(fgets(line,sizeof line,f))if(strstr(line,"форма клиента для проверки той же привязки"))strcpy(last_reason,line);
    fclose(f);assert(strstr(last_reason,"\"outcome\":\"FORM_NOT_REPRODUCED\""));
    r.degradation=0;r.knowledge=0;r.program_hash=0;r.protocol=0;memset(&r.binding,0,sizeof r.binding);
    /* Corrupt or missing client observations cannot promote a template's
       result to the live client context. */
    uint8_t corrupt[]={0,1,2};
    assert(!d2k_shadow_snapshot_write(queue,&r,corrupt,sizeof corrupt,NULL,0,r.time));
    /* R4: свежий пассивный «чистый обмен» без прикладного успеха живость не
       доказывает — опорная точка не пропускается. */
    {   char dp[600];snprintf(dp,sizeof dp,"%s.direct",queue);unlink(dp); }
    r.history_time=r.time;strcpy(r.history_name,"earlier.example.net");
    sim.reference_down=1;references=0;
    d2km_net count_net={.run=count_reference};d2km_store_init(&store);
    assert(!d2k_shadow_run(&r,&options,&store,&j,&count_net,log,&report));
    assert(!references && report.outcome==D2KM_FORM_NOT_REPRODUCED && !report.runs && !store.knowledge.count);
    assert(d2k_shadow_snapshot_read(queue,&r,(d2k_shadow_snapshot[1]){{0}})<0);
    f=fopen(log,"r");assert(f);marked=0;while(fgets(line,sizeof line,f))
        if(strstr(line,"outcome=FORM_NOT_REPRODUCED") && strstr(line,"form=not-client"))marked++;
    fclose(f);assert(marked>=1);
    /* Only an actual DIRECT_OK task produces the shadow's own candidates. */
    sim.blocked_suffix=NULL;sim.reference_down=0;r.history_time=0;r.history_name[0]=0;
    assert(!d2k_shadow_snapshot_write(queue,&r,client_hello,client_len,opts,2,r.time));
    assert(!d2k_shadow_run(&r,&options,&store,&j,&net,log,&report) && report.outcome==D2KM_DIRECT_OK);
    d2k_shadow_recent measured={0};assert(!d2k_shadow_recent_load(queue,"direct",&measured,r.time));
    assert(measured.count==1 && measured.entries[0].signal==1 && !strcmp(measured.entries[0].host,r.host));
    char direct_path[600];snprintf(direct_path,sizeof direct_path,"%s.direct",queue);unlink(direct_path);
    d2km_journal_close(&j);f=fopen(why,"r");assert(f);marked=0;
    while(fgets(line,sizeof line,f))if(strstr(line,"earlier.example.net"))marked++;
    fclose(f);assert(marked);
    f=fopen(why,"r");assert(f);marked=0;while(fgets(line,sizeof line,f))if(strstr(line,"form=not-client"))marked++;
    fclose(f);assert(marked>=4);
    /* Diagnostics are one line, with control characters and quotes escaped. */
    strcpy(report.reason,"phase=send\nerrno=1 \"denied\"\\");
    assert(!d2k_shadow_log(log,&r,r.time,&report));
    f=fopen(log,"r");assert(f);char last[4096]="";
    while(fgets(line,sizeof line,f))strcpy(last,line);fclose(f);
    assert(strstr(last,"reason=\"phase=send\\u000aerrno=1 \\\"denied\\\"\\\\\"") && strchr(last,'\n')==last+strlen(last)-1);
    unlink(log);unlink(why);rmdir(dir);
    puts("shadow task/dedup: ok");return 0;
}
