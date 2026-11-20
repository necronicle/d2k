#define _POSIX_C_SOURCE 200809L
#include "d2km_task.h"
#include "fixture.h"
#include "test.h"
static d2km_store store;
static d2km_box box;
static d2km_context context;
static unsigned calls,trial_calls,direct_calls;
static uint64_t original_hash;
static int mode,checkpoint_failure;static unsigned checkpoints;
static int checkpoint(void *unused) {
    (void)unused;checkpoints++;CHECK(!d2km_knowledge_active(&store.knowledge.entries[0]));
    return checkpoint_failure?-1:0;
}
static int network(void *unused,const d2km_arm_spec *a,d2km_observation *obs,d2km_result *res) {
    (void)unused;memset(obs,0,sizeof *obs);calls++;
    if(a->program) {
        trial_calls++;
        if(mode==5 && trial_calls==1) {
            store.knowledge.entries[0].program.splits[0].offset=2;
            store.knowledge.entries[0].hash=d2km_program_hash(&store.knowledge.entries[0].program);
        }
        CHECK(d2km_program_hash(a->program)==(mode==5?original_hash:store.knowledge.entries[0].hash));
        CHECK(a->context->protocol==context.protocol && a->context->family==context.family);
        if(mode==1)res->kind=D2KM_R_RST;
        else if(mode==2)res->kind=D2KM_R_LOCAL_FAIL;
        else if(mode==3)res->kind=D2KM_R_NOT_MEASURED;
        else if(mode==4)res->kind=trial_calls%2?D2KM_R_APP_OK:D2KM_R_RST;
        else res->kind=D2KM_R_APP_OK;
    } else {direct_calls++;CHECK(trial_calls>=2 && checkpoints);res->kind=D2KM_R_APP_OK;}
    return 0;
}
static d2km_outcome run_case(int selected,d2km_task_report *r) {
    calls=trial_calls=direct_calls=checkpoints=0;mode=selected;d2km_box_init(&box,1);
    d2km_net net={.run=network};uint8_t hello[]={22,3,1,0,1,1};
    d2km_tls_task task={.net=&net,.box=&box,.knowledge=&store.knowledge,.context=&context,
        .hello=hello,.hello_length=sizeof hello,.next_experiment=20,.next_fact=20,
        .knowledge_changed=checkpoint,.degradation_knowledge=1,.degradation_hash=store.knowledge.entries[0].hash};
    original_hash=task.degradation_hash;
    return d2km_tls_task_run(&task,r);
}
static void fixture(void) {
    d2km_store_init(&store);fixture_context(&context);store.knowledge.count=1;
    d2km_knowledge *k=&store.knowledge.entries[0];k->context=context;k->binding=D2KM_BIND_NAME;
    k->id=1;k->experiment=1;k->box=1;k->model_version=1;k->last_success_ms=100;
    k->program.transport=D2KM_TCP;k->program.protocol=D2KM_P_TLS13;k->program.split_count=1;
    k->program.splits[0].anchor=D2KM_AT_PAYLOAD_START;k->program.splits[0].offset=1;
    strcpy(k->program.splits[0].why,"F1 measured boundary");k->hash=d2km_program_hash(&k->program);
    strcpy(k->why,"{\"reason\":\"вопросы\"}");
}
int main(void) {
    static d2km_task_report r;fixture();
    CHECK(run_case(0,&r)==D2KM_APPLIED);CHECK(trial_calls==2 && !direct_calls);
    CHECK(d2km_knowledge_active(&store.knowledge.entries[0]));
    for(int i=2;i<=4;i++) {fixture();d2km_outcome expect=i==2?D2KM_LOCAL_FAIL:i==3?D2KM_NOT_MEASURED:D2KM_CONFLICTING;
        CHECK(run_case(i,&r)==expect);CHECK(!direct_calls && !store.knowledge.entries[0].history_count);}
    fixture();CHECK(run_case(1,&r)==D2KM_BLOCK_GONE);CHECK(trial_calls==2 && direct_calls==2);
    CHECK(!d2km_knowledge_active(&store.knowledge.entries[0]));
    store.knowledge.entries[0].last_success_ms=UINT64_MAX;CHECK(!d2km_knowledge_active(&store.knowledge.entries[0]));
    fixture();checkpoint_failure=1;CHECK(run_case(1,&r)==D2KM_LOCAL_FAIL && !direct_calls && checkpoints==1);checkpoint_failure=0;
    fixture();context.form.hello_print++;CHECK(run_case(0,&r)==D2KM_APPLIED && trial_calls==2);
    fixture();context.form.ech=1;CHECK(run_case(0,&r)==D2KM_NOT_MEASURED && !calls);
    fixture();context.family=D2KM_IPV6;CHECK(run_case(0,&r)==D2KM_NOT_MEASURED && !calls);
    fixture();context.protocol=D2KM_P_TLS12;CHECK(run_case(0,&r)==D2KM_NOT_MEASURED && !calls);
    fixture();d2km_target_name(&context.target,"other.example");CHECK(run_case(0,&r)==D2KM_NOT_MEASURED && !calls);
    fixture();CHECK(run_case(5,&r)==D2KM_NOT_MEASURED && trial_calls==2 && !direct_calls);
    CHECK(store.knowledge.entries[0].program.splits[0].offset==2);
    CHECK(store.knowledge.entries[0].last_success_ms==100 && !store.knowledge.entries[0].history_count);
    DONE("degradation exact program before DIRECT");
}
