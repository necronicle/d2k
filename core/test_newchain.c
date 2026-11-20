#define _POSIX_C_SOURCE 200809L
#include "d2k_newchain.h"
#include "d2k_ctl.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
static d2km_store store;
static unsigned char frame[100000];
static void log_note(void *ctx,const char *reason) { unsigned *n=ctx;assert(*reason);(*n)++; }
static unsigned command(int fd) {
    assert(read(fd,frame,4)==4);
    size_t length=(size_t)frame[0]*16777216u+(size_t)frame[1]*65536u+(size_t)frame[2]*256u+frame[3];
    assert(length>=2 && length<sizeof frame-4);size_t used=0;
    while(used<length) {ssize_t n=read(fd,frame+4+used,length-used);assert(n>0);used+=(size_t)n;}
    return (unsigned)frame[4]*256+frame[5];
}
static void fixture(void) {
    d2km_store_init(&store);store.knowledge.count=1;
    d2km_knowledge *k=&store.knowledge.entries[0];
    store.boxes.count=1;store.boxes.entries[0].id=2;store.boxes.entries[0].version=1;
    k->id=1;k->box=2;k->model_version=1;k->experiment=3;k->last_success_ms=1000;
    assert(!d2km_target_name(&k->context.target,"blocked.example"));
    k->context.transport=D2KM_TCP;k->context.protocol=D2KM_P_TLS13;k->context.family=D2KM_IPV4;
    k->binding=D2KM_BIND_NAME;k->program.transport=D2KM_TCP;k->program.protocol=D2KM_P_TLS13;
    k->program.split_count=1;k->program.splits[0].anchor=D2KM_AT_PAYLOAD_START;k->program.splits[0].offset=1;
    strcpy(k->program.splits[0].why,"F1: measured split");k->hash=d2km_program_hash(&k->program);
    strcpy(k->why,"{\"reason\":\"K1: вопросы\"}\n");
}
static d2k_ev accepted(const d2k_newchain *n,size_t i) {
    const d2k_newchain_entry *e=&n->entries[i];
    d2k_ev ack={.kind=D2K_EV_ACK,.code=D2K_CMD_SET_NAME_BOUND,.num=1u<<8};
    memcpy(ack.trial_id,e->token,16);
    ack.execution_binding=(d2k_binding_context){.kind=D2K_BIND_NAME,.family=e->desired.family,
        .shape=e->desired.shape,.generation=7+i};ack.execution_binding.epoch[0]=1;return ack;
}
static void loss_and_refusal(const char *path,int fd,int peer) {
    fixture();d2km_store_error error;assert(d2km_store_save(path,&store,&error)==D2KM_STORE_OK);
    d2k_newchain n={0};assert(!d2k_newchain_set(&n,path));
    assert(d2k_newchain_poll(&n,fd,1000,NULL,NULL)==1);assert(command(peer)==D2K_CMD_SET_NAME_BOUND);
    d2k_ev ack=accepted(&n,0),stale=ack;ack.num=D2K_ACK_BAD_PLAN;
    assert(d2k_newchain_event(&n,&ack,NULL,NULL));assert(!d2k_newchain_count(&n));
    assert(!d2k_newchain_protects(&n,"blocked.example",6,4,1));
    assert(d2k_newchain_poll(&n,fd,6000,NULL,NULL)==1);assert(command(peer)==D2K_CMD_SET_NAME_BOUND);
    assert(!d2k_newchain_event(&n,&stale,NULL,NULL)); /* refused generation cannot acquire ownership */
    stale=accepted(&n,0);
    assert(d2k_newchain_poll(&n,fd,11000,NULL,NULL)==1);assert(command(peer)==D2K_CMD_SET_NAME_BOUND);
    assert(!d2k_newchain_event(&n,&stale,NULL,NULL)); /* retry changed correlation */
    store.knowledge.count=0;assert(d2km_store_save(path,&store,&error)==D2KM_STORE_OK);
    assert(d2k_newchain_poll(&n,fd,16000,NULL,NULL)==1);assert(command(peer)==D2K_CMD_SET_NAME_BOUND);
    ack=accepted(&n,0);assert(d2k_newchain_event(&n,&ack,NULL,NULL));
    assert(d2k_newchain_poll(&n,fd,21000,NULL,NULL)==1);
    assert(command(peer)==D2K_CMD_DEL_NAME_BOUND && command(peer)==D2K_CMD_ARM_SHAPE);
    int broken=open(path,O_WRONLY|O_TRUNC);assert(broken>=0);assert(write(broken,"bad",3)==3);close(broken);
    assert(d2k_newchain_poll(&n,fd,26000,NULL,NULL)==1);assert(command(peer)==D2K_CMD_ARM_SHAPE);
    /* Foreign HTTP deletion ACK never releases this binding. */
    ack.code=D2K_CMD_DEL_NAME_BOUND;assert(!d2k_newchain_event(&n,&ack,NULL,NULL));assert(d2k_newchain_count(&n)==1);
    ack.code=D2K_CMD_ARM_SHAPE;ack.num=D2K_ACK_BAD_ARGS;memcpy(ack.trial_id,n.entries[0].token,16);
    assert(d2k_newchain_event(&n,&ack,NULL,NULL));assert(!d2k_newchain_count(&n));
    assert(!d2k_newchain_set(&n,NULL));
}
static void separate_contexts(const char *path,int fd,int peer) {
    fixture();store.knowledge.count=5;
    for(size_t i=1;i<5;i++) {
        store.knowledge.entries[i]=store.knowledge.entries[0];d2km_knowledge *k=&store.knowledge.entries[i];
        k->id=(uint32_t)i+1;k->context.family=i==2||i==3?D2KM_IPV6:D2KM_IPV4;
        k->context.protocol=i==1||i==3?D2KM_P_TLS12:D2KM_P_TLS13;k->program.protocol=k->context.protocol;
        k->context.form.ech=i==4;k->hash=d2km_program_hash(&k->program);
    }
    d2km_store_error error;assert(d2km_store_save(path,&store,&error)==D2KM_STORE_OK);
    d2k_newchain n={0};assert(!d2k_newchain_set(&n,path));
    for(size_t i=0;i<5;i++) {
        assert(d2k_newchain_poll(&n,fd,1000+(int64_t)i,NULL,NULL)==1);assert(command(peer)==D2K_CMD_SET_NAME_BOUND);
        d2k_ev ack=accepted(&n,i);assert(d2k_newchain_event(&n,&ack,NULL,NULL));
    }
    assert(!d2k_newchain_poll(&n,fd,1006,NULL,NULL));assert(d2k_newchain_count(&n)==5);
    assert(d2k_newchain_protects(&n,"blocked.example",6,4,D2K_LINK_SHAPE_ECH_TCP));
    /* Invalid store names are rejected before emitting any commands/JSON. */
    strcpy(store.knowledge.entries[0].context.target.name,"bad\"name.example");
    assert(d2km_store_save(path,&store,&error)==D2KM_STORE_OK);
    assert(d2k_newchain_poll(&n,fd,7000,NULL,NULL)<0);assert(d2k_newchain_count(&n)==5);
    assert(!d2k_newchain_set(&n,NULL));
}
static void retirement_dominates_older(const char *path,int fd,int peer) {
    for(int different=0;different<2;different++) {
        fixture();store.knowledge.count=2;store.knowledge.entries[1]=store.knowledge.entries[0];
        d2km_knowledge *latest=&store.knowledge.entries[1];latest->id=2;latest->last_success_ms=2000;
        latest->context.form.hello_print=42;
        if(different)latest->program.splits[0].offset=2;
        latest->hash=d2km_program_hash(&latest->program);
        d2km_store_error error;assert(d2km_store_save(path,&store,&error)==D2KM_STORE_OK);
        d2k_newchain n={0};assert(!d2k_newchain_set(&n,path));assert(d2k_newchain_poll(&n,fd,1000,NULL,NULL)==1);
        assert(command(peer)==D2K_CMD_SET_NAME_BOUND);d2k_ev ack=accepted(&n,0);assert(d2k_newchain_event(&n,&ack,NULL,NULL));
        assert(n.entries[0].active.knowledge==2);
        latest->history_count=1;latest->history[0]=(d2km_knowledge_history){.time_ms=3000,.previous_hash=latest->hash,.experiment=5,.outcome=D2KM_DEGRADED};
        assert(d2km_store_save(path,&store,&error)==D2KM_STORE_OK);
        assert(d2k_newchain_poll(&n,fd,6000,NULL,NULL)==1);
        assert(command(peer)==D2K_CMD_DEL_NAME_BOUND && command(peer)==D2K_CMD_ARM_SHAPE);
        ack.code=D2K_CMD_ARM_SHAPE;ack.num=D2K_ACK_BAD_ARGS;memcpy(ack.trial_id,n.entries[0].token,16);
        assert(d2k_newchain_event(&n,&ack,NULL,NULL));assert(!d2k_newchain_count(&n));
        assert(!d2k_newchain_set(&n,NULL));assert(!d2k_newchain_set(&n,path));
        assert(!d2k_newchain_poll(&n,fd,1000,NULL,NULL) && !d2k_newchain_count(&n));
        assert(store.knowledge.entries[0].id==1 && d2km_knowledge_active(&store.knowledge.entries[0]));
        /* Only a genuinely newer successful validation can reactivate key. */
        store.knowledge.entries[2]=store.knowledge.entries[0];store.knowledge.count=3;
        store.knowledge.entries[2].id=3;store.knowledge.entries[2].last_success_ms=4000;
        store.knowledge.entries[2].context.form.hello_print=43;
        assert(d2km_store_save(path,&store,&error)==D2KM_STORE_OK);
        assert(d2k_newchain_poll(&n,fd,6000,NULL,NULL)==1);assert(command(peer)==D2K_CMD_SET_NAME_BOUND);
        ack=accepted(&n,0);assert(d2k_newchain_event(&n,&ack,NULL,NULL));assert(n.entries[0].active.knowledge==3);
        assert(!d2k_newchain_set(&n,NULL));
    }
}
int main(void) {
    char path[]="/tmp/newchain-test-XXXXXX";int file=mkstemp(path);assert(file>=0);close(file);
    fixture();d2km_store_error error;assert(d2km_store_save(path,&store,&error)==D2KM_STORE_OK);
    int pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));unsigned logs=0;
    d2k_newchain n={0};assert(!d2k_newchain_set(&n,NULL));
    assert(!d2k_newchain_poll(&n,pair[0],1000,log_note,&logs));assert(!n.count);
    assert(!d2k_newchain_set(&n,path));assert(d2k_newchain_poll(&n,pair[0],1000,log_note,&logs)>0);
    assert(command(pair[1])==D2K_CMD_SET_NAME_BOUND); /* atomic SET, never DEL first */
    assert(d2k_newchain_protects(&n,"blocked.example",6,4,D2K_SHAPE_MODERN));
    assert(!d2k_newchain_count(&n)); /* write is not ACK */
    d2k_ev ack={.kind=D2K_EV_ACK,.code=D2K_CMD_SET_NAME_BOUND,.num=1u<<8};
    memcpy(ack.trial_id,n.entries[0].token,16);
    ack.execution_binding=(d2k_binding_context){.kind=D2K_BIND_NAME,.family=4,.shape=D2K_SHAPE_MODERN,.generation=7};
    ack.execution_binding.epoch[0]=1;
    assert(d2k_newchain_event(&n,&ack,log_note,&logs));assert(d2k_newchain_count(&n)==1);
    assert(!d2k_newchain_protects(&n,"blocked.example",6,6,D2K_SHAPE_MODERN));
    assert(!d2k_newchain_protects(&n,"blocked.example",6,4,D2K_SHAPE_LEGACY));
    assert(!d2k_newchain_protects(&n,"other.example",6,4,D2K_SHAPE_MODERN));
    /* Reload an invalid store without losing current ownership. */
    file=open(path,O_WRONLY|O_TRUNC);assert(file>=0);assert(write(file,"bad",3)==3);close(file);
    assert(d2k_newchain_poll(&n,pair[0],6000,log_note,&logs)<0);assert(d2k_newchain_count(&n)==1);
    /* Durable DEGRADED history suppresses restart and conditionally removes current generation. */
    store.knowledge.entries[0].history_count=1;
    store.knowledge.entries[0].history[0]=(d2km_knowledge_history){.outcome=D2KM_DEGRADED,.previous_hash=store.knowledge.entries[0].hash,.experiment=5,.time_ms=2000};
    assert(d2km_store_save(path,&store,&error)==D2KM_STORE_OK);
    assert(d2k_newchain_poll(&n,pair[0],11000,log_note,&logs)>0);
    assert(command(pair[1])==D2K_CMD_DEL_NAME_BOUND);
    assert(command(pair[1])==D2K_CMD_ARM_SHAPE);
    ack.num=D2K_ACK_BAD_ARGS;ack.code=D2K_CMD_ARM_SHAPE;memcpy(ack.trial_id,n.entries[0].token,16);assert(d2k_newchain_event(&n,&ack,log_note,&logs));assert(!d2k_newchain_count(&n));
    d2k_newchain restart={0};assert(!d2k_newchain_set(&restart,path));
    assert(!d2k_newchain_poll(&restart,pair[0],16000,log_note,&logs));assert(!restart.count);
    assert(!d2k_newchain_set(&restart,NULL));assert(!d2k_newchain_set(&n,NULL));
    /* Missing/corrupt startup keeps the controller alive with a reason. */
    unsigned before=logs;d2k_newchain missing={0};assert(!d2k_newchain_set(&missing,"/nonexistent/newchain-store"));
    assert(d2k_newchain_poll(&missing,pair[0],1000,log_note,&logs)<0 && !d2k_newchain_count(&missing));
    assert(logs>before);assert(!d2k_newchain_set(&missing,NULL));
    file=open(path,O_WRONLY|O_TRUNC);assert(file>=0);assert(write(file,"bad",3)==3);close(file);
    assert(!d2k_newchain_set(&missing,path));before=logs;
    assert(d2k_newchain_poll(&missing,pair[0],1000,log_note,&logs)<0 && !d2k_newchain_count(&missing));
    assert(logs>before);assert(!d2k_newchain_set(&missing,NULL));
    assert(logs>=3);loss_and_refusal(path,pair[0],pair[1]);separate_contexts(path,pair[0],pair[1]);retirement_dominates_older(path,pair[0],pair[1]);close(pair[0]);close(pair[1]);unlink(path);puts("newchain: ok");return 0;
}
