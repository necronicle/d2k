#define _DARWIN_C_SOURCE
#define pthread_create newchain_thread_create
#include "sched.c"
#undef pthread_create
#include <assert.h>
#include <sys/socket.h>
int newchain_thread_create(pthread_t *t,const pthread_attr_t *a,void *(*fn)(void *),void *arg)
{(void)t;(void)a;(void)fn;(void)arg;return EAGAIN;}
static d2km_store newchain_store;
static void persisted(const char *path) {
    d2km_store_init(&newchain_store);newchain_store.boxes.count=1;
    newchain_store.boxes.entries[0].id=2;newchain_store.boxes.entries[0].version=1;
    newchain_store.knowledge.count=1;d2km_knowledge *k=&newchain_store.knowledge.entries[0];
    k->id=1;k->box=2;k->model_version=1;k->experiment=3;k->last_success_ms=1000;
    assert(!d2km_target_name(&k->context.target,"blocked.example"));
    k->context.transport=D2KM_TCP;k->context.protocol=D2KM_P_TLS13;k->context.family=D2KM_IPV4;k->binding=D2KM_BIND_NAME;
    k->program.transport=D2KM_TCP;k->program.protocol=D2KM_P_TLS13;k->program.split_count=1;
    k->program.splits[0].anchor=D2KM_AT_PAYLOAD_START;k->program.splits[0].offset=1;
    strcpy(k->program.splits[0].why,"F1: measured boundary");k->hash=d2km_program_hash(&k->program);
    strcpy(k->why,"{\"reason\":\"K1: вопросы\"}\n");d2km_store_error error;
    assert(d2km_store_save(path,&newchain_store,&error)==D2KM_STORE_OK);
}
static void drain_command(int fd,unsigned expected) {
    uint8_t header[6];assert(read(fd,header,6)==6);
    unsigned cmd=(unsigned)header[4]*256+header[5];assert(cmd==expected);
    size_t len=(size_t)header[0]*16777216u+(size_t)header[1]*65536u+(size_t)header[2]*256u+header[3]-2;
    uint8_t buf[4096];while(len) {size_t n=len<sizeof buf?len:sizeof buf;ssize_t used=read(fd,buf,n);assert(used>0);len-=(size_t)used;}
}
static void no_command(int fd) {uint8_t c;assert(read(fd,&c,1)<0 && (errno==EAGAIN || errno==EWOULDBLOCK));}
static d2k_ev client(uint16_t kind) {
    d2k_ev e={.kind=kind,.family=4,.transport=6,.low_port=50000,.high_port=443,.client_side=D2K_CLIENT_SIDE_LOW,.client_shape=D2K_SHAPE_MODERN};
    inet_pton(AF_INET,"192.168.1.2",e.low_ip);inet_pton(AF_INET,"192.0.2.5",e.high_ip);return e;
}
int main(void) {
    alarm(20);
    char dir[]="/tmp/newchain-sched-XXXXXX",path[512],queue[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/store",dir);snprintf(queue,sizeof queue,"%s/queue",dir);persisted(path);
    d2k_catalog cat={0};cat.n_boxes=1;cat.boxes=calloc(1,sizeof *cat.boxes);assert(cat.boxes);
    d2k_cat_box *b=&cat.boxes[0];strcpy(b->id,"old-box");b->n_plans=b->n_binds=1;
    b->plans=calloc(1,sizeof *b->plans);b->binds=calloc(1,sizeof *b->binds);assert(b->plans && b->binds);
    strcpy(b->plans[0].id,"old-plan");b->plans[0].enabled=1;
    char old_text[8192];assert(d2km_program_text(&newchain_store.knowledge.entries[0].program,old_text,sizeof old_text));
    b->plans[0].text=strdup(old_text);
    d2k_cat_binding *bd=&b->binds[0];strcpy(bd->kind,"name");strcpy(bd->target,"blocked.example");strcpy(bd->plan_id,"old-plan");
    bd->enabled=1;bd->level=3;bd->transport=6;bd->shape=D2K_SHAPE_MODERN;bd->family=4;bd->confirmed=100;
    int sv[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));
    d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2d);assert(s);s->meas_limit=0;s->clock_seen=1;s->now_ms=1000;
    assert(!d2k_sched_set_shadow(s,queue));
    d2k_sched_sync(s);while(d2k_sched_sync_pending(s))d2k_sched_sync_step(s);
    drain_command(sv[1],D2K_CMD_SET_NAME);
    assert(!d2k_sched_set_newchain(s,path));drain_command(sv[1],D2K_CMD_SET_NAME_BOUND);
    assert(d2k_sched_newchain_pending(s) && !d2k_newchain_count(&s->newchain));
    assert(!fcntl(sv[1],F_SETFL,O_NONBLOCK));
    d2k_sched_sync(s);while(d2k_sched_sync_pending(s))d2k_sched_sync_step(s);no_command(sv[1]);
    assert(bd->enabled && !strcmp(bd->plan_id,"old-plan") && b->n_binds==1);
    d2k_newchain_entry *entry=&s->newchain.entries[0];
    d2k_ev ack={.kind=D2K_EV_ACK,.code=D2K_CMD_SET_NAME_BOUND,.num=1u<<8};memcpy(ack.trial_id,entry->token,16);
    ack.execution_binding=(d2k_binding_context){.kind=D2K_BIND_NAME,.family=4,.shape=1,.generation=7};ack.execution_binding.epoch[0]=1;
    d2k_sched_event(s,&ack);assert(d2k_newchain_count(&s->newchain)==1);
    s->n_force=1;strcpy(s->force_suffixes[0],"blocked.example");
    d2k_ev e=client(D2K_EV_FLOW);d2k_sched_event(s,&e);
    e=client(D2K_EV_HELLO);strcpy(e.name,"blocked.example");d2k_sched_event(s,&e);
    assert(!task_of(s,e.name,6,4));
    e=client(D2K_EV_SUSPECT);e.code=D2K_SUSPECT_SILENT;e.planned=D2K_LINK_PLANNED_YES;
    e.execution_binding=entry->binding;memcpy(e.plan_id,entry->active.plan_id,16);d2k_sched_event(s,&e);
    d2k_shadow_record r;d2k_shadow_reader reader={0};assert(d2k_shadow_queue_next(queue,&r,&reader)==1);
    assert(r.degradation && r.protocol==2 && r.knowledge==1 && r.program_hash==entry->active.hash);
    assert(d2k_binding_equal(&r.binding,&entry->binding));assert(!task_of(s,"blocked.example",6,4));
    e.execution_binding.generation++;d2k_sched_event(s,&e);assert(!d2k_shadow_queue_next(queue,&r,&reader));
    /* Delayed old results cannot confirm, delete, start a worker or mutate catalog. */
    task *t=&s->tasks[0];strcpy(t->name,"blocked.example");t->transport=6;t->family=4;t->trigger_shape=1;t->state=T_PLANNING;
    forget_clear_target_bindings(s,t,2000);assert(!bd->recheck_since);
    assert(start_worker(s,t,JOB_CLASSIFY)<0);assert(!start_search(s,t));
    verify_confirm(s,t,2000);assert(t->state==T_FREE);assert(b->n_binds==1);no_command(sv[1]);
    char live[512];snprintf(live,sizeof live,"%s/live",dir);assert(!d2k_sched_write_live(s,live,NULL));
    FILE *f=fopen(live,"r");assert(f);char text[8192];size_t n=fread(text,1,sizeof text-1,f);text[n]=0;fclose(f);
    assert(strstr(text,"\"newchain_count\": 1") && strstr(text,"\"source\":\"questions\"") && strstr(text,"\"knowledge\":1"));
    /* A fresh controller restores valid knowledge before old catalog work. */
    d2k_sched_free(s);close(sv[0]);close(sv[1]);assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));
    s=d2k_sched_new(&cat,sv[0],0x2d);assert(s);s->now_ms=1000;s->clock_seen=1;s->meas_limit=0;
    assert(!d2k_sched_set_shadow(s,queue));assert(!d2k_sched_set_newchain(s,path));drain_command(sv[1],D2K_CMD_SET_NAME_BOUND);
    assert(!d2k_sched_set_synthesis_only(s,1));
    entry=&s->newchain.entries[0];memcpy(ack.trial_id,entry->token,16);d2k_sched_event(s,&ack);
    assert(d2k_newchain_count(&s->newchain)==1);
    /* The controller sets poll(timeout=0) while legacy sync is pending.
       A NEWCHAIN ACK must not leave it spinning in synthesis-only mode. */
    assert(!d2k_sched_sync_step(s));
    assert(!d2k_sched_sync_pending(s));
    s->sync_pending=1;s->sync_active=0;
    assert(!d2k_sched_sync_step(s));
    assert(!d2k_sched_sync_pending(s));
    assert(!d2k_sched_set_synthesis_only(s,0));
    /* Confirmed durable degradation removes only this generation, then old
       catalog can send its retained plan again. */
    d2km_knowledge *k=&newchain_store.knowledge.entries[0];k->history_count=1;
    k->history[0]=(d2km_knowledge_history){.previous_hash=k->hash,.outcome=D2KM_DEGRADED,.experiment=5,.time_ms=2000};
    d2km_store_error error;assert(d2km_store_save(path,&newchain_store,&error)==D2KM_STORE_OK);
    assert(d2k_newchain_poll(&s->newchain,sv[0],6000,newchain_log,s)==1);
    drain_command(sv[1],D2K_CMD_DEL_NAME_BOUND);drain_command(sv[1],D2K_CMD_ARM_SHAPE);
    ack.code=D2K_CMD_ARM_SHAPE;ack.num=D2K_ACK_BAD_ARGS;memcpy(ack.trial_id,entry->token,16);d2k_sched_event(s,&ack);
    assert(!d2k_newchain_count(&s->newchain));
    d2k_sched_sync(s);while(d2k_sched_sync_pending(s))d2k_sched_sync_step(s);drain_command(sv[1],D2K_CMD_SET_NAME);
    assert(b->n_binds==1 && bd->enabled && !bd->recheck_since && !strcmp(bd->plan_id,"old-plan"));
    d2k_sched_free(s);d2k_catalog_free(&cat);close(sv[0]);close(sv[1]);unlink(path);unlink(queue);unlink(live);assert(!rmdir(dir));
    puts("newchain scheduler ownership, queue, old workers/catalog, live JSON: ok");return 0;
}
