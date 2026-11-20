#define _POSIX_C_SOURCE 200809L
#include "sched.c"
#include <poll.h>
static int fails;
#define CHECK(c,m) do {if(!(c)){fprintf(stderr,"FAIL: %s\n",m);fails++;}}while(0)
static const char *plan="d2k-plan 1 1\nid 00000000000000000000000000000000\nproto udp voice\npayload 1 00\npoison 1 badsum\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\n";
static int mark_ok(int fd,uint32_t m){(void)fd;return m==0x2e?0:-1;}
static int read_all(int fd,uint8_t *p,size_t n){
    while(n){struct pollfd q={fd,POLLIN,0};if(poll(&q,1,100)<=0)return -1;
        ssize_t k=read(fd,p,n);if(k<=0)return -1;p+=k;n-=(size_t)k;}return 0;
}
static void installed(int fd,int family,uint16_t port,const uint8_t token[16]){
    uint8_t h[6],body[8192];
    if(read_all(fd,h,6)){CHECK(0,"confirmation sends scoped installation");return;}
    size_t n=((size_t)h[0]<<24)|((size_t)h[1]<<16)|((size_t)h[2]<<8)|h[3];
    if(n<2||n>sizeof body+2||read_all(fd,body,n-2)){CHECK(0,"complete installation frame");return;}
    CHECK((((unsigned)h[4]<<8)|h[5])==D2K_CMD_SET_ENDPOINT_BOUND,"protocol success requests scoped acknowledged installation");
    uint8_t ip[16]={0};inet_pton(family==6?AF_INET6:AF_INET,family==6?"::1":"127.0.0.1",ip);
    CHECK(n>22 && body[0]==family && !memcmp(body+1,ip,16) && body[17]==D2K_LINK_SHAPE_VOICE &&
        body[18]==(port>>8) && body[19]==(port&255),"installation carries measured family, address, shape and port");
    CHECK(n>=38 && !memcmp(body+n-2-16,token,16),"installation carries its own request token");
}
static task *prepare(d2k_sched *s,int family,uint16_t port,int discovery){
    task *t=&s->tasks[0];task_reset(s,t);t->state=T_VOICE_WATCH;
    t->family=(uint8_t)family;t->transport=17;t->port=port;
    strcpy(t->ip,family==6?"::1":"127.0.0.1");strcpy(t->name,D2K_LINK_VOICE_CLASS);
    t->voice_proof_code=discovery?D2K_UDP_PROOF_VOICE_DISCOVERY:D2K_UDP_PROOF_STUN;
    t->voice_discovery_verified=discovery==1;t->n_plans=1;strcpy(t->plans[0],plan);
    return t;
}
static void run(int family,int discovery){
    int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"control pair");
    d2k_catalog c={0};d2k_sched *s=d2k_sched_new(&c,sv[0],0x2e);if(!s){fails++;return;}
    /* This fixture starts at the confirmation sink. It checks scope and
       persistence, not whether the preceding application evidence is valid. */
    for(unsigned i=0;i<3;i++){
        uint16_t port=i==1?3479:3478;task *t=prepare(s,family,port,discovery);
        uint64_t before=c.revision;
        voice_confirm(s,t,1000+i);installed(sv[1],family,port,t->voice_install_token);
        CHECK(c.revision==before && t->state==T_VOICE_INSTALL,"sending command cannot persist confirmation");
        d2k_ev ack={0};ack.kind=D2K_EV_ACK;ack.code=D2K_CMD_SET_ENDPOINT_BOUND;ack.num=0x100;
        memcpy(ack.trial_id,t->voice_install_token,16);
        ack.execution_binding.kind=D2K_BIND_ADDR;ack.execution_binding.family=family;
        ack.execution_binding.shape=D2K_LINK_SHAPE_VOICE;
        ack.execution_binding.generation=i+1;ack.execution_binding.epoch[0]=1;
        ack.trial_id[0]^=1;d2k_sched_event(s,&ack);
        voice_confirm(s,t,1000+i);
        CHECK(c.revision==before,"foreign install ACK cannot authorize persistence");
        ack.trial_id[0]^=1;d2k_sched_event(s,&ack);voice_confirm(s,t,1000+i);
    }
    size_t count=0;int first=0,second=0;
    for(size_t i=0;i<c.n_boxes;i++)for(size_t j=0;j<c.boxes[i].n_binds;j++){
        d2k_cat_binding *b=&c.boxes[i].binds[j];count++;
        CHECK(!strcmp(b->kind,"service") && b->family==family && b->transport==17 &&
              b->shape==D2K_LINK_SHAPE_VOICE,"confirmation persists a protocol-specific service key");
        if(b->server_port==3478){first++;CHECK(b->successes==2,"repeat updates only the same service");}
        if(b->server_port==3479){second++;CHECK(b->successes==1,"neighbor service retains its own history");}
    }
    CHECK(count==2 && first==1 && second==1,"two server ports cannot overwrite each other's confirmation");
    char path[]="/tmp/d2k-service-confirm-XXXXXX",err[160];int file=mkstemp(path);
    CHECK(file>=0,"catalog temporary file");if(file>=0)close(file);
    d2k_catalog restored={0};
    CHECK(!d2k_catalog_save(&c,path,err,sizeof err) &&
          !d2k_catalog_load(path,&restored,err,sizeof err),"real service confirmations survive catalog round trip");
    unlink(path);
    s->cat=&restored;
    if(!discovery){
        task *t=prepare(s,family,3478,0);
        CHECK(stun_candidate_start(s,t,2000)==1,"real STUN catalog producer feeds own-service candidate consumer");
        d2k_ev cleanup={0};cleanup.kind=D2K_EV_ACK;cleanup.code=D2K_CMD_DEL_ADDR_PROBE;cleanup.num=0x100;
        memcpy(cleanup.trial_id,t->stun_trial_id,16);task_done(s,t);d2k_stun_trial_reap(&cleanup);
    }
    s->cat=&c;
    d2k_sched_free(s);d2k_catalog_free(&restored);d2k_catalog_free(&c);close(sv[0]);close(sv[1]);
}
int main(void){
    d2k_mark_fn saved=d2k_mark_hook;d2k_mark_hook=mark_ok;
    for(int f=4;f<=6;f+=2)for(int d=0;d<3;d++)run(f,d);
    d2k_mark_hook=saved;if(fails)return 1;
    puts("Service confirmation scope: all checks passed");return 0;
}
