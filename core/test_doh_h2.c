/* Virtual monotonic clock: no network and no wall-clock sleeps. */
/* Те же макросы, что у verify.c: time.h подключается раньше него, и без
   них glibc под -std=c99 не объявляет clockid_t и struct timespec. */
#define _POSIX_C_SOURCE 200809L
#include <time.h>
#include <stdint.h>
static int64_t virtual_ms;
static int fake_clock_gettime(clockid_t id,struct timespec *t) {
    (void)id;t->tv_sec=virtual_ms/1000;t->tv_nsec=(virtual_ms%1000)*1000000;return 0;
}
static int fake_nanosleep(const struct timespec *t,struct timespec *remaining) {
    (void)remaining;virtual_ms+=(int64_t)t->tv_sec*1000+(t->tv_nsec+999999)/1000000;return 0;
}
#define clock_gettime fake_clock_gettime
#define nanosleep fake_nanosleep
#include "verify.c"
static int failures;
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);failures++;}}while(0)
typedef struct {uint8_t q[4096];size_t n,p;unsigned requests;int cut,bad,control,hints,cut_progress,write_fail,no_end,latency_ms,counter_unavailable,goaway;long packets;} fake;
static void add_frame(fake *f,unsigned type,unsigned flags,uint32_t stream,const uint8_t *b,size_t n) {
    uint8_t *p=f->q+f->n;p[0]=p[1]=0;p[2]=(uint8_t)n;p[3]=type;p[4]=flags;
    p[5]=stream>>24;p[6]=stream>>16;p[7]=stream>>8;p[8]=stream;
    memcpy(p+9,b,n);f->n+=9+n;
}
static int fake_write(void *v,const uint8_t *b,size_t n,char *e,size_t cap) {
    (void)e;(void)cap;fake *f=v;
    if(n>=9&&b[3]==1) {
        f->requests++;f->n=f->p=0;virtual_ms+=f->latency_ms;
        if(f->write_fail && f->requests==2)return -1;
        if(f->cut&&(int)f->requests>f->cut) {
            if(f->cut_progress<0)f->packets=-1;
            else f->packets+=f->cut_progress;
            return 0;
        }
        uint32_t stream=(uint32_t)b[5]<<24|(uint32_t)b[6]<<16|(uint32_t)b[7]<<8|b[8];
        if(f->goaway && f->requests==2) {
            uint8_t message[8]={0,0,0,1,0,0,0,0};
            add_frame(f,7,0,0,message,sizeof message);
            return 0;
        }
        if(f->control){uint8_t ctl[]={0,0,0,0,16};add_frame(f,f->control==1?2:42,0,stream,ctl,5);}
        if(f->hints){uint8_t early[]={8,3,'1','0','3'};add_frame(f,1,4,stream,early,sizeof early);}
        uint8_t h[]={0x88};
add_frame(f,1,4,stream,h,1);
        uint8_t dns[sizeof doh_query];memcpy(dns,doh_query,sizeof dns);dns[2]=0x81;dns[3]=0x83;
        if(f->bad&&(int)f->requests==f->bad)dns[13]='X';
        add_frame(f,0,f->no_end?0:1,stream,dns,sizeof dns);f->packets+=4;
    }
    return 0;
}
static long fake_read(void *v,uint8_t *b,size_t cap,int wait,char *e,size_t ec) {
    fake *f=v;if(f->p==f->n){struct timespec ts={wait/1000,(wait%1000)*1000000L};nanosleep(&ts,NULL);snprintf(e,ec,"timeout");return -1;}
    size_t n=f->n-f->p;if(n>cap)n=cap;if(n>3)n=3;memcpy(b,f->q+f->p,n);f->p+=n;return (long)n;
}
static long packets(void *v){fake *f=v;return f->counter_unavailable?-1:f->packets;}
static int peer(void *v){(void)v;return 0;}
typedef struct {unsigned calls,stop;int refuse;d2k_doh_observation last;} watcher;
static int observe(void *ctx,const d2k_doh_observation *o) {
    watcher *w=ctx;w->calls++;w->last=*o;
    CHECK(o->ordinal==w->calls && o->stream_id==2*w->calls-1);
    CHECK(o->finished_ms>=o->started_ms);
    CHECK(o->query_schema==D2K_DOH_QUERY_SCHEMA_V1 && o->timeout_ms==5);
    return w->refuse?-1:w->calls<w->stop;
}
int main(void) {
    {
        fake f={.no_end=1};watcher w={.stop=1};budget_io bio={packets,peer,&f};
        d2k_ver_result r={0};char err[160]={0};
        request_doh_h2_observed(fake_read,fake_write,&f,"dns.example","/dns-query",5,&bio,0,&r,err,sizeof err,observe,&w);
        CHECK(!r.body_complete && !r.doh_replies && !w.last.dns_valid);
        CHECK(r.status==200 && r.body_bytes==sizeof doh_query);
        CHECK(strstr(r.reason,"frame header") && strstr(r.reason,"DATA bytes"));
    }
    for(int mode=0;mode<5;mode++) {
        fake f={0};watcher w={0};w.stop=3;int64_t started=virtual_ms;
        if(mode==1)f.cut=1;
        if(mode==2)w.refuse=1;
        if(mode==3)f.bad=2;
        if(mode==4)f.write_fail=1;
        budget_io bio={packets,peer,&f};d2k_ver_result r={0};r.fd=-1;
        char err[160]={0};
        request_doh_h2_observed(fake_read,fake_write,&f,"dns.example","/dns-query",5,&bio,0,&r,err,sizeof err,observe,&w);
        CHECK(w.calls==(mode==0?3u:mode==2?1u:2u));
        if(mode==0)CHECK(virtual_ms==started);
        CHECK(f.requests==w.calls);
        CHECK(r.budget!=D2K_BUDGET_PASSED);
        CHECK(w.last.dns_valid==(mode==0||mode==2));
        CHECK(w.last.timed_out==(mode==1));
        CHECK(r.local_refusal==(mode==2));
        if(mode==1){CHECK(strstr(w.last.response.reason,"timeout"));CHECK(strstr(r.reason,"timeout"));}
        if(mode==3){CHECK(strstr(w.last.response.reason,"invalid response"));CHECK(strstr(r.reason,"invalid response"));}
        if(mode==3)CHECK(w.last.response.body_complete && w.last.response.status==200);
        if(mode==4)CHECK(!w.last.response.body_complete && !w.last.response.status && !w.last.response.body_bytes);
    }
    for(int mode=0;mode<6;mode++) {
        fake f={0};if(mode==1)f.cut=4;if(mode==2)f.bad=2;if(mode==3)f.control=1;if(mode==4)f.control=2;if(mode==5)f.hints=1;
        budget_io bio={packets,peer,&f};d2k_ver_result r={0};r.fd=-1;r.level=D2K_VER_HANDSHAKE;
        int64_t started=virtual_ms;char err[160]={0};request_doh_h2(fake_read,fake_write,&f,"dns.example","/dns-query",5,&bio,10,&r,err,sizeof err);
        if(mode==0||mode>=3)CHECK(r.level==D2K_VER_APPLICATION&&r.budget==D2K_BUDGET_PASSED&&f.requests==20 && virtual_ms-started>=30000);
        if(mode==1)CHECK(r.budget==D2K_BUDGET_CUT&&!r.dns_reply_rejected&&f.requests==5);
        if(mode==2)CHECK(r.dns_reply_rejected&&r.level!=D2K_VER_APPLICATION&&r.budget!=D2K_BUDGET_PASSED&&f.requests==2);
    }
    for(int unavailable=0;unavailable<2;unavailable++) {
        fake f={0};f.cut=4;f.cut_progress=unavailable?-1:3;
        budget_io bio={packets,peer,&f};d2k_ver_result r={0};r.fd=-1;
        char err[160]={0};
        request_doh_h2(fake_read,fake_write,&f,"dns.example","/dns-query",5,&bio,10,&r,err,sizeof err);
        CHECK(r.budget==D2K_BUDGET_CUT && r.budget_requests==5);
        CHECK(r.doh_replies==4 && r.status==0 && !r.body_complete);
        CHECK(r.budget_uncountable==unavailable);
        CHECK(r.budget_packets==(unavailable?0u:19u));
    }
    /* One response, packet budget already reached: still not durable. */
    for(unsigned budget=0;budget<=1;budget++) {
        fake f={.cut=1};budget_io bio={packets,peer,&f};d2k_ver_result r={0};char err[160]={0};
        request_doh_h2(fake_read,fake_write,&f,"dns.example","/dns-query",5,&bio,budget,&r,err,sizeof err);
        CHECK(r.doh_replies==1 && r.budget!=D2K_BUDGET_PASSED && f.requests==2);
        CHECK(r.level!=D2K_VER_APPLICATION);
    }
    /* Immediate replies must be paced to span the full verification window. */
    {
        fake f={0};budget_io bio={packets,peer,&f};d2k_ver_result r={0};char err[160]={0};
        int64_t started=virtual_ms;
        request_doh_h2(fake_read,fake_write,&f,"dns.example","/dns-query",5,&bio,0,&r,err,sizeof err);
        CHECK(r.doh_replies>=20 && r.budget==D2K_BUDGET_PASSED);
        CHECK(virtual_ms-started>=30000 && f.requests==20);
    }
    {
        fake f={.goaway=1};budget_io bio={packets,peer,&f};
        d2k_ver_result r={0};char err[160]={0};
        request_doh_h2(fake_read,fake_write,&f,"dns.example","/dns-query",5,&bio,0,&r,err,sizeof err);
        CHECK(r.dns_session_ended && r.doh_replies==1);
        CHECK(r.level==D2K_VER_HANDSHAKE && r.budget==D2K_BUDGET_NOT_APPLICABLE);
    }
    /* Duration alone and 19 valid replies followed by an invalid reply fail. */
    for(int mode=0;mode<2;mode++) {
        fake f={.latency_ms=2000};
        if(mode)f.bad=20;else f.cut=19;
        budget_io bio={packets,peer,&f};d2k_ver_result r={0};char err[160]={0};
        int64_t started=virtual_ms;
        request_doh_h2(fake_read,fake_write,&f,"dns.example","/dns-query",3000,&bio,0,&r,err,sizeof err);
        CHECK(virtual_ms-started>=30000 && r.doh_replies==19);
        CHECK(r.budget!=D2K_BUDGET_PASSED && r.level!=D2K_VER_APPLICATION);
    }
    /* Packet counters are diagnostic; unavailable counts cannot replace DNS proof. */
    {
        fake f={.counter_unavailable=1};budget_io bio={packets,peer,&f};
        d2k_ver_result r={0};char err[160]={0};int64_t started=virtual_ms;
        request_doh_h2(fake_read,fake_write,&f,"dns.example","/dns-query",5,&bio,10,&r,err,sizeof err);
        CHECK(r.doh_replies==20 && virtual_ms-started>=30000);
        CHECK(r.budget==D2K_BUDGET_PASSED && !r.budget_uncountable && !r.budget_packets);
    }
    int status=0;uint8_t unsupported[]={0xbe};CHECK(dh2_headers(unsupported,1,&status)<0);
    uint8_t valid[]={0x88};CHECK(!dh2_headers(valid,1,&status)&&status==200);
    return failures?1:0;
}
