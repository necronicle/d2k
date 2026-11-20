#include "raw_tls.h"
#include "../core/include/d2k_hello.h"
#include "../core/include/d2k_plantlv.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
struct d2k_raw_tls {
    d2k_raw_episode *episode;
    d2k_detect_stop cancel;
    int has_cancel,sealed,first,eof,prepared;
    int scoped;
    uint32_t scope_offset;
    uint32_t after_offset,after_length;
    uint32_t sent;
    size_t begin,end;
    uint8_t reply[65535];
    d2k_trigger trigger;
    char plan[4096];
    d2k_raw_observation observed;
    d2k_raw_tls_sink sink;
    d2k_raw_tuple tuple;
    uint64_t ordinal;
};
static int record_io(d2k_raw_tls *t,d2k_raw_tls_action action,int64_t started,
    int result,int wait,const uint8_t *bytes,size_t len,const char *program) {
    if(!t->sink.record)return 0;
    d2k_raw_tls_event event={.experience=t->sink.experience,.ordinal=t->ordinal++,
        .started_ms=started,.finished_ms=d2k_now_ms(),.action=action,.send_offset=t->sent,
        .result=result,.wait_ms=wait,.observation=t->observed,.tuple=t->tuple,
        .bytes=bytes,.length=len,.program=program};
    if(!t->sink.record(t->sink.context,&event))return 0;
    t->sealed=1;t->observed.kind=D2K_RAW_OBS_LOCAL;return -1;
}
static const char identity[]=D2K_RAW_TLS_IDENTITY;
static int stopped(d2k_raw_tls *t) {
    if(t->has_cancel && d2k_detect_stopped(&t->cancel)) {
        t->sealed=1;t->observed.kind=D2K_RAW_OBS_CANCELLED;
    }
    return t->sealed;
}
static int submit(void *ctx,const uint8_t *buf,size_t len,char *err,size_t cap) {
    d2k_raw_tls *t=ctx;
    if(t && t->prepared) {
        if(stopped(t) || !buf || len!=t->trigger.len || memcmp(buf,t->trigger.payload,len)) {
            t->sealed=1;t->observed.kind=D2K_RAW_OBS_LOCAL;
            snprintf(err,cap,"TLS first write differs from measured input");return -1;
        }
        t->prepared=0;return 0;
    }
    if(!t || stopped(t) || t->eof || !buf || !len || len>UINT32_MAX-t->sent ||
       (t->first && len>sizeof t->trigger.payload)) {
        if(t)t->sealed=1;
        snprintf(err,cap,"raw TLS write unavailable or exceeds stream coordinates");return -1;
    }
    for(size_t off=0;off<len;) {
        size_t n=len-off;if(n>sizeof t->trigger.payload)n=sizeof t->trigger.payload;
        memset(&t->trigger,0,sizeof t->trigger);
        memcpy(t->trigger.payload,buf+off,n);t->trigger.len=n;
        size_t name_off=0,name_len=0;
        if(t->first && !d2k_hello_sni(buf+off,n,&name_off,&name_len)) {
            t->trigger.sni_off=(int)name_off;t->trigger.sni_len=(int)name_len;
        }
        if(t->scoped && t->sent<t->scope_offset && n>t->scope_offset-t->sent) {
            t->sealed=1;t->observed.kind=D2K_RAW_OBS_LOCAL;
            snprintf(err,cap,"write crosses measured TCP action offset");return -1;
        }
        if(t->after_length && ((t->sent<t->after_offset && n>t->after_offset-t->sent) ||
           (t->sent==t->after_offset && (n!=t->after_length || len-off!=n)))) {
            t->sealed=1;t->observed.kind=D2K_RAW_OBS_LOCAL;
            snprintf(err,cap,"write differs from composed TCP request interval");return -1;
        }
        const char *program=t->scoped?(t->sent==t->scope_offset?t->plan:identity):
            (t->first || (t->after_length && t->sent==t->after_offset)?t->plan:identity);
        int64_t started=d2k_now_ms();
        int rc=d2k_raw_episode_send(t->episode,t->sent,t->sent+(uint32_t)n,
            &t->trigger,program,t->has_cancel?&t->cancel:NULL,
            err,cap,&t->observed);
        if(record_io(t,D2K_RAW_TLS_SEND,started,rc,0,buf+off,n,program)) {
            snprintf(err,cap,"raw TLS send evidence was not recorded");return -1;
        }
        if(rc){t->sealed=1;return -1;}
        t->sent+=(uint32_t)n;off+=n;t->first=0;
    }
    return 0;
}
static long receive(void *ctx,uint8_t *buf,size_t cap,int wait,char *err,size_t ec) {
    d2k_raw_tls *t=ctx;
    if(!t || stopped(t) || t->prepared || !buf || !cap || wait<=0) {
        snprintf(err,ec,"raw TLS read unavailable");return -1;
    }
    if(t->begin==t->end) {
        if(t->eof)return 0;
        t->begin=t->end=0;
        int64_t started=d2k_now_ms();
        int rc=d2k_raw_episode_read(t->episode,wait,t->has_cancel?&t->cancel:NULL,
            t->reply,sizeof t->reply,&t->end,1,&t->observed);
        if(record_io(t,D2K_RAW_TLS_READ,started,rc,wait,t->reply,t->end,NULL)) {
            snprintf(err,ec,"raw TLS receive evidence was not recorded");return -1;
        }
        if(t->observed.kind==D2K_RAW_OBS_RESPONSE_FIN) {
            t->eof=1;
            if(!t->end)return 0;
        } else if(rc || !t->end) {
            t->sealed=1;snprintf(err,ec,"raw TLS read failed (observation %d)",(int)t->observed.kind);
            return -1;
        }
    }
    size_t n=t->end-t->begin;if(n>cap)n=cap;
    memcpy(buf,t->reply+t->begin,n);t->begin+=n;return (long)n;
}
int d2k_raw_tls_prepare(d2k_raw_tls *t,const uint8_t *bytes,size_t length,char *err,size_t cap) {
    if(!t || !t->first || t->prepared || t->sent) {
        snprintf(err,cap,"raw TLS first input already submitted");return -1;
    }
    if(submit(t,bytes,length,err,cap))return -1;
    t->prepared=1;return 0;
}
int d2k_raw_tls_prefix(d2k_raw_tls *t,int wait,const uint8_t **bytes,size_t *length,char *err,size_t cap) {
    if(bytes)*bytes=NULL;
    if(length)*length=0;
    if(!t || !bytes || !length || !t->prepared || stopped(t) || t->eof || wait<=0 ||
       t->end==sizeof t->reply) {
        snprintf(err,cap,"raw TLS prefix unavailable");return -1;
    }
    size_t received=0;int64_t started=d2k_now_ms();
    int rc=d2k_raw_episode_read(t->episode,wait,t->has_cancel?&t->cancel:NULL,
        t->reply+t->end,sizeof t->reply-t->end,&received,1,&t->observed);
    if(record_io(t,D2K_RAW_TLS_READ,started,rc,wait,t->reply+t->end,received,NULL)) {
        snprintf(err,cap,"raw TLS prefix evidence was not recorded");return -1;
    }
    t->end+=received;*bytes=t->reply;*length=t->end;
    if(t->observed.kind==D2K_RAW_OBS_RESPONSE_FIN)t->eof=1;
    else if(rc || !received) {
        t->sealed=1;snprintf(err,cap,"raw TLS prefix read failed");return -1;
    }
    return 0;
}
d2k_raw_tls *d2k_raw_tls_open_observed(const d2k_experiment *e,const char *plan,
    const d2k_raw_tls_sink *sink,char *err,size_t cap) {
    if(!e || !plan || !*plan || strlen(plan)>=4096 ||
       (sink && (!sink->experience || !sink->record))) {
        snprintf(err,cap,"invalid raw TLS configuration");return NULL;
    }
    d2k_raw_tls *t=calloc(1,sizeof *t);
    if(!t){snprintf(err,cap,"raw TLS allocation failed");return NULL;}
    t->scoped=d2k_plan_text_stream_offset(plan,&t->scope_offset,err,cap);
    if(t->scoped<0){free(t);return NULL;}
    uint32_t cut;
    if(d2k_plan_text_after_split(plan,&t->after_offset,&t->after_length,&cut,err,cap)<0){free(t);return NULL;}
    memcpy(t->plan,plan,strlen(plan)+1);t->first=1;
    if(sink)t->sink=*sink;
    if(e->cancel){t->cancel=*e->cancel;t->has_cancel=1;}
    int64_t started=d2k_now_ms();
    t->episode=d2k_raw_episode_open(e->ip,e->family,e->port,e->connect_ms,e->mark,
        e->offer_ts,t->has_cancel?&t->cancel:NULL,err,cap,&t->observed);
    if(t->episode && !d2k_raw_episode_tuple(t->episode,&t->tuple)) {
        d2k_raw_episode_free(t->episode);t->episode=NULL;t->observed.kind=D2K_RAW_OBS_LOCAL;
        snprintf(err,cap,"raw TLS connection identity unavailable");
    }
    if(record_io(t,D2K_RAW_TLS_OPEN,started,t->episode?0:-1,e->connect_ms,NULL,0,NULL)) {
        d2k_raw_episode_free(t->episode);free(t);
        snprintf(err,cap,"raw TLS open evidence was not recorded");return NULL;
    }
    if(!t->episode){free(t);return NULL;}
    return t;
}
d2k_raw_tls *d2k_raw_tls_open(const d2k_experiment *e,const char *plan,char *err,size_t cap) {
    return d2k_raw_tls_open_observed(e,plan,NULL,err,cap);
}
d2k_tls_io d2k_raw_tls_io(d2k_raw_tls *t) {
    return t?(d2k_tls_io){t,receive,submit}:(d2k_tls_io){0};
}
void d2k_raw_tls_observation(const d2k_raw_tls *t,d2k_raw_observation *out) {
    if(out)*out=t?t->observed:(d2k_raw_observation){0};
}
void d2k_raw_tls_close(d2k_raw_tls *t) {
    if(t){
        int64_t started=d2k_now_ms();d2k_raw_episode_free(t->episode);
        (void)record_io(t,D2K_RAW_TLS_CLOSE,started,0,0,NULL,0,NULL);free(t);
    }
}
