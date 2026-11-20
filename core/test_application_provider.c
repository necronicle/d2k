#define _DARWIN_C_SOURCE
#define d2k_sched_application_request provider_request
#define d2k_application_search_new provider_new
#define d2k_application_search_next provider_next
#define d2k_application_search_free provider_free
#define d2k_application_search_matches provider_matches
#define d2k_application_search_feedback provider_feedback
#define d2k_application_search_history provider_history
#define d2k_sched_synthesis_take provider_take
#define d2k_sched_synthesis_retain provider_retain
#define d2k_tls_path_session_new provider_raw_new
#define d2k_tls_path_session_new_response provider_response_new
#define d2k_tls_path_session_next provider_session_next
#define d2k_tls_path_session_free provider_session_free
#define d2k_tls_path_session_add_prefix provider_prefix
#define main controller_main
#include "d2kc.c"
#undef main
#include <assert.h>
#include <dirent.h>
static int eligible,created,released,raw_created,response_created;
static int response_live,prefix_calls,session_marker;
static int candidate_mode,match=1,feedback_calls,next_calls;
static void *retained;
static void (*retained_release)(void *);
static d2k_synthesis_continuation_feedback retained_feedback;
static uint64_t retained_generation;
static uint64_t expected_generation=7;
static size_t expected_wire=1200;
void *provider_take(void (*release)(void *),uint64_t *generation) {
    if(!retained || release!=retained_release)return NULL;
    void *out=retained;retained=NULL;*generation=retained_generation;return out;
}
int provider_retain(uint64_t generation,void *ctx,void (*release)(void *),
    d2k_synthesis_continuation_feedback feedback) {
    assert(!retained && ctx && release && feedback);
    retained=ctx;retained_release=release;retained_feedback=feedback;retained_generation=generation;return 1;
}
static d2k_application_request request;
struct d2k_application_search {int unused;};
static struct d2k_application_search fixed;
int provider_history(d2k_application_search *s,FILE *f) {
    assert(s==&fixed && f);return 0;
}
int provider_matches(const d2k_application_search *s,const d2k_application_request *r,
    const d2k_experiment *e,uint64_t generation,int timeout,size_t wire) {
    assert(s==&fixed && r->search_id==42 && e->mark==0x2f && generation==retained_generation && timeout==5000 && wire==expected_wire);
    return match;
}
int provider_feedback(d2k_application_search *s,const d2k_synthesis_feedback *e,d2k_verification_status outcome) {
    assert(s==&fixed && e && outcome==D2K_VF_NOT_MET);feedback_calls++;return 1;
}
int provider_request(d2k_application_request *out){*out=request;return eligible;}
d2k_application_search *provider_new(const d2k_application_request *r,
    const d2k_experiment *e,uint64_t generation,int timeout,size_t wire,FILE *archive) {
    assert(r->search_id==42 && r->doh && e->mark==0x2f && generation==expected_generation);
    assert(timeout==5000 && wire==expected_wire && archive);created++;
    assert(fputs("fixture\n",archive)>0);return &fixed;
}
d2k_syn_status provider_next(d2k_application_search *search,d2k_vres *out) {
    assert(search==&fixed);memset(out,0,sizeof *out);out->protocol_response=1;
    out->owns_search=1;out->verdict=D2K_V_INCONCLUSIVE;next_calls++;
    out->probes=next_calls==3?6:8;
    return candidate_mode?D2K_SYN_CANDIDATE:D2K_SYN_DIRECT_RESPONSE;
}
void provider_free(d2k_application_search *s){if(s){assert(s==&fixed);released++;}}
d2k_tls_path_session *provider_raw_new(const d2k_tls_stream *s,const d2k_experiment *e,uint64_t g) {
    (void)s;(void)e;(void)g;raw_created++;return NULL;
}
d2k_tls_path_session *provider_response_new(const d2k_tls_stream *s,const d2k_experiment *e,uint64_t g) {
    assert(s->chunks==1 && s->chunk_bytes[0]==s->trigger->len);
    assert(e->tls_input==s->trigger->payload && e->tls_input_length==s->trigger->len);
    (void)g;response_created++;return response_live?(d2k_tls_path_session *)&session_marker:NULL;
}
d2k_syn_status provider_session_next(d2k_tls_path_session *s,d2k_vres *out) {
    memset(out,0,sizeof *out);if(!s)return D2K_SYN_ERROR;
    assert(s==(d2k_tls_path_session *)&session_marker);out->probes=prefix_calls?2:1;
    return prefix_calls?D2K_SYN_CANDIDATE:D2K_SYN_CLOSED;
}
void provider_session_free(d2k_tls_path_session *s){assert(!s || s==(d2k_tls_path_session *)&session_marker);}
int provider_prefix(d2k_tls_path_session *s,const uint8_t *bytes,size_t n,size_t segment,unsigned mods) {
    assert(s==(d2k_tls_path_session *)&session_marker && n && segment && segment<=n && !mods);
    size_t off,len;assert(!d2k_hello_sni(bytes,n,&off,&len));
    assert(len==strlen("healthy.example") && !memcmp(bytes+off,"healthy.example",len));
    prefix_calls++;return 1;
}
int main(void) {
    char directory[]="/tmp/d2k-app-provider-XXXXXX";assert(mkdtemp(directory));
    char catalog[512];snprintf(catalog,sizeof catalog,"%s/catalog.json",directory);
    synthesis_catalog_path=catalog;
    request=(d2k_application_request){.search_id=42,.doh=1,.transport=6,.shape=D2K_SHAPE_MODERN};
    strcpy(request.resource,"/dns-query");
    d2k_trigger *trigger=calloc(1,sizeof *trigger);assert(trigger);trigger->len=1200;
    size_t whole=1200;d2k_tls_stream stream={trigger,&whole,1,5000,1};
    d2k_experiment network={.mark=0x2f};d2k_vres *result=calloc(1,sizeof *result);assert(result);
    assert(application_search_provider(&request,&stream,&network,7,result)==D2K_SYN_DIRECT_RESPONSE);
    eligible=1;
    assert(synthesis_session_provider(&stream,&network,7,result)==D2K_SYN_DIRECT_RESPONSE);
    assert(created==2 && released==2 && !raw_created);
    candidate_mode=1;
    assert(application_search_provider(&request,&stream,&network,7,result)==D2K_SYN_CANDIDATE);
    assert(created==3 && released==2 && retained && next_calls==3 && result->probes==6);
    d2k_synthesis_feedback feedback={0};
    assert(retained_feedback(retained,&feedback,D2K_VF_NOT_MET)==1 && feedback_calls==1);
    assert(application_search_provider(&request,&stream,&network,8,result)==D2K_SYN_CANDIDATE);
    assert(created==3 && released==2 && retained && next_calls==4 && retained_generation==7 && result->probes==2);
    match=0;
    expected_generation=9;expected_wire=1591;trigger->len=whole=1591;
    assert(application_search_provider(&request,&stream,&network,9,result)==D2K_SYN_CANDIDATE);
    assert(retained && created==4 && released==3 && next_calls==5);
    assert(retained_generation==9 && result->probes==8);
    uint64_t cleaned_generation=0;
    application_search_release(provider_take(application_search_release,&cleaned_generation));
    assert(cleaned_generation==9 && !retained && released==4);
    candidate_mode=0;
    request.ech=1;
    assert(synthesis_session_provider(&stream,&network,7,result)==D2K_SYN_ERROR && raw_created==1);
    request.ech=0;request.by_addr=1;
    assert(synthesis_session_provider(&stream,&network,7,result)==D2K_SYN_ERROR && raw_created==2);
    request.by_addr=0;synthesis_catalog_path="/nonexistent-d2k-parent/catalog.json";
    assert(synthesis_session_provider(&stream,&network,7,result)==D2K_SYN_ERROR && created==4 && raw_created==2);
    request.resource[0]=0;
    assert(synthesis_session_provider(&stream,&network,7,result)==D2K_SYN_ERROR && created==4 && raw_created==2 && response_created==1);
    response_live=1;request.family=network.family=4;network.offer_ts=1;
    strcpy(request.target,"blocked.example");
    d2k_application_control control={.family=4,.transport=6,.incarnation=7,.bytes=100,
        .low_port=443,.high_port=50000,.epoch={1}};
    strcpy(control.name,"healthy.example");
    for(int mode=0;mode<5;mode++) {
        request.control=control;prefix_calls=0;
        if(mode==1)memset(request.control.epoch,0,sizeof request.control.epoch);
        if(mode==2)request.control.family=6;
        if(mode==3)strcpy(request.control.name,request.target);
        if(mode==4)request.control.name[0]='\n';
        assert(synthesis_session_provider(&stream,&network,7,result)==(mode?D2K_SYN_CLOSED:D2K_SYN_CANDIDATE));
        assert(prefix_calls==!mode);
        if(retained)synthesis_session_release(provider_take(synthesis_session_release,&cleaned_generation));
    }
    DIR *dir=opendir(directory);assert(dir);struct dirent *entry;
    while((entry=readdir(dir)))if(entry->d_name[0]!='.') {
        char path[1024];snprintf(path,sizeof path,"%s/%s",directory,entry->d_name);assert(!unlink(path));
    }
    closedir(dir);assert(!rmdir(directory));free(trigger);free(result);return 0;
}
