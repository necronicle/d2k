#include "application_late.h"
#include "../core/include/d2k_plantlv.h"
#include "../core/include/d2k_hello.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static int direct_identity(const char *s) {
    static const char *prefixes[]={"d2k-plan 1 5\nid ","d2k-plan 1 8\nid "};
    static const char *bodies[]={"\nproto tcp tls\nwire detect-tcp-v1\norder forward\n",
        "\nproto tcp tls\nwire tcp-template-v1\norder forward\n"};
    if(!s)return 0;
    for(size_t kind=0;kind<2;kind++) {
        size_t n=strlen(prefixes[kind]);
        if(strlen(s)!=n+32+strlen(bodies[kind]) || memcmp(s,prefixes[kind],n) || strcmp(s+n+32,bodies[kind]))continue;
        for(size_t i=0;i<32;i++)if(!((s[n+i]>='0' && s[n+i]<='9') || (s[n+i]>='a' && s[n+i]<='f')))return 0;
        return 1;
    }
    return 0;
}
static int http_interval(const d2k_application_model *m,uint32_t *offset,uint32_t *bytes,uint32_t *boundary) {
    d2k_application_http_interval measured;
    if(!d2k_application_model_http_interval(m,&measured) ||
       measured.length<2 || measured.length>UINT16_MAX)return 0;
    *offset=measured.offset;*bytes=measured.length;
    *boundary=measured.ack==2?measured.acked_bytes:measured.length/2;
    return 1;
}
static int interval(const d2k_application_model *m,int direct,uint32_t *offset,uint32_t *bytes,uint32_t *boundary) {
    const d2k_application_end *e=d2k_application_model_end(m);
    size_t count=0;const d2k_application_observation *h=d2k_application_model_history(m,&count);
    if(!e || !e->identity || !e->network_evidence ||
       e->identity->by_addr || e->identity->transport!=6 || (direct && !direct_identity(e->identity->program)) ||
       e->result.local_refusal || e->result.local_limit || e->result.unsupported ||
       e->result.body_complete)return 0;
    if(!e->identity->doh)return http_interval(m,offset,bytes,boundary);
    if(!h || count<2 || count>UINT32_MAX ||
       h[count-1].query.dns_valid || !h[count-2].query.dns_valid ||
       e->result.budget_requests!=count || e->result.doh_replies!=count-1)return 0;
    const d2k_raw_transport *before=&h[count-2].transport,*after=&h[count-1].transport;
    if(!before->available || !after->available || before->sent_end<e->input_length ||
       after->sent_end<=before->sent_end || after->sent_end>=UINT32_C(0x80000000))return 0;
    uint32_t length=after->sent_end-before->sent_end;
    if(length<2 || length>UINT16_MAX)return 0;
    uint32_t cut=length/2;
    if(d2k_application_query_ack(h,count)==2)
        cut=after->acked_end-before->sent_end;
    *offset=before->sent_end;*bytes=length;*boundary=cut;return 1;
}
static int render(uint32_t offset,uint32_t length,uint32_t cut,int native,char **plan) {
    char text[512],err[160];uint8_t *tlv=malloc(D2K_PLAN_TLV_MAX);if(!tlv)return -1;
    int size=snprintf(text,sizeof text,"d2k-plan 1 16\nid 00000000000000000000000000000000\nproto tcp tls\nwire %s\nstream-offset %u\ninput %u 0 0\nsplit payload_start +%u\norder forward\n",native?"tcp-template-v1":"detect-tcp-v1",offset,length,cut);
    size_t written=0;
    int valid=size>0 && (size_t)size<sizeof text && !d2k_plan_text_to_tlv(text,tlv,D2K_PLAN_TLV_MAX,&written,err,sizeof err);
    free(tlv);if(!valid)return -1;
    *plan=malloc((size_t)size+1);if(!*plan)return -1;memcpy(*plan,text,(size_t)size+1);return 1;
}
int d2k_application_late_question(const d2k_application_model *m,char **plan) {
    if(!plan)return -1;
    *plan=NULL;
    uint32_t offset,length,cut;
    if(!interval(m,1,&offset,&length,&cut))return 0;
    const d2k_application_end *end=d2k_application_model_end(m);
    return render(offset,length,cut,strstr(end->identity->program,"\nwire tcp-template-v1\n")!=NULL,plan);
}
static int compose(const d2k_application_end *end,uint32_t offset,uint32_t length,
    uint32_t cut,char **plan,char *err,size_t cap) {
    size_t snioff=0,snilen=0;
    if(d2k_hello_sni(end->input,end->input_length,&snioff,&snilen))snioff=snilen=0;
    return d2k_plan_text_compose_after_split(end->identity->program,(uint32_t)end->input_length,
        (uint32_t)snioff,(uint32_t)snilen,offset,length,cut,plan,err,cap);
}
int d2k_application_late_composed_question(const d2k_application_model *m,char **plan) {
    if(!plan)return -1;
    *plan=NULL;
    uint32_t offset,length,cut;
    if(!interval(m,0,&offset,&length,&cut))return 0;
    const d2k_application_end *end=d2k_application_model_end(m);
    if(!end || !end->identity || !end->input_length || end->input_length>UINT32_MAX)return 0;
    uint32_t unused,old_length,old_cut;char err[160];
    if(d2k_plan_text_stream_offset(end->identity->program,&unused,err,sizeof err)!=0 ||
       d2k_plan_text_after_split(end->identity->program,&unused,&old_length,&old_cut,err,sizeof err)!=0)return 0;
    return compose(end,offset,length,cut,plan,err,sizeof err)?-1:1;
}
static int refine(const d2k_application_model *baseline,
    const d2k_application_model *trial,unsigned char *seen,size_t seen_size,char **plan,int composed) {
    if(!plan)return -1;
    *plan=NULL;
    if(!seen || seen_size<D2K_LATE_SEEN_BYTES)return -1;
    uint32_t offset,length,cut,other_offset,other_length,unused;
    if(!interval(baseline,!composed,&offset,&length,&unused) ||
       !interval(trial,0,&other_offset,&other_length,&cut) ||
       offset!=other_offset || length!=other_length)return 0;
    d2k_application_question comparison=d2k_application_model_question(baseline,trial);
    if(comparison.status!=D2K_APP_CHANGED && comparison.status!=D2K_APP_REPRODUCED)return 0;
    const d2k_application_end *end=d2k_application_model_end(trial);
    if(end->identity->doh) {
        size_t n=0;const d2k_application_observation *history=d2k_application_model_history(trial,&n);
        size_t base_n=0;d2k_application_model_history(baseline,&base_n);
        if(n!=base_n || d2k_application_query_ack(history,n)!=2)return 0;
    } else {
        d2k_application_http_interval last,prior;
        if(!d2k_application_model_http_interval(trial,&last) ||
           !d2k_application_model_http_interval(baseline,&prior) ||
           last.ordinal!=prior.ordinal || last.ack!=2)return 0;
    }
    const char *program=end->identity->program;
    unsigned old_cut;
    if(composed) {
        uint32_t declared_offset,declared_length,declared_cut;char err[160];
        if(d2k_plan_text_after_split(program,&declared_offset,&declared_length,&declared_cut,err,sizeof err)!=1 ||
           declared_offset!=offset || declared_length!=length)return 0;
        old_cut=declared_cut;
    } else {
    const char *at=program?strstr(program,"\nsplit payload_start +"):NULL;
    if(!at)return 0;
    const char *number=at+strlen("\nsplit payload_start +");
    if(*number<'0' || *number>'9')return 0;
    char *tail=NULL;errno=0;
    unsigned long parsed=strtoul(number,&tail,10);
    if(errno || !tail || strcmp(tail,"\norder forward\n") || !parsed || parsed>=length)return 0;
    old_cut=(unsigned)parsed;
    }
    char *expected=NULL;
    const d2k_application_end *base=d2k_application_model_end(baseline);
    char err[160];
    if(composed) {
        if(compose(base,offset,length,old_cut,&expected,err,sizeof err))return -1;
    } else if(render(offset,length,old_cut,strstr(base->identity->program,"\nwire tcp-template-v1\n")!=NULL,&expected)<0)return -1;
    const char *id=strstr(program,"\nid ");
    char *expected_id=strstr(expected,"\nid ");
    int valid=id && expected_id && strlen(id+4)>=32 && strlen(program)==strlen(expected);
    for(size_t i=0;valid && i<32;i++) {
        char c=id[4+i];
        if(!((c>='0' && c<='9') || (c>='a' && c<='f')))valid=0;
    }
    if(valid){memcpy(expected_id+4,id+4,32);valid=!strcmp(expected,program);}
    free(expected);if(!valid)return 0;
    seen[old_cut/8]|=(unsigned char)(1u<<(old_cut%8));
    if(seen[cut/8]&(1u<<(cut%8)))return 0;
    int rc=composed?(compose(base,offset,length,cut,plan,err,sizeof err)?-1:1):render(offset,length,cut,strstr(base->identity->program,"\nwire tcp-template-v1\n")!=NULL,plan);
    if(rc==1)seen[cut/8]|=(unsigned char)(1u<<(cut%8));
    return rc;
}
int d2k_application_late_refine(const d2k_application_model *baseline,
    const d2k_application_model *trial,unsigned char *seen,size_t seen_size,char **plan) {
    return refine(baseline,trial,seen,seen_size,plan,0);
}
int d2k_application_late_composed_refine(const d2k_application_model *baseline,
    const d2k_application_model *trial,unsigned char *seen,size_t seen_size,char **plan) {
    return refine(baseline,trial,seen,seen_size,plan,1);
}
