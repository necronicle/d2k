#include "lower.h"
#include "../core/include/d2k_plantlv.h"
#include "../datapath/include/d2k_plan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
static int hex_value(unsigned char c) {
    return c>='0' && c<='9'?c-'0':c>='a' && c<='f'?c-'a'+10:-1;
}
d2k_lower_status d2k_lower_tls_prefix_read(const char *s,uint8_t **b,size_t *n,size_t *seg,unsigned *mods,char *err,size_t cap) {
    if(b)*b=NULL;
    if(n)*n=0;
    if(seg)*seg=0;
    if(mods)*mods=0;
    if(!s || !b || !n || !seg || !mods || !err || !cap)return D2K_LOWER_ERROR;
    uint8_t *tlv=malloc(D2K_PLAN_TLV_MAX);size_t tl=0;
    if(!tlv)return D2K_LOWER_ERROR;
    int valid=d2k_plan_text_to_tlv(s,tlv,D2K_PLAN_TLV_MAX,&tl,err,cap);free(tlv);
    if(valid)return D2K_LOWER_INVALID;
    const char *size=strstr(s,"\nsegment "),*payload=strstr(s,"\npayload 1 "),*id=strstr(s,"\nid ");
    uint8_t *bytes=NULL;char *canonical=NULL;d2k_lower_status status=D2K_LOWER_UNSUPPORTED;
    if(!size || !payload || !id || size[9]<'0' || size[9]>'9')goto done;
    char *end;unsigned long segment=strtoul(size+9,&end,10);
    if(*end!='\n' || !segment || segment>UINT16_MAX)goto done;
    payload+=11;const char *nl=strchr(payload,'\n');
    if(!nl || nl==payload || (size_t)(nl-payload)%2 || (size_t)(nl-payload)/2>UINT16_MAX)goto done;
    size_t length=(size_t)(nl-payload)/2;bytes=malloc(length);
    if(!bytes){status=D2K_LOWER_ERROR;goto done;}
    for(size_t i=0;i<length;i++) {
        int hi=hex_value((unsigned char)payload[2*i]),lo=hex_value((unsigned char)payload[2*i+1]);
        if(hi<0 || lo<0)goto done;
        bytes[i]=(uint8_t)(hi*16+lo);
    }
    unsigned flags=strstr(s," tlsmod=rnd,dupsid\n")?3:strstr(s," tlsmod=dupsid\n")?2:strstr(s," tlsmod=rnd\n")?1:0;
    status=d2k_lower_tls_prefix(bytes,length,(size_t)segment,flags,&canonical,err,cap);
    if(status!=D2K_LOWER_OK)goto done;
    status=D2K_LOWER_UNSUPPORTED;
    size_t offset=(size_t)(id+4-s),total=strlen(s);
    const char *canonical_id=strstr(canonical,"\nid ");
    if(!canonical_id || (size_t)(canonical_id+4-canonical)!=offset || total!=strlen(canonical) ||
       offset>total || total-offset<33 || memcmp(s,canonical,offset) ||
       strcmp(s+offset+32,canonical+offset+32))goto done;
    *b=bytes;bytes=NULL;*n=length;*seg=(size_t)segment;*mods=flags;status=D2K_LOWER_OK;
done:
    free(bytes);free(canonical);
    if(status==D2K_LOWER_UNSUPPORTED)snprintf(err,cap,"plan is not the exact single-prefix compiler form");
    return status;
}
static int compare_piece(const void *a,const void *b) {
    const d2k_payload_piece *x=a,*y=b;
    return (x->offset>y->offset)-(x->offset<y->offset);
}
d2k_lower_status d2k_lower_tls_prefix_partition_read(const char *s,size_t total,
    uint8_t **bytes,size_t *length,size_t *segment,unsigned *mods,
    d2k_payload_piece **pieces,size_t *count,char *err,size_t cap) {
    if(bytes)*bytes=NULL;
    if(length)*length=0;
    if(segment)*segment=0;
    if(mods)*mods=0;
    if(pieces)*pieces=NULL;
    if(count)*count=0;
    if(!s || !bytes || !length || !segment || !mods || !pieces || !count || !err || !cap)
        return D2K_LOWER_ERROR;
    err[0]=0;
    if(!total)return D2K_LOWER_INVALID;
    const char *fake=strstr(s,"\nfake payload=1 "),*tail=fake?strchr(fake+1,'\n'):NULL;
    if(!tail){snprintf(err,cap,"missing canonical prefix");return D2K_LOWER_UNSUPPORTED;}
    tail++;
    const char *header_end = strchr(s, '\n');
    if (!header_end || header_end >= fake) {
        snprintf(err,cap,"missing plan header");return D2K_LOWER_UNSUPPORTED;
    }
    size_t head=(size_t)(tail-s),slots=strlen(tail)/22+1,n=0,covered=0;
    if(head>SIZE_MAX-32 || tail-header_end>INT_MAX ||
       slots>SIZE_MAX/sizeof(d2k_payload_piece))return D2K_LOWER_ERROR;
    char *base=malloc(head+32),*canonical=NULL;
    d2k_payload_piece *p=calloc(slots,sizeof *p);
    uint8_t *b=NULL;size_t len=0,seg=0;unsigned flags=0;
    d2k_lower_status status=D2K_LOWER_ERROR;
    if(!base || !p)goto done;
    snprintf(base,head+32,"d2k-plan 1 8%.*sorder forward\n",
             (int)(tail-header_end),header_end);
    status=d2k_lower_tls_prefix_read(base,&b,&len,&seg,&flags,err,cap);
    if(status!=D2K_LOWER_OK)goto done;
    status=D2K_LOWER_UNSUPPORTED;
    if (!strncmp(tail,"input ",6)) {
        char exact[48];
        int len = snprintf(exact,sizeof exact,"input %zu 0 0\n",total);
        if (len < 0 || (size_t)len >= sizeof exact || strncmp(tail,exact,(size_t)len)) goto done;
        tail += len;
    }
    while(!strncmp(tail,"split payload_start +",21)) {
        const char *value=tail+21;char *end;
        if(*value<'0' || *value>'9')goto done;
        unsigned long cut=strtoul(value,&end,10);
        if(*end!='\n' || cut>INT16_MAX || cut<=covered || cut>=total || n>=slots-1)goto done;
        p[n++]=(d2k_payload_piece){covered,(size_t)cut-covered,0};covered=(size_t)cut;tail=end+1;
    }
    p[n++]=(d2k_payload_piece){covered,total-covered,0};
    if (!strncmp(tail,"order emissions=0,",18)) {
        if (n >= D2K_WIRE_BATCH_MAX) goto done;
        d2k_payload_piece ordered[D2K_WIRE_BATCH_MAX];
        uint8_t order[D2K_WIRE_BATCH_MAX] = {0};
        tail += 18;
        for (size_t i = 0; i < n; i++) {
            char *end;
            if (*tail < '1' || *tail > '9') goto done;
            unsigned long index = strtoul(tail,&end,10);
            if (index > n || *end != (i+1 == n ? '\n' : ',')) goto done;
            order[i+1] = (uint8_t)index;
            ordered[i] = p[index-1];
            tail = end+1;
        }
        if (!d2k_emission_order_valid(order,n+1)) goto done;
        memcpy(p,ordered,n*sizeof *p);
    } else {
        int reverse=!strncmp(tail,"order reverse\n",14);
        if(!reverse && strncmp(tail,"order forward\n",14))goto done;
        tail+=14;
        if(reverse)for(size_t i=0;i<n/2;i++){
            d2k_payload_piece swap=p[i];p[i]=p[n-1-i];p[n-1-i]=swap;
        }
    }
    uint32_t pace=0;
    if(!strncmp(tail,"pace ",5)) {
        const char *value=tail+5;char *end;
        if(*value<'0' || *value>'9')goto done;
        unsigned long parsed=strtoul(value,&end,10);
        if(*end!='\n' || parsed>UINT32_MAX)goto done;
        pace=(uint32_t)parsed;tail=end+1;
    }
    if(*tail)goto done;
    for(size_t i=1;i<n;i++)p[i].delay_us=pace;
    status=d2k_lower_tls_prefix_partition(b,len,seg,flags,total,p,n,&canonical,err,cap);
    if(status!=D2K_LOWER_OK)goto done;
    status=D2K_LOWER_UNSUPPORTED;
    const char *id=strstr(s,"\nid ");char *copy_id=strstr(canonical,"\nid ");
    if(!id || !copy_id)goto done;
    memcpy(copy_id+4,id+4,32);
    if(strcmp(s,canonical))goto done;
    *bytes=b;b=NULL;*length=len;*segment=seg;*mods=flags;
    *pieces=p;p=NULL;*count=n;status=D2K_LOWER_OK;
done:
    free(base);free(canonical);free(p);free(b);
    if(status==D2K_LOWER_UNSUPPORTED)snprintf(err,cap,"plan is not the exact prefix-partition compiler form");
    return status;
}
static int append(char *s,size_t cap,size_t *n,const char *fmt,...) {
    va_list ap;va_start(ap,fmt);int rc=vsnprintf(s+*n,cap-*n,fmt,ap);va_end(ap);
    if(rc<0 || (size_t)rc>=cap-*n)return -1;
    *n+=(size_t)rc;return 0;
}
struct partition_prefix {
    const char *text;
    size_t text_length, segment_size, minimum_emits;
};

static d2k_lower_status lower_partition(size_t total,const d2k_payload_piece *p,size_t count,
    const char *proto,const struct partition_prefix *prefix,size_t sni_off,size_t sni_len,
    char **out,char *err,size_t errcap) {
    if(out)*out=NULL;
    if(err && errcap)err[0]=0;
    if(!out || !err || !errcap)return D2K_LOWER_ERROR;
    if(!p || !count || !total || count>total || !proto ||
       ((sni_off || sni_len) && (!sni_len || sni_off>total || sni_len>total-sni_off)) ||
       (strcmp(proto,"tls") && strcmp(proto,"http") && strcmp(proto,"unknown"))) {
        snprintf(err,errcap,"invalid payload partition or protocol");return D2K_LOWER_INVALID;
    }
    size_t prefix_len = prefix ? prefix->text_length : 0;
    if(count>SIZE_MAX/sizeof *p || prefix_len>SIZE_MAX-256 ||
       count>(SIZE_MAX-256-prefix_len)/64 || prefix_len>INT_MAX) {
        snprintf(err,errcap,"partition allocation overflow");return D2K_LOWER_ERROR;
    }
    d2k_payload_piece *sorted=malloc(count*sizeof *sorted);
    if(!sorted){snprintf(err,errcap,"partition allocation failed");return D2K_LOWER_ERROR;}
    memcpy(sorted,p,count*sizeof *sorted);qsort(sorted,count,sizeof *sorted,compare_piece);
    d2k_lower_status status=D2K_LOWER_INVALID;
    char *text=NULL;uint8_t *tlv=NULL;size_t covered=0;
    for(size_t i=0;i<count;i++) {
        if(sorted[i].offset!=covered || !sorted[i].length || sorted[i].length>total-covered) {
            snprintf(err,errcap,"payload partition has a gap, overlap or out-of-range piece");goto done;
        }
        covered+=sorted[i].length;
    }
    if(covered!=total){snprintf(err,errcap,"payload partition omits the tail");goto done;}
    status=D2K_LOWER_UNSUPPORTED;
    int forward=1,reverse=1;
    for(size_t i=0;i<count;i++) {
        forward &= p[i].offset==sorted[i].offset;
        reverse &= p[i].offset==sorted[count-1-i].offset;
    }
    int explicit_order = !forward && !reverse;
    size_t leading = prefix ? 1 : 0;
    if (explicit_order) {
        size_t emits = prefix ? prefix->minimum_emits : 0;
        for (size_t i = 0; i < count; i++) {
            size_t pieces = prefix ? (p[i].length-1)/prefix->segment_size+1 : 1;
            if (emits > D2K_WIRE_BATCH_MAX || pieces > D2K_WIRE_BATCH_MAX-emits) {
                snprintf(err,errcap,"Plan emission list exceeds the executor capacity");goto done;
            }
            emits += pieces;
        }
    }
    uint32_t pace=count>1?p[1].delay_us:0;
    if(p[0].delay_us){snprintf(err,errcap,"Plan partition has no initial-delay encoding");goto done;}
    for(size_t i=1;i<count;i++)if(p[i].delay_us!=pace) {
        snprintf(err,errcap,"Plan partition cannot encode unequal piece delays");goto done;
    }
    size_t cap=count*64+256+prefix_len,n=0;
    text=malloc(cap);tlv=malloc(D2K_PLAN_TLV_MAX);
    status=D2K_LOWER_ERROR;
    if(!text || !tlv){snprintf(err,errcap,"plan allocation failed");goto done;}
    unsigned version = explicit_order ? D2K_EXEC_EMISSION_ORDER : 8;
    if (prefix) {
        const char *body = strchr(prefix->text,'\n');
        if (!body || append(text,cap,&n,"d2k-plan 1 %u%.*s",version,
                            (int)(prefix_len-(size_t)(body-prefix->text)),body)) goto format;
    } else if (append(text,cap,&n,
               "d2k-plan 1 %u\nid 00000000000000000000000000000000\nproto tcp %s\nwire tcp-template-v1\n",
               version,proto)) goto format;
    if ((explicit_order || sni_len) &&
        append(text,cap,&n,"input %zu %zu %zu\n",total,sni_off,sni_len)) goto format;
    for(size_t i=1;i<count;i++) {
        if(sorted[i].offset>INT16_MAX) {
            status=D2K_LOWER_UNSUPPORTED;snprintf(err,errcap,"partition boundary exceeds Plan anchor offset");goto done;
        }
        if(append(text,cap,&n,"split payload_start +%zu\n",sorted[i].offset))goto format;
    }
    if (explicit_order) {
        if (append(text,cap,&n,"order emissions=%s",leading?"0,":"")) goto format;
        for (size_t i = 0; i < count; i++) {
            size_t index = 0;
            while (sorted[index].offset != p[i].offset) index++;
            if (append(text,cap,&n,"%zu%s",index+leading,i+1==count?"\n":",")) goto format;
        }
    } else if (append(text,cap,&n,"order %s\n",forward?"forward":"reverse")) goto format;
    if(pace && append(text,cap,&n,"pace %u\n",(unsigned)pace))goto format;
    size_t tlv_len=0;
    if(d2k_plan_text_to_tlv(text,tlv,D2K_PLAN_TLV_MAX,&tlv_len,err,errcap)) {
        status=D2K_LOWER_UNSUPPORTED;goto done;
    }
    *out=text;text=NULL;status=D2K_LOWER_OK;goto done;
format:
    snprintf(err,errcap,"plan text formatting failed");
done:
    free(sorted);free(text);free(tlv);return status;
}

d2k_lower_status d2k_lower_partition(size_t total,const d2k_payload_piece *p,size_t count,
    const char *proto,char **out,char *err,size_t errcap) {
    return lower_partition(total,p,count,proto,NULL,0,0,out,err,errcap);
}
d2k_lower_status d2k_lower_partition_observed(size_t total,const d2k_payload_piece *p,size_t count,
    const char *proto,size_t sni_off,size_t sni_len,char **out,char *err,size_t errcap) {
    return lower_partition(total,p,count,proto,NULL,sni_off,sni_len,out,err,errcap);
}

d2k_lower_status d2k_lower_tls_prefix(const uint8_t *prefix,size_t length,
    size_t segment,unsigned mods,char **out,char *err,size_t errcap) {
    if(out)*out=NULL;
    if(err && errcap)err[0]=0;
    if(!out || !err || !errcap)return D2K_LOWER_ERROR;
    if(!prefix || !length || length>UINT16_MAX || !segment || segment>UINT16_MAX || mods>3) {
        snprintf(err,errcap,"invalid TLS prefix, segment size or modifiers");return D2K_LOWER_INVALID;
    }
    size_t cap=length*2+512,n=0,tlv_length=0;
    char *text=malloc(cap);uint8_t *tlv=malloc(D2K_PLAN_TLV_MAX);
    d2k_lower_status status=D2K_LOWER_ERROR;
    if(!text || !tlv){snprintf(err,errcap,"prefix compilation allocation failed");goto done;}
    if(append(text,cap,&n,"d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\ninput tls-sni\nsegment %zu\npayload 1 ",segment))goto format;
    static const char hex[]="0123456789abcdef";
    for(size_t i=0;i<length;i++){text[n++]=hex[prefix[i]>>4];text[n++]=hex[prefix[i]&15];}
    text[n]=0;
    const char *modifier=mods==3?" tlsmod=rnd,dupsid":mods==2?" tlsmod=dupsid":mods==1?" tlsmod=rnd":"";
    if(append(text,cap,&n,"\npoison 1 tcpts\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before%s\norder forward\n",modifier))goto format;
    if(d2k_plan_text_to_tlv(text,tlv,D2K_PLAN_TLV_MAX,&tlv_length,err,errcap)) {
        status=D2K_LOWER_UNSUPPORTED;goto done;
    }
    *out=text;text=NULL;status=D2K_LOWER_OK;goto done;
format:
    snprintf(err,errcap,"prefix plan formatting failed");
done:
    free(text);free(tlv);return status;
}

d2k_lower_status d2k_lower_tls_prefix_partition(const uint8_t *bytes,size_t length,
    size_t segment,unsigned mods,size_t total,const d2k_payload_piece *pieces,
    size_t count,char **out,char *err,size_t errcap) {
    if(out)*out=NULL;
    if(!out || !err || !errcap)return D2K_LOWER_ERROR;
    char *prefix = NULL;
    d2k_lower_status status = d2k_lower_tls_prefix(bytes,length,segment,mods,&prefix,err,errcap);
    if (status != D2K_LOWER_OK) return status;
    const char *order = strstr(prefix,"order forward\n");
    if (order) {
        /* Modifiers of tcp-template-v1 preserve the prefix length. */
        size_t emits = (length-1)/segment+1;
        const struct partition_prefix head = {prefix, (size_t)(order-prefix), segment, emits};
        status = lower_partition(total,pieces,count,"tls",&head,0,0,out,err,errcap);
    } else {
        snprintf(err,errcap,"compiler composition form mismatch");
        status = D2K_LOWER_ERROR;
    }
    free(prefix);
    return status;
}
