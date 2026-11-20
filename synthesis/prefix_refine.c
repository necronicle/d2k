#include "prefix_refine.h"
#include "lower.h"
#include <stdlib.h>
#include <string.h>
struct d2k_prefix_refiner {
    uint8_t *hypothesis,*reference,*proposal;
    size_t *different,length,count,width,cursor,take;
    uint64_t ticket;
    int pending,closed;
    size_t segment;
    unsigned modifiers;
    char *program;
    d2k_payload_piece *pieces;
    size_t piece_count,input_length;
};
d2k_prefix_refiner *d2k_prefix_refiner_new_plans(const char *a,const char *b) {
    uint8_t *left=NULL,*right=NULL;size_t ln=0,rn=0,ls=0,rs=0;unsigned lm=0,rm=0;
    char err[200];d2k_prefix_refiner *r=NULL;
    if(d2k_lower_tls_prefix_read(a,&left,&ln,&ls,&lm,err,sizeof err)!=D2K_LOWER_OK ||
       d2k_lower_tls_prefix_read(b,&right,&rn,&rs,&rm,err,sizeof err)!=D2K_LOWER_OK ||
       ln!=rn || ls!=rs || lm!=rm)goto done;
    r=d2k_prefix_refiner_new(left,right,ln);
    if(r){r->segment=ls;r->modifiers=lm;}
done:
    free(left);free(right);return r;
}
d2k_prefix_refiner *d2k_prefix_refiner_new_partition_plans(const char *a,const char *b,size_t input) {
    uint8_t *left=NULL,*right=NULL;size_t ln=0,rn=0,ls=0,rs=0,lc=0,rc=0;unsigned lm=0,rm=0;
    d2k_payload_piece *lp=NULL,*rp=NULL;d2k_prefix_refiner *r=NULL;char err[200];
    if(!input || d2k_lower_tls_prefix_partition_read(a,input,&left,&ln,&ls,&lm,&lp,&lc,err,sizeof err)!=D2K_LOWER_OK ||
       d2k_lower_tls_prefix_partition_read(b,input,&right,&rn,&rs,&rm,&rp,&rc,err,sizeof err)!=D2K_LOWER_OK ||
       ln!=rn || ls!=rs || lm!=rm || lc!=rc)goto done;
    for(size_t i=0;i<lc;i++)if(lp[i].offset!=rp[i].offset || lp[i].length!=rp[i].length ||
        lp[i].delay_us!=rp[i].delay_us)goto done;
    r=d2k_prefix_refiner_new(left,right,ln);
    if(r){r->segment=ls;r->modifiers=lm;r->pieces=lp;lp=NULL;r->piece_count=lc;r->input_length=input;}
done:
    free(left);free(right);free(lp);free(rp);return r;
}
int d2k_prefix_refiner_next_plan(d2k_prefix_refiner *r,uint64_t *t,const char **p) {
    if(p)*p=NULL;
    if(!r || !r->segment || !t || !p)return -1;
    const uint8_t *bytes;size_t n;int rc=d2k_prefix_refiner_next(r,t,&bytes,&n);
    if(rc!=1)return rc;
    char err[200];
    if(!r->program) {
        d2k_lower_status lowered=r->pieces?
            d2k_lower_tls_prefix_partition(bytes,n,r->segment,r->modifiers,r->input_length,
                r->pieces,r->piece_count,&r->program,err,sizeof err):
            d2k_lower_tls_prefix(bytes,n,r->segment,r->modifiers,&r->program,err,sizeof err);
        if(lowered!=D2K_LOWER_OK)return -1;
    }
    *p=r->program;return 1;
}
static void rebuild(d2k_prefix_refiner *r) {
    r->count=0;
    for(size_t i=0;i<r->length;i++)
        if(r->hypothesis[i]!=r->reference[i])r->different[r->count++]=i;
    r->width=r->count/2+r->count%2;r->cursor=0;r->closed=!r->count;
}
d2k_prefix_refiner *d2k_prefix_refiner_new(const uint8_t *a,const uint8_t *b,size_t n) {
    if(!a || !b || !n || n>SIZE_MAX/sizeof(size_t))return NULL;
    d2k_prefix_refiner *r=calloc(1,sizeof *r);if(!r)return NULL;
    r->hypothesis=malloc(n);r->reference=malloc(n);r->proposal=malloc(n);
    r->different=malloc(n*sizeof *r->different);
    if(!r->hypothesis || !r->reference || !r->proposal || !r->different){d2k_prefix_refiner_free(r);return NULL;}
    r->length=n;memcpy(r->hypothesis,a,n);memcpy(r->reference,b,n);rebuild(r);return r;
}
void d2k_prefix_refiner_free(d2k_prefix_refiner *r) {
    if(!r)return;
    free(r->hypothesis);free(r->reference);free(r->proposal);free(r->different);free(r->program);free(r->pieces);free(r);
}
int d2k_prefix_refiner_next(d2k_prefix_refiner *r,uint64_t *t,const uint8_t **p,size_t *n) {
    if(!r || !t || !p || !n)return -1;
    *t=0;*p=NULL;*n=0;
    if(r->closed)return 0;
    if(!r->pending) {
        if(r->ticket==UINT64_MAX)return -1;
        memcpy(r->proposal,r->hypothesis,r->length);
        r->take=r->count-r->cursor;
        if(r->take>r->width)r->take=r->width;
        for(size_t i=0;i<r->take;i++) {
            size_t at=r->different[r->cursor+i];r->proposal[at]=r->reference[at];
        }
        r->ticket++;r->pending=1;
    }
    *t=r->ticket;*p=r->proposal;*n=r->length;return 1;
}
int d2k_prefix_refiner_feedback(d2k_prefix_refiner *r,uint64_t t,int outcome) {
    if(!r || outcome< -1 || outcome>1)return -1;
    if(!r->pending || t!=r->ticket || outcome== -1)return 0;
    free(r->program);r->program=NULL;
    r->pending=0;
    if(outcome) {
        memcpy(r->hypothesis,r->proposal,r->length);rebuild(r);
    } else {
        r->cursor+=r->take;
        if(r->cursor==r->count) {
            r->cursor=0;
            if(r->width==1)r->closed=1;
            else r->width=r->width/2+r->width%2;
        }
    }
    return 1;
}
const uint8_t *d2k_prefix_refiner_hypothesis(const d2k_prefix_refiner *r,size_t *n) {
    if(n)*n=r?r->length:0;
    return r?r->hypothesis:NULL;
}
