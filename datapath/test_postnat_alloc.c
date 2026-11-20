#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned calls, fail_call, calloc_calls, fail_calloc_call;
static size_t live_allocations;
static int deny_alloc;
static void *fault_malloc(size_t n) {
    calls++;
    if (deny_alloc || (fail_call && calls == fail_call)) return NULL;
    void *p=malloc(n);
    if (p) live_allocations++;
    return p;
}
static void *fault_calloc(size_t n,size_t size) {
    calloc_calls++;
    if (fail_calloc_call && calloc_calls==fail_calloc_call) return NULL;
    void *p=calloc(n,size);
    if (p) live_allocations++;
    return p;
}
static void fault_free(void *p) {
    if (p) live_allocations--;
    free(p);
}
#define malloc fault_malloc
#define calloc fault_calloc
#define free fault_free
#include "postnat_own.c"
#undef malloc
#undef calloc
#undef free
static int failures, fallback_count;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"postnat-alloc:%d: %s\n",__LINE__,#x); failures++; } } while (0)
static int fallback(void *ctx,const uint8_t *original,size_t olen,const uint8_t *p,size_t n,const d2k_postnat_identity *id) {
    (void)id; fallback_count++;
    CHECK(p && n==28 && !memcmp(p,ctx,n));
    CHECK(original && olen==28 && !memcmp(original,ctx,olen));
    return 1;
}
int main(void) {
    uint8_t p[28]={0x45,0,0,28,0,1,0,0,64,17};
    p[12]=10;p[15]=1;p[16]=10;p[19]=2;
    p[20]=0xc0;p[21]=1;p[22]=1;p[23]=0xbb;p[25]=8;
    d2k_postnat_identity id={.generation=1,.epoch={1},.trial={1}};
    d2k_postnat_own *o;
    for (fail_calloc_call=1;fail_calloc_call<=2;fail_calloc_call++) {
        calloc_calls=0;
        o=d2k_postnat_own_new(1,128);
        CHECK(!o);
        CHECK(live_allocations==0);
    }
    fail_calloc_call=0;
    for (int failure=1;failure<=2;failure++) {
        calls=0;calloc_calls=0;deny_alloc=0;fail_call=failure;
        o=d2k_postnat_own_new(1,128);
        CHECK(o);
        size_t before_alloc=live_allocations;
        CHECK(d2k_postnat_own_begin(o,p,sizeof p,&id,100)==0);
        CHECK(d2k_postnat_own_pending(o)==0);
        CHECK(live_allocations==before_alloc);
        fail_call=0;calls=0;
        CHECK(d2k_postnat_own_begin(o,p,sizeof p,&id,100)==1);
        CHECK(d2k_postnat_own_pending(o)==1);
        unsigned before=calls;deny_alloc=1;
        CHECK(d2k_postnat_own_captured(o,p,sizeof p)==1);
        CHECK(calls==before);
        CHECK(d2k_postnat_own_expire(o,100,fallback,p)==1);
        CHECK(fallback_count==failure && d2k_postnat_own_pending(o)==0);
        d2k_postnat_own_free(o);
        CHECK(live_allocations==0);
    }
    return failures?1:0;
}
