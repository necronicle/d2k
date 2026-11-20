#include "prefix_refine.h"
#include "lower.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
int main(void) {
    for(int reverse=0;reverse<2;reverse++) {
        d2k_payload_piece pieces[]={{0,3,0},{3,5,0}};
        if(reverse){pieces[0]=(d2k_payload_piece){3,5,0};pieces[1]=(d2k_payload_piece){0,3,0};}
        char *a=NULL,*b=NULL,err[200];
        assert(d2k_lower_tls_prefix_partition((uint8_t[]){1,2,3,4},4,1200,0,8,pieces,2,&a,err,sizeof err)==D2K_LOWER_OK);
        assert(d2k_lower_tls_prefix_partition((uint8_t[]){0,0,0,0},4,1200,0,8,pieces,2,&b,err,sizeof err)==D2K_LOWER_OK);
        d2k_prefix_refiner *r=d2k_prefix_refiner_new_partition_plans(a,b,8);assert(r);
        const char *plan;uint64_t ticket;assert(d2k_prefix_refiner_next_plan(r,&ticket,&plan)==1);
        uint8_t *bytes=NULL;size_t n,segment,count;unsigned mods;d2k_payload_piece *actual=NULL;
        assert(d2k_lower_tls_prefix_partition_read(plan,8,&bytes,&n,&segment,&mods,&actual,&count,err,sizeof err)==D2K_LOWER_OK);
        assert(n==4 && !memcmp(bytes,(uint8_t[]){0,0,3,4},4) && count==2 && segment==1200 && !mods);
        for(size_t i=0;i<count;i++)assert(actual[i].offset==pieces[i].offset && actual[i].length==pieces[i].length && actual[i].delay_us==pieces[i].delay_us);
        free(bytes);free(actual);d2k_prefix_refiner_free(r);
        free(b);b=NULL;
        d2k_payload_piece other[]={{0,2,0},{2,6,0}};
        assert(d2k_lower_tls_prefix_partition((uint8_t[]){0,0,0,0},4,1200,0,8,other,2,&b,err,sizeof err)==D2K_LOWER_OK);
        assert(!d2k_prefix_refiner_new_partition_plans(a,b,8));free(a);free(b);
    }
    {
        char *a=NULL,*b=NULL,err[200];
        assert(d2k_lower_tls_prefix((uint8_t[]){1,2,3,4},4,1400,3,&a,err,sizeof err)==D2K_LOWER_OK);
        assert(d2k_lower_tls_prefix((uint8_t[]){0,0,0,0},4,1400,3,&b,err,sizeof err)==D2K_LOWER_OK);
        d2k_prefix_refiner *plans=d2k_prefix_refiner_new_plans(a,b);assert(plans);
        for(int variant=0;variant<3;variant++) {
            char *different=NULL;
            assert(d2k_lower_tls_prefix((uint8_t[]){0,0,0,0},variant==0?3:4,
                variant==1?1300:1400,variant==2?1:3,&different,err,sizeof err)==D2K_LOWER_OK);
            assert(!d2k_prefix_refiner_new_plans(a,different));free(different);
        }
        free(a);free(b);
        const char *plan;uint64_t token;uint8_t *bytes;size_t length,segment;unsigned mods;
        assert(d2k_prefix_refiner_next_plan(plans,&token,&plan)==1);
        const char *same;uint64_t repeated;
        assert(!d2k_prefix_refiner_feedback(plans,token,-1));
        assert(d2k_prefix_refiner_next_plan(plans,&repeated,&same)==1 && repeated==token && same==plan);
        assert(d2k_lower_tls_prefix_read(plan,&bytes,&length,&segment,&mods,err,sizeof err)==D2K_LOWER_OK);
        assert(length==4 && segment==1400 && mods==3 && !memcmp(bytes,(uint8_t[]){0,0,3,4},4));free(bytes);
        assert(d2k_prefix_refiner_feedback(plans,token,1)==1);
        d2k_prefix_refiner_free(plans);
    }
    uint8_t good[]={1,2,3,4},other[]={0,0,0,0};
    d2k_prefix_refiner *r=d2k_prefix_refiner_new(good,other,4);assert(r);
    memset(good,9,4);memset(other,9,4);
    uint64_t ticket,again;const uint8_t *p,*q;size_t n,m;
    assert(d2k_prefix_refiner_next(r,&ticket,&p,&n)==1 && n==4);
    assert(p[0]==0 && p[1]==0 && p[2]==3 && p[3]==4);
    assert(d2k_prefix_refiner_next(r,&again,&q,&m)==1 && again==ticket && q==p);
    assert(d2k_prefix_refiner_feedback(r,ticket+1,1)==0);
    assert(d2k_prefix_refiner_feedback(r,ticket,-1)==0);
    assert(d2k_prefix_refiner_next(r,&again,&q,&m)==1 && again==ticket);
    assert(d2k_prefix_refiner_feedback(r,ticket,1)==1);
    assert(d2k_prefix_refiner_feedback(r,ticket,1)==0);
    /* The last byte is required by this deterministic test oracle. */
    unsigned questions=1;
    while(d2k_prefix_refiner_next(r,&ticket,&p,&n)==1) {
        assert(++questions<20);
        assert(d2k_prefix_refiner_feedback(r,ticket,p[3]==4)==1);
    }
    p=d2k_prefix_refiner_hypothesis(r,&n);
    assert(n==4 && p[0]==0 && p[1]==0 && p[2]==0 && p[3]==4);
    d2k_prefix_refiner_free(r);
    r=d2k_prefix_refiner_new((uint8_t[]){1},(uint8_t[]){1},1);assert(r);
    assert(d2k_prefix_refiner_next(r,&ticket,&p,&n)==0);
    d2k_prefix_refiner_free(r);
    assert(!d2k_prefix_refiner_new(NULL,good,4));
    for(int accept=0;accept<2;accept++) {
        const uint8_t a[]={1,8,2,8,3},b[]={0,8,0,8,0};
        r=d2k_prefix_refiner_new(a,b,sizeof a);assert(r);
        questions=0;
        while(d2k_prefix_refiner_next(r,&ticket,&p,&n)==1) {
            assert(++questions<20 && n==sizeof a && p[1]==8 && p[3]==8);
            assert(d2k_prefix_refiner_feedback(r,ticket,2)==-1);
            assert(d2k_prefix_refiner_feedback(r,ticket,accept)==1);
        }
        p=d2k_prefix_refiner_hypothesis(r,&n);
        assert(!memcmp(p,accept?b:a,n));
        d2k_prefix_refiner_free(r);
    }
    return 0;
}
