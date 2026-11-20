#define _POSIX_C_SOURCE 200809L
#include "sched.c"
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    d2k_catalog c={0};char err[256];
    if(d2k_catalog_load(argv[1],&c,err,sizeof err)){fprintf(stderr,"%s\n",err);return 1;}
    d2k_sched *s=d2k_sched_new(&c,-1,0x2d);
    printf("groups=%zu observations=%zu overflow=%d index=%d slots=%zu\n",c.groups->n_groups,c.groups->n_observations,c.groups->groups_overflow,c.groups->derived_ready,d2k_group_slots(c.groups));
    clock_t start=clock();size_t desired=0;
    for(size_t i=0;i<d2k_group_slots(c.groups)+c.groups->n_observations;i++){installed_area a;if(desired_area(s,i,&a))desired++;}
    printf("desired=%zu cpu=%.3f\n",desired,(double)(clock()-start)/CLOCKS_PER_SEC);
    d2k_sched_free(s);d2k_catalog_free(&c);return 0;
}
