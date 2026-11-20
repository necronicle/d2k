#include "lower.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    {
        uint8_t prefix[]={22,3,3,0,1,0};char *program=NULL,why[200];
        d2k_payload_piece pieces[]={{0,3,0},{3,8,0},{11,9,0}};
        assert(d2k_lower_tls_prefix_partition(prefix,sizeof prefix,1400,0,
            20,pieces,3,&program,why,sizeof why)==D2K_LOWER_OK);
        assert(strstr(program,"fake payload=1 poison=1 repeats=1"));
        assert(strstr(program,"split payload_start +3\n"));
        assert(strstr(program,"split payload_start +11\n"));
        assert(strstr(program,"order forward\n"));
        uint8_t *decoded=NULL;size_t bytes=0,segment=0,count=0;unsigned mods=99;
        d2k_payload_piece *partition=NULL;
        assert(d2k_lower_tls_prefix_partition_read(program,20,&decoded,&bytes,&segment,&mods,
            &partition,&count,why,sizeof why)==D2K_LOWER_OK);
        assert(bytes==sizeof prefix && !memcmp(decoded,prefix,bytes) && segment==1400 && !mods && count==3);
        for(size_t i=0;i<count;i++)assert(partition[i].offset==pieces[i].offset && partition[i].length==pieces[i].length);
        free(decoded);free(partition);
        assert(d2k_lower_tls_prefix_partition_read(program,11,&decoded,&bytes,&segment,&mods,
            &partition,&count,why,sizeof why)!=D2K_LOWER_OK && !decoded && !partition);
        free(program);
        d2k_payload_piece reverse[]={{11,9,0},{3,8,23},{0,3,23}};
        assert(d2k_lower_tls_prefix_partition(prefix,sizeof prefix,1400,3,
            20,reverse,3,&program,why,sizeof why)==D2K_LOWER_OK);
        strstr(program,"\nid ")[4]='f';
        assert(d2k_lower_tls_prefix_partition_read(program,20,&decoded,&bytes,&segment,&mods,
            &partition,&count,why,sizeof why)==D2K_LOWER_OK);
        assert(mods==3 && count==3);
        for(size_t i=0;i<count;i++)assert(partition[i].offset==reverse[i].offset &&
            partition[i].length==reverse[i].length && partition[i].delay_us==reverse[i].delay_us);
        free(decoded);free(partition);
        char *extra=malloc(strlen(program)+30);assert(extra);
        strcpy(extra,program);strcat(extra,"split payload_start +12\n");
        assert(d2k_lower_tls_prefix_partition_read(extra,20,&decoded,&bytes,&segment,&mods,
            &partition,&count,why,sizeof why)!=D2K_LOWER_OK && !decoded && !partition);
        free(extra);free(program);
        pieces[2].length--;
        assert(d2k_lower_tls_prefix_partition(prefix,sizeof prefix,1400,0,
            20,pieces,3,&program,why,sizeof why)==D2K_LOWER_INVALID && !program);
    }
    for(unsigned flags=0;flags<4;flags++) {
        uint8_t source[]={0,1,254,255},*decoded=NULL;char *program=NULL,why[200];
        size_t length=0,segment=0;unsigned mods=99;
        assert(d2k_lower_tls_prefix(source,sizeof source,1379,flags,&program,why,sizeof why)==D2K_LOWER_OK);
        char *id=strstr(program,"\nid ");assert(id);id[4]='a';
        assert(d2k_lower_tls_prefix_read(program,&decoded,&length,&segment,&mods,why,sizeof why)==D2K_LOWER_OK);
        assert(length==sizeof source && segment==1379 && mods==flags && !memcmp(decoded,source,length));free(decoded);
        char *extra=malloc(strlen(program)+40);assert(extra);
        strcpy(extra,program);strcat(extra,"split payload_start +2\n");
        assert(d2k_lower_tls_prefix_read(extra,&decoded,&length,&segment,&mods,why,sizeof why)!=D2K_LOWER_OK && !decoded);
        free(extra);free(program);
    }
    char *text=NULL,err[256];
    d2k_payload_piece p[]={{0,3,0},{3,4,17},{7,13,17}};
    assert(d2k_lower_partition(20,p,3,"tls",&text,err,sizeof err)==D2K_LOWER_OK);
    assert(strstr(text,"d2k-plan 1 8\n") && strstr(text,"\nwire tcp-template-v1\n"));
    assert(strstr(text,"split payload_start +3\n") && strstr(text,"split payload_start +7\n"));
    assert(strstr(text,"order forward\n") && strstr(text,"pace 17\n"));free(text);
    d2k_payload_piece reverse[]={{7,13,0},{3,4,17},{0,3,17}};
    assert(d2k_lower_partition(20,reverse,3,"http",&text,err,sizeof err)==D2K_LOWER_OK);
    assert(strstr(text,"order reverse\n") && strstr(text,"proto tcp http\n"));free(text);
    p[1].length=3;
    assert(d2k_lower_partition(20,p,3,"tls",&text,err,sizeof err)==D2K_LOWER_INVALID && !text && err[0]);
    p[1].length=5;
    assert(d2k_lower_partition(20,p,3,"tls",&text,err,sizeof err)==D2K_LOWER_INVALID && !text);
    p[1].length=4;p[2].delay_us=18;
    assert(d2k_lower_partition(20,p,3,"tls",&text,err,sizeof err)==D2K_LOWER_UNSUPPORTED && !text);
    p[2].delay_us=17;
    d2k_payload_piece mixed[]={p[1],p[0],p[2]};mixed[0].delay_us=0;
    assert(d2k_lower_partition(20,mixed,3,"tls",&text,err,sizeof err)==D2K_LOWER_UNSUPPORTED && !text);
    assert(d2k_lower_partition(21,p,3,"tls",&text,err,sizeof err)==D2K_LOWER_INVALID && !text);
    puts("lower: exact partition, order, pacing, gaps/overlap and unsupported emission rejection PASS");
}
