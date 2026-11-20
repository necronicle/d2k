#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "d2k_provider_ips.h"

int main(void) {
    d2k_provider_ips ips={0}, restored={0};
    d2k_dns_answer a={.type=1,.count=1,.ttl=30};
    strcpy(a.question,"rr2---sn-4g5ednrs.googlevideo.com");
    a.addresses[0][0]=173;a.addresses[0][1]=194;a.addresses[0][2]=6;a.addresses[0][3]=231;
    assert(d2k_provider_ips_observe(&ips,&a,100)==1);
    assert(d2k_provider_ips_has(&ips,a.addresses[0],4,101));
    assert(!d2k_provider_ips_has(&ips,a.addresses[0],4,3701));
    const char *path="/tmp/d2k-provider-ips-test.txt";
    assert(!d2k_provider_ips_save(&ips,path,100));
    assert(!d2k_provider_ips_load(&restored,path,101));
    assert(d2k_provider_ips_has(&restored,a.addresses[0],4,101));
    strcpy(a.question,"notgooglevideo.com");
    a.addresses[0][3]=232;
    assert(!d2k_provider_ips_observe(&ips,&a,102));
    assert(!d2k_provider_ips_has(&ips,a.addresses[0],4,102));
    strcpy(a.question,"redirector.gvt1.com");
    assert(!d2k_provider_ips_observe(&ips,&a,102));
    strcpy(a.question,"r1.sn-node.gvt1.com");
    assert(d2k_provider_ips_observe(&ips,&a,102)==1);
    assert(d2k_provider_ips_has(&ips,a.addresses[0],4,103));
    a.type=28;memset(a.addresses[0],0,16);a.addresses[0][0]=0x20;a.addresses[0][1]=0x01;
    assert(d2k_provider_ips_observe(&ips,&a,103)==1);
    assert(d2k_provider_ips_has(&ips,a.addresses[0],6,104));
    assert(!d2k_provider_ips_save(&ips,path,104));
    assert(!d2k_provider_ips_load(&restored,path,105));
    assert(d2k_provider_ips_has(&restored,a.addresses[0],6,105));
    FILE *corrupt=fopen(path,"w");assert(corrupt);
    assert(fputs("bad snapshot\n",corrupt)>=0);assert(!fclose(corrupt));
    assert(d2k_provider_ips_load(&restored,path,106));
    assert(d2k_provider_ips_has(&restored,a.addresses[0],6,106));
    remove(path);
    puts("provider ips ok");
    return 0;
}
