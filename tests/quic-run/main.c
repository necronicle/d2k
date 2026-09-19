/* Test-only entry point: real C classifier against the local donor oracle. */
#define _DEFAULT_SOURCE 1
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "d2k_meas.h"
#include "d2k_quichello.h"
#include "d2k_quicprobe.h"
#include "d2k_quic_arms.h"
#include "d2k_ipfrag.h"

static const char *verdict(d2k_verdict v) {
    switch (v) {
    case D2K_V_CLEAR: return "clear";
    case D2K_V_ADDRESS: return "address";
    case D2K_V_NO_QUIC: return "no_quic";
    case D2K_V_FLAKY: return "flaky";
    case D2K_V_INCONCLUSIVE: return "inconclusive";
    case D2K_V_LOCAL_ADDRESS: return "local_address";
    case D2K_V_OPAQUE: return "content";
    default: return "other";
    }
}

static size_t no_extra_addresses(const char *sni, char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    (void)sni; (void)out; (void)cap;
    return 0; /* Explicit loopback endpoint only: do not query external DNS. */
}
static int reject_mark;
static int reject_nodefrag;
/* Only quicprobe.c is compiled with this syscall replacement. No product
   hook and no mutation of the donor; all other options use the real call. */
int d2k_test_setsockopt(int fd,int level,int option,const void *value,socklen_t len) {
#ifdef IP_NODEFRAG
    if(reject_nodefrag && level==IPPROTO_IP && option==IP_NODEFRAG) {
        errno=ENOPROTOOPT;return -1;
    }
#endif
    return setsockopt(fd,level,option,value,len);
}
static int mark_failure(int fd,uint32_t mark) {
    (void)mark;
    int type=0;socklen_t n=sizeof type;
    if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n)!=0)return -1;
    return reject_mark==1 || type==SOCK_RAW?-1:0;
}

int main(int argc, char **argv) {
    if(argc==9 && !strcmp(argv[1],"--fragments")) {
        unsigned values[7];
        for(int i=0;i<7;i++) {
            char *end;long v=strtol(argv[i+2],&end,10);
            if(*end || v<0 || v>65535)return 2;
            values[i]=(unsigned)v;
        }
        size_t len=values[0],cap=3u*65535u;
        uint8_t *payload=malloc(len?len:1),*out=malloc(cap);
        if(!payload || !out){free(payload);free(out);return 2;}
        for(size_t i=0;i<len;i++)payload[i]=(uint8_t)i;
        d2k_ipfrag_plan p={.three=(uint8_t)values[1],.pos1=(uint16_t)values[2],
            .pos2=(uint16_t)values[3],.overlap12=(uint16_t)values[4],
            .overlap23=(uint16_t)values[5],.reverse=(uint8_t)values[6]};
        uint8_t src[4]={10,0,0,1},dst[4]={93,184,216,34};d2k_ipfrag_span spans[3];
        size_t n=d2k_udpfrag_build(src,dst,51234,443,payload,len,&p,0x1234,out,cap,spans);
        if(!n)puts("ERR");
        for(size_t i=0;i<n;i++) {
            for(size_t j=0;j<spans[i].len;j++)printf("%02x",out[spans[i].off+j]);
            putchar('\n');
        }
        free(payload);free(out);return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--blobs")) {
        for (size_t i=0;i<5;i++) {
            size_t len; const char *name;
            const uint8_t *b=d2k_quic_original_blob(i,&len,&name);
            printf("%s ",name);
            for(size_t j=0;j<len;j++) printf("%02x",b[j]);
            putchar('\n');
        }
        return 0;
    }
    if (argc != 2 && argc != 3 && argc != 4 && argc != 5) { return 2; }
    char *end;
    long port = strtol(argv[1], &end, 10);
    if (*end || port < 1 || port > 65535) { return 2; }
    uint8_t trigger[1500], control[1500];
    size_t tn = 0, cn = 0;
    if (d2k_quic_probe_initial("blocked.example", trigger, sizeof trigger, &tn) != 0 ||
        d2k_quic_probe_initial("z0011223344.example.com", control, sizeof control, &cn) != 0) { return 2; }
    d2k_quic_allow_local = 1;
    d2k_quic_resolve_hook = no_extra_addresses;
    d2k_quic_wait_ms = 40;
    if(argc>=4 && !strcmp(argv[2],"fragment")) {
        long shape=strtol(argv[3],&end,10);if(*end || shape<1 || shape>4)return 2;
        uint32_t mark=0;
        if(argc==5) {
            if(!strcmp(argv[4],"mark-rx"))reject_mark=1;
            else if(!strcmp(argv[4],"mark-raw"))reject_mark=2;
            else if(!strcmp(argv[4],"nodefrag"))reject_nodefrag=1;
            else return 2;
            if(reject_mark){d2k_mark_hook=mark_failure;mark=45;}
        }
        int sent=0;
        d2k_tally t=d2k_quic_fragment_hook("127.0.0.1",(uint16_t)port,(int)shape,
            (d2k_hello){trigger,tn},40,mark,3,&sent);
        printf("%d %d %d %d %d\n",t.pass,t.fail,t.err,t.marked,sent);return 0;
    }
    if (argc==3 && !strcmp(argv[2],"arms")) {
        char pool[1][D2K_QUIC_ADDR_LEN]={"127.0.0.1"};
        d2k_quic_arm_context c={.pool=pool,.n_pool=1,.next=1,.marked=1};
        d2k_quic_arm a=d2k_quic_original_measure(&c,(uint16_t)port,
            (d2k_hello){trigger,tn},(d2k_hello){control,cn},40,0);
        printf("%s %d %d %d\n",a.blob_name,a.copies,a.ttl,a.probes);
        for(size_t i=0;i<a.n_trace;i++) {
            d2k_quic_arm_step *s=&a.trace[i];
            printf("%s|%d|%d|%d\n",s->label,s->sent,s->answered,s->not_measured);
        }
        return 0;
    }
    d2k_quic_arm arm;
    d2k_vres r = d2k_quic_run("127.0.0.1", (uint16_t)port, "blocked.example",
                                  (d2k_hello){trigger, tn}, (d2k_hello){control, cn}, 0, &arm);
    if(argc==3 && !strcmp(argv[2],"content")) {
        printf("%s %d %s %d %d\n",verdict(r.verdict),r.qprops.residual_blocking,
               arm.blob_name,arm.copies,arm.ttl);
        return 0;
    }
    printf("%s %d\n", verdict(r.verdict), r.probes);
    return 0;
}
