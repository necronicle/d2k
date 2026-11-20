#define _GNU_SOURCE
#include "d2k_dns_capture.h"
#include <string.h>
#include <strings.h>

static unsigned read16(const uint8_t *p) {
    return (unsigned)p[0]*256+p[1];
}

static int parse_question(const uint8_t *dns,size_t len,char name[256],uint16_t *type) {
    if (len<17 || (dns[2]&0xfa) || read16(dns+4)!=1 || read16(dns+6) || read16(dns+8))
        return 0;
    size_t p=12,used=0;
    while (p<len) {
        unsigned n=dns[p++];
        if (!n) {
            if (!used || len-p<4 || read16(dns+p+2)!=1 || !read16(dns+p))return 0;
            name[used]=0;*type=(uint16_t)read16(dns+p);
            return 1;
        }
        if (n>63 || n>len-p || used+n+(used!=0)>253)return 0;
        if (used)name[used++]='.';
        for (unsigned i=0;i<n;i++) {
            unsigned char c=dns[p++];
            if (!((c>='a' && c<='z') || (c>='A' && c<='Z') ||
                (c>='0' && c<='9') || c=='-' || c=='_'))return 0;
            name[used++]=(char)c;
        }
    }
    return 0;
}

int d2k_dns_capture_question(const uint8_t *p,size_t len,uint8_t dst[16],int *family,
    char name[256],uint16_t *type) {
    size_t at,total;unsigned protocol;
    if (!len)return 0;
    if ((p[0]>>4)==4) {
        if (len<20 || (read16(p+6)&0x3fff))return 0;
        at=(p[0]&15)*4;total=read16(p+2);protocol=p[9];
        if (at<20 || total<at || total>len)return 0;
        memset(dst,0,16);memcpy(dst,p+16,4);*family=4;
    } else if ((p[0]>>4)==6) {
        if (len<40)return 0;
        at=40;total=40+read16(p+4);protocol=p[6];
        if (total>len)return 0;
        memcpy(dst,p+24,16);*family=6;
    } else return 0;
    p+=at;len=total-at;
    if (len<4 || read16(p+2)!=53)return 0;
    if (protocol==17) {
        if (len<8)return 0;
        unsigned size=read16(p+4);
        return size>=8 && size==len && parse_question(p+8,len-8,name,type);
    }
    if (protocol==6) {
        if (len<22)return 0;
        size_t offset=(p[12]>>4)*4;
        if (offset<20 || offset+2>len || (p[13]&0x07))return 0;
        unsigned dns_len=read16(p+offset);
        return dns_len<=len-offset-2 && parse_question(p+offset+2,dns_len,name,type);
    }
    return 0;
}

static int read_name(const uint8_t *dns,size_t len,size_t *pos,char out[256]) {
    size_t p=*pos,end=0,used=0;unsigned steps=0;int jumped=0;
    for(;;) {
        if(p>=len||++steps>64)return 0;
        unsigned n=dns[p++];
        if((n&0xc0)==0xc0) {
            if(p>=len)return 0;
            size_t next=((n&0x3f)<<8)|dns[p++];
            if(!jumped){end=p;jumped=1;}
            if(next>=len)return 0;p=next;continue;
        }
        if(n&0xc0)return 0;
        if(!n) {if(!jumped)end=p;break;}
        if(n>63||n>len-p||used+n+(used!=0)>253)return 0;
        if(used)out[used++]='.';
        for(size_t i=0;i<n;i++) {
            uint8_t c=dns[p++];
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return 0;
            out[used++]=(char)c;
        }
    }
    if(!used)return 0;out[used]=0;*pos=end;return 1;
}

int d2k_dns_capture_answer(const uint8_t *packet,size_t len,d2k_dns_answer *out) {
    if(!packet||!out)return 0;
    memset(out,0,sizeof *out);out->ttl=UINT32_MAX;
    size_t at,total;unsigned protocol;
    if(!len)return 0;
    if((packet[0]>>4)==4) {
        if(len<20||(read16(packet+6)&0x3fff))return 0;
        at=(packet[0]&15)*4;total=read16(packet+2);protocol=packet[9];out->family=4;
        if(at<20||total<at||total>len)return 0;
        memcpy(out->client,packet+16,4);memcpy(out->server,packet+12,4);
    } else if((packet[0]>>4)==6) {
        if(len<40)return 0;at=40;total=40+read16(packet+4);protocol=packet[6];out->family=6;
        if(total>len)return 0;memcpy(out->client,packet+24,16);memcpy(out->server,packet+8,16);
    } else return 0;
    packet+=at;len=total-at;
    if(len<4||read16(packet)!=53)return 0;
    const uint8_t *dns;size_t dns_len;
    if(protocol==17) {
        if(len<8||read16(packet+4)!=len)return 0;dns=packet+8;dns_len=len-8;
    } else if(protocol==6) {
        if(len<22)return 0;size_t offset=(packet[12]>>4)*4;
        if(offset<20||offset+2>len||(packet[13]&7))return 0;
        dns_len=read16(packet+offset);dns=packet+offset+2;
        if(dns_len!=len-offset-2)return 0;
    } else return 0;
    if(dns_len<18||!(dns[2]&0x80)||(dns[2]&0x7a)||(dns[3]&15) ||
        read16(dns+4)!=1||!read16(dns+6))return 0;
    size_t pos=12;char question[256];uint16_t qtype,qclass;
    if(!read_name(dns,dns_len,&pos,question)||pos+4>dns_len)return 0;
    qtype=read16(dns+pos);qclass=read16(dns+pos+2);pos+=4;
    if(qclass!=1||(qtype!=1&&qtype!=28))return 0;
    strcpy(out->question,question);
    strcpy(out->name,question);
    out->type=qtype;
    const size_t records=pos;
    unsigned answers=read16(dns+6);
    /* RR order is immaterial. Follow only the chain rooted at the question. */
    for (unsigned hops=0; hops<=answers; hops++) {
        char alias[256]="";
        pos=records;
        for (unsigned i=0;i<answers;i++) {
            char owner[256];
            if (!read_name(dns,dns_len,&pos,owner) || dns_len-pos<10) return 0;
            unsigned type=read16(dns+pos), cls=read16(dns+pos+2);
            uint32_t ttl=((uint32_t)read16(dns+pos+4)<<16)|read16(dns+pos+6);
            size_t size=read16(dns+pos+8);
            pos+=10;
            if (size>dns_len-pos) return 0;
            if (cls==1 && !strcasecmp(owner,out->name) && (type==5 || type==qtype)) {
                if (ttl>INT32_MAX) ttl=0;
                if (ttl<out->ttl) out->ttl=ttl;
                if (type==5) {
                    char target[256]; size_t end=pos;
                    if (!read_name(dns,dns_len,&end,target) || end!=pos+size ||
                        (alias[0] && strcasecmp(alias,target))) return 0;
                    strcpy(alias,target);
                } else {
                    if (size!=(qtype==1?4u:16u) || out->count==D2K_DNS_ANSWER_MAX_ADDR) return 0;
                    memcpy(out->addresses[out->count++],dns+pos,size);
                }
            }
            pos+=size;
        }
        if (!alias[0]) return out->count!=0;
        if (out->count) return 0;
        strcpy(out->name,alias);
    }
    return 0;
}

#ifdef __linux__
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

struct local_dns_address {int family; unsigned interface; uint8_t bytes[16];};
struct d2k_dns_capture {
    int fd,answer_fd;
    int64_t refresh_at;
    size_t count;
    struct local_dns_address addresses[64];
};

static void refresh(struct d2k_dns_capture *c,int64_t now) {
    c->refresh_at=now+10000;
    struct ifaddrs *list;
    if (getifaddrs(&list)) {
        c->count=0;
        return;
    }
    c->count=0;
    for (const struct ifaddrs *a=list;a && c->count<64;a=a->ifa_next) {
        if (!a->ifa_addr || !a->ifa_name || !(a->ifa_flags&IFF_UP) ||
            (a->ifa_flags&IFF_LOOPBACK))continue;
        int af=a->ifa_addr->sa_family;
        if (af!=AF_INET && af!=AF_INET6)continue;
        char path[128];
        int n=snprintf(path,sizeof path,"/sys/class/net/%s/bridge",a->ifa_name);
        if (n<0 || (size_t)n>=sizeof path || access(path,F_OK))continue;
        unsigned interface=if_nametoindex(a->ifa_name);
        if (!interface)continue;
        struct local_dns_address *out=c->addresses+c->count++;
        out->interface=interface;out->family=af==AF_INET ? 4 : 6;
        if (af==AF_INET)
            memcpy(out->bytes,&((const struct sockaddr_in *)a->ifa_addr)->sin_addr,4);
        else
            memcpy(out->bytes,&((const struct sockaddr_in6 *)a->ifa_addr)->sin6_addr,16);
    }
    freeifaddrs(list);
}

static int filtered_socket(unsigned port_offset) {
    /* SOCK_DGRAM supplies IP bytes without an Ethernet header. Filter in the
       kernel so userspace does not consume non-DNS traffic on busy routers. */
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS,0),BPF_STMT(BPF_ALU|BPF_AND|BPF_K,0xf0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0x40,1,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0x60,6,12),
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS,9),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,17,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,6,0,9),BPF_STMT(BPF_LDX|BPF_B|BPF_MSH,0),
        BPF_STMT(BPF_LD|BPF_H|BPF_IND,port_offset-40),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,53,5,6),
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS,6),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,17,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,6,0,3),BPF_STMT(BPF_LD|BPF_H|BPF_ABS,port_offset),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,53,0,1),BPF_STMT(BPF_RET|BPF_K,2048),BPF_STMT(BPF_RET|BPF_K,0)
    };
    struct sock_fprog filter={(unsigned short)(sizeof code/sizeof *code),code};
    int fd=socket(AF_PACKET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,htons(ETH_P_ALL));
    if(fd<0)return -1;
    if(setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&filter,sizeof filter)){close(fd);return -1;}
    return fd;
}

struct d2k_dns_capture *d2k_dns_capture_open(void) {
    int question=filtered_socket(42),answer=filtered_socket(40);
    if(question<0||answer<0) {if(question>=0)close(question);if(answer>=0)close(answer);return NULL;}
    struct d2k_dns_capture *c=calloc(1,sizeof *c);
    if(!c){close(question);close(answer);return NULL;}
    c->fd=question;c->answer_fd=answer;return c;
}

void d2k_dns_capture_drain_full(struct d2k_dns_capture *c,int64_t now,d2k_dns_capture_fn observe,
    d2k_dns_capture_answer_fn answer_observe,void *context) {
    if(!c||(!observe&&!answer_observe))return;
    if(now>=c->refresh_at)refresh(c,now);
    if(observe)for(unsigned i=0;i<32;i++) {
        uint8_t packet[2048],dst[16];struct sockaddr_ll source;socklen_t source_len=sizeof source;
        ssize_t n=recvfrom(c->fd,packet,sizeof packet,0,(struct sockaddr *)&source,&source_len);
        if(n<0){if(errno==EINTR)continue;break;}
        if(source_len<sizeof source||source.sll_pkttype!=PACKET_HOST)continue;
        int family;char name[256];uint16_t type;
        if(!d2k_dns_capture_question(packet,(size_t)n,dst,&family,name,&type))continue;
        for(size_t j=0;j<c->count;j++) {
            const struct local_dns_address *local=c->addresses+j;
            if((unsigned)source.sll_ifindex==local->interface&&family==local->family&&
                !memcmp(dst,local->bytes,family==4?4:16)){observe(context,name,type);break;}
        }
    }
    if(answer_observe)for(unsigned i=0;i<32;i++) {
        uint8_t packet[2048];struct sockaddr_ll source;socklen_t source_len=sizeof source;
        ssize_t n=recvfrom(c->answer_fd,packet,sizeof packet,0,(struct sockaddr *)&source,&source_len);
        if(n<0){if(errno==EINTR)continue;break;}
        if(source_len<sizeof source || source.sll_pkttype!=PACKET_OUTGOING)continue;
        d2k_dns_answer answer;
        if(!d2k_dns_capture_answer(packet,(size_t)n,&answer))continue;
        answer.ingress=(uint32_t)source.sll_ifindex;
        for(size_t j=0;j<c->count;j++) {
            const struct local_dns_address *local=c->addresses+j;
            if((unsigned)source.sll_ifindex==local->interface&&answer.family==local->family&&
                !memcmp(answer.server,local->bytes,answer.family==4?4:16)){answer_observe(context,&answer);break;}
        }
    }
}

void d2k_dns_capture_drain(struct d2k_dns_capture *c,int64_t now,d2k_dns_capture_fn observe,void *context) {
    d2k_dns_capture_drain_full(c,now,observe,NULL,context);
}

void d2k_dns_capture_free(struct d2k_dns_capture *c) {
    if(c){close(c->fd);close(c->answer_fd);free(c);}
}
#else
struct d2k_dns_capture *d2k_dns_capture_open(void) {return NULL;}
void d2k_dns_capture_drain(struct d2k_dns_capture *c,int64_t now,d2k_dns_capture_fn f,void *ctx) {
    (void)c;(void)now;(void)f;(void)ctx;
}
void d2k_dns_capture_drain_full(struct d2k_dns_capture *c,int64_t now,d2k_dns_capture_fn f,
    d2k_dns_capture_answer_fn a,void *ctx) {(void)c;(void)now;(void)f;(void)a;(void)ctx;}
void d2k_dns_capture_free(struct d2k_dns_capture *c) {(void)c;}
#endif
