#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_mirred.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "d2k_postnat_link.h"

struct request {struct nlmsghdr h;struct tcmsg tc;unsigned char data[1024];};
struct d2k_postnat_link {int fd;unsigned output;uint32_t mark,seq;uint16_t priority;};
static int64_t clock_ms(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
    return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static int add(struct request *r,unsigned type,const void *data,size_t n) {
    size_t off=NLMSG_ALIGN(r->h.nlmsg_len),len=RTA_LENGTH(n);
    if(n>UINT16_MAX-RTA_LENGTH(0)||off>sizeof *r||RTA_ALIGN(len)>sizeof *r-off)return -1;
    struct rtattr *a=(void *)((unsigned char *)r+off);
    a->rta_type=(unsigned short)type;a->rta_len=(unsigned short)len;
    if(n)memcpy(RTA_DATA(a),data,n);
    memset((unsigned char *)a+len,0,RTA_ALIGN(len)-len);
    r->h.nlmsg_len=(unsigned)(off+RTA_ALIGN(len));return 0;
}
static size_t begin(struct request *r,unsigned type) {
    size_t off=NLMSG_ALIGN(r->h.nlmsg_len);
    return add(r,type,NULL,0)?0:off;
}
static void end(struct request *r,size_t off) {
    struct rtattr *a=(void *)((unsigned char *)r+off);
    a->rta_len=(unsigned short)(r->h.nlmsg_len-off);
}
static int transact(d2k_postnat_link *l,struct request *r) {
    r->h.nlmsg_seq=++l->seq;
    struct sockaddr_nl kernel={.nl_family=AF_NETLINK};
    ssize_t sent;
    do {sent=sendto(l->fd,r,r->h.nlmsg_len,0,(struct sockaddr *)&kernel,sizeof kernel);}
    while(sent<0&&errno==EINTR);
    if(sent!=(ssize_t)r->h.nlmsg_len)return -(sent<0?errno:EIO);
    int64_t deadline=clock_ms()+2000;
    for(;;) {
        int64_t left=deadline-clock_ms();if(left<=0)return -ETIMEDOUT;
        struct pollfd p={l->fd,POLLIN,0};int ready=poll(&p,1,(int)left);
        if(ready<0&&errno==EINTR)continue;
        if(ready<0)return -errno;
        if(!ready)continue;
        unsigned char buf[8192];struct sockaddr_nl from={0};
        struct iovec iov={buf,sizeof buf};
        struct msghdr msg={0};msg.msg_name=&from;msg.msg_namelen=sizeof from;
        msg.msg_iov=&iov;msg.msg_iovlen=1;
        ssize_t n=recvmsg(l->fd,&msg,MSG_DONTWAIT);
        if(n<0&&(errno==EINTR||errno==EAGAIN))continue;
        if(n<=0)return -(n<0?errno:EIO);
        if((msg.msg_flags&MSG_TRUNC)||from.nl_pid)return -EPROTO;
        for(size_t off=0;off+NLMSG_HDRLEN<=(size_t)n;) {
            struct nlmsghdr h;memcpy(&h,buf+off,sizeof h);
            if(h.nlmsg_len<NLMSG_HDRLEN||h.nlmsg_len>(size_t)n-off)return -EPROTO;
            if(h.nlmsg_seq==l->seq&&h.nlmsg_type==NLMSG_ERROR) {
                if(h.nlmsg_len<NLMSG_LENGTH(sizeof(struct nlmsgerr)))return -EPROTO;
                struct nlmsgerr e;memcpy(&e,buf+off+NLMSG_HDRLEN,sizeof e);
                return e.error>0?-EPROTO:e.error;
            }
            off+=NLMSG_ALIGN(h.nlmsg_len);
        }
    }
}
static void init(struct request *r,d2k_postnat_link *l,unsigned type) {
    memset(r,0,sizeof *r);r->h.nlmsg_len=NLMSG_LENGTH(sizeof r->tc);
    r->h.nlmsg_type=(unsigned short)type;r->h.nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK;
    r->tc.tcm_family=AF_UNSPEC;r->tc.tcm_ifindex=(int)l->output;
}
static int filter(d2k_postnat_link *l,unsigned capture,int install) {
    struct request r;init(&r,l,install?RTM_NEWTFILTER:RTM_DELTFILTER);
    r.tc.tcm_parent=TC_H_MAKE(TC_H_CLSACT,TC_H_MIN_EGRESS);
    r.tc.tcm_handle=l->mark;r.tc.tcm_info=((unsigned)l->priority<<16)|htons(ETH_P_ALL);
    if(install)r.h.nlmsg_flags|=NLM_F_CREATE|NLM_F_EXCL;
    if(add(&r,TCA_KIND,"fw",3))return -EMSGSIZE;
    if(install) {
        size_t opts=begin(&r,TCA_OPTIONS);if(!opts)return -EMSGSIZE;
        if(add(&r,TCA_FW_MASK,&l->mark,sizeof l->mark))return -EMSGSIZE;
        size_t acts=begin(&r,TCA_FW_ACT),one=begin(&r,1);
        if(!acts||!one||add(&r,TCA_ACT_KIND,"mirred",7))return -EMSGSIZE;
        size_t ao=begin(&r,TCA_ACT_OPTIONS);if(!ao)return -EMSGSIZE;
        struct tc_mirred m={0};m.action=TC_ACT_STOLEN;m.eaction=TCA_EGRESS_REDIR;m.ifindex=capture;
        if(add(&r,TCA_MIRRED_PARMS,&m,sizeof m))return -EMSGSIZE;
        end(&r,ao);end(&r,one);end(&r,acts);end(&r,opts);
    }
    return transact(l,&r);
}
d2k_postnat_link *d2k_postnat_link_open(unsigned output,unsigned capture,
    uint32_t mark,uint16_t priority,char *err,size_t cap) {
    if(!output||output>INT_MAX||!capture||capture>INT_MAX||output==capture||
       !mark||(mark&(mark-1))||!priority) {
        snprintf(err,cap,"invalid post-NAT capture parameters");return NULL;
    }
    d2k_postnat_link *l=calloc(1,sizeof *l);
    if(!l){snprintf(err,cap,"post-NAT allocation failed");return NULL;}
    l->output=output;l->mark=mark;l->priority=priority;
    l->fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK,NETLINK_ROUTE);
    if(l->fd<0){snprintf(err,cap,"post-NAT netlink: %s",strerror(errno));free(l);return NULL;}
    struct request r;init(&r,l,RTM_NEWQDISC);
    r.h.nlmsg_flags|=NLM_F_CREATE|NLM_F_EXCL;
    r.tc.tcm_parent=TC_H_CLSACT;r.tc.tcm_handle=TC_H_MAKE(TC_H_CLSACT,0);
    int rc=add(&r,TCA_KIND,"clsact",7)?-EMSGSIZE:transact(l,&r);
    if(!rc||rc==-EEXIST)rc=filter(l,capture,1);
    if(rc){snprintf(err,cap,"post-NAT filter: %s",strerror(-rc));close(l->fd);free(l);return NULL;}
    return l;
}
int d2k_postnat_link_close(d2k_postnat_link *l,char *err,size_t cap) {
    if(!l)return 0;
    int rc=filter(l,0,0);
    if(rc==-ENOENT||rc==-ENODEV)rc=0;
    if(rc)snprintf(err,cap,"post-NAT filter removal: %s",strerror(-rc));
    close(l->fd);free(l);return rc?-1:0;
}
