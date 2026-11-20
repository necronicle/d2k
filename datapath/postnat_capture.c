#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_postnat_capture.h"
#include "d2k_postnat_link.h"
#include "d2k_packet.h"

struct d2k_postnat_capture {
    int fd;
    size_t link_len;
    d2k_postnat_link *filter;
};
d2k_postnat_capture *d2k_postnat_capture_open(unsigned output,uint32_t mark,
    uint16_t priority,char *err,size_t cap) {
    int ctl=-1,saved=0;
    d2k_postnat_capture *c=calloc(1,sizeof *c);
    if(!c){snprintf(err,cap,"post-NAT capture allocation failed");return NULL;}
    c->fd=-1;
    struct ifreq original={0},capture={0};
    if(!if_indextoname(output,original.ifr_name))goto fail;
    ctl=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    if(ctl<0 || ioctl(ctl,SIOCGIFHWADDR,&original)<0)goto fail;
    if(original.ifr_hwaddr.sa_family==ARPHRD_ETHER)c->link_len=14;
    else if(original.ifr_hwaddr.sa_family!=ARPHRD_PPP &&
            original.ifr_hwaddr.sa_family!=ARPHRD_NONE) {errno=EAFNOSUPPORT;goto fail;}
    if(ioctl(ctl,SIOCGIFMTU,&original)<0)goto fail;
    int mtu=original.ifr_mtu;
    c->fd=open("/dev/net/tun",O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if(c->fd<0)goto fail;
    capture.ifr_flags=(c->link_len?IFF_TAP:IFF_TUN)|IFF_NO_PI|IFF_TUN_EXCL;
    snprintf(capture.ifr_name,sizeof capture.ifr_name,"d2knat%%d");
    if(ioctl(c->fd,TUNSETIFF,&capture)<0)goto fail;
    capture.ifr_mtu=mtu;
    if(ioctl(ctl,SIOCSIFMTU,&capture)<0 || ioctl(ctl,SIOCGIFFLAGS,&capture)<0)goto fail;
    capture.ifr_flags|=IFF_UP;
    if(ioctl(ctl,SIOCSIFFLAGS,&capture)<0)goto fail;
    unsigned index=if_nametoindex(capture.ifr_name);
    if(!index)goto fail;
    close(ctl);ctl=-1;
    c->filter=d2k_postnat_link_open(output,index,mark,priority,err,cap);
    if(!c->filter){close(c->fd);free(c);return NULL;}
    return c;
fail:
    saved=errno;
    if(ctl>=0)close(ctl);
    if(c->fd>=0)close(c->fd);
    free(c);
    snprintf(err,cap,"post-NAT capture: %s",strerror(saved));errno=saved;
    return NULL;
}
int d2k_postnat_capture_fd(const d2k_postnat_capture *c) {return c?c->fd:-1;}
int d2k_postnat_capture_read(d2k_postnat_capture *c,uint8_t *out,size_t cap,size_t *len) {
    if(!c||!out||!len){errno=EINVAL;return -1;}
    *len=0;
    /* Extra byte makes an oversized frame distinguishable from a complete
       frame. This buffer is transient packet storage, not flow history. */
    uint8_t frame[65576+14];
    ssize_t n;
    do {n=read(c->fd,frame,sizeof frame);}while(n<0&&errno==EINTR);
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))return 0;
    if(n<0)return -1;
    if((size_t)n<=c->link_len){errno=EPROTO;return -1;}
    if(c->link_len && !((frame[12]==8&&frame[13]==0)||
                        (frame[12]==0x86&&frame[13]==0xdd)))return 0;
    size_t size=(size_t)n-c->link_len;
    d2k_packet_view v;
    /* A new TAP can emit its own IPv6 neighbour/router discovery. Those
       control frames are not redirected application packets. */
    if(!d2k_packet_parse(frame+c->link_len,size,&v))return 0;
    if(v.total!=size) {errno=EPROTO;return -1;}
    if(size>cap){errno=EMSGSIZE;return -1;}
    memcpy(out,frame+c->link_len,size);*len=size;return 1;
}
int d2k_postnat_capture_close(d2k_postnat_capture *c,char *err,size_t cap) {
    if(!c)return 0;
    int rc=d2k_postnat_link_close(c->filter,err,cap);
    close(c->fd);free(c);return rc;
}
