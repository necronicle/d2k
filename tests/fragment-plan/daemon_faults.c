/* Only the test daemon's raw.o substitutes these syscalls. Product unchanged. */
#define _DEFAULT_SOURCE 1
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
int d2k_test_setsockopt(int fd,int level,int option,const void *p,socklen_t len) {
    const char *mode=getenv("D2K_TEST_FAULT");
    if(mode && !strcmp(mode,"setupfail") && level==IPPROTO_IP && option==IP_NODEFRAG) {
        errno=ENOPROTOOPT;return -1;
    }
    return setsockopt(fd,level,option,p,len);
}
ssize_t d2k_test_sendto(int fd,const void *p,size_t len,int flags,const struct sockaddr *to,socklen_t n) {
    static unsigned fragments;
    const char *mode=getenv("D2K_TEST_FAULT");const unsigned char *b=p;
    if(mode && !strcmp(mode,"partial") && len>=20 && ((b[6]&0x3f) || b[7]) && ++fragments==2) {
        errno=EIO;return -1;
    }
    return sendto(fd,p,len,flags,to,n);
}
