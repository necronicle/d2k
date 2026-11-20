/* Exercise the public DoH socket path with transport stubs, no sockets. */
#define _POSIX_C_SOURCE 200809L
#define d2k_props_contact_on_family authority_contact
#include "verify.c"
#include <assert.h>
static char actual_authority[300],actual_target[1100],actual_sni[300];
static unsigned requests;
int authority_contact(int fd,const char *ip,uint16_t port,d2k_hello h,uint8_t family,
    uint8_t *local,uint16_t *local_port,int *out) {
    (void)fd;(void)ip;(void)port;(void)h;(void)family;(void)local;
    *local_port=32000;*out=-1;return 0;
}
static int authority_write(void *t,const uint8_t *bytes,size_t n,char *err,size_t cap) {
    (void)t;(void)err;(void)cap;
    if(n>=9 && bytes[3]==1) {
        size_t p=12,z;const uint8_t *value;int huff;
        assert(bytes[9]==0x82 && bytes[10]==0x87 && bytes[11]==1);
        assert(!dh2_string(bytes,n,&p,&value,&z,&huff) && !huff && z<sizeof actual_authority);
        memcpy(actual_authority,value,z);actual_authority[z]=0;
        assert(bytes[p++]==4);
        assert(!dh2_string(bytes,n,&p,&value,&z,&huff) && !huff && z<sizeof actual_target);
        memcpy(actual_target,value,z);actual_target[z]=0;requests++;
        return -1; /* Request captured: no response or durable success claimed. */
    }
    return 0;
}
static long authority_read(void *t,uint8_t *b,size_t n,int ms,char *e,size_t cap) {
    (void)t;(void)b;(void)n;(void)ms;(void)e;(void)cap;assert(0);return -1;
}
static d2k_doh_tls_status tls_result;
static uint16_t actual_version;
static unsigned sessions_released;
static void authority_release(void *context) {
    assert(context==&requests);
    sessions_released++;
}
static d2k_doh_tls_status authority_open(int fd,const char *host,uint16_t version,int timeout,
    d2k_doh_tls_session *session) {
    (void)fd;(void)timeout;
    actual_version=version;
    snprintf(actual_sni,sizeof actual_sni,"%s",host);
    if(tls_result!=D2K_DOH_TLS_OK)return tls_result;
    session->io=(d2k_tls_io){&requests,authority_read,authority_write};
    session->release=authority_release;
    session->http_version=2;
    session->tls_version=version;
    return D2K_DOH_TLS_OK;
}
int main(void) {
    d2k_verify_doh_set_tls(authority_open);
    const struct {const char *host,*ip,*want;uint16_t port;} cases[]={
        {"resolver.test","192.0.2.53","resolver.test",443},
        {"resolver.test","192.0.2.53","resolver.test:8443",8443},
        {"Resolver.TEST","192.0.2.53","resolver.test:8443",8443},
        {"2001:0DB8:0:0:0:0:0:53","2001:db8::53","[2001:db8::53]:8443",8443},
        {"192.0.2.53","192.0.2.53","192.0.2.53:65535",65535},
        {"2001:db8::53","2001:db8::53","[2001:db8::53]",443},
        {"2001:db8::53","2001:db8::53","[2001:db8::53]:8443",8443}
    };
    const char *path="/private/query?account=fixture";int fails=0;
    for(size_t i=0;i<sizeof cases/sizeof *cases;i++) {
        requests=0;actual_authority[0]=actual_target[0]=actual_sni[0]=0;
        d2k_ver_result r=d2k_verify_doh_on(-1,cases[i].ip,cases[i].port,cases[i].host,5,0,0,0,path);
        if(requests!=1 || strcmp(actual_authority,cases[i].want)) {
            fprintf(stderr,"authority case %zu: got '%s', expected '%s'\n",i,actual_authority,cases[i].want);fails++;
        }
        if(requests) {
            assert(!strcmp(actual_sni,cases[i].host));
            assert(!strncmp(actual_target,path,strlen(path)) && !strncmp(actual_target+strlen(path),"&dns=",5));
            if(i==0)
                assert(!strcmp(actual_target+strlen(path)+5,"AAABAAABAAAAAAAACHJlc29sdmVyBHRlc3QAAAEAAQ"));
            if(i==4)
                assert(!strcmp(actual_target+strlen(path)+5,"AAABAAABAAAAAAAAAjUzATIBMAMxOTIHaW4tYWRkcgRhcnBhAAAMAAE"));
        }
        assert(r.peer_authenticated && r.level!=D2K_VER_APPLICATION && r.budget!=D2K_BUDGET_PASSED);
    }
    /* A legal 253-byte name plus :65535 exceeds the old 255-byte host
       limit in the actual HTTP/2 request builder. */
    char long_host[254],long_authority[262];
    memset(long_host,'a',sizeof long_host-1);long_host[253]=0;
    long_host[63]=long_host[127]=long_host[191]='.';
    snprintf(long_authority,sizeof long_authority,"%s:65535",long_host);
    requests=0;actual_authority[0]=0;
    (void)d2k_verify_doh_on(-1,"192.0.2.53",65535,long_host,5,0,0,0,path);
    if(requests!=1 || strcmp(actual_authority,long_authority)) {
        fprintf(stderr,"long DNS authority was not emitted intact\n");fails++;
    }
    assert(!strcmp(actual_sni,long_host));
    assert(sessions_released==sizeof cases/sizeof *cases + 1);
    tls_result=D2K_DOH_TLS_AUTH;requests=0;
    d2k_ver_result r=d2k_verify_doh_on(-1,"192.0.2.53",443,"resolver.test",5,0,1,0,path);
    assert(actual_version==0x0303 && r.peer_auth_failed && !r.peer_authenticated &&
        !r.local_refusal && !requests && r.level==D2K_VER_TRANSPORT);
    tls_result=D2K_DOH_TLS_LOCAL;
    r=d2k_verify_doh_on(-1,"192.0.2.53",443,"resolver.test",5,0,0,0,path);
    assert(r.local_refusal && !r.peer_auth_failed && !requests);
    d2k_verify_doh_set_tls(NULL);
    r=d2k_verify_doh_on(-1,"192.0.2.53",443,"resolver.test",5,0,0,0,path);
    assert(r.unsupported && !r.peer_authenticated && !requests);
    if(fails)return 1;
    puts("DoH native request authority: default/custom ports, IPv4/IPv6, unchanged TLS identity and opaque resource PASS");return 0;
}
