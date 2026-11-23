#define _POSIX_C_SOURCE 200809L
#define d2k_props_contact_on_family preflight_contact
#include "verify.c"
#include <assert.h>

static int http_kind,tls_status;
static uint16_t opened_version;
static unsigned opens,releases;
static uint8_t response[4096];static size_t response_len,response_pos;
int preflight_contact(int fd,const char *ip,uint16_t port,d2k_hello h,uint8_t family,
    uint8_t *local,uint16_t *local_port,int *out) {
    (void)fd;(void)ip;(void)port;(void)h;(void)family;(void)local;
    *local_port=41008;*out=-1;return 0;
}
static long fake_read(void *ctx,uint8_t *out,size_t cap,int wait,char *err,size_t errcap) {
    (void)ctx;(void)wait;(void)err;(void)errcap;
    if(response_pos==response_len)return 0;
    size_t n=response_len-response_pos;if(n>cap)n=cap;
    memcpy(out,response+response_pos,n);response_pos+=n;return (long)n;
}
static int fake_write(void *ctx,const uint8_t *bytes,size_t n,char *err,size_t errcap) {
    (void)ctx;(void)err;(void)errcap;
    if(http_kind==1) {
        assert(n>=16 && !memcmp(bytes,"GET / HTTP/1.1\r\n",16));
    } else if(n>12 && bytes[3]==1) {
        size_t p=12,z;const uint8_t *value;int huff;
        assert(bytes[9]==0x82 && bytes[10]==0x87 && bytes[11]==1);
        assert(!dh2_string(bytes,n,&p,&value,&z,&huff)&&!huff);
        assert(bytes[p++]==4);
        assert(!dh2_string(bytes,n,&p,&value,&z,&huff)&&!huff&&z==1&&value[0]=='/');
    }
    return 0;
}
static void fake_release(void *ctx){(void)ctx;releases++;}
static d2k_doh_tls_status fake_open(int fd,const char *host,uint16_t version,int timeout,
    d2k_doh_tls_session *session) {
    (void)fd;(void)host;(void)timeout;opens++;opened_version=version;
    if(tls_status!=D2K_DOH_TLS_OK)return tls_status;
    session->io=(d2k_tls_io){NULL,fake_read,fake_write};session->release=fake_release;
    session->http_version=http_kind;session->tls_version=version;return D2K_DOH_TLS_OK;
}
int main(void) {
    d2k_verify_doh_set_tls(fake_open);
    for(int shape=0;shape<2;shape++)for(http_kind=1;http_kind<=2;http_kind++) {
        const char text[]="HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        const uint8_t h2[]={0,0,1,1,5,0,0,0,1,0x88};
        if(http_kind==1) {memcpy(response,text,sizeof text-1);response_len=sizeof text-1;}
        else {memcpy(response,h2,sizeof h2);response_len=sizeof h2;}
        response_pos=0;tls_status=D2K_DOH_TLS_OK;
        d2k_ver_result r=d2k_verify_preflight_on(-1,"192.0.2.8",443,"video.example",1000,0,shape);
        assert((r.level==D2K_VER_APPLICATION && r.body_complete && r.body_bytes==3) ||
               (http_kind==2 && r.level==D2K_VER_APPLICATION && r.body_complete));
        assert(r.peer_authenticated && !r.peer_auth_failed && r.http_version==http_kind);
        assert(r.negotiated_tls==(shape?0x0303:0x0304) && opened_version==r.negotiated_tls);
        assert(r.local_port==41008 && r.family==4 && r.fd==-1);
    }
    {
        const char challenge[]="HTTP/1.1 403 Forbidden\r\nCf-Mitigated: challenge\r\n"
            "Content-Length: 3\r\n\r\nabc";
        memcpy(response,challenge,sizeof challenge-1);
        response_len=sizeof challenge-1;response_pos=0;http_kind=1;
        d2k_ver_result r=d2k_verify_preflight_on(-1,"192.0.2.8",443,
            "video.example",1000,0,0);
        assert(r.level==D2K_VER_CHALLENGE && r.cloudflare_challenge &&
            r.body_complete && r.peer_authenticated && r.name_ok==1 &&
            strstr(r.reason,"challenge")!=NULL);
        d2k_verify_page_set_tls(fake_open);
        response_pos=0;
        r=d2k_verify_family_page_on(-1,"192.0.2.8",443,"video.example",1000,0,0);
        assert(r.level==D2K_VER_CHALLENGE && r.body_complete &&
            r.peer_authenticated && r.http_version==1);
        d2k_verify_page_set_tls(NULL);
        r=d2k_verify_family_page_on(-1,"192.0.2.8",443,"video.example",1000,0,0);
        assert(r.unsupported && !r.peer_authenticated);
    }
    tls_status=D2K_DOH_TLS_AUTH;
    d2k_ver_result r=d2k_verify_preflight_on(-1,"192.0.2.8",443,"video.example",1000,0,1);
    assert(r.peer_auth_failed && !r.peer_authenticated && r.level==D2K_VER_TRANSPORT);
    d2k_verify_doh_set_tls(NULL);
    r=d2k_verify_preflight_on(-1,"192.0.2.8",443,"video.example",1000,0,0);
    assert(r.unsupported && !r.peer_authenticated && r.fd==-1);
    assert(opens==7 && releases==6);
    puts("authenticated preflight verifier: TLS12/13, HTTP1/2, auth failure and unsupported PASS");
    return 0;
}
