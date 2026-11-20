/* The TLS boundary is simulated; HTTP parsing and the owned-stream adapter
 * are production code. This test makes no claim about real TLS on the wire. */
#define d2k_tls_connect_probe fixture_connect
#define d2k_tls_read fixture_read_tls
#define d2k_tls_write fixture_write_tls
#define d2k_tls_free fixture_free_tls
#define d2k_tls_peer_name fixture_peer_name
#define d2k_tls_version fixture_version
#define d2k_tls_rx_wire_bytes fixture_wire_bytes
#define d2k_tls_rx_record_missing fixture_record_missing
#include "quicconn.c"
#include "verify.c"
#include <assert.h>

static const char *response;
static size_t position;
static char request[8192];
static int connections,freed,fail_tls;
static const d2k_tls_io *expected_io;
static const d2k_tls_probe_seed *expected_seed;
static int token;
static unsigned observed_events;
static int reject_observation;
static int observe_https(void *ctx,const d2k_https_observation *event) {
    assert(ctx==&token && event->ordinal==1);
    observed_events++;
    assert(event->phase==(observed_events==1?D2K_HTTPS_REQUEST_BEGIN:
        observed_events==2?D2K_HTTPS_REQUEST_SENT:D2K_HTTPS_EXCHANGE_END));
    if(observed_events<3) {
        assert(event->request && event->request_length &&
            !memcmp(event->request,"GET /file HTTP/1.1",18));
        assert(position==0);
    } else assert(event->response && event->response->body_complete &&
        event->response->body_bytes==5);
    return reject_observation==(int)observed_events?-1:0;
}
int fixture_connect(const d2k_tls_io *io,const d2k_tls_probe_seed *seed,const char *host,
    int timeout,size_t wire,const uint8_t *alpn,size_t alpn_len,d2k_tls **out,char *err,size_t cap) {
    assert(io==expected_io && seed==expected_seed && !strcmp(host,"example.com"));
    assert(timeout==100 && wire==1200);
    assert(alpn_len==9 && !memcmp(alpn,"\10http/1.1",9));
    connections++;
    if(fail_tls){snprintf(err,cap,"fixture handshake failure");return -1;}
    *out=(d2k_tls *)&token;return 0;
}
long fixture_read_tls(d2k_tls *t,uint8_t *buf,size_t cap,int wait,char *err,size_t errcap) {
    (void)wait;(void)err;(void)errcap;assert(t==(d2k_tls *)&token);
    size_t left=strlen(response)-position;if(left>cap)left=cap;if(left>7)left=7;
    memcpy(buf,response+position,left);position+=left;return (long)left;
}
int fixture_write_tls(d2k_tls *t,const uint8_t *buf,size_t n,char *err,size_t cap) {
    (void)err;(void)cap;assert(t==(d2k_tls *)&token && n<sizeof request);
    memcpy(request,buf,n);request[n]=0;return 0;
}
void fixture_free_tls(d2k_tls *t){assert(t==(d2k_tls *)&token);freed++;}
int fixture_peer_name(const d2k_tls *t){(void)t;return 1;}
uint16_t fixture_version(const d2k_tls *t){(void)t;return 0x0304;}
uint64_t fixture_wire_bytes(const d2k_tls *t){(void)t;return 100+position;}
uint32_t fixture_record_missing(const d2k_tls *t){(void)t;return 0;}
static long unused_read(void *ctx,uint8_t *buf,size_t n,int wait,char *err,size_t cap) {
    (void)ctx;(void)buf;(void)n;(void)wait;(void)err;(void)cap;assert(0);return -1;
}
static int unused_write(void *ctx,const uint8_t *buf,size_t n,char *err,size_t cap) {
    (void)ctx;(void)buf;(void)n;(void)err;(void)cap;assert(0);return -1;
}
int main(void) {
    d2k_tls_io io={NULL,unused_read,unused_write};
    d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();assert(seed);
    expected_io=&io;expected_seed=seed;
    response="HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    d2k_ver_result r=d2k_verify_https_probe_io(&io,seed,"example.com","/file",100,1200,0);
    assert(r.level==D2K_VER_APPLICATION && r.status==200 && r.body_complete && r.body_bytes==5);
    assert(r.fd==-1 && r.name_ok==1 && r.negotiated_tls==0x0304);
    assert(r.rx_tls_wire_bytes==strlen(response) && connections==1 && freed==1);
    assert(strstr(request,"GET /file HTTP/1.1\r\n") && strstr(request,"Accept-Encoding: identity"));
    response="HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort";position=0;
    r=d2k_verify_https_probe_io(&io,seed,"example.com","/file",100,1200,1);
    assert(r.level==D2K_VER_HANDSHAKE && !r.body_complete && r.body_expected==50 && r.body_bytes==5);
    assert(strstr(request,"Accept-Encoding: gzip") && freed==2);
    response="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n";position=0;
    r=d2k_verify_https_probe_io(&io,seed,"example.com","/file",100,1200,0);
    assert(r.level==D2K_VER_APPLICATION && r.body_complete && r.body_bytes==2 && freed==3);
    fail_tls=1;
    r=d2k_verify_https_probe_io(&io,seed,"example.com","/file",100,1200,0);
    assert(r.level==D2K_VER_TRANSPORT && r.name_ok==-1 && !r.body_complete && freed==3);
    int before=connections;
    r=d2k_verify_https_probe_io(&io,NULL,"example.com","/file",100,1200,0);
    assert(r.local_refusal && connections==before);
    fail_tls=0;position=0;observed_events=0;
    response="HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    r=d2k_verify_https_observe_io(&io,seed,"example.com","/file",100,1200,0,observe_https,&token);
    assert(r.body_complete && observed_events==3);
    position=0;observed_events=0;reject_observation=1;request[0]=0;
    r=d2k_verify_https_observe_io(&io,seed,"example.com","/file",100,1200,0,observe_https,&token);
    assert(r.local_refusal && observed_events==1 && !request[0] && !position);
    for(reject_observation=2;reject_observation<=3;reject_observation++) {
        position=0;observed_events=0;request[0]=0;
        r=d2k_verify_https_observe_io(&io,seed,"example.com","/file",100,1200,0,observe_https,&token);
        assert(r.local_refusal && observed_events==(unsigned)reject_observation && request[0]);
        assert(reject_observation==2?!position:position==strlen(response));
    }
    reject_observation=0;observed_events=0;fail_tls=1;
    r=d2k_verify_https_observe_io(&io,seed,"example.com","/file",100,1200,0,observe_https,&token);
    assert(r.level==D2K_VER_TRANSPORT && !observed_events);
    before=connections;
    r=d2k_verify_https_probe_io(&io,seed,"example.com","/bad\r\npath",100,1200,0);
    assert(r.local_refusal && connections==before);
    r=d2k_verify_https_probe_io(&io,seed,"bad\r\nHost: evil","/file",100,1200,0);
    assert(r.local_refusal && connections==before);
    d2k_tls_probe_seed_free(seed);
    puts("owned HTTPS: complete/fractured/chunked HTTP, handshake failure, identity and input refusal pass");
    return 0;
}
