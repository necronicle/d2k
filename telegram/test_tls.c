#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "tg_tls.h"
#include "tg_session.h"
#include "tg_ws.h"
#include "tg_identity.h"
#include "tg_register.h"
#include "tg_tunnel.h"
#include "tg_wire.h"

#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct { int listener; const char *cert; const char *key; char sni[128]; int status; } server_args;

typedef struct { uint8_t data[16]; size_t len; int received; size_t big; } pump_capture;
static int capture_message(void *ctx,const uint8_t *data,size_t len) {
    pump_capture *c=ctx;
    if(len>sizeof(c->data)){c->big=len;for(size_t i=0;i<len;i++)if(data[i]!=(uint8_t)i)return -1;return 0;}
    memcpy(c->data,data,len);c->len=len;c->received=1;return 0;
}

typedef struct {
    int listener;
    const char *cert;
    const char *key;
    uint16_t echo_port;
    int status;
    atomic_int close_seen;
} tunnel_server_args;

typedef struct { int listener; } echo_server_args;
typedef struct { uint8_t ip[4]; uint16_t port; } original_dst_args;
typedef struct { tg_tunnel_config *cfg; int result; } tunnel_runner;

static void *run_tunnel_thread(void *opaque) {
    tunnel_runner *runner=opaque;runner->result=tg_tunnel_run(runner->cfg);return NULL;
}

static int ssl_read_exact(SSL *ssl,uint8_t *buf,size_t len);
static int ssl_write_exact(SSL *ssl,const uint8_t *buf,size_t len);

static int ws_read_client_mux(SSL *ssl, uint8_t *dst, size_t cap, size_t *len) {
    uint8_t h[10], mask[4]; size_t header=2; uint64_t payload_len;
    if(ssl_read_exact(ssl,h,2)!=0 || h[0]!=0x82 || !(h[1]&0x80))return -1;
    uint8_t short_len=(uint8_t)(h[1]&0x7f);
    if(short_len<126)payload_len=short_len;
    else if(short_len==126){if(ssl_read_exact(ssl,h+2,2)!=0)return -1;payload_len=((uint64_t)h[2]<<8)|h[3];header=4;if(payload_len<126)return -1;}
    else {if(ssl_read_exact(ssl,h+2,8)!=0 || (h[2]&0x80))return -1;payload_len=0;for(size_t i=0;i<8;i++)payload_len=(payload_len<<8)|h[2+i];header=10;if(payload_len<=UINT16_MAX)return -1;}
    if(payload_len>cap || payload_len>SIZE_MAX || ssl_read_exact(ssl,mask,4)!=0 || ssl_read_exact(ssl,dst,(size_t)payload_len)!=0)return -1;
    for(size_t i=0;i<(size_t)payload_len;i++)dst[i]^=mask[i&3];
    *len=(size_t)payload_len;(void)header;return 0;
}

static int ws_write_server_mux(SSL *ssl,uint16_t id,uint8_t type,const uint8_t *payload,size_t payload_len) {
    uint8_t mux[8192], frame[8202];
    size_t mux_len=tg_mux_encode(mux,sizeof(mux),id,type,payload,payload_len);
    if(!mux_len || mux_len > sizeof mux)return -1;
    frame[0]=0x82;size_t head;
    if(mux_len<126){frame[1]=(uint8_t)mux_len;head=2;}
    else if(mux_len<=UINT16_MAX){frame[1]=126;frame[2]=(uint8_t)(mux_len>>8);frame[3]=(uint8_t)mux_len;head=4;}
    else {frame[1]=127;for(size_t i=0;i<8;i++)frame[2+i]=(uint8_t)((uint64_t)mux_len>>(56-8*i));head=10;}
    memcpy(frame+head,mux,mux_len);return ssl_write_exact(ssl,frame,head+mux_len);
}

static int resolve_test_dst(int fd,uint8_t ipv4[4],uint16_t *port,void *opaque) {
    original_dst_args *a=opaque;(void)fd;memcpy(ipv4,a->ip,4);*port=a->port;return 0;
}

static void *serve_echo(void *opaque) {
    echo_server_args *a=opaque;int fd=accept(a->listener,NULL,NULL);assert(fd>=0);
    uint8_t buf[256];ssize_t n=recv(fd,buf,sizeof(buf),0);assert(n>0);
    size_t off=0;while(off<(size_t)n){ssize_t w=send(fd,buf+off,(size_t)n-off,0);assert(w>0);off+=(size_t)w;}
    shutdown(fd,SHUT_WR);close(fd);return NULL;
}

static void *serve_fake_tunnel(void *opaque) {
    tunnel_server_args *a=opaque;SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());
    int fd=accept(a->listener,NULL,NULL);assert(ctx&&fd>=0);
    assert(SSL_CTX_use_certificate_file(ctx,a->cert,SSL_FILETYPE_PEM)==1);
    assert(SSL_CTX_use_PrivateKey_file(ctx,a->key,SSL_FILETYPE_PEM)==1);
    struct timeval tv={.tv_sec=5};assert(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv))==0);
    SSL *ssl=SSL_new(ctx);assert(ssl&&SSL_set_fd(ssl,fd)==1&&SSL_accept(ssl)==1);
    char req[2048];size_t used=0;
    while(used<sizeof(req)-1&&(used<4||memcmp(req+used-4,"\r\n\r\n",4))){assert(ssl_read_exact(ssl,(uint8_t *)req+used,1)==0);used++;}
    req[used]='\0';char *keyline=strstr(req,"Sec-WebSocket-Key: ");assert(keyline);keyline+=strlen("Sec-WebSocket-Key: ");
    char input[128];snprintf(input,sizeof(input),"%.24s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",keyline);
    uint8_t digest[SHA_DIGEST_LENGTH];unsigned int digest_len=0;assert(EVP_Digest(input,strlen(input),digest,&digest_len,EVP_sha1(),NULL)==1);
    char accept[64];int alen=EVP_EncodeBlock((unsigned char *)accept,digest,(int)digest_len);accept[alen]='\0';
    char response[256];int rlen=snprintf(response,sizeof(response),"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",accept);
    assert(rlen>0&&ssl_write_exact(ssl,(uint8_t *)response,(size_t)rlen)==0);
    uint8_t raw[8192];size_t raw_len=0;tg_frame f;
    assert(ws_read_client_mux(ssl,raw,sizeof(raw),&raw_len)==0&&tg_mux_decode(raw,raw_len,&f)==0);
    assert(f.type==1&&f.payload_len==7&&f.payload[0]==1&&memcmp(f.payload+1,"\xcb\0\x71\x07",4)==0);
    assert((uint16_t)((f.payload[5]<<8)|f.payload[6])==a->echo_port);
    uint16_t sid=f.stream_id;uint8_t credit[4]={0,1,0,0};assert(ws_write_server_mux(ssl,sid,4,credit,sizeof(credit))==0);
    assert(ws_read_client_mux(ssl,raw,sizeof(raw),&raw_len)==0&&tg_mux_decode(raw,raw_len,&f)==0&&f.stream_id==sid&&f.type==2);
    int echo=socket(AF_INET,SOCK_STREAM,0);assert(echo>=0);
    struct sockaddr_in target={.sin_family=AF_INET,.sin_port=htons(a->echo_port)};target.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    assert(connect(echo,(struct sockaddr *)&target,sizeof(target))==0);
    assert(send(echo,f.payload,f.payload_len,0)==(ssize_t)f.payload_len);
    uint8_t echoed[512];ssize_t n=recv(echo,echoed,sizeof(echoed),0);assert(n==(ssize_t)f.payload_len);
    assert(ws_write_server_mux(ssl,sid,2,echoed,(size_t)n)==0);
    assert(ws_read_client_mux(ssl,raw,sizeof(raw),&raw_len)==0&&tg_mux_decode(raw,raw_len,&f)==0&&f.stream_id==sid&&f.type==3);
    close(echo);assert(ws_write_server_mux(ssl,sid,3,NULL,0)==0);atomic_store(&a->close_seen,1);
    (void)ws_read_client_mux(ssl,raw,sizeof(raw),&raw_len);
    SSL_free(ssl);close(fd);SSL_CTX_free(ctx);return NULL;
}

static void *serve_one(void *opaque) {
    server_args *a = opaque;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    int fd = accept(a->listener, NULL, NULL);
    assert(ctx && fd >= 0);
    assert(SSL_CTX_use_certificate_file(ctx, a->cert, SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_use_PrivateKey_file(ctx, a->key, SSL_FILETYPE_PEM) == 1);
    SSL *ssl = SSL_new(ctx);
    assert(ssl && SSL_set_fd(ssl, fd) == 1);
    if (SSL_accept(ssl) == 1) {
        const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (name) snprintf(a->sni, sizeof(a->sni), "%s", name);
    }
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return NULL;
}

static int ssl_read_exact(SSL *ssl, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_read(ssl, buf + off, (int)(len - off));
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int ssl_write_exact(SSL *ssl, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, buf + off, (int)(len - off));
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static void *serve_ws(void *opaque) {
    server_args *a = opaque;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    int fd = accept(a->listener, NULL, NULL);
    assert(ctx && fd >= 0);
    assert(SSL_CTX_use_certificate_file(ctx, a->cert, SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_use_PrivateKey_file(ctx, a->key, SSL_FILETYPE_PEM) == 1);
    SSL *ssl = SSL_new(ctx);
    assert(ssl && SSL_set_fd(ssl, fd) == 1 && SSL_accept(ssl) == 1);
    char req[8192]; size_t used = 0;
    while (used < sizeof(req)-1 && (used < 4 || memcmp(req + used - 4, "\r\n\r\n", 4))) {
        assert(ssl_read_exact(ssl, (uint8_t *)req + used, 1) == 0);
        ++used;
    }
    req[used] = '\0';
    char *keyline = strstr(req, "Sec-WebSocket-Key: ");
    assert(keyline != NULL);
    keyline += strlen("Sec-WebSocket-Key: ");
    char client_key[25]; memcpy(client_key, keyline, 24); client_key[24] = '\0';
    char input[128]; snprintf(input, sizeof(input), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);
    uint8_t digest[SHA_DIGEST_LENGTH]; unsigned int digest_len = 0;
    assert(EVP_Digest(input, strlen(input), digest, &digest_len, EVP_sha1(), NULL) == 1);
    char accept[64]; int accept_len = EVP_EncodeBlock((unsigned char *)accept, digest, (int)digest_len);
    accept[accept_len] = '\0';
    char response[512];
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept);
    assert(response_len > 0 && ssl_write_exact(ssl, (uint8_t *)response, (size_t)response_len) == 0);
    /* Optional INFO text can fill the maximum WebSocket message. */
    const uint8_t ping_auth[] = {0x89,1,'a'};
    assert(ssl_write_exact(ssl,ping_auth,sizeof(ping_auth))==0);
    uint8_t pong[7];
    assert(ssl_read_exact(ssl,pong,sizeof(pong))==0);
    assert(pong[0]==0x8a && pong[1]==0x81 && (pong[6]^pong[2])=='a');
    uint8_t header[10]={0x82,127};
    for(size_t i=0;i<8;i++) header[2+i]=(uint8_t)((uint64_t)TG_WS_MAX_MESSAGE>>(56-8*i));
    assert(ssl_write_exact(ssl,header,sizeof(header))==0);
    const uint8_t info[]={0,0,TG_MUX_INFO,TG_INFO_AUTH_OK,0,0,0,0};
    assert(ssl_write_exact(ssl,info,sizeof(info))==0);
    uint8_t padding[4096]={0};
    for(size_t remaining=TG_WS_MAX_MESSAGE-sizeof(info);remaining;) {
        size_t chunk=remaining<sizeof(padding)?remaining:sizeof(padding);
        assert(ssl_write_exact(ssl,padding,chunk)==0);
        remaining-=chunk;
    }
    uint8_t frame[128];
    assert(ssl_read_exact(ssl, frame, 2) == 0);
    assert(frame[0] == 0x82 && (frame[1] & 0x80) && (frame[1] & 0x7f) == 5);
    assert(ssl_read_exact(ssl, frame + 2, 9) == 0);
    for (size_t i=0; i<5; ++i) assert((uint8_t)(frame[6+i] ^ frame[2+i%4]) == "hello"[i]);
    const uint8_t ping[] = {0x89,0x01,'p'};
    assert(ssl_write_exact(ssl, ping, sizeof(ping)) == 0);
    assert(ssl_read_exact(ssl, frame, 7) == 0);
    assert(frame[0] == 0x8a && frame[1] == 0x81 && frame[6] == ('p' ^ frame[2]));
    /* Большой кадр: буфер приёма клиента растёт под него и после разбора
       отдаёт память обратно. */
    size_t big_len = 300000;
    uint8_t *big = malloc(10 + big_len); assert(big);
    big[0]=0x82; big[1]=127;
    for (int i=0;i<8;i++) big[2+i]=(uint8_t)((uint64_t)big_len >> (56-8*i));
    for (size_t i=0;i<big_len;i++) big[10+i]=(uint8_t)i;
    assert(ssl_write_exact(ssl, big, 10 + big_len) == 0);
    free(big);
    const uint8_t binary[] = {0x82,0x02,'o','k'};
    assert(ssl_write_exact(ssl, binary, sizeof(binary)) == 0);
    const uint8_t close_frame[] = {0x88,0x00};
    assert(ssl_write_exact(ssl, close_frame, sizeof(close_frame)) == 0);
    SSL_free(ssl); close(fd); SSL_CTX_free(ctx);
    return NULL;
}

static void *serve_register(void *opaque) {
    server_args *a=opaque;
    SSL_CTX *ctx=SSL_CTX_new(TLS_server_method()); int fd=accept(a->listener,NULL,NULL);
    assert(ctx && fd>=0 && SSL_CTX_use_certificate_file(ctx,a->cert,SSL_FILETYPE_PEM)==1);
    assert(SSL_CTX_use_PrivateKey_file(ctx,a->key,SSL_FILETYPE_PEM)==1);
    SSL *ssl=SSL_new(ctx); assert(ssl && SSL_set_fd(ssl,fd)==1 && SSL_accept(ssl)==1);
    char req[8192]; size_t used=0;
    while(used<sizeof(req)-1 && (used<4 || memcmp(req+used-4,"\r\n\r\n",4))) {
        assert(ssl_read_exact(ssl,(uint8_t *)req+used,1)==0); ++used;
    }
    req[used]='\0';
    char *length_line=strstr(req,"Content-Length: "); assert(length_line);
    size_t body_len=(size_t)strtoul(length_line+15,NULL,10);
    assert(body_len<sizeof(req)-used);
    assert(ssl_read_exact(ssl,(uint8_t *)req+used,body_len)==0);
    req[used+body_len]='\0';
    assert(strncmp(req,"POST /register HTTP/1.1\r\n",strlen("POST /register HTTP/1.1\r\n"))==0);
    assert(strstr(req,"Content-Type: application/json\r\n"));
    assert(strstr(req,"\"install_id\":\"") && strstr(req,"\",\"pubkey\":\""));
    char *auth=strstr(req,"X-Z2K-Auth: "); assert(auth);
    auth+=strlen("X-Z2K-Auth: "); char expected[65];
    assert(tg_register_hmac_hex("unit-secret",req+used,body_len,expected)==0);
    assert(strncmp(auth,expected,64)==0);
    char response[128]; int n=snprintf(response,sizeof(response),
        "HTTP/1.1 %d Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",a->status);
    assert(n>0 && ssl_write_exact(ssl,(uint8_t *)response,(size_t)n)==0);
    SSL_free(ssl); close(fd); SSL_CTX_free(ctx); return NULL;
}

static EVP_PKEY *make_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    assert(ctx && EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1);
    assert(EVP_PKEY_keygen(ctx, &key) == 1);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static X509 *make_cert(EVP_PKEY *key) {
    X509 *cert = X509_new();
    X509_NAME *name;
    X509_EXTENSION *ext;
    assert(cert && X509_set_version(cert, 2) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(cert), -60) != NULL);
    assert(X509_gmtime_adj(X509_getm_notAfter(cert), 3600) != NULL);
    assert(X509_set_pubkey(cert, key) == 1);
    name = X509_get_subject_name(cert);
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                      (const unsigned char *)"relay.test", -1, -1, 0) == 1);
    assert(X509_set_issuer_name(cert, name) == 1);
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    assert(ext && X509_add_ext(cert, ext, -1) == 1); X509_EXTENSION_free(ext);
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
                              "DNS:relay.test,IP:127.0.0.1");
    assert(ext && X509_add_ext(cert, ext, -1) == 1); X509_EXTENSION_free(ext);
    assert(X509_sign(cert, key, EVP_sha256()) > 0);
    return cert;
}

static int listen_loopback(void) {
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=0};
    socklen_t len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(fd, 1) == 0);
    assert(getsockname(fd, (struct sockaddr *)&addr, &len) == 0);
    return fd;
}

static int connect_loopback(int listener) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0 && getsockname(listener, (struct sockaddr *)&addr, &len) == 0);
    assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    return fd;
}

static void test_sni_and_certificate_validation(void) {
    char dir[] = "/tmp/d2k-tg-tls-XXXXXX", cert_path[256], key_path[256];
    EVP_PKEY *key;
    X509 *cert;
    SSL_CTX *client_ctx;
    SSL *ssl;
    pthread_t thread;
    server_args args = {0};
    assert(mkdtemp(dir) != NULL);
    snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", dir);
    snprintf(key_path, sizeof(key_path), "%s/key.pem", dir);
    key = make_key(); cert = make_cert(key);
    FILE *f = fopen(cert_path, "w"); assert(f && PEM_write_X509(f, cert) == 1); fclose(f);
    f = fopen(key_path, "w"); assert(f && PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) == 1); fclose(f);
    X509_free(cert); EVP_PKEY_free(key);
    args.cert = cert_path; args.key = key_path;

    args.listener = listen_loopback();
    assert(pthread_create(&thread, NULL, serve_one, &args) == 0);
    client_ctx = tg_tls_client_context(cert_path);
    assert(client_ctx != NULL);
    ssl = tg_tls_connect_fd(client_ctx, connect_loopback(args.listener), "relay.test");
    assert(ssl != NULL);
    SSL_free(ssl); SSL_CTX_free(client_ctx);
    pthread_join(thread, NULL); close(args.listener);
    assert(strcmp(args.sni, "relay.test") == 0);

    args.listener = listen_loopback(); args.sni[0] = '\0';
    assert(pthread_create(&thread, NULL, serve_one, &args) == 0);
    client_ctx = tg_tls_client_context(cert_path); assert(client_ctx);
    ssl = tg_tls_connect_fd_sni(client_ctx, connect_loopback(args.listener), "relay.test", "example.com");
    assert(ssl != NULL);
    SSL_free(ssl); SSL_CTX_free(client_ctx);
    pthread_join(thread, NULL); close(args.listener);
    assert(strcmp(args.sni, "example.com") == 0);

    args.listener = listen_loopback();
    assert(pthread_create(&thread, NULL, serve_one, &args) == 0);
    client_ctx = tg_tls_client_context(cert_path); assert(client_ctx);
    ssl = tg_tls_connect_fd_sni(client_ctx, connect_loopback(args.listener), "wrong.test", "relay.test");
    assert(ssl == NULL); /* A valid SNI certificate must not authenticate the wrong target. */
    SSL_CTX_free(client_ctx);
    pthread_join(thread, NULL); close(args.listener);

    args.listener = listen_loopback(); args.sni[0] = '\0';
    assert(pthread_create(&thread, NULL, serve_one, &args) == 0);
    client_ctx = tg_tls_client_context(cert_path);
    assert(client_ctx != NULL);
    ssl = tg_tls_connect_fd(client_ctx, connect_loopback(args.listener), "wrong.test");
    assert(ssl == NULL);
    SSL_CTX_free(client_ctx);
    pthread_join(thread, NULL); close(args.listener);
    unlink(key_path); unlink(cert_path); rmdir(dir);
}

static void test_shipped_relay_trust_bundle_loads(void) {
    SSL_CTX *ctx=tg_tls_client_context("../files/tg-roots.pem");
    assert(ctx!=NULL);SSL_CTX_free(ctx);
}

static void test_websocket_upgrade_binary_and_ping(void) {
    char dir[] = "/tmp/d2k-tg-ws-XXXXXX", cert_path[256], key_path[256];
    EVP_PKEY *key; X509 *cert; SSL_CTX *client_ctx; SSL *ssl;
    pthread_t thread; server_args args = {0};
    tg_ws_pump pump; pump_capture capture={0};
    assert(mkdtemp(dir) != NULL);
    snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", dir);
    snprintf(key_path, sizeof(key_path), "%s/key.pem", dir);
    key=make_key(); cert=make_cert(key);
    FILE *f=fopen(cert_path,"w"); assert(f && PEM_write_X509(f,cert)==1); fclose(f);
    f=fopen(key_path,"w"); assert(f && PEM_write_PrivateKey(f,key,NULL,NULL,0,NULL,NULL)==1); fclose(f);
    X509_free(cert); EVP_PKEY_free(key);
    args.cert=cert_path; args.key=key_path; args.listener=listen_loopback();
    assert(pthread_create(&thread,NULL,serve_ws,&args)==0);
    client_ctx=tg_tls_client_context(cert_path); assert(client_ctx);
    ssl=tg_tls_connect_fd(client_ctx,connect_loopback(args.listener),"relay.test"); assert(ssl);
    assert(tg_ws_upgrade(ssl,"relay.test:443","/ws")==0);
    uint8_t prefix[TG_MUX_HEADER_LEN+TG_INFO_FIXED_LEN]; size_t message_len;
    assert(tg_ws_read_binary_prefix(ssl,prefix,sizeof(prefix),&message_len)==0);
    assert(message_len==TG_WS_MAX_MESSAGE && prefix[2]==TG_MUX_INFO && prefix[3]==TG_INFO_AUTH_OK);
    assert(tg_ws_pump_init(&pump,ssl)==0);
    /* Буфер приёма не занимает предел сообщения заранее. */
    assert(pump.rx_cap==TG_WS_RX_BASE);
    assert(tg_ws_pump_queue_binary(&pump,(const uint8_t *)"hello",5)==0);
    for(unsigned i=0;i<100&&!capture.received;i++) {
        struct pollfd pfd={.fd=tg_ws_pump_fd(&pump),.events=tg_ws_pump_events(&pump)};
        int rc=poll(&pfd,1,200); assert(rc>=0);
        assert(tg_ws_pump_process(&pump,pfd.revents,capture_message,&capture)==0);
    }
    assert(capture.received && capture.len==2 && memcmp(capture.data,"ok",2)==0);
    assert(capture.big==300000);
    /* Кадр разобран — память буфера отдана, остался исходный малый буфер. */
    assert(pump.rx_len==0 && pump.rx_cap==TG_WS_RX_BASE);
    assert(pump.tx_bytes==0 && pump.tx_memory_bytes==0 && pump.tx_head==NULL);
    tg_ws_pump_destroy(&pump);
    SSL_free(ssl); SSL_CTX_free(client_ctx); pthread_join(thread,NULL); close(args.listener);
    unlink(key_path); unlink(cert_path); rmdir(dir);
}

static void test_websocket_tiny_frames_charge_allocations(void) {
    tg_ws_pump pump={0};size_t accepted=0;
    while(accepted<150000 && tg_ws_pump_queue_binary(&pump,NULL,0)==0){
        accepted++;assert(pump.tx_memory_bytes<=4u*1024u*1024u);
    }
    assert(accepted>0 && accepted<150000);
    assert(pump.tx_bytes<4u*1024u*1024u);
    size_t memory=pump.tx_memory_bytes;
    assert(tg_ws_pump_queue_binary(&pump,NULL,0)!=0 && pump.tx_memory_bytes==memory);
    tg_ws_pump_destroy(&pump);
    assert(pump.tx_memory_bytes==0 && pump.tx_bytes==0);
    assert(tg_ws_pump_queue_binary(&pump,(const uint8_t *)"x",1)==0);
    tg_ws_pump_destroy(&pump);
}

static void test_websocket_partial_write_retains_memory_budget(void) {
    int sockets[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,sockets)==0);
    for(size_t i=0;i<2;i++){
        int flags=fcntl(sockets[i],F_GETFL,0);assert(flags>=0);
        assert(fcntl(sockets[i],F_SETFL,flags|O_NONBLOCK)==0);
    }
    int sendbuf=65536;assert(setsockopt(sockets[0],SOL_SOCKET,SO_SNDBUF,&sendbuf,sizeof(sendbuf))==0);
    SSL_CTX *server_ctx=SSL_CTX_new(TLS_server_method()),*client_ctx=SSL_CTX_new(TLS_client_method());
    EVP_PKEY *key=make_key();X509 *cert=make_cert(key);assert(server_ctx && client_ctx);
    assert(SSL_CTX_use_certificate(server_ctx,cert)==1 && SSL_CTX_use_PrivateKey(server_ctx,key)==1);
    X509_free(cert);EVP_PKEY_free(key);
    SSL *client=SSL_new(client_ctx),*server=SSL_new(server_ctx);assert(client && server);
    assert(SSL_set_fd(client,sockets[0])==1 && SSL_set_fd(server,sockets[1])==1);
    SSL_set_connect_state(client);SSL_set_accept_state(server);
    for(unsigned i=0;i<1000 && (!SSL_is_init_finished(client)||!SSL_is_init_finished(server));i++){
        SSL *peers[]={client,server};
        for(size_t j=0;j<2;j++)if(!SSL_is_init_finished(peers[j])){
            int rc=SSL_do_handshake(peers[j]);
            if(rc!=1){int error=SSL_get_error(peers[j],rc);assert(error==SSL_ERROR_WANT_READ||error==SSL_ERROR_WANT_WRITE);}
        }
    }
    assert(SSL_is_init_finished(client) && SSL_is_init_finished(server));
    SSL_set_mode(client,SSL_MODE_ENABLE_PARTIAL_WRITE);
    tg_ws_pump pump;assert(tg_ws_pump_init(&pump,client)==0);
    uint8_t *payload=malloc(TG_WS_MAX_MESSAGE);assert(payload);memset(payload,1,TG_WS_MAX_MESSAGE);
    assert(tg_ws_pump_queue_binary(&pump,payload,TG_WS_MAX_MESSAGE)==0);
    size_t queued=pump.tx_bytes,memory=pump.tx_memory_bytes;
    assert(memory>queued && memory<=4u*1024u*1024u);
    assert(tg_ws_pump_process(&pump,POLLOUT,NULL,NULL)==0);
    assert(pump.tx_bytes>0 && pump.tx_bytes<queued);
    assert(pump.tx_memory_bytes==memory);
    assert(tg_ws_pump_queue_binary(&pump,payload,TG_WS_MAX_MESSAGE)!=0);
    assert(pump.tx_memory_bytes==memory);
    uint8_t *wire=malloc(queued);assert(wire);size_t received=0;
    for(unsigned i=0;i<1000 && (pump.tx_bytes||received<queued);i++){
        assert(tg_ws_pump_process(&pump,POLLOUT,NULL,NULL)==0);
        while(received<queued){
            size_t n=0;int rc=SSL_read_ex(server,wire+received,queued-received,&n);
            if(rc!=1){int error=SSL_get_error(server,rc);assert(error==SSL_ERROR_WANT_READ||error==SSL_ERROR_WANT_WRITE);break;}
            assert(n>0);received+=n;
        }
    }
    assert(received==queued && pump.tx_bytes==0 && pump.tx_memory_bytes==0);
    uint8_t length[10]={0x82,0xff,0,0,0,0,0,0x20,0,0};
    assert(memcmp(wire,length,sizeof(length))==0);
    for(size_t i=0;i<TG_WS_MAX_MESSAGE;i++)assert((uint8_t)(wire[14+i]^wire[10+(i&3)])==1);
    assert(tg_ws_pump_queue_binary(&pump,payload,TG_WS_MAX_MESSAGE)==0);
    tg_ws_pump_destroy(&pump);free(payload);free(wire);
    SSL_free(client);SSL_free(server);SSL_CTX_free(client_ctx);SSL_CTX_free(server_ctx);
    close(sockets[0]);close(sockets[1]);
}

static void test_register_post_and_conflict(void) {
    char dir[]="/tmp/d2k-tg-reg-XXXXXX", cert_path[256], key_path[256], id_path[256];
    EVP_PKEY *key; X509 *cert; tg_identity id;
    pthread_t thread; server_args args={0}; struct sockaddr_in addr; socklen_t alen=sizeof(addr);
    assert(mkdtemp(dir)); snprintf(cert_path,sizeof(cert_path),"%s/cert.pem",dir);
    snprintf(key_path,sizeof(key_path),"%s/key.pem",dir); snprintf(id_path,sizeof(id_path),"%s/id",dir);
    key=make_key(); cert=make_cert(key);
    FILE *f=fopen(cert_path,"w"); assert(f && PEM_write_X509(f,cert)==1); fclose(f);
    f=fopen(key_path,"w"); assert(f && PEM_write_PrivateKey(f,key,NULL,NULL,0,NULL,NULL)==1); fclose(f);
    X509_free(cert); EVP_PKEY_free(key); assert(tg_identity_load_or_mint(id_path,&id)==0);
    args.cert=cert_path; args.key=key_path; args.listener=listen_loopback(); args.status=200;
    assert(getsockname(args.listener,(struct sockaddr *)&addr,&alen)==0);
    assert(pthread_create(&thread,NULL,serve_register,&args)==0);
    assert(tg_register_identity("relay.test",ntohs(addr.sin_port),"127.0.0.1",cert_path,
                                "unit-secret",&id)==0);
    pthread_join(thread,NULL); close(args.listener);
    args.listener=listen_loopback(); args.status=409; alen=sizeof(addr);
    assert(getsockname(args.listener,(struct sockaddr *)&addr,&alen)==0);
    assert(pthread_create(&thread,NULL,serve_register,&args)==0);
    assert(tg_register_identity("relay.test",ntohs(addr.sin_port),"127.0.0.1",cert_path,
                                "unit-secret",&id)==TG_REGISTER_ID_CONFLICT);
    pthread_join(thread,NULL); close(args.listener); tg_identity_cleanup(&id);
    unlink(id_path); unlink(key_path); unlink(cert_path); rmdir(dir);
}

static void test_tunnel_local_echo_through_fake_relay(void) {
    char dir[]="/tmp/d2k-tg-tunnel-XXXXXX",cert_path[256],key_path[256];
    assert(mkdtemp(dir));snprintf(cert_path,sizeof(cert_path),"%s/cert.pem",dir);snprintf(key_path,sizeof(key_path),"%s/key.pem",dir);
    EVP_PKEY *key=make_key();X509 *cert=make_cert(key);
    FILE *f=fopen(cert_path,"w");assert(f&&PEM_write_X509(f,cert)==1);fclose(f);
    f=fopen(key_path,"w");assert(f&&PEM_write_PrivateKey(f,key,NULL,NULL,0,NULL,NULL)==1);fclose(f);
    X509_free(cert);EVP_PKEY_free(key);
    SSL_CTX *client_ctx=tg_tls_client_context(cert_path);assert(client_ctx);

    echo_server_args echo={.listener=listen_loopback()};struct sockaddr_in echo_addr;socklen_t echo_len=sizeof(echo_addr);
    assert(getsockname(echo.listener,(struct sockaddr *)&echo_addr,&echo_len)==0);
    pthread_t echo_thread;assert(pthread_create(&echo_thread,NULL,serve_echo,&echo)==0);

    tunnel_server_args relay={.listener=listen_loopback(),.cert=cert_path,.key=key_path,.echo_port=ntohs(echo_addr.sin_port)};
    atomic_init(&relay.close_seen,0);
    struct sockaddr_in relay_addr;socklen_t relay_len=sizeof(relay_addr);assert(getsockname(relay.listener,(struct sockaddr *)&relay_addr,&relay_len)==0);
    pthread_t relay_thread;assert(pthread_create(&relay_thread,NULL,serve_fake_tunnel,&relay)==0);
    SSL *ssl=tg_tls_connect_fd(client_ctx,connect_loopback(relay.listener),"relay.test");assert(ssl);
    char host[64];snprintf(host,sizeof(host),"relay.test:%u",ntohs(relay_addr.sin_port));
    assert(tg_ws_upgrade(ssl,host,"/ws")==0);

    int local_listener=listen_loopback();struct sockaddr_in local_addr;socklen_t local_len=sizeof(local_addr);
    assert(getsockname(local_listener,(struct sockaddr *)&local_addr,&local_len)==0);
    int flags=fcntl(local_listener,F_GETFL,0);assert(flags>=0&&fcntl(local_listener,F_SETFL,flags|O_NONBLOCK)==0);
    volatile sig_atomic_t stop=0;original_dst_args original={{203,0,113,7},ntohs(echo_addr.sin_port)};
    tg_tunnel_config tunnel={.relay_ssl=ssl,.listener_fd=local_listener,.listen_port=ntohs(local_addr.sin_port),
        .protocol_v2=1,.window=65536,.stop=&stop,.resolve_dst=resolve_test_dst,.resolve_dst_ctx=&original};
    tunnel_runner runner={.cfg=&tunnel};
    pthread_t tunnel_thread;assert(pthread_create(&tunnel_thread,NULL,run_tunnel_thread,&runner)==0);
    int client=connect_loopback(local_listener);assert(send(client,"telegram",8,0)==8);
    char answer[16];size_t answer_len=0;
    while(answer_len<8) {
        struct pollfd wait={.fd=client,.events=POLLIN};assert(poll(&wait,1,5000)>0);
        ssize_t n=recv(client,answer+answer_len,8-answer_len,0);assert(n>0);answer_len+=(size_t)n;
    }
    assert(memcmp(answer,"telegram",8)==0);
    close(client);
    for(unsigned i=0;i<500&&!atomic_load(&relay.close_seen);i++)(void)poll(NULL,0,10);
    assert(atomic_load(&relay.close_seen));stop=1;shutdown(local_listener,SHUT_RDWR);pthread_join(tunnel_thread,NULL);
    shutdown(SSL_get_fd(ssl),SHUT_RDWR);pthread_join(relay_thread,NULL);pthread_join(echo_thread,NULL);
    close(local_listener);close(echo.listener);close(relay.listener);SSL_free(ssl);SSL_CTX_free(client_ctx);
    assert(runner.result==0);
    unlink(key_path);unlink(cert_path);rmdir(dir);
}

int main(void) {
    test_websocket_partial_write_retains_memory_budget();
    test_websocket_tiny_frames_charge_allocations();
    test_sni_and_certificate_validation();
    test_shipped_relay_trust_bundle_loads();
    test_websocket_upgrade_binary_and_ping();
    test_register_post_and_conflict();
    test_tunnel_local_echo_through_fake_relay();
    puts("TLS verification tests: ok");
    return 0;
}
