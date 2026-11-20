/* test_tls12_live.c — ЖИВОЕ рукопожатие TLS 1.2 без имени против настоящего
 * сервера (этап 15, 28.10.2026). Сервер — `openssl s_server` на петле со
 * свежим самоподписанным ключом (OpenSSL 3 из Homebrew, иначе системный
 * openssl/LibreSSL; путь можно задать D2K_OPENSSL). Проверяется зонд
 * d2k_verify_probe12_handshake_on:
 *   1. шесть AEAD-наборов TLS 1.2, X25519/P-256, в том числе форма Chrome;
 *      сервер только TLS 1.2 с нашим набором шифров — рукопожатие завершено,
 *      level HANDSHAKE, handshake_proof, negotiated 0x0303; HTTP не запрашивался;
 *   2. сервер только TLS 1.3 — отказ (alert protocol_version), не успех;
 *   3. сервер только с неподдержанным CBC — отказ (handshake_failure);
 *   4. закрытый порт — «нет TCP»;
 *   5. слушатель, закрывающий соединение сразу — отказ без рукопожатия.
 * Без openssl тест называет это ошибкой среды и выходит с кодом 3 (не «зелёный»). */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "d2k_verify.h"
#include "d2k_tls13.h"
#include "d2k_tls12.h"
#include "d2k_hello.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s\n", (m)); fails++; } } while (0)

static const char *openssl_bin(void) {
    const char *env = getenv("D2K_OPENSSL");
    if (env && env[0] && access(env, X_OK) == 0) return env;
    static const char *cands[] = { "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl", "/usr/bin/openssl", "/bin/openssl", NULL };
    for (int i = 0; cands[i]; i++) if (access(cands[i], X_OK) == 0) return cands[i];
    return NULL;
}
static uint16_t free_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof a;
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(fd, (struct sockaddr *)&a, &al) != 0) { if (fd >= 0) close(fd); return 0; }
    uint16_t p = ntohs(a.sin_port); close(fd); return p;
}
static int wait_listen(uint16_t port, int ms) {
    for (int i = 0; i < ms / 50; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(port);
        int ok = fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) == 0;
        if (fd >= 0) close(fd);
        if (ok) return 1;
        usleep(50000);
    }
    return 0;
}
static pid_t spawn(const char *bin, char *const argv[], const char *log) {
    pid_t pid = fork();
    if (pid == 0) {
        int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); }
        int nul = open("/dev/null", O_RDONLY); if (nul >= 0) dup2(nul, 0);
        execv(bin, argv); _exit(127);
    }
    return pid;
}
static void stop(pid_t pid) { if (pid > 0) { kill(pid, SIGTERM); waitpid(pid, NULL, 0); } }

static d2k_ver_result probe(uint16_t port) {
    return d2k_verify_probe12_handshake_on(-1, "127.0.0.1", port, "", 3000, 0);
}
typedef struct {int fd;unsigned reads,writes;uint64_t received;uint8_t first[2048];size_t first_length;} measured_io;
static long measured_read(void *ctx,uint8_t *buf,size_t cap,int wait,char *err,size_t ec) {
    measured_io *m=ctx;struct pollfd p={m->fd,POLLIN,0};
    if(poll(&p,1,wait)<=0){snprintf(err,ec,"measurement read timeout");return -1;}
    long n=recv(m->fd,buf,cap>7?7:cap,0);m->reads++;
    if(n>0)m->received+=(uint64_t)n;
    return n;
}
static int measured_write(void *ctx,const uint8_t *buf,size_t n,char *err,size_t ec) {
    measured_io *m=ctx;
    if(!m->writes && n<=sizeof m->first){memcpy(m->first,buf,n);m->first_length=n;}
    m->writes++;
    for(size_t at=0;at<n;) {
        size_t left=n-at;ssize_t sent=send(m->fd,buf+at,left>11?11:left,0);
        if(sent<=0){snprintf(err,ec,"measurement write failed");return -1;}
        at+=(size_t)sent;
    }
    return 0;
}
static void measured_exchange(uint16_t port,const d2k_tls_probe_seed *seed) {
    measured_io m={.fd=socket(AF_INET,SOCK_STREAM,0)};
    struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(port);
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(m.fd<0 || connect(m.fd,(struct sockaddr *)&a,sizeof a)) {
        CHECK(0,"measurement transport connect");if(m.fd>=0)close(m.fd);return;
    }
    d2k_tls_io io={&m,measured_read,measured_write};
    d2k_tls *tls=NULL;char err[256]={0};
    const uint8_t alpn[]={8,'h','t','t','p','/','1','.','1'};
    int rc=seed?d2k_tls_connect_probe(&io,seed,"localhost",3000,1200,alpn,sizeof alpn,&tls,err,sizeof err):
        d2k_tls_connect_io(&io,"localhost",3000,1200,alpn,sizeof alpn,&tls,err,sizeof err);
    CHECK(rc==0,err);
    if(rc==0) {
        CHECK(d2k_tls_version(tls)==0x0304,"measurement negotiated TLS1.3");
        memset(&io,0,sizeof io);
        const uint8_t req[]="GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        CHECK(d2k_tls_write(tls,req,sizeof req-1,err,sizeof err)==0,err);
        uint8_t response[4096];long n=d2k_tls_read(tls,response,sizeof response,3000,err,sizeof err);
        CHECK(n>=12 && !memcmp(response,"HTTP/1.0 200",12),"HTTP response over same measurement transport");
        CHECK(m.writes>=4 && m.reads>1,"handshake and app both use callbacks");
        CHECK(d2k_tls_rx_wire_bytes(tls)==m.received,"wire accounting includes callback reads");
    }
    d2k_tls_free(tls);
    CHECK(fcntl(m.fd,F_GETFD)>=0,"TLS does not close borrowed transport");close(m.fd);
}
static int observe_legacy(void *ctx,const d2k_https_observation *o) {
    unsigned *phases=ctx;
    CHECK(o->ordinal==1,"legacy observer retains request identity");
    *phases|=1u<<o->phase;
    if(o->phase==D2K_HTTPS_EXCHANGE_END)
        CHECK(o->response && o->response->status==200 && o->response->body_complete,
              "legacy observer carries complete HTTP response");
    else CHECK(o->request && o->request_length,"legacy observer carries submitted request");
    return 0;
}
static void measured_legacy_exchange(uint16_t port,unsigned seed_byte) {
    measured_io m={.fd=socket(AF_INET,SOCK_STREAM,0)};
    struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(port);
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(m.fd<0 || connect(m.fd,(struct sockaddr *)&a,sizeof a)) {
        CHECK(0,"legacy measurement connect");if(m.fd>=0)close(m.fd);return;
    }
    uint8_t random[32],hello[2048];memset(random,(int)seed_byte,sizeof random);
    size_t length=d2k_tls12_probe_hello(random,"localhost",1200,hello,sizeof hello);
    CHECK(length>0,"legacy measurement hello generated");
    d2k_tls_io io={&m,measured_read,measured_write};unsigned phases=0;
    d2k_ver_result r=d2k_verify_https12_observe_io(&io,random,"localhost","/",3000,1200,0,
                                                observe_legacy,&phases);
    CHECK(r.level==D2K_VER_APPLICATION && r.status==200 && r.body_complete,r.reason);
    CHECK(length && m.first_length==length && !memcmp(m.first,hello,length),
          "legacy verifier sends the exact hello used by the measurement");
    CHECK(phases==((1u<<D2K_HTTPS_REQUEST_BEGIN)|(1u<<D2K_HTTPS_REQUEST_SENT)|(1u<<D2K_HTTPS_EXCHANGE_END)),
          "legacy verifier reports request begin, submission and completion");
    CHECK(m.reads>1 && m.writes>1 && m.received,"legacy handshake and HTTP use measurement callbacks");
    CHECK(fcntl(m.fd,F_GETFD)>=0,"legacy verifier preserves borrowed socket");close(m.fd);
}
/* A real Chrome ClientHello, with its EMS extension, must resume as TLS1.2
 * and carry HTTP on the very same connection. Server cipher/group are pinned. */
static void form_exchange(uint16_t port) {
    int fd=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a={0};
    a.sin_family=AF_INET;a.sin_port=htons(port);a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(fd<0 || connect(fd,(struct sockaddr *)&a,sizeof a)) {
        CHECK(0,"form transport connect");if(fd>=0)close(fd);return;
    }
    uint8_t form[4096];size_t flen=0;
    CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN,"localhost",form,sizeof form,&flen)==0,
          "Chrome form with localhost SNI");
    char err[256]={0};d2k_tls *t=NULL;
    int rc=d2k_tls_connect_form(fd,NULL,"localhost",form,flen,5000,&t,err,sizeof err);
    CHECK(rc==0,err);
    if(rc==0) {
        CHECK(d2k_tls_version(t)==0x0303,"form selected TLS1.2");
        CHECK(d2k_tls_peer_name(t)==1,"form certificate name check retained");
        const uint8_t req[]="GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        CHECK(d2k_tls_write(t,req,sizeof req-1,err,sizeof err)==0,err);
        uint8_t reply[4096];long n=d2k_tls_read(t,reply,sizeof reply,3000,err,sizeof err);
        CHECK(n>=12 && !memcmp(reply,"HTTP/1.0 200",12),"HTTP over TLS1.2 Chrome form");
    }
    d2k_tls_free(t);CHECK(fcntl(fd,F_GETFD)>=0,"form borrows socket");close(fd);
}
static int server_case(const char *bin, const char *cert, const char *key, const char *dir,
                       const char *mode, const char *cipher, const char *group, const char *what, int want_ok) {
    uint16_t port = free_port(); if (!port) { CHECK(0, "нет свободного порта"); return -1; }
    char acc[16], logp[256]; snprintf(acc, sizeof acc, "%u", (unsigned)port);
    snprintf(logp, sizeof logp, "%s/%s.log", dir, what);
    char *argv[20]; int n = 0;
    argv[n++] = (char *)bin; argv[n++] = "s_server"; argv[n++] = "-accept"; argv[n++] = acc;
    argv[n++] = "-cert"; argv[n++] = (char *)cert; argv[n++] = "-key"; argv[n++] = (char *)key;
    argv[n++] = (char *)mode; argv[n++] = "-quiet";argv[n++]="-www";
    if (cipher) { argv[n++] = "-cipher"; argv[n++] = (char *)cipher; }
    if (group) { argv[n++] = "-groups"; argv[n++] = (char *)group; }
    argv[n] = NULL;
    pid_t pid = spawn(bin, argv, logp);
    if (!wait_listen(port, 4000)) { CHECK(0, what); stop(pid); return -1; }
    d2k_ver_result r = probe(port);
    d2k_verify_close(&r);
    char msg[320];
    if (want_ok) {
        snprintf(msg, sizeof msg, "%s: рукопожатие 1.2 без имени не завершено: %s", what, r.reason);
        CHECK(r.level == D2K_VER_HANDSHAKE && r.handshake_proof && r.negotiated_tls == 0x0303, msg);
        CHECK(r.status == 0, "сервер TLS 1.2: зонд рукопожатия запросил HTTP (status не 0)");
    } else {
        snprintf(msg, sizeof msg, "%s: отказ сервера выдан за рукопожатие: %s", what, r.reason);
        CHECK(r.level < D2K_VER_HANDSHAKE && !r.handshake_proof, msg);
        snprintf(msg, sizeof msg, "%s: причина отказа не названа клиентом 1.2: %s", what, r.reason);
        CHECK(strstr(r.reason, "нет TLS 1.2") != NULL, msg);
    }
    printf("%s: level=%d proof=%d reason=%s\n", what, (int)r.level, r.handshake_proof, r.reason);
    if(want_ok){measured_legacy_exchange(port,1);measured_legacy_exchange(port,2);form_exchange(port);}
    if(!strcmp(mode,"-tls1_3")) {
        measured_exchange(port,NULL);
        d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();CHECK(seed!=NULL,"controlled TLS seed");
        if(seed){measured_exchange(port,seed);measured_exchange(port,seed);}
        d2k_tls_probe_seed_free(seed);
    }
    stop(pid);
    return 0;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    const char *bin = openssl_bin();
    if (!bin) { printf("ОШИБКА СРЕДЫ: openssl не найден (D2K_OPENSSL) — живое рукопожатие TLS 1.2 не проверено\n"); return 3; }
    if (!free_port()) {
        printf("ОШИБКА СРЕДЫ: loopback socket/bind: %s — TLS1.2 live checks not run\n",strerror(errno));
        return 3;
    }
    char dir[64]; snprintf(dir, sizeof dir, "/tmp/d2k-tls12-live-%ld", (long)getpid());
    if (mkdir(dir, 0700) != 0) { printf("ОШИБКА СРЕДЫ: %s: %s\n", dir, strerror(errno)); return 3; }
    char cert[128], key[128], log[128];
    snprintf(cert, sizeof cert, "%s/cert.pem", dir); snprintf(key, sizeof key, "%s/key.pem", dir);
    snprintf(log, sizeof log, "%s/req.log", dir);
    char *req[] = { (char *)bin, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", cert, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1", NULL };
    pid_t rp = spawn(bin, req, log); int st = 0; waitpid(rp, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || access(cert, R_OK) != 0) {
        printf("ОШИБКА СРЕДЫ: openssl req не создал ключ/сертификат (%s)\n", log); return 3;
    }
    char eccert[128],eckey[128];
    snprintf(eccert,sizeof eccert,"%s/ec-cert.pem",dir);snprintf(eckey,sizeof eckey,"%s/ec-key.pem",dir);
    char *ecreq[]={(char *)bin,"req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256",
                  "-nodes","-keyout",eckey,"-out",eccert,"-subj","/CN=localhost",
                  "-addext","subjectAltName=DNS:localhost","-days","1",NULL};
    rp=spawn(bin,ecreq,log);waitpid(rp,&st,0);
    if(!WIFEXITED(st) || WEXITSTATUS(st)!=0 || access(eccert,R_OK)!=0) {
        printf("ОШИБКА СРЕДЫ: openssl req EC failed (%s)\n",log);return 3;
    }
    const char *ciphers[]={"ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384","ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305","ECDHE-RSA-CHACHA20-POLY1305"};
    const char *groups[]={"X25519","P-256"};
    for(size_t i=0;i<6;i++)for(size_t g=0;g<2;g++) {
        char label[128];snprintf(label,sizeof label,"%s-%s",ciphers[i],groups[g]);
        server_case(bin,i%2?cert:eccert,i%2?key:eckey,dir,"-tls1_2",ciphers[i],groups[g],label,1);
    }
    server_case(bin,cert,key,dir,"-tls1_3",NULL,NULL,"tls13-only",0);
    server_case(bin,cert,key,dir,"-tls1_2","ECDHE-RSA-AES128-SHA256",NULL,"cipher-mismatch",0);
    {   /* закрытый порт */
        uint16_t port = free_port();
        d2k_ver_result r = probe(port); d2k_verify_close(&r);
        CHECK(r.level == D2K_VER_NOT_MEASURED && strstr(r.reason, "нет TCP"), "закрытый порт: не «нет TCP»");
        printf("closed-port: level=%d reason=%s\n", (int)r.level, r.reason);
    }
    {   /* слушатель, закрывающий сразу: TCP есть, рукопожатия нет */
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t al = sizeof a;
        CHECK(lfd >= 0 && bind(lfd, (struct sockaddr *)&a, sizeof a) == 0 && listen(lfd, 1) == 0 &&
              getsockname(lfd, (struct sockaddr *)&a, &al) == 0, "EOF-слушатель");
        pid_t ep = fork();
        if (ep == 0) { int c = accept(lfd, NULL, NULL); if (c >= 0) close(c); _exit(0); }
        d2k_ver_result r = probe(ntohs(a.sin_port)); d2k_verify_close(&r);
        CHECK(r.level == D2K_VER_TRANSPORT && !r.handshake_proof && strstr(r.reason, "нет TLS 1.2"),
              "обрыв до рукопожатия выдан не за отказ TLS 1.2");
        printf("eof: level=%d reason=%s\n", (int)r.level, r.reason);
        waitpid(ep, NULL, 0); close(lfd);
    }
    char rm[256]; snprintf(rm, sizeof rm, "rm -rf %s", dir); (void)!system(rm);
    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("TLS 1.2 без имени, живой сервер: все проверки прошли (%s)\n", bin);
    return 0;
}
