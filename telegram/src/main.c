#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "../../runtime/d2k_runtime.h"
#include "tg_config.h"
#include "tg_identity.h"
#include "tg_net.h"
#include "tg_register.h"
#include "tg_enroll.h"
#include "tg_session.h"
#include "tg_tunnel.h"
#include "tg_wire.h"
#include "tg_tls.h"
#include "tg_ws.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TG_BUILD "d2k-tg-0.3"
#define TG_DEFAULT_WINDOW (2u*1024u*1024u)

static const char *health_path = "/tmp/d2k/d2ktg.health";
static atomic_int health_running, external_available;
typedef struct { int listener; } health_local;
static void *health_thread(void *arg) {
    const health_local *local=arg;
    while(atomic_load(&health_running)) {
        int ready=d2k_runtime_listener_ready(local->listener);
        (void)d2k_runtime_heartbeat(health_path,NULL,0,ready,atomic_load(&external_available));
        struct timespec delay={.tv_nsec=100000000L};(void)nanosleep(&delay,NULL);
    }
    return NULL;
}
static volatile sig_atomic_t stop_requested;

static void on_signal(int signo) { (void)signo;stop_requested=1; }

static void log_msg(const char *message) {
    time_t now=time(NULL);struct tm tmv;char stamp[32]="unknown-time";
    if(localtime_r(&now,&tmv))strftime(stamp,sizeof(stamp),"%Y-%m-%d %H:%M:%S",&tmv);
    fprintf(stderr,"%s d2ktg: %s\n",stamp,message);fflush(stderr);
}

static int write_status(const char *path,const char *value) {
    char tmp[600];if(!path||!*path||snprintf(tmp,sizeof(tmp),"%s.tmp.%ld",path,(long)getpid())>=(int)sizeof(tmp))return -1;
    int fd=open(tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0644);if(fd<0)return -1;
    size_t len=strlen(value);ssize_t n=write(fd,value,len);int ok=n==(ssize_t)len&&fsync(fd)==0;
    if(close(fd)!=0)ok=0;
    if(!ok||rename(tmp,path)!=0){unlink(tmp);return -1;}
    return 0;
}

static int create_listener(uint16_t port) {
    int fd=socket(AF_INET,SOCK_STREAM,0),one=1;if(fd<0)return -1;
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr={.s_addr=htonl(INADDR_ANY)}};
    int flags=fcntl(fd,F_GETFL,0);
    if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)!=0||
       setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))!=0||
       bind(fd,(struct sockaddr *)&addr,sizeof(addr))!=0||listen(fd,256)!=0){close(fd);return -1;}
    return fd;
}

typedef struct { SSL *ssl; } session_transport;
static int session_send(void *opaque,const uint8_t *data,size_t len) {
    session_transport *t=opaque;return tg_ws_write_binary(t->ssl,data,len);
}
static int session_read(void *opaque,uint8_t *dst,size_t cap,size_t *len) {
    session_transport *t=opaque;int rc=tg_ws_read_binary_prefix(t->ssl,dst,cap,len);return rc==0?0:-1;
}

static int establish_ws(SSL_CTX *ctx,const tg_relay_url *url,SSL **out_ssl,int *out_fd) {
    int fd=tg_tcp_connect_ipv4(url->host,url->port,10000);if(fd<0)return -1;
    SSL *ssl=tg_tls_connect_fd(ctx,fd,url->host);
    if(!ssl){close(fd);return -1;}
    char host_header[320];int n=snprintf(host_header,sizeof(host_header),"%s:%u",url->host,(unsigned)url->port);
    if(n<=0||(size_t)n>=sizeof(host_header)||tg_ws_upgrade(ssl,host_header,url->path)!=0){SSL_free(ssl);close(fd);return -1;}
    *out_ssl=ssl;*out_fd=fd;return 0;
}

static void close_ws(SSL **ssl,int *fd) {
    if(*ssl){SSL_free(*ssl);*ssl=NULL;}if(*fd>=0){close(*fd);*fd=-1;}
}

static int register_identity(const tg_config *cfg,const tg_relay_url *url,tg_identity *identity) {
    if(!cfg->relay_secret[0])return tg_enroll_identity(url->host,cfg->enroll_port,cfg->ca_bundle,identity);
    return tg_register_identity(url->host,url->port,url->host,cfg->ca_bundle,cfg->relay_secret,identity);
}

static int ensure_registered(const tg_config *cfg,const tg_relay_url *url,tg_identity *identity) {
    int rc=register_identity(cfg,url,identity);
    if(rc!=TG_REGISTER_ID_CONFLICT)return rc;
    log_msg("relay reports an identity conflict; rotating the local installation identity");
    tg_identity_cleanup(identity);
    if(unlink(cfg->identity_path)!=0&&errno!=ENOENT)return -1;
    if(tg_identity_load_or_mint(cfg->identity_path,identity)!=0)return -1;
    return register_identity(cfg,url,identity);
}

static void interruptible_wait(uint32_t delay_ms) {
    struct timespec req={.tv_sec=(time_t)(delay_ms/1000u),.tv_nsec=(long)(delay_ms%1000u)*1000000L};
    while(!stop_requested&&nanosleep(&req,&req)!=0&&errno==EINTR){}
}

static double random_unit(void) {
    uint64_t value=0;if(RAND_bytes((unsigned char *)&value,sizeof(value))!=1)return 0.5;
    return (double)value/(double)UINT64_MAX;
}

static int run_daemon(const char *config_path) {
    tg_config cfg;tg_relay_url url;tg_identity identity={0};SSL_CTX *ctx=NULL;int listener=-1,rc=1;pthread_t observer;int observer_started=0;health_local local={0};
    if(tg_config_read(config_path,&cfg)!=0){log_msg("cannot read configuration");return 1;}
    if(!cfg.enabled||!cfg.relay_url[0]||(!cfg.relay_secret[0]&&!cfg.enroll_port)){
        (void)write_status(cfg.status_path,"not_configured\n");tg_config_clean(&cfg);return 0;
    }
    if(tg_relay_url_parse(cfg.relay_url,&url)!=0){log_msg("TG_RELAY_URL must be a valid wss://host[:port]/ws URL");(void)write_status(cfg.status_path,"error\n");goto done;}
    ctx=tg_tls_client_context(cfg.ca_bundle);if(!ctx){log_msg("cannot load Telegram relay trust bundle");(void)write_status(cfg.status_path,"error\n");goto done;}
    if(tg_identity_load_or_mint(cfg.identity_path,&identity)!=0){log_msg("cannot load or create the per-install relay identity");(void)write_status(cfg.status_path,"error\n");goto done;}
    listener=create_listener(cfg.listen_port);if(listener<0){log_msg("cannot bind the Telegram redirect listener");(void)write_status(cfg.status_path,"error\n");goto done;}
    struct sigaction sa;memset(&sa,0,sizeof(sa));sa.sa_handler=on_signal;sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT,&sa,NULL);(void)sigaction(SIGTERM,&sa,NULL);(void)signal(SIGPIPE,SIG_IGN);

    local.listener=listener;atomic_store(&health_running,1);
    /* Only the main thread handles termination: it owns stop_requested and
     * its blocking reconnect wait must receive the signal to be interrupted. */
    sigset_t termination,original_mask;sigemptyset(&termination);
    sigaddset(&termination,SIGINT);sigaddset(&termination,SIGTERM);
    if(pthread_sigmask(SIG_BLOCK,&termination,&original_mask)!=0){log_msg("cannot protect local observer signal mask");goto done;}
    int create_rc=pthread_create(&observer,NULL,health_thread,&local);
    if(create_rc==0)observer_started=1;
    /* Restore even when creation fails; the observer inherited the blocked
     * mask, while main resumes its original termination delivery policy. */
    int restore_rc=pthread_sigmask(SIG_SETMASK,&original_mask,NULL);
    if(restore_rc!=0){log_msg("cannot restore main signal mask");goto done;}
    if(create_rc!=0){log_msg("cannot start local health observer");goto done;}
    unsigned failures=0,fast_deaths=0;int healthy=0,identity_registered=0;
    while(!stop_requested) {
        atomic_store(&external_available,0);
        (void)write_status(cfg.status_path,"connecting\n");
        if(!identity_registered) {
            int registered=ensure_registered(&cfg,&url,&identity);
            if(registered!=0){log_msg("relay identity registration failed; will retry");failures++;
                interruptible_wait(tg_reconnect_delay_ms(failures,0,healthy,random_unit()));continue;}
            identity_registered=1;
        }
        SSL *ssl=NULL;int relay_fd=-1;int protocol_v2=1;uint32_t window=TG_DEFAULT_WINDOW;
        if(establish_ws(ctx,&url,&ssl,&relay_fd)!=0){log_msg("verified relay WSS connection failed; will retry");failures++;
            interruptible_wait(tg_reconnect_delay_ms(failures,0,healthy,random_unit()));continue;}
        session_transport transport={.ssl=ssl};tg_session_io io={.ctx=&transport,.send_binary=session_send,.read_binary_prefix=session_read};
        tg_session_state session={0};time_t began=time(NULL);
        int auth=tg_session_authenticate_v2(&io,&identity,TG_BUILD,(int64_t)began,&session);
        if(auth==TG_SESSION_FALLBACK_V1) {
            close_ws(&ssl,&relay_fd);
            if(establish_ws(ctx,&url,&ssl,&relay_fd)!=0){log_msg("could not reconnect for the explicit v1 protocol fallback");failures++;
                interruptible_wait(tg_reconnect_delay_ms(failures,0,healthy,random_unit()));continue;}
            transport.ssl=ssl;protocol_v2=0;
            if(tg_session_authenticate_v1(&io,&identity,(int64_t)time(NULL))!=0){log_msg("v1 identity authentication failed");close_ws(&ssl,&relay_fd);failures++;
                interruptible_wait(tg_reconnect_delay_ms(failures,0,healthy,random_unit()));continue;}
            window=0;
        } else if(auth!=TG_SESSION_V2_OK) {
            log_msg("relay authentication failed; no protocol fallback is attempted");close_ws(&ssl,&relay_fd);failures++;fast_deaths++;
            if(tg_reconnect_needs_reregister(fast_deaths)){int rer=ensure_registered(&cfg,&url,&identity);fast_deaths=0;identity_registered=rer==0;if(rer!=0)log_msg("identity re-registration after repeated fast failures failed");}
            interruptible_wait(tg_reconnect_delay_ms(failures,session.retry_after,healthy,random_unit()));continue;
        } else if(session.window)window=session.window;
        atomic_store(&external_available,1);
        (void)write_status(cfg.status_path,"connected\n");log_msg(protocol_v2?"relay session authenticated (mux v2)":"relay session authenticated (mux v1)");
        tg_tunnel_config tunnel={.relay_ssl=ssl,.listener_fd=listener,.listen_port=cfg.listen_port,
            .protocol_v2=protocol_v2,.window=window,.stop=&stop_requested};
        int tunnel_rc=tg_tunnel_run(&tunnel);atomic_store(&external_available,0);close_ws(&ssl,&relay_fd);
        time_t lifetime=time(NULL)-began;
        if(lifetime>=60){healthy=1;failures=0;fast_deaths=0;}
        else {healthy=0;failures++;fast_deaths++;}
        if(tg_reconnect_needs_reregister(fast_deaths)){int rer=ensure_registered(&cfg,&url,&identity);fast_deaths=0;identity_registered=rer==0;if(rer!=0)log_msg("identity re-registration after repeated fast session deaths failed");}
        if(!stop_requested){
            if(tunnel_rc<0) { log_msg("relay session ended; reconnecting"); }
            (void)write_status(cfg.status_path,"connecting\n");
            interruptible_wait(tg_reconnect_delay_ms(failures,0,healthy,random_unit()));
        }
    }
    (void)write_status(cfg.status_path,"stopped\n");rc=0;
done:
    atomic_store(&health_running,0);if(observer_started)(void)pthread_join(observer,NULL);
    if(listener>=0)close(listener);
    if(ctx)SSL_CTX_free(ctx);
    tg_identity_cleanup(&identity);tg_config_clean(&cfg);return rc;
}

static int check_config(const char *path) {
    tg_config cfg;tg_relay_url url;
    int ok=tg_config_read(path,&cfg)==0;
    if(ok)ok=(cfg.relay_secret[0]||cfg.enroll_port)&&cfg.relay_url[0]&&access(cfg.ca_bundle,R_OK)==0&&
        tg_relay_url_parse(cfg.relay_url,&url)==0;
    tg_config_clean(&cfg);return ok?0:1;
}

static int redirect_log(const char *path) {
    if(!path||!*path)return 0;
    int fd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW,0644);if(fd<0)return -1;
    if(dup2(fd,STDERR_FILENO)<0){close(fd);return -1;}close(fd);return 0;
}

/* DNS edge health, not an application/bypass verdict. Keep the certificate
   bound to the requested Meta name while avoiding its blocked wire SNI.
   No HTTP requests, account data, or relay traffic are involved.
   The list is the router script's HOSTS and the VPS /resolve allowlist
   (scripts/test-instagram-dns.sh compares all three). Measured 03.10.2026
   with SNI example.com: Instagram edges present *.instagram.com and
   *.cdninstagram.com; fbcdn edges *.facebook.com with *.xx.fbcdn.net in SAN;
   WhatsApp edges *.whatsapp.net with *.whatsapp.com in SAN (static/mmg/pps
   .whatsapp.net match *.whatsapp.net). So every name is
   verified as itself, except the c10r alias below. */
static const char *const meta_hosts[]={
    /* META_HOSTS_BEGIN */
    "instagram.com","www.instagram.com","graph.instagram.com","api.instagram.com",
    "i.instagram.com","instagram.c10r.instagram.com","static.cdninstagram.com",
    "scontent.cdninstagram.com","static.xx.fbcdn.net","scontent.xx.fbcdn.net",
    "web.whatsapp.com","www.whatsapp.com","scontent.whatsapp.net","graph.whatsapp.com",
    "v.whatsapp.com","static.whatsapp.net","mmg.whatsapp.net","pps.whatsapp.net"
    /* META_HOSTS_END */
};

/* The certificate name that authenticates host, or NULL outside the list. */
static const char *meta_verify_name(const char *host) {
    for(size_t i=0;i<sizeof(meta_hosts)/sizeof(meta_hosts[0]);i++){
        if(strcmp(host,meta_hosts[i])!=0)continue;
        /* This DNS alias is not covered by *.instagram.com; authenticate its
           canonical service rather than disabling certificate validation. */
        return strcmp(host,"instagram.c10r.instagram.com")==0?"instagram.com":meta_hosts[i];
    }
    return NULL;
}

static int check_instagram_ip(const char *host,const char *ip,const char *ca) {
    struct in_addr address;const char *verify=meta_verify_name(host);
    if(!verify||inet_pton(AF_INET,ip,&address)!=1)return 2;
    (void)signal(SIGPIPE,SIG_IGN);
    alarm(5); /* Bound the entire operation, including slow TLS peers. */
    SSL_CTX *ctx=tg_tls_client_context(ca);if(!ctx)return 1;
    int fd=tg_tcp_connect_ipv4(ip,443,3000);
    SSL *ssl=fd<0?NULL:tg_tls_connect_fd_sni(ctx,fd,verify,"example.com");
    int rc=ssl?0:1;
    if(ssl) { puts("Meta edge reachable; certificate verified (not a bypass verdict)"); }
    SSL_free(ssl);SSL_CTX_free(ctx);if(fd>=0)close(fd);alarm(0);return rc;
}

static int offline_self_check(void) {
    uint8_t encoded[8], payload[2]={0x12,0x34}; tg_frame frame;
    size_t n=tg_mux_encode(encoded,sizeof encoded,7,1,payload,sizeof payload);
    if(n!=5||tg_mux_decode(encoded,n,&frame)!=0||frame.stream_id!=7||frame.type!=1||frame.payload_len!=2||memcmp(frame.payload,payload,2))return -1;
    return OPENSSL_init_ssl(0,NULL)==1?0:-1;
}

int main(int argc,char **argv) {
    int offline = d2k_runtime_offline(argc, argv, "d2ktg", offline_self_check);
    if (offline >= 0) return offline;
    const char *config="/opt/d2k/config",*log_path=NULL;
    if(argc==2&&strcmp(argv[1],"--version")==0){puts(TG_BUILD " features=per-install-enrollment,instagram-ip-probe,meta-hosts-v3 release=" D2K_RELEASE_ID);return 0;}
    if(argc==5&&strcmp(argv[1],"--check-instagram-ip")==0)return check_instagram_ip(argv[2],argv[3],argv[4]);
    if(argc==2&&strcmp(argv[1],"--help")==0){puts("d2ktg [--config FILE]");return 0;}
    if(argc==3&&strcmp(argv[1],"--check-config")==0)return check_config(argv[2]);
    for(int i=1;i<argc;i++) {
        if(strcmp(argv[i],"--health-file")==0&&i+1<argc)health_path=argv[++i];
        else if(strcmp(argv[i],"--config")==0&&i+1<argc)config=argv[++i];
        else if(strcmp(argv[i],"--log")==0&&i+1<argc)log_path=argv[++i];
        else {fprintf(stderr,"usage: d2ktg [--config FILE] [--log FILE]\n");return 2;}
    }
    if(redirect_log(log_path)!=0){fprintf(stderr,"d2ktg: cannot open configured log file\n");return 1;}
    return run_daemon(config);
}
