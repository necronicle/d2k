/* Automatic configuration joins the existing scheduler, not a second search.
 * Registry mutations occur only on the controller's event-loop thread. */
#include "d2k_dns_upstreams.h"
#include "dns_question_wire.inc"
#include <ifaddrs.h>
#include <net/if.h>
static void task_done(d2k_sched *,task *);
static int dns_read_configuration(const char *path,char **out,size_t *length) {
    FILE *f=fopen(path,"rb");if(!f)return errno==ENOENT?0:-1;
    /* Local configuration resource bound, unrelated to a filtering mechanism. */
    size_t capacity=65536;char *bytes=malloc(capacity+1);
    if(!bytes){fclose(f);return -1;}
    size_t n=fread(bytes,1,capacity,f);int bad=ferror(f);
    if(n==capacity && (fgetc(f)!=EOF || ferror(f)))bad=1;
    if(fclose(f))bad=1;
    if(bad){free(bytes);return -1;}bytes[n]=0;*out=bytes;*length=n;return 1;
}
static int dns_same_service(const doh_target *a,const doh_target *b) {
    return a->plain==b->plain && a->dot==b->dot && a->port==b->port &&
        !strcasecmp(a->host,b->host) && !strcmp(a->path,b->path);
}
static int encrypted_dns_task(const task *t) {
    return t->dns_dot || t->doh_path[0];
}
static const doh_target *dns_unambiguous_service(const d2k_sched *s) {
    if (!s->n_doh)return NULL;
    for (size_t i=1;i<s->n_doh;i++)
        if (!dns_same_service(&s->doh[0],&s->doh[i]))return NULL;
    return &s->doh[0];
}
void d2k_sched_dns_observe_question(d2k_sched *s,const char *name,uint16_t type,int64_t timestamp) {
    if (!s || !type || timestamp<0 || timestamp<s->recent_dns_at ||
        !name)return;
    const doh_target *service=dns_unambiguous_service(s);
    if (!service)return;
    uint8_t encoded[272];
    if (!dns_encode_question(name,type,0,encoded,sizeof encoded))return;
    size_t length=strlen(name);
    if (name[length-1]=='.')length--;
    for (size_t i=0;i<length;i++) {
        unsigned char c=(unsigned char)name[i];
        s->recent_dns_question[i]=(char)(c>='A' && c<='Z' ? c+'a'-'A' : c);
    }
    s->recent_dns_question[length]=0;
    s->recent_dns_qtype=type;s->recent_dns_at=timestamp;
    s->recent_dns_service=*service;
}
static int dns_nonzero(const uint8_t *p,size_t n) {
    uint8_t any=0;for(size_t i=0;i<n;i++)any|=p[i];return any!=0;
}
/* A named client flow supplies its own address family even when its DNS
 * query used another family or an encrypted resolver. Require an unambiguous
 * directly connected client interface before asking the forwarding table. */
static uint32_t named_client_interface(const uint8_t *client,uint8_t family) {
    struct ifaddrs *all=NULL;uint32_t found=0;
    if(getifaddrs(&all))return 0;
    int af=family==6?AF_INET6:AF_INET;size_t n=family==6?16:4;
    for(struct ifaddrs *a=all;a;a=a->ifa_next) {
        if(!a->ifa_addr||!a->ifa_netmask||a->ifa_addr->sa_family!=af)continue;
        const uint8_t *ip=af==AF_INET?(const uint8_t *)&((struct sockaddr_in *)a->ifa_addr)->sin_addr:
            (const uint8_t *)&((struct sockaddr_in6 *)a->ifa_addr)->sin6_addr;
        const uint8_t *mask=af==AF_INET?(const uint8_t *)&((struct sockaddr_in *)a->ifa_netmask)->sin_addr:
            (const uint8_t *)&((struct sockaddr_in6 *)a->ifa_netmask)->sin6_addr;
        int match=1;for(size_t i=0;i<n;i++)if((client[i]&mask[i])!=(ip[i]&mask[i]))match=0;
        if(!match||!dns_nonzero(mask,n))continue;
        uint32_t index=if_nametoindex(a->ifa_name);
        if(found&&found!=index){found=0;break;}found=index;
    }
    freeifaddrs(all);return found;
}
#ifdef __linux__
static int dns_route_attr(void *buffer,size_t cap,uint16_t type,const void *p,size_t n) {
    struct nlmsghdr *h=buffer;
    size_t at=NLMSG_ALIGN(h->nlmsg_len),need=at+RTA_ALIGN(RTA_LENGTH(n));
    if(need>cap)return -1;
    struct rtattr *a=(struct rtattr *)((uint8_t *)buffer+at);a->rta_type=type;a->rta_len=RTA_LENGTH(n);
    memcpy(RTA_DATA(a),p,n);h->nlmsg_len=(uint32_t)need;return 0;
}
/* Ask the forwarding route table with the observed client and LAN ingress.
 * The returned OIF is exactly the path identity used by d2kd at POSTROUTING. */
static uint32_t dns_route_path(const d2k_dns_answer *a,const uint8_t *server,uint8_t family) {
    if(!a->ingress || a->family!=family || !dns_nonzero(a->client,family==4?4:16))return 0;
    int fd=socket(AF_NETLINK,SOCK_RAW,NETLINK_ROUTE);if(fd<0)return 0;
    struct {struct nlmsghdr h;struct rtmsg r;uint8_t attrs[128];} q;
    memset(&q,0,sizeof q);q.h.nlmsg_len=NLMSG_LENGTH(sizeof q.r);q.h.nlmsg_type=RTM_GETROUTE;
    q.h.nlmsg_flags=NLM_F_REQUEST;q.h.nlmsg_seq=1;q.r.rtm_family=family==4?AF_INET:AF_INET6;
    q.r.rtm_dst_len=q.r.rtm_src_len=family==4?32:128;
    size_t width=family==4?4:16;
    if(dns_route_attr(&q,sizeof q,RTA_DST,server,width) ||
       dns_route_attr(&q,sizeof q,RTA_SRC,a->client,width) ||
       dns_route_attr(&q,sizeof q,RTA_IIF,&a->ingress,sizeof a->ingress)){close(fd);return 0;}
    struct timeval tv={0,200000};struct sockaddr_nl kernel={.nl_family=AF_NETLINK};socklen_t peer_len=sizeof kernel;
    if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv)||
       sendto(fd,&q,q.h.nlmsg_len,0,(struct sockaddr *)&kernel,sizeof kernel)!=(ssize_t)q.h.nlmsg_len){close(fd);return 0;}
    uint8_t reply[4096];ssize_t got=recvfrom(fd,reply,sizeof reply,0,(struct sockaddr *)&kernel,&peer_len);
    close(fd);if(got<=0||peer_len<sizeof kernel||kernel.nl_pid!=0)return 0;
    for(struct nlmsghdr *h=(struct nlmsghdr *)reply;NLMSG_OK(h,(unsigned)got);h=NLMSG_NEXT(h,got)) {
        if(h->nlmsg_seq!=1||h->nlmsg_type==NLMSG_ERROR)continue;
        if(h->nlmsg_type!=RTM_NEWROUTE)continue;
        struct rtmsg *r=NLMSG_DATA(h);int left=RTM_PAYLOAD(h);
        for(struct rtattr *x=RTM_RTA(r);RTA_OK(x,left);x=RTA_NEXT(x,left))
            if(x->rta_type==RTA_OIF && RTA_PAYLOAD(x)==4){uint32_t path;memcpy(&path,RTA_DATA(x),4);return path;}
    }
    return 0;
}
#else
static uint32_t dns_route_path(const d2k_dns_answer *a,const uint8_t *server,uint8_t family) {
    (void)a;(void)server;(void)family;return 0;
}
#endif
static int dns_same_client(const dns_address_name *r,const d2k_dns_answer *a,uint8_t family,uint32_t path) {
    size_t width=family==4?4:16;
    return r->client_family==family && r->path==path && !memcmp(r->client,a->client,width);
}
/* DNS transport family and answer address family are independent. A lease is
 * possible only when the client address belongs to the answer family; the
 * address/name history is still useful when that exact client context is not
 * available. */
static void dns_observe_answer_paths(d2k_sched *s,const d2k_dns_answer *a,int64_t now,
    const uint32_t paths[D2K_DNS_ANSWER_MAX_ADDR]) {
    if (!s || !a || now<0 || !a->question[0] || !a->count ||
        a->count>D2K_DNS_ANSWER_MAX_ADDR || (a->type!=1 && a->type!=28)) return;
    uint8_t family=a->type==1 ? 4 : 6;
    size_t width=family==4 ? 4 : 16;
    int exact_client=a->family==family && dns_nonzero(a->client,width);
    int64_t span=(int64_t)a->ttl*1000;
    int64_t expiry=now>INT64_MAX-span ? INT64_MAX : now+span;
    uint8_t affected[D2K_DNS_ANSWER_MAX_ADDR*2][16];uint32_t affected_path[D2K_DNS_ANSWER_MAX_ADDR*2];size_t n_affected=0;
    for(size_t i=0;i<SCHED_SEEN;i++)if(s->dns_names[i].expires_ms<=now)memset(&s->dns_names[i],0,sizeof s->dns_names[i]);
    /* One answer replaces this client's earlier RRset for the same name. */
    if(exact_client)for(size_t i=0;i<SCHED_SEEN;i++) {
        dns_address_name *r=&s->dns_names[i];
        if(!r->family || r->family!=family || strcasecmp(r->name,a->question) ||
           !dns_same_client(r,a,family,r->path))continue;
        int keep=0;for(size_t j=0;j<a->count;j++)if(paths[j]==r->path && !memcmp(r->address,a->addresses[j],width))keep=1;
        if(!keep) {if(n_affected<sizeof affected/sizeof affected[0]){memcpy(affected[n_affected],r->address,width);affected_path[n_affected++]=r->path;}memset(r,0,sizeof *r);}
    }
    for (size_t j=0;j<a->count;j++) {
        dns_address_name *slot=NULL, *oldest=&s->dns_names[0];
        for (size_t i=0;i<SCHED_SEEN;i++) {
            dns_address_name *row=&s->dns_names[i];
            if (row->family==family && !memcmp(row->address,a->addresses[j],width) &&
                !strcasecmp(row->name,a->question) &&
                (!exact_client || dns_same_client(row,a,family,paths[j]))) { slot=row; break; }
            if (row->expires_ms<oldest->expires_ms) oldest=row;
        }
        if (!a->ttl) {
            if (slot) memset(slot,0,sizeof *slot);
            if(exact_client)preflight_dns_reconcile(s,a->client,family,a->addresses[j],paths[j],now);
            continue;
        }
        if (!slot) slot=oldest;
        memset(slot,0,sizeof *slot);
        slot->family=family;
        memcpy(slot->address,a->addresses[j],width);
        snprintf(slot->name,sizeof slot->name,"%s",a->question);
        slot->expires_ms=expiry;
        if(exact_client && paths[j]) {slot->client_family=family;memcpy(slot->client,a->client,width);slot->path=paths[j];}
        if(exact_client && paths[j])preflight_dns_reconcile(s,a->client,family,a->addresses[j],paths[j],now);
    }
    for(size_t i=0;i<n_affected;i++)preflight_dns_reconcile(s,a->client,family,affected[i],affected_path[i],now);
}
#ifdef D2K_SCHED_DNS_TEST
static void d2k_sched_dns_observe_answer_path(d2k_sched *s,const d2k_dns_answer *a,int64_t now,uint32_t path) {
    uint32_t paths[D2K_DNS_ANSWER_MAX_ADDR]={0};for(size_t i=0;i<a->count&&i<D2K_DNS_ANSWER_MAX_ADDR;i++)paths[i]=path;
    dns_observe_answer_paths(s,a,now,paths);
}
#endif
static void family_dns_client_observe(d2k_sched *s,const d2k_dns_answer *a,int64_t now) {
    if(!s||!a||!a->question[0]||!a->ttl||
       (a->family!=4&&a->family!=6)||(a->type!=1&&a->type!=28))return;
    size_t width=a->family==4?4:16;
    if(!dns_nonzero(a->client,width))return;
    /* This is a recent client/answer observation, not a DNS RR cache entry.
     * The failed IPv6 search may outlast a 60-second CDN TTL. Revalidate the
     * A address with authenticated HTTPS before publishing any policy. */
    int64_t span=600000;
    family_dns_client *slot=NULL,*old=&s->family_clients[0];
    for(size_t i=0;i<sizeof s->family_clients/sizeof s->family_clients[0];i++) {
        family_dns_client *c=&s->family_clients[i];
        if(c->expires_ms<=now){slot=c;break;}
        if(c->family==a->family&&!strcasecmp(c->name,a->question)&&
           !memcmp(c->client,a->client,width)){slot=c;break;}
        if(c->expires_ms<old->expires_ms)old=c;
    }
    if(!slot)slot=old;
    memset(slot,0,sizeof *slot);
    slot->family=a->family;memcpy(slot->client,a->client,width);
    snprintf(slot->name,sizeof slot->name,"%s",a->question);
    slot->expires_ms=now>INT64_MAX-span?INT64_MAX:now+span;
    if(a->type==1)for(size_t j=0;j<a->count;j++) {
        family_dns_a *dst=NULL,*oldest=&s->family_a[0];
        for(size_t i=0;i<sizeof s->family_a/sizeof s->family_a[0];i++) {
            family_dns_a *r=&s->family_a[i];
            if(r->expires_ms<=now){dst=r;break;}
            if(!strcasecmp(r->name,a->question)&&!memcmp(r->address,a->addresses[j],4)){
                dst=r;break;
            }
            if(r->expires_ms<oldest->expires_ms)oldest=r;
        }
        if(!dst)dst=oldest;
        memset(dst,0,sizeof *dst);
        snprintf(dst->name,sizeof dst->name,"%s",a->question);
        memcpy(dst->address,a->addresses[j],4);
        dst->expires_ms=now>INT64_MAX-span?INT64_MAX:now+span;
    }
}
void d2k_sched_dns_observe_answer(d2k_sched *s,const d2k_dns_answer *a,int64_t now) {
    family_dns_client_observe(s,a,now);
    uint32_t paths[D2K_DNS_ANSWER_MAX_ADDR]={0};uint8_t family=a&&a->type==28?6:4;
    if(a)for(size_t i=0;i<a->count&&i<D2K_DNS_ANSWER_MAX_ADDR;i++)paths[i]=dns_route_path(a,a->addresses[i],family);
    dns_observe_answer_paths(s,a,now,paths);
}
static void preflight_observe_named_path(d2k_sched *s,const d2k_ev *ev,uint32_t path) {
    if(!s||!ev->name[0]||ev->transport!=6||(ev->family!=4&&ev->family!=6)||
       (ev->client_shape!=D2K_SHAPE_MODERN&&ev->client_shape!=D2K_SHAPE_LEGACY)||
       (ev->client_side!=D2K_CLIENT_SIDE_LOW&&ev->client_side!=D2K_CLIENT_SIDE_HIGH))return;
    int low=ev->client_side==D2K_CLIENT_SIDE_LOW;
    d2k_dns_answer a={.family=ev->family,.type=ev->family==6?28:1,.count=1,.ttl=600};
    snprintf(a.question,sizeof a.question,"%s",ev->name);
    memcpy(a.client,low?ev->low_ip:ev->high_ip,16);
    memcpy(a.addresses[0],low?ev->high_ip:ev->low_ip,16);
    if(!path){a.ingress=named_client_interface(a.client,a.family);path=dns_route_path(&a,a.addresses[0],a.family);}
    if(!path)return;
    dns_address_name *slot=NULL,*oldest=&s->dns_names[0];
    for(size_t i=0;i<SCHED_SEEN;i++) {
        dns_address_name *r=&s->dns_names[i];
        if(r->family==a.family&&r->client_family==a.family&&r->path==path&&
           !memcmp(r->client,a.client,16)&&!memcmp(r->address,a.addresses[0],16)&&
           !strcasecmp(r->name,a.question)){slot=r;break;}
        if(r->expires_ms<oldest->expires_ms)oldest=r;
    }
    if(!slot)slot=oldest;
    memset(slot,0,sizeof *slot);slot->family=slot->client_family=a.family;slot->path=path;
    memcpy(slot->client,a.client,16);memcpy(slot->address,a.addresses[0],16);
    snprintf(slot->name,sizeof slot->name,"%s",a.question);
    slot->observed_port=low?ev->high_port:ev->low_port;slot->observed_shape=ev->client_shape;
    /* Same ten-minute observation lifetime as seen_name, not a DNS TTL. */
    slot->expires_ms=s->now_ms+600000;
    preflight_dns_reconcile(s,a.client,a.family,a.addresses[0],path,s->now_ms);
}

static const char *known_service_name(const d2k_sched *s,const uint8_t *ip,uint8_t family,
                                      uint8_t transport,uint16_t port,int64_t now) {
    if (family!=4 && family!=6) return NULL;
    const char *name=NULL;
    size_t width=family==4 ? 4 : 16;
    for (size_t i=0;i<SCHED_SEEN;i++) {
        const dns_address_name *row=&s->dns_names[i];
        if (row->family!=family || row->expires_ms<=now || memcmp(row->address,ip,width)) continue;
        if (name && strcasecmp(name,row->name)) return NULL;
        name=row->name;
    }
    /* HELLO history uses the same ten-minute freshness window as other
       consumers of the controller's recent connection observations. */
    for (size_t i=0;i<SCHED_SEEN;i++) {
        const seen_name *row=&s->seen[i];
        if (!row->used || !row->name[0] || row->family!=family || row->transport!=transport ||
            now-row->named_ms>600000) continue;
        if (row->named_client_side!=D2K_CLIENT_SIDE_LOW && row->named_client_side!=D2K_CLIENT_SIDE_HIGH)
            continue;
        int low=row->named_client_side==D2K_CLIENT_SIDE_HIGH;
        if ((low?row->low_port:row->high_port)!=port || memcmp(low?row->low_ip:row->high_ip,ip,width))
            continue;
        if (name && strcasecmp(name,row->name)) return NULL;
        name=row->name;
    }
    if (!s->cat || !s->cat->n_boxes) return name;
    /* Verified service endpoints already persist in the catalog. */
    char address[INET6_ADDRSTRLEN];
    if (!inet_ntop(family==4?AF_INET:AF_INET6,ip,address,sizeof address)) return NULL;
    for (size_t i=0;i<s->cat->n_boxes;i++) {
        const d2k_cat_box *box=&s->cat->boxes[i];
        for (size_t j=0;j<box->n_binds;j++) {
            const d2k_cat_binding *b=&box->binds[j];
            if (!b->enabled || b->recheck_since || b->level<3 || !b->preflight_name[0] ||
                b->family!=family || b->transport!=transport || b->server_port!=port ||
                strcmp(b->kind,"service") || strcmp(b->target,address)) continue;
            if (name && strcasecmp(name,b->preflight_name)) return NULL;
            name=b->preflight_name;
        }
    }
    return name;
}

static void dns_pick_question(const d2k_sched *s,task *t,int64_t now) {
    t->dns_qtype=0;t->dns_question[0]=0;
    const doh_target *service=dns_unambiguous_service(s);
    /* A LAN question does not reveal which of several private upstreams was
       selected by the resolver. Never copy it to a different service. */
    if (s->recent_dns_qtype && service && dns_same_service(service,&s->recent_dns_service) &&
        t->port==service->port && t->dns_dot==service->dot && t->dns_plain==service->plain &&
        !strcasecmp(t->name,service->host) && !strcmp(t->doh_path,service->path) &&
        now>=s->recent_dns_at && now-s->recent_dns_at<3600000) {
        snprintf(t->dns_question,sizeof t->dns_question,"%s",s->recent_dns_question);
        t->dns_qtype=s->recent_dns_qtype;
    }
}
static void dns_configure_task(task *t,const doh_target *d) {
    t->dns_dot=d->dot;
    t->dns_plain=d->plain;
    t->dns_expected_http=d->http_version;
    snprintf(t->doh_path,sizeof t->doh_path,"%s",d->path);
    snprintf(t->measure_path,sizeof t->measure_path,"%s",d->path);
}
static doh_target *dns_target_of(d2k_sched *s,const task *t) {
    for(size_t i=0;i<s->n_doh;i++) {
        doh_target *d=&s->doh[i];
        if(t->dns_plain==d->plain && t->dns_dot==d->dot && t->port==d->port && !strcasecmp(t->name,d->host) &&
           !strcmp(t->doh_path,d->path) && !strcmp(t->ip,d->ip))return d;
    }
    return NULL;
}
static int dns_task_registered(d2k_sched *s,const task *t) {return dns_target_of(s,t)!=NULL;}
static task *dns_task_of(d2k_sched *s,const doh_target *d) {
    for(size_t i=0;i<s->task_count;i++) {
        task *t=s->tasks[i];
        if(t->state!=T_FREE && t->transport==(d->plain ? d->plain : 6) &&
           t->dns_plain==d->plain && t->dns_dot==d->dot && t->port==d->port &&
           !strcasecmp(t->name,d->host) && !strcmp(t->ip,d->ip) && !strcmp(t->doh_path,d->path))return t;
    }
    return NULL;
}
static int dns_add_address(doh_target *rows,size_t *used,size_t cap,const doh_target *d,const char *ip) {
    for(size_t i=0;i<*used;i++)if(!strcmp(rows[i].ip,ip))return 0;
    if(*used==cap){errno=ENOBUFS;return -1;}
    rows[*used]=*d;snprintf(rows[*used].ip,sizeof rows[*used].ip,"%s",ip);(*used)++;return 0;
}
/* Keenetic keeps bootstrap addresses in show dns-proxy even when its own
 * resolver cannot answer. Only addresses for this exact upstream are useful. */
static int dns_static_addresses(const char *path,const doh_target *d,doh_target *rows,size_t *used,size_t cap) {
    FILE *f=fopen(path,"r");if(!f)return -1;
    char line[512],key[16],equal[2],name[256],ip[INET6_ADDRSTRLEN],extra;
    unsigned ttl;int bad=0;
    while(fgets(line,sizeof line,f)) {
        uint8_t address[16];
        if(sscanf(line," %15s %1s %255s %45s %u %c",key,equal,name,ip,&ttl,&extra)!=5 ||
           strcmp(equal,"=") || strcasecmp(name,d->host))continue;
        int family=!strcmp(key,"static_a") ? AF_INET : !strcmp(key,"static_aaaa") ? AF_INET6 : 0;
        if(!family || inet_pton(family,ip,address)!=1)continue;
        if(dns_add_address(rows,used,cap,d,ip)){bad=1;break;}
    }
    if(ferror(f))bad=1;
    if(fclose(f))bad=1;
    return bad?-1:0;
}
static int dns_observed_addresses(const char *path,const doh_target *d,doh_target *rows,size_t *used,size_t cap) {
    if(!path)return 0;
    FILE *f=fopen(path,"r");if(!f)return errno==ENOENT?0:-1;
    char line[512],name[256],ip[INET6_ADDRSTRLEN],extra;unsigned port;int bad=0;
    while(fgets(line,sizeof line,f)) {
        uint8_t address[16];
        if(sscanf(line,"%255s %45s %u %c",name,ip,&port,&extra)!=3 || !port || port>65535 ||
           (inet_pton(AF_INET,ip,address)!=1 && inet_pton(AF_INET6,ip,address)!=1)){bad=1;break;}
        if(port==d->port && !strcasecmp(name,d->host) && dns_add_address(rows,used,cap,d,ip)){bad=1;break;}
    }
    if(ferror(f))bad=1;
    if(fclose(f))bad=1;
    return bad?-1:0;
}
static int dns_catalog_addresses(const d2k_sched *s,const doh_target *d,doh_target *rows,size_t *used,size_t cap) {
    if(!s->cat || d->plain)return 0;
    for(size_t i=0;i<s->cat->n_boxes;i++)for(size_t j=0;j<s->cat->boxes[i].n_binds;j++) {
        const d2k_cat_binding *b=s->cat->boxes[i].binds+j;
        if(b->transport!=6 || b->dns_dot!=d->dot || strcmp(b->kind,"service") || strcasecmp(b->dns_name,d->host) ||
           b->server_port!=d->port || strcmp(b->target,b->dns_address) || b->dns_port!=d->port || strcmp(b->probe_path,d->path) || !b->dns_address[0] ||
           b->budget!=D2K_CAT_BUDGET_PASSED)continue;
        uint8_t bytes[16];
        if((b->family!=4 && b->family!=6) ||
           inet_pton(b->family==6?AF_INET6:AF_INET,b->dns_address,bytes)!=1)continue;
        if(dns_add_address(rows,used,cap,d,b->dns_address))return -1;
    }
    return 0;
}
int d2k_sched_doh_discover(d2k_sched *s,const char *configuration,const char *addresses) {
    if(!s || !configuration){errno=EINVAL;return -1;}
    char *text=NULL;size_t length=0;int read=dns_read_configuration(configuration,&text,&length);
    if(read<=0)return read;
    d2k_dns_endpoint parsed[64];size_t count=0;
    int rc=d2k_dns_upstreams_parse(text,length,parsed,sizeof parsed/sizeof *parsed,&count);free(text);
    if(rc){errno=rc==D2K_DNS_PARSE_LIMIT?ENOBUFS:EINVAL;return -1;}
    doh_target pending[sizeof s->doh/sizeof *s->doh];size_t used=0;
    memset(pending,0,sizeof pending);
    for(size_t i=0;i<s->n_doh;i++)if(s->doh[i].sources!=2) {
        pending[used]=s->doh[i];pending[used++].sources=1;
    }
    for(size_t i=0;i<count;i++) {
        const d2k_dns_endpoint *e=parsed+i;
        if(e->transport==D2K_DNS_QUIC)continue;
        uint8_t plain=e->transport==D2K_DNS_PLAIN ? 17 : e->transport==D2K_DNS_TCP ? 6 : 0;
        doh_target d={.port=e->port,.sources=2,.dot=e->transport==D2K_DNS_TLS,.plain=plain};
        if(strlen(e->host)>=sizeof d.host || strlen(e->path)>=sizeof d.path){errno=ENOBUFS;return -1;}
        snprintf(d.host,sizeof d.host,"%s",e->host);snprintf(d.path,sizeof d.path,"%s",e->path);
        snprintf(d.ip,sizeof d.ip,"%s",e->address);
        doh_target rows[sizeof pending/sizeof *pending];size_t addresses_used=0;
        if(d.ip[0]) {rows[0]=d;addresses_used=1;}
        else {
            if(dns_static_addresses(configuration,&d,rows,&addresses_used,sizeof rows/sizeof *rows))return -1;
            if(dns_observed_addresses(addresses,&d,rows,&addresses_used,sizeof rows/sizeof *rows))return -1;
            if(!addresses_used)for(size_t j=0;j<s->n_doh;j++)
                if(dns_same_service(s->doh+j,&d) && s->doh[j].ip[0] &&
                   dns_add_address(rows,&addresses_used,sizeof rows/sizeof *rows,&d,s->doh[j].ip))return -1;
            if(!addresses_used && dns_catalog_addresses(s,&d,rows,&addresses_used,sizeof rows/sizeof *rows))return -1;
            if(!addresses_used){rows[0]=d;addresses_used=1;}
        }
        for(size_t k=0;k<addresses_used;k++) {
            d=rows[k];size_t j;
            for(j=0;j<used;j++)if(dns_same_service(pending+j,&d) && !strcmp(pending[j].ip,d.ip))break;
            if(j<used){pending[j].sources|=2;continue;}
            for(j=0;j<s->n_doh;j++)if(dns_same_service(s->doh+j,&d) && !strcmp(d.ip,s->doh[j].ip)) {
                d.next_ms=s->doh[j].next_ms;d.health_ok=s->doh[j].health_ok;d.recovery=s->doh[j].recovery;
                d.journal_pending=s->doh[j].journal_pending;
                d.http_version=s->doh[j].http_version;
                d.plain_outcome=s->doh[j].plain_outcome;
                break;
            }
            for(j=0;j<s->n_doh;j++)if(dns_same_service(s->doh+j,&d) && s->doh[j].journal_pending) {
                d.journal_pending=1;d.next_ms=0;break;
            }
            if(used==sizeof pending/sizeof *pending){errno=ENOBUFS;return -1;}
            pending[used++]=d;
        }
    }
    memcpy(s->doh,pending,sizeof pending);s->n_doh=used;
    for(size_t i=0;i<s->task_count;i++) {
        task *t=s->tasks[i];
        if(t->state==T_FREE || (!encrypted_dns_task(t) && !t->dns_plain) || dns_task_registered(s,t))continue;
        if(t->th_live)t->stop=1;
        else task_done(s,t);
    }
    return (int)used;
}

static int dns_proof_missing_authentication(const d2k_cat_binding *b) {
    return (b->dns_port || b->dns_name[0] || b->dns_address[0]) && !b->dns_authenticated;
}

static uint8_t dns_binding_http_version(const d2k_cat_binding *b) {
    /* The first authenticated DoH format supported HTTP/2 exclusively. */
    return b->dns_dot ? 0 : b->dns_http_version ? b->dns_http_version : 2;
}

static int dns_application_proved(const d2k_ver_result *r) {
    return r->peer_authenticated && !r->peer_auth_failed &&
        r->level == D2K_VER_APPLICATION && r->body_complete &&
        r->budget == D2K_BUDGET_PASSED && r->doh_replies >= 20;
}

static int dns_non_path_failure(const d2k_ver_result *r) {
    /* An actual DNS round timed out even if the firewall supplied no packet
       count. That is a reachability symptom, not a measured packet threshold. */
    int query_timeout=r->peer_authenticated && r->budget==D2K_BUDGET_CUT &&
        r->budget_requests>r->doh_replies;
    return r->local_refusal || r->local_limit || r->unsupported ||
        (r->budget_uncountable && !query_timeout) || r->peer_auth_failed ||
        r->dns_reply_rejected || r->dns_session_ended ||
        (r->level == D2K_VER_APPLICATION && !r->peer_authenticated);
}

/* A web-page success is never a DNS witness. This predicate is scoped to
 * the exact configured address, port and opaque resource of the DNS proof. */
static int dns_saved_route(const d2k_sched *s,const doh_target *d) {
    if(!s->cat || d->plain)return 0;
    uint8_t family=strchr(d->ip,':')?6:4;
    for(size_t i=0;i<s->cat->n_boxes;i++) {
        const d2k_cat_box *box=s->cat->boxes+i;
        for(size_t j=0;j<box->n_binds;j++) {
            const d2k_cat_binding *b=box->binds+j;
            if(!b->dns_authenticated || b->dns_dot!=d->dot ||
               (d->http_version && dns_binding_http_version(b)!=d->http_version) ||
               !b->enabled || b->level<3 || b->recheck_since || b->transport!=6 ||
               (b->family?b->family:4)!=family || strcmp(b->kind,"service") ||
               strcmp(b->target,d->ip) || b->server_port!=d->port ||
               strcasecmp(b->dns_name,d->host) || b->dns_port!=d->port ||
               strcmp(b->dns_address,d->ip) || strcmp(b->probe_path,d->path) ||
               b->budget!=D2K_CAT_BUDGET_PASSED || newer_target_binding(s->cat,b))continue;
            for(size_t k=0;k<box->n_plans;k++)
                if(box->plans[k].enabled && !strcmp(box->plans[k].id,b->plan_id))return 1;
        }
    }
    return 0;
}
/* Candidate reuse and direct-clear retirement use the same exact DNS scope. */
static int dns_binding_matches_task(const d2k_cat_binding *b,const task *t) {
    return b->dns_authenticated && b->dns_dot==t->dns_dot && encrypted_dns_task(t) &&
        (!t->dns_expected_http || dns_binding_http_version(b)==t->dns_expected_http) &&
        !strcmp(b->kind,"service") && b->transport==6 &&
        b->family==t->family && b->server_port==t->port && b->dns_port==t->port &&
        !strcmp(b->target,t->ip) && !strcmp(b->dns_address,t->ip) &&
        !strcasecmp(b->dns_name,t->name) && !strcmp(b->probe_path,t->doh_path) &&
        b->budget==D2K_CAT_BUDGET_PASSED;
}
static int dns_recovery_live(d2k_sched *s,const doh_target *d) {
    if(!d->recovery)return 0;
    task *t=dns_task_of(s,d);
    return t && t->state!=T_FREE && t->state!=T_WATCHING && t->state!=T_RESTING && t->state!=T_DOH_HEALTH;
}
static int dns_recovery_active(d2k_sched *s) {
    for(size_t i=0;i<s->n_doh;i++)if(dns_recovery_live(s,s->doh+i))return 1;
    return 0;
}

static int plain_endpoint_key(const plain_endpoint *p,const doh_target *d) {
    return d->plain && p->transport==d->plain && p->port==d->port && !strcmp(p->ip,d->ip);
}

static d2k_cat_binding *plain_dns_binding(const d2k_sched *s,const doh_target *d,
    const d2k_cat_plan **plan) {
    if (!s->cat || !d->plain || !d->ip[0])return NULL;
    uint8_t family=strchr(d->ip,':') ? 6 : 4;
    /* Admission marks an entire local tuple. Preserve the direct route for a
       different configured service sharing that same transport and tuple. */
    for(size_t i=0;i<s->n_doh;i++) {
        const doh_target *other=&s->doh[i];
        if (other!=d && (other->plain?other->plain:6)==d->plain && other->port==d->port &&
            !strcmp(other->ip,d->ip) && !dns_same_service(other,d))return NULL;
    }
    d2k_cat_binding *best=NULL;
    const d2k_cat_plan *selected=NULL;
    for(size_t i=0;i<s->cat->n_boxes;i++) {
        d2k_cat_box *box=&s->cat->boxes[i];
        for(size_t j=0;j<box->n_binds;j++) {
            d2k_cat_binding *b=&box->binds[j];
            if (b->shape!=D2K_CAT_SHAPE_DNS || !b->enabled || b->recheck_since || b->level<3 ||
                b->transport!=d->plain || b->family!=family || b->server_port!=d->port ||
                b->dns_port!=d->port || strcmp(b->kind,"service") || strcmp(b->target,d->ip) ||
                strcmp(b->dns_address,d->ip) || strcasecmp(b->dns_name,d->host) ||
                b->dns_authenticated || b->dns_dot || b->dns_http_version || b->probe_path[0] ||
                b->dns_query_bytes<(d->plain==6 ? 19 : 17) ||
                b->dns_query_bytes>(d->plain==6 ? 274 : 272) ||
                b->verified_by!=D2K_VERBY_PROBE || b->budget!=D2K_CAT_BUDGET_PASSED ||
                (best && best->confirmed>=b->confirmed))continue;
            for(size_t k=0;k<box->n_plans;k++) {
                const d2k_cat_plan *p=&box->plans[k];
                if (p->enabled && p->text && !strcmp(p->id,b->plan_id) && !strcmp(p->proto,"dns")) {
                    best=b;selected=p;break;
                }
            }
        }
    }
    if (plan)*plan=selected;
    return best;
}

static int plain_dns_same_plan(const plain_endpoint *p,const d2k_cat_binding *b) {
    return b && p->wire_length==b->dns_query_bytes && !strcmp(p->plan_id,b->plan_id);
}

static plain_endpoint *plain_dns_slot(d2k_sched *s,const doh_target *d) {
    for(size_t i=0;i<sizeof s->plain_endpoints/sizeof s->plain_endpoints[0];i++)
        if (plain_endpoint_key(&s->plain_endpoints[i],d))return &s->plain_endpoints[i];
    return NULL;
}

static void plain_dns_reconcile(d2k_sched *s) {
    if (s->link_fd<0 || !s->mark)return;
    for(size_t i=0;i<sizeof s->plain_endpoints/sizeof s->plain_endpoints[0];i++) {
        plain_endpoint *p=&s->plain_endpoints[i];
        if (!p->transport)continue;
        const doh_target *d=NULL;
        for(size_t j=0;j<s->n_doh;j++)if (plain_endpoint_key(p,&s->doh[j])) { d=&s->doh[j];break; }
        if (d && plain_dns_same_plan(p,plain_dns_binding(s,d,NULL)))continue;
        p->active=0;
        memset(p->request,0,sizeof p->request);
        uint8_t address[16]={0};char err[160];
        if (inet_pton(p->family==6 ? AF_INET6 : AF_INET,p->ip,address)==1 &&
            !d2k_link_del_dns_endpoint(s->link_fd,address,p->family,htons(p->port),p->transport,
                err,sizeof err))memset(p,0,sizeof *p);
    }
    if (s->plain_dns_revision!=s->plain_dns_saved)return;
    for(size_t i=0;i<s->n_doh;i++) {
        const doh_target *d=&s->doh[i];
        const d2k_cat_plan *plan=NULL;
        const d2k_cat_binding *b=plain_dns_binding(s,d,&plan);
        if (!b)continue;
        plain_endpoint *p=plain_dns_slot(s,d);
        if (p && (p->active || !plain_dns_same_plan(p,b) || s->now_ms<p->retry_at))continue;
        if (!p)for(size_t j=0;j<sizeof s->plain_endpoints/sizeof s->plain_endpoints[0];j++)
            if (!s->plain_endpoints[j].transport) {p=&s->plain_endpoints[j];break;}
        if (!p)continue;
        p->transport=d->plain;p->family=b->family;p->port=d->port;p->wire_length=b->dns_query_bytes;
        snprintf(p->ip,sizeof p->ip,"%s",d->ip);
        snprintf(p->plan_id,sizeof p->plan_id,"%s",b->plan_id);
        memset(p->request,0,sizeof p->request);
        p->retry_at=s->now_ms+5000;
        char text[sizeof ((task *)0)->plans[0]],hex[2*D2K_PLAN_TLV_MAX+1],err[160];
        uint8_t address[16]={0},id[D2K_PLAN_ID_LEN]={0};
        if (strlen(plan->text)>=sizeof text || inet_pton(p->family==6?AF_INET6:AF_INET,p->ip,address)!=1)continue;
        strcpy(text,plan->text);
        memcpy(id,plan->id,strlen(plan->id)<sizeof id?strlen(plan->id):sizeof id);
        if (stamp_plan_id(text,id) || d2k_plan_text_to_hex(text,hex,sizeof hex,err,sizeof err) ||
            fresh_trial_id(p->request) || d2k_link_set_dns_endpoint(s->link_fd,address,p->family,
                htons(p->port),p->wire_length,hex,p->request,err,sizeof err))memset(p->request,0,sizeof p->request);
    }
}

static int plain_dns_ack(d2k_sched *s,const d2k_ev *ev) {
    if (ev->kind!=D2K_EV_ACK || ev->code!=D2K_CMD_SET_DNS_ENDPOINT)return 0;
    if (!memcmp(ev->trial_id,(const uint8_t[D2K_TRIAL_ID_LEN]){0},D2K_TRIAL_ID_LEN))return 1;
    for(size_t i=0;i<sizeof s->plain_endpoints/sizeof s->plain_endpoints[0];i++) {
        plain_endpoint *p=&s->plain_endpoints[i];
        if (!p->transport || memcmp(p->request,ev->trial_id,sizeof p->request))continue;
        memset(p->request,0,sizeof p->request);
        const d2k_binding_context *b=&ev->execution_binding;
        p->active=((ev->num>>8)&255)==1 && d2k_binding_known(b) && b->kind==D2K_BIND_ADDR &&
            !b->temporary && b->family==p->family && b->shape==D2K_LINK_SHAPE_DNS;
        if (p->active)for(size_t j=0;j<s->n_doh;j++)if(plain_endpoint_key(p,&s->doh[j])) {
            s->doh[j].plain_outcome=0;
            s->doh[j].next_ms=s->now_ms+5000;
            break;
        }
        break;
    }
    return 1;
}

void d2k_sched_dns_routed(d2k_sched *s,const char *path) {
    if (!s || !path)return;
    FILE *f=fopen(path,"r");
    uint8_t matched[sizeof s->plain_endpoints/sizeof s->plain_endpoints[0]]={0};
    if (f) {
        char line[512];
        while(fgets(line,sizeof line,f)) {
            char host[256],ip[INET6_ADDRSTRLEN],protocol[4],tail;
            unsigned port;
            if (sscanf(line,"%255s %45s %u %3s %c",host,ip,&port,protocol,&tail)!=4)continue;
            uint8_t transport=!strcmp(protocol,"tcp")?6:!strcmp(protocol,"udp")?17:0;
            if (!transport)continue;
            for(size_t i=0;i<sizeof matched;i++) {
                const plain_endpoint *p=&s->plain_endpoints[i];
                if (p->active && p->transport==transport && p->port==port && !strcmp(p->ip,ip))matched[i]=1;
            }
        }
        if(ferror(f))memset(matched,0,sizeof matched);
        fclose(f);
    }
    for(size_t i=0;i<sizeof matched;i++) {
        plain_endpoint *p=&s->plain_endpoints[i];
        if (matched[i] && !p->routed)for(size_t j=0;j<s->n_doh;j++)if(plain_endpoint_key(p,&s->doh[j])) {
            s->doh[j].plain_outcome=0;
            s->doh[j].next_ms=s->now_ms;
            break;
        }
        p->routed=matched[i];
    }
}

int d2k_sched_dns_routes(d2k_sched *s,const char *path) {
    if(!s || !path){errno=EINVAL;return -1;}
    size_t n=strlen(path);if(n>4096){errno=ENAMETOOLONG;return -1;}
    char *tmp=malloc(n+12);if(!tmp)return -1;
    snprintf(tmp,n+12,"%s.XXXXXX",path);
    int fd=mkstemp(tmp);if(fd<0){free(tmp);return -1;}
    FILE *f=fdopen(fd,"w");if(!f){close(fd);unlink(tmp);free(tmp);return -1;}
    int count=0,bad=0;
    for(size_t i=0;i<s->n_doh;i++) {
        const doh_target *d=s->doh+i;
        if(d->plain) {
            plain_endpoint *p=plain_dns_slot(s,d);
            if (!p || !p->active || !plain_dns_same_plan(p,plain_dns_binding(s,d,NULL)))continue;
            if (fprintf(f,"%s %s %u %s\n",d->host,d->ip,(unsigned)d->port,d->plain==17?"udp":"tcp")<0)bad=1;
            count++;
            continue;
        }
        if(!d->ip[0] || (!dns_recovery_live(s,d) && !dns_saved_route(s,d)))continue;
        /* TLS does not expose the encrypted resource path. A shared tuple
         * must not select the first failed resource over a healthy one. */
        int safe=1,duplicate=0;
        for(size_t j=0;j<s->n_doh;j++) {
            const doh_target *other=s->doh+j;
            if(other->plain==17 || other->port!=d->port || strcmp(other->ip,d->ip))continue;
            if(!dns_recovery_live(s,other) && !dns_saved_route(s,other))safe=0;
            if(j<i && !strcasecmp(other->host,d->host))duplicate=1;
        }
        if(!safe || duplicate)continue;
        if(fprintf(f,"%s %s %u tcp\n",d->host,d->ip,(unsigned)d->port)<0)bad=1;
        count++;
    }
    if(fclose(f))bad=1;
    if(!bad && rename(tmp,path))bad=1;
    if(bad)unlink(tmp);
    free(tmp);return bad?-1:count;
}

/* Bootstrap from the owner's observed exchange, not from another resolver.
 * Unknown direction cannot establish a server address on an arbitrary port. */
static void dns_observe_hello(d2k_sched *s,const d2k_ev *ev) {
    if(ev->transport!=6 || !ev->name[0] ||
       (ev->family!=4 && ev->family!=6) ||
       (ev->client_side!=D2K_CLIENT_SIDE_LOW && ev->client_side!=D2K_CLIENT_SIDE_HIGH))return;
    char ip[INET6_ADDRSTRLEN]={0};uint16_t port=0;server_of(ev,ip,sizeof ip,&port);
    if(!ip[0])return;
    for(size_t i=0;i<s->n_doh;i++) {
        doh_target *d=s->doh+i;
        if(d->plain || d->ip[0] || d->port!=port || strcasecmp(d->host,ev->name))continue;
        snprintf(d->ip,sizeof d->ip,"%s",ip);d->next_ms=0;
    }
}
