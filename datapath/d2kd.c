/* d2kd — служба датапата. Только Linux.
 *
 * Берёт пакеты из NFQUEUE, ведёт учёт потоков, при необходимости применяет
 * план и отвечает вердиктом. Собственные пакеты уходят сырым сокетом; те, у
 * которых в плане назначена задержка, ждут своего срока в очереди отправки, а
 * не в цикле — спать в цикле значит остановить весь трафик роутера.
 *
 * УМОЛЧАНИЕ — НАБЛЮДЕНИЕ. В режиме observe ни один пакет не снимается и ни
 * один не выпускается: план прогоняется, его результат считается, трафик идёт
 * как шёл. Этап C документа прямо говорит «обход пока не применяется
 * автоматически», и режим по умолчанию обязан этому соответствовать. Активное
 * исполнение включается явным --mode apply.
 *
 * Времена — целые наносекунды от CLOCK_MONOTONIC. Плавающей арифметики на
 * пакетном пути нет: MIPS-коробки идут без сопроцессора.
 */
#define _POSIX_C_SOURCE 200809L

#include "../runtime/d2k_runtime.h"
#include "d2k_crypto.h"
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <poll.h>

#include "d2k_ctl.h"
#include "d2k_ctlsrv.h"
#include "d2k_journal.h"
#include "d2k_nfq.h"
#include "d2k_nl.h"
#include "d2k_raw.h"
#include "d2k_resend.h"
#include "d2k_sched.h"
#include "d2k_session.h"
#include "d2k_preflight_path.h"
#include "d2k_time.h"
#include "d2k_hold.h"
#include "d2k_udp_hold.h"
#include "d2k_udp_release.h"
#include "d2k_udp_path.h"
#include "d2k_routemark.h"
#include "d2k_packet.h"
#include "d2k_lateobs.h"
#include "d2k_latewatch.h"
#include "d2k_lwexec.h"
#include "d2k_lwrules.h"
#include "d2k_http80.h"
#include "d2k_http_trace.h"
#include "d2k_icmpguard.h"
#include "d2k_postnat_own.h"
#include "d2k_postnat_capture.h"
#include "d2k_dns_family.h"

/* Сколько решений по клиентскому QUIC пишется в журнал за запуск. */
#define D2K_CLIENT_QUIC_LOG 300u
/* РЕШЕНИЯ ПО КЛИЕНТСКОМУ TCP — В ЖУРНАЛ (24.10.2026). У QUIC такая запись
   есть с 15.10, а про TCP датапат молчал: по журналу нельзя было ответить,
   видел ли он поток браузера и почему не применил план (issue 25 и 28, где
   «в логах нет записей» прочиталось как «не видел»). Первые
   D2K_CLIENT_TCP_LOG решений на запуск, дальше тишина: на живом роутере
   строка на сегмент — это журнал в десятки мегабайт. */
#define D2K_CLIENT_TCP_LOG 300u
static unsigned client_tcp_logged;

/* Порты клиентского TCP-сегмента и первый байт нагрузки: 1 — разобрано.
 *
 * ТОЛЬКО ЗАПИСЬ РУКОПОЖАТИЯ (first == 0x16). Первая редакция писала строку на
 * каждый сегмент с нагрузкой, и круг all-w1 (24.10.2026) дал 324 строки, из
 * которых почти все — «плана для этой цели нет» на данных после рукопожатия:
 * предел в 300 решений съедался шумом, а приветствия до журнала не доходили.
 * Первый байт — та же улика, которой сессия отличает приветствие от данных
 * (last_nonhello_first). */
static int client_tcp_ports(const uint8_t *pkt, size_t len,
                            unsigned *sport, unsigned *dport, size_t *payload,
                            uint8_t *first)
{
    if (!pkt || len < 40 || (pkt[0] >> 4) != 4 || pkt[9] != 6) { return 0; }
    size_t ihl = (size_t)(pkt[0] & 15u) * 4u;
    if (ihl < 20 || ihl + 20 > len) { return 0; }
    const uint8_t *tcp = pkt + ihl;
    size_t doff = (size_t)(tcp[12] >> 4) * 4u;
    if (doff < 20 || ihl + doff > len) { return 0; }
    *sport = ((unsigned)tcp[0] << 8) | tcp[1];
    *dport = ((unsigned)tcp[2] << 8) | tcp[3];
    *payload = len - ihl - doff;
    *first = *payload ? pkt[ihl + doff] : 0;
    return 1;
}

#define RECV_BUF   65536
#define MAX_PKT     1600
enum { MODE_OBSERVE = 0, MODE_APPLY = 1 };

/* The controller owns the decision. The datapath only executes a short
 * exact-name/client lease on locally generated ordinary DNS replies. */
static d2k_dns_family_rule dns_family_rules[64];
static size_t dns_family_count;
static time_t dns_family_loaded_at;
static int dns_family_loaded;
static unsigned dns_family_logged;
static struct {
    d2k_dns_family_request request;
    time_t expires_at;
} dns_family_requests[128];

static int dns_family_step(d2k_nfq *q,const d2k_nl_pkt *np,const char *path,int mode) {
    if(!path || !np->have_payload || np->payload_len<28 || np->truncated ||
       (np->hook!=D2K_HOOK_OUTPUT&&np->hook!=D2K_HOOK_INPUT))return 0;
    const uint8_t *p=np->payload;
    size_t ip_len=(p[0]>>4)==4 ? (size_t)(p[0]&15u)*4u :
                  (p[0]>>4)==6 ? 40u : 0u;
    if(!ip_len || np->payload_len<ip_len+8 ||
       p[(p[0]>>4)==4?9:6]!=17 ||
       (np->hook==D2K_HOOK_OUTPUT ? (p[ip_len]!=0||p[ip_len+1]!=53) :
        (p[ip_len+2]!=0||p[ip_len+3]!=53)))return 0;
    time_t now=time(NULL);
    if(now<0)now=0;
    if(!dns_family_loaded || !dns_family_count || now-dns_family_loaded_at>=2 ||
       now<dns_family_loaded_at) {
        dns_family_loaded=1;dns_family_loaded_at=now;
        if(d2k_dns_family_load(path,dns_family_rules,
            sizeof dns_family_rules/sizeof dns_family_rules[0],&dns_family_count,now))
            dns_family_count=0;
    }
    char err[160];
    if(mode==MODE_APPLY && dns_family_count && np->payload_len<=MAX_PKT) {
        if(np->hook==D2K_HOOK_INPUT) {
            for(size_t i=0;i<dns_family_count;i++) {
                d2k_dns_family_request request;
                if(d2k_dns_family_request_parse(p,np->payload_len,&dns_family_rules[i],&request)!=1)
                    continue;
                size_t slot=0;
                int found=0;
                for(size_t j=0;j<sizeof dns_family_requests/sizeof dns_family_requests[0];j++) {
                    const d2k_dns_family_request *old=&dns_family_requests[j].request;
                    if(dns_family_requests[j].expires_at>now && old->family==request.family &&
                       old->id==request.id && old->client_port==request.client_port &&
                       old->qtype==request.qtype &&
                       !strcmp(old->name,request.name) &&
                       !memcmp(old->client,request.client,request.family==4?4:16) &&
                       !memcmp(old->server,request.server,request.family==4?4:16)) {
                        slot=j;found=1;break;
                    }
                    if(dns_family_requests[j].expires_at<=now && !found) {slot=j;found=1;}
                    if(found)continue;
                    if(dns_family_requests[j].expires_at<dns_family_requests[slot].expires_at)slot=j;
                }
                dns_family_requests[slot].request=request;
                dns_family_requests[slot].expires_at=now+10;
                break;
            }
        } else {
            for(size_t i=0;i<sizeof dns_family_requests/sizeof dns_family_requests[0];i++) {
                if(dns_family_requests[i].expires_at<=now ||
                   !d2k_dns_family_response_matches(p,np->payload_len,
                       &dns_family_requests[i].request))continue;
                d2k_dns_family_request request=dns_family_requests[i].request;
                dns_family_requests[i].expires_at=0;
                if(request.dnssec)break;
                uint8_t rewritten[MAX_PKT];
                memcpy(rewritten,p,np->payload_len);
                for(size_t j=0;j<dns_family_count;j++) {
                    if(strcmp(dns_family_rules[j].name,request.name)||
                       dns_family_rules[j].client_family!=request.family||
                       memcmp(dns_family_rules[j].client,request.client,
                           request.family==4?4:16))continue;
                    size_t length=np->payload_len;
                    if(d2k_dns_family_rewrite(rewritten,&length,sizeof rewritten,
                        &dns_family_rules[j],now,1)==1 &&
                       d2k_nfq_verdict_payload(q,np->id,D2K_NF_ACCEPT,rewritten,length,
                           err,sizeof err)==0) {
                        if(dns_family_logged<64) {
                            fprintf(stderr,"d2kd: DNS IPv4 preference: %s qtype=%u, reply rewritten\n",
                                request.name,(unsigned)request.qtype);
                            dns_family_logged++;
                        }
                        return 1;
                    }
                    break;
                }
                break;
            }
        }
    }
    (void)d2k_nfq_verdict(q,np->id,D2K_NF_ACCEPT,err,sizeof err);
    return 1;
}
#define OUT_BUF    (D2K_RESULT_MAX * MAX_PKT)

static volatile sig_atomic_t stop_flag;
static volatile sig_atomic_t stop_sender;
static void on_signal(int sig, siginfo_t *info, void *context) {
    (void)context;
    stop_sender = info && info->si_code <= 0 ? info->si_pid : 0;
    stop_flag = sig;
}

/* Собственная цена. Читается у ядра, а не оценивается: §10 требует CPU и RSS
   как метрики, а «на глаз не тормозит» метрикой не является.
   /proc/self/stat: поля 14 и 15 — utime и stime в тиках.
   /proc/self/statm: поле 2 — резидентные страницы. */
static void self_cost(uint64_t *cpu_ms, uint64_t *rss_kb) {
    *cpu_ms = 0;
    *rss_kb = 0;

    FILE *f = fopen("/proc/self/stat", "r");
    if (f) {
        char buf[1024];
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        buf[n] = '\0';
        /* Имя процесса в скобках может содержать пробелы; поля считаем после
           последней закрывающей скобки. */
        char *p = strrchr(buf, ')');
        if (p) {
            int field = 2;
            unsigned long ut = 0, stime = 0;
            for (p++; *p; ) {
                while (*p == ' ') { p++; }
                if (!*p) { break; }
                field++;
                unsigned long v = strtoul(p, &p, 10);
                if (field == 14) { ut = v; }
                if (field == 15) { stime = v; break; }
            }
            long hz = sysconf(_SC_CLK_TCK);
            if (hz > 0) {
                *cpu_ms = (uint64_t)(ut + stime) * 1000u / (uint64_t)hz;
            }
        }
    }

    f = fopen("/proc/self/statm", "r");
    if (f) {
        unsigned long total = 0, resident = 0;
        if (fscanf(f, "%lu %lu", &total, &resident) == 2) {
            long pg = sysconf(_SC_PAGESIZE);
            if (pg > 0) {
                *rss_kb = (uint64_t)resident * (uint64_t)pg / 1024u;
            }
        }
        fclose(f);
    }
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NS_PER_S + (uint64_t)ts.tv_nsec;
}

/* Route lookup is needed only when a TLS ClientHello is about to be examined,
   not for every packet that crosses NFQUEUE. The resulting cap reserves the
   largest TCP header the wire builder can emit (32 bytes) and therefore
   keeps a split payload below the route's IP MTU even when TCP timestamps are
   requested by the measured strategy. */
static size_t tls_route_segment_cap(d2k_raw *raw, const uint8_t *pkt, size_t len) {
    if (!raw || !pkt || len < 40) { return 0; }
    uint8_t family = pkt[0] >> 4;
    size_t ip_len, tcp_off;
    const uint8_t *dst;
    if (family == 4) {
        ip_len = (size_t)(pkt[0] & 15u) * 4u;
        if (ip_len < 20 || len < ip_len + 20 || pkt[9] != 6) { return 0; }
        dst = pkt + 16;
        tcp_off = ip_len;
    } else if (family == 6) {
        /* The session parser handles extension headers. For this fast-path
           MTU hint, skip them rather than guessing their length. */
        if (len < 60 || pkt[6] != 6) { return 0; }
        ip_len = 40;
        dst = pkt + 24;
        tcp_off = 40;
    } else {
        return 0;
    }
    size_t tcp_len = (size_t)(pkt[tcp_off + 12] >> 4) * 4u;
    if (tcp_len < 20 || len < tcp_off + tcp_len + 5 ||
        pkt[tcp_off + tcp_len] != 0x16 || pkt[tcp_off + tcp_len + 1] != 3) {
        return 0;
    }
    size_t mtu = d2k_raw_route_maxlen_family(raw, dst, family);
    size_t overhead = ip_len + 32u; /* 20-byte TCP base + 12-byte options */
    return mtu > overhead ? mtu - overhead : 0;
}

/* --- учёт причин пропуска -------------------------------------------------
 * «План не сработал» и «план не применялся» — разные факты, и сводка обязана
 * их различать. Причины приходят строковыми литералами из session.c, поэтому
 * сравнение сперва по указателю (почти всегда попадает и стоит копейки) и
 * только потом по содержимому. */
#define MAX_REASONS 32
static struct {
    const char *text;
    uint64_t    n;
} reasons[MAX_REASONS];
static size_t n_reasons;

static void count_reason(const char *r) {
    if (!r) {
        return;
    }
    for (size_t i = 0; i < n_reasons; i++) {
        if (reasons[i].text == r) {
            reasons[i].n++;
            return;
        }
    }
    for (size_t i = 0; i < n_reasons; i++) {
        if (strcmp(reasons[i].text, r) == 0) {
            reasons[i].n++;
            return;
        }
    }
    if (n_reasons < MAX_REASONS) {
        reasons[n_reasons].text = r;
        reasons[n_reasons].n = 1;
        n_reasons++;
    }
}

/* --- счётчики -------------------------------------------------------------- */
static struct {
    uint64_t seen, bytes;
    uint64_t accepted, dropped;
    uint64_t emitted;          /* собственных пакетов выпущено */
    uint64_t deferred;         /* отложено до срока */
    uint64_t stale_deferred;   /* созревшая посылка не ушла: поток забыт/отказал */
    uint64_t emitted_now;      /* ушло сразу, без задержки */
    uint64_t emitted_late;     /* ушло из очереди отложенных */
    uint64_t truncated;        /* ядро отдало кусок пакета */
    uint64_t no_payload;       /* атрибута с пакетом не было вовсе */
    uint64_t no_hdr;           /* некому отвечать вердиктом */
    uint64_t verdict_fail;
    uint64_t send_fail;
    uint64_t recv_err;
    uint64_t udp_marked_kept;  /* потоков UDP с меткой клиента: хвосты не переизданы */
    uint64_t busy_lines;       /* строк «сокет полон» в журнале (первые 16) */
    uint64_t routes_watch;     /* уведомлений о правилах/маршрутах */
    uint64_t icmp_seen;        /* ICMP time-exceeded из очереди */
    uint64_t hold_owned;       /* сегментов приветствия взято у ядра (DROP в слот) */
    uint64_t hold_resent;      /* оригиналов возвращено на провод своей посылкой */
    uint64_t hold_resend_fail; /* оригиналов, которые вернуть не удалось */
    uint64_t hold_resend_split; /* оригиналов возвращено нарезкой по пределу пути */
} st;

/* ICMP time-exceeded на собственные фальшивки с пониженным TTL (поле
   04.10.2026, d2k_icmpguard.h): клиент не должен получать ошибку на пакет,
   которого не посылал. Static: ~20 КиБ кольца не место на стеке. */
static d2k_icmpguard icmpg;

/* ICMP из очереди: 1 — разобран здесь (вердикт выдан или некому), 0 — не
   ICMP, дальше обычным путём. Снимается только ответ на нашу же фальшивку;
   всё прочее — ACCEPT без изменений. */
static int icmp_step(d2k_nfq *q, const d2k_nl_pkt *np, uint64_t t) {
    if (!np->have_payload || np->payload_len < 1) { return 0; }
    uint8_t family = np->payload[0] >> 4;
    if (!((family == 4 && np->payload_len >= 20 && np->payload[9] == 1) ||
          (family == 6 && np->payload_len >= 40 && np->payload[6] == 58))) {
        return 0;
    }
    st.icmp_seen++;
    /* Только входящее: FORWARD к клиенту, INPUT к роутеру. */
    int inbound = np->hook == D2K_HOOK_FORWARD || np->hook == D2K_HOOK_INPUT;
    uint32_t v = inbound && d2k_icmpguard_check(&icmpg, np->payload, np->payload_len, t)
        ? D2K_NF_DROP : D2K_NF_ACCEPT;
    if (v == D2K_NF_DROP && d2k_icmpguard_dropped(&icmpg) == 1) {
        char from[64] = "?";
        (void)inet_ntop(family == 6 ? AF_INET6 : AF_INET,
                        np->payload + (family == 6 ? 8 : 12), from, sizeof from);
        fprintf(stderr, "d2kd: ICMP time-exceeded от %s на собственную фальшивку с "
                        "пониженным TTL снят, клиенту не передан (дальше только "
                        "счётчик в сводке)\n", from);
    }
    char err[200];
    if (d2k_nfq_verdict(q, np->id, v, err, sizeof err) != 0) {
        st.verdict_fail++;
        fprintf(stderr, "d2kd: %s\n", err);
        return 1;
    }
    if (v == D2K_NF_DROP) { st.dropped++; } else { st.accepted++; }
    return 1;
}

/* Отказ сырой посылки плана — строка журнала. Полный сокет (EAGAIN/ENOBUFS,
   финальное ревью M-3) под забитым аплинком повторяется на каждом плане:
   первые 16 строк, дальше счётчик d2k_raw_busy в сводке. */
static void log_send_fail(const char *what, const char *err, int e) {
    if (d2k_udp_send_busy(e)) {
        if (++st.busy_lines > 16) { return; }
        fprintf(stderr, "d2kd: %s%s%s\n", what, err,
                st.busy_lines == 16 ? " (дальше только счётчик «сокет полон»)" : "");
        return;
    }
    fprintf(stderr, "d2kd: %s%s\n", what, err);
}

/* raw/sched are set only in apply mode with a raw socket: without them held
   UDP tails go back to the kernel as before (observe mode). */
typedef struct {
    d2k_session *sess; d2k_nfq *q;
    d2k_raw *raw; d2k_sched *sched;
    int skip_verdict; uint32_t skip_id;
    uint32_t *retry_ids, *retry_verdicts;
    size_t *retry_count;
} hold_context;
/* Dedicated marks/sockets: never turn an ordinary fake into a preflight. */
static d2k_raw *preflight_raw[3];
static size_t preflight_releases_pending;
static d2k_hold *holding;
static d2k_udp_hold *udp_holding;
static d2k_udp_release *udp_releases;
static d2k_udp_follow *udp_follow;
static d2k_udp_out udp_out;
/* Селекторы ip rule по метке (задача 47): клиент, чья метка выбирает
   маршрут по политике, идёт ядром без плана. */
static d2k_routemark routes;

static int routes_routed(const void *r, uint8_t ipver, uint32_t mark) {
    return d2k_routemark_routed(r, ipver, mark);
}

static void describe_oifs(char *buf, size_t cap, const uint32_t *o, size_t n, int read) {
    size_t w = 0;
    buf[0] = 0;
    if (!read) { snprintf(buf, cap, "неизвестен (проверка по интерфейсу выключена)"); return; }
    if (!n) { snprintf(buf, cap, "нет"); return; }
    for (size_t i = 0; i < n && w < cap; i++) {
        char name[IF_NAMESIZE] = "";
        if (!if_indextoname(o[i], name)) { snprintf(name, sizeof name, "#%u", o[i]); }
        int k = snprintf(buf + w, cap - w, "%s%s", i ? ", " : "", name);
        if (k < 0) { break; }
        w += (size_t)k;
    }
}

/* Правила по метке и выход сырой посылки (финальное ревью I-1, M-2): один
   поиск маршрута к пробному адресу на семейство, без дампа таблиц (ревью
   I-A). Каждая часть читается сама по себе; не
   прочитанная держит прежнее значение. Каждое состояние пишется в журнал
   один раз, при смене, а не раз в 30 с. */
#define ROUTES_QUIET_NS (600ull * NS_PER_S)
static void routes_refresh(void) {
    static int last_fail = 0, last_v4 = 1, last_v6 = 1, last_r4 = 1, last_r6 = 1;
    static int last_trunc = 0, first = 1;
    char err[256] = "";
    d2k_routemark_status st_rm;
    int r4 = 0, r6 = 0;
    int rc = d2k_routemark_load(&routes, &st_rm, &r4, &r6, err, sizeof err);
    if (rc < 0) {
        /* Не прочли ничего — держим прежнее: пропажа правил не должна
           выключать d2k, их появление не должно молча пропасть навсегда. */
        if (!last_fail) {
            fprintf(stderr, "d2kd: правила и маршруты не прочитаны: %s — держу прежние%s\n",
                    err, first ? " (до первого чтения клиент с чужой меткой идёт ядром)" : "");
        }
        last_fail = 1;
        first = 0;
        return;
    }
    if (last_fail) { fprintf(stderr, "d2kd: правила и маршруты снова читаются\n"); }
    last_fail = 0;
    first = 0;
    int now[4] = {st_rm.v4_ok, st_rm.v6_ok, r4, r6};
    int *last[4] = {&last_v4, &last_v6, &last_r4, &last_r6};
    static const char *what[4] = {"правила IPv4 по метке", "правила IPv6 по метке",
                                  "маршрут IPv4", "маршрут IPv6"};
    for (int i = 0; i < 4; i++) {
        if (now[i] == *last[i]) { continue; }
        if (now[i] == 2) {
            /* Маршрут есть, а интерфейса в ответе нет (объекты nexthop):
               сравнивать не с чем — для семейства только проверка метки. */
            fprintf(stderr, "d2kd: %s без интерфейса в ответе ядра — проверка выхода "
                            "по интерфейсу для этого семейства выключена, действует "
                            "только метка\n", what[i]);
        } else if (now[i]) {
            fprintf(stderr, "d2kd: %s снова читаются\n", what[i]);
        } else {
            fprintf(stderr, "d2kd: %s не прочитаны: %s — держу прежние\n", what[i], err);
        }
        *last[i] = now[i];
    }
    if (st_rm.truncated != last_trunc) {
        if (st_rm.truncated) {
            fprintf(stderr, "d2kd: правил по метке %zu, учтены первые %d\n",
                    st_rm.found, D2K_ROUTEMARK_MAX);
        }
        last_trunc = st_rm.truncated;
    }
    /* Поле 06.10: правила Keenetic перескакивают между двумя-тремя наборами,
       и строка звучала тысячи раз в сутки, раздувая журнал на флеше. Смена
       применяется сразу; запись — не чаще раза в ROUTES_QUIET_NS, с числом
       смен между записями, а итоговое состояние пишется по истечении окна. */
    static uint64_t quiet_until = 0;
    static unsigned changes = 0;
    if (rc == 1) { changes++; }
    uint64_t t = now_ns();
    if (changes && t >= quiet_until) {
        char text[512], o4[256], o6[256], more[64] = "";
        (void)d2k_routemark_describe(&routes, text, sizeof text);
        describe_oifs(o4, sizeof o4, routes.oif4, routes.n_oif4, routes.oifs_read4);
        describe_oifs(o6, sizeof o6, routes.oif6, routes.n_oif6, routes.oifs_read6);
        if (changes > 1) { snprintf(more, sizeof more, " [смен с прошлой записи: %u]", changes); }
        fprintf(stderr, "d2kd: метки маршрута по ip rule (клиент с такой меткой — без плана): %s; "
                        "выход сырой посылки IPv4: %s, IPv6: %s "
                        "(клиент, уходящий через другой интерфейс, — без плана)%s\n",
                text, o4, o6, more);
        changes = 0;
        quiet_until = t + ROUTES_QUIET_NS;
    }
}
static d2k_udp_path udp_path;
/* Предел длины посылки — по интерфейсу ВЫХОДА сырой посылки, а не по
   наименьшему MTU среди поднятых (поле 22.10.2026, issue #5/#7: VPN-туннель с
   MTU 1280 опускал предел всем, и каждый план с посылкой 1440 байт отвергался
   на активации; см. d2k_raw_adopt_egress). Выход уже найден поиском маршрута
   (routes_refresh), поэтому зовётся сразу за ним. Смена предела уезжает
   контроллеру тем же событием PROTO, что и при подключении: предел нужен
   сборке планов, а не только нашей проверке. Названный --iface не трогается. */
static void cap_refresh(d2k_raw *raw, d2k_ctlsrv *cx, d2k_ctl *ctl) {
    if (!raw) { return; }
    uint32_t oifs[2 * D2K_ROUTEMARK_OIF_MAX];
    size_t n = 0;
    if (routes.oifs_read4) {
        for (size_t i = 0; i < routes.n_oif4 && n < sizeof oifs / sizeof oifs[0]; i++) {
            oifs[n++] = routes.oif4[i];
        }
    }
    if (routes.oifs_read6) {
        for (size_t i = 0; i < routes.n_oif6 && n < sizeof oifs / sizeof oifs[0]; i++) {
            oifs[n++] = routes.oif6[i];
        }
    }
    if (!n) { return; }
    size_t before = d2k_raw_maxlen(raw);
    char names[256];
    if (d2k_raw_adopt_egress(raw, oifs, n, names, sizeof names) != 1) { return; }
    size_t after = d2k_raw_maxlen(raw);
    fprintf(stderr, "d2kd: предел длины посылки %zu байт — по MTU выхода сырой посылки (%s); "
                    "было %zu%s\n", after, names, before,
            before < after ? " — наименьший MTU среди поднятых интерфейсов, "
                             "туннель к делу не относится" : "");
    cx->send_maxlen = (uint32_t)after;
    if (ctl && d2k_ctl_peer_fd(ctl) >= 0) { d2k_ctlsrv_greet(ctl, (uint32_t)after); }
}

static int send_original_verdict(void *ctx, uint32_t id, uint32_t verdict) {
    hold_context *c = ctx;
    if (c->skip_verdict && id == c->skip_id) return 0;
    char err[256];
    int rc = d2k_nfq_verdict(c->q, id, verdict, err, sizeof err);
    if (rc != 0) {
        st.verdict_fail++;
        if (c->retry_count && *c->retry_count < D2K_UDP_HOLD_PACKETS) {
            size_t i = (*c->retry_count)++;
            c->retry_ids[i] = id; c->retry_verdicts[i] = verdict;
        }
        fprintf(stderr, "d2kd: вердикт оригинала %u: %s\n", id, err);
    }
    if (verdict == D2K_NF_DROP) { st.dropped++; } else { st.accepted++; }
    return rc;
}

static int send_delayed_verdict(void *ctx, uint32_t id, uint32_t verdict) {
    return send_original_verdict(ctx, id, verdict);
}

static void delayed_verdict_done(void *ctx, const d2k_key *key,
                                 uint64_t execution, int complete, size_t sent) {
    hold_context *c = ctx;
    uint64_t at = now_ns();
    /* Token 0: a single deferred verdict of a client datagram (out_defer),
       not a plan's execution — nothing to account. */
    if (execution == 0) { return; }
    if (complete) {
        d2k_session_sent(c->sess, at, key, execution);
        return;
    }
    (void)d2k_session_exec_failed(c->sess, at, key, NULL, D2K_REFUSE_SEND,
                                  execution, 0, sent != 0);
}
/* ОТПУЩЕН БЕЗ СБОРКИ — ЭТО ОТДЕЛЬНЫЙ ИСХОД, И ЕГО НАДО НАЗВАТЬ ПО ПОТОКУ.
 *
 * Удержание начинается, когда TLS-запись пришла НЕПОЛНОЙ и к цели есть план:
 * план обязан лечь на приветствие целиком. Если остаток не пришёл, пакеты
 * отпускаются как есть — плана на них не будет, причины пропуска тоже
 * (её ставит другая ветка), и в журнале остаётся только «приветствие».
 *
 * Поле 17.09.2026: ровно так терялся зонд подтверждения на живой линии.
 * У клиентских потоков строка «план не применён» есть на каждом, у зонда — ни
 * одной, и по общему счётчику («составной вход: начато=1 собрано=0
 * таймаутов=1») нельзя было сказать, ЧЕЙ это поток. Теперь можно. */
/* ВЛАДЕНИЕ ВМЕСТО УДЕРЖАНИЯ (поле 21.10.2026, hello-shape-probe, rutracker.org).
 *
 * Приветствие Chrome (1734 Б, постквантовый key_share) не влезает в сегмент,
 * и имя у него через раз лежит во втором куске. Голова без имени шла в слот,
 * а вердикт ядру не выдавался до сборки. Для потоков самого роутера это
 * тупик: пока голова лежит в очереди без вердикта, TCP-стек хвост не
 * выпускает (ядро держит его за неотправленной головой), сборка не
 * завершается никогда, через 100 мс голова уходит голой — и коробка режет
 * рукопожатие. Прибор на роутере: Safari 6/6, Chrome 6/20; у провалов
 * SYN→голова 150–360 мс против 60 у удач. У LAN-клиентов хвост приходит
 * (стек не наш), и та же сборка работала.
 *
 * Поэтому сегмент, взятый в слот, снимается у ядра СРАЗУ (NF_DROP): копия
 * уже в слоте, буфер ядра свободен, хвост выходит за ~0,2 мс и тоже ложится в
 * слот. Лёг план — оригиналы ушли его посылкой, как и раньше у READY. Не лёг
 * (таймаут, смена ревизии, несовместимый кусок, READY без плана) — оригиналы
 * возвращаются на провод нашей посылкой, с теми же данными, по порядку потока.
 * Сегмент OUTPUT до GSO может быть длиннее MTU: возврат режет его по тому
 * же пределу пути, что проверяет посылки плана (поле 11.11.2026).
 * Метка сырого сокета (0x2d) исключена из очереди правилом D2K_OUT, повторно
 * они не удерживаются. Так уже живут хвосты удержанной пачки UDP (задачи 42,
 * 46). Для TCP-стека DROP в OUTPUT после nf_queue — «отправлено»: номер
 * сдвинут, ретрансмита до нашего повтора (≤ 100 мс, RTO ≥ 200 мс) не будет.
 *
 * Только TLS-удержание. Составной запрос HTTP (порт 80) остаётся на вердиктах:
 * его оригиналу вердикт выдаёт http80 (замена вставки провайдера), и
 * снимать его у ядра здесь нельзя. Режим наблюдения (без сырого сокета) —
 * как было. */
static int hold_owns(const hold_context *c, const uint8_t *p, size_t n) {
    d2k_hold_info v;
    if (!c || !c->raw || !d2k_hold_parse(p, n, &v)) { return 0; }
    const uint8_t *tcp = p + v.ihl;
    return !(tcp[2] == 0 && tcp[3] == 80);
}

/* Socket boundary shared by all pieces of one original. */
typedef struct { d2k_raw *raw; char err[256]; } original_sender;
static int send_original_piece(void *ctx, const uint8_t *p, size_t n) {
    original_sender *s = ctx;
    if (d2k_raw_prepare(s->raw, p, n, s->err, sizeof s->err) != 0) return -1;
    return d2k_raw_send(s->raw, p, n, s->err, sizeof s->err);
}

/* Оригинал уже снят у ядра. Данные возвращаются без изменений; слишком
   большой OUTPUT/GSO-сегмент режется по пределу ЕГО направления, ровно
   тому же d2k_raw_route_maxlen_family, что проверяет план в send_result. */
static int resend_original(hold_context *c, const uint8_t *p, size_t n) {
    original_sender sender = {.raw = c->raw, .err = ""};
    size_t cap = d2k_raw_maxlen(c->raw), sent = 0;
    if (p && n >= 20) {
        uint8_t family = p[0] >> 4;
        if (family == 4 || (family == 6 && n >= 40)) {
            cap = d2k_raw_route_maxlen_family(c->raw, p + (family == 6 ? 24 : 16), family);
        }
    }
    int rc = d2k_resend_original(p, n, cap, send_original_piece, &sender, &sent);
    int saved = errno;
    /* A later piece can fail: count what actually left, without declaring
       the entire original returned or retrying its already-sent prefix. */
    st.emitted += sent;
    st.emitted_now += sent;
    if (rc != 0) {
        st.hold_resend_fail++;
        st.send_fail++;
        if (st.hold_resend_fail <= 16) {
            fprintf(stderr, "d2kd: оригинал приветствия не возвращён на провод: %s\n",
                    sender.err[0] ? sender.err : strerror(saved));
        }
        errno = saved;
        return -1;
    }
    st.hold_resent++;
    if (sent > 1) st.hold_resend_split++;
    return 0;
}

static int preflight_drop(void *ctx, uint32_t id) {
    hold_context *c = ctx;
    char err[256];
    int rc = d2k_nfq_verdict(c->q, id, D2K_NF_DROP, err, sizeof err);
    if (rc) {
        st.verdict_fail++;
        fprintf(stderr, "d2kd: preflight DROP: %s\n", err);
    } else st.dropped++;
    return rc;
}
static int preflight_send(void *ctx, const uint8_t *p, size_t n, uint32_t packet_mark) {
    hold_context *c = ctx;
    char err[256];
    (void)c;
    d2k_raw *sender=packet_mark>=D2K_PF_MARK && packet_mark<=D2K_PF_TOKEN_MARK
        ? preflight_raw[packet_mark-D2K_PF_MARK] : NULL;
    if (!sender) return -1;
    if ((p[0] >> 4) == 6) {
        if (routes.n_oif6)
            (void)d2k_raw_adopt_egress(sender,routes.oif6,routes.n_oif6,NULL,0);
    } else if (routes.n_oif4) {
        (void)d2k_raw_adopt_egress(sender,routes.oif4,routes.n_oif4,NULL,0);
    }
    if (d2k_raw_prepare(sender, p, n, err, sizeof err) != 0 ||
        d2k_raw_send(sender, p, n, err, sizeof err) != 0) {
        st.send_fail++;
        fprintf(stderr, "d2kd: preflight raw send failed: %s\n", err);
        return -1;
    }
    if (packet_mark==D2K_PF_RELEASE_MARK || packet_mark==D2K_PF_TOKEN_MARK)
        preflight_releases_pending++;
    st.emitted++; st.emitted_now++;
    return 0;
}
static int preflight_repeat(d2k_nfq *q,const d2k_nl_pkt *np) {
    if (!np->have_mark || (np->mark!=D2K_PF_RELEASE_MARK && np->mark!=D2K_PF_TOKEN_MARK))
        return 0;
    char err[256];
    d2k_nfq_release_packet(q,np->id,np->mark,D2K_PF_RELEASE_BIT);
    if (d2k_nfq_verdict(q,np->id,D2K_NF_ACCEPT,err,sizeof err))
        fprintf(stderr,"d2kd: preflight repeat failed: %s\n",err);
    else if (preflight_releases_pending) preflight_releases_pending--;
    return 1;
}

static int resend_originals(hold_context *c, const d2k_hold_batch *b) {
    int failed = 0;
    for (size_t i = 0; i < b->orig_count; i++) {
        if (resend_original(c, b->orig[i], b->orig_len[i]) != 0) { failed++; }
    }
    return failed;
}

static void release_original(void *ctx, uint32_t id, const uint8_t *p, size_t n) {
    hold_context *c = ctx;
    /* A released segment is never marked (holds refuse marked packets), and
       the mark of whatever packet is being processed must not reach it, nor
       be lost for that packet (task 47 review I1). */
    uint32_t keep_mark = d2k_session_route_mark(c->sess);
    d2k_session_set_route_mark(c->sess, 0);
    d2k_key udp_key;
    /* A timeout/flush must close the UDP hold transaction as well as release
       the NFQUEUE ID; otherwise the next packet on the same 5-tuple would be
       held against a generation whose originals are already gone. */
    if (d2k_session_udp_hold_begin(c->sess, p, n, now_ns(), &udp_key)) {
        d2k_session_udp_hold_end(c->sess, &udp_key);
    }
    d2k_session_note_unassembled(c->sess, p, n, now_ns());
    d2k_session_observe_tcp(c->sess, p, n, now_ns());
    d2k_session_set_route_mark(c->sess, keep_mark);
    if (hold_owns(c, p, n)) {
        /* Ядро этот сегмент уже отдало (DROP при взятии в слот) — вердикта
           у него нет, на провод он возвращается нашей посылкой. */
        (void)resend_original(c, p, n);
        return;
    }
    (void)send_original_verdict(ctx, id, D2K_NF_ACCEPT);
}

/* ХВОСТ ПОТОКА UDP — ЗА ГОЛОВОЙ, НАШЕЙ ПОСЫЛКОЙ (задачи 42, 46).
 *
 * Датаграмма, пришедшая в conntrack, пока голова потока ещё стояла в очереди,
 * несёт свою неподтверждённую запись; отпущенная ядру после головы, она
 * проигрывает вставку и снимается (insert_failed/drop: 61 из 61 прироста на
 * роутере 03.10.2026 — хвосты ClientHello, 0-RTT, повторы). Поэтому она уходит
 * сырым путём побайтно, как пришла (суммы ядро досчитало до выдачи: GSO в
 * очереди выключен, см. nfq.c), через запись, которую голова только что
 * подтвердила, — с той же трансляцией; копия в очереди снимается. Порядок и
 * владение ID — в d2k_udp_out_* / d2k_udp_path_* (проверяются тестами без
 * сокетов); здесь только сами сокеты. Посылка, которой положено ждать
 * отложенных посылок плана, встаёт в их очередь без ключа: это байты клиента,
 * и уйти они обязаны при любом исходе плана. */
/* Счётчики потока у ядра по кортежу (детекторы «QUIC замолчал», задача 50,
   раунд 3, и «TCP встал на бюджете», задача 56): один неблокирующий запрос
   ctnetlink на наблюдаемый поток. */
typedef struct { int fd; uint32_t seq; int up; int told_off; int told_acct; } ct_link;
static int ct_query(void *ctx, const d2k_ct_tuple *t, d2k_ct_info *out) {
    ct_link *c = ctx;
    if (++c->seq == 0) { c->seq = 1; }
    int rc = d2k_ct_query_info_fd(c->fd, c->seq, t, out);
    if (rc == 2 && !c->told_acct) {
        c->told_acct = 1;
        fprintf(stderr, "d2kd: в записях conntrack нет счётчиков (nf_conntrack_acct выключен) — "
                        "детекторы тишины QUIC и TCP ничего не видят\n");
    }
    return rc;
}

static ct_link ctl_ct = { -1, 0, 0, 0, 0 };

/* Проба ctnetlink (раунд 4, N2): при старте и на обновлении правил/маршрутов,
   НИКОГДА на пакетах. Недоступен — запросов по потокам нет вовсе (иначе ядро
   звало бы модпроб на каждый GET), строка в журнал — один раз. */
static void ct_probe(d2k_session *sess, int startup) {
    if (!sess || ctl_ct.up) { return; }
    if (ctl_ct.fd < 0) { ctl_ct.fd = d2k_ct_open(); }
    if (++ctl_ct.seq == 0) { ctl_ct.seq = 1; }
    if (ctl_ct.fd >= 0 && d2k_ct_probe_fd(ctl_ct.fd, ctl_ct.seq, startup ? 200 : 0) == 1) {
        ctl_ct.up = 1;
        d2k_session_set_ct_query(sess, ct_query, &ctl_ct);
        if (ctl_ct.told_off) {
            fprintf(stderr, "d2kd: ctnetlink появился — детекторы тишины QUIC и TCP включены\n");
        }
        return;
    }
    d2k_session_set_ct_query(sess, NULL, NULL);
    if (!ctl_ct.told_off) {
        ctl_ct.told_off = 1;
        fprintf(stderr, "d2kd: детекторы тишины QUIC и TCP выключены: нет ctnetlink\n");
    }
}

/* ---- ПОЗДНЯЯ ДОСТАВКА (этап 17) ------------------------------------------
 * Опыт на УЖЕ ИДУЩЕМ потоке: его пакеты за окном connbytes в очередь не
 * попадают, повтор клиента под пробой невидим, опыт истекает «опыта не было»
 * (этап 13). Правило S99d2k LATE_WATCH ставит в очередь пакеты записей
 * conntrack с битом late_bit; бит ставит d2kd через ctnetlink на ТОЧНЫЙ кортеж
 * опыта при установке пробы (крючки d2k_ctlsrv) и снимает при её снятии, по
 * сроку (не дольше D2K_LW_MAX_NS) или при уходе контроллера. Ничего
 * глобального: ни перехвата всего трафика, ни отключения ускорителя. Если за
 * время опыта ни один пакет потока за окном не пришёл — это называется в
 * журнале (ускоритель держит поток в железе, поток умер), а не выдаётся за
 * опыт. Метка читается-меняется-пишется целиком: старые ядра без
 * CTA_MARK_MASK иначе затёрли бы биты политики маршрутизации. */
static uint32_t late_bit;       /* --late-watch-mark: бит способа «метка» */
static int late_rules;          /* --late-rules: запасной способ «правила точного кортежа» */
static int late_force_rules;    /* --late-backend rules: только правила (стенд) */
static d2k_lw lwt;
static d2k_lwexec *lwx;


static d2k_session *lw_sess;

/* ---- ИСПОЛНИТЕЛЬ ПОЗДНЕЙ ДОСТАВКИ (этап 53) --------------------------------
   Всё медленное — в потоке исполнителя: своё ctnetlink (метка, перечисление,
   проверка маски) и iptables (правила точного кортежа, -w). Цикл NFQUEUE
   только кладёт заявки и забирает итоги. Состояние исполнителя статическое и
   не освобождается: брошенный при остановке поток может ещё им пользоваться. */
/* Внешний срок одного запуска iptables: при --wait=5 его не достичь; у старого
   iptables (простое -w, ждёт без конца) — он и держит исполнитель. */
static unsigned lwk_child_deadline_s = 15;
static struct {
    int fd;
    uint32_t seq;
    int backend;
    d2k_lwrules rules;
} lwk = { -1, 0, D2K_LW_BACKEND_NONE, { "D2K_LATE_OUT", "D2K_LATE_IN", 0, 5, 0, d2k_lwrules_spawn, &lwk_child_deadline_s } };

static uint32_t lwk_seq(void) { if (++lwk.seq == 0) lwk.seq = 1; return lwk.seq; }

/* Метка (маска подтверждена): одна маскированная запись нашего бита. */
static int lwk_mark(const d2k_ct_tuple *t, int on) {
    if (lwk.fd < 0) return -1;
    int e = d2k_ct_mark_fd(lwk.fd, lwk_seq(), t, on ? late_bit : 0, late_bit, 200);
    return e == 0 ? 0 : e == 2 ? 1 : -1;
}

static int lwk_collect(void *ctx, const d2k_ct_tuple *t, const d2k_ct_info *i) {
    d2k_lw_done *d = ctx;
    if (!i->mark_known || !(i->mark & late_bit)) return 0;
    if (d->n < D2K_LW_SWEEP_LIST) d->list[d->n++] = *t; else d->over = 1;
    return 0;
}

static void lwk_init(d2k_lw_done *d) {
    if (late_bit && !late_force_rules) {
        if (lwk.fd < 0) lwk.fd = d2k_ct_open();
        int mask = lwk.fd >= 0 ? d2k_ct_mask_probe_fd(lwk.fd, &lwk.seq, late_bit, (uint16_t)getpid(), 200) : -1;
        if (mask == 1) { d->backend = D2K_LW_BACKEND_MARK; return; }
        fprintf(stderr, "d2kd: поздняя доставка: метка без маски стёрла бы чужие биты записи (%s)%s\n",
                lwk.fd < 0 ? "нет ctnetlink" : mask == 0 ? "ядро пишет метку conntrack целиком"
                                              : "поведение маски не определить",
                late_rules ? " — способ «правила точного кортежа»" : " — поздняя доставка выключена");
    }
    d->backend = late_rules ? D2K_LW_BACKEND_RULES : D2K_LW_BACKEND_NONE;
}

static void lw_run(void *ctx, const d2k_lw_req *req, d2k_lw_done *d) {
    (void)ctx;
    switch (req->op) {
    case D2K_LWOP_INIT:
        lwk_init(d);
        lwk.backend = d->backend;
        d->rc = 0;
        return;
    case D2K_LWOP_INSTALL:
    case D2K_LWOP_CLEAR: {
        int on = req->op == D2K_LWOP_INSTALL;
        if (lwk.backend == D2K_LW_BACKEND_MARK) d->rc = lwk_mark(&req->t, on);
        else if (lwk.backend == D2K_LW_BACKEND_RULES)
            d->rc = on ? d2k_lwrules_install(&lwk.rules, &req->t) : d2k_lwrules_clear(&lwk.rules, &req->t);
        else d->rc = on ? -1 : 1;
        return;
    }
    case D2K_LWOP_SWEEP:
        if (lwk.backend == D2K_LW_BACKEND_RULES) { d->rc = d2k_lwrules_sweep(&lwk.rules); return; }
        if (lwk.backend != D2K_LW_BACKEND_MARK) { d->rc = 0; d->dump_ok = 1; return; }
        d->rc = 0;
        d->dump_ok = 1;
        for (uint8_t fam = 4; fam <= 6; fam += 2)
            if (d2k_ct_dump_fd(lwk.fd, lwk_seq(), fam, lwk_collect, d, 500) < 0) d->dump_ok = 0;
        return;
    default:
        d->rc = -1;
    }
}

/* Граница d2k_latewatch: исполнитель, сессия, подтверждения контроллеру. */
static d2k_ctlsrv *lw_cx;
static int lw_op_submit(void *ctx, const d2k_lw_req *r) { (void)ctx; return d2k_lwexec_submit(lwx, r); }
static void lw_op_ack(void *ctx, int ok, uint8_t reason, const uint8_t token[D2K_TRIAL_ID_LEN]) {
    (void)ctx; if (lw_cx) d2k_ctlsrv_ack_late(lw_cx, ok, reason, token);
}
static void lw_op_flag(void *ctx, const d2k_ct_tuple *t, int on) {
    (void)ctx; (void)d2k_session_late_watch(lw_sess, t, on);
}
static uint64_t lw_op_delivered(void *ctx) { (void)ctx; return d2k_session_late_delivered(lw_sess); }
static void lw_op_note(void *ctx, const d2k_ct_tuple *t, uint8_t code, uint32_t repeats,
                       const uint8_t token[D2K_TRIAL_ID_LEN], uint64_t now) {
    (void)ctx; d2k_session_note_lateobs(lw_sess, t, code, repeats, token, now);
}
static void lw_op_say(void *ctx, const char *line) { (void)ctx; fprintf(stderr, "%s\n", line); }

static int lw_raw_identity(void *ctx,const struct d2k_rawmeasure_request *r,int *previous) {
    (void)ctx;uint8_t epoch[16];uint64_t generation;
    return !d2k_session_raw_identity(lw_sess,&r->tuple,epoch,&generation,previous) &&
           generation==r->generation && !memcmp(epoch,r->epoch,16);
}
static void lw_raw_ack(void *ctx,int ok,uint8_t reason,const uint8_t token[16]) {
    (void)ctx;if(lw_cx)d2k_ctlsrv_ack_raw_measure(lw_cx,ok,reason,token);
}
static void lw_raw_note(void *ctx,const struct d2k_rawmeasure_report *r) {
    (void)ctx;if(lw_cx)(void)d2k_ctlsrv_raw_measure(lw_cx,r);
}
static void raw_measure_hook(void *ctx,const struct d2k_rawmeasure_request *r) {
    (void)ctx;d2k_lw_measure(&lwt,r,now_ns());
}

/* Контроллер отключился — его наблюдения и опыты отменяются сразу (этап 53). */
static void late_peer_closed(void *ctx) { (void)ctx; d2k_lw_peer_closed(&lwt, now_ns()); }

/* D2K_CMD_LATE_OBSERVE (этап 49): наблюдение точного потока; подтверждение —
   по готовности доставки (этап 53). */
static void late_observe_hook(void *ctx, const d2k_ct_tuple *t, uint32_t seconds,
                              const uint8_t token[D2K_TRIAL_ID_LEN]) {
    (void)ctx;
    d2k_lw_observe(&lwt, t, seconds, token, now_ns());
}

static void late_addr_hook(void *ctx, const d2k_addr_probe_flow *flow, uint64_t expires_ns, int installed) {
    (void)ctx;
    d2k_ct_tuple t;
    memset(&t, 0, sizeof t);
    t.family = flow->family == 6 ? 6 : 4;
    /* Measured probes also own TCP continuations beyond the initial window. */
    t.proto = flow->transport;
    memcpy(t.src, t.family == 6 ? flow->src_ip6 : flow->src_ip4, t.family == 6 ? 16 : 4);
    memcpy(t.dst, t.family == 6 ? flow->dst_ip6 : flow->dst_ip4, t.family == 6 ? 16 : 4);
    memcpy(t.sport_be, &flow->src_port_be, 2);
    memcpy(t.dport_be, &flow->dst_port_be, 2);
    if (installed) { (void)d2k_lw_trial_add(&lwt, &t, expires_ns, now_ns()); } else { d2k_lw_trial_del(&lwt, &t, now_ns()); }
}

static void late_name_hook(void *ctx, const uint8_t *name, size_t len, uint8_t transport, uint8_t family,
                           uint16_t sport_be, uint64_t expires_ns, int installed) {
    (void)ctx; (void)transport;
    d2k_ct_tuple t;
    if (d2k_session_tcp_tuple_by_port(lw_sess, name, len, family, sport_be, &t) != 0) {
        /* Поток с этим портом в таблице не наблюдается: метить нечего. Это не
           отказ опыта — проба порта стоит, новый поток клиента её получит. */
        return;
    }
    if (installed) { (void)d2k_lw_trial_add(&lwt, &t, expires_ns, now_ns()); } else { d2k_lw_trial_del(&lwt, &t, now_ns()); }
}

static int out_verdict(void *ctx, uint32_t id, uint32_t verdict) {
    return send_original_verdict(ctx, id, verdict);
}

/* Отказ переиздания считается здесь; строка журнала — одна на поток, с
   адресом, семейством и длиной (out_resend_failed). errno сохраняется для неё. */
static int out_fail(int err) {
    st.send_fail++;
    errno = err;
    return -1;
}

/* МЕТКА КЛИЕНТА — ЕГО МАРШРУТ (поле 03.10, задача 46). Keenetic метит пакеты
   клиента с маршрутизацией по доменам/политике (PREROUTING mangle,
   0xffffaaa -> таблица 4096, например VPN) ДО нашей очереди в POSTROUTING.
   Сырая посылка с меткой d2k ушла бы мимо этой таблицы — через ppp0.
   Такие датаграммы идут ядром, как раньше; поток отмечается один раз. */
static unsigned port_of(const void *p);
static void out_marked(void *ctx, const uint8_t *p, size_t n, uint32_t mark) {
    (void)ctx;
    st.udp_marked_kept++;
    if (st.udp_marked_kept <= 16) {
        d2k_packet_view v;
        unsigned sport = 0, dport = 0;
        if (d2k_packet_parse(p, n, &v) && v.l4 + 4 <= n) {
            sport = port_of(p + v.l4);
            dport = port_of(p + v.l4 + 2);
        }
        if (mark == D2K_ROUTE_OTHER_DEV) {
            fprintf(stderr, "d2kd: поток UDP %u -> %u уходит через другой интерфейс: хвосты "
                            "идут ядром, не сырой посылкой%s\n", sport, dport,
                    st.udp_marked_kept == 16 ? " (дальше только счётчик)" : "");
        } else {
            fprintf(stderr, "d2kd: поток UDP %u -> %u с меткой клиента 0x%x: хвосты идут ядром, "
                            "не сырой посылкой%s\n", sport, dport, mark,
                    st.udp_marked_kept == 16 ? " (дальше только счётчик)" : "");
        }
    }
}

/* Вердикт клиентской датаграммы — позже, за отложенной головой плана
   (ревью 4 задачи 46, I3): кольцо отложенных вердиктов сливается после
   очереди сырых посылок того же прохода. Нет места — вердикт сразу. */
static int out_defer(void *ctx, uint64_t at, uint32_t id, uint32_t verdict) {
    static const d2k_key none = {.proto = 17};
    if (udp_releases &&
        d2k_udp_release_enqueue(udp_releases, at, &id, &verdict, 1, &none, 0) == 0) {
        return 0;
    }
    return send_original_verdict(ctx, id, verdict);
}

/* Одна строка на поток (поле 03.10: «sendto: Permission denied» 17 раз за
   35 мин без единого адреса). */
static void out_resend_failed(void *ctx, const uint8_t *p, size_t n, int err) {
    (void)ctx;
    d2k_packet_view v;
    char src[64] = "?", dst[64] = "?";
    unsigned sport = 0, dport = 0;
    int fam = 0;
    if (d2k_packet_parse(p, n, &v) && v.l4 + 4 <= n) {
        fam = v.family;
        (void)inet_ntop(fam == 6 ? AF_INET6 : AF_INET, v.src.bytes, src, sizeof src);
        (void)inet_ntop(fam == 6 ? AF_INET6 : AF_INET, v.dst.bytes, dst, sizeof dst);
        sport = port_of(p + v.l4);
        dport = port_of(p + v.l4 + 2);
    }
    /* Вызывается для первых D2K_UDP_REFUSED_LOG потоков (финальное ревью
       M-7); остальные — счётчик в сводке. */
    fprintf(stderr, "d2kd: поток UDP %s:%u -> %s:%u (IPv%d, %zu байт): хвост не переиздан, "
                    "отдаю ядру, поток дальше без переиздания: %s%s\n",
            src, sport, dst, dport, fam, n, strerror(err),
            d2k_udp_follow_refused(udp_follow) == D2K_UDP_REFUSED_LOG
                ? " (дальше только счётчик)" : "");
}

static int out_send_now(void *ctx, const uint8_t *p, size_t n) {
    hold_context *c = ctx;
    char err[256];
    if (!c->raw) { return out_fail(ENOTSOCK); }
    if (d2k_raw_prepare(c->raw, p, n, err, sizeof err) != 0 ||
        d2k_raw_send(c->raw, p, n, err, sizeof err) != 0) {
        return out_fail(errno ? errno : EIO);
    }
    st.emitted++;
    st.emitted_now++;
    return 0;
}

static int out_send_at(void *ctx, uint64_t at, const uint8_t *p, size_t n) {
    hold_context *c = ctx;
    char err[256];
    if (!c->raw || !c->sched) { return out_fail(ENOTSOCK); }
    if (d2k_raw_prepare(c->raw, p, n, err, sizeof err) != 0) { return out_fail(errno ? errno : EIO); }
    if (d2k_sched_push_serial(c->sched, at, p, n, NULL, 0) != 0) {
        return out_fail(ENOSPC);   /* очередь отложенных полна — не «сокет полон» */
    }
    st.deferred++;
    return 0;
}

/* То же, но очередь владеет ID копии до выдачи (ревью I-A m-2). */
static int out_send_at_owned(void *ctx, uint64_t at, const uint8_t *p, size_t n, uint32_t id) {
    hold_context *c = ctx;
    char err[256];
    if (!c->raw || !c->sched) { return out_fail(ENOTSOCK); }
    if (d2k_raw_prepare(c->raw, p, n, err, sizeof err) != 0) { return out_fail(errno ? errno : EIO); }
    if (d2k_sched_push_owned(c->sched, at, p, n, id) != 0) {
        return out_fail(ENOSPC);
    }
    st.deferred++;
    return 0;
}

/* --- вставка провайдера в открытый HTTP (задача 51) -----------------------
 * Узнаётся по первым пакетам потока порта 80 (d2k_http80.h). Строка журнала
 * на каждую узнанную вставку: они редки (только заблокированные имена), а
 * без строки «HTTP не открылся» не отличить от «сайт лежит». */
static d2k_http80 *http80;

static void http80_log(const d2k_http80_res *r, const char *outcome) {
    char srv[64] = "?";
    d2k_addr a;
    memset(&a, 0, sizeof a);
    a.family = r->family;
    memcpy(a.bytes, r->server, sizeof a.bytes);
    (void)d2k_addr_text(&a, srv, sizeof srv);
    fprintf(stderr, "d2kd: HTTP %s (IPv%u %s:%u): вставка провайдера — 30x на %s через %" PRIu64
                    " мкс после запроса при RTT потока %" PRIu64 " мкс; %s\n",
            r->host, (unsigned)r->family, srv, (unsigned)r->server_port, r->portal,
            r->reply_ns / 1000u, r->rtt_ns / 1000u, outcome);
}

/* Вердикты и RST для d2k_http80_swap: настоящие очередь и сырой сокет. */
typedef struct { d2k_nfq *q; d2k_raw *raw; uint32_t id; } http80_ctx;

static int http80_io_payload(void *c, const uint8_t *p, size_t n) {
    http80_ctx *x = c;
    char err[200];
    if (d2k_nfq_verdict_payload(x->q, x->id, D2K_NF_ACCEPT, p, n, err, sizeof err) != 0) {
        st.verdict_fail++;
        fprintf(stderr, "d2kd: %s\n", err);
        return -1;
    }
    st.accepted++;
    return 0;
}

static int http80_io_accept(void *c) {
    http80_ctx *x = c;
    char err[200];
    if (d2k_nfq_verdict(x->q, x->id, D2K_NF_ACCEPT, err, sizeof err) != 0) {
        st.verdict_fail++;
        fprintf(stderr, "d2kd: %s\n", err);
        return -1;
    }
    st.accepted++;
    return 0;
}

static int http80_io_rst(void *c, const uint8_t *p, size_t n) {
    http80_ctx *x = c;
    char err[200];
    if (d2k_raw_send(x->raw, p, n, err, sizeof err) != 0) {
        int e = errno;
        st.send_fail++;
        log_send_fail("RST к серверу после 307: ", err, e);
        return -1;
    }
    st.emitted++;
    return 0;
}

/* Пакет очереди глазами http80. 1 — пакет обработан здесь (вердикт уже
   отправлен), 0 — дальше обычным путём. Заменять и снимать — только в
   режиме apply с сырым сокетом: в наблюдении трафик не трогается. */
/* ОБРЫВ ОТВЕТА БЕЗ ПОРТАЛА (поле 15.10.2026, media5.cdnbase.com): ответ с
   заявленной длиной встал раньше конца. Контроллеру — всегда, и без плана:
   иначе имя не попадает в замер вовсе. */
static void http80_cut(void *ctx, const d2k_http80_res *r) {
    d2k_ctl *ctl = ctx;
    fprintf(stderr, "d2kd: HTTP обрыв ответа host=%s path=%s: тело %llu байт, до заявленной длины "
                    "не дошло (запрос %llu потока, RTT %llu мс)\n",
            r->host, r->request_path[0] ? r->request_path : "-",
            (unsigned long long)r->body_bytes, (unsigned long long)r->request_no,
            (unsigned long long)(r->rtt_ns / 1000000ull));
    d2k_ctlsrv_http80_event(ctl, r);
}

static int http80_step(d2k_nfq *q, d2k_raw *raw, d2k_ctl *ctl, uint32_t id,
                       const uint8_t *p, size_t n, uint64_t t, uint64_t kstamp, d2k_http80_res *observation) {
    if (!http80) { return 0; }
    static uint8_t out[D2K_HTTP80_TARGET_MAX + 1024];
    static uint8_t rst[128];
    char err[200];
    d2k_http80_res r;
    d2k_http80_packet(http80, p, n, t, kstamp, raw ? out : NULL, raw ? sizeof out : 0,
                      rst, sizeof rst, &r);
    *observation=r;
    if (r.response == D2K_HTTP80_CUT) { http80_cut(ctl, &r); }
    /* Событие — после исхода замены (ревью N1): признак «307 ушёл» в нём
       верный, и контроллер не повторяет SET_HTTPS зря. */
    if (r.injection && (r.action != D2K_HTTP80_REPLACE || !raw)) { d2k_ctlsrv_http80_event(ctl, &r); }
    if (r.action == D2K_HTTP80_DROP && raw) {
        if (d2k_nfq_verdict(q, id, D2K_NF_DROP, err, sizeof err) != 0) {
            st.verdict_fail++;
            fprintf(stderr, "d2kd: %s\n", err);
        } else {
            st.dropped++;
        }
        return 1;
    }
    if (r.action != D2K_HTTP80_REPLACE || !raw) {
        if (r.injection) {
            http80_log(&r, raw ? "HTTPS имени не подтверждён и не срезан — пропущена клиенту как есть"
                               : "наблюдение — пропущена как есть");
        }
        return 0;
    }
    /* Одна строка на каждую замену: по ней полевая проверка видит, что 307
       ушёл, или что ядро не приняло вердикт и ушла сама вставка. */
    http80_ctx x = {q, raw, id};
    d2k_http80_io io = {http80_io_payload, http80_io_accept, http80_io_rst, &x};
    int swapped = d2k_http80_swap(http80, &r, out, rst, &io);
    d2k_ctlsrv_http80_event(ctl, &r);
    if (swapped) {
        http80_log(&r, "замена: клиенту 307 на https, серверу RST");
    } else {
        http80_log(&r, "замена НЕ ушла (вердикт с заменой отвергнут) — вставка пропущена как есть, "
                       "поток не тронут");
    }
    return 1;
}

static const char *MODE_NAMES[] = {"observe", "apply"};

static void usage(void) {
    fprintf(stderr,
        "d2kd — служба датапата d2k\n"
        "\n"
        "  --queue N          номер очереди NFQUEUE (обязательно)\n"
        "  --plan FILE        план в канонической форме TLV\n"
        "  --watch-release-bit M  opt-in firewall watch-release handshake bit\n"
        "  --late-watch-mark M  opt-in: бит connmark, которым d2kd помечает через ctnetlink запись\n"
        "                     ТОЧНОГО потока опыта, чтобы его пакеты за окном connbytes шли в очередь\n"
        "                     (правило LATE_WATCH в S99d2k); снимается при снятии опыта или по сроку\n"
        "  --late-rules         запасной способ поздней доставки без connmark (ядро без маски метки):\n"
        "                     правила точного кортежа conntrack в своих цепочках D2K_LATE_OUT/D2K_LATE_IN\n"
        "  --late-backend rules только правила точного кортежа (стенд)\n"
        "  --adopt-ports LIST  на старте принять из conntrack уже существующие TCP/UDP потоки к этим\n"
        "                     портам сервера (например 443,3478:3481); наблюдаются только счётчиками\n"
        "  --mode observe|apply   умолчание observe: ничего не менять\n"
        "  --mark M           SO_MARK на собственных пакетах (умолчание 0)\n"
        "  --probe-mark M     SO_MARK контроллера; его зонды не становятся новыми целями\n"
        "  --only-mark M[/K]|none  только клиенты политики Keenetic с этой меткой;\n"
        "                     none — политика не найдена, клиентов не обслуживать\n"
        "  --preflight        пробное TCP-соединение по endpoint-плану или известному IP провайдера\n"
        "  --provider-ips FILE  сохранённые DNS-адреса googlevideo/gvt1 для preflight\n"
        "  --preflight-ipv6   разрешить пробу на маршрутизируемом IPv6 без NAT\n"
        "  --udp-reverse-hook обратное UDP-направление гарантированно стоит в NFQUEUE\n"
        "  --iface NAME       чей MTU берётся пределом длины посылки\n"
        "  --flows N          предел числа потоков — отдельно на TCP и на\n"
        "                     UDP/QUIC, не общий бюджет датапата (2048)\n"
        "  --queue-len N      глубина очереди ядра в пакетах (1024)\n"
        "  --copy-range N     сколько байт пакета брать у ядра (1600)\n"
        "  --sched-slots N    сколько отложенных пакетов держать (128)\n"
        "  --journal N        глубина диагностического журнала, 0 — без него (256)\n"
        "  --control PATH     управляющий сокет для контроллера\n"
        "  --exp-control PATH сокет опытов новой цепочки: только пробный план на свой порт\n"
        "  --idle SEC         молчащий поток забывается через (120)\n"
        "  --log FILE         писать вывод сюда вместо stdout\n"
        "  --stats SEC        период печати сводки, 0 — не печатать (10)\n"
        "  --duration SEC     остановиться через N секунд, 0 — бесконечно\n"
        "  --no-fail-open     НЕ пропускать при переполнении очереди\n"
        "\n"
        "Без --mode apply служба ничего не меняет в трафике.\n");
}

static int arg_u32(const char *v, uint32_t *out) {
    char *end = NULL;
    unsigned long n = strtoul(v, &end, 0);
    if (!end || *end != '\0' || n > 0xffffffffUL) {
        return -1;
    }
    *out = (uint32_t)n;
    return 0;
}

static unsigned port_of(const void *p) {
    const uint8_t *b = p;
    return (unsigned)b[0] << 8 | b[1];
}

static void print_stats(const d2k_session *s, const d2k_sched *sched,
                        const d2k_nfq *q, const d2k_raw *r, uint64_t run_ns) {
    uint64_t cpu_ms = 0, rss_kb = 0;
    self_cost(&cpu_ms, &rss_kb);
    uint64_t secs = run_ns / NS_PER_S;
    /* Номер процесса в каждой сводке. Журнал дописывается через перезапуски,
       и «последний блок» без подписи принадлежит неизвестно кому: однажды я
       приписал показания одного экземпляра другому и сутки искал дефект,
       которого в той настройке не было. */
    printf("--- d2kd[%ld], %" PRIu64 " с; процессор %" PRIu64 " мс (%" PRIu64
           ",%" PRIu64 " %%), RSS %" PRIu64 " КиБ ---\n",
           (long)getpid(), secs, cpu_ms,
           secs ? cpu_ms / (secs * 10) : 0,
           secs ? (cpu_ms * 10 / secs) % 100 : 0,
           rss_kb);
    if (http80) {
        d2k_http80_stats hst = d2k_http80_get_stats(http80);
        if (hst.requests || hst.injections || hst.untracked || hst.unparsed || hst.later) {
            /* Хвост — нагрузка клиента, где вставку не узнать: без него
               портал в браузере при «запросов +0» не отличить от «запроса
               к :80 не было» (поле 04.10.2026). */
            printf("HTTP: запросов %" PRIu64 ", вставок провайдера %" PRIu64
                   ", потоков вытеснено %" PRIu64 "; не разобрать, пакетов клиента: "
                   "поток без SYN %" PRIu64 ", не целый запрос %" PRIu64
                   ", после первой нагрузки потока %" PRIu64 "\n",
                   hst.requests, hst.injections, hst.evicted,
                   hst.untracked, hst.unparsed, hst.later);
        }
    }
    d2k_hold_stats hs;
    d2k_hold_get_stats(holding, &hs);
    printf("составной вход: начато=%" PRIu64 " собрано=%" PRIu64
           " отпущено=%" PRIu64 " таймаутов=%" PRIu64 " (пакетов в них=%" PRIu64 ")"
           " по смене плана=%" PRIu64 " по сбросу=%" PRIu64
           " добавлено к голове=%" PRIu64 " несовместимых=%" PRIu64
           " с другой стороны=%" PRIu64
           " отказов ёмкости=%" PRIu64 " ожидающих пакетов=%zu\n",
           hs.started, hs.ready, hs.released, hs.timed_out, hs.timed_out_pkts,
           hs.plan_changed, hs.dropped_all, hs.joined, hs.mismatched, hs.sided,
           hs.full, hs.pending);
    printf("владение приветствием: взято у ядра=%" PRIu64
           " возвращено на провод оригиналов=%" PRIu64 " не возвращено=%" PRIu64
           " возвращено нарезкой=%" PRIu64 "\n",
           st.hold_owned, st.hold_resent, st.hold_resend_fail, st.hold_resend_split);
    printf("пакетов %" PRIu64 ", байт %" PRIu64
           ", пропущено %" PRIu64 ", снято %" PRIu64 "\n",
           st.seen, st.bytes, st.accepted, st.dropped);
    if (st.icmp_seen || d2k_icmpguard_noted(&icmpg)) {
        printf("ICMP time-exceeded: получено %" PRIu64 ", снято на свои фальшивки %" PRIu64
               "; фальшивок с пониженным TTL запомнено %" PRIu64 "\n",
               st.icmp_seen, d2k_icmpguard_dropped(&icmpg), d2k_icmpguard_noted(&icmpg));
    }
    /* Счёт применений берётся у сессии, а не свой. Своя переменная считала
       применения по числу выпущенных пакетов, и план из одной защиты — без
       единой посылки — показывался как «применён 0», хотя журнал той же
       минутой писал «план применён». Один факт не может иметь двух счётчиков. */
    printf("план подготовлен %" PRIu64 ", ДОИСПОЛНЕН %" PRIu64
           ", выпущено %" PRIu64 ", отложено %" PRIu64
           " (сразу %" PRIu64 ", из очереди %" PRIu64 ")"
           ", потоков испорчено %" PRIu64 ", отложенных протухло %" PRIu64 ", уведомлений потеряно %" PRIu64 "\n",
           d2k_session_applied(s), d2k_session_done(s), st.emitted, st.deferred,
           st.emitted_now, st.emitted_late,
           d2k_session_damaged_count(s), st.stale_deferred, d2k_session_sent_lost(s));
    /* Второе число — предел таблицы, а не что попало. В первом полевом
       прогоне здесь стояла длина очереди отправки, и строка читалась как
       «23 потока из 0».
       TCP и UDP — раздельно, а не суммой (ревью задачи 4, круг 2): --flows
       задаёт ёмкость КАЖДОЙ таблицы отдельно, и сумма топит ситуацию «одна
       таблица уже у предела, другая пустая» в благополучном на вид числе —
       например, «1600 из 4096» читается как 39% занятости ровно в момент,
       когда TCP-таблица (2048 потоков, порог отказа 3/4 — 1536) уже
       отказывает. По той же причине — отказы каждой таблицы отдельно: сумма
       не говорит, какая из двух реально отказывала. */
    printf("потоков TCP %zu из %zu (отказов %" PRIu64 "), "
           "UDP %zu из %zu (отказов %" PRIu64 ")\n",
           d2k_session_flows_tcp(s), d2k_session_capacity_tcp(s),
           d2k_session_refusals_tcp(s),
           d2k_session_flows_udp(s), d2k_session_capacity_udp(s),
           d2k_session_refusals_udp(s));
    printf("узнано приветствий %" PRIu64 ", из них с именем %" PRIu64
           ", обменов %" PRIu64 ", подозрений %" PRIu64
           ", снято чужих сбросов %" PRIu64 "\n",
           d2k_session_hellos(s), d2k_session_with_sni(s),
           d2k_session_exchanges(s), d2k_session_suspects(s),
           d2k_session_rst_dropped(s));
    /* Видимость ответов (ускоритель Keenetic уводит поток мимо очереди).
       Формат строки читает d2k-ppe-deoffload.sh status — менять вместе. */
    printf("ответ невидим очереди: %" PRIu64 " из %" PRIu64
           " TCP-потоков с приветствием\n",
           d2k_session_reply_hidden(s), d2k_session_tcp_hello_flows(s));
    printf("в очереди отправки %zu, отказов расписания %" PRIu64 "\n",
           d2k_sched_count(sched), d2k_sched_refusals(sched));
    printf("обрезано %" PRIu64 ", без нагрузки %" PRIu64
           ", без заголовка %" PRIu64 "\n",
           st.truncated, st.no_payload, st.no_hdr);
    {
        d2k_payload_stats ps;
        d2k_session_payload_stats(s, &ps);
        printf("нагрузка мимо приветствия: обратная %" PRIu64
               ", после приветствия %" PRIu64 ", за окном %" PRIu64
               ", не приветствие %" PRIu64 " (первый байт %#02x)\n",
               ps.reverse, ps.after_hello, ps.late, ps.not_hello,
               ps.last_first_byte);
        printf("имя уехало во второй сегмент: %" PRIu64 "\n", ps.sni_next_seg);
        /* Этап 42: подавленные ограничением объёма потоки контроллер не
           наблюдает — предел виден числом. */
        printf("поток без протокола: сообщено %" PRIu64 ", подавлено %" PRIu64 "\n",
               ps.flow_told, ps.flow_suppressed);
        if (ps.http_later || ps.http_unaligned || ps.http_open_end) {
            /* Keep-alive (поле 04.10.2026): следующие запросы соединения
               получают план, только начинаясь на известной границе с начала
               сегмента; прочие идут как есть — их счёт здесь. */
            printf("HTTP keep-alive: следующих запросов узнано %" PRIu64
                   ", граница не на начале сегмента %" PRIu64
                   ", конец запроса неизвестен %" PRIu64 "\n",
                   ps.http_later, ps.http_unaligned, ps.http_open_end);
        }
        printf("снимки TCP: полных=%" PRIu64 " отвергнутых=%" PRIu64
               " истекших=%" PRIu64 " отказов ёмкости=%" PRIu64 "\n",
               ps.capture_complete, ps.capture_rejected,
               ps.capture_expired, ps.capture_full);
    }
    if (lwx) {
        printf("поздняя доставка (%s): поставлено %" PRIu64 ", снято %" PRIu64 ", записи не стало %" PRIu64
               ", установка не подтверждена %" PRIu64 ", снятие не подтверждено (повтор) %" PRIu64
               ", ждут снятия %zu, очередь исполнителя полна %" PRIu64 ", в исполнителе %zu, без пакетов %" PRIu64
               "; датаграмм за окном принято в опыт %" PRIu64 "\n",
               lwt.backend == D2K_LW_BACKEND_MARK ? "метка" : lwt.backend == D2K_LW_BACKEND_RULES ? "правила" : "нет",
               lwt.st.set, lwt.st.cleared, lwt.st.gone, lwt.st.install_fail, lwt.st.clear_fail,
               d2k_lw_pending_clears(&lwt), lwt.st.queue_full, d2k_lwexec_pending(lwx), lwt.st.silent,
               d2k_session_late_delivered(s));
    }
    printf("потеряно ядром %" PRIu64 ", ошибок вердикта %" PRIu64
           ", ошибок отправки %" PRIu64 ", ошибок чтения %" PRIu64 "\n",
           d2k_nfq_lost(q), st.verdict_fail, st.send_fail, st.recv_err);
    if (r) {
        {
        /* Ведётся ли поток conntrack (d2k_nat.h): без этого посылки плана
           уходят мимо NAT, и обход работает только для трафика самого
           роутера. */
        uint64_t nok = 0, nm = 0, nn = 0, nr = 0;
        d2k_session_nat_stats(&nok, &nm, &nn, &nr);
        printf("поток ведётся conntrack: да %" PRIu64 ", нет %" PRIu64
               ", таблицы нет %" PRIu64 ", спасла перепроверка %" PRIu64 "\n",
               nok, nm, nn, nr);
    }
    printf("потоков клиентов с меткой маршрутизации (ядром, без плана): %" PRIu64 "\n",
           d2k_session_routed_flows(s));
    printf("UDP с меткой клиента или через другой интерфейс, хвосты ядром: %" PRIu64
           " потоков\n", st.udp_marked_kept);
    printf("сырым сокетом отправлено %" PRIu64 ", ошибок %" PRIu64
           " (из них сокет полон %" PRIu64 ")\n",
               d2k_raw_sent(r), d2k_raw_errors(r), d2k_raw_busy(r));
    printf("UDP переиздание: отказано потоков %" PRIu64 ", сокет полон %" PRIu64
           " раз, очередь отложенных полна %" PRIu64 " раз; уведомлений о правилах/"
           "маршрутах %" PRIu64 "\n",
           d2k_udp_follow_refused(udp_follow), d2k_udp_follow_busy(udp_follow),
           d2k_udp_follow_queue_full(udp_follow), st.routes_watch);
    }
    printf("отказов по форме приветствия %zu\n",
           d2k_plantab_shape_misses(d2k_session_plans((d2k_session *)s)));
    printf("планов по целям %zu из %zu\n",
           d2k_session_plan_count(s), d2k_session_plan_capacity(s));
    for (size_t i = 0; i < n_reasons; i++) {
        printf("  пропуск «%s»: %" PRIu64 "\n", reasons[i].text, reasons[i].n);
    }
    fflush(stdout);
}

/* Порт в ключе лежит в сетевом порядке — ровно как в заголовке. Читаем его
   как сетевой, а не переставляем байты «наугад»: перестановка вслепую уже
   стоила ошибки в контрольных суммах. */

/* Для показа. Источник истины — числовой код в ключе (d2k_key.proto), а не
   этот текст: сравнивать поведение по строке нельзя (тот же принцип, что и
   у d2k_suspect_text). */
static const char *proto_name(uint8_t proto) {
    switch (proto) {
    case 6:  return "tcp";
    case 17: return "udp";
    default: return "?";
    }
}

/* Все виды записей названы вслух. Пропущенный вид печатался «?», и в
   диагностике лаборатории 13.09 судьба посылок выглядела как «?план
   доисполнен» — читатель видел знак вопроса там, где всё сошлось. */
static const char *jrn_kind(uint8_t k) {
    switch (k) {
    case D2K_JRN_PREFLIGHT_START: return "preflight START";
    case D2K_JRN_PREFLIGHT_HANDOVER: return "preflight HANDOVER";
    case D2K_JRN_PREFLIGHT_GAVE_UP: return "preflight GAVE_UP";
    case D2K_JRN_HELLO_SNI:     return "приветствие";
    case D2K_JRN_HELLO_NONAME:  return "приветствие без имени";
    case D2K_JRN_PLAN_APPLIED:  return "план применён";
    case D2K_JRN_PLAN_REFUSED:  return "план не применён";
    case D2K_JRN_SUSPECT:       return "подозрение";
    case D2K_JRN_EXCHANGE:      return "обмен пошёл";
    case D2K_JRN_SHAPE:         return "снята форма приветствия";
    /* У этой записи всё сказано в пояснении («план доисполнен»), и вид
       печатать нечем: «план: план доисполнен» — не строка для человека. */
    case D2K_JRN_PLAN_DONE:     return "";
    case D2K_JRN_PLAN_UNSENT:   return "посылка не ушла";
    case D2K_JRN_PLAN_DAMAGED:  return "поток испорчен";
    case D2K_JRN_FLOW:          return "поток без протокола появился";
    default:                    return "запись неизвестного вида";
    }
}

/* Журнал печатается один раз, в конце: это диагностика, а не поток событий.
 * Печатать его на каждом тике значило бы утопить сводку. */
static void print_journal(const d2k_session *s, uint64_t start) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j);
    if (n == 0) {
        printf("журнал пуст\n");
        return;
    }
    printf("--- журнал: %zu записей, затёрто %" PRIu64 " ---\n",
           n, d2k_journal_dropped(j));
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (!e) {
            continue;
        }
        if (e->kind == D2K_JRN_PREFLIGHT_START || e->kind == D2K_JRN_PREFLIGHT_HANDOVER ||
            e->kind == D2K_JRN_PREFLIGHT_GAVE_UP) {
            printf("  preflight K=%u elapsed_ns=%" PRIu64 " client_side=%u plan=", e->num,
                   e->preflight_elapsed_ns, e->d_client_side);
            for (size_t k=0;k<D2K_PLAN_ID_LEN;k++) printf("%02x",e->plan_id[k]);
            printf("\n");
        }
        /* Ключ канонизирован: «низкая» и «высокая» стороны, а не источник и
           назначение. Печатается как пара, через тире, чтобы стрелка не врала
           о направлении. */
        const uint8_t *la = (const uint8_t *)&e->key.low_ip;
        const uint8_t *ha = (const uint8_t *)&e->key.high_ip;
        printf("  %6" PRIu64 " мс  %s %u.%u.%u.%u:%u - %u.%u.%u.%u:%u  %s%s%s%s%s\n",
               (e->at_ns - start) / NS_PER_MS,
               proto_name(e->key.proto),
               la[0], la[1], la[2], la[3], port_of(&e->key.low_port),
               ha[0], ha[1], ha[2], ha[3], port_of(&e->key.high_port),
               jrn_kind(e->kind),
               e->name_len ? " " : "", e->name_len ? e->name : "",
               /* Пояснение отделяется двоеточием: без него «план не
                  применён» и «плана для этой цели нет» слипались в одно
                  слово. И только там, где есть ЧТО отделять: у записи о
                  судьбе посылок вид пустой, и строка начиналась бы с него. */
               (e->note && jrn_kind(e->kind)[0]) ? ": " : "",
               e->note ? e->note : "");
    }
    fflush(stdout);
}

/* Причина отказа отправки кодом журнала. Различаем ровно то, что различимо:
   «длиннее того, что унесёт способ отправки» отделено от прочих отказов ядра,
   потому что это ЕДИНСТВЕННАЯ причина, которую можно было предвидеть заранее
   (d2k_plan_fits) — её появление здесь означает, что предел разошёлся с
   настоящим, например MTU сменился под нами после старта (см. d2k_raw_open).
   Остальное сваливается в D2K_REFUSE_SEND намеренно: выдумывать по errno
   градации, которых журнал не различает, значило бы обещать точность,
   которой нет. */
static uint8_t refuse_of_errno(int e) {
    return (e == EMSGSIZE) ? D2K_REFUSE_TOO_LONG : D2K_REFUSE_SEND;
}

/* Both queued originals and post-NAT continuations use this sender. */
static int send_result(d2k_session *sess, d2k_raw *raw, d2k_sched *sched,
    int mode, uint64_t t, d2k_result *result, const uint8_t *obuf,
    const uint8_t *original, size_t original_len, uint32_t *v,
    int *payload_sent, uint64_t *last_at) {
    d2k_result res = *result;
    uint32_t verdict = *v;
    char err[256];
    int output_failed = 0;
    if (mode == MODE_APPLY && raw && res.applied) {
        /* Предел КАЖДОЙ ПОСЫЛКИ по ЕЁ направлению, а не один
           общий на план: общий не знает ни про туннель,
           поднятый к другой цели, ни про PMTU этого маршрута.
           Адрес берётся из самого пакета (байты 16..19
           заголовка IPv4), а не из ключа потока: ключ
           канонический — в нём «низкий» и «высокий» конец, а
           не источник и назначение. Маршрут спрашивается раз на
           направление (d2k_raw_route_maxlen), дальше —
           сравнение чисел. */
        size_t cap = d2k_raw_maxlen(raw);
        size_t too_long = 0;
        for (size_t k = 0; k < res.n_out; k++) {
            const uint8_t *ip = obuf + res.out[k].off;
            uint8_t family = ip[0] >> 4;
            size_t here = res.out[k].len >= (family == 6 ? 40u : 20u)
                ? d2k_raw_route_maxlen_family(raw, ip + (family == 6 ? 24 : 16), family)
                : cap;
            if (res.out[k].len > here) {
                too_long = res.out[k].len;
                cap = here;
                break;
            }
        }
        if (too_long) {
            fprintf(stderr,
                "d2kd: план не исполнен: посылка %zu байт при пределе %zu\n",
                too_long, cap);
            st.send_fail++;
            output_failed = 1;
            res.n_out = 0;
            /* Ничего не ушло и вердикт не отправлен — исход
               считает общая политика, а не эта ветка. */
            if (d2k_session_exec_failed(sess, t, &res.key, res.plan_id,
                                        D2K_REFUSE_TOO_LONG,
                                        res.execution_id, 0, 0)) {
                verdict = D2K_NF_ACCEPT;
            }
        }
    }

    if (mode==MODE_APPLY && raw && res.applied && res.n_out) {
        for(size_t k=0;k<res.n_out;k++) {
            if(d2k_raw_prepare(raw,obuf+res.out[k].off,res.out[k].len,
                               err,sizeof err)==0) continue;
            fprintf(stderr,"d2kd: план не отправлен: %s\n",err);
            st.send_fail++; output_failed = 1; res.n_out=0;
            if(d2k_session_exec_failed(sess,t,&res.key,res.plan_id,
                 D2K_REFUSE_SEND,res.execution_id,0,0)) verdict=D2K_NF_ACCEPT;
            break;
        }
    }

    /* ФАЛЬШИВКИ С ПОНИЖЕННЫМ TTL — В ПАМЯТЬ ДО ОТПРАВКИ:
       ICMP узла, где она умрёт, может прийти раньше, чем
       закончится этот проход. Мерило — TTL исходного пакета
       потока: посылка ниже него сервера не достигнет. */
    if (mode == MODE_APPLY && raw && res.applied && res.n_out &&
        original && original_len >= 20) {
        uint8_t orig_ttl = (original[0] >> 4) == 6
            ? original[7] : original[8];
        for (size_t k = 0; k < res.n_out; k++) {
            (void)d2k_icmpguard_note(&icmpg, obuf + res.out[k].off,
                                     res.out[k].len, orig_ttl, t);
        }
    }

    /* Ушла ли уже НАГРУЗКА. Берётся из факта отправки, а не
       из арифметики по номеру: номер не отличает ушедшее от
       положенного в очередь. */
    int payload_on_wire = 0;
    uint64_t at = t;
    for (size_t k = 0; k < res.n_out && mode == MODE_APPLY; k++) {
        at += (uint64_t)res.out[k].delay_us * NS_PER_US;
        const uint8_t *p = obuf + res.out[k].off;
        size_t plen = res.out[k].len;
        if (at <= t) {
            if (d2k_raw_send(raw, p, plen, err, sizeof err) != 0) {
                int send_errno = errno;
                uint8_t failure = refuse_of_errno(send_errno);
                st.send_fail++;
                output_failed = 1;
                /* Полный сокет: план не исполняется дальше,
                   оригинал — общей политикой ниже (пока ушли
                   одни фальшивки, он проходит ядром). */
                log_send_fail("", err, send_errno);
                /* НАША неудача — не свойство коробки. Пока её
                   знал только этот счётчик, контроллер видел
                   «план применён» и делал из неё вывод о
                   коробке (0006). Теперь отказ уезжает
                   отдельным фактом, привязанным к потоку и
                   плану. */
                if (res.applied) {
                    /* Пока на провод уходили одни фальшивки,
                       клиентский поток цел: коробка увидела
                       лишнее, но байты человека не разорваны,
                       и оригинал обязан пройти. Как только
                       ушёл кусок нагрузки, чистого выхода
                       нет. Решает общая политика. */
                    if (d2k_session_exec_failed(sess, t, &res.key, res.plan_id,
                                                failure, res.execution_id,
                                                payload_on_wire, 0)) {
                        verdict = D2K_NF_ACCEPT;
                    } else {
                        fprintf(stderr,
                            "d2kd: поток испорчен: ушло %zu посылок из %zu, "
                            "нагрузка уже на проводе\n", k, res.n_out);
                    }
                }
                break;
            }
            st.emitted++;
            st.emitted_now++;
            if (k == res.first_payload) { payload_on_wire = 1; }
            if (res.applied) {
                d2k_session_sent(sess, t, &res.key, res.execution_id);
            }
        } else if (d2k_sched_push_serial(sched, at, p, plen,
                                  res.applied ? &res.key : NULL, res.execution_id) != 0) {
            st.send_fail++;
            output_failed = 1;
            if (res.applied &&
                d2k_session_exec_failed(sess, t, &res.key, res.plan_id,
                                        D2K_REFUSE_QUEUE, res.execution_id,
                                        payload_on_wire, 0)) {
                verdict = D2K_NF_ACCEPT;
            }
            break;
        } else {
            st.deferred++;
        }
    }

    *result = res; *v = verdict; *payload_sent = payload_on_wire; *last_at = at;
    return output_failed;
}

#define POSTNAT_MARK 0x10000000u
#define POSTNAT_SLOTS 32
/* Sidecars retain held QUIC tails and a fallback after a partially sent plan.
 * They outlive queue callbacks; callback success always transfers ownership. */
typedef struct {
    int used;
    uint32_t head_id;
    d2k_udp_hold_batch batch;
    uint8_t *fallback;
    size_t fallback_len;
    uint64_t ready_at, execution;
    d2k_key key;
    int tails_done, wait_scheduler;
    size_t retry_count;
    uint32_t retry_ids[D2K_UDP_HOLD_PACKETS], retry_verdicts[D2K_UDP_HOLD_PACKETS];
} postnat_side;
typedef struct {
    d2k_postnat_capture *capture;
    d2k_postnat_own *own;
    d2k_ct_async queries;
    int ct;
    unsigned ifindex;
    size_t capture_limit;
    int capture_failed;
    uint64_t accepted, continued, fallback_count;
    hold_context *hc;
    d2k_udp_out *out;
    uint64_t now, seq, drained_at;
    postnat_side side[POSTNAT_SLOTS];
} postnat_context;
static void postnat_finish(postnat_context *c, unsigned slot, uint64_t at) {
    postnat_side *s = &c->side[slot];
    s->ready_at = at ? at : c->now;
    s->wait_scheduler = s->ready_at > c->now;
}
/* Only after the scheduler has drained the head's generated sends. Failed
 * NFQUEUE verdicts retry just their verdict, never their already-sent bytes. */
static void postnat_finish_ready(postnat_context *c, postnat_side *s) {
    if (!s->ready_at || s->ready_at > c->now || s->fallback ||
        (s->wait_scheduler && s->ready_at > c->drained_at)) return;
    if (!s->tails_done) {
        s->tails_done = 1;
        if (s->batch.count) {
            c->hc->skip_verdict = 1; c->hc->skip_id = s->head_id;
            c->hc->retry_ids = s->retry_ids; c->hc->retry_verdicts = s->retry_verdicts;
            c->hc->retry_count = &s->retry_count;
            int failed = d2k_udp_out_batch(c->out, &s->batch, D2K_NF_DROP, 1,
                                           c->now, c->now, c->seq);
            c->hc->retry_count = NULL; c->hc->skip_verdict = 0;
            if (failed && s->execution) {
                (void)d2k_session_exec_failed(c->hc->sess, c->now, &s->key, NULL,
                    D2K_REFUSE_SEND, s->execution, 1, 1);
                s->execution = 0;
            }
        }
    }
    for (size_t i = 0; i < s->retry_count;) {
        if (out_verdict(c->hc, s->retry_ids[i], s->retry_verdicts[i])) { i++; continue; }
        s->retry_count--;
        s->retry_ids[i] = s->retry_ids[s->retry_count];
        s->retry_verdicts[i] = s->retry_verdicts[s->retry_count];
    }
    if (s->retry_count) return;
    if (s->execution) d2k_session_sent(c->hc->sess, c->now, &s->key, s->execution);
    memset(s, 0, sizeof *s);
}
static int postnat_fallback(void *ctx, const uint8_t *orig, size_t olen,
    const uint8_t *cap, size_t clen, const d2k_postnat_identity *id) {
    postnat_context *c = ctx;
    /* No capture means the kernel may still own the marked packet. Keep the
       abandoned slot: a late capture must still fall back, never execute. */
    if (!cap || !clen) return 0;
    if (out_send_now(c->hc, orig, olen)) return 0;
    if (++c->fallback_count <= 16) fprintf(stderr, "d2kd: postnat fallback original\n");
    postnat_finish(c, id->owner_slot, c->now);
    return 1;
}
static int postnat_query(void *ctx, const d2k_ct_tuple *t, d2k_ct_info *out) {
    postnat_context *c = ctx;
    return d2k_ct_async_query(&c->queries, c->ct, t, c->now, out);
}
static int postnat_keep(void *ctx, const d2k_postnat_identity *id) {
    postnat_context *c = ctx;
    return d2k_plantab_find_by_binding(d2k_session_plans(c->hc->sess),
                                      &id->binding, c->now) != NULL;
}
static int postnat_emit(void *ctx, const uint8_t *orig, size_t olen,
    const uint8_t *cap, size_t clen, const d2k_ct_info *map,
    const d2k_postnat_identity *id) {
    postnat_context *c = ctx;
    /* Allocate before execution: if only fakes went out and fallback is busy,
       this sidecar takes responsibility without violating emit's contract. */
    uint8_t *backup = malloc(olen);
    if (!backup) return 0;
    memcpy(backup, orig, olen);
    uint8_t buf[OUT_BUF]; d2k_result r;
    if (!d2k_session_udp_continue(c->hc->sess, c->now, &id->key, id->plan_id,
        id->trial, &id->binding, id->flow_epoch, id->incarnation, map,
        orig, olen, buf, sizeof buf, &r)) {
        free(backup);
        return postnat_fallback(c, orig, olen, cap, clen, id);
    }
    c->continued++; /* preparation count, never evidence of application success */
    uint32_t verdict = r.verdict == D2K_VERDICT_DROP ? D2K_NF_DROP : D2K_NF_ACCEPT;
    int payload = 0; uint64_t at = c->now;
    uint64_t sent = st.emitted_now, queued = st.deferred;
    int failed = send_result(c->hc->sess, c->hc->raw, c->hc->sched, MODE_APPLY,
        c->now, &r, buf, orig, olen, &verdict, &payload, &at);
    if (failed && sent == st.emitted_now && queued == st.deferred) {
        free(backup); return 0;
    }
    if (!failed) {
        c->side[id->owner_slot].key = r.key;
        c->side[id->owner_slot].execution = r.execution_id;
    }
    if (verdict == D2K_NF_ACCEPT) {
        if (out_send_now(c->hc, orig, olen)) {
            if (sent == st.emitted_now && queued == st.deferred) {
                free(backup); return 0; /* nothing sent or queued */
            }
            c->side[id->owner_slot].fallback = backup;
            c->side[id->owner_slot].fallback_len = olen;
            return 1;
        }
    }
    free(backup);
    if (c->continued <= 16) fprintf(stderr, "d2kd: postnat continuation prepared=%u failed=%d\n", r.applied, failed);
    postnat_finish(c, id->owner_slot, at);
    return 1;
}
static void postnat_step(postnat_context *c, int stopping) {
    if (!c->capture) return;
    c->now = now_ns();
    uint8_t packet[65575]; size_t n;
    for (unsigned i = 0; i < POSTNAT_SLOTS * 2; i++) {
        int rc = d2k_postnat_capture_read(c->capture, packet, sizeof packet, &n);
        if (rc < 0) {
            if (!c->capture_failed) fprintf(stderr, "d2kd: postnat capture read failed: %s; new originals pass\n", strerror(errno));
            c->capture_failed = 1;
        }
        if (rc <= 0) break;
        (void)d2k_postnat_own_captured(c->own, packet, n);
    }
    d2k_ct_async_poll(&c->queries, c->ct);
    d2k_postnat_own_clear(c->own, stopping ? NULL : postnat_keep, c,
                          postnat_fallback, c);
    d2k_postnat_own_expire(c->own, (int64_t)c->now, postnat_fallback, c);
    if (!stopping) d2k_postnat_own_resolve(c->own, postnat_query, c, postnat_emit, c);
    for (unsigned i = 0; i < POSTNAT_SLOTS; i++) {
        postnat_side *s = &c->side[i];
        if (s->fallback && !out_send_now(c->hc, s->fallback, s->fallback_len)) {
            free(s->fallback); s->fallback = NULL;
            postnat_finish(c, i, c->now);
        }
        postnat_finish_ready(c, s);
    }
}
static int postnat_pending(const postnat_context *c) {
    for (unsigned i = 0; i < POSTNAT_SLOTS; i++) if (c->side[i].used) return 1;
    return 0;
}
static void postnat_stop_incomplete(postnat_context *c) {
    unsigned flows = 0;
    for (unsigned i = 0; i < POSTNAT_SLOTS; i++) {
        postnat_side *s = &c->side[i];
        if (!s->used) continue;
        flows++;
        if (s->execution) {
            (void)d2k_session_exec_failed(c->hc->sess, c->now, &s->key, NULL,
                D2K_REFUSE_SEND, s->execution, 1, 1);
        }
        /* An unobserved head may still be in the kernel. Never replay it.
         * Unsent tails cannot complete this transaction; retire their queue
         * IDs without transmitting them. Already-sent tails retry only their
         * recorded verdict. Closing NFQUEUE retires any failed verdicts. */
        if (!s->tails_done) {
            for (size_t j = 0; j < s->batch.count; j++)
                if (s->batch.ids[j] != s->head_id)
                    (void)out_verdict(c->hc, s->batch.ids[j], D2K_NF_DROP);
        }
        for (size_t j = 0; j < s->retry_count; j++)
            (void)out_verdict(c->hc, s->retry_ids[j], s->retry_verdicts[j]);
        free(s->fallback);
        memset(s, 0, sizeof *s);
    }
    fprintf(stderr, "d2kd: postnat shutdown incomplete owners=%zu flows=%u; uncertain heads not replayed, delivery not confirmed\n",
            d2k_postnat_own_pending(c->own), flows);
}
static int postnat_begin(postnat_context *c, const d2k_nl_pkt *np,
    const d2k_result *r, const d2k_udp_hold_batch *batch, uint32_t mark,
    uint64_t now, uint64_t seq) {
    if (!c->capture || c->capture_failed || !d2k_binding_known(&r->udp_defer_binding) || !r->udp_defer_pending || !np->have_payload || np->truncated ||
        np->hook != D2K_HOOK_POSTROUTING ||
        !np->have_outdev || np->outdev != c->ifindex || (mark & POSTNAT_MARK)) return 0;
    /* The product queues at mangle POSTROUTING, after destination NAT.
       Only SNAT-invariant packets that reach egress whole are captureable:
       kernel fragmentation before tc would steal fragments without an owner. */
    d2k_packet_view ip;
    if (!d2k_packet_parse(np->payload, np->payload_len, &ip) ||
        np->payload_len > c->capture_limit ||
        np->payload_len > d2k_raw_maxlen(c->hc->raw) ||
        np->payload_len > d2k_raw_route_maxlen_family(c->hc->raw, ip.dst.bytes, ip.family)) return 0;
    unsigned i;
    for (i = 0; i < POSTNAT_SLOTS; i++) if (!c->side[i].used) break;
    if (i == POSTNAT_SLOTS) return 0;
    if (d2k_routemark_routed(&routes, np->payload[0] >> 4, mark | POSTNAT_MARK)) return 0;
    d2k_postnat_identity id = {0};
    id.binding = r->udp_defer_binding; id.generation = id.binding.generation;
    memcpy(id.epoch, id.binding.epoch, 16); memcpy(id.trial, r->udp_defer_trial_id, 16);
    id.key = r->udp_defer_key; memcpy(id.plan_id, r->udp_defer_plan_id, 16);
    memcpy(id.flow_epoch, r->udp_defer_epoch, 16); id.incarnation = r->udp_defer_incarnation;
    id.owner_slot = i;
    if (d2k_postnat_own_begin(c->own, np->payload, np->payload_len, &id,
                              (int64_t)(now + 500 * NS_PER_MS)) != 1) return 0;
    d2k_ct_tuple tuple;
    if (d2k_postnat_udp_tuple(np->payload, np->payload_len, &tuple))
        d2k_ct_async_forget(&c->queries, &tuple);
    char err[256];
    if (d2k_nfq_accept_mark(c->hc->q, np->id, mark | POSTNAT_MARK, err, sizeof err)) {
        /* sendmsg failed atomically: kernel still owns the original. */
        d2k_postnat_own_cancel(c->own, np->payload, np->payload_len);
        fprintf(stderr, "d2kd: postnat mark failed: %s\n", err); return 0;
    }
    c->side[i].used = 1; c->side[i].head_id = np->id;
    if (batch && batch->count) c->side[i].batch = *batch;
    c->seq = seq;
    if (++c->accepted <= 16) fprintf(stderr, "d2kd: postnat owned\n");
    return 1;
}

/* Приём существующих потоков (этап 13): список портов сервера «a,b:c», до 16
   диапазонов; принимаются TCP/UDP потоки с таким портом назначения. */
typedef struct { d2k_session *sess; uint64_t now_ns; size_t adopted; size_t n; uint16_t lo[16], hi[16]; } adopt_ctx;
static int adopt_parse_ports(const char *list, adopt_ctx *c) {
    const char *p = list;
    while (*p) {
        char *end = NULL;
        unsigned long a = strtoul(p, &end, 10), b = a;
        if (end == p || a > 65535) return -1;
        if (*end == ':') { p = end + 1; b = strtoul(p, &end, 10); if (end == p || b > 65535 || b < a) return -1; }
        if (c->n >= 16) return -1;
        c->lo[c->n] = (uint16_t)a; c->hi[c->n] = (uint16_t)b; c->n++;
        if (*end == ',') { p = end + 1; } else if (*end == '\0') { break; } else { return -1; }
    }
    return c->n ? 0 : -1;
}
static int adopt_one(void *ctx, const d2k_ct_tuple *t, const d2k_ct_info *i) {
    adopt_ctx *c = ctx;
    uint16_t dport = (uint16_t)(t->dport_be[0] << 8 | t->dport_be[1]);
    int want = 0;
    for (size_t k = 0; k < c->n && !want; k++) want = dport >= c->lo[k] && dport <= c->hi[k];
    if (!want) return 0;
    if (t->proto == 6 && i->tcp_state_known && i->tcp_state != D2K_CT_TCP_ESTABLISHED) return 0;
    if (d2k_session_adopt(c->sess, t, i, c->now_ns) == 0) c->adopted++;
    return 0;
}

static int offline_self_check(void) {
    static const uint8_t want[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    uint8_t got[32]; d2k_sha256((const uint8_t *)"abc", 3, got);
    return D2K_CTL_PROTO_VERSION == D2K_RUNTIME_WIRE && memcmp(got, want, 32) == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) { printf("d2kd release=%s wire=%u\n", D2K_RELEASE_ID, D2K_RUNTIME_WIRE); return 0; }
    int offline = d2k_runtime_offline(argc, argv, "d2kd", offline_self_check);
    if (offline >= 0) return offline;
    const char *health_path = "/tmp/d2k/d2kd.health";
    uint32_t queue = 0;
    int have_queue = 0;
    const char *plan_path = NULL;
    const char *log_path = NULL;
    /* Интерфейс, чей MTU станет пределом длины посылки. NULL — взять
       наименьший среди поднятых (см. d2k_raw_open, d2k_raw.h). */
    const char *ifname = NULL;
    const char *ctl_path = NULL;
    const char *provider_ips_path = NULL;
    const char *dns_family_path = NULL;
    const char *exp_ctl_path = NULL;   /* второй управляющий: только опыты новой цепочки */
    int mode = MODE_OBSERVE;
    uint32_t mark = 0;
    uint32_t probe_mark = 0;
    uint32_t release_bit = 0;
    uint32_t late_mark = 0;
    const char *adopt_ports = NULL; /* этап 13: принять существующие потоки на старте */
    uint32_t flows = 2048, qlen = 1024, copy_range = MAX_PKT;
    uint32_t slots = 128, idle_s = 120, stats_s = 10, duration_s = 0;
    uint32_t journal = 256;
    int fail_open = 1;
    int udp_reverse_hook = 0;
    int preflight = 0, preflight_ipv6 = 0;
    /* Только политика Keenetic (задача 59): S99d2k переводит имя политики в
       её метку (ndmc show ip policy) и отдаёт сюда. */
    int only_on = 0, only_none = 0;
    uint32_t only_mark = 0, only_mask = 0xffffffffu;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
#define NEEDV() do { if (!v) { fprintf(stderr, "%s требует значения\n", a); return 2; } i++; } while (0)
        if (strcmp(a, "--health-file") == 0) { NEEDV(); health_path = v; }
        else if (strcmp(a, "--queue") == 0)            { NEEDV(); if (arg_u32(v, &queue)) goto badval; have_queue = 1; }
        else if (strcmp(a, "--watch-release-bit") == 0) { NEEDV(); if (arg_u32(v, &release_bit) || !release_bit || (release_bit & (release_bit-1))) goto badval; }
        else if (strcmp(a, "--late-watch-mark") == 0) { NEEDV(); if (arg_u32(v, &late_mark) || !late_mark || (late_mark & (late_mark-1))) goto badval; }
        else if (strcmp(a, "--late-rules") == 0) { late_rules = 1; }
        else if (strcmp(a, "--late-backend") == 0) { NEEDV(); if (strcmp(v, "rules") != 0) goto badval; late_rules = late_force_rules = 1; }
        else if (strcmp(a, "--adopt-ports") == 0) { NEEDV(); adopt_ports = v; }
        else if (strcmp(a, "--plan") == 0)        { NEEDV(); plan_path = v; }
        else if (strcmp(a, "--log") == 0)         { NEEDV(); log_path = v; }
        else if (strcmp(a, "--control") == 0)     { NEEDV(); ctl_path = v; }
        else if (strcmp(a, "--exp-control") == 0) { NEEDV(); exp_ctl_path = v; }
        else if (strcmp(a, "--provider-ips") == 0) { NEEDV(); provider_ips_path = v; }
        else if (strcmp(a, "--dns-family-file") == 0) { NEEDV(); dns_family_path = v; }
        else if (strcmp(a, "--mark") == 0)        { NEEDV(); if (arg_u32(v, &mark)) goto badval; }
        else if (strcmp(a, "--probe-mark") == 0)  { NEEDV(); if (arg_u32(v, &probe_mark)) goto badval; }
        else if (strcmp(a, "--only-mark") == 0) {
            NEEDV();
            only_on = 1;
            if (strcmp(v, "none") == 0) { only_none = 1; }
            else {
                char mbuf[32];
                const char *slash = strchr(v, '/');
                size_t ml = slash ? (size_t)(slash - v) : strlen(v);
                if (ml == 0 || ml >= sizeof mbuf) goto badval;
                memcpy(mbuf, v, ml); mbuf[ml] = '\0';
                if (arg_u32(mbuf, &only_mark) || (slash && arg_u32(slash + 1, &only_mask)) ||
                    only_mask == 0) goto badval;
            }
        }
        else if (strcmp(a, "--preflight") == 0) { preflight = 1; }
        else if (strcmp(a, "--preflight-ipv6") == 0) { preflight_ipv6 = 1; }
        else if (strcmp(a, "--udp-reverse-hook") == 0) { udp_reverse_hook = 1; }
        else if (strcmp(a, "--iface") == 0)       { NEEDV(); ifname = v; }
        else if (strcmp(a, "--flows") == 0)       { NEEDV(); if (arg_u32(v, &flows)) goto badval; }
        else if (strcmp(a, "--queue-len") == 0)   { NEEDV(); if (arg_u32(v, &qlen)) goto badval; }
        else if (strcmp(a, "--copy-range") == 0)  { NEEDV(); if (arg_u32(v, &copy_range)) goto badval; }
        else if (strcmp(a, "--sched-slots") == 0) { NEEDV(); if (arg_u32(v, &slots)) goto badval; }
        else if (strcmp(a, "--journal") == 0)     { NEEDV(); if (arg_u32(v, &journal)) goto badval; }
        else if (strcmp(a, "--idle") == 0)        { NEEDV(); if (arg_u32(v, &idle_s)) goto badval; }
        else if (strcmp(a, "--stats") == 0)       { NEEDV(); if (arg_u32(v, &stats_s)) goto badval; }
        else if (strcmp(a, "--duration") == 0)    { NEEDV(); if (arg_u32(v, &duration_s)) goto badval; }
        else if (strcmp(a, "--no-fail-open") == 0) { fail_open = 0; }
        else if (strcmp(a, "--mode") == 0) {
            NEEDV();
            if (strcmp(v, "observe") == 0)      { mode = MODE_OBSERVE; }
            else if (strcmp(v, "apply") == 0)   { mode = MODE_APPLY; }
            else { fprintf(stderr, "режим бывает observe или apply\n"); return 2; }
        }
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(); return 0; }
        else { fprintf(stderr, "неизвестный ключ: %s\n", a); usage(); return 2; }
#undef NEEDV
        continue;
    badval:
        fprintf(stderr, "плохое значение у %s\n", a);
        return 2;
    }

    if (!have_queue) {
        fprintf(stderr, "не задан --queue\n");
        usage();
        return 2;
    }
    if (queue > 0xffff) {
        fprintf(stderr, "номер очереди не помещается в 16 бит\n");
        return 2;
    }
    if (copy_range < 64 || copy_range > MAX_PKT) {
        fprintf(stderr, "--copy-range должен быть от 64 до %d\n", MAX_PKT);
        return 2;
    }
    if (mode == MODE_APPLY && !plan_path && !ctl_path) {
        /* Планы приходят либо файлом, либо от контроллера через сокет. Без
           обоих исполнять нечего, и запускаться в таком виде значит оставить
           человеку процесс, который выглядит работающим обходом. */
        fprintf(stderr, "режим apply без --plan и без --control ничего не сделал бы\n");
        return 2;
    }
    if (mode == MODE_APPLY && mark == 0) {
        /* §5.5: неудача пометки — явное снижение достоверности, если
           исключение обхода не гарантировано. Работать активно без метки
           значит рисковать тем, что собственные пакеты вернутся в свою же
           очередь и обучат систему на её собственном эхе. */
        fprintf(stderr, "режим apply без --mark запрещён: собственные пакеты "
                        "нечем исключить из своей же очереди\n");
        return 2;
    }
    if (probe_mark != 0 && probe_mark == mark) {
        fprintf(stderr, "--probe-mark должен отличаться от --mark: иначе собственные raw-пакеты нельзя отличить от зондов контроллера\n");
        return 2;
    }
    /* Бит освобождения watch (NF_REPEAT с mark|bit) не должен быть частью
       --mark/--probe-mark: иначе пакет с нашей/зондовой меткой выглядел бы уже
       освобождённым и не освобождался бы никогда, а освобождённый пользовательский
       пакет мог бы совпасть с меткой зонда. S99d2k проверяет это в watch_validate;
       служба, запущенная мимо S99 (лаборатория), обязана отказать сама. */
    if (release_bit && ((mark | probe_mark) & release_bit)) {
        fprintf(stderr, "--watch-release-bit 0x%x пересекается с --mark 0x%x / --probe-mark 0x%x\n",
                (unsigned)release_bit, (unsigned)mark, (unsigned)probe_mark);
        return 2;
    }
    /* Бит поздней доставки (connmark записи, этап 17) — та же логика: он не
       может быть частью меток посылок/зондов и бита освобождения. */
    if (late_mark && (((mark | probe_mark) & late_mark) || (release_bit & late_mark))) {
        fprintf(stderr, "--late-watch-mark 0x%x пересекается с --mark 0x%x / --probe-mark 0x%x / --watch-release-bit 0x%x\n",
                (unsigned)late_mark, (unsigned)mark, (unsigned)probe_mark, (unsigned)release_bit);
        return 2;
    }
    late_bit = late_mark;

    if (log_path) {
        /* Служба уходит в фон через start-stop-daemon, который потоки не
           перенаправляет. Раз файл нужен нам, открываем его сами — до первой
           печати, иначе стартовая строка уйдёт в никуда. */
        if (!freopen(log_path, "a", stdout) || !freopen(log_path, "a", stderr)) {
            fprintf(stderr, "не открыть журнал %s: %s\n", log_path, strerror(errno));
            return 1;
        }
        setvbuf(stdout, NULL, _IOLBF, 0);
    }

    char err[256];
    err[0] = '\0';

    /* --- план ------------------------------------------------------------- */
    d2k_plan *plan = NULL;
    if (plan_path) {
        FILE *f = fopen(plan_path, "rb");
        if (!f) {
            fprintf(stderr, "план %s: %s\n", plan_path, strerror(errno));
            return 1;
        }
        static uint8_t pbuf[65536];
        size_t n = fread(pbuf, 1, sizeof pbuf, f);
        int short_read = !feof(f);
        fclose(f);
        if (short_read) {
            fprintf(stderr, "план %s длиннее %zu байт\n", plan_path, sizeof pbuf);
            return 1;
        }
        if (d2k_plan_load(pbuf, n, &plan, err, sizeof err) != 0) {
            fprintf(stderr, "план %s не принят: %s\n", plan_path, err);
            return 1;
        }
    }

    /* --- сырой сокет и сверка пределов ------------------------------------ */
    d2k_raw *raw = NULL;
    if (mode == MODE_APPLY) {
        raw = d2k_raw_open(mark, ifname, err, sizeof err);
        if (!raw) {
            fprintf(stderr, "сырой сокет: %s\n", err);
            d2k_plan_free(plan);
            return 1;
        }
        char why[200];
        if (plan && !d2k_plan_fits(plan, d2k_raw_limits(raw),
                                   (uint32_t)d2k_raw_maxlen(raw), why, sizeof why)) {
            fprintf(stderr, "план не активируется: %s.\n"
                            "Исполненное разошлось бы с измеренным (§2.5).\n", why);
            d2k_raw_close(raw);
            d2k_plan_free(plan);
            return 1;
        }
    }

    /* --- очередь ---------------------------------------------------------- */
    d2k_nfq_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.queue = (uint16_t)queue;
    cfg.copy_range = copy_range;
    cfg.maxlen = qlen;
    cfg.fail_open = fail_open;
    cfg.rcvbuf = 4 * 1024 * 1024;

    d2k_nfq *q = d2k_nfq_open(&cfg, err, sizeof err);
    if (!q) {
        fprintf(stderr, "очередь %u: %s\n", queue, err);
        d2k_raw_close(raw);
        d2k_plan_free(plan);
        return 1;
    }

    /* Метки времени приёма у пакетов очереди (NFQA_TIMESTAMP): ядро ставит
       их, только когда кто-то включил SO_TIMESTAMP. По ним http80 меряет RTT
       без задержки очереди и самой службы (задача 51, ревью M1). Отказ — не
       беда: замер идёт по своим часам, как раньше. */
    {
        int one = 1;
        if (setsockopt(d2k_nfq_fd(q), SOL_SOCKET, SO_TIMESTAMP, &one, sizeof one) != 0) {
            fprintf(stderr, "d2kd: метки времени ядра недоступны (%s) — RTT HTTP по своим часам\n",
                    strerror(errno));
        }
    }

    d2k_ctl *ctl = NULL;
    if (ctl_path) {
        ctl = d2k_ctl_open(ctl_path, err, sizeof err);
        if (!ctl) {
            fprintf(stderr, "управляющий сокет: %s\n", err);
            d2k_nfq_close(q);
            d2k_raw_close(raw);
            d2k_plan_free(plan);
            return 1;
        }
    }

    d2k_session *sess = d2k_session_new(flows, journal);
    if (sess && preflight && mode == MODE_APPLY &&
        d2k_session_set_preflight(sess, 1) != 0)
        fprintf(stderr, "d2kd: preflight выключен: не удалось создать таблицу\n");
    if (sess && preflight && mode == MODE_APPLY && provider_ips_path)
        (void)d2k_session_provider_ips_load(sess,provider_ips_path,(uint64_t)time(NULL));
    http80 = d2k_http80_new();
    if (!http80) {
        fprintf(stderr, "d2kd: нет памяти для разбора HTTP — вставка провайдера не узнаётся\n");
    }
    if (sess && udp_reverse_hook) {
        d2k_session_set_udp_reverse_hook(sess, 1);
    }
    ct_probe(sess, 1);
    /* УЖЕ СУЩЕСТВУЮЩИЕ ПОТОКИ (этап 13, opt-in): один проход по таблице
       conntrack на старте, приём потоков к названным портам сервера; дальше
       они наблюдаются только счётчиками (d2k_session_adopt). Без ctnetlink —
       принимать нечем, об этом сказано выше. */
    if (adopt_ports && ctl_ct.up) {
        adopt_ctx ac;
        memset(&ac, 0, sizeof ac);
        ac.sess = sess; ac.now_ns = now_ns();
        if (adopt_parse_ports(adopt_ports, &ac) != 0) {
            fprintf(stderr, "d2kd: --adopt-ports: не разобрано: %s\n", adopt_ports);
        } else {
            for (uint8_t fam = 4; fam <= 6; fam += 2) {
                if (++ctl_ct.seq == 0) { ctl_ct.seq = 1; }
                int got = d2k_ct_dump_fd(ctl_ct.fd, ctl_ct.seq, fam, adopt_one, &ac, 500);
                if (got < 0) { fprintf(stderr, "d2kd: перечисление conntrack IPv%u не удалось\n", (unsigned)fam); }
            }
            fprintf(stderr, "d2kd: принято из conntrack на старте: %zu потоков к портам %s (наблюдение счётчиками, без плана)\n",
                    ac.adopted, adopt_ports);
        }
    }
    /* Вместимость ячейки — «сколько байт унесёт способ отправки», а не
       «сколько байт пакета мы берём у ядра» (--copy-range): посылка плана
       бывает длиннее пришедшего, перекрытие несёт приставку сверх нагрузки.
       Пока это было одним числом, очередь отвергала посылку по чужому
       пределу (см. d2k_sched_new, d2k_sched.h). */
    d2k_sched   *sched = d2k_sched_new(slots, raw ? d2k_raw_maxlen(raw) : copy_range);
    if (!sess || !sched) {
        fprintf(stderr, "не хватило памяти на состояние\n");
        d2k_ctl_close(ctl);
        d2k_sched_free(sched);
        d2k_session_free(sess);
        d2k_nfq_close(q);
        d2k_raw_close(raw);
        d2k_plan_free(plan);
        return 1;
    }
    if (plan) {
        d2k_session_set_plan(sess, plan);   /* владение переходит сессии */
        plan = NULL;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = on_signal;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    printf("=== d2kd[%ld] запущен ===\n", (long)getpid());
    printf("d2kd: очередь %u, режим %s, метка %u, метка зондов %u, потоков до %u, "
           "fail-open %s%s\n",
           queue, MODE_NAMES[mode], mark, probe_mark, flows, fail_open ? "да" : "НЕТ",
           plan_path ? ", план загружен" : ", плана нет");
    if (mode == MODE_OBSERVE) {
        printf("d2kd: наблюдение. Ни один пакет не будет изменён, снят или "
               "выпущен.\n");
    }
    fflush(stdout);

    /* Вход опытов новой цепочки (ТЗ §16): пробный план на местный порт
       собственного потока и его снятие — и больше ничего. Отказ открыть его
       работу основного контроллера не останавливает. */
    d2k_ctl *xctl = NULL;
    d2k_ctl *xpeers[D2K_EXP_PEERS_MAX]={0};
    if (exp_ctl_path) {
        xctl = d2k_ctl_open(exp_ctl_path, err, sizeof err);
        if (!xctl) fprintf(stderr, "сокет опытов не открыт (работаю без него): %s\n", err);
    }

    d2k_ctlsrv cx;
    memset(&cx, 0, sizeof cx);
    cx.sess = sess;
    cx.ctl = ctl;
    cx.http80 = http80;
    lw_sess = sess;
    if (late_bit || late_rules) {
        /* ПОЗДНЯЯ ДОСТАВКА (этапы 17, 49, 51, 53): способ (метка при подтверждённой
           маске / правила точного кортежа / нет) выбирает исполнитель первой
           заявкой; до его итога заявки ждут в очереди исполнителя, не в цикле. */
        lwk.rules.queue = queue;
        lwx = d2k_lwexec_start(lw_run, NULL, 128);
        if (!lwx) {
            fprintf(stderr, "d2kd: поздняя доставка выключена: исполнитель не запустился (память, поток)\n");
        } else {
            lw_cx = &cx;
            d2k_lw_ops lw_ops = { lw_op_submit, lw_op_ack, lw_op_flag, lw_op_delivered, lw_op_note, lw_op_say, NULL,
                                  late_bit };
            d2k_lw_init(&lwt, &lw_ops);
            d2k_lw_raw_ops raw_ops={lw_raw_identity,lw_raw_ack,lw_raw_note,NULL};
            d2k_lw_raw_hooks(&lwt,&raw_ops);
            cx.raw_measure_hook=raw_measure_hook;
            cx.addr_probe_hook = late_addr_hook;
            cx.name_probe_hook = late_name_hook;
            cx.late_observe_hook = late_observe_hook;
            cx.peer_closed_hook = late_peer_closed;
            cx.probe_hook_ctx = &cx;
            printf("d2kd: поздняя доставка: бит connmark 0x%x%s, исполнитель запущен\n",
                   (unsigned)late_bit, late_rules ? ", запасной способ — правила точного кортежа" : "");
            fflush(stdout);
            d2k_lw_start(&lwt, now_ns());
        }
    }
    d2k_ctl_set_disconnect_hook(ctl, d2k_ctlsrv_peer_closed, &cx);
    cx.send_limits = raw ? d2k_raw_limits(raw) : 0;
    /* Ноль без сырого сокета — «предел не объявлен»: в режиме наблюдения на
       провод ничего не пойдёт, и резать по длине нечего. */
    cx.send_maxlen = raw ? (uint32_t)d2k_raw_maxlen(raw) : 0;
    uint64_t events_seen = 0;
    holding = mode == MODE_APPLY ? d2k_hold_new() : NULL;
    udp_holding = mode == MODE_APPLY ? d2k_udp_hold_new() : NULL;
    udp_releases = mode == MODE_APPLY ? d2k_udp_release_new(16, D2K_UDP_HOLD_PACKETS) : NULL;
    if (mode == MODE_APPLY && !holding) {
        fprintf(stderr, "d2kd: нет памяти для составного входа — пакеты не удерживаются\n");
    }
    if (mode == MODE_APPLY && !udp_holding) {
        fprintf(stderr, "d2kd: нет памяти для split QUIC — UDP будет пропускаться без удержания\n");
    }
    if (mode == MODE_APPLY && !udp_releases) {
        fprintf(stderr, "d2kd: нет памяти для задержанных UDP-вердиктов — split Plan будет fail-open\n");
    }
    udp_follow = mode == MODE_APPLY && raw ? d2k_udp_follow_new() : NULL;
    hold_context hc = {sess, q, mode == MODE_APPLY ? raw : NULL,
                       mode == MODE_APPLY ? sched : NULL, 0, 0, NULL, NULL, NULL};
    udp_out.verdict = out_verdict;
    udp_out.send_now = out_send_now;
    udp_out.send_at = out_send_at;
    udp_out.send_at_owned = out_send_at_owned;
    udp_out.ctx = &hc;
    udp_out.follow = udp_follow;
    udp_out.can_resend = udp_follow != NULL;
    udp_out.neutral_mark = probe_mark;
    udp_out.marked = out_marked;
    udp_out.defer_verdict = out_defer;
    udp_out.resend_failed = out_resend_failed;
    udp_out.routed = routes_routed;
    udp_out.routes = &routes;
    d2k_routemark_init(&routes);
    if (only_on) {
        d2k_routemark_set_policy(&routes, only_none, only_mark, only_mask);
        if (only_none) {
            printf("d2kd: только политика Keenetic — политика не найдена: клиентов не обслуживаю\n");
        } else {
            printf("d2kd: только политика Keenetic: клиенты с меткой 0x%x/0x%x, прочие идут ядром\n",
                   (unsigned)(only_mark & only_mask), (unsigned)only_mask);
        }
    }
    /* Изменения правил и маршрутов — сразу, по уведомлению (финальное ревью
       M-2): правило, добавленное при работающей службе (включили политику
       VPN, переподключение), иначе было бы неизвестно до 30 с. Опрос раз в
       30 с остаётся страховкой. */
    int routes_fd;
    {
        char werr[256];
        routes_fd = d2k_routemark_watch_open(werr, sizeof werr);
        if (routes_fd < 0) {
            fprintf(stderr, "d2kd: уведомления о правилах/маршрутах недоступны: %s — "
                            "только опрос раз в 30 с\n", werr);
        }
    }
    routes_refresh();
    cap_refresh(raw, &cx, ctl);
    if (raw) {
        /* Один раз при старте, всегда: по журналам репортёров предел был виден
           только по отказам планов (поле 22.10.2026, issue #5/#7). */
        fprintf(stderr, "d2kd: предел длины посылки %zu байт (%s)\n", d2k_raw_maxlen(raw),
                ifname ? "назван --iface" : "угадан: MTU выхода сырой посылки, "
                                            "иначе наименьший среди поднятых");
    }
    postnat_context *pn = calloc(1, sizeof *pn);
    if (pn) {
        pn->ct = -1; pn->hc = &hc; pn->out = &udp_out;
        pn->capture_limit = raw ? d2k_raw_maxlen(raw) : 0;
        pn->ifindex = ifname ? if_nametoindex(ifname) :
            (routes.n_oif4 == 1 ? routes.oif4[0] : 0);
        const char *reason = "not apply mode or raw sender unavailable";
        if (mode == MODE_APPLY && raw) {
            reason = "no single eligible output interface";
            if (pn->ifindex) {
                reason = "capture mark conflicts with product marks or route policy";
                if (!((mark | probe_mark | release_bit | late_mark) & POSTNAT_MARK) &&
                    !d2k_routemark_routed(&routes, 4, POSTNAT_MARK) &&
                    !d2k_routemark_routed(&routes, 6, POSTNAT_MARK)) {
                    pn->own = d2k_postnat_own_new(POSTNAT_SLOTS, 65575);
                    reason = "ownership allocation failed";
                    if (pn->own) {
                        pn->ct = d2k_ct_open();
                        reason = "conntrack query socket unavailable";
                        if (pn->ct >= 0) {
                            pn->capture = d2k_postnat_capture_open(pn->ifindex,
                                POSTNAT_MARK, 49152, err, sizeof err);
                            reason = err;
                        }
                    }
                }
            }
        }
        if (pn->capture) fprintf(stderr, "d2kd: postnat capture enabled\n");
        else fprintf(stderr, "d2kd: postnat capture disabled: %s; originals pass\n", reason);
    } else {
        fprintf(stderr, "d2kd: postnat capture disabled: context allocation failed; originals pass\n");
    }
    if (preflight && mode==MODE_APPLY && raw) {
        int failed=0;
        for (unsigned i=0;i<3;i++) {
            preflight_raw[i]=d2k_raw_open(D2K_PF_MARK+i,ifname,err,sizeof err);
            if (!preflight_raw[i]) { failed=1; break; }
        }
        if (failed) {
            fprintf(stderr,"d2kd: preflight disabled: raw sockets: %s\n",err);
            for (unsigned i=0;i<3;i++) { d2k_raw_close(preflight_raw[i]); preflight_raw[i]=NULL; }
            (void)d2k_session_set_preflight(sess,0);
            preflight=0;
        } else if (preflight_ipv6) {
            /* Prepare all three IPv6 senders before taking ownership of a SYN.
             * prepare opens sockets and sets marks without sending a packet. */
            const uint8_t ipv6_header[40] = {0x60, [6] = IPPROTO_TCP};
            for (unsigned i=0;i<3;i++) {
                if (d2k_raw_prepare(preflight_raw[i],ipv6_header,sizeof ipv6_header,err,sizeof err)) {
                    fprintf(stderr,"d2kd: IPv6 preflight unsupported: %s\n",err);
                    preflight_ipv6=0;
                    break;
                }
            }
        }
    }
    d2k_session_preflight_ipv6(sess, preflight && preflight_ipv6);
    d2k_preflight_io pf_io = {&hc, preflight_drop, preflight_send};
    uint64_t last_routes = now_ns();
    uint64_t next_routes = last_routes + D2K_ROUTEMARK_REFRESH_NS;
    udp_path.sess = sess;
    udp_path.hold = udp_holding;
    udp_path.out = &udp_out;
    /* Номер пачки приёма ведёт udp_path (d2k_udp_path_read/expire): всё,
       что прочитано в одной пачке с выпуском головы, стояло в очереди до её
       вердикта (окно столкновения, d2k_udp_follow). */

    static uint8_t rbuf[RECV_BUF];
    static uint8_t obuf[OUT_BUF];
    /* Буфер выдачи отложенных обязан вмещать САМУЮ ДЛИННУЮ посылку, какую
       способна принять очередь: её вместимость задана пределом отправки
       (d2k_raw_maxlen), а не размером входящего пакета. Меньший буфер
       превращал выдачу в отказ, и до правки 13.09 одна такая посылка
       запирала очередь целиком. */
    static uint8_t sbuf[D2K_SCHED_SLOT_MAX];

    const uint64_t start = now_ns();
    const uint64_t idle_ns = (uint64_t)idle_s * NS_PER_S;
    uint64_t next_stats = stats_s ? start + (uint64_t)stats_s * NS_PER_S : 0;
    uint64_t next_expire = start + NS_PER_S;
    uint64_t next_provider_reload = start;
    ino_t provider_file_inode=0;
    struct timespec provider_file_mtime={0};
    /* Счётчики связи уезжают контроллеру раз в секунду: реже — и он узнавал бы
       о своей слепоте позже, чем успел бы выбросить рабочий план. */
    uint64_t next_ctl_stats = start + NS_PER_S;

    char fw_repair_path[2][4096];
    int fw_repair_enabled[2];
    int fw_repair_started[2] = {0, 0};
    for (int i = 0; i < 2; i++) {
        int n = snprintf(fw_repair_path[i], sizeof fw_repair_path[i], "%s.fw%d", health_path, i ? 6 : 4);
        fw_repair_enabled[i] = n > 0 && (size_t)n < sizeof fw_repair_path[i];
    }
    while (!stop_flag) {
        (void)d2k_runtime_heartbeat(health_path, NULL, ctl && d2k_ctl_peer_fd(ctl) >= 0, 1, 1);
        uint64_t t = now_ns();
        if(preflight && provider_ips_path && t>=next_provider_reload) {
            struct stat st;
            if(!stat(provider_ips_path,&st) &&
               (st.st_ino!=provider_file_inode ||
                st.st_mtim.tv_sec!=provider_file_mtime.tv_sec ||
                st.st_mtim.tv_nsec!=provider_file_mtime.tv_nsec)) {
                if(!d2k_session_provider_ips_load(sess,provider_ips_path,(uint64_t)time(NULL))) {
                    provider_file_inode=st.st_ino;
                    provider_file_mtime=st.st_mtim;
                }
            }
            next_provider_reload=t+100*NS_PER_MS;
        }
        /* Часы для вытеснения в таблице планов (d2k_plantab_set_name/set_addr,
           см. d2k_plans.h) — точность в сотни миллисекунд достаточна: там
           считают минуты простоя записи, а не наносекунды. */
        cx.now_ns = t;
        if (duration_s && t - start >= (uint64_t)duration_s * NS_PER_S) {
            break;
        }

        /* Досыпаем ровно до ближайшего дела: созревшего пакета, срока сводки,
           уборки таблицы. Не до фиксированного тика — иначе задержки плана
           округлялись бы вверх на его величину. */
        uint64_t wake = t + 200 * NS_PER_MS;      /* потолок ожидания: 200 мс */
        if(preflight && provider_ips_path && next_provider_reload<wake)
            wake=next_provider_reload;
        uint64_t due = d2k_sched_next_ns(sched);
        if (due && due < wake) { wake = due; }
        due = d2k_udp_release_next_ns(udp_releases);
        if (due && due < wake) { wake = due; }
        due = d2k_udp_hold_next_ns(udp_holding);
        if (due && due < wake) { wake = due; }
        due = d2k_session_preflight_next_ns(sess);
        if (due && due < wake) { wake = due; }
        due = d2k_hold_next(holding);
        if (due && due < wake) { wake = due; }
        if (next_stats && next_stats < wake) { wake = next_stats; }
        if (next_expire < wake) { wake = next_expire; }
        if (next_routes < wake) { wake = next_routes; }

        int timeout_ms = 0;
        if (wake > t) {
            uint64_t d = (wake - t + NS_PER_MS - 1) / NS_PER_MS;
            timeout_ms = (d > 200) ? 200 : (int)d;
        }

        if (pn && postnat_pending(pn) && timeout_ms > 2) timeout_ms = 2;
        struct pollfd pfd[8+D2K_EXP_PEERS_MAX];
        nfds_t nfd = 0;
        pfd[nfd].fd = d2k_nfq_fd(q);
        pfd[nfd].events = POLLIN;
        pfd[nfd].revents = 0;
        const nfds_t iq = nfd++;
        nfds_t iw = (nfds_t)-1;
        if (routes_fd >= 0) {
            pfd[nfd].fd = routes_fd;
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            iw = nfd++;
        }

        nfds_t il = (nfds_t)-1, ip = (nfds_t)-1;
        if (ctl) {
            pfd[nfd].fd = d2k_ctl_listen_fd(ctl);
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            il = nfd++;
            int p = d2k_ctl_peer_fd(ctl);
            if (p >= 0) {
                pfd[nfd].fd = p;
                pfd[nfd].events = POLLIN;
                pfd[nfd].revents = 0;
                ip = nfd++;
            }
        }

        nfds_t ixl=(nfds_t)-1,ixp[D2K_EXP_PEERS_MAX];
        for(unsigned i=0;i<D2K_EXP_PEERS_MAX;i++)ixp[i]=(nfds_t)-1;
        if(xctl) {
            pfd[nfd]=(struct pollfd){d2k_ctl_listen_fd(xctl),POLLIN,0};
            ixl=nfd++;
            for(unsigned i=0;i<D2K_EXP_PEERS_MAX;i++)if(xpeers[i]) {
                pfd[nfd]=(struct pollfd){d2k_ctl_peer_fd(xpeers[i]),POLLIN,0};
                ixp[i]=nfd++;
            }
        }

        if (pn && pn->capture) {
            if (!pn->capture_failed)
                pfd[nfd++] = (struct pollfd){d2k_postnat_capture_fd(pn->capture), POLLIN, 0};
            pfd[nfd++] = (struct pollfd){pn->ct, POLLIN, 0};
        }
        int pr = poll(pfd, nfd, timeout_ms);
        if (pr < 0 && errno != EINTR) {
            st.recv_err++;
        }

        /* Правило или маршрут изменились: перечитать до следующего пакета —
           после пачки уведомлений, не чаще раза в D2K_ROUTEMARK_SETTLE_NS. */
        if (pr > 0 && iw != (nfds_t)-1 && (pfd[iw].revents & (POLLIN | POLLERR)) &&
            d2k_routemark_watch_drain(routes_fd)) {
            st.routes_watch++;
            uint64_t soon = last_routes + D2K_ROUTEMARK_SETTLE_NS;
            uint64_t tn = now_ns();
            if (soon < tn) { soon = tn; }
            if (soon < next_routes) { next_routes = soon; }
        }
        if (now_ns() >= next_routes) {
            routes_refresh();
            cap_refresh(raw, &cx, ctl);
            ct_probe(sess, 0);
            last_routes = now_ns();
            next_routes = last_routes + D2K_ROUTEMARK_REFRESH_NS;
        }

        if (ctl) {
            if (il != (nfds_t)-1 && (pfd[il].revents & POLLIN)) {
                d2k_ctl_accept(ctl);
                /* Версия провода — первым делом, до любых других событий. */
                d2k_ctlsrv_greet(ctl, raw ? (uint32_t)d2k_raw_maxlen(raw) : 0u);
            }
            if (ip != (nfds_t)-1 && (pfd[ip].revents & (POLLIN | POLLHUP))) {
                d2k_ctl_poll(ctl, d2k_ctlsrv_command, &cx);
            }
            d2k_ctl_flush(ctl);
        }
        if(xctl) {
            if(ixl!=(nfds_t)-1 && (pfd[ixl].revents&POLLIN)) {
                unsigned i=0;while(i<D2K_EXP_PEERS_MAX && xpeers[i])i++;
                if(i<D2K_EXP_PEERS_MAX) {
                    xpeers[i]=d2k_ctl_accept_peer(xctl);
                    if(xpeers[i])d2k_ctlsrv_greet(xpeers[i],raw?(uint32_t)d2k_raw_maxlen(raw):0u);
                } else {
                    /* Capacity is a resource limit, never eviction of a
                       running experiment's stream. */
                    int rejected=accept(d2k_ctl_listen_fd(xctl),NULL,NULL);
                    if(rejected>=0)close(rejected);
                }
            }
            for(unsigned i=0;i<D2K_EXP_PEERS_MAX;i++)if(xpeers[i]) {
                if(ixp[i]!=(nfds_t)-1 && (pfd[ixp[i]].revents&(POLLIN|POLLHUP|POLLERR))) {
                    d2k_ctlsrv xcx=cx;xcx.ctl=xpeers[i];
                    d2k_ctl_poll(xpeers[i],d2k_ctlsrv_command_exp,&xcx);
                    cx.ok_cmds=xcx.ok_cmds;cx.bad_cmds=xcx.bad_cmds;
                }
                d2k_ctl_flush(xpeers[i]);
                if(d2k_ctl_peer_fd(xpeers[i])<0) {
                    d2k_ctlsrv_forget_exp_ctl(xpeers[i]);
                    d2k_ctl_close(xpeers[i]);xpeers[i]=NULL;
                }
            }
        }

        d2k_hold_flush(holding, now_ns(), d2k_session_plan_revision(sess), 0,
                        release_original, &hc);
        /* Номер следующего чтения истёкшая ячейка получает, только если это
           чтение будет в этом же проходе: иначе её окно открылось бы для
           чтения через сколько угодно времени (ревью N2). */
        int read_follows = pr > 0 && (pfd[iq].revents & POLLIN);
        (void)d2k_udp_path_expire(&udp_path, now_ns(), read_follows);
        if (read_follows) {
            ssize_t n = d2k_nfq_recv(q, rbuf, sizeof rbuf, err, sizeof err);
            if (n == -1) {
                st.recv_err++;
                fprintf(stderr, "d2kd: %s\n", err);
                d2k_hold_flush(holding, now_ns(), 0, 1, release_original, &hc);
                /* Чтения не было: его номер не достаётся никому. */
                d2k_udp_path_read(&udp_path, now_ns());
                (void)d2k_udp_path_expire(&udp_path, now_ns(), 0);
            } else if (n == -2) {
                d2k_hold_flush(holding, now_ns(), 0, 1, release_original, &hc);
                /* Чтения не было: его номер не достаётся никому. */
                d2k_udp_path_read(&udp_path, now_ns());
                (void)d2k_udp_path_expire(&udp_path, now_ns(), 0);
            } else if (n > 0) {
                t = now_ns();
                d2k_udp_path_read(&udp_path, t);
                d2k_nl_iter it;
                d2k_nl_msg m;
                d2k_nl_iter_init(&it, rbuf, (size_t)n);
                while (d2k_nl_next(&it, &m)) {
                    int32_t kerr = 0;
                    if (d2k_nl_errno(&m, &kerr) == 0) {
                        if (kerr != 0) {
                            /* Молчаливо копить пакеты, получая EINVAL, уже
                               случалось на этапе 0. Больше не молча. */
                            fprintf(stderr, "d2kd: ядро отвергло сообщение: %s\n",
                                    strerror(-kerr));
                        }
                        continue;
                    }
                    if ((m.type & 0xff) != D2K_NFQNL_MSG_PACKET) {
                        continue;
                    }

                    d2k_nl_pkt np;
                    if (d2k_nl_packet(&m, &np) != 0 || !np.have_hdr) {
                        st.no_hdr++;
                        continue;   /* вердикт слать некому: нет номера пакета */
                    }

                    d2k_nfq_release_packet(q, np.id, np.have_mark ? np.mark : 0, 0);
                    /* Release requests never reach discovery, hold or the
                     * normal fake sender. ACCEPT encodes NF_REPEAT with the
                     * temporary bit; the firewall consumes control tokens. */
                    if (preflight && mode==MODE_APPLY && np.have_mark &&
                        (np.mark==D2K_PF_RELEASE_MARK || np.mark==D2K_PF_TOKEN_MARK)) {
                        (void)preflight_repeat(q,&np);
                        continue;
                    }
                    if(dns_family_step(q,&np,dns_family_path,mode))continue;
                    st.seen++;
                    st.bytes += np.payload_len;
                    /* ICMP идёт в очередь только как time-exceeded (S99d2k,
                       D2K_IN) и к сессии отношения не имеет. */
                    if (icmp_step(q, &np, t)) {
                        continue;
                    }
                    /* Зонды контроллера (метка зондов) — не трафик человека:
                       их вставку не заменяем и о ней не сообщаем, иначе
                       собственный замер HTTP (шаг 4) мерил бы нашу же
                       замену. */

                    d2k_hold_batch batch;
                    memset(&batch, 0, sizeof batch);
                    /* Группа READY, чьи оригиналы уже сняты у ядра (см.
                       hold_owns): вердиктов им не будет, без плана — повтор. */
                    int batch_owned = 0;
                    d2k_udp_hold_batch udp_batch;
                    memset(&udp_batch, 0, sizeof udp_batch);
                    int udp_replay = 0;
                    d2k_key udp_key;
                    memset(&udp_key, 0, sizeof udp_key);

                    /* Direction evidence is needed before split-QUIC hold:
                       non-443 client Initials are accepted only when NFQUEUE
                       supplied OUTPUT/POSTROUTING. */
                    d2k_session_set_hook(sess, np.have_hdr ? np.hook : D2K_HOOK_UNKNOWN);
                    /* МЕТКА МАРШРУТИЗАЦИИ КЛИЕНТА (задача 47): метка, которую
                       выбирает правило ip rule (кроме собственных меток d2k), —
                       поток идёт ядром, без плана и удержания. Метка без
                       правила (PPPoE, QoS, чужая) d2k не выключает. Ставится
                       на КАЖДЫЙ пакет — единственное место. */
                    /* ВЫХОДНОЙ ИНТЕРФЕЙС (финальное ревью I-1): клиент,
                       которого увели в другую таблицу по адресу, iif, tos или
                       uidrange, метки не несёт, а сырая посылка такие правила
                       не проходит и идёт по главной таблице. Исходящий пакет,
                       уходящий не через выход маршрута по умолчанию главной
                       таблицы, — тоже поток ядра. */
                    const int outbound = np.hook == D2K_HOOK_POSTROUTING ||
                                         np.hook == D2K_HOOK_OUTPUT;
                    const uint32_t preflight_path = outbound ? np.outdev : np.indev;
                    d2k_session_set_packet_path(sess,preflight_path);
                    const uint32_t route_gate = d2k_routemark_gate(&routes,
                        (np.have_payload && np.payload_len)
                            ? (uint8_t)(np.payload[0] >> 4) : 4,
                        outbound, np.have_mark, np.mark, probe_mark, mark,
                        np.have_outdev, np.outdev);
                    d2k_session_set_route_mark(sess, route_gate);
                    /* Метка для UDP-выпуска: решение шлюза, если он сказал
                       «маршрут», иначе метка пакета как есть. */
                    const uint32_t umark = route_gate ? route_gate
                                                      : (np.have_mark ? np.mark : 0);

                    /* Own SYN/replies before capture/hold/accounting. A raw
                     * sender is mandatory; observe mode never starts a probe. */
                    if (preflight && mode == MODE_APPLY && raw && !route_gate &&
                        np.have_payload && !np.truncated && np.payload_len>=40 &&
                        (((np.payload[0]>>4)==4 && np.payload[9]==6) ||
                         (preflight_ipv6 && (np.payload[0]>>4)==6 &&
                          np.payload_len>=60 && np.payload[6]==6)) &&
                        !(np.have_mark && mark && np.mark == mark)) {
                        uint8_t family=np.payload[0]>>4;
                        size_t pf_cap=d2k_raw_route_maxlen_family(raw,np.payload+(family==6?24:16),family);
                        if (pf_cap>d2k_raw_maxlen(raw)) pf_cap=d2k_raw_maxlen(raw);
                        d2k_session_preflight_send_cap(sess,pf_cap);
                        int pf = d2k_preflight_path_packet_path(sess, np.payload, np.payload_len,
                            np.id, t, &pf_io, preflight_path);
                        if (pf) {
                            if (pf < 0) fprintf(stderr, "d2kd: preflight NF_DROP failed\n");
                            continue;
                        }
                    }

                    /* QUIC split hold starts before session inspection, so the
                       first tail cannot escape while the ClientHello is still
                       incomplete.  The session only classifies; it never
                       concatenates these datagrams. */
                    int udp_fed = udp_holding && np.have_payload && !np.truncated &&
                        d2k_udp_path_pre(&udp_path, np.id, np.payload, np.payload_len,
                                         umark, t, &udp_key);
                    if (holding && np.have_payload && !np.truncated) {
                        /* НАЧАЛО ПОТОКА — ИЗ САМОГО ПОТОКА, а не из первого
                           байта куска: куски приветствия приходят в любом
                           порядке (замерено 17.09), и угадывать по содержимому
                           нельзя (см. d2k_capture_feed). */
                        uint32_t anchor = 0;
                        int have_anchor = d2k_session_stream_anchor(sess, np.payload,
                                                                    np.payload_len, &anchor);
                        /* Решается по ОРИГИНАЛУ до сборки: после READY np.payload
                           — синтетический пакет, у него порт тот же, но правило
                           должно читаться с того, что взято у ядра. */
                        int owned_take = hold_owns(&hc, np.payload, np.payload_len);
                        int hr = d2k_hold_feed(holding, np.id, np.payload, np.payload_len,
                            t, d2k_session_plan_revision(sess),
                            d2k_session_hold_candidate(sess, np.payload, np.payload_len),
                            anchor, have_anchor,
                            release_original, &hc, &batch);
                        if (hr == 1) {
                            /* Зонд контроллера узнаётся по метке; его строки
                               пишет своя ветка ниже. */
                            int probe_here = probe_mark != 0 && np.have_mark &&
                                             np.mark == probe_mark;
                            if (!probe_here && client_tcp_logged < D2K_CLIENT_TCP_LOG) {
                                unsigned sp = 0, dp = 0; size_t pl = 0; uint8_t f0 = 0;
                                if (client_tcp_ports(np.payload, np.payload_len,
                                                     &sp, &dp, &pl, &f0) && dp == 443) {
                                    client_tcp_logged++;
                                    fprintf(stderr, "d2kd: клиент TCP %u -> %u len=%zu: удержан; "
                                                    "кусок приветствия собирается; applied=0 emits=0%s\n",
                                            sp, dp, pl,
                                            client_tcp_logged == D2K_CLIENT_TCP_LOG
                                                ? " (дальше без журнала)" : "");
                                }
                            }
                            /* Взят в слот (или уже возвращён на провод из него):
                               у ядра копия больше не нужна — иначе хвост
                               локального потока не выйдет (см. hold_owns). */
                            if (owned_take) {
                                (void)send_original_verdict(&hc, np.id, D2K_NF_DROP);
                                st.hold_owned++;
                            }
                            continue; /* ID still held or already released */
                        }
                        if (hr == 2) {
                            if (owned_take) {
                                (void)send_original_verdict(&hc, np.id, D2K_NF_DROP);
                                st.hold_owned++;
                                batch_owned = 1;
                            }
                            np.payload = batch.packet;
                            np.payload_len = batch.len;
                        }
                    }

                    /* Observe the same assembled request identity as Session.
                       WAIT owns all originals; a synthetic view is never sent. */
                    d2k_http80_res http_observation={0};
                    if (np.have_payload && !np.truncated &&
                        !(probe_mark && np.have_mark && np.mark == probe_mark) &&
                        http80_step(q, mode == MODE_APPLY ? raw : NULL, ctl, np.id,
                                    np.payload, np.payload_len, t,
                                    np.have_tstamp ? np.tstamp_ns : 0, &http_observation)) {
                        continue;
                    }


                    uint32_t verdict = D2K_NF_ACCEPT;
                    d2k_result res;
                    memset(&res, 0, sizeof res);
                    res.verdict = D2K_VERDICT_ACCEPT;
                    /* memset обнулил бы номер первой посылки нагрузки, а ноль
                       — законный НОМЕР. Ставим «нагрузки нет» явно: ветки, до
                       которых сессия не дошла, не должны выглядеть так, будто
                       нагрузка стоит первой. */
                    res.first_payload = 0xFF;
                    int controller_probe = probe_mark != 0 && np.have_mark &&
                                           np.mark == probe_mark;
                    size_t tcp_segment_cap = mode == MODE_APPLY
                        ? tls_route_segment_cap(raw, np.payload, np.payload_len) : 0;

                    if (!np.have_payload) {
                        st.no_payload++;
                        res.skipped = "ядро не отдало пакет";
                    } else if (np.truncated) {
                        /* Рассуждать о куске, считая его целым, нельзя. */
                        st.truncated++;
                        res.skipped = "пакет обрезан copy_range";
                    } else {
                        if (controller_probe) {
                            if (tcp_segment_cap) {
                                d2k_session_packet_probe_mtu(sess, np.payload, np.payload_len, t,
                                                             tcp_segment_cap, obuf, sizeof obuf, &res);
                            } else {
                                d2k_session_packet_probe(sess, np.payload, np.payload_len, t,
                                                         obuf, sizeof obuf, &res);
                            }
                        } else {
                            if (tcp_segment_cap) {
                                d2k_session_packet_mtu(sess, np.payload, np.payload_len, t,
                                                       tcp_segment_cap, obuf, sizeof obuf, &res);
                            } else {
                                d2k_session_packet(sess, np.payload, np.payload_len, t,
                                                   obuf, sizeof obuf, &res);
                            }
                        }
                    }

                    /* Rules set the watch on SYN. Release only ACCEPTed current
                       packets; owned/delayed DROP IDs must never be re-injected. */
                    /* Пакет наблюдаемого потока (этап 49) не освобождается с битом
                       снятия: правило D2K_WCLR сняло бы метку наблюдения. */
                    int late_observed = np.have_payload && !np.truncated &&
                                        d2k_lw_packet(&lwt, np.payload, np.payload_len, t);
                    if (release_bit && mode == MODE_APPLY && np.have_payload && !np.truncated &&
                        !late_observed && !(np.have_mark && (np.mark & release_bit)) &&
                        d2k_session_retry_watch(sess, np.payload, np.payload_len) == 0)
                        d2k_nfq_release_packet(q, np.id, np.have_mark ? np.mark : 0, release_bit);

                    if (controller_probe && np.payload && np.payload_len >= 28 &&
                        np.payload[9] == 17) {
                        size_t ihl = (size_t)(np.payload[0] & 15u) * 4u;
                        if ((np.payload[0] >> 4) == 4 && ihl >= 20 &&
                            ihl + 8 <= np.payload_len) {
                            const uint8_t *udp = np.payload + ihl;
                            unsigned sport = ((unsigned)udp[0] << 8) | udp[1];
                            unsigned dport = ((unsigned)udp[2] << 8) | udp[3];
                            fprintf(stderr, "d2kd: verifier UDP %u -> %u hook=%u: %s; "
                                            "applied=%u emits=%zu verdict=%u\n",
                                    sport, dport, np.hook,
                                    res.skipped ? res.skipped : "план исполнен",
                                    (unsigned)res.applied, res.n_out, verdict);
                        }
                    }

                    /* Владение ID: удержан — молчим; собран — повтор головы
                       через план; взят удержанием, но сессия не удержала и не
                       собрала (ранний выход) — ячейка выпущена целиком здесь,
                       этот ID в ней (ревью I1). */
                    int udp_how = udp_holding
                        ? d2k_udp_path_post(&udp_path, udp_fed, &udp_key, &res, &udp_batch)
                        : D2K_UDP_PATH_NORMAL;
                    /* РЕШЕНИЯ ПО КЛИЕНТСКОМУ QUIC — В ЖУРНАЛ (поле 15.10.2026).
                       Строки исполнения писались только для зондов контроллера,
                       и о потоке Chrome, на который план не лёг, датапат не
                       сказал ни слова: ни «удержан», ни «нет плана», ни отказ.
                       Первые D2K_CLIENT_QUIC_LOG решений на запуск, дальше
                       только счётчик. */
                    if (!controller_probe && np.payload && np.payload_len >= 28 &&
                        np.payload[9] == 17 && (np.payload[0] >> 4) == 4) {
                        size_t ihl = (size_t)(np.payload[0] & 15u) * 4u;
                        if (ihl >= 20 && ihl + 8 <= np.payload_len) {
                            const uint8_t *udp = np.payload + ihl;
                            unsigned sport = ((unsigned)udp[0] << 8) | udp[1];
                            unsigned dport = ((unsigned)udp[2] << 8) | udp[3];
                            static unsigned client_quic_logged;
                            if (dport == 443 && client_quic_logged < D2K_CLIENT_QUIC_LOG) {
                                client_quic_logged++;
                                const char *how =
                                    udp_how == D2K_UDP_PATH_HELD ? "удержан" :
                                    udp_how == D2K_UDP_PATH_RECLAIMED ? "выпущен из удержания" :
                                    udp_how == D2K_UDP_PATH_REPLAY ? "собран, повтор головы" :
                                    udp_how == D2K_UDP_PATH_LOST ? "удержание потеряно" :
                                    udp_holding ? "без удержания" : "удержание выключено";
                                fprintf(stderr, "d2kd: клиент QUIC %u -> %u len=%zu%s%s%s: %s; %s; "
                                                "applied=%u emits=%zu%s\n",
                                        sport, dport, np.payload_len - ihl - 8,
                                        res.flow_name[0] ? " имя=" : "", res.flow_name,
                                        res.shape_miss ? " (имя в таблице, формы QUIC нет)" : "",
                                        how,
                                        res.skipped ? res.skipped : "решение без отказа",
                                        (unsigned)res.applied, res.n_out,
                                        client_quic_logged == D2K_CLIENT_QUIC_LOG
                                            ? " (дальше без журнала)" : "");
                            }
                        }
                    }
                    if (udp_how == D2K_UDP_PATH_HELD || udp_how == D2K_UDP_PATH_RECLAIMED) {
                        continue;
                    }
                    if (udp_how == D2K_UDP_PATH_REPLAY) {
                        udp_replay = 1;
                        /* Apply the ordinary plan to the first original
                           datagram only.  The remaining originals retain
                           their own datagram boundaries and are released
                           separately below. */
                        np.id = udp_batch.ids[0];
                        np.payload = udp_batch.packets[0];
                        np.payload_len = udp_batch.len[0];
                        memset(&res, 0, sizeof res);
                        res.verdict = D2K_VERDICT_ACCEPT;
                        res.first_payload = 0xFF;
                        if (controller_probe) {
                            if (tcp_segment_cap) {
                                d2k_session_packet_probe_mtu(sess, np.payload, np.payload_len, t,
                                                             tcp_segment_cap, obuf, sizeof obuf, &res);
                            } else {
                                d2k_session_packet_probe(sess, np.payload, np.payload_len, t,
                                                         obuf, sizeof obuf, &res);
                            }
                        } else {
                            if (tcp_segment_cap) {
                                d2k_session_packet_mtu(sess, np.payload, np.payload_len, t,
                                                       tcp_segment_cap, obuf, sizeof obuf, &res);
                            } else {
                                d2k_session_packet(sess, np.payload, np.payload_len, t,
                                                   obuf, sizeof obuf, &res);
                            }
                        }
                        if (controller_probe) {
                            fprintf(stderr, "d2kd: verifier QUIC replay: %s; applied=%u emits=%zu\n",
                                    res.skipped ? res.skipped : "план исполнен",
                                    (unsigned)res.applied, res.n_out);
                        } else {
                            fprintf(stderr, "d2kd: клиент QUIC replay головы имя=%s%s: %s; applied=%u emits=%zu\n",
                                    res.flow_name,
                                    res.shape_miss ? " (имя в таблице, формы QUIC нет)" : "",
                                    res.skipped ? res.skipped : "план исполнен",
                                    (unsigned)res.applied, res.n_out);
                        }
                    } else if (udp_how == D2K_UDP_PATH_LOST) {
                        /* A missing slot is an internal ownership failure, not
                           a reason to leave the NFQUEUE ID pending forever. */
                        res.udp_hold_ready = 0;
                        res.skipped = "split QUIC hold исчез до replay";
                    }

                    if (res.routed_first) {
                        uint64_t rf = d2k_session_routed_flows(sess);
                        if (rf <= 16 && res.routed_mark == D2K_ROUTE_OTHER_DEV) {
                            char dev[IF_NAMESIZE] = "?";
                            if (!np.have_outdev || !if_indextoname(np.outdev, dev)) {
                                snprintf(dev, sizeof dev, "#%u", np.outdev);
                            }
                            fprintf(stderr, "d2kd: поток клиента уходит через %s — не тем "
                                            "выходом, что сырая посылка; идёт "
                                            "ядром, без плана%s\n", dev,
                                    rf == 16 ? " (дальше только счётчик)" : "");
                        } else if (rf <= 16) {
                            fprintf(stderr, "d2kd: поток клиента с меткой маршрутизации 0x%x "
                                            "идёт ядром, без плана%s\n", res.routed_mark,
                                    rf == 16 ? " (дальше только счётчик)" : "");
                        }
                    }
                    if (res.skipped) {
                        count_reason(res.skipped);
                    }

                    if (mode == MODE_APPLY) {
                        if (res.verdict == D2K_VERDICT_DROP) {
                            verdict = D2K_NF_DROP;
                        }
                    }


                    /* ПОРЯДОК ЗДЕСЬ — ЧАСТЬ ПЛАНА, А НЕ ДЕТАЛЬ.
                     *
                     * Посылки без задержки уходят ДО вердикта. Плечо
                     * place=before означает «фальшивка перед нагрузкой»; если
                     * сперва отпустить оригинал, фальшивка придёт коробке
                     * после него, и плечо превратится в другое. Первая
                     * редакция службы посылала вердикт первым делом, ради
                     * освобождения ячейки очереди, — и молча ломала бы
                     * каждое плечо с place=before.
                     *
                     * Ячейка при этом держится дольше ровно на одну
                     * sendto — десятки микросекунд.
                     *
                     * Задержки отсчитываются от предыдущей посылки. */

                    /* ПРЕДЕЛ ДЛИНЫ — ПО РЕАЛЬНО СОБРАННЫМ ПОСЫЛКАМ, ДО ПЕРВОЙ
                     * ОТПРАВКИ.
                     *
                     * d2k_plan_fits считает то, что план объявляет САМ:
                     * приманки фальшивок и приставку перекрытия. Кусок
                     * нагрузки зависит от ПАКЕТА и на этапе установки
                     * неизвестен, поэтому перекрытие на полном сегменте
                     * проходит проверку установки и упирается в ядро уже
                     * здесь. Здесь длины известны точно — это готовые пакеты
                     * вместе с заголовками.
                     *
                     * Отказ до первой отправки — единственный случай, когда
                     * чистый выход есть: воздействия не было, поток не
                     * испорчен, оригинал уходит нетронутым. Частичная
                     * отправка такого выхода уже не даёт, поэтому проверяем
                     * ВСЕ посылки разом, а не по одной на ходу. */
                    const size_t http_planned = res.n_out;
                    const uint64_t http_sent_before = st.emitted_now;
                    const uint64_t http_queued_before = st.deferred;
                    int payload_on_wire = 0;
                    uint64_t at = t;
                    int output_failed = send_result(sess, raw, sched, mode, t, &res,
                        obuf, np.have_payload ? np.payload : NULL, np.payload_len,
                        &verdict, &payload_on_wire, &at);

                    /* ХВОСТЫ УДЕРЖАННОЙ ПАЧКИ — ЗА ГОЛОВОЙ (задачи 42, 46).
                     *
                     * План забрал голову (fate drop) — она ушла последней его
                     * посылкой; не забрал или плана нет — голова уходит ядру
                     * своим вердиктом. Остальные датаграммы пачки в обоих
                     * случаях уходят нашей посылкой следом, их копии в очереди
                     * снимаются (см. tail_resend). Раньше так было только при
                     * плане, а пачка без плана отдавала хвосты ядру — и каждый
                     * снимался как дубль (поле 03.10.2026). */
                    int owned_batch = 0;
                    if (udp_replay) {
                        owned_batch = mode == MODE_APPLY && raw && res.applied &&
                                      !output_failed && verdict == D2K_NF_DROP;
                    }

                    int delayed_originals = 0;
                    if (udp_replay && !owned_batch && res.applied && !output_failed &&
                        udp_batch.count > 1 && at > t && udp_releases) {
                        uint32_t ids[D2K_UDP_HOLD_PACKETS];
                        uint32_t verdicts[D2K_UDP_HOLD_PACKETS];
                        for (size_t i = 0; i < udp_batch.count; i++) {
                            ids[i] = udp_batch.ids[i];
                            verdicts[i] = (i == 0) ? verdict : D2K_NF_ACCEPT;
                        }
                        if (d2k_udp_release_enqueue(udp_releases, at, ids, verdicts,
                                                    udp_batch.count, &res.key,
                                                    res.execution_id) == 0) {
                            delayed_originals = 1;
                        } else {
                            /* Bounded ownership is fail-open: never leave
                               NFQUEUE IDs pending when the release ring is
                               full. The generated plan is marked incomplete,
                               then the ordinary verdict path below releases
                               every original immediately. */
                            output_failed = 1;
                            if (d2k_session_exec_failed(sess, t, &res.key, res.plan_id,
                                                        D2K_REFUSE_QUEUE,
                                                        res.execution_id, 0, 0)) {
                                verdict = D2K_NF_ACCEPT;
                            }
                        }
                    }

                    int original_failed = 0;
                    int postnat_owned = pn && mode == MODE_APPLY && !route_gate &&
                        (!controller_probe || (res.udp_defer_binding.shape==D2K_PLAN_SHAPE_DNS &&
                            !res.udp_defer_binding.temporary)) && outbound && !batch.count &&
                        postnat_begin(pn, &np, &res, udp_replay ? &udp_batch : NULL,
                                      np.have_mark ? np.mark : 0, t, udp_path.seq);
                    if (postnat_owned) {
                        /* Marked ACCEPT already sent; continuation owns head and tails. */
                    } else if (udp_replay && res.quic_deny) {
                        /* QUIC для имени не пропускается: вся пачка снимается,
                           хвосты не уходят ни ядром, ни нашей посылкой —
                           иначе сервер получил бы часть ClientHello. */
                        for (size_t i = 0; i < udp_batch.count; i++) {
                            if (out_verdict(&hc, udp_batch.ids[i], D2K_NF_DROP) != 0) {
                                original_failed = 1;
                            }
                        }
                    } else if (udp_replay && !delayed_originals) {
                        /* Only the first original was replaced by the
                           strategy.  Later QUIC datagrams are real client
                           input and must remain in the stream: they follow
                           the head out through the raw path. */
                        original_failed = d2k_udp_out_batch(&udp_out, &udp_batch, verdict,
                                                            owned_batch, at, t, udp_path.seq) != 0;
                    } else if (!delayed_originals && !batch.count &&
                               verdict == D2K_NF_ACCEPT && !res.applied &&
                               np.have_payload && !np.truncated &&
                               d2k_udp_out_late(&udp_out, np.id, np.payload,
                                                np.payload_len, umark,
                                                t, udp_path.seq,
                                                &original_failed)) {
                        /* ЗАПОЗДАВШИЙ ХВОСТ (задача 46): голова потока уже
                           выпущена одна (имя собралось на ней), а эта
                           датаграмма стояла в очереди за ней со своей
                           неподтверждённой записью — 0-RTT, вторая половина
                           ClientHello, повтор. Тот же путь, что у хвоста пачки;
                           не ушла — отдаём ядру. Поле 03.10.2026: такой хвост
                           спланированного Initial снимался всякий раз. Только
                           в окне столкновения (та же пачка приёма или ≤5 мс);
                           позже — обычный ACCEPT. Вердикт выдан там. */
                    } else if (!delayed_originals && batch_owned) {
                        /* ОРИГИНАЛЫ СОБРАННОГО ПРИВЕТСТВИЯ УЖЕ У НАС (hold_owns).
                           План лёг (fate drop) — они ушли его посылкой. Не лёг
                           или отказан — возвращаются на провод как есть, по
                           порядку потока. Вердиктов этим ID больше нет. */
                        original_failed = 0;
                        if (verdict == D2K_NF_ACCEPT) {
                            original_failed = resend_originals(&hc, &batch) != 0;
                        }
                    } else if (!delayed_originals) {
                        const uint32_t *original_ids = batch.count ? batch.ids : &np.id;
                        size_t original_count = batch.count ? batch.count : 1;
                        original_failed = d2k_hold_verdicts(original_ids, original_count,
                                                            verdict, send_original_verdict,
                                                            &hc) != 0;
                        /* ПЕРВАЯ ДАТАГРАММА ПОТОКА БЕЗ УДЕРЖАНИЯ (поле 03.10 после
                           4ed54d4): то, что стоит в очереди за ней, пришло в
                           conntrack до её вердикта — тот же путь, что за
                           выпущенной головой. */
                        if (!batch.count && !original_failed && verdict == D2K_NF_ACCEPT &&
                            !res.applied && np.have_payload && !np.truncated) {
                            (void)d2k_udp_path_passed(&udp_path, np.payload,
                                                      np.payload_len, umark, t);
                        }
                        /* UDP-ПЛАН БЕЗ УДЕРЖАНИЯ (голос/STUN, задача 47): план
                           забрал датаграмму и выпустил её после своих сырых
                           посылок — их запись уже подтверждена, и то, что
                           стоит в очереди за ней, пойдёт тем же путём. */
                        if (!batch.count && !original_failed && !output_failed &&
                            mode == MODE_APPLY && res.applied && verdict == D2K_NF_DROP &&
                            np.have_payload && !np.truncated) {
                            (void)d2k_udp_path_planned(&udp_path, np.payload,
                                                       np.payload_len, umark, at, t);
                        }
                    }
                    if (original_failed) {
                        if (res.applied && mode == MODE_APPLY) {
                            /* Возврат игнорируется намеренно: вердикт ядру не
                               дошёл, отпускать оригинал уже нечем. */
                            (void)d2k_session_exec_failed(sess, t, &res.key, res.plan_id,
                                                          D2K_REFUSE_SEND, res.execution_id,
                                                          payload_on_wire, 1);
                        }
                    } else if (!delayed_originals && res.applied && mode == MODE_APPLY) {
                        d2k_session_sent(sess, t, &res.key, res.execution_id);
                    }
                    if (preflight && mode==MODE_APPLY && !controller_probe &&
                        np.have_payload && !np.truncated) {
                        if (d2k_preflight_path_complete_on(sess,np.payload,np.payload_len,t,&pf_io,preflight_path))
                            fprintf(stderr,"d2kd: preflight cleanup send failed\n");
                    }
                    if(!controller_probe && np.have_payload && !np.truncated) {
                        d2k_http80_delivered(http80,np.payload,np.payload_len,
                            !original_failed && !delayed_originals && verdict==D2K_NF_ACCEPT,
                            &http_observation);
                        /* A late known portal is a suspicion even before any
                           plan exists. Complete responses still need their
                           execution identity to become plan evidence. */
                        if(http_observation.response &&
                           (http_observation.execution_id || http_observation.response == 3 ||
                            http_observation.response == D2K_HTTP80_RESET_BEFORE_RESPONSE ||
                            http_observation.response == D2K_HTTP80_RETRY_BEFORE_RESPONSE) &&
                           http_observation.response!=D2K_HTTP80_CUT) /* обрыв уже сообщён */
                            d2k_ctlsrv_http80_event(ctl,&http_observation);
                    }
                    /* One live-request result after the actual raw sends and
                       NFQUEUE verdict. PREPARED alone is never success. */
                    if (!controller_probe && np.have_payload && !np.truncated) {
                        d2k_http_trace_outcome outcome = {
                            .apply = mode == MODE_APPLY,
                            .output_failed = output_failed,
                            .original_failed = original_failed,
                            .original_pending = delayed_originals,
                            .pending = res.applied && d2k_session_send_pending(sess, &res.key, res.execution_id),
                            .hook = np.hook, .mark = np.have_mark ? np.mark : 0,
                            .outdev = np.have_outdev ? np.outdev : 0, .verdict = verdict,
                            .planned = http_planned,
                            .sent = (size_t)(st.emitted_now - http_sent_before),
                            .queued = (size_t)(st.deferred - http_queued_before)
                        };
                        char line[1600];
                        if (outcome.apply && res.applied && !outcome.output_failed &&
                            !outcome.original_failed && !outcome.original_pending && !outcome.pending) {
                            d2k_http80_executed(http80, np.payload, np.payload_len, t,
                                res.execution_id, res.plan_id, res.trial_id, &res.binding);
                        }
                        if (d2k_http_trace(line, sizeof line, np.payload, np.payload_len, &res, &outcome)) {
                            fprintf(stderr, "%s\n", line);
                        }
                        static unsigned tls_logged;
                        if (tls_logged < 300 &&
                            d2k_tls_trace(line, sizeof line, np.payload, np.payload_len,
                                          &res, &outcome, batch.count, batch_owned)) {
                            tls_logged++;
                            fprintf(stderr, "%s%s\n", line,
                                tls_logged == 300 ? " (TLS trace limit reached)" : "");
                        }
                    }
                }
            }
        }

        /* --- созревшие отложенные ------------------------------------------ */
        t = now_ns();
        if (raw) {
            size_t slen = 0;
            d2k_key skey;
            uint64_t execution;
            int owned = 0, popped;
            uint32_t owner_id = 0;
            while ((popped = d2k_sched_pop_due_ex(sched, t, sbuf, sizeof sbuf, &slen, &skey,
                                                  &execution, &owned, &owner_id)) != 0) {
                /* ОТЛОЖЕННЫЙ ХВОСТ UDP СО СВОИМ ID (ревью I-A m-2): ушёл —
                   DROP копии, не ушёл (полный сокет) — копия идёт ядром, а не
                   теряется. Ровно один вердикт. */
                if (owned) {
                    int e = 0;
                    if (popped < 0) {
                        e = EMSGSIZE;
                    } else if (d2k_raw_send(raw, sbuf, slen, err, sizeof err) != 0) {
                        e = errno ? errno : EIO;
                        st.send_fail++;
                        log_send_fail("отложенный хвост UDP: ", err, e);
                    } else {
                        st.emitted++;
                        st.emitted_late++;
                    }
                    if (d2k_udp_out_owned_emit(&udp_out, owner_id, e) != 0) {
                        st.verdict_fail++;
                    }
                    continue;
                }
                if (popped < 0) { continue; }
                /* Нулевой ключ означает «клали без метки» (лаборатория):
                   приписывать такую посылку некому, и молчание тут честнее
                   выдумки. */
                int named = (skey.proto != 0);
                if (named && !d2k_session_send_pending(sess, &skey, execution)) {
                    /* Поток забыт, отказал или переиспользован: старые байты
                       не шлём. Считаем отдельно — разрыв между «подготовлен» и
                       «доисполнен» объясняется чаще всего именно здесь. */
                    st.stale_deferred++;
                    continue;
                }
                if (d2k_raw_send(raw, sbuf, slen, err, sizeof err) != 0) {
                    int send_errno = errno;
                    uint8_t failure = refuse_of_errno(send_errno);
                    st.send_fail++;
                    log_send_fail("отложенная посылка: ", err, send_errno);
                    if (named) {
                        /* Вердикт этой попытки ядру уже ушёл: оригинал либо на
                           проводе, либо уничтожен, и копии у нас нет. Хранить
                           его ради этого нельзя — это память на каждый
                           применённый план и риск послать байты дважды.
                           Решает сохранённое владение: план забирал оригинал —
                           поток испорчен; план из одних фальшивок — поток цел,
                           и факт только один: воздействие неполно. */
                        (void)d2k_session_exec_failed(sess, t, &skey, NULL, failure,
                                                      execution, 0, 1);
                    }
                } else {
                    st.emitted++;
                    st.emitted_late++;
                    if (named) {
                        d2k_session_sent(sess, t, &skey, execution);
                    }
                }
            }
        }

        if (pn) { pn->seq = udp_path.seq; pn->drained_at = t; postnat_step(pn, 0); }

        /* A split QUIC batch may keep its original NFQUEUE verdict behind the
           last delayed fake.  Drain only after the raw scheduler above has
           emitted every due fake, so the tail cannot overtake REC_DELAY. */
        if (udp_releases) {
            (void)d2k_udp_release_flush(udp_releases, now_ns(),
                                         send_delayed_verdict,
                                         delayed_verdict_done, &hc);
        }

        /* Drain every due FSM, not just the first bounded output batch. */
        while (d2k_session_preflight_next_ns(sess) &&
               d2k_session_preflight_next_ns(sess) <= t) {
            if (d2k_preflight_path_tick(sess, t, &pf_io) != 0)
                fprintf(stderr, "d2kd: preflight timer raw send failed\n");
        }

        if (t >= next_expire) {
            for (int i = 0; i < 2; i++) {
                if (!fw_repair_enabled[i] || access(fw_repair_path[i], F_OK) != 0) continue;
                uint8_t family = i ? 6 : 4;
                if (!fw_repair_started[i] && lwx) d2k_lw_family_mangle_reset(&lwt, family, t);
                fw_repair_started[i] = 1;
                if ((!lwx || !d2k_lw_family_repair_pending(&lwt, family)) &&
                    rmdir(fw_repair_path[i]) == 0) fw_repair_started[i] = 0;
            }
            /* Сперва заметить молчание, потом забывать. Обратный порядок
               означал бы, что о молчании узнаём только при забвении потока —
               через две минуты, когда человек уже ушёл со страницы. */
            d2k_session_sweep(sess, t);
            if (http80) { (void)d2k_http80_sweep(http80, t, http80_cut, ctl); }
            d2k_session_expire(sess, t, idle_ns);
            if (lwx) {
                d2k_lw_done lwd;
                while (d2k_lwexec_poll(lwx, &lwd)) { d2k_lw_complete(&lwt, &lwd, t); }
                d2k_lw_tick(&lwt, t, ctl && d2k_ctl_peer_fd(ctl) < 0);
            }
            /* Окно следования — миллисекунды: всё старше и из прежних пачек
               приёма убирается (финальное ревью M-5). */
            d2k_udp_follow_age(udp_follow, t, udp_path.rseq + 1);
            next_expire = t + NS_PER_S;
        }
        if (ctl) {
            d2k_ctlsrv_pump(ctl, sess, &events_seen);
        }
        if (ctl && t >= next_ctl_stats) {
            /* Счётчики потерь канала — раз в секунду (тело и ключ — в ctlsrv,
               рядом с приветствием: один формат событий без потока). */
            d2k_ctlsrv_stats(ctl);
            next_ctl_stats = t + NS_PER_S;
        }
        if (next_stats && t >= next_stats) {
            print_stats(sess, sched, q, raw, t - start);
            next_stats = t + (uint64_t)stats_s * NS_PER_S;
        }
    }

    fprintf(stderr, "d2kd: engine-exit time=%ld pid=%ld signal=%d sender_pid=%d duration_s=%u\n",
            (long)time(NULL), (long)getpid(), (int)stop_flag, (int)stop_sender, duration_s);
    d2k_hold_flush(holding, now_ns(), 0, 1, release_original, &hc);
    (void)d2k_udp_path_expire(&udp_path, now_ns(), 0);
    if (udp_releases) {
        (void)d2k_udp_release_flush(udp_releases, UINT64_MAX,
                                     send_delayed_verdict,
                                     delayed_verdict_done, &hc);
        size_t cancelled = d2k_udp_release_cancel(udp_releases,
                                                  delayed_verdict_done, &hc);
        if (cancelled)
            fprintf(stderr, "d2kd: shutdown incomplete delayed-verdict batches=%zu; unresolved IDs retire when NFQUEUE closes\n", cancelled);
    }
    /* Return every SYN owned by an unfinished probe while the marked raw
     * socket is still alive. No conntrack/firewall edits belong to this step. */
    while (d2k_session_preflight_next_ns(sess)) {
        if (d2k_preflight_path_flush(sess, now_ns(), &pf_io) != 0) {
            fprintf(stderr, "d2kd: preflight shutdown raw send failed\n");
            break; /* no busy loop on a persistent local sender failure */
        }
    }
    /* The returned SYNs still need their queued NF_REPEAT. Closing NFQUEUE
     * here would discard those SYNs and leave their watch bits behind. */
    if (preflight_releases_pending) {
        uint64_t stop_at=now_ns()+2*NS_PER_S;
        while (preflight_releases_pending && now_ns()<stop_at) {
            struct pollfd p={d2k_nfq_fd(q),POLLIN,0};
            if (poll(&p,1,10)<=0) continue;
            ssize_t n=d2k_nfq_recv(q,rbuf,sizeof rbuf,err,sizeof err);
            if(n<=0) continue;
            d2k_nl_iter it; d2k_nl_msg m;
            d2k_nl_iter_init(&it,rbuf,(size_t)n);
            while(d2k_nl_next(&it,&m)) {
                d2k_nl_pkt np;
                if ((m.type&0xff)!=D2K_NFQNL_MSG_PACKET ||
                    d2k_nl_packet(&m,&np) || !np.have_hdr) continue;
                if (preflight_repeat(q,&np)) continue;
                d2k_nfq_release_packet(q,np.id,np.have_mark ? np.mark : 0,0);
                (void)d2k_nfq_verdict(q,np.id,D2K_NF_ACCEPT,err,sizeof err);
            }
        }
        if(preflight_releases_pending)
            fprintf(stderr,"d2kd: preflight shutdown incomplete: %zu release requests not received\n",preflight_releases_pending);
    }
    /* Originals already committed by completed groups cannot be replayed
       on shutdown. Explicitly fail their remaining queued sends; never let
       freeing the queue silently leave an execution waiting for DONE. */
    {
        size_t slen;
        d2k_key skey;
        uint64_t execution;
        int owned = 0;
        uint32_t owner_id = 0;
        while (d2k_sched_pop_due_ex(sched, UINT64_MAX, sbuf, sizeof sbuf,
                                    &slen, &skey, &execution, &owned, &owner_id) != 0) {
            if (owned) {
                /* Хвост клиента не ушёл — его копия идёт ядром. */
                (void)d2k_udp_out_owned_emit(&udp_out, owner_id, ECANCELED);
                continue;
            }
            if (skey.proto && d2k_session_send_pending(sess, &skey, execution)) {
                (void)d2k_session_exec_failed(sess, now_ns(), &skey, NULL,
                    D2K_REFUSE_QUEUE, execution, 0, 1);
            }
            st.stale_deferred++;
        }
    }
    if (pn) {
        pn->drained_at = UINT64_MAX; /* scheduler cancelled above */
        uint64_t warn_at = now_ns() + 2 * NS_PER_S;
        /* Reserve the rest of the service's ten-second datapath stop grace
         * for filter/device cleanup and the late-worker join. */
        uint64_t stop_at = now_ns() + 2500 * NS_PER_MS;
        while (postnat_pending(pn)) {
            postnat_step(pn, 1);
            if (postnat_pending(pn)) {
                if (now_ns() >= stop_at) {
                    postnat_stop_incomplete(pn);
                    break;
                }
                if (now_ns() >= warn_at) {
                    fprintf(stderr, "d2kd: postnat shutdown waits for capture/verdict/sender; retained originals are not discarded or blindly replayed\n");
                    warn_at = now_ns() + 30 * NS_PER_S;
                }
                struct pollfd p = {pn->capture_failed ? -1 : d2k_postnat_capture_fd(pn->capture), POLLIN, 0};
                (void)poll(&p, 1, 2);
            }
        }
        if (d2k_postnat_capture_close(pn->capture, err, sizeof err))
            fprintf(stderr, "d2kd: postnat cleanup: %s\n", err);
        if (pn->ct >= 0) close(pn->ct);
        fprintf(stderr, "d2kd: postnat totals owned=%llu prepared=%llu fallback=%llu pending=%zu\n",
                (unsigned long long)pn->accepted, (unsigned long long)pn->continued,
                (unsigned long long)pn->fallback_count, d2k_postnat_own_pending(pn->own));
        d2k_postnat_own_free(pn->own); free(pn);
    }
    printf("\n=== итог d2kd[%ld] ===\n", (long)getpid());
    print_stats(sess, sched, q, raw, now_ns() - start);
    print_journal(sess, start);

    if (lwx && d2k_lwexec_stop(lwx, 2000) != 0) {
        /* Исполнитель висит (iptables -w, ядро): брошен; его остатки (метки, свои
           цепочки) уберёт уборка следующего старта. */
        fprintf(stderr, "d2kd: исполнитель поздней доставки не вышел за 2 с — брошен; остатки уберёт следующий старт\n");
    }
    lwx = NULL;
    d2k_ctl_close(ctl);
    for(unsigned i=0;i<D2K_EXP_PEERS_MAX;i++)if(xpeers[i]) {
        d2k_ctlsrv_forget_exp_ctl(xpeers[i]);d2k_ctl_close(xpeers[i]);
    }
    d2k_ctl_close(xctl);
    /* The hold first, while the scheduler still exists (ревью M3); its
       release sends now (at == now). */
    udp_path.now_ns = now_ns();
    udp_path.seq = D2K_UDP_SEQ_NONE;
    d2k_udp_hold_free(udp_holding, d2k_udp_path_release, &udp_path);
    udp_holding = NULL;
    udp_path.hold = NULL;
    hc.sched = NULL;
    d2k_sched_free(sched);
    d2k_hold_free(holding);
    holding = NULL;
    d2k_udp_release_free(udp_releases);
    udp_releases = NULL;
    d2k_udp_follow_free(udp_follow);
    if (routes_fd >= 0) { close(routes_fd); }
    udp_follow = NULL;
    d2k_http80_free(http80);
    d2k_session_free(sess);
    d2k_nfq_close(q);
    for (unsigned i=0;i<3;i++) { d2k_raw_close(preflight_raw[i]); preflight_raw[i]=NULL; }
    d2k_raw_close(raw);
    return 0;
}
