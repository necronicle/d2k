// nfqview.c — та же работа, что делает Go-версия, но на C и сыром netlink.
// Инструмент замера этапа 0 d2k, НЕ продуктовый код.
//
// Зачем существует: утверждение «другой язык здесь не поможет, потому что
// платим за границу ядро/юзерспейс» — рассуждение, пока нет второй реализации.
// Эта программа делает ровно то же самое, чтобы разница была разницей рантайма,
// а не разницей алгоритма:
//   * один поток, один цикл событий;
//   * вердикт выставляется ПЕРВЫМ делом, до разбора;
//   * разбирается тот же IPv4/IPv6+TCP заголовок, считаются те же поля;
//   * те же выходные файлы.
//
// Внешних библиотек нет намеренно. libnetfilter_queue добавила бы к сравнению
// свой слой, а Go-версия ходит в netlink напрямую — сравнивать надо
// сопоставимое.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef NETLINK_NO_ENOBUFS
#define NETLINK_NO_ENOBUFS 5
#endif

#define NFQ_SUBSYS (NFNL_SUBSYS_QUEUE << 8)

// Чтение полей копированием, а не приведением указателя: пакет лежит по
// произвольному смещению внутри netlink-буфера, а приведение указателя на
// ARM опирается на выравнивание и нарушает строгий алиасинг.
static inline uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return ntohs(v); }
static inline uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return ntohl(v); }
#define RECV_BUF (256 * 1024)
#define MAX_SEQ_SAMPLES 96
#define HASH_BUCKETS 8192

// ---------------------------------------------------------------- параметры
static int opt_queue = 200;
static int opt_copylen = 128;
static int opt_qlen = 8192;
static int opt_dur = 60;
static int opt_tick = 10;
static int opt_batch = 0;
static int dbg_left = 0;
static const char *opt_out = "/tmp/nfqview";
static uint32_t lan_addr = 0, lan_mask = 0;

// ------------------------------------------------------------------- потоки
struct flow {
    struct flow *next;
    uint8_t proto;
    uint8_t is6;
    uint8_t lip[16], rip[16];
    uint16_t lport, rport;

    uint64_t out_pkts, in_pkts, out_bytes, in_bytes;
    uint8_t saw_syn, saw_synack, rst_in, rst_out, fin_in, fin_out;
    uint8_t client_hello, server_hello, last_in_fin, last_in_rst;

    uint32_t in_base, out_base;
    uint8_t in_set, out_set;
    uint32_t in_max, out_max;

    uint32_t in_samples[MAX_SEQ_SAMPLES];
    uint32_t out_samples[MAX_SEQ_SAMPLES];
    int n_in_samples, n_out_samples;

    double first, last, last_in, last_out;
};

static struct flow *buckets[HASH_BUCKETS];
static uint64_t n_flows = 0;

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint32_t hash_key(const uint8_t *lip, const uint8_t *rip, uint16_t lp, uint16_t rp, uint8_t proto) {
    // FNV-1a: дешёвая и достаточная, таблица маленькая и локальная.
    uint32_t h = 2166136261u;
    for (int i = 0; i < 16; i++) { h = (h ^ lip[i]) * 16777619u; }
    for (int i = 0; i < 16; i++) { h = (h ^ rip[i]) * 16777619u; }
    h = (h ^ (lp & 0xff)) * 16777619u;
    h = (h ^ (lp >> 8)) * 16777619u;
    h = (h ^ (rp & 0xff)) * 16777619u;
    h = (h ^ (rp >> 8)) * 16777619u;
    h = (h ^ proto) * 16777619u;
    return h;
}

static struct flow *flow_get(const uint8_t *lip, const uint8_t *rip, uint16_t lp, uint16_t rp,
                             uint8_t proto, uint8_t is6, double t) {
    uint32_t h = hash_key(lip, rip, lp, rp, proto) & (HASH_BUCKETS - 1);
    for (struct flow *f = buckets[h]; f; f = f->next) {
        if (f->proto == proto && f->lport == lp && f->rport == rp &&
            memcmp(f->lip, lip, 16) == 0 && memcmp(f->rip, rip, 16) == 0)
            return f;
    }
    struct flow *f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->proto = proto;
    f->is6 = is6;
    memcpy(f->lip, lip, 16);
    memcpy(f->rip, rip, 16);
    f->lport = lp;
    f->rport = rp;
    f->first = t;
    f->next = buckets[h];
    buckets[h] = f;
    n_flows++;
    return f;
}

// --------------------------------------------------------------- статистика
static uint64_t stat_pkts = 0, stat_bytes = 0, stat_parse_fail = 0, stat_verdict_fail = 0, stat_recv_err = 0;
static volatile sig_atomic_t stop_flag = 0;

static void on_signal(int s) { (void)s; stop_flag = 1; }

// ------------------------------------------------------------------ netlink
static int nl_fd = -1;

static ssize_t nl_send(void *buf, size_t len) {
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    return sendto(nl_fd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
}

static void put_attr(struct nlmsghdr *nlh, uint16_t type, const void *data, uint16_t len) {
    struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    a->nla_type = type;
    a->nla_len = NLA_HDRLEN + len;
    memcpy((char *)a + NLA_HDRLEN, data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(a->nla_len);
}

static struct nlmsghdr *msg_init(char *buf, uint16_t type, uint16_t flags, uint16_t queue) {
    memset(buf, 0, NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg)));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    struct nfgenmsg *nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(queue);
    return nlh;
}

static int queue_config(void) {
    char buf[512];
    struct nlmsghdr *nlh;

    struct nfqnl_msg_config_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.command = NFQNL_CFG_CMD_BIND;
    cmd.pf = htons(AF_INET);
    nlh = msg_init(buf, NFQ_SUBSYS | NFQNL_MSG_CONFIG, NLM_F_REQUEST | NLM_F_ACK, opt_queue);
    put_attr(nlh, NFQA_CFG_CMD, &cmd, sizeof(cmd));
    if (nl_send(buf, nlh->nlmsg_len) < 0) { perror("bind очереди"); return -1; }

    struct nfqnl_msg_config_params params;
    memset(&params, 0, sizeof(params));
    params.copy_range = htonl((uint32_t)opt_copylen);
    params.copy_mode = opt_copylen > 0 ? NFQNL_COPY_PACKET : NFQNL_COPY_META;
    uint32_t maxlen = htonl((uint32_t)opt_qlen);
    // FAIL_OPEN по тем же соображениям, что и в Go-версии: переполнение должно
    // пропускать пакет, а не ронять его. Замер идёт на живом роутере.
    uint32_t flags = htonl(NFQA_CFG_F_FAIL_OPEN), mask = htonl(NFQA_CFG_F_FAIL_OPEN);
    nlh = msg_init(buf, NFQ_SUBSYS | NFQNL_MSG_CONFIG, NLM_F_REQUEST | NLM_F_ACK, opt_queue);
    put_attr(nlh, NFQA_CFG_PARAMS, &params, sizeof(params));
    put_attr(nlh, NFQA_CFG_QUEUE_MAXLEN, &maxlen, sizeof(maxlen));
    put_attr(nlh, NFQA_CFG_FLAGS, &flags, sizeof(flags));
    put_attr(nlh, NFQA_CFG_MASK, &mask, sizeof(mask));
    if (nl_send(buf, nlh->nlmsg_len) < 0) { perror("параметры очереди"); return -1; }
    return 0;
}

static int send_verdict(uint32_t id, int batch) {
    char buf[256];
    struct nfqnl_msg_verdict_hdr vh;
    vh.verdict = htonl(NF_ACCEPT);
    vh.id = htonl(id);
    struct nlmsghdr *nlh = msg_init(buf, NFQ_SUBSYS | (batch ? NFQNL_MSG_VERDICT_BATCH : NFQNL_MSG_VERDICT),
                                    NLM_F_REQUEST, opt_queue);
    put_attr(nlh, NFQA_VERDICT_HDR, &vh, sizeof(vh));
    return nl_send(buf, nlh->nlmsg_len) < 0 ? -1 : 0;
}

// -------------------------------------------------------------------- разбор
static void account(const uint8_t *p, size_t len, double t) {
    if (len < 20) { stat_parse_fail++; return; }

    uint8_t src[16] = {0}, dst[16] = {0};
    uint8_t proto = 0, is6 = 0;
    uint64_t total = 0;
    const uint8_t *l4 = NULL;
    size_t l4len = 0;

    if ((p[0] >> 4) == 4) {
        size_t ihl = (size_t)(p[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl) { stat_parse_fail++; return; }
        total = rd16(p + 2);
        proto = p[9];
        memcpy(src, p + 12, 4);
        memcpy(dst, p + 16, 4);
        if ((rd16(p + 6) & 0x1fff) == 0) { l4 = p + ihl; l4len = len - ihl; }
    } else if ((p[0] >> 4) == 6) {
        if (len < 40) { stat_parse_fail++; return; }
        is6 = 1;
        total = (uint64_t)rd16(p + 4) + 40;
        proto = p[6];
        memcpy(src, p + 8, 16);
        memcpy(dst, p + 24, 16);
        l4 = p + 40;
        l4len = len - 40;
    } else {
        stat_parse_fail++;
        return;
    }

    // Направление по локальной подсети — так же, как в Go-версии. Для IPv6
    // локальной подсети нет, поэтому такой поток считаем исходящим: на этом
    // замере он лишь фон, а выдумывать направление хуже, чем зафиксировать
    // договорённость.
    int outbound = 1;
    if (!is6) {
        uint32_t s, d;
        memcpy(&s, src, 4);
        memcpy(&d, dst, 4);
        if ((s & lan_mask) == lan_addr) outbound = 1;
        else if ((d & lan_mask) == lan_addr) outbound = 0;
    }

    uint16_t sport = 0, dport = 0;
    if ((proto == 6 || proto == 17) && l4 && l4len >= 4) {
        sport = rd16(l4);
        dport = rd16(l4 + 2);
    }

    const uint8_t *lip = outbound ? src : dst;
    const uint8_t *rip = outbound ? dst : src;
    uint16_t lp = outbound ? sport : dport;
    uint16_t rp = outbound ? dport : sport;

    struct flow *f = flow_get(lip, rip, lp, rp, proto, is6, t);
    if (!f) return;
    f->last = t;

    uint8_t fin = 0, syn = 0, rst = 0, ack = 0, ch = 0, sh = 0;
    uint32_t seq = 0;
    if (proto == 6 && l4 && l4len >= 20) {
        seq = rd32(l4 + 4);
        uint8_t fl = l4[13];
        fin = fl & 0x01; syn = fl & 0x02; rst = fl & 0x04; ack = fl & 0x10;
        size_t doff = (size_t)(l4[12] >> 4) * 4;
        if (doff >= 20 && l4len > doff) {
            const uint8_t *pay = l4 + doff;
            size_t paylen = l4len - doff;
            if (paylen >= 6 && pay[0] == 0x16 && pay[1] == 0x03) {
                if (pay[5] == 0x01) ch = 1;
                else if (pay[5] == 0x02) sh = 1;
            }
        }
    }

    if (outbound) {
        f->out_pkts++;
        f->out_bytes += total;
        f->last_out = t;
        if (syn && !ack) f->saw_syn = 1;
        if (rst) f->rst_out = 1;
        if (fin) f->fin_out = 1;
        if (ch) f->client_hello = 1;
        if (proto == 6) {
            if (!f->out_set) { f->out_base = seq; f->out_set = 1; }
            uint32_t d = seq - f->out_base;
            if (d < (1u << 31)) {
                if (d > f->out_max) f->out_max = d;
                if (f->n_out_samples < MAX_SEQ_SAMPLES) f->out_samples[f->n_out_samples++] = d;
            }
        }
    } else {
        f->in_pkts++;
        f->in_bytes += total;
        f->last_in = t;
        if (syn && ack) f->saw_synack = 1;
        if (rst) f->rst_in = 1;
        if (fin) f->fin_in = 1;
        if (sh) f->server_hello = 1;
        f->last_in_fin = fin ? 1 : 0;
        f->last_in_rst = rst ? 1 : 0;
        if (proto == 6) {
            if (!f->in_set) { f->in_base = seq; f->in_set = 1; }
            uint32_t d = seq - f->in_base;
            if (d < (1u << 31)) {
                if (d > f->in_max) f->in_max = d;
                if (f->n_in_samples < MAX_SEQ_SAMPLES) f->in_samples[f->n_in_samples++] = d;
            }
        }
    }
}

// --------------------------------------------------------- счётчики и вывод
struct qstat { uint64_t depth, copy_mode, copy_range, dropped, user_dropped, id_seq; };

// Порядок полей — из nfnetlink_queue.c (seq_show): queue_num, peer_portid,
// queue_total, copy_mode, copy_range, queue_dropped, queue_user_dropped,
// id_sequence, 1. queue_total — ТЕКУЩАЯ глубина, не накопленный счётчик.
static struct qstat read_qstat(void) {
    struct qstat s;
    memset(&s, 0, sizeof(s));
    FILE *fh = fopen("/proc/net/netfilter/nfnetlink_queue", "r");
    if (!fh) return s;
    char line[512];
    while (fgets(line, sizeof(line), fh)) {
        unsigned long q, peer, total, cmode, crange, drop, udrop, idseq;
        if (sscanf(line, "%lu %lu %lu %lu %lu %lu %lu %lu", &q, &peer, &total, &cmode, &crange, &drop, &udrop, &idseq) != 8)
            continue;
        if ((int)q != opt_queue) continue;
        s.depth = total; s.copy_mode = cmode; s.copy_range = crange;
        s.dropped = drop; s.user_dropped = udrop; s.id_seq = idseq;
        break;
    }
    fclose(fh);
    return s;
}

static double read_self_cpu(void) {
    FILE *fh = fopen("/proc/self/stat", "r");
    if (!fh) return 0;
    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fh);
    fclose(fh);
    buf[n] = 0;
    char *p = strrchr(buf, ')');
    if (!p) return 0;
    p++;
    unsigned long ut = 0, st = 0;
    int field = 0;
    char *tok = strtok(p, " ");
    while (tok) {
        field++;
        if (field == 12) ut = strtoul(tok, NULL, 10);
        if (field == 13) { st = strtoul(tok, NULL, 10); break; }
        tok = strtok(NULL, " ");
    }
    return (double)(ut + st) / 100.0;
}

static uint64_t read_self_rss(void) {
    FILE *fh = fopen("/proc/self/statm", "r");
    if (!fh) return 0;
    unsigned long size = 0, rss = 0;
    if (fscanf(fh, "%lu %lu", &size, &rss) != 2) rss = 0;
    fclose(fh);
    return (uint64_t)rss * (uint64_t)getpagesize();
}

static void ipstr(const uint8_t *ip, int is6, char *out, size_t n) {
    if (is6) inet_ntop(AF_INET6, ip, out, (socklen_t)n);
    else inet_ntop(AF_INET, ip, out, (socklen_t)n);
}

static void write_outputs(double elapsed, double cpu, struct qstat q0, struct qstat q1) {
    char path[512];
    snprintf(path, sizeof(path), "%s.summary.json", opt_out);
    FILE *fh = fopen(path, "w");
    if (fh) {
        fprintf(fh,
                "{\n  \"impl\": \"c\",\n  \"queue\": %d,\n  \"copylen\": %d,\n  \"qlen\": %d,\n"
                "  \"batch_verdict\": %s,\n  \"duration_s\": %.3f,\n  \"packets\": %llu,\n"
                "  \"packets_per_s\": %.1f,\n  \"bytes_copied\": %llu,\n  \"flows\": %llu,\n"
                "  \"parse_fail\": %llu,\n  \"verdict_fail\": %llu,\n  \"recv_errors\": %llu,\n"
                "  \"cpu_seconds\": %.2f,\n  \"cpu_percent\": %.2f,\n  \"rss_kib\": %llu,\n"
                "  \"kernel_queue_start\": {\"queue_depth_now\": %llu, \"copy_mode\": %llu, \"copy_range\": %llu, \"queue_dropped\": %llu, \"user_dropped\": %llu, \"id_sequence\": %llu},\n"
                "  \"kernel_queue_last\": {\"queue_depth_now\": %llu, \"copy_mode\": %llu, \"copy_range\": %llu, \"queue_dropped\": %llu, \"user_dropped\": %llu, \"id_sequence\": %llu}\n}\n",
                opt_queue, opt_copylen, opt_qlen, opt_batch ? "true" : "false", elapsed,
                (unsigned long long)stat_pkts, stat_pkts / (elapsed > 0 ? elapsed : 1),
                (unsigned long long)stat_bytes, (unsigned long long)n_flows,
                (unsigned long long)stat_parse_fail, (unsigned long long)stat_verdict_fail,
                (unsigned long long)stat_recv_err, cpu, 100.0 * cpu / (elapsed > 0 ? elapsed : 1),
                (unsigned long long)(read_self_rss() / 1024),
                (unsigned long long)q0.depth, (unsigned long long)q0.copy_mode, (unsigned long long)q0.copy_range,
                (unsigned long long)q0.dropped, (unsigned long long)q0.user_dropped, (unsigned long long)q0.id_seq,
                (unsigned long long)q1.depth, (unsigned long long)q1.copy_mode, (unsigned long long)q1.copy_range,
                (unsigned long long)q1.dropped, (unsigned long long)q1.user_dropped, (unsigned long long)q1.id_seq);
        fclose(fh);
        fh = fopen(path, "r");
        if (fh) {
            char line[1024];
            while (fgets(line, sizeof(line), fh)) fputs(line, stdout);
            fclose(fh);
        }
    }

    snprintf(path, sizeof(path), "%s.flows.tsv", opt_out);
    fh = fopen(path, "w");
    if (!fh) return;
    fprintf(fh, "proto\tlocal\tlport\tremote\trport\tout_pkts\tin_pkts\tout_bytes\tin_bytes\t"
                "seen_out_span\tseen_in_span\tsyn\tsynack\trst_in\trst_out\tfin_in\tfin_out\t"
                "client_hello\tserver_hello\tlast_in_fin\tlast_in_rst\tlife_s\tlast_in_after_s\tlast_out_after_s\n");
    char ls[64], rs[64];
    for (int i = 0; i < HASH_BUCKETS; i++) {
        for (struct flow *f = buckets[i]; f; f = f->next) {
            ipstr(f->lip, f->is6, ls, sizeof(ls));
            ipstr(f->rip, f->is6, rs, sizeof(rs));
            fprintf(fh, "%u\t%s\t%u\t%s\t%u\t%llu\t%llu\t%llu\t%llu\t%u\t%u\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.2f\t%.2f\t%.2f\n",
                    f->proto, ls, f->lport, rs, f->rport,
                    (unsigned long long)f->out_pkts, (unsigned long long)f->in_pkts,
                    (unsigned long long)f->out_bytes, (unsigned long long)f->in_bytes,
                    f->out_max, f->in_max,
                    f->saw_syn, f->saw_synack, f->rst_in, f->rst_out, f->fin_in, f->fin_out,
                    f->client_hello, f->server_hello, f->last_in_fin, f->last_in_rst,
                    f->last - f->first,
                    f->last_in > 0 ? f->last_in - f->first : -1.0,
                    f->last_out > 0 ? f->last_out - f->first : -1.0);
        }
    }
    fclose(fh);

    snprintf(path, sizeof(path), "%s.seq.tsv", opt_out);
    fh = fopen(path, "w");
    if (!fh) return;
    fprintf(fh, "dir\tlocal\tlport\tremote\trport\tspan\tn_seen\toffsets\n");
    for (int i = 0; i < HASH_BUCKETS; i++) {
        for (struct flow *f = buckets[i]; f; f = f->next) {
            if (f->proto != 6) continue;
            ipstr(f->lip, f->is6, ls, sizeof(ls));
            ipstr(f->rip, f->is6, rs, sizeof(rs));
            for (int dir = 0; dir < 2; dir++) {
                int n = dir ? f->n_out_samples : f->n_in_samples;
                if (n == 0) continue;
                uint32_t *sm = dir ? f->out_samples : f->in_samples;
                fprintf(fh, "%s\t%s\t%u\t%s\t%u\t%u\t%d\t", dir ? "out" : "in", ls, f->lport, rs, f->rport,
                        dir ? f->out_max : f->in_max, n);
                for (int k = 0; k < n; k++) fprintf(fh, "%s%u", k ? "," : "", sm[k]);
                fprintf(fh, "\n");
            }
        }
    }
    fclose(fh);
}

// --------------------------------------------------------------------- main
static void usage(void) {
    fprintf(stderr,
            "nfqview (C) — измеритель датапата\n"
            "  -q N        номер NFQUEUE (200)\n"
            "  -copylen N  байт пакета в юзерспейс, 0 = только метаданные (128)\n"
            "  -qlen N     глубина очереди в ядре (8192)\n"
            "  -dur N      длительность в секундах (60)\n"
            "  -tick N     интервал отчёта в секундах (10)\n"
            "  -lan CIDR   локальная подсеть (192.168.1.0/24)\n"
            "  -out PFX    префикс файлов результата (/tmp/nfqview)\n"
            "  -batch      групповой вердикт\n"
            "  -debug N    разобрать первые N сообщений вслух\n");
}

static int parse_lan(const char *cidr) {
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s", cidr);
    char *slash = strchr(tmp, '/');
    int bits = 24;
    if (slash) { *slash = 0; bits = atoi(slash + 1); }
    struct in_addr a;
    if (inet_pton(AF_INET, tmp, &a) != 1) return -1;
    if (bits < 0 || bits > 32) return -1;
    lan_mask = bits == 0 ? 0 : htonl(0xffffffffu << (32 - bits));
    lan_addr = a.s_addr & lan_mask;
    return 0;
}

int main(int argc, char **argv) {
    const char *lan = "192.168.1.0/24";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-q") && i + 1 < argc) opt_queue = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-copylen") && i + 1 < argc) opt_copylen = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-qlen") && i + 1 < argc) opt_qlen = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-dur") && i + 1 < argc) opt_dur = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-tick") && i + 1 < argc) opt_tick = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-lan") && i + 1 < argc) lan = argv[++i];
        else if (!strcmp(argv[i], "-out") && i + 1 < argc) opt_out = argv[++i];
        else if (!strcmp(argv[i], "-batch")) opt_batch = 1;
        else if (!strcmp(argv[i], "-debug") && i + 1 < argc) dbg_left = atoi(argv[++i]);
        else { usage(); return 2; }
    }
    if (parse_lan(lan) < 0) { fprintf(stderr, "плохая подсеть -lan\n"); return 2; }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (nl_fd < 0) { perror("socket netlink"); return 1; }

    int one = 1;
    if (setsockopt(nl_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one)) < 0)
        fprintf(stderr, "предупреждение: NO_ENOBUFS не установлен: %s\n", strerror(errno));
    int rcv = 4 * 1024 * 1024;
    if (setsockopt(nl_fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv)) < 0)
        fprintf(stderr, "предупреждение: буфер чтения не увеличен: %s\n", strerror(errno));

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }

    if (queue_config() < 0) return 1;

    struct qstat q0 = read_qstat(), qlast = q0;
    double t0 = now_sec(), cpu0 = read_self_cpu(), next_tick = t0 + opt_tick;

    char *buf = malloc(RECV_BUF);
    if (!buf) { fprintf(stderr, "нет памяти под буфер\n"); return 1; }

    uint32_t batch_id = 0;
    int batch_n = 0;
    const int batch_size = 16;

    while (!stop_flag) {
        double t = now_sec();
        if (t - t0 >= opt_dur) break;

        // Таймаут нужен, чтобы тик отчёта и выход по времени случались даже в
        // полной тишине на линии.
        struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
        setsockopt(nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        ssize_t n = recv(nl_fd, buf, RECV_BUF, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                if (opt_batch && batch_n > 0) { send_verdict(batch_id, 1); batch_n = 0; }
            } else {
                stat_recv_err++;
            }
        } else {
            t = now_sec();
            // Обход сделан вручную, без NLMSG_NEXT и NLA_ALIGN-арифметики в
            // условии цикла. Причина: и там и там вычитается ВЫРОВНЕННАЯ длина,
            // а у последнего атрибута хвоста выравнивания в буфере может не
            // быть. Счётчик уходит в минус, беззнаковое сравнение пропускает
            // цикл дальше, и разбор уходит за буфер. Ровно на этом C-версия
            // упала на первом же пакете 2026-09-05.
            size_t left = (size_t)n;
            char *cur = buf;
            while (left >= sizeof(struct nlmsghdr)) {
                struct nlmsghdr *nlh = (struct nlmsghdr *)cur;
                size_t mlen = nlh->nlmsg_len;
                if (mlen < sizeof(struct nlmsghdr) || mlen > left) break;

                if (dbg_left > 0) {
                    fprintf(stderr, "[отладка] сообщение type=0x%04x len=%zu из %zu\n",
                            nlh->nlmsg_type, mlen, left);
                }

                if ((nlh->nlmsg_type & 0xff) == NFQNL_MSG_PACKET &&
                    nlh->nlmsg_type != NLMSG_ERROR && nlh->nlmsg_type != NLMSG_DONE) {
                    struct nfqnl_msg_packet_hdr *ph = NULL;
                    const uint8_t *payload = NULL;
                    size_t paylen = 0;

                    size_t apos = NLMSG_ALIGN(sizeof(struct nfgenmsg));
                    size_t aleft = mlen - NLMSG_HDRLEN;
                    char *ap = (char *)NLMSG_DATA(nlh) + apos;
                    if (aleft >= apos) {
                        aleft -= apos;
                        while (aleft >= NLA_HDRLEN) {
                            struct nlattr *a = (struct nlattr *)ap;
                            size_t alen = a->nla_len;
                            if (alen < NLA_HDRLEN || alen > aleft) break;
                            uint16_t atype = a->nla_type & NLA_TYPE_MASK;
                            if (atype == NFQA_PACKET_HDR && alen - NLA_HDRLEN >= 7)
                                ph = (struct nfqnl_msg_packet_hdr *)(ap + NLA_HDRLEN);
                            else if (atype == NFQA_PAYLOAD) {
                                payload = (const uint8_t *)ap + NLA_HDRLEN;
                                paylen = alen - NLA_HDRLEN;
                            }
                            if (dbg_left > 0) {
                                fprintf(stderr, "[отладка]   атрибут type=%u len=%zu остаток=%zu выравн=%zu\n",
                                        atype, alen, aleft, (size_t)NLA_ALIGN(alen));
                            }
                            size_t astep = NLA_ALIGN(alen);
                            if (astep > aleft) break;
                            ap += astep;
                            aleft -= astep;
                        }
                    }
                    if (dbg_left > 0) dbg_left--;

                    if (ph) {
                        uint32_t id = 0;
                        memcpy(&id, ph, 4);
                        id = ntohl(id);

                        // Вердикт первым делом — как в Go-версии.
                        if (opt_batch) {
                            if (id > batch_id) batch_id = id;
                            if (++batch_n >= batch_size) {
                                if (send_verdict(batch_id, 1) < 0) stat_verdict_fail++;
                                batch_n = 0;
                            }
                        } else if (send_verdict(id, 0) < 0) {
                            stat_verdict_fail++;
                        }

                        stat_pkts++;
                        if (payload) {
                            stat_bytes += paylen;
                            account(payload, paylen, t);
                        }
                    }
                }

                size_t step = NLMSG_ALIGN(mlen);
                if (step > left) break;
                cur += step;
                left -= step;
            }
        }

        t = now_sec();
        if (t >= next_tick) {
            struct qstat q = read_qstat();
            if (q.id_seq || q.dropped || q.user_dropped) qlast = q;
            double el = t - t0, cpu = read_self_cpu() - cpu0;
            printf("[%4.0fс] пакетов=%llu (%.0f/с) байт=%llu потоков=%llu | ядро: выдано=%llu глубина=%llu "
                   "дроп-очереди=%llu дроп-юзера=%llu | cpu=%.1f%% rss=%lluКиБ\n",
                   el, (unsigned long long)stat_pkts, stat_pkts / el, (unsigned long long)stat_bytes,
                   (unsigned long long)n_flows, (unsigned long long)q.id_seq, (unsigned long long)q.depth,
                   (unsigned long long)q.dropped, (unsigned long long)q.user_dropped,
                   100.0 * cpu / el, (unsigned long long)(read_self_rss() / 1024));
            fflush(stdout);
            next_tick = t + opt_tick;
        }
    }

    if (opt_batch && batch_n > 0) send_verdict(batch_id, 1);

    double elapsed = now_sec() - t0;
    double cpu = read_self_cpu() - cpu0;
    struct qstat qend = read_qstat();
    if (qend.id_seq || qend.dropped || qend.user_dropped) qlast = qend;

    write_outputs(elapsed, cpu, q0, qlast);
    fprintf(stderr, "потоки записаны: %s.flows.tsv, выборка seq: %s.seq.tsv (%llu потоков)\n",
            opt_out, opt_out, (unsigned long long)n_flows);
    close(nl_fd);
    return 0;
}
