/* ctq.c — контракт и обоснования в d2k_ctq.h. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

#include "d2k_ctq.h"
#include "d2k_nl.h"

static size_t align4(size_t n) { return (n + 3u) & ~(size_t)3u; }

static void wr16h(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void wr32h(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint16_t rd16h(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint64_t rd64be(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static uint32_t rd32be(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* Атрибут с полезной нагрузкой; возвращает новую позицию или 0. */
static size_t put(uint8_t *o, size_t cap, size_t pos, uint16_t type,
                  const void *val, size_t vlen) {
    size_t alen = D2K_NLA_HDRLEN + vlen, step = align4(alen);
    if (pos + step > cap) return 0;
    wr16h(o + pos, (uint16_t)alen);
    wr16h(o + pos + 2, type);
    if (vlen) memcpy(o + pos + 4, val, vlen);
    memset(o + pos + alen, 0, step - alen);
    return pos + step;
}

/* Открыть вложенный атрибут: заголовок пишется, длина — при закрытии. */
static size_t open_nest(uint8_t *o, size_t cap, size_t pos, uint16_t type) {
    if (pos + D2K_NLA_HDRLEN > cap) return 0;
    wr16h(o + pos + 2, (uint16_t)(type | D2K_NLA_F_NESTED));
    return pos + D2K_NLA_HDRLEN;
}
static void close_nest(uint8_t *o, size_t start, size_t end) {
    wr16h(o + start, (uint16_t)(end - start));
}

/* Вложенный кортеж (CTA_TUPLE_ORIG/REPLY): адреса и порты t, reverse — в
   обратную сторону. 0 — не влезло. */
static size_t put_tuple(uint8_t *o, size_t cap, size_t pos, uint16_t type, const d2k_ct_tuple *t, int reverse) {
    size_t alen = t->family == 6 ? 16 : 4;
    const uint8_t *src = reverse ? t->dst : t->src, *dst = reverse ? t->src : t->dst;
    const uint8_t *sp = reverse ? t->dport_be : t->sport_be, *dp = reverse ? t->sport_be : t->dport_be;
    size_t tup = pos;
    if (!(pos = open_nest(o, cap, pos, type))) return 0;
    size_t ipn = pos;
    if (!(pos = open_nest(o, cap, pos, D2K_CTA_TUPLE_IP))) return 0;
    if (!(pos = put(o, cap, pos, t->family == 6 ? D2K_CTA_IP_V6_SRC : D2K_CTA_IP_V4_SRC, src, alen))) return 0;
    if (!(pos = put(o, cap, pos, t->family == 6 ? D2K_CTA_IP_V6_DST : D2K_CTA_IP_V4_DST, dst, alen))) return 0;
    close_nest(o, ipn, pos);
    size_t prn = pos;
    if (!(pos = open_nest(o, cap, pos, D2K_CTA_TUPLE_PROTO))) return 0;
    if (!(pos = put(o, cap, pos, D2K_CTA_PROTO_NUM, &t->proto, 1))) return 0;
    if (!(pos = put(o, cap, pos, D2K_CTA_PROTO_SRC_PORT, sp, 2))) return 0;
    if (!(pos = put(o, cap, pos, D2K_CTA_PROTO_DST_PORT, dp, 2))) return 0;
    close_nest(o, prn, pos);
    close_nest(o, tup, pos);
    return pos;
}

size_t d2k_ct_get_req(uint8_t *o, size_t cap, uint32_t seq, const d2k_ct_tuple *t) {
    if (!o || !t || (t->family != 4 && t->family != 6) || cap < 20) return 0;
    size_t pos = D2K_NLMSG_HDRLEN;
    o[pos++] = t->family == 6 ? 10 : 2;   /* AF_INET6 / AF_INET (Linux) */
    o[pos++] = D2K_NFNETLINK_V0;
    o[pos++] = 0; o[pos++] = 0;           /* res_id */
    if (!(pos = put_tuple(o, cap, pos, D2K_CTA_TUPLE_ORIG, t, 0))) return 0;
    wr32h(o, (uint32_t)pos);
    wr16h(o + 4, (uint16_t)(D2K_NFNL_SUBSYS_CTNETLINK << 8 | D2K_IPCTNL_MSG_CT_GET));
    wr16h(o + 6, D2K_NLM_F_REQUEST);
    wr32h(o + 8, seq);
    wr32h(o + 12, 0);
    return pos;
}

/* Счётчик байт из вложенного CTA_COUNTERS_* (этап 37): 0 — найден. */
static int counter_bytes(const uint8_t *p, size_t n, uint64_t *out) {
    size_t off = 0;
    while (off + D2K_NLA_HDRLEN <= n) {
        uint16_t alen = rd16h(p + off), type = rd16h(p + off + 2) & D2K_NLA_TYPE_MASK;
        if (alen < D2K_NLA_HDRLEN || alen > n - off) return -1;
        const uint8_t *v = p + off + D2K_NLA_HDRLEN;
        size_t vl = alen - D2K_NLA_HDRLEN;
        if (type == D2K_CTA_COUNTERS_BYTES && vl == 8) { *out = rd64be(v); return 0; }
        off += align4(alen);
    }
    return -1;
}

/* Счётчик пакетов из вложенного CTA_COUNTERS_*: 0 — найден. */
static int counter(const uint8_t *p, size_t n, uint64_t *out) {
    size_t off = 0;
    while (off + D2K_NLA_HDRLEN <= n) {
        uint16_t alen = rd16h(p + off), type = rd16h(p + off + 2) & D2K_NLA_TYPE_MASK;
        if (alen < D2K_NLA_HDRLEN || alen > n - off) return -1;
        const uint8_t *v = p + off + D2K_NLA_HDRLEN;
        size_t vl = alen - D2K_NLA_HDRLEN;
        if (type == D2K_CTA_COUNTERS_PACKETS && vl == 8) { *out = rd64be(v); return 0; }
        if (type == D2K_CTA_COUNTERS32_PACKETS && vl == 4) { *out = rd32be(v); return 0; }
        off += align4(alen);
    }
    return -1;
}

/* Состояние TCP из вложенного CTA_PROTOINFO (enum tcp_conntrack + 1): 0 — нет. */
static unsigned tcp_state(const uint8_t *p, size_t n) {
    size_t off = 0;
    while (off + D2K_NLA_HDRLEN <= n) {
        uint16_t alen = rd16h(p + off), type = rd16h(p + off + 2) & D2K_NLA_TYPE_MASK;
        if (alen < D2K_NLA_HDRLEN || alen > n - off) return 0;
        const uint8_t *v = p + off + D2K_NLA_HDRLEN;
        size_t vl = alen - D2K_NLA_HDRLEN;
        if (type == D2K_CTA_PROTOINFO_TCP) {
            size_t o2 = 0;
            while (o2 + D2K_NLA_HDRLEN <= vl) {
                uint16_t l2 = rd16h(v + o2), t2 = rd16h(v + o2 + 2) & D2K_NLA_TYPE_MASK;
                if (l2 < D2K_NLA_HDRLEN || l2 > vl - o2) return 0;
                if (t2 == D2K_CTA_PROTOINFO_TCP_STATE && l2 >= D2K_NLA_HDRLEN + 1)
                    return v[o2 + D2K_NLA_HDRLEN] + 1u;
                o2 += align4(l2);
            }
            return 0;
        }
        off += align4(alen);
    }
    return 0;
}

static int tuple_parse(const uint8_t *,size_t,uint8_t,d2k_ct_tuple *);
int d2k_ct_info_parse(const uint8_t *buf, size_t len, uint32_t seq, d2k_ct_info *out) {
    if(out)memset(out,0,sizeof *out);
    d2k_nl_iter it;
    d2k_nl_msg m;
    d2k_nl_iter_init(&it, buf, len);
    while (d2k_nl_next(&it, &m)) {
        if (m.seq != seq) continue;
        int32_t e = 0;
        if (d2k_nl_errno(&m, &e) == 0) return e == 0 ? -1 : 1;
        if (m.type != (D2K_NFNL_SUBSYS_CTNETLINK << 8 | D2K_IPCTNL_MSG_CT_NEW) ||
            m.body_len < D2K_NFGENMSG_LEN) return -1;
        const uint8_t *p = m.body + D2K_NFGENMSG_LEN;
        size_t n = m.body_len - D2K_NFGENMSG_LEN, off = 0;
        int have_o = 0, have_r = 0, have_mark = 0;
        uint64_t o = 0, r = 0, ob = 0, rb = 0;
        uint32_t mark = 0;
        unsigned st = 0;
        uint8_t family=m.body[0]==2?4:m.body[0]==10?6:0;
        d2k_ct_tuple reply={0};int have_reply=0;
        while (off + D2K_NLA_HDRLEN <= n) {
            uint16_t alen = rd16h(p + off), type = rd16h(p + off + 2) & D2K_NLA_TYPE_MASK;
            if (alen < D2K_NLA_HDRLEN || alen > n - off) return -1;
            const uint8_t *v = p + off + D2K_NLA_HDRLEN;
            size_t vl = alen - D2K_NLA_HDRLEN;
            if (type == D2K_CTA_COUNTERS_ORIG) { have_o = counter(v, vl, &o) == 0; (void)counter_bytes(v, vl, &ob); }
            if (type == D2K_CTA_COUNTERS_REPLY) { have_r = counter(v, vl, &r) == 0; (void)counter_bytes(v, vl, &rb); }
            if (type == D2K_CTA_PROTOINFO) st = tcp_state(v, vl);
            if (type == D2K_CTA_MARK && vl == 4) { have_mark = 1; mark = rd32be(v); }
            if(type==D2K_CTA_TUPLE_REPLY) {
                if(have_reply||!family||tuple_parse(v,vl,family,&reply)||
                   (reply.proto!=6&&reply.proto!=17))return -1;
                have_reply=1;
            }
            off += align4(alen);
        }
        if (out) {
            out->mark_known = (uint8_t)have_mark;
            out->mark = mark;
            out->reply_tuple_known=(uint8_t)have_reply;
            if(have_reply)out->reply_tuple=reply;
        }
        if (out) out->counters_known = 0;
        if (!have_o || !have_r) return 2;
        if (out) {
            out->counters_known = 1;
            out->orig_pkts = o; out->reply_pkts = r;
            out->orig_bytes = ob; out->reply_bytes = rb;
            out->tcp_state_known = st != 0;
            out->tcp_state = st ? (uint8_t)(st - 1u) : 0;
        }
        return 0;
    }
    return -1;
}

int d2k_ct_counters_parse(const uint8_t *buf, size_t len, uint32_t seq,
                          uint64_t *orig_pkts, uint64_t *reply_pkts) {
    d2k_ct_info i;
    int rc = d2k_ct_info_parse(buf, len, seq, &i);
    if (rc == 0) {
        if (orig_pkts) *orig_pkts = i.orig_pkts;
        if (reply_pkts) *reply_pkts = i.reply_pkts;
    }
    return rc;
}

int d2k_ct_query_info_fd(int fd, uint32_t seq, const d2k_ct_tuple *t, d2k_ct_info *out) {
    if (fd < 0 || !t) return -1;
    uint8_t req[128];
    size_t n = d2k_ct_get_req(req, sizeof req, seq, t);
    if (!n) return -1;
    if (send(fd, req, n, MSG_DONTWAIT) != (ssize_t)n) return -1;
    /* Legacy best-effort observation, not asynchronous ownership. A reply
       may arrive later; callers needing continuity use d2k_ct_async on a
       dedicated socket instead of discarding the previous sequence. */
    uint8_t buf[4096];
    int rc = -1;
    for (int i = 0; i < 8; i++) {
        ssize_t got = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (got <= 0) break;
        int r = d2k_ct_info_parse(buf, (size_t)got, seq, out);
        if (r == 0 || r == 1 || r == 2) { rc = r; break; }
    }
    return rc;
}

int d2k_ct_query_fd(int fd, uint32_t seq, const d2k_ct_tuple *t,
                    uint64_t *orig_pkts, uint64_t *reply_pkts) {
    d2k_ct_info i;
    int rc = d2k_ct_query_info_fd(fd, seq, t, &i);
    if (rc == 0) {
        if (orig_pkts) *orig_pkts = i.orig_pkts;
        if (reply_pkts) *reply_pkts = i.reply_pkts;
    }
    return rc;
}

size_t d2k_ct_dump_req(uint8_t *o, size_t cap, uint32_t seq, uint8_t family) {
    if (!o || (family != 4 && family != 6) || cap < D2K_NLMSG_HDRLEN + D2K_NFGENMSG_LEN) return 0;
    size_t pos = D2K_NLMSG_HDRLEN;
    o[pos++] = family == 6 ? 10 : 2;
    o[pos++] = D2K_NFNETLINK_V0;
    o[pos++] = 0; o[pos++] = 0;
    wr32h(o, (uint32_t)pos);
    wr16h(o + 4, (uint16_t)(D2K_NFNL_SUBSYS_CTNETLINK << 8 | D2K_IPCTNL_MSG_CT_GET));
    wr16h(o + 6, (uint16_t)(D2K_NLM_F_REQUEST | D2K_NLM_F_DUMP));
    wr32h(o + 8, seq);
    wr32h(o + 12, 0);
    return pos;
}

/* Прямой кортеж из CTA_TUPLE_ORIG: 0 — разобран целиком. */
static int tuple_parse(const uint8_t *p, size_t n, uint8_t family, d2k_ct_tuple *t) {
    size_t off = 0;
    int have_src = 0, have_dst = 0, have_proto = 0, have_sp = 0, have_dp = 0;
    memset(t, 0, sizeof *t);
    t->family = family;
    size_t alen_addr = family == 6 ? 16 : 4;
    while (off + D2K_NLA_HDRLEN <= n) {
        uint16_t alen = rd16h(p + off), type = rd16h(p + off + 2) & D2K_NLA_TYPE_MASK;
        if (alen < D2K_NLA_HDRLEN || alen > n - off) return -1;
        const uint8_t *v = p + off + D2K_NLA_HDRLEN;
        size_t vl = alen - D2K_NLA_HDRLEN, o2 = 0;
        if (type == D2K_CTA_TUPLE_IP) {
            while (o2 + D2K_NLA_HDRLEN <= vl) {
                uint16_t l2 = rd16h(v + o2), t2 = rd16h(v + o2 + 2) & D2K_NLA_TYPE_MASK;
                if (l2 < D2K_NLA_HDRLEN || l2 > vl - o2) return -1;
                const uint8_t *a = v + o2 + D2K_NLA_HDRLEN;
                size_t al = l2 - D2K_NLA_HDRLEN;
                if (al == alen_addr && (t2 == D2K_CTA_IP_V4_SRC || t2 == D2K_CTA_IP_V6_SRC)) { memcpy(t->src, a, al); have_src = 1; }
                if (al == alen_addr && (t2 == D2K_CTA_IP_V4_DST || t2 == D2K_CTA_IP_V6_DST)) { memcpy(t->dst, a, al); have_dst = 1; }
                o2 += align4(l2);
            }
        } else if (type == D2K_CTA_TUPLE_PROTO) {
            while (o2 + D2K_NLA_HDRLEN <= vl) {
                uint16_t l2 = rd16h(v + o2), t2 = rd16h(v + o2 + 2) & D2K_NLA_TYPE_MASK;
                if (l2 < D2K_NLA_HDRLEN || l2 > vl - o2) return -1;
                const uint8_t *a = v + o2 + D2K_NLA_HDRLEN;
                size_t al = l2 - D2K_NLA_HDRLEN;
                if (t2 == D2K_CTA_PROTO_NUM && al >= 1) { t->proto = a[0]; have_proto = 1; }
                if (t2 == D2K_CTA_PROTO_SRC_PORT && al >= 2) { memcpy(t->sport_be, a, 2); have_sp = 1; }
                if (t2 == D2K_CTA_PROTO_DST_PORT && al >= 2) { memcpy(t->dport_be, a, 2); have_dp = 1; }
                o2 += align4(l2);
            }
        }
        off += align4(alen);
    }
    return have_src && have_dst && have_proto && have_sp && have_dp ? 0 : -1;
}

int d2k_ct_dump_parse(const uint8_t *buf, size_t len, uint32_t seq,
                      d2k_ct_dump_fn fn, void *ctx, int *done) {
    d2k_nl_iter it;
    d2k_nl_msg m;
    int count = 0;
    if (done) *done = 0;
    d2k_nl_iter_init(&it, buf, len);
    while (d2k_nl_next(&it, &m)) {
        if (m.seq != seq) continue;
        int32_t e = 0;
        /* ACK is not the end of a multipart dump. An interrupted dump or
           an error carried by DONE must never certify a complete table. */
        if (m.flags & 0x10u) return -1; /* NLM_F_DUMP_INTR */
        if (d2k_nl_errno(&m, &e) == 0) {
            if (e) return -1;
            continue;
        }
        if (m.type == D2K_NLMSG_DONE) {
            if (m.body_len && m.body_len < sizeof e) return -1;
            if (m.body_len >= sizeof e) memcpy(&e, m.body, sizeof e);
            if (e) return -1;
            if (done) *done = 1;
            return count;
        }
        if (m.type != (D2K_NFNL_SUBSYS_CTNETLINK << 8 | D2K_IPCTNL_MSG_CT_NEW) ||
            m.body_len < D2K_NFGENMSG_LEN) continue;
        uint8_t family = m.body[0] == 10 ? 6 : m.body[0] == 2 ? 4 : 0;
        if (!family) continue;
        const uint8_t *p = m.body + D2K_NFGENMSG_LEN;
        size_t n = m.body_len - D2K_NFGENMSG_LEN, off = 0;
        d2k_ct_tuple t;
        d2k_ct_info info;
        memset(&info, 0, sizeof info);
        int have_t = 0, have_o = 0, have_r = 0;
        unsigned st = 0;
        while (off + D2K_NLA_HDRLEN <= n) {
            uint16_t alen = rd16h(p + off), type = rd16h(p + off + 2) & D2K_NLA_TYPE_MASK;
            if (alen < D2K_NLA_HDRLEN || alen > n - off) break;
            const uint8_t *v = p + off + D2K_NLA_HDRLEN;
            size_t vl = alen - D2K_NLA_HDRLEN;
            if (type == D2K_CTA_TUPLE_ORIG) have_t = tuple_parse(v, vl, family, &t) == 0;
            if (type == D2K_CTA_COUNTERS_ORIG) { have_o = counter(v, vl, &info.orig_pkts) == 0; (void)counter_bytes(v, vl, &info.orig_bytes); }
            if (type == D2K_CTA_COUNTERS_REPLY) { have_r = counter(v, vl, &info.reply_pkts) == 0; (void)counter_bytes(v, vl, &info.reply_bytes); }
            if (type == D2K_CTA_PROTOINFO) st = tcp_state(v, vl);
            if (type == D2K_CTA_MARK && vl == 4) { info.mark_known = 1; info.mark = rd32be(v); }
            off += align4(alen);
        }
        if (!have_t || (t.proto != 6 && t.proto != 17)) continue;
        info.tcp_state_known = st != 0;
        info.tcp_state = st ? (uint8_t)(st - 1u) : 0;
        if (!have_o || !have_r) { info.orig_pkts = info.reply_pkts = 0; info.orig_bytes = info.reply_bytes = 0; }
        info.counters_known = (uint8_t)(have_o && have_r);
        count++;
        if (fn && fn(ctx, &t, &info) != 0) { if (done) *done = 1; return count; }
    }
    return count;
}

int d2k_ct_dump_fd(int fd, uint32_t seq, uint8_t family, d2k_ct_dump_fn fn, void *ctx, int wait_ms) {
    if (fd < 0) return -1;
    uint8_t req[64];
    size_t n = d2k_ct_dump_req(req, sizeof req, seq, family);
    if (!n || send(fd, req, n, 0) != (ssize_t)n) return -1;
    static uint8_t buf[65536];
    int total = 0, done = 0;
    while (!done) {
        struct pollfd p = { fd, POLLIN, 0 };
        int pr = poll(&p, 1, wait_ms);
        if (pr <= 0) return -1;
        ssize_t got = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (got <= 0) return -1;
        int c = d2k_ct_dump_parse(buf, (size_t)got, seq, fn, ctx, &done);
        if (c < 0) return -1;
        total += c;
    }
    return total;
}

/* Код ошибки ядра (errno Linux, положительный) в ответе на seq; 0 — ответ
   не ошибка; -1 — ответа на seq нет. */
static int reply_errno(const uint8_t *buf, size_t len, uint32_t seq) {
    d2k_nl_iter it;
    d2k_nl_msg m;
    d2k_nl_iter_init(&it, buf, len);
    while (d2k_nl_next(&it, &m)) {
        if (m.seq != seq) continue;
        int32_t e = 0;
        if (d2k_nl_errno(&m, &e) == 0) return e < 0 ? -e : e;
        return 0;
    }
    return -1;
}

static size_t put_be32(uint8_t *o, size_t cap, size_t pos, uint16_t type, uint32_t v) {
    uint8_t be[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    return put(o, cap, pos, type, be, 4);
}

/* Тот же кортеж, что у GET, плюс CTA_MARK и CTA_MARK_MASK; тип CT_NEW, флаги
   REQUEST|ACK — см. d2k_ctq.h. Значение вне маски не собирается. */
size_t d2k_ct_mark_req(uint8_t *o, size_t cap, uint32_t seq, const d2k_ct_tuple *t,
                       uint32_t value, uint32_t mask) {
    if (value & ~mask) return 0;
    size_t pos = d2k_ct_get_req(o, cap, seq, t);
    if (!pos) return 0;
    if (!(pos = put_be32(o, cap, pos, D2K_CTA_MARK, value))) return 0;
    if (!(pos = put_be32(o, cap, pos, D2K_CTA_MARK_MASK, mask))) return 0;
    wr32h(o, (uint32_t)pos);
    wr16h(o + 4, (uint16_t)(D2K_NFNL_SUBSYS_CTNETLINK << 8 | D2K_IPCTNL_MSG_CT_NEW));
    wr16h(o + 6, (uint16_t)(D2K_NLM_F_REQUEST | D2K_NLM_F_ACK));
    return pos;
}

/* Послать запрос с ACK и дождаться ответа своего seq: errno ядра (0 — да),
   -1 — ответа нет. */
static int ack_fd(int fd, const uint8_t *req, size_t n, uint32_t seq, int wait_ms);

int d2k_ct_mark_fd(int fd, uint32_t seq, const d2k_ct_tuple *t, uint32_t value, uint32_t mask,
                   int wait_ms) {
    if (fd < 0 || !t) return -1;
    uint8_t req[128];
    size_t n = d2k_ct_mark_req(req, sizeof req, seq, t, value, mask);
    if (!n) return -1;
    return ack_fd(fd, req, n, seq, wait_ms);
}

static int ack_fd(int fd, const uint8_t *req, size_t n, uint32_t seq, int wait_ms) {
    if (send(fd, req, n, MSG_DONTWAIT) != (ssize_t)n) return -1;
    struct pollfd p;
    p.fd = fd; p.events = POLLIN; p.revents = 0;
    for (int i = 0; i < 8; i++) {
        if (poll(&p, 1, wait_ms) <= 0) return -1;
        uint8_t buf[4096];
        ssize_t got = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (got <= 0) return -1;
        int e = reply_errno(buf, (size_t)got, seq);
        if (e < 0) continue;                         /* чужой ответ */
        return e;
    }
    return -1;
}

/* Временная запись проверки маски (этап 51): своя, UDP, на 127.62.0.x. */
#define D2K_CTA_TIMEOUT 7
#define D2K_IPCTNL_MSG_CT_DELETE 2
#define D2K_NLM_F_EXCL 0x200
#define D2K_NLM_F_CREATE 0x400
static int probe_req(uint8_t *o, size_t cap, uint32_t seq, const d2k_ct_tuple *t, int create, uint32_t mark) {
    size_t pos = d2k_ct_get_req(o, cap, seq, t);
    if (!pos) return 0;
    uint16_t flags = D2K_NLM_F_REQUEST | D2K_NLM_F_ACK;
    if (create) {
        if (!(pos = put_tuple(o, cap, pos, D2K_CTA_TUPLE_REPLY, t, 1))) return 0;
        if (!(pos = put_be32(o, cap, pos, D2K_CTA_TIMEOUT, 10))) return 0;
        if (!(pos = put_be32(o, cap, pos, D2K_CTA_MARK, mark))) return 0;
        flags |= D2K_NLM_F_CREATE | D2K_NLM_F_EXCL;
    }
    wr32h(o, (uint32_t)pos);
    wr16h(o + 4, (uint16_t)(D2K_NFNL_SUBSYS_CTNETLINK << 8 |
                            (create ? D2K_IPCTNL_MSG_CT_NEW : D2K_IPCTNL_MSG_CT_DELETE)));
    wr16h(o + 6, flags);
    return (int)pos;
}

int d2k_ct_mask_probe_fd(int fd, uint32_t *seq, uint32_t bit, uint16_t salt, int wait_ms) {
    if (fd < 0 || !seq || !bit) return -1;
    const uint32_t other = 0x5u & ~bit;
    uint8_t req[256];
    int n;
#define NEXT_SEQ() (++*seq == 0 ? (*seq = 1) : *seq)
    /* Своя запись — только подтверждённо созданная CREATE|EXCL. Занятая
       кандидатура (EEXIST: чужой поток или чужая проверка) не трогается —
       берётся следующая; удаления «на всякий случай» нет. */
    for (unsigned k = 0; k < 8; k++) {
        d2k_ct_tuple t;
        memset(&t, 0, sizeof t);
        t.family = 4; t.proto = 17;
        t.src[0] = 127; t.src[1] = 62; t.src[3] = 1;
        t.dst[0] = 127; t.dst[1] = 62; t.dst[3] = 2;
        uint16_t sp = (uint16_t)(40000u + (uint32_t)(salt * 8u + k) % 20000u);
        t.sport_be[0] = (uint8_t)(sp >> 8); t.sport_be[1] = (uint8_t)sp;
        t.dport_be[1] = 9;
        if ((n = probe_req(req, sizeof req, NEXT_SEQ(), &t, 1, other)) <= 0) return -1;
        int ce = ack_fd(fd, req, (size_t)n, *seq, wait_ms);
        if (ce == 17) continue;                        /* EEXIST — не наша */
        if (ce != 0) return -1;                        /* отказ или нет ответа: не наша, истечёт сама */
        int verdict = -1;
        if (d2k_ct_mark_fd(fd, NEXT_SEQ(), &t, bit, bit, wait_ms) == 0) {
            d2k_ct_info ci;
            memset(&ci, 0, sizeof ci);
            int qe = d2k_ct_query_info_fd(fd, NEXT_SEQ(), &t, &ci);   /* 2 — без счётчиков: метке не мешает */
            if ((qe == 0 || qe == 2) && ci.mark_known) {
                if (ci.mark == (other | bit)) verdict = 1;
                else if (ci.mark == bit) verdict = 0;
            }
        }
        if ((n = probe_req(req, sizeof req, NEXT_SEQ(), &t, 0, 0)) > 0) (void)ack_fd(fd, req, (size_t)n, *seq, wait_ms);
        return verdict;
    }
#undef NEXT_SEQ
    return -1;
}

int d2k_ct_probe_fd(int fd, uint32_t seq, int wait_ms) {
    if (fd < 0) return 0;
    d2k_ct_tuple t;
    memset(&t, 0, sizeof t);       /* 0.0.0.0:0 → 0.0.0.0:0 udp: такой записи нет */
    t.family = 4;
    t.proto = 17;
    uint8_t req[128];
    size_t n = d2k_ct_get_req(req, sizeof req, seq, &t);
    if (!n || send(fd, req, n, MSG_DONTWAIT) != (ssize_t)n) return 0;
    struct pollfd p;
    p.fd = fd; p.events = POLLIN; p.revents = 0;
    for (int i = 0; i < 8; i++) {
        if (poll(&p, 1, wait_ms) <= 0) return 0;     /* молчание — недоступно */
        uint8_t buf[4096];
        ssize_t got = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (got <= 0) return 0;
        int e = reply_errno(buf, (size_t)got, seq);
        if (e < 0) continue;                         /* чужой ответ */
        /* ENOENT (2): подсистема на месте, записи просто нет. Ответ-запись
           (e == 0) — тоже на месте. Остальное: EOPNOTSUPP, EPROTONOSUPPORT,
           ENOSYS, EINVAL, EPERM — нет. */
        return e == 2 || e == 0;
    }
    return 0;
}

#ifdef __linux__
#include <sys/socket.h>
#include <linux/netlink.h>
int d2k_ct_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, D2K_NETLINK_NETFILTER);
    if (fd < 0) return -1;
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) { close(fd); return -1; }
    struct sockaddr_nl a;
    memset(&a, 0, sizeof a);
    a.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    return fd;
}
#else
int d2k_ct_open(void) { return -1; }
#endif

void d2k_ct_async_poll(d2k_ct_async *a, int fd) {
    if (!a || fd < 0) return;
    uint8_t buf[8192];
    for (unsigned n = 0; n < D2K_CT_ASYNC_SLOTS; n++) {
        ssize_t got = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (got <= 0) break;
        for (size_t i = 0; i < D2K_CT_ASYNC_SLOTS; i++) {
            d2k_ct_async_slot *s = &a->slots[i];
            if (!s->seq || s->ready) continue;
            d2k_ct_info info;
            int rc = d2k_ct_info_parse(buf, (size_t)got, s->seq, &info);
            if (rc == 0 || rc == 2) { s->info = info; s->ready = 1; }
            else if (rc == 1) { s->ready = -1; }
        }
    }
}
int d2k_ct_async_query(d2k_ct_async *a, int fd, const d2k_ct_tuple *t,
                       uint64_t now, d2k_ct_info *out) {
    if (!a || fd < 0 || !t || !out) return 0;
    d2k_ct_async_slot *free_slot = NULL;
    for (size_t i = 0; i < D2K_CT_ASYNC_SLOTS; i++) {
        d2k_ct_async_slot *s = &a->slots[i];
        if (s->seq && s->until_ns <= now) memset(s, 0, sizeof *s);
        if (!s->seq) { if (!free_slot) free_slot = s; continue; }
        if (memcmp(&s->tuple, t, sizeof *t)) continue;
        if (!s->ready) return 0;
        int ok = s->ready == 1 && s->info.reply_tuple_known;
        if (ok) *out = s->info;
        memset(s, 0, sizeof *s);
        return ok;
    }
    if (!free_slot) return 0;
    /* Sequence wrap must not alias a still-live request. */
    uint32_t seq;
    for (;;) {
        seq = ++a->seq; if (!seq) continue;
        size_t i;
        for (i = 0; i < D2K_CT_ASYNC_SLOTS; i++) if (a->slots[i].seq == seq) break;
        if (i == D2K_CT_ASYNC_SLOTS) break;
    }
    uint8_t req[160]; size_t n = d2k_ct_get_req(req, sizeof req, seq, t);
    if (!n || send(fd, req, n, MSG_DONTWAIT) != (ssize_t)n) return 0;
    free_slot->seq = seq; free_slot->tuple = *t;
    free_slot->until_ns = now + D2K_CT_ASYNC_TIMEOUT_NS;
    return 0;
}

void d2k_ct_async_forget(d2k_ct_async *a, const d2k_ct_tuple *t) {
    if (!a || !t) return;
    for (size_t i = 0; i < D2K_CT_ASYNC_SLOTS; i++)
        if (a->slots[i].seq && !memcmp(&a->slots[i].tuple, t, sizeof *t))
            memset(&a->slots[i], 0, sizeof a->slots[i]);
}
