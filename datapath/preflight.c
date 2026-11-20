/* Pure TCP preflight. Owns bounded copies, never sends or touches CT.
 * IP/TCP headers are copied (including IPv4 options) before editing, hence
 * checksums here cover those exact bytes, rather than a rebuilt template.
 * PF_DONE means TCP handover only, never application or measured success. */
#include <stdlib.h>
#include <string.h>
#include "d2k_preflight.h"
#include "d2k_preflight_plan.h"
#include "d2k_raw.h"

struct d2k_pf_flow {
    int used, client_low, have_ts, handshaken, cleanup_pending, handover_started;
    d2k_key key;
    d2k_pf_stage stage;
    uint64_t deadline, probe_deadline;
    uint32_t isn, cli_next, srv_next, ts_val, ts_ecr;
    uint32_t first_syn_ts;
    uint16_t ip_id;
    unsigned pieces, resets, retries, dup_acks;
    uint32_t srv_isn;
    size_t hello_acked;
    d2k_pf_params params;
    size_t orig_len, ihl, hello_sent, segment_cap;
    uint64_t send_due, cleanup_due, resyn_due;
    unsigned resyn_sends;
    uint8_t orig[D2K_HOLD_HEADER], hello[D2K_CAPTURE_BYTES];
};
static unsigned rd16(const uint8_t *p) {
    return (unsigned)p[0] << 8 | p[1];
}
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void wr16(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}
static uint32_t sum16(const uint8_t *p, size_t n, uint32_t s) {
    while (n >= 2) {
        s += rd16(p);
        p += 2;
        n -= 2;
    }
    if (n)
        s += (uint32_t)*p << 8;
    return s;
}
static uint16_t finish_sum(uint32_t s) {
    while (s >> 16)
        s = (s & 65535) + (s >> 16);
    return (uint16_t)~s;
}
static void checksum(uint8_t *p, size_t n, size_t ihl) {
    const int ipv6 = (p[0] >> 4) == 6;
    p[ihl + 16] = p[ihl + 17] = 0;
    if (!ipv6) {
        p[10] = p[11] = 0;
        wr16(p + 10, finish_sum(sum16(p, ihl, 0)));
    }
    uint32_t pseudo = sum16(p + (ipv6 ? 8 : 12), ipv6 ? 32 : 8,
                           6 + (uint32_t)(n - ihl));
    wr16(p + ihl + 16,
         finish_sum(sum16(p + ihl, n - ihl, pseudo)));
}
static void packet_length(uint8_t *p, size_t n) {
    if ((p[0] >> 4) == 6)
        wr16(p + 4, (unsigned)(n - 40));
    else
        wr16(p + 2, (unsigned)n);
}
/* Validate all options before admitting a packet, including EOL padding.
 * Only MSS, WS and TS have protocol-specific lengths used by this module. */
static int options_ok(const uint8_t *tcp, size_t n) {
    for (size_t i = 20; i < n;) {
        unsigned k = tcp[i];
        if (k == 0)
            return 1;
        if (k == 1) {
            i++;
            continue;
        }
        if (i + 1 >= n || tcp[i + 1] < 2 || tcp[i + 1] > n - i)
            return 0;
        unsigned l = tcp[i + 1];
        if ((k == 2 && l != 4) || (k == 3 && l != 3) || (k == 8 && l != 10))
            return 0;
        i += l;
    }
    return 1;
}
static size_t option(const uint8_t *tcp, unsigned kind) {
    size_t n = (tcp[12] >> 4) * 4u;
    for (size_t i = 20; i < n;) {
        unsigned k = tcp[i];
        if (k == 0)
            break;
        if (k == kind)
            return i;
        i += k == 1 ? 1 : tcp[i + 1];
    }
    return 0;
}
static int parse(const d2k_pkt *p, d2k_hold_info *v) {
    return p && p->wire && p->wire_len &&
           ((p->wire[0] >> 4) == 4 ||
            ((p->wire[0] >> 4) == 6 && p->wire_len >= 60 && p->wire[6] == 6)) &&
           d2k_hold_parse(p->wire, p->wire_len, v) &&
           options_ok(p->wire + v->ihl, v->header - v->ihl);
}
static int active(const d2k_pf_flow *f) {
    return f->stage <= PF_HANDOVER || f->cleanup_pending;
}
static d2k_pf_flow *find(const d2k_pf_table *t, const d2k_hold_info *v, int server) {
    if (t && t->flows)
        for (unsigned i = 0; i < t->cap; i++) {
            d2k_pf_flow *f = &t->flows[i];
            if (f->used && d2k_key_equal(&f->key, &v->key) &&
                (v->src_low != f->client_low) == server)
                return f;
        }
    return NULL;
}
int d2k_pf_table_init(d2k_pf_table *t, unsigned cap) {
    if (!t)
        return 0;
    memset(t, 0, sizeof *t);
    if (!cap)
        return 0;
    t->flows = calloc(cap, sizeof *t->flows);
    if (!t->flows)
        return 0;
    t->cap = cap;
    return 1;
}
void d2k_pf_table_free(d2k_pf_table *t) {
    if (t) {
        free(t->flows);
        memset(t, 0, sizeof *t);
    }
}
static void original(d2k_pf_flow *f, d2k_pf_out *o) {
    if (f->stage==PF_RESYN) f->handover_started=1;
    size_t i = o->count++;
    memcpy(o->packet[i], f->orig, f->orig_len);
    o->len[i] = f->orig_len;
    o->original[i] = 1;
    o->clear[i] = 0;
}
static void emit(d2k_pf_flow *f, d2k_pf_out *o, uint8_t flags, uint32_t seq, uint32_t ack,
                 const uint8_t *data, size_t n) {
    size_t i = o->count++, ihl = f->ihl, opt = f->have_ts ? 12 : 0;
    o->original[i] = 0;
    o->clear[i] = 0;
    uint8_t *p = o->packet[i], *tcp = p + ihl;
    memcpy(p, f->orig, ihl + 20);
    memset(tcp + 20, 0, opt);
    if ((p[0] >> 4) == 4)
        wr16(p + 4, ++f->ip_id);
    tcp[12] = (uint8_t)((20 + opt) / 4 << 4);
    tcp[13] = flags;
    wr32(tcp + 4, seq);
    wr32(tcp + 8, ack);
    wr16(tcp + 14, f->params.window);
    tcp[18] = tcp[19] = 0; /* no urgent data in synthetic packets */
    if (opt) {
        tcp[20] = tcp[21] = 1;
        tcp[22] = 8;
        tcp[23] = 10;
        wr32(tcp + 24, f->ts_val++);
        wr32(tcp + 28, f->ts_ecr);
    }
    if (n)
        memcpy(tcp + 20 + opt, data, n);
    o->len[i] = ihl + 20 + opt + n;
    packet_length(p, o->len[i]);
    checksum(p, o->len[i], ihl);
}
/* Keep client options with TS, like keepts; without TS retain MSS and WS.
 * Insert WS if absent: the measured scale must actually be offered. */
static int probe_syn(d2k_pf_flow *f, d2k_pf_out *o, const uint8_t *syn, size_t syn_len) {
    uint8_t *p = o->packet[o->count], *tcp = p + f->ihl;
    memcpy(p, syn, syn_len);
    size_t scale = option(tcp, 3), old = (tcp[12] >> 4) * 4u, n = 20;
    if (f->have_ts || f->params.reference_hello) {
        n = old;
        if (scale)
            tcp[scale + 2] = f->params.wscale;
        else {
            /* Remove EOL/padding before appending the missing scale. */
            n = 20;
            while (n < old && tcp[n])
                n += tcp[n] == 1 ? 1 : tcp[n + 1];
            if (n + 3 > 60)
                return 0;
            tcp[n++] = 3;
            tcp[n++] = 3;
            tcp[n++] = f->params.wscale;
        }
    } else {
        const uint8_t *orig = f->orig + f->ihl;
        for (size_t j = 20; j < old && orig[j];) {
            unsigned kind = orig[j], len = kind == 1 ? 1 : orig[j + 1];
            if (kind == 2 || kind == 3) {
                memcpy(tcp + n, orig + j, len);
                if (kind == 3)
                    tcp[n + 2] = f->params.wscale;
                n += len;
            }
            j += len;
        }
        if (!scale) {
            if (n + 3 > 60)
                return 0;
            tcp[n++] = 3;
            tcp[n++] = 3;
            tcp[n++] = f->params.wscale;
        }
    }
    while (n % 4)
        tcp[n++] = 0;
    tcp[12] = (uint8_t)(n / 4 << 4);
    wr16(tcp + 14, f->params.window);
    size_t total = f->ihl + n;
    packet_length(p, total);
    checksum(p, total, f->ihl);
    o->original[o->count] = 0;
    o->clear[o->count] = 0;
    o->len[o->count++] = total;
    return 1;
}
/* A copied tuple is a control token, consumed by the firewall after repeat.
 * It is not a second SYN on the wire and never enters normal session logic. */
static void clear_token(d2k_pf_flow *f, d2k_pf_out *o) {
    emit(f,o,16,f->cli_next,f->srv_next,NULL,0);
    o->clear[o->count-1]=2;
    f->cleanup_pending=1;
    if (!f->cleanup_due) f->cleanup_due=f->deadline;
}
static void give_up(d2k_pf_flow *f, d2k_pf_out *o) {
    if (f->stage == PF_HANDOVER) {
        clear_token(f,o); /* real handshake already belongs to the client */
    } else {
        if (f->handshaken)
            emit(f, o, 4, f->cli_next, 0, NULL, 0);
        original(f, o);
        o->clear[o->count-1]=1;
    }
    f->send_due=f->resyn_due=0;
    f->stage = PF_GAVE_UP;
}
static void schedule_resyn(d2k_pf_flow *f, uint64_t now, d2k_pf_out *o) {
    f->send_due=0;
    f->stage=PF_RESYN;
    if (!f->params.resyn_delay_ms) { original(f,o); return; }
    if (f->resyn_sends>=f->params.resyn_sends) return;
    uint64_t delta=(uint64_t)f->params.resyn_delay_ms*1000000;
    f->resyn_due=now>UINT64_MAX-delta ? UINT64_MAX : now+delta;
}
static void resyn_attempt(d2k_pf_flow *f,uint64_t now) {
    f->resyn_sends++;f->resyn_due=0;
    if (f->resyn_sends<f->params.resyn_sends) {
        uint64_t delta=(uint64_t)f->params.resyn_delay_ms*1000000;
        f->resyn_due=now>UINT64_MAX-delta ? UINT64_MAX : now+delta;
    }
}
static uint64_t flow_deadline(const d2k_pf_flow *f) {
    return f->stage<PF_RESYN ? f->probe_deadline : f->deadline;
}
static int expired(d2k_pf_flow *f, uint64_t now, d2k_pf_out *o) {
    if (active(f) && now >= flow_deadline(f)) {
        give_up(f, o);
        return 1;
    }
    return 0;
}
static void hello_batch(d2k_pf_flow *f, uint64_t now, d2k_pf_out *o) {
    while (f->hello_sent < f->params.hello_len && o->count < D2K_PF_OUT_MAX) {
        size_t n=f->params.hello_len-f->hello_sent;
        if (n>f->segment_cap) n=f->segment_cap;
        emit(f,o,24,f->isn+1+(uint32_t)f->hello_sent,f->srv_next,f->hello+f->hello_sent,n);
        f->hello_sent+=n;
        if ((uint32_t)(f->cli_next-f->isn-1)<f->hello_sent)
            f->cli_next=f->isn+1+(uint32_t)f->hello_sent;
    }
    f->send_due=f->hello_sent < f->params.hello_len ? (now ? now : 1) : 0;
}
/* Finite loss recovery budget shared by all retry causes. This is a local
 * resource bound, not an inferred property of anything on the path. */
static void retry_hello(d2k_pf_flow *f, uint64_t now, d2k_pf_out *o, int synack) {
    if (f->send_due || f->hello_acked==f->params.hello_len || f->retries>=2) return;
    f->retries++; f->dup_acks=0;
    emit(f,o,16,synack ? f->isn+1 : f->cli_next,f->srv_next,NULL,0);
    f->hello_sent=f->hello_acked;
    hello_batch(f,now,o);
}
d2k_pf_verdict d2k_pf_client_syn(d2k_pf_table *t, const d2k_pkt *pkt, const d2k_pf_params *p,
                                 uint64_t now, d2k_pf_out *o) {
    o->count = 0;
    d2k_hold_info v;
    if (!parse(pkt, &v) || (v.flags & 0x17) != 2)
        return PF_ACT_PASS;
    d2k_pf_flow *f = find(t, &v, 0);
    if (f && f->isn == v.seq) {
        if (f->stage>=PF_DONE)
            return PF_ACT_PASS;
        if (expired(f, now, o))
            return PF_ACT_DROP;
        if (f->stage == PF_RESYN || f->stage == PF_HANDOVER) {
            if (f->stage==PF_RESYN && f->resyn_due) {
                if (now<f->resyn_due) return PF_ACT_DROP;
                resyn_attempt(f,now); /* this client retry replaces the due timer SYN */
            }
            f->handover_started=1;
            return PF_ACT_PASS;
        }
        if (f->stage == PF_PROBE_SYN) {
            if (f->params.reference_hello && v.ihl==f->ihl && !v.payload &&
                v.total<=sizeof f->orig && v.total==pkt->wire_len) {
                size_t ts=option(pkt->wire+v.ihl,8);
                if (f->have_ts && ts)
                    f->ts_val=rd32(pkt->wire+v.ihl+ts+2)+1;
                (void)probe_syn(f,o,pkt->wire,v.total);
            } else {
                (void)probe_syn(f,o,f->orig,f->orig_len);
            }
        }
        else if (f->stage == PF_PROBE_DATA)
            retry_hello(f,now,o,0);
        return PF_ACT_DROP;
    }
    if (!t || !t->flows || !p || !p->window || p->wscale > 14 || !p->pieces || p->hello_own > 1 ||
        (!p->resyn_delay_ms != !p->resyn_sends) ||
        p->resyn_delay_ms>=p->timeout_ms || p->resyn_timeout_ms>=p->timeout_ms ||
        (p->resyn_timeout_ms && p->resyn_timeout_ms<(uint64_t)p->resyn_delay_ms*p->resyn_sends) ||
        !p->timeout_ms || p->timeout_ms>D2K_PF_EXEC_MAX_TIMEOUT_MS ||
        now>UINT64_MAX-(uint64_t)p->timeout_ms*1000000 || !p->hello || !p->hello_len || p->hello_len > D2K_CAPTURE_BYTES ||
        v.payload || v.total > sizeof f->orig || pkt->wire_len != v.total)
        return PF_ACT_PASS;
    if (!f)
        for (unsigned i = 0; i < t->cap; i++) {
            if (!t->flows[i].used || !active(&t->flows[i])) {
                f = &t->flows[i];
                break;
            }
        }
    if (!f) {
        t->full_passes++;
        return PF_ACT_PASS;
    }
    memset(f, 0, sizeof *f);
    f->used = 1;
    f->key = v.key;
    f->client_low = v.src_low;
    f->stage = PF_PROBE_SYN;
    f->params = *p;
    memcpy(f->hello, p->hello, p->hello_len);
    if (p->reference_hello && !d2k_pf_randomize_hello(f->hello,p->hello_len)) {
        f->used = 0;
        return PF_ACT_PASS;
    }
    f->params.hello = f->hello;
    memcpy(f->orig, pkt->wire, v.total);
    f->orig_len = v.total;
    f->ihl = v.ihl;
    f->isn = v.seq;
    if ((f->orig[0] >> 4) == 4)
        f->ip_id = (uint16_t)rd16(f->orig + 4);
    uint64_t delta = (uint64_t)p->timeout_ms * 1000000;
    f->deadline = now > UINT64_MAX - delta ? UINT64_MAX : now + delta;
    uint64_t reserve=(uint64_t)p->resyn_timeout_ms*1000000;
    f->probe_deadline=f->deadline-reserve;
    size_t ts = option(f->orig + v.ihl, 8);
    if (ts) {
        f->have_ts = 1;
        f->first_syn_ts = rd32(f->orig + v.ihl + ts + 2);
        f->ts_val = f->first_syn_ts + 1;
    }

    if (!probe_syn(f, o, f->orig, f->orig_len)) {
        f->used = 0;
        return PF_ACT_PASS;
    }
    return PF_ACT_DROP;
}
d2k_pf_verdict d2k_pf_client_pkt(d2k_pf_table *t, const d2k_pkt *pkt, uint64_t now, d2k_pf_out *o) {
    o->count = 0;
    d2k_hold_info v;
    if (!parse(pkt, &v))
        return PF_ACT_PASS;
    if ((v.flags & 0x17) == 2)
        return d2k_pf_client_syn(t, pkt, NULL, now, o);
    d2k_pf_flow *f = find(t, &v, 0);
    if (!f || f->stage>=PF_DONE)
        return PF_ACT_PASS;
    int handed_over=f->stage==PF_HANDOVER;
    if (expired(f, now, o)) return handed_over ? PF_ACT_PASS : PF_ACT_DROP;
    return f->stage == PF_HANDOVER ? PF_ACT_PASS : PF_ACT_DROP;
}
d2k_pf_verdict d2k_pf_server_pkt(d2k_pf_table *t, const d2k_pkt *pkt, uint64_t now, d2k_pf_out *o) {
    o->count = 0;
    d2k_hold_info v;
    if (!parse(pkt, &v))
        return PF_ACT_PASS;
    d2k_pf_flow *f = find(t, &v, 1);
    if (!f || f->stage>=PF_DONE)
        return PF_ACT_PASS;
    int handed_over=f->stage==PF_HANDOVER;
    if (expired(f, now, o))
        return handed_over ? PF_ACT_PASS : PF_ACT_DROP;
    const uint8_t *tcp = pkt->wire + v.ihl;
    if (f->stage == PF_HANDOVER) return PF_ACT_PASS;
    if (f->stage == PF_RESYN) {
        if ((v.flags & 0x17) == 0x12 && v.ack == f->isn + 1 &&
            v.seq != f->srv_isn && f->handover_started) {
            f->stage = PF_HANDOVER;
            f->resyn_due=0;
            f->cli_next=f->isn+1;
            f->srv_next=v.seq+1;
            return PF_ACT_PASS;
        }
        if (v.flags == 0x10 && !v.payload && f->resets < 5) {
            f->resets++;
            emit(f, o, 4, v.ack, 0, NULL, 0);
            schedule_resyn(f,now,o);
        }
        return PF_ACT_DROP;
    }
    if (v.flags & 4) {
        schedule_resyn(f,now,o);
        return PF_ACT_DROP;
    }
    if (f->stage == PF_PROBE_SYN) {
        if ((v.flags & 0x17) == 0x12 && v.ack == f->isn + 1) {
            f->handshaken = 1;
            f->srv_isn=v.seq;
            f->srv_next = v.seq + 1;
            f->cli_next = f->isn + 1;
            size_t ts = option(tcp, 8);
            if (f->have_ts) {
                if (!ts) f->have_ts=0;
                else if (f->params.reference_hello) {
                    uint32_t echoed=rd32(tcp+ts+6);
                    if (echoed-f->first_syn_ts <= f->ts_val-1-f->first_syn_ts)
                        f->ts_val=echoed+1;
                }
            }
            size_t overhead=f->ihl+20+(f->have_ts ? 12u : 0u);
            size_t cap=f->params.send_cap ? f->params.send_cap : D2K_RAW_MTU_FALLBACK;
            size_t mss_opt=option(tcp,2);
            unsigned default_mss = v.dst.family == 6 ? 1220 : 536;
            unsigned mss=mss_opt ? rd16(tcp+mss_opt+2) : default_mss;
            if (!mss || cap<=overhead) { give_up(f,o); return PF_ACT_DROP; }
            f->segment_cap=cap-overhead;
            if (f->segment_cap>mss) f->segment_cap=mss;
            if (f->params.reference_hello && f->params.hello_len>f->segment_cap) {
                give_up(f,o);
                return PF_ACT_DROP;
            }
            if (f->have_ts && ts)
                f->ts_ecr = rd32(tcp + ts + 2);
            emit(f, o, 16, f->isn + 1, f->srv_next, NULL, 0);
            hello_batch(f,now,o);
            f->stage = PF_PROBE_DATA;
        }
        return PF_ACT_DROP;
    }
    if (v.flags & 2) {
        if ((v.flags & 0x17)==0x12 && v.seq==f->srv_isn && v.ack==f->isn+1)
            retry_hello(f,now,o,1);
        return PF_ACT_DROP;
    }
    if (v.flags & 16) {
        uint32_t acked=v.ack-f->isn-1;
        if (acked>=f->hello_acked && acked<=(uint32_t)(f->cli_next-f->isn-1)) {
            if (acked>f->hello_acked) { f->hello_acked=acked; f->dup_acks=0; }
            else if (!v.payload && f->hello_acked<f->params.hello_len && ++f->dup_acks==3)
                retry_hello(f,now,o,0); /* RFC 5681 duplicate ACK threshold */
        }
    }
    if (v.payload && !(v.flags & 2) && (v.flags & 16) &&
        !f->send_due && v.ack == f->isn + 1 + (uint32_t)f->params.hello_len) {
        /* As in Task 3, count new contiguous data, including the new suffix
         * of an overlapping retransmission. Serial subtraction handles wrap;
         * duplicate/gapped data gets an ACK but never advances K. */
        uint32_t skip = f->srv_next - v.seq;
        if (skip < UINT32_C(0x80000000) && skip < v.payload) {
            f->srv_next += (uint32_t)v.payload - skip;
            f->pieces++;
        }
        size_t ts = option(tcp, 8);
        if (f->have_ts && ts)
            f->ts_ecr = rd32(tcp + ts + 2);
        if (!f->send_due && f->pieces >= f->params.pieces) {
            emit(f, o, 4, f->cli_next, 0, NULL, 0);
            schedule_resyn(f,now,o);
        } else
            emit(f, o, 16, f->cli_next, f->srv_next, NULL, 0);
    }
    return PF_ACT_DROP;
}
void d2k_pf_tick(d2k_pf_table *t, uint64_t now, d2k_pf_out *o) {
    o->count = 0;
    if (!t || !t->flows)
        return;
    for (unsigned i = 0; i < t->cap; i++) {
        d2k_pf_flow *f = &t->flows[i];
        if (f->used && f->cleanup_pending) {
            if(now>=f->cleanup_due) {
                if(o->count==D2K_PF_OUT_MAX) break;
                clear_token(f,o);
                uint64_t delta=(uint64_t)f->params.timeout_ms*1000000;
                f->cleanup_due=now>UINT64_MAX-delta ? UINT64_MAX : now+delta;
            }
        } else if (f->used && active(f) && now >= flow_deadline(f)) {
            if (o->count + (f->handshaken ? 2u : 1u) > D2K_PF_OUT_MAX)
                break;
            give_up(f, o);
        } else if (f->used && f->resyn_due && now>=f->resyn_due) {
            if (o->count==D2K_PF_OUT_MAX) break;
            original(f,o); resyn_attempt(f,now);
        } else if (f->used && f->send_due && now>=f->send_due) {
            hello_batch(f,now,o);
            if (o->count==D2K_PF_OUT_MAX) break;
        }
    }
}
void d2k_pf_abort(d2k_pf_table *t, const d2k_pkt *pkt, d2k_pf_out *o) {
    o->count = 0;
    d2k_hold_info v;
    if (!parse(pkt, &v))
        return;
    d2k_pf_flow *f = find(t, &v, 0);
    if (f && active(f)) {
        if(f->cleanup_pending) clear_token(f,o);
        else give_up(f, o);
    }
}
uint64_t d2k_pf_next_ns(const d2k_pf_table *t) {
    uint64_t n = 0;
    if (t && t->flows)
        for (unsigned i = 0; i < t->cap; i++) {
            const d2k_pf_flow *f = &t->flows[i];
            if (f->used && active(f)) {
                uint64_t due=f->cleanup_pending ? f->cleanup_due :
                    f->send_due && f->send_due<flow_deadline(f) ? f->send_due : flow_deadline(f);
                if (f->resyn_due && f->resyn_due<due) due=f->resyn_due;
                if (!n || due<n) n=due;
            }
        }
    return n;
}
int d2k_pf_get_stage(const d2k_pf_table *t, const d2k_pkt *pkt, d2k_pf_stage *s) {
    d2k_hold_info v;
    if (!s || !parse(pkt, &v))
        return 0;
    d2k_pf_flow *f = find(t, &v, 0);
    if (!f)
        return 0;
    *s = f->stage;
    return 1;
}

void d2k_pf_complete(d2k_pf_table *t, const d2k_pkt *p, d2k_pf_out *o) {
    o->count=0;
    d2k_hold_info v;
    if (!parse(p,&v) || !v.payload) return;
    d2k_pf_flow *f=find(t,&v,0);
    if (!f || f->stage!=PF_HANDOVER) return;
    f->cli_next=v.seq+(uint32_t)v.payload; f->srv_next=v.ack;
    clear_token(f,o); f->stage=PF_DONE;
}

void d2k_pf_output_sent(d2k_pf_table *t,const d2k_pkt *p,unsigned clear) {
    d2k_hold_info v;
    if (clear!=2 || !parse(p,&v)) return;
    d2k_pf_flow *f=find(t,&v,0);
    if(f) f->cleanup_pending=0;
}
