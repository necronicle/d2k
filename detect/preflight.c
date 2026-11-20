/* Three questions about a TCP response gate, using owned raw episodes.
 * A positive result is ServerHello on the fresh normal-window connection,
 * never a claim of HTTP/application success. */
#include "d2k_preflight_probe.h"
#include "d2k_compose.h"
#include "d2k_hello.h"
#include "d2k_preflight_plan.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

/* Keep the options negotiated by this episode. The legacy detect profile
 * drops timestamps from data even when its SYN offered them; that can make
 * the peer discard the hello before the response-gate experiment begins. */
static const char pf_direct[] =
    "d2k-plan 1 8\nid 00000000000000000000000000000000\n"
    "proto tcp tls\nwire tcp-template-v1\norder forward\n";

static int pf_wait(uint32_t rtt)
{
    uint64_t ms=(uint64_t)rtt*8;
    return ms<1000 ? 1000 : ms>5000 ? 5000 : (int)ms;
}
static int pf_close(d2k_raw_episode *ep)
{
    int rc=d2k_raw_episode_reset(ep);
    d2k_raw_episode_free(ep);
    return rc;
}
static d2k_raw_episode *pf_open(const uint8_t *ip,uint8_t family,uint16_t port,
    const d2k_raw_tuple *reuse,uint16_t window,uint8_t scale,int timestamps,
    const d2k_opts *opt,d2k_raw_observation *obs)
{
    d2k_raw_shape shape={.sport=reuse?reuse->local_port:0,.syn_window=window,
        .syn_wscale=scale,.data_window=window,.defer_response_ack=1,
        .initial_seq_known=reuse!=NULL,.initial_seq=reuse?reuse->initial_seq:0,
        .syn_retry_ms=reuse?D2K_PF_FALLBACK_RESYN_DELAY_MS:0,
        .syn_max_sends=reuse?D2K_PF_FALLBACK_RESYN_SENDS:0};
    char err[160];
    return d2k_raw_episode_open_shaped(ip,family,port,opt->timeout_ms,opt->mark,timestamps,
        &shape,&opt->cancel,err,sizeof err,obs);
}
static int pf_send(d2k_raw_episode *ep,const d2k_trigger *tr,const d2k_opts *opt)
{
    char err[160];
    return d2k_raw_episode_send(ep,0,(uint32_t)tr->len,tr,pf_direct,
        &opt->cancel,err,sizeof err,NULL);
}
/* Read distinct in-order packets, stopping the small-window question at
 * the complete record containing ServerHello or at an earlier complete flight.
 * Partial records/handshakes are incomplete experiments, never negative carry.
 * Retransmissions and ACKs do not count or extend the per-piece deadline. */
static int pf_read(d2k_raw_episode *ep,unsigned k,int timeout,const d2k_opts *opt,
    uint8_t *prefix,size_t *have,unsigned *pieces,int *ended,d2k_raw_observation *obs,
    const d2k_trigger *accept)
{
    uint8_t packet[65535];
    uint32_t next=0;
    uint8_t header[5],handshake[4];
    size_t header_n=0,record_left=0,handshake_n=0,hello_left=0;
    int hello_started=0,hello_done=0;
    *have=0;*pieces=0;*ended=0;
    int64_t deadline=d2k_now_ms()+timeout;
    while(*pieces<k) {
        int64_t left=deadline-d2k_now_ms();
        if(left<=0) {
            if(*pieces && (header_n || record_left || (hello_started && !hello_done)))return -1;
            *ended=1;return 0;
        }
        d2k_raw_packet_event ev;
        int rc=d2k_raw_episode_event(ep,(int)left,&opt->cancel,packet,sizeof packet,&ev,obs);
        if(rc) {
            if(obs->kind==D2K_RAW_OBS_RESPONSE_TIMEOUT) {
                if(*pieces && (header_n || record_left || (hello_started && !hello_done)))return -1;
                *ended=1;return 0;
            }
            return -1;
        }
        if(ev.flags & 4)return -1;
        if(!ev.payload_len) {if(ev.flags & 1)return -1;continue;}
        if(!ev.ack_in_sent_range || ev.sequence_offset>next) return -1;
        uint32_t skip=next-ev.sequence_offset;
        if(skip>=ev.payload_len) continue;
        size_t n=ev.payload_len-skip;
        if(n>UINT32_MAX-next) return -1;
        size_t copy=n;
        if(copy>4096-*have) copy=4096-*have;
        memcpy(prefix+*have,packet+skip,copy);*have+=copy;
        next+=(uint32_t)n;(*pieces)++;
        if(accept && d2k_trigger_accepts(accept,prefix,*have))return 0;
        for(size_t i=skip;i<ev.payload_len;i++) {
            if(record_left) {
                if(header[0]==22 && !hello_done) {
                    if(handshake_n<4) {
                        handshake[handshake_n++]=packet[i];
                        hello_started=1;
                        if(handshake_n==4) {
                            if(handshake[0]!=2)return -1;
                            hello_left=((size_t)handshake[1]<<16)|
                                ((size_t)handshake[2]<<8)|handshake[3];
                            if(hello_left<38)return -1;
                        }
                    } else if(hello_left && --hello_left==0)hello_done=1;
                }
                record_left--;
                if(!accept && hello_done && !record_left) {
                    *ended=2;return 0;
                }
                continue;
            }
            header[header_n++]=packet[i];
            if(header_n==5) {
                if(header[0]<20 || header[0]>23 || header[1]!=3)return -1;
                record_left=((size_t)header[3]<<8)|header[4];header_n=0;
            }
        }
        if(ev.flags & 1)return -1;
        deadline=d2k_now_ms()+timeout;
    }
    return 0;
}
static int record_alternate(const d2k_trigger *tr,d2k_preflight_meas *out)
{
    size_t off=0,len=0;
    if(!tr->len || tr->len>D2K_TRIGGER_MAX ||
       d2k_hello_sni(tr->payload,tr->len,&off,&len) ||
       !len || len>=sizeof out->white_name) return 0;
    memcpy(out->white_name,tr->payload+off,len);
    out->white_name[len]=0;
    out->hello_own=0;
    return 1;
}
static int probe_once(const char *addr,const d2k_trigger *tr,const d2k_trigger *alternate,
    int start_alternate,const d2k_opts *opt,d2k_preflight_meas *out)
{
    uint8_t ip[16],prefix[4096];char host[INET6_ADDRSTRLEN];
    d2k_raw_observation obs; d2k_raw_tuple tuple;
    size_t have;unsigned pieces;int ended,rc;
    memset(out,0,sizeof *out);
    if((!opt->control_vouched && !opt->preflight_auto) || opt->no_raw || tr->accept!=D2K_ACCEPT_SERVERHELLO ||
       !tr->len || tr->len>D2K_TRIGGER_MAX || d2k_detect_stopped(&opt->cancel)) return 0;
    const char *colon=strrchr(addr,':');
    if(!colon || colon==addr) return 0;
    const char *begin=addr,*host_end=colon;
    if(*begin=='[') {
        if(host_end-begin<3 || host_end[-1]!=']') return 0;
        begin++;host_end--;
    }
    size_t host_len=(size_t)(host_end-begin);
    if(host_len>=sizeof host) return 0;
    memcpy(host,begin,host_len);host[host_len]=0;
    char *end;unsigned long port=strtoul(colon+1,&end,10);
    if(!colon[1] || *end || !port || port>65535) return 0;
    uint8_t family=4;
    if(inet_pton(AF_INET,host,ip)!=1) {
        if(!opt->preflight_ipv6 || inet_pton(AF_INET6,host,ip)!=1) return 0;
        family=6;
    }

    /* A full ACK raises response-measurement priority; silence of the ACK
     * does not rule out a useful candidate. Establish the normal-window
     * failure here, then require repeated small-window AND fresh handover
     * success. This experiment does not identify where the baseline was lost. */
    int timestamps=opt->preflight_auto && tr->client_tcp_known && d2k_trigger_offers_ts(tr);
    d2k_raw_episode *ep=pf_open(ip,family,(uint16_t)port,0,65535,D2K_GATE_MEASURED_WSCALE,
        timestamps,opt,&obs);
    if(!ep)return -1;
    out->baseline_probes=1;
    if(!d2k_raw_episode_tuple(ep,&tuple) || !obs.rtt_ms || pf_send(ep,tr,opt)) {
        pf_close(ep);return -1;
    }
    rc=pf_read(ep,1,pf_wait(obs.rtt_ms),opt,prefix,&have,&pieces,&ended,&obs,tr);
    int gate=!rc && ended && !have && obs.kind==D2K_RAW_OBS_RESPONSE_TIMEOUT &&
        obs.transport.available;
    out->baseline_acked=obs.transport.acked_end;
    int closed=pf_close(ep);
    if(have)return 2; /* Any direct response defeats the silent-gate premise. */
    if(closed)return -1;
    if(!gate) {
        if(!rc && obs.kind==D2K_RAW_OBS_RESPONSE_TIMEOUT)
            snprintf(out->reason,sizeof out->reason,"прямой пробой подтверждено %u из %zu байт приветствия",
                     obs.transport.acked_end,tr->len);
        return rc ? -1 : 0;
    }
    /* Without a full ACK, baseline silence alone does not establish a
     * response property. A later small-window reply can establish it. */
    out->response_gate=out->baseline_acked>=tr->len;

    d2k_trigger randomized;
    const d2k_trigger *hello=tr;
    out->hello_own=1;
    if(start_alternate) {
        if(!record_alternate(alternate,out))return -1;
        randomized=*alternate;
        if(!d2k_pf_randomize_hello(randomized.payload,randomized.len))return -1;
        hello=&randomized;
    }
    unsigned k=1,low=0,high=0;
    uint8_t scale=start_alternate?D2K_PF_REFERENCE_WSCALE:D2K_GATE_MEASURED_WSCALE;
    for(;;) {
        out->probes++;
        ep=pf_open(ip,family,(uint16_t)port,0,1,scale,timestamps,opt,&obs);
        if(!ep)return -1;
        if(!obs.rtt_ms || !d2k_raw_episode_tuple(ep,&tuple) || pf_send(ep,hello,opt)) {
            pf_close(ep);return -1;
        }
        out->rtt_ms=obs.rtt_ms;
        rc=pf_read(ep,k,pf_wait(out->rtt_ms),opt,prefix,&have,&pieces,&ended,&obs,NULL);
        if(pf_close(ep) || rc)return -1;
        if(!pieces) {
            if(hello==tr && record_alternate(alternate,out)) {
                hello=alternate;k=1;low=high=0;continue;
            }
            snprintf(out->reason,sizeof out->reason,"сервер не прислал данных в малом окне");
            return 0;
        }
        out->response_gate=1;out->pieces_pass=1;out->window=1;out->window_scale=scale;
        out->small_response_bytes=(uint32_t)have;
        /* Each K trial has a fresh source port. Only its handover reuses it;
         * previous trial permissions cannot contaminate a larger K. */
        out->probes++;
        /* Exercise the executor's initial delay and finite retry schedule.
         * The complete executor program still
         * requires application verification. The delay is an empirical
         * candidate parameter, not a measured state lifetime. */
        if(d2k_detect_stopped(&opt->cancel) ||
           d2k_sleep_us(D2K_PF_FALLBACK_RESYN_DELAY_MS*1000u) ||
           d2k_detect_stopped(&opt->cancel))return -1;
        ep=pf_open(ip,family,(uint16_t)port,&tuple,65535,D2K_GATE_MEASURED_WSCALE,
            timestamps,opt,&obs);
        if(!ep)return -1;
        d2k_raw_tuple handover;
        if(!d2k_raw_episode_tuple(ep,&handover) ||
           handover.family!=tuple.family || handover.local_port!=tuple.local_port ||
           handover.initial_seq!=tuple.initial_seq ||
           memcmp(handover.local,tuple.local,family==6?16:4) || pf_send(ep,tr,opt)) {
            pf_close(ep);return -1;
        }
        size_t reply;unsigned packets;int quiet;
        rc=pf_read(ep,UINT_MAX,pf_wait(out->rtt_ms),opt,prefix,&reply,&packets,&quiet,&obs,tr);
        int accepted=!rc && d2k_trigger_accepts(tr,prefix,reply);
        closed=pf_close(ep);
        if(!accepted && (closed || rc))return -1;
        if(accepted) {
            high=pieces;
        } else {
            low=pieces;
            if(ended || start_alternate) {
                snprintf(out->reason,sizeof out->reason,"%s: перенос через RST не наступил",
                    ended==2 ? "ServerHello получен целиком" : "первый полёт сервера завершён");
                return 0;
            }
        }
        if(high) {
            if(high-low==1) {
                out->carry_over_rst=1;out->pieces_needed=high;return 1;
            }
            k=low+(high-low)/2;
        } else {
            if(k>UINT_MAX/2)return -1; /* representation overflow, not a budget */
            k*=2;
        }
    }
}

/* Repeat whole isolated questions, rather than treating one successful raw
 * exchange as a stable path property. Each run owns fresh control tuples. */
static int repeat_probe(const char *addr,const d2k_trigger *tr,const d2k_trigger *alternate,
    int start_alternate,const d2k_opts *opt,d2k_preflight_meas *out)
{
    d2k_preflight_meas previous={0},current={0};
    unsigned attempts=0,locals=0,probes=0,controls=0;
    int prev=-2;
    for(;;) {
        int rc=probe_once(addr,tr,alternate,start_alternate,opt,&current);
        probes+=current.probes;controls+=current.baseline_probes;
        *out=current;out->probes=(uint16_t)probes;out->baseline_probes=(uint8_t)controls;
        if(rc==2 || (!current.baseline_probes && rc==0))return rc;
        if(d2k_detect_stopped(&opt->cancel))return -1;
        if(rc<0) { if(++locals==3)return -1; continue; }
        locals=0;attempts++;
        if(rc==prev && current.response_gate==previous.response_gate &&
           current.pieces_pass==previous.pieces_pass && current.window==previous.window &&
           current.window_scale==previous.window_scale &&
           current.pieces_needed==previous.pieces_needed &&
           current.carry_over_rst==previous.carry_over_rst &&
           current.hello_own==previous.hello_own &&
           !strcmp(current.white_name,previous.white_name))return rc;
        if(attempts==4) {
            out->carry_over_rst=0;out->pieces_needed=0;
            snprintf(out->reason,sizeof out->reason,"response/carry observations conflicting after four runs");
            return -1;
        }
        previous=current;prev=rc;
    }
}

int d2k_probe_preflight(const char *addr,const d2k_trigger *tr,
    const d2k_opts *opt,d2k_preflight_meas *out)
{
    if(!opt->preflight_auto) return repeat_probe(addr,tr,&opt->white,0,opt,out);
    d2k_trigger alternate={0};
    const char *name=opt->response_probe_name;
    if(!name || !*name || !d2k_pf_name_valid((const uint8_t *)name,strlen(name)) ||
       d2k_white_decoy_hello(name,alternate.payload,sizeof alternate.payload,&alternate.len))
        return repeat_probe(addr,tr,&alternate,0,opt,out);
    int rc=repeat_probe(addr,tr,&alternate,1,opt,out);
    if(rc || !out->response_gate || d2k_detect_stopped(&opt->cancel)) return rc;
    if(opt->preflight_combined && out->pieces_pass && out->window==1 &&
       out->window_scale==D2K_PF_REFERENCE_WSCALE && !out->hello_own &&
       out->white_name[0] && out->rtt_ms) {
        out->candidate=(d2k_preflight_candidate){.present=1,.window=out->window,
            .window_scale=out->window_scale,.pieces=1,.rtt_ms=out->rtt_ms,
            .response_bytes=out->small_response_bytes};
        snprintf(out->candidate.name,sizeof out->candidate.name,"%.*s",
            (int)sizeof out->candidate.name-1,out->white_name);
        return 3; /* candidate only: no positive carry property */
    }

    /* The single-piece probe did not carry. Measure the general candidate
     * separately, on fresh connections, before assigning any program. */
    d2k_preflight_meas first=*out;
    rc=repeat_probe(addr,tr,&alternate,0,opt,out);
    out->probes+=first.probes;
    out->baseline_probes+=first.baseline_probes;
    if(rc==0 && first.reason[0]) {
        char reason[sizeof out->reason];
        snprintf(reason,sizeof reason,"окно со scale=1: %.58s; scale=0: %.58s",
                 first.reason,out->reason);
        memcpy(out->reason,reason,strlen(reason)+1);
    }
    return rc;
}
