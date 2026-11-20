/* The daemon's ownership boundary, portable so ordering can be exercised
 * without opening NFQUEUE or raw sockets. No packet waits in a kernel queue. */
#include "d2k_preflight_path.h"
static int deliver(d2k_session *s, uint64_t now, const d2k_pf_out *out,
                   const d2k_preflight_io *io, int *original_sent) {
    int failed=0;
    d2k_key aborted[D2K_PF_OUT_MAX]; size_t aborted_count=0;
    if(original_sent) *original_sent=0;
    for(size_t i=0;i<out->count;i++) {
        /* After any failure, abandon synthetic traffic but attempt EVERY
         * owned original, including other flows in a bounded timeout batch. */
        d2k_hold_info v; int parsed=d2k_hold_parse(out->packet[i],out->len[i],&v);
        int skip=0;
        for(size_t j=0;j<aborted_count;j++)
            if(parsed && d2k_key_equal(&aborted[j],&v.key)) skip=1;
        if(skip && !out->original[i] && !out->clear[i]) continue;
        uint32_t mark=out->clear[i]==2 ? D2K_PF_TOKEN_MARK :
            out->clear[i]==1 ? D2K_PF_RELEASE_MARK : D2K_PF_MARK;
        if(io->send(io->ctx,out->packet[i],out->len[i],mark)) {
            failed=1;
            int will_release=0;
            for(size_t j=i+1;j<out->count;j++) {
                d2k_hold_info next;
                if(out->original[j] && parsed && d2k_hold_parse(out->packet[j],out->len[j],&next) &&
                    d2k_key_equal(&v.key,&next.key)) will_release=1;
            }
            if(!out->original[i] && !out->clear[i] && !will_release) {
                d2k_pf_out fallback;
                d2k_session_preflight_abort(s,out->packet[i],out->len[i],now,&fallback);
                int sent=0;
                (void)deliver(s,now,&fallback,io,&sent);
                if(sent && original_sent) *original_sent=1;
                if(parsed && aborted_count<D2K_PF_OUT_MAX) aborted[aborted_count++]=v.key;
            }
            continue;
        }
        d2k_session_preflight_output_sent(s,out->packet[i],out->len[i],out->clear[i]);
        /* Only a successfully re-injected original belongs to normal traffic
         * accounting. The probe SYN has the same tuple but is not the client. */
        if(out->original[i]) {
            if(original_sent) *original_sent=1;
            d2k_session_preflight_original_sent(s,out->packet[i],out->len[i],now);
            d2k_session_observe_tcp(s,out->packet[i],out->len[i],now);
        }
    }
    return failed ? -1 : 0;
}
int d2k_preflight_path_packet_path(d2k_session *s,const uint8_t *p,size_t n,uint32_t id,
                              uint64_t now,const d2k_preflight_io *io,uint32_t path) {
    if(!io || !io->drop || !io->send) return 0;
    d2k_pf_out out;
    if(!d2k_session_preflight_packet_path(s,p,n,now,&out,path)) {
        /* Expiry after handover may emit a cleanup token while the real
         * packet still belongs to the ordinary processing path. */
        if(out.count) (void)deliver(s,now,&out,io,NULL);
        return 0;
    }
    if(io->drop(io->ctx,id)) {
        /* No ownership acknowledged: cancel all future synthetic output. */
        d2k_session_preflight_abort(s,p,n,now,&out);
        return -1;
    }
    int original_sent=0;
    if(deliver(s,now,&out,io,&original_sent) && !original_sent) {
        /* Our send failed, not the measured path. Stop probing and release the
         * saved original; each failed raw send is reported by the daemon. */
        d2k_session_preflight_abort(s,p,n,now,&out);
        (void)deliver(s,now,&out,io,NULL);
    }
    return 1;
}
int d2k_preflight_path_packet(d2k_session *s,const uint8_t *p,size_t n,uint32_t id,
    uint64_t now,const d2k_preflight_io *io) {
    return d2k_preflight_path_packet_path(s,p,n,id,now,io,0);
}
int d2k_preflight_path_tick(d2k_session *s,uint64_t now,const d2k_preflight_io *io) {
    if(!io || !io->send) return -1;
    d2k_pf_out out;
    d2k_session_preflight_tick(s,now,&out);
    return deliver(s,now,&out,io,NULL);
}

int d2k_preflight_path_flush(d2k_session *s,uint64_t now,const d2k_preflight_io *io) {
    if(!io || !io->send) return -1;
    d2k_pf_out out;
    d2k_session_preflight_flush(s,now,&out);
    return deliver(s,now,&out,io,NULL);
}

int d2k_preflight_path_complete_on(d2k_session *s,const uint8_t *p,size_t n,uint64_t now,
                                const d2k_preflight_io *io, uint32_t path) {
    if (!io || !io->send) return -1;
    d2k_pf_out out;
    d2k_session_preflight_complete_on(s,p,n,now,&out,path);
    return deliver(s,now,&out,io,NULL);
}

int d2k_preflight_path_complete(d2k_session *s,const uint8_t *p,size_t n,uint64_t now,
                                const d2k_preflight_io *io) {
    return d2k_preflight_path_complete_on(s,p,n,now,io,0);
}
