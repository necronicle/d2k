#ifndef D2K_QUIC_FLOW_H
#define D2K_QUIC_FLOW_H

#include <stdlib.h>
#include <string.h>
#include "d2k_track.h"

/* Once ClientHello is complete, its CRYPTO bytes can no longer change.
 * Retain only what identifies and authenticates another Initial in this
 * flight and the name it would recover (including during hold replay). */
struct d2k_quic_replay {
    uint32_t version;
    size_t dcid_len;
    uint8_t dcid[D2K_QW_CID_MAX];
    d2k_qw_keys keys;
    uint64_t largest_pn;
    int named;
    char name[];
};

/* Caller has identified a client Initial with d2k_quic_is_initial. */
static int flow_quic_feed(d2k_flow *f, const uint8_t *payload, size_t len,
                          char name[256], int *complete) {
    *complete = 0;
    struct d2k_quic_replay *r = f->quic_replay;
    if (r) {
        d2k_qw_hdr h;
        if (len > D2K_QW_MAX_DGRAM || d2k_qw_hdr_parse(payload, len, 0, &h) != 0 ||
            !h.long_hdr || h.type != D2K_QW_LT_INITIAL) return -1;
        if (h.version == r->version && h.dcid_len == r->dcid_len &&
            !memcmp(payload + h.dcid_off, r->dcid, r->dcid_len)) {
            uint8_t plain[D2K_QW_MAX_DGRAM];
            size_t plain_len;
            uint64_t pn;
            if (d2k_qw_open(&r->keys, &h, payload, r->largest_pn,
                            plain, &plain_len, &pn) != 0) return -1;
            if (pn > r->largest_pn) r->largest_pn = pn;
            if (r->named) memcpy(name, r->name, strlen(r->name) + 1);
            *complete = 1;
            return r->named;
        }
    }

    d2k_quic_assembly first;
    first.active = 0;
    d2k_quic_assembly *a = f->quic_assembly ? f->quic_assembly : &first;
    int named = d2k_quic_assembly_feed(a, payload, len, name, 256);
    if (!a->active) return -1;  /* Unauthenticated first packet or change of DCID. */
    free(f->quic_replay);
    f->quic_replay = NULL;

    if (named >= 0 && d2k_quic_assembly_complete(a)) {
        *complete = 1;
        size_t name_len = named ? strlen(name) + 1 : 0;
        r = malloc(sizeof *r + name_len);
        if (r) {
            r->version = a->version;
            r->dcid_len = a->dcid_len;
            memcpy(r->dcid, a->dcid, a->dcid_len);
            r->keys = a->keys;
            r->largest_pn = a->largest_pn;
            r->named = named;
            if (named) memcpy(r->name, name, name_len);
            f->quic_replay = r;
            free(f->quic_assembly);
            f->quic_assembly = NULL;
        }
        /* Failed compaction leaves any existing full assembly available. */
        return named;
    }

    if (!f->quic_assembly) {
        f->quic_assembly = malloc(sizeof *a);
        if (f->quic_assembly) *f->quic_assembly = *a;
        else if (!named) return -1;
    }
    return named;
}

#endif
