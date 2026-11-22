#ifndef D2K_QUIC_FLOW_H
#define D2K_QUIC_FLOW_H

#include "d2k_track.h"

static int flow_quic_feed(d2k_flow *f, const uint8_t *payload, size_t len,
                          char name[256], int *complete) {
    if (!f->quic_assembly) {
        f->quic_assembly = &f->storage->quic;
        d2k_quic_assembly_init(f->quic_assembly);
    }
    int named = d2k_quic_assembly_feed(f->quic_assembly, payload, len, name, 256);
    *complete = named >= 0 && d2k_quic_assembly_complete(f->quic_assembly);
    return named;
}
#endif
