/* Наблюдатель позднего потока (этап 49), см. include/d2k_lateobs.h. */
#include <string.h>
#include "d2k_lateobs.h"
#include "d2k_packet.h"

void d2k_lateobs_init(d2k_lateobs *o, const d2k_ct_tuple *t) {
    memset(o, 0, sizeof *o);
    o->t = *t;
}

/* 1 — пакет клиента этого потока, 2 — сервера, 0 — чужой. */
static int side_of(const d2k_ct_tuple *t, const d2k_packet_view *v, const uint8_t *th) {
    size_t al = t->family == 6 ? 16 : 4;
    if (v->family != t->family || v->protocol != 6) return 0;
    if (!memcmp(v->src.bytes, t->src, al) && !memcmp(v->dst.bytes, t->dst, al) &&
        !memcmp(th, t->sport_be, 2) && !memcmp(th + 2, t->dport_be, 2)) return 1;
    if (!memcmp(v->src.bytes, t->dst, al) && !memcmp(v->dst.bytes, t->src, al) &&
        !memcmp(th, t->dport_be, 2) && !memcmp(th + 2, t->sport_be, 2)) return 2;
    return 0;
}

int d2k_lateobs_feed(d2k_lateobs *o, const uint8_t *pkt, size_t n) {
    d2k_packet_view v;
    if (!o || !d2k_packet_parse(pkt, n, &v) || v.protocol != 6) return 0;
    const uint8_t *th = pkt + v.l4;
    size_t doff = (size_t)(th[12] >> 4) * 4u;
    if (doff < 20 || doff > v.total - v.l4) return 0;
    int side = side_of(&o->t, &v, th);
    if (side == 2) { o->server_pkts++; return 1; }
    if (side != 1) return 0;
    o->client_pkts++;
    uint32_t len = (uint32_t)(v.total - v.l4 - doff);
    if (!len) return 1;
    o->client_data++;
    uint32_t seq = (uint32_t)th[4] << 24 | (uint32_t)th[5] << 16 | (uint32_t)th[6] << 8 | th[7];
    /* Повтор — уже посланные байты снова (перекрытие диапазонов seq по
       модулю 2^32): Linux при повторе сливает мелкие сегменты, и тот же seq
       приходит с другой длиной. Стык — не повтор. */
    for (uint8_t i = 0; i < o->n_seq; i++) {
        if ((int32_t)(seq - (o->seq[i] + o->len[i])) < 0 && (int32_t)(o->seq[i] - (seq + len)) < 0) {
            o->repeats++;
            return 1;
        }
    }
    o->seq[o->next] = seq;
    o->len[o->next] = len;
    o->next = (uint8_t)((o->next + 1) % D2K_LATEOBS_SEQS);
    if (o->n_seq < D2K_LATEOBS_SEQS) o->n_seq++;
    return 1;
}

uint8_t d2k_lateobs_result(const d2k_lateobs *o, int expired) {
    if (o->server_pkts) return D2K_LATEOBS_SERVER_ANSWERED;
    if (o->repeats) return D2K_LATEOBS_REPEAT_SILENT;
    if (!expired) return D2K_LATEOBS_PENDING;
    if (!o->client_pkts) return D2K_LATEOBS_NOTHING;
    return o->client_data ? D2K_LATEOBS_CLIENT_NEW_DATA : D2K_LATEOBS_NO_CLIENT_DATA;
}
