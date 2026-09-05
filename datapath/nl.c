/* nl.c — разбор и сборка сообщений netlink/NFQUEUE.
 *
 * Ни одного выделения памяти. Ни одной структуры ядра. Каждый цикл имеет явную
 * границу, и ни одно условие цикла не вычитает выровненную длину.
 */
#include <string.h>

#include "d2k_nl.h"

static size_t align4(size_t v) {
    return (v + 3u) & ~(size_t)3u;
}

/* Порядок байт ХОЗЯИНА — поля заголовков netlink. memcpy заодно снимает
   вопрос выравнивания указателя. */
static uint16_t h16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t h32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static void wh16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void wh32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

/* Порядок байт СЕТИ — содержимое атрибутов nfqueue. */
static uint16_t n16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}
static uint32_t n32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}
static void wn16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static void wn32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

void d2k_nl_iter_init(d2k_nl_iter *it, const uint8_t *buf, size_t len) {
    if (!it) {
        return;
    }
    it->p = buf;
    it->left = buf ? len : 0;
}

int d2k_nl_next(d2k_nl_iter *it, d2k_nl_msg *m) {
    if (!it || !m || it->left < D2K_NLMSG_HDRLEN) {
        if (it) {
            it->left = 0;
        }
        return 0;
    }

    uint32_t mlen = h32(it->p);
    if (mlen < D2K_NLMSG_HDRLEN || (size_t)mlen > it->left) {
        /* Врущая или обрезанная длина. Гасим итератор: следующий заголовок
           пришлось бы искать по выдуманному смещению. */
        it->left = 0;
        return 0;
    }

    m->type     = h16(it->p + 4);
    m->flags    = h16(it->p + 6);
    m->seq      = h32(it->p + 8);
    m->pid      = h32(it->p + 12);
    m->body     = it->p + D2K_NLMSG_HDRLEN;
    m->body_len = (size_t)mlen - D2K_NLMSG_HDRLEN;

    size_t step = align4(mlen);
    if (step >= it->left) {
        /* Последнее сообщение: выравнивающего хвоста в буфере может не быть. */
        it->left = 0;
    } else {
        it->p += step;
        it->left -= step;
    }
    return 1;
}

int d2k_nl_packet(const d2k_nl_msg *m, d2k_nl_pkt *out) {
    if (!m || !out) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (m->body_len < D2K_NFGENMSG_LEN) {
        return -1;
    }

    size_t pos = align4(D2K_NFGENMSG_LEN);
    while (pos + D2K_NLA_HDRLEN <= m->body_len) {
        const uint8_t *a = m->body + pos;
        size_t   alen  = h16(a);
        uint16_t atype = (uint16_t)(h16(a + 2) & D2K_NLA_TYPE_MASK);

        if (alen < D2K_NLA_HDRLEN || alen > m->body_len - pos) {
            break;
        }
        const uint8_t *val = a + D2K_NLA_HDRLEN;
        size_t vlen = alen - D2K_NLA_HDRLEN;

        switch (atype) {
        case D2K_NFQA_PACKET_HDR:
            /* Заголовок упакован: 4+2+1 = 7 байт без хвоста. */
            if (vlen >= 7) {
                out->id          = n32(val);
                out->hw_protocol = n16(val + 4);
                out->hook        = val[6];
                out->have_hdr    = 1;
            }
            break;
        case D2K_NFQA_PAYLOAD:
            out->payload      = val;
            out->payload_len  = vlen;
            out->have_payload = 1;
            break;
        case D2K_NFQA_CAP_LEN:
            if (vlen >= 4) {
                out->cap_len = n32(val);
            }
            break;
        case D2K_NFQA_SKB_INFO:
            if (vlen >= 4) {
                out->skb_info = n32(val);
            }
            break;
        case D2K_NFQA_MARK:
            if (vlen >= 4) {
                out->mark = n32(val);
                out->have_mark = 1;
            }
            break;
        default:
            break;
        }

        size_t step = align4(alen);
        if (step > m->body_len - pos) {
            /* Хвост последнего атрибута не выровнен — это конец, а не ошибка. */
            break;
        }
        pos += step;
    }

    out->truncated = out->cap_len > out->payload_len;
    return 0;
}

int d2k_nl_errno(const d2k_nl_msg *m, int32_t *err) {
    if (!m || m->type != D2K_NLMSG_ERROR || m->body_len < 4) {
        return -1;
    }
    if (err) {
        /* struct nlmsgerr { int error; struct nlmsghdr msg; } — int в порядке
           хозяина, отрицательный errno. */
        uint32_t v = h32(m->body);
        int32_t signed_v;
        memcpy(&signed_v, &v, 4);
        *err = signed_v;
    }
    return 0;
}

/* --- сборка --------------------------------------------------------------- */

/* Общий заголовок: nlmsghdr + nfgenmsg. Возвращает позицию за ними. */
static size_t hdr_init(uint8_t *o, size_t cap, uint16_t type, uint16_t flags,
                       uint32_t seq, uint16_t queue) {
    size_t need = D2K_NLMSG_HDRLEN + D2K_NFGENMSG_LEN;
    if (!o || cap < need) {
        return 0;
    }
    memset(o, 0, need);
    /* nlmsg_len проставляется в конце, когда известна полная длина. */
    wh16(o + 4, type);
    wh16(o + 6, flags);
    wh32(o + 8, seq);
    wh32(o + 12, 0);            /* pid: ядро подставит наш */
    o[16] = 0;                  /* nfgen_family = AF_UNSPEC */
    o[17] = D2K_NFNETLINK_V0;
    wn16(o + 18, queue);        /* res_id — в порядке сети */
    return need;
}

/* Кладёт атрибут, возвращает новую позицию или 0 при нехватке места. */
static size_t put_attr(uint8_t *o, size_t cap, size_t pos, uint16_t type,
                       const uint8_t *val, size_t vlen) {
    size_t alen = D2K_NLA_HDRLEN + vlen;
    size_t step = align4(alen);
    if (pos + step > cap) {
        return 0;
    }
    wh16(o + pos, (uint16_t)alen);
    wh16(o + pos + 2, type);
    memcpy(o + pos + D2K_NLA_HDRLEN, val, vlen);
    /* Выравнивающий хвост обнуляем: ядро его не читает, но посылать наружу
       содержимое чужой памяти нельзя. */
    if (step > alen) {
        memset(o + pos + alen, 0, step - alen);
    }
    return pos + step;
}

size_t d2k_nl_verdict(uint8_t *o, size_t cap, uint16_t queue, uint32_t seq,
                      uint32_t pkt_id, uint32_t verdict) {
    size_t pos = hdr_init(o, cap, D2K_NFQ_TYPE(D2K_NFQNL_MSG_VERDICT),
                          D2K_NLM_F_REQUEST, seq, queue);
    if (pos == 0) {
        return 0;
    }
    uint8_t vh[8];
    wn32(vh + 0, verdict);
    wn32(vh + 4, pkt_id);
    pos = put_attr(o, cap, pos, D2K_NFQA_VERDICT_HDR, vh, sizeof vh);
    if (pos == 0) {
        return 0;
    }
    wh32(o, (uint32_t)pos);
    return pos;
}

size_t d2k_nl_cfg_cmd(uint8_t *o, size_t cap, uint16_t queue, uint32_t seq,
                      uint8_t cmd, uint16_t pf) {
    /* NLM_F_ACK намеренно: без подтверждения «привязались к очереди» и «ядро
       нас отвергло» неразличимы, а различать их обязательно. */
    size_t pos = hdr_init(o, cap, D2K_NFQ_TYPE(D2K_NFQNL_MSG_CONFIG),
                          D2K_NLM_F_REQUEST | D2K_NLM_F_ACK, seq, queue);
    if (pos == 0) {
        return 0;
    }
    uint8_t c[4];
    c[0] = cmd;
    c[1] = 0;
    wn16(c + 2, pf);
    pos = put_attr(o, cap, pos, D2K_NFQA_CFG_CMD, c, sizeof c);
    if (pos == 0) {
        return 0;
    }
    wh32(o, (uint32_t)pos);
    return pos;
}

size_t d2k_nl_cfg_params(uint8_t *o, size_t cap, uint16_t queue, uint32_t seq,
                         uint32_t copy_range, uint8_t copy_mode,
                         uint32_t maxlen, uint32_t flags, uint32_t mask) {
    size_t pos = hdr_init(o, cap, D2K_NFQ_TYPE(D2K_NFQNL_MSG_CONFIG),
                          D2K_NLM_F_REQUEST | D2K_NLM_F_ACK, seq, queue);
    if (pos == 0) {
        return 0;
    }
    uint8_t params[5];
    wn32(params + 0, copy_range);
    params[4] = copy_mode;
    uint8_t u32be[4];

    pos = put_attr(o, cap, pos, D2K_NFQA_CFG_PARAMS, params, sizeof params);
    if (pos == 0) {
        return 0;
    }
    wn32(u32be, maxlen);
    pos = put_attr(o, cap, pos, D2K_NFQA_CFG_QUEUE_MAXLEN, u32be, sizeof u32be);
    if (pos == 0) {
        return 0;
    }
    wn32(u32be, flags);
    pos = put_attr(o, cap, pos, D2K_NFQA_CFG_FLAGS, u32be, sizeof u32be);
    if (pos == 0) {
        return 0;
    }
    wn32(u32be, mask);
    pos = put_attr(o, cap, pos, D2K_NFQA_CFG_MASK, u32be, sizeof u32be);
    if (pos == 0) {
        return 0;
    }
    wh32(o, (uint32_t)pos);
    return pos;
}
