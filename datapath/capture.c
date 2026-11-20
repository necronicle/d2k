#include <string.h>
#include "d2k_capture.h"

static int same(const d2k_key *a, const d2k_key *b) {
    return d2k_key_equal(a, b);
}

void d2k_capture_forget(d2k_capture *c, const d2k_key *key) {
    for (size_t i = 0; i < D2K_CAPTURE_SLOTS; i++) {
        if (c->slots[i].state && same(&c->slots[i].key, key)) {
            c->slots[i].state = 0;
        }
    }
}

static int reject(d2k_capture *c, d2k_capture_slot *s) {
    s->state = 2; /* Don't restart on a conflicting retransmitted head. */
    c->rejected++;
    return -1;
}

static int feed(d2k_capture *c, const d2k_key *key, uint64_t generation,
                     uint64_t now_ns, uint32_t seq, uint32_t anchor, int have_anchor,
                     const uint8_t *bytes,
                     size_t len, const uint8_t **hello, size_t *hello_len,
                     uint32_t *hello_seq, d2k_capture_ready ready,size_t exact) {
    *hello = NULL;
    *hello_len = 0;
    *hello_seq = 0;
    if (!len || key->proto != 6) { return 0; }
    d2k_capture_slot *s = NULL, *vacant = NULL;
    for (size_t i = 0; i < D2K_CAPTURE_SLOTS; i++) {
        d2k_capture_slot *p = &c->slots[i];
        if (p->state && (now_ns < p->started_ns ||
            now_ns - p->started_ns >= D2K_CAPTURE_TTL_NS)) {
            if (p->state == 1) { c->expired++; }
            p->state = 0;
        }
        if (p->state && same(&p->key, key)) {
            if (p->generation == generation) { s = p; }
            else { p->state = 0; }
        }
        if (!p->state && !vacant) { vacant = p; }
    }
    /* ЯКОРЬ ПРИНИМАЕТСЯ, ТОЛЬКО ЕСЛИ ОН СОГЛАСЕН С ЭТИМ КУСКОМ.
       Наблюдённый SYN и данные могут разойтись: SYN не виден, номера
       переписаны по дороге, поток начат до нас. Доверять такому якорю —
       значит класть байты по выдуманному смещению. Не согласен — работаем
       по-прежнему, от куска, начинающего запись. */
    if (have_anchor) {
        uint32_t off_from_anchor = seq - anchor;
        if ((int32_t)off_from_anchor < 0 || off_from_anchor >= D2K_CAPTURE_BYTES ||
            len > D2K_CAPTURE_BYTES - off_from_anchor) {
            if(exact)return -1;
            have_anchor = 0;
        }
    }
    if (!s) {
        /* НАЧАЛО БЕРЁТСЯ ИЗ ПОТОКА, А НЕ ИЗ СОДЕРЖИМОГО.
           Знаем начало — слот заводит любой кусок, и порядок прихода не
           значит ничего. Не знаем — прежнее правило: только тот, что начинает
           запись TLS. */
        if (!have_anchor && bytes[0] != 22) { return 0; }
        if (!vacant) { c->full++; return -2; }
        s = vacant;
        memset(s, 0, sizeof *s);
        s->key = *key;
        s->generation = generation;
        s->started_ns = now_ns;
        s->seq = have_anchor ? anchor : seq;
        s->state = 1;
        s->anchored = 1;
    }
    if (s->state != 1) { return 0; }

    /* Unsigned subtraction also handles sequence wrap. Bytes before the
     * observed head are ambiguous, not a license to move the head. */
    uint32_t delta = seq - s->seq;
    if (delta >= D2K_CAPTURE_BYTES || len > D2K_CAPTURE_BYTES - delta) {
        return reject(c, s);
    }
    size_t off = delta;
    for (size_t i = 0; i < len; i++) {
        size_t p = off + i;
        uint8_t mask = (uint8_t)(1u << (p % 8));
        if ((s->present[p / 8] & mask) && s->bytes[p] != bytes[i]) {
            return reject(c, s);
        }
        s->bytes[p] = bytes[i];
        s->present[p / 8] |= mask;
    }
    if (off + len > s->high) { s->high = off + len; }
    while (s->contiguous < D2K_CAPTURE_BYTES &&
           (s->present[s->contiguous / 8] & (1u << (s->contiguous % 8)))) {
        s->contiguous++;
    }
    size_t n = s->contiguous;
    const uint8_t *b = s->bytes;
    int status=exact?(s->high>exact?-1:n==exact):ready(b,n,s->high);
    if(status<0)return reject(c,s);
    if(!status)return 0;
    s->state = 3;
    c->completed++;
    *hello = b;
    *hello_len = n;
    *hello_seq = s->seq;
    return 1;
}
int d2k_capture_feed_ready(d2k_capture *c,const d2k_key *key,uint64_t generation,
    uint64_t now,uint32_t seq,uint32_t anchor,int have_anchor,const uint8_t *bytes,
    size_t len,const uint8_t **hello,size_t *hello_len,uint32_t *hello_seq,d2k_capture_ready ready) {
    return feed(c,key,generation,now,seq,anchor,have_anchor,bytes,len,hello,hello_len,hello_seq,ready,0);
}
int d2k_capture_feed_exact(d2k_capture *c,const d2k_key *key,uint64_t generation,
    uint64_t now,uint32_t seq,uint32_t anchor,const uint8_t *bytes,size_t len,
    const uint8_t **data,size_t *data_len,uint32_t *data_seq,size_t exact) {
    if(!exact || exact>D2K_CAPTURE_BYTES) {
        *data=NULL;*data_len=0;*data_seq=0;return -1;
    }
    return feed(c,key,generation,now,seq,anchor,1,bytes,len,data,data_len,data_seq,NULL,exact);
}

static int tls_ready(const uint8_t *b,size_t n,size_t high) {
    if ((n >= 2 && b[1] != 3) || (n >= 6 && b[5] != 1))return -1;
    if(n<5)return 0;
    size_t total=5+((size_t)b[3]<<8)+b[4];
    if(total<9 || total>D2K_CAPTURE_BYTES || high>total)return -1;
    if(n<9)return 0;
    size_t hs=((size_t)b[6]<<16)|((size_t)b[7]<<8)|b[8];
    if(hs+9!=total)return -1;
    return n==total;
}
int d2k_capture_feed(d2k_capture *c,const d2k_key *key,uint64_t generation,
    uint64_t now,uint32_t seq,uint32_t anchor,int have_anchor,const uint8_t *bytes,
    size_t len,const uint8_t **hello,size_t *hello_len,uint32_t *hello_seq) {
    return d2k_capture_feed_ready(c,key,generation,now,seq,anchor,have_anchor,
        bytes,len,hello,hello_len,hello_seq,tls_ready);
}
