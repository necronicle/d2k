/* sched.c — очередь отложенной отправки, двоичная куча по (срок, номер).
 *
 * Куча, а не линейный поиск, чтобы предел числа слотов можно было поднять, не
 * оглядываясь на цену обхода. Слоты и позиции в куче разведены: в куче лежат
 * записи с индексом слота, сами байты не двигаются.
 */
#include <stdlib.h>
#include <string.h>

#include "d2k_sched.h"

typedef struct {
    uint64_t due_ns;
    uint64_t seq;      /* номер постановки — устойчивость при равных сроках */
    size_t   slot;
    size_t   len;
} entry;

struct d2k_sched {
    size_t   cap;
    size_t   slot_size;
    uint8_t *mem;

    entry   *heap;
    size_t   n;

    size_t  *freelist;
    size_t   nfree;

    uint64_t next_seq;
    uint64_t refusals;
};

d2k_sched *d2k_sched_new(size_t slots, size_t slot_size) {
    if (slots == 0 || slot_size == 0) {
        return NULL;
    }
    /* Защита от переполнения при умножении: на 32-битной арке slots*slot_size
       способно завернуться, и тогда calloc выделит меньше, чем мы будем
       писать. */
    if (slots > (size_t)-1 / slot_size) {
        return NULL;
    }
    d2k_sched *s = calloc(1, sizeof *s);
    if (!s) {
        return NULL;
    }
    s->cap = slots;
    s->slot_size = slot_size;
    s->mem = calloc(slots, slot_size);
    s->heap = calloc(slots, sizeof *s->heap);
    s->freelist = calloc(slots, sizeof *s->freelist);
    if (!s->mem || !s->heap || !s->freelist) {
        d2k_sched_free(s);
        return NULL;
    }
    for (size_t i = 0; i < slots; i++) {
        s->freelist[i] = slots - 1 - i;   /* сверху стека — слот 0 */
    }
    s->nfree = slots;
    return s;
}

void d2k_sched_free(d2k_sched *s) {
    if (!s) {
        return;
    }
    free(s->mem);
    free(s->heap);
    free(s->freelist);
    free(s);
}

/* Раньше — тот, у кого меньше срок; при равных сроках — тот, кого поставили
   раньше. Возвращает 1, если a должен уйти раньше b. */
static int earlier(const entry *a, const entry *b) {
    if (a->due_ns != b->due_ns) {
        return a->due_ns < b->due_ns;
    }
    return a->seq < b->seq;
}

static void sift_up(d2k_sched *s, size_t i) {
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (!earlier(&s->heap[i], &s->heap[parent])) {
            break;
        }
        entry t = s->heap[i];
        s->heap[i] = s->heap[parent];
        s->heap[parent] = t;
        i = parent;
    }
}

static void sift_down(d2k_sched *s, size_t i) {
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, best = i;
        if (l < s->n && earlier(&s->heap[l], &s->heap[best])) {
            best = l;
        }
        if (r < s->n && earlier(&s->heap[r], &s->heap[best])) {
            best = r;
        }
        if (best == i) {
            return;
        }
        entry t = s->heap[i];
        s->heap[i] = s->heap[best];
        s->heap[best] = t;
        i = best;
    }
}

int d2k_sched_push(d2k_sched *s, uint64_t due_ns, const uint8_t *data, size_t len) {
    if (!s || !data || len == 0) {
        return -2;
    }
    if (len > s->slot_size) {
        s->refusals++;
        return -2;
    }
    if (s->n >= s->cap || s->nfree == 0) {
        s->refusals++;
        return -1;
    }
    size_t slot = s->freelist[--s->nfree];
    memcpy(s->mem + slot * s->slot_size, data, len);

    s->heap[s->n].due_ns = due_ns;
    s->heap[s->n].seq = s->next_seq++;
    s->heap[s->n].slot = slot;
    s->heap[s->n].len = len;
    s->n++;
    sift_up(s, s->n - 1);
    return 0;
}

int d2k_sched_pop_due(d2k_sched *s, uint64_t now_ns,
                      uint8_t *out, size_t outcap, size_t *len) {
    if (!s || s->n == 0 || !out) {
        return 0;
    }
    if (s->heap[0].due_ns > now_ns) {
        return 0;
    }
    if (s->heap[0].len > outcap) {
        /* Буфер вызывающего мал. Пакет остаётся в очереди: выбросить его
           молча значит исполнить половину плана и не узнать об этом. */
        return 0;
    }
    memcpy(out, s->mem + s->heap[0].slot * s->slot_size, s->heap[0].len);
    if (len) {
        *len = s->heap[0].len;
    }
    s->freelist[s->nfree++] = s->heap[0].slot;

    s->n--;
    if (s->n > 0) {
        s->heap[0] = s->heap[s->n];
        sift_down(s, 0);
    }
    return 1;
}

uint64_t d2k_sched_next_ns(const d2k_sched *s) {
    return (s && s->n > 0) ? s->heap[0].due_ns : 0;
}

size_t d2k_sched_count(const d2k_sched *s) {
    return s ? s->n : 0;
}

uint64_t d2k_sched_refusals(const d2k_sched *s) {
    return s ? s->refusals : 0;
}
