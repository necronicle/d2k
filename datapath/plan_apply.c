/* plan_apply.c — превращение плана в список посылок для одного пакета.
 *
 * Договорённость о выводе, из которой следует всё остальное: список содержит
 * ТОЛЬКО то, что порождаем мы. Судьба оригинала — отдельное поле, а не ещё
 * одна строка в списке. Иначе «пропустить оригинал» и «выпустить его копию»
 * стали бы неразличимы, и пакет ушёл бы дважды.
 *
 * Отсюда правило: если план выпускает нагрузку сам (есть разрезы или
 * перекрытие), оригинал снимается. Если план только добавляет фальшивку —
 * оригинал пропускается, а наши посылки идут перед ним.
 *
 * Плавающей арифметики здесь нет: MIPS-коробки без сопроцессора, и каждая
 * операция с double там становится вызовом libgcc.
 */
#include <stdlib.h>
#include <string.h>

#include "d2k_plan.h"
#include "plan_internal.h"

/* Разрешение якоря. Невычислимый якорь — ОТКАЗ, а не нулевое смещение:
 * молчаливый ноль исполнил бы не тот план, который измеряли. */
static int anchor_offset(const d2k_pkt *in, uint16_t anchor, size_t *out) {
    switch (anchor) {
    case ANCHOR_PAYLOAD_START:
        *out = 0;
        return 0;
    case ANCHOR_SNI_START:
        if (!in->have_sni) {
            return -1;
        }
        *out = in->sni_off;
        return 0;
    case ANCHOR_SNI_END:
        if (!in->have_sni) {
            return -1;
        }
        *out = in->sni_off + in->sni_len;
        return 0;
    case ANCHOR_HELLO_MIDDLE:
        *out = in->payload_len / 2;
        return 0;
    case ANCHOR_RECORD_END:
        /* Границу записи TLS обязан передать протокольный модуль. Пока он не
           написан, честный ответ — отказ, а не догадка о длине. */
        return -1;
    default:
        return -1;
    }
}

static int cmp_size(const void *a, const void *b) {
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* Позиции разрезов: якорь плюс смещение, отсортированы по возрастанию и
 * очищены от повторов и краёв. Порядок именно возрастающий, а не порядок
 * записей: иначе перестановка записей в плане меняла бы куски. */
static int split_points(const d2k_plan *p, const d2k_pkt *in,
                        size_t *pts, size_t *n_out) {
    size_t n = 0;
    for (size_t i = 0; i < p->n_splits; i++) {
        size_t base;
        if (anchor_offset(in, p->splits[i].anchor, &base) != 0) {
            return -1;
        }
        long v = (long)base + p->splits[i].offset;
        if (v <= 0 || (size_t)v >= in->payload_len) {
            /* Разрез вне нагрузки не режет ничего. Это не отказ: якорь
               вычислился, просто пакет короче. */
            continue;
        }
        pts[n++] = (size_t)v;
    }
    if (n > 1) {
        qsort(pts, n, sizeof *pts, cmp_size);
        size_t w = 1;
        for (size_t i = 1; i < n; i++) {
            if (pts[i] != pts[w - 1]) {
                pts[w++] = pts[i];
            }
        }
        n = w;
    }
    *n_out = n;
    return 0;
}

static void emit_fake(d2k_emit *e, const d2k_plan *p, const struct d2k_fake *f,
                      uint32_t seq, uint32_t delay) {
    const struct d2k_payload *pl = d2k_find_payload(p, f->payload_id);
    const struct d2k_poison *po = f->poison_id ? d2k_find_poison(p, f->poison_id) : NULL;
    memset(e, 0, sizeof *e);
    e->kind = D2K_EMIT_FAKE;
    e->delay_us = delay;
    e->seq = seq;
    e->bytes = pl->bytes;
    e->len = pl->len;
    if (po) {
        e->ttl = po->ttl;
        e->poison = po->flags;
        e->seq_shift = po->seq_shift;
    }
}

int d2k_plan_apply(const d2k_plan *p, const d2k_flow *f,
                   const d2k_pkt *in, d2k_actions *out) {
    (void)f;
    if (!p || !in || !out) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (!in->payload || in->payload_len == 0) {
        return -1;
    }

    size_t *pts = NULL;
    size_t n_pts = 0;
    if (p->n_splits) {
        pts = calloc(p->n_splits, sizeof *pts);
        if (!pts) {
            return -1;
        }
        if (split_points(p, in, pts, &n_pts) != 0) {
            free(pts);
            return -1; /* невычислимый якорь */
        }
    }

    int owns_payload = (n_pts > 0) || (p->n_seqovls > 0);

    /* Верхняя оценка числа посылок: копии фальшивок плюс куски. Считаем
       заранее, чтобы выделить память один раз. */
    size_t max_emits = 0;
    for (size_t i = 0; i < p->n_fakes; i++) {
        uint8_t r = p->fakes[i].repeats;
        max_emits += (r == 0 ? 1 : r);
    }
    if (owns_payload) {
        max_emits += n_pts + 1;
    }
    if (max_emits == 0) {
        free(pts);
        out->fate = D2K_ORIG_PASS;
        return 0;
    }

    d2k_emit *v = calloc(max_emits, sizeof *v);
    if (!v) {
        free(pts);
        return -1;
    }
    size_t n = 0;

    /* Фальшивки, стоящие перед всеми кусками. */
    for (size_t i = 0; i < p->n_fakes; i++) {
        if (p->fakes[i].placement != PLACE_BEFORE) {
            continue;
        }
        uint8_t reps = p->fakes[i].repeats ? p->fakes[i].repeats : 1;
        for (uint8_t r = 0; r < reps; r++) {
            emit_fake(&v[n++], p, &p->fakes[i], in->seq,
                      r == 0 ? 0 : p->fakes[i].gap_us);
        }
    }

    if (owns_payload) {
        /* Куски нагрузки. Перекрытие первой версии не реализовано в этой
           задаче — оно приходит следующей, и до тех пор план с ним
           отвергается при загрузке. */
        size_t start = 0;
        for (size_t i = 0; i <= n_pts; i++) {
            size_t end = (i < n_pts) ? pts[i] : in->payload_len;
            d2k_emit *e = &v[n++];
            memset(e, 0, sizeof *e);
            e->kind = D2K_EMIT_PAYLOAD;
            e->delay_us = 0;
            e->seq = in->seq + (uint32_t)start;
            e->bytes = in->payload + start;
            e->len = end - start;
            start = end;

            /* Фальшивка между кусками — после каждого, кроме последнего. */
            if (i < n_pts) {
                for (size_t k = 0; k < p->n_fakes; k++) {
                    if (p->fakes[k].placement != PLACE_BETWEEN) {
                        continue;
                    }
                    uint8_t reps = p->fakes[k].repeats ? p->fakes[k].repeats : 1;
                    for (uint8_t r = 0; r < reps; r++) {
                        emit_fake(&v[n++], p, &p->fakes[k], in->seq + (uint32_t)start,
                                  r == 0 ? 0 : p->fakes[k].gap_us);
                    }
                }
            }
        }

        if (p->order == ORDER_REVERSE) {
            /* Переворачиваем только куски нагрузки, не фальшивки: смысл
               обратного порядка в том, что хвост приветствия уходит раньше
               головы, а фальшивка обязана остаться там, куда её поставили. */
            size_t lo = 0, hi = n;
            while (lo < hi && v[lo].bytes < in->payload) {
                lo++;
            }
            while (hi > lo && v[hi - 1].bytes < in->payload) {
                hi--;
            }
            for (size_t i = lo, j = hi; i < j - 1; i++, j--) {
                d2k_emit t = v[i];
                v[i] = v[j - 1];
                v[j - 1] = t;
            }
        }
    }

    free(pts);
    out->v = v;
    out->n = n;
    out->fate = owns_payload ? D2K_ORIG_DROP : D2K_ORIG_PASS;
    return 0;
}

/* Отмена исполнения на середине.
 *
 * Три правила, и все три следуют из одного: коробка уже увидела часть того,
 * что мы собирались показать, и вернуть это назад нельзя.
 *
 * 1. Пока нагрузку не трогали — оригинал отпускается. Он цел, и потерять его
 *    значило бы оборвать соединение человеку из-за нашей внутренней причины.
 * 2. Как только ушёл хоть один кусок нагрузки — чистого выхода нет. Отпустить
 *    оригинал значит послать те же байты дважды, не отпустить — потерять
 *    остаток. Поток испорчен, и исполнитель сообщает об этом фактом, а не
 *    выбирает меньшее зло сам: что делать с испорченным потоком — политика
 *    контроллера.
 * 3. Любая незавершённая отправка делает исполнение неполным. По нему нельзя
 *    записывать ни успех, ни неудачу: коробка видела не тот набор пакетов,
 *    который описывает план, а §2.3 запрещает сохранять неподтверждённое.
 */
void d2k_actions_cancel(const d2k_actions *a, size_t emitted, d2k_cancel *out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof *out);
    if (!a) {
        out->fate = D2K_ORIG_PASS;
        return;
    }
    if (emitted > a->n) {
        emitted = a->n;
    }

    int payload_out = 0;
    for (size_t i = 0; i < emitted; i++) {
        if (a->v[i].kind == D2K_EMIT_PAYLOAD) {
            payload_out = 1;
            break;
        }
    }

    out->partial = (emitted < a->n) ? 1 : 0;
    out->stream_damaged = (payload_out && emitted < a->n) ? 1 : 0;

    if (payload_out) {
        /* Байты нагрузки уже на проводе: повторять их нельзя. */
        out->fate = D2K_ORIG_DROP;
    } else {
        out->fate = D2K_ORIG_PASS;
    }
}

void d2k_actions_free(d2k_actions *a) {
    if (!a) {
        return;
    }
    free(a->v);
    a->v = NULL;
    a->n = 0;
}
