/* plan_parse.c — разбор канонической формы плана.
 *
 * Главное свойство: всё, что не понято ЦЕЛИКОМ, отвергается. Неизвестный тип
 * записи, завышенная схема, завышенная версия исполнителя, ненулевые флаги,
 * несовпадение числа записей, висячая ссылка — каждая из этих причин валит
 * загрузку. План, часть которого не разобрана, — это не «план попроще», а
 * план, отличный от измеренного.
 *
 * Границы считаются ЯВНО. Здесь намеренно нет ни одного вычитания выровненной
 * длины из остатка: измеритель этапа 0 на такой арифметике дал сегфолт на
 * первом же пакете, потому что у последнего атрибута хвоста выравнивания в
 * буфере не оказалось, а счётчик размера беззнаковый.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_plan.h"
#include "plan_internal.h"

#define HEADER_LEN 12

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static void fail(char *err, size_t errlen, const char *msg) {
    if (err && errlen) {
        snprintf(err, errlen, "%s", msg);
    }
}

/* Счётчик записей каждого вида — чтобы выделить память ровно один раз, а не
 * наращивать массивы по ходу. Проход дешёвый, а realloc в датапате — лишний
 * источник ошибок. */
struct counts {
    size_t payloads, poisons, splits, fakes, seqovls;
};

static int scan(const uint8_t *b, size_t len, struct counts *c,
                uint16_t *recs_seen, char *err, size_t errlen) {
    size_t off = HEADER_LEN;
    *recs_seen = 0;
    memset(c, 0, sizeof *c);

    while (off < len) {
        if (off + 4 > len) {
            fail(err, errlen, "обрезанный заголовок записи");
            return -1;
        }
        uint16_t typ = rd16(b + off);
        size_t ln = rd16(b + off + 2);
        off += 4;
        if (ln > len || off + ln > len) {
            fail(err, errlen, "запись выходит за буфер");
            return -1;
        }

        switch (typ) {
        case REC_ID:
            if (ln != 16) { fail(err, errlen, "id не 16 байт"); return -1; }
            break;
        case REC_PROTO:
            if (ln != 2) { fail(err, errlen, "proto не 2 байта"); return -1; }
            break;
        case REC_PAYLOAD:
            if (ln < 2) { fail(err, errlen, "приманка без номера"); return -1; }
            c->payloads++;
            break;
        case REC_POISON:
            if (ln != 8) { fail(err, errlen, "порча не 8 байт"); return -1; }
            c->poisons++;
            break;
        case REC_SPLIT:
            if (ln != 4) { fail(err, errlen, "разрез не 4 байта"); return -1; }
            c->splits++;
            break;
        case REC_FAKE:
            if (ln != 10) { fail(err, errlen, "фальшивка не 10 байт"); return -1; }
            c->fakes++;
            break;
        case REC_SEQOVL:
            if (ln != 4) { fail(err, errlen, "перекрытие не 4 байта"); return -1; }
            c->seqovls++;
            break;
        case REC_ORDER:
            if (ln != 1) { fail(err, errlen, "порядок не 1 байт"); return -1; }
            break;
        case REC_GUARD:
            if (ln != 1) { fail(err, errlen, "защита не 1 байт"); return -1; }
            if (b[off] == 0 || (b[off] & ~(unsigned)D2K_GUARD_RST_ALIEN) != 0) {
                /* Пустая или незнакомая защита — отказ, а не «ничего не
                   делаем»: план, часть которого исполнитель не понял, не
                   должен исполняться вовсе (§2.5). */
                fail(err, errlen, "неизвестные биты защиты");
                return -1;
            }
            break;
        default:
            /* Незнакомое не пропускается: см. заголовок файла. */
            fail(err, errlen, "неизвестный тип записи");
            return -1;
        }

        off += ln;
        if (*recs_seen == 0xffff) {
            fail(err, errlen, "слишком много записей");
            return -1;
        }
        (*recs_seen)++;
    }
    return 0;
}

/* Ссылки обязаны разрешаться. Ноль означает «ничего» и висячей ссылкой не
 * является: фальшивка без порчи законна. */
static int check_refs(const d2k_plan *p, char *err, size_t errlen) {
    for (size_t i = 0; i < p->n_fakes; i++) {
        if (p->fakes[i].payload_id == 0 ||
            !d2k_find_payload(p, p->fakes[i].payload_id)) {
            fail(err, errlen, "фальшивка ссылается на несуществующую приманку");
            return -1;
        }
        if (p->fakes[i].poison_id != 0 &&
            !d2k_find_poison(p, p->fakes[i].poison_id)) {
            fail(err, errlen, "фальшивка ссылается на несуществующую порчу");
            return -1;
        }
    }
    for (size_t i = 0; i < p->n_seqovls; i++) {
        if (p->seqovls[i].payload_id == 0 ||
            !d2k_find_payload(p, p->seqovls[i].payload_id)) {
            fail(err, errlen, "перекрытие ссылается на несуществующую приманку");
            return -1;
        }
        if (p->seqovls[i].poison_id != 0 &&
            !d2k_find_poison(p, p->seqovls[i].poison_id)) {
            fail(err, errlen, "перекрытие ссылается на несуществующую порчу");
            return -1;
        }
    }

    /* Фальшивке «между кусками» нужны куски. План, который просит положить её
       туда, где кусков нет, невыполним — и отвергается здесь, а не
       приближается размещением «перед всеми». Приблизить неподдерживаемую
       операцию другой запрещает §2.5. */
    for (size_t i = 0; i < p->n_fakes; i++) {
        if (p->fakes[i].placement == PLACE_BETWEEN && p->n_splits == 0) {
            fail(err, errlen, "фальшивка между кусками, а разрезов нет");
            return -1;
        }
        if (p->fakes[i].placement != PLACE_BEFORE &&
            p->fakes[i].placement != PLACE_BETWEEN) {
            fail(err, errlen, "неизвестное размещение фальшивки");
            return -1;
        }
    }

    if (p->order != ORDER_FORWARD && p->order != ORDER_REVERSE) {
        fail(err, errlen, "неизвестный порядок посылки");
        return -1;
    }

    /* Перекрытие объявлено форматом, но исполнителем этой версии ещё не
       поддержано. Отказ, а не тихое игнорирование: план, часть которого не
       исполняется, — это не тот план, который измеряли. */
    if (p->n_seqovls > 0) {
        fail(err, errlen, "перекрытие этой версией исполнителя не поддержано");
        return -1;
    }
    return 0;
}

const struct d2k_payload *d2k_find_payload(const d2k_plan *p, uint16_t id) {
    for (size_t i = 0; i < p->n_payloads; i++) {
        if (p->payloads[i].id == id) {
            return &p->payloads[i];
        }
    }
    return NULL;
}

const struct d2k_poison *d2k_find_poison(const d2k_plan *p, uint16_t id) {
    for (size_t i = 0; i < p->n_poisons; i++) {
        if (p->poisons[i].id == id) {
            return &p->poisons[i];
        }
    }
    return NULL;
}

int d2k_plan_load(const uint8_t *buf, size_t len,
                  d2k_plan **out, char *err, size_t errlen) {
    if (out) {
        *out = NULL;
    }
    if (!buf || len < HEADER_LEN) {
        fail(err, errlen, "короче заголовка");
        return -1;
    }
    if (memcmp(buf, "D2KP", 4) != 0) {
        fail(err, errlen, "не план d2k");
        return -1;
    }
    uint16_t schema = rd16(buf + 4);
    uint16_t minexec = rd16(buf + 6);
    if (schema > D2K_SCHEMA_MAX) {
        fail(err, errlen, "схема новее, чем понимает эта сборка");
        return -1;
    }
    if (minexec > D2K_EXEC_VERSION) {
        fail(err, errlen, "плану нужен более новый исполнитель");
        return -1;
    }
    if (rd16(buf + 8) != 0) {
        fail(err, errlen, "ненулевые флаги заголовка");
        return -1;
    }
    uint16_t declared = rd16(buf + 10);

    struct counts c;
    uint16_t seen = 0;
    if (scan(buf, len, &c, &seen, err, errlen) != 0) {
        return -1;
    }
    if (seen != declared) {
        fail(err, errlen, "число записей не совпадает с заявленным");
        return -1;
    }

    d2k_plan *p = calloc(1, sizeof *p);
    if (!p) {
        fail(err, errlen, "нет памяти");
        return -1;
    }
    p->schema = schema;
    p->minexec = minexec;

    if (c.payloads) { p->payloads = calloc(c.payloads, sizeof *p->payloads); }
    if (c.poisons)  { p->poisons  = calloc(c.poisons,  sizeof *p->poisons);  }
    if (c.splits)   { p->splits   = calloc(c.splits,   sizeof *p->splits);   }
    if (c.fakes)    { p->fakes    = calloc(c.fakes,    sizeof *p->fakes);    }
    if (c.seqovls)  { p->seqovls  = calloc(c.seqovls,  sizeof *p->seqovls);  }
    if ((c.payloads && !p->payloads) || (c.poisons && !p->poisons) ||
        (c.splits && !p->splits) || (c.fakes && !p->fakes) ||
        (c.seqovls && !p->seqovls)) {
        d2k_plan_free(p);
        fail(err, errlen, "нет памяти");
        return -1;
    }

    size_t off = HEADER_LEN;
    while (off < len) {
        uint16_t typ = rd16(buf + off);
        size_t ln = rd16(buf + off + 2);
        const uint8_t *v = buf + off + 4;
        off += 4 + ln;

        switch (typ) {
        case REC_ID:
            memcpy(p->id, v, 16);
            break;
        case REC_PROTO:
            p->transport = v[0];
            p->proto = v[1];
            break;
        case REC_PAYLOAD: {
            struct d2k_payload *pl = &p->payloads[p->n_payloads++];
            pl->id = rd16(v);
            pl->len = ln - 2;
            if (pl->len) {
                pl->bytes = malloc(pl->len);
                if (!pl->bytes) {
                    d2k_plan_free(p);
                    fail(err, errlen, "нет памяти под приманку");
                    return -1;
                }
                memcpy(pl->bytes, v + 2, pl->len);
            }
            break;
        }
        case REC_POISON: {
            struct d2k_poison *po = &p->poisons[p->n_poisons++];
            po->id = rd16(v);
            po->ttl = v[2];
            po->flags = v[3];
            po->seq_shift = (int32_t)rd32(v + 4);
            break;
        }
        case REC_SPLIT: {
            struct d2k_split *s = &p->splits[p->n_splits++];
            s->anchor = rd16(v);
            s->offset = (int16_t)rd16(v + 2);
            break;
        }
        case REC_FAKE: {
            struct d2k_fake *f = &p->fakes[p->n_fakes++];
            f->payload_id = rd16(v);
            f->poison_id = rd16(v + 2);
            f->repeats = v[4];
            f->placement = v[5];
            f->gap_us = rd32(v + 6);
            break;
        }
        case REC_SEQOVL: {
            struct d2k_seqovl *s = &p->seqovls[p->n_seqovls++];
            s->payload_id = rd16(v);
            s->poison_id = rd16(v + 2);
            break;
        }
        case REC_ORDER:
            p->order = v[0];
            break;
        case REC_GUARD:
            p->guards = v[0];
            break;
        default:
            /* Недостижимо: scan уже отверг бы такой план. Ветка оставлена,
               чтобы добавление кода записи без обновления scan не проходило
               молча. */
            d2k_plan_free(p);
            fail(err, errlen, "неизвестный тип записи");
            return -1;
        }
    }

    if (check_refs(p, err, errlen) != 0) {
        d2k_plan_free(p);
        return -1;
    }

    *out = p;
    return 0;
}

void d2k_plan_free(d2k_plan *p) {
    if (!p) {
        return;
    }
    for (size_t i = 0; i < p->n_payloads; i++) {
        free(p->payloads[i].bytes);
    }
    free(p->payloads);
    free(p->poisons);
    free(p->splits);
    free(p->fakes);
    free(p->seqovls);
    free(p);
}

uint8_t d2k_plan_poison_used(const d2k_plan *p) {
    if (!p) {
        return 0;
    }
    uint8_t used = 0;
    for (size_t i = 0; i < p->n_poisons; i++) {
        used |= p->poisons[i].flags;
    }
    return used;
}

uint8_t d2k_plan_guards(const d2k_plan *p) {
    return p ? p->guards : 0;
}
