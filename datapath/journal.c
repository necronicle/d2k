/* journal.c — кольцо наблюдений. Ни одного выделения памяти после создания. */
#include <stdlib.h>
#include <string.h>

#include "d2k_journal.h"

struct d2k_journal {
    d2k_jrn_entry *v;
    size_t         cap;
    size_t         n;      /* сколько занято, пока кольцо не заполнилось */
    size_t         head;   /* куда писать следующую */
    uint64_t       dropped;
    uint64_t       added;
};

d2k_journal *d2k_journal_new(size_t cap) {
    d2k_journal *j = calloc(1, sizeof *j);
    if (!j) {
        return NULL;
    }
    if (cap == 0) {
        return j;           /* журнал, который ничего не хранит */
    }
    j->v = calloc(cap, sizeof *j->v);
    if (!j->v) {
        free(j);
        return NULL;
    }
    j->cap = cap;
    return j;
}

void d2k_journal_free(d2k_journal *j) {
    if (!j) {
        return;
    }
    free(j->v);
    free(j);
}

const char *d2k_suspect_text(uint8_t code) {
    switch (code) {
    case D2K_SUSPECT_RST:     return "сброс в ответ на приветствие";
    case D2K_SUSPECT_REPEAT:  return "приветствие повторено";
    case D2K_SUSPECT_SILENT:  return "ответа на приветствие не было";
    case D2K_SUSPECT_RST_CUT: return "снят чужой сброс в ответ на приветствие";
    default:                  return "подозрение без кода";
    }
}

void d2k_journal_add(d2k_journal *j, uint64_t at_ns, const d2k_key *key,
                     uint8_t kind, uint8_t code, uint32_t num,
                     const d2k_jrn_detail *det,
                     const uint8_t *name, size_t name_len, const char *note) {
    if (!j) {
        return;
    }
    j->added++;
    if (j->cap == 0) {
        return;
    }
    if (j->n == j->cap) {
        j->dropped++;
    }

    d2k_jrn_entry *e = &j->v[j->head];
    memset(e, 0, sizeof *e);
    e->at_ns = at_ns;
    if (key) {
        e->key = *key;
    }
    e->kind = kind;
    e->code = code;
    e->num = num;
    if (det) {
        e->d_ttl = det->ttl;
        e->d_ref_ttl = det->ref_ttl;
        e->d_tos = det->tos;
        e->d_ipid = det->ipid;
    }
    e->note = note ? note : (kind == D2K_JRN_SUSPECT ? d2k_suspect_text(code) : NULL);

    if (name && name_len) {
        size_t take = name_len > D2K_JRN_NAME_MAX ? D2K_JRN_NAME_MAX : name_len;
        /* Имя приходит из сети. В журнал оно попадает как есть, но байты, на
           которых печать сломалась бы, заменяются точкой: журнал печатается в
           терминал и в панель, и управляющие символы оттуда не должны
           доезжать. Экранирование для HTML — дело панели, а не датапата. */
        for (size_t i = 0; i < take; i++) {
            uint8_t c = name[i];
            e->name[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
        e->name[take] = '\0';
        e->name_len = (uint8_t)take;
    }

    j->head = (j->head + 1) % j->cap;
    if (j->n < j->cap) {
        j->n++;
    }
}

size_t d2k_journal_count(const d2k_journal *j) {
    return j ? j->n : 0;
}

const d2k_jrn_entry *d2k_journal_at(const d2k_journal *j, size_t i) {
    if (!j || i >= j->n) {
        return NULL;
    }
    /* От старой к новой. Пока кольцо не заполнилось, старая лежит в нуле;
       после — сразу за головой. */
    size_t start = (j->n == j->cap) ? j->head : 0;
    return &j->v[(start + i) % j->cap];
}

uint64_t d2k_journal_dropped(const d2k_journal *j) {
    return j ? j->dropped : 0;
}

uint64_t d2k_journal_added(const d2k_journal *j) {
    return j ? j->added : 0;
}
