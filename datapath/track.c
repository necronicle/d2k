/* track.c — таблица потоков с открытой адресацией.
 *
 * Открытая адресация, а не списки: списки требуют выделения на каждый новый
 * поток, а на пакетном пути выделений быть не должно. Вся память берётся один
 * раз при создании таблицы.
 *
 * Удаление — СДВИГОМ НАЗАД, без надгробий. Надгробия здесь были и оказались
 * ловушкой: они занимают место наравне с живыми записями, поэтому истечение
 * освобождало счётчик, но не освобождало таблицу, и она продолжала отказывать
 * после чистки. Чинить это подкруткой порога значило бы лечить следствие;
 * сдвиг назад сохраняет цепочку пробирования и не оставляет мусора вовсе.
 */
#include <stdlib.h>
#include <string.h>

#include "d2k_track.h"

int d2k_key_make(d2k_key *k, uint8_t proto, const uint8_t *src_ip4, const uint8_t *dst_ip4,
                 const uint8_t *src_port_be, const uint8_t *dst_port_be) {
    if (!k) {
        return 0;
    }
    /* Сравниваем шесть байт «адрес+порт» как они лежат в заголовке. Сравнение
       байтов одинаково на любой арке; сравнение чисел зависело бы от порядка
       байт хозяина, и на big-endian mips канон получился бы другим. Транспорт
       в этом сравнении не участвует: порядок low/high — свойство пары
       адрес+порт, а не транспорта. */
    uint8_t a[6], b[6];
    memcpy(a, src_ip4, 4);
    memcpy(a + 4, src_port_be, 2);
    memcpy(b, dst_ip4, 4);
    memcpy(b + 4, dst_port_be, 2);

    int src_is_low = memcmp(a, b, 6) <= 0;
    const uint8_t *lo = src_is_low ? a : b;
    const uint8_t *hi = src_is_low ? b : a;

    /* memset зануляет ВЕСЬ экземпляр, включая байты выравнивания за proto —
       см. большой комментарий у d2k_key в d2k_track.h про то, почему на эти
       байты в принципе нельзя полагаться где-либо ЕЩЁ, кроме этого зануления
       здесь: правильность key_eq/key_hash в track.c (сравнение и хеш по
       sizeof *k целиком) держится именно на том, что ключ ВСЕГДА собран
       через эту функцию, а не составлен по частям где-то ещё. */
    memset(k, 0, sizeof *k);
    memcpy(&k->low_ip, lo, 4);
    memcpy(&k->low_port, lo + 4, 2);
    memcpy(&k->high_ip, hi, 4);
    memcpy(&k->high_port, hi + 4, 2);
    k->proto = proto;
    return src_is_low;
}

enum { SLOT_FREE = 0, SLOT_USED = 1 };

struct d2k_table {
    d2k_flow *slots;
    uint8_t  *state;
    size_t    cap;  /* степень двойки */
    size_t    used;
    uint64_t  refusals;
};

static size_t round_pow2(size_t n) {
    size_t p = 16;
    while (p < n) {
        p <<= 1;
    }
    return p;
}

static int key_eq(const d2k_key *a, const d2k_key *b) {
    /* Побайтово, а не полями: сравнение полями пришлось бы отдельно править
       при каждом изменении структуры, а этому — нет. Дырки выравнивания в
       d2k_key ЕСТЬ (5 полей, 4+4+2+2+1 = 13 значащих байт при sizeof 16, см.
       большой комментарий у d2k_key в d2k_track.h) — правильность memcmp тут
       держится не на их отсутствии, а на том, что d2k_key_make ВСЕГДА
       зануляет их через memset ПЕРЕД заполнением полей, и других путей
       построить d2k_key в этом датапате нет. Раньше, при четырёх полях без
       дыры, эти два довода совпадали и было легко перепутать один с другим —
       после добавления proto они разошлись, и неверный (уже не действующий)
       остался бы в комментарии, если бы отсюда не убрать. */
    return memcmp(a, b, sizeof *a) == 0;
}

/* FNV-1a по байтам ключа. Ключ читается как байты, а не как числа: порядок
 * байт для хеша безразличен, а перекладывание уже стоило одной ошибки. */
static size_t key_hash(const d2k_key *k) {
    const uint8_t *b = (const uint8_t *)k;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < sizeof *k; i++) {
        h = (h ^ b[i]) * 16777619u;
    }
    return h;
}

d2k_table *d2k_track_new(size_t capacity) {
    if (capacity == 0) {
        return NULL;
    }
    d2k_table *t = calloc(1, sizeof *t);
    if (!t) {
        return NULL;
    }
    t->cap = round_pow2(capacity);
    t->slots = calloc(t->cap, sizeof *t->slots);
    t->state = calloc(t->cap, sizeof *t->state);
    if (!t->slots || !t->state) {
        d2k_track_free(t);
        return NULL;
    }
    return t;
}

void d2k_track_free(d2k_table *t) {
    if (!t) {
        return;
    }
    free(t->slots);
    free(t->state);
    free(t);
}

d2k_flow *d2k_track_find(d2k_table *t, const d2k_key *k) {
    if (!t || !k) {
        return NULL;
    }
    size_t mask = t->cap - 1;
    size_t i = key_hash(k) & mask;
    for (size_t probe = 0; probe < t->cap; probe++) {
        size_t s = (i + probe) & mask;
        if (t->state[s] == SLOT_FREE) {
            return NULL; /* свободная ячейка обрывает цепочку */
        }
        if (key_eq(&t->slots[s].key, k)) {
            return &t->slots[s];
        }
    }
    return NULL;
}

/* Удаление сдвигом назад: сдвигаем те записи кластера, которые после освобождения
 * ячейки перестали бы находиться. Инвариант линейного пробирования при этом
 * сохраняется без надгробий. */
static void remove_at(d2k_table *t, size_t hole) {
    size_t mask = t->cap - 1;
    t->state[hole] = SLOT_FREE;
    t->slots[hole].in_use = 0;
    t->used--;

    size_t j = hole;
    for (;;) {
        j = (j + 1) & mask;
        if (t->state[j] == SLOT_FREE) {
            return;
        }
        size_t home = key_hash(&t->slots[j].key) & mask;
        /* Запись можно двигать, если её «дом» не лежит внутри отрезка
           (hole, j] по кольцу — иначе она встанет раньше своего дома и
           потеряется. */
        int movable = (hole <= j) ? (home <= hole || home > j)
                                  : (home <= hole && home > j);
        if (movable) {
            t->slots[hole] = t->slots[j];
            t->state[hole] = SLOT_USED;
            t->state[j] = SLOT_FREE;
            t->slots[j].in_use = 0;
            hole = j;
        }
    }
}

d2k_flow *d2k_track_get(d2k_table *t, const d2k_key *k, uint64_t now_ns) {
    if (!t || !k) {
        return NULL;
    }
    size_t mask = t->cap - 1;
    size_t i = key_hash(k) & mask;

    for (size_t probe = 0; probe < t->cap; probe++) {
        size_t s = (i + probe) & mask;
        if (t->state[s] == SLOT_USED) {
            if (key_eq(&t->slots[s].key, k)) {
                t->slots[s].last_ns = now_ns;
                return &t->slots[s];
            }
            continue;
        }
        /* Свободная ячейка: этого ключа в таблице нет.
           Порог заполнения считается по ЖИВЫМ записям — надгробий больше нет,
           и мёртвый вес места не занимает. При плотности выше трёх четвертей
           линейное пробирование вырождается в перебор всей таблицы, поэтому
           отказ честнее незаметной деградации. */
        if (t->used + 1 > t->cap - t->cap / 4) {
            t->refusals++;
            return NULL;
        }
        t->state[s] = SLOT_USED;
        t->used++;
        memset(&t->slots[s], 0, sizeof t->slots[s]);
        t->slots[s].key = *k;
        t->slots[s].in_use = 1;
        t->slots[s].first_ns = now_ns;
        t->slots[s].last_ns = now_ns;
        return &t->slots[s];
    }
    t->refusals++;
    return NULL;
}

void d2k_track_remove(d2k_table *t, const d2k_key *k) {
    if (!t || !k) {
        return;
    }
    d2k_flow *f = d2k_track_find(t, k);
    if (f) {
        remove_at(t, (size_t)(f - t->slots));
    }
}

void d2k_track_walk(d2k_table *t, void (*fn)(void *ctx, d2k_flow *f), void *ctx) {
    if (!t || !fn) {
        return;
    }
    for (size_t s = 0; s < t->cap; s++) {
        if (t->state[s] == SLOT_USED) {
            fn(ctx, &t->slots[s]);
        }
    }
}

size_t d2k_track_expire(d2k_table *t, uint64_t now_ns, uint64_t idle_ns,
                        void (*on_expire)(void *ctx, const d2k_flow *f),
                        void *ctx) {
    if (!t) {
        return 0;
    }
    size_t freed = 0;
    /* Идём по всей таблице, но remove_at двигает записи назад, поэтому после
       удаления ячейку надо перепроверить: на её место могла приехать другая. */
    for (size_t s = 0; s < t->cap; s++) {
        /* Сравнение до вычитания, и это не перестраховка: вычитание
           беззнаковое, и при времени, ушедшем назад, разность становится
           огромной — истечение молча снесло бы ВСЮ таблицу. Часы обязаны быть
           монотонными, но обязанность и гарантия — разные вещи. */
        while (t->state[s] == SLOT_USED &&
               now_ns >= t->slots[s].last_ns &&
               now_ns - t->slots[s].last_ns >= idle_ns) {
            if (on_expire) {
                /* До освобождения: это единственный момент, когда поток виден
                   целиком. «Приветствие было, ответа не пришло» становится
                   известно только здесь. */
                on_expire(ctx, &t->slots[s]);
            }
            remove_at(t, s);
            freed++;
        }
    }
    return freed;
}

size_t d2k_track_count(const d2k_table *t) {
    return t ? t->used : 0;
}

size_t d2k_track_capacity(const d2k_table *t) {
    return t ? t->cap : 0;
}

uint64_t d2k_track_refusals(const d2k_table *t) {
    return t ? t->refusals : 0;
}
