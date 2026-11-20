#include "d2k_crypto.h"
/* plans.c — таблица планов по целям. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "d2k_plans.h"
#include "plan_internal.h"

enum { KEY_FREE = 0, KEY_NAME = 1, KEY_ADDR = 2, KEY_ENDPOINT = 3, KEY_ENDPOINT_TRIAL = 4 };

typedef struct {
    uint8_t  kind;
    uint8_t  family;
    uint8_t  name_len;
    uint8_t  name[D2K_TARGET_NAME_MAX];
    uint8_t addr[16];
    /* Давность последнего обращения — единственное, что нужно вытеснению по
       LRU. Не индекс и не список: список давности стоил бы указателей на
       каждую запись ради таблицы, которую и так обходят целиком раз на
       установку плана (см. d2k_plans.h). */
    uint64_t last_used_ns;
    /* ФОРМА ПРИВЕТСТВИЯ, на которой план подтверждён (D2K_PLAN_SHAPE_*).
       0 — не объявлена: старая запись, совместимая с любой формой. Ненулевая
       означает, что к приветствию ДРУГОЙ формы этот план не применяется:
       успех собственного зонда на TLS 1.3 ничего не говорит про браузер с
       TLS 1.2 (docs/decisions/0009 U5). */
    uint8_t  shape;
    /* Местный порт потока, которому одному эта запись и предназначена
       (сетевой порядок). Ноль — «любому»: так стоят подтверждённые планы.
       Ненулевой ставит только испытание кандидата (см.
       d2k_plantab_set_name_probe в d2k_plans.h). */
    uint16_t only_sport;
    uint16_t endpoint_port; /* KEY_ENDPOINT: exact server port, network order. */
    uint16_t dns_length;    /* DNS endpoint: measured request length including TCP prefix. */
    d2k_plan *plan;
} entry;

typedef struct {
    uint8_t used;
    d2k_addr_probe_flow flow;
    uint8_t trial_id[D2K_TRIAL_ID_LEN];
    uint64_t expires_ns;
    d2k_plan *plan;
    struct d2k_rawmeasure_report *raw_guard;
    uint8_t raw_plan_digest[32];
    uint16_t dns_length;
    uint8_t dns_digest[32];
} probe_entry;

typedef struct {
    uint8_t name[D2K_TARGET_NAME_MAX];
    uint8_t len, transport, shape, family;
    d2k_plan *plan;
} area_entry;

/* ИНВАРИАНТ УПЛОТНЕНИЯ, общий для всего файла: занятые записи всегда лежат
 * ПОДРЯД в v[0..used), свободные — в v[used..cap). Читают его find_name,
 * find_addr и oldest; держат — drop и take_free_or_evict, единственные, кто
 * меняет used. По отдельности эти пять функций не трогать: инвариант общий,
 * а не свойство какой-то одной из них.
 *
 * Из него прямо следует то, что требовал замер (см. d2k_plans.h): поиск —
 * и на пакетном пути, и при вытеснении — идёт не больше used шагов, СОВСЕМ
 * не заглядывая в v[used..cap). До уплотнения find_name/find_addr шли до
 * cap, пропуская свободные слоты проверкой kind, и цена промаха росла вместе
 * с cap, а не с used (см. d2k_plans.h про то, во сколько это обошлось после
 * роста вместимости 256->2048).
 *
 * Поддержание инварианта:
 *  - вставка новой цели (take_free_or_evict) добавляет запись РОВНО в
 *    v[used] — свободные слоты никогда не ищутся, следующий всегда там же;
 *  - вытеснение освобождает НЕ обязательно последний слот, поэтому перед
 *    уменьшением used последняя занятая запись переносится на место
 *    вытесненной (та же техника, что и в drop ниже) — дыра посреди
 *    v[0..used) невозможна;
 *  - удаление (drop) освобождает произвольный слот той же техникой: перенос
 *    последней занятой на его место, затем used--.
 * Ни один перенос не идёт через memcpy структуры поверх чужого буфера — это
 * присваивание entry в entry, тот же типизированный объект с обеих сторон, а
 * не наложение структуры на чужую память (см. d2k_track.h про то, где такое
 * наложение запрещено и почему). */
struct d2k_plantab {
    uint64_t revision;
    uint64_t next_binding;
    uint8_t epoch[16];
    /* Сколько раз запись НАШЛАСЬ, но не подошла по форме приветствия. */
    size_t   shape_misses;
    entry *v;
    size_t cap;
    size_t used;
    probe_entry *probes;
    size_t probe_used;
    area_entry suffixes[D2K_PLAN_SUFFIX_MAX];
    area_entry bypasses[D2K_PLAN_BYPASS_MAX];
    size_t suffix_used, bypass_used;
};

/* One counter per table; its random epoch namespaces it across restarts.
 * Exhaustion leaves identity unknown rather than reusing an old generation. */
static void bind_context(d2k_plantab *t, d2k_plan *p, uint8_t kind,
                         uint8_t family, uint8_t shape, int temporary) {
    if (!p) return;
    p->binding_owner = t;
    p->binding_generation = t->next_binding == UINT64_MAX ? 0 : ++t->next_binding;
    p->binding_kind = kind; p->binding_family = family;
    p->binding_shape = shape; p->binding_temporary = temporary != 0;
    memset(p->binding_trial_id,0,sizeof p->binding_trial_id);
    p->binding_exact_shape=0;
}

d2k_plantab *d2k_plantab_new(size_t cap) {
    if (cap == 0) {
        return NULL;
    }
    d2k_plantab *t = calloc(1, sizeof *t);
    if (!t) {
        return NULL;
    }
    t->v = calloc(cap, sizeof *t->v);
    t->probes = calloc(cap, sizeof *t->probes);
    if (!t->v || !t->probes) {
        free(t->probes);
        free(t->v);
        free(t);
        return NULL;
    }
    t->cap = cap;
    /* Failure must not fabricate an identity from clocks, addresses or PIDs.
       Packet execution remains available, but evidence has unknown identity. */
    FILE *entropy = fopen("/dev/urandom", "rb");
    if (entropy) {
        if (fread(t->epoch, 1, sizeof t->epoch, entropy) != sizeof t->epoch)
            memset(t->epoch, 0, sizeof t->epoch);
        fclose(entropy);
    }
    return t;
}

void d2k_plantab_free(d2k_plantab *t) {
    if (!t) {
        return;
    }
    /* Полная вместимость, а не used: свободный хвост v[used..cap) всегда
       занулён (см. инвариант выше), и d2k_plan_free(NULL) там — безопасный
       no-op. Так безопаснее пережить нарушение инварианта, если оно всё же
       случится, — деструктору можно позволить лишнюю страховку, которую
       нельзя позволить поиску на пакетном пути. */
    for (size_t i = 0; i < t->cap; i++) {
        d2k_plan_free(t->v[i].plan);
        d2k_plan_free(t->probes[i].plan);
        free(t->probes[i].raw_guard);
    }
    for (size_t i = 0; i < t->suffix_used; i++) d2k_plan_free(t->suffixes[i].plan);
    free(t->probes);
    free(t->v);
    free(t);
}

/* Имена сравниваются без учёта регистра: в SNI регистр незначим, а клиенты
   пишут по-разному. Своя функция, а не strncasecmp — тот зависит от локали, и
   в турецкой локали «I» ведёт себя не так, как ждёт остальной мир. */
static int name_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    if (alen != blen) {
        return 0;
    }
    for (size_t i = 0; i < alen; i++) {
        uint8_t x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') { x = (uint8_t)(x - 'A' + 'a'); }
        if (y >= 'A' && y <= 'Z') { y = (uint8_t)(y - 'A' + 'a'); }
        if (x != y) {
            return 0;
        }
    }
    return 1;
}

static uint8_t shape_transport(uint8_t shape) {
    if (shape == D2K_PLAN_SHAPE_QUIC) return 17;
    if (shape == D2K_PLAN_SHAPE_MODERN || shape == D2K_PLAN_SHAPE_LEGACY ||
        shape == D2K_PLAN_SHAPE_ECH_TCP) return 6;
    return 0;
}

static int area_name_valid(const uint8_t *name, size_t len) {
    if (!name || !len || len > 253) return 0;
    size_t label = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = name[i];
        if (c == '.') {
            if (!label || name[i-1] == '-') return 0;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-') || (!label && c == '-') || ++label > 63) return 0;
        }
    }
    return label && name[len-1] != '-';
}

static int suffix_member(const area_entry *e, const uint8_t *name, size_t len) {
    if (!name || len < e->len) return 0;
    return (len == e->len || name[len-e->len-1] == '.') &&
           name_eq(name+len-e->len, e->len, e->name, e->len);
}

static area_entry *area_exact(area_entry *v, size_t used, const uint8_t *name,
    size_t len, uint8_t transport, uint8_t shape, uint8_t family) {
    for (size_t i = 0; i < used; i++) {
        area_entry *e = &v[i];
        if (e->transport == transport && e->shape == shape && e->family == family &&
            name_eq(e->name, e->len, name, len)) return e;
    }
    return NULL;
}

static int area_set(d2k_plantab *t, area_entry *v, size_t *used, size_t cap,
    const uint8_t *name, size_t len, uint8_t transport, uint8_t shape,
    uint8_t family, d2k_plan *p) {
    if ((p && p->preflight) || !area_name_valid(name, len) || transport != shape_transport(shape) ||
        !transport || (family != 4 && family != 6)) {
        d2k_plan_free(p); return -2;
    }
    area_entry *e = area_exact(v, *used, name, len, transport, shape, family);
    if (!e) {
        if (*used == cap) { d2k_plan_free(p); return -1; }
        e = &v[(*used)++];
        memcpy(e->name, name, len); e->len = (uint8_t)len;
        e->transport = transport; e->shape = shape; e->family = family;
    }
    d2k_plan_free(e->plan); e->plan = p; t->revision++;
    bind_context(t, p, D2K_BIND_SUFFIX, family, shape, 0);
    return 0;
}

int d2k_plantab_set_suffix_family(d2k_plantab *t, const uint8_t *name, size_t len,
    uint64_t now_ns, d2k_plan *p, uint8_t shape, uint8_t family) {
    (void)now_ns;
    if (!t || !p || (d2k_plan_transport(p) && d2k_plan_transport(p) != shape_transport(shape)) ||
        shape == D2K_PLAN_SHAPE_HTTP || d2k_plan_proto(p) == D2K_PLAN_PROTO_HTTP) {
        d2k_plan_free(p); return -2;   /* HTTP — только точное имя */
    }
    return area_set(t, t->suffixes, &t->suffix_used, D2K_PLAN_SUFFIX_MAX,
        name, len, shape_transport(shape), shape, family, p);
}

int d2k_plantab_set_bypass_family(d2k_plantab *t, const uint8_t *name, size_t len,
    uint8_t transport, uint8_t shape, uint8_t family) {
    if (!t) return -2;
    return area_set(t, t->bypasses, &t->bypass_used, D2K_PLAN_BYPASS_MAX,
        name, len, transport, shape, family, NULL);
}

static int area_del(d2k_plantab *t, area_entry *v, size_t *used,
    const uint8_t *name, size_t len, uint8_t transport, uint8_t shape, uint8_t family) {
    if (!t || !name || !len) return 0;
    area_entry *e = area_exact(v, *used, name, len, transport, shape, family);
    if (!e) return 0;
    d2k_plan_free(e->plan); *e = v[--*used]; memset(&v[*used], 0, sizeof *v);
    t->revision++; return 1;
}

int d2k_plantab_del_suffix_family(d2k_plantab *t, const uint8_t *name, size_t len,
    uint8_t transport, uint8_t shape, uint8_t family) {
    return t ? area_del(t, t->suffixes, &t->suffix_used, name, len, transport, shape, family) : 0;
}

int d2k_plantab_del_bypass_family(d2k_plantab *t, const uint8_t *name, size_t len,
    uint8_t transport, uint8_t shape, uint8_t family) {
    return t ? area_del(t, t->bypasses, &t->bypass_used, name, len, transport, shape, family) : 0;
}

static int area_bypassed(const d2k_plantab *t, const uint8_t *name, size_t len,
    uint8_t shape, uint8_t family) {
    for (size_t i = 0; i < t->bypass_used; i++) {
        const area_entry *e = &t->bypasses[i];
        if (e->family == family && e->shape == shape && name && len &&
            name_eq(e->name, e->len, name, len)) return 1;
    }
    return 0;
}

static const area_entry *area_match(const d2k_plantab *t, const uint8_t *name,
    size_t len, uint8_t shape, uint8_t family) {
    const area_entry *best = NULL;
    for (size_t i = 0; i < t->suffix_used; i++) {
        const area_entry *e = &t->suffixes[i];
        if (e->shape == shape && e->family == family && suffix_member(e, name, len) &&
            (!best || e->len > best->len)) best = e;
    }
    return best;
}

uint64_t d2k_plantab_revision(const d2k_plantab *t) { return t ? t->revision : 0; }

int d2k_plantab_needs_complete_tls_shape(const d2k_plantab *t,const uint8_t *name,
    size_t len,uint8_t family) {
    if(!t || !name || !len)return 0;
    for(size_t i=0;i<t->used;i++) {
        const entry *e=&t->v[i];
        if(e->kind==KEY_NAME && !e->only_sport && e->family==family &&
           e->shape==D2K_PLAN_SHAPE_MODERN && e->plan->binding_exact_shape &&
           name_eq(e->name,e->name_len,name,len))return 1;
    }
    return 0;
}

int d2k_plantab_has_ech_target(const d2k_plantab *t, const uint8_t *name,
    size_t len, const uint8_t *addr, uint8_t family, uint16_t sport_be) {
    if (!t) return 0;
    for (size_t i = 0; i < t->used; i++) {
        const entry *e = &t->v[i];
        if (e->family != family || e->shape != D2K_PLAN_SHAPE_ECH_TCP ||
            (e->only_sport && e->only_sport != sport_be)) continue;
        /* Своя точная запись имени исключением семейства не гасится. */
        if (!e->only_sport && e->kind != KEY_NAME &&
            area_bypassed(t, name, len, e->shape, family)) continue;
        if (e->kind == KEY_NAME && name && len &&
            name_eq(e->name, e->name_len, name, len)) return 1;
        if (e->kind == KEY_ADDR && addr &&
            !memcmp(e->addr, addr, family == 6 ? 16 : 4)) return 1;
    }
    if (area_bypassed(t, name, len, D2K_PLAN_SHAPE_ECH_TCP, family)) return 0;
    return area_match(t, name, len, D2K_PLAN_SHAPE_ECH_TCP, family) != NULL;
}

int d2k_plantab_stream_candidate(const d2k_plantab *t, const uint8_t *name,
                                size_t len, uint32_t addr_be, uint16_t sport_be) {
    return d2k_plantab_stream_candidate_family(t, name, len, addr_be, sport_be, 4);
}

int d2k_plantab_stream_candidate_family(const d2k_plantab *t, const uint8_t *name,
    size_t len, uint32_t addr_be, uint16_t sport_be, uint8_t family) {
    return d2k_plantab_stream_candidate_target(t, name, len,
        family == 4 ? (const uint8_t *)&addr_be : NULL, sport_be, family);
}

int d2k_plantab_stream_candidate_target(const d2k_plantab *t, const uint8_t *name,
    size_t len, const uint8_t *addr, uint16_t sport_be, uint8_t family) {
    if (!t || (family != 4 && family != 6)) { return 0; }
    for (size_t i = 0; i < t->used; i++) {
        const entry *e = &t->v[i];
        if (e->family != family) { continue; }
        if (!e->only_sport && e->kind != KEY_NAME &&
            area_bypassed(t, name, len, e->shape, family)) continue;
        if (!d2k_plan_stream_input(e->plan) ||
            (e->only_sport && e->only_sport != sport_be)) { continue; }
        if (e->kind == KEY_ADDR && addr &&
            memcmp(e->addr, addr, family == 6 ? 16 : 4) == 0) { return 1; }
        if (e->kind == KEY_NAME &&
            (!name || !len || name_eq(e->name, e->name_len, name, len))) { return 1; }
    }
    for (size_t i = 0; i < t->suffix_used; i++) {
        const area_entry *e = &t->suffixes[i];
        if (e->family == family && e->transport == 6 &&
            d2k_plan_stream_input(e->plan) &&
            (!name || !len || suffix_member(e, name, len)) &&
            !area_bypassed(t, name, len, e->shape, family)) return 1;
    }
    return 0;
}

/* used, не cap — см. инвариант уплотнения в шапке файла. */
/* Запись имени БЕЗ ПРИВЯЗКИ К ПОТОКУ. Пробные записи (only_sport != 0) сюда
   не попадают намеренно: они существуют только для одного местного порта, и
   для всех прочих вопросов их как будто нет. Пропусти это — и пробный план
   утёк бы к пользователю через ветку «имя знаем, формы такой нет». */
static entry *find_name_skip(d2k_plantab *t, const uint8_t *name, size_t len, uint8_t family,
                             int skip_http) {
    for (size_t i = 0; i < t->used; i++) {
        if (t->v[i].kind == KEY_NAME && t->v[i].family == family && t->v[i].only_sport == 0 &&
            !(skip_http && t->v[i].shape == D2K_PLAN_SHAPE_HTTP) &&
            name_eq(t->v[i].name, t->v[i].name_len, name, len)) {
            return &t->v[i];
        }
    }
    return NULL;
}

static entry *find_name(d2k_plantab *t, const uint8_t *name, size_t len, uint8_t family) {
    return find_name_skip(t, name, len, family, 0);
}

/* ЗАПИСЬ ИЩЕТСЯ ПО ИМЕНИ И ФОРМЕ, а не по одному имени.
 *
 * У одного имени бывает НЕСКОЛЬКО планов: TCP и QUIC — это разные
 * приветствия, разные коробки в общем случае и заведомо разные воздействия
 * (датаграмму нельзя резать, поток нельзя размножить приманками). Пока
 * запись была одна на имя, вторая привязка ЗАТИРАЛА первую, и какой из двух
 * обходов работает, зависело от порядка синхронизации каталога.
 *
 * Замерено на роутере Марка 13.09.2026: у www.facebook.com подтверждены и
 * TCP-план, и QUIC-план; после синхронизации в таблице оставался последний, и
 * клиент за роутером не проходил ни по одному транспорту — при том, что
 * собственный зонд на обоих отвечал 200. */
static entry *find_name_shape_port(d2k_plantab *t, const uint8_t *name, size_t len,
                                   uint8_t shape, uint16_t sport_be, uint8_t family) {
    for (size_t i = 0; i < t->used; i++) {
        if (t->v[i].kind == KEY_NAME && t->v[i].family == family && t->v[i].shape == shape &&
            t->v[i].only_sport == sport_be &&
            name_eq(t->v[i].name, t->v[i].name_len, name, len)) {
            return &t->v[i];
        }
    }
    return NULL;
}

/* Точный временный порт зонда остаётся авторитетным, если его первый
   ClientHello-сегмент ещё не позволяет классифицировать форму. Это не
   ослабляет постоянные записи: только запись, закреплённая за ненулевым
   локальным портом, может быть найдена этим путём. */
static entry *find_name_port(d2k_plantab *t, const uint8_t *name, size_t len,
                             uint16_t sport_be, uint8_t family) {
    if (!sport_be) { return NULL; }
    for (size_t i = 0; i < t->used; i++) {
        if (t->v[i].kind == KEY_NAME && t->v[i].family == family && t->v[i].only_sport == sport_be &&
            t->v[i].shape != D2K_PLAN_SHAPE_HTTP &&
            name_eq(t->v[i].name, t->v[i].name_len, name, len)) {
            return &t->v[i];
        }
    }
    return NULL;
}

int d2k_plantab_http_candidate(const d2k_plantab *t,uint8_t family,uint16_t sport) {
    if(!t)return 0;
    for(size_t i=0;i<t->used;i++) {
        const entry *e=&t->v[i];
        if(e->kind==KEY_NAME && e->family==family && e->shape==D2K_PLAN_SHAPE_HTTP &&
           e->only_sport==sport && d2k_plan_proto(e->plan)==D2K_PLAN_PROTO_HTTP)return 1;
    }
    return 0;
}

const d2k_plan *d2k_plantab_find_http(d2k_plantab *t, const uint8_t *name, size_t len,
                                      uint8_t family, uint16_t sport_be, uint64_t now_ns) {
    if (!t || !name || !len) { return NULL; }
    entry *e = find_name_shape_port(t, name, len, D2K_PLAN_SHAPE_HTTP, sport_be, family);
    if (!e || d2k_plan_proto(e->plan) != D2K_PLAN_PROTO_HTTP) { return NULL; }
    e->last_used_ns = now_ns;
    return e->plan;
}

/* Адресная запись — КЛЮЧ (адрес, семейство, форма протокола). Один IP может
   нести и QUIC, и STUN/голос, и TLS: подтверждённое на одном протоколе к
   другому отношения не имеет (D2K_SPEC §5), и одна запись на адрес давала
   голосовому плану затирать QUIC-привязку того же IP и применяться ко всем
   его Initial. find_addr — любая форма (снятие адреса целиком, учёт промаха),
   find_addr_shape — ровно одна. */
/* Транспорт записи формы RAW (этап 39): у потока без протокола решение своё
   для TCP и для UDP одного адреса. План без объявленного транспорта (0)
   подходит любому — прежнее поведение. Для прочих форм транспорт задан самой
   формой и в ключ не входит. */
static int raw_transport_fits(const entry *e, uint8_t transport) {
    if (e->shape != D2K_PLAN_SHAPE_RAW || !transport) return 1;
    uint8_t pt = d2k_plan_transport(e->plan);
    return !pt || pt == transport;
}

static entry *find_addr_shape_tr(d2k_plantab *t, const uint8_t *addr, uint8_t family,
                                 int any_shape, uint8_t shape, uint8_t transport) {
    if (!addr || (family != 4 && family != 6)) { return NULL; }
    for (size_t i = 0; i < t->used; i++) {
        if (t->v[i].kind == KEY_ADDR && t->v[i].family == family &&
            (any_shape || t->v[i].shape == shape) &&
            memcmp(t->v[i].addr, addr, family == 6 ? 16 : 4) == 0 &&
            (any_shape || raw_transport_fits(&t->v[i], transport))) {
            return &t->v[i];
        }
    }
    return NULL;
}

static entry *find_addr_shape(d2k_plantab *t, const uint8_t *addr, uint8_t family,
                              int any_shape, uint8_t shape) {
    return find_addr_shape_tr(t, addr, family, any_shape, shape, 0);
}

static entry *find_endpoint_kind(d2k_plantab *t, const uint8_t *addr, uint8_t family,
                            uint16_t port_be, uint8_t shape, uint8_t transport, unsigned kind) {
    if (!t || !addr || !port_be || (family != 4 && family != 6)) return NULL;
    for (size_t i = 0; i < t->used; i++) {
        entry *e = &t->v[i];
        if (e->kind == kind && e->family == family &&
            e->endpoint_port == port_be && e->shape == shape &&
            ((shape != D2K_PLAN_SHAPE_RAW && shape != D2K_PLAN_SHAPE_DNS) ||
             (transport && d2k_plan_transport(e->plan) == transport)) &&
            !memcmp(e->addr, addr, family == 6 ? 16 : 4)) return e;
    }
    return NULL;
}

static entry *find_endpoint(d2k_plantab *t,const uint8_t *addr,uint8_t family,
    uint16_t port,uint8_t shape,uint8_t transport) {
    return find_endpoint_kind(t,addr,family,port,shape,transport,KEY_ENDPOINT);
}

static entry *find_addr(d2k_plantab *t, const uint8_t *addr, uint8_t family) {
    return find_addr_shape(t, addr, family, 1, 0);
}

/* ОДИН ПРОХОД НА ПРОМАХЕ ПЕРВОГО ПАКЕТА (финальное ревью, п.7). Прежде путь
   без пробной записи звал find_name_shape/find_addr_shape до четырёх раз
   подряд — своя форма, TLS 1.3 для ECH, дедушкина, любая. Здесь каждая
   категория запоминается ПЕРВОЙ подходящей записью по индексу — ровно то,
   что вернул бы соответствующий отдельный поиск, — и порядок предпочтения
   решает вызывающий, как раньше. */
typedef struct { entry *shaped, *modern, *grandfather, *any; } name_hits;
typedef struct { entry *shaped, *modern, *grandfather, *any; } addr_hits;

static void scan_name(d2k_plantab *t, const uint8_t *name, size_t len,
                      uint8_t seen_shape, uint8_t family, name_hits *h) {
    memset(h, 0, sizeof *h);
    for (size_t i = 0; i < t->used; i++) {
        entry *e = &t->v[i];
        if (e->kind != KEY_NAME || e->family != family || e->only_sport != 0 ||
            !name_eq(e->name, e->name_len, name, len)) continue;
        /* Запись HTTP — не знание о TLS этого имени: «имя знаем, формы нет»
           из-за неё заслонило бы приветствию адресный план. */
        if (e->shape == D2K_PLAN_SHAPE_HTTP) continue;
        if (!h->any) h->any = e;
        if (!h->shaped && e->shape == seen_shape) h->shaped = e;
        if (!h->modern && e->shape == D2K_PLAN_SHAPE_MODERN) h->modern = e;
        if (!h->grandfather && e->shape == D2K_PLAN_SHAPE_GRANDFATHER) h->grandfather = e;
    }
}

static void scan_addr(d2k_plantab *t, const uint8_t *addr, uint8_t family,
                      uint8_t seen_shape, uint8_t transport, addr_hits *h) {
    memset(h, 0, sizeof *h);
    if (!addr || (family != 4 && family != 6)) return;
    for (size_t i = 0; i < t->used; i++) {
        entry *e = &t->v[i];
        if (e->kind != KEY_ADDR || e->family != family ||
            memcmp(e->addr, addr, family == 6 ? 16 : 4) != 0) continue;
        if (!h->any) h->any = e;
        if (!h->shaped && seen_shape != D2K_PLAN_SHAPE_ANY && e->shape == seen_shape &&
            raw_transport_fits(e, transport))
            h->shaped = e;
        if (!h->modern && e->shape == D2K_PLAN_SHAPE_MODERN) h->modern = e;
        if (!h->grandfather && e->shape == D2K_PLAN_SHAPE_GRANDFATHER) h->grandfather = e;
    }
}

/* Кандидат на вытеснение — запись с самой старой отметкой обращения.
   Линейный перебор до used (см. инвариант уплотнения выше и обоснование
   размера/частоты вызова в d2k_plans.h) — свободные слоты в v[used..cap)
   заведомо не заняты и в переборе не участвуют вовсе, проверять kind не
   нужно. Строгое "меньше", а не "меньше или равно" — при равных отметках
   (например, таблицу только что залили одной пачкой команд с одним и тем же
   now_ns) побеждает запись с МЕНЬШИМ индексом, а новые записи всегда встают
   в v[used] по возрастанию — то есть при равенстве давности вытесняется та,
   что вставлена раньше. Разумный запасной порядок, а не порча инварианта.

   used == 0 недостижимо оттуда, откуда эта функция реально зовётся (только
   из take_free_or_evict, и только когда used == cap, а cap == 0 таблицу
   d2k_plantab_new не создаёт) — проверка ниже не бумажный тигр, а страховка
   от разыменования NULL, если этот инвариант всё-таки нарушится. */
static entry *oldest(d2k_plantab *t) {
    if (t->used == 0) {
        return NULL;
    }
    entry *victim = &t->v[0];
    for (size_t i = 1; i < t->used; i++) {
        if (t->v[i].last_used_ns < victim->last_used_ns) {
            victim = &t->v[i];
        }
    }
    return victim;
}

/* Свободная запись для новой цели — своя, если она есть, иначе вытесненная.
 * Отказа здесь больше нет: см. большой комментарий у d2k_plans.h про то,
 * почему любой объявленный предел когда-нибудь заполнится и почему навсегда
 * отказывать новой цели неверно.
 *
 * Возвращает указатель на слот, который вызывающий (d2k_plantab_set_name/
 * set_addr) заполнит и учтёт в used САМ — как и раньше, эта функция used не
 * трогает НИ В КАКОЙ ветке насовсем: свободный слот в v[used] отдаётся ДО
 * увеличения used вызывающим; вытесненный — после временного уменьшения,
 * которое тот же вызывающий сразу отменяет своим "used++". */
static entry *take_free_or_evict(d2k_plantab *t) {
    if (t->used < t->cap) {
        /* Инвариант уплотнения: следующий свободный слот — ВСЕГДА v[used],
           искать нечего. Он уже занулён — либо calloc'ом при создании
           таблицы, либо явно при последнем освобождении (см. drop ниже) —
           поэтому досюда не нужен и memset. */
        return &t->v[t->used];
    }
    entry *victim = oldest(t);
    if (!victim) {
        /* Недостижимо: used == cap >= 1 здесь (иначе взяли бы ветку выше), а
           oldest() при used > 0 всегда что-то находит. Проверка — страховка
           от разыменования NULL ниже, а не ожидаемый исход. */
        return NULL;
    }
    d2k_plan_free(victim->plan);
    /* Уплотнение: вытесненный слот освобождается переносом ПОСЛЕДНЕЙ занятой
       записи на его место — иначе внутри v[0..used) осталась бы дыра, и
       следующий поиск снова зависел бы не только от used, ради чего всё это
       затевалось. victim == last, когда сама victim и есть последняя занятая
       — тогда перенос лишний (само в себя), но не вредный. */
    entry *last = &t->v[t->used - 1];
    if (victim != last) {
        *victim = *last;
    }
    memset(last, 0, sizeof *last);
    t->used--;   /* временно: вызывающий поднимет used обратно, заполнив last */
    return last;
}

int d2k_plantab_set_name_shaped(d2k_plantab *t, const uint8_t *name, size_t len,
                                uint64_t now_ns, d2k_plan *p, uint8_t shape) {
    return d2k_plantab_set_name_probe(t, name, len, now_ns, p, shape, 0);
}

int d2k_plantab_set_name_probe(d2k_plantab *t, const uint8_t *name, size_t len,
                               uint64_t now_ns, d2k_plan *p, uint8_t shape,
                               uint16_t sport_be) {
    return d2k_plantab_set_name_family(t, name, len, now_ns, p, shape, sport_be, 4);
}

static int drop(d2k_plantab *t, entry *e);

static uint8_t probe_transport(const d2k_plan *p, uint8_t shape) {
    uint8_t transport = d2k_plan_transport(p);
    if (transport) return transport;
    return shape == D2K_PLAN_SHAPE_QUIC || shape == D2K_PLAN_SHAPE_VOICE ? 17 : 6;
}

int d2k_plantab_set_name_family(d2k_plantab *t, const uint8_t *name, size_t len,
    uint64_t now_ns, d2k_plan *p, uint8_t shape, uint16_t sport_be, uint8_t family) {
    if ((p && p->preflight) || !t || !name || len == 0 || len > D2K_TARGET_NAME_MAX ||
        (family != 4 && family != 6)) {
        d2k_plan_free(p);
        return -2;
    }
    /* Форма HTTP и протокол http — только вместе (шаг 4 задачи 51). */
    if ((shape == D2K_PLAN_SHAPE_HTTP) != (d2k_plan_proto(p) == D2K_PLAN_PROTO_HTTP) ||
        (shape == D2K_PLAN_SHAPE_HTTP && d2k_plan_transport(p) != 6)) {
        d2k_plan_free(p);
        return -2;
    }
    t->revision++;
    /* The controller reserves this local port exclusively. Reuse transfers
       ownership, even if the previous task missed its cleanup. Do not leave
       two candidates for an as-yet unnamed ClientHello on that same socket. */
    if (sport_be) {
        uint8_t transport = probe_transport(p, shape);
        for (size_t i = 0; i < t->used;) {
            entry *old = &t->v[i];
            if (old->kind == KEY_NAME && old->family == family &&
                old->only_sport == sport_be &&
                probe_transport(old->plan, old->shape) == transport) {
                (void)drop(t, old);
            } else {
                i++;
            }
        }
    }
    /* Своя запись на КАЖДУЮ ИЗМЕРЕННУЮ форму этого имени — см.
       find_name_shape выше. Прежде запись была одна на имя, и вторая
       привязка (например, QUIC) затирала первую (TCP).

       ДЕДУШКИНО ПРАВО СВОЕЙ ЗАПИСИ НЕ ЗАВОДИТ, если у имени уже есть
       измеренная: оно подходит любому приветствию (shape_fits), и такая
       запись рядом с измеренной молча расширила бы план на формы, на которых
       его никто не подтверждал. Вместо этого обновляется план у измеренной
       записи — ровно прежнее поведение «форму не понижаем». */
    entry *e = NULL;
    if (shape == D2K_PLAN_SHAPE_GRANDFATHER && sport_be == 0) {
        /* Запись HTTP — другой протокол того же имени, не «измеренная форма
           TLS»: дедушкин TLS-план её не заменяет (ревью I-1 шага 4 — иначе
           пропадали и HTTP-, и TLS-план имени). */
        e = find_name_skip(t, name, len, family, 1);
        if (e && e->only_sport == 0 && e->shape != D2K_PLAN_SHAPE_GRANDFATHER) {
            e->last_used_ns = now_ns;
            d2k_plan_free(e->plan);
            e->plan = p;
            bind_context(t, p, D2K_BIND_NAME, family, e->shape, 0);
            return 0;
        }
    }
    if (!e || e->shape != shape || e->only_sport != sport_be) {
        e = find_name_shape_port(t, name, len, shape, sport_be, family);
    }
    if (!e) {
        e = take_free_or_evict(t);
        if (!e) {
            d2k_plan_free(p);
            return -1;
        }
        t->used++;
        e->kind = KEY_NAME;
        e->family = family;
        e->name_len = (uint8_t)len;
        memcpy(e->name, name, len);
        e->shape = shape;
        e->only_sport = sport_be;
    }
    e->last_used_ns = now_ns;
    /* Прежний план освобождается здесь, а не у вызывающего: иначе замена
       плана цели молча текла бы. */
    d2k_plan_free(e->plan);
    e->plan = p;
    bind_context(t, p, D2K_BIND_NAME, family, e->shape, sport_be != 0);
    return 0;
}

/* Прежняя форма вызова — «форма приветствия не записывалась», то есть
   дедушкино право. Ноль сюда класть нельзя: он означает «сказать нечего» и
   совместимости больше не даёт, а такой план молча перестал бы применяться. */
int d2k_plantab_set_name(d2k_plantab *t, const uint8_t *name, size_t len,
                         uint64_t now_ns, d2k_plan *p) {
    return d2k_plantab_set_name_shaped(t, name, len, now_ns, p,
                                       D2K_PLAN_SHAPE_GRANDFATHER);
}

int d2k_plantab_set_addr(d2k_plantab *t, uint32_t addr_be, uint64_t now_ns,
                         d2k_plan *p) {
    return d2k_plantab_set_addr_family(t, (const uint8_t *)&addr_be, 4, now_ns, p);
}

/* Без формы — дедушкино право: отдельная запись того же адреса, подходящая
   любой форме. С управляющего сокета так не ставится (SET_ADDR v7 требует
   форму, ctlsrv.c) — это вход для внутренних тестов датапата. */
int d2k_plantab_set_addr_family(d2k_plantab *t, const uint8_t *addr, uint8_t family,
                                uint64_t now_ns, d2k_plan *p) {
    return d2k_plantab_set_addr_shaped(t, addr, family, now_ns, p,
                                       D2K_PLAN_SHAPE_GRANDFATHER);
}

int d2k_plantab_set_addr_shaped(d2k_plantab *t, const uint8_t *addr, uint8_t family,
                                uint64_t now_ns, d2k_plan *p, uint8_t shape) {
    if ((p && p->preflight) || !t || !addr || (family != 4 && family != 6) || shape == D2K_PLAN_SHAPE_ANY ||
        shape == D2K_PLAN_SHAPE_HTTP || d2k_plan_proto(p) == D2K_PLAN_PROTO_HTTP) {
        d2k_plan_free(p);   /* HTTP — только точное имя, не адрес */
        return -2;
    }
    t->revision++;
    /* Своя запись на каждую форму: замена плана одной формы не трогает
       подтверждённое на другой (§7 — чужое знание не задевать). */
    /* У формы RAW — своя запись на транспорт плана (этап 39). */
    entry *e = find_addr_shape_tr(t, addr, family, 0, shape,
                                  shape == D2K_PLAN_SHAPE_RAW ? d2k_plan_transport(p) : 0);
    if (!e) {
        e = take_free_or_evict(t);
        if (!e) {
            d2k_plan_free(p);
            return -1;
        }
        t->used++;
        e->kind = KEY_ADDR;
        e->family = family;
        memset(e->addr, 0, sizeof e->addr);
        memcpy(e->addr, addr, family == 6 ? 16 : 4);
        e->shape = shape;
    }
    e->last_used_ns = now_ns;
    d2k_plan_free(e->plan);
    e->plan = p;
    bind_context(t, p, D2K_BIND_ADDR, family, shape, 0);
    return 0;
}

static int set_endpoint(d2k_plantab *t,const uint8_t *addr,uint8_t family,
    uint16_t dport_be,uint64_t now_ns,d2k_plan *p,uint8_t shape,uint16_t dns_length) {
    int dns=shape==D2K_PLAN_SHAPE_DNS;
    uint8_t transport = (shape == D2K_PLAN_SHAPE_RAW || dns) ? d2k_plan_transport(p) :
                        shape == D2K_PLAN_SHAPE_VOICE ? 17 : shape_transport(shape);
    unsigned prefix=transport==6 ? 2 : 0;
    if ((p && p->preflight && transport!=6) ||
        !t || !addr || !p || (family != 4 && family != 6) || !dport_be || (transport != 6 && transport != 17) ||
        (dns && (p->preflight || dns_length<17+prefix || dns_length>272+prefix)) ||
        d2k_plan_proto(p) == D2K_PLAN_PROTO_HTTP ||
        (d2k_plan_transport(p) && d2k_plan_transport(p) != transport) ||
        (transport == 17 && !dns && shape != D2K_PLAN_SHAPE_RAW && (d2k_plan_transport(p) != 17 ||
            d2k_plan_proto(p) != (shape == D2K_PLAN_SHAPE_VOICE ? 3 : 2)))) {
        d2k_plan_free(p);
        return -2;
    }
    entry *e = find_endpoint(t, addr, family, dport_be, shape, transport);
    if (!e) {
        e = take_free_or_evict(t);
        if (!e) { d2k_plan_free(p); return -1; }
        t->used++;
        e->kind = KEY_ENDPOINT;
        e->family = family;
        memcpy(e->addr, addr, family == 6 ? 16 : 4);
        e->endpoint_port = dport_be;
        e->shape = shape;
    }
    t->revision++;
    e->last_used_ns = now_ns;
    e->dns_length=dns_length;
    d2k_plan_free(e->plan);
    e->plan = p;
    bind_context(t, p, D2K_BIND_ADDR, family, shape, 0);
    return 0;
}

int d2k_plantab_set_endpoint(d2k_plantab *t,const uint8_t *addr,uint8_t family,
    uint16_t port,uint64_t now,d2k_plan *p,uint8_t shape) {
    return set_endpoint(t,addr,family,port,now,p,shape,0);
}

int d2k_plantab_set_dns_endpoint(d2k_plantab *t,const uint8_t *addr,uint8_t family,
    uint16_t port,uint64_t now,uint16_t wire_length,d2k_plan *p) {
    return set_endpoint(t,addr,family,port,now,p,D2K_PLAN_SHAPE_DNS,wire_length);
}

static int dns_wire_query(const uint8_t *q,size_t len,uint8_t transport) {
    if (transport==6) {
        if (len<19 || (size_t)q[0]*256+q[1]!=len-2)return 0;
        q+=2;len-=2;
    }
    if (len<17 || len>272 || (q[2]&0xf8) || q[4] || q[5]!=1 ||
        q[6] || q[7] || q[8] || q[9] || q[10] || q[11])return 0;
    size_t i=12;
    while (i<len-4 && q[i]) {
        size_t lc=q[i++];
        if (lc>63 || lc>len-4-i)return 0;
        i+=lc;
    }
    return i<=266 && i+5==len && !q[i] && (q[i+1] || q[i+2]) && !q[i+3] && q[i+4]==1;
}

const d2k_plan *d2k_plantab_find_dns_endpoint(d2k_plantab *t,const uint8_t *addr,uint8_t family,
    uint16_t port,uint8_t transport,const uint8_t *wire,size_t len,uint64_t now) {
    entry *e=find_endpoint(t,addr,family,port,D2K_PLAN_SHAPE_DNS,transport);
    if (!e || !wire || len!=e->dns_length || !dns_wire_query(wire,len,transport))return NULL;
    e->last_used_ns=now;
    return e->plan;
}

int d2k_plantab_set_endpoint_trial_port(d2k_plantab *t,const uint8_t *addr,uint8_t family,
    uint16_t port,uint16_t sport,uint64_t now,d2k_plan *p,uint8_t shape,const uint8_t trial[16]) {
    uint8_t any=0;
    if(trial)for(unsigned i=0;i<16;i++)any|=trial[i];
    if(!any){d2k_plan_free(p);return -2;}
    if(!p || !p->preflight) {
        int rc=d2k_plantab_set_endpoint(t,addr,family,port,now,p,shape);
        if(!rc)memcpy(p->binding_trial_id,trial,16);
        return rc;
    }
    if(!t || !addr || (family!=4 && family!=6) || !port ||
       (shape!=D2K_PLAN_SHAPE_MODERN && shape!=D2K_PLAN_SHAPE_LEGACY)) {
        d2k_plan_free(p);return -2;
    }
    /* A candidate never replaces or evicts confirmed knowledge or another trial. */
    if(t->used==t->cap || find_endpoint_kind(t,addr,family,port,shape,6,KEY_ENDPOINT_TRIAL)) {
        d2k_plan_free(p);return -1;
    }
    entry *e=&t->v[t->used++];memset(e,0,sizeof *e);
    p->preflight_trial_sport = sport;
    e->kind=KEY_ENDPOINT_TRIAL;e->family=family;e->shape=shape;e->endpoint_port=port;e->only_sport=sport;
    memcpy(e->addr,addr,family==6?16:4);e->plan=p;e->last_used_ns=now;t->revision++;
    bind_context(t,p,D2K_BIND_ADDR,family,shape,1);memcpy(p->binding_trial_id,trial,16);
    return 0;
}

int d2k_plantab_set_endpoint_trial(d2k_plantab *t,const uint8_t *addr,uint8_t family,
    uint16_t port,uint64_t now,d2k_plan *p,uint8_t shape,const uint8_t trial[16]) {
    return d2k_plantab_set_endpoint_trial_port(t,addr,family,port,0,now,p,shape,trial);
}

/* Убирает произвольную запись, сохраняя уплотнение — той же техникой, что и
   вытеснение в take_free_or_evict: перенос последней занятой на освободившееся
   место, затем used--. Без этого удаление прогрызало бы дыру в v[0..used), и
   find_name/find_addr снова были бы обязаны обходить весь cap, чтобы её не
   пропустить, — то есть в точности регресс, который чинит эта задача. */
static int drop(d2k_plantab *t, entry *e) {
    if (!e) {
        return 0;
    }
    t->revision++;
    d2k_plan_free(e->plan);
    entry *last = &t->v[t->used - 1];
    if (e != last) {
        *e = *last;
    }
    memset(last, 0, sizeof *last);
    t->used--;
    return 1;
}

int d2k_plantab_del_endpoint_trial(d2k_plantab *t, const uint8_t *addr, uint8_t family,
    uint16_t port, uint8_t shape, const uint8_t trial[16]) {
    uint8_t any=0;
    if(!trial)return 0;
    for(unsigned i=0;i<16;i++)any|=trial[i];
    entry *e=find_endpoint_kind(t,addr,family,port,shape,0,KEY_ENDPOINT_TRIAL);
    if(!any || !e || memcmp(e->plan->binding_trial_id,trial,16))return 0;
    return drop(t,e);
}

int d2k_plantab_commit_endpoint_trial(d2k_plantab *t,const uint8_t *addr,uint8_t family,
    uint16_t port,uint8_t shape,const uint8_t trial[16]) {
    entry *e=find_endpoint_kind(t,addr,family,port,shape,0,KEY_ENDPOINT_TRIAL);
    if(!trial || !e || memcmp(e->plan->binding_trial_id,trial,16))return 0;
    /* drop may compact the trial, so resolve it again after removing the old owner. */
    (void)drop(t,find_endpoint(t,addr,family,port,shape,0));
    e=find_endpoint_kind(t,addr,family,port,shape,0,KEY_ENDPOINT_TRIAL);
    e->plan->preflight_trial_sport = 0;
    e->kind=KEY_ENDPOINT;e->only_sport=0;e->plan->binding_temporary=0;t->revision++;
    return 1;
}

int d2k_plantab_del_endpoint(d2k_plantab *t, const uint8_t *addr, uint8_t family,
    uint16_t dport_be, uint8_t shape) {
    /* RAW deletion without a transport is ambiguous: preserve both owners. */
    return drop(t, find_endpoint(t, addr, family, dport_be, shape, 0));
}

int d2k_plantab_del_raw_endpoint(d2k_plantab *t, const uint8_t *addr, uint8_t family,
    uint16_t dport_be, uint8_t transport) {
    if (transport != 6 && transport != 17) return 0;
    return drop(t, find_endpoint(t, addr, family, dport_be, D2K_PLAN_SHAPE_RAW, transport));
}

int d2k_plantab_del_dns_endpoint(d2k_plantab *t,const uint8_t *addr,uint8_t family,
    uint16_t port,uint8_t transport) {
    return drop(t,find_endpoint(t,addr,family,port,D2K_PLAN_SHAPE_DNS,transport));
}

void d2k_plantab_clear_dns_endpoints(d2k_plantab *t) {
    for(size_t i=0;t && i<t->used;) {
        entry *e=&t->v[i];
        if (e->kind==KEY_ENDPOINT && e->shape==D2K_PLAN_SHAPE_DNS)drop(t,e);
        else i++;
    }
}

int d2k_plantab_del_name(d2k_plantab *t, const uint8_t *name, size_t len) {
    return d2k_plantab_del_name_family(t, name, len, 4);
}

int d2k_plantab_del_name_family(d2k_plantab *t, const uint8_t *name, size_t len, uint8_t family) {
    if (!t || !name || len == 0) {
        return 0;
    }
    /* Снимаем ВСЕ записи этого имени, а не первую попавшуюся: у имени их
       теперь столько, сколько измеренных форм приветствия (см.
       find_name_shape). «Сними план с этой цели» означает снять его целиком;
       оставленная вторая форма продолжала бы применяться, и человек видел бы
       обход там, где его выключили. */
    int n = 0;
    for (;;) {
        entry *e = find_name(t, name, len, family);
        if (!e || drop(t, e) == 0) {
            break;
        }
        n++;
    }
    return n > 0;
}

/* Снятие ПОСТОЯННОЙ записи по ключу (имя, транспорт, форма, семейство) —
   единственное снятие по имени, доступное с управляющего сокета (DEL_NAME
   v9, задача 21). Пробы (only_sport != 0) не трогает никогда: их снимает
   только DEL_NAME_PROBE своим портом. Прежнее «все записи имени» уносило
   пробу параллельной задачи другого транспорта и подтверждённое знание
   других форм (§7). Форма ANY — не шаблон: снимать нечего. */
int d2k_plantab_del_name_shaped(d2k_plantab *t, const uint8_t *name, size_t len,
    uint8_t transport, uint8_t shape, uint8_t family) {
    if (!t || !name || len == 0 || shape == D2K_PLAN_SHAPE_ANY ||
        (transport != 6 && transport != 17)) { return 0; }
    int n = 0;
    for (size_t i = 0; i < t->used;) {
        entry *e = &t->v[i];
        if (e->kind == KEY_NAME && e->family == family && e->only_sport == 0 &&
            e->shape == shape && probe_transport(e->plan, e->shape) == transport &&
            name_eq(e->name, e->name_len, name, len)) {
            (void)drop(t, e);
            n++;
            continue; /* drop() compacted the last entry into slot i */
        }
        i++;
    }
    return n > 0;
}

int d2k_plantab_del_name_bound(d2k_plantab *t, const uint8_t *name, size_t len,
    uint8_t transport, const d2k_binding_context *expected) {
    if (!t || !name || !len || !d2k_binding_known(expected) ||
        expected->kind!=D2K_BIND_NAME || expected->temporary ||
        (transport!=6 && transport!=17)) return 0;
    for (size_t i=0;i<t->used;i++) {
        entry *e=&t->v[i]; d2k_binding_context current;
        if(e->kind==KEY_NAME && !e->only_sport && name_eq(e->name,e->name_len,name,len) &&
           probe_transport(e->plan,e->shape)==transport &&
           d2k_plantab_binding(t,e->plan,&current) && d2k_binding_equal(&current,expected)) {
            (void)drop(t,e); return 1;
        }
    }
    return 0;
}

int d2k_plantab_del_name_probe(d2k_plantab *t, const uint8_t *name, size_t len,
                               uint8_t shape, uint16_t sport_be) {
    return d2k_plantab_del_name_probe_family(t, name, len, shape, sport_be, 4);
}

static int del_name_probe_if(d2k_plantab *t,const uint8_t *name,size_t len,
    uint8_t shape,uint16_t sport_be,uint8_t family,const uint8_t *trial) {
    if (!t || !name || len == 0 || sport_be == 0) { return 0; }
    int n = 0;
    for (size_t i = 0; i < t->used;) {
        entry *e = &t->v[i];
        if (e->kind == KEY_NAME && e->family == family && e->only_sport == sport_be &&
            e->shape == shape && name_eq(e->name, e->name_len, name, len) &&
            (!trial || !memcmp(e->plan->binding_trial_id,trial,D2K_TRIAL_ID_LEN))) {
            (void)drop(t, e);
            n++;
            continue; /* drop() compacted the last entry into slot i */
        }
        i++;
    }
    return n > 0;
}

int d2k_plantab_del_name_probe_family(d2k_plantab *t,const uint8_t *name,size_t len,
    uint8_t shape,uint16_t sport_be,uint8_t family) {
    return del_name_probe_if(t,name,len,shape,sport_be,family,NULL);
}

int d2k_plantab_del_name_probe_trial(d2k_plantab *t,const uint8_t *name,size_t len,
    uint8_t shape,uint16_t sport_be,uint8_t family,const uint8_t trial[D2K_TRIAL_ID_LEN]) {
    uint8_t any=0;
    if(trial)for(size_t i=0;i<D2K_TRIAL_ID_LEN;i++)any|=trial[i];
    if(!any || !shape || (family!=4 && family!=6))return 0;
    return del_name_probe_if(t,name,len,shape,sport_be,family,trial);
}

int d2k_plantab_del_addr(d2k_plantab *t, uint32_t addr_be) {
    return d2k_plantab_del_addr_family(t, (const uint8_t *)&addr_be, 4);
}

/* Без формы — снять адрес целиком, все формы (как del_name снимает все
   формы имени). С управляющего сокета этот путь недоступен: DEL_ADDR v7
   несёт форму и снимает ровно её (d2k_plantab_del_addr_shaped). */
int d2k_plantab_del_addr_family(d2k_plantab *t, const uint8_t *addr, uint8_t family) {
    if (!t) { return 0; }
    int n = 0;
    while (drop(t, find_addr(t, addr, family))) { n++; }
    return n > 0;
}

int d2k_plantab_del_addr_shaped(d2k_plantab *t, const uint8_t *addr, uint8_t family,
                                uint8_t shape) {
    if (!t || shape == D2K_PLAN_SHAPE_ANY) { return 0; }
    return drop(t, find_addr_shape(t, addr, family, 0, shape));
}

static int trial_id_valid(const uint8_t id[D2K_TRIAL_ID_LEN]) {
    if (!id) { return 0; }
    uint8_t any = 0;
    for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) { any |= id[i]; }
    return any != 0;
}

/* src_port_be == 0 is the voice wildcard: same LAN client, same server
   endpoint, ANY client port (the next call/rejoin socket). Only
   d2k_plantab_find_voice_probe consults such entries. */
static int probe_flow_valid(const d2k_addr_probe_flow *f) {
    if (!f || (f->transport != 6 && f->transport != 17) || (f->transport==6 && !f->src_port_be) || f->dst_port_be == 0) {
        return 0;
    }
    if (f->family != 0 && f->family != 4 && f->family != 6) return 0;
    const uint8_t *s = f->family == 6 ? f->src_ip6 : f->src_ip4;
    const uint8_t *d = f->family == 6 ? f->dst_ip6 : f->dst_ip4;
    size_t n = f->family == 6 ? 16 : 4;
    uint8_t src = 0, dst = 0;
    for (size_t i = 0; i < n; i++) {
        src |= s[i];
        dst |= d[i];
    }
    return src != 0 && dst != 0;
}

static int probe_flow_equal(const d2k_addr_probe_flow *a,
                            const d2k_addr_probe_flow *b) {
    if ((a->family == 6) != (b->family == 6)) return 0;
    size_t n = a->family == 6 ? 16 : 4;
    const uint8_t *as = a->family == 6 ? a->src_ip6 : a->src_ip4;
    const uint8_t *ad = a->family == 6 ? a->dst_ip6 : a->dst_ip4;
    const uint8_t *bs = b->family == 6 ? b->src_ip6 : b->src_ip4;
    const uint8_t *bd = b->family == 6 ? b->dst_ip6 : b->dst_ip4;
    return a->transport == b->transport &&
           a->src_port_be == b->src_port_be && a->dst_port_be == b->dst_port_be &&
           memcmp(as, bs, n) == 0 && memcmp(ad, bd, n) == 0;
}

static void probe_drop(d2k_plantab *t, probe_entry *e) {
    if (!t || !e || !e->used) { return; }
    d2k_plan_free(e->plan);
    free(e->raw_guard);
    memset(e, 0, sizeof *e);
    t->probe_used--;
    t->revision++;
}

void d2k_plantab_clear_probes(d2k_plantab *t) {
    if (!t) return;
    for (size_t i = 0; i < t->used;) {
        /* Опыты контроллера и запрет QUIC (задача 50, раунд 4): ни то, ни
           другое не знание каталога; без контроллера снимать их некому. */
        if (t->v[i].kind == KEY_ENDPOINT_TRIAL || (t->v[i].kind == KEY_NAME &&
            (t->v[i].only_sport || d2k_plan_quic_deny(t->v[i].plan)))) {
            (void)drop(t, &t->v[i]);
        } else {
            i++;
        }
    }
    for (size_t i = 0; i < t->cap; i++) probe_drop(t, &t->probes[i]);
}

static int set_addr_probe_impl(d2k_plantab *t,
                               const d2k_addr_probe_flow *flow,
                               const uint8_t trial_id[D2K_TRIAL_ID_LEN],
                               uint64_t now_ns, uint64_t expires_ns,
                               d2k_plan *p,int measured) {
    if ((p && p->preflight) || (!measured && flow && flow->transport!=17) || !t || !probe_flow_valid(flow) || !trial_id_valid(trial_id) || !p ||
        expires_ns <= now_ns) {
        d2k_plan_free(p);
        return -2;
    }
    uint8_t shape = d2k_plan_proto(p) == 2 ? D2K_PLAN_SHAPE_QUIC :
                    d2k_plan_proto(p) == 3 ? D2K_PLAN_SHAPE_VOICE : D2K_PLAN_SHAPE_ANY;
    probe_entry *free_slot = NULL;
    for (size_t i = 0; i < t->cap; i++) {
        probe_entry *e = &t->probes[i];
        if (!e->used) {
            if (!free_slot) { free_slot = e; }
            continue;
        }
        if (e->expires_ns <= now_ns) {
            probe_drop(t, e);
            if (!free_slot) { free_slot = e; }
            continue;
        }
        if (!probe_flow_equal(&e->flow, flow)) { continue; }
        if (e->dns_length || memcmp(e->trial_id, trial_id, D2K_TRIAL_ID_LEN) != 0) {
            d2k_plan_free(p);
            return -3;
        }
        d2k_plan_free(e->plan);
        free(e->raw_guard);e->raw_guard=NULL;
        e->plan = p;
        bind_context(t, p, D2K_BIND_FLOW, flow->family ? flow->family : 4, shape, 1);
        e->expires_ns = expires_ns;
        t->revision++;
        return 0;
    }
    if (!free_slot) {
        d2k_plan_free(p);
        return -1;
    }
    free_slot->used = 1;
    free_slot->flow = *flow;
    memcpy(free_slot->trial_id, trial_id, D2K_TRIAL_ID_LEN);
    free_slot->expires_ns = expires_ns;
    free_slot->plan = p;
    bind_context(t, p, D2K_BIND_FLOW, flow->family ? flow->family : 4, shape, 1);
    t->probe_used++;
    t->revision++;
    return 0;
}

int d2k_plantab_set_addr_probe(d2k_plantab *t,const d2k_addr_probe_flow *flow,
    const uint8_t trial_id[16],uint64_t now_ns,uint64_t expires_ns,d2k_plan *p) {
    return set_addr_probe_impl(t,flow,trial_id,now_ns,expires_ns,p,0);
}
int d2k_plantab_set_dns_probe(d2k_plantab *t,const d2k_addr_probe_flow *flow,
    const uint8_t trial[16],uint64_t now,uint64_t expires,uint16_t length,
    const uint8_t digest[32],d2k_plan *p) {
    if (!t || !probe_flow_valid(flow) || (flow->family!=4 && flow->family!=6) ||
        !flow->src_port_be || !trial_id_valid(trial) || !digest || !p ||
        length<(flow->transport==6 ? 19 : 17) || length>274 ||
        d2k_plan_transport(p)!=flow->transport) {
        d2k_plan_free(p);
        return -2;
    }
    for (size_t i=0;i<t->cap;i++) {
        const probe_entry *e=t->probes+i;
        if (e->used && e->expires_ns>now && probe_flow_equal(&e->flow,flow)) {
            d2k_plan_free(p);
            return -3;
        }
    }
    int rc=set_addr_probe_impl(t,flow,trial,now,expires,p,1);
    if (rc)return rc;
    for (size_t i=0;i<t->cap;i++) {
        probe_entry *e=t->probes+i;
        if (e->used && e->plan==p) {
            e->dns_length=length;
            memcpy(e->dns_digest,digest,32);
            bind_context(t,p,D2K_BIND_FLOW,flow->family,D2K_PLAN_SHAPE_RAW,1);
            memcpy(p->binding_trial_id,trial,16);
            return 0;
        }
    }
    return -2;
}
const d2k_plan *d2k_plantab_find_dns_probe(d2k_plantab *t,const d2k_addr_probe_flow *flow,
    int controller_owned,const uint8_t *payload,size_t length,uint64_t now,uint8_t trial[16],int *reserved) {
    if (reserved)*reserved=0;
    if (!t || !controller_owned || !probe_flow_valid(flow) || !flow->src_port_be)return NULL;
    for (size_t i=0;i<t->cap;i++) {
        probe_entry *e=t->probes+i;
        if (!e->used || !e->dns_length)continue;
        if (e->expires_ns<=now) {probe_drop(t,e);continue;}
        if (!probe_flow_equal(&e->flow,flow))continue;
        if (reserved)*reserved=1;
        if (!payload || length!=e->dns_length)return NULL;
        uint8_t digest[32];d2k_sha256(payload,length,digest);
        if (memcmp(digest,e->dns_digest,sizeof digest))return NULL;
        if (trial)memcpy(trial,e->trial_id,16);
        return e->plan;
    }
    return NULL;
}
static void measured_flow(const d2k_ct_tuple *q,d2k_addr_probe_flow *f) {
    memset(f,0,sizeof *f);f->family=q->family;f->transport=q->proto;
    memcpy(q->family==6?f->src_ip6:f->src_ip4,q->src,q->family==6?16:4);
    memcpy(q->family==6?f->dst_ip6:f->dst_ip4,q->dst,q->family==6?16:4);
    memcpy(&f->src_port_be,q->sport_be,2);memcpy(&f->dst_port_be,q->dport_be,2);
}
int d2k_plantab_set_measured_probe(d2k_plantab *t,const struct d2k_rawmeasure_report *r,
    const uint8_t trial[16],const uint8_t plan_digest[32],uint64_t now,uint64_t expires,d2k_plan *p) {
    if(p && p->preflight) {d2k_plan_free(p);return -2;}
    if(!t||!d2k_rawmeasure_report_valid(r)||r->code!=D2K_RM_REPEAT_SILENT||!p||!plan_digest||
       d2k_plan_transport(p)!=r->request.tuple.proto||expires<=now) {d2k_plan_free(p);return -2;}
    d2k_addr_probe_flow f;measured_flow(&r->request.tuple,&f);
    /* Lease renewal: only this trial, only identical evidence and plan. A
       different trial on the flow is refused below and keeps its entry. */
    for(size_t i=0;i<t->cap;i++) {
        probe_entry *e=&t->probes[i];
        if(!e->used||!e->raw_guard||e->expires_ns<=now||!probe_flow_equal(&e->flow,&f)||
           memcmp(e->trial_id,trial,16))continue;
        uint8_t was[D2K_RM_REPORT_LEN],now_r[D2K_RM_REPORT_LEN];
        int same=!d2k_rawmeasure_report_write(was,sizeof was,e->raw_guard)&&
                 !d2k_rawmeasure_report_write(now_r,sizeof now_r,r)&&!memcmp(was,now_r,sizeof was)&&
                 !memcmp(e->raw_plan_digest,plan_digest,32);
        d2k_plan_free(p);
        if(!same)return -3;
        e->expires_ns=expires;t->revision++;return 0;
    }
    struct d2k_rawmeasure_report *guard=malloc(sizeof *guard);
    if(!guard){d2k_plan_free(p);return -1;}*guard=*r;
    int rc=set_addr_probe_impl(t,&f,trial,now,expires,p,1);
    if(rc){free(guard);return rc;}
    for(size_t i=0;i<t->cap;i++) {
        probe_entry *e=&t->probes[i];
        if(e->used&&probe_flow_equal(&e->flow,&f)&&!memcmp(e->trial_id,trial,16)) {
            e->raw_guard=guard;memcpy(e->raw_plan_digest,plan_digest,32);
            bind_context(t,p,D2K_BIND_FLOW,f.family,D2K_PLAN_SHAPE_RAW,1);
            memcpy(p->binding_trial_id,trial,16);
            return 0;
        }
    }
    free(guard);return -2;
}
const d2k_plan *d2k_plantab_find_measured_probe(d2k_plantab *t,const d2k_ct_tuple *tuple,
    const uint8_t epoch[16],uint64_t generation,uint32_t seq,const uint8_t *payload,size_t len,
    uint64_t now,uint8_t trial_out[16]) {
    if(!t||!tuple||!epoch||!generation||!payload||!len||len>D2K_RAWMEASURE_SAMPLE)return NULL;
    d2k_addr_probe_flow f;measured_flow(tuple,&f);if(!probe_flow_valid(&f))return NULL;
    for(size_t i=0;i<t->cap;i++) {
        probe_entry *e=&t->probes[i];if(!e->used)continue;
        if(e->expires_ns<=now){probe_drop(t,e);continue;}
        const struct d2k_rawmeasure_report *r=e->raw_guard;
        if(!r||!probe_flow_equal(&e->flow,&f)||r->request.generation!=generation||
           memcmp(r->request.epoch,epoch,16)||r->sample_len!=len||
           (tuple->proto==6&&r->sample_seq!=seq))continue;
        uint8_t digest[32];d2k_sha256(payload,len,digest);
        if(memcmp(digest,r->sample_digest,32))continue;
        if(trial_out)memcpy(trial_out,e->trial_id,16);
        return e->plan;
    }
    return NULL;
}

int d2k_plantab_del_addr_probe(d2k_plantab *t,
                               const d2k_addr_probe_flow *flow,
                               const uint8_t trial_id[D2K_TRIAL_ID_LEN]) {
    if (!t || !probe_flow_valid(flow) || !trial_id_valid(trial_id)) { return 0; }
    for (size_t i = 0; i < t->cap; i++) {
        probe_entry *e = &t->probes[i];
        if (e->used && probe_flow_equal(&e->flow, flow) &&
            memcmp(e->trial_id, trial_id, D2K_TRIAL_ID_LEN) == 0) {
            int removed = e->dns_length ? 2 : 1;
            probe_drop(t, e);
            return removed;
        }
    }
    return 0;
}

static const d2k_plan *find_probe(d2k_plantab *t, const d2k_addr_probe_flow *flow,
                                  uint64_t now_ns, uint8_t trial_id_out[D2K_TRIAL_ID_LEN],
                                  int voice) {
    if (!t || !probe_flow_valid(flow) || flow->src_port_be == 0) { return NULL; }
    for (size_t i = 0; i < t->cap; i++) {
        probe_entry *e = &t->probes[i];
        if (!e->used) { continue; }
        if (e->expires_ns <= now_ns) {
            probe_drop(t, e);
            continue;
        }
        if(e->raw_guard || e->dns_length)continue; /* Only guarded lookup may execute it. */
        int match;
        if (e->flow.src_port_be == 0) {
            /* Wildcard client port: voice only, every other field exact. */
            d2k_addr_probe_flow q = *flow;
            q.src_port_be = 0;
            match = voice && probe_flow_equal(&e->flow, &q);
        } else {
            match = probe_flow_equal(&e->flow, flow);
        }
        if (match) {
            if (trial_id_out) {
                memcpy(trial_id_out, e->trial_id, D2K_TRIAL_ID_LEN);
            }
            return e->plan;
        }
    }
    return NULL;
}

const d2k_plan *d2k_plantab_find_addr_probe(
    d2k_plantab *t, const d2k_addr_probe_flow *flow, uint64_t now_ns,
    uint8_t trial_id_out[D2K_TRIAL_ID_LEN]) {
    return find_probe(t, flow, now_ns, trial_id_out, 0);
}

const d2k_plan *d2k_plantab_find_voice_probe(
    d2k_plantab *t, const d2k_addr_probe_flow *flow, uint64_t now_ns,
    uint8_t trial_id_out[D2K_TRIAL_ID_LEN]) {
    return find_probe(t, flow, now_ns, trial_id_out, 1);
}

size_t d2k_plantab_probe_count(const d2k_plantab *t) {
    return t ? t->probe_used : 0;
}

/* Подходит ли запись наблюдаемой форме приветствия — ТРИ НАЗВАННЫХ ИСХОДА,
 * а не арифметика нулей.
 *
 *   совпало           — форма записи и форма наблюдения одна и та же;
 *   дедушкино право   — у записи формы не было (старый каталог по имени), и
 *                       отказать значило бы выключить работающий у человека
 *                       обход (адресные записи с v7 несут форму, задача 16);
 *   не подходит       — всё остальное, и в первую очередь ОБЪЯВЛЕННАЯ форма
 *                       записи против НЕИЗМЕРЕННОГО наблюдения.
 *
 * Последнее и есть исправление: раньше ноль наблюдения проходил к любой
 * записи, то есть «не измерено» выдавалось за доказанную совместимость. План,
 * подтверждённый на конкретном приветствии, не имеет права молча достаться
 * обращению, про форму которого мы ничего не знаем (0009, U5-R3).
 *
 * Дедушкино право НЕ ограничено транспортом намеренно: в каталоге есть
 * подтверждённые привязки QUIC, заведённые до появления поля формы, и
 * запретить их значило бы выключить работающий обход ради строгости, которую
 * старая запись всё равно не может подтвердить. Ограничение туда придёт
 * вместе с миграцией каталога, где у записи есть транспорт. */
static int shape_fits(uint8_t entry_shape, uint8_t seen_shape) {
    if (entry_shape == D2K_PLAN_SHAPE_GRANDFATHER) { return 1; }
    /* ECH offer is also used by GREASE. Preserve the old TLS-1.3 binding
     * when no dedicated ECH binding exists; never use ECH proof for non-ECH. */
    if (entry_shape == D2K_PLAN_SHAPE_MODERN && seen_shape == D2K_PLAN_SHAPE_ECH_TCP) return 1;
    return entry_shape != 0 && entry_shape == seen_shape;
}

/* Correlated production bindings attest exactly their declared form.
 * The old unbound catalog keeps its legacy MODERN/GREASE fallback. */
static int entry_shape_fits(const entry *e,uint8_t seen_shape) {
    return (!e->plan->binding_exact_shape || e->shape==seen_shape) && shape_fits(e->shape,seen_shape);
}

static inline int shape_is_udp(uint8_t shape) {
    return shape == D2K_PLAN_SHAPE_QUIC || shape == D2K_PLAN_SHAPE_VOICE;
}

size_t d2k_plantab_shape_misses(const d2k_plantab *t) {
    return t ? t->shape_misses : 0;
}

const d2k_plan *d2k_plantab_find(d2k_plantab *t, const uint8_t *name,
                                 size_t len, uint32_t addr_be, uint64_t now_ns,
                                 uint8_t seen_shape) {
    return d2k_plantab_find_sport(t, name, len, addr_be, now_ns, seen_shape, 0);
}

const d2k_plan *d2k_plantab_find_sport(d2k_plantab *t, const uint8_t *name,
                                       size_t len, uint32_t addr_be, uint64_t now_ns,
                                       uint8_t seen_shape, uint16_t sport_be) {
    return d2k_plantab_find_family(t, name, len, addr_be, now_ns, seen_shape, sport_be, 4);
}

const d2k_plan *d2k_plantab_find_family(d2k_plantab *t, const uint8_t *name,
    size_t len, uint32_t addr_be, uint64_t now_ns, uint8_t seen_shape,
    uint16_t sport_be, uint8_t family) {
    return d2k_plantab_find_target(t, name, len,
        family == 4 ? (const uint8_t *)&addr_be : NULL, family, now_ns, seen_shape, sport_be);
}

const d2k_plan *d2k_plantab_find_target(d2k_plantab *t, const uint8_t *name, size_t len,
    const uint8_t *addr, uint8_t family, uint64_t now_ns, uint8_t seen_shape, uint16_t sport_be) {
    return d2k_plantab_find_target_endpoint(t, name, len, addr, family, now_ns,
                                           seen_shape, sport_be, 0);
}

static const d2k_plan *find_target_endpoint_impl(d2k_plantab *t, const uint8_t *name, size_t len,
    const uint8_t *addr, uint8_t family, uint64_t now_ns, uint8_t seen_shape,
    uint16_t sport_be, uint16_t dport_be, uint8_t transport);

const d2k_plan *d2k_plantab_find_target_endpoint(d2k_plantab *t, const uint8_t *name, size_t len,
    const uint8_t *addr, uint8_t family, uint64_t now_ns, uint8_t seen_shape,
    uint16_t sport_be, uint16_t dport_be) {
    return find_target_endpoint_impl(t, name, len, addr, family, now_ns, seen_shape, sport_be, dport_be, 0);
}

static const d2k_plan *find_target_endpoint_impl(d2k_plantab *t, const uint8_t *name, size_t len,
    const uint8_t *addr, uint8_t family, uint64_t now_ns, uint8_t seen_shape,
    uint16_t sport_be, uint16_t dport_be, uint8_t transport) {
    if (!t || (family != 4 && family != 6)) {
        return NULL;
    }
    /* Первый QUIC Initial может ещё не нести собранное имя: его CRYPTO
       fragments будут собраны позже, а первый пакет нельзя выпускать без
       уже назначенного verifier-плана. У пробной записи есть независимый
       точный ключ — выделенный локальный порт единственного verifier-сокета.
       Разрешаем такой поиск только среди портовых записей подходящей формы;
       если порт почему-либо неоднозначен, ничего не применяем. Постоянные
       записи (only_sport == 0) и чужие потоки этим путём недоступны. */
    if ((!name || len == 0) && sport_be != 0) {
        entry *probe = NULL;
        for (size_t i = 0; i < t->used; i++) {
            entry *e = &t->v[i];
            if (e->kind != KEY_NAME || e->family != family || e->only_sport != sport_be ||
                !entry_shape_fits(e, seen_shape)) {
                continue;
            }
            if (probe) {
                return NULL;
            }
            probe = e;
        }
        if (probe) {
            probe->last_used_ns = now_ns;
            return probe->plan;
        }
        /* Обычный поток с пустым SNI всё ещё может иметь постоянный план по
           адресу. Отсутствие совпавшей пробной записи не должно его затенять. */
    }
    if (name && len) {
        /* ПРОБНАЯ ЗАПИСЬ ЭТОГО ПОТОКА — ПЕРВОЙ. Она поставлена под один
           конкретный местный порт (испытание кандидата), и если поток тот
           самый, судить его обязан именно испытуемый план. Для всех
           остальных потоков её как будто нет вовсе. */
        entry *e = NULL;
        if (sport_be != 0) {
            e = find_name_shape_port(t, name, len, seen_shape, sport_be, family);
            if (!e && seen_shape == D2K_PLAN_SHAPE_ECH_TCP)
                e = find_name_shape_port(t, name, len, D2K_PLAN_SHAPE_MODERN, sport_be, family);
            if (!e && seen_shape == D2K_PLAN_SHAPE_ANY) {
                /* Probe-specific SET_NAME carries the verifier's known shape;
                   a segmented ClientHello may not reveal it in its first
                   packet. Exact name+ephemeral-port identity is sufficient. */
                e = find_name_port(t, name, len, sport_be, family);
            }
            if (!e) {
                e = find_name_shape_port(t, name, len, D2K_PLAN_SHAPE_GRANDFATHER, sport_be, family);
            }
            if (e) {
                e->last_used_ns = now_ns;
                if (seen_shape == D2K_PLAN_SHAPE_ANY && e->only_sport == sport_be) {
                    return e->plan;
                }
                if (entry_shape_fits(e, seen_shape)) {
                    return e->plan;
                }
                t->shape_misses++;
                return NULL;
            }
        }
        /* Сперва запись СВОЕЙ формы: у имени их может быть несколько.
           Точная запись имени — собственное подтверждённое решение цели —
           сильнее исключения семейства (BYPASS): исключение снимает
           унаследованный план, а не чужой точный (Task 22, §7). Своей
           считается и запись TLS 1.3 для ECH-формы (тот же перенос, что
           ниже), и — для TCP TLS — дедушкина запись имени без формы:
           старое подтверждённое решение цели (финальное ревью, п.3, п.6).
           Один проход по таблице на промахе (п.7), порядок прежний. */
        name_hits h;
        scan_name(t, name, len, seen_shape, family, &h);
        e = h.shaped;
        if (!e && seen_shape == D2K_PLAN_SHAPE_ECH_TCP && h.modern && !h.modern->plan->binding_exact_shape) e = h.modern;
        if (!e && shape_transport(seen_shape) == 6) e = h.grandfather;
        /* A measured exact IP/port/shape is stronger than inherited area
           knowledge. Own name/probe and grandfather authority stay first;
           legacy whole-address fallback retains its old lower priority. */
        if (!e && !h.grandfather) {
            entry *service=find_endpoint_kind(t,addr,family,dport_be,seen_shape,transport,KEY_ENDPOINT_TRIAL);
            if(service && service->only_sport && service->only_sport!=sport_be)service=NULL;
            if(!service)service=find_endpoint(t,addr,family,dport_be,seen_shape,transport);
            if(service) {service->last_used_ns=now_ns;return service->plan;}
        }
        if (!e && area_bypassed(t, name, len, seen_shape, family)) return NULL;
        if (!e) {
            /* Дедушкино право — отдельная запись, и она подходит любой
               форме (см. shape_fits). Ищем её только когда своей нет. */
            e = h.grandfather;
        }
        if (!e) {
            const area_entry *area = area_match(t, name, len, seen_shape, family);
            /* ECH offers (including GREASE) retain the ordinary TLS 1.3
               suffix fallback, just like exact-name/address lookup. A
               dedicated ECH family wins; neither family's exception may
               be bypassed by inheriting the ordinary family instead. */
            if (!area && seen_shape == D2K_PLAN_SHAPE_ECH_TCP) {
                if (area_bypassed(t, name, len, D2K_PLAN_SHAPE_MODERN, family)) return NULL;
                area = area_match(t, name, len, D2K_PLAN_SHAPE_MODERN, family);
            }
            if (area) return area->plan;
            /* Имя знаем, а формы такой у него нет — это отдельный факт, см.
               счётчик ниже. */
            e = h.any;
        }
        if (e) {
            /* Обращение продлевает жизнь записи — см. d2k_plans.h про то,
               почему рабочая цель не должна вытесняться наравне с забытой.
               Отметку ставим и тогда, когда форма не подошла: обращение к
               цели было, и забывать запись раньше времени незачем. */
            e->last_used_ns = now_ns;
            if (entry_shape_fits(e, seen_shape)) {
                return e->plan;
            }
            if (e->shape != D2K_PLAN_SHAPE_ANY &&
                e->shape != D2K_PLAN_SHAPE_GRANDFATHER &&
                seen_shape != D2K_PLAN_SHAPE_ANY &&
                seen_shape != D2K_PLAN_SHAPE_GRANDFATHER &&
                shape_is_udp(seen_shape) && !shape_is_udp(e->shape)) {
                /* Запись другого транспорта (TCP TLS у имени при запросе QUIC)
                   не должна блокировать поиск адресного обхода для своего транспорта:
                   в частности, для QUIC ECH sched.c специально связывает план с адресом.
                   В обратную сторону (TCP-поток к имени с QUIC-записью) переход по
                   адресу запрещён: имя названо, чужой TCP-план соседа по CDN брать нельзя. */
                goto check_addr;
            }
            /* Форма не та — по адресу тоже не ищем: имя названо, и план
               соседа по CDN подставлять вместо него нельзя.

               Считаем отдельно: «плана для цели нет» срабатывает и на каждом
               не-приветствии, и по нему отличить «имени не знаем» от «знаем,
               но форма другая» невозможно. А различие это ровно то, из-за
               которого обход может молча не применяться. */
            t->shape_misses++;
            return NULL;
        }
    }
check_addr:;
    /* Exact service authority precedes legacy whole-address knowledge. It
       never transfers across ports or shapes, including TLS -> ECH. */
    entry *endpoint = find_endpoint_kind(t,addr,family,dport_be,seen_shape,transport,KEY_ENDPOINT_TRIAL);
    if(endpoint && endpoint->only_sport && endpoint->only_sport!=sport_be)endpoint=NULL;
    if(!endpoint)endpoint = find_endpoint(t, addr, family, dport_be, seen_shape, transport);
    if (endpoint) {
        endpoint->last_used_ns = now_ns;
        return endpoint->plan;
    }
    /* Только теперь по адресу: обратный порядок дал бы плану соседа по CDN
       перебить план, подтверждённый для этого имени. */
    /* Запись СВОЕЙ формы; ECH без своей — запись TLS 1.3 (как у имени);
       затем дедушкино право. Запись адреса другой формы не подходит: план,
       подтверждённый на STUN/голосе, QUIC Initial этого IP не достаётся, и
       наоборот (§5). */
    /* Один проход по таблице (финальное ревью, п.7), порядок прежний. */
    addr_hits a;
    scan_addr(t, addr, family, seen_shape, transport, &a);
    entry *e = a.shaped;
    if (!e && seen_shape == D2K_PLAN_SHAPE_ECH_TCP) e = a.modern;
    if (!e) e = a.grandfather;
    if (e) {
        e->last_used_ns = now_ns;
        return e->plan;
    }
    if (a.any) {
        /* Адрес знаем, а протокола такого у него нет — тот же отдельный
           факт, что и у имени. */
        t->shape_misses++;
    }
    return NULL;
}

const d2k_plan *d2k_plantab_find_target_endpoint_tr(d2k_plantab *t, const uint8_t *name, size_t len,
    const uint8_t *addr, uint8_t family, uint64_t now_ns, uint8_t seen_shape,
    uint16_t sport_be, uint16_t dport_be, uint8_t transport) {
    return find_target_endpoint_impl(t, name, len, addr, family, now_ns, seen_shape, sport_be, dport_be, transport);
}

size_t d2k_plantab_count(const d2k_plantab *t) {
    return t ? t->used : 0;
}

size_t d2k_plantab_capacity(const d2k_plantab *t) {
    return t ? t->cap : 0;
}

int d2k_plantab_binding(const d2k_plantab *t, const d2k_plan *p, d2k_binding_context *out) {
    if (!out) return 0;
    memset(out, 0, sizeof *out);
    if (!t || !p || p->binding_owner != t || !p->binding_generation) return 0;
    const uint8_t unknown[16] = {0};
    if (!memcmp(t->epoch, unknown, sizeof unknown)) return 0;
    out->generation = p->binding_generation;
    out->kind = p->binding_kind; out->family = p->binding_family;
    out->shape = p->binding_shape; out->temporary = p->binding_temporary;
    memcpy(out->epoch, t->epoch, sizeof out->epoch);
    return 1;
}

/* Разрешить ТОЧНУЮ ещё живую установку по её привязке. Поколение привязки —
 * монотонный счётчик таблицы, уникальный на установку, поэтому совпадение
 * привязки (d2k_binding_equal: поколение + эпоха таблицы + вид/семейство/форма/
 * временность) указывает ровно на тот план, который был выбран, независимо от
 * того, каким селектором его нашли (цель/имя/адрес/суффикс/проба). Возврат
 * того же плана, что и обычный путь, без ДУБЛИРОВАНИЯ выбора: переустановленные
 * те же байты несут новое поколение и сюда не попадут (NULL → отказ выше).
 * Пробы с истёкшим сроком (now_ns за expires_ns) пропускаем — область пробы
 * уже не живёт. Постоянные записи срока не имеют. */
const d2k_plan *d2k_plantab_find_by_binding(const d2k_plantab *t,
                                            const d2k_binding_context *b,
                                            uint64_t now_ns) {
    if (!t || !d2k_binding_known(b)) { return NULL; }
    d2k_binding_context c;
    for (size_t i = 0; i < t->used; i++) {
        if (t->v[i].plan && d2k_plantab_binding(t, t->v[i].plan, &c) &&
            d2k_binding_equal(&c, b)) { return t->v[i].plan; }
    }
    for (size_t i = 0; i < t->probe_used; i++) {
        const probe_entry *pe = &t->probes[i];
        if (!pe->used || !pe->plan) { continue; }
        if (pe->expires_ns && now_ns >= pe->expires_ns) { continue; }
        if (d2k_plantab_binding(t, pe->plan, &c) && d2k_binding_equal(&c, b)) {
            return pe->plan;
        }
    }
    for (size_t i = 0; i < t->suffix_used; i++) {
        if (t->suffixes[i].plan && d2k_plantab_binding(t, t->suffixes[i].plan, &c) &&
            d2k_binding_equal(&c, b)) { return t->suffixes[i].plan; }
    }
    for (size_t i = 0; i < t->bypass_used; i++) {
        if (t->bypasses[i].plan && d2k_plantab_binding(t, t->bypasses[i].plan, &c) &&
            d2k_binding_equal(&c, b)) { return t->bypasses[i].plan; }
    }
    return NULL;
}

int d2k_plantab_set_name_bound(d2k_plantab *t,const uint8_t *name,size_t len,
    uint64_t now_ns,d2k_plan *p,uint8_t shape,uint8_t family) {
    int rc=d2k_plantab_set_name_family(t,name,len,now_ns,p,shape,0,family);
    if(!rc)p->binding_exact_shape=1;
    return rc;
}

int d2k_plantab_set_name_trial(d2k_plantab *t, const uint8_t *name, size_t len,
    uint64_t now_ns, d2k_plan *p, uint8_t shape, uint16_t sport_be, uint8_t family,
    const uint8_t trial_id[D2K_TRIAL_ID_LEN]) {
    /* Legacy callers carry an all-zero token: install, but never invent proof. */
    if (!sport_be || !trial_id) { d2k_plan_free(p); return -2; }
    int rc = d2k_plantab_set_name_family(t,name,len,now_ns,p,shape,sport_be,family);
    if (!rc) memcpy(p->binding_trial_id,trial_id,D2K_TRIAL_ID_LEN);
    return rc;
}
void d2k_plantab_trial(const d2k_plantab *t, const d2k_plan *p,
                     uint8_t out[D2K_TRIAL_ID_LEN]) {
    memset(out,0,D2K_TRIAL_ID_LEN);
    if (t && p && p->binding_owner==t)
        memcpy(out,p->binding_trial_id,D2K_TRIAL_ID_LEN);
}
