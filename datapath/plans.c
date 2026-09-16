/* plans.c — таблица планов по целям. */
#include <stdlib.h>
#include <string.h>

#include "d2k_plans.h"

enum { KEY_FREE = 0, KEY_NAME = 1, KEY_ADDR = 2 };

typedef struct {
    uint8_t  kind;
    uint8_t  name_len;
    uint8_t  name[D2K_TARGET_NAME_MAX];
    uint32_t addr_be;
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
    d2k_plan *plan;
} entry;

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
    /* Сколько раз запись НАШЛАСЬ, но не подошла по форме приветствия. */
    size_t   shape_misses;
    entry *v;
    size_t cap;
    size_t used;
};

d2k_plantab *d2k_plantab_new(size_t cap) {
    if (cap == 0) {
        return NULL;
    }
    d2k_plantab *t = calloc(1, sizeof *t);
    if (!t) {
        return NULL;
    }
    t->v = calloc(cap, sizeof *t->v);
    if (!t->v) {
        free(t);
        return NULL;
    }
    t->cap = cap;
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
    }
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

uint64_t d2k_plantab_revision(const d2k_plantab *t) { return t ? t->revision : 0; }

int d2k_plantab_stream_candidate(const d2k_plantab *t, const uint8_t *name,
                                size_t len, uint32_t addr_be, uint16_t sport_be) {
    if (!t) { return 0; }
    for (size_t i = 0; i < t->used; i++) {
        const entry *e = &t->v[i];
        if (!d2k_plan_stream_input(e->plan) ||
            (e->only_sport && e->only_sport != sport_be)) { continue; }
        if (e->kind == KEY_ADDR && e->addr_be == addr_be) { return 1; }
        if (e->kind == KEY_NAME &&
            (!name || !len || name_eq(e->name, e->name_len, name, len))) { return 1; }
    }
    return 0;
}

/* used, не cap — см. инвариант уплотнения в шапке файла. */
/* Запись имени БЕЗ ПРИВЯЗКИ К ПОТОКУ. Пробные записи (only_sport != 0) сюда
   не попадают намеренно: они существуют только для одного местного порта, и
   для всех прочих вопросов их как будто нет. Пропусти это — и пробный план
   утёк бы к пользователю через ветку «имя знаем, формы такой нет». */
static entry *find_name(d2k_plantab *t, const uint8_t *name, size_t len) {
    for (size_t i = 0; i < t->used; i++) {
        if (t->v[i].kind == KEY_NAME && t->v[i].only_sport == 0 &&
            name_eq(t->v[i].name, t->v[i].name_len, name, len)) {
            return &t->v[i];
        }
    }
    return NULL;
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
                                   uint8_t shape, uint16_t sport_be) {
    for (size_t i = 0; i < t->used; i++) {
        if (t->v[i].kind == KEY_NAME && t->v[i].shape == shape &&
            t->v[i].only_sport == sport_be &&
            name_eq(t->v[i].name, t->v[i].name_len, name, len)) {
            return &t->v[i];
        }
    }
    return NULL;
}

static entry *find_name_shape(d2k_plantab *t, const uint8_t *name, size_t len,
                              uint8_t shape) {
    return find_name_shape_port(t, name, len, shape, 0);
}

static entry *find_addr(d2k_plantab *t, uint32_t addr_be) {
    for (size_t i = 0; i < t->used; i++) {
        if (t->v[i].kind == KEY_ADDR && t->v[i].addr_be == addr_be) {
            return &t->v[i];
        }
    }
    return NULL;
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
    if (!t || !name || len == 0 || len > D2K_TARGET_NAME_MAX) {
        d2k_plan_free(p);
        return -2;
    }
    t->revision++;
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
        e = find_name(t, name, len);
        if (e && e->only_sport == 0 && e->shape != D2K_PLAN_SHAPE_GRANDFATHER) {
            e->last_used_ns = now_ns;
            d2k_plan_free(e->plan);
            e->plan = p;
            return 0;
        }
    }
    if (!e || e->shape != shape || e->only_sport != sport_be) {
        e = find_name_shape_port(t, name, len, shape, sport_be);
    }
    if (!e) {
        e = take_free_or_evict(t);
        if (!e) {
            d2k_plan_free(p);
            return -1;
        }
        t->used++;
        e->kind = KEY_NAME;
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
    if (!t) {
        d2k_plan_free(p);
        return -2;
    }
    t->revision++;
    entry *e = find_addr(t, addr_be);
    if (!e) {
        e = take_free_or_evict(t);
        if (!e) {
            d2k_plan_free(p);
            return -1;
        }
        t->used++;
        e->kind = KEY_ADDR;
        e->addr_be = addr_be;
    }
    /* Адрес не приветствие: формы у него нет по построению, и лечится это не
       проверкой при поиске, а честно названным исключением. */
    e->shape = D2K_PLAN_SHAPE_GRANDFATHER;
    e->last_used_ns = now_ns;
    d2k_plan_free(e->plan);
    e->plan = p;
    return 0;
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

int d2k_plantab_del_name(d2k_plantab *t, const uint8_t *name, size_t len) {
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
        entry *e = find_name(t, name, len);
        if (!e || drop(t, e) == 0) {
            break;
        }
        n++;
    }
    return n > 0;
}

int d2k_plantab_del_addr(d2k_plantab *t, uint32_t addr_be) {
    return t ? drop(t, find_addr(t, addr_be)) : 0;
}

/* Подходит ли запись наблюдаемой форме приветствия — ТРИ НАЗВАННЫХ ИСХОДА,
 * а не арифметика нулей.
 *
 *   совпало           — форма записи и форма наблюдения одна и та же;
 *   дедушкино право   — у записи формы не было (старый каталог, план по
 *                       адресу), и отказать значило бы выключить работающий
 *                       у человека обход;
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
    return entry_shape != 0 && entry_shape == seen_shape;
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
    if (!t) {
        return NULL;
    }
    if (name && len) {
        /* ПРОБНАЯ ЗАПИСЬ ЭТОГО ПОТОКА — ПЕРВОЙ. Она поставлена под один
           конкретный местный порт (испытание кандидата), и если поток тот
           самый, судить его обязан именно испытуемый план. Для всех
           остальных потоков её как будто нет вовсе. */
        entry *e = NULL;
        if (sport_be != 0) {
            e = find_name_shape_port(t, name, len, seen_shape, sport_be);
            if (!e) {
                e = find_name_shape_port(t, name, len, D2K_PLAN_SHAPE_GRANDFATHER, sport_be);
            }
            if (e) {
                e->last_used_ns = now_ns;
                if (shape_fits(e->shape, seen_shape)) {
                    return e->plan;
                }
                t->shape_misses++;
                return NULL;
            }
        }
        /* Сперва запись СВОЕЙ формы: у имени их может быть несколько. */
        e = find_name_shape(t, name, len, seen_shape);
        if (!e) {
            /* Дедушкино право — отдельная запись, и она подходит любой
               форме (см. shape_fits). Ищем её только когда своей нет. */
            e = find_name_shape(t, name, len, D2K_PLAN_SHAPE_GRANDFATHER);
        }
        if (!e) {
            /* Имя знаем, а формы такой у него нет — это отдельный факт, см.
               счётчик ниже. */
            e = find_name(t, name, len);
        }
        if (e) {
            /* Обращение продлевает жизнь записи — см. d2k_plans.h про то,
               почему рабочая цель не должна вытесняться наравне с забытой.
               Отметку ставим и тогда, когда форма не подошла: обращение к
               цели было, и забывать запись раньше времени незачем. */
            e->last_used_ns = now_ns;
            if (shape_fits(e->shape, seen_shape)) {
                return e->plan;
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
    /* Только теперь по адресу: обратный порядок дал бы плану соседа по CDN
       перебить план, подтверждённый для этого имени. */
    entry *e = find_addr(t, addr_be);
    if (e) {
        e->last_used_ns = now_ns;
        if (shape_fits(e->shape, seen_shape)) {
            return e->plan;
        }
        t->shape_misses++;
    }
    return NULL;
}

size_t d2k_plantab_count(const d2k_plantab *t) {
    return t ? t->used : 0;
}

size_t d2k_plantab_capacity(const d2k_plantab *t) {
    return t ? t->cap : 0;
}
