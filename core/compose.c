/* compose.c — свойства пересобирающей коробки и вывод плана для TCP.
 * Контракт и обоснования — в шапке d2k_compose.h; здесь реализация и то, что
 * относится именно к ней.
 *
 * ПОЧЕМУ D2K_PROPS_ASK НИЧЕГО НЕ ШЛЁТ В СЕТЬ.
 *
 * Пять Go-вопросов (internal/classify/properties.go, PropProbes) двойного
 * назначения: план, которым спрашивают, и есть план, которым обходят, если
 * вопрос пройдёт. На проводе это:
 *   - перекрытие слева — сегмент с seq ЛЕВЕЕ настоящих данных (seqovl);
 *   - счёт дубликатов, контрольная сумма, разбор протокола — фальшивка с
 *     ЗАВЕДОМО БИТОЙ TCP-суммой перед настоящей нагрузкой (poison badsum);
 *   - порядок сегментов — куски посланы НЕ в порядке их положения в потоке.
 * Всё это — управление seq/суммой/порядком отправки НИЖЕ уровня обычного
 * подключённого сокета. Единственный оракул, который эта задача потребляет,
 * d2k_meas (d2k_meas.h, задача 1), — обычный SOCK_STREAM: cuts_valid требует
 * строго возрастающих точек разреза, а send_all шлёт кусок за куском в
 * ЕСТЕСТВЕННОМ порядке без права на перекрытие или порченую сумму (meas.c).
 * Кроме порядка отправки, три из пяти вопросов физически не выразимы через
 * этот оракул вообще: обычный сокет получает от ядра ПРАВИЛЬНУЮ сумму на
 * каждый сегмент автоматически, и подделать её без пакетного доступа
 * невозможно из пространства пользователя.
 *
 * Управление пакетами такого уровня в проекте живёт в датапате (NFQUEUE) и
 * открывается ядру через протокол связи, который поднимает ПАРАЛЛЕЛЬНАЯ
 * задача 4 (core/link.c, изолированное дерево). У задачи 3 на задачу 4
 * зависимости нет (см. таблицу в progress.md той же SDD-папки), и на момент
 * этой задачи core/link.c не существует физически — заимствовать из него
 * нечего.
 *
 * Можно было бы изобразить «опрос» через один и тот же d2k_meas с обычными
 * разрезами вместо seqovl/reorder — но это не приближение, а подмена: сама
 * функция d2k_props_ask имеет смысл вызывать ТОЛЬКО после того, как
 * d2k_classify (verdict.c) уже вернула D2K_V_OPAQUE, а этот вердикт
 * ДОКАЗЫВАЕТ, что разрез на 1 (самый агрессивный из всех обычных разрезов)
 * уже не сработал. Пересборка потока не зависит от того, ГДЕ проходит
 * разрез — правильно собранный поток после пересборки побайтно одинаков
 * независимо от точки разреза, — так что ЛЮБОЙ следующий обычный разрез
 * гарантированно повторит тот же результат (тот же довод есть в шапке
 * d2k_verdict.h про то, почему дерево не пробует разрез правее единицы).
 * Значит "пять вопросов на обычных разрезах" на практике значили бы пять
 * платных заходов в сеть, которые вернут один и тот же уже известный ответ,
 * выданный за пять разных измерений, — то есть подмену измерения, а не его
 * упрощение. §2.4 запрещает превращать «не спрашивали» в «нет», но не менее
 * строго запрещает превращать «спросили не то» в «да»/«нет» — вектор из
 * одних D2K_P_UNKNOWN (memset ниже) единственный вариант, который не врёт.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "d2k_compose.h"
#include "d2k_hello.h"

/* --------------------------------------------------------------------
 * d2k_props_ask — см. большой комментарий в шапке файла.
 * -------------------------------------------------------------------- */

d2k_props d2k_props_ask(const char *ip, uint16_t port, d2k_hello trigger,
                        d2k_hello control, uint32_t mark) {
    /* Аргументы — контракт интерфейса задачи (см. d2k_compose.h), а не
       мёртвый груз: они понадобятся реализации, которая появится вместе с
       протоколом связи задачи 4/5. Здесь они не участвуют ни в одном
       наблюдении ни при каких условиях (см. почему выше), и не использовать
       их молча — то же самое явное решение, что и просто их не принимать. */
    (void)ip;
    (void)port;
    (void)trigger;
    (void)control;
    (void)mark;

    d2k_props pr;
    memset(&pr, 0, sizeof pr);
    return pr;
}

/* --------------------------------------------------------------------
 * Сборка текста плана: append_fmt — единственная точка, где что-либо
 * пишется в буфер вызывающего, и единственная точка, где проверяется, что
 * это не вышло за cap. Переполнение — ОТКАЗ этого плана целиком (return -1),
 * а не усечение: усечённый план прочитать нельзя как правильный (то же
 * рассуждение, что у d2k_meas_once про точки разреза — тихая подмена на
 * похожее это тот же грех, что и пересборка, которую этот модуль как раз
 * измеряет).
 * -------------------------------------------------------------------- */

static int append_fmt(char *buf, size_t cap, size_t *pos, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *pos, cap - *pos, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *pos) {
        return -1;
    }
    *pos += (size_t)n;
    return 0;
}

/* Общая шапка любого плана этого файла: во всех шести Schema=1, MinExec=1
 * (plan.SchemaCurrent, properties.go), а plan.ID у Go-стороны здесь везде
 * нулевой — ни один из шести конструкторов (overlapPlan..everythingPlan) не
 * заполняет поле ID, каталожный идентификатор ("plan-XXXXXXXX") считается
 * ПОЗЖЕ и ОТДЕЛЬНО хэшем текста (planID(text) в properties.go), а не хранится
 * в самом тексте плана. */
static int emit_header(char *buf, size_t cap, size_t *pos) {
    static const char zero32[] = "00000000000000000000000000000000000000";
    if (append_fmt(buf, cap, pos, "d2k-plan 1 1\n") != 0) { return -1; }
    if (append_fmt(buf, cap, pos, "id %.32s\n", zero32) != 0) { return -1; }
    if (append_fmt(buf, cap, pos, "proto tcp tls\n") != 0) { return -1; }
    return 0;
}

static int append_hex(char *buf, size_t cap, size_t *pos,
                       const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (append_fmt(buf, cap, pos, "%02x", b[i]) != 0) { return -1; }
    }
    return 0;
}

/* --------------------------------------------------------------------
 * Вопрос 1 — перекрытие слева (overlapPlan, properties.go:234-242).
 * decoy не нужен: приём про склейку потока, а не про имя.
 * -------------------------------------------------------------------- */
static int overlap_plan_text(char *buf, size_t cap) {
    size_t pos = 0;
    if (emit_header(buf, cap, &pos) != 0) { return -1; }
    /* overlapByte = {0x41} — сама приставка перекрытия, длина = длине
       приманки (plan.Seqovl не хранит число: см. комментарий у Seqovl,
       plan.go). PoisonID=0 у Seqovl не задан Go-стороной — печатается как
       poison=0 безусловно (см. Text(), text.go:93). */
    if (append_fmt(buf, cap, &pos, "payload 1 41\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "seqovl payload=1 poison=0\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "order forward\n") != 0) { return -1; }
    return 0;
}

/* --------------------------------------------------------------------
 * Вопрос 3 — порядок сегментов (reorderPlan, properties.go:264-275).
 *
 * ФОРМА ЗАФИКСИРОВАНА ЗАМЕРОМ ДОНОРА 07.09.2026 — НЕ ИЗОБРЕТАТЬ ЗАНОВО.
 * Резы {payload_start+1, sni_middle}, порядок reverse: три куска [0,1),
 * [1,mid), [mid,n) уходят на провод как [mid,n),[1,mid),[0,1) — хвост,
 * середина, голова. Первая редакция резала ОДНИМ AnchorHelloMiddle
 * (серединой ВСЕГО приветствия, а не имени) — донор совершил ту же ошибку
 * раньше (z2k-detect/internal/classify/raw_linux.go:667-690) и исправил её
 * тем же способом: рез по середине пакета чаще оставляет имя нетронутым в
 * одном куске, коробка получает осмысленное начало записи и спокойно ждёт
 * остаток. decoy не участвует: якорь sni_middle вычисляется датапатом из
 * sni_off/sni_len ТЕКУЩЕГО пакета, а не контроллером под конкретное имя. */
static int reorder_plan_text(char *buf, size_t cap) {
    size_t pos = 0;
    if (emit_header(buf, cap, &pos) != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "split payload_start +1\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "split sni_middle +0\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "order reverse\n") != 0) { return -1; }
    return 0;
}

/* --------------------------------------------------------------------
 * Общая форма вопросов 2, 4, 5 (badsumFakePlan, properties.go:321-333):
 * приманка с испорченной суммой ПЕРЕД настоящей нагрузкой, без TTL (TTL там
 * нужен только боевому плечу как страховка — здесь вопрос именно про сумму
 * и про разбор, подмешивать вторую порчу значило бы спрашивать не то, что
 * названо).
 * -------------------------------------------------------------------- */
static int badsum_fake_plan_text(const uint8_t *payload, size_t paylen,
                                  unsigned repeats, uint32_t gap_us,
                                  char *buf, size_t cap) {
    size_t pos = 0;
    if (emit_header(buf, cap, &pos) != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "payload 1 ") != 0) { return -1; }
    if (append_hex(buf, cap, &pos, payload, paylen) != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "poison 1 badsum\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos,
                    "fake payload=1 poison=1 repeats=%u gap_us=%u place=before\n",
                    repeats, (unsigned)gap_us) != 0) {
        return -1;
    }
    if (append_fmt(buf, cap, &pos, "order forward\n") != 0) { return -1; }
    return 0;
}

/* Вопрос 4 — контрольная сумма (checksumPlan, properties.go:285-288):
 * набивка 64×0x41, а НЕ приветствие — намеренно (task-4-plans.md, п.3):
 * коробка, что РАЗБИРАЕТ TLS, мусор проигнорирует и продолжит ждать
 * настоящее приветствие, и разница с вопросом «разбор протокола» именно в
 * этом, не косметическая. */
static int checksum_plan_text(char *buf, size_t cap) {
    uint8_t filler[64];
    memset(filler, 0x41, sizeof filler);
    return badsum_fake_plan_text(filler, sizeof filler, 1, 0, buf, cap);
}

/* Верхняя граница декой-приветствия: LEGACY-профиль весит 210 байт «в
 * живую» (core/profiles/legacy.hex, замер), имя в нём можно заменить на
 * decoy любой разумной длины — запас взят на несколько раз больше типичного
 * доменного имени. Почему LEGACY, а не MODERN, см. build_decoy_hello. */
#define D2K_COMPOSE_HELLO_MAX 600

/* Собирает приманку-приветствие для decoy ТЕМ ЖЕ путём, что и остальное
 * ядро — d2k_hello_from_profile (hello.c, задача 1), а не самодельными
 * байтами наподобие Go plan.Hello (build.go): самодельное приветствие уже
 * стоило каталога 06.09.2026 (см. шапку d2k_meas.h) — коробка сравнивает то,
 * что реально шлёт клиент, а не то, что "похоже на спецификацию".
 *
 * ПРОФИЛЬ ИМЕННО LEGACY, А НЕ MODERN — ограничение интерфейса, не вкус.
 * MODERN весит 1530 байт (замер: wc -c profiles/modern.hex после вырезания
 * комментариев / 2); в hex это 3060 символов — ОДНА строка "payload 1 <hex>"
 * не влезла бы в буфer плана (out[][2048], d2k_compose.h) даже без остальных
 * строк. LEGACY весит 210 байт «в живую» — 420 hex-символов, — и укладывается
 * в 2048 байт вместе с poison/fake/order с большим запасом.
 *
 * Сравнение с Go тут НЕ работает, и важно не перепутать: plan.Hello
 * (build.go:21) строит НЕ MODERN, а минимальное самодельное приветствие
 * ровно 76+len(sni) байт, причём отвергает имя длиннее 255 — то есть
 * структурно не может дать больше 331 байта. Для "disk.rzd.ru" это 87 байт.
 * Go не оглядывается на буфер по другой причине: Plan.Text() возвращает
 * строку неограниченной длины, а не потому, что его приветствие велико.
 * Здесь размер задан контрактом задачи 3 (char out[][2048]).
 *
 * Попутно: наш LEGACY — НАСТОЯЩИЙ захват, а Go-шная приманка самодельная.
 * По этому признаку C-сторона ближе к правилу «коробка сравнивает то, что
 * реально шлёт клиент», чем эталон. */
static int build_decoy_hello(const char *decoy, uint8_t *out, size_t cap, size_t *out_len) {
    if (!decoy || decoy[0] == '\0') { return -1; }
    return d2k_hello_from_profile(D2K_SHAPE_LEGACY, decoy, out, cap, out_len);
}

/* Вопрос 5 — разбор протокола (parseProtocolPlan, properties.go:293-299):
 * та же форма, что у checksumPlan, но приманка — целое правдоподобное
 * приветствие с decoy-именем, а не набивка. */
static int parse_protocol_plan_text(const char *decoy, char *buf, size_t cap) {
    uint8_t hello[D2K_COMPOSE_HELLO_MAX];
    size_t hello_len;
    if (build_decoy_hello(decoy, hello, sizeof hello, &hello_len) != 0) { return -1; }
    return badsum_fake_plan_text(hello, hello_len, 1, 0, buf, cap);
}

/* Вопрос 2 — счёт дубликатов (duplicatesPlan, properties.go:307-313): две
 * копии приманки с паузой 20000мкс — число и пауза наследованы из замера
 * донора (боевое плечо обходится ДВУМЯ копиями с разрывом, плотной очереди
 * нужно семь). */
static int duplicates_plan_text(const char *decoy, char *buf, size_t cap) {
    uint8_t hello[D2K_COMPOSE_HELLO_MAX];
    size_t hello_len;
    if (build_decoy_hello(decoy, hello, sizeof hello, &hello_len) != 0) { return -1; }
    return badsum_fake_plan_text(hello, hello_len, 2, 20000, buf, cap);
}

/* --------------------------------------------------------------------
 * everythingPlan (properties.go:369-394) — единственный честный кандидат при
 * ПОЛНОСТЬЮ неизмеренном векторе: перекрытие слева, разнесённая пара дублей
 * и порядок сегментов ОДНИМ планом. Разрез — тот же {payload_start+1,
 * sni_middle}, что и у reorder_plan_text (задача reorder-cut, ревью
 * 2026-09-06) — НЕ AnchorHelloMiddle, той же забракованной замером формы.
 * -------------------------------------------------------------------- */
static int everything_plan_text(const char *decoy, char *buf, size_t cap) {
    uint8_t hello[D2K_COMPOSE_HELLO_MAX];
    size_t hello_len;
    if (build_decoy_hello(decoy, hello, sizeof hello, &hello_len) != 0) { return -1; }

    size_t pos = 0;
    if (emit_header(buf, cap, &pos) != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "payload 1 ") != 0) { return -1; }
    if (append_hex(buf, cap, &pos, hello, hello_len) != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "\n") != 0) { return -1; }
    /* payload 2 — overlapByte, та же приставка {0x41}, что и у
       overlap_plan_text. */
    if (append_fmt(buf, cap, &pos, "payload 2 41\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "poison 1 badsum\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "split payload_start +1\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "split sni_middle +0\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos,
                    "fake payload=1 poison=1 repeats=2 gap_us=20000 place=before\n") != 0) {
        return -1;
    }
    if (append_fmt(buf, cap, &pos, "seqovl payload=2 poison=0\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "order reverse\n") != 0) { return -1; }
    return 0;
}

/* --------------------------------------------------------------------
 * d2k_compose — порт Go Compose (properties.go:153-223).
 *
 * Порядок веток — ИЗ GO-СТОРОНЫ буквально (см. её же комментарий на
 * properties.go:166-169: этот порядок СВОЙ, отличный от порядка опроса в
 * PropProbes — тот подчинён цене таймаута, а этот приоритету кандидата).
 * yes()/no() Go-стороны (nil-указатель на bool) здесь — прямое сравнение с
 * D2K_P_YES/D2K_P_NO: D2K_P_UNKNOWN не совпадает ни с тем, ни с другим,
 * ровно как nil не совпадал ни с *b==true, ни с *b==false.
 * -------------------------------------------------------------------- */
size_t d2k_compose(const d2k_props *pr, const char *decoy,
                   char out[][2048], size_t cap) {
    if (!pr || !out || cap == 0) { return 0; }
    size_t n = 0;

    if (pr->tolerates_left_overlap == D2K_P_NO && n < cap) {
        if (overlap_plan_text(out[n], 2048) == 0) { n++; }
    }
    if (pr->tolerates_reorder == D2K_P_NO && n < cap) {
        if (reorder_plan_text(out[n], 2048) == 0) { n++; }
    }
    if (pr->counts_duplicates == D2K_P_YES && n < cap) {
        if (duplicates_plan_text(decoy, out[n], 2048) == 0) { n++; }
    }
    /* Сумма продолжает тот же список только если ValidatesChecksum=NO не
       пришло ВМЕСТЕ с ParsesL7=YES — properties.go:185-207 объясняет, почему:
       вопрос «разбор протокола» пишет оба поля из ОДНОГО факта, и когда оба
       поля стоят одновременно, откуда взялось ValidatesChecksum=NO — от
       собственного прохода вопроса о сумме или от побочного эффекта вопроса
       о разборе — неотличимо, а checksumPlan (голая набивка) на коробке, что
       РАЗБИРАЕТ TLS, заведомо не пройдёт. */
    if (pr->validates_checksum == D2K_P_NO && pr->parses_l7 != D2K_P_YES && n < cap) {
        if (checksum_plan_text(out[n], 2048) == 0) { n++; }
    }
    if (pr->parses_l7 == D2K_P_YES && n < cap) {
        if (parse_protocol_plan_text(decoy, out[n], 2048) == 0) { n++; }
    }
    if (n == 0 && cap > 0) {
        /* Вектор пуст (или каждое подходящее плечо не собралось — см.
           doc-комментарий cap в d2k_compose.h): единственный честный
           кандидат — «всё сразу» (everythingPlan, properties.go:214-221),
           а не «плечей нет». */
        if (everything_plan_text(decoy, out[0], 2048) == 0) { n = 1; }
    }
    return n;
}
