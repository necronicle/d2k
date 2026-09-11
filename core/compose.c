/* compose.c — свойства пересобирающей коробки и вывод плана для TCP.
 * Контракт и обоснования — в шапке d2k_compose.h; здесь реализация и то, что
 * относится именно к ней.
 *
 * ПОЧЕМУ D2K_PROPS_ASK ТЕПЕРЬ ШЛЁТ В СЕТЬ (задача 5, шаг 0).
 *
 * Пять Go-вопросов (internal/classify/properties.go, PropProbes) двойного
 * назначения: план, которым спрашивают, и есть план, которым обходят, если
 * вопрос пройдёт. На проводе это:
 *   - перекрытие слева — сегмент с seq ЛЕВЕЕ настоящих данных (seqovl);
 *   - счёт дубликатов, контрольная сумма, разбор протокола — фальшивка с
 *     ЗАВЕДОМО БИТОЙ TCP-суммой перед настоящей нагрузкой (poison badsum);
 *   - порядок сегментов — куски посланы НЕ в порядке их положения в потоке.
 * Всё это — управление seq/суммой/порядком отправки НИЖЕ уровня обычного
 * подключённого сокета: обычный SOCK_STREAM получает от ядра ПРАВИЛЬНУЮ сумму
 * на каждый сегмент автоматически, и подделать её без пакетного доступа
 * невозможно из пространства пользователя (см. d2k_meas — cuts_valid/
 * send_all там честно ограничены обычным возрастающим разрезом, meas.c).
 *
 * До этой задачи спросить было физически нечем: протокол связи с датапатом
 * (core/link.c, d2k_link.h) поднимала ПАРАЛЛЕЛЬНАЯ задача 4, и на момент
 * задачи 3 он не существовал — отсюда честный вектор из одних
 * D2K_P_UNKNOWN, который эта функция отдавала раньше (подробное рассуждение,
 * почему имитация измерения чужим приёмом была бы ХУЖЕ отказа, — в отчёте
 * задачи 3). Задача 4 эту связь дала (слияние 308cc44), и зависимость,
 * не объявленная в плане, закрывается здесь явно: d2k_props_ask ставит
 * план датапату командой SET_NAME (d2k_link_set_name), дожидается
 * подтверждения (D2K_EV_ACK), делает ОДНО обращение к цели тем же
 * приёмом, что d2k_meas_once (connect+одна посылка, без собственных
 * разрезов — сегментацию теперь делает датапат по плану, а не эта
 * функция), и читает исход СТРОГО по событию обмена датапата
 * (D2K_EV_EXCHANGE, порог d2k_ev_has_appdata) — НЕ по тому, что вернул
 * локальный recv(): обратное направление почти всегда слепо для
 * аппаратной разгрузки роутера, а датапат (NFQUEUE) стоит ДО неё
 * (см. большой комментарий у seen_types/d2k_ev_has_appdata, d2k_link.h).
 *
 * ПОЧЕМУ ПЛАНЫ СОБИРАЮТСЯ В TLV ЗДЕСЬ, А НЕ ЧЕРЕЗ *_plan_text НИЖЕ.
 * Функции ...plan_text в этом файле строят ЧЕЛОВЕЧЕСКУЮ форму плана
 * (d2k-plan N N\n...) — ту, что хранит каталог (d2k_cat_plan.text) и
 * печатает Go Plan.Text(). Исполнитель на датапате читает ТОЛЬКО
 * каноническую TLV-форму (datapath/include/d2k_plan.h: «разборщик текста
 * здесь был бы лишней поверхностью для ошибок в компоненте, чей вход
 * приходит из сети»), а компилятора «текст → TLV» на C-стороне нет и не
 * планируется (то же решение — docs/decisions/0002, зеркало Go, где этим
 * занимается ТОЛЬКО internal/plan, а не датапат). Строить текст, которому
 * всё равно нечем стать TLV, и парсить его тут же обратно — не перенос
 * логики, а лишний шов. Пяти зондам d2k_props_ask нужны ровно пять МАЛЫХ,
 * заранее известных по форме планов — они собираются в TLV прямо здесь,
 * маленькими помощниками ниже (tlv_rec/tlv_header и *_plan_tlv), по той же
 * раскладке полей, что datapath/plan_parse.c читает и internal/plan/tlv.go
 * пишет (коды записей и якоря — их приватное зеркало, не общий заголовок:
 * ни plan_internal.h, ни recID и т.п. в tlv.go не экспортированы НИКУДА —
 * см. комментарий у enum ниже). Совпадение раскладки проверяется тем же
 * способом, что и весь этот модуль с задачи 4 — настоящим ctlprobe
 * (test_compose.c), а не сравнением исходников на глаз.
 *
 * ПОЧЕМУ CONTROL ИДЁТ В ФАЛЬШИВКУ ВЕРБАТИМ, А НЕ ЧЕРЕЗ build_decoy_hello.
 * Вопросам «счёт дубликатов» и «разбор протокола» нужна приманка похожая на
 * целое приветствие (properties.go: duplicatesPlan/parseProtocolPlan берут
 * plan.Hello(decoy,0)). d2k_compose ниже синтезирует её профилем
 * (build_decoy_hello), потому что у него на входе только ИМЯ decoy строкой —
 * никаких снятых байт. У d2k_props_ask на входе НАСТОЯЩИЙ захват — control,
 * приветствие ДРУГОГО имени, снятое датапатом с живого клиента (того же
 * рода снимок, что и trigger). Синтезировать из него заново профилем —
 * отбросить более достоверные байты ради менее достоверных без единой
 * причины; этот модуль настаивает на настоящих байтах везде (см. шапку
 * d2k_meas.h про то, чего стоил самодельный hello 06.09.2026) — здесь тот же
 * принцип просто применён к байтам, которые уже есть на руках.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "d2k_compose.h"
#include "d2k_hello.h"
#include "d2k_link.h"
#include "d2k_plan.h" /* datapath/include — D2K_POISON_BADSUM, тот же публичный контракт, что уже читает d2k_link.h через d2k_ctl.h */

/* --------------------------------------------------------------------
 * Сборка канонической TLV-формы плана — см. большой комментарий в шапке
 * файла ("ПОЧЕМУ ПЛАНЫ СОБИРАЮТСЯ В TLV ЗДЕСЬ"). Коды записей и якоря —
 * ЗЕРКАЛО datapath/plan_internal.h (REC_*, ANCHOR_*, ORDER_*, PLACE_*) и
 * internal/plan/tlv.go (recID и т.п.) — значения подтверждены построчным
 * чтением plan_internal.h 11.09.2026, а не по памяти. Общего заголовка с
 * этими значениями нет НИ У ОДНОЙ стороны: plan_internal.h прямо говорит
 * "наружу торчит контракт из четырёх функций", а Go-константы в tlv.go —
 * package-private (lowercase); обе стороны держат свою копию, и совпадение
 * проверяет мостовой тест на их стороне и test_compose.c (настоящий
 * ctlprobe) на этой.
 * -------------------------------------------------------------------- */
enum {
    D2K_REC_PAYLOAD = 0x0010,
    D2K_REC_POISON  = 0x0011,
    D2K_REC_SPLIT   = 0x0100,
    D2K_REC_FAKE    = 0x0101,
    D2K_REC_SEQOVL  = 0x0102,
    D2K_REC_ORDER   = 0x0103
};
enum { D2K_REC_ID = 0x0001, D2K_REC_PROTO = 0x0002 };
enum { D2K_ANCHOR_PAYLOAD_START = 0, D2K_ANCHOR_SNI_MIDDLE = 5 };
enum { D2K_ORDER_FORWARD = 0, D2K_ORDER_REVERSE = 1 };
enum { D2K_PLACE_BEFORE = 0 };

static void wr16be(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* Дописывает одну запись TLV из ДВУХ частей подряд (a затем b), без сборки
 * временного буфера под их сумму — тот же приём, что d2k_emit.pre/pre_len
 * в datapath/include/d2k_plan.h (там ради packet-пути без выделений, тут
 * просто чтобы не копировать payload дважды: id-префикс да сами байты
 * приманки). b/blen может быть NULL/0 — тогда запись это просто a. */
static int tlv_rec(uint8_t *buf, size_t cap, size_t *pos, uint16_t typ,
                   const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    size_t vlen = alen + blen;
    if (vlen > 0xFFFFu || *pos + 4 > cap || cap - (*pos + 4) < vlen) { return -1; }
    buf[*pos + 0] = (uint8_t)(typ >> 8);
    buf[*pos + 1] = (uint8_t)typ;
    buf[*pos + 2] = (uint8_t)(vlen >> 8);
    buf[*pos + 3] = (uint8_t)vlen;
    if (alen) { memcpy(buf + *pos + 4, a, alen); }
    if (blen) { memcpy(buf + *pos + 4 + alen, b, blen); }
    *pos += 4 + vlen;
    return 0;
}

/* Заголовок (12 байт) плюс REC_ID (нулевой — идентификатор плана считает
 * каталог хэшем ТЕКСТА при сохранении, см. emit_header ниже; у зондов
 * d2k_props_ask текстовой формы и каталога вовсе нет, а плану на проводе
 * id всё равно только для чтения человеком) и REC_PROTO. n_records — уже
 * ИТОГОВОЕ число записей плана, включая эти две: у каждого из пяти зондов
 * оно известно заранее по форме (см. вызовы в *_plan_tlv ниже), поэтому
 * запись в один проход без второго прохода/патча длины постфактум. transport
 * всегда 6 (TCP) — d2k_props_ask, как и весь этот файл, только про TCP/TLS
 * (proto=1, см. emit_header). guards не бывают: minexec=1 достаточно
 * (Plan.NeedExec, plan.go — 2 только когда Guards!=0). */
static int tlv_header(uint8_t *buf, size_t cap, size_t *pos, uint16_t n_records) {
    if (*pos + 12 > cap) { return -1; }
    buf[*pos + 0] = 'D'; buf[*pos + 1] = '2'; buf[*pos + 2] = 'K'; buf[*pos + 3] = 'P';
    wr16be(buf + *pos + 4, 1); /* schema */
    wr16be(buf + *pos + 6, 1); /* minexec */
    wr16be(buf + *pos + 8, 0); /* флаги — обязаны быть 0 (plan_parse.c) */
    wr16be(buf + *pos + 10, n_records);
    *pos += 12;
    static const uint8_t id16[16] = { 0 };
    if (tlv_rec(buf, cap, pos, D2K_REC_ID, id16, sizeof id16, NULL, 0) != 0) { return -1; }
    uint8_t pr[2]; pr[0] = 6; pr[1] = 1; /* transport=TCP, proto=TLS */
    return tlv_rec(buf, cap, pos, D2K_REC_PROTO, pr, sizeof pr, NULL, 0);
}

/* Вопрос 1 — перекрытие слева (overlapPlan, properties.go:234-242): та же
 * приставка {0x41}, что и в overlap_plan_text — длина перекрытия равна
 * длине приманки (Seqovl не хранит число, см. её же комментарий в plan.go),
 * decoy не нужен. Записей: ID, PROTO, PAYLOAD, SEQOVL, ORDER = 5. */
static int overlap_plan_tlv(uint8_t *buf, size_t cap, size_t *out_len) {
    size_t pos = 0;
    if (tlv_header(buf, cap, &pos, 5) != 0) { return -1; }
    uint8_t pid[2]; wr16be(pid, 1);
    uint8_t ovl = 0x41;
    if (tlv_rec(buf, cap, &pos, D2K_REC_PAYLOAD, pid, sizeof pid, &ovl, 1) != 0) { return -1; }
    uint8_t so[4]; wr16be(so, 1); wr16be(so + 2, 0); /* payload_id=1, poison_id=0 */
    if (tlv_rec(buf, cap, &pos, D2K_REC_SEQOVL, so, sizeof so, NULL, 0) != 0) { return -1; }
    uint8_t ord = D2K_ORDER_FORWARD;
    if (tlv_rec(buf, cap, &pos, D2K_REC_ORDER, &ord, 1, NULL, 0) != 0) { return -1; }
    *out_len = pos;
    return 0;
}

/* Вопрос 3 — порядок сегментов (reorderPlan, properties.go:264-275): те же
 * два разреза, что и reorder_plan_text — {payload_start+1, sni_middle},
 * порядок reverse. decoy/якорь sni_middle не нужны здесь: якорь вычисляет
 * датапат из sni_off/sni_len ТЕКУЩЕГО пакета (anchor_offset, plan_apply.c).
 * Записей: ID, PROTO, SPLIT, SPLIT, ORDER = 5. */
static int reorder_plan_tlv(uint8_t *buf, size_t cap, size_t *out_len) {
    size_t pos = 0;
    if (tlv_header(buf, cap, &pos, 5) != 0) { return -1; }
    uint8_t s1[4]; wr16be(s1, D2K_ANCHOR_PAYLOAD_START); wr16be(s1 + 2, 1);
    if (tlv_rec(buf, cap, &pos, D2K_REC_SPLIT, s1, sizeof s1, NULL, 0) != 0) { return -1; }
    uint8_t s2[4]; wr16be(s2, D2K_ANCHOR_SNI_MIDDLE); wr16be(s2 + 2, 0);
    if (tlv_rec(buf, cap, &pos, D2K_REC_SPLIT, s2, sizeof s2, NULL, 0) != 0) { return -1; }
    uint8_t ord = D2K_ORDER_REVERSE;
    if (tlv_rec(buf, cap, &pos, D2K_REC_ORDER, &ord, 1, NULL, 0) != 0) { return -1; }
    *out_len = pos;
    return 0;
}

/* Общая форма вопросов 2, 4, 5 (badsumFakePlan, properties.go:321-333):
 * приманка с испорченной суммой ПЕРЕД настоящей нагрузкой, без TTL — тот же
 * смысл, что у badsum_fake_plan_text. Записей: ID, PROTO, PAYLOAD, POISON,
 * FAKE, ORDER = 6. */
static int badsum_fake_plan_tlv(const uint8_t *payload, size_t paylen,
                                uint8_t repeats, uint32_t gap_us,
                                uint8_t *buf, size_t cap, size_t *out_len) {
    size_t pos = 0;
    if (tlv_header(buf, cap, &pos, 6) != 0) { return -1; }
    uint8_t pid[2]; wr16be(pid, 1);
    if (tlv_rec(buf, cap, &pos, D2K_REC_PAYLOAD, pid, sizeof pid, payload, paylen) != 0) { return -1; }
    uint8_t po[8];
    wr16be(po, 1); po[2] = 0; po[3] = D2K_POISON_BADSUM; wr32be(po + 4, 0);
    if (tlv_rec(buf, cap, &pos, D2K_REC_POISON, po, sizeof po, NULL, 0) != 0) { return -1; }
    uint8_t fk[10];
    wr16be(fk, 1); wr16be(fk + 2, 1); fk[4] = repeats; fk[5] = D2K_PLACE_BEFORE;
    wr32be(fk + 6, gap_us);
    if (tlv_rec(buf, cap, &pos, D2K_REC_FAKE, fk, sizeof fk, NULL, 0) != 0) { return -1; }
    uint8_t ord = D2K_ORDER_FORWARD;
    if (tlv_rec(buf, cap, &pos, D2K_REC_ORDER, &ord, 1, NULL, 0) != 0) { return -1; }
    *out_len = pos;
    return 0;
}

/* Вопрос 4 — контрольная сумма (checksumPlan, properties.go:285-288):
 * набивка 64×0x41, а НЕ приветствие — та же причина, что у checksum_plan_text
 * (коробка, что РАЗБИРАЕТ TLS, мусор проигнорирует и продолжит ждать
 * настоящее приветствие). */
static int checksum_plan_tlv(uint8_t *buf, size_t cap, size_t *out_len) {
    uint8_t filler[64];
    memset(filler, 0x41, sizeof filler);
    return badsum_fake_plan_tlv(filler, sizeof filler, 1, 0, buf, cap, out_len);
}

/* Кодирует байты в шестнадцатеричную строку нижнего регистра, тем же
 * алфавитом, что весь остальной провод этого дерева (см. datapath/
 * test_ctl.c, core/test_link.c). out обязан быть не короче 2*n+1. */
static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[b[i] >> 4];
        out[2 * i + 1] = digits[b[i] & 0xFu];
    }
    out[2 * n] = '\0';
}

/* Ждёт событие вида want (и, если code_filter >= 0, с этим кодом ev.code) не
 * дольше deadline_ms суммарно, пропуская мимо остальное — тот же приём, что
 * next_of_kind в test_link.c, но с бюджетом по ВРЕМЕНИ, а не по числу попыток:
 * число попыток ничего не говорит о реальной длительности, а датапат волен
 * прислать сколько угодно посторонних событий (HELLO/SUSPECT от чужого
 * трафика) между нужными нам ACK/EXCHANGE. Возвращает 0 при находке (*out
 * заполнен), -1 иначе (тайм-аут всего бюджета, ошибка связи, обрыв). */
static int wait_for_event(int fd, uint16_t want, int code_filter,
                          uint32_t deadline_ms, d2k_ev *out,
                          char *err, size_t errcap) {
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - t0.tv_sec) * 1000L +
                          (now.tv_nsec - t0.tv_nsec) / 1000000L;
        if (elapsed_ms < 0) { elapsed_ms = 0; }
        if (elapsed_ms >= (long)deadline_ms) { return -1; }
        int rc = d2k_link_next(fd, out, (int)((long)deadline_ms - elapsed_ms), err, errcap);
        if (rc != 0) { return -1; } /* тайм-аут этого чтения = тайм-аут всего бюджета, либо ошибка */
        if (out->kind == want && (code_filter < 0 || out->code == (uint16_t)code_filter)) {
            return 0;
        }
    }
}

/* Потолок ожидания ОДНОГО шага (ack SET_NAME, событие обмена) — то же число,
 * что WAIT_CEIL_MS в meas.c (5000мс), то же происхождение (connectTimeout/
 * transportCeiling Go-стороны) и тот же смысл: страховка, а не ожидаемая
 * длительность. Ack по AF_UNIX между двумя процессами на одной машине —
 * миллисекунды; обмен с целью — сеть, которая может молчать. Одно число на
 * оба шага осознанно: изобретать второе без замера запрещено (проектное
 * правило "числа только из замера или наследования"). */
#define D2K_PROPS_ASK_WAIT_MS 5000

/* --------------------------------------------------------------------
 * d2k_props_ask — см. большой комментарий в шапке файла.
 * -------------------------------------------------------------------- */

d2k_props d2k_props_ask(int link_fd, const char *ip, uint16_t port,
                        d2k_hello trigger, d2k_hello control, uint32_t mark) {
    d2k_props pr;
    memset(&pr, 0, sizeof pr);

    if (link_fd < 0 || !ip || ip[0] == '\0' || !trigger.bytes || trigger.len == 0) {
        /* Нечем спросить: без связи с датапатом или без адреса и байт
           триггера ни один из пяти вопросов не задать — тройственная
           логика: не измерено, а не «нет» (§2.4). */
        return pr;
    }

    size_t sni_off = 0, sni_len = 0;
    char name[256];
    if (d2k_hello_sni(trigger.bytes, trigger.len, &sni_off, &sni_len) != 0 ||
        sni_len == 0 || sni_len >= sizeof name) {
        /* В триггере нет извлекаемого имени — SET_NAME нечем задать:
           датапат матчит план по имени, а не по адресу (d2k_link.h). */
        return pr;
    }
    memcpy(name, trigger.bytes + sni_off, sni_len);
    name[sni_len] = '\0';

    for (int i = 0; i < 5; i++) {
        uint8_t planbuf[2200]; /* control до 2048 байт (потолок D2K_EV_SHAPE.shape,
                                   d2k_link.h) плюс заголовок и записи —
                                   ID(20)+PROTO(6)+PAYLOAD-заголовок(6)+
                                   POISON(12)+FAKE(14)+ORDER(5) = 63, запас
                                   до 2200 округлением вверх. */
        size_t plan_len = 0;
        int built;

        switch (i) {
        case 0:
            built = overlap_plan_tlv(planbuf, sizeof planbuf, &plan_len);
            break;
        case 1:
            /* Счёт дубликатов нуждается в decoy-содержимом (control) — без
               него (не измерено само по себе, не «нет») вопрос не задать,
               и он просто пропускается, как пропускает соответствующее
               плечо d2k_compose при пустом decoy. */
            built = (control.bytes && control.len > 0)
                        ? badsum_fake_plan_tlv(control.bytes, control.len, 2, 20000,
                                              planbuf, sizeof planbuf, &plan_len)
                        : -1;
            break;
        case 2:
            built = reorder_plan_tlv(planbuf, sizeof planbuf, &plan_len);
            break;
        case 3:
            built = checksum_plan_tlv(planbuf, sizeof planbuf, &plan_len);
            break;
        default: /* 4 — разбор протокола: та же нужда в control, что и в 1 */
            built = (control.bytes && control.len > 0)
                        ? badsum_fake_plan_tlv(control.bytes, control.len, 1, 0,
                                              planbuf, sizeof planbuf, &plan_len)
                        : -1;
            break;
        }
        if (built != 0) {
            continue; /* этот вопрос сегодня не собрать — не измерено, дальше */
        }

        char hexbuf[2 * sizeof planbuf + 1];
        to_hex(planbuf, plan_len, hexbuf);

        char err[128];
        if (d2k_link_set_name(link_fd, name, 6, hexbuf, err, sizeof err) != 0) {
            continue; /* план не отправился вовсе — не измерено */
        }
        d2k_ev ack;
        if (wait_for_event(link_fd, D2K_EV_ACK, D2K_CMD_SET_NAME,
                           D2K_PROPS_ASK_WAIT_MS, &ack, err, sizeof err) != 0) {
            continue; /* ack не пришёл в срок — не измерено */
        }
        if (((ack.num >> 8) & 0xFFu) != 1) {
            /* Датапат отверг план (BAD_PLAN/BAD_ARGS/NO_ROOM) — это не
               наблюдение о коробке, а наш кандидат, которым сегодня нечем
               спросить (см. онAck в controller.go про то, почему причина
               отказа важна: NO_ROOM не по вине плана, но одинаково не даёт
               задать этот вопрос СЕЙЧАС). */
            continue;
        }

        /* Одно обращение к цели — connect + одна посылка целиком, как
           d2k_meas_once без собственных разрезов (n_cuts=0): сегментацию
           теперь делает датапат по только что поставленному плану, а не
           эта функция. Собственный вердикт d2k_meas_once (вернулось что-то
           по ЭТОМУ сокету локально или нет) здесь не читается — см. шапку
           файла про то, почему судит только датапат. */
        (void)d2k_meas_once(ip, port, trigger, NULL, 0, 0,
                            D2K_PROPS_ASK_WAIT_MS, mark, NULL);

        d2k_ev exch;
        int passed = wait_for_event(link_fd, D2K_EV_EXCHANGE, -1,
                                    D2K_PROPS_ASK_WAIT_MS, &exch, err, sizeof err) == 0 &&
                     d2k_ev_has_appdata(&exch);
        if (!passed) {
            continue; /* промах — не пишет ничего (§2.4, каждый Set в Go
                          начинается с if !passed { return }) */
        }

        switch (i) {
        case 0: pr.tolerates_left_overlap = D2K_P_NO; break;
        case 1: pr.counts_duplicates = D2K_P_YES; break;
        case 2: pr.tolerates_reorder = D2K_P_NO; break;
        case 3: pr.validates_checksum = D2K_P_NO; break;
        default:
            /* Разбор протокола пишет ОБА поля из ОДНОГО факта (properties.go,
               комментарий у Set вопроса «разбор протокола»): коробка
               разобрала приманку как TLS И проглотила сегмент с битой
               суммой — иначе испорченный сегмент не дошёл бы до разбора. */
            pr.parses_l7 = D2K_P_YES;
            pr.validates_checksum = D2K_P_NO;
            break;
        }
        /* Вопрос прошёл — это уже стратегия (двойное назначение плана,
           см. шапку файла), второй вопрос той же цели не задаётся: тот же
           принцип, что в controller.go verdictCandidates про то, почему до
           сбора НЕСКОЛЬКИХ подтверждённых свойств в одном поиске дело
           физически не доходит. */
        break;
    }

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

/* Верхняя граница декой-приветствия. До задачи 5 здесь всегда стоял
 * LEGACY (210 байт «в живую», core/profiles/legacy.hex, замер) — потолок был
 * 600. Задача 5 (шаг 0б) снимает это ограничение: профиль теперь выбирается
 * ПО ВИДУ СНЯТОГО ПРИВЕТСТВИЯ ЦЕЛИ (см. build_decoy_hello), и MODERN весит
 * 1530 байт (замер: wc -c profiles/modern.hex после вырезания комментариев /
 * 2). Запас — 1530 + 253 (максимальная длина имени по RFC 1035, на случай
 * decoy длиннее метки __SNI__, которую он заменяет) = 1783, округлено вверх
 * до 1800. */
#define D2K_COMPOSE_HELLO_MAX 1800

/* Собирает приманку-приветствие для decoy ТЕМ ЖЕ путём, что и остальное
 * ядро — d2k_hello_from_profile (hello.c, задача 1), а не самодельными
 * байтами наподобие Go plan.Hello (build.go): самодельное приветствие уже
 * стоило каталога 06.09.2026 (см. шапку d2k_meas.h) — коробка сравнивает то,
 * что реально шлёт клиент, а не то, что "похоже на спецификацию".
 *
 * ВИД ПРИМАНКИ — ПО ВИДУ СНЯТОГО ПРИВЕТСТВИЯ ЦЕЛИ, А НЕ НАЗНАЧЕН (задача 5,
 * шаг 0б). До этой задачи здесь всегда стоял LEGACY — ограничение
 * интерфейса задачи 3, а не вывод: char out[][2048] (тогдашний буфер
 * d2k_compose) не вмещал MODERN — 1530 байт приветствия дают 3060
 * hex-символов в ОДНОЙ строке "payload 1 <hex>", а буфер расширен до 4096
 * именно шагом 0б. Теперь профиль решает shape — вид СНЯТОГО приветствия
 * цели (d2k_hello_shape, а не приманки): §6 спеки говорит, что коробка может
 * по-разному относиться к TLS 1.2 и 1.3, и подсовывать ей приманку не того
 * вида значит мерить не ту коробку, что видит настоящий клиент. shape
 * известен из снимка цели — выбирать наугад нечего.
 *
 * D2K_SHAPE_UNKNOWN падает на LEGACY (меньший профиль) — безопасный запасной
 * вариант, а не угаданное измерение: это выбор ФОРМЫ ПРИМАНКИ, а не диагноз
 * о коробке, тройственная логика d2k_props здесь не участвует вовсе (та
 * логика — про то, что записывается в d2k_props, а не про то, каким видом
 * собран decoy).
 *
 * Попутно: этот профиль — НАСТОЯЩИЙ захват (снят один раз с настоящего
 * клиента, файлы .hex в core/profiles), а Go-шная приманка (plan.Hello, build.go)
 * самодельная — по этому признаку C-сторона ближе к правилу «коробка
 * сравнивает то, что реально шлёт клиент», чем эталон. */
static int build_decoy_hello(d2k_shape shape, const char *decoy,
                             uint8_t *out, size_t cap, size_t *out_len) {
    if (!decoy || decoy[0] == '\0') { return -1; }
    if (shape != D2K_SHAPE_MODERN) { shape = D2K_SHAPE_LEGACY; }
    return d2k_hello_from_profile(shape, decoy, out, cap, out_len);
}

/* Вопрос 5 — разбор протокола (parseProtocolPlan, properties.go:293-299):
 * та же форма, что у checksumPlan, но приманка — целое правдоподобное
 * приветствие с decoy-именем, а не набивка. */
static int parse_protocol_plan_text(d2k_shape shape, const char *decoy, char *buf, size_t cap) {
    uint8_t hello[D2K_COMPOSE_HELLO_MAX];
    size_t hello_len;
    if (build_decoy_hello(shape, decoy, hello, sizeof hello, &hello_len) != 0) { return -1; }
    return badsum_fake_plan_text(hello, hello_len, 1, 0, buf, cap);
}

/* Вопрос 2 — счёт дубликатов (duplicatesPlan, properties.go:307-313): две
 * копии приманки с паузой 20000мкс — число и пауза наследованы из замера
 * донора (боевое плечо обходится ДВУМЯ копиями с разрывом, плотной очереди
 * нужно семь). */
static int duplicates_plan_text(d2k_shape shape, const char *decoy, char *buf, size_t cap) {
    uint8_t hello[D2K_COMPOSE_HELLO_MAX];
    size_t hello_len;
    if (build_decoy_hello(shape, decoy, hello, sizeof hello, &hello_len) != 0) { return -1; }
    return badsum_fake_plan_text(hello, hello_len, 2, 20000, buf, cap);
}

/* --------------------------------------------------------------------
 * everythingPlan (properties.go:369-394) — единственный честный кандидат при
 * ПОЛНОСТЬЮ неизмеренном векторе: перекрытие слева, разнесённая пара дублей
 * и порядок сегментов ОДНИМ планом. Разрез — тот же {payload_start+1,
 * sni_middle}, что и у reorder_plan_text (задача reorder-cut, ревью
 * 2026-09-06) — НЕ AnchorHelloMiddle, той же забракованной замером формы.
 * -------------------------------------------------------------------- */
static int everything_plan_text(d2k_shape shape, const char *decoy, char *buf, size_t cap) {
    uint8_t hello[D2K_COMPOSE_HELLO_MAX];
    size_t hello_len;
    if (build_decoy_hello(shape, decoy, hello, sizeof hello, &hello_len) != 0) { return -1; }

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
size_t d2k_compose(const d2k_props *pr, d2k_shape target_shape, const char *decoy,
                   char out[][4096], size_t cap) {
    if (!pr || !out || cap == 0) { return 0; }
    size_t n = 0;
    size_t buflen = sizeof(out[0]); /* не литерал: буфер вызывающего меняет размер вместе с сигнатурой, не порознь */

    if (pr->tolerates_left_overlap == D2K_P_NO && n < cap) {
        if (overlap_plan_text(out[n], buflen) == 0) { n++; }
    }
    if (pr->tolerates_reorder == D2K_P_NO && n < cap) {
        if (reorder_plan_text(out[n], buflen) == 0) { n++; }
    }
    if (pr->counts_duplicates == D2K_P_YES && n < cap) {
        if (duplicates_plan_text(target_shape, decoy, out[n], buflen) == 0) { n++; }
    }
    /* Сумма продолжает тот же список только если ValidatesChecksum=NO не
       пришло ВМЕСТЕ с ParsesL7=YES — properties.go:185-207 объясняет, почему:
       вопрос «разбор протокола» пишет оба поля из ОДНОГО факта, и когда оба
       поля стоят одновременно, откуда взялось ValidatesChecksum=NO — от
       собственного прохода вопроса о сумме или от побочного эффекта вопроса
       о разборе — неотличимо, а checksumPlan (голая набивка) на коробке, что
       РАЗБИРАЕТ TLS, заведомо не пройдёт. */
    if (pr->validates_checksum == D2K_P_NO && pr->parses_l7 != D2K_P_YES && n < cap) {
        if (checksum_plan_text(out[n], buflen) == 0) { n++; }
    }
    if (pr->parses_l7 == D2K_P_YES && n < cap) {
        if (parse_protocol_plan_text(target_shape, decoy, out[n], buflen) == 0) { n++; }
    }
    if (n == 0 && cap > 0) {
        /* Вектор пуст (или каждое подходящее плечо не собралось — см.
           doc-комментарий cap в d2k_compose.h): единственный честный
           кандидат — «всё сразу» (everythingPlan, properties.go:214-221),
           а не «плечей нет». */
        if (everything_plan_text(target_shape, decoy, out[0], buflen) == 0) { n = 1; }
    }
    return n;
}
