/* verdict.c — дерево вердиктов. Порядок вопросов и то, почему он такой,
 * описаны в шапке d2k_verdict.h; здесь только реализация.
 *
 * Один d2k_meas() на каждый заданный вопрос дерева. Выходов у функции ДВА,
 * и это осознанно, а не расхождение с намерением:
 *   - ранний guard на структурно непригодный вход (триггер короче двух
 *     байт) — это отказ ДО всякого измерения, а не его исход, поэтому у
 *     него свой, более ранний return, и r.marked там 0 по построению
 *     (memset) — ни один опыт не задавался, подтверждать нечего;
 *   - у самого дерева (база → подтверждение → разрез на 1 → контроль) —
 *     ровно один return в самом низу. Марка прогона (r.marked, «метка
 *     подтверждена на КАЖДОМ опыте») копится по всем фактически заданным
 *     вопросам одинаково, и одна точка выхода — самый простой способ не
 *     забыть учесть её на каком-нибудь новом пути позже.
 */
#include <string.h>
#include <stdio.h>

#include "d2k_hello.h"
#include "d2k_meas.h"
#include "d2k_verdict.h"

/* Тип записи TLS «рукопожатие» (RFC 8446 §5.1). То же число названо в meas.c
 * (TLS_REC_HANDSHAKE) и в d2k_link.h (D2K_TLS_HANDSHAKE) — здесь оно нужно
 * ровно для одного вопроса: шлём мы TLS или чужой протокол. */
#define TLS_REC_HANDSHAKE 0x16

/* Похоже ли то, что мы шлём, на запись TLS. От ответа зависит ПРИЁМКА: у
 * приветствия TLS доказательством прохода может быть только ServerHello, а у
 * сырых байт чужого протокола — любой непустой ответ, потому что разбирать
 * чужой протокол ради вердикта незачем (TLSTrigger против RawTrigger у
 * донора, internal/classify/trigger.go). */
static int looks_like_tls(d2k_hello h) {
    return h.bytes != NULL && h.len > 0 && h.bytes[0] == TLS_REC_HANDSHAKE;
}

/* Оговорка к CLEAR: обратное направление не проверено.
 *
 * В TLS 1.2 сертификат сервера едет ОТКРЫТЫМ ТЕКСТОМ и содержит имя, и
 * коробка может пропустить запрос, а убить ОТВЕТ (§6 спеки и шапка
 * internal/classify/response.go донора). Дерево вердиктов меряет ровно одно
 * направление — клиент → сервер: наш ClientHello доходит, ServerHello
 * возвращается, и «проходит как есть» тут правда про запрос и, возможно,
 * неправда про жизнь. Зонда обратного направления (рукопожатие 1.2 до конца,
 * ProbeResponse у донора) в d2k сегодня нет вовсе, поэтому CLEAR обязан
 * сказать, чего он не мерил.
 *
 * MODERN оговорки не несёт, и это не поблажка: в TLS 1.3 всё после
 * ServerHello зашифровано, резать по имени в сертификате нечего, класса
 * блокировки не существует. UNKNOWN несёт оговорку тоже — вид приветствия не
 * разобран, и исключить 1.2 нечем (см. про UNKNOWN в d2k_hello.h: уверенный
 * неправильный ответ хуже честного «не знаю»). */
static const char *reverse_note(d2k_hello trigger) {
    switch (d2k_hello_shape(trigger.bytes, trigger.len)) {
    case D2K_SHAPE_MODERN:
        return "";
    case D2K_SHAPE_LEGACY:
        return "; форма TLS 1.2 — обратное направление не проверено";
    default:
        return "; вид приветствия не разобран — обратное направление не проверено";
    }
}

/* Оговорка к выводам о РАЗРЕЗЕ: на какой паузе между кусками он замерен.
 *
 * Пауза — параметр опыта, а не подробность реализации: боевое умолчание 60 мс
 * (§7 спеки, у донора WriteGap в withDefaults) существует затем, чтобы куски
 * гарантированно разъехались по разным сегментам. Нулевая пауза этого не
 * гарантирует — замерено прямо в этом дереве: «на петле два send подряд
 * попадают в один recv» (test_meas.c), и тогда опыт про место разреза
 * перестаёт быть опытом про место разреза. Вывод, снятый на одной паузе,
 * обязан называть её: на другой он может не повториться, а других дерево не
 * задаёт. */
static void pause_note(char *out, size_t cap, uint32_t gap_us) {
    if (gap_us == 0) {
        snprintf(out, cap, "замерено без пауз между кусками");
    } else {
        snprintf(out, cap, "замерено с паузой %u мкс между кусками", (unsigned)gap_us);
    }
}

/* Сколько ДОПОЛНИТЕЛЬНЫХ повторов задать базовому вопросу перед тем, как
 * вынести CLEAR — независимо от repeats. Ложный clear — худшая из ошибок
 * дерева: он ЗАКРЫВАЕТ поиск словами «обходить нечего», а человек остаётся
 * заблокирован. Число и обоснование не мои: перенесено из Go-донора один в
 * один (internal/classify/classify.go: clearConfirmRepeats, строки 96-103 и
 * применение в 262-278) — тот же принцип, что и «три повтора, не один»
 * везде в этом дереве, просто с удвоенной ставкой ровно там, где ошибиться
 * дороже всего. */
#define D2K_CLEAR_CONFIRM_REPEATS 2

d2k_vres d2k_classify(const char *ip, uint16_t port,
                       d2k_hello trigger, d2k_hello control,
                       uint32_t mark, int repeats,
                       uint32_t gap_us, uint32_t wait_ms) {
    d2k_vres r;
    memset(&r, 0, sizeof r);
    /* Копится по И: один неподтверждённый опыт гасит метку всего прогона —
       тот же принцип, что d2k_tally.marked внутри одной серии (d2k_meas.h),
       только уровнем выше: здесь серий несколько подряд. */
    int all_marked = 1;

    /* Тот же дефолт, что и в d2k_meas — здесь он ПРОДУБЛИРОВАН, а не просто
       передан насквозь, потому что сравнения ниже (pass == repeats) обязаны
       знать РЕАЛЬНОЕ число повторов, которое использует d2k_meas, а не
       что попало, если вызывающий передал <= 0. */
    if (repeats <= 0) { repeats = 3; }

    /* ПРИЁМКА — по одной на роль, и роли разные. Триггеру доказательством
       прохода служит только ServerHello; контролю достаточно любой записи
       TLS, включая алерт, потому что он отвечает на другой вопрос — жива ли
       линия, а не прошло ли имя (см. d2k_meas.h). */
    d2k_accept_fn acc_trig = looks_like_tls(trigger) ? d2k_accept_serverhello
                                                     : d2k_accept_any;
    d2k_accept_fn acc_ctl  = looks_like_tls(control) ? d2k_accept_tls_record
                                                     : d2k_accept_any;
    /* 96 байт: самая длинная оговорка — «замерено с паузой 4294967295 мкс
       между кусками», 76 байт с запасом на кириллицу в UTF-8 (два байта на
       букву). В 64 она молча теряла хвост. */
    char gap_note[96];
    pause_note(gap_note, sizeof gap_note, gap_us);

    /* Разрез на 1 определён только когда в приветствии есть что резать
       ПОСЛЕ первого байта — вопрос 2 дерева не имеет смысла на триггере
       короче двух байт. Это не «повторы разошлись» (обычный смысл FLAKY,
       см. d2k_verdict.h) — это «измерения не было вообще»: вход структурно
       непригоден для вопроса дерева, и причина обязана сказать это прямо,
       а не звучать как отчёт о невоспроизводимости того, чего не мерили. */
    if (trigger.len < 2) {
        r.verdict = D2K_V_FLAKY;
        snprintf(r.reason, sizeof r.reason,
                 "триггер короче двух байт — измерения не было: вход "
                 "структурно непригоден, резать не на чем");
        return r;
    }

    /* 1. БАЗА. Триггер целиком, ни одного разреза. */
    d2k_tally base = d2k_meas(ip, port, trigger, NULL, 0, gap_us, wait_ms, mark,
                              acc_trig, repeats);
    r.probes += repeats;
    if (!base.marked) { all_marked = 0; }

    if (base.pass == 0 && base.err == repeats) {
        r.verdict = D2K_V_UNREACHABLE;
        snprintf(r.reason, sizeof r.reason,
                 "нет TCP до цели: ни один из %d опытов не состоялся", repeats);
    } else if (base.pass > 0 && base.pass < repeats) {
        r.verdict = D2K_V_FLAKY;
        snprintf(r.reason, sizeof r.reason,
                 "база не воспроизводится: %d из %d — расхождение повторов "
                 "это flaky, а не округление в удобную сторону",
                 base.pass, repeats);
    } else if (base.pass == repeats) {
        /* ПОДТВЕРЖДЕНИЕ. Единственное место дерева с усиленным числом
           повторов — см. D2K_CLEAR_CONFIRM_REPEATS выше. Без него «3 из 3»
           выглядит как clear ровно так же, как «3 из 3, а следующие два
           дозвона уже молчат» — дереву нечем их различить. */
        d2k_tally confirm = d2k_meas(ip, port, trigger, NULL, 0, gap_us, wait_ms,
                                      mark, acc_trig, D2K_CLEAR_CONFIRM_REPEATS);
        r.probes += D2K_CLEAR_CONFIRM_REPEATS;
        if (!confirm.marked) { all_marked = 0; }

        if (confirm.err > 0) {
            r.verdict = D2K_V_FLAKY;
            snprintf(r.reason, sizeof r.reason,
                     "подтверждение базы: %d из %d опытов не состоялись — "
                     "ошибка транспорта, а не решение коробки",
                     confirm.err, D2K_CLEAR_CONFIRM_REPEATS);
        } else {
            int total_pass = base.pass + confirm.pass;
            int total_repeats = repeats + D2K_CLEAR_CONFIRM_REPEATS;
            if (total_pass != total_repeats) {
                r.verdict = D2K_V_FLAKY;
                snprintf(r.reason, sizeof r.reason,
                         "база не подтвердилась: итого %d из %d — ложный "
                         "clear дороже честного flaky", total_pass, total_repeats);
            } else if (all_marked) {
                r.verdict = D2K_V_CLEAR;
                snprintf(r.reason, sizeof r.reason,
                         "триггер проходит как есть, метка подтверждена "
                         "(%d/%d подряд) — обходить нечего%s",
                         total_pass, total_repeats, reverse_note(trigger));
            } else {
                /* Самоподтверждение: зонд шёл СКВОЗЬ наш обход, а не мимо
                   него (см. шапку d2k_verdict.h) — «обходить нечего» отсюда
                   не следует, вердикта нет. */
                r.verdict = D2K_V_INCONCLUSIVE;
                snprintf(r.reason, sizeof r.reason,
                         "триггер прошёл (%d/%d), но БЕЗ подтверждённой "
                         "метки SO_MARK — успех мог дать наш обход, а не "
                         "линия; clear не принимается", total_pass, total_repeats);
            }
        }
    } else {
        /* base.pass == 0 и хотя бы один опыт ДОШЁЛ (err < repeats) — цель
           отвечает молчанием на содержимое, а не сеть виновата. Идём
           дальше по дереву. */

        /* 2. ПОМОГАЕТ ЛИ РЕЗАТЬ ВООБЩЕ. Разрез после первого байта — самый
           агрессивный: в первом сегменте остаётся один байт. */
        size_t cut1 = 1;
        d2k_tally one = d2k_meas(ip, port, trigger, &cut1, 1, gap_us, wait_ms, mark,
                                 acc_trig, repeats);
        r.probes += repeats;
        if (!one.marked) { all_marked = 0; }

        if (one.err > 0) {
            /* ЛЮБАЯ ошибка транспорта в серии — не только полный отказ
               всех repeats. Один сбой на фазе SYN плюс два настоящих
               молчания дают pass==0 и 0<err<repeats: если бы порог был
               err==repeats, это молча провалилось бы в ветку «пересобирает
               ли коробку контроль», смешивая «не дозвонились» с «отбили» —
               то самое смешение, против которого дерево и писалось. Порог
               «любая ошибка» — как у донора, stopOnErr в
               classify.go:170-177. */
            r.verdict = D2K_V_FLAKY;
            snprintf(r.reason, sizeof r.reason,
                     "разрез на 1: %d из %d опытов не состоялись — ошибка "
                     "транспорта, а не решение коробки", one.err, repeats);
        } else if (one.pass > 0 && one.pass < repeats) {
            r.verdict = D2K_V_FLAKY;
            snprintf(r.reason, sizeof r.reason,
                     "разрез на 1 не воспроизводится: %d из %d", one.pass, repeats);
        } else if (one.pass == repeats) {
            /* Разрез на 1 прошёл единогласно — стратегия уже известна:
               split на 1 годится при любой границе сигнатуры правее.
               Дальше в дерево (граница, буфер пересборки) не идём — см.
               D2K_V_WHOLE в шапке заголовка. */
            r.verdict = D2K_V_PREFIX;
            r.split_pos = 1;
            snprintf(r.reason, sizeof r.reason,
                     "разрез на 1 проходит единогласно (%d/%d), %s — матчер "
                     "решает по первому байту, пересборка его не спасает",
                     one.pass, repeats, gap_note);
        } else {
            /* one.pass == 0 — разрез не помог. Прежде чем говорить
               «пересборка», исключаем, что дело вообще не в содержимом:
               контроль ДРУГИМ именем на ту же цель (§2.3 — d2k не
               утверждает блокировку по адресу). */
            d2k_tally ctl = d2k_meas(ip, port, control, NULL, 0, gap_us, wait_ms, mark,
                                     acc_ctl, repeats);
            r.probes += repeats;
            if (!ctl.marked) { all_marked = 0; }

            if (ctl.err > 0) {
                /* Тот же принцип, что и у разреза на 1 чуть выше — ЛЮБАЯ
                   ошибка транспорта, не только полный отказ. */
                r.verdict = D2K_V_FLAKY;
                snprintf(r.reason, sizeof r.reason,
                         "контроль другим именем: %d из %d опытов не "
                         "состоялись — ошибка транспорта, а не решение "
                         "коробки", ctl.err, repeats);
            } else if (ctl.pass > 0 && ctl.pass < repeats) {
                r.verdict = D2K_V_FLAKY;
                snprintf(r.reason, sizeof r.reason,
                         "контроль другим именем не воспроизводится: %d из %d",
                         ctl.pass, repeats);
            } else if (ctl.pass == repeats) {
                if (base.unproven > 0 || one.unproven > 0) {
                    /* Триггер НЕ молчал: на него отвечали — просто не
                       доказательством прохода. «Решает содержимое, поток
                       пересобирается» отсюда не следует: до кого дошли наши
                       байты и кто именно ответил, этот ответ не говорит.
                       Алерт инжектируют и коробки, и серверы (сервер
                       отвечает им на незнакомое имя), а различить инжект и
                       отказ сервера дереву нечем — значит, вердикта нет,
                       а не «пересборка». */
                    r.verdict = D2K_V_INCONCLUSIVE;
                    snprintf(r.reason, sizeof r.reason,
                             "на триггер ответили не доказательством прохода "
                             "(%d опытов из %d): алерт инжектируют и коробки, "
                             "и серверы — вердикта нет",
                             base.unproven + one.unproven, repeats * 2);
                } else {
                    r.verdict = D2K_V_OPAQUE;
                    snprintf(r.reason, sizeof r.reason,
                             "разрез не помог (%s), но контроль другим именем "
                             "прошёл (%d/%d) — решает содержимое, поток "
                             "пересобирается",
                             gap_note, ctl.pass, repeats);
                }
            } else if (ctl.unproven > 0) {
                /* Контроль ответил, и ответ не признан: у контроля приёмка
                   самая широкая — любая запись TLS, включая алерт, — а
                   пришло не это. Молчанием такое звать нельзя: «молчит вся
                   линия» и «линия ответила не тем» — разные состояния, и
                   вывод из них разный (§2.4). */
                r.verdict = D2K_V_INCONCLUSIVE;
                snprintf(r.reason, sizeof r.reason,
                         "контроль другим именем ответил не записью TLS "
                         "(%d из %d) — это не проход и не молчание; "
                         "вердикта нет", ctl.unproven, repeats);
            } else {
                r.verdict = D2K_V_INCONCLUSIVE;
                snprintf(r.reason, sizeof r.reason,
                         "молчит и контроль другим именем (0 из %d) — "
                         "отличить «режут наши байты» от «молчит вся линия» "
                         "нечем, вердикта нет (§2.3)", repeats);
            }
        }
    }

    r.marked = (mark != 0) && all_marked;
    return r;
}
