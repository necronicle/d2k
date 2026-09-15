/* bridge.c — переходник: планировщик d2k зовёт ПЕРЕНЕСЁННЫЙ измеритель.
 *
 * ЧТО ЗДЕСЬ МЕНЯЕТСЯ ПО СУЩЕСТВУ. Прежнее дерево d2k (core/verdict.c) отвечало
 * на вопрос «какого класса блокировка» и на этом кончалось: чем именно брать
 * коробку, выяснял уже планировщик — отдельными вопросами, которые ставят план
 * командой и ждут события обмена через датапат. Перенесённый измеритель
 * отвечает на оба вопроса СРАЗУ и своими сокетами: его фаза свойств и его
 * перебор отравлений живут в том же блокирующем вызове, что и дерево. Поэтому
 * он возвращает не только вердикт, но и НАЙДЕННОЕ ПЛЕЧО (d2k_vres.have_arm).
 *
 * ПОЧЕМУ ПЕРЕХОДНИК, А НЕ ПРЯМАЯ ЗАМЕНА. Планировщик держит один крючок на
 * транспорт (d2k_sched_tcp_hook) с фиксированной сигнатурой, и её же подменяют
 * тесты, чтобы утверждать развилку по транспорту, не выходя в сеть. Ломать эту
 * точку ради переноса нельзя: тогда вместе с измерителем пришлось бы менять и
 * то, чем он проверяется.
 *
 * ЧЕГО ЗДЕСЬ НЕТ. Транспорт QUIC идёт своим путём (d2k_quic_classify) и этого
 * переходника не касается вовсе: дерево разреза потока к датаграмме
 * неприменимо — см. шапку d2k_quicprobe.h. Перенос вопросника QUIC — отдельная
 * работа, и молчать об этом нельзя: молчание читалось бы как «перенесено всё».
 */
#include "d2k_detect.h"

#include "d2k_arm.h"
#include "d2k_hello.h"
#include "d2k_verdict.h"

#include <stdio.h>
#include <string.h>

/* Плечо измерителя в термины сборщика планов.
 *
 * Возврат 0 — выразимо, -1 — язык плана этого не знает. Отказ здесь — пробел
 * РЕАЛИЗАЦИИ, а не отрицательное свойство коробки (0007 п.3): воздействие
 * найдено и на замере сработало, просто поставить его мы сегодня не умеем.
 * Подставлять «похожее» нельзя — это был бы план, отличающийся от того, что
 * прошло проверку. */
int d2k_arm_from_poison(const d2k_poison *p, d2k_arm *a, char *why, size_t whycap)
{
    memset(a, 0, sizeof(*a));
    if (p->syn_data) {
        snprintf(why, whycap, "данные в SYN языком плана не выражаются");
        return -1;
    }
    if (p->oob) {
        snprintf(why, whycap, "срочный байт (URG) языком плана не выражается");
        return -1;
    }
    if (p->md5) {
        snprintf(why, whycap, "опция TCP-MD5 языком плана не выражается");
        return -1;
    }
    /* The result crosses worker threads by value. Keep its display name
     * in d2k_vres.arm_name, not as a pointer into res.hit/the bridge stack. */
    a->name         = NULL;
    if (p->seq_shift != 0 && p->seq_shift != -66000) {
        snprintf(why, whycap, "сдвиг TCP seq %d не выражается флагом seq_out",
                 (int)p->seq_shift);
        return -1;
    }
    a->badsum       = p->badsum;
    a->repeats      = p->repeats > 0 ? (unsigned)p->repeats : 0u;
    /* In the original, TTL/seq-shift alone also send a fake (one by
     * default). The Plan builder needs this explicitly to emit its body. */
    if (a->repeats == 0 && d2k_poison_has_fake(p)) { a->repeats = 1; }
    a->gap_ms       = p->gap_ms > 0 ? (unsigned)p->gap_ms : 0u;
    a->disorder     = p->disorder;
    a->between      = p->fake_between;
    a->ttl          = p->ttl > 0 ? (unsigned)p->ttl : 0u;
    a->seq_out      = p->seq_shift != 0;
    a->decoy_hello  = p->decoy_hello;
    a->tcpts        = p->tcp_ts;
    a->ipidzero     = p->ip_id_zero;
    if (p->seqovl_exact) {
        /* «Длиной в целое приветствие» — не число, а правило: сборщик кладёт
         * туда приманку целиком. Задать то же число вручную не то же самое —
         * см. комментарий к seqovlExact у донора. */
        a->seqovl_hello = 1;
    } else if (p->seqovl > 0) {
        a->seqovl = (unsigned)p->seqovl;
    }
    return 0;
}

static d2k_verdict map_verdict(d2k_verdict_t v)
{
    switch (v) {
    case D2K_DV_CLEAR:        return D2K_V_CLEAR;
    case D2K_DV_PREFIX:       return D2K_V_PREFIX;
    case D2K_DV_WHOLE_PACKET: return D2K_V_WHOLE;
    case D2K_DV_OPAQUE:       return D2K_V_OPAQUE;
    /* Отравимая коробка — это ТОТ ЖЕ класс «решает содержимое»: разрез её не
     * берёт. Отличие не в классе, а в том, что мы знаем, чем её брать, и это
     * едет отдельным полем, а не подменой вердикта. */
    case D2K_DV_POISONABLE:   return D2K_V_OPAQUE;
    case D2K_DV_ADDRESS:      return D2K_V_ADDRESS;
    case D2K_DV_RESPONSE:     return D2K_V_RESPONSE;
    case D2K_DV_UNREACHABLE:  return D2K_V_UNREACHABLE;
    case D2K_DV_FLAKY:        return D2K_V_FLAKY;
    default:                  return D2K_V_INCONCLUSIVE;
    }
}

/* Крючок планировщика. Сигнатура — d2k_sched_tcp_fn, менять её нельзя. */
d2k_vres d2k_detect_sched_tcp(const char *ip, uint16_t port,
                              d2k_hello trigger, d2k_hello control,
                              uint32_t mark, int repeats,
                              uint32_t gap_us, uint32_t wait_ms)
{
    d2k_vres out;
    d2k_opts opt;
    d2k_trigger tr;
    d2k_result res;
    char addr[96];
    size_t off = 0, len = 0;

    memset(&out, 0, sizeof(out));
    memset(&opt, 0, sizeof(opt));
    memset(&tr, 0, sizeof(tr));

    if (!ip || !trigger.bytes || trigger.len < 2 || trigger.len > D2K_TRIGGER_MAX) {
        out.verdict = D2K_V_FLAKY;
        snprintf(out.reason, sizeof(out.reason),
                 "мерить нечем: снятого приветствия нет или оно не по размеру");
        return out;
    }

    /* ТРИГГЕР — СНЯТОЕ ПРИВЕТСТВИЕ, ПОБАЙТНО. Ни пересборки, ни подстановки
     * имени: форма приветствия и есть измерительный инструмент, и самодельная
     * мерила бы другую коробку, чем видит клиент (см. d2k_meas.h). */
    memcpy(tr.payload, trigger.bytes, trigger.len);
    tr.len = trigger.len;
    tr.accept = D2K_ACCEPT_SERVERHELLO;
    snprintf(tr.name, sizeof(tr.name), "tls:%s", ip);
    if (d2k_hello_sni(tr.payload, tr.len, &off, &len) == 0) {
        tr.sni_off = (int)off;
        tr.sni_len = (int)len;
    }

    if (control.bytes && control.len >= 2 && control.len <= D2K_TRIGGER_MAX) {
        memcpy(opt.control.payload, control.bytes, control.len);
        opt.control.len = control.len;
        opt.control.accept = D2K_ACCEPT_TLSRECORD;
        snprintf(opt.control.name, sizeof(opt.control.name), "control");
        /* Scheduler builds this automatically (currently disk.rzd.ru).
         * Supplying bytes does NOT promise that this target serves that
         * name. Match the original's automatic ControlTrigger path: a
         * silent unvouched control cannot prove an address block. The
         * scheduler hook carries no explicit operator-vouch argument. */
        opt.control_vouched = 0;
    }

    opt.repeats = repeats;
    opt.write_gap_ms = gap_us > 0 ? (int)(gap_us / 1000u) : 0;
    opt.timeout_ms = wait_ms > 0 ? (int)wait_ms : 0;
    /* МЕТКА — ОТ ВЫЗЫВАЮЩЕГО, а не зашитая. У z2k мимо очереди пропускает
     * 0x40000000, у d2k — своя (её задаёт --mark датапату, у владельца 0x2d).
     * Зашитая константа означала бы, что зонд идёт ЧЕРЕЗ наш же обход и мерит
     * его, а не коробку провайдера. */
    opt.mark = mark;

    snprintf(addr, sizeof(addr), "%s:%u", ip, (unsigned)port);
    d2k_classify_run(addr, &tr, &opt, &res);

    out.verdict = map_verdict(res.verdict);
    snprintf(out.reason, sizeof(out.reason), "%s", res.reason);
    out.split_pos = res.split_pos;
    out.probes = res.probes;
    /* Метку измеритель ставит всегда и на всех сокетах, но ПОДТВЕРЖДЕНИЯ, что
     * ядро её приняло, у него нет — в отличие от d2k_meas с его крючком. Врать
     * «подтверждена» нельзя: на непомеченном зонде «обходить нечего» было бы
     * самоподтверждающимся (см. d2k_verdict.h). */
    out.marked = 0;
    if (res.has_hit) {
        char why[160];
        if (d2k_arm_from_poison(&res.hit, &out.arm, why, sizeof(why)) == 0) {
            snprintf(out.arm_name, sizeof(out.arm_name), "%s", res.hit.name);
            out.have_arm = 1;
        } else {
            /* Молчать об этом нельзя: иначе «плана нет» читается как «коробку
             * не взяли», а коробку как раз взяли — не выразили. */
            size_t n = strlen(out.reason);
            snprintf(out.reason + n, sizeof(out.reason) - n,
                     "; приём «%s» сработал, но планом не задаётся: %s", res.hit.name, why);
        }
    }
    return out;
}
