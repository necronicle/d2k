#include "d2km_synth.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static int is_field(const d2km_arm *a, d2km_operator op, uint32_t field)
{
    return a->has_action && a->action.op == op && a->action.field == field;
}

/* Установленный факт «без воздействия — реакция коробки, с воздействием
 * op/field — прикладной успех». */
static const d2km_fact *relief_if(const d2km_box *b, d2km_operator op, uint32_t field,
                                  int server_answer_enough)
{
    for (size_t i = 0; i < b->fact_count; i++) {
        const d2km_fact *f = &b->facts[i];
        if (!d2km_fact_usable(f) || f->invariant || f->numeric)
            continue;
        if (!f->a.has_action && is_field(&f->b, op, field) &&
            d2km_result_is_box_reaction(f->ra) &&
            (f->rb.kind == D2KM_R_APP_OK ||
             (server_answer_enough && d2km_result_server_reached(f->rb))))
            return f;
    }
    return NULL;
}

/* «Коробка читает имя»: с другим именем реакции коробки нет, а сервер
 * ответил (§4.3 п. 1). Прикладного успеха с чужим именем может не быть —
 * у сервера нет сертификата на это имя, — а вывод о коробке тот же. */
static const d2km_fact *reads_name(const d2km_box *b)
{
    return relief_if(b, D2KM_OP_SET_FIELD, D2KM_TLS_F_SNI, 1);
}

/* Числовой факт по полю: граница между f->a.value и f->b.value; *hop —
 * наименьшее значение со сменой исхода. Если таких фактов несколько,
 * берётся самый свежий по версии модели. */
static const d2km_fact *boundary(const d2km_box *b, uint32_t field, int64_t *hop)
{
    const d2km_fact *best = NULL;
    for (size_t i = 0; i < b->fact_count; i++) {
        const d2km_fact *f = &b->facts[i];
        if (!d2km_fact_usable(f) || !f->numeric ||
            !is_field(&f->a, D2KM_OP_LIMIT_DELIVERY, field) ||
            !is_field(&f->b, D2KM_OP_LIMIT_DELIVERY, field))
            continue;
        if (best == NULL || f->model_version >= best->model_version)
            best = f;
    }
    if (best != NULL)
        *hop = best->b.action.value;   /* a < b по построению числового факта */
    return best;
}

/* Запись «почему» не обрезается молча: обрезанная теряет номера фактов. */
static int why_write(char *buf, size_t cap, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int n = vsnprintf(buf, cap, format, args);
    va_end(args);
    return n >= 0 && (size_t)n < cap;
}
#define WHY(buf, ...) why_write((buf), sizeof(buf), __VA_ARGS__)

static void say(char *r, size_t cap, const char *msg)
{
    if (r != NULL && cap)
        snprintf(r, cap, "%s", msg);
}

d2km_synth_code d2km_synth_message(const d2km_synth_in *in, d2km_program *p,
                                      char *reason, size_t cap)
{
    if (in == NULL || in->box == NULL || p == NULL || in->client_hello == NULL || in->pass_name == NULL)
        return D2KM_SYN_BAD_INPUT;
    memset(p, 0, sizeof(*p));
    p->transport = D2KM_TCP;
    p->protocol = D2KM_P_TLS13;
    p->seed = in->seed;
    /* Сообщение: приветствие клиента, новые поля соединения от своего
       генератора, имя — пропускаемое. Остальная форма — клиента. */
    static d2km_tls_hello h;
    if (d2km_tls_parse(in->client_hello, in->client_hello_length, &h) != D2KM_TLS_OK) {
        say(reason, cap, "приветствие клиента не разбирается грамматикой TLS");
        return D2KM_SYN_BAD_INPUT;
    }
    d2km_rng rng;
    d2km_rng_seed(&rng, in->seed);
    if (d2km_tls_refresh(&h, &rng) != D2KM_TLS_OK ||
        d2km_tls_set_sni(&h, in->pass_name) != D2KM_TLS_OK) {
        say(reason, cap, "имя не встаёт в приветствие клиента по грамматике");
        return D2KM_SYN_REQ_CONFLICT;
    }
    size_t n = d2km_tls_build(&h, p->payloads[0].bytes, sizeof(p->payloads[0].bytes));
    /* Фальшивка — наше сообщение: если она длиннее посылки исполнителя,
       грамматика позволяет её ужать — убрать padding и оставить в key_share
       только X25519 (клиент вправе предложить меньше ключей, RFC 8446
       §4.2.8). Сработает ли ужатая фальшивка на коробке, решает испытание. */
    char shrunk[160] = "";
    if (in->max_payload && n > in->max_payload) {
        size_t before = n;
        d2km_tls_drop_ext(&h, 21);
        for (size_t i = 0; i < h.ext_count; i++) {
            if (h.ext[i].type != 51) continue;
            const uint8_t *d = h.arena + h.ext[i].offset;
            size_t len = h.ext[i].length, q = 2;
            uint8_t keep[4 + 32 + 2];
            while (q + 4 <= len) {
                size_t kl = (size_t)(d[q + 2] << 8 | d[q + 3]);
                if (d[q] == 0x00 && d[q + 1] == 0x1d && kl == 32 && q + 4 + kl <= len) {
                    keep[0] = 0; keep[1] = 36;
                    memcpy(keep + 2, d + q, 36);
                    d2km_tls_put_ext(&h, 51, keep, 38);
                    break;
                }
                q += 4 + kl;
            }
            break;
        }
        n = d2km_tls_build(&h, p->payloads[0].bytes, sizeof(p->payloads[0].bytes));
        if (n == 0 || n > in->max_payload) {
            if (reason != NULL && cap)
                snprintf(reason, cap, "фальшивка %zu байт не влезает в посылку исполнителя (%zu байт) "
                         "даже без padding и лишних ключей", n ? n : before, in->max_payload);
            return D2KM_SYN_EXEC_UNSUPPORTED;
        }
        snprintf(shrunk, sizeof(shrunk), "; ужата с %zu до %zu байт — предел посылки исполнителя %zu",
                 before, n, in->max_payload);
    }
    /* Обратная проверка: собранное разбирается, и имя — то, что задано. */
    static d2km_tls_hello back;
    char got[256];
    if (n == 0 || d2km_tls_parse(p->payloads[0].bytes, n, &back) != D2KM_TLS_OK ||
        d2km_tls_sni(&back, got, sizeof(got)) != D2KM_TLS_OK ||
        strcmp(got, in->pass_name) != 0) {
        say(reason, cap, "собранная фальшивка не прошла обратный разбор");
        return D2KM_SYN_EXEC_UNSUPPORTED;
    }
    p->payload_count = 1;
    p->payloads[0].length = (uint16_t)n;
    const d2km_fact *name = reads_name(in->box);
    int fit = WHY(p->payloads[0].why,
             "приветствие по форме клиента с именем «%.80s»: коробка читает имя "
             "(F%u), это имя она пропускает (F%u); зерно %llu%s",
             in->pass_name, (unsigned)(name ? name->id : in->pass_name_fact), (unsigned)in->pass_name_fact,
             (unsigned long long)in->seed, shrunk);
    if (!fit) return D2KM_SYN_EXEC_UNSUPPORTED;
    return D2KM_SYN_CANDIDATE;
}

void d2km_synth_poison(d2km_poison *p, unsigned method, uint8_t hop)
{
    memset(p, 0, sizeof(*p));
    if (method == 0) p->ttl = hop;
    if (method == 1) p->tcpts = 1;
    if (method == 2) p->md5 = 1;
    if (method == 3) p->badsum = 1;
}

static int tried(const d2km_synth_in *in, const d2km_program *p)
{
    return in->target != NULL && d2km_box_tried(in->box, d2km_program_hash(p), in->target);
}

d2km_synth_code d2km_synth_tls(const d2km_synth_in *in, d2km_program *p,
                               d2km_fact_kind *need, char *reason, size_t cap)
{
    if (in == NULL || in->box == NULL || p == NULL || in->client_hello == NULL)
        return D2KM_SYN_BAD_INPUT;
    memset(p, 0, sizeof(*p));
    p->transport = D2KM_TCP;
    p->protocol = D2KM_P_TLS13;
    p->seed = in->seed;

    /* Все установленные разрезы: tried одного не исключает другие. */
    for (size_t ci = 0; ci < in->box->fact_count; ci++) {
        const d2km_fact *cut = &in->box->facts[ci];
        if (!d2km_fact_usable(cut) || cut->invariant || cut->numeric || cut->a.has_action ||
            !cut->b.has_action || cut->b.action.op != D2KM_OP_SPLIT ||
            (cut->b.action.field != D2KM_TLS_F_SNI && cut->b.action.field != D2KM_FIELD_RECORD) ||
            !d2km_result_is_box_reaction(cut->ra) || cut->rb.kind != D2KM_R_APP_OK) continue;
        int64_t off = cut->b.action.value;
        if (off < INT16_MIN || off > INT16_MAX) continue;
        p->split_count = 1;
        p->splits[0].anchor = cut->b.action.field == D2KM_FIELD_RECORD ? D2KM_AT_PAYLOAD_START : D2KM_AT_SNI_START;
        p->splits[0].offset = (int16_t)off;
        if (!WHY(p->splits[0].why,
                 "разрез %s%+lld: без него реакция коробки, с ним прикладной успех (F%u)",
                 cut->b.action.field == D2KM_FIELD_RECORD ? "PAYLOAD_START" : "SNI_START",
                 (long long)off, (unsigned)cut->id)) {
            say(reason, cap, "запись «почему» не помещается");
            return D2KM_SYN_EXEC_UNSUPPORTED;
        }
        if (!tried(in, p)) {
            say(reason, cap, "кандидат: разрез по установленному факту");
            return D2KM_SYN_CANDIDATE;
        }
        p->split_count = 0;
    }

    /* Правило 2: коробка читает имя — фальшивое приветствие, которое она
       разберёт, а сервер не получит. */
    const d2km_fact *name = reads_name(in->box);
    if (name == NULL) {
        if (need) *need = D2KM_F_PARSE;
        say(reason, cap, "не установлено, что коробка читает имя: нужен факт вида «Разбор»");
        return D2KM_SYN_NEED_FACT;
    }
    if (in->pass_name == NULL || in->pass_name_fact == 0) {
        if (need) *need = D2KM_F_NAME;
        say(reason, cap, "нет имени, которое коробка пропускает: нужен факт вида «Имя»");
        return D2KM_SYN_NEED_FACT;
    }
    int64_t box_hop = 0, server_hop = 0;
    const d2km_fact *fb = boundary(in->box, D2KM_FIELD_PATH_BOX, &box_hop);
    const d2km_fact *fs = boundary(in->box, D2KM_FIELD_PATH_SERVER, &server_hop);
    if (fs == NULL || (fb == NULL && !in->box_hop_unmeasurable)) {
        if (need) *need = D2KM_F_PATH;
        say(reason, cap, fb == NULL ? "не измерен хоп коробки: нужен факт вида «Путь»"
                                    : "не измерен хоп сервера: нужен факт вида «Путь»");
        return D2KM_SYN_NEED_FACT;
    }
    int ttl_valid = fb != NULL && box_hop >= 1 && box_hop <= 255 && box_hop < server_hop;
    int safe_transport = 0;
    for (size_t i = 0; i < in->box->fact_count; i++) {
        const d2km_fact *f = &in->box->facts[i];
        if (d2km_fact_usable(f) && f->kind == D2KM_F_PATH && f->invariant &&
            is_field(&f->b, D2KM_OP_SPOIL_TRANSPORT, D2KM_FIELD_SPOIL) &&
            f->b.action.value >= 1 && f->b.action.value <= 3 &&
            f->ra.kind == D2KM_R_APP_OK && f->rb.kind == D2KM_R_APP_OK) safe_transport = 1;
    }
    if (!ttl_valid && !safe_transport && fb == NULL) {
        /* Хоп коробки не измерить: остаётся порча транспорта — нужен ответ
           сервера о ней (вопрос B); все порчи отвечены и ни одна не
           безопасна — требования несовместимы. */
        unsigned answered = 0;
        for (size_t i = 0; i < in->box->fact_count; i++) {
            const d2km_fact *f = &in->box->facts[i];
            if (d2km_fact_usable(f) && f->kind == D2KM_F_PATH &&
                is_field(&f->b, D2KM_OP_SPOIL_TRANSPORT, D2KM_FIELD_SPOIL) &&
                f->b.action.value >= 1 && f->b.action.value <= 3)
                answered |= 1u << (unsigned)f->b.action.value;
        }
        if (answered != 14u) {
            if (need) *need = D2KM_F_PATH;
            say(reason, cap, "хоп коробки не измерить, нужна порча, которую сервер отвергает: нужен факт вида «Путь»");
            return D2KM_SYN_NEED_FACT;
        }
        say(reason, cap, "хоп коробки не измерить, а безопасной для сервера порчи нет: требования несовместимы");
        return D2KM_SYN_REQ_CONFLICT;
    }
    if (!ttl_valid && !safe_transport) {
        if (reason != NULL && cap)
            snprintf(reason, cap,
                 "фальшивка с TTL %lld дойдёт до сервера (сервер на хопе %lld): "
                 "F%u и F%u несовместимы с требованием «сервер не получает фальшивку»",
                 (long long)box_hop, (long long)server_hop, (unsigned)fb->id,
                 (unsigned)fs->id);
        return D2KM_SYN_REQ_CONFLICT;
    }

    d2km_synth_code built = d2km_synth_message(in, p, reason, cap);
    if (built != D2KM_SYN_CANDIDATE) return built;
    for (unsigned method = 0; method <= 3; method++) {
        if (!method && !ttl_valid) continue;
        const d2km_fact *safe = NULL, *copies = NULL;
        for (size_t i = 0; i < in->box->fact_count; i++) {
            const d2km_fact *f = &in->box->facts[i];
            if (!d2km_fact_usable(f)) continue;
            if (method && f->kind == D2KM_F_PATH && f->invariant &&
                !f->a.has_action && is_field(&f->b, D2KM_OP_SPOIL_TRANSPORT, D2KM_FIELD_SPOIL) &&
                f->b.action.value == (int64_t)method && f->ra.kind == D2KM_R_APP_OK &&
                f->rb.kind == D2KM_R_APP_OK) safe = f;
            if (f->kind == D2KM_F_ASSEMBLY && f->numeric &&
                is_field(&f->a, D2KM_OP_ADD_MESSAGE, D2KM_FIELD_FAKE_COPIES) &&
                is_field(&f->b, D2KM_OP_ADD_MESSAGE, D2KM_FIELD_FAKE_COPIES) &&
                f->a.action.value / 256 == (int64_t)method &&
                f->b.action.value / 256 == (int64_t)method &&
                f->rb.kind == D2KM_R_APP_OK) copies = f;
        }
        if (method && safe == NULL) continue;
        /* У каждого сочетания собственные R и k. Граница C относится
         * к fake-only и не заменяет число, проверенное вопросом D. */
        for (size_t ci = 0; ci <= in->box->fact_count; ci++) {
            const d2km_fact *combo = ci < in->box->fact_count ? &in->box->facts[ci] : NULL;
            unsigned k;
            int64_t pos = 0;
            if (combo) {
                if (!d2km_fact_usable(combo) || combo->kind != D2KM_F_ASSEMBLY ||
                    combo->invariant || combo->numeric ||
                    !is_field(&combo->a, D2KM_OP_SPLIT, D2KM_FIELD_FAKE_SPLIT) ||
                    !is_field(&combo->b, D2KM_OP_SPLIT, D2KM_FIELD_FAKE_SPLIT) ||
                    combo->b.action.value < 0 || combo->rb.kind != D2KM_R_APP_OK)
                    continue;
                int64_t encoded = combo->b.action.value / 512;
                if (encoded / 256 != (int64_t)method) continue;
                k = (unsigned)(encoded % 256);
                pos = combo->b.action.value % 512;
                if (combo->a.action.value != D2KM_COMBO_VALUE(method, k, 0) ||
                    (pos != 1 && pos != 3 && pos != 5 && pos != 257)) continue;
            } else {
                k = copies ? (unsigned)(copies->b.action.value % 256) : 1;
            }
            if (!k || k > 255) continue;
            const d2km_fact *number_fact = NULL;
            for (size_t i = 0; i < in->box->fact_count; i++) {
                const d2km_fact *f = &in->box->facts[i];
                if (d2km_fact_usable(f) && f->kind == D2KM_F_ASSEMBLY && f->numeric &&
                    is_field(&f->a, D2KM_OP_ADD_MESSAGE, D2KM_FIELD_FAKE_COPIES) &&
                    is_field(&f->b, D2KM_OP_ADD_MESSAGE, D2KM_FIELD_FAKE_COPIES) &&
                    f->a.action.value / 256 == (int64_t)method &&
                    f->b.action.value == D2KM_COPIES_VALUE(method, k) && f->rb.kind == D2KM_R_APP_OK)
                    number_fact = f;
            }
            p->fake_count = 1;
            p->fakes[0].payload = 0;
            p->fakes[0].repeats = (uint8_t)k;
            d2km_synth_poison(&p->fakes[0].poison, method, (uint8_t)box_hop);
            char number[180];
            int nw;
            if (number_fact)
                nw = snprintf(number, sizeof(number), "копий %u: числовая граница (F%u)", k, (unsigned)number_fact->id);
            else if (combo)
                nw = snprintf(number, sizeof(number), "копий %u: проверенное сочетание (F%u)", k, (unsigned)combo->id);
            else
                nw = fb ? snprintf(number, sizeof(number), "одна копия: коробка реагирует на одно приветствие (F%u)", (unsigned)fb->id)
                        : snprintf(number, sizeof(number), "одна копия: коробка читает имя в одном приветствии (F%u)", (unsigned)name->id);
            int fit = nw >= 0 && nw < (int)sizeof(number);
            if (!method)
                fit = fit && WHY(p->fakes[0].why,
                    "TTL %lld: с этого хопа коробка реагирует (F%u), сервер на хопе %lld (F%u); %s",
                    (long long)box_hop, (unsigned)fb->id, (long long)server_hop, (unsigned)fs->id, number);
            else
                fit = fit && WHY(p->fakes[0].why,
                    "порча %s, полный TTL: сервер отвергает фальшивку (F%u); %s",
                    method == 1 ? "tcpts" : method == 2 ? "md5" : "badsum", (unsigned)safe->id, number);
            p->split_count = 0;
            if (combo) {
                p->split_count = 1;
                p->splits[0].anchor = pos == 257 ? D2KM_AT_SNI_START : D2KM_AT_PAYLOAD_START;
                p->splits[0].offset = (int16_t)(pos == 257 ? 1 : pos);
                fit = fit && WHY(p->splits[0].why,
                    "разрез %s+%d вместе с фальшивкой R%u, копий %u даёт прикладной успех (F%u)",
                    pos == 257 ? "SNI_START" : "PAYLOAD_START", p->splits[0].offset,
                    method, k, (unsigned)combo->id);
            }
            if (!fit) {
                say(reason, cap, "запись «почему» не помещается");
                return D2KM_SYN_EXEC_UNSUPPORTED;
            }
            if (!tried(in, p)) {
                say(reason, cap, "кандидат: фальшивое приветствие по установленным фактам");
                return D2KM_SYN_CANDIDATE;
            }
        }
    }
    unsigned spoil_answered = 0;
    for (size_t i = 0; i < in->box->fact_count; i++) {
        const d2km_fact *f = &in->box->facts[i];
        if (d2km_fact_usable(f) && f->kind == D2KM_F_PATH &&
            is_field(&f->b, D2KM_OP_SPOIL_TRANSPORT, D2KM_FIELD_SPOIL) &&
            f->b.action.value >= 1 && f->b.action.value <= 3)
            spoil_answered |= 1u << (unsigned)f->b.action.value;
    }
    if (need) *need = spoil_answered != 14u ? D2KM_F_PATH : D2KM_F_ASSEMBLY;
    say(reason, cap, "недостающие факты: безопасность порчи для сервера; граница копий для метода R; сочетание фальшивки с разрезом");
    return D2KM_SYN_NEED_FACT;
}
