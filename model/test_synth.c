#include "d2km_synth.h"
#include "fixture.h"
#include "test.h"

static d2km_result R(d2km_result_kind k) { d2km_result r = {.kind = k}; return r; }

static d2km_arm_record rec(uint32_t e, int has, d2km_operator op, uint32_t field,
                           int64_t v, d2km_result r)
{
    d2km_arm_record a;
    memset(&a, 0, sizeof(a));
    a.experiment = e;
    fixture_context(&a.context);
    a.arm.has_action = has;
    a.arm.action.op = op;
    a.arm.action.field = field;
    a.arm.action.value = v;
    a.result = r;
    return a;
}

static size_t w16(uint8_t *p, size_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2; }

static size_t hello(uint8_t *out, const char *sni)
{
    uint8_t e[256]; size_t n = strlen(sni);
    w16(e, 0); w16(e + 2, n + 5); w16(e + 4, n + 3); e[6] = 0; w16(e + 7, n);
    memcpy(e + 9, sni, n);
    size_t el = 9 + n;
    uint8_t body[512]; size_t b = 0;
    b += w16(body + b, 0x0303);
    memset(body + b, 0x11, 32); b += 32;
    body[b++] = 0;
    b += w16(body + b, 2); b += w16(body + b, 0x1301);
    body[b++] = 1; body[b++] = 0;
    b += w16(body + b, el); memcpy(body + b, e, el); b += el;
    out[0] = 0x16; w16(out + 1, 0x0301); w16(out + 3, b + 4);
    out[5] = 1; out[6] = 0; w16(out + 7, b);
    memcpy(out + 9, body, b);
    return 9 + b;
}

static void add(d2km_box *b, d2km_fact *f) { CHECK(d2km_box_add_fact(b, f, NULL) == D2KM_BOX_OK); }

int main(void)
{
    static d2km_box box;
    static d2km_program p;
    d2km_box_init(&box, 1);
    uint8_t ch[512];
    size_t chn = hello(ch, "blocked.example");
    d2km_synth_in in = {.box = &box, .client_hello = ch, .client_hello_length = chn, .seed = 42};
    d2km_fact_kind need = 0;
    char why[300];
    d2km_result ok = R(D2KM_R_APP_OK), rst = R(D2KM_R_RST);
    d2km_arm_record base = rec(1, 0, 0, 0, 0, rst), ctl = rec(2, 0, 0, 0, 0, ok);

    /* Пустая модель — нужен факт, а не «всё сразу». */
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_NEED_FACT);
    CHECK(need == D2KM_F_PARSE);

    /* Коробка читает имя. */
    d2km_fact f;
    d2km_arm_record sni = rec(3, 1, D2KM_OP_SET_FIELD, D2KM_TLS_F_SNI, 1, ok);
    CHECK(d2km_fact_establish(&f, 10, D2KM_F_PARSE, &base, &sni, &ctl, ok, 0, 0) == D2KM_FR_OK);
    add(&box, &f);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_NEED_FACT && need == D2KM_F_NAME);
    in.pass_name = "passes.example"; in.pass_name_fact = 11;
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_NEED_FACT && need == D2KM_F_PATH);

    /* Хоп коробки 5 (на 4 реакции нет, на 5 есть), хоп сервера 11. */
    d2km_arm_record b4 = rec(20, 1, D2KM_OP_LIMIT_DELIVERY, D2KM_FIELD_PATH_BOX, 4, ok);
    d2km_arm_record b5 = rec(21, 1, D2KM_OP_LIMIT_DELIVERY, D2KM_FIELD_PATH_BOX, 5, rst);
    CHECK(d2km_fact_establish(&f, 12, D2KM_F_PATH, &b5, &b4, &ctl, ok, 1, 0) == D2KM_FR_OK && f.numeric);
    add(&box, &f);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_NEED_FACT && need == D2KM_F_PATH);
    d2km_arm_record s10 = rec(22, 1, D2KM_OP_LIMIT_DELIVERY, D2KM_FIELD_PATH_SERVER, 10, R(D2KM_R_SYN_SILENT));
    d2km_arm_record s11 = rec(23, 1, D2KM_OP_LIMIT_DELIVERY, D2KM_FIELD_PATH_SERVER, 11, ok);
    CHECK(d2km_fact_establish(&f, 13, D2KM_F_PATH, &s10, &s11, &ctl, ok, 1, 0) == D2KM_FR_OK);
    add(&box, &f);

    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(d2km_program_check(&p) == D2KM_PC_OK);
    CHECK(p.fake_count == 1 && p.fakes[0].poison.ttl == 5 && p.split_count == 0);
    CHECK(strstr(p.fakes[0].why, "F12") && strstr(p.fakes[0].why, "F13"));
    CHECK(strstr(p.payloads[0].why, "F10") && strstr(p.payloads[0].why, "F11"));
    /* Фальшивка — приветствие клиента с пропускаемым именем, по грамматике. */
    static d2km_tls_hello h;
    char name[64];
    CHECK(d2km_tls_parse(p.payloads[0].bytes, p.payloads[0].length, &h) == D2KM_TLS_OK);
    CHECK(d2km_tls_sni(&h, name, sizeof name) == D2KM_TLS_OK && !strcmp(name, "passes.example"));
    CHECK(h.random[0] != 0x11 || h.random[1] != 0x11);   /* Random — свой, не клиента */
    /* Воспроизводимо по зерну; другое зерно — другие байты, та же форма. */
    static d2km_program p2;
    CHECK(d2km_synth_tls(&in, &p2, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(p2.payloads[0].length == p.payloads[0].length &&
          !memcmp(p2.payloads[0].bytes, p.payloads[0].bytes, p.payloads[0].length));
    in.seed = 43;
    CHECK(d2km_synth_tls(&in, &p2, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(memcmp(p2.payloads[0].bytes, p.payloads[0].bytes, p.payloads[0].length) != 0);
    in.seed = 42;

    /* §7.1 п. 5: фальшивка длиннее посылки исполнителя ужимается по
       грамматике (padding, лишние ключи); не влезает — честный отказ. */
    {
        static d2km_tls_hello ph;
        static uint8_t padded[1024];
        CHECK(d2km_tls_parse(ch, chn, &ph) == D2KM_TLS_OK && d2km_tls_pad_to(&ph, 600) == D2KM_TLS_OK);
        size_t pn = d2km_tls_build(&ph, padded, sizeof padded);
        CHECK(pn == 600);
        d2km_synth_in pin = in;
        pin.client_hello = padded;
        pin.client_hello_length = pn;
        pin.max_payload = 400;
        CHECK(d2km_synth_tls(&pin, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
        CHECK(p.payloads[0].length <= 400 && strstr(p.payloads[0].why, "ужата с 599"));
        pin.max_payload = 50;
        CHECK(d2km_synth_tls(&pin, &p, &need, why, sizeof why) == D2KM_SYN_EXEC_UNSUPPORTED);
        CHECK(strstr(why, "не влезает") != NULL);
    }

    /* Контрпример цели запрещает повтор той же программы. */
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    d2km_counterexample failed = {.candidate = d2km_program_hash(&p), .experiment = 90,
        .result = {.kind = D2KM_R_RST}, .target = base.context.target};
    in.target = &base.context.target;
    CHECK(d2km_box_add_counter(&box, &failed) == D2KM_BOX_OK);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_NEED_FACT);
    CHECK(need == D2KM_F_PATH);
    d2km_target other_target = base.context.target;
    CHECK(d2km_target_name(&other_target, "other.example") == 0);
    in.target = &other_target;
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    in.target = &base.context.target;
    d2km_arm_record clean = rec(91, 0, 0, 0, 0, ok);
    d2km_arm_record poisoned = rec(92, 1, D2KM_OP_SPOIL_TRANSPORT, D2KM_FIELD_SPOIL, 1, ok);
    clean.context.form.hello_print++;
    poisoned.context = clean.context;
    CHECK(d2km_fact_establish_invariance(&f, 50, D2KM_F_PATH, &clean, &poisoned, &clean, ok, 1) == D2KM_FR_OK);
    add(&box, &f);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(p.fakes[0].poison.tcpts && !p.fakes[0].poison.ttl && strstr(p.fakes[0].why, "F50"));
    box.fact_count--; box.counter_count = 0;

    /* Коробка дальше сервера — требования несовместимы, а не «попробуем». */
    static d2km_box far;
    d2km_box_init(&far, 2);
    CHECK(d2km_fact_establish(&f, 10, D2KM_F_PARSE, &base, &sni, &ctl, ok, 0, 0) == D2KM_FR_OK); add(&far, &f);
    d2km_arm_record fb11 = rec(30, 1, D2KM_OP_LIMIT_DELIVERY, D2KM_FIELD_PATH_BOX, 11, ok);
    d2km_arm_record fb12 = rec(31, 1, D2KM_OP_LIMIT_DELIVERY, D2KM_FIELD_PATH_BOX, 12, rst);
    CHECK(d2km_fact_establish(&f, 14, D2KM_F_PATH, &fb11, &fb12, &ctl, ok, 1, 0) == D2KM_FR_OK); add(&far, &f);
    CHECK(d2km_fact_establish(&f, 13, D2KM_F_PATH, &s10, &s11, &ctl, ok, 1, 0) == D2KM_FR_OK); add(&far, &f);
    in.box = &far;
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_REQ_CONFLICT);
    CHECK(strstr(why, "F14") && strstr(why, "F13"));

    /* Разрез на имени снимает реакцию — программа только из разреза. */
    d2km_arm_record cut = rec(40, 1, D2KM_OP_SPLIT, D2KM_TLS_F_SNI, 2, ok);
    CHECK(d2km_fact_establish(&f, 15, D2KM_F_ASSEMBLY, &base, &cut, &ctl, ok, 0, 0) == D2KM_FR_OK); add(&far, &f);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(p.split_count == 1 && p.fake_count == 0 && p.splits[0].offset == 2 &&
          p.splits[0].anchor == D2KM_AT_SNI_START && strstr(p.splits[0].why, "F15"));
    CHECK(d2km_program_check(&p) == D2KM_PC_OK);

    /* Tried разрез не скрывает следующий обоснованный RECORD-разрез. */
    d2km_counterexample cut_failed = {.candidate = d2km_program_hash(&p), .experiment = 93,
        .result = {.kind = D2KM_R_RST}, .target = base.context.target};
    CHECK(d2km_box_add_counter(&far, &cut_failed) == D2KM_BOX_OK);
    d2km_arm_record header_cut = rec(94, 1, D2KM_OP_SPLIT, D2KM_FIELD_RECORD, 3, ok);
    CHECK(d2km_fact_establish(&f, 51, D2KM_F_ASSEMBLY, &base, &header_cut, &ctl, ok, 0, 1) == D2KM_FR_OK);
    add(&far, &f);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(p.split_count == 1 && p.splits[0].anchor == D2KM_AT_PAYLOAD_START &&
        p.splits[0].offset == 3 && strstr(p.splits[0].why, "PAYLOAD_START"));
    far.fact_count--; far.counter_count = 0;

    /* Понижённый факт в синтезе не используется. */
    d2km_arm_record again = rec(41, 1, D2KM_OP_SPLIT, D2KM_TLS_F_SNI, 2, rst);
    CHECK(d2km_box_observe(&far, &again) == 1);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_REQ_CONFLICT);

    /* Недоставку TTL нельзя использовать, но доказанная порча всё ещё
       безопасна даже если коробка стоит за сервером. */
    CHECK(d2km_fact_establish_invariance(&f, 52, D2KM_F_PATH, &clean, &poisoned, &clean, ok, 1) == D2KM_FR_OK);
    add(&far, &f);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(p.fakes[0].poison.tcpts && !p.fakes[0].poison.ttl);
    d2km_synth_in invalid = {.client_hello = ch, .client_hello_length = chn, .pass_name = "passes.example"};
    CHECK(d2km_synth_message(&invalid, &p, why, sizeof why) == D2KM_SYN_BAD_INPUT);

    /* Два обоснованных сочетания одного R: контрпример первого не
       исключает второго; копии другого R не подмешиваются. */
    in.box = &box;
    d2km_arm_record c7 = rec(100, 1, D2KM_OP_ADD_MESSAGE, D2KM_FIELD_FAKE_COPIES, D2KM_COPIES_VALUE(0, 7), rst);
    d2km_arm_record c8 = rec(101, 1, D2KM_OP_ADD_MESSAGE, D2KM_FIELD_FAKE_COPIES, D2KM_COPIES_VALUE(0, 8), ok);
    CHECK(d2km_fact_establish(&f, 60, D2KM_F_ASSEMBLY, &c7, &c8, &ctl, ok, 1, 1) == D2KM_FR_OK); add(&box, &f);
    c7.arm.action.value = D2KM_COPIES_VALUE(1, 254); c8.arm.action.value = D2KM_COPIES_VALUE(1, 255);
    CHECK(d2km_fact_establish(&f, 61, D2KM_F_ASSEMBLY, &c7, &c8, &ctl, ok, 1, 1) == D2KM_FR_OK); add(&box, &f);
    d2km_arm_record no_cut = rec(102, 1, D2KM_OP_SPLIT, D2KM_FIELD_FAKE_SPLIT, D2KM_COMBO_VALUE(0, 8, 0), rst);
    d2km_arm_record combo_cut = rec(103, 1, D2KM_OP_SPLIT, D2KM_FIELD_FAKE_SPLIT, D2KM_COMBO_VALUE(0, 8, 1), ok);
    CHECK(d2km_fact_establish(&f, 62, D2KM_F_ASSEMBLY, &no_cut, &combo_cut, &ctl, ok, 0, 1) == D2KM_FR_OK); add(&box, &f);
    combo_cut.arm.action.value = D2KM_COMBO_VALUE(0, 8, 3);
    CHECK(d2km_fact_establish(&f, 63, D2KM_F_ASSEMBLY, &no_cut, &combo_cut, &ctl, ok, 0, 1) == D2KM_FR_OK); add(&box, &f);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(p.fakes[0].repeats == 8 && p.splits[0].offset == 1 && strstr(p.fakes[0].why, "F60"));
    cut_failed.candidate = d2km_program_hash(&p);
    CHECK(d2km_box_add_counter(&box, &cut_failed) == D2KM_BOX_OK);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(p.fakes[0].repeats == 8 && p.splits[0].offset == 3 && strstr(p.splits[0].why, "F63"));
    cut_failed.candidate = d2km_program_hash(&p);
    CHECK(d2km_box_add_counter(&box, &cut_failed) == D2KM_BOX_OK);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(p.fakes[0].repeats == 8 && p.split_count == 0);

    /* Регрессия A1: числовая граница fake-only не заменяет k,
       установленное отдельным фактом сочетания. */
    cut_failed.candidate = d2km_program_hash(&p); /* plain, k=8 */
    CHECK(d2km_box_add_counter(&box, &cut_failed) == D2KM_BOX_OK);
    no_cut.arm.action.value = D2KM_COMBO_VALUE(0, 1, 0);
    combo_cut.arm.action.value = D2KM_COMBO_VALUE(0, 1, 1);
    CHECK(d2km_fact_establish(&f, 64, D2KM_F_ASSEMBLY, &no_cut, &combo_cut, &ctl, ok, 0, 1) == D2KM_FR_OK); add(&box, &f);
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_CANDIDATE);
    CHECK(p.fake_count == 1 && p.fakes[0].repeats == 1 && p.split_count == 1 && p.splits[0].offset == 1);
    CHECK(strstr(p.fakes[0].why, "F64") != NULL);

    /* Не TLS — не синтезируется. */
    uint8_t junk[10] = {0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5};
    in.box = &box; in.client_hello = junk; in.client_hello_length = sizeof junk;
    CHECK(d2km_synth_tls(&in, &p, &need, why, sizeof why) == D2KM_SYN_BAD_INPUT);
    DONE("test_synth");
}
