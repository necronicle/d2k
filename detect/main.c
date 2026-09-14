/* main.c — d2k-detect: командная строка инструмента «Поиск по домену» на C.
 *
 * Флаги и формат вывода повторяют `z2k-detect classify` эталона, чтобы вывод
 * можно было сверять построчно, а не пересказывать. Отличие одно и оно
 * названо в trigger.c: приветствие собирается из снятого профиля, поэтому
 * сверка алгоритма идёт на общем триггере (--raw).
 */
#include "d2k_detect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(void)
{
    fprintf(stderr,
        "d2k-detect classify <host:port> [флаги]\n"
        "\n"
        "  --sni ИМЯ          собрать триггер как ClientHello с этим именем\n"
        "  --raw HEX          триггер шестнадцатеричной строкой (для не-TLS протоколов)\n"
        "  --repeats N        повторов на зонд; вердикт только при единогласии (3)\n"
        "  --timeout MS       сколько ждать ответа (6000)\n"
        "  --only ИМЯ         прогнать только эту гипотезу (для отладки зондов)\n"
        "  --skip ИМЯ         не пробовать эту гипотезу (можно повторять)\n"
        "  --control-sni ИМЯ  имя для контрольного зонда; сервер обязан его обслуживать\n"
        "  --control-raw HEX  байты контрольного зонда шестнадцатеричной строкой.\n"
        "                     Нужен сверке: контроль — такой же ВХОД замера, как триггер,\n"
        "                     и гипотезы с приманкой берут длину перекрытия равной его длине\n"
        "  --hello modern|legacy   какое приветствие TLS мерить\n"
        "  --no-raw           выключить сырые зонды\n"
        "  --mark HEX         метка SO_MARK для всех зондов (умолчание 0x40000000 — z2k).\n"
        "                     У d2k метка своя, её задаёт --mark датапату: с чужой зонд\n"
        "                     пойдёт ЧЕРЕЗ наш обход и замерит его, а не коробку\n"
        "  --allow-loopback   снять защиту от цели на localhost (для стенда)\n"
        "  --json             выдать результат как JSON\n"
        "  --dump-trigger     напечатать байты триггера hex и выйти\n"
        "                     (тем же hex кормится эталон: z2k-detect classify -raw ...,\n"
        "                      только так сверка меряет АЛГОРИТМ, а не разные приветствия)\n");
}

static void print_json_str(const char *s)
{
    putchar('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            printf("\\%c", c);
        } else if (c < 0x20) {
            printf("\\u%04x", c);
        } else {
            putchar(c);
        }
    }
    putchar('"');
}

static void print_tri(const char *key, d2k_tri t)
{
    if (t == D2K_TRI_UNSET) {
        return;
    }
    printf(",\n    \"%s\": %s", key, t == D2K_TRI_TRUE ? "true" : "false");
}

static void print_json(const d2k_result *r)
{
    int i, j;
    printf("{\n  \"target\": ");
    print_json_str(r->target);
    printf(",\n  \"verdict\": ");
    print_json_str(d2k_verdict_name(r->verdict));
    printf(",\n  \"reason\": ");
    print_json_str(r->reason);
    printf(",\n  \"repeats\": %d", r->repeats);
    printf(",\n  \"probes\": %d", r->probes);
    printf(",\n  \"duration\": ");
    {
        char b[32];
        snprintf(b, sizeof(b), "%ldms", r->duration_ms);
        print_json_str(b);
    }
    printf(",\n  \"trigger_len\": %d", r->trigger_len);
    if (r->boundary > 0) {
        printf(",\n  \"boundary\": %d", r->boundary);
    }
    if (r->split_pos > 0) {
        printf(",\n  \"split_pos\": %d", r->split_pos);
    }
    if (r->reassembles != D2K_TRI_UNSET) {
        printf(",\n  \"reassembles\": %s", r->reassembles == D2K_TRI_TRUE ? "true" : "false");
    }
    if (r->strategy[0]) {
        printf(",\n  \"strategy\": ");
        print_json_str(r->strategy);
    }
    if (r->nnotes > 0) {
        printf(",\n  \"notes\": [");
        for (i = 0; i < r->nnotes; i++) {
            printf("%s\n    ", i ? "," : "");
            print_json_str(r->notes[i]);
        }
        printf("\n  ]");
    }
    if (r->has_response) {
        printf(",\n  \"response\": {\n    \"verdict\": ");
        print_json_str(d2k_resp_name(r->response.verdict));
        printf(",\n    \"reason\": ");
        print_json_str(r->response.reason);
        printf(",\n    \"target\": %d,\n    \"control\": %d\n  }",
               r->response.target, r->response.control);
    }
    if (r->covers_tls12 != D2K_TRI_UNSET) {
        printf(",\n  \"covers_tls12\": %s", r->covers_tls12 == D2K_TRI_TRUE ? "true" : "false");
    }
    printf(",\n  \"props\": {");
    {
        /* Первое поле печатаем без запятой, остальные с ней: поля
         * необязательные, и порядок обязан совпадать с эталоном. */
        int first = 1;
        const char *keys[7] = {"reassembles", "parses_l7", "validates_checksum",
                               "tolerates_reorder", "tolerates_left_overlap",
                               "counts_duplicates", "inspects_syn"};
        d2k_tri vals[7];
        vals[0] = r->props.reassembles;
        vals[1] = r->props.parses_l7;
        vals[2] = r->props.validates_checksum;
        vals[3] = r->props.tolerates_reorder;
        vals[4] = r->props.tolerates_left_overlap;
        vals[5] = r->props.counts_duplicates;
        vals[6] = r->props.inspects_syn;
        for (i = 0; i < 7; i++) {
            if (vals[i] == D2K_TRI_UNSET) {
                continue;
            }
            if (first) {
                printf("\n    \"%s\": %s", keys[i], vals[i] == D2K_TRI_TRUE ? "true" : "false");
                first = 0;
            } else {
                print_tri(keys[i], vals[i]);
            }
        }
        if (r->props.hop_ttl > 0) {
            printf("%s\n    \"hop_ttl\": %d", first ? "" : ",", r->props.hop_ttl);
            first = 0;
        }
        printf("%s}", first ? "" : "\n  ");
    }
    if (r->path[0]) {
        printf(",\n  \"path\": ");
        print_json_str(r->path);
    }
    printf(",\n  \"composed\": %s", r->composed ? "true" : "false");
    printf(",\n  \"raw_usable\": %s", r->raw_usable ? "true" : "false");
    printf(",\n  \"trace\": [");
    for (i = 0; i < r->ntrace; i++) {
        const d2k_obs *o = &r->trace[i];
        printf("%s\n    {\n      \"probe\": ", i ? "," : "");
        print_json_str(o->probe);
        if (o->ncuts > 0) {
            printf(",\n      \"cuts\": [");
            for (j = 0; j < o->ncuts; j++) {
                printf("%s%d", j ? "," : "", o->cuts[j]);
            }
            printf("]");
        }
        if (o->delay_ms > 0) {
            printf(",\n      \"delay_ms\": %d", o->delay_ms);
        }
        printf(",\n      \"pass\": %d,\n      \"fail\": %d", o->pass, o->fail);
        if (o->err[0]) {
            printf(",\n      \"err\": ");
            print_json_str(o->err);
        }
        printf("\n    }");
    }
    printf("\n  ]\n}\n");
}

static const char *tri_word(d2k_tri t)
{
    if (t == D2K_TRI_UNSET) { return "не измерено"; }
    return t == D2K_TRI_TRUE ? "да" : "нет";
}

static void print_human(const d2k_result *r, const d2k_trigger *tr)
{
    const d2k_dprops *pr = &r->props;
    int i, j;

    printf("Цель:     %s\n", r->target);
    printf("Триггер:  %s (%d байт)\n", tr->name, r->trigger_len);
    printf("Вердикт:  %s — %s\n", d2k_verdict_name(r->verdict), r->reason);
    printf("Зондов:   %d за %ldms (по %d повтора)\n", r->probes, r->duration_ms, r->repeats);
    if (r->boundary > 0) {
        printf("Граница:  сигнатура кончается на байте %d\n", r->boundary);
    }
    if (r->reassembles != D2K_TRI_UNSET) {
        printf(r->reassembles == D2K_TRI_TRUE
               ? "Пересборка: ЕСТЬ — при паузе блок возвращается\n"
               : "Пересборка: нет\n");
    }
    if (r->strategy[0]) {
        const char *how = "путь не отмечен";
        if (strcmp(r->path, "свойство") == 0) {
            how = "ответила фаза свойств — 6 вопросов о коробке";
        } else if (strcmp(r->path, "собрано") == 0) {
            how = "СОБРАНА из вектора свойств";
        } else if (strcmp(r->path, "перебор") == 0) {
            how = "вектор не помог, найдена запасным перебором";
        }
        printf("Стратегия: %s\n           (%s)\n", r->strategy, how);
    }
    if (r->has_response) {
        printf("Ответ:    %s — %s (цель %d, контроль %d)\n",
               d2k_resp_name(r->response.verdict), r->response.reason,
               r->response.target, r->response.control);
    }
    for (i = 0; i < r->nnotes; i++) {
        printf("Оговорка:  %s\n", r->notes[i]);
    }
    if (r->verdict == D2K_DV_OPAQUE && !r->raw_usable) {
        printf("ВНИМАНИЕ: сырые зонды не отработали — отрицательный вывод про отравление НЕ значим\n");
    }
    if (pr->reassembles != D2K_TRI_UNSET || pr->parses_l7 != D2K_TRI_UNSET ||
        pr->validates_checksum != D2K_TRI_UNSET || pr->tolerates_reorder != D2K_TRI_UNSET ||
        pr->tolerates_left_overlap != D2K_TRI_UNSET || pr->hop_ttl > 0) {
        printf("Свойства коробки:\n");
        printf("  пересобирает поток:        %s\n", tri_word(pr->reassembles));
        printf("  разбирает протокол:        %s\n", tri_word(pr->parses_l7));
        printf("  проверяет контр. сумму:    %s\n", tri_word(pr->validates_checksum));
        printf("  держит переупорядочивание: %s\n", tri_word(pr->tolerates_reorder));
        printf("  держит перекрытие слева:   %s\n", tri_word(pr->tolerates_left_overlap));
        if (pr->hop_ttl > 0) {
            printf("  расстояние до неё:         %d хопов\n", pr->hop_ttl);
        }
    }
    printf("Трасса:\n");
    for (i = 0; i < r->ntrace; i++) {
        const d2k_obs *o = &r->trace[i];
        char cuts[32];
        if (o->ncuts == 0) {
            snprintf(cuts, sizeof(cuts), "-");
        } else {
            int k = snprintf(cuts, sizeof(cuts), "[");
            for (j = 0; j < o->ncuts; j++) {
                k += snprintf(cuts + k, sizeof(cuts) - (size_t)k, "%s%d", j ? " " : "", o->cuts[j]);
            }
            snprintf(cuts + k, sizeof(cuts) - (size_t)k, "]");
        }
        printf("  %-11s cuts=%-8s пауза=%dмс  прошло=%d не прошло=%d %s\n",
               o->probe, cuts, o->delay_ms, o->pass, o->fail, o->err);
    }
}

int main(int argc, char **argv)
{
    d2k_opts opt;
    d2k_trigger tr;
    d2k_result res;
    char err[256];
    const char *addr = NULL;
    const char *sni = NULL, *raw = NULL, *ctl_sni = NULL, *ctl_raw = NULL, *hello = "modern";
    int as_json = 0;
    int dump_trigger = 0;
    int i;

    memset(&opt, 0, sizeof(opt));
    err[0] = '\0';

    if (argc < 3 || strcmp(argv[1], "classify") != 0) {
        usage();
        return 2;
    }
    addr = argv[2];
    for (i = 3; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(a, "--sni") == 0 && v)              { sni = v; i++; }
        else if (strcmp(a, "--raw") == 0 && v)          { raw = v; i++; }
        else if (strcmp(a, "--repeats") == 0 && v)      { opt.repeats = atoi(v); i++; }
        else if (strcmp(a, "--timeout") == 0 && v)      { opt.timeout_ms = atoi(v); i++; }
        else if (strcmp(a, "--write-gap") == 0 && v)    { opt.write_gap_ms = atoi(v); i++; }
        else if (strcmp(a, "--long-gap") == 0 && v)     { opt.long_gap_ms = atoi(v); i++; }
        else if (strcmp(a, "--only") == 0 && v)         { snprintf(opt.only, sizeof(opt.only), "%s", v); i++; }
        else if (strcmp(a, "--skip") == 0 && v)         {
            if (opt.nskip < D2K_SKIP_MAX) {
                snprintf(opt.skip[opt.nskip++], sizeof(opt.skip[0]), "%s", v);
            }
            i++;
        }
        else if (strcmp(a, "--control-sni") == 0 && v)  { ctl_sni = v; i++; }
        else if (strcmp(a, "--control-raw") == 0 && v)  { ctl_raw = v; i++; }
        else if (strcmp(a, "--hello") == 0 && v)        { hello = v; i++; }
        else if (strcmp(a, "--no-raw") == 0)            { opt.no_raw = 1; }
        else if (strcmp(a, "--mark") == 0 && v)         { opt.mark = (uint32_t)strtoul(v, NULL, 0); i++; }
        else if (strcmp(a, "--allow-loopback") == 0)    { opt.allow_loopback = 1; }
        else if (strcmp(a, "--json") == 0)              { as_json = 1; }
        else if (strcmp(a, "--dump-trigger") == 0)      { dump_trigger = 1; }
        else {
            fprintf(stderr, "classify: неизвестный флаг %s\n", a);
            usage();
            return 2;
        }
    }

    if (strcmp(hello, "modern") != 0 && strcmp(hello, "legacy") != 0) {
        /* Режим «both» эталона здесь не перенесён, и предлагать его нельзя:
         * он обещает покрытие старых устройств, а обещание без замера — это
         * ровно та ложь, которую инструмент существует чтобы не говорить. */
        fprintf(stderr, "classify: --hello может быть modern или legacy, а не «%s»\n", hello);
        return 2;
    }
    if (raw && sni) {
        fprintf(stderr, "classify: --sni и --raw взаимоисключающие\n");
        return 2;
    }

    if (raw) {
        if (d2k_trigger_raw_hex(raw, &tr, err, sizeof(err)) != 0) {
            fprintf(stderr, "%s\n", err);
            return 1;
        }
    } else {
        char name[160];
        if (sni) {
            snprintf(name, sizeof(name), "%s", sni);
        } else {
            /* Имя не задано — берём его из адреса. Для TLS это ровно то, по
             * чему DPI и принимает решение, так что умолчание осмысленное. */
            const char *colon = strrchr(addr, ':');
            size_t n = colon ? (size_t)(colon - addr) : strlen(addr);
            if (n >= sizeof(name)) {
                n = sizeof(name) - 1;
            }
            memcpy(name, addr, n);
            name[n] = '\0';
        }
        if (d2k_trigger_tls(name, strcmp(hello, "legacy") == 0, &tr, err, sizeof(err)) != 0) {
            fprintf(stderr, "%s\n", err);
            return 1;
        }
    }

    if (dump_trigger) {
        size_t k;
        for (k = 0; k < tr.len; k++) {
            printf("%02x", tr.payload[k]);
        }
        printf("\n");
        return 0;
    }

    /* Контроль тем же именем, что и триггер, — не контроль вовсе: если имя под
     * блокировкой, молчать будут оба, и вердикт «режут адрес» получится из
     * собственной ошибки ввода. */
    if (ctl_raw && ctl_sni) {
        fprintf(stderr, "classify: --control-raw и --control-sni взаимоисключающие\n");
        return 2;
    }
    if (ctl_sni && sni && strcmp(ctl_sni, sni) == 0) {
        fprintf(stderr, "classify: --control-sni совпадает с --sni; контролем должно быть ДРУГОЕ "
                        "имя, заведомо не блокируемое\n");
        return 2;
    }
    if (ctl_raw) {
        /* Контроль задан байтами. Поручительства это НЕ даёт: оператор назвал
         * байты, а не ручался, что сервер обслуживает это имя, — а именно
         * поручительство превращает молчание контроля в «блок по адресу». */
        if (d2k_trigger_raw_hex(ctl_raw, &opt.control, err, sizeof(err)) != 0) {
            fprintf(stderr, "%s\n", err);
            return 1;
        }
        snprintf(opt.control.name, sizeof(opt.control.name), "control");
        /* Доказательством прохода для контроля служит ЛЮБАЯ запись TLS,
         * включая алерт: сервер, отвечающий отказом на незнакомое имя, — это
         * всё равно сервер, до которого дошли. */
        opt.control.accept = D2K_ACCEPT_TLSRECORD;
    } else if (ctl_sni) {
        /* Имя названо руками — значит за базу ручается оператор, и молчание
         * контроля можно засчитать как блок по адресу. */
        if (d2k_trigger_tls(ctl_sni, 0, &opt.control, err, sizeof(err)) == 0) {
            snprintf(opt.control.name, sizeof(opt.control.name), "control:%s", ctl_sni);
            opt.control_vouched = 1;
        }
    } else {
        (void)d2k_trigger_control("d2k", &opt.control, err, sizeof(err));
    }

    d2k_classify_run(addr, &tr, &opt, &res);

    if (as_json) {
        print_json(&res);
    } else {
        print_human(&res, &tr);
    }
    return 0;
}
