/* d2kexp — новая цепочка D2K для одной цели (ТЗ §4.1): прямой контроль с
 * доказательствами живости сервера, вопросы, факты, поиск хопов, синтез,
 * испытание. Собственные потоки с меткой опыта (по умолчанию метка
 * измерения d2kc), рабочая сборка и каталог не трогаются. Пробные планы
 * исполняются через отдельный сокет опытов --exp-control с квитанцией.
 * --store хранит только собственные модели и прикладно проверенное знание.
 *
 *   d2kexp --host H --ip A [--port 443] [--family 4|6] --form F.hex
 *          --pass NAME [--mark 0x2f] [--journal PATH] [--store PATH] [--exp-control SOCK]
 *
 * Форма — запись TLS с ClientHello клиента в hex (строки после # —
 * комментарии); имя в ней заменяется на --host. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "d2k_exp_task.h"
#include "d2k_hello.h"
#include "d2k_link.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include "d2k_tls13core.h"
#include <arpa/inet.h>
#include "d2km_task.h"
#include "d2km_tls.h"

static const char *rname(d2km_result r)
{
    const char *n = d2km_result_name(r.kind);
    return n ? n : "?";
}

static void print_arm(const d2km_arm *a)
{
    if (!a->has_action) { printf("без воздействия"); return; }
    printf("%s поле=0x%x значение=%lld", d2km_operator_name(a->action.op),
           (unsigned)a->action.field, (long long)a->action.value);
}

int main(int argc, char **argv)
{
    const char *host = NULL, *ip = NULL, *form = NULL, *pass = NULL, *journal = NULL, *expsock = NULL;
    const char *store_path = NULL;
    int port = 443, family = 4;
    unsigned long mark = 0x2f;
    if ((argc - 1) % 2) { fprintf(stderr, "у каждого ключа должен быть аргумент\n"); return 2; }
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--host")) host = argv[i + 1];
        else if (!strcmp(argv[i], "--ip")) ip = argv[i + 1];
        else if (!strcmp(argv[i], "--port")) port = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--family")) family = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--form")) form = argv[i + 1];
        else if (!strcmp(argv[i], "--pass")) pass = argv[i + 1];
        else if (!strcmp(argv[i], "--mark")) mark = strtoul(argv[i + 1], NULL, 0);
        else if (!strcmp(argv[i], "--store")) store_path = argv[i + 1];
        else if (!strcmp(argv[i], "--journal")) journal = argv[i + 1];
        else if (!strcmp(argv[i], "--exp-control")) expsock = argv[i + 1];
        else { fprintf(stderr, "неизвестный ключ %s\n", argv[i]); return 2; }
    }
    if (!host || !ip || !form || port <= 0 || port > 65535) {
        fprintf(stderr, "нужны --host, --ip, --form\n");
        return 2;
    }
    static d2km_store catalog;
    d2km_store_init(&catalog);
    d2km_store_error store_error = {0};
    d2km_store_code load_code = D2KM_STORE_OK;
    if (store_path) {
        load_code = d2km_store_load(store_path, &catalog, &store_error);
        if (load_code != D2KM_STORE_OK)
            fprintf(stderr, "хранилище %s: %s; работа с пустым знанием\n", store_path, store_error.reason);
    }
    d2km_journal j;
    int jok = journal && d2km_journal_open(&j, journal, 1u << 20) == 0;
    d2k_exp_options options={.host=host,.ip=ip,.form=form,.pass_name=pass,
        .exp_control=expsock,.port=(uint16_t)port,.family=family,.mark=(uint32_t)mark};
    char task_error[300];
    d2k_exp_task *task=d2k_exp_task_open(&options,store_path?&catalog:NULL,
                                       jok?&j:NULL,NULL,task_error,sizeof task_error);
    if(!task) {
        fprintf(stderr,"%s\n",task_error);
        if(jok)d2km_journal_close(&j);
        return 2;
    }
    const d2km_context *ctx=d2k_exp_task_context(task);
    const d2km_box *box=d2k_exp_task_box(task);
    if (jok && load_code != D2KM_STORE_OK) {
        d2km_why w = {.task = ctx, .step = D2KM_STEP_OWN, .reason = store_error.reason};
        if (d2km_journal_append(&j, &w, NULL) != D2KM_WHY_OK)
            fprintf(stderr, "не удалось записать причину отказа загрузки в журнал\n");
    }
    static d2km_task_report rep;
    d2km_outcome o = d2k_exp_task_run(task, &rep);
    printf("цель %s (%s:%d): итог %s, состояние %s\n  %s\n  опытов %u, прогонов %u\n", host, ip, port,
           d2km_outcome_name(o) ? d2km_outcome_name(o) : "?",
           d2km_task_state_name(rep.state) ? d2km_task_state_name(rep.state) : "?",
           rep.reason, rep.experiments, rep.runs);
    if (o == D2KM_APPLIED)
        printf("  источник результата: %s (K%u, B%u)\n", rep.from_own ? "своё знание" : "вопросы",
               rep.knowledge_id, rep.box_id);
    int save_failed = 0;
    if (store_path) {
        if (d2km_store_save(store_path, &catalog, &store_error) != D2KM_STORE_OK) {
            save_failed = 1;
            fprintf(stderr, "хранилище %s не сохранено: %s\n", store_path, store_error.reason);
            if (jok) {
                d2km_why w = {.task = ctx, .step = D2KM_STEP_KNOWLEDGE,
                    .outcome = D2KM_LOCAL_FAIL, .reason = store_error.reason};
                if (d2km_journal_append(&j, &w, NULL) != D2KM_WHY_OK)
                    fprintf(stderr, "не удалось записать причину отказа сохранения в журнал\n");
            }
        }
    }
    for (size_t i = 0; i < box->fact_count; i++) {
        const d2km_fact *f = &box->facts[i];
        printf("  F%u %s %s%s%s: ", (unsigned)f->id, d2km_fact_kind_name(f->kind),
               f->level == D2KM_LEVEL_ESTABLISHED ? "установленный" : "наблюдённый",
               f->numeric ? " числовой" : "", f->invariant ? " неизменность" : "");
        print_arm(&f->a);
        printf(" → %s", rname(f->ra));
        if (f->level == D2KM_LEVEL_ESTABLISHED) { printf("; "); print_arm(&f->b); printf(" → %s", rname(f->rb)); }
        printf("\n");
    }
    const d2km_program *p = o == D2KM_APPLIED ? &rep.program : rep.has_candidate ? &rep.candidate : NULL;
    if (p) {
        static char text[16384];
        printf("  %s:\n", o == D2KM_APPLIED ? "программа" : "кандидат (не испытан)");
        for (size_t i = 0; i < p->payload_count; i++) printf("    почему (нагрузка): %s\n", p->payloads[i].why);
        for (size_t i = 0; i < p->fake_count; i++) printf("    почему (фальшивка): %s\n", p->fakes[i].why);
        for (size_t i = 0; i < p->split_count; i++) printf("    почему (разрез): %s\n", p->splits[i].why);
        if (d2km_program_text(p, text, sizeof text)) {
            /* Нагрузка в плане длинная — показываем начало строк. */
            for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n"))
                printf("    | %.100s%s\n", line, strlen(line) > 100 ? "…" : "");
        }
    }
    if (jok) d2km_journal_close(&j);
    d2k_exp_task_close(task);
    return !save_failed && (o == D2KM_APPLIED || o == D2KM_DIRECT_OK) ? 0 : 1;
}
