#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_sched.h"

static char report[1024];
static void collect(void *ctx, const char *line) {
    (void)ctx;
    size_t used = strlen(report);
    snprintf(report + used, sizeof report - used, "%s\n", line);
}
int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return 2;
    d2k_catalog c = {0};
    c.n_boxes = 2; c.boxes = calloc(2, sizeof *c.boxes);
    if (!c.boxes) return 2;
    for (size_t i = 0; i < 2; i++) {
        d2k_cat_box *b = &c.boxes[i];
        snprintf(b->id, sizeof b->id, "box-%zu", i);
        b->n_plans = 1; b->plans = calloc(1, sizeof *b->plans);
        b->n_binds = i ? 3 : 1; b->binds = calloc(b->n_binds, sizeof *b->binds);
        if (!b->plans || !b->binds) return 2;
        strcpy(b->plans[0].id, "plan-test"); b->plans[0].enabled = 1;
        b->plans[0].text = strdup("d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\npayload 1 00\npoison 1 badsum\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\n");
        for (size_t j = 0; j < b->n_binds; j++) {
            d2k_cat_binding *bd = &b->binds[j];
            strcpy(bd->kind, "name"); strcpy(bd->target, "same-context.test");
            strcpy(bd->plan_id, "plan-test");
            bd->enabled = 1; bd->level = 3; bd->transport = 6;
            bd->shape = j == 1 ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN;
            bd->family = j == 2 ? 6 : 4;
            bd->confirmed = i ? 100 : 200;
        }
    }
    d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2e);
    if (!s) return 2;
    d2k_sched_set_say(s, collect, NULL);
    d2k_sched_sync(s);
    for (int i = 0; d2k_sched_sync_pending(s) && i < 10; i++) d2k_sched_sync_step(s);
    /* New modern IPv4 wins; old modern IPv4 must not overwrite it. Both
       legacy IPv4 and modern IPv6 remain independent valid bindings. */
    int failed = strstr(report, "привязкам: 3") == NULL;
    if (failed) fprintf(stderr, "catalog-sync: stale duplicate replaced newest binding: %s\n", report);
    /* A newer but weak/disabled/missing-plan record must not suppress the
       older valid confirmation. Independent contexts still all survive. */
    for (int mode = 0; mode < 3; mode++) {
        d2k_cat_binding *bd = &c.boxes[0].binds[0];
        bd->level = mode == 0 ? 2 : 3;
        bd->enabled = mode != 1;
        strcpy(bd->plan_id, mode == 2 ? "missing" : "plan-test");
        report[0] = 0;
        d2k_sched_sync(s);
        for (int i = 0; d2k_sched_sync_pending(s) && i < 10; i++) d2k_sched_sync_step(s);
        if (strstr(report, "привязкам: 3") == NULL) {
            fprintf(stderr, "catalog-sync: unusable newer record hides valid context (%d): %s\n", mode, report);
            failed = 1;
        }
    }
    for (size_t bi=0;bi<c.n_boxes;bi++) {
        for (size_t j=0;j<c.boxes[bi].n_binds;j++) {
            d2k_cat_binding *bd=&c.boxes[bi].binds[j];
            strcpy(bd->kind,"service");
            strcpy(bd->target,bd->family==6?"2001:db8::1":"192.0.2.1");
            strcpy(bd->plan_id,"plan-test");
            bd->server_port=443;bd->enabled=1;bd->level=3;
        }
    }
    for (int mode=0;mode<3;mode++) {
        d2k_cat_binding *newest=&c.boxes[0].binds[0];
        newest->server_port=mode==1?8443:443;
        newest->level=mode==2?0:3;
        report[0]=0;
        d2k_sched_sync(s);
        for(int i=0;d2k_sched_sync_pending(s)&&i<10;i++) d2k_sched_sync_step(s);
        if (!strstr(report,mode==1?"привязкам: 4":"привязкам: 3")) {
            fprintf(stderr,"catalog-sync: service context collision or weak authority (%d): %s\n",mode,report);
            failed=1;
        }
    }
    /* Legacy RAW address authority has no measured port. Keep its candidate,
       but do not reinstall it across every service after controller restart. */
    for (size_t bi = 0; bi < c.n_boxes; bi++)
        for (size_t j = 0; j < c.boxes[bi].n_binds; j++) c.boxes[bi].binds[j].enabled = 0;
    for (unsigned tr = 6; tr <= 17; tr += 11) {
        d2k_cat_binding *bd = &c.boxes[0].binds[0];
        d2k_cat_plan *plan = &c.boxes[0].plans[0];
        free(plan->text);
        plan->text = strdup(tr == 6 ?
            "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\norder forward\n" :
            "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto udp voice\norder forward\n");
        bd->enabled = 1; bd->level = 3; bd->transport = tr; bd->shape = 8;
        for (unsigned service = 0; service < 2; service++) {
            strcpy(bd->kind, service ? "service" : "addr"); bd->server_port = service ? 443 : 0;
            report[0] = 0;
            d2k_sched_sync(s);
            for (int i = 0; d2k_sched_sync_pending(s) && i < 10; i++) d2k_sched_sync_step(s);
            if (!strstr(report, service ? "привязкам: 1" : "привязкам: 0") ||
                !bd->enabled || !plan->enabled) {
                fprintf(stderr, "catalog-sync: RAW scope or candidate retention failed (%u/%u): %s\n", tr, service, report);
                failed = 1;
            }
        }
    }
    d2k_sched_free(s); d2k_catalog_free(&c); close(sv[0]); close(sv[1]);
    if (failed) return 1;
    puts("catalog-sync: newest exact context, TLS versions and families preserved");
    return 0;
}
