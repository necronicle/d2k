/* Модель коробки для проверки без сети (D2K_SPEC.md §15.1).
 *
 * Отвечает на опыты как настоящая коробка с заданным поведением: читает ли
 * имя в приветствии, собирает ли сегменты, на каком хопе стоит, где сервер,
 * чем реагирует. Это стенд проверки, не знание продукта: в продуктовый код
 * не входит и ни одного ответа ведущему не подсказывает. */
#ifndef D2KM_SIM_H
#define D2KM_SIM_H

#include "d2km_net.h"

typedef struct {
    const char *blocked_suffix;   /* имена с этим суффиксом коробка блокирует */
    int reads_name;               /* коробка разбирает имя в приветствии */
    int reassembles;              /* собирает приветствие из сегментов */
    int box_hop, server_hop;      /* хопы коробки и сервера */
    int server_down;              /* сервер не отвечает и через опорную точку */
    int reference_down;           /* опорная точка недоступна */
    int flaky_every;              /* каждый N-й прогон — потеря (0 — нет) */
    unsigned server_flaky;        /* маска порч, которые сервер отвергает через раз (1 tcpts, 2 md5, 4 badsum) */
    const char *cert_suffix;      /* сертификат сервера только на эти имена; NULL — на любое */
    int silent_box;               /* реакция коробки — тишина вместо RST */
    int local_fail_every;         /* каждый N-й прогон — локальная ошибка своей стороны (0 — нет) */
    int late_cut;                 /* блок не по первому приветствию: сервер отвечает, обмен рвётся */
    int addr_block;               /* блок адреса: SYN не проходит ни с каким именем */
    unsigned min_copies;          /* 0 = 1, предел языка 255 */
    unsigned checks;              /* D2KM_SPOIL_MASK: коробка отвергает порчу */
    unsigned server_accepts;      /* сервер принимает такую порчу */
    int ignores_low_ttl;          /* коробка игнорирует фальшивку с заданным TTL */
    int header_split_relief;      /* разрез PAYLOAD_START+1..4 скрывает hello */
    unsigned runs;                /* счётчик прогонов (для flaky и отчёта) */
    unsigned max_repeats_seen;    /* наибольшее число копий фальшивки в одном плече */
} d2km_sim;

d2km_net d2km_sim_net(d2km_sim *);

#endif
