/* Исполнитель плеча опыта в сети роутера (D2K_SPEC.md §6.7, §8.1, §4.3).
 *
 * Реализует d2km_net (model/include/d2km_net.h) для собственного потока
 * D2K: свой сокет с меткой опыта (SO_MARK), приветствие формы клиента,
 * прикладной GET по выбранному ALPN. Программа кандидата ставится пробным
 * планом на местный порт потока через обратный вызов (датапат), и только
 * на время плеча. Исход судится по сокету: ошибка сокета, закрытие
 * сервером, время — а не по тексту ошибки.
 *
 * Опорная точка (§2.1) — собственный сервис D2K на сервере проекта; пока
 * он не подключён, плечо через неё даёт NOT_MEASURED, и ведущий получает
 * NO_REFERENCE, а не выдуманный ответ. */
#ifndef D2K_NETARM_H
#define D2K_NETARM_H

#include <stdint.h>
#include "d2km_net.h"

typedef struct {
    uint32_t mark;          /* SO_MARK собственных потоков; 0 — без метки */
    uint32_t probe_mark;    /* метка потока с пробным планом: он обязан пройти датапат */
    int family;             /* 4 или 6 */
    const char *ip;         /* адрес сервера цели */
    uint16_t port;
    const char *host;       /* имя для сверки сертификата и Host/:authority */
    const char *path;       /* путь прикладного запроса (§9.2) */
    const char *doh_path,*dns_name; /* NULL: ordinary HTTP contract */
    int connect_ms;         /* предел установления TCP */
    int exchange_ms;        /* предел рукопожатия и ответа */
    /* Пробный план программы на местный порт потока; 0 — поставлен. name —
       имя в приветствии этого плеча (контекст плеча): вопрос может идти с
       другим именем, чем цель, и план датапата ищет поток по нему. */
    int (*install)(void *ctx, const char *name, uint16_t local_port, const d2km_program *,
                   uint32_t experiment, char *err, size_t cap);
    void (*remove)(void *ctx, const char *name, uint16_t local_port, uint32_t experiment);
    /* Квитанция исполнителя (ТЗ §8.3): 1 — план исполнен на потоке плеча,
       0 — отвергнут или квитанции нет. NULL — квитанций нет вовсе. */
    int (*receipt)(void *ctx, uint16_t local_port, uint32_t experiment, char *note, size_t cap);
    void *plan_ctx;
    char last_reason[200]; /* actual arm phase/error/application observation, retained in why */
} d2k_netarm;

d2km_net d2k_netarm_net(d2k_netarm *);

#endif
