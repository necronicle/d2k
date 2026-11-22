#ifndef D2K_LATEWATCH_H
#define D2K_LATEWATCH_H

#include <stddef.h>
#include <stdint.h>
#include "d2k_ctq.h"
#include "d2k_ctl.h"
#include "d2k_lateobs.h"
#include "d2k_lwexec.h"
#include "d2k_rawmeasure_wire.h"

/* ПОЗДНЯЯ ДОСТАВКА: ВЛАДЕНИЕ, ГОТОВНОСТЬ, СНЯТИЕ (этапы 17, 49, 51, 53).
 *
 * Доставку потоку (метку записи conntrack или пару правил точного кортежа —
 * способ выбирает исполнитель) держат владельцы: опыт (trial) и позднее
 * наблюдение (observe). Один слот на кортеж; доставка снимается, когда
 * владельцев нет.
 *
 * АСИНХРОННО (этап 53). Модуль не ждёт ядро и iptables: он сверяет «нужно» и
 * «есть» и отдаёт заявки исполнителю (ops.submit), итоги приходят в
 * d2k_lw_complete. У слота не больше одной операции в полёте; итог чужого
 * поколения не принимается. Готовность владельца — только по итогу своей
 * установки: подтверждение наблюдения (ops.ack) и срок наблюдения — от неё.
 *   установка OK   — доставка есть;
 *   GONE           — записи нет: владельцам отказ, слот свободен;
 *   FAIL           — неясно (ядро могло поставить): владельцам отказ, снятие;
 *   снятие OK/GONE — слот свободен; FAIL — повтор 1, 2, 4… до 60 с.
 * Отмена во время установки — после её итога снятие. Полная очередь
 * исполнителя: установке — отказ владельцу, снятию — повтор позже.
 *
 * Уборка остатков прежнего экземпляра (D2K_LWOP_SWEEP): у способа «метка» —
 * найденные записи с нашим битом снимаются как сироты, кроме записей живых
 * владельцев; у способа «правила» — свои цепочки очищаются целиком. Сбой —
 * повтор с откатом, пока остатков нет.
 *
 * БАРЬЕР (находка ревью): установок нет, пока способ не известен, а у способа
 * «правила» — пока стартовая очистка своих цепочек не прошла целиком (обоих
 * семейств): её повтор (-F) удалил бы живые правила. Владельцы ждут, не
 * получая отказа; после очистки — установка и подтверждение. */

#define D2K_LW_SLOTS 64
#define D2K_LW_MAX_NS (120ull * 1000000000ull)
#define D2K_LW_RETRY_FIRST_NS 1000000000ull
#define D2K_LW_RETRY_MAX_NS (60ull * 1000000000ull)

typedef struct {
    /* Заявка исполнителю: 0 — принята, -1 — очередь полна. */
    int (*submit)(void *ctx, const d2k_lw_req *req);
    /* Подтверждение D2K_CMD_LATE_OBSERVE: ok, причина (D2K_ACK_*), токен. */
    void (*ack)(void *ctx, int ok, uint8_t reason, const uint8_t token[D2K_TRIAL_ID_LEN]);
    /* Флаг потока в сессии (держать пакеты опыта). NULL — нет. */
    void (*flow_flag)(void *ctx, const d2k_ct_tuple *t, int on);
    /* Сколько пакетов за окном сессия приняла под доставкой (для журнала). */
    uint64_t (*delivered)(void *ctx);
    /* Итог позднего наблюдения — в журнал (событие D2K_EV_LATE_OBS). */
    void (*note)(void *ctx, const d2k_ct_tuple *t, uint8_t code, uint32_t repeats,
                 const uint8_t token[D2K_TRIAL_ID_LEN], uint64_t now_ns);
    /* Строка журнала d2kd. NULL — молча. */
    void (*say)(void *ctx, const char *line);
    void *ctx;
    uint32_t bit;   /* бит connmark — только для строк журнала (договор этапа 17) */
} d2k_lw_ops;

enum { D2K_LW_NO = 0, D2K_LW_YES = 1, D2K_LW_UNKNOWN = 2 };

#define D2K_LW_RAW_MEASURE 1
typedef struct {
    /* 1 only for the exact live incarnation; previous_reply is measured locally. */
    int (*identity)(void *,const struct d2k_rawmeasure_request *,int *previous_reply);
    void (*ack)(void *,int ok,uint8_t reason,const uint8_t token[16]);
    void (*note)(void *,const struct d2k_rawmeasure_report *);
    void *ctx;
} d2k_lw_raw_ops;

typedef struct {
    uint8_t used, trial, observe, obs_pending, installed, busy, op;
    d2k_ct_tuple t;
    uint8_t raw_pending, raw_active;
    uint64_t raw_conn, raw_expires_ns, raw_started_ns, raw_heartbeat_ns;
    struct d2k_rawmeasure_request raw_request;
    struct d2k_rawmeasure raw;
    uint64_t gen;
    uint64_t expires_ns, obs_expires_ns, obs_secs;
    uint64_t retry_ns, retry_step_ns;
    uint64_t delivered_at_set;
    const char *why;
    uint8_t fail_told;
    d2k_lateobs obs;
    uint8_t obs_token[D2K_TRIAL_ID_LEN];
    uint64_t obs_conn;           /* поколение подключения контроллера наблюдения */
} d2k_lw_slot;

typedef struct {
    uint8_t used, busy;
    d2k_ct_tuple t;
    uint64_t gen, retry_ns, retry_step_ns;
} d2k_lw_orphan;

typedef struct {
    uint64_t set, cleared, gone, clear_fail, install_fail, queue_full, silent;
    uint64_t swept, sweep_fail;
} d2k_lw_stats;

typedef struct {
    d2k_lw_slot slot[D2K_LW_SLOTS];
    d2k_lw_orphan orphan[D2K_LW_SWEEP_LIST];
    size_t n_obs;
    d2k_lw_stats st;
    d2k_lw_ops ops;
    d2k_lw_raw_ops raw_ops;
    uint64_t gen;
    int backend, enabled;        /* итог D2K_LWOP_INIT */
    int backend_known;           /* INIT пришёл; до него установок нет (барьер) */
    uint64_t conn_gen;           /* поколение подключения контроллера */
    int sweep_pending, sweep_busy, sweep_clean;
    uint64_t sweep_gen, sweep_next_ns, sweep_step_ns;
} d2k_lw;

void d2k_lw_raw_hooks(d2k_lw *,const d2k_lw_raw_ops *);
void d2k_lw_measure(d2k_lw *,const struct d2k_rawmeasure_request *,uint64_t now);

void d2k_lw_init(d2k_lw *lw, const d2k_lw_ops *ops);
/* Выбор способа и уборка — первыми заявками исполнителю. */
void d2k_lw_start(d2k_lw *lw, uint64_t now);

/* Опыт: доставка t до expires_ns (0 — предел D2K_LW_MAX_NS). 0 — принято
 * (ставится или уже стоит), -1 — мест/способа нет. */
int  d2k_lw_trial_add(d2k_lw *lw, const d2k_ct_tuple *t, uint64_t expires_ns, uint64_t now);
void d2k_lw_trial_del(d2k_lw *lw, const d2k_ct_tuple *t, uint64_t now);

/* Позднее наблюдение t на seconds под токеном. Подтверждение (ops.ack) — по
 * готовности доставки; срок — от неё. Отказ — ops.ack(0, причина). Повторный
 * запрос того же кортежа заменяет прежнее наблюдение (ждущему — отказ). */
void d2k_lw_observe(d2k_lw *lw, const d2k_ct_tuple *t, uint32_t seconds,
                    const uint8_t token[D2K_TRIAL_ID_LEN], uint64_t now);

/* Пакет из очереди. 1 — пакет наблюдаемого потока (не освобождать с битом
 * снятия). Считаются только пакеты после готовности доставки. */
int  d2k_lw_packet(d2k_lw *lw, const uint8_t *pkt, size_t n, uint64_t now);

/* Итог исполнителя. */
void d2k_lw_complete(d2k_lw *lw, const d2k_lw_done *done, uint64_t now);

/* Контроллер отключился (событие отключения, этап 53): наблюдения его
 * подключения отменяются сразу — ни подтверждений, ни итогов следующему
 * контроллеру; опыты его подключения (пробы ctlsrv снимает тут же) — тоже;
 * доставка снимается. */
void d2k_lw_peer_closed(d2k_lw *lw, uint64_t now);

/* Сроки и повторы; controller_gone — снять всех владельцев. */
void d2k_lw_ipv4_mangle_reset(d2k_lw *lw, uint64_t now);
int d2k_lw_ipv4_repair_pending(const d2k_lw *lw);
void d2k_lw_family_mangle_reset(d2k_lw *lw, uint8_t family, uint64_t now);
int d2k_lw_family_repair_pending(const d2k_lw *lw, uint8_t family);
void d2k_lw_tick(d2k_lw *lw, uint64_t now, int controller_gone);

size_t d2k_lw_pending_clears(const d2k_lw *lw);
int  d2k_lw_sweep_pending(const d2k_lw *lw);

#endif
