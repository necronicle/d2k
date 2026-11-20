/* d2k_ctlsrv.h — смысл команд и событий управляющего сокета.
 *
 * Отдельно от службы намеренно. В d2kd.c живёт цикл — опрос, вердикты,
 * отправка; смысл протокола там оказался бы заперт за NFQUEUE, то есть за
 * Linux и правами root. А это ровно то место, где две реализации (C и Go)
 * расходятся молча, и проверять его надо не «на глаз по исходникам», а
 * настоящим клиентом. Здесь код переносим и потому проверяем везде.
 */
#ifndef D2K_CTLSRV_H
#define D2K_CTLSRV_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_ctl.h"
#include "d2k_rawmeasure_wire.h"
/* Только ради констант D2K_RAW_CANT_*: сам d2k_raw.c — Linux, а его
 * заголовок переносим и объявляет пределы способа отправки. */
#include "d2k_raw.h"
#include "d2k_session.h"
#include "d2k_http80.h"

/* Control v4: family(1), low/high address(16+16), ports(2+2), protocol(1).
 * IPv4 occupies the first four address bytes with zero tails. Fields are
 * encoded explicitly, never by copying the native d2k_key structure. */
#define D2K_KEY_WIRE_LEN 38
#define D2K_ADDR_PROBE_FLOW_WIRE_LEN 38

/* Контекст обслуживания команд. */
typedef struct {
    d2k_session *sess;
    /* Куда слать подтверждения. NULL — не слать (стенд без контроллера). */
    d2k_ctl     *ctl;
    /* Биты D2K_RAW_CANT_* выбранного способа отправки. Не сам сокет: смысл
     * команды не должен зависеть от того, как именно пакеты поедут. */
    uint32_t     send_limits;
    /* Сколько байт унесёт ОДНА посылка выбранным способом отправки
       (d2k_raw_maxlen). Ноль — предел не объявлен: по длине не проверяем.
       Полем контекста по той же причине, что и send_limits: смысл команды не
       должен зависеть от того, как именно пакеты поедут, но отказ обязан
       случаться ДО активации плана, а не прилетать от ядра потом. */
    uint32_t     send_maxlen;
    uint64_t     ok_cmds;
    uint64_t     bad_cmds;
    /* Давность «сейчас» для вытеснения в таблице планов (d2k_plantab_set_name/
     * set_addr, см. d2k_plans.h). Полем контекста, а не аргументом
     * d2k_ctlsrv_command — та вызывается как обратный вызов d2k_ctl_poll с
     * фиксированной сигнатурой (cb в d2k_ctl.h), и часы туда добавить нельзя,
     * не сломав протокольно-независимый d2k_ctl.c. Вызывающий (d2kd.c,
     * ctlprobe.c) обновляет now_ns перед d2k_ctl_poll — как и wake/t в цикле
     * d2kd.c, часы не обязаны быть точнее нескольких сотен миллисекунд:
     * вытеснение считает минуты, не наносекунды. */
    uint64_t     now_ns;
    uint8_t      area_id[D2K_TRIAL_ID_LEN];
    d2k_binding_context installed_binding;
    /* Имена с подтверждённым HTTPS (D2K_CMD_SET_HTTPS). NULL — команда
       отвергается. */
    d2k_http80  *http80;
    /* ПОЗДНЯЯ ДОСТАВКА (этап 17): кому сказать об установке/снятии опыта
       на ТОЧНОМ потоке — d2kd ставит/снимает метку записи conntrack, чтобы
       пакеты уже идущего потока (за окном connbytes) попадали в очередь.
       NULL — никому. installed 1 — поставлен (expires_ns — срок, 0 — без
       срока у команды), 0 — снят. Адресная проба несёт 5-tuple; именная
       проба порта (TCP без протокола, этап 12) — имя-адрес, транспорт,
       семейство и порт клиента. Зовётся ПОСЛЕ успешной записи в таблицу. */
    void (*addr_probe_hook)(void *ctx, const d2k_addr_probe_flow *flow,
                            uint64_t expires_ns, int installed);
    void (*name_probe_hook)(void *ctx, const uint8_t *name, size_t len,
                            uint8_t transport, uint8_t family, uint16_t sport_be,
                            uint64_t expires_ns, int installed);
    void *probe_hook_ctx;
    /* ПОЗДНЕЕ НАБЛЮДЕНИЕ ТОЧНОГО ПОТОКА (этап 49, D2K_CMD_LATE_OBSERVE): d2kd
       ставит метку и наблюдает; итог он сам кладёт в журнал. NULL — наблюдать
       нечем: ctlsrv сразу пишет итог «недоступно». */
    void (*late_observe_hook)(void *ctx, const d2k_ct_tuple *t, uint32_t seconds,
                              const uint8_t token[D2K_TRIAL_ID_LEN]);
    /* Контроллер отключился (этап 53): отменить его наблюдения и опыты сразу,
       по событию, а не следующим тактом. NULL — нечего. */
    void (*peer_closed_hook)(void *ctx);
    /* Hook must validate live connection identity and acknowledge only after
       delivery is ready. Absence is an explicit unavailable response. */
    void (*raw_measure_hook)(void *ctx, const struct d2k_rawmeasure_request *request);
} d2k_ctlsrv;

/* Подтверждение D2K_CMD_LATE_OBSERVE (этап 53): шлёт модуль поздней доставки,
   когда доставка своего поколения готова (ok) или поставить её не удалось. */
void d2k_ctlsrv_ack_late(d2k_ctlsrv *cx, int ok, uint8_t reason, const uint8_t token[D2K_TRIAL_ID_LEN]);

/* Может ли способ отправки исполнить план ЧЕСТНО — не «примерно».
 * §2.5 запрещает молча приближать неподдерживаемую операцию другой.
 * 1 — да; 0 — нет, причина в why. */
int d2k_plan_fits(const d2k_plan *p, uint32_t send_limits, uint32_t send_maxlen,
                  char *why, size_t cap);

/* Объявляет версию управляющего протокола подключившемуся контроллеру.
 * Зовётся СРАЗУ после d2k_ctl_accept и до любых других событий: контроллер,
 * не получивший версии или получивший чужую, обязан отказаться работать, а не
 * мерить пустоту смешанной парой (см. D2K_CTL_PROTO_VERSION в d2k_ctl.h). */
/* send_maxlen — предел длины посылки, который объявляет ЭТОТ датапат
 * (d2k_raw_maxlen); 0 — предела нет (стенд без сырого сокета). Едет
 * контроллеру вместе с версией: без него тот собирает планы, не зная, что
 * унесёт канал (см. D2K_EV_PROTO в d2k_ctl.h). */
void d2k_ctlsrv_greet(d2k_ctl *ctl, uint32_t send_maxlen);
/* Счётчики канала (D2K_EV_STATS): сколько событий датапат потерял и сколько
 * отправил. Тот же ключ без потока, что у приветствия и ACK: кадр с нулевым
 * семейством контроллер отвергает. Зовётся раз в секунду из d2kd. */
void d2k_ctlsrv_stats(d2k_ctl *ctl);
void d2k_ctlsrv_peer_closed(void *ctx);

/* Обработчик для d2k_ctl_poll. ctx — d2k_ctlsrv *. */
void d2k_ctlsrv_command(void *ctx, uint16_t type, const uint8_t *body, size_t len);
/* Обработчик второго (опытного) управляющего: только пробный план на
   местный порт потока опыта и его снятие; остальное — отказ. */
void d2k_ctlsrv_command_exp(void *ctx, uint16_t type, const uint8_t *body, size_t len);
/* Four shadow workers plus a manual experiment and reconnect headroom.
 * Resource ceiling on independent input/output buffers, not a search budget. */
#define D2K_EXP_PEERS_MAX 8u
/* Forget stream ownership before freeing/reusing a disconnected peer. */
void d2k_ctlsrv_forget_exp_ctl(d2k_ctl *x);

/* Выкладывает контроллеру записи журнала, появившиеся с прошлого раза.
 * *seen — курсор вызывающего по счётчику «добавлено за всё время». Если
 * нового больше, чем вмещает кольцо, часть уже затёрта — и это видно по
 * разнице, а не пропадает молча. */
void d2k_ctlsrv_pump(d2k_ctl *ctl, const d2k_session *s, uint64_t *seen);

void d2k_ctlsrv_http80_event(d2k_ctl *,const d2k_http80_res *);

#define D2K_RAWMEASURE_EMITTER 1
int d2k_ctlsrv_raw_measure(d2k_ctlsrv *, const struct d2k_rawmeasure_report *);
void d2k_ctlsrv_ack_raw_measure(d2k_ctlsrv *, int ok, uint8_t reason,
                                const uint8_t token[D2K_TRIAL_ID_LEN]);
#endif /* D2K_CTLSRV_H */
