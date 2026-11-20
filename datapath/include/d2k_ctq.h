/* d2k_ctq.h — счётчики ОДНОГО потока conntrack по его кортежу (ctnetlink).
 *
 * Зачем (задача 50, раунд 3). Детектор «QUIC замолчал после рукопожатия»
 * смотрит на счётчики пакетов потока: прямой растёт, обратный стоит. Очередь
 * видит у UDP лишь первые 8 пакетов в каждую сторону, так что счётчики — из
 * conntrack. Раунд 2 читал для этого /proc/net/nf_conntrack целиком раз в
 * секунду прямо в цикле очереди: O(всей таблицы), на 10–30 тысячах записей —
 * сотни миллисекунд, пока очередь не разбирается. Здесь — запрос ЯДРУ по
 * кортежу (IPCTNL_MSG_CT_GET с CTA_TUPLE_ORIG): поиск в хэше, O(1) на поток,
 * O(наблюдаемых потоков) на обход.
 *
 * НЕ ЖДАТЬ НА ПАКЕТНОМ ПУТИ. Ответ может прийти позже возврата send.
 * Старые query_fd/query_info_fd дают только best-effort наблюдение: ответа
 * сейчас нет — ничего не знаем. Для владения пакетом нужен d2k_ct_async:
 * он сохраняет sequence между проходами poll на отдельном сокете и не
 * отбрасывает поздний ответ как ответ чужого запроса.
 *
 * Проводной формат собирается по явным смещениям, как в d2k_nl.h, и потому
 * собирается и проверяется на любой машине. Сокет netlink — только Linux.
 *
 * Константы сверены с linux/netfilter/nfnetlink.h и
 * linux/netfilter/nfnetlink_conntrack.h. */
#ifndef D2K_CTQ_H
#define D2K_CTQ_H

#include <stddef.h>
#include <stdint.h>

#define D2K_NFNL_SUBSYS_CTNETLINK 1
#define D2K_IPCTNL_MSG_CT_NEW     0
#define D2K_IPCTNL_MSG_CT_GET     1

#define D2K_CTA_TUPLE_ORIG        1
#define D2K_CTA_TUPLE_REPLY       2
#define D2K_CTA_COUNTERS_ORIG     9
#define D2K_CTA_COUNTERS_REPLY    10
#define D2K_CTA_TUPLE_IP          1
#define D2K_CTA_TUPLE_PROTO       2
#define D2K_CTA_IP_V4_SRC         1
#define D2K_CTA_IP_V4_DST         2
#define D2K_CTA_IP_V6_SRC         3
#define D2K_CTA_IP_V6_DST         4
#define D2K_CTA_PROTO_NUM         1
#define D2K_CTA_PROTO_SRC_PORT    2
#define D2K_CTA_PROTO_DST_PORT    3
#define D2K_CTA_COUNTERS_PACKETS  1
#define D2K_CTA_COUNTERS_BYTES    2
#define D2K_CTA_COUNTERS32_PACKETS 3
#define D2K_NLA_F_NESTED          0x8000
/* Состояние TCP у conntrack (задача 56): CTA_PROTOINFO → CTA_PROTOINFO_TCP →
   CTA_PROTOINFO_TCP_STATE, u8; значения — enum tcp_conntrack ядра. */
#define D2K_CTA_PROTOINFO         4
#define D2K_CTA_PROTOINFO_TCP     1
#define D2K_CTA_PROTOINFO_TCP_STATE 1
#define D2K_CT_TCP_ESTABLISHED    3

/* Кортеж прямого направления: адреса 4 или 16 байт по family, порты в
   сетевом порядке (как в пакете). */
typedef struct {
    uint8_t family;      /* 4 или 6 */
    uint8_t proto;       /* 6 или 17 */
    uint8_t src[16], dst[16];
    uint8_t sport_be[2], dport_be[2];
} d2k_ct_tuple;

/* Что ядро сказало о потоке. Состояние TCP есть не всегда (UDP, старое
   ядро): без него «соединение ещё установлено» не доказано. */
typedef struct {
    uint64_t orig_pkts, reply_pkts;
    uint64_t orig_bytes, reply_bytes; /* этап 37: из тех же CTA_COUNTERS_*; 0 — ядро не дало */
    uint8_t  counters_known;   /* этап 38: счётчики обеих сторон есть (учёт conntrack включён) */
    uint8_t  tcp_state;        /* enum tcp_conntrack, если tcp_state_known */
    uint8_t  tcp_state_known;
    uint8_t  mark_known;       /* CTA_MARK в ответе (ядро с CONFIG_NF_CONNTRACK_MARK) */
    uint32_t mark;             /* connmark записи, если mark_known */
    uint8_t reply_tuple_known;
    d2k_ct_tuple reply_tuple;
} d2k_ct_info;

/* Запрос CT_GET по кортежу. Длина сообщения или 0, если не поместилось. */
size_t d2k_ct_get_req(uint8_t *o, size_t cap, uint32_t seq, const d2k_ct_tuple *t);

/* Разбор ответа на запрос seq. 0 — счётчики есть; 1 — ядро ответило ошибкой
   (записи нет: -ENOENT); 2 — запись без счётчиков (accounting выключен);
   -1 — не тот seq или мусор. */
int d2k_ct_counters_parse(const uint8_t *buf, size_t len, uint32_t seq,
                          uint64_t *orig_pkts, uint64_t *reply_pkts);

/* То же, со состоянием TCP (d2k_ct_info). Коды возврата — как у
   d2k_ct_counters_parse. */
int d2k_ct_info_parse(const uint8_t *buf, size_t len, uint32_t seq, d2k_ct_info *out);

/* Спросить по уже открытому сокету fd: послать и забрать ответ БЕЗ ожидания.
   0 — счётчики; 1 — ошибка ядра (записи нет); 2 — запись без счётчиков
   (accounting выключен); -1 — ответа нет. Всё, кроме 0, — «не знаем». Чужие
   и устаревшие ответы в сокете вычитываются и отбрасываются. */
int d2k_ct_query_fd(int fd, uint32_t seq, const d2k_ct_tuple *t,
                    uint64_t *orig_pkts, uint64_t *reply_pkts);

/* То же с d2k_ct_info: счётчики и состояние TCP одним запросом. */
int d2k_ct_query_info_fd(int fd, uint32_t seq, const d2k_ct_tuple *t, d2k_ct_info *out);

/* ПРОБА ДОСТУПНОСТИ (раунд 4, N2). Где nf_conntrack_netlink не загружен, ядро
   на каждый GET синхронно зовёт request_module внутри sendmsg — модпроб на
   пакетном пути. Поэтому при старте (и только на обновлении правил/маршрутов,
   не на пакетах) задаётся один GET несуществующей записи: ENOENT — ctnetlink
   есть (1); любая другая ошибка или молчание wait_ms — нет (0), и запросов по
   потокам d2kd не шлёт вовсе. */
int d2k_ct_probe_fd(int fd, uint32_t seq, int wait_ms);

/* ПЕРЕЧИСЛЕНИЕ ТАБЛИЦЫ (этап 13, 28.10.2026): уже существующие потоки на старте
 * службы. Запрос — CT_GET с NLM_F_DUMP (без кортежа), ответ — серия CT_NEW с
 * прямым кортежем и счётчиками, в конце NLMSG_DONE. Разбор не блокирует
 * пакетный путь: зовётся только на старте. fn получает прямой кортеж (клиент →
 * сервер) и счётчики; 0 — продолжать, иначе разбор прекращается. */
typedef int (*d2k_ct_dump_fn)(void *ctx, const d2k_ct_tuple *t, const d2k_ct_info *i);
#define D2K_NLM_F_DUMP 0x300
size_t d2k_ct_dump_req(uint8_t *o, size_t cap, uint32_t seq, uint8_t family);
/* Разбирает один буфер ответа: возвращает число записей (≥0) или -1 при
 * ошибке/отказе ядра; *done = 1, когда встречен NLMSG_DONE для seq. */
int d2k_ct_dump_parse(const uint8_t *buf, size_t len, uint32_t seq,
                      d2k_ct_dump_fn fn, void *ctx, int *done);
/* Запрос и чтение до NLMSG_DONE (не дольше wait_ms на каждый recv). Возвращает
 * число записей или -1 (включая неполный dump). Уже вызванные callbacks
 * не откатываются; их записи не означают полноту снимка. */
int d2k_ct_dump_fd(int fd, uint32_t seq, uint8_t family, d2k_ct_dump_fn fn, void *ctx, int wait_ms);

/* МЕТКА ЗАПИСИ (этапы 17, 51, поздняя доставка). CT_NEW по кортежу с CTA_MARK
 * и CTA_MARK_MASK, NLM_F_ACK, БЕЗ NLM_F_CREATE: меняется только существующая
 * запись (нет записи — ENOENT), новой не заводится. Ядро, которое чтит маску,
 * меняет атомарно ТОЛЬКО биты маски: новая = (старая & ~маска) ^ значение —
 * поэтому значение обязано лежать внутри маски. Прежнее «прочитать всю метку
 * и записать целиком» теряло чужие биты, сменившиеся между GET и записью.
 * Ядро, которое маску НЕ чтит, записало бы значение целиком и стёрло бы чужие
 * биты: поэтому до любой метки d2kd проверяет поведение на своей временной
 * записи (d2k_ct_mask_probe_fd) и без подтверждения метку не ставит.
 * d2k_ct_mark_fd: 0 — ядро подтвердило; >0 — errno ядра (2 ENOENT — записи
 * нет); -1 — ответа нет за wait_ms. Не на пакетном пути. */
#define D2K_CTA_MARK 8
#define D2K_CTA_MARK_MASK 21
size_t d2k_ct_mark_req(uint8_t *o, size_t cap, uint32_t seq, const d2k_ct_tuple *t,
                       uint32_t value, uint32_t mask);
int d2k_ct_mark_fd(int fd, uint32_t seq, const d2k_ct_tuple *t, uint32_t value, uint32_t mask,
                   int wait_ms);

/* ЧТИТ ЛИ ЯДРО МАСКУ МЕТКИ (этап 51). На СВОЕЙ временной записи UDP
 * 127.62.0.1:P → 127.62.0.2:9 (P — из salt, до 8 кандидатур), созданной
 * CREATE|EXCL с чужими битами 0x5 в метке и сроком 10 с: маскированная
 * установка bit, чтение, удаление. Занятая кандидатура (EEXIST) не трогается;
 * удаляется только подтверждённо созданная запись; без ответа на создание —
 * ничего не удаляется (запись истечёт сама). 1 — маска учтена (чужие биты
 * целы, bit стоит); 0 — не учтена (запись целиком: vanilla 4.9); -1 — не
 * определить. *seq — счётчик последовательностей вызывающего; salt — свой у
 * экземпляра (pid), чтобы параллельные проверки не делили кортеж. */
int d2k_ct_mask_probe_fd(int fd, uint32_t *seq, uint32_t bit, uint16_t salt, int wait_ms);

/* Сокет NETLINK_NETFILTER, неблокирующий. -1 — не Linux или ядро не дало. */
int d2k_ct_open(void);

/* Dedicated nonblocking socket; replies remain associated across poll turns.
 * At most 32 requests, each bounded to 100 ms. A successful query consumes
 * its answer; no cached mapping is reused for a later incarnation. */
#define D2K_CT_ASYNC_SLOTS 32
#define D2K_CT_ASYNC_TIMEOUT_NS 100000000ULL
typedef struct {
    uint32_t seq;
    uint64_t until_ns;
    int ready;
    d2k_ct_tuple tuple;
    d2k_ct_info info;
} d2k_ct_async_slot;
typedef struct {
    uint32_t seq;
    d2k_ct_async_slot slots[D2K_CT_ASYNC_SLOTS];
} d2k_ct_async;
void d2k_ct_async_forget(d2k_ct_async *, const d2k_ct_tuple *);
void d2k_ct_async_poll(d2k_ct_async *, int fd);
int d2k_ct_async_query(d2k_ct_async *, int fd, const d2k_ct_tuple *,
                       uint64_t now_ns, d2k_ct_info *);

#endif /* D2K_CTQ_H */
