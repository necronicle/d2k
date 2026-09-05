/* d2k_nl.h — netlink и NFQUEUE на уровне байтов.
 *
 * Модуль намеренно НЕ включает <linux/netlink.h> и не использует структуры
 * ядра. Netlink — проводной формат, и разбирается он как проводной формат: по
 * явным смещениям, с явными границами. Причин три.
 *
 *   1. Так модуль собирается и проверяется на любой машине, а не только на
 *      Linux. Разбор чужих байтов — самое опасное место датапата, и оставлять
 *      его без тестов, потому что «на маке не собирается», нельзя.
 *   2. NLMSG_NEXT и NLA_ALIGN вычитают ВЫРОВНЕННУЮ длину. У последнего
 *      атрибута выравнивающего хвоста в буфере может не быть, счётчик уходит
 *      в минус, беззнаковое сравнение пропускает цикл дальше — и разбор идёт
 *      за буфер. Ровно на этом упала C-версия замерщика 2026-09-05.
 *   3. Доступ к полям через структуру предполагает выравнивание указателя.
 *      На mipsel чтение uint32_t по нечётному адресу — ловушка, а не медленное
 *      чтение. Здесь всё читается через memcpy.
 *
 * Константы и раскладки сверены с заголовками ядра из sysroot целевой арки:
 * linux/netlink.h, linux/netfilter.h, linux/netfilter/nfnetlink.h,
 * linux/netfilter/nfnetlink_queue.h.
 *
 * Поля ЗАГОЛОВКОВ netlink (nlmsg_len, nla_len, nla_type) идут в порядке байт
 * хозяина. Содержимое атрибутов nfqueue — в порядке сети. Путать эти два
 * порядка — классическая ошибка, и здесь они разведены разными функциями.
 */
#ifndef D2K_NL_H
#define D2K_NL_H

#include <stddef.h>
#include <stdint.h>

/* linux/netlink.h */
#define D2K_NETLINK_NETFILTER 12
#define D2K_NLMSG_HDRLEN      16u
#define D2K_NLMSG_ERROR       0x2
#define D2K_NLMSG_DONE        0x3
#define D2K_NLM_F_REQUEST     0x01
#define D2K_NLM_F_ACK         0x04
#define D2K_NLA_HDRLEN         4u
#define D2K_NLA_TYPE_MASK     0x3fff  /* ~(NLA_F_NESTED|NLA_F_NET_BYTEORDER) */

/* linux/netfilter/nfnetlink.h */
#define D2K_NFNL_SUBSYS_QUEUE 3
#define D2K_NFNETLINK_V0      0
#define D2K_NFGENMSG_LEN      4u

/* linux/netfilter/nfnetlink_queue.h */
#define D2K_NFQNL_MSG_PACKET        0
#define D2K_NFQNL_MSG_VERDICT       1
#define D2K_NFQNL_MSG_CONFIG        2
#define D2K_NFQNL_MSG_VERDICT_BATCH 3

#define D2K_NFQA_PACKET_HDR   1
#define D2K_NFQA_VERDICT_HDR  2
#define D2K_NFQA_MARK         3
#define D2K_NFQA_PAYLOAD     10
#define D2K_NFQA_CAP_LEN     13
#define D2K_NFQA_SKB_INFO    14

#define D2K_NFQA_CFG_CMD          1
#define D2K_NFQA_CFG_PARAMS       2
#define D2K_NFQA_CFG_QUEUE_MAXLEN 3
#define D2K_NFQA_CFG_MASK         4
#define D2K_NFQA_CFG_FLAGS        5

#define D2K_NFQNL_CFG_CMD_BIND      1
#define D2K_NFQNL_CFG_CMD_UNBIND    2
#define D2K_NFQNL_CFG_CMD_PF_BIND   3
#define D2K_NFQNL_CFG_CMD_PF_UNBIND 4

#define D2K_NFQNL_COPY_NONE   0
#define D2K_NFQNL_COPY_META   1
#define D2K_NFQNL_COPY_PACKET 2

#define D2K_NFQA_CFG_F_FAIL_OPEN  (1u << 0)
#define D2K_NFQA_CFG_F_CONNTRACK  (1u << 1)
#define D2K_NFQA_CFG_F_GSO        (1u << 2)

/* linux/netfilter.h */
#define D2K_NF_DROP   0
#define D2K_NF_ACCEPT 1
#define D2K_NF_REPEAT 4

/* Тип сообщения nfnetlink: старший байт — подсистема, младший — операция. */
#define D2K_NFQ_TYPE(op) (uint16_t)((D2K_NFNL_SUBSYS_QUEUE << 8) | (op))

/* --- чтение --------------------------------------------------------------- */

typedef struct {
    uint16_t type;
    uint16_t flags;
    uint32_t seq;
    uint32_t pid;
    const uint8_t *body;   /* сразу после 16-байтового заголовка */
    size_t   body_len;     /* nlmsg_len - 16, без выравнивающего хвоста */
} d2k_nl_msg;

typedef struct {
    const uint8_t *p;
    size_t         left;
} d2k_nl_iter;

void d2k_nl_iter_init(d2k_nl_iter *it, const uint8_t *buf, size_t len);

/* 1 — сообщение разобрано, 0 — буфер кончился либо содержит мусор.
 * Мусор гасит итератор целиком: искать следующий заголовок по выдуманному
 * смещению нельзя, а «пропустить и продолжить» здесь означает разбирать
 * произвольные байты как заголовки. */
int d2k_nl_next(d2k_nl_iter *it, d2k_nl_msg *m);

typedef struct {
    uint32_t id;
    uint16_t hw_protocol;
    uint8_t  hook;
    uint32_t mark;
    uint32_t cap_len;      /* настоящая длина пакета на проводе */
    uint32_t skb_info;

    const uint8_t *payload;
    size_t   payload_len;

    int have_hdr;      /* без него вердикт послать не о чем */
    int have_payload;
    int have_mark;
    /* Ядро отдало меньше, чем было на проводе: copy_range обрезал. Работать с
     * таким пакетом нельзя — мы рассуждали бы о куске, считая его целым. */
    int truncated;
} d2k_nl_pkt;

/* 0 — разобрано (даже если атрибутов не хватило: смотреть have_*).
 * -1 — тело короче nfgenmsg, разбирать нечего. */
int d2k_nl_packet(const d2k_nl_msg *m, d2k_nl_pkt *out);

/* Ошибка от ядра. 0 — это NLMSG_ERROR, err заполнен (0 означает подтверждение
 * на запрос с NLM_F_ACK, отрицательное — errno со знаком минус).
 * -1 — сообщение другого рода.
 *
 * Читать ошибки обязательно. Go-версия замерщика молча копила пакеты, потому
 * что посылала неверный тип атрибута, получала EINVAL и не смотрела на него. */
int d2k_nl_errno(const d2k_nl_msg *m, int32_t *err);

/* --- сборка --------------------------------------------------------------- */
/* Все возвращают длину сообщения или 0, если не поместилось в cap. */

size_t d2k_nl_verdict(uint8_t *o, size_t cap, uint16_t queue, uint32_t seq,
                      uint32_t pkt_id, uint32_t verdict);

size_t d2k_nl_cfg_cmd(uint8_t *o, size_t cap, uint16_t queue, uint32_t seq,
                      uint8_t cmd, uint16_t pf);

size_t d2k_nl_cfg_params(uint8_t *o, size_t cap, uint16_t queue, uint32_t seq,
                         uint32_t copy_range, uint8_t copy_mode,
                         uint32_t maxlen, uint32_t flags, uint32_t mask);

#endif /* D2K_NL_H */
