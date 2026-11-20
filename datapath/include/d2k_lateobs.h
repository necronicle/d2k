#ifndef D2K_LATEOBS_H
#define D2K_LATEOBS_H

#include <stddef.h>
#include <stdint.h>
#include "d2k_ctq.h"

/* ПОЗДНЕЕ НАБЛЮДЕНИЕ ТОЧНОГО ПОТОКА (этап 49).
 *
 * Счётчики conntrack показали: сервер отвечал, затем от него ни одного
 * пакета, а клиент шлёт. Что именно шлёт клиент, счётчики не говорят: чистые
 * ACK и обновления окна ответа не требуют, байты не доказывают данные (IPv4 —
 * до 120 байт заголовков, IPv6 — заголовки расширения без предела). Это
 * свидетельство добывается на САМОМ потоке: d2kd на ограниченное время ставит
 * метку поздней доставки на его запись conntrack (этап 17), пакеты обеих
 * сторон идут в очередь, и этот наблюдатель классифицирует их — ничего не
 * меняя: пакеты отпускаются как есть.
 *
 * Итог — только наблюдаемое:
 *   REPEAT_SILENT  — клиент снова послал уже посланные байты данных
 *                    (перекрытие диапазонов seq), от сервера ни пакета;
 *   SERVER_ANSWERED — пришёл хоть один пакет сервера (жив на уровне TCP);
 *   CLIENT_NEW_DATA — данные клиента шли, повтора не видно;
 *   NO_CLIENT_DATA — пакеты клиента без данных (ACK, окно, опции);
 *   NOTHING        — за срок не пришло ни одного пакета потока (метка не
 *                    сработала, ускоритель, поток умер);
 *   UNAVAILABLE    — наблюдать нечем (поздняя доставка выключена, нет
 *                    ctnetlink, нет места).
 * Только TCP: у UDP «повтор данных» протоколом не определён. */
enum {
    D2K_LATEOBS_PENDING = 0,
    D2K_LATEOBS_REPEAT_SILENT = 1,
    D2K_LATEOBS_SERVER_ANSWERED = 2,
    D2K_LATEOBS_CLIENT_NEW_DATA = 3,
    D2K_LATEOBS_NO_CLIENT_DATA = 4,
    D2K_LATEOBS_NOTHING = 5,
    D2K_LATEOBS_UNAVAILABLE = 6
};

/* Сколько последних сегментов с данными помнить для поиска повтора. */
#define D2K_LATEOBS_SEQS 8

typedef struct {
    d2k_ct_tuple t;          /* orig: клиент → сервер */
    uint32_t seq[D2K_LATEOBS_SEQS];
    uint32_t len[D2K_LATEOBS_SEQS];
    uint8_t  n_seq, next;
    uint32_t client_pkts, client_data, repeats, server_pkts;
} d2k_lateobs;

void d2k_lateobs_init(d2k_lateobs *o, const d2k_ct_tuple *t);

/* Пакет IP (как из очереди). 1 — пакет этого потока (учтён), 0 — чужой или
 * не разобран. Пакет не меняется. */
int d2k_lateobs_feed(d2k_lateobs *o, const uint8_t *pkt, size_t n);

/* Итог: окончательный сразу при повторе в тишине или ответе сервера; иначе
 * PENDING до срока (expired = 1), по сроку — по накопленному. */
uint8_t d2k_lateobs_result(const d2k_lateobs *o, int expired);

/* Текст итога — один на датапат и контроллер (inline: контроллеру не нужен
 * объект наблюдателя ради строки). */
static inline const char *d2k_lateobs_text(uint8_t code) {
    switch (code) {
    case D2K_LATEOBS_REPEAT_SILENT: return "клиент повторил сегмент с данными, от сервера ни пакета";
    case D2K_LATEOBS_SERVER_ANSWERED: return "сервер прислал пакет";
    case D2K_LATEOBS_CLIENT_NEW_DATA: return "данные клиента шли, повтора не видно";
    case D2K_LATEOBS_NO_CLIENT_DATA: return "пакеты клиента без данных (ACK, окно, опции)";
    case D2K_LATEOBS_NOTHING: return "за срок не пришло ни одного пакета потока";
    case D2K_LATEOBS_UNAVAILABLE: return "наблюдать нечем (поздняя доставка выключена или нет места)";
    default: return "наблюдение идёт";
    }
}

#endif
