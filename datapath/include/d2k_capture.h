/* Observation only: bounded TCP ClientHello capture, never packet retention.
 * Starts at an observed record head (even one byte); tails may arrive out of
 * order AFTER that head. No guessing of a head from an arbitrary stream tail.
 * One TLS record containing exactly one ClientHello, at most D2K_CAPTURE_BYTES.
 * Resource limits are capture limits, NOT evidence of blocking.
 */
#ifndef D2K_CAPTURE_H
#define D2K_CAPTURE_H
#include "d2k_track.h"

/* ПОТОЛОК СНИМКА — ПО ЗАМЕРУ ЖИВЫХ ПРИВЕТСТВИЙ, А НЕ ПО ПРИВЫЧКЕ.
 *
 * Прежние 2048 байт были сняты с приветствий прошлого поколения. Поле
 * 13.10.2026, forum.ru-board.com: Chrome шлёт 2118-2214 байт —
 * постквантовый key_share плюс перемешанный порядок расширений, — и у части
 * соединений имя уезжает в самый хвост (в снятом приветствии 2182 байта имя
 * на смещении 2129, то есть во ВТОРОМ сегменте). Снимок такое приветствие
 * отвергал целиком («total > D2K_CAPTURE_BYTES» в capture.c), сборка головы с
 * хвостом не состоялась, имени датапат не узнал, плана не поставил — а
 * коробка после своей пересборки имя видит и глушит поток молча. В браузере
 * это ERR_TIMED_OUT на картинках: из 23 потоков к цели план получили 5, у
 * остальных 18 не было ни ответа, ни сброса.
 *
 * 4096 — удвоенный измеренный максимум (2214), ближайшая степень двойки.
 * Цена: слот снимка держит bytes[] плюс карту present[] (1/8), и при 64
 * слотах это 147 КиБ против 288 КиБ. Предел записи TLS (16384) сюда не
 * берётся: это был бы бюджет «на всякий случай», а не по замеру. */
#define D2K_CAPTURE_BYTES 4096
#define D2K_CAPTURE_SLOTS 64
#define D2K_CAPTURE_WINDOW 64
#define D2K_CAPTURE_TTL_NS UINT64_C(5000000000)

typedef struct {
    d2k_key key;
    uint64_t generation, started_ns;
    uint32_t seq;
    size_t contiguous, high;
    unsigned state; /* 0 free, 1 collecting, 2 rejected, 3 delivered */
    /* Якорь стоит на НАЧАЛЕ записи TLS. Ноль значит, что слот заведён куском,
       пришедшим раньше головы: такой якорь временный и сдвинется, когда
       голова придёт (см. d2k_capture_feed). */
    unsigned anchored;
    uint8_t bytes[D2K_CAPTURE_BYTES];
    uint8_t present[D2K_CAPTURE_BYTES / 8];
} d2k_capture_slot;

typedef struct {
    d2k_capture_slot slots[D2K_CAPTURE_SLOTS];
    uint64_t completed, rejected, expired, full;
} d2k_capture;

/* Zero initialize once. No allocation on feed. READY (1) points into the
 * table; copy before feeding again. Others: 0 incomplete/ignored, -1 invalid
 * or unsupported, -2 capacity. Identical retransmits do not duplicate READY.
 * generation is the owning flow's first_ns; forget on SYN/FIN/RST as well.
 */
/* anchor/have_anchor — ИЗВЕСТНОЕ начало потока (номер сразу за SYN). С ним
 * кусок кладётся по смещению от начала и порядок прихода перестаёт значить
 * что-либо. Без него слот заводится только куском, начинающим запись TLS, —
 * прежнее поведение для вызывающих, которые начала не знают.
 *
 * Угадывать начало по первому байту (0x16) НЕЛЬЗЯ: третий кусок, пришедший
 * первым, головой не является, а хвост может начинаться с 0x16 случайно — это
 * просто байт данных. Обе ошибки воспроизведены (test_session.c). */
int d2k_capture_feed(d2k_capture *c, const d2k_key *key, uint64_t generation,
                     uint64_t now_ns, uint32_t seq, uint32_t anchor, int have_anchor,
                     const uint8_t *bytes,
                     size_t len, const uint8_t **hello, size_t *hello_len,
                     uint32_t *hello_seq);
/* Shared byte ownership/overlap engine; readiness is protocol-specific.
 * Callback: 1 ready, 0 incomplete, -1 invalid. All held bytes must be covered. */
typedef int (*d2k_capture_ready)(const uint8_t *,size_t,size_t);
int d2k_capture_feed_exact(d2k_capture *,const d2k_key *,uint64_t,uint64_t,
    uint32_t,uint32_t,const uint8_t *,size_t,const uint8_t **,size_t *,uint32_t *,size_t);
int d2k_capture_feed_ready(d2k_capture *,const d2k_key *,uint64_t,uint64_t,
    uint32_t,uint32_t,int,const uint8_t *,size_t,const uint8_t **,size_t *,uint32_t *,
    d2k_capture_ready);
void d2k_capture_forget(d2k_capture *c, const d2k_key *key);
#endif
