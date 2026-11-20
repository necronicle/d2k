/* d2k_arm.h — ПЛЕЧО: чем травят буфер пересборки, структурой.
 *
 * Отдельный заголовок, а не поле внутри d2k_compose.h, по одной причине: плечо
 * теперь ездит в обе стороны. Его СОБИРАЕТ в план core/compose.c и его же
 * НАХОДИТ перенесённый измеритель (detect/), а результат измерения едет в
 * d2k_vres (d2k_verdict.h). Если бы структура жила в d2k_compose.h, вердикт
 * тянул бы за собой сборку планов целиком — и всякий, кто читает вердикт,
 * получал бы зависимость, которая ему не нужна.
 *
 * Поля — ровно те, что читает отправитель донора (probePoison, raw_linux.go).
 * Чего здесь нет, того язык плана сегодня не выражает: данные в SYN. Это пробел РЕАЛИЗАЦИИ, а не отрицательное свойство
 * коробки (0007 п.3), и сборщик на таком плече обязан отказать, а не
 * подставить похожее.
 */
#ifndef D2K_ARM_H
#define D2K_ARM_H

#include <stddef.h>

typedef struct {
    const char *name;
    unsigned    seqovl;      /* длина перекрытия в байтах, 0 — нет */
    int         seqovl_hello;/* перекрытие длиной в целое приветствие */
    int         badsum;      /* фальшивка с битой суммой */
    unsigned    repeats;     /* копий фальшивки */
    unsigned    gap_ms;      /* пауза между копиями */
    int         disorder;    /* сбитый порядок сегментов */
    unsigned    disorder_pos;/* одиночный абсолютный разрез reverse-disorder */
    int         between;     /* фальшивка МЕЖДУ кусками, а не перед ними */
    unsigned    ttl;         /* TTL фальшивки, 0 — не задан */
    /* TTL ПО ИЗМЕРЕННОМУ ПУТИ (ip_autottl документации zapret2): считает
     * датапат на исполнении по TTL ответной стороны потока. Константа в ttl
     * сама приметна — у донора жёсткий ip_ttl=8 палился с роутера в 50 хопах.
     * autottl == 0 — поля не значимы. */
    int         autottl;
    int         autottl_delta;
    unsigned    autottl_min;
    unsigned    autottl_max;
    int         seq_out;     /* номер вне окна */
    int         decoy_hello; /* телом фальшивки идёт приветствие, не набивка */
    int         md5;         /* нулевая TCP-MD5 подпись, как у сырого зонда */
    int         md5_ts;      /* MD5 первой + метка времени (раскладка nfqws1
                                tcp_md5_first); отдельная ось от md5-одиночки */
    int         tcpts;       /* метка времени со сдвигом назад */
    /* Поднять опцию метки в начало опций TCP (tcp_ts_up документации
     * zapret2): условие отбрасывания у linux зависит от порядка опций. */
    int         tcpts_up;
    int         ipidzero;    /* обнулённый идентификатор IP */
    int         oob;         /* вставка байта TCP urgent в середину имени */
    unsigned    split_pos;   /* прямой разрез настоящей нагрузки в этой позиции
                                (split payload_start +N, order forward) — так
                                режет настоящее приветствие семейство C; 0 —
                                нет. Отличен от disorder_pos (обратный порядок). */
} d2k_arm;

/* Owned decoy input. No borrowed pointers may cross worker results.
 * Trigger bytes stay with the caller; the raw trigger supports 16 KiB even
 * though scheduler snapshots and owned decoys currently hold 2048 bytes. */
#define D2K_ARM_TRIGGER_MAX 16384
#define D2K_ARM_DECOY_MAX 2048
/* Existing raw sender's segment ceiling, shared rather than copied. */
#define D2K_ARM_SEGMENT_MAX 1400
/* Заголовки поверх сегмента в посылке: IPv6 40 + TCP 20 + метка времени 12.
 * Берётся худший случай, а не IPv4: при обычном канале (1500, 1492) это ничего
 * не меняет — 1400 остаётся 1400, — а на узком не обещает лишних 20 байт.
 * Датапат при активации считает IPv4 (plan_apply.c emit_overhead), так что
 * сегмент, уложенный под этот запас, у него проходит всегда. */
#define D2K_ARM_SEGMENT_HEADS 72

/* Сегмент посылок плана под объявленный предел канала. send_cap — предел
 * длины посылки целиком, с заголовком IP, как его объявляет датапат
 * (D2K_EV_PROTO); 0 — не объявлен, тогда прежняя константа.
 *
 * Поле 22.10.2026 (issue #5, #7): сегмент константой 1400 при пределе ниже
 * 1472 означал отказ датапата на активации и «план отвергнут исполнителем»
 * на каждом кандидате — у человека с узким каналом измеренных TCP-планов не
 * было вовсе. Ту же величину ставит себе отправитель замера (detect/raw.c,
 * d2k_raw_set_segment_max): измеренное и исполненное уходят одними сегментами.
 * 0 — предел так мал, что сегмента нет; плечо не задать. */
static inline unsigned d2k_arm_segment(size_t send_cap) {
    if (send_cap == 0) { return D2K_ARM_SEGMENT_MAX; }
    if (send_cap <= D2K_ARM_SEGMENT_HEADS) { return 0; }
    size_t room = send_cap - D2K_ARM_SEGMENT_HEADS;
    return room < D2K_ARM_SEGMENT_MAX ? (unsigned)room : D2K_ARM_SEGMENT_MAX;
}
typedef struct {
    size_t trigger_len;
    size_t sni_off, sni_len;
    size_t decoy_len;
    unsigned char decoy[D2K_ARM_DECOY_MAX];
} d2k_arm_input;

#endif /* D2K_ARM_H */
