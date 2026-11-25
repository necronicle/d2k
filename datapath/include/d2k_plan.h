/* d2k_plan.h — контракт исполнителя планов.
 *
 * Исполнитель читает ТОЛЬКО каноническую форму TLV. Человеческую форму
 * порождает и разбирает core/plantlv.c: разборщик текста здесь был бы лишней поверхностью
 * для ошибок в компоненте, чей вход приходит из сети, а падение кладёт весь
 * транзитный трафик.
 *
 * На пути пакета нет плавающей арифметики: MIPS-коробки идут без
 * сопроцессора, и каждая операция с double там становится вызовом libgcc.
 * Все времена — целые микросекунды.
 */
#ifndef D2K_PLAN_H
#define D2K_PLAN_H

#include <stddef.h>
#include <stdint.h>


/* Версии, которые понимает эта сборка. Схема — как разбирать байты, версия
 * исполнителя — какие операции он умеет. Старый исполнитель может понимать
 * раскладку и всё равно не уметь нужного, поэтому полей два. */
/* Версия 2 добавила защиту потока (D2K_GUARD_*). План, которому она не нужна,
 * по-прежнему объявляет 1 и исполняется где угодно. */
/* Version 3: measured input constraints, a distinct fake→truth delay,
 * and explicit TCP segmentation without shortening the logical payload. */
/* Version 4 adds explicit detect/raw.c TCP wire semantics. Legacy plans
 * retain their old header semantics; learned plans are never reinterpreted. */
/* Version 5 adds a complete TLS/SNI input guard for parametric actions. */
/* Версия 6 добавляет ВЫДЕРЖКУ ПЕРЕД ЕДИНСТВЕННОЙ ПОСЫЛКОЙ (REC_DELAY): ни
 * pace, ни settle её не выражают (см. d2k_plan_internal.h про delay_us).
 * Понадобилась датаграммам: приветствие QUIC настоящего клиента едет двумя
 * Initial в 40 мкс друг от друга, и коробка складывает имя из обоих. */
/* Version 7: original IPv4/UDP fragment shapes, independently of fake.
 * Version 8 adds per-fake TLS random/session-ID runtime modifiers. */
/* Version 9 adds REC_UDPLEN: the whole UDP payload is re-emitted with N
 * appended zero bytes (zapret udplen increment=N, donor QUIC compose). */
/* Version 10 adds REC_QSPLIT: the client's Initial is re-sealed with the
 * ClientHello split into two CRYPTO frames, tail first, same length and
 * packet number (core d2k_quic_initial_split_crypto, task 40). */
/* 11 (сборка 04.10, обе ветки вместе — ни одна не выходила отдельно):
 * протокол http (задача 51, шаг 4) — вход плана — запрос HTTP, якоря
 * «sni_*» считаются от имени в Host; и REC_QDENY (задача 50, раунд 2) — QUIC
 * для имени не пропускается (датаграммы клиента снимаются, посылок нет),
 * чтобы клиент ушёл на TCP; это не обход QUIC. Старый исполнитель такие
 * планы не принимает. */
/* Version 12: raw TCP-MD5 poison in detect-tcp-v1. */
/* Version 14: independent TCP ACK shift in extended poison records. */
/* Version 15: MD5-first + timestamp fake option layout (D2K_POISON_MD5_TS). */
/* Version 16: explicit offset from the first TCP data byte, never inferred
 * from a packet's absolute sequence number or its application protocol. */
/* Version 18: TCP preflight program (window, scale, pieces, hello payload reference, timeout). */
/* Version 19: explicit delayed SYN handover and finite retry count. */
/* Version 20: explicit outgoing program after owned preflight handover. */
/* Version 21: explicit TCP emission order and fresh TLS fake repeats. */
#define D2K_EXEC_EMISSION_ORDER 21
#define D2K_EXEC_VERSION D2K_EXEC_EMISSION_ORDER
#define D2K_PLAN_PROTO_HTTP 4
/* Shared result capacity for measured and live packet programs. */
#define D2K_WIRE_BATCH_MAX 26

#define D2K_TLS_MOD_RND    (1u << 0)
#define D2K_TLS_MOD_DUPSID (1u << 1)
#define D2K_TLS_MOD_FRESH  (1u << 2)

enum { PLACE_BEFORE = 0, PLACE_BETWEEN = 1 };

/* ORDER_EMISSIONS lists indices in send order, after expanding repeats but
 * before MTU segmentation. Indices refer to the forward logical order:
 * leading fakes, then each payload slice and its between-slice fakes. */
enum { ORDER_FORWARD = 0, ORDER_REVERSE = 1, ORDER_EMISSIONS = 2 };

static inline int d2k_emission_order_valid(const uint8_t *order, size_t count) {
    if (count < 2 || count > D2K_WIRE_BATCH_MAX) return 0;
    uint32_t seen = 0;
    for (size_t i = 0; i < count; i++) {
        if (order[i] >= count) return 0;
        uint32_t bit = UINT32_C(1) << order[i];
        if (seen & bit) return 0;
        seen |= bit;
    }
    return 1;
}
#define D2K_WIRE_DETECT_TCP 1
#define D2K_WIRE_TCP_TEMPLATE 2
#define D2K_SCHEMA_MAX   1

/* Ширина идентификатора плана — записи REC_ID в TLV.
 *
 * Константой, а не числом по месту, ровно по той же причине, по которой ею
 * стала ширина ключа потока (D2K_KEY_WIRE_LEN, d2k_ctlsrv.h): зашитое число
 * расползается по разбору, журналу, проводу и разбору на той стороне, и
 * однажды меняется не везде. Здесь она видна и датапату, и контроллеру:
 * d2k_ctl.h тянет этот заголовок транзитивно (d2k_journal.h → d2k_track.h →
 * d2k_plan.h), и core/link.c читает её оттуда. */
#define D2K_PLAN_ID_LEN 16
/* Per-experience identity carried beside (never instead of) REC_ID. */
#define D2K_TRIAL_ID_LEN 16

typedef struct d2k_plan d2k_plan;
int d2k_plan_stream_input(const d2k_plan *p);

/* Судьба оригинального пакета. Задаётся ВСЕГДА: умолчания здесь нет, потому
 * что §4.1 документа требует определённой судьбы оригиналов при отмене и
 * отказе. */
typedef enum {
    D2K_ORIG_PASS = 0,
    D2K_ORIG_DROP = 1,
    D2K_ORIG_HOLD = 2
} d2k_orig_fate;

/* Биты порчи. Смысл один: сервер такой сегмент выбросит, коробка возьмёт. */
#define D2K_POISON_BADSUM     (1u << 0)
#define D2K_POISON_TCPTS_BACK (1u << 1)
#define D2K_POISON_IPID_ZERO  (1u << 2)
#define D2K_POISON_MD5        (1u << 3)
/* Поднять опцию метки времени в начало опций TCP (tcp_ts_up документации
 * zapret2). Не порча сама по себе, а ПОРЯДОК: условие, при котором linux
 * отбрасывает наш сегмент, зависит от того, первой ли идёт метка. Флагом, а
 * не отдельной записью, потому что живёт ровно там же, где TCPTS_BACK, и
 * без неё смысла не имеет. */
#define D2K_POISON_TS_UP      (1u << 4)

/* MD5-первой + метка времени, как собирает nfqws1
 * (tcp_md5:tcp_ts_up:tcp_md5_first): опция MD5 (kind 19, len 18) ПЕРВОЙ, за
 * ней метка времени (kind 8, len 10). 18+10 = 28 байт, уже кратно четырём —
 * добивка не нужна; если бы понадобилась, добивать NOP, а не EOL (донор
 * 74725023). ОТДЕЛЬНЫЙ БИТ, а не сочетание MD5|TCPTS_BACK: это сочетание
 * исторически значит «MD5 ЗАМЕЩАЕТ опции, метку отбрасывает» (test_measured
 * md5_wire это закрепляет), и менять его молча нельзя. Только измеренная
 * гипотеза профиля detect-tcp-v1, minexec=15. MD5-одиночка (бит 3) не
 * трогается. */
#define D2K_POISON_MD5_TS     (1u << 5)

/* Защита потока от подделанных ответов. Не порча и не преобразование
 * исходящего: это решение о ЧУЖОМ входящем пакете, и потому отдельное поле.
 *
 * D2K_GUARD_RST_ALIEN — снять входящий RST, чей отправитель не тот, что
 * отвечал по этому же соединению. Ориентир берётся ИЗ САМОГО ПОТОКА: из
 * SYN-ACK, который сервер прислал секунду назад. Не из константы — у донора
 * та же идея была сделана правилом по идентификатору IP 0..15 и снимала
 * НАСТОЯЩИЕ сбросы Linux-серверов (они ходят с id 0), а подделку с id 54321
 * не ловила вовсе. Ориентир, взятый из чужого потока, с этим потоком
 * разойтись не может. */
#define D2K_GUARD_RST_ALIEN (1u << 0)

/* Чем является посылка. Различать обязательно: отмена посреди фальшивок
 * безобидна, а посреди нагрузки — нет, и без этого признака одно от другого не
 * отличить. */
#define D2K_EMIT_FAKE    0
#define D2K_EMIT_PAYLOAD 1

/* Одна посылка: что выпустить, когда и с какой порчей. */
typedef struct {
    uint8_t  kind;       /* D2K_EMIT_* */
    uint32_t delay_us;   /* от предыдущей посылки */
    uint32_t seq;        /* абсолютный номер последовательности */
    uint8_t  ttl;        /* 0 — как обычно */
    /* TTL ПО ИЗМЕРЕННОМУ ПУТИ (ip_autottl документации zapret2). Константа в
     * ttl сама становится приметой: у донора жёсткий ip_ttl=8 палился с
     * роутера в 50 хопах от назначения. Здесь TTL считается на исполнении из
     * TTL ответной стороны потока: угадать исходный TTL сервера (64/128/255),
     * получить длину пути в хопах, прибавить delta и зажать в [min, max].
     * autottl == 0 — поля не значимы. */
    /* МЕТКУ ВРЕМЕНИ — ПЕРВОЙ В ОПЦИЯХ (tcp_ts_up документации zapret2).
     * Там же причина: linux отбрасывает пакеты с валидным seq и невалидным ack
     * только когда опция метки идёт ПЕРВОЙ; nfqws1 порядок не соблюдал и метка
     * оказывалась первой всегда, поэтому старая версия работала стабильно, а
     * новая нет. Профиль tcp-template-v1 копирует опции потока как есть, то
     * есть условие срабатывания наших tcpts-планов от нас скрыто. */
    uint8_t  ts_up;
    uint8_t  autottl;    /* 1 — считать TTL по пути */
    int8_t   autottl_delta;
    uint8_t  autottl_min;
    uint8_t  autottl_max;
    uint8_t  poison;     /* биты D2K_POISON_* */
    int32_t  seq_shift;
    int32_t  ack_shift;
    uint8_t  wire_profile; /* 0 legacy, D2K_WIRE_DETECT_TCP measured raw TCP */
    /* Original QUIC IPv4 fragment shape 1..4; zero = whole datagram.
       One PAYLOAD action owns the entire UDP datagram. Session expands it
       into wire fragments, never independent partial UDP datagrams. */
    uint8_t  ipfrag;
    /* This emitted segment carries one TCP urgent byte. */
    uint8_t  urgent;
    uint16_t urgent_ptr;
    /* Приставка перед нагрузкой — байты, которых в исходном пакете нет.
     *
     * Нужна перекрытию: сегмент выходит с номером на pre_len МЕНЬШЕ, чем
     * начало нагрузки, и несёт эти байты впереди. Сервер их выбросит как уже
     * полученные, а коробка, складывающая поток по порядку прихода, положит
     * их в поток и получит не то, что получит сервер.
     *
     * Отдельным полем, а не сборкой в буфер: на пути пакета нет ни выделения
     * памяти, ни копирования лишнего — сборщик проволоки всё равно копирует
     * в выходной буфер, и ему безразлично, из скольких кусков. */
    const uint8_t *pre;
    size_t   pre_len;
    const uint8_t *bytes;
    size_t   len;
    /* Не NULL только для фальшивок, созданных из шаблона с tlsmod. Владеет
       d2k_actions и освобождается d2k_actions_free. */
    uint8_t *owned_bytes;
} d2k_emit;

typedef struct {
    d2k_orig_fate fate;
    size_t    n;
    d2k_emit *v;
    /* Строковый литерал причины отказа d2k_plan_apply, если исполнитель её
       знает (задача 40: разрез CRYPTO без имени в датаграмме); NULL —
       общий отказ. Владения нет. */
    const char *refuse_why;
} d2k_actions;

/* Входной пакет. Якоря вычисляет протокольный модуль и передаёт готовыми:
 * исполнитель протоколов не разбирает и разбирать не должен. */
typedef struct {
    const uint8_t *payload;
    size_t   payload_len;
    uint32_t seq;
    int      have_sni;
    int      is_tls13;
    size_t   sni_off;
    size_t   sni_len;
    /* Максимальная длина полезной части одного TCP-сегмента, выведенная из
       MTU маршрута вызывающей стороной. Ноль — обычное поведение плана. */
    size_t   segment_cap;
    /* Оригинал нельзя отдавать ядру ПОСЛЕ наших фальшивок: вызывающий просит
       выпустить его собственной посылкой сразу за ними (fate drop). Ставит
       UDP-ветка сессии: первая датаграмма потока (QUIC Initial, голос) ещё не
       имеет подтверждённой записи conntrack, сырая фальшивка создаёт и
       подтверждает её первой, и удержанный в NFQUEUE оригинал ядро затем
       снимает как дубль (insert_failed/drop). Замерено на роутере 02.10.2026
       (задача 33): настоящий Initial не уходил, вместо него через ~300 мс
       уходил повтор клиента без плана. Без фальшивок гонки нет — флаг ничего
       не меняет. */
    int      own_after_fakes;
    /* Raw experiments have no queued kernel original to ACCEPT. */
    int      emit_original;
    /* Вход — запрос HTTP (sni_off/sni_len — имя в Host). План протокола
       http исполняется только на таком входе, иной план — только на ином. */
    int      is_http;
    int      have_stream_offset;
    uint32_t stream_offset;
    /* Session-authorized retransmission of an already completed late range. */
    int after_split_retry;
    /* Optional immutable complete IP packet for preflight (not payload).
     * Borrowed for the duration of the call; existing Plan users omit it. */
    const uint8_t *wire;
    size_t wire_len;
} d2k_pkt;

/* Состояние потока определяется в d2k_track.h. Здесь только опережающее
 * объявление: исполнителю плана достаточно указателя, а знать устройство
 * учёта потоков ему незачем и вредно — иначе один модуль начал бы зависеть от
 * раскладки другого. */
typedef struct d2k_flow d2k_flow;

/* Возвращает 0 при успехе, -1 при отказе; err заполняется причиной.
 *
 * Неподдерживаемая операция валит ИМЕННО ЭТУ функцию — до того, как план
 * коснулся хоть одного соединения. Активировать наполовину понятый план
 * нельзя. */
int  d2k_plan_load(const uint8_t *buf, size_t len,
                   d2k_plan **out, char *err, size_t errlen);
void d2k_plan_free(d2k_plan *p);

/* 0 при успехе, -1 при отказе. Отказ означает, что план к этому пакету
 * неприменим (например, не вычисляется якорь) — тогда действий нет вовсе, а не
 * «действия по умолчанию». */
int  d2k_plan_apply(const d2k_plan *p, const d2k_flow *f,
                    const d2k_pkt *in, d2k_actions *out);
void d2k_actions_free(d2k_actions *a);

/* Итог отмены исполнения на середине.
 *
 * Отмена бывает не только по воле контроллера: поток может кончиться, посылка
 * не уйти, служба остановиться. §4.1 документа требует определённой судьбы
 * оригиналов при отмене и отказе, и вот она. */
typedef struct {
    /* Что сделать с оригиналом ПРЯМО СЕЙЧАС. */
    d2k_orig_fate fate;

    /* План исполнен не полностью. Коробка увидела не то, что описывает план,
     * поэтому по такому исполнению НЕЛЬЗЯ записывать ни успех, ни неудачу:
     * §2.3 запрещает сохранять то, что не подтверждено. */
    int partial;

    /* Часть нагрузки уже на проводе, и чистого выхода нет: отпустить оригинал
     * значит послать те же байты дважды, не отпустить — потерять их. Поток
     * испорчен. Исполнитель лишь сообщает факт; что делать с таким потоком —
     * решение контроллера, а не датапата. */
    int stream_damaged;
} d2k_cancel;

/* emitted — сколько посылок из списка РЕАЛЬНО ушло в сеть. */
void d2k_actions_cancel(const d2k_actions *a, size_t emitted, d2k_cancel *out);

/* Все биты порчи, встречающиеся в плане, объединённые ИЛИ.
 *
 * Нужно тому, кто отправляет пакеты: способ отправки может не распоряжаться
 * частью полей заголовка (см. d2k_raw.h — ядро переписывает нулевой
 * идентификатор IP). Такой план нельзя активировать, потому что на проводе
 * получится не то, что описано, а §2.5 запрещает молча приближать операцию
 * другой. Сверять пределы обязан вызывающий: датапат не знает, каким способом
 * его пакеты поедут. */
uint8_t d2k_plan_poison_used(const d2k_plan *p);

/* ЧТО ПЛАН ТРЕБУЕТ ОТ ПОТОКА КЛИЕНТА — биты D2K_FLOW_NEED_*, выведенные из
 * бит порчи и профиля провода (формат TLV не меняется). Профиль
 * tcp-template-v1 копирует опции потока клиента и сдвигает в них метку
 * времени назад: такая порча исполнима только на потоке, который метку
 * предлагает. Датапат сверяет это с пакетом ДО сборки и отказывает своим
 * кодом (D2K_REFUSE_FLOW_UNFIT), а не нулём сборщика: поле issue #7,
 * 22.10.2026 — ПК без метки времени, 13 из 13 «план не применён» с текстом
 * «буфер отправки кончился». Измеренный профиль (detect-tcp-v1) предлагает
 * метку сам и от потока ничего не требует. */
#define D2K_FLOW_NEED_TCPTS (1u << 0)
uint8_t d2k_plan_flow_needs(const d2k_plan *p);
/* 1 for an explicit TCP stream coordinate, 0 for an unscoped plan. */
int d2k_plan_stream_offset(const d2k_plan *p, uint32_t *offset);
/* Additional measured request partition; first-input actions remain intact. */
int d2k_plan_after_split(const d2k_plan *,uint32_t *,uint32_t *,uint32_t *);

/* САМАЯ ДЛИННАЯ ПОСЫЛКА, которую план объявляет САМ, в байтах на проводе —
 * вместе с заголовками и опциями, то есть ровно то число, которое увидит
 * ядро.
 *
 * Нужно тому, кто отправляет: способ отправки уносит ограниченное число байт
 * (d2k_raw.h, d2k_raw_maxlen), и план, чья посылка в него не влезает, нельзя
 * активировать — на живой пробе 12.09.2026 отказ приходил от ядра («sendto:
 * Message too large») уже ПОСЛЕ того, как команда подтверждена и событие
 * «план применён» ушло контроллеру. Сверять обязан вызывающий, как и с
 * битами порчи выше: датапат не знает, каким способом его пакеты поедут.
 *
 * ЧТО СЮДА НЕ ВХОДИТ И ПОЧЕМУ. Кусок нагрузки, который план отрезает от
 * приветствия, зависит от ПАКЕТА, а не от плана, и на этапе загрузки
 * неизвестен. Считать его по худшему случаю (полный кадр) значило бы
 * отвергать любое перекрытие, потому что приставка добавляется сверх и так
 * полного кадра, — то есть резать формы, которые на настоящем, коротком
 * приветствии прошли бы. Поэтому здесь только то, что план несёт с собой:
 * приманки фальшивок и приставка перекрытия. Всё, что зависит от пакета,
 * ловится уже на отправке и сообщается наружу отдельно
 * (D2K_JRN_PLAN_UNSENT, d2k_journal.h) — «не измерено», а не «коробка не
 * поддалась».
 *
 * 0 означает «план ничего своего на провод не кладёт»: чистый разрез только
 * укорачивает то, что и так пришло целым. */
size_t d2k_plan_max_emit(const d2k_plan *p);

/* Биты защиты, объявленные планом. Их выставляет на поток вызывающий: защита
 * действует не на один пакет, а на соединение, и потому не является
 * действием. */
uint8_t d2k_plan_guards(const d2k_plan *p);
/* 1 — план «QUIC для имени не пропускается» (REC_QDENY). */
int d2k_plan_quic_deny(const d2k_plan *p);

/* ТРАНСПОРТ, ДЛЯ КОТОРОГО ПЛАН ОБЪЯВЛЕН: 6 TCP, 17 UDP, 0 — не объявлен.
 *
 * Нужен на применении: таблица планов ключуется именем и формой приветствия,
 * а «дедушкино право» (форма не объявлена) совместимо с любой формой, включая
 * QUIC. Без этой проверки план, подтверждённый на TLS поверх TCP, достаётся
 * датаграмме того же имени, и исполнитель упирается в «посылка невыполнима
 * для UDP»: разреза и перекрытия у датаграммы нет вовсе.
 *
 * Ноль — «не объявлен» (старый файл), и это НЕ «не тот» (§2.4). */
uint8_t d2k_plan_transport(const d2k_plan *p);
/* Протокол плана (запись proto): 1 tls, 2 quic, 3 voice, 4 http, 0 — не сказан. */
uint8_t d2k_plan_proto(const d2k_plan *p);

/* Идентификатор плана — те же D2K_PLAN_ID_LEN байт, что пришли записью
 * REC_ID. Нужен контроллеру, чтобы отличить применение СВОЕГО кандидата от
 * применения предыдущего (d2k_ctl.h объявляет это полем события APPLIED с
 * самого начала). NULL — плана нет.
 *
 * Плана без REC_ID разбор не запрещает, и у такого все байты нулевые. Это не
 * «идентификатор ноль», а «плану нечем представиться»: приписать его
 * кандидату нельзя, и контроллер обязан читать нули именно так (см. поле
 * plan_id в core/include/d2k_link.h). */
const uint8_t *d2k_plan_id(const d2k_plan *p);

#endif /* D2K_PLAN_H */
