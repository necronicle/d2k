#ifndef D2K_QUIC_ARMS_H
#define D2K_QUIC_ARMS_H
#include "d2k_quicprobe.h"
#include "d2k_quicconn.h"

/* One question of the original askArms. Fragments use explicit donor shapes,
 * never the old midpoint substitute. frag: 0 normal, 1 pos8, 2 reverse pos8,
 * 3 tiny three-fragment overlap, 4 three-fragment overlap. */
typedef struct {
    const char *label;
    const char *addr;
    const uint8_t *blob;
    size_t blob_len;
    int copies, ttl, frag, control;
    /* Задача 40. split: 1 — ClientHello нашего Initial разрезан на два кадра
       CRYPTO, хвост первым (d2k_quic_initial_split_crypto); blob при нём
       пуст. benign: blob — безобидная датаграмма вопроса «остаточное
       разрешение» (D2K_QUIC_BENIGN), а не приманка перебора. */
    int split, benign;
    unsigned udplen; /* append after the intact Initial through the Plan executor */
    /* Задача 50, раунд 3: засчитывать только ответ целиком (поиск по обрыву
       после рукопожатия — сравнение с прямым запросом на том же пути). */
    int need_complete;
    /* Поле 04.10 (rua.gr): бюджет коробки в пакетах для воспроизведения
       обрыва своим запросом. 0 — один запрос (без воспроизведения обрыва). Больше
       нуля — запросы на новых потоках той же связи, пока она не перенесёт
       2 × budget_pk датаграмм или сервер не замолчит (PING). */
    unsigned budget_pk;
} d2k_quic_arm_question;

/* БЕЗОБИДНАЯ ДАТАГРАММА ВОПРОСА «ОСТАТОЧНОЕ РАЗРЕШЕНИЕ» (задача 40).
 *
 * Heitmann et al., FOCI 2026: для части имён (discord.com, *.googlevideo.com,
 * play.google.com …) коробка не трогает Initial, если по той же четвёрке
 * раньше ушли незапрещённые данные. Вопрос: одна такая датаграмма, затем наш
 * Initial на той же свежей четвёрке.
 *
 * Форма — 16 нулевых байт, и выбрана она по трём причинам:
 *   - коробке её не разобрать как Initial: первый байт 0x00 — короткий
 *     заголовок с погашенным фиксированным битом, 16 байт меньше любого
 *     Initial (RFC 9000 §14.1: не меньше 1200);
 *   - серверу отвечать на неё нечем: пакет с нулевым фиксированным битом
 *     отбрасывается (RFC 9000 §17.3.1), а для сброса без состояния он мал
 *     (§10.3) — ответ на сокете вопроса остаётся только ответом на наш
 *     Initial; случайные байты с первым 0xC0.. выглядели бы длинным
 *     заголовком чужой версии и могли бы вызвать Version Negotiation;
 *   - это те же байты, что «мусор» оригинала (questions.go:97) и приманка
 *     0x00…0 askArms, и датапат их уже исполняет (fake place=before): что
 *     мерили, то и ставится, без новой грамматики плана.
 * Копия одна: вопрос ровно про «первой ушла безобидная датаграмма». */
#define D2K_QUIC_BENIGN_LEN 16
extern const uint8_t d2k_quic_benign[D2K_QUIC_BENIGN_LEN];

/* Верхняя граница: benign/split/TTL/length — до двух опросов каждый;
   адаптивное произведение fake×split — один опрос. Бюджет Run выводится
   из этой границы, без изменения критерия 3/3. */
#define D2K_QUIC_STRATEGY_ASKS_MAX 9u
#define D2K_QUIC_LENGTH_INCREMENT 100u
typedef d2k_tally (*d2k_quic_arm_probe_fn)(const d2k_quic_arm_question *, void *, int *);

/* Порог и вердикты этапа данных — d2k_quicprobe.h (D2K_QUIC_ARM_DATA_BYTES). */
typedef struct {
    d2k_quic_arm_data_verdict verdict;
    uint64_t app_bytes;   /* данные ответа на запрос, прошедшие после рукопожатия */
    uint16_t local_port;  /* местный порт соединения — свежая четвёрка */
    char note[256];      /* приветствие и путь этапа (в трассу шага) */
    char reason[256];
    /* Воспроизведение по бюджету (budget_pk вопроса > 0): сколько запросов
       ушло на новых потоках, сколько датаграмм перенесла связь в обе
       стороны после первого запроса и сколько было нужно (2 × бюджет). */
    unsigned requests;
    uint64_t packets;
    unsigned need;
    /* ИЗМЕРЕННОЕ НАПРАВЛЕНИЕ ОБРЫВА. 1 — сервер продолжал шлать датаграммы,
       но ни одного НАШЕГО пакета не подтвердил (два PING без ACK): исходящее
       направление заглушено. Это измеренная форма обоих известных цензоров
       QUIC (FOCI 2026(2) §3 — Россия, 420 с по четвёрке; USENIX Sec 25 —
       Китай, 180 с), и ответ на неё — свежая четвёрка или безобидная
       датаграмма впереди, а не другая форма приветствия. Вердикт при этом
       D2K_QAD_CUT: плечо не прошло. 0 — направление не выяснено (обрыв был
       тишиной в обе стороны либо обрыва не было). */
    int oneway;
} d2k_quic_arm_data;

/* d2k_quic_arm_data_judge — d2k_quicprobe.h (одно правило с verify.c). */

/* Данные плеча, прошедшего фильтр: user — из контекста. */
typedef d2k_quic_arm_data (*d2k_quic_arm_data_fn)(const d2k_quic_arm_question *, void *user);

/* Сетевой этап данных (quicprobe.c): d2k_qc с воздействием вопроса перед
 * первым Initial, запрос HTTP/3 к sni по пути path (NULL или пусто — «/»;
 * планировщик подставляет известный большой ресурс цели). Подменяем в тестах. */
typedef d2k_quic_arm_data (*d2k_quic_arm_data_wire_fn)(const d2k_quic_arm_question *,
    const char *sni, const char *path, uint16_t port, uint32_t wait_ms, uint32_t mark);
extern d2k_quic_arm_data_wire_fn d2k_quic_arm_data_hook;

/* Этап данных на уже установленной связи c (quicprobe.c): управляющий поток
 * HTTP/3, запрос и чтение ответа до вердикта в *out (note и local_port —
 * вызывающего). Связь не закрывает. step — измеренный срок ожидания. */
void d2k_quic_data_stage(d2k_qc *c, const char *sni, const char *path, int need_complete,
                         unsigned budget_pk, uint32_t step, d2k_quic_arm_data *out);

typedef struct {
    const char (*pool)[D2K_QUIC_ADDR_LEN];
    size_t n_pool, next;
    int residual;
    d2k_quic_arm_probe_fn probe;
    void *user;
    int marked;
    int (*can_ask)(void *); /* shared Run budget; NULL for unbounded unit oracle */
    void *limit_user;
    /* Этап данных (задача 39). NULL — только фильтр: юнит-оракул порядка
       лестницы. Рабочий путь (d2k_quic_original_measure) ставит его всегда. */
    d2k_quic_arm_data_fn data;
    void *data_user;
    /* Время этапа данных — цена уже заданного вопроса, а не следующих:
       бюджет Run продлевается на него (NULL — не продлевать). */
    void (*spent)(void *limit_user, uint32_t ms);
    /* Путь запроса этапа данных (d2k_quic_arm.probe_path); NULL — «/». */
    const char *path;
    /* Задача 40: вопрос «остаточное разрешение» уже задан в этом поиске (до
       решающего ответа или до предела повторов) — запасной перебор не задаёт
       его второй раз под видом приманки 0x00…0 ×1 (тот же вопрос). */
    int benign_answered;
    /* Вопросы IP-фрагментации уже заданы стратегией (оба её ответа «нет»):
       перебор askArms их не повторяет. */
    int frag_answered;
    int split_failed; /* plain split measured NO, permits adaptive fake x split */
    int ttl_pair_answered; /* post-handshake quic5 x2 TTL3 already measured */
    /* Финальное ревью core, I1: разрез CRYPTO клиенту неприменим (ClientHello
       шире датаграммы) — вопрос о нём не задаётся, он не может стать планом. */
    int no_split;
    /* Задача 50, раунд 3: этап данных засчитывает только ответ целиком. */
    int need_complete;
    /* Same data-stage packet budget as the direct comparison; 0: one response. */
    unsigned budget_pk;
} d2k_quic_arm_context;

/* Runtime transport for one original askArms question. It receives the SNI
 * and question shape so the wire layer can rebuild a fresh donor Initial for
 * each parallel repeat without changing snapshot-based probes elsewhere.
 * The control question (fragment survival) is called with sni == NULL: the
 * wire layer draws a fresh donor neutralName() for every repeat
 * (arms.go:204-205, probe.go:230-234). */
typedef d2k_tally (*d2k_quic_ask_arm_fn)(const d2k_quic_arm_question *,
    const char *, uint16_t, uint32_t, uint32_t, int *);
extern d2k_quic_ask_arm_fn d2k_quic_ask_arm_hook;

d2k_quic_arm d2k_quic_original_arms(d2k_quic_arm_context *ctx);

/* СТРАТЕГИЯ ИЗ ОТВЕТОВ (задача 40) — рабочий путь подбора QUIC.
 *
 * Два вопроса, каждый — фильтр (ответ сервера, привязанный к нашему Initial,
 * 3/3) и этап данных (d2k_quic_arm_data_judge), на свежей четвёрке, по тому
 * же правилу адресов, что у askArms:
 *   1. остаточное разрешение: D2K_QUIC_BENIGN первой, затем Initial.
 *      Да → kind D2K_QA_BLOB, байты D2K_QUIC_BENIGN, copies 1,
 *      strategy D2K_QS_CLEARANCE; дальше ничего не спрашивается.
 *   2. разрез ClientHello на два кадра CRYPTO. Да → kind D2K_QA_SPLIT,
 *      strategy D2K_QS_SPLIT.
 *   3. +100 байт после Initial, его содержимое неизменно. Да после того же
 *      этапа данных → kind D2K_QA_UDPLEN, strategy D2K_QS_LENGTH.
 * Оба решающих «нет» → вопросы IP-фрагментации; не прошла ни одна форма —
 * перебор приманок d2k_quic_original_arms без уже заданных вопросов
 * (strategy D2K_QS_LADDER; поле 04.10, rutracker.org: «нет» на оба вопроса
 * приманок не исключает). Решающий исход — 3/3 с итогом
 * этапа данных либо 0/3; иначе (1–2 из 3, не отправилось, этап данных не
 * состоялся) вопрос повторяется ОДИН раз. Остался без решающего ответа хотя
 * бы один вопрос — запасной путь: d2k_quic_original_arms (strategy
 * D2K_QS_LADDER), его трасса дописывается следом. clearance/split_crypto
 * несут ответы (D2K_PROP_*). Метка не подтверждена — D2K_QA_FLAKY. */
d2k_quic_arm d2k_quic_strategy_arms(d2k_quic_arm_context *ctx);
/* Рабочий адаптер стратегии (props.c): те же провод и этап данных, что у
 * d2k_quic_original_measure; запасной перебор — его же лестница. */
d2k_quic_arm d2k_quic_strategy_measure(d2k_quic_arm_context *ctx, uint16_t port,
    d2k_hello trigger, d2k_hello control, uint32_t wait_ms, uint32_t mark);
/* Immutable instrument data; NULL is not replaced with a similar packet. */
/* Приманки лестницы: четыре донорских плюс 0x00…0 и quic_initial_nofix —
 * форма, которую коробка читает как Initial, а сервер обязан отбросить
 * (см. quicarms.c). */
#define D2K_QUIC_BLOBS 6
const uint8_t *d2k_quic_original_blob(size_t index, size_t *len, const char **name);

/* ОТВЕТИТ ЛИ СЕРВЕР НА ЭТУ ФАЛЬШИВКУ (поле 24.10.2026, h3-1024).
 *
 * 1 — датаграмма выглядит для сервера настоящим Initial нашей версии:
 * длинный заголовок (бит 0x80), фиксированный бит (0x40), версия 1 и не
 * меньше 1200 байт (RFC 9000 §14.1). Такая копия, дойдя до сервера, заводит
 * ему СВОЁ соединение: ответ приходит с её DCID, а настоящий Initial клиента
 * проигрывает гонку. Поэтому она обязана нести измеренный TTL и умереть по
 * дороге — документация zapret о том же: фальшивка либо не доходит до
 * сервера, либо доходит и там отбрасывается.
 *
 * 0 — сервер отбросит сам: погашенный фиксированный бит (§17.3.1), короткий
 * заголовок без состояния, чужая версия или слишком малый размер. Такой
 * фальшивке TTL не нужен — она безвредна на любом расстоянии. */
/* static inline, как судьи вердиктов в d2k_quicprobe.h: предикат над байтами
 * нужен и ядру, и сборщику плана из libd2k_udp.a, которую d2kvoice линкует без
 * quicarms.o — отдельная единица трансляции сломала бы линковку деплой-бинарей,
 * и зелёный make check этого бы не поймал. */
static inline int d2k_quic_blob_answerable(const uint8_t *bytes, size_t len) {
    if (!bytes || len < 1200) { return 0; }                    /* RFC 9000 §14.1 */
    if (!(bytes[0] & 0x80) || !(bytes[0] & 0x40)) { return 0; } /* короткий заголовок / §17.3.1 */
    if (((bytes[0] >> 4) & 3) != 0) { return 0; }               /* длинный заголовок не Initial */
    uint32_t ver = (uint32_t)bytes[1] << 24 | (uint32_t)bytes[2] << 16 |
                   (uint32_t)bytes[3] << 8 | bytes[4];
    return ver == 1;
}
d2k_quic_arm d2k_quic_original_measure(d2k_quic_arm_context *ctx, uint16_t port,
    d2k_hello trigger, d2k_hello control, uint32_t wait_ms, uint32_t mark);
/* Exact original raw-IP shapes; independent from the legacy midpoint hook. */
typedef d2k_tally (*d2k_quic_fragment_fn)(const char *,uint16_t,int,d2k_hello,
    uint32_t,uint32_t,int,int *);
extern d2k_quic_fragment_fn d2k_quic_fragment_hook;
#endif
