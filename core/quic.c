/* quic.c — разбор QUIC Initial: узнавание, снятие защиты, имя.
 *
 * Как и datapath/tls.c, этот файл отвечает на один вопрос — что здесь лежит
 * и где в этом имя — и разбирает чужие байты с явной границей на КАЖДОМ шаге:
 * поле, не помещающееся в объявленную (кем-то на проводе) длину, —
 * противоречие; не помещающееся в то, что реально пришло, — обрывок. Смешивать
 * эти два случая нельзя: первое — подделка или баг отправителя, второе —
 * нормальная недостача данных (например, обрезанный вход при тестировании
 * границ под ASan).
 *
 * ТРИ ЛОВУШКИ, КУПЛЕННЫЕ ЗАМЕРОМ ДОНОРА (z2k-detect/internal/quicprobe).
 *
 * 1. Биты типа длинного заголовка (маска 0x30 первого байта) защитой
 *    заголовка НЕ закрыты (RFC 9001 §5.4.1 защищает только младшие 4 бита и
 *    номер пакета). На этом стоит d2k_quic_is_initial — узнать Initial можно
 *    БЕЗ вывода ключей и без расшифровки.
 *
 * 2. Версия 2 (RFC 9369) — не экзотика, а отдельный, специально
 *    сконструированный «трудный случай»: другая соль вывода ключей (§3.3.1),
 *    другие метки HKDF («quicv2 key/iv/hp» вместо «quic key/iv/hp», §3.3.2) и
 *    ДРУГАЯ нумерация типа пакета (Initial=1, а не 0, §3.2). Коробка,
 *    зашитая на v1, здесь не расшифрует ничего и даже не опознает тип; этот
 *    разбор различает версию по полю Version и не предполагает v1 умолчанием
 *    ни в одном месте. Обе версии проверены отдельными байтовыми векторами
 *    (test_quic.c: RFC 9001 A.2 для v1, RFC 9369 A.2 для v2 — тот же самый
 *    ClientHello, разные соль/метки/номер версии, что и задумано авторами
 *    RFC 9369 для лёгкой сверки реализаций).
 *
 * 3. Пакет, ПОХОЖИЙ на нужный, но не расшифровавшийся этими ключами, —
 *    НЕ доказательство: у донора был замер, где такой пакет приходил дважды
 *    из двух с задержкой как у живого ответа, и это не засчиталось успехом
 *    (см. бриф задачи). Здесь то же самое правило работает в обратную
 *    сторону: d2k_quic_sni возвращает имя ТОЛЬКО если шифротекст прошёл
 *    проверку тега AEAD (d2k_aes128_gcm_decrypt, d2k_crypto.h) — структурно
 *    похожий, но не аутентифицированный пакет имени не даёт никогда.
 *
 * СБОРКА ПОТОКА CRYPTO. Кадры внутри одного Initial-пакета — это ломтики
 * потока байт ClientHello, каждый со своим смещением; реальные браузеры (не
 * только эвазивные инструменты) режут ClientHello на несколько кадров CRYPTO
 * в одном и том же пакете, и кадры НЕ ОБЯЗАНЫ идти по возрастанию смещения.
 * Гадать о длине кадра НЕИЗВЕСТНОГО типа нельзя (в Initial разрешены только
 * PADDING/PING/ACK/CRYPTO/CONNECTION_CLOSE-0x1c, RFC 9000 §17.2.2) — на первом
 * непризнанном байте разбор кадров останавливается насовсем, но уже собранные
 * куски CRYPTO остаются в силе (см. collect_crypto_frames). Реассемблируются
 * куски в буфер фиксированного размера БЕЗ выделений памяти: смещение растёт,
 * пока следующий кусок примыкает встык или с перехлёстом к уже собранному —
 * первый же разрыв («с пропусками», ровно как предупреждает бриф) стопорит
 * рост и дальше уже не восстанавливается в пределах ОДНОГО пакета: продолжение
 * потока — за пределами этого вызова, а гадать, что там, нельзя.
 *
 * БЕЗ ВЫДЕЛЕНИЙ ПАМЯТИ. Обе функции вызываются на каждом UDP-пакете в
 * горячем пути датапата (задача 4 этой же вертикали, ещё не написана) — вся
 * работа целиком на стеке, буферы фиксированного размера, см.
 * D2K_QUIC_MAX_DGRAM ниже.
 */
#include <string.h>

#include "d2k_quic.h"
#include "d2k_quicwire.h"

/* ---------------------------------------------------------------------
 * Константы протокола. Каждая — из текста RFC, а не «на вкус».
 * --------------------------------------------------------------------- */

#define D2K_QUIC_V1 0x00000001u /* RFC 9000 */
#define D2K_QUIC_V2 0x6b3343cfu /* RFC 9369 §3.1 — первые 4 байта sha256("QUICv2 version number") */

/* Обе соли — 20 байт (RFC 9001 §5.2 и RFC 9369 §3.3.1 задают одну и ту же
 * длину), поэтому один именованный размер на обе — decrypt_initial ниже
 * передаёт его в d2k_hkdf_extract независимо от того, какая соль выбрана. */
#define D2K_QUIC_SALT_LEN 20

/* RFC 9000 §17.2: длина DCID/SCID в длинном заголовке — 8-битное число, но
 * "MUST NOT exceed 20 bytes... Endpoints that receive a ... value larger than
 * 20 MUST drop the packet". Это не граница буфера (любое значение 0..255
 * технически ПОМЕЩАЕТСЯ в однобайтовое поле) — это требование стандарта,
 * нарушение которого само по себе говорит «не наш Initial». Действует для
 * обеих версий: RFC 9369 не меняет этот пункт. */
#define D2K_QUIC_CID_MAX 20

/* Наибольшая датаграмма, которую готов держать разбор. Функции этого модуля
 * не выделяют память (задача 4 зовёт их на каждом UDP-пакете в горячем пути)
 * — значит буферы фиксированного размера, а не по размеру входа. Нижняя
 * граница задана стандартом: RFC 9000 §14.1 требует от клиента дополнять
 * Initial минимум до 1200 байт (см. protected_packet в test_crypto.c и оба
 * вектора в test_quic.c — ровно 1200). Верхняя граница стандартом не
 * зафиксирована («MAY exceed 1200 bytes if the sender believes the network
 * path... support the size», §14.1) — берётся размер кадра Ethernet (1500,
 * IEEE 802.3), с которым такая датаграмма проходит без фрагментации почти
 * везде, включая WAN Keenetic (PPPoE даже режет до 1492). Датаграмма крупнее
 * этого предела — не типичный браузерный Initial, и не в этом её отвергать
 * ЖИЗНЕННО: разбор просто честно не пытается её понять (см. parse_initial_header). */
#define D2K_QUIC_MAX_DGRAM 1500

/* Сколько кадров CRYPTO в ОДНОМ Initial-пакете готов держать разбор. Реальные
 * браузеры режут ClientHello на несколько кадров в одном пакете (донор
 * ссылается на Firefox 137 по умолчанию и на USENIX Sec'25 про GFW, который
 * такие кадры не пересобирает) — на практике это 2-3 куска. Восемь — запас
 * той же природы, что и D2K_HKDF_LABEL_MAX в d2k_crypto.h: цена лишних слотов
 * в стековом массиве нулевая, а лишний кадр сверх этого числа просто не
 * учитывается (см. collect_crypto_frames), а не роняет разбор. */
#define D2K_QUIC_MAX_CRYPTO_CHUNKS 8

/* ---------------------------------------------------------------------
 * Мелкие читалки. rd16/rd32 — big-endian, как весь QUIC (RFC 9000 §17).
 * --------------------------------------------------------------------- */

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}


/* Переменная длина QUIC (RFC 9000 §16): два старших бита ПЕРВОГО байта задают
 * ширину поля (1/2/4/8 байт) — а значит ширину можно узнать только прочитав
 * этот байт, и лишь ПОСЛЕ этого проверять, что она умещается в avail. Именно
 * в такой последовательности, а не наоборот: прочитать "на всякий случай"
 * 8 байт нельзя — за пришедшими n байт может не быть ничего. val/width не
 * трогаются при отказе (obryvok — не хватило байт даже на объявленную ширину,
 * это не наша забота отличать от "поле неверно устроено": и то и другое
 * означает "здесь нечего читать дальше"). */
static int read_varint(const uint8_t *p, size_t avail, uint64_t *val, size_t *width) {
    if (avail < 1) {
        return -1;
    }
    size_t w = (size_t)1 << (p[0] >> 6);
    if (avail < w) {
        return -1;
    }
    uint64_t v = (uint64_t)(p[0] & 0x3f);
    for (size_t i = 1; i < w; i++) {
        v = (v << 8) | p[i];
    }
    *val = v;
    *width = w;
    return 0;
}

/* ---------------------------------------------------------------------
 * Версия: соль и метки. "client in"/"server in" ОБЩИЕ для v1 и v2 — RFC 9369
 * меняет только метки пакетной защиты и защиты заголовка (§3.3.2), метки
 * извлечения секрета уровня не трогает. Здесь нужна только клиентская сторона
 * ("client in"): этот модуль расшифровывает ПАКЕТ КЛИЕНТА (ClientHello — то,
 * что клиент посылает серверу), а не ответ сервера — это другая точка
 * наблюдения и задача другого модуля (core/quicprobe.c, ещё не написан).
 * --------------------------------------------------------------------- */

/* ---------------------------------------------------------------------
 * Разбор заголовка Initial — общий для d2k_quic_is_initial и d2k_quic_sni,
 * чтобы у них не было шанса разойтись в том, что считать Initial. НЕ трогает
 * ключи и шифр вовсе — только структура заголовка и границы.
 * --------------------------------------------------------------------- */

typedef struct {
    uint32_t version;
    size_t dcid_off, dcid_len;
    size_t pn_offset;      /* где начинается (ещё защищённый) номер пакета */
    size_t length_claimed; /* поле Length: номер пакета + payload + тег AEAD */
} quic_hdr;

static int parse_initial_header(const uint8_t *p, size_t n, quic_hdr *h) {
    if (!p) {
        return -1; /* проверяется здесь один раз, а не в каждом из двух публичных входов */
    }
    if (n > D2K_QUIC_MAX_DGRAM) {
        return -1; /* см. комментарий у константы: за этим пределом разбор сознательно не пытается */
    }
    /* РАЗБОР — ОБЩИЙ (core/quicwire.c), а не свой. Копия этого кода уже жила
       здесь и в quicprobe.c, и копии успели разойтись: одна знала версию 2,
       другая нет. Здесь остаются только требования, которые предъявляет
       ИМЕННО ЭТОТ путь — пакетный, где нас интересует ровно клиентский
       Initial известной версии. */
    d2k_qw_hdr qh;
    if (d2k_qw_hdr_parse(p, n, 0, &qh) != 0) {
        return -1;
    }
    if (!qh.long_hdr) {
        return -1; /* короткий заголовок — до него в Initial-пространстве дело не доходит */
    }
    if (qh.version != D2K_QW_V1 && qh.version != D2K_QW_V2) {
        return -1; /* неизвестная версия — честно не наш Initial */
    }
    if (qh.type != D2K_QW_LT_INITIAL) {
        return -1; /* тот же длинный заголовок, но 0-RTT/Handshake/Retry */
    }
    h->version = qh.version;
    h->dcid_off = qh.dcid_off;
    h->dcid_len = qh.dcid_len;
    h->pn_offset = qh.pn_offset;
    h->length_claimed = qh.length_claimed;
    return 0;
}

int d2k_quic_is_initial(const uint8_t *p, size_t n) {
    quic_hdr h;
    return parse_initial_header(p, n, &h) == 0;
}

/* ---------------------------------------------------------------------
 * Снятие защиты заголовка, вывод ключей, расшифровка.
 * --------------------------------------------------------------------- */

static int decrypt_initial(const uint8_t *p, const quic_hdr *h, uint8_t *plain, size_t *plain_len) {
    /* Ключи и снятие защиты — ОБЩИЕ (core/quicwire.c). Здесь остаётся только
       то, что знает этот путь: сторона клиентская, а номер пакета в начале
       соединения мал, и наибольшего принятого у пакетного разбора нет —
       состояния между вызовами у него не бывает по устройству. */
    uint8_t secret[32];
    if (d2k_qw_initial_secret(h->version, p + h->dcid_off, h->dcid_len,
                              D2K_QW_CLIENT, secret) != 0) {
        return -1;
    }
    d2k_qw_keys k;
    if (d2k_qw_keys_from_secret(h->version, secret, &k) != 0) {
        return -1;
    }
    d2k_qw_hdr qh;
    memset(&qh, 0, sizeof qh);
    qh.long_hdr = 1;
    qh.version = h->version;
    qh.type = D2K_QW_LT_INITIAL;
    qh.dcid_off = h->dcid_off;
    qh.dcid_len = h->dcid_len;
    qh.pn_offset = h->pn_offset;
    qh.length_claimed = h->length_claimed;
    qh.packet_len = h->pn_offset + h->length_claimed;
    return d2k_qw_open(&k, &qh, p, 0, plain, plain_len, NULL);
}

/* ---------------------------------------------------------------------
 * Кадры внутри расшифрованного payload. Разрешены (RFC 9000 §17.2.2, дословно
 * «CRYPTO frame(s)... ACK frames... PING, PADDING, and CONNECTION_CLOSE
 * frames of type 0x1c are also permitted»): PADDING(0x00), PING(0x01),
 * ACK(0x02/0x03), CRYPTO(0x06), CONNECTION_CLOSE-0x1c(0x1c). Заявление 0x1d
 * (закрытие уровня приложения) явно НЕ входит в этот список — и правда,
 * RFC 9000 §19.19: "The application-specific variant of CONNECTION_CLOSE
 * (type 0x1d) can only be sent using 0-RTT or 1-RTT packets" — то есть 0x1d
 * в Initial есть нарушение протокола, и разбор останавливается на нём точно
 * так же, как на любом другом неразрешённом здесь типе.
 * --------------------------------------------------------------------- */

typedef struct {
    uint64_t offset; /* положение куска В ПОТОКЕ CRYPTO (не в payload!) */
    size_t pos;       /* положение данных куска внутри plain[] */
    size_t len;
} crypto_chunk;

/* Возвращает число собранных кусков CRYPTO (0..D2K_QUIC_MAX_CRYPTO_CHUNKS).
 * Кадры читаются строго в порядке ПЕРЕДАЧИ (как лежат в payload) — это НЕ то
 * же самое, что порядок смещений в потоке: порядок смещений восстанавливает
 * отдельно reassemble_crypto_stream. На первом нераспознанном или сломанном
 * (объявленная кадром длина не помещается в payload) байте разбор кадров
 * останавливается насовсем — гадать, где начинается следующий кадр, нельзя
 * ни для неизвестного типа, ни для битого известного: оба случая одинаково
 * лишают нас точки, откуда продолжать. */
static size_t collect_crypto_frames(const uint8_t *plain, size_t plen, crypto_chunk *chunks) {
    size_t n_chunks = 0;
    size_t i = 0;
    while (i < plen) {
        uint8_t t = plain[i];

        if (t == 0x00) { /* PADDING — просто нулевые байты, длина в кадре не хранится */
            while (i < plen && plain[i] == 0x00) {
                i++;
            }
            continue;
        }
        if (t == 0x01) { /* PING — без данных */
            i++;
            continue;
        }
        if (t == 0x02 || t == 0x03) { /* ACK / ACK_ECN, RFC 9000 §19.3-19.3.2 */
            size_t j = i + 1;
            size_t w;
            uint64_t largest, delay, range_count, first_range;
            if (read_varint(plain + j, plen - j, &largest, &w) != 0) {
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &delay, &w) != 0) {
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &range_count, &w) != 0) {
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &first_range, &w) != 0) {
                break;
            }
            j += w;
            int ranges_ok = 1;
            /* range_count заявлен отправителем и может быть сколь угодно
             * большим (до 2^62-1) — но каждая итерация обязана прочитать ещё
             * хотя бы 2 варинта, а payload не больше D2K_QUIC_MAX_DGRAM,
             * поэтому read_varint откажет самое позднее через ~plen/2
             * итераций независимо от того, что заявляет range_count. Отдельный
             * потолок на сам range_count не нужен: буфер уже его ставит. */
            for (uint64_t r = 0; r < range_count; r++) {
                uint64_t gap, range_len;
                if (read_varint(plain + j, plen - j, &gap, &w) != 0) {
                    ranges_ok = 0;
                    break;
                }
                j += w;
                if (read_varint(plain + j, plen - j, &range_len, &w) != 0) {
                    ranges_ok = 0;
                    break;
                }
                j += w;
            }
            if (!ranges_ok) {
                break;
            }
            if (t == 0x03) { /* ECN-счётчики есть только у типа 0x03 */
                uint64_t ect0, ect1, ecn_ce;
                if (read_varint(plain + j, plen - j, &ect0, &w) != 0) {
                    break;
                }
                j += w;
                if (read_varint(plain + j, plen - j, &ect1, &w) != 0) {
                    break;
                }
                j += w;
                if (read_varint(plain + j, plen - j, &ecn_ce, &w) != 0) {
                    break;
                }
                j += w;
            }
            i = j;
            continue;
        }
        if (t == 0x06) { /* CRYPTO, RFC 9000 §19.6 */
            size_t j = i + 1;
            size_t w;
            uint64_t foff, flen;
            if (read_varint(plain + j, plen - j, &foff, &w) != 0) {
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &flen, &w) != 0) {
                break;
            }
            j += w;
            if (flen > (uint64_t)(plen - j)) {
                break; /* кадр заявляет больше данных, чем есть в расшифрованном payload, — противоречие кадра */
            }
            if (n_chunks < D2K_QUIC_MAX_CRYPTO_CHUNKS) {
                chunks[n_chunks].offset = foff;
                chunks[n_chunks].pos = j;
                chunks[n_chunks].len = (size_t)flen;
                n_chunks++;
            } /* иначе кадр валиден, но слоты кончились — редкий случай, не отказ (см. константу) */
            j += (size_t)flen;
            i = j;
            continue;
        }
        if (t == 0x1c) { /* CONNECTION_CLOSE транспортного уровня, RFC 9000 §19.19 */
            size_t j = i + 1;
            size_t w;
            uint64_t err_code, frame_type, reason_len;
            if (read_varint(plain + j, plen - j, &err_code, &w) != 0) {
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &frame_type, &w) != 0) { /* только у 0x1c */
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &reason_len, &w) != 0) {
                break;
            }
            j += w;
            if (reason_len > (uint64_t)(plen - j)) {
                break;
            }
            j += (size_t)reason_len;
            i = j;
            continue;
        }

        /* Сюда попадают ДВА разных случая, и у них РАЗНЫЕ причины отказа —
         * путать их нельзя (ревью 2026-09-06: прежняя редакция валила обе
         * причины в одну "длину не угадать", что для второго случая неверно).
         *
         * Случай 1 — тип НЕИЗВЕСТЕН вовсе (не из Table 3 RFC 9000 §12.4).
         * Действительно "длину не угадать": формат тела кадра неизвестен, а
         * RFC 9000 §12.4 отдельно требует трактовать это как FRAME_ENCODING_ERROR.
         *
         * Случай 2 — тип ИЗВЕСTEН (это 0x1d, CONNECTION_CLOSE прикладного
         * уровня), и длина его тела ВЫЧИСЛИМА — формат тот же, что у 0x1c,
         * только без поля Frame Type. Отказ здесь НЕ из-за длины, а из-за
         * ПРОСТРАНСТВА НОМЕРОВ ПАКЕТОВ: 0x1d в Initial запрещён целиком, и
         * это подтверждено трижды независимо (сноска к Table 3 в §12.4:
         * "Only a CONNECTION_CLOSE frame of type 0x1c can appear in Initial
         * or Handshake packets"; §12.5: "CONNECTION_CLOSE frames signaling
         * application errors (type 0x1d) MUST only appear in the application
         * data packet number space"; §19.19, уже процитировано выше) — RFC
         * requires PROTOCOL_VIOLATION здесь, а не FRAME_ENCODING_ERROR, ровно
         * потому что кадр разобрать МОЖНО, просто ему сюда нельзя. Цена этой
         * строгости для настоящего браузера — нулевая: это разбор ПЕРВОГО
         * пакета КЛИЕНТА, а клиент физически не кладёт в Initial кадр
         * прикладной ошибки (донор трактует 0x1d так же, как 0x1c, — это
         * недосмотр донора, а не намеренная терпимость к живому трафику: его
         * же комментарий в parse.go говорит "только разрешённые в Initial
         * типы", а код принимает оба).
         *
         * Практическое следствие ОБЩЕЕ для обоих случаев: раз длина текущего
         * кадра (случай 1) или сама применимость типа (случай 2) не даёт
         * продолжить, гадать, где начинается следующий кадр, нельзя —
         * разбор кадров прекращается насовсем. Уже собранные куски CRYPTO
         * (если есть) остаются в силе: каждый прошёл свою собственную
         * проверку границ независимо от того, что случилось позже в payload. */
        break;
    }
    return n_chunks;
}

/* Сшивает куски CRYPTO в буфер stream[0..cap) по СМЕЩЕНИЮ В ПОТОКЕ, а не по
 * порядку, в котором они лежали в payload. Растёт только непрерывно от 0:
 * первый же разрыв (кусок, начинающийся дальше уже собранного) буквально
 * "с пропуском", как предупреждает бриф, — и заполнение на нём и
 * останавливается, потому что дальше данных для ClientHello у нас нет и
 * гадать о них нельзя. O(K^2) по числу кусков (K <= D2K_QUIC_MAX_CRYPTO_CHUNKS
 * = 8) — не более 64 сравнений, для одного пакета на горячем пути бесплатно. */
static size_t reassemble_crypto_stream(const uint8_t *plain, const crypto_chunk *chunks,
                                        size_t n_chunks, uint8_t *stream, size_t cap) {
    size_t filled = 0;
    int progress = 1;
    while (progress) {
        progress = 0;
        for (size_t i = 0; i < n_chunks; i++) {
            uint64_t coff = chunks[i].offset;
            size_t clen = chunks[i].len;
            if (coff > (uint64_t)filled) {
                continue; /* дальше уже собранного — пропуск, пока не найдётся смежный кусок */
            }
            uint64_t cend = coff + (uint64_t)clen; /* clen <= D2K_QUIC_MAX_DGRAM, переполнения нет */
            if (cend <= (uint64_t)filled) {
                continue; /* кусок целиком уже учтён (повтор/перекрытие) */
            }
            size_t new_filled = (cend > (uint64_t)cap) ? cap : (size_t)cend;
            if (new_filled <= filled) {
                continue; /* после обрезки по потолку буфера добавить нечего */
            }
            size_t skip = filled - (size_t)coff; /* сколько байт куска уже перекрыто предыдущими */
            memcpy(stream + filled, plain + chunks[i].pos + skip, new_filled - filled);
            filled = new_filled;
            progress = 1;
        }
    }
    return filled;
}

/* ---------------------------------------------------------------------
 * ClientHello внутри собранного потока CRYPTO. QUIC передаёт содержимое
 * Handshake-сообщений TLS БЕЗ записи TLS: "QUIC takes the unprotected content
 * of TLS handshake records as the content of CRYPTO frames. TLS record
 * protection is not used by QUIC" (RFC 9001 §4.1.3). Поэтому здесь нет ни
 * REC_HDR, ни проверки типа/версии записи — сразу заголовок Handshake
 * (тип + 3-байтная длина), как в datapath/tls.c сразу ПОСЛЕ снятия записи.
 * Дальше — тот же приём: claimed (что заявляет длина Handshake) и avail (что
 * реально собралось в stream) — разные границы, и путать их нельзя.
 * --------------------------------------------------------------------- */

#define HS_HDR 4
#define HS_CLIENT_HELLO 0x01
#define EXT_SERVER_NAME 0x0000
#define SNI_HOST_NAME 0x00

static int skip_u8_vec(const uint8_t *b, size_t len, size_t *off) {
    if (*off + 1 > len) {
        return -1;
    }
    size_t n = b[*off];
    if (*off + 1 + n > len) {
        return -1;
    }
    *off += 1 + n;
    return 0;
}

static int skip_u16_vec(const uint8_t *b, size_t len, size_t *off) {
    if (*off + 2 > len) {
        return -1;
    }
    size_t n = rd16(b + *off);
    if (*off + 2 + n > len) {
        return -1;
    }
    *off += 2 + n;
    return 0;
}

static int find_sni(const uint8_t *b, size_t exts_off, size_t exts_end,
                     size_t *sni_off, size_t *sni_len) {
    size_t off = exts_off;
    while (off + 4 <= exts_end) {
        uint16_t type = rd16(b + off);
        size_t elen = rd16(b + off + 2);
        off += 4;
        if (off + elen > exts_end) {
            return -1;
        }
        if (type == EXT_SERVER_NAME) {
            size_t p = off;
            if (p + 2 > off + elen) {
                return -1;
            }
            size_t list_len = rd16(b + p);
            p += 2;
            if (p + list_len > off + elen) {
                return -1;
            }
            size_t list_end = p + list_len;
            while (p + 3 <= list_end) {
                uint8_t nt = b[p];
                size_t nlen = rd16(b + p + 1);
                p += 3;
                if (p + nlen > list_end) {
                    return -1;
                }
                if (nt == SNI_HOST_NAME) {
                    if (nlen == 0) {
                        return -1; /* пустое имя — это не имя */
                    }
                    *sni_off = p;
                    *sni_len = nlen;
                    return 0;
                }
                p += nlen;
            }
            return -1;
        }
        off += elen;
    }
    return -1;
}

static int find_client_hello_sni(const uint8_t *stream, size_t filled,
                                  size_t *sni_off, size_t *sni_len) {
    if (filled < HS_HDR) {
        return -1;
    }
    if (stream[0] != HS_CLIENT_HELLO) {
        return -1; /* на уровне Initial клиент шлёт единственное сообщение — ClientHello (RFC 9001 §4.1.3) */
    }
    size_t hs_len = (size_t)stream[1] << 16 | (size_t)stream[2] << 8 | stream[3];
    size_t claimed = HS_HDR + hs_len;
    size_t avail = filled;
    size_t end = claimed < avail ? claimed : avail;

    size_t off = HS_HDR;
    if (off + 2 + 32 > end) { /* client_version(2) + random(32) */
        return -1;
    }
    off += 2 + 32;
    if (skip_u8_vec(stream, end, &off) != 0) {  /* legacy_session_id */
        return -1;
    }
    if (skip_u16_vec(stream, end, &off) != 0) { /* cipher_suites */
        return -1;
    }
    if (skip_u8_vec(stream, end, &off) != 0) {  /* compression_methods */
        return -1;
    }
    if (off + 2 > end) {
        return -1; /* расширений нет вовсе — законный ClientHello, но имени тогда нет */
    }
    size_t exts_len = rd16(stream + off);
    off += 2;
    if (off + exts_len > claimed) {
        return -1; /* блок расширений врёт даже в рамках заявленной длины Handshake — противоречие */
    }
    size_t exts_end = off + exts_len;
    if (exts_end > avail) {
        exts_end = avail; /* влезает в заявленное, но не в то, что реально собралось, — читаем что есть */
    }

    return find_sni(stream, off, exts_end, sni_off, sni_len);
}

/* ---------------------------------------------------------------------
 * Публичный вход.
 * --------------------------------------------------------------------- */

/* Общая часть d2k_quic_sni и d2k_quic_client_hello: из защищённой датаграммы
 * — собранный поток CRYPTO. Возвращает длину собранного (0 — не вышло). */
static size_t crypto_stream_of(const uint8_t *p, size_t n,
                               uint8_t *stream, size_t cap) {
    quic_hdr h;
    if (parse_initial_header(p, n, &h) != 0) {
        return 0;
    }
    uint8_t plain[D2K_QUIC_MAX_DGRAM];
    size_t plain_len;
    if (decrypt_initial(p, &h, plain, &plain_len) != 0) {
        return 0;
    }
    crypto_chunk chunks[D2K_QUIC_MAX_CRYPTO_CHUNKS];
    size_t n_chunks = collect_crypto_frames(plain, plain_len, chunks);
    return reassemble_crypto_stream(plain, chunks, n_chunks, stream, cap);
}

int d2k_quic_client_hello(const uint8_t *p, size_t n,
                          uint8_t *out, size_t cap, size_t *out_len) {
    if (!p || !out || !out_len) {
        return -1;
    }
    uint8_t stream[D2K_QUIC_MAX_DGRAM];
    size_t filled = crypto_stream_of(p, n, stream, sizeof stream);
    if (filled < HS_HDR || stream[0] != HS_CLIENT_HELLO) {
        return -1;
    }
    size_t claimed = ((size_t)stream[1] << 16) | ((size_t)stream[2] << 8) | stream[3];
    size_t whole = HS_HDR + claimed;
    /* ЦЕЛИКОМ — по СОБСТВЕННОЙ заявленной длине, а не «сколько собралось».
       Тот же разбор границ, что и всюду в этом файле: claimed и filled —
       разные величины, и отдать вызывающему обрывок как приветствие значило
       бы отдать ему пакет, который никто не примет. */
    if (whole > filled || whole > cap) {
        return -1;
    }
    memcpy(out, stream, whole);
    *out_len = whole;
    return 0;
}

int d2k_quic_sni(const uint8_t *p, size_t n, char *out, size_t cap) {
    if (!p || !out || cap == 0) {
        return -1;
    }

    uint8_t stream[D2K_QUIC_MAX_DGRAM];
    size_t filled = crypto_stream_of(p, n, stream, sizeof stream);

    size_t sni_off, sni_len;
    if (find_client_hello_sni(stream, filled, &sni_off, &sni_len) != 0) {
        return -1;
    }
    if (sni_len + 1 > cap) {
        return -1; /* не помещается в буфер вызывающего целиком — режем молча только по прямому запросу, не здесь */
    }

    memcpy(out, stream + sni_off, sni_len);
    out[sni_len] = '\0';
    return 0;
}
