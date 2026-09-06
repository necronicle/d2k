/* quicprobe.c — вопросы к коробке по QUIC. Порядок и устройство описаны в
 * шапке d2k_quicprobe.h; здесь — почему порядок именно такой и как устроен
 * оракул.
 *
 * ПОЧЕМУ ПОРЯДОК НЕСУЩИЙ (§7, спецификация; повторено донором независимо —
 * см. USENIX Sec'25 по GFW): остаточная блокировка глушит ТРОЙКУ (адрес
 * источника, адрес назначения, порт назначения) на минуты ПОСЛЕ того, как
 * коробка увидела заблокированное содержимое. Если проверять её не сразу
 * после прямого зонда — предыдущие вопросы УЖЕ отравят тройку своим
 * содержимым, и результат будет описывать их последствия, а не свойство
 * коробки. Отсюда:
 *
 *   0. БАЗОВАЯ ЖИВОСТЬ — контроль (нейтральное имя) на первый адрес, ДО
 *      прямого зонда. Без этого шага молчание дохлого пути (битый анкаст,
 *      HTTP/3 выключен на конкретном IP) неотличимо от молчания блокировки —
 *      см. правку ревью 2026-09-06 круг 2 и обоснование в d2k_quicprobe.h.
 *      Заодно даёт RTT: потолок ожидания для всего, что дальше, выводится из
 *      него (d2k_quic_wait_ms используется только ЗДЕСЬ, где RTT ещё
 *      неизвестен).
 *   1. ПРЯМОЙ ЗОНД — триггер как есть, на ТОТ ЖЕ адрес (живость уже
 *      подтверждена). Тишина здесь — первое и единственное событие, которое
 *      МОГЛО БЫ завести остаточную блокировку.
 *   2. ПРОВЕРКА ОСТАТОЧНОЙ БЛОКИРОВКИ — контроль на ТОТ ЖЕ адрес. Если
 *      коробка сработала на шаге 1, эта тройка теперь глохнет НА ЛЮБОЕ
 *      содержимое — и это надо увидеть ДО того, как её примут за "контроль
 *      тоже заблокирован".
 *   3. ВОПРОС ПРО УСТРОЙСТВО — ТОЛЬКО если шаг 2 показал остаточную
 *      блокировку (иначе адрес и так уже дважды подтверждён живым тем же
 *      контролем, шаг 3 избыточен и только тратил бы бюджет на пустое место)
 *      — контроль на СВЕЖЕМ адресе. Правка ревью 2026-09-06 круг 2: адрес
 *      РОТИРУЕТСЯ ТОЛЬКО ПОСЛЕ ОБНАРУЖЕНИЯ блокировки, не безусловно — см.
 *      обоснование в шапке d2k_quicprobe.h (безусловная ротация на цели с
 *      одним адресом не давала вердикта никогда, хотя доказательство уже
 *      было готово на одном маршруте).
 *   4. ВОПРОС ПРО ИСПОЛНИМОЕ ПЛЕЧО — если содержимое действительно решает,
 *      один дешёвый предварительный зонд (мусор перед Initial, простейшее
 *      из плеч донора) на ещё одном свежем адресе — задаче 6 будет с чего
 *      начинать подбор, а не с нуля.
 *
 * ПРАКТИЧЕСКИЙ ИСТОЧНИК СВЕЖИХ ТРОЕК. Адрес источника на роутере один, менять
 * его нечем. У цели, наоборот, обычно много адресов (CDN, балансировка) — это
 * и есть единственный практический способ получить новую тройку без ожидания
 * трёх минут на цель. d2k_quic_resolve_hook отдаёт этот пул; когда он
 * исчерпан РАНЬШЕ дерева, дальнейшие вопросы попадают в r.reason КАК
 * НЕЗАДАННЫЕ — см. шапку d2k_quicprobe.h про то, чего стоила обратная
 * ошибка этому проекту однажды.
 *
 * ОРАКУЛ: "ПРОШЛО" ТОЛЬКО ПРИ ПОДТВЕРЖДЁННОЙ ПОДЛИННОСТИ ОТВЕТА. Замер донора
 * 04.09.2026: пакет, похожий на ответ (задержка как у живого сервера, два
 * повтора из двух), НЕ расшифровался нашими ключами — и не был засчитан
 * успехом, хотя наивный оракул "recv() > 0" засчитал бы.
 *
 * ЧЕГО ЭТА ПРОВЕРКА НЕ ДАЁТ — И ЭТО НЕ ТО, ЧТО УТВЕРЖДАЛА ПРЕЖНЯЯ РЕДАКЦИЯ
 * (правка ревью 2026-09-06, круг 2). Ключи Initial выводятся из DCID,
 * лежащего в НАШЕЙ ЖЕ отправленной датаграмме ОТКРЫТЫМ ТЕКСТОМ (d2k_quic.h:
 * "Расшифровать клиентский Initial может кто угодно на пути — просто взяв
 * DCID из того же пакета и повторив HKDF") — значит ЛЮБОЙ на пути выводит те
 * же ключи и подделывает АУТЕНТИЧНЫЙ серверный Initial ничуть не хуже
 * настоящего сервера. Проверка тега НЕ защищает от инъекции на пути — против
 * неё защиты здесь нет вовсе, и не может быть, раз ключи публичны по
 * конструкции протокола. Она отсекает ДРУГОЕ: слепую инъекцию (тот, кто не
 * видел наш пакет и не знает DCID, не подделает тег), офф-путевую инъекцию
 * (та же причина) и посторонний UDP-сервис, ответивший на порт случайно или
 * по недоразумению (тег не сойдётся ни при каком DCID, которого у него нет).
 * Ставка от смешения этих двух вещей высокая: она разобрана ниже, у
 * qp_verify_server_response, вместе с тем, как проект её снижает (порог
 * успеха — не любой аутентичный Initial, а кадр CRYPTO внутри).
 *
 * ТРИГГЕР И КОНТРОЛЬ — ПАРАМЕТРЫ, А НЕ СОБИРАЮТСЯ ЗДЕСЬ. Причина НЕ в нехватке
 * криптографии (собрать структурно валидный самодельный Initial можно было бы
 * и без единого байта новой криптографии сверх d2k_crypto.h — ключи выводятся
 * из DCID, который выбираем мы сами, а рукопожатие не нужно вовсе; см.
 * подробный разбор в d2k_quicprobe.h). Причина в другом: коробка сличает
 * форму приветствия РЕАЛЬНОГО браузера, а не любой протокольно валидный набор
 * байт — самодельное приветствие мерило бы не ту коробку (тот же класс
 * ошибки, что уже стоил проекту каталога 06.09.2026 на TCP, см. d2k_meas.h).
 * Источника настоящего снимка для QUIC в проекте сегодня нет, поэтому
 * d2k_quic_classify берёт trigger/control параметрами: у кого снимка нет,
 * тот передаёт {NULL, 0} и получает честный вердикт, а не догадку.
 * Единственное шифрование в этом файле — расшифровка ОТВЕТА сервера
 * (qp_verify_server_response ниже); собственное AEAD-шифрование здесь не
 * нужно нигде, а d2k_ghash_for_test (см. d2k_crypto.h: "не для общего
 * пользования") этот файл не зовёт ни разу.
 *
 * ПОВТОРЫ ПАРАЛЛЕЛЬНЫ, А НЕ ПОСЛЕДОВАТЕЛЬНЫ (правка ревью 2026-09-06, круг
 * 2). Если слать три попытки одну за другой по одной тройке, попытка 1,
 * сработав по коробке, отравляет тройку остаточной блокировкой ДО того, как
 * попытки 2 и 3 успели уйти — тогда "три независимых повтора" превращаются в
 * один замер плюс два его эха, и единогласие перестаёт что-либо доказывать.
 * Донор (probe.go, Parallel=6) гонит их в полёте одновременно. quic_ask ниже
 * делает то же: открывает N сокетов, отправляет ВСЕ куски на ВСЕ сокеты,
 * только потом ждёт ответы через poll(). Потоков не заводит — poll на
 * нескольких дескрипторах занимает один.
 *
 * ОТКРЫТЫЙ ВОПРОС, ТРЕБУЮЩИЙ ЗАМЕРА (записан явно вместо того, чтобы
 * промолчать, — правка ревью 2026-09-06 круг 2). Параллельные датаграммы
 * побайтно идентичны: тот же DCID, тот же номер пакета (0), тот же
 * одноразовый вектор GCM. Побайтный повтор снимка — закон проекта (d2k_meas.h),
 * и §4 спецификации разрешает править случайное поле ТОЛЬКО после замера,
 * показывающего необходимость — такого замера нет, значит поле не трогаем.
 * Но остаётся НЕ ИЗМЕРЕННЫМ: отбивает ли реальный сервер (или коробка
 * посередине) три дословно одинаковые датаграммы как дубликаты одного и того
 * же пакета, засчитывая только первую и молча роняя две другие. Если да —
 * единогласие 3/3 на самом деле проверяет "дошла ли ХОТЯ БЫ одна копия", а не
 * "решает ли коробка одинаково три раза". Средств отличить один исход от
 * другого сегодня нет; решение — измерить на живой линии, не гадать.
 *
 * СВОЙ ОТПРАВИТЕЛЬ, А НЕ d2k_meas. Оракул TCP (d2k_meas.h/meas.c) открывает
 * потоковый сокет и шлёт РАЗРЕЗАННОЕ приветствие; у QUIC нет ни соединения,
 * ни разрезов в том же смысле — есть атомарные датаграммы. Общее с TCP —
 * только d2k_mark_hook (используется как есть, см. d2k_meas.h) и форма
 * счёта (d2k_tally: pass/fail/marked/err) — она достаточно общая, чтобы не
 * заводить копию только ради другого имени типа.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "d2k_quic.h"       /* d2k_quic_is_initial — канонический разбор заголовка Task 2 */
#include "d2k_quicprobe.h"

/* ---------------------------------------------------------------------
 * Умолчание и тестовый шов. См. шапку d2k_quicprobe.h про то, почему
 * они именно такие (и почему шов ниже — не точка расширения).
 * --------------------------------------------------------------------- */

/* Настоящий прямой DNS-запрос, IPv4 (см. шапку заголовка про то, почему это
 * не "DNS-подлог"). Возвращает 0 при любом сбое резолва — вызывающий не
 * считает это отказом всего вопросника, только пустым пулом. */
static size_t resolve_real(const char *sni, char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    if (!sni || cap == 0) {
        return 0;
    }
    struct addrinfo hints, *res, *it;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; /* d2k сегодня весь IPv4, см. d2k_quicprobe.h */
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(sni, NULL, &hints, &res) != 0) {
        return 0;
    }
    size_t n = 0;
    for (it = res; it != NULL && n < cap; it = it->ai_next) {
        struct sockaddr_in *a = (struct sockaddr_in *)(void *)it->ai_addr;
        if (!inet_ntop(AF_INET, &a->sin_addr, out[n], D2K_QUIC_ADDR_LEN)) {
            continue;
        }
        n++;
    }
    freeaddrinfo(res);
    return n;
}
d2k_quic_resolve_fn d2k_quic_resolve_hook = resolve_real;

/* Донор: firstTimeout, probe.go:397-402 (не deriveTimeout: та функция —
 * probe.go:404-418, соседняя, "3×RTT с полом и потолком", и адрес у неё
 * другой — правка ревью 2026-09-06 круг 3, находка E: числа совпадали, ссылка
 * была на чужую строку) — 3 с. До базовой живости RTT ещё не измерен,
 * выводить потолок не из чего. Число унаследовано, не выдумано (см.
 * d2k_quicprobe.h). */
uint32_t d2k_quic_wait_ms = 3000;
uint32_t d2k_quic_budget_s = 120;

/* Пауза 60 мс (§7: "пауза 60 мс между кусками"). У TCP-дерева "кусок" —
 * сегмент разрезанного потока; у QUIC разрезать нечего (датаграмма атомарна,
 * см. шапку файла), поэтому здесь два ДРУГИХ смысла того же числа: (1) между
 * необязательным мусором-приманкой и самим QUIC-куском ВНУТРИ одной попытки
 * (шаг 4) и (2) между вопросом, который мог завести остаточную блокировку, и
 * следующим вопросом на ТУ ЖЕ тройку (шаг 2). Фиксированная величина, а не
 * глобальная переменная, как d2k_quic_wait_ms/d2k_quic_budget_s выше: те две
 * тесту НУЖНО ужимать, а 60 мс сами по себе настолько малы, что даже десятки
 * опытов в одном прогоне `make check` не делают тесты заметно медленнее. */
#define D2K_QUIC_GAP_US 60000u

/* D2K_QUIC_REPEATS (сколько повторов у ОБЫЧНОГО вопроса дерева) — публичная
 * величина, объявлена в d2k_quicprobe.h: тест сравнивает с тем же числом
 * (находка ревью 2026-09-06 круг 2 — голый литерал "3" в восьми местах не
 * "знает", что это то же самое число, что и параметр repeats). */

/* Сколько ДОПОЛНИТЕЛЬНЫХ повторов задать прямому зонду перед CLEAR — тот же
 * приём и то же число, что D2K_CLEAR_CONFIRM_REPEATS в verdict.c (TCP-дерево),
 * по той же причине: ложный clear закрывает поиск словами "обходить нечего",
 * и это самая дорогая из возможных ошибок. */
#define D2K_QUIC_CLEAR_CONFIRM_REPEATS 2

/* Пул адресов назначения. 8 — трём вопросам дерева (устройство/плечо после
 * прямого зонда используют по одному свежему каждый, база и прямой зонд —
 * первый) с большим запасом; цена лишних слотов на стеке нулевая, как и у
 * аналогичных констант в quic.c (D2K_QUIC_MAX_CRYPTO_CHUNKS). Потолок и на
 * ПАРАЛЛЕЛЬНЫЕ попытки одного вопроса — общий, см. quic_ask. */
#define D2K_QUIC_MAX_ADDRS 8

/* ---------------------------------------------------------------------
 * Разбор заголовка Initial — минимальное подмножество parse_initial_header
 * из quic.c (задача 2), нужное ЭТОМУ файлу. Копия неизбежна: та функция
 * статическая (внутренняя для quic.c), а нужна она здесь для ЕДИНСТВЕННОГО
 * во всём проекте случая — проверки СЕРВЕРНОГО направления ответа (задача 2
 * разбирает только клиентские Initial, см. d2k_quic.h). Заводить это
 * публичным в quic.c ради одного вызывающего было бы преждевременным
 * обобщением интерфейса, рассчитанного на горячий путь (принято ревью
 * 2026-09-06 круг 1 как отложенная находка того же класса, что и в задаче 2,
 * — не чиним здесь). НЕ дублирует предел D2K_QUIC_MAX_DGRAM (здесь не
 * горячий путь) и верхнюю границу длины CID (некорректная длина всё равно
 * споткнётся о проверки границ буфера ниже) — но КАЖДУЮ проверку границы
 * перед КАЖДЫМ чтением сохраняет: вход — датаграмма с провода, которую мог
 * собрать кто угодно, а не только настоящий сервер.
 * --------------------------------------------------------------------- */

typedef struct {
    uint32_t version;
    size_t   dcid_off, dcid_len;
    size_t   pn_offset;
    size_t   length_claimed;
} qp_hdr;

static int qp_varint(const uint8_t *p, size_t avail, uint64_t *val, size_t *width) {
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

static int qp_parse_hdr(const uint8_t *p, size_t n, qp_hdr *h) {
    /* Согласие с каноническим разбором Task 2 в вопросе "это вообще Initial"
       — так у "да/нет" не остаётся шанса разойтись между двумя копиями
       заголовочной логики в дереве; расходиться может только НАБОР ПОЛЕЙ,
       который этому разбору нужен дальше и которого quic.c наружу не
       отдаёт (см. комментарий выше). */
    if (!d2k_quic_is_initial(p, n)) {
        return -1;
    }
    if (n < 5) {
        return -1;
    }

    uint32_t version = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 8 | (uint32_t)p[4];

    size_t off = 5;
    if (off + 1 > n) {
        return -1;
    }
    size_t dcid_len = p[off];
    off += 1;
    if (off + dcid_len > n) {
        return -1;
    }
    size_t dcid_off = off;
    off += dcid_len;

    if (off + 1 > n) {
        return -1;
    }
    size_t scid_len = p[off];
    off += 1;
    if (off + scid_len > n) {
        return -1;
    }
    off += scid_len;

    uint64_t token_len;
    size_t w;
    if (qp_varint(p + off, n - off, &token_len, &w) != 0) {
        return -1;
    }
    off += w;
    if (token_len > (uint64_t)(n - off)) {
        return -1;
    }
    off += (size_t)token_len;

    uint64_t length_claimed;
    if (qp_varint(p + off, n - off, &length_claimed, &w) != 0) {
        return -1;
    }
    off += w;

    size_t pn_offset = off;
    if (length_claimed > (uint64_t)(n - pn_offset)) {
        return -1;
    }
    if (pn_offset + 4 + 16 > n) {
        return -1; /* сэмпл для снятия защиты заголовка, RFC 9001 §5.4.2 */
    }

    h->version = version;
    h->dcid_off = dcid_off;
    h->dcid_len = dcid_len;
    h->pn_offset = pn_offset;
    h->length_claimed = (size_t)length_claimed;
    return 0;
}

/* Координаты DCID в НАШЕЙ ЖЕ отправленной датаграмме (триггер или контроль)
   — только они нужны, чтобы вывести ожидаемые серверные ключи; остальные
   поля своего же снимка этому файлу не нужны, разбирать его целиком было
   бы измерением того, что мы и так знаем. */
static int qp_dcid_of(const uint8_t *p, size_t n, uint32_t *version, size_t *off, size_t *len) {
    qp_hdr h;
    if (qp_parse_hdr(p, n, &h) != 0) {
        return -1;
    }
    *version = h.version;
    *off = h.dcid_off;
    *len = h.dcid_len;
    return 0;
}

/* ---------------------------------------------------------------------
 * Соль версии — те же 20 байт, что и в crypto.c/quic.c (RFC 9001 §5.2 и
 * RFC 9369 §3.3.1). Копия по той же причине, что и координаты DCID выше:
 * crypto.c отдаёт только примитивы, quic.c — только клиентское направление.
 * --------------------------------------------------------------------- */

#define QP_VERSION_V1 0x00000001u
#define QP_VERSION_V2 0x6b3343cfu

static const uint8_t qp_salt_v1[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};
static const uint8_t qp_salt_v2[20] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

/* ---------------------------------------------------------------------
 * Внутри РАСШИФРОВАННОГО серверного Initial: хотя бы один кадр CRYPTO?
 * (правка ревью 2026-09-06 круг 2, находка 5). §8 спецификации требует
 * прикладной обмен, а не любые вернувшиеся байты; полного прикладного обмена
 * на уровне Initial нам не видно (ключи Handshake/1-RTT недоступны), но
 * РАЗЛИЧИТЬ "рукопожатие продвинулось" (кадр CRYPTO — часть ServerHello) от
 * "сервер вежливо отказал" (только CONNECTION_CLOSE) можно и обязательно:
 * серверный Initial мы РАСШИФРОВЫВАЕМ, значит кадры внутри видны. Это
 * доказательство СЛАБЕЕ, чем у TCP (там видны типы записей вплоть до
 * ApplicationData) — выше подняться нечем: дальше Initial у нас нет ключей
 * ни при каких обстоятельствах, ни здесь, ни в проде.
 *
 * Разбор — тот же набор разрешённых в Initial типов, что и
 * collect_crypto_frames в quic.c (RFC 9000 §17.2.2), и по той же причине
 * (задача 2 разбирает клиентский Initial, эта функция — серверный; те же
 * основания для копии, что и у qp_parse_hdr выше). Короче: не реассемблирует
 * поток CRYPTO, останавливается на первом же кадре этого типа — достаточно
 * самого факта, координаты внутри ClientHello/ServerHello не нужны. */
static int qp_progressed(const uint8_t *plain, size_t plen) {
    size_t i = 0;
    while (i < plen) {
        uint8_t t = plain[i];
        if (t == 0x00) { /* PADDING */
            while (i < plen && plain[i] == 0x00) {
                i++;
            }
            continue;
        }
        if (t == 0x01) { /* PING */
            i++;
            continue;
        }
        if (t == 0x02 || t == 0x03) { /* ACK / ACK_ECN */
            size_t j = i + 1;
            size_t w;
            uint64_t largest, delay, range_count, first_range;
            if (qp_varint(plain + j, plen - j, &largest, &w) != 0) {
                break;
            }
            j += w;
            if (qp_varint(plain + j, plen - j, &delay, &w) != 0) {
                break;
            }
            j += w;
            if (qp_varint(plain + j, plen - j, &range_count, &w) != 0) {
                break;
            }
            j += w;
            if (qp_varint(plain + j, plen - j, &first_range, &w) != 0) {
                break;
            }
            j += w;
            int ranges_ok = 1;
            for (uint64_t r = 0; r < range_count; r++) {
                uint64_t gap, rlen;
                if (qp_varint(plain + j, plen - j, &gap, &w) != 0) {
                    ranges_ok = 0;
                    break;
                }
                j += w;
                if (qp_varint(plain + j, plen - j, &rlen, &w) != 0) {
                    ranges_ok = 0;
                    break;
                }
                j += w;
            }
            if (!ranges_ok) {
                break;
            }
            if (t == 0x03) {
                uint64_t e0, e1, ecn;
                if (qp_varint(plain + j, plen - j, &e0, &w) != 0) {
                    break;
                }
                j += w;
                if (qp_varint(plain + j, plen - j, &e1, &w) != 0) {
                    break;
                }
                j += w;
                if (qp_varint(plain + j, plen - j, &ecn, &w) != 0) {
                    break;
                }
                j += w;
            }
            i = j;
            continue;
        }
        if (t == 0x06) { /* CRYPTO — рукопожатие продвинулось, дальше читать незачем */
            return 1;
        }
        if (t == 0x1c) { /* CONNECTION_CLOSE транспортного уровня — вежливый отказ, не прогресс */
            size_t j = i + 1;
            size_t w;
            uint64_t err_code, frame_type, reason_len;
            if (qp_varint(plain + j, plen - j, &err_code, &w) != 0) {
                break;
            }
            j += w;
            if (qp_varint(plain + j, plen - j, &frame_type, &w) != 0) {
                break;
            }
            j += w;
            if (qp_varint(plain + j, plen - j, &reason_len, &w) != 0) {
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
        break; /* неразрешённый в Initial тип — дальше не гадаем, как и quic.c */
    }
    return 0;
}

/* Проверяет, что p[0..n) — АУТЕНТИЧНЫЙ Initial-пакет СЕРВЕРНОГО направления
 * для DCID (dcid, dcid_len), которым мы сами адресовали отправленную
 * датаграмму, И что рукопожатие внутри него ПРОДВИНУЛОСЬ (кадр CRYPTO, не
 * только CONNECTION_CLOSE — см. большой комментарий у qp_progressed и в
 * шапке файла про то, что проверка тега защищает НЕ от инъекции на пути:
 * ключи выводятся из DCID, лежащего в нашем же пакете открытым текстом,
 * значит подделать аутентичный Initial с CONNECTION_CLOSE внутри может
 * кто угодно на пути, и без проверки кадра "три раза получили вежливый
 * отказ, подделанный посторонним" превратилось бы в D2K_V_CLEAR — самую
 * дорогую ошибку дерева по его же доктрине). Возвращает 0, если оба условия
 * выполнены, -1 во всех остальных случаях. */
static int qp_verify_server_response(const uint8_t *p, size_t n,
                                      const uint8_t *dcid, size_t dcid_len,
                                      uint32_t version) {
    qp_hdr h;
    if (qp_parse_hdr(p, n, &h) != 0) {
        return -1;
    }
    if (h.version != version) {
        return -1; /* отвечает не той версией, которой спросили, — не наш ответ */
    }

    uint8_t initial_secret[32], server_secret[32], key[16], iv[12], hp[16];
    const uint8_t *salt = (version == QP_VERSION_V2) ? qp_salt_v2 : qp_salt_v1;
    d2k_hkdf_extract(salt, sizeof qp_salt_v1, dcid, dcid_len, initial_secret);

    const char *lk = (version == QP_VERSION_V2) ? "quicv2 key" : "quic key";
    const char *li = (version == QP_VERSION_V2) ? "quicv2 iv" : "quic iv";
    const char *lh = (version == QP_VERSION_V2) ? "quicv2 hp" : "quic hp";
    if (d2k_hkdf_expand_label(initial_secret, "server in", server_secret, sizeof server_secret) != 0) {
        return -1;
    }
    if (d2k_hkdf_expand_label(server_secret, lk, key, sizeof key) != 0) {
        return -1;
    }
    if (d2k_hkdf_expand_label(server_secret, li, iv, sizeof iv) != 0) {
        return -1;
    }
    if (d2k_hkdf_expand_label(server_secret, lh, hp, sizeof hp) != 0) {
        return -1;
    }

    size_t sample_off = h.pn_offset + 4;
    uint8_t mask[16];
    d2k_aes128_ecb(hp, p + sample_off, mask);

    uint8_t byte0 = (uint8_t)(p[0] ^ (mask[0] & 0x0f));
    size_t pn_len = (size_t)(byte0 & 0x03) + 1;
    uint8_t pn_bytes[4];
    for (size_t i = 0; i < pn_len; i++) {
        pn_bytes[i] = (uint8_t)(p[h.pn_offset + i] ^ mask[1 + i]);
    }

    if (h.length_claimed < pn_len) {
        return -1;
    }
    size_t ct_len = h.length_claimed - pn_len;
    if (ct_len < 16) {
        return -1;
    }

    size_t aad_len = h.pn_offset + pn_len;
    uint8_t aad[2048];
    if (aad_len > sizeof aad) {
        return -1; /* заведомо больше любой правдоподобной Initial-датаграммы — не наш случай */
    }
    memcpy(aad, p, aad_len);
    aad[0] = byte0;
    memcpy(aad + h.pn_offset, pn_bytes, pn_len);

    uint32_t pn = 0;
    for (size_t i = 0; i < pn_len; i++) {
        pn = (pn << 8) | pn_bytes[i];
    }
    uint8_t nonce[12];
    memcpy(nonce, iv, sizeof nonce);
    for (size_t i = 0; i < 4; i++) {
        nonce[sizeof nonce - 1 - i] ^= (uint8_t)(pn >> (8 * i));
    }

    if (ct_len > 2048) {
        return -1;
    }
    uint8_t plain[2048];
    const uint8_t *ct = p + h.pn_offset + pn_len;
    if (d2k_aes128_gcm_decrypt(key, nonce, aad, aad_len, ct, ct_len, plain) != 0) {
        return -1; /* тег не сошёлся: похоже на ответ, но не доказательство — см. шапку файла */
    }

    /* Резервные биты после снятия ОБЕИХ защит обязаны быть нулём (RFC 9000
       §17.2); проверять это можно только сейчас — byte0 аутентифицирован
       только после совпавшего тега (он часть AAD). Тот же порядок, что и в
       quic.c decrypt_initial, и по той же причине. */
    if ((byte0 & 0x0c) != 0) {
        return -1;
    }

    size_t plain_len = ct_len - 16;
    if (!qp_progressed(plain, plain_len)) {
        return -1; /* аутентичный, но без кадра CRYPTO — вежливый отказ, не прогресс */
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * Базовая живость: зонд согласования версии (RFC 9000 §6). Проверка ответа
 * СТРУКТУРНАЯ, а не криптографическая — у Version Negotiation нет AEAD
 * вовсе (ключи разворачивать не из чего: ответ по конструкции протокола НЕ
 * шифрован): длинный заголовок, поле версии — все нули (RFC 9000 §6:
 * "A Version Negotiation packet ... value of 0 for the Version field").
 * Слабее, чем аутентификация тегом, и это честно — большего у Version
 * Negotiation в принципе не бывает.
 *
 * ТРИ ПОВТОРА, КАК И У ЛЮБОГО ДРУГОГО ВОПРОСА (правка ревью 2026-09-06, круг
 * 3, находка C). Прежняя редакция гоняла один зонд под тем доводом, что
 * "единственный источник недостоверности — обычная потеря пакета, и её
 * достаточно один раз пережить проверкой" — довод опровергает сам себя: три
 * повтора во всём остальном дереве существуют РОВНО против потери пакета, и
 * этот вопрос от неё не защищён чем-то особым. Он не различает CLEAR/OPAQUE,
 * но различает UNREACHABLE и INCONCLUSIVE — а это разные решения о том,
 * возвращаться ли к цели вообще, и одна обычная потеря не должна их
 * разводить по стенке монетки. Донор гоняет его через ту же обёртку с
 * повторами (probe.go:303). Цена здесь нулевая: параллельная отправка уже
 * есть в quic_ask_ex ниже — qp_ask_vn просто зовёт её с другим проверщиком
 * ответа и без учёта RTT (он не нужен диагностике).
 * --------------------------------------------------------------------- */

/* GREASE-версия, зарезервированная RFC 9000 §15 специально для того, чтобы
 * заставить получателя ответить Version Negotiation (маска 0x?a?a?a?a). */
#define QP_GREASE_VERSION 0x1a2a3a4au

static size_t qp_build_vn_trigger(uint8_t *out, size_t cap) {
    /* Общие для ЛЮБОЙ версии поля длинного заголовка — Version, DCID,
       SCID (RFC 9000 §17.2); всё, что идёт ПОСЛЕ SCID, версия-специфично, и
       получателю с нераспознанной версией это не нужно вовсе — ему достаточно
       увидеть длинный заголовок и незнакомую версию, чтобы ответить VN.
       Паддинг до 1200 байт — не подстраховка "на всякий случай", а прямое
       требование первоисточника: RFC 9000 §6.1 отвечает VN "if the packet is
       large enough to initiate a new connection", а §14.1 задаёт этот порог
       ровно в 1200 байт (правка ревью 2026-09-06 круг 3, находка E —
       предыдущая редакция называла это неизмеренным гаданием, хотя цитата
       была доступна). */
    size_t need = 1 + 4 + 1 + 8 + 1;
    if (need > cap) {
        return 0;
    }
    size_t off = 0;
    out[off++] = 0xC0;
    out[off++] = (uint8_t)(QP_GREASE_VERSION >> 24);
    out[off++] = (uint8_t)(QP_GREASE_VERSION >> 16);
    out[off++] = (uint8_t)(QP_GREASE_VERSION >> 8);
    out[off++] = (uint8_t)(QP_GREASE_VERSION);
    out[off++] = 0x08; /* dcid_len */
    for (int i = 0; i < 8; i++) {
        out[off++] = (uint8_t)(0xD0 + i);
    }
    out[off++] = 0x00; /* scid_len */
    size_t total = off < 1200 && cap >= 1200 ? 1200 : off;
    if (total > cap) {
        total = off;
    }
    if (total > off) {
        memset(out + off, 0, total - off);
    }
    return total;
}

static int qp_looks_like_vn(const uint8_t *p, size_t n) {
    if (n < 5) {
        return 0;
    }
    if ((p[0] & 0x80) == 0) {
        return 0; /* не длинный заголовок */
    }
    return p[1] == 0 && p[2] == 0 && p[3] == 0 && p[4] == 0; /* версия нулевая — RFC 9000 §6 */
}

/* ---------------------------------------------------------------------
 * Оракул: серия ПАРАЛЛЕЛЬНЫХ попыток с единогласием (см. шапку файла,
 * находка 6 ревью).
 * --------------------------------------------------------------------- */

static void nap_us(uint32_t us) {
    struct timespec ts;
    ts.tv_sec = (time_t)(us / 1000000u);
    ts.tv_nsec = (long)(us % 1000000u) * 1000L;
    (void)nanosleep(&ts, NULL);
}

/* Открывает, метит, подключает и отправляет ОДНУ попытку (включая
   необязательный мусор-приманку перед основным куском); НЕ ждёт ответа —
   ожидание общее для всех попыток серии, см. quic_ask_ex. Возвращает fd
   готовый к чтению или -1, если попытка не состоялась (сбой
   сокета/адреса/отправки — тогда это "опыт не состоялся", d2k_tally.err, а
   не тишина). *marked — 1, если метка подтверждена или не запрошена
   (mark==0). Общая для quic_ask_ex (AEAD) и qp_ask_vn (VN) — байты есть
   байты, отправка не знает и не обязана знать, что внутри. */
static int qp_send_one(const char *addr, uint16_t port,
                        const uint8_t *prefix, size_t prefix_len,
                        d2k_hello msg, uint32_t mark, int *marked) {
    *marked = (mark == 0);
    if (!addr || !msg.bytes || msg.len == 0) {
        return -1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (mark != 0 && d2k_mark_hook(fd, mark) == 0) {
        *marked = 1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &a.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    /* "Подключенный" UDP-сокет — не ради семантики соединения (её у UDP
       нет), а чтобы ICMP-отказ (порт/хост недоступен) дошёл до нас через
       POLLERR/код ошибки, а не неотличимой тишиной. */
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    if (prefix && prefix_len > 0) {
        if (send(fd, prefix, prefix_len, 0) < 0) {
            close(fd);
            return -1;
        }
        nap_us(D2K_QUIC_GAP_US); /* §7: пауза между кусками ВНУТРИ этой попытки */
    }
    if (send(fd, msg.bytes, msg.len, 0) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Проверщик ОДНОГО пришедшего ответа — разный для обычных вопросов (AEAD,
   qp_verify_aead) и для согласования версии (структурный, qp_verify_vn), но
   параллельная отправка/ожидание вокруг него — ОДНА функция (quic_ask_ex
   ниже), не две копии одного и того же цикла poll(). msg — та же датаграмма,
   что ушла на провод: AEAD-проверщику нужен её DCID, структурному — не нужно
   ничего, кроме самого ответа. Возвращает 0 — ответ подтверждён, -1 — нет
   (похож, но не доказывает, либо вовсе не похож). */
typedef int (*qp_verify_fn)(const uint8_t *p, size_t n, d2k_hello msg);

static int qp_verify_aead(const uint8_t *p, size_t n, d2k_hello msg) {
    uint32_t version;
    size_t dcid_off, dcid_len;
    if (qp_dcid_of(msg.bytes, msg.len, &version, &dcid_off, &dcid_len) != 0) {
        return -1; /* свой же снимок не разобрать как Initial — подлинность проверить нечем */
    }
    return qp_verify_server_response(p, n, msg.bytes + dcid_off, dcid_len, version);
}

static int qp_verify_vn(const uint8_t *p, size_t n, d2k_hello msg) {
    (void)msg;
    return qp_looks_like_vn(p, n) ? 0 : -1;
}

/* Серия из repeats ПАРАЛЛЕЛЬНЫХ попыток: сначала ВСЕ уходят на провод (см.
   шапку файла), потом ждём ответы разом через poll(), пока не истечёт
   wait_ms с момента отправки или не ответят все. Каждый пришедший ответ
   проверяется независимо через verify (см. qp_verify_fn выше), тайм-аут без
   ответа — тишина (fail, не err); явная ошибка сокета при отправке — err. */
static d2k_tally quic_ask_ex(const char *addr, uint16_t port,
                              const uint8_t *prefix, size_t prefix_len,
                              d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                              int repeats, uint32_t *rtt_ms_out, qp_verify_fn verify) {
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    if (repeats <= 0) {
        repeats = D2K_QUIC_REPEATS;
    }
    if (repeats > D2K_QUIC_MAX_ADDRS) {
        /* Тихая подмена запрошенного числа повторов на "сколько влезло в
           буфер" — тот же класс ошибки, который d2k_meas.h отвергает для
           точек разреза (нарушение контракта отклоняется целиком, а не
           ужимается до похожего): опыт не проводится вовсе, вместо того
           чтобы молча провести МЕНЬШЕ, чем спросили (правка ревью 2026-09-06
           круг 3, находка E). Сегодня недостижимо — оба вызывающих просят
           D2K_QUIC_REPEATS=3 или D2K_QUIC_CLEAR_CONFIRM_REPEATS=2, оба
           меньше D2K_QUIC_MAX_ADDRS=8, — но контракт не должен держаться на
           том, что сегодняшние вызовы его не нарушают. */
        d2k_tally bad;
        memset(&bad, 0, sizeof bad);
        bad.err = repeats;
        bad.fail = repeats;
        bad.marked = (mark == 0);
        if (rtt_ms_out) {
            *rtt_ms_out = 0;
        }
        return bad;
    }
    if (wait_ms == 0) {
        wait_ms = D2K_QUIC_RTT_WAIT_FLOOR_MS;
    }
    if (rtt_ms_out) {
        *rtt_ms_out = 0;
    }

    int fds[D2K_QUIC_MAX_ADDRS];
    int marked[D2K_QUIC_MAX_ADDRS];
    int done[D2K_QUIC_MAX_ADDRS];
    int result[D2K_QUIC_MAX_ADDRS]; /* 1 pass, 0 тишина/не подтверждено, -1 транспорт */
    struct timespec sent_at[D2K_QUIC_MAX_ADDRS];
    int pending = 0;

    for (int i = 0; i < repeats; i++) {
        fds[i] = qp_send_one(addr, port, prefix, prefix_len, msg, mark, &marked[i]);
        if (!marked[i]) {
            t.marked = 0;
        }
        if (fds[i] < 0) {
            result[i] = -1;
            done[i] = 1;
        } else {
            result[i] = 0;
            done[i] = 0;
            clock_gettime(CLOCK_MONOTONIC, &sent_at[i]);
            pending++;
        }
    }

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += (time_t)(wait_ms / 1000u);
    deadline.tv_nsec += (long)(wait_ms % 1000u) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }

    struct pollfd pfds[D2K_QUIC_MAX_ADDRS];
    while (pending > 0) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long remain_ms =
            (long)(deadline.tv_sec - now.tv_sec) * 1000L + (deadline.tv_nsec - now.tv_nsec) / 1000000L;
        if (remain_ms <= 0) {
            break;
        }
        int nfd = 0;
        int idx_of[D2K_QUIC_MAX_ADDRS];
        for (int i = 0; i < repeats; i++) {
            if (!done[i]) {
                pfds[nfd].fd = fds[i];
                pfds[nfd].events = POLLIN;
                pfds[nfd].revents = 0;
                idx_of[nfd] = i;
                nfd++;
            }
        }
        int pr = poll(pfds, (nfds_t)nfd, (int)remain_ms);
        if (pr <= 0) {
            break; /* тайм-аут или сбой poll — оставшиеся остаются тишиной */
        }
        for (int k = 0; k < nfd; k++) {
            if (pfds[k].revents == 0) {
                continue;
            }
            int i = idx_of[k];
            done[i] = 1;
            pending--;
            uint8_t buf[2048];
            ssize_t n = recv(fds[i], buf, sizeof buf, 0);
            if (n > 0) {
                if (verify(buf, (size_t)n, msg) == 0) {
                    result[i] = 1;
                    if (rtt_ms_out) {
                        struct timespec arrived;
                        clock_gettime(CLOCK_MONOTONIC, &arrived);
                        uint32_t rtt_ms = (uint32_t)((arrived.tv_sec - sent_at[i].tv_sec) * 1000L +
                                                      (arrived.tv_nsec - sent_at[i].tv_nsec) / 1000000L);
                        if (*rtt_ms_out == 0 || rtt_ms < *rtt_ms_out) {
                            *rtt_ms_out = rtt_ms;
                        }
                    }
                } else {
                    result[i] = 0; /* пришло, но не подтверждено — не доказательство */
                }
            } else if (n == 0) {
                result[i] = 0;
            } else {
                result[i] = -1; /* POLLERR/явная ошибка сокета — транспорт */
            }
        }
    }

    for (int i = 0; i < repeats; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
        }
        if (result[i] == 1) {
            t.pass++;
        } else if (result[i] < 0) {
            t.err++;
            t.fail++;
        } else {
            t.fail++;
        }
    }
    return t;
}

static d2k_tally quic_ask(const char *addr, uint16_t port,
                           const uint8_t *prefix, size_t prefix_len,
                           d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                           int repeats, uint32_t *rtt_ms_out) {
    return quic_ask_ex(addr, port, prefix, prefix_len, msg, wait_ms, mark, repeats, rtt_ms_out,
                        qp_verify_aead);
}

/* Живость через согласование версии — та же дисциплина повторов, метки и
   параллельной отправки, что и у обычных вопросов (см. большой комментарий
   у qp_build_vn_trigger выше, находка C ревью), только проверщик другой
   (структурный, не AEAD) и RTT не нужен (rtt_ms_out=NULL). Не через
   d2k_quic_ask_hook: разветвлять ПОДМЕНЯЕМЫЙ в тестах оракул на два
   независимых протокола ответа ради одного вызывающего было бы
   преждевременным обобщением шва, который и так существует только из-за
   ограничения тестовой платформы (см. d2k_quicprobe.h у d2k_quic_ask_hook);
   тестируется отдельно, настоящими сокетами на 127.0.0.1 — адресная ротация
   этому зонду не нужна, он до неё не доходит. */
static d2k_tally qp_ask_vn(const char *addr, uint16_t port, uint32_t wait_ms, uint32_t mark) {
    uint8_t trig_buf[1200];
    size_t tlen = qp_build_vn_trigger(trig_buf, sizeof trig_buf);
    d2k_hello msg;
    msg.bytes = (tlen > 0) ? trig_buf : NULL;
    msg.len = tlen;
    return quic_ask_ex(addr, port, NULL, 0, msg, wait_ms, mark, D2K_QUIC_REPEATS, NULL, qp_verify_vn);
}

/* Реальный оракул — умолчание d2k_quic_ask_hook (см. d2k_quicprobe.h про то,
   зачем этот хук вообще существует). Дерево ниже зовёт ИСКЛЮЧИТЕЛЬНО хук, не
   quic_ask напрямую — иначе подмена в тесте не достала бы до дерева.
   qp_ask_vn хук не проходит вовсе (см. её же комментарий) — вызывается из
   d2k_quic_classify напрямую. */
d2k_quic_ask_fn d2k_quic_ask_hook = quic_ask;

/* ---------------------------------------------------------------------
 * Дерево вопросов.
 * --------------------------------------------------------------------- */

static void reason_set(d2k_vres *r, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(r->reason, sizeof r->reason, fmt, ap);
    va_end(ap);
}

static void reason_append(d2k_vres *r, const char *fmt, ...) {
    size_t used = strlen(r->reason);
    if (used >= sizeof r->reason - 1) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(r->reason + used, sizeof r->reason - used, fmt, ap);
    va_end(ap);
}

/* now < deadline (в секундах монотонных часов, целочисленно — §"плавающей
   арифметики нет"). */
static int budget_left(const struct timespec *start) {
    /* Бюджет 0 — это НОЛЬ секунд, а не "проверить и посмотреть": он обязан
       значить "исчерпан всегда", а не зависеть от разрешения часов — иначе
       на очень быстром (мок) пути now успевает совпасть со start вплоть до
       наносекунды, и результат становится гонкой (найдено повторным
       прогоном `sh scripts/check.sh` при разработке задачи 5, круг 1).
       Явный случай снимает гонку совсем. */
    if (d2k_quic_budget_s == 0) {
        return 0;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    time_t deadline = start->tv_sec + (time_t)d2k_quic_budget_s;
    if (now.tv_sec > deadline) {
        return 0;
    }
    if (now.tv_sec == deadline && now.tv_nsec > start->tv_nsec) {
        return 0;
    }
    return 1;
}

/* Адрес для СЛЕДУЮЩЕГО вопроса — ОДНО правило на ВСЕ вопросы дерева после
   базовой живости, без исключений (правка ревью 2026-09-06, круг 3, находка
   B; донор, questions.go:44: "if (!p.fresh) { return p.pinned }"). Пока
   остаточная блокировка не обнаружена — закреплённый pool[0], всегда, для
   ЛЮБОГО вопроса, не только для шага 3. Прежняя редакция применяла это
   правило только к шагу 3, а шаг 4 (плечо) ротировал безусловно — и от этого
   ломалось В ОБЕ СТОРОНЫ: на цели с одним адресом, где остаточной блокировки
   нет, плечо честно "не задано (адреса)" вместо того, чтобы спросить на уже
   ДВАЖДЫ подтверждённом живым pool[0] (спросить было чем — незаданность
   должна значить обратное); а когда запасной адрес всё же был, плечо
   мерилось на ДРУГОМ маршруте, чем тот, где измерен провал триггера, — та
   самая примесь маршрута, ради устранения которой ротацию вообще сделали
   условной. residual_detected передаёт РЕАЛЬНОЕ состояние из
   d2k_quic_classify — эта функция ничего не решает сама, только применяет
   уже принятое решение. Возвращает NULL, если ротация НУЖНА, но пул
   исчерпан — это и есть "адресов не осталось", а не "адрес есть, но решили
   не спрашивать". */
static const char *qp_pinned_or_next(const char pool[][D2K_QUIC_ADDR_LEN], size_t n_pool,
                                      size_t *next_addr, int residual_detected) {
    if (!residual_detected) {
        return pool[0];
    }
    if (*next_addr >= n_pool) {
        return NULL;
    }
    return pool[(*next_addr)++];
}

/* Шаг 4: вопрос про исполнимое плечо (мусор перед Initial, простейшее из
   плеч донора) — общий хвост для ОБЕИХ веток, которыми дерево приходит к
   D2K_V_OPAQUE (без ротации и с ней, см. шапку файла). Вынесен в отдельную
   функцию, а не продублирован дважды, — тело d2k_quic_classify и так
   держит единственный выход, дублирование пятнадцати строк не помогло бы
   этому, только расползлось бы при следующей правке одной копии без другой.
   Дописывает в r->reason (уже содержащий причину OPAQUE) через
   reason_append, ничего не возвращает — вызывающему нечего с этим делать,
   кроме как продолжить к своему единственному return.
   residual_detected — см. qp_pinned_or_next. */
static void qp_arm_step(d2k_vres *r, const char pool[][D2K_QUIC_ADDR_LEN], size_t n_pool,
                         size_t *next_addr, int residual_detected, uint16_t port, d2k_hello trigger,
                         uint32_t wait_ms, uint32_t mark, int *all_marked, const struct timespec *start) {
    if (!budget_left(start)) {
        reason_append(r, "; плечо не задано (бюджет)");
        return;
    }
    const char *fresh = qp_pinned_or_next(pool, n_pool, next_addr, residual_detected);
    if (!fresh) {
        reason_append(r, "; плечо не задано (адреса)");
        return;
    }
    static const uint8_t garbage16[16]; /* ровно 16 нулей — тот же мусор, что и у донора (questions.go:97) */
    d2k_tally armed =
        d2k_quic_ask_hook(fresh, port, garbage16, sizeof garbage16, trigger, wait_ms, mark, D2K_QUIC_REPEATS, NULL);
    r->probes += D2K_QUIC_REPEATS;
    if (!armed.marked) {
        *all_marked = 0;
    }
    if (armed.err > 0 || (armed.pass > 0 && armed.pass < D2K_QUIC_REPEATS)) {
        reason_append(r, "; плечо: расхождение");
    } else if (armed.pass == D2K_QUIC_REPEATS) {
        reason_append(r, "; плечо(мусор)=%d/%d — старт для задачи 6", armed.pass, D2K_QUIC_REPEATS);
    } else {
        reason_append(r, "; плечо(мусор)=0/%d", D2K_QUIC_REPEATS);
    }
}

d2k_vres d2k_quic_classify(const char *ip, uint16_t port, const char *sni,
                            d2k_hello trigger, d2k_hello control, uint32_t mark) {
    d2k_vres r;
    memset(&r, 0, sizeof r);

    /* ОДИН guard на весь класс "структурно непригодный вход" — было разведено
       на FLAKY и INCONCLUSIVE (находка 9 ревью, круг 2): эталон относит
       "мерить было структурно нечем" целиком к FLAKY (d2k_verdict.h) — здесь
       то же самое: нет адреса/имени, нет снимка триггера, или ip не
       разбирается как настоящий IPv4-адрес. Проверка ЧЕРЕЗ inet_pton, не
       только по длине строки (правка ревью 2026-09-06, круг 3, находка E):
       "999.999.999.999" короче буфера пула, но inet_pton его отвергнет —
       раньше такой ip не ловился здесь и утекал в quic_ask_ex, где
       connect()/inet_pton падали на КАЖДОЙ из D2K_QUIC_REPEATS попыток и
       наружу уходило СЕТЕВОЕ утверждение ("нет UDP-ответа", "транспорт"),
       выведенное из НЕПРИГОДНОГО ввода, а не из сети. */
    int ip_ok = 0;
    if (ip && strlen(ip) < D2K_QUIC_ADDR_LEN) {
        struct in_addr ip_probe;
        ip_ok = (inet_pton(AF_INET, ip, &ip_probe) == 1);
    }
    if (!ip_ok || !sni || !trigger.bytes || trigger.len == 0) {
        r.verdict = D2K_V_FLAKY;
        reason_set(&r, "вход структурно непригоден: адрес не разбирается как IPv4, имя или снимок "
                       "триггера отсутствуют — измерения не было");
        return r; /* r.marked=0 по построению — ни один опыт не задавался; единственный ранний
                     выход, как и у эталона (verdict.c) — это отказ ДО измерения, не его исход */
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Пул адресов: ip — первый и гарантированный (это ровно тот адрес, для
       которого нас позвали), остальное — из резолвера, с отбросом дублей
       (иначе "свежий" адрес мог бы совпасть с уже использованным, и ротация
       была бы фиктивной). */
    char pool[D2K_QUIC_MAX_ADDRS][D2K_QUIC_ADDR_LEN];
    memset(pool, 0, sizeof pool); /* хвосты слотов детерминированы (нули), а не читаются как есть */
    (void)strncpy(pool[0], ip, D2K_QUIC_ADDR_LEN - 1); /* длина уже проверена guard'ом выше */
    size_t n_pool = 1;

    char extra[D2K_QUIC_MAX_ADDRS][D2K_QUIC_ADDR_LEN];
    memset(extra, 0, sizeof extra);
    size_t n_extra = d2k_quic_resolve_hook(sni, extra, D2K_QUIC_MAX_ADDRS);
    if (n_extra > D2K_QUIC_MAX_ADDRS) {
        /* Хук обязан был вернуть не больше cap (D2K_QUIC_MAX_ADDRS), но
           буферу всё равно, кто ошибся: без этого зажима цикл ниже читал бы
           extra[i] за границей массива — порча памяти, а не мелочь (находка
           9 ревью, круг 2). */
        n_extra = D2K_QUIC_MAX_ADDRS;
    }
    for (size_t i = 0; i < n_extra && n_pool < D2K_QUIC_MAX_ADDRS; i++) {
        int dup = 0;
        for (size_t j = 0; j < n_pool; j++) {
            if (strcmp(pool[j], extra[i]) == 0) {
                dup = 1;
                break;
            }
        }
        if (!dup) {
            memcpy(pool[n_pool], extra[i], D2K_QUIC_ADDR_LEN);
            n_pool++;
        }
    }
    size_t next_addr = 1; /* pool[0] занят базовой живостью/прямым зондом/шагом 2 — см. шапку файла */

    int all_marked = 1;

    /* ===== ШАГ 0: базовая живость пути (см. шапку файла и d2k_quicprobe.h) ===== */
    if (!control.bytes || control.len == 0) {
        r.verdict = D2K_V_INCONCLUSIVE;
        reason_set(&r, "нет контрольного имени — базовая живость не проверена, вопрос не задан (§2.3)");
    } else if (!budget_left(&start)) {
        r.verdict = D2K_V_INCONCLUSIVE;
        reason_set(&r, "бюджет исчерпан до базовой проверки живости — вопрос НЕ ЗАДАН");
    } else {
        uint32_t rtt_ms = 0;
        d2k_tally base_ctl =
            d2k_quic_ask_hook(pool[0], port, NULL, 0, control, d2k_quic_wait_ms, mark, D2K_QUIC_REPEATS, &rtt_ms);
        r.probes += D2K_QUIC_REPEATS;
        if (!base_ctl.marked) {
            all_marked = 0;
        }

        if (base_ctl.err == D2K_QUIC_REPEATS) {
            /* "Транспорт" здесь — любой сбой ДО ответа (socket()/inet_pton()/
               connect()/send() тоже считаются через qp_send_one, не только
               ICMP): называть это "портом недоступен" значило бы утверждать
               конкретный сетевой факт, которого err сам по себе не
               различает — прежняя редакция называла (правка ревью
               2026-09-06 круг 3, находка E, "верни осторожность"). */
            r.verdict = D2K_V_UNREACHABLE;
            reason_set(&r, "нет UDP-ответа с %s: %d/%d — транспорт, не решение коробки", pool[0],
                       base_ctl.err, D2K_QUIC_REPEATS);
        } else if (base_ctl.err > 0) {
            r.verdict = D2K_V_FLAKY;
            reason_set(&r, "базовая живость: %d/%d не состоялись — транспорт", base_ctl.err,
                       D2K_QUIC_REPEATS);
        } else if (base_ctl.pass > 0 && base_ctl.pass < D2K_QUIC_REPEATS) {
            r.verdict = D2K_V_FLAKY;
            reason_set(&r, "базовая живость не воспроизводится: %d/%d", base_ctl.pass, D2K_QUIC_REPEATS);
        } else if (base_ctl.pass == 0) {
            /* Тишина без единой ошибки транспорта — путь мог быть и жив, и
               мёртв; зонд согласования версии решает, не неся содержимого
               вовсе (см. большой комментарий у qp_build_vn_trigger). Три
               параллельных попытки, метка, учёт в all_marked — та же
               дисциплина, что и у любого другого вопроса (правка ревью
               2026-09-06 круг 3, находки A и C: раньше был один зонд без
               метки, и его исход не входил в r.marked). */
            d2k_tally vn = qp_ask_vn(pool[0], port, d2k_quic_wait_ms, mark);
            r.probes += D2K_QUIC_REPEATS;
            if (!vn.marked) {
                all_marked = 0;
            }
            if (vn.err > 0) {
                r.verdict = D2K_V_FLAKY;
                reason_set(&r, "согласование версии: %d/%d не состоялись — транспорт", vn.err,
                           D2K_QUIC_REPEATS);
            } else if (vn.pass > 0 && vn.pass < D2K_QUIC_REPEATS) {
                r.verdict = D2K_V_FLAKY;
                reason_set(&r, "согласование версии не воспроизводится: %d/%d — одна обычная потеря "
                               "не должна решать между UNREACHABLE и INCONCLUSIVE",
                           vn.pass, D2K_QUIC_REPEATS);
            } else if (vn.pass == D2K_QUIC_REPEATS) {
                r.verdict = D2K_V_INCONCLUSIVE;
                /* Честно: наше имя (trigger) на этой ветке НЕ СПРАШИВАЛОСЬ ни
                   разу — молчит именно КОНТРОЛЬНОЕ имя, а согласование версии
                   лишь показывает, что путь жив. Прежняя редакция писала
                   "Initial молчит на обоих именах", хотя триггер не
                   отправлялся вовсе, — подмена "незадан" на "задан и
                   отказан", ровно то, ради недопущения чего писана вся
                   задача (правка ревью 2026-09-06 круг 3, находка D; текст
                   был дословно унаследован от донора, probe.go:315-317, где
                   неверен по той же причине — донор источник устройства, не
                   источник истины, см. решение по кадру 0x1d в задаче 2). */
                reason_set(&r, "контрольное имя молчит (0/%d), путь при этом жив (согласование "
                               "версии %d/%d) — наше имя не спрашивалось, мерить нечем",
                           D2K_QUIC_REPEATS, vn.pass, D2K_QUIC_REPEATS);
            } else {
                r.verdict = D2K_V_UNREACHABLE;
                reason_set(&r, "молчит всё, включая согласование версии (0/%d) — транспорт, не "
                               "решение коробки",
                           D2K_QUIC_REPEATS);
            }
        } else {
            /* base_ctl.pass == D2K_QUIC_REPEATS: живость подтверждена, RTT
               измерен — потолок ожидания для всего остального дерева
               выводится из него (см. d2k_quicprobe.h). */
            uint32_t dyn_wait = rtt_ms * 3;
            if (dyn_wait < D2K_QUIC_RTT_WAIT_FLOOR_MS) {
                dyn_wait = D2K_QUIC_RTT_WAIT_FLOOR_MS;
            }
            if (dyn_wait > D2K_QUIC_RTT_WAIT_CEIL_MS) {
                dyn_wait = D2K_QUIC_RTT_WAIT_CEIL_MS;
            }

            /* ===== ШАГ 1: прямой зонд (тот же адрес — живость уже подтверждена) ===== */
            d2k_tally base =
                d2k_quic_ask_hook(pool[0], port, NULL, 0, trigger, dyn_wait, mark, D2K_QUIC_REPEATS, NULL);
            r.probes += D2K_QUIC_REPEATS;
            if (!base.marked) {
                all_marked = 0;
            }

            if (base.err > 0) {
                r.verdict = D2K_V_FLAKY;
                reason_set(&r, "прямой зонд: %d/%d не состоялись — транспорт, не коробка", base.err,
                           D2K_QUIC_REPEATS);
            } else if (base.pass == D2K_QUIC_REPEATS) {
                d2k_tally confirm = d2k_quic_ask_hook(pool[0], port, NULL, 0, trigger, dyn_wait, mark,
                                                       D2K_QUIC_CLEAR_CONFIRM_REPEATS, NULL);
                r.probes += D2K_QUIC_CLEAR_CONFIRM_REPEATS;
                if (!confirm.marked) {
                    all_marked = 0;
                }
                int total_pass = base.pass + confirm.pass;
                int total_repeats = D2K_QUIC_REPEATS + D2K_QUIC_CLEAR_CONFIRM_REPEATS;
                if (confirm.err > 0) {
                    r.verdict = D2K_V_FLAKY;
                    reason_set(&r, "подтверждение: %d/%d не состоялись — транспорт", confirm.err,
                               D2K_QUIC_CLEAR_CONFIRM_REPEATS);
                } else if (total_pass != total_repeats) {
                    r.verdict = D2K_V_FLAKY;
                    reason_set(&r, "не подтвердился: итого %d/%d — flaky дешевле ложного clear",
                               total_pass, total_repeats);
                } else if (all_marked) {
                    r.verdict = D2K_V_CLEAR;
                    reason_set(&r, "триггер проходит как есть, метка подтверждена (%d/%d) — "
                                   "обходить нечего",
                               total_pass, total_repeats);
                } else {
                    r.verdict = D2K_V_INCONCLUSIVE;
                    reason_set(&r, "прошёл (%d/%d), но БЕЗ подтверждённой метки — clear не "
                                   "принимается",
                               total_pass, total_repeats);
                }
            } else if (base.pass > 0) {
                r.verdict = D2K_V_FLAKY;
                reason_set(&r, "прямой зонд не воспроизводится: %d/%d", base.pass, D2K_QUIC_REPEATS);
            } else {
                /* base.pass == 0, base.err == 0 — тишина по содержимому. */

                /* ===== ШАГ 2: проверка остаточной блокировки (control, ТОТ ЖЕ адрес) ===== */
                if (!budget_left(&start)) {
                    r.verdict = D2K_V_INCONCLUSIVE;
                    reason_set(&r, "молчит (0/%d); бюджет исчерпан до шага 2 — вопрос НЕ ЗАДАН",
                               D2K_QUIC_REPEATS);
                } else {
                    nap_us(D2K_QUIC_GAP_US); /* §7: пауза между вопросами по той же тройке */
                    d2k_tally same = d2k_quic_ask_hook(pool[0], port, NULL, 0, control, dyn_wait, mark,
                                                        D2K_QUIC_REPEATS, NULL);
                    r.probes += D2K_QUIC_REPEATS;
                    if (!same.marked) {
                        all_marked = 0;
                    }

                    if (same.err > 0) {
                        r.verdict = D2K_V_FLAKY;
                        reason_set(&r, "шаг 2 (та же тройка): %d/%d не состоялись — транспорт",
                                   same.err, D2K_QUIC_REPEATS);
                    } else if (same.pass > 0 && same.pass < D2K_QUIC_REPEATS) {
                        r.verdict = D2K_V_FLAKY;
                        reason_set(&r, "шаг 2 не воспроизводится: %d/%d", same.pass, D2K_QUIC_REPEATS);
                    } else if (same.pass == D2K_QUIC_REPEATS) {
                        /* Остаточная блокировка НЕ обнаружена: адрес дважды
                           (база + шаг 2) подтверждён живым тем же контролем
                           — ротация не нужна, шаг 3 избыточен (правка ревью
                           2026-09-06 круг 2: "адрес закреплён, пока
                           остаточная блокировка не обнаружена"). */
                        r.verdict = D2K_V_OPAQUE;
                        reason_set(&r, "0/%d; контр.: до=%d/%d, после=%d/%d на том же адресе — "
                                       "блокировки по тройке нет; решает содержимое",
                                   D2K_QUIC_REPEATS, D2K_QUIC_REPEATS, D2K_QUIC_REPEATS, same.pass,
                                   D2K_QUIC_REPEATS);
                        /* residual_detected=0: правило одно на все вопросы
                           (см. qp_pinned_or_next) — плечо тоже спрашивает
                           закреплённый pool[0], не ротирует (правка ревью
                           2026-09-06 круг 3, находка B). */
                        qp_arm_step(&r, pool, n_pool, &next_addr, 0, port, trigger, dyn_wait, mark,
                                    &all_marked, &start);
                    } else {
                        /* same.pass == 0: остаточная блокировка ОБНАРУЖЕНА —
                           теперь и только теперь адрес ротируется (см.
                           qp_pinned_or_next: residual_detected=1 с этой точки
                           и до конца этой ветки, включая плечо ниже). Бюджет
                           проверяется ДО обращения к пулу — иначе исчерпанный
                           бюджет всё равно "съедал" бы адрес, который потом
                           некому было бы использовать. */
                        if (!budget_left(&start)) {
                            r.verdict = D2K_V_INCONCLUSIVE;
                            reason_set(&r, "молчит (0/%d); шаг 2 тоже молчит; бюджет исчерпан до "
                                           "шага 3 — вопрос НЕ ЗАДАН",
                                       D2K_QUIC_REPEATS);
                        } else {
                            const char *fresh1 = qp_pinned_or_next(pool, n_pool, &next_addr, 1);
                            if (!fresh1) {
                                r.verdict = D2K_V_INCONCLUSIVE;
                                reason_set(&r, "молчит (0/%d); шаг 2 тоже молчит; адрес для шага 3 НЕ "
                                               "ЗАДАН — пул из %zu исчерпан",
                                           D2K_QUIC_REPEATS, n_pool);
                            } else {
                                d2k_tally clean = d2k_quic_ask_hook(fresh1, port, NULL, 0, control,
                                                                     dyn_wait, mark, D2K_QUIC_REPEATS, NULL);
                                r.probes += D2K_QUIC_REPEATS;
                                if (!clean.marked) {
                                    all_marked = 0;
                                }

                                if (clean.err > 0) {
                                    r.verdict = D2K_V_FLAKY;
                                    reason_set(&r, "шаг 3 на %s: %d/%d не состоялись — транспорт",
                                               fresh1, clean.err, D2K_QUIC_REPEATS);
                                } else if (clean.pass > 0 && clean.pass < D2K_QUIC_REPEATS) {
                                    r.verdict = D2K_V_FLAKY;
                                    reason_set(&r, "шаг 3 на %s не воспроизводится: %d/%d", fresh1,
                                               clean.pass, D2K_QUIC_REPEATS);
                                } else if (clean.pass == 0) {
                                    r.verdict = D2K_V_INCONCLUSIVE;
                                    reason_set(&r, "контроль молчит и на чистом %s — нельзя отличить "
                                                   "содержимое от недоступности сервера (§2.3/§2.4)",
                                               fresh1);
                                } else {
                                    /* clean.pass == D2K_QUIC_REPEATS */
                                    r.verdict = D2K_V_OPAQUE;
                                    reason_set(&r, "0/%d; контр.: чисто=%d/%d, здесь=0/%d — вероятна "
                                                   "ост.блокировка; решает содержимое",
                                               D2K_QUIC_REPEATS, D2K_QUIC_REPEATS, D2K_QUIC_REPEATS,
                                               D2K_QUIC_REPEATS);
                                    /* residual_detected=1: этот вопрос УЖЕ
                                       ротировал один раз (fresh1 выше) —
                                       плечо продолжает с того же next_addr,
                                       забирая СЛЕДУЮЩИЙ свежий (см.
                                       qp_pinned_or_next). */
                                    qp_arm_step(&r, pool, n_pool, &next_addr, 1, port, trigger, dyn_wait,
                                                mark, &all_marked, &start);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    r.marked = (mark != 0) && all_marked;
    return r;
}
