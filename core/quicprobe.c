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
 * Порог успеха — критерий донора (parse.go:72-74): любой расшифрованный
 * Initial, Retry или Version Negotiation; прежний собственный порог «нужен
 * кадр CRYPTO» снят планом 2026-10-02-review-fixes, задача 10 — см.
 * комментарий у qp_donor_unauth_reply.
 *
 * ТРИГГЕР И КОНТРОЛЬ — ПАРАМЕТРЫ, А НЕ СОБИРАЮТСЯ ЗДЕСЬ. Причина НЕ в нехватке
 * криптографии (собрать структурно валидный самодельный Initial можно было бы
 * и без единого байта новой криптографии сверх d2k_crypto.h — ключи выводятся
 * из DCID, который выбираем мы сами, а рукопожатие не нужно вовсе; см.
 * подробный разбор в d2k_quicprobe.h). Причина в другом: коробка сличает
 * форму приветствия РЕАЛЬНОГО браузера, а не любой протокольно валидный набор
 * байт — самодельное приветствие мерило бы не ту коробку (тот же класс
 * ошибки, что уже стоил проекту каталога 06.09.2026 на TCP, см. d2k_meas.h).
 * d2k_quic_classify берёт trigger/control параметрами. При холодном старте
 * планировщик использует d2k_quic_probe_initial — измерительный вход
 * оригинала, проверяемый независимым Go-кодом; он не выдаётся за снимок.
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
/* Файл включают и как текст в составные тесты — после системных заголовков,
   где glibc (с 2026) уже задал _POSIX_C_SOURCE сам: голый #define там —
   переопределение под -Werror (CI 22.10.2026). Отдельной единицей трансляции
   значение задаётся как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* IP_TTL (задача 6, приманка с укороченным TTL — см. qp_send_one) не POSIX:
 * на macOS <netinet/in.h> прячет его за этим переключателем при строгом
 * _POSIX_C_SOURCE (проверено эмпирически на машине разработки), на Linux/glibc
 * определение IP_TTL от этого переключателя не зависит — макрос там просто
 * не распознаётся и ни на что не влияет. */
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "d2k_quic.h"       /* d2k_quic_is_initial — канонический разбор заголовка Task 2 */
#include "d2k_net4.h"
#include "d2k_quichello.h"
#include "d2k_quicsnap.h"
#include "d2k_quicwire.h"
#include "d2k_udpruntime.h"
#include "d2k_quicprobe.h"
#include "d2k_verify.h" /* D2K_VERIFY_HEADER_LIMIT */
#include "d2k_ip6frag_send.h"
#include "d2k_quic_arms.h"
#include "d2k_ipfrag.h"
#include "d2k_tls13core.h"
#include "d2k_quicconn.h"
#include "d2k_h3.h"
#include "d2k_meas.h"
#include "d2k_resource.h"
#include "d2k_volume.h"  /* D2K_VOLUME_PACKET_SLACK — один допуск с TCP-веткой */
#include "d2k_catalog.h"  /* D2K_VOLUME_SLACK — тот же допуск по байтам */

/* ---------------------------------------------------------------------
 * Умолчание и тестовый шов. См. шапку d2k_quicprobe.h про то, почему
 * они именно такие (и почему шов ниже — не точка расширения).
 * --------------------------------------------------------------------- */

/* Настоящий прямой DNS-запрос, IPv4 (см. шапку заголовка про то, почему это
 * не "DNS-подлог"). Возвращает 0 при любом сбое резолва — вызывающий не
 * считает это отказом всего вопросника, только пустым пулом. */
static int qp_addr_parse(const char *text, uint8_t bytes[16]) {
    memset(bytes, 0, 16);
    if (!text || strchr(text, '%')) return 0;
    if (inet_pton(AF_INET, text, bytes) == 1) return AF_INET;
    if (inet_pton(AF_INET6, text, bytes) == 1) return AF_INET6;
    return 0;
}

static size_t resolve_family(const char *sni, int family,
                              char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    if (!sni || cap == 0) {
        return 0;
    }
    struct addrinfo hints, *res, *it;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(sni, NULL, &hints, &res) != 0) {
        return 0;
    }
    size_t n = 0;
    for (it = res; it != NULL && n < cap; it = it->ai_next) {
        const void *addr;
        if (it->ai_family == AF_INET6) {
            addr = &((struct sockaddr_in6 *)(void *)it->ai_addr)->sin6_addr;
        } else if (it->ai_family == AF_INET) {
            addr = &((struct sockaddr_in *)(void *)it->ai_addr)->sin_addr;
        } else { continue; }
        if (!inet_ntop(it->ai_family, addr, out[n], D2K_QUIC_ADDR_LEN)) {
            continue;
        }
        n++;
    }
    freeaddrinfo(res);
    return n;
}
static size_t resolve_real(const char *sni, char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    return resolve_family(sni, AF_INET, out, cap);
}
d2k_quic_resolve_fn d2k_quic_resolve_hook = resolve_real;

/* Донор: firstTimeout, probe.go:397-402 (не deriveTimeout: та функция —
 * probe.go:404-418, соседняя, "3×RTT с полом и потолком", и адрес у неё
 * другой — правка ревью 2026-09-06 круг 3, находка E: числа совпадали, ссылка
 * была на чужую строку) — 3 с. До базовой живости RTT ещё не измерен,
 * выводить потолок не из чего. Число унаследовано, не выдумано (см.
 * d2k_quicprobe.h). */
uint32_t d2k_quic_wait_ms = D2K_QUIC_WAIT_MS_DEFAULT;

/* БЮДЖЕТ ВЫВОДИТСЯ ИЗ ЛЕСТНИЦЫ RUN, а не назначается круглым числом — см.
 * d2k_quic_budget_ms рядом с таблицей вопросов. Прежнее выражение
 * (1+2+20+3)×3000 мс = 78 с описывало давно не существующую развёртку TTL
 * 1..20 и не покрывало настоящий худший путь уже при RTT 1 с (84 с).
 * Явное число здесь — только тестовое переопределение. */
uint32_t d2k_quic_budget_s = D2K_QUIC_BUDGET_DERIVED;

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

/* D2K_QUIC_MAX_ADDRS теперь в d2k_quicprobe.h (перенесена оттуда сюда) —
 * задаче 6 (props.c) нужно знать тот же предел, чтобы завести пул того же
 * размера для d2k_quic_build_pool; значение и обоснование там же. */

/* Сборка пула адресов цели. Вынесена сюда (не статическая), а не
 * продублирована в props.c, по той же причине, что qp_parse_hdr не дублирует
 * quic.c целиком, а берёт из него только согласие в вопросе "это Initial":
 * расходиться может НАБОР полей, которые нужны разным вызывающим, но не
 * сама логика "первый гарантированный + дедуп резолвера". */
size_t d2k_quic_build_pool(const char *ip, const char *sni, char pool[][D2K_QUIC_ADDR_LEN], size_t cap) {
    uint8_t target[16];
    int family = qp_addr_parse(ip, target);
    if (cap == 0 || !pool || !family || strlen(ip) >= D2K_QUIC_ADDR_LEN) {
        return 0;
    }
    memset(pool, 0, cap * D2K_QUIC_ADDR_LEN); /* хвосты слотов детерминированы (нули), а не читаются как есть */
    (void)strncpy(pool[0], ip, D2K_QUIC_ADDR_LEN - 1); /* длина уже проверена вызывающим */
    size_t n_pool = 1;

    char extra[D2K_QUIC_MAX_ADDRS][D2K_QUIC_ADDR_LEN];
    memset(extra, 0, sizeof extra);
    size_t n_extra = d2k_quic_resolve_hook == resolve_real
        ? resolve_family(sni, family, extra, D2K_QUIC_MAX_ADDRS)
        : d2k_quic_resolve_hook(sni, extra, D2K_QUIC_MAX_ADDRS);
    if (n_extra > D2K_QUIC_MAX_ADDRS) {
        /* Хук обязан был вернуть не больше cap (D2K_QUIC_MAX_ADDRS), но
           буферу всё равно, кто ошибся: без этого зажима цикл ниже читал бы
           extra[i] за границей массива — порча памяти, а не мелочь (находка
           9 ревью, круг 2, quic_classify). */
        n_extra = D2K_QUIC_MAX_ADDRS;
    }
    for (size_t i = 0; i < n_extra && n_pool < cap; i++) {
        uint8_t candidate[16];
        if (!memchr(extra[i], 0, D2K_QUIC_ADDR_LEN) ||
            qp_addr_parse(extra[i], candidate) != family) continue;
        int dup = 0;
        for (size_t j = 0; j < n_pool; j++) {
            uint8_t existing[16];
            (void)qp_addr_parse(pool[j], existing);
            if (memcmp(existing, candidate, 16) == 0) {
                dup = 1;
                break;
            }
        }
        if (!dup) {
            memcpy(pool[n_pool], extra[i], D2K_QUIC_ADDR_LEN);
            n_pool++;
        }
    }
    return n_pool;
}

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

/* ---------------------------------------------------------------------
 * ЧТО СЧИТАЕТСЯ ОТВЕТОМ — КРИТЕРИЙ ДОНОРА, БЕЗ ДОБАВОК.
 *
 * Донор: z2k-detect/internal/quicprobe/parse.go, Parse (:77-179) и
 * Response.Answered (:72-74). Ответ — одно из трёх:
 *   - Version Negotiation: длинный заголовок, версия 0 (:110-116); CID с
 *     нашими не сверяются, список версий не проверяется;
 *   - Retry: тип Retry ДЛЯ НАШЕЙ версии и версия совпадает (:118-122); тег
 *     целостности Retry (RFC 9001 §5.8) донор НЕ проверяет;
 *   - Initial нашей версии, РАСШИФРОВАННЫЙ серверными ключами из нашего DCID
 *     (:176-178) — любой: ACK-only, CONNECTION_CLOSE, CRYPTO. Кадры на
 *     ответ не влияют.
 * Всё прочее (короткий заголовок, чужой тип/версия, не раскрывшийся
 * нашими ключами пакет) — не ответ, ожидание продолжается.
 *
 * Здесь раньше стояло отступление «нужен кадр CRYPTO» (правка ревью
 * 2026-09-06 круг 2, находка 5) с доводом про инъекцию на пути. Оно
 * отменено планом .superpowers/sdd/2026-10-02-review-fixes, задача 10:
 * AGENTS.md — «не перепридумывать критерии оригинала». Граница
 * доказательства та же, что у донора: Retry/VN не аутентифицированы, а
 * Initial-ключи публичны для всякого, кто видел наш пакет.
 * --------------------------------------------------------------------- */

/* Retry/VN по donor Parse. 1 — ответ, 0 — не Retry/VN нашей версии, но
   может оказаться Initial (решает дальнейший разбор), -1 — не ответ. */
static int qp_donor_unauth_reply(const uint8_t *p, size_t n, uint32_t version) {
    if (n < 7) {
        return -1; /* parse.go:78-80 */
    }
    if ((p[0] & 0x80) == 0) {
        return -1; /* короткий заголовок — KindForeign, parse.go:81-85 */
    }
    uint32_t ver = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 8 | (uint32_t)p[4];
    size_t off = 5;
    size_t dcid_len = p[off++];
    if (off + dcid_len > n) {
        return -1; /* parse.go:91-93 */
    }
    off += dcid_len;
    if (off >= n) {
        return -1; /* parse.go:96-98 */
    }
    size_t scid_len = p[off++];
    if (off + scid_len > n) {
        return -1; /* parse.go:101-103 */
    }
    if (ver == 0) {
        return 1; /* Version Negotiation, parse.go:110-116 */
    }
    uint8_t typ = (uint8_t)((p[0] & 0x30) >> 4);
    uint8_t retry_type = version == QP_VERSION_V2 ? 0x00 : 0x03;   /* initial.go:64-67 */
    uint8_t initial_type = version == QP_VERSION_V2 ? 0x01 : 0x00;
    if (typ == retry_type && ver == version) {
        return 1; /* Retry, parse.go:118-122 */
    }
    if (typ != initial_type || ver != version) {
        return -1; /* KindForeign, parse.go:123-127 */
    }
    return 0;
}

/* Ответ сервера на датаграмму с DCID (dcid, dcid_len) версии version — по
 * критерию донора (см. комментарий выше). Возвращает 0 — ответ, -1 — нет. */
static int qp_verify_server_response(const uint8_t *p, size_t n,
                                      const uint8_t *dcid, size_t dcid_len,
                                      uint32_t version) {
    int unauth = qp_donor_unauth_reply(p, n, version);
    if (unauth != 0) {
        return unauth > 0 ? 0 : -1;
    }
    qp_hdr h;
    if (qp_parse_hdr(p, n, &h) != 0) {
        return -1;
    }
    if (h.version != version) {
        return -1; /* отвечает не той версией, которой спросили, — не наш ответ */
    }

    /* КЛЮЧИ И СНЯТИЕ ЗАЩИТЫ — ОБЩИЕ (core/quicwire.c). Здесь была копия
       того же кода, что в quic.c: две соли, четыре метки, маска защиты
       заголовка, сборка AAD и вектора. Копии успели разойтись — одна
       восстанавливала номер пакета дополнением нулями, другая тоже, но
       обе молча, — и третья копия (зонд подтверждения) спецификацией
       запрещена (§2.5). Осталось то, что знает ЭТОТ путь: сторона
       серверная, а наибольшего принятого у одиночного зонда нет. */
    uint8_t server_secret[32];
    if (d2k_qw_initial_secret(version, dcid, dcid_len, D2K_QW_SERVER, server_secret) != 0) {
        return -1;
    }
    d2k_qw_keys k;
    if (d2k_qw_keys_from_secret(version, server_secret, &k) != 0) {
        return -1;
    }
    d2k_qw_hdr qh;
    memset(&qh, 0, sizeof qh);
    qh.long_hdr = 1;
    qh.version = h.version;
    qh.type = D2K_QW_LT_INITIAL;
    qh.dcid_off = h.dcid_off;
    qh.dcid_len = h.dcid_len;
    qh.pn_offset = h.pn_offset;
    qh.length_claimed = h.length_claimed;
    qh.packet_len = h.pn_offset + h.length_claimed;

    uint8_t plain[2048];
    size_t plain_len = 0;
    if (h.length_claimed > sizeof plain) {
        return -1; /* заведомо больше любой правдоподобной Initial-датаграммы */
    }
    if (d2k_qw_open(&k, &qh, p, 0, plain, &plain_len, NULL) != 0) {
        return -1; /* не раскрывается нашими ключами — KindForeign, parse.go:171-175 */
    }
    return 0; /* KindInitial: любой расшифрованный Initial, parse.go:176-178 */
}

/* ---------------------------------------------------------------------
 * Базовая живость: зонд согласования версии (RFC 9000 §6). Ответ —
 * донорский Answered() (см. qp_verify_vn); сам VN узнаётся СТРУКТУРНО, а не
 * криптографически — у Version Negotiation нет AEAD
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
       была доступна).

       Раскладка — донорская versionNegotiationProbe (hello.go:99-111): 0xc0,
       версия, DCID 8, SCID 8, пустой токен (varint 0), нули до 1200. DCID и
       SCID — СВОИ СЛУЧАЙНЫЕ НА КАЖДЫЙ ВЫЗОВ, как randomID(8), randomID(8) в
       замыкании попытки (probe.go:303-306): три повтора — три разных
       соединения, а не одна и та же датаграмма трижды (прежние постоянные
       D0..D7 и пустой SCID). */
    const size_t total = 1200;
    if (!out || cap < total) {
        return 0;
    }
    size_t off = 0;
    out[off++] = 0xC0;
    out[off++] = (uint8_t)(QP_GREASE_VERSION >> 24);
    out[off++] = (uint8_t)(QP_GREASE_VERSION >> 16);
    out[off++] = (uint8_t)(QP_GREASE_VERSION >> 8);
    out[off++] = (uint8_t)(QP_GREASE_VERSION);
    out[off++] = 0x08; /* dcid_len */
    if (d2k_t13_random(out + off, 8) != 0) {
        return 0;
    }
    off += 8;
    out[off++] = 0x08; /* scid_len */
    if (d2k_t13_random(out + off, 8) != 0) {
        return 0;
    }
    off += 8;
    out[off++] = 0x00; /* пустой токен, varint 0 */
    memset(out + off, 0, total - off);
    return total;
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

/* Сокет одной попытки: открыт, помечен, при необходимости привязан к
   спрошенному исходному порту и подключён к цели — и с МЕСТНЫМ ПОРТОМ,
   которого не было у наших зондов за окно остаточной блокировки
   (d2k_udp_port_claim, задача 39). Отвергнутые сокеты не закрываются, пока
   идёт поиск (чтобы ядро не выдало тот же порт тут же снова), и все
   закрываются при возврате. Спрошенный исходный
   порт (вопрос 7 оригинала) не подменяется: его выбирает вопрос, а не ядро,
   — он только записывается. *marked — как у qp_send_one. */
static int qp_open_fresh(int family, const struct sockaddr *a, socklen_t alen,
                         int src_port, uint32_t mark, int *marked) {
    int held[D2K_UDP_FRESH_TRIES];
    int n_held = 0, fd = -1;
    for (;;) {
        *marked = (mark == 0);
        fd = socket(family, SOCK_DGRAM, 0);
        if (fd < 0) { break; }
#ifdef SO_NOSIGPIPE
        /* macOS can raise SIGPIPE on a rejected connected UDP send too.
           Preserve the send error as an unmeasured probe, not process death. */
        int no_sigpipe = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
                       &no_sigpipe, sizeof no_sigpipe) != 0) {
            close(fd); fd = -1; break;
        }
#endif
        if (mark != 0 && d2k_mark_hook(fd, mark) == 0) {
            *marked = 1;
        }
        /* ИСХОДНЫЙ ПОРТ — ТОЛЬКО когда его СПРОСИЛИ (вопрос 7 оригинала: коробка
           экономит на разборе и не смотрит на датаграммы, у которых исходный порт
           не больше порта назначения; у GFW подтверждено перебором пар портов).
           Во всех прочих вопросах bind'а нет намеренно: свой эфемерный порт на
           каждую попытку — это и есть то, чем шаг 2 доказывает независимость
           остаточной блокировки от исходного порта.

           Порт ниже 1024 требует прав, и отказ bind'а — это НЕ сетевой факт:
           попытка не отправляется вовсе (-1, «наша сторона»), и вопрос честно
           остаётся незаданным, а не «не помог». */
        if (src_port > 0 && src_port < 65536) {
            struct sockaddr_storage src;
            memset(&src, 0, sizeof src);
            socklen_t slen;
            if (family == AF_INET6) {
                struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&src;
                v6->sin6_family = AF_INET6; v6->sin6_port = htons((uint16_t)src_port);
                slen = sizeof *v6;
            } else {
                struct sockaddr_in *v4 = (struct sockaddr_in *)&src;
                v4->sin_family = AF_INET; v4->sin_port = htons((uint16_t)src_port);
                slen = sizeof *v4;
            }
            if (bind(fd, (struct sockaddr *)&src, slen) != 0) {
                close(fd); fd = -1; break;
            }
        }
        /* "Подключенный" UDP-сокет — не ради семантики соединения (её у UDP
           нет), а чтобы ICMP-отказ (порт/хост недоступен) дошёл до нас через
           POLLERR/код ошибки, а не неотличимой тишиной. Местный порт ядро
           выдаёт здесь же. */
        if (connect(fd, a, alen) != 0) {
            close(fd); fd = -1; break;
        }
        int recent = d2k_udp_port_claim(fd);
        if (recent <= 0 || src_port > 0) { break; }
        if (n_held == D2K_UDP_FRESH_TRIES) { close(fd); fd = -1; break; }
        held[n_held++] = fd;
        fd = -1;
    }
    for (int i = 0; i < n_held; i++) { close(held[i]); }
    return fd;
}

/* Открывает, метит, подключает и отправляет ОДНУ попытку (включая
   необязательный мусор-приманку перед основным куском); НЕ ждёт ответа —
   ожидание общее для всех попыток серии, см. quic_ask_ex. Возвращает fd
   готовый к чтению или -1, если попытка не состоялась (сбой
   сокета/адреса/отправки — тогда это "опыт не состоялся", d2k_tally.err, а
   не тишина); -2 — send() вернул ECONNREFUSED: ICMP-отказ на уже ушедшую
   датаграмму (приманку), у донора это refused (probe.go:642-643). *marked — 1, если метка подтверждена или не запрошена
   (mark==0). Общая для quic_ask_ex (AEAD) и qp_ask_vn (VN) — байты есть
   байты, отправка не знает и не обязана знать, что внутри.
   prefix_ttl<=0 — TTL сокета не трогать (обычная приманка, умолчание
   системы); prefix_ttl>0 — задача 6 (d2k_quic_ask_ttl_hook): выставить
   IP_TTL ПЕРЕД отправкой приманки и вернуть исходное значение сокета
   ПЕРЕД отправкой msg — trigger обязан уйти обычным TTL, иначе он тоже
   рискует не дойти до настоящего сервера, а нам нужен его настоящий ответ.
   IP_TTL, а не сырой сокет: это управление TTL ИСХОДЯЩЕГО сокета уровня
   ядра, доступно на обычном SOCK_DGRAM без CAP_NET_RAW — сырой сокет в
   этом файле нужен только фрагментации (props.c), не приманке с TTL. */
static int qp_send_one(const char *addr, uint16_t port,
                        const uint8_t *prefix, size_t prefix_len, int prefix_ttl,
                        int prefix_copies, int src_port,
                        d2k_hello msg, uint32_t mark, int *marked, int split, unsigned longer) {
    *marked = (mark == 0);
    if (!addr || !msg.bytes || msg.len == 0) {
        return -1;
    }
    uint8_t dst[16];
    int family = qp_addr_parse(addr, dst);
    if (!family) return -1;
    struct sockaddr_storage a;
    memset(&a, 0, sizeof a);
    socklen_t alen;
    if (family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&a;
        v6->sin6_family = AF_INET6; v6->sin6_port = htons(port);
        memcpy(&v6->sin6_addr, dst, 16); alen = sizeof *v6;
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&a;
        v4->sin_family = AF_INET; v4->sin_port = htons(port);
        memcpy(&v4->sin_addr, dst, 4); alen = sizeof *v4;
    }
    int fd = qp_open_fresh(family, (struct sockaddr *)&a, alen, src_port, mark, marked);
    if (fd < 0) {
        return -1;
    }
#ifdef IP_RECVTTL
    /* СЫРОЙ TTL ОТВЕТА. Просим ядро принести его вместе с датаграммой; отказ
       не важен и не проверяется — поле тогда останется нулём, что и значит
       «не измерено». Ради факта, который и так придёт, отдельного зонда не
       заводим. */
    {
        int on = 1;
        if (family == AF_INET) (void)setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof on);
    }
#endif
    if (family == AF_INET6) {
        int on = 1;
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof on);
    }
    int rc=0;
    /* ПАЧКА — ПО ДАТАГРАММЕ НА ПОСЫЛКУ (задача 66). Приветствие клиента с
       постквантовым key_share занимает два Initial, и уехать одной посылкой
       они не могут: получилась бы датаграмма в 2,4 КБ, которой клиент не
       слал. Воздействие (приманка, разрез, длина) относится к ГОЛОВЕ полёта —
       так же, как его применяет датапат; хвост уходит как есть. */
    d2k_qsnap pack;
    int packed = d2k_qsnap_is(msg.bytes, msg.len) &&
                 d2k_qsnap_parse(msg.bytes, msg.len, &pack) == 0;
    if(packed){
        d2k_hello head = {pack.dg[0], pack.len[0], NULL, 0, 0, 0};
        if((prefix && prefix_len) || split || longer){
            char plan[16384];d2k_quic_arm_question q={0};
            q.blob=prefix;q.blob_len=prefix_len;q.ttl=prefix_ttl;q.copies=prefix_copies;q.split=split;
            q.udplen=longer;
            rc=d2k_quic_question_plan(&q,plan,sizeof plan);
            if(!rc)rc=d2k_udp_plan_send(fd,plan,head.bytes,head.len,mark);
        }else if(send(fd,head.bytes,head.len,0)!=(ssize_t)head.len)
            rc=errno==ECONNREFUSED?-2:-1;
        for(size_t i=1;!rc && i<pack.n;i++){
            if(send(fd,pack.dg[i],pack.len[i],0)!=(ssize_t)pack.len[i])
                rc=errno==ECONNREFUSED?-2:-1;
        }
    }else if((prefix && prefix_len) || split || longer){
        char plan[16384];d2k_quic_arm_question q={0};
        q.blob=prefix;q.blob_len=prefix_len;q.ttl=prefix_ttl;q.copies=prefix_copies;q.split=split;
        q.udplen=longer;
        rc=d2k_quic_question_plan(&q,plan,sizeof plan);
        if(!rc)rc=d2k_udp_plan_send(fd,plan,msg.bytes,msg.len,mark);
    }else if(send(fd,msg.bytes,msg.len,0)!=(ssize_t)msg.len)rc=errno==ECONNREFUSED?-2:-1;
    if(rc){close(fd);return rc;}
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

/* ЧТО УШЛО НА ПРОВОД, ЕСЛИ УШЛА ПАЧКА (задача 66). Ответ сервера адресован
   соединению, а соединение задают DCID и SCID — у всех датаграмм пачки они
   общие (перезапечатка ставит один свежий DCID на всю пачку). Разбирать
   сами байты пачки как Initial нельзя: у неё свой заголовок, и разбор не
   проходил — любой ответ сервера отвергался как чужой, и каждый замер
   пачкой читал «имя молчит» (стенд 15.10.2026). */
static d2k_hello qp_head_of(d2k_hello msg) {
    d2k_qsnap pk;
    if (msg.bytes && d2k_qsnap_is(msg.bytes, msg.len) &&
        d2k_qsnap_parse(msg.bytes, msg.len, &pk) == 0 && pk.n > 0) {
        return (d2k_hello){pk.dg[0], pk.len[0], NULL, 0, 0, 0};
    }
    return msg;
}

static int qp_verify_aead(const uint8_t *p, size_t n, d2k_hello msg) {
    msg = qp_head_of(msg);
    uint32_t version;
    size_t dcid_off, dcid_len;
    if (qp_dcid_of(msg.bytes, msg.len, &version, &dcid_off, &dcid_len) != 0) {
        return -1; /* свой же снимок не разобрать как Initial — подлинность проверить нечем */
    }
    return qp_verify_server_response(p, n, msg.bytes + dcid_off, dcid_len, version);
}

/* ОТВЕТ ПЛЕЧУ — ТОЛЬКО ПРИВЯЗАННЫЙ К НАШЕМУ INITIAL (задача 39).
   Ответ донора (qp_verify_aead) засчитывает и Version Negotiation, и Retry
   без проверки тега: оба не аутентифицированы, и на линии, где коробка
   отвечает за сервер или сервер отвечает на приманку (Heitmann et al.,
   FOCI 2026), они не доказывают, что НАШ Initial дошёл. Для плеча годится
   Initial нашей версии, который раскрывается серверными ключами из НАШЕГО
   DCID и адресован НАШЕМУ SCID (RFC 9000 §7.2: DCID ответа — SCID
   клиента), либо Retry нашему SCID с верным тегом от нашего DCID. Ответ на
   приманку несёт её собственный DCID и сюда не проходит; VN и Retry с
   неверным тегом или чужим CID — тишина этого вопроса, а не его успех. */
static int qp_verify_bound(const uint8_t *p, size_t n, d2k_hello msg) {
    msg = qp_head_of(msg);
    uint32_t version;
    size_t dcid_off, dcid_len;
    if (qp_dcid_of(msg.bytes, msg.len, &version, &dcid_off, &dcid_len) != 0) {
        return -1;
    }
    size_t so = dcid_off + dcid_len;
    if (so >= msg.len) return -1;
    size_t scid_len = msg.bytes[so];
    if (so + 1 + scid_len > msg.len) return -1;
    int unauth = qp_donor_unauth_reply(p, n, version);
    if (unauth < 0) return -1;            /* чужое */
    if (unauth > 0) {
        /* Retry ПРИВЯЗАН к нашему Initial, только если адресован нашему
           SCID и его тег целостности сходится с НАШИМ DCID как ODCID
           (RFC 9001 §5.8) — подделать тег без нашего DCID нельзя. Такой Retry
           проходит фильтр; дальше решает этап данных: d2k_qc идёт за его
           токеном. VN (версия 0) не аутентифицируется ничем — не успех. */
        uint32_t ver = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 |
                       (uint32_t)p[3] << 8 | (uint32_t)p[4];
        if (ver == 0) return -1;
        size_t rd = p[5];
        if ((size_t)6 + rd > n || rd != scid_len ||
            (scid_len && memcmp(p + 6, msg.bytes + so + 1, scid_len) != 0)) {
            return -1;
        }
        /* RFC 9000 §17.2.5.2: Retry с пустым токеном отбрасывается, как и
           Retry, чей SCID пуст или равен DCID нашего Initial. */
        size_t at = 6 + rd;
        if (at >= n) return -1;
        size_t rs = p[at++];
        if (rs == 0 || at + rs + 16 >= n) return -1;   /* пустой SCID или токен */
        if (rs == dcid_len && memcmp(p + at, msg.bytes + dcid_off, dcid_len) == 0) return -1;
        return d2k_qw_retry_verify(version, msg.bytes + dcid_off, dcid_len, p, n) == 0 ? 0 : -1;
    }
    qp_hdr h;
    if (qp_parse_hdr(p, n, &h) != 0) return -1;
    if (h.dcid_len != scid_len ||
        (scid_len && memcmp(p + h.dcid_off, msg.bytes + so + 1, scid_len) != 0)) {
        return -1; /* адресован не нашему соединению */
    }
    return qp_verify_server_response(p, n, msg.bytes + dcid_off, dcid_len, version);
}

int d2k_quic_verify_bound(const uint8_t *p, size_t n, d2k_hello msg) {
    return qp_verify_bound(p, n, msg);
}

/* Тонкая публичная обёртка над qp_verify_aead — задаче 6 (props.c, реальный
 * отправитель фрагментации) нужна та же проверка подлинности ответа, что и
 * обычным вопросам дерева, а не собственная копия расшифровки: это ровно тот
 * код, что уже прошёл несколько кругов ревью (см. qp_verify_server_response),
 * дублировать его для одного вызывающего было бы тем самым риском
 * расхождения, который в проекте уже отмечен для других копий. */
int d2k_quic_verify_response(const uint8_t *p, size_t n, d2k_hello msg) {
    return qp_verify_aead(p, n, msg);
}

/* Зонд согласования версии у донора идёт через ту же exchange/Parse, что и
   любой вопрос (probe.go:303-307: probeSpec{dcid, ver: V1}), значит и
   ответом для него служит тот же Answered(): VN, Retry v1 или Initial v1,
   раскрывшийся ключами из DCID зонда. */
static int qp_verify_vn(const uint8_t *p, size_t n, d2k_hello msg) {
    if (!msg.bytes || msg.len < 6 || (size_t)6 + msg.bytes[5] > msg.len) {
        return -1;
    }
    return qp_verify_server_response(p, n, msg.bytes + 6, msg.bytes[5], QP_VERSION_V1);
}

/* Серия из repeats ПАРАЛЛЕЛЬНЫХ попыток: сначала ВСЕ уходят на провод (см.
   шапку файла), потом ждём ответы разом через poll(), пока не истечёт
   wait_ms с момента отправки или не ответят все. Каждый пришедший ответ
   проверяется независимо через verify (см. qp_verify_fn выше), тайм-аут без
   ответа — тишина (fail, не err). ДВА РАЗНЫХ "не получилось", неразличимых
   ранее (правка ревью 2026-09-06, круг 4, находка 5): попытка вовсе НЕ
   ОТПРАВИЛАСЬ (сбой socket()/connect()/send() в qp_send_one, наша сторона,
   к сети отношения не имеет) против попытка ОТПРАВИЛАСЬ и получила явный
   сетевой отказ ECONNREFUSED (ICMP «порт недоступен», донор probe.go:643,
   :663; прочие ошибки чтения — тишина, как у донора). Первые идут в err,
   вторые — в fail как «нет ответа» (measure, probe.go:573-574: refused не
   попадает в NotBuilt; план 2026-10-02-review-fixes задача 10);
   refused_out, если не NULL, — число вторых. sent_out, если не NULL, — сколько
   ИЗ repeats ДЕЙСТВИТЕЛЬНО ушло на провод (repeats минус "не отправилось") —
   находка 4 ревью, круг 5: pass+fail тождественно равно repeats всегда (обе
   величины считают ВСЕ repeats попыток, просто по разным категориям), значит
   "измеренное вместо литерала" был тем же литералом другими словами;
   sent_out — единственное поле, которое на самом деле отличает "запрошено"
   от "запрошено И отправлено".
   prefix_ttl — см. qp_send_one; статический параметр этого файла, НЕ часть
   типажа d2k_quic_ask_fn (все существующие вызовы дерева вопросов передают
   0 — "не трогать", им TTL-приём не нужен, а расширять уже рассмотренный
   ревью публичный контракт ради одного вызывающего задачи 6 значило бы
   тащить лишний параметр через всё дерево). */
/* Принимает датаграмму и, если ядро принесло, достаёт TTL из контрольных
   данных. Обычный recv() этого не отдаёт: TTL живёт в IP-заголовке, а сокет
   отдаёт только полезную нагрузку — единственный переносимый способ узнать
   его с пользовательского сокета — попросить IP_RECVTTL и читать recvmsg.
   Ядро без этой опции просто не положит ничего, и *ttl останется нулём —
   «не измерено», а не выдуманное число. */
int (*d2k_quic_recv_fault_hook)(int fd);

static ssize_t qp_recv_ttl(int fd, uint8_t *buf, size_t cap, uint8_t *ttl) {
    *ttl = 0;
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = cap;
    union {
        struct cmsghdr align;
        uint8_t space[256];
    } ctl;
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl.space;
    msg.msg_controllen = sizeof ctl.space;
    if (d2k_quic_recv_fault_hook) {
        int e = d2k_quic_recv_fault_hook(fd);
        if (e != 0) {
            errno = e;
            return -1;
        }
    }
    ssize_t n = recvmsg(fd, &msg, 0);
    if (n <= 0) { return n; }
#if defined(IP_RECVTTL) || defined(IPV6_HOPLIMIT)
    /* ПОДАВЛЕНИЕ ТОЧЕЧНОЕ И НЕ НАШЕ. CMSG_NXTHDR у musl сам сравнивает
       знаковое с беззнаковым внутри макроса; под -Werror это ломает
       кросс-сборку на строке, где нашего кода нет вовсе. Переписывать обход
       контрольных данных руками значило бы завести свою копию выравнивания
       cmsg — цена выше ошибки. Подавляем ровно на этот цикл. */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        int is_hop = c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_HOPLIMIT;
        /* Linux отдаёт IP_TTL, BSD и macOS — IP_RECVTTL под тем же номером,
           что и опция. Принимаем оба: имя различается, смысл один. */
        int is_ttl = 0;
#ifdef IP_RECVTTL
        is_ttl = c->cmsg_level == IPPROTO_IP &&
                 (c->cmsg_type == IP_TTL || c->cmsg_type == IP_RECVTTL);
#endif
        if (!is_hop && !is_ttl) continue;
        if (c->cmsg_len < CMSG_LEN(0)) continue;
        size_t len = (size_t)c->cmsg_len - (size_t)CMSG_LEN(0);
        if (len >= sizeof(int)) {
            int v = 0;
            memcpy(&v, CMSG_DATA(c), sizeof v);
            if (v > 0 && v <= 255) { *ttl = (uint8_t)v; }
        } else if (len >= 1) {
            *ttl = *(uint8_t *)CMSG_DATA(c);
        }
        break;
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif
    return n;
}

/* Original nextIPID: random start, shared monotonic counter, never zero.
   Ports are not in the kernel's reassembly key, so they cannot serve as IDs. */
/* Port of exchangeFragmented: the connected receive socket remains owned
   until the common authenticated-response loop closes it. No close/rebind
   race, no repeated packet/port/ID for independent attempts. */
static int qp_send_fragmented(const char *addr,uint16_t port,d2k_hello msg,
    const d2k_ipfrag_plan *plan,uint32_t mark,int *marked) {
    *marked=1; /* an unsent/unsupported question cannot contaminate a trial */
#ifndef __linux__
    (void)addr;(void)port;(void)msg;(void)plan;(void)mark;
    return -1; /* original frag_other.go: not built, not negative evidence */
#else
    if(!addr || !msg.bytes || !msg.len || msg.len>D2K_QW_MAX_DGRAM)return -1;
    uint8_t target[16];
    int family=qp_addr_parse(addr,target);
    if(!family)return -1;
    struct sockaddr_storage dst;
    memset(&dst,0,sizeof dst);
    socklen_t dst_len;
    if(family==AF_INET6) {
        struct sockaddr_in6 *v6=(struct sockaddr_in6 *)&dst;
        v6->sin6_family=AF_INET6;v6->sin6_port=htons(port);
        memcpy(&v6->sin6_addr,target,16);dst_len=sizeof *v6;
    } else {
        struct sockaddr_in *v4=(struct sockaddr_in *)&dst;
        v4->sin_family=AF_INET;v4->sin_port=htons(port);
        memcpy(&v4->sin_addr,target,4);dst_len=sizeof *v4;
    }
    /* Fresh local port (task 39): same discipline as every other attempt. */
    int rx_marked=1;
    int rx=qp_open_fresh(family,(struct sockaddr *)&dst,dst_len,0,mark,&rx_marked);
    if(rx<0)return -1;
    if(mark && !rx_marked){*marked=0;close(rx);return -1;}
    int shape=0;
    for(int i=1;i<=4;i++){d2k_ipfrag_plan candidate;
        if(!d2k_ipfrag_shape(i,&candidate) && !memcmp(&candidate,plan,sizeof candidate)){shape=i;break;}}
    char text[16384];d2k_quic_arm_question q={0};q.frag=shape;
    if(!shape || d2k_quic_question_plan(&q,text,sizeof text) ||
       d2k_udp_plan_send(rx,text,msg.bytes,msg.len,mark)){close(rx);return -1;}
    return rx;
#endif
}

/* Donor probe.go:neutralName — a fresh random z<10 hex>.example.com for
   every control repetition. The fixed-size name lets the captured SNI be
   replaced without changing the client's otherwise measured TLS profile. */
static int qp_neutral_control_sni(char out[24]) {
    static const char hex[] = "0123456789abcdef";
    uint8_t random[5];
    if (!out || d2k_t13_random(random, sizeof random) != 0) {
        return -1;
    }
    out[0] = 'z';
    for (size_t i = 0; i < sizeof random; i++) {
        out[1 + i * 2] = hex[random[i] >> 4];
        out[2 + i * 2] = hex[random[i] & 0x0f];
    }
    memcpy(out + 11, ".example.com", sizeof ".example.com");
    return 0;
}

/* crypto_split (задача 40): свежий Initial каждой попытки уходит с
   ClientHello, разрезанным на два кадра CRYPTO (d2k_quic_initial_split_crypto
   — та же функция, что исполняет план в датапате). Только вместе с
   fresh_sni; не разрезалось — попытка не отправляется. */
static d2k_tally quic_ask_core(const char *addr, uint16_t port,
                              const uint8_t *prefix, size_t prefix_len, int prefix_ttl,
                              int prefix_copies, int src_port, const char *split_sni,
                              d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                              int repeats, uint32_t *rtt_ms_out, int *refused_out,
                              int *sent_out, uint8_t *ttl_in_out, qp_verify_fn verify,
                              const d2k_ipfrag_plan *fragment, const char *fresh_sni,
                              int neutral_control, int crypto_split, unsigned longer) {
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
           круг 3, находка E). НЕ "недостижимо" (прежняя редакция ошибалась,
           проверив только вызовы ИЗНУТРИ d2k_quic_classify, а не сам хук —
           d2k_quic_ask_hook extern и часть контракта независимо от
           вызывающего; ревьюер вызвал его напрямую с repeats=99 и получил
           err=99, правка ревью 2026-09-06, круг 4, находка 2) — предел
           D2K_QUIC_MAX_ADDRS назван в doc-комментарии d2k_quic_ask_fn,
           покрыт тестом (см. test_quicprobe.c). */
        d2k_tally bad;
        memset(&bad, 0, sizeof bad);
        bad.err = repeats;
        bad.fail = repeats;
        bad.marked = (mark == 0);
        if (rtt_ms_out) {
            *rtt_ms_out = 0;
        }
        if (refused_out) {
            *refused_out = 0; /* ни одна попытка не отправлялась — отказывать нечему */
        }
        if (sent_out) {
            *sent_out = 0; /* отказ до единого send() — на провод не ушло ничего */
        }
        return bad;
    }
    if (wait_ms == 0) {
        wait_ms = D2K_QUIC_RTT_WAIT_FLOOR_MS;
    }
    if (rtt_ms_out) {
        *rtt_ms_out = 0;
    }
    if (ttl_in_out) {
        *ttl_in_out = 0;
    }

    int fds[D2K_QUIC_MAX_ADDRS];
    int marked[D2K_QUIC_MAX_ADDRS];
    int done[D2K_QUIC_MAX_ADDRS];
    /* 1 pass, 0 тишина/не подтверждено, -1 НЕ ОТПРАВИЛОСЬ (наша сторона, сеть
       не спрошена), -2 ОТПРАВИЛОСЬ и получило явный сетевой отказ (правка
       ревью 2026-09-06, круг 4, находка 5 — прежде оба случая были одним и
       тем же -1, и вызывающий не мог отличить "не спросили" от "спросили и
       отказали"). */
    int result[D2K_QUIC_MAX_ADDRS];
    struct timespec sent_at[D2K_QUIC_MAX_ADDRS];
    int pending = 0;

    /* КАЖДАЯ ПАРАЛЛЕЛЬНАЯ ПОПЫТКА — СВОЁ СОЕДИНЕНИЕ.
     *
     * Здесь стоял открытый вопрос (см. шапку файла): отбивает ли сервер три
     * дословно одинаковые датаграммы как повтор одного пакета. Замер сделан
     * 13.09.2026 в lab-quic.sh на www.google.com: контрольное имя давало
     * ровно 1/3 — первая попытка засчитывалась, две другие пропадали молча.
     * Единогласие 3/3 при этом недостижимо ни на одном вопросе, и дерево
     * честно объявляло «измерению верить нельзя» ВСЕГДА.
     *
     * Ответ — не ослабить порог, а перестать слать один и тот же пакет
     * одного и того же соединения. Для снимочных вопросов обновляем только
     * CID через d2k_quic_hello_recid: там форма приветствия должна остаться
     * прежней. Оригинальный askArms задаёт fresh_sni и, как donor
     * arms.go:ask -> measure -> buildInitial, строит полное новое приветствие
     * отдельно на каждый повтор. Этот режим локален для arm-hook.
     *
     * Не удалось обновить CID (не Initial, чужая версия, склеенная
     * датаграмма) — обычные вопросы сохраняют прежний fallback: снимок как
     * есть. arm-hook такого fallback не имеет: не собрался свежий Initial —
     * вопрос не отправляется. */
    static const size_t COPY_CAP = D2K_QW_MAX_DGRAM;
    uint8_t copies[D2K_QUIC_MAX_ADDRS][D2K_QW_MAX_DGRAM];
    /* Пачка на попытку — отдельный буфер: она в разы длиннее одиночного
       снимка, и класть её в copies значило бы раздуть кадр на стеке для всех
       вопросов. Статический: рабочий поток у замера свой. */
    static __thread uint8_t packs[D2K_QUIC_MAX_ADDRS][D2K_SHAPE_MAX];
    uint8_t tails[D2K_QUIC_MAX_ADDRS][D2K_QW_MAX_DGRAM];
    const uint8_t *pfx[D2K_QUIC_MAX_ADDRS];
    size_t pfx_len[D2K_QUIC_MAX_ADDRS];
    d2k_hello sent[D2K_QUIC_MAX_ADDRS];
    for (int i = 0; i < repeats; i++) {
        size_t clen = 0, tlen = 0;
        pfx[i] = prefix;
        pfx_len[i] = prefix_len;
        if (verify == qp_verify_vn) {
            /* Зонд согласования версии: свои случайные DCID/SCID на каждую
               попытку (донор probe.go:303-306). Не собрался — попытка не
               отправляется, а не повторяет чужие идентификаторы. */
            clen = qp_build_vn_trigger(copies[i], COPY_CAP);
            sent[i] = clen ? (d2k_hello){copies[i], clen, NULL, 0, 0, 0} : (d2k_hello){NULL, 0, NULL, 0, 0, 0};
        } else if (fresh_sni && fresh_sni[0]) {
            if (d2k_quic_probe_initial(fresh_sni, copies[i], COPY_CAP, &clen) == 0) {
                sent[i].bytes = copies[i];
                sent[i].len = clen;

            } else {
                sent[i] = (d2k_hello){NULL, 0, NULL, 0, 0, 0};
            }
        } else if (neutral_control) {
            char neutral_sni[24];
            /* Donor probe.go builds a fresh Initial for every neutral control
               repetition.  Re-encrypting the captured packet here used the
               generic snapshot builder, which recomputed PNLen=1 for PN=0;
               donor buildInitial uses PNLen=4 and the loopback oracle rejects
               the former as a malformed measurement. */
            if (qp_neutral_control_sni(neutral_sni) == 0 &&
                d2k_quic_probe_initial(neutral_sni, copies[i], COPY_CAP, &clen) == 0) {
                sent[i].bytes = copies[i];
                sent[i].len = clen;
            } else {
                /* A failed rebuild is a local unsent attempt, never a replay
                   of the stale/fixed control name. */
                sent[i] = (d2k_hello){NULL, 0, NULL, 0, 0, 0};
            }
        } else if (split_sni) {
            /* ПАРА ДАТАГРАММ СОБИРАЕТСЯ НА КАЖДУЮ ПОПЫТКУ ЦЕЛИКОМ, а не
               пересобирается идентификатором, как одиночный пакет: обе
               половины обязаны нести ОДИН DCID (иначе сервер увидит два
               соединения по половине приветствия), и свежесть на попытку
               даёт сама сборка пары. Не собралось — попытка НЕ отправляется
               (sent[i].bytes=NULL даст "не отправилось"), и вопрос останется
               незаданным: подменить пару одиночным снимком значило бы
               измерить другой вопрос под этим именем. */
            if (msg.bytes && msg.len &&
                d2k_quic_hello_split(msg.bytes, msg.len, split_sni,
                                     copies[i], COPY_CAP, &clen,
                                     tails[i], COPY_CAP, &tlen) == 0) {
                sent[i].bytes = copies[i];
                sent[i].len = clen;
                pfx[i] = tails[i];   /* хвост уезжает ПЕРВЫМ */
                pfx_len[i] = tlen;
            } else {
                sent[i].bytes = NULL;
                sent[i].len = 0;
            }
        } else if (msg.bytes && msg.len && d2k_qsnap_is(msg.bytes, msg.len)) {
            /* ПАЧКА: свежий идентификатор на всю пачку разом (задача 66).
               Половинки обязаны нести ОДИН DCID, иначе сервер увидит два
               соединения по половине приветствия; поштучное обновление, как
               у одиночного снимка, здесь невозможно по устройству. */
            d2k_qsnap in;
            if (d2k_qsnap_parse(msg.bytes, msg.len, &in) == 0 &&
                d2k_qsnap_recid(&in, packs[i], sizeof packs[i], &clen) == 0) {
                sent[i].bytes = packs[i];
                sent[i].len = clen;
            } else {
                sent[i] = (d2k_hello){NULL, 0, NULL, 0, 0, 0};
            }
        } else if (msg.bytes && msg.len &&
                   d2k_quic_hello_recid(msg.bytes, msg.len, copies[i], COPY_CAP, &clen) == 0) {
            sent[i].bytes = copies[i];
            sent[i].len = clen;
        } else {
            sent[i] = msg;
            if(fragment)sent[i]=(d2k_hello){NULL, 0, NULL, 0, 0, 0}; /* never replay an unrefreshable input */
        }
    }

    for (int i = 0; i < repeats; i++) {
        /* Свой порт на каждую попытку: три параллельные попытки с одним
           bind'ом подрались бы за него, и две упали бы с EADDRINUSE (то же
           решение у оригинала, questions.go: port-1-attempt). */
        int sp = (src_port > 0) ? src_port - i : 0;
        fds[i] = fragment ? qp_send_fragmented(addr,port,sent[i],fragment,mark,&marked[i]) :
            qp_send_one(addr, port, pfx[i], pfx_len[i], prefix_ttl, prefix_copies, sp,
                        sent[i], mark, &marked[i], crypto_split, longer);
        if (!marked[i]) {
            t.marked = 0;
        }
        if (fds[i] < 0) {
            /* -1 не отправилось (socket()/connect()/send() в qp_send_one);
               -2 сетевой отказ всплыл уже на send() — см. qp_send_one. */
            result[i] = fds[i] == -2 ? -2 : -1;
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
            uint8_t buf[2048];
            uint8_t ttl_seen = 0;
            ssize_t n;
            int sock_err = 0;
            if ((pfds[k].revents & POLLERR) && !(pfds[k].revents & POLLIN)) {
                /* Ошибка без данных: читаем SO_ERROR, а не recv() — у
                   блокирующего сокета recv() без данных мог бы встать. */
                socklen_t el = sizeof sock_err;
                if (getsockopt(fds[i], SOL_SOCKET, SO_ERROR, &sock_err, &el) != 0) {
                    sock_err = errno;
                }
                if (sock_err == 0) {
                    continue; /* ошибка уже снята — ждём дальше */
                }
                n = -1;
            } else {
                n = qp_recv_ttl(fds[i], buf, sizeof buf, &ttl_seen);
                sock_err = n < 0 ? errno : 0;
            }
            if (n < 0 && (sock_err == EINTR || sock_err == EAGAIN || sock_err == EWOULDBLOCK)) {
                continue; /* не исход обмена — ждём дальше в пределах срока */
            }
            if (n > 0) {
                /* Проверять ответ надо ключами ТОЙ копии, что ушла с этого
                   сокета: у каждой свой идентификатор, а из него выводятся
                   ключи сервера. */
                if (verify(buf, (size_t)n, sent[i]) == 0) {
                    done[i] = 1;
                    pending--;
                    result[i] = 1;
                    if (ttl_in_out && *ttl_in_out == 0 && ttl_seen > 0) {
                        *ttl_in_out = ttl_seen;
                    }
                    if (rtt_ms_out) {
                        struct timespec arrived;
                        clock_gettime(CLOCK_MONOTONIC, &arrived);
                        uint32_t rtt_ms = (uint32_t)((arrived.tv_sec - sent_at[i].tv_sec) * 1000L +
                                                      (arrived.tv_nsec - sent_at[i].tv_nsec) / 1000000L);
                        if (*rtt_ms_out == 0 || rtt_ms < *rtt_ms_out) {
                            *rtt_ms_out = rtt_ms;
                        }
                    }
                }
                /* НЕ ПОДТВЕРДИЛОСЬ — ЗОНД НЕ ЗАКРЫВАЕМ, и это не мелочь.
                   Прежняя редакция закрывала его на ПЕРВОЙ же пришедшей
                   датаграмме, чем бы она ни была. Настоящий сервер, получив
                   несколько Initial, отвечает СНАЧАЛА подтверждением, а
                   ServerHello шлёт следом: замер 17.09 на www.google.com дал
                   48 байт с одним кадром ACK, потом ещё ACK, и лишь ТРЕТЬИМ
                   пакетом CRYPTO. Закрытый на первом ACK зонд объявлял такой
                   сервер МОЛЧАЩИМ — а молчание здесь основание всех вердиктов.
                   И это не край: браузер с постквантовым key_share шлёт два
                   Initial всегда, то есть так отвечала бы вся живая цель.
                   Цикл всё равно ограничен сроком ожидания: каждая итерация
                   съедает одну датаграмму и перечитывает остаток времени. */
            } else if (n == 0) {
                done[i] = 1;
                pending--;
                result[i] = 0;
            } else {
                done[i] = 1;
                pending--;
                /* Ошибка чтения ПОСЛЕ успешной отправки. Донор exchange
                   (probe.go:660-663, frag_linux.go:91) считает отказом ТОЛЬКО
                   ECONNREFUSED (ICMP «порт недоступен»); любая другая ошибка
                   (EHOSTUNREACH, ENETUNREACH, ...) — просто конец обмена без
                   ответа, то есть тишина. Код -2 — только для первого. */
                result[i] = sock_err == ECONNREFUSED ? -2 : 0;
            }
        }
    }

    int refused = 0;
    int not_sent = 0;
    for (int i = 0; i < repeats; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
        }
        if (result[i] == 1) {
            t.pass++;
        } else if (result[i] == -2) {
            /* ECONNREFUSED (probe.go:643, :663) — «нет ответа», не «опыт
               не состоялся». Донор measure (probe.go:573-574): case
               r.refused стоит ДО case r.err и в NotBuilt не попадает; дальше прямой зонд даёт
               content (probe.go:322-337), повторный контроль —
               residual=true (probe.go:355), плечо — «не прошло»
               (arms.go:69-94). Отдельно виден только через refused_out. */
            t.fail++;
            refused++;
        } else if (result[i] == -1) {
            t.err++;
            t.fail++;
            not_sent++;
        } else {
            t.fail++;
        }
    }
    if (refused_out) {
        *refused_out = refused;
    }
    if (sent_out) {
        *sent_out = repeats - not_sent; /* находка 4 ревью, круг 5: что реально ушло на провод */
    }
    return t;
}

static d2k_tally quic_ask_ex(const char *addr, uint16_t port,
                              const uint8_t *prefix, size_t prefix_len, int prefix_ttl,
                              int prefix_copies, int src_port, const char *split_sni,
                              d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                              int repeats, uint32_t *rtt_ms_out, int *refused_out,
                              int *sent_out, uint8_t *ttl_in_out, qp_verify_fn verify,
                              const d2k_ipfrag_plan *fragment, const char *fresh_sni,
                              int neutral_control) {
    return quic_ask_core(addr, port, prefix, prefix_len, prefix_ttl, prefix_copies, src_port,
                         split_sni, msg, wait_ms, mark, repeats, rtt_ms_out, refused_out,
                         sent_out, ttl_in_out, verify, fragment, fresh_sni, neutral_control, 0, 0);
}

static d2k_tally quic_fragment(const char *addr,uint16_t port,int shape,d2k_hello msg,
    uint32_t wait_ms,uint32_t mark,int repeats,int *sent_out) {
    d2k_ipfrag_plan p;
    if(d2k_ipfrag_shape(shape,&p)!=0) {
        d2k_tally t={0};t.marked=1;t.fail=t.err=repeats>0?repeats:D2K_QUIC_REPEATS;
        if(sent_out)*sent_out=0;
        return t;
    }
    return quic_ask_ex(addr,port,NULL,0,0,1,0,NULL,msg,wait_ms,mark,repeats,
        NULL,NULL,sent_out,NULL,qp_verify_aead,&p,NULL,0);
}
d2k_quic_fragment_fn d2k_quic_fragment_hook=quic_fragment;
/* d2k_quic_progress_hook определён в quicarms.c: тот линкуется и без
   quicprobe.o (test_quic_original_arms), а quicprobe.o — только с ним. */
static void qp_progress(const char *question, int sent)
{
    if (d2k_quic_progress_hook && sent > 0) d2k_quic_progress_hook(question, sent);
}

static d2k_tally quic_ask_arm(const d2k_quic_arm_question *q, const char *sni,
    uint16_t port, uint32_t wait_ms, uint32_t mark, int *sent_out) {
    d2k_tally bad={0};
    bad.marked=(mark==0);
    bad.fail=bad.err=D2K_QUIC_REPEATS;
    /* The control question (fragment survival) carries no caller name:
       donor arms.go:204-205 builds buildInitial(neutralName(), ...) per
       attempt, so each repeat draws a fresh neutral name below. */
    int neutral=q && q->control;
    if(!q || !q->addr || (!neutral && (!sni || !sni[0]))) {
        if(sent_out)*sent_out=0;
        return bad;
    }
    d2k_ipfrag_plan plan;
    const d2k_ipfrag_plan *fragment=NULL;
    const uint8_t *prefix=q->blob;
    size_t prefix_len=q->blob_len;
    int ttl=q->ttl;
    int copies=q->copies>1?q->copies:1;
    if(q->split && (q->frag || neutral)) {
        if(sent_out)*sent_out=0;
        return bad; /* разрез CRYPTO не совместим с фрагментами и нейтральным контролем */
    }
    if(q->frag) {
        if(q->blob_len || d2k_ipfrag_shape(q->frag,&plan)!=0) {
            if(sent_out)*sent_out=0;
            return bad;
        }
        prefix=NULL;
        prefix_len=0;
        ttl=0;
        copies=1;
        fragment=&plan;
    }
    d2k_hello no_snapshot={NULL,0,NULL,0,0, 0};
    /* Arm answers are bound to our Initial only (qp_verify_bound, task 39);
       the fragment-survival control keeps the donor's reply criterion. */
    return quic_ask_core(q->addr,port,prefix,prefix_len,ttl,copies,0,NULL,
        no_snapshot,wait_ms,mark,D2K_QUIC_REPEATS,NULL,NULL,sent_out,NULL,
        neutral?qp_verify_aead:qp_verify_bound,fragment,neutral?NULL:sni,neutral,q->split,q->udplen);
}
d2k_quic_ask_arm_fn d2k_quic_ask_arm_hook=quic_ask_arm;

/* ---------------------------------------------------------------------
 * ЭТАП ДАННЫХ ПЛЕЧА (задача 39, см. D2K_QUIC_ARM_DATA_BYTES).
 * Одно настоящее соединение d2k_qc на СВЕЖЕЙ четвёрке, тот же адрес, что у
 * фильтра, и то же воздействие перед первым Initial: фальшивки с копиями и
 * TTL — qp_send_prefix, фрагменты — qp_emit_fragments. Затем управляющий
 * поток HTTP/3 и GET / к имени цели; засчитываются данные ответа,
 * прошедшие линию после рукопожатия (d2k_qc_app_progress).
 * --------------------------------------------------------------------- */

typedef struct {
    const d2k_quic_arm_question *q;
    int family;
    uint8_t target[16];
    uint16_t port;
    uint32_t mark;
    d2k_ipfrag_plan plan;
    int initial_out; /* первый Initial ушёл на провод: дальше отказ — сеть */
    uint16_t local_port;
} qp_arm_action;

static int qp_arm_first_send(int fd, const uint8_t *initial, size_t len, void *user) {
    qp_arm_action *a=user;struct sockaddr_storage me;socklen_t ml=sizeof me;
    if(getsockname(fd,(struct sockaddr *)&me,&ml)==0)a->local_port=me.ss_family==AF_INET6?
        ntohs(((struct sockaddr_in6 *)&me)->sin6_port):ntohs(((struct sockaddr_in *)&me)->sin_port);
    char plan[16384];
    if(d2k_quic_question_plan(a->q,plan,sizeof plan) ||
       d2k_udp_plan_send(fd,plan,initial,len,a->mark))return -1;
    a->initial_out=1;return 1;
}

static int64_t qp_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000L;
}

static d2k_quic_arm_data quic_arm_data(const d2k_quic_arm_question *q, const char *sni,
    const char *path, uint16_t port, uint32_t wait_ms, uint32_t mark) {
    d2k_quic_arm_data d;
    memset(&d, 0, sizeof d);
    d.verdict = D2K_QAD_NOT_RUN;
    snprintf(d.reason, sizeof d.reason, "этап данных не начат");
    if (!q || q->control || !q->addr || !sni || !sni[0]) return d;
    qp_arm_action a;
    memset(&a, 0, sizeof a);
    a.q = q;
    a.port = port;
    a.mark = mark;
    a.family = qp_addr_parse(q->addr, a.target);
    if (!a.family) return d;
    if (q->frag && (q->blob_len || d2k_ipfrag_shape(q->frag, &a.plan) != 0)) return d;
    /* Сроки — из того же измеренного ожидания, что у фильтра (3×RTT в
       [пол; потолок]): рукопожатию — два таких срока, тишине потока после
       последнего прироста — один, всему чтению — четыре. */
    uint32_t step = wait_ms ? wait_ms : D2K_QUIC_RTT_WAIT_FLOOR_MS;
    if (!path || !path[0]) path = "/";
    /* Приветствие этапа — клиент d2k_qc (только он доводит рукопожатие), но
       первая датаграмма добита до длины Initial фильтра (донорский
       d2k_quic_probe_initial к тому же имени): коробка видит датаграмму той же
       длины, что в вопросе. Что именно ушло — в трассе шага. */
    size_t filter_len = 0, filter_ch = 0;
    {
        uint8_t probe[D2K_QW_MAX_DGRAM], ch[D2K_QW_MAX_DGRAM];
        if (d2k_quic_probe_initial(sni, probe, sizeof probe, &filter_len) != 0 ||
            d2k_quic_client_hello(probe, filter_len, ch, sizeof ch, &filter_ch) != 0) {
            filter_len = filter_ch = 0;
        }
    }
    /* pad_to у d2k_qc — длина ClientHello: добиваем до ClientHello фильтра,
       тогда и датаграмма выходит длиной с Initial фильтра. */
    /* После Retry (и в повторах по PTO) Initial уходит БЕЗ воздействия:
       ровно так поток плана ведёт датапат — session.c пропускает Initial
       потока, где план уже применён («поток уже показывал приветствие»). */
    snprintf(d.note, sizeof d.note, "hello d2k_qc, ClientHello %zu как у Initial %zu фильтра, "
             "GET %.32s; после Retry Initial без воздействия, как датапат",
             filter_ch, filter_len, path);
    d2k_qc_opts o;
    memset(&o, 0, sizeof o);
    o.ip = q->addr;
    o.port = port;
    o.sni = sni;
    o.alpn = "h3";
    o.deadline_ms = (int)(2u * step);
    o.pad_to = filter_ch;
    o.mark = mark;
    o.first_send = qp_arm_first_send;
    o.first_send_user = &a;
    d2k_qc *c = NULL;
    char err[200];
    err[0] = '\0';
    int connected = d2k_qc_connect(&o, &c, err, sizeof err) == 0;
    d.local_port = a.local_port;
    if (!connected) {
        if (!a.initial_out) {
            snprintf(d.reason, sizeof d.reason, "этап данных не состоялся: %.120s", err);
            return d;
        }
        d.verdict = d2k_quic_arm_data_judge(0, 0, 0, 0);
        snprintf(d.reason, sizeof d.reason, "фильтр прошёл, рукопожатия нет: %.120s", err);
        return d;
    }
    d2k_quic_data_stage(c, sni, path, q->need_complete, q->budget_pk, step, &d);
    d2k_qc_close(c);
    return d;
}
d2k_quic_arm_data_wire_fn d2k_quic_arm_data_hook=quic_arm_data;

/* Этап данных на уже установленном соединении c: управляющий поток HTTP/3,
 * запрос к sni по path и чтение ответа до вердикта. Соединение не
 * закрывает. Выделено из quic_arm_data ради стенда на петле (задача 50,
 * поле 04.10: воспроизведение по бюджету коробки). */
void d2k_quic_data_stage(d2k_qc *c, const char *sni, const char *path, int need_complete,
                         unsigned budget_pk, uint32_t step, d2k_quic_arm_data *out) {
    d2k_quic_arm_data d = *out;
    char err[200];
    err[0] = '\0';
    uint8_t buf[4096];
    uint64_t sid = 0;
    size_t cn = d2k_h3_control(buf, sizeof buf);
    if (cn == 0 || d2k_qc_stream_send(c, 2, buf, cn, 0, err, sizeof err) != 0) {
        d.verdict = D2K_QAD_NOT_RUN;
        snprintf(d.reason, sizeof d.reason, "управляющий поток не ушёл: %.120s", err);
        { *out = d; return; }
    }
    /* Та же пауза до вопроса, что у проверки плана (verify.c): сервер обязан
       увидеть SETTINGS раньше запроса. */
    (void)d2k_qc_stream_recv(c, &sid, buf, sizeof buf, 400, err, sizeof err);
    size_t rn = d2k_h3_request(sni, path, buf, sizeof buf);
    if (rn == 0 || d2k_qc_stream_send(c, 0, buf, rn, 1, err, sizeof err) != 0) {
        /* ВЕРДИКТ СТАВИТСЯ ЯВНО, а не остаётся нулём от memset вызывающего.
           Первый запрос не ушёл — опыта не было: ни обрыва, ни прохода. То,
           что D2K_QAD_NOT_RUN равен нулю, сегодня верно и молча нас спасало,
           но полагаться на совпадение значения с «обнулённой структурой»
           нельзя: ровно так «не задан» однажды и превращается в «задан и
           отвечен». Среди причин, которые тут бывают, есть и предел потоков
           СЕРВЕРА (d2k_qc_stream_send, задача 29) — замер на таком сервере не
           состоится, и назвать это обрывом было бы ложью. */
        d.verdict = D2K_QAD_NOT_RUN;
        snprintf(d.reason, sizeof d.reason, "запрос не ушёл: %.120s", err);
        { *out = d; return; }
    }
    uint64_t bytes = 0, last = 0;
    int complete = 0, closed = 0, status = 0;
    /* Начало ответа — ради HEADERS: тот же разбор кода, что у проверки
       плана (verify.c), чтобы правило было одно и в предусловии. */
    /* Буфер заголовков на куче и того же размера, что у проверки плана: прежние
       8 КБ обрезали длинный HEADERS, и рабочее плечо становилось «обрывом». */
    uint8_t *head = malloc(D2K_VERIFY_HEADER_LIMIT);
    size_t head_len = 0;
    int head_full = 0;
    if (!head) {
        d.verdict = D2K_QAD_NOT_RUN;
        snprintf(d.reason, sizeof d.reason, "не хватило памяти под заголовки ответа HTTP/3");
        { *out = d; return; }
    }
    int64_t start = qp_now_ms(), progress_at = start;
    /* Раунд 3 (задача 50): «встал» решает молчание транспорта, проверенное
       PING (d2k_qstall), а не пауза в ответе. Медленный первый байт и
       потерянный пакет — не обрыв; живой сервер, не успевший ответить, — «не
       измерено». Общий предел — четыре срока или три RTO с запасом, что
       больше: обрыву нужно RTO тишины и два PING без ответа. */
    d2k_qstall st;
    {
        uint64_t prog0 = 0;
        d2k_qc_app_progress(c, &prog0, NULL);
        d2k_qstall_init(&st, d2k_qc_rtt_ms(c), start, prog0, d2k_qc_rx_wire_bytes(c));
    }
    int stalled = 0, budget = 0, req_failed = 0, oneway = 0;
    uint64_t tx0 = 0, rx0 = 0, pk = 0, done_bytes = 0;
    d2k_qc_dgrams(c, &tx0, &rx0);
    int64_t limit = (int64_t)(4u * step);
    if (limit < 4 * st.rto_ms) limit = 4 * st.rto_ms;
    (void)progress_at;
    /* ВОСПРОИЗВЕДЕНИЕ ПО БЮДЖЕТУ КОРОБКИ (поле 04.10, rua.gr в Safari).
       Коробка рвёт поток после бюджета пакетов, а ответ на один запрос
       короткой страницы кончается внутри бюджета — «пришёл целиком» ничего
       не говорил об обрыве. Как у подтверждений (задача 55, verify.c
       budget_quic): полный ответ — следующий запрос тем же путём на новом
       двунаправленном потоке той же связи, пока связь не перенесёт
       2 × бюджет датаграмм (сервер отвечает — не заблокировано) или сервер
       не замолчит (PING без ответа — обрыв воспроизведён). Срок ожидания
       отсчитывается от каждого запроса заново. */
    int repeat = budget_pk > 0;
    d2k_qbudget bg;
    d2k_qbudget_init(&bg, budget_pk);
    unsigned need = bg.need;
    unsigned requests = 1;
    uint64_t req_sid = 0;
    int64_t req_at = start;
    while (repeat || (!(complete && status) &&
                      (need_complete || bytes < D2K_QUIC_ARM_DATA_BYTES || !status))) {
        int64_t now = qp_now_ms();
        if (now - req_at >= limit) break;
        /* РАЗНЫЕ байты ответа за весь этап: внутри одного запроса их даёт
           app_progress, а при переходе на следующий поток счёт продолжается с
           done_bytes — иначе величина не монотонна и «ответ вырос» нечем
           проверить (повторы при этом не считаются ни там, ни тут). */
        uint64_t prog = 0, acked = 0;
        d2k_qc_app_progress(c, &prog, NULL);
        prog += done_bytes;
        int have_ack = d2k_qc_outbound(c, NULL, &acked);
        int act = d2k_qstall_step(&st, now, prog, d2k_qc_rx_wire_bytes(c), have_ack, acked);
        if (act == D2K_QSTALL_STALLED) { stalled = 1; break; }
        if (act == D2K_QSTALL_ONEWAY) { stalled = 1; oneway = 1; break; }
        {
            uint64_t tx = 0, rx = 0;
            d2k_qc_dgrams(c, &tx, &rx);
            pk = (tx - tx0) + (rx - rx0);
            if (d2k_qbudget_ok(&bg, pk, prog, status, now, st.last_prog_ms, st.rto_ms)) {
                budget = 1;
                break;
            }
        }
        if (repeat && complete && status) {
            /* Ответ целиком внутри бюджета — следующий запрос. */
            done_bytes += bytes;
            req_sid += 4;
            rn = d2k_h3_request(sni, path, buf, sizeof buf);
            if (rn == 0 || d2k_qc_stream_send(c, req_sid, buf, rn, 1, err, sizeof err) != 0) {
                req_failed = 1;
                break;
            }
            requests++;
            req_at = now;
            bytes = last = 0;
            complete = 0;
            /* HEADERS and status belong to this request stream. A complete
               prior response cannot validate DATA-only bytes on the next. */
            head_len = 0;
            status = 0;
            continue;
        }
        if (act == D2K_QSTALL_PROBE && d2k_qc_ping(c, err, sizeof err) == 0) {
            /* Номер пакета с PING: подтверждение сличается с ним, а не с
               фактом прихода чего-нибудь (см. d2k_qstall). */
            uint64_t pn = 0;
            (void)d2k_qc_outbound(c, &pn, NULL);
            d2k_qstall_sent(&st, pn);
        }
        long n = d2k_qc_stream_recv(c, &sid, buf, sizeof buf, 200, err, sizeof err);
        if (n < 0) { closed = 1; }
        if (n > 0 && head_len < D2K_VERIFY_HEADER_LIMIT) {
            size_t room = D2K_VERIFY_HEADER_LIMIT - head_len;
            size_t take = (size_t)n < room ? (size_t)n : room;
            memcpy(head + head_len, buf, take);
            head_len += take;
        }
        if (!status && head_len > 0) {
            int st = 0;
            if (d2k_h3_status(head, head_len, &st) == 0) status = st;
            else if (head_len >= D2K_VERIFY_HEADER_LIMIT) { head_full = 1; break; }
        }
        d2k_qc_app_progress(c, &bytes, &complete);
        if (status == 451) break; /* Explicit refusal belongs to this response. */
        if (bytes > last) { last = bytes; progress_at = qp_now_ms(); }
        if (closed) break;
    }
    free(head);
    d2k_qc_app_progress(c, &bytes, &complete);
    d.app_bytes = done_bytes + bytes;
    d.requests = requests;
    d.need = repeat ? need : 0;
    {
        uint64_t tx = 0, rx = 0;
        d2k_qc_dgrams(c, &tx, &rx);
        d.packets = pk = (tx - tx0) + (rx - rx0);
    }
    /* Раунд 4 (M-n1): ошибка соединения — не молчание. CONNECTION_CLOSE
       сервера доказывает, что он жив; разбор и сокет — наша сторона. Обрыв —
       только тишина, доказанная PING (d2k_qstall). При воспроизведении по
       бюджету полный ответ сам по себе успехом не считается: успех — только
       бюджет, пройденный при живом сервере. */
    d.verdict = d2k_quic_arm_data_judge3(1, status, bytes, repeat ? 0 : complete, stalled,
                                         repeat ? 1 : need_complete, head_full, budget);
    d.oneway = oneway;
    /* «Сервер жив» вправе утверждать только подтверждение НАШЕГО пакета.
       Прежде этот текст печатался всегда, когда сокет не закрылся, и при
       заглушённом исходящем направлении уверял, что сервер отвечает на PING,
       которого он не получал. */
    /* Массив, а не указатель: причина целиком не влезает в reason, и
       неограниченный «%s» прячет от компилятора вопрос «а хвост уцелеет?» —
       mipsel-gcc ловит это как -Werror=format-truncation, и правильно ловит
       (ловушка 9193228: кириллица по два байта съедала САМ вердикт). */
    int ack_seen = d2k_qc_outbound(c, NULL, NULL);
    char alive[64];
    snprintf(alive, sizeof alive, "%s", closed ? "закрыл связь"
                                      : ack_seen ? "жив, наши пакеты доходят"
                                                 : "наши пакеты до него не доходят");
    if (repeat && req_failed) {
        d.verdict = D2K_QAD_NOT_RUN;
        snprintf(d.reason, sizeof d.reason,
                 "%u-й запрос HTTP/3 не ушёл (связь перенесла %llu датаграмм из нужных %u): %.80s"
                 " — не измерено", requests + 1, (unsigned long long)pk, need, err);
    } else if (repeat && d.verdict == D2K_QAD_PASS) {
        snprintf(d.reason, sizeof d.reason,
                 "HTTP %d, %u запрос(ов) на новых потоках: %llu из %u датаграмм (2×%u), "
                 "сервер ответил на каждый",
                 status, requests, (unsigned long long)pk, need, need / 2);
    } else if (repeat && d.verdict == D2K_QAD_CUT && status > 0 && status != 451) {
        snprintf(d.reason, sizeof d.reason,
                 "HTTP %d, встал %u-й запрос: %llu из %u датаграмм (2×%u), %llu байт",
                 status, requests, (unsigned long long)pk, need, need / 2,
                 (unsigned long long)(done_bytes + bytes));
    } else if (repeat && d.verdict == D2K_QAD_NOT_RUN && !head_full) {
        snprintf(d.reason, sizeof d.reason,
                 "сервер %s, но %u-й запрос за %lld мс не довёл связь до %u датаграмм (%llu, HTTP %d)"
                 " — не обрыв, не измерено%s%.60s", alive,
                 requests, (long long)limit, need, (unsigned long long)pk, status,
                 closed ? ": " : "", closed ? err : "");
    } else if (d.verdict == D2K_QAD_NOT_RUN && head_full && status <= 0) {
        snprintf(d.reason, sizeof d.reason,
                 "заголовки ответа HTTP/3 длиннее %d байт — наш предел, не обрыв линии",
                 D2K_VERIFY_HEADER_LIMIT);
    } else if (d.verdict == D2K_QAD_NOT_RUN) {
        snprintf(d.reason, sizeof d.reason,
                 "сервер %s, но ответ за %lld мс не %s (HTTP %d, %llu байт) — "
                 "не обрыв, не измерено", alive, (long long)limit,
                 need_complete ? "пришёл целиком" : "донёс порог", status,
                 (unsigned long long)bytes);
    } else if (d.verdict == D2K_QAD_PASS) {
        snprintf(d.reason, sizeof d.reason, "рукопожатие, HTTP %d и %llu байт данных%s",
                 status, (unsigned long long)bytes, complete ? ", ответ целиком" :
                 budget ? ", поток прошёл бюджет коробки (2×25 пакетов), сервер ещё шлёт" : "");
    } else if (!status || status == 451) {
        snprintf(d.reason, sizeof d.reason, "рукопожатие есть, %s (%llu байт)%s%.80s",
                 status ? "HTTP 451 — отказ, не успех" : "заголовков ответа HTTP/3 нет",
                 (unsigned long long)bytes, closed ? ": " : "", closed ? err : "");
    } else {
        snprintf(d.reason, sizeof d.reason, "рукопожатие есть, поток оборван на %llu байт%s%.80s",
                 (unsigned long long)bytes, closed ? ": " : "", closed ? err : "");
    }
    if (d.verdict == D2K_QAD_CUT && stalled) {
        size_t rl = strlen(d.reason);
        if (oneway) {
            /* ИЗМЕРЕНО НАПРАВЛЕНИЕ: наше исходящее заглушено. Ответ на такой
               обрыв — свежая четвёрка или безобидная датаграмма впереди, а не
               другая форма приветствия. */
            snprintf(d.reason + rl, sizeof d.reason - rl,
                     "; наши пакеты до сервера не доходят: он шлёт (%llu байт на проводе), "
                     "а два PING не подтвердил (RTO %lld мс)",
                     (unsigned long long)st.wire_seen, (long long)st.rto_ms);
        } else {
            snprintf(d.reason + rl, sizeof d.reason - rl,
                     "; сервер молчит: два PING без ответа (RTO %lld мс)", (long long)st.rto_ms);
        }
    }
    *out = d;
}


static d2k_tally quic_ask(const char *addr, uint16_t port,
                           const uint8_t *prefix, size_t prefix_len,
                           d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                           int repeats, uint32_t *rtt_ms_out, int *refused_out, int *sent_out,
                           uint8_t *ttl_in_out) {
    return quic_ask_ex(addr, port, prefix, prefix_len, 0, 1, 0, NULL, msg, wait_ms, mark,
                        repeats, rtt_ms_out, refused_out, sent_out, ttl_in_out, qp_verify_aead, NULL,NULL,0);
}

/* Живость через согласование версии — та же дисциплина ПОВТОРОВ, метки и
   параллельной отправки, что и у обычных вопросов (см. большой комментарий
   у qp_build_vn_trigger выше, находка C ревью), только проверщик другой
   (структурный, не AEAD), RTT не нужен (rtt_ms_out=NULL), и ПОРОГ ПРИЁМА
   ДРУГОЙ: вызывающий (d2k_quic_classify) принимает ЛЮБОЙ vn.pass > 0 как
   доказательство "путь жив" — не единогласие 3/3 (правка ревью 2026-09-06,
   круг 4, находка 1). Это решение вызывающего, не этой функции: quic_ask_ex
   лишь считает "сколько из скольких", порог — на стороне того, кто читает
   d2k_tally. Не через d2k_quic_ask_hook: разветвлять ПОДМЕНЯЕМЫЙ в тестах
   оракул на два независимых протокола ответа ради одного вызывающего было
   бы преждевременным обобщением шва, который и так существует только
   из-за ограничения тестовой платформы (см. d2k_quicprobe.h у
   d2k_quic_ask_hook); тестируется отдельно, настоящими сокетами на
   127.0.0.1 — адресная ротация этому зонду не нужна, он до неё не доходит. */
static d2k_tally qp_ask_vn(const char *addr, uint16_t port, uint32_t wait_ms, uint32_t mark,
                            int *sent_out) {
    /* Датаграмму собирает quic_ask_ex — свою на каждую попытку (см.
       qp_build_vn_trigger); общего снимка у этого вопроса нет. */
    d2k_hello msg = {NULL, 0, NULL, 0, 0, 0};
    return quic_ask_ex(addr, port, NULL, 0, 0, 1, 0, NULL, msg, wait_ms, mark,
                        D2K_QUIC_REPEATS, NULL, NULL, sent_out, NULL, qp_verify_vn, NULL,NULL,0);
}

/* Задача 6: как quic_ask (умолчание d2k_quic_ask_hook), но с TTL приманки —
   см. doc-комментарий d2k_quic_ask_ttl_fn в d2k_quicprobe.h. rtt/refused не
   нужны вызывающим этот крючок: RTT берётся из уже пройденного
   d2k_quic_classify, а refused — различие, нужное только базовой живости
   дерева вопросов. */
static d2k_tally quic_ask_ttl(const char *addr, uint16_t port, const uint8_t *prefix, size_t prefix_len,
                               int prefix_ttl, d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                               int repeats, int *sent_out) {
    return quic_ask_ex(addr, port, prefix, prefix_len, prefix_ttl, 1, 0, NULL, msg, wait_ms,
                        mark, repeats, NULL, NULL, sent_out, NULL, qp_verify_aead, NULL,NULL,0);
}
d2k_quic_ask_ttl_fn d2k_quic_ask_ttl_hook = quic_ask_ttl;

/* ЧИСЛО КОПИЙ ПРИМАНКИ — отдельная ось поиска, как у донора.
   Донор пробует 6 и 11 копий (arms.go:140) ОТДЕЛЬНО от выбора блоба: одна
   копия могла потеряться, а могла и не хватить коробке. Замер это и
   показывает — instagram берётся только одиннадцатью копиями quic5, а
   одиночные копии всех четырёх блобов дают 0/3
   (docs/field/2026-09-12-donor-reference.md).
   Отдельным хуком, а не расширением d2k_quic_ask_fn, по той же причине, что
   и TTL: публичный контракт уже прошёл ревью, и тащить через всё дерево
   параметр, нужный одному вызывающему, незачем. */
static d2k_tally quic_ask_copies(const char *addr, uint16_t port,
                                  const uint8_t *prefix, size_t prefix_len,
                                  int copies, d2k_hello msg, uint32_t wait_ms,
                                  uint32_t mark, int repeats, int *sent_out) {
    return quic_ask_ex(addr, port, prefix, prefix_len, 0, copies, 0, NULL, msg, wait_ms, mark,
                        repeats, NULL, NULL, sent_out, NULL, qp_verify_aead, NULL,NULL,0);
}
d2k_quic_ask_copies_fn d2k_quic_ask_copies_hook = quic_ask_copies;

/* Вопрос 7: исходный порт НИЖЕ порта назначения. Отдельным хуком, а не
   расширением d2k_quic_ask_fn, по той же причине, что TTL и копии: контракт
   дерева уже прошёл ревью, а параметр нужен одному вопросу. */
static d2k_tally quic_ask_srcport(const char *addr, uint16_t port, int src_port,
                                   d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                                   int repeats, int *sent_out) {
    return quic_ask_ex(addr, port, NULL, 0, 0, 1, src_port, NULL, msg, wait_ms, mark,
                        repeats, NULL, NULL, sent_out, NULL, qp_verify_aead, NULL,NULL,0);
}
d2k_quic_ask_srcport_fn d2k_quic_ask_srcport_hook = quic_ask_srcport;

/* Вопрос 4: приветствие ДВУМЯ датаграммами, хвост первым. Берёт СНИМОК и имя,
   а не готовый пакет: пара собирается заново на каждую попытку (общий DCID у
   половин, свежий у каждой попытки — см. quic_ask_ex). */
static d2k_tally quic_ask_split(const char *addr, uint16_t port, d2k_hello snap,
                                 const char *sni, uint32_t wait_ms, uint32_t mark,
                                 int repeats, int *sent_out) {
    return quic_ask_ex(addr, port, NULL, 0, 0, 1, 0, sni, snap, wait_ms, mark,
                        repeats, NULL, NULL, sent_out, NULL, qp_verify_aead, NULL,NULL,0);
}
d2k_quic_ask_split_fn d2k_quic_ask_split_hook = quic_ask_split;

/* Реальный оракул — умолчание d2k_quic_ask_hook (см. d2k_quicprobe.h про то,
   зачем этот хук вообще существует). Дерево ниже зовёт ИСКЛЮЧИТЕЛЬНО хук, не
   quic_ask напрямую — иначе подмена в тесте не достала бы до дерева.
   qp_ask_vn хук не проходит вовсе (см. её же комментарий) — вызывается из
   d2k_quic_classify напрямую. */
int d2k_quic_allow_local;

static d2k_tally quic_ask_longer(const char *addr,uint16_t port,const uint8_t *prefix,
    size_t prefix_len,d2k_hello msg,uint32_t wait,uint32_t mark,int repeats,
    uint32_t *rtt,int *refused,int *sent,uint8_t *ttl){
    (void)prefix;(void)prefix_len;
    return quic_ask_core(addr,port,NULL,0,0,1,0,NULL,msg,wait,mark,repeats,
        rtt,refused,sent,ttl,qp_verify_aead,NULL,NULL,0,0,100);
}
static d2k_tally quic_ask_frames(const char *addr,uint16_t port,const uint8_t *prefix,
    size_t prefix_len,d2k_hello msg,uint32_t wait,uint32_t mark,int repeats,
    uint32_t *rtt,int *refused,int *sent,uint8_t *ttl){
    (void)prefix;(void)prefix_len;
    return quic_ask_core(addr,port,NULL,0,0,1,0,NULL,msg,wait,mark,repeats,
        rtt,refused,sent,ttl,qp_verify_aead,NULL,NULL,0,1,0);
}
d2k_quic_ask_fn d2k_quic_ask_frames_hook=quic_ask_frames;
d2k_quic_ask_fn d2k_quic_ask_longer_hook=quic_ask_longer;
d2k_quic_ask_fn d2k_quic_ask_hook = quic_ask;

static d2k_tally quic_ask_control(const char *addr, uint16_t port,
                                  const uint8_t *prefix, size_t prefix_len,
                                  d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                                  int repeats, uint32_t *rtt_ms_out, int *refused_out,
                                  int *sent_out, uint8_t *ttl_in_out) {
    return quic_ask_ex(addr, port, prefix, prefix_len, 0, 1, 0, NULL, msg,
                       wait_ms, mark, repeats, rtt_ms_out, refused_out, sent_out,
                       ttl_in_out, qp_verify_aead, NULL, NULL, 1);
}
d2k_quic_ask_fn d2k_quic_ask_control_hook = quic_ask_control;

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

/* Бюджет одного Run: начало и предел в миллисекундах. Предел уточняется,
   когда базовая живость измерила RTT (до неё — по полу ожидания). */
typedef struct {
    struct timespec start;
    uint32_t limit_ms;
} qp_budget;

/* elapsed <= limit (монотонные часы, целочисленно — §"плавающей арифметики
   нет"). */
static int budget_left(const qp_budget *b) {
    /* Бюджет 0 — это НОЛЬ, а не "проверить и посмотреть": он обязан
       значить "исчерпан всегда", а не зависеть от разрешения часов — иначе
       на очень быстром (мок) пути now успевает совпасть со start вплоть до
       наносекунды, и результат становится гонкой (найдено повторным
       прогоном `sh scripts/check.sh` при разработке задачи 5, круг 1).
       Явный случай снимает гонку совсем. */
    if (b->limit_ms == 0) {
        return 0;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t elapsed_ms = (int64_t)(now.tv_sec - b->start.tv_sec) * 1000 +
                         (now.tv_nsec - b->start.tv_nsec) / 1000000L;
    return elapsed_ms <= (int64_t)b->limit_ms;
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

/* ШАГ 4: ВОПРОСНИК ПРО УСТРОЙСТВО КОРОБКИ.
 *
 * Семь вопросов оригинала (internal/quicprobe/questions.go), по одному, В ТОМ
 * ЖЕ ПОРЯДКЕ: он там не случаен — сперва дешёвое и уже бравшее живые коробки.
 * Прежняя редакция задавала из них ровно один (мусор перед Initial) и
 * называла его «плечом»; имя было точным, пока вопрос был один, и стало
 * враньём, как только их стало семь — исполнимо здесь ровно одно, остальные
 * шесть коробку ЛОМАЮТ, но исполнить их движку сегодня нечем, и это самый
 * ценный выход замера, а не повод его прятать.
 *
 * ВОСЬМОЙ ВОПРОС ОРИГИНАЛА (фальшивый Initial с разрешённым именем перед
 * своим) здесь НЕ задаётся и остаётся «не измерено»: он живёт в задаче 6
 * (props.c, D2K_QA_BLOB) вместе с числом копий и развёрткой TTL, и задать его
 * дважды значило бы потратить бюджет на то, что уже меряется подробнее.
 *
 * Общий хвост для ОБЕИХ веток, которыми дерево приходит к D2K_V_OPAQUE.
 * residual_detected — см. qp_pinned_or_next. */
typedef enum {
    QK_JUNK = 0,  /* мусорная датаграмма перед снимком */
    QK_RESHAPE,   /* снимок пересобран иначе (d2k_quic_hello_ask) */
    QK_SPLIT,     /* снимок уехал двумя датаграммами */
    QK_SRCPORT    /* снимок как есть, но с низкого исходного порта */
} qp_kind;

typedef struct {
    const char  *label;  /* как назвать в причине — коротко: 384 байта на весь вердикт */
    qp_kind      kind;
    d2k_quic_ask ask;    /* для QK_RESHAPE */
    size_t       slot;   /* поле d2k_quic_props, куда ложится исход */
} qp_question;

static const qp_question qp_list[] = {
    { "мусор",      QK_JUNK,    D2K_QASK_PLAIN,           offsetof(d2k_quic_props, junk_ahead) },
    { "кадры",      QK_RESHAPE, D2K_QASK_SPLIT_CRYPTO,    offsetof(d2k_quic_props, split_crypto) },
    { "датаграммы", QK_SPLIT,   D2K_QASK_PLAIN,           offsetof(d2k_quic_props, split_datagrams) },
    /* «ВЕРСИЯ2» БОЛЬШЕ НЕ ЗАДАЁТСЯ (задача 57, поле 14.10.2026, spike/quicv2.c).
       Ответ не давал ничего: Cloudflare Initial второй версии молча
       отбрасывает (на смазочную версию отвечает Version Negotiation), так что
       на его адресах «0/3» — сервер, а не коробка; коробка линии режет QUIC
       по имени во всех версиях (fost.club на адрес Google: v1, v2, смазка —
       0/3, www.google.com туда же — v2 3/3); а движок версию на живом пакете
       переписать не может — она в связанных данных AEAD. Три зонда в каждом
       проваленном поиске ради справки. Поле version2 остаётся неизмеренным. */
    { "бит",        QK_RESHAPE, D2K_QASK_CLEAR_FIXED_BIT, offsetof(d2k_quic_props, clear_fixed_bit) },
    { "низкийпорт", QK_SRCPORT, D2K_QASK_PLAIN,           offsetof(d2k_quic_props, low_source_port) },
    { "длина",      QK_RESHAPE, D2K_QASK_LONGER,          offsetof(d2k_quic_props, longer) }
};
#define QP_N_QUESTIONS (sizeof qp_list / sizeof qp_list[0])

/* ОПРОСЫ ХУДШЕГО ПУТИ RUN после базовой живости, каждый ждёт dyn_wait:
   прямой зонд и повторный контроль (probe.go:322-355), вопросы стратегии с
   одним повтором каждый (D2K_QUIC_STRATEGY_ASKS_MAX, задача 40), вся
   лестница askArms (D2K_QUIC_ARM_QUESTIONS_MAX) и все вопросы таблицы выше.
   Верхняя граница учитывает все повторяемые вопросы стратегии. Из этого
   числа — и только из него — выводится
   бюджет. */
#define QP_RUN_DYN_POLLS (2u + D2K_QUIC_STRATEGY_ASKS_MAX + D2K_QUIC_ARM_QUESTIONS_MAX + \
                          (unsigned)QP_N_QUESTIONS)

/* deriveTimeout донора (probe.go:404-418): 3×RTT в [пол; потолок]. */
static uint32_t qp_dyn_wait(uint32_t rtt_ms) {
    uint32_t w = rtt_ms > D2K_QUIC_RTT_WAIT_CEIL_MS ? D2K_QUIC_RTT_WAIT_CEIL_MS : rtt_ms * 3u;
    if (w < D2K_QUIC_RTT_WAIT_FLOOR_MS) w = D2K_QUIC_RTT_WAIT_FLOOR_MS;
    if (w > D2K_QUIC_RTT_WAIT_CEIL_MS) w = D2K_QUIC_RTT_WAIT_CEIL_MS;
    return w;
}

uint32_t d2k_quic_budget_ms(uint32_t rtt_ms) {
    if (d2k_quic_budget_s != D2K_QUIC_BUDGET_DERIVED) {
        return d2k_quic_budget_s > UINT32_MAX / 1000u ? UINT32_MAX : d2k_quic_budget_s * 1000u;
    }
    /* Паузы между опытами (D2K_QUIC_GAP_US) и местная работа — по паузе на
       опрос: это не запас «на всякий случай», а явная цена шагов, которые
       тоже идут по часам бюджета. */
    uint32_t per_poll = qp_dyn_wait(rtt_ms) + D2K_QUIC_GAP_US / 1000u;
    return d2k_quic_wait_ms + QP_RUN_DYN_POLLS * per_poll;
}

/* Исход одного вопроса -> значение свойства. ЕДИНОГЛАСИЕ ИЛИ НИЧЕГО (см.
   d2k_quic_props): разошедшиеся повторы — это «не измерено», а не «не
   помогает». Сбой отправки (err) — тоже: он про нашу сторону, не про
   коробку. */
static int8_t qp_outcome(d2k_tally t) {
    if (t.err > 0 || (t.pass > 0 && t.pass < D2K_QUIC_REPEATS)) {
        return D2K_PROP_UNKNOWN;
    }
    return (t.pass == D2K_QUIC_REPEATS) ? D2K_PROP_YES : D2K_PROP_NO;
}

static void qp_questions_step(d2k_vres *r, const char pool[][D2K_QUIC_ADDR_LEN], size_t n_pool,
                               size_t *next_addr, int residual_detected, uint16_t port,
                               const char *sni, d2k_hello trigger,
                               uint32_t wait_ms, uint32_t mark, int *all_marked,
                               const qp_budget *start, int junk_asked, int frames_asked, int longer_asked) {
    /* Ровно 16 нулей — тот же мусор, что и у оригинала (questions.go:97), и
       ровно те байты, которые потом уйдут в строке стратегии
       (blob=0x000...0): слать случайное, а рекомендовать нули значило бы
       мерить одно, а применять другое. */
    static const uint8_t garbage16[16];

    char took[192];
    size_t tn = 0;
    int n_budget = 0, n_addr = 0, n_unbuilt = 0, n_strategy = 0;
    uint8_t shaped[D2K_QW_MAX_DGRAM], scratch[D2K_QW_MAX_DGRAM];

    for (size_t qi = 0; qi < QP_N_QUESTIONS; qi++) {
        const qp_question *q = &qp_list[qi];
        int8_t *slot = (int8_t *)&r->qprops + q->slot;

        /* УЖЕ ОТВЕЧЕНО СТРАТЕГИЕЙ (задача 40): «мусор» — тот же вопрос, что
           остаточное разрешение, «кадры» — тот же, что разрез CRYPTO.
           Повтор исхода не изменит. Исход остаётся в свойстве и в трассе. */
        /* Заданный стратегией вопрос не задаётся снова ни при каком исходе —
           и при «ответа нет» после повтора (круг 1): лишний зонд исхода не
           изменит. */
        if ((q->slot == offsetof(d2k_quic_props, junk_ahead) &&
             (junk_asked || *slot != D2K_PROP_UNKNOWN)) ||
            (q->slot == offsetof(d2k_quic_props, split_crypto) &&
             (frames_asked || *slot != D2K_PROP_UNKNOWN)) ||
            (q->slot == offsetof(d2k_quic_props, longer) && longer_asked)) {
            if (qi < D2K_QTRACE_MAX) {
                d2k_quic_step *st = &r->qtrace[qi];
                snprintf(st->label, sizeof st->label, "%s (стратегия)", q->label);
                st->sent = 0;
                st->answered = 0;
                st->outcome = *slot;
            }
            n_strategy++;
            if (*slot == D2K_PROP_YES && tn + strlen(q->label) + 2 < sizeof took) {
                if (tn) { took[tn++] = ','; }
                memcpy(took + tn, q->label, strlen(q->label));
                tn += strlen(q->label);
            }
            continue;
        }
        if (!budget_left(start)) {
            n_budget++;
            continue;
        }

        /* СНАЧАЛА СОБРАТЬ, ПОТОМ СПРАШИВАТЬ. Несобравшийся зонд — не
           измерение (оригинал: NotBuilt), и отправлять вместо него снимок
           как есть значило бы измерить другой вопрос под этим именем.
           Проверка идёт ДО взятия адреса: незаданный вопрос не имеет права
           тратить свежую тройку. */
        d2k_hello msg = trigger;
        size_t slen = 0;
        int src_port = 0;
        const char *label = q->label;
        if (q->kind == QK_RESHAPE) {
            int built = trigger.bytes &&
                d2k_quic_hello_ask(trigger.bytes, trigger.len,
                    (q->ask==D2K_QASK_LONGER || q->ask==D2K_QASK_SPLIT_CRYPTO)?D2K_QASK_PLAIN:q->ask,sni,
                    shaped,sizeof shaped,&slen)==0;
            if (!built) {
                n_unbuilt++;
                continue;
            }
            msg.bytes = shaped;
            msg.len = slen;
        } else if (q->kind == QK_SPLIT) {
            size_t tlen = 0;
            if (!trigger.bytes ||
                d2k_quic_hello_split(trigger.bytes, trigger.len, sni,
                                     shaped, sizeof shaped, &slen,
                                     scratch, sizeof scratch, &tlen) != 0) {
                n_unbuilt++;
                continue;
            }
            /* Пара собирается заново внутри оракула, на каждую попытку: здесь
               она построена только чтобы убедиться, что вопрос ВЫРАЗИМ. */
        } else if (q->kind == QK_SRCPORT) {
            /* Порт ниже порта назначения, свой на каждую попытку (оракул
               вычитает номер попытки). Ниже 1024 bind требует прав — тогда
               попытка не отправится и вопрос останется «не измерено»; это
               честнее, чем взять порт повыше и назвать его «низким». */
            if (port <= (uint16_t)D2K_QUIC_REPEATS) {
                n_unbuilt++;
                continue;
            }
            src_port = (int)port - 1;
        }

        const char *addr = qp_pinned_or_next(pool, n_pool, next_addr, residual_detected);
        if (!addr) {
            n_addr++;
            continue;
        }

        int sent = 0;
        d2k_tally t;
        if (q->kind == QK_SPLIT) {
            t = d2k_quic_ask_split_hook(addr, port, trigger, sni, wait_ms, mark,
                                        D2K_QUIC_REPEATS, &sent);
        } else if (q->kind == QK_SRCPORT) {
            t = d2k_quic_ask_srcport_hook(addr, port, src_port, msg, wait_ms, mark,
                                          D2K_QUIC_REPEATS, &sent);
        } else {
            const uint8_t *pre = (q->kind == QK_JUNK) ? garbage16 : NULL;
            size_t pre_len = (q->kind == QK_JUNK) ? sizeof garbage16 : 0;
            d2k_quic_ask_fn oracle=q->kind==QK_RESHAPE && q->ask==D2K_QASK_LONGER?
                d2k_quic_ask_longer_hook:q->kind==QK_RESHAPE && q->ask==D2K_QASK_SPLIT_CRYPTO?
                d2k_quic_ask_frames_hook:d2k_quic_ask_hook;
            t = oracle(addr, port, pre, pre_len, msg, wait_ms, mark,
                                  D2K_QUIC_REPEATS, NULL, NULL, &sent, NULL);
        }
        r->probes += sent; /* сколько реально ушло на провод, не pass+fail */
        qp_progress(label, sent);
        if (!t.marked) {
            *all_marked = 0;
        }
        *slot = qp_outcome(t);
        if (q->ask == D2K_QASK_LONGER && q->kind == QK_RESHAPE) {
            r->qprops.longer_profile = (label != q->label) ? 1 : 0;
        }
        if (qi < D2K_QTRACE_MAX) {
            d2k_quic_step *st = &r->qtrace[qi];
            snprintf(st->label, sizeof st->label, "%s", label);
            st->sent = (uint8_t)(sent < 0 ? 0 : sent);
            st->answered = (uint8_t)t.pass;
            st->outcome = *slot;
        }
        if (*slot == D2K_PROP_YES && tn + strlen(label) + 2 < sizeof took) {
            if (tn) { took[tn++] = ','; }
            memcpy(took + tn, label, strlen(label));
            tn += strlen(label);
        }
    }
    took[tn] = '\0';

    if (tn) {
        reason_append(r, "; вопросы(%d): взяли %s", (int)QP_N_QUESTIONS, took);
    } else {
        reason_append(r, "; вопросы(%d): не взял ни один", (int)QP_N_QUESTIONS);
    }
    if (n_strategy) { reason_append(r, "; %d отвечено стратегией", n_strategy); }
    if (n_budget) { reason_append(r, "; не задано %d (бюджет)", n_budget); }
    if (n_addr) { reason_append(r, "; не задано %d (адреса)", n_addr); }
    if (n_unbuilt) { reason_append(r, "; не задано %d (не собралось)", n_unbuilt); }

}

/* Находки — см. контракт в d2k_quicprobe.h. Тексты перенесены из оригинала
   (questions.go, поле finding) дословно по смыслу: они не описание приёма, а
   ответ на вопрос «и что мне с этим делать», и именно эта половина обычно
   теряется при переносе. */
int d2k_quic_props_findings(const d2k_quic_props *p, char *out, size_t cap) {
    if (!out || cap == 0) { return 0; }
    out[0] = '\0';
    if (!p) { return 0; }

    static const struct { size_t slot; const char *text; } texts[] = {
        { offsetof(d2k_quic_props, split_crypto),
          "приветствие, разложенное на два кадра CRYPTO, проходит — коробка их не пересобирает. "
          "Исполнимо (задача 40): план quicsplit — датапат перекладывает кадры CRYPTO в Initial "
          "клиента; ставится ответом вопроса стратегии с этапом данных." },
        { offsetof(d2k_quic_props, split_datagrams),
          "приветствие, разложенное на две датаграммы, проходит — коробка их не собирает. "
          "Движок так не умеет: второму пакету нужен свой номер, а следующий номер принадлежит "
          "клиенту — сервер отбросил бы его настоящий пакет как повтор." },
        { offsetof(d2k_quic_props, version2),
          "Initial второй версии проходит — коробка знает только первую. На живом пакете версию "
          "не переписать: она входит в связанные данные AEAD, и правка ломает рукопожатие самого "
          "пользователя. Движок так не умеет; это довод для клиента, не для движка." },
        { offsetof(d2k_quic_props, clear_fixed_bit),
          "с погашенным фиксированным битом Initial проходит. Сервер обязан такой пакет принять "
          "только если сам объявил grease_quic_bit, поэтому приём ненадёжен, а движок его не умеет." },
        { offsetof(d2k_quic_props, low_source_port),
          "с исходным портом ниже порта назначения Initial проходит — коробка так экономит на "
          "разборе. Десинком это не выражается и движок так не умеет: нужен SNAT исходного порта, "
          "отдельное правило фаервола." },
        /* Мусор перед Initial и удлинённая датаграмма ИСПОЛНИМЫ — их
           подхватывает подбор плеча (задача 6), и повторять их здесь значило
           бы называть находкой то, что уже стало плечом. */
        { offsetof(d2k_quic_props, fake_ahead),
          "фальшивый Initial с разрешённым именем перед своим проходит — коробка считает поток "
          "разрешённым. Это исполнимо: ровно то же делает приманка движка." }
    };

    int found = 0;
    size_t used = 0;
    for (size_t i = 0; i < sizeof texts / sizeof texts[0]; i++) {
        if (*((const int8_t *)p + texts[i].slot) != D2K_PROP_YES) {
            continue;
        }
        found++;
        if (used + 1 < cap) {
            int n = snprintf(out + used, cap - used, "%s%s", used ? "\n" : "", texts[i].text);
            if (n < 0) { break; }
            used += (size_t)n;
            if (used >= cap) { used = cap - 1; break; }
        }
    }
    out[(used < cap) ? used : cap - 1] = '\0';
    return found;
}

static int arm_budget_left(void *budget) { return budget_left(budget); }
/* The arm data stage belongs to an already asked question (task 39): the Run
   budget grows by its measured time instead of starving later questions. */
static void arm_budget_spent(void *budget, uint32_t ms) {
    qp_budget *b = budget;
    b->limit_ms = UINT32_MAX - b->limit_ms < ms ? UINT32_MAX : b->limit_ms + ms;
}

/* base_only — только базовый вопрос (шаги 0 и 1: контроль живости и прямой
   зонд), задача 32; seed — исход этих двух шагов, уже снятый этим же входом:
   прогон берёт его вместо повторного опроса. */
static d2k_vres classify_run(const char *ip, uint16_t port, const char *sni,
                            d2k_hello trigger, d2k_hello control, uint32_t mark,
                            d2k_quic_arm *arm, int base_only, const d2k_base_seed *seed) {
    d2k_vres r;
    memset(&r, 0, sizeof r);
    char arm_path[sizeof ((d2k_quic_arm *)0)->probe_path] = "";
    int arm_split_unfit = 0, data_cut = 0;
    unsigned arm_budget = 0;
    if(arm) {
        arm_split_unfit = arm->split_unfit != 0;
        data_cut = arm->data_cut;
        arm_budget = arm->budget_pk;
        /* Input only when the caller filled it: a terminated, public resource
           path (d2k_resource_path_ok). Anything else -- including an
           uninitialised arm -- means "/". */
        if(memchr(arm->probe_path,0,sizeof arm->probe_path) &&
           d2k_resource_path_ok(arm->probe_path))
            memcpy(arm_path,arm->probe_path,strlen(arm->probe_path)+1);
        memset(arm,0,sizeof *arm); arm->kind=D2K_QA_NOT_FOUND;
        memcpy(arm->probe_path,arm_path,sizeof arm_path);
        arm->split_unfit = arm_split_unfit;
        arm->data_cut = data_cut;
        arm->budget_pk = arm_budget;
    }

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
        uint8_t ip_probe[16];
        ip_ok = qp_addr_parse(ip, ip_probe) != 0;
    }
    if (!ip_ok || !sni || !trigger.bytes || trigger.len == 0) {
        r.verdict = D2K_V_FLAKY;
        reason_set(&r, "вход структурно непригоден: адрес не разбирается как IP, имя или снимок "
                       "триггера отсутствуют — измерения не было");
        return r; /* r.marked=0 по построению — ни один опыт не задавался; единственный ранний
                     выход, как и у эталона (verdict.c) — это отказ ДО измерения, не его исход */
    }

    /* АДРЕС, ДО КОТОРОГО ПРОВАЙДЕРСКАЯ КОРОБКА ФИЗИЧЕСКИ НЕ УЧАСТВУЕТ.
     *
     * Имя, разрешённое в приватный диапазон, — это подмена на уровне DNS:
     * роутер, AdGuard или наш собственный редирект по хостлисту. Датаграммы
     * до провайдера не доходят вовсе, и любой вердикт про коробку тут был бы
     * выдумкой. Донор (probe.go, isLocal) относит сюда петлю, RFC 1918,
     * link-local, нулевой адрес и 100.64/10: последний приватным в смысле
     * 1918 не считается, но за ним точно так же стоит чужой NAT.
     *
     * Замер донора 04.09 на этой же линии: rutracker.org локально даёт
     * 10.171.171.171, тогда как 8.8.8.8 отдаёт 188.186.154.79. Без этой
     * проверки инструмент объявил бы «режут адрес» и был бы неправ полностью. */
    if (!d2k_quic_allow_local) {
        uint8_t ip6[16];
        if (inet_pton(AF_INET6, ip, ip6) == 1 && d2k_ip6_private(ip6)) {
            r.verdict = D2K_V_LOCAL_ADDRESS;
            reason_set(&r, "адрес %s локальный или не является публичной целью — "
                           "измерения блокировки провайдера не было", ip);
            return r;
        }
        struct in_addr a;
        if (inet_pton(AF_INET, ip, &a) == 1) {
            /* Список диапазонов — ОДИН на проект (d2k_net4.h): тот же вопрос
               задаёт голосовой путь, и второй экземпляр списка разошёлся бы с
               этим молча — обе копии продолжали бы «работать», просто считая
               разное. */
            if (d2k_ip4_private(a.s_addr)) {
                r.verdict = D2K_V_LOCAL_ADDRESS;
                reason_set(&r, "имя разрешается в адрес %s из приватного диапазона — это подмена "
                               "на уровне DNS (роутер, AdGuard или свой редирект по хостлисту), "
                               "а не блокировка провайдера", ip);
                return r;
            }
        }
    }

    /* До базовой живости RTT не измерен: предел — по полу ожидания; после
       неё уточняется измеренным RTT (d2k_quic_budget_ms). */
    qp_budget start;
    clock_gettime(CLOCK_MONOTONIC, &start.start);
    start.limit_ms = d2k_quic_budget_ms(0);

    /* Пул адресов: ip — первый и гарантированный (это ровно тот адрес, для
       которого нас позвали), остальное — из резолвера, с отбросом дублей
       (иначе "свежий" адрес мог бы совпасть с уже использованным, и ротация
       была бы фиктивной). Сама сборка — d2k_quic_build_pool. */
    char pool[D2K_QUIC_MAX_ADDRS][D2K_QUIC_ADDR_LEN];
    size_t n_pool = d2k_quic_build_pool(ip, sni, pool, D2K_QUIC_MAX_ADDRS);
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
        uint8_t ttl_in = 0;
        int refused = 0;
        int base_sent = 0;
        int seeded = seed && seed->valid && seed->repeats == D2K_QUIC_REPEATS;
        d2k_tally base_ctl;
        if (seeded) {
            memset(&base_ctl, 0, sizeof base_ctl);
            base_ctl.pass = seed->ctl_pass; base_ctl.fail = seed->ctl_fail;
            base_ctl.err = seed->ctl_err; base_ctl.marked = seed->ctl_marked;
            rtt_ms = seed->rtt_ms; refused = seed->ctl_refused; ttl_in = seed->ttl_in;
        } else {
            base_ctl = d2k_quic_ask_control_hook(pool[0], port, NULL, 0, control, d2k_quic_wait_ms,
                                                 mark, D2K_QUIC_REPEATS, &rtt_ms, &refused, &base_sent, &ttl_in);
        }
        if (base_only) {
            r.base.valid = 1; r.base.repeats = D2K_QUIC_REPEATS;
            r.base.ctl_pass = base_ctl.pass; r.base.ctl_fail = base_ctl.fail;
            r.base.ctl_err = base_ctl.err; r.base.ctl_refused = refused;
            r.base.ctl_marked = base_ctl.marked; r.base.rtt_ms = rtt_ms; r.base.ttl_in = ttl_in;
        }
        r.probes += base_sent; /* сколько реально ушло на провод, не pass+fail (находка 4 ревью, круг 5) */
        qp_progress("контроль живости", base_sent);
        if (!base_ctl.marked) {
            all_marked = 0;
        }
        /* СЫРОЙ TTL ОТВЕТА — с ПЕРВОГО же подтверждённого пакета, то есть с
           контроля базовой живости: дальше зонды пойдут на другие адреса, и
           TTL смешался бы с маршрутом. Без пересчёта в расстояние — см.
           d2k_quic_props.server_ttl_in. */
        r.qprops.server_ttl_in = ttl_in;
        if (base_only && base_ctl.pass == 0) {
            /* Путь не подтверждён живым: блокировка рукопожатия не доказана,
               дальше (согласование версии и прочее) решает полный прогон. */
            r.verdict = D2K_V_INCONCLUSIVE;
            reason_set(&r, "базовый вопрос: контроль молчит (0/%d) — блокировка имени не доказана",
                       D2K_QUIC_REPEATS);
            r.marked = (mark != 0) && all_marked && base_ctl.marked;
            return r;
        }

        /* Run: ЛЮБОЙ ответ контроля позволяет перейти к прямому зонду.
           Refused рассматривается только при pass==0. Локальные сбои
           отправки без единого ответа по-прежнему не считаем молчанием сети. */
        if (base_ctl.pass == 0 && refused > 0) {
            /* probe.go:Run — отсутствие ответов и сетевой отказ дают
               no_quic, не приглашение к новому подбору. Вердикт оригинала
               не локализует источник ICMP: ограничение доказательства
               называем отдельно, не подменяя им исход прибора. */
            r.verdict = D2K_V_NO_QUIC;
            reason_set(&r, "%s отвечает сетевым отказом (%d/%d, ICMP или подобное): "
                           "исход оригинала no_quic. Источник отказа (цель или путь) не локализован",
                       pool[0], refused, D2K_QUIC_REPEATS);
        } else if (base_ctl.pass == 0 && base_ctl.err == D2K_QUIC_REPEATS) {
            /* pass == 0 и refused == 0 здесь по построению (обе ветки выше
               уже исключены) — значит НИ ОДНА из трёх попыток не была даже
               отправлена: сбой socket()/connect()/send() в qp_send_one,
               наша сторона, к сети отношения не имеет. */
            r.verdict = D2K_V_FLAKY;
            reason_set(&r, "не отправилось ни разу (%d/%d) — наша сторона, опыт не состоялся",
                       base_ctl.err, D2K_QUIC_REPEATS);
        } else if (base_ctl.pass == 0 && base_ctl.err > 0) {
            /* pass == 0 и refused == 0 здесь ТОЖЕ по построению (обе ветки
               выше проверены раньше) — значит и здесь err весь целиком "не
               отправилось", наша сторона, не абстрактный "транспорт"
               (мелкая правка ревью 2026-09-06, круг 5: соседняя ветка тремя
               строками выше уже называла это честно, эта — нет). */
            r.verdict = D2K_V_FLAKY;
            reason_set(&r, "базовая живость: %d/%d не отправились — наша сторона", base_ctl.err,
                       D2K_QUIC_REPEATS);
        } else if (base_ctl.pass == 0) {
            /* Тишина без единой ошибки транспорта и без единого сетевого
               отказа (все ветки выше уже исключены) — путь мог быть и жив,
               и мёртв; зонд согласования версии решает, не неся содержимого
               вовсе (см. большой комментарий у qp_build_vn_trigger). Три
               параллельных попытки, метка, учёт в all_marked — та же
               дисциплина ПОВТОРОВ, что и у любого другого вопроса (правка
               ревью 2026-09-06 круг 3, находки A и C), но ПОРОГ ПРИЁМА —
               другой, см. ветку vn.pass > 0 ниже. */
            int vn_sent = 0;
            d2k_tally vn = qp_ask_vn(pool[0], port, d2k_quic_wait_ms, mark, &vn_sent);
            r.probes += vn_sent; /* сколько реально ушло на провод (находка 4 ревью, круг 5) */
            qp_progress("согласование версии", vn_sent);
            if (!vn.marked) {
                all_marked = 0;
            }
            if (vn.err > 0) {
                r.verdict = D2K_V_FLAKY;
                reason_set(&r, "согласование версии: %d/%d не состоялись — транспорт", vn.err,
                           D2K_QUIC_REPEATS);
            } else if (vn.pass > 0) {
                /* ПОРОГ ПРИСУТСТВИЯ, НЕ ЕДИНОГЛАСИЯ (правка ревью
                   2026-09-06, круг 4, находка 1 — ошибка формулировки
                   дispatch круга 3, не моей реализации: единогласие
                   отвечает на вопрос "одинаково ли коробка решает три раза"
                   — вопрос про РЕШЕНИЕ. Зонд согласования версии спрашивает
                   про ФАКТ: жив ли путь. ОДИН пришедший ответ уже доказывает
                   факт; второй и третий ничего к доказательству не
                   добавляют и отнять его не могут. RFC 9000 §6.1: "A server
                   MAY limit the number of packets to which it responds with
                   a Version Negotiation packet"; §21.5.4 объясняет причину
                   — VN является вектором усиления, ограничение отклика
                   штатно, не аномалия сети. Донор (probe.go:308) использует
                   тот же порог: `if vn.Answered == 0`. Неполный ответ здесь
                   НЕ обязательно потеря — это может быть штатный лимит
                   сервера, поэтому текст ниже не утверждает причину
                   недостающих ответов, только факт присутствия. */
                /* Run оригинала здесь завершается. Прямой зонд НЕ
                   отправлялся: нельзя добавлять его ради неверного текста
                   «молчат оба имени». Сохраняем исход и называем факты. */
                r.verdict = D2K_V_NO_QUIC;
                reason_set(&r, "контрольное имя молчит (0/%d), путь жив (согласование "
                               "версии %d/%d): исход оригинала no_quic; наше имя в этой ветке не спрашивалось",
                           D2K_QUIC_REPEATS, vn.pass, D2K_QUIC_REPEATS);
            } else {
                /* vn.pass == 0 и vn.err == 0: опыты СОСТОЯЛИСЬ (отправлены,
                   дождались тайм-аута без единой ошибки) и на контроле, и на
                   согласовании версии — ответа нет ни на один. НАХОДКА 3
                   РЕВЬЮ (круг 4): это тишина, а не "транспорт не случился",
                   и полная тишина на UDP/443 одинаково объясняется мёртвым
                   путём и блокировкой порта/протокола целиком — различить
                   нельзя (§2.3), значит нельзя утверждать "не решение
                   коробки": прежняя формулировка знала ровно то, чего знать
                   нельзя, только с другой стороны, чем запрещает §2.3.
                   Приведено к тому же честному виду, что и у соседнего
                   вывода на шаге 3 ("нельзя отличить содержимое от
                   недоступности сервера"). */
                r.verdict = D2K_V_ADDRESS;
                reason_set(&r, "молчит всё, включая согласование версии (0/%d) — нельзя отличить "
                               "мёртвый путь от блокировки порта/протокола; исход оригинала address, "
                               "подбор десинхронизации по содержимому не запускается",
                           D2K_QUIC_REPEATS);
            }
        } else {
            /* base_ctl.pass > 0: порог контроля оригинала — ЛЮБОЙ ответ.
               Единогласие требуется от прямого зонда, не от контроля. RTT
               измерен — потолок ожидания для всего остального дерева
               выводится из него (см. d2k_quicprobe.h). */
            uint32_t dyn_wait = qp_dyn_wait(rtt_ms);
            start.limit_ms = d2k_quic_budget_ms(rtt_ms);

            /* ===== ШАГ 1: прямой зонд (тот же адрес — живость уже подтверждена) ===== */
            int base_sent2 = 0;
            d2k_tally base;
            if (seeded && seed->direct_asked) {
                memset(&base, 0, sizeof base);
                base.pass = seed->pass; base.fail = seed->fail;
                base.err = seed->direct_err; base.marked = seed->direct_marked;
            } else {
                base = d2k_quic_ask_hook(pool[0], port, NULL, 0, trigger, dyn_wait, mark,
                                         D2K_QUIC_REPEATS, NULL, NULL, &base_sent2, NULL);
            }
            if (base_only) {
                r.probes += base_sent2;
                qp_progress("прямой зонд", base_sent2);
                r.base.direct_asked = 1;
                r.base.pass = base.pass; r.base.fail = base.fail;
                r.base.direct_err = base.err; r.base.direct_marked = base.marked;
                r.base_blocked = base.pass == 0 && base.err == 0;
                r.verdict = base.pass == D2K_QUIC_REPEATS ? D2K_V_CLEAR : D2K_V_INCONCLUSIVE;
                reason_set(&r, r.base_blocked
                           ? "базовый вопрос: контроль отвечает (%d/%d), наш Initial молчит (0/%d)"
                           : "базовый вопрос: контроль %d/%d, наш Initial %d/%d — блокировки рукопожатия нет",
                           base_ctl.pass, D2K_QUIC_REPEATS,
                           r.base_blocked ? D2K_QUIC_REPEATS : base.pass,
                           D2K_QUIC_REPEATS);
                r.marked = (mark != 0) && all_marked && base.marked;
                return r;
            }
            r.probes += base_sent2; /* сколько реально ушло на провод (находка 4 ревью, круг 5) */
            qp_progress("прямой зонд", base_sent2);
            if (!base.marked) {
                all_marked = 0;
            }

            /* err — только «не отправилось» (NotBuilt донора, probe.go:323).
               ICMP-отказ сюда не попадает: он в fail, и молчащий прямой
               зонд ведёт к content (probe.go:322-337). */
            if (base.err > 0) {
                r.verdict = D2K_V_FLAKY;
                reason_set(&r, "прямой зонд: %d/%d не состоялись — транспорт, не коробка", base.err,
                           D2K_QUIC_REPEATS);
            } else if (base.pass == D2K_QUIC_REPEATS ||
                       (base.pass > 0 && all_marked && data_cut && arm)) {
                /* ВОПРОС О ДАННЫХ НЕ СНИМАЕТСЯ ПОТЕРЯННЫМ INITIAL (поле
                   24.10.2026, h3-1024: katzauction.com, rua.gr, enimerosi.com).
                   Подозрение — о молчании ПОСЛЕ рукопожатия; прямой Initial
                   2/3 говорит лишь, что одна датаграмма из трёх потерялась, и
                   прежде на этом поиск кончался FLAKY — «подбор не открыт», а
                   у клиента запрос HTTP/3 оставался без ответа. Этап данных
                   сам ведёт свои соединения до рукопожатия; ему хватает, что
                   рукопожатие проходит хоть раз. Вопрос ТОЛЬКО о рукопожатии
                   остаётся строгим: 2/3 без признака обрыва данных — FLAKY. */
                /* Run завершает прямой успех после исходных repeats.
                   Дополнительные два зонда были перенесены из TCP-дерева,
                   а не из QUIC-оригинала. Изоляция через mark остаётся
                   самостоятельным условием достоверности опыта D2K. */
                if (all_marked && data_cut && arm) {
                    /* Задача 50, раунд 2: рукопожатие проходит, вопрос — в
                       ответе. Своё соединение без воздействия, запрос HTTP/3
                       к тому же ресурсу, что у плеч; правило то же
                       (d2k_quic_arm_data_judge). */
                    /* Раунд 3: ДВА своих запроса на свежих соединениях,
                       оба обязаны встать (молчание транспорта, d2k_qstall);
                       засчитывается только ответ целиком — как и у плеч,
                       с которыми их сравнивают на том же пути. */
                    d2k_quic_arm_question dq;
                    memset(&dq, 0, sizeof dq);
                    dq.addr = pool[0];
                    dq.label = "прямой запрос HTTP/3";
                    dq.need_complete = 1;
                    /* Поле 04.10: короткий ответ кончается внутри бюджета
                       коробки — запросы повторяются на новых потоках до
                       2 × бюджет датаграмм или тишины сервера. */
                    dq.budget_pk = arm_budget ? arm_budget : D2K_QUIC_BOX_BUDGET_PKTS;
                    d2k_quic_arm_data dd = d2k_quic_arm_data_hook(&dq, sni,
                        arm_path[0] ? arm_path : NULL, port, dyn_wait, mark);
                    r.probes += 1;
                    qp_progress("прямой запрос HTTP/3", 1);
                    d2k_quic_arm_data dd2;
                    memset(&dd2, 0, sizeof dd2);
                    if (dd.verdict == D2K_QAD_CUT) {
                        dd2 = d2k_quic_arm_data_hook(&dq, sni,
                            arm_path[0] ? arm_path : NULL, port, dyn_wait, mark);
                        r.probes += 1;
                        qp_progress("прямой запрос HTTP/3, повтор", 1);
                    }
                    if (dd.verdict == D2K_QAD_CUT && dd2.verdict == D2K_QAD_PASS) {
                        r.verdict = D2K_V_FLAKY;
                        reason_set(&r, "Initial проходит (%d/%d), свой запрос HTTP/3 встал один раз "
                                       "из двух (второй: %.100s) — обрыв не воспроизводится",
                                   base.pass, D2K_QUIC_REPEATS, dd2.reason);
                    } else if (dd.verdict == D2K_QAD_CUT && dd2.verdict != D2K_QAD_CUT) {
                        r.verdict = D2K_V_INCONCLUSIVE;
                        reason_set(&r, "Initial проходит (%d/%d), второй свой запрос HTTP/3 не "
                                       "измерен: %.120s", base.pass, D2K_QUIC_REPEATS, dd2.reason);
                    } else if (dd.verdict == D2K_QAD_PASS) {
                        r.verdict = D2K_V_CLEAR;
                        reason_set(&r, "Initial проходит (%d/%d), свои запросы HTTP/3 прошли бюджет "
                                       "коробки (%.150s) — обрыв после рукопожатия не воспроизвёлся",
                                   base.pass, D2K_QUIC_REPEATS, dd.reason);
                    } else if (dd.verdict != D2K_QAD_CUT) {
                        r.verdict = D2K_V_INCONCLUSIVE;
                        reason_set(&r, "Initial проходит (%d/%d), прямой запрос HTTP/3 не "
                                       "состоялся как замер: %.120s", base.pass,
                                   D2K_QUIC_REPEATS, dd.reason);
                    } else {
                        /* Воспроизведено: плечи — этапом данных на том же
                           адресе (остаточной блокировки рукопожатия нет, её
                           вопрос здесь не задаётся). */
                        r.verdict = D2K_V_OPAQUE;
                        /* ЧТО ИМЕННО НАЗНАЧИЛО ОСТАНОВКУ: РАЗМЕР ИЛИ САМ ПОТОК
                           (задача 27).
                           Про ЧЕТВЁРКУ отвечать нечем и не нужно: у каждого
                           опыта этапа данных свой местный порт (см. шапку
                           test_quic_arm_data.c), значит два повтора встали на
                           ДВУХ РАЗНЫХ четвёрках, и остаточное состояние
                           прошлой тут ни при чём — это ответ без нового зонда.
                           Чего два одинаковых повтора сказать не могут —
                           зависит ли остановка от размера ответа. Поэтому
                           задаётся контроль, который ОБЯЗАН дойти: заведомо
                           отсутствующий путь того же имени (короткое тело 404)
                           на свежей четвёрке, один полный ответ без
                           воспроизведения по бюджету. Путь со случайным
                           хвостом, чтобы не наткнуться на настоящий ресурс.
                           Перепроверка перед снятием запрета (data_cut 2)
                           контроля не спрашивает: ей нужен один ответ
                           «встаёт ли ещё», и лишний зонд там незачем. */
                        if (data_cut != 2 && budget_left(&start)) {
                            uint8_t rnd[4];
                            char cpath[32];
                            static const char hex[] = "0123456789abcdef";
                            if (d2k_t13_random(rnd, sizeof rnd) == 0) {
                                size_t o = 0;
                                cpath[o++] = '/'; cpath[o++] = 'd'; cpath[o++] = '2';
                                cpath[o++] = 'k'; cpath[o++] = '-';
                                for (size_t i = 0; i < sizeof rnd; i++) {
                                    cpath[o++] = hex[rnd[i] >> 4];
                                    cpath[o++] = hex[rnd[i] & 0x0f];
                                }
                                cpath[o] = '\0';
                                d2k_quic_arm_question cq = dq;
                                cq.label = "контроль: короткий ответ";
                                cq.budget_pk = 0;
                                cq.need_complete = 1;
                                d2k_quic_arm_data cc = d2k_quic_arm_data_hook(&cq, sni, cpath,
                                                                             port, dyn_wait, mark);
                                r.probes += 1;
                                qp_progress("контроль: короткий ответ", 1);
                                if (cc.verdict == D2K_QAD_PASS) {
                                    r.qprops.flow_cut_any_size = D2K_PROP_NO;
                                } else if (cc.verdict == D2K_QAD_CUT) {
                                    r.qprops.flow_cut_any_size = D2K_PROP_YES;
                                }
                                /* NOT_RUN и «рукопожатия нет» ответом не
                                   считаются: вопрос остаётся НЕ ЗАДАННЫМ. */
                            }
                        }
                        /* Измеренные признаки называются ОТДЕЛЬНЫМИ строками
                           фиксированного размера, а не надеждой на то, что они
                           уцелеют в усечённом тексте (кириллица по два байта —
                           ловушка 9193228; массив, а не указатель, чтобы
                           компилятор мог проверить границу). Направление —
                           только когда ОБА повтора измерили его одинаково.
                           ЧИСЛА ОСТАНОВКИ — ОБА ПОВТОРА И В ДВУХ ВИДАХ: байты
                           и датаграммы. На чём они сошлись, решают ТЕ ЖЕ
                           допуски, что у TCP-ветки (задача 28), и только если
                           короткий ответ дошёл: иначе величина ни при чём. */
                        if (r.qprops.flow_cut_any_size == D2K_PROP_NO) {
                            uint64_t blo = dd.app_bytes < dd2.app_bytes ? dd.app_bytes : dd2.app_bytes;
                            uint64_t bhi = dd.app_bytes > dd2.app_bytes ? dd.app_bytes : dd2.app_bytes;
                            uint64_t plo = dd.packets < dd2.packets ? dd.packets : dd2.packets;
                            uint64_t phi = dd.packets > dd2.packets ? dd.packets : dd2.packets;
                            r.qprops.stop_by_bytes =
                                bhi - blo <= (uint64_t)D2K_VOLUME_SLACK * 1024
                                    ? D2K_PROP_YES : D2K_PROP_NO;
                            r.qprops.stop_by_packets =
                                phi - plo <= (uint64_t)D2K_VOLUME_PACKET_SLACK
                                    ? D2K_PROP_YES : D2K_PROP_NO;
                        }
                        char ow[64], ctl[112];
                        snprintf(ow, sizeof ow, "%s",
                                 dd.oneway && dd2.oneway ? ", наши пакеты не доходят" : "");
                        if (r.qprops.flow_cut_any_size == D2K_PROP_YES) {
                            snprintf(ctl, sizeof ctl, "; короткий ответ тоже встал");
                        } else if (r.qprops.flow_cut_any_size == D2K_PROP_NO) {
                            /* Сошлось и там и там — короткий ответ эти два
                               объяснения не различает, и выбирать нельзя. */
                            snprintf(ctl, sizeof ctl, "; короткий ответ дошёл, %s",
                                     r.qprops.stop_by_bytes == D2K_PROP_YES &&
                                     r.qprops.stop_by_packets == D2K_PROP_YES
                                         ? "сошлись и байты, и пакеты"
                                     : r.qprops.stop_by_bytes == D2K_PROP_YES ? "сошлись байты"
                                     : r.qprops.stop_by_packets == D2K_PROP_YES ? "сошлись пакеты"
                                                                 : "не сошлись ни байты, ни пакеты");
                        } else {
                            ctl[0] = '\0';
                        }
                        /* Подробная причина самого этапа (dd.reason) здесь уже
                           не нужна: байты и датаграммы обоих повторов названы
                           числом, а направление — отдельным признаком. */
                        reason_set(&r, "Initial %d/%d, свой запрос HTTP/3 встал после рукопожатия "
                                       "дважды: %llu и %llu байт, %llu и %llu датаграмм%s%s",
                                   base.pass, D2K_QUIC_REPEATS,
                                   (unsigned long long)dd.app_bytes,
                                   (unsigned long long)dd2.app_bytes,
                                   (unsigned long long)dd.packets,
                                   (unsigned long long)dd2.packets,
                                   ow, ctl);
                        d2k_quic_arm_context context = {.pool=pool, .n_pool=n_pool,
                            .next=next_addr, .residual=0, .marked=all_marked,
                            .can_ask=arm_budget_left, .limit_user=&start,
                            .spent=arm_budget_spent,
                            .path=arm_path[0]?arm_path:NULL,
                            .no_split=arm_split_unfit,
                            .need_complete=1, .budget_pk=dq.budget_pk};
                        arm->data_cut_seen = 1;
                        if (data_cut == 2) {
                            /* Перепроверка перед снятием запрета QUIC: нужен
                               только ответ «встаёт ли ещё»; плечи — не здесь. */
                            arm->data_cut = 2;
                        } else if (budget_left(&start)) {
                            char why[sizeof r.reason];
                            snprintf(why, sizeof why, "%s", r.reason);
                            *arm = d2k_quic_strategy_measure(&context, port, trigger, control,
                                                             dyn_wait, mark);
                            arm->data_cut = 1;
                            arm->data_cut_seen = 1;
                            arm->budget_pk = arm_budget;
                            next_addr = context.next;
                            r.probes += arm->probes;
                            if (!context.marked) all_marked = 0;
                            snprintf(r.reason, sizeof r.reason, "%s", why);
                        } else {
                            arm->original = 1; arm->incomplete = 1; arm->data_cut = 1;
                            snprintf(arm->reason, sizeof arm->reason, "budget exhausted before askArms");
                        }
                    }
                } else if (all_marked && base.pass == D2K_QUIC_REPEATS) {
                    /* Проверено ТОЛЬКО рукопожатие: ответ на свой запрос
                       HTTP/3 не спрашивался (подозрение не о данных или нет
                       arm). Строка называет, что именно прошло, — прежде
                       тут стояла TCP-фраза «триггер проходит как есть». */
                    r.verdict = D2K_V_CLEAR;
                    reason_set(&r, "наш Initial получает ответ (%d/%d, метка подтверждена) — "
                                   "рукопожатие QUIC не режется; ответ на свой запрос HTTP/3 "
                                   "не проверялся",
                               base.pass, D2K_QUIC_REPEATS);
                } else {
                    r.verdict = D2K_V_INCONCLUSIVE;
                    reason_set(&r, "прошёл (%d/%d), но БЕЗ подтверждённой метки — clear не "
                                   "принимается",
                               base.pass, D2K_QUIC_REPEATS);
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
                    int same_sent = 0;
                    d2k_tally same = d2k_quic_ask_control_hook(pool[0], port, NULL, 0, control, dyn_wait, mark,
                                                        D2K_QUIC_REPEATS, NULL, NULL, &same_sent, NULL);
                    r.probes += same_sent; /* сколько реально ушло на провод (находка 4 ревью, круг 5) */
                    qp_progress("остаточная блокировка", same_sent);
                    if (!same.marked) {
                        all_marked = 0;
                    }

                    if (same.err > 0) {
                        r.verdict = D2K_V_FLAKY;
                        reason_set(&r, "остаточная блокировка: локальная ошибка, опыт не завершён");
                    } else {
                        /* probe.go:355: hasResidual = Answered == 0 —
                           ICMP-отказ на повторный контроль тоже «нет ответа». */
                        int residual = same.pass == 0;
                        r.qprops.residual_blocking = residual ? D2K_PROP_YES : D2K_PROP_NO;
                        r.qprops.residual_ignores_src_port = residual ? D2K_PROP_YES : D2K_PROP_UNKNOWN;
                        r.verdict = D2K_V_OPAQUE;
                        reason_set(&r, "контроль ответил, имя молчит; ост.блокировка: %s",
                                   residual ? "да" : "нет");
                        if (arm) {
                            d2k_quic_arm_context context = {.pool=pool, .n_pool=n_pool,
                                .next=next_addr, .residual=residual, .marked=all_marked,
                                .can_ask=arm_budget_left, .limit_user=&start,
                                .spent=arm_budget_spent,
                                .path=arm_path[0]?arm_path:NULL,
                                .no_split=arm_split_unfit};
                            if (budget_left(&start)) {
                                /* Задача 40: сначала вопросы стратегии
                                   (остаточное разрешение, разрез CRYPTO),
                                   перебор askArms — только запасной. */
                                *arm = d2k_quic_strategy_measure(&context, port, trigger, control, dyn_wait, mark);
                                next_addr = context.next;
                                r.probes += arm->probes;
                                if (!context.marked) all_marked = 0;
                                /* Те же вопросы, что «мусор» и «кадры»
                                   вопросника: решающий ответ стратегии
                                   ложится в их свойства, и вопросник их
                                   второй раз не задаёт. */
                                if (arm->clearance != D2K_PROP_UNKNOWN)
                                    r.qprops.junk_ahead = arm->clearance;
                                if (arm->split_crypto != D2K_PROP_UNKNOWN)
                                    r.qprops.split_crypto = arm->split_crypto;
                                if (arm->longer != D2K_PROP_UNKNOWN)
                                    r.qprops.longer = arm->longer;
                            } else {
                                arm->original = 1; arm->incomplete = 1;
                                snprintf(arm->reason, sizeof arm->reason, "budget exhausted before askArms");
                            }
                        }
                        /* The arm already passed its handshake AND data stage.
                           Unrelated diagnostics cannot improve this candidate
                           and must not delay it or poison its mark evidence.
                           Classify-only and failed searches retain diagnostics. */
                        int have_arm=arm && arm->original && arm->n_trace &&
                                     arm->kind!=D2K_QA_NOT_FOUND && arm->kind!=D2K_QA_FLAKY &&
                                     arm->trace[arm->n_trace-1].data==D2K_QAD_PASS &&
                                     arm->trace[arm->n_trace-1].answered==D2K_QUIC_REPEATS &&
                                     !arm->trace[arm->n_trace-1].not_measured;
                        if(have_arm) reason_append(&r,"; кандидат прошёл этап данных — дальнейшие вопросы не нужны");
                        else qp_questions_step(&r, pool, n_pool, &next_addr, residual,
                                          port, sni, trigger, dyn_wait, mark,
                                          &all_marked, &start,
                                          arm ? arm->clearance_asked : 0,
                                          arm ? arm->split_asked : 0,
                                          arm ? arm->longer_asked : 0);
                    }
                }
            }
        }
    }

    r.marked = (mark != 0) && all_marked;
    return r;
}

d2k_vres d2k_quic_classify(const char *ip, uint16_t port, const char *sni,
    d2k_hello trigger, d2k_hello control, uint32_t mark) {
    return classify_run(ip,port,sni,trigger,control,mark,NULL,0,NULL);
}
d2k_vres d2k_quic_base(const char *ip, uint16_t port, const char *sni,
    d2k_hello trigger, d2k_hello control, uint32_t mark) {
    return classify_run(ip,port,sni,trigger,control,mark,NULL,1,NULL);
}
d2k_vres d2k_quic_run_seeded(const char *ip, uint16_t port, const char *sni,
    d2k_hello trigger, d2k_hello control, uint32_t mark, d2k_quic_arm *arm,
    const d2k_base_seed *seed) {
    return classify_run(ip,port,sni,trigger,control,mark,arm,0,seed);
}
d2k_vres d2k_quic_run(const char *ip, uint16_t port, const char *sni,
    d2k_hello trigger, d2k_hello control, uint32_t mark, d2k_quic_arm *arm) {
    return classify_run(ip,port,sni,trigger,control,mark,arm,0,NULL);
}
