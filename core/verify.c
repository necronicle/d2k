/* verify.c — зонд, читающий начало прикладного ответа. См. d2k_verify.h:
 * почему внешний тип записи 23 доказательством не является и почему повтор
 * снятого чужого приветствия рукопожатия не завершает.
 *
 * СОБИРАЕТСЯ ИЗ ГОТОВОГО, А НЕ ПИШЕТСЯ ЗАНОВО, и обе половины взяты не ради
 * экономии строк:
 *
 * 1. Обращение — d2k_props_contact (compose.c). Её две оговорки —
 *    «непомеченное» и «сокет закрывает вызывающий» — это ровно те условия,
 *    без которых измерение перестаёт измерять (см. её doc-комментарий и
 *    docs/field/2026-09-11-first-c-ask.md). Второе обращение к цели,
 *    написанное здесь рядом, разошлось бы с ним в мелочи, которая стоила бы
 *    измерения, — а расходятся такие копии молча.
 *
 * 2. Рукопожатие — d2k_tls13 (tls13.c), свой клиент TLS 1.3 на X25519 и
 *    AES-128-GCM, проверенный на живых серверах. Ключ у него СВОЙ, поэтому
 *    он может довести рукопожатие до конца и заговорить внутри сессии;
 *    снятое приветствие цели этого не может в принципе.
 *
 * ЧТО ЗДЕСЬ НЕ ПРОВЕРЯЕТСЯ: подлинность сервера. Предмет измерения — коробка
 * на линии. Поэтому результат НЕ доказывает доступность настоящего сайта:
 * HTTP мог вернуть посредник. Это ограничение нельзя переносить с объёмного
 * измерителя на достоверность обхода без отдельной проверки подлинности.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "d2k_compose_internal.h" /* d2k_props_contact — общее обращение к цели */
#include "d2k_h3.h"
#include "d2k_quicconn.h"
#include "d2k_tls13.h"
#include "d2k_verify.h"

static int64_t verify_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* RFC 9112 §4, RFC 9110 §15.2. Записи TLS не являются границами HTTP.
   Ждём полную строку и конец заголовков окончательного ответа; 1xx сам по
   себе не успех. Ограничены и общий объём заголовков, и время всей сборки.
   Тело ответа, происхождение страницы и сертификат здесь НЕ проверяются. */
/* Ищет CRLFCRLF в ПАМЯТИ, а не строковыми функциями: ответ содержит нулевые
   байты, и strstr останавливается на первом из них. */
static const uint8_t *find_hdr_end(const uint8_t *b, size_t n) {
    for (size_t i = 0; i + 3 < n; i++) {
        if (b[i] == 13 && b[i + 1] == 10 && b[i + 2] == 13 && b[i + 3] == 10) {
            return b + i;
        }
    }
    return NULL;
}

/* Конец ПЕРВОЙ строки (CRLF) в памяти, либо NULL. */
static const uint8_t *find_eol(const uint8_t *b, size_t n) {
    for (size_t i = 0; i + 1 < n; i++) {
        if (b[i] == 13 && b[i + 1] == 10) { return b + i; }
    }
    return NULL;
}

/* Код окончательного ответа HTTP, либо 0 — «полных заголовков нет».
 *
 * НОЛЬ В ТЕЛЕ БОЛЬШЕ НИЧЕГО НЕ РЕШАЕТ. Здесь стояло `if (memchr(...0...)) break;`
 * — разбор бросался, едва во ВХОДЯЩИХ байтах попадался нулевой. Тело ответа
 * его содержит сплошь и рядом, и зонд выбрасывал полноценный ответ вместе с
 * кандидатом, который его добыл.
 *
 * Замерено на живой линии 14.09.2026: i.ytimg.com отдаёт
 * «HTTP/1.1 404 Not Found» в первом же чтении (1378 байт, конец заголовков на
 * месте), нулевой байт лежит на смещении 386 — в ТЕЛЕ. Клиент в ту же секунду
 * получал 404 за 0,16 с, а зонд докладывал «нет полных заголовков
 * окончательного HTTP-ответа» и объявлял рабочий план негодным. Так за ночь
 * терялись найденные обходы (0010, R2: ложный ответ о свойствах DPI).
 *
 * Заголовки HTTP нулевого байта содержать не вправе, поэтому проверка на него
 * осталась — но только ДО конца заголовков, где она и означает «ответ битый».
 */
static int read_status(d2k_tls *t, int wait_ms, char *err, size_t errcap) {
    uint8_t buf[8193];
    size_t used = 0;
    int64_t until = verify_now_ms() + (wait_ms > 0 ? wait_ms : 8000);
    for (;;) {
        const uint8_t *end = find_hdr_end(buf, used);
        if (end) {
            size_t hdr_len = (size_t)(end - buf);
            /* Ноль ВНУТРИ заголовков — ответ битый, а не «ещё не всё». */
            if (memchr(buf, 0, hdr_len)) { return 0; }
            /* With no header fields, the status line's CRLF is the first
             * half of CRLFCRLF. Include it in the line search, but keep
             * the body excluded from the header/NUL validation above. */
            const uint8_t *eol = find_eol(buf, hdr_len + 2);
            if (!eol) { return 0; }
            size_t line_len = (size_t)(eol - buf);
            if (line_len < 13 || memcmp(buf, "HTTP/1.", 7) != 0 ||
                (buf[7] != '0' && buf[7] != '1') || buf[8] != ' ' ||
                buf[9] < '1' || buf[9] > '5' || buf[10] < '0' || buf[10] > '9' ||
                buf[11] < '0' || buf[11] > '9' || buf[12] != ' ') {
                return 0;
            }
            for (size_t p = 13; p < line_len; p++) {
                if ((buf[p] < 32 && buf[p] != '\t') || buf[p] == 127) { return 0; }
            }
            int code = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + buf[11] - '0';
            if (code >= 200) { return code; }
            if (code == 101) { return 0; } /* upgrade не запрашивали */
            /* Промежуточный ответ (1xx) — отбрасываем его вместе с
               заголовками и ждём окончательного. */
            size_t consumed = hdr_len + 4;
            memmove(buf, buf + consumed, used - consumed);
            used -= consumed;
            continue;
        }
        if (used >= sizeof buf - 1) { return 0; }
        int64_t left = until - verify_now_ms();
        if (left <= 0) { return 0; }
        long got = d2k_tls_read(t, buf + used, sizeof buf - 1 - used, (int)left, err, errcap);
        if (got <= 0) { return 0; }
        used += (size_t)got;
    }
}

d2k_ver_result d2k_verify_probe(const char *ip, uint16_t port, const char *sni,
                                int deadline_ms, size_t hello_wire) {
    return d2k_verify_probe_on(-1, ip, port, sni, deadline_ms, hello_wire);
}

/* use_fd — УЖЕ ЗАНЯТЫЙ сокет (d2k_props_bind), чей местный порт вызывающий
   назвал датапату заранее, чтобы пробный план достался только этому потоку.
   Меньше нуля — создать свой, тогда это в точности d2k_verify_probe. */
d2k_ver_result d2k_verify_probe_on(int use_fd, const char *ip, uint16_t port, const char *sni,
                                   int deadline_ms, size_t hello_wire) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;   /* не смотрели — «сказать нечего», а не «нет» (§2.4) */
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    const char *host = (sni && sni[0]) ? sni : ip;
    if (!host || !host[0]) { return r; }
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p <= 32 || *p == 127) {
            snprintf(r.reason, sizeof r.reason, "недопустимый символ в имени HTTP");
            return r;
        }
    }

    /* Байты приветствия сюда НЕ передаются: рукопожатие ведёт d2k_tls13,
       своим ключом, и чужой ClientHello перед ним был бы мусором в начале
       потока. Пустое приветствие d2k_props_contact принимает намеренно —
       нужны от неё ровно непомеченный сокет, открытый наружу, и местные
       адрес с портом. */
    d2k_hello none;
    none.bytes = NULL;
    none.len = 0;
    if (d2k_props_contact_on(use_fd, ip, port, none, r.local_ip4, &r.local_port, &r.fd) != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TCP");
        return r;
    }
    r.level = D2K_VER_TRANSPORT;
    snprintf(r.reason, sizeof r.reason, "транспорт встал, рукопожатия нет");

    char err[160];
    err[0] = '\0';
    d2k_tls *t = NULL;
    if (d2k_tls_connect(r.fd, sni, deadline_ms, hello_wire, &t, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TLS: %.150s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    r.name_ok = d2k_tls_peer_name(t);
    snprintf(r.reason, sizeof r.reason, "рукопожатие завершено, приложение молчит");

    char req[512];
    int n = snprintf(req, sizeof req,
                     "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n",
                     host);
    if (n <= 0 || (size_t)n >= sizeof req) {
        snprintf(r.reason, sizeof r.reason, "запрос не собрался: имя длиннее запроса");
    } else if (d2k_tls_write(t, (const uint8_t *)req, (size_t)n, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "запрос не ушёл: %.150s", err);
    } else {
        int code = read_status(t, deadline_ms, err, sizeof err);
        if (code) {
            r.level = D2K_VER_APPLICATION;
            r.status = code;
            snprintf(r.reason, sizeof r.reason, "HTTP-заголовки получены, статус %d", code);
        } else {
            snprintf(r.reason, sizeof r.reason,
                     "нет полных заголовков окончательного HTTP-ответа: %.100s", err);
        }
    }
    /* Сессию освобождаем, сокет — нет: d2k_tls_free владения им не берёт
       (d2k_tls13.h), а закрыть его здесь значило бы послать FIN и потерять
       ячейку потока в датапате раньше, чем вызывающий свяжет с ней событие. */
    d2k_tls_free(t);
    return r;
}

void d2k_verify_close(d2k_ver_result *r) {
    if (r && r->fd >= 0) {
        close(r->fd);
        r->fd = -1;
    }
}

/* --- то же самое, но по QUIC --------------------------------------------- */

d2k_ver_result d2k_verify_probe_quic(const char *ip, uint16_t port, const char *sni,
                                     int deadline_ms, size_t hello_wire) {
    return d2k_verify_probe_quic_on(-1, ip, port, sni, deadline_ms, hello_wire);
}

/* use_fd — УЖЕ ЗАНЯТЫЙ сокет UDP (d2k_props_bind_udp), под чей местный порт
   поставлен пробный план. Меньше единицы — завести свой. */
d2k_ver_result d2k_verify_probe_quic_on(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms,
                                        size_t hello_wire) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    const char *host = (sni && sni[0]) ? sni : ip;
    if (!host || !host[0]) { return r; }
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p <= 32 || *p == 127) {
            snprintf(r.reason, sizeof r.reason, "недопустимый символ в имени");
            return r;
        }
    }

    d2k_qc_opts o;
    memset(&o, 0, sizeof o);
    o.ip = ip;
    o.port = port ? port : 443;
    o.sni = sni;
    o.alpn = "h3";
    o.deadline_ms = deadline_ms > 0 ? deadline_ms : 5000;
    o.pad_to = hello_wire;
    o.use_fd = use_fd;
    /* Метки НЕТ намеренно — ровно по той же причине, что у TCP-зонда: к
       помеченному пакету поставленный план не применится, и зонд мерил бы
       линию БЕЗ обхода, считая, что мерит с обходом. */

    d2k_qc *c = NULL;
    char err[200];
    err[0] = '\0';
    if (d2k_qc_connect(&o, &c, err, sizeof err) != 0) {
        /* Транспорт у QUIC не «встал» отдельно от рукопожатия: датаграмма
           уходит всегда, и отличить «ушла в никуда» от «ушла и не понравилась»
           можно только по тому, ответил ли сервер хоть чем-то. Оба случая для
           нас — «не измерено», и приписывать им уровень транспорта значило бы
           дописать доказательство. */
        snprintf(r.reason, sizeof r.reason, "рукопожатия нет: %.150s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    r.name_ok = d2k_qc_peer_name(c);
    d2k_qc_local(c, r.local_ip4, &r.local_port);
    r.fd = d2k_qc_fd(c);
    snprintf(r.reason, sizeof r.reason, "рукопожатие завершено, приложение молчит");

    /* Управляющий поток обязателен: без SETTINGS сервер вправе не отвечать
       вовсе, и молчание записалось бы блокировкой. */
    uint8_t ctl[16];
    size_t cn = d2k_h3_control(ctl, sizeof ctl);
    if (cn == 0 || d2k_qc_stream_send(c, 2, ctl, cn, 0, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "управляющий поток не ушёл: %.140s", err);
        r.fd = d2k_qc_release(c);
        return r;
    }
    /* Пауза между управляющим потоком и вопросом. Измерено 13.09.2026 на
       живых серверах: без неё отвечает только один стек из четырёх — сервер
       обязан увидеть SETTINGS раньше запроса, а за это же время доезжает его
       NEW_CONNECTION_ID и меняется адрес ответа. */
    {
        uint64_t sid = 0;
        uint8_t drop[2048];
        (void)d2k_qc_stream_recv(c, &sid, drop, sizeof drop, 400, err, sizeof err);
    }

    uint8_t req[512];
    size_t rn = d2k_h3_request(host, "/", req, sizeof req);
    if (rn == 0 || d2k_qc_stream_send(c, 0, req, rn, 1, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "запрос не ушёл: %.150s", err);
        r.fd = d2k_qc_release(c);
        return r;
    }

    uint8_t rx[8192];
    size_t got = 0;
    int64_t until = verify_now_ms() + (deadline_ms > 0 ? deadline_ms : 5000);
    while (got < sizeof rx && verify_now_ms() < until) {
        uint64_t sid = 0;
        long n = d2k_qc_stream_recv(c, &sid, rx + got, sizeof rx - got, 200,
                                    err, sizeof err);
        if (n < 0) { break; }
        if (n > 0) { got += (size_t)n; }
        int st = 0;
        if (got > 0 && d2k_h3_status(rx, got, &st) == 0) {
            r.level = D2K_VER_APPLICATION;
            r.status = st;
            snprintf(r.reason, sizeof r.reason,
                     "заголовки HTTP/3 получены, статус %d", st);
            break;
        }
    }
    if (r.level != D2K_VER_APPLICATION) {
        snprintf(r.reason, sizeof r.reason,
                 "кода ответа HTTP/3 нет: принято %zu байт", got);
    }
    /* Сокет остаётся ОТКРЫТЫМ до d2k_verify_close — по той же причине, что у
       TCP-зонда: закрытие удаляет ячейку потока в датапате раньше, чем придёт
       событие применения плана. */
    r.fd = d2k_qc_release(c);
    return r;
}
