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
static int read_status(d2k_tls *t, int wait_ms, char *err, size_t errcap) {
    char buf[8193];
    size_t used = 0, total = 0;
    int64_t until = verify_now_ms() + (wait_ms > 0 ? wait_ms : 8000);
    while (total < sizeof buf - 1) {
        int64_t left = until - verify_now_ms();
        if (left <= 0) { break; }
        long got = d2k_tls_read(t, (uint8_t *)buf + used,
                               sizeof buf - 1 - total, (int)left, err, errcap);
        if (got <= 0) { break; }
        if (memchr(buf + used, 0, (size_t)got)) { break; }
        used += (size_t)got;
        total += (size_t)got;
        buf[used] = '\0';
        for (;;) {
            char *line = strstr(buf, "\r\n");
            if (!line) { break; }
            if (line - buf < 13 || memcmp(buf, "HTTP/1.", 7) != 0 ||
                (buf[7] != '0' && buf[7] != '1') || buf[8] != ' ' ||
                buf[9] < '1' || buf[9] > '5' || buf[10] < '0' || buf[10] > '9' ||
                buf[11] < '0' || buf[11] > '9' || buf[12] != ' ') { return 0; }
            for (const char *p = buf + 13; p < line; p++) {
                if (((unsigned char)*p < 32 && *p != '\t') || *p == 127) { return 0; }
            }
            char *end = strstr(line, "\r\n\r\n");
            if (!end) { break; }
            int code = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + buf[11] - '0';
            if (code >= 200) { return code; }
            if (code == 101) { return 0; } /* upgrade не запрашивали */
            size_t consumed = (size_t)(end + 4 - buf);
            used -= consumed;
            memmove(buf, buf + consumed, used + 1);
        }
    }
    return 0;
}

d2k_ver_result d2k_verify_probe(const char *ip, uint16_t port, const char *sni,
                                int deadline_ms, size_t hello_wire) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
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
    if (d2k_props_contact(ip, port, none, r.local_ip4, &r.local_port, &r.fd) != 0) {
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
