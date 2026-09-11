/* verify.c — зонд, доводящий прикладной обмен до конца. См. d2k_verify.h:
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
 * на линии, и подмена сервера этому не мешает (та же оговорка, что в шапке
 * d2k_tls13.h). Доказательством служит факт РАЗОБРАННОГО ответа приложения,
 * а не его содержимое.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "d2k_compose_internal.h" /* d2k_props_contact — общее обращение к цели */
#include "d2k_tls13.h"
#include "d2k_verify.h"

d2k_ver_result d2k_verify_probe(const char *ip, uint16_t port, const char *sni,
                                int deadline_ms) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");

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
    if (d2k_tls_connect(r.fd, sni, deadline_ms, &t, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TLS: %.150s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    snprintf(r.reason, sizeof r.reason, "рукопожатие завершено, приложение молчит");

    char req[512];
    int n = snprintf(req, sizeof req,
                     "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n",
                     (sni && sni[0]) ? sni : ip);
    if (n <= 0 || (size_t)n >= sizeof req) {
        snprintf(r.reason, sizeof r.reason, "запрос не собрался: имя длиннее запроса");
    } else if (d2k_tls_write(t, (const uint8_t *)req, (size_t)n, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "запрос не ушёл: %.150s", err);
    } else {
        /* Одно чтение, а не сбор всего ответа: строка состояния приходит
           первой записью, а больше нам и не нужно — доказывается факт
           ответа приложения, не его содержимое. */
        uint8_t buf[1024];
        long got = d2k_tls_read(t, buf, sizeof buf - 1, deadline_ms, err, sizeof err);
        if (got > 0) {
            buf[got] = '\0';
            unsigned code = 0;
            /* Разбор ровно до кода состояния. Границы 100..599 — не вкусовые:
               код состояния HTTP трёхзначный и бывает только пяти классов
               (RFC 9110 §15), а без верхней границы «HTTP/1.1 999999» прошло
               бы за ответ приложения. */
            if (sscanf((const char *)buf, "HTTP/1.%*d %u", &code) == 1 &&
                code >= 100 && code <= 599) {
                r.level = D2K_VER_APPLICATION;
                r.status = (int)code;
                snprintf(r.reason, sizeof r.reason, "приложение ответило %u", code);
            } else {
                snprintf(r.reason, sizeof r.reason, "ответ не разобрался как HTTP");
            }
        } else {
            snprintf(r.reason, sizeof r.reason,
                     "рукопожатие прошло, ответа нет: %.120s", err);
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
