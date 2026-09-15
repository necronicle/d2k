#define _POSIX_C_SOURCE 200809L
/* SO_MARK — НЕ POSIX, и под строгим _POSIX_C_SOURCE библиотека его ПРЯЧЕТ.
 * Молча: #ifdef не срабатывает, компилятор не ругается, метка просто не
 * ставится ни на одном зонде — и замер меряет наш же обход поверх коробки.
 * Та же причина и то же лекарство, что в core/meas.c и datapath/raw.c.
 * Ловится это только счётчиком iptables, то есть уже на роутере. */
#define _DEFAULT_SOURCE 1

/* response.c — ОТВЕТНОЕ НАПРАВЛЕНИЕ. Перенос internal/classify/response.go.
 *
 * Всё остальное в этом модуле меряет направление клиент → сервер: проходит ли
 * НАШ ClientHello. Но у TLS 1.2 есть класс блокировки, которого при таком
 * замере не видно вовсе.
 *
 * В TLS 1.2 сертификат сервера едет ОТКРЫТЫМ ТЕКСТОМ и содержит имя домена.
 * Коробка может пропустить запрос и убить ОТВЕТ — на сертификате. Тогда наш
 * ClientHello доходит, ServerHello возвращается, инструмент честно объявляет
 * «проходит как есть», а сайт у человека не открывается. Вердикт получается не
 * просто неточным, а противоположным правде.
 *
 * В TLS 1.3 такого класса не существует: там всё после ServerHello уже
 * зашифровано, и резать по имени в сертификате нечего. Поэтому зонд насильно
 * договаривается на 1.2 — именно так коробка увидела бы сертификат в открытую.
 *
 * Оракул тот же, что и везде: сравнение с контролем. Рукопожатие с нейтральным
 * именем на ТОТ ЖЕ адрес обязано доходить. Не доходит — значит сервер не умеет
 * 1.2 или мешает что-то ещё, и вывода мы не делаем.
 *
 * ЕДИНСТВЕННОЕ ОТЛИЧИЕ ОТ ЭТАЛОНА, И ОНО НАЗВАНО ЗДЕСЬ. Там рукопожатие
 * доводится до конца средствами crypto/tls; здесь критерий — дошёл ли до нас
 * ServerHelloDone (тип 14). Это ТА ЖЕ граница: коробка режет ответ на записи с
 * сертификатом, то есть ДО ServerHelloDone, и ни одно рукопожатие 1.2 её не
 * переживает. Разница только в том, что критерий не требует своей реализации
 * обмена ключами — а лишний код в оракуле это лишний способ соврать. Случай, в
 * котором ответы разойдутся, ровно один: сервер прислал весь свой флайт, но
 * сломался бы позже, на нашем ClientKeyExchange. Это несовместимость клиента,
 * а не цензура, и эталон назвал бы её «режут ответ» ошибочно.
 */
#include "d2k_detect.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_MARK
#define SO_MARK 36
#endif

/* respTimeout — потолок на одно рукопожатие проверки.
 *
 * Он НИЖЕ общего: сюда мы попадаем только тогда, когда сервер уже ответил на
 * наш ClientHello, то есть он рядом и жив. Ждать его шесть секунд незачем, а
 * цена ожидания — прямое время в глазах человека. */
static int resp_timeout(const d2k_opts *opt)
{
    if (opt->timeout_ms > 0 && opt->timeout_ms < 3000) {
        return opt->timeout_ms;
    }
    return 3000;
}

/* Ждём ServerHelloDone, разбирая поток записей TLS. Возврат 1 — дошёл. */
static int handshake12(const char *host, const char *port, const char *sni,
                       const d2k_opts *opt)
{
    d2k_trigger tr;
    char err[160];
    struct addrinfo hints, *ai = NULL;
    int fd = -1, rc = 0;
    int to = resp_timeout(opt);
    long deadline;
    enum { RESPONSE_CAP = 65536 };
    uint8_t *buf; /* heap-owned: each handshake has its own partial records */
    size_t have = 0;
    size_t pos = 0;

    if (d2k_trigger_tls(sni, 1 /* legacy: без supported_versions, сервер пойдёт на 1.2 */,
                        &tr, err, sizeof(err)) != 0) {
        return 0;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &ai) != 0 || !ai) {
        return 0;
    }
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(ai);
        return 0;
    }
    {
        int mark = (int)(opt->mark ? opt->mark : (uint32_t)D2K_BYPASS_MARK);
        int one = 1;
        struct timeval tv;
        (void)setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        tv.tv_sec = to / 1000;
        tv.tv_usec = (to % 1000) * 1000;
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        freeaddrinfo(ai);
        close(fd);
        return 0;
    }
    freeaddrinfo(ai);

    if (send(fd, tr.payload, tr.len, 0) != (ssize_t)tr.len) {
        close(fd);
        return 0;
    }

    buf = malloc(RESPONSE_CAP);
    if (!buf) { close(fd); return 0; }
    deadline = d2k_now_ms() + to;
    while (d2k_now_ms() < deadline) {
        struct pollfd pfd;
        ssize_t n;
        int left = (int)(deadline - d2k_now_ms());

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, left < 0 ? 0 : left) <= 0) {
            break;
        }
        n = recv(fd, buf + have, RESPONSE_CAP - have, 0);
        if (n <= 0) {
            break;
        }
        have += (size_t)n;

        /* Разбираем записи TLS по заголовкам: тип(1) версия(2) длина(2).
         * Внутри записей типа handshake (0x16) идут сообщения: тип(1)
         * длина(3). Ищем ServerHelloDone (14). Алерт (0x15) — конец. */
        for (;;) {
            size_t rlen, off;
            if (have - pos < 5) {
                break;
            }
            rlen = ((size_t)buf[pos + 3] << 8) | buf[pos + 4];
            if (have - pos < 5 + rlen) {
                break;
            }
            if (buf[pos] == 0x15) {
                goto out; /* фатальный алерт — рукопожатия не будет */
            }
            if (buf[pos] == 0x16) {
                off = pos + 5;
                while (off + 4 <= pos + 5 + rlen) {
                    size_t hlen = ((size_t)buf[off + 1] << 16) |
                                  ((size_t)buf[off + 2] << 8) | buf[off + 3];
                    if (buf[off] == 14) { /* ServerHelloDone */
                        rc = 1;
                        goto out;
                    }
                    if (off + 4 + hlen > pos + 5 + rlen) {
                        /* Сообщение разорвано между записями — дочитываем
                         * следующую запись, а не гадаем о его содержимом. */
                        break;
                    }
                    off += 4 + hlen;
                }
            }
            pos += 5 + rlen;
        }
        if (have == RESPONSE_CAP) {
            break;
        }
    }
out:
    free(buf);
    close(fd);
    return rc;
}

/* countHandshakes считает, сколько рукопожатий TLS 1.2 дошли до конца.
 *
 * ПОСЛЕДОВАТЕЛЬНО, А НЕ ВЕЕРОМ. В эталоне повторы идут параллельно ради
 * времени (на rutracker.org прогон вырос с 4 до 39 секунд), но там за это
 * платит рантайм Go, а здесь пришлось бы заводить потоки ради одной функции.
 * Цена честная и названа: до полуминуты на заблокированной цели. */
static int count_handshakes(const char *host, const char *port, const char *sni,
                            const d2k_opts *opt)
{
    int i, done = 0;
    for (i = 0; i < opt->repeats; i++) {
        if (handshake12(host, port, sni, opt)) {
            done++;
        }
    }
    return done;
}

/* neutralSNI — имя для контроля. Домен example.com зарезервирован IANA
 * (RFC 2606) и в списках не встречается; случайная метка спереди убирает
 * попадание в кэши и в состояние коробки. */
static void neutral_sni(char *out, size_t cap)
{
    unsigned i;
    char hex[11];
    for (i = 0; i < 10; i++) {
        hex[i] = "0123456789abcdef"[random() & 0xf];
    }
    hex[10] = '\0';
    snprintf(out, cap, "z%s.example.com", hex);
}

/* ProbeResponse проверяет, не режут ли ОТВЕТ сервера.
 *
 * Зовётся только там, где запрос уже признан проходящим: если режут запрос,
 * про ответ говорить рано. */
void d2k_probe_response(const char *host, const char *port, const char *sni,
                        const d2k_opts *opt, d2k_resp_result *res)
{
    char neutral[64];
    int target, control;

    memset(res, 0, sizeof(*res));
    target = count_handshakes(host, port, sni, opt);
    /* Контроль ОБЯЗАН быть другим именем на том же адресе. Если бы мы взяли то
     * же самое, молчали бы оба, и «режут ответ» получилось бы из собственной
     * ошибки ввода. */
    neutral_sni(neutral, sizeof(neutral));
    control = count_handshakes(host, port, neutral, opt);

    res->target = target;
    res->control = control;
    if (control == 0) {
        res->verdict = D2K_RESP_NOT_APPLICABLE;
        snprintf(res->reason, sizeof(res->reason),
                 "контрольное рукопожатие по TLS 1.2 не завершается — сервер его не поддерживает "
                 "или мешает что-то ещё; про ответное направление вывода нет");
    } else if (target == opt->repeats) {
        res->verdict = D2K_RESP_CLEAR;
        snprintf(res->reason, sizeof(res->reason),
                 "рукопожатие TLS 1.2 доходит до конца — сертификат не режут");
    } else if (target == 0) {
        res->verdict = D2K_RESP_BLOCKED;
        snprintf(res->reason, sizeof(res->reason),
                 "запрос проходит, а рукопожатие не завершается: с нейтральным именем на тот же "
                 "адрес оно завершается каждый раз. Значит режут ОТВЕТ — сертификат в TLS 1.2 "
                 "идёт открытым текстом");
    } else {
        res->verdict = D2K_RESP_FLAKY;
        snprintf(res->reason, sizeof(res->reason),
                 "рукопожатий дошло %d из %d — не воспроизводится", target, opt->repeats);
    }
}
