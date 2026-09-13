/* quicping.c — довести рукопожатие QUIC до прикладных ключей и сказать, чем
 * кончилось. Только для опытов: в сборку d2k не входит.
 *
 * Нужен затем, что стенд на петле проверяет нас против НАС ЖЕ, а первый вопрос
 * к клиенту QUIC другой: сходится ли он с настоящим сервером. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_h3.h"
#include "d2k_quicconn.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "использование: quicping <ip> <имя> [порт]\n");
        return 2;
    }
    d2k_qc_opts o;
    memset(&o, 0, sizeof o);
    o.ip = argv[1];
    o.sni = argv[2];
    o.port = (uint16_t)(argc > 3 ? atoi(argv[3]) : 443);
    o.alpn = "h3";
    o.deadline_ms = 5000;

    d2k_qc *c = NULL;
    char err[256];
    if (d2k_qc_connect(&o, &c, err, sizeof err) != 0) {
        printf("рукопожатие НЕ завершилось: %s\n", err);
        return 1;
    }
    printf("рукопожатие завершено; имя в сертификате: %d\n", d2k_qc_peer_name(c));

    uint8_t ctl[16];
    size_t cn = d2k_h3_control(ctl, sizeof ctl);
    if (d2k_qc_stream_send(c, 2, ctl, cn, 0, err, sizeof err) != 0) {
        printf("управляющий поток не ушёл: %s\n", err);
        d2k_qc_close(c); return 1;
    }
    /* Потоки QPACK: кодировщик (тип 2) и декодировщик (тип 3), пустые.
       Опыт: часть серверов не отвечает, пока их нет. */
    uint8_t qe[1] = { 0x02 }, qd[1] = { 0x03 };
    (void)d2k_qc_stream_send(c, 6, qe, 1, 0, err, sizeof err);
    (void)d2k_qc_stream_send(c, 10, qd, 1, 0, err, sizeof err);
    /* Пауза между управляющим потоком и запросом: сервер обязан увидеть наш
       SETTINGS раньше запроса, а заодно за это время доезжают его
       NEW_CONNECTION_ID и смена адреса ответа. */
    {
        uint64_t sid = 0; uint8_t tmp[2048];
        (void)d2k_qc_stream_recv(c, &sid, tmp, sizeof tmp, 400, err, sizeof err);
    }
    uint8_t req[512];
    size_t rn = d2k_h3_request(argv[2], "/", req, sizeof req);
    if (rn == 0 || d2k_qc_stream_send(c, 0, req, rn, 1, err, sizeof err) != 0) {
        printf("запрос не ушёл: %s\n", err);
        d2k_qc_close(c); return 1;
    }

    uint8_t rx[8192];
    size_t got = 0;
    for (int i = 0; i < 40 && got < sizeof rx; i++) {
        uint64_t sid = 0;
        long n = d2k_qc_stream_recv(c, &sid, rx + got, sizeof rx - got, 200, err, sizeof err);
        if (n < 0) { break; }
        if (n > 0) { got += (size_t)n; }
        int st = 0;
        if (got && d2k_h3_status(rx, got, &st) == 0) {
            printf("ПРИКЛАДНОЙ ОТВЕТ: статус %d (поток %llu, байт %zu), HANDSHAKE_DONE %d\n",
                   st, (unsigned long long)sid, got, d2k_qc_handshake_done(c));
            d2k_qc_close(c);
            return 0;
        }
    }
    printf("прикладного ответа нет: принято %zu байт, HANDSHAKE_DONE %d, %s\n",
           got, d2k_qc_handshake_done(c), err);
    d2k_qc_close(c);
    return 1;
}
