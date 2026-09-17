/* labtls.c — форкающий сервер TLS 1.3 для лаборатории. Только для опытов.
 *
 * Зачем свой, а не готовый. Измерено в лаборатории 13.09.2026:
 *   openssl s_server — обслуживает соединения ПО ОЧЕРЕДИ. Зарезанное цензором
 *     рукопожатие оставляет его внутри SSL_accept, и следующие соединения,
 *     включая контрольное, не обслуживаются вовсе. Отличить «цензор режет» от
 *     «сервер занят» становится нечем, и опыт превращается в гадание.
 *   socat OPENSSL-LISTEN — форкает, но отвергает приветствие нашего зонда
 *     тревогой 40 на том же сертификате и той же петле, где s_server отвечает
 *     статусом 200. Причина не в обходе, а в самом socat, и весь опыт
 *     показывал бы «зонд не дошёл» на каждом плече, включая рабочие.
 *
 * Поэтому здесь ровно то, чего не хватало: форк на соединение и обычные
 * умолчания OpenSSL, с которыми наш зонд заведомо сходится.
 *
 * Это НЕ часть продукта и не участвует в сборке d2k. Живёт в spike/ вместе с
 * остальными вспомогательными стендами.
 */
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

static const char *RESPONSE =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "использование: labtls <порт> <cert.pem> <key.pem>\n");
        return 2;
    }
    int port = atoi(argv[1]);

    /* Дети не должны становиться зомби: соединений за опыт бывают сотни. */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return 1; }
    /* ОБЕ ВЕРСИИ, А НЕ ТОЛЬКО 1.3.
     *
     * Здесь стоял минимум TLS 1.3 — и это делало стенд слепым к целому классу
     * клиентов. Подтверждать найденное надо ТЕМ ЖЕ протоколом, каким говорит
     * клиент (MVP_CHECKLIST, пункт 3), а у старого клиента это TLS 1.2; зонд
     * для него отдельный, и проверить его было негде: сервер отвечал тревогой
     * 70 (protocol_version). Настоящий сервер в сети обслуживает и тех, и
     * других, и стенд обязан быть таким же. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, argv[2], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((unsigned short)port);
    if (bind(lfd, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); return 1; }
    if (listen(lfd, 64) != 0) { perror("listen"); return 1; }
    printf("labtls: слушаю %d\n", port);
    fflush(stdout);

    for (;;) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0) { continue; }
        pid_t pid = fork();
        if (pid == 0) {
            close(lfd);
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, c);
            if (SSL_accept(ssl) == 1) {
                char buf[2048];
                /* Читаем запрос, но не разбираем: предмет опыта — дошло ли
                   приветствие до сервера, а не что в нём написано. */
                (void)SSL_read(ssl, buf, sizeof buf);
                SSL_write(ssl, RESPONSE, (int)strlen(RESPONSE));
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(c);
            _exit(0);
        }
        close(c);
    }
}
