/* sink.c — молчаливая мишень для снятия входов эталона.
 *
 * ЗАЧЕМ. Контрольный зонд — такой же ВХОД замера, как триггер: гипотезы с
 * приманкой берут длину перекрытия РАВНОЙ длине контроля, и приманкой служат
 * его байты. Сверять на разных контролях нельзя ровно по той же причине, по
 * которой нельзя на разных триггерах — замер 14.09 на www.youtube.com разошёлся
 * именно здесь: эталон нашёл «СОБРАНО: всё сразу» с перекрытием в 305 байт,
 * порт на своём контроле в 1534 байта — нет, и упал в запасной перебор.
 *
 * У эталона нет флага, отдающего контроль наружу, а донор править нельзя.
 * Поэтому байты СНИМАЮТСЯ: мишень молчит на всё, дерево эталона доходит до
 * контроля и шлёт его сюда. Третье соединение прогона и есть контроль
 * (первые два — база, она же «целиком»). Дальше они отдаются порту флагом
 * --control-raw.
 *
 * Запуск на роутере (эталон отвергает цель на localhost, поэтому адрес LAN):
 *     /tmp/sink 9443 &
 *     z2k-detect classify -raw 5741060348454c4c4f -repeats 1 -timeout 2s \
 *                192.168.1.1:9443
 *     cat /tmp/sink-3.hex     # 305 байт, ClientHello с именем контроля
 *
 * Случайные поля приветствия (client random, session id) от прогона к прогону
 * разные — сверке это не мешает: длина постоянна, а именно она попадает в
 * параметры приёма. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int fd, n = 0;
    struct sockaddr_in sa;
    int one = 1;
    if (argc < 2) { return 2; }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons((unsigned short)atoi(argv[1]));
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { perror("bind"); return 1; }
    listen(fd, 64);
    printf("мишень на :%s\n", argv[1]);
    fflush(stdout);
    for (;;) {
        static unsigned char buf[65536];
        char path[64];
        FILE *f;
        size_t have = 0;
        ssize_t k;
        struct timeval tv;
        int c = accept(fd, NULL, NULL);
        if (c < 0) { continue; }
        tv.tv_sec = 2; tv.tv_usec = 0;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        while ((k = recv(c, buf + have, sizeof(buf) - have, 0)) > 0) {
            have += (size_t)k;
            if (have >= sizeof(buf)) { break; }
        }
        close(c);
        if (have == 0) { continue; }
        n++;
        snprintf(path, sizeof(path), "/tmp/sink-%d.hex", n);
        f = fopen(path, "w");
        if (f) {
            size_t i;
            for (i = 0; i < have; i++) { fprintf(f, "%02x", buf[i]); }
            fclose(f);
        }
        printf("[%d] %d байт -> %s\n", n, (int)have, path);
        fflush(stdout);
    }
}
