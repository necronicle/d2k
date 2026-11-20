/* Исполнитель плеча на loopback: исход по сокету (сброс, закрытие, тишина,
 * ответ), путь до сервера, отказ без исполнителя плана, опорная точка. */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include "d2k_netarm.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); fails++; } } while (0)

enum { SILENT, RESET, CLOSE, REPLY };
typedef struct { int lfd, mode; } srv;

static void *serve(void *v)
{
    srv *s = v;
    int c = accept(s->lfd, NULL, NULL);
    if (c < 0) return NULL;
    char buf[4096];
    if (s->mode != SILENT) { ssize_t r = recv(c, buf, sizeof buf, 0); (void)r; }
    if (s->mode == RESET) {
        struct linger lg = {1, 0};
        setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        close(c);
    } else if (s->mode == CLOSE) {
        close(c);
    } else if (s->mode == REPLY) {
        ssize_t w = send(c, "\x15\x03\x03\x00\x02\x02\x28", 7, 0); (void)w;
        usleep(400000);
        close(c);
    } else {
        usleep(1200000);
        close(c);
    }
    return NULL;
}

static uint16_t listen_on(int *lfd)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    *lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(*lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    bind(*lfd, (struct sockaddr *)&a, sizeof a);
    listen(*lfd, 4);
    socklen_t l = sizeof a;
    getsockname(*lfd, (struct sockaddr *)&a, &l);
    return ntohs(a.sin_port);
}

static size_t w16(uint8_t *p, size_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2; }

static size_t hello(uint8_t *out)
{
    uint8_t e[128]; size_t el = 0;
    const char *sni = "lab.example"; size_t n = strlen(sni);
    w16(e, 0); w16(e + 2, n + 5); w16(e + 4, n + 3); e[6] = 0; w16(e + 7, n); memcpy(e + 9, sni, n); el = 9 + n;
    w16(e + el, 51); w16(e + el + 2, 38); w16(e + el + 4, 36); w16(e + el + 6, 0x1d); w16(e + el + 8, 32);
    memset(e + el + 10, 9, 32); el += 42;
    uint8_t body[256]; size_t b = 0;
    b += w16(body + b, 0x0303); memset(body + b, 1, 32); b += 32; body[b++] = 0;
    b += w16(body + b, 2); b += w16(body + b, 0x1301); body[b++] = 1; body[b++] = 0;
    b += w16(body + b, el); memcpy(body + b, e, el); b += el;
    out[0] = 0x16; w16(out + 1, 0x0301); w16(out + 3, b + 4); out[5] = 1; out[6] = 0; w16(out + 7, b);
    memcpy(out + 9, body, b);
    return 9 + b;
}

static d2km_result arm(int mode, d2km_arm_kind kind, int ttl, int reference, const d2km_program *p, int *rc)
{
    srv s;
    uint16_t port = listen_on(&s.lfd);
    s.mode = mode;
    pthread_t th;
    pthread_create(&th, NULL, serve, &s);
    d2k_netarm n = {.family=4,.ip="127.0.0.1",.port=port,.host="lab.example",.path="/",.connect_ms=1000,.exchange_ms=800};
    d2km_net net = d2k_netarm_net(&n);
    static uint8_t h[512];
    size_t hn = hello(h);
    d2km_arm_spec spec = {kind, NULL, h, hn, p, (uint8_t)ttl, reference, 7};
    d2km_observation obs;
    d2km_result res = {0, 0};
    *rc = net.run(net.ctx, &spec, &obs, &res);
    /* Разбудить сервер, если плечо к нему не подключалось. */
    int k = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(port);
    if (reference || p) connect(k, (struct sockaddr *)&a, sizeof a);
    close(k);
    pthread_join(th, NULL);
    close(s.lfd);
    return res;
}

int main(void)
{
    int rc;
    d2km_result r;
    r = arm(SILENT, D2KM_ARM_EXCHANGE, 0, 0, NULL, &rc);
    CHECK(rc == 0 && r.kind == D2KM_R_HELLO_SILENT);
    r = arm(RESET, D2KM_ARM_EXCHANGE, 0, 0, NULL, &rc);
    CHECK(rc == 0 && r.kind == D2KM_R_RST && r.value == 0);
    r = arm(CLOSE, D2KM_ARM_EXCHANGE, 0, 0, NULL, &rc);
    CHECK(rc == 0 && r.kind == D2KM_R_RST && r.value == 1);
    r = arm(REPLY, D2KM_ARM_PATH_BOX, 64, 0, NULL, &rc);
    CHECK(rc == 0 && r.kind == D2KM_R_REPLY);
    r = arm(SILENT, D2KM_ARM_PATH_BOX, 64, 0, NULL, &rc);
    CHECK(rc == 0 && r.kind == D2KM_R_HELLO_SILENT);
    r = arm(RESET, D2KM_ARM_PATH_BOX, 64, 0, NULL, &rc);
    CHECK(rc == 0 && r.kind == D2KM_R_RST);
    r = arm(SILENT, D2KM_ARM_PATH_SERVER, 64, 0, NULL, &rc);
    CHECK(rc == 0 && r.kind == D2KM_R_APP_OK);
    /* Опорной точки нет — не измерено, а не выдуманный ответ. */
    r = arm(SILENT, D2KM_ARM_EXCHANGE, 0, 1, NULL, &rc);
    CHECK(rc == 0 && r.kind == D2KM_R_NOT_MEASURED);
    /* A local install failure enters the task's local retry rule. */
    d2km_program p;
    memset(&p, 0, sizeof p);
    r = arm(SILENT, D2KM_ARM_EXCHANGE, 0, 0, &p, &rc);
    CHECK(rc == 0 && r.kind == D2KM_R_LOCAL_FAIL);
    /* Закрытый порт: сервер отказал сбросом на SYN. */
    int lfd;
    uint16_t port = listen_on(&lfd);
    close(lfd);
    d2k_netarm n = {.family=4,.ip="127.0.0.1",.port=port,.host="lab.example",.path="/",.connect_ms=500,.exchange_ms=500};
    d2km_net net = d2k_netarm_net(&n);
    uint8_t h[512];
    d2km_arm_spec spec = {D2KM_ARM_PATH_SERVER, NULL, h, hello(h), NULL, 64, 0, 7};
    d2km_observation obs;
    CHECK(net.run(net.ctx, &spec, &obs, &r) == 0 && r.kind == D2KM_R_RST);
    if (fails) return 1;
    puts("network arm executor on loopback PASS");
    return 0;
}
