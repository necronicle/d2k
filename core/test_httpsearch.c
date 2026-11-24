/* test_httpsearch.c — поиск обхода открытого HTTP (задача 51, шаг 4). */
/* Файл включают и как текст в составные тесты — после системных заголовков,
   где glibc (с 2026) уже задал _POSIX_C_SOURCE сам: голый #define там —
   переопределение под -Werror (CI 22.10.2026). Отдельной единицей трансляции
   значение задаётся как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
/* struct timeval для SO_RCVTIMEO: у musl её объявляет только sys/time.h, а
   sys/socket.h даёт неполное объявление. Без этого цель cross-runtime-gates
   не собирается под aarch64-linux-musl (проверено 12.10.2026) — то есть
   кросс-гейт, который ловит ошибки формата, молча стоял красным. */
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "d2k_httpsearch.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s (строка %d)\n", m, __LINE__); fails++; } } while (0)

static const char INJECT[] =
    "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://lawfilter.ertelecom.ru\r\n"
    "Connection: close\r\nContent-Length: 13\r\n\r\nlawfilter.ru\n";
static const char REAL[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>";

static void test_judge(void) {
    CHECK(d2k_hs_judge("target.example","HTTP/1.1 200 OK\r\nLocation: http://lawfilter.ertelecom.ru", 53, 1, 5)==D2K_HS_GARBAGE,"incomplete headers cannot prove real server");
    CHECK(d2k_hs_judge("rutracker.org", INJECT, sizeof INJECT - 1, 98000, 700) == D2K_HS_INJECTED,
          "вставка поля не узнана");
    CHECK(d2k_hs_judge("rutracker.org", INJECT, sizeof INJECT - 1, 98000, 120000) == D2K_HS_INJECTED,
          "поздний 302 на портал принят за сервер");
    CHECK(d2k_hs_judge("rutracker.org", REAL, sizeof REAL - 1, 98000, 99000) == D2K_HS_REAL,
          "ответ сервера не узнан");
    CHECK(d2k_hs_judge("rutracker.org", REAL, sizeof REAL - 1, 98000, 1000) == D2K_HS_EARLY,
          "ответ быстрее RTT/2 принят за сервер");
    static const char own[] = "HTTP/1.1 301 Moved\r\nLocation: https://rutracker.org/\r\n\r\n";
    CHECK(d2k_hs_judge("rutracker.org", own, sizeof own - 1, 98000, 99000) == D2K_HS_REAL,
          "редирект сервера на свой https не принят за ответ сервера");
    CHECK(d2k_hs_judge("rutracker.org", "\x16\x03\x01", 3, 98000, 99000) == D2K_HS_GARBAGE,
          "не-HTTP принят за ответ");
    CHECK(d2k_hs_judge("rutracker.org", "HTTP/1.1", 8, 98000, 99000) == D2K_HS_GARBAGE,
          "обрывок строки статуса принят за ответ");
    /* Ответ сервера на ПРИМАНКУ — не ответ цели (повторное ревью I-A). */
    static const char to_decoy[] = "HTTP/1.1 301 Moved\r\nLocation: https://disk.rzd.ru/\r\n\r\n";
    CHECK(d2k_hs_judge("rutracker.org", to_decoy, sizeof to_decoy - 1, 98000, 99000) == D2K_HS_DECOY,
          "ответ с именем приманки принят за ответ цели");
    /* Задача 62: промежуточный 1xx предшествует ОКОНЧАТЕЛЬНОМУ ответу того же
       запроса — судить надо финальный, а не «100». */
    static const char cont200[] = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n";
    CHECK(d2k_hs_judge("rutracker.org", cont200, sizeof cont200 - 1, 98000, 99000) == D2K_HS_REAL,
          "финальный 200 после промежуточного 100 не признан ответом сервера");
    static const char cont421[] = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 421 Misdirected Request\r\n\r\n";
    CHECK(d2k_hs_judge("rutracker.org", cont421, sizeof cont421 - 1, 98000, 99000) == D2K_HS_DECOY,
          "финальный 421 после промежуточного 100 ошибочно признан ответом сервера");
    static const char hints204[] = "HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
    CHECK(d2k_hs_judge("rutracker.org", hints204, sizeof hints204 - 1, 98000, 99000) == D2K_HS_REAL,
          "финальный 204 после 103 не признан ответом сервера");
    static const char cont_only[] = "HTTP/1.1 100 Continue\r\n\r\n";
    CHECK(d2k_hs_judge("rutracker.org", cont_only, sizeof cont_only - 1, 98000, 99000) == D2K_HS_GARBAGE,
          "один промежуточный 100 без финального принят за ответ");
    /* Большой Location (портал с длинным адресом за пределами буфера хоста)
       не крэшит и не выдаётся за портальную вставку. */
    static char biglow[700];
    { int k = snprintf(biglow, sizeof biglow, "HTTP/1.1 302 Found\r\nLocation: http://");
      for (int i = 0; i < 400; i++) biglow[k++] = 'a';
      snprintf(biglow + k, sizeof biglow - (size_t)k, ".lawfilter.example/\r\n\r\n"); }
    d2k_hs_answer big = d2k_hs_judge("rutracker.org", biglow, strlen(biglow), 98000, 99000);
    CHECK(big == D2K_HS_REAL, "непомерный Location ошибочно признан порталом или уронил судью");
    /* Финальный 100-перед-порталом: портал всё равно узнаётся (его статус 30x
       финальный, не промежуточный). */
    static const char cont_portal[] = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302 Found\r\nLocation: http://lawfilter.ertelecom.ru/\r\n\r\n";
    CHECK(d2k_hs_judge("rutracker.org", cont_portal, sizeof cont_portal - 1, 98000, 99000) != D2K_HS_REAL,
          "портал после промежуточного 100 принят за ответ сервера");
    static const char misdirected[] = "HTTP/1.1 421 Misdirected Request\r\n\r\n";
    CHECK(d2k_hs_judge("rutracker.org", misdirected, sizeof misdirected - 1, 98000, 99000) == D2K_HS_DECOY,
          "421 принят за ответ цели");
    static const char bad[] = "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n";
    CHECK(d2k_hs_judge("rutracker.org", bad, sizeof bad - 1, 98000, 99000) == D2K_HS_DECOY,
          "400 (склейка приманки с запросом) принят за ответ цели");
}

/* Кандидаты: каждый — годный план протокола http, исполнимый на запросе. */
static void test_candidates(void) {
    CHECK(d2k_hs_candidate_count() >= 4, "кандидатов меньше заявленных вопросов");
    static const char req[] = "GET / HTTP/1.1\r\nHost: rutracker.org\r\nAccept: */*\r\n\r\n";
    const uint8_t id[16] = {1, 2, 3};
    for (size_t i = 0; i < d2k_hs_candidate_count(); i++) {
        char text[2048];
        const char *k = d2k_hs_candidate_key(i);
        CHECK(k && d2k_hs_candidate_text(k, id, text, sizeof text) == 0, "текст кандидата не собран");
        uint8_t tlv[4096];
        size_t tl = 0;
        char err[200];
        if (d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tl, err, sizeof err) != 0) {
            printf("  %s: %s\n", k, err);
            fails++;
            continue;
        }
        d2k_plan *p = NULL;
        CHECK(d2k_plan_load(tlv, tl, &p, err, sizeof err) == 0 && p, "план кандидата не принят датапатом");
        if (!p) { continue; }
        CHECK(d2k_plan_proto(p) == D2K_PLAN_PROTO_HTTP && d2k_plan_transport(p) == 6,
              "план кандидата не объявляет HTTP поверх TCP");
        CHECK(!memcmp(d2k_plan_id(p), id, 16), "идентификатор плана не тот");
        d2k_pkt in;
        memset(&in, 0, sizeof in);
        in.payload = (const uint8_t *)req;
        in.payload_len = sizeof req - 1;
        in.seq = 1000;
        in.is_http = 1;
        in.have_sni = 1;
        in.sni_off = (size_t)(strstr(req, "rutracker") - req);
        in.sni_len = 13;
        d2k_actions acts;
        CHECK(d2k_plan_apply(p, NULL, &in, &acts) == 0 && acts.n >= 2 &&
              acts.fate == D2K_ORIG_DROP, "кандидат не режет запрос");
        d2k_actions_free(&acts);
        in.is_http = 0;
        CHECK(d2k_plan_apply(p, NULL, &in, &acts) != 0, "HTTP-кандидат исполнился на не-HTTP входе");
        d2k_plan_free(p);
    }
    char text[2048];
    CHECK(d2k_hs_candidate_text("nonsense", id, text, sizeof text) != 0, "неизвестный кандидат собран");
}

/* --- настоящий зонд против местного сервера -------------------------------- */
typedef struct { int fd; const char *answer; int delay_ms; int close_only; } srv;
static void *serve(void *arg) {
    srv *v = arg;
    int c = accept(v->fd, NULL, NULL);
    if (c < 0) { return NULL; }
    char buf[2048];
    (void)recv(c, buf, sizeof buf, 0);
    if (v->delay_ms) {
        struct timespec ts = {0, (long)v->delay_ms * 1000000L};
        nanosleep(&ts, NULL);
    }
    if (v->answer) { (void)send(c, v->answer, strlen(v->answer), 0); }
    if (!v->close_only && !v->answer) { (void)recv(c, buf, sizeof buf, 0); }
    close(c);
    return NULL;
}

static d2k_hs_answer probe_local(const char *answer, int close_only, char *status, size_t cap) {
    /* Ответ — не раньше RTT/2: местный RTT в десятки мкс, задержка 20 мс
       исключает случайный «слишком ранний» ответ. */
    srv v = {socket(AF_INET, SOCK_STREAM, 0), answer, 20, close_only};
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001u);
    socklen_t al = sizeof a;
    int one = 1;
    (void)setsockopt(v.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(v.fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(v.fd, 4) != 0 ||
        getsockname(v.fd, (struct sockaddr *)&a, &al) != 0) { return D2K_HS_NONE; }
    d2k_hs_probe_port = ntohs(a.sin_port);
    pthread_t th;
    pthread_create(&th, NULL, serve, &v);
    d2k_hs_job job;
    memset(&job, 0, sizeof job);
    job.fd = socket(AF_INET, SOCK_STREAM, 0);
    job.family = 4;
    job.addr[0] = 127; job.addr[3] = 1;
    snprintf(job.host, sizeof job.host, "rutracker.org");
    d2k_hs_result r;
    d2k_hs_probe_run(&job, &r);
    close(job.fd);   /* сокет зонда закрывает владелец, а не d2k_hs_probe_run */
    shutdown(v.fd, SHUT_RDWR);
    close(v.fd);
    pthread_join(th, NULL);
    if (status) { snprintf(status, cap, "%s", r.status); }
    return r.answer;
}

typedef struct { int fd; const char *first, *second; const char *path; int matched; int check_first; } ka_srv;
static void *serve_keepalive(void *arg) {
    ka_srv *v=arg; int c=accept(v->fd,NULL,NULL); if(c<0)return NULL;
    struct timeval tv={1,0}; setsockopt(c,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    char buf[2048];
    for(int i=0;i<2;i++) {
        ssize_t got=recv(c,buf,sizeof buf,0);if(got<=0)break;
        if(i==1 || (i==0 && v->check_first)) {
            char expected[1100];int en=snprintf(expected,sizeof expected,"GET %s HTTP/1.1\r\n",v->path?v->path:"/");
            v->matched=got>=en&&!memcmp(buf,expected,(size_t)en);
        }
        struct timespec ts={0,20000000};nanosleep(&ts,NULL);
        const char *answer=i ? v->second : v->first;
        if(!answer)break;
        if(send(c,answer,strlen(answer),0)<0)break;
        if(!v->second)break;
    }
    close(c);return NULL;
}
static d2k_hs_result keepalive_path(const char *first,const char *second,const char *path) {
    ka_srv v={socket(AF_INET,SOCK_STREAM,0),first,second,path,0,0};
    struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(0x7f000001u);
    socklen_t al=sizeof a; CHECK(!bind(v.fd,(struct sockaddr *)&a,sizeof a)&&!listen(v.fd,1),"keepalive listen");
    getsockname(v.fd,(struct sockaddr *)&a,&al);d2k_hs_probe_port=ntohs(a.sin_port);d2k_hs_probe_ms=800;
    pthread_t th;pthread_create(&th,NULL,serve_keepalive,&v);
    d2k_hs_job job={0};job.fd=socket(AF_INET,SOCK_STREAM,0);job.family=4;job.addr[0]=127;job.addr[3]=1;
    snprintf(job.host,sizeof job.host,"target.example");
    if(path)snprintf(job.repeat_path,sizeof job.repeat_path,"%s",path);
    d2k_hs_result r;d2k_hs_probe_run(&job,&r);
    struct sockaddr_in local={0};socklen_t ll=sizeof local;
    CHECK(!getsockname(job.fd,(struct sockaddr *)&local,&ll) &&
        r.local_port==ntohs(local.sin_port) && !memcmp(r.local_ip,&local.sin_addr,4),
        "probe returns its actual connected socket identity");
    close(job.fd);pthread_join(th,NULL);close(v.fd);
    if(path)CHECK(v.matched,"actual second socket request must retain observed path");
    d2k_hs_probe_port=80;d2k_hs_probe_ms=6000;return r;
}
static d2k_hs_result keepalive_local(const char *first,const char *second) { return keepalive_path(first,second,NULL); }
static void test_keepalive_portal(void) {
    const char *complete="HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none";
    d2k_hs_result r=keepalive_local(complete,INJECT);
    CHECK(r.answer==D2K_HS_INJECTED,"first 200 then same-connection portal must reject candidate");
    r=keepalive_path(complete,INJECT,"/False/");
    CHECK(r.answer==D2K_HS_INJECTED,"portal on observed second path rejects candidate");
#ifdef D2K_HS_KEEPALIVE_PROOF
    CHECK(r.complete_responses==1,"portal is not a second complete success");
#endif
    r=keepalive_local(complete,complete);
#ifdef D2K_HS_KEEPALIVE_PROOF
    CHECK(r.answer==D2K_HS_REAL&&r.complete_responses==2,"two framed keepalive replies confirm the connection");
#endif
    r=keepalive_local("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\n\r\n",complete);
#ifdef D2K_HS_KEEPALIVE_PROOF
    CHECK(r.answer==D2K_HS_REAL&&r.complete_responses==2,"chunked first body is drained before second request");
#endif
    r=keepalive_local("HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\nshort",NULL);
#ifdef D2K_HS_KEEPALIVE_PROOF
    CHECK(r.answer!=D2K_HS_REAL&&!r.complete_responses,"truncated body cannot confirm first response");
#endif
    r=keepalive_local("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\none",NULL);
#ifdef D2K_HS_KEEPALIVE_PROOF
    CHECK(r.answer==D2K_HS_REAL&&r.complete_responses==1,"server close preserves single-response verdict without keepalive proof");
#endif
}

static void test_probe(void) {
    d2k_hs_probe_ms = 800;
    char st[64];
    /* Локальный RTT ~0: ответ «раньше RTT/2» невозможен, судит содержимое. */
    CHECK(probe_local(INJECT, 0, st, sizeof st) == D2K_HS_INJECTED, "зонд не узнал вставку");
    CHECK(probe_local(REAL, 0, st, sizeof st) == D2K_HS_REAL && !strcmp(st, "HTTP/1.1 200 OK"),
          "зонд не узнал ответ сервера");
    CHECK(probe_local(NULL, 1, NULL, 0) == D2K_HS_CLOSED, "закрытие без ответа не узнано");
    CHECK(probe_local(NULL, 0, NULL, 0) == D2K_HS_SILENT, "молчание не узнано");
    /* Закрытый порт. */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001u);
    socklen_t al = sizeof a;
    (void)bind(s, (struct sockaddr *)&a, sizeof a);
    (void)getsockname(s, (struct sockaddr *)&a, &al);
    close(s);
    d2k_hs_probe_port = ntohs(a.sin_port);
    d2k_hs_job job;
    memset(&job, 0, sizeof job);
    job.fd = socket(AF_INET, SOCK_STREAM, 0);
    job.family = 4; job.addr[0] = 127; job.addr[3] = 1;
    snprintf(job.host, sizeof job.host, "rutracker.org");
    d2k_hs_result r;
    d2k_hs_probe_run(&job, &r);
    close(job.fd);
    CHECK(r.answer == D2K_HS_CONNECT_FAIL, "отказ соединения не узнан");
    d2k_hs_probe_port = 80;
    d2k_hs_probe_ms = 6000;
}

/* --- машина поиска с подделанным вводом-выводом ----------------------------- */
typedef struct {
    int next_fd, open_n, close_n, set_probe_n, del_probe_n, set_plan_n, del_plan_n, start_n, changed_n;
    uint16_t sport;
    char last_probe_plan[2048], last_plan[2048], last_plan_host[256], said[8192];
    uint8_t trial[16], plan_id[16];
    d2k_hs_job job;
    int fail_ack, hold_install_ack, unknown_delete;
    uint8_t install_id[16];
    d2k_binding_context binding;
} fake;

static int f_open(void *c, uint8_t fam, int *fd, uint16_t *sport) {
    fake *f = c; (void)fam; f->open_n++; *fd = 100 + f->next_fd++; *sport = ++f->sport; return 0;
}
static void f_close(void *c, int fd) { (void)fd; ((fake *)c)->close_n++; }
static int hexval(char c) { return c >= 'a' ? c - 'a' + 10 : c - '0'; }
static int f_set_probe(void *c, const char *h, uint8_t fam, uint16_t sp, const char *text,
                       const uint8_t trial[16]) {
    fake *f = c; (void)h; (void)fam; (void)sp;
    f->set_probe_n++;
    snprintf(f->last_probe_plan, sizeof f->last_probe_plan, "%s", text);
    memcpy(f->trial, trial, 16);
    const char *id = strstr(text, "\nid ");
    if (id) { for (int i = 0; i < 16; i++) f->plan_id[i] = (uint8_t)(hexval(id[4 + 2 * i]) << 4 | hexval(id[5 + 2 * i])); }
    return 0;
}
static int f_del_probe(void *c, const char *h, uint8_t fam, uint16_t sp) {
    (void)h; (void)fam; (void)sp; ((fake *)c)->del_probe_n++; return 0;
}
static int f_set_plan(void *c, const char *h, uint8_t fam, const char *text, const uint8_t token[16]) {
    fake *f = c; f->set_plan_n++;
    memcpy(f->install_id,token,16);
    f->binding.generation++; f->binding.kind=D2K_BIND_NAME; f->binding.family=fam;
    f->binding.shape=D2K_PLAN_SHAPE_HTTP; f->binding.epoch[0]=9;
    snprintf(f->last_plan, sizeof f->last_plan, "%s", text);
    snprintf(f->last_plan_host, sizeof f->last_plan_host, "%s", h);
    return 0;
}
static int f_del_plan(void *c, const char *h, uint8_t fam, const d2k_binding_context *binding) { (void)h; (void)fam; if(!d2k_binding_known(binding))((fake *)c)->unknown_delete++; ((fake *)c)->del_plan_n++; return 0; }
static int f_start(void *c, const d2k_hs_job *j) { fake *f = c; f->start_n++; f->job = *j; return 0; }
static void f_say(void *c, const char *line) {
    fake *f = c;
    size_t n = strlen(f->said);
    if (n < sizeof f->said - 2) { snprintf(f->said + n, sizeof f->said - n, "%s\n", line); }
}
static void f_changed(void *c) { ((fake *)c)->changed_n++; }

/* ОБРЫВ ОТВЕТА (поле 15.10.2026, media5.cdnbase.com): заголовки ответа
   сервера пришли, тело оборвалось раньше Content-Length. Это не «мусор», а
   свой исход — D2K_HS_CUT; в режиме обрыва первый запрос идёт на путь
   ресурса клиента, а не на «/». */
static void test_probe_cut(void) {
    ka_srv v={socket(AF_INET,SOCK_STREAM,0),"HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\nshort",NULL,
              "/media/theme/fast.5.css",0,1};
    struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(0x7f000001u);
    socklen_t al=sizeof a; CHECK(!bind(v.fd,(struct sockaddr *)&a,sizeof a)&&!listen(v.fd,1),"cut listen");
    getsockname(v.fd,(struct sockaddr *)&a,&al);d2k_hs_probe_port=ntohs(a.sin_port);d2k_hs_probe_ms=800;
    pthread_t th;pthread_create(&th,NULL,serve_keepalive,&v);
    d2k_hs_job job={0};job.fd=socket(AF_INET,SOCK_STREAM,0);job.family=4;job.addr[0]=127;job.addr[3]=1;
    snprintf(job.host,sizeof job.host,"media5.cdnbase.com");
    snprintf(job.repeat_path,sizeof job.repeat_path,"/media/theme/fast.5.css");job.cut=1;
    d2k_hs_result r;d2k_hs_probe_run(&job,&r);
    close(job.fd);pthread_join(th,NULL);close(v.fd);
    CHECK(v.matched,"cut mode: the first request goes to the client's resource path");
    CHECK(r.answer==D2K_HS_CUT && !r.complete_responses,"a real header with a short body is a cut, not garbage");
    d2k_hs_probe_port=80;d2k_hs_probe_ms=6000;
}

static d2k_hs_ops ops_of(fake *f) {
    d2k_hs_ops o = {f_open, f_close, f_set_probe, f_del_probe, f_set_plan, f_del_plan,
                    f_start, f_say, f_changed, f};
    return o;
}

static d2k_hs_result res(fake *f,d2k_hs_answer a) {
    d2k_hs_result r;
    memset(&r, 0, sizeof r);
    r.requests_sent=2;r.local_ip[0]=127;r.local_ip[3]=1;r.local_port=ntohs(f->sport);
    r.answer = a; r.rtt_us = 98000; r.reply_us = a == D2K_HS_INJECTED ? 700 : 99000;
#ifdef D2K_HS_KEEPALIVE_PROOF
    r.complete_responses = a == D2K_HS_REAL ? 2 : 0;
#endif
    return r;
}

static const uint8_t IP[16] = {37, 221, 67, 160};

static d2k_ev applied_event(const fake *f,uint64_t execution) {
    d2k_ev e={0};e.kind=D2K_EV_APPLIED;e.family=f->job.family;e.transport=6;
    e.low_ip[0]=127;e.low_ip[3]=1;memcpy(e.high_ip,f->job.addr,16);
    e.low_port=ntohs(f->sport);e.high_port=80;
    memcpy(e.plan_id,f->plan_id,16);memcpy(e.trial_id,f->trial,16);
    e.execution_id=execution;e.execution_binding.epoch[0]=7;e.execution_binding.generation=1;
    e.execution_binding.family=e.family;e.execution_binding.kind=D2K_BIND_NAME;
    e.execution_binding.shape=D2K_PLAN_SHAPE_HTTP;e.execution_binding.temporary=1;
    return e;
}
static void applied_pair(d2k_httpsearch *hs,const fake *f) {
    d2k_ev e=applied_event(f,1);
    (void)d2k_httpsearch_control(hs,&e,0);
    e.execution_id=2;(void)d2k_httpsearch_control(hs,&e,0);
}

/* Одно испытание: подтверждение, зонд, APPLIED (если applied), ответ. */
static void trial(d2k_httpsearch *hs, fake *f, int64_t *now, int applied, d2k_hs_answer a) {
    int before = f->start_n;
    d2k_httpsearch_ack(hs, f->trial, 1, *now += 10);
    CHECK(f->start_n == before + 1 && f->job.fd >= 100, "после подтверждения зонд не запущен своим сокетом");
    if (applied) { applied_pair(hs,f); }
    d2k_hs_result r = res(f,a);
    r.seq = f->job.seq;
    r.fd = f->job.fd;
    d2k_httpsearch_result(hs, &r, *now += 100);
    if(!f->hold_install_ack)d2k_httpsearch_install_ack(hs,f->install_id,1,&f->binding);
}

static unsigned diag_failed,diag_confirmed,diag_direct;
static void diagnostic_capture(void *ctx,const d2k_diag_event *e) {
    (void)ctx;CHECK(!strcmp(e->protocol,"http"),"HTTP diagnostics protocol");
    CHECK(e->id>0 && e->elapsed_ms>=0,"HTTP diagnostic identity/time");
    if(!strcmp(e->outcome,"probe-direct"))diag_direct++;
    if(!strcmp(e->outcome,"failed"))diag_failed++;
    if(!strcmp(e->outcome,"probe-confirmed"))diag_confirmed++;
}
static void test_search(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    d2k_httpsearch_diagnostics(hs,diagnostic_capture,NULL);
    int64_t now = 1000;
    d2k_httpsearch_portal(hs, "www.fast-torrent.ru", 4, IP, now);
    CHECK(f.start_n == 1 && f.set_probe_n == 0, "база: зонд без плана не запущен");
    d2k_hs_result r = res(&f,D2K_HS_INJECTED);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    /* Вопрос 1 — разрез Host. */
    CHECK(f.set_probe_n == 1 && strstr(f.last_probe_plan, "split sni_middle") &&
          strstr(f.last_probe_plan, "proto tcp http") && !strstr(f.last_probe_plan, "fake"),
          "первый вопрос — не разрез Host");
    /* Повторная вставка во время поиска нового поиска не начинает. */
    d2k_httpsearch_portal(hs, "www.fast-torrent.ru", 4, IP, now);
    CHECK(f.set_probe_n == 1 && f.start_n == 1, "повторная вставка сорвала идущий поиск");
    trial(hs, &f, &now, 1, D2K_HS_CONNECT_FAIL); /* local failure -> fallback */
    CHECK(f.del_probe_n == 1 && f.close_n >= 1, "пробный план не снят после испытания");
    /* Вопрос 2 — тот же разрез, хвост первым. */
    CHECK(f.set_probe_n == 2 && strstr(f.last_probe_plan, "order reverse"), "второй вопрос — не обратный порядок");
    /* Исполнения не было — кандидат не судим, идём дальше. */
    trial(hs, &f, &now, 0, D2K_HS_REAL);
    CHECK(f.set_plan_n == 0 && f.set_probe_n == 2, "кандидат без исполнения судим до срока APPLIED");
    d2k_httpsearch_tick(hs, now += 1000);
    CHECK(f.set_plan_n == 0, "кандидат без исполнения на проводе подтверждён");
    CHECK(strstr(f.said, "исполнение каждого запроса на потоке зонда не подтверждено") != NULL,
          "missing execution proof remains unknown");
    /* Вопрос 3 — приманка с испорченной суммой. Отказ датапата — тоже не суд. */
    CHECK(f.set_probe_n == 3 && strstr(f.last_probe_plan, "badsum"), "третий вопрос — не приманка badsum");
    d2k_httpsearch_ack(hs, f.trial, 0, now += 10);
    CHECK(f.start_n == 3, "отвергнутый датапатом кандидат всё равно испытан");
    /* Вопрос 4 — приманка вне окна: настоящий ответ, затем подтверждение. */
    CHECK(f.set_probe_n == 4 && strstr(f.last_probe_plan, "seqshift"), "четвёртый вопрос — не приманка seqshift");
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(f.set_plan_n == 0 && f.set_probe_n == 5 && strstr(f.last_probe_plan, "seqshift"),
          "успех не перепроверен тем же кандидатом");
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(f.set_plan_n == 1 && !strcmp(f.last_plan_host, "www.fast-torrent.ru") &&
          strstr(f.last_plan, "seqshift") && strstr(f.last_plan, "proto tcp http") && f.changed_n == 1,
          "подтверждённый план не поставлен постоянным");
    CHECK(!d2k_httpsearch_busy(hs), "поиск не закончился");
    CHECK(d2k_httpsearch_plan_of(hs, "WWW.FAST-TORRENT.RU", 4) &&
          !strcmp(d2k_httpsearch_plan_of(hs, "www.fast-torrent.ru", 4), "fake-seqshift"),
          "подтверждённый кандидат не запомнен");
    CHECK(f.open_n == f.close_n, "сокеты зондов не закрыты");

    /* Второе имя: сначала свой подтверждённый план. */
    int sp = f.set_probe_n;
    d2k_httpsearch_portal(hs, "rutracker.org", 4, IP, now += 1000);
    r = res(&f,D2K_HS_INJECTED);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == sp + 1 && strstr(f.last_probe_plan, "seqshift"),
          "свой подтверждённый план не испытан первым");
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(f.set_plan_n == 2, "свой план для второго имени не подтверждён");

    /* База без вставки — блокировка не воспроизводится, вопросов нет. */
    sp = f.set_probe_n;
    d2k_httpsearch_portal(hs, "free.example", 4, IP, now += 1000);
    r = res(&f,D2K_HS_REAL);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == sp && !d2k_httpsearch_busy(hs) && strstr(f.said, "не воспроизвод"),
          "поиск начат без воспроизведённой вставки");
    CHECK(diag_direct>0,"working direct HTTP is not a diagnostic failure");
    /* Вставка по имени с планом — перепроверка: план испытан первым. */
    sp = f.set_probe_n;
    d2k_httpsearch_portal(hs, "rutracker.org", 4, IP, now += D2K_HS_RECHECK_MS + 1);
    r = res(&f,D2K_HS_INJECTED);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == sp + 1 && strstr(f.last_probe_plan, "seqshift"), "перепроверка не начата своим планом");
    /* Все вопросы мимо — план снят, имя ждёт D2K_HS_RETRY_MS. */
    for (int i = 0; i < 8 && d2k_httpsearch_busy(hs); i++) { trial(hs, &f, &now, 1, D2K_HS_INJECTED); }
    CHECK(!d2k_httpsearch_busy(hs) && f.del_plan_n == 1 && !d2k_httpsearch_plan_of(hs, "rutracker.org", 4),
          "неработающий план не снят после перепроверки");
    CHECK(diag_failed>0 && diag_confirmed>0,"both HTTP terminal outcomes observed");
    int st = f.start_n;
    d2k_httpsearch_portal(hs, "rutracker.org", 4, IP, now += 1000);
    CHECK(f.start_n == st, "имя без обхода перепроверено раньше срока");

    /* Сроки: нет подтверждения — проба снята, следующий кандидат. */
    d2k_httpsearch_portal(hs, "slow.example", 4, IP, now += 1000);
    r = res(&f,D2K_HS_INJECTED);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    int dp = f.del_probe_n, spn = f.set_probe_n;
    d2k_httpsearch_tick(hs, now += 60000);
    CHECK(f.del_probe_n == dp + 1 && f.set_probe_n == spn + 1, "срок подтверждения не соблюдён");
    d2k_httpsearch_free(hs);
    CHECK(f.open_n == f.close_n, "сокеты зондов не закрыты при освобождении");
}

/* Обрыв без плана (код 4) — поиск на том же пути: база своим зондом,
   воспроизведённый обрыв ведёт к вопросам, обрыв под кандидатом — отказ,
   два полных ответа подряд — план. Полный ответ в базе — поиска нет. */
static void test_cut_search(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    d2k_ev e = {0};
    e.kind = D2K_EV_HTTP_RESPONSE; e.code = 4; e.family = 4; e.transport = 6; e.high_port = 80;
    memcpy(e.high_ip, IP, 16);
    snprintf(e.name, sizeof e.name, "media5.cdnbase.com");
    snprintf(e.live_http_path, sizeof e.live_http_path, "/media/theme/fast.5.css");
    e.live_request_no = 1; e.live_body_bytes = 33120; e.live_http_status = 200;
    CHECK(d2k_httpsearch_control(hs, &e, now) == 1 && f.start_n == 1 && f.job.cut == 1 &&
          !strcmp(f.job.repeat_path, "/media/theme/fast.5.css"),
          "a cut without a plan starts the base on the client's resource path");
    CHECK(strstr(f.said, "обрыв") != NULL, "the base says it is a cut, not a portal");
    d2k_hs_result r = res(&f, D2K_HS_CUT);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == 1, "a reproduced cut leads to the questions");
    int sp = f.set_probe_n;
    trial(hs, &f, &now, 1, D2K_HS_CUT);
    CHECK(f.set_probe_n == sp + 1, "a cut under a candidate is a negative outcome, next candidate");
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(f.set_plan_n == 1 && !strcmp(f.last_plan_host, "media5.cdnbase.com") &&
          d2k_httpsearch_plan_of(hs, "media5.cdnbase.com", 4) != NULL,
          "two complete bodies under a candidate install the plan");
    /* Повтор обрыва по тому же имени во время поиска нового не начинает. */
    int st = f.start_n;
    snprintf(e.name, sizeof e.name, "free.example");
    CHECK(d2k_httpsearch_control(hs, &e, now += 1000) == 1 && f.start_n == st + 1, "second cut name starts");
    sp = f.set_probe_n;
    r = res(&f, D2K_HS_REAL);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == sp && !d2k_httpsearch_busy(hs) && strstr(f.said, "не воспроизвод"),
          "a complete body in the base starts no search");
    d2k_httpsearch_free(hs);
    CHECK(f.open_n == f.close_n, "cut probe sockets closed");
}

static void test_reset_before_response_starts_direct_check(void) {
  for (int code = 5; code <= 6; code++) for (int closed = 0; closed < 2; closed++) {
    fake f = {0};
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    d2k_ev e = {0};
    e.kind = D2K_EV_HTTP_RESPONSE;
    e.code = code;
    e.family = 4;
    e.transport = 6;
    e.high_port = 80;
    memcpy(e.high_ip, IP, 16);
    snprintf(e.name, sizeof e.name, "www.fast-torrent.ru");
    snprintf(e.live_http_path, sizeof e.live_http_path, "/");
    e.live_request_no = 1;
    CHECK(d2k_httpsearch_control(hs, &e, 1000) == 1 && f.start_n == 1 &&
          f.job.cut == 1 && !strcmp(f.job.repeat_path, "/"),
          "a reset or repeated request before response starts an isolated direct check");
    d2k_hs_result r = res(&f, closed ? D2K_HS_CLOSED : D2K_HS_SILENT);
    r.requests_sent = 1;
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, 1100);
    CHECK(f.start_n == 2, "an unanswered direct check is repeated once");
    r = res(&f, closed ? D2K_HS_CLOSED : D2K_HS_SILENT);
    r.requests_sent = 1;
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, 1200);
    CHECK(f.set_probe_n > 0, "a repeated unanswered direct check starts candidate search");
    d2k_httpsearch_free(hs);
  }
}

/* Ревью I-2: неизмеренный поиск не снимает план и не ставит часовую паузу. */
static void base_injected(d2k_httpsearch *hs, fake *f, int64_t *now) {
    d2k_hs_result r = res(f,D2K_HS_INJECTED);
    r.seq = f->job.seq; r.fd = f->job.fd;
    d2k_httpsearch_result(hs, &r, *now += 100);
}

static void permanent_id(const fake *f,uint8_t id[16]) {
    const char *p=strstr(f->last_plan,"\nid ");
    CHECK(p!=NULL,"installed plan has identity");
    memset(id,0,16);
    if(p)for(int i=0;i<16;i++)id[i]=(uint8_t)(hexval(p[4+2*i])*16+hexval(p[5+2*i]));
}

/* Обрыв тела после полноценного ответа сервера: один диагностический повтор,
   сброс ok, требование двух REAL подряд и 5 минут паузы при неудаче. */
static void test_cut_retry_and_inconclusive(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    d2k_httpsearch_portal(hs, "cut.example", 4, IP, now);
    base_injected(hs, &f, &now);

    /* Кандидат 1: "split" */
    CHECK(f.set_probe_n == 1 && strstr(f.last_probe_plan, "split"), "первый кандидат split");
    /* 1. Первый опыт успешен: REAL */
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(f.set_probe_n == 2 && strstr(f.last_probe_plan, "split"), "тот же кандидат split на второй опыт");
    CHECK(f.set_plan_n == 0, "один REAL ещё не подтверждает");

    /* 2. Второй опыт: обрыв тела (CUT) */
    trial(hs, &f, &now, 1, D2K_HS_CUT);
    /* Должен получить ОДИН диагностический повтор ДЛЯ ТОГО ЖЕ кандидата split */
    CHECK(f.set_probe_n == 3 && strstr(f.last_probe_plan, "split"), "CUT после REAL даёт диагностический повтор того же кандидата");
    CHECK(strstr(f.said, "диагностический повтор") != NULL, "в журнале зафиксирован диагностический повтор");
    CHECK(f.set_plan_n == 0, "CUT не подтверждает");

    /* 3. Третий опыт: снова REAL (цепочка REAL -> CUT -> REAL) */
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    /* ok был сброшен в 0, поэтому теперь ok == 1, план НЕ должен подтвердиться! */
    CHECK(f.set_plan_n == 0, "REAL после CUT не подтверждает (ok был сброшен в 0)");
    CHECK(f.set_probe_n == 4 && strstr(f.last_probe_plan, "split"), "тот же кандидат split ждёт подтверждения (второго REAL подряд)");

    /* 4. Четвёртый опыт: снова REAL (цепочка REAL -> CUT -> REAL -> REAL) */
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    /* Теперь ok == 2, подтверждено! */
    CHECK(f.set_plan_n == 1 && !strcmp(f.last_plan_host, "cut.example"), "REAL -> CUT -> REAL -> REAL подтверждает план");
    d2k_httpsearch_free(hs);

    /* Тест 5: REAL -> CUT -> CUT (второй CUT не даёт повтора и переходит дальше),
       а при исчерпании списка candidates с any_had_real назначается 5 минут (D2K_HS_INCONCLUSIVE_MS) */
    memset(&f, 0, sizeof f);
    ops = ops_of(&f);
    hs = d2k_httpsearch_new(&ops);
    now = 1000;
    d2k_httpsearch_portal(hs, "retry.example", 4, IP, now);
    base_injected(hs, &f, &now);

    /* Кандидат 1: REAL, затем CUT (даёт повтор), затем снова CUT (больше повторов нет) */
    CHECK(f.set_probe_n == 1 && strstr(f.last_probe_plan, "split"), "кандидат split");
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    trial(hs, &f, &now, 1, D2K_HS_CUT);
    CHECK(f.set_probe_n == 3 && strstr(f.last_probe_plan, "split"), "диагностический повтор split");
    /* Второй CUT подряд на split */
    trial(hs, &f, &now, 1, D2K_HS_CUT);
    /* Теперь кандидат split должен отпасть, переход к вопросу 2 (fake-badsum-whole) */
    CHECK(f.set_probe_n == 4 && !strstr(f.last_probe_plan, "split"), "второй CUT переводит к следующему кандидату");

    /* Все остальные кандидаты проваливаются тишиной */
    while (d2k_httpsearch_busy(hs)) {
        trial(hs, &f, &now, 1, D2K_HS_SILENT);
    }
    CHECK(f.set_plan_n == 0, "план не подтверждён");
    CHECK(strstr(f.said, "устойчивость не подтверждена") != NULL, "честное сообщение в журнале о неподтверждённой устойчивости");
    CHECK(strstr(f.said, "5 мин") != NULL, "в журнале 5 минут отсрочки");

    /* Проверка отсрочки: до истечения 5 минут новый поиск по retry.example не начинается */
    int st = f.start_n;
    d2k_httpsearch_portal(hs, "retry.example", 4, IP, now + 1000);
    CHECK(f.start_n == st, "поиск до истечения 5 минут не начат");
    /* После истечения D2K_HS_INCONCLUSIVE_MS — поиск разрешён */
    d2k_httpsearch_portal(hs, "retry.example", 4, IP, now + D2K_HS_INCONCLUSIVE_MS + 10);
    CHECK(f.start_n == st + 1, "поиск после 5 минут начат");

    d2k_httpsearch_free(hs);

    /* Тест 6: any_had_real + conflicts: конфликт с живым отказом имеет приоритет над 5 минутами (получает 60 мин) */
    memset(&f, 0, sizeof f);
    ops = ops_of(&f);
    hs = d2k_httpsearch_new(&ops);
    now = 1000;
    d2k_httpsearch_portal(hs, "conflict-real.example", 4, IP, now);
    base_injected(hs, &f, &now);
    /* Кандидат 1 дал REAL (any_had_real = 1) */
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(f.set_plan_n == 1, "первый кандидат подтверждён");
    uint8_t id[16];
    permanent_id(&f, id);
    /* Вносим живой отказ под этой привязкой */
    CHECK(d2k_httpsearch_bound_failure(hs, "conflict-real.example", 4, IP, id, &f.binding,
          999, now + 1, "/test", now + 2), "bound failure registered");
    /* Запускаем новый поиск */
    base_injected(hs, &f, &now);
    /* Кандидат 1 (свой план) снова даёт REAL, но у него конфликт с живым отказом -> conflicts++ */
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    /* Все остальные проваливаются тишиной */
    while (d2k_httpsearch_busy(hs)) {
        trial(hs, &f, &now, 1, D2K_HS_SILENT);
    }
    CHECK(strstr(f.said, "живой отказ в области привязки") != NULL, "приоритет сообщения о конфликте");
    /* Проверяем, что отсрочка именно 60 минут, а не 5 минут: через 5 минут поиск ещё НЕ должен начинаться */
    st = f.start_n;
    d2k_httpsearch_portal(hs, "conflict-real.example", 4, IP, now + D2K_HS_INCONCLUSIVE_MS + 10);
    CHECK(f.start_n == st, "при конфликте отсрочка не 5 минут, а 60 минут");
    d2k_httpsearch_portal(hs, "conflict-real.example", 4, IP, now + D2K_HS_RETRY_MS + 10);
    CHECK(f.start_n == st + 1, "после 60 минут поиск разрешён");
    d2k_httpsearch_free(hs);
}
static void test_inconclusive(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    /* Первый поиск: датапат отверг все пробы — не измерено. */
    d2k_httpsearch_portal(hs, "a.example", 4, IP, now);
    base_injected(hs, &f, &now);
    for (int i = 0; i < 8 && d2k_httpsearch_busy(hs); i++) {
        d2k_httpsearch_ack(hs, f.trial, 0, now += 10);
    }
    CHECK(!d2k_httpsearch_busy(hs) && strstr(f.said, "не измерен") && !strstr(f.said, "обход не найден"),
          "отказы датапата названы «обход не найден»");
    int st = f.start_n;
    d2k_httpsearch_portal(hs, "a.example", 4, IP, now + D2K_HS_INCONCLUSIVE_MS + 1);
    CHECK(f.start_n == st + 1, "после неизмеренного поиска повтор отложен на час");
    while (d2k_httpsearch_busy(hs)) { d2k_httpsearch_tick(hs, now += 60000); }

    /* Перепроверка подтверждённого плана, где ни одно исполнение не
       подтвердилось (APPLIED потерян) — план остаётся. */
    now += 10 * D2K_HS_RETRY_MS;
    d2k_httpsearch_portal(hs, "b.example", 4, IP, now);
    base_injected(hs, &f, &now);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(d2k_httpsearch_plan_of(hs, "b.example", 4) != NULL, "план b.example не подтверждён");
    d2k_httpsearch_portal(hs, "b.example", 4, IP, now += D2K_HS_RECHECK_MS + 1);
    base_injected(hs, &f, &now);
    for (int i = 0; i < 8 && d2k_httpsearch_busy(hs); i++) {
        trial(hs, &f, &now, 0, D2K_HS_INJECTED);
        d2k_httpsearch_tick(hs, now += 1000);
    }
    CHECK(!d2k_httpsearch_busy(hs) && f.del_plan_n == 0 && d2k_httpsearch_plan_of(hs, "b.example", 4),
          "перепроверка без единого исполнения сняла план");
    d2k_httpsearch_free(hs);
}

/* Измеренная порча (каталог TLS-коробок этой линии) — вместо заготовок. */
static void test_measured_poison(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    CHECK(d2k_httpsearch_measured_poison(hs, "ttl=5 badsum") == 0, "измеренная порча не принята");
    CHECK(d2k_httpsearch_measured_poison(hs, "tcpts") != 0, "порча, которую HTTP-исполнитель не повторит, принята");
    /* Одна ttl приманку до сервера не останавливает наверняка: HTTP-сервер
       бывает ближе TLS-сервера, по которому ttl подбирали (повторное ревью
       I-A). Только вместе с badsum или seqshift. */
    CHECK(d2k_httpsearch_measured_poison(hs, "ttl=5") != 0, "приманка только с ttl принята");
    CHECK(d2k_httpsearch_measured_poison(hs, "ttl=6 seqshift=-66000") == 0, "ttl+seqshift не принята");
    CHECK(d2k_httpsearch_measured_poison(hs, "badsum") == 0, "измеренная badsum не принята");
    int64_t now = 1000;
    d2k_httpsearch_portal(hs, "c.example", 4, IP, now);
    base_injected(hs, &f, &now);
    trial(hs, &f, &now, 1, D2K_HS_CONNECT_FAIL);   /* split unmeasured -> fallback */
    trial(hs, &f, &now, 1, D2K_HS_INJECTED);   /* disorder */
    CHECK(strstr(f.last_probe_plan, "fake payload=1") && strstr(f.last_probe_plan, "ttl=5") &&
          strstr(f.last_probe_plan, "badsum"), "третий вопрос — не измеренная порча");
    trial(hs, &f, &now, 1, D2K_HS_INJECTED);
    CHECK(strstr(f.last_probe_plan, "ttl=6") && strstr(f.last_probe_plan, "seqshift=-66000"),
          "четвёртый вопрос — не вторая измеренная порча");
    trial(hs, &f, &now, 1, D2K_HS_INJECTED);
    CHECK(strstr(f.last_probe_plan, "badsum") && !strstr(f.last_probe_plan, "ttl="),
          "пятый вопрос — не третья измеренная порча");
    trial(hs, &f, &now, 1, D2K_HS_INJECTED);
    CHECK(!d2k_httpsearch_busy(hs), "при измеренной порче заданы и заготовки");
    /* Извлечение из текста подтверждённого TLS-плана (как в каталоге). */
    static const char tls[] = "d2k-plan 1 1\nid 00\nproto tcp tls\npayload 1 16\npayload 2 41\n"
        "poison 1 badsum\npoison 2 ttl=4\nsplit hello_middle +0\n"
        "fake payload=1 poison=1 repeats=2 gap_us=20000 place=before\n"
        "seqovl payload=2 poison=2\norder reverse\n";
    char sp[8][64];
    CHECK(d2k_hs_plan_poisons(tls, sp, 8) == 1 && !strcmp(sp[0], "badsum"),
          "порча приманки не извлечена или взята порча перекрытия");
    CHECK(d2k_hs_plan_poisons("d2k-plan 1 11\nid 00\nproto tcp http\npoison 1 badsum\n"
                              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n", sp, 8) == 0,
          "порча взята из не-TLS плана");
    char text[2048];
    const uint8_t id[16] = {1};
    CHECK(d2k_hs_candidate_text("fake:ttl=5+badsum", id, text, sizeof text) == 0 &&
          strstr(text, "poison 1 ttl=5 badsum"), "ключ измеренной порчи не собирается в план");
    CHECK(d2k_hs_candidate_text("fake:tcpts", id, text, sizeof text) != 0, "негодный ключ порчи собран");
    CHECK(d2k_hs_candidate_text("fake:ttl=5", id, text, sizeof text) != 0,
          "ключ приманки только с ttl собран (например, из старого http-plans.txt)");
    d2k_httpsearch_free(hs);
}

/* Ревью M-7: ответ чужого (устаревшего) зонда не судит текущий опыт. */
static void test_stale_result(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    d2k_httpsearch_portal(hs, "d.example", 4, IP, now);
    d2k_hs_result r = res(&f,D2K_HS_INJECTED);
    r.seq = f.job.seq + 7; r.fd = 999;
    int cl = f.close_n;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == 0 && f.close_n == cl + 1, "ответ чужого зонда принят или его сокет не закрыт");
    d2k_httpsearch_free(hs);
}

static void test_persist(void) {
    char path[] = "/tmp/d2k-http-plansXXXXXX";
    int fd = mkstemp(path);
    close(fd);
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    d2k_httpsearch_portal(hs, "www.fast-torrent.ru", 6, IP, now);
    d2k_hs_result r = res(&f,D2K_HS_INJECTED);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    char err[256];
    CHECK(d2k_httpsearch_save(hs, path, 1700000000, err, sizeof err) == 0, "планы не сохранены");
    d2k_httpsearch_free(hs);

    memset(&f, 0, sizeof f);
    hs = d2k_httpsearch_new(&ops);
    size_t n = 0;
    CHECK(d2k_httpsearch_load(hs, path, &n, err, sizeof err) == 0 && n == 1 && f.set_plan_n == 1 &&
          !strcmp(f.last_plan_host, "www.fast-torrent.ru") && strstr(f.last_plan, "split sni_middle"),
          "план не восстановлен после перезапуска");
    CHECK(d2k_httpsearch_plan_of(hs, "www.fast-torrent.ru", 6) && !d2k_httpsearch_plan_of(hs, "www.fast-torrent.ru", 4),
          "семейство плана потеряно");
    d2k_httpsearch_push_all(hs);
    CHECK(f.set_plan_n == 2, "переустановка планов не сработала");
    d2k_httpsearch_free(hs);

    FILE *g = fopen(path, "w");
    fprintf(g, "d2k-http-plans 1\nok.example 4 split 1700000000\nbad name 4 split 1\n"
               "x.example 4 nonsense 1\ny.example 5 split 1\nz.example 4 split\n");
    fclose(g);
    memset(&f, 0, sizeof f);
    hs = d2k_httpsearch_new(&ops);
    CHECK(d2k_httpsearch_load(hs, path, &n, err, sizeof err) == 0 && n == 1 && f.set_plan_n == 1,
          "негодные строки не пропущены");
    d2k_httpsearch_free(hs);
    g = fopen(path, "w");
    fprintf(g, "{}\n");
    fclose(g);
    memset(&f, 0, sizeof f);
    hs = d2k_httpsearch_new(&ops);
    CHECK(d2k_httpsearch_load(hs, path, &n, err, sizeof err) == -1 && f.set_plan_n == 0, "чужой файл принят");
    d2k_httpsearch_free(hs);
    unlink(path);
    hs = d2k_httpsearch_new(&ops);
    CHECK(d2k_httpsearch_load(hs, path, &n, err, sizeof err) == 0 && n == 0, "нет файла — не пустой список");
    d2k_httpsearch_free(hs);
}

static void test_portal_properties(void) {
    fake f={0}; d2k_hs_ops ops=ops_of(&f);
    d2k_httpsearch *hs=d2k_httpsearch_new(&ops);
    int64_t now=1;
    d2k_httpsearch_portal(hs,"portal-target.example",4,IP,now);
    d2k_hs_result r=res(&f,D2K_HS_INJECTED); r.seq=f.job.seq; r.fd=f.job.fd;
    d2k_httpsearch_result(hs,&r,++now);
    CHECK(strstr(f.last_probe_plan,"split sni_middle") && !strstr(f.last_probe_plan,"fake "),"property: split control");
    trial(hs,&f,&now,1,D2K_HS_SILENT);
    CHECK(strstr(f.last_probe_plan,"badsum") && !strstr(f.last_probe_plan,"split "),"property: pure checksum question, unchanged real request");
    trial(hs,&f,&now,1,D2K_HS_INJECTED);
    CHECK(strstr(f.last_probe_plan,"badsum") && strstr(f.last_probe_plan,"split sni_middle"),"property: measured two NOs ask product, not disorder");
    trial(hs,&f,&now,1,D2K_HS_REAL);
    CHECK(!f.set_plan_n,"one header response does not confirm question");
    trial(hs,&f,&now,1,D2K_HS_REAL);
    CHECK(f.set_plan_n==1 && strstr(f.said,"путь: свойство") && f.set_probe_n==4,"portal property must confirm exact composite before fallback");
    d2k_httpsearch_free(hs);
}

static void test_reused_property_answer(void) {
    fake f={0}; d2k_hs_ops ops=ops_of(&f);
    d2k_httpsearch *hs=d2k_httpsearch_new(&ops); int64_t now=1;
    d2k_httpsearch_portal(hs,"saved.example",4,IP,now); base_injected(hs,&f,&now);
    trial(hs,&f,&now,1,D2K_HS_REAL); trial(hs,&f,&now,1,D2K_HS_REAL);
    d2k_httpsearch_portal(hs,"saved.example",4,IP,now+=1);
    base_injected(hs,&f,&now); trial(hs,&f,&now,1,D2K_HS_SILENT);
    CHECK(strstr(f.last_probe_plan,"badsum") && !strstr(f.last_probe_plan,"split "),
          "saved split NO must advance to checksum, not skip properties through dedup");
    d2k_httpsearch_free(hs);
}

#ifdef D2K_HS_KEEPALIVE_PROOF
static void test_single_response_not_confirmation(void) {
    fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
    d2k_httpsearch_portal(hs,"short.example",4,IP,now);base_injected(hs,&f,&now);
    for(int i=0;i<2;i++) {
        d2k_httpsearch_ack(hs,f.trial,1,now+=10);applied_pair(hs,&f);
        d2k_hs_result r=res(&f,D2K_HS_REAL);r.complete_responses=1;r.fd=f.job.fd;r.seq=f.job.seq;
        d2k_httpsearch_result(hs,&r,now+=100);
    }
    CHECK(!f.set_plan_n,"two fresh single responses do not prove keepalive");
    d2k_httpsearch_free(hs);
}

static void test_failed_reinstall_keeps_owner(void) {
    fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
    d2k_httpsearch_portal(hs,"nack.example",4,IP,now);base_injected(hs,&f,&now);
    trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
    d2k_binding_context installed=f.binding;uint8_t id[16];const char *s=strstr(f.last_plan,"\nid ");
    CHECK(s!=NULL,"NACK owner fixture");
    if(s)for(int i=0;i<16;i++)id[i]=(uint8_t)(hexval(s[4+2*i])*16+hexval(s[5+2*i]));
    d2k_httpsearch_push_all(hs);
    CHECK(!d2k_httpsearch_bound_failure(hs,"nack.example",4,IP,id,&installed,1,now+1,"",now+2),
          "pending replacement cannot accept old binding failure");
    d2k_httpsearch_install_ack(hs,f.install_id,0,&f.binding);
    CHECK(d2k_httpsearch_bound_failure(hs,"nack.example",4,IP,id,&installed,1,now+1,"",now+2)==1,
          "matched NACK must retain last ACKed installation ownership");
    CHECK(f.del_plan_n==1&&!f.unknown_delete,"failed reinstall still permits own exact cleanup");
    d2k_httpsearch_free(hs);
    /* If an earlier SET was never ACKed, a later NACK cannot prove that
       the original installation is still current. */
    memset(&f,0,sizeof f);ops=ops_of(&f);hs=d2k_httpsearch_new(&ops);now=1;
    d2k_httpsearch_portal(hs,"overlap.example",4,IP,now);base_injected(hs,&f,&now);
    trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
    installed=f.binding;s=strstr(f.last_plan,"\nid ");
    if(s)for(int i=0;i<16;i++)id[i]=(uint8_t)(hexval(s[4+2*i])*16+hexval(s[5+2*i]));
    d2k_httpsearch_push_all(hs);d2k_httpsearch_push_all(hs);
    d2k_httpsearch_install_ack(hs,f.install_id,0,&f.binding);
    CHECK(!d2k_httpsearch_bound_failure(hs,"overlap.example",4,IP,id,&installed,1,now+1,"",now+2),
          "NACK after unobserved replacement cannot resurrect stale ownership");
    d2k_httpsearch_free(hs);
}

static void test_pending_revoke(void) {
    fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
    d2k_httpsearch_portal(hs,"pending-revoke.example",4,IP,now);base_injected(hs,&f,&now);
    trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
    f.hold_install_ack=1;d2k_httpsearch_push_all(hs);
    uint8_t token[16];memcpy(token,f.install_id,16);
    d2k_httpsearch_portal(hs,"pending-revoke.example",4,IP,now+=D2K_HS_RECHECK_MS+1);
    base_injected(hs,&f,&now);
    for(int i=0;i<20 && d2k_httpsearch_busy(hs);i++)trial(hs,&f,&now,1,D2K_HS_INJECTED);
    CHECK(!d2k_httpsearch_busy(hs)&&!d2k_httpsearch_plan_of(hs,"pending-revoke.example",4),"pending revoke reaches judged failure");
    CHECK(!f.unknown_delete,"cannot delete a pending installation without its binding");
    int deleted=f.del_plan_n;
    d2k_httpsearch_install_ack(hs,token,1,&f.binding);
    CHECK(f.del_plan_n==deleted+1&&!f.unknown_delete,"late SET ACK must complete pending exact revocation");
    d2k_httpsearch_free(hs);
}

static void test_live_failure_outweighs_probe(void) {
    for(int family=4;family<=6;family+=2) {
        fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);
        int64_t now=1;uint8_t id[16],addr[16]={0};
        if(family==4)memcpy(addr,IP,4);else inet_pton(AF_INET6,"2001:db8::80",addr);
        d2k_httpsearch_portal(hs,"conflict.example",family,addr,now);base_injected(hs,&f,&now);
        trial(hs,&f,&now,1,D2K_HS_INJECTED); /* split alone failed */
        trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
        CHECK(d2k_httpsearch_plan_of(hs,"conflict.example",family) &&
            !strcmp(d2k_httpsearch_plan_of(hs,"conflict.example",family),"fake-badsum-whole"),
            "fixture selected measured checksum whole candidate");
        permanent_id(&f,id);int installed=f.set_plan_n;
        CHECK(d2k_httpsearch_bound_failure(hs,"conflict.example",family,addr,id,&f.binding,
            501,now+1,"/False/",now+2),"exact live portal invalidates checksum candidate");
        base_injected(hs,&f,&now);
        trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
        CHECK(f.set_plan_n==installed && !d2k_httpsearch_plan_of(hs,"conflict.example",family),
            "two probe successes cannot reinstall a candidate disproved on its live flow");
        CHECK(d2k_httpsearch_busy(hs) && strstr(f.last_probe_plan,"split sni_middle") &&
            !strstr(f.last_probe_plan,"fake "),"conflict continues to another measured question");
        CHECK(strstr(f.said,"живой отказ") && strstr(f.said,"зонд"),"probe/live conflict is visible");
        d2k_httpsearch_free(hs);
    }
}

static void test_live_failure_history(void) {
    fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);
    int64_t now=1;uint8_t id[16];char failed[12][40];size_t nfailed=0;
    d2k_httpsearch_portal(hs,"history.example",4,IP,now);base_injected(hs,&f,&now);
    /* Every simplified probe passes. Each newly installed program is then
       disproved by its exact live portal. Search must not cycle A -> B -> A. */
    for(size_t round=0;round<8;round++) {
        for(size_t attempts=0;d2k_httpsearch_busy(hs)&&attempts<32;attempts++)
            trial(hs,&f,&now,1,D2K_HS_REAL);
        CHECK(!d2k_httpsearch_busy(hs),"finite candidate set terminates each search");
        const char *key=d2k_httpsearch_plan_of(hs,"history.example",4);
        if(!key)break;
        int duplicate=0;
        for(size_t i=0;i<nfailed;i++)if(!strcmp(key,failed[i]))duplicate=1;
        CHECK(!duplicate,"a different accepted candidate cannot erase older live failures");
        snprintf(failed[nfailed++],sizeof failed[0],"%s",key);
        permanent_id(&f,id);
        CHECK(d2k_httpsearch_bound_failure(hs,"history.example",4,IP,id,&f.binding,
            600+round,now+1,"/False/",now+2),"history failure belongs to actual current installation");
        base_injected(hs,&f,&now);
    }
    CHECK(nfailed>=2 && !d2k_httpsearch_plan_of(hs,"history.example",4) &&
          !d2k_httpsearch_busy(hs),"exhausted live-disproved programs remain unconfirmed");
    int sets=f.set_plan_n;d2k_httpsearch_push_all(hs);
    CHECK(f.set_plan_n==sets,"push_all cannot restore a live-disproved program");
    /* A different address can be measured, but a NAME-wide installation
       would also return this program to the old, disproved address. */
    uint8_t other[16];memcpy(other,IP,16);other[3]++;
    now+=3600000;d2k_httpsearch_portal(hs,"history.example",4,other,now);
    base_injected(hs,&f,&now);trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
    CHECK(!d2k_httpsearch_plan_of(hs,"history.example",4) && f.set_plan_n==sets &&
          d2k_httpsearch_busy(hs),
          "another IP's probe cannot restore a failed program through a name-wide binding");
    d2k_httpsearch_free(hs);
}

static void test_live_failure_alias(void) {
    const char *keys[][2]={{"fake-badsum","fake:badsum"},
                           {"fake:ttl=03+badsum","fake:ttl=3+badsum"}};
    for(size_t k=0;k<sizeof keys/sizeof keys[0];k++) {
        fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);
        char path[]="/tmp/d2k-http-alias-XXXXXX",err[200];int fd=mkstemp(path);
        CHECK(fd>=0,"alias fixture file");if(fd<0){d2k_httpsearch_free(hs);continue;}close(fd);
        FILE *file=fopen(path,"w");CHECK(file!=NULL,"alias target fixture");
        if(!file){unlink(path);d2k_httpsearch_free(hs);continue;}
        fprintf(file,"d2k-http-plans 1\nalias-target.example 4 %s 1\n",keys[k][0]);fclose(file);
        size_t loaded=0;
        CHECK(!d2k_httpsearch_load(hs,path,&loaded,err,sizeof err)&&loaded==1,"load target candidate");
        d2k_httpsearch_install_ack(hs,f.install_id,1,&f.binding);
        uint8_t id[16];permanent_id(&f,id);d2k_binding_context owner=f.binding;
        file=fopen(path,"w");CHECK(file!=NULL,"alias source fixture");
        if(!file){unlink(path);d2k_httpsearch_free(hs);continue;}
        fprintf(file,"d2k-http-plans 1\nalias-source.example 4 %s 2\n",keys[k][1]);fclose(file);
        CHECK(!d2k_httpsearch_load(hs,path,&loaded,err,sizeof err)&&loaded==1,"load reusable alias candidate");
        d2k_httpsearch_install_ack(hs,f.install_id,1,&f.binding);unlink(path);
        int sets=f.set_plan_n;int64_t now=1;
        CHECK(d2k_httpsearch_bound_failure(hs,"alias-target.example",4,IP,id,&owner,
              800,now+1,"/False/",now+2),"alias fixture records owned live failure");
        base_injected(hs,&f,&now);
        /* Own program and the same program under another stored key. */
#ifdef D2K_TEST_HTTP_COMPARE_FAILURE
        compare_fault=1;
#endif
        for(int i=0;i<4;i++)trial(hs,&f,&now,1,D2K_HS_REAL);
        CHECK(f.set_plan_n==sets && !d2k_httpsearch_plan_of(hs,"alias-target.example",4),
              "alternate spelling cannot republish the same live-disproved program");
#ifdef D2K_TEST_HTTP_COMPARE_FAILURE
        compare_fault=0;
        CHECK(!d2k_httpsearch_busy(hs) && strstr(f.said,"сравнение программ неизвестно"),
              "compiler failure stops publication with an explicit unknown result");
        d2k_httpsearch_push_all(hs);
        d2k_httpsearch_portal(hs,"alias-target.example",4,IP,now+3600000);
        CHECK(!d2k_httpsearch_busy(hs) && f.set_plan_n==sets+1 &&
              !d2k_httpsearch_plan_of(hs,"alias-target.example",4),
              "later compiler recovery cannot erase the evidence gap; only source name is pushed");
#endif
        d2k_httpsearch_free(hs);
    }
}

static void test_bound_failure(void) {
    /* Writing SET_NAME is not an installation ACK. A portal from the old
       binding may start after that write and arrive after replacement. */
    {
        fake pending={0}; pending.hold_install_ack=1; d2k_hs_ops ops=ops_of(&pending);
        d2k_httpsearch *hs=d2k_httpsearch_new(&ops); int64_t now=1;
        d2k_httpsearch_portal(hs,"pending.example",4,IP,now);
        base_injected(hs,&pending,&now);
        trial(hs,&pending,&now,1,D2K_HS_REAL);
        trial(hs,&pending,&now,1,D2K_HS_REAL);
        uint8_t id[16]; const char *s=strstr(pending.last_plan,"\nid ");
        CHECK(s!=NULL,"pending install fixture");
        if(s) for(int i=0;i<16;i++)id[i]=(uint8_t)(hexval(s[4+2*i])*16+hexval(s[5+2*i]));
        CHECK(s && !d2k_httpsearch_bound_failure(hs,"pending.example",4,IP,id,&pending.binding,1,
              now+1,"/False/",now+2) && !pending.del_plan_n,
              "unacknowledged replacement accepted old live failure");
        uint8_t old_token[16];memcpy(old_token,pending.install_id,16);
        d2k_httpsearch_push_all(hs);
        d2k_httpsearch_install_ack(hs,old_token,0,&pending.binding);
        d2k_httpsearch_install_ack(hs,old_token,1,&pending.binding);
        CHECK(!d2k_httpsearch_bound_failure(hs,"pending.example",4,IP,id,&pending.binding,1,now+1,"",now+2),
              "late ACK/NACK cannot bind or cancel a new pending install");
        d2k_httpsearch_install_ack(hs,pending.install_id,0,&pending.binding);
        CHECK(!d2k_httpsearch_bound_failure(hs,"pending.example",4,IP,id,&pending.binding,1,now+1,"",now+2),
              "NACK cannot assign its supplied binding");
        d2k_httpsearch_push_all(hs);
        d2k_httpsearch_install_ack(hs,pending.install_id,1,&pending.binding);
        CHECK(d2k_httpsearch_bound_failure(hs,"pending.example",4,IP,id,&pending.binding,1,now+1,"",now+2)==1,
              "fresh own ACK enables exact live revocation");
        d2k_httpsearch_free(hs);
    }
    fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
    d2k_httpsearch_portal(hs,"bound.example",4,IP,now);base_injected(hs,&f,&now);
    trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
    uint8_t id[16];const char *textid=strstr(f.last_plan,"\nid ");
    CHECK(textid!=NULL,"permanent id present");
    for(int i=0;i<16;i++)id[i]=(uint8_t)(hexval(textid[4+i*2])*16+hexval(textid[5+i*2]));
    id[0]^=1;
    CHECK(!d2k_httpsearch_bound_failure(hs,"bound.example",4,IP,id,&f.binding,1,now+1,"/False/",now+2)&&!f.del_plan_n,"foreign plan failure cannot revoke own plan");
    id[0]^=1;
    CHECK(!d2k_httpsearch_bound_failure(hs,"bound.example",6,IP,id,&f.binding,1,now+1,"/False/",now+2)&&!f.del_plan_n,"other family cannot revoke own plan");
    CHECK(d2k_httpsearch_bound_failure(hs,"bound.example",4,IP,id,&f.binding,1,now+1,"/False/",now+2)==1,"bound live portal must revoke confirmed success");
    CHECK(f.del_plan_n==1&&!d2k_httpsearch_plan_of(hs,"bound.example",4)&&d2k_httpsearch_busy(hs),"revoked plan hidden and remeasurement started immediately");
    CHECK(!d2k_httpsearch_bound_failure(hs,"bound.example",4,IP,id,&f.binding,1,now+1,"/False/",now+2)&&f.del_plan_n==1,"duplicate failure cannot delete again");
    CHECK(!strcmp(f.job.repeat_path,"/False/"),"bound observed path must reach baseline probe");
    base_injected(hs,&f,&now);
    d2k_httpsearch_ack(hs,f.trial,1,now+=10);
    CHECK(!strcmp(f.job.repeat_path,"/False/"),"bound observed path must reach candidate probe");
    /* Finish this already started candidate before using the trial helper. */
    applied_pair(hs,&f);d2k_hs_result first=res(&f,D2K_HS_REAL);first.fd=f.job.fd;first.seq=f.job.seq;
    d2k_httpsearch_result(hs,&first,now+=100);
    CHECK(strstr(f.last_probe_plan,"split ")!=NULL,"revoked old plan remains first hypothesis");
    int64_t old_request=now;
    d2k_binding_context old_binding=f.binding;
    trial(hs,&f,&now,1,D2K_HS_REAL);
    CHECK(!d2k_httpsearch_plan_of(hs,"bound.example",4),"old live failure survives repeated probe success");
    CHECK(strstr(f.last_probe_plan,"fake ") && !strstr(f.last_probe_plan,"split "),
          "live-disproved split continues to measured checksum-whole question, not fallback");
    trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
    CHECK(d2k_httpsearch_plan_of(hs,"bound.example",4)!=NULL,"different program may become a new candidate");
    permanent_id(&f,id);old_binding=f.binding;
    d2k_httpsearch_push_all(hs);d2k_httpsearch_install_ack(hs,f.install_id,1,&f.binding);
    int deleted=f.del_plan_n;
    CHECK(!d2k_httpsearch_bound_failure(hs,"bound.example",4,IP,id,&old_binding,1,old_request,"/False/",now+1)&&f.del_plan_n==deleted,
          "same-hash old request cannot revoke a newly confirmed generation");
    d2k_httpsearch_free(hs);
}

#endif

static void test_missing_repro_context(void) {
    char too_long[1025];memset(too_long,'a',sizeof too_long-1);too_long[0]='/';too_long[sizeof too_long-1]=0;
    const char *invalid[]={too_long,"", "/?token=hidden", "/a#fragment", "http://other/", "/bad\r\nInjected:x"};
    for(size_t k=0;k<sizeof invalid/sizeof invalid[0];k++) {
        fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
        d2k_httpsearch_portal(hs,"context.example",4,IP,now);base_injected(hs,&f,&now);
        trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
        uint8_t id[16];const char *idtext=strstr(f.last_plan,"\nid ");
        for(int i=0;i<16;i++)id[i]=(uint8_t)(hexval(idtext[4+2*i])*16+hexval(idtext[5+2*i]));
        int starts=f.start_n;
        CHECK(d2k_httpsearch_bound_failure(hs,"context.example",4,IP,id,&f.binding,1,now+1,invalid[k],now+2)==1,"lost context still revokes success");
        d2k_httpsearch_portal(hs,"context.example",4,IP,now+3);
        CHECK(!d2k_httpsearch_plan_of(hs,"context.example",4)&&f.start_n==starts&&!d2k_httpsearch_busy(hs),"unsupported context cannot silently become GET /");
        CHECK(!strstr(f.said,"hidden")&&!strstr(f.said,"Injected:x"),"request values are not logged");
        d2k_httpsearch_free(hs);
    }
}

/* An APPLIED from just the first request is not proof for the second. */
static void test_each_request_execution(void) {
    fake f={0};d2k_hs_ops ops=ops_of(&f);
    d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
    d2k_httpsearch_portal(hs,"execution.example",4,IP,now);
    base_injected(hs,&f,&now);
    for(int i=0;i<2;i++) {
        d2k_httpsearch_ack(hs,f.trial,1,now+=10);
        d2k_ev e=applied_event(&f,1);(void)d2k_httpsearch_control(hs,&e,now);
        d2k_hs_result r=res(&f,D2K_HS_REAL);r.fd=f.job.fd;r.seq=f.job.seq;
        d2k_httpsearch_result(hs,&r,now+=100);
        d2k_httpsearch_tick(hs,now+=501);
    }
    CHECK(!f.set_plan_n,"one request execution cannot confirm two-response trials");
    d2k_httpsearch_free(hs);
    /* A portal on the first request stops the probe: do not demand execution
       of a second request that was never sent to classify this negative. */
    memset(&f,0,sizeof f);ops=ops_of(&f);hs=d2k_httpsearch_new(&ops);now=1;
    d2k_httpsearch_portal(hs,"execution.example",4,IP,now);base_injected(hs,&f,&now);
    d2k_httpsearch_ack(hs,f.trial,1,++now);
    d2k_ev first=applied_event(&f,1);(void)d2k_httpsearch_control(hs,&first,now);
    d2k_hs_result portal=res(&f,D2K_HS_INJECTED);
    portal.requests_sent=1;portal.fd=f.job.fd;portal.seq=f.job.seq;
    d2k_httpsearch_result(hs,&portal,++now);
    CHECK(f.set_probe_n==2&&strstr(f.last_probe_plan,"fake")&&!f.set_plan_n,
          "first-request portal is measured negative without unsent second execution");
    d2k_httpsearch_free(hs);
}

static void test_execution_identity(void) {
    for(int family=4;family<=6;family+=2) for(int variant=0;variant<18;variant++) {
        fake f={0};d2k_hs_ops ops=ops_of(&f);
        d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
        d2k_httpsearch_portal(hs,"identity.example",(uint8_t)family,IP,now);
        base_injected(hs,&f,&now);
        for(int attempt=0;attempt<2;attempt++) {
            d2k_httpsearch_ack(hs,f.trial,1,now+=10);
            d2k_ev e=applied_event(&f,1);
            CHECK(d2k_httpsearch_control(hs,&e,now)==1,"first exact execution accepted");
            e.execution_id=2;
            switch(variant) {
            case 0:e.trial_id[0]^=1;break;
            case 1:e.plan_id[0]^=1;break;
            case 2:e.low_port++;break;
            case 3:e.high_ip[0]^=1;break;
            case 4:e.transport=17;break;
            case 5:e.family=(uint8_t)(family==4?6:4);break;
            case 6:e.execution_id=0;break;
            case 7:memset(e.execution_binding.epoch,0,16);break;
            case 8:e.execution_binding.generation=0;break;
            case 9:e.execution_binding.temporary=0;break;
            case 10:e.execution_binding.kind=D2K_BIND_ADDR;break;
            case 11:e.execution_binding.shape=D2K_PLAN_SHAPE_LEGACY;break;
            case 12:e.execution_id=1;break; /* replay of first request */
            case 13:e.execution_binding.generation++;break;
            case 14:e.low_ip[0]^=1;break;
            default:break;
            }
            d2k_hs_result r=res(&f,D2K_HS_REAL);r.fd=f.job.fd;r.seq=f.job.seq;
            if(variant==15)r.local_ip[0]^=1;
            if(variant==16)r.local_port++;
            if(variant==17) { /* result/DEL_PROBE may precede the last APPLIED */
                d2k_httpsearch_result(hs,&r,now+=100);
                CHECK(!f.set_plan_n,"one execution still pending after result");
                uint8_t ip[16];memcpy(ip,e.low_ip,16);memcpy(e.low_ip,e.high_ip,16);memcpy(e.high_ip,ip,16);
                uint16_t port=e.low_port;e.low_port=e.high_port;e.high_port=port;
                CHECK(d2k_httpsearch_control(hs,&e,now)==1,"late execution matches reversed canonical endpoints");
            } else {
                CHECK(d2k_httpsearch_control(hs,&e,now)==(variant>=15),"foreign or duplicate execution rejected");
                d2k_httpsearch_result(hs,&r,now+=100);
                d2k_httpsearch_tick(hs,now+=501);
            }
        }
        CHECK(f.set_plan_n==(variant==17),"only two exact executions on actual probe socket confirm");
        d2k_httpsearch_free(hs);
    }
}

/* ПОЛЕ 16.10.2026, fast-torrent на выпуске 1bd394e: клиент получил заглушку
   провайдера (lawfilter.ertelecom.ru), а базовый запрос роутера — тишину.
   Тишина на свой GET — та же блокировка в другой форме, а не «блока нет»:
   поиск обязан начаться. Настоящий ответ сервера (REAL) по-прежнему его не
   начинает. */
static void test_silent_base_after_portal(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    d2k_httpsearch_portal(hs, "www.fast-torrent.ru", 4, IP, now);
    d2k_hs_result r = res(&f, D2K_HS_SILENT);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == 1 && d2k_httpsearch_busy(hs),
          "тишина базы после заглушки клиента не начала поиск");
    CHECK(strstr(f.said, "не воспроизвод") == NULL, "тишина названа «не воспроизводится»");
    d2k_httpsearch_free(hs);
}

/* МЕСТНЫЙ ОТКАЗ СОЕДИНЕНИЯ НА БАЗЕ — «НЕ ИЗМЕРЕНО», А НЕ «НЕ ВОСПРОИЗВОДИТСЯ».
 *
 * Поле 23.10.2026. `media5.cdnbase.com` отдавал клиенту 33 120 Б из 106 050
 * трижды подряд, то есть обрыв был. Базовый зонд один раз не установил
 * соединение, и поиск закрылся:
 *
 *   16:34:27 база — соединение не установилось: обрыв с роутера не
 *            воспроизводится, поиск HTTP не начат (подозрение не равно блокировке)
 *
 * Приём `fake-badsum`, которым тот же билд в повторе того же вечера
 * (`cand-32e84f2-2`, 16:41:03) отдал полные 106 050 Б, не был даже опробован,
 * и цель ушла на 10 минут штрафа.
 *
 * Отказ НАШЕГО сокета не говорит о коробке ничего (§2.4). Его цена не должна
 * равняться цене измеренного «блока нет»: повтор базы в том же поиске, а если
 * и он местный — короткий срок «не измерено», а не длинный «не воспроизводится».
 */
static void test_base_connect_fail_is_unmeasured(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    d2k_httpsearch_cut(hs, "media5.cdnbase.com", 4, IP, "/media/theme/fast.5.css", 33120, now);
    CHECK(f.start_n == 1, "база не запущена");
    d2k_hs_result r = res(&f, D2K_HS_CONNECT_FAIL);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(strstr(f.said, "не воспроизводится") == NULL,
          "местный отказ соединения назван «не воспроизводится»");
    CHECK(f.start_n == 2, "база не повторена после местного отказа");
    CHECK(d2k_httpsearch_busy(hs), "поиск брошен после местного отказа базы");
    /* Повтор базы увидел обрыв — поиск идёт своим чередом. */
    d2k_hs_result r2 = res(&f, D2K_HS_CUT);
    r2.seq = f.job.seq; r2.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r2, now += 100);
    CHECK(f.set_probe_n >= 1, "после повтора базы вопросы не начались");
    d2k_httpsearch_free(hs);
}

/* ТИШИНА НА БАЗЕ ОБРЫВА — ТОЖЕ НЕ «БЛОКА НЕТ».
 *
 * Поле 23.10.2026, тот же `media5.cdnbase.com`, прогон `final-e861d26-1`:
 *
 *   17:13:47 обрыв ответа на /media/theme/fast.5.css после 33120 байт тела
 *   17:13:57 обрыв ответа без портала — поиск обхода HTTP — база: тот же
 *            запрос своим зондом без плана
 *   17:14:03 база — ТИШИНА: обрыв с роутера не воспроизводится, поиск HTTP
 *            не начат (подозрение не равно блокировке)
 *   17:15:47 обрыв ответа ... после 33120 байт тела
 *   17:17:48 обрыв ответа ... после 33120 байт тела
 *
 * Клиент получал обрыв и до, и после. Ответа на НАШ запрос не было вовсе —
 * это отсутствие замера, а не измеренное «блока нет». Ветка портала ровно
 * так тишину и читает с 16.10.2026 («тишина на свой GET — та же блокировка
 * в другой форме»), но была закрыта условием `!hs->cur.cut`, то есть для
 * цели с обрывом не работала.
 *
 * Правило здесь то же, что у местного отказа соединения: повтор базы, а
 * повторная тишина — сигнал, с которого поиск начинается, а не вердикт
 * «не воспроизводится». */
static void test_base_silence_on_cut_is_not_absence(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    d2k_httpsearch_cut(hs, "media5.cdnbase.com", 4, IP, "/media/theme/fast.5.css", 33120, now);
    CHECK(f.start_n == 1, "база не запущена");
    d2k_hs_result r = res(&f, D2K_HS_SILENT);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(strstr(f.said, "не воспроизводится") == NULL,
          "тишина на базе обрыва названа «не воспроизводится»");
    CHECK(f.start_n == 2, "база не повторена после тишины");
    /* Повторная тишина — сигнал: поиск начинается. */
    d2k_hs_result r2 = res(&f, D2K_HS_SILENT);
    r2.seq = f.job.seq; r2.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r2, now += 100);
    CHECK(f.set_probe_n >= 1, "повторная тишина не начала поиск");
    CHECK(strstr(f.said, "не воспроизводится") == NULL,
          "повторная тишина названа «не воспроизводится»");
    d2k_httpsearch_free(hs);
}


/* ---- task 62: intentional close, local limits, large headers ---------- */
static void test_probe_interim_large_header(void) {
    /* A real probe through a loopback server: an interim 100 precedes a final
       200 whose header is larger than the old 4 KiB judge clamp, with a marker
       (the decoy name) only in that late part. Before the fix the judge was
       clamped to the interim header and reported REAL with status "100"; now
       it scans the full final header and reports the final status. */
    static char resp[8192];
    int k = snprintf(resp, sizeof resp, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX-Pad: ");
    for (int i = 0; i < 5000; i++) resp[k++] = 'a';
    k += snprintf(resp + k, sizeof resp - (size_t)k,
                  "\r\nX-Echo: disk.rzd.ru\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    d2k_hs_result r = keepalive_local(resp, NULL);
    CHECK(r.answer == D2K_HS_DECOY,
          "late decoy name beyond 4 KiB in the final header not seen (clamp truncated to interim 100)");
    CHECK(!strcmp(r.status, "HTTP/1.1 200 OK"),
          "status reported the interim 100 instead of the final 200");
    /* Same shape, no marker: the large final header is a plain real response,
       and the status is still the final 200, not the interim 100. */
    k = snprintf(resp, sizeof resp, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX-Pad: ");
    for (int i = 0; i < 5000; i++) resp[k++] = 'b';
    k += snprintf(resp + k, sizeof resp - (size_t)k,
                  "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    r = keepalive_local(resp, NULL);
    CHECK(r.answer == D2K_HS_REAL && !strcmp(r.status, "HTTP/1.1 200 OK"),
          "large final header after interim 100 not a plain real response with final status");
    CHECK(r.complete_responses == 1 && r.server_closed,
          "interim 100 + final close counted wrong");
}
static void test_server_close_probe(void) {
    /* Announced close after an explicitly framed complete response. */
    d2k_hs_result r=keepalive_local("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\none",NULL);
    CHECK(r.answer==D2K_HS_REAL&&r.complete_responses==1&&r.requests_sent==1&&r.server_closed,
          "Connection: close with Content-Length is the server's own end of connection");
    r=keepalive_local("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: Close\r\n\r\n3\r\none\r\n0\r\n\r\n",NULL);
    CHECK(r.answer==D2K_HS_REAL&&r.server_closed,"chunked + close token is an announced close");
    r=keepalive_local("HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\none",NULL);
    CHECK(r.answer==D2K_HS_REAL&&r.complete_responses==1&&r.server_closed,"HTTP/1.0 without keep-alive closes by protocol");
    r=keepalive_local("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\none",NULL);
    CHECK(r.answer==D2K_HS_REAL&&r.server_closed,"final head after an interim one decides the close");
    /* A close-delimited body can be cut by an injected FIN: never a success. */
    r=keepalive_local("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody",NULL);
    CHECK(r.answer==D2K_HS_REAL&&!r.server_closed,"close-delimited body is not proven complete");
    const char *ka10="HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 3\r\n\r\none";
    r=keepalive_local(ka10,ka10);
    CHECK(r.answer==D2K_HS_REAL&&r.complete_responses==2&&!r.server_closed,"HTTP/1.0 keep-alive is a keep-alive proof");
    /* Large but valid headers: a real response, not garbage. */
    static char big[8192],huge[70000];
    int n=snprintf(big,sizeof big,"HTTP/1.1 200 OK\r\nX-Big: ");
    memset(big+n,'a',6000);snprintf(big+n+6000,sizeof big-(size_t)n-6000,"\r\nContent-Length: 3\r\n\r\none");
    r=keepalive_local(big,big);
    CHECK(r.answer==D2K_HS_REAL&&r.complete_responses==2,"6 KB of headers judged as a real response");
    /* Beyond the reader's own limit: our limit, not path evidence. */
    n=snprintf(huge,sizeof huge,"HTTP/1.1 200 OK\r\nX-Big: ");
    memset(huge+n,'a',68000);snprintf(huge+n+68000,sizeof huge-(size_t)n-68000,"\r\nContent-Length: 3\r\n\r\none");
    r=keepalive_local(huge,NULL);
    CHECK(r.answer==D2K_HS_NONE&&!r.complete_responses,"local header limit is not a cut or garbage");
}
static d2k_hs_result closed_res(fake *f,int requests) {
    d2k_hs_result r=res(f,D2K_HS_REAL);
    r.requests_sent=(unsigned)requests;r.complete_responses=1;r.server_closed=1;
    r.fd=f->job.fd;r.seq=f->job.seq;return r;
}
static void test_server_close_confirmation(void) {
    fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
    d2k_httpsearch_portal(hs,"closer.example",4,IP,now);base_injected(hs,&f,&now);
    for(int i=0;i<2;i++) {
        d2k_httpsearch_ack(hs,f.trial,1,now+=10);applied_pair(hs,&f);
        d2k_hs_result r=closed_res(&f,1);
        d2k_httpsearch_result(hs,&r,now+=100);
    }
    CHECK(f.set_plan_n==1,"two trials ending in the server's announced close confirm the candidate");
    d2k_httpsearch_free(hs);
    memset(&f,0,sizeof f);ops=ops_of(&f);hs=d2k_httpsearch_new(&ops);now=1;
    d2k_httpsearch_portal(hs,"closer2.example",4,IP,now);base_injected(hs,&f,&now);
    for(int i=0;i<2;i++) {
        d2k_httpsearch_ack(hs,f.trial,1,now+=10);applied_pair(hs,&f);
        d2k_hs_result r=closed_res(&f,2); /* contradictory: a second request was sent */
        d2k_httpsearch_result(hs,&r,now+=100);
    }
    CHECK(!f.set_plan_n,"server_closed with a second request sent is not a success");
    d2k_httpsearch_free(hs);
}
static unsigned base_direct,base_inconclusive;
static void base_capture(void *ctx,const d2k_diag_event *e) {
    (void)ctx;
    if(!strcmp(e->outcome,"probe-direct"))base_direct++;
    if(!strcmp(e->outcome,"inconclusive"))base_inconclusive++;
}
static void test_baseline_close_and_local(void) {
    fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
    d2k_httpsearch_diagnostics(hs,base_capture,NULL);base_direct=base_inconclusive=0;
    d2k_httpsearch_portal(hs,"direct-close.example",4,IP,now);
    d2k_hs_result r=closed_res(&f,1);
    d2k_httpsearch_result(hs,&r,now+=100);
    CHECK(!f.set_probe_n&&base_direct==1&&!base_inconclusive,
          "valid response with an announced close is direct, not a reason to search");
    d2k_httpsearch_portal(hs,"limit.example",4,IP,now+=1000);
    r=res(&f,D2K_HS_NONE);r.fd=f.job.fd;r.seq=f.job.seq;
    snprintf(r.why,sizeof r.why,"local response limit");
    d2k_httpsearch_result(hs,&r,now+=100);
    CHECK(!f.set_probe_n&&base_inconclusive==1&&strstr(f.said,"местный предел"),
          "local limit at baseline is unmeasured: no search, no verdict");
    d2k_httpsearch_free(hs);
}
int main(void) {
    test_reset_before_response_starts_direct_check();
    test_probe_interim_large_header();
    test_server_close_probe();
    test_server_close_confirmation();
    test_baseline_close_and_local();
    test_base_silence_on_cut_is_not_absence();
    test_base_connect_fail_is_unmeasured();
    test_silent_base_after_portal();
    test_probe_cut();
    test_cut_search();
    test_cut_retry_and_inconclusive();
    test_execution_identity();
    test_each_request_execution();
#ifdef D2K_HS_KEEPALIVE_PROOF
    test_missing_repro_context();
    test_failed_reinstall_keeps_owner();
    test_pending_revoke();
    test_bound_failure();
    test_live_failure_outweighs_probe();
    test_live_failure_history();
    test_live_failure_alias();
    test_single_response_not_confirmation();
#endif
    test_portal_properties();
    test_reused_property_answer();
    test_judge();
    test_candidates();
    test_probe();
    test_keepalive_portal();
    test_search();
    test_persist();
    test_inconclusive();
    test_measured_poison();
    test_stale_result();
    if (fails) { printf("test_httpsearch: провалов %d\n", fails); return 1; }
    printf("test_httpsearch: все проверки прошли\n");
    return 0;
}
