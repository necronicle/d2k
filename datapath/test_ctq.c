/* test_ctq.c — запрос счётчиков conntrack по кортежу (d2k_ctq.h).
 *
 * 1. Запрос CT_GET собран по формату ядра (байты сверены с тем, что принял
 *    и на что ответил ctnetlink роутера KN-1811 04.10.2026).
 * 2. Ответ ядра с этого же роутера разбирается: прямой 14, обратный 7.
 * 3. Ошибка ядра (записи нет), чужой seq, ответ без счётчиков — «не знаем».
 * 4. ЦИКЛ ОЧЕРЕДИ НЕ ЖДЁТ: на сокете, который не отвечает вовсе, запрос
 *    возвращается сразу (fail open), а устаревший чужой ответ не путается со
 *    своим. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "d2k_ctq.h"
#include "d2k_nl.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s\n", m); fails++; } } while (0)

static size_t unhex(const char *h, uint8_t *o, size_t cap) {
    size_t n = 0;
    while (h[0] && h[1] && n < cap) {
        unsigned v; sscanf(h, "%2x", &v); o[n++] = (uint8_t)v; h += 2;
    }
    return n;
}

static double now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

/* Перечисление таблицы (этап 13): запрос с NLM_F_DUMP; ответ CT_NEW с прямым
   кортежем и счётчиками разбирается в кортеж клиент→сервер; NLMSG_DONE
   завершает; чужой seq и запись без кортежа пропускаются. */
static size_t nla(uint8_t *o, size_t pos, uint16_t type, const void *v, size_t n) {
    o[pos] = (uint8_t)((n + 4) & 0xff); o[pos + 1] = (uint8_t)((n + 4) >> 8);
    o[pos + 2] = (uint8_t)(type & 0xff); o[pos + 3] = (uint8_t)(type >> 8);
    memcpy(o + pos + 4, v, n);
    return pos + ((n + 4 + 3) & ~(size_t)3);
}
static size_t nest_open(size_t pos) { return pos + 4; }
static void nest_close(uint8_t *o, size_t start, size_t end, uint16_t type) {
    size_t n = end - start;
    o[start] = (uint8_t)(n & 0xff); o[start + 1] = (uint8_t)(n >> 8);
    o[start + 2] = (uint8_t)((type | D2K_NLA_F_NESTED) & 0xff); o[start + 3] = (uint8_t)((type | D2K_NLA_F_NESTED) >> 8);
}
static int dump_seen;
static d2k_ct_tuple dump_t;
static d2k_ct_info dump_i;
static int dump_cb(void *ctx, const d2k_ct_tuple *t, const d2k_ct_info *i) {
    (void)ctx; dump_seen++; dump_t = *t; dump_i = *i; return 0;
}
static void check_dump(void) {
    uint8_t req[64];
    size_t rn = d2k_ct_dump_req(req, sizeof req, 77, 4);
    CHECK(rn == 20 && (req[6] | req[7] << 8) == (D2K_NLM_F_REQUEST | D2K_NLM_F_DUMP) && req[16] == 2,
          "перечисление: запрос без NLM_F_DUMP или не того семейства");
    uint8_t m[256]; memset(m, 0, sizeof m);
    size_t pos = 16;
    m[pos++] = 2; m[pos++] = 0; m[pos++] = 0; m[pos++] = 0;           /* nfgenmsg AF_INET */
    size_t tup = pos; pos = nest_open(pos);
    size_t ipn = pos; pos = nest_open(pos);
    uint8_t src[4] = {192, 168, 1, 67}, dst[4] = {1, 2, 3, 4};
    pos = nla(m, pos, D2K_CTA_IP_V4_SRC, src, 4);
    pos = nla(m, pos, D2K_CTA_IP_V4_DST, dst, 4);
    nest_close(m, ipn, pos, D2K_CTA_TUPLE_IP);
    size_t prn = pos; pos = nest_open(pos);
    uint8_t proto = 17, sp[2] = {0xc3, 0x50}, dp[2] = {0x01, 0xbb};
    pos = nla(m, pos, D2K_CTA_PROTO_NUM, &proto, 1);
    pos = nla(m, pos, D2K_CTA_PROTO_SRC_PORT, sp, 2);
    pos = nla(m, pos, D2K_CTA_PROTO_DST_PORT, dp, 2);
    nest_close(m, prn, pos, D2K_CTA_TUPLE_PROTO);
    nest_close(m, tup, pos, D2K_CTA_TUPLE_ORIG);
    size_t co = pos; pos = nest_open(pos);
    uint8_t pk[8] = {0, 0, 0, 0, 0, 0, 0, 12};
    pos = nla(m, pos, D2K_CTA_COUNTERS_PACKETS, pk, 8);
    nest_close(m, co, pos, D2K_CTA_COUNTERS_ORIG);
    size_t cr = pos; pos = nest_open(pos);
    uint8_t pr[8] = {0, 0, 0, 0, 0, 0, 0, 9};
    pos = nla(m, pos, D2K_CTA_COUNTERS_PACKETS, pr, 8);
    nest_close(m, cr, pos, D2K_CTA_COUNTERS_REPLY);
    uint8_t mk[4] = {0x40, 0x00, 0x00, 0x00};                          /* CTA_MARK 0x40000000 (этап 17) */
    pos = nla(m, pos, D2K_CTA_MARK, mk, 4);
    m[0] = (uint8_t)(pos & 0xff); m[1] = (uint8_t)(pos >> 8);
    uint16_t type = (uint16_t)(D2K_NFNL_SUBSYS_CTNETLINK << 8 | D2K_IPCTNL_MSG_CT_NEW);
    m[4] = (uint8_t)(type & 0xff); m[5] = (uint8_t)(type >> 8);
    m[8] = 77;
    /* второе сообщение — DONE того же seq */
    size_t d = pos;
    memset(m + d, 0, 20);
    m[d] = 20; m[d + 4] = D2K_NLMSG_DONE; m[d + 8] = 77;
    size_t total = d + 20;
    int done = 0;
    dump_seen = 0;
    int c = d2k_ct_dump_parse(m, total, 77, dump_cb, NULL, &done);
    CHECK(c == 1 && done == 1 && dump_seen == 1, "перечисление: запись не разобрана или DONE не замечен");
    CHECK(dump_t.family == 4 && dump_t.proto == 17 && !memcmp(dump_t.src, src, 4) && !memcmp(dump_t.dst, dst, 4) &&
          dump_t.sport_be[0] == 0xc3 && dump_t.sport_be[1] == 0x50 && dump_t.dport_be[0] == 0x01 && dump_t.dport_be[1] == 0xbb,
          "перечисление: прямой кортеж разобран неверно");
    CHECK(dump_i.orig_pkts == 12 && dump_i.reply_pkts == 9, "перечисление: счётчики разобраны неверно");
    CHECK(dump_i.mark_known && dump_i.mark == 0x40000000u, "перечисление: метка записи (CTA_MARK) не разобрана");
    dump_seen = 0; done = 0;
    CHECK(d2k_ct_dump_parse(m, total, 78, dump_cb, NULL, &done) == 0 && dump_seen == 0 && done == 0,
          "перечисление: чужой seq принят");
    /* A multipart dump is complete only on a successful DONE, not a partial
       table followed by timeout, ACK, or a failed/interrupted terminator. */
    int32_t status = -5;
    memcpy(m + d + 16, &status, 4);
    CHECK(d2k_ct_dump_parse(m, total, 77, dump_cb, NULL, &done) == -1,
          "dump: error in DONE accepted as success");
    status = 0; memcpy(m + d + 16, &status, 4);
    uint16_t flags = 0x10; /* NLM_F_DUMP_INTR */
    memcpy(m + d + 6, &flags, 2);
    CHECK(d2k_ct_dump_parse(m, total, 77, dump_cb, NULL, &done) == -1,
          "dump: interrupted DONE accepted as success");
    flags = 0; memcpy(m + d + 6, &flags, 2);
    uint16_t ack_type = D2K_NLMSG_ERROR;
    memcpy(m + d + 4, &ack_type, 2);
    done = 0;
    CHECK(d2k_ct_dump_parse(m + d, 20, 77, dump_cb, NULL, &done) == 0 && !done,
          "dump: success ACK terminates multipart dump");
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "dump socketpair");
    CHECK(send(pair[1], m, d, 0) == (ssize_t)d, "dump partial send");
    CHECK(d2k_ct_dump_fd(pair[0], 77, 4, dump_cb, NULL, 5) == -1,
          "dump: partial table followed by timeout accepted as success");
    close(pair[0]); close(pair[1]);

}

static void check_reply_tuple(void) {
    for(unsigned family=4;family<=6;family+=2) {
        d2k_ct_tuple original={0},reply={0};
        original.family=reply.family=(uint8_t)family;
        original.proto=reply.proto=17;
        original.src[0]=10;original.dst[0]=20;
        reply.src[0]=20;reply.dst[0]=30;
        original.sport_be[0]=0x12;original.sport_be[1]=0x34;
        reply.dport_be[0]=0xd6;reply.dport_be[1]=0xd9;
        original.dport_be[0]=reply.sport_be[0]=1;
        original.dport_be[1]=reply.sport_be[1]=0xbb;
        uint8_t message[512],other[160];
        size_t n=d2k_ct_get_req(message,sizeof message,91,&original);
        size_t r=d2k_ct_get_req(other,sizeof other,91,&reply);
        CHECK(n>20&&r>20,"NAT tuple fixtures build");
        if(n<=20||r<=20)continue;
        uint16_t kind=(D2K_NFNL_SUBSYS_CTNETLINK<<8)|D2K_IPCTNL_MSG_CT_NEW;
        memcpy(message+4,&kind,2);
        d2k_ct_info info;memset(&info,0xff,sizeof info);
        CHECK(d2k_ct_info_parse(message,n,91,&info)==2&&!info.reply_tuple_known,
              "missing reply tuple must not reuse a previous mapping");
        memcpy(message+n,other+20,r-20);
        uint16_t type=D2K_CTA_TUPLE_REPLY|D2K_NLA_F_NESTED;
        memcpy(message+n+2,&type,2);
        size_t total=n+r-20;uint32_t length=(uint32_t)total;
        memcpy(message,&length,4);
        CHECK(d2k_ct_info_parse(message,total,91,&info)==2&&info.reply_tuple_known&&
              !memcmp(&info.reply_tuple,&reply,sizeof reply),
              "post-NAT reply tuple must survive missing conntrack counters");
        CHECK(d2k_ct_info_parse(message,total-1,91,&info)==-1&&!info.reply_tuple_known,
              "truncated mapping must not remain usable");
    }
}

static void check_async(void) {
    int fd[2]; CHECK(!socketpair(AF_UNIX, SOCK_DGRAM, 0, fd), "async socketpair");
    d2k_ct_async a = {0}; d2k_ct_tuple t = {0}; d2k_ct_info info;
    t.family = 4; t.proto = 17; t.src[0] = 10; t.dst[0] = 20;
    t.sport_be[1] = 1; t.dport_be[1] = 2;
    CHECK(!d2k_ct_async_query(&a, fd[0], &t, 100, &info), "async starts pending");
    uint8_t req[512]; ssize_t n = recv(fd[1], req, sizeof req, MSG_DONTWAIT);
    CHECK(n > 20, "async sent request");
    CHECK(!d2k_ct_async_query(&a, fd[0], &t, 200, &info), "absent reply remains pending");
    CHECK(recv(fd[1], req+256, 256, MSG_DONTWAIT) < 0, "no replacement seq while pending");
    uint16_t type = D2K_CTA_TUPLE_REPLY | D2K_NLA_F_NESTED;
    memcpy(req+22, &type, 2);
    type = (D2K_NFNL_SUBSYS_CTNETLINK << 8) | D2K_IPCTNL_MSG_CT_NEW;
    memcpy(req+4, &type, 2);
    CHECK(send(fd[1], req, (size_t)n, 0) == n, "deliver delayed reply");
    d2k_ct_async_poll(&a, fd[0]);
    CHECK(d2k_ct_async_query(&a, fd[0], &t, 300, &info) == 1 &&
          info.reply_tuple_known && !memcmp(&t, &info.reply_tuple, sizeof t),
          "late reply resolved by retained seq");
    CHECK(!d2k_ct_async_query(&a, fd[0], &t, 400, &info), "new query after consume");
    n = recv(fd[1], req, sizeof req, MSG_DONTWAIT);
    CHECK(n > 20, "new sequence request");
    d2k_ct_async_forget(&a, &t);
    memcpy(req+22, &(uint16_t){D2K_CTA_TUPLE_REPLY | D2K_NLA_F_NESTED}, 2);
    memcpy(req+4, &type, 2);
    CHECK(send(fd[1], req, (size_t)n, 0) == n, "late cancelled reply");
    d2k_ct_async_poll(&a, fd[0]);
    CHECK(!d2k_ct_async_query(&a, fd[0], &t, 500, &info),
          "cancelled incarnation cannot donate mapping");
    CHECK(recv(fd[1], req, sizeof req, MSG_DONTWAIT) > 20, "fresh incarnation sends own query");
    CHECK(!d2k_ct_async_query(&a, fd[0], &t, D2K_CT_ASYNC_TIMEOUT_NS+501, &info),
          "timeout retries without blocking");
    CHECK(recv(fd[1], req, sizeof req, MSG_DONTWAIT) > 20, "timeout new request");
    memset(&a, 0, sizeof a);
    for (unsigned i = 0; i < D2K_CT_ASYNC_SLOTS; i++) {
        t.sport_be[1] = (uint8_t)i;
        CHECK(!d2k_ct_async_query(&a, fd[0], &t, 100, &info), "bounded async pending slot");
        CHECK(recv(fd[1], req, sizeof req, MSG_DONTWAIT) > 20, "bounded request sent");
    }
    t.sport_be[1] = D2K_CT_ASYNC_SLOTS;
    CHECK(!d2k_ct_async_query(&a, fd[0], &t, 100, &info), "full async table is fail-open");
    CHECK(recv(fd[1], req, sizeof req, MSG_DONTWAIT) < 0, "full table sent no untracked request");
    close(fd[0]); close(fd[1]);
}

int main(void) {
    check_async();
    check_reply_tuple();
    check_dump();
    d2k_ct_tuple t;
    memset(&t, 0, sizeof t);
    t.family = 4; t.proto = 17;
    inet_pton(AF_INET, "192.168.1.67", t.src);
    inet_pton(AF_INET, "17.248.214.12", t.dst);
    t.sport_be[0] = 0xe6; t.sport_be[1] = 0x8e;   /* 59022 */
    t.dport_be[0] = 0x01; t.dport_be[1] = 0xbb;   /* 443 */

    /* 1. Запрос. */
    uint8_t req[128], want[128];
    size_t n = d2k_ct_get_req(req, sizeof req, 7, &t);
    size_t wn = unhex("48000000" "0101" "0100" "07000000" "00000000"  /* nlmsghdr */
                      "02000000"                                       /* nfgenmsg AF_INET */
                      "34000180"                                       /* CTA_TUPLE_ORIG */
                      "14000180" "08000100c0a80143" "0800020011f8d60c" /* CTA_TUPLE_IP */
                      "1c000280" "0500010011000000"                    /* CTA_TUPLE_PROTO, udp */
                      "06000200e68e0000" "0600030001bb0000",           /* ports */
                      want, sizeof want);
    CHECK(n == 72 && n == wn && memcmp(req, want, n) == 0,
          "запрос CT_GET собран не так, как его принимает ядро");
    CHECK(d2k_ct_get_req(req, 40, 7, &t) == 0, "запрос в маленький буфер собрался");

    /* 2. Ответ ядра роутера (обрезан до счётчиков и статуса). */
    uint8_t rsp[400];
    size_t rn = unhex(
        "440100000001020007000000e966000002000000"
        "340001801400018008000100c0a801430800020011f8d60c1c000280050001001100000006000200e68e000006000300" "01bb0000"
        "340002801400018008000100" "11f8d60c0800020058575d0b1c00028005000100110000000600020001bb000006000300e68e0000"
        "08000300" "0020019e" "08000700" "00000013"
        "1c0009800c00010000000000000000" "0e0c0002000000000000001fd6"
        "1c000a800c00010000000000000000" "070c00020000000000000017f9", rsp, sizeof rsp);
    /* Длина сообщения — по собранному. */
    rsp[0] = (uint8_t)rn; rsp[1] = (uint8_t)(rn >> 8);
    uint64_t o = 0, r = 0;
    CHECK(d2k_ct_counters_parse(rsp, rn, 7, &o, &r) == 0 && o == 14 && r == 7,
          "ответ ядра со счётчиками не разобран (ждали 14/7)");
    CHECK(d2k_ct_counters_parse(rsp, rn, 8, &o, &r) == -1, "ответ на чужой запрос принят");
    /* Без счётчиков (accounting выключен) — не знаем. */
    {
        uint8_t no[64];
        memcpy(no, rsp, 20);
        no[0] = 20; no[1] = 0;
        CHECK(d2k_ct_counters_parse(no, 20, 7, &o, &r) == 2, "запись без счётчиков дала числа");
    }
    /* 3. Ошибка ядра: записи нет (-ENOENT). */
    {
        uint8_t er[36];
        memset(er, 0, sizeof er);
        er[0] = 36; er[4] = 2; /* NLMSG_ERROR */
        er[8] = 9;             /* seq */
        int32_t e = -2;
        memcpy(er + 16, &e, 4);
        CHECK(d2k_ct_counters_parse(er, 36, 9, &o, &r) == 1, "ошибка ядра не распознана");
    }

    /* 3б. МЕТКА ЗАПИСИ (этапы 17, 51): тот же кортеж, CTA_MARK и CTA_MARK_MASK
       сетевого порядка — ядро меняет ТОЛЬКО биты маски атомарно (новая =
       (старая & ~маска) ^ значение), без чтения и записи всей метки; тип
       CT_NEW (0x0100), флаги REQUEST|ACK (0x05), без CREATE. Значение вне
       маски — ошибка (ядро испортило бы чужие биты XOR-ом). */
    {
        uint8_t mreq[128], mwant[128];
        size_t mn = d2k_ct_mark_req(mreq, sizeof mreq, 7, &t, 0x40000000u, 0x40000000u);
        size_t mwn = unhex("58000000" "0001" "0500" "07000000" "00000000"
                           "02000000"
                           "34000180"
                           "14000180" "08000100c0a80143" "0800020011f8d60c"
                           "1c000280" "0500010011000000"
                           "06000200e68e0000" "0600030001bb0000"
                           "08000800" "40000000"                            /* CTA_MARK */
                           "08001500" "40000000",                           /* CTA_MARK_MASK */
                           mwant, sizeof mwant);
        CHECK(mn == 88 && mn == mwn && memcmp(mreq, mwant, mn) == 0,
              "запрос CT_NEW с маской метки собран не так, как его принимает ядро");
        CHECK(d2k_ct_mark_req(mreq, 80, 7, &t, 0x40000000u, 0x40000000u) == 0, "запрос метки в маленький буфер собрался");
        CHECK(d2k_ct_mark_req(mreq, sizeof mreq, 7, &t, 0x40000001u, 0x40000000u) == 0,
              "значение метки вне маски принято");
        /* Ответ GET с CTA_MARK разбирается: метка известна (читать-изменить-записать). */
        uint8_t rm[420];
        memcpy(rm, rsp, rn);
        size_t rmn = rn;
        static const uint8_t mark_attr[8] = {0x08, 0x00, 0x08, 0x00, 0x00, 0x12, 0x00, 0x2d};
        memcpy(rm + rmn, mark_attr, 8); rmn += 8;
        rm[0] = (uint8_t)rmn; rm[1] = (uint8_t)(rmn >> 8);
        d2k_ct_info mi; memset(&mi, 0, sizeof mi);
        CHECK(d2k_ct_info_parse(rm, rmn, 7, &mi) == 0 && mi.mark_known && mi.mark == 0x0012002du,
              "метка записи из ответа ядра не прочитана");
        d2k_ct_info ni; memset(&ni, 0xff, sizeof ni);
        CHECK(d2k_ct_info_parse(rsp, rn, 7, &ni) == 0 && !ni.mark_known, "метка «известна» без CTA_MARK");
    }

    /* 4. Неотвечающий сокет: возврат сразу, без ожидания. */
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0, "socketpair");
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL, 0) | O_NONBLOCK);
    double a = now_ms();
    for (int i = 0; i < 100; i++) {
        CHECK(d2k_ct_query_fd(sv[0], (uint32_t)(100 + i), &t, &o, &r) == -1,
              "молчащий сокет дал счётчики");
        char drain[256];
        while (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) { }
    }
    CHECK(now_ms() - a < 50.0, "сто запросов в молчащий сокет заняли больше 50 мс — цикл ждёт");
    /* Метка: подтверждение ядра (NLMSG_ERROR 0) — 0; -ENOENT — 2; молчание — -1. */
    {
        uint8_t er[36];
        memset(er, 0, sizeof er);
        er[0] = 36; er[4] = 2; er[8] = 77;
        int32_t e = 0; memcpy(er + 16, &e, 4);
        CHECK(send(sv[1], er, 36, 0) == 36, "ack send");
        CHECK(d2k_ct_mark_fd(sv[0], 77, &t, 0x40000000u, 0x40000000u, 50) == 0, "подтверждение метки не принято");
        char drain[256]; while (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) { }
        er[8] = 78; e = -2; memcpy(er + 16, &e, 4);
        CHECK(send(sv[1], er, 36, 0) == 36, "enoent send");
        CHECK(d2k_ct_mark_fd(sv[0], 78, &t, 0x40000000u, 0x40000000u, 50) == 2, "ENOENT на метку не распознан");
        while (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) { }
        double b = now_ms();
        CHECK(d2k_ct_mark_fd(sv[0], 79, &t, 0x40000000u, 0x40000000u, 20) == -1 && now_ms() - b < 200.0,
              "молчание на метку не -1 или ждёт дольше срока");
        while (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) { }
    }
    /* Проверка маски метки (этап 51) на своей временной записи: ответы ядра
       заранее в сокете по seq. Запись создаётся только CREATE|EXCL, без
       предварительного удаления; удаляется только подтверждённо созданная.
         0 ядро чтит маску — чужие биты 0x5 целы (1);
         1 ядро v4.9 пишет CTA_MARK целиком — осталась только наша метка (0);
         2 создать не дали — не определить (-1), удалять нечего;
         3 чтит маску, но ответ без счётчиков (учёта нет) — маска учтена (1);
         4 первая кандидатура занята (EEXIST) — её не трогаем, берём следующую;
         5 на создание нет ответа — неясно, чья запись: не удаляем (истечёт). */
    for (int kernel = 0; kernel < 6; kernel++) {
        char drain[512];
        while (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) { }
        while (recv(sv[0], drain, sizeof drain, MSG_DONTWAIT) > 0) { }   /* ответы прежних проверок */
        uint32_t seq0 = 500u + (uint32_t)kernel * 10u;
        uint8_t er[36];
        int32_t e;
        /* seq берётся один раз: аргумент бывает ++q. */
        #define ACK(sq, errv) do { uint32_t sq1 = (sq); memset(er, 0, sizeof er); er[0] = 36; er[4] = 2; \
            memcpy(er + 8, &sq1, 4); e = (errv); memcpy(er + 16, &e, 4); \
            CHECK(send(sv[1], er, 36, 0) == 36, "probe ack send"); } while (0)
        uint32_t q = seq0;
        if (kernel == 2) { ACK(++q, -1); }              /* EPERM */
        else if (kernel != 5) {
            if (kernel == 4) ACK(++q, -17);             /* EEXIST: чужая или чужой проверки */
            ACK(++q, 0);                                /* создана с меткой 0x5 */
            ACK(++q, 0);                                /* маскированная установка принята */
            uint8_t gm[420];
            size_t gn;
            if (kernel == 3) {
                memset(gm, 0, 20);
                uint16_t ty = (uint16_t)(D2K_NFNL_SUBSYS_CTNETLINK << 8 | D2K_IPCTNL_MSG_CT_NEW);
                memcpy(gm + 4, &ty, 2);
                gm[16] = 2;
                gn = 20;
            } else {
                memcpy(gm, rsp, rn);
                gn = rn;
            }
            uint32_t mk = kernel == 1 ? 0x40000000u : 0x40000005u;
            uint8_t ma[8] = {0x08, 0x00, 0x08, 0x00, (uint8_t)(mk >> 24), (uint8_t)(mk >> 16),
                             (uint8_t)(mk >> 8), (uint8_t)mk};
            memcpy(gm + gn, ma, 8); gn += 8;
            gm[0] = (uint8_t)gn; gm[1] = (uint8_t)(gn >> 8);
            uint32_t gs = ++q;
            memcpy(gm + 8, &gs, 4);
            CHECK(send(sv[1], gm, gn, 0) == (ssize_t)gn, "probe get send");
            ACK(++q, 0);                                /* удалена */
        }
        #undef ACK
        uint32_t sq = seq0;
        int v = d2k_ct_mask_probe_fd(sv[0], &sq, 0x40000000u, 0x1234, 50);
        CHECK(v == (kernel == 0 || kernel == 3 || kernel == 4 ? 1 : kernel == 1 ? 0 : -1),
              kernel == 0 ? "ядро, чтущее маску, не признано" :
              kernel == 1 ? "ядро v4.9 (метка целиком) признано чтущим маску" :
              kernel == 2 ? "проверка без созданной записи дала ответ" :
              kernel == 3 ? "ядро без учёта conntrack (ответ без счётчиков) не признано чтущим маску" :
              kernel == 4 ? "занятая кандидатура: проверка не перешла к следующей" :
                            "без ответа на создание проверка дала ответ");
        /* Что проверка послала ядру: типы и порты источника по порядку. */
        int creates = 0, deletes = 0;
        uint8_t first_create[2] = {0}, del_port[2] = {0}, last_create[2] = {0};
        ssize_t got;
        while ((got = recv(sv[1], drain, sizeof drain, MSG_DONTWAIT)) > 0) {
            uint16_t ty; memcpy(&ty, drain + 4, 2);
            /* порт источника: nlmsg 16 + nfgen 4 + nest(4) + ip nest(4+2×8) + proto nest(4) + num(8) + attr hdr(4) */
            const uint8_t *port = (const uint8_t *)drain + 16 + 4 + 4 + 4 + 16 + 4 + 8 + 4;
            if ((ty & 0xff) == D2K_IPCTNL_MSG_CT_NEW && (drain[7] & 0x04)) {   /* NLM_F_CREATE 0x400 */
                if (!creates) memcpy(first_create, port, 2);
                memcpy(last_create, port, 2);
                creates++;
            }
            if ((ty & 0xff) == 2) { deletes++; memcpy(del_port, port, 2); }
        }
        if (kernel == 2 || kernel == 5)
            CHECK(deletes == 0, "проверка удалила запись, создание которой не подтверждено");
        if (kernel == 4) {
            CHECK(creates == 2 && memcmp(first_create, last_create, 2) != 0 && deletes == 1 &&
                  !memcmp(del_port, last_create, 2),
                  "занятая (EEXIST) кандидатура тронута или удалена не своя запись");
        }
        if (kernel == 0)
            CHECK(creates == 1 && deletes == 1 && !memcmp(del_port, first_create, 2),
                  "проверка: лишнее удаление (до создания) или удалена не созданная запись");
        while (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) { }
    }
    /* Параллельные проверки (два d2kd, разные соли) — разные кортежи. */
    {
        char drain[512];
        uint8_t p1[2] = {0}, p2[2] = {0};
        uint32_t sq = 900;
        (void)d2k_ct_mask_probe_fd(sv[0], &sq, 0x40000000u, 0x0101, 5);
        if (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) memcpy(p1, drain + 60, 2);
        while (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) { }
        (void)d2k_ct_mask_probe_fd(sv[0], &sq, 0x40000000u, 0x0202, 5);
        if (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) memcpy(p2, drain + 60, 2);
        while (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) { }
        CHECK(memcmp(p1, p2, 2) != 0, "параллельные проверки с разной солью взяли один кортеж");
    }
    /* Устаревший чужой ответ лежит в сокете, свой следом: берётся свой. */
    {
        uint8_t stale[400];
        memcpy(stale, rsp, rn);
        stale[8] = 0x55;                        /* чужой seq */
        CHECK(send(sv[1], stale, rn, 0) == (ssize_t)rn, "stale send");
        uint8_t mine[400];
        memcpy(mine, rsp, rn);
        mine[8] = 200; mine[9] = mine[10] = mine[11] = 0;
        CHECK(send(sv[1], mine, rn, 0) == (ssize_t)rn, "mine send");
        o = r = 0;
        CHECK(d2k_ct_query_fd(sv[0], 200, &t, &o, &r) == 0 && o == 14 && r == 7,
              "свой ответ за устаревшим чужим не найден");
    }
    /* Запись без счётчиков (accounting выключен) — свой код: d2kd скажет об
       этом один раз (раунд 4, M-n2). */
    {
        uint8_t no[64];
        memcpy(no, rsp, 20);
        no[0] = 20; no[1] = 0;
        no[8] = 201; no[9] = no[10] = no[11] = 0;
        CHECK(send(sv[1], no, 20, 0) == 20, "no-acct send");
        CHECK(d2k_ct_query_fd(sv[0], 201, &t, &o, &r) == 2, "запись без счётчиков не отличена");
    }
    close(sv[0]); close(sv[1]);
    CHECK(d2k_ct_query_fd(-1, 1, &t, &o, &r) == -1, "запрос без сокета");

    /* 5. Раунд 4, N2: проба доступности при старте. Ответ ядра на GET
       несуществующей записи: ENOENT — ctnetlink есть; EOPNOTSUPP,
       EPROTONOSUPPORT, ENOSYS, EINVAL — нет (подсистема не зарегистрирована,
       модуль не загрузился); молчание — тоже нет. Номера — Linux. */
    {
        static const struct { int32_t err; int want; const char *what; } cases[] = {
            { -2, 1, "ENOENT" }, { -95, 0, "EOPNOTSUPP" }, { -93, 0, "EPROTONOSUPPORT" },
            { -38, 0, "ENOSYS" }, { -22, 0, "EINVAL" }, { -1, 0, "EPERM" },
        };
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            int p[2];
            CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, p) == 0, "socketpair");
            fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL, 0) | O_NONBLOCK);
            uint8_t er[36];
            memset(er, 0, sizeof er);
            er[0] = 36; er[4] = 2;            /* NLMSG_ERROR */
            uint32_t seq = 77;
            memcpy(er + 8, &seq, 4);
            memcpy(er + 16, &cases[i].err, 4);
            CHECK(send(p[1], er, sizeof er, 0) == (ssize_t)sizeof er, "err send");
            int got = d2k_ct_probe_fd(p[0], 77, 50);
            if (got != cases[i].want) {
                printf("ПРОВАЛ: проба при %s дала %d\n", cases[i].what, got); fails++;
            }
            close(p[0]); close(p[1]);
        }
        /* Молчание — недоступно, и ждём не дольше заданного. */
        int p[2];
        CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, p) == 0, "socketpair");
        fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL, 0) | O_NONBLOCK);
        double a0 = now_ms();
        CHECK(d2k_ct_probe_fd(p[0], 78, 50) == 0, "молчание ядра принято за доступный ctnetlink");
        CHECK(now_ms() - a0 < 500.0, "проба ждала дольше своего срока");
        close(p[0]); close(p[1]);
        CHECK(d2k_ct_probe_fd(-1, 1, 50) == 0, "проба без сокета");
    }

    /* 6. Задача 56: TCP — счётчики и СОСТОЯНИЕ одним ответом. Ответ ядра
       роутера KN-1811 04.10.2026 на GET по кортежу живого потока Mac →
       173.194.221.119:443 (ESTABLISHED, packets 12/1 по /proc в тот же миг),
       целиком, как пришёл. */
    {
        uint8_t tr[400];
        size_t tn = unhex(
            "7401000000010200070000007b23000002000000340001801400018008000100c0a8014308000200adc2dd77"
            "1c000280050001000600000006000200f22000000600030001bb0000340002801400018008000100adc2dd77"
            "0800020058575d0b1c00028005000100060000000600020001bb000006000300f22000000800030000200"
            "19e08000700000004ac1c0009800c000100000000000000000c0c00020000000000000033e61c000a800c00"
            "010000000000000000010c000200000000000000003c300004802c00018005000100030000000500020006"
            "0000000500030000000000060004000300000006000500000000000800080000000000080018000001000028"
            "001980080000002500000008000100210000000a000200685edd83161a0000080003000000000138001a8008"
            "0000000000000008000100000000000c000200000000000000000005000300000000000500040000000000050"
            "005000000000008000c008acddbed08000b0000000002", tr, sizeof tr);
        CHECK(tn == 372, "фикстура TCP-ответа ядра собрана не той длины");
        d2k_ct_info ti;
        memset(&ti, 0xee, sizeof ti);
        CHECK(d2k_ct_info_parse(tr, tn, 7, &ti) == 0 && ti.orig_pkts == 12 && ti.reply_pkts == 1,
              "TCP-ответ ядра: счётчики не разобраны (ждали 12/1)");
        CHECK(ti.tcp_state_known && ti.tcp_state == D2K_CT_TCP_ESTABLISHED,
              "TCP-ответ ядра: состояние ESTABLISHED не прочитано");
        /* Этап 37: байты из тех же вложенных CTA_COUNTERS_* (настоящий ответ
           ядра KN-1811): клиент 13286 байт, сервер 60. Без них скорость и
           застой ответа по conntrack не посчитать. */
        CHECK(ti.orig_bytes == 13286 && ti.reply_bytes == 60,
              "TCP-ответ ядра: байтовые счётчики не разобраны (ждали 13286/60)");
        CHECK(ti.counters_known, "TCP-ответ ядра: счётчики есть, а признак «известны» не стоит");
        /* У UDP-ответа состояния TCP нет — «не сказано», а не ESTABLISHED. */
        memset(&ti, 0xee, sizeof ti);
        CHECK(d2k_ct_info_parse(rsp, rn, 7, &ti) == 0 && !ti.tcp_state_known,
              "у записи без CTA_PROTOINFO выдумано состояние TCP");
        /* Неотвечающий сокет: и этот запрос не ждёт. */
        int q[2];
        CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, q) == 0, "socketpair");
        fcntl(q[0], F_SETFL, fcntl(q[0], F_GETFL, 0) | O_NONBLOCK);
        double b = now_ms();
        for (int i = 0; i < 100; i++) {
            CHECK(d2k_ct_query_info_fd(q[0], (uint32_t)(300 + i), &t, &ti) == -1,
                  "молчащий сокет дал состояние");
            char drain[256];
            while (recv(q[1], drain, sizeof drain, MSG_DONTWAIT) > 0) { }
        }
        CHECK(now_ms() - b < 50.0, "сто TCP-запросов в молчащий сокет заняли больше 50 мс");
        tr[8] = 44; tr[9] = tr[10] = tr[11] = 0;
        CHECK(send(q[1], tr, tn, 0) == (ssize_t)tn, "tcp send");
        memset(&ti, 0, sizeof ti);
        CHECK(d2k_ct_query_info_fd(q[0], 44, &t, &ti) == 0 && ti.tcp_state_known &&
              ti.tcp_state == D2K_CT_TCP_ESTABLISHED && ti.reply_pkts == 1,
              "запрос по сокету не вернул состояние TCP");
        close(q[0]); close(q[1]);
    }

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("ctnetlink по кортежу: все проверки прошли\n");
    return 0;
}
