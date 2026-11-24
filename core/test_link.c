/* test_link.c — связь с датапатом (d2k_link.h), на настоящем ctlprobe.
 *
 * ctlprobe — тот же разбор команд (d2k_ctlsrv_command) и та же сессия
 * (d2k_session), что в боевом d2kd, но пакеты собираются на месте, а не из
 * NFQUEUE (см. шапку datapath/ctlprobe.c). Проверять d2k_link_* против
 * представления о протоколе бесполезно — расходятся они молча; здесь
 * расхождение падает набором, как и в internal/control/bridge_test.go на
 * Go-стороне (этот файл — её зеркало на C, тот же сценарий hello+quic).
 *
 * Управление стендом — по двум трубам (stdin/stdout ctlprobe, команды
 * "hello"/"quic"/"reply"/... построчно) и ОТДЕЛЬНО настоящий AF_UNIX-сокет
 * управления, который ctlprobe сам слушает по переданному пути — их два, и
 * путать нельзя: трубы это как в тесте дёргать стенд, сокет это то, что
 * проверяется.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "d2k_link.h"
#include "d2k_rawmeasure_wire.h"
#include "d2k_quicsnap.h"
#include "test_quic_pq.h"
/* Только ради D2K_KEY_WIRE_LEN — строим синтетические кадры руками (см.
 * send_synthetic ниже), тем же приёмом, что datapath/test_ctl.c: ширина
 * ключа нужна настоящая, а не переизобретённая здесь копией. */
#include "d2k_ctlsrv.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static void nap_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    (void)nanosleep(&ts, NULL);
}

static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[b[i] >> 4];
        out[2 * i + 1] = digits[b[i] & 0xFu];
    }
    out[2 * n] = '\0';
}

/* Собирает и пишет в fd кадр вида [длина][тип][ключ (13 произвольных байт,
 * не важных для этих проверок)][rest]. Нужен ровно для того, ЧЕГО настоящий
 * ctlprobe никогда не пришлёт: он воспитанный сервер и обрезанных/
 * переполненных событий не шлёт — а разбор обязан отказывать на них не
 * только на бумаге. rest может быть NULL при rest_len == 0. */
static void send_synthetic(int fd, uint16_t kind, const uint8_t *rest, size_t rest_len) {
    static uint8_t frame[6 + D2K_KEY_WIRE_LEN + D2K_SHAPE_MAX + 64];
    size_t body_len = D2K_KEY_WIRE_LEN + rest_len;
    uint32_t plen = (uint32_t)(2 + body_len);
    frame[0] = (uint8_t)(plen >> 24);
    frame[1] = (uint8_t)(plen >> 16);
    frame[2] = (uint8_t)(plen >> 8);
    frame[3] = (uint8_t)plen;
    frame[4] = (uint8_t)(kind >> 8);
    frame[5] = (uint8_t)kind;
    memset(frame + 6, 0xAB, D2K_KEY_WIRE_LEN);
    frame[6] = 6;
    if (rest_len) {
        memcpy(frame + 6 + D2K_KEY_WIRE_LEN, rest, rest_len);
    }
    (void)!write(fd, frame, 6 + body_len);
}

/* --- запуск и остановка стенда ------------------------------------------ */

typedef struct {
    pid_t pid;
    int   in_fd;  /* пишем сюда команды построчно */
    FILE *out;    /* читаем отсюда ответные строки */
} probe;

static void probe_write_line(probe *p, const char *line) {
    char buf[700];
    int n = snprintf(buf, sizeof buf, "%s\n", line);
    if (n > 0) {
        (void)!write(p->in_fd, buf, (size_t)n);
    }
}

/* Отправляет команду стенду и возвращает его ответную строку (без \n).
 * Синхронизирует: ctlprobe печатает строку-ответ ПОСЛЕ того, как обработал
 * команду и прогнал d2k_ctlsrv_pump — значит, к этому моменту событие(я) уже
 * лежат в сокете управления и можно смело читать их через d2k_link_next. */
static const char *probe_say(probe *p, const char *line) {
    static char resp[512];
    probe_write_line(p, line);
    if (!fgets(resp, sizeof resp, p->out)) {
        resp[0] = '\0';
        return resp;
    }
    resp[strcspn(resp, "\r\n")] = '\0';
    return resp;
}

/* 0 — запущен и поздоровался; -1 — отказ (причина в stderr самого дочернего
 * процесса и в сообщении здесь). */
static int probe_start(probe *p, const char *sock_path) {
    if (access("../datapath/ctlprobe", X_OK) != 0) {
        fprintf(stderr,
                "стенд не собран (%s); нужен `make -C datapath ctlprobe`\n",
                strerror(errno));
        return -1;
    }
    int inpipe[2], outpipe[2];
    if (pipe(inpipe) < 0 || pipe(outpipe) < 0) {
        fprintf(stderr, "pipe: %s\n", strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        (void)!dup2(inpipe[0], STDIN_FILENO);
        (void)!dup2(outpipe[1], STDOUT_FILENO);
        close(inpipe[0]);
        close(inpipe[1]);
        close(outpipe[0]);
        close(outpipe[1]);
        execl("../datapath/ctlprobe", "ctlprobe", sock_path, (char *)NULL);
        _exit(127); /* execl не вернулся бы при успехе */
    }
    close(inpipe[0]);
    close(outpipe[1]);
    p->pid = pid;
    p->in_fd = inpipe[1];
    p->out = fdopen(outpipe[0], "r");
    if (!p->out) {
        fprintf(stderr, "fdopen: %s\n", strerror(errno));
        return -1;
    }
    char line[512];
    if (!fgets(line, sizeof line, p->out)) {
        fprintf(stderr, "стенд молчит на старте\n");
        return -1;
    }
    line[strcspn(line, "\r\n")] = '\0';
    if (strcmp(line, "готов") != 0) {
        fprintf(stderr, "стенд не поздоровался: \"%s\"\n", line);
        return -1;
    }
    return 0;
}

static void probe_stop(probe *p, const char *sock_path) {
    if (p->in_fd >= 0) {
        probe_write_line(p, "quit");
        close(p->in_fd);
    }
    if (p->out) {
        fclose(p->out);
    }
    if (p->pid > 0) {
        (void)waitpid(p->pid, NULL, 0);
    }
    unlink(sock_path);
}

static int dial_retry(const char *sock_path, char *err, size_t errcap) {
    int fd = -1;
    for (int i = 0; i < 50; i++) {
        fd = d2k_link_open(sock_path, err, errcap);
        if (fd >= 0) {
            return fd;
        }
        nap_ms(20);
    }
    return fd;
}

/* Читает события, пропуская мимо всё, что не нужного вида, — до tries
 * штук. Нужно потому, что за приветствием без плана честно идёт REFUSED
 * (session.c ищет план и не находит), и это не сбой, а протокол (тот же
 * приём, что nextHello в internal/control/bridge_test.go). Возвращает 0,
 * если нашли (и *out заполнено), -1 иначе (тайм-аут/ошибка/не нашли за
 * tries попыток — вызывающему достаточно этой границы, причина не важна: он
 * всё равно CHECK'ает факт "нашли или нет"). */
static int next_of_kind(int fd, uint16_t want, int tries, d2k_ev *out,
                        char *err, size_t errcap) {
    for (int i = 0; i < tries; i++) {
        int rc = d2k_link_next(fd, out, 2000, err, errcap);
        if (rc != 0) {
            return -1;
        }
        if (out->kind == want) {
            return 0;
        }
    }
    return -1;
}

/* Событие с заданной маской встреченных типов и остальными полями
 * занулёнными — ровно то, что даёт d2k_link_next (см. memset в начале
 * d2k_link_next), только собранное руками для проверки порога без сети. */
static d2k_ev ev_with_seen(uint8_t seen_types) {
    d2k_ev ev;
    memset(&ev, 0, sizeof ev);
    ev.seen_types = seen_types;
    return ev;
}

int main(void) {
#ifndef D2K_EV_RAW_SUSPECT
    CHECK(0,"incarnation-bound suspicion event missing");
#else
    {
        int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"flow incarnation socketpair");
        uint8_t rest[11+24]={0};rest[0]=D2K_SUSPECT_SILENT;rest[6]=D2K_LINK_PLANNED_NO;
        rest[7]=D2K_LINK_SHAPE_RAW;rest[10]=D2K_CLIENT_SIDE_HIGH;rest[11]=9;rest[34]=7;
        d2k_ev ev;char err[128];
        send_synthetic(sv[0],D2K_EV_RAW_SUSPECT,rest,sizeof rest);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err)&&ev.kind==D2K_EV_SUSPECT&&
              ev.flow_incarnation==7&&ev.flow_epoch[0]==9&&ev.client_side==D2K_CLIENT_SIDE_HIGH,"suspicion incarnation lost");
        for(size_t n=0;n<sizeof rest;n++) {
            send_synthetic(sv[0],D2K_EV_RAW_SUSPECT,rest,n);
            CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)<0,"partial incarnation accepted");
        }
#ifdef D2K_EV_RAW_FLOW
        uint8_t flow[25]={0};flow[0]=D2K_CLIENT_SIDE_HIGH;flow[1]=9;flow[24]=7;
        send_synthetic(sv[0],D2K_EV_RAW_FLOW,flow,sizeof flow);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err)&&ev.kind==D2K_EV_FLOW&&ev.flow_incarnation==7&&ev.flow_epoch[0]==9,"flow birth lost identity");
        for(size_t n=0;n<sizeof flow;n++) {send_synthetic(sv[0],D2K_EV_RAW_FLOW,flow,n);
            CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)<0,"partial flow identity accepted");}
#else
        CHECK(0,"flow birth identity missing");
#endif
        rest[34]=0;send_synthetic(sv[0],D2K_EV_RAW_SUSPECT,rest,sizeof rest);
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)<0,"zero incarnation accepted");rest[34]=7;
        rest[11]=0;send_synthetic(sv[0],D2K_EV_RAW_SUSPECT,rest,sizeof rest);
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)<0,"zero table epoch accepted");
        close(sv[0]);close(sv[1]);
    }
#endif

#ifndef D2K_EV_RAW_MEASURE
    CHECK(0,"measurement result event missing");
#else
    {
        int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"measurement result socketpair");
        struct d2k_rawmeasure_report r={0};
        r.request.tuple.family=6;r.request.tuple.proto=17;
        r.request.tuple.src[15]=1;r.request.tuple.dst[15]=2;
        r.request.tuple.sport_be[1]=9;r.request.tuple.dport_be[1]=8;
        r.request.epoch[0]=3;r.request.generation=7;r.request.token[0]=4;r.request.seconds=10;
        r.code=D2K_RM_REPEAT_SILENT;r.flags=D2K_RM_PRIOR_REPLY;
        r.sample_digest[0]=1;
        r.sample_len=20;r.smallest_data=20;r.largest_data=20;r.client_data=2;r.exact_repeats=1;
        r.repeat_gap_ms=64000;r.repeat_age_ms=12;
        uint8_t frame[6+D2K_KEY_WIRE_LEN+D2K_RM_REPORT_LEN]={0};
        frame[3]=(uint8_t)(sizeof frame-4);frame[5]=D2K_EV_RAW_MEASURE;
        uint8_t *key=frame+6;key[0]=6;key[16]=1;key[32]=2;key[34]=9;key[36]=8;key[37]=17;
        CHECK(!d2k_rawmeasure_report_write(key+D2K_KEY_WIRE_LEN,D2K_RM_REPORT_LEN,&r),"measurement result encode");
        d2k_ev ev;char err[128];
        CHECK(write(sv[0],frame,sizeof frame)==sizeof frame,"measurement result write");
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.raw_measure.request.generation==7 &&
              ev.raw_measure.exact_repeats==1 && ev.raw_measure.request.token[0]==4,"measurement result context lost");
        CHECK(ev.raw_measure.repeat_gap_ms==64000 && ev.raw_measure.repeat_age_ms==12,
              "controller codec lost v27 repeat timing facts");
        frame[3]=(uint8_t)(sizeof frame-4-8); /* v26 body: timing absent */
        CHECK(write(sv[0],frame,sizeof frame-8)==(ssize_t)(sizeof frame-8),"short result write");
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)<0,"v26 report length accepted by v27 controller");
        frame[3]=(uint8_t)(sizeof frame-4);
        key[36]=7; /* valid report but envelope points at another service */
        CHECK(write(sv[0],frame,sizeof frame)==sizeof frame,"foreign result write");
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)<0,"foreign service accepted");
        key[36]=8;key[37]=6;
        CHECK(write(sv[0],frame,sizeof frame)==sizeof frame,"foreign transport write");
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)<0,"foreign transport accepted");
        key[37]=17;key[16]=2;key[32]=1;key[34]=8;key[36]=9;
        CHECK(write(sv[0],frame,sizeof frame)==sizeof frame,"reverse result write");
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err),"reversed envelope rejected");
        close(sv[0]);close(sv[1]);
    }
#endif

    {
        int pair[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,pair),"RAW_MEASURE socketpair");
        struct d2k_rawmeasure_request request;memset(&request,0,sizeof request);
        request.tuple.family=6;request.tuple.proto=17;request.tuple.src[15]=1;request.tuple.dst[15]=2;
        request.tuple.sport_be[0]=1;request.tuple.dport_be[0]=2;request.epoch[0]=3;request.generation=0x0102030405060708ULL;
        request.token[15]=9;request.seconds=20;char err[128];uint8_t wire[6+D2K_RM_REQUEST_LEN];
        CHECK(!d2k_link_raw_measure(pair[0],&request,err,sizeof err),"RAW_MEASURE send");
        CHECK(read(pair[1],wire,sizeof wire)==(ssize_t)sizeof wire,"RAW_MEASURE frame length");
        CHECK(wire[0]==0&&wire[1]==0&&wire[2]==0&&wire[3]==2+D2K_RM_REQUEST_LEN&&
              wire[4]==(D2K_CMD_RAW_MEASURE>>8)&&wire[5]==(D2K_CMD_RAW_MEASURE&255),"RAW_MEASURE frame header");
        struct d2k_rawmeasure_request got;
        CHECK(!d2k_rawmeasure_request_read(&got,wire+6,D2K_RM_REQUEST_LEN)&&got.generation==request.generation&&
              got.tuple.proto==17&&got.tuple.family==6&&!memcmp(got.token,request.token,16),"RAW_MEASURE wire context");

#ifndef D2K_LINK_RAW_PROBE
        CHECK(0,"measured trial sender missing");
#else
        struct d2k_rawmeasure_report report={0};report.request=request;
        report.code=D2K_RM_REPEAT_SILENT;report.flags=D2K_RM_PRIOR_REPLY;
        report.sample_len=report.smallest_data=report.largest_data=1;report.client_data=2;report.exact_repeats=1;report.sample_digest[0]=5;
        static const uint8_t program[]={'D','2','K','P',0,1,0,1,0,0,0,2,0,2,0,2,17,2,1,3,0,1,0};
        char hex[2*sizeof program+1];to_hex(program,sizeof program,hex);uint8_t trial[16]={0x55};
        uint8_t trialwire[6+D2K_RM_REPORT_LEN+20+sizeof program];
        CHECK(!d2k_link_set_raw_probe(pair[0],&report,trial,500,hex,err,sizeof err),"measured trial send");
        CHECK(read(pair[1],trialwire,sizeof trialwire)==sizeof trialwire,"measured trial frame length");
        struct d2k_rawmeasure_report decoded;
        CHECK(trialwire[4]==(D2K_CMD_SET_RAW_PROBE>>8)&&trialwire[5]==(D2K_CMD_SET_RAW_PROBE&255)&&
              !d2k_rawmeasure_report_read(&decoded,trialwire+6,D2K_RM_REPORT_LEN)&&decoded.request.generation==request.generation,
              "trial sender changed measured identity");
        CHECK(!memcmp(trialwire+6+D2K_RM_REPORT_LEN,trial,16)&&
              d2k_rm_get32(trialwire+6+D2K_RM_REPORT_LEN+16)==500&&
              !memcmp(trialwire+6+D2K_RM_REPORT_LEN+20,program,sizeof program),"trial sender lost token/lease/program");
        CHECK(d2k_link_set_raw_probe(pair[0],&report,trial,0,hex,err,sizeof err)<0,"zero trial lease sent");
        uint16_t sp=htons(49001),dp=htons(7777);
        CHECK(!d2k_link_del_addr_probe_family(pair[0],request.tuple.src,sp,request.tuple.dst,dp,6,6,trial,err,sizeof err),"TCP exact trial cleanup rejected");
        uint8_t deletion[6+38+16];CHECK(read(pair[1],deletion,sizeof deletion)==sizeof deletion&&deletion[43]==6&&
            !memcmp(deletion+44,trial,16),"TCP cleanup lost transport or ownership token");
#endif
        memset(request.token,0,16);CHECK(d2k_link_raw_measure(pair[0],&request,err,sizeof err)<0,"RAW_MEASURE empty token allowed");
        close(pair[0]);close(pair[1]);
    }

    {
        int sv[2]; CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"bound exchange socketpair");
        uint8_t owned[32]={22,0,0,0,0,64,1,D2K_LINK_PLANNED_NO};
        owned[8]=9;owned[31]=7;
        d2k_ev observed;char message[128];
        send_synthetic(sv[0],D2K_EV_OWNED_EXCHANGE,owned,sizeof owned);
        CHECK(!d2k_link_next(sv[1],&observed,100,message,sizeof message) &&
              observed.kind==D2K_EV_EXCHANGE && observed.flow_incarnation==7 &&
              observed.flow_epoch[0]==9 && observed.num==64 && !observed.execution_id,
              "owned direct exchange identity lost");
        for(size_t n=0;n<sizeof owned;n++) {
            send_synthetic(sv[0],D2K_EV_OWNED_EXCHANGE,owned,n);
            CHECK(d2k_link_next(sv[1],&observed,100,message,sizeof message)<0,"truncated owned exchange accepted");
        }
        owned[31]=0;send_synthetic(sv[0],D2K_EV_OWNED_EXCHANGE,owned,sizeof owned);
        CHECK(d2k_link_next(sv[1],&observed,100,message,sizeof message)<0,"zero exchange incarnation accepted");
        owned[31]=7;owned[8]=0;send_synthetic(sv[0],D2K_EV_OWNED_EXCHANGE,owned,sizeof owned);
        CHECK(d2k_link_next(sv[1],&observed,100,message,sizeof message)<0,"zero exchange epoch accepted");
        uint8_t rest[8+32+D2K_CTL_EXECUTION_LEN]={0};
        rest[0]=D2K_UDP_PROOF_STUN; rest[7]=D2K_LINK_PLANNED_YES;
        memset(rest+8,0x51,16);memset(rest+24,0x72,16);
        uint8_t *p=rest+40;
        for(unsigned b=0;b<8;b++){p[b]=(uint8_t)(1+b);p[8+b]=(uint8_t)(0x81+b);}
        p[16]=D2K_BIND_FLOW;p[17]=4;p[18]=D2K_PLAN_SHAPE_VOICE;p[19]=1;
        memset(p+20,0x91,16);
        d2k_ev ev;char err[128];
        send_synthetic(sv[0],D2K_EV_EXCHANGE,rest,sizeof rest);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) &&
              ev.execution_id==UINT64_C(0x0102030405060708) &&
              ev.execution_binding.generation==UINT64_C(0x8182838485868788) &&
              !memcmp(ev.plan_id,rest+8,16) && !memcmp(ev.trial_id,rest+24,16) &&
              !memcmp(ev.execution_binding.epoch,p+20,16),"EXCHANGE lost request context");
        uint8_t bound_owned[sizeof rest+24];
        memcpy(bound_owned,rest,sizeof rest);
        memset(bound_owned+sizeof rest,0,24);
        bound_owned[sizeof rest]=9;
        bound_owned[sizeof bound_owned-1]=7;
        send_synthetic(sv[0],D2K_EV_OWNED_EXCHANGE,bound_owned,sizeof bound_owned);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) &&
              ev.kind==D2K_EV_EXCHANGE && ev.flow_incarnation==7 && ev.flow_epoch[0]==9 &&
              ev.execution_id==UINT64_C(0x0102030405060708) &&
              ev.execution_binding.generation==UINT64_C(0x8182838485868788) &&
              !memcmp(ev.plan_id,rest+8,16) && !memcmp(ev.trial_id,rest+24,16) &&
              !memcmp(ev.execution_binding.epoch,p+20,16),"owned EXCHANGE lost execution binding");
        for(size_t n=9;n<sizeof rest;n++) {
            send_synthetic(sv[0],D2K_EV_EXCHANGE,rest,n);
            CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)!=0,"partial EXCHANGE context accepted");
        }
        send_synthetic(sv[0],D2K_EV_EXCHANGE,rest,8);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && !ev.execution_id &&
              !d2k_binding_known(&ev.execution_binding),"unbound EXCHANGE must remain unknown");
        close(sv[0]);close(sv[1]);
    }
    {
        int sv[2]; CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"bound suspicion socketpair");
        uint8_t rest[11+32+D2K_CTL_EXECUTION_LEN]={0};
        rest[0]=D2K_UDP_PROOF_STUN; rest[6]=D2K_LINK_PLANNED_YES;
        memset(rest+11,0x51,16);memset(rest+27,0x72,16);
        uint8_t *p=rest+43;
        for(unsigned b=0;b<8;b++){p[b]=(uint8_t)(1+b);p[8+b]=(uint8_t)(0x81+b);}
        p[16]=D2K_BIND_FLOW;p[17]=4;p[18]=D2K_PLAN_SHAPE_VOICE;p[19]=1;
        memset(p+20,0x91,16);
        d2k_ev ev;char err[128];
        send_synthetic(sv[0],D2K_EV_SUSPECT,rest,sizeof rest);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) &&
              ev.execution_id==UINT64_C(0x0102030405060708) &&
              ev.execution_binding.generation==UINT64_C(0x8182838485868788) &&
              !memcmp(ev.plan_id,rest+11,16) && !memcmp(ev.trial_id,rest+27,16) &&
              !memcmp(ev.execution_binding.epoch,p+20,16),"SUSPECT lost request context");
        for(size_t n=12;n<sizeof rest;n++) {
            send_synthetic(sv[0],D2K_EV_SUSPECT,rest,n);
            CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)!=0,"partial SUSPECT context accepted");
        }
        send_synthetic(sv[0],D2K_EV_SUSPECT,rest,11);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && !ev.execution_id &&
              !d2k_binding_known(&ev.execution_binding),"unbound SUSPECT must remain unknown");
        close(sv[0]);close(sv[1]);
    }

    {   /* Этап 49: итог позднего наблюдения — итог, сторона, повторы; вне
           диапазона и короче — порча. */
        int sv[2]; CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"late obs socketpair");
        uint8_t rest[4+D2K_TRIAL_ID_LEN]={D2K_LATEOBS_REPEAT_SILENT,D2K_CLIENT_SIDE_LOW,0x01,0x02};
        for(int i=0;i<D2K_TRIAL_ID_LEN;i++) rest[4+i]=(uint8_t)(0x30+i);
        d2k_ev ev;char err[128];
        send_synthetic(sv[0],D2K_EV_LATE_OBS,rest,sizeof rest);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.kind==D2K_EV_LATE_OBS &&
              ev.code==D2K_LATEOBS_REPEAT_SILENT && ev.client_side==D2K_CLIENT_SIDE_LOW && ev.num==0x0102 &&
              !memcmp(ev.trial_id,rest+4,D2K_TRIAL_ID_LEN),
              "LATE_OBS разобран неверно (итог, сторона, повторы, токен)");
        send_synthetic(sv[0],D2K_EV_LATE_OBS,rest,4);
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)!=0,"LATE_OBS без токена принят");
        rest[0]=D2K_LATEOBS_UNAVAILABLE+1;
        send_synthetic(sv[0],D2K_EV_LATE_OBS,rest,sizeof rest);
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)!=0,"LATE_OBS с неизвестным итогом принят");
        close(sv[0]);close(sv[1]);
    }

    {   /* Этап 42: факт появления потока — сторона клиента необязательна по
           длине; вне диапазона — порча. */
        int sv[2]; CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"flow fact socketpair");
        uint8_t rest[1]={D2K_CLIENT_SIDE_HIGH};
        d2k_ev ev;char err[128];
        send_synthetic(sv[0],D2K_EV_FLOW,rest,1);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.kind==D2K_EV_FLOW &&
              ev.client_side==D2K_CLIENT_SIDE_HIGH,"FLOW lost observed client endpoint");
        send_synthetic(sv[0],D2K_EV_FLOW,rest,0);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.kind==D2K_EV_FLOW &&
              ev.client_side==0,"FLOW without endpoint must stay unknown");
        rest[0]=3;
        send_synthetic(sv[0],D2K_EV_FLOW,rest,1);
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)!=0,"FLOW with invalid endpoint accepted");
        close(sv[0]);close(sv[1]);
    }

    {   /* Приветствие: совместимая и несовместимые пары (очередь 28.10, задание 02).
           Контракт проекта — точная версия провода и свой выпуск; иначе
           команды другой раскладки и ACK без нужных полей. */
        int sv[2]; CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"greeting socketpair");
        size_t idlen=strlen(D2K_RELEASE_ID);
        uint8_t rest[7+64]; memset(rest,0,sizeof rest);
        rest[0]=(uint8_t)(D2K_CTL_PROTO_VERSION>>8); rest[1]=(uint8_t)D2K_CTL_PROTO_VERSION;
        rest[4]=0x05; rest[5]=0xdc; rest[6]=(uint8_t)idlen; memcpy(rest+7,D2K_RELEASE_ID,idlen);
        d2k_ev ev; char why[160];
        send_synthetic(sv[1],D2K_EV_PROTO,rest,7+idlen);
        CHECK(d2k_link_greeting(sv[0],1000,&ev,why,sizeof why)==0 && ev.kind==D2K_EV_PROTO &&
              ev.num==D2K_CTL_PROTO_VERSION && ev.send_maxlen==1500 && !strcmp(ev.release_id,D2K_RELEASE_ID),
              "own greeting accepted with its fields");
        rest[1]=(uint8_t)(D2K_CTL_PROTO_VERSION-1); why[0]=0;
        send_synthetic(sv[1],D2K_EV_PROTO,rest,7+idlen);
        CHECK(d2k_link_greeting(sv[0],1000,&ev,why,sizeof why)==-1 && strstr(why,"несовместимое приветствие"),
              "previous wire version refused by name");
        /* Этап 21: датапат ДО формы RAW (v23) отвергал бы SET_ADDR формы 8 — такая
           пара не должна начинать работу вовсе; версия поднята до 24. */
        CHECK(D2K_CTL_PROTO_VERSION >= 24u, "wire version not bumped for shape RAW (8)");
        CHECK(D2K_CTL_PROTO_VERSION >= 27u && D2K_RM_REPORT_LEN == 147u,
              "RAW report timing changed without wire version bump");
        rest[1]=23; why[0]=0;
        send_synthetic(sv[1],D2K_EV_PROTO,rest,7+idlen);
        CHECK(d2k_link_greeting(sv[0],1000,&ev,why,sizeof why)==-1, "pre-RAW datapath (v23) greeting accepted");
        rest[1]=(uint8_t)(D2K_CTL_PROTO_VERSION+1); why[0]=0;
        send_synthetic(sv[1],D2K_EV_PROTO,rest,7+idlen);
        CHECK(d2k_link_greeting(sv[0],1000,&ev,why,sizeof why)==-1 && strstr(why,"несовместимое приветствие"),
              "future wire version refused — exact match, not minimum");
        rest[1]=(uint8_t)D2K_CTL_PROTO_VERSION;
        {   /* чужой выпуск той же версии провода: тот же алфавит, другая длина */
            uint8_t other[7+64]; memcpy(other,rest,sizeof other);
            size_t olen = idlen>1 ? idlen-1 : idlen+1;
            if (olen>idlen) other[7+idlen]='x';
            other[6]=(uint8_t)olen; why[0]=0;
            send_synthetic(sv[1],D2K_EV_PROTO,other,7+olen);
            CHECK(d2k_link_greeting(sv[0],1000,&ev,why,sizeof why)==-1 && strstr(why,"выпуск"),
                  "same wire version but foreign release refused");
        }
        {   /* первым пришло не приветствие */
            uint8_t hello[2]={0,0}; why[0]=0;
            send_synthetic(sv[1],D2K_EV_HELLO,hello,1);
            CHECK(d2k_link_greeting(sv[0],1000,&ev,why,sizeof why)==-1 && strstr(why,"не приветствие"),
                  "non-greeting first event refused");
        }
        why[0]=0;
        CHECK(d2k_link_greeting(sv[0],20,&ev,why,sizeof why)==-1 && why[0],
              "silent peer is not a compatible peer");
        close(sv[0]); close(sv[1]);
    }
    {
        int sv[2];d2k_ev ev;char err[160];
        CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"bound ACK fixture socket");
        uint8_t rest[4+16+28+1]={0};
        rest[0]=D2K_CMD_SET_NAME_BOUND>>8;rest[1]=(uint8_t)D2K_CMD_SET_NAME_BOUND;
        rest[2]=1;rest[4]=0x87;
        for(unsigned i=0;i<8;i++)rest[20+i]=(uint8_t)(0x81+i);
        rest[28]=D2K_BIND_NAME;rest[29]=6;rest[30]=D2K_PLAN_SHAPE_HTTP;
        for(unsigned i=0;i<16;i++)rest[32+i]=(uint8_t)(0xf0+i);
        send_synthetic(sv[0],D2K_EV_ACK,rest,48);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.trial_id[0]==0x87 &&
              ev.execution_binding.generation==UINT64_C(0x8182838485868788) &&
              ev.execution_binding.family==6 && !memcmp(ev.execution_binding.epoch,rest+32,16),
              "permanent ACK loses command or binding identity");
        for(size_t n=4;n<48;n++) {
            send_synthetic(sv[0],D2K_EV_ACK,rest,n);
            CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)==-1,"truncated permanent ACK accepted");
        }
        send_synthetic(sv[0],D2K_EV_ACK,rest,49);
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)==-1,"oversized permanent ACK accepted");
        rest[29]=5;send_synthetic(sv[0],D2K_EV_ACK,rest,48);
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)==-1,"invalid ACK binding family accepted");
        /* Форма RAW (8, этапы 12/16) в контексте привязки — законна: постоянный
           адресный план формы RAW иначе терял APPLIED/EXCHANGE у контроллера как
           «повреждённый контекст» (стенд lab-udp-raw.sh, 28.10.2026). */
        rest[29]=6;rest[30]=D2K_PLAN_SHAPE_RAW;send_synthetic(sv[0],D2K_EV_ACK,rest,48);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.execution_binding.shape==D2K_PLAN_SHAPE_RAW,
              "binding context with shape RAW refused as corrupted");
        rest[0]=D2K_CMD_SET_DNS_ENDPOINT>>8;rest[1]=(uint8_t)D2K_CMD_SET_DNS_ENDPOINT;
        rest[28]=D2K_BIND_ADDR;rest[30]=D2K_PLAN_SHAPE_DNS;
        send_synthetic(sv[0],D2K_EV_ACK,rest,48);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.trial_id[0]==0x87 &&
              ev.execution_binding.shape==D2K_PLAN_SHAPE_DNS && d2k_binding_known(&ev.execution_binding),
              "DNS endpoint ACK loses request ID or binding generation");
        rest[0]=D2K_CMD_SET_PREFLIGHT_LEASE>>8;rest[1]=(uint8_t)D2K_CMD_SET_PREFLIGHT_LEASE;
        rest[30]=D2K_PLAN_SHAPE_MODERN;rest[31]=1;
        send_synthetic(sv[0],D2K_EV_ACK,rest,48);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.trial_id[0]==0x87 &&
              ev.execution_binding.kind==D2K_BIND_ADDR && ev.execution_binding.temporary &&
              ev.execution_binding.shape==D2K_PLAN_SHAPE_MODERN,
              "preflight lease ACK loses lease ID or temporary binding");
        rest[30]=D2K_PLAN_SHAPE_DNS+1;send_synthetic(sv[0],D2K_EV_ACK,rest,48);
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)==-1,"unknown binding shape accepted");
        close(sv[0]);close(sv[1]);
    }

    /* Independent wire fixture: high bytes, both fates, every truncated tail. */
    for (unsigned refused = 0; refused < 2; refused++) {
        int sv[2];
        CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv), "execution context socketpair");
        const size_t base = refused ? 34u : 32u;
        uint8_t rest[34 + D2K_CTL_EXECUTION_LEN] = {0};
        uint8_t *p = rest + base;
        for (unsigned b = 0; b < 8; b++) { p[b] = 1+b; p[8+b] = 0x81+b; }
        p[16] = D2K_BIND_FLOW; p[17] = 6; p[18] = D2K_PLAN_SHAPE_QUIC; p[19] = 1;
        for (unsigned b = 0; b < 16; b++) p[20+b] = (uint8_t)(0xf0+b);
        d2k_ev ev; char err[128];
        const uint16_t kind = refused ? D2K_EV_REFUSED : D2K_EV_APPLIED;
        send_synthetic(sv[0], kind, rest, base + D2K_CTL_EXECUTION_LEN);
        CHECK(!d2k_link_next(sv[1], &ev, 100, err, sizeof err) &&
              ev.execution_id == UINT64_C(0x0102030405060708) &&
              ev.execution_binding.generation == UINT64_C(0x8182838485868788) &&
              ev.execution_binding.kind == D2K_BIND_FLOW && ev.execution_binding.family == 6 &&
              ev.execution_binding.shape == D2K_PLAN_SHAPE_QUIC && ev.execution_binding.temporary == 1 &&
              !memcmp(ev.execution_binding.epoch, p+20, 16),
              "execution context endian/IPv6/probe fields lost");
        for (size_t tail = 1; tail < D2K_CTL_EXECUTION_LEN; tail++) {
            send_synthetic(sv[0], kind, rest, base + tail);
            CHECK(d2k_link_next(sv[1], &ev, 100, err, sizeof err) == -1,
                  "truncated execution context accepted");
        }
        p[17] = 5;
        send_synthetic(sv[0], kind, rest, base + D2K_CTL_EXECUTION_LEN);
        CHECK(d2k_link_next(sv[1], &ev, 100, err, sizeof err) == -1,
              "invalid execution family accepted");
        send_synthetic(sv[0], kind, rest, base);
        CHECK(!d2k_link_next(sv[1], &ev, 100, err, sizeof err) &&
              !ev.execution_id && !ev.execution_binding.generation,
              "legacy frame fabricated execution context");
        close(sv[0]); close(sv[1]);
    }
    /* v20 (задача 66): снимок QUIC — пачка Initial-датаграмм клиента.
       Приветствие Chrome с ML-KEM длиннее прежнего предела 2048, и обрезка
       снимка на проводе означала бы замер половиной приветствия. */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (пачка QUIC) не создался");
        if (sv[0] >= 0) {
            uint8_t d1[1500], d2[1500];
            size_t l1 = 0, l2 = 0;
            CHECK(d2k_test_pq_initials("rutracker.org", d1, &l1, d2, &l2) == 0,
                  "стенд двух Initial");
            const uint8_t *dg[2] = {d1, d2};
            size_t len[2] = {l1, l2};
            static uint8_t rest[D2K_SHAPE_MAX];
            size_t bl = d2k_qsnap_pack(dg, len, 2, rest, sizeof rest);
            CHECK(bl > 2048, "пачка двух датаграмм не длиннее прежнего предела");
            send_synthetic(sv[1], D2K_EV_SHAPE, rest, bl);
            d2k_ev ev;
            char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0 &&
                  ev.kind == D2K_EV_SHAPE && ev.shape_len == bl &&
                  d2k_qsnap_is(ev.shape, ev.shape_len) &&
                  memcmp(ev.shape, rest, bl) == 0,
                  "пачка приехала не целиком");
            close(sv[0]); close(sv[1]);
        }
    }

    /* v10 (задача 51): вставка провайдера в HTTP и имя с HTTPS. */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "HTTP portal socketpair");
        const uint8_t rest[] = {1, 13, 'r','u','t','r','a','c','k','e','r','.','o','r','g'};
        send_synthetic(sv[0], D2K_EV_HTTP_PORTAL, rest, sizeof rest);
        d2k_ev ev;
        char err[256];
        CHECK(d2k_link_next(sv[1], &ev, 100, err, sizeof err) == 0 &&
              ev.kind == D2K_EV_HTTP_PORTAL && ev.code == 1 &&
              strcmp(ev.name, "rutracker.org") == 0, "HTTP_PORTAL разобран не так");
        uint8_t bound[sizeof rest + 50 + 7] = {0};
        memcpy(bound, rest, sizeof rest);
        bound[sizeof rest + 7] = 72;
        bound[sizeof rest + 8] = 0x42;
        bound[sizeof rest + 47] = 99;
        bound[sizeof rest + 49] = 7;
        memcpy(bound + sizeof rest + 50, "/False/", 7);
        send_synthetic(sv[0], D2K_EV_HTTP_PORTAL, bound, sizeof bound);
        CHECK(d2k_link_next(sv[1], &ev, 100, err, sizeof err) == 0 &&
              ev.plan_id[0] == 0x42 && ev.live_execution == 72 && ev.live_request_ms == 99 && !strcmp(ev.live_http_path, "/False/"),
              "HTTP portal lost exact executed plan identity");
        uint8_t response[sizeof bound+D2K_CTL_BINDING_LEN+18]={0};
        memcpy(response,bound,sizeof bound);response[0]=1;
        uint8_t *meta=response+sizeof bound;
        meta[7]=9;meta[8]=D2K_BIND_NAME;meta[9]=4;meta[10]=D2K_PLAN_SHAPE_HTTP;meta[12]=7;
        meta+=D2K_CTL_BINDING_LEN;meta[1]=200;meta[8]=1;meta[9]=2;meta[17]=2;
        send_synthetic(sv[0],D2K_EV_HTTP_RESPONSE,response,sizeof response);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.kind==D2K_EV_HTTP_RESPONSE &&
              ev.code==1 && ev.live_http_status==200 && ev.live_body_bytes==258 && ev.live_request_no==2 &&
              ev.execution_binding.generation==9 && ev.execution_binding.epoch[0]==7 && ev.live_execution==72,
              "complete live response keeps framing and binding over control socket");
        /* v19: код 4 — обрыв ответа без плана (поле 15.10.2026, cdnbase). */
        response[0]=4;
        send_synthetic(sv[0],D2K_EV_HTTP_RESPONSE,response,sizeof response);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.kind==D2K_EV_HTTP_RESPONSE &&
              ev.code==4 && ev.live_body_bytes==258 && !strcmp(ev.live_http_path,"/False/"),
              "a cut (code 4) is decoded with its path and received body");
        response[0]=5;
        send_synthetic(sv[0],D2K_EV_HTTP_RESPONSE,response,sizeof response);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.code==5 &&
              !strcmp(ev.live_http_path,"/False/"),
              "a reset before response keeps the request path over the control socket");
        response[0]=6;
        send_synthetic(sv[0],D2K_EV_HTTP_RESPONSE,response,sizeof response);
        CHECK(!d2k_link_next(sv[1],&ev,100,err,sizeof err) && ev.code==6 &&
              !strcmp(ev.live_http_path,"/False/"),
              "a repeated unanswered request keeps its path over the control socket");
        response[0]=7;
        send_synthetic(sv[0],D2K_EV_HTTP_RESPONSE,response,sizeof response);
        CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)==-1,"unknown HTTP response code accepted");
        response[0]=1;
        for(size_t k=sizeof bound;k<sizeof response;k++) {
            send_synthetic(sv[0],D2K_EV_HTTP_RESPONSE,response,k);
            CHECK(d2k_link_next(sv[1],&ev,100,err,sizeof err)==-1,"truncated live response evidence accepted");
        }
        const uint8_t cut[] = {0, 13, 'r','u'};
        send_synthetic(sv[0], D2K_EV_HTTP_PORTAL, cut, sizeof cut);
        CHECK(d2k_link_next(sv[1], &ev, 100, err, sizeof err) == -1,
              "HTTP_PORTAL с обрезанным именем принят");
        CHECK(d2k_link_set_https(sv[0], "RuTracker.org", 21600, err, sizeof err) == 0,
              "SET_HTTPS не отправился");
        uint8_t f[64];
        ssize_t n = read(sv[1], f, sizeof f);
        CHECK(n == 6 + 1 + 13 + 4 && f[3] == 2 + 1 + 13 + 4 &&
              f[4] == (uint8_t)(D2K_CMD_SET_HTTPS >> 8) && f[5] == (uint8_t)D2K_CMD_SET_HTTPS &&
              f[6] == 13 && memcmp(f + 7, "RuTracker.org", 13) == 0 &&
              f[20] == 0 && f[21] == 0 && f[22] == 0x54 && f[23] == 0x60,
              "кадр SET_HTTPS собран не так");
        CHECK(d2k_link_set_https(sv[0], "", 1, err, sizeof err) != 0, "SET_HTTPS с пустым именем ушёл");
        close(sv[0]); close(sv[1]);
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "IPv6 event socketpair");
        /* v4 control: family, two 16-byte addresses, ports, transport, name. */
        uint8_t frame[45] = {0,0,0,41,0,0};
        frame[4] = (uint8_t)(D2K_EV_HELLO >> 8);
        frame[5] = (uint8_t)D2K_EV_HELLO;
        frame[6] = 6;
        frame[7] = 0x20; frame[8] = 1; frame[22] = 1;
        frame[23] = 0x20; frame[24] = 2; frame[38] = 2;
        frame[39] = 0xc0; frame[40] = 1;
        frame[41] = 1; frame[42] = 0xbb;
        frame[43] = 6; frame[44] = 0;
        CHECK(write(sv[0], frame, sizeof frame) == (ssize_t)sizeof frame, "IPv6 frame write");
        d2k_ev ev;
        char err[256];
        int rc = d2k_link_next(sv[1], &ev, 100, err, sizeof err);
        CHECK(rc == 0 && ev.low_port == 49153 && ev.high_port == 443 && ev.transport == 6,
              "IPv6 control event misdecoded");
        CHECK(ev.family == 6 && memcmp(ev.low_ip, frame + 7, 16) == 0 &&
              memcmp(ev.high_ip, frame + 23, 16) == 0, "IPv6 control address truncated");
        frame[6] = 7;
        CHECK(write(sv[0], frame, sizeof frame) == (ssize_t)sizeof frame, "bad family write");
        CHECK(d2k_link_next(sv[1], &ev, 100, err, sizeof err) == -1,
              "unknown address family accepted");
        frame[6] = 4;
        CHECK(write(sv[0], frame, sizeof frame) == (ssize_t)sizeof frame, "noncanonical IPv4 write");
        CHECK(d2k_link_next(sv[1], &ev, 100, err, sizeof err) == -1,
              "IPv4 address with nonzero tail accepted");
        close(sv[0]); close(sv[1]);
    }
    /* Controller status must turn false when the datapath peer vanishes;
       checking a live PID alone is not enough to prove this link is alive. */
    {
        int sv[2] = {-1, -1};
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair (проверка живости связи) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            CHECK(d2k_link_peer_closed(sv[0]) == 0,
                  "открытый управляющий сокет ошибочно признан закрытым");
            close(sv[1]);
            CHECK(d2k_link_peer_closed(sv[0]) == 1,
                  "закрытый управляющий peer не распознан");
            CHECK(d2k_link_peer_closed(-1) == -1,
                  "ошибочный fd не вернул ошибку живости связи");
            close(sv[0]);
        }
    }
    /* On peer close POLLIN and POLLHUP can coexist. The controller's normal
       256-event fairness cap must not discard a final finite batch. */
    {
        int sv[2] = {-1, -1};
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair (финальная очередь событий) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            const uint8_t hello[] = {0};
            int capacity = 256 * 1024;
            CHECK(setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &capacity, sizeof capacity) == 0,
                  "room for 300 queued IPv6 events");
            for (int i = 0; i < 300; i++) {
                send_synthetic(sv[1], D2K_EV_HELLO, hello, sizeof hello);
            }
            close(sv[1]);
            CHECK(d2k_link_peer_closed(sv[0]) == 1,
                  "закрытие peer не видно при ещё читаемой очереди");
            int received = 0;
            for (;;) {
                int drained = 0;
                for (; drained < 256; drained++) {
                    d2k_ev ev; char err[128];
                    if (d2k_link_next(sv[0], &ev, 0, err, sizeof err) != 0) { break; }
                    received++;
                }
                if (drained < 256 || d2k_link_peer_closed(sv[0]) != 1) { break; }
            }
            CHECK(received == 300, "закрытие потеряло конечную очередь из 300 событий");
            close(sv[0]);
        }
    }
    /* A real closed AF_UNIX peer must return an error even when the
       application has the default SIGPIPE disposition (e.g. d2kask). */
    {
        pid_t pid = fork();
        CHECK(pid >= 0, "fork for closed-peer regression");
        if (pid == 0) {
            signal(SIGPIPE, SIG_DFL);
            int sv[2]; char err[128];
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { _exit(2); }
            close(sv[1]);
            int rc = d2k_link_arm_shape(sv[0], "closed.example", 6, err, sizeof err);
            close(sv[0]); _exit(rc == -1 ? 0 : 3);
        }
        if (pid > 0) {
            int status = 0; waitpid(pid, &status, 0);
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                  "closed peer killed the caller with SIGPIPE");
        }
    }
    /* --- ВНЕШНИЙ тип записи живёт на событии (маска seen_types), а не на
     * голом типе записи. Функция называется outer_appdata, а не has_appdata,
     * потому что видит она ровно внешний тип: в TLS 1.3 типом 23 наружу едет
     * и ВЕСЬ второй полёт рукопожатия (RFC 8446 §5.2), а настоящий тип лежит
     * внутри шифротекста. Значит это НАБЛЮДЕНИЕ (§4.2, уровень 2), а не
     * подтверждение работы приложения — подтверждение даёт собственный зонд
     * (core/verify.c). Каждый бит — свой тип записи (D2K_TLS_* минус 20);
     * проверяем и «только этот бит», и «этот бит среди прочих», и «все
     * прочие биты, кроме него». ---------------------------------------- */
    {
        uint8_t bit_appdata = (uint8_t)(1u << (D2K_TLS_APPLICATION_DATA - 20));      /* 8 */
        uint8_t bit_handshake = (uint8_t)(1u << (D2K_TLS_HANDSHAKE - 20));           /* 4 */
        uint8_t bit_alert = (uint8_t)(1u << (D2K_TLS_ALERT - 20));                   /* 2 */
        uint8_t bit_ccs = (uint8_t)(1u << (D2K_TLS_CHANGE_CIPHER_SPEC - 20));         /* 1 */

        d2k_ev e;
        e = ev_with_seen(bit_appdata);
        CHECK(d2k_ev_outer_appdata(&e) == 1, "внешний тип 23 не распознан");
        e = ev_with_seen(bit_alert);
        CHECK(d2k_ev_outer_appdata(&e) == 0, "предупреждение TLS принято за внешний тип 23 — это ОТКАЗ сервера");
        e = ev_with_seen(bit_handshake);
        CHECK(d2k_ev_outer_appdata(&e) == 0, "рукопожатие принято за внешний тип 23");
        e = ev_with_seen(bit_ccs);
        CHECK(d2k_ev_outer_appdata(&e) == 0, "смена шифра принята за внешний тип 23");
        e = ev_with_seen(0);
        CHECK(d2k_ev_outer_appdata(&e) == 0, "пустая маска принята за внешний тип 23");
        /* Внешний тип 23 СРЕДИ прочих типов — реалистичный многозаписный
           обмен (рукопожатие, потом данные): бит смещения обязан быть ровно
           тем, а не соседним — мутация индекса сдвига здесь и поймается. */
        e = ev_with_seen((uint8_t)(bit_handshake | bit_appdata));
        CHECK(d2k_ev_outer_appdata(&e) == 1, "внешний тип 23 среди прочих типов не распознан");
        /* Все ТРИ прочих типа сразу, но НЕ 23 — граница, отличающая «бит
           appdata» от «маска вообще не нулевая». */
        e = ev_with_seen((uint8_t)(bit_ccs | bit_alert | bit_handshake));
        CHECK(d2k_ev_outer_appdata(&e) == 0, "все типы кроме 23 приняты за внешний тип 23");
        e = ev_with_seen(0xFF);
        CHECK(d2k_ev_outer_appdata(&e) == 1, "полная маска (включая 23) не распознана");
        CHECK(d2k_ev_outer_appdata(NULL) == 0, "у NULL-события нашёлся внешний тип 23");
    }

    /* --- открытие несуществующего сокета отказывает, а не зависает -------- */
    {
        char err[200] = {0};
        int fd = d2k_link_open("/tmp/d2k-core-link-test-nobody-home.sock", err, sizeof err);
        CHECK(fd < 0, "открытие несуществующего сокета должно отказать");
        CHECK(err[0] != '\0', "отказ открытия без причины в err");
    }
    {
        /* NULL и пустая строка — отдельная ветка ДО strlen/connect: без неё
           strlen(NULL) — неопределённое поведение, а не просто "тоже
           откажет" (в отличие от предыдущей проверки, где отказ пришёл бы и
           без явной проверки, через ENOENT от connect() на несуществующем
           пути — здесь такой смежной страховки нет). */
        char err[200] = {0};
        CHECK(d2k_link_open(NULL, err, sizeof err) < 0, "открытие с NULL-путём должно отказать, не падать");
        CHECK(d2k_link_open("", err, sizeof err) < 0, "открытие с пустым путём должно отказать");
    }

    /* --- защита входа d2k_link_next/d2k_link_close ------------------------ */
    {
        char err[200] = {0};
        d2k_ev ev;
        CHECK(d2k_link_next(-1, &ev, 100, err, sizeof err) == -1, "закрытый fd должен отказывать, не тайм-аутить");
        CHECK(d2k_link_next(-1, NULL, 100, err, sizeof err) == -1, "нет места для события должно отказывать");
        d2k_link_close(-1); /* не должно падать */
    }

    /* --- разбор кадра против ПОДДЕЛЬНОГО собеседника: границы длины ------- */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (длина < 2) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            uint8_t bad[6] = { 0, 0, 0, 0, 0, 0 }; /* plen = 0: короче минимума под тип */
            CHECK(write(sv[1], bad, sizeof bad) == (ssize_t)sizeof bad, "тестовый кадр (длина 0) не записался");
            d2k_ev ev;
            char err[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, err, sizeof err) == -1,
                  "кадр с длиной payload < 2 должен быть отказом, а не тихо принят");
            close(sv[0]);
            close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (короче ключа) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            /* plen=2 — только тип, тела вовсе нет: короче D2K_KEY_WIRE_LEN. */
            uint8_t bad[6];
            bad[0] = 0; bad[1] = 0; bad[2] = 0; bad[3] = 2;
            bad[4] = (uint8_t)(D2K_EV_HELLO >> 8);
            bad[5] = (uint8_t)D2K_EV_HELLO;
            CHECK(write(sv[1], bad, sizeof bad) == (ssize_t)sizeof bad, "тестовый кадр (короче ключа) не записался");
            d2k_ev ev;
            char err[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, err, sizeof err) == -1,
                  "кадр короче ключа потока должен быть отказом");
            close(sv[0]);
            close(sv[1]);
        }
    }
    {
        /* Тот же отказ, но РОВНО на 1 байт короче ключа — граница, отличающая
           верную проверку "body_len < D2K_KEY_WIRE_LEN" от однобайтно
           ослабленной "< D2K_KEY_WIRE_LEN - 1"; предыдущая проверка (тело
           нулевой длины) обе версии отклоняют одинаково и мутацию здесь не
           поймала бы (поймано мутацией на первом прогоне). Размер — через
           D2K_KEY_WIRE_LEN, не литералом: это ИМЕННО тот тест, что должен
           защищать от зашитой числом ширины ключа, а не сам её зашивать. */
        enum { SHORT_KEY_LEN = D2K_KEY_WIRE_LEN - 1 };
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (ключ короче на 1 байт) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            uint8_t frame[6 + SHORT_KEY_LEN];
            uint32_t plen = (uint32_t)(2 + SHORT_KEY_LEN);
            frame[0] = (uint8_t)(plen >> 24); frame[1] = (uint8_t)(plen >> 16);
            frame[2] = (uint8_t)(plen >> 8);  frame[3] = (uint8_t)plen;
            frame[4] = (uint8_t)(D2K_EV_APPLIED >> 8); frame[5] = (uint8_t)D2K_EV_APPLIED;
            memset(frame + 6, 0xAB, SHORT_KEY_LEN);
            CHECK(write(sv[1], frame, sizeof frame) == (ssize_t)sizeof frame,
                  "тестовый кадр (ключ короче на 1 байт) не записался");
            d2k_ev ev;
            char err[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, err, sizeof err) == -1,
                  "кадр короче ключа РОВНО на 1 байт (D2K_KEY_WIRE_LEN - 1) должен отклоняться");
            close(sv[0]);
            close(sv[1]);
        }
    }
    {
        /* Кадр за пределом D2K_CTL_FRAME_MAX. Тело — ровно на 1 байт больше
           разрешённого (D2K_CTL_FRAME_MAX - 2 + 1): без верхней границы
           разбор попытался бы дочитать все эти байты в g_scratch (тот на 6
           байт больше предела, так что здесь бы не переполнился, но принял
           бы кадр как валидный — 0 вместо -1). Писать 65535 байт в один
           конец пары синхронно и ПОТОМ читать нельзя — сокет-пара такой
           объём не бufferизует, write() блокируется, а читающего пока нет:
           классический дедлок. Пишущий — отдельный процесс, читает
           родитель, как и с настоящим ctlprobe. */
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (кадр за пределом) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            pid_t wpid = fork();
            CHECK(wpid >= 0, "fork писателя (кадр за пределом) не удался");
            if (wpid == 0) {
                close(sv[0]);
                uint32_t body_len = (uint32_t)D2K_CTL_FRAME_MAX - 1;
                uint32_t plen = body_len + 2;
                uint8_t hdr[6];
                hdr[0] = (uint8_t)(plen >> 24); hdr[1] = (uint8_t)(plen >> 16);
                hdr[2] = (uint8_t)(plen >> 8);  hdr[3] = (uint8_t)plen;
                hdr[4] = (uint8_t)(D2K_EV_STATS >> 8); hdr[5] = (uint8_t)D2K_EV_STATS;
                (void)!write(sv[1], hdr, sizeof hdr);
                static uint8_t filler[D2K_CTL_FRAME_MAX];
                memset(filler, 0x22, body_len);
                size_t sent = 0;
                while (sent < body_len) {
                    ssize_t n = write(sv[1], filler + sent, body_len - sent);
                    if (n <= 0) { break; }
                    sent += (size_t)n;
                }
                close(sv[1]);
                _exit(0);
            }
            close(sv[1]);
            d2k_ev ev;
            char err[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 2000, err, sizeof err) == -1,
                  "кадр длиннее D2K_CTL_FRAME_MAX должен отклоняться");
            close(sv[0]);
            if (wpid > 0) { (void)waitpid(wpid, NULL, 0); }
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (уход без байта) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            close(sv[1]); /* собеседник ушёл, не написав ни байта заголовка */
            d2k_ev ev;
            char err[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, err, sizeof err) == -1,
                  "уход без единого байта — это отказ, а не тайм-аут (1)");
            close(sv[0]);
        }
    }

    /* --- границы разбора по каждому виду события — настоящий ctlprobe их
     * никогда не пришлёт (он воспитанный сервер), значит без синтетического
     * собеседника эти ветки НИКОГДА не исполнятся ни одним другим тестом
     * этого файла. -------------------------------------------------------- */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (HELLO без длины имени) не создался");
        if (sv[0] >= 0) {
            send_synthetic(sv[1], D2K_EV_HELLO, NULL, 0);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "HELLO без байта длины имени должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (HELLO обрезанное имя) не создался");
        if (sv[0] >= 0) {
            /* Ровно на 1 байт короче нужного (rlen == nl, а нужно nl+1: сам
               байт длины плюс nl байт имени) — граница, отличающая верную
               проверку "rlen < 1+nl" от однобайтно ослабленной "rlen < nl";
               с запасом в несколько байт (как было раньше) обе проверки
               совпадали, и мутация в этом самом месте прошла бы незамеченной
               (поймано мутацией на первом прогоне этого файла). */
            uint8_t rest[5] = { 5, 'a', 'b', 'c', 'd' }; /* заявлено 5, дано 4 */
            send_synthetic(sv[1], D2K_EV_HELLO, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "HELLO короче объявленной длины имени РОВНО на 1 байт должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (HELLO 255 байт) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[256];
            rest[0] = 255;
            for (int i = 0; i < 255; i++) { rest[1 + i] = (uint8_t)('a' + (i % 26)); }
            send_synthetic(sv[1], D2K_EV_HELLO, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0,
                  "HELLO с именем ровно 255 байт (граница буфера name[256]) должен приниматься");
            CHECK(strlen(ev.name) == 255, "имя длиной 255 байт не поместилось целиком в out->name");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (SUSPECT без кода) не создался");
        if (sv[0] >= 0) {
            send_synthetic(sv[1], D2K_EV_SUSPECT, NULL, 0);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "SUSPECT без кода причины должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        /* Подробности подозрения — те самые пять байт, из которых складывается
           отпечаток коробки (datapath/ctlsrv.c, D2K_JRN_SUSPECT). До 11.09
           разбор читал только код и молча терял их: каталог хранил бы факт
           «был сброс», по которому одну коробку от другой не отличить. */
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (подробности SUSPECT) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[8] = { 1, 127, 53, 0x20, 0x12, 0x34, D2K_LINK_PLANNED_NO, 1 };
            send_synthetic(sv[1], D2K_EV_SUSPECT, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0,
                  "SUSPECT с подробностями должен приниматься");
            CHECK(ev.code == 1, "код причины подозрения потерян");
            CHECK(ev.ttl == 127, "TTL подделки потерян — по нему узнаётся коробка");
            CHECK(ev.ref_ttl == 53, "TTL сервера потерян — без него разность не посчитать");
            CHECK(ev.tos == 0x20, "ToS подозрения потерян");
            CHECK(ev.ipid == 0x1234, "идентификатор пакета потерян");
            CHECK(ev.client_shape == 1, "SUSPECT retains flow TLS shape for family admission");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        /* v12 (задача 56): хвостом SUSPECT — число при записи, u16 BE; у «TCP
           встал на бюджете» это оценка пакетов с данными. Без хвоста — ноль. */
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (SUSPECT v12) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[11] = { D2K_SUSPECT_TCP_STALL, 0, 0, 0, 0, 0, D2K_LINK_PLANNED_NO, 1, 0, 25, D2K_CLIENT_SIDE_HIGH };
            send_synthetic(sv[1], D2K_EV_SUSPECT, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0 &&
                  ev.code == D2K_SUSPECT_TCP_STALL && ev.num == 25,
                  "оценка пакетов в подозрении «TCP встал на бюджете» потеряна");
            CHECK(ev.client_side == D2K_CLIENT_SIDE_HIGH,
                  "observed client endpoint lost on control wire");
            send_synthetic(sv[1], D2K_EV_SUSPECT, rest, 10);
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0 &&
                  ev.num == 25 && ev.client_side == D2K_CLIENT_SIDE_UNKNOWN,
                  "old suspicion fabricated an observed endpoint");
            rest[10] = 3;
            send_synthetic(sv[1], D2K_EV_SUSPECT, rest, sizeof rest);
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "invalid observed endpoint accepted");
            send_synthetic(sv[1], D2K_EV_SUSPECT, rest, 8);
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0 && ev.num == 0 && ev.client_side == 0,
                  "подозрение без хвоста v12 получило выдуманное число");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        /* Короткое подозрение (только код) — законный вход, а не отказ:
           старый датапат подробностей не слал. Поля обязаны остаться нулями,
           а не мусором. */
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (короткий SUSPECT) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[1] = { 3 };
            send_synthetic(sv[1], D2K_EV_SUSPECT, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0,
                  "SUSPECT без подробностей должен приниматься");
            CHECK(ev.code == 3, "код причины короткого подозрения потерян");
            CHECK(ev.ttl == 0 && ev.ref_ttl == 0 && ev.tos == 0 && ev.ipid == 0,
                  "подробности, которых не было, пришли не нулями");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        /* Событие применения обязано нести идентификатор плана: без него
           «план применился» неотличимо от «применился какой-то план», и при
           смене кандидата событие предыдущего засчиталось бы новому.
           Байты нарочно НЕпечатные (0xA0..0xAF): идентификатор двоичный, и
           путь до провода не имеет права его чистить под печать — именно так
           его испортила бы дорога через поле имени в журнале датапата
           (datapath/journal.c заменяет всё вне 0x20..0x7e точкой). */
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (APPLIED с id) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN];
            for (int i = 0; i < D2K_PLAN_ID_LEN; i++) { rest[i] = (uint8_t)(0xA0 + i); }
            for (int i = 0; i < D2K_TRIAL_ID_LEN; i++) { rest[D2K_PLAN_ID_LEN + i] = (uint8_t)(0xD0 + i); }
            send_synthetic(sv[1], D2K_EV_APPLIED, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0,
                  "APPLIED с идентификатором плана должен приниматься");
            int same = 1;
            for (int i = 0; i < 16; i++) { if (ev.plan_id[i] != (uint8_t)(0xA0 + i)) { same = 0; } }
            CHECK(same, "идентификатор плана потерян при разборе события");
            CHECK(memcmp(ev.trial_id, rest + D2K_PLAN_ID_LEN, D2K_TRIAL_ID_LEN) == 0,
                  "trial ID потерян при разборе события");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        /* Новый wire-код исполнения не имеет старого формата без ID. */
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (APPLIED без id) не создался");
        if (sv[0] >= 0) {
            send_synthetic(sv[1], D2K_EV_APPLIED, NULL, 0);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "APPLIED без идентификатора должен отвергаться");
            int zero = 1;
            for (int i = 0; i < 16; i++) { if (ev.plan_id[i] != 0) { zero = 0; } }
            CHECK(zero, "идентификатора не было, а поле пришло не нулевым");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        /* Обрезанный идентификатор — ошибочный кадр подтверждения. */
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (APPLIED с обрезанным id) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN - 1];
            memset(rest, 0xC7, sizeof rest);
            send_synthetic(sv[1], D2K_EV_APPLIED, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "APPLIED с обрезанным идентификатором должен отвергаться");
            int zero = 1;
            for (int i = 0; i < 16; i++) { if (ev.plan_id[i] != 0) { zero = 0; } }
            CHECK(zero, "обрезанный идентификатор принят за настоящий");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (старое исполнение) не создался");
        if (sv[0] >= 0) {
            uint8_t id[16]; memset(id, 0xC7, sizeof id);
            send_synthetic(sv[1], D2K_EV_PREPARED, id, sizeof id);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0,
                  "старое событие не должно ломать канал");
            CHECK(ev.kind == D2K_EV_PREPARED && ev.kind != D2K_EV_APPLIED,
                  "старая подготовка выдана за подтверждение исполнения");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (отказ с ID) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[1 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN];
            memset(rest, 0xC7, sizeof rest); rest[0] = 3;
            send_synthetic(sv[1], D2K_EV_REFUSED, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0,
                  "отказ с ID не разобран");
            CHECK(ev.code == 3 && memcmp(ev.plan_id, rest + 1, 16) == 0,
                  "отказ потерял код или ID кандидата");
            CHECK(memcmp(ev.trial_id, rest + 1 + D2K_PLAN_ID_LEN, D2K_TRIAL_ID_LEN) == 0,
                  "отказ потерял trial ID");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (EXCHANGE короче 6) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[5] = { 22, 0, 0, 0, 0 }; /* на 1 короче минимума в 6 байт */
            send_synthetic(sv[1], D2K_EV_EXCHANGE, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "EXCHANGE короче 6 байт (тип записи + маска + длина) должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        /* Порядок байт num — четырьмя РАЗЛИЧИМЫМИ значениями, не настоящим
           обменом с ctlprobe: там реальные величины (64, 128) занимают
           только младший байт, старшие три — нули, и перестановка ЛЮБЫХ
           ДВУХ из них осталась бы невидимой (ревью прогнало ровно такую
           мутацию — обмен rest[2]<<24 и rest[3]<<16 — и живой прогон не
           заметил её). {1,2,3,4} различает перестановку каждой пары. */
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (EXCHANGE num порядок байт) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[6] = { 23, 0, 0x01, 0x02, 0x03, 0x04 };
            send_synthetic(sv[1], D2K_EV_EXCHANGE, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0, "EXCHANGE с различимым num не разобрался");
            CHECK(ev.num == 0x01020304u,
                  "EXCHANGE.num собран не в том порядке байт (ожидали 0x01020304)");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (ACK короче 4) не создался");
        if (sv[0] >= 0) {
            uint8_t rest[3] = { 0, 0x81, 1 }; /* на 1 короче минимума в 4 байта */
            send_synthetic(sv[1], D2K_EV_ACK, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "ACK короче 4 байт (тип команды + признак + причина) должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    /* Successful v23 removal ACK cannot release an unidentified owner. */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,sv)==0,"delete ACK decoder pair");
        uint8_t rest[4+D2K_TRIAL_ID_LEN]={0,D2K_CMD_DEL_ADDR_PROBE,1,0};
        d2k_ev ev;char why[160];
        send_synthetic(sv[1],D2K_EV_ACK,rest,4);
        CHECK(d2k_link_next(sv[0],&ev,1000,why,sizeof why)==-1,"successful delete ACK without identity rejected");
        send_synthetic(sv[1],D2K_EV_ACK,rest,sizeof rest);
        CHECK(d2k_link_next(sv[0],&ev,1000,why,sizeof why)==-1,"successful delete ACK with zero identity rejected");
        rest[2]=0;rest[3]=D2K_ACK_BAD_ARGS;
        send_synthetic(sv[1],D2K_EV_ACK,rest,4);
        CHECK(d2k_link_next(sv[0],&ev,1000,why,sizeof why)==0 && ev.num==D2K_ACK_BAD_ARGS,
              "unidentified malformed-command rejection remains diagnostic only");
        close(sv[0]);close(sv[1]);
    }
    /* ЗАМЫСЕЛ 2026-10-23, п. 5.1: CLIENT_TCP — набор опций TCP клиента перед
       его SHAPE. Пустое тело — известный пустой набор; длиннее 40 — отказ. */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (CLIENT_TCP) не создался");
        if (sv[0] >= 0) {
            static const uint8_t ts[12] = {1, 1, 8, 10, 0, 0, 0x23, 0x28, 0, 0, 0, 0};
            send_synthetic(sv[1], D2K_EV_CLIENT_TCP, ts, sizeof ts);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0 &&
                  ev.kind == D2K_EV_CLIENT_TCP &&
                  ev.tcp_options_len == 12 && memcmp(ev.tcp_options, ts, 12) == 0,
                  "CLIENT_TCP: набор опций клиента не разобран");
            send_synthetic(sv[1], D2K_EV_CLIENT_TCP, NULL, 0);
            memset(&ev, 0xff, sizeof ev);
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0 &&
                  ev.kind == D2K_EV_CLIENT_TCP && ev.tcp_options_len == 0,
                  "CLIENT_TCP: пустой набор не принят как известный");
            static const uint8_t over[41] = {0};
            send_synthetic(sv[1], D2K_EV_CLIENT_TCP, over, sizeof over);
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "CLIENT_TCP длиннее 40 байт должен отклоняться");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (SHAPE переполнение) не создался");
        if (sv[0] >= 0) {
            static uint8_t rest[D2K_SHAPE_MAX + 1]; /* на 1 больше буфера out->shape */
            memset(rest, 0x16, sizeof rest);
            send_synthetic(sv[1], D2K_EV_SHAPE, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == -1,
                  "форма приветствия длиннее буфера должна отклоняться, а не переполнять его");
            close(sv[0]); close(sv[1]);
        }
    }
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (SHAPE во весь буфер) не создался");
        if (sv[0] >= 0) {
            static uint8_t rest[D2K_SHAPE_MAX]; /* ровно во весь буфер out->shape */
            memset(rest, 0x16, sizeof rest);
            send_synthetic(sv[1], D2K_EV_SHAPE, rest, sizeof rest);
            d2k_ev ev; char e[200] = {0};
            CHECK(d2k_link_next(sv[0], &ev, 1000, e, sizeof e) == 0,
                  "форма приветствия во весь буфер (граница) должна приниматься");
            CHECK(ev.shape_len == D2K_SHAPE_MAX, "shape_len не во весь буфер на границе");
            close(sv[0]); close(sv[1]);
        }
    }

    /* --- проверка hex/имени у d2k_link_set_name — без сети целиком --------
     * Один заведомо валидный fd (сокет-пара, второй конец никто не читает)
     * достаточен: все эти отказы случаются ДО первой попытки записи. */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair (валидация set_name) не создался");
        if (sv[0] >= 0) {
            char err[200] = {0};
            CHECK(d2k_link_set_name(sv[0], "x.example", 6, "abc", D2K_LINK_SHAPE_GRANDFATHER, err, sizeof err) == -1,
                  "нечётная длина hex должна отклоняться");
            CHECK(d2k_link_set_name(sv[0], "x.example", 6, "zz", D2K_LINK_SHAPE_GRANDFATHER, err, sizeof err) == -1,
                  "недопустимый hex-символ должен отклоняться");
            CHECK(d2k_link_set_name(sv[0], "", 6, "", D2K_LINK_SHAPE_GRANDFATHER, err, sizeof err) == -1,
                  "пустое имя должно отклоняться");
            CHECK(d2k_link_set_name(sv[0], "x.example", 99, "", D2K_LINK_SHAPE_GRANDFATHER, err, sizeof err) == -1,
                  "транспорт вне {6,17} должен отклоняться до похода к серверу");
            char longname[300];
            memset(longname, 'a', sizeof longname - 1);
            longname[sizeof longname - 1] = '\0';
            CHECK(d2k_link_set_name(sv[0], longname, 6, "", D2K_LINK_SHAPE_GRANDFATHER, err, sizeof err) == -1,
                  "имя длиннее 255 байт должно отклоняться");
            close(sv[0]);
            close(sv[1]);
        }
    }
    /* Name plans carry an explicit family, including IPv4 compatibility calls. */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "name family socketpair");
        char err[200]; uint8_t wire[64];
        CHECK(d2k_link_set_name_family(sv[0], "x", 6, "aabb", 1, 0, 6,
                                      err, sizeof err) == 0, "IPv6 name command");
        CHECK(read(sv[1], wire, sizeof wire) == 12, "IPv6 name command length");
        CHECK(wire[6] == 1 && wire[7] == 'x' && wire[8] == 1 &&
              wire[9] == 6 && wire[10] == 0xaa && wire[11] == 0xbb,
              "IPv6 name command exact bytes");
        CHECK(d2k_link_set_name_family(sv[0], "x", 6, "", 1, 0, 0,
                                      err, sizeof err) == -1, "ambiguous family rejected");
        CHECK(d2k_link_set_name(sv[0], "x", 6, "", 1, err, sizeof err) == 0,
              "IPv4 compatibility command");
        CHECK(read(sv[1], wire, sizeof wire) == 10 && wire[9] == 4,
              "legacy API explicitly encodes IPv4");
        CHECK(d2k_link_del_name_family(sv[0], "x", 17, D2K_LINK_SHAPE_QUIC, 6,
                                       err, sizeof err) == 0,
              "IPv6 delete name");
        CHECK(read(sv[1], wire, sizeof wire) == 11 && wire[5] == D2K_CMD_DEL_NAME &&
              wire[8] == 17 && wire[9] == D2K_LINK_SHAPE_QUIC && wire[10] == 6,
              "DEL_NAME v9 carries transport, shape and family");
        CHECK(d2k_link_del_name_family(sv[0], "x", 6, 0, 4, err, sizeof err) == -1,
              "DEL_NAME without shape (name-wide delete) rejected");
        CHECK(d2k_link_del_name_family(sv[0], "x", 0, 1, 4, err, sizeof err) == -1,
              "DEL_NAME without transport rejected");
        CHECK(d2k_link_set_suffix_family(sv[0], "x.com", 6, "aabb", 1, 6, err, sizeof err) == 0,
              "IPv6 suffix send");
        CHECK(read(sv[1], wire, sizeof wire) == 32 && wire[5] == D2K_CMD_SET_SUFFIX &&
              wire[12] == 1 && wire[13] == 6 && wire[14] == 0xaa, "suffix wire layout");
        CHECK(d2k_link_set_bypass_family(sv[0], "x.com", 6, 1, 6, err, sizeof err) == 0,
              "IPv6 exact bypass send");
        CHECK(read(sv[1], wire, sizeof wire) == 31 && wire[5] == D2K_CMD_SET_BYPASS &&
              wire[12] == 6 && wire[13] == 1 && wire[14] == 6, "bypass context wire layout");
        CHECK(d2k_link_del_name_probe_family(sv[0], "x", 17, 3, htons(40000), 6,
                                             err, sizeof err) == 0, "IPv6 probe delete");
        CHECK(read(sv[1], wire, sizeof wire) == 12 && wire[8] == 3 &&
              wire[9] == 6 && wire[10] == 0x9c && wire[11] == 0x40,
              "IPv6 probe delete wire");
        CHECK(d2k_link_arm_shape_family(sv[0], "x", 17, 6, err, sizeof err) == 0,
              "IPv6 snapshot request");
        CHECK(read(sv[1], wire, sizeof wire) == 10 && wire[8] == 17 && wire[9] == 6,
              "snapshot wire carries transport and family");
        const uint8_t ip6[16] = {0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,1};
        CHECK(d2k_link_set_addr_family(sv[0], ip6, 6, D2K_LINK_SHAPE_QUIC, "aabb",
                                       err, sizeof err) == 0,
              "IPv6 address binding command");
        CHECK(read(sv[1], wire, sizeof wire) == 26 && wire[6] == 6 &&
              !memcmp(wire + 7, ip6, 16) && wire[23] == D2K_LINK_SHAPE_QUIC &&
              wire[24] == 0xaa && wire[25] == 0xbb,
              "IPv6 address binding wire carries protocol shape before the plan");
        CHECK(d2k_link_del_addr_family(sv[0], ip6, 6, D2K_LINK_SHAPE_VOICE,
                                       err, sizeof err) == 0,
              "IPv6 address unbind command");
        CHECK(read(sv[1], wire, sizeof wire) == 24 && wire[6] == 6 &&
              !memcmp(wire + 7, ip6, 16) && wire[23] == D2K_LINK_SHAPE_VOICE,
              "IPv6 address unbind wire carries protocol shape");
        for (unsigned family=4;family<=6;family+=2) {
            CHECK(d2k_link_set_endpoint(sv[0],ip6,family,htons(3478),D2K_LINK_SHAPE_VOICE,
                  "aabb",err,sizeof err)==0,"service endpoint command encodes");
            CHECK(read(sv[1],wire,sizeof wire)==28 && wire[3]==24 &&
                  wire[4]==0 && wire[5]==D2K_CMD_SET_ENDPOINT && wire[6]==family &&
                  !memcmp(wire+7,ip6,family==6?16:4) && wire[23]==D2K_LINK_SHAPE_VOICE &&
                  wire[24]==0x0d && wire[25]==0x96 && wire[26]==0xaa && wire[27]==0xbb,
                  "service endpoint wire preserves port and plan boundary");
            if (family==4) {
                const uint8_t zero[12]={0};
                CHECK(!memcmp(wire+11,zero,12),"IPv4 service address padding canonical");
            }
            const uint8_t token[D2K_TRIAL_ID_LEN]={0x55,0x33};
            CHECK(d2k_link_set_endpoint_bound(sv[0],ip6,family,htons(3478),
                  D2K_LINK_SHAPE_VOICE,"aabb",token,err,sizeof err)==0,
                  "bound service command encodes");
            CHECK(read(sv[1],wire,sizeof wire)==44 && wire[3]==40 &&
                  wire[5]==D2K_CMD_SET_ENDPOINT_BOUND && wire[6]==family &&
                  wire[24]==0x0d && wire[25]==0x96 && wire[26]==0xaa && wire[27]==0xbb &&
                  !memcmp(wire+28,token,sizeof token),
                  "bound service retains plan boundary and appends exact request token");
            CHECK(d2k_link_del_endpoint(sv[0],ip6,family,htons(3478),D2K_LINK_SHAPE_VOICE,
                  err,sizeof err)==0,"service endpoint delete encodes");
            CHECK(read(sv[1],wire,sizeof wire)==26 && wire[3]==22 &&
                  wire[4]==0 && wire[5]==D2K_CMD_DEL_ENDPOINT && wire[6]==family &&
                  !memcmp(wire+7,ip6,family==6?16:4) && wire[23]==D2K_LINK_SHAPE_VOICE &&
                  wire[24]==0x0d && wire[25]==0x96,"service deletion retains exact port");
        }
        CHECK(d2k_link_set_endpoint(sv[0],ip6,6,0,D2K_LINK_SHAPE_VOICE,"aabb",err,sizeof err)!=0 &&
              d2k_link_del_endpoint(sv[0],ip6,6,0,D2K_LINK_SHAPE_VOICE,err,sizeof err)!=0,
              "zero service port never sent");
        for (unsigned family=4;family<=6;family+=2) {
            CHECK(d2k_link_del_endpoint(sv[0],ip6,family,htons(443),D2K_LINK_SHAPE_RAW,
                  err,sizeof err)!=0,"RAW deletion without transport rejected locally");
            for (unsigned tr=6;tr<=17;tr+=11) {
                CHECK(d2k_link_del_raw_endpoint(sv[0],ip6,family,htons(443),tr,err,sizeof err)==0,
                      "RAW endpoint deletion encodes transport");
                CHECK(read(sv[1],wire,sizeof wire)==27 && wire[3]==23 && wire[5]==D2K_CMD_DEL_ENDPOINT &&
                      wire[6]==family && wire[23]==D2K_LINK_SHAPE_RAW && wire[24]==1 && wire[25]==187 &&
                      wire[26]==tr,"RAW endpoint deletion wire exact");
            }
        }
        /* Форма RAW (этапы 12/16: доказанный путь без протокола) — законная
           адресная форма: подтверждённая RAW-привязка обязана доехать до
           датапата как SET_ADDR с формой 8, иначе каталог знает решение,
           а провод — нет. */
        {
            int rc = d2k_link_set_addr_family(sv[0], ip6, 6, D2K_LINK_SHAPE_RAW, "aabb",
                                              err, sizeof err);
            CHECK(rc == 0, "RAW address binding command refused");
            if (rc == 0) {
                CHECK(read(sv[1], wire, sizeof wire) == 26 && wire[23] == D2K_LINK_SHAPE_RAW &&
                      wire[24] == 0xaa && wire[25] == 0xbb,
                      "RAW address binding wire carries shape 8 before the plan");
            }
            rc = d2k_link_del_addr_family(sv[0], ip6, 6, D2K_LINK_SHAPE_RAW, err, sizeof err);
            CHECK(rc == 0, "RAW address unbind refused");
            if (rc == 0) {
                CHECK(read(sv[1], wire, sizeof wire) == 24 && wire[23] == D2K_LINK_SHAPE_RAW,
                      "RAW address unbind wire carries shape 8");
            }
        }
        /* Адресная привязка без формы или с дедушкиным правом «подходила бы
           всем протоколам IP» (задача 16) — на провод не уходит. */
        CHECK(d2k_link_set_addr_family(sv[0], ip6, 6, 0, "aabb", err, sizeof err) != 0 &&
              d2k_link_set_addr_family(sv[0], ip6, 6, D2K_LINK_SHAPE_GRANDFATHER, "aabb",
                                       err, sizeof err) != 0 &&
              d2k_link_del_addr_family(sv[0], ip6, 6, 0, err, sizeof err) != 0,
              "address command without protocol shape accepted");
        /* Этап 21: неизвестная форма (9) на провод не уходит — старый датапат
           ответил бы отказом, а здесь не должно быть даже попытки. */
        CHECK(d2k_link_set_addr_family(sv[0], ip6, 6, D2K_LINK_SHAPE_RAW + 1, "aabb", err, sizeof err) != 0 &&
              d2k_link_del_addr_family(sv[0], ip6, 6, D2K_LINK_SHAPE_RAW + 1, err, sizeof err) != 0,
              "address command with unknown shape 9 sent");
        close(sv[0]); close(sv[1]);
    }
    /* Address-trial command encoding is byte-level protocol, not a struct ABI. */
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair (SET_ADDR_PROBE wire) не создался");
        if (sv[0] >= 0 && sv[1] >= 0) {
            const uint8_t src[4] = {192, 0, 2, 10}, dst[4] = {203, 0, 113, 7};
            const uint8_t trial[D2K_TRIAL_ID_LEN] = {1, 2, 3, 4, 5, 6, 7, 8,
                9, 10, 11, 12, 13, 14, 15, 16};
            char err[160] = {0};
            CHECK(d2k_link_set_addr_probe(sv[0], src, htons(40000), dst,
                  htons(443), 17, trial, 120000, "00", err, sizeof err) == 0,
                  "SET_ADDR_PROBE wire-команда не собралась");
            uint8_t frame[128];
            ssize_t n = read(sv[1], frame, sizeof frame);
            CHECK(n == 6 + 38 + D2K_TRIAL_ID_LEN + 4 + 1,
                  "SET_ADDR_PROBE имеет неверную длину кадра");
            if (n >= 6 + 38 + D2K_TRIAL_ID_LEN + 4 + 1) {
                CHECK(frame[4] == 0 && frame[5] == D2K_CMD_SET_ADDR_PROBE,
                      "SET_ADDR_PROBE имеет неверный command type");
                CHECK(frame[6] == 4 && memcmp(frame + 7, src, 4) == 0 &&
                      memcmp(frame + 39, (uint8_t[]){0x9c, 0x40}, 2) == 0 &&
                      memcmp(frame + 23, dst, 4) == 0 &&
                      memcmp(frame + 41, (uint8_t[]){0x01, 0xbb, 17}, 3) == 0,
                      "SET_ADDR_PROBE потерял exact flow tuple");
                CHECK(memcmp(frame + 44, trial, sizeof trial) == 0 &&
                      memcmp(frame + 60, (uint8_t[]){0, 1, 0xd4, 0xc0}, 4) == 0 &&
                      frame[64] == 0,
                      "SET_ADDR_PROBE потерял generation, lease или TLV");
            }
            const uint8_t src6[16] = {0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,1};
            const uint8_t dst6[16] = {0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,2};
            CHECK(d2k_link_set_addr_probe_family(sv[0], src6, htons(40000), dst6,
                  htons(443), 17, 6, trial, 120000, "00", err, sizeof err) == 0,
                  "IPv6 exact tuple command");
            n = read(sv[1], frame, sizeof frame);
            CHECK(n == 65 && frame[6] == 6 && memcmp(frame + 7, src6, 16) == 0 &&
                  memcmp(frame + 23, dst6, 16) == 0, "IPv6 tuple full addresses");
            const uint8_t digest[32] = {0x38, 0xb1};
            CHECK(d2k_link_set_dns_probe(sv[0], src6, htons(40000), dst6,
                  htons(53), 6, 6, trial, 1000, "00", 19, digest, err, sizeof err) == 0,
                  "DNS exact tuple command");
            n = read(sv[1], frame, sizeof frame);
            CHECK(n == 99 && frame[5] == 0x9c && frame[43] == 6 &&
                  memcmp(frame + 44, trial, sizeof trial) == 0 &&
                  memcmp(frame + 60, (uint8_t[]){0, 0, 3, 0xe8, 0, 19}, 6) == 0 &&
                  memcmp(frame + 66, digest, sizeof digest) == 0 && frame[98] == 0,
                  "DNS command wire fields");
            CHECK(d2k_link_set_dns_endpoint(sv[0],dst6,6,htons(53),37,"00",trial,err,sizeof err)==0,
                  "DNS endpoint install command");
            n=read(sv[1],frame,sizeof frame);
            CHECK(n==45 && frame[5]==0x9d && frame[6]==6 && !memcmp(frame+7,dst6,16) &&
                  !memcmp(frame+23,(uint8_t[]){9,0,53,0,37,0},6) &&
                  !memcmp(frame+29,trial,16),"DNS endpoint wire fields");
            CHECK(d2k_link_del_dns_endpoint(sv[0],dst6,6,htons(53),17,err,sizeof err)==0,
                  "DNS endpoint retirement command");
            n=read(sv[1],frame,sizeof frame);
            CHECK(n==27 && frame[5]==0x95 && !memcmp(frame+23,(uint8_t[]){9,0,53,17},4),
                  "DNS endpoint retirement includes transport");
            close(sv[0]); close(sv[1]);
        }
    }

    /* --- дальше всё против НАСТОЯЩЕГО ctlprobe ----------------------------- */
    char sock_path[64];
    snprintf(sock_path, sizeof sock_path, "/tmp/d2k-core-link-%d.sock", (int)getpid());
    probe p;
    memset(&p, 0, sizeof p);
    p.in_fd = -1;
    if (probe_start(&p, sock_path) != 0) {
        printf("ПРОВАЛ: стенд ctlprobe не поднялся — далее проверки против настоящего сервера пропущены\n");
        fails++;
        if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
        return 0;
    }

    char err[200] = {0};
    int fd = dial_retry(sock_path, err, sizeof err);
    CHECK(fd >= 0, "клиент не подключился к настоящему ctlprobe");
    if (fd < 0) {
        probe_stop(&p, sock_path);
        printf("ПРОВАЛ: без подключения к ctlprobe остальные проверки не имеют смысла\n");
        fails++;
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }

    /* Full controller -> socket -> command handler -> decoder roundtrip.
       Idempotent deletion still identifies exactly which trial is gone. */
    for (unsigned family=4;family<=6;family+=2) {
        uint8_t src[16]={0},dst[16]={0},trial[D2K_TRIAL_ID_LEN]={0};
        inet_pton(family==4?AF_INET:AF_INET6,family==4?"192.0.2.1":"2001:db8::1",src);
        inet_pton(family==4?AF_INET:AF_INET6,family==4?"192.0.2.2":"2001:db8::2",dst);
        trial[0]=(uint8_t)family;trial[15]=0x71;
        CHECK(d2k_link_del_addr_probe_family(fd,src,htons(40000),dst,htons(3478),17,family,
              trial,err,sizeof err)==0,"send exact trial deletion");
        d2k_ev ack;
        CHECK(next_of_kind(fd,D2K_EV_ACK,5,&ack,err,sizeof err)==0 &&
              ack.code==D2K_CMD_DEL_ADDR_PROBE && ack.num==0x100 &&
              !memcmp(ack.trial_id,trial,sizeof trial),"decoded deletion ACK carries exact trial identity");
    }

    /* --- транспорт доезжает и различает TCP- и QUIC-поток к ОДНОМУ и тому
     * же адресу и порту (зеркало TestTCPИQUICСОдинаковымАдресомИПортомДают
     * РазныеКлючи из internal/control/bridge_test.go). "quic" в ctlprobe
     * нарочно переиспользует порт последнего "hello". ------------------- */
    {
        (void)probe_say(&p, "hello example.com");
        d2k_ev a;
        char e1[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_HELLO, 5, &a, e1, sizeof e1) == 0, "первое (TCP) приветствие не пришло");

        (void)probe_say(&p, "quic");
        d2k_ev b;
        char e2[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_HELLO, 5, &b, e2, sizeof e2) == 0, "второе (QUIC) приветствие не пришло");

        CHECK(strcmp(a.name, "example.com") == 0, "имя TCP-приветствия не example.com");
        CHECK(strcmp(b.name, "example.com") == 0, "имя QUIC-приветствия не example.com");
        CHECK(memcmp(a.low_ip, b.low_ip, 4) == 0 && memcmp(a.high_ip, b.high_ip, 4) == 0 &&
              a.low_port == b.low_port && a.high_port == b.high_port,
              "адрес+порт TCP и QUIC разошлись — проверка не про то, что должна быть про то же");
        CHECK(a.transport == 6, "транспорт TCP-ключа не 6");
        CHECK(b.transport == 17, "транспорт QUIC-ключа не 17");
        CHECK(a.transport != b.transport,
              "TCP и QUIC к одному адресу и порту неразличимы — планы двух транспортов перетрут друг друга");

        /* Абсолютные значения, не только взаимное совпадение a и b: сверка
           "a==b" одна не поймает побайтную перестановку внутри разбора
           ключа (например, перепутанные low_port/high_port) — она даёт ОДНУ
           и ТУ ЖЕ неверную пару на обеих сторонах и остаётся незамеченной.
           Ключ канонизирован по шести байтам "адрес+порт": WAN 93.184.216.34
           численно меньше LAN 192.168.1.67 уже по первому байту адреса,
           независимо от порта, поэтому WAN — низкий конец ВСЕГДА (см. тот
           же вывод в bridge_test.go). Порт клиента — детерминированное
           40001: ctlprobe стартует со 40000 и делает port++ ОДИН раз перед
           первым же "hello" в процессе (см. ctlprobe.c) — а это первый
           hello/raw/quic во всём прогоне этого файла. */
        CHECK(memcmp(a.low_ip, (uint8_t[4]){93, 184, 216, 34}, 4) == 0,
              "низкий конец ключа не 93.184.216.34 — порядок байт адреса разобрался неверно");
        CHECK(a.low_port == 443, "порт низкого конца не 443 — порядок байт порта разобрался неверно");
        CHECK(memcmp(a.high_ip, (uint8_t[4]){192, 168, 1, 67}, 4) == 0,
              "высокий конец ключа не 192.168.1.67");
        CHECK(a.high_port == 40001, "порт высокого конца не 40001 (первый hello в процессе)");

        /* Дренируем то, что осталось (REFUSED от "quic": плана для имени
           нет), прежде чем проверять тайм-аут ниже — иначе d2k_link_next
           честно вернёт 0 на уже лежащем в очереди событии, а не тайм-аут. */
        d2k_ev tmp;
        char e3[200] = {0};
        while (d2k_link_next(fd, &tmp, 200, e3, sizeof e3) == 0) { }
    }

    /* --- тайм-аут без события — это 1, а не 0 и не -1 ---------------------- */
    {
        d2k_ev ev;
        char e[200] = {0};
        int rc = d2k_link_next(fd, &ev, 50, e, sizeof e);
        CHECK(rc == 1, "тайм-аут без события должен возвращать 1");
    }

    /* --- SET_NAME долетает, ack различим по причине (годный план) --------- */
    {
        /* "tiny" — тот же минимальный годный план (только порядок), что и в
           datapath/test_ctl.c: 'D''2''K''P' схема=1 минисполн=1 флаги=0
           записей=1, запись ORDER (тип 0x0103, длина 1, значение 0). */
        static const uint8_t tiny[] = {
            'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 1,
            0x01, 0x03, 0x00, 0x01, 0x00
        };
        char tiny_hex[2 * sizeof tiny + 1];
        to_hex(tiny, sizeof tiny, tiny_hex);

        char e1[200] = {0};
        CHECK(d2k_link_set_name(fd, "ok.example", 6, tiny_hex, D2K_LINK_SHAPE_GRANDFATHER, e1, sizeof e1) == 0,
              "SET_NAME с годным планом не отправилась");

        d2k_ev ack;
        char e2[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_ACK, 5, &ack, e2, sizeof e2) == 0, "ack на годную команду не пришёл");
        CHECK(ack.code == D2K_CMD_SET_NAME, "ack не на команду SET_NAME");
        CHECK(((ack.num >> 8) & 0xFFu) == 1, "годная команда подтверждена как отвергнутая");
        CHECK((ack.num & 0xFFu) == D2K_ACK_OK, "у успеха причина не D2K_ACK_OK");

        d2k_ev first = {0}, second = {0};
        (void)probe_say(&p, "hello ok.example");
        CHECK(!next_of_kind(fd, D2K_EV_APPLIED, 8, &first, e2, sizeof e2),
              "bound execution did not reach controller");
        CHECK(first.execution_id && first.execution_binding.generation &&
              memcmp(first.execution_binding.epoch, (const uint8_t[16]){0}, 16) &&
              first.execution_binding.kind == D2K_BIND_NAME &&
              first.execution_binding.family == 4 && !first.execution_binding.temporary,
              "Session/journal/control/link lost execution binding");
        CHECK(!d2k_link_set_name(fd, "ok.example", 6, tiny_hex,
              D2K_LINK_SHAPE_GRANDFATHER, e1, sizeof e1), "same plan reinstall");
        CHECK(!next_of_kind(fd, D2K_EV_ACK, 8, &ack, e2, sizeof e2), "reinstall ACK");
        (void)probe_say(&p, "hello ok.example");
        CHECK(!next_of_kind(fd, D2K_EV_APPLIED, 8, &second, e2, sizeof e2), "reinstalled execution");
        CHECK(second.execution_id != first.execution_id &&
              second.execution_binding.generation != first.execution_binding.generation &&
              !memcmp(first.execution_binding.epoch, second.execution_binding.epoch, 16) &&
              !memcmp(first.plan_id, second.plan_id, sizeof first.plan_id),
              "same hash reinstall collapsed distinct execution generations");
    }

    /* --- SET_NAME с негодным планом — ack ok=0, причина D2K_ACK_BAD_PLAN --- */
    {
        char e1[200] = {0};
        CHECK(d2k_link_set_name(fd, "bad.example", 6, "0000000000000000", D2K_LINK_SHAPE_GRANDFATHER, e1, sizeof e1) == 0,
              "SET_NAME с негодным планом должна ДОЕХАТЬ — отказ приходит по ack, не по rc отправки");

        d2k_ev ack;
        char e2[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_ACK, 5, &ack, e2, sizeof e2) == 0, "ack на негодный план не пришёл");
        CHECK(((ack.num >> 8) & 0xFFu) == 0, "негодный план подтверждён как принятый");
        CHECK((ack.num & 0xFFu) == D2K_ACK_BAD_PLAN, "негодный план не помечен D2K_ACK_BAD_PLAN");
    }

    /* --- Пассивная форма и ответ ARM_SHAPE — ДВА разных снимка. Первый
     * привязан к потоку клиента; ответ из кэша имеет нулевые адреса/порты.
     * Для каждого TCP-снимка CLIENT_TCP идёт непосредственно перед SHAPE,
     * а за ответом из кэша — непосредственно ACK самой команды. ---------- */
    {
        (void)probe_say(&p, "hello shape.example");

        char e1[200] = {0};
        d2k_ev hello = {0}, passive_options = {0}, passive = {0}, options = {0}, ev = {0};
        CHECK(next_of_kind(fd, D2K_EV_HELLO, 6, &hello, e1, sizeof e1) == 0 &&
              !strcmp(hello.name, "shape.example"), "passive shape HELLO missing");
        CHECK(d2k_link_next(fd, &passive_options, 2000, e1, sizeof e1) == 0 &&
              passive_options.kind == D2K_EV_CLIENT_TCP, "passive CLIENT_TCP must follow HELLO");
        CHECK(d2k_link_next(fd, &passive, 2000, e1, sizeof e1) == 0 &&
              passive.kind == D2K_EV_SHAPE, "passive SHAPE must follow CLIENT_TCP without ARM_SHAPE");
        CHECK(passive.transport == 6 && passive.family == 4 &&
              passive.low_port == hello.low_port && passive.high_port == hello.high_port &&
              !memcmp(passive.low_ip, hello.low_ip, sizeof hello.low_ip) &&
              !memcmp(passive.high_ip, hello.high_ip, sizeof hello.high_ip) &&
              passive_options.transport == passive.transport && passive_options.family == passive.family &&
              passive_options.low_port == passive.low_port && passive_options.high_port == passive.high_port &&
              !memcmp(passive_options.low_ip, passive.low_ip, sizeof passive.low_ip) &&
              !memcmp(passive_options.high_ip, passive.high_ip, sizeof passive.high_ip),
              "passive snapshot/options lost observed flow key");
        const uint8_t request_id[16] = {0x45, 0x67, 0x89};
        CHECK(d2k_link_arm_shape_request(fd, "shape.example", 6, 4, request_id, e1, sizeof e1) == 0, "ARM_SHAPE не отправилась");

        /* REFUSED на поток без плана ещё может стоять в очереди. Ищем
         * начало ответа команды, затем проверяем порядок без пропусков. */
        CHECK(next_of_kind(fd, D2K_EV_CLIENT_TCP, 6, &options, e1, sizeof e1) == 0 &&
              options.transport == 6 && options.family == 4 &&
              options.low_port == 0 && options.high_port == 0 &&
              !memcmp(options.low_ip, (const uint8_t[16]){0}, sizeof options.low_ip) &&
              !memcmp(options.high_ip, (const uint8_t[16]){0}, sizeof options.high_ip),
              "cached CLIENT_TCP must identify a command snapshot, not a live flow");
        CHECK(d2k_link_next(fd, &ev, 2000, e1, sizeof e1) == 0 &&
              ev.kind == D2K_EV_SHAPE && ev.transport == 6 && ev.family == 4 &&
              ev.low_port == 0 && ev.high_port == 0 &&
              !memcmp(ev.low_ip, options.low_ip, sizeof ev.low_ip) &&
              !memcmp(ev.high_ip, options.high_ip, sizeof ev.high_ip),
              "cached SHAPE must immediately follow its CLIENT_TCP with the same key");
        CHECK(ev.shape_len == passive.shape_len &&
              !memcmp(ev.shape, passive.shape, ev.shape_len),
              "cached request did not return the observed client form");
        CHECK(options.tcp_options_len == passive_options.tcp_options_len &&
              !memcmp(options.tcp_options, passive_options.tcp_options, options.tcp_options_len),
              "cached request changed the observed TCP options");
        CHECK(ev.shape_len >= 3 && ev.shape[0] == 0x16 && ev.shape[1] == 0x03 && ev.shape[2] == 0x01,
              "форма приветствия не похожа на снятый ClientHello (build_hello, ctlprobe.c)");

        d2k_ev ack;
        char e3[200] = {0};
        CHECK(d2k_link_next(fd, &ack, 2000, e3, sizeof e3) == 0, "ack на ARM_SHAPE не пришёл следом за формой");
        CHECK(ack.kind == D2K_EV_ACK, "событие сразу после формы — не ack (нарушен документированный порядок)");
        CHECK(ack.code == D2K_CMD_ARM_SHAPE, "ack не на команду ARM_SHAPE");
        CHECK(!memcmp(ack.trial_id, request_id, sizeof request_id), "snapshot ACK lost request identity");
        CHECK(((ack.num >> 8) & 0xFFu) == 1, "ARM_SHAPE не подтверждена как принятая");
        const uint8_t missing_id[16] = {0x45, 0x67, 0x90};
        CHECK(d2k_link_arm_shape_request(fd, "uncached-shape.example", 6, 4,
            missing_id, e1, sizeof e1) == 0, "uncached snapshot request failed");
        CHECK(d2k_link_next(fd, &ack, 2000, e1, sizeof e1) == 0 &&
              ack.kind == D2K_EV_ACK && ack.code == D2K_CMD_ARM_SHAPE &&
              !memcmp(ack.trial_id, missing_id, sizeof missing_id),
              "uncached snapshot must acknowledge its own request without waiting for traffic");
        const uint8_t zero_id[16] = {0};
        CHECK(d2k_link_arm_shape_request(fd, "shape.example", 6, 4,
            zero_id, e1, sizeof e1) != 0, "zero snapshot identity accepted");
    }

    /* --- EXCHANGE: code липкий (первый тип), поэтому появление прикладных
     * данных ПОСЛЕ другого типа видно только по seen_types, а не по code —
     * ровно та причина, по которой seen_types добавлено сверх контракта
     * брифа (см. d2k_link.h). Проверяем на настоящем обмене: рукопожатие
     * (22), потом прикладные данные (23) на ОДНОМ потоке. --------------- */
    {
        (void)probe_say(&p, "hello exchange.example");
        (void)probe_say(&p, "reply 22");

        d2k_ev ev1;
        char e1[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_EXCHANGE, 6, &ev1, e1, sizeof e1) == 0, "первый обмен (код 22) не пришёл");
        CHECK(ev1.code == 22, "первый обмен: тип записи не 22");
        /* rec[64] в ctlprobe.c ("reply <тип>") — 64 байта нагрузки ровно
           одним пакетом; num = fl->rev_payload_after_hello (session.c) —
           НАКОПЛЕННЫЙ счёт с момента приветствия, не размер текущего
           пакета, поэтому после ВТОРОГО reply это 128, а не снова 64. */
        CHECK(ev1.num == 64, "первый обмен: число байт не 64 — порядок байт длины разобрался неверно");
        CHECK(ev1.flow_incarnation && d2k_rm_nonzero(ev1.flow_epoch,16),
              "live TLS exchange lost immutable flow identity");
        CHECK(d2k_ev_outer_appdata(&ev1) == 0,
              "рукопожатие в настоящем обмене принято за внешний тип 23");

        (void)probe_say(&p, "reply 23");
        d2k_ev ev2;
        char e2[200] = {0};
        CHECK(next_of_kind(fd, D2K_EV_EXCHANGE, 6, &ev2, e2, sizeof e2) == 0,
              "второй обмен (появились прикладные данные) не пришёл");
        CHECK(ev2.code == 22,
              "второй обмен: code изменился — липкое поле ведёт себя иначе, чем задокументировано в d2k_link.h");
        CHECK(ev2.num == 128, "второй обмен: накопленное число байт не 128 (64+64)");
        CHECK(ev1.flow_incarnation==ev2.flow_incarnation &&
              !memcmp(ev1.flow_epoch,ev2.flow_epoch,16),"same TLS flow changed incarnation");
        /* Ровно тот вход, на котором старый (удалённый по ревью) подход —
           «тип ПЕРВОЙ записи == 23» — солгал бы: code второй записи EXCHANGE
           всё равно 22 (липкое поле, проверено строкой выше), а не 23.
           Документируем эту ложь явно, не называя удалённую функцию (её
           больше нет в дереве), а наблюдение внешнего типа обязано на ЭТОМ
           ЖЕ входе дать истину. */
        CHECK(ev2.code != D2K_TLS_APPLICATION_DATA,
              "документирует дефект старого подхода: код первой записи не должен быть 23 на этом входе");
        CHECK(d2k_ev_outer_appdata(&ev2) == 1,
              "внешний тип 23 во втором обмене не увиден — та самая дырка, которую закрывает seen_types");
        /* И ровно здесь проходит граница задачи 4: этот же вход НЕ является
           доказательством работы приложения. Второй полёт рукопожатия
           TLS 1.3 едет наружу тем же типом 23 (RFC 8446 §5.2), и с провода
           он неотличим от прикладных данных. Что ответило ПРИЛОЖЕНИЕ,
           узнаёт только тот, кто вёл рукопожатие своим ключом
           (core/verify.c, D2K_VER_APPLICATION); порог каталога живёт там, а
           не здесь. Стенд ctlprobe шлёт "reply 23" открытым текстом — он не
           умеет и не обязан отличать одно от другого, и это ровно то, что
           умеет наблюдатель на проводе. */
    }

    /* --- отрицательный wait_ms — «ждать неограниченно» (семантика poll(2)),
     * проверяется безопасно: событие гарантированно уже лежит в буфере к
     * моменту вызова (иначе тест мог бы зависнуть навечно при поломке). --- */
    {
        char e1[200] = {0};
        CHECK(d2k_link_set_name(fd, "forever.example", 17, "", D2K_LINK_SHAPE_GRANDFATHER, e1, sizeof e1) == 0,
              "SET_NAME для проверки wait_ms<0 не отправилась");
        nap_ms(100); /* ack успевает дойти и лечь в буфер сокета */

        d2k_ev ack;
        char e2[200] = {0};
        int rc = d2k_link_next(fd, &ack, -1, e2, sizeof e2);
        CHECK(rc == 0, "wait_ms<0 не увидел уже лежащее в буфере событие");
        CHECK(ack.kind == D2K_EV_ACK, "wait_ms<0 прочитал не то событие");
    }

    /* Real serializer path: SYN establishes direction, RST generates the
       suspicion, journal -> ctlsrv -> Unix socket -> controller decoder. */
    {
        d2k_ev hello, suspicion;
        char e[200] = {0};
        (void)probe_say(&p, "hello direction.example");
        CHECK(next_of_kind(fd, D2K_EV_HELLO, 8, &hello, e, sizeof e) == 0,
              "direction fixture hello missing");
        (void)probe_say(&p, "rst");
        CHECK(next_of_kind(fd, D2K_EV_SUSPECT, 8, &suspicion, e, sizeof e) == 0 &&
              suspicion.client_side == D2K_CLIENT_SIDE_HIGH &&
              suspicion.high_port == hello.high_port,
              "observed direction lost between real datapath and controller");
    }

    d2k_link_close(fd);
    probe_stop(&p, sock_path);

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("связь с датапатом и порог успеха: все проверки прошли\n");
    return 0;
}
