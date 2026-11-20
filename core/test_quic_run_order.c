#include <stdio.h>
#include <string.h>
#include "d2k_quic_arms.h"
#include "d2k_quichello.h"
#include "d2k_quic.h"
static int calls, fails, lose_base_mark, junk16_asks, all_pass;
static int base_pass_short; /* прямой Initial отвечает 2/3 (поле 24.10.2026, katzauction.com) */
static int fragment_calls, arm_second_stalls;
static int candidate_passed, diagnostics_after_pass;
static size_t first_prefix;
static uint8_t first_arm_hello[2048];
static size_t first_arm_hello_len;
static int arm_hello_count, arm_hello_changed;
#define CHECK(x) do { if(!(x)) { printf("FAIL %d %s\n",__LINE__,#x); fails++; } } while(0)
static size_t resolve(const char *sni,char out[][D2K_QUIC_ADDR_LEN],size_t cap) {
    (void)sni;(void)out;(void)cap;return 0;
}
static d2k_tally answer(int n,int *sent) {
    d2k_tally t={0}; t.marked=1; if(sent)*sent=n;
    if(lose_base_mark && calls==0)t.marked=0;
    if(base_pass_short && calls==1){ calls++; t.pass=n-1; t.fail=1; return t; } /* второй опрос — прямой Initial (первый — контроль) */
    if(calls++==1 && !all_pass) t.fail=n; else t.pass=n;
    return t;
}
static d2k_tally ask(const char *ip,uint16_t port,const uint8_t *pre,size_t len,
    d2k_hello msg,uint32_t wait,uint32_t mark,int n,uint32_t *rtt,int *ref,int *sent,uint8_t *ttl) {
    (void)ip;(void)port;(void)wait;(void)mark;
    if(candidate_passed && !pre) diagnostics_after_pass++;
    if(pre && !first_prefix) first_prefix=len;
    if(pre && len==16) junk16_asks++;
    if(pre) {
        uint8_t hello[2048]; size_t hello_len=0;
        CHECK(d2k_quic_client_hello(msg.bytes,msg.len,hello,sizeof hello,&hello_len)==0);
        if(arm_hello_count==0) {
            memcpy(first_arm_hello,hello,hello_len);
            first_arm_hello_len=hello_len;
        } else if(hello_len!=first_arm_hello_len ||
                  memcmp(hello,first_arm_hello,hello_len)!=0) {
            arm_hello_changed++;
        }
        arm_hello_count++;
    }
    if(rtt)*rtt=1;
    if(ref)*ref=0;
    if(ttl)*ttl=64;
    return answer(n,sent);
}
static d2k_tally copies(const char *ip,uint16_t port,const uint8_t *p,size_t l,int c,
    d2k_hello h,uint32_t w,uint32_t m,int n,int *sent) {
    (void)c; return ask(ip,port,p,l,h,w,m,n,NULL,NULL,sent,NULL);
}
static d2k_tally srcport(const char *ip,uint16_t port,int sp,d2k_hello h,uint32_t w,uint32_t m,int n,int *sent) {
    (void)sp;return ask(ip,port,NULL,0,h,w,m,n,NULL,NULL,sent,NULL);
}
static d2k_tally split(const char *ip,uint16_t port,d2k_hello h,const char *sni,uint32_t w,uint32_t m,int n,int *sent) {
    (void)sni;return ask(ip,port,NULL,0,h,w,m,n,NULL,NULL,sent,NULL);
}
static d2k_tally fragment(const char *ip,uint16_t port,int shape,d2k_hello h,uint32_t w,uint32_t m,int n,int *sent) {
    (void)ip;(void)port;(void)w;(void)m;
    char sni[256];
    CHECK(shape==1);
    CHECK(d2k_quic_sni(h.bytes,h.len,sni,sizeof sni)==0);
    CHECK(!strcmp(sni,fragment_calls%2==0?"z0123456789.example.com":"target.example"));
    fragment_calls++;
    d2k_tally t={0};t.pass=n;t.marked=1;*sent=n;return t;
}
/* Задача 40: вопросы стратегии (остаточное разрешение, разрез CRYPTO) идут
   раньше лестницы. 'U' — ответ не решающий (1/3 оба раза): лестница
   askArms остаётся запасным путём, и её порядок проверяется как прежде;
   'Y' — разрешение есть; 'N' — оба «нет». */
static char strategy_mode='U';
static int strategy_calls;
static int length_pass,length_calls,length_diagnostics;
static d2k_tally diagnostic_length(const char *ip,uint16_t port,const uint8_t *pre,size_t len,
    d2k_hello msg,uint32_t wait,uint32_t mark,int n,uint32_t *rtt,int *ref,int *sent,uint8_t *ttl) {
    length_diagnostics++;
    return ask(ip,port,pre,len,msg,wait,mark,n,rtt,ref,sent,ttl);
}
static d2k_tally arm_probe(const d2k_quic_arm_question *q,const char *sni,
    uint16_t port,uint32_t wait,uint32_t mark,int *sent) {
    uint8_t initial[1500];size_t initial_len=0;
    if(q->udplen) {
        length_calls++;*sent=D2K_QUIC_REPEATS;
        return (d2k_tally){.marked=1,.pass=length_pass?3:0,.fail=length_pass?0:3};
    }
    if(q->benign || q->split) {
        d2k_tally t={0};t.marked=1;*sent=D2K_QUIC_REPEATS;strategy_calls++;
        CHECK(sni && !strcmp(sni,"target.example"));
        if(strategy_mode=='U'){t.pass=1;t.fail=D2K_QUIC_REPEATS-1;}
        else if(strategy_mode=='Y' && q->benign) t.pass=D2K_QUIC_REPEATS;
        else t.fail=D2K_QUIC_REPEATS;
        return t;
    }
    if(arm_second_stalls && q->control) {
        d2k_tally t={0}; t.marked=1; t.fail=D2K_QUIC_REPEATS;
        *sent=D2K_QUIC_REPEATS; return t;
    }
    /* Fragment survival names nothing: the wire layer draws a fresh donor
       neutralName() per repeat (arms.go:204-205), never the control
       snapshot's name or the scheduler decoy. */
    if(q->control) {
        CHECK(sni==NULL);
        sni="z0123456789.example.com";
    }
    if(!sni || d2k_quic_probe_initial(sni,initial,sizeof initial,&initial_len)!=0) {
        d2k_tally t={0};t.fail=t.err=D2K_QUIC_REPEATS;t.marked=(mark==0);*sent=0;return t;
    }
    d2k_hello msg={initial,initial_len,NULL,0,0, 0};
    if(q->frag)return d2k_quic_fragment_hook(q->addr,port,q->frag,msg,wait,mark,D2K_QUIC_REPEATS,sent);
    if(q->ttl)return d2k_quic_ask_ttl_hook(q->addr,port,q->blob,q->blob_len,q->ttl,msg,wait,mark,D2K_QUIC_REPEATS,sent);
    if(q->copies>1)return d2k_quic_ask_copies_hook(q->addr,port,q->blob,q->blob_len,q->copies,msg,wait,mark,D2K_QUIC_REPEATS,sent);
    return d2k_quic_ask_hook(q->addr,port,q->blob,q->blob_len,msg,wait,mark,D2K_QUIC_REPEATS,NULL,NULL,sent,NULL);
}
/* Task 39: this test pins the ladder ORDER; the arm data stage (handshake
   plus application data) is stubbed as passed, and counted. */
static int data_calls;
static d2k_quic_arm_data data_failed(const d2k_quic_arm_question *q,const char *sni,
    const char *path,uint16_t port,uint32_t wait,uint32_t mark) {
    (void)q;(void)sni;(void)path;(void)port;(void)wait;(void)mark;data_calls++;
    return (d2k_quic_arm_data){.verdict=D2K_QAD_CUT};
}
static char want_path[64];
static d2k_quic_arm_data data_pass(const d2k_quic_arm_question *q,const char *sni,
    const char *path,uint16_t port,uint32_t wait,uint32_t mark) {
    (void)port;(void)wait;(void)mark;
    if(want_path[0]) CHECK(path && !strcmp(path,want_path));
    else CHECK(path==NULL); /* no known resource: the data stage asks "/" */
    CHECK(!q->control && sni && !strcmp(sni,"target.example"));
    data_calls++;
    d2k_quic_arm_data d; memset(&d,0,sizeof d);
    d.verdict=D2K_QAD_PASS; d.app_bytes=D2K_QUIC_ARM_DATA_BYTES;
    candidate_passed=1;
    return d;
}
/* Задача 50, раунд 2: прямой этап данных — без воздействия. Обрыв после
   рукопожатия: сам по себе ответ встаёт, плечо с воздействием проходит. */
static int direct_data_calls, direct_cut, direct_seq[4], arm_need_complete = -1;
static unsigned direct_budget, arm_budget_seen;
/* Задача 27: контроль «заведомо короткий ответ». Отличается от прямых
   повторов тем, что воспроизведения по бюджету не просит (budget_pk == 0), и
   спрашивает свой путь со случайным хвостом. */
static int ctl_calls, ctl_verdict = D2K_QAD_PASS;
static char ctl_path[64];
static uint64_t direct_bytes[2], direct_pkts[2];
static d2k_quic_arm_data data_cut(const d2k_quic_arm_question *q,const char *sni,
    const char *path,uint16_t port,uint32_t wait,uint32_t mark) {
    (void)port;(void)wait;(void)mark;(void)sni;
    d2k_quic_arm_data d; memset(&d,0,sizeof d);
    int plain=!q->blob && q->copies<=1 && !q->ttl && !q->frag && !q->benign && !q->split && !q->udplen;
    if(plain && q->budget_pk==0) {
        ctl_calls++;
        snprintf(ctl_path,sizeof ctl_path,"%s",path?path:"");
        CHECK(q->need_complete==1);
        d.verdict=(d2k_quic_arm_data_verdict)ctl_verdict;
        d.app_bytes=ctl_verdict==D2K_QAD_PASS?263:0;
        return d;
    }
    if(plain) {
        /* direct_seq: 1 — обрыв, 2 — ответ целиком; 0 — по direct_cut. */
        int v = direct_data_calls < 4 && direct_seq[direct_data_calls] ?
                direct_seq[direct_data_calls] : (direct_cut ? 1 : 2);
        CHECK(q->need_complete == 1);
        direct_budget = q->budget_pk;
        d.verdict=v==1?D2K_QAD_CUT:D2K_QAD_PASS;
        d.app_bytes=v==1?1169:D2K_QUIC_ARM_DATA_BYTES;
        /* Задача 28: числа остановки задаёт тест, когда ему нужно проверить,
           на чём сошлась пара. Ноль — как прежде, оба повтора одинаковы. */
        if(direct_data_calls<2 && (direct_bytes[direct_data_calls] ||
                                   direct_pkts[direct_data_calls])) {
            if(direct_bytes[direct_data_calls]) d.app_bytes=direct_bytes[direct_data_calls];
            d.packets=direct_pkts[direct_data_calls];
        }
        direct_data_calls++;
    } else {
        arm_need_complete = q->need_complete;
        arm_budget_seen = q->budget_pk;
        data_calls++;
        /* A short complete first response succeeds only when no packet-budget
           reproduction was requested. With it, the silent second request cuts. */
        d.verdict=arm_second_stalls && q->budget_pk ? D2K_QAD_CUT : D2K_QAD_PASS;
        d.app_bytes=1100;
        if(arm_second_stalls) CHECK(q->budget_pk==direct_budget);
    }
    return d;
}

/* Раунд 3: «встал» — это молчание ТРАНСПОРТА, проверенное нашими пакетами,
   требующими подтверждения (PING), а не медленный первый байт. */
static void stall_machine(void) {
    d2k_qstall st;
    /* Медленный первый байт: сервер ПОДТВЕРЖДАЕТ наш PING, данных ещё нет.
       Подтверждение моделируется номером пакета, а не приходом байт: прежняя
       редакция этой проверки прибавляла 40 байт «ACK на PING», и правило
       «вырос приём — значит ответил» было записано прямо в модели. */
    d2k_qstall_init(&st, 50, 0, 1000, 5000);
    int stalled = 0, pings = 0, oneway = 0;
    uint64_t prog = 1000, wire = 5000, acked = 0, pn = 0;
    int have_ack = 0;
    for (int64_t t = 0; t <= 6000; t += 50) {
        if (t >= 4000) { prog += 1200; wire += 1200; }  /* ответ пошёл на 4-й секунде */
        int a = d2k_qstall_step(&st, t, prog, wire, have_ack, acked);
        if (a == D2K_QSTALL_PROBE) {
            pings++;
            d2k_qstall_sent(&st, ++pn);
            acked = pn; have_ack = 1; wire += 40;      /* сервер подтвердил его */
        }
        if (a == D2K_QSTALL_STALLED) stalled = 1;
        if (a == D2K_QSTALL_ONEWAY) oneway = 1;
    }
    CHECK(!stalled && !oneway && pings >= 2);
    /* Один потерянный пакет: секунда без роста ответа, PING, сервер
       подтверждает — поток идёт. */
    d2k_qstall_init(&st, 50, 0, 1000, 5000);
    prog = 1000; wire = 5000; stalled = 0; oneway = 0; acked = 0; pn = 0; have_ack = 0;
    for (int64_t t = 0; t <= 6000; t += 50) {
        if (t < 500 || t >= 1500) { prog += 1200; wire += 1200; }
        int a = d2k_qstall_step(&st, t, prog, wire, have_ack, acked);
        if (a == D2K_QSTALL_PROBE) { d2k_qstall_sent(&st, ++pn); acked = pn; have_ack = 1; }
        if (a == D2K_QSTALL_STALLED) stalled = 1;
        if (a == D2K_QSTALL_ONEWAY) oneway = 1;
    }
    CHECK(!stalled && !oneway);
    /* Настоящий обрыв: данные шли, затем ни одного пакета, два PING без ответа. */
    d2k_qstall_init(&st, 50, 0, 1000, 5000);
    prog = 1000; wire = 5000; stalled = 0; pings = 0; pn = 0;
    int64_t at = -1;
    for (int64_t t = 0; t <= 6000 && at < 0; t += 50) {
        if (t < 300) { prog += 1200; wire += 1200; }
        int a = d2k_qstall_step(&st, t, prog, wire, 0, 0);
        if (a == D2K_QSTALL_PROBE) { pings++; d2k_qstall_sent(&st, ++pn); }
        if (a == D2K_QSTALL_STALLED) at = t;
    }
    CHECK(at >= 3000 && at <= 3400 && pings == 2);
    /* ЗАГЛУШЕНО ИСХОДЯЩЕЕ НАПРАВЛЕНИЕ: ответ не растёт, а датаграммы сервера
       идут (повтор его последнего полёта по PTO) и наш PING не подтверждён.
       Прежнее правило в этом случае не объявляло обрыв НИКОГДА. */
    d2k_qstall_init(&st, 50, 0, 1000, 5000);
    prog = 1000; wire = 5000; stalled = 0; oneway = 0; pings = 0; pn = 0;
    int64_t ow_at = -1;
    for (int64_t t = 0; t <= 6000 && ow_at < 0; t += 50) {
        wire += 1200;                                  /* сервер шлёт без остановки */
        int a = d2k_qstall_step(&st, t, prog, wire, 0, 0);
        if (a == D2K_QSTALL_PROBE) { pings++; d2k_qstall_sent(&st, ++pn); }
        if (a == D2K_QSTALL_STALLED) stalled = 1;
        if (a == D2K_QSTALL_ONEWAY) ow_at = t;
    }
    CHECK(ow_at >= 3000 && ow_at <= 3400 && pings == 2 && !stalled);
    /* RTO растёт с измеренным RTT: 3×500 мс. */
    d2k_qstall_init(&st, 500, 0, 1000, 5000);
    CHECK(st.rto_ms == 1500);

    /* Вердикт этапа данных (раунд 3). */
    CHECK(d2k_quic_arm_data_judge3(1, 200, 5000, 1, 0, 1, 0, 0) == D2K_QAD_PASS);   /* ответ целиком */
    CHECK(d2k_quic_arm_data_judge3(1, 0, 0, 0, 1, 1, 0, 0) == D2K_QAD_CUT);         /* встал до заголовков */
    CHECK(d2k_quic_arm_data_judge3(1, 200, 9000, 0, 1, 1, 0, 0) == D2K_QAD_CUT);    /* встал посреди */
    CHECK(d2k_quic_arm_data_judge3(1, 0, 0, 0, 0, 1, 0, 0) == D2K_QAD_NOT_RUN);     /* жив, но не успел */
    CHECK(d2k_quic_arm_data_judge3(1, 200, 40000, 0, 0, 1, 0, 0) == D2K_QAD_NOT_RUN); /* нужен целый */
    CHECK(d2k_quic_arm_data_judge3(1, 200, 40000, 0, 0, 0, 0, 0) == D2K_QAD_PASS);  /* прежнее правило */
    CHECK(d2k_quic_arm_data_judge3(1, 451, 300, 1, 0, 1, 0, 0) == D2K_QAD_CUT);
    CHECK(d2k_quic_arm_data_judge3(0, 0, 0, 0, 0, 1, 0, 0) == D2K_QAD_NO_HANDSHAKE);
    CHECK(d2k_quic_arm_data_judge3(1, 0, 0, 0, 0, 1, 1, 0) == D2K_QAD_NOT_RUN);     /* наш предел заголовков */
    /* Раунд 4, N1: бюджет коробки. Поток, пронёсший 2 × 25 пакетов при живом
       сервере, засчитывается до конца ответа — обход большого ресурса не
       становится «обрывом». Встал — всё равно обрыв. */
    CHECK(d2k_quic_arm_data_judge3(1, 200, 60000, 0, 0, 1, 0, 1) == D2K_QAD_PASS);
    CHECK(d2k_quic_arm_data_judge3(1, 0, 0, 0, 0, 1, 0, 1) == D2K_QAD_NOT_RUN);
    CHECK(d2k_quic_arm_data_judge3(1, 200, 9000, 0, 1, 1, 0, 0) == D2K_QAD_CUT);
    CHECK(D2K_QUIC_BOX_BUDGET_PKTS == 25);
    /* Бюджет коробки: порог перейдён — ещё не пройден, нужен РОСТ ответа
       после порога. Шторм повторов при нулевом росте обходом не считается. */
    d2k_qbudget bg;
    d2k_qbudget_init(&bg, 0);
    CHECK(bg.need == 50);
    CHECK(d2k_qbudget_ok(&bg, 49, 9000, 200, 5000, 4900, 1000) == 0);  /* 49 — мало */
    CHECK(d2k_qbudget_ok(&bg, 50, 9000, 200, 5000, 4900, 1000) == 0);  /* порог только что перейдён */
    CHECK(d2k_qbudget_ok(&bg, 52, 9000, 200, 5000, 4900, 1000) == 0);  /* ответ не вырос */
    CHECK(d2k_qbudget_ok(&bg, 52, 9600, 200, 5000, 4900, 1000) == 1);  /* вырос — пройден */
    CHECK(d2k_qbudget_ok(&bg, 52, 9600, 0, 5000, 4900, 1000) == 0);    /* нет ответа HTTP */
    CHECK(d2k_qbudget_ok(&bg, 52, 9600, 200, 5000, 3900, 1000) == 0);  /* ответ не растёт RTO */
    /* Шторм повторов: датаграмм сколько угодно, ответ не вырос ни на байт. */
    d2k_qbudget_init(&bg, 25);
    CHECK(d2k_qbudget_ok(&bg, 842229, 513, 200, 5000, 4990, 1000) == 0);
}

/* Поле 24.10.2026 (h3-1024, класс C): katzauction.com, rua.gr, enimerosi.com —
   рукопожатие QUIC проходит, запрос HTTP/3 остаётся без ответа (pcap: после
   0.146 с сервер молчит совсем), а поиск кончался «прямой зонд не
   воспроизводится: 2/3» и подбор не открывался. Вопрос подозрения — о данных
   после рукопожатия; одна потерянная датаграмма Initial из трёх на него не
   отвечает и не вправе его снимать. Без признака обрыва данных строгость
   рукопожатия прежняя: 2/3 — FLAKY. */
static void flaky_initial_keeps_data_question(void) {
    uint8_t tb[1500],cb[1500];size_t tn=0,cn=0;
    CHECK(d2k_quic_probe_initial("target.example",tb,sizeof tb,&tn)==0);
    CHECK(d2k_quic_probe_initial("neutral.example",cb,sizeof cb,&cn)==0);
    d2k_quic_arm_data_wire_fn saved=d2k_quic_arm_data_hook;
    d2k_quic_arm_data_hook=data_cut;
    all_pass=1; base_pass_short=1;
    d2k_quic_arm arm;
    memset(&arm,0,sizeof arm); arm.data_cut=1; calls=0; data_calls=direct_data_calls=0; direct_cut=1;
    memset(direct_seq,0,sizeof direct_seq); ctl_verdict=D2K_QAD_PASS;
    d2k_vres r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE && direct_data_calls==2);
    CHECK(strstr(r.reason,"2/3")!=NULL && strstr(r.reason,"после рукопожатия")!=NULL);
    /* Без признака обрыва данных — как прежде. */
    memset(&arm,0,sizeof arm); calls=0; data_calls=direct_data_calls=0;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_FLAKY && direct_data_calls==0);
    base_pass_short=0; all_pass=0; direct_cut=0;
    d2k_quic_arm_data_hook=saved;
}

static void post_handshake_stall(void) {
    uint8_t tb[1500],cb[1500];size_t tn=0,cn=0;
    CHECK(d2k_quic_probe_initial("target.example",tb,sizeof tb,&tn)==0);
    CHECK(d2k_quic_probe_initial("neutral.example",cb,sizeof cb,&cn)==0);
    d2k_quic_arm_data_wire_fn saved=d2k_quic_arm_data_hook;
    d2k_quic_arm_data_hook=data_cut;
    all_pass=1;
    d2k_quic_arm arm;
    /* Без признака обрыва после рукопожатия — как прежде: прямой Initial
       3/3 и CLEAR, этап данных не задаётся. */
    memset(&arm,0,sizeof arm); calls=0; data_calls=direct_data_calls=0; direct_cut=1;
    d2k_vres r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_CLEAR && direct_data_calls==0 && data_calls==0);
    /* Строка называет, что прошло: только рукопожатие (не TCP-фраза). */
    CHECK(strstr(r.reason,"Initial")!=NULL && strstr(r.reason,"не проверялся")!=NULL &&
          strstr(r.reason,"триггер проходит как есть")==NULL);
    /* Признак есть, ответ своим запросом встаёт: обрыв воспроизведён, плечи
       меряются этапом данных, найденное плечо — кандидат. */
    memset(&arm,0,sizeof arm); arm.data_cut=1; calls=0; data_calls=direct_data_calls=0;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    /* Раунд 3: два своих запроса на свежих соединениях, оба встали. Плечо
       засчитывается только полным ответом (need_complete). */
    CHECK(r.verdict==D2K_V_OPAQUE && direct_data_calls==2 && data_calls>=1);
    CHECK(arm_need_complete==1);
    CHECK(arm.original && arm.kind!=D2K_QA_NOT_FOUND && arm.kind!=D2K_QA_FLAKY);
    CHECK(strstr(r.reason,"после рукопожатия")!=NULL);
    CHECK(arm.data_cut==1);
    /* Поле 04.10: свой запрос мерится бюджетом коробки (по умолчанию 25),
       плечи обязаны пройти тот же бюджет. Воспроизведение — выход. */
    CHECK(direct_budget==D2K_QUIC_BOX_BUDGET_PKTS && arm_budget_seen==D2K_QUIC_BOX_BUDGET_PKTS);
    CHECK(arm.data_cut_seen==1);
    /* ЗАДАЧА 27: ЧТО НАЗНАЧИЛО ОСТАНОВКУ — РАЗМЕР ИЛИ САМ ПОТОК. Два повтора
       встали на двух РАЗНЫХ четвёрках (у каждого опыта свой местный порт), то
       есть про четвёрку вопрос уже отвечен без нового зонда. Чего они не
       говорят — зависит ли остановка от размера; это и спрашивает контроль:
       заведомо отсутствующий путь того же имени, один полный ответ. */
    CHECK(ctl_calls==1 && !strncmp(ctl_path,"/d2k-",5) && strlen(ctl_path)==13);
    CHECK(r.qprops.flow_cut_any_size==D2K_PROP_NO);
    CHECK(strstr(r.reason,"короткий ответ дошёл")!=NULL);
    /* Оба повтора вернули одни и те же числа — сошлось и там, и там, и
       выбрать одно объяснение нельзя. */
    CHECK(r.qprops.stop_by_bytes==D2K_PROP_YES && r.qprops.stop_by_packets==D2K_PROP_YES);
    CHECK(strstr(r.reason,"и байты, и пакеты")!=NULL);
    /* Числа остановки печатаются в ДВУХ видах: решать, который повторяется,
       здесь нечем (парная дисциплина — задача 28), но поле обязано их видеть. */
    CHECK(strstr(r.reason,"байт")!=NULL && strstr(r.reason,"датаграмм")!=NULL);
    /* Контроль тоже встал: режется сам поток, объёмные числа ничего не значат. */
    memset(&arm,0,sizeof arm); arm.data_cut=1; calls=0; data_calls=direct_data_calls=0;
    ctl_calls=0; ctl_verdict=D2K_QAD_CUT;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE && ctl_calls==1);
    CHECK(r.qprops.flow_cut_any_size==D2K_PROP_YES);
    CHECK(strstr(r.reason,"короткий ответ тоже встал")!=NULL);
    /* Контроль не измерился — вопрос НЕ ЗАДАН, а не отвечен отрицательно. */
    memset(&arm,0,sizeof arm); arm.data_cut=1; calls=0; data_calls=direct_data_calls=0;
    ctl_calls=0; ctl_verdict=D2K_QAD_NOT_RUN;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE && ctl_calls==1);
    CHECK(r.qprops.flow_cut_any_size==D2K_PROP_UNKNOWN);
    CHECK(strstr(r.reason,"короткий ответ")==NULL);
    /* Вопрос не задан — на чём сошлась пара, тоже не спрашивается: величина
       ни при чём, пока не доказано, что короткий ответ доходит. */
    CHECK(r.qprops.stop_by_bytes==D2K_PROP_UNKNOWN &&
          r.qprops.stop_by_packets==D2K_PROP_UNKNOWN);
    ctl_verdict=D2K_QAD_PASS;
    /* ЗАДАЧА 28: НА ЧЁМ ОСТАНОВКА ПОВТОРЯЕТСЯ. Допуски — те же, что у
       TCP-ветки: D2K_VOLUME_SLACK килобайт по байтам, D2K_VOLUME_PACKET_SLACK
       по пакетам. Три различимых случая. */
    struct { uint64_t b0,b1,p0,p1; int8_t by,pk; const char *tag; } basis[] = {
        /* байты сошлись (в пределах 4 КиБ), пакеты разъехались */
        { 16000, 17000, 20, 40, D2K_PROP_YES, D2K_PROP_NO,  "сошлись байты" },
        /* пакеты сошлись (в пределах 3), байты разъехались */
        { 5000, 60000, 25, 26, D2K_PROP_NO,  D2K_PROP_YES, "сошлись пакеты" },
        /* не сошлось ничего: остановка по величине не повторяется */
        { 1000, 90000, 10, 90, D2K_PROP_NO,  D2K_PROP_NO,  "ни байты, ни пакеты" },
    };
    for(size_t i=0;i<sizeof basis/sizeof basis[0];i++) {
        memset(&arm,0,sizeof arm); arm.data_cut=1; calls=0;
        data_calls=direct_data_calls=0; ctl_calls=0;
        direct_bytes[0]=basis[i].b0; direct_bytes[1]=basis[i].b1;
        direct_pkts[0]=basis[i].p0;  direct_pkts[1]=basis[i].p1;
        r=d2k_quic_run("127.0.0.1",443,"target.example",
            (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
        CHECK(r.verdict==D2K_V_OPAQUE && ctl_calls==1);
        CHECK(r.qprops.stop_by_bytes==basis[i].by);
        CHECK(r.qprops.stop_by_packets==basis[i].pk);
        CHECK(strstr(r.reason,basis[i].tag)!=NULL);
        if(r.qprops.stop_by_bytes!=basis[i].by||r.qprops.stop_by_packets!=basis[i].pk||
           !strstr(r.reason,basis[i].tag))
            fprintf(stderr,"основа %zu: байты %d пакеты %d [%s]\n",i,
                    r.qprops.stop_by_bytes,r.qprops.stop_by_packets,r.reason);
    }
    direct_bytes[0]=direct_bytes[1]=direct_pkts[0]=direct_pkts[1]=0;
    /* Бюджет коробки из замера доходит до своего запроса и переживает прогон. */
    memset(&arm,0,sizeof arm); arm.data_cut=1; arm.budget_pk=17;
    calls=0; data_calls=direct_data_calls=0; direct_budget=0;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE && direct_budget==17 && arm_budget_seen==17 && arm.budget_pk==17);
    /* Both strategy and fallback arms must reject first-response-only success. */
    memset(&arm,0,sizeof arm); arm.data_cut=1; arm.budget_pk=17;
    calls=0; data_calls=direct_data_calls=0; arm_second_stalls=1;
    char saved_mode=strategy_mode; strategy_mode='Y';
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE && arm.kind==D2K_QA_NOT_FOUND);
    CHECK(data_calls>2 && arm_budget_seen==17);
    arm_second_stalls=0; strategy_mode=saved_mode;
    /* Перепроверка перед снятием запрета QUIC (data_cut 2): только прямые
       запросы, плечи не меряются. Прежде вход сводился к 0/1, и ветка
       «2» была мёртвой — перепроверка мерила плечи. */
    memset(&arm,0,sizeof arm); arm.data_cut=2; calls=0; data_calls=direct_data_calls=0;
    ctl_calls=0;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE && direct_data_calls==2 && data_calls==0);
    CHECK(arm.data_cut==2 && arm.data_cut_seen==1);
    /* Перепроверке контроль не нужен: ей нужен один ответ «встаёт ли ещё». */
    CHECK(ctl_calls==0);
    /* Признак есть, но ответ приходит целиком: не воспроизвелось — CLEAR,
       плечи не меряются. */
    memset(&arm,0,sizeof arm); arm.data_cut=1; calls=0; data_calls=direct_data_calls=0;
    direct_cut=0;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_CLEAR && direct_data_calls==1 && data_calls==0);
    CHECK(strstr(r.reason,"не воспроизв")!=NULL);
    CHECK(arm.data_cut_seen==0);
    /* Первый встал, второй прошёл целиком — не воспроизводится: плечи не
       меряются, ни плана, ни снятия QUIC. */
    memset(&arm,0,sizeof arm); arm.data_cut=1; calls=0; data_calls=direct_data_calls=0;
    direct_seq[0]=1; direct_seq[1]=2;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_FLAKY && direct_data_calls==2 && data_calls==0);
    CHECK(arm.kind==D2K_QA_NOT_FOUND || !arm.original);
    direct_seq[0]=direct_seq[1]=0;
    all_pass=0;
    d2k_quic_arm_data_hook=saved;
}

int main(void) {
    d2k_quic_arm_data_hook=data_pass;
    d2k_quic_allow_local=1; d2k_quic_resolve_hook=resolve;
    d2k_quic_ask_hook=ask; d2k_quic_ask_longer_hook=diagnostic_length; d2k_quic_ask_frames_hook=ask; d2k_quic_ask_control_hook=ask;
    d2k_quic_ask_copies_hook=copies; d2k_quic_ask_ttl_hook=copies;
    d2k_quic_ask_srcport_hook=srcport; d2k_quic_ask_split_hook=split;
    d2k_quic_fragment_hook=fragment;
    d2k_quic_ask_arm_hook=arm_probe;
    uint8_t tb[1500],cb[1500];size_t tn=0,cn=0;
    CHECK(d2k_quic_probe_initial("target.example",tb,sizeof tb,&tn)==0);
    CHECK(d2k_quic_probe_initial("neutral.example",cb,sizeof cb,&cn)==0);
    d2k_quic_arm arm;
    memset(&arm,0,sizeof arm);
    d2k_vres r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE);
    CHECK(first_prefix==1200); /* приманка 1200 байт раньше 16-байтного «мусора» свойств */
    CHECK(arm_hello_count==1); /* первое полное плечо кончает поиск */
    CHECK(arm.original && arm.len==1200 && arm.ttl==0 && arm.copies==1 &&
          !strcmp(arm.blob_name,"quic5"));
    CHECK(fragment_calls==0 && arm.frag_kind==0 && arm.frag_survives==D2K_PROP_UNKNOWN);
    CHECK(data_calls==1); /* первое плечо прошло; копий/TTL/фрагментов не понадобилось */
    CHECK(strategy_calls==4 && arm.strategy==D2K_QS_LADDER); /* два вопроса, по одному повтору */
    /* Круг 1: заданное до предела повторов не задаётся снова — ни приманкой
       0x00…0 перебора, ни «мусором»/«кадрами» вопросника. */
    CHECK(junk16_asks==0 && arm.clearance_asked && arm.split_asked);
    CHECK(r.qtrace[0].sent==0 && r.qtrace[1].sent==0);
    CHECK(r.qprops.junk_ahead==D2K_PROP_UNKNOWN && r.qprops.split_crypto==D2K_PROP_UNKNOWN);
    CHECK(arm.n_trace>=4 && arm.trace[0].answered==1 && arm.trace[3].answered==1);
    /* The scheduler's known large resource reaches the data stage. */
    calls=0;first_prefix=0;fragment_calls=0;data_calls=0;
    memset(&arm,0,sizeof arm);
    snprintf(want_path,sizeof want_path,"/static/site.css");
    snprintf(arm.probe_path,sizeof arm.probe_path,"%s",want_path);
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(data_calls==1 && !strcmp(arm.probe_path,want_path));
    /* Задача 40: остаточное разрешение есть — план из ответа, перебора нет,
       «мусор» вопросника второй раз не задаётся. */
    want_path[0]=0; memset(&arm,0,sizeof arm);
    calls=0;first_prefix=0;fragment_calls=0;data_calls=0;strategy_calls=0;strategy_mode='Y';
    candidate_passed=diagnostics_after_pass=0;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE && arm.kind==D2K_QA_BLOB && arm.strategy==D2K_QS_CLEARANCE);
    CHECK(arm.len==D2K_QUIC_BENIGN_LEN && arm.copies==1 && strategy_calls==1 && data_calls==1);
    CHECK(fragment_calls==0 && first_prefix==0);
    CHECK(r.qprops.junk_ahead==D2K_PROP_YES && r.qtrace[0].sent==0);
    CHECK(diagnostics_after_pass==0);
    /* Length is decided before fake fallback and includes the data stage. */
    memset(&arm,0,sizeof arm);
    calls=0;first_prefix=0;fragment_calls=0;data_calls=0;strategy_calls=0;strategy_mode='N';
    candidate_passed=diagnostics_after_pass=0;length_pass=1;length_calls=0;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(arm.kind==D2K_QA_UDPLEN && arm.strategy==D2K_QS_LENGTH);
    CHECK(length_calls==1 && data_calls==1 && !first_prefix && !fragment_calls);
    CHECK(r.qprops.longer==D2K_PROP_YES && !diagnostics_after_pass);
    memset(&arm,0,sizeof arm);calls=length_calls=length_diagnostics=0;
    candidate_passed=0;arm_second_stalls=1;d2k_quic_arm_data_hook=data_failed;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    CHECK(arm.kind==D2K_QA_NOT_FOUND && arm.longer==D2K_PROP_NO);
    CHECK(length_calls==1 && !length_diagnostics);
    CHECK(r.qprops.longer==D2K_PROP_NO && r.qtrace[5].sent==0);
    arm_second_stalls=0;d2k_quic_arm_data_hook=data_pass;
    length_pass=0;
    /* Оба «нет», фрагменты проходят: план из ответа фрагментации. */
    memset(&arm,0,sizeof arm);
    calls=0;first_prefix=0;fragment_calls=0;data_calls=0;strategy_calls=0;strategy_mode='N';
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},0,&arm);
    /* Круг 1: приманки не перебираются, но вопросы фрагментации задаются;
       стенд пропускает фрагменты — план из ответа. */
    CHECK(arm.kind==D2K_QA_FRAG && arm.strategy==D2K_QS_FRAG && arm.frag_kind==1 &&
          arm.frag_survives==D2K_PROP_YES && !arm.incomplete);
    CHECK(strategy_calls==2 && data_calls==1 && fragment_calls==2 && first_prefix==0);
    CHECK(r.qprops.junk_ahead==D2K_PROP_NO && r.qprops.split_crypto==D2K_PROP_NO);
    CHECK(r.qtrace[0].sent==0 && r.qtrace[1].sent==0);
    strategy_mode='U';
    memset(&arm,0,sizeof arm);
    calls=0;first_prefix=0;lose_base_mark=1;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb, tn, NULL, 0, 0, 0},(d2k_hello){cb, cn, NULL, 0, 0, 0},99,&arm);
    CHECK(!r.marked && arm.kind==D2K_QA_FLAKY);
    lose_base_mark=0; calls=0;
    stall_machine();
    post_handshake_stall();
    flaky_initial_keeps_data_question();
    if(fails)return 1;
    puts("original Run order: passed");return 0;
}
