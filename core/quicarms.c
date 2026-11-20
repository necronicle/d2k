#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "d2k_quic_arms.h"
#include "profiles/quic_arms.h"

static const uint8_t default_blob[620]={0x40};
static const uint8_t zero_blob[16]={0};
/* ИНИЦИАЛ, КОТОРЫЙ КОРОБКА ЧИТАЕТ, А СЕРВЕР ОБЯЗАН ОТБРОСИТЬ.
 *
 * Правило коробки измерено и опубликовано (NTC.Party «Ограничение HTTP/3»,
 * ValdikSS 26.05.2022 и bolvan 27.07.2022): пакет считается QUIC Initial,
 * если длина UDP не меньше 1200, установлен СТАРШИЙ бит первого байта
 * (длинный заголовок) и байты 1…4 как uint32 BE дают версию QUIC. Про
 * ФИКСИРОВАННЫЙ бит (0x40) в правиле нет ничего — bolvan приводит ровно такой
 * пакет, «80 00 00 00 01 00 … 00» на 1200 байт, и он коробкой перехватывается.
 *
 * А сервер обязан отбросить его: RFC 9000 §17.3.1 — пакет с нулевым
 * фиксированным битом не является допустимым пакетом этой версии и ДОЛЖЕН
 * быть отброшен. Значит эта фальшивка читается коробкой как настоящая и при
 * этом не заводит серверу соединения: ни гонки с настоящим Initial клиента,
 * ни нужды топить копию укороченным TTL (а значит и ICMP-риска, поле 04.10,
 * icmpguard). Этим она отличается от quic5/quic_google/quic_rutracker —
 * настоящих перехваченных Initial, которым сервер отвечает (поле 24.10.2026,
 * h3-1024: rutracker.org, nnmclub.to, kinozal.me, lostfilm.tv). */
static const uint8_t nofix_blob[1200]={0x80,0x00,0x00,0x00,0x01};
static const char *names[]={"quic5","quic_google","quic_rutracker","fake_default_quic",
                           "0x00000000000000000000000000000000","quic_initial_nofix"};
const uint8_t *d2k_quic_original_blob(size_t index, size_t *len, const char **name) {
    static const uint8_t *const bytes[]={quic_donor_blob_0,quic_donor_blob_1,quic_donor_blob_2,default_blob,zero_blob,nofix_blob};
    static const size_t sizes[]={sizeof quic_donor_blob_0,sizeof quic_donor_blob_1,sizeof quic_donor_blob_2,sizeof default_blob,sizeof zero_blob,sizeof nofix_blob};
    if(index>=D2K_QUIC_BLOBS || !len) return NULL;
    *len=sizes[index]; if(name) *name=names[index]; return bytes[index];
}

const uint8_t d2k_quic_benign[D2K_QUIC_BENIGN_LEN] = {0};

/* Исход одного опроса: 1 прошло (фильтр 3/3 и этап данных), 0 не прошло.
   *measured — смысл askArms: все попытки ушли, и этап данных (если был)
   состоялся. *retry (может быть NULL) — исход НЕ решающий и спросить ещё
   раз есть на чём: не отправилось, повторы разошлись (1–2 из 3) или этап
   данных не состоялся. Решающий исход — measured без retry. */
/* Ход прогона (задача 49), см. d2k_quicprobe.h. */
d2k_quic_progress_fn d2k_quic_progress_hook = NULL;
d2k_quic_yield_fn d2k_quic_yield_hook = NULL;

static int ask_q(d2k_quic_arm_context *c, d2k_quic_arm *r, d2k_quic_arm_question *q,
                 const char *label, int *measured, int *retry) {
    *measured=0;
    if(retry) *retry=0;
    uint32_t paused_ms=0;
    if(d2k_quic_yield_hook && d2k_quic_yield_hook(&paused_ms)<0) {
        r->incomplete=1; return 0;
    }
    if(paused_ms && c && c->spent)c->spent(c->limit_user,paused_ms);
    q->label=label;
    if(r->n_trace>=D2K_QUIC_ARM_STEPS) { r->incomplete=1; return 0; }
    d2k_quic_arm_step *step=&r->trace[r->n_trace++];
    snprintf(step->label,sizeof step->label,"%s",label);
    if(c && c->can_ask && !c->can_ask(c->limit_user)) {
        r->incomplete=1; step->not_measured=2; return 0;
    }
    if(!c || !c->probe || !c->pool || !c->n_pool || (c->residual && c->next>=c->n_pool)) {
        r->incomplete=1; step->not_measured=1; return 0;
    }
    q->addr=c->pool[c->residual ? c->next++ : 0];
    snprintf(step->addr,sizeof step->addr,"%s",q->addr);
    int sent=0;
    d2k_tally t=c->probe(q,c->user,&sent);
    step->sent=sent; step->answered=t.pass;
    if(sent>0) r->probes+=sent;
    if(sent>0 && d2k_quic_progress_hook) d2k_quic_progress_hook(label,sent); /* задача 49 */
    if(!t.marked) c->marked=0;
    /* Unsent/local failures are not negative network observations. An
       ECONNREFUSED refusal (probe.go:643/663) is not err (quic_ask_ex counts
       it as fail): donor measure probe.go:573-574 keeps Refused out of
       NotBuilt, so askArms.ask
       (arms.go:69-94) treats the question as asked and not passed. */
    if(sent!=D2K_QUIC_REPEATS || t.err>0) {
        r->incomplete=1; step->not_measured=3; if(retry) *retry=1; return 0;
    }
    *measured=1;
    if(t.pass!=D2K_QUIC_REPEATS) {
        /* 0/3 — решающее «нет»; 1–2 из 3 — повторы разошлись. */
        if(t.pass>0 && retry) *retry=1;
        return 0;
    }
    /* Fragment survival is a reachability control on a neutral name, not an
       arm; its answer is the original question. */
    if(q->control || !c->data) return 1;
    /* Task 39: the cheap filter passed; the arm counts only if real
       application data flows after a handshake with the same action. */
    struct timespec t0,t1;
    clock_gettime(CLOCK_MONOTONIC,&t0);
    q->need_complete=c->need_complete;
    q->budget_pk=c->budget_pk;
    d2k_quic_arm_data d=c->data(q,c->data_user);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    if(c->spent) {
        int64_t ms=(int64_t)(t1.tv_sec-t0.tv_sec)*1000+(t1.tv_nsec-t0.tv_nsec)/1000000L;
        c->spent(c->limit_user,ms>0?(uint32_t)ms:0u);
    }
    step->data=(int)d.verdict; step->data_bytes=d.app_bytes;
    /* Измеренное направление обрыва идёт в трассу шага: иначе единственный
       измеряемый признак этого класса в журнале не виден вовсе (d.reason
       сюда не попадает). Направление стоит ПЕРВЫМ и граница заметки задана
       явно: буферы одного размера, и «%s%s» и усекло бы хвост, и дало бы
       -Werror=format-truncation у mipsel-gcc (поймано cross-runtime-gates). */
    if (d.oneway) {
        static const char head[] = "наше исходящее заглушено; ";
        snprintf(step->data_note,sizeof step->data_note,"%s%.*s",head,
                 (int)(sizeof step->data_note - sizeof head),d.note);
    } else {
        snprintf(step->data_note,sizeof step->data_note,"%s",d.note);
    }
    if(d.verdict==D2K_QAD_PASS) return 1;
    if(d.verdict==D2K_QAD_NOT_RUN) {
        r->incomplete=1; step->not_measured=3; *measured=0; if(retry) *retry=1;
    }
    return 0;
}

static int ask(d2k_quic_arm_context *c, d2k_quic_arm *r, int blob, int copies,
               int ttl, int frag, int control, int *measured);

/* Вопросы IP-фрагментации askArms: выживание на контроле, затем формы. Это
   вопросы замера, а не перебор приманок — их задаёт и стратегия, когда оба
   её ответа «нет» (задача 40, круг 1). */
static void ask_frag(d2k_quic_arm_context *c, d2k_quic_arm *r) {
    int measured=0;
    int survived=ask(c,r,-1,0,0,1,1,&measured);
    if(measured) {
        r->frag_survives=survived?D2K_PROP_YES:D2K_PROP_NO;
        if(survived) for(int shape=1;shape<=4;shape++) {
            if(ask(c,r,-1,0,0,shape,0,&measured)) { r->frag_kind=shape; break; }
        }
    }
}

/* Direct port of askArms.ask + addrPool.take. Never demand a second IP when
 * the already measured residual policy says to remain on the pinned address. */
static int ask(d2k_quic_arm_context *c, d2k_quic_arm *r, int blob, int copies,
               int ttl, int frag, int control, int *measured) {
    d2k_quic_arm_question q={0};
    q.copies=copies; q.ttl=ttl; q.frag=frag; q.control=control;
    const char *name="";
    if(blob>=0) q.blob=d2k_quic_original_blob((size_t)blob,&q.blob_len,&name);
    char label[192];
    static const char *frags[]={"", "ipfrag pos=8", "ipfrag pos=8 обратный порядок",
                               "z2k_ipfrag3_tiny", "z2k_ipfrag3"};
    if(control) snprintf(label,sizeof label,"фрагменты доходят вообще (контрольное имя)");
    else if(frag) snprintf(label,sizeof label,"фрагментация: %s",frags[frag]);
    else if(ttl) snprintf(label,sizeof label,"фальшивка %s с TTL %d",name,ttl);
    else if(copies>1) snprintf(label,sizeof label,"фальшивка %s ×%d",name,copies);
    else snprintf(label,sizeof label,"фальшивка %s",name);
    return ask_q(c,r,&q,label,measured,NULL);
}

d2k_quic_arm d2k_quic_original_arms(d2k_quic_arm_context *c) {
    d2k_quic_arm r; memset(&r,0,sizeof r); r.kind=D2K_QA_NOT_FOUND; r.original=1;
    int chosen=-1, measured=0;
    /* 1. Intrinsic fakes, донорский порядок, затем наша гипотеза
       quic_initial_nofix — ПОСЛЕДНЕЙ. Поле 25.10.2026 (h3e-1): на этой линии
       она дала 0/3 по семи целям и 1/3 по восьмой — коробка за Initial с
       погашенным фиксированным битом настоящий Initial не пропускает. Вопрос
       оставлен (на другой коробке правило может отличаться), но стоит в конце:
       когда донорская приманка работает, он не стоит ни одного зонда. */
    static const int step1[D2K_QUIC_BLOBS]={0,1,2,3,4,5};
    for(int i=0;i<D2K_QUIC_BLOBS;i++) {
        int b=step1[i];
        /* 0x00…0 ×1 — ровно вопрос «остаточное разрешение»; на него уже есть
           решающее «нет» (задача 40), второй раз он исхода не изменит. */
        if(b==4 && c && c->benign_answered) continue;
        if(ask(c,&r,b,1,0,0,0,&measured)) { chosen=b; r.copies=1; goto selected; }
    }
    /* 2. Single copies failed: quic5 then fake_default_quic with repeats. */
    const int candidates[2]={0,3};
    const int repeats[]={D2K_QUIC_COPIES_A,D2K_QUIC_COPIES_B};
    for(int i=0;i<2;i++) for(size_t j=0;j<2;j++) {
        if(ask(c,&r,candidates[i],repeats[j],0,0,0,&measured)) {
            chosen=candidates[i]; r.copies=repeats[j]; goto selected;
        }
        /* Field e/f: fake_default x11 gets bound replies but not a usable
           connection. Plain split failed. Ask their product only on this
           measured contrast, never launch a Cartesian sweep. */
        if(c && c->split_failed && !c->no_split && candidates[i]==3 && repeats[j]==D2K_QUIC_COPIES_B &&
           r.n_trace && r.trace[r.n_trace-1].answered>0 &&
           ((r.trace[r.n_trace-1].answered<D2K_QUIC_REPEATS && !r.trace[r.n_trace-1].not_measured) ||
            r.trace[r.n_trace-1].data==D2K_QAD_CUT ||
            r.trace[r.n_trace-1].data==D2K_QAD_NO_HANDSHAKE)) {
            d2k_quic_arm_question q={.copies=D2K_QUIC_COPIES_B,.split=1};
            const char *name;
            char label[160]; /* кириллица — 2 байта на знак; с запасом под %d */
            q.blob=d2k_quic_original_blob(3,&q.blob_len,&name);
            /* Число копий печатается ИЗ константы, а не повторяется цифрой в
               тексте: иначе правка лестницы молча оставила бы в журнале
               неверное число — читающий поле сверяет вопрос по этой строке. */
            snprintf(label,sizeof label,
                     "частичный ответ на приманку: fake_default ×%d вместе с разрезом CRYPTO",
                     D2K_QUIC_COPIES_B);
            if(ask_q(c,&r,&q,label,&measured,NULL)) {
                r.kind=c->marked?D2K_QA_SPLIT:D2K_QA_FLAKY;
                r.strategy=D2K_QS_FAKE_SPLIT; r.copies=D2K_QUIC_COPIES_B; r.len=q.blob_len;
                memcpy(r.bytes,q.blob,q.blob_len);
                snprintf(r.blob_name,sizeof r.blob_name,"%s",name);
                snprintf(r.reason,sizeof r.reason,
                         "приманка ×%d и разрез вместе: фильтр 3/3 и этап данных прошли",
                         D2K_QUIC_COPIES_B);
                return r;
            }
        }
    }
    /* 3. No complete fake/repeat candidate: measure quic5 x2 with TTL. */
    int decoy=0;
    int ttl_copies=2;
    const int ttls[]={3,5,8,12};
    for(size_t i=0;i<4;i++) {
        if(c && c->ttl_pair_answered && decoy==0 && ttl_copies==2 && ttls[i]==3) continue;
        if(ask(c,&r,decoy,ttl_copies,ttls[i],0,0,&measured)) {
        chosen=decoy; r.copies=ttl_copies; r.ttl=ttls[i]; goto selected;
        }
    }
    /* 4. Survival on control precedes every fragmentation arm. Уже заданные
       стратегией (оба её ответа «нет») вопросы фрагментации не повторяются:
       их исход тот же, и он уже в трассе. */
    if(!(c && c->frag_answered)) ask_frag(c,&r);
selected:
    /* A complete measured candidate ends search (§0.1). Later axes neither
       strengthen this exact action nor justify changing its wire program. */
    if(chosen>=0) {
        const char *name="";
        const uint8_t *blob=d2k_quic_original_blob((size_t)chosen,&r.len,&name);
        memcpy(r.bytes,blob,r.len); snprintf(r.blob_name,sizeof r.blob_name,"%s",name);
        /* Fragment-only questions did not measure fake+fragment together. */
        r.frag_kind=0;
        r.kind=r.ttl?D2K_QA_TTL:D2K_QA_COPIES;
    } else if(r.frag_kind) r.kind=D2K_QA_FRAG;
    if(c && !c->marked) r.kind=D2K_QA_FLAKY;
    snprintf(r.reason,sizeof r.reason,"original askArms: %s copies=%d ttl=%d frag=%d%s",
             chosen>=0?r.blob_name:"no fake",r.copies,r.ttl,r.frag_kind,
             r.incomplete?"; incomplete questions":"");
    return r;
}

/* ---------------------------------------------------------------------
 * СТРАТЕГИЯ ИЗ ОТВЕТОВ (задача 40) — см. d2k_quic_arms.h.
 * --------------------------------------------------------------------- */

/* Один вопрос стратегии: до одного повтора, пока исход не решающий.
   Возвращает D2K_PROP_YES/NO или UNKNOWN (ответа нет). */
static int8_t strategy_ask(d2k_quic_arm_context *c, d2k_quic_arm *r,
                           const d2k_quic_arm_question *shape, const char *label,
                           int8_t *asked) {
    for(int attempt=0;attempt<2;attempt++) {
        d2k_quic_arm_question q=*shape;
        int measured=0, retry=0;
        int ok=ask_q(c,r,&q,label,&measured,&retry);
        /* Дошёл до провода (адрес и бюджет были) — вопрос задан. */
        if(r->n_trace && r->trace[r->n_trace-1].not_measured!=1 &&
           r->trace[r->n_trace-1].not_measured!=2) *asked=1;
        if(ok) return D2K_PROP_YES;
        if(measured && !retry) return D2K_PROP_NO;
        if(!retry) break; /* адрес или бюджет кончились — повтор не на чем */
    }
    return D2K_PROP_UNKNOWN;
}

static const char *prop_word(int8_t v) {
    return v==D2K_PROP_YES ? "прошло" : v==D2K_PROP_NO ? "не прошло" : "ответа нет";
}

d2k_quic_arm d2k_quic_strategy_arms(d2k_quic_arm_context *c) {
    d2k_quic_arm r; memset(&r,0,sizeof r);
    r.kind=D2K_QA_NOT_FOUND; r.original=1; r.strategy=D2K_QS_NONE;
    r.clearance=D2K_PROP_UNKNOWN; r.split_crypto=D2K_PROP_UNKNOWN;
    r.longer=D2K_PROP_UNKNOWN;

    int8_t ttl_asked=0;
    int8_t ttl_answer=D2K_PROP_UNKNOWN;
    if(c && c->need_complete && c->budget_pk) {
        d2k_quic_arm_question q={.copies=2,.ttl=3};
        const char *name;
        q.blob=d2k_quic_original_blob(0,&q.blob_len,&name);
        if((ttl_answer=strategy_ask(c,&r,&q,
            "срок жизни после Initial: quic5 ×2 с TTL 3 перед приветствием",
            &ttl_asked))==D2K_PROP_YES) {
            memcpy(r.bytes,q.blob,q.blob_len); r.len=q.blob_len;
            snprintf(r.blob_name,sizeof r.blob_name,"%s",name);
            r.copies=2; r.ttl=3; r.kind=c->marked?D2K_QA_TTL:D2K_QA_FLAKY;
            r.strategy=D2K_QS_TTL_LIFETIME; r.incomplete=0;
            snprintf(r.reason,sizeof r.reason,
                "пост-рукопожатный обрыв снят: quic5 ×2 TTL3; полный ответ и бюджет данных прошли");
            return r;
        }
    }

    d2k_quic_arm_question benign={0};
    benign.blob=d2k_quic_benign; benign.blob_len=D2K_QUIC_BENIGN_LEN;
    benign.copies=1; benign.benign=1;
    r.clearance=strategy_ask(c,&r,&benign,
        "остаточное разрешение: безобидная датаграмма первой, затем Initial",
        &r.clearance_asked);
    if(r.clearance==D2K_PROP_YES) {
        memcpy(r.bytes,d2k_quic_benign,D2K_QUIC_BENIGN_LEN);
        r.len=D2K_QUIC_BENIGN_LEN;
        snprintf(r.blob_name,sizeof r.blob_name,"benign16");
        r.copies=1; r.kind=D2K_QA_BLOB; r.strategy=D2K_QS_CLEARANCE;
        r.incomplete=0; /* решающий ответ получен: прежний неустойчивый опрос — не пробел */
        snprintf(r.reason,sizeof r.reason,
                 "остаточное разрешение: одна безобидная датаграмма (%u нулевых байт) перед Initial",
                 (unsigned)D2K_QUIC_BENIGN_LEN);
    } else {
        d2k_quic_arm_question split={0};
        split.split=1;
        /* Финальное ревью core, I1: клиенту, чей ClientHello шире
           датаграммы, разрез CRYPTO не исполнится (датапат отказывает: имени
           нет в датаграмме). Ответ этого вопроса планом стать не может, и
           вопрос не задаётся; для выбора пути он считается «нет». */
        int no_split = c && c->no_split;
        if(!no_split)
            r.split_crypto=strategy_ask(c,&r,&split,"ClientHello двумя кадрами CRYPTO, хвост первым",
                                        &r.split_asked);
        if(r.split_crypto==D2K_PROP_YES) {
            r.kind=D2K_QA_SPLIT; r.strategy=D2K_QS_SPLIT; r.incomplete=0;
            snprintf(r.reason,sizeof r.reason,
                     "разрез ClientHello на два кадра CRYPTO проходит (остаточное разрешение: %s)",
                     prop_word(r.clearance));
        } else {
            /* Length is an independent one-datagram question, not a fake
               product. It used to run only after the entire fallback ladder
               and without the data-stage criterion. */
            d2k_quic_arm_question length={.udplen=D2K_QUIC_LENGTH_INCREMENT};
            r.longer=strategy_ask(c,&r,&length,
                "длина UDP: 100 нулевых байт после неизменённого Initial",&r.longer_asked);
            if(r.longer==D2K_PROP_YES) {
                r.kind=c->marked?D2K_QA_UDPLEN:D2K_QA_FLAKY;
                r.strategy=D2K_QS_LENGTH;r.udplen=length.udplen;r.incomplete=0;
                snprintf(r.reason,sizeof r.reason,
                    "удлинение UDP на 100 байт: фильтр 3/3 и тот же этап данных прошли");
                return r;
            }
            /* Оба «нет» — вопросы IP-фрагментации задаются (круг 1); форма,
               что прошла, и есть план. Не прошла ни одна — перебор приманок
               askArms. Прежде (задача 40) он здесь не запускался: «нет» на
               безобидную датаграмму и на разрез читалось как «приманки
               бесполезны». Поле это опровергло: rutracker.org 04.10 — 0/3,
               0/3, фрагменты 0/3, «обход по QUIC не найден», а на том же
               имени 02.10 fake_default_quic ×11 прошла 3/3, и её план
               389a3920 отдаёт ответы целиком 4/4 (task-55-facts §2). Ответы
               стратегии говорят о безобидной датаграмме и о разрезе, не о
               фальшивом Initial. */
            int both_no=r.clearance==D2K_PROP_NO && (r.split_crypto==D2K_PROP_NO || no_split);
            if(both_no) {
                /* Definitive benign/split replies resolve their retries, but
                   cannot resolve an unanswered independent length question. */
                r.incomplete=r.longer==D2K_PROP_UNKNOWN ||
                    (ttl_asked && ttl_answer==D2K_PROP_UNKNOWN);
                ask_frag(c,&r);
                if(r.frag_kind) {
                    r.kind=D2K_QA_FRAG; r.strategy=D2K_QS_FRAG; r.incomplete=0;
                    snprintf(r.reason,sizeof r.reason,
                             "разрешение не прошло, разрез CRYPTO %s; IP-фрагментация формы %d прошла "
                             "(приманки не перебирались)",
                             no_split ? "клиенту неприменим (ClientHello шире датаграммы)" : "не прошёл",
                             r.frag_kind);
                    if(c && !c->marked) r.kind=D2K_QA_FLAKY;
                    return r;
                }
            }
            /* Запасной путь — перебор приманок оригинала: и при неизмеримом
               ответе, и после двух «нет». */
            int strategy_incomplete=r.incomplete;
            d2k_quic_arm_context local=*c;
            local.benign_answered=r.clearance_asked;
            local.frag_answered=both_no;
            local.ttl_pair_answered=ttl_answer==D2K_PROP_NO;
            local.split_failed=r.split_crypto==D2K_PROP_NO;
            d2k_quic_arm l=d2k_quic_original_arms(&local);
            c->next=local.next; c->marked=local.marked;
            size_t head=r.n_trace;
            int probes=r.probes;
            int8_t cl=r.clearance, sp=r.split_crypto, lng=r.longer;
            int8_t cla=r.clearance_asked, spa=r.split_asked, lnga=r.longer_asked;
            int8_t fs=r.frag_survives;
            d2k_quic_arm_step steps[D2K_QUIC_ARM_STEPS];
            memcpy(steps,r.trace,head*sizeof steps[0]);
            r=l;
            size_t room=D2K_QUIC_ARM_STEPS-head;
            size_t take=l.n_trace<room?l.n_trace:room;
            memmove(r.trace+head,l.trace,take*sizeof r.trace[0]);
            memcpy(r.trace,steps,head*sizeof steps[0]);
            r.n_trace=head+take;
            r.probes+=probes;
            r.clearance=cl; r.split_crypto=sp;
            r.clearance_asked=cla; r.split_asked=spa;
            r.longer=lng;r.longer_asked=lnga;
            if(both_no) r.frag_survives=fs;
            r.strategy=l.strategy==D2K_QS_FAKE_SPLIT ? l.strategy : D2K_QS_LADDER;
            r.incomplete=r.incomplete||strategy_incomplete||take<l.n_trace;
            /* Причина перебора — его собственная строка, урезанная так,
               чтобы вместе с заголовком влезть в r.reason. */
            if(r.strategy==D2K_QS_FAKE_SPLIT) {
                snprintf(r.reason,sizeof r.reason,"%s",l.reason);
            } else if(both_no) {
                const char *fw = fs==D2K_PROP_NO ? "фрагм. не доживают" :
                                 fs==D2K_PROP_YES ? "фрагм. не прошли" : "фрагм. не измерены";
                snprintf(r.reason,sizeof r.reason,
                         "разрешение: нет, разрез CRYPTO: %s, %s — перебор приманок: %.90s",
                         no_split ? "неприменим" : "нет", fw, l.reason);
            } else {
                snprintf(r.reason,sizeof r.reason,
                         "ответа нет (разрешение: %s, разрез CRYPTO: %s) — запасной перебор: %.90s",
                         prop_word(cl),prop_word(sp),l.reason);
            }
            return r;
        }
    }
    if(c && !c->marked) r.kind=D2K_QA_FLAKY;
    return r;
}
