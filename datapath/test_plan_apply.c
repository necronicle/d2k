/* test_plan_apply.c — проверки применения плана.
 *
 * Список посылок содержит ТОЛЬКО то, что порождаем мы. Судьба оригинала —
 * отдельное поле, а не ещё одна строка в списке: иначе «пропустить оригинал» и
 * «выпустить его копию» стали бы неразличимы, и пакет ушёл бы дважды.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_plan.h"
/* Полное определение потока живёт здесь: d2k_plan.h объявляет тип
   опережающе, и одного его для переменной по значению не хватает. */
#include "d2k_track.h"
/* Потолок посылок в результате — проверяем, что самое длинное плечо донора
   в него помещается: число и плечо обязаны сходиться в одном месте. */
#include "d2k_session.h"
/* UDP length/checksum of the lengthened datagram are checked on the real
   wire builder, not on the emit fields alone. */
#include "d2k_wire.h"
/* Task 40: the split executor is the core function the question used. */
#include "d2k_quic.h"
#include "../core/test_quic_vector.h"
#include "../core/test_quic_pq.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* REC_FAKE minexec=8 carries native TLS rnd+dupsid modifiers. */
static void put16(uint8_t *b, size_t *n, uint16_t v) {
    b[(*n)++] = (uint8_t)(v >> 8); b[(*n)++] = (uint8_t)v;
}
static void putrec(uint8_t *b, size_t *n, uint16_t type,
                   const uint8_t *v, uint16_t len) {
    put16(b, n, type); put16(b, n, len);
    if (len) { memcpy(b + *n, v, len); } /* пустая запись: v == NULL */
    *n += len;
}
static size_t tls_fake_plan(uint8_t *plan) {
    uint8_t hello[87] = {0};
    size_t n = 0;
    hello[0]=0x16; hello[1]=3; hello[2]=1; hello[3]=0; hello[4]=82;
    hello[5]=1; hello[6]=0; hello[7]=0; hello[8]=78;
    hello[9]=3; hello[10]=3;
    for (size_t i=0; i<32; i++) hello[11+i]=(uint8_t)(0x40+i);
    hello[43]=32;
    for (size_t i=0; i<32; i++) hello[44+i]=(uint8_t)(0x80+i);
    hello[76]=0; hello[77]=2; hello[78]=0x13; hello[79]=1;
    hello[80]=1; hello[81]=0; hello[82]=0; hello[83]=0;
    memcpy(plan, "D2KP", 4); plan[4]=0; plan[5]=1; plan[6]=0; plan[7]=8;
    plan[8]=0; plan[9]=0; plan[10]=0; plan[11]=7; n=12;
    uint8_t id[16]={0}; putrec(plan,&n,0x0001,id,sizeof id);
    uint8_t proto[2]={6,1}; putrec(plan,&n,0x0002,proto,sizeof proto);
    uint8_t payload[89]={0}; payload[1]=1; memcpy(payload+2,hello,sizeof hello);
    putrec(plan,&n,0x0010,payload,sizeof payload);
    uint8_t poison[8]={0,1,0,2,0,0,0,0}; putrec(plan,&n,0x0011,poison,8);
    uint8_t fake[11]={0,1,0,1,1,0,0,0,0,0,3}; putrec(plan,&n,0x0101,fake,11);
    uint8_t order=0; putrec(plan,&n,0x0103,&order,1);
    putrec(plan,&n,0x010a,NULL,0);
    return n;
}

static void test_tls_fake_modifiers(void) {
    uint8_t plan[256], client[87]={0};
    size_t plan_len=tls_fake_plan(plan);
    d2k_plan *p=NULL; d2k_actions a={0}; d2k_pkt in={0};
    d2k_flow flow={0}; char err[160];
    client[0]=0x16;client[1]=3;client[2]=1;client[3]=0;client[4]=82;
    client[5]=1;client[6]=0;client[7]=0;client[8]=78;client[9]=3;client[10]=3;
    for(size_t i=0;i<32;i++)client[11+i]=(uint8_t)(0x10+i);
    client[43]=32;
    for(size_t i=0;i<32;i++)client[44+i]=(uint8_t)(0xc0+i);
    client[76]=0;client[77]=2;client[78]=0x13;client[79]=1;
    client[80]=1;client[81]=0;client[82]=0;client[83]=0;
    int load_rc=d2k_plan_load(plan,plan_len,&p,err,sizeof err);
    if(load_rc!=0)printf("TLS modifier plan rejected: %s\n",err);
    CHECK(load_rc==0,"TLS modifiers plan should parse at exec 8");
    if(!p)return;
    in.payload=client;in.payload_len=sizeof client;in.seq=100;
    in.have_sni=1;in.sni_off=20;in.sni_len=8;in.is_tls13=1;
    CHECK(d2k_plan_apply(p,&flow,&in,&a)==0,"TLS modifier plan should apply");
    CHECK(a.n==1,"TLS modifier plan should emit one fake");
    if(a.n==1) {
        CHECK(a.v[0].len==sizeof client,"modified fake keeps template length");
        CHECK(memcmp(a.v[0].bytes+11,client+11,32)!=0,
              "rnd changes fake ClientHello random");
        CHECK(memcmp(a.v[0].bytes+44,client+44,32)==0,
              "dupsid copies the live ClientHello session ID");
    }
    d2k_actions_free(&a);
    in.is_tls13=0;
    CHECK(d2k_plan_apply(p,&flow,&in,&a)!=0,
          "TLS modifiers reject non-TLS-1.3 input");
    CHECK(a.refuse_why && strstr(a.refuse_why, "TLS 1.3"),
          "отказ по форме назван: правка просит TLS 1.3");
    d2k_plan_free(p);
}

/* ПРИЧИНА ОТКАЗА — НЕ УКРАШЕНИЕ ЖУРНАЛА. Поле 13.10.2026,
   forum.ru-board.com: исполнитель отказал 10 раз за 15 минут обобщённым
   «план неприменим к этому пакету», зонд ушёл голым, коробка его срезала, и
   контроллер записал НАШ отказ в вину кандидату — рабочий приём (плотная
   серия с битой суммой, три ServerHello на проводе) был выброшен. Отличить
   «коробка срезала» от «мы сами не применили» можно только по названной
   причине, поэтому молчащий отказ здесь — провал теста. */
static void test_refusal_names_reason(void) {
    uint8_t plan[256];
    size_t plan_len = tls_fake_plan(plan);
    d2k_plan *p = NULL; char err[160];
    if (d2k_plan_load(plan, plan_len, &p, err, sizeof err) != 0 || !p) {
        CHECK(0, "план причин не разобран");
        return;
    }
    uint8_t hello[87] = {0};
    hello[0]=0x16;hello[1]=3;hello[2]=1;hello[3]=0;hello[4]=82;
    hello[5]=1;hello[6]=0;hello[7]=0;hello[8]=78;hello[9]=3;hello[10]=3;
    for (size_t i=0;i<32;i++) hello[11+i]=(uint8_t)(0x10+i);
    hello[43]=32;
    for (size_t i=0;i<32;i++) hello[44+i]=(uint8_t)(0xc0+i);
    hello[76]=0;hello[77]=2;hello[78]=0x13;hello[79]=1;
    hello[80]=1;hello[81]=0;hello[82]=0;hello[83]=0;
    uint8_t junk[64];
    memset(junk, 0xab, sizeof junk);

    struct { const char *what; d2k_pkt in; } cases[] = {
        /* нагрузки нет */
        { "пустая нагрузка", (d2k_pkt){0} },
        /* не ClientHello: правка приветствия не соберётся */
        { "не приветствие", (d2k_pkt){ .payload = junk, .payload_len = sizeof junk,
                                       .is_tls13 = 1, .seq = 1 } },
        /* форма не та */
        { "форма не TLS 1.3", (d2k_pkt){ .payload = hello, .payload_len = sizeof hello,
                                         .is_tls13 = 0, .seq = 1 } },
        /* план не для запроса HTTP */
        { "запрос HTTP", (d2k_pkt){ .payload = hello, .payload_len = sizeof hello,
                                    .is_tls13 = 1, .is_http = 1, .seq = 1 } },
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        d2k_actions a = {0};
        int rc = d2k_plan_apply(p, NULL, &cases[i].in, &a);
        CHECK(rc != 0, cases[i].what);
        CHECK(a.refuse_why != NULL && a.refuse_why[0] != '\0',
              "отказ исполнителя обязан называть причину");
        if (rc != 0 && !a.refuse_why) {
            printf("  молчащий отказ: %s\n", cases[i].what);
        }
        CHECK(a.n == 0, "при отказе посылок нет");
        d2k_actions_free(&a);
    }
    d2k_plan_free(p);
}

/* Фальшивка перед всеми кусками, две копии с паузой 78 мс — ровно то, чем
   обходится боевое плечо донора. Байты собраны здесь, а не подсунуты внешним
   символом: тест не должен зависеть от порядка сборки. */
static const uint8_t plan_fake_before[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 4,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* РАЗРЕЗ ЗА ПРЕДЕЛАМИ СЕГМЕНТА. Один разрез, ANCHOR_PAYLOAD_START
   (anchor=0) со смещением 1500 (0x05DC) — то есть измеренный на приветствии,
   которое целиком уместилось в один сегмент. Нужен для одной проверки: на
   более коротких пришедших байтах такой план обязан быть ОТВЕРГНУТ, а не
   исполнен без своего разреза. */
static const uint8_t plan_split_far[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x05, 0xDC,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Разрез по началу SNI и ничего больше. */
static const uint8_t plan_split_sni[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Тот же разрез по SNI, но вход объявлен приветствием TLS (REC_INPUT_TLS,
   0x010a, пустое тело). Такой план требователен ко входу — на нём и
   проверяется, что первый сегмент составного приветствия входом считается. */
static const uint8_t plan_split_sni_tls[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 5, 0, 0, 0, 4,
    0x00, 0x02, 0x00, 0x02, 0x06, 0x01,
    0x01, 0x0a, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Измеренное плечо URG: сервер вынимает вставленный байт из потока,
   DPI может оставить его. Якорь — середина имени текущего TLS-входа. */
static const uint8_t plan_oob_sni[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 8, 0, 0, 0, 5,
    0x00, 0x02, 0x00, 0x02, 0x06, 0x01,
    0x01, 0x09, 0x00, 0x01, 0x01,
    0x01, 0x0a, 0x00, 0x00,
    0x01, 0x0d, 0x00, 0x03, 0x00, 0x05, 0x0f,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* ВЫДЕРЖКА ПЕРЕД ЕДИНСТВЕННОЙ ПОСЫЛКОЙ (REC_DELAY = 0x010b, minexec=6).
 *
 * pace задерживает посылки ПОСЛЕ первой, settle — первую, но только когда
 * перед ней что-то стоит (фальшивка). Одну-единственную посылку задержать
 * было нечем, а именно это и нужно, чтобы развести во времени датаграммы
 * одного QUIC-приветствия (поле 19.09.2026). */
static const uint8_t plan_delay[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 6, 0, 0, 0, 1,
    0x01, 0x0b, 0x00, 0x04, 0x00, 0x00, 0x3a, 0x98   /* delay 15000 мкс */
};

/* Фальшивка МЕЖДУ кусками, но разрезов в плане нет: класть её некуда. */
static const uint8_t plan_between_no_split[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 3,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0xAA,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01,
                            0, 0, 0, 0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Перекрытие: приставка в два байта, разрезов нет. Ответ на коробку, которая
   ПЕРЕСОБИРАЕТ поток — разрез её не берёт, а склейку отравить можно. */
static const uint8_t plan_seqovl[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 3,
    0x00, 0x10, 0x00, 0x04, 0x00, 0x01, 0xAA, 0xBB,
    0x01, 0x02, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Перекрытие вместе с разрезом по началу имени. */
static const uint8_t plan_seqovl_split[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 4,
    0x00, 0x10, 0x00, 0x04, 0x00, 0x01, 0xAA, 0xBB,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Тот же разрез по началу SNI, что и plan_split_sni, но с обратным порядком
   отправки: хвост приветствия обязан уйти раньше головы, а номера
   последовательности — остаться при своих кусках (переставляется ОТПРАВКА,
   а не содержимое). */
static const uint8_t plan_split_reverse[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x01
};

/* Фальшивка ПЕРЕД нагрузкой вместе с обратным порядком: она обязана остаться
   первой, а перевёрнутыми уходят только куски позади неё. */
static const uint8_t plan_fake_before_reverse[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 4,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0xAA,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
                            0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x01
};

/* Фальшивка МЕЖДУ кусками вместе с обратным порядком: она стоит ВНУТРИ
   диапазона нагрузки, и диапазонный переворот утащил бы её вместе с
   кусками, хотя обязана остаться на своей позиции. */
static const uint8_t plan_between_reverse[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 4,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0xAA,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01,
                            0x00, 0x00, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x01
};

/* Перекрытие без разреза вместе с обратным порядком: кусок ровно один, и
   переворачивать нечего. У старого кода `j - 1` в условии цикла считался ДО
   проверки `j >= 1`: на пустом диапазоне (hi == lo == 0) это уходит в
   беззнаковое переполнение и пишет за пределы массива посылок. Здесь диапазон
   не пуст (один кусок, hi=1, lo=0) — переполнение зависело бы ещё и от того,
   куда лягут указатели фальшивок, а тут их вовсе нет, — но именно для
   одного/нулевого куска у старой защиты не было, и новый цикл обязан пройти
   этот случай без единой итерации сам по себе. */
static const uint8_t plan_seqovl_reverse[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 3,
    0x00, 0x10, 0x00, 0x04, 0x00, 0x01, 0xAA, 0xBB,
    0x01, 0x02, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x01
};

/* Полная связка: перекрытие + два разреза (единица и середина имени) +
   фальшивка перед нагрузкой + обратный порядок — те же четыре ингредиента,
   что в everythingPlan (internal/classify/properties.go), с упрощённым
   repeats=1 вместо 2 (счёт копий проверяется другим тестом и к перевороту
   отношения не имеет). До задачи reorder-cut здесь стоял один разрез по
   ANCHOR_SNI_START — тоже упрощение (выбор якоря был не тем, что
   проверяется здесь). После неё everythingPlan сам режет ДВУМЯ разрезами
   ({AnchorPayloadStart+1, AnchorSNIMiddle}, см. properties.go) — та же
   пара, что у reorderPlan, — и фикстура обязана нести ту же форму: иначе
   она проверяла бы связку, которой прод больше не строит. Предыдущие
   четыре теста в этом файле берут связку только попарно (фальшивка+разрез+
   обратный порядок БЕЗ перекрытия, перекрытие+обратный порядок БЕЗ разреза
   и фальшивки).

   У everythingPlan есть отдельная проверка через planlab
   (TestЛабораторияВсёСразуИсполняетТриПриёмаВместе, properties_test.go) —
   она гоняет ТОЧНЫЙ прод-план и ловит расхождение кодов записей между Go
   и C. Этот тест — её дополнение, не замена: planlab запускается внешним
   процессом и до правки datapath/Makefile не пересобирался ни под
   санитайзерами, ни под кросс-компиляторами, а именно эту связку раньше
   не проверял на C напрямую никто. */
static const uint8_t plan_everything_reverse[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 7,
    0x00, 0x10, 0x00, 0x04, 0x00, 0x01, 0xAA, 0xBB,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x02, 0xDD,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00,
                            0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x01
};

/* ДВА РЕЗА И ФАЛЬШИВКА МЕЖДУ КУСКАМИ — та самая пара, на которой исполнитель
   писал за границу выделенного массива.

   Верхняя оценка числа посылок считалась так, будто фальшивка «между
   кусками» выпускается ОДИН раз, а выпускается она в КАЖДЫЙ разрез. С одним
   разрезом оценка совпадала со счётом случайно (один разрез — одно место), и
   ни один прежний тест здесь не ставил двух разрезов вместе с такой
   фальшивкой. На живом стенде 13.09.2026 план с двумя разрезами и двумя
   копиями фальшивки уронил датапат: `malloc(): corrupted top size`.

   Два реза (единица и середина имени) дают три куска и ДВА места для
   фальшивки; две копии в каждом — четыре фальшивки. Итого семь посылок при
   прежней оценке в пять. */
static const uint8_t plan_between_two_splits[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 5,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0xAA,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01,
                            0x00, 0x00, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* То же самое с семью копиями — БУКВАЛЬНО плечо донора `fakedsplit-x7`
   (core/compose.c, g_fb_head: badsum=1, repeats=7, between=1). Составитель
   выдаёт для него два разреза и фальшивку «между кусками», то есть три
   куска и 2*7 фальшивок — семнадцать посылок. Ровно на нём датапат и падал,
   и ровно оно упирается в потолок d2k_result.out[]. */
static const uint8_t plan_fakedsplit_x7[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 5,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0xAA,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x07, 0x01,
                            0x00, 0x00, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Разрез по середине ИМЕНИ (ANCHOR_SNI_MIDDLE = 5), а не по середине пакета.
   Задача reorder-cut: боевое плечо донора режет на midsld — середине домена
   второго уровня, а не на n/2 (z2k-detect/internal/classify/raw_linux.go:
   667-690). Анкор здесь сырой числовой байт 0x05, а не символ из
   plan_internal.h: тест собирает канонический TLV напрямую, как и остальные
   планы в этом файле, и обязан отличать «якорь не разрешился» от «датапат
   его вовсе не знает» — оба случая обязаны вести себя одинаково (отказ), но
   первое проверяется реальным разбором, а не догадкой о числе. */
static const uint8_t plan_split_sni_middle[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Два реза — единица и середина имени — с обратным порядком. Ровно то, чем
   reorderPlan (internal/classify/properties.go) обязан отвечать на вопрос
   «порядок сегментов» после фикса: резы в 1 и mid дают куски [0,1), [1,mid),
   [mid,n), а обратный порядок кладёт их на провод как [mid,n), [1,mid),
   [0,1) — донорская последовательность (seq 268:344, затем 2:268, затем 1:2,
   первый байт последним). */
static const uint8_t plan_reorder_by_name[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 3,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00,
    0x01, 0x03, 0x00, 0x01, 0x01
};

static uint8_t hello[64];

static void init_pkt(d2k_pkt *in, int have_sni) {
    memset(in, 0, sizeof *in);
    memset(hello, 0xCC, sizeof hello);
    in->payload = hello;
    in->payload_len = sizeof hello;
    in->seq = 1000;
    in->have_sni = have_sni;
    in->sni_off = 10;
    in->sni_len = 8;
}

/* Приветствие TLS заданной длины записи, от которого в пакете лежат первые
   have байт. record_total == have — запись пришла целиком. */
static uint8_t frag[512];
static void init_frag(d2k_pkt *in, size_t have, size_t record_total) {
    memset(in, 0, sizeof *in);
    memset(frag, 0xCC, sizeof frag);
    frag[0] = 0x16; frag[1] = 3; frag[2] = 1;
    frag[3] = (uint8_t)((record_total - 5) >> 8);
    frag[4] = (uint8_t)(record_total - 5);
    frag[5] = 1;
    frag[6] = (uint8_t)((record_total - 9) >> 16);
    frag[7] = (uint8_t)((record_total - 9) >> 8);
    frag[8] = (uint8_t)(record_total - 9);
    in->payload = frag;
    in->payload_len = have;
    in->seq = 1000;
    in->have_sni = 1;
    in->sni_off = 20;
    in->sni_len = 8;
}

/* udplen — donor compose `--lua-desync=udplen:payload=quic_initial:dir=out:
 * increment=100` (questions.go:331-334). zapret udplen (lua/zapret-antidpi.lua
 * function udplen) appends `increment` bytes of pattern, default "\x00", to
 * the L4 payload: payload .. pattern("\x00", 1, 100). The first 1250 bytes
 * stay byte-identical; only the tail is new, all zeros. */
static uint32_t ones_sum(const uint8_t *b, size_t n, uint32_t acc) {
    size_t i = 0;
    for (; i + 1 < n; i += 2) acc += (uint32_t)b[i] << 8 | b[i + 1];
    if (i < n) acc += (uint32_t)b[i] << 8;
    return acc;
}
static int udp4_ok(const uint8_t *pkt, size_t total) {
    uint32_t acc = 0;
    size_t ulen = total - 20;
    uint8_t ph[12];
    memcpy(ph, pkt + 12, 8); ph[8] = 0; ph[9] = 17;
    ph[10] = (uint8_t)(ulen >> 8); ph[11] = (uint8_t)ulen;
    acc = ones_sum(ph, sizeof ph, 0);
    acc = ones_sum(pkt + 20, ulen, acc);
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)~acc == 0;
}

static void test_udplen(void) {
    static const uint8_t plan[] = {'D','2','K','P',0,1,0,9,0,0,0,3,
        0,2,0,2,17,2, 1,3,0,1,0, 1,14,0,2,0,100};
    static uint8_t initial[1250], before[1250];
    char err[160];
    for (size_t i = 0; i < sizeof initial; i++) initial[i] = (uint8_t)(0xc0 ^ (i * 7));
    memcpy(before, initial, sizeof initial);
    d2k_plan *p = NULL;
    int rc = d2k_plan_load(plan, sizeof plan, &p, err, sizeof err);
    if (rc) printf("udplen plan rejected: %s\n", err);
    CHECK(rc == 0, "udplen plan loads");
    if (!p) return;
    CHECK(d2k_plan_max_emit(p) >= 20 + 8 + 1200 + 100,
          "max_emit must count the 100 bytes the plan adds to a >=1200-byte Initial");
    d2k_pkt in = {0};
    d2k_actions a = {0};
    in.payload = initial; in.payload_len = sizeof initial;
    CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "udplen applies to a 1250-byte Initial");
    CHECK(a.fate == D2K_ORIG_DROP, "lengthened datagram replaces the original");
    CHECK(a.n == 1 && a.v[0].kind == D2K_EMIT_PAYLOAD, "udplen emits exactly one payload");
    if (a.n == 1) {
        const d2k_emit *e = &a.v[0];
        CHECK(e->len == 1350, "1250 + increment 100 = 1350");
        CHECK(e->bytes && memcmp(e->bytes, before, 1250) == 0, "original 1250 bytes unchanged");
        int zeros = 1;
        for (size_t i = 1250; e->bytes && i < e->len; i++) if (e->bytes[i]) zeros = 0;
        CHECK(zeros, "appended tail is zero bytes (zapret pattern default \\x00)");
        CHECK(memcmp(initial, before, sizeof before) == 0, "input packet not modified in place");
        CHECK(e->ipfrag == 0 && e->pre_len == 0 && e->delay_us == 0, "no other action attached");
        d2k_conn c;
        memset(&c, 0, sizeof c);
        uint8_t s4[4] = {192, 168, 1, 67}, d4[4] = {1, 2, 3, 4};
        memcpy(&c.src_ip, s4, 4); memcpy(&c.dst_ip, d4, 4);
        c.src_port = 0x3930; c.dst_port = 0xbb01; c.ttl = 64; c.family = 4;
        static uint8_t wire[2048];
        size_t made = d2k_wire_build_udp(&c, e, wire, sizeof wire);
        CHECK(made == 20 + 8 + 1350, "wire datagram carries 1350 payload bytes");
        if (made == 20 + 8 + 1350) {
            CHECK(((size_t)wire[24] << 8 | wire[25]) == 8 + 1350, "UDP length field 1358");
            CHECK(((size_t)wire[2] << 8 | wire[3]) == made, "IP total length matches");
            CHECK(udp4_ok(wire, made), "UDP checksum valid over the lengthened payload");
            CHECK(memcmp(wire + 28, before, 1250) == 0, "wire keeps original bytes first");
        }
    }
    d2k_actions_free(&a);

    /* Junk fake ahead + udplen: fakes untouched, then the lengthened truth. */
    {
        uint8_t combo[128];
        size_t n = 0;
        memcpy(combo, "D2KP\0\1\0\x09\0\0\0\x06", 12); n = 12;
        uint8_t proto[2] = {17, 2}; putrec(combo, &n, 0x0002, proto, 2);
        uint8_t pay[18] = {0, 1}; putrec(combo, &n, 0x0010, pay, sizeof pay);
        uint8_t poi[8] = {0, 1}; putrec(combo, &n, 0x0011, poi, 8);
        uint8_t fk[10] = {0, 1, 0, 1, 2, 0, 0, 0, 0, 0}; putrec(combo, &n, 0x0101, fk, 10);
        uint8_t ord = 0; putrec(combo, &n, 0x0103, &ord, 1);
        uint8_t inc[2] = {0, 100}; putrec(combo, &n, 0x010e, inc, 2);
        d2k_plan *q = NULL;
        CHECK(d2k_plan_load(combo, n, &q, err, sizeof err) == 0, "junk+udplen plan loads");
        if (q) {
            d2k_actions b = {0};
            CHECK(d2k_plan_apply(q, NULL, &in, &b) == 0 && b.n == 3 &&
                  b.v[0].kind == D2K_EMIT_FAKE && b.v[0].len == 16 &&
                  b.v[1].kind == D2K_EMIT_FAKE && b.v[1].len == 16 &&
                  b.v[2].kind == D2K_EMIT_PAYLOAD && b.v[2].len == 1350 &&
                  b.fate == D2K_ORIG_DROP,
                  "junk x2 ahead, then the lengthened Initial");
            d2k_actions_free(&b);
            d2k_plan_free(q);
        }
    }
    d2k_plan_free(p);
}

/* ОРИГИНАЛ ПОСЛЕ ФАЛЬШИВОК — СВОЕЙ ПОСЫЛКОЙ, если вызывающий не может отдать
   его ядру (задача 42: первая датаграмма QUIC, conntrack). Порядок: все
   фальшивки, затем оригинал целиком без собственной паузы; судьба — снять
   удерживаемую копию. Без фальшивок владеть нечем: оригинал проходит. */
static void test_own_after_fakes(void) {
    d2k_plan *p = NULL; char err[160]; d2k_flow f; d2k_actions a; d2k_pkt in;
    memset(&f, 0, sizeof f);
    CHECK(d2k_plan_load(plan_fake_before, sizeof plan_fake_before, &p, err, sizeof err) == 0,
          "fake-before plan loads for owned original");
    if (!p) { return; }
    init_pkt(&in, 0);
    in.own_after_fakes = 1;
    memset(&a, 0, sizeof a);
    CHECK(d2k_plan_apply(p, &f, &in, &a) == 0, "owned-original plan applies");
    CHECK(a.n == 3, "two fakes and then the original itself");
    CHECK(a.fate == D2K_ORIG_DROP, "the held copy is dropped: the original is ours");
    if (a.n == 3) {
        CHECK(a.v[0].kind == D2K_EMIT_FAKE && a.v[1].kind == D2K_EMIT_FAKE,
              "fakes keep their place before the original");
        CHECK(a.v[1].delay_us == 78000, "gap between fake copies kept");
        CHECK(a.v[2].kind == D2K_EMIT_PAYLOAD && a.v[2].len == in.payload_len &&
              a.v[2].bytes == in.payload && !a.v[2].pre_len,
              "original goes whole and unchanged");
        CHECK(a.v[2].delay_us == 0 && a.v[2].ttl == 0 && a.v[2].poison == 0,
              "original right after the last fake, without fooling");
    }
    d2k_actions_free(&a);

    /* Не просили — прежнее поведение: оригинал отпускает ядро. */
    init_pkt(&in, 0);
    memset(&a, 0, sizeof a);
    CHECK(d2k_plan_apply(p, &f, &in, &a) == 0 && a.n == 2 && a.fate == D2K_ORIG_PASS,
          "without the request fakes-only plans still pass the original");
    d2k_actions_free(&a);
    d2k_plan_free(p);

    /* План без фальшивок (только разрез) владеет нагрузкой по своей причине;
       просьба ничего к нему не добавляет. План вообще без посылок — пропуск. */
    p = NULL;
    static const uint8_t empty_plan[] = {'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 1,
                                         0x01, 0x03, 0x00, 0x01, 0x00};
    CHECK(d2k_plan_load(empty_plan, sizeof empty_plan, &p, err, sizeof err) == 0,
          "order-only plan loads");
    if (p) {
        init_pkt(&in, 0);
        in.own_after_fakes = 1;
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) == 0 && a.n == 0 && a.fate == D2K_ORIG_PASS,
              "no fakes: nothing races the original, the kernel releases it");
        d2k_actions_free(&a);
        in.emit_original=1;
        CHECK(d2k_plan_apply(p,&f,&in,&a)==0 && a.n==1 && a.fate==D2K_ORIG_DROP,
              "raw owner materializes unchanged original");
        if(a.n==1)CHECK(a.v[0].seq==in.seq && a.v[0].len==in.payload_len &&
                       !memcmp(a.v[0].bytes,in.payload,in.payload_len),
                       "raw original has exact bytes and sequence");
        d2k_actions_free(&a);
        d2k_plan_free(p);
    }
}

/* quicsplit — разрез ClientHello на кадры CRYPTO внутри Initial (задача 40).
 * Исполнитель отдаёт РОВНО то, что даёт функция ядра, которой пользовался
 * вопрос замера: одна посылка той же длины вместо оригинала. Не Initial —
 * отказ целиком, оригинал уходит нетронутым. */
static void test_quicsplit(void) {
    static const uint8_t plan[] = {'D','2','K','P',0,1,0,10,0,0,0,3,
        0,2,0,2,17,2, 1,3,0,1,0, 1,15,0,1,1};
    char err[160];
    d2k_plan *p = NULL;
    int rc = d2k_plan_load(plan, sizeof plan, &p, err, sizeof err);
    if (rc) printf("quicsplit plan rejected: %s\n", err);
    CHECK(rc == 0, "quicsplit plan loads");
    if (!p) return;
    static uint8_t initial[1200], want[1500];
    memcpy(initial, d2k_test_v1_initial, sizeof initial);
    size_t want_len = 0;
    CHECK(d2k_quic_initial_split_crypto(initial, sizeof initial, want, sizeof want, &want_len) == 0,
          "core split builds");
    d2k_pkt in = {0};
    d2k_actions a = {0};
    in.payload = initial; in.payload_len = sizeof initial;
    CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "quicsplit applies to a real Initial");
    CHECK(a.fate == D2K_ORIG_DROP, "split Initial replaces the original");
    CHECK(a.n == 1 && a.v[0].kind == D2K_EMIT_PAYLOAD, "quicsplit emits exactly one payload");
    if (a.n == 1) {
        const d2k_emit *e = &a.v[0];
        CHECK(e->len == sizeof initial && e->bytes && memcmp(e->bytes, want, want_len) == 0,
              "emitted bytes are the core split, same length");
        CHECK(memcmp(initial, d2k_test_v1_initial, sizeof initial) == 0,
              "input packet not modified in place");
        CHECK(e->ipfrag == 0 && e->pre_len == 0 && e->delay_us == 0, "no other action attached");
        char name[64];
        CHECK(e->bytes && d2k_quic_sni(e->bytes, e->len, name, sizeof name) == 0 &&
              strcmp(name, "example.com") == 0, "server still assembles the same name");
    }
    d2k_actions_free(&a);
    static uint8_t junk[1200];
    memset(junk, 0xab, sizeof junk);
    in.payload = junk; in.payload_len = sizeof junk;
    d2k_actions b = {0};
    CHECK(d2k_plan_apply(p, NULL, &in, &b) != 0, "not an Initial: refused, original passes as is");
    d2k_actions_free(&b);
    /* Task 40 round 1 (I1): Chrome ML-KEM ClientHello, name in datagram 2.
       Datagram 1 is never resealed with an unmeasured cut: explicit refusal. */
    static uint8_t d1[1500], d2[1500];
    size_t l1 = 0, l2 = 0;
    CHECK(d2k_test_pq_initials("example.com", d1, &l1, d2, &l2) == 0, "PQ fixture builds");
    in.payload = d1; in.payload_len = l1;
    d2k_actions c = {0};
    CHECK(d2k_plan_apply(p, NULL, &in, &c) != 0 && c.n == 0,
          "name not in the first datagram: split refused, nothing emitted");
    CHECK(c.refuse_why && strstr(c.refuse_why, "имени нет"),
          "refusal names its reason (name not in this datagram)");
    d2k_actions_free(&c);
    d2k_plan_free(p);
}

/* ИЗМЕРЕННЫЙ ВХОД И СЕГМЕНТ ПРОВОДА. Поле 13.10.2026, forum.ru-board.com:
   приём найден замером (плотная серия с битой суммой, три ServerHello), а
   план из него пришпилен к длине приветствия 1541 байт. Датапат видит ТОЛЬКО
   первый сегмент (1452 при MSS 1452), и равенство длин не выполняется никогда
   — исполнитель отказывал, зонд уходил голым, приём выбрасывался. Журнал
   датапата назвал это дословно: «байты плана собраны под другой вход».

   Приставка годится, если это ТО ЖЕ приветствие и программа на ней та же:
   объявленная длина записи совпадает с измеренной, имя на том же месте и той
   же длины, и каждый ЧИСЛОВОЙ разрез плана лежит внутри пришедшего. Разрез
   за приставкой — отказ: иначе исполнилась бы другая программа, чем мерили
   (split_points молча пропускает разрез вне нагрузки). */
static size_t pinned_plan(uint8_t *b, unsigned total, unsigned sni_off,
                          unsigned sni_len, unsigned split_at) {
    size_t n = 0;
    b[n++]='D';b[n++]='2';b[n++]='K';b[n++]='P';
    put16(b,&n,1); put16(b,&n,5); put16(b,&n,0); put16(b,&n,5);
    uint8_t proto[2]={6,1}; putrec(b,&n,0x0002,proto,2);
    uint8_t inp[12]={(uint8_t)(total>>24),(uint8_t)(total>>16),(uint8_t)(total>>8),(uint8_t)total,
                     (uint8_t)(sni_off>>24),(uint8_t)(sni_off>>16),(uint8_t)(sni_off>>8),(uint8_t)sni_off,
                     (uint8_t)(sni_len>>24),(uint8_t)(sni_len>>16),(uint8_t)(sni_len>>8),(uint8_t)sni_len};
    putrec(b,&n,0x0106,inp,12);
    uint8_t sp[4]={0,0,(uint8_t)(split_at>>8),(uint8_t)split_at};
    putrec(b,&n,0x0100,sp,4);
    uint8_t wire[1]={1}; putrec(b,&n,0x0109,wire,1);
    uint8_t order[1]={0}; putrec(b,&n,0x0103,order,1);
    return n;
}

static void test_pinned_input_prefix(void) {
    /* Приветствие 1541 байт: запись объявляет 1536, рукопожатие 1532. */
    static uint8_t hello[1541];
    memset(hello, 0x5a, sizeof hello);
    hello[0]=0x16; hello[1]=3; hello[2]=1;
    hello[3]=(uint8_t)((sizeof hello - 5) >> 8); hello[4]=(uint8_t)(sizeof hello - 5);
    hello[5]=1;
    hello[6]=(uint8_t)((sizeof hello - 9) >> 16);
    hello[7]=(uint8_t)((sizeof hello - 9) >> 8);
    hello[8]=(uint8_t)(sizeof hello - 9);
    const unsigned SNI_OFF = 97, SNI_LEN = 18, SEG = 1452;
    uint8_t plan[256]; char err[160];

    /* Разрез 770 (n/2 у замера) лежит внутри первого сегмента. */
    size_t pl = pinned_plan(plan, (unsigned)sizeof hello, SNI_OFF, SNI_LEN, 770);
    d2k_plan *p = NULL;
    CHECK(d2k_plan_load(plan, pl, &p, err, sizeof err) == 0 && p,
          "пришпиленный план не разобран");
    if (!p) { return; }
    d2k_pkt in; memset(&in, 0, sizeof in);
    in.payload = hello; in.payload_len = SEG; in.seq = 1;
    in.have_sni = 1; in.sni_off = SNI_OFF; in.sni_len = SNI_LEN; in.is_tls13 = 1;
    d2k_actions a = {0};
    CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0,
          "приставка того же приветствия отвергнута — приём недоступен проводу");
    if (a.n) { CHECK(a.n >= 2, "разрез внутри приставки не исполнен"); }
    d2k_actions_free(&a);

    /* Целое приветствие — как прежде. */
    in.payload_len = sizeof hello;
    d2k_actions whole = {0};
    CHECK(d2k_plan_apply(p, NULL, &in, &whole) == 0, "целый вход отвергнут");
    d2k_actions_free(&whole);

    /* КОНТРОЛЬ: имя не на том месте — это другой вход, отказ с причиной. */
    in.payload_len = SEG; in.sni_off = SNI_OFF + 1;
    d2k_actions moved = {0};
    CHECK(d2k_plan_apply(p, NULL, &in, &moved) != 0 &&
          moved.refuse_why && strstr(moved.refuse_why, "другой вход"),
          "сдвинутое имя принято за измеренный вход");
    d2k_actions_free(&moved);
    in.sni_off = SNI_OFF;

    /* КОНТРОЛЬ: чужая длина записи — другое приветствие. */
    static uint8_t other[1541];
    memcpy(other, hello, sizeof other);
    other[3] = (uint8_t)((1400 - 5) >> 8); other[4] = (uint8_t)(1400 - 5);
    other[6] = 0; other[7] = (uint8_t)((1400 - 9) >> 8); other[8] = (uint8_t)(1400 - 9);
    in.payload = other;
    d2k_actions diff = {0};
    CHECK(d2k_plan_apply(p, NULL, &in, &diff) != 0 &&
          diff.refuse_why && strstr(diff.refuse_why, "другой вход"),
          "другое приветствие принято за измеренный вход");
    d2k_actions_free(&diff);
    in.payload = hello;
    d2k_plan_free(p);

    /* КОНТРОЛЬ: разрез ЗА приставкой — программа была бы другой. */
    pl = pinned_plan(plan, (unsigned)sizeof hello, SNI_OFF, SNI_LEN, 1500);
    d2k_plan *q = NULL;
    CHECK(d2k_plan_load(plan, pl, &q, err, sizeof err) == 0 && q, "план с поздним разрезом");
    if (q) {
        d2k_actions late = {0};
        CHECK(d2k_plan_apply(q, NULL, &in, &late) != 0 &&
              late.refuse_why && strstr(late.refuse_why, "разрез") != NULL,
              "разрез за пришедшими байтами исполнен молча другой программой");
        d2k_actions_free(&late);
        d2k_plan_free(q);
    }
}

/* ПЛАН БЕЗ СВОЕГО РАЗРЕЗА — ЭТО ДРУГАЯ ПРОГРАММА (24.10.2026).
 *
 * split_points пропускает разрез за нагрузкой молча («разрез вне нагрузки не
 * режет ничего»), и до этой правки план исполнялся без разреза и возвращался
 * ПРИМЕНЁННЫМ. Так выглядит поток браузера: приветствие Chrome 1919–2015 байт
 * при MSS 1388 уезжает в два сегмента (issue 28), и числовой разрез,
 * измеренный на одном сегменте собственного зонда, в голову клиента не
 * попадает. Коробка режет по-прежнему, а контроллер видит applied=1.
 *
 * Отказ — только когда не попал НИ ОДИН разрез: план, часть разрезов
 * которого законно не попала, по-прежнему исполняется. */
static void test_split_beyond_segment_refused(void) {
    d2k_plan *p = NULL;
    char err[160];
    CHECK(d2k_plan_load(plan_split_far, sizeof plan_split_far, &p, err, sizeof err) == 0,
          "план с далёким разрезом не загрузился");
    if (!p) { return; }
    uint8_t head[1388];
    memset(head, 0x41, sizeof head);
    d2k_actions a = {0};
    d2k_pkt in = {0};
    in.payload = head;
    in.payload_len = sizeof head;   /* первый сегмент: разрез 1500 за его концом */
    in.seq = 100;
    CHECK(d2k_plan_apply(p, NULL, &in, &a) != 0,
          "план без единого попавшего разреза применён — исполнилась другая программа");
    CHECK(a.refuse_why && strstr(a.refuse_why, "ни один измеренный разрез"),
          "отказ не назван: по журналу не отличить его от «плана нет»");
    d2k_actions_free(&a);

    /* Те же байты целиком: разрез попадает, и план исполняется как мерили. */
    uint8_t whole[1600];
    memset(whole, 0x41, sizeof whole);
    memset(&a, 0, sizeof a);
    in.payload = whole;
    in.payload_len = sizeof whole;
    CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0,
          "на целых байтах тот же план обязан исполниться");
    CHECK(a.n == 2, "разрез на целых байтах дал не два куска");
    d2k_actions_free(&a);
    d2k_plan_free(p);
}

int main(void) {
    d2k_plan *p = NULL;
    char err[160];
    d2k_flow f;
    memset(&f, 0, sizeof f);
    d2k_actions a;
    d2k_pkt in;

    test_split_beyond_segment_refused();
    test_tls_fake_modifiers();
    test_refusal_names_reason();
    test_pinned_input_prefix();
    test_udplen();
    test_quicsplit();
    test_own_after_fakes();

    /* A TCP route hint must not turn one QUIC datagram into fragments. */
    {
        uint8_t plan[128], body[64]={0}, proto[2]={17,2};
        memcpy(plan,plan_delay,sizeof plan_delay);
        size_t n=sizeof plan_delay;
        putrec(plan,&n,0x0002,proto,sizeof proto);
        plan[11]=2;
        d2k_plan *udp=NULL; d2k_pkt pkt={0}; d2k_actions actions={0};
        CHECK(d2k_plan_load(plan,n,&udp,err,sizeof err)==0,
              "UDP delay plan loads for TCP-cap isolation");
        if(udp) {
            pkt.payload=body; pkt.payload_len=sizeof body; pkt.segment_cap=32;
            CHECK(d2k_plan_apply(udp,NULL,&pkt,&actions)==0,
                  "UDP plan still applies with foreign TCP route hint");
            CHECK(actions.n==1 && actions.v[0].len==64,
                  "TCP route hint never segments a QUIC datagram");
            d2k_actions_free(&actions); d2k_plan_free(udp);
        }
    }

    /* Discord CDN: fake+pace owns an assembled 1760-byte ClientHello.
       Unlike seqovl, this plan has no prefix and no explicit segmentation. */
    {
        uint8_t plan[512], client[1760] = {0};
        size_t n = tls_fake_plan(plan);
        uint8_t pace[4] = {0, 0, 0x3a, 0x98};
        putrec(plan, &n, 0x0105, pace, sizeof pace);
        plan[11] = 8;
        client[0]=0x16; client[1]=3; client[2]=1;
        client[3]=6; client[4]=0xdb; /* record total 1760 */
        client[5]=1; client[7]=6; client[8]=0xd7;
        client[43]=32;
        for (size_t i=44; i<sizeof client; i++) client[i]=(uint8_t)i;
        d2k_plan *paced=NULL;
        CHECK(d2k_plan_load(plan,n,&paced,err,sizeof err)==0,
              "paced fake plan loads for route-MTU regression");
        if (paced) {
            d2k_pkt pkt={0}; d2k_actions actions={0};
            pkt.payload=client; pkt.payload_len=sizeof client; pkt.seq=1000;
            pkt.have_sni=1; pkt.is_tls13=1; pkt.sni_off=20; pkt.sni_len=8;
            pkt.segment_cap=1440;
            CHECK(d2k_plan_apply(paced,NULL,&pkt,&actions)==0,
                  "paced long ClientHello applies");
            CHECK(actions.n==3,
                  "paced ClientHello without overlap splits below route MTU");
            CHECK(actions.fate==D2K_ORIG_DROP,"paced plan still owns original");
            size_t offset=0;
            for(size_t i=0;i<actions.n;i++) {
                const d2k_emit *e=&actions.v[i];
                if(e->kind==D2K_EMIT_FAKE) {
                    CHECK(i==0 && e->len==87,"fake remains first and unsplit");
                    continue;
                }
                CHECK(e->len<=1440,"real TCP emit fits route MTU");
                CHECK(e->seq==1000+offset,"real TCP sequence remains contiguous");
                CHECK(e->delay_us==(offset==0?15000u:0u),
                      "pace occurs once before the real byte stream");
                CHECK(offset+e->len<=sizeof client,"real bytes stay in bounds");
                if(offset+e->len<=sizeof client)
                    CHECK(memcmp(e->bytes,client+offset,e->len)==0,
                          "segmentation preserves every real byte");
                offset+=e->len;
            }
            CHECK(offset==sizeof client,"whole ClientHello emitted exactly once");
            d2k_actions_free(&actions);
            pkt.segment_cap=32;
            CHECK(d2k_plan_apply(paced,NULL,&pkt,&actions)==0,
                  "small route cap applies to real stream");
            CHECK(actions.n && actions.v[0].kind==D2K_EMIT_FAKE &&
                  actions.v[0].len==87,"route cap never splits a fake packet");
            d2k_actions_free(&actions);
            d2k_plan_free(paced);
        }
    }

    /* --- фальшивка перед кусками ------------------------------------- */
    CHECK(d2k_plan_load(plan_fake_before, sizeof plan_fake_before, &p, err, sizeof err) == 0,
          "план с фальшивкой не загрузился");
    if (p) {
        init_pkt(&in, 1);
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) == 0, "применение не удалось");
        CHECK(a.n == 2, "ожидались ровно две копии фальшивки");
        if (a.n == 2) {
            CHECK(a.v[0].delay_us == 0, "первая копия не должна ждать");
            CHECK(a.v[1].delay_us == 78000, "пауза между копиями потеряна");
            CHECK(a.v[0].seq == in.seq, "фальшивка обязана занимать место начала потока");
            CHECK(a.v[0].ttl == 3, "ttl порчи не доехал");
            CHECK(a.v[0].poison == D2K_POISON_BADSUM, "флаг порчи не доехал");
            CHECK(a.v[0].len == 3, "длина приманки не совпала");
        }
        /* Оригинал мы не трогали — его обязан выпустить вызывающий. */
        CHECK(a.fate == D2K_ORIG_PASS, "судьба оригинала должна быть «пропустить»");
        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- OOB/URG: вставка не удаляет байт оригинального TLS ---------------- */
    CHECK(d2k_plan_load(plan_oob_sni, sizeof plan_oob_sni, &p, err, sizeof err) == 0,
          "план TCP URG по середине SNI не загрузился");
    if (p) {
        init_frag(&in, 64, 64);
        for (size_t i = 20; i < 28; i++) { frag[i] = (uint8_t)('a' + i - 20); }
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) == 0, "план TCP URG не применился");
        CHECK(a.n == 3, "OOB должен дать префикс, срочный байт и суффикс");
        if (a.n == 3) {
            CHECK(a.v[0].seq == 1000 && a.v[0].len == 24,
                  "префикс OOB разрезан не по середине SNI");
            CHECK(a.v[1].seq == 1024 && a.v[1].len == 1 && a.v[1].urgent &&
                  a.v[1].urgent_ptr == 1,
                  "срочный байт не помечен TCP URG в правильной позиции");
            CHECK(a.v[2].seq == 1025 && a.v[2].len == 40 && a.v[2].bytes == frag + 24,
                  "суффикс OOB потерял байт исходного ClientHello");
        }
        CHECK(a.fate == D2K_ORIG_DROP, "исходный ClientHello не снят при OOB-вставке");
        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- разрез по SNI ------------------------------------------------ */
    CHECK(d2k_plan_load(plan_split_sni, sizeof plan_split_sni, &p, err, sizeof err) == 0,
          "план с разрезом не загрузился");
    if (p) {
        init_pkt(&in, 1);
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) == 0, "применение разреза не удалось");
        CHECK(a.n == 2, "разрез обязан дать два куска");
        if (a.n == 2) {
            CHECK(a.v[0].seq == 1000 && a.v[0].len == 10, "первый кусок не по якорю");
            CHECK(a.v[1].seq == 1010 && a.v[1].len == 54, "второй кусок не по якорю");
        }
        /* Нагрузку выпустили мы сами — оригинал обязан быть снят, иначе
           байты уйдут дважды. */
        CHECK(a.fate == D2K_ORIG_DROP, "при своём выпуске нагрузки оригинал обязан сниматься");
        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- ВЫДЕРЖКА ПЕРЕД ЕДИНСТВЕННОЙ ПОСЫЛКОЙ -------------------------- */
    CHECK(d2k_plan_load(plan_delay, sizeof plan_delay, &p, err, sizeof err) == 0,
          "план с выдержкой не загрузился");
    if (p) {
        init_pkt(&in, 1);
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) == 0, "план с выдержкой не применился");
        CHECK(a.n == 1, "выдержка обязана дать РОВНО одну посылку — саму нагрузку");
        if (a.n == 1) {
            CHECK(a.v[0].kind == D2K_EMIT_PAYLOAD, "посылка не нагрузка");
            CHECK(a.v[0].delay_us == 15000, "выдержка не доехала до посылки");
            CHECK(a.v[0].len == in.payload_len, "нагрузка урезана");
        }
        /* Выдержать паузу можно только тогда, когда правду выпускаем мы сами:
           оригинал, отпущенный ядром, уходит когда ему угодно. */
        CHECK(a.fate == D2K_ORIG_DROP,
              "оригинал не снят — ядро выпустит его без всякой выдержки");
        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- ПЕРВЫЙ СЕГМЕНТ СОСТАВНОГО ПРИВЕТСТВИЯ ------------------------
       Приветствие длиннее сегмента — обычное дело: у клиента 1534 байта при
       MSS 1388 (поле 18.09.2026). Требовать целую запись значит не применять
       план к таким потокам вовсе, а дождаться остатка нельзя: пока первый
       сегмент лежит в очереди без вердикта, ядро остаток не выпускает
       (замерено там же — «добавлено к голове=0» при двух удержаниях).
       Имя в сегменте есть, разрез считается от него — этого достаточно;
       остаток уйдёт за нашими кусками сам. */
    CHECK(d2k_plan_load(plan_split_sni_tls, sizeof plan_split_sni_tls, &p, err, sizeof err) == 0,
          "план со входом-приветствием не загрузился");
    if (p) {
        init_frag(&in, 64, 64);
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) == 0, "целая запись не принята входом");
        d2k_actions_free(&a);
        init_frag(&in, 64, 200);
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) == 0,
              "первый сегмент составного приветствия отвергнут как вход");
        CHECK(a.n == 2 && a.v[0].len == 20 && a.v[1].len == 44,
              "куски посчитаны не по сегменту");
        d2k_actions_free(&a);
        /* А вот обрывок БЕЗ имени входом не считается: разрез от него не
           вычислить, и гадать не из чего. */
        init_frag(&in, 64, 200);
        in.have_sni = 0;
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) != 0,
              "обрывок без имени принят входом");
        d2k_actions_free(&a);
        /* Обрывок, который длиннее объявленной записи, — не начало
           приветствия, а мусор. */
        init_frag(&in, 64, 32);
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) != 0,
              "кусок длиннее объявленной записи принят входом");
        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- невычислимый якорь ------------------------------------------- */
    CHECK(d2k_plan_load(plan_split_sni, sizeof plan_split_sni, &p, err, sizeof err) == 0,
          "план не загрузился повторно");
    if (p) {
        init_pkt(&in, 0); /* SNI в пакете нет */
        memset(&a, 0, sizeof a);
        CHECK(d2k_plan_apply(p, &f, &in, &a) != 0,
              "невычислимый якорь обязан давать отказ, а не нулевое смещение");
        CHECK(a.n == 0, "при отказе действий быть не должно");
        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- фальшивка между кусками без разрезов -------------------------- */
    CHECK(d2k_plan_load(plan_between_no_split, sizeof plan_between_no_split, &p, err, sizeof err) != 0,
          "фальшивка «между кусками» без разрезов принята: класть её некуда");
    if (p) {
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- отмена исполнения на середине -------------------------------- */
    CHECK(d2k_plan_load(plan_fake_before, sizeof plan_fake_before, &p, err, sizeof err) == 0,
          "план с фальшивкой не загрузился для проверки отмены");
    if (p) {
        init_pkt(&in, 1);
        memset(&a, 0, sizeof a);
        d2k_plan_apply(p, &f, &in, &a);
        d2k_cancel c;

        /* Ничего не ушло: отмена совершенно чистая. */
        memset(&c, 0, sizeof c);
        d2k_actions_cancel(&a, 0, &c);
        CHECK(c.fate == D2K_ORIG_PASS, "до первой посылки оригинал обязан пройти");
        /* partial означает «полного исполнения не было», а не «оборвалось на
           середине». Потребитель решает по нему единственный вопрос — можно ли
           записывать измерение, — и ответ «нельзя» одинаков и для оборванного
           плана, и для не начинавшегося. Ноль здесь прочитался бы как
           разрешение записать измерение по плану, который не исполнялся.
           Различить «не начинался» и «оборвался» контроллер может по emitted,
           которое он и так передаёт. */
        CHECK(c.partial == 1, "неисполненный план не должен выглядеть исполненным");
        CHECK(c.stream_damaged == 0, "поток не мог испортиться до первой посылки");

        /* Ушла одна копия фальшивки из двух: нагрузку не трогали. */
        memset(&c, 0, sizeof c);
        d2k_actions_cancel(&a, 1, &c);
        CHECK(c.fate == D2K_ORIG_PASS, "после фальшивки оригинал обязан пройти");
        CHECK(c.partial == 1, "исполнение неполное — измерение по нему недействительно");
        CHECK(c.stream_damaged == 0, "фальшивка нагрузку не портит");

        /* Ушло всё: это не отмена. */
        memset(&c, 0, sizeof c);
        d2k_actions_cancel(&a, a.n, &c);
        CHECK(c.partial == 0, "полностью исполненный план не является частичным");

        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* Отмена посреди НАГРУЗКИ: чистого выхода нет. */
    CHECK(d2k_plan_load(plan_split_sni, sizeof plan_split_sni, &p, err, sizeof err) == 0,
          "план с разрезом не загрузился для проверки отмены");
    if (p) {
        init_pkt(&in, 1);
        memset(&a, 0, sizeof a);
        d2k_plan_apply(p, &f, &in, &a);
        d2k_cancel c;

        /* Первый кусок уже на проводе. Отпустить оригинал — послать те же
           байты дважды; не отпустить — потерять остаток. */
        memset(&c, 0, sizeof c);
        d2k_actions_cancel(&a, 1, &c);
        CHECK(c.stream_damaged == 1, "отмена посреди нагрузки обязана помечать поток испорченным");
        CHECK(c.fate == D2K_ORIG_DROP, "оригинал нельзя отпускать: его байты уже частично ушли");
        CHECK(c.partial == 1, "исполнение неполное");

        /* До первого куска — ещё чисто. */
        memset(&c, 0, sizeof c);
        d2k_actions_cancel(&a, 0, &c);
        CHECK(c.stream_damaged == 0, "до первого куска поток цел");
        CHECK(c.fate == D2K_ORIG_PASS, "нагрузку не трогали — оригинал обязан пройти");

        d2k_actions_free(&a);
        d2k_plan_free(p);
        p = NULL;
    }

    /* --- перекрытие без разреза ----------------------------------------- */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_seqovl, sizeof plan_seqovl, &p, err, sizeof err) == 0,
              "план с перекрытием не загрузился");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            init_pkt(&in, 1);
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "перекрытие не применилось");
            CHECK(a.n == 1, "перекрытие без разреза даёт один кусок");
            if (a.n == 1) {
                CHECK(a.v[0].pre_len == 2, "приставка не поставлена");
                CHECK(a.v[0].pre != NULL && a.v[0].pre[0] == 0xAA && a.v[0].pre[1] == 0xBB,
                      "приставка не та");
                /* Номер сдвинут НАЗАД на длину приставки: сервер выбросит её
                   как уже полученное, коробка — положит в поток. */
                CHECK(a.v[0].seq == in.seq - 2, "номер не сдвинут назад на длину приставки");
                CHECK(a.v[0].len == in.payload_len, "нагрузка урезана");
                CHECK(a.fate == D2K_ORIG_DROP, "оригинал обязан быть подавлен: мы шлём его сами");
            }
            d2k_actions_free(&a);

            /* MTU-предел — только дополнительная граница TCP-сегментации:
               prefix + исходное тело режутся вместе, без потери/дублирования
               байтов и с непрерывными номерами последовательности. */
            uint8_t large_payload[2200];
            memset(large_payload, 0x5a, sizeof large_payload);
            memset(&in, 0, sizeof in);
            in.payload = large_payload;
            in.payload_len = sizeof large_payload;
            in.seq = 1000;
            in.segment_cap = 1400;
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0,
                  "перекрытие с пределом MTU не применилось");
            CHECK(a.n == 2, "перекрытие выше MTU автоматически делится на два сегмента");
            size_t total = 0;
            uint32_t expected_seq = in.seq - 2;
            for (size_t i = 0; i < a.n; i++) {
                size_t body = a.v[i].pre_len + a.v[i].len;
                CHECK(body <= in.segment_cap, "сегмент после деления не превышает MTU-предел");
                CHECK(a.v[i].seq == expected_seq, "после деления последовательность непрерывна");
                expected_seq += (uint32_t)body;
                total += body;
            }
            CHECK(total == sizeof large_payload + 2,
                  "деление сохраняет приставку перекрытия и все исходные байты");
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- перекрытие вместе с разрезом ------------------------------------ */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_seqovl_split, sizeof plan_seqovl_split, &p, err, sizeof err) == 0,
              "план с перекрытием и разрезом не загрузился");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            init_pkt(&in, 1);
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "не применилось");
            CHECK(a.n == 2, "разрез даёт два куска");
            if (a.n == 2) {
                CHECK(a.v[0].pre_len == 2, "приставка только у первого куска");
                CHECK(a.v[0].seq == in.seq - 2, "первый кусок не сдвинут назад");
                CHECK(a.v[0].len == in.sni_off, "первый кусок не до имени");
                CHECK(a.v[1].pre_len == 0, "приставка попала и во второй кусок");
                CHECK(a.v[1].seq == in.seq + (uint32_t)in.sni_off,
                      "второй кусок с неверным номером");
            }
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- обратный порядок: разрез, без фальшивок ------------------------- */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_split_reverse, sizeof plan_split_reverse, &p, err, sizeof err) == 0,
              "план с обратным порядком и разрезом не загрузился");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            init_pkt(&in, 1);
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "обратный порядок не применился");
            CHECK(a.n == 2, "разрез обязан дать два куска и при обратном порядке");
            if (a.n == 2) {
                /* Хвост уходит ПЕРВЫМ, а номер последовательности остаётся при
                   своём содержимом: переставляется порядок ОТПРАВКИ, а не
                   сами байты и не их номера. */
                CHECK(a.v[0].kind == D2K_EMIT_PAYLOAD && a.v[0].seq == 1010 && a.v[0].len == 54,
                      "первым обязан уйти хвост, а не голова");
                CHECK(a.v[1].kind == D2K_EMIT_PAYLOAD && a.v[1].seq == 1000 && a.v[1].len == 10,
                      "голова обязана уйти второй");
            }
            CHECK(a.fate == D2K_ORIG_DROP, "нагрузку выпустили сами — оригинал обязан сниматься");
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- обратный порядок: фальшивка ПЕРЕД нагрузкой --------------------- */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_fake_before_reverse, sizeof plan_fake_before_reverse, &p, err, sizeof err) == 0,
              "план с фальшивкой перед нагрузкой и обратным порядком не загрузился");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            init_pkt(&in, 1);
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "применение не удалось");
            CHECK(a.n == 3, "ожидались фальшивка и два куска");
            if (a.n == 3) {
                CHECK(a.v[0].kind == D2K_EMIT_FAKE && a.v[0].seq == 1000,
                      "фальшивка обязана остаться первой — переворот её не касается");
                /* За фальшивкой куски идут хвостом вперёд, как и без неё. */
                CHECK(a.v[1].kind == D2K_EMIT_PAYLOAD && a.v[1].seq == 1010 && a.v[1].len == 54,
                      "после фальшивки первым обязан идти хвост");
                CHECK(a.v[2].kind == D2K_EMIT_PAYLOAD && a.v[2].seq == 1000 && a.v[2].len == 10,
                      "голова обязана идти последней");
            }
            CHECK(a.fate == D2K_ORIG_DROP, "нагрузку выпустили сами — оригинал обязан сниматься");
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- обратный порядок: фальшивка МЕЖДУ кусками ------------------------ */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_between_reverse, sizeof plan_between_reverse, &p, err, sizeof err) == 0,
              "план с фальшивкой между кусками и обратным порядком не загрузился");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            init_pkt(&in, 1);
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "применение не удалось");
            CHECK(a.n == 3, "ожидались кусок, фальшивка и ещё кусок");
            if (a.n == 3) {
                /* Фальшивка стоит ВНУТРИ диапазона нагрузки: диапазонный
                   переворот утащил бы её вместе с кусками. Она обязана
                   остаться на своей позиции, а куски — обменяться местами
                   вокруг неё. */
                CHECK(a.v[1].kind == D2K_EMIT_FAKE, "фальшивка обязана остаться на своём месте — посередине");
                CHECK(a.v[0].kind == D2K_EMIT_PAYLOAD && a.v[0].seq == 1010 && a.v[0].len == 54,
                      "первым обязан уйти хвост");
                CHECK(a.v[2].kind == D2K_EMIT_PAYLOAD && a.v[2].seq == 1000 && a.v[2].len == 10,
                      "голова обязана уйти последней");
            }
            CHECK(a.fate == D2K_ORIG_DROP, "нагрузку выпустили сами — оригинал обязан сниматься");
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- обратный порядок: без разрезов вовсе ----------------------------- */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_seqovl_reverse, sizeof plan_seqovl_reverse, &p, err, sizeof err) == 0,
              "план с перекрытием и обратным порядком не загрузился");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            init_pkt(&in, 1);
            /* Кусок один, переворачивать нечего. У старого цикла `j - 1`
               считался ДО проверки `j >= 1`, и на пустом диапазоне это
               уходило в беззнаковое переполнение и запись за пределы v —
               ровно тот класс входа (один кусок и меньше), для которого
               защиты не было вовсе. Новый цикл обязан пройти его без единой
               итерации сам по себе, не полагаясь на раскладку кучи. */
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "применение не удалось");
            CHECK(a.n == 1, "перекрытие без разреза даёт один кусок и при обратном порядке");
            if (a.n == 1) {
                CHECK(a.v[0].kind == D2K_EMIT_PAYLOAD, "единственная посылка обязана остаться куском нагрузки");
                CHECK(a.v[0].seq == in.seq - 2, "перевернуть один кусок значит не менять его вовсе");
                CHECK(a.v[0].len == in.payload_len, "длина куска не должна была измениться");
                CHECK(a.v[0].pre_len == 2, "приставка перекрытия обязана остаться на месте");
            }
            CHECK(a.fate == D2K_ORIG_DROP, "нагрузку выпустили сами — оригинал обязан сниматься");
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- обратный порядок: полная связка (everythingPlan) ----------------- */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_everything_reverse, sizeof plan_everything_reverse, &p, err, sizeof err) == 0,
              "план полной связки не загрузился");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            init_pkt(&in, 1);
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "применение полной связки не удалось");
            /* sni_off=10, sni_len=8 (init_pkt) → середина имени = 14. Резы в
               1 и 14 дают три куска [0,1), [1,14), [14,64) — фальшивка и три
               куска. */
            CHECK(a.n == 4, "ожидались фальшивка и три куска (два разреза после reorder-cut)");
            if (a.n == 4) {
                CHECK(a.v[0].kind == D2K_EMIT_FAKE && a.v[0].seq == 1000,
                      "фальшивка обязана остаться первой и при перекрытии, и при разрезах");
                /* Переворот меняет местами только КРАЙНИЕ куски нагрузки —
                   хвост [mid,n) первым, голова [0,1) последней, — средний
                   кусок [1,mid) остаётся на своей позиции; номера
                   последовательности не пересчитаны заново: обмен местами
                   переносит содержимое целиком, включая уже вычисленный
                   seq. */
                CHECK(a.v[1].kind == D2K_EMIT_PAYLOAD && a.v[1].seq == 1014 && a.v[1].len == 50,
                      "первым среди кусков обязан идти хвост [mid,n), с тем же номером, что и до перестановки");
                CHECK(a.v[1].pre_len == 0, "приставка не должна была попасть на хвост");
                CHECK(a.v[2].kind == D2K_EMIT_PAYLOAD && a.v[2].seq == 1001 && a.v[2].len == 13,
                      "средним обязан остаться кусок [1,mid) — переворот его не касается");
                CHECK(a.v[2].pre_len == 0, "приставка не должна была попасть на средний кусок");
                CHECK(a.v[3].kind == D2K_EMIT_PAYLOAD && a.v[3].len == 1,
                      "голова [0,1) обязана идти последней и в полной связке");
                /* Приставка перекрытия остаётся только у головы (куска,
                   покрывающего начало нагрузки) — независимо от того, на
                   каком месте в списке посылок она в итоге оказалась. */
                CHECK(a.v[3].pre_len == 2 && a.v[3].pre != NULL &&
                      a.v[3].pre[0] == 0xAA && a.v[3].pre[1] == 0xBB,
                      "приставка перекрытия обязана остаться у головы");
                CHECK(a.v[3].seq == in.seq - 2,
                      "номер головы обязан остаться сдвинутым назад на длину приставки");
            }
            CHECK(a.fate == D2K_ORIG_DROP, "нагрузку выпустили сами — оригинал обязан сниматься");
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- разрез по середине ИМЕНИ, а не середине пакета (reorder-cut) ----- */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_split_sni_middle, sizeof plan_split_sni_middle, &p, err, sizeof err) == 0,
              "план с разрезом по середине имени не загрузился");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            /* sni_off=10, sni_len=8 (init_pkt) → середина имени = 10+8/2 = 14. */
            init_pkt(&in, 1);
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "разрез по середине имени не применился");
            CHECK(a.n == 2, "разрез по середине имени обязан дать два куска");
            if (a.n == 2) {
                CHECK(a.v[0].seq == 1000 && a.v[0].len == 14, "первый кусок не по середине ИМЕНИ");
                CHECK(a.v[1].seq == 1014 && a.v[1].len == 50, "второй кусок не по середине ИМЕНИ");
            }
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- та же середина имени: без SNI якорь ОТКАЗЫВАЕТ, а не подменяется
       серединой ПАКЕТА молча — §2.5, тот же довод, что у ANCHOR_SNI_START. */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_split_sni_middle, sizeof plan_split_sni_middle, &p, err, sizeof err) == 0,
              "план не загрузился повторно (середина имени без SNI)");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            init_pkt(&in, 0); /* SNI в пакете нет */
            CHECK(d2k_plan_apply(p, NULL, &in, &a) != 0,
                  "середина имени без SNI обязана давать отказ, а не середину пакета");
            CHECK(a.n == 0, "при отказе действий быть не должно");
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- зажим снизу: короткое имя не даёт вырожденный кусок --------------- */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_split_sni_middle, sizeof plan_split_sni_middle, &p, err, sizeof err) == 0,
              "план не загрузился повторно (зажим снизу)");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            memset(&in, 0, sizeof in);
            in.payload = hello; /* содержимое не важно — проверяем смещения */
            in.payload_len = 20;
            in.seq = 5000;
            in.have_sni = 1;
            in.sni_off = 0;
            in.sni_len = 2; /* сырая середина = 0+2/2 = 1; донор зажимает в 2 */
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "зажатый снизу разрез не применился");
            CHECK(a.n == 2, "зажатый снизу разрез обязан дать два куска");
            if (a.n == 2) {
                CHECK(a.v[0].len == 2, "зажим снизу не сработал: рез обязан быть в 2, а не в 1");
                CHECK(a.v[1].seq == 5002 && a.v[1].len == 18, "второй кусок не от зажатой позиции");
            }
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- зажим сверху: середина не уходит в конец нагрузки или дальше ------ */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_split_sni_middle, sizeof plan_split_sni_middle, &p, err, sizeof err) == 0,
              "план не загрузился повторно (зажим сверху)");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            memset(&in, 0, sizeof in);
            in.payload = hello;
            in.payload_len = 10;
            in.seq = 6000;
            in.have_sni = 1;
            in.sni_off = 8;
            in.sni_len = 4; /* сырая середина = 8+4/2 = 10, не меньше длины нагрузки (10) */
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "зажатый сверху разрез не применился");
            CHECK(a.n == 2, "зажатый сверху разрез обязан дать два куска");
            if (a.n == 2) {
                CHECK(a.v[0].len == 9, "зажим сверху не сработал: рез обязан быть в payload_len-1=9");
                CHECK(a.v[1].seq == 6009 && a.v[1].len == 1, "второй кусок не от зажатой позиции");
            }
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- порядок: резы в 1 и на середине имени дают донорские три куска ---- */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_reorder_by_name, sizeof plan_reorder_by_name, &p, err, sizeof err) == 0,
              "план разреза по имени с обратным порядком не загрузился");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            /* sni_off=10, sni_len=8 (init_pkt) → середина имени = 14. Резы в 1
               и 14 дают [0,1), [1,14), [14,64); обратный порядок кладёт их на
               провод как [14,64), [1,14), [0,1) — ровно донорская
               последовательность (raw_linux.go:667-690: seq 268:344, затем
               seq 2:268, затем seq 1:2, одинокий первый байт последним).
               Проверяем СМЕЩЕНИЯМИ и ПОРЯДКОМ, а не числом кусков: порядок
               здесь и есть предмет проверки. */
            init_pkt(&in, 1);
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "применение не удалось");
            CHECK(a.n == 3, "два реза обязаны дать три куска");
            if (a.n == 3) {
                CHECK(a.v[0].kind == D2K_EMIT_PAYLOAD && a.v[0].seq == 1014 && a.v[0].len == 50,
                      "первым обязан идти хвост [mid,n)");
                CHECK(a.v[1].kind == D2K_EMIT_PAYLOAD && a.v[1].seq == 1001 && a.v[1].len == 13,
                      "вторым обязана идти середина [1,mid)");
                CHECK(a.v[2].kind == D2K_EMIT_PAYLOAD && a.v[2].seq == 1000 && a.v[2].len == 1,
                      "последним обязан идти одинокий первый байт [0,1)");
            }
            CHECK(a.fate == D2K_ORIG_DROP, "нагрузку выпустили сами — оригинал обязан сниматься");
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- два реза и фальшивка между кусками: счёт посылок ----------------- */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_between_two_splits, sizeof plan_between_two_splits,
                            &p, err, sizeof err) == 0,
              "план с двумя резами и фальшивкой между кусками не загрузился");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            /* sni_off=10, sni_len=8 → середина имени 14; резы в 1 и 14 дают
               куски [0,1), [1,14), [14,64) и два места для фальшивки. */
            init_pkt(&in, 1);
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "применение не удалось");
            CHECK(a.n == 7, "три куска и четыре фальшивки — семь посылок");
            if (a.n == 7) {
                CHECK(a.v[0].kind == D2K_EMIT_PAYLOAD && a.v[0].len == 1,
                      "первым обязан идти кусок [0,1)");
                CHECK(a.v[1].kind == D2K_EMIT_FAKE && a.v[2].kind == D2K_EMIT_FAKE,
                      "за первым куском обязаны идти две копии фальшивки");
                CHECK(a.v[3].kind == D2K_EMIT_PAYLOAD && a.v[3].len == 13,
                      "третьим обязан идти кусок [1,14)");
                CHECK(a.v[4].kind == D2K_EMIT_FAKE && a.v[5].kind == D2K_EMIT_FAKE,
                      "во втором разрезе фальшивка обязана быть выпущена снова");
                CHECK(a.v[6].kind == D2K_EMIT_PAYLOAD && a.v[6].len == 50,
                      "последним обязан идти хвост [14,64)");
            }
            CHECK(a.fate == D2K_ORIG_DROP, "нагрузку выпустили сами — оригинал обязан сниматься");
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    /* --- плечо донора fakedsplit-x7 целиком ------------------------------- */
    {
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_fakedsplit_x7, sizeof plan_fakedsplit_x7,
                            &p, err, sizeof err) == 0,
              "плечо fakedsplit-x7 не загрузилось");
        if (p) {
            d2k_pkt in;
            d2k_actions a;
            init_pkt(&in, 1);
            CHECK(d2k_plan_apply(p, NULL, &in, &a) == 0, "применение не удалось");
            CHECK(a.n == 17, "три куска и дважды по семь фальшивок — семнадцать посылок");
            CHECK(a.n <= D2K_RESULT_MAX,
                  "самое длинное плечо донора обязано помещаться в результат: "
                  "иначе оно отвергается на каждой цели и не проверяется вовсе");
            if (a.n == 17) {
                size_t fakes = 0, chunks = 0;
                for (size_t i = 0; i < a.n; i++) {
                    if (a.v[i].kind == D2K_EMIT_FAKE) { fakes++; }
                    if (a.v[i].kind == D2K_EMIT_PAYLOAD) { chunks++; }
                }
                CHECK(fakes == 14, "фальшивок обязано быть четырнадцать");
                CHECK(chunks == 3, "кусков нагрузки обязано быть три");
            }
            d2k_actions_free(&a);
            d2k_plan_free(p);
        }
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("применение: все проверки прошли\n");
    return 0;
}
