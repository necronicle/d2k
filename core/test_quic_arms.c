/* test_quic_arms.c — транспорт и перевод в план для плеч QUIC.
 *
 * ЛЕСТНИЦА ПЛЕЧ ПРОВЕРЯЕТСЯ НЕ ЗДЕСЬ. Боевой порядок вопросов
 * (d2k_quic_strategy_arms -> d2k_quic_original_arms, quicarms.c) держат
 * test_quic_strategy.c, test_quic_original_arms.c и сквозной
 * test_quic_run_order.c: там он проверяется точными счётчиками вопросов и
 * опытов, на том же проводе и с тем же этапом данных, что в поле. Прежде в
 * этом файле стояли ещё двенадцать проверок устаревшего d2k_quic_pick_arm —
 * вместе с самой функцией они удалены: боевых вызывающих у неё не было, а
 * утверждала она отменённое (развёртка TTL 1..255 вместо четырёх значений
 * 3/5/8/12, подтверждение единогласием на отдельном IP, приманка, выведенная
 * из снимка, вместо собственных приманок оригинала).
 *
 * Тем же заходом удалён мёртвый отправитель фрагментации
 * (d2k_quic_ask_frag_hook) и его сборщик двух фрагментов
 * d2k_quic_build_frag2: вызывающих у хука не было ни одного, то есть ни одна
 * собранная им пара никогда не уходила на провод. Проверка его байтов стояла
 * прежде первой частью этого файла; НИЧЕГО из неё не потеряно — всё то же
 * утверждает core/test_ipfrag.c о ЖИВОМ сборщике (d2k_udpfrag_build_ex,
 * которым шлют quicprobe.c, udpruntime.c и datapath/session.c): IHL и версия
 * (f[0]==0x45), total length против реальной длины посылки, TTL, общий
 * Identification у всех фрагментов, MF на всех кроме последнего, точные
 * смещения, верная сумма IP-заголовка и верная сумма UDP по псевдозаголовку
 * — обе СВОИМ кодом теста. Сверх того он проверяет то, чего у удалённого не
 * было вовсе: все четыре боевые формы, тройную нарезку с наложениями,
 * обратный порядок, отказ при id==0 и отсутствие частичного вывода при
 * недостаточной ёмкости, и то же на IPv6.
 *
 * Остаётся то, что про транспорт и про план, и проверяется в две стороны:
 *
 * 1. РЕАЛЬНЫЙ TTL НА ПРОВОДЕ (loopback, IP_RECVTTL) — то, что реально можно
 *    проверить без цензора на пути: приманка действительно уходит с
 *    запрошенным TTL, а сам триггер — обычным. Смерть приманки НЕ ДО сервера
 *    этот стенд доказать не может (на loopback нет промежуточных прыжков) —
 *    и не должен. Рядом — ICMP «порт недоступен» на боевое плечо: вопрос
 *    задан, ответа нет, а не «не измерено».
 * 2. ПЕРЕВОД ИЗМЕРЕННОГО В ПЛАН (d2k_quic_arm_plan, d2k_quic_compose_plan,
 *    d2k_voice_plan, d2k_quic_delay_plan) — текст плана, его грамматика и
 *    отказ на невыразимом плече.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE /* IP_TTL/IP_RECVTTL/INADDR_LOOPBACK на macOS — тот же приём, что в props.c */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_crypto.h"
#include "d2k_meas.h"
#include "d2k_compose.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include "d2k_quicprobe.h"
#include "d2k_quic_arms.h"
#include "d2k_udpruntime.h"
/* d2k_quic_hello_rename — тот же вывод приманки, что у планировщика. */
#include "d2k_quichello.h"
/* d2k_quic_is_initial — им проверяется, что снятые приманки доехали в бинарник
   именно приветствиями, а не чем попало (см. test_blob_catalogue_is_captured). */
#include "d2k_quic.h"
/* Настоящий Initial из RFC 9001, приложение A.2 — тот же вектор, что у
   test_quichello/test_sched. Нужен затем, что приманка теперь ВЫВОДИТСЯ из
   снятого приветствия: выдуманные двадцать байт не пересобираются, и подбор
   честно отказал бы ещё до первого опыта. */
#include "test_quic_vector.h"

static int fails;
#define CHECK(cond, msg)                          \
    do {                                           \
        if (!(cond)) {                             \
            printf("ПРОВАЛ: %s\n", (msg));         \
            fails++;                               \
        }                                          \
    } while (0)

/* Имя, которым подставляется выведенная приманка. Вывод делает тот же
   d2k_quic_hello_rename, которым выводит приманку планировщик (sched.c,
   SCHED_DECOY) — обёртки d2k_quic_decoy_from_trigger над ним больше нет:
   боевых вызывающих у неё не было, а проверять надо пересборку, а не
   обёртку. Боевой подбор берёт собственные приманки оригинала, а не вывод из
   снимка; здесь имя нужно ровно затем, чтобы проверить сам вывод и перевод в
   план. */
#define TEST_DECOY_SNI "disk.rzd.ru"
/* Триггер — настоящий Initial: из него выводится приманка. */
#define g_trig_bytes d2k_test_v1_initial

/* =========================================================================
 * Часть 2: реальный TTL на проводе (127.0.0.1, IP_RECVTTL) — без цензора на
 * пути это не доказывает, что приманка умирает ДО сервера (промежуточных
 * прыжков на loopback нет); проверяет ровно то, что проверяемо: приманка
 * реально уходит с запрошенным TTL, а триггер — обычным, и что после отправки
 * приманки TTL сокета корректно восстанавливается.
 * ========================================================================= */

static uint8_t recv_ttl_of(int fd) {
    uint8_t buf[512];
    uint8_t ctrl[256];
    struct iovec iov = {buf, sizeof buf};
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = ctrl;
    mh.msg_controllen = sizeof ctrl;
    ssize_t n = recvmsg(fd, &mh, 0);
    if (n < 0) {
        return 0xFF; /* часовой: "не пришло" — вызывающий тест сам сверится по числу байт снаружи */
    }
    /* Единственный запрошенный ancillary-тип — IP_RECVTTL, второго не будет,
       поэтому достаточно CMSG_FIRSTHDR без обхода CMSG_NXTHDR: её
       реализация в musl (см. cross-сборку через zig, aarch64-linux-musl)
       сравнивает знаковое с беззнаковым внутри самого макроса — предупреждение
       о чужом заголовке, не о коде этого файла, обходить через цикл незачем,
       когда в цикле и так только один элемент. */
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    if (c != NULL) {
        /* Проверено репродукцией на машине разработки (macOS): ancillary-
           данные о принятом TTL приходят с cmsg_type == IP_RECVTTL (24), а
           НЕ IP_TTL (4) — расхождение с Linux, где cmsg_type для этих же
           данных равен IP_TTL. Принимаем оба, а не гадаем один. */
        if (c->cmsg_level == IPPROTO_IP && (c->cmsg_type == IP_TTL || c->cmsg_type == IP_RECVTTL)) {
            return *(uint8_t *)CMSG_DATA(c);
        }
    }
    return 0xFF;
}

static void test_real_ttl_hook_on_wire(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0, "стенд обязан открыть UDP-сокет");
    if (fd < 0) {
        return;
    }
    int on = 1;
    CHECK(setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof on) == 0,
          "стенд обязан включить IP_RECVTTL, иначе TTL проверить нечем");
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    CHECK(bind(fd, (struct sockaddr *)&a, sizeof a) == 0, "стенд обязан забиндиться на 127.0.0.1");
    socklen_t alen = sizeof a;
    getsockname(fd, (struct sockaddr *)&a, &alen);
    uint16_t port = ntohs(a.sin_port);

    static const uint8_t prefix[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    d2k_hello msg = {g_trig_bytes, sizeof g_trig_bytes, NULL, 0, 0, 0};
    int sent = 0;
    d2k_tally t =
        d2k_quic_ask_ttl_hook("127.0.0.1", port, prefix, sizeof prefix, 5, msg, 300, 0, 1, &sent);
    (void)t;
    CHECK(sent == 1, "реальный оракул TTL обязан реально отправить единственную запрошенную попытку");

    struct pollfd pfd = {fd, POLLIN, 0};
    CHECK(poll(&pfd, 1, 500) > 0, "приманка обязана дойти по loopback");
    uint8_t ttl_prefix = recv_ttl_of(fd);
    CHECK(ttl_prefix == 5, "приманка обязана реально уйти с запрошенным TTL=5, а не с обычным");

    CHECK(poll(&pfd, 1, 500) > 0, "триггер обязан дойти по loopback вторым пакетом");
    uint8_t ttl_trigger = recv_ttl_of(fd);
    CHECK(ttl_trigger != 5, "TTL сокета обязан быть ВОССТАНОВЛЕН перед отправкой триггера — иначе он тоже "
                            "уйдёт укороченным и рискует не дойти до настоящего сервера");
    close(fd);
}

/* ICMP «ПОРТ НЕДОСТУПЕН» НА ПЛЕЧО — ПЛЕЧО «НЕ ПРОШЛО», А НЕ «НЕ ИЗМЕРЕНО».
 *
 * Донор: askArms.ask (z2k-detect/internal/quicprobe/arms.go:69-94) считает
 * вопрос незаданным только при NotBuilt>0; measure (probe.go:573-574) кладёт
 * ECONNREFUSED (probe.go:643/663) в Refused, не в NotBuilt — значит вопрос задан, ответа нет.
 * Настоящий оракул плеча (d2k_quic_ask_arm_hook) на закрытый порт 127.0.0.1. */
static uint16_t g_icmp_port;
static d2k_tally icmp_arm_probe(const d2k_quic_arm_question *q, void *user, int *sent) {
    (void)user;
    return d2k_quic_ask_arm_hook(q, "x.example.com", g_icmp_port, 500, 0, sent);
}

static void test_real_arm_icmp_is_measured_silence(void) {
    int probe = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(probe >= 0, "щуп свободного порта");
    if (probe < 0) return;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(probe, (struct sockaddr *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(probe, (struct sockaddr *)&a, &al);
    g_icmp_port = ntohs(a.sin_port);
    close(probe); /* порт закрыт — настоящий ICMP port-unreachable */

    static const char pool[1][D2K_QUIC_ADDR_LEN] = {"127.0.0.1"};
    d2k_quic_arm_context c;
    memset(&c, 0, sizeof c);
    c.pool = pool; c.n_pool = 1; c.residual = 0; c.probe = icmp_arm_probe; c.marked = 1;
    d2k_quic_arm r = d2k_quic_original_arms(&c);
    CHECK(r.n_trace > 0, "первый вопрос лестницы задан");
    CHECK(r.trace[0].sent == D2K_QUIC_REPEATS && r.trace[0].answered == 0,
          "плечо ушло 3/3 и получило ICMP, ответов 0");
    CHECK(r.trace[0].not_measured == 0,
          "ICMP на плечо — «не прошло» (arms.go:69-94, probe.go:573-574), не «не измерено»");
}

/* ПОДОБРАННОЕ ПЛЕЧО ПЕРЕВОДИТСЯ В ПЛАН, И ПЛАН ЭТОТ ИСПОЛНИМ.
 *
 * До сих пор подбор плеча был вещью в себе: результат некуда было девать.
 * Проверяется три утверждения, и все три обязательны:
 *   - текст плана объявляет UDP и QUIC, а не унаследованные tcp/tls;
 *   - грамматика его принимает (d2k_plan_text_to_hex собирает TLV) — иначе
 *     «план» это строка, которую датапат отвергнет;
 *   - плечи, которые сегодня не выразимы, честно дают отказ, а не подменяются
 *     похожими (§2.5).
 */
static void test_arm_to_plan(void) {
    char plan[8192], err[200], hex[2 * D2K_PLAN_TLV_MAX + 1];
    d2k_quic_arm original = {0};
    original.original = 1; original.kind = D2K_QA_TTL;
    original.copies = 6; original.ttl = 3;
    original.len = 4; memcpy(original.bytes, "\x41\x42\x43\x44", 4);
    CHECK(d2k_quic_arm_plan(&original, original.bytes, original.len, plan, sizeof plan) == 0,
          "original fake must compose");
    CHECK(strstr(plan, "payload 1 41424344\n") != NULL, "exact original fake bytes");
    CHECK(strstr(plan, "repeats=6") != NULL, "TTL must not discard measured repeats");
    CHECK(strstr(plan, "pace ") == NULL, "original has no extra settle delay");
    CHECK(d2k_plan_text_to_hex(plan, hex, sizeof hex, err, sizeof err) == 0,
          "original plan grammar");
    original.frag_kind = 1;
    original.frag_survives = D2K_PROP_YES;
    CHECK(d2k_quic_arm_plan(&original, original.bytes, original.len, plan, sizeof plan) == 0,
          "original fake and fragment must compose together");
    CHECK(strstr(plan, "ipfrag 1\n") && strstr(plan, "repeats=6") &&
          strstr(plan, "d2k-plan 1 7\n"), "fragment combination/version lost");
    CHECK(d2k_plan_text_to_hex(plan, hex, sizeof hex, err, sizeof err) == 0,
          "fragment text grammar");
    original.frag_survives = D2K_PROP_UNKNOWN;
    CHECK(d2k_quic_arm_plan(&original, original.bytes, original.len, plan, sizeof plan) != 0,
          "cannot use unconfirmed fragment survival");
    original.frag_kind = 0;
    CHECK(d2k_quic_arm_plan(&original, (const uint8_t *)"other", 5, plan, sizeof plan) != 0,
          "cannot replace original owned fake");
    d2k_quic_arm frag = {0};
    frag.original=1;frag.kind=D2K_QA_FRAG;frag.frag_survives=D2K_PROP_YES;
    for(int shape=1;shape<=4;shape++) {
        frag.frag_kind=shape;
        CHECK(d2k_quic_arm_plan(&frag,NULL,0,plan,sizeof plan)==0,
              "original fragment-only requires no fake bytes");
        CHECK(strstr(plan,"fake ")==NULL && strstr(plan,"ipfrag "),
              "fragment-only must not invent fake");
        CHECK(d2k_plan_text_to_hex(plan,hex,sizeof hex,err,sizeof err)==0,
              "fragment-only grammar");
    }
    /* ФАЛЬШИВКА, НА КОТОРУЮ ОТВЕТИТ СЕРВЕР, ОБЯЗАНА НЕСТИ ИЗМЕРЕННЫЙ TTL
       (поле 24.10.2026, h3-1024). quic5, quic_google и quic_rutracker —
       настоящие перехваченные Initial: длинный заголовок, фиксированный бит,
       версия 1, 1200 байт. Без TTL такая копия доживает до сервера, сервер
       отвечает ЕЙ (pcap: DCID ответа — SCID фальшивки), а настоящий Initial
       клиента проигрывает гонку: rutracker.org, nnmclub.to, kinozal.me,
       lostfilm.tv открывались у клиента примерно в одном случае из трёх, тогда
       как зонд тот же план подтверждал. Документация zapret о том же:
       фальшивка либо не доходит до сервера, либо доходит и там отбрасывается.
       fake_default_quic (0x40, короткий заголовок) и 0x00…0 (погашенный
       фиксированный бит) сервер отбрасывает сам — им TTL не нужен. */
    {
        size_t rlen = 0;
        const char *rname = NULL;
        const uint8_t *real = d2k_quic_original_blob(0, &rlen, &rname);
        CHECK(real && rlen == 1200 && !strcmp(rname, "quic5"), "блоб quic5 не на месте");
        CHECK(d2k_quic_blob_answerable(real, rlen) == 1,
              "настоящий Initial не распознан как отвечаемый сервером");
        size_t dlen = 0;
        const uint8_t *dflt = d2k_quic_original_blob(3, &dlen, NULL);
        CHECK(d2k_quic_blob_answerable(dflt, dlen) == 0,
              "fake_default_quic (короткий заголовок) принят за настоящий Initial");
        size_t zlen = 0;
        const uint8_t *zero = d2k_quic_original_blob(4, &zlen, NULL);
        CHECK(d2k_quic_blob_answerable(zero, zlen) == 0,
              "датаграмма из нулей принята за настоящий Initial");
        /* ФОРМА, КОТОРУЮ КОРОБКА ЧИТАЕТ, А СЕРВЕР ОБЯЗАН ОТБРОСИТЬ. Правило
           коробки измерено и опубликовано (NTC.Party, ValdikSS 26.05.2022 и
           bolvan 27.07.2022): длина ≥1200, старший бит первого байта, версия в
           байтах 1…4; фиксированный бит в правиле не участвует. Сервер же по
           RFC 9000 §17.3.1 обязан отбросить пакет с нулевым фиксированным
           битом — значит ни гонки, ни нужды в TTL. */
        size_t nlen = 0;
        const char *nname = NULL;
        const uint8_t *nofix = d2k_quic_original_blob(5, &nlen, &nname);
        CHECK(nofix && nlen == 1200 && nname && !strcmp(nname, "quic_initial_nofix"),
              "приманки quic_initial_nofix нет в наборе");
        CHECK(nofix && (nofix[0] & 0x80) && !(nofix[0] & 0x40),
              "форма: длинный заголовок обязателен, фиксированный бит обязан быть снят");
        CHECK(nofix && !nofix[1] && !nofix[2] && !nofix[3] && nofix[4] == 1,
              "версия QUIC 1 обязана стоять в байтах 1…4 — по ним коробка и сечёт");
        CHECK(d2k_quic_blob_answerable(nofix, nlen) == 0,
              "фальшивка с погашенным фиксированным битом принята за отвечаемую сервером");
        CHECK(d2k_quic_original_blob(D2K_QUIC_BLOBS, &nlen, NULL) == NULL,
              "набор приманок отдаёт блоб за своей границей");
        d2k_quic_props np;
        memset(&np, 0, sizeof np);
        d2k_quic_arm live = {0};
        live.original = 1; live.kind = D2K_QA_COPIES; live.copies = 11;
        live.len = rlen; memcpy(live.bytes, real, rlen);
        /* ЗАПРЕТА ПО ФОРМЕ ЗДЕСЬ НЕТ (поле 25.10.2026, h3e-1). Я запрещал план
           с настоящим Initial без TTL — и потерял QUIC у шести целей, которые
           отвечали и у выпуска, и у прошлого кандидата (adguard.com,
           enimerosi.com, kinozal.me, romfea.gr, spzh.eu, katzauction.com):
           гонка с сервером реальна, но случается не всегда, и запрет по форме
           выбрасывает рабочее вместе с гоночным. Надёжность измеряется
           подтверждением плана 3/3 новыми соединениями, а не формой. */
        CHECK(d2k_quic_compose_plan(&live, &np, plan, sizeof plan) == 0,
              "настоящий Initial без TTL плана не дал: запрет по форме вернулся");
        live.kind = D2K_QA_TTL; live.ttl = 3;
        CHECK(d2k_quic_compose_plan(&live, &np, plan, sizeof plan) == 0,
              "настоящий Initial с измеренным TTL плана не дал");
        CHECK(strstr(plan, "ttl=3") != NULL && strstr(plan, "repeats=11") != NULL,
              "TTL или число копий не доехали в план");
        d2k_quic_arm harmless = {0};
        harmless.original = 1; harmless.kind = D2K_QA_COPIES; harmless.copies = 11;
        harmless.len = dlen; memcpy(harmless.bytes, dflt, dlen);
        CHECK(d2k_quic_compose_plan(&harmless, &np, plan, sizeof plan) == 0,
              "отбрасываемая сервером фальшивка без TTL плана не дала");
        d2k_quic_arm nf = {0};
        nf.original = 1; nf.kind = D2K_QA_COPIES; nf.copies = 1;
        nf.len = nlen; if (nofix) memcpy(nf.bytes, nofix, nlen);
        CHECK(d2k_quic_compose_plan(&nf, &np, plan, sizeof plan) == 0,
              "Initial с погашенным фиксированным битом без TTL плана не дал");
        CHECK(strstr(plan, "ttl=") == NULL,
              "безвредной фальшивке TTL не нужен — он сузил бы её без причины");
    }

    /* Тело приманки — выведенное, как и в бою: то же, что подбор и увидит. */
    static uint8_t decoy[2048];
    size_t blen = 0;
    d2k_hello trg = {g_trig_bytes, sizeof g_trig_bytes, NULL, 0, 0, 0};
    CHECK(d2k_quic_hello_rename(trg.bytes, trg.len, TEST_DECOY_SNI, decoy, sizeof decoy, &blen) == 0,
          "приманка не вывелась из снятого приветствия");
    const uint8_t *blob = decoy;

    struct { d2k_quic_arm_kind kind; int copies; int ttl; int ok; const char *what; } c[] = {
        { D2K_QA_BLOB,      0,  0, 0, "legacy diagnostic is not a runtime proof" },
        { D2K_QA_COPIES,   11,  0, 0, "legacy copies are not exported" },
        { D2K_QA_TTL,       0,  3, 0, "legacy TTL is not exported" },
        { D2K_QA_FRAG,      0,  0, 0, "legacy fragment без исходной формы — отказ" },
        { D2K_QA_NOT_FOUND, 0,  0, 0, "плечо не найдено — ставить нечего" },
        { D2K_QA_FLAKY,     0,  0, 0, "измерению верить нельзя" },
    };
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = c[i].kind;
        a.copies = c[i].copies;
        a.ttl = c[i].ttl;
        int rc = d2k_quic_arm_plan(&a, blob, blen, plan, sizeof plan);
        if (!c[i].ok) {
            CHECK(rc != 0, "невыразимое плечо всё-таки дало план");
            continue;
        }
        CHECK(rc == 0, "выразимое плечо не дало плана");
        CHECK(strstr(plan, "proto udp quic") != NULL,
              "план плеча QUIC объявил не тот транспорт или протокол");
        CHECK(strstr(plan, "place=before") != NULL,
              "приманка поставлена не перед правдой — между чем её ставить у датаграммы?");
        CHECK(d2k_plan_text_to_hex(plan, hex, sizeof hex, err, sizeof err) == 0,
              "грамматика не приняла план плеча QUIC");
        if (c[i].kind == D2K_QA_COPIES) {
            CHECK(strstr(plan, "repeats=11") != NULL, "число копий не доехало в план");
        }
        if (c[i].kind == D2K_QA_TTL) {
            CHECK(strstr(plan, "ttl=3") != NULL, "TTL приманки не доехал в план");
        }
    }
}


/* --- ПРИМАНКА ВЫВОДИТСЯ ИЗ ЗАМЕРА, А НЕ ВЫБИРАЕТСЯ ИЗ НАБОРА ---------------
 *
 * Здесь стоял каталог из девяти заготовок и снятых дампов, перебираемый по
 * очереди. Перебор набора — это блокчек, а не замер: длина набора влияла и на
 * цену подбора, и на бюджет, чего быть не должно.
 *
 * Приманка обязана выглядеть для коробки настоящим приветствием ЭТОГО
 * соединения. Ничего более похожего на него, чем оно само, не существует —
 * значит берётся оно, с подменённым именем. */
static void test_decoy_is_derived(void) {
    d2k_hello trg = {g_trig_bytes, sizeof g_trig_bytes, NULL, 0, 0, 0};
    uint8_t out[2048];
    size_t olen = 0;
    char sni[256];

    CHECK(d2k_quic_hello_rename(trg.bytes, trg.len, TEST_DECOY_SNI, out, sizeof out, &olen) == 0,
          "приманка не вывелась из снятого приветствия");
    CHECK(olen > 0 && d2k_quic_is_initial(out, olen),
          "выведенная приманка не Initial — коробка такому не поверит");
    CHECK(d2k_quic_sni(out, olen, sni, sizeof sni) == 0 && strcmp(sni, TEST_DECOY_SNI) == 0,
          "в выведенной приманке стоит не имя приманки");
    /* Имя ПОДМЕНЕНО, а не оставлено: приманка с именем цели ничего не
       отвлекает — коробка прочтёт ровно то, что и собиралась. */
    {
        char orig[256];
        if (d2k_quic_sni(g_trig_bytes, sizeof g_trig_bytes, orig, sizeof orig) == 0) {
            CHECK(strcmp(orig, sni) != 0, "приманка несёт имя цели — отвлекать нечем");
        }
    }
    /* Длина сохранена: длина — часть формы, по которой коробка отличает
       приветствие от чего угодно другого (см. d2k_quichello.h). */
    CHECK(olen == sizeof g_trig_bytes,
          "длина приманки разошлась с длиной снятого приветствия");

    /* Вывести не из чего — честный отказ, а не подстановка заготовки. */
    {
        d2k_hello empty = {NULL, 0, NULL, 0, 0, 0};
        size_t n = 1;
        CHECK(d2k_quic_hello_rename(empty.bytes, empty.len, TEST_DECOY_SNI, out, sizeof out, &n) != 0,
              "приманка «вывелась» из пустого снимка");
    }

}

/* --- ПЛАН ГОЛОСА: приманка перед IP Discovery --------------------------
 *
 * Та же фигура, что у плеча QUIC, — приманка отдельными датаграммами ПЕРЕД
 * первым пакетом потока, — только первый пакет другой: запрос IP Discovery
 * Дискорда. Протокол объявлен своим словом, и датапат отдаёт такой план
 * только голосу (форма D2K_PLAN_SHAPE_VOICE). Копий — десять: унаследовано у
 * боевого профиля discord_udp (strategy=1, «рабочий референс»). */
static void test_voice_plan(void) {
    uint8_t decoy[1200];
    for (size_t i = 0; i < sizeof decoy; i++) { decoy[i] = (uint8_t)(i * 7 + 1); }
    decoy[0] = 0xc3;
    char plan[8192], hex[16384], err[160];
    CHECK(d2k_voice_plan(decoy, sizeof decoy, plan, sizeof plan) == 0,
          "план голоса не собрался");
    CHECK(strstr(plan, "proto udp voice") != NULL, "план голоса объявил не свой протокол");
    CHECK(strstr(plan, "place=before") != NULL, "приманка голоса не перед правдой");
    CHECK(strstr(plan, "repeats=10") != NULL,
          "число копий не унаследовано у боевого профиля (10)");
    CHECK(strstr(plan, "c3080f") != NULL, "байты приманки не доехали в план");
    CHECK(d2k_plan_text_to_hex(plan, hex, sizeof hex, err, sizeof err) == 0,
          "грамматика не приняла план голоса");
    CHECK(d2k_voice_plan(NULL, 0, plan, sizeof plan) != 0,
          "план голоса собрался без приманки");
}

/* --- ПЛАН РАЗНОСА INITIAL-ДАТАГРАММ ------------------------------------ */
static void test_quic_delay_plan(void) {
    char plan[2048], hex[8192], err[160];
    CHECK(d2k_quic_delay_plan(plan, sizeof plan) == 0, "план разноса не собрался");
    CHECK(strstr(plan, "proto udp quic") != NULL, "план разноса объявил не тот протокол");
    CHECK(strstr(plan, "delay 15000") != NULL,
          "выдержка не унаследована у D2K_PACE_SETTLE_US");
    CHECK(strstr(plan, "payload") == NULL,
          "в плане разноса завелась приманка — резать и подменять датаграмму нечем");
    CHECK(d2k_plan_text_to_hex(plan, hex, sizeof hex, err, sizeof err) == 0,
          "грамматика не приняла план разноса");
    CHECK(d2k_quic_delay_plan(plan, 10) != 0, "план собрался в буфер на десять байт");
}

/* --- QUIC: «мусор перед Initial» и «длина» становятся планом -------------
 *
 * Донор compose (z2k-detect/internal/quicprobe/questions.go:296-345) склеивает
 * ВСЕ исполнимые приёмы в одну строку:
 *   FakeAhead (плечо askArms) ИЛИ, если его нет, JunkAheadHelps →
 *     --lua-desync=fake:payload=quic_initial:dir=out:
 *                 blob=0x00000000000000000000000000000000:repeats=2
 *   FragArm+FragSurvives → send:ipfrag… + drop
 *   UDPLen → --lua-desync=udplen:payload=quic_initial:dir=out:increment=100
 * Здесь проверяется ровно эта склейка на языке плана D2K. */
static d2k_quic_arm quic_arm_of(d2k_quic_arm_kind kind) {
    d2k_quic_arm a;
    memset(&a, 0, sizeof a);
    a.kind = kind;
    a.original = 1;
    if (kind == D2K_QA_COPIES || kind == D2K_QA_TTL || kind == D2K_QA_BLOB) {
        a.len = 4;
        memcpy(a.bytes, "\x41\x42\x43\x44", 4);
        a.copies = 6;
        if (kind == D2K_QA_TTL) { a.ttl = 5; }
    }
    return a;
}

static void quic_props_compose_checks(void) {
    static const char zero16[] = "payload 1 00000000000000000000000000000000\n";
    static const char junk_fake[] = "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n";
    char plan[4096];
    d2k_quic_props p;
    d2k_quic_arm nf = quic_arm_of(D2K_QA_NOT_FOUND);

    /* Мусор подтверждён, плеча нет — план всё равно есть (прежде: «плечо не
       нашлось»). Ровно 16 нулей, две копии, без TTL, перед Initial. */
    memset(&p, 0, sizeof p);
    p.junk_ahead = D2K_PROP_YES;
    CHECK(d2k_quic_compose_plan(&nf, &p, plan, sizeof plan) == 0,
          "QUIC: «мусор» без плеча не стал планом");
    CHECK(strstr(plan, "proto udp quic\n") != NULL, "QUIC мусор: план не объявил udp/quic");
    CHECK(strstr(plan, zero16) != NULL, "QUIC мусор: не 16 нулевых байт донора");
    CHECK(strstr(plan, junk_fake) != NULL, "QUIC мусор: не две копии перед Initial");
    CHECK(strstr(plan, "ttl=") == NULL, "QUIC мусор: донор TTL мусору не задаёт");
    CHECK(strstr(plan, "udplen") == NULL && strstr(plan, "ipfrag") == NULL,
          "QUIC мусор: в план попало неизмеренное");

    /* Длина подтверждена — действие «удлинить на 100». Executor 9. */
    memset(&p, 0, sizeof p);
    p.longer = D2K_PROP_YES;
    CHECK(d2k_quic_compose_plan(&nf, &p, plan, sizeof plan) == 0,
          "QUIC: «длина» без плеча не стала планом");
    CHECK(strncmp(plan, "d2k-plan 1 9\n", 13) == 0, "QUIC длина: план не требует исполнителя 9");
    CHECK(strstr(plan, "udplen 100\n") != NULL, "QUIC длина: нет действия udplen 100");
    CHECK(strstr(plan, "fake ") == NULL, "QUIC длина: выдумана фальшивка");
    CHECK(strstr(plan, "PROFILE") == NULL, "QUIC длина: PROFILE без основания");

    /* Длина измерена собственным Initial донора — провенанс в тексте плана. */
    /* Провенанс измерения — не часть плана: текст (а значит и имя
       plan-<fnv1a>) одинаков при «длине», измеренной PROFILE и снимком. */
    {
        char plain[4096];
        memcpy(plain, plan, sizeof plain);
        p.longer_profile = 1;
        CHECK(d2k_quic_compose_plan(&nf, &p, plan, sizeof plan) == 0 &&
              strcmp(plan, plain) == 0 && strstr(plan, "PROFILE") == NULL,
              "QUIC длина PROFILE: провенанс изменил текст/идентичность плана");
    }

    /* Оба свойства — одна строка донора, один план. */
    memset(&p, 0, sizeof p);
    p.junk_ahead = D2K_PROP_YES;
    p.longer = D2K_PROP_YES;
    CHECK(d2k_quic_compose_plan(&nf, &p, plan, sizeof plan) == 0 &&
          strstr(plan, zero16) && strstr(plan, junk_fake) && !strstr(plan, "udplen"),
          "QUIC мусор+длина: донор склеивает оба приёма");

    /* Плечо askArms с фальшивкой ВЫТЕСНЯЕТ мусор (switch донора), длина
       добавляется. */
    d2k_quic_arm cp = quic_arm_of(D2K_QA_COPIES);
    CHECK(d2k_quic_compose_plan(&cp, &p, plan, sizeof plan) == 0 &&
          strstr(plan, "payload 1 41424344\n") && strstr(plan, "repeats=6") &&
          !strstr(plan, zero16) && !strstr(plan, "udplen"),
          "QUIC плечо+мусор+длина: не fake плеча + udplen");

    /* Фрагментация + мусор: мусор заменяет отсутствующую фальшивку. */
    d2k_quic_arm fr = quic_arm_of(D2K_QA_FRAG);
    fr.frag_kind = 2;
    fr.frag_survives = D2K_PROP_YES;
    memset(&p, 0, sizeof p);
    p.junk_ahead = D2K_PROP_YES;
    CHECK(d2k_quic_compose_plan(&fr, &p, plan, sizeof plan) == 0 &&
          strstr(plan, "ipfrag 2\n") && !strstr(plan, zero16) && !strstr(plan, "fake "),
          "QUIC фрагменты+мусор: донор ставит мусор перед фрагментами");

    /* Фрагментация + длина: у донора udplen идёт ПОСЛЕ drop, а DROP в
       zapret липкий (nfq2/desync.c verdict_aggregate) — на провод длина не
       попадает. План обязан описывать провод, а не строку. */
    memset(&p, 0, sizeof p);
    p.longer = D2K_PROP_YES;
    CHECK(d2k_quic_compose_plan(&fr, &p, plan, sizeof plan) == 0 &&
          strstr(plan, "ipfrag 2\n") && !strstr(plan, "udplen"),
          "QUIC фрагменты+длина: udplen после drop на провод не попадает");

    /* Ничего не подтверждено / не измерено / измерению не верить. */
    memset(&p, 0, sizeof p);
    p.junk_ahead = D2K_PROP_NO;
    p.longer = D2K_PROP_UNKNOWN;
    CHECK(d2k_quic_compose_plan(&nf, &p, plan, sizeof plan) != 0,
          "QUIC: план без единого подтверждённого приёма");
    d2k_quic_arm fl = quic_arm_of(D2K_QA_FLAKY);
    p.junk_ahead = D2K_PROP_YES;
    CHECK(d2k_quic_compose_plan(&fl, &p, plan, sizeof plan) != 0,
          "QUIC: план из прогона, которому верить нельзя");

    /* Каждый собранный план обязан переводиться в TLV (тот же мост, что
       ставит его в датапат). */
    memset(&p, 0, sizeof p);
    p.junk_ahead = D2K_PROP_YES; p.longer = D2K_PROP_YES; p.longer_profile = 1;
    {
        uint8_t tlv[8192]; size_t n = 0; char err[200];
        int rc = d2k_quic_compose_plan(&nf, &p, plan, sizeof plan);
        CHECK(rc == 0 && d2k_plan_text_to_tlv(plan, tlv, sizeof tlv, &n, err, sizeof err) == 0,
              "QUIC мусор+длина: план не переводится в TLV");
        rc = d2k_quic_compose_plan(&fr, &p, plan, sizeof plan);
        CHECK(rc == 0 && d2k_plan_text_to_tlv(plan, tlv, sizeof tlv, &n, err, sizeof err) == 0,
              "QUIC фрагменты+мусор: план не переводится в TLV");
    }
}

/* Задача 40: планы стратегии из ответов. */
static void quic_strategy_compose_checks(void) {
    char plan[4096];
    uint8_t tlv[8192]; size_t n = 0; char err[200];
    d2k_quic_props p;
    memset(&p, 0, sizeof p);

    /* Остаточное разрешение: РОВНО одна безобидная датаграмма перед Initial —
       то, что мерили (не две копии «мусора» донора). */
    d2k_quic_arm cl;
    memset(&cl, 0, sizeof cl);
    cl.kind = D2K_QA_BLOB; cl.original = 1; cl.strategy = D2K_QS_CLEARANCE;
    cl.len = D2K_QUIC_BENIGN_LEN; cl.copies = 1;
    memcpy(cl.bytes, d2k_quic_benign, D2K_QUIC_BENIGN_LEN);
    p.junk_ahead = D2K_PROP_YES; /* тот же ответ лежит и в свойстве */
    CHECK(d2k_quic_compose_plan(&cl, &p, plan, sizeof plan) == 0 &&
          strstr(plan, "payload 1 00000000000000000000000000000000\n") &&
          strstr(plan, "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n") &&
          !strstr(plan, "ttl=") && !strstr(plan, "pace"),
          "QUIC разрешение: не одна безобидная датаграмма перед Initial");
    CHECK(d2k_plan_text_to_tlv(plan, tlv, sizeof tlv, &n, err, sizeof err) == 0,
          "QUIC разрешение: план не переводится в TLV");
    /* Круг 1 (I2): «длина» взяла, но разрешение мерили без удлинения —
       план ровно «одна безобидная датаграмма перед Initial». */
    p.longer = D2K_PROP_YES;
    CHECK(d2k_quic_compose_plan(&cl, &p, plan, sizeof plan) == 0 &&
          !strstr(plan, "udplen") && !strstr(plan, "ipfrag") && !strstr(plan, "quicsplit") &&
          strstr(plan, "repeats=1 gap_us=0 place=before\n") &&
          strncmp(plan, "d2k-plan 1 9\n", 13) != 0,
          "QUIC разрешение+длина: в план попало неизмеренное удлинение");
    p.longer = D2K_PROP_UNKNOWN;

    /* Разрез CRYPTO: одна запись quicsplit, исполнитель 10, без приманок;
       «длина» с ним не склеивается — такого сочетания никто не мерил. */
    d2k_quic_arm sp;
    memset(&sp, 0, sizeof sp);
    sp.kind = D2K_QA_SPLIT; sp.original = 1; sp.strategy = D2K_QS_SPLIT;
    memset(&p, 0, sizeof p);
    p.split_crypto = D2K_PROP_YES;
    p.longer = D2K_PROP_YES;
    CHECK(d2k_quic_compose_plan(&sp, &p, plan, sizeof plan) == 0 &&
          !strncmp(plan, "d2k-plan 1 10\n", 14) && strstr(plan, "proto udp quic\n") &&
          strstr(plan, "quicsplit 1\n") && !strstr(plan, "fake ") && !strstr(plan, "udplen") &&
          !strstr(plan, "ipfrag"),
          "QUIC разрез: не план quicsplit 1 исполнителя 10 без прочих действий");
    CHECK(d2k_plan_text_to_tlv(plan, tlv, sizeof tlv, &n, err, sizeof err) == 0,
          "QUIC разрез: план не переводится в TLV");
    /* Свойство «кадры» без плеча стратегии плана не даёт: исполнитель
       появился вместе с вопросом стратегии, и только её ответ его ставит. */
    d2k_quic_arm nf;
    memset(&nf, 0, sizeof nf);
    nf.kind = D2K_QA_NOT_FOUND; nf.original = 1;
    memset(&p, 0, sizeof p);
    p.split_crypto = D2K_PROP_YES;
    CHECK(d2k_quic_compose_plan(&nf, &p, plan, sizeof plan) != 0,
          "QUIC: свойство «кадры» само по себе стало планом");
    sp.len=620; sp.bytes[0]=0x40; sp.copies=11;
    CHECK(d2k_quic_compose_plan(&sp,&p,plan,sizeof plan)==0 &&
          strstr(plan,"quicsplit 1") && strstr(plan,"repeats=11") && !strstr(plan,"udplen"),
          "fake x split: composer must preserve the measured product");
    CHECK(d2k_quic_arm_plan(&sp,sp.bytes,sp.len,plan,sizeof plan)==0 &&
          d2k_plan_text_to_tlv(plan,tlv,sizeof tlv,&n,err,sizeof err)==0,
          "fake x split: both composer paths export the product");
    d2k_plan *runtime=NULL;
    CHECK(d2k_plan_load(tlv,n,&runtime,err,sizeof err)==0,"fake x split: runtime loads composer output");
    if(runtime) {
        d2k_pkt in={0}; d2k_actions out={0}; uint8_t expected[1500]; size_t en=0;
        in.payload=d2k_test_v1_initial; in.payload_len=sizeof d2k_test_v1_initial;
        CHECK(d2k_quic_initial_split_crypto(in.payload,in.payload_len,expected,sizeof expected,&en)==0,
              "fake x split: same measured transform builds expected encrypted Initial");
        CHECK(d2k_plan_apply(runtime,NULL,&in,&out)==0 && out.n==12 && out.fate==D2K_ORIG_DROP,
              "fake x split runtime emits eleven prefixes and one reshaped original");
        if(out.n==12) {
            for(size_t k=0;k<11;k++) CHECK(out.v[k].len==sp.len && !memcmp(out.v[k].bytes,sp.bytes,sp.len),
                                          "fake x split exact prefix bytes");
            CHECK(out.v[11].len==en && !memcmp(out.v[11].bytes,expected,en),
                  "fake x split exact encrypted Initial equals measurement transform");
        }
        d2k_actions_free(&out); d2k_plan_free(runtime);
    }
    /* Неполное плечо разреза (не original) — не план. */
    sp.original = 0;
    CHECK(d2k_quic_compose_plan(&sp, &p, plan, sizeof plan) != 0,
          "QUIC разрез: плечо не из замера стало планом");
}

int main(void) {
    quic_props_compose_checks();
    quic_strategy_compose_checks();
    test_real_ttl_hook_on_wire();
    test_real_arm_icmp_is_measured_silence();

    /* Вывод приманки из снятого приветствия: сам он от удалённого подбора не
       зависит, а в план (test_arm_to_plan) его байты попадают. */
    test_decoy_is_derived();
    test_arm_to_plan();
    test_voice_plan();
    test_quic_delay_plan();

    if (fails == 0) {
        printf("плечи QUIC: все проверки прошли\n");
        return 0;
    }
    printf("плечи QUIC: %d провалов\n", fails);
    return 1;
}
