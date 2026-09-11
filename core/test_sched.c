/* test_sched.c — развилка по транспорту и то, что вокруг неё.
 *
 * ГЛАВНАЯ ПРОВЕРКА ЗАДАЧИ 5: подозрение по TCP уходит в дерево вердиктов,
 * подозрение по UDP — в вопросник QUIC, и никогда наоборот. Ради этого шва
 * переписан план, и он же — единственное место, где две половины движка
 * встречаются.
 *
 * СЕТИ ЗДЕСЬ НЕТ. Оба сетевых оракула подменены через d2k_sched_tcp_hook и
 * d2k_sched_quic_hook — тот же приём, что d2k_mark_hook (d2k_meas.h), и по той
 * же причине: тест обязан утверждать развилку одинаково и на машине
 * разработки, и на роутере, а не зависеть от того, что сегодня отвечает
 * настоящий instagram.com. Датапат подменён обычным socketpair: планировщик
 * пишет в него команды, тест их читает.
 *
 * ПОДОЗРЕНИЕ НЕ НЕСЁТ ИМЕНИ. На проводе D2K_EV_SUSPECT — это ключ потока и код
 * причины, и только (core/link.c, разбор события; datapath/include/d2k_ctl.h).
 * Имя цели приходит РАНЬШЕ, отдельным D2K_EV_HELLO, и планировщик обязан их
 * связать по ключу. Go-сторона делает ровно это (controller.go, Handle:
 * `c.remember(ev.Key, ev.Name)` на EvHello). Поэтому каждый случай ниже сперва
 * шлёт приветствие и лишь затем подозрение: тест, который клал бы имя прямо в
 * подозрение, проверял бы путь, которого на проводе не существует. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_compose_internal.h"
#include "d2k_sched.h"

/* Что планировщик говорил о себе. Нужен не для красоты: узнавание коробки
   снаружи иначе НЕ отличить от совпадения имени — имя коробки выводится из
   отпечатка, поэтому вторая цель с тем же отпечатком попадёт в ту же запись
   каталога и БЕЗ узнавания. Отличает их ровно одно: пришли ли готовые планы
   узнанной коробки в кандидаты. Про это планировщик говорит, и только по
   этому проверка честна (первая редакция этой проверки смотрела на число
   коробок и проходила даже при выключенном d2k_catalog_match). */
static char saidbuf[16384];
static void collect_say(void *ctx, const char *line) {
    (void)ctx;
    size_t n = strlen(saidbuf);
    snprintf(saidbuf + n, sizeof saidbuf - n, "%s\n", line);
}
static int said(const char *needle) { return strstr(saidbuf, needle) != NULL; }

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { printf("ПРОВАЛ: %s\n", (msg)); fails++; } } while (0)

/* --- подменённые оракулы ------------------------------------------------- */

static int tcp_calls, quic_calls;
static d2k_verdict tcp_answer = D2K_V_OPAQUE;
static d2k_verdict quic_answer = D2K_V_OPAQUE;
static char tcp_last_ip[64], quic_last_sni[256];

static d2k_vres stub_tcp(const char *ip, uint16_t port, d2k_hello trigger,
                         d2k_hello control, uint32_t mark, int repeats,
                         uint32_t gap_us, uint32_t wait_ms) {
    (void)port; (void)trigger; (void)control; (void)mark;
    (void)repeats; (void)gap_us; (void)wait_ms;
    tcp_calls++;
    snprintf(tcp_last_ip, sizeof tcp_last_ip, "%s", ip ? ip : "");
    d2k_vres r;
    memset(&r, 0, sizeof r);
    r.verdict = tcp_answer;
    snprintf(r.reason, sizeof r.reason, "подменённое дерево вердиктов");
    return r;
}

/* Проба на объём подменена: иначе планировщик гонял бы настоящую лестницу
   HTTP-запросов к стенду, который TLS не умеет, и тест мерил бы это. */
static int vol_calls;
static d2k_vol_verdict vol_answer = D2K_VOL_PASSED;

static d2k_vol_result stub_vol(const char *ip, uint16_t port, const char *sni,
                               int plain, uint32_t mark) {
    (void)ip; (void)port; (void)sni; (void)plain; (void)mark;
    vol_calls++;
    d2k_vol_result r;
    memset(&r, 0, sizeof r);
    r.verdict = vol_answer;
    r.at_kb = 20;
    snprintf(r.reason, sizeof r.reason, "подменённая проба объёма");
    return r;
}

static d2k_vres stub_quic(const char *ip, uint16_t port, const char *sni,
                          d2k_hello trigger, d2k_hello control, uint32_t mark) {
    (void)ip; (void)port; (void)trigger; (void)control; (void)mark;
    quic_calls++;
    snprintf(quic_last_sni, sizeof quic_last_sni, "%s", sni ? sni : "");
    d2k_vres r;
    memset(&r, 0, sizeof r);
    r.verdict = quic_answer;
    snprintf(r.reason, sizeof r.reason, "подменённый вопросник QUIC");
    return r;
}

/* --- события ------------------------------------------------------------- */

/* Адрес «сервера» в ключах событий. 127.0.0.1 и НЕ 443 — потому что
   планировщик, задавая вопросы о свойствах, действительно идёт к этому адресу
   настоящим сокетом (d2k_props_contact). Поставь сюда чужой адрес — и модульный
   тест начал бы ходить в интернет, а его вердикт зависел бы от того, что
   сегодня отвечает чужой сервер. Порт подставляет стенд, когда он нужен. */
static uint16_t g_server_port = 1; /* 1 — заведомо никто не слушает */

static d2k_ev ev_hello(uint8_t transport, uint16_t cport, const char *name) {
    d2k_ev e;
    memset(&e, 0, sizeof e);
    e.kind = D2K_EV_HELLO;
    e.transport = transport;
    /* Сервер — тот конец, чей порт НЕ эфемерный (server_of в sched.c);
       клиентские порты здесь всегда 4xxxx, серверный — маленький. */
    e.low_ip[0] = 127; e.low_ip[1] = 0; e.low_ip[2] = 0; e.low_ip[3] = 1;
    e.low_port = g_server_port;
    e.high_ip[0] = 192; e.high_ip[1] = 168; e.high_ip[2] = 1; e.high_ip[3] = 67;
    e.high_port = cport;
    snprintf(e.name, sizeof e.name, "%s", name);
    return e;
}

static d2k_ev ev_suspect(uint8_t transport, uint16_t cport) {
    d2k_ev e = ev_hello(transport, cport, "");
    e.kind = D2K_EV_SUSPECT;
    e.name[0] = '\0';
    e.code = 1;      /* подделанный сброс */
    e.ttl = 127;     /* примета коробки: она на фиксированном расстоянии */
    e.ref_ttl = 53;  /* сервер — на своём, разность приметой не является */
    e.tos = 0x88;
    e.ipid = 54321;
    return e;
}

/* Обмен с прикладными данными — §8, порог успеха: бит типа 23 в маске
   встреченных типов (d2k_ev_has_appdata). Без него подтверждения нет и
   привязка в каталог не идёт. */
static d2k_ev ev_exchange(uint8_t transport, uint16_t cport, int appdata) {
    d2k_ev e = ev_hello(transport, cport, "");
    e.kind = D2K_EV_EXCHANGE;
    e.name[0] = '\0';
    e.code = 22;
    e.num = 1380;
    e.seen_types = (uint8_t)(appdata ? 0x0C : 0x04);
    return e;
}

/* Осушает сторону датапата: планировщик пишет туда команды SET_NAME, и
   приветствие-приманка внутри плана весит полтора килобайта. Без чтения
   буфер socketpair переполняется, и d2k_link_set_name встаёт в write
   навсегда — первый прогон этого теста так и повис. На живом датапате
   команды читает d2kd своим циклом; здесь читать обязан тест. */
static int drain_fd = -1;
static void drain(void) {
    uint8_t buf[4096];
    /* Неблокирующее чтение через O_NONBLOCK на самом дескрипторе, а не через
       MSG_DONTWAIT: флага recv нет в чистом POSIX, и -std=c99 его не даёт. */
    while (read(drain_fd, buf, sizeof buf) > 0) { }
}

/* Крутит планировщик заданное число тиков. Сетевой оракул уезжает в рабочий
   поток и возвращается позже; ждать его сном "на авось" здесь нельзя так же,
   как в остальных тестах дерева, поэтому крутим тики — каждый забирает всё,
   что уже готово. Потолок щедрый: на машине разработки подменённый оракул
   возвращается мгновенно, а на медленной сборке — за несколько миллисекунд. */
static void settle(d2k_sched *s) {
    for (int i = 0; i < 400; i++) {
        /* Ждём на будилке планировщика, а не крутим тики вплотную: рабочий
           поток сетевого оракула ещё даже не начинался, когда четыреста
           пустых тиков уже кончились — первая редакция этой функции так и
           плавала, проходя или падая в зависимости от того, успел ли поток
           встать. Миллисекунда на круг — это и ожидание, и уступка
           планировщику ОС, и ровно тот же приём, каким d2kc ждёт событий. */
        struct pollfd pfd;
        pfd.fd = d2k_sched_wake_fd(s); pfd.events = POLLIN; pfd.revents = 0;
        (void)poll(&pfd, 1, 1);
        d2k_sched_tick(s, (int64_t)i * 5);
        drain();
    }
}

static size_t total_bindings(const d2k_catalog *c) {
    size_t n = 0;
    for (size_t i = 0; i < c->n_boxes; i++) { n += c->boxes[i].n_binds; }
    return n;
}

static const d2k_cat_binding *binding_of(const d2k_catalog *c, const char *target,
                                          uint8_t transport) {
    for (size_t i = 0; i < c->n_boxes; i++) {
        for (size_t j = 0; j < c->boxes[i].n_binds; j++) {
            const d2k_cat_binding *b = &c->boxes[i].binds[j];
            if (strcmp(b->target, target) == 0 && b->transport == transport) { return b; }
        }
    }
    return NULL;
}

int main(void) {
    d2k_sched_vol_hook = stub_vol;
    d2k_sched_tcp_hook = stub_tcp;
    d2k_sched_quic_hook = stub_quic;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("ПРОВАЛ: socketpair не создался\n");
        return 1;
    }

    drain_fd = sv[1];
    {
        int fl = fcntl(drain_fd, F_GETFL, 0);
        if (fl >= 0) { (void)fcntl(drain_fd, F_SETFL, fl | O_NONBLOCK); }
    }

    d2k_catalog cat;
    memset(&cat, 0, sizeof cat);

    /* --- подозрение по TCP идёт в дерево вердиктов --------------------- */
    {
        tcp_calls = quic_calls = 0;
        d2k_sched *s = d2k_sched_new(&cat, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик не завёлся");
        d2k_ev h = ev_hello(6, 40001, "instagram.com");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40001);
        CHECK(d2k_sched_event(s, &su) == 1, "поиск по TCP не начат");
        settle(s);
        CHECK(tcp_calls == 1, "дерево вердиктов TCP не вызвано");
        CHECK(quic_calls == 0, "по TCP-подозрению позван вопросник QUIC");
        CHECK(strcmp(tcp_last_ip, "127.0.0.1") == 0,
              "дереву вердиктов достался не адрес сервера из ключа потока");
        d2k_sched_free(s);
    }

    /* --- подозрение по UDP идёт в вопросник QUIC ----------------------- */
    {
        tcp_calls = quic_calls = 0;
        d2k_sched *s = d2k_sched_new(&cat, sv[0], 0x2d);
        d2k_ev h = ev_hello(17, 40002, "instagram.com");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40002);
        CHECK(d2k_sched_event(s, &su) == 1, "поиск по QUIC не начат");
        settle(s);
        CHECK(quic_calls == 1, "вопросник QUIC не вызван");
        CHECK(tcp_calls == 0, "по UDP-подозрению позвано дерево вердиктов TCP");
        CHECK(strcmp(quic_last_sni, "instagram.com") == 0,
              "вопроснику QUIC досталось не имя цели");
        d2k_sched_free(s);
    }

    /* --- подозрение без предшествующего приветствия: имени нет, искать
     * нечего, и это НЕ отказ ------------------------------------------- */
    {
        tcp_calls = quic_calls = 0;
        d2k_sched *s = d2k_sched_new(&cat, sv[0], 0x2d);
        d2k_ev su = ev_suspect(6, 40003);
        CHECK(d2k_sched_event(s, &su) == 0,
              "подозрение по неизвестному потоку начало поиск без имени цели");
        settle(s);
        CHECK(tcp_calls == 0, "поиск без имени всё же позвал дерево вердиктов");
        d2k_sched_free(s);
    }

    /* --- планы двух транспортов не перетирают друг друга --------------- */
    {
        d2k_catalog c2;
        memset(&c2, 0, sizeof c2);
        d2k_sched *s = d2k_sched_new(&c2, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        quic_answer = D2K_V_PREFIX;

        d2k_ev h1 = ev_hello(6, 40010, "instagram.com");
        d2k_sched_event(s, &h1);
        d2k_ev s1 = ev_suspect(6, 40010);
        d2k_sched_event(s, &s1);
        settle(s);
        d2k_ev x1 = ev_exchange(6, 40010, 1);
        d2k_sched_event(s, &x1);

        d2k_ev h2 = ev_hello(17, 40011, "instagram.com");
        d2k_sched_event(s, &h2);
        d2k_ev s2 = ev_suspect(17, 40011);
        d2k_sched_event(s, &s2);
        settle(s);
        d2k_ev x2 = ev_exchange(17, 40011, 1);
        d2k_sched_event(s, &x2);

        const d2k_cat_binding *btcp = binding_of(&c2, "instagram.com", 6);
        const d2k_cat_binding *budp = binding_of(&c2, "instagram.com", 17);
        CHECK(btcp != NULL, "привязка по TCP не записана");
        CHECK(budp != NULL, "привязка по QUIC не записана — план одного транспорта затёр другой");
        d2k_sched_free(s);
        d2k_catalog_free(&c2);
    }

    /* --- вопросы о свойствах: задаются, проходят, и ответ меняет план --- */
    {
        /* Что здесь проверяется. На вердикт «решает содержимое» разрез коробку
           не берёт — и до появления вопросов планировщик получал от
           d2k_compose РОВНО ОДИН запасной план (пустой вектор), ставил его и
           на этом сдавался. Вопрос — это план-кандидат, который проходит
           только если коробку можно отравить ИМЕННО ТАК; его проход пишет
           свойство, и уже по вектору d2k_compose собирает прицельные плечи.
           Проверяем всю цепочку: вопрос задан → подтверждён → зонд сходил к
           цели → обмен с прикладными данными по ЕГО потоку → свойство
           записано → кандидатов стало больше одного.

           Цель — настоящий слушающий сокет на локалхосте: планировщик идёт к
           ней НАСТОЯЩИМ соединением (d2k_props_contact), и местный порт
           назначает ядро. Узнать его вовремя может только тот, кто принял
           соединение, — отсюда стенд, а не догадка. */
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(lfd >= 0, "стенд-цель не открылась");
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(0x7f000001);
        /* Порт НЕ эфемерный: сервером планировщик считает тот конец, чей порт
           вне диапазона, из которого ядро раздаёт клиентские (server_of в
           sched.c). Возьми bind(0) — стенд получил бы порт из того же
           диапазона, что и клиент в ключе события, и планировщик пошёл бы
           измерять клиента. Ищем свободный низкий, а не назначаем один: на
           машине разработки он может быть занят. */
        int bound = 0;
        for (uint16_t port = 19400; port < 19500 && !bound; port++) {
            a.sin_port = htons(port);
            bound = (bind(lfd, (struct sockaddr *)&a, sizeof a) == 0);
        }
        CHECK(bound, "стенд-цель не привязалась ни к одному свободному низкому порту");
        socklen_t al = sizeof a;
        CHECK(getsockname(lfd, (struct sockaddr *)&a, &al) == 0, "порт стенда не узнать");
        CHECK(listen(lfd, 4) == 0, "стенд-цель не слушает");
        g_server_port = ntohs(a.sin_port);

        d2k_catalog c8;
        memset(&c8, 0, sizeof c8);
        d2k_sched *s = d2k_sched_new(&c8, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_OPAQUE;

        d2k_ev h = ev_hello(6, 40060, "непрозрачная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40060);
        d2k_sched_event(s, &su);

        /* Крутим до вопроса: он задаётся, когда вернулся вердикт. */
        for (int i = 0; i < 200 && !said("спрашиваю коробку о свойствах"); i++) {
            struct pollfd p2; p2.fd = d2k_sched_wake_fd(s); p2.events = POLLIN; p2.revents = 0;
            (void)poll(&p2, 1, 1);
            d2k_sched_tick(s, (int64_t)i * 5);
            drain();
        }
        CHECK(said("спрашиваю коробку о свойствах"),
              "на вердикт «решает содержимое» вопросы о свойствах не начались");

        /* Подтверждения команды планировщик не ждёт и ждать не может: события
           у датапата лосси по контракту, и привязать ack к своей команде по
           порядку нельзя (см. prop_send_next в sched.c). Зонд уходит к цели
           сразу. */
        int peer = -1;
        for (int i = 0; i < 200 && peer < 0; i++) {
            struct pollfd p2; p2.fd = lfd; p2.events = POLLIN; p2.revents = 0;
            if (poll(&p2, 1, 5) > 0) {
                struct sockaddr_in pa;
                socklen_t pl = sizeof pa;
                peer = accept(lfd, (struct sockaddr *)&pa, &pl);
                if (peer >= 0) { a = pa; }
            }
            d2k_sched_tick(s, (int64_t)i * 5);
            drain();
        }
        CHECK(peer >= 0, "зонд не пришёл к цели после подтверждения плана-вопроса");

        /* Принять соединение — ещё не значит, что планировщик уже ЖДЁТ обмена:
           рабочий поток зонда возвращается позже, чем цель его приняла, и
           событие обмена, посланное раньше, просто некому было бы отнести
           (в T_PROPS_WAIT ни одной задачи). Ждём, пока планировщик сам
           скажет, что ждёт. */
        for (int i = 0; i < 400 && !said("жду обмена"); i++) {
            struct pollfd p3; p3.fd = d2k_sched_wake_fd(s); p3.events = POLLIN; p3.revents = 0;
            (void)poll(&p3, 1, 1);
            d2k_sched_tick(s, (int64_t)i * 5);
            drain();
        }
        CHECK(said("жду обмена"), "планировщик не дошёл до ожидания обмена по вопросу");

        if (peer >= 0) {
            /* Обмен по ЕГО потоку: ключ — настоящий местный порт зонда,
               который знает только принявшая сторона. */
            uint16_t pport = ntohs(a.sin_port);
            d2k_ev x;
            memset(&x, 0, sizeof x);
            x.transport = 6;
            x.low_ip[0] = 127; x.low_ip[3] = 1;
            x.low_port = g_server_port;
            x.high_ip[0] = 127; x.high_ip[3] = 1;
            x.high_port = pport;

            /* СПЕРВА обмен БЕЗ доказательства применения: план мог не встать,
               и тогда зонд шёл к цели голым. Засчитать такой обмен за ответ
               значит записать свойство коробки по измерению не того. */
            x.kind = D2K_EV_EXCHANGE;
            x.code = 22;
            x.num = 1380;
            x.seen_types = 0x0C; /* рукопожатие + прикладные данные */
            d2k_sched_event(s, &x);
            CHECK(said("план к зонду не применялся — не засчитан"),
                  "обмен без доказательства применения засчитан за ответ коробки");
            CHECK(!said("перекрытие слева=нет"),
                  "свойство записано по зонду, который мог идти без плана");

            /* Теперь честно: датапат говорит, что план применён к ПАКЕТАМ
               ЭТОГО потока, и следом приходит обмен. */
            for (int i = 0; i < 400 && !said("зонд вопроса 2 ушёл"); i++) {
                struct pollfd p4; p4.fd = d2k_sched_wake_fd(s); p4.events = POLLIN; p4.revents = 0;
                (void)poll(&p4, 1, 1);
                d2k_sched_tick(s, (int64_t)i * 5);
                drain();
            }
            /* Ждать соединения, а не висеть на accept: если зонд не пришёл
               (а именно так выглядит поломка, которую этот случай и ловит),
               блокирующий accept подвесил бы весь тест вместо честного
               провала. */
            int peer2 = -1;
            {
                struct pollfd pa3;
                pa3.fd = lfd; pa3.events = POLLIN; pa3.revents = 0;
                if (poll(&pa3, 1, 500) > 0) { peer2 = accept(lfd, NULL, NULL); }
            }
            if (peer2 >= 0) {
                struct sockaddr_in pa2;
                socklen_t pl2 = sizeof pa2;
                if (getpeername(peer2, (struct sockaddr *)&pa2, &pl2) == 0) {
                    x.high_port = ntohs(pa2.sin_port);
                }
            }
            x.kind = D2K_EV_APPLIED;
            d2k_sched_event(s, &x);
            x.kind = D2K_EV_EXCHANGE;
            d2k_sched_event(s, &x);
            settle(s);
            if (peer2 >= 0) { close(peer2); }

            CHECK(said("вопрос 2 прошёл") || said("вопрос 3 прошёл"),
                  "проход вопроса не записан — свойство коробки потеряно");
            /* Проход обязан попасть В ВЕКТОР, а не просто в строку лога:
               проверка на «сказал, что прошёл» пропустила бы планировщик,
               который говорит и не записывает. */
            CHECK(said("порядок сегментов=нет") || said("счёт дубликатов=да"),
                  "вопрос прошёл, а вектор остался пустым — свойство не записано");
            CHECK(said("поставил план 1 из"),
                  "после ответа коробки кандидаты не собрались");

            /* Ответ обязан МЕНЯТЬ план, иначе спрашивать незачем. Число
               кандидатов для этого не годится: на «не держит перекрытие
               слева» d2k_compose даёт ровно одно прицельное плечо, и пустой
               вектор тоже даёт один план — запасной. Различаются они
               СОДЕРЖИМЫМ, и сверять надо его. */
            char empty_plan[8][4096], answered_plan[8][4096];
            d2k_props none, answered;
            memset(&none, 0, sizeof none);
            memset(&answered, 0, sizeof answered);
            d2k_props_question_passed(2, &answered);
            size_t n_empty = d2k_compose(&none, D2K_SHAPE_MODERN, "disk.rzd.ru", empty_plan, 8);
            size_t n_answ = d2k_compose(&answered, D2K_SHAPE_MODERN, "disk.rzd.ru", answered_plan, 8);
            CHECK(n_empty >= 1 && n_answ >= 1, "d2k_compose не собрал план ни там, ни там");
            CHECK(n_empty >= 1 && n_answ >= 1 && strcmp(empty_plan[0], answered_plan[0]) != 0,
                  "план по отвеченному вектору совпал с запасным — ответ коробки ничего не изменил");
            close(peer);
        }
        d2k_sched_free(s);
        d2k_catalog_free(&c8);
        close(lfd);
        g_server_port = 1;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* --- узнанная коробка отдаёт свои планы, и успех идёт ЕЙ ----------- */
    {
        d2k_catalog c6;
        memset(&c6, 0, sizeof c6);
        d2k_sched *s = d2k_sched_new(&c6, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;

        /* Первая цель: коробка ещё не известна — заводится новая, по
           отпечатку. */
        d2k_ev h = ev_hello(6, 40050, "первая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40050);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev x = ev_exchange(6, 40050, 1);
        d2k_sched_event(s, &x);
        CHECK(c6.n_boxes == 1, "первый успех не завёл коробку");
        CHECK(c6.n_boxes == 1 && c6.boxes[0].fp.n_sig == 1,
              "у заведённой коробки не записан отпечаток — узнать её потом будет нечем");
        CHECK(c6.n_boxes == 1 && strcmp(c6.boxes[0].id, "box-без-приметы") != 0,
              "коробка заведена без имени по отпечатку");

        /* Вторая цель с ТЕМ ЖЕ отпечатком: коробка обязана узнаться, её план —
           уйти в кандидаты первым, а успех — лечь в ту же коробку, а не в
           клон. */
        size_t boxes_before = c6.n_boxes;
        d2k_ev h2 = ev_hello(6, 40051, "вторая.цель");
        d2k_sched_event(s, &h2);
        d2k_ev su2 = ev_suspect(6, 40051);
        d2k_sched_event(s, &su2);
        settle(s);
        d2k_ev x2 = ev_exchange(6, 40051, 1);
        d2k_sched_event(s, &x2);
        CHECK(c6.n_boxes == boxes_before,
              "вторая цель с тем же отпечатком завела КЛОН коробки вместо узнавания");
        CHECK(binding_of(&c6, "вторая.цель", 6) != NULL, "вторая привязка не записана");
        CHECK(said("готовых планов узнанной коробки"),
              "коробка не узнана: её проверенные планы не попали в кандидаты второй цели");
        CHECK(c6.n_boxes == 1 && c6.boxes[0].n_plans >= 1 &&
              strcmp(c6.boxes[0].plans[0].proto, "tls") == 0,
              "proto записанного плана не \"tls\" — в живом каталоге у всех планов именно он, "
              "и сравнение с транспортом отбрасывало бы каждый настоящий план");
        d2k_sched_free(s);
        d2k_catalog_free(&c6);
    }

    /* --- каталог едет датапату при запуске, а не лежит мёртвым грузом --- */
    {
        /* Каталог с одной коробкой, одним планом и двумя привязками: по имени
           и по адресу. d2k_sched_sync обязан поставить обе — датапат состояния
           между запусками не хранит, и без этого прохода уже изученная цель
           начинала бы поиск заново. */
        d2k_catalog c7;
        memset(&c7, 0, sizeof c7);
        c7.boxes = calloc(1, sizeof *c7.boxes);
        CHECK(c7.boxes != NULL, "каталог не завёлся");
        if (c7.boxes) {
            c7.n_boxes = 1;
            snprintf(c7.boxes[0].id, sizeof c7.boxes[0].id, "box-эталон");
            c7.boxes[0].plans = calloc(1, sizeof *c7.boxes[0].plans);
            c7.boxes[0].n_plans = 1;
            snprintf(c7.boxes[0].plans[0].id, sizeof c7.boxes[0].plans[0].id, "plan-эталон");
            /* "tls", а не "tcp": proto плана — протокол уровня приложения,
               как в живом каталоге (см. known_plans в sched.c). */
            snprintf(c7.boxes[0].plans[0].proto, sizeof c7.boxes[0].plans[0].proto, "tls");
            c7.boxes[0].plans[0].enabled = 1;
            c7.boxes[0].plans[0].text = strdup(
                "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\n"
                "split payload_start +1\norder reverse\n");
            c7.boxes[0].binds = calloc(3, sizeof *c7.boxes[0].binds);
            c7.boxes[0].n_binds = 3;
            for (int i = 0; i < 3; i++) {
                snprintf(c7.boxes[0].binds[i].plan_id, sizeof c7.boxes[0].binds[i].plan_id,
                         "plan-эталон");
                c7.boxes[0].binds[i].transport = 6;
            }
            snprintf(c7.boxes[0].binds[0].kind, sizeof c7.boxes[0].binds[0].kind, "name");
            snprintf(c7.boxes[0].binds[0].target, sizeof c7.boxes[0].binds[0].target, "по.имени");
            c7.boxes[0].binds[0].enabled = 1;
            snprintf(c7.boxes[0].binds[1].kind, sizeof c7.boxes[0].binds[1].kind, "addr");
            snprintf(c7.boxes[0].binds[1].target, sizeof c7.boxes[0].binds[1].target, "1.2.3.4");
            c7.boxes[0].binds[1].enabled = 1;
            /* Третья выключена — ставиться не должна. */
            snprintf(c7.boxes[0].binds[2].kind, sizeof c7.boxes[0].binds[2].kind, "name");
            snprintf(c7.boxes[0].binds[2].target, sizeof c7.boxes[0].binds[2].target, "выключена");
            c7.boxes[0].binds[2].enabled = 0;

            d2k_sched *s = d2k_sched_new(&c7, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            /* Проход идёт ПОРЦИЯМИ: залпом он создавал бы окно, в котором
               датапату некуда сказать про живой трафик (см. d2k_sched_sync_step).
               Крутим его так же, как это делает цикл d2kc — до конца. */
            (void)d2k_sched_sync(s);
            int rounds = 0;
            while (d2k_sched_sync_step(s) && rounds++ < 1000) { drain(); }
            drain();
            CHECK(rounds < 1000, "проход по каталогу не закончился");
            CHECK(!d2k_sched_sync_pending(s), "проход по каталогу остался незакрытым");
            CHECK(said("поставлено планов по подтверждённым привязкам: 2"),
                  "проход по каталогу не сказал, сколько поставил");
            d2k_sched_free(s);
            d2k_catalog_free(&c7);
        }
    }

    /* --- кандидат, применяющийся без обмена, не залипает навсегда ------ */
    {
        d2k_catalog c5;
        memset(&c5, 0, sizeof c5);
        d2k_sched *s = d2k_sched_new(&c5, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        d2k_ev h = ev_hello(6, 40040, "instagram.com");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40040);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(d2k_sched_active(s) == 1, "поиск не дошёл до ожидания обмена");

        /* Два применения без обмена — кандидат обязан смениться, а поиск
           продолжиться (или честно кончиться), но не стоять до истечения
           задачи (десять минут). */
        d2k_ev ap = ev_hello(6, 40040, "");
        ap.kind = D2K_EV_APPLIED;
        ap.name[0] = '\0';
        for (int i = 0; i < 2; i++) { d2k_sched_event(s, &ap); }
        settle(s);
        CHECK(total_bindings(&c5) == 0, "молчаливое применение записано как успех");
        CHECK(d2k_sched_active(s) == 0,
              "кандидат, применившийся дважды без обмена, залип — поиск не двинулся");
        d2k_sched_free(s);
        d2k_catalog_free(&c5);
    }

    /* --- потерянный обмен НЕ улика против плана ------------------------ */
    {
        /* Датапат держит ровно один исходящий кадр и теряет всё, что не
           поместилось (d2k_ctl.h). Пропавший обмен снаружи неотличим от «план
           не сработал» — и без этой проверки планировщик выбрасывал бы
           РАБОЧИЙ план просто потому, что о его успехе не смогли сказать. */
        d2k_catalog c9;
        memset(&c9, 0, sizeof c9);
        d2k_sched *s = d2k_sched_new(&c9, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        d2k_ev h = ev_hello(6, 40070, "молчащая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40070);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(d2k_sched_active(s) == 1, "поиск не дошёл до ожидания обмена");

        d2k_ev ap = ev_hello(6, 40070, "");
        ap.kind = D2K_EV_APPLIED;
        ap.name[0] = '\0';

        /* Между применениями связь сообщает о потерях — молчание перестаёт
           быть уликой, и план обязан остаться. */
        d2k_ev st;
        memset(&st, 0, sizeof st);
        st.kind = D2K_EV_STATS;
        for (int i = 0; i < 6; i++) {
            st.dropped = (uint32_t)(i + 1);
            d2k_sched_event(s, &st);
            d2k_sched_event(s, &ap);
        }
        settle(s);
        CHECK(said("молчание не в счёт"),
              "потери событий не учтены — молчание засчитано как улика против плана");
        CHECK(d2k_sched_active(s) == 1,
              "план выброшен по молчанию, хотя связь в это время теряла события");

        /* А когда потерь нет — молчание снова улика, и поиск идёт дальше. */
        d2k_sched_event(s, &ap);
        d2k_sched_event(s, &ap);
        settle(s);
        CHECK(d2k_sched_active(s) == 0,
              "без потерь связи план так и не сменился — поиск встал");
        d2k_sched_free(s);
        d2k_catalog_free(&c9);
    }

    /* --- обрыв по объёму: дерево вердиктов не зовём, в каталог не пишем -- */
    {
        /* Пока ответ про объём неизвестен, вопрос «режут по имени или по
           адресу» ЛЖЁТ: при блоке по объёму рукопожатие проходит с любым
           именем, и дерево всегда отвечает «по адресу». Поэтому проба идёт
           ПЕРВОЙ, а на её «обрыв» дерево не зовётся вовсе. */
        d2k_catalog cA;
        memset(&cA, 0, sizeof cA);
        d2k_sched *s = d2k_sched_new(&cA, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = 0;
        vol_answer = D2K_VOL_CUT;

        d2k_ev h = ev_hello(6, 40080, "режут.по.объёму");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40080);
        d2k_sched_event(s, &su);
        settle(s);

        CHECK(vol_calls == 1, "проба на объём не вызвана");
        CHECK(tcp_calls == 0,
              "на обрыв по объёму позвано дерево вердиктов — его ответ там ложен");
        CHECK(total_bindings(&cA) == 0, "обрыв по объёму записан в каталог");
        CHECK(said("обрыв по объёму"), "обрыв по объёму не назван в отчёте");
        vol_answer = D2K_VOL_PASSED;
        d2k_sched_free(s);
        d2k_catalog_free(&cA);
    }

    /* --- обмен БЕЗ прикладных данных не подтверждает ничего (§8) ------- */
    {
        d2k_catalog c4;
        memset(&c4, 0, sizeof c4);
        d2k_sched *s = d2k_sched_new(&c4, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        d2k_ev h = ev_hello(6, 40030, "instagram.com");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40030);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev x = ev_exchange(6, 40030, 0); /* только рукопожатие */
        d2k_sched_event(s, &x);
        CHECK(total_bindings(&c4) == 0,
              "обмен без прикладных данных засчитан за успех — §8 требует прикладного обмена");
        d2k_sched_free(s);
        d2k_catalog_free(&c4);
    }

    /* --- отрицательный результат не сохраняется (§10) ------------------ */
    {
        d2k_catalog c3;
        memset(&c3, 0, sizeof c3);
        d2k_sched *s = d2k_sched_new(&c3, sv[0], 0x2d);
        tcp_answer = D2K_V_INCONCLUSIVE;
        d2k_ev h = ev_hello(6, 40020, "безнадёжная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40020);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(total_bindings(&c3) == 0,
              "неудачный поиск оставил след в каталоге — §10 это запрещает");
        CHECK(c3.n_boxes == 0, "неудачный поиск завёл коробку");
        d2k_sched_free(s);
        d2k_catalog_free(&c3);
        tcp_answer = D2K_V_OPAQUE;
    }

    close(sv[0]);
    close(sv[1]);
    d2k_catalog_free(&cat);

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("планировщик: все проверки прошли\n");
    return 0;
}
