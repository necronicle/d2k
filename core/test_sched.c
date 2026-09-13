/* test_sched.c — развилка по транспорту и то, что вокруг неё.
 *
 * ГЛАВНАЯ ПРОВЕРКА ЗАДАЧИ 5: подозрение по TCP уходит в дерево вердиктов,
 * подозрение по UDP — в вопросник QUIC, и никогда наоборот. Ради этого шва
 * переписан план, и он же — единственное место, где две половины движка
 * встречаются.
 *
 * СЕТИ ЗДЕСЬ НЕТ. Сетевые оракулы подменены через d2k_sched_tcp_hook,
 * d2k_sched_quic_hook, d2k_sched_vol_hook и d2k_sched_ver_hook — тот же приём,
 * что d2k_mark_hook (d2k_meas.h), и по той же причине: тест обязан утверждать
 * развилку одинаково и на машине разработки, и на роутере, а не зависеть от
 * того, что сегодня отвечает настоящий instagram.com. Датапат подменён обычным
 * socketpair: планировщик пишет в него команды, тест их читает.
 *
 * ЧТО СЧИТАЕТСЯ ПОДТВЕРЖДЕНИЕМ. Две вещи вместе, и ни одна по отдельности:
 * СОБСТВЕННЫЙ зонд планировщика дошёл до ответа приложения (D2K_VER_APPLICATION
 * от подменённого d2k_sched_ver_hook) И датапат сказал, что ИМЕННО ЭТОТ план
 * применился к ключу ИМЕННО ЕГО потока (D2K_EV_APPLIED с идентификатором
 * плана). Событие обмена с внешним типом записи 23 подтверждением больше не
 * является вовсе: в TLS 1.3 им едет и второй полёт рукопожатия (RFC 8446
 * §5.2). Идентификатор плана тест не выдумывает, а ЧИТАЕТ С ПРОВОДА — из той
 * самой команды, которую планировщик только что отправил (см. last_plan_id
 * ниже): иначе он проверял бы своё представление о связи, а не связь.
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
#include <time.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_compose_internal.h"
#include "d2k_quichello.h"
#include "d2k_sched.h"
#include "d2k_quic.h"
#include "test_quic_vector.h"
#include "d2k_tls13.h"

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

/* Подменённый зонд подтверждения. Уровень задаёт тест; местный порт — тоже,
   потому что планировщик сверяет событие применения со СВОИМ потоком, а
   местный порт настоящего зонда назначает ядро. ver_fail_first позволяет
   «провалить» первые обращения: так проверяется, что очередь кандидатов
   движется сама, без пользователя. */
static int ver_calls;
static int ver_fail_first;
static uint8_t ver_last_transport;
static d2k_ver_level ver_answer = D2K_VER_APPLICATION;
static uint16_t ver_answer_port;

/* Подменённый подбор плеча QUIC: настоящий ходит в сеть десятками опытов, а
   тест обязан утверждать поведение планировщика, не выходя наружу. */
static d2k_quic_arm_kind arm_kind = D2K_QA_BLOB;
static int arm_calls;

static d2k_quic_arm stub_arm(const char *ip, uint16_t port, const char *sni,
                             const char *decoy_sni, d2k_hello trigger, uint32_t mark) {
    (void)ip; (void)port; (void)sni; (void)decoy_sni; (void)trigger; (void)mark;
    arm_calls++;
    d2k_quic_arm a;
    memset(&a, 0, sizeof a);
    a.kind = arm_kind;
    a.copies = 6;
    a.ttl = 3;
    a.probes = 4;
    snprintf(a.reason, sizeof a.reason, "подменённый подбор");
    return a;
}

static size_t ver_last_wire;

/* Что подменённый зонд говорит про имя сервера: -1 «сказать нечего» (так
   ведёт себя стенд без сертификата), 0 — измеренное несовпадение, 1 —
   совпадение. */
static int ver_name_ok = -1;

/* Умеет ли подменённый зонд такой транспорт. Ноль — умеет (так он вёл себя
   всегда), единица — «не про кандидата, а про транспорт». */
static int ver_unsupported;

/* Сокет зонда приходит УЖЕ ЗАНЯТЫМ (под его порт поставлен пробный план).
   Подменённый зонд в сеть не ходит, но владение обязан взять: иначе каждый
   опыт течёт дескриптором, и тест упрётся в их предел. */
static int ver_last_fd = -2;
static d2k_ver_result stub_ver(int use_fd, const char *ip, uint16_t port, uint8_t transport,
                               const char *sni, int deadline_ms, size_t hello_wire) {
    ver_last_fd = use_fd;
    if (use_fd >= 0) { close(use_fd); }
    (void)ip; (void)port; (void)sni; (void)deadline_ms;
    ver_last_wire = hello_wire;
    ver_calls++;
    ver_last_transport = transport;
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    /* «Сказать нечего», а не «чужое имя»: ноль здесь значил бы ИЗМЕРЕННОЕ
       несовпадение, и обнуление структуры молча отменяло бы все
       подтверждения теста. */
    r.name_ok = ver_name_ok;
    r.unsupported = ver_unsupported;
    /* Сокета нет вовсе: ver_close планировщика на отрицательном дескрипторе
       ничего не закрывает, и чужой дескриптор тест не теряет. */
    r.fd = -1;
    r.level = (ver_calls <= ver_fail_first) ? D2K_VER_HANDSHAKE : ver_answer;
    r.status = (r.level == D2K_VER_APPLICATION) ? 200 : 0;
    /* Тот же местный конец, что в ключах событий этого теста (ev_hello). */
    r.local_ip4[0] = 192; r.local_ip4[1] = 168; r.local_ip4[2] = 1; r.local_ip4[3] = 67;
    r.local_port = ver_answer_port;
    snprintf(r.reason, sizeof r.reason, "подменённый зонд");
    return r;
}

static char quic_last_trig[256];
static char quic_last_ctl[256];

static d2k_vres stub_quic(const char *ip, uint16_t port, const char *sni,
                          d2k_hello trigger, d2k_hello control, uint32_t mark) {
    (void)ip; (void)port; (void)mark;
    quic_calls++;
    snprintf(quic_last_sni, sizeof quic_last_sni, "%s", sni ? sni : "");
    /* Чем именно позвали мерить — разбираем ТЕМ ЖЕ разбором, что и коробка.
       Без этого «вопросник вызван» ничего не значит: ему могли подсунуть
       TLS-приветствие, и стенд не заметил бы. */
    quic_last_trig[0] = '\0';
    quic_last_ctl[0] = '\0';
    if (trigger.bytes && trigger.len &&
        d2k_quic_sni(trigger.bytes, trigger.len, quic_last_trig, sizeof quic_last_trig) != 0) {
        snprintf(quic_last_trig, sizeof quic_last_trig, "<не QUIC>");
    }
    if (control.bytes && control.len &&
        d2k_quic_sni(control.bytes, control.len, quic_last_ctl, sizeof quic_last_ctl) != 0) {
        snprintf(quic_last_ctl, sizeof quic_last_ctl, "<не QUIC>");
    }
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

/* СНИМОК ПРИВЕТСТВИЯ QUIC для имени. У TLS ту же роль в этом файле играет
   d2k_hello_from_profile; для QUIC профиля нет и быть не может (см.
   d2k_quichello.h), поэтому снимок делается ровно тем же способом, каким его
   делает продукт: из настоящего снятого Initial с подставленным именем.

   Нужен он теперь КАЖДОМУ поиску по QUIC: без снимка планировщик больше не
   меряет вовсе (T_SHAPE_WAIT) — прежде он подставлял TLS-приветствие, то есть
   байты другого протокола, и «цель молчит» говорило про нашу ошибку. */
static int quic_shape(d2k_ev *sh, const char *name) {
    memset(sh, 0, sizeof *sh);
    sh->kind = D2K_EV_SHAPE;
    sh->transport = 17;
    return d2k_quic_hello_rename(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                 name, sh->shape, sizeof sh->shape, &sh->shape_len);
}

/* Обмен с ВНЕШНИМ типом записи 23 в маске встреченных типов
   (d2k_ev_outer_appdata). Порогом успеха это БОЛЬШЕ НЕ является: в TLS 1.3 тем
   же типом едет второй полёт рукопожатия (RFC 8446 §5.2). Наблюдение не
   повышает достоверность уже подтверждённой записи. */
static d2k_ev ev_exchange(uint8_t transport, uint16_t cport, int appdata) {
    d2k_ev e = ev_hello(transport, cport, "");
    e.kind = D2K_EV_EXCHANGE;
    e.name[0] = '\0';
    e.code = 22;
    e.num = 1380;
    e.seen_types = (uint8_t)(appdata ? 0x0C : 0x04);
    /* ПРИЁМКА вопроса — ответ сервера, а не тип записи (донор,
       acceptServerHello, trigger.go:67-70). Тот же признак, что несёт
       датапат седьмым байтом события. */
    e.server_hello = (uint8_t)(appdata ? 1 : 0);
    return e;
}

/* Осушает сторону датапата: планировщик пишет туда команды SET_NAME, и
   приветствие-приманка внутри плана весит полтора килобайта. Без чтения
   буфер socketpair переполняется, и d2k_link_set_name встаёт в write
   навсегда — первый прогон этого теста так и повис. На живом датапате
   команды читает d2kd своим циклом; здесь читать обязан тест.

   Прочитанное НЕ выбрасывается: из него тест берёт идентификатор плана (см.
   last_plan_id). */
static int drain_fd = -1;
static uint8_t sentbuf[1 << 18];
static size_t sent_len;

static void drain(void) {
    uint8_t buf[4096];
    /* Неблокирующее чтение через O_NONBLOCK на самом дескрипторе, а не через
       MSG_DONTWAIT: флага recv нет в чистом POSIX, и -std=c99 его не даёт. */
    for (;;) {
        ssize_t n = read(drain_fd, buf, sizeof buf);
        if (n <= 0) { break; }
        size_t take = (size_t)n;
        if (take > sizeof sentbuf) { take = sizeof sentbuf; }
        if (sent_len + take > sizeof sentbuf) {
            /* Нужен ПОСЛЕДНИЙ отправленный план, а не вся история: начинаем
               буфер заново, а не отказываемся читать (иначе тест повиснет на
               write планировщика — см. выше). */
            sent_len = 0;
        }
        memcpy(sentbuf + sent_len, buf, take);
        sent_len += take;
    }
}

static void forget_sent(void) { sent_len = 0; }

/* Идентификатор ПОСЛЕДНЕГО отправленного плана — прямо с провода.
 *
 * Планировщик подставляет его в запись REC_ID кандидата перед отправкой
 * (install_next, sched.c) байтами ASCII "plan-xxxxxxxx", добитыми нулями до
 * шестнадцати. Тест ищет эти байты в отправленной команде, а не вычисляет их
 * заново: вторая реализация правила разошлась бы с первой молча, и тест
 * проверял бы себя. Возвращает 1, если нашёл. */
static int last_plan_id(uint8_t out[16]) {
    if (sent_len < 16) { return 0; }
    for (size_t i = sent_len - 16 + 1; i-- > 0;) {
        if (memcmp(sentbuf + i, "plan-", 5) == 0) {
            memcpy(out, sentbuf + i, 16);
            return 1;
        }
    }
    return 0;
}

/* Событие применения ПО КЛЮЧУ ПОТОКА ЗОНДА и с идентификатором того плана,
   который планировщик только что отправил. Вместе с уровнем «приложение» от
   подменённого зонда это и есть полное доказательство. */
static d2k_ev ev_applied(uint8_t transport, uint16_t cport) {
    d2k_ev e = ev_hello(transport, cport, "");
    e.kind = D2K_EV_APPLIED;
    e.name[0] = '\0';
    (void)last_plan_id(e.plan_id);
    return e;
}

/* Отказ отправки ПО КЛЮЧУ ПОТОКА ЗОНДА. code — D2K_REFUSE_*: ненулевой
   означает «посылка плана не покинула машину», то есть опыта не было. Это НЕ
   ответ коробки, и свойство от него меняться не имеет права.
   own_id == 0 подставляет ЧУЖОЙ идентификатор: такой отказ относится к
   другому плану и не должен влиять на нашего кандидата (0009, U2). */
static d2k_ev ev_refused(uint8_t transport, uint16_t cport, uint8_t code, int own_id) {
    d2k_ev e = ev_hello(transport, cport, "");
    e.kind = D2K_EV_REFUSED;
    e.name[0] = '\0';
    e.code = code;
    (void)last_plan_id(e.plan_id);
    if (!own_id) { e.plan_id[0] = (uint8_t)~e.plan_id[0]; }
    return e;
}

/* Модельные часы теста. ТОЛЬКО ВПЕРЁД и общие на весь файл: у планировщика
   есть сроки, измеряемые секундами (потолок шага испытания — пять секунд), и
   тик, поданный «назад», отменял бы их молча. Раньше каждый цикл ожидания
   считал время от нуля своим i*5, и пересечь пятисекундный срок было нечем. */
static int64_t g_now_ms;

/* Один круг: ждём на будилке планировщика, двигаем часы, тикаем, читаем
   команды. Ждём, а не крутим тики вплотную: рабочий поток сетевого оракула ещё
   даже не начинался, когда четыреста пустых тиков уже кончились — первая
   редакция этой функции так и плавала, проходя или падая в зависимости от
   того, успел ли поток встать. Миллисекунда на круг — это и ожидание, и
   уступка планировщику ОС, и ровно тот же приём, каким d2kc ждёт событий. */
static void tick_once(d2k_sched *s) {
    struct pollfd pfd;
    pfd.fd = d2k_sched_wake_fd(s); pfd.events = POLLIN; pfd.revents = 0;
    (void)poll(&pfd, 1, 1);
    g_now_ms += 5;
    d2k_sched_tick(s, g_now_ms);
    drain();
}

static void spin(d2k_sched *s, int rounds) {
    for (int i = 0; i < rounds; i++) { tick_once(s); }
}

/* Крутит планировщик четыреста кругов — две секунды модельного времени.
   Потолок щедрый: на машине разработки подменённый оракул возвращается
   мгновенно, а на медленной сборке — за несколько миллисекунд. */
static void settle(d2k_sched *s) { spin(s, 400); }

/* Крутит до УСТАНОВКИ ПЕРВОГО кандидата и останавливается. Нужно тем
   проверкам, которым надо вмешаться, пока задача ещё испытывает именно его:
   settle() к тому времени прогонит всю очередь.

   Ждём именно УСТАНОВКУ, а не первое обращение зонда. Зонд работает в
   отдельном потоке, и его счётчик виден главному потоку асинхронно: пока
   счётчик доходит, очередной тик успевает забрать результат и объявить
   промах — впрыск опаздывал, и отказ доставался уже СЛЕДУЮЩЕМУ кандидату
   (поймано санитайзерами, где всё медленнее). Установка происходит в самом
   тике, и после неё главный поток гарантированно успевает вмешаться до
   разбора результата.

   drain() обязателен: идентификатор кандидата тест берёт из последней ушедшей
   команды SET_NAME (last_plan_id по sentbuf), а туда она попадает только
   через drain(). Без него отказ строился со старым идентификатором, не
   совпадал с кандидатом и молча пропадал. */
static void spin_until_installed(d2k_sched *s) {
    for (int i = 0; i < 400 && !said("поставил план"); i++) { tick_once(s); }
    drain();
}

/* Перешагивает срок планировщика: сроки считаются секундами, а settle()
   проходит меньше двух секунд модельного времени и потолок не пересекает
   никогда. Живое время при этом не тратится — у планировщика часы приходят
   аргументом, а не из ОС. */
static void skip_ahead(d2k_sched *s, int64_t ms) {
    g_now_ms += ms;
    d2k_sched_tick(s, g_now_ms);
    drain();
}

/* Доводит поиск до конца очереди кандидатов. Каждый неподтверждённый кандидат
   уходит по потолку ожидания применения, а тот считается секундами модельного
   времени — значит нужны прыжки часов, а не долгое кручение. Сорока кругов
   между прыжками хватает с запасом: рабочий поток будит цикл сам, а tick_once
   этого пробуждения и ждёт. */
/* Докручивает проход по каталогу до конца и ЧИТАЕТ провод после каждой
   порции, включая последнюю: последняя возвращает ноль («больше нечего»), уже
   отправив свои команды, и цикл вида while(step) { drain(); } их теряет. */
/* Есть ли байты подстроки в том, что УЖЕ уехало датапату. Нужна там, где
   идентификатор плана не годится: план из каталога несёт идентичность своего
   текста, а не подставленную установкой. */
static int sent_has(const char *needle) {
    size_t n = strlen(needle);
    if (n == 0 || sent_len < n) { return 0; }
    for (size_t i = 0; i + n <= sent_len; i++) {
        if (memcmp(sentbuf + i, needle, n) == 0) { return 1; }
    }
    return 0;
}

static void sync_out(d2k_sched *s) {
    for (int i = 0; i < 1000; i++) {
        int more = d2k_sched_sync_step(s);
        drain();
        if (!more) { break; }
    }
}

static void run_out(d2k_sched *s) {
    for (int i = 0; i < 60 && d2k_sched_active(s); i++) {
        skip_ahead(s, 6000);
        spin(s, 40);
    }
}

static size_t total_bindings(const d2k_catalog *c) {
    size_t n = 0;
    for (size_t i = 0; i < c->n_boxes; i++) { n += c->boxes[i].n_binds; }
    return n;
}

/* Форма приветствия СОБСТВЕННОГО зонда — ИЗМЕРЕННАЯ, а не назначенная.
 *
 * Планировщик записывает её в привязку константой (SCHED_PROBE_SHAPE,
 * sched.c): спрашивать зонд о форме его же приветствия на каждом успехе
 * незачем, она не меняется. Но константа, назначенная из головы, — это тот
 * самый параметр без замера, который здесь запрещён. Поэтому тест ДОБЫВАЕТ
 * её: поднимает клиента TLS 1.3 (core/tls13.c — тот самый, которым ходит
 * зонд) поверх socketpair, снимает с провода его приветствие и отдаёт на
 * разбор d2k_hello_shape — ровно тем же способом, которым планировщик
 * определяет форму снятого приветствия цели.
 *
 * Рукопожатие при этом не состоится (на том конце socketpair никто не
 * отвечает), и это неважно: приветствие уходит ПЕРВЫМ, до любого чтения. */
static d2k_shape probe_hello_shape(void) {
    int p[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) != 0) { return D2K_SHAPE_UNKNOWN; }
    d2k_tls *t = NULL;
    char e[200];
    /* Потолок маленький: ждать здесь нечего, а тест платит за это временем. */
    (void)d2k_tls_connect(p[0], "пример.цель", 50, 0, &t, e, sizeof e);
    d2k_tls_free(t);
    uint8_t buf[2048];
    ssize_t n = read(p[1], buf, sizeof buf);
    close(p[0]);
    close(p[1]);
    if (n <= 0) { return D2K_SHAPE_UNKNOWN; }
    return d2k_hello_shape(buf, (size_t)n);
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

/* Сколько привязок у одной цели по одному транспорту. До задачи 5 ответ был
   «не больше одной» по построению; теперь ключ — тройка с формой приветствия,
   и число записей стало наблюдаемым различием между «обновили» и «завели
   рядом». */
static size_t bindings_of(const d2k_catalog *c, const char *target, uint8_t transport) {
    size_t n = 0;
    for (size_t i = 0; i < c->n_boxes; i++) {
        for (size_t j = 0; j < c->boxes[i].n_binds; j++) {
            const d2k_cat_binding *b = &c->boxes[i].binds[j];
            if (strcmp(b->target, target) == 0 && b->transport == transport) { n++; }
        }
    }
    return n;
}

/* Тот же поиск, но для правки: тест изображает файл, снятый ДО появления
   полей (shape = 0), и файл, где записана ДРУГАЯ форма. Настоящих путей
   завести такую запись у планировщика сегодня нет — зонд один, и форма у
   него одна, — а проверить ключ надо сейчас, а не когда появится второй. */
static d2k_cat_binding *binding_mut(d2k_catalog *c, const char *target, uint8_t transport) {
    for (size_t i = 0; i < c->n_boxes; i++) {
        for (size_t j = 0; j < c->boxes[i].n_binds; j++) {
            d2k_cat_binding *b = &c->boxes[i].binds[j];
            if (strcmp(b->target, target) == 0 && b->transport == transport) { return b; }
        }
    }
    return NULL;
}

/* Один полный проход поиска до подтверждения: подозрение, испытание зондом,
   событие применения по ключу потока зонда. Результат остаётся в каталоге —
   его вызывающий и смотрит; планировщик после прохода закрывается, потому что
   проверяется именно НАКОПЛЕННОЕ в файле, а не живое состояние задачи. Порт
   клиента задаёт вызывающий: по нему сходятся зонд и событие. */
static void confirm_once(d2k_catalog *cat, int link_fd, const char *target,
                         uint16_t cport) {
    d2k_sched *s = d2k_sched_new(cat, link_fd, 0x2d);
    if (!s) { CHECK(0, "планировщик не завёлся"); return; }
    d2k_sched_set_say(s, collect_say, NULL);
    ver_answer_port = cport;
    ver_calls = 0;
    forget_sent();
    d2k_ev h = ev_hello(6, cport, target);
    d2k_sched_event(s, &h);
    d2k_ev su = ev_suspect(6, cport);
    d2k_sched_event(s, &su);
    settle(s);
    d2k_ev ap = ev_applied(6, cport);
    d2k_sched_event(s, &ap);
    spin(s, 40);
    d2k_sched_free(s);
}

int main(void) {
    d2k_sched_vol_hook = stub_vol;
    d2k_sched_tcp_hook = stub_tcp;
    d2k_sched_quic_hook = stub_quic;
    /* Зонд подтверждения тоже подменён: настоящий пошёл бы к 127.0.0.1 своим
       рукопожатием TLS 1.3, а стенд этого теста TLS не умеет — тест мерил бы
       стенд. */
    d2k_sched_ver_hook = stub_ver;
    d2k_sched_arm_hook = stub_arm;

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
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "instagram.com") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(quic_calls == 1, "вопросник QUIC не вызван");
        CHECK(tcp_calls == 0, "по UDP-подозрению позвано дерево вердиктов TCP");
        CHECK(strcmp(quic_last_sni, "instagram.com") == 0,
              "вопроснику QUIC досталось не имя цели");
        d2k_sched_free(s);
    }

    /* --- БЕЗ СНИМКА ПО QUIC НЕ МЕРЯЕМ ВОВСЕ ---------------------------
     *
     * Лаборатория lab-quic.sh 13.09.2026: поиск начинался немедленно и уходил
     * мерить ПРОФИЛЕМ TLS — байтами другого протокола. Сервер на них не
     * отвечает никогда, и вердикт выходил «контрольное имя молчит», то есть
     * измерение рассказывало про нашу ошибку. Профиля холодного старта для
     * QUIC нет и быть не может (d2k_quichello.h), поэтому правильный ответ —
     * подождать форму, а не подставить похожее. */
    {
        tcp_calls = quic_calls = 0;
        d2k_catalog cW;
        memset(&cW, 0, sizeof cW);
        d2k_sched *s = d2k_sched_new(&cW, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        d2k_ev h = ev_hello(17, 40004, "ждём.форму");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40004);
        CHECK(d2k_sched_event(s, &su) == 1, "подозрение по QUIC не завело задачу");
        settle(s);
        CHECK(quic_calls == 0,
              "по QUIC пошли мерить без снимка — профилем TLS, байтами другого протокола");
        CHECK(said("жду форму приветствия"), "ожидание формы не названо вслух");
        CHECK(d2k_sched_active(s) == 1, "задача, ждущая форму, не считается занятой");

        /* Форма пришла — поиск обязан пойти дальше сам, без нового
           подозрения: подозрение уже было, и второго может не случиться. */
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "ждём.форму") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(quic_calls == 1, "после прихода формы поиск не начался");
        CHECK(strcmp(quic_last_trig, "ждём.форму") == 0,
              "мерить пошли не снятым приветствием цели");
        /* КОНТРОЛЬ — тоже QUIC, и с именем приманки: он собирается из того же
           снимка (core/quichello.c). Прежде сюда уезжало TLS-приветствие, и
           базовая живость не подтверждалась никогда. */
        CHECK(strcmp(quic_last_ctl, "disk.rzd.ru") == 0,
              "контроль по QUIC не собран из снимка с именем приманки");
        d2k_sched_free(s);
        d2k_catalog_free(&cW);
    }

    /* --- СНИМОК СОСЕДА ЗАКРЫВАЕТ ХОЛОДНЫЙ СТАРТ QUIC ---------------------
     *
     * Рилсы Instagram у владельца роутера 13.09.2026 не грузились вовсе:
     * ролики едут с хостов `scontent-*.cdninstagram.com`, которые меняются от
     * ролика к ролику, второго обращения к тому же имени не бывает, и задача
     * умирала с «формы приветствия так и не пришло» — три смерти за тридцать
     * секунд листания на живой линии.
     *
     * Байты приветствия задаёт КЛИЕНТ: снимок, снятый с одной цели, годится
     * соседней с переписанным именем (d2k_quic_hello_rename — им уже
     * собирается контроль). Проверяем, что вторая цель мерится СРАЗУ и своим
     * именем, а не ждёт собственного снимка. */
    {
        tcp_calls = quic_calls = 0;
        d2k_catalog cQ;
        memset(&cQ, 0, sizeof cQ);
        d2k_sched *s = d2k_sched_new(&cQ, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);

        d2k_ev h1 = ev_hello(17, 40201, "первая.цель");
        d2k_sched_event(s, &h1);
        d2k_ev su1 = ev_suspect(17, 40201);
        d2k_sched_event(s, &su1);
        settle(s);
        CHECK(quic_calls == 0, "первая цель пошла мерить без снимка");
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "первая.цель") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(quic_calls == 1, "после прихода формы поиск первой цели не начался");

        /* Вторая цель — своего снимка у неё нет и не будет. */
        d2k_ev h2 = ev_hello(17, 40202, "вторая.цель");
        d2k_sched_event(s, &h2);
        d2k_ev su2 = ev_suspect(17, 40202);
        d2k_sched_event(s, &su2);
        settle(s);
        CHECK(quic_calls == 2,
              "вторая цель QUIC ушла ждать собственный снимок — рилсы так и теряются");
        CHECK(strcmp(quic_last_trig, "вторая.цель") == 0,
              "мерить пошли чужим именем: снимок соседа не переименован");
        CHECK(strcmp(quic_last_ctl, "disk.rzd.ru") == 0,
              "контроль из переписанного снимка не собрался");
        d2k_sched_free(s);
        d2k_catalog_free(&cQ);
    }

    /* --- ГОТОВЫЙ ПЛАН УЗНАННОЙ КОРОБКИ СНИМКА НЕ ЖДЁТ -------------------
     *
     * Чтобы ИСПЫТАТЬ подтверждённый план, мерить нечего: зонд QUIC ведёт своё
     * рукопожатие сам, а отпечаток коробки приехал вместе с подозрением.
     * Прежде эта ветка стояла после требования снимка, и цель с готовым
     * планом уходила ждать второго обращения наравне с незнакомой. */
    {
        tcp_calls = quic_calls = 0;
        d2k_catalog cK;
        memset(&cK, 0, sizeof cK);
        cK.boxes = calloc(1, sizeof *cK.boxes);
        CHECK(cK.boxes != NULL, "не удалось создать модель коробки");
        if (cK.boxes) {
            cK.n_boxes = 1;
            d2k_cat_box *b = &cK.boxes[0];
            snprintf(b->id, sizeof b->id, "box-quic-known");
            b->fp.method = D2K_FP_METHOD;
            b->fp.n_sig = 1;
            snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rst");
            b->fp.sig[0].ttl = 127;
            b->fp.sig[0].tos = 0x88;
            b->fp.sig[0].ipid = 54321;
            b->plans = calloc(1, sizeof *b->plans);
            CHECK(b->plans != NULL, "не удалось создать план модели");
            if (b->plans) {
                b->n_plans = 1;
                b->plans[0].enabled = 1;
                b->plans[0].successes = 4;
                snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "quic");
                b->plans[0].text = strdup(
                    "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                    "proto udp quic\npayload 1 hex aabb\n"
                    "fake payload=1 poison=0 repeats=1 gap_us=0 place=before\n"
                    "order forward\n");
                CHECK(b->plans[0].text != NULL, "текст плана не создался");
            }
            if (b->plans && b->plans[0].text) {
                d2k_sched *s = d2k_sched_new(&cK, sv[0], 0x2d);
                saidbuf[0] = '\0';
                d2k_sched_set_say(s, collect_say, NULL);
                ver_answer = D2K_VER_APPLICATION;
                ver_fail_first = 0;
                ver_calls = 0;
                ver_answer_port = 40203;
                d2k_ev h = ev_hello(17, 40203, "новый.хост.цдн");
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(17, 40203);
                d2k_sched_event(s, &su);
                settle(s);
                CHECK(said("коробка узнана"),
                      "готовый план узнанной коробки не испытан без снимка");
                CHECK(quic_calls == 0,
                      "цель с готовым планом пошла мерить, хотя мерить было незачем");
                CHECK(ver_calls >= 1, "готовый план не дошёл до зонда");
                d2k_sched_free(s);
            }
        }
        d2k_catalog_free(&cK);
    }

    /* --- ЗАМЕР ПОСЛЕ ПРОВАЛА ГОТОВЫХ ПЛАНОВ ИДЁТ С КОНТРОЛЕМ ------------
     *
     * Задача QUIC входит в испытание готовых планов БЕЗ приветствий вовсе
     * (коробка узнана, снимка ещё нет — испытать готовый план ими не нужно).
     * Если готовые планы не помогли, начинается замер — и вот ему приветствия
     * нужны оба. На живой линии 13.09.2026 замер стартовал со старым пустым
     * контролем и закончился «вердикта нет (нет контрольного имени)»: вопрос
     * коробке не задавался вовсе, а восемь кандидатов ушли в никуда.
     *
     * Снимок здесь приезжает ПОСЛЕ входа в испытание — ровно как на линии. */
    {
        tcp_calls = quic_calls = 0;
        d2k_catalog cR;
        memset(&cR, 0, sizeof cR);
        cR.boxes = calloc(1, sizeof *cR.boxes);
        CHECK(cR.boxes != NULL, "не удалось создать модель коробки");
        if (cR.boxes) {
            cR.n_boxes = 1;
            d2k_cat_box *b = &cR.boxes[0];
            snprintf(b->id, sizeof b->id, "box-quic-remeasure");
            b->fp.method = D2K_FP_METHOD;
            b->fp.n_sig = 1;
            snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rst");
            b->fp.sig[0].ttl = 127;
            b->fp.sig[0].tos = 0x88;
            b->fp.sig[0].ipid = 54321;
            b->plans = calloc(1, sizeof *b->plans);
            CHECK(b->plans != NULL, "не удалось создать план модели");
            if (b->plans) {
                b->n_plans = 1;
                b->plans[0].enabled = 1;
                b->plans[0].successes = 3;
                snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "quic");
                b->plans[0].text = strdup(
                    "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                    "proto udp quic\npayload 1 hex aabb\n"
                    "fake payload=1 poison=0 repeats=1 gap_us=0 place=before\n"
                    "order forward\n");
                CHECK(b->plans[0].text != NULL, "текст плана не создался");
            }
            if (b->plans && b->plans[0].text) {
                d2k_sched *s = d2k_sched_new(&cR, sv[0], 0x2d);
                saidbuf[0] = '\0';
                d2k_sched_set_say(s, collect_say, NULL);
                /* Зонд доходит только до рукопожатия — готовый план не
                   засчитывается, и планы кончаются. */
                ver_answer = D2K_VER_HANDSHAKE;
                ver_fail_first = 0;
                ver_calls = 0;
                ver_answer_port = 40205;
                d2k_ev h = ev_hello(17, 40205, "остыл.снимок.позже");
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(17, 40205);
                d2k_sched_event(s, &su);
                /* Крутим ровно до установки первого готового плана: задача уже
                   вошла в испытание БЕЗ приветствий, но планы ещё не кончились
                   — ровно то состояние, в котором на линии приехал снимок. */
                spin_until_installed(s);
                CHECK(said("коробка узнана"), "готовый план не пошёл в дело без снимка");
                {
                    d2k_ev sh;
                    CHECK(quic_shape(&sh, "остыл.снимок.позже") == 0, "снимок QUIC не собрался");
                    d2k_sched_event(s, &sh);
                }
                settle(s);
                CHECK(quic_calls == 1,
                      "после провала готовых планов замер не пошёл вовсе");
                CHECK(strcmp(quic_last_ctl, "disk.rzd.ru") == 0,
                      "замер пошёл БЕЗ контрольного имени — вопрос коробке не задан, "
                      "а кандидаты будут потрачены впустую");
                CHECK(strcmp(quic_last_trig, "остыл.снимок.позже") == 0,
                      "мерить пошли не приветствием цели");
                d2k_sched_free(s);
            }
        }
        d2k_catalog_free(&cR);
    }

    /* --- ПРОБНЫЙ ПЛАН СТАВИТСЯ ПОД ПОРТ ЗОНДА, А НЕ ВСЕМ ------------------
     *
     * Испытывает кандидата зонд, а платил за испытание пользователь: план
     * вставал по имени и доставался всем, кто шёл к этой цели. На роутере
     * владельца 13.09.2026 поиск по i.ytimg.com шёл двадцать одну минуту, и
     * всё это время цель работала через раз.
     *
     * Проверяем, что зонду достаётся УЖЕ ЗАНЯТЫЙ сокет: значит порт известен
     * заранее и план поставлен именно под него. */
    {
        d2k_catalog cP;
        memset(&cP, 0, sizeof cP);
        d2k_sched *s = d2k_sched_new(&cP, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_calls = 0;
        ver_last_fd = -2;
        ver_answer_port = 40301;
        d2k_ev h = ev_hello(6, 40301, "испытание.под.портом");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40301);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls >= 1, "зонд не пошёл вовсе");
        CHECK(ver_last_fd >= 0,
              "зонду достался пустой сокет — порт не занят заранее, значит пробный "
              "план встал ВСЕМ, а не одному потоку");
        d2k_sched_free(s);
        d2k_catalog_free(&cP);
    }

    /* --- ПРОБНЫЙ ПЛАН СТАВИТСЯ ПОД ФОРМУ ЗОНДА, А НЕ КЛИЕНТА -------------
     *
     * План ставится РАДИ ИСПЫТАНИЯ, а испытывает его наш зонд: он ведёт своё
     * рукопожатие TLS 1.3, и его приветствие всегда современной формы. Когда
     * форму брали у клиента и она оказывалась другой, план к потоку зонда не
     * применялся вовсе — «зонд прошёл, а применения этого плана к его потоку
     * не было», успех выброшен. На роутере владельца 13.09.2026 таких
     * выброшенных успехов набралось 269. */
    {
        d2k_catalog cS;
        memset(&cS, 0, sizeof cS);
        d2k_sched *s = d2k_sched_new(&cS, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_calls = 0;
        ver_answer_port = 40311;
        forget_sent();
        d2k_ev h = ev_hello(6, 40311, "форма.зонда");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40311);
        d2k_sched_event(s, &su);
        spin_until_installed(s);
        CHECK(said("поставил план"), "кандидат не поставлен вовсе");
        /* Форма стоит байтом сразу ПОСЛЕ имени в теле команды (d2k_ctl.h:
           длина имени, имя, ФОРМА, план). Ищем имя прямо в отправленных
           байтах — вторая реализация разбора разошлась бы с первой молча. */
        {
            drain();
            const char *nm = "форма.зонда";
            size_t nl = strlen(nm);
            int seen = 0, shaped_ok = 0;
            for (size_t i = 0; i + nl + 1 < sent_len; i++) {
                if (memcmp(sentbuf + i, nm, nl) != 0) { continue; }
                seen = 1;
                /* Команд с этим именем в потоке несколько (ARM_SHAPE, DEL_NAME,
                   установка кандидата), и форма есть только у установки.
                   Достаточно, чтобы хоть одна несла форму зонда. */
                if (sentbuf[i + nl] == (uint8_t)D2K_SHAPE_MODERN) { shaped_ok = 1; }
            }
            CHECK(seen, "имя цели не найдено в отправленном вовсе");
            CHECK(shaped_ok,
                  "пробный план ушёл не формой зонда — к его потоку он не применится");
        }
        d2k_sched_free(s);
        d2k_catalog_free(&cS);
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
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;

        /* Зонд «занимает» тот же местный порт, что стоит в ключе событий этой
           цели: планировщик сверяет применение со СВОИМ потоком, и чужой порт
           здесь означал бы чужой поток. */
        ver_answer_port = 40010;
        forget_sent();
        d2k_ev h1 = ev_hello(6, 40010, "instagram.com");
        d2k_sched_event(s, &h1);
        d2k_ev s1 = ev_suspect(6, 40010);
        d2k_sched_event(s, &s1);
        settle(s);
        d2k_ev a1 = ev_applied(6, 40010);
        d2k_sched_event(s, &a1);
        spin(s, 40);

        ver_answer_port = 40011;
        forget_sent();
        d2k_ev h2 = ev_hello(17, 40011, "instagram.com");
        d2k_sched_event(s, &h2);
        d2k_ev s2 = ev_suspect(17, 40011);
        d2k_sched_event(s, &s2);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "instagram.com") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(ver_last_transport == 17,
              "зонду не сказали транспорт — умолчание не смогло бы отказать QUIC");
        d2k_ev a2 = ev_applied(17, 40011);
        d2k_sched_event(s, &a2);
        spin(s, 40);

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
            tick_once(s);
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
            g_now_ms += 5;
            d2k_sched_tick(s, g_now_ms);
            drain();
        }
        CHECK(peer >= 0, "зонд не пришёл к цели после подтверждения плана-вопроса");

        /* Принять соединение — ещё не значит, что планировщик уже ЖДЁТ обмена:
           рабочий поток зонда возвращается позже, чем цель его приняла, и
           событие обмена, посланное раньше, просто некому было бы отнести
           (в T_PROPS_WAIT ни одной задачи). Ждём, пока планировщик сам
           скажет, что ждёт. */
        for (int i = 0; i < 400 && !said("жду обмена"); i++) {
            tick_once(s);
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
            x.server_hello = 1;  /* сервер ответил — приёмка вопроса */
            d2k_sched_event(s, &x);
            CHECK(said("жду подтверждения полного исполнения"),
                  "обмен без доказательства применения засчитан за ответ коробки");
            CHECK(!said("перекрытие слева=нет"),
                  "свойство записано по зонду, который мог идти без плана");

            /* Последняя посылка завершилась позже ответа: не нужен новый
               вопрос или повторное EXCHANGE для того же полного потока. */
            x.kind = D2K_EV_APPLIED;
            /* С идентификатором ИМЕННО ТОГО плана, который планировщик
               только что отправил: по одному ключу потока «применён» больше
               не засчитывается (0009, U1). */
            (void)last_plan_id(x.plan_id);
            d2k_sched_event(s, &x);
            spin(s, 40);

            CHECK(said("вопрос 1 прошёл"),
                  "проход вопроса не записан — свойство коробки потеряно");
            /* Проход обязан попасть В ВЕКТОР, а не просто в строку лога:
               проверка на «сказал, что прошёл» пропустила бы планировщик,
               который говорит и не записывает. */
            CHECK(said("перекрытие слева=нет"),
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
            size_t n_empty = d2k_compose(&none, D2K_SHAPE_MODERN, "disk.rzd.ru", 0, empty_plan, 8);
            size_t n_answ = d2k_compose(&answered, D2K_SHAPE_MODERN, "disk.rzd.ru", 0, answered_plan, 8);
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
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;

        /* Первая цель: коробка ещё не известна — заводится новая, по
           отпечатку. */
        ver_answer_port = 40050;
        forget_sent();
        d2k_ev h = ev_hello(6, 40050, "первая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40050);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev x = ev_applied(6, 40050);
        d2k_sched_event(s, &x);
        spin(s, 40);
        CHECK(c6.n_boxes == 1, "первый успех не завёл коробку");
        CHECK(c6.n_boxes == 1 && c6.boxes[0].fp.n_sig == 1,
              "у заведённой коробки не записан отпечаток — узнать её потом будет нечем");
        CHECK(c6.n_boxes == 1 && strcmp(c6.boxes[0].id, "box-без-приметы") != 0,
              "коробка заведена без имени по отпечатку");

        /* Вторая цель с ТЕМ ЖЕ отпечатком: коробка обязана узнаться, её план —
           уйти в кандидаты первым, а успех — лечь в ту же коробку, а не в
           клон. */
        size_t boxes_before = c6.n_boxes;
        tcp_calls = vol_calls = 0;
        ver_answer_port = 40051;
        forget_sent();
        d2k_ev h2 = ev_hello(6, 40051, "вторая.цель");
        d2k_sched_event(s, &h2);
        d2k_ev su2 = ev_suspect(6, 40051);
        d2k_sched_event(s, &su2);
        settle(s);
        CHECK(tcp_calls == 0 && vol_calls == 0,
              "узнанная коробка запустила новый замер ДО проверки готового плана");
        d2k_ev x2 = ev_applied(6, 40051);
        d2k_sched_event(s, &x2);
        spin(s, 40);
        CHECK(c6.n_boxes == boxes_before,
              "вторая цель с тем же отпечатком завела КЛОН коробки вместо узнавания");
        CHECK(binding_of(&c6, "вторая.цель", 6) != NULL, "вторая привязка не записана");
        CHECK(said("готовых планов узнанной коробки"),
              "коробка не узнана: её проверенные планы не попали в кандидаты второй цели");
        CHECK(c6.n_boxes == 1 && c6.boxes[0].n_plans >= 1 &&
              strcmp(c6.boxes[0].plans[0].proto, "tls") == 0,
              "proto записанного плана не \"tls\" — в живом каталоге у всех планов именно он, "
              "и сравнение с транспортом отбрасывало бы каждый настоящий план");

        /* A miss on a new target falls back to research ONCE, without
           discarding the established bindings of the other targets. */
        tcp_calls = vol_calls = 0;
        /* Готовый план узнанной коробки третьей цели НЕ помогает: зонд доходит
           до рукопожатия и молчит. Промах виден планировщику сам, без единого
           события от пользователя. */
        ver_answer = D2K_VER_HANDSHAKE;
        forget_sent();
        d2k_ev h3 = ev_hello(6, 40052, "третья.цель");
        d2k_sched_event(s, &h3);
        d2k_ev su3 = ev_suspect(6, 40052);
        d2k_sched_event(s, &su3);
        settle(s);
        CHECK(tcp_calls == 1 && vol_calls == 1,
              "после промаха готового плана исследование не запущено ровно один раз");
        CHECK(binding_of(&c6, "вторая.цель", 6) != NULL,
              "промах третьей цели повредил подтверждённую вторую");
        CHECK(binding_of(&c6, "третья.цель", 6) == NULL,
              "промах готового плана записан как новая привязка");
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
            c7.boxes[0].binds = calloc(4, sizeof *c7.boxes[0].binds);
            c7.boxes[0].n_binds = 4;
            for (int i = 0; i < 4; i++) {
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
            /* Четвёртая — по АДРЕСУ и с уровнем 2 «сервер ответил»: ровно та
               запись, что 13.09.2026 сломала контрольную цель на роутере.
               Доказательство слабее обмена — на провод не едет.

               У первых трёх уровень нулевой, и это НЕ упущение фикстуры: ноль
               означает «не записано» (старый файл), и он обязан ставиться
               по-прежнему — иначе правило обнулило бы человеку весь каталог
               разом. Обе половины правила проверяются одним прогоном. */
            snprintf(c7.boxes[0].binds[3].kind, sizeof c7.boxes[0].binds[3].kind, "addr");
            snprintf(c7.boxes[0].binds[3].target, sizeof c7.boxes[0].binds[3].target, "8.47.69.0");
            c7.boxes[0].binds[3].enabled = 1;
            c7.boxes[0].binds[3].level = 2;

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
            CHECK(said("не поставлено привязок со слабым доказательством: 1"),
                  "привязка уровня «сервер ответил» ушла на провод наравне с "
                  "подтверждённой либо пропала молча");
            d2k_sched_free(s);
            d2k_catalog_free(&c7);
        }
    }

    /* --- очередь кандидатов движется БЕЗ пользователя (задача 3) -------- */
    {
        /* Раньше поставленный кандидат ждал чужого обмена: пока цель не
           откроют ещё раз, очередь стояла, а у телевизора «ещё раз» — через
           три минуты. Теперь кандидата испытывает сам планировщик, и промах
           виден через секунды, без единого события от пользователя. */
        d2k_catalog c5;
        memset(&c5, 0, sizeof c5);
        d2k_sched *s = d2k_sched_new(&c5, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_HANDSHAKE;  /* рукопожатие есть, приложение молчит */
        ver_fail_first = 0;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40040, "instagram.com");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40040);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls >= 1, "планировщик не испытал кандидата сам");
        CHECK(total_bindings(&c5) == 0,
              "рукопожатие без ответа приложения записано как успех");
        CHECK(d2k_sched_active(s) == 0,
              "очередь кандидатов не продвинулась сама — поиск ждёт пользователя");
        d2k_sched_free(s);
        d2k_catalog_free(&c5);
    }

    /* --- потерянное применение НЕ улика против кандидата ---------------- */
    {
        /* Датапат держит ровно один исходящий кадр и теряет всё, что не
           поместилось (d2k_ctl.h). Пропавшее применение снаружи неотличимо от
           «план к зонду не применялся» — и без этой проверки планировщик
           выбрасывал бы РАБОЧИЙ кандидат просто потому, что о его применении
           не смогли сказать. */
        d2k_catalog c9;
        memset(&c9, 0, sizeof c9);
        d2k_sched *s = d2k_sched_new(&c9, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40070;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40070, "молчащая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40070);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls == 1, "кандидат не испытан");
        CHECK(said("жду применения плана"),
              "зонд дошёл до приложения, а применения плана никто не ждёт");

        /* Связь сообщает о потерях, и события применения так и нет: считать
           это уликой против кандидата нельзя — испытываем его ЕЩЁ РАЗ. */
        d2k_ev st;
        memset(&st, 0, sizeof st);
        st.kind = D2K_EV_STATS;
        st.dropped = 3;
        d2k_sched_event(s, &st);
        skip_ahead(s, 6000); /* перешагнуть потолок ожидания применения */
        settle(s);
        CHECK(said("молчание не в счёт"),
              "потери событий не учтены — молчание засчитано как улика против кандидата");
        CHECK(ver_calls == 2, "кандидат не испытан повторно, хотя связь теряла события");
        CHECK(total_bindings(&c9) == 0, "потеря событий записана как успех");

        /* А когда потерь больше нет — кандидат честно сменяется, и поиск
           доходит до конца очереди сам. */
        run_out(s);
        CHECK(total_bindings(&c9) == 0,
              "зонд прошёл, а применения не было — записано как успех");
        CHECK(d2k_sched_active(s) == 0,
              "без потерь связи кандидат так и не сменился — поиск встал");
        d2k_sched_free(s);
        d2k_catalog_free(&c9);
    }

    /* --- отказ отправки: временный лечится повтором, постоянный — нет ---
     *
     * 0009, U2. Четыре утверждения в одном сценарии, потому что все четыре про
     * одно: НАША неудача не имеет права стать свойством чужого устройства и не
     * имеет права съесть поиск.
     *
     *   чужой отказ (не наш идентификатор плана) не трогает кандидата;
     *   временный отказ даёт ПОВТОР того же кандидата, а не выброс;
     *   повторов ограниченное число, а не «пока не кончится бюджет»;
     *   постоянный отказ (посылка длиннее канала) не повторяется вовсе,
     *     кандидат сменяется, и «рабочего обхода нет» никто не объявляет. */
    {
        d2k_catalog cu;
        memset(&cu, 0, sizeof cu);
        d2k_sched *s = d2k_sched_new(&cu, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40077;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40077, "отказная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40077);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls == 1, "кандидат не испытан");

        /* ЧУЖОЙ отказ: ключ наш, идентификатор плана — нет. */
        d2k_ev alien = ev_refused(6, 40077, D2K_REFUSE_SEND, 0);
        d2k_sched_event(s, &alien);
        skip_ahead(s, 6000);
        settle(s);
        CHECK(!said("посылка плана не ушла на провод"),
              "чужой отказ приписан нашему кандидату");

        CHECK(total_bindings(&cu) == 0, "чужой отказ записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cu);
    }

    {
        /* СВОЙ временный отказ — повтор ТОГО ЖЕ кандидата. Отдельный
           планировщик: проверка выше уже израсходовала своё окно ожидания,
           и слать сюда второй отказ было бы некому. */
        d2k_catalog ct;
        memset(&ct, 0, sizeof ct);
        d2k_sched *s = d2k_sched_new(&ct, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40079;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40079, "временная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40079);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls == 1, "кандидат не испытан");

        int before = ver_calls;
        d2k_ev tmp = ev_refused(6, 40079, D2K_REFUSE_QUEUE, 1);
        d2k_sched_event(s, &tmp);
        skip_ahead(s, 6000);
        settle(s);
        CHECK(said("посылка плана не ушла на провод"),
              "временный отказ отправки не назван — он неотличим от промаха коробки");
        CHECK(ver_calls > before, "после временного отказа кандидат не переиспытан");
        CHECK(total_bindings(&ct) == 0, "отказ отправки записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&ct);
    }

    {
        /* Постоянный отказ: повторять нечего, тот же план даст то же. */
        d2k_catalog cp;
        memset(&cp, 0, sizeof cp);
        d2k_sched *s = d2k_sched_new(&cp, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40078;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40078, "длинная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40078);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls == 1, "кандидат не испытан");

        int before = ver_calls;
        d2k_ev big = ev_refused(6, 40078, D2K_REFUSE_TOO_LONG, 1);
        d2k_sched_event(s, &big);
        skip_ahead(s, 6000);
        settle(s);
        CHECK(said("опыт невозможен"),
              "постоянный отказ не назван причиной невозможности опыта");
        CHECK(!said("испытываю кандидата ещё раз"),
              "постоянный отказ лечится повтором — тот же план даст тот же результат");
        CHECK(ver_calls == before || ver_calls == before + 1,
              "постоянный отказ породил череду одинаковых повторов");
        CHECK(total_bindings(&cp) == 0, "отказ по длине записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cp);
    }

    /* --- запасной перебор: синтез не помог — поиск продолжается ---------
     *
     * 0007 п.3, 0008 п.7. Раньше очередь синтеза кончалась — и задача уходила
     * в отдых, хотя у донора после синтеза начинается перебор poisons(). При
     * пустом векторе синтез даёт РОВНО ОДИН план («всё сразу»), поэтому без
     * перебора испытание было бы ровно одно.
     *
     * Проверяем две вещи: испытаний стало больше одного (перебор подхватил) и
     * поиск всё равно КОНЧАЕТСЯ — общий бюджет зондов принадлежит
     * планировщику, а не длине списка. */
    {
        d2k_catalog cf;
        memset(&cf, 0, sizeof cf);
        d2k_sched *s = d2k_sched_new(&cf, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;   /* зонд не доходит до приложения: промах */
        ver_fail_first = 0;
        ver_answer_port = 40081;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40081, "перебор.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40081);
        d2k_sched_event(s, &su);
        run_out(s);

        CHECK(ver_calls > 1,
              "после синтеза поиск встал — запасной перебор не подхватил");
        CHECK(d2k_sched_active(s) == 0,
              "запасной перебор не кончился — бюджет зондов не ограничил поиск");
        CHECK(total_bindings(&cf) == 0,
              "перебор записал привязку, хотя ни один зонд не дошёл до приложения");
        d2k_sched_free(s);
        d2k_catalog_free(&cf);
    }

    /* --- отказ отправки + ОБОРВАННЫЙ ЗОНД: кандидат не виноват -----------
     *
     * 0009, U2, пропущенный путь. Сочетание обычное: посылка плана не ушла,
     * значит воздействия не было, значит цель ответила ровно как без обхода —
     * зонд не доходит до приложения. Раньше этот путь шёл мимо разбора
     * unsent_code: код видел «зонд не дошёл» и выбрасывал кандидата из-за
     * НАШЕЙ неудачи. Проверки успешного TLS этого не ловили — там до ветки
     * с провалом зонда дело не доходит вовсе.
     *
     * Временный отказ обязан дать повтор ТОГО ЖЕ кандидата. */
    {
        d2k_catalog cw;
        memset(&cw, 0, sizeof cw);
        d2k_sched *s = d2k_sched_new(&cw, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;   /* зонд оборван: до приложения не дошёл */
        ver_fail_first = 0;
        ver_answer_port = 40091;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40091, "оборванная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40091);
        d2k_sched_event(s, &su);
        /* Кандидат обязан уже стоять: отказ относится к ЕГО посылке, и до
           установки приписывать его нечему. */
        spin_until_installed(s);
        /* Отказ приходит, пока задача ещё испытывает кандидата. */
        d2k_ev tmp = ev_refused(6, 40091, D2K_REFUSE_QUEUE, 1);
        d2k_sched_event(s, &tmp);
        settle(s);

        CHECK(said("посылка плана не ушла на провод"),
              "зонд оборван и посылка не ушла — отказ не разобран, наша неудача "
              "записана промахом кандидата");
        CHECK(ver_calls > 1, "кандидат не переиспытан после временного отказа");
        CHECK(total_bindings(&cw) == 0, "отказ отправки записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cw);
    }

    {
        /* Тот же путь, но отказ ПОСТОЯННЫЙ: повторять нечего, опыт невозможен,
           и кандидат всё равно не объявляется промахнувшимся. */
        d2k_catalog cx2;
        memset(&cx2, 0, sizeof cx2);
        d2k_sched *s = d2k_sched_new(&cx2, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;
        ver_fail_first = 0;
        ver_answer_port = 40092;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40092, "длинная-оборванная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40092);
        d2k_sched_event(s, &su);
        /* Кандидат обязан уже стоять: отказ относится к ЕГО посылке, и до
           установки приписывать его нечему. */
        spin_until_installed(s);
        d2k_ev big = ev_refused(6, 40092, D2K_REFUSE_TOO_LONG, 1);
        d2k_sched_event(s, &big);
        settle(s);

        CHECK(said("опыт невозможен"),
              "постоянный отказ на оборванном зонде не назван причиной невозможности опыта");
        /* Порядком, а не отсутствием: следующие кандидаты промахиваются
           законно — у них своего отказа не было, и «зонд не дошёл» про них
           правда. Проверяем, что ПЕРВЫЙ кандидат не обвинён: объяснение про
           невозможность опыта обязано прозвучать РАНЬШЕ первого промаха. */
        {
            const char *imp = strstr(saidbuf, "опыт невозможен");
            const char *miss = strstr(saidbuf, "зонд не дошёл до приложения");
            CHECK(imp && (!miss || imp < miss),
                  "наша неудача объявлена промахом зонда — кандидат обвинён не за что");
        }
        CHECK(total_bindings(&cx2) == 0, "отказ по длине записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cx2);
    }

    {
        /* ЧУЖОЙ ранний отказ на том же потоке не должен трогать кандидата:
           зонд оборван по своей причине, и объяснение обязано остаться про
           зонд, а не про нашу отправку. */
        d2k_catalog cy;
        memset(&cy, 0, sizeof cy);
        d2k_sched *s = d2k_sched_new(&cy, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;
        ver_fail_first = 0;
        ver_answer_port = 40093;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40093, "чужой-отказ.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40093);
        d2k_sched_event(s, &su);
        /* Кандидат обязан уже стоять: отказ относится к ЕГО посылке, и до
           установки приписывать его нечему. */
        spin_until_installed(s);
        d2k_ev alien = ev_refused(6, 40093, D2K_REFUSE_SEND, 0);
        d2k_sched_event(s, &alien);
        settle(s);

        CHECK(!said("посылка плана не ушла на провод"),
              "чужой отказ приписан нашему кандидату");
        CHECK(said("зонд не дошёл до приложения"),
              "объяснение промаха подменено чужим отказом");
        CHECK(total_bindings(&cy) == 0, "чужой отказ записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cy);
    }

    /* --- ЧУЖОЙ ОТКАЗ С НАШИМ ПЛАНОМ (0009, U2-R1) ----------------------
     *
     * Доказано стендом ревью, не предположение. Один пробный план действует на
     * ВСЕ подключения к этой цели, поэтому отказ соседнего клиента совпадает
     * с нашим по цели, транспорту и идентификатору плана — а отказом НАШЕГО
     * зонда при этом не является. Местный порт зонда до его возврата не знает
     * никто: ядро назначает его при обращении.
     *
     * Раньше такой отказ съедался как свой и без нужды переиспытывал
     * кандидата; при постоянном коде объявил бы опыт невозможным там, где он
     * состоялся. */
    {
        d2k_catalog cr;
        memset(&cr, 0, sizeof cr);
        d2k_sched *s = d2k_sched_new(&cr, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;
        ver_fail_first = 0;
        ver_answer_port = 40091;   /* местный порт НАШЕГО зонда */
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40091, "чужой-порт.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40091);
        d2k_sched_event(s, &su);
        spin_until_installed(s);

        /* Цель и идентификатор плана НАШИ, клиентский порт ДРУГОЙ. */
        d2k_ev alien = ev_refused(6, 49999, D2K_REFUSE_QUEUE, 1);
        d2k_sched_event(s, &alien);
        settle(s);

        CHECK(!said("посылка плана не ушла на провод"),
              "отказ ЧУЖОГО соединения с тем же планом съеден как свой — "
              "кандидат переиспытан без причины");
        CHECK(said("зонд не дошёл до приложения"),
              "объяснение промаха подменено чужим отказом");
        CHECK(total_bindings(&cr) == 0, "чужой отказ записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cr);
    }

    /* --- дата подтверждения — стенная, а не монотонная ------------------ */
    {
        /* Внутри планировщик считает МОНОТОННЫМИ миллисекундами, и это верно:
           стенные часы на роутере прыгают при синхронизации времени, а сроки
           от этого прыгать не должны. Но каталог читает человек и панель.
           Живая приёмка 12.09.2026 показала, чем это кончается: у всех новых
           подтверждений в файле стояло «1970-01-01T04:14:39Z» — монотонные
           миллисекунды, записанные как секунды эпохи. */
        d2k_catalog cC;
        memset(&cC, 0, sizeof cC);
        ver_answer = D2K_VER_APPLICATION;
        tcp_answer = D2K_V_PREFIX;
        confirm_once(&cC, sv[0], "часы.цель", 40120);

        const d2k_cat_binding *bd = binding_of(&cC, "часы.цель", 6);
        CHECK(bd != NULL, "часы: привязка не записана");
        /* Живая приёмка 12.09.2026 поймала ВТОРУЮ половину той же ошибки:
           CLOCK_MONOTONIC на Linux отсчитывается от ЗАГРУЗКИ, и привязка,
           снятая своим вызовом часов при заведении планировщика, считала
           уптайм дважды — запись легла временем 05:16Z при настоящих 00:43Z,
           ровно на 4,5 часа работы роутера вперёд. Здесь роутер «уже работает»
           четыре часа: часы приходят аргументом, как в проде. */
        g_now_ms += 4 * 60 * 60 * 1000;
        d2k_catalog cD;
        memset(&cD, 0, sizeof cD);
        confirm_once(&cD, sv[0], "часы.уптайм", 40121);
        const d2k_cat_binding *bu = binding_of(&cD, "часы.уптайм", 6);
        CHECK(bu != NULL, "часы: привязка при ненулевом уптайме не записана");
        if (bu) {
            int64_t now = (int64_t)time(NULL);
            int64_t off = bu->confirmed - now;
            if (off < 0) { off = -off; }
            CHECK(off < 120,
                  "дата подтверждения разошлась с настоящей больше чем на две "
                  "минуты — уптайм посчитан дважды");
        }
        d2k_catalog_free(&cD);
        if (bd) {
            /* 2026-01-01 в секундах эпохи. Всё, что меньше, — это не дата, а
               время с загрузки, попавшее в файл как дата. */
            CHECK(bd->confirmed > 1767225600,
                  "дата подтверждения меньше 2026 года — в каталог уехали "
                  "монотонные часы вместо стенных");
        }
        d2k_catalog_free(&cC);
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

    /* --- внешний тип 23 сам по себе не подтверждает ничего (задача 4) --- */
    {
        /* В TLS 1.3 внешним типом записи 23 наружу едет ВЕСЬ второй полёт
           рукопожатия (RFC 8446 §5.2): с провода «приложение ответило» и
           «коробка пропустила приветствие» неотличимы. Ровно на этом пороге
           в каталоге накопились 4796 «успехов» по instagram при мёртвом
           плане (§1 спецификации). Событие обмена по потоку задачи обязано
           остаться НАБЛЮДЕНИЕМ и привязку не заводить. */
        d2k_catalog c4;
        memset(&c4, 0, sizeof c4);
        d2k_sched *s = d2k_sched_new(&c4, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_HANDSHAKE; /* зонд до приложения НЕ дошёл */
        ver_fail_first = 0;
        d2k_ev h = ev_hello(6, 40030, "instagram.com");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40030);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev x = ev_exchange(6, 40030, 1); /* внешний тип 23 по потоку цели */
        d2k_sched_event(s, &x);
        spin(s, 40);
        CHECK(total_bindings(&c4) == 0,
              "внешний тип 23 записан как подтверждение — это только наблюдение (RFC 8446 §5.2)");
        d2k_ev x0 = ev_exchange(6, 40030, 0); /* и рукопожатие тем более */
        d2k_sched_event(s, &x0);
        spin(s, 40);
        CHECK(total_bindings(&c4) == 0, "обмен без внешнего типа 23 засчитан за успех");
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

    /* Two compatible models are alternatives, not "first match wins". */
    {
        d2k_catalog c;
        memset(&c, 0, sizeof c);
        c.boxes = calloc(2, sizeof *c.boxes);
        CHECK(c.boxes != NULL, "не удалось создать две модели");
        if (c.boxes) {
            c.n_boxes = 2;
            int ready = 1;
            for (size_t i = 0; i < 2; i++) {
                d2k_cat_box *b = &c.boxes[i];
                snprintf(b->id, sizeof b->id, "box-alternative-%u", (unsigned)i);
                b->fp.method = D2K_FP_METHOD;
                b->fp.n_sig = 1;
                snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rst");
                b->fp.sig[0].ttl = 127;
                b->fp.sig[0].tos = 0x88;
                b->fp.sig[0].ipid = 54321;
                b->plans = calloc(1, sizeof *b->plans);
                if (!b->plans) { ready = 0; break; }
                b->n_plans = 1;
                b->plans[0].enabled = 1;
                b->plans[0].successes = (int)(2 - i);
                snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "tls");
                char plan[256];
                snprintf(plan, sizeof plan,
                         "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                         "proto tcp tls\nsplit payload_start +%u\norder reverse\n",
                         (unsigned)(i + 1));
                b->plans[0].text = strdup(plan);
                if (!b->plans[0].text) { ready = 0; break; }
            }
            CHECK(ready, "не удалось создать планы альтернативных моделей");
            if (ready) {
                d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
                tcp_calls = vol_calls = 0;
                /* Первый кандидат (план модели с бо́льшим числом успехов) не
                   помогает: зонд доходит только до рукопожатия. Второй —
                   помогает. Обе развилки видит сам планировщик. */
                ver_answer = D2K_VER_APPLICATION;
                ver_fail_first = 1;
                ver_calls = 0;
                ver_answer_port = 40101;
                forget_sent();
                d2k_ev h = ev_hello(6, 40101, "неоднозначная.цель");
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, 40101);
                d2k_sched_event(s, &su);
                settle(s);
                CHECK(tcp_calls == 0 && vol_calls == 0,
                      "первая похожая модель не помогла — вторая пропущена ради исследования");
                d2k_ev ap = ev_applied(6, 40101);
                d2k_sched_event(s, &ap);
                spin(s, 40);
                CHECK(c.boxes[0].n_binds == 0 && c.boxes[1].n_binds == 1,
                      "результат второго плана записан не в его модель");
                ver_fail_first = 0;
                d2k_sched_free(s);
            }
            d2k_catalog_free(&c);
        }
    }

    /* Missing diagnostic control is not permission to abandon synthesis. */
    {
        d2k_catalog c;
        memset(&c, 0, sizeof c);
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_INCONCLUSIVE;
        ver_answer = D2K_VER_HANDSHAKE; /* кандидатов собрали, но не подтвердили */
        d2k_ev h = ev_hello(6, 40100, "без.контроля");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40100);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(said("поставил план 1 из"), "нет диагноза — генерация ошибочно запрещена");
        CHECK(c.n_boxes == 0, "непроверенная гипотеза попала в каталог");
        d2k_sched_free(s);
        d2k_catalog_free(&c);
        tcp_answer = D2K_V_OPAQUE;
    }

    /* --- редкую цель планировщик испытывает САМ (задача 3) -------------- */
    {
        /* Главная проверка этой вертикали. Событий от пользователя после
           подозрения НЕТ ВОВСЕ — только то, что говорит датапат о НАШЕМ
           зонде. Спецификация (§4) прямо отказывается от того, чтобы цель
           открывали несколько раз ради перебора: у телевизора одно обращение,
           следующее через три минуты. */
        d2k_catalog cB;
        memset(&cB, 0, sizeof cB);
        d2k_sched *s = d2k_sched_new(&cB, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40090;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40090, "редкая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40090);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls >= 1, "планировщик не испытал кандидата сам");

        /* Датапат говорит, что план применился к пакетам ЭТОГО потока. */
        d2k_ev ap = ev_applied(6, 40090);
        CHECK(ap.plan_id[0] != 0,
              "кандидат ушёл на провод без идентификатора — сверять применение нечем");
        d2k_sched_event(s, &ap);
        spin(s, 40);
        CHECK(total_bindings(&cB) == 1,
              "успех собственного испытания не записан — перебор снова ждёт пользователя");
        CHECK(said("ПОДТВЕРЖДЕНО собственным зондом"),
              "подтверждение не названо тем, чем оно является");
        const d2k_cat_binding *bd = binding_of(&cB, "редкая.цель", 6);
        CHECK(bd != NULL && bd->level == 3,
              "уровень записи не третий («обмен прошёл») — именно это и доказано зондом");

        /* Чужое применение того же плана к той же цели — НЕ наше испытание:
           ключ потока другой. Проверяется отдельной целью, чтобы поймать
           сверку по порту, а не «по чему-нибудь». */
        ver_answer_port = 40091;
        ver_calls = 0;
        forget_sent();
        d2k_ev h2 = ev_hello(6, 40091, "чужой.поток");
        d2k_sched_event(s, &h2);
        d2k_ev su2 = ev_suspect(6, 40091);
        d2k_sched_event(s, &su2);
        settle(s);
        d2k_ev ap2 = ev_applied(6, 40091);
        ap2.high_port = 40099; /* тот же план и та же цель, но ЧУЖОЙ поток */
        d2k_sched_event(s, &ap2);
        run_out(s);
        CHECK(binding_of(&cB, "чужой.поток", 6) == NULL,
              "применение по ЧУЖОМУ потоку засчитано за испытание нашего зонда");

        /* Применение ЧУЖОГО плана по НАШЕМУ потоку — тоже не испытание: так
           выглядит опоздавшее событие предыдущего кандидата (ради этого
           различия идентификатор и завели, d2k_link.h). */
        ver_answer_port = 40092;
        ver_calls = 0;
        forget_sent();
        d2k_ev h3 = ev_hello(6, 40092, "старый.план");
        d2k_sched_event(s, &h3);
        d2k_ev su3 = ev_suspect(6, 40092);
        d2k_sched_event(s, &su3);
        settle(s);
        d2k_ev ap3 = ev_applied(6, 40092);
        memcpy(ap3.plan_id, "plan-deadbeef\0\0", 16); /* идентификатор другого плана */
        d2k_sched_event(s, &ap3);
        run_out(s);
        CHECK(binding_of(&cB, "старый.план", 6) == NULL,
              "применение ЧУЖОГО плана засчитано за испытание нашего кандидата");
        d2k_sched_free(s);
        d2k_catalog_free(&cB);
    }

    /* СЕДЬМАЯ НАХОДКА ЛАБОРАТОРИИ: подтверждение на зонде ≠ работа у клиента.
       Кандидат стоит на ЦЕЛИ, и по нему одновременно с зондом ходит браузер.
       Приветствие браузера длиннее зондового, и бывает так: зонду план
       исполняется и доходит до приложения, а потоку клиента — нет, отказом по
       длине. Записать такое подтверждённым значит выдать человеку каталог с
       «подтверждено» и отсутствием обхода. */
    {
        d2k_catalog cuf;
        memset(&cuf, 0, sizeof cuf);
        d2k_sched *s = d2k_sched_new(&cuf, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;   /* зонду план исполнился до конца */
        ver_fail_first = 0;
        ver_answer_port = 40160;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40160, "непереносимая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40160);
        d2k_sched_event(s, &su);
        settle(s);
        spin_until_installed(s);

        /* Второй поток к ТОЙ ЖЕ цели — его открыл клиент, а не зонд. Имя за
           ним планировщик знает из приветствия, как и на живой линии. */
        d2k_ev hc = ev_hello(6, 40161, "непереносимая.цель");
        d2k_sched_event(s, &hc);
        d2k_ev big = ev_refused(6, 40161, D2K_REFUSE_TOO_LONG, 1);
        CHECK(big.plan_id[0] != 0,
              "кандидат ушёл на провод без идентификатора — приписать отказ нечему");
        d2k_sched_event(s, &big);

        /* А зонду тот же план исполнился: полное доказательство на руках. */
        d2k_ev ap = ev_applied(6, 40160);
        d2k_sched_event(s, &ap);
        run_out(s);

        CHECK(said("потоку клиента"),
              "план не исполнился клиенту, а планировщик об этом промолчал");
        CHECK(binding_of(&cuf, "непереносимая.цель", 6) == NULL,
              "план, не исполнимый потоку клиента, записан подтверждённым — "
              "в каталоге «подтверждено», у человека обхода нет");
        d2k_sched_free(s);
        d2k_catalog_free(&cuf);
    }

    /* Тот же ход, но отказ у клиента ВРЕМЕННЫЙ: очередь переполнилась, к
       переносимости это отношения не имеет, и подтверждение обязано пройти. */
    {
        d2k_catalog ctq;
        memset(&ctq, 0, sizeof ctq);
        d2k_sched *s = d2k_sched_new(&ctq, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40162;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40162, "временная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40162);
        d2k_sched_event(s, &su);
        settle(s);
        spin_until_installed(s);

        d2k_ev hc = ev_hello(6, 40163, "временная.цель");
        d2k_sched_event(s, &hc);
        d2k_ev tmp = ev_refused(6, 40163, D2K_REFUSE_QUEUE, 1);
        d2k_sched_event(s, &tmp);

        d2k_ev ap = ev_applied(6, 40162);
        d2k_sched_event(s, &ap);
        run_out(s);

        CHECK(binding_of(&ctq, "временная.цель", 6) != NULL,
              "временный отказ у клиента отменил состоявшееся подтверждение — "
              "всплеск очереди объявлен непереносимостью");
        d2k_sched_free(s);
        d2k_catalog_free(&ctq);
    }

    /* Ранние APPLIED: два клиента вправе иметь одинаковый местный порт.
       События подаются до следующего tick: результат worker ещё не принят. */
    for (int with_own = 0; with_own < 2; with_own++) {
        d2k_catalog early;
        memset(&early, 0, sizeof early);
        d2k_sched *s = d2k_sched_new(&early, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40109;
        forget_sent();
        d2k_ev h = ev_hello(6, 40109, "early.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40109);
        d2k_sched_event(s, &su);
        uint8_t id[16];
        int installed = 0;
        for (int i = 0; i < 400 && !installed; i++) {
            tick_once(s);
            installed = last_plan_id(id);
        }
        CHECK(installed, "кандидат для ранних событий не установлен");
        d2k_ev ap = ev_applied(6, 40109);
        ap.high_ip[3] = 68;
        d2k_sched_event(s, &ap); /* правильные цель/план/порт, но чужой IP */
        ap.high_ip[3] = 67;
        memset(ap.plan_id, 0, sizeof ap.plan_id);
        d2k_sched_event(s, &ap); /* свой поток без идентификатора не доказательство */
        if (with_own) {
            ap = ev_applied(6, 40109);
            d2k_sched_event(s, &ap);
        }
        settle(s);
        CHECK((binding_of(&early, "early.example", 6) != NULL) == with_own,
              "раннее применение перепутало клиентов или потеряло своё за чужим");
        d2k_sched_free(s);
        d2k_catalog_free(&early);
    }

    /* --- живой TLS-ответ ПОСЛЕ подтверждения остаётся наблюдением ------- */
    {
        /* T_WATCHING теперь означает другое: не «ждём, пока пользователь
           откроет цель», а «план подтверждён и стоит, смотрим на живой
           трафик». Наблюдение внешнего типа 23 привязку не заводит (проверено
           выше), но уже подтверждённой поднять уровень может — это и есть
           пятый уровень, «подтверждён последующими соединениями». */
        d2k_catalog cC;
        memset(&cC, 0, sizeof cC);
        d2k_sched *s = d2k_sched_new(&cC, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40110;
        forget_sent();

        d2k_ev h = ev_hello(6, 40110, "подтверждённая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40110);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40110);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        const d2k_cat_binding *bd = binding_of(&cC, "подтверждённая.цель", 6);
        CHECK(bd != NULL && bd->level == 3, "подтверждение зондом не записано третьим уровнем");

        /* Обмен по потоку САМОГО зонда уровень не поднимает: это он и был
           доказательством, и считать его ещё и «последующим соединением»
           значит подтвердить себя собой. */
        d2k_ev own = ev_exchange(6, 40110, 1);
        d2k_sched_event(s, &own);
        bd = binding_of(&cC, "подтверждённая.цель", 6);
        CHECK(bd != NULL && bd->level == 3,
              "обмен по потоку самого зонда поднял уровень — запись подтвердила себя собой");

        /* Другое соединение тоже могло оборваться на рукопожатии. */
        d2k_ev h2 = ev_hello(6, 40111, "подтверждённая.цель");
        d2k_sched_event(s, &h2);
        d2k_ev live = ev_exchange(6, 40111, 1);
        d2k_sched_event(s, &live);
        bd = binding_of(&cC, "подтверждённая.цель", 6);
        CHECK(bd != NULL && bd->level == 3,
              "пассивный TLS-ответ ошибочно повысил уровень доказательства");
        CHECK(said("это не доказательство"), "граница наблюдения не названа в отчёте");
        CHECK(bd != NULL && bd->verified_by == D2K_VERBY_PROBE,
              "пассивный TLS-ответ затёр источник прикладного подтверждения");
        /* А форма осталась той, что ИЗМЕРЕНА зондом: приветствие живого
           клиента датапат не присылал, и «не измерено» не отменяет
           измеренного (§2.4). */
        CHECK(bd != NULL && bd->shape == (uint8_t)D2K_SHAPE_MODERN,
              "измеренная форма затёрта нулём от клиента, чьё приветствие не снято");
        d2k_sched_free(s);
        d2k_catalog_free(&cC);
    }

    /* --- контекст проверки записан в привязке (задача 5) ---------------- */
    {
        /* У зонда СВОЯ форма приветствия — не та, которой ходит браузер, и
           коробка вправе относиться к ним по-разному (§6). Значит успех,
           добытый зондом, нельзя молча переносить на произвольную форму: в
           привязке обязан стоять контекст, в котором проверка ДЕЙСТВИТЕЛЬНО
           состоялась. */
        d2k_shape probe_shape = probe_hello_shape();
        CHECK(probe_shape == D2K_SHAPE_MODERN,
              "приветствие собственного зонда оказалось не современной формы — "
              "константа планировщика разошлась с тем, что уходит на провод");

        d2k_catalog cD;
        memset(&cD, 0, sizeof cD);
        saidbuf[0] = '\0';
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;

        confirm_once(&cD, sv[0], "контекст.цель", 40130);
        CHECK(bindings_of(&cD, "контекст.цель", 6) == 1, "подтверждение не записано");
        const d2k_cat_binding *bd = binding_of(&cD, "контекст.цель", 6);
        CHECK(bd != NULL && bd->shape == (uint8_t)probe_shape,
              "в привязке не та форма приветствия, которой зонд ходил на самом деле");
        CHECK(bd != NULL && bd->verified_by == D2K_VERBY_PROBE,
              "в привязке не записано, что проверял собственный зонд");

        /* Файл, снятый ДО появления полей: форма не записана. Такая привязка
           совместима с любой формой, и повторное подтверждение обязано её
           ОБНОВИТЬ, а не завести рядом вторую. Иначе каталог роутера (376
           подтверждённых целей, копившихся неделями) удвоился бы на первой же
           проверке. */
        d2k_cat_binding *m = binding_mut(&cD, "контекст.цель", 6);
        CHECK(m != NULL, "нечего помечать под старый файл");
        if (m) { m->shape = 0; m->verified_by = 0; }
        confirm_once(&cD, sv[0], "контекст.цель", 40131);
        CHECK(bindings_of(&cD, "контекст.цель", 6) == 1,
              "запись без формы (старый файл) не обновлена, а продублирована");
        bd = binding_of(&cD, "контекст.цель", 6);
        CHECK(bd != NULL && bd->successes == 2,
              "повторное подтверждение не досталось прежней записи");
        CHECK(bd != NULL && bd->shape == (uint8_t)probe_shape,
              "измеренная форма не записана поверх «не измерено»");

        /* А ДРУГАЯ форма — уже другая запись: ключ привязки стал тройкой
           (цель, транспорт, форма приветствия). Успех современной формы не
           имеет права лечь в запись, добытую старой. */
        m = binding_mut(&cD, "контекст.цель", 6);
        if (m) { m->shape = (uint8_t)D2K_SHAPE_LEGACY; }
        confirm_once(&cD, sv[0], "контекст.цель", 40132);
        CHECK(bindings_of(&cD, "контекст.цель", 6) == 2,
              "успех одной формы приветствия лёг в запись, добытую другой");
        {
            int legacy_kept = 0, modern_new = 0;
            for (size_t i = 0; i < cD.n_boxes; i++) {
                for (size_t j = 0; j < cD.boxes[i].n_binds; j++) {
                    const d2k_cat_binding *x = &cD.boxes[i].binds[j];
                    if (strcmp(x->target, "контекст.цель") != 0) { continue; }
                    if (x->shape == (uint8_t)D2K_SHAPE_LEGACY && x->successes == 2) { legacy_kept++; }
                    if (x->shape == (uint8_t)probe_shape && x->successes == 1) { modern_new++; }
                }
            }
            CHECK(legacy_kept == 1, "чужая по форме запись изменена, а не оставлена в покое");
            CHECK(modern_new == 1, "новая форма не завела своей записи");
        }
        d2k_catalog_free(&cD);
    }

    /* --- живой клиент ДРУГОЙ формы уровень не поднимает ------------------ */
    {
        /* Зеркало предыдущего блока со стороны наблюдения. Запись добыта
           современной формой; живой клиент, чьё приветствие снято датапатом и
           оказалось СТАРОЙ формы, — это другой контекст, и его обмен ничего
           не говорит о записанном. Уровень остаётся третьим.
           Пара к проверке выше по файлу, где форма живого клиента не снята
           вовсе («не измерено») и уровень поднимается. */
        d2k_catalog cE;
        memset(&cE, 0, sizeof cE);
        d2k_sched *s = d2k_sched_new(&cE, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40140;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40140, "форма.важна");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40140);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40140);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        const d2k_cat_binding *bd = binding_of(&cE, "форма.важна", 6);
        CHECK(bd != NULL && bd->level == 3, "подтверждение зондом не записано третьим уровнем");

        /* Датапат снял приветствие живого клиента — и оно СТАРОЙ формы.
           Профиль берётся тот же, что у холодного старта (core/profiles), а
           не собирается в тесте руками. */
        {
            d2k_ev sh;
            memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE;
            sh.transport = 6;
            CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "форма.важна",
                                         sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
                  "приветствие старой формы не собралось — проверять нечем");
            CHECK(d2k_hello_shape(sh.shape, sh.shape_len) == D2K_SHAPE_LEGACY,
                  "собранное приветствие оказалось не старой формы");
            d2k_sched_event(s, &sh);
            CHECK(said("поймана форма приветствия"),
                  "снимок приветствия не дошёл до задачи — проверка ниже ничего не значит");
        }

        d2k_ev h2 = ev_hello(6, 40141, "форма.важна");
        d2k_sched_event(s, &h2);
        d2k_ev live = ev_exchange(6, 40141, 1);
        d2k_sched_event(s, &live);
        bd = binding_of(&cE, "форма.важна", 6);
        CHECK(bd != NULL && bd->level == 3,
              "обмен клиента ДРУГОЙ формы поднял уровень записи, добытой не им");
        CHECK(bd != NULL && bd->verified_by == D2K_VERBY_PROBE,
              "контекст проверки переписан обменом клиента другой формы");
        CHECK(bindings_of(&cE, "форма.важна", 6) == 1,
              "наблюдение завело привязку — заводить её может только подтверждение");
        d2k_sched_free(s);
        d2k_catalog_free(&cE);
    }

    /* --- снимок приветствия не уходит на ЧУЖОЙ транспорт --------------- */
    {
        /* Приветствие TLS поверх TCP и Initial поверх UDP — разные байты
           разной формы. Пока снимок раздавался всем задачам имени, QUIC-задача
           уходила мерить TLS-приветствием, и первый же разбор его отвергал. */
        d2k_catalog cS;
        memset(&cS, 0, sizeof cS);
        d2k_sched *s = d2k_sched_new(&cS, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        quic_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_HANDSHAKE;
        ver_fail_first = 0;
        ver_answer_port = 40210;
        forget_sent();

        /* Две задачи одного имени: по TCP и по QUIC. */
        d2k_ev h1 = ev_hello(6, 40210, "оба.транспорта");
        d2k_sched_event(s, &h1);
        d2k_ev s1 = ev_suspect(6, 40210);
        d2k_sched_event(s, &s1);
        d2k_ev h2 = ev_hello(17, 40211, "оба.транспорта");
        d2k_sched_event(s, &h2);
        d2k_ev s2 = ev_suspect(17, 40211);
        d2k_sched_event(s, &s2);
        settle(s);

        /* Снимок приходит с транспортом TCP. */
        d2k_ev sh;
        memset(&sh, 0, sizeof sh);
        sh.kind = D2K_EV_SHAPE;
        sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "оба.транспорта",
                                     sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
              "приветствие для снимка не собралось");
        saidbuf[0] = '\0';
        d2k_sched_event(s, &sh);

        CHECK(said("(TCP) поймана форма приветствия"),
              "снимок не дошёл до задачи своего транспорта");
        CHECK(!said("(QUIC) поймана форма приветствия"),
              "снимок TCP положили QUIC-задаче — она пойдёт мерить чужими байтами");
        d2k_sched_free(s);
        d2k_catalog_free(&cS);
    }

    /* --- неудачный ВТОРОЙ поиск не уносит подтверждённый план ---------- */
    {
        /* Второй поиск по уже подтверждённой цели — обычное дело: новое
           подозрение закрывает наблюдение и заводит поиск заново. Пробный
           план такого поиска встаёт на то же имя ПОВЕРХ подтверждённого, а
           снятие уносит их вместе: в каталоге «подтверждено», в датапате
           пусто, у человека обхода нет. Поймано лабораторией с памятью. */
        d2k_catalog cR;
        memset(&cR, 0, sizeof cR);
        d2k_sched *s = d2k_sched_new(&cR, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40200;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40200, "второй.поиск");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40200);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40200);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        CHECK(binding_of(&cR, "второй.поиск", 6) != NULL, "первый поиск не подтвердился");
        /* Проход по каталогу, заказанный подтверждением, надо ДОКРУТИТЬ: его
           порции крутит цикл d2kc, а не тик, и недокрученный проход не даст
           начаться следующему. */
        sync_out(s);

        /* Коробка вмешалась снова: наблюдение прекращается. */
        d2k_ev su2 = ev_suspect(6, 40200);
        d2k_sched_event(s, &su2);
        spin(s, 5);

        /* И ещё раз — заводится ВТОРОЙ поиск, который ничем не кончится. */
        ver_answer = D2K_VER_HANDSHAKE;   /* зонд до приложения не доходит */
        ver_answer_port = 40201;
        d2k_ev h3 = ev_hello(6, 40201, "второй.поиск");
        d2k_sched_event(s, &h3);
        d2k_ev su3 = ev_suspect(6, 40201);
        d2k_sched_event(s, &su3);
        /* Дольше, чем run_out: задача сдаётся либо по бюджету зондов, либо по
           сроку жизни (десять минут модельных часов), и до этого места надо
           дожить. */
        for (int i = 0; i < 300 && d2k_sched_active(s); i++) {
            skip_ahead(s, 6000);
            spin(s, 20);
        }

        /* Задача сдалась. Знание каталога обязано вернуться на провод. */
        forget_sent();
        spin(s, 5);
        /* Проход по каталогу разложен на порции, и крутит их цикл d2kc
           (d2k_sched_sync_step) — здесь за него это делает тест, ровно как в
           проверке синхронизации выше. */
        sync_out(s);
        /* Ищем на проводе САМ ПЛАН (заголовок "D2KP"), а не идентификатор:
           план каталога несёт ту идентичность, что записана в его тексте, и у
           подтверждённого она нулевая — «plan-…» подставляется только пробному
           при установке (install_next). Присутствие тела плана отличает
           SET_NAME от DEL_NAME, а имя цели проверяется рядом. */
        CHECK(sent_has("D2KP"),
              "после неудачного второго поиска цель осталась БЕЗ плана — "
              "в каталоге «подтверждено», в датапате пусто");
        CHECK(sent_has("второй.поиск"),
              "на провод вернулся план не той цели");
        d2k_sched_free(s);
        d2k_catalog_free(&cR);
    }

    /* --- ПЕТЛЯ ПО QUIC ЗАМКНУТА: плечо → план → подтверждение ---------- */
    {
        /* До этой правки задача транспорта 17 шла в d2k_compose, который про
           QUIC не знает, и получала разрезы — а датаграмму резать нельзя.
           Подбор плеча был написан и не звался ниоткуда, кроме тестов. */
        d2k_catalog cQ;
        memset(&cQ, 0, sizeof cQ);
        d2k_sched *s = d2k_sched_new(&cQ, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40220;
        ver_calls = 0;
        arm_calls = 0;
        arm_kind = D2K_QA_COPIES;
        forget_sent();

        d2k_ev h = ev_hello(17, 40220, "квик.обход");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40220);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "квик.обход") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(arm_calls == 1, "плечо QUIC не подбиралось вовсе");
        CHECK(said("плечо подобрано"), "подбор плеча не назван вслух");

        d2k_ev ap = ev_applied(17, 40220);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        const d2k_cat_binding *bd = binding_of(&cQ, "квик.обход", 17);
        CHECK(bd != NULL, "подтверждённый обход по QUIC не записан в каталог");
        CHECK(bd != NULL && bd->level == 3, "уровень записи по QUIC не третий");
        /* Текст записанного плана — из плеча, а не из разрезов: датаграмму
           резать нельзя, и план обязан объявлять udp/quic. На проводе он едет
           байтами TLV, поэтому сверяем то, что легло в каталог. */
        {
            int quic_text = 0;
            for (size_t bi = 0; bi < cQ.n_boxes; bi++) {
                for (size_t pj = 0; pj < cQ.boxes[bi].n_plans; pj++) {
                    const char *txt = cQ.boxes[bi].plans[pj].text;
                    if (txt && strstr(txt, "proto udp quic")) { quic_text = 1; }
                }
            }
            CHECK(quic_text,
                  "записанный план не объявляет udp/quic — он собран не из плеча");
        }
        d2k_sched_free(s);
        d2k_catalog_free(&cQ);
    }

    /* --- невыразимое плечо QUIC не подменяется похожим ------------------ */
    {
        d2k_catalog cF2;
        memset(&cF2, 0, sizeof cF2);
        d2k_sched *s = d2k_sched_new(&cF2, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
        ver_answer_port = 40221;
        arm_kind = D2K_QA_FRAG;     /* фрагментации язык плана не знает */
        forget_sent();

        d2k_ev h = ev_hello(17, 40221, "фрагмент.квик");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40221);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "фрагмент.квик") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        run_out(s);

        CHECK(said("не выразимо"),
              "невыразимое плечо не названо пробелом реализации");
        CHECK(!said("не нашлось"),
              "невыразимое плечо выдано за ненайденное — это разные факты");
        CHECK(binding_of(&cF2, "фрагмент.квик", 17) == NULL,
              "по невыразимому плечу появилась привязка");
        arm_kind = D2K_QA_BLOB;
        quic_answer = D2K_V_CLEAR;
        d2k_sched_free(s);
        d2k_catalog_free(&cF2);
    }

    /* --- «не нашлось» и «не выразимо» — РАЗНЫЕ ответы --------------------
     *
     * Первое про коробку и бюджет: перебор кончился, воздействия нет.
     * Второе про нас: воздействие есть, языка плана на него нет. Лаборатория
     * 13.09 на коробке без состояния получила «не выразимо» там, где на деле
     * кончился бюджет развёртки TTL, — то есть отчиталась нашим пробелом
     * вместо свойства сети. */
    {
        d2k_catalog cNF;
        memset(&cNF, 0, sizeof cNF);
        d2k_sched *s = d2k_sched_new(&cNF, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_OPAQUE;
        ver_answer_port = 40222;
        arm_kind = D2K_QA_NOT_FOUND;
        forget_sent();

        d2k_ev h = ev_hello(17, 40222, "нечем.квик");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40222);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "нечем.квик") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        run_out(s);

        CHECK(said("плечо не нашлось"),
              "исчерпанный перебор не назван своим именем");
        CHECK(!said("не выразимо"),
              "ненайденное плечо выдано за пробел реализации");
        CHECK(binding_of(&cNF, "нечем.квик", 17) == NULL,
              "по ненайденному плечу появилась привязка");
        arm_kind = D2K_QA_BLOB;
        quic_answer = D2K_V_CLEAR;
        d2k_sched_free(s);
        d2k_catalog_free(&cNF);
    }

    /* --- подтверждать нечем: перебор кандидатов не начинается ---------- */
    {
        /* У QUIC вопросник есть, а зонда подтверждения нет. Перебор в такой
           задаче потратил бы весь бюджет зондов на установку планов, которых
           никто не проверит, — а на живом роутере таких целей десятки. */
        d2k_catalog cU;
        memset(&cU, 0, sizeof cU);
        d2k_sched *s = d2k_sched_new(&cU, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;   /* не важно: до ответа не дойдёт */
        ver_fail_first = 0;
        ver_answer_port = 40190;
        ver_calls = 0;
        ver_unsupported = 1;
        forget_sent();

        d2k_ev h = ev_hello(17, 40190, "квик.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40190);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "квик.цель") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        run_out(s);

        CHECK(said("подтверждать нечем"),
              "транспорт без зонда подтверждения не назван своим именем");
        CHECK(ver_calls == 1,
              "перебор кандидатов пошёл дальше, хотя ответ будет тот же — "
              "бюджет зондов тратится впустую");
        CHECK(binding_of(&cU, "квик.цель", 17) == NULL,
              "непроверяемый транспорт дал запись в каталоге");
        ver_unsupported = 0;
        quic_answer = D2K_V_CLEAR;
        d2k_sched_free(s);
        d2k_catalog_free(&cU);
    }

    /* --- сервер представился ЧУЖИМ именем: это не обход ---------------- */
    {
        /* Коробка, терминирующая TLS, доводит зонд до приложения и отвечает
           страницей блокировки. Уровень «приложение» при этом настоящий —
           обманывает не он, а вывод из него. */
        d2k_catalog cN;
        memset(&cN, 0, sizeof cN);
        d2k_sched *s = d2k_sched_new(&cN, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40180;
        ver_calls = 0;
        ver_name_ok = 0;                 /* ИЗМЕРЕННОЕ несовпадение */
        forget_sent();

        d2k_ev h = ev_hello(6, 40180, "подмена.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40180);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40180);
        d2k_sched_event(s, &ap);
        run_out(s);

        CHECK(said("представился ЧУЖИМ"),
              "разговор с чужим сервером не назван своим именем");
        CHECK(binding_of(&cN, "подмена.цель", 6) == NULL,
              "страница блокировки записана обходом — каталог наполняется ложью");
        ver_name_ok = -1;
        d2k_sched_free(s);
        d2k_catalog_free(&cN);
    }

    /* --- зонд ходит ДЛИНОЙ КЛИЕНТА, а не своей ------------------------- */
    {
        /* Приветствие зонда вчетверо короче браузерного (замерено: curl шлёт
           1581 байт), и на этой разнице ломается переносимость: план, чьи
           куски помещаются в посылку на коротком приветствии, на длинном не
           помещается вовсе. Поэтому длина снятого с клиента приветствия
           обязана доехать до зонда — проверяем, что доезжает именно она, а не
           ноль и не своя. */
        d2k_catalog cW;
        memset(&cW, 0, sizeof cW);
        d2k_sched *s = d2k_sched_new(&cW, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40170;
        ver_calls = 0;
        ver_last_wire = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40170, "длина.клиента");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40170);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls >= 1, "зонд не позван — длину проверять не на чем");
        CHECK(ver_last_wire > 0,
              "зонду досталась нулевая длина — он пойдёт СВОИМ коротким приветствием, "
              "и подтверждение достанется ему, а не человеку");

        /* Теперь датапат прислал снимок приветствия ЖИВОГО клиента. Со
           следующего испытания зонд обязан ходить ЕГО длиной. */
        d2k_ev sh;
        memset(&sh, 0, sizeof sh);
        sh.kind = D2K_EV_SHAPE;
        sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "длина.клиента",
                                     sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
              "приветствие клиента не собралось — проверять нечем");
        d2k_sched_event(s, &sh);
        CHECK(said("поймана форма приветствия"), "снимок не дошёл до задачи");

        size_t want = sh.shape_len;
        ver_last_wire = 0;
        ver_answer_port = 40171;
        run_out(s);
        CHECK(ver_last_wire == want,
              "зонд пошёл НЕ длиной снятого с клиента приветствия — испытание идёт "
              "в другом контексте, чем работа человека");
        d2k_sched_free(s);
        d2k_catalog_free(&cW);
    }

    /* --- живой обмен не ВЫДУМЫВАЕТ форму клиента ------------------------ */
    {
        /* Обратная сторона предыдущей проверки. Приветствия живого клиента
           датапат не присылал — значит его форма НЕ ИЗМЕРЕНА, и взять её из
           заготовки холодного старта (fill_hellos подставляет туда MODERN)
           нельзя: заготовка — это то, чем планировщик ходит сам, а не то, чем
           ходит клиент. Запись изображает старый файл (формы в ней нет), и
           после наблюдения формы в ней по-прежнему быть не должно. */
        d2k_catalog cF;
        memset(&cF, 0, sizeof cF);
        d2k_sched *s = d2k_sched_new(&cF, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40150;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40150, "снимка.нет");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40150);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40150);
        d2k_sched_event(s, &ap);
        spin(s, 40);

        d2k_cat_binding *m = binding_mut(&cF, "снимка.нет", 6);
        CHECK(m != NULL, "подтверждение не записано");
        if (m) { m->shape = 0; }   /* запись из файла, снятого до появления поля */

        d2k_ev h2 = ev_hello(6, 40151, "снимка.нет");
        d2k_sched_event(s, &h2);
        d2k_ev live = ev_exchange(6, 40151, 1);
        d2k_sched_event(s, &live);
        const d2k_cat_binding *bd = binding_of(&cF, "снимка.нет", 6);
        CHECK(bd != NULL && bd->level == 3,
              "TLS-ответ повысил уровень записи без записанной формы");
        CHECK(bd != NULL && bd->shape == 0,
              "форма клиента не измерена, а в записи появилась — заготовка выдана за замер");
        CHECK(bd != NULL && bd->verified_by == D2K_VERBY_PROBE,
              "наблюдение подменило источник проверки");
        d2k_sched_free(s);
        d2k_catalog_free(&cF);
    }

    close(sv[0]);
    close(sv[1]);
    d2k_catalog_free(&cat);

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("планировщик: все проверки прошли\n");
    return 0;
}
